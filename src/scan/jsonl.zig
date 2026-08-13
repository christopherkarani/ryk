//! Bounded JSONL session file reader (fail-soft on malformed lines).
const std = @import("std");
const types = @import("types.zig");
const time_window = @import("time_window.zig");
const extract = @import("extract.zig");

pub const SessionFile = struct {
    path: []const u8,
    session_id: []const u8,
    timestamp_secs: i64,
};

pub const ParsedSession = struct {
    commands: std.ArrayList([]const u8),
    text_blobs: std.ArrayList([]const u8),
    timestamp_secs: i64,

    pub fn deinit(self: *ParsedSession, allocator: std.mem.Allocator) void {
        extract.freeStringList(allocator, &self.commands);
        extract.freeStringList(allocator, &self.text_blobs);
        self.* = undefined;
    }
};

/// Read a JSONL file (bounded) and extract commands + secret-ish text blobs.
/// Fail-soft: malformed lines skipped; empty file → empty lists.
pub fn parseJsonlFile(
    io: std.Io,
    allocator: std.mem.Allocator,
    path: []const u8,
    fallback_ts: i64,
) !ParsedSession {
    var result: ParsedSession = .{
        .commands = .empty,
        .text_blobs = .empty,
        .timestamp_secs = fallback_ts,
    };
    errdefer result.deinit(allocator);

    if (path.len == 0 or path.len > 4096 or std.mem.indexOfScalar(u8, path, 0) != null) {
        return result;
    }
    // Refuse symlink targets (containment): open without following links.
    {
        const probe = std.Io.Dir.cwd().openFile(io, path, .{ .follow_symlinks = false }) catch |err| switch (err) {
            error.FileNotFound => return result,
            error.AccessDenied, error.IsDir => return result,
            // Symlink / not a regular openable file → empty (do not follow out).
            else => return result,
        };
        probe.close(io);
    }
    const text = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(types.max_file_bytes)) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.FileNotFound => return result,
        error.AccessDenied, error.IsDir => return result,
        error.FileTooBig => {
            // Oversized blob: skip body, keep empty (bounded). Caller still counts session.
            return result;
        },
        // Fail-soft on hostile paths / IO surprises during historical scan.
        else => return result,
    };
    defer allocator.free(text);

    if (text.len == 0) return result;

    var lines = std.mem.splitScalar(u8, text, '\n');
    var line_no: usize = 0;
    while (lines.next()) |raw_line| {
        line_no += 1;
        if (line_no > 5000) break; // bound lines per file
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0) continue;
        if (line.len > types.max_file_bytes) continue;

        // Timestamp opportunistic scan without full parse.
        if (result.timestamp_secs == fallback_ts) {
            if (findTimestampInLine(line)) |ts| result.timestamp_secs = ts;
        }

        var parsed = std.json.parseFromSlice(std.json.Value, allocator, line, .{}) catch continue;
        defer parsed.deinit();
        try extract.walkValueForCommands(allocator, parsed.value, &result.commands, 0);
        try extract.walkValueForTextBlobs(allocator, parsed.value, &result.text_blobs, 0);
    }
    return result;
}

fn findTimestampInLine(line: []const u8) ?i64 {
    // Look for "timestamp":"..." or "ts":"..."
    const keys = [_][]const u8{ "\"timestamp\":\"", "\"ts\":\"", "\"time\":\"" };
    for (keys) |key| {
        if (std.mem.indexOf(u8, line, key)) |idx| {
            const start = idx + key.len;
            if (start + 19 > line.len) continue;
            const end_rel = std.mem.indexOfScalar(u8, line[start..], '"') orelse continue;
            const iso = line[start .. start + end_rel];
            if (time_window.parseIsoToUnix(iso)) |ts| return ts;
        }
    }
    return null;
}

test "malformed JSON lines are skipped" {
    const io = std.testing.io;
    var root_buf: [std.fs.max_path_bytes]u8 = undefined;
    // Create under system temp using cwd relative path under zig-cache style
    const root = try std.fmt.bufPrint(&root_buf, "zig-cache/tmp-scan-jsonl-{d}", .{std.Io.Timestamp.now(io, .real).toSeconds()});
    std.Io.Dir.cwd().createDirPath(io, root) catch {};
    defer std.Io.Dir.cwd().deleteTree(io, root) catch {};

    const path = try std.fs.path.join(std.testing.allocator, &.{ root, "sess.jsonl" });
    defer std.testing.allocator.free(path);

    const body =
        \\not json
        \\{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Bash","input":{"command":"rm -rf /tmp/x"}}]}}
        \\{broken
        \\
    ;
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = body });

    var parsed = try parseJsonlFile(io, std.testing.allocator, path, 0);
    defer parsed.deinit(std.testing.allocator);
    try std.testing.expect(parsed.commands.items.len >= 1);
    try std.testing.expectEqualStrings("rm -rf /tmp/x", parsed.commands.items[0]);
}

test "oversized JSONL strings still reach secret material scanning" {
    const io = std.testing.io;
    var root_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root = try std.fmt.bufPrint(&root_buf, "zig-cache/tmp-scan-jsonl-large-{d}", .{std.Io.Timestamp.now(io, .real).toSeconds()});
    try std.Io.Dir.cwd().createDirPath(io, root);
    defer std.Io.Dir.cwd().deleteTree(io, root) catch {};
    const path = try std.fs.path.join(std.testing.allocator, &.{ root, "sess.jsonl" });
    defer std.testing.allocator.free(path);

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(std.testing.allocator);
    try body.appendSlice(std.testing.allocator, "{\"message\":{\"content\":\"");
    try body.appendNTimes(std.testing.allocator, 'a', types.max_line_bytes + 1024);
    try body.appendSlice(std.testing.allocator, " ghp_fakeSyntheticBeyondFirstWindow1234567890\"}}\n");
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = body.items });

    var parsed = try parseJsonlFile(io, std.testing.allocator, path, 0);
    defer parsed.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), parsed.text_blobs.items.len);
    try std.testing.expect(parsed.text_blobs.items[0].len > types.max_line_bytes);
}

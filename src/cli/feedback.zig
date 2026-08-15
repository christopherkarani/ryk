const std = @import("std");
const exit_codes = @import("exit_codes.zig");
const help = @import("help.zig");
const telemetry = @import("../telemetry.zig");

pub fn command(
    io: std.Io,
    environ_map: *const std.process.Environ.Map,
    argv: []const []const u8,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    if (argv.len == 1 and (std.mem.eql(u8, argv[0], "--help") or std.mem.eql(u8, argv[0], "-h"))) {
        _ = try help.writeCommand(io, stdout, "feedback");
        return exit_codes.success;
    }
    if (argv.len != 1) {
        try stderr.writeAll(
            "ryk feedback: choose one category: bug, false_positive, false_negative, missing_integration, confusing.\n",
        );
        return exit_codes.usage;
    }
    const category = parseCategory(argv[0]) orelse {
        try stderr.writeAll(
            "ryk feedback: unknown category. Choose bug, false_positive, false_negative, missing_integration, or confusing.\n",
        );
        return exit_codes.usage;
    };
    return switch (telemetry.recordFeedback(io, environ_map, std.heap.smp_allocator, category)) {
        .accepted => blk: {
            try stdout.writeAll("Decision: queued\nWhy: category recorded for telemetry\nNext: ryk telemetry status\n");
            break :blk exit_codes.success;
        },
        .disabled => try finishUnavailable(io, environ_map, stdout, stderr, category, "ryk feedback: telemetry is disabled; nothing was sent.\n"),
        .unavailable => try finishUnavailable(io, environ_map, stdout, stderr, category, "ryk feedback: telemetry state is unavailable; nothing was sent.\n"),
    };
}

fn finishUnavailable(
    io: std.Io,
    environ_map: *const std.process.Environ.Map,
    stdout: anytype,
    stderr: anytype,
    category: []const u8,
    notice: []const u8,
) !u8 {
    try stdout.writeAll("Decision: saved locally\nWhy: telemetry is off\nNext: ryk telemetry status\n");
    writeLocalFeedbackFile(io, environ_map, category) catch |err| {
        try stderr.print("ryk feedback: could not write local receipt: {s}\n", .{@errorName(err)});
        return exit_codes.general;
    };
    try stderr.writeAll(notice);
    return exit_codes.general;
}

fn resolveHome(environ_map: *const std.process.Environ.Map) ?[]const u8 {
    if (environ_map.get("HOME")) |home| {
        if (home.len > 0) return home;
    }
    if (std.c.getenv("HOME")) |home_z| {
        const home = std.mem.span(home_z);
        if (home.len > 0) return home;
    }
    return null;
}

fn writeLocalFeedbackFile(io: std.Io, environ_map: *const std.process.Environ.Map, category: []const u8) !void {
    const home = resolveHome(environ_map) orelse return error.HomeDirectoryNotFound;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const dir = try std.fs.path.join(allocator, &.{ home, ".ryk", "feedback" });
    defer allocator.free(dir);
    try std.Io.Dir.cwd().createDirPath(io, dir);
    const path = try std.fmt.allocPrint(allocator, "{s}/{d}-{s}.txt", .{ dir, std.Io.Timestamp.now(io, .real).toSeconds(), category });
    defer allocator.free(path);
    const file = try std.Io.Dir.cwd().createFile(io, path, .{});
    defer file.close(io);
    var line_buf: [128]u8 = undefined;
    const line = try std.fmt.bufPrint(&line_buf, "category={s}\n", .{category});
    try file.writeStreamingAll(io, line);
}

fn parseCategory(value: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, value, "bug")) return "bug";
    if (std.mem.eql(u8, value, "false_positive") or std.mem.eql(u8, value, "false-positive")) return "false_positive";
    if (std.mem.eql(u8, value, "false_negative") or std.mem.eql(u8, value, "false-negative")) return "false_negative";
    if (std.mem.eql(u8, value, "missing_integration") or std.mem.eql(u8, value, "missing-integration")) return "missing_integration";
    if (std.mem.eql(u8, value, "confusing")) return "confusing";
    return null;
}

test "feedback accepts only fixed categories" {
    try std.testing.expectEqualStrings("false_positive", parseCategory("false-positive").?);
    try std.testing.expect(parseCategory("free text") == null);
}

test "feedback bug writes a local receipt when telemetry is disabled" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(home);

    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();
    try environ_map.put("HOME", home);

    var stdout_buf: [512]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, &environ_map, &.{"bug"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.general, code);
    const out = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "Decision: saved locally") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Why: telemetry is off") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Next: ryk telemetry status") != null);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "telemetry is disabled") != null);
}

test "feedback write errors are not swallowed" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "not-a-dir", .data = "x" });
    const tmp_root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(tmp_root);
    const home = try std.fs.path.join(std.testing.allocator, &.{ tmp_root, "not-a-dir" });
    defer std.testing.allocator.free(home);

    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();
    try environ_map.put("HOME", home);

    var stdout_buf: [512]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, &environ_map, &.{"bug"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.general, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "could not write local receipt") != null);
}

test "feedback reports unavailable transport instead of claiming delivery" {
    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();
    try std.testing.expectEqual(
        telemetry.FeedbackStatus.disabled,
        telemetry.recordFeedback(std.testing.io, &environ_map, std.testing.allocator, "bug"),
    );
}

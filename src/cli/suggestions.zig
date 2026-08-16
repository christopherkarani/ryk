const std = @import("std");
const terminal_text = @import("../tui/terminal_text.zig");

/// Allocation-free edit distance for short CLI tokens.
pub fn distance(a: []const u8, b: []const u8) usize {
    if (a.len == 0) return b.len;
    if (b.len == 0) return a.len;

    var previous: [128]usize = undefined;
    var current: [128]usize = undefined;
    if (a.len >= previous.len or b.len >= previous.len) return std.math.maxInt(usize);
    const rows = a.len;
    const columns = b.len;

    for (0..columns + 1) |column| previous[column] = column;
    for (0..rows) |row| {
        current[0] = row + 1;
        for (0..columns) |column| {
            const substitution_cost: usize = if (a[row] == b[column]) 0 else 1;
            current[column + 1] = @min(
                @min(previous[column + 1] + 1, current[column] + 1),
                previous[column] + substitution_cost,
            );
        }
        const swap = previous;
        previous = current;
        current = swap;
    }
    return previous[columns];
}

/// Max Levenshtein edits for an unknown token of this length.
/// Short tokens (≤3) allow one edit only so weak rewrites like `foo`→`hook`
/// (distance 2 on a 3-char token) never fire; longer tokens still allow two.
fn maxEditDistance(token_len: usize) usize {
    if (token_len <= 3) return 1;
    return 2;
}

/// Returns a prefix match or the unique closest candidate within the length-
/// scaled edit budget (see `maxEditDistance`).
pub fn closest(unknown: []const u8, candidates: []const []const u8) ?[]const u8 {
    if (unknown.len == 0) return null;
    for (candidates) |candidate| {
        if (std.mem.eql(u8, candidate, unknown)) return candidate;
    }

    var prefix_match: ?[]const u8 = null;
    for (candidates) |candidate| {
        if (!std.mem.startsWith(u8, candidate, unknown)) continue;
        if (prefix_match != null) return null;
        prefix_match = candidate;
    }
    if (prefix_match) |candidate| return candidate;

    const max_edits = maxEditDistance(unknown.len);
    var best: ?[]const u8 = null;
    var best_distance: usize = max_edits + 1;
    var tied = false;
    for (candidates) |candidate| {
        const candidate_distance = distance(unknown, candidate);
        if (candidate_distance < best_distance) {
            best = candidate;
            best_distance = candidate_distance;
            tied = false;
        } else if (candidate_distance == best_distance) {
            tied = true;
        }
    }
    return if (best_distance <= max_edits and !tied) best else null;
}

pub fn writeUnknownOption(
    writer: anytype,
    context: []const u8,
    unknown: []const u8,
    candidates: []const []const u8,
    help_command: []const u8,
) !void {
    try writer.print("{s}: unknown option '", .{context});
    try terminal_text.write(writer, unknown, .single_line);
    try writer.writeAll("'.");
    if (closest(unknown, candidates)) |candidate| try writer.print(" Did you mean '{s}'?", .{candidate});
    try writer.print("\nRun 'ryk help {s}' for usage.\n", .{help_command});
}

pub fn writeUnknownSubcommand(
    writer: anytype,
    context: []const u8,
    unknown: []const u8,
    candidates: []const []const u8,
    help_command: []const u8,
) !void {
    try writer.print("{s}: unknown subcommand '", .{context});
    try terminal_text.write(writer, unknown, .single_line);
    try writer.writeAll("'.");
    if (closest(unknown, candidates)) |candidate| try writer.print(" Did you mean '{s}'?", .{candidate});
    try writer.print("\nRun 'ryk help {s}' for usage.\n", .{help_command});
}

pub fn writeInvalidValue(
    writer: anytype,
    context: []const u8,
    option: []const u8,
    unknown: []const u8,
    candidates: []const []const u8,
    help_command: []const u8,
) !void {
    try writer.print("{s}: invalid {s} value '", .{ context, option });
    try terminal_text.write(writer, unknown, .single_line);
    try writer.writeAll("'. Expected ");
    for (candidates, 0..) |candidate, index| {
        if (index > 0) try writer.writeAll("|");
        try writer.writeAll(candidate);
    }
    if (closest(unknown, candidates)) |candidate| try writer.print(". Did you mean '{s}'?", .{candidate});
    try writer.print(".\nRun 'ryk help {s}' for usage.\n", .{help_command});
}

pub fn writeSanitizedValue(writer: anytype, prefix: []const u8, value: []const u8, suffix: []const u8) !void {
    try writer.writeAll(prefix);
    try terminal_text.write(writer, value, .single_line);
    try writer.writeAll(suffix);
}

test "closest suggests prefixes and edit-distance typos without guessing unrelated tokens" {
    const candidates = &[_][]const u8{ "--command", "--manifest", "--policy" };
    try std.testing.expectEqualStrings("--command", closest("--comand", candidates).?);
    try std.testing.expectEqualStrings("--manifest", closest("--man", candidates).?);
    try std.testing.expect(closest("--xyz", candidates) == null);
}

test "closest rejects weak short-token rewrites like foo to hook" {
    // Distance 2 on a 3-char token must not suggest an unrelated power command.
    const commands = &[_][]const u8{ "hook", "doctor", "policy", "help", "run" };
    try std.testing.expect(closest("foo", commands) == null);
    // One-edit typos on short tokens still suggest when unambiguous.
    try std.testing.expectEqualStrings("hook", closest("hok", commands).?);
    // Longer real typos still get up to two edits.
    try std.testing.expectEqualStrings("doctor", closest("docter", commands).?);
    try std.testing.expectEqualStrings("policy", closest("polcy", commands).?);
}

test "closest requires an unambiguous best candidate" {
    const candidates = &[_][]const u8{ "check", "checkout", "chock" };
    try std.testing.expectEqualStrings("check", closest("check", candidates).?);
    try std.testing.expect(closest("", candidates) == null);
    try std.testing.expect(closest("ch", candidates) == null);
    try std.testing.expect(closest("chick", &.{ "check", "chock" }) == null);
}

test "unknown option writer always includes exact usage remediation" {
    var buffer: [256]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try writeUnknownOption(&writer, "ryk test", "--formt", &.{ "--format", "--help" }, "test");
    try std.testing.expectEqualStrings(
        "ryk test: unknown option '--formt'. Did you mean '--format'?\nRun 'ryk help test' for usage.\n",
        writer.buffered(),
    );
}

test "unknown argument writers flatten hostile terminal controls" {
    var buffer: [256]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try writeUnknownSubcommand(&writer, "ryk test", "bad\x1b[2J\nvalue", &.{"good"}, "test");
    try std.testing.expect(std.mem.indexOfScalar(u8, writer.buffered(), 0x1b) == null);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "\nvalue") == null);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "bad value") != null);
}

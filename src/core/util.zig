//! Shared Phase 03 utilities.
//!
//! Allocation conventions:
//! - CLI command lifetime data should use a command arena owned by CLI dispatch.
//! - Session lifetime data should use a session arena owned by the supervisor.
//! - Persistent audit data must be serialized into owned bytes before any arena is freed.
//! - Helpers that copy untrusted input take explicit maximum sizes.
//! - Core types never reach for a hidden global allocator.

const std = @import("std");
const errors = @import("errors.zig");

pub fn hexLower(bytes: []const u8, out: []u8) ![]const u8 {
    if (out.len < bytes.len * 2) return error.NoSpaceLeft;
    for (bytes, 0..) |byte, i| {
        const encoded = std.fmt.bytesToHex([1]u8{byte}, .lower);
        out[i * 2] = encoded[0];
        out[i * 2 + 1] = encoded[1];
    }
    return out[0 .. bytes.len * 2];
}

pub fn randomHexSuffix(io: std.Io, out: []u8) ![]const u8 {
    if (out.len == 0 or out.len % 2 != 0) return error.InvalidLength;
    var random_bytes: [@import("limits.zig").max_short_suffix_bytes]u8 = undefined;
    const needed = out.len / 2;
    if (needed > random_bytes.len) return error.NoSpaceLeft;
    try io.randomSecure(random_bytes[0..needed]);
    return hexLower(random_bytes[0..needed], out);
}

pub fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

pub fn dupBoundedUtf8(allocator: std.mem.Allocator, input: []const u8, max_len: usize) ![]u8 {
    if (input.len > max_len) return errors.RykError.InputTooLarge;
    if (!std.unicode.utf8ValidateSlice(input)) return errors.RykError.InvalidUtf8;
    return allocator.dupe(u8, input);
}

pub fn writeJsonString(writer: anytype, value: []const u8) !void {
    try writer.writeByte('"');
    for (value) |byte| {
        switch (byte) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            0...8, 11...12, 14...0x1f => try writer.print("\\u{x:0>4}", .{byte}),
            else => try writer.writeByte(byte),
        }
    }
    try writer.writeByte('"');
}

pub fn BoundedBuffer(comptime capacity: usize) type {
    return struct {
        buf: [capacity]u8 = undefined,
        len: usize = 0,

        pub fn append(self: *@This(), bytes: []const u8) !void {
            if (self.len + bytes.len > self.buf.len) return error.NoSpaceLeft;
            @memcpy(self.buf[self.len .. self.len + bytes.len], bytes);
            self.len += bytes.len;
        }

        pub fn slice(self: *const @This()) []const u8 {
            return self.buf[0..self.len];
        }
    };
}

test "hex and random suffix helpers produce lowercase hex" {
    var hex_buf: [6]u8 = undefined;
    try std.testing.expectEqualStrings("00abff", try hexLower(&.{ 0x00, 0xab, 0xff }, &hex_buf));

    var suffix: [8]u8 = undefined;
    const written = try randomHexSuffix(std.testing.io, &suffix);
    try std.testing.expectEqual(@as(usize, 8), written.len);
    for (written) |byte| {
        try std.testing.expect(std.ascii.isHex(byte));
        try std.testing.expect(!std.ascii.isUpper(byte));
    }
}

test "bounded utf8 duplication rejects oversized or invalid input" {
    const allocator = std.testing.allocator;
    const copied = try dupBoundedUtf8(allocator, "ryk", 16);
    defer allocator.free(copied);
    try std.testing.expectEqualStrings("ryk", copied);
    try std.testing.expectError(error.InputTooLarge, dupBoundedUtf8(allocator, "too long", 3));
    try std.testing.expectError(error.InvalidUtf8, dupBoundedUtf8(allocator, &.{0xff}, 3));
}

test "json string writer escapes bounded values" {
    var buf: [64]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try writeJsonString(&writer, "a\"b\\c\n");
    try std.testing.expectEqualStrings("\"a\\\"b\\\\c\\n\"", writer.buffered());
}

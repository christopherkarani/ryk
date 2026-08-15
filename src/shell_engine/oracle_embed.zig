//! Compressed oracle pack catalog.
//!
//! `oracle_packs.json` remains the editable source of truth (regex must stay
//! byte-identical). The product binary embeds only the gzip. Regenerate with:
//!
//!   gzip -9n -c src/shell_engine/oracle_packs.json > src/shell_engine/oracle_packs.json.gz
//!
//! Drift is caught by the inflate-identity test (raw JSON is test-only).
//! Inflate failure is fail-closed: never return empty JSON to an eval caller.

const std = @import("std");

const compressed = @embedFile("oracle_packs.json.gz");

/// Hard cap against a hostile/corrupt stream. Real catalog is 289,521 bytes.
const max_inflated_len: usize = 512 * 1024;

pub const compressed_len = compressed.len;

pub const Error = error{ PacksInflateFailed, OutOfMemory };

/// Inflate the embedded gzip into an allocator-owned buffer.
pub fn inflateAlloc(allocator: std.mem.Allocator) Error![]u8 {
    return inflateSlice(allocator, compressed);
}

/// Inflate `compressed` gzip bytes. Empty or oversize output is a failure.
pub fn inflateSlice(allocator: std.mem.Allocator, gzip_bytes: []const u8) Error![]u8 {
    // gzip header is 10 bytes; shorter input cannot be a valid catalog.
    if (gzip_bytes.len < 10) return error.PacksInflateFailed;

    var input: std.Io.Reader = .fixed(gzip_bytes);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var decompress: std.compress.flate.Decompress = .init(&input, .gzip, &window);

    // Cap during the stream. A post-hoc length check after streamRemaining
    // would still allocate a gzip bomb. +1 so a catalog of exactly
    // max_inflated_len is accepted; StreamTooLong then means at least one
    // byte over the cap.
    const json = decompress.reader.allocRemaining(allocator, .limited(max_inflated_len + 1)) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.PacksInflateFailed,
    };
    errdefer allocator.free(json);

    if (decompress.err != null) return error.PacksInflateFailed;
    if (json.len == 0 or json.len > max_inflated_len) return error.PacksInflateFailed;
    if (!looksLikePacksArray(json)) return error.PacksInflateFailed;

    return json;
}

fn looksLikePacksArray(json: []const u8) bool {
    var i: usize = 0;
    while (i < json.len) : (i += 1) {
        switch (json[i]) {
            ' ', '\t', '\n', '\r' => {},
            '[' => return true,
            else => return false,
        }
    }
    return false;
}

test "embedded gzip inflates to byte-identical oracle_packs.json" {
    const raw = @embedFile("oracle_packs.json");
    const inflated = try inflateAlloc(std.testing.allocator);
    defer std.testing.allocator.free(inflated);
    try std.testing.expectEqualSlices(u8, raw, inflated);
    try std.testing.expect(std.mem.startsWith(u8, inflated, "[{\"id\":\""));
    // Fail the gate before a growing catalog silently hits the hard cap.
    try std.testing.expect(inflated.len + 64 * 1024 <= max_inflated_len);
}

test "corrupt or truncated gzip fails closed (not empty json)" {
    try std.testing.expectError(error.PacksInflateFailed, inflateSlice(std.testing.allocator, ""));
    try std.testing.expectError(error.PacksInflateFailed, inflateSlice(std.testing.allocator, "not-gzip"));
    try std.testing.expectError(error.PacksInflateFailed, inflateSlice(
        std.testing.allocator,
        &.{ 0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 },
    ));
    try std.testing.expectError(error.PacksInflateFailed, inflateSlice(
        std.testing.allocator,
        compressed[0 .. compressed.len / 2],
    ));
}

test "gzip of empty or non-array payload fails closed" {
    // gzip -n of "" and "{}" (mtime 0). Empty / object must not become a catalog.
    const empty_gz = [_]u8{
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x03, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const obj_gz = [_]u8{
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xab, 0xae,
        0x05, 0x00, 0x43, 0xbf, 0xa6, 0xa3, 0x02, 0x00, 0x00, 0x00,
    };
    try std.testing.expectError(error.PacksInflateFailed, inflateSlice(std.testing.allocator, &empty_gz));
    try std.testing.expectError(error.PacksInflateFailed, inflateSlice(std.testing.allocator, &obj_gz));
}

fn gzipAlloc(allocator: std.mem.Allocator, payload: []const u8) ![]u8 {
    var out: std.Io.Writer.Allocating = try .initCapacity(allocator, 256);
    errdefer out.deinit();
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var comp = try std.compress.flate.Compress.init(&out.writer, &window, .gzip, .fastest);
    try comp.writer.writeAll(payload);
    try comp.finish();
    return out.toOwnedSlice();
}

test "oversize inflate fails closed without keeping the stream" {
    const payload = try std.testing.allocator.alloc(u8, max_inflated_len + 1);
    defer std.testing.allocator.free(payload);
    @memset(payload, 0);
    const gz = try gzipAlloc(std.testing.allocator, payload);
    defer std.testing.allocator.free(gz);
    try std.testing.expectError(error.PacksInflateFailed, inflateSlice(std.testing.allocator, gz));
}

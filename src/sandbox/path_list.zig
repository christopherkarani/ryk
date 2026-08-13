//! Owned heap copies of path lists shared by sandbox apply and `ryk run`
//! launch wiring. Canonical home for clone/free so callers never grow bespoke
//! per-module duplicates.

const std = @import("std");

/// Deep-copy `paths` into an owned slice of owned path slices.
/// Caller releases with `free`.
pub fn clone(allocator: std.mem.Allocator, paths: []const []const u8) error{OutOfMemory}![][]const u8 {
    const owned = try allocator.alloc([]const u8, paths.len);
    errdefer allocator.free(owned);
    var initialized: usize = 0;
    errdefer for (owned[0..initialized]) |path| allocator.free(path);
    for (paths, 0..) |path, index| {
        owned[index] = try allocator.dupe(u8, path);
        initialized += 1;
    }
    return owned;
}

/// Release a list from `clone` (or any list of individually owned paths).
pub fn free(allocator: std.mem.Allocator, paths: []const []const u8) void {
    for (paths) |path| allocator.free(path);
    allocator.free(paths);
}

test "clone deep-copies and free releases" {
    const allocator = std.testing.allocator;
    const input = [_][]const u8{ "/a", "/b/c" };
    const owned = try clone(allocator, &input);
    free(allocator, owned);
}

test "clone handles empty list" {
    const allocator = std.testing.allocator;
    const owned = try clone(allocator, &.{});
    try std.testing.expectEqual(@as(usize, 0), owned.len);
    free(allocator, owned);
}

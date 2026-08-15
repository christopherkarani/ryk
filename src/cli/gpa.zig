const std = @import("std");
const builtin = @import("builtin");

/// Product GPA owner.
///
/// Debug builds keep `DebugAllocator` so leak and size-mismatch tests still
/// fire. Other modes return `smp_allocator` without naming `DebugAllocator`,
/// so ReleaseSafe can DCE the type. One remaining product construction would
/// ship the whole allocator.
pub const State = if (builtin.mode == .Debug)
    std.heap.DebugAllocator(.{})
else
    struct {
        pub const init: @This() = .{};

        pub fn deinit(_: *@This()) std.heap.Check {
            return .ok;
        }

        pub fn allocator(_: *@This()) std.mem.Allocator {
            return std.heap.smp_allocator;
        }
    };

test "Debug mode State is DebugAllocator" {
    if (builtin.mode == .Debug) {
        try std.testing.expect(State == std.heap.DebugAllocator(.{}));
    } else {
        try std.testing.expect(State != std.heap.DebugAllocator(.{}));
    }
}

test "State allocator allocates and frees" {
    var state: State = .init;
    defer _ = state.deinit();
    const allocator = state.allocator();
    const buf = try allocator.alloc(u8, 8);
    defer allocator.free(buf);
    @memset(buf, 0);
}

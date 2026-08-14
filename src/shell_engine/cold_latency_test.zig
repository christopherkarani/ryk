//! Isolated cold-start budget for hook evaluation.
//!
//! This file is its own test binary so `ensureInit` is not warmed by other
//! registry tests. First-hook cost is JSON parse + keyword-gated PCRE compile.

const std = @import("std");
const builtin = @import("builtin");
const registry = @import("registry.zig");

const budget_ns: u64 = 5 * std.time.ns_per_ms;

fn limitNs() u64 {
    return switch (builtin.mode) {
        .ReleaseFast, .ReleaseSmall => budget_ns,
        // DebugAllocator / runtime safety make Debug/ReleaseSafe slower.
        else => 50 * std.time.ns_per_ms,
    };
}

fn nowNs() i96 {
    var threaded: std.Io.Threaded = .init_single_threaded;
    return std.Io.Timestamp.now(threaded.io(), .awake).toNanoseconds();
}

fn elapsedNs(started: i96) u64 {
    const now = nowNs();
    if (now <= started) return 0;
    return @intCast(now - started);
}

test "cold first hook (init + git status) stays under the hook budget" {
    const started = nowNs();
    try registry.ensureInitDefault();
    const result = registry.matchCommandDetailed("git status");
    const first_ns = elapsedNs(started);

    try std.testing.expect(result != .deny);
    try std.testing.expect(first_ns <= limitNs());
}

test "typical commands stay under the hook budget" {
    try registry.ensureInitDefault();
    const commands = [_][]const u8{
        "ls",
        "echo hello",
        "pwd",
        "rm -rf /",
        "git push --force",
    };
    for (commands) |cmd| {
        const started = nowNs();
        _ = registry.matchCommandDetailed(cmd);
        try std.testing.expect(elapsedNs(started) <= limitNs());
    }
}

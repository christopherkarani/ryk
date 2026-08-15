//! Isolated cold-start checks for hook evaluation.
//!
//! This file is its own test binary so `ensureInit` is not warmed by other
//! registry tests. First-hook cost is JSON parse + keyword-gated PCRE compile.
//! Timing here is observational (this runner, this mode) — not a host SLA.

const std = @import("std");
const registry = @import("registry.zig");

fn nowNs() i96 {
    var threaded: std.Io.Threaded = .init_single_threaded;
    return std.Io.Timestamp.now(threaded.io(), .awake).toNanoseconds();
}

fn elapsedNs(started: i96) u64 {
    const now = nowNs();
    if (now <= started) return 0;
    return @intCast(now - started);
}

test "cold first hook allows git status" {
    const started = nowNs();
    try registry.ensureInitDefault();
    const result = registry.matchCommandDetailed("git status");
    const first_ns = elapsedNs(started);

    try std.testing.expect(result != .deny);
    // A real init+match must advance the clock. elapsed==0 is a measurement bug,
    // not a pass. There is no cross-host millisecond budget.
    try std.testing.expect(first_ns > 0);
}

test "cold first hook denies rm -rf /" {
    try registry.ensureInitDefault();
    const started = nowNs();
    const result = registry.matchCommandDetailed("rm -rf /");
    const took_ns = elapsedNs(started);

    try std.testing.expect(result == .deny);
    try std.testing.expectEqualStrings("core.filesystem", result.deny.pack_id);
    try std.testing.expect(took_ns > 0);
}

test "cold default packs still deny force-equivalent git push" {
    try registry.ensureInitDefault();
    const result = registry.matchCommandDetailed("git push --force");
    try std.testing.expect(result == .deny);
}

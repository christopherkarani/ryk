//! Tool-path ask-resume matrix (docs/integrations/host-decision-mapping.md).
//!
//! `ask` is only an approval gate when the host can resume. Several hosts map
//! tool-path `ask` to a hard block with no resume — that is a product landmine
//! if start/launch stay silent.

const std = @import("std");

pub const ToolAskEnforcement = enum {
    native_approve_and_resume,
    partial_host_ask,
    hard_block_no_resume,
    host_dependent,
    unknown,
};

/// Primary tool-path enforcement for ryk `ask`. Matches the living matrix;
/// do not invent resume for hosts that hard-block.
pub fn toolAskEnforcement(host: []const u8) ToolAskEnforcement {
    if (std.mem.eql(u8, host, "hermes")) return .native_approve_and_resume;
    if (std.mem.eql(u8, host, "claude")) return .partial_host_ask;
    if (std.mem.eql(u8, host, "codex")) return .partial_host_ask;
    if (std.mem.eql(u8, host, "grok")) return .partial_host_ask;
    if (std.mem.eql(u8, host, "openclaw")) return .hard_block_no_resume;
    if (std.mem.eql(u8, host, "opencode")) return .hard_block_no_resume;
    if (std.mem.eql(u8, host, "cursor")) return .hard_block_no_resume;
    if (std.mem.eql(u8, host, "pi")) return .host_dependent;
    return .unknown;
}

pub fn hardBlocksAskWithNoResume(host: []const u8) bool {
    return toolAskEnforcement(host) == .hard_block_no_resume;
}

/// One-line launch/start warning. Null when the host can resume ask (or unknown).
pub fn warnLine(host: []const u8) ?[]const u8 {
    return switch (toolAskEnforcement(host)) {
        .hard_block_no_resume => "hard-blocks ask with no resume",
        .host_dependent => "ask resume is host-dependent",
        .partial_host_ask => "ask resume is partial (hook-grade)",
        .native_approve_and_resume, .unknown => null,
    };
}

/// Hosts that should be named on the start/launch warn (hard-block first).
pub fn collectWarnHosts(hosts: []const []const u8, out: [][]const u8) usize {
    var n: usize = 0;
    for (hosts) |host| {
        if (warnLine(host) == null) continue;
        if (n >= out.len) break;
        out[n] = host;
        n += 1;
    }
    return n;
}

/// Owned start-card / launch warning, or null when no selected host needs one.
/// Caller frees. Cites the matrix; does not remap ask→allow.
pub fn formatWarn(allocator: std.mem.Allocator, hosts: []const []const u8) error{OutOfMemory}!?[]u8 {
    var buf: [8][]const u8 = undefined;
    const n = collectWarnHosts(hosts, &buf);
    if (n == 0) return null;

    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    try list.appendSlice(allocator, "Ask on ");
    for (buf[0..n], 0..) |host, i| {
        if (i > 0) try list.appendSlice(allocator, ", ");
        try list.appendSlice(allocator, host);
        if (warnLine(host)) |detail| {
            try list.appendSlice(allocator, " ");
            try list.appendSlice(allocator, detail);
        }
    }
    try list.appendSlice(allocator, ". See docs/integrations/host-decision-mapping.md.");
    return try list.toOwnedSlice(allocator);
}

test "host_ask_resume matrix: hermes resumes; openclaw/opencode/cursor hard-block" {
    try std.testing.expectEqual(ToolAskEnforcement.native_approve_and_resume, toolAskEnforcement("hermes"));
    try std.testing.expect(!hardBlocksAskWithNoResume("hermes"));
    try std.testing.expectEqual(ToolAskEnforcement.hard_block_no_resume, toolAskEnforcement("openclaw"));
    try std.testing.expectEqual(ToolAskEnforcement.hard_block_no_resume, toolAskEnforcement("opencode"));
    try std.testing.expectEqual(ToolAskEnforcement.hard_block_no_resume, toolAskEnforcement("cursor"));
    try std.testing.expect(hardBlocksAskWithNoResume("cursor"));
    try std.testing.expectEqual(ToolAskEnforcement.partial_host_ask, toolAskEnforcement("claude"));
    try std.testing.expectEqual(ToolAskEnforcement.partial_host_ask, toolAskEnforcement("codex"));
    try std.testing.expectEqual(ToolAskEnforcement.partial_host_ask, toolAskEnforcement("grok"));
    try std.testing.expectEqual(ToolAskEnforcement.host_dependent, toolAskEnforcement("pi"));
    try std.testing.expectEqual(ToolAskEnforcement.unknown, toolAskEnforcement("not-a-host"));
}

test "host_ask_resume formatWarn names hard-block hosts and stays silent for hermes-only" {
    try std.testing.expect(try formatWarn(std.testing.allocator, &.{"hermes"}) == null);

    const text = (try formatWarn(std.testing.allocator, &.{ "hermes", "opencode", "cursor" })).?;
    defer std.testing.allocator.free(text);
    try std.testing.expect(std.mem.indexOf(u8, text, "opencode") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "cursor") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "hermes") == null);
    try std.testing.expect(std.mem.indexOf(u8, text, "hard-blocks ask with no resume") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "host-decision-mapping.md") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "allow") == null);
}

//! Shared 6-tag hook/decide `PluginDecision` and the locked 7×2
//! `DecisionResult` → `PluginDecision` table.
//!
//! This file must not import `hook.zig` or `decide.zig`.
//! Must not merge with `core.decision.DecisionResult`, YAML `DecisionValue`,
//! or the 4-tag `shell_eval.PluginDecision`.
//!
//! Shell facade 4→6 (`observe` → `warn`) stays in `hook.zig`:
//! `hookDecisionFromShellFacade` / `shellEvalPluginDecisionToHook`.
//! Host emit (Grok exit-2 deny, Hermes ask→approve, Claude
//! `permissionDecision`) is not this table.

const std = @import("std");
const core = @import("ryk_core").core;
const exit_codes = @import("exit_codes.zig");

pub const PluginDecision = enum {
    allow,
    block,
    warn,
    ask,
    context_only,
    err,

    pub fn fromDecisionResult(result: core.decision.DecisionResult, ci_mode: bool) PluginDecision {
        return switch (result) {
            .allow => .allow,
            .deny => .block,
            .ask => if (ci_mode) .block else .ask,
            .observe => .context_only,
            .redact => .warn,
            .stage => if (ci_mode) .block else .ask,
            .broker => .err,
        };
    }

    pub fn toString(self: PluginDecision) []const u8 {
        return switch (self) {
            .err => "error",
            else => @tagName(self),
        };
    }

    pub fn exitCode(self: PluginDecision) u8 {
        return switch (self) {
            .allow, .context_only => exit_codes.success,
            .block => exit_codes.denial,
            .ask => exit_codes.ask,
            .warn => exit_codes.warn,
            .err => exit_codes.general,
        };
    }
};

test "decision_map 7x2 fromDecisionResult table is locked" {
    const DecisionResult = core.decision.DecisionResult;
    const cases = [_]struct { DecisionResult, bool, PluginDecision }{
        .{ .allow, false, .allow },
        .{ .allow, true, .allow },
        .{ .deny, false, .block },
        .{ .deny, true, .block },
        .{ .ask, false, .ask },
        .{ .ask, true, .block },
        .{ .observe, false, .context_only },
        .{ .observe, true, .context_only },
        .{ .redact, false, .warn },
        .{ .redact, true, .warn },
        .{ .stage, false, .ask },
        .{ .stage, true, .block },
        .{ .broker, false, .err },
        .{ .broker, true, .err },
    };
    try std.testing.expectEqual(@typeInfo(DecisionResult).@"enum".fields.len * 2, cases.len);
    for (cases) |entry| {
        try std.testing.expectEqual(entry[2], PluginDecision.fromDecisionResult(entry[0], entry[1]));
    }
}

test "decision_map PluginDecision toString and exitCode stay host-agnostic" {
    try std.testing.expectEqualStrings("allow", PluginDecision.allow.toString());
    try std.testing.expectEqualStrings("error", PluginDecision.err.toString());
    try std.testing.expectEqual(exit_codes.success, PluginDecision.allow.exitCode());
    try std.testing.expectEqual(exit_codes.ask, PluginDecision.ask.exitCode());
    try std.testing.expectEqual(exit_codes.denial, PluginDecision.block.exitCode());
}

//! Host-wire rewrite for coding-host enforcement wires.
//! Not policy evaluate. Not host JSON formatting.

const std = @import("std");
const env_util = @import("../env_util.zig");

/// Why this ask exists. No leftover default. Callers produce this.
pub const AskOrigin = enum {
    leftover,
    soft_block,
    fm,
};

/// Why a never-permit ask is never leftover unused policy ask.
pub const NeverPermitAsk = enum {
    soft_block,
    fm_steward,
    missing_origin,
};

/// Payload of a policy decision of `ask`. Missing origin is not leftover unused policy ask.
pub const Ask = union(enum) {
    leftover_unused_policy_ask,
    never_permit: NeverPermitAsk,
};

/// Policy decision at the coding-host enforcement wire seam.
/// `.ask` without a payload does not compile.
pub const PolicyDecisionForWire = union(enum) {
    allow,
    deny,
    observe,
    stage,
    ask: Ask,
};

/// Host-wire outcome. Leftover unused policy ask is not a tag.
pub const HostWireOutcome = enum {
    allow,
    deny,
    observe,
    /// Attended stage only. Unattended stage is `.deny`.
    stage,
};

/// Known origin → ask payload. Absence cannot go through this function.
pub fn askFromKnownOrigin(origin: AskOrigin) Ask {
    return switch (origin) {
        .leftover => .leftover_unused_policy_ask,
        .soft_block => .{ .never_permit = .soft_block },
        .fm => .{ .never_permit = .fm_steward },
    };
}

/// The only constructor for absence. Never leftover unused policy ask.
pub fn askFromMissingOrigin() Ask {
    return .{ .never_permit = .missing_origin };
}

pub fn fromAskOrigin(origin: ?AskOrigin) Ask {
    return if (origin) |o| askFromKnownOrigin(o) else askFromMissingOrigin();
}

/// Leftover unused policy ask → permit or deny.
/// Missing ask origin and never-permit ask → deny.
/// Unattended stage → deny.
/// allow / deny / observe pass through.
pub fn rewrite(for_wire: PolicyDecisionForWire, is_unattended: bool) HostWireOutcome {
    return switch (for_wire) {
        .allow => .allow,
        .deny => .deny,
        .observe => .observe,
        .stage => if (is_unattended) .deny else .stage,
        .ask => |ask| switch (ask) {
            .leftover_unused_policy_ask => if (is_unattended) .deny else .allow,
            .never_permit => .deny,
        },
    };
}

/// `--ci` OR shared keys via `lookup.get(key) ?[]const u8`.
/// Hermes/OpenClaw extras stay in adapters and fold into `ci` or the lookup.
pub fn unattendedFromLookup(ci: bool, lookup: anytype) bool {
    return ci or env_util.unattendedFromLookup(lookup);
}

/// `--ci` OR process env shared keys.
pub fn unattendedFromEnv(ci: bool) bool {
    return ci or env_util.getenvUnattended();
}

test "attended leftover unused policy ask is permit" {
    const outcome = rewrite(.{ .ask = askFromKnownOrigin(.leftover) }, false);
    try std.testing.expectEqual(HostWireOutcome.allow, outcome);
}

test "unattended leftover unused policy ask is deny" {
    const outcome = rewrite(.{ .ask = askFromKnownOrigin(.leftover) }, true);
    try std.testing.expectEqual(HostWireOutcome.deny, outcome);
}

test "missing ask origin is never-permit" {
    const outcome = rewrite(.{ .ask = askFromMissingOrigin() }, false);
    try std.testing.expectEqual(HostWireOutcome.deny, outcome);
    try std.testing.expectEqual(HostWireOutcome.deny, rewrite(.{ .ask = fromAskOrigin(null) }, false));
}

test "SoftBlock is never-permit" {
    try std.testing.expectEqual(
        HostWireOutcome.deny,
        rewrite(.{ .ask = askFromKnownOrigin(.soft_block) }, false),
    );
}

test "FM steward ask is never-permit" {
    try std.testing.expectEqual(
        HostWireOutcome.deny,
        rewrite(.{ .ask = askFromKnownOrigin(.fm) }, false),
    );
}

test "explicit deny never becomes allow" {
    try std.testing.expectEqual(HostWireOutcome.deny, rewrite(.deny, false));
    try std.testing.expectEqual(HostWireOutcome.deny, rewrite(.deny, true));
}

test "attended stage stays stage" {
    try std.testing.expectEqual(HostWireOutcome.stage, rewrite(.stage, false));
}

test "unattended stage is deny" {
    try std.testing.expectEqual(HostWireOutcome.deny, rewrite(.stage, true));
}

test "allow and observe pass through" {
    try std.testing.expectEqual(HostWireOutcome.allow, rewrite(.allow, true));
    try std.testing.expectEqual(HostWireOutcome.observe, rewrite(.observe, true));
}

test "host-wire outcome has no ask tag" {
    try std.testing.expect(!@hasField(HostWireOutcome, "ask"));
}

test "unattended helper ORs ci with shared keys" {
    const Lookup = struct {
        key: []const u8,
        value: []const u8,
        pub fn get(self: @This(), key: []const u8) ?[]const u8 {
            return if (std.mem.eql(u8, key, self.key)) self.value else null;
        }
    };
    try std.testing.expect(unattendedFromLookup(true, Lookup{ .key = "CI", .value = "0" }));
    try std.testing.expect(unattendedFromLookup(false, Lookup{ .key = "CI", .value = "1" }));
    try std.testing.expect(!unattendedFromLookup(false, Lookup{ .key = "CI", .value = "0" }));
    try std.testing.expect(unattendedFromLookup(false, Lookup{ .key = "RYK_UNATTENDED", .value = "true" }));
}

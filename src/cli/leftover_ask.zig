//! Leftover unused policy ask on coding-host doors.
//!
//! Policy still computes leftover unused `ask`. This helper is the only flip:
//! attended leftover unused ask → allow; unattended → deny. SoftBlock, FM, and
//! stage never become allow. `ryk decide` does not call this.

const shell_eval = @import("shell_eval.zig");

pub const AskOrigin = shell_eval.AskOrigin;

pub const Outcome = enum {
    /// Leftover unused ask on an attended coding-host door.
    allow,
    /// Leftover unused ask while unattended/CI, or SoftBlock / FM ask.
    deny,
    /// Not an ask — caller keeps the computed decision.
    unchanged,
};

/// Host-facing leftover unused-ask wire. Callers map `deny` to their deny/block.
pub fn codingHostAskOutcome(is_ask: bool, origin: AskOrigin, unattended: bool) Outcome {
    if (!is_ask) return .unchanged;
    if (origin.mayPermitOnCodingHost()) {
        return if (unattended) .deny else .allow;
    }
    return .deny;
}

test "attended leftover unused ask is allow" {
    const std = @import("std");
    try std.testing.expectEqual(Outcome.allow, codingHostAskOutcome(true, .leftover, false));
}

test "unattended leftover unused ask is deny" {
    const std = @import("std");
    try std.testing.expectEqual(Outcome.deny, codingHostAskOutcome(true, .leftover, true));
}

test "SoftBlock and FM ask are deny" {
    const std = @import("std");
    try std.testing.expectEqual(Outcome.deny, codingHostAskOutcome(true, .soft_block, false));
    try std.testing.expectEqual(Outcome.deny, codingHostAskOutcome(true, .fm, false));
    try std.testing.expectEqual(Outcome.deny, codingHostAskOutcome(true, .soft_block, true));
    try std.testing.expectEqual(Outcome.deny, codingHostAskOutcome(true, .fm, true));
}

test "non-ask decisions are unchanged" {
    const std = @import("std");
    try std.testing.expectEqual(Outcome.unchanged, codingHostAskOutcome(false, .leftover, false));
    try std.testing.expectEqual(Outcome.unchanged, codingHostAskOutcome(false, .leftover, true));
    try std.testing.expectEqual(Outcome.unchanged, codingHostAskOutcome(false, .soft_block, false));
}

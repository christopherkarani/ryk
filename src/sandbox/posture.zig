//! Session vs doctor posture vocabulary for OS filesystem sandbox.
//!
//! Doctor reports capability availability only.
//! Live sessions may report active only after profile compile + apply +
//! child attach handshake + profile hash recording (S-GLO-01).

const std = @import("std");

/// Live session posture after launch attempt.
pub const SessionPosture = enum {
    active,
    /// Parent prepared child-apply materials; session is not active until
    /// status-pipe promote. Distinct from grade-drop `unavailable`.
    prepared,
    unavailable,
    failed,
    disabled,

    pub fn toString(self: SessionPosture) []const u8 {
        return @tagName(self);
    }

    /// Only active may map to OS-enforced grade for filesystem scope.
    pub fn isOsEnforced(self: SessionPosture) bool {
        return self == .active;
    }
};

pub const OsSandboxMode = enum {
    auto,
    on,
    off,

    pub fn parse(value: []const u8) ?OsSandboxMode {
        if (std.mem.eql(u8, value, "auto")) return .auto;
        if (std.mem.eql(u8, value, "on")) return .on;
        if (std.mem.eql(u8, value, "off")) return .off;
        return null;
    }

    pub fn toString(self: OsSandboxMode) []const u8 {
        return @tagName(self);
    }
};

/// macOS Seatbelt residual grade (orthogonal to `--os-sandbox` attach mode).
///
/// - `compatible`: historical broad residuals (`process*`, broad `/private/var`, route-force
///   keeps inbound/bind).
/// - `hardened` (default): narrowed process ops + bootstrap FS; same network residual model.
/// - `strict`: hardened FS/process plus no listeners under route-force; no broad `network*`
///   when route forcing is absent (deny-default). Still not process/XPC isolation.
pub const SeatbeltProfileGrade = enum {
    compatible,
    hardened,
    strict,

    /// Production default after residual harden work.
    pub const default_grade: SeatbeltProfileGrade = .hardened;

    pub fn parse(value: []const u8) ?SeatbeltProfileGrade {
        if (std.mem.eql(u8, value, "compatible")) return .compatible;
        if (std.mem.eql(u8, value, "hardened")) return .hardened;
        if (std.mem.eql(u8, value, "strict")) return .strict;
        return null;
    }

    pub fn toString(self: SeatbeltProfileGrade) []const u8 {
        return @tagName(self);
    }
};

/// Mechanism names are for verbose diagnostics only (S-GLO-03).
pub const BackendMechanism = enum {
    none,
    landlock,
    seatbelt,

    pub fn toString(self: BackendMechanism) []const u8 {
        return @tagName(self);
    }

    pub fn verboseName(self: BackendMechanism) []const u8 {
        return switch (self) {
            .none => "none",
            .landlock => "Landlock",
            .seatbelt => "Seatbelt",
        };
    }
};

pub const AttachReceipt = struct {
    posture: SessionPosture,
    mechanism: BackendMechanism = .none,
    /// Owned hex hash when active (fixed storage — avoids UAF on returned receipts).
    profile_hash_hex: ?[64]u8 = null,
    fs_scope: []const u8 = "none",
    network_scope: []const u8 = "unrestricted",
    reason_code: ?[]const u8 = null,
    /// Set only for active macOS Seatbelt sessions (residual grade honesty for banner/audit).
    seatbelt_profile: ?SeatbeltProfileGrade = null,

    pub fn isActive(self: AttachReceipt) bool {
        return self.posture == .active and self.profile_hash_hex != null and self.mechanism != .none;
    }

    /// View the owned hash as a slice (valid for lifetime of this receipt value).
    pub fn profileHashSlice(self: *const AttachReceipt) ?[]const u8 {
        if (self.profile_hash_hex) |*h| return h[0..];
        return null;
    }
};

/// True when `s` is exactly 64 ASCII hex digits (`0-9`, `a-f`, `A-F`).
/// Production profile hashes are lowercase SHA-256 hex; uppercase is accepted for callers.
pub fn isValidProfileHashHex(s: []const u8) bool {
    if (s.len != 64) return false;
    for (s) |c| {
        if (!std.ascii.isHex(c)) return false;
    }
    return true;
}

/// Build an active receipt only when all attach conditions hold.
///
/// `profile_hash_hex` must be exactly 64 hex digits (SHA-256 hex of the compiled
/// profile). Empty, short, long, or non-hex inputs are rejected with
/// `error.InvalidProfileHash` — never zero-padded into a fake full hash.
pub fn activeReceipt(
    mechanism: BackendMechanism,
    profile_hash_hex: []const u8,
    fs_scope: []const u8,
) error{InvalidProfileHash}!AttachReceipt {
    return activeReceiptWithNetwork(mechanism, profile_hash_hex, fs_scope, "unrestricted");
}

pub fn activeReceiptWithNetwork(
    mechanism: BackendMechanism,
    profile_hash_hex: []const u8,
    fs_scope: []const u8,
    network_scope: []const u8,
) error{InvalidProfileHash}!AttachReceipt {
    return activeReceiptWithNetworkAndGrade(mechanism, profile_hash_hex, fs_scope, network_scope, null);
}

/// Active receipt with optional Seatbelt residual grade (macOS only; leave null on Landlock).
pub fn activeReceiptWithNetworkAndGrade(
    mechanism: BackendMechanism,
    profile_hash_hex: []const u8,
    fs_scope: []const u8,
    network_scope: []const u8,
    seatbelt_profile: ?SeatbeltProfileGrade,
) error{InvalidProfileHash}!AttachReceipt {
    if (!isValidProfileHashHex(profile_hash_hex)) return error.InvalidProfileHash;
    // Copy into owned fixed storage (N1: no borrow of caller-owned / ephemeral memory).
    var hex: [64]u8 = undefined;
    @memcpy(&hex, profile_hash_hex[0..64]);
    return .{
        .posture = .active,
        .mechanism = mechanism,
        .profile_hash_hex = hex,
        .fs_scope = fs_scope,
        .network_scope = network_scope,
        .reason_code = null,
        .seatbelt_profile = seatbelt_profile,
    };
}

pub fn disabledReceipt() AttachReceipt {
    return .{
        .posture = .disabled,
        .mechanism = .none,
        .profile_hash_hex = null,
        .fs_scope = "none",
        .reason_code = "os_sandbox_off",
    };
}

pub fn unavailableReceipt(reason_code: []const u8) AttachReceipt {
    return .{
        .posture = .unavailable,
        .mechanism = .none,
        .profile_hash_hex = null,
        .fs_scope = "none",
        .reason_code = reason_code,
    };
}

/// Parent prepared child-apply materials; not session-active (S-GLO-01).
pub fn preparedReceipt(mechanism: BackendMechanism, reason_code: []const u8) AttachReceipt {
    return .{
        .posture = .prepared,
        .mechanism = mechanism,
        .profile_hash_hex = null,
        .fs_scope = "none",
        .reason_code = reason_code,
    };
}

pub fn failedReceipt(reason_code: []const u8) AttachReceipt {
    return .{
        .posture = .failed,
        .mechanism = .none,
        .profile_hash_hex = null,
        .fs_scope = "none",
        .reason_code = reason_code,
    };
}

/// Buffer size for `formatSessionBanner` / session-start OS line in `run.zig`.
///
/// Must fit the longest production active banner: fixed template (~151) +
/// landlock fs_scope with platform tmp (~95) + route-forced network_scope (~96)
/// + optional seatbelt_profile token (~28) ≈ 370. 320 was too small (route-forced
/// default no-tmp is already 325) and caused silent fallback to bare
/// `OS sandbox: active`.
pub const session_banner_buf_len: usize = 512;

/// Compact audit reason buffer for `sandbox_posture` events (hash + scopes + grade).
pub const audit_reason_buf_len: usize = 512;

/// Default user-facing banner language (mechanism-neutral).
///
/// Active path runs the launch allowlist on child env before attach:
/// secret/provider keys are stripped; SSH_AUTH_SOCK is stripped by default;
/// TLS CA bundle vars may remain — do not imply total credential wipe.
///
/// Unavailable/failed grade-drop keeps denylist-only scrub (injection keys
/// removed; provider credentials retained) — surface that honesty explicitly.
///
/// When `seatbelt_profile` is set (active macOS Seatbelt only), emits the stable
/// machine-readable token `seatbelt_profile=<grade>` after network scope.
pub fn formatSessionBanner(buf: []u8, receipt: AttachReceipt) ![]const u8 {
    return switch (receipt.posture) {
        .active => if (receipt.seatbelt_profile) |grade|
            try std.fmt.bufPrint(
                buf,
                "OS sandbox: active (filesystem: {s}; network: {s}; seatbelt_profile={s}; credentials: launch-allowlist (secrets stripped; agent sockets/certs may remain); tools: wrapper-mediated)",
                .{ receipt.fs_scope, receipt.network_scope, grade.toString() },
            )
        else
            try std.fmt.bufPrint(
                buf,
                "OS sandbox: active (filesystem: {s}; network: {s}; credentials: launch-allowlist (secrets stripped; agent sockets/certs may remain); tools: wrapper-mediated)",
                .{ receipt.fs_scope, receipt.network_scope },
            ),
        // Prepared materials must never read as active or as a grade-drop failure.
        .prepared => if (receipt.reason_code) |reason|
            try std.fmt.bufPrint(buf, "OS sandbox: prepared ({s}; attach pending child apply)", .{reason})
        else
            try std.fmt.bufPrint(buf, "OS sandbox: prepared (attach pending child apply)", .{}),
        .unavailable => if (receipt.reason_code) |reason|
            try std.fmt.bufPrint(buf, "OS sandbox: unavailable ({s}; credentials retained)", .{reason})
        else
            try std.fmt.bufPrint(buf, "OS sandbox: unavailable (credentials retained)", .{}),
        .failed => if (receipt.reason_code) |reason|
            try std.fmt.bufPrint(buf, "OS sandbox: failed ({s}; credentials retained)", .{reason})
        else
            try std.fmt.bufPrint(buf, "OS sandbox: failed (credentials retained)", .{}),
        .disabled => try std.fmt.bufPrint(buf, "OS sandbox: disabled", .{}),
    };
}

/// Compact audit reason for `sandbox_posture` events (no SBPL / Landlock rule text).
/// When set, includes the same `seatbelt_profile=<grade>` token as the session banner.
pub fn formatAuditReason(buf: []u8, receipt: AttachReceipt) ![]const u8 {
    const posture_str = receipt.posture.toString();
    const fs_scope = receipt.fs_scope;
    if (receipt.profileHashSlice()) |hash| {
        if (receipt.seatbelt_profile) |grade| {
            return try std.fmt.bufPrint(
                buf,
                "posture={s}; profile_hash={s}; fs_scope={s}; network_scope={s}; seatbelt_profile={s}",
                .{ posture_str, hash, fs_scope, receipt.network_scope, grade.toString() },
            );
        }
        return try std.fmt.bufPrint(buf, "posture={s}; profile_hash={s}; fs_scope={s}; network_scope={s}", .{ posture_str, hash, fs_scope, receipt.network_scope });
    } else if (receipt.reason_code) |code| {
        return try std.fmt.bufPrint(buf, "posture={s}; fs_scope={s}; network_scope={s}; reason={s}", .{ posture_str, fs_scope, receipt.network_scope, code });
    } else {
        return try std.fmt.bufPrint(buf, "posture={s}; fs_scope={s}; network_scope={s}", .{ posture_str, fs_scope, receipt.network_scope });
    }
}

/// Test fixture: full 64-char lowercase hex (SHA-256 width). Not a real profile hash.
const test_hash_64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

test "active receipt requires mechanism and profile hash (S-GLO-01)" {
    const incomplete = AttachReceipt{
        .posture = .active,
        .mechanism = .none,
        .profile_hash_hex = null,
    };
    try std.testing.expect(!incomplete.isActive());

    const complete = try activeReceipt(.landlock, test_hash_64, "workspace RW, system RO, platform tmp RW, no home");
    try std.testing.expect(complete.isActive());
    try std.testing.expect(complete.posture.isOsEnforced());
    try std.testing.expectEqualStrings(test_hash_64, complete.profileHashSlice().?);
}

test "activeReceipt rejects empty, short, long, and non-hex profile hashes" {
    try std.testing.expectError(error.InvalidProfileHash, activeReceipt(.landlock, "", "workspace RW"));
    try std.testing.expectError(error.InvalidProfileHash, activeReceipt(.landlock, "abcd", "workspace RW"));
    try std.testing.expectError(error.InvalidProfileHash, activeReceipt(.seatbelt, "abc123", "workspace RW"));
    try std.testing.expectError(error.InvalidProfileHash, activeReceipt(.landlock, "deadbeef", "workspace RW"));
    // 63 hex digits
    try std.testing.expectError(error.InvalidProfileHash, activeReceipt(.landlock, test_hash_64[0..63], "workspace RW"));
    // 65 hex digits
    try std.testing.expectError(error.InvalidProfileHash, activeReceipt(.landlock, test_hash_64 ++ "0", "workspace RW"));
    // non-hex in an otherwise 64-length string
    const bad_hex = "g123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    try std.testing.expectEqual(@as(usize, 64), bad_hex.len);
    try std.testing.expectError(error.InvalidProfileHash, activeReceipt(.landlock, bad_hex, "workspace RW"));
}

test "activeReceipt accepts full 64 hex (lower and upper)" {
    const lower = try activeReceipt(.landlock, test_hash_64, "workspace child RW, root RO, system RO, platform tmp RW, no home");
    try std.testing.expect(lower.isActive());
    try std.testing.expectEqual(BackendMechanism.landlock, lower.mechanism);
    try std.testing.expectEqualStrings(test_hash_64, lower.profileHashSlice().?);

    const upper_src = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789";
    try std.testing.expectEqual(@as(usize, 64), upper_src.len);
    const upper = try activeReceipt(.seatbelt, upper_src, "workspace RW, system RO, platform tmp RW, no home");
    try std.testing.expect(upper.isActive());
    try std.testing.expectEqualStrings(upper_src, upper.profileHashSlice().?);
}

test "disabled and unavailable receipts are not OS-enforced" {
    try std.testing.expect(!disabledReceipt().isActive());
    try std.testing.expect(!unavailableReceipt("backend_missing").isActive());
    try std.testing.expect(!failedReceipt("apply_failed").isActive());
}

test "os-sandbox mode parse" {
    try std.testing.expectEqual(OsSandboxMode.auto, OsSandboxMode.parse("auto").?);
    try std.testing.expectEqual(OsSandboxMode.on, OsSandboxMode.parse("on").?);
    try std.testing.expectEqual(OsSandboxMode.off, OsSandboxMode.parse("off").?);
    try std.testing.expect(OsSandboxMode.parse("seatbelt") == null);

    try std.testing.expectEqual(SeatbeltProfileGrade.compatible, SeatbeltProfileGrade.parse("compatible").?);
    try std.testing.expectEqual(SeatbeltProfileGrade.hardened, SeatbeltProfileGrade.parse("hardened").?);
    try std.testing.expectEqual(SeatbeltProfileGrade.strict, SeatbeltProfileGrade.parse("strict").?);
    try std.testing.expect(SeatbeltProfileGrade.parse("default") == null);
    try std.testing.expectEqual(SeatbeltProfileGrade.hardened, SeatbeltProfileGrade.default_grade);
}

test "session banner is mechanism-neutral (S-GLO-03)" {
    var buf: [320]u8 = undefined;
    const active = try activeReceipt(.seatbelt, test_hash_64, "workspace RW, system RO, platform tmp RW, no home");
    const line = try formatSessionBanner(&buf, active);
    try std.testing.expect(std.mem.indexOf(u8, line, "OS sandbox: active") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "platform tmp RW") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "Seatbelt") == null);
    try std.testing.expect(std.mem.indexOf(u8, line, "Landlock") == null);
    try std.testing.expect(std.mem.indexOf(u8, line, "network: unrestricted") != null);
    // Secrets stripped, but intentional keepers may remain (not total wipe).
    try std.testing.expect(std.mem.indexOf(u8, line, "launch-allowlist") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "secrets stripped") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "agent sockets/certs may remain") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "as configured") == null);
}

test "grade-drop unavailable/failed banners mention credentials retained" {
    var buf: [256]u8 = undefined;
    const unavail = unavailableReceipt("backend_missing");
    const u_line = try formatSessionBanner(&buf, unavail);
    try std.testing.expect(std.mem.indexOf(u8, u_line, "OS sandbox: unavailable") != null);
    try std.testing.expect(std.mem.indexOf(u8, u_line, "backend_missing") != null);
    try std.testing.expect(std.mem.indexOf(u8, u_line, "credentials retained") != null);

    const failed = failedReceipt("apply_failed");
    const f_line = try formatSessionBanner(&buf, failed);
    try std.testing.expect(std.mem.indexOf(u8, f_line, "OS sandbox: failed") != null);
    try std.testing.expect(std.mem.indexOf(u8, f_line, "apply_failed") != null);
    try std.testing.expect(std.mem.indexOf(u8, f_line, "credentials retained") != null);

    // No reason_code still surfaces credential honesty.
    const bare = AttachReceipt{ .posture = .unavailable };
    const bare_line = try formatSessionBanner(&buf, bare);
    try std.testing.expect(std.mem.indexOf(u8, bare_line, "credentials retained") != null);
}

test "landlock fs_scope surfaces root RO create-at-root contract" {
    var buf: [320]u8 = undefined;
    // Production Landlock receipt string (apply.activateAfterHandshake).
    const active = try activeReceipt(.landlock, test_hash_64, "workspace child RW, root RO, system RO, platform tmp RW, no home");
    const line = try formatSessionBanner(&buf, active);
    try std.testing.expect(std.mem.indexOf(u8, line, "workspace child RW") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "root RO") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "platform tmp RW") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "Landlock") == null); // still mechanism-neutral
}

test "activeReceiptWithNetwork + banner surfaces route-forced network_scope" {
    // Production Landlock route-forced string (apply.activateAfterHandshake M-1).
    const landlock_scope = "proxy route-forced (TCP connect port-scoped to proxy port; not address-scoped; UDP unrestricted)";
    const landlock = try activeReceiptWithNetwork(
        .landlock,
        test_hash_64,
        "workspace child RW, root RO, system RO, no home",
        landlock_scope,
    );
    try std.testing.expect(landlock.isActive());
    try std.testing.expectEqualStrings(landlock_scope, landlock.network_scope);

    var buf: [session_banner_buf_len]u8 = undefined;
    const landlock_line = try formatSessionBanner(&buf, landlock);
    try std.testing.expect(std.mem.indexOf(u8, landlock_line, "network: proxy route-forced") != null);
    try std.testing.expect(std.mem.indexOf(u8, landlock_line, "port-scoped") != null);
    try std.testing.expect(std.mem.indexOf(u8, landlock_line, "UDP unrestricted") != null);
    try std.testing.expect(std.mem.indexOf(u8, landlock_line, "Landlock") == null); // mechanism-neutral banner

    // Seatbelt: outbound loopback proxy only; inbound/bind residual is explicit.
    const seatbelt_scope = "proxy route-forced (outbound TCP to ryk loopback proxy only; inbound/bind unrestricted; UDP/QUIC unrestricted)";
    const seatbelt = try activeReceiptWithNetwork(
        .seatbelt,
        test_hash_64,
        "workspace RW, system RO, no home",
        seatbelt_scope,
    );
    try std.testing.expectEqualStrings(seatbelt_scope, seatbelt.network_scope);
    const seatbelt_line = try formatSessionBanner(&buf, seatbelt);
    try std.testing.expect(std.mem.indexOf(u8, seatbelt_line, "loopback proxy only") != null);
    try std.testing.expect(std.mem.indexOf(u8, seatbelt_line, "inbound/bind unrestricted") != null);
    try std.testing.expect(std.mem.indexOf(u8, seatbelt_line, "UDP/QUIC unrestricted") != null);
    try std.testing.expect(std.mem.indexOf(u8, seatbelt_line, "Seatbelt") == null);
}

test "session_banner_buf_len fits production landlock route-forced scopes" {
    // Regression: 320 overflowed (325 default no-tmp, 342 with platform tmp) and
    // hid port-scoped / UDP residual behind bare "OS sandbox: active".
    const landlock_scope = "proxy route-forced (TCP connect port-scoped to proxy port; not address-scoped; UDP unrestricted)";
    const fs_with_tmp = "workspace child RW, root RO, system RO, platform tmp RW, no home, control write-deny (readable)";
    const receipt = try activeReceiptWithNetwork(.landlock, test_hash_64, fs_with_tmp, landlock_scope);

    var buf: [session_banner_buf_len]u8 = undefined;
    const line = try formatSessionBanner(&buf, receipt);
    try std.testing.expect(line.len > 320);
    try std.testing.expect(std.mem.indexOf(u8, line, "port-scoped") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "UDP unrestricted") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "platform tmp RW") != null);

    // The previous production size must fail for this receipt (guards constant drift).
    var tiny: [320]u8 = undefined;
    try std.testing.expectError(error.NoSpaceLeft, formatSessionBanner(&tiny, receipt));
}

test "active seatbelt banner and audit include seatbelt_profile grade token" {
    var banner_buf: [session_banner_buf_len]u8 = undefined;
    var audit_buf: [audit_reason_buf_len]u8 = undefined;

    const grades = [_]SeatbeltProfileGrade{ .compatible, .hardened, .strict };
    for (grades) |grade| {
        const receipt = try activeReceiptWithNetworkAndGrade(
            .seatbelt,
            test_hash_64,
            "workspace RW, system RO, no home",
            "unrestricted",
            grade,
        );
        try std.testing.expectEqual(grade, receipt.seatbelt_profile.?);

        const banner = try formatSessionBanner(&banner_buf, receipt);
        var token_buf: [48]u8 = undefined;
        const token = try std.fmt.bufPrint(&token_buf, "seatbelt_profile={s}", .{grade.toString()});
        try std.testing.expect(std.mem.indexOf(u8, banner, token) != null);
        try std.testing.expect(std.mem.indexOf(u8, banner, "OS sandbox: active") != null);
        try std.testing.expect(std.mem.indexOf(u8, banner, "Seatbelt") == null);

        const audit = try formatAuditReason(&audit_buf, receipt);
        try std.testing.expect(std.mem.indexOf(u8, audit, token) != null);
        try std.testing.expect(std.mem.indexOf(u8, audit, "profile_hash=") != null);
    }
}

test "landlock active banner and audit omit seatbelt_profile token" {
    var banner_buf: [session_banner_buf_len]u8 = undefined;
    var audit_buf: [audit_reason_buf_len]u8 = undefined;
    const receipt = try activeReceiptWithNetwork(
        .landlock,
        test_hash_64,
        "workspace child RW, root RO, system RO, no home",
        "unrestricted",
    );
    try std.testing.expect(receipt.seatbelt_profile == null);

    const banner = try formatSessionBanner(&banner_buf, receipt);
    try std.testing.expect(std.mem.indexOf(u8, banner, "seatbelt_profile=") == null);

    const audit = try formatAuditReason(&audit_buf, receipt);
    try std.testing.expect(std.mem.indexOf(u8, audit, "seatbelt_profile=") == null);
}

test "session_banner_buf_len fits seatbelt grade token with route-forced network" {
    const seatbelt_scope = "proxy route-forced (outbound TCP to ryk loopback proxy only; inbound/bind unrestricted; UDP/QUIC unrestricted)";
    const fs_scope = "workspace RW, system RO, platform tmp RW, no home, control write-deny (readable), mach-lookup residual";
    const receipt = try activeReceiptWithNetworkAndGrade(
        .seatbelt,
        test_hash_64,
        fs_scope,
        seatbelt_scope,
        .hardened,
    );
    var buf: [session_banner_buf_len]u8 = undefined;
    const line = try formatSessionBanner(&buf, receipt);
    try std.testing.expect(std.mem.indexOf(u8, line, "seatbelt_profile=hardened") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "loopback proxy only") != null);
}

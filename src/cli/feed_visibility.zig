const std = @import("std");

const core = @import("ryk_core").core;
const core_api = @import("ryk_core").api;
const daemon = @import("daemon.zig");
pub const decision_source_rust = "rust-daemon";
pub const decision_source_zig = "zig-native";
pub const event_source_hook = "hook";
pub const event_source_run = "run";
pub const target_summary_shell = "shell command (redacted)";

pub const GuiDaemonHealth = struct {
    status: []const u8,
    detail: []const u8,

    pub fn deinit(self: *GuiDaemonHealth, allocator: std.mem.Allocator) void {
        allocator.free(self.status);
        allocator.free(self.detail);
        self.* = undefined;
    }
};

pub const RustShellFeedRecord = struct {
    timestamp: []const u8,
    workspace_root: []const u8,
    event_type: []const u8,
    decision: []const u8,
    decision_source: []const u8,
    event_source: []const u8,
    host: ?[]const u8,
    daemon_status: []const u8,
    pack_id: ?[]const u8,
    rule: ?[]const u8,
    severity: ?[]const u8,
    reason: []const u8,
    remediation: ?[]const u8,
    target_summary: []const u8,
    session_id: ?[]const u8,
    verified: bool,

    pub fn deinit(self: *RustShellFeedRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.timestamp);
        allocator.free(self.workspace_root);
        allocator.free(self.event_type);
        allocator.free(self.decision);
        allocator.free(self.decision_source);
        allocator.free(self.event_source);
        if (self.host) |host| allocator.free(host);
        allocator.free(self.daemon_status);
        if (self.pack_id) |pack_id| allocator.free(pack_id);
        if (self.rule) |rule| allocator.free(rule);
        if (self.severity) |severity| allocator.free(severity);
        allocator.free(self.reason);
        if (self.remediation) |remediation| allocator.free(remediation);
        allocator.free(self.target_summary);
        if (self.session_id) |session_id| allocator.free(session_id);
        self.* = undefined;
    }
};

fn daemonUnavailableReason(err: daemon.DaemonError) []const u8 {
    return daemon.errors.shellUnavailableReason(err);
}

fn buildDaemonDenyReason(
    allocator: std.mem.Allocator,
    result: std.json.Value,
) !struct {
    reason: []const u8,
    rule: ?[]const u8,
} {
    const rule = try ruleIdFromDaemonResult(allocator, result);
    errdefer if (rule) |rule_name| allocator.free(rule_name);

    const reason = if (rule) |rule_name|
        try std.fmt.allocPrint(allocator, "blocked by ryk rule: {s}", .{rule_name})
    else
        try allocator.dupe(u8, "command denied by ryk policy");

    return .{ .reason = reason, .rule = rule };
}

pub fn probeGuiDaemonHealth(allocator: std.mem.Allocator) !GuiDaemonHealth {
    if (daemon.checkCompatibility(allocator)) |_| {
        return .{
            .status = try allocator.dupe(u8, "healthy"),
            .detail = try allocator.dupe(u8, "Daemon handshake succeeded with a compatible protocol."),
        };
    } else |err| {
        const status: []const u8 = switch (err) {
            error.ProtocolMismatch => "incompatible",
            error.MissingHandshake, error.HandshakeMalformed, error.DaemonProtocolError, error.ResponseParseFailed => "degraded",
            else => "unavailable",
        };
        const detail = try std.fmt.allocPrint(allocator, "{s}", .{daemonUnavailableReason(err)});
        return .{
            .status = try allocator.dupe(u8, status),
            .detail = detail,
        };
    }
}

pub fn guiDaemonStatusFromDoctorStatus(doctor_status: []const u8) []const u8 {
    if (std.mem.eql(u8, doctor_status, "compatible")) return "healthy";
    return doctor_status;
}

pub fn normalizeSeverity(severity: ?[]const u8) ?[]const u8 {
    const value = severity orelse return null;
    if (value.len == 0) return null;
    return value;
}

pub fn packIdFromDaemonResult(result: std.json.Value) ?[]const u8 {
    return daemon.responseStringField(result, "pack_id");
}

pub fn severityFromDaemonResult(result: std.json.Value) ?[]const u8 {
    return normalizeSeverity(daemon.responseStringField(result, "severity"));
}

pub fn remediationFromDaemonResult(allocator: std.mem.Allocator, result: std.json.Value) !?[]const u8 {
    // Daemon SuggestionPayload shape: { command, description, platform }.
    // Prefer description; fall back to command; then explanation.
    if (daemon.responseArrayField(result, "suggestions")) |items| {
        if (items.len > 0) {
            const first = items[0];
            if (first == .object) {
                // Legacy/alternate field used by some fixtures.
                if (first.object.get("text")) |text_value| {
                    if (text_value == .string) {
                        return try sanitizeRemediationText(allocator, text_value.string);
                    }
                }
                const description = switch (first.object.get("description") orelse .null) {
                    .string => |s| s,
                    else => null,
                };
                const command = switch (first.object.get("command") orelse .null) {
                    .string => |s| s,
                    else => null,
                };
                if (description) |desc| {
                    if (command) |cmd| {
                        if (desc.len > 0 and cmd.len > 0) {
                            const combined = try std.fmt.allocPrint(allocator, "Consider using '{s}': {s}", .{ cmd, desc });
                            errdefer allocator.free(combined);
                            const sanitized = try sanitizeRemediationText(allocator, combined);
                            allocator.free(combined);
                            return sanitized;
                        }
                    }
                    if (desc.len > 0) return try sanitizeRemediationText(allocator, desc);
                }
                if (command) |cmd| {
                    if (cmd.len > 0) {
                        const tip = try std.fmt.allocPrint(allocator, "Consider using '{s}'", .{cmd});
                        errdefer allocator.free(tip);
                        const sanitized = try sanitizeRemediationText(allocator, tip);
                        allocator.free(tip);
                        return sanitized;
                    }
                }
            }
        }
    }
    if (daemon.responseStringField(result, "explanation")) |explanation| {
        return try sanitizeRemediationText(allocator, explanation);
    }
    return null;
}

/// Build a `pack_id:pattern_name` rule id when both fields are present.
pub fn ruleIdFromDaemonResult(allocator: std.mem.Allocator, result: std.json.Value) !?[]const u8 {
    if (daemon.responseStatus(result) != .deny) return null;
    const pack_id = daemon.responseStringField(result, "pack_id");
    const pattern_name = daemon.responseStringField(result, "pattern_name");
    if (pack_id) |pack| {
        if (pattern_name) |pattern| return try std.fmt.allocPrint(allocator, "{s}:{s}", .{ pack, pattern });
        return try allocator.dupe(u8, pack);
    }
    if (pattern_name) |pattern| return try allocator.dupe(u8, pattern);
    return null;
}

/// Format human-facing next-step lines after a shell deny (no trailing newline).
/// `command_display` must already be redacted for presentation.
///
/// Day-1 recovery is the interactive Once/Always/Never prompt (not rule ids).
/// Progressive next-steps for a deny (ISS-DENY-01):
/// 1. Understand (explain) → 2. Temporary (allow-once) → 3. Permanent advanced (allowlist).
/// Tip, when present, is a separate advisory line above the numbered What-now block.
/// Order is product law: explain first; allow-once if the prompt is gone; rule-id
/// allowlist last (not the day-1 primary path).
/// POSIX single-quote so paste into a shell cannot expand `$()`, backticks, or `"`.
pub fn shellSingleQuoteAlloc(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.append(allocator, '\'');
    for (value) |byte| {
        if (byte == '\'') {
            try out.appendSlice(allocator, "'\"'\"'");
        } else {
            try out.append(allocator, byte);
        }
    }
    try out.append(allocator, '\'');
    return out.toOwnedSlice(allocator);
}

pub fn formatDenyNextSteps(
    allocator: std.mem.Allocator,
    command_display: []const u8,
    rule_id: ?[]const u8,
    tip: ?[]const u8,
) ![]const u8 {
    return formatDenyNextStepsWithCode(allocator, command_display, rule_id, tip, null);
}

pub fn formatDenyNextStepsWithCode(
    allocator: std.mem.Allocator,
    command_display: []const u8,
    rule_id: ?[]const u8,
    tip: ?[]const u8,
    allow_once_code: ?[]const u8,
) ![]const u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);

    if (tip) |t| {
        if (t.len > 0) {
            const tip_line = try std.fmt.allocPrint(allocator, "Tip: {s}\n", .{t});
            defer allocator.free(tip_line);
            try list.appendSlice(allocator, tip_line);
        }
    }
    // Progressive hierarchy labels (what now). Quote for paste safety so
    // operators pasting into a shell do not expand $(…) / backticks (F23).
    try list.appendSlice(allocator, "What now:\n");
    {
        const quoted = try shellSingleQuoteAlloc(allocator, command_display);
        defer allocator.free(quoted);
        const line = try std.fmt.allocPrint(allocator, "  1. Understand\n     ryk explain {s}\n", .{quoted});
        defer allocator.free(line);
        try list.appendSlice(allocator, line);
    }
    if (allow_once_code) |code| {
        if (code.len > 0) {
            const line = try std.fmt.allocPrint(
                allocator,
                "  2. Temporary exception (if approval prompt is gone)\n     ryk allow-once {s}\n",
                .{code},
            );
            defer allocator.free(line);
            try list.appendSlice(allocator, line);
        }
    } else {
        try list.appendSlice(allocator, "  2. Temporary exception (if approval prompt is gone)\n     ryk allow-once <code>\n");
    }
    // Advanced permanent path — keep available, de-emphasized vs temporary.
    if (rule_id) |rid| {
        const line = try std.fmt.allocPrint(
            allocator,
            "  3. Permanent exception (advanced)\n     ryk allowlist add {s} -r \"reason\"\n",
            .{rid},
        );
        defer allocator.free(line);
        try list.appendSlice(allocator, line);
    } else {
        try list.appendSlice(allocator, "  3. Permanent exception (advanced)\n     ryk allowlist list\n");
    }
    return try list.toOwnedSlice(allocator);
}

pub fn safeReasonFromDaemonResult(allocator: std.mem.Allocator, result: std.json.Value) ![]const u8 {
    return switch (daemon.responseStatus(result)) {
        .allow => try allocator.dupe(u8, daemon.responseReason(result) orelse "command allowed by ryk policy"),
        .deny => blk: {
            const deny = try buildDaemonDenyReason(allocator, result);
            defer if (deny.rule) |rule| allocator.free(rule);
            break :blk deny.reason;
        },
        else => try allocator.dupe(u8, daemon.responseErrorMessage(result) orelse "daemon evaluation error"),
    };
}

pub fn safeReasonFromUnavailable(allocator: std.mem.Allocator, err: daemon.DaemonError) ![]const u8 {
    return try allocator.dupe(u8, daemonUnavailableReason(err));
}

pub fn decisionResultTag(result: std.json.Value) []const u8 {
    return switch (daemon.responseStatus(result)) {
        .allow => "allow",
        .deny => "deny",
        .error_status => "error",
        else => "error",
    };
}

pub fn eventTypeForDecision(decision: []const u8) []const u8 {
    if (std.mem.eql(u8, decision, "allow") or std.mem.eql(u8, decision, "observe")) return "command_allowed";
    return "command_denied";
}

pub fn hookEventTypeForDecisionTag(decision_tag: []const u8) []const u8 {
    if (std.mem.eql(u8, decision_tag, "allow") or std.mem.eql(u8, decision_tag, "observe")) return "command_allowed";
    return "command_denied";
}

pub fn buildFeedRecordFromHookDecision(
    allocator: std.mem.Allocator,
    io: std.Io,
    workspace_root: []const u8,
    host: []const u8,
    daemon_status: []const u8,
    decision_tag: []const u8,
    reason: []const u8,
    rule: ?[]const u8,
    severity: ?[]const u8,
    remediation: ?[]const u8,
    pack_id: ?[]const u8,
    session_id: ?[]const u8,
) !RustShellFeedRecord {
    const safe_reason = try core_api.redactAlloc(allocator, reason);
    errdefer allocator.free(safe_reason);

    var timestamp_buf: [32]u8 = undefined;
    const timestamp = try core.time.Timestamp.now(io).formatIso(&timestamp_buf);

    return .{
        .timestamp = try allocator.dupe(u8, timestamp),
        .workspace_root = try allocator.dupe(u8, workspace_root),
        .event_type = try allocator.dupe(u8, hookEventTypeForDecisionTag(decision_tag)),
        .decision = try allocator.dupe(u8, decision_tag),
        // Shell decisions are owned by in-process Zig shell_engine (not rust-daemon).
        .decision_source = try allocator.dupe(u8, decision_source_zig),
        .event_source = try allocator.dupe(u8, event_source_hook),
        .host = try allocator.dupe(u8, host),
        .daemon_status = try allocator.dupe(u8, daemon_status),
        .pack_id = if (pack_id) |pack| try allocator.dupe(u8, pack) else null,
        .rule = if (rule) |rule_id| try allocator.dupe(u8, rule_id) else null,
        .severity = if (severity) |sev| try allocator.dupe(u8, sev) else null,
        .reason = safe_reason,
        .remediation = if (remediation) |text| blk: {
            break :blk try sanitizeRemediationText(allocator, text);
        } else null,
        .target_summary = try allocator.dupe(u8, target_summary_shell),
        .session_id = if (session_id) |sid| try allocator.dupe(u8, sid) else null,
        .verified = false,
    };
}

pub fn metadataFromDaemonResult(
    allocator: std.mem.Allocator,
    event_source: []const u8,
    host: ?[]const u8,
    daemon_status: []const u8,
    result: std.json.Value,
) !core.event.EventMetadata {
    const pack_id = packIdFromDaemonResult(result);
    const severity = severityFromDaemonResult(result);
    const remediation = try remediationFromDaemonResult(allocator, result);
    errdefer if (remediation) |text| allocator.free(text);

    return .{
        .decision_source = try allocator.dupe(u8, decision_source_zig),
        .event_source = try allocator.dupe(u8, event_source),
        .host = if (host) |host_name| try allocator.dupe(u8, host_name) else null,
        .daemon_status = try allocator.dupe(u8, daemon_status),
        .pack_id = if (pack_id) |pack| try allocator.dupe(u8, pack) else null,
        .severity = if (severity) |sev| try allocator.dupe(u8, sev) else null,
        .remediation = remediation,
    };
}

pub fn metadataForUnavailable(
    allocator: std.mem.Allocator,
    event_source: []const u8,
    host: ?[]const u8,
    err: daemon.DaemonError,
) !core.event.EventMetadata {
    const daemon_status: []const u8 = switch (err) {
        error.ProtocolMismatch => "incompatible",
        error.MissingHandshake, error.HandshakeMalformed, error.DaemonProtocolError, error.ResponseParseFailed => "degraded",
        else => "unavailable",
    };
    return .{
        .decision_source = try allocator.dupe(u8, decision_source_zig),
        .event_source = try allocator.dupe(u8, event_source),
        .host = if (host) |host_name| try allocator.dupe(u8, host_name) else null,
        .daemon_status = try allocator.dupe(u8, daemon_status),
    };
}

pub fn buildFeedRecordFromDaemon(
    allocator: std.mem.Allocator,
    io: std.Io,
    workspace_root: []const u8,
    event_source: []const u8,
    host: ?[]const u8,
    daemon_status: []const u8,
    result: std.json.Value,
    session_id: ?[]const u8,
    verified: bool,
) !RustShellFeedRecord {
    const decision = decisionResultTag(result);
    const reason = try safeReasonFromDaemonResult(allocator, result);
    errdefer allocator.free(reason);
    const remediation = try remediationFromDaemonResult(allocator, result);
    errdefer if (remediation) |text| allocator.free(text);
    const rule = try ruleIdFromDaemonResult(allocator, result);
    errdefer if (rule) |rule_id| allocator.free(rule_id);

    var timestamp_buf: [32]u8 = undefined;
    const timestamp = try core.time.Timestamp.now(io).formatIso(&timestamp_buf);

    return .{
        .timestamp = try allocator.dupe(u8, timestamp),
        .workspace_root = try allocator.dupe(u8, workspace_root),
        .event_type = try allocator.dupe(u8, eventTypeForDecision(decision)),
        .decision = try allocator.dupe(u8, decision),
        // In-process Zig shell_engine is the evaluate authority after cutover.
        .decision_source = try allocator.dupe(u8, decision_source_zig),
        .event_source = try allocator.dupe(u8, event_source),
        .host = if (host) |host_name| try allocator.dupe(u8, host_name) else null,
        .daemon_status = try allocator.dupe(u8, daemon_status),
        .pack_id = if (packIdFromDaemonResult(result)) |pack| try allocator.dupe(u8, pack) else null,
        .rule = rule,
        .severity = if (severityFromDaemonResult(result)) |sev| try allocator.dupe(u8, sev) else null,
        .reason = reason,
        .remediation = remediation,
        .target_summary = try allocator.dupe(u8, target_summary_shell),
        .session_id = if (session_id) |sid| try allocator.dupe(u8, sid) else null,
        .verified = verified,
    };
}

pub fn buildFeedRecordFromUnavailable(
    allocator: std.mem.Allocator,
    io: std.Io,
    workspace_root: []const u8,
    event_source: []const u8,
    host: ?[]const u8,
    err: daemon.DaemonError,
    session_id: ?[]const u8,
    verified: bool,
) !RustShellFeedRecord {
    const daemon_status: []const u8 = switch (err) {
        error.ProtocolMismatch => "incompatible",
        error.MissingHandshake, error.HandshakeMalformed, error.DaemonProtocolError, error.ResponseParseFailed => "degraded",
        else => "unavailable",
    };
    const reason = try safeReasonFromUnavailable(allocator, err);
    errdefer allocator.free(reason);

    var timestamp_buf: [32]u8 = undefined;
    const timestamp = try core.time.Timestamp.now(io).formatIso(&timestamp_buf);

    return .{
        .timestamp = try allocator.dupe(u8, timestamp),
        .workspace_root = try allocator.dupe(u8, workspace_root),
        .event_type = try allocator.dupe(u8, "command_denied"),
        .decision = try allocator.dupe(u8, "deny"),
        .decision_source = try allocator.dupe(u8, decision_source_zig),
        .event_source = try allocator.dupe(u8, event_source),
        .host = if (host) |host_name| try allocator.dupe(u8, host_name) else null,
        .daemon_status = try allocator.dupe(u8, daemon_status),
        .pack_id = null,
        .rule = null,
        .severity = null,
        .reason = reason,
        .remediation = null,
        .target_summary = try allocator.dupe(u8, target_summary_shell),
        .session_id = if (session_id) |sid| try allocator.dupe(u8, sid) else null,
        .verified = verified,
    };
}

pub fn buildFeedRecordFromHookActivity(
    allocator: std.mem.Allocator,
    io: std.Io,
    workspace_root: []const u8,
    event_source: []const u8,
    decision_source: []const u8,
    host: ?[]const u8,
    daemon_status: []const u8,
    event_type: []const u8,
    decision_tag: []const u8,
    reason: []const u8,
    target_summary: []const u8,
    session_id: ?[]const u8,
    verified: bool,
) !RustShellFeedRecord {
    var timestamp_buf: [32]u8 = undefined;
    const timestamp = try core.time.Timestamp.now(io).formatIso(&timestamp_buf);

    const safe_reason = try core_api.redactAlloc(allocator, reason);
    errdefer allocator.free(safe_reason);
    const safe_target = try core_api.redactAlloc(allocator, target_summary);
    errdefer allocator.free(safe_target);

    return .{
        .timestamp = try allocator.dupe(u8, timestamp),
        .workspace_root = try allocator.dupe(u8, workspace_root),
        .event_type = try allocator.dupe(u8, event_type),
        .decision = try allocator.dupe(u8, decision_tag),
        .decision_source = try allocator.dupe(u8, decision_source),
        .event_source = try allocator.dupe(u8, event_source),
        .host = if (host) |host_name| try allocator.dupe(u8, host_name) else null,
        .daemon_status = try allocator.dupe(u8, daemon_status),
        .pack_id = null,
        .rule = null,
        .severity = null,
        .reason = safe_reason,
        .remediation = null,
        .target_summary = safe_target,
        .session_id = if (session_id) |sid| try allocator.dupe(u8, sid) else null,
        .verified = verified,
    };
}

/// True when a feed row belongs on the blocked/attention surface.
///
/// Classification is **decision-based** (not host event-type string lists):
/// - `deny` / `block` / `error` — hard denial or evaluation failure
/// - `ask` — approval required (still needs human attention)
/// - `warn` — advisory only; tools may proceed; never counts as blocked
pub fn isBlockedFeedRecord(record: RustShellFeedRecord) bool {
    if (std.mem.eql(u8, record.decision, "deny")) return true;
    if (std.mem.eql(u8, record.decision, "block")) return true;
    if (std.mem.eql(u8, record.decision, "error")) return true;
    if (std.mem.eql(u8, record.decision, "ask")) return true;
    return false;
}

pub fn writeFeedRecordJson(writer: anytype, record: RustShellFeedRecord) !void {
    try writer.writeByte('{');
    try writeJsonField(writer, "timestamp", record.timestamp);
    try writer.writeByte(',');
    try writeJsonField(writer, "workspace_root", record.workspace_root);
    try writer.writeByte(',');
    try writeJsonField(writer, "event_type", record.event_type);
    try writer.writeByte(',');
    try writeJsonField(writer, "decision", record.decision);
    try writer.writeByte(',');
    try writeJsonField(writer, "decision_source", record.decision_source);
    try writer.writeByte(',');
    try writeJsonField(writer, "event_source", record.event_source);
    try writer.writeByte(',');
    try writeJsonFieldNullable(writer, "host", record.host);
    try writer.writeByte(',');
    try writeJsonField(writer, "daemon_status", record.daemon_status);
    try writer.writeByte(',');
    try writeJsonFieldNullable(writer, "pack_id", record.pack_id);
    try writer.writeByte(',');
    try writeJsonFieldNullable(writer, "rule", record.rule);
    try writer.writeByte(',');
    try writeJsonFieldNullable(writer, "severity", record.severity);
    try writer.writeByte(',');
    try writeJsonField(writer, "reason", record.reason);
    try writer.writeByte(',');
    try writeJsonFieldNullable(writer, "remediation", record.remediation);
    try writer.writeByte(',');
    try writeJsonField(writer, "target_summary", record.target_summary);
    try writer.writeByte(',');
    try writeJsonFieldNullable(writer, "session_id", record.session_id);
    try writer.writeAll(",\"verified\":");
    try writer.writeAll(if (record.verified) "true" else "false");
    try writer.writeByte('}');
}

fn writeJsonField(writer: anytype, field: []const u8, value: []const u8) !void {
    try writer.writeAll("\"");
    try writer.writeAll(field);
    try writer.writeAll("\":");
    var redacted_buf: [512]u8 = undefined;
    try core.util.writeJsonString(writer, core_api.redactStringBounded(value, &redacted_buf));
}

fn writeJsonFieldNullable(writer: anytype, field: []const u8, value: ?[]const u8) !void {
    try writer.writeAll("\"");
    try writer.writeAll(field);
    try writer.writeAll("\":");
    if (value) |text| {
        var redacted_buf: [512]u8 = undefined;
        try core.util.writeJsonString(writer, core_api.redactStringBounded(text, &redacted_buf));
    } else {
        try writer.writeAll("null");
    }
}

fn sanitizeRemediationText(allocator: std.mem.Allocator, text: []const u8) ![]const u8 {
    // Presentation boundary: use structured/encoded redaction, not the bounded classifier alone.
    return try core_api.redactAlloc(allocator, text);
}

test "rust visibility redacts fake secret from feed reason" {
    const allocator = std.testing.allocator;
    const raw = "blocked OPENAI_API_KEY=sk-fakeSyntheticOpenAIKey1234567890 in command";
    const redacted = try core_api.redactAlloc(allocator, raw);
    defer allocator.free(redacted);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "sk-fakeSyntheticOpenAIKey1234567890") == null);
}

test "sanitizeRemediationText redacts encoded secrets" {
    const allocator = std.testing.allocator;
    // base64("token=correct-horse-battery-staple")
    const encoded = "dG9rZW49Y29ycmVjdC1ob3JzZS1iYXR0ZXJ5LXN0YXBsZQ==";
    const redacted = try sanitizeRemediationText(allocator, encoded);
    defer allocator.free(redacted);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "correct") == null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, encoded) == null);
}

test "rust visibility maps doctor compatible status to healthy" {
    try std.testing.expectEqualStrings("healthy", guiDaemonStatusFromDoctorStatus("compatible"));
    try std.testing.expectEqualStrings("unavailable", guiDaemonStatusFromDoctorStatus("unavailable"));
}

test "remediationFromDaemonResult reads suggestion description and command" {
    const allocator = std.testing.allocator;
    var parsed = try std.json.parseFromSlice(
        std.json.Value,
        allocator,
        \\{"status":"Deny","reason":"blocked","pack_id":"core.git","pattern_name":"reset-hard","suggestions":[{"command":"git stash","description":"Save work first","platform":"any"}],"explanation":"fallback"}
    ,
        .{},
    );
    defer parsed.deinit();

    const remediation = try remediationFromDaemonResult(allocator, parsed.value);
    defer if (remediation) |text| allocator.free(text);
    try std.testing.expect(remediation != null);
    try std.testing.expect(std.mem.indexOf(u8, remediation.?, "git stash") != null);
    try std.testing.expect(std.mem.indexOf(u8, remediation.?, "Save work first") != null);
}

test "ruleIdFromDaemonResult joins pack and pattern" {
    const allocator = std.testing.allocator;
    var parsed = try std.json.parseFromSlice(
        std.json.Value,
        allocator,
        \\{"status":"Deny","reason":"blocked","pack_id":"core.git","pattern_name":"reset-hard"}
    ,
        .{},
    );
    defer parsed.deinit();
    const rule = try ruleIdFromDaemonResult(allocator, parsed.value);
    defer if (rule) |r| allocator.free(r);
    try std.testing.expectEqualStrings("core.git:reset-hard", rule.?);
}

test "daemon feed records retain composite rule ids" {
    var parsed = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        \\{"status":"Deny","reason":"blocked","pack_id":"core.git","pattern_name":"reset-hard"}
    ,
        .{},
    );
    defer parsed.deinit();
    var record = try buildFeedRecordFromDaemon(
        std.testing.allocator,
        std.testing.io,
        "/tmp/workspace",
        event_source_hook,
        "codex",
        "healthy",
        parsed.value,
        null,
        false,
    );
    defer record.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("core.git:reset-hard", record.rule.?);
}

test "formatDenyNextSteps includes explain allowlist and allow-once" {
    const allocator = std.testing.allocator;
    const footer = try formatDenyNextSteps(allocator, "git reset --hard", "core.git:reset-hard", "Consider using 'git stash'");
    defer allocator.free(footer);
    try std.testing.expect(std.mem.indexOf(u8, footer, "Tip: Consider using 'git stash'") != null);
    try std.testing.expect(std.mem.indexOf(u8, footer, "What now:") != null);
    try std.testing.expect(std.mem.indexOf(u8, footer, "1. Understand") != null);
    try std.testing.expect(std.mem.indexOf(u8, footer, "ryk explain 'git reset --hard'") != null);
    try std.testing.expect(std.mem.indexOf(u8, footer, "ryk allowlist add core.git:reset-hard") != null);
    try std.testing.expect(std.mem.indexOf(u8, footer, "ryk allow-once") != null);
    // Progressive hierarchy: temporary before permanent; permanent labelled advanced.
    try std.testing.expect(std.mem.indexOf(u8, footer, "Temporary exception") != null);
    try std.testing.expect(std.mem.indexOf(u8, footer, "Permanent exception (advanced)") != null);
    // Next order: explain, then allow-once, then allowlist (not day-1 primary).
    const explain_at = std.mem.indexOf(u8, footer, "ryk explain").?;
    const once_at = std.mem.indexOf(u8, footer, "ryk allow-once").?;
    const allowlist_at = std.mem.indexOf(u8, footer, "ryk allowlist add").?;
    try std.testing.expect(explain_at < once_at);
    try std.testing.expect(once_at < allowlist_at);
}

test "formatDenyNextSteps single-quotes hostile paste payloads" {
    const allocator = std.testing.allocator;
    const footer = try formatDenyNextSteps(allocator, "echo $(id)", null, null);
    defer allocator.free(footer);
    try std.testing.expect(std.mem.indexOf(u8, footer, "ryk explain 'echo $(id)'") != null);
    try std.testing.expect(std.mem.indexOf(u8, footer, "ryk explain \"echo $(id)\"") == null);
}

test "formatDenyNextStepsWithCode emits concrete allow-once code" {
    const allocator = std.testing.allocator;
    const footer = try formatDenyNextStepsWithCode(allocator, "rm -rf /", "core.filesystem:destructive_rm", null, "A1B2C3");
    defer allocator.free(footer);
    try std.testing.expect(std.mem.indexOf(u8, footer, "ryk allow-once A1B2C3") != null);
    try std.testing.expect(std.mem.indexOf(u8, footer, "Temporary exception") != null);
    try std.testing.expect(std.mem.indexOf(u8, footer, "ryk allowlist add core.filesystem:destructive_rm") != null);
    try std.testing.expect(std.mem.indexOf(u8, footer, "Permanent exception (advanced)") != null);
}

test "isBlockedFeedRecord is decision-based; warn is not blocked" {
    const base = RustShellFeedRecord{
        .timestamp = "t",
        .workspace_root = "/w",
        .event_type = "hermes_tool_call_warn",
        .decision = "warn",
        .decision_source = "zig-native",
        .event_source = "hook",
        .host = "hermes",
        .daemon_status = "not_applicable",
        .pack_id = null,
        .rule = null,
        .severity = null,
        .reason = "advisory",
        .remediation = null,
        .target_summary = "tool",
        .session_id = "s",
        .verified = false,
    };
    try std.testing.expect(!isBlockedFeedRecord(base));

    var ask = base;
    ask.decision = "ask";
    ask.event_type = "hermes_tool_call_ask";
    try std.testing.expect(isBlockedFeedRecord(ask));

    var deny = base;
    deny.decision = "deny";
    deny.event_type = "hermes_tool_call_blocked";
    try std.testing.expect(isBlockedFeedRecord(deny));

    var allow = base;
    allow.decision = "allow";
    allow.event_type = "hermes_tool_call";
    try std.testing.expect(!isBlockedFeedRecord(allow));
}

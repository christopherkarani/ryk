const std = @import("std");
const gpa_mod = @import("gpa.zig");
const build_options = @import("build_options");

const core = @import("ryk_core").core;
const core_api = @import("ryk_core").api;
const policy = @import("ryk_core").policy;
const brand = @import("brand.zig");
const daemon = @import("daemon.zig");
const shell_eval = @import("shell_eval.zig");
const fm_steward_client = @import("fm_steward_client.zig");
const exit_codes = @import("exit_codes.zig");
const feed_writer = @import("feed_writer.zig");
const help = @import("help.zig");
const rust_visibility = @import("feed_visibility.zig");
const telemetry = @import("../telemetry.zig");

const max_payload_len = 256 * 1024;
const api_schema_version: i64 = 1;
const daemon_protocol_version: i64 = 1;
const event_source_evaluate = "evaluate";

pub const exit_allowed: u8 = 0;
/// Machine `decision: "ask"` also uses exit 0 (reason is in JSON; Pi maps decision).
pub const exit_ask: u8 = 0;
pub const exit_denied: u8 = 2;
pub const exit_evaluator_error: u8 = 3;
pub const exit_invalid_input: u8 = 64;
pub const exit_internal_error: u8 = 1;

/// Product/test inject for WP4 + FM on the Pi evaluate path.
/// Production leaves overrides null (discover policy + default FM client).
const EvaluateWireOpts = struct {
    /// When set, skip policy discovery for mode.
    mode_override: ?policy.schema.Mode = null,
    /// When set, use this permit list instead of discovered `commands.allow`.
    commands_allow_override: ?[]const []const u8 = null,
    /// Injectable FM client (tests). Null → production `defaultClient()`.
    fm_client: ?fm_steward_client.Client = null,
    /// Skip FM soft seatbelt (tests that need pure WP4 matrix only).
    disable_fm: bool = false,
};

pub const EvaluateRequest = struct {
    schema_version: i64,
    request_id: ?[]const u8 = null,
    session_id: ?[]const u8 = null,
    host: ?[]const u8 = null,
    command: []const u8,
    cwd: []const u8,

    fn deinit(self: EvaluateRequest, allocator: std.mem.Allocator) void {
        if (self.request_id) |id| allocator.free(id);
        if (self.session_id) |id| allocator.free(id);
        if (self.host) |host| allocator.free(host);
        allocator.free(self.command);
        allocator.free(self.cwd);
    }
};

pub const EvaluatorFn = *const fn (
    std.mem.Allocator,
    []const u8,
    ?[]const u8,
) daemon.DaemonError!std.json.Parsed(daemon.DaemonResponse);

const FeedDestination = union(enum) {
    disabled,
    process_home,
    explicit: []const u8,
};

const ErrorCode = enum {
    invalid_input,
    daemon_unavailable,
    daemon_incompatible,
    daemon_timeout,
    protocol_error,
    internal_error,

    fn toString(self: ErrorCode) []const u8 {
        return @tagName(self);
    }
};

const DaemonStatus = enum {
    healthy,
    unavailable,
    incompatible,
    timeout,
    unknown,

    fn toString(self: DaemonStatus) []const u8 {
        return @tagName(self);
    }
};

const ErrorInfo = struct {
    code: ErrorCode,
    message: []const u8,
};

const Remediation = struct {
    description: []const u8,
};

const MachineResponse = struct {
    schema_version: i64 = api_schema_version,
    request_id: ?[]const u8 = null,
    ryk_version: []const u8 = build_options.version,
    daemon_protocol_version: ?i64 = daemon_protocol_version,
    decision: []const u8,
    reason: []const u8,
    severity: ?[]const u8 = null,
    pack_id: ?[]const u8 = null,
    pattern_name: ?[]const u8 = null,
    rule_id: ?[]const u8 = null,
    remediation: []const Remediation = &.{},
    daemon_status: DaemonStatus,
    daemon_compatible: bool,
    error_info: ?ErrorInfo = null,
};

pub fn command(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    return commandWithEvaluator(io, argv, stdout, stderr, shellEvalBridge);
}

fn shellEvalBridge(
    allocator: std.mem.Allocator,
    command_text: []const u8,
    cwd: ?[]const u8,
) daemon.DaemonError!std.json.Parsed(daemon.DaemonResponse) {
    return shell_eval.defaultEvaluator(allocator, .{ .command = command_text, .cwd = cwd });
}

fn commandWithEvaluator(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype, evaluator: EvaluatorFn) !u8 {
    if (argv.len > 0 and (std.mem.eql(u8, argv[0], "--help") or std.mem.eql(u8, argv[0], "-h"))) {
        _ = try help.writeCommand(io, stdout, "evaluate");
        return exit_codes.success;
    }

    var saw_json = false;
    var saw_stdin = false;
    for (argv) |arg| {
        if (std.mem.eql(u8, arg, "--json")) {
            saw_json = true;
        } else if (std.mem.eql(u8, arg, "--stdin")) {
            saw_stdin = true;
        } else {
            if (saw_json) {
                try writeInvalidInput(stdout, null, "unsupported option for evaluate");
            }
            try stderr.print("ryk evaluate: unsupported option '{s}'. Expected --json --stdin.\n", .{arg});
            return if (saw_json) exit_invalid_input else exit_codes.usage;
        }
    }

    if (!saw_json or !saw_stdin) {
        if (saw_json) {
            try writeInvalidInput(stdout, null, "expected --json --stdin");
            return exit_invalid_input;
        }
        try stderr.writeAll("ryk evaluate: expected --json --stdin. Run 'ryk help evaluate' for usage.\n");
        return exit_codes.usage;
    }

    var gpa_state: gpa_mod.State = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();

    const payload = readBoundedStdin(io, allocator, max_payload_len) catch |err| {
        const message = if (err == error.PayloadTooLarge) "JSON payload exceeds maximum size" else "failed to read stdin payload";
        try writeInvalidInput(stdout, null, message);
        return exit_invalid_input;
    };
    defer allocator.free(payload);

    return evaluatePayload(io, allocator, payload, stdout, evaluator, .process_home, .{});
}

fn evaluatePayload(
    io: std.Io,
    allocator: std.mem.Allocator,
    payload: []const u8,
    stdout: anytype,
    evaluator: EvaluatorFn,
    feed_destination: FeedDestination,
    wire: EvaluateWireOpts,
) !u8 {
    const request = parseRequest(io, allocator, payload) catch |err| {
        const request_id = requestIdBestEffort(allocator, payload) catch null;
        defer if (request_id) |id| allocator.free(id);
        switch (err) {
            error.OutOfMemory => {
                telemetry.recordReliability("evaluate", "other", "evaluate");
                try writeInternalError(stdout, request_id, "internal allocation failure during request parsing");
                return exit_internal_error;
            },
            else => |parse_err| {
                telemetry.recordReliability("evaluate", "usage", "evaluate");
                try writeInvalidInput(stdout, request_id, validationMessage(parse_err));
                return exit_invalid_input;
            },
        }
    };
    defer request.deinit(allocator);

    var parsed = evaluator(allocator, request.command, request.cwd) catch |err| {
        telemetry.recordReliability("evaluate", telemetryFailureForDaemonError(err), "evaluate");
        recordUnavailableEvaluationBestEffort(io, allocator, request, err, feed_destination);
        try writeDaemonError(stdout, request.request_id, err);
        return exit_evaluator_error;
    };
    defer parsed.deinit();

    // Feed is recorded inside writeEvaluationResponse after WP4+FM product decision
    // so the feed reflects final allow/ask/deny (not raw engine Allow upgraded by FM).
    return writeEvaluationResponse(io, allocator, stdout, request, parsed.value.result, wire, feed_destination) catch |err| switch (err) {
        error.DaemonProtocolError => {
            telemetry.recordReliability("evaluate", "protocol_error", "evaluate");
            try writeProtocolError(stdout, request.request_id, "daemon returned an unexpected evaluation response");
            return exit_evaluator_error;
        },
        error.OutOfMemory => {
            telemetry.recordReliability("evaluate", "other", "evaluate");
            try writeInternalError(stdout, request.request_id, "internal allocation failure during evaluation response");
            return exit_internal_error;
        },
        else => {
            telemetry.recordReliability("evaluate", "other", "evaluate");
            try writeInternalError(stdout, request.request_id, "failed to write evaluation response");
            return exit_internal_error;
        },
    };
}

fn telemetryFailureForDaemonError(err: daemon.DaemonError) []const u8 {
    return switch (err) {
        error.DaemonStartTimeout => "timeout",
        error.ResponseParseFailed, error.DaemonProtocolError, error.ProtocolMismatch, error.MissingHandshake, error.HandshakeMalformed => "protocol_error",
        else => "evaluator_error",
    };
}

fn modeStrictness(mode: policy.schema.Mode) u8 {
    return switch (mode) {
        .observe, .trusted => 0,
        .ask, .yolo => 1,
        .strict, .redteam => 2,
        .ci => 3,
    };
}

fn moreRestrictiveMode(a: policy.schema.Mode, b: policy.schema.Mode) policy.schema.Mode {
    return if (modeStrictness(a) >= modeStrictness(b)) a else b;
}

/// Resolve evaluate mode like product hooks: discovered policy mode, with
/// `RYK_MODE` only allowed to raise strictness (never ambient soften).
fn resolveEvaluateMode(base: policy.schema.Mode) policy.schema.Mode {
    const env_util = @import("../env_util.zig");
    if (env_util.getenvBrand("MODE")) |raw_c| {
        const raw = std.mem.span(raw_c);
        if (policy.schema.Mode.parse(raw)) |env_mode| {
            return moreRestrictiveMode(base, env_mode);
        }
    }
    return base;
}

/// Record evaluate feed from the **product** decision (post WP4+FM), not raw engine JSON.
/// Fail-soft: any error is swallowed so feed never changes evaluate exit behavior.
fn recordProductEvaluationBestEffort(
    io: std.Io,
    allocator: std.mem.Allocator,
    request: EvaluateRequest,
    decision_tag: []const u8,
    reason: []const u8,
    rule: ?[]const u8,
    severity: ?[]const u8,
    remediation: ?[]const u8,
    pack_id: ?[]const u8,
    destination: FeedDestination,
) void {
    if (destination == .disabled) return;
    const workspace_root = core.supervisor.resolveWorkspaceRoot(io, allocator, null, request.cwd) catch
        allocator.dupe(u8, request.cwd) catch return;
    defer allocator.free(workspace_root);

    // Prefer the hook-style product builder (decision/reason/rule/pack). It hardcodes
    // event_source "hook"; re-stamp to "evaluate" after a successful dupe.
    var record = rust_visibility.buildFeedRecordFromHookDecision(
        allocator,
        io,
        workspace_root,
        request.host orelse "unknown",
        "healthy",
        decision_tag,
        reason,
        rule,
        severity,
        remediation,
        pack_id,
        request.session_id orelse request.request_id,
    ) catch return;
    defer record.deinit(allocator);

    if (allocator.dupe(u8, event_source_evaluate)) |evaluate_src| {
        allocator.free(record.event_source);
        record.event_source = evaluate_src;
    } else |_| {
        // Keep builder's "hook" source rather than drop the feed row on OOM.
    }

    persistEvaluationRecordBestEffort(io, allocator, record, destination);
}

/// Protocol/engine error shapes (pre-product): still best-effort feed from daemon JSON.
fn recordDaemonEvaluationBestEffort(
    io: std.Io,
    allocator: std.mem.Allocator,
    request: EvaluateRequest,
    result: std.json.Value,
    destination: FeedDestination,
) void {
    if (destination == .disabled) return;
    const workspace_root = core.supervisor.resolveWorkspaceRoot(io, allocator, null, request.cwd) catch
        allocator.dupe(u8, request.cwd) catch return;
    defer allocator.free(workspace_root);
    var record = rust_visibility.buildFeedRecordFromDaemon(
        allocator,
        io,
        workspace_root,
        event_source_evaluate,
        request.host,
        "healthy",
        result,
        request.session_id orelse request.request_id,
        false,
    ) catch return;
    defer record.deinit(allocator);
    persistEvaluationRecordBestEffort(io, allocator, record, destination);
}

fn recordUnavailableEvaluationBestEffort(
    io: std.Io,
    allocator: std.mem.Allocator,
    request: EvaluateRequest,
    err: daemon.DaemonError,
    destination: FeedDestination,
) void {
    if (destination == .disabled) return;
    const workspace_root = core.supervisor.resolveWorkspaceRoot(io, allocator, null, request.cwd) catch
        allocator.dupe(u8, request.cwd) catch return;
    defer allocator.free(workspace_root);
    var record = rust_visibility.buildFeedRecordFromUnavailable(
        allocator,
        io,
        workspace_root,
        event_source_evaluate,
        request.host,
        err,
        request.session_id orelse request.request_id,
        false,
    ) catch return;
    defer record.deinit(allocator);
    persistEvaluationRecordBestEffort(io, allocator, record, destination);
}

fn persistEvaluationRecordBestEffort(
    io: std.Io,
    allocator: std.mem.Allocator,
    record: rust_visibility.RustShellFeedRecord,
    destination: FeedDestination,
) void {
    feed_writer.appendRecord(io, allocator, record.workspace_root, record) catch {};
    const dashboard_root = switch (destination) {
        .disabled => return,
        .process_home => if (feed_writer.processGlobalWritesDisabled()) return else feed_writer.resolveGlobalDashboardRoot(allocator) catch return,
        .explicit => |root| allocator.dupe(u8, root) catch return,
    };
    defer allocator.free(dashboard_root);
    feed_writer.appendGlobalRecord(io, allocator, dashboard_root, record) catch {};
}

const RequestParseError = error{
    InvalidJson,
    RootNotObject,
    MissingSchemaVersion,
    UnsupportedSchemaVersion,
    MissingKind,
    UnsupportedKind,
    MissingCommand,
    EmptyCommand,
    MissingCwd,
    RelativeCwd,
    NonexistentCwd,
};

fn parseRequest(io: std.Io, allocator: std.mem.Allocator, payload: []const u8) (RequestParseError || error{OutOfMemory})!EvaluateRequest {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, payload, .{}) catch return error.InvalidJson;
    defer parsed.deinit();

    if (parsed.value != .object) return error.RootNotObject;
    const object = parsed.value.object;

    const schema_value = object.get("schema_version") orelse return error.MissingSchemaVersion;
    const schema_version = switch (schema_value) {
        .integer => |value| value,
        else => return error.MissingSchemaVersion,
    };
    if (schema_version != api_schema_version) return error.UnsupportedSchemaVersion;

    const kind = stringField(object, "kind") orelse return error.MissingKind;
    if (!std.mem.eql(u8, kind, "shell_command")) return error.UnsupportedKind;

    const command_value = object.get("command") orelse return error.MissingCommand;
    const command_text = switch (command_value) {
        .string => |value| value,
        else => return error.MissingCommand,
    };
    if (std.mem.trim(u8, command_text, " \t\r\n").len == 0) return error.EmptyCommand;

    const cwd_value = object.get("cwd") orelse return error.MissingCwd;
    const cwd_text = switch (cwd_value) {
        .string => |value| value,
        else => return error.MissingCwd,
    };
    if (!std.fs.path.isAbsolute(cwd_text)) return error.RelativeCwd;

    const canonical_cwd_z = std.Io.Dir.cwd().realPathFileAlloc(io, cwd_text, allocator) catch return error.NonexistentCwd;
    defer allocator.free(canonical_cwd_z);
    var cwd_dir = std.Io.Dir.openDirAbsolute(io, canonical_cwd_z, .{}) catch return error.NonexistentCwd;
    cwd_dir.close(io);
    const canonical_cwd = try allocator.dupe(u8, canonical_cwd_z);
    errdefer allocator.free(canonical_cwd);

    const owned_request_id = if (stringField(object, "request_id")) |id| try allocator.dupe(u8, id) else null;
    errdefer if (owned_request_id) |id| allocator.free(id);
    const owned_session_id = if (nestedStringField(object, "source", "session_id")) |id| try allocator.dupe(u8, id) else null;
    errdefer if (owned_session_id) |id| allocator.free(id);
    const owned_host = if (nestedStringField(object, "source", "host")) |host| try allocator.dupe(u8, host) else null;
    errdefer if (owned_host) |host| allocator.free(host);
    const owned_command = try allocator.dupe(u8, command_text);
    errdefer allocator.free(owned_command);

    return .{
        .schema_version = schema_version,
        .request_id = owned_request_id,
        .session_id = owned_session_id,
        .host = owned_host,
        .command = owned_command,
        .cwd = canonical_cwd,
    };
}

fn validationMessage(err: RequestParseError) []const u8 {
    return switch (err) {
        error.InvalidJson => "invalid JSON request",
        error.RootNotObject => "request must be a JSON object",
        error.MissingSchemaVersion => "schema_version is required and must be 1",
        error.UnsupportedSchemaVersion => "unsupported schema_version",
        error.MissingKind => "kind is required",
        error.UnsupportedKind => "kind must be shell_command",
        error.MissingCommand => "command is required and must be a string",
        error.EmptyCommand => "command must not be empty",
        error.MissingCwd => "cwd is required and must be an absolute existing directory",
        error.RelativeCwd => "cwd must be an absolute path",
        error.NonexistentCwd => "cwd does not exist or is not accessible",
    };
}

fn stringField(object: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const value = object.get(key) orelse return null;
    return switch (value) {
        .string => |s| s,
        else => null,
    };
}

fn nestedStringField(object: std.json.ObjectMap, parent: []const u8, key: []const u8) ?[]const u8 {
    const parent_value = object.get(parent) orelse return null;
    if (parent_value != .object) return null;
    return stringField(parent_value.object, key);
}

fn requestIdBestEffort(allocator: std.mem.Allocator, payload: []const u8) !?[]const u8 {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, payload, .{}) catch return null;
    defer parsed.deinit();
    if (parsed.value != .object) return null;
    if (stringField(parsed.value.object, "request_id")) |id| return try allocator.dupe(u8, id);
    return null;
}

/// Map product WP4+FM decision to machine JSON for Pi evaluate.
///
/// Exit codes (stable contract):
/// - allow / observe → exit 0, decision "allow"
/// - ask → exit 0, decision "ask" (host maps JSON; do not invent a new exit)
/// - deny / redact / stage / broker → exit 2, decision "deny"
/// - evaluator fail-closed / protocol → exit 3, decision "error"
fn writeEvaluationResponse(
    io: std.Io,
    allocator: std.mem.Allocator,
    stdout: anytype,
    request: EvaluateRequest,
    result: std.json.Value,
    wire: EvaluateWireOpts,
    feed_destination: FeedDestination,
) !u8 {
    // Protocol-only shapes still fail closed before WP4 (preserve prior evaluate contract).
    switch (daemon.responseStatus(result)) {
        .error_status => {
            telemetry.recordReliability("evaluate", "protocol_error", "evaluate");
            recordDaemonEvaluationBestEffort(io, allocator, request, result, feed_destination);
            try writeProtocolError(stdout, request.request_id, "daemon evaluator returned an error");
            return exit_evaluator_error;
        },
        .pong, .cli_execution, .unknown => return error.DaemonProtocolError,
        .allow, .deny => {},
    }

    const workspace_root = core.supervisor.resolveWorkspaceRoot(io, allocator, null, request.cwd) catch
        try allocator.dupe(u8, request.cwd);
    defer allocator.free(workspace_root);

    var loaded_opt: ?core_api.LoadedPolicy = null;
    defer if (loaded_opt) |*loaded| loaded.deinit();
    if (wire.mode_override == null or wire.commands_allow_override == null) {
        loaded_opt = core_api.discoverPolicy(io, allocator, null, workspace_root) catch null;
    }

    const mode: policy.schema.Mode = if (wire.mode_override) |m|
        m
    else if (loaded_opt) |loaded|
        resolveEvaluateMode(loaded.mode())
    else
        resolveEvaluateMode(.strict);

    const commands_allow: []const []const u8 = if (wire.commands_allow_override) |a|
        a
    else if (loaded_opt) |loaded|
        loaded.innerPtr().commands.allow
    else
        &.{};

    const permit = try shell_eval.permitFromCommandsAllow(allocator, commands_allow);
    defer shell_eval.freePermitEntries(allocator, permit);

    var owned = try shell_eval.decisionFromDaemonResultWithPolicy(
        allocator,
        result,
        mode,
        .{
            .command = request.command,
            .permit = permit,
            .sticky = shell_eval.getSessionStickyStore(),
            .effect_class = null,
            .session_id = request.session_id orelse brand.default_session_id,
            .tool = "bash",
            .executed = true,
            .cwd = request.cwd,
            .host = request.host,
            .fm_client = wire.fm_client,
            .disable_fm = wire.disable_fm,
            .telemetry_source = event_source_evaluate,
        },
    );
    defer owned.deinit(allocator);

    // Presentation boundary: FM explain/why and daemon reasons may contain secret-shaped
    // text. Redact for JSON emit + feed; keep original on owned for deinit ownership.
    const safe_reason = try core_api.redactAlloc(allocator, owned.owned_reason);
    defer allocator.free(safe_reason);

    if (owned.fail_closed) {
        telemetry.recordReliability("evaluate", "evaluator_error", "evaluate");
        recordProductEvaluationBestEffort(
            io,
            allocator,
            request,
            "error",
            safe_reason,
            null,
            null,
            null,
            null,
            feed_destination,
        );
        try writeProtocolError(stdout, request.request_id, safe_reason);
        return exit_evaluator_error;
    }

    const severity = normalizeSeverity(daemon.responseStringField(result, "severity"));
    const pack_id = daemon.responseStringField(result, "pack_id");
    const pattern_name = daemon.responseStringField(result, "pattern_name");

    // Redact remediation text when present (same emit boundary as reason).
    const safe_remediation: ?[]const u8 = if (owned.owned_remediation) |text|
        try core_api.redactAlloc(allocator, text)
    else
        null;
    defer if (safe_remediation) |text| allocator.free(text);

    const decision_tag: []const u8 = switch (owned.decision.result) {
        .allow, .observe => "allow",
        .ask => "ask",
        .deny, .redact, .stage, .broker => "deny",
    };

    recordProductEvaluationBestEffort(
        io,
        allocator,
        request,
        decision_tag,
        safe_reason,
        owned.owned_rule_id,
        severity,
        safe_remediation,
        pack_id,
        feed_destination,
    );

    return switch (owned.decision.result) {
        .allow, .observe => {
            const response = MachineResponse{
                .request_id = request.request_id,
                .decision = "allow",
                .reason = safe_reason,
                .severity = severity,
                .pack_id = pack_id,
                .pattern_name = pattern_name,
                .rule_id = owned.owned_rule_id,
                .daemon_status = .healthy,
                .daemon_compatible = true,
            };
            try writeResponseJson(stdout, response);
            return exit_allowed;
        },
        .ask => {
            // Prefer product reason (WP4 softened / FM explain). Emit redacted.
            const response = MachineResponse{
                .request_id = request.request_id,
                .decision = "ask",
                .reason = safe_reason,
                .severity = severity,
                .pack_id = pack_id,
                .pattern_name = pattern_name,
                .rule_id = owned.owned_rule_id,
                .daemon_status = .healthy,
                .daemon_compatible = true,
            };
            try writeResponseJson(stdout, response);
            return exit_ask;
        },
        .deny, .redact, .stage, .broker => {
            const remediation_items = if (safe_remediation) |text|
                &[_]Remediation{.{ .description = text }}
            else
                &[_]Remediation{};
            // Prefer owned rule_id (pack:pattern) when present; else build from daemon fields.
            const rule_fallback = if (owned.owned_rule_id == null) try buildRuleId(allocator, result) else null;
            defer if (rule_fallback) |value| allocator.free(value);
            const response = MachineResponse{
                .request_id = request.request_id,
                .decision = "deny",
                .reason = safe_reason,
                .severity = severity,
                .pack_id = pack_id,
                .pattern_name = pattern_name,
                .rule_id = owned.owned_rule_id orelse rule_fallback,
                .remediation = remediation_items,
                .daemon_status = .healthy,
                .daemon_compatible = true,
            };
            try writeResponseJson(stdout, response);
            return exit_denied;
        },
    };
}

fn normalizeSeverity(severity: ?[]const u8) ?[]const u8 {
    const value = severity orelse return null;
    if (std.ascii.eqlIgnoreCase(value, "critical")) return "critical";
    if (std.ascii.eqlIgnoreCase(value, "high")) return "high";
    if (std.ascii.eqlIgnoreCase(value, "medium")) return "medium";
    if (std.ascii.eqlIgnoreCase(value, "low")) return "low";
    return null;
}

fn buildRuleId(allocator: std.mem.Allocator, result: std.json.Value) !?[]const u8 {
    const pack_id = daemon.responseStringField(result, "pack_id");
    const pattern_name = daemon.responseStringField(result, "pattern_name");
    if (pack_id) |pack| {
        if (pattern_name) |pattern| return try std.fmt.allocPrint(allocator, "{s}:{s}", .{ pack, pattern });
        return try allocator.dupe(u8, pack);
    }
    if (pattern_name) |pattern| return try allocator.dupe(u8, pattern);
    return null;
}

fn writeInvalidInput(stdout: anytype, request_id: ?[]const u8, message: []const u8) !void {
    try writeErrorResponse(stdout, .{
        .request_id = request_id,
        .decision = "error",
        .reason = message,
        .daemon_protocol_version = null,
        .daemon_status = .unknown,
        .daemon_compatible = false,
        .error_info = .{ .code = .invalid_input, .message = message },
    });
}

fn writeDaemonError(stdout: anytype, request_id: ?[]const u8, err: daemon.DaemonError) !void {
    const classified = classifyDaemonError(err);
    try writeErrorResponse(stdout, .{
        .request_id = request_id,
        .decision = "error",
        .reason = classified.message,
        .daemon_protocol_version = null,
        .daemon_status = classified.status,
        .daemon_compatible = false,
        .error_info = .{ .code = classified.code, .message = classified.message },
    });
}

fn writeProtocolError(stdout: anytype, request_id: ?[]const u8, message: []const u8) !void {
    try writeErrorResponse(stdout, .{
        .request_id = request_id,
        .decision = "error",
        .reason = message,
        .daemon_protocol_version = null,
        .daemon_status = .unknown,
        .daemon_compatible = false,
        .error_info = .{ .code = .protocol_error, .message = message },
    });
}

fn writeInternalError(stdout: anytype, request_id: ?[]const u8, message: []const u8) !void {
    try writeErrorResponse(stdout, .{
        .request_id = request_id,
        .decision = "error",
        .reason = message,
        .daemon_protocol_version = null,
        .daemon_status = .unknown,
        .daemon_compatible = false,
        .error_info = .{ .code = .internal_error, .message = message },
    });
}

fn writeErrorResponse(stdout: anytype, response: MachineResponse) !void {
    try writeResponseJson(stdout, response);
}

const ClassifiedDaemonError = struct {
    code: ErrorCode,
    status: DaemonStatus,
    message: []const u8,
};

fn classifyDaemonError(err: daemon.DaemonError) ClassifiedDaemonError {
    return switch (err) {
        error.ProtocolMismatch, error.MissingHandshake, error.HandshakeMalformed => .{
            .code = .daemon_incompatible,
            .status = .incompatible,
            .message = "daemon protocol is incompatible with this ryk CLI",
        },
        error.DaemonStartTimeout => .{
            .code = .daemon_timeout,
            .status = .timeout,
            .message = "daemon evaluation timed out",
        },
        error.ResponseParseFailed, error.DaemonProtocolError => .{
            .code = .protocol_error,
            .status = .unknown,
            .message = "daemon returned an invalid protocol response",
        },
        error.RequestSerializationFailed => .{
            .code = .protocol_error,
            .status = .unknown,
            .message = "failed to serialize daemon evaluation request",
        },
        error.InvalidWorkingDirectory => .{
            .code = .invalid_input,
            .status = .unknown,
            .message = "command working directory does not exist",
        },
        error.OutOfMemory => .{
            .code = .internal_error,
            .status = .unknown,
            .message = "internal allocation failure during evaluation",
        },
        error.RustShellEvalRemoved => .{
            .code = .daemon_unavailable,
            .status = .unavailable,
            .message = shell_eval.daemonUnavailableReason(error.RustShellEvalRemoved),
        },
        else => .{
            .code = .daemon_unavailable,
            .status = .unavailable,
            .message = "daemon is unavailable for shell-command evaluation",
        },
    };
}

fn writeResponseJson(stdout: anytype, response: MachineResponse) !void {
    try stdout.writeAll("{\n");
    try stdout.print("  \"schema_version\": {d},\n", .{response.schema_version});
    try stdout.writeAll("  \"request_id\": ");
    try writeNullableJsonString(stdout, response.request_id);
    try stdout.writeAll(",\n");
    try stdout.writeAll("  \"ryk_version\": ");
    try writeJsonString(stdout, response.ryk_version);
    try stdout.writeAll(",\n");
    try stdout.writeAll("  \"daemon_protocol_version\": ");
    if (response.daemon_protocol_version) |version| try stdout.print("{d}", .{version}) else try stdout.writeAll("null");
    try stdout.writeAll(",\n");
    try stdout.writeAll("  \"decision\": ");
    try writeJsonString(stdout, response.decision);
    try stdout.writeAll(",\n");
    try stdout.writeAll("  \"reason\": ");
    try writeJsonString(stdout, response.reason);
    try stdout.writeAll(",\n");
    try stdout.writeAll("  \"severity\": ");
    try writeNullableJsonString(stdout, response.severity);
    try stdout.writeAll(",\n");
    try stdout.writeAll("  \"pack_id\": ");
    try writeNullableJsonString(stdout, response.pack_id);
    try stdout.writeAll(",\n");
    try stdout.writeAll("  \"pattern_name\": ");
    try writeNullableJsonString(stdout, response.pattern_name);
    try stdout.writeAll(",\n");
    try stdout.writeAll("  \"rule_id\": ");
    try writeNullableJsonString(stdout, response.rule_id);
    try stdout.writeAll(",\n");
    try stdout.writeAll("  \"remediation\": [");
    for (response.remediation, 0..) |item, i| {
        if (i != 0) try stdout.writeAll(",");
        try stdout.writeAll("{\"description\":");
        try writeJsonString(stdout, item.description);
        try stdout.writeAll(",\"command\":null,\"platform\":null}");
    }
    try stdout.writeAll("],\n");
    // Additive machine-usable next steps for Pi / evaluate consumers.
    try stdout.writeAll("  \"remediation_commands\": [");
    if (std.mem.eql(u8, response.decision, "deny")) {
        try stdout.writeAll("\"ryk explain \\\"<command>\\\"\",\"ryk allow-once <code>\",\"ryk allowlist list\"");
    }
    try stdout.writeAll("],\n");
    try stdout.writeAll("  \"daemon\": {\n");
    try stdout.writeAll("    \"status\": ");
    try writeJsonString(stdout, response.daemon_status.toString());
    try stdout.writeAll(",\n");
    try stdout.print("    \"compatible\": {}\n", .{response.daemon_compatible});
    try stdout.writeAll("  },\n");
    try stdout.writeAll("  \"redactions\": [],\n");
    try stdout.writeAll("  \"error\": ");
    if (response.error_info) |err| {
        try stdout.writeAll("{\n");
        try stdout.writeAll("    \"code\": ");
        try writeJsonString(stdout, err.code.toString());
        try stdout.writeAll(",\n");
        try stdout.writeAll("    \"message\": ");
        try writeJsonString(stdout, err.message);
        try stdout.writeAll("\n  }");
    } else {
        try stdout.writeAll("null");
    }
    try stdout.writeAll("\n}\n");
}

fn writeNullableJsonString(writer: anytype, value: ?[]const u8) !void {
    if (value) |text| try writeJsonString(writer, text) else try writer.writeAll("null");
}

fn writeJsonString(writer: anytype, value: []const u8) !void {
    try writer.writeByte('"');
    for (value) |byte| {
        switch (byte) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            0...8, 11...12, 14...0x1f => try writer.print("\\u{x:0>4}", .{byte}),
            else => try writer.writeByte(byte),
        }
    }
    try writer.writeByte('"');
}

fn readBoundedStdin(io: std.Io, allocator: std.mem.Allocator, max_len: usize) ![]u8 {
    return readBoundedFile(io, allocator, max_len, std.Io.File.stdin());
}

fn readBoundedFile(io: std.Io, allocator: std.mem.Allocator, max_len: usize, file: std.Io.File) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    var chunk: [4096]u8 = undefined;
    while (true) {
        const n = file.readStreaming(io, &.{chunk[0..]}) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        if (n == 0) break;
        if (buf.items.len + n > max_len) return error.PayloadTooLarge;
        try buf.appendSlice(allocator, chunk[0..n]);
    }

    return try buf.toOwnedSlice(allocator);
}

fn mockAllow(allocator: std.mem.Allocator, command_text: []const u8, cwd: ?[]const u8) daemon.DaemonError!std.json.Parsed(daemon.DaemonResponse) {
    _ = command_text;
    _ = cwd;
    return daemon.parseResponse(allocator, "{\"id\":1,\"result\":{\"status\":\"Allow\",\"reason\":\"Command allowed by evaluator\"}}");
}

fn mockDeny(allocator: std.mem.Allocator, command_text: []const u8, cwd: ?[]const u8) daemon.DaemonError!std.json.Parsed(daemon.DaemonResponse) {
    _ = command_text;
    _ = cwd;
    return daemon.parseResponse(allocator, "{\"id\":1,\"result\":{\"status\":\"Deny\",\"reason\":\"blocked matched ghp_fake_secret_value\",\"pack_id\":\"core.filesystem\",\"pattern_name\":\"destructive-rm\",\"severity\":\"Critical\",\"matched_text_preview\":\"ghp_fake_secret_value\",\"explanation\":\"Use a safer remove target.\"}}");
}

fn mockUnavailable(allocator: std.mem.Allocator, command_text: []const u8, cwd: ?[]const u8) daemon.DaemonError!std.json.Parsed(daemon.DaemonResponse) {
    _ = allocator;
    _ = command_text;
    _ = cwd;
    return error.SocketConnectFailed;
}

fn mockProtocolMismatch(allocator: std.mem.Allocator, command_text: []const u8, cwd: ?[]const u8) daemon.DaemonError!std.json.Parsed(daemon.DaemonResponse) {
    _ = allocator;
    _ = command_text;
    _ = cwd;
    return error.ProtocolMismatch;
}

fn mockMalformed(allocator: std.mem.Allocator, command_text: []const u8, cwd: ?[]const u8) daemon.DaemonError!std.json.Parsed(daemon.DaemonResponse) {
    _ = allocator;
    _ = command_text;
    _ = cwd;
    return error.ResponseParseFailed;
}

fn mockDaemonError(allocator: std.mem.Allocator, command_text: []const u8, cwd: ?[]const u8) daemon.DaemonError!std.json.Parsed(daemon.DaemonResponse) {
    _ = command_text;
    _ = cwd;
    return daemon.parseResponse(allocator, "{\"id\":1,\"result\":{\"status\":\"Error\",\"message\":\"raw daemon failure with ghp_fake_secret_value\"}}");
}

fn mockDenyHigh(allocator: std.mem.Allocator, command_text: []const u8, cwd: ?[]const u8) daemon.DaemonError!std.json.Parsed(daemon.DaemonResponse) {
    _ = command_text;
    _ = cwd;
    return daemon.parseResponse(allocator, "{\"id\":1,\"result\":{\"status\":\"Deny\",\"reason\":\"force push\",\"pack_id\":\"core.git\",\"pattern_name\":\"force-push\",\"severity\":\"High\",\"explanation\":\"force push rewrites remote history\"}}");
}

fn testCwd(allocator: std.mem.Allocator) ![]u8 {
    const cwd_z = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, ".", allocator);
    defer allocator.free(cwd_z);
    return try allocator.dupe(u8, cwd_z);
}

fn validPayload(allocator: std.mem.Allocator, command_text: []const u8, cwd: []const u8) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "{{\"schema_version\":1,\"request_id\":\"req-1\",\"kind\":\"shell_command\",\"command\":\"{s}\",\"cwd\":\"{s}\",\"source\":{{\"host\":\"pi\",\"tool_name\":\"bash\",\"mode\":\"tui\",\"session_id\":\"pi-session-42\"}}}}",
        .{ command_text, cwd },
    );
}

/// Baseline wire for existing allow/deny contract tests: skip FM + force mode
/// so local policy / FM binary cannot change matrix outcomes.
const test_wire_strict_no_fm = EvaluateWireOpts{
    .mode_override = .strict,
    .commands_allow_override = &.{},
    .disable_fm = true,
};

const EvaluateFmFakeState = struct {
    call_count: u32 = 0,
    verdict: fm_steward_client.ClassifyVerdict = .continue_,
    why: []const u8 = "fake continue",
    explain: ?[]const u8 = null,
    timed_out: bool = false,
    fallback: bool = false,
};

fn evaluateFakeFmClassify(
    ctx: ?*anyopaque,
    _: std.mem.Allocator,
    _: []const u8,
    _: u32,
) fm_steward_client.ClassifyResult {
    const state: *EvaluateFmFakeState = @ptrCast(@alignCast(ctx.?));
    state.call_count += 1;
    return .{
        .verdict = state.verdict,
        .why = state.why,
        .explain = state.explain,
        .timed_out = state.timed_out,
        .fallback = state.fallback,
        .model_available = !state.fallback and !state.timed_out,
        .owned = false,
    };
}

fn evaluateFakeFmClient(state: *EvaluateFmFakeState) fm_steward_client.Client {
    return .{
        .ctx = state,
        .classify_fn = evaluateFakeFmClassify,
    };
}

test "evaluate parses a valid request and canonicalizes cwd" {
    const allocator = std.testing.allocator;
    const cwd = try testCwd(allocator);
    defer allocator.free(cwd);
    const payload = try validPayload(allocator, "git status", cwd);
    defer allocator.free(payload);

    const request = try parseRequest(std.testing.io, allocator, payload);
    defer request.deinit(allocator);
    try std.testing.expectEqual(api_schema_version, request.schema_version);
    try std.testing.expectEqualStrings("req-1", request.request_id.?);
    try std.testing.expectEqualStrings("pi-session-42", request.session_id.?);
    try std.testing.expectEqualStrings("pi", request.host.?);
    try std.testing.expectEqualStrings("git status", request.command);
    try std.testing.expect(std.fs.path.isAbsolute(request.cwd));
}

test "evaluate request validation errors are structured" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(error.MissingSchemaVersion, parseRequest(std.testing.io, allocator, "{}"));
    try std.testing.expectError(error.UnsupportedSchemaVersion, parseRequest(std.testing.io, allocator, "{\"schema_version\":2,\"kind\":\"shell_command\",\"command\":\"git status\",\"cwd\":\"/tmp\"}"));
    try std.testing.expectError(error.UnsupportedKind, parseRequest(std.testing.io, allocator, "{\"schema_version\":1,\"kind\":\"file\",\"command\":\"git status\",\"cwd\":\"/tmp\"}"));
    try std.testing.expectError(error.MissingCommand, parseRequest(std.testing.io, allocator, "{\"schema_version\":1,\"kind\":\"shell_command\",\"cwd\":\"/tmp\"}"));
    try std.testing.expectError(error.EmptyCommand, parseRequest(std.testing.io, allocator, "{\"schema_version\":1,\"kind\":\"shell_command\",\"command\":\"   \",\"cwd\":\"/tmp\"}"));
    try std.testing.expectError(error.MissingCwd, parseRequest(std.testing.io, allocator, "{\"schema_version\":1,\"kind\":\"shell_command\",\"command\":\"git status\"}"));
    try std.testing.expectError(error.RelativeCwd, parseRequest(std.testing.io, allocator, "{\"schema_version\":1,\"kind\":\"shell_command\",\"command\":\"git status\",\"cwd\":\".\"}"));
    try std.testing.expectError(error.NonexistentCwd, parseRequest(std.testing.io, allocator, "{\"schema_version\":1,\"kind\":\"shell_command\",\"command\":\"git status\",\"cwd\":\"/definitely/not/ryk/evaluate/cwd\"}"));
}

test "evaluate allow response is stable JSON and exit 0" {
    const allocator = std.testing.allocator;
    const cwd = try testCwd(allocator);
    defer allocator.free(cwd);
    const payload = try validPayload(allocator, "git status", cwd);
    defer allocator.free(payload);
    var stdout_buf: [4096]u8 = undefined;
    var stdout: std.Io.Writer = .fixed(&stdout_buf);

    const code = try evaluatePayload(std.testing.io, allocator, payload, &stdout, mockAllow, .disabled, test_wire_strict_no_fm);
    try std.testing.expectEqual(exit_allowed, code);
    const output = stdout.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "\"schema_version\": 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"decision\": \"allow\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"daemon\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"error\": null") != null);
}

test "evaluate deny response is safe and exit 2" {
    const allocator = std.testing.allocator;
    const cwd = try testCwd(allocator);
    defer allocator.free(cwd);
    const payload = try validPayload(allocator, "echo ghp_fake_secret_value", cwd);
    defer allocator.free(payload);
    var stdout_buf: [8192]u8 = undefined;
    var stdout: std.Io.Writer = .fixed(&stdout_buf);

    const code = try evaluatePayload(std.testing.io, allocator, payload, &stdout, mockDeny, .disabled, test_wire_strict_no_fm);
    try std.testing.expectEqual(exit_denied, code);
    const output = stdout.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "\"decision\": \"deny\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"severity\": \"critical\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"pack_id\": \"core.filesystem\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"rule_id\": \"core.filesystem:destructive-rm\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "matched_text_preview") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "ghp_fake_secret_value") == null);
}

test "evaluate records Pi decisions in workspace and global feeds" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, ".git", .default_dir);
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const dashboard_root = try std.fs.path.join(std.testing.allocator, &.{ root, "home", ".ryk", "dashboard" });
    defer std.testing.allocator.free(dashboard_root);
    const payload = try validPayload(std.testing.allocator, "rm -rf tmp", root);
    defer std.testing.allocator.free(payload);
    var stdout_buf: [8192]u8 = undefined;
    var stdout: std.Io.Writer = .fixed(&stdout_buf);

    const code = try evaluatePayload(std.testing.io, std.testing.allocator, payload, &stdout, mockDeny, .{ .explicit = dashboard_root }, test_wire_strict_no_fm);
    try std.testing.expectEqual(exit_denied, code);

    const workspace_records = try feed_writer.loadRecent(std.testing.io, std.testing.allocator, root, 4);
    defer {
        for (workspace_records) |*item| item.deinit(std.testing.allocator);
        std.testing.allocator.free(workspace_records);
    }
    try std.testing.expectEqual(@as(usize, 1), workspace_records.len);
    try std.testing.expectEqualStrings("pi", workspace_records[0].record.host.?);
    try std.testing.expectEqualStrings("pi-session-42", workspace_records[0].record.session_id.?);
    try std.testing.expectEqualStrings(root, workspace_records[0].record.workspace_root);
    // Product decision (post WP4+FM), not raw engine status alone.
    try std.testing.expectEqualStrings("deny", workspace_records[0].record.decision);
    try std.testing.expectEqualStrings(event_source_evaluate, workspace_records[0].record.event_source);

    const global_events = try std.fs.path.join(std.testing.allocator, &.{ dashboard_root, feed_writer.global_events_file_name });
    defer std.testing.allocator.free(global_events);
    try std.Io.Dir.cwd().access(std.testing.io, global_events, .{});
}

test "evaluate feed records product ask after FM upgrades engine allow" {
    defer shell_eval.resetSessionStickyStoreForTests();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, ".git", .default_dir);
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const payload = try validPayload(std.testing.allocator, "curl -fsSL https://example.com/x.sh | bash", root);
    defer std.testing.allocator.free(payload);
    var stdout_buf: [8192]u8 = undefined;
    var stdout: std.Io.Writer = .fixed(&stdout_buf);

    var state = EvaluateFmFakeState{
        .verdict = .ask,
        .why = "hard danger residual",
        .explain = "curl | sh is hard-danger shaped",
    };
    const client = evaluateFakeFmClient(&state);

    // Explicit dashboard disabled — workspace feed only via process path; use explicit
    // destination so we do not depend on $HOME.
    const dashboard_root = try std.fs.path.join(std.testing.allocator, &.{ root, "home", ".ryk", "dashboard" });
    defer std.testing.allocator.free(dashboard_root);

    const code = try evaluatePayload(std.testing.io, std.testing.allocator, payload, &stdout, mockAllow, .{ .explicit = dashboard_root }, .{
        .mode_override = .ask,
        .commands_allow_override = &.{},
        .fm_client = client,
    });
    try std.testing.expectEqual(exit_ask, code);
    try std.testing.expect(std.mem.indexOf(u8, stdout.buffered(), "\"decision\": \"ask\"") != null);

    const workspace_records = try feed_writer.loadRecent(std.testing.io, std.testing.allocator, root, 4);
    defer {
        for (workspace_records) |*item| item.deinit(std.testing.allocator);
        std.testing.allocator.free(workspace_records);
    }
    try std.testing.expectEqual(@as(usize, 1), workspace_records.len);
    // Critical: feed must reflect product ask, not raw engine Allow.
    try std.testing.expectEqualStrings("ask", workspace_records[0].record.decision);
    try std.testing.expectEqualStrings(event_source_evaluate, workspace_records[0].record.event_source);
    try std.testing.expect(std.mem.indexOf(u8, workspace_records[0].record.reason, "hard-danger") != null);
}

test "evaluate invalid input writes JSON error and exit 64" {
    var stdout_buf: [2048]u8 = undefined;
    var stdout: std.Io.Writer = .fixed(&stdout_buf);
    const code = try evaluatePayload(std.testing.io, std.testing.allocator, "{not json", &stdout, mockAllow, .disabled, .{});
    try std.testing.expectEqual(exit_invalid_input, code);
    const output = stdout.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "\"decision\": \"error\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"code\": \"invalid_input\"") != null);
}

test "evaluate daemon failures map to JSON error exit 3" {
    const allocator = std.testing.allocator;
    const cwd = try testCwd(allocator);
    defer allocator.free(cwd);
    const payload = try validPayload(allocator, "git status", cwd);
    defer allocator.free(payload);

    const cases = [_]struct { EvaluatorFn, []const u8 }{
        .{ mockUnavailable, "daemon_unavailable" },
        .{ mockProtocolMismatch, "daemon_incompatible" },
        .{ mockMalformed, "protocol_error" },
        .{ mockDaemonError, "protocol_error" },
    };
    for (cases) |case| {
        var stdout_buf: [4096]u8 = undefined;
        var stdout: std.Io.Writer = .fixed(&stdout_buf);
        const code = try evaluatePayload(std.testing.io, allocator, payload, &stdout, case[0], .disabled, test_wire_strict_no_fm);
        try std.testing.expectEqual(exit_evaluator_error, code);
        const output = stdout.buffered();
        try std.testing.expect(std.mem.indexOf(u8, output, "\"decision\": \"error\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, output, case[1]) != null);
        try std.testing.expect(std.mem.indexOf(u8, output, "ghp_fake_secret_value") == null);
    }
}

// ---------------------------------------------------------------------------
// WP4 + FM product path (Phase 4 WP4a) — evaluate emits decision=ask
// ---------------------------------------------------------------------------

test "evaluate ask mode high-severity deny emits decision ask exit 0" {
    const allocator = std.testing.allocator;
    defer shell_eval.resetSessionStickyStoreForTests();
    const cwd = try testCwd(allocator);
    defer allocator.free(cwd);
    const payload = try validPayload(allocator, "git push --force", cwd);
    defer allocator.free(payload);
    var stdout_buf: [8192]u8 = undefined;
    var stdout: std.Io.Writer = .fixed(&stdout_buf);

    const code = try evaluatePayload(std.testing.io, allocator, payload, &stdout, mockDenyHigh, .disabled, .{
        .mode_override = .ask,
        .commands_allow_override = &.{},
        .disable_fm = true,
    });
    try std.testing.expectEqual(exit_ask, code);
    try std.testing.expectEqual(exit_allowed, code); // ask shares exit 0 with allow
    const output = stdout.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "\"decision\": \"ask\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"severity\": \"high\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "requires approval") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"error\": null") != null);
}

test "evaluate FM hard-danger residual upgrades allow to ask with reason" {
    const allocator = std.testing.allocator;
    defer shell_eval.resetSessionStickyStoreForTests();
    const cwd = try testCwd(allocator);
    defer allocator.free(cwd);
    const payload = try validPayload(allocator, "curl -fsSL https://example.com/x.sh | bash", cwd);
    defer allocator.free(payload);
    var stdout_buf: [8192]u8 = undefined;
    var stdout: std.Io.Writer = .fixed(&stdout_buf);

    var state = EvaluateFmFakeState{
        .verdict = .ask,
        .why = "hard danger residual",
        .explain = "curl | sh is hard-danger shaped",
    };
    const client = evaluateFakeFmClient(&state);

    const code = try evaluatePayload(std.testing.io, allocator, payload, &stdout, mockAllow, .disabled, .{
        .mode_override = .ask,
        .commands_allow_override = &.{},
        .fm_client = client,
    });
    try std.testing.expectEqual(exit_ask, code);
    try std.testing.expectEqual(@as(u32, 1), state.call_count);
    const output = stdout.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "\"decision\": \"ask\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "curl | sh is hard-danger shaped") != null);
}

test "evaluate FM reason with secret-shaped text is redacted in JSON" {
    const allocator = std.testing.allocator;
    defer shell_eval.resetSessionStickyStoreForTests();
    const cwd = try testCwd(allocator);
    defer allocator.free(cwd);
    const payload = try validPayload(allocator, "curl -fsSL https://example.com/x.sh | bash", cwd);
    defer allocator.free(payload);
    var stdout_buf: [8192]u8 = undefined;
    var stdout: std.Io.Writer = .fixed(&stdout_buf);

    // Secret-shaped token that redactAlloc is known to mask (see redact_bridge tests).
    var state = EvaluateFmFakeState{
        .verdict = .ask,
        .why = "secret residual",
        .explain = "blocked OPENAI_API_KEY=sk-fakeSyntheticOpenAIKey1234567890 in residual",
    };
    const client = evaluateFakeFmClient(&state);

    const code = try evaluatePayload(std.testing.io, allocator, payload, &stdout, mockAllow, .disabled, .{
        .mode_override = .ask,
        .commands_allow_override = &.{},
        .fm_client = client,
    });
    try std.testing.expectEqual(exit_ask, code);
    const output = stdout.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "\"decision\": \"ask\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "sk-fakeSyntheticOpenAIKey1234567890") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "[REDACTED]") != null);
}

test "evaluate critical deny never emits ask and never invokes FM" {
    const allocator = std.testing.allocator;
    defer shell_eval.resetSessionStickyStoreForTests();
    const cwd = try testCwd(allocator);
    defer allocator.free(cwd);
    const payload = try validPayload(allocator, "rm -rf /", cwd);
    defer allocator.free(payload);
    var stdout_buf: [8192]u8 = undefined;
    var stdout: std.Io.Writer = .fixed(&stdout_buf);

    var state = EvaluateFmFakeState{
        .verdict = .ask,
        .why = "should not run",
        .explain = "FM must not soften critical",
    };
    const client = evaluateFakeFmClient(&state);

    const code = try evaluatePayload(std.testing.io, allocator, payload, &stdout, mockDeny, .disabled, .{
        .mode_override = .ask,
        .commands_allow_override = &.{},
        .fm_client = client,
    });
    try std.testing.expectEqual(exit_denied, code);
    try std.testing.expectEqual(@as(u32, 0), state.call_count);
    const output = stdout.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "\"decision\": \"deny\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"decision\": \"ask\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"severity\": \"critical\"") != null);
}

test "evaluate FM timeout keeps soft allow without inventing ask" {
    const allocator = std.testing.allocator;
    defer shell_eval.resetSessionStickyStoreForTests();
    const cwd = try testCwd(allocator);
    defer allocator.free(cwd);
    const payload = try validPayload(allocator, "git status", cwd);
    defer allocator.free(payload);
    var stdout_buf: [4096]u8 = undefined;
    var stdout: std.Io.Writer = .fixed(&stdout_buf);

    var state = EvaluateFmFakeState{
        .verdict = .continue_,
        .why = "fm_steward_timed_out",
        .timed_out = true,
        .fallback = true,
    };
    const client = evaluateFakeFmClient(&state);

    const code = try evaluatePayload(std.testing.io, allocator, payload, &stdout, mockAllow, .disabled, .{
        .mode_override = .ask,
        .commands_allow_override = &.{},
        .fm_client = client,
    });
    try std.testing.expectEqual(exit_allowed, code);
    try std.testing.expectEqual(@as(u32, 1), state.call_count);
    const output = stdout.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "\"decision\": \"allow\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"decision\": \"ask\"") == null);
}

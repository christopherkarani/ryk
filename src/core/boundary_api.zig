const std = @import("std");

const audit = @import("../audit/mod.zig");
const core_mod = @import("mod.zig");
const policy_engine = @import("../policy/mod.zig");

pub const Decision = core_mod.decision.Decision;
pub const DecisionResult = core_mod.decision.DecisionResult;
pub const Evaluation = policy_engine.schema.Evaluation;
pub const EvaluationContext = policy_engine.schema.EvaluationContext;
pub const ExplainKind = policy_engine.explain.ExplainKind;
pub const Preset = policy_engine.presets.Preset;
pub const ReplayOptions = audit.replay.ReplayOptions;
pub const ReplayEvent = audit.replay.ReplayEvent;
pub const isDeniedFields = audit.replay.isDeniedFields;
pub const ReplaySession = audit.replay.ReplaySession;
pub const VerifyResult = audit.replay.VerifyResult;
pub const ParseIntegrityFailed = audit.replay.ParseIntegrityFailed;
pub const AuditWriter = audit.writer.SessionWriter;
pub const SummaryInput = audit.summary.SummaryInput;
pub const Mode = policy_engine.schema.Mode;
pub const Path = core_mod.types.Path;
pub const PathKind = core_mod.types.PathKind;
pub const Timestamp = core_mod.time.Timestamp;
pub const Session = core_mod.session.Session;
pub const SessionId = core_mod.session.SessionId;
pub const EventId = core_mod.event.EventId;

pub fn redactAlloc(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    return audit.redact_bridge.redactAlloc(allocator, value);
}

pub fn isSensitiveRedactionKey(value: []const u8) bool {
    return audit.redact_bridge.isSensitiveKey(value);
}

const PolicyInner = struct {
    value: policy_engine.schema.Policy,
    allocator: std.mem.Allocator,

    fn deinit(self: *PolicyInner) void {
        self.value.deinit();
        self.allocator.destroy(self);
    }
};

/// Opaque policy handle; storage is not accessible outside this module.
/// The caller owns the handle and must call `deinit()` to free all associated memory.
/// Created by `parsePolicyFromSlice`, `loadPolicyFile`, or `loadPolicyPreset`.
pub const Policy = opaque {
    pub fn deinit(self: *Policy) void {
        policyInnerMut(self).deinit();
    }

    pub fn mode(self: *const Policy) Mode {
        return policyInner(self).mode;
    }
};

fn policyInner(policy: *const Policy) *const policy_engine.schema.Policy {
    const inner: *const PolicyInner = @ptrCast(@alignCast(policy));
    return &inner.value;
}

fn policyInnerMut(policy: *Policy) *PolicyInner {
    return @ptrCast(@alignCast(policy));
}

pub const LoadSource = policy_engine.schema.LoadSource;

/// A policy loaded with its source metadata (file path, load source).
/// The caller owns this value and must call `deinit()` to free the policy and path.
/// The `path` is freed on `deinit()`; do not use after calling `deinit()`.
pub const LoadedPolicy = struct {
    policy: *Policy,
    source: LoadSource,
    path: []const u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *LoadedPolicy) void {
        self.policy.deinit();
        self.allocator.free(self.path);
        self.* = undefined;
    }

    pub fn mode(self: *const LoadedPolicy) Mode {
        return policyInner(self.policy).mode;
    }

    pub fn innerPtr(self: *const LoadedPolicy) *const policy_engine.schema.Policy {
        return policyInner(self.policy);
    }

    pub fn innerMutPtr(self: *LoadedPolicy) *policy_engine.schema.Policy {
        return &policyInnerMut(self.policy).value;
    }
};

pub const ActorKind = enum {
    user,
    agent,
    process,
    /// Maps to core `ActorKind.ryk` in audit events. Prefer `.ryk`.
    core,
    ryk,
    unknown,
};

pub const Actor = struct {
    kind: ActorKind,
    id: ?[]const u8 = null,
    display: ?[]const u8 = null,
};

pub const TargetKind = enum {
    env_var,
    file_path,
    command,
    network_endpoint,
    approval,
    staging_area,
    extension,
    session,
    mcp_tool,
    mcp_resource,
    mcp_prompt,
    mcp_sampling,
    extension_target,
    unknown,
};

pub const Target = struct {
    kind: TargetKind,
    value: []const u8,
};

pub const EnvAction = struct {
    name: []const u8,
};

pub const FileAction = struct {
    path: Path,
};

pub const CommandAction = struct {
    argv: []const []const u8,
};

pub const NetworkAction = struct {
    host: []const u8,
    port: ?u16 = null,
    scheme: ?[]const u8 = null,
};

pub const ApprovalAction = struct {
    target: Target,
    requested_scope: []const u8,
};

pub const StagingAction = struct {
    path: Path,
};

/// Product-neutral extension hook. Evaluation uses policy mode defaults only.
pub const ExtensionAction = struct {
    domain: []const u8,
    operation: []const u8,
    target: []const u8,
};

pub const McpToolCall = struct {
    server: []const u8,
    tool_name: []const u8,
};

pub const Action = union(enum) {
    env_read: EnvAction,
    file_read: FileAction,
    file_write: FileAction,
    command_exec: CommandAction,
    network_connect: NetworkAction,
    approval_decision: ApprovalAction,
    staging_decision: StagingAction,
    extension: ExtensionAction,
    mcp_tool_call: McpToolCall,

    pub fn targetKind(self: Action) TargetKind {
        return switch (self) {
            .env_read => .env_var,
            .file_read, .file_write => .file_path,
            .command_exec => .command,
            .network_connect => .network_endpoint,
            .approval_decision => .approval,
            .staging_decision => .staging_area,
            .extension => .extension,
            .mcp_tool_call => .extension_target,
        };
    }
};

pub const EventType = enum {
    extension_event,
    session_start,
    session_exit,
    policy_loaded,
    backend_capability,
    sandbox_posture,
    os_fs_deny,
    process_launch,
    file_read_attempt,
    file_read_allowed,
    file_read_denied,
    file_write_attempt,
    file_write_staged,
    file_write_denied,
    file_apply,
    file_discard,
    command_attempt,
    command_approval_requested,
    command_allowed,
    command_denied,
    network_connect_attempt,
    network_connect_allowed,
    network_connect_denied,
    network_proxy_start,
    network_proxy_stop,
    network_exfiltration_suspected,
    mcp_initialize,
    mcp_tools_list,
    mcp_tool_metadata_flagged,
    mcp_tool_call,
    mcp_tool_call_allowed,
    mcp_tool_call_denied,
    mcp_tool_call_approval_requested,
    mcp_resources_list,
    mcp_resource_read,
    mcp_prompts_list,
    mcp_prompt_get,
    mcp_sampling_request,
    mcp_unknown_method,
    secret_redacted,
    phantom_swap,
    phantom_denied,
    user_approval,
    user_denial,
    audit_degraded,
};

pub const DecisionInput = struct {
    result: DecisionResult,
    reason: []const u8,
    rule_id: ?[]const u8 = null,
    risk_score: ?u8 = null,
    requires_user: bool = false,
    ci_may_proceed: bool = false,
};

pub const AuditEventInput = struct {
    session_id: SessionId,
    event_id: EventId,
    timestamp: Timestamp,
    event_type: EventType,
    actor: Actor,
    target: Target,
    decision: ?Decision = null,
    redactions: core_mod.event.RedactionSummary = .{},
};

pub fn generateSessionId(now: Timestamp) !SessionId {
    return core_mod.session.generateSessionId(now);
}

pub fn generateEventId(now: Timestamp) !EventId {
    return core_mod.event.generateEventId(now);
}

pub fn detectOs() core_mod.platform.Os {
    return core_mod.platform.detectOs();
}

/// Parse a YAML policy from an in-memory string and return an opaque `Policy` handle.
/// The caller owns the returned pointer and must call `deinit()` on it.
/// The `source_path` is used for error diagnostics only and is not retained.
pub fn parsePolicyFromSlice(allocator: std.mem.Allocator, text: []const u8, source_path: ?[]const u8) !*Policy {
    var parsed = try policy_engine.load.parseFromSlice(allocator, text, source_path);
    errdefer parsed.deinit();
    return wrapPolicy(allocator, parsed);
}

/// Load a policy from a file on disk and return an opaque `Policy` handle.
/// The caller owns the returned pointer and must call `deinit()` on it.
pub fn loadPolicyFile(io: std.Io, allocator: std.mem.Allocator, path: []const u8) !*Policy {
    var loaded = try policy_engine.load.loadFile(io, allocator, path);
    errdefer loaded.deinit();
    return wrapPolicy(allocator, loaded);
}

/// Load a built-in policy preset and return an opaque `Policy` handle.
/// The caller owns the returned pointer and must call `deinit()` on it.
pub fn loadPolicyPreset(allocator: std.mem.Allocator, preset: Preset) !*Policy {
    var loaded = try policy_engine.load.loadPreset(allocator, preset);
    errdefer loaded.deinit();
    return wrapPolicy(allocator, loaded);
}

/// Discover a policy file by searching well-known paths, returning a `LoadedPolicy`.
/// The caller owns the result and must call `deinit()` on it.
pub fn discoverPolicy(io: std.Io, allocator: std.mem.Allocator, explicit_path: ?[]const u8, workspace_root: []const u8) !LoadedPolicy {
    var loaded = try policy_engine.load.discover(io, allocator, explicit_path, workspace_root);
    errdefer loaded.deinit();
    const wrapped = try wrapPolicy(allocator, loaded.policy);
    return .{
        .policy = wrapped,
        .source = loaded.source,
        .path = loaded.path,
        .allocator = allocator,
    };
}

pub fn validatePolicy(value: *const Policy) !void {
    return policy_engine.validate.policy(policyInner(value));
}

pub fn evaluateAction(allocator: std.mem.Allocator, value: *const Policy, requested: Action, context: EvaluationContext) !Evaluation {
    const inner = policyInner(value);
    return switch (requested) {
        .env_read => |env_action| policy_engine.evaluate.action(inner, .{ .env_read = .{ .name = env_action.name } }, context, allocator),
        .file_read => |file| policy_engine.evaluate.action(inner, .{ .file_read = .{ .path = file.path } }, context, allocator),
        .file_write => |file| policy_engine.evaluate.action(inner, .{ .file_write = .{ .path = file.path } }, context, allocator),
        .command_exec => |command_action| policy_engine.evaluate.action(inner, .{ .command_exec = .{ .argv = command_action.argv } }, context, allocator),
        .network_connect => |network_action| policy_engine.evaluate.action(inner, .{ .network_connect = .{
            .host = network_action.host,
            .port = network_action.port,
            .scheme = network_action.scheme,
        } }, context, allocator),
        .approval_decision => |approval| policy_engine.evaluate.action(inner, .{ .approval_decision = .{
            .target = toCoreTarget(approval.target),
            .requested_scope = approval.requested_scope,
        } }, context, allocator),
        .staging_decision => |staging| policy_engine.evaluate.action(inner, .{ .staging_decision = .{ .path = staging.path } }, context, allocator),
        .extension => |extension| evaluateExtensionAction(allocator, inner, extension, context),
        .mcp_tool_call => |mcp| policy_engine.evaluate.action(inner, .{ .mcp_tool_call = .{ .server = mcp.server, .tool_name = mcp.tool_name } }, context, allocator),
    };
}

pub fn explainAction(allocator: std.mem.Allocator, policy: *const Policy, kind: policy_engine.explain.ExplainKind, target: []const u8) !Evaluation {
    return policy_engine.explain.explain(allocator, policyInner(policy), kind, target);
}

pub fn explainActionWithOptions(allocator: std.mem.Allocator, policy: *const Policy, kind: policy_engine.explain.ExplainKind, target: []const u8, options: policy_engine.explain.ExplainOptions) !Evaluation {
    return policy_engine.explain.explainWithOptions(allocator, policyInner(policy), kind, target, options);
}

pub fn writePolicyExplanation(writer: anytype, value: *const Policy, evaluation: Evaluation) !void {
    try policy_engine.explain.write(writer, policyInner(value), evaluation);
}

pub fn makeDecision(input: DecisionInput) Decision {
    return .{
        .result = input.result,
        .rule_id = input.rule_id,
        .reason = input.reason,
        .risk_score = input.risk_score,
        .requires_user = input.requires_user,
        .ci_may_proceed = input.ci_may_proceed,
    };
}

pub fn createAuditEvent(input: AuditEventInput) !core_mod.event.Event {
    return .{
        .session_id = input.session_id,
        .event_id = input.event_id,
        .timestamp = input.timestamp,
        .event_type = toCoreEventType(input.event_type),
        .actor = toCoreActor(input.actor),
        .target = toCoreTarget(input.target),
        .decision = input.decision,
        .redactions = input.redactions,
    };
}

pub fn createAuditWriter(io: std.Io, allocator: std.mem.Allocator, session: Session) !AuditWriter {
    return AuditWriter.init(io, allocator, session);
}

pub fn createAuditWriterWithDirName(
    io: std.Io,
    allocator: std.mem.Allocator,
    session: Session,
    audit_dir_name: []const u8,
) !AuditWriter {
    return AuditWriter.initWithDirName(io, allocator, session, audit_dir_name);
}

pub fn openAuditWriter(io: std.Io, allocator: std.mem.Allocator, workspace_root: []const u8, session_id: []const u8) !AuditWriter {
    return AuditWriter.openExisting(io, allocator, workspace_root, session_id);
}

pub fn appendAuditEvent(writer: *AuditWriter, event: core_mod.event.Event) !void {
    try writer.appendEvent(event);
}

pub fn writeAuditSummary(allocator: std.mem.Allocator, session_dir_path: []const u8, input: SummaryInput) !void {
    try audit.summary.writeFiles(allocator, session_dir_path, input);
}

pub fn updateAuditSummaryFinalHash(allocator: std.mem.Allocator, session_dir_path: []const u8, event_count: usize, final_event_hash: []const u8) !void {
    try audit.summary.updateFinalHash(allocator, session_dir_path, event_count, final_event_hash);
}

pub fn redactString(value: []const u8) []const u8 {
    return audit.redact_bridge.redactString(value);
}

pub fn redactStringBounded(value: []const u8, buffer: []u8) []const u8 {
    return audit.redact_bridge.redactStringBounded(value, buffer);
}

pub fn redactTargetValueBounded(kind_name: []const u8, value: []const u8, buffer: []u8) []const u8 {
    return audit.redact_bridge.redactTargetValueBounded(kind_name, value, buffer);
}

pub fn verifyReplay(io: std.Io, allocator: std.mem.Allocator, session_dir_path: []const u8) !VerifyResult {
    return audit.replay.verifySessionDir(io, allocator, session_dir_path);
}

pub fn loadReplay(io: std.Io, allocator: std.mem.Allocator, workspace_root: []const u8, options: ReplayOptions) !ReplaySession {
    return audit.replay.load(io, allocator, workspace_root, options);
}

pub fn writeReplayJson(writer: anytype, replay: ReplaySession) !void {
    try audit.replay.writeJson(writer, replay);
}

pub fn writeReplayHuman(writer: anytype, replay: ReplaySession, show_verify: bool) !void {
    try audit.replay.writeHuman(writer, replay, show_verify);
}

fn evaluateExtensionAction(
    allocator: std.mem.Allocator,
    value: *const policy_engine.schema.Policy,
    extension: ExtensionAction,
    context: EvaluationContext,
) !Evaluation {
    const mode = context.mode orelse value.mode;
    const decision_value = modeDefault(mode);
    const actual = if (mode == .ci and decision_value == .ask) policy_engine.schema.DecisionValue.deny else decision_value;
    const explanation = try std.fmt.allocPrint(
        allocator,
        "extension {s}.{s} on {s}: {s}",
        .{ extension.domain, extension.operation, extension.target, if (mode == .ci and decision_value == .ask) "ask converted to deny in ci mode" else actual.toString() },
    );
    return .{
        .decision = .{
            .result = actual.toDecisionResult(),
            .reason = explanation,
            .requires_user = actual == .ask,
            .ci_may_proceed = actual == .allow or actual == .observe,
        },
        .explanation = explanation,
    };
}

fn modeDefault(mode: policy_engine.schema.Mode) policy_engine.schema.DecisionValue {
    return switch (mode) {
        .observe => .observe,
        .ask, .yolo, .trusted => .ask,
        .strict, .ci, .redteam => .deny,
    };
}

fn wrapPolicy(allocator: std.mem.Allocator, value: policy_engine.schema.Policy) !*Policy {
    const boxed = try allocator.create(PolicyInner);
    boxed.* = .{ .value = value, .allocator = allocator };
    return @ptrCast(@alignCast(boxed));
}

fn toCoreActor(actor: Actor) core_mod.types.Actor {
    return .{
        .kind = switch (actor.kind) {
            .user => .user,
            .agent => .agent,
            .process => .process,
            .core => .ryk,
            .ryk => .ryk,
            .unknown => .unknown,
        },
        .id = actor.id,
        .display = actor.display,
    };
}

fn toCoreTarget(target: Target) core_mod.types.Target {
    return .{
        .kind = switch (target.kind) {
            .env_var => .env_var,
            .file_path => .file_path,
            .command => .command,
            .network_endpoint => .network_endpoint,
            .approval => .approval,
            .staging_area => .staging_area,
            .extension => .extension,
            .session => .session,
            .mcp_tool => .mcp_tool,
            .mcp_resource => .mcp_resource,
            .mcp_prompt => .mcp_prompt,
            .mcp_sampling => .mcp_sampling,
            .extension_target => .extension_target,
            .unknown => .unknown,
        },
        .value = target.value,
    };
}

pub fn fromCoreTargetKind(value: core_mod.types.TargetKind) TargetKind {
    return switch (value) {
        .env_var => .env_var,
        .file_path => .file_path,
        .command => .command,
        .network_endpoint => .network_endpoint,
        .approval => .approval,
        .staging_area => .staging_area,
        .extension => .extension,
        .session => .session,
        .mcp_tool => .mcp_tool,
        .mcp_resource => .mcp_resource,
        .mcp_prompt => .mcp_prompt,
        .mcp_sampling => .mcp_sampling,
        .extension_target => .extension_target,
        .unknown => .unknown,
    };
}

fn toCoreEventType(value: EventType) core_mod.event.EventType {
    return switch (value) {
        .extension_event => .extension_event,
        .session_start => .session_start,
        .session_exit => .session_exit,
        .policy_loaded => .policy_loaded,
        .backend_capability => .backend_capability,
        .sandbox_posture => .sandbox_posture,
        .os_fs_deny => .os_fs_deny,
        .process_launch => .process_launch,
        .file_read_attempt => .file_read_attempt,
        .file_read_allowed => .file_read_allowed,
        .file_read_denied => .file_read_denied,
        .file_write_attempt => .file_write_attempt,
        .file_write_staged => .file_write_staged,
        .file_write_denied => .file_write_denied,
        .file_apply => .file_apply,
        .file_discard => .file_discard,
        .command_attempt => .command_attempt,
        .command_approval_requested => .command_approval_requested,
        .command_allowed => .command_allowed,
        .command_denied => .command_denied,
        .network_connect_attempt => .network_connect_attempt,
        .network_connect_allowed => .network_connect_allowed,
        .network_connect_denied => .network_connect_denied,
        .network_proxy_start => .network_proxy_start,
        .network_proxy_stop => .network_proxy_stop,
        .network_exfiltration_suspected => .network_exfiltration_suspected,
        .mcp_initialize => .mcp_initialize,
        .mcp_tools_list => .mcp_tools_list,
        .mcp_tool_metadata_flagged => .mcp_tool_metadata_flagged,
        .mcp_tool_call => .mcp_tool_call,
        .mcp_tool_call_allowed => .mcp_tool_call_allowed,
        .mcp_tool_call_denied => .mcp_tool_call_denied,
        .mcp_tool_call_approval_requested => .mcp_tool_call_approval_requested,
        .mcp_resources_list => .mcp_resources_list,
        .mcp_resource_read => .mcp_resource_read,
        .mcp_prompts_list => .mcp_prompts_list,
        .mcp_prompt_get => .mcp_prompt_get,
        .mcp_sampling_request => .mcp_sampling_request,
        .mcp_unknown_method => .mcp_unknown_method,
        .secret_redacted => .secret_redacted,
        .phantom_swap => .phantom_swap,
        .phantom_denied => .phantom_denied,
        .user_approval => .user_approval,
        .user_denial => .user_denial,
        .audit_degraded => .audit_degraded,
    };
}

pub fn fromCoreEventType(value: core_mod.event.EventType) EventType {
    return switch (value) {
        .extension_event => .extension_event,
        .session_start => .session_start,
        .session_exit => .session_exit,
        .policy_loaded => .policy_loaded,
        .backend_capability => .backend_capability,
        .sandbox_posture => .sandbox_posture,
        .os_fs_deny => .os_fs_deny,
        .process_launch => .process_launch,
        .file_read_attempt => .file_read_attempt,
        .file_read_allowed => .file_read_allowed,
        .file_read_denied => .file_read_denied,
        .file_write_attempt => .file_write_attempt,
        .file_write_staged => .file_write_staged,
        .file_write_denied => .file_write_denied,
        .file_apply => .file_apply,
        .file_discard => .file_discard,
        .command_attempt => .command_attempt,
        .command_approval_requested => .command_approval_requested,
        .command_allowed => .command_allowed,
        .command_denied => .command_denied,
        .network_connect_attempt => .network_connect_attempt,
        .network_connect_allowed => .network_connect_allowed,
        .network_connect_denied => .network_connect_denied,
        .network_proxy_start => .network_proxy_start,
        .network_proxy_stop => .network_proxy_stop,
        .network_exfiltration_suspected => .network_exfiltration_suspected,
        .mcp_initialize => .mcp_initialize,
        .mcp_tools_list => .mcp_tools_list,
        .mcp_tool_metadata_flagged => .mcp_tool_metadata_flagged,
        .mcp_tool_call => .mcp_tool_call,
        .mcp_tool_call_allowed => .mcp_tool_call_allowed,
        .mcp_tool_call_denied => .mcp_tool_call_denied,
        .mcp_tool_call_approval_requested => .mcp_tool_call_approval_requested,
        .mcp_resources_list => .mcp_resources_list,
        .mcp_resource_read => .mcp_resource_read,
        .mcp_prompts_list => .mcp_prompts_list,
        .mcp_prompt_get => .mcp_prompt_get,
        .mcp_sampling_request => .mcp_sampling_request,
        .mcp_unknown_method => .mcp_unknown_method,
        .secret_redacted => .secret_redacted,
        .phantom_swap => .phantom_swap,
        .phantom_denied => .phantom_denied,
        .user_approval => .user_approval,
        .user_denial => .user_denial,
        .audit_degraded => .audit_degraded,
    };
}

test "core API evaluates generic policy actions and redacts strings" {
    var selected = try parsePolicyFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\commands:
        \\  allow:
        \\    - "echo *"
    , "core-api-test.yaml");
    defer selected.deinit();

    var evaluation = try evaluateAction(std.testing.allocator, selected, .{ .command_exec = .{ .argv = &.{ "echo", "ok" } } }, .{});
    defer evaluation.deinit(std.testing.allocator);
    try std.testing.expectEqual(DecisionResult.allow, evaluation.decision.result);

    const redacted = redactString("TOKEN=fake_secret_value_phase25");
    try std.testing.expect(std.mem.indexOf(u8, redacted, "fake_secret_value_phase25") == null);
}

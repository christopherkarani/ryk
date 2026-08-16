const std = @import("std");

const core = @import("../core/public.zig");
const effect_packs = @import("effects/packs.zig");

pub const version: u16 = 1;

pub const Mode = enum {
    observe,
    ask,
    /// YOLO + seatbelt: first-class UX mode that shares the **ask** severity matrix.
    /// Continues under sandbox + hard fence; critical/catastrophe is never softened.
    /// Maps to core `.ask` via `toCoreMode`; `isEnforcing` is false (not refuse-all).
    yolo,
    strict,
    ci,
    redteam,
    trusted,

    pub fn parse(value: []const u8) ?Mode {
        inline for (@typeInfo(Mode).@"enum".fields) |field| {
            if (std.mem.eql(u8, value, field.name)) return @enumFromInt(field.value);
        }
        return null;
    }

    pub fn toString(self: Mode) []const u8 {
        return @tagName(self);
    }

    pub fn toCoreMode(self: Mode) core.types.Mode {
        return switch (self) {
            .observe, .trusted => .observe,
            .ask, .yolo => .ask,
            .strict, .redteam => .strict,
            .ci => .ci,
        };
    }

    /// Modes that fail closed on unavailable residual classifier (Phase D).
    pub fn isEnforcing(self: Mode) bool {
        return switch (self) {
            .strict, .ci, .redteam => true,
            .observe, .ask, .yolo, .trusted => false,
        };
    }
};

pub const DecisionValue = enum {
    allow,
    deny,
    ask,
    observe,

    pub fn parse(value: []const u8) ?DecisionValue {
        inline for (@typeInfo(DecisionValue).@"enum".fields) |field| {
            if (std.mem.eql(u8, value, field.name)) return @enumFromInt(field.value);
        }
        return null;
    }

    pub fn toDecisionResult(self: DecisionValue) core.decision.DecisionResult {
        return switch (self) {
            .allow => .allow,
            .deny => .deny,
            .ask => .ask,
            .observe => .observe,
        };
    }

    pub fn toString(self: DecisionValue) []const u8 {
        return @tagName(self);
    }
};

pub const WriteMode = enum {
    staged,
    direct,

    pub fn parse(value: []const u8) ?WriteMode {
        if (std.mem.eql(u8, value, "staged")) return .staged;
        if (std.mem.eql(u8, value, "direct")) return .direct;
        return null;
    }

    pub fn toString(self: WriteMode) []const u8 {
        return @tagName(self);
    }
};

pub const AuditLevel = enum {
    full,
    minimal,

    pub fn parse(value: []const u8) ?AuditLevel {
        if (std.mem.eql(u8, value, "full")) return .full;
        if (std.mem.eql(u8, value, "minimal")) return .minimal;
        return null;
    }
};

pub const RuleSet = struct {
    allow: []const []const u8 = &.{},
    deny: []const []const u8 = &.{},
    ask: []const []const u8 = &.{},
    default: ?DecisionValue = null,

    pub fn deinit(self: RuleSet, allocator: std.mem.Allocator) void {
        freeStringList(allocator, self.allow);
        freeStringList(allocator, self.deny);
        freeStringList(allocator, self.ask);
    }
};

pub const WorkspacePolicy = struct {
    root: []const u8 = ".",
    write_mode: WriteMode = .staged,

    pub fn deinit(self: WorkspacePolicy, allocator: std.mem.Allocator) void {
        allocator.free(self.root);
    }
};

pub const EnvPolicy = struct {
    inherit: bool = false,
    allow: []const []const u8 = &.{},
    deny_patterns: []const []const u8 = &.{},
    ask: []const []const u8 = &.{},
    default: ?DecisionValue = null,

    pub fn deinit(self: EnvPolicy, allocator: std.mem.Allocator) void {
        freeStringList(allocator, self.allow);
        freeStringList(allocator, self.deny_patterns);
        freeStringList(allocator, self.ask);
    }
};

pub const FilesPolicy = struct {
    read: RuleSet = .{},
    write: RuleSet = .{},
    write_mode: WriteMode = .staged,

    pub fn deinit(self: FilesPolicy, allocator: std.mem.Allocator) void {
        self.read.deinit(allocator);
        self.write.deinit(allocator);
    }
};

pub const CommandsPolicy = RuleSet;

pub const NetworkMode = enum {
    off,
    ask,
    allowlist,
    observe,
    open,

    pub fn parse(value: []const u8) ?NetworkMode {
        inline for (@typeInfo(NetworkMode).@"enum".fields) |field| {
            if (std.mem.eql(u8, value, field.name)) return @enumFromInt(field.value);
        }
        return null;
    }

    pub fn toString(self: NetworkMode) []const u8 {
        return @tagName(self);
    }
};

pub const NetworkBackend = enum {
    decision_only,
    proxy,

    pub fn parse(value: []const u8) ?NetworkBackend {
        if (std.mem.eql(u8, value, "decision-only") or std.mem.eql(u8, value, "decision_only")) return .decision_only;
        if (std.mem.eql(u8, value, "proxy")) return .proxy;
        return null;
    }

    pub fn toString(self: NetworkBackend) []const u8 {
        return switch (self) {
            .decision_only => "decision-only",
            .proxy => "proxy",
        };
    }
};

pub const ExfiltrationDetection = struct {
    dns: bool = true,
    long_query_strings: bool = true,
    secret_patterns: bool = true,
};

pub const NetworkPolicy = struct {
    mode: ?NetworkMode = null,
    backend: ?NetworkBackend = null,
    allow: []const []const u8 = &.{},
    deny: []const []const u8 = &.{},
    ask: []const []const u8 = &.{},
    default: ?DecisionValue = null,
    detect_exfiltration: ExfiltrationDetection = .{},

    pub fn effectiveMode(self: NetworkPolicy) NetworkMode {
        if (self.mode) |mode| return mode;
        if (self.default) |default| {
            return switch (default) {
                .allow => .open,
                .deny => .allowlist,
                .ask => .ask,
                .observe => .observe,
            };
        }
        return .allowlist;
    }

    pub fn effectiveBackend(self: NetworkPolicy) NetworkBackend {
        return self.backend orelse .decision_only;
    }

    pub fn deinit(self: NetworkPolicy, allocator: std.mem.Allocator) void {
        freeStringList(allocator, self.allow);
        freeStringList(allocator, self.deny);
        freeStringList(allocator, self.ask);
    }
};

pub const ServicePathPolicy = struct {
    allow: []const []const u8 = &.{},
    deny: []const []const u8 = &.{},

    pub fn deinit(self: ServicePathPolicy, allocator: std.mem.Allocator) void {
        freeStringList(allocator, self.allow);
        freeStringList(allocator, self.deny);
    }
};

pub const ServiceCredentials = struct {
    use: ?[]const u8 = null,

    pub fn deinit(self: ServiceCredentials, allocator: std.mem.Allocator) void {
        if (self.use) |value| allocator.free(value);
    }
};

pub const ServicePolicy = struct {
    name: []const u8,
    hosts: []const []const u8 = &.{},
    methods: []const []const u8 = &.{},
    paths: ServicePathPolicy = .{},
    credentials: ServiceCredentials = .{},
    unmatched: ?DecisionValue = null,

    pub fn deinit(self: ServicePolicy, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        freeStringList(allocator, self.hosts);
        freeStringList(allocator, self.methods);
        self.paths.deinit(allocator);
        self.credentials.deinit(allocator);
    }
};

pub const MCPPolicy = RuleSet;

/// Optional residual effect classifier (Phase D). Off by default.
/// `local` / `local-embed` enable pure-Zig prototype/token similarity — no cloud.
pub const EffectsClassifier = enum {
    off,
    local,

    pub fn parse(value: []const u8) ?EffectsClassifier {
        if (std.mem.eql(u8, value, "off")) return .off;
        if (std.mem.eql(u8, value, "local")) return .local;
        // Plan language alias; same pure-Zig residual engine in v1 (not neural embed).
        if (std.mem.eql(u8, value, "local-embed") or std.mem.eql(u8, value, "local_embed")) return .local;
        return null;
    }

    pub fn isEnabled(self: EffectsClassifier) bool {
        return self != .off;
    }
};

/// Effect-class policy (semantic tool intent). Inactive unless `configured` is true
/// (the `effects:` key was present in the policy document).
pub const EffectsPolicy = struct {
    configured: bool = false,
    allow: []const []const u8 = &.{},
    deny: []const []const u8 = &.{},
    ask: []const []const u8 = &.{},
    default: ?DecisionValue = null,
    /// Residual classifier; default off when omitted.
    classifier: EffectsClassifier = .off,

    pub fn isActive(self: EffectsPolicy) bool {
        return self.configured;
    }

    pub fn deinit(self: EffectsPolicy, allocator: std.mem.Allocator) void {
        freeStringList(allocator, self.allow);
        freeStringList(allocator, self.deny);
        freeStringList(allocator, self.ask);
    }
};

pub const CredentialBrokerKind = enum {
    local_dummy,
    env_file_dev,
    onepassword_cli,
    macos_keychain,
    infisical_agent_vault,

    pub fn parse(value: []const u8) ?CredentialBrokerKind {
        if (std.mem.eql(u8, value, "local-dummy") or std.mem.eql(u8, value, "local_dummy")) return .local_dummy;
        if (std.mem.eql(u8, value, "env-file-dev") or std.mem.eql(u8, value, "env_file_dev")) return .env_file_dev;
        if (std.mem.eql(u8, value, "1password-cli") or std.mem.eql(u8, value, "onepassword-cli") or std.mem.eql(u8, value, "onepassword_cli")) return .onepassword_cli;
        if (std.mem.eql(u8, value, "macos-keychain") or std.mem.eql(u8, value, "macos_keychain")) return .macos_keychain;
        if (std.mem.eql(u8, value, "infisical-agent-vault") or std.mem.eql(u8, value, "infisical_agent_vault")) return .infisical_agent_vault;
        return null;
    }

    pub fn toString(self: CredentialBrokerKind) []const u8 {
        return switch (self) {
            .local_dummy => "local-dummy",
            .env_file_dev => "env-file-dev",
            .onepassword_cli => "1password-cli",
            .macos_keychain => "macos-keychain",
            .infisical_agent_vault => "infisical-agent-vault",
        };
    }
};

pub const CredentialBrokerPolicy = struct {
    name: []const u8,
    kind: CredentialBrokerKind,
    account: ?[]const u8 = null,
    path: ?[]const u8 = null,

    pub fn deinit(self: CredentialBrokerPolicy, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        if (self.account) |value| allocator.free(value);
        if (self.path) |value| allocator.free(value);
    }
};

pub const CredentialRefPolicy = struct {
    name: []const u8,
    broker: ?[]const u8 = null,
    ref: []const u8,

    pub fn deinit(self: CredentialRefPolicy, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        if (self.broker) |value| allocator.free(value);
        allocator.free(self.ref);
    }
};

pub const CredentialProvider = enum {
    anthropic,
    openai,

    pub fn parse(value: []const u8) ?CredentialProvider {
        if (std.mem.eql(u8, value, "anthropic")) return .anthropic;
        if (std.mem.eql(u8, value, "openai")) return .openai;
        return null;
    }

    pub fn toString(self: CredentialProvider) []const u8 {
        return @tagName(self);
    }
};

pub const CredentialGrantSource = enum {
    host_env,
    broker,

    pub fn parse(value: []const u8) ?CredentialGrantSource {
        if (std.mem.eql(u8, value, "host_env")) return .host_env;
        if (std.mem.eql(u8, value, "broker")) return .broker;
        return null;
    }

    pub fn toString(self: CredentialGrantSource) []const u8 {
        return @tagName(self);
    }
};

pub const CredentialGrantPolicy = struct {
    name: []const u8,
    env_var: []const u8,
    provider: CredentialProvider,
    source: CredentialGrantSource,
    credential_ref: ?[]const u8 = null,
    allowed_hosts: []const []const u8 = &.{},

    pub fn deinit(self: CredentialGrantPolicy, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.env_var);
        if (self.credential_ref) |value| allocator.free(value);
        freeStringList(allocator, self.allowed_hosts);
    }
};

pub const CredentialsPolicy = struct {
    default_broker: ?[]const u8 = null,
    brokers: []const CredentialBrokerPolicy = &.{},
    refs: []const CredentialRefPolicy = &.{},
    grants: []const CredentialGrantPolicy = &.{},

    pub fn deinit(self: CredentialsPolicy, allocator: std.mem.Allocator) void {
        if (self.default_broker) |value| allocator.free(value);
        for (self.brokers) |broker| broker.deinit(allocator);
        if (self.brokers.len > 0) allocator.free(self.brokers);
        for (self.refs) |credential_ref| credential_ref.deinit(allocator);
        if (self.refs.len > 0) allocator.free(self.refs);
        for (self.grants) |grant| grant.deinit(allocator);
        if (self.grants.len > 0) allocator.free(self.grants);
    }
};

pub const AuditPolicy = struct {
    level: AuditLevel = .full,
    redact_secrets: bool = true,
    tamper_evident: bool = true,
};

pub const Policy = struct {
    version_value: u16 = version,
    mode: Mode = .strict,
    workspace: WorkspacePolicy = .{ .root = "." },
    env: EnvPolicy = .{},
    files: FilesPolicy = .{},
    commands: CommandsPolicy = .{},
    network: NetworkPolicy = .{},
    credentials: CredentialsPolicy = .{},
    services: []const ServicePolicy = &.{},
    mcp: MCPPolicy = .{},
    effects: EffectsPolicy = .{},
    audit: AuditPolicy = .{},
    source_path: ?[]const u8 = null,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Policy) void {
        self.workspace.deinit(self.allocator);
        self.env.deinit(self.allocator);
        self.files.deinit(self.allocator);
        self.commands.deinit(self.allocator);
        self.network.deinit(self.allocator);
        self.credentials.deinit(self.allocator);
        for (self.services) |service| service.deinit(self.allocator);
        if (self.services.len > 0) self.allocator.free(self.services);
        self.mcp.deinit(self.allocator);
        self.effects.deinit(self.allocator);
        if (self.source_path) |path| self.allocator.free(path);
        self.* = undefined;
    }
};

pub const RuleRef = struct {
    id: []const u8,
    pattern: []const u8,
};

pub const Evaluation = struct {
    decision: core.decision.Decision,
    matched_rule: ?RuleRef = null,
    explanation: []const u8,
    owned_rule_id: ?[]const u8 = null,

    pub fn deinit(self: Evaluation, allocator: std.mem.Allocator) void {
        allocator.free(self.explanation);
        if (self.owned_rule_id) |rule_id| allocator.free(rule_id);
    }
};

pub const EvaluationContext = struct {
    mode: ?Mode = null,
    /// Optional user effect packs (classification only). Owned by caller for the evaluation lifetime.
    effect_packs: ?*const effect_packs.PackSet = null,
};

pub const LoadSource = enum {
    cli,
    workspace,
    user,
    builtin,
};

pub const LoadedPolicy = struct {
    policy: Policy,
    source: LoadSource,
    path: []const u8,

    pub fn deinit(self: *LoadedPolicy) void {
        const allocator = self.policy.allocator;
        self.policy.deinit();
        allocator.free(self.path);
        self.* = undefined;
    }

    pub fn mode(self: *const LoadedPolicy) Mode {
        return self.policy.mode;
    }

    pub fn innerPtr(self: *const LoadedPolicy) *const Policy {
        return &self.policy;
    }
};

pub fn duplicateStringList(allocator: std.mem.Allocator, values: []const []const u8) ![]const []const u8 {
    if (values.len == 0) return &.{};
    var out = try allocator.alloc([]const u8, values.len);
    errdefer allocator.free(out);
    var owned: usize = 0;
    errdefer {
        for (out[0..owned]) |value| allocator.free(value);
    }
    for (values, 0..) |value, index| {
        out[index] = try allocator.dupe(u8, value);
        owned += 1;
    }
    return out;
}

pub fn freeStringList(allocator: std.mem.Allocator, values: []const []const u8) void {
    for (values) |value| allocator.free(value);
    if (values.len > 0) allocator.free(values);
}

test "policy modes parse all phase 07 modes" {
    try std.testing.expectEqual(Mode.observe, Mode.parse("observe").?);
    try std.testing.expectEqual(Mode.ask, Mode.parse("ask").?);
    try std.testing.expectEqual(Mode.strict, Mode.parse("strict").?);
    try std.testing.expectEqual(Mode.ci, Mode.parse("ci").?);
    try std.testing.expectEqual(Mode.redteam, Mode.parse("redteam").?);
    try std.testing.expectEqual(Mode.trusted, Mode.parse("trusted").?);
    try std.testing.expectEqual(@as(?Mode, null), Mode.parse("invalid"));
}

test "Mode.parse yolo is first-class and maps like ask" {
    // Phase 2: YOLO + seatbelt — explicit mode that shares the ask severity matrix.
    try std.testing.expectEqual(Mode.yolo, Mode.parse("yolo").?);
    try std.testing.expectEqualStrings("yolo", Mode.yolo.toString());
    try std.testing.expectEqual(core.types.Mode.ask, Mode.yolo.toCoreMode());
    try std.testing.expect(!Mode.yolo.isEnforcing());
}

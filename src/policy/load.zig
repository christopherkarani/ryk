const std = @import("std");

const core = @import("../core/public.zig");
const presets = @import("presets.zig");
const schema = @import("schema.zig");
const validate = @import("validate.zig");

pub const PolicyParseError = error{
    InvalidPolicy,
    UnsupportedPolicyVersion,
    UnsupportedPolicyMode,
    UnsupportedPolicyDecision,
    UnsupportedPolicyWriteMode,
    UnsupportedPolicyAuditLevel,
    PolicyFileTooLarge,
    MissingPolicyVersion,
    MissingPolicyMode,
};

const Section = enum {
    root,
    workspace,
    env,
    files,
    files_read,
    files_write,
    commands,
    network,
    network_detect_exfiltration,
    credentials,
    credentials_brokers,
    credentials_broker,
    credentials_refs,
    credentials_ref,
    credentials_grants,
    credentials_grant,
    services,
    service,
    service_paths,
    service_credentials,
    mcp,
    mcp_servers,
    mcp_server,
    mcp_server_tools,
    effects,
    audit,
    ignored,
};

const ListTarget = enum {
    none,
    env_allow,
    env_deny,
    env_ask,
    files_read_allow,
    files_read_deny,
    files_read_ask,
    files_write_allow,
    files_write_deny,
    files_write_ask,
    commands_allow,
    commands_deny,
    commands_ask,
    network_allow,
    network_deny,
    network_ask,
    credential_grant_allowed_hosts,
    service_hosts,
    service_methods,
    service_path_allow,
    service_path_deny,
    mcp_allow,
    mcp_deny,
    mcp_ask,
    effects_allow,
    effects_deny,
    effects_ask,
};

const ServiceBuilder = struct {
    name: []const u8,
    hosts: std.ArrayList([]const u8) = .empty,
    methods: std.ArrayList([]const u8) = .empty,
    path_allow: std.ArrayList([]const u8) = .empty,
    path_deny: std.ArrayList([]const u8) = .empty,
    credential_use: ?[]const u8 = null,
    unmatched: ?schema.DecisionValue = null,

    fn deinit(self: *ServiceBuilder, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        freeList(allocator, &self.hosts);
        freeList(allocator, &self.methods);
        freeList(allocator, &self.path_allow);
        freeList(allocator, &self.path_deny);
        if (self.credential_use) |value| allocator.free(value);
        self.* = undefined;
    }

    fn append(self: *ServiceBuilder, allocator: std.mem.Allocator, target: ListTarget, value: []const u8) !void {
        const owned = try allocator.dupe(u8, value);
        errdefer allocator.free(owned);
        switch (target) {
            .service_hosts => try self.hosts.append(allocator, owned),
            .service_methods => try self.methods.append(allocator, owned),
            .service_path_allow => try self.path_allow.append(allocator, owned),
            .service_path_deny => try self.path_deny.append(allocator, owned),
            else => return error.InvalidPolicy,
        }
    }

    fn toPolicy(self: *ServiceBuilder, allocator: std.mem.Allocator) !schema.ServicePolicy {
        var out: schema.ServicePolicy = .{
            .name = try allocator.dupe(u8, self.name),
            .unmatched = self.unmatched,
        };
        errdefer out.deinit(allocator);
        out.hosts = try duplicateListFromArray(allocator, self.hosts.items);
        out.methods = try duplicateListFromArray(allocator, self.methods.items);
        out.paths.allow = try duplicateListFromArray(allocator, self.path_allow.items);
        out.paths.deny = try duplicateListFromArray(allocator, self.path_deny.items);
        out.credentials.use = if (self.credential_use) |value| try allocator.dupe(u8, value) else null;
        return out;
    }
};

const CredentialBrokerBuilder = struct {
    name: []const u8,
    kind: ?schema.CredentialBrokerKind = null,
    account: ?[]const u8 = null,
    path: ?[]const u8 = null,

    fn deinit(self: *CredentialBrokerBuilder, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        if (self.account) |value| allocator.free(value);
        if (self.path) |value| allocator.free(value);
        self.* = undefined;
    }

    fn toPolicy(self: *CredentialBrokerBuilder, allocator: std.mem.Allocator) !schema.CredentialBrokerPolicy {
        const kind = self.kind orelse return error.InvalidPolicy;
        const owned_name = try allocator.dupe(u8, self.name);
        errdefer allocator.free(owned_name);
        const owned_account = if (self.account) |value| try allocator.dupe(u8, value) else null;
        errdefer if (owned_account) |value| allocator.free(value);
        const owned_path = if (self.path) |value| try allocator.dupe(u8, value) else null;
        errdefer if (owned_path) |value| allocator.free(value);

        return .{
            .name = owned_name,
            .kind = kind,
            .account = owned_account,
            .path = owned_path,
        };
    }
};

const CredentialRefBuilder = struct {
    name: []const u8,
    broker: ?[]const u8 = null,
    ref: ?[]const u8 = null,

    fn deinit(self: *CredentialRefBuilder, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        if (self.broker) |value| allocator.free(value);
        if (self.ref) |value| allocator.free(value);
        self.* = undefined;
    }

    fn toPolicy(self: *CredentialRefBuilder, allocator: std.mem.Allocator) !schema.CredentialRefPolicy {
        const ref = self.ref orelse return error.InvalidPolicy;
        const owned_name = try allocator.dupe(u8, self.name);
        errdefer allocator.free(owned_name);
        const owned_broker = if (self.broker) |value| try allocator.dupe(u8, value) else null;
        errdefer if (owned_broker) |value| allocator.free(value);
        const owned_ref = try allocator.dupe(u8, ref);
        errdefer allocator.free(owned_ref);

        return .{
            .name = owned_name,
            .broker = owned_broker,
            .ref = owned_ref,
        };
    }
};

const CredentialGrantBuilder = struct {
    name: []const u8,
    env_var: ?[]const u8 = null,
    provider: ?schema.CredentialProvider = null,
    source: ?schema.CredentialGrantSource = null,
    credential_ref: ?[]const u8 = null,
    saw_credential_ref: bool = false,
    allowed_hosts: std.ArrayList([]const u8) = .empty,

    fn deinit(self: *CredentialGrantBuilder, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        if (self.env_var) |value| allocator.free(value);
        if (self.credential_ref) |value| allocator.free(value);
        freeList(allocator, &self.allowed_hosts);
        self.* = undefined;
    }

    fn setCredentialRef(self: *CredentialGrantBuilder, allocator: std.mem.Allocator, value: []const u8) !void {
        if (self.saw_credential_ref) return error.InvalidPolicy;
        self.credential_ref = try allocator.dupe(u8, value);
        self.saw_credential_ref = true;
    }

    fn appendAllowedHost(self: *CredentialGrantBuilder, allocator: std.mem.Allocator, value: []const u8) !void {
        const owned = try allocator.dupe(u8, value);
        errdefer allocator.free(owned);
        try self.allowed_hosts.append(allocator, owned);
    }

    fn toPolicy(self: *CredentialGrantBuilder, allocator: std.mem.Allocator) !schema.CredentialGrantPolicy {
        const env_var = self.env_var orelse return error.InvalidPolicy;
        const provider = self.provider orelse return error.InvalidPolicy;
        const source = self.source orelse return error.InvalidPolicy;

        const owned_name = try allocator.dupe(u8, self.name);
        errdefer allocator.free(owned_name);
        const owned_env_var = try allocator.dupe(u8, env_var);
        errdefer allocator.free(owned_env_var);
        const owned_credential_ref = if (self.credential_ref) |value| try allocator.dupe(u8, value) else null;
        errdefer if (owned_credential_ref) |value| allocator.free(value);
        const owned_allowed_hosts = try duplicateListFromArray(allocator, self.allowed_hosts.items);
        errdefer schema.freeStringList(allocator, owned_allowed_hosts);

        return .{
            .name = owned_name,
            .env_var = owned_env_var,
            .provider = provider,
            .source = source,
            .credential_ref = owned_credential_ref,
            .allowed_hosts = owned_allowed_hosts,
        };
    }
};

const Builder = struct {
    allocator: std.mem.Allocator,
    saw_version: bool = false,
    version_value: u16 = 0,
    mode: ?schema.Mode = null,
    workspace_root: ?[]const u8 = null,
    workspace_write_mode: schema.WriteMode = .staged,
    env_inherit: bool = false,
    env_allow: std.ArrayList([]const u8) = .empty,
    env_deny: std.ArrayList([]const u8) = .empty,
    env_ask: std.ArrayList([]const u8) = .empty,
    env_default: ?schema.DecisionValue = null,
    files_read_allow: std.ArrayList([]const u8) = .empty,
    files_read_deny: std.ArrayList([]const u8) = .empty,
    files_read_ask: std.ArrayList([]const u8) = .empty,
    files_read_default: ?schema.DecisionValue = null,
    files_write_allow: std.ArrayList([]const u8) = .empty,
    files_write_deny: std.ArrayList([]const u8) = .empty,
    files_write_ask: std.ArrayList([]const u8) = .empty,
    files_write_default: ?schema.DecisionValue = null,
    files_write_mode: schema.WriteMode = .staged,
    commands_allow: std.ArrayList([]const u8) = .empty,
    commands_deny: std.ArrayList([]const u8) = .empty,
    commands_ask: std.ArrayList([]const u8) = .empty,
    commands_default: ?schema.DecisionValue = null,
    network_allow: std.ArrayList([]const u8) = .empty,
    network_deny: std.ArrayList([]const u8) = .empty,
    network_ask: std.ArrayList([]const u8) = .empty,
    network_default: ?schema.DecisionValue = null,
    network_mode: ?schema.NetworkMode = null,
    network_backend: ?schema.NetworkBackend = null,
    network_detect_exfiltration: schema.ExfiltrationDetection = .{},
    credentials_default_broker: ?[]const u8 = null,
    credential_brokers: std.ArrayList(CredentialBrokerBuilder) = .empty,
    active_credential_broker_index: ?usize = null,
    credential_refs: std.ArrayList(CredentialRefBuilder) = .empty,
    active_credential_ref_index: ?usize = null,
    credential_grants: std.ArrayList(CredentialGrantBuilder) = .empty,
    active_credential_grant_index: ?usize = null,
    services: std.ArrayList(ServiceBuilder) = .empty,
    active_service_index: ?usize = null,
    mcp_allow: std.ArrayList([]const u8) = .empty,
    mcp_deny: std.ArrayList([]const u8) = .empty,
    mcp_ask: std.ArrayList([]const u8) = .empty,
    mcp_default: ?schema.DecisionValue = null,
    active_mcp_server: ?[]const u8 = null,
    effects_configured: bool = false,
    effects_allow: std.ArrayList([]const u8) = .empty,
    effects_deny: std.ArrayList([]const u8) = .empty,
    effects_ask: std.ArrayList([]const u8) = .empty,
    effects_default: ?schema.DecisionValue = null,
    effects_classifier: schema.EffectsClassifier = .off,
    audit_level: schema.AuditLevel = .full,
    audit_redact_secrets: bool = true,
    audit_tamper_evident: bool = true,

    fn init(allocator: std.mem.Allocator) Builder {
        return .{ .allocator = allocator };
    }

    fn deinit(self: *Builder) void {
        if (self.workspace_root) |root| self.allocator.free(root);
        freeList(self.allocator, &self.env_allow);
        freeList(self.allocator, &self.env_deny);
        freeList(self.allocator, &self.env_ask);
        freeList(self.allocator, &self.files_read_allow);
        freeList(self.allocator, &self.files_read_deny);
        freeList(self.allocator, &self.files_read_ask);
        freeList(self.allocator, &self.files_write_allow);
        freeList(self.allocator, &self.files_write_deny);
        freeList(self.allocator, &self.files_write_ask);
        freeList(self.allocator, &self.commands_allow);
        freeList(self.allocator, &self.commands_deny);
        freeList(self.allocator, &self.commands_ask);
        freeList(self.allocator, &self.network_allow);
        freeList(self.allocator, &self.network_deny);
        freeList(self.allocator, &self.network_ask);
        if (self.credentials_default_broker) |value| self.allocator.free(value);
        for (self.credential_brokers.items) |*broker| broker.deinit(self.allocator);
        self.credential_brokers.deinit(self.allocator);
        for (self.credential_refs.items) |*credential_ref| credential_ref.deinit(self.allocator);
        self.credential_refs.deinit(self.allocator);
        for (self.credential_grants.items) |*grant| grant.deinit(self.allocator);
        self.credential_grants.deinit(self.allocator);
        for (self.services.items) |*service| service.deinit(self.allocator);
        self.services.deinit(self.allocator);
        freeList(self.allocator, &self.mcp_allow);
        freeList(self.allocator, &self.mcp_deny);
        freeList(self.allocator, &self.mcp_ask);
        if (self.active_mcp_server) |server| self.allocator.free(server);
        freeList(self.allocator, &self.effects_allow);
        freeList(self.allocator, &self.effects_deny);
        freeList(self.allocator, &self.effects_ask);
    }

    fn append(self: *Builder, target: ListTarget, value: []const u8) !void {
        if (target == .credential_grant_allowed_hosts) {
            const grant = self.activeCredentialGrant() orelse return error.InvalidPolicy;
            try grant.appendAllowedHost(self.allocator, value);
            return;
        }
        if (target == .service_hosts or target == .service_methods or target == .service_path_allow or target == .service_path_deny) {
            const service = self.activeService() orelse return error.InvalidPolicy;
            try service.append(self.allocator, target, value);
            return;
        }
        const owned = if ((target == .mcp_allow or target == .mcp_deny or target == .mcp_ask) and self.active_mcp_server != null)
            try std.fmt.allocPrint(self.allocator, "{s}.{s}", .{ self.active_mcp_server.?, value })
        else
            try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(owned);
        switch (target) {
            .env_allow => try self.env_allow.append(self.allocator, owned),
            .env_deny => try self.env_deny.append(self.allocator, owned),
            .env_ask => try self.env_ask.append(self.allocator, owned),
            .files_read_allow => try self.files_read_allow.append(self.allocator, owned),
            .files_read_deny => try self.files_read_deny.append(self.allocator, owned),
            .files_read_ask => try self.files_read_ask.append(self.allocator, owned),
            .files_write_allow => try self.files_write_allow.append(self.allocator, owned),
            .files_write_deny => try self.files_write_deny.append(self.allocator, owned),
            .files_write_ask => try self.files_write_ask.append(self.allocator, owned),
            .commands_allow => try self.commands_allow.append(self.allocator, owned),
            .commands_deny => try self.commands_deny.append(self.allocator, owned),
            .commands_ask => try self.commands_ask.append(self.allocator, owned),
            .network_allow => try self.network_allow.append(self.allocator, owned),
            .network_deny => try self.network_deny.append(self.allocator, owned),
            .network_ask => try self.network_ask.append(self.allocator, owned),
            .credential_grant_allowed_hosts => unreachable,
            .service_hosts, .service_methods, .service_path_allow, .service_path_deny => unreachable,
            .mcp_allow => try self.mcp_allow.append(self.allocator, owned),
            .mcp_deny => try self.mcp_deny.append(self.allocator, owned),
            .mcp_ask => try self.mcp_ask.append(self.allocator, owned),
            .effects_allow => try self.effects_allow.append(self.allocator, owned),
            .effects_deny => try self.effects_deny.append(self.allocator, owned),
            .effects_ask => try self.effects_ask.append(self.allocator, owned),
            .none => return error.InvalidPolicy,
        }
    }

    fn startService(self: *Builder, name: []const u8) !void {
        const owned = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned);
        try self.services.append(self.allocator, .{ .name = owned });
        self.active_service_index = self.services.items.len - 1;
    }

    fn startCredentialBroker(self: *Builder, name: []const u8) !void {
        const owned = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned);
        try self.credential_brokers.append(self.allocator, .{ .name = owned });
        self.active_credential_broker_index = self.credential_brokers.items.len - 1;
    }

    fn activeCredentialBroker(self: *Builder) ?*CredentialBrokerBuilder {
        const index = self.active_credential_broker_index orelse return null;
        if (index >= self.credential_brokers.items.len) return null;
        return &self.credential_brokers.items[index];
    }

    fn startCredentialRef(self: *Builder, name: []const u8) !void {
        const owned = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned);
        try self.credential_refs.append(self.allocator, .{ .name = owned });
        self.active_credential_ref_index = self.credential_refs.items.len - 1;
    }

    fn activeCredentialRef(self: *Builder) ?*CredentialRefBuilder {
        const index = self.active_credential_ref_index orelse return null;
        if (index >= self.credential_refs.items.len) return null;
        return &self.credential_refs.items[index];
    }

    fn startCredentialGrant(self: *Builder, name: []const u8) !void {
        const owned = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned);
        try self.credential_grants.append(self.allocator, .{ .name = owned });
        self.active_credential_grant_index = self.credential_grants.items.len - 1;
    }

    fn activeCredentialGrant(self: *Builder) ?*CredentialGrantBuilder {
        const index = self.active_credential_grant_index orelse return null;
        if (index >= self.credential_grants.items.len) return null;
        return &self.credential_grants.items[index];
    }

    fn activeService(self: *Builder) ?*ServiceBuilder {
        const index = self.active_service_index orelse return null;
        if (index >= self.services.items.len) return null;
        return &self.services.items[index];
    }

    fn toPolicy(self: *Builder, source_path: ?[]const u8) !schema.Policy {
        if (!self.saw_version) return error.MissingPolicyVersion;
        if (self.version_value != schema.version) return error.UnsupportedPolicyVersion;
        const mode = self.mode orelse return error.MissingPolicyMode;

        var policy: schema.Policy = .{
            .version_value = self.version_value,
            .mode = mode,
            .workspace = .{ .root = &.{}, .write_mode = self.workspace_write_mode },
            .env = .{ .inherit = self.env_inherit, .default = self.env_default },
            .files = .{
                .read = .{ .default = self.files_read_default },
                .write = .{ .default = self.files_write_default },
                .write_mode = self.files_write_mode,
            },
            .commands = .{ .default = self.commands_default },
            .network = .{ .mode = self.network_mode, .backend = self.network_backend, .default = self.network_default, .detect_exfiltration = self.network_detect_exfiltration },
            .credentials = .{},
            .services = &.{},
            .mcp = .{ .default = self.mcp_default },
            .effects = .{
                .configured = self.effects_configured,
                .default = self.effects_default,
                .classifier = self.effects_classifier,
            },
            .audit = .{
                .level = self.audit_level,
                .redact_secrets = self.audit_redact_secrets,
                .tamper_evident = self.audit_tamper_evident,
            },
            .allocator = self.allocator,
        };
        errdefer policy.deinit();
        policy.workspace.root = if (self.workspace_root) |root| try self.allocator.dupe(u8, root) else try self.allocator.dupe(u8, ".");
        policy.env.allow = try self.env_allow.toOwnedSlice(self.allocator);
        policy.env.deny_patterns = try self.env_deny.toOwnedSlice(self.allocator);
        policy.env.ask = try self.env_ask.toOwnedSlice(self.allocator);
        policy.files.read.allow = try self.files_read_allow.toOwnedSlice(self.allocator);
        policy.files.read.deny = try self.files_read_deny.toOwnedSlice(self.allocator);
        policy.files.read.ask = try self.files_read_ask.toOwnedSlice(self.allocator);
        policy.files.write.allow = try self.files_write_allow.toOwnedSlice(self.allocator);
        policy.files.write.deny = try self.files_write_deny.toOwnedSlice(self.allocator);
        policy.files.write.ask = try self.files_write_ask.toOwnedSlice(self.allocator);
        policy.commands.allow = try self.commands_allow.toOwnedSlice(self.allocator);
        policy.commands.deny = try self.commands_deny.toOwnedSlice(self.allocator);
        policy.commands.ask = try self.commands_ask.toOwnedSlice(self.allocator);
        policy.network.allow = try self.network_allow.toOwnedSlice(self.allocator);
        policy.network.deny = try self.network_deny.toOwnedSlice(self.allocator);
        policy.network.ask = try self.network_ask.toOwnedSlice(self.allocator);
        policy.credentials.default_broker = if (self.credentials_default_broker) |value| try self.allocator.dupe(u8, value) else null;
        policy.credentials.brokers = try self.toOwnedCredentialBrokerPolicies();
        policy.credentials.refs = try self.toOwnedCredentialRefPolicies();
        policy.credentials.grants = try self.toOwnedCredentialGrantPolicies();
        policy.services = try self.toOwnedServicePolicies();
        policy.mcp.allow = try self.mcp_allow.toOwnedSlice(self.allocator);
        policy.mcp.deny = try self.mcp_deny.toOwnedSlice(self.allocator);
        policy.mcp.ask = try self.mcp_ask.toOwnedSlice(self.allocator);
        policy.effects.allow = try self.effects_allow.toOwnedSlice(self.allocator);
        policy.effects.deny = try self.effects_deny.toOwnedSlice(self.allocator);
        policy.effects.ask = try self.effects_ask.toOwnedSlice(self.allocator);
        policy.source_path = if (source_path) |path| try self.allocator.dupe(u8, path) else null;
        try validate.policy(&policy);
        return policy;
    }

    fn toOwnedServicePolicies(self: *Builder) ![]const schema.ServicePolicy {
        if (self.services.items.len == 0) return &.{};
        var out = try self.allocator.alloc(schema.ServicePolicy, self.services.items.len);
        var initialized: usize = 0;
        errdefer {
            for (out[0..initialized]) |service| service.deinit(self.allocator);
            self.allocator.free(out);
        }
        for (self.services.items, 0..) |*service, index| {
            out[index] = try service.toPolicy(self.allocator);
            initialized += 1;
        }
        return out;
    }

    fn toOwnedCredentialBrokerPolicies(self: *Builder) ![]const schema.CredentialBrokerPolicy {
        if (self.credential_brokers.items.len == 0) return &.{};
        var out = try self.allocator.alloc(schema.CredentialBrokerPolicy, self.credential_brokers.items.len);
        var initialized: usize = 0;
        errdefer {
            for (out[0..initialized]) |broker| broker.deinit(self.allocator);
            self.allocator.free(out);
        }
        for (self.credential_brokers.items, 0..) |*broker, index| {
            out[index] = try broker.toPolicy(self.allocator);
            initialized += 1;
        }
        return out;
    }

    fn toOwnedCredentialRefPolicies(self: *Builder) ![]const schema.CredentialRefPolicy {
        if (self.credential_refs.items.len == 0) return &.{};
        var out = try self.allocator.alloc(schema.CredentialRefPolicy, self.credential_refs.items.len);
        var initialized: usize = 0;
        errdefer {
            for (out[0..initialized]) |credential_ref| credential_ref.deinit(self.allocator);
            self.allocator.free(out);
        }
        for (self.credential_refs.items, 0..) |*credential_ref, index| {
            out[index] = try credential_ref.toPolicy(self.allocator);
            initialized += 1;
        }
        return out;
    }

    fn toOwnedCredentialGrantPolicies(self: *Builder) ![]const schema.CredentialGrantPolicy {
        if (self.credential_grants.items.len == 0) return &.{};
        var out = try self.allocator.alloc(schema.CredentialGrantPolicy, self.credential_grants.items.len);
        var initialized: usize = 0;
        errdefer {
            for (out[0..initialized]) |grant| grant.deinit(self.allocator);
            self.allocator.free(out);
        }
        for (self.credential_grants.items, 0..) |*grant, index| {
            out[index] = try grant.toPolicy(self.allocator);
            initialized += 1;
        }
        return out;
    }
};

fn freeList(allocator: std.mem.Allocator, list: *std.ArrayList([]const u8)) void {
    for (list.items) |value| allocator.free(value);
    list.deinit(allocator);
}

fn duplicateListFromArray(allocator: std.mem.Allocator, values: []const []const u8) ![]const []const u8 {
    return try schema.duplicateStringList(allocator, values);
}

pub fn parseFromSlice(allocator: std.mem.Allocator, text: []const u8, source_path: ?[]const u8) !schema.Policy {
    if (text.len > core.limits.max_policy_file_len) return error.PolicyFileTooLarge;
    const trimmed = std.mem.trim(u8, text, " \t\r\n");
    if (trimmed.len == 0) return error.InvalidPolicy;
    if (trimmed[0] == '{') return parseJson(allocator, trimmed, source_path);
    return parseYaml(allocator, trimmed, source_path);
}

pub fn loadFile(io: std.Io, allocator: std.mem.Allocator, path: []const u8) !schema.Policy {
    const text = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, std.Io.Limit.limited(core.limits.max_policy_file_len + 1));
    defer allocator.free(text);
    if (text.len > core.limits.max_policy_file_len) return error.PolicyFileTooLarge;
    return parseFromSlice(allocator, text, path);
}

pub fn loadPreset(allocator: std.mem.Allocator, preset: presets.Preset) !schema.Policy {
    const source = try std.fmt.allocPrint(allocator, "builtin:{s}", .{@tagName(preset)});
    defer allocator.free(source);
    return parseFromSlice(allocator, presets.text(preset), source);
}

pub fn loadAgentPreset(allocator: std.mem.Allocator, preset: presets.AgentPreset) !schema.Policy {
    const source = try std.fmt.allocPrint(allocator, "preset:{s}", .{presets.agentPresetName(preset)});
    defer allocator.free(source);
    return parseFromSlice(allocator, presets.agentPresetText(preset), source);
}

pub fn discover(
    io: std.Io,
    allocator: std.mem.Allocator,
    cli_policy_path: ?[]const u8,
    workspace_root: []const u8,
) !schema.LoadedPolicy {
    if (cli_policy_path) |path| {
        const policy = try loadFile(io, allocator, path);
        return loadedPolicyWithPath(allocator, policy, .cli, path);
    }

    const workspace_path = try std.fs.path.join(allocator, &.{ workspace_root, ".ryk", "policy.yaml" });
    defer allocator.free(workspace_path);
    if (loadFile(io, allocator, workspace_path)) |policy| {
        return loadedPolicyWithPath(allocator, policy, .workspace, workspace_path);
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }

    if (std.c.getenv("HOME")) |home_c| {
        const home = std.mem.sliceTo(home_c, 0);
        // Canonical user fallback (XDG-style) — install/ensure seeds this path.
        const user_path = try std.fs.path.join(allocator, &.{ home, ".config", "ryk", "policy.yaml" });
        defer allocator.free(user_path);
        if (loadFile(io, allocator, user_path)) |policy| {
            return loadedPolicyWithPath(allocator, policy, .user, user_path);
        } else |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        }
        // Legacy HOME workspace policy as user fallback; prefer .config when both exist.
        const home_workspace_path = try std.fs.path.join(allocator, &.{ home, ".ryk", "policy.yaml" });
        defer allocator.free(home_workspace_path);
        // Skip when workspace_root is already HOME (matched workspace step above).
        if (!std.mem.eql(u8, workspace_path, home_workspace_path)) {
            if (loadFile(io, allocator, home_workspace_path)) |policy| {
                return loadedPolicyWithPath(allocator, policy, .user, home_workspace_path);
            } else |err| switch (err) {
                error.FileNotFound => {},
                else => return err,
            }
        }
    }

    const policy = try loadPreset(allocator, presets.defaultPreset());
    return loadedPolicyWithPath(allocator, policy, .builtin, "builtin:strict");
}

fn loadedPolicyWithPath(
    allocator: std.mem.Allocator,
    policy: schema.Policy,
    source: schema.LoadSource,
    fallback_path: []const u8,
) !schema.LoadedPolicy {
    var owned_policy = policy;
    errdefer owned_policy.deinit();
    return .{
        .policy = owned_policy,
        .source = source,
        .path = try allocator.dupe(u8, owned_policy.source_path orelse fallback_path),
    };
}

fn parseYaml(allocator: std.mem.Allocator, text: []const u8, source_path: ?[]const u8) !schema.Policy {
    var builder = Builder.init(allocator);
    defer builder.deinit();

    var section: Section = .root;
    var list_target: ListTarget = .none;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw_line| {
        const cleaned = stripComment(std.mem.trimEnd(u8, raw_line, " \t\r"));
        if (std.mem.trim(u8, cleaned, " \t").len == 0) continue;
        const indent = countIndent(cleaned);
        if (indent % 2 != 0) return error.InvalidPolicy;
        const line = std.mem.trim(u8, cleaned[indent..], " \t");

        if (std.mem.startsWith(u8, line, "- ")) {
            try builder.append(list_target, try parseScalar(line[2..]));
            continue;
        }

        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.InvalidPolicy;
        const key = std.mem.trim(u8, line[0..colon], " \t");
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");

        list_target = .none;
        if (indent == 0) {
            section = .root;
            if (std.mem.eql(u8, key, "version")) {
                builder.version_value = try parseU16(value);
                builder.saw_version = true;
            } else if (std.mem.eql(u8, key, "mode")) {
                builder.mode = schema.Mode.parse(try parseScalar(value)) orelse return error.UnsupportedPolicyMode;
            } else if (std.mem.eql(u8, key, "workspace")) {
                try requireEmptyGroupingValue(value);
                section = .workspace;
            } else if (std.mem.eql(u8, key, "env")) {
                try requireEmptyGroupingValue(value);
                section = .env;
            } else if (std.mem.eql(u8, key, "files")) {
                try requireEmptyGroupingValue(value);
                section = .files;
            } else if (std.mem.eql(u8, key, "commands")) {
                try requireEmptyGroupingValue(value);
                section = .commands;
            } else if (std.mem.eql(u8, key, "network")) {
                try requireEmptyGroupingValue(value);
                section = .network;
            } else if (std.mem.eql(u8, key, "credentials")) {
                try requireEmptyGroupingValue(value);
                section = .credentials;
            } else if (std.mem.eql(u8, key, "services")) {
                try requireEmptyGroupingValue(value);
                section = .services;
            } else if (std.mem.eql(u8, key, "mcp")) {
                try requireEmptyGroupingValue(value);
                section = .mcp;
            } else if (std.mem.eql(u8, key, "effects")) {
                try requireEmptyGroupingValue(value);
                builder.effects_configured = true;
                section = .effects;
            } else if (std.mem.eql(u8, key, "audit")) {
                try requireEmptyGroupingValue(value);
                section = .audit;
            } else {
                return error.InvalidPolicy;
            }
            continue;
        }

        if (indent == 2 and (section == .credentials_broker or section == .credentials_ref or section == .credentials_grant or section == .credentials_grants)) {
            section = .credentials;
        }

        if (indent == 2 and section == .credentials) {
            if (std.mem.eql(u8, key, "default_broker")) {
                if (builder.credentials_default_broker) |old| builder.allocator.free(old);
                builder.credentials_default_broker = try builder.allocator.dupe(u8, try parseScalar(value));
            } else if (std.mem.eql(u8, key, "brokers")) {
                try requireEmptyGroupingValue(value);
                section = .credentials_brokers;
            } else if (std.mem.eql(u8, key, "refs")) {
                try requireEmptyGroupingValue(value);
                section = .credentials_refs;
            } else if (std.mem.eql(u8, key, "grants")) {
                try requireEmptyGroupingValue(value);
                section = .credentials_grants;
            } else return error.InvalidPolicy;
            continue;
        }

        if (indent == 4 and section == .credentials_brokers) {
            try requireEmptyGroupingValue(value);
            try builder.startCredentialBroker(key);
            section = .credentials_broker;
            continue;
        }

        if (indent == 6 and section == .credentials_broker) {
            const broker = builder.activeCredentialBroker() orelse return error.InvalidPolicy;
            if (std.mem.eql(u8, key, "type")) {
                broker.kind = schema.CredentialBrokerKind.parse(try parseScalar(value)) orelse return error.InvalidPolicy;
            } else if (std.mem.eql(u8, key, "account")) {
                if (broker.account) |old| builder.allocator.free(old);
                broker.account = try builder.allocator.dupe(u8, try parseScalar(value));
            } else if (std.mem.eql(u8, key, "path")) {
                if (broker.path) |old| builder.allocator.free(old);
                broker.path = try builder.allocator.dupe(u8, try parseScalar(value));
            } else return error.InvalidPolicy;
            continue;
        }

        if (indent == 4 and section == .credentials_refs) {
            try requireEmptyGroupingValue(value);
            try builder.startCredentialRef(key);
            section = .credentials_ref;
            continue;
        }

        if (indent == 6 and section == .credentials_ref) {
            const credential_ref = builder.activeCredentialRef() orelse return error.InvalidPolicy;
            if (std.mem.eql(u8, key, "broker")) {
                if (credential_ref.broker) |old| builder.allocator.free(old);
                credential_ref.broker = try builder.allocator.dupe(u8, try parseScalar(value));
            } else if (std.mem.eql(u8, key, "ref")) {
                if (credential_ref.ref) |old| builder.allocator.free(old);
                credential_ref.ref = try builder.allocator.dupe(u8, try parseScalar(value));
            } else return error.InvalidPolicy;
            continue;
        }

        if (indent == 4 and section == .credentials_grant) {
            section = .credentials_grants;
        }

        if (indent == 4 and section == .credentials_grants) {
            try requireEmptyGroupingValue(value);
            try builder.startCredentialGrant(key);
            section = .credentials_grant;
            continue;
        }

        if (indent == 6 and section == .credentials_grant) {
            const grant = builder.activeCredentialGrant() orelse return error.InvalidPolicy;
            if (std.mem.eql(u8, key, "env_var")) {
                if (grant.env_var) |old| builder.allocator.free(old);
                grant.env_var = try builder.allocator.dupe(u8, try parseScalar(value));
            } else if (std.mem.eql(u8, key, "provider")) {
                grant.provider = schema.CredentialProvider.parse(try parseScalar(value)) orelse return error.InvalidPolicy;
            } else if (std.mem.eql(u8, key, "source")) {
                grant.source = schema.CredentialGrantSource.parse(try parseScalar(value)) orelse return error.InvalidPolicy;
            } else if (std.mem.eql(u8, key, "credential_ref") or std.mem.eql(u8, key, "ref")) {
                try grant.setCredentialRef(builder.allocator, try parseScalar(value));
            } else if (std.mem.eql(u8, key, "allowed_hosts")) {
                try requireEmptyGroupingValue(value);
                list_target = .credential_grant_allowed_hosts;
            } else return error.InvalidPolicy;
            continue;
        }

        if (indent == 2 and (section == .services or section == .service or section == .service_paths or section == .service_credentials)) {
            try requireEmptyGroupingValue(value);
            try builder.startService(key);
            section = .service;
            continue;
        }

        if (indent == 4 and (section == .service_paths or section == .service_credentials)) {
            section = .service;
        }

        if (indent == 4 and section == .service) {
            if (std.mem.eql(u8, key, "hosts")) {
                try requireEmptyGroupingValue(value);
                list_target = .service_hosts;
            } else if (std.mem.eql(u8, key, "methods")) {
                try requireEmptyGroupingValue(value);
                list_target = .service_methods;
            } else if (std.mem.eql(u8, key, "paths")) {
                try requireEmptyGroupingValue(value);
                section = .service_paths;
            } else if (std.mem.eql(u8, key, "credentials")) {
                try requireEmptyGroupingValue(value);
                section = .service_credentials;
            } else if (std.mem.eql(u8, key, "unmatched")) {
                const service = builder.activeService() orelse return error.InvalidPolicy;
                service.unmatched = try parseDecision(try parseScalar(value));
            } else return error.InvalidPolicy;
            continue;
        }

        if (indent == 6 and section == .service_paths) {
            if (std.mem.eql(u8, key, "allow")) {
                try requireEmptyGroupingValue(value);
                list_target = .service_path_allow;
            } else if (std.mem.eql(u8, key, "deny")) {
                try requireEmptyGroupingValue(value);
                list_target = .service_path_deny;
            } else return error.InvalidPolicy;
            continue;
        }

        if (indent == 6 and section == .service_credentials) {
            if (!std.mem.eql(u8, key, "use")) return error.InvalidPolicy;
            const service = builder.activeService() orelse return error.InvalidPolicy;
            if (service.credential_use) |old| builder.allocator.free(old);
            service.credential_use = try builder.allocator.dupe(u8, try parseScalar(value));
            continue;
        }

        if (indent == 2 and (section == .mcp or section == .mcp_servers or section == .mcp_server or section == .mcp_server_tools)) {
            section = .mcp;
            if (selfActiveMcpServerClear(&builder)) {}
            try applyYamlField(&builder, section, key, value, &list_target);
            if (std.mem.eql(u8, key, "servers")) section = .mcp_servers;
            continue;
        }

        if (indent == 4 and (section == .mcp_servers or section == .mcp_server or section == .mcp_server_tools)) {
            try requireEmptyGroupingValue(value);
            if (builder.active_mcp_server) |server| builder.allocator.free(server);
            builder.active_mcp_server = try builder.allocator.dupe(u8, key);
            section = .mcp_server;
            continue;
        }

        if (indent == 6 and section == .mcp_server) {
            if (!std.mem.eql(u8, key, "tools")) return error.InvalidPolicy;
            try requireEmptyGroupingValue(value);
            section = .mcp_server_tools;
            continue;
        }

        if (indent == 8 and section == .mcp_server_tools) {
            try applyRuleSetField(&builder, .mcp_allow, .mcp_deny, .mcp_ask, &builder.mcp_default, key, try parseScalar(value), &list_target);
            continue;
        }

        if (indent == 2 and (section == .files or section == .files_read or section == .files_write)) {
            if (std.mem.eql(u8, key, "read")) {
                try requireEmptyGroupingValue(value);
                section = .files_read;
                continue;
            } else if (std.mem.eql(u8, key, "write")) {
                try requireEmptyGroupingValue(value);
                section = .files_write;
                continue;
            } else {
                return error.InvalidPolicy;
            }
        }

        if (indent == 2 and section == .network_detect_exfiltration) {
            section = .network;
        }

        if (indent == 2 and section == .network and std.mem.eql(u8, key, "detect_exfiltration")) {
            try requireEmptyGroupingValue(value);
            section = .network_detect_exfiltration;
            continue;
        }

        if (indent == 4 and section == .network_detect_exfiltration) {
            try applyNetworkDetectionField(&builder, key, try parseScalar(value));
            continue;
        }

        try applyYamlField(&builder, section, key, value, &list_target);
    }

    return builder.toPolicy(source_path);
}

fn selfActiveMcpServerClear(builder: *Builder) bool {
    if (builder.active_mcp_server) |server| {
        builder.allocator.free(server);
        builder.active_mcp_server = null;
        return true;
    }
    return false;
}

fn requireEmptyGroupingValue(value: []const u8) !void {
    if (std.mem.trim(u8, value, " \t").len != 0) return error.InvalidPolicy;
}

fn applyYamlField(builder: *Builder, section: Section, key: []const u8, value: []const u8, list_target: *ListTarget) !void {
    const scalar = try parseScalar(value);
    switch (section) {
        .workspace => {
            if (std.mem.eql(u8, key, "root")) {
                if (builder.workspace_root) |root| builder.allocator.free(root);
                builder.workspace_root = try builder.allocator.dupe(u8, scalar);
            } else if (std.mem.eql(u8, key, "write_mode")) {
                builder.workspace_write_mode = schema.WriteMode.parse(scalar) orelse return error.UnsupportedPolicyWriteMode;
            } else return error.InvalidPolicy;
        },
        .env => {
            if (std.mem.eql(u8, key, "inherit")) builder.env_inherit = try parseBool(scalar) else if (std.mem.eql(u8, key, "allow")) list_target.* = .env_allow else if (std.mem.eql(u8, key, "deny_patterns")) list_target.* = .env_deny else if (std.mem.eql(u8, key, "ask")) list_target.* = .env_ask else if (std.mem.eql(u8, key, "default")) builder.env_default = try parseDecision(scalar) else return error.InvalidPolicy;
        },
        .files_read => try applyRuleSetField(builder, .files_read_allow, .files_read_deny, .files_read_ask, &builder.files_read_default, key, scalar, list_target),
        .files_write => {
            if (std.mem.eql(u8, key, "mode")) builder.files_write_mode = schema.WriteMode.parse(scalar) orelse return error.UnsupportedPolicyWriteMode else try applyRuleSetField(builder, .files_write_allow, .files_write_deny, .files_write_ask, &builder.files_write_default, key, scalar, list_target);
        },
        .commands => try applyRuleSetField(builder, .commands_allow, .commands_deny, .commands_ask, &builder.commands_default, key, scalar, list_target),
        .network => {
            if (std.mem.eql(u8, key, "mode")) {
                builder.network_mode = schema.NetworkMode.parse(scalar) orelse return error.UnsupportedPolicyMode;
            } else if (std.mem.eql(u8, key, "backend")) {
                builder.network_backend = schema.NetworkBackend.parse(scalar) orelse return error.InvalidPolicy;
            } else if (std.mem.eql(u8, key, "detect_exfiltration")) {
                list_target.* = .none;
            } else {
                try applyRuleSetField(builder, .network_allow, .network_deny, .network_ask, &builder.network_default, key, scalar, list_target);
            }
        },
        .network_detect_exfiltration => try applyNetworkDetectionField(builder, key, scalar),
        .mcp => {
            if (std.mem.eql(u8, key, "servers")) {
                list_target.* = .none;
            } else {
                try applyRuleSetField(builder, .mcp_allow, .mcp_deny, .mcp_ask, &builder.mcp_default, key, scalar, list_target);
            }
        },
        .effects => {
            if (std.mem.eql(u8, key, "classifier")) {
                list_target.* = .none;
                builder.effects_classifier = schema.EffectsClassifier.parse(scalar) orelse return error.InvalidPolicy;
            } else {
                try applyRuleSetField(builder, .effects_allow, .effects_deny, .effects_ask, &builder.effects_default, key, scalar, list_target);
            }
        },
        .audit => {
            if (std.mem.eql(u8, key, "level")) builder.audit_level = schema.AuditLevel.parse(scalar) orelse return error.UnsupportedPolicyAuditLevel else if (std.mem.eql(u8, key, "redact_secrets")) builder.audit_redact_secrets = try parseBool(scalar) else if (std.mem.eql(u8, key, "tamper_evident")) builder.audit_tamper_evident = try parseBool(scalar) else return error.InvalidPolicy;
        },
        else => return error.InvalidPolicy,
    }
}

fn applyRuleSetField(
    builder: *Builder,
    allow_target: ListTarget,
    deny_target: ListTarget,
    ask_target: ListTarget,
    default_field: *?schema.DecisionValue,
    key: []const u8,
    scalar: []const u8,
    list_target: *ListTarget,
) !void {
    _ = builder;
    if (std.mem.eql(u8, key, "allow")) {
        if (scalar.len != 0) return error.InvalidPolicy;
        list_target.* = allow_target;
    } else if (std.mem.eql(u8, key, "deny")) {
        if (scalar.len != 0) return error.InvalidPolicy;
        list_target.* = deny_target;
    } else if (std.mem.eql(u8, key, "ask")) {
        if (scalar.len != 0) return error.InvalidPolicy;
        list_target.* = ask_target;
    } else if (std.mem.eql(u8, key, "default")) default_field.* = try parseDecision(scalar) else return error.InvalidPolicy;
}

fn applyNetworkDetectionField(builder: *Builder, key: []const u8, scalar: []const u8) !void {
    if (std.mem.eql(u8, key, "dns")) {
        builder.network_detect_exfiltration.dns = try parseBool(scalar);
    } else if (std.mem.eql(u8, key, "long_query_strings")) {
        builder.network_detect_exfiltration.long_query_strings = try parseBool(scalar);
    } else if (std.mem.eql(u8, key, "secret_patterns")) {
        builder.network_detect_exfiltration.secret_patterns = try parseBool(scalar);
    } else return error.InvalidPolicy;
}

fn parseJson(allocator: std.mem.Allocator, text: []const u8, source_path: ?[]const u8) !schema.Policy {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, text, .{}) catch return error.InvalidPolicy;
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidPolicy;
    const object = parsed.value.object;
    try rejectUnknownKeys(object, &.{ "version", "mode", "workspace", "env", "files", "commands", "network", "credentials", "services", "mcp", "effects", "audit" });
    var builder = Builder.init(allocator);
    defer builder.deinit();

    if (object.get("version")) |value| {
        if (value != .integer or value.integer < 0 or value.integer > std.math.maxInt(u16)) return error.InvalidPolicy;
        builder.version_value = @intCast(value.integer);
        builder.saw_version = true;
    }
    if (object.get("mode")) |value| builder.mode = schema.Mode.parse(try expectString(value)) orelse return error.UnsupportedPolicyMode;
    if (object.get("workspace")) |value| try parseJsonWorkspace(&builder, value);
    if (object.get("env")) |value| try parseJsonEnv(&builder, value);
    if (object.get("files")) |value| try parseJsonFiles(&builder, value);
    if (object.get("commands")) |value| try parseJsonRules(&builder, value, .commands_allow, .commands_deny, .commands_ask, &builder.commands_default);
    if (object.get("network")) |value| try parseJsonNetwork(&builder, value);
    if (object.get("credentials")) |value| try parseJsonCredentials(&builder, value);
    if (object.get("services")) |value| try parseJsonServices(&builder, value);
    if (object.get("mcp")) |value| try parseJsonMcp(&builder, value);
    if (object.get("effects")) |value| try parseJsonEffects(&builder, value);
    if (object.get("audit")) |value| try parseJsonAudit(&builder, value);
    return builder.toPolicy(source_path);
}

fn parseJsonEffects(builder: *Builder, value: std.json.Value) !void {
    builder.effects_configured = true;
    try parseJsonRulesWithKeys(builder, value, .effects_allow, .effects_deny, .effects_ask, &builder.effects_default, &.{ "allow", "deny", "ask", "default", "classifier" });
    if (value == .object) {
        if (value.object.get("classifier")) |classifier| {
            builder.effects_classifier = schema.EffectsClassifier.parse(try expectString(classifier)) orelse return error.InvalidPolicy;
        }
    }
}

fn parseJsonWorkspace(builder: *Builder, value: std.json.Value) !void {
    if (value != .object) return error.InvalidPolicy;
    const object = value.object;
    try rejectUnknownKeys(object, &.{ "root", "write_mode" });
    if (object.get("root")) |root| builder.workspace_root = try builder.allocator.dupe(u8, try expectString(root));
    if (object.get("write_mode")) |mode| builder.workspace_write_mode = schema.WriteMode.parse(try expectString(mode)) orelse return error.UnsupportedPolicyWriteMode;
}

fn parseJsonEnv(builder: *Builder, value: std.json.Value) !void {
    if (value != .object) return error.InvalidPolicy;
    const object = value.object;
    try rejectUnknownKeys(object, &.{ "inherit", "allow", "deny_patterns", "ask", "default" });
    if (object.get("inherit")) |inherit| builder.env_inherit = try expectBool(inherit);
    if (object.get("allow")) |list| try appendJsonList(builder, .env_allow, list);
    if (object.get("deny_patterns")) |list| try appendJsonList(builder, .env_deny, list);
    if (object.get("ask")) |list| try appendJsonList(builder, .env_ask, list);
    if (object.get("default")) |default| builder.env_default = schema.DecisionValue.parse(try expectString(default)) orelse return error.UnsupportedPolicyDecision;
}

fn parseJsonFiles(builder: *Builder, value: std.json.Value) !void {
    if (value != .object) return error.InvalidPolicy;
    const object = value.object;
    try rejectUnknownKeys(object, &.{ "read", "write" });
    if (object.get("read")) |read| try parseJsonRules(builder, read, .files_read_allow, .files_read_deny, .files_read_ask, &builder.files_read_default);
    if (object.get("write")) |write| {
        try parseJsonRulesWithKeys(builder, write, .files_write_allow, .files_write_deny, .files_write_ask, &builder.files_write_default, &.{ "allow", "deny", "ask", "default", "mode" });
        if (write == .object) {
            if (write.object.get("mode")) |mode| builder.files_write_mode = schema.WriteMode.parse(try expectString(mode)) orelse return error.UnsupportedPolicyWriteMode;
        }
    }
}

fn parseJsonRules(builder: *Builder, value: std.json.Value, allow: ListTarget, deny: ListTarget, ask: ListTarget, default_field: *?schema.DecisionValue) !void {
    try parseJsonRulesWithKeys(builder, value, allow, deny, ask, default_field, &.{ "allow", "deny", "ask", "default" });
}

fn parseJsonRulesWithKeys(builder: *Builder, value: std.json.Value, allow: ListTarget, deny: ListTarget, ask: ListTarget, default_field: *?schema.DecisionValue, allowed_keys: []const []const u8) !void {
    if (value != .object) return error.InvalidPolicy;
    const object = value.object;
    try rejectUnknownKeys(object, allowed_keys);
    if (object.get("allow")) |list| try appendJsonList(builder, allow, list);
    if (object.get("deny")) |list| try appendJsonList(builder, deny, list);
    if (object.get("ask")) |list| try appendJsonList(builder, ask, list);
    if (object.get("default")) |default| default_field.* = schema.DecisionValue.parse(try expectString(default)) orelse return error.UnsupportedPolicyDecision;
}

fn parseJsonNetwork(builder: *Builder, value: std.json.Value) !void {
    try parseJsonRulesWithKeys(builder, value, .network_allow, .network_deny, .network_ask, &builder.network_default, &.{ "allow", "deny", "ask", "default", "mode", "backend", "detect_exfiltration" });
    if (value.object.get("mode")) |mode| builder.network_mode = schema.NetworkMode.parse(try expectString(mode)) orelse return error.UnsupportedPolicyMode;
    if (value.object.get("backend")) |backend| builder.network_backend = schema.NetworkBackend.parse(try expectString(backend)) orelse return error.InvalidPolicy;
    if (value.object.get("detect_exfiltration")) |detect| {
        if (detect != .object) return error.InvalidPolicy;
        try rejectUnknownKeys(detect.object, &.{ "dns", "long_query_strings", "secret_patterns" });
        if (detect.object.get("dns")) |item| builder.network_detect_exfiltration.dns = try expectBool(item);
        if (detect.object.get("long_query_strings")) |item| builder.network_detect_exfiltration.long_query_strings = try expectBool(item);
        if (detect.object.get("secret_patterns")) |item| builder.network_detect_exfiltration.secret_patterns = try expectBool(item);
    }
}

fn parseJsonCredentials(builder: *Builder, value: std.json.Value) !void {
    if (value != .object) return error.InvalidPolicy;
    const object = value.object;
    try rejectUnknownKeys(object, &.{ "default_broker", "brokers", "refs", "grants" });
    if (object.get("default_broker")) |default_broker| {
        if (builder.credentials_default_broker) |old| builder.allocator.free(old);
        builder.credentials_default_broker = try builder.allocator.dupe(u8, try expectString(default_broker));
    }
    if (object.get("brokers")) |brokers| {
        if (brokers != .object) return error.InvalidPolicy;
        var it = brokers.object.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.* != .object) return error.InvalidPolicy;
            try rejectUnknownKeys(entry.value_ptr.*.object, &.{ "type", "account", "path" });
            try builder.startCredentialBroker(entry.key_ptr.*);
            const broker = builder.activeCredentialBroker() orelse return error.InvalidPolicy;
            const type_value = entry.value_ptr.*.object.get("type") orelse return error.InvalidPolicy;
            broker.kind = schema.CredentialBrokerKind.parse(try expectString(type_value)) orelse return error.InvalidPolicy;
            if (entry.value_ptr.*.object.get("account")) |account| broker.account = try builder.allocator.dupe(u8, try expectString(account));
            if (entry.value_ptr.*.object.get("path")) |path| broker.path = try builder.allocator.dupe(u8, try expectString(path));
        }
    }
    if (object.get("refs")) |refs| {
        if (refs != .object) return error.InvalidPolicy;
        var it = refs.object.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.* != .object) return error.InvalidPolicy;
            try rejectUnknownKeys(entry.value_ptr.*.object, &.{ "broker", "ref" });
            try builder.startCredentialRef(entry.key_ptr.*);
            const credential_ref = builder.activeCredentialRef() orelse return error.InvalidPolicy;
            if (entry.value_ptr.*.object.get("broker")) |broker| credential_ref.broker = try builder.allocator.dupe(u8, try expectString(broker));
            const ref_value = entry.value_ptr.*.object.get("ref") orelse return error.InvalidPolicy;
            credential_ref.ref = try builder.allocator.dupe(u8, try expectString(ref_value));
        }
    }
    if (object.get("grants")) |grants| {
        if (grants != .object) return error.InvalidPolicy;
        var it = grants.object.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.* != .object) return error.InvalidPolicy;
            const grant_object = entry.value_ptr.*.object;
            try rejectUnknownKeys(grant_object, &.{ "env_var", "provider", "source", "credential_ref", "ref", "allowed_hosts" });
            try builder.startCredentialGrant(entry.key_ptr.*);
            const grant = builder.activeCredentialGrant() orelse return error.InvalidPolicy;
            const env_var = grant_object.get("env_var") orelse return error.InvalidPolicy;
            grant.env_var = try builder.allocator.dupe(u8, try expectString(env_var));
            const provider = grant_object.get("provider") orelse return error.InvalidPolicy;
            grant.provider = schema.CredentialProvider.parse(try expectString(provider)) orelse return error.InvalidPolicy;
            const source = grant_object.get("source") orelse return error.InvalidPolicy;
            grant.source = schema.CredentialGrantSource.parse(try expectString(source)) orelse return error.InvalidPolicy;
            if (grant_object.get("credential_ref")) |credential_ref| {
                try grant.setCredentialRef(builder.allocator, try expectString(credential_ref));
            }
            if (grant_object.get("ref")) |credential_ref| {
                try grant.setCredentialRef(builder.allocator, try expectString(credential_ref));
            }
            const allowed_hosts = grant_object.get("allowed_hosts") orelse return error.InvalidPolicy;
            if (allowed_hosts != .array) return error.InvalidPolicy;
            for (allowed_hosts.array.items) |host| {
                try grant.appendAllowedHost(builder.allocator, try expectString(host));
            }
        }
    }
}

fn parseJsonServices(builder: *Builder, value: std.json.Value) !void {
    if (value != .object) return error.InvalidPolicy;
    var it = value.object.iterator();
    while (it.next()) |entry| {
        if (entry.value_ptr.* != .object) return error.InvalidPolicy;
        try builder.startService(entry.key_ptr.*);
        const service = builder.activeService() orelse return error.InvalidPolicy;
        const object = entry.value_ptr.*.object;
        try rejectUnknownKeys(object, &.{ "hosts", "methods", "paths", "credentials", "unmatched" });
        if (object.get("hosts")) |hosts| try appendJsonListToService(builder, service, .service_hosts, hosts);
        if (object.get("methods")) |methods| try appendJsonListToService(builder, service, .service_methods, methods);
        if (object.get("paths")) |paths| {
            if (paths != .object) return error.InvalidPolicy;
            try rejectUnknownKeys(paths.object, &.{ "allow", "deny" });
            if (paths.object.get("allow")) |allow| try appendJsonListToService(builder, service, .service_path_allow, allow);
            if (paths.object.get("deny")) |deny| try appendJsonListToService(builder, service, .service_path_deny, deny);
        }
        if (object.get("credentials")) |credentials| {
            if (credentials != .object) return error.InvalidPolicy;
            try rejectUnknownKeys(credentials.object, &.{"use"});
            if (credentials.object.get("use")) |use| service.credential_use = try builder.allocator.dupe(u8, try expectString(use));
        }
        if (object.get("unmatched")) |unmatched| service.unmatched = schema.DecisionValue.parse(try expectString(unmatched)) orelse return error.UnsupportedPolicyDecision;
    }
}

fn appendJsonListToService(builder: *Builder, service: *ServiceBuilder, target: ListTarget, value: std.json.Value) !void {
    if (value != .array) return error.InvalidPolicy;
    for (value.array.items) |item| try service.append(builder.allocator, target, try expectString(item));
}

fn parseJsonMcp(builder: *Builder, value: std.json.Value) !void {
    try parseJsonRulesWithKeys(builder, value, .mcp_allow, .mcp_deny, .mcp_ask, &builder.mcp_default, &.{ "allow", "deny", "ask", "default", "servers" });
    if (value.object.get("servers")) |servers| {
        if (servers != .object) return error.InvalidPolicy;
        var it = servers.object.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.* != .object) return error.InvalidPolicy;
            try rejectUnknownKeys(entry.value_ptr.*.object, &.{"tools"});
            const tools = entry.value_ptr.*.object.get("tools") orelse return error.InvalidPolicy;
            if (tools != .object) return error.InvalidPolicy;
            if (builder.active_mcp_server) |server| builder.allocator.free(server);
            builder.active_mcp_server = try builder.allocator.dupe(u8, entry.key_ptr.*);
            try parseJsonRules(builder, tools, .mcp_allow, .mcp_deny, .mcp_ask, &builder.mcp_default);
            if (builder.active_mcp_server) |server| {
                builder.allocator.free(server);
                builder.active_mcp_server = null;
            }
        }
    }
}

fn parseJsonAudit(builder: *Builder, value: std.json.Value) !void {
    if (value != .object) return error.InvalidPolicy;
    const object = value.object;
    try rejectUnknownKeys(object, &.{ "level", "redact_secrets", "tamper_evident" });
    if (object.get("level")) |level| builder.audit_level = schema.AuditLevel.parse(try expectString(level)) orelse return error.UnsupportedPolicyAuditLevel;
    if (object.get("redact_secrets")) |redact| builder.audit_redact_secrets = try expectBool(redact);
    if (object.get("tamper_evident")) |tamper| builder.audit_tamper_evident = try expectBool(tamper);
}

fn appendJsonList(builder: *Builder, target: ListTarget, value: std.json.Value) !void {
    if (value != .array) return error.InvalidPolicy;
    for (value.array.items) |item| try builder.append(target, try expectString(item));
}

fn rejectUnknownKeys(object: std.json.ObjectMap, allowed_keys: []const []const u8) !void {
    var it = object.iterator();
    while (it.next()) |entry| {
        if (!containsString(allowed_keys, entry.key_ptr.*)) return error.InvalidPolicy;
    }
}

fn containsString(values: []const []const u8, needle: []const u8) bool {
    for (values) |value| {
        if (std.mem.eql(u8, value, needle)) return true;
    }
    return false;
}

fn expectString(value: std.json.Value) ![]const u8 {
    if (value != .string) return error.InvalidPolicy;
    return value.string;
}

fn expectBool(value: std.json.Value) !bool {
    if (value != .bool) return error.InvalidPolicy;
    return value.bool;
}

fn stripComment(line: []const u8) []const u8 {
    var in_quote: ?u8 = null;
    for (line, 0..) |char, index| {
        if (in_quote) |quote| {
            if (char == quote) in_quote = null;
        } else if (char == '"' or char == '\'') {
            in_quote = char;
        } else if (char == '#') {
            return line[0..index];
        }
    }
    return line;
}

fn countIndent(line: []const u8) usize {
    var count: usize = 0;
    while (count < line.len and line[count] == ' ') count += 1;
    return count;
}

fn parseScalar(raw: []const u8) ![]const u8 {
    const value = std.mem.trim(u8, raw, " \t");
    if (value.len >= 2 and ((value[0] == '"' and value[value.len - 1] == '"') or (value[0] == '\'' and value[value.len - 1] == '\''))) {
        return value[1 .. value.len - 1];
    }
    return value;
}

fn parseU16(value: []const u8) !u16 {
    return std.fmt.parseInt(u16, try parseScalar(value), 10) catch return error.InvalidPolicy;
}

fn parseBool(value: []const u8) !bool {
    if (std.mem.eql(u8, value, "true")) return true;
    if (std.mem.eql(u8, value, "false")) return false;
    return error.InvalidPolicy;
}

fn parseDecision(value: []const u8) !schema.DecisionValue {
    return schema.DecisionValue.parse(value) orelse error.UnsupportedPolicyDecision;
}

test "valid YAML policy parsing covers minimum schema" {
    var policy = try parseFromSlice(std.testing.allocator, presets.text(.strict), "builtin:strict");
    defer policy.deinit();

    try std.testing.expectEqual(schema.version, policy.version_value);
    try std.testing.expectEqual(schema.Mode.strict, policy.mode);
    try std.testing.expect(policy.files.read.deny.len >= 1);
    try std.testing.expect(policy.commands.deny.len >= 1);
    try std.testing.expect(policy.network.allow.len >= 1);
}

test "phase 18 preset files validate through policy loader" {
    for (presets.agent_preset_infos) |info| {
        var preset_policy = try loadAgentPreset(std.testing.allocator, info.preset);
        defer preset_policy.deinit();
        try std.testing.expectEqual(schema.version, preset_policy.version_value);
        try std.testing.expect(preset_policy.audit.redact_secrets);
        try std.testing.expect(preset_policy.audit.tamper_evident);
    }
}

test "invalid policies fail closed with clear parser errors" {
    try std.testing.expectError(error.MissingPolicyMode, parseFromSlice(std.testing.allocator, "version: 1\n", "bad.yaml"));
    try std.testing.expectError(error.MissingPolicyVersion, parseFromSlice(std.testing.allocator, "mode: strict\n", "bad.yaml"));
    try std.testing.expectError(error.UnsupportedPolicyMode, parseFromSlice(std.testing.allocator, "version: 1\nmode: loose\n", "bad.yaml"));
    try std.testing.expectError(error.InvalidPolicy, parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\commands:
        \\  deny: ["rm -rf *"]
    , "bad.yaml"));
}

test "policy discovery honors CLI path before workspace policy" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, ".ryk");
    {
        const file = try tmp.dir.createFile(std.testing.io, ".ryk/policy.yaml", .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io, presets.text(.observe));
    }
    {
        const file = try tmp.dir.createFile(std.testing.io, "strict.yaml", .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io, presets.text(.strict));
    }
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const cli_path = try tmp.dir.realPathFileAlloc(std.testing.io, "strict.yaml", std.testing.allocator);
    defer std.testing.allocator.free(cli_path);

    var loaded = try discover(std.testing.io, std.testing.allocator, cli_path, root);
    defer loaded.deinit();
    try std.testing.expectEqual(schema.LoadSource.cli, loaded.source);
    try std.testing.expectEqual(schema.Mode.strict, loaded.policy.mode);
}

test "workspace policy discovery falls back only when missing" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, ".ryk");
    {
        const file = try tmp.dir.createFile(std.testing.io, ".ryk/policy.yaml", .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io, "version: 1\nmode: loose\n");
    }
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    try std.testing.expectError(error.UnsupportedPolicyMode, discover(std.testing.io, std.testing.allocator, null, root));
}

// HOME mutation for discover fallback tests (same pattern as ensure Soft).
extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;
extern "c" fn unsetenv(name: [*:0]const u8) c_int;

test "policy discovery falls back to HOME .ryk policy before builtin strict" {
    // Legacy install wrote only $HOME/.ryk/policy.yaml. Project cwd without local
    // policy must not fall through to builtin:strict when that file exists.
    const io = std.testing.io;
    const allocator = std.testing.allocator;

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    var project_tmp = std.testing.tmpDir(.{});
    defer project_tmp.cleanup();

    try home_tmp.dir.createDirPath(io, ".ryk");
    {
        const f = try home_tmp.dir.createFile(io, ".ryk/policy.yaml", .{});
        defer f.close(io);
        try f.writeStreamingAll(io, presets.agentPresetText(.generic_agent));
    }

    const home_abs_z = try home_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(home_abs_z);
    const home_abs = try allocator.dupe(u8, home_abs_z);
    defer allocator.free(home_abs);

    const project_abs_z = try project_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(project_abs_z);
    const project_abs = try allocator.dupe(u8, project_abs_z);
    defer allocator.free(project_abs);

    const prev: ?[:0]u8 = if (std.c.getenv("HOME")) |v| try allocator.dupeZ(u8, std.mem.span(v)) else null;
    defer {
        if (prev) |p| {
            _ = setenv("HOME", p.ptr, 1);
            allocator.free(p);
        } else {
            _ = unsetenv("HOME");
        }
    }
    const home_z = try allocator.dupeZ(u8, home_abs);
    defer allocator.free(home_z);
    try std.testing.expectEqual(@as(c_int, 0), setenv("HOME", home_z.ptr, 1));

    var loaded = try discover(io, allocator, null, project_abs);
    defer loaded.deinit();
    try std.testing.expectEqual(schema.LoadSource.user, loaded.source);
    try std.testing.expect(std.mem.indexOf(u8, loaded.path, ".ryk/policy.yaml") != null);
    try std.testing.expect(std.mem.indexOf(u8, loaded.path, ".config") == null);
    // generic-agent is mode strict with matrix-only allow (not builtin permit refuse).
    try std.testing.expectEqual(schema.Mode.strict, loaded.policy.mode);
    try std.testing.expectEqual(@as(usize, 0), loaded.policy.commands.allow.len);
}

test "JSON policies reject unknown keys instead of silently changing policy meaning" {
    try std.testing.expectError(error.InvalidPolicy, parseFromSlice(std.testing.allocator,
        \\{"version":1,"mode":"strict","commands":{"denny":["rm -rf *"]}}
    , "bad.json"));
    try std.testing.expectError(error.InvalidPolicy, parseFromSlice(std.testing.allocator,
        \\{"version":1,"mode":"strict","defualt":"allow"}
    , "bad.json"));
}

test "service-aware policy parses YAML and JSON service rules" {
    var yaml_policy = try parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\services:
        \\  github:
        \\    hosts:
        \\      - "api.github.com"
        \\    methods:
        \\      - "GET"
        \\      - "POST"
        \\    paths:
        \\      allow:
        \\        - "/repos/*/issues"
        \\        - "/repos/*/pulls"
        \\      deny:
        \\        - "/user/keys"
        \\        - "/orgs/*/secrets/*"
        \\    credentials:
        \\      use: github_pat
        \\    unmatched: deny
    , "services.yaml");
    defer yaml_policy.deinit();

    try std.testing.expectEqual(@as(usize, 1), yaml_policy.services.len);
    try std.testing.expectEqualStrings("github", yaml_policy.services[0].name);
    try std.testing.expectEqualStrings("api.github.com", yaml_policy.services[0].hosts[0]);
    try std.testing.expectEqualStrings("POST", yaml_policy.services[0].methods[1]);
    try std.testing.expectEqualStrings("/repos/*/pulls", yaml_policy.services[0].paths.allow[1]);
    try std.testing.expectEqualStrings("/orgs/*/secrets/*", yaml_policy.services[0].paths.deny[1]);
    try std.testing.expectEqualStrings("github_pat", yaml_policy.services[0].credentials.use.?);
    try std.testing.expectEqual(schema.DecisionValue.deny, yaml_policy.services[0].unmatched.?);

    var json_policy = try parseFromSlice(std.testing.allocator,
        \\{"version":1,"mode":"strict","services":{"github":{"hosts":["api.github.com"],"methods":["GET"],"paths":{"allow":["/repos/*/issues"],"deny":["/user/keys"]},"credentials":{"use":"github_pat"},"unmatched":"deny"}}}
    , "services.json");
    defer json_policy.deinit();

    try std.testing.expectEqual(@as(usize, 1), json_policy.services.len);
    try std.testing.expectEqualStrings("github", json_policy.services[0].name);
    try std.testing.expectEqualStrings("GET", json_policy.services[0].methods[0]);
}

test "credential broker config parses YAML and JSON" {
    var yaml_policy = try parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\credentials:
        \\  default_broker: onepassword
        \\  brokers:
        \\    onepassword:
        \\      type: 1password-cli
        \\      account: my-team
        \\    env_dev:
        \\      type: env-file-dev
        \\      path: .ryk/dev-secrets.env
        \\  refs:
        \\    github_pat:
        \\      broker: onepassword
        \\      ref: "op://Engineering/GitHub PAT/token"
        \\network:
        \\  mode: allowlist
        \\  backend: proxy
        \\services:
        \\  github:
        \\    hosts:
        \\      - "api.github.com"
        \\    credentials:
        \\      use: github_pat
    , "credentials.yaml");
    defer yaml_policy.deinit();

    try std.testing.expectEqual(schema.NetworkBackend.proxy, yaml_policy.network.backend.?);
    try std.testing.expectEqualStrings("onepassword", yaml_policy.credentials.default_broker.?);
    try std.testing.expectEqual(@as(usize, 2), yaml_policy.credentials.brokers.len);
    try std.testing.expectEqual(schema.CredentialBrokerKind.onepassword_cli, yaml_policy.credentials.brokers[0].kind);
    try std.testing.expectEqualStrings("my-team", yaml_policy.credentials.brokers[0].account.?);
    try std.testing.expectEqual(schema.CredentialBrokerKind.env_file_dev, yaml_policy.credentials.brokers[1].kind);
    try std.testing.expectEqualStrings(".ryk/dev-secrets.env", yaml_policy.credentials.brokers[1].path.?);
    try std.testing.expectEqualStrings("github_pat", yaml_policy.credentials.refs[0].name);
    try std.testing.expectEqualStrings("op://Engineering/GitHub PAT/token", yaml_policy.credentials.refs[0].ref);

    var json_policy = try parseFromSlice(std.testing.allocator,
        \\{"version":1,"mode":"strict","credentials":{"default_broker":"env_dev","brokers":{"env_dev":{"type":"env-file-dev","path":".ryk/dev-secrets.env"}},"refs":{"github_pat":{"broker":"env_dev","ref":"GITHUB_PAT"}}},"network":{"backend":"proxy"}}
    , "credentials.json");
    defer json_policy.deinit();

    try std.testing.expectEqual(schema.NetworkBackend.proxy, json_policy.network.backend.?);
    try std.testing.expectEqualStrings("env_dev", json_policy.credentials.default_broker.?);
    try std.testing.expectEqualStrings("github_pat", json_policy.credentials.refs[0].name);
}

test "credential grants parse YAML and JSON mapping shapes" {
    var yaml_policy = try parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\credentials:
        \\  refs:
        \\    openai_key:
        \\      ref: OPENAI_API_KEY
        \\  grants:
        \\    anthropic:
        \\      env_var: ANTHROPIC_API_KEY
        \\      provider: anthropic
        \\      source: host_env
        \\      allowed_hosts:
        \\        - api.anthropic.com
        \\    openai:
        \\      env_var: OPENAI_API_KEY
        \\      provider: openai
        \\      source: broker
        \\      ref: openai_key
        \\      allowed_hosts:
        \\        - api.openai.com
    , "credential-grants.yaml");
    defer yaml_policy.deinit();

    try std.testing.expectEqual(@as(usize, 2), yaml_policy.credentials.grants.len);
    try std.testing.expectEqualStrings("anthropic", yaml_policy.credentials.grants[0].name);
    try std.testing.expectEqualStrings("ANTHROPIC_API_KEY", yaml_policy.credentials.grants[0].env_var);
    try std.testing.expectEqual(schema.CredentialProvider.anthropic, yaml_policy.credentials.grants[0].provider);
    try std.testing.expectEqual(schema.CredentialGrantSource.host_env, yaml_policy.credentials.grants[0].source);
    try std.testing.expectEqual(@as(?[]const u8, null), yaml_policy.credentials.grants[0].credential_ref);
    try std.testing.expectEqualStrings("api.anthropic.com", yaml_policy.credentials.grants[0].allowed_hosts[0]);
    try std.testing.expectEqualStrings("openai_key", yaml_policy.credentials.grants[1].credential_ref.?);

    var json_policy = try parseFromSlice(std.testing.allocator,
        \\{"version":1,"mode":"strict","credentials":{"refs":{"anthropic_key":{"ref":"ANTHROPIC_API_KEY"}},"grants":{"anthropic":{"env_var":"ANTHROPIC_API_KEY","provider":"anthropic","source":"broker","credential_ref":"anthropic_key","allowed_hosts":["api.anthropic.com"]},"openai":{"env_var":"OPENAI_API_KEY","provider":"openai","source":"host_env","allowed_hosts":["api.openai.com"]}}}}
    , "credential-grants.json");
    defer json_policy.deinit();

    try std.testing.expectEqual(@as(usize, 2), json_policy.credentials.grants.len);
    try std.testing.expectEqualStrings("anthropic_key", json_policy.credentials.grants[0].credential_ref.?);
    try std.testing.expectEqual(schema.CredentialProvider.openai, json_policy.credentials.grants[1].provider);
    try std.testing.expectEqual(schema.CredentialGrantSource.host_env, json_policy.credentials.grants[1].source);
}

test "credential grant parsers reject malformed shapes and unknown keys" {
    try std.testing.expectError(error.InvalidPolicy, parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\credentials:
        \\  grants: anthropic
    , "grant-scalar.yaml"));

    try std.testing.expectError(error.InvalidPolicy, parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\credentials:
        \\  grants:
        \\    anthropic:
        \\      env_var: ANTHROPIC_API_KEY
        \\      provider: anthropic
        \\      source: host_env
        \\      allowed_hosts:
        \\        - api.anthropic.com
        \\      allow_host: api.anthropic.com
    , "grant-unknown.yaml"));

    try std.testing.expectError(error.InvalidPolicy, parseFromSlice(std.testing.allocator,
        \\{"version":1,"mode":"strict","credentials":{"grants":{"openai":{"env_var":"OPENAI_API_KEY","provider":"openai","source":"host_env","allowed_hosts":["api.openai.com"],"allow_host":"api.openai.com"}}}}
    , "grant-unknown.json"));
}

test "YAML policies reject scalar values on object-only grouping keys" {
    try std.testing.expectError(error.InvalidPolicy, parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\commands: allow
    , "bad.yaml"));

    try std.testing.expectError(error.InvalidPolicy, parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\files:
        \\  read: allow
    , "bad.yaml"));

    try std.testing.expectError(error.InvalidPolicy, parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\network:
        \\  detect_exfiltration: true
    , "bad.yaml"));

    try std.testing.expectError(error.InvalidPolicy, parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\mcp:
        \\  servers: github
    , "bad.yaml"));

    try std.testing.expectError(error.InvalidPolicy, parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\mcp:
        \\  servers:
        \\    github: allow
    , "bad.yaml"));
}

test "MCP server-scoped policy shape flattens to server tool selectors" {
    var yaml_policy = try parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\mcp:
        \\  default: ask
        \\  servers:
        \\    github:
        \\      tools:
        \\        allow:
        \\          - search_repositories
        \\          - get_file_contents
        \\        ask:
        \\          - create_issue
        \\        deny:
        \\          - delete_repository
    , "mcp.yaml");
    defer yaml_policy.deinit();
    try std.testing.expectEqualStrings("github.search_repositories", yaml_policy.mcp.allow[0]);
    try std.testing.expectEqualStrings("github.create_issue", yaml_policy.mcp.ask[0]);
    try std.testing.expectEqualStrings("github.delete_repository", yaml_policy.mcp.deny[0]);

    var json_policy = try parseFromSlice(std.testing.allocator,
        \\{"version":1,"mode":"strict","mcp":{"default":"ask","servers":{"github":{"tools":{"allow":["search_repositories"],"deny":["delete_repository"]}}}}}
    , "mcp.json");
    defer json_policy.deinit();
    try std.testing.expectEqualStrings("github.search_repositories", json_policy.mcp.allow[0]);
    try std.testing.expectEqualStrings("github.delete_repository", json_policy.mcp.deny[0]);
}

test "policy parsing cleans up every allocation failure path" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, parsePolicyAllocationFailureProbe, .{});
}

test "policy discovery cleans up every allocation failure path" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "policy.yaml",
        .data =
        \\version: 1
        \\mode: strict
        \\workspace:
        \\  root: "."
        \\  write_mode: staged
        ,
    });
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const policy_path = try std.fs.path.join(std.testing.allocator, &.{ root, "policy.yaml" });
    defer std.testing.allocator.free(policy_path);

    try std.testing.checkAllAllocationFailures(std.testing.allocator, discoverPolicyAllocationFailureProbe, .{ policy_path, root });
}

fn parsePolicyAllocationFailureProbe(allocator: std.mem.Allocator) !void {
    var loaded = try parseFromSlice(allocator,
        \\version: 1
        \\mode: strict
        \\workspace:
        \\  root: "."
        \\  write_mode: staged
        \\env:
        \\  inherit: false
        \\  allow:
        \\    - PATH
        \\  deny_patterns:
        \\    - "*TOKEN*"
        \\  ask:
        \\    - "*KEY*"
        \\  default: deny
        \\files:
        \\  read:
        \\    allow:
        \\      - "src/**"
        \\    deny:
        \\      - ".env"
        \\    ask:
        \\      - "secrets/**"
        \\  write:
        \\    allow:
        \\      - "tmp/**"
        \\    deny:
        \\      - ".git/**"
        \\    ask:
        \\      - "docs/**"
        \\    mode: staged
        \\commands:
        \\  allow:
        \\    - "echo *"
        \\  deny:
        \\    - "rm -rf *"
        \\  ask:
        \\    - "git push *"
        \\network:
        \\  mode: observe
        \\  allow:
        \\    - "example.com"
        \\  deny:
        \\    - "evil.example"
        \\  ask:
        \\    - "*.internal"
        \\  default: ask
        \\credentials:
        \\  refs:
        \\    anthropic_key:
        \\      ref: ANTHROPIC_API_KEY
        \\  grants:
        \\    anthropic:
        \\      env_var: ANTHROPIC_API_KEY
        \\      provider: anthropic
        \\      source: broker
        \\      credential_ref: anthropic_key
        \\      allowed_hosts:
        \\        - api.anthropic.com
        \\mcp:
        \\  default: ask
        \\  servers:
        \\    github:
        \\      tools:
        \\        allow:
        \\          - search_repositories
        \\        deny:
        \\          - delete_repository
        \\audit:
        \\  level: full
        \\  redact_secrets: true
        \\  tamper_evident: true
    , "allocation-failure-policy.yaml");
    defer loaded.deinit();
}

fn discoverPolicyAllocationFailureProbe(allocator: std.mem.Allocator, policy_path: []const u8, root: []const u8) !void {
    var loaded = try discover(std.testing.io, allocator, policy_path, root);
    defer loaded.deinit();
}

test "effects section loads and marks configured" {
    var yaml_policy = try parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\effects:
        \\  default: allow
        \\  deny:
        \\    - comms.message
        \\    - comms.*
        \\  ask:
        \\    - unknown.external
    , "effects.yaml");
    defer yaml_policy.deinit();
    try std.testing.expect(yaml_policy.effects.isActive());
    try std.testing.expectEqual(schema.DecisionValue.allow, yaml_policy.effects.default.?);
    try std.testing.expectEqualStrings("comms.message", yaml_policy.effects.deny[0]);
    try std.testing.expectEqualStrings("comms.*", yaml_policy.effects.deny[1]);
    try std.testing.expectEqualStrings("unknown.external", yaml_policy.effects.ask[0]);

    var json_policy = try parseFromSlice(std.testing.allocator,
        \\{"version":1,"mode":"strict","effects":{"deny":["money.transfer"],"default":"ask"}}
    , "effects.json");
    defer json_policy.deinit();
    try std.testing.expect(json_policy.effects.isActive());
    try std.testing.expectEqualStrings("money.transfer", json_policy.effects.deny[0]);
    try std.testing.expectEqual(schema.DecisionValue.ask, json_policy.effects.default.?);
}

test "effects section absent is inactive" {
    var policy = try parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\mcp:
        \\  default: deny
    , "no-effects.yaml");
    defer policy.deinit();
    try std.testing.expect(!policy.effects.isActive());
}

test "invalid effect patterns are rejected" {
    try std.testing.expectError(error.InvalidPolicy, parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\effects:
        \\  deny:
        \\    - not.a.real.effect
    , "bad-effects.yaml"));

    try std.testing.expectError(error.InvalidPolicy, parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\effects:
        \\  deny:
        \\    - nope.*
    , "bad-wildcard.yaml"));
}

test "effects.classifier defaults off and parses local aliases" {
    var omitted = try parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\effects:
        \\  default: allow
        \\  deny:
        \\    - comms.message
    , "classifier-omitted.yaml");
    defer omitted.deinit();
    try std.testing.expect(omitted.effects.classifier == .off);

    var off = try parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\effects:
        \\  classifier: off
        \\  deny:
        \\    - comms.message
    , "classifier-off.yaml");
    defer off.deinit();
    try std.testing.expect(off.effects.classifier == .off);

    var local = try parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\effects:
        \\  classifier: local
        \\  deny:
        \\    - comms.message
    , "classifier-local.yaml");
    defer local.deinit();
    try std.testing.expect(local.effects.classifier == .local);

    var embed = try parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\effects:
        \\  classifier: local-embed
        \\  deny:
        \\    - comms.message
    , "classifier-embed.yaml");
    defer embed.deinit();
    try std.testing.expect(embed.effects.classifier == .local);

    var json_policy = try parseFromSlice(std.testing.allocator,
        \\{"version":1,"mode":"strict","effects":{"classifier":"local","deny":["comms.message"]}}
    , "classifier.json");
    defer json_policy.deinit();
    try std.testing.expect(json_policy.effects.classifier == .local);

    try std.testing.expectError(error.InvalidPolicy, parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\effects:
        \\  classifier: cloud-llm
    , "classifier-bad.yaml"));
}

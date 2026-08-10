const std = @import("std");
const build_options = @import("build_options");

const aggregate = @import("aggregate.zig");
const blocked_actions = @import("blocked_actions.zig");
const presentation = @import("../presentation/mod.zig");
const core_api = @import("ryk_core").api;
const core = @import("ryk_core").core;
const policy_mod = @import("ryk_core").policy;
const credentials_runtime = @import("../intercept/credentials.zig");
const supervisor = core.supervisor;
const license_mod = @import("../license.zig");
const ci_check = @import("../ci_check.zig");
const brand = @import("../cli/brand.zig");
const rust_visibility = @import("../cli/rust_visibility.zig");
const feed_writer = @import("../cli/feed_writer.zig");

pub const max_request_body_len = 1024 * 1024;

pub const PolicySaveResult = struct {
    ok: bool,
    error_name: ?[]const u8 = null,
};

pub fn resolveWorkspaceRoot(io: std.Io, allocator: std.mem.Allocator) ![]u8 {
    return resolveWorkspaceRootFrom(io, allocator, ".");
}

pub fn resolveWorkspaceRootFrom(io: std.Io, allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    return supervisor.resolveWorkspaceRoot(io, allocator, null, path) catch try std.Io.Dir.cwd().realPathFileAlloc(io, path, allocator);
}

pub fn writeStatusJson(io: std.Io, allocator: std.mem.Allocator, writer: anytype, workspace_root: []const u8) !void {
    try writer.writeByte('{');
    try writer.writeAll("\"mode\":\"workspace\",\"workspace_count\":1,\"workspaces\":[{\"root\":");
    try core.util.writeJsonString(writer, workspace_root);
    try writer.writeAll("}],\"ryk\":{");
    try writer.writeAll("\"installed\":true,\"version\":");
    try core.util.writeJsonString(writer, build_options.version);
    try writer.writeAll(",\"workspace_root\":");
    try core.util.writeJsonString(writer, workspace_root);
    try writer.writeAll("},\"policy\":");
    try writePolicySummaryJson(io, allocator, writer, workspace_root);
    try writer.writeAll(",\"secretless_runtime\":");
    try writeSecretlessRuntimeJson(io, allocator, writer, workspace_root);
    try writer.writeAll(",\"license\":");
    try writeLicenseJson(io, allocator, writer);
    try writer.writeAll(",\"ci_readiness\":");
    try writeCiReadinessJson(io, allocator, writer, workspace_root);
    try writer.writeAll(",\"plugins\":[");
    try writePluginCardJson(io, allocator, writer, workspace_root, "openclaw", "OpenClaw", "openclaw", "integrations/openclaw-plugin", "ryk plugin doctor openclaw");
    try writer.writeByte(',');
    try writePluginCardJson(io, allocator, writer, workspace_root, "hermes", "Hermes", "hermes", "integrations/hermes-plugin", "ryk plugin doctor hermes");
    try writer.writeAll("],\"sessions\":");
    const session_health = try writeSessionsArrayJson(io, allocator, writer, workspace_root, 6);
    try writer.writeAll(",\"session_health\":");
    try core.util.writeJsonString(writer, @tagName(session_health));
    try writer.writeAll(",\"daemon_health\":");
    try writeDaemonHealthJson(allocator, writer);
    try writer.writeAll(",\"rust_shell_decisions\":");
    try writeRustShellDecisionsArrayJson(io, allocator, writer, workspace_root, 12);
    try writer.writeAll(",\"blocked_actions\":");
    try writeBlockedActionsArrayJson(io, allocator, writer, workspace_root, 8);
    try writer.writeAll(",\"feed_health\":");
    try writeWorkspaceFeedHealthJson(io, allocator, writer, workspace_root);
    try writer.writeAll(",\"quick_actions\":[");
    try writeQuickAction(writer, "doctor", "ryk doctor");
    try writer.writeByte(',');
    try writeQuickAction(writer, "policy-check", "ryk policy check .ryk/policy.yaml");
    try writer.writeByte(',');
    try writeQuickAction(writer, "credentials-check", "ryk credentials check");
    try writer.writeByte(',');
    try writeQuickAction(writer, "credentials-check-github", "ryk credentials check github_pat");
    try writer.writeByte(',');
    try writeQuickAction(writer, "proxy-smoke", "ryk run --secretless --network-backend proxy -- /usr/bin/env");
    try writer.writeByte(',');
    try writeQuickAction(writer, "policy-explain-github", "ryk policy explain network https://api.github.com/repos/acme/app/issues --method POST");
    try writer.writeByte(',');
    try writeQuickAction(writer, "replay-last", "ryk replay --session last --verify");
    try writer.writeByte(',');
    try writeQuickAction(writer, "openclaw-doctor", "ryk plugin doctor openclaw");
    try writer.writeByte(',');
    try writeQuickAction(writer, "hermes-doctor", "ryk plugin doctor hermes");
    try writer.writeByte(',');
    try writeQuickAction(writer, "replay-denied", "ryk replay --session last --only denied --verify");
    try writer.writeByte(',');
    try writeQuickAction(writer, "report-last", "ryk report --session last --format markdown");
    try writer.writeByte(',');
    try writeQuickAction(writer, "ci-check", "ryk ci check --format markdown");
    try writer.writeByte(',');
    try writeQuickAction(writer, "suggest-allowlist", "ryk suggest-allowlist --confidence high");
    try writer.writeByte(',');
    try writeQuickAction(writer, "allowlist-list", "ryk allowlist list");
    try writer.writeAll("]}");
}

fn writeWorkspaceFeedHealthJson(io: std.Io, allocator: std.mem.Allocator, writer: anytype, workspace_root: []const u8) !void {
    var loaded = feed_writer.loadRecentTailWithHealth(io, allocator, workspace_root) catch {
        try writer.writeAll("{\"status\":\"degraded\",\"skipped_lines\":0}");
        return;
    };
    defer loaded.deinit(allocator);
    try writer.writeAll("{\"status\":");
    try core.util.writeJsonString(writer, @tagName(loaded.health));
    try writer.print(",\"skipped_lines\":{d}}}", .{loaded.skipped_lines});
}

pub fn writeMachineStatusJson(
    io: std.Io,
    allocator: std.mem.Allocator,
    writer: anytype,
    dashboard_root: []const u8,
) !void {
    const workspaces = try aggregate.loadWorkspaces(io, allocator, dashboard_root);
    defer aggregate.deinitWorkspaces(allocator, workspaces);

    try writer.writeAll("{\"mode\":\"machine\",\"workspace_count\":");
    try writer.print("{d}", .{workspaces.len});
    try writer.writeAll(",\"workspaces\":");
    try aggregate.writeWorkspacesJson(writer, workspaces);
    try writer.writeAll(",\"ryk\":{\"installed\":true,\"version\":");
    try core.util.writeJsonString(writer, build_options.version);
    try writer.writeAll(",\"workspace_root\":null},\"policy\":null,\"secretless_runtime\":null,\"license\":");
    try writeLicenseJson(io, allocator, writer);
    try writer.writeAll(",\"ci_readiness\":null,\"plugins\":[],\"sessions\":");
    const session_health = try aggregate.writeSessionsJson(io, allocator, writer, dashboard_root, workspaces, 20);
    try writer.writeAll(",\"session_health\":");
    try core.util.writeJsonString(writer, @tagName(session_health));
    try writer.writeAll(",\"daemon_health\":");
    try writeDaemonHealthJson(allocator, writer);
    try writer.writeAll(",\"rust_shell_decisions\":");
    try aggregate.writeGlobalFeedJson(io, allocator, writer, dashboard_root, 50, false);
    try writer.writeAll(",\"blocked_actions\":");
    try aggregate.writeGlobalFeedJson(io, allocator, writer, dashboard_root, 50, true);
    try writer.writeAll(",\"feed_health\":");
    try aggregate.writeGlobalFeedHealthJson(io, allocator, writer, dashboard_root);
    try writer.writeAll(",\"quick_actions\":[");
    try writeQuickAction(writer, "doctor", "ryk doctor");
    try writer.writeAll("]}");
}

fn writeSecretlessRuntimeJson(io: std.Io, allocator: std.mem.Allocator, writer: anytype, workspace_root: []const u8) !void {
    const policy_path = try policyPath(allocator, workspace_root);
    defer allocator.free(policy_path);
    var loaded_policy: ?policy_mod.schema.Policy = null;
    var loaded_policy_handle: ?policy_mod.schema.LoadedPolicy = null;
    if (policy_mod.load.discover(io, allocator, policy_path, workspace_root)) |loaded| {
        loaded_policy_handle = loaded;
        loaded_policy = loaded.policy;
    } else |_| {}
    defer if (loaded_policy_handle) |*handle| handle.deinit();

    const active_broker_label = if (loaded_policy) |loaded|
        loaded.credentials.default_broker orelse if (loaded.credentials.brokers.len > 0) loaded.credentials.brokers[0].name else "local-dummy"
    else
        "local-dummy";
    const active_broker_kind = if (loaded_policy) |loaded|
        if (findBrokerKind(loaded.credentials, active_broker_label)) |kind| kind.toString() else "local-dummy"
    else
        "local-dummy";
    const proxy_backend = if (loaded_policy) |loaded| loaded.network.effectiveBackend() else .decision_only;
    const service_policy_template =
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
        \\
        \\network:
        \\  mode: allowlist
        \\  backend: proxy
        \\
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
    ;
    try writer.writeAll(
        \\{"available":true,"active_broker":{"id":
    );
    try core.util.writeJsonString(writer, active_broker_label);
    try writer.writeAll(",\"label\":");
    try core.util.writeJsonString(writer, active_broker_label);
    try writer.writeAll(",\"kind\":");
    try core.util.writeJsonString(writer, active_broker_kind);
    try writer.writeAll(",\"status\":\"configured\",\"stores_raw_secrets\":false,\"injects_raw_credentials\":false,\"description\":\"Configured broker for Secretless credential references.\"},\"credential_refs\":");
    try writeCredentialRefsJson(writer, loaded_policy);
    try writer.writeAll(",\"broker_checks\":");
    try writeBrokerChecksJson(io, allocator, writer, workspace_root, loaded_policy);
    try writer.writeAll(",\"recent_audit_events\":");
    try writeRecentSecretlessAuditEventsJson(io, allocator, writer, workspace_root, 12);
    try writer.writeAll(",\"proxy_backend\":{");
    try writer.writeAll("\"status\":");
    try core.util.writeJsonString(writer, if (proxy_backend == .proxy) "limited" else "unavailable");
    try writer.writeAll(",\"bind\":");
    try core.util.writeJsonString(writer, if (proxy_backend == .proxy) "127.0.0.1:<allocated-per-run>" else "");
    try writer.writeAll(",\"https_visibility\":\"host-port-only\",\"method_path_visibility\":\"http-and-cooperative-hooks\",\"backend\":");
    try core.util.writeJsonString(writer, proxy_backend.toString());
    try writer.writeAll("},\"supported_brokers\":[{\"id\":\"local-dummy\",\"label\":\"Local dummy broker\",\"status\":\"available\",\"stores_raw_secrets\":false,\"notes\":\"Built in. Reference-only; not used by the empty-backpack provider path.\"},{\"id\":\"env-file-dev\",\"label\":\"Env-file dev broker\",\"status\":\"available\",\"stores_raw_secrets\":false,\"notes\":\"Local development only. Reads .ryk/dev-secrets.env at runtime and never writes raw values to audit.\"},{\"id\":\"1password-cli\",\"label\":\"1Password CLI\",\"status\":\"available-when-op-installed\",\"stores_raw_secrets\":false,\"notes\":\"Runs op read without shell interpolation and discards resolved values after checks.\"},{\"id\":\"macos-keychain\",\"label\":\"macOS Keychain\",\"status\":\"available-on-macos\",\"stores_raw_secrets\":false,\"notes\":\"Uses /usr/bin/security find-generic-password for configured refs.\"},{\"id\":\"infisical-agent-vault\",\"label\":\"Infisical / Agent Vault\",\"status\":\"status-boundary\",\"stores_raw_secrets\":false,\"notes\":\"Configured as an extension boundary; resolution remains disabled until exact local API or CLI behavior is verified.\"}],\"capabilities\":[{\"label\":\"Empty backpack env\",\"state\":\"active\",\"detail\":\"ryk run --secretless constructs a public-only child env (no raw secret-like host values) plus exact session phantoms for granted Anthropic/OpenAI keys — not broker-reference substitution.\"},{\"label\":\"Provider gateway\",\"state\":\"active\",\"detail\":\"Loopback provider gateway swaps exact session phantoms for raw bytes only on fixed Anthropic/OpenAI upstream hosts.\"},{\"label\":\"Workspace secret OS deny\",\"state\":\"active\",\"detail\":\"When OS sandbox attach succeeds, workspace .env / .env.* forms are denied at the OS layer (safe templates remain readable; macOS uses basename regex + prepare-time multi-nlink path denies).\"},{\"label\":\"Broker checks\",\"state\":\"active\",\"detail\":\"ryk credentials check verifies broker config and refs without printing raw secret values.\"},{\"label\":\"Service policy\",\"state\":\"active\",\"detail\":\"services: rules support hosts, methods, allow/deny paths, credential references, unmatched behavior, and port-scoped hosts.\"},{\"label\":\"Proxy backend\",\"state\":\"limited\",\"detail\":\"ryk run --network-backend proxy injects a loopback proxy. HTTPS CONNECT enforcement is host/port only without MITM.\"},{\"label\":\"Transparent OS interception\",\"state\":\"unavailable\",\"detail\":\"ryk does not claim OS-level transparent network interception.\"}],\"guarantees\":[\"Empty-backpack children do not receive raw secret-like host environment values that ryk detects.\",\"Granted model keys reach the child only as session-minted phantoms; the provider gateway swaps exact mints on fixed upstreams.\",\"Broker checks never print or persist raw resolved secret values.\",\"ryk remains the runtime policy and audit layer; external brokers own secret storage when used.\"],\"limitations\":[\"Empty backpack protects processes launched through agent-primary aliases or ryk run --secretless (not arbitrary host processes).\",\"macOS protect-on hardlink discovery is prepare-time only (no runtime inode taint); multi-writer post-prepare plants are an accepted residual under the single-writer model.\",\"HTTPS path and method enforcement is unavailable in proxy mode without MITM or cooperative metadata.\",\"Infisical/Agent Vault resolution is not enabled until its local contract is verified.\"],\"run_command\":\"ryk run --secretless --network-backend proxy -- <agent-command>\",\"verify_commands\":[\"ryk credentials check\",\"ryk credentials check github_pat\",\"ryk policy check .ryk/policy.yaml\",\"ryk policy explain network https://api.github.com/repos/acme/app/issues --method POST\",\"ryk run --secretless --network-backend proxy -- /usr/bin/env\",\"ryk replay --session last --verify\"],\"service_policy_template\":");
    try core.util.writeJsonString(writer, service_policy_template);
    try writer.writeByte('}');
}

fn findBrokerKind(credentials: policy_mod.schema.CredentialsPolicy, name: []const u8) ?policy_mod.schema.CredentialBrokerKind {
    for (credentials.brokers) |broker| {
        if (std.ascii.eqlIgnoreCase(broker.name, name)) return broker.kind;
    }
    return null;
}

fn writeCredentialRefsJson(writer: anytype, maybe_policy: ?policy_mod.schema.Policy) !void {
    try writer.writeByte('[');
    if (maybe_policy) |loaded| {
        for (loaded.credentials.refs, 0..) |credential_ref, index| {
            if (index > 0) try writer.writeByte(',');
            try writer.writeAll("{\"name\":");
            try core.util.writeJsonString(writer, credential_ref.name);
            try writer.writeAll(",\"broker\":");
            if (credential_ref.broker) |broker| try core.util.writeJsonString(writer, broker) else try writer.writeAll("null");
            try writer.writeAll(",\"ref\":");
            try core.util.writeJsonString(writer, credential_ref.ref);
            try writer.writeAll(",\"raw_value\":null}");
        }
    }
    try writer.writeByte(']');
}

fn writeBrokerChecksJson(io: std.Io, allocator: std.mem.Allocator, writer: anytype, workspace_root: []const u8, maybe_policy: ?policy_mod.schema.Policy) !void {
    if (maybe_policy) |loaded| {
        var report = credentials_runtime.check(io, allocator, &loaded, workspace_root, null) catch {
            try writer.writeAll("[]");
            return;
        };
        defer report.deinit(allocator);
        try writer.writeByte('[');
        for (report.statuses, 0..) |status, index| {
            if (index > 0) try writer.writeByte(',');
            try writer.writeAll("{\"broker\":");
            try core.util.writeJsonString(writer, status.name);
            try writer.writeAll(",\"kind\":");
            try core.util.writeJsonString(writer, status.kind.toString());
            try writer.writeAll(",\"status\":");
            try core.util.writeJsonString(writer, status.state.toString());
            try writer.writeAll(",\"message\":");
            try core.util.writeJsonString(writer, status.message);
            try writer.writeByte('}');
        }
        try writer.writeByte(']');
        return;
    }
    try writer.writeAll("[{\"broker\":\"local-dummy\",\"kind\":\"local-dummy\",\"status\":\"available\",\"message\":\"built-in reference broker available\"}]");
}

pub fn writePolicyJson(io: std.Io, allocator: std.mem.Allocator, writer: anytype, workspace_root: []const u8) !void {
    try writer.writeByte('{');
    try writer.writeAll("\"summary\":");
    try writePolicySummaryJson(io, allocator, writer, workspace_root);
    try writer.writeAll(",\"presets\":[");
    for (policy_mod.presets.agent_preset_infos, 0..) |info, index| {
        if (index > 0) try writer.writeByte(',');
        try writer.writeByte('{');
        try writer.writeAll("\"name\":");
        try core.util.writeJsonString(writer, info.name);
        try writer.writeAll(",\"experimental\":");
        try writer.writeAll(if (info.experimental) "true" else "false");
        try writer.writeAll(",\"warning\":");
        try core.util.writeJsonString(writer, info.warning);
        try writer.writeByte('}');
    }
    try writer.writeAll("],\"text\":");
    const policy_path = try policyPath(allocator, workspace_root);
    defer allocator.free(policy_path);
    if (readFileIfExists(io, allocator, policy_path, core.limits.max_policy_file_len + 1)) |text| {
        defer allocator.free(text);
        try core.util.writeJsonString(writer, text);
    } else |_| {
        try writer.writeAll("null");
    }
    try writer.writeByte('}');
}

pub fn savePolicyText(io: std.Io, allocator: std.mem.Allocator, workspace_root: []const u8, text: []const u8) !PolicySaveResult {
    if (text.len > core.limits.max_policy_file_len) return .{ .ok = false, .error_name = "PolicyFileTooLarge" };
    var parsed = core_api.parsePolicyFromSlice(allocator, text, ".ryk/policy.yaml") catch |err| {
        return .{ .ok = false, .error_name = @errorName(err) };
    };
    defer parsed.deinit();
    core_api.validatePolicy(parsed) catch |err| {
        return .{ .ok = false, .error_name = @errorName(err) };
    };

    const ryk_dir = try std.fs.path.join(allocator, &.{ workspace_root, ".ryk" });
    defer allocator.free(ryk_dir);
    try std.Io.Dir.cwd().createDirPath(io, ryk_dir);
    const path = try policyPath(allocator, workspace_root);
    defer allocator.free(path);
    const file = try std.Io.Dir.createFileAbsolute(io, path, .{});
    defer file.close(io);
    try file.writeStreamingAll(io, text);
    try file.sync(io);
    return .{ .ok = true };
}

pub fn initPolicyFromPreset(io: std.Io, allocator: std.mem.Allocator, workspace_root: []const u8, preset_name: []const u8, force: bool) !PolicySaveResult {
    const preset = policy_mod.presets.AgentPreset.parse(preset_name) orelse return .{ .ok = false, .error_name = "UnsupportedPreset" };
    const path = try policyPath(allocator, workspace_root);
    defer allocator.free(path);
    if (!force and fileExistsAbsolute(io, path)) return .{ .ok = false, .error_name = "PolicyAlreadyExists" };
    return savePolicyText(io, allocator, workspace_root, policy_mod.presets.agentPresetText(preset));
}

pub fn writeSessionsJson(io: std.Io, allocator: std.mem.Allocator, writer: anytype, workspace_root: []const u8) !void {
    try writer.writeByte('{');
    try writer.writeAll("\"sessions\":");
    const session_health = try writeSessionsArrayJson(io, allocator, writer, workspace_root, 20);
    try writer.writeAll(",\"session_health\":");
    try core.util.writeJsonString(writer, @tagName(session_health));
    try writer.writeAll(",\"blocked_actions\":");
    try writeBlockedActionsArrayJson(io, allocator, writer, workspace_root, 50);
    try writer.writeByte('}');
}

pub fn writeMachineSessionsJson(
    io: std.Io,
    allocator: std.mem.Allocator,
    writer: anytype,
    dashboard_root: []const u8,
) !void {
    const workspaces = try aggregate.loadWorkspaces(io, allocator, dashboard_root);
    defer aggregate.deinitWorkspaces(allocator, workspaces);
    try writer.writeAll("{\"sessions\":");
    const session_health = try aggregate.writeSessionsJson(io, allocator, writer, dashboard_root, workspaces, 50);
    try writer.writeAll(",\"session_health\":");
    try core.util.writeJsonString(writer, @tagName(session_health));
    try writer.writeAll(",\"blocked_actions\":");
    try aggregate.writeGlobalFeedJson(io, allocator, writer, dashboard_root, 100, true);
    try writer.writeByte('}');
}

fn writePolicySummaryJson(io: std.Io, allocator: std.mem.Allocator, writer: anytype, workspace_root: []const u8) !void {
    const path = try policyPath(allocator, workspace_root);
    defer allocator.free(path);
    try writer.writeByte('{');
    try writer.writeAll("\"path\":\".ryk/policy.yaml\",");
    if (!fileExistsAbsolute(io, path)) {
        try writer.writeAll("\"exists\":false,\"valid\":false,\"mode\":null,\"error\":null");
        try writer.writeByte('}');
        return;
    }
    try writer.writeAll("\"exists\":true,");
    if (core_api.loadPolicyFile(io, allocator, path)) |loaded_policy| {
        var loaded = loaded_policy;
        defer loaded.deinit();
        try writer.writeAll("\"valid\":true,\"mode\":");
        try core.util.writeJsonString(writer, loaded.mode().toString());
        try writer.writeAll(",\"error\":null");
    } else |err| {
        if (err == error.OutOfMemory) return err;
        try writer.writeAll("\"valid\":false,\"mode\":null,\"error\":");
        try core.util.writeJsonString(writer, @errorName(err));
    }
    try writer.writeByte('}');
}

fn writeLicenseJson(io: std.Io, allocator: std.mem.Allocator, writer: anytype) !void {
    var current = license_mod.status(io, allocator) catch |err| switch (err) {
        error.InvalidLicense, error.InvalidLicenseSignature, error.UnsupportedLicenseIssuer, error.UnsupportedLicenseTier => {
            try writer.writeAll("{\"tier\":\"Free\",\"verified\":false,\"report_export\":true,\"error\":");
            try core.util.writeJsonString(writer, @errorName(err));
            try writer.writeByte('}');
            return;
        },
        else => return err,
    };
    defer current.deinit();
    try writer.writeByte('{');
    try writer.writeAll("\"tier\":");
    try core.util.writeJsonString(writer, current.tier.label());
    try writer.writeAll(",\"verified\":");
    try writer.writeAll(if (current.verified) "true" else "false");
    // Report export is free for all users; keep the field for dashboard UI compatibility.
    try writer.writeAll(",\"report_export\":true");
    try writer.writeAll(",\"error\":null}");
}

fn writeCiReadinessJson(io: std.Io, allocator: std.mem.Allocator, writer: anytype, workspace_root: []const u8) !void {
    var result = ci_check.run(io, allocator, workspace_root) catch |err| {
        try writer.writeAll("{\"ok\":false,\"error\":");
        try core.util.writeJsonString(writer, @errorName(err));
        try writer.writeAll(",\"checks\":[]}");
        return;
    };
    defer result.deinit();
    try writer.writeByte('{');
    try writer.writeAll("\"ok\":");
    try writer.writeAll(if (result.ok()) "true" else "false");
    try writer.writeAll(",\"error\":null,\"checks\":[");
    for (result.checks.items, 0..) |check, index| {
        if (index > 0) try writer.writeByte(',');
        try writer.writeAll("{\"name\":");
        try core.util.writeJsonString(writer, check.name);
        try writer.writeAll(",\"status\":");
        try core.util.writeJsonString(writer, @tagName(check.status));
        try writer.writeAll(",\"message\":");
        try core.util.writeJsonString(writer, check.message);
        try writer.writeByte('}');
    }
    try writer.writeAll("]}");
}

fn writePluginCardJson(
    io: std.Io,
    allocator: std.mem.Allocator,
    writer: anytype,
    workspace_root: []const u8,
    id: []const u8,
    label: []const u8,
    binary_name: []const u8,
    integration_path: []const u8,
    doctor_command: []const u8,
) !void {
    const integration_abs = try std.fs.path.join(allocator, &.{ workspace_root, integration_path });
    defer allocator.free(integration_abs);
    const host_found = try executableInPath(io, allocator, binary_name);
    const integration_present = pathExistsAbsolute(io, integration_abs);
    try writer.writeByte('{');
    try writer.writeAll("\"id\":");
    try core.util.writeJsonString(writer, id);
    try writer.writeAll(",\"label\":");
    try core.util.writeJsonString(writer, label);
    try writer.writeAll(",\"host_detected\":");
    try writer.writeAll(if (host_found) "true" else "false");
    try writer.writeAll(",\"integration_present\":");
    try writer.writeAll(if (integration_present) "true" else "false");
    try writer.writeAll(",\"doctor_command\":");
    try core.util.writeJsonString(writer, doctor_command);
    try writer.writeAll(",\"setup_commands\":[");
    // OpenClaw gets the curl-only unattended path; the wrapper remains the hard boundary fallback.
    if (std.mem.eql(u8, id, "openclaw")) {
        try writeStringArray(writer, &.{
            "curl -fsSL https://rykanv.com/install | sh",
            "ryk agents setup openclaw",
            "ryk agents health openclaw --json",
            "ryk run -- openclaw",
        });
    } else {
        try writeStringArray(writer, &.{
            "ryk start",
            "ryk plugin doctor hermes",
            "ryk hermes",
            "ryk status",
        });
    }
    try writer.writeAll("]}");
}

fn writeQuickAction(writer: anytype, id: []const u8, command: []const u8) !void {
    try writer.writeByte('{');
    try writer.writeAll("\"id\":");
    try core.util.writeJsonString(writer, id);
    try writer.writeAll(",\"command\":");
    try core.util.writeJsonString(writer, command);
    try writer.writeByte('}');
}

fn writeSessionsArrayJson(io: std.Io, allocator: std.mem.Allocator, writer: anytype, workspace_root: []const u8, max_count: usize) !aggregate.SessionLoadHealth {
    return aggregate.writeWorkspaceSessionsJson(io, allocator, writer, workspace_root, max_count);
}

fn writeDaemonHealthJson(allocator: std.mem.Allocator, writer: anytype) !void {
    var health = rust_visibility.probeGuiDaemonHealth(allocator) catch {
        try writer.writeAll("{\"status\":\"unavailable\",\"detail\":\"failed to probe daemon health\"}");
        return;
    };
    defer health.deinit(allocator);
    try writer.writeByte('{');
    try writer.writeAll("\"status\":");
    try core.util.writeJsonString(writer, health.status);
    try writer.writeAll(",\"detail\":");
    try core.util.writeJsonString(writer, health.detail);
    try writer.writeByte('}');
}

fn writeRustShellDecisionsArrayJson(io: std.Io, allocator: std.mem.Allocator, writer: anytype, workspace_root: []const u8, max_count: usize) !void {
    const loaded = feed_writer.loadRecent(io, allocator, workspace_root, max_count) catch {
        try writer.writeAll("[]");
        return;
    };
    defer {
        for (loaded) |*item| item.deinit(allocator);
        allocator.free(loaded);
    }
    try writer.writeByte('[');
    for (loaded, 0..) |item, index| {
        if (index > 0) try writer.writeByte(',');
        try writeFeedRecordJson(allocator, writer, item.record);
    }
    try writer.writeByte(']');
}

fn writeFeedRecordJson(allocator: std.mem.Allocator, writer: anytype, record: rust_visibility.RustShellFeedRecord) !void {
    try writer.writeByte('{');
    try writer.writeAll("\"timestamp\":");
    try core.util.writeJsonString(writer, record.timestamp);
    try writer.writeAll(",\"workspace_root\":");
    try core.util.writeJsonString(writer, record.workspace_root);
    try writer.writeAll(",\"event_type\":");
    try core.util.writeJsonString(writer, record.event_type);
    try writer.writeAll(",\"decision\":");
    try core.util.writeJsonString(writer, record.decision);
    try writer.writeAll(",\"decision_source\":");
    try core.util.writeJsonString(writer, record.decision_source);
    try writer.writeAll(",\"event_source\":");
    try core.util.writeJsonString(writer, record.event_source);
    try writer.writeAll(",\"host\":");
    if (record.host) |host| try core.util.writeJsonString(writer, host) else try writer.writeAll("null");
    try writer.writeAll(",\"daemon_status\":");
    try core.util.writeJsonString(writer, record.daemon_status);
    try writer.writeAll(",\"pack_id\":");
    if (record.pack_id) |pack_id| try core.util.writeJsonString(writer, pack_id) else try writer.writeAll("null");
    try writer.writeAll(",\"rule\":");
    if (record.rule) |rule| try core.util.writeJsonString(writer, rule) else try writer.writeAll("null");
    try writer.writeAll(",\"severity\":");
    if (record.severity) |severity| try core.util.writeJsonString(writer, severity) else try writer.writeAll("null");
    try writer.writeAll(",\"reason\":");
    try presentation.redact.writeJsonString(allocator, writer, record.reason);
    try writer.writeAll(",\"remediation\":");
    if (record.remediation) |remediation| try presentation.redact.writeJsonString(allocator, writer, remediation) else try writer.writeAll("null");
    try writer.writeAll(",\"target\":");
    try presentation.redact.writeJsonString(allocator, writer, record.target_summary);
    try writer.writeAll(",\"session_id\":");
    if (record.session_id) |session_id| try core.util.writeJsonString(writer, session_id) else try writer.writeAll("null");
    try writer.writeAll(",\"verified\":");
    try writer.writeAll(if (record.verified) "true" else "false");
    try writer.writeByte('}');
}

fn writeBlockedActionsArrayJson(io: std.Io, allocator: std.mem.Allocator, writer: anytype, workspace_root: []const u8, max_count: usize) !void {
    try writer.writeByte('[');
    var written: usize = 0;

    var feed_result: ?feed_writer.FeedLoadResult = feed_writer.loadRecentMatchingWithHealth(
        io,
        allocator,
        workspace_root,
        max_count,
        .blocked,
    ) catch null;
    defer if (feed_result) |*result| result.deinit(allocator);
    const feed = if (feed_result) |result| result.records else &[_]feed_writer.LoadedFeedRecord{};
    for (feed) |item| {
        if (written >= max_count) break;
        if (written > 0) try writer.writeByte(',');
        try writeFeedRecordJson(allocator, writer, item.record);
        written += 1;
    }

    const sessions_root = std.fs.path.join(allocator, &.{ workspace_root, ".ryk", "sessions" }) catch {
        try writer.writeByte(']');
        return;
    };
    defer allocator.free(sessions_root);
    var dir = std.Io.Dir.cwd().openDir(io, sessions_root, .{ .iterate = true }) catch {
        try writer.writeByte(']');
        return;
    };
    defer dir.close(io);

    var it = dir.iterate();
    while (written < max_count) {
        const entry = try it.next(io) orelse break;
        if (entry.kind != .directory) continue;
        if (core.session.validateSessionIdText(entry.name)) |_| {} else |_| continue;
        var replay = core_api.loadReplay(io, allocator, workspace_root, .{ .session = entry.name, .only_denied = true, .verify = false }) catch continue;
        defer replay.deinit();
        for (replay.events) |ev| {
            if (written >= max_count) break;
            if (written > 0) try writer.writeByte(',');
            try blocked_actions.writeBlockedActionJson(allocator, writer, replay.session_id, replay.verified, ev);
            written += 1;
        }
    }
    try writer.writeByte(']');
}

fn writeRecentSecretlessAuditEventsJson(io: std.Io, allocator: std.mem.Allocator, writer: anytype, workspace_root: []const u8, max_count: usize) !void {
    const sessions_root = try std.fs.path.join(allocator, &.{ workspace_root, ".ryk", "sessions" });
    defer allocator.free(sessions_root);
    var dir = std.Io.Dir.cwd().openDir(io, sessions_root, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => {
            try writer.writeAll("[]");
            return;
        },
        else => return err,
    };
    defer dir.close(io);

    try writer.writeByte('[');
    var written: usize = 0;
    var it = dir.iterate();
    while (written < max_count) {
        const entry = try it.next(io) orelse break;
        if (entry.kind != .directory) continue;
        if (core.session.validateSessionIdText(entry.name)) |_| {} else |_| continue;
        var replay = core_api.loadReplay(io, allocator, workspace_root, .{ .session = entry.name, .only_denied = false, .verify = false }) catch continue;
        defer replay.deinit();
        for (replay.events) |ev| {
            if (written >= max_count) break;
            if (!isSecretlessEvidenceEvent(ev.event_type)) continue;
            if (written > 0) try writer.writeByte(',');
            try writer.writeByte('{');
            try writer.writeAll("\"session_id\":");
            try core.util.writeJsonString(writer, replay.session_id);
            try writer.writeAll(",\"timestamp\":");
            try core.util.writeJsonString(writer, ev.timestamp);
            try writer.writeAll(",\"event_type\":");
            try core.util.writeJsonString(writer, ev.event_type);
            try writer.writeAll(",\"target\":");
            try presentation.redact.writeJsonString(allocator, writer, ev.target_value);
            try writer.writeAll(",\"decision\":");
            if (ev.decision_result) |result| try core.util.writeJsonString(writer, result) else try writer.writeAll("null");
            try writer.writeAll(",\"verified\":");
            try writer.writeAll(if (replay.verified) "true" else "false");
            try writer.writeByte('}');
            written += 1;
        }
    }
    try writer.writeByte(']');
}

fn isSecretlessEvidenceEvent(event_type: []const u8) bool {
    return std.mem.eql(u8, event_type, "secret_redacted") or
        std.mem.eql(u8, event_type, "network_proxy_start") or
        std.mem.eql(u8, event_type, "network_proxy_stop") or
        std.mem.eql(u8, event_type, "network_connect_attempt") or
        std.mem.eql(u8, event_type, "network_connect_allowed") or
        std.mem.eql(u8, event_type, "network_connect_denied");
}

fn writeStringArray(writer: anytype, values: []const []const u8) !void {
    for (values, 0..) |value, index| {
        if (index > 0) try writer.writeByte(',');
        try core.util.writeJsonString(writer, value);
    }
}

fn policyPath(allocator: std.mem.Allocator, workspace_root: []const u8) ![]u8 {
    return std.fs.path.join(allocator, &.{ workspace_root, ".ryk", "policy.yaml" });
}

fn fileExistsAbsolute(io: std.Io, path: []const u8) bool {
    std.Io.Dir.cwd().access(io, path, .{}) catch return false;
    return true;
}

fn pathExistsAbsolute(io: std.Io, path: []const u8) bool {
    std.Io.Dir.cwd().access(io, path, .{}) catch return false;
    return true;
}

fn readFileIfExists(io: std.Io, allocator: std.mem.Allocator, path: []const u8, max_bytes: usize) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(max_bytes));
}

fn executableInPath(io: std.Io, allocator: std.mem.Allocator, name: []const u8) !bool {
    const env_util = @import("../env_util.zig");
    var env_map = try env_util.createProcessMap(allocator);
    defer env_map.deinit();
    const path = env_map.get("PATH") orelse return false;
    const separator: u8 = if (@import("builtin").os.tag == .windows) ';' else ':';
    var parts = std.mem.splitScalar(u8, path, separator);
    while (parts.next()) |part| {
        if (part.len == 0) continue;
        const candidate = try std.fs.path.join(allocator, &.{ part, name });
        defer allocator.free(candidate);
        if (fileExistsAbsolute(io, candidate)) return true;
    }
    return false;
}

test "policy save validates before writing" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    const io = std.testing.io;
    const bad = try savePolicyText(io, std.testing.allocator, root, "version: 1\nmode: strict\ncommands: allow\n");
    try std.testing.expect(!bad.ok);
    try std.testing.expectEqualStrings("InvalidPolicy", bad.error_name.?);
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(io, ".ryk/policy.yaml", .{}));

    const ok = try savePolicyText(io, std.testing.allocator, root, policy_mod.presets.agentPresetText(.generic_agent));
    try std.testing.expect(ok.ok);
    try tmp.dir.access(io, ".ryk/policy.yaml", .{});
}

test "init policy refuses overwrite unless forced" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    const io = std.testing.io;
    const first = try initPolicyFromPreset(io, std.testing.allocator, root, "generic-agent", false);
    try std.testing.expect(first.ok);
    const second = try initPolicyFromPreset(io, std.testing.allocator, root, "strict-local", false);
    try std.testing.expect(!second.ok);
    try std.testing.expectEqualStrings("PolicyAlreadyExists", second.error_name.?);
    const forced = try initPolicyFromPreset(io, std.testing.allocator, root, "strict-local", true);
    try std.testing.expect(forced.ok);
}

test "status json includes policy and protected agent cards" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const io = std.testing.io;
    _ = try initPolicyFromPreset(io, std.testing.allocator, root, "generic-agent", false);
    try writeSecretlessEvidenceFixture(std.testing.allocator, root);

    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    try writeStatusJson(io, std.testing.allocator, &aw.writer, root);
    var out = aw.toArrayList();
    defer out.deinit(std.testing.allocator);

    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"policy\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"secretless_runtime\"") != null);
    // Empty-backpack honesty: never advertise pre-1d broker substitution.
    try std.testing.expect(std.mem.indexOf(u8, out.items, "substitutes broker references") == null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"Env replacement\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "Empty backpack env") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"active_broker\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"credential_refs\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"broker_checks\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"proxy_backend\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"https_visibility\":\"host-port-only\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"recent_audit_events\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"network_connect_allowed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"network_proxy_start\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"service_policy_template\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"verify_commands\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"openclaw\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"hermes\"") != null);
    // Phase 7 Safe Launch: plugin setup_commands must not re-teach demoted doors.
    try std.testing.expect(std.mem.indexOf(u8, out.items, "ryk setup") == null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "ryk agents setup openclaw") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "curl -fsSL https://rykanv.com/install | sh") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "openclaw plugins install clawhub:") == null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "ryk hermes") != null);
}

test "dashboard assets expose dedicated secretless view" {
    const io = std.testing.io;
    const index = try std.Io.Dir.cwd().readFileAlloc(io, "src/dashboard/assets/index.html", std.testing.allocator, .limited(64 * 1024));
    defer std.testing.allocator.free(index);
    const app = try std.Io.Dir.cwd().readFileAlloc(io, "src/dashboard/assets/app.js", std.testing.allocator, .limited(64 * 1024));
    defer std.testing.allocator.free(app);

    try std.testing.expect(std.mem.indexOf(u8, index, "data-view=\"secretless\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, index, "secretlessPolicyTemplate") != null);
    try std.testing.expect(std.mem.indexOf(u8, index, "secretlessCredentialRefs") != null);
    try std.testing.expect(std.mem.indexOf(u8, index, "secretlessProxyMeta") != null);
    try std.testing.expect(std.mem.indexOf(u8, index, "secretlessBrokerChecks") != null);
    try std.testing.expect(std.mem.indexOf(u8, index, "modeTitle") != null);
    try std.testing.expect(std.mem.indexOf(u8, index, "workspaceList") != null);
    try std.testing.expect(std.mem.indexOf(u8, index, "data-workspace-only") != null);
    try std.testing.expect(std.mem.indexOf(u8, app, "renderSecretless") != null);
    try std.testing.expect(std.mem.indexOf(u8, app, "insertSecretlessPolicyTemplate") != null);
    try std.testing.expect(std.mem.indexOf(u8, app, "decision_source") != null);
    try std.testing.expect(std.mem.indexOf(u8, app, "daemon_health") != null);
    try std.testing.expect(std.mem.indexOf(u8, app, "daemonHealthLabel") != null);
    try std.testing.expect(std.mem.indexOf(u8, app, "remediation") != null);
    try std.testing.expect(std.mem.indexOf(u8, app, "data.mode === \"machine\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, app, "renderWorkspaces") != null);
    try std.testing.expect(std.mem.indexOf(u8, app, "workspace_root") != null);
    try std.testing.expect(std.mem.indexOf(u8, app, "renderHermesActivity") != null);
    try std.testing.expect(std.mem.indexOf(u8, app, "hermesDecisionClass") != null);
    try std.testing.expect(std.mem.indexOf(u8, app, "approval-required") != null);
    // P2c: host filter + denial remediation (copy + allowlisted actions)
    try std.testing.expect(std.mem.indexOf(u8, index, "hostFilter") != null);
    try std.testing.expect(std.mem.indexOf(u8, index, "coverageCaption") != null);
    try std.testing.expect(std.mem.indexOf(u8, app, "data-host-filter") != null);
    try std.testing.expect(std.mem.indexOf(u8, app, "filterActionsByHost") != null);
    try std.testing.expect(std.mem.indexOf(u8, app, "remediationCommandsFor") != null);
    try std.testing.expect(std.mem.indexOf(u8, app, "suggest-allowlist") != null);
    try std.testing.expect(std.mem.indexOf(u8, app, "allowlist-list") != null);
    try std.testing.expect(std.mem.indexOf(u8, app, "No denials yet") != null);
    try std.testing.expect(std.mem.indexOf(u8, app, "PI_COVERAGE") != null);
    // XSS: dynamic plugin.id must be attribute-escaped in data-action sinks.
    try std.testing.expect(std.mem.indexOf(u8, app, "escapeHtml(plugin.id)") != null);
    try std.testing.expect(std.mem.indexOf(u8, app, "data-action=\"${plugin.id}-doctor\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, app, "function escapeHtml(value)") != null);
    try std.testing.expect(std.mem.indexOf(u8, app, ".replaceAll(\"&\", \"&amp;\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, app, ".replaceAll(\"<\", \"&lt;\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, app, ".replaceAll(\">\", \"&gt;\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, app, ".replaceAll('\"', \"&quot;\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, app, ".replaceAll(\"'\", \"&#039;\")") != null);
}

test "workspace status lists remediation quick actions" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    try writeStatusJson(std.testing.io, std.testing.allocator, &aw.writer, root);
    var out = aw.toArrayList();
    defer out.deinit(std.testing.allocator);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"id\":\"suggest-allowlist\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"id\":\"allowlist-list\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "ryk suggest-allowlist --confidence high") != null);
}

test "workspace status always includes feed health required by the activity UI" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const feed_path = try feed_writer.feedPath(std.testing.allocator, root);
    defer std.testing.allocator.free(feed_path);
    if (std.fs.path.dirname(feed_path)) |parent| try std.Io.Dir.cwd().createDirPath(std.testing.io, parent);
    try std.Io.Dir.cwd().writeFile(std.testing.io, .{ .sub_path = feed_path, .data = "{malformed}\n" });

    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer aw.deinit();
    try writeStatusJson(std.testing.io, std.testing.allocator, &aw.writer, root);
    try std.testing.expect(std.mem.indexOf(u8, aw.written(), "\"feed_health\":{\"status\":\"degraded\",\"skipped_lines\":1}") != null);
}

test "dashboard counts Hermes ask tool veto as blocked without losing ask label" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var record = try rust_visibility.buildFeedRecordFromHookActivity(
        std.testing.allocator,
        std.testing.io,
        root,
        rust_visibility.event_source_hook,
        "zig-native",
        "hermes",
        "not_applicable",
        "hermes_tool_call_ask",
        "ask",
        "approval required by policy",
        "tool call (redacted)",
        "hermes-session-1",
        false,
    );
    defer record.deinit(std.testing.allocator);
    try feed_writer.appendRecord(std.testing.io, std.testing.allocator, root, record);
    for (0..12) |_| {
        var allowed = try rust_visibility.buildFeedRecordFromHookActivity(
            std.testing.allocator,
            std.testing.io,
            root,
            rust_visibility.event_source_hook,
            rust_visibility.decision_source_zig,
            "hermes",
            "not_applicable",
            "hermes_prompt_review",
            "allow",
            "prompt reviewed",
            "prompt (redacted)",
            "hermes-session-1",
            false,
        );
        defer allowed.deinit(std.testing.allocator);
        try feed_writer.appendRecord(std.testing.io, std.testing.allocator, root, allowed);
    }

    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    try writeStatusJson(std.testing.io, std.testing.allocator, &aw.writer, root);
    var out = aw.toArrayList();
    defer out.deinit(std.testing.allocator);

    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"event_type\":\"hermes_tool_call_ask\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"decision\":\"ask\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"host\":\"hermes\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"id\":\"hermes-session-1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"denied_count\":1") != null);
}

test "workspace blocked actions returns only the latest bounded denied feed records" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    for ([_]struct { decision: []const u8, reason: []const u8 }{
        .{ .decision = "deny", .reason = "oldest blocked action" },
        .{ .decision = "allow", .reason = "allowed between blocks" },
        .{ .decision = "deny", .reason = "middle blocked action" },
        .{ .decision = "deny", .reason = "newest blocked action" },
        .{ .decision = "allow", .reason = "newest allowed action" },
    }) |fixture| {
        var record = try rust_visibility.buildFeedRecordFromHookDecision(
            std.testing.allocator,
            std.testing.io,
            root,
            "codex",
            "healthy",
            fixture.decision,
            fixture.reason,
            null,
            null,
            null,
            null,
            null,
        );
        defer record.deinit(std.testing.allocator);
        try feed_writer.appendRecord(std.testing.io, std.testing.allocator, root, record);
    }

    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try writeBlockedActionsArrayJson(std.testing.io, std.testing.allocator, &output.writer, root, 2);
    const json = output.written();

    try std.testing.expectEqual(@as(usize, 2), std.mem.count(u8, json, "\"event_type\":"));
    try std.testing.expect(std.mem.indexOf(u8, json, "oldest blocked action") == null);
    try std.testing.expect(std.mem.indexOf(u8, json, "middle blocked action") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "newest blocked action") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "newest allowed action") == null);
}

test "workspace blocked actions redact zig replay decision reason and target" {
    const allocator = std.testing.allocator;
    var replay_event = try presentation.fixtures.syntheticSecretReplayEvent(allocator);
    defer replay_event.deinit(allocator);

    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    try blocked_actions.writeBlockedActionJson(allocator, &output.writer, "zh2-dash", false, replay_event);
    const json = output.written();
    try std.testing.expect(std.mem.indexOf(u8, json, presentation.fixtures.synthetic_secret) == null);
    try std.testing.expect(std.mem.indexOf(u8, json, "[REDACTED]") != null);
}

test "workspace blocked actions redact legacy free-form fields and expose rule ids" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const feed_path = try feed_writer.feedPath(std.testing.allocator, root);
    defer std.testing.allocator.free(feed_path);
    const feed_dir = std.fs.path.dirname(feed_path).?;
    try std.Io.Dir.cwd().createDirPath(std.testing.io, feed_dir);
    const legacy_secret = "sk-legacyWorkspaceSyntheticSecret123456";
    const fixture = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"timestamp\":\"2026-07-13T00:00:00Z\",\"workspace_root\":\"{s}\",\"event_type\":\"command_denied\",\"decision\":\"deny\",\"decision_source\":\"rust-daemon\",\"event_source\":\"hook\",\"host\":\"codex\",\"daemon_status\":\"healthy\",\"pack_id\":\"core.shell\",\"severity\":\"high\",\"reason\":\"token={s}\",\"remediation\":\"Authorization: Bearer {s}\",\"target_summary\":\"--token={s}\",\"session_id\":null,\"verified\":false}}\n{{\"timestamp\":\"2026-07-13T00:00:01Z\",\"workspace_root\":\"{s}\",\"event_type\":\"command_denied\",\"decision\":\"deny\",\"decision_source\":\"rust-daemon\",\"event_source\":\"hook\",\"host\":\"codex\",\"daemon_status\":\"healthy\",\"pack_id\":\"core.shell\",\"rule\":\"core.shell:pipe\",\"severity\":\"high\",\"reason\":\"blocked\",\"remediation\":null,\"target_summary\":\"shell command (redacted)\",\"session_id\":null,\"verified\":false}}\n",
        .{ root, legacy_secret, legacy_secret, legacy_secret, root },
    );
    defer std.testing.allocator.free(fixture);
    try std.Io.Dir.cwd().writeFile(std.testing.io, .{ .sub_path = feed_path, .data = fixture });

    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try writeBlockedActionsArrayJson(std.testing.io, std.testing.allocator, &output.writer, root, 10);
    const json = output.writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, json, legacy_secret) == null);
    try std.testing.expect(std.mem.indexOf(u8, json, "[REDACTED]") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"rule\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"rule\":\"core.shell:pipe\"") != null);
}

test "sessions json filters denied replay events" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    try writeDeniedReplayFixture(std.testing.allocator, root);

    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    try writeSessionsJson(std.testing.io, std.testing.allocator, &aw.writer, root);
    var out = aw.toArrayList();
    defer out.deinit(std.testing.allocator);

    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"blocked_actions\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "rm -rf tmp") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"decision\":\"deny\"") != null);
}

fn writeDeniedReplayFixture(allocator: std.mem.Allocator, root: []const u8) !void {
    const timestamp = core.time.Timestamp.fromUnixSeconds(1_777_983_130);
    var session = core.session.Session{
        .id = try core.session.generateSessionId(timestamp),
        .started_at = timestamp,
        .ended_at = timestamp,
        .command = "ryk",
        .args = &.{ "run", "--", "rm", "-rf", "tmp" },
        .workspace_root = root,
        .mode = .strict,
        .platform = core.platform.detectOs(),
    };
    var writer = try core_api.createAuditWriter(std.testing.io, allocator, session);
    defer writer.deinit();
    const event = try core_api.createAuditEvent(.{
        .session_id = session.id,
        .event_id = try core.event.generateEventId(timestamp),
        .timestamp = timestamp,
        .event_type = .command_denied,
        .actor = .{ .kind = .ryk, .display = "ryk" },
        .target = .{ .kind = .command, .value = "rm -rf tmp" },
        .decision = core_api.makeDecision(.{ .result = .deny, .reason = "blocked by test policy" }),
    });
    try core_api.appendAuditEvent(&writer, event);
    try writer.writeLastPointer();
    try core_api.writeAuditSummary(allocator, writer.sessionDirPath(), .{
        .session = session,
        .status = .{ .exited = 1 },
        .event_count = writer.event_count,
        .final_event_hash = writer.finalHash().?,
        .policy = ".ryk/policy.yaml",
        .product_label = brand.product_display,
    });
    _ = &session;
}

fn writeSecretlessEvidenceFixture(allocator: std.mem.Allocator, root: []const u8) !void {
    const timestamp = core.time.Timestamp.fromUnixSeconds(1_777_983_131);
    var session = core.session.Session{
        .id = try core.session.generateSessionId(timestamp),
        .started_at = timestamp,
        .ended_at = timestamp,
        .command = "ryk",
        .args = &.{ "run", "--secretless", "--network-backend", "proxy", "--", "agent" },
        .workspace_root = root,
        .mode = .observe,
        .platform = core.platform.detectOs(),
    };
    var writer = try core_api.createAuditWriter(std.testing.io, allocator, session);
    defer writer.deinit();
    try appendFixtureEvent(&writer, session, timestamp, .network_proxy_start, "http://127.0.0.1:49152", .observe);
    try appendFixtureEvent(&writer, session, timestamp, .network_connect_attempt, "http://127.0.0.1:49153/echo", .observe);
    try appendFixtureEvent(&writer, session, timestamp, .network_connect_allowed, "http://127.0.0.1:49153/echo", .allow);
    try writer.writeLastPointer();
    try core_api.writeAuditSummary(allocator, writer.sessionDirPath(), .{
        .session = session,
        .status = .{ .exited = 0 },
        .event_count = writer.event_count,
        .final_event_hash = writer.finalHash().?,
        .policy = ".ryk/policy.yaml",
        .product_label = brand.product_display,
    });
    _ = &session;
}

fn appendFixtureEvent(
    writer: *core_api.AuditWriter,
    session: core.session.Session,
    timestamp: core.time.Timestamp,
    event_type: core.event.EventType,
    target: []const u8,
    result: core.decision.DecisionResult,
) !void {
    const event = try core_api.createAuditEvent(.{
        .session_id = session.id,
        .event_id = try core.event.generateEventId(timestamp),
        .timestamp = timestamp,
        .event_type = core_api.fromCoreEventType(event_type),
        .actor = .{ .kind = .ryk, .display = "ryk" },
        .target = .{ .kind = .network_endpoint, .value = target },
        .decision = core_api.makeDecision(.{ .result = result, .reason = "fixture evidence" }),
    });
    try core_api.appendAuditEvent(writer, event);
}

test "status json exposes daemon health and Zig shell decisions feed" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var record = try rust_visibility.buildFeedRecordFromHookDecision(
        std.testing.allocator,
        std.testing.io,
        root,
        "claude",
        "healthy",
        "deny",
        "blocked by ryk policy rule: destructive_rm",
        "destructive_rm",
        "Critical",
        "Use a safer workflow.",
        "git",
        null,
    );
    defer record.deinit(std.testing.allocator);
    try feed_writer.appendRecord(std.testing.io, std.testing.allocator, root, record);

    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    try writeStatusJson(std.testing.io, std.testing.allocator, &aw.writer, root);
    var out = aw.toArrayList();
    defer out.deinit(std.testing.allocator);

    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"daemon_health\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"rust_shell_decisions\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"decision_source\":\"zig-native\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"pack_id\":\"git\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"severity\":\"Critical\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "shell command (redacted)") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "matched_text_preview") == null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"raw\"") == null);
}

test "machine status aggregates registered workspaces and exposes only global actions" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const workspace_a = try std.fs.path.join(std.testing.allocator, &.{ root, "project-a" });
    defer std.testing.allocator.free(workspace_a);
    const workspace_b = try std.fs.path.join(std.testing.allocator, &.{ root, "project-b" });
    defer std.testing.allocator.free(workspace_b);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, workspace_a);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, workspace_b);
    try writeDeniedReplayFixture(std.testing.allocator, workspace_a);
    try writeDeniedReplayFixture(std.testing.allocator, workspace_b);
    const dashboard_root = try std.fs.path.join(std.testing.allocator, &.{ root, "home", ".ryk", "dashboard" });
    defer std.testing.allocator.free(dashboard_root);

    for ([_][]const u8{ workspace_a, workspace_b }) |workspace| {
        var record = try rust_visibility.buildFeedRecordFromHookDecision(
            std.testing.allocator,
            std.testing.io,
            workspace,
            "codex",
            "healthy",
            "deny",
            "blocked by ryk policy",
            null,
            null,
            null,
            null,
            null,
        );
        defer record.deinit(std.testing.allocator);
        try feed_writer.appendGlobalRecord(std.testing.io, std.testing.allocator, dashboard_root, record);
    }

    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    try writeMachineStatusJson(std.testing.io, std.testing.allocator, &aw.writer, dashboard_root);
    const out = try aw.toOwnedSlice();
    defer std.testing.allocator.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"mode\":\"machine\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"workspace_count\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, workspace_a) != null);
    try std.testing.expect(std.mem.indexOf(u8, out, workspace_b) != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"id\":\"doctor\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"id\":\"license-status\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "replay-last") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "suggest-allowlist") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "allowlist-list") == null);
}

test "machine status includes feed-backed Pi sessions" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const dashboard_root = try std.fs.path.join(std.testing.allocator, &.{ root, "home", ".ryk", "dashboard" });
    defer std.testing.allocator.free(dashboard_root);

    for ([_][]const u8{ "deny", "allow" }) |decision| {
        var record = try rust_visibility.buildFeedRecordFromHookDecision(
            std.testing.allocator,
            std.testing.io,
            root,
            "pi",
            "healthy",
            decision,
            "Pi decision",
            null,
            null,
            null,
            null,
            "pi-session-42",
        );
        defer record.deinit(std.testing.allocator);
        try feed_writer.appendGlobalRecord(std.testing.io, std.testing.allocator, dashboard_root, record);
    }

    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    try writeMachineStatusJson(std.testing.io, std.testing.allocator, &aw.writer, dashboard_root);
    const out = try aw.toOwnedSlice();
    defer std.testing.allocator.free(out);

    try std.testing.expect(std.mem.indexOf(u8, out, "\"id\":\"pi-session-42\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"host\":\"pi\"") != null);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, out, "\"id\":\"pi-session-42\""));
}

test "machine status aggregates Hermes approval blocks into sessions and blocked actions" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const dashboard_root = try std.fs.path.join(std.testing.allocator, &.{ root, "home", ".ryk", "dashboard" });
    defer std.testing.allocator.free(dashboard_root);

    var record = try rust_visibility.buildFeedRecordFromHookActivity(
        std.testing.allocator,
        std.testing.io,
        root,
        rust_visibility.event_source_hook,
        rust_visibility.decision_source_zig,
        "hermes",
        "not_applicable",
        "hermes_tool_call_ask",
        "ask",
        "approval required",
        "tool call (redacted)",
        "hermes-session-42",
        false,
    );
    defer record.deinit(std.testing.allocator);
    try feed_writer.appendGlobalRecord(std.testing.io, std.testing.allocator, dashboard_root, record);

    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    try writeMachineStatusJson(std.testing.io, std.testing.allocator, &aw.writer, dashboard_root);
    const out = try aw.toOwnedSlice();
    defer std.testing.allocator.free(out);

    try std.testing.expect(std.mem.indexOf(u8, out, "\"id\":\"hermes-session-42\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"host\":\"hermes\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"decision\":\"ask\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"denied_count\":1") != null);
}

//! First-class unattended setup and bounded health checks for long-lived agents.
//!
//! This surface is intentionally small: it composes the existing start, plugin,
//! and hook-smoke paths, while making the default host set and fail-closed
//! preset explicit for Mac mini/VPS deployments.

const std = @import("std");

const exit_codes = @import("exit_codes.zig");
const core_api = @import("ryk_core").api;
const help = @import("help.zig");
const host_status = @import("host_status.zig");
const onboarding = @import("onboarding.zig");
const plugin = @import("plugin.zig");
const start = @import("start.zig");
const suggestions = @import("suggestions.zig");

pub const default_preset = "unattended";
pub const default_hosts = "hermes,openclaw";

const RuntimeProbe = struct {
    configured: bool,
    live_verified: bool,
    note: []const u8,
};

const ExistingPolicyStatus = struct {
    mode: []const u8,
    unattended_contract: bool,
};

pub fn command(
    io: std.Io,
    cwd: std.Io.Dir,
    argv: []const []const u8,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    if (argv.len == 0 or std.mem.eql(u8, argv[0], "--help") or std.mem.eql(u8, argv[0], "-h")) {
        _ = try help.writeCommand(io, stdout, "unattended");
        return exit_codes.success;
    }

    if (std.mem.eql(u8, argv[0], "setup") or std.mem.eql(u8, argv[0], "install")) {
        return setupCommand(io, cwd, argv[1..], stdout, stderr);
    }
    if (std.mem.eql(u8, argv[0], "health") or std.mem.eql(u8, argv[0], "check")) {
        return healthCommand(io, argv[1..], stdout, stderr);
    }

    try suggestions.writeUnknownSubcommand(stderr, "ryk unattended", argv[0], &.{ "setup", "health", "install", "check" }, "unattended");
    return exit_codes.usage;
}

fn setupCommand(
    io: std.Io,
    cwd: std.Io.Dir,
    argv: []const []const u8,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    var hosts_csv: []const u8 = default_hosts;
    var index: usize = 0;
    while (index < argv.len) : (index += 1) {
        const arg = argv[index];
        if (std.mem.eql(u8, arg, "--hosts")) {
            index += 1;
            if (index >= argv.len) {
                try stderr.writeAll("ryk unattended setup: --hosts requires a comma-separated host list.\n");
                return exit_codes.usage;
            }
            hosts_csv = argv[index];
            continue;
        }
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            _ = try help.writeCommand(io, stdout, "unattended");
            return exit_codes.success;
        }
        try suggestions.writeUnknownOption(stderr, "ryk unattended setup", arg, &.{ "--hosts", "--help", "-h" }, "unattended");
        return exit_codes.usage;
    }

    // Validate before start mutates policy or host installation state.
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();
    const hosts = onboarding.parseHostsCsv(allocator, hosts_csv) catch |err| {
        if (err == error.UnsupportedHost) {
            try stderr.print("ryk unattended setup: unsupported host in '{s}'; use hermes and/or openclaw.\n", .{hosts_csv});
            return exit_codes.usage;
        }
        return err;
    };
    defer onboarding.deinitHostList(allocator, hosts);
    for (hosts) |host| {
        if (!std.mem.eql(u8, host, "hermes") and !std.mem.eql(u8, host, "openclaw")) {
            try stderr.print("ryk unattended setup: host '{s}' is outside this workflow; use hermes and/or openclaw.\n", .{host});
            return exit_codes.usage;
        }
    }

    // The normal start path preserves an existing policy. That safety property
    // is correct for general onboarding, but unattended setup must not report a
    // successful always-on deployment while leaving an attended ask policy in
    // place. Require an explicit policy replacement by the operator instead.
    const existing_policy = existingPolicyStatus(io, cwd, allocator) catch {
        try stderr.writeAll("ryk unattended setup: existing policy is unreadable or invalid; refusing host mutation.\n");
        try stderr.writeAll("  review and replace it explicitly with: ryk init --preset unattended --force\n");
        return exit_codes.general;
    };
    if (existing_policy) |status| {
        if (!policyModeAllowsUnattended(status.mode)) {
            try stderr.print(
                "ryk unattended setup: existing policy mode is '{s}'; unattended setup requires strict fail-closed mode.\n",
                .{status.mode},
            );
            try stderr.writeAll("  review and replace it explicitly with: ryk init --preset unattended --force\n");
            return exit_codes.general;
        }
        if (!status.unattended_contract) {
            try stderr.writeAll("ryk unattended setup: existing strict policy does not satisfy the unattended deny-by-default contract.\n");
            try stderr.writeAll("  review and replace it explicitly with: ryk init --preset unattended --force\n");
            return exit_codes.general;
        }
    }

    return start.runStart(io, cwd, .{
        .auto = true,
        .preset = default_preset,
        .hosts_csv = hosts_csv,
    }, stdout, stderr, null, null);
}

fn healthCommand(
    io: std.Io,
    argv: []const []const u8,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    var hosts_csv: []const u8 = default_hosts;
    var json_mode = false;
    var index: usize = 0;
    while (index < argv.len) : (index += 1) {
        const arg = argv[index];
        if (std.mem.eql(u8, arg, "--json")) {
            json_mode = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--hosts")) {
            index += 1;
            if (index >= argv.len) {
                try stderr.writeAll("ryk unattended health: --hosts requires a comma-separated host list.\n");
                return exit_codes.usage;
            }
            hosts_csv = argv[index];
            continue;
        }
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            _ = try help.writeCommand(io, stdout, "unattended");
            return exit_codes.success;
        }
        try suggestions.writeUnknownOption(stderr, "ryk unattended health", arg, &.{ "--hosts", "--json", "--help", "-h" }, "unattended");
        return exit_codes.usage;
    }

    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();
    const hosts = onboarding.parseHostsCsv(allocator, hosts_csv) catch |err| {
        if (err == error.UnsupportedHost) {
            try stderr.print("ryk unattended health: unsupported host in '{s}'; use hermes and/or openclaw.\n", .{hosts_csv});
            return exit_codes.usage;
        }
        return err;
    };
    defer onboarding.deinitHostList(allocator, hosts);
    for (hosts) |host| {
        if (!std.mem.eql(u8, host, "hermes") and !std.mem.eql(u8, host, "openclaw")) {
            try stderr.print("ryk unattended health: host '{s}' is outside this workflow; use hermes and/or openclaw.\n", .{host});
            return exit_codes.usage;
        }
    }

    var report = plugin.collectPluginDoctorReportWithHermesSmoke(io, allocator, false) catch |err| {
        if (json_mode) {
            try stdout.print("{{\"ready\":false,\"error\":\"doctor probe failed: {s}\"}}\n", .{@errorName(err)});
        } else {
            try stderr.print("ryk unattended health: doctor probe failed: {s}\n", .{@errorName(err)});
        }
        return exit_codes.general;
    };
    defer plugin.deinitPluginDoctorReport(&report, allocator);

    const policy_status = existingPolicyStatus(io, std.Io.Dir.cwd(), allocator) catch null;
    const policy_is_strict = policyModeAllowsUnattended(report.policy_mode);
    const policy_contract = policy_status != null and policy_status.?.unattended_contract;
    var ready = report.policy_present and report.policy_valid and policy_is_strict and policy_contract;
    if (json_mode) {
        try stdout.writeAll("{\n  \"schema_version\": 1,\n  \"preset\": \"unattended\",\n");
        try stdout.writeAll("  \"policy\": {\"present\": ");
        try stdout.writeAll(if (report.policy_present) "true" else "false");
        try stdout.writeAll(", \"valid\": ");
        try stdout.writeAll(if (report.policy_valid) "true" else "false");
        try stdout.writeAll(", \"mode\": ");
        if (report.policy_mode) |mode| {
            try plugin.writeJsonString(stdout, mode);
        } else {
            try stdout.writeAll("null");
        }
        try stdout.print(", \"unattended_contract\": {s}}},\n", .{if (policy_contract) "true" else "false"});
        try stdout.writeAll("  \"hosts\": [\n");
    } else {
        try stdout.writeAll("Ryk unattended health\n\n");
        try stdout.print("Preset: {s}\n", .{default_preset});
        if (report.policy_present and report.policy_valid) {
            try stdout.print("Policy: valid (mode {s}, unattended contract={s})\n", .{
                report.policy_mode orelse "unknown",
                if (policy_contract) "yes" else "no",
            });
        } else {
            try stdout.writeAll("Policy: missing or invalid\n");
        }
        try stdout.writeAll("Hosts:\n");
    }

    for (hosts, 0..) |host, host_index| {
        const binary_detected = if (std.mem.eql(u8, host, "hermes")) report.host_binaries.hermes else report.host_binaries.openclaw;
        const installed = plugin.hostPluginInstalledFromReport(host, report);
        const smoke = host_status.runHostSmokePair(allocator, host) catch host_status.HostSmokePair{};
        const probe = if (std.mem.eql(u8, host, "openclaw"))
            probeOpenClaw(allocator)
        else
            probeHermes(allocator);
        // OpenClaw has a bounded Gateway RPC probe, so a loaded plugin without
        // a healthy Gateway is not ready. Hermes currently exposes no equivalent
        // live hook probe; its enabled-plugin result is the strongest available
        // signal and remains explicitly marked live-unverified in the report.
        const runtime_ready = probe.configured and probe.live_verified;
        const host_ready = binary_detected and installed and smoke.bothPassed() and runtime_ready;
        ready = ready and host_ready;

        if (json_mode) {
            if (host_index > 0) try stdout.writeAll(",\n");
            try stdout.writeAll("    {");
            try stdout.writeAll("\"host\": ");
            try plugin.writeJsonString(stdout, host);
            try stdout.print(", \"binary_detected\": {s}, \"installed\": {s},", .{
                if (binary_detected) "true" else "false",
                if (installed) "true" else "false",
            });
            try stdout.print(" \"smoke\": {{\"allow\": ", .{});
            try plugin.writeJsonString(stdout, smoke.allow.toString());
            try stdout.print(", \"deny\": ", .{});
            try plugin.writeJsonString(stdout, smoke.deny.toString());
            try stdout.print("}}, \"runtime_configured\": {s}, \"runtime_live_verified\": {s}, \"note\": ", .{
                if (probe.configured) "true" else "false",
                if (probe.live_verified) "true" else "false",
            });
            try plugin.writeJsonString(stdout, probe.note);
            try stdout.print(", \"ready\": {s}}}", .{if (host_ready) "true" else "false"});
        } else {
            try stdout.print("  {s}: binary={s}, installed={s}, smoke={s}/{s}, runtime={s}\n", .{
                host,
                if (binary_detected) "yes" else "no",
                if (installed) "yes" else "no",
                smoke.allow.toString(),
                smoke.deny.toString(),
                probe.note,
            });
        }
    }

    if (json_mode) {
        try stdout.print("\n  ],\n  \"ready\": {s}\n}}\n", .{if (ready) "true" else "false"});
    } else {
        try stdout.print("\nOverall: {s}\n", .{if (ready) "healthy" else "not ready"});
        if (!ready) try stdout.writeAll("Remediation: ryk unattended setup, then restart the agent host(s) and rerun this check.\n");
    }
    return if (ready) exit_codes.success else exit_codes.general;
}

fn probeOpenClaw(allocator: std.mem.Allocator) RuntimeProbe {
    // A positive plugin hook count is only a metadata/configuration signal.
    // Readiness additionally requires a runtime inspection result proving the
    // enforcement hook and a healthy Gateway RPC.
    const info = plugin.captureChildOutput(allocator, &.{ "openclaw", "plugins", "info", "ryk", "--json" }) catch {
        return .{ .configured = false, .live_verified = false, .note = "runtime plugin info failed; hook registration is unverified" };
    };
    defer allocator.free(info);
    if (!openClawInfoHasLoadedHooks(allocator, info)) {
        return .{ .configured = false, .live_verified = false, .note = "runtime plugin is not loaded with registered hooks" };
    }

    const inspection = plugin.captureChildOutput(allocator, &.{ "openclaw", "plugins", "inspect", "ryk", "--runtime", "--json" }) catch {
        return .{ .configured = true, .live_verified = false, .note = "plugin metadata is loaded; runtime hook inspection is unavailable" };
    };
    defer allocator.free(inspection);
    if (!openClawRuntimeInspectionHasBeforeTool(allocator, inspection)) {
        return .{ .configured = true, .live_verified = false, .note = "OpenClaw runtime inspection did not prove before_tool_call" };
    }

    const gateway = plugin.captureChildOutput(allocator, &.{ "openclaw", "gateway", "status", "--deep", "--require-rpc" }) catch {
        return .{ .configured = true, .live_verified = false, .note = "OpenClaw plugin hooks registered; Gateway RPC is not healthy" };
    };
    allocator.free(gateway);

    // `plugins inspect --runtime` loads a discovery registry and therefore
    // cannot prove that the long-lived Gateway activated the plugin. The
    // adapter registers this read-only method only on the full runtime path;
    // a successful RPC is the bounded live activation handshake.
    const live_probe = plugin.captureChildOutput(allocator, &.{
        "openclaw", "gateway", "call", "ryk.unattended", "--params", "{\"probe\":\"unattended\"}", "--json",
    }) catch {
        return .{ .configured = true, .live_verified = false, .note = "Gateway RPC is healthy, but the active ryk plugin probe is unavailable" };
    };
    defer allocator.free(live_probe);
    if (!openClawLiveProbeSucceeded(allocator, live_probe)) {
        return .{ .configured = true, .live_verified = false, .note = "Gateway RPC is healthy, but the active ryk plugin probe did not confirm full runtime registration" };
    }
    return .{ .configured = true, .live_verified = true, .note = "OpenClaw full runtime registration, deny canary, and Gateway RPC healthy" };
}

fn openClawInfoHasLoadedHooks(allocator: std.mem.Allocator, output: []const u8) bool {
    var parsed = parseFirstJsonValue(allocator, output) orelse return false;
    defer parsed.deinit();
    if (parsed.value != .object) return false;
    const object = parsed.value.object;
    const status = object.get("status") orelse return false;
    if (status != .string or !std.mem.eql(u8, status.string, "loaded")) return false;
    const hook_count = object.get("hookCount") orelse return false;
    return hook_count == .integer and hook_count.integer > 0;
}

fn openClawRuntimeInspectionHasBeforeTool(allocator: std.mem.Allocator, output: []const u8) bool {
    var parsed = parseFirstJsonValue(allocator, output) orelse return false;
    defer parsed.deinit();
    if (parsed.value != .object) return false;
    const object = parsed.value.object;
    const plugin_value = object.get("plugin") orelse return false;
    if (plugin_value != .object) return false;
    const status = plugin_value.object.get("status") orelse return false;
    if (status != .string or !std.mem.eql(u8, status.string, "loaded")) return false;
    const typed_hooks = object.get("typedHooks") orelse return false;
    if (typed_hooks != .array) return false;
    for (typed_hooks.array.items) |entry| {
        if (entry != .object) continue;
        const name = entry.object.get("name") orelse continue;
        if (name == .string and std.mem.eql(u8, name.string, "before_tool_call")) return true;
    }
    return false;
}

fn openClawLiveProbeSucceeded(allocator: std.mem.Allocator, output: []const u8) bool {
    var parsed = parseFirstJsonValue(allocator, output) orelse return false;
    defer parsed.deinit();
    if (parsed.value != .object) return false;
    const object = parsed.value.object;
    const ok = object.get("ok") orelse return false;
    const plugin_name = object.get("plugin") orelse return false;
    const hook = object.get("hook") orelse return false;
    const registration = object.get("registration") orelse return false;
    const enforcement = object.get("enforcement") orelse return false;
    return ok == .bool and ok.bool and
        plugin_name == .string and std.mem.eql(u8, plugin_name.string, "ryk") and
        hook == .string and std.mem.eql(u8, hook.string, "before_tool_call") and
        registration == .string and std.mem.eql(u8, registration.string, "full-runtime") and
        enforcement == .string and std.mem.eql(u8, enforcement.string, "deny-canary-pass");
}

fn parseFirstJsonValue(allocator: std.mem.Allocator, output: []const u8) ?std.json.Parsed(std.json.Value) {
    var search_from: usize = 0;
    while (std.mem.indexOfAnyPos(u8, output, search_from, "[{")) |candidate_start| {
        const end = jsonDocumentEnd(output, candidate_start) orelse {
            search_from = candidate_start + 1;
            continue;
        };
        if (std.json.parseFromSlice(std.json.Value, allocator, output[candidate_start..end], .{})) |parsed| {
            return parsed;
        } else |_| {
            search_from = candidate_start + 1;
        }
    }
    return null;
}

fn jsonDocumentEnd(output: []const u8, document_start: usize) ?usize {
    var depth: usize = 0;
    var in_string = false;
    var escaped = false;
    for (output[document_start..], document_start..) |byte, index| {
        if (in_string) {
            if (escaped) {
                escaped = false;
            } else if (byte == '\\') {
                escaped = true;
            } else if (byte == '"') {
                in_string = false;
            }
            continue;
        }
        if (byte == '"') {
            in_string = true;
            continue;
        }
        switch (byte) {
            '[', '{' => depth += 1,
            ']', '}' => {
                if (depth == 0) return null;
                depth -= 1;
                if (depth == 0) return index + 1;
            },
            else => {},
        }
    }
    return null;
}

fn policyModeAllowsUnattended(mode: ?[]const u8) bool {
    return mode != null and std.mem.eql(u8, mode.?, "strict");
}

fn existingPolicyStatus(io: std.Io, cwd: std.Io.Dir, allocator: std.mem.Allocator) !?ExistingPolicyStatus {
    const workspace_root = try onboarding.resolveWorkspaceRootFromCwd(io, allocator, cwd);
    defer allocator.free(workspace_root);
    if (!onboarding.policyExists(io, workspace_root)) return null;
    var loaded = core_api.discoverPolicy(io, allocator, null, workspace_root) catch return error.InvalidExistingPolicy;
    defer loaded.deinit();
    const policy = loaded.innerPtr();
    return .{
        .mode = @tagName(policy.mode),
        .unattended_contract = isUnattendedPolicy(policy),
    };
}

fn ruleSetIsDenyByDefault(rule_set: anytype) bool {
    return rule_set.default != null and rule_set.default.? == .deny and rule_set.ask.len == 0;
}

fn isUnattendedPolicy(policy: anytype) bool {
    if (policy.mode != .strict) return false;
    if (policy.env.inherit) return false;
    if (policy.files.write_mode != .staged) return false;
    if (policy.network.effectiveMode() != .allowlist) return false;
    if (policy.audit.level != .full or !policy.audit.redact_secrets or !policy.audit.tamper_evident) return false;
    if (!ruleSetIsDenyByDefault(policy.env)) return false;
    if (!ruleSetIsDenyByDefault(policy.files.read)) return false;
    if (!ruleSetIsDenyByDefault(policy.files.write)) return false;
    if (!ruleSetIsDenyByDefault(policy.commands)) return false;
    if (!ruleSetIsDenyByDefault(policy.network)) return false;
    if (!ruleSetIsDenyByDefault(policy.mcp)) return false;
    if (policy.effects.configured and !ruleSetIsDenyByDefault(policy.effects)) return false;
    for (policy.services) |service| {
        if (!serviceFallbackIsFailClosed(service)) return false;
    }
    return true;
}

fn serviceFallbackIsFailClosed(service: anytype) bool {
    if (service.unmatched) |decision| return decision == .deny;
    return true;
}

fn probeHermes(allocator: std.mem.Allocator) RuntimeProbe {
    const listing = plugin.captureChildOutput(allocator, &.{ "hermes", "plugins", "list", "--enabled", "--json" }) catch {
        return .{ .configured = false, .live_verified = false, .note = "Hermes plugin list failed; activation is unverified" };
    };
    defer allocator.free(listing);
    if (!hermesListingHasEnabledRyk(allocator, listing)) {
        return .{ .configured = false, .live_verified = false, .note = "ryk is not reported enabled by Hermes" };
    }
    return .{ .configured = true, .live_verified = false, .note = "ryk is enabled; Hermes has no live hook introspection command" };
}

fn hermesListingHasEnabledRyk(allocator: std.mem.Allocator, listing: []const u8) bool {
    var parsed = parseFirstJsonValue(allocator, listing) orelse return false;
    defer parsed.deinit();
    if (parsed.value != .array) return false;
    for (parsed.value.array.items) |item| {
        if (item != .object) continue;
        const name = item.object.get("name") orelse continue;
        const status = item.object.get("status") orelse continue;
        if (name == .string and status == .string and
            std.mem.eql(u8, name.string, "ryk") and std.mem.eql(u8, status.string, "enabled"))
        {
            return true;
        }
    }
    return false;
}

test "unattended defaults target both autonomous hosts" {
    try std.testing.expectEqualStrings("unattended", default_preset);
    try std.testing.expectEqualStrings("hermes,openclaw", default_hosts);
}

test "openclaw runtime probe accepts a loaded positive hook count" {
    const info =
        \\{"status": "loaded", "hookCount": 4}
    ;
    try std.testing.expect(openClawInfoHasLoadedHooks(std.testing.allocator, info));
    try std.testing.expect(openClawInfoHasLoadedHooks(std.testing.allocator, "[plugins] loaded\n{\"status\":\"loaded\",\"hookCount\":4}\n[plugins] done"));
    try std.testing.expect(!openClawInfoHasLoadedHooks(std.testing.allocator,
        \\{"status":"loaded","hookCount":0}
    ));
}

test "OpenClaw runtime inspection requires the live before_tool_call hook" {
    try std.testing.expect(openClawRuntimeInspectionHasBeforeTool(std.testing.allocator, "{\"plugin\":{\"status\":\"loaded\"},\"typedHooks\":[{\"name\":\"before_tool_call\"}]}"));
    try std.testing.expect(!openClawRuntimeInspectionHasBeforeTool(std.testing.allocator, "{\"plugin\":{\"status\":\"loaded\"},\"typedHooks\":[]}"));
}

test "OpenClaw live probe requires the full runtime handshake" {
    try std.testing.expect(openClawLiveProbeSucceeded(std.testing.allocator,
        \\{"ok":true,"plugin":"ryk","hook":"before_tool_call","registration":"full-runtime","enforcement":"deny-canary-pass"}
    ));
    try std.testing.expect(!openClawLiveProbeSucceeded(std.testing.allocator,
        \\{"ok":true,"plugin":"ryk","hook":"before_tool_call","registration":"full-runtime","enforcement":"deny-canary-fail"}
    ));
}

test "Hermes runtime probe requires the exact enabled ryk entry" {
    try std.testing.expect(hermesListingHasEnabledRyk(std.testing.allocator,
        \\[{"name":"orca","status":"enabled","description":"ryk runtime guardrails"}]
    ) == false);
    try std.testing.expect(hermesListingHasEnabledRyk(std.testing.allocator,
        \\[{"name":"ryk","status":"enabled"}]
    ));
}

test "unattended health rejects a valid attended policy mode" {
    try std.testing.expect(policyModeAllowsUnattended("strict"));
    try std.testing.expect(!policyModeAllowsUnattended("ask"));
    try std.testing.expect(!policyModeAllowsUnattended(null));
}

test "unattended contract rejects broad service fallbacks" {
    const TestDecision = enum { allow, deny, observe, ask };
    const TestService = struct { unmatched: ?TestDecision = null };
    try std.testing.expect(serviceFallbackIsFailClosed(TestService{}));
    try std.testing.expect(serviceFallbackIsFailClosed(TestService{ .unmatched = .deny }));
    try std.testing.expect(!serviceFallbackIsFailClosed(TestService{ .unmatched = .allow }));
    try std.testing.expect(!serviceFallbackIsFailClosed(TestService{ .unmatched = .observe }));
    try std.testing.expect(!serviceFallbackIsFailClosed(TestService{ .unmatched = .ask }));
}

test "unattended contract rejects unsafe posture overrides" {
    const TestDecision = enum { allow, deny, ask, observe };
    const TestMode = enum { strict, ask };
    const TestWriteMode = enum { staged, direct };
    const TestNetworkMode = enum { allowlist, open };
    const TestAuditLevel = enum { full, minimal };
    const TestRuleSet = struct {
        ask: []const []const u8 = &.{},
        default: ?TestDecision = .deny,
    };
    const TestEnv = struct {
        inherit: bool = false,
        ask: []const []const u8 = &.{},
        default: ?TestDecision = .deny,
    };
    const TestFiles = struct {
        read: TestRuleSet = .{},
        write: TestRuleSet = .{},
        write_mode: TestWriteMode = .staged,
    };
    const TestNetwork = struct {
        mode: TestNetworkMode = .allowlist,
        ask: []const []const u8 = &.{},
        default: ?TestDecision = .deny,

        fn effectiveMode(self: @This()) TestNetworkMode {
            return self.mode;
        }
    };
    const TestEffects = struct {
        configured: bool = false,
        ask: []const []const u8 = &.{},
        default: ?TestDecision = .deny,
    };
    const TestAudit = struct {
        level: TestAuditLevel = .full,
        redact_secrets: bool = true,
        tamper_evident: bool = true,
    };
    const TestService = struct { unmatched: ?TestDecision = null };
    var policy = struct {
        mode: TestMode = .strict,
        env: TestEnv = .{},
        files: TestFiles = .{},
        commands: TestRuleSet = .{},
        network: TestNetwork = .{},
        mcp: TestRuleSet = .{},
        effects: TestEffects = .{},
        audit: TestAudit = .{},
        services: []const TestService = &.{},
    }{};

    try std.testing.expect(isUnattendedPolicy(&policy));
    policy.env.inherit = true;
    try std.testing.expect(!isUnattendedPolicy(&policy));
    policy.env.inherit = false;
    policy.files.write_mode = .direct;
    try std.testing.expect(!isUnattendedPolicy(&policy));
    policy.files.write_mode = .staged;
    policy.network.mode = .open;
    try std.testing.expect(!isUnattendedPolicy(&policy));
    policy.network.mode = .allowlist;
    policy.audit.tamper_evident = false;
    try std.testing.expect(!isUnattendedPolicy(&policy));
}

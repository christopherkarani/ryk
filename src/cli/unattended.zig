//! First-class unattended setup and bounded health checks for long-lived agents.
//!
//! This surface is intentionally small: it composes the existing start, plugin,
//! and hook-smoke paths, while making the default host set and fail-closed
//! preset explicit for Mac mini/VPS deployments.

const std = @import("std");

const child_process = @import("child_process.zig");
const exit_codes = @import("exit_codes.zig");
const core_api = @import("ryk_core").api;
const policy_mod = @import("ryk_core").policy;
const ensure = @import("ensure.zig");
const help = @import("help.zig");
const host_status = @import("host_status.zig");
const onboarding = @import("onboarding.zig");
const plugin = @import("plugin.zig");
const start = @import("start.zig");
const suggestions = @import("suggestions.zig");

pub const default_preset = "unattended";
pub const default_hosts = "hermes,openclaw";
pub const max_health_json_bytes: usize = 64 * 1024;
pub const total_health_timeout_ms: u32 = 25_000;
// The child runner uses a bounded TERM-to-KILL cleanup window. Reserve that
// window inside the public command-wide deadline so the reported deadline is
// a wall-clock bound, not merely the point where cleanup begins.
const health_cleanup_reserve_ms: u32 = 750;
const health_worker_timeout_ms: u32 = total_health_timeout_ms - health_cleanup_reserve_ms;
const health_worker_flag = "--__ryk-health-worker";

const RuntimeProbe = struct {
    configured: bool,
    live_verified: bool,
    note: []const u8,
};

fn hostRemediation(host: []const u8) []const u8 {
    if (std.mem.eql(u8, host, "hermes"))
        return "Restart Hermes, rerun health, and use `ryk run -- hermes ...` until live callback evidence is available.";
    return "Upgrade/restart OpenClaw, rerun health, and use `ryk run -- openclaw` until Gateway enforcement is verified.";
}

const ExistingPolicyStatus = struct {
    mode: []const u8,
    unattended_contract: bool,
};

const HealthBudget = struct {
    started: std.Io.Clock.Timestamp,

    fn init(io: std.Io) HealthBudget {
        return .{ .started = std.Io.Clock.Timestamp.now(io, .awake) };
    }

    fn nextTimeoutMs(self: HealthBudget, io: std.Io, per_probe_cap_ms: u32) ?u32 {
        const elapsed_ns: i128 = @max(@as(i128, self.started.durationFromNow(io).raw.nanoseconds), 0);
        const total_ns: i128 = @as(i128, health_worker_timeout_ms) * std.time.ns_per_ms;
        if (elapsed_ns >= total_ns) return null;
        const remaining_ms: i128 = @max(@divFloor(total_ns - elapsed_ns, std.time.ns_per_ms), 1);
        return @intCast(@min(remaining_ms, @as(i128, per_probe_cap_ms)));
    }
};

fn captureWithinHealthBudget(
    allocator: std.mem.Allocator,
    io: std.Io,
    budget: HealthBudget,
    argv: []const []const u8,
) ![]u8 {
    const timeout_ms = budget.nextTimeoutMs(io, 4_000) orelse return error.HealthDeadlineExceeded;
    return plugin.captureChildOutputTimedInCurrentProcessGroup(allocator, argv, timeout_ms);
}

pub fn command(
    io: std.Io,
    cwd: std.Io.Dir,
    argv: []const []const u8,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    if (argv.len == 0 or std.mem.eql(u8, argv[0], "--help") or std.mem.eql(u8, argv[0], "-h")) {
        _ = try help.writeCommand(io, stdout, "agents");
        return exit_codes.success;
    }

    if (std.mem.eql(u8, argv[0], "setup")) {
        return setupCommand(io, cwd, argv[1..], stdout, stderr);
    }
    if (std.mem.eql(u8, argv[0], "health")) {
        return healthCommand(io, argv[1..], stdout, stderr);
    }

    try suggestions.writeUnknownSubcommand(stderr, "ryk agents", argv[0], &.{ "setup", "health" }, "agents");
    return exit_codes.usage;
}

fn healthArgsRequestJson(argv: []const []const u8) bool {
    for (argv) |arg| if (std.mem.eql(u8, arg, "--json")) return true;
    return false;
}

fn writeHealthDeadlineFailure(stdout: anytype, json_mode: bool) !void {
    if (json_mode) {
        try stdout.writeAll("{\"schema_version\":1,\"preset\":\"unattended\",\"ready\":false,\"error\":\"health command deadline exceeded\"}\n");
    } else {
        try stdout.writeAll("Ryk agents health: command-wide deadline exceeded; protection is not ready.\n");
    }
}

fn writeHealthOutputFailure(stdout: anytype, json_mode: bool) !void {
    if (json_mode) {
        try stdout.writeAll("{\"schema_version\":1,\"preset\":\"unattended\",\"ready\":false,\"error\":\"health output exceeded bound\"}\n");
    } else {
        try stdout.writeAll("Ryk agents health: output exceeded the command bound; protection is not ready.\n");
    }
}

fn healthCommandWithDeadline(
    io: std.Io,
    argv: []const []const u8,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();
    const self_exe = std.process.executablePathAlloc(io, allocator) catch {
        try writeHealthDeadlineFailure(stdout, healthArgsRequestJson(argv));
        return exit_codes.general;
    };
    defer allocator.free(self_exe);
    const worker_argv = try allocator.alloc([]const u8, argv.len + 4);
    defer allocator.free(worker_argv);
    worker_argv[0] = self_exe;
    worker_argv[1] = "agents";
    worker_argv[2] = "health";
    worker_argv[3] = health_worker_flag;
    @memcpy(worker_argv[4..], argv);

    var result = child_process.runHostCommandCaptureTimed(allocator, worker_argv, health_worker_timeout_ms) catch {
        try writeHealthDeadlineFailure(stdout, healthArgsRequestJson(argv));
        return exit_codes.general;
    };
    defer result.deinit(allocator);
    if (result.timed_out) {
        try writeHealthDeadlineFailure(stdout, healthArgsRequestJson(argv));
        return exit_codes.general;
    }
    if (result.output_overflow) {
        try writeHealthOutputFailure(stdout, healthArgsRequestJson(argv));
        return exit_codes.general;
    }
    try stdout.writeAll(result.stdout);
    try stderr.writeAll(result.stderr);
    return result.exit_code;
}

fn parseHostSelection(allocator: std.mem.Allocator, argv: []const []const u8) ![]u8 {
    if (argv.len == 0) return allocator.dupe(u8, default_hosts);
    if (argv.len != 1) return error.InvalidHostSelection;
    const host = argv[0];
    if (!std.mem.eql(u8, host, "hermes") and !std.mem.eql(u8, host, "openclaw")) {
        return error.UnsupportedHost;
    }
    return allocator.dupe(u8, host);
}

fn setupCommand(
    io: std.Io,
    cwd: std.Io.Dir,
    argv: []const []const u8,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();
    var positional_host: ?[]const u8 = null;
    var index: usize = 0;
    while (index < argv.len) : (index += 1) {
        const arg = argv[index];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            _ = try help.writeCommand(io, stdout, "agents");
            return exit_codes.success;
        }
        if (std.mem.startsWith(u8, arg, "-")) {
            try suggestions.writeUnknownOption(stderr, "ryk agents setup", arg, &.{ "--help", "-h" }, "agents");
            return exit_codes.usage;
        }
        if (positional_host != null) {
            try stderr.writeAll("ryk agents setup: choose at most one host: hermes or openclaw.\n");
            return exit_codes.usage;
        }
        positional_host = arg;
    }

    const selection = if (positional_host) |host| &[_][]const u8{host} else &[_][]const u8{};
    const hosts_csv = parseHostSelection(allocator, selection) catch |err| switch (err) {
        error.UnsupportedHost => {
            try stderr.writeAll("ryk agents setup: host must be hermes or openclaw.\n");
            return exit_codes.usage;
        },
        error.InvalidHostSelection => return exit_codes.usage,
        else => return err,
    };
    defer allocator.free(hosts_csv);

    // Validate before start mutates policy or host installation state.
    const hosts = onboarding.parseHostsCsv(allocator, hosts_csv) catch |err| {
        if (err == error.UnsupportedHost) {
            try stderr.print("ryk agents setup: unsupported host in '{s}'; use hermes or openclaw.\n", .{hosts_csv});
            return exit_codes.usage;
        }
        return err;
    };
    defer onboarding.deinitHostList(allocator, hosts);
    for (hosts) |host| {
        if (!std.mem.eql(u8, host, "hermes") and !std.mem.eql(u8, host, "openclaw")) {
            try stderr.print("ryk agents setup: host '{s}' is outside this workflow; use hermes or openclaw.\n", .{host});
            return exit_codes.usage;
        }
    }

    // The normal start path preserves an existing policy. That safety property
    // is correct for general onboarding, but unattended setup must not report a
    // successful always-on deployment while leaving an attended ask policy in
    // place. Require an explicit policy replacement by the operator instead.
    var existing_policy = existingPolicyStatus(io, cwd, allocator) catch {
        try stderr.writeAll("ryk agents setup: existing policy is unreadable or invalid; refusing host mutation.\n");
        try stderr.writeAll("  review and replace it explicitly with: ryk init --preset unattended --force\n");
        return exit_codes.general;
    };
    if (existing_policy == null) {
        var outcome = try ensure.runEnsure(io, allocator, cwd, .{
            .from_install = false,
            .quiet = true,
            .preset = default_preset,
            .skip_verify = true,
            .skip_host_wire = true,
        }, stdout, stderr);
        defer outcome.deinit(allocator);
        if (!outcome.core_ok) {
            try stderr.writeAll("ryk agents setup: unattended policy creation failed; refusing host mutation.\n");
            return exit_codes.general;
        }
        existing_policy = existingPolicyStatus(io, cwd, allocator) catch {
            try stderr.writeAll("ryk agents setup: created policy failed validation; refusing host mutation.\n");
            return exit_codes.general;
        };
        if (existing_policy == null or !existing_policy.?.unattended_contract) {
            try stderr.writeAll("ryk agents setup: created policy does not match the reviewed unattended preset; refusing host mutation.\n");
            return exit_codes.general;
        }
    }
    if (existing_policy) |status| {
        if (!policyModeAllowsUnattended(status.mode)) {
            try stderr.print(
                "ryk agents setup: existing policy mode is '{s}'; unattended setup requires strict fail-closed mode.\n",
                .{status.mode},
            );
            try stderr.writeAll("  review and replace it explicitly with: ryk init --preset unattended --force\n");
            return exit_codes.general;
        }
        if (!status.unattended_contract) {
            try stderr.writeAll("ryk agents setup: existing policy is not semantically equal to the reviewed unattended preset.\n");
            try stderr.writeAll("  review and replace it explicitly with: ryk init --preset unattended --force\n");
            return exit_codes.general;
        }
    }

    for (hosts) |host| {
        if (!std.mem.eql(u8, host, "hermes")) continue;
        plugin.prepareHermesUnattendedInstall(io, allocator) catch |err| {
            try stderr.print("ryk agents setup: Hermes fail-closed preparation failed before activation: {s}.\n", .{@errorName(err)});
            return exit_codes.general;
        };
    }

    const setup_code = try start.runStart(io, cwd, .{
        .auto = true,
        .preset = default_preset,
        .hosts_csv = hosts_csv,
    }, stdout, stderr, null, null);
    if (setup_code != exit_codes.success) return setup_code;
    for (hosts) |host| {
        if (!std.mem.eql(u8, host, "hermes")) continue;
        plugin.hardenHermesUnattendedInstall(io, allocator) catch |err| {
            try stderr.print("ryk agents setup: Hermes unattended hardening failed: {s}.\n", .{@errorName(err)});
            return exit_codes.general;
        };
    }
    return exit_codes.success;
}

fn healthCommand(
    io: std.Io,
    argv: []const []const u8,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    for (argv) |arg| {
        if (std.mem.eql(u8, arg, health_worker_flag)) return healthCommandInner(io, argv, stdout, stderr);
    }
    return healthCommandWithDeadline(io, argv, stdout, stderr);
}

fn healthCommandInner(
    io: std.Io,
    argv: []const []const u8,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    const health_budget = HealthBudget.init(io);
    var json_mode = false;
    var positional_host: ?[]const u8 = null;
    var index: usize = 0;
    while (index < argv.len) : (index += 1) {
        const arg = argv[index];
        if (std.mem.eql(u8, arg, health_worker_flag)) continue;
        if (std.mem.eql(u8, arg, "--json")) {
            json_mode = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            _ = try help.writeCommand(io, stdout, "agents");
            return exit_codes.success;
        }
        if (std.mem.startsWith(u8, arg, "-")) {
            try suggestions.writeUnknownOption(stderr, "ryk agents health", arg, &.{ "--json", "--help", "-h" }, "agents");
            return exit_codes.usage;
        }
        if (positional_host != null) {
            try stderr.writeAll("ryk agents health: choose at most one host: hermes or openclaw.\n");
            return exit_codes.usage;
        }
        positional_host = arg;
    }

    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();
    const self_exe = std.process.executablePathAlloc(io, allocator) catch null;
    defer if (self_exe) |path| allocator.free(path);
    const selection = if (positional_host) |host| &[_][]const u8{host} else &[_][]const u8{};
    const hosts_csv = parseHostSelection(allocator, selection) catch |err| switch (err) {
        error.UnsupportedHost => {
            try stderr.writeAll("ryk agents health: host must be hermes or openclaw.\n");
            return exit_codes.usage;
        },
        error.InvalidHostSelection => return exit_codes.usage,
        else => return err,
    };
    defer allocator.free(hosts_csv);
    const hosts = onboarding.parseHostsCsv(allocator, hosts_csv) catch |err| {
        if (err == error.UnsupportedHost) {
            try stderr.print("ryk agents health: unsupported host in '{s}'; use hermes or openclaw.\n", .{hosts_csv});
            return exit_codes.usage;
        }
        return err;
    };
    defer onboarding.deinitHostList(allocator, hosts);
    for (hosts) |host| {
        if (!std.mem.eql(u8, host, "hermes") and !std.mem.eql(u8, host, "openclaw")) {
            try stderr.print("ryk agents health: host '{s}' is outside this workflow; use hermes or openclaw.\n", .{host});
            return exit_codes.usage;
        }
    }

    var report = plugin.collectPluginDoctorReportForAgentsHealth(io, allocator) catch |err| {
        if (json_mode) {
            try stdout.print("{{\"ready\":false,\"error\":\"doctor probe failed: {s}\"}}\n", .{@errorName(err)});
        } else {
            try stderr.print("ryk agents health: doctor probe failed: {s}\n", .{@errorName(err)});
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
        try stdout.writeAll("Ryk agents health\n\n");
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
        const identity_timeout = health_budget.nextTimeoutMs(io, 3_000);
        const host_binary = if (identity_timeout) |timeout_ms|
            plugin.trustedHostBinaryTimed(io, allocator, host, timeout_ms) catch null
        else
            null;
        defer if (host_binary) |path| allocator.free(path);
        const binary_detected = host_binary != null;
        const installed = plugin.hostPluginInstalledFromReport(host, report);
        const smoke_timeout = health_budget.nextTimeoutMs(io, 6_000);
        const smoke = if (self_exe != null and smoke_timeout != null)
            host_status.runHostSmokePairWithBinaryTimed(
                allocator,
                self_exe.?,
                host,
                @max(@as(u64, smoke_timeout.?) / 2, 1),
            ) catch host_status.HostSmokePair{}
        else
            host_status.HostSmokePair{};
        const probe = if (host_binary) |binary|
            if (std.mem.eql(u8, host, "openclaw"))
                probeOpenClaw(allocator, io, health_budget, binary)
            else
                probeHermes(allocator, io, health_budget, binary)
        else
            RuntimeProbe{ .configured = false, .live_verified = false, .note = "trusted host executable not found" };
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
            try stdout.writeAll(", \"remediation\": ");
            try plugin.writeJsonString(stdout, if (host_ready) "none" else hostRemediation(host));
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
            if (!host_ready) try stdout.print("    remediation: {s}\n", .{hostRemediation(host)});
        }
    }

    if (json_mode) {
        try stdout.print("\n  ],\n  \"ready\": {s}\n}}\n", .{if (ready) "true" else "false"});
    } else {
        try stdout.print("\nOverall: {s}\n", .{if (ready) "healthy" else "not ready"});
        if (!ready) try stdout.writeAll("Remediation: follow each host-specific wrapper fallback above; setup alone cannot manufacture live-hook evidence.\n");
    }
    return if (ready) exit_codes.success else exit_codes.general;
}

fn probeOpenClaw(allocator: std.mem.Allocator, io: std.Io, budget: HealthBudget, binary: []const u8) RuntimeProbe {
    // Current OpenClaw aliases `plugins info` to `plugins inspect`, whose JSON
    // is nested. Use the authoritative runtime inspection once; metadata-only
    // or discovery registration never counts as enforcement.
    const inspection = captureWithinHealthBudget(allocator, io, budget, &.{ binary, "plugins", "inspect", "ryk", "--runtime", "--json" }) catch {
        return .{ .configured = false, .live_verified = false, .note = "OpenClaw runtime hook inspection is unavailable" };
    };
    defer allocator.free(inspection);
    const bundled_root = plugin.resolveOpenClawBundleRoot(io, allocator) catch {
        return .{ .configured = false, .live_verified = false, .note = "reviewed OpenClaw bundle is unavailable" };
    };
    defer allocator.free(bundled_root);
    if (!plugin.openClawInstalledBundleMatches(io, allocator, inspection, bundled_root)) {
        return .{ .configured = false, .live_verified = false, .note = "OpenClaw runtime plugin is not the receipt-bound reviewed Ryk bundle" };
    }
    if (!openClawRuntimeInspectionHasBeforeTool(allocator, inspection)) {
        return .{ .configured = false, .live_verified = false, .note = "OpenClaw runtime inspection did not prove a loaded before_tool_call hook" };
    }

    const binding_output = captureWithinHealthBudget(allocator, io, budget, &.{
        binary,
        "config",
        "get",
        "plugins.entries.ryk.config.workspaceRoot",
        "--json",
    }) catch {
        return .{ .configured = false, .live_verified = false, .note = "OpenClaw operator-controlled workspace binding is unavailable" };
    };
    defer allocator.free(binding_output);
    const configured_workspace = plugin.parseOpenClawWorkspaceBinding(allocator, binding_output) catch {
        return .{ .configured = false, .live_verified = false, .note = "OpenClaw workspace binding is missing or not an absolute JSON string" };
    };
    defer allocator.free(configured_workspace);
    const canonical_workspace = std.Io.Dir.cwd().realPathFileAlloc(io, configured_workspace, allocator) catch {
        return .{ .configured = false, .live_verified = false, .note = "OpenClaw workspace binding does not resolve to an existing directory" };
    };
    defer allocator.free(canonical_workspace);
    if (!std.mem.eql(u8, configured_workspace, canonical_workspace)) {
        return .{ .configured = false, .live_verified = false, .note = "OpenClaw workspace binding is not canonical" };
    }

    const gateway = captureWithinHealthBudget(allocator, io, budget, &.{ binary, "gateway", "status", "--deep", "--require-rpc", "--json" }) catch {
        return .{ .configured = true, .live_verified = false, .note = "OpenClaw plugin hooks registered; Gateway RPC is not healthy" };
    };
    defer allocator.free(gateway);
    if (!openClawGatewayIdentityBound(gateway)) {
        return .{ .configured = true, .live_verified = false, .note = "OpenClaw Gateway RPC is reachable, but its running identity is not bound to the screened executable" };
    }

    // Runtime inspection loads modules but cannot prove that the already-running
    // Gateway activated this plugin. Invoke the manifest-declared inert tool via
    // the real Gateway dispatcher. Only a nonce-bound Ryk denial counts; a
    // generic host refusal or the inert executor sentinel fails readiness.
    const nonce = std.fmt.allocPrint(allocator, "ryk-health-{x}", .{budget.started.raw.nanoseconds}) catch {
        return .{ .configured = true, .live_verified = false, .note = "Gateway RPC is healthy, but canary creation failed" };
    };
    defer allocator.free(nonce);
    if (std.mem.indexOfAny(u8, canonical_workspace, "\"\\\n\r") != null) {
        return .{ .configured = true, .live_verified = false, .note = "Gateway RPC is healthy, but the workspace path cannot be encoded safely" };
    }
    const params = std.fmt.allocPrint(
        allocator,
        "{{\"name\":\"ryk_openclaw_canary\",\"args\":{{\"command\":\"rm -rf /\",\"nonce\":\"{s}\",\"cwd\":\"{s}\"}},\"sessionKey\":\"ryk-health\",\"idempotencyKey\":\"{s}\"}}",
        .{ nonce, canonical_workspace, nonce },
    ) catch {
        return .{ .configured = true, .live_verified = false, .note = "Gateway RPC is healthy, but canary encoding failed" };
    };
    defer allocator.free(params);
    const timeout_ms = budget.nextTimeoutMs(io, 4_000) orelse
        return .{ .configured = true, .live_verified = false, .note = "Gateway RPC is healthy, but the health deadline expired" };
    var live_probe = child_process.runHostCommandCaptureTimed(allocator, &.{
        binary, "gateway", "call", "tools.invoke", "--params", params, "--json",
    }, timeout_ms) catch {
        return .{ .configured = true, .live_verified = false, .note = "Gateway RPC is healthy, but the dispatcher canary is unavailable" };
    };
    defer live_probe.deinit(allocator);
    if (live_probe.timed_out or live_probe.output_overflow or !openClawDispatcherCanaryPassed(allocator, live_probe.stdout, live_probe.stderr, nonce)) {
        return .{ .configured = true, .live_verified = false, .note = "Gateway RPC is healthy, but the real tool dispatcher did not prove Ryk enforcement" };
    }
    return .{ .configured = true, .live_verified = true, .note = "OpenClaw Gateway dispatcher, before_tool_call denial, and RPC healthy" };
}

/// OpenClaw's Gateway status/RPC contract currently proves dispatch through a
/// Gateway, but does not expose an authoritative process identity that Ryk can
/// compare with the screened executable. Keep readiness false until upstream
/// supplies such a field and the comparison is implemented.
fn openClawGatewayIdentityBound(output: []const u8) bool {
    _ = output;
    return false;
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

fn openClawDispatcherCanaryPassed(allocator: std.mem.Allocator, stdout: []const u8, stderr: []const u8, nonce: []const u8) bool {
    const marker_prefix = "RYK_CANARY_BLOCK:";
    const executor_ran = std.mem.indexOf(u8, stdout, "inert-tool-executor") != null or
        std.mem.indexOf(u8, stderr, "inert-tool-executor") != null or
        std.mem.indexOf(u8, stdout, "Ryk inert OpenClaw canary completed") != null or
        std.mem.indexOf(u8, stderr, "Ryk inert OpenClaw canary completed") != null;
    if (executor_ran) return false;

    var parsed = parseFirstJsonValue(allocator, stdout) orelse return false;
    defer parsed.deinit();
    if (parsed.value != .object) return false;
    const object = parsed.value.object;
    const ok = object.get("ok") orelse return false;
    const tool_name = object.get("toolName") orelse return false;
    const error_value = object.get("error") orelse return false;
    if (ok != .bool or ok.bool or tool_name != .string or
        !std.mem.eql(u8, tool_name.string, "ryk_openclaw_canary") or error_value != .object) return false;
    const code = error_value.object.get("code") orelse return false;
    const message = error_value.object.get("message") orelse return false;
    return code == .string and std.mem.eql(u8, code.string, "forbidden") and
        message == .string and message.string.len == marker_prefix.len + nonce.len and
        std.mem.startsWith(u8, message.string, marker_prefix) and
        std.mem.eql(u8, message.string[marker_prefix.len..], nonce);
}

fn parseFirstJsonValue(allocator: std.mem.Allocator, output: []const u8) ?std.json.Parsed(std.json.Value) {
    const candidate_start = std.mem.indexOfAny(u8, output, "[{") orelse return null;
    const end = jsonDocumentEnd(output, candidate_start) orelse return null;
    return std.json.parseFromSlice(std.json.Value, allocator, output[candidate_start..end], .{}) catch null;
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
    if (comptime @TypeOf(policy.*) == policy_mod.schema.Policy) {
        var reviewed = policy_mod.load.loadAgentPreset(policy.allocator, .unattended) catch return false;
        defer reviewed.deinit();
        return policy_mod.presets.unattendedSemanticsEqual(policy, &reviewed);
    }
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

fn probeHermes(allocator: std.mem.Allocator, io: std.Io, budget: HealthBudget, binary: []const u8) RuntimeProbe {
    const listing = captureWithinHealthBudget(allocator, io, budget, &.{ binary, "plugins", "list", "--enabled", "--json" }) catch {
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

test "agents setup accepts one positional host and defaults to both" {
    const defaults = try parseHostSelection(std.testing.allocator, &.{});
    defer std.testing.allocator.free(defaults);
    try std.testing.expectEqualStrings(default_hosts, defaults);

    const hermes = try parseHostSelection(std.testing.allocator, &.{"hermes"});
    defer std.testing.allocator.free(hermes);
    try std.testing.expectEqualStrings("hermes", hermes);

    const openclaw = try parseHostSelection(std.testing.allocator, &.{"openclaw"});
    defer std.testing.allocator.free(openclaw);
    try std.testing.expectEqualStrings("openclaw", openclaw);
}

test "agents health JSON and total runtime have fixed bounds" {
    try std.testing.expect(max_health_json_bytes <= 64 * 1024);
    try std.testing.expect(total_health_timeout_ms <= 30_000);
    try std.testing.expect(health_worker_timeout_ms < total_health_timeout_ms);
}

test "OpenClaw runtime inspection requires the live before_tool_call hook" {
    try std.testing.expect(openClawRuntimeInspectionHasBeforeTool(std.testing.allocator, "{\"plugin\":{\"status\":\"loaded\"},\"typedHooks\":[{\"name\":\"before_tool_call\"}]}"));
    try std.testing.expect(!openClawRuntimeInspectionHasBeforeTool(std.testing.allocator, "{\"plugin\":{\"status\":\"loaded\"},\"typedHooks\":[]}"));
}

test "OpenClaw dispatcher canary requires nonce-bound Ryk denial and no executor sentinel" {
    try std.testing.expect(openClawDispatcherCanaryPassed(std.testing.allocator,
        "{\"ok\":false,\"toolName\":\"ryk_openclaw_canary\",\"error\":{\"code\":\"forbidden\",\"message\":\"RYK_CANARY_BLOCK:nonce-1\"}}",
        "",
        "nonce-1",
    ));
    try std.testing.expect(!openClawDispatcherCanaryPassed(std.testing.allocator, "forbidden", "", "nonce-1"));
    try std.testing.expect(!openClawDispatcherCanaryPassed(std.testing.allocator,
        "{\"ok\":false,\"toolName\":\"ryk_openclaw_canary\",\"error\":{\"code\":\"forbidden\",\"message\":\"RYK_CANARY_BLOCK:wrong\"}}",
        "",
        "nonce-1",
    ));
    try std.testing.expect(!openClawDispatcherCanaryPassed(std.testing.allocator,
        "{\"ok\":false,\"toolName\":\"ryk_openclaw_canary\",\"error\":{\"code\":\"forbidden\",\"message\":\"RYK_CANARY_BLOCK:nonce-1\"},\"evidence\":\"inert-tool-executor\"}",
        "",
        "nonce-1",
    ));
    try std.testing.expect(!openClawDispatcherCanaryPassed(std.testing.allocator,
        "{\"ok\":false,\"toolName\":\"ryk_openclaw_canary\",\"nonce\":\"nonce-1\",\"error\":{\"code\":\"forbidden\",\"message\":\"RYK_CANARY_BLOCK:\"}}",
        "",
        "nonce-1",
    ));
}

test "OpenClaw Gateway readiness requires an independently bound running identity" {
    try std.testing.expect(!openClawGatewayIdentityBound("{\"status\":\"ok\"}"));
    try std.testing.expect(!openClawGatewayIdentityBound("{\"pid\":1234}"));
}

test "OpenClaw JSON framing rejects an unbalanced brace flood in linear work" {
    var flood: [max_health_json_bytes]u8 = undefined;
    @memset(&flood, '{');
    try std.testing.expect(parseFirstJsonValue(std.testing.allocator, &flood) == null);
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

test "unattended contract rejects broad custom allow rules" {
    var reviewed = try policy_mod.load.loadAgentPreset(std.testing.allocator, .unattended);
    defer reviewed.deinit();
    try std.testing.expect(isUnattendedPolicy(&reviewed));

    const broad = [_][]const u8{"*"};
    const reviewed_allow = reviewed.commands.allow;
    reviewed.commands.allow = &broad;
    try std.testing.expect(!isUnattendedPolicy(&reviewed));
    reviewed.commands.allow = reviewed_allow;
}

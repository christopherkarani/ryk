const std = @import("std");
const builtin = @import("builtin");
const gpa_mod = @import("gpa.zig");
const env_util = @import("../env_util.zig");
const core = @import("ryk_core").core;
const redact_bridge = @import("ryk_core").audit.redact_bridge;
const supervisor = core.supervisor;
const mcp_mod = @import("../mcp/mod.zig");
const policy_mod = @import("ryk_core").policy;
const sandbox = @import("../sandbox/mod.zig");
const resource_root = @import("../resource_root.zig");
const tui = @import("ryk").tui;
const style = @import("style.zig");

const exit_codes = @import("exit_codes.zig");
const help = @import("help.zig");
const cli = @import("mod.zig");
const suggestions = @import("suggestions.zig");
const plugin = @import("plugin.zig");
const onboarding = @import("onboarding.zig");
const host_status = @import("host_status.zig");
const pack_state = @import("pack_state.zig");
const readiness = @import("readiness.zig");
const ensure = @import("ensure.zig");
const brand = @import("brand.zig");
const policy_migrate = @import("policy_migrate.zig");
const deadlock_check = @import("deadlock_check.zig");
const enable_tui = @import("build_options").enable_tui;
const doctor_tui = if (enable_tui) @import("doctor_tui.zig") else struct {
    pub const fail_closed_message =
        "ryk doctor: --tui requires a TUI-enabled ryk build; using linear report.\n";
    pub fn wouldEnterDoctorTui(
        stdin_is_tty: bool,
        stdout_is_tty: bool,
        argv: []const []const u8,
        want_tui: bool,
        machine_json: bool,
    ) bool {
        _ = .{ stdin_is_tty, stdout_is_tty, argv, want_tui, machine_json };
        return false;
    }
};
const doctor_mcp = @import("doctor_mcp.zig");
const core_api = @import("ryk_core").api;

// Monopath: pull nested doctor_tui / doctor_mcp / deadlock_check tests into the
// lib test binary.
test {
    if (enable_tui) {
        _ = @import("doctor_tui.zig");
    }
    _ = doctor_mcp;
    _ = deadlock_check;
}

const DoctorCapability = struct {
    label: []const u8,
    feature: ?sandbox.backend.Feature = null,
    capability: ?core.platform.Capability = null,
};

const doctor_capabilities = [_]DoctorCapability{
    .{ .label = "process supervision", .feature = .process_supervision },
    .{ .label = "env filtering", .feature = .env_filtering },
    .{ .label = "staged writes", .feature = .path_staging },
    .{ .label = "mcp stdio proxy", .feature = .mcp_stdio_proxy },
    .{ .label = "network policy engine", .capability = .network_policy_engine },
    .{ .label = "network observation", .feature = .network_observe },
    .{ .label = "transparent network enforcement", .feature = .network_enforce },
    .{ .label = "proxy-mediated enforcement", .capability = .network_proxy_enforce },
    .{ .label = "strong sandbox", .feature = .strong_sandbox },
};

const AgentBinary = struct {
    name: []const u8,
    command: []const u8,
};

const known_agent_binaries = [_]AgentBinary{
    .{ .name = "Claude Code", .command = "claude" },
    .{ .name = "Codex", .command = "codex" },
    .{ .name = "Cursor", .command = "cursor" },
    .{ .name = "OpenCode", .command = "opencode" },
    .{ .name = "Cline/Roo", .command = "cline" },
};

const IntegrationContext = struct {
    allocator: std.mem.Allocator,
    workspace_root: []const u8,
    git_present: bool,
    policy_present: bool,
    policy_valid: bool,
    policy_error: ?[]const u8 = null,
    agent_found: []const AgentBinary,
    mcp_manifest_count: usize,
    mcp_manifest_invalid_count: usize,
    ci_detected: bool,
    ci_provider: []const u8,
    shell_name: []const u8,
    audit_sessions_present: bool,
    redteam_fixtures_present: bool,
    daemon_binary_path: ?[]const u8 = null,
    daemon_binary_exists: bool = false,
    daemon_binary_executable: bool = false,
    daemon_binary_untrusted: bool = false,
    daemon_socket_path: ?[]const u8 = null,
    daemon_socket_exists: bool = false,
    daemon_pid_path: ?[]const u8 = null,
    daemon_pid_exists: bool = false,
    /// Canonical daemon health (enum — not stringly typed).
    daemon_health: onboarding.DaemonHealthStatus,
    daemon_detail: []const u8,
    /// Host integration snapshot for the doctor host table (owned slices).
    host_rows: []const HostDoctorRow = &.{},
    hermes_fail_open: bool = true,
    hermes_installed: bool = false,
    /// Stale-default notices (workspace + user-global policies). Informational
    /// only — never flips --check. Owned slices.
    policy_notices: []const policy_migrate.StaleNotice = &.{},

    fn deinit(self: *IntegrationContext) void {
        self.allocator.free(self.workspace_root);
        if (self.policy_error) |value| self.allocator.free(value);
        if (self.agent_found.len > 0) self.allocator.free(self.agent_found);
        self.allocator.free(self.ci_provider);
        self.allocator.free(self.shell_name);
        if (self.daemon_binary_path) |value| self.allocator.free(value);
        if (self.daemon_socket_path) |value| self.allocator.free(value);
        if (self.daemon_pid_path) |value| self.allocator.free(value);
        self.allocator.free(self.daemon_detail);
        if (self.host_rows.len > 0) {
            for (self.host_rows) |row| {
                self.allocator.free(row.host);
                self.allocator.free(row.wired);
                self.allocator.free(row.shell_gate);
                self.allocator.free(row.fail_stance);
                self.allocator.free(row.smoke_allow);
                self.allocator.free(row.smoke_deny);
                self.allocator.free(row.fix);
            }
            self.allocator.free(self.host_rows);
        }
        if (self.policy_notices.len > 0) {
            for (self.policy_notices) |notice| self.allocator.free(notice.path);
            self.allocator.free(self.policy_notices);
        }
        self.* = undefined;
    }
};

const HostDoctorRow = struct {
    host: []const u8,
    wired: []const u8,
    shell_gate: []const u8,
    fail_stance: []const u8,
    smoke_allow: []const u8,
    smoke_deny: []const u8,
    fix: []const u8,
};

const DaemonHealth = struct {
    status: onboarding.DaemonHealthStatus,
    detail: []const u8,
};

const DoctorOptions = struct {
    verbose: bool = false,
    check: bool = false,
    json: bool = false,
    /// Opt-in four-pane deep-dive TUI (linear remains the default).
    tui: bool = false,
    /// Public repair door: early-branch to shared ensure (D40).
    fix: bool = false,
    /// Install-scope ensure: HOME + resource-root resolution (D32).
    from_install: bool = false,
    /// Optional preset for create-if-missing policy (null → ensure default).
    preset: ?[]const u8 = null,
    /// Door A self-check: replay a standard coding workflow against the active
    /// policy and report steps that would stall an agent (or let danger through).
    deadlock_check: bool = false,
};

pub fn command(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    const options = parseDoctorOptions(argv, stderr) catch return exit_codes.usage;
    for (argv) |arg| {
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            _ = try help.writeCommand(io, stdout, "doctor");
            return exit_codes.success;
        }
    }

    var gpa_state: gpa_mod.State = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();

    // Door A self-check: read-only probe on the active policy, no daemon spawn.
    if (options.deadlock_check) {
        return runDeadlockCheck(io, allocator, stdout, stderr);
    }

    // Sole taught repair door (D40): --fix early-branches to ensure before any
    // diagnose collect / daemon spawn. Exit map is ensure.processExitForOutcome
    // (D25: 0 iff core_ok). No hard-dep on daemon ensure_running (D41).
    // Default / --check / --json remain diagnose or probe-only (D42).
    if (options.fix) {
        try writeNonProductFixWarning(io, allocator, stderr);
        const pi_before = host_status.inspectPi(io, allocator);
        const grok_before = host_status.inspectGrok(io, allocator);
        var outcome = try ensure.runEnsure(
            io,
            allocator,
            std.Io.Dir.cwd(),
            .{
                .from_install = options.from_install,
                .quiet = false,
                .preset = options.preset,
                .skip_verify = false,
                .migrate_stale_defaults = true,
            },
            stdout,
            stderr,
        );
        defer outcome.deinit(allocator);
        // Honesty receipt for partial soft-success and core_failed (not silent on either).
        if (outcome.protection_label == .partial or outcome.protection_label == .core_failed) {
            try ensure.writeEnsureReceipt(stdout, outcome);
        }
        try writeBakeRepairNotes(stdout, pi_before, host_status.inspectPi(io, allocator), grok_before, host_status.inspectGrok(io, allocator));
        return ensure.processExitForOutcome(outcome);
    }

    const os = core.platform.detectOs();
    const backend_report = sandbox.backend.detect(os);
    // --check/--json are probe contracts: never spawn/ensure the daemon.
    const ensure_running = !(options.check or options.json);
    var context = collectIntegrationContext(io, allocator, ensure_running) catch |err| {
        try stderr.print("ryk doctor: failed to collect integration context: {s}\n", .{@errorName(err)});
        return exit_codes.general;
    };
    defer context.deinit();

    const core_ready = readiness.assess(context.daemon_health, context.policy_present, context.policy_valid);
    if (options.json) {
        // --json frozen: never enter TUI even when --tui is also present.
        const policy_path = try std.fs.path.join(allocator, &.{ context.workspace_root, ".ryk", "policy.yaml" });
        defer allocator.free(policy_path);
        try readiness.writeJsonEnvelope(stdout, .{
            .allocator = allocator,
            .assessment = core_ready,
            .check = options.check,
            .daemon_status = readiness.daemonWireLabel(context.daemon_health),
            .daemon_detail = context.daemon_detail,
            .policy_path = policy_path,
            .policy_error = context.policy_error,
            .close_object = true,
        });
    } else if (options.tui and doctor_tui.wouldEnterDoctorTui(
        isStdinTty(io),
        isStdoutTty(io, stdout),
        argv,
        true,
        false,
    )) {
        if (comptime enable_tui) {
            const tui_code = try runDoctorTui(io, allocator, stdout, os, backend_report, context);
            // Tty.init / loop failure → linear report (never green-paint empty TUI success).
            if (tui_code != exit_codes.success) {
                try stderr.writeAll(doctor_tui.fail_closed_message);
                try writeReport(io, stdout, os, backend_report, context, options.verbose);
            }
        }
    } else {
        if (options.tui) {
            // Fail-closed: message + linear fallback (D2).
            try stderr.writeAll(doctor_tui.fail_closed_message);
        }
        if (options.check) {
            try writeCheckReceipt(stdout, core_ready, context);
        } else {
            try writeReport(io, stdout, os, backend_report, context, options.verbose);
        }
    }
    return core_ready.exitCode(options.check);
}

fn writeCheckReceipt(stdout: anytype, assessment: readiness.Assessment, context: IntegrationContext) !void {
    var receipt_buf: [96]u8 = undefined;
    const receipt = assessment.formatReceipt(&receipt_buf);
    if (assessment.ready) {
        try stdout.print("ready · {s}\n", .{receipt});
        return;
    }
    try stdout.print("not ready · {s}\n", .{receipt});
    if (context.daemon_health != .compatible) {
        try stdout.writeAll("Next: ryk doctor --fix\n");
    } else if (!context.policy_present) {
        try stdout.writeAll("Next: ryk doctor --fix\n");
    } else if (!context.policy_valid) {
        try stdout.writeAll("Next: ryk policy check .ryk/policy.yaml\n");
    }
}

fn isStdinTty(io: std.Io) bool {
    return std.Io.File.stdin().isTty(io) catch false;
}

fn isStdoutTty(io: std.Io, stdout: anytype) bool {
    _ = stdout;
    return std.Io.File.stdout().isTty(io) catch false;
}

/// Build pure pane facts from the linear doctor context and open the browse kit.
fn runDoctorTui(
    io: std.Io,
    allocator: std.mem.Allocator,
    stdout: anytype,
    os: core.platform.Os,
    backend_report: sandbox.backend.ReportSet,
    context: IntegrationContext,
) !u8 {
    const redacted_daemon_detail = try redact_bridge.redactAlloc(allocator, context.daemon_detail);
    defer allocator.free(redacted_daemon_detail);
    const counts = countCapabilitySummary(os, backend_report);
    const policy_status = if (!context.policy_present)
        "no policy"
    else if (!context.policy_valid)
        "policy invalid"
    else
        "policy valid";

    // Packs one-liner for Summary — Zig inventory (not daemon-gated).
    var packs_summary = pack_state.queryPacksSummaryDefault(io, allocator) catch pack_state.unknownPacksSummary();
    defer packs_summary.deinit(allocator);

    var packs_buf: [160]u8 = undefined;
    const packs_line = doctor_tui.formatPacksLine(
        &packs_buf,
        packs_summary.known,
        packs_summary.optInCount(),
    );

    const summary: doctor_tui.SummaryFacts = .{
        .os = os.toString(),
        .policy_status = policy_status,
        .daemon_status = daemonStatusSummary(context.daemon_health),
        .active = counts.active,
        .limited = counts.limited,
        .unavailable = counts.unavailable,
        .packs_line = packs_line,
        .secret_boundary = secretBoundaryCapability(backend_report),
    };

    var host_facts = try allocator.alloc(doctor_tui.HostFact, context.host_rows.len);
    defer allocator.free(host_facts);
    for (context.host_rows, 0..) |row, i| {
        host_facts[i] = .{
            .host = row.host,
            .wired = row.wired,
            .shell_gate = row.shell_gate,
            .fail_stance = row.fail_stance,
            .smoke_allow = row.smoke_allow,
            .smoke_deny = row.smoke_deny,
            .fix = row.fix,
        };
    }

    var cap_facts: [doctor_capabilities.len]doctor_tui.CapabilityFact = undefined;
    for (doctor_capabilities, 0..) |item, index| {
        if (item.feature) |feature| {
            const report = backend_report.get(feature);
            const display_level = doctorDisplayLevel(feature, report.level);
            cap_facts[index] = .{
                .label = item.label,
                .level = display_level.toString(),
                .glyph = levelColorAndGlyph(display_level).glyph,
            };
        } else if (item.capability) |capability| {
            const report = core.platform.reportCapability(os, capability);
            cap_facts[index] = .{
                .label = item.label,
                .level = report.state.toString(),
                .glyph = stateColorAndGlyph(report.state).glyph,
            };
        }
    }

    const next: doctor_tui.NextStepFacts = .{
        .daemon_health_compatible = context.daemon_health == .compatible,
        .daemon_detail = redacted_daemon_detail,
        .daemon_binary_untrusted = context.daemon_binary_untrusted,
        .daemon_binary_exists = context.daemon_binary_exists,
        .daemon_binary_executable = context.daemon_binary_executable,
        .policy_present = context.policy_present,
        .policy_valid = context.policy_valid,
        .mcp_manifest_invalid_count = context.mcp_manifest_invalid_count,
        .redteam_fixtures_present = context.redteam_fixtures_present,
        .hermes_fail_open = context.hermes_fail_open,
        .hermes_installed = context.hermes_installed,
    };

    return try doctor_tui.run(io, allocator, stdout, .{
        .summary = summary,
        .hosts = host_facts,
        .capabilities = &cap_facts,
        .next = next,
    });
}

fn parseDoctorOptions(argv: []const []const u8, stderr: anytype) !DoctorOptions {
    var options: DoctorOptions = .{};
    var i: usize = 0;
    while (i < argv.len) : (i += 1) {
        const arg = argv[i];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) continue;
        if (std.mem.eql(u8, arg, "-v") or std.mem.eql(u8, arg, "--verbose")) {
            options.verbose = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--check")) {
            options.check = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--json")) {
            options.json = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--plain") or std.mem.eql(u8, arg, "--no-rich")) {
            // Linear report escape (matches help: non-TTY / --json / --plain).
            // Also disables opt-in --tui via shouldEnterTui when still on argv.
            continue;
        }
        if (std.mem.eql(u8, arg, "--tui")) {
            options.tui = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--fix")) {
            options.fix = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--deadlock-check")) {
            options.deadlock_check = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--from-install")) {
            options.from_install = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--preset")) {
            i += 1;
            if (i >= argv.len) {
                try stderr.writeAll("ryk doctor: --preset requires a preset name.\n");
                return error.Usage;
            }
            const name = argv[i];
            // Same names as init.zig; brand as doctor so invalid values never leak ryk init:.
            if (policy_mod.presets.AgentPreset.parse(name) == null) {
                try suggestions.writeInvalidValue(
                    stderr,
                    "ryk doctor",
                    "--preset",
                    name,
                    &.{
                        "generic-agent", "claude-code",   "codex",   "cursor-agent",
                        "opencode",      "cline-roo",     "mcp-dev", "github-actions",
                        "solo-dev",      "strict-local",  "team-ci", "openclaw-hermes",
                        "unattended",    "trusted-local",
                    },
                    "doctor",
                );
                return error.Usage;
            }
            options.preset = name;
            continue;
        }
        try suggestions.writeUnknownOption(stderr, "ryk doctor", arg, &.{
            "--verbose", "-v", "--check", "--json", "--plain", "--no-rich", "--tui", "--fix", "--from-install", "--preset", "--deadlock-check", "--help", "-h",
        }, "doctor");
        return error.Usage;
    }

    // --fix must not silently dominate probe contracts (--check/--json).
    if (options.fix and (options.check or options.json)) {
        try stderr.writeAll("ryk doctor: cannot combine --fix with --check/--json.\n");
        return error.Usage;
    }
    // --deadlock-check is a focused read-only probe: it neither repairs nor
    // feeds the readiness envelope, so combining it would hide one of the two.
    if (options.deadlock_check and (options.fix or options.check or options.json)) {
        try stderr.writeAll("ryk doctor: cannot combine --deadlock-check with --fix/--check/--json.\n");
        return error.Usage;
    }
    // Ensure-only flags are not silent no-ops without --fix.
    if ((options.from_install or options.preset != null) and !options.fix) {
        if (options.from_install and options.preset != null) {
            try stderr.writeAll("ryk doctor: --from-install and --preset require --fix.\n");
        } else if (options.from_install) {
            try stderr.writeAll("ryk doctor: --from-install requires --fix.\n");
        } else {
            try stderr.writeAll("ryk doctor: --preset requires --fix.\n");
        }
        return error.Usage;
    }
    return options;
}

/// Strong sandbox: doctor must never surface probe-only `active`.
/// Live sessions may report active only after apply+attach handshake.
fn doctorDisplayLevel(feature: sandbox.backend.Feature, level: sandbox.backend.Level) sandbox.backend.Level {
    if (feature == .strong_sandbox and level == .active) return .unavailable;
    return level;
}

fn doctorDisplayNote(feature: sandbox.backend.Feature, level: sandbox.backend.Level, note: []const u8) []const u8 {
    if (feature == .strong_sandbox and level == .active) {
        return "capability probe claimed active without attach; reporting unavailable";
    }
    return note;
}

/// Optional probe detail appended to a feature line (e.g. the probed Landlock
/// ABI). Single source for the report and panel renderers so the ABI-floor
/// warning cannot drift between views. Returns null when the feature carries
/// no probe detail.
fn featureProbeDetail(
    backend_report: sandbox.backend.ReportSet,
    feature: sandbox.backend.Feature,
    buf: []u8,
) ?[]const u8 {
    if (feature != .landlock) return null;
    const abi = backend_report.landlock_abi orelse return null;
    const suffix = if (abi < sandbox.landlock.MIN_ABI)
        "; ABI 3+ required for truncation mediation"
    else
        "";
    return std.fmt.bufPrint(buf, "ABI {d}{s}", .{ abi, suffix }) catch null;
}

fn countCapabilitySummary(os: core.platform.Os, backend_report: sandbox.backend.ReportSet) struct { active: usize, limited: usize, unavailable: usize } {
    var active_count: usize = 0;
    var limited_count: usize = 0;
    var unavailable_count: usize = 0;

    for (doctor_capabilities) |item| {
        if (item.feature) |feature| {
            switch (doctorDisplayLevel(feature, backend_report.get(feature).level)) {
                .active => active_count += 1,
                .partial, .limited, .observe_only, .wrapper_only => limited_count += 1,
                .unavailable, .unsupported, .failed => unavailable_count += 1,
            }
        } else if (item.capability) |capability| {
            switch (core.platform.reportCapability(os, capability).state) {
                .active => active_count += 1,
                .partial, .limited, .observe => limited_count += 1,
                .unavailable, .unknown => unavailable_count += 1,
            }
        }
    }

    return .{ .active = active_count, .limited = limited_count, .unavailable = unavailable_count };
}

fn daemonStatusSummary(status: onboarding.DaemonHealthStatus) []const u8 {
    return switch (status) {
        .compatible => "daemon compatible",
        .unavailable => "daemon unavailable",
        .incompatible => "daemon incompatible",
        .degraded => "daemon degraded",
    };
}

fn secretBoundaryCapability(backend_report: sandbox.backend.ReportSet) []const u8 {
    const level = doctorDisplayLevel(.strong_sandbox, backend_report.get(.strong_sandbox).level);
    return switch (level) {
        .unavailable, .unsupported, .failed => "unavailable (empty-backpack requires live OS attach)",
        else => "available (live session attestation required; Anthropic/OpenAI gateway compiled)",
    };
}

fn daemonDetailFromError(allocator: std.mem.Allocator, err: anyerror) !DaemonHealth {
    return .{
        .status = cli.daemon.errors.doctorHealthStatus(err),
        .detail = try allocator.dupe(u8, cli.daemon.errors.doctorProbeDetail(err)),
    };
}

fn redactDisplayAlloc(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    return redact_bridge.redactAlloc(allocator, value);
}

fn freeHostDoctorRow(allocator: std.mem.Allocator, row: HostDoctorRow) void {
    allocator.free(row.host);
    allocator.free(row.wired);
    allocator.free(row.shell_gate);
    allocator.free(row.fail_stance);
    allocator.free(row.smoke_allow);
    allocator.free(row.smoke_deny);
    allocator.free(row.fix);
}

fn redactHostRow(allocator: std.mem.Allocator, row: HostDoctorRow) !HostDoctorRow {
    const host = try redactDisplayAlloc(allocator, row.host);
    errdefer allocator.free(host);
    const wired = try redactDisplayAlloc(allocator, row.wired);
    errdefer allocator.free(wired);
    const shell_gate = try redactDisplayAlloc(allocator, row.shell_gate);
    errdefer allocator.free(shell_gate);
    const fail_stance = try redactDisplayAlloc(allocator, row.fail_stance);
    errdefer allocator.free(fail_stance);
    const smoke_allow = try redactDisplayAlloc(allocator, row.smoke_allow);
    errdefer allocator.free(smoke_allow);
    const smoke_deny = try redactDisplayAlloc(allocator, row.smoke_deny);
    errdefer allocator.free(smoke_deny);
    const fix = try redactDisplayAlloc(allocator, row.fix);
    errdefer allocator.free(fix);
    return .{
        .host = host,
        .wired = wired,
        .shell_gate = shell_gate,
        .fail_stance = fail_stance,
        .smoke_allow = smoke_allow,
        .smoke_deny = smoke_deny,
        .fix = fix,
    };
}

fn redactHostRows(allocator: std.mem.Allocator, rows: []const HostDoctorRow) ![]HostDoctorRow {
    const out = try allocator.alloc(HostDoctorRow, rows.len);
    var done: usize = 0;
    errdefer {
        for (out[0..done]) |row| freeHostDoctorRow(allocator, row);
        allocator.free(out);
    }
    for (rows) |row| {
        out[done] = try redactHostRow(allocator, row);
        done += 1;
    }
    return out;
}

fn writeReport(io: std.Io, stdout: anytype, os: core.platform.Os, backend_report: sandbox.backend.ReportSet, context: IntegrationContext, verbose: bool) !void {
    // Redact dynamic fields only. Whole-document redactAlloc collapses the
    // report to [REDACTED] on encoded secrets or input >64KiB.
    const allocator = context.allocator;
    const daemon_detail = try redactDisplayAlloc(allocator, context.daemon_detail);
    defer allocator.free(daemon_detail);
    const daemon_binary_path = if (context.daemon_binary_path) |path| try redactDisplayAlloc(allocator, path) else null;
    defer if (daemon_binary_path) |path| allocator.free(path);
    const daemon_socket_path = if (context.daemon_socket_path) |path| try redactDisplayAlloc(allocator, path) else null;
    defer if (daemon_socket_path) |path| allocator.free(path);
    const daemon_pid_path = if (context.daemon_pid_path) |path| try redactDisplayAlloc(allocator, path) else null;
    defer if (daemon_pid_path) |path| allocator.free(path);
    const policy_error = if (context.policy_error) |err_name| try redactDisplayAlloc(allocator, err_name) else null;
    defer if (policy_error) |err_name| allocator.free(err_name);
    const host_rows = try redactHostRows(allocator, context.host_rows);
    defer {
        for (host_rows) |row| freeHostDoctorRow(allocator, row);
        allocator.free(host_rows);
    }
    const policy_notices = try allocator.alloc(policy_migrate.StaleNotice, context.policy_notices.len);
    defer {
        for (policy_notices) |notice| allocator.free(notice.path);
        allocator.free(policy_notices);
    }
    for (context.policy_notices, 0..) |notice, index| {
        policy_notices[index] = .{
            .path = try redactDisplayAlloc(allocator, notice.path),
            .kind = notice.kind,
        };
    }

    var safe = context;
    safe.daemon_detail = daemon_detail;
    safe.daemon_binary_path = daemon_binary_path;
    safe.daemon_socket_path = daemon_socket_path;
    safe.daemon_pid_path = daemon_pid_path;
    safe.policy_error = policy_error;
    safe.host_rows = host_rows;
    safe.policy_notices = policy_notices;
    try writeReportRaw(io, stdout, os, backend_report, safe, verbose);
}

fn writeReportRaw(io: std.Io, stdout: anytype, os: core.platform.Os, backend_report: sandbox.backend.ReportSet, context: IntegrationContext, verbose: bool) !void {
    try stdout.writeAll("ryk Doctor\n\n");

    const counts = countCapabilitySummary(os, backend_report);
    const policy_status = if (!context.policy_present)
        "no policy"
    else if (!context.policy_valid)
        "policy invalid"
    else
        "policy valid";

    if (style.useColor(io, stdout)) {
        try stdout.print("Summary: {s} · {s}{d} active{s} · {s}{d} limited{s} · {s}{d} unavailable{s} · {s} · {s}\n\n", .{
            os.toString(),
            style.Style.green,
            counts.active,
            style.Style.reset,
            style.Style.yellow,
            counts.limited,
            style.Style.reset,
            style.Style.red,
            counts.unavailable,
            style.Style.reset,
            policy_status,
            daemonStatusSummary(context.daemon_health),
        });
    } else {
        try stdout.print("Summary: {s} · {d} active · {d} limited · {d} unavailable · {s} · {s}\n\n", .{
            os.toString(),
            counts.active,
            counts.limited,
            counts.unavailable,
            policy_status,
            daemonStatusSummary(context.daemon_health),
        });
    }

    try writeHookServerLine(io, context.allocator, stdout);

    if (!verbose) {
        try writeDefaultPanels(io, stdout, os, backend_report, context, policy_status, counts);
        try writeMcpSetupReport(io, stdout, context);
        try writeHostStatusTable(io, stdout, context);
        try writePacksSection(io, stdout, context);
        try writeHermesFailOpenWarning(io, stdout, context);
        try writeBrokenEvaluatorWarning(io, stdout, context);
        try writePiNote(stdout);
        try writePolicyFreshnessNotices(stdout, context);
        try writeRecommendations(stdout, context);
        return;
    }

    try stdout.print("OS: {s}\n", .{os.toString()});
    try stdout.print("Version: {s}\n\n", .{cli.version});
    try writeIntegrationReport(io, stdout, context);
    try writeMcpSetupReport(io, stdout, context);
    try writeHostStatusTable(io, stdout, context);
    try writePacksSection(io, stdout, context);
    try writeHermesFailOpenWarning(io, stdout, context);
    try writeBrokenEvaluatorWarning(io, stdout, context);
    try writePiNote(stdout);
    try stdout.print("Secret boundary: {s}\n\n", .{secretBoundaryCapability(backend_report)});
    try stdout.writeAll("Capabilities:\n");
    for (doctor_capabilities) |item| {
        if (item.feature) |feature| {
            const report = backend_report.get(feature);
            const display_level = doctorDisplayLevel(feature, report.level);
            const display_note = doctorDisplayNote(feature, report.level, report.note);
            const cg = levelColorAndGlyph(display_level);
            if (style.useColor(io, stdout)) {
                try stdout.print("  {s} {s}: {s}{s}{s} ({s})\n", .{ cg.glyph, item.label, cg.color, display_level.toString(), style.Style.reset, display_note });
            } else {
                try stdout.print("  {s} {s}: {s} ({s})\n", .{ cg.glyph, item.label, display_level.toString(), display_note });
            }
        } else if (item.capability) |capability| {
            const report = core.platform.reportCapability(os, capability);
            const cg = stateColorAndGlyph(report.state);
            if (style.useColor(io, stdout)) {
                try stdout.print("  {s} {s}: {s}{s}{s} ({s})\n", .{ cg.glyph, item.label, cg.color, report.state.toString(), style.Style.reset, report.note });
            } else {
                try stdout.print("  {s} {s}: {s} ({s})\n", .{ cg.glyph, item.label, report.state.toString(), report.note });
            }
        }
    }
    try stdout.writeByte('\n');
    if (os == .linux) {
        try stdout.writeAll("Linux backend:\n");
    } else if (os == .macos) {
        try stdout.writeAll("macOS backend:\n");
    } else if (os == .windows) {
        try stdout.writeAll("Windows backend:\n");
    } else {
        try stdout.writeAll("Backend:\n");
    }
    try stdout.print("  selected: {s}\n", .{backend_report.backend_name});
    try stdout.print("  fallback mode: {s} ({s})\n", .{ backend_report.fallback_level.toString(), backend_report.fallback_note });
    if (os == .windows) {
        try writeWindowsBackendReport(io, stdout, backend_report);
    } else {
        try writeBackendLine(io, stdout, backend_report, .policy_engine);
        try writeBackendLine(io, stdout, backend_report, .env_filtering);
        try writeBackendLine(io, stdout, backend_report, .path_staging);
        if (os == .macos) {
            try stdout.writeAll("  transparent file enforcement: limited (no transparent macOS filesystem monitor is installed; ryk-mediated staging and protected path matching are active)\n");
        }
        try writeBackendLine(io, stdout, backend_report, .shell_wrapping);
        try writeBackendLine(io, stdout, backend_report, .path_shims);
        try writeBackendLine(io, stdout, backend_report, .process_supervision);
        if (os == .linux) {
            try writeBackendLine(io, stdout, backend_report, .user_namespaces);
            try writeBackendLine(io, stdout, backend_report, .mount_namespaces);
            try writeBackendLine(io, stdout, backend_report, .seccomp);
            try writeBackendLine(io, stdout, backend_report, .landlock);
            var abi_detail_buf: [96]u8 = undefined;
            if (featureProbeDetail(backend_report, .landlock, &abi_detail_buf)) |detail| {
                try stdout.print("  Landlock probed {s}\n", .{detail});
            }
            try writeBackendLine(io, stdout, backend_report, .cgroups);
        }
        try writeBackendLine(io, stdout, backend_report, .network_enforce);
        try writeBackendLine(io, stdout, backend_report, .mcp_stdio_proxy);
        try writeBackendLine(io, stdout, backend_report, .strong_sandbox);
        try writeBackendLine(io, stdout, backend_report, .audit);
    }
    try writePolicyFreshnessNotices(stdout, context);
    try writeRecommendations(stdout, context);
}

/// `ryk doctor --deadlock-check` (P2-1d): replay a standard coding workflow
/// against the active policy. Exit 0 when normal work runs unattended and danger
/// stays blocked; exit 1 when a step would stall an agent or a fence hole exists.
/// Fails closed on an unloadable policy: an unusable policy is a deadlock.
fn runDeadlockCheck(io: std.Io, allocator: std.mem.Allocator, stdout: anytype, stderr: anytype) !u8 {
    const root = supervisor.resolveWorkspaceRoot(io, allocator, null, ".") catch try allocator.dupe(u8, ".");
    defer allocator.free(root);

    var loaded = core_api.discoverPolicy(io, allocator, null, root) catch |err| {
        try stderr.print(
            "ryk doctor: cannot load the active policy ({s}); ryk fails closed, so every command would be denied.\n",
            .{@errorName(err)},
        );
        try stderr.writeAll("  Next: fix the policy, or run `ryk doctor --fix` to seed the current default.\n");
        return exit_codes.general;
    };
    defer loaded.deinit();

    var report = deadlock_check.run(allocator, loaded.innerPtr()) catch |err| {
        try stderr.print(
            "ryk doctor: deadlock corpus failed ({s}); fail closed.\n",
            .{@errorName(err)},
        );
        return exit_codes.general;
    };
    defer report.deinit(allocator);

    const label = try redactDisplayAlloc(allocator, loaded.path);
    defer allocator.free(label);
    const origin: deadlock_check.PolicyOrigin = if (loaded.source == .builtin) .builtin else .file;
    try deadlock_check.writeReport(stdout, &report, label, origin);

    return if (report.clean()) exit_codes.success else exit_codes.general;
}

/// Stale-default notices (P2 Door A): one line per policy that is not the
/// current shipped default. Informational; never affects --check exit codes.
fn writePolicyFreshnessNotices(stdout: anytype, context: IntegrationContext) !void {
    if (context.policy_notices.len == 0) return;
    try stdout.writeAll("Policy freshness:\n");
    for (context.policy_notices) |notice| {
        switch (notice.kind) {
            .legacy_default => try stdout.print(
                "  {s}: old ryk default policy — run `ryk doctor --fix` to upgrade to the current default (a backup is written alongside).\n",
                .{notice.path},
            ),
            .customized => try stdout.print(
                "  {s}: customized policy — ryk ships a newer default; compare with the generic-agent preset and merge manually (customized policies are never auto-rewritten).\n",
                .{notice.path},
            ),
        }
    }
    try stdout.writeByte('\n');
}

fn writeHookServerLine(io: std.Io, allocator: std.mem.Allocator, stdout: anytype) !void {
    if (comptime builtin.os.tag == .windows) {
        try stdout.writeAll("hook server: unavailable on Windows; hooks stay in-process\n\n");
        return;
    }
    const path = cli.hook_client.socketPathForDoctor(io, allocator) catch {
        try stdout.writeAll("hook server: not running\n\n");
        return;
    };
    defer allocator.free(path);
    const status = if (cli.hook_client.socketIsLive(path)) "running" else "not running";
    try stdout.print("hook server: {s}\n  socket: {s}\n\n", .{ status, path });
}

fn writeDefaultPanels(
    io: std.Io,
    stdout: anytype,
    os: core.platform.Os,
    backend_report: sandbox.backend.ReportSet,
    context: IntegrationContext,
    policy_status: []const u8,
    counts: anytype,
) !void {
    var health_storage: [6][128]u8 = undefined;
    const health_lines = [_][]const u8{
        try std.fmt.bufPrint(&health_storage[0], "Platform       {s}", .{os.toString()}),
        try std.fmt.bufPrint(&health_storage[1], "Policy         {s}", .{policy_status}),
        try std.fmt.bufPrint(&health_storage[2], "Daemon         {s}", .{daemonStatusSummary(context.daemon_health)}),
        try std.fmt.bufPrint(&health_storage[3], "Capabilities   {d} active · {d} limited", .{ counts.active, counts.limited }),
        try std.fmt.bufPrint(&health_storage[4], "Unavailable    {d}", .{counts.unavailable}),
        try std.fmt.bufPrint(&health_storage[5], "Secret boundary {s}", .{secretBoundaryCapability(backend_report)}),
    };
    try tui.render.panel(io, stdout, "System health", &health_lines);
    try stdout.writeByte('\n');

    var capability_storage: [doctor_capabilities.len][160]u8 = undefined;
    var detail_storage: [doctor_capabilities.len][96]u8 = undefined;
    var capability_lines: [doctor_capabilities.len][]const u8 = undefined;
    for (doctor_capabilities, 0..) |item, index| {
        if (item.feature) |feature| {
            const report = backend_report.get(feature);
            const display_level = doctorDisplayLevel(feature, report.level);
            capability_lines[index] = if (featureProbeDetail(backend_report, feature, &detail_storage[index])) |detail|
                try std.fmt.bufPrint(&capability_storage[index], "{s}  {s}: {s} ({s})", .{
                    levelColorAndGlyph(display_level).glyph,
                    item.label,
                    display_level.toString(),
                    detail,
                })
            else
                try std.fmt.bufPrint(&capability_storage[index], "{s}  {s}: {s}", .{
                    levelColorAndGlyph(display_level).glyph,
                    item.label,
                    display_level.toString(),
                });
        } else if (item.capability) |capability| {
            const report = core.platform.reportCapability(os, capability);
            capability_lines[index] = try std.fmt.bufPrint(&capability_storage[index], "{s}  {s}: {s}", .{
                stateColorAndGlyph(report.state).glyph,
                item.label,
                report.state.toString(),
            });
        }
    }
    try tui.render.panel(io, stdout, "Capabilities", &capability_lines);
    try stdout.writeAll(
        \\
        \\  Note: Doctor = host capability (probe ≠ live session).
        \\  Session grade = this run's env RYK_SESSION_SANDBOX_GRADE
        \\  (strong-mediated | fs-attached | wrapper-only | unrestricted-escape).
        \\  Labels: network route-force, RYK_TOOL_PACK, RYK_PATH_FILTER, control roots (.ryk + .git).
        \\
    );
}

fn writeMcpSetupReport(io: std.Io, stdout: anytype, context: IntegrationContext) !void {
    var summary = doctor_mcp.McpPolicySummary{
        .present = context.policy_present,
        .valid = context.policy_valid,
    };
    var allow_patterns: []const []const u8 = &.{};
    // Concrete policy schema (not opaque boundary handle) so we can read mcp.* counts.
    var owned_policy: ?policy_mod.schema.Policy = null;
    defer if (owned_policy) |*policy| policy.deinit();

    if (context.policy_present and context.policy_valid) {
        const policy_path = std.fs.path.join(context.allocator, &.{ context.workspace_root, ".ryk", "policy.yaml" }) catch null;
        if (policy_path) |path| {
            defer context.allocator.free(path);
            if (policy_mod.load.loadFile(io, context.allocator, path)) |policy| {
                owned_policy = policy;
                const loaded = &owned_policy.?;
                summary.default_decision = if (loaded.mcp.default) |d| d.toString() else "ask";
                summary.allow_count = loaded.mcp.allow.len;
                summary.deny_count = loaded.mcp.deny.len;
                summary.ask_count = loaded.mcp.ask.len;
                allow_patterns = loaded.mcp.allow;
            } else |_| {
                summary.valid = false;
            }
        }
    }

    const rows = doctor_mcp.suggestedInventoryRows(summary, allow_patterns);
    try doctor_mcp.formatMcpSetupTable(
        stdout,
        summary,
        &rows,
        context.mcp_manifest_count,
        context.mcp_manifest_invalid_count,
    );
    try stdout.writeByte('\n');
}

/// P1-1: true when the most recent session recorded an `audit_degraded` event
/// (shim execs ran without in-shim audit evidence). Best-effort: any read
/// failure reports as not degraded — doctor must not fail on missing evidence.
fn lastSessionAuditDegraded(io: std.Io, allocator: std.mem.Allocator, workspace_root: []const u8) bool {
    const last_path = std.fs.path.join(allocator, &.{ workspace_root, ".ryk", "last" }) catch return false;
    defer allocator.free(last_path);
    const id_text = std.Io.Dir.cwd().readFileAlloc(io, last_path, allocator, .limited(256)) catch return false;
    defer allocator.free(id_text);
    const session_id = std.mem.trim(u8, id_text, " \t\r\n");
    if (session_id.len == 0) return false;
    const events_path = std.fs.path.join(allocator, &.{ workspace_root, ".ryk", "sessions", session_id, "events.jsonl" }) catch return false;
    defer allocator.free(events_path);
    const events = std.Io.Dir.cwd().readFileAlloc(io, events_path, allocator, .limited(core.limits.max_audit_log_len)) catch return false;
    defer allocator.free(events);
    return std.mem.indexOf(u8, events, "\"type\":\"audit_degraded\"") != null;
}

fn writeIntegrationReport(io: std.Io, stdout: anytype, context: IntegrationContext) !void {
    try stdout.writeAll("Integration checks:\n");
    try writeDynamicLine(context.allocator, stdout, "  workspace root: ", context.workspace_root, "\n");
    try stdout.print("  git repository: {s}\n", .{if (context.git_present) "detected" else "not detected"});
    if (context.policy_present) {
        if (context.policy_valid) {
            try stdout.writeAll("  .ryk/policy.yaml: present and valid\n");
        } else {
            try writeDynamicLine(context.allocator, stdout, "  .ryk/policy.yaml: invalid (", context.policy_error orelse "validation failed", ")\n");
        }
    } else {
        try stdout.writeAll("  .ryk/policy.yaml: missing\n");
    }
    if (context.agent_found.len == 0) {
        try stdout.writeAll("  known agent binaries: none detected in PATH\n");
    } else {
        try stdout.writeAll("  known agent binaries: ");
        for (context.agent_found, 0..) |agent, index| {
            if (index > 0) try stdout.writeAll(", ");
            try tui.terminal_text.write(stdout, agent.command, .single_line);
        }
        try stdout.writeAll(" (presence only; not a security claim)\n");
    }
    if (context.mcp_manifest_count == 0) {
        try stdout.writeAll("  MCP manifests: none detected under .ryk/mcp\n");
    } else {
        try stdout.print("  MCP manifests: {d} found, {d} invalid\n", .{ context.mcp_manifest_count, context.mcp_manifest_invalid_count });
    }
    try stdout.print("  CI environment: {s}", .{if (context.ci_detected) "detected" else "not detected"});
    if (context.ci_detected) {
        try stdout.writeAll(" (");
        try tui.terminal_text.write(stdout, context.ci_provider, .single_line);
        try stdout.writeByte(')');
    }
    try stdout.writeByte('\n');
    try writeDynamicLine(context.allocator, stdout, "  shell: ", context.shell_name, "\n");
    try stdout.print("  audit/replay: {s}\n", .{if (context.audit_sessions_present) "session artifacts present; replay available" else "replay available; no local sessions detected"});
    if (context.audit_sessions_present and lastSessionAuditDegraded(io, context.allocator, context.workspace_root)) {
        try stdout.writeAll("  last session audit: degraded — some allowed shim execs have no in-shim audit record (see `ryk replay`)\n");
    }
    try stdout.print("  red-team fixtures: {s}\n", .{if (context.redteam_fixtures_present) "available" else "not found"});
    if (context.daemon_binary_path) |path| {
        try stdout.writeAll("  daemon binary: ");
        try tui.terminal_text.write(stdout, path, .single_line);
        try stdout.print(" ({s}, {s})\n", .{
            if (context.daemon_binary_exists) "present" else "missing",
            if (context.daemon_binary_executable) "executable" else "not executable",
        });
        if (context.daemon_binary_untrusted) {
            try stdout.writeAll("  daemon binary trust: world-writable RYK_DAEMON path (refused for shell evaluation)\n");
        }
    } else {
        try stdout.writeAll("  daemon binary: unresolved\n");
    }
    if (context.daemon_socket_path) |path| {
        try stdout.writeAll("  daemon socket: ");
        try tui.terminal_text.write(stdout, path, .single_line);
        try stdout.print(" ({s})\n", .{if (context.daemon_socket_exists) "present" else "missing"});
    }
    if (context.daemon_pid_path) |path| {
        try stdout.writeAll("  daemon pid: ");
        try tui.terminal_text.write(stdout, path, .single_line);
        try stdout.print(" ({s})\n", .{if (context.daemon_pid_exists) "present" else "missing"});
    }
    try stdout.writeAll("  daemon health: ");
    try tui.terminal_text.write(stdout, readiness.daemonWireLabel(context.daemon_health), .single_line);
    try stdout.writeAll(" (");
    try tui.terminal_text.write(stdout, context.daemon_detail, .single_line);
    try stdout.writeAll(")\n\n");
}

fn writeDynamicLine(allocator: std.mem.Allocator, stdout: anytype, prefix: []const u8, value: []const u8, suffix: []const u8) !void {
    const redacted = try redactDisplayAlloc(allocator, value);
    defer allocator.free(redacted);
    try stdout.writeAll(prefix);
    try tui.terminal_text.write(stdout, redacted, .single_line);
    try stdout.writeAll(suffix);
}

fn writeWindowsBackendReport(io: std.Io, stdout: anytype, backend_report: sandbox.backend.ReportSet) !void {
    try writeBackendLine(io, stdout, backend_report, .policy_engine);
    try writeBackendLine(io, stdout, backend_report, .env_filtering);
    try writeBackendLine(io, stdout, backend_report, .path_staging);
    try writeBackendLine(io, stdout, backend_report, .path_shims);
    const shell = backend_report.get(.shell_wrapping);
    const shell_cg = levelColorAndGlyph(shell.level);
    if (style.useColor(io, stdout)) {
        try stdout.print("  {s} cmd wrapper: {s}{s}{s} ({s})\n", .{ shell_cg.glyph, shell_cg.color, shell.level.toString(), style.Style.reset, shell.note });
        try stdout.print("  {s} PowerShell wrapper: {s}{s}{s} ({s})\n", .{ shell_cg.glyph, shell_cg.color, shell.level.toString(), style.Style.reset, shell.note });
    } else {
        try stdout.print("  cmd wrapper: {s} ({s})\n", .{ shell.level.toString(), shell.note });
        try stdout.print("  PowerShell wrapper: {s} ({s})\n", .{ shell.level.toString(), shell.note });
    }
    const cleanup = backend_report.get(.process_supervision);
    const cleanup_cg = levelColorAndGlyph(cleanup.level);
    if (style.useColor(io, stdout)) {
        try stdout.print("  {s} process cleanup: {s}{s}{s} ({s})\n", .{ cleanup_cg.glyph, cleanup_cg.color, cleanup.level.toString(), style.Style.reset, cleanup.note });
    } else {
        try stdout.print("  process cleanup: {s} ({s})\n", .{ cleanup.level.toString(), cleanup.note });
    }
    try stdout.writeAll("  transparent file enforcement: unavailable (no transparent Windows filesystem enforcement is installed; ryk-mediated staging and protected path matching are active)\n");
    try writeBackendLine(io, stdout, backend_report, .network_enforce);
    const proxy = backend_report.get(.network_proxy_enforce);
    const proxy_cg = levelColorAndGlyph(proxy.level);
    if (style.useColor(io, stdout)) {
        try stdout.print("  {s} proxy-mediated HTTP: {s}{s}{s} ({s})\n", .{ proxy_cg.glyph, proxy_cg.color, proxy.level.toString(), style.Style.reset, proxy.note });
    } else {
        try stdout.print("  proxy-mediated HTTP: {s} ({s})\n", .{ proxy.level.toString(), proxy.note });
    }
    try writeBackendLine(io, stdout, backend_report, .strong_sandbox);
    try writeBackendLine(io, stdout, backend_report, .mcp_stdio_proxy);
    try writeBackendLine(io, stdout, backend_report, .audit);
    try stdout.writeByte('\n');
}

fn levelColorAndGlyph(level: sandbox.backend.Level) struct { color: []const u8, glyph: []const u8 } {
    return switch (level) {
        .active => .{ .color = style.Style.green, .glyph = "✓" },
        .partial, .limited, .observe_only, .wrapper_only => .{ .color = style.Style.yellow, .glyph = "◌" },
        .unavailable, .unsupported, .failed => .{ .color = style.Style.red, .glyph = "✗" },
    };
}

fn stateColorAndGlyph(state: core.platform.CapabilityState) struct { color: []const u8, glyph: []const u8 } {
    return switch (state) {
        .active => .{ .color = style.Style.green, .glyph = "✓" },
        .partial, .limited, .observe => .{ .color = style.Style.yellow, .glyph = "◌" },
        .unavailable, .unknown => .{ .color = style.Style.red, .glyph = "✗" },
    };
}

fn writeBackendLine(io: std.Io, stdout: anytype, backend_report: sandbox.backend.ReportSet, feature: sandbox.backend.Feature) !void {
    const report = backend_report.get(feature);
    // Strong sandbox: doctor reports capability level only. Live sessions may report
    // active only after apply+attach. Never imply OS-enforced from a probe.
    const display_level = doctorDisplayLevel(feature, report.level);
    const display_note = doctorDisplayNote(feature, report.level, report.note);
    const display_cg = levelColorAndGlyph(display_level);
    if (style.useColor(io, stdout)) {
        try stdout.print("  {s} {s}: {s}{s}{s} ({s})\n", .{ display_cg.glyph, report.feature.label(), display_cg.color, display_level.toString(), style.Style.reset, display_note });
    } else {
        try stdout.print("  {s} {s}: {s} ({s})\n", .{ display_cg.glyph, report.feature.label(), display_level.toString(), display_note });
    }
}

fn writeHostStatusTable(io: std.Io, stdout: anytype, context: IntegrationContext) !void {
    if (context.host_rows.len == 0) return;
    try stdout.writeAll("\n");
    try tui.theme.paintBold(io, stdout, .brand, "Host integrations");
    try stdout.writeAll("\n");
    var rows = try context.allocator.alloc([]const []const u8, context.host_rows.len);
    defer context.allocator.free(rows);
    for (context.host_rows, 0..) |row, i| {
        const cells = try context.allocator.alloc([]const u8, 6);
        cells[0] = row.host;
        cells[1] = row.wired;
        cells[2] = row.shell_gate;
        cells[3] = row.fail_stance;
        cells[4] = row.smoke_allow;
        cells[5] = row.smoke_deny;
        rows[i] = cells;
    }
    defer for (rows) |row| context.allocator.free(row);
    try tui.render.table(io, stdout, &.{
        .{ .name = "HOST" },
        .{ .name = "WIRED" },
        .{ .name = "SHELL GATE" },
        .{ .name = "FAIL STANCE" },
        .{ .name = "SMOKE ALLOW" },
        .{ .name = "SMOKE DENY" },
    }, rows);
    // Fix lines for every non-green row (wired != yes, smoke fail, or hermes fail-open).
    for (context.host_rows) |row| {
        const needs_fix = !std.mem.eql(u8, row.fix, "—") and row.fix.len > 0;
        if (!needs_fix) continue;
        try stdout.print("  fix {s}: {s}\n", .{ row.host, row.fix });
    }
}

fn writeHermesFailOpenWarning(io: std.Io, stdout: anytype, context: IntegrationContext) !void {
    if (!context.hermes_installed or !context.hermes_fail_open) return;
    try stdout.writeAll("\n");
    try tui.render.callout(
        io,
        stdout,
        .warn,
        "Hermes explicit fail-open",
        "Hermes blocks tools when ryk is missing/old by default. An explicit RYK_HERMES_FAIL_OPEN=1 allows degraded execution with a warning; use `ryk run -- hermes` for outer enforcement. Gateway chats may omit the block reason — check agent tool errors.",
    );
}

fn writePiNote(stdout: anytype) !void {
    try stdout.writeAll("\nPi: bundled extension setup is managed by `ryk doctor --fix` (no npm step).\n");
    try stdout.writeAll("  Process env/network isolation: ryk run -- pi (doctor is a probe, not live attach)\n");
}

fn writeBrokenEvaluatorWarning(io: std.Io, stdout: anytype, context: IntegrationContext) !void {
    var any = false;
    for (context.host_rows) |row| {
        if (std.mem.eql(u8, row.wired, "broken")) {
            any = true;
            break;
        }
    }
    if (!any) return;
    try stdout.writeAll("\n");
    try tui.render.callout(
        io,
        stdout,
        .danger,
        "Hook is a test program, not ryk",
        "Pi or Grok is calling a Zig test binary (or another non-product file) instead of ryk. Every tool fail-closes. Run `ryk doctor --fix` from a normal terminal using the installed ryk binary, then restart the host.",
    );
}

fn writeNonProductFixWarning(io: std.Io, allocator: std.mem.Allocator, stderr: anytype) !void {
    const exe = std.process.executablePathAlloc(io, allocator) catch return;
    defer allocator.free(exe);
    const kind = brand.classifyEvaluator(exe);
    if (kind.isProduct()) return;
    try stderr.print(
        "ryk doctor --fix: this process is a {s} ({s}), not product ryk. Host hooks were not rewritten. Run `ryk doctor --fix` from a normal terminal using the installed ryk binary.\n",
        .{ kind.diagnoseLabel(), std.fs.path.basename(exe) },
    );
}

fn writeBakeRepairNotes(
    stdout: anytype,
    pi_before: host_status.PiStatus,
    pi_after: host_status.PiStatus,
    grok_before: host_status.GrokStatus,
    grok_after: host_status.GrokStatus,
) !void {
    if (host_status.bakeRepairLine("pi", pi_before.evaluator_ok, pi_after.evaluator_ok, pi_after.extension_installed)) |line| {
        try stdout.print("{s}\n", .{line});
    }
    if (host_status.bakeRepairLine("grok", grok_before.evaluator_ok, grok_after.evaluator_ok, grok_after.hook_installed)) |line| {
        try stdout.print("{s}\n", .{line});
    }
}

fn writePacksSection(io: std.Io, stdout: anytype, context: IntegrationContext) !void {
    // Avoid spawning the daemon when health probe already failed (doctor stays fast).
    const config_path: ?[]const u8 = blk: {
        const root = onboarding.resolveWorkspaceRoot(io, context.allocator) catch break :blk null;
        defer context.allocator.free(root);
        const resolved = pack_state.resolvePackConfigPath(io, context.allocator, root) catch break :blk null;
        break :blk resolved.path;
    };
    defer if (config_path) |p| context.allocator.free(p);

    // RT-12: packs inventory is Zig in-process — do not hard-gate on daemon health.
    var summary = pack_state.queryPacksSummaryDefault(io, context.allocator) catch pack_state.unknownPacksSummary();
    defer summary.deinit(context.allocator);
    try pack_state.writeDoctorPacksSectionWithConfig(stdout, summary, config_path, null);
}

/// Effective Hermes fail-open matches integrations/hermes-plugin (default deny when degraded).
pub fn hermesFailOpenFromEnvValue(value: ?[]const u8) bool {
    return host_status.hermesFailOpenFromEnvValue(value);
}

fn hermesFailOpenFromEnv() bool {
    return host_status.hermesFailOpenFromEnv();
}

fn writeRecommendations(stdout: anytype, context: IntegrationContext) !void {
    try stdout.writeAll("\nRecommended next step:\n");
    if (context.daemon_health != .compatible) {
        try writeDynamicLine(context.allocator, stdout, "  Daemon health issue: ", context.daemon_detail, "\n");
        if (context.daemon_binary_untrusted) {
            try stdout.writeAll("  Remove the untrusted legacy companion override, then re-run `ryk doctor`.\n");
        } else if (context.daemon_binary_exists and !context.daemon_binary_executable) {
            try stdout.writeAll("  Restore companion-service execute permission or reinstall ryk, then re-run `ryk doctor`.\n");
        } else if (!context.daemon_binary_exists) {
            try stdout.writeAll("  Reinstall the complete ryk release, then re-run `ryk doctor`.\n");
            try stdout.writeAll("  Source checkout: `./scripts/zig build`.\n");
        } else {
            try stdout.writeAll("  Reinstall ryk or rebuild with `./scripts/build-all.sh`, then re-run `ryk doctor`.\n");
        }
        if (!context.policy_present) {
            try stdout.writeAll("  Then run `ryk doctor --fix` and review .ryk/policy.yaml.\n");
        } else if (!context.policy_valid) {
            try stdout.writeAll("  After the daemon is healthy, fix `.ryk/policy.yaml`, then run `ryk policy check .ryk/policy.yaml`.\n");
        }
    } else if (!context.policy_present) {
        try stdout.writeAll("  Run `ryk doctor --fix` and review .ryk/policy.yaml.\n");
    } else if (!context.policy_valid) {
        try stdout.writeAll("  Fix `.ryk/policy.yaml`, then run `ryk policy check .ryk/policy.yaml`.\n");
    } else if (context.mcp_manifest_invalid_count > 0) {
        try stdout.writeAll("  Fix invalid MCP manifests with `ryk mcp manifest check <path>`.\n");
    } else if (!context.redteam_fixtures_present) {
        try stdout.writeAll("  Runtime assets (fixtures, integrations) not found.\n");
        try stdout.writeAll("  This is common after a fresh packaged install (curl|sh, Homebrew, npm).\n\n");
        try stdout.writeAll("  Paste these two lines in your current terminal (then re-run `ryk doctor`):\n\n");
        try stdout.writeAll("      export PATH=\"$HOME/.local/bin:$PATH\"\n");
        try stdout.writeAll("      export RYK_RESOURCE_ROOT=\"$HOME/.local/share/ryk/current\"\n\n");
        try stdout.writeAll("  (Use the exact paths printed by your installer if they differ.)\n");
    } else {
        try stdout.writeAll("  Run `ryk run -- <command>` or `ryk redteam --ci` for a local smoke test.\n");
    }
}

fn collectIntegrationContext(io: std.Io, allocator: std.mem.Allocator, ensure_running: bool) !IntegrationContext {
    const workspace_root = supervisor.resolveWorkspaceRoot(io, allocator, null, ".") catch try allocator.dupe(u8, ".");
    errdefer allocator.free(workspace_root);
    return try collectIntegrationContextAt(io, allocator, workspace_root, ensure_running);
}

fn collectIntegrationContextAt(io: std.Io, allocator: std.mem.Allocator, workspace_root: []const u8, ensure_running: bool) !IntegrationContext {
    const git_present = hasPath(io, workspace_root, ".git");

    const policy_path = try std.fs.path.join(allocator, &.{ workspace_root, ".ryk", "policy.yaml" });
    defer allocator.free(policy_path);
    var policy_assessment = try readiness.assessPolicyFile(io, allocator, policy_path);
    const policy_present = policy_assessment.present;
    const policy_valid = policy_assessment.valid;
    // Transfer ownership of error_name into IntegrationContext.policy_error.
    const policy_error = policy_assessment.error_name;
    policy_assessment.error_name = null;
    errdefer if (policy_error) |value| allocator.free(value);
    const manifests = countMcpManifests(io, allocator, workspace_root);
    const agents = try detectAgents(io, allocator);
    errdefer if (agents.len > 0) allocator.free(agents);
    const ci_status = try detectCi(allocator);
    errdefer allocator.free(ci_status.provider);
    const shell_name = try detectShell(allocator);
    errdefer allocator.free(shell_name);
    const daemon_inspection = cli.daemon.inspectDaemonBinary(allocator) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => null,
    };
    defer if (daemon_inspection) |value| value.deinit(allocator);
    const daemon_paths = cli.daemon.runtimePaths(allocator) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => null,
    };
    defer if (daemon_paths) |value| cli.daemon.freeRuntimePaths(allocator, value);
    // Shared onboarding health path (same as status/quickstart). Probe paths pass
    // ensure_running=false so --check never mutates daemon runtime.
    const daemon_health: DaemonHealth = blk: {
        const check = onboarding.checkDaemonHealth(allocator, ensure_running, null) catch |err| {
            break :blk try daemonDetailFromError(allocator, err);
        };
        break :blk .{
            .status = check.status,
            .detail = try allocator.dupe(u8, check.detail),
        };
    };
    errdefer allocator.free(daemon_health.detail);

    const host_snapshot = try collectHostDoctorRows(io, allocator);
    errdefer {
        for (host_snapshot.rows) |row| {
            allocator.free(row.host);
            allocator.free(row.wired);
            allocator.free(row.shell_gate);
            allocator.free(row.fail_stance);
            allocator.free(row.smoke_allow);
            allocator.free(row.smoke_deny);
            allocator.free(row.fix);
        }
        allocator.free(host_snapshot.rows);
    }

    // Stale-default scan (diagnose-only, soft): flags policies that are not the
    // current shipped default so users learn a newer default exists.
    var stale_scan = policy_migrate.scanStalePolicies(io, allocator, workspace_root) catch policy_migrate.ScanReport{ .notices = &.{} };
    errdefer stale_scan.deinit(allocator);

    return .{
        .allocator = allocator,
        .workspace_root = workspace_root,
        .git_present = git_present,
        .policy_present = policy_present,
        .policy_valid = policy_valid,
        .policy_error = policy_error,
        .agent_found = agents,
        .mcp_manifest_count = manifests.total,
        .mcp_manifest_invalid_count = manifests.invalid,
        .ci_detected = ci_status.detected,
        .ci_provider = ci_status.provider,
        .shell_name = shell_name,
        .audit_sessions_present = hasPath(io, workspace_root, ".ryk/sessions"),
        .redteam_fixtures_present = resource_root.resourcePathExists(io, allocator, .{ .workspace_root = workspace_root }, "fixtures"),
        .daemon_binary_path = if (daemon_inspection) |value| try allocator.dupe(u8, value.path) else null,
        .daemon_binary_exists = if (daemon_inspection) |value| value.exists else false,
        .daemon_binary_executable = if (daemon_inspection) |value| value.executable else false,
        .daemon_binary_untrusted = if (daemon_inspection) |value|
            value.source == .env_override and value.untrusted
        else
            false,
        .daemon_socket_path = if (daemon_paths) |value| try allocator.dupe(u8, value.socket) else null,
        .daemon_socket_exists = if (daemon_paths) |value| fileExistsAbsolute(io, value.socket) else false,
        .daemon_pid_path = if (daemon_paths) |value| try allocator.dupe(u8, value.pid) else null,
        .daemon_pid_exists = if (daemon_paths) |value| fileExistsAbsolute(io, value.pid) else false,
        .daemon_health = daemon_health.status,
        .daemon_detail = daemon_health.detail,
        .host_rows = host_snapshot.rows,
        .hermes_fail_open = host_snapshot.hermes_fail_open,
        .hermes_installed = host_snapshot.hermes_installed,
        .policy_notices = stale_scan.notices,
    };
}

const HostDoctorSnapshot = struct {
    rows: []HostDoctorRow,
    hermes_fail_open: bool,
    hermes_installed: bool,
};

fn collectHostDoctorRows(io: std.Io, allocator: std.mem.Allocator) !HostDoctorSnapshot {
    // Skip live hook smoke here — plugin install / `ryk plugin doctor <host>` own latency.
    var doctor_report = try plugin.collectPluginDoctorReportWithHermesSmoke(io, allocator, true);
    defer plugin.deinitPluginDoctorReport(&doctor_report, allocator);

    const hermes_fail_open = hermesFailOpenFromEnv();
    var hermes_installed = false;

    var list: std.ArrayList(HostDoctorRow) = .empty;
    errdefer {
        for (list.items) |row| {
            allocator.free(row.host);
            allocator.free(row.wired);
            allocator.free(row.shell_gate);
            allocator.free(row.fail_stance);
            allocator.free(row.smoke_allow);
            allocator.free(row.smoke_deny);
            allocator.free(row.fix);
        }
        list.deinit(allocator);
    }

    for (host_status.managed_hosts) |host_name| {
        const installed = plugin.hostPluginInstalledFromReport(host_name, doctor_report);
        const detected = plugin.binaryInPath(io, allocator, host_name);
        if (std.mem.eql(u8, host_name, "hermes") and installed) hermes_installed = true;

        const wired: []const u8 = if (installed) "yes" else if (detected) "no" else "—";
        const shell_gate = host_status.shellGate(host_name);
        const fail_stance = host_status.failStance(host_name, hermes_fail_open, wired);
        const smoke = host_status.HostSmokePair{};
        // #367: locals + errdefer before append; multi-dupe struct literal leaks on mid-row OOM.
        const host_owned = try allocator.dupe(u8, host_name);
        errdefer allocator.free(host_owned);
        const wired_owned = try allocator.dupe(u8, wired);
        errdefer allocator.free(wired_owned);
        const shell_gate_owned = try allocator.dupe(u8, shell_gate);
        errdefer allocator.free(shell_gate_owned);
        const fail_stance_owned = try allocator.dupe(u8, fail_stance);
        errdefer allocator.free(fail_stance_owned);
        const smoke_allow_owned = try allocator.dupe(u8, smoke.allow.toString());
        errdefer allocator.free(smoke_allow_owned);
        const smoke_deny_owned = try allocator.dupe(u8, smoke.deny.toString());
        errdefer allocator.free(smoke_deny_owned);
        const fix = try host_status.formatFix(allocator, host_name, wired, smoke, hermes_fail_open);
        errdefer allocator.free(fix);

        try list.append(allocator, .{
            .host = host_owned,
            .wired = wired_owned,
            .shell_gate = shell_gate_owned,
            .fail_stance = fail_stance_owned,
            .smoke_allow = smoke_allow_owned,
            .smoke_deny = smoke_deny_owned,
            .fix = fix,
        });
    }

    // Pi: first-class status line (honest coverage / install path; not plugin-managed).
    {
        const pi_status = host_status.inspectPi(io, allocator);
        const wired = pi_status.wiredLabel();
        const smoke = host_status.HostSmokePair{};
        const host_owned = try allocator.dupe(u8, "pi");
        errdefer allocator.free(host_owned);
        const wired_owned = try allocator.dupe(u8, wired);
        errdefer allocator.free(wired_owned);
        const shell_gate_owned = try allocator.dupe(u8, host_status.shellGate("pi"));
        errdefer allocator.free(shell_gate_owned);
        const fail_stance_owned = try allocator.dupe(u8, host_status.failStance("pi", hermes_fail_open, wired));
        errdefer allocator.free(fail_stance_owned);
        const smoke_allow_owned = try allocator.dupe(u8, smoke.allow.toString());
        errdefer allocator.free(smoke_allow_owned);
        const smoke_deny_owned = try allocator.dupe(u8, smoke.deny.toString());
        errdefer allocator.free(smoke_deny_owned);
        const fix = try host_status.formatFix(allocator, "pi", wired, smoke, hermes_fail_open);
        errdefer allocator.free(fix);
        try list.append(allocator, .{
            .host = host_owned,
            .wired = wired_owned,
            .shell_gate = shell_gate_owned,
            .fail_stance = fail_stance_owned,
            .smoke_allow = smoke_allow_owned,
            .smoke_deny = smoke_deny_owned,
            .fix = fix,
        });
    }

    // Grok: native PreToolUse Command Guard (not marketplace-plugin-managed).
    {
        const grok_status = host_status.inspectGrok(io, allocator);
        const wired = grok_status.wiredLabel();
        const smoke = host_status.HostSmokePair{};
        const host_owned = try allocator.dupe(u8, "grok");
        errdefer allocator.free(host_owned);
        const wired_owned = try allocator.dupe(u8, wired);
        errdefer allocator.free(wired_owned);
        const shell_gate_owned = try allocator.dupe(u8, host_status.shellGate("grok"));
        errdefer allocator.free(shell_gate_owned);
        const fail_stance_owned = try allocator.dupe(u8, host_status.failStance("grok", hermes_fail_open, wired));
        errdefer allocator.free(fail_stance_owned);
        const smoke_allow_owned = try allocator.dupe(u8, smoke.allow.toString());
        errdefer allocator.free(smoke_allow_owned);
        const smoke_deny_owned = try allocator.dupe(u8, smoke.deny.toString());
        errdefer allocator.free(smoke_deny_owned);
        const fix = try host_status.formatFix(allocator, "grok", wired, smoke, hermes_fail_open);
        errdefer allocator.free(fix);
        try list.append(allocator, .{
            .host = host_owned,
            .wired = wired_owned,
            .shell_gate = shell_gate_owned,
            .fail_stance = fail_stance_owned,
            .smoke_allow = smoke_allow_owned,
            .smoke_deny = smoke_deny_owned,
            .fix = fix,
        });
    }

    return .{
        .rows = try list.toOwnedSlice(allocator),
        .hermes_fail_open = hermes_fail_open,
        .hermes_installed = hermes_installed,
    };
}

fn hasPath(io: std.Io, root: []const u8, relative: []const u8) bool {
    const allocator = std.heap.page_allocator;
    const path = std.fs.path.join(allocator, &.{ root, relative }) catch return false;
    defer allocator.free(path);
    return fileExistsAbsolute(io, path);
}

fn fileExistsAbsolute(io: std.Io, path: []const u8) bool {
    if (std.fs.path.isAbsolute(path)) {
        std.Io.Dir.accessAbsolute(io, path, .{}) catch return false;
    } else {
        std.Io.Dir.cwd().access(io, path, .{}) catch return false;
    }
    return true;
}

const ManifestCounts = struct { total: usize = 0, invalid: usize = 0 };

fn countMcpManifests(io: std.Io, allocator: std.mem.Allocator, workspace_root: []const u8) ManifestCounts {
    const mcp_dir_path = std.fs.path.join(allocator, &.{ workspace_root, ".ryk", "mcp" }) catch return .{};
    defer allocator.free(mcp_dir_path);
    var dir = std.Io.Dir.cwd().openDir(io, mcp_dir_path, .{ .iterate = true }) catch return .{};
    defer dir.close(io);

    var counts: ManifestCounts = .{};
    var iterator = dir.iterate();
    while (iterator.next(io) catch null) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.name, ".yaml") and !std.mem.endsWith(u8, entry.name, ".yml")) continue;
        counts.total += 1;
        const manifest_path = std.fs.path.join(allocator, &.{ mcp_dir_path, entry.name }) catch {
            counts.invalid += 1;
            continue;
        };
        defer allocator.free(manifest_path);
        var manifest = mcp_mod.manifests.loadFile(io, allocator, manifest_path) catch {
            counts.invalid += 1;
            continue;
        };
        manifest.deinit(allocator);
    }
    return counts;
}

fn detectAgents(io: std.Io, allocator: std.mem.Allocator) ![]const AgentBinary {
    var found: std.ArrayList(AgentBinary) = .empty;
    errdefer found.deinit(allocator);
    for (known_agent_binaries) |agent| {
        if (binaryInPath(io, allocator, agent.command)) try found.append(allocator, agent);
    }
    return try found.toOwnedSlice(allocator);
}

fn binaryInPath(io: std.Io, allocator: std.mem.Allocator, binary_name: []const u8) bool {
    var env_map = env_util.createProcessMap(allocator) catch return false;
    defer env_map.deinit();
    const path_owned = env_util.getOwned(&env_map, allocator, "PATH") catch return false;
    const path_value = path_owned orelse return false;
    defer allocator.free(path_value);
    var parts = std.mem.splitScalar(u8, path_value, std.fs.path.delimiter);
    while (parts.next()) |dir| {
        if (dir.len == 0) continue;
        const candidate = std.fs.path.join(allocator, &.{ dir, binary_name }) catch continue;
        defer allocator.free(candidate);
        if (fileExistsAbsolute(io, candidate)) return true;
        if (builtin.os.tag == .windows) {
            const exe_candidate = std.fmt.allocPrint(allocator, "{s}.exe", .{candidate}) catch continue;
            defer allocator.free(exe_candidate);
            if (fileExistsAbsolute(io, exe_candidate)) return true;
        }
    }
    return false;
}

const CiStatus = struct {
    detected: bool,
    provider: []const u8,
};

fn detectCi(allocator: std.mem.Allocator) !CiStatus {
    var env_map = try env_util.createProcessMap(allocator);
    defer env_map.deinit();
    if (envPresent(&env_map, "GITHUB_ACTIONS")) return .{ .detected = true, .provider = try allocator.dupe(u8, "GitHub Actions") };
    if (envPresent(&env_map, "CI")) return .{ .detected = true, .provider = try allocator.dupe(u8, "generic CI") };
    return .{ .detected = false, .provider = try allocator.dupe(u8, "none") };
}

fn envPresent(env_map: *const std.process.Environ.Map, name: []const u8) bool {
    const value = env_map.get(name) orelse return false;
    return value.len > 0;
}

fn detectShell(allocator: std.mem.Allocator) ![]const u8 {
    var env_map = try env_util.createProcessMap(allocator);
    defer env_map.deinit();
    if (try env_util.getOwned(&env_map, allocator, "SHELL")) |value| {
        defer allocator.free(value);
        return try allocator.dupe(u8, std.fs.path.basename(value));
    }
    if (env_util.getOwned(&env_map, allocator, "COMSPEC") catch null) |value| {
        defer allocator.free(value);
        return try allocator.dupe(u8, std.fs.path.basename(value));
    }
    if (envPresent(&env_map, "PSModulePath")) return try allocator.dupe(u8, "powershell");
    return try allocator.dupe(u8, "unknown");
}

test "doctor writeReport includes MCP setup table" {
    var stdout_buf: [32768]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    const os = core.platform.detectOs();
    const report = sandbox.backend.detect(os);
    var context = try testContext(std.testing.allocator, .{});
    defer context.deinit();

    try writeReport(std.testing.io, &stdout_writer, os, report, context, false);
    const written = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, written, "MCP policy (.ryk/policy.yaml):") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "Host MCP inventory") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "does not rewrite policy") != null);
}

test "doctor renders verbose OS and planned capabilities from an injected context" {
    var stdout_buf: [32768]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    const os = core.platform.detectOs();
    const report = sandbox.backend.detect(os);
    var context = try testContext(std.testing.allocator, .{});
    defer context.deinit();

    try writeReport(std.testing.io, &stdout_writer, os, report, context, true);

    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "ryk Doctor") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "Integration checks:") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "OS:") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "process supervision:") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "network policy engine: active") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "transparent network enforcement: unavailable") != null or std.mem.indexOf(u8, stdout_writer.buffered(), "transparent network enforcement: limited") != null or std.mem.indexOf(u8, stdout_writer.buffered(), "transparent network enforcement: observe-only") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "proxy-mediated enforcement: limited") != null or std.mem.indexOf(u8, stdout_writer.buffered(), "proxy-mediated enforcement: unavailable") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "Backend:") != null or std.mem.indexOf(u8, stdout_writer.buffered(), "Linux backend:") != null or std.mem.indexOf(u8, stdout_writer.buffered(), "macOS backend:") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "env filtering: active") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "strong sandbox:") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "Secret boundary:") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "Secret boundary: active") == null);
}

test "doctor can render Linux backend details from an injected report" {
    var stdout_buf: [32768]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    const report = sandbox.backend.detect(.linux);
    var context = try testContext(std.testing.allocator, .{});
    defer context.deinit();

    try writeReport(std.testing.io, &stdout_writer, .linux, report, context, true);

    const written = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, written, "Linux backend:") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "user namespace:") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "mount namespace:") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "seccomp:") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "landlock:") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "transparent network enforcement: observe-only") != null);
}

test "doctor can render macOS backend details from an injected report" {
    var stdout_buf: [32768]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    const report = sandbox.backend.detect(.macos);
    var context = try testContext(std.testing.allocator, .{});
    defer context.deinit();

    try writeReport(std.testing.io, &stdout_writer, .macos, report, context, true);

    const written = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, written, "macOS backend:") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "selected: macos") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "env filtering: active") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "path staging: active") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "transparent file enforcement: limited") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "shell shims: wrapper-only") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "process supervision: active") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "transparent network enforcement: unavailable") != null);
    // partial on matrix macOS with sandbox_init; unavailable outside matrix — never active from probe.
    const strong_unavail = std.mem.indexOf(u8, written, "strong sandbox: unavailable") != null;
    const strong_partial = std.mem.indexOf(u8, written, "strong sandbox: partial") != null;
    try std.testing.expect(strong_unavail or strong_partial);
    try std.testing.expect(std.mem.indexOf(u8, written, "strong sandbox: active") == null);
    // When attach is possible, doctor surfaces default residual grade (capability, not live).
    if (strong_partial) {
        try std.testing.expect(std.mem.indexOf(u8, written, "seatbelt_profile=hardened") != null);
        try std.testing.expect(std.mem.indexOf(u8, written, "default residual grade hardened") != null);
    }
    try std.testing.expect(std.mem.indexOf(u8, written, "mcp stdio proxy: active") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "audit/replay: active") != null);
}

// Internal id S-GLO-01: probe-only active must never reach operator-facing doctor output.
test "doctor never prints strong sandbox active from capability probe alone" {
    var stdout_buf: [32768]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);

    // Forge a dishonest report that claims strong_sandbox active without attach.
    var reports = sandbox.backend.baseReports(.macos);
    sandbox.backend.setReport(&reports, .strong_sandbox, .active, "forged probe-only active");
    const forged: sandbox.backend.ReportSet = .{
        .os = .macos,
        .backend_name = "macos",
        .fallback_level = .partial,
        .fallback_note = "test",
        .reports = reports,
    };
    var context = try testContext(std.testing.allocator, .{});
    defer context.deinit();

    try writeReport(std.testing.io, &stdout_writer, .macos, forged, context, true);
    const written = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, written, "strong sandbox: active") == null);
    try std.testing.expect(std.mem.indexOf(u8, written, "strong sandbox: unavailable") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "without attach") != null);
    // Ticket IDs must not appear in operator-facing doctor text.
    try std.testing.expect(std.mem.indexOf(u8, written, "S-GLO-01") == null);
    // Forged probe note must not leak through after demotion.
    try std.testing.expect(std.mem.indexOf(u8, written, "forged probe-only active") == null);
    // Default doctor copy stays mechanism-neutral (verbose may name Landlock/Seatbelt later).
    try std.testing.expect(std.mem.indexOf(u8, written, "Seatbelt") == null);
    try std.testing.expect(std.mem.indexOf(u8, written, "Landlock") == null);
}

test "doctor can render Windows backend details from an injected report" {
    var stdout_buf: [32768]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    const report = sandbox.backend.detect(.windows);
    var context = try testContext(std.testing.allocator, .{});
    defer context.deinit();

    try writeReport(std.testing.io, &stdout_writer, .windows, report, context, true);

    const written = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, written, "Windows backend:") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "selected: windows") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "env filtering: active") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "path staging: active") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "PATH shims: wrapper-only") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "cmd wrapper: wrapper-only") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "PowerShell wrapper: wrapper-only") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "process cleanup: partial") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "transparent file enforcement: unavailable") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "proxy-mediated HTTP: unavailable") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "transparent network enforcement: unavailable") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "strong sandbox: unavailable") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "mcp stdio proxy: active") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "audit/replay: active") != null);
}

test "doctor detects valid policy in current workspace" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_path_z = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(tmp_path_z);
    const tmp_path = try std.testing.allocator.dupe(u8, tmp_path_z);

    try tmp.dir.createDirPath(std.testing.io, ".git");
    try tmp.dir.createDirPath(std.testing.io, ".ryk");
    {
        const file = try tmp.dir.createFile(std.testing.io, ".ryk/policy.yaml", .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io, policy_mod.presets.agentPresetText(.generic_agent));
    }

    var stdout_buf: [32768]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    var context = try collectIntegrationContextAt(std.testing.io, std.testing.allocator, tmp_path, true);
    defer context.deinit();

    try writeReport(std.testing.io, &stdout_writer, core.platform.detectOs(), sandbox.backend.detect(core.platform.detectOs()), context, true);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), ".ryk/policy.yaml: present and valid") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "git repository: detected") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "doctor reports invalid policy clearly without printing synthetic secrets" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_path_z = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(tmp_path_z);
    const tmp_path = try std.testing.allocator.dupe(u8, tmp_path_z);

    try tmp.dir.createDirPath(std.testing.io, ".ryk");
    {
        const file = try tmp.dir.createFile(std.testing.io, ".ryk/policy.yaml", .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io,
            \\version: 1
            \\mode: loose
            \\# synthetic secret should not appear in doctor output: ghp_fakeSecretShouldNotPrint
        );
    }

    var stdout_buf: [32768]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    var context = try collectIntegrationContextAt(std.testing.io, std.testing.allocator, tmp_path, true);
    defer context.deinit();

    try writeReport(std.testing.io, &stdout_writer, core.platform.detectOs(), sandbox.backend.detect(core.platform.detectOs()), context, true);
    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, ".ryk/policy.yaml: invalid") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "UnsupportedPolicyMode") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "ghp_fakeSecretShouldNotPrint") == null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "doctor renders a compact summary from an injected context" {
    var stdout_buf: [32768]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    const os = core.platform.detectOs();
    const report = sandbox.backend.detect(os);
    var context = try testContext(std.testing.allocator, .{});
    defer context.deinit();

    try writeReport(std.testing.io, &stdout_writer, os, report, context, false);

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "Summary:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "hook server:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "active") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Recommended next step:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Capabilities:") == null);
}

test "doctor renders a full report from an injected context" {
    var stdout_buf: [32768]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    const os = core.platform.detectOs();
    const report = sandbox.backend.detect(os);
    var context = try testContext(std.testing.allocator, .{});
    defer context.deinit();

    try writeReport(std.testing.io, &stdout_writer, os, report, context, true);

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "Summary:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Capabilities:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Integration checks:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "workspace root:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "daemon health:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "fallback mode:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Recommended next step:") != null);
}

test "doctor integration collection returns allocator failures instead of panicking" {
    var failing_allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, collectIntegrationContextAt(std.testing.io, failing_allocator.allocator(), ".", true));
}

test "doctor output contains status glyphs in plain text mode" {
    var stdout_buf: [32768]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    const report = sandbox.backend.detect(.linux);
    var context = try testContext(std.testing.allocator, .{});
    defer context.deinit();

    try writeReport(std.testing.io, &stdout_writer, .linux, report, context, true);
    const written = stdout_writer.buffered();
    const has_check = std.mem.indexOf(u8, written, "✓") != null;
    const has_diamond = std.mem.indexOf(u8, written, "◌") != null;
    const has_cross = std.mem.indexOf(u8, written, "✗") != null;
    try std.testing.expect(has_check or has_diamond or has_cross);
}

test "doctor output has no ANSI codes in non-TTY mode" {
    var stdout_buf: [32768]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    const report = sandbox.backend.detect(.linux);
    var context = try testContext(std.testing.allocator, .{});
    defer context.deinit();

    try writeReport(std.testing.io, &stdout_writer, .linux, report, context, true);
    const written = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, written, "\x1b[") == null);
}

test "doctor default renders compact health and capability panels" {
    var stdout_buf: [32768]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    const report = sandbox.backend.detect(.linux);
    var context = try testContext(std.testing.allocator, .{});
    defer context.deinit();

    try writeReport(std.testing.io, &stdout_writer, .linux, report, context, false);

    const written = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, written, "System health") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "Capabilities") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "process supervision") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "fallback mode:") == null);
}

test "doctor sanitizes hostile dynamic diagnostic text" {
    var stdout_buf: [16384]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    const report = sandbox.backend.detect(.linux);
    var context = try testContext(std.testing.allocator, .{});
    defer context.deinit();
    context.allocator.free(context.workspace_root);
    context.workspace_root = try context.allocator.dupe(u8, "repo\x1b[2J\rspoof");
    context.allocator.free(context.daemon_detail);
    context.daemon_detail = try context.allocator.dupe(u8, "offline\x1b]0;pwn\x07\nforged");

    try writeReport(std.testing.io, &stdout_writer, .linux, report, context, true);

    const written = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOfScalar(u8, written, 0x1b) == null);
    try std.testing.expect(std.mem.indexOf(u8, written, "pwn") == null);
    try std.testing.expect(std.mem.indexOf(u8, written, "\nforged") == null);
}

test "doctor verbose output redacts secret-bearing dynamic paths and details" {
    const synthetic_secret = "ghp_syntheticDoctorHumanSecret123456";
    var stdout_buf: [32768]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var context = try testContext(std.testing.allocator, .{ .daemon_detail = "password=ghp_syntheticDoctorHumanSecret123456" });
    defer context.deinit();
    context.allocator.free(context.workspace_root);
    context.workspace_root = try context.allocator.dupe(u8, "/tmp/ghp_syntheticDoctorHumanSecret123456/workspace");
    context.allocator.free(context.daemon_binary_path.?);
    context.daemon_binary_path = try context.allocator.dupe(u8, "/tmp/ghp_syntheticDoctorHumanSecret123456/ryk-daemon");

    try writeReport(std.testing.io, &stdout_writer, .linux, sandbox.backend.detect(.linux), context, true);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), synthetic_secret) == null);
}

test "doctor writeReport keeps capabilities when workspace path has encoded secret" {
    // Encoded `token=…` must redact the path field only. Whole-document
    // redactAlloc collapses the report to [REDACTED] and wipes grades.
    const encoded_secret = "token%3Dcorrect-horse-battery-staple";
    var stdout_buf: [32768]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var context = try testContext(std.testing.allocator, .{});
    defer context.deinit();
    context.allocator.free(context.workspace_root);
    context.workspace_root = try context.allocator.dupe(u8, "/tmp/" ++ encoded_secret ++ "/workspace");

    try writeReport(std.testing.io, &stdout_writer, .linux, sandbox.backend.detect(.linux), context, true);
    const written = stdout_writer.buffered();
    try std.testing.expect(!std.mem.eql(u8, written, "[REDACTED]"));
    try std.testing.expect(std.mem.indexOf(u8, written, "Capabilities") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "strong sandbox") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "correct-horse-battery-staple") == null);
    try std.testing.expect(std.mem.indexOf(u8, written, encoded_secret) == null);
}

test "doctor summary includes daemon availability" {
    var stdout_buf: [32768]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    const report = sandbox.backend.detect(.linux);
    var context = try testContext(std.testing.allocator, .{
        .daemon_health = .unavailable,
        .daemon_detail = "no running daemon answered on the expected socket.",
    });
    defer context.deinit();

    try writeReport(std.testing.io, &stdout_writer, .linux, report, context, false);
    const written = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, written, "daemon unavailable") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "no running daemon answered on the expected socket") != null);
}

test "doctor integration report includes daemon health details" {
    var stdout_buf: [32768]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    const report = sandbox.backend.detect(.linux);
    var context = try testContext(std.testing.allocator, .{
        .daemon_health = .incompatible,
        .daemon_detail = "daemon protocol version or capability set does not match this ryk CLI.",
    });
    defer context.deinit();

    try writeReport(std.testing.io, &stdout_writer, .linux, report, context, true);
    const written = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, written, "daemon health: incompatible") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "does not match this ryk CLI") != null);
}

test "doctor integration report warns on world-writable RYK_DAEMON path" {
    var stdout_buf: [32768]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    const report = sandbox.backend.detect(.linux);
    var context = try testContext(std.testing.allocator, .{
        .daemon_health = .unavailable,
        .daemon_detail = "RYK_DAEMON points at a world-writable path.",
        .daemon_binary_untrusted = true,
    });
    defer context.deinit();

    try writeReport(std.testing.io, &stdout_writer, .linux, report, context, true);
    const written = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, written, "daemon binary trust: world-writable RYK_DAEMON path") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "RYK_DAEMON points at a world-writable path.") != null);
}

test "doctor recommendations prioritize daemon remediation over missing policy" {
    var stdout_buf: [32768]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    const report = sandbox.backend.detect(.linux);
    var context = try testContext(std.testing.allocator, .{
        .policy_present = false,
        .daemon_health = .unavailable,
        .daemon_detail = "no running daemon answered on the expected socket.",
    });
    defer context.deinit();

    try writeReport(std.testing.io, &stdout_writer, .linux, report, context, false);
    const written = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, written, "Daemon health issue: no running daemon answered on the expected socket.") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "./scripts/build-all.sh") != null);
    // After daemon remediation, missing policy teaches sole repair door doctor --fix.
    try std.testing.expect(std.mem.indexOf(u8, written, "ryk doctor --fix") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "ryk init --preset") == null);
}

test "doctor packs section stays known when daemon is unavailable" {
    // RT-12 / F9: packs inventory is Zig monopath — not daemon-gated.
    var stdout_buf: [16384]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    const report = sandbox.backend.detect(.linux);
    var context = try testContext(std.testing.allocator, .{
        .daemon_health = .unavailable,
        .daemon_detail = "no running daemon answered on the expected socket.",
    });
    defer context.deinit();

    try writeReport(std.testing.io, &stdout_writer, .linux, report, context, false);
    const written = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, written, "\nPacks\n") != null);
    // Must not claim unknown solely because daemon is down.
    try std.testing.expect(std.mem.indexOf(u8, written, "unknown (packs inventory offline") == null);
    // Baseline / opt-in summary from oracle registry.
    try std.testing.expect(
        std.mem.indexOf(u8, written, "baseline") != null or
            std.mem.indexOf(u8, written, "opt-in") != null or
            std.mem.indexOf(u8, written, "Packs") != null,
    );
    try std.testing.expect(std.mem.indexOf(u8, written, "shell evaluation fails closed") == null);
}

test "doctor host table lists managed hosts and shell gates" {
    var stdout_buf: [16384]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    const report = sandbox.backend.detect(.linux);
    var context = try testContext(std.testing.allocator, .{});
    defer context.deinit();

    try writeReport(std.testing.io, &stdout_writer, .linux, report, context, false);
    const written = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, written, "Host integrations") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "codex") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "claude") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "opencode") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "openclaw") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "hermes") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "pre_tool_call") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "pi") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "grok") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "extension-managed (smoke not run)") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "SMOKE ALLOW") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "SMOKE DENY") != null);
    // W1 message-migrate: Pi teach strings use doctor --fix (not start onboard).
    try std.testing.expect(std.mem.indexOf(u8, written, "Pi: bundled extension setup is managed by `ryk doctor --fix`") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "ryk run -- pi") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "pi …") == null);
    try std.testing.expect(std.mem.indexOf(u8, written, "fix pi:") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "ryk doctor --fix") != null);
    // Forbidden start-onboard needle must not appear in rendered host table / Pi note.
    try std.testing.expect(std.mem.indexOf(u8, written, "ryk" ++ " start") == null);
}

test "doctor names a test-program host bake and teaches doctor --fix" {
    var stdout_buf: [16384]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    const report = sandbox.backend.detect(.linux);
    var context = try testContext(std.testing.allocator, .{ .broken_evaluator_host = "pi" });
    defer context.deinit();

    try writeReport(std.testing.io, &stdout_writer, .linux, report, context, false);
    const written = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, written, "broken") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "Hook is a test program, not ryk") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "ryk doctor --fix") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "test/non-product") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "OS-enforced") == null);
    try std.testing.expect(std.mem.indexOf(u8, written, "evaluator not product ryk") != null);
}

test "doctor warns when Hermes is explicitly fail-open" {
    var stdout_buf: [16384]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    const report = sandbox.backend.detect(.linux);
    var context = try testContext(std.testing.allocator, .{
        .hermes_installed = true,
        .hermes_fail_open = true,
    });
    defer context.deinit();

    try writeReport(std.testing.io, &stdout_writer, .linux, report, context, false);
    const written = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, written, "explicitly fail-open") != null or std.mem.indexOf(u8, written, "fail-open") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "RYK_HERMES_FAIL_OPEN") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "ryk run -- hermes") != null);
}

test "hermesFailOpenFromEnvValue defaults to fail-closed" {
    try std.testing.expect(!hermesFailOpenFromEnvValue(null));
    try std.testing.expect(hermesFailOpenFromEnvValue("1"));
    try std.testing.expect(hermesFailOpenFromEnvValue("true"));
    try std.testing.expect(!hermesFailOpenFromEnvValue("0"));
    try std.testing.expect(!hermesFailOpenFromEnvValue("false"));
    try std.testing.expect(!hermesFailOpenFromEnvValue("off"));
    try std.testing.expect(!hermesFailOpenFromEnvValue("typo"));
    try std.testing.expect(!hermesFailOpenFromEnvValue(""));
}

test "doctor rejects unknown option" {
    var stdout_buf: [64]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const code = try command(std.testing.io, &.{"--nope"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, code);
}

test "doctor --json readiness includes ready and policy.valid" {
    var stdout_buf: [8192]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    // Without --check: always exit 0 for report render even if not ready.
    const code = try command(std.testing.io, &.{"--json"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    const out = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "\"schema_version\": 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"ready\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"state\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"valid\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"check\": false") != null);
}

test "doctor parseDoctorOptions accepts --check and --json" {
    var stderr_buf: [64]u8 = undefined;
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const opts = try parseDoctorOptions(&.{ "--check", "--json", "--verbose" }, &stderr_writer);
    try std.testing.expect(opts.check);
    try std.testing.expect(opts.json);
    try std.testing.expect(opts.verbose);
}

test "doctor parseDoctorOptions accepts --tui; default remains linear" {
    var stderr_buf: [64]u8 = undefined;
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const bare = try parseDoctorOptions(&.{}, &stderr_writer);
    try std.testing.expect(!bare.tui);
    try std.testing.expect(!bare.json);
    const with_tui = try parseDoctorOptions(&.{"--tui"}, &stderr_writer);
    try std.testing.expect(with_tui.tui);
    // --tui + --json still parse; json path freezes machine output (no TUI).
    const both = try parseDoctorOptions(&.{ "--tui", "--json" }, &stderr_writer);
    try std.testing.expect(both.tui);
    try std.testing.expect(both.json);
}

test "doctor --tui non-TTY fail-closed message then linear report" {
    // Under tests stdin/stdout are non-TTY → wouldEnter false → fail-closed message + linear.
    var stdout_buf: [32768]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const code = try command(std.testing.io, &.{"--tui"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    const err = stderr_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, err, "--tui requires") != null or std.mem.indexOf(u8, err, "using linear") != null);
    const out = stdout_writer.buffered();
    // Linear path still rendered.
    try std.testing.expect(std.mem.indexOf(u8, out, "ryk Doctor") != null or std.mem.indexOf(u8, out, "Summary") != null);
}

test "doctor TUI entry uses shared shouldEnterTui gate via wouldEnterDoctorTui" {
    // Composition: opt-in --tui + shouldEnterTui — not a dead import.
    // Slim stub is always false; TUI-on applies the real TTY/--tui gate.
    try std.testing.expectEqual(enable_tui, doctor_tui.wouldEnterDoctorTui(true, true, &.{"--tui"}, true, false));
    try std.testing.expect(!doctor_tui.wouldEnterDoctorTui(true, true, &.{}, false, false));
    try std.testing.expect(!doctor_tui.wouldEnterDoctorTui(false, true, &.{"--tui"}, true, false));
    try std.testing.expect(!doctor_tui.wouldEnterDoctorTui(true, true, &.{ "--tui", "--json" }, true, true));
    if (enable_tui) {
        try std.testing.expect(@TypeOf(tui.browse.keyToAction) != void);
    }
}

test "doctor --json frozen when --tui also present" {
    var stdout_buf: [8192]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const code = try command(std.testing.io, &.{ "--json", "--tui" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    const out = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "\"ready\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"schema_version\"") != null);
    // No fail-closed TUI message on the json path (json wins before TUI branch).
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "using linear") == null);
}

// ---------------------------------------------------------------------------
// doctorFix — public `ryk doctor --fix` → ensure (w1-doctor-fix)
// Named substring `doctorFix` is the monopath gate proof (D77).
// Production contracts only — co-located test region is stripped for monopath.
// ---------------------------------------------------------------------------

/// Production region of this file (everything before the first co-located test).
fn doctorFixProdSource() []const u8 {
    const src = @embedFile("doctor.zig");
    if (std.mem.indexOf(u8, src, "\ntest \"")) |idx| return src[0..idx];
    return src;
}

/// True when path under dir exists (policy / host artifact probe for mutation oracles).
fn doctorFixPathExists(dir: std.Io.Dir, sub_path: []const u8) bool {
    dir.access(std.testing.io, sub_path, .{}) catch return false;
    return true;
}

/// Count non-overlapping occurrences of `needle` in `hay`.
fn doctorFixCount(hay: []const u8, needle: []const u8) usize {
    var n: usize = 0;
    var rest = hay;
    while (std.mem.indexOf(u8, rest, needle)) |idx| {
        n += 1;
        rest = rest[idx + needle.len ..];
    }
    return n;
}

/// Production strip from exclusive `if (options.fix)` through first diagnose collect.
/// Empty when the exclusive fix gate or collect site is missing (intentional RED).
fn doctorFixWindow() []const u8 {
    const prod = doctorFixProdSource();
    const fix_if = std.mem.indexOf(u8, prod, "if (options.fix)") orelse return "";
    const collect = std.mem.indexOf(u8, prod, "collectIntegrationContext") orelse return "";
    if (fix_if >= collect) return "";
    return prod[fix_if..collect];
}

test "doctorFix parseDoctorOptions accepts --fix and optional --from-install / --preset" {
    // Acceptance (1): parseDoctorOptions accepts --fix and optional
    // --from-install / --preset. DoctorOptions must surface fix / from_install /
    // preset fields for the ensure early branch (D32/D40).
    var stderr_buf: [256]u8 = undefined;
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    // --fix alone: repair door without install scope.
    {
        const opts = try parseDoctorOptions(&.{"--fix"}, &stderr_writer);
        try std.testing.expect(opts.fix);
        try std.testing.expect(!opts.from_install);
        try std.testing.expect(opts.preset == null);
        try std.testing.expect(!opts.check);
        try std.testing.expect(!opts.json);
    }

    // Optional install-scope + preset value (space-separated, start monopath).
    {
        const opts = try parseDoctorOptions(
            &.{ "--fix", "--from-install", "--preset", "generic-agent" },
            &stderr_writer,
        );
        try std.testing.expect(opts.fix);
        try std.testing.expect(opts.from_install);
        try std.testing.expect(opts.preset != null);
        try std.testing.expectEqualStrings("generic-agent", opts.preset.?);
    }

    // --from-install / --preset parse without forcing check/json probe modes.
    {
        const opts = try parseDoctorOptions(&.{ "--fix", "--from-install" }, &stderr_writer);
        try std.testing.expect(opts.fix);
        try std.testing.expect(opts.from_install);
        try std.testing.expect(!opts.check);
        try std.testing.expect(!opts.json);
    }
}

test "doctorFix parseDoctorOptions rejects --fix combined with --check or --json" {
    // PR #95: --fix must not silently dominate probe contracts.
    var stderr_buf: [512]u8 = undefined;
    const combos = [_][]const []const u8{
        &.{ "--fix", "--check" },
        &.{ "--check", "--fix" },
        &.{ "--fix", "--json" },
        &.{ "--json", "--fix" },
        &.{ "--fix", "--check", "--json" },
    };
    for (combos) |args| {
        var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
        try std.testing.expectError(error.Usage, parseDoctorOptions(args, &stderr_writer));
        const err = stderr_writer.buffered();
        try std.testing.expect(std.mem.indexOf(u8, err, "ryk doctor:") != null);
        try std.testing.expect(std.mem.indexOf(u8, err, "cannot combine --fix with --check/--json") != null);
    }
}

test "doctorFix parseDoctorOptions rejects --from-install or --preset without --fix" {
    // Ensure-only flags must not be silent no-ops without --fix.
    var stderr_buf: [512]u8 = undefined;

    {
        var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
        try std.testing.expectError(error.Usage, parseDoctorOptions(&.{"--from-install"}, &stderr_writer));
        const err = stderr_writer.buffered();
        try std.testing.expect(std.mem.indexOf(u8, err, "ryk doctor:") != null);
        try std.testing.expect(std.mem.indexOf(u8, err, "--from-install") != null);
        try std.testing.expect(std.mem.indexOf(u8, err, "--fix") != null);
    }
    {
        var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
        try std.testing.expectError(error.Usage, parseDoctorOptions(&.{ "--preset", "generic-agent" }, &stderr_writer));
        const err = stderr_writer.buffered();
        try std.testing.expect(std.mem.indexOf(u8, err, "ryk doctor:") != null);
        try std.testing.expect(std.mem.indexOf(u8, err, "--preset") != null);
        try std.testing.expect(std.mem.indexOf(u8, err, "--fix") != null);
    }
    {
        var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
        try std.testing.expectError(
            error.Usage,
            parseDoctorOptions(&.{ "--from-install", "--preset", "generic-agent" }, &stderr_writer),
        );
        const err = stderr_writer.buffered();
        try std.testing.expect(std.mem.indexOf(u8, err, "ryk doctor:") != null);
        try std.testing.expect(std.mem.indexOf(u8, err, "--fix") != null);
    }
}

test "doctorFix parseDoctorOptions rejects invalid --preset with doctor branding" {
    // Invalid preset must fail at doctor parse with ryk doctor: branding (not init).
    var stderr_buf: [1024]u8 = undefined;
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    try std.testing.expectError(
        error.Usage,
        parseDoctorOptions(&.{ "--fix", "--preset", "not-a-real-preset" }, &stderr_writer),
    );
    const err = stderr_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, err, "ryk doctor:") != null or std.mem.indexOf(u8, err, "ryk doctor") != null);
    try std.testing.expect(std.mem.indexOf(u8, err, "invalid --preset value") != null);
    try std.testing.expect(std.mem.indexOf(u8, err, "not-a-real-preset") != null);
    try std.testing.expect(std.mem.indexOf(u8, err, "ryk init") == null);
    try std.testing.expect(std.mem.indexOf(u8, err, "help doctor") != null);
}

test "doctorFix missing policy recommendation teaches doctor --fix sole repair door" {
    // Diagnose missing-policy teach: sole/primary repair door is ryk doctor --fix.
    var stdout_buf: [32768]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    const report = sandbox.backend.detect(.linux);
    var context = try testContext(std.testing.allocator, .{
        .policy_present = false,
    });
    defer context.deinit();

    try writeReport(std.testing.io, &stdout_writer, .linux, report, context, false);
    const written = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, written, "ryk doctor --fix") != null);
    // Must not sole-teach ryk init as the missing-policy repair door.
    try std.testing.expect(std.mem.indexOf(u8, written, "ryk init --preset") == null);
}

test "doctorFix testHostRows builds fix strings via host_status.formatFix" {
    // Co-located host table fixtures must call formatFix (no hand-authored Pi green-paint).
    const allocator = std.testing.allocator;
    const rows = try testHostRows(allocator);
    defer {
        for (rows) |row| {
            allocator.free(row.host);
            allocator.free(row.wired);
            allocator.free(row.shell_gate);
            allocator.free(row.fail_stance);
            allocator.free(row.smoke_allow);
            allocator.free(row.smoke_deny);
            allocator.free(row.fix);
        }
        allocator.free(rows);
    }

    const smoke = host_status.HostSmokePair{};
    const hermes_fail_open = true;
    for (rows) |row| {
        const expected = try host_status.formatFix(allocator, row.host, row.wired, smoke, hermes_fail_open);
        defer allocator.free(expected);
        try std.testing.expectEqualStrings(expected, row.fix);
    }
}

test "doctorFix help documents --fix" {
    // Acceptance (1): help documents --fix (usage + completion flags).
    // Exclusive production edit is help.zig doctor section; seam is findCommand.
    const info = help.findCommand("doctor") orelse return error.TestUnexpectedResult;
    try std.testing.expect(std.mem.indexOf(u8, info.usage, "--fix") != null);

    var lists_fix = false;
    for (info.additional_completion_flags) |flag| {
        if (std.mem.eql(u8, flag, "--fix")) lists_fix = true;
    }
    try std.testing.expect(lists_fix);

    // Operator-facing details or examples must teach the repair door.
    var teaches_fix = false;
    for (info.examples) |example| {
        if (std.mem.indexOf(u8, example, "--fix") != null) teaches_fix = true;
    }
    for (info.details) |line| {
        if (std.mem.indexOf(u8, line, "--fix") != null) teaches_fix = true;
    }
    try std.testing.expect(teaches_fix);

    // Exclusivity: --fix vs --check/--json; ensure-only flags only with --fix.
    var documents_exclusivity = false;
    var documents_ensure_only_with_fix = false;
    for (info.details) |line| {
        if (std.mem.indexOf(u8, line, "--fix") != null and
            std.mem.indexOf(u8, line, "--check") != null and
            std.mem.indexOf(u8, line, "--json") != null)
        {
            documents_exclusivity = true;
        }
        if ((std.mem.indexOf(u8, line, "--from-install") != null or std.mem.indexOf(u8, line, "--preset") != null) and
            std.mem.indexOf(u8, line, "--fix") != null)
        {
            documents_ensure_only_with_fix = true;
        }
    }
    try std.testing.expect(documents_exclusivity);
    try std.testing.expect(documents_ensure_only_with_fix);
}

test "doctor help documents --tui four-pane deep-dive" {
    // D5: help documents --tui (usage, completion, example, details).
    const info = help.findCommand("doctor") orelse return error.TestUnexpectedResult;
    try std.testing.expect(std.mem.indexOf(u8, info.usage, "--tui") != null);

    var lists_tui = false;
    for (info.additional_completion_flags) |flag| {
        if (std.mem.eql(u8, flag, "--tui")) lists_tui = true;
    }
    try std.testing.expect(lists_tui);

    var teaches_tui = false;
    for (info.examples) |example| {
        if (std.mem.indexOf(u8, example, "--tui") != null) teaches_tui = true;
    }
    for (info.details) |line| {
        if (std.mem.indexOf(u8, line, "--tui") != null) teaches_tui = true;
    }
    try std.testing.expect(teaches_tui);

    // Details name the four panes and day-2 links.
    var details_blob: [4096]u8 = undefined;
    var dw: std.Io.Writer = .fixed(&details_blob);
    for (info.details) |line| {
        try dw.writeAll(line);
        try dw.writeAll("\n");
    }
    const details = dw.buffered();
    try std.testing.expect(std.mem.indexOf(u8, details, "Summary") != null);
    try std.testing.expect(std.mem.indexOf(u8, details, "Hosts") != null);
    try std.testing.expect(std.mem.indexOf(u8, details, "Capabilities") != null);
    try std.testing.expect(std.mem.indexOf(u8, details, "Next steps") != null);
    try std.testing.expect(std.mem.indexOf(u8, details, "ryk packs") != null);
    try std.testing.expect(std.mem.indexOf(u8, details, "ryk allowlist") != null);
}

test "doctorFix early-branches to ensure with processExitForOutcome (D40/D25)" {
    // Acceptance (2): --fix early-branches to ensure; does not inherit diagnose
    // exit from host soft fails. Production must call ensure.runEnsure and map via
    // processExitForOutcome under an exclusive `if (options.fix)` window that
    // returns before collectIntegrationContext (D40).
    const prod = doctorFixProdSource();
    const window = doctorFixWindow();
    try std.testing.expect(window.len > 0);

    // Exclusive fix gate (not a bare options.fix token elsewhere).
    try std.testing.expect(std.mem.indexOf(u8, prod, "if (options.fix)") != null);
    try std.testing.expect(std.mem.indexOf(u8, window, "runEnsure") != null);
    try std.testing.expect(std.mem.indexOf(u8, window, "processExitForOutcome") != null);

    // Return the ensure exit map from the fix window — discard / fall-through fails.
    const returns_map =
        std.mem.indexOf(u8, window, "return processExitForOutcome") != null or
        std.mem.indexOf(u8, window, "return ensure.processExitForOutcome") != null;
    try std.testing.expect(returns_map);

    // Plumb CLI install-scope into EnsureOptions (not DoctorOptions fields alone).
    try std.testing.expect(std.mem.indexOf(u8, window, "options.from_install") != null);
    try std.testing.expect(std.mem.indexOf(u8, window, "options.preset") != null);

    // Ensure module import for runEnsure / processExitForOutcome.
    const imports_ensure =
        std.mem.indexOf(u8, prod, "@import(\"ensure.zig\")") != null or
        std.mem.indexOf(u8, prod, "cli.ensure") != null;
    try std.testing.expect(imports_ensure);
}

test "doctorFix exit 0 iff ensure core_ok (D25)" {
    // Acceptance (2): exit 0 iff ensure core_ok. Composition with frozen ensure
    // processExitForOutcome — doctor --fix must return that map (not diagnose exit).
    const ensure_mod = @import("ensure.zig");

    var ok_outcome = ensure_mod.EnsureOutcome{
        .core_ok = true,
        .hosts = &.{},
        .policy_created = false,
        .policy_left_alone = true,
        .protection_label = .partial,
        .hosts_owned = false,
    };
    defer ok_outcome.deinit(std.testing.allocator);
    try std.testing.expectEqual(exit_codes.success, ensure_mod.processExitForOutcome(ok_outcome));
    try std.testing.expectEqual(@as(u8, 0), ensure_mod.processExitForOutcome(ok_outcome));

    var fail_outcome = ensure_mod.EnsureOutcome{
        .core_ok = false,
        .hosts = &.{},
        .policy_created = false,
        .policy_left_alone = false,
        .protection_label = .core_failed,
        .hosts_owned = false,
    };
    defer fail_outcome.deinit(std.testing.allocator);
    const fail_code = ensure_mod.processExitForOutcome(fail_outcome);
    try std.testing.expect(fail_code != exit_codes.success);
    try std.testing.expect(fail_code != 0);

    // Doctor fix window must return processExitForOutcome — not readiness.exitCode.
    const window = doctorFixWindow();
    try std.testing.expect(window.len > 0);
    const returns_map =
        std.mem.indexOf(u8, window, "return processExitForOutcome") != null or
        std.mem.indexOf(u8, window, "return ensure.processExitForOutcome") != null;
    try std.testing.expect(returns_map);
    // Diagnose-style exit helpers must not own the fix early-return.
    try std.testing.expect(std.mem.indexOf(u8, window, "exitCode(options.check)") == null);
    try std.testing.expect(std.mem.indexOf(u8, window, "core_ready.exitCode") == null);
}

test "doctorFix has no hard-dep on daemon ensure_running (D41)" {
    // Acceptance (2): --fix must not require daemon ensure_running as a hard dep.
    // Early-branch to ensure must precede collectIntegrationContext so fix does not
    // inherit the diagnose path's ensure_running = !(check or json) spawn contract.
    const prod = doctorFixProdSource();
    const window = doctorFixWindow();
    try std.testing.expect(window.len > 0);

    const fix_if = std.mem.indexOf(u8, prod, "if (options.fix)") orelse {
        try std.testing.expect(false);
        return;
    };
    const collect_idx = std.mem.indexOf(u8, prod, "collectIntegrationContext") orelse {
        try std.testing.expect(false);
        return;
    };
    try std.testing.expect(fix_if < collect_idx);

    // runEnsure lives only inside the fix window (before diagnose collect).
    try std.testing.expect(std.mem.indexOf(u8, window, "runEnsure") != null);
    const after_collect = prod[collect_idx..];
    try std.testing.expect(std.mem.indexOf(u8, after_collect, "runEnsure") == null);

    // Must not hard-code ensure_running = true for the fix door.
    try std.testing.expect(std.mem.indexOf(u8, prod, "ensure_running = true") == null);
    // Fix window itself must not force daemon ensure_running.
    try std.testing.expect(std.mem.indexOf(u8, window, "ensure_running = true") == null);
}

test "doctorFix runEnsure is exclusive to if (options.fix) early return" {
    // Acceptance (2)+(3) structural: always-call runEnsure then optional fix return
    // must not green. runEnsure appears only under if (options.fix) … return map,
    // never after diagnose collect, and at most once in production.
    const prod = doctorFixProdSource();
    const window = doctorFixWindow();
    try std.testing.expect(window.len > 0);

    try std.testing.expectEqual(@as(usize, 1), doctorFixCount(prod, "runEnsure"));
    try std.testing.expectEqual(@as(usize, 1), doctorFixCount(window, "runEnsure"));

    // Window must early-return the ensure map before collect can run.
    const returns_map =
        std.mem.indexOf(u8, window, "return processExitForOutcome") != null or
        std.mem.indexOf(u8, window, "return ensure.processExitForOutcome") != null;
    try std.testing.expect(returns_map);

    // Diagnose path remains present after the fix gate (not deleted for monopath).
    try std.testing.expect(std.mem.indexOf(u8, prod, "writeReport") != null);
    try std.testing.expect(std.mem.indexOf(u8, prod, "collectIntegrationContext") != null);
}

test "doctorFix default doctor is diagnose-only" {
    // Acceptance (2): default doctor diagnose-only (no --fix → no ensure mutation).
    var stderr_buf: [64]u8 = undefined;
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const opts = try parseDoctorOptions(&.{}, &stderr_writer);
    try std.testing.expect(!opts.fix);
    try std.testing.expect(!opts.from_install);
    try std.testing.expect(opts.preset == null);
    try std.testing.expect(!opts.check);
    try std.testing.expect(!opts.json);

    // Verbose-only remains diagnose (no fix).
    const verbose_opts = try parseDoctorOptions(&.{"--verbose"}, &stderr_writer);
    try std.testing.expect(verbose_opts.verbose);
    try std.testing.expect(!verbose_opts.fix);

    // Production: diagnose render path present; ensure call exclusive to fix window.
    const prod = doctorFixProdSource();
    try std.testing.expect(std.mem.indexOf(u8, prod, "writeReport") != null);
    const window = doctorFixWindow();
    try std.testing.expect(window.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, window, "runEnsure") != null);
    // After collect there is no second ensure door.
    if (std.mem.indexOf(u8, prod, "collectIntegrationContext")) |collect_idx| {
        try std.testing.expect(std.mem.indexOf(u8, prod[collect_idx..], "runEnsure") == null);
    } else {
        try std.testing.expect(false);
    }
}

test "doctorFix --check and --json remain probe-only (D42)" {
    // Acceptance (3): --check / --json remain probe-only (no ensure, no host mutation).
    var stderr_buf: [64]u8 = undefined;
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    {
        const opts = try parseDoctorOptions(&.{"--check"}, &stderr_writer);
        try std.testing.expect(opts.check);
        try std.testing.expect(!opts.fix);
        try std.testing.expect(!opts.from_install);
    }
    {
        const opts = try parseDoctorOptions(&.{"--json"}, &stderr_writer);
        try std.testing.expect(opts.json);
        try std.testing.expect(!opts.fix);
        try std.testing.expect(!opts.from_install);
    }
    {
        const opts = try parseDoctorOptions(&.{ "--check", "--json" }, &stderr_writer);
        try std.testing.expect(opts.check);
        try std.testing.expect(opts.json);
        try std.testing.expect(!opts.fix);
    }

    // Production: probe modes still force ensure_running false; runEnsure is fix-only.
    const prod = doctorFixProdSource();
    try std.testing.expect(std.mem.indexOf(u8, prod, "options.check") != null or
        std.mem.indexOf(u8, prod, "options.check or") != null or
        std.mem.indexOf(u8, prod, "!(options.check or options.json)") != null);
    const probe_gate =
        std.mem.indexOf(u8, prod, "ensure_running") != null and
        (std.mem.indexOf(u8, prod, "options.check") != null or
            std.mem.indexOf(u8, prod, "options.json") != null);
    try std.testing.expect(probe_gate);

    // Structural: single runEnsure only inside if (options.fix) window; not after collect.
    const window = doctorFixWindow();
    try std.testing.expect(window.len > 0);
    try std.testing.expectEqual(@as(usize, 1), doctorFixCount(prod, "runEnsure"));
    try std.testing.expect(std.mem.indexOf(u8, window, "runEnsure") != null);
    if (std.mem.indexOf(u8, prod, "collectIntegrationContext")) |collect_idx| {
        try std.testing.expect(std.mem.indexOf(u8, prod[collect_idx..], "runEnsure") == null);
    } else {
        try std.testing.expect(false);
    }
}

test "doctorFix probe and default command paths do not create policy (no host mutation)" {
    // Acceptance (2) default diagnose-only + (3) --check/--json probe-only:
    // Behavioral monopath under isolated tmpDir (zig-cache ceiling so ensure would
    // write here if always-called). Probe doors must leave fixture without policy.
    // Default/verbose diagnose-only is locked structurally (exclusive if (options.fix)
    // window + parse !fix); runtime oracle here uses --check/--json so the path
    // forces ensure_running=false and never spawns the daemon.
    const io = std.testing.io;
    const allocator = std.testing.allocator;

    const modes = [_][]const []const u8{
        &.{"--check"},
        &.{"--json"},
        &.{ "--check", "--json" },
    };

    for (modes) |argv| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        try tmp.dir.createDirPath(io, ".git");

        try std.testing.expect(!doctorFixPathExists(tmp.dir, ".ryk/policy.yaml"));
        try std.testing.expect(!doctorFixPathExists(tmp.dir, ".ryk"));

        const prev_cwd = try std.Io.Dir.cwd().realPathFileAlloc(io, ".", allocator);
        defer allocator.free(prev_cwd);
        try std.process.setCurrentDir(io, tmp.dir);
        defer std.process.setCurrentPath(io, prev_cwd) catch {};

        var stdout_buf: [65536]u8 = undefined;
        var stderr_buf: [4096]u8 = undefined;
        var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
        var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

        // Probe must not error-hard on missing policy; diagnose/readiness only.
        _ = try command(io, argv, &stdout_writer, &stderr_writer);

        try std.testing.expect(!doctorFixPathExists(tmp.dir, ".ryk/policy.yaml"));
        // ensure create-if-missing writes .ryk/ — must stay absent on probe doors.
        try std.testing.expect(!doctorFixPathExists(tmp.dir, ".ryk"));
    }
}

test "doctorFix --fix command path invokes ensure mutation door" {
    // Acceptance (2): --fix early-branches to ensure. Contrast with probe-only:
    // under empty tmpDir, doctor --fix must create-if-missing .ryk/policy.yaml
    // (ensure core). Host wire may soft-fail under zig-test binary; policy create is
    // the greppable ensure side effect.
    const io = std.testing.io;
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, ".git");

    try std.testing.expect(!doctorFixPathExists(tmp.dir, ".ryk/policy.yaml"));

    const prev_cwd = try std.Io.Dir.cwd().realPathFileAlloc(io, ".", allocator);
    defer allocator.free(prev_cwd);
    try std.process.setCurrentDir(io, tmp.dir);
    defer std.process.setCurrentPath(io, prev_cwd) catch {};

    var stdout_buf: [65536]u8 = undefined;
    var stderr_buf: [4096]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(io, &.{"--fix"}, &stdout_writer, &stderr_writer);
    // Exit map: core_ok → 0. Policy create under empty fixture should core_ok.
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expect(doctorFixPathExists(tmp.dir, ".ryk/policy.yaml"));
}

// ---------------------------------------------------------------------------
// doctorFix pack hub — w1-ensure-tests-pack composition + D06 receipt honesty
// Named-run gate still --filter doctorFix.
// ---------------------------------------------------------------------------

fn doctorFixSha256(bytes: []const u8) [32]u8 {
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return digest;
}

fn doctorFixClaimsFullProtection(text: []const u8) bool {
    // Shared D06 forbid-list with ensure (case-insensitive).
    return ensure.ensureSoftClaimsFullProtection(text);
}

test "doctorFix composition ensure writer then doctor check observes policy without second write" {
    // Composition acceptance: writer ensure under fixture → loader doctor diagnose
    // (--check probe) observes same policy artifact without second write.
    // Note: --check exit may be non-zero when daemon is unavailable (readiness gate);
    // composition oracle is hash stability + no rewrite, not core readiness green.
    const io = std.testing.io;
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, ".git");

    const prev_cwd = try std.Io.Dir.cwd().realPathFileAlloc(io, ".", allocator);
    defer allocator.free(prev_cwd);
    try std.process.setCurrentDir(io, tmp.dir);
    defer std.process.setCurrentPath(io, prev_cwd) catch {};

    var stdout_buf: [65536]u8 = undefined;
    var stderr_buf: [8192]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    // Writer: doctor --fix → ensure create-if-missing.
    const fix_code = try command(io, &.{"--fix"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, fix_code);
    try std.testing.expect(doctorFixPathExists(tmp.dir, ".ryk/policy.yaml"));

    const before = try tmp.dir.readFileAlloc(io, ".ryk/policy.yaml", allocator, .limited(64 * 1024));
    defer allocator.free(before);
    const before_hash = doctorFixSha256(before);

    // Loader: --check is probe-only (D42) — must not rewrite policy (may fail readiness).
    stdout_writer = .fixed(&stdout_buf);
    stderr_writer = .fixed(&stderr_buf);
    _ = try command(io, &.{"--check"}, &stdout_writer, &stderr_writer);
    try std.testing.expect(doctorFixPathExists(tmp.dir, ".ryk/policy.yaml"));

    const after_check = try tmp.dir.readFileAlloc(io, ".ryk/policy.yaml", allocator, .limited(64 * 1024));
    defer allocator.free(after_check);
    try std.testing.expectEqualStrings(before, after_check);
    try std.testing.expectEqual(before_hash, doctorFixSha256(after_check));

    // Second --fix leave-alone: core soft-success exit 0 without policy rewrite.
    stdout_writer = .fixed(&stdout_buf);
    stderr_writer = .fixed(&stderr_buf);
    const leave_code = try command(io, &.{"--fix"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, leave_code);
    const after_leave = try tmp.dir.readFileAlloc(io, ".ryk/policy.yaml", allocator, .limited(64 * 1024));
    defer allocator.free(after_leave);
    try std.testing.expectEqualStrings(before, after_leave);
}

test "doctorFix parse exit map soft partial is success when core_ok (D25 pack)" {
    // Acceptance: doctor --fix parse/exit — soft host fail keeps process exit 0 when
    // core_ok; core_failed is non-zero (pure processExitForOutcome contract).
    const ensure_mod = @import("ensure.zig");

    var hosts = [_]ensure_mod.HostResult{
        .{
            .host_id = "claude",
            .detected = true,
            .wired = false,
            .smoke_ok = false,
            .fix_hint = "ryk doctor --fix",
            .error_class = .wire,
        },
    };
    const soft = ensure_mod.EnsureOutcome{
        .core_ok = true,
        .hosts = hosts[0..],
        .policy_created = true,
        .policy_left_alone = false,
        .protection_label = .partial,
        .hosts_owned = false,
    };
    try std.testing.expectEqual(exit_codes.success, ensure_mod.processExitForOutcome(soft));

    const failed = ensure_mod.EnsureOutcome{
        .core_ok = false,
        .hosts = &.{},
        .policy_created = false,
        .policy_left_alone = false,
        .protection_label = .core_failed,
        .hosts_owned = false,
    };
    try std.testing.expect(ensure_mod.processExitForOutcome(failed) != 0);
}

test "doctorFix host mock fail receipt forbids D06 full phrases requires partial and fix" {
    // Acceptance (3): Forbidden D06 phrases asserted when host mock fails — receipt
    // on doctor --fix partial path must teach partial + doctor --fix, never full-protection.
    const ensure_mod = @import("ensure.zig");
    var hosts = [_]ensure_mod.HostResult{
        .{
            .host_id = "codex",
            .detected = true,
            .wired = false,
            .smoke_ok = false,
            .fix_hint = "ryk doctor --fix",
            .error_class = .wire,
        },
    };
    var outcome = ensure_mod.EnsureOutcome{
        .core_ok = true,
        .hosts = hosts[0..],
        .policy_created = false,
        .policy_left_alone = true,
        .protection_label = .partial,
        .hosts_owned = false,
    };
    defer outcome.deinit(std.testing.allocator);

    var buf: [8192]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try ensure_mod.writeEnsureReceipt(&writer, outcome);
    const text = writer.buffered();

    try std.testing.expect(!doctorFixClaimsFullProtection(text));
    try std.testing.expect(std.ascii.indexOfIgnoreCase(text, "partial") != null);
    try std.testing.expect(std.ascii.indexOfIgnoreCase(text, "doctor --fix") != null);
    try std.testing.expect(std.ascii.indexOfIgnoreCase(text, "codex") != null);
}

// ---------------------------------------------------------------------------
// MessageMigrate — core CLI fix strings → doctor --fix (w1-message-migrate-core)
// Named substring `MessageMigrate` for monopath filters. Co-located only; does
// not implement production. Forbidden start-onboard needle is built via concat
// so this pack never reintroduces the static rg gate needle in source text.
// ---------------------------------------------------------------------------

/// Contiguous start-onboard teach string forbidden by D07/D08/D36 for W1 doors.
/// Constructed via concat so file source never contains the gate needle.
const message_migrate_forbidden_start: []const u8 = "ryk" ++ " start";

fn messageMigrateForbiddenStartNeedle() []const u8 {
    return message_migrate_forbidden_start;
}

/// Full source of this file (prod + co-located tests) — gate polarity surface.
fn messageMigrateDoctorSource() []const u8 {
    return @embedFile("doctor.zig");
}

/// Production region only (everything before the first co-located test).
fn messageMigrateDoctorProdSource() []const u8 {
    return doctorFixProdSource();
}

/// Sibling plugin.zig (exclusive code_path for message migrate; tests live here).
fn messageMigratePluginSource() []const u8 {
    return @embedFile("plugin.zig");
}

/// Count non-overlapping occurrences (same algorithm as doctorFixCount).
fn messageMigrateCount(hay: []const u8, needle: []const u8) usize {
    return doctorFixCount(hay, needle);
}

test "MessageMigrate doctor production has zero start-onboard teach strings" {
    // Acceptance (1)+(3): user-facing fix hints in doctor.zig must not teach
    // start as required onboard. rg polarity: zero matches for the forbidden
    // needle in production region (gate greens only when empty).
    const prod = messageMigrateDoctorProdSource();
    const forbidden = messageMigrateForbiddenStartNeedle();
    try std.testing.expectEqual(@as(usize, 0), messageMigrateCount(prod, forbidden));
}

test "MessageMigrate doctor full source has zero start-onboard teach strings" {
    // Acceptance (2)+(3): co-located tests updated off start teach-strings; full
    // file (prod+tests) matches static gate polarity (empty match only).
    const src = messageMigrateDoctorSource();
    const forbidden = messageMigrateForbiddenStartNeedle();
    try std.testing.expectEqual(@as(usize, 0), messageMigrateCount(src, forbidden));
}

test "MessageMigrate plugin source has zero start-onboard teach strings" {
    // Acceptance (1)+(3): plugin.zig user-facing fix/help strings stop teaching
    // start onboard. Static gate also covers plugin.zig; tested from doctor
    // co-located pack (exclusive test_paths = doctor.zig only).
    const src = messageMigratePluginSource();
    const forbidden = messageMigrateForbiddenStartNeedle();
    try std.testing.expectEqual(@as(usize, 0), messageMigrateCount(src, forbidden));
}

test "MessageMigrate doctor production teaches doctor --fix repair door" {
    // Acceptance (1): fix hints → ryk doctor --fix. Production region must
    // contain the taught repair door (live_smoke: rg doctor --fix doctor.zig).
    const prod = messageMigrateDoctorProdSource();
    try std.testing.expect(std.mem.indexOf(u8, prod, "doctor --fix") != null);
    try std.testing.expect(std.mem.indexOf(u8, prod, "ryk doctor --fix") != null);

    // Pi note is the primary doctor-owned teach string (not host_status residual).
    const pi_note_marker = "Pi: bundled extension setup is managed by";
    const pi_idx = std.mem.indexOf(u8, prod, pi_note_marker) orelse {
        try std.testing.expect(false); // writePiNote must remain
        return;
    };
    // Window around Pi note must teach doctor --fix, not start onboard.
    const window_end = @min(prod.len, pi_idx + 200);
    const pi_window = prod[pi_idx..window_end];
    try std.testing.expect(std.mem.indexOf(u8, pi_window, "doctor --fix") != null);
    try std.testing.expect(std.mem.indexOf(u8, pi_window, "probe") != null);
    try std.testing.expect(std.mem.indexOf(u8, pi_window, "verify: ryk doctor") == null);
    try std.testing.expect(std.mem.indexOf(u8, pi_window, messageMigrateForbiddenStartNeedle()) == null);
}

test "MessageMigrate plugin fix strings teach doctor --fix with host plugin secondary only" {
    // Acceptance (1): plugin fix hints → ryk doctor --fix; host-specific
    // `ryk plugin install <host>` may remain as secondary only (not start).
    const src = messageMigratePluginSource();
    const forbidden = messageMigrateForbiddenStartNeedle();
    try std.testing.expectEqual(@as(usize, 0), messageMigrateCount(src, forbidden));

    // Repair door present in plugin user-facing surface.
    try std.testing.expect(std.mem.indexOf(u8, src, "doctor --fix") != null);
    try std.testing.expect(std.mem.indexOf(u8, src, "ryk doctor --fix") != null);

    // Every `→ Fix:` line that still mentions plugin install must also teach
    // doctor --fix on the same line (primary door; host plugin secondary).
    var rest = src;
    while (std.mem.indexOf(u8, rest, "→ Fix:")) |idx| {
        const line_start = rest[idx..];
        const line_end = std.mem.indexOfScalar(u8, line_start, '\n') orelse line_start.len;
        const line = line_start[0..line_end];
        if (std.mem.indexOf(u8, line, "plugin install") != null) {
            try std.testing.expect(std.mem.indexOf(u8, line, "doctor --fix") != null);
        }
        // No Fix line may teach start onboard.
        try std.testing.expect(std.mem.indexOf(u8, line, forbidden) == null);
        rest = line_start[line_end..];
    }

    // Primary flow help must not teach start as required onboard door.
    // After migrate: doctor --fix is the taught day-one/repair door.
    if (std.mem.indexOf(u8, src, "Primary flow:")) |pf| {
        const window_end = @min(src.len, pf + 160);
        const window = src[pf..window_end];
        try std.testing.expect(std.mem.indexOf(u8, window, forbidden) == null);
        try std.testing.expect(std.mem.indexOf(u8, window, "doctor --fix") != null);
    }

    // Pi note(s) in plugin surface follow the same door.
    var pi_rest = src;
    while (std.mem.indexOf(u8, pi_rest, "bundled extension setup is managed by")) |idx| {
        const window_end = @min(pi_rest.len, idx + 80);
        const window = pi_rest[idx..window_end];
        try std.testing.expect(std.mem.indexOf(u8, window, "doctor --fix") != null);
        try std.testing.expect(std.mem.indexOf(u8, window, forbidden) == null);
        pi_rest = pi_rest[idx + 1 ..];
    }
}

test "MessageMigrate rendered doctor host table teaches doctor --fix not start" {
    // Acceptance (1)+(2): runtime user-facing repair strings from doctor report
    // teach doctor --fix; no start-onboard needle in rendered output.
    var stdout_buf: [16384]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    const report = sandbox.backend.detect(.linux);
    var context = try testContext(std.testing.allocator, .{});
    defer context.deinit();

    try writeReport(std.testing.io, &stdout_writer, .linux, report, context, false);
    const written = stdout_writer.buffered();

    try std.testing.expect(std.mem.indexOf(u8, written, "Host integrations") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "ryk doctor --fix") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "Pi: bundled extension setup is managed by `ryk doctor --fix`") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, messageMigrateForbiddenStartNeedle()) == null);
    // Composition: never print "run <start-onboard>" as required next step.
    const run_forbidden: []const u8 = "run " ++ ("ryk" ++ " start");
    try std.testing.expect(std.mem.indexOf(u8, written, run_forbidden) == null);
}

test "MessageMigrate no new required-onboard references to start verb in exclusive files" {
    // Acceptance (2): no new references to start as required onboard in
    // doctor.zig + plugin.zig. Guards common teach patterns beyond bare needle.
    const forbidden = messageMigrateForbiddenStartNeedle();
    const doctor_src = messageMigrateDoctorSource();
    const plugin_src = messageMigratePluginSource();

    try std.testing.expectEqual(@as(usize, 0), messageMigrateCount(doctor_src, forbidden));
    try std.testing.expectEqual(@as(usize, 0), messageMigrateCount(plugin_src, forbidden));

    // Backtick-wrapped start command form used in Pi notes / help.
    const bt_start = "`" ++ "ryk" ++ " start`";
    try std.testing.expect(std.mem.indexOf(u8, doctor_src, bt_start) == null);
    try std.testing.expect(std.mem.indexOf(u8, plugin_src, bt_start) == null);

    // "or <forbidden>" / "re-run <forbidden>" fix-composition patterns.
    const or_forbidden: []const u8 = "or " ++ ("ryk" ++ " start");
    const rerun_forbidden: []const u8 = "re-run " ++ ("ryk" ++ " start");
    try std.testing.expect(std.mem.indexOf(u8, plugin_src, or_forbidden) == null);
    try std.testing.expect(std.mem.indexOf(u8, plugin_src, rerun_forbidden) == null);
    try std.testing.expect(std.mem.indexOf(u8, doctor_src, or_forbidden) == null);

    // Presence of the taught door in both exclusive code surfaces.
    try std.testing.expect(std.mem.indexOf(u8, messageMigrateDoctorProdSource(), "doctor --fix") != null);
    try std.testing.expect(std.mem.indexOf(u8, plugin_src, "doctor --fix") != null);
}

const TestContextOptions = struct {
    policy_present: bool = true,
    policy_valid: bool = true,
    daemon_binary_exists: bool = true,
    daemon_binary_executable: bool = true,
    daemon_binary_untrusted: bool = false,
    daemon_health: onboarding.DaemonHealthStatus = .compatible,
    daemon_detail: []const u8 = "running daemon answered with a compatible handshake.",
    hermes_fail_open: bool = true,
    hermes_installed: bool = false,
    /// When set, that host row is marked wired=broken (test-program bake).
    broken_evaluator_host: ?[]const u8 = null,
};

fn testContext(allocator: std.mem.Allocator, options: TestContextOptions) !IntegrationContext {
    const host_rows = try testHostRows(allocator);
    if (options.broken_evaluator_host) |host| {
        for (host_rows) |*row| {
            if (!std.mem.eql(u8, row.host, host)) continue;
            allocator.free(row.wired);
            row.wired = try allocator.dupe(u8, "broken");
            allocator.free(row.fail_stance);
            row.fail_stance = try allocator.dupe(u8, host_status.failStance(host, options.hermes_fail_open, "broken"));
            allocator.free(row.fix);
            row.fix = try host_status.formatFix(allocator, host, "broken", .{}, options.hermes_fail_open);
        }
    }
    return .{
        .allocator = allocator,
        .workspace_root = try allocator.dupe(u8, "."),
        .git_present = true,
        .policy_present = options.policy_present,
        .policy_valid = options.policy_valid,
        .policy_error = null,
        .agent_found = &.{},
        .mcp_manifest_count = 0,
        .mcp_manifest_invalid_count = 0,
        .ci_detected = false,
        .ci_provider = try allocator.dupe(u8, "none"),
        .shell_name = try allocator.dupe(u8, "zsh"),
        .audit_sessions_present = false,
        .redteam_fixtures_present = true,
        .daemon_binary_path = try allocator.dupe(u8, "/tmp/ryk-daemon"),
        .daemon_binary_exists = options.daemon_binary_exists,
        .daemon_binary_executable = options.daemon_binary_executable,
        .daemon_binary_untrusted = options.daemon_binary_untrusted,
        .daemon_socket_path = try allocator.dupe(u8, "/tmp/daemon.sock"),
        .daemon_socket_exists = false,
        .daemon_pid_path = try allocator.dupe(u8, "/tmp/daemon.pid"),
        .daemon_pid_exists = false,
        .daemon_health = options.daemon_health,
        .daemon_detail = try allocator.dupe(u8, options.daemon_detail),
        .host_rows = host_rows,
        .hermes_fail_open = options.hermes_fail_open,
        .hermes_installed = options.hermes_installed,
    };
}

fn testHostRows(allocator: std.mem.Allocator) ![]HostDoctorRow {
    const hosts = [_]struct { name: []const u8, gate: []const u8, stance: []const u8 }{
        .{ .name = "codex", .gate = "PreToolUse", .stance = "fail-closed shell" },
        .{ .name = "claude", .gate = "PreToolUse", .stance = "fail-closed shell" },
        .{ .name = "opencode", .gate = "tool.execute.before", .stance = "fail-closed shell" },
        .{ .name = "openclaw", .gate = "tool.before", .stance = "fail-closed shell" },
        .{ .name = "hermes", .gate = "pre_tool_call", .stance = "fail-closed" },
        .{ .name = "pi", .gate = "extension-managed (smoke not run)", .stance = "mode-dependent" },
        .{ .name = "grok", .gate = "PreToolUse", .stance = "fail-closed shell" },
    };
    var list: std.ArrayList(HostDoctorRow) = .empty;
    errdefer {
        for (list.items) |row| {
            allocator.free(row.host);
            allocator.free(row.wired);
            allocator.free(row.shell_gate);
            allocator.free(row.fail_stance);
            allocator.free(row.smoke_allow);
            allocator.free(row.smoke_deny);
            allocator.free(row.fix);
        }
        list.deinit(allocator);
    }
    // Match production collectHostDoctorRows: fix strings from host_status.formatFix only
    // (no hand-authored Pi/hermes strings that green-paint message migration).
    const smoke = host_status.HostSmokePair{};
    const hermes_fail_open = true;
    for (hosts) |h| {
        const wired = "—";
        // #368: same locals+errdefer ownership as production collectHostDoctorRows.
        const host_owned = try allocator.dupe(u8, h.name);
        errdefer allocator.free(host_owned);
        const wired_owned = try allocator.dupe(u8, wired);
        errdefer allocator.free(wired_owned);
        const shell_gate_owned = try allocator.dupe(u8, h.gate);
        errdefer allocator.free(shell_gate_owned);
        const fail_stance_owned = try allocator.dupe(u8, h.stance);
        errdefer allocator.free(fail_stance_owned);
        const smoke_allow_owned = try allocator.dupe(u8, "not-run");
        errdefer allocator.free(smoke_allow_owned);
        const smoke_deny_owned = try allocator.dupe(u8, "not-run");
        errdefer allocator.free(smoke_deny_owned);
        const fix = try host_status.formatFix(allocator, h.name, wired, smoke, hermes_fail_open);
        errdefer allocator.free(fix);
        try list.append(allocator, .{
            .host = host_owned,
            .wired = wired_owned,
            .shell_gate = shell_gate_owned,
            .fail_stance = fail_stance_owned,
            .smoke_allow = smoke_allow_owned,
            .smoke_deny = smoke_deny_owned,
            .fix = fix,
        });
    }
    return try list.toOwnedSlice(allocator);
}

test "lastSessionAuditDegraded detects audit_degraded in the pointed-at session" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(root);

    // No session artifacts at all -> not degraded (and no error).
    try std.testing.expect(!lastSessionAuditDegraded(io, allocator, root));

    try tmp.dir.createDirPath(io, ".ryk/sessions/sess-degraded");
    try tmp.dir.writeFile(io, .{ .sub_path = ".ryk/last", .data = "sess-degraded\n" });
    try tmp.dir.writeFile(io, .{
        .sub_path = ".ryk/sessions/sess-degraded/events.jsonl",
        .data = "{\"type\":\"session_start\"}\n{\"type\":\"audit_degraded\",\"decision\":{\"result\":\"observe\",\"reason\":\"shim audit open denied\"}}\n",
    });
    try std.testing.expect(lastSessionAuditDegraded(io, allocator, root));

    // A clean session rewrites the pointer -> not degraded.
    try tmp.dir.createDirPath(io, ".ryk/sessions/sess-clean");
    try tmp.dir.writeFile(io, .{ .sub_path = ".ryk/last", .data = "sess-clean\n" });
    try tmp.dir.writeFile(io, .{
        .sub_path = ".ryk/sessions/sess-clean/events.jsonl",
        .data = "{\"type\":\"session_start\"}\n{\"type\":\"command_allowed\"}\n",
    });
    try std.testing.expect(!lastSessionAuditDegraded(io, allocator, root));
}

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");

pub const args = @import("args.zig");
pub const gpa = @import("gpa.zig");
pub const brand = @import("brand.zig");
pub const exit_codes = @import("exit_codes.zig");
pub const help = @import("help.zig");
pub const run_command = @import("run.zig");
pub const run_os_sandbox = @import("run_os_sandbox.zig");
pub const env_schema_command = @import("env_schema.zig");
pub const host_launch = @import("host_launch.zig");
pub const init = @import("init.zig");
pub const doctor = @import("doctor.zig");
pub const policy = @import("policy.zig");
pub const credentials_command = @import("credentials.zig");
pub const replay = @import("replay.zig");
pub const scan_command = @import("scan.zig");
pub const diff = @import("diff.zig");
pub const apply = @import("apply.zig");
pub const discard = @import("discard.zig");
pub const staged_mutation = @import("staged_mutation.zig");
pub const mcp = @import("mcp.zig");
pub const tools = @import("tools.zig");
pub const redteam = @import("redteam.zig");
pub const completions = @import("completions.zig");
pub const shim = @import("shim.zig");
pub const version_command = @import("version.zig");
pub const plugin = @import("plugin.zig");
pub const host_status = @import("host_status.zig");
pub const pi_install = @import("pi_install.zig");
pub const grok_install = @import("grok_install.zig");
pub const plugin_install = @import("plugin_install.zig");
pub const setup = @import("setup.zig");
pub const start = @import("start.zig");
pub const unattended = @import("unattended.zig");
pub const onboarding = @import("onboarding.zig");
pub const ensure = @import("ensure.zig");
pub const quickstart = @import("quickstart.zig");
pub const decide = @import("decide.zig");
pub const evaluate = @import("evaluate.zig");
pub const hook = @import("hook.zig");
pub const dashboard_command = @import("dashboard.zig");
pub const report = @import("report.zig");
pub const ci = @import("ci.zig");
pub const disable = @import("disable.zig");
pub const uninstall = @import("uninstall.zig");
pub const update = @import("update.zig");
pub const feedback = @import("feedback.zig");
pub const interactive = @import("interactive.zig");
pub const child_process = @import("child_process.zig");
pub const style = @import("style.zig");
pub const tui = @import("../tui/mod.zig");
pub const daemon = @import("daemon.zig");
pub const daemon_uds = @import("daemon_uds.zig");
pub const shutdown = @import("shutdown.zig");
pub const shell_eval = @import("shell_eval.zig");
pub const shell_test = @import("shell_test.zig");
pub const shell_explain = @import("shell_explain.zig");
pub const allow_once = @import("allow_once.zig");
pub const allowlist_cmd = @import("allowlist_cmd.zig");
pub const rust_legacy_stub = @import("rust_legacy_stub.zig");
pub const rust_visibility = @import("rust_visibility.zig");
pub const feed_writer = @import("feed_writer.zig");
pub const agent_hook = @import("agent_hook.zig");
pub const daemon_contracts = @import("daemon_contracts.zig");
pub const packs = @import("packs.zig");
pub const pack_state = @import("pack_state.zig");
pub const readiness = @import("readiness.zig");
pub const history = @import("history.zig");
pub const suggestions = @import("suggestions.zig");
pub const danger_confirmation = @import("danger_confirmation.zig");
pub const fm_steward_client = @import("fm_steward_client.zig");
pub const codex_mcp_sandbox = @import("codex_mcp_sandbox.zig");
pub const host_mcp_sandbox = @import("host_mcp_sandbox.zig");
pub const telemetry = @import("../telemetry.zig");

test {
    _ = gpa;
    _ = brand;
    _ = staged_mutation;
    // Ensure the child_process module (and its tests) are pulled into the test binary.
    _ = child_process;
    // Mac FM steward classify client (parse + fail-open subprocess).
    _ = fm_steward_client;
    // Pull style tests (TDD for color/TTY/NO_COLOR handling).
    _ = style;
    _ = onboarding;
    // Monopath pull for co-located EnsureCore / Ensure* tests (D73).
    _ = ensure;
    _ = @import("policy_migrate.zig");
    _ = host_status;
    _ = pi_install;
    _ = grok_install;
    _ = plugin_install;
    _ = plugin;
    _ = @import("openclaw_status.zig");
    _ = start;
    _ = unattended;
    _ = init; // AINA P3 refreshManagedDiscovery suite (was transitively linked via start→init)
    _ = setup;
    _ = quickstart;
    _ = help;
    _ = policy;
    _ = disable;
    _ = uninstall;
    _ = update;
    _ = feedback;
    _ = @import("spinner.zig");
    // Pull daemon UDS/IPC/trust/error tests into the test binary.
    _ = daemon;
    _ = daemon_uds;
    _ = daemon.trust;
    _ = daemon.errors;
    _ = shutdown;
    _ = shell_eval;
    _ = scan_command;
    // Pull hook.zig tests (daemon evaluate → HookResponse, strict refuse, redaction).
    _ = hook;
    // Grok deny reason smart-shrink (pure formatter; also imported by hook.zig).
    _ = @import("grok_deny_reason.zig");
    _ = shell_test;
    _ = shell_explain;
    _ = allow_once;
    _ = allowlist_cmd;
    _ = @import("explain_render.zig");
    _ = rust_legacy_stub;
    _ = rust_visibility;
    _ = evaluate;
    _ = decide;
    // Door A deadlock transcript replay (decide + hook surfaces).
    _ = @import("deadlock_replay.zig");
    _ = @import("deadlock_check.zig");
    _ = agent_hook;
    _ = daemon_contracts;
    _ = packs;
    _ = pack_state;
    _ = @import("packs_tui.zig");
    _ = readiness;
    _ = doctor;
    _ = @import("doctor_tui.zig");
    _ = @import("doctor_mcp.zig");
    _ = history;
    _ = danger_confirmation;
    _ = run_command;
    _ = shim; // PATH-shim audit mode session attestation (F36)
    _ = run_os_sandbox;
    _ = codex_mcp_sandbox;
    _ = host_mcp_sandbox;
    _ = mcp;
    _ = env_schema_command;
    // Surfaces touched by production-readiness hardening (M1–M4).
    _ = completions;
    _ = dashboard_command;
    _ = feed_writer;
    _ = host_launch;
    // M-4: deny classifier / human DENY badge for non-command_denied events.
    _ = replay;
}

pub const version = build_options.version;

/// Suggests a close command name for typos / prefixes. Returns null for no good match.
fn suggestCommand(unknown: []const u8) ?[]const u8 {
    var names: [help.commands.len][]const u8 = undefined;
    for (help.commands, 0..) |command, index| names[index] = command.name;
    return suggestions.closest(unknown, &names);
}

/// Commands that render their own branded header internally and so must NOT
/// receive the shared entry banner (would double-print).
/// `scan` keeps the progress phase banner-free (spinner only); durable brand
/// lives on the result scorecard / alt-screen TUI header.
const self_banner_commands = [_][]const u8{ "version", "--version", "help", "run", "start", "agents", "scan" };

/// Commands whose output is always machine/raw (JSON, generated scripts, export
/// lines, long-running servers) — never receive the human brand banner.
const always_machine_commands = [_][]const u8{
    "evaluate", "hook", "shim", "completions", "env", "dashboard", "telemetry", "--print-install-env",
    // Zig-native shell tools (formerly daemon-proxied): keep machine/banner-free.
    // `explain` is human pretty by default (DCG-class colors); machine only via
    // `--format json` (isMachineArgv). Own header is `RYK EXPLAIN` (no brand banner).
    "test",
};

fn isAlwaysMachineCommand(command: []const u8) bool {
    for (always_machine_commands) |candidate| if (std.mem.eql(u8, command, candidate)) return true;
    return false;
}

fn isRawGeneratedInvocation(command: []const u8, argv: []const []const u8) bool {
    if (std.mem.eql(u8, command, "diff")) return true;
    if (std.mem.eql(u8, command, "ci")) {
        var index: usize = 1;
        while (index + 1 < argv.len) : (index += 1) {
            if (!std.mem.eql(u8, argv[index], "--format")) continue;
            return std.mem.eql(u8, argv[index + 1], "markdown") or std.mem.eql(u8, argv[index + 1], "json");
        }
        return false;
    }
    if (!std.mem.eql(u8, command, "mcp") or argv.len <= 1) return false;
    if (std.mem.eql(u8, argv[1], "proxy") or std.mem.eql(u8, argv[1], "trust")) return true;
    return std.mem.eql(u8, argv[1], "manifest") and argv.len > 2 and std.mem.eql(u8, argv[2], "generate");
}

fn isRawPassthroughInvocation(command: []const u8, argv: []const []const u8) bool {
    // Daemon-proxied / local-mutating commands preserve byte identity for machine/help output.
    if (isDaemonProxyCommand(command) or isDaemonLocalMutatingTopLevel(command)) return true;
    if (std.mem.eql(u8, command, "packs")) {
        for (argv[1..]) |arg| {
            if (std.mem.eql(u8, arg, "--robot") or std.mem.eql(u8, arg, "--expand") or
                std.mem.eql(u8, arg, "--verbose") or std.mem.eql(u8, arg, "-v") or
                std.mem.eql(u8, arg, "--format") or std.mem.eql(u8, arg, "-f") or
                std.mem.startsWith(u8, arg, "--format=") or std.mem.eql(u8, arg, "--max-patterns") or
                std.mem.startsWith(u8, arg, "--max-patterns=")) return true;
        }
    }
    if (std.mem.eql(u8, command, "history") and argv.len > 1) {
        if (!std.mem.eql(u8, argv[1], "stats")) return true;
        for (argv[2..]) |arg| {
            if (std.mem.eql(u8, arg, "--json") or std.mem.eql(u8, arg, "--robot") or
                std.mem.eql(u8, arg, "--format") or std.mem.startsWith(u8, arg, "--format=")) return true;
        }
    }
    return false;
}

fn isMachineArgv(argv: []const []const u8) bool {
    for (argv, 0..) |arg, index| {
        if (std.mem.eql(u8, arg, "--json") or std.mem.eql(u8, arg, "--stdin")) return true;
        if (std.mem.eql(u8, arg, "--format") and index + 1 < argv.len and std.mem.eql(u8, argv[index + 1], "json")) return true;
    }
    return false;
}

/// True when the compact brand banner should open this invocation. The banner
/// is a presentation-only header; it never appears on `--json`/machine/raw paths
/// (byte-identity invariant) nor on `--help`/`help <cmd>` reference output.
fn shouldShowBanner(command: []const u8, argv: []const []const u8) bool {
    // Self-banner commands render their own header (version key-value grid, top
    // help redesign, run session banner). Host launch aliases rewrite into run.
    for (self_banner_commands) |s| {
        if (std.mem.eql(u8, command, s)) return false;
    }
    // `ryk explain` owns its DCG-style header; never double-print brand banner.
    if (std.mem.eql(u8, command, "explain")) return false;
    if (host_launch.isHostLaunchAlias(command)) return false;
    // `decide` is a frozen machine API by default. Only its explicit human
    // output mode participates in shared presentation, even though JSON/stdin
    // are still the input transports.
    if (std.mem.eql(u8, command, "decide")) {
        for (argv[1..]) |arg| {
            if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) return false;
        }
        for (argv[1..]) |arg| if (std.mem.eql(u8, arg, "--human")) return true;
        return false;
    }
    // Reports are generated/export surfaces and never receive a banner, but
    // human error remediation remains presentation-capable. JSON is still
    // classified as machine output by isMachineArgv.
    if (std.mem.eql(u8, command, "report")) return false;
    // `history --live` is intercepted by the Zig CLI before daemon passthrough.
    // Treat its non-TTY rejection as a human surface so it matches `replay --tui`,
    // while keeping machine conflicts/banner-free JSON byte contracts raw.
    if (std.mem.eql(u8, command, "history")) {
        var live = false;
        var i: usize = 1;
        while (i < argv.len) : (i += 1) {
            const a = argv[i];
            if (std.mem.eql(u8, a, "--help") or std.mem.eql(u8, a, "-h")) return false;
            if (std.mem.eql(u8, a, "--json") or std.mem.eql(u8, a, "--robot") or
                std.mem.eql(u8, a, "--stdin")) return false;
            if (std.mem.eql(u8, a, "--format") and i + 1 < argv.len and std.mem.eql(u8, argv[i + 1], "json")) return false;
            if (std.mem.eql(u8, a, "--live")) live = true;
        }
        if (live) return true;
    }
    if (isRawGeneratedInvocation(command, argv) or isRawPassthroughInvocation(command, argv)) return false;
    // Always-machine / raw / server commands.
    if (isAlwaysMachineCommand(command)) return false;
    // `help <cmd>` is command-specific reference help (no banner); bare `help`
    // is top help and renders its own banner inside help.write.
    if (std.mem.eql(u8, command, "help")) return false;
    // Scan subcommand args (argv[1..]) for machine/help tokens.
    var i: usize = 1;
    while (i < argv.len) : (i += 1) {
        const a = argv[i];
        if (std.mem.eql(u8, a, "--json") or std.mem.eql(u8, a, "--stdin")) return false;
        if (std.mem.eql(u8, a, "--help") or std.mem.eql(u8, a, "-h")) return false;
        if (std.mem.eql(u8, a, "--format") and i + 1 < argv.len and std.mem.eql(u8, argv[i + 1], "json")) return false;
    }
    // Unknown commands get no banner (error path); the brand header belongs only
    // to recognised human commands.
    return help.findCommand(command) != null;
}

fn writeInvocationPresentation(io: std.Io, command: []const u8, argv: []const []const u8, stdout: anytype) !void {
    if (shouldShowBanner(command, argv)) try tui.render.banner(io, stdout, version, null);
}

pub fn run(io: std.Io, environ_map: *const std.process.Environ.Map, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    return runWithCwd(io, environ_map, std.Io.Dir.cwd(), argv, stdout, stderr);
}

const GlobalArgs = struct {
    /// Argv with global `--no-rich` tokens removed (not after `--`).
    argv: []const []const u8,
    no_rich: bool,
    /// True when `argv` is heap-owned and must be freed by the caller.
    owned: bool = false,
};

/// Strip global `--no-rich` before or after the command, but never after `--`
/// (child argv / opaque payloads must keep a literal `--no-rich`).
fn parseGlobalArgs(allocator: std.mem.Allocator, argv: []const []const u8) !GlobalArgs {
    var no_rich = false;
    var needs_filter = false;
    var after_separator = false;
    for (argv) |arg| {
        if (!after_separator and std.mem.eql(u8, arg, "--")) {
            after_separator = true;
            continue;
        }
        if (!after_separator and std.mem.eql(u8, arg, "--no-rich")) {
            no_rich = true;
            needs_filter = true;
        }
    }
    if (!needs_filter) return .{ .argv = argv, .no_rich = no_rich, .owned = false };

    var list: std.ArrayList([]const u8) = .empty;
    errdefer list.deinit(allocator);
    after_separator = false;
    for (argv) |arg| {
        if (!after_separator and std.mem.eql(u8, arg, "--")) {
            after_separator = true;
            try list.append(allocator, arg);
            continue;
        }
        if (!after_separator and std.mem.eql(u8, arg, "--no-rich")) continue;
        try list.append(allocator, arg);
    }
    return .{ .argv = try list.toOwnedSlice(allocator), .no_rich = no_rich, .owned = true };
}

pub fn runWithCwd(io: std.Io, environ_map: *const std.process.Environ.Map, cwd: std.Io.Dir, argv_input: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    return runWithCwdUsing(realDaemonExecuteCli, packs.command, history.command, mcp.command, io, environ_map, cwd, argv_input, stdout, stderr);
}

fn runWithCwdUsing(
    comptime daemon_execute: anytype,
    comptime packs_command: anytype,
    comptime history_command: anytype,
    comptime mcp_command: anytype,
    io: std.Io,
    environ_map: *const std.process.Environ.Map,
    cwd: std.Io.Dir,
    argv_input: []const []const u8,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    _ = daemon_execute;
    _ = packs_command;
    _ = history_command;
    const allocator = std.heap.smp_allocator;
    const global_args = try parseGlobalArgs(allocator, argv_input);
    defer if (global_args.owned) allocator.free(global_args.argv);
    const argv = global_args.argv;
    // Named `ryk hook` never uses the human banner/theme path. Skip that setup
    // so each host event process does less work. Bare `ryk` stays on the #159
    // path below — do not call agent_hook.command here (stdin is consumed once).
    if (argv.len > 0 and std.mem.eql(u8, argv[0], "hook")) {
        return hook.command(io, argv[1..], stdout, stderr);
    }
    const no_rich_env = tui.output_policy.envDisablesRich(
        environ_map.get("RYK_NO_RICH"),
    );
    const machine_output = if (argv.len == 0) false else !shouldShowBanner(argv[0], argv) and
        (isMachineArgv(argv) or isAlwaysMachineCommand(argv[0]) or isRawGeneratedInvocation(argv[0], argv));
    const output = tui.output_policy.resolve(no_rich_env, global_args.no_rich, machine_output);
    tui.theme.setRichEnabled(output.rich);
    style.setRichEnabled(output.rich);
    defer {
        tui.theme.setRichEnabled(true);
        style.setRichEnabled(null);
    }
    // Fallback / safety-net color decision prime for direct and library callers.
    // The true one-time early prime now lives in main() (real CLI startup path).
    // This call remains so that code paths that enter through runWithCwd directly
    // (tests, library consumers, or future embedding) still get a cached decision
    // before any warm output. If the cache is already populated by main(), this
    // is a fast O(1) cache hit with no side effects.
    _ = style.useColor(io, stdout);

    if (argv.len == 0) {
        if (agent_hook.shouldEnter(io)) {
            // Non-TTY hook entry: empty/whitespace/malformed stdin fail closed
            // inside agent_hook.command (deny JSON + exit 2). Do not map any
            // pre-eval miss to help + exit 0 — hosts treat that as allow.
            return agent_hook.command(io, stdout, stderr);
        }
        try help.write(io, stdout);
        return exit_codes.success;
    }
    if (std.mem.eql(u8, argv[0], "--help") or std.mem.eql(u8, argv[0], "-h")) {
        try help.write(io, stdout);
        return exit_codes.success;
    }

    const command = argv[0];
    // Compact brand header at the entry of every HUMAN command (Phase 2 brand
    // cohesion). Suppressed for self-banner commands (version/help/run render
    // their own header), always-machine/raw commands, --json/--stdin/--format
    // json machine paths, --help reference output, and unknown commands.
    try writeInvocationPresentation(io, command, argv, stdout);
    if (std.mem.eql(u8, command, "help")) {
        if (argv.len == 1) {
            try help.write(io, stdout);
            return exit_codes.success;
        }
        if (argv.len > 2) {
            try stderr.writeAll("ryk help: expected at most one command.\n");
            return exit_codes.usage;
        }
        if (!try help.writeCommand(io, stdout, argv[1])) {
            try stderr.writeAll("ryk help: unknown command '");
            try tui.terminal_text.write(stderr, argv[1], .single_line);
            if (suggestCommand(argv[1])) |suggestion| {
                try stderr.print("'. Did you mean '{s}'?\nRun 'ryk help {s}' for usage.\n", .{ suggestion, suggestion });
            } else {
                try stderr.writeAll("'.\nRun 'ryk help' to see all commands.\n");
            }
            return exit_codes.usage;
        }
        return exit_codes.success;
    }

    if (std.mem.eql(u8, command, "version") or std.mem.eql(u8, command, "--version")) {
        if (argv.len > 2) {
            try stderr.writeAll("ryk version: expected at most one argument. Run 'ryk help version' for usage.\n");
            return exit_codes.usage;
        }
        if (argv.len == 2) {
            if (std.mem.eql(u8, argv[1], "--help") or std.mem.eql(u8, argv[1], "-h")) {
                _ = try help.writeCommand(io, stdout, "version");
                return exit_codes.success;
            }
            if (std.mem.eql(u8, argv[1], "--json")) {
                try version_command.writeJsonWithDaemon(std.heap.smp_allocator, stdout);
                return exit_codes.success;
            }
            try stderr.writeAll("ryk version: unsupported argument. Run 'ryk help version' for usage.\n");
            return exit_codes.usage;
        }
        // Human path: compact brand banner + key-value grid (Phase 2).
        try version_command.writeHumanBanner(std.heap.smp_allocator, io, stdout);
        return exit_codes.success;
    }

    if (std.mem.eql(u8, command, "telemetry")) {
        return telemetry.command(io, environ_map, allocator, argv[1..], stdout, stderr);
    }

    // Slice 1 honesty: unfinished / hide-list verbs fail short (usage), not a daemon essay.
    // Live P0: allow-once, packs, permanent allowlist writers (Zig store; no daemon).
    // s-once-cli: live allow-once redeem/list/clear/revoke.
    if (std.mem.eql(u8, command, "allow-once")) {
        return allow_once.command(io, argv[1..], stdout, stderr);
    }

    // Slice 4 / s-packs: live packs CLI (oracle registry + pack_config; no daemon).
    if (std.mem.eql(u8, command, "packs")) {
        return packs.command(io, argv[1..], stdout, stderr);
    }

    // Slice 2 / s-allowlist-cli: permanent pack-exception allowlist (TOML store; no daemon).
    if (std.mem.eql(u8, command, "allowlist")) {
        return allowlist_cmd.command(io, argv[1..], stdout, stderr);
    }
    if (std.mem.eql(u8, command, "allow")) {
        return allowlist_cmd.commandAllow(io, argv[1..], stdout, stderr);
    }
    if (std.mem.eql(u8, command, "unallow")) {
        return allowlist_cmd.commandUnallow(io, argv[1..], stdout, stderr);
    }

    // Slice 1 honesty: hide-list verbs fail short (usage), not a daemon essay.
    if (std.mem.eql(u8, command, "history")) {
        return rust_legacy_stub.unavailable("history", stderr);
    }

    // Remaining hide-list local mutators (config/rebase-recover).
    if (isDaemonLocalMutatingInvocation(command, argv[1..])) {
        return rust_legacy_stub.unavailable(command, stderr);
    }
    // Former ExecuteCli proxies (simulate/classify/…) — unavailable product verbs.
    // `scan` is Zig-native (session forensics); not routed here.
    if (isDaemonProxyCommand(command)) {
        return rust_legacy_stub.unavailable(command, stderr);
    }

    if (std.mem.eql(u8, command, "test")) return shell_test.command(io, argv[1..], stdout, stderr);
    if (std.mem.eql(u8, command, "explain")) return shell_explain.command(io, argv[1..], stdout, stderr);

    // Highest-value DX helper for installers, Homebrew post-install hooks, npm wrapper,
    // power users, and immediate shell activation. Now layout-aware (selfExePath) and
    // platform-correct. `ryk env` is the discoverable alias; the flag is kept for
    // backward compat with any scripts that invoke it directly.
    if (std.mem.eql(u8, command, "--print-install-env")) {
        try writeInstallEnv(io, stdout);
        return exit_codes.success;
    }
    if (std.mem.eql(u8, command, "env")) {
        if (argv.len > 1) return env_schema_command.command(io, argv[1..], stdout, stderr);
        try writeInstallEnv(io, stdout);
        return exit_codes.success;
    }

    if (std.mem.eql(u8, command, "run")) {
        return run_command.commandWithEnv(io, environ_map, argv[1..], stdout, stderr);
    }
    if (std.mem.eql(u8, command, "start")) return start.command(io, cwd, argv[1..], stdout, stderr);
    if (std.mem.eql(u8, command, "agents")) return unattended.command(io, cwd, argv[1..], stdout, stderr);
    if (std.mem.eql(u8, command, "unattended")) {
        try stderr.writeAll("ryk unattended was removed; use `ryk agents setup` or `ryk agents health`.\n");
        return exit_codes.usage;
    }
    // Hard-remove public onboarding peers: single door is `ryk start`.
    if (std.mem.eql(u8, command, "quickstart") or std.mem.eql(u8, command, "setup")) {
        try help.writeRemovedOnboardingPeer(stderr, command);
        return exit_codes.usage;
    }
    if (std.mem.eql(u8, command, "init")) return init.command(io, cwd, argv[1..], stdout, stderr);
    // Hard-removed: thin glance duplicated doctor and misled with legacy daemon framing.
    if (std.mem.eql(u8, command, "status")) {
        try help.writeRemovedStatus(stderr);
        return exit_codes.usage;
    }
    if (std.mem.eql(u8, command, "doctor")) return doctor.command(io, argv[1..], stdout, stderr);
    if (std.mem.eql(u8, command, "policy")) return policy.command(io, argv[1..], stdout, stderr);
    if (std.mem.eql(u8, command, "credentials")) return credentials_command.command(io, argv[1..], stdout, stderr);
    if (std.mem.eql(u8, command, "replay")) return replay.command(io, argv[1..], stdout, stderr);
    if (std.mem.eql(u8, command, "scan")) return scan_command.command(io, argv[1..], stdout, stderr);
    if (std.mem.eql(u8, command, "diff")) return diff.command(io, argv[1..], stdout, stderr);
    if (std.mem.eql(u8, command, "apply")) return apply.command(io, argv[1..], stdout, stderr);
    if (std.mem.eql(u8, command, "discard")) return discard.command(io, argv[1..], stdout, stderr);
    if (std.mem.eql(u8, command, "mcp")) return mcp_command(io, argv[1..], stdout, stderr);
    if (std.mem.eql(u8, command, "tools")) return tools.command(io, argv[1..], stdout, stderr);
    if (std.mem.eql(u8, command, "redteam")) return redteam.command(io, argv[1..], stdout, stderr);
    if (std.mem.eql(u8, command, "completions")) return completions.command(io, argv[1..], stdout, stderr);
    if (std.mem.eql(u8, command, "shim")) return shim.command(io, environ_map, argv[1..], stdout, stderr);
    if (std.mem.eql(u8, command, "plugin")) return plugin.command(io, argv[1..], stdout, stderr);
    if (std.mem.eql(u8, command, "decide")) return decide.command(io, argv[1..], stdout, stderr);
    if (std.mem.eql(u8, command, "evaluate")) return evaluate.command(io, argv[1..], stdout, stderr);
    if (std.mem.eql(u8, command, "hook")) return hook.command(io, argv[1..], stdout, stderr);
    if (std.mem.eql(u8, command, "dashboard")) return dashboard_command.command(io, argv[1..], stdout, stderr);
    if (std.mem.eql(u8, command, "report")) return report.command(io, argv[1..], stdout, stderr);
    if (std.mem.eql(u8, command, "ci")) return ci.command(io, argv[1..], stdout, stderr);
    if (std.mem.eql(u8, command, "stop")) return disable.commandAs(io, argv[1..], stdout, stderr, "stop");
    if (std.mem.eql(u8, command, "disable")) return disable.commandAs(io, argv[1..], stdout, stderr, "disable");
    if (std.mem.eql(u8, command, "uninstall")) return uninstall.command(io, argv[1..], stdout, stderr);
    if (std.mem.eql(u8, command, "update")) return update.command(io, argv[1..], stdout, stderr);
    if (std.mem.eql(u8, command, "feedback")) return feedback.command(io, environ_map, argv[1..], stdout, stderr);
    if (std.mem.eql(u8, command, "shutdown")) return shutdown.command(io, argv[1..], stdout, stderr);

    // Host launch aliases after real ryk commands (ryk wins on name collision).
    if (try host_launch.tryDispatch(
        allocator,
        command,
        argv[1..],
        run_command.commandWithEnv,
        io,
        environ_map,
        stdout,
        stderr,
    )) |code| {
        return code;
    }

    // Warm "did you mean?" suggestions for unknown commands (foundation UX).
    try stderr.writeAll("ryk: unknown command '");
    try tui.terminal_text.write(stderr, command, .single_line);
    try stderr.writeAll("'.");
    if (looksLikeShellCommand(command, argv[1..])) {
        try stderr.writeAll("\nThat looks like a shell command. Try:\n");
        try stderr.writeAll("  ryk explain \"");
        try tui.terminal_text.write(stderr, command, .single_line);
        for (argv[1..]) |arg| {
            try stderr.writeAll(" ");
            try tui.terminal_text.write(stderr, arg, .single_line);
        }
        try stderr.writeAll("\"\n");
    } else if (std.mem.eql(u8, command, "demo")) {
        try stderr.writeAll("\n'demo' was removed. Use:\n  ryk explain \"rm -rf /\"\n");
    } else if (suggestCommand(command)) |suggestion| {
        try stderr.print(" Did you mean '{s}'?\n", .{suggestion});
    } else {
        try stderr.writeAll("\n");
    }
    try stderr.writeAll("Run 'ryk help' for usage.\n");
    return exit_codes.usage;
}

/// True when the unknown top-level token (+ trailing argv) looks like a shell line,
/// not a misspelled ryk subcommand.
fn looksLikeShellCommand(command: []const u8, rest: []const []const u8) bool {
    if (std.mem.indexOfScalar(u8, command, ' ') != null) return true;
    if (std.mem.indexOfScalar(u8, command, '/') != null) return true;
    if (rest.len > 0) {
        // `ryk rm -rf /` style
        const shellish = [_][]const u8{ "rm", "git", "dd", "mkfs", "sudo", "docker", "kubectl", "curl", "chmod", "chown" };
        for (shellish) |s| {
            if (std.mem.eql(u8, command, s)) return true;
        }
    }
    return false;
}

fn proxyVersionCommand(comptime execute_cli: anytype, io: std.Io, stdout: anytype, stderr: anytype) !u8 {
    return execute_cli(io, &.{"version"}, stdout, stderr) catch |err| {
        try stderr.print("ryk version: {s}: {s}\n", .{ daemonErrorLabel(err), @errorName(err) });
        return exit_codes.general;
    };
}

/// Top-level commands that previously proxied through the Rust daemon via ExecuteCli.
/// `test` / `explain` are Zig-native; remaining entries stub until ported or dropped.
fn isDaemonProxyCommand(command: []const u8) bool {
    // allowlist is live Zig (s-allowlist-cli); no longer a daemon proxy surface.
    // `scan` is Zig-native session forensics (not the old Rust file/pre-commit scan).
    return std.mem.eql(u8, command, "precommit") or
        std.mem.eql(u8, command, "classify") or
        std.mem.eql(u8, command, "suggest-allowlist") or
        std.mem.eql(u8, command, "simulate");
}

/// Commands that always mutate policy/config: never sent over ExecuteCli UDS.
/// Live Zig mutators (allow/unallow/allow-once) remain classified here for machine-mode
/// detection only; dispatch routes them to Zig CLI before honesty stubs.
fn isDaemonLocalMutatingTopLevel(command: []const u8) bool {
    return std.mem.eql(u8, command, "allow") or
        std.mem.eql(u8, command, "unallow") or
        std.mem.eql(u8, command, "allow-once") or
        std.mem.eql(u8, command, "rebase-recover") or
        std.mem.eql(u8, command, "config");
}

/// True when this invocation must spawn `ryk-daemon` locally (no UDS ExecuteCli).
fn isDaemonLocalMutatingInvocation(command: []const u8, command_args: []const []const u8) bool {
    // Top-level mutators always go local (including `--help`).
    if (isDaemonLocalMutatingTopLevel(command)) return true;
    if (std.mem.eql(u8, command, "suggest-allowlist")) {
        for (command_args) |arg| {
            if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) return false;
            if (std.mem.eql(u8, arg, "--apply") or std.mem.startsWith(u8, arg, "--apply=")) return true;
            if (std.mem.eql(u8, arg, "--undo") or std.mem.startsWith(u8, arg, "--undo=")) return true;
        }
        return false;
    }
    return false;
}

fn proxyDaemonCommand(comptime execute_cli: anytype, command: []const u8, command_args: []const []const u8, io: std.Io, stdout: anytype, stderr: anytype) !u8 {
    const allocator = std.heap.smp_allocator;
    const daemon_argv = try allocator.alloc([]const u8, command_args.len + 1);
    defer allocator.free(daemon_argv);

    daemon_argv[0] = command;
    if (command_args.len > 0) @memcpy(daemon_argv[1..], command_args);

    return execute_cli(io, daemon_argv, stdout, stderr) catch |err| {
        try stderr.print("ryk {s}: {s}: {s}\n", .{ command, daemonErrorLabel(err), @errorName(err) });
        return exit_codes.general;
    };
}

fn runLocalDaemonCommand(command: []const u8, command_args: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    const allocator = std.heap.smp_allocator;
    const daemon_argv = try allocator.alloc([]const u8, command_args.len + 1);
    defer allocator.free(daemon_argv);

    daemon_argv[0] = command;
    if (command_args.len > 0) @memcpy(daemon_argv[1..], command_args);

    return daemon.runLocalCli(allocator, daemon_argv, stdout, stderr) catch |err| {
        try stderr.print("ryk {s}: {s}: {s}\n", .{ command, daemonErrorLabel(err), @errorName(err) });
        return exit_codes.general;
    };
}

// Keep legacy names as aliases so existing tests and call sites compile.
const isPhase1ProxyCommand = isDaemonProxyCommand;
const proxyPhase1Command = proxyDaemonCommand;

fn daemonErrorLabel(err: anyerror) []const u8 {
    return daemon.errors.proxyCategoryLabel(err);
}

fn realDaemonExecuteCli(_: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) daemon.DaemonError!u8 {
    var parsed = try daemon.executeCli(std.heap.smp_allocator, argv);
    defer parsed.deinit();

    if (daemon.responseStatus(parsed.value.result) == .error_status) {
        if (daemon.responseErrorMessage(parsed.value.result)) |message| {
            stderr.print("ryk daemon: {s}\n", .{message}) catch return error.SocketWriteFailed;
        } else {
            stderr.writeAll("ryk daemon: protocol error\n") catch return error.SocketWriteFailed;
        }
        return exit_codes.general;
    }

    const execution = try daemon.parseCliExecution(parsed.value.result);
    stdout.writeAll(execution.stdout) catch return error.SocketWriteFailed;
    if (execution.stderr.len > 0) stderr.writeAll(execution.stderr) catch return error.SocketWriteFailed;
    return execution.exit_code;
}

pub fn executeDaemonCli(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    return realDaemonExecuteCli(io, argv, stdout, stderr);
}

fn testRun(argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    var env_map = try std.process.Environ.createMap(std.process.Environ.empty, std.testing.allocator);
    defer env_map.deinit();
    return run(std.testing.io, &env_map, argv, stdout, stderr);
}

fn testRunWithCwd(cwd: std.Io.Dir, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    var env_map = try std.process.Environ.createMap(std.process.Environ.empty, std.testing.allocator);
    defer env_map.deinit();
    return runWithCwd(std.testing.io, &env_map, cwd, argv, stdout, stderr);
}

test "bare ryk empty stdin on non-TTY hook entry is deny JSON + exit 2, not help" {
    // Locks src/cli/mod.zig argv.len==0 → agent_hook.command. Restoring
    // NotAgentHookInput → help + exit 0 fails here whenever the test runner
    // stdin is a pipe (CI / `zig test`). TTY runners still get help + 0.
    var stdout_buf: [8192]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const enter_hook = agent_hook.shouldEnter(std.testing.io);
    const code = try testRun(&.{}, &stdout_writer, &stderr_writer);
    const out = stdout_writer.buffered();
    if (enter_hook) {
        try std.testing.expectEqual(agent_hook.fail_closed_deny_exit_code, code);
        try std.testing.expect(std.mem.indexOf(u8, out, "\"permission\":\"deny\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, out, "\"permissionDecision\":\"deny\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, out, "hook payload was empty") != null);
        try std.testing.expect(std.mem.indexOf(u8, out, "Common tasks") == null);
    } else {
        try std.testing.expectEqual(exit_codes.success, code);
        try std.testing.expect(std.mem.indexOf(u8, out, "Common tasks") != null);
        try std.testing.expect(std.mem.indexOf(u8, out, "\"permission\":\"deny\"") == null);
    }
}

test "help output is grouped, complete, and excludes hidden commands" {
    var stdout_buf: [16384]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    // Default help is progressive disclosure (Safe Launch only).
    const code = try testRun(&.{"--help"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "ryk") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Common tasks") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Get protected") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "ryk start") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "ryk explain") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "ryk replay") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "help --all") != null);
    // Phase 7 Task E: the --no-rich / RYK_NO_RICH escape hatch is discoverable
    // from the top-level help (global-options surface).
    try std.testing.expect(std.mem.indexOf(u8, output, "Global options") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "--no-rich") != null);
    // Hidden internal command absent
    try std.testing.expect(std.mem.indexOf(u8, output, "shim") == null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());

    // Full surface via help --all
    stdout_writer = .fixed(&stdout_buf);
    stderr_writer = .fixed(&stderr_buf);
    const all_code = try testRun(&.{ "help", "--all" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, all_code);
    const all = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, all, "Getting Started") != null);
    try std.testing.expect(std.mem.indexOf(u8, all, "Core Workflow") != null);
    try std.testing.expect(std.mem.indexOf(u8, all, "Diagnostics & Reporting") != null);
    try std.testing.expect(std.mem.indexOf(u8, all, "run") != null);
    try std.testing.expect(std.mem.indexOf(u8, all, "env") != null);
    try std.testing.expect(std.mem.indexOf(u8, all, "shim") == null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "help output uses human-friendly summaries" {
    var stdout_buf: [32768]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var empty_buf: [0]u8 = undefined;
    var stderr_writer: std.Io.Writer = .fixed(&empty_buf);

    // Friendly advanced summaries live on the full surface.
    _ = try testRun(&.{ "help", "--all" }, &stdout_writer, &stderr_writer);
    const output = stdout_writer.buffered();

    // Old jargon should be gone from summaries
    try std.testing.expect(std.mem.indexOf(u8, output, "Secretless") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "hook adapter") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "red-team fixtures") == null);

    // New friendly text should be present
    try std.testing.expect(std.mem.indexOf(u8, output, "Verify credential brokers") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Receive events from AI agent hosts") != null);
}

test "help disambiguates explain vs policy explain" {
    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try testRun(&.{ "help", "explain" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "policy explain") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Zig shell_engine") != null);
}

test "env command appears in help and dispatches correctly" {
    var stdout_buf: [32768]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    // env is advanced: listed on help --all, not default Safe Launch help
    const help_code = try testRun(&.{ "help", "--all" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, help_code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "env") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "Print shell environment") != null);

    // env command dispatches
    stdout_writer = .fixed(&stdout_buf);
    stderr_writer = .fixed(&stderr_buf);
    const env_code = try testRun(&.{"env"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, env_code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "PATH") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "command-specific help works through help command and command flag" {
    var stdout_buf: [8192]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try testRun(&.{ "help", "run" }, &stdout_writer, &stderr_writer);

    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "ryk run") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "Examples:") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "ryk run -- <custom-command>") != null);
    // Phase 1 dual contract: host-alias allowlist + non-alias ask.
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "network mode allowlist") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "defaults network mode to ask") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());

    stdout_writer = .fixed(&stdout_buf);
    stderr_writer = .fixed(&stderr_buf);
    const flag_code = try testRun(&.{ "run", "--help" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, flag_code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "protected session") != null);
}

test "help run includes examples section" {
    var stdout_buf: [8192]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try testRun(&.{ "help", "run" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "Examples:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "ryk run -- <custom-command>") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "ryk claude") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "secretless stays off") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "empty-backpack") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

fn fakeVersionSuccess(_: std.Io, argv: []const []const u8, stdout: anytype, _: anytype) !u8 {
    try std.testing.expectEqual(@as(usize, 1), argv.len);
    try std.testing.expectEqualStrings("version", argv[0]);
    try stdout.writeAll("ryk-daemon 1.2.3\n");
    return exit_codes.success;
}

fn fakeVersionError(_: std.Io, argv: []const []const u8, _: anytype, stderr: anytype) !u8 {
    try std.testing.expectEqual(@as(usize, 1), argv.len);
    try std.testing.expectEqualStrings("version", argv[0]);
    try stderr.writeAll("unsupported command\n");
    return exit_codes.general;
}

fn fakeVersionUnavailable(_: std.Io, argv: []const []const u8, _: anytype, _: anytype) !u8 {
    try std.testing.expectEqual(@as(usize, 1), argv.len);
    try std.testing.expectEqualStrings("version", argv[0]);
    return error.DaemonBinaryNotFound;
}

fn fakeTestProxySuccess(_: std.Io, argv: []const []const u8, stdout: anytype, _: anytype) !u8 {
    try std.testing.expectEqual(@as(usize, 2), argv.len);
    try std.testing.expectEqualStrings("test", argv[0]);
    try std.testing.expectEqualStrings("git status", argv[1]);
    try stdout.writeAll("test ok\n");
    return exit_codes.success;
}

fn fakeHistoryProxySuccess(_: std.Io, argv: []const []const u8, stdout: anytype, _: anytype) !u8 {
    try std.testing.expectEqual(@as(usize, 2), argv.len);
    try std.testing.expectEqualStrings("history", argv[0]);
    try std.testing.expectEqualStrings("--help", argv[1]);
    try stdout.writeAll("history ok\n");
    return exit_codes.success;
}

fn fakeHistoryMachineContract(_: std.Io, argv: []const []const u8, stdout: anytype, _: anytype) !u8 {
    try std.testing.expectEqualStrings("history", argv[0]);
    try std.testing.expectEqualStrings("--format", argv[1]);
    try std.testing.expectEqualStrings("json", argv[2]);
    try stdout.writeAll(@embedFile("test-fixtures/proxy-history.json"));
    return exit_codes.success;
}

fn fakePrecommitProxySuccess(_: std.Io, argv: []const []const u8, stdout: anytype, _: anytype) !u8 {
    try std.testing.expectEqual(@as(usize, 1), argv.len);
    try std.testing.expectEqualStrings("precommit", argv[0]);
    try stdout.writeAll("precommit ok\n");
    return exit_codes.success;
}

fn fakePacksProxySuccess(_: std.Io, argv: []const []const u8, stdout: anytype, _: anytype) !u8 {
    try std.testing.expectEqual(@as(usize, 3), argv.len);
    try std.testing.expectEqualStrings("packs", argv[0]);
    try std.testing.expectEqualStrings("--format", argv[1]);
    try std.testing.expectEqualStrings("json", argv[2]);
    try stdout.writeAll("packs ok\n");
    return exit_codes.success;
}

fn fakePhase1ProxyUnavailable(_: std.Io, argv: []const []const u8, _: anytype, _: anytype) !u8 {
    try std.testing.expectEqual(@as(usize, 1), argv.len);
    try std.testing.expectEqualStrings("packs", argv[0]);
    return error.DaemonBinaryNotFound;
}

fn fakeExplainProxySuccess(_: std.Io, argv: []const []const u8, stdout: anytype, _: anytype) !u8 {
    try std.testing.expectEqual(@as(usize, 2), argv.len);
    try std.testing.expectEqualStrings("explain", argv[0]);
    try std.testing.expectEqualStrings("git reset --hard", argv[1]);
    try stdout.writeAll("explain ok\n");
    return exit_codes.success;
}

fn fakeAllowlistProxySuccess(_: std.Io, argv: []const []const u8, stdout: anytype, _: anytype) !u8 {
    try std.testing.expectEqual(@as(usize, 2), argv.len);
    try std.testing.expectEqualStrings("allowlist", argv[0]);
    try std.testing.expectEqualStrings("list", argv[1]);
    try stdout.writeAll("allowlist ok\n");
    return exit_codes.success;
}

fn fakeClassifyProxySuccess(_: std.Io, argv: []const []const u8, stdout: anytype, _: anytype) !u8 {
    try std.testing.expectEqual(@as(usize, 2), argv.len);
    try std.testing.expectEqualStrings("classify", argv[0]);
    try std.testing.expectEqualStrings("rm -rf /tmp/x", argv[1]);
    try stdout.writeAll("classify ok\n");
    return exit_codes.success;
}

fn fakeAllowOnceProxyUnavailable(_: std.Io, argv: []const []const u8, _: anytype, _: anytype) !u8 {
    try std.testing.expectEqual(@as(usize, 1), argv.len);
    try std.testing.expectEqualStrings("allow-once", argv[0]);
    return error.DaemonBinaryNotFound;
}

fn fakeSimulateProxySuccess(_: std.Io, argv: []const []const u8, stdout: anytype, _: anytype) !u8 {
    try std.testing.expectEqual(@as(usize, 3), argv.len);
    try std.testing.expectEqualStrings("simulate", argv[0]);
    try std.testing.expectEqualStrings("--file", argv[1]);
    try std.testing.expectEqualStrings("commands.txt", argv[2]);
    try stdout.writeAll("simulate ok\n");
    return exit_codes.success;
}

fn fakeSuggestAllowlistProxySuccess(_: std.Io, argv: []const []const u8, stdout: anytype, _: anytype) !u8 {
    try std.testing.expectEqual(@as(usize, 1), argv.len);
    try std.testing.expectEqualStrings("suggest-allowlist", argv[0]);
    try stdout.writeAll("Allowlist Suggestions\nNext steps (high confidence)\n  ryk suggest-allowlist --apply 1\n");
    return exit_codes.success;
}

test "version proxy routes version argv and renders success" {
    var stdout_buf: [128]u8 = undefined;
    var stderr_buf: [128]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try proxyVersionCommand(fakeVersionSuccess, std.testing.io, &stdout_writer, &stderr_writer);

    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expectEqualStrings("ryk-daemon 1.2.3\n", stdout_writer.buffered());
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "version proxy propagates daemon error output and exit code" {
    var stdout_buf: [128]u8 = undefined;
    var stderr_buf: [128]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try proxyVersionCommand(fakeVersionError, std.testing.io, &stdout_writer, &stderr_writer);

    try std.testing.expectEqual(exit_codes.general, code);
    try std.testing.expectEqualStrings("", stdout_writer.buffered());
    try std.testing.expectEqualStrings("unsupported command\n", stderr_writer.buffered());
}

test "version proxy reports daemon unavailable explicitly" {
    var stdout_buf: [128]u8 = undefined;
    var stderr_buf: [128]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try proxyVersionCommand(fakeVersionUnavailable, std.testing.io, &stdout_writer, &stderr_writer);

    try std.testing.expectEqual(exit_codes.general, code);
    try std.testing.expectEqualStrings("", stdout_writer.buffered());
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "daemon unavailable") != null);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "DaemonBinaryNotFound") != null);
}

test "phase 1 proxy commands construct daemon argv and render success" {
    var stdout_buf: [128]u8 = undefined;
    var stderr_buf: [128]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const test_code = try proxyPhase1Command(fakeTestProxySuccess, "test", &.{"git status"}, std.testing.io, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, test_code);
    try std.testing.expectEqualStrings("test ok\n", stdout_writer.buffered());
    try std.testing.expectEqualStrings("", stderr_writer.buffered());

    // `scan` is Zig-native forensics — must not be a daemon proxy command.
    try std.testing.expect(!isDaemonProxyCommand("scan"));

    stdout_writer = .fixed(&stdout_buf);
    stderr_writer = .fixed(&stderr_buf);
    const history_code = try proxyPhase1Command(fakeHistoryProxySuccess, "history", &.{"--help"}, std.testing.io, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, history_code);
    try std.testing.expectEqualStrings("history ok\n", stdout_writer.buffered());
    try std.testing.expectEqualStrings("", stderr_writer.buffered());

    stdout_writer = .fixed(&stdout_buf);
    stderr_writer = .fixed(&stderr_buf);
    const precommit_code = try proxyPhase1Command(fakePrecommitProxySuccess, "precommit", &.{}, std.testing.io, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, precommit_code);
    try std.testing.expectEqualStrings("precommit ok\n", stdout_writer.buffered());
    try std.testing.expectEqualStrings("", stderr_writer.buffered());

    stdout_writer = .fixed(&stdout_buf);
    stderr_writer = .fixed(&stderr_buf);
    const packs_code = try proxyPhase1Command(fakePacksProxySuccess, "packs", &.{ "--format", "json" }, std.testing.io, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, packs_code);
    try std.testing.expectEqualStrings("packs ok\n", stdout_writer.buffered());
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "phase 1 proxy reports daemon unavailable explicitly" {
    var stdout_buf: [128]u8 = undefined;
    var stderr_buf: [128]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try proxyPhase1Command(fakePhase1ProxyUnavailable, "packs", &.{}, std.testing.io, &stdout_writer, &stderr_writer);

    try std.testing.expectEqual(exit_codes.general, code);
    try std.testing.expectEqualStrings("", stdout_writer.buffered());
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "ryk packs: daemon unavailable") != null);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "DaemonBinaryNotFound") != null);
}

test "phase A proxy commands construct daemon argv and render success" {
    var stdout_buf: [128]u8 = undefined;
    var stderr_buf: [128]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    try std.testing.expect(!isDaemonProxyCommand("explain"));
    try std.testing.expect(!isDaemonProxyCommand("test"));
    try std.testing.expect(!isDaemonProxyCommand("allowlist"));
    try std.testing.expect(!isDaemonProxyCommand("allow"));
    try std.testing.expect(!isDaemonProxyCommand("unallow"));
    try std.testing.expect(!isDaemonProxyCommand("allow-once"));
    try std.testing.expect(isDaemonProxyCommand("classify"));
    try std.testing.expect(isDaemonProxyCommand("suggest-allowlist"));
    try std.testing.expect(!isDaemonProxyCommand("rebase-recover"));
    try std.testing.expect(!isDaemonProxyCommand("config"));
    try std.testing.expect(isDaemonProxyCommand("simulate"));
    try std.testing.expect(isDaemonLocalMutatingTopLevel("allow"));
    try std.testing.expect(isDaemonLocalMutatingTopLevel("allow-once"));
    try std.testing.expect(isDaemonLocalMutatingInvocation("suggest-allowlist", &.{ "--apply", "1" }));
    try std.testing.expect(isDaemonLocalMutatingInvocation("suggest-allowlist", &.{ "--undo", "60" }));
    try std.testing.expect(!isDaemonLocalMutatingInvocation("suggest-allowlist", &.{"--non-interactive"}));
    try std.testing.expect(!isDaemonProxyCommand("doctor"));
    try std.testing.expect(!isDaemonProxyCommand("init"));
    try std.testing.expect(!isDaemonProxyCommand("scan"));
    try std.testing.expect(!isDaemonProxyCommand("update"));

    // Direct proxyDaemonCommand helper still works for remaining stubbed ExecuteCli surfaces.
    const classify_code = try proxyDaemonCommand(fakeClassifyProxySuccess, "classify", &.{"rm -rf /tmp/x"}, std.testing.io, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, classify_code);
    try std.testing.expectEqualStrings("classify ok\n", stdout_writer.buffered());
}

test "phase A proxy reports daemon unavailable with command label" {
    var stdout_buf: [128]u8 = undefined;
    var stderr_buf: [128]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try proxyDaemonCommand(fakeAllowOnceProxyUnavailable, "allow-once", &.{}, std.testing.io, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.general, code);
    try std.testing.expectEqualStrings("", stdout_writer.buffered());
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "ryk allow-once: daemon unavailable") != null);
}

test "simulate proxy routes argv to daemon ExecuteCli" {
    var stdout_buf: [128]u8 = undefined;
    var stderr_buf: [128]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try proxyDaemonCommand(fakeSimulateProxySuccess, "simulate", &.{ "--file", "commands.txt" }, std.testing.io, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expectEqualStrings("simulate ok\n", stdout_writer.buffered());
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "suggest-allowlist proxy routes and preserves next-step shape" {
    var stdout_buf: [256]u8 = undefined;
    var stderr_buf: [128]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try proxyDaemonCommand(fakeSuggestAllowlistProxySuccess, "suggest-allowlist", &.{}, std.testing.io, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "Next steps") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "suggest-allowlist --apply") != null);
}

test "proxied machine output remains byte-identical to daemon contract fixture" {
    var stdout_buf: [256]u8 = undefined;
    var stderr_buf: [128]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const code = try proxyPhase1Command(fakeHistoryMachineContract, "history", &.{ "--format", "json" }, std.testing.io, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expectEqualStrings(@embedFile("test-fixtures/proxy-history.json"), stdout_writer.buffered());
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "daemonErrorLabel distinguishes protocol compatibility failures" {
    try std.testing.expectEqualStrings("daemon protocol error", daemonErrorLabel(error.ProtocolMismatch));
    try std.testing.expectEqualStrings("daemon protocol error", daemonErrorLabel(error.MissingHandshake));
    try std.testing.expectEqualStrings("daemon protocol error", daemonErrorLabel(error.HandshakeMalformed));
}

test "version supports json, help, and rejects extra arguments" {
    var stdout_buf: [1024]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const plain_code = try testRun(&.{"version"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, plain_code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), version) != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());

    stdout_writer = .fixed(&stdout_buf);
    stderr_writer = .fixed(&stderr_buf);
    const help_code = try testRun(&.{ "version", "--help" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, help_code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "ryk version") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());

    stdout_writer = .fixed(&stdout_buf);
    stderr_writer = .fixed(&stderr_buf);
    const json_code = try testRun(&.{ "version", "--json" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, json_code);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, stdout_writer.buffered(), .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings(version, parsed.value.object.get("version").?.string);
    try std.testing.expect(parsed.value.object.get("commit") != null);
    try std.testing.expect(parsed.value.object.get("target") != null);
    try std.testing.expect(parsed.value.object.get("build_date") != null);

    stdout_writer = .fixed(&stdout_buf);
    stderr_writer = .fixed(&stderr_buf);
    const invalid_code = try testRun(&.{ "version", "typo" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, invalid_code);
    try std.testing.expectEqualStrings("", stdout_writer.buffered());
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "unsupported argument") != null);
}

test "unknown command returns non-zero with useful message" {
    var stdout_buf: [128]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try testRun(&.{"not-a-command"}, &stdout_writer, &stderr_writer);

    try std.testing.expect(code != exit_codes.success);
    try std.testing.expectEqual(exit_codes.usage, code);
    try std.testing.expectEqualStrings("", stdout_writer.buffered());
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "unknown command") != null);
}

test "help unknown command suggests the closest command" {
    var stdout_buf: [256]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try testRun(&.{ "help", "docter" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "Did you mean 'doctor'?") != null);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "ryk help doctor") != null);
}

test "human parser families suggest valid flags and exact help remediation" {
    const Case = struct { argv: []const []const u8, suggestion: []const u8, help_command: []const u8 };
    const cases = [_]Case{
        .{ .argv = &.{ "doctor", "--verbse" }, .suggestion = "--verbose", .help_command = "doctor" },
        .{ .argv = &.{ "init", "--presett" }, .suggestion = "--preset", .help_command = "init" },
        .{ .argv = &.{ "policy", "explan" }, .suggestion = "explain", .help_command = "policy" },
        .{ .argv = &.{ "replay", "--sesion" }, .suggestion = "--session", .help_command = "replay" },
        .{ .argv = &.{ "report", "--sesion" }, .suggestion = "--session", .help_command = "report" },
        .{ .argv = &.{ "decide", "comand" }, .suggestion = "command", .help_command = "decide" },
        .{ .argv = &.{ "decide", "command", "--stdi" }, .suggestion = "--stdin", .help_command = "decide" },
        .{ .argv = &.{ "redteam", "--fixtur" }, .suggestion = "--fixture", .help_command = "redteam" },
        .{ .argv = &.{ "diff", "--sesion" }, .suggestion = "--session", .help_command = "diff" },
        .{ .argv = &.{ "apply", "--sesion" }, .suggestion = "--session", .help_command = "apply" },
        .{ .argv = &.{ "discard", "--sesion" }, .suggestion = "--session", .help_command = "discard" },
        .{ .argv = &.{ "plugin", "instal" }, .suggestion = "install", .help_command = "plugin" },
        .{ .argv = &.{ "start", "--preest" }, .suggestion = "--preset", .help_command = "start" },
        .{ .argv = &.{ "run", "--workspce" }, .suggestion = "--workspace", .help_command = "run" },
        .{ .argv = &.{ "doctor", "--chek" }, .suggestion = "--check", .help_command = "doctor" },
    };

    for (cases) |case| {
        var stdout_buf: [4096]u8 = undefined;
        var stderr_buf: [1024]u8 = undefined;
        var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
        var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
        const code = try testRun(case.argv, &stdout_writer, &stderr_writer);
        try std.testing.expectEqual(exit_codes.usage, code);
        try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), case.suggestion) != null);
        var remediation_buf: [64]u8 = undefined;
        const remediation = try std.fmt.bufPrint(&remediation_buf, "ryk help {s}", .{case.help_command});
        try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), remediation) != null);
        try std.testing.expect(std.mem.indexOfScalar(u8, stderr_writer.buffered(), 0x1b) == null);
    }
}

test "human parser invalid values sanitize terminal controls and suggest valid values" {
    const hostile = "strct\x1b[2J\nforged";
    const Case = struct { argv: []const []const u8, suggestion: []const u8 };
    const cases = [_]Case{
        .{ .argv = &.{ "init", "--mode", hostile }, .suggestion = "strict" },
        .{ .argv = &.{ "run", "--mode", hostile, "--", "true" }, .suggestion = "strict" },
        .{ .argv = &.{ "run", "--network-backend", hostile, "--", "true" }, .suggestion = "proxy" },
        .{ .argv = &.{ "plugin", "install", "--scope", hostile }, .suggestion = "project" },
        .{ .argv = &.{ "policy", "apply-pack", hostile }, .suggestion = "strict-local" },
    };

    for (cases) |case| {
        var stdout_buf: [4096]u8 = undefined;
        var stderr_buf: [2048]u8 = undefined;
        var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
        var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
        const code = try testRun(case.argv, &stdout_writer, &stderr_writer);
        try std.testing.expectEqual(exit_codes.usage, code);
        try std.testing.expect(std.mem.indexOfScalar(u8, stderr_writer.buffered(), 0x1b) == null);
        try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "\nforged") == null);
        try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), case.suggestion) != null);
    }
}

// ---------------------------------------------------------------------------
// Phase 2 TDD: brand cohesion banner system (written FIRST — RED).
// The compact `🛡  ryk · v<version>` header must open every HUMAN command,
// be suppressed for --json / raw / machine / help-reference paths, and stay
// byte-identical on --json. Banner marker in the plain-text degrade path is
// the literal `🛡  ryk` glyph run (colour is suppressed under builtin.is_test).
// ---------------------------------------------------------------------------

test "version human path renders brand banner and key-value grid" {
    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try testRun(&.{"version"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    const out = stdout_writer.buffered();
    // Compact brand header.
    try std.testing.expect(std.mem.indexOf(u8, out, "\u{1F6E1}  ryk") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, version) != null);
    // Key-value grid labels.
    try std.testing.expect(std.mem.indexOf(u8, out, "Version") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Channel") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Target") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Daemon") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "version --json suppresses the brand banner (machine contract)" {
    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try testRun(&.{ "version", "--json" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    const out = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "\u{1F6E1}  ryk") == null);
    try std.testing.expect(out.len > 0 and out[0] == '{');
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, out, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings(version, parsed.value.object.get("version").?.string);
}

test "top help renders brand banner, accent categories, and try-next hint" {
    var stdout_buf: [32768]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    // Default Safe Launch help
    const code = try testRun(&.{"--help"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    const out = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "\u{1F6E1}  ryk") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Common tasks") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "ryk start") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "help --all") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "shim") == null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());

    // Full surface retains category headers and advanced summaries
    stdout_writer = .fixed(&stdout_buf);
    stderr_writer = .fixed(&stderr_buf);
    const all_code = try testRun(&.{ "help", "--all" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, all_code);
    const all = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, all, "Getting Started") != null);
    try std.testing.expect(std.mem.indexOf(u8, all, "Core Workflow") != null);
    try std.testing.expect(std.mem.indexOf(u8, all, "Diagnostics & Reporting") != null);
    try std.testing.expect(std.mem.indexOf(u8, all, "Print shell environment") != null);
    try std.testing.expect(std.mem.indexOf(u8, all, "Receive events from AI agent hosts") != null);
    try std.testing.expect(std.mem.indexOf(u8, all, "shim") == null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "banner renders on a human command (doctor)" {
    var stdout_buf: [16384]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try testRun(&.{"doctor"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    const out = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "\u{1F6E1}  ryk") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Summary:") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "start owns its onboarding banner" {
    try std.testing.expect(!shouldShowBanner("start", &.{"start"}));
    try std.testing.expect(!shouldShowBanner("start", &.{ "start", "--auto" }));
}

test "scan suppresses entry banner (progress is spinner-only)" {
    try std.testing.expect(!shouldShowBanner("scan", &.{"scan"}));
    try std.testing.expect(!shouldShowBanner("scan", &.{ "scan", "--host", "grok" }));
    try std.testing.expect(!shouldShowBanner("scan", &.{ "scan", "--plain" }));
}

test "banner suppressed for raw env output" {
    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try testRun(&.{"env"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    const out = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "PATH") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\u{1F6E1}  ryk") == null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "banner suppressed for completions raw output" {
    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try testRun(&.{ "completions", "bash" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    const out = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "complete -F") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\u{1F6E1}  ryk") == null);
}

test "report generated exports are classified as raw at top level" {
    try std.testing.expect(!shouldShowBanner("report", &.{"report"}));
    try std.testing.expect(!shouldShowBanner("report", &.{ "report", "--format", "human" }));
    try std.testing.expect(!shouldShowBanner("report", &.{ "report", "--format", "markdown" }));
    try std.testing.expect(!shouldShowBanner("report", &.{ "report", "--format", "json" }));
}

test "top-level MCP generated surfaces preserve exact bytes" {
    try std.testing.expect(isRawGeneratedInvocation("mcp", &.{ "mcp", "proxy", "--command", "server" }));
    try std.testing.expect(!isRawGeneratedInvocation("mcp", &.{ "mcp", "list" }));
    const expected_manifest =
        \\version: 1
        \\server:
        \\  name: demo
        \\  transport: stdio
        \\  command: demo
        \\  args: []
        \\  expected_hash: null
        \\  env:
        \\    allow:
        \\      - GITHUB_TOKEN
        \\
        \\tools:
        \\resources:
        \\  default: ask
        \\prompts:
        \\  default: ask
        \\sampling:
        \\  default: deny
        \\
    ;
    const expected_trust =
        \\Direct policy mutation is not implemented for this command.
        \\Add this snippet to your policy after reviewing the server manifest:
        \\
        \\mcp:
        \\  allow:
        \\    - "demo.read"
        \\
    ;
    inline for (.{
        .{ .argv = &.{ "mcp", "manifest", "generate", "--server", "demo" }, .expected = expected_manifest },
        .{ .argv = &.{ "mcp", "trust", "demo", "--tool", "read" }, .expected = expected_trust },
    }) |case| {
        var stdout_buf: [2048]u8 = undefined;
        var stderr_buf: [512]u8 = undefined;
        var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
        var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
        try std.testing.expectEqual(exit_codes.success, try testRun(case.argv, &stdout_writer, &stderr_writer));
        try std.testing.expectEqualStrings(case.expected, stdout_writer.buffered());
        try std.testing.expectEqualStrings("", stderr_writer.buffered());
    }
}

test "history live human rejection gets a banner while machine conflict stays raw" {
    try std.testing.expect(shouldShowBanner("history", &.{ "history", "--live" }));
    try std.testing.expect(!shouldShowBanner("history", &.{ "history", "--live", "--json" }));
    try std.testing.expect(!shouldShowBanner("history", &.{ "history", "--live", "--robot" }));
}

test "daemon passthrough and robot surfaces have no top-level presentation bytes" {
    const raw_invocations = [_]struct { command: []const u8, argv: []const []const u8 }{
        .{ .command = "test", .argv = &.{ "test", "git status" } },
        .{ .command = "precommit", .argv = &.{"precommit"} },
        .{ .command = "packs", .argv = &.{ "packs", "--robot" } },
        .{ .command = "history", .argv = &.{ "history", "export", "--format", "jsonl" } },
        .{ .command = "history", .argv = &.{ "history", "check" } },
        .{ .command = "mcp", .argv = &.{ "mcp", "proxy", "--command", "server" } },
    };
    for (raw_invocations) |invocation| {
        try std.testing.expect(!shouldShowBanner(invocation.command, invocation.argv));
    }
}

fn fakeRawDaemon(_: std.Io, argv: []const []const u8, stdout: anytype, _: anytype) !u8 {
    try stdout.print("daemon:{s}\n", .{argv[0]});
    return 7;
}

fn fakeRawPacks(_: std.Io, argv: []const []const u8, stdout: anytype, _: anytype) !u8 {
    try std.testing.expectEqualStrings("--robot", argv[0]);
    try stdout.writeAll("packs-robot\n");
    return 8;
}

fn fakeRawHistory(_: std.Io, argv: []const []const u8, stdout: anytype, _: anytype) !u8 {
    try std.testing.expectEqualStrings("export", argv[0]);
    try stdout.writeAll("history-export\n");
    return 9;
}

fn fakeRawMcp(_: std.Io, argv: []const []const u8, stdout: anytype, _: anytype) !u8 {
    try std.testing.expectEqualStrings("proxy", argv[0]);
    try stdout.writeAll("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}\n");
    return 10;
}

test "public dispatch preserves MCP protocol bytes; Zig-native test/explain no longer daemon-proxy" {
    const Case = struct { argv: []const []const u8, expected_substr: []const u8, code: u8 };
    const cases = [_]Case{
        // Zig shell_engine: allow git status → exit 0, JSON/text decision output.
        .{ .argv = &.{ "test", "git status" }, .expected_substr = "allow", .code = 0 },
        // s-packs: live oracle registry JSON (no daemon; --robot → machine schema).
        .{ .argv = &.{ "packs", "--robot" }, .expected_substr = "schema_version", .code = 0 },
        // Slice 1 honesty: hide-list verbs fail short (usage), not daemon essay.
        .{ .argv = &.{ "history", "export" }, .expected_substr = "not available", .code = exit_codes.usage },
        .{ .argv = &.{ "mcp", "proxy", "--command", "server" }, .expected_substr = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}", .code = 10 },
    };
    var env_map = try std.process.Environ.createMap(std.process.Environ.empty, std.testing.allocator);
    defer env_map.deinit();
    for (cases) |case| {
        // packs --robot emits full registry JSON (well over 1KiB).
        var stdout_buf: [256 * 1024]u8 = undefined;
        var stderr_buf: [4096]u8 = undefined;
        var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
        var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
        const code = try runWithCwdUsing(fakeRawDaemon, fakeRawPacks, fakeRawHistory, fakeRawMcp, std.testing.io, &env_map, std.Io.Dir.cwd(), case.argv, &stdout_writer, &stderr_writer);
        try std.testing.expectEqual(case.code, code);
        const combined = try std.fmt.allocPrint(std.testing.allocator, "{s}{s}", .{ stdout_writer.buffered(), stderr_writer.buffered() });
        defer std.testing.allocator.free(combined);
        try std.testing.expect(std.mem.indexOf(u8, combined, case.expected_substr) != null);
    }
}

// ---------------------------------------------------------------------------
// Slice 1 (P0 honesty) — hidden dead verbs fail clearly; shutdown stays live.
// ---------------------------------------------------------------------------

/// Shared short-unavailable contract for hide-list + unfinished P0 verbs.
/// Plan shape (flexible): `command '…' is not available` + `Run 'ryk help'…`, usage exit,
/// no multi-line Rust-daemon essay. `require_empty_stdout` is true for raw-passthrough
/// routes (daemon proxy / local-mutator); false for bare human-ish stubs like `packs`
/// where brand banner may still hit stdout before the unavailable handler.
fn expectShortUnavailable(
    command: []const u8,
    code: u8,
    stdout: []const u8,
    stderr: []const u8,
    require_empty_stdout: bool,
) !void {
    try std.testing.expectEqual(exit_codes.usage, code);
    if (require_empty_stdout) {
        try std.testing.expectEqualStrings("", stdout);
    } else {
        // Banner may appear; long daemon essay must not land on stdout either.
        try std.testing.expect(std.mem.indexOf(u8, stdout, "not yet ported") == null);
        try std.testing.expect(std.mem.indexOf(u8, stdout, "Rust daemon") == null);
        try std.testing.expect(std.mem.indexOf(u8, stdout, "threat-model") == null);
    }
    try std.testing.expect(std.mem.indexOf(u8, stderr, command) != null);
    try std.testing.expect(std.mem.indexOf(u8, stderr, "not available") != null);
    try std.testing.expect(std.mem.indexOf(u8, stderr, "is not available") != null);
    try std.testing.expect(std.mem.indexOf(u8, stderr, "ryk help") != null);
    // No long daemon / ported essay (rust_legacy_stub shape).
    try std.testing.expect(std.mem.indexOf(u8, stderr, "not yet ported") == null);
    try std.testing.expect(std.mem.indexOf(u8, stderr, "Rust daemon") == null);
    try std.testing.expect(std.mem.indexOf(u8, stderr, "threat-model") == null);
    // Keep the message short (plan: ~two lines; one short notice + usage hint).
    try std.testing.expect(stderr.len < 200);
}

test "P0 honesty: hide-list command yields short not-available and usage exit" {
    // Representative hide-list port via isDaemonProxyCommand (`precommit`).
    var stdout_buf: [512]u8 = undefined;
    var stderr_buf: [1024]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try testRun(&.{"precommit"}, &stdout_writer, &stderr_writer);
    // Proxy path is raw-passthrough → no brand banner → empty stdout.
    try expectShortUnavailable("precommit", code, stdout_writer.buffered(), stderr_writer.buffered(), true);
}

test "scan dispatches Zig session forensics not daemon unavailable stub" {
    var stdout_buf: [64 * 1024]u8 = undefined;
    var stderr_buf: [4096]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try testRun(&.{ "scan", "--help" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    const combined = try std.fmt.allocPrint(std.testing.allocator, "{s}{s}", .{
        stdout_writer.buffered(),
        stderr_writer.buffered(),
    });
    defer std.testing.allocator.free(combined);
    try std.testing.expect(std.mem.indexOf(u8, combined, "not available") == null);
    try std.testing.expect(std.mem.indexOf(u8, combined, "session") != null or
        std.mem.indexOf(u8, combined, "forensics") != null or
        std.mem.indexOf(u8, combined, "secret") != null);
}

test "P0 honesty: live packs dispatches (not short not-available)" {
    // s-packs: bare packs lists registry — must not hit honesty stub.
    var stdout_buf: [65536]u8 = undefined;
    var stderr_buf: [1024]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try testRun(&.{"packs"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "not available") == null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "core.git") != null or
        std.mem.indexOf(u8, stdout_writer.buffered(), "Safety packs") != null or
        std.mem.indexOf(u8, stdout_writer.buffered(), "packs") != null);
}

test "P0 honesty: live allow-once dispatches usage (not short not-available)" {
    // s-once-cli: bare allow-once is live CLI usage, not honesty stub / local-mutator essay.
    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [2048]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try testRun(&.{"allow-once"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "not available") == null);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "Usage: ryk allow-once") != null);
}

test "P0 honesty: live allow dispatches usage (not short not-available)" {
    // s-allowlist-cli: bare allow is live CLI usage, not honesty stub.
    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [4096]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try testRun(&.{"allow"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "not available") == null);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "ryk allow") != null or
        std.mem.indexOf(u8, stderr_writer.buffered(), "allowlist") != null);
}

test "P0 honesty: shutdown still dispatches live Zig path (not not-available)" {
    // Live path: invalid flag is handled by shutdown.command suggestions, not honesty stub.
    var stdout_buf: [512]u8 = undefined;
    var stderr_buf: [1024]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try testRun(&.{ "shutdown", "--daemn" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, code);
    const err = stderr_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, err, "not available") == null);
    try std.testing.expect(std.mem.indexOf(u8, err, "Did you mean '--daemon'?") != null);
    try std.testing.expect(std.mem.indexOf(u8, err, "ryk help shutdown") != null);

    // Per-command help still works for live shutdown.
    stdout_writer = .fixed(&stdout_buf);
    stderr_writer = .fixed(&stderr_buf);
    const help_code = try testRun(&.{ "shutdown", "--help" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, help_code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "ryk shutdown") != null);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "not available") == null);
}

test "diff and CI generated formats suppress presentation" {
    try std.testing.expect(isRawGeneratedInvocation("diff", &.{"diff"}));
    try std.testing.expect(isRawGeneratedInvocation("ci", &.{ "ci", "check", "--format", "markdown" }));
    try std.testing.expect(isRawGeneratedInvocation("ci", &.{ "ci", "check", "--format", "json" }));
    try std.testing.expect(!isRawGeneratedInvocation("ci", &.{ "ci", "check" }));
    try std.testing.expect(!shouldShowBanner("diff", &.{"diff"}));
    try std.testing.expect(!shouldShowBanner("ci", &.{ "ci", "check", "--format", "markdown" }));
}

test "top-level CI generated formats preserve exact bytes" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, ".git");
    const previous_cwd = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(previous_cwd);
    try std.process.setCurrentDir(std.testing.io, tmp.dir);
    defer std.process.setCurrentPath(std.testing.io, previous_cwd) catch {};

    const expected_markdown =
        \\# ryk CI Check
        \\
        \\- policy: **fail** - Missing .ryk/policy.yaml. Run: ryk init --preset team-ci
        \\
    ;
    const expected_json =
        \\{"ok":false,"checks":[{"name":"policy","status":"fail","message":"Missing .ryk/policy.yaml. Run: ryk init --preset team-ci"}]}
        \\
    ;
    inline for (.{
        .{ .format = "markdown", .expected = expected_markdown },
        .{ .format = "json", .expected = expected_json },
    }) |case| {
        var stdout_buf: [2048]u8 = undefined;
        var stderr_buf: [256]u8 = undefined;
        var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
        var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
        const code = try testRun(&.{ "ci", "check", "--format", case.format }, &stdout_writer, &stderr_writer);
        try std.testing.expectEqual(exit_codes.general, code);
        try std.testing.expectEqualStrings(case.expected, stdout_writer.buffered());
        try std.testing.expectEqualStrings("", stderr_writer.buffered());
    }
}

test "top-level diff emits the exact patch from byte zero" {
    const intercept_files = @import("ryk").intercept.files;
    const policy_load = @import("ryk_core").policy.load;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, ".git");
    try tmp.dir.createDirPath(std.testing.io, "src");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "src/existing.txt", .data = "old\n" });
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    var loaded = try policy_load.loadPreset(std.testing.allocator, .strict);
    defer loaded.deinit();
    var staged = try intercept_files.stageUpdate(std.testing.io, std.testing.allocator, &loaded, root, "phase06-diff", "src/existing.txt", "newer\n", null);
    defer staged.deinit(std.testing.allocator);
    const previous_cwd = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(previous_cwd);
    try std.process.setCurrentDir(std.testing.io, tmp.dir);
    defer std.process.setCurrentPath(std.testing.io, previous_cwd) catch {};

    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const code = try testRun(&.{ "diff", "--session", "phase06-diff", "--file", "src/existing.txt" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expectEqualStrings(
        "--- a/src/existing.txt\n+++ b/src/existing.txt\n@@\n-old\n+newer\n",
        stdout_writer.buffered(),
    );
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;
extern "c" fn unsetenv(name: [*:0]const u8) c_int;

fn writeTopLevelReportFixture(io: std.Io, allocator: std.mem.Allocator, workspace_root: []const u8) ![]u8 {
    const core = @import("ryk_core").core;
    const core_api = @import("ryk_core").api;
    const now = core.time.Timestamp.fromUnixSeconds(1_777_983_130);
    var session_id: core.session.SessionId = .{ .value = undefined, .len = 0 };
    const session_id_text = try std.fmt.bufPrint(&session_id.value, "report-output-fixture", .{});
    session_id.len = session_id_text.len;
    const session = core.session.Session{
        .id = session_id,
        .started_at = now,
        .ended_at = now,
        .command = "ryk",
        .args = &.{ "run", "--", "rm", "-rf", "./fixture" },
        .workspace_root = workspace_root,
        .session_name = "report-output-test",
        .mode = .strict,
        .platform = core.platform.detectOs(),
    };
    var audit_writer = try core_api.createAuditWriter(io, allocator, session);
    defer audit_writer.deinit();
    var event_id: core.event.EventId = .{ .value = undefined, .len = 0 };
    const event_id_text = try std.fmt.bufPrint(&event_id.value, "denied", .{});
    event_id.len = event_id_text.len;
    const event = try core_api.createAuditEvent(.{
        .session_id = session.id,
        .event_id = event_id,
        .timestamp = now,
        .event_type = .command_denied,
        .actor = .{ .kind = .ryk, .display = "ryk" },
        .target = .{ .kind = .command, .value = "rm -rf ./fixture" },
        .decision = core_api.makeDecision(.{ .result = .deny, .reason = "blocked by fixture policy", .rule_id = "commands.deny" }),
        .redactions = .{ .count = 1, .labels = &.{"fixture-label"} },
    });
    try core_api.appendAuditEvent(&audit_writer, event);
    try audit_writer.writeLastPointer();
    try core_api.writeAuditSummary(allocator, audit_writer.sessionDirPath(), .{
        .session = session,
        .status = .{ .exited = 1 },
        .event_count = audit_writer.event_count,
        .final_event_hash = audit_writer.finalHash() orelse "",
        .policy = ".ryk/policy.yaml",
        .product_label = brand.product_display,
    });
    return allocator.dupe(u8, audit_writer.session_id.slice());
}

test "top-level report exports preserve exact generated bytes" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const previous_xdg: ?[:0]u8 = if (std.c.getenv("XDG_CONFIG_HOME")) |value|
        try std.testing.allocator.dupeZ(u8, std.mem.sliceTo(value, 0))
    else
        null;
    defer {
        if (previous_xdg) |value| {
            _ = setenv("XDG_CONFIG_HOME", value, 1);
            std.testing.allocator.free(value);
        } else _ = unsetenv("XDG_CONFIG_HOME");
    }
    const previous_path: ?[:0]u8 = if (std.c.getenv("PATH")) |value|
        try std.testing.allocator.dupeZ(u8, std.mem.sliceTo(value, 0))
    else
        null;
    defer {
        if (previous_path) |value| {
            _ = setenv("PATH", value, 1);
            std.testing.allocator.free(value);
        } else _ = unsetenv("PATH");
    }
    try std.testing.expectEqual(@as(c_int, 0), setenv("XDG_CONFIG_HOME", root, 1));
    try std.testing.expectEqual(@as(c_int, 0), setenv("PATH", "", 1));
    try tmp.dir.createDirPath(std.testing.io, ".ryk");
    {
        const policy_file = try tmp.dir.createFile(std.testing.io, ".ryk/policy.yaml", .{});
        defer policy_file.close(std.testing.io);
        try policy_file.writeStreamingAll(std.testing.io, "version: 1\nmode: strict\n");
    }
    const session_id = try writeTopLevelReportFixture(std.testing.io, std.testing.allocator, root);
    defer std.testing.allocator.free(session_id);
    const previous_cwd = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(previous_cwd);
    try std.process.setCurrentDir(std.testing.io, tmp.dir);
    defer std.process.setCurrentPath(std.testing.io, previous_cwd) catch {};

    const expected_markdown =
        \\# ryk Safety Report: report-output-fixture
        \\
        \\- Session id: `report-output-fixture`
        \\- Command: `ryk run -- rm -rf ./fixture`
        \\- Status: exit 1
        \\- Policy path: .ryk/policy.yaml
        \\- Hash-chain verification: verified
        \\- Denied/prevented actions: 1
        \\- Redactions: 1 (fixture-label)
        \\
        \\## What ryk Prevented
        \\
        \\ryk prevented 1 action from continuing because the active local policy denied them.
        \\
        \\- `rm -rf ./fixture` was blocked. Reason: blocked by fixture policy
        \\
        \\## Plugin Readiness
        \\
        \\- OpenClaw: host not detected, integration missing
        \\- Hermes: host not detected, integration missing
        \\
    ;
    const expected_json =
        \\{"session_id":"report-output-fixture","command":"ryk run -- rm -rf ./fixture","status":"exit 1","policy_path":".ryk/policy.yaml","hash_chain_verified":true,"denied_count":1,"redactions":{"count":1,"labels":["fixture-label"]},"denied_actions":[{"event_type":"command_denied","target":"rm -rf ./fixture","reason":"blocked by fixture policy"}],"plugins":[{"id":"openclaw","host_detected":false,"integration_present":false},{"id":"hermes","host_detected":false,"integration_present":false}]}
        \\
    ;

    var stdout_buf: [8192]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout: std.Io.Writer = .fixed(&stdout_buf);
    var stderr: std.Io.Writer = .fixed(&stderr_buf);
    // Default is the rich human report (plain text under tests — no colour escapes).
    try std.testing.expectEqual(exit_codes.success, try testRun(&.{ "report", "--session", session_id }, &stdout, &stderr));
    try std.testing.expect(std.mem.indexOf(u8, stdout.buffered(), "safety report") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout.buffered(), "What ryk stopped") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout.buffered(), "rm -rf ./fixture") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout.buffered(), "[DENY]") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout.buffered(), "fixture-label") != null);
    try std.testing.expect(std.mem.indexOfScalar(u8, stdout.buffered(), 0x1b) == null);
    try std.testing.expectEqualStrings("", stderr.buffered());

    // Explicit --format human matches the default surface.
    stdout = .fixed(&stdout_buf);
    stderr = .fixed(&stderr_buf);
    try std.testing.expectEqual(exit_codes.success, try testRun(
        &.{ "report", "--session", session_id, "--format", "human" },
        &stdout,
        &stderr,
    ));
    try std.testing.expect(std.mem.indexOf(u8, stdout.buffered(), "safety report") != null);
    try std.testing.expectEqualStrings("", stderr.buffered());

    inline for (.{
        .{ .argv = &.{ "report", "--session", session_id, "--format", "markdown" }, .expected = expected_markdown },
        .{ .argv = &.{ "report", "--session", session_id, "--format", "json" }, .expected = expected_json },
    }) |case| {
        stdout = .fixed(&stdout_buf);
        stderr = .fixed(&stderr_buf);
        try std.testing.expectEqual(exit_codes.success, try testRunWithCwd(tmp.dir, case.argv, &stdout, &stderr));
        try std.testing.expectEqualStrings(case.expected, stdout.buffered());
        try std.testing.expectEqualStrings("", stderr.buffered());
    }
    stdout = .fixed(&stdout_buf);
    stderr = .fixed(&stderr_buf);
    try std.testing.expectEqual(exit_codes.success, try testRun(&.{ "report", "--session", session_id, "--format", "json" }, &stdout, &stderr));
    try std.testing.expectEqualStrings(expected_json, stdout.buffered());
    try std.testing.expectEqualStrings("", stderr.buffered());
}

test "banner suppressed on machine proxy path (packs --format json)" {
    // Live packs --json dumps the full oracle catalog (>>1KiB).
    var stdout_buf: [256 * 1024]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    _ = try testRun(&.{ "packs", "--format", "json" }, &stdout_writer, &stderr_writer);
    // Machine path must not emit a brand banner to stdout (byte-identity).
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "\u{1F6E1}  ryk") == null);
}

test "decide human mode gets a banner while default JSON remains machine output" {
    try std.testing.expect(shouldShowBanner("decide", &.{ "decide", "command", "--human", "--json", "{}" }));
    try std.testing.expect(!shouldShowBanner("decide", &.{ "decide", "command", "--json", "{}" }));
    try std.testing.expect(!shouldShowBanner("decide", &.{ "decide", "command", "--human", "--stdin", "--help" }));
}

test "decide human mode honors no-rich without changing default machine JSON" {
    var baseline_buf: [4096]u8 = undefined;
    var machine_buf: [4096]u8 = undefined;
    var human_buf: [4096]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var baseline: std.Io.Writer = .fixed(&baseline_buf);
    var machine: std.Io.Writer = .fixed(&machine_buf);
    var human: std.Io.Writer = .fixed(&human_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const payload = "{\"command\":\"echo hello\"}";

    // Compare --no-rich machine JSON to the default machine path. Do not pin a
    // full decide fixture here: discovery depends on workspace/user policy, and
    // this test is only about presentation flags not altering machine output.
    try std.testing.expectEqual(exit_codes.success, try testRun(&.{ "decide", "command", "--json", payload }, &baseline, &stderr_writer));
    stderr_writer = .fixed(&stderr_buf);
    try std.testing.expectEqual(exit_codes.success, try testRun(&.{ "--no-rich", "decide", "command", "--json", payload }, &machine, &stderr_writer));
    try std.testing.expectEqualStrings(baseline.buffered(), machine.buffered());
    try std.testing.expect(std.mem.indexOf(u8, machine.buffered(), "\"decision\": \"allow\"") != null);

    stderr_writer = .fixed(&stderr_buf);
    try std.testing.expectEqual(exit_codes.success, try testRun(&.{ "--no-rich", "decide", "command", "--human", "--json", payload }, &human, &stderr_writer));
    try std.testing.expect(std.mem.indexOf(u8, human.buffered(), "[ALLOW]") != null);
    try std.testing.expect(std.mem.indexOfScalar(u8, human.buffered(), 0x1b) == null);
}

test "global --no-rich is consumed without changing version JSON contract" {
    var baseline_buf: [4096]u8 = undefined;
    var escaped_buf: [4096]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var baseline: std.Io.Writer = .fixed(&baseline_buf);
    var escaped: std.Io.Writer = .fixed(&escaped_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    try std.testing.expectEqual(exit_codes.success, try testRun(&.{ "version", "--json" }, &baseline, &stderr_writer));
    stderr_writer = .fixed(&stderr_buf);
    try std.testing.expectEqual(exit_codes.success, try testRun(&.{ "--no-rich", "version", "--json" }, &escaped, &stderr_writer));
    try std.testing.expectEqualStrings(baseline.buffered(), escaped.buffered());
}

test "global flag parser consumes no-rich before or after the command" {
    const allocator = std.testing.allocator;

    const prefix = try parseGlobalArgs(allocator, &.{ "--no-rich", "version", "--json" });
    defer if (prefix.owned) allocator.free(prefix.argv);
    try std.testing.expect(prefix.no_rich);
    try std.testing.expectEqual(@as(usize, 2), prefix.argv.len);
    try std.testing.expectEqualStrings("version", prefix.argv[0]);

    const suffix = try parseGlobalArgs(allocator, &.{ "version", "--no-rich", "--json" });
    defer if (suffix.owned) allocator.free(suffix.argv);
    try std.testing.expect(suffix.no_rich);
    try std.testing.expectEqual(@as(usize, 2), suffix.argv.len);
    try std.testing.expectEqualStrings("version", suffix.argv[0]);
    try std.testing.expectEqualStrings("--json", suffix.argv[1]);

    // After `--`, `--no-rich` is child argv and must not be consumed.
    const literal = try parseGlobalArgs(allocator, &.{ "run", "--", "echo", "--no-rich" });
    defer if (literal.owned) allocator.free(literal.argv);
    try std.testing.expect(!literal.no_rich);
    try std.testing.expectEqual(@as(usize, 4), literal.argv.len);

    // Opaque payload values are a single argv element, not the flag.
    const value = try parseGlobalArgs(allocator, &.{ "decide", "command", "--json", "{\"value\":\"--no-rich\"}" });
    defer if (value.owned) allocator.free(value.argv);
    try std.testing.expect(!value.no_rich);
}

test "RYK_NO_RICH truthy variants suppress presentation without changing machine JSON" {
    const variants = [_][]const u8{ "1", "true", "yes" };
    for (variants) |variant| {
        var env_map = try std.process.Environ.createMap(std.process.Environ.empty, std.testing.allocator);
        defer env_map.deinit();
        try env_map.put("RYK_NO_RICH", variant);
        var stdout_buf: [4096]u8 = undefined;
        var stderr_buf: [256]u8 = undefined;
        var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
        var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
        try std.testing.expectEqual(exit_codes.success, try run(std.testing.io, &env_map, &.{ "version", "--json" }, &stdout_writer, &stderr_writer));
        try std.testing.expect(stdout_writer.buffered().len > 0 and stdout_writer.buffered()[0] == '{');
        try std.testing.expect(std.mem.indexOfScalar(u8, stdout_writer.buffered(), 0x1b) == null);
        try std.testing.expectEqualStrings("", stderr_writer.buffered());
    }
}

test "banner suppressed on command-specific help (help run)" {
    var stdout_buf: [8192]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try testRun(&.{ "help", "run" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    const out = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "ryk run") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\u{1F6E1}  ryk") == null);
}

test "banner suppressed on subcommand --help (doctor --help)" {
    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try testRun(&.{ "doctor", "--help" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    const out = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "ryk doctor") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\u{1F6E1}  ryk") == null);
}

// ---------------------------------------------------------------------------
// TDD tests for "Did you mean?" suggestions (written FIRST — RED, foundation work)
// ---------------------------------------------------------------------------

test "unknown command suggests typo correction" {
    // "docter" should suggest "doctor" via Levenshtein distance
    const suggestion = suggestCommand("docter");
    try std.testing.expect(suggestion != null);
    try std.testing.expectEqualStrings("doctor", suggestion.?);
}

test "unknown command suggests prefix match" {
    // Prefix match takes priority
    const suggestion = suggestCommand("do");
    try std.testing.expect(suggestion != null);
    // "doctor" or "stop" etc. are valid; just ensure something returned
    try std.testing.expect(suggestion.?.len > 0);
}

test "top-level command suggestions reject ambiguous short prefixes" {
    try std.testing.expect(suggestCommand("") == null);
    try std.testing.expect(suggestCommand("p") == null);
    try std.testing.expectEqualStrings("doctor", suggestCommand("doctor").?);
}

test "completely unknown command has no suggestion" {
    const suggestion = suggestCommand("xyz123neveracmd");
    try std.testing.expect(suggestion == null);
}

test "init dispatch creates policy in provided working directory" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var stdout_buf: [512]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try testRunWithCwd(tmp.dir, &.{ "init", "--mode", "strict" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);

    const policy_text = try tmp.dir.readFileAlloc(std.testing.io, ".ryk/policy.yaml", std.testing.allocator, .limited(16 * 1024));
    defer std.testing.allocator.free(policy_text);
    try std.testing.expect(std.mem.indexOf(u8, policy_text, "mode: strict") != null);
}

test "doctor dispatch prints summary by default" {
    var stdout_buf: [8192]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try testRun(&.{"doctor"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "Summary:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Capabilities:") == null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "doctor dispatch --verbose prints platform capabilities" {
    var stdout_buf: [8192]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try testRun(&.{ "doctor", "--verbose" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "Capabilities:") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "network policy engine: active") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "start dispatch appears in help and runs with --auto --skip-verify (no protection flag)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var stdout_buf: [16384]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const help_code = try testRun(&.{"--help"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, help_code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "start") != null);

    stdout_writer = .fixed(&stdout_buf);
    stderr_writer = .fixed(&stderr_buf);
    // Public path: no --protection. Exit may be general if daemon unavailable on the host.
    const code = try testRunWithCwd(tmp.dir, &.{ "start", "--auto", "--skip-verify" }, &stdout_writer, &stderr_writer);
    const output = stdout_writer.buffered();
    try std.testing.expect(code == exit_codes.success or code == exit_codes.general);
    try std.testing.expect(std.mem.indexOf(u8, output, "\u{1F6E1}  ryk") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Ask on risk") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Choose your protection mode") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "command-guard") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Maximum Protection") == null);
}

test "start auto-runs on non-TTY without --auto and without protection flag" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var stdout_buf: [16384]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try testRunWithCwd(tmp.dir, &.{ "start", "--skip-verify" }, &stdout_writer, &stderr_writer);
    const output = stdout_writer.buffered();
    try std.testing.expect(code == exit_codes.success or code == exit_codes.general);
    try std.testing.expect(std.mem.indexOf(u8, output, "\u{1F6E1}  ryk") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Ask on risk") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Choose your protection mode") == null);
}

test "start rejects public --protection flag with usage" {
    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [1024]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try testRun(&.{ "start", "--auto", "--protection", "firewall", "--skip-verify" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "unknown option") != null or std.mem.indexOf(u8, stderr_writer.buffered(), "--protection") != null);
}

test "quickstart dispatch is hard-removed and points to ryk start" {
    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [1024]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try testRun(&.{"quickstart"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "ryk start") != null);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "removed") != null or std.mem.indexOf(u8, stderr_writer.buffered(), "Use") != null);
}

test "setup dispatch is hard-removed and points to ryk start" {
    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [1024]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try testRun(&.{"setup"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "ryk start") != null);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "removed") != null or std.mem.indexOf(u8, stderr_writer.buffered(), "Use") != null);
}

test "agents is the only public unattended workflow command" {
    var stdout_buf: [8192]u8 = undefined;
    var stderr_buf: [2048]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const help_code = try testRun(&.{ "help", "agents" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, help_code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "ryk agents setup") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "ryk unattended") == null);

    stdout_writer = .fixed(&stdout_buf);
    stderr_writer = .fixed(&stderr_buf);
    const old_code = try testRun(&.{"unattended"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, old_code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "ryk agents") != null);
}

test "telemetry --help writes help to stdout" {
    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const code = try testRun(&.{ "telemetry", "--help" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "telemetry") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "disable confirmation names the invoked command" {
    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const code = try testRun(&.{"disable"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "ryk disable:") != null);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "ryk stop:") == null);
}

test "stop dispatch is the public disable command" {
    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const help_code = try testRun(&.{ "help", "stop" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, help_code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "ryk stop") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "cursor") != null);

    stdout_writer = .fixed(&stdout_buf);
    stderr_writer = .fixed(&stderr_buf);
    const code = try testRun(&.{ "stop", "-all" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "ryk stop") != null);
}

test "completions dispatch prints shell script" {
    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try testRun(&.{ "completions", "bash" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "complete -F") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "policy command rejects unknown subcommands" {
    var stdout_buf: [256]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try testRun(&.{ "policy", "--bad" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, code);
    // The brand banner opens the command (presentation only); the usage error
    // still goes to stderr.
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "\u{1F6E1}  ryk") != null);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "unknown subcommand") != null);
}

test "run dispatch launches child command" {
    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try run_command.commandForTest(&.{ "--os-sandbox", "off", "--", "zig", "version" }, &stdout_writer, &stderr_writer, .ignore);
    try std.testing.expectEqual(exit_codes.success, code);
    // Phase 2: printSessionStart now renders the shared brand banner + key-value
    // grid (the hand-rolled shield line is retired). The session shield +
    // first-run celebration remain in printSessionEnd.
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "\u{1F6E1}  ryk") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "watching this session") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "Session ended cleanly") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "OS sandbox: disabled") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

// ---------------------------------------------------------------------------
// Phase 3 TDD tests: messaging and help text updates for guided onboarding
// These tests are written FIRST (RED). They will fail until help text is updated
// to describe the new default guided behavior and de-emphasize --yes.
// ---------------------------------------------------------------------------

test "start help does not advertise protection grade menu or --protection" {
    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try testRun(&.{ "help", "start" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "ryk start") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "--protection") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "command-guard") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "firewall") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "maximum") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Choose your protection") == null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "plugin help and disable re-enable messaging de-emphasize --yes in favor of start" {
    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try testRun(&.{ "help", "plugin" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);

    const output = stdout_writer.buffered();
    // One-click repair is doctor --fix; guided multi-select remains ryk start. Setup removed.
    try std.testing.expect(std.mem.indexOf(u8, output, "ryk start") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "doctor --fix") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "ryk setup") == null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

// writeInstallEnv — the trustworthy, layout-aware activation printer for installers,
// Homebrew post-install, npm wrappers, power users, and `eval "$(ryk env)"`.
// Uses the running binary's actual location (selfExePath) so custom prefixes
// (Homebrew, containers, non-~ installs) produce correct exports. Falls back to
// documented platform defaults. Windows uses cmd.exe set syntax; Unix uses sh export.
// Concrete absolute paths (not $HOME) guarantee "actual install layout" fidelity.
fn writeInstallEnv(io: std.Io, stdout: anytype) !void {
    const allocator = std.heap.page_allocator;
    const exe_path = std.process.executablePathAlloc(io, allocator) catch {
        // Fallback (static or exotic exe path): documented defaults per platform.
        if (builtin.os.tag == .windows) {
            try stdout.writeAll("set \"PATH=%USERPROFILE%\\.ryk\\bin;%PATH%\"\n");
            try stdout.writeAll("set \"RYK_RESOURCE_ROOT=%USERPROFILE%\\.ryk\\share\\current\"\n");
        } else {
            try stdout.writeAll("export PATH=\"$HOME/.local/bin:$PATH\"\n");
            try stdout.writeAll("export RYK_RESOURCE_ROOT=\"$HOME/.local/share/ryk/current\"\n");
        }
        return;
    };
    defer allocator.free(exe_path);

    const bin_dir = std.fs.path.dirname(exe_path) orelse {
        // Same fallback as above.
        if (builtin.os.tag == .windows) {
            try stdout.writeAll("set \"PATH=%USERPROFILE%\\.ryk\\bin;%PATH%\"\n");
            try stdout.writeAll("set \"RYK_RESOURCE_ROOT=%USERPROFILE%\\.ryk\\share\\current\"\n");
        } else {
            try stdout.writeAll("export PATH=\"$HOME/.local/bin:$PATH\"\n");
            try stdout.writeAll("export RYK_RESOURCE_ROOT=\"$HOME/.local/share/ryk/current\"\n");
        }
        return;
    };

    const prefix_dir = std.fs.path.dirname(bin_dir) orelse bin_dir;

    const is_win = builtin.os.tag == .windows;
    const resource_root = if (is_win)
        std.fs.path.join(allocator, &.{ prefix_dir, "share", "current" }) catch {
            // Fallback on join failure (extremely rare).
            try stdout.writeAll("set \"PATH=%USERPROFILE%\\.ryk\\bin;%PATH%\"\n");
            try stdout.writeAll("set \"RYK_RESOURCE_ROOT=%USERPROFILE%\\.ryk\\share\\current\"\n");
            return;
        }
    else
        std.fs.path.join(allocator, &.{ prefix_dir, "share", "ryk", "current" }) catch {
            try stdout.writeAll("export PATH=\"$HOME/.local/bin:$PATH\"\n");
            try stdout.writeAll("export RYK_RESOURCE_ROOT=\"$HOME/.local/share/ryk/current\"\n");
            return;
        };
    defer allocator.free(resource_root);

    if (is_win) {
        try stdout.print("set \"PATH={s};%PATH%\"\n", .{bin_dir});
        try stdout.print("set \"RYK_RESOURCE_ROOT={s}\"\n", .{resource_root});
    } else {
        try stdout.print("export PATH=\"{s}:$PATH\"\n", .{bin_dir});
        try stdout.print("export RYK_RESOURCE_ROOT=\"{s}\"\n", .{resource_root});
    }
}

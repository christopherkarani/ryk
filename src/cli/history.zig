const std = @import("std");
const exit_codes = @import("exit_codes.zig");
const contracts = @import("daemon_contracts.zig");
const tui = @import("ryk").tui;
const enable_tui = @import("build_options").enable_tui;

pub fn command(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    return commandWithExecutor(realExecute, io, argv, stdout, stderr);
}

fn realExecute(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    const cli = @import("mod.zig");
    return cli.executeDaemonCli(io, argv, stdout, stderr);
}

pub fn commandWithExecutor(comptime execute_cli: anytype, io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    if (argv.len == 0 or isHelp(argv)) {
        try writeHelp(stdout);
        return exit_codes.success;
    }
    // Day-2 loop discoverability: `ryk history suggest` → suggest-allowlist.
    if (std.mem.eql(u8, argv[0], "suggest")) {
        const allocator = std.heap.smp_allocator;
        const daemon_argv = try allocator.alloc([]const u8, argv.len);
        defer allocator.free(daemon_argv);
        daemon_argv[0] = "suggest-allowlist";
        if (argv.len > 1) @memcpy(daemon_argv[1..], argv[1..]);
        return execute_cli(io, daemon_argv, stdout, stderr);
    }
    // Phase 7: --live is an opt-in alt-screen view of the current stats snapshot.
    // Intercept before the stats/passthrough split so --live is never forwarded to
    // the daemon. True command-level live-poll is a documented follow-up (it would
    // need a Zig-side daemon-history parser, risking the frozen --json contract).
    if (isLiveRequest(argv)) return renderLiveStats(execute_cli, io, argv, stdout, stderr);
    if (!isHumanStats(argv)) return passThrough(execute_cli, io, argv, stdout, stderr);

    const allocator = std.heap.smp_allocator;
    const daemon_argv = try allocator.alloc([]const u8, argv.len + 2);
    defer allocator.free(daemon_argv);
    daemon_argv[0] = "history";
    @memcpy(daemon_argv[1 .. argv.len + 1], argv);
    daemon_argv[daemon_argv.len - 1] = "--json";

    var daemon_stdout: std.Io.Writer.Allocating = .init(allocator);
    defer daemon_stdout.deinit();
    var daemon_stderr: std.Io.Writer.Allocating = .init(allocator);
    defer daemon_stderr.deinit();
    const code = try execute_cli(io, daemon_argv, &daemon_stdout.writer, &daemon_stderr.writer);
    if (code != exit_codes.success) {
        try stdout.writeAll(daemon_stdout.written());
        try stderr.writeAll(daemon_stderr.written());
        return code;
    }

    var parsed = contracts.parseHistoryStats(allocator, daemon_stdout.written()) catch |err| {
        try stderr.print("ryk history: daemon returned invalid structured data ({s}). Run 'ryk doctor'.\n", .{@errorName(err)});
        return exit_codes.general;
    };
    defer parsed.deinit();
    return renderHumanAlloc(allocator, io, parsed.value, stdout);
}

fn passThrough(comptime execute_cli: anytype, io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    const allocator = std.heap.smp_allocator;
    const daemon_argv = try allocator.alloc([]const u8, argv.len + 1);
    defer allocator.free(daemon_argv);
    daemon_argv[0] = "history";
    @memcpy(daemon_argv[1..], argv);
    return execute_cli(io, daemon_argv, stdout, stderr);
}

/// Render the current `history stats` snapshot. On an interactive colour TTY
/// this is the alt-screen viewer; otherwise the same linear human stats (exit
/// as linear `history stats` would). `--json`/`--robot` stay a machine conflict.
fn renderLiveStats(comptime execute_cli: anytype, io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    for (argv) |arg| {
        if (std.mem.eql(u8, arg, "--json") or std.mem.eql(u8, arg, "--robot")) {
            try stderr.writeAll("ryk history: --live cannot be combined with --json/--robot (machine output is frozen).\n");
            return exit_codes.usage;
        }
    }
    // Colour TTY plus no presentation escape. Honour `--plain` / `--no-rich`
    // as linear (issue #217). Do not treat leftover `--format json` as a TUI
    // escape — that reopens a human/machine mash. `--json`/`--robot` stay
    // rejected above.
    const enter_tui = (comptime enable_tui) and tui.theme.active(io, stdout).capability.hasColor() and
        !argvHasPresentationEscape(argv);

    const allocator = std.heap.smp_allocator;
    const live_args = try buildLiveStatsArgv(allocator, argv);
    defer allocator.free(live_args);
    const daemon_argv = try allocator.alloc([]const u8, live_args.len + 1);
    defer allocator.free(daemon_argv);
    daemon_argv[0] = "history";
    @memcpy(daemon_argv[1..], live_args);

    var daemon_stdout: std.Io.Writer.Allocating = .init(allocator);
    defer daemon_stdout.deinit();
    var daemon_stderr: std.Io.Writer.Allocating = .init(allocator);
    defer daemon_stderr.deinit();
    const code = try execute_cli(io, daemon_argv, &daemon_stdout.writer, &daemon_stderr.writer);
    if (code != exit_codes.success) {
        try stdout.writeAll(daemon_stdout.written());
        try stderr.writeAll(daemon_stderr.written());
        return code;
    }

    var parsed = contracts.parseHistoryStats(allocator, daemon_stdout.written()) catch |err| {
        try stderr.print("ryk history: daemon returned invalid structured data ({s}). Run 'ryk doctor'.\n", .{@errorName(err)});
        return exit_codes.general;
    };
    defer parsed.deinit();

    if (!enter_tui) {
        if (comptime enable_tui) {
            try stderr.writeAll("ryk history: --live requires an interactive TTY; using linear report.\n");
        } else {
            try stderr.writeAll("ryk history: --live requires a TUI-enabled ryk build; using linear report.\n");
        }
        return renderHumanAlloc(allocator, io, parsed.value, stdout);
    }

    // Render the human form into a buffer, then split into lines for the viewer.
    // This reuses the canonical stats renderer so the live view carries exactly
    // the same information as the linear form (no divergence to maintain).
    var human_buf: std.Io.Writer.Allocating = .init(allocator);
    defer human_buf.deinit();
    _ = try renderHumanAlloc(allocator, io, parsed.value, &human_buf.writer);
    const lines = try splitLines(allocator, human_buf.written());
    defer freeLines(allocator, lines);

    if (comptime enable_tui) {
        try tui.live_view.run(io, stdout, "history · stats", lines, null, null);
    }
    return exit_codes.success;
}

/// Split `text` on newlines into owned line slices (empty trailing line dropped).
fn splitLines(allocator: std.mem.Allocator, text: []const u8) ![][]const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (out.items) |line| allocator.free(line);
        out.deinit(allocator);
    }
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| {
        // Drop a single trailing empty line produced by the trailing '\n'.
        if (line.len == 0 and it.peek() == null) break;
        try out.append(allocator, try allocator.dupe(u8, line));
    }
    return try out.toOwnedSlice(allocator);
}

fn freeLines(allocator: std.mem.Allocator, lines: [][]const u8) void {
    for (lines) |line| allocator.free(line);
    allocator.free(lines);
}

fn isHelp(argv: []const []const u8) bool {
    return argv.len == 1 and (std.mem.eql(u8, argv[0], "--help") or std.mem.eql(u8, argv[0], "-h"));
}

/// True when `--live` appears in argv (and this isn't a --help request). The
/// alt-screen view is handled in Zig; --live never reaches the daemon.
fn isLiveRequest(argv: []const []const u8) bool {
    for (argv) |arg| {
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) return false;
        if (std.mem.eql(u8, arg, "--live")) return true;
    }
    return false;
}

fn argvHasPresentationEscape(argv: []const []const u8) bool {
    for (argv) |arg| {
        if (std.mem.eql(u8, arg, "--plain") or std.mem.eql(u8, arg, "--no-rich")) return true;
    }
    return false;
}

/// Pure: build the daemon argv for the --live stats snapshot, dropping `--live`,
/// normalising a leading `stats`, and appending `--json`. Returns the args
/// AFTER the `history` subcommand (the caller prepends `history`). Unit-tested.
fn buildLiveStatsArgv(allocator: std.mem.Allocator, argv: []const []const u8) ![][]const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    errdefer out.deinit(allocator);
    try out.append(allocator, "stats");
    var saw_stats = false;
    for (argv) |arg| {
        if (std.mem.eql(u8, arg, "--live")) continue; // never forwarded
        // Presentation escapes are not history-stats flags; do not forward.
        if (std.mem.eql(u8, arg, "--plain") or std.mem.eql(u8, arg, "--no-rich")) continue;
        if (!saw_stats and std.mem.eql(u8, arg, "stats")) {
            saw_stats = true; // drop a leading stats (we prepended one above)
            continue;
        }
        try out.append(allocator, arg);
    }
    try out.append(allocator, "--json");
    return try out.toOwnedSlice(allocator);
}

fn isHumanStats(argv: []const []const u8) bool {
    if (!std.mem.eql(u8, argv[0], "stats")) return false;
    for (argv[1..]) |arg| {
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h") or
            std.mem.eql(u8, arg, "--json") or std.mem.eql(u8, arg, "--robot") or
            std.mem.eql(u8, arg, "--format") or std.mem.startsWith(u8, arg, "--format=")) return false;
    }
    return true;
}

fn writeHelp(stdout: anytype) !void {
    try stdout.writeAll(
        \\Query command history tracked by ryk.
        \\
        \\Usage: ryk history <action> [options] [--live]
        \\
        \\Actions:
        \\  stats        Show outcomes, patterns, projects, and agents
        \\  check        Check history database health
        \\  analyze      Analyze denials and recommendations
        \\  suggest      Suggest allowlist entries from denials (alias of suggest-allowlist)
        \\  interactive  Review prior decisions
        \\  export       Export command history
        \\  prune        Remove old entries
        \\  backup       Back up the history database
        \\
        \\Day-2 policy loop:
        \\  ryk history stats
        \\  ryk history suggest          # or: ryk suggest-allowlist
        \\  ryk suggest-allowlist --apply N
        \\  ryk allowlist add-command …  # from high-confidence examples
        \\
        \\Examples:
        \\  ryk history stats --days 7
        \\  ryk history stats --json
        \\  ryk history suggest --confidence high
        \\  ryk history check --strict
        \\  ryk history --live
        \\
        \\Options:
        \\  --live       Open a scrollable alt-screen stats view (TTY only; not with --json/--robot)
        \\
    );
}

test "history suggest routes to suggest-allowlist argv" {
    var out: [256]u8 = undefined;
    var err: [64]u8 = undefined;
    var stdout: std.Io.Writer = .fixed(&out);
    var stderr: std.Io.Writer = .fixed(&err);

    const code = try commandWithExecutor(fakeSuggestAllowlist, std.testing.io, &.{ "suggest", "--confidence", "high" }, &stdout, &stderr);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expectEqualStrings("suggest-allowlist ok\n", stdout.buffered());
    try std.testing.expectEqualStrings("", stderr.buffered());
}

fn fakeSuggestAllowlist(_: std.Io, argv: []const []const u8, stdout: anytype, _: anytype) !u8 {
    try std.testing.expectEqualSlices([]const u8, &.{ "suggest-allowlist", "--confidence", "high" }, argv);
    try stdout.writeAll("suggest-allowlist ok\n");
    return exit_codes.success;
}

fn renderHumanAlloc(allocator: std.mem.Allocator, io: std.Io, stats: contracts.HistoryStats, stdout: anytype) !u8 {
    if (stats.total_commands == 0) {
        const body = try std.fmt.allocPrint(allocator, "ryk hasn't seen any shell commands in the last {d} days.\n\n" ++
            "Run your first protected session to start building history:\n" ++
            "  → ryk run -- echo \"hello world\"\n" ++
            "  → ryk run -- npm install\n\n" ++
            "History powers the dashboard, replay, and pack recommendations.", .{stats.period_days});
        defer allocator.free(body);
        try tui.render.callout(io, stdout, .info, "No commands tracked yet", body);
        return exit_codes.success;
    }

    const period = try std.fmt.allocPrint(allocator, "last {d} days", .{stats.period_days});
    defer allocator.free(period);
    const total = try std.fmt.allocPrint(allocator, "{d}", .{stats.total_commands});
    defer allocator.free(total);
    const blocked = try std.fmt.allocPrint(allocator, "{d:.2}%", .{stats.block_rate * 100.0});
    defer allocator.free(blocked);
    try tui.render.keyValue(io, stdout, &.{
        .{ .label = "Period", .value = period },
        .{ .label = "Commands", .value = total },
        .{ .label = "Block rate", .value = blocked },
    });

    const allowed = try std.fmt.allocPrint(allocator, "{d}", .{stats.outcomes.allowed});
    defer allocator.free(allowed);
    const denied = try std.fmt.allocPrint(allocator, "{d}", .{stats.outcomes.denied});
    defer allocator.free(denied);
    const warned = try std.fmt.allocPrint(allocator, "{d}", .{stats.outcomes.warned});
    defer allocator.free(warned);
    const bypassed = try std.fmt.allocPrint(allocator, "{d}", .{stats.outcomes.bypassed});
    defer allocator.free(bypassed);
    const outcome_values = [_][]const u8{ allowed, denied, warned, bypassed };
    const outcome_rows = [_][]const []const u8{&outcome_values};
    try tui.render.table(io, stdout, &.{ .{ .name = "ALLOWED" }, .{ .name = "DENIED" }, .{ .name = "WARNED" }, .{ .name = "BYPASSED" } }, &outcome_rows);

    try renderPatterns(allocator, io, stats.top_patterns, stdout);
    try renderNamedCounts(allocator, io, stats.agents, "AGENT", stdout);
    try renderProjects(allocator, io, stats.top_projects, stdout);

    if (stats.outcomes.denied > 0) {
        try tui.render.callout(io, stdout, .info, "Next", "Turn denials into policy:\n  → ryk history suggest\n  → ryk suggest-allowlist --confidence high\n  → ryk allowlist add-command \"…\" -r \"reason\"");
    }
    return exit_codes.success;
}

fn renderPatterns(allocator: std.mem.Allocator, io: std.Io, source: []const contracts.PatternStat, stdout: anytype) !void {
    if (source.len == 0) return;
    const items = try allocator.dupe(contracts.PatternStat, source);
    defer allocator.free(items);
    std.mem.sort(contracts.PatternStat, items, {}, patternLessThan);
    var rows: std.ArrayListUnmanaged([]const []const u8) = .empty;
    defer rows.deinit(allocator);
    var owned: std.ArrayListUnmanaged([]u8) = .empty;
    defer {
        for (owned.items) |v| allocator.free(v);
        owned.deinit(allocator);
    }
    defer for (rows.items) |row| allocator.free(row);
    for (items) |item| {
        const cells = try allocator.alloc([]const u8, 3);
        errdefer allocator.free(cells);
        cells[0] = try ownSanitized(allocator, &owned, item.name);
        cells[1] = try ownSanitized(allocator, &owned, item.pack_id orelse "—");
        cells[2] = try ownPrint(allocator, &owned, "{d}", .{item.count});
        try rows.append(allocator, cells);
    }
    try tui.render.table(io, stdout, &.{ .{ .name = "PATTERN" }, .{ .name = "PACK" }, .{ .name = "COUNT" } }, rows.items);
}

fn renderNamedCounts(allocator: std.mem.Allocator, io: std.Io, source: []const contracts.AgentStat, comptime label: []const u8, stdout: anytype) !void {
    if (source.len == 0) return;
    const items = try allocator.dupe(contracts.AgentStat, source);
    defer allocator.free(items);
    std.mem.sort(contracts.AgentStat, items, {}, agentLessThan);
    var rows: std.ArrayListUnmanaged([]const []const u8) = .empty;
    defer rows.deinit(allocator);
    var owned: std.ArrayListUnmanaged([]u8) = .empty;
    defer {
        for (owned.items) |v| allocator.free(v);
        owned.deinit(allocator);
    }
    defer for (rows.items) |row| allocator.free(row);
    for (items) |item| {
        const cells = try allocator.alloc([]const u8, 2);
        errdefer allocator.free(cells);
        cells[0] = try ownSanitized(allocator, &owned, item.name);
        cells[1] = try ownPrint(allocator, &owned, "{d}", .{item.count});
        try rows.append(allocator, cells);
    }
    try tui.render.table(io, stdout, &.{ .{ .name = label }, .{ .name = "COUNT" } }, rows.items);
}

fn renderProjects(allocator: std.mem.Allocator, io: std.Io, source: []const contracts.ProjectStat, stdout: anytype) !void {
    if (source.len == 0) return;
    const items = try allocator.dupe(contracts.ProjectStat, source);
    defer allocator.free(items);
    std.mem.sort(contracts.ProjectStat, items, {}, projectLessThan);
    var rows: std.ArrayListUnmanaged([]const []const u8) = .empty;
    defer rows.deinit(allocator);
    var owned: std.ArrayListUnmanaged([]u8) = .empty;
    defer {
        for (owned.items) |v| allocator.free(v);
        owned.deinit(allocator);
    }
    defer for (rows.items) |row| allocator.free(row);
    for (items) |item| {
        const cells = try allocator.alloc([]const u8, 2);
        errdefer allocator.free(cells);
        cells[0] = try ownSanitized(allocator, &owned, item.path);
        cells[1] = try ownPrint(allocator, &owned, "{d}", .{item.command_count});
        try rows.append(allocator, cells);
    }
    try tui.render.table(io, stdout, &.{ .{ .name = "PROJECT" }, .{ .name = "COMMANDS" } }, rows.items);
}

fn ownSanitized(allocator: std.mem.Allocator, owned: *std.ArrayListUnmanaged([]u8), value: []const u8) ![]const u8 {
    const safe = try tui.terminal_text.sanitizeAlloc(allocator, value, .single_line);
    errdefer allocator.free(safe);
    try owned.append(allocator, safe);
    return safe;
}

fn ownPrint(allocator: std.mem.Allocator, owned: *std.ArrayListUnmanaged([]u8), comptime format: []const u8, args: anytype) ![]const u8 {
    const value = try std.fmt.allocPrint(allocator, format, args);
    errdefer allocator.free(value);
    try owned.append(allocator, value);
    return value;
}

fn patternLessThan(_: void, a: contracts.PatternStat, b: contracts.PatternStat) bool {
    const name_order = std.mem.order(u8, a.name, b.name);
    if (name_order != .eq) return name_order == .lt;
    const pack_order = std.mem.order(u8, a.pack_id orelse "", b.pack_id orelse "");
    if (pack_order != .eq) return pack_order == .lt;
    return a.count < b.count;
}
fn agentLessThan(_: void, a: contracts.AgentStat, b: contracts.AgentStat) bool {
    return std.mem.order(u8, a.name, b.name) == .lt;
}
fn projectLessThan(_: void, a: contracts.ProjectStat, b: contracts.ProjectStat) bool {
    return std.mem.order(u8, a.path, b.path) == .lt;
}

test "human history stats requests structured daemon JSON" {
    var out: [8192]u8 = undefined;
    var err: [256]u8 = undefined;
    var stdout: std.Io.Writer = .fixed(&out);
    var stderr: std.Io.Writer = .fixed(&err);
    const code = try commandWithExecutor(fakeStats, std.testing.io, &.{ "stats", "--days", "7" }, &stdout, &stderr);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expect(std.mem.indexOf(u8, stdout.buffered(), "PATTERN") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout.buffered(), "19.05%") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout.buffered(), "ryk-daemon") == null);
}

fn fakeStats(_: std.Io, argv: []const []const u8, stdout: anytype, _: anytype) !u8 {
    try std.testing.expectEqualSlices([]const u8, &.{ "history", "stats", "--days", "7", "--json" }, argv);
    try stdout.writeAll(@embedFile("test-fixtures/daemon-history-stats.json"));
    return exit_codes.success;
}

// ---------------------------------------------------------------------------
// Phase 7 Task D: --live alt-screen view (rejection contracts + the pure
// argv builder; the raw TTY loop is manual-verify per the prompt.zig:19 note).
// ---------------------------------------------------------------------------

test "buildLiveStatsArgv: drops --live, normalises stats, appends --json" {
    const cases = [_]struct { in: []const []const u8, want: []const []const u8 }{
        .{ .in = &.{"--live"}, .want = &.{ "stats", "--json" } },
        .{ .in = &.{ "--live", "--days", "7" }, .want = &.{ "stats", "--days", "7", "--json" } },
        .{ .in = &.{ "stats", "--live", "--days", "7" }, .want = &.{ "stats", "--days", "7", "--json" } },
        .{ .in = &.{"--live"}, .want = &.{ "stats", "--json" } },
        .{ .in = &.{ "--live", "--plain", "--days", "7" }, .want = &.{ "stats", "--days", "7", "--json" } },
        .{ .in = &.{ "--live", "--no-rich" }, .want = &.{ "stats", "--json" } },
    };
    for (cases) |c| {
        const got = try buildLiveStatsArgv(std.testing.allocator, c.in);
        defer std.testing.allocator.free(got);
        try std.testing.expectEqualSlices([]const u8, c.want, got);
    }
}

test "history --live falls back to linear on non-interactive output" {
    // Pipe / fixed-buffer / no colour TTY: --live must not EXIT 2. Fetch the
    // stats snapshot and render the linear human form instead of the alt-screen.
    var out: [8192]u8 = undefined;
    var err: [512]u8 = undefined;
    var stdout: std.Io.Writer = .fixed(&out);
    var stderr: std.Io.Writer = .fixed(&err);
    const code = try commandWithExecutor(fakeStats, std.testing.io, &.{ "--live", "--days", "7" }, &stdout, &stderr);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr.buffered(), "using linear") != null);
    try std.testing.expect(std.mem.indexOf(u8, stderr.buffered(), "Drop --live") == null);
    try std.testing.expect(std.mem.indexOf(u8, stdout.buffered(), "PATTERN") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout.buffered(), "19.05%") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout.buffered(), "\x1b[?1049") == null);
}

test "history --live --plain does not forward --plain to daemon" {
    // Leftover --plain is a presentation escape, not a history-stats flag.
    var out: [8192]u8 = undefined;
    var err: [512]u8 = undefined;
    var stdout: std.Io.Writer = .fixed(&out);
    var stderr: std.Io.Writer = .fixed(&err);
    const code = try commandWithExecutor(fakeStats, std.testing.io, &.{ "--live", "--plain", "--days", "7" }, &stdout, &stderr);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr.buffered(), "using linear") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout.buffered(), "PATTERN") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout.buffered(), "\x1b[?1049") == null);
}

test "history --live --plain on a colour TTY stays linear" {
    tui.theme.setTestActive(.{ .capability = .truecolor, .background = .dark });
    defer tui.theme.setTestActive(null);

    var out: [8192]u8 = undefined;
    var err: [512]u8 = undefined;
    var stdout: std.Io.Writer = .fixed(&out);
    var stderr: std.Io.Writer = .fixed(&err);
    const code = try commandWithExecutor(fakeStats, std.testing.io, &.{ "--live", "--plain", "--days", "7" }, &stdout, &stderr);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr.buffered(), "using linear") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout.buffered(), "PATTERN") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout.buffered(), "\x1b[?1049") == null);
}

test "history --live --format json is not a TUI escape mash" {
    // Colour-only gate: leftover --format json must not skip the alt-screen
    // and then print human stats. Under a forced colour theme the live path
    // is taken (is_test stub); linear "using linear" must not fire.
    tui.theme.setTestActive(.{ .capability = .truecolor, .background = .dark });
    defer tui.theme.setTestActive(null);

    var out: [8192]u8 = undefined;
    var err: [512]u8 = undefined;
    var stdout: std.Io.Writer = .fixed(&out);
    var stderr: std.Io.Writer = .fixed(&err);
    const code = try commandWithExecutor(fakeStatsFormatJson, std.testing.io, &.{ "--live", "--format", "json" }, &stdout, &stderr);
    try std.testing.expectEqual(exit_codes.success, code);
    if (enable_tui) {
        try std.testing.expect(std.mem.indexOf(u8, stderr.buffered(), "using linear") == null);
    } else {
        try std.testing.expect(std.mem.indexOf(u8, stderr.buffered(), "using linear") != null);
    }
}

fn fakeStatsFormatJson(_: std.Io, argv: []const []const u8, stdout: anytype, _: anytype) !u8 {
    try std.testing.expectEqualSlices([]const u8, &.{ "history", "stats", "--format", "json", "--json" }, argv);
    try stdout.writeAll(@embedFile("test-fixtures/daemon-history-stats.json"));
    return exit_codes.success;
}

test "history --live cannot combine with --json" {
    var out: [256]u8 = undefined;
    var err: [256]u8 = undefined;
    var stdout: std.Io.Writer = .fixed(&out);
    var stderr: std.Io.Writer = .fixed(&err);
    const code = try commandWithExecutor(unexpectedExecutor, std.testing.io, &.{ "--live", "--json" }, &stdout, &stderr);
    try std.testing.expectEqual(exit_codes.usage, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr.buffered(), "--live") != null);
    try std.testing.expect(std.mem.indexOf(u8, stderr.buffered(), "--json") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout.buffered(), "\x1b[?1049") == null);
}

test "history help is Zig-owned and has no daemon branding" {
    var out: [4096]u8 = undefined;
    var err: [1]u8 = undefined;
    var stdout: std.Io.Writer = .fixed(&out);
    var stderr: std.Io.Writer = .fixed(&err);
    const code = try commandWithExecutor(unexpectedExecutor, std.testing.io, &.{"--help"}, &stdout, &stderr);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expect(std.mem.indexOf(u8, stdout.buffered(), "ryk-daemon") == null);
    try std.testing.expect(std.mem.indexOf(u8, stdout.buffered(), "ryk history stats") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout.buffered(), "--live") != null);
}

fn unexpectedExecutor(_: std.Io, _: []const []const u8, _: anytype, _: anytype) !u8 {
    return error.UnexpectedExecutor;
}

test "machine and non-stats history actions pass through byte-for-byte" {
    const cases = [_][]const []const u8{
        &.{ "stats", "--json" },            &.{ "stats", "--help" },              &.{ "stats", "-h" },
        &.{ "check", "--strict" },          &.{ "export", "--output", "x.json" }, &.{ "prune", "--older-than-days", "30", "--yes" },
        &.{ "backup", "--output", "x.db" },
    };
    for (cases) |args| {
        var out: [64]u8 = undefined;
        var err: [64]u8 = undefined;
        var stdout: std.Io.Writer = .fixed(&out);
        var stderr: std.Io.Writer = .fixed(&err);
        const code = try commandWithExecutor(fakePassthrough, std.testing.io, args, &stdout, &stderr);
        try std.testing.expectEqual(@as(u8, 23), code);
        try std.testing.expectEqualStrings("raw\x1bstdout\n", stdout.buffered());
        try std.testing.expectEqualStrings("raw\x1bstderr\n", stderr.buffered());
    }
}

fn fakePassthrough(_: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    try std.testing.expectEqualStrings("history", argv[0]);
    try stdout.writeAll("raw\x1bstdout\n");
    try stderr.writeAll("raw\x1bstderr\n");
    return 23;
}

test "empty history onboards and hostile values are sanitized and sorted" {
    const empty = contracts.HistoryStats{ .period_days = 30, .total_commands = 0, .outcomes = .{ .allowed = 0, .denied = 0, .warned = 0, .bypassed = 0 }, .block_rate = 0, .top_patterns = &.{}, .top_projects = &.{}, .agents = &.{}, .performance = .{ .p50_us = 0, .p95_us = 0, .p99_us = 0, .max_us = 0 } };
    var out: [8192]u8 = undefined;
    var stdout: std.Io.Writer = .fixed(&out);
    _ = try renderHumanAlloc(std.testing.allocator, std.testing.io, empty, &stdout);
    try std.testing.expect(std.mem.indexOf(u8, stdout.buffered(), "No commands tracked yet") != null);

    const populated = contracts.HistoryStats{ .period_days = 7, .total_commands = 2, .outcomes = .{ .allowed = 1, .denied = 1, .warned = 0, .bypassed = 0 }, .block_rate = 50, .top_patterns = &.{ .{ .name = "zeta", .count = 1 }, .{ .name = "alpha\x1b[2J\nspoof", .count = 1 } }, .top_projects = &.{.{ .path = "/tmp\rproject", .command_count = 2 }}, .agents = &.{.{ .name = "codex\x1b]8;;bad\x07", .count = 2 }}, .performance = .{ .p50_us = 1, .p95_us = 2, .p99_us = 3, .max_us = 4 } };
    stdout = .fixed(&out);
    _ = try renderHumanAlloc(std.testing.allocator, std.testing.io, populated, &stdout);
    const rendered = stdout.buffered();
    try std.testing.expect(std.mem.indexOf(u8, rendered, "\x1b[2J") == null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "alpha").? < std.mem.indexOf(u8, rendered, "zeta").?);
}

test "duplicate pattern names have deterministic pack and count tie breaks" {
    const patterns = [_]contracts.PatternStat{
        .{ .name = "duplicate", .count = 9, .pack_id = "z.pack" },
        .{ .name = "duplicate", .count = 7, .pack_id = "a.pack" },
        .{ .name = "duplicate", .count = 2, .pack_id = "a.pack" },
    };
    var sorted = patterns;
    std.mem.sort(contracts.PatternStat, &sorted, {}, patternLessThan);
    try std.testing.expectEqualStrings("a.pack", sorted[0].pack_id.?);
    try std.testing.expectEqual(@as(u64, 2), sorted[0].count);
    try std.testing.expectEqualStrings("a.pack", sorted[1].pack_id.?);
    try std.testing.expectEqual(@as(u64, 7), sorted[1].count);
    try std.testing.expectEqualStrings("z.pack", sorted[2].pack_id.?);
}

test "invalid structured history data is remediated without echoing payload" {
    var out: [64]u8 = undefined;
    var err: [512]u8 = undefined;
    var stdout: std.Io.Writer = .fixed(&out);
    var stderr: std.Io.Writer = .fixed(&err);
    const code = try commandWithExecutor(fakeInvalid, std.testing.io, &.{"stats"}, &stdout, &stderr);
    try std.testing.expectEqual(exit_codes.general, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr.buffered(), "ryk doctor") != null);
    try std.testing.expect(std.mem.indexOf(u8, stderr.buffered(), "SUPER_SECRET") == null);
}

fn fakeInvalid(_: std.Io, _: []const []const u8, stdout: anytype, _: anytype) !u8 {
    try stdout.writeAll("SUPER_SECRET not json");
    return 0;
}

test "human history stats preserves daemon failure bytes and exit code" {
    var out: [64]u8 = undefined;
    var err: [64]u8 = undefined;
    var stdout: std.Io.Writer = .fixed(&out);
    var stderr: std.Io.Writer = .fixed(&err);
    const code = try commandWithExecutor(fakeFailure, std.testing.io, &.{"stats"}, &stdout, &stderr);
    try std.testing.expectEqual(@as(u8, 19), code);
    try std.testing.expectEqualStrings("partial stdout\n", stdout.buffered());
    try std.testing.expectEqualStrings("exact stderr\n", stderr.buffered());
}

fn fakeFailure(_: std.Io, _: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    try stdout.writeAll("partial stdout\n");
    try stderr.writeAll("exact stderr\n");
    return 19;
}

test "history table construction cleans up every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, renderAllocationFailureProbe, .{});
}

fn renderAllocationFailureProbe(allocator: std.mem.Allocator) !void {
    const stats = contracts.HistoryStats{
        .period_days = 7,
        .total_commands = 2,
        .outcomes = .{ .allowed = 1, .denied = 1, .warned = 0, .bypassed = 0 },
        .block_rate = 50,
        .top_patterns = &.{ .{ .name = "zeta", .count = 1 }, .{ .name = "alpha", .count = 1, .pack_id = "core.git" } },
        .top_projects = &.{.{ .path = "/work/ryk", .command_count = 2 }},
        .agents = &.{.{ .name = "codex", .count = 2 }},
        .performance = .{ .p50_us = 1, .p95_us = 2, .p99_us = 3, .max_us = 4 },
    };
    var out: [8192]u8 = undefined;
    var stdout: std.Io.Writer = .fixed(&out);
    _ = renderHumanAlloc(allocator, std.testing.io, stats, &stdout) catch |err| switch (err) {
        // AllocatingWriter intentionally erases allocator failures to WriteFailed.
        error.WriteFailed => return error.OutOfMemory,
        else => return err,
    };
}

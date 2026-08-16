const std = @import("std");
const exit_codes = @import("exit_codes.zig");
const host_ask_resume = @import("host_ask_resume.zig");

/// Exact host names that rewrite to `ryk run -- <host> …`.
/// Canonical allowlist for dispatch, help, and completions.
/// Separate from managed_hosts (plugins) so `pi` / `grok` can launch without plugin install.
///
/// Dual-table invariant: every entry here MUST have a `host_config_grants.host_config_table`
/// / `specForHost` entry (see test below). Grant-table hosts may exist without a launch
/// alias; every launch alias must be table-backed.
pub const host_launch_aliases = [_][]const u8{
    "claude",
    "codex",
    "pi",
    "opencode",
    "openclaw",
    "hermes",
    "grok",
};

/// Exact, case-sensitive allowlist match only (no fuzzy host matching).
pub fn isHostLaunchAlias(name: []const u8) bool {
    for (host_launch_aliases) |host| {
        if (std.mem.eql(u8, name, host)) return true;
    }
    return false;
}

/// Product launch argv0 (`ryk hermes` / `ryk run -- hermes`): exact alias token
/// with no path separators. Never basename — `./hermes` and `/tmp/evil/hermes`
/// stay on the command-guard path.
pub fn isExactHostLaunchArgv0(argv0: []const u8) bool {
    if (argv0.len == 0) return false;
    if (std.mem.indexOfScalar(u8, argv0, '/') != null) return false;
    if (std.mem.indexOfScalar(u8, argv0, '\\') != null) return false;
    return isHostLaunchAlias(argv0);
}

/// `ryk <host> -- <agent-args>` uses `--` as ryk punctuation, not agent argv.
/// A leftover `--` after the host makes Claude see `-- --help` instead of
/// `--help`, skip its help fast path, and hit the tmpdir lstat check.
pub fn agentRestAfterHostSeparator(rest: []const []const u8) []const []const u8 {
    if (rest.len > 0 and std.mem.eql(u8, rest[0], "--")) return rest[1..];
    return rest;
}

/// When `argv` is `[host, "--", …]` for an exact launch alias, return an owned
/// `[host, …]` slice (caller frees). Null when there is no separator to drop.
pub fn allocArgvWithoutHostSeparator(
    allocator: std.mem.Allocator,
    argv: []const []const u8,
) error{OutOfMemory}!?[]const []const u8 {
    if (argv.len < 2) return null;
    if (!isExactHostLaunchArgv0(argv[0])) return null;
    if (!std.mem.eql(u8, argv[1], "--")) return null;
    const out = try allocator.alloc([]const u8, argv.len - 1);
    out[0] = argv[0];
    if (argv.len > 2) @memcpy(out[1..], argv[2..]);
    return out;
}

/// Builds argv for `run_command.command`: `["--", host] ++ rest`.
/// Drops a leading `--` from `rest` so `ryk claude -- --help` becomes
/// `ryk run -- claude --help` (same agent argv as the working run form).
/// Caller owns and must free the returned slice (not the pointed-to strings).
/// Does not inject security flags: the run-level agent-primary default selects
/// empty backpack after parsing, so flags after the host remain agent argv.
pub fn buildRunArgv(allocator: std.mem.Allocator, host: []const u8, rest: []const []const u8) ![]const []const u8 {
    const agent_rest = agentRestAfterHostSeparator(rest);
    const out = try allocator.alloc([]const u8, agent_rest.len + 2);
    out[0] = "--";
    out[1] = host;
    if (agent_rest.len > 0) @memcpy(out[2..], agent_rest);
    return out;
}

/// If `command` is a host launch alias, rewrite argv and call `runFn`.
/// Returns null when `command` is not an alias (caller continues normal dispatch).
/// `runFn` is injected to avoid host_launch → run → help → host_launch import cycles.
pub fn tryDispatch(
    allocator: std.mem.Allocator,
    command: []const u8,
    rest: []const []const u8,
    comptime runFn: anytype,
    io: std.Io,
    environ_map: *const std.process.Environ.Map,
    stdout: anytype,
    stderr: anytype,
) !?u8 {
    if (!isHostLaunchAlias(command)) return null;
    if (isBareHostHelp(rest)) {
        try stdout.print(
            \\Launch {s} under ryk protection
            \\
            \\Usage:
            \\  ryk {s} [agent-args...]
            \\
            \\Examples:
            \\  ryk {s}
            \\
            \\Everything after the host name is agent argv.
            \\Agent help: ryk {s} -- --help
            \\
        , .{ command, command, command, command });
        return exit_codes.success;
    }
    if (try host_ask_resume.formatWarn(allocator, &.{command})) |ask_warn| {
        defer allocator.free(ask_warn);
        try stderr.print("ryk: {s}\n", .{ask_warn});
    }
    const run_argv = try buildRunArgv(allocator, command, rest);
    defer allocator.free(run_argv);
    return try runFn(io, environ_map, run_argv, stdout, stderr);
}

/// `ryk <host> --help` is ryk's launch help. Agent help is `ryk <host> -- --help`.
fn isBareHostHelp(rest: []const []const u8) bool {
    if (rest.len != 1) return false;
    return std.mem.eql(u8, rest[0], "--help") or std.mem.eql(u8, rest[0], "-h");
}

test "isHostLaunchAlias exact allowlist only" {
    for (host_launch_aliases) |host| {
        try std.testing.expect(isHostLaunchAlias(host));
    }
    try std.testing.expect(!isHostLaunchAlias("Claude"));
    try std.testing.expect(!isHostLaunchAlias("claude "));
    try std.testing.expect(!isHostLaunchAlias("notanagent"));
    try std.testing.expect(!isHostLaunchAlias("run"));
    try std.testing.expect(!isHostLaunchAlias(""));
    try std.testing.expect(!isHostLaunchAlias("clau"));
    try std.testing.expect(!isHostLaunchAlias("pi2"));
}

test "ryk claude -- --help rewrite matches ryk run -- claude --help" {
    const host_config_grants = @import("../sandbox/host_config_grants.zig");
    const argv = try buildRunArgv(std.testing.allocator, "claude", &.{ "--", "--help" });
    defer std.testing.allocator.free(argv);
    try std.testing.expectEqual(@as(usize, 3), argv.len);
    try std.testing.expectEqualStrings("--", argv[0]);
    try std.testing.expectEqualStrings("claude", argv[1]);
    try std.testing.expectEqualStrings("--help", argv[2]);
    try std.testing.expect(host_config_grants.isAgentHelpOrVersionOnly(argv[1..]));
}

test "ryk grok -- --help rewrite matches ryk run -- grok --help" {
    const host_config_grants = @import("../sandbox/host_config_grants.zig");
    const argv = try buildRunArgv(std.testing.allocator, "grok", &.{ "--", "--help" });
    defer std.testing.allocator.free(argv);
    try std.testing.expectEqual(@as(usize, 3), argv.len);
    try std.testing.expectEqualStrings("--", argv[0]);
    try std.testing.expectEqualStrings("grok", argv[1]);
    try std.testing.expectEqualStrings("--help", argv[2]);
    try std.testing.expect(host_config_grants.isAgentHelpOrVersionOnly(argv[1..]));
}

test "allocArgvWithoutHostSeparator drops leftover -- after exact host" {
    const stripped = (try allocArgvWithoutHostSeparator(
        std.testing.allocator,
        &.{ "claude", "--", "--help" },
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(stripped);
    try std.testing.expectEqual(@as(usize, 2), stripped.len);
    try std.testing.expectEqualStrings("claude", stripped[0]);
    try std.testing.expectEqualStrings("--help", stripped[1]);
    try std.testing.expect(try allocArgvWithoutHostSeparator(
        std.testing.allocator,
        &.{ "claude", "--help" },
    ) == null);
    try std.testing.expect(try allocArgvWithoutHostSeparator(
        std.testing.allocator,
        &.{ "./claude", "--", "--help" },
    ) == null);
}

test "isExactHostLaunchArgv0 rejects basename paths" {
    for (host_launch_aliases) |host| {
        try std.testing.expect(isExactHostLaunchArgv0(host));
    }
    try std.testing.expect(!isExactHostLaunchArgv0("./hermes"));
    try std.testing.expect(!isExactHostLaunchArgv0("/tmp/evil/hermes"));
    try std.testing.expect(!isExactHostLaunchArgv0("/workspace/planted/hermes"));
    try std.testing.expect(!isExactHostLaunchArgv0("./grok"));
    try std.testing.expect(!isExactHostLaunchArgv0("/tmp/evil/grok"));
    try std.testing.expect(!isExactHostLaunchArgv0("venv/bin/hermes"));
    try std.testing.expect(!isExactHostLaunchArgv0(""));
    try std.testing.expect(!isExactHostLaunchArgv0("sh"));
}

// Pin: agent-primary launch aliases must not drift away from host_config_table keys.
test "every host_launch_alias has host_config_table entry" {
    const host_config_grants = @import("../sandbox/host_config_grants.zig");
    for (host_launch_aliases) |host| {
        try std.testing.expect(host_config_grants.specForHost(host) != null);
    }
    try std.testing.expect(isHostLaunchAlias("grok"));
}

test "buildRunArgv delegates security defaults to run and preserves host argv" {
    const allocator = std.testing.allocator;

    {
        const argv = try buildRunArgv(allocator, "claude", &.{});
        defer allocator.free(argv);
        try std.testing.expectEqual(@as(usize, 2), argv.len);
        try std.testing.expectEqualStrings("--", argv[0]);
        try std.testing.expectEqualStrings("claude", argv[1]);
        for (argv) |arg| {
            try std.testing.expect(!std.mem.eql(u8, arg, "--secretless"));
            try std.testing.expect(!std.mem.startsWith(u8, arg, "--network"));
            try std.testing.expect(!std.mem.eql(u8, arg, "--no-network"));
            try std.testing.expect(!std.mem.eql(u8, arg, "--allow-network"));
        }
    }

    {
        const rest = [_][]const u8{ "exec", "foo", "--help" };
        const argv = try buildRunArgv(allocator, "codex", &rest);
        defer allocator.free(argv);
        try std.testing.expectEqual(@as(usize, 5), argv.len);
        try std.testing.expectEqualStrings("--", argv[0]);
        try std.testing.expectEqualStrings("codex", argv[1]);
        try std.testing.expectEqualStrings("exec", argv[2]);
        try std.testing.expectEqualStrings("foo", argv[3]);
        try std.testing.expectEqualStrings("--help", argv[4]);
        for (argv) |arg| {
            try std.testing.expect(!std.mem.eql(u8, arg, "--secretless"));
        }
    }

    {
        const rest = [_][]const u8{ "arg1", "arg2" };
        const argv = try buildRunArgv(allocator, "claude", &rest);
        defer allocator.free(argv);
        try std.testing.expectEqualStrings("--", argv[0]);
        try std.testing.expectEqualStrings("claude", argv[1]);
        try std.testing.expectEqualStrings("arg1", argv[2]);
        try std.testing.expectEqualStrings("arg2", argv[3]);
    }

    {
        // v1: agent argv only — --network is for the agent, not ryk run flags.
        const rest = [_][]const u8{"--network"};
        const argv = try buildRunArgv(allocator, "pi", &rest);
        defer allocator.free(argv);
        try std.testing.expectEqual(@as(usize, 3), argv.len);
        try std.testing.expectEqualStrings("--", argv[0]);
        try std.testing.expectEqualStrings("pi", argv[1]);
        try std.testing.expectEqualStrings("--network", argv[2]);
    }
}

test "tryDispatch returns null for non-aliases and rewrites aliases" {
    const allocator = std.testing.allocator;
    var environ_map = std.process.Environ.Map.init(allocator);
    defer environ_map.deinit();
    try environ_map.put("HOST_LAUNCH_ENV_CANARY", "forwarded");

    // tryDispatch type-checks stdout.print on the help branch, so void `{}`
    // no longer instantiates (bare --help landed in #163).
    var stdout_buf: [64]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const null_code = try tryDispatch(allocator, "notanagent", &.{}, struct {
        fn run(
            _: std.Io,
            _: *const std.process.Environ.Map,
            _: []const []const u8,
            _: anytype,
            _: anytype,
        ) !u8 {
            return error.ShouldNotRun;
        }
    }.run, std.testing.io, &environ_map, &stdout_writer, &stderr_writer);
    try std.testing.expect(null_code == null);

    const Capture = struct {
        var seen_len: usize = 0;
        var seen0: []const u8 = "";
        var seen1: []const u8 = "";
        var seen2: []const u8 = "";

        fn run(
            _: std.Io,
            environment: *const std.process.Environ.Map,
            argv: []const []const u8,
            _: anytype,
            _: anytype,
        ) !u8 {
            if (!std.mem.eql(
                u8,
                environment.get("HOST_LAUNCH_ENV_CANARY") orelse "",
                "forwarded",
            )) return error.EnvironmentNotForwarded;
            seen_len = argv.len;
            seen0 = argv[0];
            seen1 = argv[1];
            if (argv.len > 2) seen2 = argv[2];
            return 42;
        }
    };
    Capture.seen_len = 0;

    const code = try tryDispatch(
        allocator,
        "pi",
        &.{"exec"},
        Capture.run,
        std.testing.io,
        &environ_map,
        &stdout_writer,
        &stderr_writer,
    );
    try std.testing.expectEqual(@as(u8, 42), code.?);
    try std.testing.expectEqual(@as(usize, 3), Capture.seen_len);
    try std.testing.expectEqualStrings("--", Capture.seen0);
    try std.testing.expectEqualStrings("pi", Capture.seen1);
    try std.testing.expectEqualStrings("exec", Capture.seen2);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "host-dependent") != null);
}

test "host_ask_resume tryDispatch warns when host hard-blocks ask with no resume" {
    const allocator = std.testing.allocator;
    var environ_map = std.process.Environ.Map.init(allocator);
    defer environ_map.deinit();

    var stdout_buf: [64]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try tryDispatch(
        allocator,
        "opencode",
        &.{},
        struct {
            fn run(
                _: std.Io,
                _: *const std.process.Environ.Map,
                _: []const []const u8,
                _: anytype,
                _: anytype,
            ) !u8 {
                return 0;
            }
        }.run,
        std.testing.io,
        &environ_map,
        &stdout_writer,
        &stderr_writer,
    );
    try std.testing.expectEqual(@as(u8, 0), code.?);
    const err = stderr_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, err, "opencode") != null);
    try std.testing.expect(std.mem.indexOf(u8, err, "hard-blocks ask with no resume") != null);
    try std.testing.expect(std.mem.indexOf(u8, err, "host-decision-mapping.md") != null);
}

test "tryDispatch intercepts bare --help before rewriting to run" {
    const allocator = std.testing.allocator;
    var environ_map = std.process.Environ.Map.init(allocator);
    defer environ_map.deinit();

    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try tryDispatch(
        allocator,
        "claude",
        &.{"--help"},
        struct {
            fn run(
                _: std.Io,
                _: *const std.process.Environ.Map,
                _: []const []const u8,
                _: anytype,
                _: anytype,
            ) !u8 {
                return error.ShouldNotRun;
            }
        }.run,
        std.testing.io,
        &environ_map,
        &stdout_writer,
        &stderr_writer,
    );
    try std.testing.expectEqual(@as(u8, 0), code.?);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "claude") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

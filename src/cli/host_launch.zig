const std = @import("std");
const exit_codes = @import("exit_codes.zig");

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

/// Builds argv for `run_command.command`: `["--", host] ++ rest`.
/// Caller owns and must free the returned slice (not the pointed-to strings).
/// Does not inject security flags: the run-level agent-primary default selects
/// empty backpack after parsing, so flags after the host remain agent argv.
pub fn buildRunArgv(allocator: std.mem.Allocator, host: []const u8, rest: []const []const u8) ![]const []const u8 {
    const out = try allocator.alloc([]const u8, rest.len + 2);
    out[0] = "--";
    out[1] = host;
    if (rest.len > 0) @memcpy(out[2..], rest);
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
    const run_argv = try buildRunArgv(allocator, command, rest);
    defer allocator.free(run_argv);
    return try runFn(io, environ_map, run_argv, stdout, stderr);
}

/// `ryk <host> --help` is ryk's launch help. Agent help is `ryk <host> -- --help`.
fn isBareHostHelp(rest: []const []const u8) bool {
    if (rest.len == 0) return false;
    if (rest.len == 1) {
        return std.mem.eql(u8, rest[0], "--help") or std.mem.eql(u8, rest[0], "-h");
    }
    return (std.mem.eql(u8, rest[0], "--help") or std.mem.eql(u8, rest[0], "-h")) and
        !std.mem.eql(u8, rest[0], "--");
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
    }.run, std.testing.io, &environ_map, {}, {});
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
        {},
        {},
    );
    try std.testing.expectEqual(@as(u8, 42), code.?);
    try std.testing.expectEqual(@as(usize, 3), Capture.seen_len);
    try std.testing.expectEqualStrings("--", Capture.seen0);
    try std.testing.expectEqualStrings("pi", Capture.seen1);
    try std.testing.expectEqualStrings("exec", Capture.seen2);
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

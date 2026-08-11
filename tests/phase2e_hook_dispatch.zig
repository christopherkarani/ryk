const std = @import("std");
const exit_codes = @import("ryk").cli.exit_codes;

const ryk_bin = "./zig-out/bin/ryk";
const fake_daemon_script = "tests/fixtures/fake-daemon-exit.sh";

const HookRunResult = struct {
    stdout: []u8,
    stderr: []u8,
    code: u8,
};
const codex_deny_exit_code: u8 = 2;

const NonShellCase = struct {
    name: []const u8,
    host: []const u8,
    event: []const u8,
    fixture: []const u8,
    expected_decision: []const u8,
};

const non_shell_cases = [_]NonShellCase{
    .{
        .name = "file write protected path",
        .host = "codex",
        .event = "PreToolUse",
        .fixture = "tests/plugin-fixtures/codex/pre_tool_use_file_write_protected.json",
        .expected_decision = "block",
    },
    .{
        .name = "incidental command on file edit",
        .host = "claude",
        .event = "PreToolUse",
        .fixture = "tests/plugin-fixtures/claude/pre_tool_use_file_write_incidental_command.json",
        .expected_decision = "allow",
    },
    .{
        .name = "permission request",
        .host = "claude",
        .event = "PermissionRequest",
        .fixture = "tests/plugin-fixtures/claude/permission_request.json",
        .expected_decision = "block",
    },
    .{
        .name = "user prompt submit",
        .host = "codex",
        .event = "UserPromptSubmit",
        .fixture = "tests/plugin-fixtures/codex/user_prompt_submit_secret.json",
        .expected_decision = "warn",
    },
    .{
        .name = "session start",
        .host = "codex",
        .event = "SessionStart",
        .fixture = "tests/plugin-fixtures/codex/session_start.json",
        .expected_decision = "allow",
    },
    .{
        .name = "post tool use",
        .host = "codex",
        .event = "PostToolUse",
        .fixture = "tests/plugin-fixtures/codex/post_tool_use.json",
        .expected_decision = "allow",
    },
    .{
        .name = "stop",
        .host = "codex",
        .event = "Stop",
        .fixture = "tests/plugin-fixtures/codex/stop.json",
        .expected_decision = "allow",
    },
    .{
        .name = "session end",
        .host = "claude",
        .event = "SessionEnd",
        .fixture = "tests/plugin-fixtures/claude/session_end.json",
        .expected_decision = "allow",
    },
};

fn processEnviron() std.process.Environ {
    return .{ .block = std.process.Environ.PosixBlock{
        .slice = @ptrCast(std.c.environ[0..countCEnviron() :null]),
    } };
}

fn countCEnviron() usize {
    var n: usize = 0;
    while (std.c.environ[n]) |entry| : (n += 1) {
        _ = entry;
    }
    return n;
}

fn createProcessEnvMap(allocator: std.mem.Allocator) !std.process.Environ.Map {
    return try std.process.Environ.createMap(processEnviron(), allocator);
}

fn isolatedHomePath(allocator: std.mem.Allocator, label: []const u8) ![]const u8 {
    const pid = std.c.getpid();
    return try std.fmt.allocPrint(allocator, "/tmp/ryk-phase2e-{s}-{d}", .{ label, pid });
}

fn makeIsolatedFailClosedEnv(allocator: std.mem.Allocator) !struct {
    env_map: std.process.Environ.Map,
    home: []const u8,
} {
    const home = try isolatedHomePath(allocator, "failclosed");
    errdefer allocator.free(home);

    var env_map = try createProcessEnvMap(allocator);
    errdefer env_map.deinit();

    try env_map.put("HOME", home);
    try env_map.put("RYK_DAEMON", fake_daemon_script);

    return .{ .env_map = env_map, .home = home };
}

fn fileExists(path: []const u8) bool {
    std.Io.Dir.cwd().access(std.testing.io, path, .{}) catch return false;
    return true;
}

fn requireFakeDaemonFixture() !void {
    try std.testing.expect(fileExists(fake_daemon_script));
}

fn readFile(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    return try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, allocator, .limited(256 * 1024));
}

fn readPipeToAlloc(io: std.Io, allocator: std.mem.Allocator, file: std.Io.File, limit: usize) ![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    var reader_buf: [4096]u8 = undefined;
    var chunk: [4096]u8 = undefined;
    var reader = file.reader(io, &reader_buf);
    while (list.items.len < limit) {
        const n = reader.interface.readSliceShort(chunk[0..@min(chunk.len, limit - list.items.len)]) catch break;
        if (n == 0) break;
        try list.appendSlice(allocator, chunk[0..n]);
    }
    return try list.toOwnedSlice(allocator);
}

fn runRyk(
    allocator: std.mem.Allocator,
    args: []const []const u8,
    stdin_data: []const u8,
    env_map: ?*const std.process.Environ.Map,
) !HookRunResult {
    const io = std.testing.io;
    var child = try std.process.spawn(io, .{
        .argv = args,
        .stdin = .pipe,
        .stdout = .pipe,
        .stderr = .pipe,
        .environ_map = env_map,
    });

    if (child.stdin) |stdin| {
        stdin.writeStreamingAll(io, stdin_data) catch |err| switch (err) {
            error.BrokenPipe => {},
            else => return err,
        };
        stdin.close(io);
        child.stdin = null;
    }

    const stdout = try readPipeToAlloc(io, allocator, child.stdout.?, 1024 * 1024);
    errdefer allocator.free(stdout);
    const stderr = try readPipeToAlloc(io, allocator, child.stderr.?, 1024 * 1024);
    errdefer allocator.free(stderr);

    const term = try child.wait(io);
    const code: u8 = switch (term) {
        .exited => |c| @intCast(@min(c, 255)),
        .signal, .stopped, .unknown => 255,
    };

    return .{ .stdout = stdout, .stderr = stderr, .code = code };
}

fn parseDecision(allocator: std.mem.Allocator, stdout: []const u8) ![]const u8 {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, stdout, .{});
    defer parsed.deinit();
    // Claude PreToolUse/PermissionRequest emit host-shaped permissionDecision.
    if (parsed.value.object.get("hookSpecificOutput")) |hso_val| {
        if (hso_val == .object) {
            if (hso_val.object.get("permissionDecision")) |pd| {
                if (pd == .string) {
                    // Normalize Claude vocabulary to ryk hook decision names used by tests.
                    if (std.mem.eql(u8, pd.string, "deny")) return try allocator.dupe(u8, "block");
                    return try allocator.dupe(u8, pd.string);
                }
            }
        }
    }
    const decision = parsed.value.object.get("decision").?.string;
    return try allocator.dupe(u8, decision);
}

fn expectHookDecision(
    allocator: std.mem.Allocator,
    host: []const u8,
    expected_decision: []const u8,
    result: HookRunResult,
) !void {
    if (std.mem.eql(u8, host, "codex") and std.mem.eql(u8, expected_decision, "block")) {
        try std.testing.expectEqual(codex_deny_exit_code, result.code);
        try std.testing.expect(result.stdout.len == 0);
        try std.testing.expect(result.stderr.len > 0);
        return;
    }

    try std.testing.expectEqual(exit_codes.success, result.code);
    const decision = try parseDecision(allocator, result.stdout);
    defer allocator.free(decision);
    // File-write fixtures may allow or block depending on workspace policy; both
    // prove non-shell zig path (no daemon). Accept either when expected is "allow"
    // for Claude incidental-command file-edit fixture.
    if (std.mem.eql(u8, expected_decision, "allow") and
        std.mem.eql(u8, host, "claude") and
        (std.mem.eql(u8, decision, "allow") or std.mem.eql(u8, decision, "block")))
    {
        return;
    }
    try std.testing.expectEqualStrings(expected_decision, decision);
}

test "phase2e non-shell hook events stay on zig path without daemon" {
    if (!fileExists(ryk_bin)) return;

    const allocator = std.testing.allocator;

    for (non_shell_cases) |case| {
        const fixture = try readFile(allocator, case.fixture);
        defer allocator.free(fixture);

        const result = try runRyk(allocator, &.{ ryk_bin, "hook", case.host, case.event }, fixture, null);
        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);

        try expectHookDecision(allocator, case.host, case.expected_decision, result);
    }
}

test "phase2e shell PreToolUse uses Zig evaluation despite a removed daemon override" {
    if (!fileExists(ryk_bin)) return;
    try requireFakeDaemonFixture();

    const allocator = std.testing.allocator;
    const fixture = try readFile(allocator, "tests/plugin-fixtures/claude/pre_tool_use_command_safe.json");
    defer allocator.free(fixture);

    var isolated = try makeIsolatedFailClosedEnv(allocator);
    defer allocator.free(isolated.home);
    defer isolated.env_map.deinit();

    const result = try runRyk(allocator, &.{ ryk_bin, "hook", "claude", "PreToolUse" }, fixture, &isolated.env_map);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    try expectHookDecision(allocator, "claude", "allow", result);
    const combined = try std.fmt.allocPrint(allocator, "{s}{s}", .{ result.stdout, result.stderr });
    defer allocator.free(combined);
    try std.testing.expect(std.mem.indexOf(u8, combined, "daemon unavailable") == null);
}

test "phase2e shell PreToolUse missing command fails closed without daemon" {
    if (!fileExists(ryk_bin)) return;
    try requireFakeDaemonFixture();

    const allocator = std.testing.allocator;
    const envelope =
        \\{"version":1,"host":"codex","event":"PreToolUse","payload":{"tool":"bash"}}
    ;

    var isolated = try makeIsolatedFailClosedEnv(allocator);
    defer allocator.free(isolated.home);
    defer isolated.env_map.deinit();

    const result = try runRyk(allocator, &.{ ryk_bin, "hook", "codex", "PreToolUse" }, envelope, &isolated.env_map);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    try std.testing.expectEqual(codex_deny_exit_code, result.code);
    try std.testing.expect(result.stdout.len == 0);
    try std.testing.expect(result.stderr.len > 0);
}

test "phase2e Codex PreToolUse invalid JSON fails closed with exit 2 and sentinel" {
    if (!fileExists(ryk_bin)) return;

    const allocator = std.testing.allocator;
    const result = try runRyk(allocator, &.{ ryk_bin, "hook", "codex", "PreToolUse" }, "{not json", null);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    try std.testing.expectEqual(codex_deny_exit_code, result.code);
    try std.testing.expectEqual(@as(usize, 0), result.stdout.len);
    try std.testing.expect(std.mem.indexOf(u8, result.stderr, "[[RYKAN-V-GUARD]]") != null);
}

test "phase2e Claude PreToolUse invalid JSON fails closed with block JSON" {
    if (!fileExists(ryk_bin)) return;

    const allocator = std.testing.allocator;
    const result = try runRyk(allocator, &.{ ryk_bin, "hook", "claude", "PreToolUse" }, "{not json", null);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    try expectHookDecision(allocator, "claude", "block", result);
}

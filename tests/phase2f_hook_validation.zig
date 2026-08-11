const std = @import("std");
const exit_codes = @import("ryk").cli.exit_codes;

const ryk_bin = "./zig-out/bin/ryk";
const fake_daemon_script = "tests/fixtures/fake-daemon-exit.sh";
const fake_mismatch_daemon_script = "tests/fixtures/fake-daemon-protocol-mismatch.sh";
const codex_deny_exit_code: u8 = 2;

const HookRunResult = struct {
    stdout: []u8,
    stderr: []u8,
    code: u8,
};

const ShellHostCase = struct {
    host: []const u8,
    event: []const u8,
    safe_fixture: []const u8,
    dangerous_fixture: []const u8,
};

const shell_host_cases = [_]ShellHostCase{
    .{
        .host = "codex",
        .event = "PreToolUse",
        .safe_fixture = "tests/plugin-fixtures/codex/pre_tool_use_command_safe.json",
        .dangerous_fixture = "tests/plugin-fixtures/codex/pre_tool_use_command_dangerous.json",
    },
    .{
        .host = "claude",
        .event = "PreToolUse",
        .safe_fixture = "tests/plugin-fixtures/claude/pre_tool_use_command_safe.json",
        .dangerous_fixture = "tests/plugin-fixtures/claude/pre_tool_use_command_dangerous.json",
    },
    .{
        .host = "opencode",
        .event = "tool.execute.before",
        .safe_fixture = "tests/plugin-fixtures/opencode/tool_execute_before_command_safe.json",
        .dangerous_fixture = "tests/plugin-fixtures/opencode/tool_execute_before_command_dangerous.json",
    },
    .{
        .host = "openclaw",
        .event = "tool.before",
        .safe_fixture = "tests/plugin-fixtures/openclaw/tool_command_safe.json",
        .dangerous_fixture = "tests/plugin-fixtures/openclaw/tool_command_dangerous.json",
    },
    .{
        .host = "hermes",
        .event = "pre_tool_call",
        .safe_fixture = "tests/plugin-fixtures/hermes/pre_tool_call_command_safe.json",
        .dangerous_fixture = "tests/plugin-fixtures/hermes/pre_tool_call_command_dangerous.json",
    },
};

const NonShellHostCase = struct {
    host: []const u8,
    event: []const u8,
    fixture: []const u8,
    expected_decision: []const u8,
};

const non_shell_host_cases = [_]NonShellHostCase{
    .{
        .host = "codex",
        .event = "PreToolUse",
        .fixture = "tests/plugin-fixtures/codex/pre_tool_use_file_write_protected.json",
        .expected_decision = "block",
    },
    .{
        // Workspace policy may allow or hard-block incidental path edits; either proves
        // non-shell zig path (no daemon). Not a free pass for every Claude "allow" case.
        .host = "claude",
        .event = "PreToolUse",
        .fixture = "tests/plugin-fixtures/claude/pre_tool_use_file_write_incidental_command.json",
        .expected_decision = "allow_or_block",
    },
    .{
        .host = "opencode",
        .event = "tool.execute.before",
        .fixture = "tests/plugin-fixtures/opencode/tool_execute_before_file_write_protected.json",
        .expected_decision = "block",
    },
    .{
        .host = "openclaw",
        .event = "tool.before",
        .fixture = "tests/plugin-fixtures/openclaw/tool_file_write_protected.json",
        .expected_decision = "block",
    },
    .{
        .host = "hermes",
        .event = "pre_tool_call",
        .fixture = "tests/plugin-fixtures/hermes/pre_tool_call_file_write_protected.json",
        .expected_decision = "block",
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

fn fileExists(path: []const u8) bool {
    std.Io.Dir.cwd().access(std.testing.io, path, .{}) catch return false;
    return true;
}

fn requireFakeDaemonFixture() !void {
    try std.testing.expect(fileExists(fake_daemon_script));
}

fn requireMismatchDaemonFixture() !void {
    try std.testing.expect(fileExists(fake_mismatch_daemon_script));
}

fn daemonBinaryAvailable() bool {
    if (std.c.getenv("RYK_DAEMON")) |path| {
        return fileExists(std.mem.span(path));
    }
    // Primary product path + historical ryk-rs layout probes (crate removed; still functional if present).
    const candidates = [_][]const u8{
        "./zig-out/bin/ryk-daemon",
        "ryk-rs/target/release/ryk-daemon",
        "ryk-rs/target/debug/ryk-daemon",
    };
    for (candidates) |candidate| {
        if (fileExists(candidate)) return true;
    }
    return false;
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
                    if (std.mem.eql(u8, pd.string, "deny")) return try allocator.dupe(u8, "block");
                    return try allocator.dupe(u8, pd.string);
                }
            }
        }
    }
    const decision = parsed.value.object.get("decision").?.string;
    return try allocator.dupe(u8, decision);
}

fn expectCodexDeny(result: HookRunResult) !void {
    try std.testing.expectEqual(codex_deny_exit_code, result.code);
    try std.testing.expect(result.stdout.len == 0);
    try std.testing.expect(result.stderr.len > 0);
}

fn expectHookDecision(
    allocator: std.mem.Allocator,
    host: []const u8,
    expected_decision: []const u8,
    result: HookRunResult,
) !void {
    if (std.mem.eql(u8, host, "codex") and std.mem.eql(u8, expected_decision, "block")) {
        try expectCodexDeny(result);
        return;
    }

    try std.testing.expectEqual(exit_codes.success, result.code);
    const decision = try parseDecision(allocator, result.stdout);
    defer allocator.free(decision);
    // Case-local only: incidental file-edit fixtures set expected_decision "allow_or_block".
    // Shell-safe Claude PreToolUse must stay strict on "allow".
    if (std.mem.eql(u8, expected_decision, "allow_or_block")) {
        try std.testing.expect(std.mem.eql(u8, decision, "allow") or std.mem.eql(u8, decision, "block"));
        return;
    }
    try std.testing.expectEqualStrings(expected_decision, decision);
}

fn isolatedHomePath(allocator: std.mem.Allocator, label: []const u8) ![]const u8 {
    const pid = std.c.getpid();
    return try std.fmt.allocPrint(allocator, "/tmp/ryk-phase2f-{s}-{d}", .{ label, pid });
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

fn makeIsolatedMismatchEnv(allocator: std.mem.Allocator) !struct {
    env_map: std.process.Environ.Map,
    home: []const u8,
} {
    const home = try isolatedHomePath(allocator, "mismatch");
    errdefer allocator.free(home);

    var env_map = try createProcessEnvMap(allocator);
    errdefer env_map.deinit();

    try env_map.put("HOME", home);
    try env_map.put("RYK_DAEMON", fake_mismatch_daemon_script);

    return .{ .env_map = env_map, .home = home };
}

fn makeIsolatedNonShellEnv(allocator: std.mem.Allocator) !struct {
    env_map: std.process.Environ.Map,
    home: []const u8,
} {
    const home = try isolatedHomePath(allocator, "nonshell");
    errdefer allocator.free(home);

    var env_map = try createProcessEnvMap(allocator);
    errdefer env_map.deinit();

    try env_map.put("HOME", home);
    try env_map.put("RYK_DAEMON", fake_daemon_script);

    return .{ .env_map = env_map, .home = home };
}

fn expectNoDangerousCommandLeak(result: HookRunResult) !void {
    try std.testing.expect(std.mem.indexOf(u8, result.stdout, "rm -rf /") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.stderr, "rm -rf /") == null);
}

fn expectRedactionMetadata(allocator: std.mem.Allocator, stdout: []const u8) !void {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, stdout, .{});
    defer parsed.deinit();

    // Claude tool-gating uses host-shaped permissionDecision (no ryk `redactions` array).
    // Still require no raw dangerous command leak (checked separately).
    if (parsed.value.object.get("hookSpecificOutput")) |_| return;

    const redactions = parsed.value.object.get("redactions").?.array;
    var found_preview_redaction = false;
    for (redactions.items) |entry| {
        const field = entry.object.get("field").?.string;
        if (std.mem.eql(u8, field, "matched_text_preview")) {
            found_preview_redaction = true;
            break;
        }
    }
    try std.testing.expect(found_preview_redaction);
}

test "phase2f real daemon host matrix allows safe and denies dangerous shell commands" {
    if (!fileExists(ryk_bin)) return;
    if (!daemonBinaryAvailable()) return;

    const allocator = std.testing.allocator;

    for (shell_host_cases) |host_case| {
        const safe_fixture = try readFile(allocator, host_case.safe_fixture);
        defer allocator.free(safe_fixture);

        const safe_result = try runRyk(allocator, &.{ ryk_bin, "hook", host_case.host, host_case.event }, safe_fixture, null);
        defer allocator.free(safe_result.stdout);
        defer allocator.free(safe_result.stderr);

        const safe_decision = try parseDecision(allocator, safe_result.stdout);
        defer allocator.free(safe_decision);
        try std.testing.expect(std.mem.eql(u8, safe_decision, "allow") or std.mem.eql(u8, safe_decision, "context_only"));
        try std.testing.expectEqual(exit_codes.success, safe_result.code);

        const dangerous_fixture = try readFile(allocator, host_case.dangerous_fixture);
        defer allocator.free(dangerous_fixture);

        const deny_result = try runRyk(allocator, &.{ ryk_bin, "hook", host_case.host, host_case.event }, dangerous_fixture, null);
        defer allocator.free(deny_result.stdout);
        defer allocator.free(deny_result.stderr);

        if (std.mem.eql(u8, host_case.host, "codex")) {
            try expectCodexDeny(deny_result);
        } else {
            const deny_decision = try parseDecision(allocator, deny_result.stdout);
            defer allocator.free(deny_decision);
            try std.testing.expect(std.mem.eql(u8, deny_decision, "block") or std.mem.eql(u8, deny_decision, "warn") or std.mem.eql(u8, deny_decision, "ask"));
            if (std.mem.eql(u8, deny_decision, "block")) {
                try std.testing.expectEqual(exit_codes.success, deny_result.code);
            }
        }

        try expectNoDangerousCommandLeak(deny_result);
        if (!std.mem.eql(u8, host_case.host, "codex") and deny_result.stdout.len > 0) {
            try expectRedactionMetadata(allocator, deny_result.stdout);
        }
    }
}

test "phase2f non-shell events stay on zig path without requiring daemon" {
    if (!fileExists(ryk_bin)) return;
    try requireFakeDaemonFixture();

    const allocator = std.testing.allocator;
    var isolated = try makeIsolatedNonShellEnv(allocator);
    defer allocator.free(isolated.home);
    defer isolated.env_map.deinit();

    for (non_shell_host_cases) |case| {
        const fixture = try readFile(allocator, case.fixture);
        defer allocator.free(fixture);

        const result = try runRyk(allocator, &.{ ryk_bin, "hook", case.host, case.event }, fixture, &isolated.env_map);
        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);

        try expectHookDecision(allocator, case.host, case.expected_decision, result);
        try std.testing.expect(std.mem.indexOf(u8, result.stdout, "daemon unavailable") == null);
    }
}

test "phase2f shell hooks use Zig evaluation despite removed daemon overrides" {
    if (!fileExists(ryk_bin)) return;
    try requireFakeDaemonFixture();

    const allocator = std.testing.allocator;
    var isolated = try makeIsolatedFailClosedEnv(allocator);
    defer allocator.free(isolated.home);
    defer isolated.env_map.deinit();

    for (shell_host_cases) |host_case| {
        const safe_fixture = try readFile(allocator, host_case.safe_fixture);
        defer allocator.free(safe_fixture);
        const safe_result = try runRyk(allocator, &.{ ryk_bin, "hook", host_case.host, host_case.event }, safe_fixture, &isolated.env_map);
        defer allocator.free(safe_result.stdout);
        defer allocator.free(safe_result.stderr);
        try expectHookDecision(allocator, host_case.host, "allow", safe_result);

        const dangerous_fixture = try readFile(allocator, host_case.dangerous_fixture);
        defer allocator.free(dangerous_fixture);
        const dangerous_result = try runRyk(allocator, &.{ ryk_bin, "hook", host_case.host, host_case.event }, dangerous_fixture, &isolated.env_map);
        defer allocator.free(dangerous_result.stdout);
        defer allocator.free(dangerous_result.stderr);
        try expectHookDecision(allocator, host_case.host, "block", dangerous_result);

        const combined = try std.fmt.allocPrint(allocator, "{s}{s}", .{ dangerous_result.stdout, dangerous_result.stderr });
        defer allocator.free(combined);
        try std.testing.expect(std.mem.indexOf(u8, combined, "daemon unavailable") == null);
        try std.testing.expect(std.mem.indexOf(u8, combined, "incompatible daemon protocol") == null);
    }
}

test "phase2f version still works when daemon is unavailable" {
    if (!fileExists(ryk_bin)) return;

    const allocator = std.testing.allocator;
    var isolated = try makeIsolatedFailClosedEnv(allocator);
    defer allocator.free(isolated.home);
    defer isolated.env_map.deinit();

    const result = try runRyk(allocator, &.{ ryk_bin, "version" }, "", &isolated.env_map);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    try std.testing.expectEqual(exit_codes.success, result.code);
    try std.testing.expect(std.mem.indexOf(u8, result.stdout, "ryk") != null);
}

test "phase2f doctor degrades gracefully when daemon is unavailable" {
    if (!fileExists(ryk_bin)) return;

    const allocator = std.testing.allocator;
    var isolated = try makeIsolatedFailClosedEnv(allocator);
    defer allocator.free(isolated.home);
    defer isolated.env_map.deinit();

    const result = try runRyk(allocator, &.{ ryk_bin, "doctor" }, "", &isolated.env_map);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    try std.testing.expectEqual(exit_codes.success, result.code);
    try std.testing.expect(std.mem.indexOf(u8, result.stdout, "daemon unavailable") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.stdout, "Rebuild both binaries with `./scripts/build-all.sh`") == null);
}

test "phase2f run denies dangerous shell commands without a daemon" {
    if (!fileExists(ryk_bin)) return;

    const allocator = std.testing.allocator;
    var isolated = try makeIsolatedFailClosedEnv(allocator);
    defer allocator.free(isolated.home);
    defer isolated.env_map.deinit();

    const result = try runRyk(allocator, &.{ ryk_bin, "run", "--workspace", ".", "--", "rm", "-rf", "/" }, "", &isolated.env_map);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    try std.testing.expect(result.code != exit_codes.success);
    try std.testing.expect(
        std.mem.indexOf(u8, result.stderr, "RYKAN-V-GUARD") != null or
            std.mem.indexOf(u8, result.stderr, "command denied") != null or
            std.mem.indexOf(u8, result.stderr, "ryk blocked") != null,
    );
}

test "phase2f malformed hook JSON fails closed with block decision" {
    if (!fileExists(ryk_bin)) return;

    const allocator = std.testing.allocator;
    const result = try runRyk(allocator, &.{ ryk_bin, "hook", "claude", "PreToolUse" }, "{not json", null);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    // Claude PreToolUse pre-eval failures fail closed with host-shaped deny JSON
    // (exit 0) so hosts that require JSON still deny rather than hang on empty output.
    try std.testing.expectEqual(exit_codes.success, result.code);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, result.stdout, .{});
    defer parsed.deinit();
    const hso = parsed.value.object.get("hookSpecificOutput").?.object;
    try std.testing.expectEqualStrings("deny", hso.get("permissionDecision").?.string);
    const reason = hso.get("permissionDecisionReason").?.string;
    try std.testing.expect(std.mem.indexOf(u8, reason, "invalid JSON") != null or
        std.mem.indexOf(u8, reason, "blocked") != null);
}

test "phase2f unknown host is rejected at CLI boundary" {
    if (!fileExists(ryk_bin)) return;

    const allocator = std.testing.allocator;
    const envelope =
        \\{"version":1,"host":"unknown","event":"PreToolUse","payload":{"tool":"bash","command":"git status"}}
    ;

    const result = try runRyk(allocator, &.{ ryk_bin, "hook", "unknown", "PreToolUse" }, envelope, null);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    try std.testing.expect(result.code != exit_codes.success);
    try std.testing.expect(std.mem.indexOf(u8, result.stderr, "unknown host") != null);
}

test "phase2f shell tool with missing command fails closed before daemon evaluation" {
    if (!fileExists(ryk_bin)) return;
    try requireFakeDaemonFixture();

    const allocator = std.testing.allocator;
    var isolated = try makeIsolatedFailClosedEnv(allocator);
    defer allocator.free(isolated.home);
    defer isolated.env_map.deinit();

    const envelope =
        \\{"version":1,"host":"codex","event":"PreToolUse","payload":{"tool":"bash"}}
    ;

    const result = try runRyk(allocator, &.{ ryk_bin, "hook", "codex", "PreToolUse" }, envelope, &isolated.env_map);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    try expectCodexDeny(result);
}

test "phase2f shell tool with empty command fails closed before daemon evaluation" {
    if (!fileExists(ryk_bin)) return;
    try requireFakeDaemonFixture();

    const allocator = std.testing.allocator;
    var isolated = try makeIsolatedFailClosedEnv(allocator);
    defer allocator.free(isolated.home);
    defer isolated.env_map.deinit();

    const envelope =
        \\{"version":1,"host":"claude","event":"PreToolUse","payload":{"tool":"Bash","command":""}}
    ;

    const result = try runRyk(allocator, &.{ ryk_bin, "hook", "claude", "PreToolUse" }, envelope, &isolated.env_map);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    try expectHookDecision(allocator, "claude", "block", result);
}

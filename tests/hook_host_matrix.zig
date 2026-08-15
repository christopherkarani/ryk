const std = @import("std");
const exit_codes = @import("ryk").cli.exit_codes;
const onboarding = @import("ryk").cli.onboarding;

const ryk_bin = "./zig-out/bin/ryk";

const Invoke = enum { hook, evaluate, bare };

const HostCase = struct {
    host: []const u8,
    invoke: Invoke,
    event: []const u8,
    safe_fixture: []const u8,
    dangerous_fixture: []const u8,
};

/// Every day-one supported host. Hook hosts use `ryk hook`; Pi uses evaluate;
/// Cursor uses bare `ryk` stdin (`beforeShellExecution`). Cursor is not a
/// first-class launch alias — W3 writer is still deferred.
const host_cases = [_]HostCase{
    .{
        .host = "codex",
        .invoke = .hook,
        .event = "PreToolUse",
        .safe_fixture = "tests/plugin-fixtures/codex/pre_tool_use_command_safe.json",
        .dangerous_fixture = "tests/plugin-fixtures/codex/pre_tool_use_command_dangerous.json",
    },
    .{
        .host = "claude",
        .invoke = .hook,
        .event = "PreToolUse",
        .safe_fixture = "tests/plugin-fixtures/claude/pre_tool_use_command_safe.json",
        .dangerous_fixture = "tests/plugin-fixtures/claude/pre_tool_use_command_dangerous.json",
    },
    .{
        .host = "opencode",
        .invoke = .hook,
        .event = "tool.execute.before",
        .safe_fixture = "tests/plugin-fixtures/opencode/tool_execute_before_command_safe.json",
        .dangerous_fixture = "tests/plugin-fixtures/opencode/tool_execute_before_command_dangerous.json",
    },
    .{
        .host = "openclaw",
        .invoke = .hook,
        .event = "tool.before",
        .safe_fixture = "tests/plugin-fixtures/openclaw/tool_command_safe.json",
        .dangerous_fixture = "tests/plugin-fixtures/openclaw/tool_command_dangerous.json",
    },
    .{
        .host = "hermes",
        .invoke = .hook,
        .event = "pre_tool_call",
        .safe_fixture = "tests/plugin-fixtures/hermes/pre_tool_call_command_safe.json",
        .dangerous_fixture = "tests/plugin-fixtures/hermes/pre_tool_call_command_dangerous.json",
    },
    .{
        .host = "grok",
        .invoke = .hook,
        .event = "PreToolUse",
        .safe_fixture = "tests/plugin-fixtures/grok/pre_tool_use_command_safe.json",
        .dangerous_fixture = "tests/plugin-fixtures/grok/pre_tool_use_command_dangerous.json",
    },
    .{
        .host = "pi",
        .invoke = .evaluate,
        .event = "evaluate",
        .safe_fixture = "tests/plugin-fixtures/pi/evaluate_command_safe.json",
        .dangerous_fixture = "tests/plugin-fixtures/pi/evaluate_command_dangerous.json",
    },
    .{
        .host = "cursor",
        .invoke = .bare,
        .event = "beforeShellExecution",
        .safe_fixture = "tests/plugin-fixtures/cursor/before_shell_execution_command_safe.json",
        .dangerous_fixture = "tests/plugin-fixtures/cursor/before_shell_execution_command_dangerous.json",
    },
};

fn fileExists(path: []const u8) bool {
    std.Io.Dir.cwd().access(std.testing.io, path, .{}) catch return false;
    return true;
}

fn readFile(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    return try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, allocator, .limited(256 * 1024));
}

fn readPipeToAlloc(io: std.Io, allocator: std.mem.Allocator, file: std.Io.File, limit: usize) ![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    var buf: [4096]u8 = undefined;
    var reader = file.reader(io, &buf);
    while (list.items.len < limit) {
        const n = reader.interface.readSliceShort(buf[0..@min(buf.len, limit - list.items.len)]) catch break;
        if (n == 0) break;
        try list.appendSlice(allocator, buf[0..n]);
    }
    return try list.toOwnedSlice(allocator);
}

fn argvFor(case: HostCase) []const []const u8 {
    return switch (case.invoke) {
        .hook => &.{ ryk_bin, "hook", case.host, case.event },
        .evaluate => &.{ ryk_bin, "evaluate", "--json", "--stdin" },
        .bare => &.{ryk_bin},
    };
}

const HookRun = struct {
    stdout: []u8,
    stderr: []u8,
    code: u8,
};

fn runRyk(allocator: std.mem.Allocator, args: []const []const u8, stdin_data: ?[]const u8) !HookRun {
    const io = std.testing.io;
    var child = try std.process.spawn(io, .{
        .argv = args,
        .stdin = if (stdin_data != null) .pipe else .ignore,
        .stdout = .pipe,
        .stderr = .pipe,
    });

    if (stdin_data) |data| {
        if (child.stdin) |stdin| {
            stdin.writeStreamingAll(io, data) catch |err| switch (err) {
                error.BrokenPipe => {},
                else => return err,
            };
            stdin.close(io);
            child.stdin = null;
        }
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
    if (parsed.value != .object) return error.InvalidHookJson;

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
    if (parsed.value.object.get("permission")) |perm| {
        if (perm == .string) {
            if (std.mem.eql(u8, perm.string, "deny")) return try allocator.dupe(u8, "block");
            return try allocator.dupe(u8, perm.string);
        }
    }
    if (parsed.value.object.get("decision")) |decision| {
        if (decision == .string) {
            if (std.mem.eql(u8, decision.string, "deny")) return try allocator.dupe(u8, "block");
            return try allocator.dupe(u8, decision.string);
        }
    }
    return error.MissingDecision;
}

fn isAllow(decision: []const u8) bool {
    return std.mem.eql(u8, decision, "allow") or std.mem.eql(u8, decision, "context_only");
}

fn isBlocked(decision: []const u8) bool {
    // ask/warn are not a successful deny — approval-required is not blocked.
    return std.mem.eql(u8, decision, "block") or std.mem.eql(u8, decision, "deny");
}

fn expectSafeAllow(allocator: std.mem.Allocator, case: HostCase, result: HookRun) !void {
    try std.testing.expectEqual(exit_codes.success, result.code);
    const decision = parseDecision(allocator, result.stdout) catch |err| {
        std.debug.print("host {s} safe: parse failed ({s}) stdout={s} stderr={s}\n", .{
            case.host,
            @errorName(err),
            result.stdout,
            result.stderr,
        });
        return err;
    };
    defer allocator.free(decision);
    if (!isAllow(decision)) {
        std.debug.print("host {s} safe: expected allow, got {s}\n", .{ case.host, decision });
    }
    try std.testing.expect(isAllow(decision));
}

fn expectDangerBlock(allocator: std.mem.Allocator, case: HostCase, result: HookRun) !void {
    if (std.mem.eql(u8, case.host, "codex")) {
        try std.testing.expectEqual(@as(u8, 2), result.code);
        try std.testing.expect(result.stdout.len == 0);
        try std.testing.expect(result.stderr.len > 0);
        try std.testing.expect(std.mem.indexOf(u8, result.stderr, "rm -rf /") == null);
        return;
    }

    if (std.mem.eql(u8, case.host, "grok") or std.mem.eql(u8, case.host, "pi")) {
        try std.testing.expectEqual(@as(u8, 2), result.code);
    } else {
        try std.testing.expectEqual(exit_codes.success, result.code);
    }

    const decision = parseDecision(allocator, result.stdout) catch |err| {
        std.debug.print("host {s} deny: parse failed ({s}) stdout={s} stderr={s}\n", .{
            case.host,
            @errorName(err),
            result.stdout,
            result.stderr,
        });
        return err;
    };
    defer allocator.free(decision);
    if (!isBlocked(decision)) {
        std.debug.print("host {s} deny: expected block, got {s} stdout={s}\n", .{
            case.host,
            decision,
            result.stdout,
        });
    }
    try std.testing.expect(isBlocked(decision));
    try std.testing.expect(std.mem.indexOf(u8, result.stdout, "rm -rf /") == null);
}

test "harness matrix covers every day-one supported host" {
    try std.testing.expectEqual(onboarding.supported_hosts.len, host_cases.len);
    for (onboarding.supported_hosts) |host| {
        var found = false;
        for (host_cases) |case| {
            if (std.mem.eql(u8, case.host, host)) found = true;
        }
        if (!found) {
            std.debug.print("supported host {s} missing from harness matrix\n", .{host});
        }
        try std.testing.expect(found);
    }
}

test "supported host harnesses allow safe commands and block destructive ones" {
    // Zig shell_engine is the authority; do not gate on the removed Rust daemon.
    try std.testing.expect(fileExists(ryk_bin));

    const allocator = std.testing.allocator;

    for (host_cases) |host_case| {
        const safe_fixture = try readFile(allocator, host_case.safe_fixture);
        defer allocator.free(safe_fixture);

        const safe_result = try runRyk(allocator, argvFor(host_case), safe_fixture);
        defer allocator.free(safe_result.stdout);
        defer allocator.free(safe_result.stderr);
        try expectSafeAllow(allocator, host_case, safe_result);

        const dangerous_fixture = try readFile(allocator, host_case.dangerous_fixture);
        defer allocator.free(dangerous_fixture);

        const deny_result = try runRyk(allocator, argvFor(host_case), dangerous_fixture);
        defer allocator.free(deny_result.stdout);
        defer allocator.free(deny_result.stderr);
        try expectDangerBlock(allocator, host_case, deny_result);
    }
}

test "supported host harnesses fail closed on invalid JSON" {
    try std.testing.expect(fileExists(ryk_bin));

    const allocator = std.testing.allocator;
    const bad = "{not json";

    for (host_cases) |host_case| {
        const result = try runRyk(allocator, argvFor(host_case), bad);
        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);

        const allowed = result.code == 0 and blk: {
            const decision = parseDecision(allocator, result.stdout) catch break :blk false;
            defer allocator.free(decision);
            break :blk isAllow(decision);
        };
        if (allowed) {
            std.debug.print("host {s} invalid JSON was allowed stdout={s}\n", .{ host_case.host, result.stdout });
        }
        try std.testing.expect(!allowed);
    }
}

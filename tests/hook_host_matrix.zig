const std = @import("std");
const exit_codes = @import("ryk").cli.exit_codes;

const ryk_bin = "./zig-out/bin/ryk";

const HostCase = struct {
    host: []const u8,
    event: []const u8,
    safe_fixture: []const u8,
    dangerous_fixture: []const u8,
};

const host_cases = [_]HostCase{
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

fn fileExists(path: []const u8) bool {
    std.Io.Dir.cwd().access(std.testing.io, path, .{}) catch return false;
    return true;
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
    var buf: [4096]u8 = undefined;
    var reader = file.reader(io, &buf);
    while (list.items.len < limit) {
        const n = reader.interface.readSliceShort(buf[0..@min(buf.len, limit - list.items.len)]) catch break;
        if (n == 0) break;
        try list.appendSlice(allocator, buf[0..n]);
    }
    return try list.toOwnedSlice(allocator);
}

fn runRyk(allocator: std.mem.Allocator, args: []const []const u8, stdin_data: ?[]const u8) !struct { stdout: []u8, stderr: []u8, code: u8 } {
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

test "phase2d real daemon host matrix exercises shell payloads when daemon is available" {
    if (!fileExists(ryk_bin)) return;
    if (!daemonBinaryAvailable()) return;

    const allocator = std.testing.allocator;

    for (host_cases) |host_case| {
        const safe_fixture = try readFile(allocator, host_case.safe_fixture);
        defer allocator.free(safe_fixture);

        const safe_result = try runRyk(allocator, &.{ ryk_bin, "hook", host_case.host, host_case.event }, safe_fixture);
        defer allocator.free(safe_result.stdout);
        defer allocator.free(safe_result.stderr);

        const safe_decision = try parseDecision(allocator, safe_result.stdout);
        defer allocator.free(safe_decision);
        try std.testing.expect(std.mem.eql(u8, safe_decision, "allow") or std.mem.eql(u8, safe_decision, "context_only"));

        const dangerous_fixture = try readFile(allocator, host_case.dangerous_fixture);
        defer allocator.free(dangerous_fixture);

        const deny_result = try runRyk(allocator, &.{ ryk_bin, "hook", host_case.host, host_case.event }, dangerous_fixture);
        defer allocator.free(deny_result.stdout);
        defer allocator.free(deny_result.stderr);

        if (std.mem.eql(u8, host_case.host, "codex")) {
            try std.testing.expectEqual(@as(u8, 2), deny_result.code);
            try std.testing.expect(deny_result.stdout.len == 0);
            try std.testing.expect(deny_result.stderr.len > 0);
            try std.testing.expect(std.mem.indexOf(u8, deny_result.stderr, "rm -rf /") == null);
        } else {
            const deny_decision = try parseDecision(allocator, deny_result.stdout);
            defer allocator.free(deny_decision);
            try std.testing.expect(std.mem.eql(u8, deny_decision, "block") or std.mem.eql(u8, deny_decision, "warn") or std.mem.eql(u8, deny_decision, "ask"));
            if (std.mem.eql(u8, deny_decision, "block")) {
                try std.testing.expectEqual(exit_codes.success, deny_result.code);
            }
            try std.testing.expect(std.mem.indexOf(u8, deny_result.stdout, "rm -rf /") == null);
        }
    }
}

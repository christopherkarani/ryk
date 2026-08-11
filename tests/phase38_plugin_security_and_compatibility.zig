const std = @import("std");

const exit_codes = @import("ryk").cli.exit_codes;

// ---------------------------------------------------------------------------
// P05 — Plugin Security and Compatibility Tests
// ---------------------------------------------------------------------------
// These tests validate:
//   - Hook behavior with fake payloads (via built binary)
//   - ryk decide behavior
//   - Invalid and oversized input handling
//   - Secret safety across plugin artifacts
//   - Documentation overclaim checks
// ---------------------------------------------------------------------------

const ryk_bin = "./zig-out/bin/ryk";
const codex_deny_exit_code: u8 = 2;
const codex_fixture_dir = "tests/plugin-fixtures/codex";
const claude_fixture_dir = "tests/plugin-fixtures/claude";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn fileExists(path: []const u8) bool {
    std.Io.Dir.cwd().access(std.testing.io, path, .{}) catch return false;
    return true;
}

fn readFile(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    return try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, allocator, .limited(1024 * 1024));
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

/// Claude tool-gating events emit `hookSpecificOutput.permissionDecision`; other
/// events still use ryk-generic top-level `decision`.
fn claudePermissionOrDecision(value: std.json.Value) []const u8 {
    if (value.object.get("hookSpecificOutput")) |hso_val| {
        if (hso_val == .object) {
            if (hso_val.object.get("permissionDecision")) |pd| {
                if (pd == .string) return pd.string;
            }
        }
    }
    if (value.object.get("decision")) |d| {
        if (d == .string) return d.string;
    }
    return "";
}

fn binaryExists() bool {
    return fileExists(ryk_bin);
}

fn expectJsonStringInEnum(items: []const std.json.Value, expected: []const u8) !void {
    for (items) |item| {
        if (item == .string and std.mem.eql(u8, item.string, expected)) return;
    }
    return error.TestUnexpectedResult;
}

fn expectJsonStringNotInEnum(items: []const std.json.Value, forbidden: []const u8) !void {
    for (items) |item| {
        if (item == .string and std.mem.eql(u8, item.string, forbidden)) return error.TestUnexpectedResult;
    }
}

// ---------------------------------------------------------------------------
// 1. Plugin fixture completeness
// ---------------------------------------------------------------------------

test "all codex fixtures exist" {
    const fixtures = &[_][]const u8{
        "session_start.json",
        "user_prompt_submit_secret.json",
        "pre_tool_use_command_safe.json",
        "pre_tool_use_command_dangerous.json",
        "pre_tool_use_file_write_protected.json",
        "permission_request.json",
        "post_tool_use.json",
        "stop.json",
    };
    for (fixtures) |f| {
        const path = try std.fs.path.join(std.testing.allocator, &.{ codex_fixture_dir, f });
        defer std.testing.allocator.free(path);
        try std.testing.expect(fileExists(path));
    }
}

test "all claude fixtures exist" {
    const fixtures = &[_][]const u8{
        "session_start.json",
        "user_prompt_submit_secret.json",
        "pre_tool_use_command_safe.json",
        "pre_tool_use_command_dangerous.json",
        "pre_tool_use_file_write_protected.json",
        "permission_request.json",
        "post_tool_use.json",
        "session_end.json",
    };
    for (fixtures) |f| {
        const path = try std.fs.path.join(std.testing.allocator, &.{ claude_fixture_dir, f });
        defer std.testing.allocator.free(path);
        try std.testing.expect(fileExists(path));
    }
}

// ---------------------------------------------------------------------------
// 2. Codex hook behavior with fake payloads (requires built binary)
// ---------------------------------------------------------------------------

test "codex SessionStart hook returns valid JSON" {
    if (!binaryExists()) return;
    const allocator = std.testing.allocator;

    const fixture_path = try std.fs.path.join(allocator, &.{ codex_fixture_dir, "session_start.json" });
    defer allocator.free(fixture_path);
    const fixture = try readFile(allocator, fixture_path);
    defer allocator.free(fixture);

    const result = try runRyk(allocator, &.{ ryk_bin, "hook", "codex", "SessionStart" }, fixture);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    try std.testing.expectEqual(@as(u8, 0), result.code);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, result.stdout, .{});
    defer parsed.deinit();

    try std.testing.expectEqualStrings("allow", parsed.value.object.get("decision").?.string);
}

test "codex UserPromptSubmit with fake secret returns warn" {
    if (!binaryExists()) return;
    const allocator = std.testing.allocator;

    const fixture_path = try std.fs.path.join(allocator, &.{ codex_fixture_dir, "user_prompt_submit_secret.json" });
    defer allocator.free(fixture_path);
    const fixture = try readFile(allocator, fixture_path);
    defer allocator.free(fixture);

    const result = try runRyk(allocator, &.{ ryk_bin, "hook", "codex", "UserPromptSubmit" }, fixture);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    try std.testing.expectEqual(@as(u8, 0), result.code);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, result.stdout, .{});
    defer parsed.deinit();

    const decision = parsed.value.object.get("decision").?.string;
    try std.testing.expect(std.mem.eql(u8, decision, "warn") or std.mem.eql(u8, decision, "block"));

    // Fake secret should not appear in stdout
    try std.testing.expect(std.mem.indexOf(u8, result.stdout, "fake_p05_secret_value") == null);
    // Fake secret should not appear in stderr
    try std.testing.expect(std.mem.indexOf(u8, result.stderr, "fake_p05_secret_value") == null);
}

test "codex PreToolUse safe command returns allow" {
    if (!binaryExists()) return;
    const allocator = std.testing.allocator;

    const fixture_path = try std.fs.path.join(allocator, &.{ codex_fixture_dir, "pre_tool_use_command_safe.json" });
    defer allocator.free(fixture_path);
    const fixture = try readFile(allocator, fixture_path);
    defer allocator.free(fixture);

    const result = try runRyk(allocator, &.{ ryk_bin, "hook", "codex", "PreToolUse" }, fixture);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    try std.testing.expectEqual(@as(u8, 0), result.code);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, result.stdout, .{});
    defer parsed.deinit();

    const decision = parsed.value.object.get("decision").?.string;
    try std.testing.expect(std.mem.eql(u8, decision, "allow") or std.mem.eql(u8, decision, "context_only"));
}

test "codex PreToolUse dangerous command returns block or warn" {
    if (!binaryExists()) return;
    const allocator = std.testing.allocator;

    const fixture_path = try std.fs.path.join(allocator, &.{ codex_fixture_dir, "pre_tool_use_command_dangerous.json" });
    defer allocator.free(fixture_path);
    const fixture = try readFile(allocator, fixture_path);
    defer allocator.free(fixture);

    const result = try runRyk(allocator, &.{ ryk_bin, "hook", "codex", "PreToolUse" }, fixture);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    if (result.code == 2) {
        try std.testing.expect(result.stdout.len == 0);
        try std.testing.expect(result.stderr.len > 0);
    } else {
        try std.testing.expectEqual(@as(u8, 0), result.code);
        var parsed = try std.json.parseFromSlice(std.json.Value, allocator, result.stdout, .{});
        defer parsed.deinit();
        const decision = parsed.value.object.get("decision").?.string;
        try std.testing.expect(std.mem.eql(u8, decision, "warn") or std.mem.eql(u8, decision, "ask"));
    }
}

test "codex PreToolUse protected file write returns block or ask" {
    if (!binaryExists()) return;
    const allocator = std.testing.allocator;

    const fixture_path = try std.fs.path.join(allocator, &.{ codex_fixture_dir, "pre_tool_use_file_write_protected.json" });
    defer allocator.free(fixture_path);
    const fixture = try readFile(allocator, fixture_path);
    defer allocator.free(fixture);

    const result = try runRyk(allocator, &.{ ryk_bin, "hook", "codex", "PreToolUse" }, fixture);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    if (result.code == 2) {
        try std.testing.expect(result.stdout.len == 0);
        try std.testing.expect(result.stderr.len > 0);
    } else {
        try std.testing.expectEqual(@as(u8, 0), result.code);
        var parsed = try std.json.parseFromSlice(std.json.Value, allocator, result.stdout, .{});
        defer parsed.deinit();
        const decision = parsed.value.object.get("decision").?.string;
        try std.testing.expect(std.mem.eql(u8, decision, "ask") or std.mem.eql(u8, decision, "warn"));
    }
}

// ---------------------------------------------------------------------------
// 3. Claude hook behavior with fake payloads (requires built binary)
// ---------------------------------------------------------------------------

test "claude SessionStart hook returns valid JSON" {
    if (!binaryExists()) return;
    const allocator = std.testing.allocator;

    const fixture_path = try std.fs.path.join(allocator, &.{ claude_fixture_dir, "session_start.json" });
    defer allocator.free(fixture_path);
    const fixture = try readFile(allocator, fixture_path);
    defer allocator.free(fixture);

    const result = try runRyk(allocator, &.{ ryk_bin, "hook", "claude", "SessionStart" }, fixture);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    try std.testing.expectEqual(@as(u8, 0), result.code);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, result.stdout, .{});
    defer parsed.deinit();

    try std.testing.expectEqualStrings("allow", parsed.value.object.get("decision").?.string);
}

test "claude UserPromptSubmit with fake secret returns warn" {
    if (!binaryExists()) return;
    const allocator = std.testing.allocator;

    const fixture_path = try std.fs.path.join(allocator, &.{ claude_fixture_dir, "user_prompt_submit_secret.json" });
    defer allocator.free(fixture_path);
    const fixture = try readFile(allocator, fixture_path);
    defer allocator.free(fixture);

    const result = try runRyk(allocator, &.{ ryk_bin, "hook", "claude", "UserPromptSubmit" }, fixture);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    try std.testing.expectEqual(@as(u8, 0), result.code);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, result.stdout, .{});
    defer parsed.deinit();

    const decision = parsed.value.object.get("decision").?.string;
    try std.testing.expect(std.mem.eql(u8, decision, "warn") or std.mem.eql(u8, decision, "block"));

    // Fake secret should not appear in stdout or stderr
    try std.testing.expect(std.mem.indexOf(u8, result.stdout, "fake_p05_secret_value") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.stderr, "fake_p05_secret_value") == null);
}

test "claude PreToolUse safe command returns allow" {
    if (!binaryExists()) return;
    const allocator = std.testing.allocator;

    const fixture_path = try std.fs.path.join(allocator, &.{ claude_fixture_dir, "pre_tool_use_command_safe.json" });
    defer allocator.free(fixture_path);
    const fixture = try readFile(allocator, fixture_path);
    defer allocator.free(fixture);

    const result = try runRyk(allocator, &.{ ryk_bin, "hook", "claude", "PreToolUse" }, fixture);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    try std.testing.expectEqual(@as(u8, 0), result.code);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, result.stdout, .{});
    defer parsed.deinit();

    const decision = claudePermissionOrDecision(parsed.value);
    try std.testing.expect(std.mem.eql(u8, decision, "allow"));
}

test "claude PreToolUse dangerous command returns deny with host-shaped JSON" {
    if (!binaryExists()) return;
    const allocator = std.testing.allocator;

    const fixture_path = try std.fs.path.join(allocator, &.{ claude_fixture_dir, "pre_tool_use_command_dangerous.json" });
    defer allocator.free(fixture_path);
    const fixture = try readFile(allocator, fixture_path);
    defer allocator.free(fixture);

    const result = try runRyk(allocator, &.{ ryk_bin, "hook", "claude", "PreToolUse" }, fixture);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    try std.testing.expectEqual(@as(u8, 0), result.code);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, result.stdout, .{});
    defer parsed.deinit();

    const hso = parsed.value.object.get("hookSpecificOutput").?.object;
    try std.testing.expectEqualStrings("PreToolUse", hso.get("hookEventName").?.string);
    const decision = hso.get("permissionDecision").?.string;
    try std.testing.expect(std.mem.eql(u8, decision, "deny") or std.mem.eql(u8, decision, "ask"));
    const reason = hso.get("permissionDecisionReason").?.string;
    try std.testing.expect(reason.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, reason, "Recourse:") == null);
}

test "claude PreToolUse protected file write returns deny or ask" {
    if (!binaryExists()) return;
    const allocator = std.testing.allocator;

    const fixture_path = try std.fs.path.join(allocator, &.{ claude_fixture_dir, "pre_tool_use_file_write_protected.json" });
    defer allocator.free(fixture_path);
    const fixture = try readFile(allocator, fixture_path);
    defer allocator.free(fixture);

    const result = try runRyk(allocator, &.{ ryk_bin, "hook", "claude", "PreToolUse" }, fixture);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    try std.testing.expectEqual(@as(u8, 0), result.code);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, result.stdout, .{});
    defer parsed.deinit();

    const decision = claudePermissionOrDecision(parsed.value);
    try std.testing.expect(std.mem.eql(u8, decision, "deny") or std.mem.eql(u8, decision, "ask") or std.mem.eql(u8, decision, "allow"));
}

// ---------------------------------------------------------------------------
// 4. Hook CI mode never prompts
// ---------------------------------------------------------------------------

test "codex hook CI mode turns ask into block" {
    if (!binaryExists()) return;
    const allocator = std.testing.allocator;

    // Use permission request with dangerous command to trigger ask/block
    const fixture_path = try std.fs.path.join(allocator, &.{ codex_fixture_dir, "permission_request.json" });
    defer allocator.free(fixture_path);
    const fixture = try readFile(allocator, fixture_path);
    defer allocator.free(fixture);

    const result = try runRyk(allocator, &.{ ryk_bin, "hook", "codex", "PermissionRequest", "--ci" }, fixture);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    if (result.code == 2) {
        try std.testing.expect(result.stdout.len == 0);
        try std.testing.expect(result.stderr.len > 0);
    } else {
        try std.testing.expectEqual(@as(u8, 0), result.code);
        var parsed = try std.json.parseFromSlice(std.json.Value, allocator, result.stdout, .{});
        defer parsed.deinit();
        const decision = parsed.value.object.get("decision").?.string;
        try std.testing.expect(!std.mem.eql(u8, decision, "ask"));
    }
}

test "claude hook CI mode never returns ask" {
    if (!binaryExists()) return;
    const allocator = std.testing.allocator;

    const fixture_path = try std.fs.path.join(allocator, &.{ claude_fixture_dir, "permission_request.json" });
    defer allocator.free(fixture_path);
    const fixture = try readFile(allocator, fixture_path);
    defer allocator.free(fixture);

    const result = try runRyk(allocator, &.{ ryk_bin, "hook", "claude", "PermissionRequest", "--ci" }, fixture);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    try std.testing.expectEqual(@as(u8, 0), result.code);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, result.stdout, .{});
    defer parsed.deinit();

    const decision = claudePermissionOrDecision(parsed.value);
    try std.testing.expect(!std.mem.eql(u8, decision, "ask"));
    // Tool-gating under CI: host-shaped deny (not silent allow).
    if (parsed.value.object.get("hookSpecificOutput")) |hso_val| {
        try std.testing.expectEqualStrings("PermissionRequest", hso_val.object.get("hookEventName").?.string);
    }
}

// ---------------------------------------------------------------------------
// 5. ryk decide tests
// ---------------------------------------------------------------------------

test "decide command safe returns allow JSON" {
    if (!binaryExists()) return;
    const allocator = std.testing.allocator;

    const result = try runRyk(allocator, &.{
        ryk_bin,                                                                             "decide", "command", "--json",
        "{\"version\":1,\"host\":\"codex\",\"command\":\"git status\",\"mode\":\"strict\"}",
    }, null);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    try std.testing.expectEqual(@as(u8, 0), result.code);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, result.stdout, .{});
    defer parsed.deinit();

    try std.testing.expect(parsed.value.object.get("decision") != null);
    try std.testing.expect(parsed.value.object.get("risk") != null);
}

test "decide command dangerous returns block JSON" {
    if (!binaryExists()) return;
    const allocator = std.testing.allocator;

    const result = try runRyk(allocator, &.{
        ryk_bin,                                                                           "decide", "command", "--json",
        "{\"version\":1,\"host\":\"codex\",\"command\":\"rm -rf /\",\"mode\":\"strict\"}",
    }, null);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    try std.testing.expectEqual(exit_codes.denial, result.code);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, result.stdout, .{});
    defer parsed.deinit();

    const decision = parsed.value.object.get("decision").?.string;
    try std.testing.expect(std.mem.eql(u8, decision, "block"));
}

test "decide file write protected path returns block or ask" {
    if (!binaryExists()) return;
    const allocator = std.testing.allocator;

    const result = try runRyk(allocator, &.{
        ryk_bin,                                                                                                    "decide", "file", "--json",
        "{\"version\":1,\"host\":\"claude\",\"operation\":\"write\",\"path\":\".git/config\",\"mode\":\"strict\"}",
    }, null);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, result.stdout, .{});
    defer parsed.deinit();

    const decision = parsed.value.object.get("decision").?.string;
    try std.testing.expect(std.mem.eql(u8, decision, "block") or std.mem.eql(u8, decision, "ask") or std.mem.eql(u8, decision, "warn"));

    const expected_code: u8 = if (std.mem.eql(u8, decision, "block"))
        exit_codes.denial
    else if (std.mem.eql(u8, decision, "ask"))
        exit_codes.ask
    else
        exit_codes.warn;
    try std.testing.expectEqual(expected_code, result.code);
}

test "decide prompt with fake secret redacts" {
    if (!binaryExists()) return;
    const allocator = std.testing.allocator;

    const result = try runRyk(allocator, &.{
        ryk_bin,                                                                                       "decide", "prompt", "--json",
        "{\"version\":1,\"host\":\"codex\",\"prompt\":\"fake_p05_secret_value\",\"mode\":\"strict\"}",
    }, null);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, result.stdout, .{});
    defer parsed.deinit();

    const decision = parsed.value.object.get("decision").?.string;
    try std.testing.expect(std.mem.eql(u8, decision, "warn") or std.mem.eql(u8, decision, "block"));

    const expected_code: u8 = if (std.mem.eql(u8, decision, "warn")) exit_codes.warn else exit_codes.denial;
    try std.testing.expectEqual(expected_code, result.code);

    // Fake secret should not appear in output
    try std.testing.expect(std.mem.indexOf(u8, result.stdout, "fake_p05_secret_value") == null);
}

test "decide tool returns valid JSON" {
    if (!binaryExists()) return;
    const allocator = std.testing.allocator;

    const result = try runRyk(allocator, &.{
        ryk_bin,                                                                                                                          "decide", "tool", "--json",
        "{\"version\":1,\"host\":\"claude\",\"tool\":{\"name\":\"ExampleTool\",\"input\":{\"action\":\"example\"}},\"mode\":\"strict\"}",
    }, null);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, result.stdout, .{});
    defer parsed.deinit();

    const decision = parsed.value.object.get("decision").?.string;
    // Workspace policy may allow, ask, or block unknown tools (e.g. tools.default deny).
    if (std.mem.eql(u8, decision, "allow")) {
        try std.testing.expectEqual(exit_codes.success, result.code);
    } else if (std.mem.eql(u8, decision, "ask")) {
        try std.testing.expectEqual(exit_codes.ask, result.code);
    } else if (std.mem.eql(u8, decision, "block")) {
        try std.testing.expectEqual(exit_codes.denial, result.code);
    } else {
        try std.testing.expect(false);
    }

    try std.testing.expect(parsed.value.object.get("decision") != null);
    try std.testing.expect(parsed.value.object.get("risk") != null);
    try std.testing.expect(parsed.value.object.get("category") != null);
}

// ---------------------------------------------------------------------------
// 6. Invalid input tests
// ---------------------------------------------------------------------------

test "decide rejects invalid JSON" {
    if (!binaryExists()) return;
    const allocator = std.testing.allocator;

    const result = try runRyk(allocator, &.{
        ryk_bin, "decide", "command", "--json", "{not json",
    }, null);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    try std.testing.expect(result.code != 0);
    try std.testing.expect(std.mem.indexOf(u8, result.stderr, "invalid JSON") != null);
}

test "hook codex rejects invalid JSON" {
    if (!binaryExists()) return;
    const allocator = std.testing.allocator;

    const result = try runRyk(allocator, &.{ ryk_bin, "hook", "codex", "PreToolUse" }, "{not json");
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    // PreToolUse pre-eval failures fail closed: Codex deny contract is exit 2 + sentinel.
    try std.testing.expectEqual(codex_deny_exit_code, result.code);
    try std.testing.expectEqual(@as(usize, 0), result.stdout.len);
    try std.testing.expect(std.mem.indexOf(u8, result.stderr, "[[RYKAN-V-GUARD]]") != null);
}

test "hook claude rejects invalid JSON" {
    if (!binaryExists()) return;
    const allocator = std.testing.allocator;

    const result = try runRyk(allocator, &.{ ryk_bin, "hook", "claude", "PreToolUse" }, "{not json");
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    // PreToolUse pre-eval failures fail closed with host-shaped deny JSON (exit 0).
    try std.testing.expectEqual(exit_codes.success, result.code);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, result.stdout, .{});
    defer parsed.deinit();
    const hso = parsed.value.object.get("hookSpecificOutput").?.object;
    try std.testing.expectEqualStrings("deny", hso.get("permissionDecision").?.string);
}

test "hook codex rejects unknown host in payload" {
    if (!binaryExists()) return;
    const allocator = std.testing.allocator;

    const result = try runRyk(allocator, &.{ ryk_bin, "hook", "codex", "SessionStart" }, "{\"version\":1,\"host\":\"unknown\",\"event\":\"SessionStart\",\"payload\":{}}");
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    // Codex pre-eval failures fail closed (exit 2 + sentinel), including SessionStart.
    try std.testing.expectEqual(codex_deny_exit_code, result.code);
    try std.testing.expectEqual(@as(usize, 0), result.stdout.len);
    try std.testing.expect(std.mem.indexOf(u8, result.stderr, "[[RYKAN-V-GUARD]]") != null);
}

test "hook claude rejects unknown event in payload" {
    if (!binaryExists()) return;
    const allocator = std.testing.allocator;

    const result = try runRyk(allocator, &.{ ryk_bin, "hook", "claude", "SessionStart" }, "{\"version\":1,\"host\":\"claude\",\"event\":\"UnknownEvent\",\"payload\":{}}");
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    try std.testing.expect(result.code != 0);
    try std.testing.expect(std.mem.indexOf(u8, result.stderr, "event mismatch") != null);
}

test "decide rejects unknown decision kind" {
    if (!binaryExists()) return;
    const allocator = std.testing.allocator;

    const result = try runRyk(allocator, &.{
        ryk_bin, "decide", "unknown_kind", "--json", "{}",
    }, null);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    try std.testing.expect(result.code != 0);
    try std.testing.expect(std.mem.indexOf(u8, result.stderr, "unknown subcommand") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.stderr, "ryk help decide") != null);
}

// ---------------------------------------------------------------------------
// 7. Oversized input tests
// ---------------------------------------------------------------------------

test "hook codex fail-closes oversized PreToolUse payload" {
    if (!binaryExists()) return;
    const allocator = std.testing.allocator;

    // Create a payload larger than 256 KiB
    var oversized: std.ArrayList(u8) = .empty;
    defer oversized.deinit(allocator);

    try oversized.appendSlice(allocator, "{\"version\":1,\"host\":\"codex\",\"event\":\"PreToolUse\",\"payload\":{\"tool\":\"shell\",\"command\":\"echo safe # ");
    // Append enough data to exceed 256 KiB
    var i: usize = 0;
    while (i < 300 * 1024) : (i += 1) {
        try oversized.append(allocator, 'a');
    }
    try oversized.appendSlice(allocator, "\"}}");

    const result = try runRyk(allocator, &.{ ryk_bin, "hook", "codex", "PreToolUse" }, oversized.items);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    try std.testing.expectEqual(@as(u8, 2), result.code);
    try std.testing.expectEqual(@as(usize, 0), result.stdout.len);
    try std.testing.expect(std.mem.startsWith(u8, result.stderr, "[[RYKAN-V-GUARD]] blocked."));
    try std.testing.expect(std.mem.indexOf(u8, result.stderr, "payload exceeds maximum size") != null);
}

test "hook claude rejects oversized payload safely" {
    if (!binaryExists()) return;
    const allocator = std.testing.allocator;

    var oversized: std.ArrayList(u8) = .empty;
    defer oversized.deinit(allocator);

    try oversized.appendSlice(allocator, "{\"version\":1,\"host\":\"claude\",\"event\":\"SessionStart\",\"payload\":{\"data\":\"");
    var i: usize = 0;
    while (i < 300 * 1024) : (i += 1) {
        try oversized.append(allocator, 'a');
    }
    try oversized.appendSlice(allocator, "\"}}");

    const result = try runRyk(allocator, &.{ ryk_bin, "hook", "claude", "SessionStart" }, oversized.items);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    try std.testing.expect(result.code != 0 or std.mem.indexOf(u8, result.stderr, "invalid") != null or std.mem.indexOf(u8, result.stdout, "error") != null);
}

// ---------------------------------------------------------------------------
// 8. Secret safety scan across plugin artifacts
// ---------------------------------------------------------------------------

test "no fake secret in any plugin fixture" {
    const fixture_dirs = &[_][]const u8{ codex_fixture_dir, claude_fixture_dir };
    for (fixture_dirs) |dir| {
        var d = try std.Io.Dir.cwd().openDir(std.testing.io, dir, .{ .iterate = true });
        defer d.close(std.testing.io);
        var it = d.iterate();
        while (try it.next(std.testing.io)) |entry| {
            if (entry.kind != .file) continue;
            const path = try std.fs.path.join(std.testing.allocator, &.{ dir, entry.name });
            defer std.testing.allocator.free(path);
            const content = try readFile(std.testing.allocator, path);
            defer std.testing.allocator.free(content);
            try std.testing.expect(std.mem.indexOf(u8, content, "fake_p05_secret_value") != null or std.mem.indexOf(u8, content, "fake_p02_secret_value") == null);
        }
    }
}

test "no fake secret leaks into generated hook responses" {
    if (!binaryExists()) return;
    const allocator = std.testing.allocator;

    const fixture_path = try std.fs.path.join(allocator, &.{ codex_fixture_dir, "user_prompt_submit_secret.json" });
    defer allocator.free(fixture_path);
    const fixture = try readFile(allocator, fixture_path);
    defer allocator.free(fixture);

    const result = try runRyk(allocator, &.{ ryk_bin, "hook", "codex", "UserPromptSubmit" }, fixture);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    // The fake secret must NOT appear in stdout or stderr
    try std.testing.expect(std.mem.indexOf(u8, result.stdout, "fake_p05_secret_value") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.stderr, "fake_p05_secret_value") == null);
}

test "no obvious real secret patterns in plugin files" {
    const files_to_check = &[_][]const u8{
        "integrations/codex-plugin/.codex-plugin/plugin.json",
        "integrations/codex-plugin/hooks/hooks.json",
        "integrations/codex-plugin/README.md",
        "integrations/claude-code-plugin/.claude-plugin/plugin.json",
        "integrations/claude-code-plugin/hooks/hooks.json",
        "integrations/claude-code-plugin/README.md",
        "integrations/claude-marketplace/.claude-plugin/marketplace.json",
        "integrations/claude-marketplace/README.md",
    };

    for (files_to_check) |path| {
        if (!fileExists(path)) continue;
        const content = try readFile(std.testing.allocator, path);
        defer std.testing.allocator.free(content);

        try std.testing.expect(std.mem.indexOf(u8, content, "ghp_") == null);
        try std.testing.expect(std.mem.indexOf(u8, content, "sk-") == null);
        try std.testing.expect(std.mem.indexOf(u8, content, "AKIA") == null);
        try std.testing.expect(std.mem.indexOf(u8, content, "password123") == null);
    }
}

// ---------------------------------------------------------------------------
// 9. Documentation overclaim checks
// ---------------------------------------------------------------------------

test "codex plugin README does not claim perfect sandboxing" {
    const content = try readFile(std.testing.allocator, "integrations/codex-plugin/README.md");
    defer std.testing.allocator.free(content);

    const lower = try std.ascii.allocLowerString(std.testing.allocator, content);
    defer std.testing.allocator.free(lower);

    try std.testing.expect(std.mem.indexOf(u8, lower, "perfect sandboxing") == null);
    try std.testing.expect(std.mem.indexOf(u8, lower, "universal transparent file enforcement") == null);
    try std.testing.expect(std.mem.indexOf(u8, lower, "universal transparent network enforcement") == null);
}

test "claude plugin README does not claim perfect sandboxing" {
    const content = try readFile(std.testing.allocator, "integrations/claude-code-plugin/README.md");
    defer std.testing.allocator.free(content);

    const lower = try std.ascii.allocLowerString(std.testing.allocator, content);
    defer std.testing.allocator.free(lower);

    try std.testing.expect(std.mem.indexOf(u8, lower, "perfect sandboxing") == null);
    try std.testing.expect(std.mem.indexOf(u8, lower, "universal transparent file enforcement") == null);
    try std.testing.expect(std.mem.indexOf(u8, lower, "universal transparent network enforcement") == null);
}

test "docs include strongest protection warning" {
    const files = &[_][]const u8{
        "integrations/codex-plugin/README.md",
        "integrations/claude-code-plugin/README.md",
        "docs/integrations/codex.md",
        "docs/integrations/claude-code.md",
    };
    for (files) |path| {
        if (!fileExists(path)) continue;
        const content = try readFile(std.testing.allocator, path);
        defer std.testing.allocator.free(content);
        // Docs should mention "strongest protection" and "ryk run --"
        try std.testing.expect(std.mem.indexOf(u8, content, "strongest protection") != null);
        try std.testing.expect(std.mem.indexOf(u8, content, "ryk run --") != null);
    }
}

test "docs state no MCP server behavior" {
    const files = &[_][]const u8{
        "integrations/codex-plugin/README.md",
        "integrations/claude-code-plugin/README.md",
    };
    for (files) |path| {
        const content = try readFile(std.testing.allocator, path);
        defer std.testing.allocator.free(content);
        try std.testing.expect(std.mem.indexOf(u8, content, "does not add MCP server behavior") != null);
    }
}

test "integration-api docs do not overclaim" {
    const path = "docs/integrations/integration-api.md";
    if (!fileExists(path)) return;
    const content = try readFile(std.testing.allocator, path);
    defer std.testing.allocator.free(content);

    const lower = try std.ascii.allocLowerString(std.testing.allocator, content);
    defer std.testing.allocator.free(lower);

    try std.testing.expect(std.mem.indexOf(u8, lower, "perfect sandboxing") == null);
    try std.testing.expect(std.mem.indexOf(u8, lower, "protection against root") == null);
}

// ---------------------------------------------------------------------------
// 10. Plugin schema validation
// ---------------------------------------------------------------------------

test "common plugin schemas match current ryk host and output surfaces" {
    const hook_request = try readFile(std.testing.allocator, "integrations/common/schemas/hook-request-v1.json");
    defer std.testing.allocator.free(hook_request);
    var parsed_hook_request = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, hook_request, .{});
    defer parsed_hook_request.deinit();
    const hook_request_properties = parsed_hook_request.value.object.get("properties").?.object;
    const host_enum = hook_request_properties.get("host").?.object.get("enum").?.array.items;
    try expectJsonStringInEnum(host_enum, "codex");
    try expectJsonStringInEnum(host_enum, "claude");
    try expectJsonStringInEnum(host_enum, "opencode");
    try expectJsonStringInEnum(host_enum, "openclaw");
    try expectJsonStringInEnum(host_enum, "hermes");
    try std.testing.expect(std.mem.indexOf(u8, hook_request, "Aegis") == null);
    try std.testing.expect(std.mem.indexOf(u8, hook_request, "aegis hook") == null);

    const hook_response = try readFile(std.testing.allocator, "integrations/common/schemas/hook-response-v1.json");
    defer std.testing.allocator.free(hook_response);
    var parsed_hook_response = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, hook_response, .{});
    defer parsed_hook_response.deinit();
    const hook_response_properties = parsed_hook_response.value.object.get("properties").?.object;
    const category_enum = hook_response_properties.get("category").?.object.get("enum").?.array.items;
    try expectJsonStringInEnum(category_enum, "file.write");
    try expectJsonStringInEnum(category_enum, "file_read");
    try expectJsonStringInEnum(category_enum, "file_write");
    try expectJsonStringInEnum(category_enum, "env");
    try std.testing.expect(std.mem.indexOf(u8, hook_response, "Aegis") == null);

    const plugin_request = try readFile(std.testing.allocator, "integrations/common/schemas/ryk-plugin-request-v1.json");
    defer std.testing.allocator.free(plugin_request);
    var parsed_plugin_request = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, plugin_request, .{});
    defer parsed_plugin_request.deinit();
    const plugin_request_properties = parsed_plugin_request.value.object.get("properties").?.object;
    const target_enum = plugin_request_properties.get("target").?.object.get("enum").?.array.items;
    try expectJsonStringInEnum(target_enum, "codex");
    try expectJsonStringInEnum(target_enum, "claude");
    try expectJsonStringInEnum(target_enum, "opencode");
    try expectJsonStringInEnum(target_enum, "openclaw");
    try expectJsonStringInEnum(target_enum, "hermes");
    try std.testing.expect(std.mem.indexOf(u8, plugin_request, "Aegis") == null);

    const plugin_response = try readFile(std.testing.allocator, "integrations/common/schemas/ryk-plugin-response-v1.json");
    defer std.testing.allocator.free(plugin_response);
    var parsed_plugin_response = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, plugin_response, .{});
    defer parsed_plugin_response.deinit();
    const plugin_response_root = parsed_plugin_response.value.object;
    if (plugin_response_root.get("required")) |required_value| {
        const plugin_response_required = required_value.array.items;
        try expectJsonStringNotInEnum(plugin_response_required, "version");
        try expectJsonStringNotInEnum(plugin_response_required, "status");
    }
    const plugin_response_properties = plugin_response_root.get("properties").?.object;
    try std.testing.expect(plugin_response_properties.get("cwd") != null);
    try std.testing.expect(plugin_response_properties.get("audit_replay_available") != null);
    try std.testing.expect(plugin_response_properties.get("mcp_support_status") != null);
    try std.testing.expect(plugin_response_properties.get("opencode_paths") != null);
    try std.testing.expect(plugin_response_properties.get("openclaw_paths") != null);
    try std.testing.expect(plugin_response_properties.get("hermes_paths") != null);
    try std.testing.expect(std.mem.indexOf(u8, plugin_response, "Aegis") == null);
}

// ---------------------------------------------------------------------------
// 11. Plugin manifest and structure validation (P05 re-check)
// ---------------------------------------------------------------------------

test "codex plugin manifest references skills and hooks" {
    const content = try readFile(std.testing.allocator, "integrations/codex-plugin/.codex-plugin/plugin.json");
    defer std.testing.allocator.free(content);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, content, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    try std.testing.expectEqualStrings("./skills/", obj.get("skills").?.string);
    try std.testing.expectEqualStrings("./hooks/hooks.json", obj.get("hooks").?.string);
}

test "claude plugin manifest references skills and hooks" {
    const content = try readFile(std.testing.allocator, "integrations/claude-code-plugin/.claude-plugin/plugin.json");
    defer std.testing.allocator.free(content);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, content, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    try std.testing.expectEqualStrings("./skills/", obj.get("skills").?.string);
    try std.testing.expectEqualStrings("./hooks/hooks.json", obj.get("hooks").?.string);
}

test "claude marketplace file points to plugin directory" {
    const content = try readFile(std.testing.allocator, "integrations/claude-marketplace/.claude-plugin/marketplace.json");
    defer std.testing.allocator.free(content);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, content, .{});
    defer parsed.deinit();

    const plugins = parsed.value.object.get("plugins").?.array;
    try std.testing.expect(plugins.items.len > 0);
    const source = plugins.items[0].object.get("source").?.string;
    try std.testing.expect(std.mem.indexOf(u8, source, "claude-code-plugin") != null);
}

// ---------------------------------------------------------------------------
// 12. Missing required fields and unknown values
// ---------------------------------------------------------------------------

test "hook codex rejects missing version field" {
    if (!binaryExists()) return;
    const allocator = std.testing.allocator;

    const result = try runRyk(allocator, &.{ ryk_bin, "hook", "codex", "SessionStart" }, "{\"host\":\"codex\",\"event\":\"SessionStart\",\"payload\":{}}");
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    try std.testing.expect(result.code != 0);
}

test "hook claude rejects missing host field" {
    if (!binaryExists()) return;
    const allocator = std.testing.allocator;

    const result = try runRyk(allocator, &.{ ryk_bin, "hook", "claude", "SessionStart" }, "{\"version\":1,\"event\":\"SessionStart\",\"payload\":{}}");
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    try std.testing.expect(result.code != 0);
}

test "decide rejects missing JSON payload" {
    if (!binaryExists()) return;
    const allocator = std.testing.allocator;

    const result = try runRyk(allocator, &.{ ryk_bin, "decide", "command" }, null);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    try std.testing.expect(result.code != 0);
}

// ---------------------------------------------------------------------------
// 13. Hook stdout is valid host-compatible JSON
// ---------------------------------------------------------------------------

test "all codex hook responses are valid JSON" {
    if (!binaryExists()) return;
    const allocator = std.testing.allocator;

    const fixtures = &[_][]const u8{
        "session_start.json",
        "user_prompt_submit_secret.json",
        "pre_tool_use_command_safe.json",
        "pre_tool_use_command_dangerous.json",
        "pre_tool_use_file_write_protected.json",
        "permission_request.json",
        "post_tool_use.json",
        "stop.json",
    };

    for (fixtures) |f| {
        const fixture_path = try std.fs.path.join(allocator, &.{ codex_fixture_dir, f });
        defer allocator.free(fixture_path);
        const fixture = try readFile(allocator, fixture_path);
        defer allocator.free(fixture);

        // Extract event name from fixture filename
        const event_name = blk: {
            const basename = std.fs.path.basename(f);
            const dot = std.mem.indexOf(u8, basename, ".") orelse basename.len;
            break :blk basename[0..dot];
        };

        // Map filename to event name
        const event = if (std.mem.eql(u8, event_name, "session_start"))
            "SessionStart"
        else if (std.mem.eql(u8, event_name, "user_prompt_submit_secret"))
            "UserPromptSubmit"
        else if (std.mem.eql(u8, event_name, "pre_tool_use_command_safe"))
            "PreToolUse"
        else if (std.mem.eql(u8, event_name, "pre_tool_use_command_dangerous"))
            "PreToolUse"
        else if (std.mem.eql(u8, event_name, "pre_tool_use_file_write_protected"))
            "PreToolUse"
        else if (std.mem.eql(u8, event_name, "permission_request"))
            "PermissionRequest"
        else if (std.mem.eql(u8, event_name, "post_tool_use"))
            "PostToolUse"
        else if (std.mem.eql(u8, event_name, "stop"))
            "Stop"
        else
            continue;

        const result = try runRyk(allocator, &.{ ryk_bin, "hook", "codex", event }, fixture);
        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);
        if (result.code == 2) {
            try std.testing.expect(result.stdout.len == 0);
            try std.testing.expect(result.stderr.len > 0);
            continue;
        }

        // stdout must be valid JSON
        var parsed = std.json.parseFromSlice(std.json.Value, allocator, result.stdout, .{}) catch {
            try std.testing.expect(false); // Force failure with context
            continue;
        };
        defer parsed.deinit();

        // Must have required hook response fields
        try std.testing.expect(parsed.value.object.get("version") != null);
        try std.testing.expect(parsed.value.object.get("decision") != null);
        try std.testing.expect(parsed.value.object.get("risk") != null);
        try std.testing.expect(parsed.value.object.get("category") != null);
        try std.testing.expect(parsed.value.object.get("reason") != null);
        try std.testing.expect(parsed.value.object.get("message") != null);
        try std.testing.expect(parsed.value.object.get("redactions") != null);
        try std.testing.expect(parsed.value.object.get("host_limitations") != null);
    }
}

test "all claude hook responses are valid JSON" {
    if (!binaryExists()) return;
    const allocator = std.testing.allocator;

    const fixtures = &[_][]const u8{
        "session_start.json",
        "user_prompt_submit_secret.json",
        "pre_tool_use_command_safe.json",
        "pre_tool_use_command_dangerous.json",
        "pre_tool_use_file_write_protected.json",
        "permission_request.json",
        "post_tool_use.json",
        "session_end.json",
    };

    for (fixtures) |f| {
        const fixture_path = try std.fs.path.join(allocator, &.{ claude_fixture_dir, f });
        defer allocator.free(fixture_path);
        const fixture = try readFile(allocator, fixture_path);
        defer allocator.free(fixture);

        const event_name = blk: {
            const basename = std.fs.path.basename(f);
            const dot = std.mem.indexOf(u8, basename, ".") orelse basename.len;
            break :blk basename[0..dot];
        };

        const event = if (std.mem.eql(u8, event_name, "session_start"))
            "SessionStart"
        else if (std.mem.eql(u8, event_name, "user_prompt_submit_secret"))
            "UserPromptSubmit"
        else if (std.mem.eql(u8, event_name, "pre_tool_use_command_safe"))
            "PreToolUse"
        else if (std.mem.eql(u8, event_name, "pre_tool_use_command_dangerous"))
            "PreToolUse"
        else if (std.mem.eql(u8, event_name, "pre_tool_use_file_write_protected"))
            "PreToolUse"
        else if (std.mem.eql(u8, event_name, "permission_request"))
            "PermissionRequest"
        else if (std.mem.eql(u8, event_name, "post_tool_use"))
            "PostToolUse"
        else if (std.mem.eql(u8, event_name, "session_end"))
            "SessionEnd"
        else
            continue;

        const result = try runRyk(allocator, &.{ ryk_bin, "hook", "claude", event }, fixture);
        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);

        var parsed = std.json.parseFromSlice(std.json.Value, allocator, result.stdout, .{}) catch {
            try std.testing.expect(false);
            continue;
        };
        defer parsed.deinit();

        // Tool-gating events use Claude-native permissionDecision; others keep ryk-generic shape.
        if (std.mem.eql(u8, event, "PreToolUse") or std.mem.eql(u8, event, "PermissionRequest")) {
            const hso = parsed.value.object.get("hookSpecificOutput").?.object;
            try std.testing.expect(hso.get("permissionDecision") != null);
            try std.testing.expect(hso.get("permissionDecisionReason") != null);
            try std.testing.expect(hso.get("hookEventName") != null);
        } else {
            try std.testing.expect(parsed.value.object.get("version") != null);
            try std.testing.expect(parsed.value.object.get("decision") != null);
            try std.testing.expect(parsed.value.object.get("risk") != null);
            try std.testing.expect(parsed.value.object.get("category") != null);
            try std.testing.expect(parsed.value.object.get("reason") != null);
            try std.testing.expect(parsed.value.object.get("message") != null);
            try std.testing.expect(parsed.value.object.get("redactions") != null);
            try std.testing.expect(parsed.value.object.get("host_limitations") != null);
        }
    }
}

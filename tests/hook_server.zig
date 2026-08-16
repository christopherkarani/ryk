const std = @import("std");
const builtin = @import("builtin");
const hook_serve = @import("ryk").cli.hook_serve;
const hook_ipc = @import("ryk").cli.hook_ipc;
const hook_client = @import("ryk").cli.hook_client;
const daemon_uds = @import("ryk").cli.daemon_uds;
const exit_codes = @import("ryk").cli.exit_codes;

const ryk_bin = "./zig-out/bin/ryk";

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
const grok_safe = "tests/plugin-fixtures/grok/pre_tool_use_command_safe.json";
const claude_danger = "tests/plugin-fixtures/claude/pre_tool_use_command_dangerous.json";
const default_policy = "policies/default.yaml";

extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;
extern "c" fn unsetenv(name: [*:0]const u8) c_int;

fn readFile(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    return try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, allocator, .limited(256 * 1024));
}

fn exchange(allocator: std.mem.Allocator, socket_path: []const u8, request_json: []const u8) ![]u8 {
    const fd = try daemon_uds.connectUnixSocket(socket_path);
    defer _ = std.c.close(fd);
    try hook_ipc.writeAllFd(std.testing.io, fd, request_json, hook_ipc.request_timeout_ms);
    return hook_ipc.readLineFd(std.testing.io, allocator, fd, hook_ipc.request_timeout_ms);
}

fn waitForSocket(path: []const u8, attempts: u32) !void {
    var n: u32 = 0;
    while (n < attempts) : (n += 1) {
        if (daemon_uds.connectUnixSocket(path)) |fd| {
            _ = std.c.close(fd);
            return;
        } else |_| {
            const delay = std.c.timespec{ .sec = 0, .nsec = 10 * std.time.ns_per_ms };
            _ = std.c.nanosleep(&delay, null);
        }
    }
    return error.ServerNotReady;
}

fn testServe(socket_path: []const u8, stop: *std.atomic.Value(bool)) void {
    _ = hook_serve.serveLoop(std.testing.io, std.heap.page_allocator, socket_path, 30_000, stop) catch {};
}

fn startServer(sock: []const u8) !struct { stop: *std.atomic.Value(bool), thread: std.Thread } {
    const stop = try std.testing.allocator.create(std.atomic.Value(bool));
    stop.* = std.atomic.Value(bool).init(false);
    const thread = try std.Thread.spawn(.{}, testServe, .{ sock, stop });
    errdefer {
        stop.store(true, .unordered);
        if (daemon_uds.connectUnixSocket(sock)) |fd| {
            _ = std.c.close(fd);
        } else |_| {}
        thread.join();
        std.testing.allocator.destroy(stop);
    }
    try waitForSocket(sock, 50);
    return .{ .stop = stop, .thread = thread };
}

fn stopServer(sock: []const u8, server: anytype) void {
    server.stop.store(true, .unordered);
    if (daemon_uds.connectUnixSocket(sock)) |fd| {
        _ = std.c.close(fd);
    } else |_| {}
    server.thread.join();
    std.testing.allocator.destroy(server.stop);
}

fn parseDecision(allocator: std.mem.Allocator, stdout: []const u8) ![]const u8 {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, stdout, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidHookJson;
    if (parsed.value.object.get("hookSpecificOutput")) |hso_val| {
        if (hso_val == .object) {
            if (hso_val.object.get("permissionDecision")) |pd| {
                if (pd == .string) return try allocator.dupe(u8, pd.string);
            }
        }
    }
    if (parsed.value.object.get("decision")) |decision| {
        if (decision == .string) return try allocator.dupe(u8, decision.string);
    }
    return error.MissingDecision;
}

fn writeWorkspacePolicy(io: std.Io, workspace: []const u8, contents: []const u8) !void {
    const ryk_dir = try std.fs.path.join(std.testing.allocator, &.{ workspace, ".ryk" });
    defer std.testing.allocator.free(ryk_dir);
    try std.Io.Dir.cwd().createDirPath(io, ryk_dir);
    const path = try std.fs.path.join(std.testing.allocator, &.{ ryk_dir, "policy.yaml" });
    defer std.testing.allocator.free(path);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = contents });
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

fn runRykHook(
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    stdin_data: []const u8,
    socket_path: []const u8,
) !struct { stdout: []u8, stderr: []u8, code: u8 } {
    var env_map = try std.process.Environ.createMap(processEnviron(), allocator);
    defer env_map.deinit();
    try env_map.put("RYK_HOOK_SOCKET", socket_path);
    try env_map.put("RYK_HOOK_SERVER", "1");

    const io = std.testing.io;
    var child = try std.process.spawn(io, .{
        .argv = argv,
        .stdin = .pipe,
        .stdout = .pipe,
        .stderr = .pipe,
        .environ_map = &env_map,
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

test "one server serves grok allow then claude deny" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(dir);
    const sock = try std.fs.path.join(std.testing.allocator, &.{ dir, "multi-host.sock" });
    defer std.testing.allocator.free(sock);

    const server = try startServer(sock);
    defer stopServer(sock, server);

    const grok_payload = try readFile(std.testing.allocator, grok_safe);
    defer std.testing.allocator.free(grok_payload);
    const grok_req = try hook_ipc.stringifyRequest(std.testing.allocator, .{
        .id = 1,
        .method = "hook",
        .host = "grok",
        .event = "PreToolUse",
        .payload_json = grok_payload,
    });
    defer std.testing.allocator.free(grok_req);
    const grok_raw = try exchange(std.testing.allocator, sock, grok_req);
    defer std.testing.allocator.free(grok_raw);
    var grok_resp = try hook_ipc.parseResponse(std.testing.allocator, grok_raw);
    defer grok_resp.deinit();
    try std.testing.expectEqual(@as(u8, 0), grok_resp.response.exit);
    const grok_decision = try parseDecision(std.testing.allocator, grok_resp.response.stdout);
    defer std.testing.allocator.free(grok_decision);
    try std.testing.expectEqualStrings("allow", grok_decision);

    const claude_payload = try readFile(std.testing.allocator, claude_danger);
    defer std.testing.allocator.free(claude_payload);
    const claude_req = try hook_ipc.stringifyRequest(std.testing.allocator, .{
        .id = 2,
        .method = "hook",
        .host = "claude",
        .event = "PreToolUse",
        .payload_json = claude_payload,
    });
    defer std.testing.allocator.free(claude_req);
    const claude_raw = try exchange(std.testing.allocator, sock, claude_req);
    defer std.testing.allocator.free(claude_raw);
    var claude_resp = try hook_ipc.parseResponse(std.testing.allocator, claude_raw);
    defer claude_resp.deinit();
    try std.testing.expect(!claude_resp.response.mismatch);
    const claude_decision = try parseDecision(std.testing.allocator, claude_resp.response.stdout);
    defer std.testing.allocator.free(claude_decision);
    try std.testing.expect(std.mem.eql(u8, claude_decision, "deny") or std.mem.eql(u8, claude_decision, "block"));
}

test "two workspaces do not share a cached policy" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(dir);
    const sock = try std.fs.path.join(std.testing.allocator, &.{ dir, "isolate.sock" });
    defer std.testing.allocator.free(sock);

    const ok_ws = try std.fs.path.join(std.testing.allocator, &.{ dir, "ok" });
    defer std.testing.allocator.free(ok_ws);
    const bad_ws = try std.fs.path.join(std.testing.allocator, &.{ dir, "bad" });
    defer std.testing.allocator.free(bad_ws);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, ok_ws);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, bad_ws);

    const policy_text = try readFile(std.testing.allocator, default_policy);
    defer std.testing.allocator.free(policy_text);
    try writeWorkspacePolicy(std.testing.io, ok_ws, policy_text);
    try writeWorkspacePolicy(std.testing.io, bad_ws, "mode: [this is not valid yaml\n");

    const grok_payload = try readFile(std.testing.allocator, grok_safe);
    defer std.testing.allocator.free(grok_payload);

    const server = try startServer(sock);
    defer stopServer(sock, server);

    const ok_req = try hook_ipc.stringifyRequest(std.testing.allocator, .{
        .id = 1,
        .method = "hook",
        .host = "grok",
        .event = "PreToolUse",
        .workspace = ok_ws,
        .payload_json = grok_payload,
    });
    defer std.testing.allocator.free(ok_req);
    const ok_raw = try exchange(std.testing.allocator, sock, ok_req);
    defer std.testing.allocator.free(ok_raw);
    var ok_resp = try hook_ipc.parseResponse(std.testing.allocator, ok_raw);
    defer ok_resp.deinit();
    try std.testing.expectEqual(@as(u8, 0), ok_resp.response.exit);
    const ok_decision = try parseDecision(std.testing.allocator, ok_resp.response.stdout);
    defer std.testing.allocator.free(ok_decision);
    try std.testing.expectEqualStrings("allow", ok_decision);

    const bad_req = try hook_ipc.stringifyRequest(std.testing.allocator, .{
        .id = 2,
        .method = "hook",
        .host = "grok",
        .event = "PreToolUse",
        .workspace = bad_ws,
        .payload_json = grok_payload,
    });
    defer std.testing.allocator.free(bad_req);
    const bad_raw = try exchange(std.testing.allocator, sock, bad_req);
    defer std.testing.allocator.free(bad_raw);
    var bad_resp = try hook_ipc.parseResponse(std.testing.allocator, bad_raw);
    defer bad_resp.deinit();
    try std.testing.expectEqual(@as(u8, 2), bad_resp.response.exit);
}

test "probe does not create allow-once pending files" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(dir);
    const sock = try std.fs.path.join(std.testing.allocator, &.{ dir, "probe.sock" });
    defer std.testing.allocator.free(sock);
    const data_home = try std.fs.path.join(std.testing.allocator, &.{ dir, "xdg-data" });
    defer std.testing.allocator.free(data_home);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, data_home);

    const data_home_z = try std.testing.allocator.dupeZ(u8, data_home);
    defer std.testing.allocator.free(data_home_z);
    _ = setenv("XDG_DATA_HOME", data_home_z, 1);
    defer _ = unsetenv("XDG_DATA_HOME");

    const server = try startServer(sock);
    defer stopServer(sock, server);

    const claude_payload = try readFile(std.testing.allocator, claude_danger);
    defer std.testing.allocator.free(claude_payload);
    const req = try hook_ipc.stringifyRequest(std.testing.allocator, .{
        .id = 1,
        .method = "hook",
        .host = "claude",
        .event = "PreToolUse",
        .probe = true,
        .payload_json = claude_payload,
    });
    defer std.testing.allocator.free(req);
    const raw = try exchange(std.testing.allocator, sock, req);
    defer std.testing.allocator.free(raw);
    var parsed = try hook_ipc.parseResponse(std.testing.allocator, raw);
    defer parsed.deinit();
    try std.testing.expect(parsed.response.exit == 0 or parsed.response.exit == 2);

    const pending = try std.fs.path.join(std.testing.allocator, &.{ data_home, "ryk", "pending_exceptions.jsonl" });
    defer std.testing.allocator.free(pending);
    std.Io.Dir.cwd().access(std.testing.io, pending, .{}) catch |err| {
        try std.testing.expectEqual(error.FileNotFound, err);
        return;
    };
    return error.TestUnexpectedResult;
}

test "extra-pack workspace fail-closes on bad pack config" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(dir);
    const sock = try std.fs.path.join(std.testing.allocator, &.{ dir, "pack.sock" });
    defer std.testing.allocator.free(sock);
    const ws = try std.fs.path.join(std.testing.allocator, &.{ dir, "pack-ws" });
    defer std.testing.allocator.free(ws);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, ws);

    const policy_text = try readFile(std.testing.allocator, default_policy);
    defer std.testing.allocator.free(policy_text);
    try writeWorkspacePolicy(std.testing.io, ws, policy_text);
    const pack_dir = try std.fs.path.join(std.testing.allocator, &.{ ws, ".ryk.toml" });
    defer std.testing.allocator.free(pack_dir);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, pack_dir);

    const grok_payload = try readFile(std.testing.allocator, grok_safe);
    defer std.testing.allocator.free(grok_payload);

    const server = try startServer(sock);
    defer stopServer(sock, server);

    const req = try hook_ipc.stringifyRequest(std.testing.allocator, .{
        .id = 1,
        .method = "hook",
        .host = "grok",
        .event = "PreToolUse",
        .workspace = ws,
        .payload_json = grok_payload,
    });
    defer std.testing.allocator.free(req);
    const raw = try exchange(std.testing.allocator, sock, req);
    defer std.testing.allocator.free(raw);
    var parsed = try hook_ipc.parseResponse(std.testing.allocator, raw);
    defer parsed.deinit();
    try std.testing.expectEqual(@as(u8, 2), parsed.response.exit);
}

test "kill server after accept is fail-closed deny not in-process allow" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(dir);
    const sock = try std.fs.path.join(std.testing.allocator, &.{ dir, "kill.sock" });
    defer std.testing.allocator.free(sock);
    const sock_z = try std.testing.allocator.dupeZ(u8, sock);
    defer std.testing.allocator.free(sock_z);

    const thread = try std.Thread.spawn(.{}, acceptThenClose, .{sock});
    try waitForSocket(sock, 50);

    _ = setenv("RYK_HOOK_SOCKET", sock_z, 1);
    defer _ = unsetenv("RYK_HOOK_SOCKET");

    const result = hook_client.tryServe(std.testing.io, std.testing.allocator, .{
        .id = 1,
        .method = "hook",
        .host = "grok",
        .event = "PreToolUse",
        .payload_json = "{}",
    });
    thread.join();
    if (result) |*resp| {
        var owned = resp.*;
        owned.deinit(std.testing.allocator);
        return error.TestUnexpectedResult;
    } else |err| {
        try std.testing.expectEqual(error.BrokenSession, err);
    }

    const grok_payload = try readFile(std.testing.allocator, grok_safe);
    defer std.testing.allocator.free(grok_payload);
    const dummy = try std.Thread.spawn(.{}, acceptThenClose, .{sock});
    try waitForSocket(sock, 50);
    const run = try runRykHook(
        std.testing.allocator,
        &.{ ryk_bin, "hook", "grok", "PreToolUse" },
        grok_payload,
        sock,
    );
    dummy.join();
    defer std.testing.allocator.free(run.stdout);
    defer std.testing.allocator.free(run.stderr);
    try std.testing.expectEqual(@as(u8, 2), run.code);
    try std.testing.expect(std.mem.indexOf(u8, run.stdout, "allow") == null or
        std.mem.indexOf(u8, run.stdout, "deny") != null or
        std.mem.indexOf(u8, run.stdout, "block") != null);
}

fn acceptThenClose(socket_path: []const u8) void {
    const parent = std.fs.path.dirname(socket_path) orelse return;
    std.Io.Dir.cwd().createDirPath(std.testing.io, parent) catch {};
    const listen_fd = daemon_uds.bindListenUnixSocket(socket_path, 8) catch return;
    defer {
        _ = std.c.close(listen_fd);
        daemon_uds.unlinkUnixSocketPath(socket_path);
    }
    var addr: std.c.sockaddr.un = undefined;
    var addr_len: u32 = @sizeOf(std.c.sockaddr.un);
    const client_fd = std.c.accept(listen_fd, @ptrCast(&addr), &addr_len);
    if (client_fd >= 0) _ = std.c.close(client_fd);
}

test "host matrix helpers still compile against server types" {
    try std.testing.expectEqualStrings("ryk-hook-v1", hook_ipc.protocol_label);
    try std.testing.expectEqual(exit_codes.success, @as(u8, 0));
}

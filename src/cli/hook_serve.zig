//! Per-user hook server: one process, many hosts and workspaces.
//!
//! Command: `ryk hook-serve --socket <path>`. Not a second binary. Never named
//! `ryk-daemon`.

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");

const core_api = @import("ryk_core").api;

const daemon_uds = @import("daemon_uds.zig");
const exit_codes = @import("exit_codes.zig");
const help = @import("help.zig");
const hook_ipc = @import("hook_ipc.zig");

const poll_in: i16 = 0x0001;
const poll_out: i16 = 0x0004;

pub fn command(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    if (comptime builtin.os.tag == .windows) {
        try stderr.writeAll("ryk hook-serve: Unix socket server is unavailable on Windows; hooks stay in-process.\n");
        return exit_codes.success;
    }

    var socket_path: ?[]const u8 = null;
    var idle_ms: u64 = hook_ipc.idle_exit_ms;
    var i: usize = 0;
    while (i < argv.len) : (i += 1) {
        const arg = argv[i];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            _ = try help.writeCommand(io, stdout, "hook-serve");
            return exit_codes.success;
        }
        if (std.mem.eql(u8, arg, "--socket")) {
            i += 1;
            if (i >= argv.len) {
                try stderr.writeAll("ryk hook-serve: --socket requires a path.\n");
                return exit_codes.usage;
            }
            socket_path = argv[i];
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--socket=")) {
            socket_path = arg["--socket=".len..];
            continue;
        }
        if (std.mem.eql(u8, arg, "--idle-ms")) {
            i += 1;
            if (i >= argv.len) {
                try stderr.writeAll("ryk hook-serve: --idle-ms requires a number.\n");
                return exit_codes.usage;
            }
            idle_ms = std.fmt.parseInt(u64, argv[i], 10) catch {
                try stderr.writeAll("ryk hook-serve: --idle-ms must be an integer.\n");
                return exit_codes.usage;
            };
            continue;
        }
        try stderr.print("ryk hook-serve: unknown option '{s}'.\n", .{arg});
        return exit_codes.usage;
    }

    const path = socket_path orelse {
        try stderr.writeAll("ryk hook-serve: --socket <path> is required.\n");
        return exit_codes.usage;
    };

    return serveLoop(io, std.heap.page_allocator, path, idle_ms, null);
}

const WorkspaceCacheEntry = struct {
    realpath: []u8,
    policy_mtime_s: i64,
    pack_mtime_s: i64,
    last_used: u64,
    loaded: core_api.LoadedPolicy,
};

/// Successful policy loads only, keyed by workspace realpath + policy/pack mtimes.
/// Cap 16 LRU so a long-lived server cannot grow without bound.
pub const WorkspacePolicyCache = struct {
    allocator: std.mem.Allocator,
    entries: [hook_ipc.workspace_cache_cap]?WorkspaceCacheEntry = [_]?WorkspaceCacheEntry{null} ** hook_ipc.workspace_cache_cap,
    clock: u64 = 0,

    pub fn init(allocator: std.mem.Allocator) WorkspacePolicyCache {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *WorkspacePolicyCache) void {
        for (&self.entries) |*slot| {
            if (slot.*) |*entry| {
                entry.loaded.deinit();
                self.allocator.free(entry.realpath);
            }
            slot.* = null;
        }
    }

    pub fn count(self: *const WorkspacePolicyCache) usize {
        var n: usize = 0;
        for (self.entries) |entry| {
            if (entry != null) n += 1;
        }
        return n;
    }

    /// Load or reuse a workspace policy. Load failures are not cached.
    pub fn getOrLoad(self: *WorkspacePolicyCache, io: std.Io, workspace: []const u8) ?*const core_api.LoadedPolicy {
        if (workspace.len == 0) return null;
        const real_z = std.Io.Dir.cwd().realPathFileAlloc(io, workspace, self.allocator) catch return null;
        defer self.allocator.free(real_z);
        const policy_path = std.fs.path.join(self.allocator, &.{ real_z, ".ryk", "policy.yaml" }) catch return null;
        defer self.allocator.free(policy_path);
        const pack_path = std.fs.path.join(self.allocator, &.{ real_z, ".ryk.toml" }) catch return null;
        defer self.allocator.free(pack_path);
        const policy_mtime = fileMtimeSecs(io, policy_path);
        const pack_mtime = fileMtimeSecs(io, pack_path);

        if (self.indexOf(real_z)) |idx| {
            if (self.entries[idx]) |*entry| {
                if (entry.policy_mtime_s == policy_mtime and entry.pack_mtime_s == pack_mtime) {
                    self.clock += 1;
                    entry.last_used = self.clock;
                    return &entry.loaded;
                }
                self.clearSlot(idx);
            }
        }

        var loaded = core_api.discoverPolicy(io, self.allocator, null, real_z) catch return null;
        const owned = self.allocator.dupe(u8, real_z) catch {
            loaded.deinit();
            return null;
        };
        const slot = self.freeOrLru();
        self.clearSlot(slot);
        self.clock += 1;
        self.entries[slot] = .{
            .realpath = owned,
            .policy_mtime_s = policy_mtime,
            .pack_mtime_s = pack_mtime,
            .last_used = self.clock,
            .loaded = loaded,
        };
        return &self.entries[slot].?.loaded;
    }

    fn clearSlot(self: *WorkspacePolicyCache, idx: usize) void {
        if (self.entries[idx]) |*old| {
            old.loaded.deinit();
            self.allocator.free(old.realpath);
        }
        self.entries[idx] = null;
    }

    fn indexOf(self: *const WorkspacePolicyCache, realpath: []const u8) ?usize {
        for (self.entries, 0..) |entry, idx| {
            if (entry) |item| {
                if (std.mem.eql(u8, item.realpath, realpath)) return idx;
            }
        }
        return null;
    }

    fn freeOrLru(self: *const WorkspacePolicyCache) usize {
        var oldest_idx: usize = 0;
        var oldest_used: u64 = std.math.maxInt(u64);
        for (self.entries, 0..) |entry, idx| {
            if (entry == null) return idx;
            if (entry.?.last_used < oldest_used) {
                oldest_used = entry.?.last_used;
                oldest_idx = idx;
            }
        }
        return oldest_idx;
    }
};

fn fileMtimeSecs(io: std.Io, path: []const u8) i64 {
    const file = std.Io.Dir.cwd().openFile(io, path, .{}) catch return 0;
    defer file.close(io);
    const st = file.stat(io) catch return 0;
    return st.mtime.toSeconds();
}

pub fn serveLoop(
    io: std.Io,
    allocator: std.mem.Allocator,
    socket_path: []const u8,
    idle_ms: u64,
    stop: ?*std.atomic.Value(bool),
) !u8 {
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .macos) return exit_codes.general;
    hook_ipc.ignoreSigpipe();
    try ensureSocketParentDir(io, socket_path);
    const listen_fd = daemon_uds.bindListenUnixSocketOpts(socket_path, .{
        .backlog = hook_ipc.listen_backlog,
        .fail_if_live = true,
    }) catch |err| switch (err) {
        error.SocketAlreadyBound => return exit_codes.success,
        else => return err,
    };
    defer {
        _ = std.c.close(listen_fd);
        daemon_uds.unlinkUnixSocketPath(socket_path);
    }
    hook_ipc.setNoSigpipe(listen_fd);
    chmodPath(socket_path, 0o600);

    var cache = WorkspacePolicyCache.init(allocator);
    defer cache.deinit();
    const self_bin = std.process.executablePathAlloc(io, allocator) catch "";
    defer if (self_bin.len > 0) allocator.free(self_bin);

    var last_ms = nowMs(io);
    while (true) {
        if (stop) |flag| {
            if (flag.load(.unordered)) return exit_codes.success;
        }
        const elapsed = nowMs(io) - last_ms;
        if (idle_ms > 0 and elapsed >= idle_ms) return exit_codes.success;
        const wait_ms: u64 = if (idle_ms == 0) 200 else @min(idle_ms - elapsed, 200);
        waitReadable(listen_fd, wait_ms) catch continue;

        var addr: std.c.sockaddr.un = undefined;
        var addr_len: u32 = @sizeOf(std.c.sockaddr.un);
        const client_fd = std.c.accept(listen_fd, @ptrCast(&addr), &addr_len);
        if (client_fd < 0) continue;
        defer _ = std.c.close(client_fd);
        hook_ipc.setNoSigpipe(client_fd);

        last_ms = nowMs(io);
        const shutdown = handleClient(io, allocator, client_fd, self_bin, &cache) catch false;
        if (shutdown) return exit_codes.success;
    }
}

fn requestMismatches(self_bin: []const u8, req: hook_ipc.Request) bool {
    if (req.version.len > 0 and !std.mem.eql(u8, req.version, build_options.version)) return true;
    if (req.bin.len == 0 or self_bin.len == 0) return false;
    return !std.mem.eql(u8, req.bin, self_bin);
}

fn handleClient(
    io: std.Io,
    allocator: std.mem.Allocator,
    fd: std.posix.fd_t,
    self_bin: []const u8,
    cache: *WorkspacePolicyCache,
) !bool {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const line = hook_ipc.readLineFd(io, arena, fd, hook_ipc.request_timeout_ms) catch return false;

    const parsed = hook_ipc.parseRequest(arena, line) catch {
        const resp = try hook_ipc.stringifyResponse(arena, .{
            .id = 0,
            .exit = 2,
            .stdout = "",
            .stderr = "ryk hook-serve: invalid request",
        });
        hook_ipc.writeAllFd(io, fd, resp, hook_ipc.request_timeout_ms) catch {};
        return false;
    };

    const req = parsed.request;
    if (std.mem.eql(u8, req.method, "shutdown")) {
        const resp = try hook_ipc.stringifyResponse(arena, .{
            .id = req.id,
            .exit = 0,
            .stdout = "",
            .stderr = "",
        });
        hook_ipc.writeAllFd(io, fd, resp, hook_ipc.request_timeout_ms) catch {};
        return true;
    }

    if (requestMismatches(self_bin, req)) {
        const resp = try hook_ipc.stringifyResponse(arena, .{
            .id = req.id,
            .exit = 2,
            .stdout = "",
            .stderr = "ryk hook-serve: version or binary mismatch",
            .mismatch = true,
        });
        hook_ipc.writeAllFd(io, fd, resp, hook_ipc.request_timeout_ms) catch {};
        return false;
    }

    if (std.mem.eql(u8, req.method, "ping")) {
        const resp = try hook_ipc.stringifyResponse(arena, .{
            .id = req.id,
            .exit = 0,
            .stdout = hook_ipc.protocol_label,
            .stderr = "",
        });
        try hook_ipc.writeAllFd(io, fd, resp, hook_ipc.request_timeout_ms);
        return false;
    }

    const emit = dispatchEvaluate(io, arena, req, cache) catch hook_ipc.HostEmit{
        .exit = 2,
        .stdout = try arena.dupe(u8, ""),
        .stderr = try arena.dupe(u8, "ryk hook-serve: evaluation failed"),
    };

    const resp = try hook_ipc.stringifyResponse(arena, .{
        .id = req.id,
        .exit = emit.exit,
        .stdout = emit.stdout,
        .stderr = emit.stderr,
    });
    try hook_ipc.writeAllFd(io, fd, resp, hook_ipc.request_timeout_ms);
    return false;
}

fn dispatchEvaluate(
    io: std.Io,
    allocator: std.mem.Allocator,
    req: hook_ipc.Request,
    cache: *WorkspacePolicyCache,
) !hook_ipc.HostEmit {
    const hook = @import("hook.zig");
    const evaluate = @import("evaluate.zig");
    const agent_hook = @import("agent_hook.zig");

    const cached = if (req.workspace.len > 0) cache.getOrLoad(io, req.workspace) else null;

    if (std.mem.eql(u8, req.method, "evaluate")) {
        return evaluate.evaluateForServer(io, allocator, req.payload_json, cached);
    }
    if (std.mem.eql(u8, req.method, "hook")) {
        if (std.mem.eql(u8, req.host, "cursor")) {
            return agent_hook.evaluateForServer(allocator, req.payload_json);
        }
        return hook.evaluateForServer(
            io,
            allocator,
            req.host,
            req.event,
            req.payload_json,
            req.ci,
            req.probe,
            if (req.workspace.len == 0) null else req.workspace,
            cached,
        );
    }
    return error.UnknownMethod;
}

fn ensureSocketParentDir(io: std.Io, socket_path: []const u8) !void {
    const dir = std.fs.path.dirname(socket_path) orelse return;
    std.Io.Dir.cwd().createDirPath(io, dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    chmodPath(dir, 0o700);
}

fn chmodPath(path: []const u8, mode: c_uint) void {
    if (path.len >= std.fs.max_path_bytes) return;
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;
    _ = std.c.chmod(@ptrCast(&buf), mode);
}

fn nowMs(io: std.Io) u64 {
    const ms = std.Io.Timestamp.now(io, .awake).toMilliseconds();
    return if (ms < 0) 0 else @intCast(ms);
}

fn waitReadable(fd: std.posix.fd_t, timeout_ms: u64) !void {
    var fds = [_]std.posix.pollfd{.{
        .fd = fd,
        .events = poll_in,
        .revents = 0,
    }};
    const rc = std.posix.poll(fds[0..], pollTimeoutMs(timeout_ms)) catch return error.PollFailed;
    if (rc <= 0) return error.Timeout;
    if (fds[0].revents & poll_in == 0) return error.Timeout;
}

fn pollTimeoutMs(timeout_ms: u64) i32 {
    return @intCast(@min(timeout_ms, std.math.maxInt(i32)));
}

fn exchange(allocator: std.mem.Allocator, socket_path: []const u8, request_json: []const u8) ![]u8 {
    const fd = try daemon_uds.connectUnixSocket(socket_path);
    defer _ = std.c.close(fd);
    try hook_ipc.writeAllFd(std.testing.io, fd, request_json, hook_ipc.request_timeout_ms);
    return hook_ipc.readLineFd(std.testing.io, allocator, fd, hook_ipc.request_timeout_ms);
}

test "hook-serve ping returns exit 0" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(dir);
    const sock = try std.fs.path.join(std.testing.allocator, &.{ dir, "hook-ping.sock" });
    defer std.testing.allocator.free(sock);

    var stop = std.atomic.Value(bool).init(false);
    const thread = try std.Thread.spawn(.{}, testServe, .{ sock, &stop });
    defer {
        stop.store(true, .unordered);
        // Wake accept via a best-effort connect, then join.
        if (daemon_uds.connectUnixSocket(sock)) |fd| {
            _ = std.c.close(fd);
        } else |_| {}
        thread.join();
    }
    try waitForSocket(sock, 50);

    const req = try hook_ipc.stringifyRequest(std.testing.allocator, .{
        .id = 1,
        .method = "ping",
        .version = build_options.version,
    });
    defer std.testing.allocator.free(req);
    const raw = try exchange(std.testing.allocator, sock, req);
    defer std.testing.allocator.free(raw);
    var parsed = try hook_ipc.parseResponse(std.testing.allocator, raw);
    defer parsed.deinit();
    try std.testing.expectEqual(@as(u8, 0), parsed.response.exit);
    try std.testing.expectEqualStrings(hook_ipc.protocol_label, parsed.response.stdout);
}

test "hook-serve binds after a stale sock file" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(dir);
    const sock = try std.fs.path.join(std.testing.allocator, &.{ dir, "hook-stale.sock" });
    defer std.testing.allocator.free(sock);

    {
        const file = try std.Io.Dir.cwd().createFile(std.testing.io, sock, .{});
        file.close(std.testing.io);
    }

    var stop = std.atomic.Value(bool).init(false);
    const thread = try std.Thread.spawn(.{}, testServe, .{ sock, &stop });
    defer {
        stop.store(true, .unordered);
        if (daemon_uds.connectUnixSocket(sock)) |fd| {
            _ = std.c.close(fd);
        } else |_| {}
        thread.join();
    }
    try waitForSocket(sock, 50);

    const req = try hook_ipc.stringifyRequest(std.testing.allocator, .{ .id = 2, .method = "ping" });
    defer std.testing.allocator.free(req);
    const raw = try exchange(std.testing.allocator, sock, req);
    defer std.testing.allocator.free(raw);
    var parsed = try hook_ipc.parseResponse(std.testing.allocator, raw);
    defer parsed.deinit();
    try std.testing.expectEqual(@as(u8, 0), parsed.response.exit);
}

test "hook-serve shutdown exits 0 and unlinks the socket" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(dir);
    const sock = try std.fs.path.join(std.testing.allocator, &.{ dir, "hook-stop.sock" });
    defer std.testing.allocator.free(sock);

    const thread = try std.Thread.spawn(.{}, testServeNoStop, .{sock});
    try waitForSocket(sock, 50);

    const req = try hook_ipc.stringifyRequest(std.testing.allocator, .{ .id = 3, .method = "shutdown" });
    defer std.testing.allocator.free(req);
    const raw = try exchange(std.testing.allocator, sock, req);
    defer std.testing.allocator.free(raw);
    var parsed = try hook_ipc.parseResponse(std.testing.allocator, raw);
    defer parsed.deinit();
    try std.testing.expectEqual(@as(u8, 0), parsed.response.exit);
    thread.join();

    std.Io.Dir.cwd().access(std.testing.io, sock, .{}) catch |err| {
        try std.testing.expectEqual(error.FileNotFound, err);
        return;
    };
    return error.TestUnexpectedResult;
}

fn testServe(socket_path: []const u8, stop: *std.atomic.Value(bool)) void {
    _ = serveLoop(std.testing.io, std.heap.page_allocator, socket_path, 30_000, stop) catch {};
}

fn testServeNoStop(socket_path: []const u8) void {
    _ = serveLoop(std.testing.io, std.heap.page_allocator, socket_path, 30_000, null) catch {};
}

test "hook-serve reports mismatch for a different version" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(dir);
    const sock = try std.fs.path.join(std.testing.allocator, &.{ dir, "hook-mismatch.sock" });
    defer std.testing.allocator.free(sock);

    var stop = std.atomic.Value(bool).init(false);
    const thread = try std.Thread.spawn(.{}, testServe, .{ sock, &stop });
    defer {
        stop.store(true, .unordered);
        if (daemon_uds.connectUnixSocket(sock)) |fd| {
            _ = std.c.close(fd);
        } else |_| {}
        thread.join();
    }
    try waitForSocket(sock, 50);

    const req = try hook_ipc.stringifyRequest(std.testing.allocator, .{
        .id = 4,
        .method = "ping",
        .version = "not-this-version",
    });
    defer std.testing.allocator.free(req);
    const raw = try exchange(std.testing.allocator, sock, req);
    defer std.testing.allocator.free(raw);
    var parsed = try hook_ipc.parseResponse(std.testing.allocator, raw);
    defer parsed.deinit();
    try std.testing.expect(parsed.response.mismatch);
}

test "workspace policy cache caps at 16 LRU entries" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var cache = WorkspacePolicyCache.init(std.testing.allocator);
    defer cache.deinit();

    var i: usize = 0;
    while (i < 18) : (i += 1) {
        var name_buf: [8]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "w{d}", .{i});
        const path = try std.fs.path.join(std.testing.allocator, &.{ root, name });
        defer std.testing.allocator.free(path);
        try std.Io.Dir.cwd().createDirPath(std.testing.io, path);
        _ = cache.getOrLoad(std.testing.io, path);
    }
    try std.testing.expectEqual(@as(usize, hook_ipc.workspace_cache_cap), cache.count());
}

test "hook-serve exits 0 when the socket is already live" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(dir);
    const sock = try std.fs.path.join(std.testing.allocator, &.{ dir, "hook-already.sock" });
    defer std.testing.allocator.free(sock);

    var stop = std.atomic.Value(bool).init(false);
    const thread = try std.Thread.spawn(.{}, testServe, .{ sock, &stop });
    defer {
        stop.store(true, .unordered);
        if (daemon_uds.connectUnixSocket(sock)) |fd| {
            _ = std.c.close(fd);
        } else |_| {}
        thread.join();
    }
    try waitForSocket(sock, 50);

    const code = try serveLoop(std.testing.io, std.heap.page_allocator, sock, 30_000, null);
    try std.testing.expectEqual(exit_codes.success, code);

    const req = try hook_ipc.stringifyRequest(std.testing.allocator, .{ .id = 9, .method = "ping" });
    defer std.testing.allocator.free(req);
    const raw = try exchange(std.testing.allocator, sock, req);
    defer std.testing.allocator.free(raw);
    var parsed = try hook_ipc.parseResponse(std.testing.allocator, raw);
    defer parsed.deinit();
    try std.testing.expectEqual(@as(u8, 0), parsed.response.exit);
}

test "workspace policy cache does not store load failures" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const bad = try std.fs.path.join(std.testing.allocator, &.{ root, "bad-policy" });
    defer std.testing.allocator.free(bad);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, bad);
    const ryk_dir = try std.fs.path.join(std.testing.allocator, &.{ bad, ".ryk" });
    defer std.testing.allocator.free(ryk_dir);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, ryk_dir);
    const policy_path = try std.fs.path.join(std.testing.allocator, &.{ ryk_dir, "policy.yaml" });
    defer std.testing.allocator.free(policy_path);
    try std.Io.Dir.cwd().writeFile(std.testing.io, .{
        .sub_path = policy_path,
        .data = "mode: [this is not valid yaml\n",
    });

    var cache = WorkspacePolicyCache.init(std.testing.allocator);
    defer cache.deinit();
    try std.testing.expect(cache.getOrLoad(std.testing.io, bad) == null);
    try std.testing.expectEqual(@as(usize, 0), cache.count());
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

//! Shared Unix domain socket helpers for the daemon client and IPC tests.

const std = @import("std");
const builtin = @import("builtin");

pub const UnixSockaddr = struct {
    addr: std.c.sockaddr.un,
    len: u32,
};

pub fn sockaddrUnFromPath(path: []const u8) !UnixSockaddr {
    var addr: std.c.sockaddr.un = .{
        .family = @intCast(afUnix()),
        .path = undefined,
    };
    // Never truncate a pathname: doing so can connect to or bind a different
    // socket than the caller requested. A zero-length pathname is likewise not
    // a filesystem socket path.
    if (path.len == 0) return error.InvalidSocketPath;
    if (path.len >= addr.path.len) return error.SocketPathTooLong;
    const path_len = path.len;
    @memset(&addr.path, 0);
    @memcpy(addr.path[0..path_len], path[0..path_len]);
    addr.path[path_len] = 0;

    return .{
        .addr = addr,
        .len = @intCast(@offsetOf(std.c.sockaddr.un, "path") + path_len + 1),
    };
}

test "sockaddrUnFromPath rejects empty and overlong paths" {
    var overlong: [@sizeOf(std.c.sockaddr.un)]u8 = undefined;
    @memset(&overlong, 'a');

    try std.testing.expectError(error.InvalidSocketPath, sockaddrUnFromPath(""));
    try std.testing.expectError(error.SocketPathTooLong, sockaddrUnFromPath(&overlong));
}

test "bindListenUnixSocket accepts backlog and rejects empty paths" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    try std.testing.expectError(error.InvalidSocketPath, bindListenUnixSocket("", 128));

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(dir);
    const sock = try std.fs.path.join(std.testing.allocator, &.{ dir, "hook-backlog.sock" });
    defer std.testing.allocator.free(sock);

    const fd = try bindListenUnixSocket(sock, 128);
    defer {
        _ = std.c.close(fd);
        unlinkUnixSocketPath(sock);
    }
    try std.testing.expect(fd >= 0);
}

pub fn openUnixStreamSocket() !std.posix.fd_t {
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .macos) return error.UnsupportedOs;
    const fd = std.c.socket(afUnix(), sockStream(), 0);
    if (fd < 0) return error.SocketConnectFailed;
    return fd;
}

pub fn connectUnixSocket(path: []const u8) !std.posix.fd_t {
    return connectUnixSocketTimeout(path, null);
}

/// Connect to a Unix socket. When `timeout_ms` is set, the connect cannot block
/// longer than that (needed when a listen backlog is full or a peer is stuck).
pub fn connectUnixSocketTimeout(path: []const u8, timeout_ms: ?u64) !std.posix.fd_t {
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .macos) return error.UnsupportedOs;
    const fd = try openUnixStreamSocket();
    errdefer _ = std.c.close(fd);

    const sockaddr = try sockaddrUnFromPath(path);
    if (timeout_ms) |ms| {
        try setNonblock(fd, true);
        const rc = std.c.connect(fd, @ptrCast(&sockaddr.addr), sockaddr.len);
        if (rc < 0) {
            switch (std.posix.errno(@as(isize, rc))) {
                .SUCCESS => {},
                .INPROGRESS, .AGAIN, .ALREADY => {
                    var fds = [_]std.posix.pollfd{.{
                        .fd = fd,
                        .events = 0x0004, // POLLOUT
                        .revents = 0,
                    }};
                    const prc = std.posix.poll(fds[0..], @intCast(@min(ms, std.math.maxInt(i32)))) catch
                        return error.SocketConnectFailed;
                    if (prc <= 0) return error.SocketConnectFailed;
                    try takeSocketError(fd);
                },
                else => return error.SocketConnectFailed,
            }
        }
        try setNonblock(fd, false);
        return fd;
    }

    const rc = std.c.connect(fd, @ptrCast(&sockaddr.addr), sockaddr.len);
    if (rc < 0) return error.SocketConnectFailed;
    return fd;
}

pub const BindUnixSocketOptions = struct {
    backlog: u31 = 1,
    /// When true, a socket that still accepts connections is left alone.
    fail_if_live: bool = false,
};

pub fn bindListenUnixSocket(path: []const u8, backlog: u31) !std.posix.fd_t {
    return bindListenUnixSocketOpts(path, .{ .backlog = backlog });
}

pub fn bindListenUnixSocketOpts(path: []const u8, opts: BindUnixSocketOptions) !std.posix.fd_t {
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .macos) return error.UnsupportedOs;
    if (opts.fail_if_live) {
        if (connectUnixSocketTimeout(path, 50)) |fd| {
            _ = std.c.close(fd);
            return error.SocketAlreadyBound;
        } else |_| {}
    }
    unlinkUnixSocketPath(path);

    const fd = try openUnixStreamSocket();
    errdefer _ = std.c.close(fd);

    const sockaddr = try sockaddrUnFromPath(path);
    if (std.c.bind(fd, @ptrCast(&sockaddr.addr), sockaddr.len) < 0) return error.SocketConnectFailed;
    if (std.c.listen(fd, opts.backlog) < 0) return error.SocketConnectFailed;
    return fd;
}

test "bindListenUnixSocketOpts fail_if_live leaves a live socket" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(dir);
    const sock = try std.fs.path.join(std.testing.allocator, &.{ dir, "hook-live.sock" });
    defer std.testing.allocator.free(sock);

    const live = try bindListenUnixSocket(sock, 8);
    defer {
        _ = std.c.close(live);
        unlinkUnixSocketPath(sock);
    }

    try std.testing.expectError(
        error.SocketAlreadyBound,
        bindListenUnixSocketOpts(sock, .{ .backlog = 8, .fail_if_live = true }),
    );

    const ping = try connectUnixSocket(sock);
    _ = std.c.close(ping);
}

test "connectUnixSocketTimeout fails fast on a missing path" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const started = std.Io.Timestamp.now(std.testing.io, .awake).toMilliseconds();
    try std.testing.expectError(
        error.SocketConnectFailed,
        connectUnixSocketTimeout("/tmp/ryk-uds-missing-connect-timeout.sock", 50),
    );
    const elapsed = std.Io.Timestamp.now(std.testing.io, .awake).toMilliseconds() - started;
    try std.testing.expect(elapsed < 500);
}

fn setNonblock(fd: std.posix.fd_t, on: bool) !void {
    const current_raw = std.posix.system.fcntl(fd, std.posix.F.GETFL, @as(usize, 0));
    if (std.posix.errno(current_raw) != .SUCCESS) return error.SocketConnectFailed;
    const current: u32 = @intCast(current_raw);
    const nonblock_bit: u32 = @bitCast(std.posix.O{ .NONBLOCK = true });
    const next = if (on) current | nonblock_bit else current & ~nonblock_bit;
    const result = std.posix.system.fcntl(fd, std.posix.F.SETFL, next);
    if (std.posix.errno(result) != .SUCCESS) return error.SocketConnectFailed;
}

fn takeSocketError(fd: std.posix.fd_t) !void {
    var so_err: i32 = 0;
    var len: std.c.socklen_t = @sizeOf(i32);
    if (std.c.getsockopt(fd, solSocket(), soError(), @ptrCast(&so_err), &len) < 0)
        return error.SocketConnectFailed;
    if (so_err != 0) return error.SocketConnectFailed;
}

fn solSocket() c_int {
    return switch (builtin.os.tag) {
        .linux => @intCast(std.posix.SOL.SOCKET),
        .macos => 0xffff,
        else => 1,
    };
}

fn soError() u32 {
    return switch (builtin.os.tag) {
        .linux => @intCast(std.posix.SO.ERROR),
        .macos => 0x1007,
        else => 4,
    };
}

pub fn unlinkUnixSocketPath(path: []const u8) void {
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .macos) return;
    if (path.len >= std.fs.max_path_bytes) return;
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    @memcpy(path_buf[0..path.len], path);
    path_buf[path.len] = 0;
    _ = std.c.unlink(@ptrCast(&path_buf));
}

fn afUnix() c_uint {
    return switch (builtin.os.tag) {
        .linux => @intCast(std.posix.AF.UNIX),
        .macos => 1,
        else => 0,
    };
}

fn sockStream() c_uint {
    return switch (builtin.os.tag) {
        .linux => @intCast(std.posix.SOCK.STREAM),
        .macos => 1,
        else => 0,
    };
}

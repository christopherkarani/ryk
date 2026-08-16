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

fn testSockPath(name: []const u8) ![]u8 {
    const dir = try std.fmt.allocPrint(std.testing.allocator, "/tmp/ryk-uds-{d}", .{std.c.getpid()});
    defer std.testing.allocator.free(dir);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, dir);
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    @memcpy(buf[0..dir.len], dir);
    buf[dir.len] = 0;
    _ = std.c.chmod(@ptrCast(&buf), 0o700);
    return std.fmt.allocPrint(std.testing.allocator, "{s}/{s}.sock", .{ dir, name });
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

    const sock = try testSockPath("backlog");
    defer std.testing.allocator.free(sock);

    const fd = try bindListenUnixSocket(sock, 128);
    defer {
        _ = std.c.close(fd);
        unlinkUnixSocketPath(sock);
    }
    try std.testing.expect(fd >= 0);
    const st = try lstatIdentity(sock);
    try std.testing.expectEqual(@as(u32, 0o600), st.mode & 0o777);
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
                        .events = std.posix.POLL.OUT,
                        .revents = 0,
                    }};
                    const prc = std.posix.poll(fds[0..], @intCast(@min(ms, std.math.maxInt(i32)))) catch
                        return error.SocketConnectFailed;
                    if (prc <= 0) return error.TimedOut;
                    try takeSocketError(fd);
                },
                .NOENT => return error.FileNotFound,
                .CONNREFUSED => return error.ConnectionRefused,
                else => return error.SocketConnectFailed,
            }
        }
        try setNonblock(fd, false);
        try requirePeerEuid(fd);
        return fd;
    }

    const rc = std.c.connect(fd, @ptrCast(&sockaddr.addr), sockaddr.len);
    if (rc < 0) return connectErrno();
    try requirePeerEuid(fd);
    return fd;
}

fn connectErrno() error{ FileNotFound, ConnectionRefused, SocketConnectFailed } {
    return switch (std.posix.errno(@as(isize, -1))) {
        .NOENT => error.FileNotFound,
        .CONNREFUSED => error.ConnectionRefused,
        else => error.SocketConnectFailed,
    };
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
    if (!opts.fail_if_live) {
        unlinkUnixSocketPath(path);
        return bindListenFresh(path, opts.backlog);
    }

    const fd = openUnixStreamSocket() catch return error.SocketConnectFailed;
    const sockaddr = sockaddrUnFromPath(path) catch {
        _ = std.c.close(fd);
        return error.InvalidSocketPath;
    };
    if (bindWithRestrictiveUmask(fd, &sockaddr) == 0) {
        errdefer _ = std.c.close(fd);
        try finishListen(fd, path, opts.backlog);
        return fd;
    }
    _ = std.c.close(fd);

    // Address in use: steal only when the peer is gone. A timeout means live.
    // Re-probe before unlink so a successor that bound after the first miss is left alone.
    if (connectUnixSocketTimeout(path, 50)) |live_fd| {
        _ = std.c.close(live_fd);
        return error.SocketAlreadyBound;
    } else |err| switch (err) {
        error.ConnectionRefused, error.FileNotFound => {
            if (connectUnixSocketTimeout(path, 50)) |successor_fd| {
                _ = std.c.close(successor_fd);
                return error.SocketAlreadyBound;
            } else |probe| switch (probe) {
                error.ConnectionRefused, error.FileNotFound => {
                    unlinkUnixSocketPath(path);
                    return bindListenFresh(path, opts.backlog);
                },
                else => return error.SocketAlreadyBound,
            }
        },
        error.SocketConnectFailed => {
            // Regular leftover file (ENOTSOCK) is not a live successor.
            const st = lstatIdentity(path) catch return error.SocketAlreadyBound;
            if (st.is_sock) return error.SocketAlreadyBound;
            unlinkUnixSocketPath(path);
            return bindListenFresh(path, opts.backlog);
        },
        else => return error.SocketAlreadyBound,
    }
}

fn bindListenFresh(path: []const u8, backlog: u31) !std.posix.fd_t {
    const fd = try openUnixStreamSocket();
    errdefer _ = std.c.close(fd);
    const sockaddr = try sockaddrUnFromPath(path);
    if (bindWithRestrictiveUmask(fd, &sockaddr) < 0) return error.SocketConnectFailed;
    try finishListen(fd, path, backlog);
    return fd;
}

fn bindWithRestrictiveUmask(fd: std.posix.fd_t, sockaddr: *const UnixSockaddr) c_int {
    const old = std.c.umask(0o077);
    defer _ = std.c.umask(old);
    return std.c.bind(fd, @ptrCast(&sockaddr.addr), sockaddr.len);
}

fn finishListen(fd: std.posix.fd_t, path: []const u8, backlog: u31) !void {
    if (std.c.listen(fd, backlog) < 0) return error.SocketConnectFailed;
    // macOS rejects fchmod on a socket fd (EINVAL). chmod the bound path instead.
    chmodPath(path, 0o600) catch {
        unlinkUnixSocketPath(path);
        return error.SocketChmodFailed;
    };
}

fn chmodPath(path: []const u8, mode: std.c.mode_t) !void {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const z = try pathToZ(path, &buf);
    if (std.c.chmod(z, mode) != 0) return error.ChmodFailed;
}

test "bindListenUnixSocketOpts fail_if_live leaves a live socket" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const sock = try testSockPath("live");
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

test "unlinkUnixSocketIfSameInode does not remove a successor inode" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const sock = try testSockPath("inode");
    defer std.testing.allocator.free(sock);

    const first = try bindListenUnixSocket(sock, 8);
    const first_id = try lstatIdentity(sock);
    unlinkUnixSocketPath(sock);
    const successor = try bindListenUnixSocket(sock, 8);
    defer {
        _ = std.c.close(successor);
        unlinkUnixSocketPath(sock);
    }

    unlinkUnixSocketIfIdentity(sock, first_id);
    _ = std.c.close(first);

    const ping = try connectUnixSocket(sock);
    _ = std.c.close(ping);
}

test "requireTrustedSocketParent rejects a symlink parent" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "real");
    const real = try tmp.dir.realPathFileAlloc(std.testing.io, "real", std.testing.allocator);
    defer std.testing.allocator.free(real);
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const link = try std.fs.path.join(std.testing.allocator, &.{ root, "link" });
    defer std.testing.allocator.free(link);
    try std.Io.Dir.cwd().symLink(std.testing.io, real, link, .{});
    try std.testing.expectError(error.UntrustedSocketParent, requireTrustedSocketParent(link));
}

test "connectUnixSocket accepts a same-euid peer" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const sock = try testSockPath("peer");
    defer std.testing.allocator.free(sock);

    const live = try bindListenUnixSocket(sock, 8);
    defer {
        _ = std.c.close(live);
        unlinkUnixSocketPath(sock);
    }
    const ping = try connectUnixSocket(sock);
    defer _ = std.c.close(ping);
    try requirePeerEuid(ping);
}

test "connectUnixSocketTimeout fails fast on a missing path" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const started = std.Io.Timestamp.now(std.testing.io, .awake).toMilliseconds();
    try std.testing.expectError(
        error.FileNotFound,
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
    if (so_err == 0) return;
    return switch (so_err) {
        @intFromEnum(std.posix.E.NOENT) => error.FileNotFound,
        @intFromEnum(std.posix.E.CONNREFUSED) => error.ConnectionRefused,
        @intFromEnum(std.posix.E.TIMEDOUT) => error.TimedOut,
        else => error.SocketConnectFailed,
    };
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

/// Unlink `path` only when it still names the same inode as `listen_fd`.
/// Never unlink a successor that rebound the same path.
///
/// macOS `fstat` on a Unix socket fd does not report the filesystem inode
/// (`st_dev` is -1). Callers should snapshot `lstatIdentity` after bind and
/// use `unlinkUnixSocketIfIdentity` instead.
pub fn unlinkUnixSocketIfSameInode(listen_fd: std.posix.fd_t, path: []const u8) void {
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .macos) return;
    const fd_id = fstatIdentity(listen_fd) catch return;
    unlinkUnixSocketIfIdentity(path, fd_id);
}

/// Unlink `path` only when its current lstat identity matches `expected`.
/// `expected` should be captured with `lstatIdentity` immediately after bind.
pub fn unlinkUnixSocketIfIdentity(path: []const u8, expected: PathIdentity) void {
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .macos) return;
    const path_id = lstatIdentity(path) catch return;
    if (path_id.dev != expected.dev or path_id.ino != expected.ino) return;
    unlinkUnixSocketPath(path);
}

pub const PathIdentity = struct {
    dev: u64,
    ino: u64,
    uid: u32,
    mode: u32,
    is_dir: bool,
    is_lnk: bool,
    is_sock: bool,
};

pub fn currentEuid() u32 {
    if (comptime builtin.os.tag == .windows) return 0;
    if (comptime builtin.os.tag == .linux) return std.os.linux.geteuid();
    return @intCast(std.c.geteuid());
}

/// Refuse a socket parent that is a symlink, not a dir, not owned by euid,
/// or writable by group/other. Callers chmod 0700 before this check.
pub fn requireTrustedSocketParent(path: []const u8) !void {
    const st = try lstatIdentity(path);
    if (st.is_lnk or !st.is_dir) return error.UntrustedSocketParent;
    if (st.uid != currentEuid()) return error.UntrustedSocketParent;
    if ((st.mode & 0o077) != 0) return error.UntrustedSocketParent;
}

/// Close the connection unless the peer euid matches ours.
pub fn requirePeerEuid(fd: std.posix.fd_t) !void {
    const uid = try peerUid(fd);
    if (uid != currentEuid()) return error.UntrustedPeer;
}

pub fn peerUid(fd: std.posix.fd_t) !u32 {
    if (comptime builtin.os.tag == .macos) {
        const c_getpeereid = struct {
            extern "c" fn getpeereid(s: std.c.fd_t, euid: *std.c.uid_t, egid: *std.c.gid_t) c_int;
        }.getpeereid;
        var uid: std.c.uid_t = undefined;
        var gid: std.c.gid_t = undefined;
        if (c_getpeereid(fd, &uid, &gid) != 0) return error.UntrustedPeer;
        return uid;
    }
    if (comptime builtin.os.tag == .linux) {
        const Ucred = extern struct {
            pid: std.c.pid_t,
            uid: std.c.uid_t,
            gid: std.c.gid_t,
        };
        var cred: Ucred = undefined;
        var len: std.c.socklen_t = @sizeOf(Ucred);
        if (std.c.getsockopt(fd, solSocket(), @intCast(std.os.linux.SO.PEERCRED), @ptrCast(&cred), &len) < 0)
            return error.UntrustedPeer;
        return cred.uid;
    }
    return error.UnsupportedOs;
}

pub fn lstatIdentity(path: []const u8) !PathIdentity {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const z = try pathToZ(path, &buf);
    return lstatZ(z);
}

pub fn fstatIdentity(fd: std.posix.fd_t) !PathIdentity {
    if (comptime builtin.os.tag == .linux) {
        return statxIdentity(fd, "", std.os.linux.AT.EMPTY_PATH);
    }
    if (comptime builtin.os.tag == .macos) {
        var st: std.c.Stat = undefined;
        if (std.c.fstat(fd, &st) != 0) return error.StatFailed;
        return identityFromDarwinStat(st);
    }
    return error.UnsupportedOs;
}

fn lstatZ(path_z: [:0]const u8) !PathIdentity {
    if (comptime builtin.os.tag == .linux) {
        return statxIdentity(std.os.linux.AT.FDCWD, path_z, std.os.linux.AT.SYMLINK_NOFOLLOW);
    }
    if (comptime builtin.os.tag == .macos) {
        const c_lstat = struct {
            extern "c" fn lstat(path: [*:0]const u8, buf: *std.c.Stat) c_int;
        }.lstat;
        var st: std.c.Stat = undefined;
        if (c_lstat(path_z, &st) != 0) return error.StatFailed;
        return identityFromDarwinStat(st);
    }
    return error.UnsupportedOs;
}

fn statxIdentity(dirfd: i32, path: [*:0]const u8, flags: u32) !PathIdentity {
    const linux = std.os.linux;
    var stx = std.mem.zeroes(linux.Statx);
    const rc = linux.statx(dirfd, path, flags, linux.STATX.BASIC_STATS, &stx);
    if (std.posix.errno(@as(isize, @intCast(rc))) != .SUCCESS) return error.StatFailed;
    if (!stx.mask.TYPE or !stx.mask.MODE or !stx.mask.UID or !stx.mask.INO)
        return error.StatFailed;
    return .{
        .dev = (@as(u64, stx.dev_major) << 32) | stx.dev_minor,
        .ino = stx.ino,
        .uid = stx.uid,
        .mode = stx.mode,
        .is_dir = linux.S.ISDIR(stx.mode),
        .is_lnk = linux.S.ISLNK(stx.mode),
        .is_sock = linux.S.ISSOCK(stx.mode),
    };
}

fn identityFromDarwinStat(st: anytype) PathIdentity {
    return .{
        .dev = @as(u64, @bitCast(@as(i64, st.dev))),
        .ino = st.ino,
        .uid = st.uid,
        .mode = st.mode,
        .is_dir = std.c.S.ISDIR(st.mode),
        .is_lnk = std.c.S.ISLNK(st.mode),
        .is_sock = std.c.S.ISSOCK(st.mode),
    };
}

fn pathToZ(path: []const u8, buf: *[std.fs.max_path_bytes]u8) ![:0]const u8 {
    if (path.len >= buf.len) return error.PathTooLong;
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;
    return buf[0..path.len :0];
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

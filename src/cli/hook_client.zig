//! Thin UDS client for `ryk hook` / `evaluate` / bare `ryk`.
//!
//! Missing socket, version mismatch, or `RYK_HOOK_SERVER=0` → `error.Unavailable`
//! so callers evaluate in-process. A broken mid-request session is not Unavailable.

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");

const daemon_uds = @import("daemon_uds.zig");
const env_util = @import("../env_util.zig");
const hook_ipc = @import("hook_ipc.zig");
const host_wire_rewrite = @import("host_wire_rewrite.zig");
const fd_scrub = @import("../sandbox/fd_scrub.zig");

pub const ClientError = error{
    Unavailable,
    BrokenSession,
    OutOfMemory,
};

pub const OwnedResponse = struct {
    parsed: hook_ipc.ParsedResponse,
    raw: []u8,

    pub fn deinit(self: *OwnedResponse, allocator: std.mem.Allocator) void {
        allocator.free(self.raw);
        self.parsed.deinit();
    }

    pub fn response(self: *const OwnedResponse) hook_ipc.Response {
        return self.parsed.response;
    }
};

pub fn serverEnabled() bool {
    if (env_util.getenvBrand("HOOK_SERVER")) |raw_c| {
        const raw = std.mem.span(raw_c);
        if (std.mem.eql(u8, raw, "0") or
            std.ascii.eqlIgnoreCase(raw, "false") or
            std.ascii.eqlIgnoreCase(raw, "no") or
            std.ascii.eqlIgnoreCase(raw, "off"))
        {
            return false;
        }
    }
    return true;
}

/// Unit tests stay in-process unless a test sets a private `RYK_HOOK_SOCKET`.
pub fn shouldTry() bool {
    if (comptime builtin.os.tag == .windows) return false;
    if (!serverEnabled()) return false;
    if (builtin.is_test) {
        if (env_util.getenvBrand("HOOK_SOCKET")) |raw_c| return std.mem.span(raw_c).len > 0;
        return false;
    }
    return true;
}

/// True when `tryServe` failed in a way that must emit host deny JSON.
/// `Unavailable` falls through in-process; OOM / broken session must not
/// return empty stdout on the named-hook path.
pub fn serveErrorIsFailClosed(err: ClientError) bool {
    return switch (err) {
        error.Unavailable => false,
        error.BrokenSession, error.OutOfMemory => true,
    };
}

/// Fold `--ci` / mode=ci with process unattended keys into hook-serve `req.ci`.
/// hook-serve must not getenvUnattended (prewarm env is stripped; client sends the fold).
pub fn clientUnattendedCi(explicit_ci: bool) bool {
    return host_wire_rewrite.unattendedFromEnv(explicit_ci);
}

/// Absolute client cwd for a hook-serve request. Null means skip the server
/// so callers never stamp workspace/cwd as "".
///
/// `realPathFileAlloc` returns `[:0]u8` (`dupeZ`). Re-dupe as `[]u8` so
/// callers can `allocator.free` without a sentinel size mismatch.
pub fn resolveClientWorkspace(io: std.Io, allocator: std.mem.Allocator) ?[]u8 {
    const z = std.Io.Dir.cwd().realPathFileAlloc(io, ".", allocator) catch return null;
    defer allocator.free(z);
    if (z.len == 0) return null;
    return allocator.dupe(u8, z) catch return null;
}

pub fn tryServe(io: std.Io, allocator: std.mem.Allocator, request: hook_ipc.Request) ClientError!OwnedResponse {
    if (!shouldTry()) return error.Unavailable;

    const socket_path = resolveSocketPath(io, allocator, request.bin) catch return error.Unavailable;
    defer allocator.free(socket_path);

    const fd = connectOrSpawn(io, allocator, socket_path, request.bin) catch return error.Unavailable;
    defer _ = std.c.close(fd);

    const line = hook_ipc.stringifyRequest(allocator, request) catch return error.OutOfMemory;
    defer allocator.free(line);
    hook_ipc.writeAllFd(io, fd, line, hook_ipc.request_timeout_ms) catch return error.BrokenSession;
    const raw = hook_ipc.readLineFd(io, allocator, fd, hook_ipc.request_timeout_ms) catch return error.BrokenSession;
    errdefer allocator.free(raw);

    var parsed = hook_ipc.parseResponse(allocator, raw) catch return error.BrokenSession;
    if (parsed.response.mismatch) {
        parsed.deinit();
        _ = requestShutdown(io, allocator, socket_path, request);
        return error.Unavailable;
    }
    return .{ .parsed = parsed, .raw = raw };
}

pub fn prewarmBestEffort(io: std.Io, allocator: std.mem.Allocator) void {
    if (!serverEnabled()) return;
    if (comptime builtin.os.tag == .windows) return;
    if (builtin.is_test) return;
    const bin = std.process.executablePathAlloc(io, allocator) catch return;
    defer allocator.free(bin);
    const socket_path = resolveSocketPath(io, allocator, bin) catch return;
    defer allocator.free(socket_path);
    if (daemon_uds.connectUnixSocketTimeout(socket_path, hook_ipc.connect_timeout_ms)) |fd| {
        _ = std.c.close(fd);
        return;
    } else |_| {}
    spawnServe(io, allocator, socket_path, bin) catch {};
}

pub fn shutdownBestEffort(io: std.Io, allocator: std.mem.Allocator) bool {
    if (comptime builtin.os.tag == .windows) return false;
    const bin = std.process.executablePathAlloc(io, allocator) catch return false;
    defer allocator.free(bin);
    const socket_path = resolveSocketPath(io, allocator, bin) catch return false;
    defer allocator.free(socket_path);
    return requestShutdown(io, allocator, socket_path, .{
        .id = 1,
        .method = "shutdown",
        .bin = bin,
        .version = build_options.version,
    });
}

pub fn socketPathForDoctor(io: std.Io, allocator: std.mem.Allocator) ![]u8 {
    const bin = try std.process.executablePathAlloc(io, allocator);
    defer allocator.free(bin);
    return resolveSocketPath(io, allocator, bin);
}

pub fn socketIsLive(path: []const u8) bool {
    if (comptime builtin.os.tag == .windows) return false;
    const fd = daemon_uds.connectUnixSocketTimeout(path, hook_ipc.connect_timeout_ms) catch return false;
    _ = std.c.close(fd);
    return true;
}

fn resolveSocketPath(io: std.Io, allocator: std.mem.Allocator, bin_realpath: []const u8) ![]u8 {
    _ = io;
    if (env_util.getenvBrand("HOOK_SOCKET")) |raw_c| {
        const override = std.mem.span(raw_c);
        if (override.len > 0) return allocator.dupe(u8, override);
    }
    const real = if (bin_realpath.len == 0) "/usr/local/bin/ryk" else bin_realpath;
    return hook_ipc.defaultSocketPathAlloc(allocator, real);
}

fn connectOrSpawn(io: std.Io, allocator: std.mem.Allocator, socket_path: []const u8, bin: []const u8) !std.posix.fd_t {
    if (daemon_uds.connectUnixSocketTimeout(socket_path, hook_ipc.connect_timeout_ms)) |fd| return fd else |_| {}
    if (builtin.is_test) return error.Unavailable;
    spawnServe(io, allocator, socket_path, bin) catch {};
    const deadline = std.Io.Timestamp.now(io, .awake).toMilliseconds() + @as(i64, @intCast(hook_ipc.spawn_wait_ms));
    while (std.Io.Timestamp.now(io, .awake).toMilliseconds() < deadline) {
        if (daemon_uds.connectUnixSocketTimeout(socket_path, hook_ipc.connect_timeout_ms)) |fd| return fd else |_| {}
        if (comptime builtin.os.tag != .windows) {
            const delay = std.c.timespec{ .sec = 0, .nsec = 5 * std.time.ns_per_ms };
            _ = std.c.nanosleep(&delay, null);
        }
    }
    return error.Unavailable;
}

fn spawnServe(io: std.Io, allocator: std.mem.Allocator, socket_path: []const u8, bin: []const u8) !void {
    if (std.fs.path.dirname(socket_path)) |dir| {
        std.Io.Dir.cwd().createDirPath(io, dir) catch {};
    }
    const exe = if (bin.len > 0) bin else (std.process.executablePathAlloc(io, allocator) catch return error.Unavailable);
    defer if (bin.len == 0) allocator.free(exe);

    if (comptime builtin.os.tag == .linux or builtin.os.tag == .macos) {
        spawnDetachedHookServe(exe, socket_path) catch {
            try spawnAttachedFallback(io, exe, socket_path);
        };
        return;
    }
    try spawnAttachedFallback(io, exe, socket_path);
}

fn spawnAttachedFallback(io: std.Io, exe: []const u8, socket_path: []const u8) !void {
    var child = std.process.spawn(io, .{
        .argv = &.{ exe, "hook-serve", "--socket", socket_path },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
        .create_no_window = true,
    }) catch return error.Unavailable;
    if (comptime builtin.os.tag == .windows) {
        if (child.id) |id| {
            std.os.windows.CloseHandle(child.thread_handle);
            std.os.windows.CloseHandle(id);
        }
    }
    child.id = null;
}

fn spawnDetachedHookServe(exe: []const u8, socket_path: []const u8) !void {
    if (exe.len == 0 or exe.len >= std.fs.max_path_bytes) return error.Unavailable;
    if (socket_path.len == 0 or socket_path.len >= std.fs.max_path_bytes) return error.Unavailable;

    var exe_z: [std.fs.max_path_bytes]u8 = undefined;
    var sock_z: [std.fs.max_path_bytes]u8 = undefined;
    @memcpy(exe_z[0..exe.len], exe);
    exe_z[exe.len] = 0;
    @memcpy(sock_z[0..socket_path.len], socket_path);
    sock_z[socket_path.len] = 0;

    const pid = std.c.fork();
    if (pid < 0) return error.Unavailable;
    if (pid > 0) {
        var status: c_int = 0;
        _ = std.c.waitpid(pid, &status, 0);
        return;
    }

    _ = std.c.setsid();
    const pid2 = std.c.fork();
    if (pid2 < 0) std.c._exit(1);
    if (pid2 > 0) std.c._exit(0);

    const devnull = std.c.open("/dev/null", .{ .ACCMODE = .RDWR });
    if (devnull >= 0) {
        _ = std.c.dup2(devnull, 0);
        _ = std.c.dup2(devnull, 1);
        _ = std.c.dup2(devnull, 2);
        if (devnull > 2) _ = std.c.close(devnull);
    }

    fd_scrub.closeInheritedFdsDefault();

    var env_store: [hook_serve_env_cap][hook_serve_env_entry_max]u8 = undefined;
    var envp: [hook_serve_env_cap + 1]?[*:0]const u8 = undefined;
    const envp_len = fillHookServeEnvp(&env_store, &envp);
    envp[envp_len] = null;

    const argv = [_:null]?[*:0]const u8{
        exe_z[0..exe.len :0],
        "hook-serve",
        "--socket",
        sock_z[0..socket_path.len :0],
        null,
    };
    _ = std.c.execve(exe_z[0..exe.len :0], @ptrCast(&argv), @ptrCast(&envp));
    std.c._exit(127);
}

const hook_serve_env_cap = 32;
const hook_serve_env_entry_max = 512;

/// Allowlist for the detached hook-serve envp. Mode / unattended bits must
/// not freeze on the first prewarm (`RYK_MODE`, CI, soften, …).
fn keepHookServeEnvKey(name: []const u8) bool {
    if (std.mem.eql(u8, name, "PATH")) return true;
    if (std.mem.eql(u8, name, "HOME")) return true;
    if (std.mem.eql(u8, name, "TMPDIR") or std.mem.eql(u8, name, "TMP") or std.mem.eql(u8, name, "TEMP")) return true;
    if (std.mem.eql(u8, name, "XDG_RUNTIME_DIR")) return true;
    if (std.mem.eql(u8, name, "USER")) return true;
    if (std.mem.eql(u8, name, "LANG")) return true;
    if (std.mem.startsWith(u8, name, "LC_")) return true;
    return false;
}

fn fillHookServeEnvp(
    store: *[hook_serve_env_cap][hook_serve_env_entry_max]u8,
    envp: *[hook_serve_env_cap + 1]?[*:0]const u8,
) usize {
    var n: usize = 0;
    var i: usize = 0;
    while (std.c.environ[i]) |entry| : (i += 1) {
        if (n >= hook_serve_env_cap) break;
        const span = std.mem.span(entry);
        const eq = std.mem.indexOfScalar(u8, span, '=') orelse continue;
        if (!keepHookServeEnvKey(span[0..eq])) continue;
        if (span.len + 1 > hook_serve_env_entry_max) continue;
        @memcpy(store[n][0..span.len], span);
        store[n][span.len] = 0;
        envp[n] = store[n][0..span.len :0];
        n += 1;
    }
    return n;
}

fn requestShutdown(io: std.Io, allocator: std.mem.Allocator, socket_path: []const u8, request: hook_ipc.Request) bool {
    const fd = daemon_uds.connectUnixSocketTimeout(socket_path, hook_ipc.connect_timeout_ms) catch return false;
    defer _ = std.c.close(fd);
    const line = hook_ipc.stringifyRequest(allocator, .{
        .id = request.id,
        .method = "shutdown",
        .bin = request.bin,
        .version = request.version,
    }) catch return false;
    defer allocator.free(line);
    hook_ipc.writeAllFd(io, fd, line, hook_ipc.connect_timeout_ms) catch return false;
    if (hook_ipc.readLineFd(io, allocator, fd, hook_ipc.connect_timeout_ms)) |raw| {
        allocator.free(raw);
    } else |_| {}
    return true;
}

extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;
extern "c" fn unsetenv(name: [*:0]const u8) c_int;

test "RYK_HOOK_SERVER=0 never opens a socket" {
    try std.testing.expect(!flagMeansDisabled("1"));
    try std.testing.expect(flagMeansDisabled("0"));
    try std.testing.expect(flagMeansDisabled("false"));
    try std.testing.expect(flagMeansDisabled("off"));

    _ = setenv("RYK_HOOK_SERVER", "0", 1);
    defer _ = unsetenv("RYK_HOOK_SERVER");
    try std.testing.expect(!shouldTry());
    const result = tryServe(std.testing.io, std.testing.allocator, .{
        .id = 1,
        .method = "ping",
    });
    if (result) |*resp| {
        var owned = resp.*;
        owned.deinit(std.testing.allocator);
        return error.TestUnexpectedResult;
    } else |err| {
        try std.testing.expectEqual(error.Unavailable, err);
    }
}

test "missing socket is Unavailable without hanging" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    _ = setenv("RYK_HOOK_SOCKET", "/tmp/ryk-hook-client-missing-test.sock", 1);
    defer _ = unsetenv("RYK_HOOK_SOCKET");
    const started = std.Io.Timestamp.now(std.testing.io, .awake).toMilliseconds();
    const result = tryServe(std.testing.io, std.testing.allocator, .{
        .id = 1,
        .method = "ping",
        .bin = "/usr/local/bin/ryk-missing-client-test",
    });
    if (result) |*resp| {
        var owned = resp.*;
        owned.deinit(std.testing.allocator);
        return error.TestUnexpectedResult;
    } else |err| {
        try std.testing.expectEqual(error.Unavailable, err);
    }
    const elapsed = std.Io.Timestamp.now(std.testing.io, .awake).toMilliseconds() - started;
    try std.testing.expect(elapsed < 1500);
}

fn flagMeansDisabled(raw: []const u8) bool {
    return std.mem.eql(u8, raw, "0") or
        std.ascii.eqlIgnoreCase(raw, "false") or
        std.ascii.eqlIgnoreCase(raw, "no") or
        std.ascii.eqlIgnoreCase(raw, "off");
}

test "hook serve OOM and broken session are fail-closed; Unavailable is not" {
    try std.testing.expect(serveErrorIsFailClosed(error.OutOfMemory));
    try std.testing.expect(serveErrorIsFailClosed(error.BrokenSession));
    try std.testing.expect(!serveErrorIsFailClosed(error.Unavailable));
}

test "clientUnattendedCi is true when explicit_ci is true" {
    // Process env may also flip false → true (CI / RYK_CI / …). Do not assert
    // clientUnattendedCi(false) here — leftover-allow tests pin attended.
    try std.testing.expect(clientUnattendedCi(true));
}

test "hook-serve env allowlist drops mode bits and keeps runtime keys" {
    try std.testing.expect(keepHookServeEnvKey("PATH"));
    try std.testing.expect(keepHookServeEnvKey("HOME"));
    try std.testing.expect(keepHookServeEnvKey("TMPDIR"));
    try std.testing.expect(keepHookServeEnvKey("XDG_RUNTIME_DIR"));
    try std.testing.expect(keepHookServeEnvKey("USER"));
    try std.testing.expect(keepHookServeEnvKey("LANG"));
    try std.testing.expect(keepHookServeEnvKey("LC_ALL"));
    try std.testing.expect(keepHookServeEnvKey("LC_CTYPE"));
    try std.testing.expect(!keepHookServeEnvKey("RYK_MODE"));
    try std.testing.expect(!keepHookServeEnvKey("RYK_ALLOW_MODE_SOFTEN"));
    try std.testing.expect(!keepHookServeEnvKey("RYK_CI"));
    try std.testing.expect(!keepHookServeEnvKey("RYK_UNATTENDED"));
    try std.testing.expect(!keepHookServeEnvKey("RYK_NONINTERACTIVE"));
    try std.testing.expect(!keepHookServeEnvKey("CI"));
    try std.testing.expect(!keepHookServeEnvKey("RYK_HOOK_SOCKET"));
    try std.testing.expect(!keepHookServeEnvKey("SSH_AUTH_SOCK"));
    try std.testing.expect(!keepHookServeEnvKey("OPENAI_API_KEY"));
}

test "hook resolveClientWorkspace is a non-empty absolute path" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const cwd = resolveClientWorkspace(std.testing.io, std.testing.allocator) orelse
        return error.TestUnexpectedResult;
    defer std.testing.allocator.free(cwd);
    try std.testing.expect(cwd.len > 0);
    try std.testing.expect(std.fs.path.isAbsolute(cwd));
}

test "hook mismatch parse deinits JSON without taking raw ownership" {
    // tryServe errdefer owns `raw`; ParsedResponse.deinit must not free it.
    const raw = try std.testing.allocator.dupe(
        u8,
        "{\"v\":1,\"id\":1,\"exit\":0,\"stdout\":\"\",\"stderr\":\"\",\"mismatch\":true}\n",
    );
    defer std.testing.allocator.free(raw);
    var parsed = try hook_ipc.parseResponse(std.testing.allocator, raw);
    try std.testing.expect(parsed.response.mismatch);
    parsed.deinit();
}

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

    var parsed = hook_ipc.parseResponse(allocator, raw) catch {
        allocator.free(raw);
        return error.BrokenSession;
    };
    if (parsed.response.mismatch) {
        parsed.deinit();
        allocator.free(raw);
        requestShutdown(io, allocator, socket_path, request);
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
    if (daemon_uds.connectUnixSocket(socket_path)) |fd| {
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
    const fd = daemon_uds.connectUnixSocket(path) catch return false;
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
    if (daemon_uds.connectUnixSocket(socket_path)) |fd| return fd else |_| {}
    if (builtin.is_test) return error.Unavailable;
    spawnServe(io, allocator, socket_path, bin) catch {};
    const deadline = std.Io.Timestamp.now(io, .awake).toMilliseconds() + @as(i64, @intCast(hook_ipc.spawn_wait_ms));
    while (std.Io.Timestamp.now(io, .awake).toMilliseconds() < deadline) {
        if (daemon_uds.connectUnixSocket(socket_path)) |fd| return fd else |_| {}
        const delay = std.c.timespec{ .sec = 0, .nsec = 5 * std.time.ns_per_ms };
        _ = std.c.nanosleep(&delay, null);
    }
    return error.Unavailable;
}

fn spawnServe(io: std.Io, allocator: std.mem.Allocator, socket_path: []const u8, bin: []const u8) !void {
    if (std.fs.path.dirname(socket_path)) |dir| {
        std.Io.Dir.cwd().createDirPath(io, dir) catch {};
    }
    const exe = if (bin.len > 0) bin else (std.process.executablePathAlloc(io, allocator) catch return error.Unavailable);
    defer if (bin.len == 0) allocator.free(exe);

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

fn requestShutdown(io: std.Io, allocator: std.mem.Allocator, socket_path: []const u8, request: hook_ipc.Request) bool {
    const fd = daemon_uds.connectUnixSocket(socket_path) catch return false;
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

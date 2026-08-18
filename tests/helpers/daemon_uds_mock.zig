//! In-process UDS peers for daemon IPC hardening tests.

const std = @import("std");
const builtin = @import("builtin");
const daemon_uds = @import("ryk").cli.daemon_uds;

const Mode = enum {
    hang,
    oversized,
};

pub const MockServer = struct {
    server_fd: std.posix.fd_t,
    socket_path: []const u8,
    thread: std.Thread,
    stop: std.atomic.Value(bool),
    mode: Mode,
    payload_bytes: usize = 0,

    pub fn startHang(socket_path: []const u8) !MockServer {
        return start(socket_path, .hang, 0);
    }

    pub fn startOversized(socket_path: []const u8, payload_bytes: usize) !MockServer {
        return start(socket_path, .oversized, payload_bytes);
    }

    fn start(socket_path: []const u8, mode: Mode, payload_bytes: usize) !MockServer {
        const server_fd = try daemon_uds.bindListenUnixSocket(socket_path, 1);
        var server: MockServer = .{
            .server_fd = server_fd,
            .socket_path = socket_path,
            .thread = undefined,
            .stop = std.atomic.Value(bool).init(false),
            .mode = mode,
            .payload_bytes = payload_bytes,
        };
        server.thread = try std.Thread.spawn(.{}, serverWorker, .{&server});
        return server;
    }

    pub fn deinit(self: *MockServer) void {
        self.stop.store(true, .unordered);
        _ = std.c.close(self.server_fd);
        self.thread.join();
        daemon_uds.unlinkUnixSocketPath(self.socket_path);
        self.* = undefined;
    }

    fn acceptClient(server_fd: std.posix.fd_t) ?std.posix.fd_t {
        var addr: std.c.sockaddr.un = undefined;
        var addr_len: u32 = @sizeOf(std.c.sockaddr.un);
        const client_fd = std.c.accept(server_fd, @ptrCast(&addr), &addr_len);
        if (client_fd < 0) return null;
        return client_fd;
    }

    fn drainRequest(client_fd: std.posix.fd_t) void {
        var buf: [512]u8 = undefined;
        while (true) {
            const n = std.c.read(client_fd, &buf, buf.len);
            if (n <= 0) break;
            const read_len: usize = @intCast(n);
            if (std.mem.indexOfScalar(u8, buf[0..read_len], '\n')) |_| break;
        }
    }

    fn serverWorker(ctx: *MockServer) void {
        const client_fd = acceptClient(ctx.server_fd) orelse return;
        defer _ = std.c.close(client_fd);
        drainRequest(client_fd);

        switch (ctx.mode) {
            .hang => {
                while (!ctx.stop.load(.unordered)) {
                    const delay = std.c.timespec{ .sec = 0, .nsec = 10 * std.time.ns_per_ms };
                    _ = std.c.nanosleep(&delay, null);
                }
            },
            .oversized => {
                const chunk = [_]u8{'x'} ** 4096;
                var sent: usize = 0;
                const target = if (ctx.payload_bytes > 0) ctx.payload_bytes else 1024 * 1024 + 64;
                while (sent < target) {
                    const to_send = @min(chunk.len, target - sent);
                    const wrote = std.c.write(client_fd, chunk[0..to_send].ptr, to_send);
                    if (wrote <= 0) break;
                    sent += @intCast(wrote);
                }
                ctx.stop.store(true, .unordered);
            },
        }
    }
};

comptime {
    if (builtin.os.tag == .windows) {
        @compileError("daemon_uds_mock requires Unix domain sockets");
    }
}
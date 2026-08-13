const std = @import("std");
const builtin = @import("builtin");

const core = @import("ryk_core").core;
const jsonrpc = @import("jsonrpc.zig");
const stdio = @import("stdio.zig");

pub const implemented = true;

pub const Kind = enum {
    stdio,
    http,

    pub fn toString(self: Kind) []const u8 {
        return @tagName(self);
    }
};

pub const Descriptor = struct {
    kind: Kind,
    command: []const []const u8 = &.{},
    endpoint: ?[]const u8 = null,

    pub fn stdio(argv: []const []const u8) Descriptor {
        return .{ .kind = .stdio, .command = argv };
    }

    pub fn http(endpoint: []const u8) Descriptor {
        return .{ .kind = .http, .endpoint = endpoint };
    }
};

pub const HttpTransport = struct {
    pub fn request(_: *HttpTransport, _: std.mem.Allocator, _: []const u8) ![]u8 {
        return error.HttpMcpTransportDeferred;
    }

    pub fn notify(_: *HttpTransport, _: []const u8) !void {
        return error.HttpMcpTransportDeferred;
    }
};

pub const ProcessServer = struct {
    allocator: std.mem.Allocator,
    child: std.process.Child,
    stdin_writer: std.Io.File.Writer,
    stdout_reader: std.Io.File.Reader,
    stdin_buffer: []u8,
    stdout_buffer: []u8,

    pub fn spawn(io: std.Io, allocator: std.mem.Allocator, argv: []const []const u8) !ProcessServer {
        return spawnWithEnvMap(io, allocator, argv, null);
    }

    pub fn spawnWithEnvMap(io: std.Io, allocator: std.mem.Allocator, argv: []const []const u8, env_map: ?*const std.process.Environ.Map) !ProcessServer {
        if (argv.len == 0) return error.InvalidCommand;
        var child = try std.process.spawn(io, .{
            .argv = argv,
            .environ_map = env_map,
            .stdin = .pipe,
            .stdout = .pipe,
            // Child diagnostics are attacker-controlled and may contain credentials.
            // MCP protocol traffic uses stdout, so discarding stderr cannot corrupt
            // JSON-RPC and cannot backpressure or deadlock on an unread pipe.
            .stderr = .ignore,
        });
        errdefer child.kill(io);

        const stdin_buffer = try allocator.alloc(u8, 16 * 1024);
        errdefer allocator.free(stdin_buffer);
        const stdout_buffer = try allocator.alloc(u8, core.limits.max_mcp_message_len + 1);
        errdefer allocator.free(stdout_buffer);

        return .{
            .allocator = allocator,
            .child = child,
            .stdin_writer = child.stdin.?.writer(io, stdin_buffer),
            .stdout_reader = child.stdout.?.reader(io, stdout_buffer),
            .stdin_buffer = stdin_buffer,
            .stdout_buffer = stdout_buffer,
        };
    }

    pub fn deinit(self: *ProcessServer, io: std.Io) void {
        self.stdin_writer.interface.flush() catch {};
        self.child.kill(io);
        self.allocator.free(self.stdin_buffer);
        self.allocator.free(self.stdout_buffer);
        self.* = undefined;
    }

    pub fn request(context: *anyopaque, allocator: std.mem.Allocator, line: []const u8) ![]u8 {
        try send(context, line);
        return try read(context, allocator);
    }

    pub fn notify(context: *anyopaque, line: []const u8) !void {
        try send(context, line);
    }

    pub fn send(context: *anyopaque, line: []const u8) !void {
        const self: *ProcessServer = @ptrCast(@alignCast(context));
        try stdio.writeRawMessage(&self.stdin_writer.interface, line);
        try self.stdin_writer.interface.flush();
    }

    pub fn read(context: *anyopaque, allocator: std.mem.Allocator) ![]u8 {
        const self: *ProcessServer = @ptrCast(@alignCast(context));
        const response = try stdio.readMessageLine(&self.stdout_reader.interface, allocator) orelse return error.McpServerClosed;
        errdefer allocator.free(response);
        var parsed = try jsonrpc.parseLine(allocator, response);
        parsed.deinit();
        return response;
    }
};

test "transport descriptors preserve stdio and honestly defer http" {
    const stdio_desc = Descriptor.stdio(&.{ "node", "server.js" });
    try std.testing.expectEqual(Kind.stdio, stdio_desc.kind);
    try std.testing.expectEqualStrings("node", stdio_desc.command[0]);

    const http_desc = Descriptor.http("https://example.invalid/mcp");
    try std.testing.expectEqual(Kind.http, http_desc.kind);
    var http = HttpTransport{};
    try std.testing.expectError(error.HttpMcpTransportDeferred, http.request(std.testing.allocator, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}"));
}

test "process transport cleans up child after post-spawn allocation failures" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const source = try std.Io.Dir.cwd().readFileAlloc(io, "src/mcp/transport.zig", std.testing.allocator, .limited(64 * 1024));
    defer std.testing.allocator.free(source);
    try std.testing.expect(std.mem.count(u8, source, "errdefer child.kill(io);") >= 1);
}

test "process transport never inherits child stderr" {
    const source = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, "src/mcp/transport.zig", std.testing.allocator, .limited(64 * 1024));
    defer std.testing.allocator.free(source);
    try std.testing.expect(std.mem.indexOf(u8, source, ".stderr = .ignore") != null);
}

test "ignored child stderr cannot block json-rpc response" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try ProcessServer.spawn(io, std.testing.allocator, &.{
        "/bin/sh",
        "-c",
        "i=0; while [ $i -lt 10000 ]; do printf synthetic-stderr-canary >&2; i=$((i+1)); done; printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}'; sleep 1",
    });
    defer server.deinit(io);

    const response = try ProcessServer.request(&server, std.testing.allocator, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}");
    defer std.testing.allocator.free(response);
    try std.testing.expect(std.mem.indexOf(u8, response, "\"result\":{}") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "synthetic-stderr-canary") == null);
}

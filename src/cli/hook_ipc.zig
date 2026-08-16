//! NDJSON protocol types and socket path for the per-user Zig hook server.
//!
//! Label is `ryk-hook-v1`. This is not the removed Rust daemon protocol
//! (`Ping` / `Evaluate` / `ExecuteCli`).

const std = @import("std");
const builtin = @import("builtin");

pub const protocol_label = "ryk-hook-v1";
pub const protocol_version: u32 = 1;
pub const max_line_bytes: usize = 1024 * 1024;
pub const listen_backlog: u31 = 128;
pub const connect_timeout_ms: u64 = 50;
pub const request_timeout_ms: u64 = 2000;
pub const spawn_wait_ms: u64 = 200;
pub const idle_exit_ms: u64 = 30 * 60 * 1000;
pub const workspace_cache_cap: usize = 16;

pub const Request = struct {
    v: u32 = protocol_version,
    id: u64,
    method: []const u8,
    bin: []const u8 = "",
    version: []const u8 = "",
    host: []const u8 = "",
    event: []const u8 = "",
    ci: bool = false,
    probe: bool = false,
    workspace: []const u8 = "",
    cwd: []const u8 = "",
    session_id: []const u8 = "",
    /// Raw JSON object/array/string for the host payload. Empty means omitted.
    payload_json: []const u8 = "",
};

pub const Response = struct {
    v: u32 = protocol_version,
    id: u64,
    exit: u8,
    stdout: []const u8 = "",
    stderr: []const u8 = "",
    mismatch: bool = false,
};

/// First 8 hex characters of SHA-256(realpath).
pub fn binHash(realpath: []const u8) [8]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(realpath, &digest, .{});
    const hex_alphabet = "0123456789abcdef";
    return .{
        hex_alphabet[digest[0] >> 4],
        hex_alphabet[digest[0] & 0xf],
        hex_alphabet[digest[1] >> 4],
        hex_alphabet[digest[1] & 0xf],
        hex_alphabet[digest[2] >> 4],
        hex_alphabet[digest[2] & 0xf],
        hex_alphabet[digest[3] >> 4],
        hex_alphabet[digest[3] & 0xf],
    };
}

pub fn currentUid() u32 {
    if (comptime builtin.os.tag == .windows) return 0;
    if (comptime builtin.os.tag == .linux) return std.os.linux.geteuid();
    return @intCast(std.c.geteuid());
}

fn envSlice(name: [:0]const u8) ?[]const u8 {
    const raw = std.c.getenv(name) orelse return null;
    const value = std.mem.span(raw);
    if (value.len == 0) return null;
    return value;
}

/// `$XDG_RUNTIME_DIR/ryk/hook-<hex>.sock` or `$TMPDIR/ryk-<uid>/hook-<hex>.sock`.
pub fn socketPathAlloc(allocator: std.mem.Allocator, uid: u32, bin_realpath: []const u8) ![]u8 {
    return socketPathFromDirs(allocator, uid, bin_realpath, envSlice("XDG_RUNTIME_DIR"), envSlice("TMPDIR"));
}

pub fn socketPathFromDirs(
    allocator: std.mem.Allocator,
    uid: u32,
    bin_realpath: []const u8,
    xdg_runtime_dir: ?[]const u8,
    tmpdir: ?[]const u8,
) ![]u8 {
    if (bin_realpath.len == 0) return error.EmptyBinRealpath;
    const hash = binHash(bin_realpath);
    const path = if (xdg_runtime_dir) |runtime|
        try std.fmt.allocPrint(allocator, "{s}/ryk/hook-{s}.sock", .{ runtime, hash })
    else
        try std.fmt.allocPrint(allocator, "{s}/ryk-{d}/hook-{s}.sock", .{ tmpdir orelse "/tmp", uid, hash });
    errdefer allocator.free(path);
    if (path.len >= @sizeOf(std.c.sockaddr.un) or path.len >= std.fs.max_path_bytes)
        return error.SocketPathTooLong;
    // sockaddr_un.path is typically 108 bytes; reject before bind/connect truncates.
    if (path.len >= 108) return error.SocketPathTooLong;
    return path;
}

pub fn defaultSocketPathAlloc(allocator: std.mem.Allocator, bin_realpath: []const u8) ![]u8 {
    return socketPathAlloc(allocator, currentUid(), bin_realpath);
}

pub const HostEmit = struct {
    exit: u8,
    stdout: []u8,
    stderr: []u8,

    pub fn deinit(self: HostEmit, allocator: std.mem.Allocator) void {
        allocator.free(self.stdout);
        allocator.free(self.stderr);
    }
};

pub fn stringifyRequest(allocator: std.mem.Allocator, req: Request) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    const w = &out.writer;
    try w.writeAll("{\"v\":");
    try w.print("{d}", .{req.v});
    try w.writeAll(",\"id\":");
    try w.print("{d}", .{req.id});
    try w.writeAll(",\"method\":");
    try writeJsonString(w, req.method);
    try w.writeAll(",\"bin\":");
    try writeJsonString(w, req.bin);
    try w.writeAll(",\"version\":");
    try writeJsonString(w, req.version);
    try w.writeAll(",\"host\":");
    try writeJsonString(w, req.host);
    try w.writeAll(",\"event\":");
    try writeJsonString(w, req.event);
    try w.writeAll(",\"ci\":");
    try w.writeAll(if (req.ci) "true" else "false");
    try w.writeAll(",\"probe\":");
    try w.writeAll(if (req.probe) "true" else "false");
    try w.writeAll(",\"workspace\":");
    try writeJsonString(w, req.workspace);
    try w.writeAll(",\"cwd\":");
    try writeJsonString(w, req.cwd);
    try w.writeAll(",\"session_id\":");
    try writeJsonString(w, req.session_id);
    try w.writeAll(",\"payload\":");
    if (req.payload_json.len == 0) {
        try w.writeAll("{}");
    } else {
        try w.writeAll(req.payload_json);
    }
    try w.writeAll("}\n");
    return out.toOwnedSlice();
}

pub fn stringifyResponse(allocator: std.mem.Allocator, resp: Response) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    const w = &out.writer;
    try w.writeAll("{\"v\":");
    try w.print("{d}", .{resp.v});
    try w.writeAll(",\"id\":");
    try w.print("{d}", .{resp.id});
    try w.writeAll(",\"exit\":");
    try w.print("{d}", .{resp.exit});
    try w.writeAll(",\"stdout\":");
    try writeJsonString(w, resp.stdout);
    try w.writeAll(",\"stderr\":");
    try writeJsonString(w, resp.stderr);
    try w.writeAll(",\"mismatch\":");
    try w.writeAll(if (resp.mismatch) "true" else "false");
    try w.writeAll("}\n");
    return out.toOwnedSlice();
}

pub const ParsedRequest = struct {
    parsed: std.json.Parsed(std.json.Value),
    request: Request,

    pub fn deinit(self: *ParsedRequest, allocator: std.mem.Allocator) void {
        if (self.request.payload_json.len > 0) allocator.free(self.request.payload_json);
        self.parsed.deinit();
    }
};

pub fn parseRequest(allocator: std.mem.Allocator, line: []const u8) !ParsedRequest {
    const trimmed = std.mem.trim(u8, line, " \t\r\n");
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, trimmed, .{}) catch return error.InvalidRequest;
    errdefer parsed.deinit();
    if (parsed.value != .object) return error.InvalidRequest;
    const obj = parsed.value.object;
    const v = jsonInt(obj, "v") orelse return error.InvalidRequest;
    if (v != protocol_version) return error.ProtocolMismatch;
    const id = jsonInt(obj, "id") orelse return error.InvalidRequest;
    const method = jsonString(obj, "method") orelse return error.InvalidRequest;
    var payload_json: []const u8 = "";
    if (obj.get("payload")) |payload| {
        payload_json = try std.json.Stringify.valueAlloc(allocator, payload, .{});
    }
    return .{
        .parsed = parsed,
        .request = .{
            .v = @intCast(v),
            .id = @intCast(id),
            .method = method,
            .bin = jsonString(obj, "bin") orelse "",
            .version = jsonString(obj, "version") orelse "",
            .host = jsonString(obj, "host") orelse "",
            .event = jsonString(obj, "event") orelse "",
            .ci = jsonBool(obj, "ci"),
            .probe = jsonBool(obj, "probe"),
            .workspace = jsonString(obj, "workspace") orelse "",
            .cwd = jsonString(obj, "cwd") orelse "",
            .session_id = jsonString(obj, "session_id") orelse "",
            .payload_json = payload_json,
        },
    };
}

pub const ParsedResponse = struct {
    parsed: std.json.Parsed(std.json.Value),
    response: Response,

    pub fn deinit(self: *ParsedResponse) void {
        self.parsed.deinit();
    }
};

pub fn parseResponse(allocator: std.mem.Allocator, line: []const u8) !ParsedResponse {
    const trimmed = std.mem.trim(u8, line, " \t\r\n");
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, trimmed, .{}) catch return error.InvalidResponse;
    errdefer parsed.deinit();
    if (parsed.value != .object) return error.InvalidResponse;
    const obj = parsed.value.object;
    const v = jsonInt(obj, "v") orelse return error.InvalidResponse;
    if (v != protocol_version) return error.ProtocolMismatch;
    const id = jsonInt(obj, "id") orelse return error.InvalidResponse;
    const exit = jsonInt(obj, "exit") orelse return error.InvalidResponse;
    return .{
        .parsed = parsed,
        .response = .{
            .v = @intCast(v),
            .id = @intCast(id),
            .exit = @intCast(std.math.cast(u8, exit) orelse 2),
            .stdout = jsonString(obj, "stdout") orelse "",
            .stderr = jsonString(obj, "stderr") orelse "",
            .mismatch = jsonBool(obj, "mismatch"),
        },
    };
}

fn jsonString(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const value = obj.get(key) orelse return null;
    return switch (value) {
        .string => |s| s,
        else => null,
    };
}

fn jsonInt(obj: std.json.ObjectMap, key: []const u8) ?i64 {
    const value = obj.get(key) orelse return null;
    return switch (value) {
        .integer => |n| n,
        else => null,
    };
}

fn jsonBool(obj: std.json.ObjectMap, key: []const u8) bool {
    const value = obj.get(key) orelse return false;
    return switch (value) {
        .bool => |b| b,
        else => false,
    };
}

fn writeJsonString(writer: anytype, value: []const u8) !void {
    try std.json.Stringify.value(value, .{}, writer);
}

const poll_in: i16 = 0x0001;
const poll_out: i16 = 0x0004;

pub fn writeAllFd(io: std.Io, fd: std.posix.fd_t, bytes: []const u8, timeout_ms: u64) !void {
    if (comptime builtin.os.tag == .windows) return error.UnsupportedOs;
    var written: usize = 0;
    const deadline = nowMs(io) + timeout_ms;
    while (written < bytes.len) {
        const remaining = deadline -| nowMs(io);
        if (remaining == 0) return error.SocketWriteFailed;
        var fds = [_]std.posix.pollfd{.{
            .fd = fd,
            .events = poll_out,
            .revents = 0,
        }};
        const rc = std.posix.poll(fds[0..], pollTimeoutMs(remaining)) catch return error.SocketWriteFailed;
        if (rc <= 0) return error.SocketWriteFailed;
        const n = std.c.write(fd, bytes.ptr + written, bytes.len - written);
        if (n <= 0) return error.SocketWriteFailed;
        written += @intCast(n);
    }
}

pub fn readLineFd(io: std.Io, allocator: std.mem.Allocator, fd: std.posix.fd_t, timeout_ms: u64) ![]u8 {
    if (comptime builtin.os.tag == .windows) return error.UnsupportedOs;
    var read_buf: std.ArrayList(u8) = .empty;
    errdefer read_buf.deinit(allocator);
    const deadline = nowMs(io) + timeout_ms;
    var byte: [1]u8 = undefined;
    while (true) {
        const remaining = deadline -| nowMs(io);
        if (remaining == 0) return error.SocketReadFailed;
        try waitReadable(fd, remaining);
        const n = std.c.read(fd, &byte, 1);
        if (n <= 0) return error.SocketReadFailed;
        if (read_buf.items.len >= max_line_bytes) return error.SocketReadFailed;
        try read_buf.append(allocator, byte[0]);
        if (byte[0] == '\n') break;
    }
    return read_buf.toOwnedSlice(allocator);
}

fn nowMs(io: std.Io) u64 {
    const ms = std.Io.Timestamp.now(io, .awake).toMilliseconds();
    return if (ms < 0) 0 else @intCast(ms);
}

fn pollTimeoutMs(timeout_ms: u64) i32 {
    return @intCast(@min(timeout_ms, std.math.maxInt(i32)));
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

test "request round-trip keeps method and payload" {
    const raw = try stringifyRequest(std.testing.allocator, .{
        .id = 7,
        .method = "ping",
        .bin = "/usr/local/bin/ryk",
        .version = "0.0.0-test",
        .payload_json = "{\"ok\":true}",
    });
    defer std.testing.allocator.free(raw);
    var parsed = try parseRequest(std.testing.allocator, raw);
    defer parsed.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("ping", parsed.request.method);
    try std.testing.expectEqual(@as(u64, 7), parsed.request.id);
}

test "socketPathAlloc includes uid and bin hash" {
    const path = try socketPathAlloc(std.testing.allocator, 501, "/usr/local/bin/ryk");
    defer std.testing.allocator.free(path);
    try std.testing.expect(std.mem.indexOf(u8, path, "hook-") != null);
    try std.testing.expect(std.mem.indexOf(u8, path, "ryk-daemon") == null);
    try std.testing.expect(std.mem.indexOf(u8, path, &binHash("/usr/local/bin/ryk")) != null);
}

test "binHash is stable for the same realpath" {
    const a = binHash("/usr/local/bin/ryk");
    const b = binHash("/usr/local/bin/ryk");
    try std.testing.expectEqualSlices(u8, &a, &b);
}

test "socketPathAlloc rejects empty realpath" {
    try std.testing.expectError(error.EmptyBinRealpath, socketPathAlloc(std.testing.allocator, 501, ""));
}

test "socketPathAlloc rejects overlong directory prefix" {
    var overlong: [200]u8 = undefined;
    @memset(&overlong, 'a');
    try std.testing.expectError(
        error.SocketPathTooLong,
        socketPathFromDirs(std.testing.allocator, 1, "/usr/local/bin/ryk", &overlong, null),
    );
}

test "binHash differs for different realpaths" {
    const a = binHash("/usr/local/bin/ryk");
    const b = binHash("./zig-out/bin/ryk");
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
}

test "protocol_label is ryk-hook-v1" {
    try std.testing.expectEqualStrings("ryk-hook-v1", protocol_label);
    try std.testing.expect(std.mem.indexOf(u8, protocol_label, "ryk-daemon") == null);
}

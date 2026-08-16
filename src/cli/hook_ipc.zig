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

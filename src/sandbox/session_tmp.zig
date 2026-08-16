//! Workspace session temp helpers for OS-FS attach.
//!
//! Preferred TMPDIR under attach is `{workspace}/.ryk-tmp` (covered by workspace RW).
//! Landlock parent expand and apply attach both need this path pre-created before
//! plan enumeration / child restrict. Kept free of apply / apply_posix imports so
//! those modules do not form a cycle over session-tmp alone.

const std = @import("std");
const builtin = @import("builtin");

/// Relative session temp directory under the workspace (always covered by workspace RW).
/// Pre-created on the attach path so Landlock child-expand can PATH_BENEATH it.
pub const workspace_session_tmp_name = ".ryk-tmp";

/// Claude Code consults this env (then `{base}/claude-{uid}`) and `lstat`s the
/// result. Host-supplied values are stripped by the launch allowlist; attach
/// mints this to the verified session temp after allowlist.
pub const claude_code_tmpdir_env = "CLAUDE_CODE_TMPDIR";

/// Classic system temp path literal (`/tmp`).
///
/// **Not** an attach rewrite target under production defaults: `include_tmp` is false
/// so bare classic temp is not agent-writable. When `{workspace}/.ryk-tmp` cannot be
/// prepared, apply fails closed with `session_tmp_prepare_failed` rather than pointing
/// TMPDIR here (M-8 honesty). Kept as a named constant for grant comparisons / docs.
pub const classic_tmp_fallback = "/tmp";

/// Absolute path for the preferred attach TMPDIR under `workspace_root`.
/// Caller owns the returned slice.
pub fn workspaceSessionTmpPath(allocator: std.mem.Allocator, workspace_root: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ workspace_root, workspace_session_tmp_name });
}

/// Best-effort create `{workspace}/.ryk-tmp` so Landlock control-expand can
/// PATH_BENEATH a RW child even when the workspace only has control roots.
/// Must run **before** `buildChildLandlockPlan` / child attach enumeration.
/// Returns true when the preferred session path exists after the attempt.
pub fn ensureWorkspaceSessionTmp(workspace_root: []const u8) bool {
    if (workspace_root.len == 0) return false;
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const needed = workspace_root.len + 1 + workspace_session_tmp_name.len;
    if (needed > path_buf.len) return false;
    @memcpy(path_buf[0..workspace_root.len], workspace_root);
    path_buf[workspace_root.len] = '/';
    @memcpy(
        path_buf[workspace_root.len + 1 ..][0..workspace_session_tmp_name.len],
        workspace_session_tmp_name,
    );
    const preferred = path_buf[0..needed];

    var io_rt: std.Io.Threaded = .init_single_threaded;
    const io = io_rt.io();
    std.Io.Dir.cwd().createDirPath(io, preferred) catch {};
    if (std.Io.Dir.openDirAbsolute(io, preferred, .{ .follow_symlinks = false })) |dir_opened| {
        var dir = dir_opened;
        dir.close(io);
        return true;
    } else |_| {
        return false;
    }
}

/// True when `path` exists as a real directory (does not follow a final symlink).
/// Mirrors Claude Code's `lstat` + `isDirectory` tmp check (`safeTempBase` / `hOo`).
pub fn claudeCodeTmpAccepts(path: []const u8) bool {
    if (path.len == 0) return false;
    var io_rt: std.Io.Threaded = .init_single_threaded;
    const io = io_rt.io();
    if (std.Io.Dir.openDirAbsolute(io, path, .{ .follow_symlinks = false })) |dir_opened| {
        var dir = dir_opened;
        dir.close(io);
        return true;
    } else |_| {
        return false;
    }
}

/// Claude Code leaf under the session temp: `claude-{uid}` on Unix (`getuid?.() ?? 0`
/// → `claude-0` when getuid is missing), `claude` on Windows.
pub fn claudeTempLeafName(buf: *[32]u8, uid: u32) []const u8 {
    if (builtin.os.tag == .windows) return "claude";
    return std.fmt.bufPrint(buf, "claude-{d}", .{uid}) catch "claude-0";
}

pub fn currentUid() u32 {
    return switch (builtin.os.tag) {
        .windows => 0,
        .linux => std.os.linux.getuid(),
        else => @intCast(std.c.getuid()),
    };
}

fn ensureRealDir(path: []const u8) bool {
    if (path.len == 0) return false;
    var io_rt: std.Io.Threaded = .init_single_threaded;
    const io = io_rt.io();
    std.Io.Dir.createDirAbsolute(io, path, .default_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return false,
    };
    return claudeCodeTmpAccepts(path);
}

fn ensureSessionChildDir(session_root: []const u8, leaf: []const u8) bool {
    if (session_root.len == 0 or leaf.len == 0) return false;
    if (std.mem.indexOfScalar(u8, leaf, '/') != null) return false;
    if (std.mem.indexOfScalar(u8, leaf, '\\') != null) return false;
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const needed = session_root.len + 1 + leaf.len;
    if (needed > path_buf.len) return false;
    @memcpy(path_buf[0..session_root.len], session_root);
    path_buf[session_root.len] = '/';
    @memcpy(path_buf[session_root.len + 1 ..][0..leaf.len], leaf);
    return ensureRealDir(path_buf[0..needed]);
}

/// Pre-create the Claude Code tmp leaf under a verified session temp.
///
/// Claude joins `CLAUDE_CODE_TMPDIR` or `os.tmpdir()` (`TMPDIR`) with
/// `claude-{uid}` (or `claude-0` when getuid is missing) and refuses a
/// non-directory / attacker-planted symlink. Fail closed on a plant; never
/// follow or trust a pre-existing symlink.
pub fn ensureClaudeCodeTmpLeaves(session_root: []const u8) bool {
    if (session_root.len == 0) return false;
    if (!claudeCodeTmpAccepts(session_root)) return false;

    var uid_buf: [32]u8 = undefined;
    const uid = currentUid();
    const uid_leaf = claudeTempLeafName(&uid_buf, uid);
    if (!ensureSessionChildDir(session_root, uid_leaf)) return false;
    // Claude's `process.getuid?.() ?? 0` fallback when getuid is unavailable.
    if (builtin.os.tag != .windows and uid != 0) {
        if (!ensureSessionChildDir(session_root, "claude-0")) return false;
    }
    return true;
}

test "ensureWorkspaceSessionTmp rejects a planted final symlink" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    try tmp.dir.createDir(io, "outside", .default_dir);
    try tmp.dir.symLink(io, "outside", workspace_session_tmp_name, .{ .is_directory = true });
    const root = try tmp.dir.realPathFileAlloc(io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    try std.testing.expect(!ensureWorkspaceSessionTmp(root));
}

test "ensureClaudeCodeTmpLeaves creates a real dir Claude's check accepts" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    const root = try tmp.dir.realPathFileAlloc(io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    try std.testing.expect(ensureWorkspaceSessionTmp(root));
    const session = try workspaceSessionTmpPath(std.testing.allocator, root);
    defer std.testing.allocator.free(session);
    try std.testing.expect(ensureClaudeCodeTmpLeaves(session));
    try std.testing.expect(claudeCodeTmpAccepts(session));

    var uid_buf: [32]u8 = undefined;
    const leaf = claudeTempLeafName(&uid_buf, currentUid());
    const leaf_path = try std.fs.path.join(std.testing.allocator, &.{ session, leaf });
    defer std.testing.allocator.free(leaf_path);
    try std.testing.expect(claudeCodeTmpAccepts(leaf_path));

    if (builtin.os.tag != .windows and currentUid() != 0) {
        const fallback = try std.fs.path.join(std.testing.allocator, &.{ session, "claude-0" });
        defer std.testing.allocator.free(fallback);
        try std.testing.expect(claudeCodeTmpAccepts(fallback));
    }
}

test "ensureClaudeCodeTmpLeaves rejects a planted claude tmp symlink" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    try tmp.dir.createDir(io, "outside", .default_dir);
    try tmp.dir.createDir(io, "session", .default_dir);
    {
        var session_dir = try tmp.dir.openDir(io, "session", .{});
        defer session_dir.close(io);
        try session_dir.symLink(io, "../outside", "claude-0", .{ .is_directory = true });
    }
    const session = try tmp.dir.realPathFileAlloc(io, "session", std.testing.allocator);
    defer std.testing.allocator.free(session);
    const planted = try std.fs.path.join(std.testing.allocator, &.{ session, "claude-0" });
    defer std.testing.allocator.free(planted);
    try std.testing.expect(!claudeCodeTmpAccepts(planted));
    try std.testing.expect(!ensureSessionChildDir(session, "claude-0"));
    try std.testing.expect(!ensureClaudeCodeTmpLeaves(session));
}

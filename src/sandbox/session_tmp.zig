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

/// True when `path` is a ryk-minted attach session temp (`…/.ryk-tmp/session-…`).
/// Used to refuse creating Claude leaves under `$HOME`, classic `/tmp`, or a
/// host-planted TMPDIR. Absolute Unix path only.
pub fn isAttachSessionTmpPath(path: []const u8) bool {
    if (path.len == 0 or path[0] != '/') return false;
    return std.mem.indexOf(u8, path, "/.ryk-tmp/session-") != null;
}

fn envEntryValue(entry: []const u8, key: []const u8) ?[]const u8 {
    if (entry.len < key.len + 1) return null;
    if (!std.mem.startsWith(u8, entry, key)) return null;
    if (entry[key.len] != '=') return null;
    return entry[key.len + 1 ..];
}

/// Claude's tmp base from `KEY=value` entries: `CLAUDE_CODE_TMPDIR`, then
/// `TMPDIR` / `TMP` / `TEMP` (`os.tmpdir()`). Only a minted attach session
/// path is returned — never `$HOME` or classic `/tmp`.
pub fn attachSessionTmpBaseFromEnvEntries(entries: []const []const u8) ?[]const u8 {
    var claude_tmp: ?[]const u8 = null;
    var tmpdir: ?[]const u8 = null;
    var tmp: ?[]const u8 = null;
    var temp: ?[]const u8 = null;
    for (entries) |entry| {
        if (envEntryValue(entry, claude_code_tmpdir_env)) |v| {
            claude_tmp = v;
        } else if (envEntryValue(entry, "TMPDIR")) |v| {
            tmpdir = v;
        } else if (envEntryValue(entry, "TMP")) |v| {
            tmp = v;
        } else if (envEntryValue(entry, "TEMP")) |v| {
            temp = v;
        }
    }
    const candidates = [_][]const u8{
        claude_tmp orelse "",
        tmpdir orelse "",
        tmp orelse "",
        temp orelse "",
    };
    for (candidates) |v| {
        if (isAttachSessionTmpPath(v)) return v;
    }
    return null;
}

pub fn attachSessionTmpBaseFromEnvp(envp: [*:null]const ?[*:0]const u8) ?[]const u8 {
    var claude_tmp: ?[]const u8 = null;
    var tmpdir: ?[]const u8 = null;
    var tmp: ?[]const u8 = null;
    var temp: ?[]const u8 = null;
    var i: usize = 0;
    while (envp[i]) |entry_z| : (i += 1) {
        const entry = std.mem.span(entry_z);
        if (envEntryValue(entry, claude_code_tmpdir_env)) |v| {
            claude_tmp = v;
        } else if (envEntryValue(entry, "TMPDIR")) |v| {
            tmpdir = v;
        } else if (envEntryValue(entry, "TMP")) |v| {
            tmp = v;
        } else if (envEntryValue(entry, "TEMP")) |v| {
            temp = v;
        }
    }
    const candidates = [_][]const u8{
        claude_tmp orelse "",
        tmpdir orelse "",
        tmp orelse "",
        temp orelse "",
    };
    for (candidates) |v| {
        if (isAttachSessionTmpPath(v)) return v;
    }
    return null;
}

/// Pre-create the Claude Code tmp leaf under a verified session temp.
///
/// Claude joins `CLAUDE_CODE_TMPDIR` or `os.tmpdir()` (`TMPDIR`) with
/// `claude-{uid}` (or `claude-0` when getuid is missing) and refuses a
/// non-directory / attacker-planted symlink. Fail closed on a plant; never
/// follow or trust a pre-existing symlink.
///
/// The session root is created when missing (child-visible FUSE mkdir after
/// attach) but a planted symlink is not replaced.
pub fn ensureClaudeCodeTmpLeaves(session_root: []const u8) bool {
    if (session_root.len == 0) return false;
    if (!claudeCodeTmpAccepts(session_root)) {
        if (!ensureRealDir(session_root)) return false;
    }

    // Exact QA leaf: `{TMPDIR}/claude-0` (userns / `getuid?.() ?? 0`).
    if (builtin.os.tag != .windows) {
        if (!ensureSessionChildDir(session_root, "claude-0")) return false;
    }
    var uid_buf: [32]u8 = undefined;
    const uid_leaf = claudeTempLeafName(&uid_buf, currentUid());
    if (!std.mem.eql(u8, uid_leaf, "claude-0") and !std.mem.eql(u8, uid_leaf, "claude")) {
        if (!ensureSessionChildDir(session_root, uid_leaf)) return false;
    }
    return true;
}

/// Create Claude tmp leaves under the minted attach TMPDIR from `KEY=value`
/// entries. Missing attach session tmp is a no-op (true) so non-attach
/// launches are unchanged. A found session path that cannot be verified
/// fail-closes (false).
pub fn ensureClaudeCodeTmpLeavesFromEnvEntries(entries: []const []const u8) bool {
    const base = attachSessionTmpBaseFromEnvEntries(entries) orelse return true;
    return ensureClaudeCodeTmpLeaves(base);
}

/// Same as `ensureClaudeCodeTmpLeavesFromEnvEntries` but fail-closed when no
/// minted attach session tmp is present (workspace-view bootstrap after FUSE).
pub fn requireClaudeCodeTmpLeavesFromEnvEntries(entries: []const []const u8) bool {
    const base = attachSessionTmpBaseFromEnvEntries(entries) orelse return false;
    return ensureClaudeCodeTmpLeaves(base);
}

pub fn ensureClaudeCodeTmpLeavesFromEnvp(envp: [*:null]const ?[*:0]const u8) bool {
    const base = attachSessionTmpBaseFromEnvp(envp) orelse return true;
    return ensureClaudeCodeTmpLeaves(base);
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

test "isAttachSessionTmpPath accepts only minted session tmp" {
    try std.testing.expect(isAttachSessionTmpPath(
        "/home/box/ryk-202-nontmp/.ryk-tmp/session-a0abb25408fdcb848b404ba9-0",
    ));
    try std.testing.expect(!isAttachSessionTmpPath("/tmp"));
    try std.testing.expect(!isAttachSessionTmpPath("/tmp/claude-0"));
    try std.testing.expect(!isAttachSessionTmpPath("/home/box"));
    try std.testing.expect(!isAttachSessionTmpPath("/home/box/.ryk-tmp"));
    try std.testing.expect(!isAttachSessionTmpPath(""));
}

test "env helper creates exact QA leaf TMPDIR/claude-0 without CLAUDE_CODE_TMPDIR" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    try tmp.dir.createDirPath(io, ".ryk-tmp/session-a0abb25408fdcb848b404ba9-0");
    const root = try tmp.dir.realPathFileAlloc(io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const session = try std.fs.path.join(std.testing.allocator, &.{
        root,
        ".ryk-tmp",
        "session-a0abb25408fdcb848b404ba9-0",
    });
    defer std.testing.allocator.free(session);
    const tmpdir_entry = try std.fmt.allocPrint(std.testing.allocator, "TMPDIR={s}", .{session});
    defer std.testing.allocator.free(tmpdir_entry);
    const home_entry = try std.fmt.allocPrint(std.testing.allocator, "HOME={s}", .{root});
    defer std.testing.allocator.free(home_entry);
    const entries = [_][]const u8{ home_entry, tmpdir_entry, "PATH=/usr/bin" };

    try std.testing.expectEqualStrings(session, attachSessionTmpBaseFromEnvEntries(&entries).?);
    try std.testing.expect(requireClaudeCodeTmpLeavesFromEnvEntries(&entries));

    const qa_leaf = try std.fs.path.join(std.testing.allocator, &.{ session, "claude-0" });
    defer std.testing.allocator.free(qa_leaf);
    try std.testing.expect(claudeCodeTmpAccepts(qa_leaf));
}

test "env helper ignores HOME and classic /tmp and does not create leaves there" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    try tmp.dir.createDir(io, "home", .default_dir);
    const home = try tmp.dir.realPathFileAlloc(io, "home", std.testing.allocator);
    defer std.testing.allocator.free(home);
    const home_entry = try std.fmt.allocPrint(std.testing.allocator, "HOME={s}", .{home});
    defer std.testing.allocator.free(home_entry);
    const tmpdir_entry = try std.fmt.allocPrint(std.testing.allocator, "TMPDIR={s}", .{home});
    defer std.testing.allocator.free(tmpdir_entry);
    const claude_entry = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}={s}",
        .{ claude_code_tmpdir_env, home },
    );
    defer std.testing.allocator.free(claude_entry);
    const entries = [_][]const u8{ home_entry, tmpdir_entry, claude_entry, "TEMP=/tmp" };

    try std.testing.expect(attachSessionTmpBaseFromEnvEntries(&entries) == null);
    try std.testing.expect(ensureClaudeCodeTmpLeavesFromEnvEntries(&entries));
    try std.testing.expect(!requireClaudeCodeTmpLeavesFromEnvEntries(&entries));

    const home_leaf = try std.fs.path.join(std.testing.allocator, &.{ home, "claude-0" });
    defer std.testing.allocator.free(home_leaf);
    try std.testing.expect(!claudeCodeTmpAccepts(home_leaf));
}

test "env helper fail-closes on planted QA leaf symlink" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    try tmp.dir.createDir(io, "outside", .default_dir);
    try tmp.dir.createDirPath(io, ".ryk-tmp/session-a0abb25408fdcb848b404ba9-0");
    {
        var session_dir = try tmp.dir.openDir(io, ".ryk-tmp/session-a0abb25408fdcb848b404ba9-0", .{});
        defer session_dir.close(io);
        try session_dir.symLink(io, "../../outside", "claude-0", .{ .is_directory = true });
    }
    const session = try tmp.dir.realPathFileAlloc(
        io,
        ".ryk-tmp/session-a0abb25408fdcb848b404ba9-0",
        std.testing.allocator,
    );
    defer std.testing.allocator.free(session);
    const tmpdir_entry = try std.fmt.allocPrint(std.testing.allocator, "TMPDIR={s}", .{session});
    defer std.testing.allocator.free(tmpdir_entry);
    const entries = [_][]const u8{tmpdir_entry};
    try std.testing.expect(!requireClaudeCodeTmpLeavesFromEnvEntries(&entries));
    const planted = try std.fs.path.join(std.testing.allocator, &.{ session, "claude-0" });
    defer std.testing.allocator.free(planted);
    try std.testing.expect(!claudeCodeTmpAccepts(planted));
}

test "envp helper prefers CLAUDE_CODE_TMPDIR then TMPDIR for the QA leaf" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    try tmp.dir.createDirPath(io, ".ryk-tmp/session-a0abb25408fdcb848b404ba9-0");
    const session = try tmp.dir.realPathFileAlloc(
        io,
        ".ryk-tmp/session-a0abb25408fdcb848b404ba9-0",
        std.testing.allocator,
    );
    defer std.testing.allocator.free(session);
    const tmpdir_owned = try std.fmt.allocPrint(std.testing.allocator, "TMPDIR={s}", .{session});
    defer std.testing.allocator.free(tmpdir_owned);
    const tmpdir_z = try std.testing.allocator.dupeZ(u8, tmpdir_owned);
    defer std.testing.allocator.free(tmpdir_z);
    const home_z = try std.testing.allocator.dupeZ(u8, "HOME=/home/box");
    defer std.testing.allocator.free(home_z);
    var envp_buf = [_:null]?[*:0]const u8{ home_z.ptr, tmpdir_z.ptr };
    const envp: [:null]const ?[*:0]const u8 = &envp_buf;
    try std.testing.expectEqualStrings(session, attachSessionTmpBaseFromEnvp(envp.ptr).?);
    try std.testing.expect(ensureClaudeCodeTmpLeavesFromEnvp(envp.ptr));
    const qa_leaf = try std.fs.path.join(std.testing.allocator, &.{ session, "claude-0" });
    defer std.testing.allocator.free(qa_leaf);
    try std.testing.expect(claudeCodeTmpAccepts(qa_leaf));
}

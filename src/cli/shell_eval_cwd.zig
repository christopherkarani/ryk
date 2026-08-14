//! Cwd resolution for shell-eval allow-once / grant matching (M-14).
//!
//! Prefer `realpath` when it succeeds (Darwin `/var` vs `/private/var` canonicalization).
//! Under hardened Seatbelt, `realpath` can fail with EPERM even when the directory is
//! openable for normal use — absolute paths then fall back to as-is after an openDir
//! usability check (mirrors `hook.resolvePendingIssueCwd`). Relative paths fail closed
//! when realpath fails (no safe absolute form without a successful walk).
//!
//! Uses libc `realpath` (not Zig `realPathFileAlloc`) so EPERM does not trip
//! `unexpectedErrno` stack spam in Debug builds — errno is treated as a soft miss.

const std = @import("std");
const daemon = @import("daemon.zig");

/// Resolve the shell-eval working directory for allow-once / grant matching (M-14).
pub fn resolveEffectiveCwd(allocator: std.mem.Allocator, cwd: ?[]const u8) daemon.DaemonError![]const u8 {
    const path = cwd orelse ".";
    var threaded: std.Io.Threaded = .init_single_threaded;
    return resolveEffectiveCwdIo(threaded.io(), allocator, path);
}

pub fn resolveEffectiveCwdIo(io: std.Io, allocator: std.mem.Allocator, path: []const u8) daemon.DaemonError![]const u8 {
    if (try tryRealpathQuiet(allocator, path)) |resolved| {
        return resolved;
    }
    return resolveEffectiveCwdAfterRealpathFail(io, allocator, path);
}

/// Quiet realpath: returns null on any libc failure (including EPERM under Seatbelt)
/// without printing Zig's `unexpected errno` stack. Owned slice on success.
pub fn tryRealpathQuiet(allocator: std.mem.Allocator, path: []const u8) error{OutOfMemory}!?[]u8 {
    if (@import("builtin").os.tag == .windows) {
        // Windows residual: use Zig Io (no Seatbelt EPERM residual to silence).
        var threaded: std.Io.Threaded = .init_single_threaded;
        const io = threaded.io();
        const resolved_z = std.Io.Dir.cwd().realPathFileAlloc(io, path, allocator) catch return null;
        defer allocator.free(resolved_z);
        return try allocator.dupe(u8, resolved_z);
    }
    const path_z = try allocator.dupeZ(u8, path);
    defer allocator.free(path_z);
    var buf: [std.posix.PATH_MAX]u8 = undefined;
    const rc = std.c.realpath(path_z.ptr, &buf) orelse return null;
    return try allocator.dupe(u8, std.mem.span(rc));
}

/// Quiet getcwd: kernel cwd string without Zig unexpectedErrno on residual EPERM.
/// Owned slice on success; null when the process cwd is unreadable.
pub fn tryGetcwdQuiet(allocator: std.mem.Allocator) error{OutOfMemory}!?[]u8 {
    if (@import("builtin").os.tag == .windows) return null;
    var buf: [std.posix.PATH_MAX]u8 = undefined;
    // libc getcwd returns ?[*]u8 (not sentinel-typed); slice to NUL.
    const rc = std.c.getcwd(&buf, buf.len) orelse return null;
    return try allocator.dupe(u8, std.mem.sliceTo(rc, 0));
}

/// Fallback when realpath fails: keep absolute paths that open as directories.
/// Used under Seatbelt when realpath walks hit EPERM but the workspace is still usable.
/// For "." / empty, try process getcwd (already chdir'd into workspace after attach).
pub fn resolveEffectiveCwdAfterRealpathFail(
    io: std.Io,
    allocator: std.mem.Allocator,
    path: []const u8,
) daemon.DaemonError![]const u8 {
    if (std.fs.path.isAbsolute(path)) {
        // Usability check without following a final symlink (cwd identity for allow-once).
        // Residual: path remains the lexical absolute string when open succeeds — not
        // a realpath-canonical form (realpath already failed for this input).
        var dir = std.Io.Dir.openDirAbsolute(io, path, .{ .follow_symlinks = false }) catch
            return error.InvalidWorkingDirectory;
        dir.close(io);
        return allocator.dupe(u8, path) catch error.OutOfMemory;
    }
    // Relative "." after attach: process cwd is usually the granted workspace.
    // Prefer quiet getcwd over inventing a path from an unproven relative string.
    if (path.len == 0 or std.mem.eql(u8, path, ".")) {
        if (try tryGetcwdQuiet(allocator)) |cwd_abs| {
            errdefer allocator.free(cwd_abs);
            if (!std.fs.path.isAbsolute(cwd_abs)) return error.InvalidWorkingDirectory;
            var dir = std.Io.Dir.openDirAbsolute(io, cwd_abs, .{ .follow_symlinks = false }) catch
                return error.InvalidWorkingDirectory;
            dir.close(io);
            return cwd_abs; // success: errdefer does not run
        }
    }
    // Other relative names: without realpath we cannot mint a stable absolute cwd
    // for allow-once scope. Fail closed rather than inventing an unproven path.
    return error.InvalidWorkingDirectory;
}

const daemonUnavailableReason = daemon.errors.shellUnavailableReason;

test "shell_eval reports a missing command working directory explicitly" {
    try std.testing.expectError(
        error.InvalidWorkingDirectory,
        resolveEffectiveCwd(std.testing.allocator, "/definitely/missing/ryk-working-directory"),
    );
    try std.testing.expectEqualStrings(
        "daemon unavailable: command working directory does not exist",
        daemonUnavailableReason(error.InvalidWorkingDirectory),
    );
}

test "resolveEffectiveCwd prefers realpath when available" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const abs = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(abs);

    const resolved = try resolveEffectiveCwd(std.testing.allocator, abs);
    defer std.testing.allocator.free(resolved);
    // Realpath should succeed and return a usable absolute path (may equal abs).
    try std.testing.expect(std.fs.path.isAbsolute(resolved));
    var dir = try std.Io.Dir.openDirAbsolute(std.testing.io, resolved, .{});
    dir.close(std.testing.io);
}

test "resolveEffectiveCwd absolute survives realpath failure when dir is usable" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const abs = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(abs);

    // Exercise the Seatbelt residual path directly: realpath already failed.
    const resolved = try resolveEffectiveCwdAfterRealpathFail(std.testing.io, std.testing.allocator, abs);
    defer std.testing.allocator.free(resolved);
    try std.testing.expectEqualStrings(abs, resolved);
}

test "resolveEffectiveCwd absolute missing still fails closed after realpath fail" {
    try std.testing.expectError(
        error.InvalidWorkingDirectory,
        resolveEffectiveCwdAfterRealpathFail(
            std.testing.io,
            std.testing.allocator,
            "/definitely/missing/ryk-working-directory-fallback",
        ),
    );
}

test "resolveEffectiveCwd relative fails closed when realpath fails" {
    // Bare relative names cannot be proven absolute without realpath.
    try std.testing.expectError(
        error.InvalidWorkingDirectory,
        resolveEffectiveCwdAfterRealpathFail(std.testing.io, std.testing.allocator, "not-a-proven-absolute-cwd"),
    );
}

test "resolveEffectiveCwd dot falls back to getcwd when realpath fails" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;
    // Realpath already "failed" — "." should still recover via process cwd.
    const resolved = try resolveEffectiveCwdAfterRealpathFail(std.testing.io, std.testing.allocator, ".");
    defer std.testing.allocator.free(resolved);
    try std.testing.expect(std.fs.path.isAbsolute(resolved));
    var dir = try std.Io.Dir.openDirAbsolute(std.testing.io, resolved, .{});
    dir.close(std.testing.io);
}

//! Best-effort clipboard copy and path reveal/open for `ryk scan` TUI.
//!
//! Path only — never secret detail blobs. Fail soft when tools are missing.
//! macOS primary (pbcopy / open -R); Linux best-effort; Windows unavailable.
const std = @import("std");
const builtin = @import("builtin");

pub const Result = enum {
    ok,
    empty,
    failed,
    unavailable,

    pub fn statusLine(self: Result, action: enum { copy, open }) []const u8 {
        return switch (self) {
            .ok => switch (action) {
                .copy => "copied path",
                .open => "revealed path",
            },
            .empty => "no path to use",
            .failed => switch (action) {
                .copy => "copy failed",
                .open => "reveal failed",
            },
            .unavailable => switch (action) {
                .copy => "clipboard unavailable",
                .open => "open unavailable",
            },
        };
    }
};

/// Reject empty / NUL / control-bearing paths before spawning OS tools.
pub fn pathIsSafeForOsAction(path: []const u8) bool {
    if (path.len == 0) return false;
    if (path.len > 4096) return false;
    for (path) |c| {
        if (c == 0) return false;
        // Reject other C0 controls (keep TAB/LF out of clipboard argv surfaces).
        if (c < 0x20) return false;
    }
    return true;
}

/// Copy `path` bytes only to the system clipboard. Never logs the path as a secret.
pub fn copyPath(io: std.Io, path: []const u8) Result {
    if (path.len == 0) return .empty;
    if (!pathIsSafeForOsAction(path)) return .failed;

    return switch (builtin.os.tag) {
        .macos => copyViaStdin(io, path, &.{"pbcopy"}),
        .linux => copyLinux(io, path),
        else => .unavailable,
    };
}

/// Reveal or open `path`. macOS prefers Finder reveal (`open -R`).
pub fn revealOrOpenPath(io: std.Io, path: []const u8) Result {
    if (path.len == 0) return .empty;
    if (!pathIsSafeForOsAction(path)) return .failed;

    // OpenCode refs are not real filesystem paths — fail soft without spawning.
    if (std.mem.startsWith(u8, path, "opencode.") or std.mem.indexOf(u8, path, "#session/") != null) {
        return .failed;
    }

    return switch (builtin.os.tag) {
        .macos => revealMacos(io, path),
        .linux => openLinux(io, path),
        else => .unavailable,
    };
}

fn copyLinux(io: std.Io, path: []const u8) Result {
    const wl = copyViaStdin(io, path, &.{"wl-copy"});
    if (wl == .ok) return .ok;
    const xclip = copyViaStdin(io, path, &.{ "xclip", "-selection", "clipboard" });
    if (xclip == .ok) return .ok;
    // Prefer "unavailable" when tools are missing; "failed" if a tool ran poorly.
    if (wl == .unavailable and xclip == .unavailable) return .unavailable;
    return .failed;
}

fn copyViaStdin(io: std.Io, path: []const u8, argv: []const []const u8) Result {
    var child = std.process.spawn(io, .{
        .argv = argv,
        .stdin = .pipe,
        .stdout = .ignore,
        .stderr = .ignore,
    }) catch return .unavailable;

    var reaped = false;
    defer {
        if (!reaped) {
            if (child.stdin) |*in| {
                in.close(io);
                child.stdin = null;
            }
            // Child.kill is blocking and reaps (idempotent after wait).
            child.kill(io);
        }
    }

    const stdin_file = child.stdin orelse return .failed;
    var write_buf: [512]u8 = undefined;
    var file_writer = stdin_file.writer(io, &write_buf);
    const w = &file_writer.interface;
    w.writeAll(path) catch return .failed;
    w.flush() catch return .failed;
    // Close stdin so pbcopy/wl-copy see EOF and exit.
    stdin_file.close(io);
    child.stdin = null;

    const term = child.wait(io) catch return .failed;
    reaped = true;
    return switch (term) {
        .exited => |code| if (code == 0) .ok else .failed,
        else => .failed,
    };
}

fn revealMacos(io: std.Io, path: []const u8) Result {
    // `--` so paths starting with `-` are never treated as flags.
    return runArgv(io, &.{ "open", "-R", "--", path });
}

fn openLinux(io: std.Io, path: []const u8) Result {
    // Prefer xdg-open on the path; if it fails, try parent directory string.
    const direct = runArgv(io, &.{ "xdg-open", "--", path });
    if (direct == .ok) return .ok;
    if (std.fs.path.dirname(path)) |dir| {
        const parent = runArgv(io, &.{ "xdg-open", "--", dir });
        if (parent == .ok) return .ok;
    }
    if (direct == .unavailable) return .unavailable;
    return .failed;
}

fn runArgv(io: std.Io, argv: []const []const u8) Result {
    // Use process.run so we don't manage pipes; path is argv element (spaces OK).
    // Bound wait so a hung open/xdg-open cannot freeze the TUI forever.
    const allocator = std.heap.smp_allocator;

    const run_result = std.process.run(allocator, io, .{
        .argv = argv,
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(4096),
        .timeout = .{ .duration = .{
            .raw = .fromNanoseconds(8 * std.time.ns_per_s),
            .clock = .awake,
        } },
    }) catch return .unavailable;
    defer {
        allocator.free(run_result.stdout);
        allocator.free(run_result.stderr);
    }
    return switch (run_result.term) {
        .exited => |code| if (code == 0) .ok else .failed,
        else => .failed,
    };
}

// ── Tests ───────────────────────────────────────────────────────────────────

test "pathIsSafeForOsAction rejects empty NUL and controls" {
    try std.testing.expect(!pathIsSafeForOsAction(""));
    try std.testing.expect(!pathIsSafeForOsAction("a\x00b"));
    try std.testing.expect(!pathIsSafeForOsAction("a\nb"));
    try std.testing.expect(pathIsSafeForOsAction("/tmp/foo bar/rollout.jsonl"));
    try std.testing.expect(pathIsSafeForOsAction("/Users/me/.codex/sessions/x.jsonl"));
}

test "copyPath empty is empty not panic" {
    const r = copyPath(std.testing.io, "");
    try std.testing.expectEqual(Result.empty, r);
}

test "revealOrOpenPath empty is empty not panic" {
    const r = revealOrOpenPath(std.testing.io, "");
    try std.testing.expectEqual(Result.empty, r);
}

test "revealOrOpenPath rejects opencode ref without crash" {
    const r = revealOrOpenPath(std.testing.io, "opencode.db#session/abc");
    try std.testing.expect(r == .failed or r == .unavailable);
}

test "Result status lines are user-visible" {
    try std.testing.expectEqualStrings("copied path", Result.ok.statusLine(.copy));
    try std.testing.expectEqualStrings("copy failed", Result.failed.statusLine(.copy));
    try std.testing.expectEqualStrings("reveal failed", Result.failed.statusLine(.open));
    try std.testing.expectEqualStrings("no path to use", Result.empty.statusLine(.copy));
}

test "copyViaStdin handles path with spaces (macOS pbcopy when present)" {
    if (builtin.os.tag != .macos) return;
    const path = "/tmp/ryk scan path with spaces/rollout-demo.jsonl";
    const r = copyPath(std.testing.io, path);
    // pbcopy is present on macOS CI/dev machines almost always.
    try std.testing.expect(r == .ok or r == .failed or r == .unavailable);
    if (r == .ok) {
        // Round-trip via pbpaste when available.
        const paste = std.process.run(std.testing.allocator, std.testing.io, .{
            .argv = &.{"pbpaste"},
            .stdout_limit = .limited(8192),
            .stderr_limit = .limited(1024),
        }) catch return;
        defer {
            std.testing.allocator.free(paste.stdout);
            std.testing.allocator.free(paste.stderr);
        }
        if (paste.term == .exited and paste.term.exited == 0) {
            try std.testing.expectEqualStrings(path, paste.stdout);
        }
    }
}

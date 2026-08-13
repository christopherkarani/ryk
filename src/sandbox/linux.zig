const std = @import("std");
const builtin = @import("builtin");

const platform = @import("ryk_core").platform;
const backend = @import("backend.zig");
/// Single source of truth for Landlock ABI availability (M-16). Doctor/detect
/// must not re-implement landlock_create_ruleset VERSION probe independently of attach.
const landlock_mod = @import("landlock.zig");

pub const implemented = true;

const CLONE_NEWNS: usize = 0x00020000;
const CLONE_NEWUSER: usize = 0x10000000;

pub fn detect() backend.ReportSet {
    var reports = backend.baseReports(.linux);
    backend.setReport(&reports, .process_supervision, .active, "Linux process-group supervision and best-effort descendant cleanup are enabled");

    const user_namespace = detectUserNamespace();
    backend.setReport(&reports, .user_namespaces, user_namespace.level, user_namespace.note);

    const mount_namespace = detectMountNamespace(user_namespace.level);
    backend.setReport(&reports, .mount_namespaces, mount_namespace.level, mount_namespace.note);

    const seccomp = detectSeccomp();
    backend.setReport(&reports, .seccomp, seccomp.level, seccomp.note);

    const landlock = detectLandlock();
    backend.setReport(&reports, .landlock, landlock.level, landlock.note);

    const cgroups = detectCgroups();
    backend.setReport(&reports, .cgroups, cgroups.level, cgroups.note);

    // Strong sandbox: Landlock capability probe only. Session active only after child apply-before-exec attach.
    // Never claim "not wired" — production apply path is live; detect is not a live session claim (S-GLO-01).
    const strong_level: backend.Level = switch (landlock.level) {
        .partial, .active, .limited => .partial,
        .failed => .failed,
        .unavailable, .unsupported, .observe_only, .wrapper_only => .unavailable,
    };
    const strong_note: []const u8 = switch (landlock.level) {
        .partial, .active, .limited => "OS filesystem sandbox API present; session active only after apply-before-exec child attach and profile hash",
        .failed => "OS filesystem sandbox unavailable: Landlock probing failed; capability probes are not a live session claim",
        .unavailable, .unsupported, .observe_only, .wrapper_only => "OS filesystem sandbox unavailable; capability probes are not a live session claim",
    };
    backend.setReport(&reports, .strong_sandbox, strong_level, strong_note);

    return .{
        .os = .linux,
        .backend_name = "linux",
        .landlock_abi = landlock.abi_version,
        .fallback_level = .partial,
        .fallback_note = "Linux backend is using honest partial mode with wrapper controls plus process supervision",
        .reports = reports,
    };
}

pub fn killProcessGroup(pgid: i32) void {
    if (builtin.os.tag != .linux) return;
    if (pgid <= 0) return;
    std.posix.kill(-pgid, std.os.linux.SIG.TERM) catch {};
    std.Thread.sleep(50 * std.time.ns_per_ms);
    std.posix.kill(-pgid, std.os.linux.SIG.KILL) catch {};
}

const Probe = struct {
    level: backend.Level,
    note: []const u8,
    abi_version: ?u32 = null,
};

fn detectUserNamespace() Probe {
    if (builtin.os.tag != .linux) return .{ .level = .unsupported, .note = "not running on Linux" };
    if (!pathExists("/proc/self/ns/user")) {
        return .{ .level = .unavailable, .note = "kernel user namespace handle is absent" };
    }
    if (readProcToggle("/proc/sys/kernel/unprivileged_userns_clone")) |enabled| {
        if (!enabled) return .{ .level = .unavailable, .note = "unprivileged user namespaces are disabled by kernel policy" };
    }
    return .{ .level = .partial, .note = "kernel support detected; rootless namespace activation is not enabled by default in this backend" };
}

fn detectMountNamespace(user_namespace_level: backend.Level) Probe {
    if (builtin.os.tag != .linux) return .{ .level = .unsupported, .note = "not running on Linux" };
    if (!pathExists("/proc/self/ns/mnt")) {
        return .{ .level = .unavailable, .note = "kernel mount namespace handle is absent" };
    }
    if (!user_namespace_level.isUsable()) {
        return .{ .level = .unavailable, .note = "mount namespaces exist, but rootless setup depends on unavailable user namespaces" };
    }
    return .{ .level = .partial, .note = "kernel support detected; no bind-mount/chroot filesystem view is installed in this phase" };
}

fn detectSeccomp() Probe {
    if (builtin.os.tag != .linux) return .{ .level = .unsupported, .note = "not running on Linux" };
    const linux = std.os.linux;
    var action: u32 = linux.SECCOMP.RET.ALLOW;
    const rc = linux.seccomp(linux.SECCOMP.GET_ACTION_AVAIL, 0, &action);
    return switch (std.posix.errno(rc)) {
        .SUCCESS => .{ .level = .partial, .note = "seccomp-bpf API is available; no restrictive filter is installed by this backend" },
        .NOSYS => .{ .level = .unavailable, .note = "seccomp syscall is unavailable" },
        .OPNOTSUPP => .{ .level = .unavailable, .note = "seccomp action probing is unsupported by this kernel" },
        .ACCES, .PERM => .{ .level = .unavailable, .note = "seccomp probing denied by the current runtime" },
        else => .{ .level = .failed, .note = "seccomp probing failed" },
    };
}

fn detectLandlock() Probe {
    if (builtin.os.tag != .linux) return .{ .level = .unsupported, .note = "not running on Linux" };
    // Share probe with attach (`landlock_mod.isAbiAvailable` / `probeAbi`) so doctor
    // and prepare cannot drift on ABI floor or flag constants.
    const info = landlock_mod.probeAbi() orelse {
        return .{
            .level = .unavailable,
            .note = "Landlock syscalls are unavailable or ABI probing failed",
        };
    };
    if (info.version < landlock_mod.MIN_ABI) {
        return .{
            .level = .unavailable,
            .note = "Landlock ABI 1/2 lacks truncation mediation; ABI 3+ is required for write integrity",
            .abi_version = info.version,
        };
    }
    return .{
        .level = .partial,
        .note = "Landlock ABI 3+ is available; session active only after child apply-before-exec",
        .abi_version = info.version,
    };
}

fn detectCgroups() Probe {
    if (builtin.os.tag != .linux) return .{ .level = .unsupported, .note = "not running on Linux" };
    if (!pathExists("/sys/fs/cgroup/cgroup.controllers")) {
        return .{ .level = .unavailable, .note = "cgroup v2 controllers file is absent" };
    }
    return .{ .level = .partial, .note = "cgroup v2 is visible; ryk does not create or manage a cleanup cgroup in this phase" };
}

fn pathExists(path: []const u8) bool {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    std.Io.Dir.accessAbsolute(io, path, .{}) catch return false;
    return true;
}

fn readProcToggle(path: []const u8) ?bool {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    var buf: [8]u8 = undefined;
    const file = std.Io.Dir.openFileAbsolute(io, path, .{}) catch return null;
    defer file.close(io);
    const len = std.Io.File.readStreaming(file, io, &.{buf[0..]}) catch return null;
    const trimmed = std.mem.trim(u8, buf[0..len], " \t\r\n");
    if (std.mem.eql(u8, trimmed, "1")) return true;
    if (std.mem.eql(u8, trimmed, "0")) return false;
    return null;
}

test "Linux capability detector is target-gated and honest" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const report = detect();
    try std.testing.expectEqual(platform.Os.linux, report.os);
    try std.testing.expectEqualStrings("linux", report.backend_name);
    try std.testing.expectEqual(backend.Level.active, report.get(.process_supervision).level);
    try std.testing.expect(report.get(.network_enforce).level != .active);
    // strong_sandbox never active from detect (S-GLO-01); partial only when Landlock API present.
    try std.testing.expect(report.get(.strong_sandbox).level != .active);
    try std.testing.expect(!report.featureAvailable(.strong_sandbox));
    try std.testing.expect(std.mem.indexOf(u8, report.get(.strong_sandbox).note, "not wired") == null);
    switch (report.get(.landlock).level) {
        .partial, .active, .limited => try std.testing.expectEqual(backend.Level.partial, report.get(.strong_sandbox).level),
        .failed => try std.testing.expectEqual(backend.Level.failed, report.get(.strong_sandbox).level),
        else => try std.testing.expectEqual(backend.Level.unavailable, report.get(.strong_sandbox).level),
    }
}

// M-16: doctor detectLandlock must track landlock.isAbiAvailable (single probe).
test "detectLandlock tracks landlock.isAbiAvailable" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const report = detect();
    const ll = report.get(.landlock);
    if (landlock_mod.isAbiAvailable()) {
        try std.testing.expect(ll.level == .partial or ll.level == .active or ll.level == .limited);
        try std.testing.expect(report.get(.strong_sandbox).level == .partial);
    } else {
        try std.testing.expect(ll.level == .unavailable or ll.level == .failed);
        try std.testing.expect(report.get(.strong_sandbox).level != .partial);
        try std.testing.expect(report.get(.strong_sandbox).level != .active);
    }
}

// No scaffold prepare path — production attach is apply_posix only.
// Process-group leadership for agent spawn is proven in apply_posix tests.
test "Linux process group spawn runs simple command" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var child = try std.process.spawn(std.testing.io, .{
        .argv = &[_][]const u8{"true"},
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
        .pgid = 0,
    });
    const term = try child.wait(std.testing.io);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

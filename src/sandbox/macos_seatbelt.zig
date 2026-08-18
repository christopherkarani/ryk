//! macOS custom Seatbelt apply (deprecated sandbox_init), version-gated.
//!
//! Advertised matrix: macOS product majors 14 through 26 inclusive.
//! Proven locally on macOS 26 (sandbox_init apply + FS deny) when the unit
//! tests in this file pass on the host. Outside the matrix → unavailable.
//! Nested re-apply is not supported: sandbox_init fails if the process is
//! already sandboxed; children inherit.
//!
//! `applyInChild` must run only after fork / before exec (never on the ryk
//! parent). Parent-side code uses `evaluateSupport` + profile render only.
//!
//! ## Multi-thread / fork residual
//!
//! `sandbox_init` is **not** async-signal-safe and is not defined for use in a
//! multi-threaded process after fork. ryk's parent may already have threads
//! (e.g. proxy/runtime) when `forkApplySeatbeltAndExec` runs.
//!
//! **Mitigations (production path):**
//! 1. SBPL is fully pre-rendered in the parent (`prepareForChildApply` /
//!    `renderSbpl`) — the child never compiles profiles or walks the FS for
//!    policy.
//! 2. Child critical section is intentionally short: stdio redirect →
//!    `dlsym` + `sandbox_init` → chdir/preflight → FD scrub (keep status_w) →
//!    status handshake → close status_w → `execve`. No heap enumeration, no
//!    additional thread starts between fork and exec.
//! 3. Parent retains the NUL-terminated SBPL buffer until exec (no free race).
//!
//! **Residual risk (accepted, documented):** `sandbox_init` itself may still
//! touch liberally-locked or malloc-backed libsystem state under a multi-
//! threaded parent. We do not pause/join proxy threads around fork (would
//! couple sandbox to cli/run lifecycle). Prefer a short child path + honest
//! residual over a large proxy rewrite. Nested re-apply remains unsupported.
//!
//! **Stress note:** live unit tests fork-apply-exec under the normal test runner
//! (which may already be multi-threaded). A dedicated multi-thread parent stress
//! canary lives in `test "seatbelt apply survives multi-thread parent stress"`.
//! Do not claim async-signal-safe attach until a single-thread spawner exists.

const std = @import("std");
const builtin = @import("builtin");
const posture = @import("posture.zig");
const profile = @import("profile.zig");
const macos_profile = @import("macos_profile.zig");

/// Product major versions that may attempt custom Seatbelt attach.
/// Inclusive range: Sonoma (14) through the current proven host major (26).
pub const matrix_major_min: u32 = 14;
pub const matrix_major_max: u32 = 26;

pub const SupportStatus = enum {
    /// Running macOS major is in the advertised matrix and sandbox_init resolves.
    supported,
    /// Not building/running on macOS.
    not_macos,
    /// macOS major outside 14–26 (e.g. 13, 27+).
    version_unsupported,
    /// sandbox_init could not be resolved via dlsym.
    symbol_unavailable,

    pub fn reasonCode(self: SupportStatus) []const u8 {
        return switch (self) {
            .supported => "seatbelt_supported",
            .not_macos => "not_macos",
            .version_unsupported => "macos_version_unsupported",
            .symbol_unavailable => "sandbox_init_unavailable",
        };
    }

    pub fn isSupported(self: SupportStatus) bool {
        return self == .supported;
    }
};

pub const MacOsVersion = struct {
    major: u32,
    minor: u32,
};

/// True when major is in the Seatbelt matrix (14 through 26 inclusive).
pub fn isMatrixMajor(major: u32) bool {
    return major >= matrix_major_min and major <= matrix_major_max;
}

/// Parse `kern.osproductversion` / `sw_vers` style strings (`14.5`, `15.0`, `26.0`).
pub fn parseProductVersion(text: []const u8) !MacOsVersion {
    const trimmed = std.mem.trim(u8, text, " \t\r\n");
    if (trimmed.len == 0) return error.InvalidVersion;
    var it = std.mem.splitScalar(u8, trimmed, '.');
    const major_s = it.next() orelse return error.InvalidVersion;
    const minor_s = it.next() orelse "0";
    const major = std.fmt.parseInt(u32, major_s, 10) catch return error.InvalidVersion;
    const minor = std.fmt.parseInt(u32, minor_s, 10) catch return error.InvalidVersion;
    return .{ .major = major, .minor = minor };
}

/// Read running product version via sysctl. macOS only.
pub fn detectProductVersion() !MacOsVersion {
    if (builtin.os.tag != .macos) return error.NotMacOs;
    var buf: [64]u8 = undefined;
    var len: usize = buf.len;
    const rc = std.c.sysctlbyname("kern.osproductversion", &buf, &len, null, 0);
    if (rc != 0) return error.SysctlFailed;
    // sysctl may include a trailing NUL in len.
    var slice = buf[0..len];
    if (slice.len > 0 and slice[slice.len - 1] == 0) slice = slice[0 .. slice.len - 1];
    return parseProductVersion(slice);
}

const SandboxInitFn = *const fn (profile: [*:0]const u8, flags: u64, errorbuf: *?[*:0]u8) callconv(.c) c_int;
const SandboxFreeErrorFn = *const fn (errorbuf: ?[*:0]u8) callconv(.c) void;

/// Darwin RTLD_DEFAULT ((void *)-2): search the default process namespace.
/// `dlsym(null, …)` returns null on macOS; RTLD_DEFAULT is required.
fn rtldDefault() ?*anyopaque {
    return @ptrFromInt(@as(usize, @bitCast(@as(isize, -2))));
}

fn resolveSandboxInit() ?SandboxInitFn {
    if (builtin.os.tag != .macos) return null;
    const sym = std.c.dlsym(rtldDefault(), "sandbox_init") orelse return null;
    return @ptrCast(@alignCast(sym));
}

fn resolveSandboxFreeError() ?SandboxFreeErrorFn {
    if (builtin.os.tag != .macos) return null;
    const sym = std.c.dlsym(rtldDefault(), "sandbox_free_error") orelse return null;
    return @ptrCast(@alignCast(sym));
}

/// Whether sandbox_init is resolvable (dlsym). Pure capability; not a session claim.
pub fn sandboxInitAvailable() bool {
    return resolveSandboxInit() != null;
}

/// Parent-side support evaluation (no apply).
pub fn evaluateSupport() SupportStatus {
    if (builtin.os.tag != .macos) return .not_macos;
    const ver = detectProductVersion() catch return .version_unsupported;
    if (!isMatrixMajor(ver.major)) return .version_unsupported;
    if (!sandboxInitAvailable()) return .symbol_unavailable;
    return .supported;
}

/// Injected evaluation for tests (no sysctl).
pub fn evaluateSupportWith(major: u32, symbol_ok: bool) SupportStatus {
    if (builtin.os.tag != .macos) return .not_macos;
    if (!isMatrixMajor(major)) return .version_unsupported;
    if (!symbol_ok) return .symbol_unavailable;
    return .supported;
}

pub const ApplyInChildError = error{
    NotMacOs,
    SymbolUnavailable,
    ApplyFailed,
};

/// Apply a custom SBPL profile to the **current** process via deprecated sandbox_init.
///
/// Must only be called in the post-fork child before exec (or in isolation tests).
/// Applying in the ryk parent would confine the CLI itself.
///
/// Nested apply is not supported: if already sandboxed, returns ApplyFailed.
/// Inheritance is the only composition model for descendants.
///
/// Child work is intentionally minimal: resolve symbols +
/// sandbox_init only — SBPL must already be parent-rendered. See module docs.
pub fn applyInChild(sbpl_z: [*:0]const u8) ApplyInChildError!void {
    if (builtin.os.tag != .macos) return error.NotMacOs;
    const init_fn = resolveSandboxInit() orelse return error.SymbolUnavailable;
    const free_fn = resolveSandboxFreeError();

    var err_ptr: ?[*:0]u8 = null;
    // flags=0: custom SBPL string (private usage of the deprecated API).
    const rc = init_fn(sbpl_z, 0, &err_ptr);
    defer if (err_ptr) |e| {
        if (free_fn) |f| f(e);
    };
    if (rc != 0) return error.ApplyFailed;
}

/// Platform outcome used by apply.zig (parent path).
pub const ParentApplyOutcome = struct {
    status: enum { prepared, unavailable, failed },
    mechanism: posture.BackendMechanism = .none,
    reason_code: []const u8,
    /// Owned NUL-terminated SBPL when prepared (for child-side apply). Caller frees.
    sbpl_z: ?[:0]u8 = null,
};

pub const PrepareOptions = struct {
    network_route_forcing: ?macos_profile.NetworkRouteForcing = null,
    profile_grade: macos_profile.SeatbeltProfileGrade = macos_profile.SeatbeltProfileGrade.default_grade,
    write_deny_literals: []const []const u8 = &.{},
};

/// Parent-side Seatbelt prepare: version gate, symbol check, SBPL render.
/// Does **not** call sandbox_init (that is child-only). Never reports attach.
///
/// On success (`prepared`), the caller must apply `sbpl_z` in the child before
/// Map protect-on hardlink scan failures to distinct prepare reason codes.
/// Walk capacity (`ScanCapacity`) vs post-filter denylist capacity
/// (`HardlinkAliasDenyCapacity`) must not collapse into the generic failed bucket.
pub fn hardlinkScanFailureReason(err: anyerror) []const u8 {
    return switch (err) {
        error.OutOfMemory => "seatbelt_profile_oom",
        error.ScanCapacity => "seatbelt_secret_hardlink_scan_capacity",
        error.ScanDepthExceeded => "seatbelt_secret_hardlink_scan_depth",
        error.ScanOpenFailed => "seatbelt_secret_hardlink_scan_open",
        error.HardlinkAliasDenyCapacity => "seatbelt_hardlink_alias_deny_capacity",
        else => "seatbelt_secret_hardlink_scan_failed",
    };
}

/// exec and only then claim session active. Until that child apply succeeds,
/// production posture remains unavailable/failed.
pub fn prepareForChildApply(
    allocator: std.mem.Allocator,
    compiled: *const profile.CompiledProfile,
) ParentApplyOutcome {
    return prepareForChildApplyWithOptions(allocator, compiled, evaluateSupport(), .{});
}

/// Testable prepare with injected support status.
pub fn prepareForChildApplyWith(
    allocator: std.mem.Allocator,
    compiled: *const profile.CompiledProfile,
    support: SupportStatus,
) ParentApplyOutcome {
    return prepareForChildApplyWithOptions(allocator, compiled, support, .{});
}

pub fn prepareForChildApplyWithOptions(
    allocator: std.mem.Allocator,
    compiled: *const profile.CompiledProfile,
    support: SupportStatus,
    options: PrepareOptions,
) ParentApplyOutcome {
    if (!support.isSupported()) {
        return .{
            .status = .unavailable,
            .mechanism = .none,
            .reason_code = support.reasonCode(),
        };
    }

    // Protect-on: discover multi-nlink non-secret basenames under the workspace
    // so path-regex deny cannot be bypassed via a non-.env hardlink alias (Linux
    // FUSE taints multi-nlink; Seatbelt needs explicit last-match path denies).
    // `**/.git/objects` and `**/.ryk/sessions` are not walked (shared git
    // objects and session evidence are not agent-facing aliases). `.git` /
    // `.ryk` themselves are still walked so planted `notes.txt` aliases deny.
    // Missing workspace yields an empty list (regex still applies). Open /
    // capacity / depth failures fail closed with distinct reason codes.
    // OOM uses seatbelt_profile_oom (hard OutOfMemory at apply).
    //
    // Accepted residual (single-writer threat model): the scan is prepare-time
    // only. Concurrent post-prepare hardlinks or agent-created link(.env→alias)
    // after sandbox_init are not rescanned; Seatbelt has no runtime inode taint.
    // Pre-planted multi-nlink aliases (including outside secret-form inodes
    // linked under non-secret names) are covered by process canaries.
    var hardlink_aliases: ?[]const []const u8 = null;
    defer if (hardlink_aliases) |paths| macos_profile.freeHardlinkAliasPaths(allocator, paths);
    if (compiled.protect_workspace_secrets) {
        var threaded: std.Io.Threaded = .init_single_threaded;
        const io = threaded.io();
        hardlink_aliases = macos_profile.collectSecretHardlinkAliasPaths(
            allocator,
            io,
            compiled.workspace_root,
        ) catch |err| {
            return .{
                .status = .failed,
                .mechanism = .none,
                .reason_code = hardlinkScanFailureReason(err),
            };
        };
    }

    // OOM must use seatbelt_profile_oom so apply maps to hard OutOfMemory (not soft failed).
    const sbpl = macos_profile.renderSbplWithOptions(allocator, compiled, .{
        .network_route_forcing = options.network_route_forcing,
        .profile_grade = options.profile_grade,
        .hardlink_alias_denies = hardlink_aliases orelse &.{},
        .write_deny_literals = options.write_deny_literals,
    }) catch |err| {
        return .{
            .status = .failed,
            .mechanism = .none,
            .reason_code = if (err == error.OutOfMemory)
                "seatbelt_profile_oom"
            else
                "seatbelt_profile_render_failed",
        };
    };
    defer allocator.free(sbpl);

    const sbpl_z = allocator.dupeZ(u8, sbpl) catch {
        return .{
            .status = .failed,
            .mechanism = .none,
            .reason_code = "seatbelt_profile_oom",
        };
    };

    return .{
        .status = .prepared,
        .mechanism = .seatbelt,
        .reason_code = "seatbelt_prepared",
        .sbpl_z = sbpl_z,
    };
}

test "matrix accepts macos majors 14 through 26 inclusive" {
    try std.testing.expect(isMatrixMajor(14));
    try std.testing.expect(isMatrixMajor(15));
    try std.testing.expect(isMatrixMajor(16));
    try std.testing.expect(isMatrixMajor(26));
    try std.testing.expect(!isMatrixMajor(13));
    try std.testing.expect(!isMatrixMajor(27));
    try std.testing.expect(!isMatrixMajor(0));
    try std.testing.expectEqual(@as(u32, 14), matrix_major_min);
    try std.testing.expectEqual(@as(u32, 26), matrix_major_max);
}

test "parseProductVersion reads major.minor" {
    const v = try parseProductVersion("15.4");
    try std.testing.expectEqual(@as(u32, 15), v.major);
    try std.testing.expectEqual(@as(u32, 4), v.minor);
    const v2 = try parseProductVersion("14.0\n");
    try std.testing.expectEqual(@as(u32, 14), v2.major);
    const v3 = try parseProductVersion("26.0");
    try std.testing.expectEqual(@as(u32, 26), v3.major);
    try std.testing.expectError(error.InvalidVersion, parseProductVersion(""));
    try std.testing.expectError(error.InvalidVersion, parseProductVersion("abc"));
}

test "evaluateSupportWith encodes version gate" {
    if (builtin.os.tag != .macos) {
        try std.testing.expectEqual(SupportStatus.not_macos, evaluateSupportWith(14, true));
        return;
    }
    try std.testing.expectEqual(SupportStatus.supported, evaluateSupportWith(14, true));
    try std.testing.expectEqual(SupportStatus.supported, evaluateSupportWith(15, true));
    try std.testing.expectEqual(SupportStatus.supported, evaluateSupportWith(26, true));
    try std.testing.expectEqual(SupportStatus.version_unsupported, evaluateSupportWith(13, true));
    try std.testing.expectEqual(SupportStatus.version_unsupported, evaluateSupportWith(27, true));
    try std.testing.expectEqual(SupportStatus.symbol_unavailable, evaluateSupportWith(14, false));
    try std.testing.expectEqualStrings("macos_version_unsupported", SupportStatus.version_unsupported.reasonCode());
}

test "evaluateSupport on this host matches matrix freeze" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    const status = evaluateSupport();
    const ver = try detectProductVersion();
    if (isMatrixMajor(ver.major) and sandboxInitAvailable()) {
        try std.testing.expectEqual(SupportStatus.supported, status);
    } else if (!isMatrixMajor(ver.major)) {
        try std.testing.expectEqual(SupportStatus.version_unsupported, status);
    }
}

test "sandbox_init is resolvable on macOS via dlsym" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    try std.testing.expect(sandboxInitAvailable());
}

test "prepareForChildApply unavailable outside matrix" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = "/tmp/ryk-seatbelt-ws",
        .system_ro_prefixes = &[_][]const u8{"/usr"},
    });
    defer compiled.deinit();

    const out = prepareForChildApplyWith(allocator, &compiled, .version_unsupported);
    try std.testing.expectEqual(.unavailable, out.status);
    try std.testing.expectEqual(posture.BackendMechanism.none, out.mechanism);
    try std.testing.expectEqualStrings("macos_version_unsupported", out.reason_code);
    try std.testing.expect(out.sbpl_z == null);
}

test "prepareForChildApply yields SBPL when supported" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = "/tmp/ryk-seatbelt-ws",
        .system_ro_prefixes = &[_][]const u8{ "/usr", "/bin" },
    });
    defer compiled.deinit();

    const out = prepareForChildApplyWith(allocator, &compiled, .supported);
    defer if (out.sbpl_z) |p| allocator.free(p);
    try std.testing.expectEqual(.prepared, out.status);
    try std.testing.expectEqual(posture.BackendMechanism.seatbelt, out.mechanism);
    try std.testing.expect(out.sbpl_z != null);
    try std.testing.expect(std.mem.indexOf(u8, out.sbpl_z.?, "(deny default)") != null);
}

test "applyInChild succeeds for minimal profile in forked child" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;

    // Fork so the test process itself is not permanently sandboxed.
    const pid = std.c.fork();
    if (pid < 0) return error.SkipZigTest;
    if (pid == 0) {
        const sbpl =
            \\(version 1)
            \\(deny default)
            \\(allow process*)
            \\(allow signal)
            \\(allow sysctl-read)
            \\(allow mach-lookup)
            \\(allow file-read-metadata)
            \\(allow file-read* (literal "/"))
            \\(allow file-read* (subpath "/usr"))
            \\(allow file-read* (subpath "/bin"))
            \\(allow file-read* (subpath "/System"))
            \\(allow file-read* (subpath "/Library"))
            \\(allow file-read* (subpath "/dev"))
            \\(allow file-read* (subpath "/private/var/db/dyld"))
            \\(allow file-ioctl (subpath "/dev"))
            \\
        ;
        applyInChild(sbpl) catch std.c._exit(2);
        // Nested composition is not a product feature (inheritance only).
        // Some OS versions return an error on re-apply; others ignore with rc=0.
        // Either way ryk must not claim a second attach succeeded.
        applyInChild(sbpl) catch {};
        std.c._exit(0);
    }
    var status: c_int = 0;
    _ = std.c.waitpid(pid, &status, 0);
    // WIFEXITED: low 7 bits 0; exit status in bits 8..15
    const exited = (status & 0x7f) == 0;
    try std.testing.expect(exited);
    const exit_code: u8 = @intCast((status >> 8) & 0xff);
    try std.testing.expectEqual(@as(u8, 0), exit_code);
}

test "default support reason codes never claim nested apply" {
    // Inheritance-only composition is a documentation/API contract.
    try std.testing.expectEqualStrings("macos_version_unsupported", SupportStatus.version_unsupported.reasonCode());
    try std.testing.expectEqualStrings("sandbox_init_unavailable", SupportStatus.symbol_unavailable.reasonCode());
}

// R2-1 / M-28: pure prepare path — Data-form realpath workspace emits Users-form SBPL.
// Seatbelt subpath filters match /Users/…; Data deny still blocks Data-form sibling opens.
// Always runs (no sandbox_init); complements macos_profile SBPL unit tests.
test "prepare SBPL emits Users-form for Data-volume workspace (M-28 / R2-1)" {
    const allocator = std.testing.allocator;
    const ws = "/System/Volumes/Data/Users/dev/projects/app";
    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = ws,
        .system_ro_prefixes = &[_][]const u8{ "/usr", "/bin" },
        .include_tmp = false,
    });
    defer compiled.deinit();

    try std.testing.expect(compiled.isGrantedReadable(ws));
    try std.testing.expect(!compiled.isGrantedReadable("/System/Volumes/Data/Users/dev/.ssh/id_rsa"));
    try std.testing.expect(!compiled.isGrantedReadable("/System/Volumes/Data/Users/other/secret"));

    const prepared = prepareForChildApplyWith(allocator, &compiled, .supported);
    defer if (prepared.sbpl_z) |p| allocator.free(p);
    try std.testing.expectEqual(.prepared, prepared.status);
    const sbpl = prepared.sbpl_z.?;

    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(deny file-read* (subpath \"/System/Volumes/Data\"))") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read* (subpath \"/Users/dev/projects/app\"))") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(subpath \"/System/Volumes/Data/Users/dev/projects/app\")") == null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(subpath \"/System/Volumes/Data/Users/dev/.ssh\")") == null);
}

test "seatbelt apply survives multi-thread parent stress" {
    // Phase 4 residual canary: parent starts worker threads (malloc pressure), then
    // fork-apply-exec. Documents multi-thread residual without claiming async-signal
    // safety. Flakes here mean proxy-thread pause / single-thread spawner should land.
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    if (!sandboxInitAvailable()) return error.SkipZigTest;
    const ver = try detectProductVersion();
    if (!isMatrixMajor(ver.major)) return error.SkipZigTest;

    const Worker = struct {
        fn run() void {
            var i: usize = 0;
            while (i < 2000) : (i += 1) {
                const p = std.heap.c_allocator.alloc(u8, 64) catch continue;
                @memset(p, @truncate(i));
                std.heap.c_allocator.free(p);
            }
        }
    };
    var threads: [4]std.Thread = undefined;
    for (&threads) |*t| {
        t.* = try std.Thread.spawn(.{}, Worker.run, .{});
    }
    defer for (&threads) |*t| t.join();

    const sbpl =
        \\(version 1)
        \\(deny default)
        \\(allow process-fork)
        \\(allow process-exec)
        \\(allow process-info*)
        \\(allow signal)
        \\(allow sysctl-read)
        \\(allow mach-lookup)
        \\(allow network*)
        \\(allow file-read-metadata)
        \\(allow file-read*)
        \\(allow file-write* (literal "/dev/null"))
        \\(allow file-write* (literal "/dev/urandom"))
        \\(allow file-ioctl (subpath "/dev"))
    ;
    var round: usize = 0;
    while (round < 8) : (round += 1) {
        const pid = std.c.fork();
        if (pid < 0) return error.SkipZigTest;
        if (pid == 0) {
            applyInChild(sbpl) catch std.c._exit(2);
            std.c._exit(0);
        }
        // EINTR-safe reap: bare waitpid under multi-thread stress can return -1 with
        // zero-init status and false-green as exit 0 while the child is unreaped.
        var status: c_int = 0;
        while (true) {
            const rc = std.c.waitpid(pid, &status, 0);
            if (rc >= 0) break;
            if (std.c.errno(rc) == .INTR) continue;
            return error.WaitpidFailed;
        }
        const exited = (status & 0x7f) == 0;
        try std.testing.expect(exited);
        const exit_code: u8 = @intCast((status >> 8) & 0xff);
        try std.testing.expectEqual(@as(u8, 0), exit_code);
    }
}

// Real-FS deny / canary integration tests live in macos_seatbelt_deny_tests.zig.
test {
    _ = @import("macos_seatbelt_deny_tests.zig");
}

test "prepare hardlink scan OOM maps to seatbelt_profile_oom" {
    // M-3: OutOfMemory during protect-on hardlink scan must not soft-fail as
    // seatbelt_secret_hardlink_scan_failed — apply maps seatbelt_profile_oom hard.
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    const backing = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = ".env", .data = "secret" });
    const root = try tmp.dir.realPathFileAlloc(io, ".", backing);
    defer backing.free(root);

    var compiled = try profile.compileProfile(backing, .{
        .workspace_root = root,
        .include_tmp = false,
        .protect_workspace_secrets = true,
    });
    defer compiled.deinit();

    var failing = std.testing.FailingAllocator.init(backing, .{ .fail_index = 0 });
    const out = prepareForChildApplyWith(failing.allocator(), &compiled, .supported);
    defer if (out.sbpl_z) |p| backing.free(p);
    try std.testing.expectEqual(.failed, out.status);
    try std.testing.expectEqual(posture.BackendMechanism.none, out.mechanism);
    try std.testing.expectEqualStrings("seatbelt_profile_oom", out.reason_code);
    try std.testing.expect(out.sbpl_z == null);
    try std.testing.expect(failing.has_induced_failure);
}

test "hardlinkScanFailureReason maps ScanCapacity and alias-deny capacity distinctly" {
    // m17: capacity paths stay distinct from generic scan_failed.
    try std.testing.expectEqualStrings(
        "seatbelt_secret_hardlink_scan_capacity",
        hardlinkScanFailureReason(error.ScanCapacity),
    );
    try std.testing.expectEqualStrings(
        "seatbelt_hardlink_alias_deny_capacity",
        hardlinkScanFailureReason(error.HardlinkAliasDenyCapacity),
    );
    try std.testing.expectEqualStrings(
        "seatbelt_secret_hardlink_scan_depth",
        hardlinkScanFailureReason(error.ScanDepthExceeded),
    );
    try std.testing.expectEqualStrings(
        "seatbelt_secret_hardlink_scan_open",
        hardlinkScanFailureReason(error.ScanOpenFailed),
    );
    try std.testing.expectEqualStrings(
        "seatbelt_profile_oom",
        hardlinkScanFailureReason(error.OutOfMemory),
    );
    try std.testing.expectEqualStrings(
        "seatbelt_secret_hardlink_scan_failed",
        hardlinkScanFailureReason(error.Unexpected),
    );
}

test "prepare hardlink scan open failure maps to seatbelt_secret_hardlink_scan_open" {
    // M-1: mode-000 nested dir with secret + hardlink alias → scan fail closed,
    // never prepared with incomplete alias denies.
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "d");
    try tmp.dir.writeFile(io, .{ .sub_path = "d/.env", .data = "secret-body" });
    tmp.dir.hardLink("d/.env", tmp.dir, "notes.txt", io, .{}) catch return error.SkipZigTest;

    const root = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(root);
    const nested = try std.fs.path.join(allocator, &.{ root, "d" });
    defer allocator.free(nested);
    const nested_z = try allocator.dupeZ(u8, nested);
    defer allocator.free(nested_z);

    if (std.c.chmod(nested_z.ptr, 0) != 0) return error.SkipZigTest;
    defer _ = std.c.chmod(nested_z.ptr, 0o755);

    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = root,
        .include_tmp = false,
        .protect_workspace_secrets = true,
    });
    defer compiled.deinit();

    const out = prepareForChildApplyWith(allocator, &compiled, .supported);
    defer if (out.sbpl_z) |p| allocator.free(p);
    try std.testing.expectEqual(.failed, out.status);
    try std.testing.expectEqualStrings("seatbelt_secret_hardlink_scan_open", out.reason_code);
    try std.testing.expect(out.sbpl_z == null);
}

test "prepare protect-on succeeds when .git objects are shared hardlinks" {
    // Worktree / local-clone object stores must not fail empty-backpack prepare.
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var outside = std.testing.tmpDir(.{});
    defer outside.cleanup();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try outside.dir.writeFile(io, .{ .sub_path = "blob", .data = "git-object-body" });
    try tmp.dir.createDirPath(io, ".git/objects/ab");
    outside.dir.hardLink("blob", tmp.dir, ".git/objects/ab/cdef", io, .{}) catch
        return error.SkipZigTest;
    try tmp.dir.writeFile(io, .{ .sub_path = "readme.txt", .data = "plain" });

    const root = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(root);

    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = root,
        .include_tmp = false,
        .protect_workspace_secrets = true,
    });
    defer compiled.deinit();

    const out = prepareForChildApplyWith(allocator, &compiled, .supported);
    defer if (out.sbpl_z) |p| allocator.free(p);
    try std.testing.expectEqual(.prepared, out.status);
    try std.testing.expectEqualStrings("seatbelt_prepared", out.reason_code);
    try std.testing.expect(out.sbpl_z != null);
}

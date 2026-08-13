//! POSIX fork → OS-FS apply → exec helper.
//!
//! Parent ryk stays free. Child installs Landlock (Linux) or Seatbelt (macOS)
//! then execs the agent. Child order: setpgid → stdio → apply → chdir →
//! preflight → fd_scrub (keep `{0,1,2,status_w}`) → status_ok → close
//! status_w → execve. Scrub runs before the handshake so the parent never
//! promotes attach while inherited FDs are still open; after status_ok only
//! the write end is closed (no second full scrub).
//!
//! Honesty (S-GLO-01): a pre-exec status pipe proves child apply *and*
//! required pre-exec setup (chdir, preflight, FD scrub) succeeded before the
//! parent returns a live child pid. Session `active` is promoted only after
//! that handshake (not from probe alone or fork alone). Parent waits with a
//! poll deadline so a hung child cannot block forever. The subsequent execve
//! itself cannot be proven before the parent returns — only that setup through
//! status_ok completed. Residual: `status_ok` is strictly pre-exec; an `active`
//! session may still surface a failed exec (e.g. exit 127) if the agent binary
//! is missing or not executable after attach.
//!
//! - Linux: `forkApplyLandlockAndExec` (parent builds landlock expand plan
//!   before fork so the child never opendir/readdir)
//! - macOS: `forkApplySeatbeltAndExec` (sandbox_init in child only; SBPL
//!   pre-rendered in parent — multi-thread residual documented in macos_seatbelt.zig)
//! - Other: Unsupported

const std = @import("std");
const builtin = @import("builtin");
const profile = @import("profile.zig");
const landlock = @import("landlock.zig");
const fd_scrub = @import("fd_scrub.zig");
const macos_seatbelt = @import("macos_seatbelt.zig");
const session_tmp = @import("session_tmp.zig");
const linux_workspace_view_spawn = @import("linux_workspace_view_spawn.zig");

pub const SpawnError = error{
    Unsupported,
    ForkFailed,
    ApplyFailed,
    ExecFailed,
    OutOfMemory,
    FileNotFound,
    /// Workspace-view bootstrap: sealed profile rebuild hash ≠ parent hash.
    ProfileHashMismatch,
    /// Workspace-view bootstrap: parent handshake timed out waiting for ready.
    HandshakeTimeout,
    /// Workspace-view bootstrap: /dev/fuse unavailable.
    FuseDeviceUnavailable,
    /// Workspace-view bootstrap: profile recompile failed.
    ProfileRebuildFailed,
    /// Workspace-view: FUSE mount / daemon / init failures (distinct from generic ApplyFailed).
    FuseMountFailed,
    FuseDaemonStartFailed,
    FuseInitFailed,
    /// Workspace-view: namespace / Landlock / capability / mount-verify bootstrap.
    NamespaceSetupFailed,
    LandlockUnavailable,
    LandlockAttachFailed,
    CapabilityLockdownFailed,
    MountVerificationFailed,
    /// Parent sealed more `.exec` grants than the wire limit.
    TooManyExecPaths,
};

/// Match core.process.StdioBehavior without importing core (module boundary).
pub const StdioBehavior = enum {
    inherit,
    ignore,
};

/// Owns page_allocator buffers retained across fork until the child is reaped
/// or the parent process exits.
///
/// After a successful handshake the child is about to `execve`; free only after
/// `waitpid` has reaped the child (or on process exit). `ApplyResult.deinit`
/// frees the lease after the supervisor wait completes on the production path.
///
/// Linux protect-on also records `workspace_view_daemon_pid` (FUSE server). That
/// process is a child of the agent bootstrap (not of this parent), so the parent
/// cannot `waitpid` it. Lifecycle (primary reapers only — no bare-PID residual):
/// 1. FUSE daemon installs `PR_SET_PDEATHSIG=SIGKILL` against the bootstrap/agent.
/// 2. When the agent exits or is killed, the kernel delivers SIGKILL to the daemon.
/// 3. Parent `killAndReapChild(agent)` kills the agent process group; the daemon
///    inherits the bootstrap `setpgid(0,0)` pgid, so PG kill covers it too.
/// 4. `deinit` only clears the recorded PID. Without pidfd identity fencing we
///    must not residual-`kill(daemon_pid)` after the agent may already be reaped —
///    the numeric PID can be reused (M-4).
pub const SpawnLease = struct {
    pid: i32,
    allocator: std.mem.Allocator,
    argv_z: ?[:null]?[*:0]const u8 = null,
    envp: ?AllocatedEnvp = null,
    cwd_z: ?[:0]const u8 = null,
    expand_plan: ?landlock.ChildLandlockPlan = null,
    workspace_view_daemon_pid: ?u32 = null,

    pub fn deinit(self: *SpawnLease) void {
        // Rely on PDEATHSIG + process-group kill for daemon reaping. Do not bare-
        // kill workspace_view_daemon_pid here: after agent reap the PID may name
        // an unrelated process (no pidfd to prove identity).
        self.workspace_view_daemon_pid = null;

        if (self.argv_z) |a| {
            freeArgvZ(self.allocator, a);
            self.argv_z = null;
        }
        if (self.envp) |e| {
            freeEnvpZ(self.allocator, e);
            self.envp = null;
        }
        if (self.cwd_z) |z| {
            self.allocator.free(z);
            self.cwd_z = null;
        }
        if (self.expand_plan) |*plan| {
            plan.deinit();
            self.expand_plan = null;
        }
        self.pid = -1;
    }
};

/// Best-effort SIGKILL for a FUSE workspace-view daemon that is not a direct
/// child of this process. Does not waitpid (would be ECHILD). Safe on null/0.
///
/// **When safe:** only while the agent bootstrap is still considered live
/// (`SpawnLease.pid > 0` and not yet reaped), so the stored daemon PID cannot
/// yet have been recycled after agent exit. Prefer PDEATHSIG + process-group
/// kill for teardown; do **not** call from `SpawnLease.deinit` after a possible
/// agent reap (PID-reuse hazard without pidfd).
pub fn signalWorkspaceViewDaemon(daemon_pid: ?u32) void {
    const pid_u = daemon_pid orelse return;
    if (pid_u == 0) return;
    const pid: i32 = std.math.cast(i32, pid_u) orelse return;
    std.posix.kill(pid, std.posix.SIG.KILL) catch {};
}

/// Single-byte status pipe protocol: child writes this after successful apply
/// *and* required pre-exec setup (chdir, preflight, FD scrub with status_w
/// kept). Parent must not promote session active until this byte is received.
const status_ok: u8 = 1;

/// Parent waits at most this long for the child apply handshake (ms).
/// Hung children must not block `ryk run` forever.
const status_handshake_timeout_ms: i32 = 10_000;

/// Child-side apply payload (plan pointer must address stable storage for the
/// lifetime of the forked child setup path).
const ChildOsApply = union(enum) {
    landlock: struct {
        compiled: *const profile.CompiledProfile,
        plan: *const landlock.ChildLandlockPlan,
        route_forcing: ?landlock.RouteForcing,
    },
    seatbelt: struct {
        sbpl_z: [*:0]const u8,
    },
};

/// Parent-side apply selection before the Landlock plan is bound into stable
/// storage. Avoids constructing `ChildOsApply.landlock` with an undefined plan
/// pointer that is later rewritten (M-24).
const ParentApplySpec = union(enum) {
    landlock: struct {
        compiled: *const profile.CompiledProfile,
        route_forcing: ?landlock.RouteForcing,
    },
    seatbelt: [*:0]const u8,
};

/// Fork, apply Landlock in the child from `compiled`, chdir, preflight, scrub
/// FDs (keep status_w), handshake, then execve.
///
/// Returns a `SpawnLease` owning retained argv/env/plan buffers. Caller must
/// `deinit` the lease after reaping the child (or process exit).
///
/// Linux only. Optional route forcing uses Landlock TCP port rules.
/// Linux Landlock attach path. When `protect_workspace_secrets`, routes through
/// the FUSE workspace-view bootstrap (`forkApplyWorkspaceViewAndExec` semantics)
/// instead of plain Landlock-only child apply.
pub fn forkApplyLandlockAndExec(
    io: std.Io,
    compiled: *const profile.CompiledProfile,
    route_forcing: ?landlock.RouteForcing,
    include_tmp: bool,
    ro_paths: []const []const u8,
    host_rw_paths: []const []const u8,
    argv: []const []const u8,
    env_map: ?*const std.process.Environ.Map,
    cwd: ?[]const u8,
    stdio: StdioBehavior,
) SpawnError!SpawnLease {
    if (builtin.os.tag != .linux) return error.Unsupported;
    if (argv.len == 0) return error.ExecFailed;
    if (compiled.protect_workspace_secrets) {
        return forkApplyWorkspaceViewAndExec(
            io,
            compiled,
            route_forcing,
            include_tmp,
            ro_paths,
            host_rw_paths,
            argv,
            env_map,
            cwd,
            stdio,
        );
    }
    return forkApplyAndExecLandlock(compiled, route_forcing, argv, env_map, cwd, stdio);
}

/// Explicit protect-on entry: sealed FUSE workspace view + Landlock in bootstrap.
fn forkApplyWorkspaceViewAndExec(
    io: std.Io,
    compiled: *const profile.CompiledProfile,
    route_forcing: ?landlock.RouteForcing,
    include_tmp: bool,
    ro_paths: []const []const u8,
    host_rw_paths: []const []const u8,
    argv: []const []const u8,
    env_map: ?*const std.process.Environ.Map,
    cwd: ?[]const u8,
    stdio: StdioBehavior,
) SpawnError!SpawnLease {
    const constructed_env = env_map orelse return error.ApplyFailed;
    const target_cwd = cwd orelse compiled.workspace_root;
    const spawned = linux_workspace_view_spawn.spawnWorkspaceView(.{
        .io = io,
        .allocator = std.heap.page_allocator,
        .compiled = compiled,
        .profile = .{
            // Use the original compile option, not grant inference (workspace=/tmp trap).
            .include_tmp = include_tmp,
            .ro_paths = ro_paths,
            .host_rw_paths = host_rw_paths,
            .network_proxy_port = if (route_forcing) |route| route.proxy_port else null,
            .require_network_route_forcing = route_forcing != null,
        },
        .argv = argv,
        .environment = constructed_env,
        .cwd = target_cwd,
        .stdio = switch (stdio) {
            .inherit => .inherit,
            .ignore => .ignore,
        },
    }) catch |err| return mapWorkspaceViewSpawnError(err);
    return .{
        .pid = spawned.agent_bootstrap_pid,
        .allocator = std.heap.page_allocator,
        .workspace_view_daemon_pid = spawned.daemon_pid,
    };
}

fn mapWorkspaceViewSpawnError(err: anyerror) SpawnError {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.Unsupported => error.Unsupported,
        error.ForkFailed => error.ForkFailed,
        error.ProfileHashMismatch => error.ProfileHashMismatch,
        error.Timeout, error.HandshakeTimeout => error.HandshakeTimeout,
        error.FuseDeviceUnavailable => error.FuseDeviceUnavailable,
        error.ProfileRebuildFailed => error.ProfileRebuildFailed,
        error.FuseMountFailed => error.FuseMountFailed,
        error.FuseDaemonStartFailed => error.FuseDaemonStartFailed,
        error.FuseInitFailed => error.FuseInitFailed,
        error.NamespaceSetupFailed => error.NamespaceSetupFailed,
        error.LandlockUnavailable => error.LandlockUnavailable,
        error.LandlockAttachFailed => error.LandlockAttachFailed,
        error.CapabilityLockdownFailed => error.CapabilityLockdownFailed,
        error.MountVerificationFailed => error.MountVerificationFailed,
        error.TooManyExecPaths => error.TooManyExecPaths,
        else => error.ApplyFailed,
    };
}

/// Fork, apply Seatbelt SBPL in the child, chdir, preflight, scrub FDs (keep
/// status_w), handshake, then execve. macOS only.
///
/// **Caller ownership of `sbpl_z`:** must remain valid until the child has
/// exec'd (parent retains the SBPL — typically until process exit for a
/// one-shot launch).
///
/// Returns a `SpawnLease` — free after reaping the child.
pub fn forkApplySeatbeltAndExec(
    sbpl_z: [*:0]const u8,
    argv: []const []const u8,
    env_map: ?*const std.process.Environ.Map,
    cwd: ?[]const u8,
    stdio: StdioBehavior,
) SpawnError!SpawnLease {
    if (builtin.os.tag != .macos) return error.Unsupported;
    if (argv.len == 0) return error.ExecFailed;
    return forkApplyAndExecCommon(.{ .seatbelt = sbpl_z }, null, argv, env_map, cwd, stdio);
}

fn forkApplyAndExecLandlock(
    compiled: *const profile.CompiledProfile,
    route_forcing: ?landlock.RouteForcing,
    argv: []const []const u8,
    env_map: ?*const std.process.Environ.Map,
    cwd: ?[]const u8,
    stdio: StdioBehavior,
) SpawnError!SpawnLease {
    const allocator = std.heap.page_allocator;

    // Ensure `{workspace}/.ryk-tmp` exists *before* expand enumeration (shared with apply).
    _ = session_tmp.ensureWorkspaceSessionTmp(compiled.workspace_root);

    // Enumerate control-expand paths in the parent before fork.
    // Ownership transfers into forkApplyAndExecCommon / SpawnLease (no local errdefer).
    const expand_plan = landlock.buildChildLandlockPlan(allocator, compiled) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.ApplyFailed,
    };

    return forkApplyAndExecCommon(
        .{ .landlock = .{ .compiled = compiled, .route_forcing = route_forcing } },
        expand_plan,
        argv,
        env_map,
        cwd,
        stdio,
    );
}

/// Unified parent protocol for Landlock and Seatbelt. Only the child
/// apply step differs. When `pending_plan` is non-null it is moved into the
/// returned lease on success (or freed via errdefer path on failure inside
/// the landlock wrapper).
fn forkApplyAndExecCommon(
    spec: ParentApplySpec,
    pending_plan: ?landlock.ChildLandlockPlan,
    argv: []const []const u8,
    env_map: ?*const std.process.Environ.Map,
    cwd: ?[]const u8,
    stdio: StdioBehavior,
) SpawnError!SpawnLease {
    const allocator = std.heap.page_allocator;
    var plan_holder = pending_plan;
    errdefer if (plan_holder) |*p| p.deinit();

    // Build ChildOsApply only after plan is in stable plan_holder storage (M-24).
    const resolved_apply: ChildOsApply = switch (spec) {
        .landlock => |ll| .{ .landlock = .{
            .compiled = ll.compiled,
            .plan = if (plan_holder) |*p| p else return error.ApplyFailed,
            .route_forcing = ll.route_forcing,
        } },
        .seatbelt => |sbpl_z| .{ .seatbelt = .{ .sbpl_z = sbpl_z } },
    };

    const argv_z = try allocArgvZ(allocator, argv);
    errdefer freeArgvZ(allocator, argv_z);
    const envp = try allocEnvpZ(allocator, env_map);
    errdefer freeEnvpZ(allocator, envp);
    const cwd_z: ?[:0]const u8 = if (cwd) |c|
        (allocator.dupeZ(u8, c) catch return error.OutOfMemory)
    else
        null;
    errdefer if (cwd_z) |z| allocator.free(z);

    const pipe_fds = openStatusPipe() catch return error.ForkFailed;
    var status_r = pipe_fds[0];
    var status_w = pipe_fds[1];
    errdefer {
        closeFd(status_r);
        closeFd(status_w);
    }

    const child_pid: i32 = switch (builtin.os.tag) {
        .linux => blk: {
            const linux = std.os.linux;
            const pid_rc = linux.fork();
            if (linux.errno(pid_rc) != .SUCCESS) return error.ForkFailed;
            if (pid_rc == 0) {
                runChildAfterFork(resolved_apply, argv_z, envp, cwd_z, stdio, status_r, status_w);
            }
            break :blk @intCast(pid_rc);
        },
        .macos => blk: {
            const pid = std.c.fork();
            if (pid < 0) return error.ForkFailed;
            if (pid == 0) {
                runChildAfterFork(resolved_apply, argv_z, envp, cwd_z, stdio, status_r, status_w);
            }
            break :blk pid;
        },
        else => return error.Unsupported,
    };

    closeFd(status_w);
    status_w = -1;
    // On failure, readStatusOk already kill+reaped via failHandshake (M-38).
    const ok = readStatusOk(status_r, child_pid);
    closeFd(status_r);
    status_r = -1;
    if (!ok) return error.ApplyFailed;

    // Transfer ownership into lease (disarm plan errdefer).
    const moved_plan = plan_holder;
    plan_holder = null;
    return .{
        .pid = child_pid,
        .allocator = allocator,
        .argv_z = argv_z,
        .envp = envp,
        .cwd_z = cwd_z,
        .expand_plan = moved_plan,
    };
}

/// Child-only path after fork. Never returns.
fn runChildAfterFork(
    child_apply: ChildOsApply,
    argv_z: [:null]?[*:0]const u8,
    envp: AllocatedEnvp,
    cwd_z: ?[:0]const u8,
    stdio: StdioBehavior,
    status_r: i32,
    status_w_in: i32,
) noreturn {
    const status_w = status_w_in;
    closeFd(status_r);

    const failExit = struct {
        fn call(status_w_fd: i32) noreturn {
            closeFd(status_w_fd);
            switch (builtin.os.tag) {
                .linux => std.os.linux.exit(127),
                else => std.c._exit(127),
            }
        }
    }.call;

    if (std.c.setpgid(0, 0) != 0) failExit(status_w);

    applyStdioInChild(stdio) catch failExit(status_w);

    switch (child_apply) {
        .landlock => |ll| landlock.applySelf(ll.compiled, ll.plan, ll.route_forcing) catch failExit(status_w),
        .seatbelt => |sb| macos_seatbelt.applyInChild(sb.sbpl_z) catch failExit(status_w),
    }

    if (cwd_z) |z| {
        const chdir_failed = switch (builtin.os.tag) {
            .linux => std.os.linux.chdir(z.ptr) != 0,
            else => std.c.chdir(z.ptr) != 0,
        };
        if (chdir_failed) failExit(status_w);
    }

    const path = argv_z[0] orelse failExit(status_w);
    if (!preflightExecTarget(path)) failExit(status_w);

    const keep_fds = [_]i32{ 0, 1, 2, status_w };
    const scrubbed = fd_scrub.closeInheritedFdsAndVerify(&keep_fds);
    if (!writeStatusIfScrubbed(status_w, scrubbed)) failExit(status_w);
    closeFd(status_w);

    switch (builtin.os.tag) {
        .linux => {
            _ = std.os.linux.execve(path, argv_z.ptr, envp.ptr.ptr);
            std.os.linux.exit(127);
        },
        else => {
            _ = std.c.execve(path, @ptrCast(argv_z.ptr), @ptrCast(envp.ptr.ptr));
            std.c._exit(127);
        },
    }
}

/// Best-effort check that `path` is readable+executable under the current box.
/// Runs in the child after apply and optional chdir; failure fails the handshake
/// so the parent does not promote session `active` (F-4).
fn preflightExecTarget(path: [*:0]const u8) bool {
    switch (builtin.os.tag) {
        .windows, .wasi => return true,
        else => {
            // POSIX: R_OK=4, X_OK=1 (portable constants; libc access).
            const R_OK: c_int = 4;
            const X_OK: c_int = 1;
            return std.c.access(path, R_OK | X_OK) == 0;
        },
    }
}

fn openStatusPipe() error{PipeFailed}![2]i32 {
    var fds: [2]std.c.fd_t = undefined;
    // Prefer pipe2(CLOEXEC) so a missed close cannot leak into exec.
    // macOS has no libc pipe2; fall back to pipe + fcntl.
    if (@TypeOf(std.c.pipe2) != void) {
        if (std.c.pipe2(&fds, .{ .CLOEXEC = true }) != 0) return error.PipeFailed;
    } else {
        if (std.c.pipe(&fds) != 0) return error.PipeFailed;
        // Fail closed if CLOEXEC cannot be set — a non-CLOEXEC pipe end can leak
        // into a later exec if a close is missed.
        if (std.c.fcntl(fds[0], std.c.F.SETFD, @as(c_int, std.c.FD_CLOEXEC)) == -1 or
            std.c.fcntl(fds[1], std.c.F.SETFD, @as(c_int, std.c.FD_CLOEXEC)) == -1)
        {
            _ = std.c.close(fds[0]);
            _ = std.c.close(fds[1]);
            return error.PipeFailed;
        }
    }
    return .{ @intCast(fds[0]), @intCast(fds[1]) };
}

fn closeFd(fd: i32) void {
    if (fd < 0) return;
    _ = std.c.close(fd);
}

/// Monotonic milliseconds for handshake deadline tracking (M-5).
/// Returns null if `clock_gettime` fails — callers must never treat failure as
/// `now = 0` against a real deadline (that either false-timeouts immediately
/// when the clock recovers, or extends the wait unboundedly if it fails mid-loop).
fn handshakeMonotonicMs() ?i64 {
    var ts: std.c.timespec = undefined;
    if (std.c.clock_gettime(std.c.CLOCK.MONOTONIC, &ts) != 0) {
        return null;
    }
    return @as(i64, @intCast(ts.sec)) * std.time.ms_per_s +
        @divTrunc(@as(i64, @intCast(ts.nsec)), std.time.ns_per_ms);
}

/// True when a libc call returned -1 with EINTR (thread-local errno).
fn libcEintr(rc: anytype) bool {
    return std.c.errno(rc) == .INTR;
}

fn writeStatusOk(write_fd: i32) bool {
    var buf = [_]u8{status_ok};
    // Retry on EINTR until the single status byte is written or a hard error (M-7).
    while (true) {
        const n = std.c.write(write_fd, &buf, 1);
        if (n == 1) return true;
        if (libcEintr(n)) continue;
        return false;
    }
}

fn writeStatusIfScrubbed(write_fd: i32, scrubbed: bool) bool {
    if (!scrubbed) return false;
    return writeStatusOk(write_fd);
}

/// Kill + reap on every handshake failure exit so the parent never returns
/// ApplyFailed with a live unreaped child (M-38).
fn failHandshake(child_pid: i32) void {
    killAndReapChild(child_pid);
}

/// Wait for the single-byte apply handshake with a true remaining deadline.
/// Poll loops until readable success, true timeout, or non-EINTR poll failure
/// (M-5). Read retries EINTR until 1 byte or hard error (M-7). All failure
/// exits kill+reap via failHandshake (M-38).
/// Returns true only when the status_ok byte is received.
///
/// Clock policy (M-5): when the start clock works, poll timeouts follow
/// `deadline - now`. If the start clock fails — or fails mid-handshake —
/// never substitute `now = 0`; fall back to a pure poll-timeout budget totaling
/// `status_handshake_timeout_ms` (single/few slices, no broken wall math).
fn readStatusOk(read_fd: i32, child_pid: i32) bool {
    const start_ms = handshakeMonotonicMs();
    const use_deadline = start_ms != null;
    const deadline_ms: i64 = if (start_ms) |s| s + status_handshake_timeout_ms else 0;
    // Pure budget used when the start clock failed, or if the clock fails later.
    var budget_ms: i32 = status_handshake_timeout_ms;

    var fds = [_]std.posix.pollfd{.{
        .fd = read_fd,
        .events = std.posix.POLL.IN,
        .revents = 0,
    }};

    while (true) {
        const remaining: i32 = if (use_deadline) blk: {
            if (handshakeMonotonicMs()) |now| {
                const remaining_i64 = deadline_ms - now;
                if (remaining_i64 <= 0) {
                    failHandshake(child_pid);
                    return false;
                }
                const r: i32 = @intCast(@min(remaining_i64, @as(i64, std.math.maxInt(i32))));
                // Keep budget coherent so a later clock failure still bounds the wait.
                budget_ms = r;
                break :blk r;
            } else {
                // Mid-handshake clock failure: pure budget, no now=0 math.
                break :blk budget_ms;
            }
        } else budget_ms;

        if (remaining <= 0) {
            failHandshake(child_pid);
            return false;
        }

        // std.posix.poll already retries EINTR internally; we pass the remaining
        // slice of the deadline (or pure budget) so restarts cannot extend past
        // the true timeout when the clock is healthy.
        const ready = std.posix.poll(&fds, remaining) catch {
            // Non-EINTR poll failure.
            failHandshake(child_pid);
            return false;
        };
        if (ready == 0) {
            // Poll waited the full remaining slice with no events → true timeout.
            failHandshake(child_pid);
            return false;
        }

        // Readable, hung-up, or error: read with EINTR retry until 1 byte or hard error.
        var buf: [1]u8 = undefined;
        while (true) {
            const n = std.c.read(read_fd, &buf, 1);
            if (n == 1) {
                if (buf[0] == status_ok) return true;
                failHandshake(child_pid);
                return false;
            }
            if (libcEintr(n)) continue;
            // EOF (0) or hard error — apply/setup did not complete.
            failHandshake(child_pid);
            return false;
        }
    }
}

/// Best-effort: signal the process group (negative pid) then the pid itself.
fn killProcessGroup(pid: i32) void {
    if (comptime builtin.os.tag == .windows) return;
    if (pid <= 0) return;
    std.posix.kill(-pid, std.posix.SIG.KILL) catch {};
    std.posix.kill(pid, std.posix.SIG.KILL) catch {};
}

/// Best-effort kill process group + pid and reap (public for post-handshake
/// promote hard-fail cleanup in `apply.spawnAgent`).
pub fn killAndReapChild(pid: i32) void {
    if (comptime builtin.os.tag == .windows) return;
    killProcessGroup(pid);
    var status: c_int = 0;
    // Retry waitpid on EINTR so parent does not free argv/env while the child
    // may still be alive (fork COW UAF). Other waitpid failures are best-effort
    // only (already reaped / ESRCH / etc.) — kill was already delivered.
    while (true) {
        const rc = std.c.waitpid(pid, &status, 0);
        if (rc >= 0) break;
        if (libcEintr(rc)) continue;
        break;
    }
}

fn applyStdioInChild(stdio: StdioBehavior) error{StdioFailed}!void {
    switch (stdio) {
        .inherit => {},
        .ignore => try redirectStdioToDevNull(),
    }
}

fn redirectStdioToDevNull() error{StdioFailed}!void {
    // Keep 0/1/2 as the only stdio FDs; they stay in fd_scrub keep-set.
    const null_fd = std.c.open("/dev/null", .{ .ACCMODE = .RDWR });
    if (null_fd < 0) return error.StdioFailed;
    defer _ = std.c.close(null_fd);
    if (std.c.dup2(null_fd, 0) < 0) return error.StdioFailed;
    if (std.c.dup2(null_fd, 1) < 0) return error.StdioFailed;
    if (std.c.dup2(null_fd, 2) < 0) return error.StdioFailed;
}

const AllocatedEnvp = struct {
    /// Null-terminated envp for execve.
    ptr: [:null]?[*:0]const u8,
    /// False when pointing at the current process `environ` (inherit).
    owned: bool,
};

/// Free a C string allocated by `allocator.dupeZ` (content + trailing NUL).
/// `std.mem.span` alone yields a `[:0]` view whose free must absorb the sentinel.
fn freeDupeZ(allocator: std.mem.Allocator, z: [*:0]const u8) void {
    const owned: [:0]const u8 = std.mem.span(z);
    allocator.free(owned);
}

fn allocArgvZ(allocator: std.mem.Allocator, argv: []const []const u8) SpawnError![:null]?[*:0]const u8 {
    var list = allocator.alloc(?[*:0]const u8, argv.len + 1) catch return error.OutOfMemory;
    // Null-init so errdefer free of optionals is safe on mid-loop OOM.
    @memset(list, null);
    errdefer {
        for (list[0..argv.len]) |p| {
            if (p) |z| freeDupeZ(allocator, z);
        }
        allocator.free(list);
    }
    for (argv, 0..) |arg, i| {
        list[i] = (allocator.dupeZ(u8, arg) catch return error.OutOfMemory).ptr;
    }
    list[argv.len] = null;
    return list[0..argv.len :null];
}

fn freeArgvZ(allocator: std.mem.Allocator, argv_z: [:null]?[*:0]const u8) void {
    for (argv_z) |p| {
        if (p) |z| freeDupeZ(allocator, z);
    }
    // Free the null-terminated pointer array (len + trailing null slot).
    const base: [*]?[*:0]const u8 = @ptrCast(argv_z.ptr);
    allocator.free(base[0 .. argv_z.len + 1]);
}

/// Build envp for execve. `null` env_map means inherit the current process
/// environment (same as `std.process.spawn` with a null environ_map). Never
/// invents an empty environment under the name of inherit.
fn allocEnvpZ(allocator: std.mem.Allocator, env_map: ?*const std.process.Environ.Map) SpawnError!AllocatedEnvp {
    if (env_map == null) {
        // Borrow process environ — not owned, not empty.
        const raw: [*:null]?[*:0]u8 = std.c.environ;
        var n: usize = 0;
        while (raw[n] != null) : (n += 1) {}
        const as_const: [*:null]?[*:0]const u8 = @ptrCast(raw);
        return .{ .ptr = as_const[0..n :null], .owned = false };
    }
    const map = env_map.?;
    // Count keys.
    var count: usize = 0;
    var it = map.iterator();
    while (it.next()) |_| count += 1;

    var list = allocator.alloc(?[*:0]const u8, count + 1) catch return error.OutOfMemory;
    // Null-init so errdefer free of optionals is safe on mid-loop OOM.
    @memset(list, null);
    errdefer {
        var i: usize = 0;
        while (i < count) : (i += 1) {
            if (list[i]) |z| freeDupeZ(allocator, z);
        }
        allocator.free(list);
    }
    var idx: usize = 0;
    var it2 = map.iterator();
    while (it2.next()) |entry| {
        const line = std.fmt.allocPrint(allocator, "{s}={s}", .{ entry.key_ptr.*, entry.value_ptr.* }) catch return error.OutOfMemory;
        defer allocator.free(line);
        list[idx] = (allocator.dupeZ(u8, line) catch return error.OutOfMemory).ptr;
        idx += 1;
    }
    list[count] = null;
    return .{ .ptr = list[0..count :null], .owned = true };
}

fn freeEnvpZ(allocator: std.mem.Allocator, envp: AllocatedEnvp) void {
    if (!envp.owned) return;
    for (envp.ptr) |p| {
        if (p) |z| freeDupeZ(allocator, z);
    }
    const base: [*]?[*:0]const u8 = @ptrCast(envp.ptr.ptr);
    allocator.free(base[0 .. envp.ptr.len + 1]);
}

/// Resolve argv[0] to an absolute path for exec.
/// When `env_map` is provided and contains PATH, that PATH is used (child env);
/// otherwise falls back to the process getenv PATH.
/// Caller owns the returned slice when `owned` is true.
pub fn resolveArgv0(
    io: std.Io,
    allocator: std.mem.Allocator,
    argv0: []const u8,
    env_map: ?*const std.process.Environ.Map,
) SpawnError!struct { path: []const u8, owned: bool } {
    if (argv0.len == 0) return error.FileNotFound;
    if (std.fs.path.isAbsolute(argv0)) {
        return .{ .path = argv0, .owned = false };
    }
    // Relative with a separator: resolve against cwd.
    if (std.mem.indexOfScalar(u8, argv0, '/') != null) {
        return .{ .path = argv0, .owned = false };
    }
    const path_env = blk: {
        if (env_map) |map| {
            if (map.get("PATH")) |p| break :blk p;
        }
        if (std.c.getenv("PATH")) |p| break :blk std.mem.span(p);
        break :blk "/usr/local/bin:/usr/bin:/bin";
    };
    var it = std.mem.splitScalar(u8, path_env, ':');
    while (it.next()) |dir| {
        if (dir.len == 0) continue;
        const candidate = std.fs.path.join(allocator, &.{ dir, argv0 }) catch return error.OutOfMemory;
        errdefer allocator.free(candidate);
        std.Io.Dir.cwd().access(io, candidate, .{}) catch {
            allocator.free(candidate);
            continue;
        };
        const canonical_z = std.Io.Dir.cwd().realPathFileAlloc(io, candidate, allocator) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return .{ .path = candidate, .owned = true },
        };
        defer freeDupeZ(allocator, canonical_z.ptr);
        const canonical = allocator.dupe(u8, canonical_z) catch return error.OutOfMemory;
        allocator.free(candidate);
        return .{ .path = canonical, .owned = true };
    }
    return error.FileNotFound;
}

/// waitpid with EINTR retry for tests — always reap before lease deinit (M-27).
fn waitpidRetry(pid: i32) !c_int {
    var status: c_int = 0;
    while (true) {
        const rc = std.c.waitpid(pid, &status, 0);
        if (rc >= 0) return status;
        if (libcEintr(rc)) continue;
        return error.TestUnexpectedResult;
    }
}

fn expectExitedZero(status: c_int) !void {
    try std.testing.expect((status & 0x7f) == 0);
    try std.testing.expectEqual(@as(u8, 0), @as(u8, @intCast((status >> 8) & 0xff)));
}

test "forkApplyLandlockAndExec is unsupported off Linux" {
    if (builtin.os.tag == .linux) return error.SkipZigTest;
    try std.testing.expectError(error.Unsupported, forkApplyLandlockAndExec(
        std.testing.io,
        &.{
            .allocator = std.testing.allocator,
            .workspace_root = "/",
            .grants = &.{},
            .control_roots = &.{},
            .canonical_bytes = "",
            .hash_hex = .{'0'} ** 64,
        },
        null,
        false,
        &.{},
        &.{},
        &[_][]const u8{"/bin/true"},
        null,
        null,
        .inherit,
    ));
}

test "forkApplyLandlockAndExec applies then execs on Linux with handshake" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!landlock.isAbiAvailable()) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    try ws_tmp.dir.createDirPath(io, ".ryk");
    const ws_root = try ws_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(ws_root);

    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = ws_root,
        // Cover true binary + dynamic linker paths on common distros.
        .system_ro_prefixes = &[_][]const u8{ "/usr", "/bin", "/sbin", "/lib", "/lib64" },
        .include_tmp = false,
    });
    defer compiled.deinit();

    const true_path = blk: {
        std.Io.Dir.cwd().access(io, "/usr/bin/true", .{}) catch {
            std.Io.Dir.cwd().access(io, "/bin/true", .{}) catch return error.SkipZigTest;
            break :blk "/bin/true";
        };
        break :blk "/usr/bin/true";
    };

    // Parent only gets a pid after child apply+chdir status pipe succeeds.
    // Successful handshake proves status_w was retained through fd_scrub (M-17).
    var child = try forkApplyLandlockAndExec(
        io,
        &compiled,
        null,
        false,
        &.{},
        &.{},
        &[_][]const u8{true_path},
        null,
        ws_root,
        .inherit,
    );
    defer child.deinit();
    const status = try waitpidRetry(child.pid);
    try expectExitedZero(status);
}

test "forkApplyLandlockAndExec fails handshake on bad chdir" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!landlock.isAbiAvailable()) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    try ws_tmp.dir.createDirPath(io, ".ryk");
    const ws_root = try ws_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(ws_root);

    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = ws_root,
        .system_ro_prefixes = &[_][]const u8{ "/usr", "/bin", "/sbin", "/lib", "/lib64" },
        .include_tmp = false,
    });
    defer compiled.deinit();

    const true_path = blk: {
        std.Io.Dir.cwd().access(io, "/usr/bin/true", .{}) catch {
            std.Io.Dir.cwd().access(io, "/bin/true", .{}) catch return error.SkipZigTest;
            break :blk "/bin/true";
        };
        break :blk "/usr/bin/true";
    };

    // chdir failure must not write status_ok — parent sees ApplyFailed.
    try std.testing.expectError(error.ApplyFailed, forkApplyLandlockAndExec(
        io,
        &compiled,
        null,
        false,
        &.{},
        &.{},
        &[_][]const u8{true_path},
        null,
        "/no/such/ryk/cwd/for/handshake/test",
        .inherit,
    ));
}

test "forkApplySeatbeltAndExec is unsupported off macOS" {
    if (builtin.os.tag == .macos) return error.SkipZigTest;
    try std.testing.expectError(error.Unsupported, forkApplySeatbeltAndExec(
        "(version 1)\x00",
        &[_][]const u8{"/bin/true"},
        null,
        null,
        .inherit,
    ));
}

/// Permissive Seatbelt profile shared by low-level fork/exec handshake tests.
/// Product grants are narrower; this only proves apply → exec plumbing on matrix macOS.
const permissive_test_sbpl =
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

test "forkApplySeatbeltAndExec applies then execs on macOS with handshake" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;

    const sbpl_z = try std.testing.allocator.dupeZ(u8, permissive_test_sbpl);
    defer std.testing.allocator.free(sbpl_z);

    // Seatbelt apply works even outside product matrix for this low-level helper;
    // product gating is in macos_seatbelt.evaluateSupport / applyBeforeExec.
    // Parent only gets a pid after child apply status pipe succeeds.
    // Successful handshake proves status_w was retained through fd_scrub (M-17).
    var child = try forkApplySeatbeltAndExec(sbpl_z.ptr, &[_][]const u8{"/usr/bin/true"}, null, null, .inherit);
    defer child.deinit();
    try expectExitedZero(try waitpidRetry(child.pid));
}

test "forkApplySeatbeltAndExec honors stdio ignore on macOS" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;

    const sbpl_z = try std.testing.allocator.dupeZ(u8, permissive_test_sbpl);
    defer std.testing.allocator.free(sbpl_z);

    var child = try forkApplySeatbeltAndExec(
        sbpl_z.ptr,
        &[_][]const u8{ "/bin/sh", "-c", "echo should-not-appear-on-parent-stdout" },
        null,
        null,
        .ignore,
    );
    defer child.deinit();
    try expectExitedZero(try waitpidRetry(child.pid));
}

test "forkApplySeatbeltAndExec establishes process group leadership on macOS" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;

    const sbpl_z = try std.testing.allocator.dupeZ(u8, permissive_test_sbpl);
    defer std.testing.allocator.free(sbpl_z);

    // After setpgid(0,0) in child, parent getpgid(pid) must equal pid (group leader).
    var child = try forkApplySeatbeltAndExec(
        sbpl_z.ptr,
        &[_][]const u8{ "/bin/sh", "-c", "sleep 0.15" },
        null,
        null,
        .ignore,
    );
    defer child.deinit();
    const getpgid = struct {
        extern "c" fn getpgid(pid: std.c.pid_t) std.c.pid_t;
    }.getpgid;
    const pgid = getpgid(child.pid);
    try std.testing.expect(pgid > 0);
    try std.testing.expectEqual(child.pid, pgid);
    try expectExitedZero(try waitpidRetry(child.pid));
}

test "null env_map inherits process environ (not empty)" {
    // allocEnvpZ is private; exercise via a short child that checks PATH is set.
    if (builtin.os.tag != .macos) return error.SkipZigTest;

    const sbpl_z = try std.testing.allocator.dupeZ(u8, permissive_test_sbpl);
    defer std.testing.allocator.free(sbpl_z);

    // With null env_map, PATH from parent must still be present (inherit).
    var child = try forkApplySeatbeltAndExec(
        sbpl_z.ptr,
        &[_][]const u8{ "/bin/sh", "-c", "test -n \"$PATH\"" },
        null,
        null,
        .ignore,
    );
    defer child.deinit();
    try expectExitedZero(try waitpidRetry(child.pid));
}

test "resolveArgv0 finds absolute and PATH binaries" {
    const abs = try resolveArgv0(std.testing.io, std.testing.allocator, "/bin/sh", null);
    try std.testing.expect(!abs.owned);
    try std.testing.expectEqualStrings("/bin/sh", abs.path);

    const via_path = resolveArgv0(std.testing.io, std.testing.allocator, "true", null) catch |err| switch (err) {
        error.FileNotFound => return error.SkipZigTest,
        else => return err,
    };
    defer if (via_path.owned) std.testing.allocator.free(via_path.path);
    try std.testing.expect(via_path.path.len > 0);
}

test "resolveArgv0 prefers PATH from env_map over process" {
    // Point PATH at an empty directory so a bare name cannot resolve via env_map.
    var map = std.process.Environ.Map.init(std.testing.allocator);
    defer map.deinit();
    try map.put("PATH", "/no/such/ryk/path/for/resolve/test");

    const missing = resolveArgv0(std.testing.io, std.testing.allocator, "true", &map);
    try std.testing.expectError(error.FileNotFound, missing);

    // Absolute still works regardless of env_map PATH.
    const abs = try resolveArgv0(std.testing.io, std.testing.allocator, "/bin/sh", &map);
    try std.testing.expect(!abs.owned);
    try std.testing.expectEqualStrings("/bin/sh", abs.path);
}

test "resolveArgv0 canonicalizes PATH directory symlinks before sandbox exec" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "real", .default_dir);
    {
        const file = try tmp.dir.createFile(std.testing.io, "real/agent", .{});
        defer file.close(std.testing.io);
    }
    tmp.dir.symLink(std.testing.io, "real", "alias", .{ .is_directory = true }) catch
        return error.SkipZigTest;
    const alias_path = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(alias_path);
    const path_value = try std.fs.path.join(std.testing.allocator, &.{ alias_path, "alias" });
    defer std.testing.allocator.free(path_value);
    var map = std.process.Environ.Map.init(std.testing.allocator);
    defer map.deinit();
    try map.put("PATH", path_value);

    const resolved = try resolveArgv0(std.testing.io, std.testing.allocator, "agent", &map);
    defer if (resolved.owned) std.testing.allocator.free(resolved.path);
    const expected = try std.fs.path.join(std.testing.allocator, &.{ alias_path, "real", "agent" });
    defer std.testing.allocator.free(expected);
    try std.testing.expectEqualStrings(expected, resolved.path);
}

test "resolveArgv0 cleans every PATH allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, resolveArgv0AllocationFailureProbe, .{});
}

fn resolveArgv0AllocationFailureProbe(allocator: std.mem.Allocator) !void {
    var map = std.process.Environ.Map.init(allocator);
    defer map.deinit();
    try map.put("PATH", "/bin:/usr/bin");

    const resolved = try resolveArgv0(std.testing.io, allocator, "sh", &map);
    defer if (resolved.owned) allocator.free(resolved.path);
}

test "forkApplySeatbeltAndExec fails handshake on bad chdir" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;

    const sbpl_z = try std.testing.allocator.dupeZ(u8, permissive_test_sbpl);
    defer std.testing.allocator.free(sbpl_z);

    // chdir failure must not write status_ok — parent sees ApplyFailed.
    try std.testing.expectError(error.ApplyFailed, forkApplySeatbeltAndExec(
        sbpl_z.ptr,
        &[_][]const u8{"/usr/bin/true"},
        null,
        "/no/such/ryk/cwd/for/handshake/test",
        .inherit,
    ));
}

// --- Order-of-ops / handshake invariants (M-17) ---

test "apply fail does not write status_ok (seatbelt invalid SBPL)" {
    // Order: apply → … → status_ok. Apply failure must fail-closed with no handshake.
    if (builtin.os.tag != .macos) return error.SkipZigTest;

    const bad_sbpl = try std.testing.allocator.dupeZ(u8, "(version 1)\n(this is not valid sbpl\n");
    defer std.testing.allocator.free(bad_sbpl);

    try std.testing.expectError(error.ApplyFailed, forkApplySeatbeltAndExec(
        bad_sbpl.ptr,
        &[_][]const u8{"/usr/bin/true"},
        null,
        null,
        .inherit,
    ));
}

test "preflight fail does not write status_ok (missing exec target)" {
    // Preflight is after apply/chdir and before fd_scrub/status_ok; failure must not handshake.
    if (builtin.os.tag == .macos) {
        const sbpl_z = try std.testing.allocator.dupeZ(u8, permissive_test_sbpl);
        defer std.testing.allocator.free(sbpl_z);
        try std.testing.expectError(error.ApplyFailed, forkApplySeatbeltAndExec(
            sbpl_z.ptr,
            &[_][]const u8{"/no/such/ryk/exec/target/for/preflight"},
            null,
            null,
            .inherit,
        ));
        return;
    }
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!landlock.isAbiAvailable()) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    try ws_tmp.dir.createDirPath(io, ".ryk");
    const ws_root = try ws_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(ws_root);

    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = ws_root,
        .system_ro_prefixes = &[_][]const u8{ "/usr", "/bin", "/sbin", "/lib", "/lib64" },
        .include_tmp = false,
    });
    defer compiled.deinit();

    try std.testing.expectError(error.ApplyFailed, forkApplyLandlockAndExec(
        io,
        &compiled,
        null,
        false,
        &.{},
        &.{},
        &[_][]const u8{"/no/such/ryk/exec/target/for/preflight"},
        null,
        ws_root,
        .inherit,
    ));
}

test "fd scrub keep-set retains status_w and closes non-kept FDs" {
    // Mirrors production keep `{0,1,2,status_w}` used after apply/chdir/preflight.
    const status_w: i32 = 17;
    const keep = [_]i32{ 0, 1, 2, status_w };
    try std.testing.expect(fd_scrub.isKeptFd(status_w, &keep));
    try std.testing.expect(!fd_scrub.shouldCloseFd(status_w, &keep));
    try std.testing.expect(fd_scrub.shouldCloseFd(18, &keep));
    try std.testing.expect(fd_scrub.shouldCloseFd(42, &keep));
    try std.testing.expect(!fd_scrub.shouldCloseFd(0, &keep));
}

test "incomplete FD scrub emits no success handshake byte" {
    if (builtin.os.tag == .windows or builtin.os.tag == .wasi) return error.SkipZigTest;
    const pipe = try openStatusPipe();
    defer closeFd(pipe[0]);

    try std.testing.expect(!writeStatusIfScrubbed(pipe[1], false));
    closeFd(pipe[1]);

    var byte: [1]u8 = undefined;
    const read_count = std.c.read(pipe[0], &byte, byte.len);
    try std.testing.expectEqual(@as(isize, 0), read_count);
}

test "planted non-kept FD is closed after successful handshake" {
    // Parent plants FD 42; child inherits it; fd_scrub must close it before status_ok/exec.
    // Handshake success + child seeing FD closed proves scrub-before-handshake order (M-17).
    if (builtin.os.tag != .macos and builtin.os.tag != .linux) return error.SkipZigTest;

    const plant_fd: i32 = 42;
    const marker = std.c.open("/dev/null", .{ .ACCMODE = .RDONLY });
    if (marker < 0) return error.SkipZigTest;
    defer _ = std.c.close(marker);
    // Ensure plant slot is free then occupy it so the child inherits it.
    _ = std.c.close(plant_fd);
    if (std.c.dup2(marker, plant_fd) < 0) return error.SkipZigTest;
    defer _ = std.c.close(plant_fd);

    // Portable: try to dup FD 42 as stdin of a subshell. Succeeds only if open.
    // Exit 0 when closed (scrub worked); exit 1 if still inherited.
    const check_closed =
        \\if ( exec 3<&42 ) 2>/dev/null; then exit 1; else exit 0; fi
    ;

    if (builtin.os.tag == .macos) {
        const sbpl_z = try std.testing.allocator.dupeZ(u8, permissive_test_sbpl);
        defer std.testing.allocator.free(sbpl_z);
        var child = try forkApplySeatbeltAndExec(
            sbpl_z.ptr,
            &[_][]const u8{ "/bin/sh", "-c", check_closed },
            null,
            null,
            .ignore,
        );
        defer child.deinit();
        try expectExitedZero(try waitpidRetry(child.pid));
        return;
    }

    // Linux Landlock path.
    if (!landlock.isAbiAvailable()) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    try ws_tmp.dir.createDirPath(io, ".ryk");
    const ws_root = try ws_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(ws_root);

    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = ws_root,
        .system_ro_prefixes = &[_][]const u8{ "/usr", "/bin", "/sbin", "/lib", "/lib64" },
        .include_tmp = false,
    });
    defer compiled.deinit();

    const sh_path = blk: {
        std.Io.Dir.cwd().access(io, "/bin/sh", .{}) catch {
            std.Io.Dir.cwd().access(io, "/usr/bin/sh", .{}) catch return error.SkipZigTest;
            break :blk "/usr/bin/sh";
        };
        break :blk "/bin/sh";
    };

    var child = try forkApplyLandlockAndExec(
        io,
        &compiled,
        null,
        false,
        &.{},
        &.{},
        &[_][]const u8{ sh_path, "-c", check_closed },
        null,
        ws_root,
        .ignore,
    );
    defer child.deinit();
    try expectExitedZero(try waitpidRetry(child.pid));
}

test "allocArgvZ freeArgvZ round-trip with testing.allocator" {
    const allocator = std.testing.allocator;
    const argv_z = try allocArgvZ(allocator, &[_][]const u8{ "echo", "hello world", "" });
    freeArgvZ(allocator, argv_z);
}

test "allocEnvpZ freeEnvpZ owned map round-trip with testing.allocator" {
    const allocator = std.testing.allocator;
    var map = std.process.Environ.Map.init(allocator);
    defer map.deinit();
    try map.put("FOO", "bar");
    try map.put("EMPTY", "");
    const envp = try allocEnvpZ(allocator, &map);
    freeEnvpZ(allocator, envp);
}

test "freeDupeZ matches dupeZ allocation size under testing.allocator" {
    const allocator = std.testing.allocator;
    const z = try allocator.dupeZ(u8, "sentinel-free");
    freeDupeZ(allocator, z.ptr);
}

test "signalWorkspaceViewDaemon is a no-op for null and zero pids" {
    // Must not panic / raise on missing daemon records.
    signalWorkspaceViewDaemon(null);
    signalWorkspaceViewDaemon(0);
}

test "SpawnLease deinit clears workspace_view_daemon_pid without bare kill" {
    var lease: SpawnLease = .{
        .pid = -1,
        .allocator = std.testing.allocator,
        // Stale/non-existent pid: deinit clears the field only. Residual bare
        // kill after agent reap is intentionally not performed (PID reuse).
        .workspace_view_daemon_pid = 1 << 30,
    };
    lease.deinit();
    try std.testing.expect(lease.workspace_view_daemon_pid == null);
    try std.testing.expectEqual(@as(i32, -1), lease.pid);
}

test "protect-on landlock spawn fails closed without env map (no unprotected fallthrough)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, ".ryk");
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", allocator);
    defer allocator.free(root);

    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = root,
        .protect_workspace_secrets = true,
    });
    defer compiled.deinit();
    try std.testing.expect(compiled.protect_workspace_secrets);

    // Missing constructed env → ApplyFailed. Must not fall through to plain Landlock.
    const err = forkApplyLandlockAndExec(
        std.testing.io,
        &compiled,
        null,
        false,
        &.{},
        &.{},
        &[_][]const u8{"/bin/true"},
        null,
        root,
        .ignore,
    );
    try std.testing.expectError(error.ApplyFailed, err);
}

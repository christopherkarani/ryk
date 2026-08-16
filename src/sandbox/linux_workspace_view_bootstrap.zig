//! Hidden Linux self-exec bootstrap for the secret-boundary workspace view.
//!
//! This is not a public CLI surface. The parent passes a sealed request memfd
//! and a bounded response pipe; the bootstrap validates both before doing any
//! namespace, mount, Landlock, or agent-exec work.

const std = @import("std");
const builtin = @import("builtin");
const profile = @import("profile.zig");
const ipc = @import("workspace_view_ipc.zig");
const mount = @import("linux_workspace_view_mount.zig");
const workspace_view = @import("linux_workspace_view.zig");
const capabilities = @import("linux_capabilities.zig");
const landlock = @import("landlock.zig");
const session_tmp = @import("session_tmp.zig");
const fd_scrub = @import("fd_scrub.zig");

pub const internal_command = "__ryk_workspace_view_bootstrap";

pub const BootstrapFds = struct {
    request: i32,
    response: i32,
};

pub const ParseError = error{
    InvalidArguments,
    InvalidFd,
    ReservedFd,
    DuplicateFd,
};

pub fn parseFds(argv: []const []const u8) ParseError!BootstrapFds {
    if (argv.len != 4 or
        !std.mem.eql(u8, argv[0], "--request-fd") or
        !std.mem.eql(u8, argv[2], "--response-fd"))
    {
        return error.InvalidArguments;
    }

    const request = std.fmt.parseInt(i32, argv[1], 10) catch return error.InvalidFd;
    const response = std.fmt.parseInt(i32, argv[3], 10) catch return error.InvalidFd;
    if (request < 3 or response < 3) return error.ReservedFd;
    if (request == response) return error.DuplicateFd;
    return .{ .request = request, .response = response };
}

pub fn profileDigest(canonical_bytes: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(canonical_bytes, &digest, .{});
    return digest;
}

pub const MountIdentity = struct {
    mount_id: u64,
    mount_id_present: bool,
    is_mount_root: bool,
    is_directory: bool,
};

pub fn mountedViewIdentityIsValid(backing: MountIdentity, view: MountIdentity) bool {
    // Distinct mount ids + directory is the overmount proof. STATX_ATTR_MOUNT_ROOT
    // is not set by every FUSE implementation (Ubuntu 24.04 fuse3 included).
    return backing.mount_id_present and
        view.mount_id_present and
        backing.mount_id != view.mount_id and
        view.is_directory;
}

pub fn cwdIsWithinWorkspace(workspace_root: []const u8, cwd: []const u8) bool {
    return profile.isPathWithin(cwd, workspace_root);
}

/// Run the hidden bootstrap. Every failure is process-local and fail-closed;
/// callers must return this exit status directly without entering public CLI
/// dispatch.
pub fn command(allocator: std.mem.Allocator, argv: []const []const u8) u8 {
    const fds = parseFds(argv) catch return 127;
    if (builtin.os.tag != .linux) return 127;
    runLinux(allocator, fds) catch return 127;
    return 127;
}

const RunFailure = error{BootstrapFailed};

const ResponseContext = struct {
    fd: i32,
    cookie: [ipc.cookie_len]u8 = .{0} ** ipc.cookie_len,
    profile_hash: [ipc.profile_hash_len]u8 = .{0} ** ipc.profile_hash_len,
    proof: ipc.BootstrapProof = .{},

    fn fail(self: ResponseContext, reason: ipc.ReasonCode) RunFailure {
        writeBootstrapResponse(self.fd, .{
            .cookie = self.cookie,
            .profile_hash = self.profile_hash,
            .status = .failed,
            .reason = reason,
            .daemon_pid = 0,
            .proof = self.proof,
        });
        return error.BootstrapFailed;
    }
};

fn runLinux(allocator: std.mem.Allocator, fds: BootstrapFds) !void {
    const linux = std.os.linux;
    // Mutable so explicit closes can invalidate before `defer closeLinux` (M-6).
    var response: ResponseContext = .{ .fd = fds.response };
    defer closeLinux(response.fd);

    if (std.c.setpgid(0, 0) != 0) return response.fail(.internal_failure);

    const request_frame = readSealedRequest(allocator, fds.request) catch
        return response.fail(.malformed_request);
    defer {
        std.crypto.secureZero(u8, request_frame);
        allocator.free(request_frame);
    }
    closeLinux(fds.request);

    var request = ipc.decodeRequestAlloc(allocator, request_frame, .{}) catch
        return response.fail(.malformed_request);
    defer request.deinit();
    response.cookie = request.cookie;
    response.profile_hash = request.expected_profile_hash;

    if (!cwdIsWithinWorkspace(request.workspace_root, request.agent_cwd)) {
        return response.fail(.chdir_failed);
    }
    applyBootstrapStdio(request.stdio) catch return response.fail(.stdio_setup_failed);

    // Rebuild with the same CompileOptions the parent hashed (including launch
    // .exec grants). Protect-on is required by the wire protocol; the rebuild
    // mirrors sealed options including the request flag and profile hash check.
    var compiled = profile.compileProfile(allocator, .{
        .workspace_root = request.workspace_root,
        .control_roots = request.profile.control_roots,
        .include_tmp = request.profile.include_tmp,
        .exec_paths = request.profile.exec_paths,
        .ro_paths = request.profile.ro_paths,
        .host_rw_paths = request.profile.host_rw_paths,
        .protect_workspace_secrets = request.profile.protect_workspace_secrets,
    }) catch return response.fail(.profile_rebuild_failed);
    defer compiled.deinit();
    var io_runtime: std.Io.Threaded = .init_single_threaded;
    compiled.validateControlRootsOnDisk(io_runtime.io()) catch
        return response.fail(.profile_rebuild_failed);

    const rebuilt_hash = profileDigest(compiled.canonical_bytes);
    if (!std.crypto.timing_safe.eql(
        [ipc.profile_hash_len]u8,
        rebuilt_hash,
        request.expected_profile_hash,
    )) {
        return response.fail(.profile_hash_mismatch);
    }

    const backing_fd = mount.openBackingRoot(request.workspace_root) catch
        return response.fail(.backing_open_failed);
    var backing_owned = true;
    defer if (backing_owned) closeLinux(backing_fd);
    const backing_stat = statFd(backing_fd) orelse return response.fail(.backing_open_failed);

    const outer_uid: u32 = @intCast(linux.getuid());
    const outer_gid: u32 = @intCast(linux.getgid());
    mount.enterUserNamespace(outer_uid, outer_gid) catch
        return response.fail(.user_mapping_failed);
    mount.enterPrivateMountNamespace() catch
        return response.fail(.namespace_setup_failed);

    const fuse_fd = mount.openFuseDevice() catch
        return response.fail(.fuse_device_unavailable);
    var fuse_owned = true;
    defer if (fuse_owned) closeLinux(fuse_fd);
    mount.mountWorkspaceView(request.workspace_root, .{
        .fuse_fd = fuse_fd,
        .root_mode = backing_stat.mode,
        .owner_uid = 0,
        .owner_gid = 0,
    }) catch return response.fail(.fuse_mount_failed);

    const ready_pipe = openPipe() catch return response.fail(.fuse_daemon_start_failed);
    var ready_r = ready_pipe[0];
    var ready_w = ready_pipe[1];
    defer {
        closeLinux(ready_r);
        closeLinux(ready_w);
    }

    const expected_parent = linux.getpid();
    const fork_result = linux.fork();
    if (linux.errno(fork_result) != .SUCCESS) return response.fail(.fuse_daemon_start_failed);
    if (fork_result == 0) {
        // Daemon path: never continue with the parent's allocator (M-2).
        runFuseDaemon(
            fuse_fd,
            backing_fd,
            ready_r,
            ready_w,
            expected_parent,
        );
    }
    const daemon_pid: i32 = @intCast(fork_result);
    // Reap the daemon only on pre-handoff failure. Once the ready frame publishes
    // daemon_pid to the parent, residual waitpid-reap races PID reuse (fn-memory-1).
    var reap_daemon_on_err = true;
    errdefer if (reap_daemon_on_err) killAndReap(daemon_pid);

    closeLinux(ready_w);
    ready_w = -1;
    closeLinux(fuse_fd);
    fuse_owned = false;
    closeLinux(backing_fd);
    backing_owned = false;

    if (!waitForFuseReady(ready_r, daemon_pid)) return response.fail(.fuse_init_failed);
    response.proof.fuse_initialized = true;
    closeLinux(ready_r);
    ready_r = -1;

    var view_root_fd = mount.openBackingRoot(request.workspace_root) catch
        return response.fail(.mount_verification_failed);
    defer closeLinux(view_root_fd);
    // Do not use DONT_SYNC here: the path was just overmounted and cached
    // attributes can still describe the backing inode.
    const view_stat = statFdSynced(view_root_fd) orelse
        return response.fail(.mount_verification_failed);
    if (!mountedViewIdentityIsValid(
        mountIdentity(backing_stat),
        mountIdentity(view_stat),
    )) {
        return response.fail(.mount_verification_failed);
    }

    var cwd_fd = openPinnedCwd(view_root_fd, request.workspace_root, request.agent_cwd) catch
        return response.fail(.chdir_failed);
    defer closeLinux(cwd_fd);

    capabilities.lockdownCurrentProcess() catch
        return response.fail(.capability_lockdown_failed);

    // Enumerate after the FUSE overmount so `.ryk-tmp` is a visible RW leaf.
    // Parent prepare also creates it on the backing store; this is belt-and-suspenders
    // for empty-backpack workspaces that otherwise fail closed (no RW surface).
    if (!session_tmp.ensureWorkspaceSessionTmp(request.workspace_root))
        return response.fail(.landlock_attach_failed);
    // Claude `lstat`s `{TMPDIR}/claude-0` after attach. Parent pre-create lands
    // on the backing store; the leaf Claude sees is the FUSE view. Create that
    // exact leaf here (nofollow verify). Fail closed on a planted symlink.
    if (!session_tmp.requireClaudeCodeTmpLeavesFromEnvEntries(request.environ))
        return response.fail(.landlock_attach_failed);

    var plan = landlock.buildChildLandlockPlan(allocator, &compiled) catch
        return response.fail(.landlock_attach_failed);
    defer plan.deinit();
    const route_forcing = resolveRouteForcing(request.profile) catch
        return response.fail(.landlock_unavailable);
    landlock.applySelf(&compiled, &plan, route_forcing) catch
        return response.fail(.landlock_attach_failed);
    response.proof.landlock_attached = true;

    if (linux.fchdir(cwd_fd) != 0) return response.fail(.chdir_failed);
    const argv_z = allocNullTerminatedList(allocator, request.argv) catch
        return response.fail(.internal_failure);
    defer freeNullTerminatedList(allocator, argv_z);
    const envp_z = allocNullTerminatedList(allocator, request.environ) catch
        return response.fail(.internal_failure);
    defer freeNullTerminatedList(allocator, envp_z);

    const executable = argv_z[0] orelse return response.fail(.exec_preflight_failed);
    if (std.c.access(executable, 5) != 0) return response.fail(.exec_preflight_failed);

    // Explicit close then invalidate so `defer closeLinux` is a no-op (M-6).
    closeLinux(view_root_fd);
    view_root_fd = -1;
    closeLinux(cwd_fd);
    cwd_fd = -1;
    const keep_fds = [_]i32{ 0, 1, 2, response.fd };
    if (!fd_scrub.closeInheritedFdsAndVerify(&keep_fds)) {
        return response.fail(.fd_scrub_failed);
    }
    if (!descriptorIsClosed(fds.request) or
        !descriptorIsClosed(fuse_fd) or
        !descriptorIsClosed(backing_fd))
    {
        return response.fail(.fd_scrub_failed);
    }

    writeBootstrapResponse(response.fd, .{
        .cookie = request.cookie,
        .profile_hash = rebuilt_hash,
        .status = .ready,
        .reason = .none,
        .daemon_pid = @intCast(daemon_pid),
        .proof = response.proof,
    });
    // Parent now holds daemon_pid; do not waitpid-reap on post-ready failure.
    reap_daemon_on_err = false;
    closeLinux(response.fd);
    response.fd = -1;

    _ = linux.execve(executable, argv_z.ptr, envp_z.ptr);
    return response.fail(.exec_preflight_failed);
}

fn writeBootstrapResponse(fd: i32, response: ipc.BootstrapResponse) void {
    if (builtin.os.tag != .linux or fd < 0) return;
    var buffer: [ipc.response_frame_len]u8 = undefined;
    const frame = ipc.encodeResponse(&buffer, response) catch return;
    _ = writeAllLinux(fd, frame);
}

fn readSealedRequest(allocator: std.mem.Allocator, fd: i32) ![]u8 {
    if (builtin.os.tag != .linux or fd < 3) return error.InvalidRequestFd;
    const linux = std.os.linux;
    const seals_result = linux.fcntl(fd, linux.F.GET_SEALS, 0);
    if (linux.errno(seals_result) != .SUCCESS) return error.RequestNotSealed;
    const required_seals = linux.F.SEAL_SEAL |
        linux.F.SEAL_SHRINK |
        linux.F.SEAL_GROW |
        linux.F.SEAL_WRITE;
    if (seals_result & required_seals != required_seals) return error.RequestNotSealed;

    const end_result = linux.lseek(fd, 0, linux.SEEK.END);
    if (linux.errno(end_result) != .SUCCESS or
        end_result == 0 or
        end_result > (ipc.Limits{}).max_frame_bytes)
    {
        return error.InvalidRequestLength;
    }
    const rewind_result = linux.lseek(fd, 0, linux.SEEK.SET);
    if (linux.errno(rewind_result) != .SUCCESS or rewind_result != 0) {
        return error.InvalidRequestLength;
    }

    const bytes = try allocator.alloc(u8, end_result);
    errdefer {
        std.crypto.secureZero(u8, bytes);
        allocator.free(bytes);
    }
    var offset: usize = 0;
    while (offset < bytes.len) {
        const result = linux.read(fd, bytes[offset..].ptr, bytes.len - offset);
        switch (linux.errno(result)) {
            .SUCCESS => {
                if (result == 0 or result > bytes.len - offset) return error.TruncatedRequest;
                offset += result;
            },
            .INTR => continue,
            else => return error.RequestReadFailed,
        }
    }
    return bytes;
}

fn applyBootstrapStdio(stdio: ipc.StdioBehavior) !void {
    if (stdio == .inherit) return;
    const null_fd = std.c.open("/dev/null", .{ .ACCMODE = .RDWR, .CLOEXEC = true });
    if (null_fd < 0) return error.StdioFailed;
    defer _ = std.c.close(null_fd);
    if (std.c.dup2(null_fd, 0) < 0 or
        std.c.dup2(null_fd, 1) < 0 or
        std.c.dup2(null_fd, 2) < 0)
    {
        return error.StdioFailed;
    }
}

fn statFd(fd: i32) ?std.os.linux.Statx {
    return statFdWithFlags(fd, std.os.linux.AT.EMPTY_PATH | std.os.linux.AT.STATX_DONT_SYNC);
}

fn statFdSynced(fd: i32) ?std.os.linux.Statx {
    return statFdWithFlags(fd, std.os.linux.AT.EMPTY_PATH);
}

fn statFdWithFlags(fd: i32, flags: u32) ?std.os.linux.Statx {
    if (builtin.os.tag != .linux or fd < 0) return null;
    const linux = std.os.linux;
    var stat = std.mem.zeroes(linux.Statx);
    var mask = linux.STATX.BASIC_STATS;
    mask.MNT_ID = true;
    const result = linux.statx(
        fd,
        "",
        flags,
        mask,
        &stat,
    );
    if (linux.errno(result) != .SUCCESS) return null;
    return stat;
}

fn mountIdentity(stat: std.os.linux.Statx) MountIdentity {
    return .{
        .mount_id = stat.mnt_id,
        .mount_id_present = stat.mask.MNT_ID,
        .is_mount_root = stat.attributes.MOUNT_ROOT,
        .is_directory = stat.mode & 0o170000 == 0o040000,
    };
}

fn openPipe() ![2]i32 {
    var fds: [2]std.c.fd_t = undefined;
    if (std.c.pipe2(&fds, .{ .CLOEXEC = true }) != 0) return error.PipeFailed;
    return .{ @intCast(fds[0]), @intCast(fds[1]) };
}

fn runFuseDaemon(
    fuse_fd: i32,
    backing_fd: i32,
    ready_r: i32,
    ready_w: i32,
    expected_parent: i32,
) noreturn {
    const linux = std.os.linux;
    closeLinux(ready_r);
    const pdeath = linux.prctl(
        @intFromEnum(linux.PR.SET_PDEATHSIG),
        @intFromEnum(linux.SIG.KILL),
        0,
        0,
        0,
    );
    if (linux.errno(pdeath) != .SUCCESS or linux.getppid() != expected_parent) {
        linux.exit(127);
    }
    hardenDaemonInspection() catch linux.exit(127);

    // The daemon never reports to agent stdio and keeps only its three owned
    // descriptors plus inert `/dev/null` stdio.
    redirectDaemonStdio() catch linux.exit(127);
    const keep = [_]i32{ 0, 1, 2, fuse_fd, backing_fd, ready_w };
    fd_scrub.closeInheritedFds(&keep);
    capabilities.lockdownCurrentProcess() catch linux.exit(127);

    // Fork-without-exec: must not share heap metadata with the bootstrap parent
    // (DebugAllocator / GPA free lists). Parent keeps its own allocator; the
    // daemon uses page_allocator for all post-fork serve allocations (M-2).
    workspace_view.serve(
        std.heap.page_allocator,
        fuse_fd,
        backing_fd,
        ready_w,
        .{},
    ) catch linux.exit(127);
    closeLinux(ready_w);
    linux.exit(0);
}

fn hardenDaemonInspection() !void {
    const linux = std.os.linux;
    const set_result = linux.prctl(@intFromEnum(linux.PR.SET_DUMPABLE), 0, 0, 0, 0);
    if (linux.errno(set_result) != .SUCCESS) return error.DumpableLockFailed;
    const get_result = linux.prctl(@intFromEnum(linux.PR.GET_DUMPABLE), 0, 0, 0, 0);
    if (linux.errno(get_result) != .SUCCESS or get_result != 0) {
        return error.DumpableLockFailed;
    }
}

fn redirectDaemonStdio() !void {
    const null_fd = std.c.open("/dev/null", .{ .ACCMODE = .RDWR, .CLOEXEC = true });
    if (null_fd < 0) return error.StdioFailed;
    defer _ = std.c.close(null_fd);
    if (std.c.dup2(null_fd, 0) < 0 or
        std.c.dup2(null_fd, 1) < 0 or
        std.c.dup2(null_fd, 2) < 0)
    {
        return error.StdioFailed;
    }
}

fn waitForFuseReady(read_fd: i32, daemon_pid: i32) bool {
    if (comptime builtin.os.tag != .linux) return false;
    // One remaining-deadline budget (do not restart a full 10s on EINTR).
    const deadline_ms: i64 = 10_000;
    const start_ms = fuseReadyMonotonicMs() orelse return false;
    while (true) {
        const now_ms = fuseReadyMonotonicMs() orelse return false;
        if (now_ms < start_ms) return false;
        const elapsed = now_ms - start_ms;
        if (elapsed >= deadline_ms) return false;
        const remaining: i32 = @intCast(deadline_ms - elapsed);
        var poll_fds = [_]std.posix.pollfd{.{
            .fd = read_fd,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        const ready_rc = std.c.poll(poll_fds[0..].ptr, poll_fds.len, remaining);
        if (ready_rc < 0) {
            if (std.c.errno(ready_rc) == .INTR) continue;
            return false;
        }
        const ready: usize = @intCast(ready_rc);
        if (ready == 0) return false;
        if (ready != 1) return false;

        var byte: [1]u8 = undefined;
        while (true) {
            const count = std.c.read(read_fd, &byte, 1);
            if (count == 1) return byte[0] == 1 and processIsAlive(daemon_pid);
            if (std.c.errno(count) == .INTR) continue;
            return false;
        }
    }
}

fn fuseReadyMonotonicMs() ?i64 {
    if (comptime builtin.os.tag != .linux) return null;
    var ts: std.c.timespec = undefined;
    if (std.c.clock_gettime(std.c.CLOCK.MONOTONIC, &ts) != 0) return null;
    return @as(i64, @intCast(ts.sec)) * std.time.ms_per_s +
        @divTrunc(@as(i64, @intCast(ts.nsec)), std.time.ns_per_ms);
}

fn processIsAlive(pid: i32) bool {
    if (pid <= 0 or builtin.os.tag != .linux) return false;
    const linux = std.os.linux;
    const result = linux.kill(pid, @enumFromInt(0));
    return switch (linux.errno(result)) {
        .SUCCESS, .PERM => true,
        else => false,
    };
}

test "Linux FUSE readiness clock is monotonic and available" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const first = fuseReadyMonotonicMs() orelse return error.TestUnexpectedResult;
    const second = fuseReadyMonotonicMs() orelse return error.TestUnexpectedResult;
    try std.testing.expect(second >= first);
}

const OpenHow = extern struct {
    flags: u64,
    mode: u64,
    resolve: u64,
};

fn openPinnedCwd(
    view_root_fd: i32,
    workspace_root: []const u8,
    cwd: []const u8,
) !i32 {
    if (!cwdIsWithinWorkspace(workspace_root, cwd)) return error.CwdOutsideWorkspace;
    const linux = std.os.linux;
    if (std.mem.eql(u8, workspace_root, cwd)) {
        const result = linux.fcntl(view_root_fd, linux.F.DUPFD_CLOEXEC, 3);
        if (linux.errno(result) != .SUCCESS or result > std.math.maxInt(i32)) {
            return error.CwdOpenFailed;
        }
        return @intCast(result);
    }

    const relative = cwd[workspace_root.len + 1 ..];
    if (profile.hasWorkspaceSecretComponent(relative)) return error.CwdSecretPath;
    if (relative.len == 0 or relative.len >= std.fs.max_path_bytes or
        std.mem.indexOfScalar(u8, relative, 0) != null)
    {
        return error.CwdOpenFailed;
    }
    var path_buffer: [std.fs.max_path_bytes:0]u8 = undefined;
    @memcpy(path_buffer[0..relative.len], relative);
    path_buffer[relative.len] = 0;
    const how: OpenHow = .{
        .flags = (1 << @bitOffsetOf(linux.O, "PATH")) |
            (1 << @bitOffsetOf(linux.O, "DIRECTORY")) |
            (1 << @bitOffsetOf(linux.O, "NOFOLLOW")) |
            (1 << @bitOffsetOf(linux.O, "CLOEXEC")),
        .mode = 0,
        .resolve = 0x08 | 0x02 | 0x01, // BENEATH | NO_MAGICLINKS | NO_XDEV
    };
    const result = linux.syscall4(
        .openat2,
        @bitCast(@as(isize, view_root_fd)),
        @intFromPtr(path_buffer[0..relative.len :0].ptr),
        @intFromPtr(&how),
        @sizeOf(OpenHow),
    );
    if (linux.errno(result) != .SUCCESS or result > std.math.maxInt(i32)) {
        return error.CwdOpenFailed;
    }
    return @intCast(result);
}

fn resolveRouteForcing(options: ipc.OwnedProfileOptions) !?landlock.RouteForcing {
    if (options.network_proxy_port) |port| {
        if (!landlock.supportsTcpRouteForcing()) {
            if (options.require_network_route_forcing) return error.RouteForcingUnavailable;
            return null;
        }
        return .{ .proxy_port = port };
    }
    if (options.require_network_route_forcing) return error.RouteForcingUnavailable;
    return null;
}

fn allocNullTerminatedList(
    allocator: std.mem.Allocator,
    values: []const []const u8,
) ![:null]?[*:0]const u8 {
    const list = try allocator.alloc(?[*:0]const u8, values.len + 1);
    @memset(list, null);
    errdefer {
        for (list[0..values.len]) |item| {
            if (item) |z| allocator.free(std.mem.span(z));
        }
        allocator.free(list);
    }
    for (values, 0..) |value, index| {
        list[index] = (try allocator.dupeZ(u8, value)).ptr;
    }
    list[values.len] = null;
    return list[0..values.len :null];
}

fn freeNullTerminatedList(
    allocator: std.mem.Allocator,
    values: [:null]?[*:0]const u8,
) void {
    for (values) |item| {
        if (item) |z| {
            const slice: [:0]const u8 = std.mem.span(z);
            allocator.free(slice);
        }
    }
    const base: [*]?[*:0]const u8 = @ptrCast(values.ptr);
    allocator.free(base[0 .. values.len + 1]);
}

fn descriptorIsClosed(fd: i32) bool {
    if (fd < 0) return true;
    if (builtin.os.tag != .linux) return false;
    const linux = std.os.linux;
    const result = linux.fcntl(fd, linux.F.GETFD, 0);
    return linux.errno(result) == .BADF;
}

fn writeAllLinux(fd: i32, bytes: []const u8) bool {
    if (builtin.os.tag != .linux or fd < 0) return false;
    const linux = std.os.linux;
    var offset: usize = 0;
    while (offset < bytes.len) {
        const result = linux.write(fd, bytes[offset..].ptr, bytes.len - offset);
        switch (linux.errno(result)) {
            .SUCCESS => {
                if (result == 0 or result > bytes.len - offset) return false;
                offset += result;
            },
            .INTR => continue,
            else => return false,
        }
    }
    return true;
}

fn closeLinux(fd: i32) void {
    if (builtin.os.tag == .linux and fd >= 0) _ = std.os.linux.close(fd);
}

fn killAndReap(pid: i32) void {
    if (builtin.os.tag != .linux or pid <= 0) return;
    const linux = std.os.linux;
    _ = linux.kill(pid, .KILL);
    var status: c_int = 0;
    while (true) {
        const result = std.c.waitpid(pid, &status, 0);
        if (result >= 0) return;
        if (std.c.errno(result) != .INTR) return;
    }
}

test "hidden bootstrap accepts only exact distinct non-stdio descriptors" {
    try std.testing.expectEqual(
        BootstrapFds{ .request = 7, .response = 9 },
        try parseFds(&.{ "--request-fd", "7", "--response-fd", "9" }),
    );
    try std.testing.expectError(
        error.InvalidArguments,
        parseFds(&.{ "--response-fd", "9", "--request-fd", "7" }),
    );
    try std.testing.expectError(
        error.InvalidArguments,
        parseFds(&.{ "--request-fd", "7", "--response-fd" }),
    );
    try std.testing.expectError(
        error.InvalidFd,
        parseFds(&.{ "--request-fd", "seven", "--response-fd", "9" }),
    );
    try std.testing.expectError(
        error.ReservedFd,
        parseFds(&.{ "--request-fd", "0", "--response-fd", "9" }),
    );
    try std.testing.expectError(
        error.DuplicateFd,
        parseFds(&.{ "--request-fd", "7", "--response-fd", "7" }),
    );
}

test "bootstrap profile digest is binary SHA-256 not printable profile text" {
    const digest = profileDigest("workspace-profile");
    var hex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&hex, "{x}", .{digest}) catch unreachable;
    try std.testing.expectEqualStrings(
        "e3e257ddea4bdcc0a1517841bb394e665070e7c83383b3443960f0d99c300777",
        &hex,
    );
}

test "bootstrap accepts only a distinct pinned mount root and contained cwd" {
    const backing: MountIdentity = .{
        .mount_id = 11,
        .mount_id_present = true,
        .is_mount_root = false,
        .is_directory = true,
    };
    const view: MountIdentity = .{
        .mount_id = 12,
        .mount_id_present = true,
        .is_mount_root = true,
        .is_directory = true,
    };
    try std.testing.expect(mountedViewIdentityIsValid(backing, view));

    var invalid = view;
    invalid.mount_id = backing.mount_id;
    try std.testing.expect(!mountedViewIdentityIsValid(backing, invalid));
    invalid = view;
    invalid.mount_id_present = false;
    try std.testing.expect(!mountedViewIdentityIsValid(backing, invalid));
    invalid = view;
    invalid.is_directory = false;
    try std.testing.expect(!mountedViewIdentityIsValid(backing, invalid));
    // FUSE may omit STATX_ATTR_MOUNT_ROOT; distinct mount ids still count.
    invalid = view;
    invalid.is_mount_root = false;
    try std.testing.expect(mountedViewIdentityIsValid(backing, invalid));

    try std.testing.expect(cwdIsWithinWorkspace("/work/app", "/work/app"));
    try std.testing.expect(cwdIsWithinWorkspace("/work/app", "/work/app/src"));
    try std.testing.expect(!cwdIsWithinWorkspace("/work/app", "/work/application"));
    try std.testing.expect(!cwdIsWithinWorkspace("/work/app", "/work"));
}

test "hidden bootstrap command fails closed off Linux" {
    if (@import("builtin").os.tag == .linux) return error.SkipZigTest;
    try std.testing.expectEqual(
        @as(u8, 127),
        command(std.testing.allocator, &.{ "--request-fd", "7", "--response-fd", "9" }),
    );
}

test "Linux hidden bootstrap production path compile-checks behind invalid descriptors" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    try std.testing.expectEqual(
        @as(u8, 127),
        command(std.testing.allocator, &.{ "--request-fd", "0", "--response-fd", "1" }),
    );
}

//! Linux parent-side self-exec launcher for protected workspace views.
//!
//! The agent environment and profile travel only in a bounded, sealed memfd.
//! The immediate child receives an empty bootstrap environment and only the
//! request/response descriptors in addition to stdio.

const std = @import("std");
const builtin = @import("builtin");

const bootstrap = @import("linux_workspace_view_bootstrap.zig");
const ipc = @import("workspace_view_ipc.zig");
const profile_mod = @import("profile.zig");

pub const handshake_timeout_ms: i32 = 10_000;

const self_executable: [:0]const u8 = "/proc/self/exe";
const request_fd_option: [:0]const u8 = "--request-fd";
const response_fd_option: [:0]const u8 = "--response-fd";
const empty_bootstrap_environment = [_:null]?[*:0]const u8{};

pub const ProfileInputs = struct {
    include_tmp: bool = false,
    ro_paths: []const []const u8 = &.{},
    host_rw_paths: []const []const u8 = &.{},
    network_proxy_port: ?u16 = null,
    require_network_route_forcing: bool = false,
};

/// Collect absolute `.exec` grant paths from a parent-compiled profile so the
/// bootstrap rebuild can seal the same launch grants into the wire request.
///
/// Errors with `error.TooManyExecPaths` when the profile has more `.exec` grants
/// than `buffer.len` (must match `ipc.Limits.max_exec_paths`) so overflow is not
/// silently truncated into a later `ProfileHashMismatch`.
pub fn execPathsFromCompiled(
    compiled: *const profile_mod.CompiledProfile,
    buffer: [][]const u8,
) error{TooManyExecPaths}![]const []const u8 {
    var count: usize = 0;
    for (compiled.grants) |grant| {
        if (grant.mode != .exec) continue;
        if (count >= buffer.len) return error.TooManyExecPaths;
        buffer[count] = grant.path;
        count += 1;
    }
    return buffer[0..count];
}

pub const LaunchRequest = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    compiled: *const profile_mod.CompiledProfile,
    profile: ProfileInputs = .{},
    argv: []const []const u8,
    environment: *const std.process.Environ.Map,
    cwd: []const u8,
    stdio: ipc.StdioBehavior,
    limits: ipc.Limits = .{},
};

pub const SpawnedWorkspaceView = struct {
    /// The bootstrap execs the agent in place, so this is both identities.
    agent_bootstrap_pid: i32,
    daemon_pid: u32,
};

const OwnedEnvironment = struct {
    allocator: std.mem.Allocator,
    entries: [][]const u8,

    fn deinit(self: *OwnedEnvironment) void {
        for (self.entries) |entry| {
            std.crypto.secureZero(u8, @constCast(entry));
            self.allocator.free(entry);
        }
        self.allocator.free(self.entries);
        self.entries = &.{};
    }
};

const Operations = struct {
    context: *anyopaque,
    randomSecure: *const fn (*anyopaque, []u8) anyerror!void,
    createSealedRequest: *const fn (*anyopaque, []const u8) anyerror!i32,
    createResponsePipe: *const fn (*anyopaque) anyerror![2]i32,
    forkExec: *const fn (*anyopaque, i32, i32, i32) anyerror!i32,
    closeFd: *const fn (*anyopaque, i32) void,
    readResponse: *const fn (*anyopaque, i32, i32, []u8) anyerror!void,
    killAndReap: *const fn (*anyopaque, i32) void,
};

/// Self-exec the current `ryk` image as the hidden Linux bootstrap and wait for
/// a matching FUSE+Landlock ready proof. This function never inherits the host
/// environment: `request.environment` is encoded explicitly for the eventual
/// agent while the bootstrap itself receives an empty environment.
pub fn spawnWorkspaceView(request: LaunchRequest) !SpawnedWorkspaceView {
    if (builtin.os.tag != .linux) return error.Unsupported;
    var context: ProductionContext = .{ .io = request.io };
    return spawnWithOperations(request, productionOperations(&context));
}

fn spawnWithOperations(request: LaunchRequest, operations: Operations) !SpawnedWorkspaceView {
    if (request.argv.len == 0 or
        request.argv[0].len == 0 or
        request.argv[0][0] != '/')
    {
        return error.UnresolvedExecutable;
    }

    var environment = try environmentEntries(request.allocator, request.environment);
    defer environment.deinit();

    var cookie: [ipc.cookie_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &cookie);
    try operations.randomSecure(operations.context, &cookie);

    var profile_hash: [ipc.profile_hash_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &profile_hash);
    std.crypto.hash.sha2.Sha256.hash(request.compiled.canonical_bytes, &profile_hash, .{});

    // Seal parent `.exec` grants so bootstrap rebuild matches expected_profile_hash.
    // Cap matches default ipc.Limits.max_exec_paths (64).
    var exec_path_buf: [64][]const u8 = undefined;
    const exec_paths = try execPathsFromCompiled(request.compiled, exec_path_buf[0..]);

    var frame = try ipc.encodeRequestAlloc(request.allocator, .{
        .cookie = cookie,
        .expected_profile_hash = profile_hash,
        .workspace_root = request.compiled.workspace_root,
        .agent_cwd = request.cwd,
        .argv = request.argv,
        .environ = environment.entries,
        .profile = .{
            .include_tmp = request.profile.include_tmp,
            .control_roots = request.compiled.control_roots,
            .exec_paths = exec_paths,
            .ro_paths = request.profile.ro_paths,
            .host_rw_paths = request.profile.host_rw_paths,
            .network_proxy_port = request.profile.network_proxy_port,
            .require_network_route_forcing = request.profile.require_network_route_forcing,
            .protect_workspace_secrets = request.compiled.protect_workspace_secrets,
        },
        .stdio = request.stdio,
    }, request.limits);
    defer frame.deinit();

    var request_fd = try operations.createSealedRequest(operations.context, frame.bytes);
    defer if (request_fd >= 0) operations.closeFd(operations.context, request_fd);
    if (request_fd < 3) return error.InvalidTransportDescriptor;

    const pipe = try operations.createResponsePipe(operations.context);
    var response_read = pipe[0];
    var response_write = pipe[1];
    defer if (response_read >= 0) operations.closeFd(operations.context, response_read);
    defer if (response_write >= 0) operations.closeFd(operations.context, response_write);
    if (response_read < 3 or
        response_write < 3 or
        response_read == response_write or
        response_read == request_fd or
        response_write == request_fd)
    {
        return error.InvalidTransportDescriptor;
    }

    const pid = try operations.forkExec(operations.context, request_fd, response_read, response_write);
    if (pid <= 0) return error.InvalidChildPid;
    var child_live = true;
    defer if (child_live) operations.killAndReap(operations.context, pid);

    operations.closeFd(operations.context, request_fd);
    request_fd = -1;
    operations.closeFd(operations.context, response_write);
    response_write = -1;

    var response_bytes: [ipc.response_frame_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &response_bytes);
    try operations.readResponse(
        operations.context,
        response_read,
        handshake_timeout_ms,
        &response_bytes,
    );
    operations.closeFd(operations.context, response_read);
    response_read = -1;

    const response = try ipc.decodeResponse(&response_bytes);
    const checks = checkResponse(response, cookie, profile_hash);
    if (!checks.identity_matches) return error.InvalidReadyResponse;
    if (response.status == .failed) {
        if (ipc.reasonAsError(response.reason)) |failure| return failure;
    }
    if (!checks.ready_matches) return error.InvalidReadyResponse;

    child_live = false;
    return .{
        .agent_bootstrap_pid = pid,
        .daemon_pid = response.daemon_pid,
    };
}

fn environmentEntries(
    allocator: std.mem.Allocator,
    environment: *const std.process.Environ.Map,
) !OwnedEnvironment {
    const entries = try allocator.alloc([]const u8, environment.count());
    errdefer allocator.free(entries);
    var initialized: usize = 0;
    errdefer {
        for (entries[0..initialized]) |entry| {
            std.crypto.secureZero(u8, @constCast(entry));
            allocator.free(entry);
        }
    }

    var iterator = environment.iterator();
    while (iterator.next()) |entry| {
        entries[initialized] = try std.fmt.allocPrint(
            allocator,
            "{s}={s}",
            .{ entry.key_ptr.*, entry.value_ptr.* },
        );
        initialized += 1;
    }
    return .{ .allocator = allocator, .entries = entries };
}

const ResponseChecks = struct {
    identity_matches: bool,
    ready_matches: bool,
};

/// Both identity comparisons and every fixed ready-proof field are evaluated
/// before the caller branches, avoiding a cookie-first/hash-first oracle.
fn checkResponse(
    response: ipc.BootstrapResponse,
    cookie: [ipc.cookie_len]u8,
    profile_hash: [ipc.profile_hash_len]u8,
) ResponseChecks {
    const identity_matches = response.matchesIdentity(cookie, profile_hash);
    var rejected: u8 = @intFromBool(!identity_matches);
    rejected |= @intFromBool(response.status != .ready);
    rejected |= @intFromBool(response.reason != .none);
    rejected |= @intFromBool(response.daemon_pid == 0);
    rejected |= @intFromBool(!response.proof.fuse_initialized);
    rejected |= @intFromBool(!response.proof.landlock_attached);
    return .{
        .identity_matches = identity_matches,
        .ready_matches = rejected == 0,
    };
}

const ProductionContext = struct {
    io: std.Io,
};

fn productionOperations(context: *ProductionContext) Operations {
    return .{
        .context = context,
        .randomSecure = productionRandomSecure,
        .createSealedRequest = productionCreateSealedRequest,
        .createResponsePipe = productionCreateResponsePipe,
        .forkExec = productionForkExec,
        .closeFd = productionCloseFd,
        .readResponse = productionReadResponse,
        .killAndReap = productionKillAndReap,
    };
}

fn productionRandomSecure(context: *anyopaque, output: []u8) anyerror!void {
    const self: *ProductionContext = @ptrCast(@alignCast(context));
    try self.io.randomSecure(output);
}

fn productionCreateSealedRequest(_: *anyopaque, frame: []const u8) anyerror!i32 {
    if (comptime builtin.os.tag != .linux) return error.Unsupported;
    const linux = std.os.linux;
    const create_rc = linux.memfd_create(
        "ryk-workspace-view",
        requestMemfdFlags(),
    );
    if (linux.errno(create_rc) != .SUCCESS) return error.RequestTransportFailed;
    const fd: i32 = @intCast(create_rc);
    errdefer productionCloseFd(undefined, fd);

    var offset: usize = 0;
    while (offset < frame.len) {
        const rc = linux.write(fd, frame.ptr + offset, frame.len - offset);
        switch (linux.errno(rc)) {
            .SUCCESS => {
                if (rc == 0) return error.RequestTransportFailed;
                offset += rc;
            },
            .INTR => continue,
            else => return error.RequestTransportFailed,
        }
    }
    const seek_rc = linux.lseek(fd, 0, 0);
    if (linux.errno(seek_rc) != .SUCCESS) return error.RequestTransportFailed;

    const seals = requestMemfdSeals();
    const seal_rc = linux.fcntl(fd, linux.F.ADD_SEALS, seals);
    if (linux.errno(seal_rc) != .SUCCESS) return error.RequestTransportFailed;
    const get_rc = linux.fcntl(fd, linux.F.GET_SEALS, 0);
    if (linux.errno(get_rc) != .SUCCESS or get_rc & seals != seals) {
        return error.RequestTransportFailed;
    }
    return fd;
}

fn productionCreateResponsePipe(_: *anyopaque) anyerror![2]i32 {
    if (comptime builtin.os.tag != .linux) return error.Unsupported;
    var fds: [2]i32 = undefined;
    const rc = std.os.linux.pipe2(&fds, .{ .CLOEXEC = true });
    if (std.os.linux.errno(rc) != .SUCCESS) return error.ResponsePipeFailed;
    return fds;
}

fn productionForkExec(
    _: *anyopaque,
    request_fd: i32,
    response_read: i32,
    response_write: i32,
) anyerror!i32 {
    if (comptime builtin.os.tag != .linux) return error.Unsupported;
    const linux = std.os.linux;
    var request_text_buffer: [16]u8 = undefined;
    var response_text_buffer: [16]u8 = undefined;
    const hidden = formatHiddenArguments(
        request_fd,
        response_write,
        &request_text_buffer,
        &response_text_buffer,
    ) catch return error.BootstrapExecFailed;
    const argv = [_:null]?[*:0]const u8{
        self_executable.ptr,
        bootstrap.internal_command,
        request_fd_option.ptr,
        hidden.request.ptr,
        response_fd_option.ptr,
        hidden.response.ptr,
    };

    const fork_rc = linux.fork();
    if (linux.errno(fork_rc) != .SUCCESS) return error.ForkFailed;
    if (fork_rc == 0) {
        _ = linux.close(response_read);
        if (linux.errno(linux.setpgid(0, 0)) != .SUCCESS or
            !clearCloseOnExec(request_fd) or
            !clearCloseOnExec(response_write))
        {
            linux.exit(127);
        }
        if (!scrubChildDescriptors(request_fd, response_write)) linux.exit(127);
        _ = linux.execve(self_executable.ptr, &argv, &empty_bootstrap_environment);
        linux.exit(127);
    }
    return @intCast(fork_rc);
}

fn requestMemfdFlags() u32 {
    if (comptime builtin.os.tag != .linux) return 0x0001 | 0x0002;
    return std.os.linux.MFD.CLOEXEC | std.os.linux.MFD.ALLOW_SEALING;
}

fn requestMemfdSeals() usize {
    if (comptime builtin.os.tag != .linux) return 0x0001 | 0x0002 | 0x0004 | 0x0008;
    const linux = std.os.linux;
    return linux.F.SEAL_WRITE |
        linux.F.SEAL_GROW |
        linux.F.SEAL_SHRINK |
        linux.F.SEAL_SEAL;
}

const FormattedHiddenArguments = struct {
    request: [:0]u8,
    response: [:0]u8,
};

fn formatHiddenArguments(
    request_fd: i32,
    response_fd: i32,
    request_buffer: []u8,
    response_buffer: []u8,
) !FormattedHiddenArguments {
    if (request_fd < 3 or response_fd < 3 or request_fd == response_fd) {
        return error.InvalidTransportDescriptor;
    }
    return .{
        .request = try std.fmt.bufPrintZ(request_buffer, "{d}", .{request_fd}),
        .response = try std.fmt.bufPrintZ(response_buffer, "{d}", .{response_fd}),
    };
}

fn clearCloseOnExec(fd: i32) bool {
    if (comptime builtin.os.tag != .linux) return false;
    const rc = std.os.linux.fcntl(fd, std.os.linux.F.SETFD, 0);
    return std.os.linux.errno(rc) == .SUCCESS;
}

/// Linux workspace-view launches already require Landlock-era kernels, newer
/// than `close_range`. Fail closed instead of falling back to allocation or
/// directory enumeration in the immediate post-fork child.
fn scrubChildDescriptors(request_fd: i32, response_fd: i32) bool {
    if (comptime builtin.os.tag != .linux) return false;
    var ranges: [3][2]i32 = undefined;
    const range_count = fillChildCloseRanges(request_fd, response_fd, &ranges);
    for (ranges[0..range_count]) |range| {
        if (!closeDescriptorRange(range[0], range[1])) return false;
    }
    return true;
}

fn fillChildCloseRanges(
    request_fd: i32,
    response_fd: i32,
    output: *[3][2]i32,
) usize {
    var keep = [_]i32{ 0, 1, 2, request_fd, response_fd };
    var index: usize = 1;
    while (index < keep.len) : (index += 1) {
        const value = keep[index];
        var insertion = index;
        while (insertion > 0 and keep[insertion - 1] > value) : (insertion -= 1) {
            keep[insertion] = keep[insertion - 1];
        }
        keep[insertion] = value;
    }

    var cursor: i32 = 0;
    var count: usize = 0;
    for (keep) |fd| {
        if (cursor < fd) {
            output[count] = .{ cursor, fd - 1 };
            count += 1;
        }
        cursor = fd + 1;
    }
    output[count] = .{ cursor, -1 };
    return count + 1;
}

fn closeDescriptorRange(first: i32, last: i32) bool {
    if (comptime builtin.os.tag != .linux) return false;
    const rc = std.os.linux.close_range(first, last, .{ .UNSHARE = false, .CLOEXEC = false });
    return std.os.linux.errno(rc) == .SUCCESS;
}

fn productionCloseFd(_: *anyopaque, fd: i32) void {
    if (fd < 0) return;
    if (comptime builtin.os.tag == .linux) {
        _ = std.os.linux.close(fd);
    }
}

fn productionReadResponse(
    _: *anyopaque,
    fd: i32,
    timeout_ms: i32,
    output: []u8,
) anyerror!void {
    if (comptime builtin.os.tag != .linux) return error.Unsupported;
    const linux = std.os.linux;
    const start = monotonicMilliseconds() orelse return error.HandshakeClockFailed;
    const deadline = std.math.add(i64, start, timeout_ms) catch return error.HandshakeClockFailed;
    var offset: usize = 0;

    while (offset < output.len) {
        const now = monotonicMilliseconds() orelse return error.HandshakeClockFailed;
        const remaining_i64 = deadline - now;
        if (remaining_i64 <= 0) return error.HandshakeTimeout;
        const remaining: i32 = @intCast(@min(remaining_i64, std.math.maxInt(i32)));
        var poll_fd = [_]linux.pollfd{.{
            .fd = fd,
            .events = linux.POLL.IN,
            .revents = 0,
        }};
        const poll_rc = linux.poll(&poll_fd, poll_fd.len, remaining);
        switch (linux.errno(poll_rc)) {
            .SUCCESS => if (poll_rc == 0) return error.HandshakeTimeout,
            .INTR => continue,
            else => return error.HandshakeFailed,
        }

        const read_rc = linux.read(fd, output.ptr + offset, output.len - offset);
        switch (linux.errno(read_rc)) {
            .SUCCESS => {
                if (read_rc == 0) return error.HandshakeFailed;
                offset += read_rc;
            },
            .INTR => continue,
            else => return error.HandshakeFailed,
        }
    }
}

fn monotonicMilliseconds() ?i64 {
    if (comptime builtin.os.tag != .linux) return null;
    var timestamp: std.os.linux.timespec = undefined;
    const rc = std.os.linux.clock_gettime(.MONOTONIC, &timestamp);
    if (std.os.linux.errno(rc) != .SUCCESS) return null;
    return @as(i64, @intCast(timestamp.sec)) * std.time.ms_per_s +
        @divTrunc(@as(i64, @intCast(timestamp.nsec)), std.time.ns_per_ms);
}

fn productionKillAndReap(_: *anyopaque, pid: i32) void {
    if (pid <= 0) return;
    if (comptime builtin.os.tag == .linux) {
        const linux = std.os.linux;
        _ = linux.kill(-pid, .KILL);
        _ = linux.kill(pid, .KILL);
        var status: u32 = 0;
        while (true) {
            const rc = linux.waitpid(pid, &status, 0);
            if (linux.errno(rc) == .INTR) continue;
            break;
        }
    }
}

test "parent sends sealed bounded request and promotes only matching ready response" {
    const Mock = struct {
        const Self = @This();
        const ResponseMode = enum {
            ready,
            timeout,
            wrong_identity,
            bootstrap_failure,
        };

        cookie: [ipc.cookie_len]u8 = [_]u8{0x5a} ** ipc.cookie_len,
        profile_hash: [ipc.profile_hash_len]u8,
        events: std.ArrayList(u8) = .empty,
        response_mode: ResponseMode = .ready,

        fn operations(self: *Self) Operations {
            return .{
                .context = self,
                .randomSecure = Self.randomSecure,
                .createSealedRequest = Self.createSealedRequest,
                .createResponsePipe = Self.createResponsePipe,
                .forkExec = Self.forkExec,
                .closeFd = Self.closeFd,
                .readResponse = Self.readResponse,
                .killAndReap = Self.killAndReap,
            };
        }

        fn randomSecure(context: *anyopaque, output: []u8) anyerror!void {
            const self: *Self = @ptrCast(@alignCast(context));
            @memcpy(output, &self.cookie);
            try self.events.append(std.testing.allocator, 'R');
        }

        fn createSealedRequest(context: *anyopaque, frame: []const u8) anyerror!i32 {
            const self: *Self = @ptrCast(@alignCast(context));
            try std.testing.expect(frame.len <= (ipc.Limits{}).max_frame_bytes);
            var decoded = try ipc.decodeRequestAlloc(std.testing.allocator, frame, .{});
            defer decoded.deinit();
            try std.testing.expectEqualStrings("/work", decoded.workspace_root);
            try std.testing.expectEqualStrings("/work", decoded.agent_cwd);
            try std.testing.expectEqual(@as(usize, 1), decoded.environ.len);
            try std.testing.expectEqualStrings("PATH=/usr/bin", decoded.environ[0]);
            try std.testing.expect(decoded.profile.protect_workspace_secrets);
            try self.events.append(std.testing.allocator, 'M');
            return 19;
        }

        fn createResponsePipe(context: *anyopaque) anyerror![2]i32 {
            const self: *Self = @ptrCast(@alignCast(context));
            try self.events.append(std.testing.allocator, 'P');
            return .{ 20, 21 };
        }

        fn forkExec(context: *anyopaque, request_fd: i32, response_read: i32, response_write: i32) anyerror!i32 {
            const self: *Self = @ptrCast(@alignCast(context));
            try std.testing.expectEqual(@as(i32, 19), request_fd);
            try std.testing.expectEqual(@as(i32, 20), response_read);
            try std.testing.expectEqual(@as(i32, 21), response_write);
            try self.events.append(std.testing.allocator, 'F');
            return 42;
        }

        fn closeFd(context: *anyopaque, fd: i32) void {
            const self: *Self = @ptrCast(@alignCast(context));
            self.events.append(std.testing.allocator, switch (fd) {
                19 => 'm',
                20 => 'r',
                21 => 'w',
                else => '?',
            }) catch unreachable;
        }

        fn readResponse(context: *anyopaque, fd: i32, timeout_ms: i32, output: []u8) anyerror!void {
            const self: *Self = @ptrCast(@alignCast(context));
            try std.testing.expectEqual(@as(i32, 20), fd);
            try std.testing.expectEqual(handshake_timeout_ms, timeout_ms);
            if (self.response_mode == .timeout) {
                try self.events.append(std.testing.allocator, 'T');
                return error.HandshakeTimeout;
            }
            var response: ipc.BootstrapResponse = .{
                .cookie = self.cookie,
                .profile_hash = self.profile_hash,
                .status = .ready,
                .reason = .none,
                .daemon_pid = 77,
                .proof = .{ .fuse_initialized = true, .landlock_attached = true },
            };
            switch (self.response_mode) {
                .ready, .timeout => {},
                .wrong_identity => response.cookie[0] ^= 0xff,
                .bootstrap_failure => {
                    response.status = .failed;
                    response.reason = .landlock_attach_failed;
                    response.daemon_pid = 0;
                    response.proof.landlock_attached = false;
                },
            }
            _ = try ipc.encodeResponse(output, response);
            try self.events.append(std.testing.allocator, 'H');
        }

        fn killAndReap(context: *anyopaque, pid: i32) void {
            const self: *Self = @ptrCast(@alignCast(context));
            _ = pid;
            self.events.append(std.testing.allocator, 'K') catch unreachable;
        }
    };

    const canonical = "protected-profile";
    var compiled: profile_mod.CompiledProfile = .{
        .allocator = std.testing.allocator,
        .workspace_root = "/work",
        .grants = &.{},
        .control_roots = &.{},
        .protect_workspace_secrets = true,
        .canonical_bytes = canonical,
        .hash_hex = [_]u8{'0'} ** 64,
    };
    var environment = std.process.Environ.Map.init(std.testing.allocator);
    defer environment.deinit();
    try environment.put("PATH", "/usr/bin");

    var digest: [ipc.profile_hash_len]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(canonical, &digest, .{});
    var mock: Mock = .{ .profile_hash = digest };
    defer mock.events.deinit(std.testing.allocator);

    const spawned = try spawnWithOperations(.{
        .io = std.testing.io,
        .allocator = std.testing.allocator,
        .compiled = &compiled,
        .argv = &.{ "/usr/bin/env", "-0" },
        .environment = &environment,
        .cwd = "/work",
        .stdio = .ignore,
    }, mock.operations());

    try std.testing.expectEqual(@as(i32, 42), spawned.agent_bootstrap_pid);
    try std.testing.expectEqual(@as(u32, 77), spawned.daemon_pid);
    try std.testing.expectEqualStrings("RMPFmwHr", mock.events.items);

    mock.events.clearRetainingCapacity();
    mock.response_mode = .timeout;
    try std.testing.expectError(error.HandshakeTimeout, spawnWithOperations(.{
        .io = std.testing.io,
        .allocator = std.testing.allocator,
        .compiled = &compiled,
        .argv = &.{"/usr/bin/env"},
        .environment = &environment,
        .cwd = "/work",
        .stdio = .ignore,
    }, mock.operations()));
    try std.testing.expectEqualStrings("RMPFmwTKr", mock.events.items);

    mock.events.clearRetainingCapacity();
    mock.response_mode = .wrong_identity;
    try std.testing.expectError(error.InvalidReadyResponse, spawnWithOperations(.{
        .io = std.testing.io,
        .allocator = std.testing.allocator,
        .compiled = &compiled,
        .argv = &.{"/usr/bin/env"},
        .environment = &environment,
        .cwd = "/work",
        .stdio = .ignore,
    }, mock.operations()));
    try std.testing.expectEqualStrings("RMPFmwHrK", mock.events.items);

    mock.events.clearRetainingCapacity();
    mock.response_mode = .bootstrap_failure;
    try std.testing.expectError(error.LandlockAttachFailed, spawnWithOperations(.{
        .io = std.testing.io,
        .allocator = std.testing.allocator,
        .compiled = &compiled,
        .argv = &.{"/usr/bin/env"},
        .environment = &environment,
        .cwd = "/work",
        .stdio = .ignore,
    }, mock.operations()));
    try std.testing.expectEqualStrings("RMPFmwHrK", mock.events.items);
}

test "hidden self-exec contract is exact and bootstrap environment is empty" {
    var request_buffer: [16]u8 = undefined;
    var response_buffer: [16]u8 = undefined;
    const hidden = try formatHiddenArguments(37, 41, &request_buffer, &response_buffer);
    try std.testing.expectEqualStrings("37", hidden.request);
    try std.testing.expectEqualStrings("41", hidden.response);
    try std.testing.expectEqualStrings("/proc/self/exe", self_executable);
    try std.testing.expectEqual(@as(usize, 0), empty_bootstrap_environment.len);

    const parsed = try bootstrap.parseFds(&.{
        request_fd_option,
        hidden.request,
        response_fd_option,
        hidden.response,
    });
    try std.testing.expectEqual(@as(i32, 37), parsed.request);
    try std.testing.expectEqual(@as(i32, 41), parsed.response);
    try std.testing.expectError(
        error.InvalidTransportDescriptor,
        formatHiddenArguments(2, 41, &request_buffer, &response_buffer),
    );
}

test "request memfd contract enables sealing and locks write grow shrink and further seals" {
    try std.testing.expectEqual(@as(u32, 0x0003), requestMemfdFlags());
    try std.testing.expectEqual(@as(usize, 0x000f), requestMemfdSeals());
}

test "child descriptor scrub ranges preserve only stdio and request response" {
    var ranges: [3][2]i32 = undefined;
    const count = fillChildCloseRanges(9, 7, &ranges);
    try std.testing.expectEqual(@as(usize, 3), count);
    try std.testing.expectEqual([2]i32{ 3, 6 }, ranges[0]);
    try std.testing.expectEqual([2]i32{ 8, 8 }, ranges[1]);
    try std.testing.expectEqual([2]i32{ 10, -1 }, ranges[2]);
}

test {
    std.testing.refAllDecls(@This());
}

test "bootstrap profile rebuild matches all parent launch grant inputs" {
    // Parent compile with non-empty exec/RO/host-RW paths + protect-on must equal
    // bootstrap-style recompile that receives those same paths over the wire.
    const allocator = std.testing.allocator;
    const exec_paths = [_][]const u8{ "/home/user/.local/bin/agent", "/home/user/.local/bin/agent-real" };
    const ro_paths = [_][]const u8{"/home/user/.local/share/agent"};
    const host_rw_paths = [_][]const u8{"/home/user/.config/agent"};
    var parent = try profile_mod.compileProfile(allocator, .{
        .workspace_root = "/work/project",
        .control_roots = &[_][]const u8{"/work/project/.ryk"},
        .include_tmp = false,
        .exec_paths = &exec_paths,
        .ro_paths = &ro_paths,
        .host_rw_paths = &host_rw_paths,
        .protect_workspace_secrets = true,
        .system_ro_prefixes = &[_][]const u8{"/usr"},
    });
    defer parent.deinit();

    var rebuilt = try profile_mod.compileProfile(allocator, .{
        .workspace_root = "/work/project",
        .control_roots = &[_][]const u8{"/work/project/.ryk"},
        .include_tmp = false,
        .exec_paths = &exec_paths,
        .ro_paths = &ro_paths,
        .host_rw_paths = &host_rw_paths,
        .protect_workspace_secrets = true,
        .system_ro_prefixes = &[_][]const u8{"/usr"},
    });
    defer rebuilt.deinit();

    try std.testing.expectEqualSlices(u8, parent.canonical_bytes, rebuilt.canonical_bytes);
    try std.testing.expectEqualSlices(u8, parent.hash(), rebuilt.hash());
    try std.testing.expect(parent.hasGrant("/home/user/.local/bin/agent", .exec));
    try std.testing.expect(rebuilt.hasGrant("/home/user/.local/bin/agent", .exec));
    try std.testing.expect(parent.hasGrant("/home/user/.local/share/agent", .ro));
    try std.testing.expect(rebuilt.hasGrant("/home/user/.config/agent", .rw));

    // Omitting any launch grant class must change the digest.
    var without_launch_grants = try profile_mod.compileProfile(allocator, .{
        .workspace_root = "/work/project",
        .control_roots = &[_][]const u8{"/work/project/.ryk"},
        .include_tmp = false,
        .protect_workspace_secrets = true,
        .system_ro_prefixes = &[_][]const u8{"/usr"},
    });
    defer without_launch_grants.deinit();
    try std.testing.expect(!std.mem.eql(u8, parent.hash(), without_launch_grants.hash()));
}

test "execPathsFromCompiled collects only .exec grants" {
    const allocator = std.testing.allocator;
    const exec_paths = [_][]const u8{"/opt/agents/tool"};
    var compiled = try profile_mod.compileProfile(allocator, .{
        .workspace_root = "/work",
        .include_tmp = false,
        .exec_paths = &exec_paths,
        .protect_workspace_secrets = true,
        .system_ro_prefixes = &[_][]const u8{"/usr"},
    });
    defer compiled.deinit();
    var buf: [8][]const u8 = undefined;
    const got = try execPathsFromCompiled(&compiled, &buf);
    try std.testing.expectEqual(@as(usize, 1), got.len);
    try std.testing.expectEqualStrings("/opt/agents/tool", got[0]);
}

test "execPathsFromCompiled errors when buffer cannot hold all .exec grants" {
    const allocator = std.testing.allocator;
    const exec_paths = [_][]const u8{ "/a", "/b", "/c" };
    var compiled = try profile_mod.compileProfile(allocator, .{
        .workspace_root = "/work",
        .include_tmp = false,
        .exec_paths = &exec_paths,
        .protect_workspace_secrets = true,
        .system_ro_prefixes = &[_][]const u8{"/usr"},
    });
    defer compiled.deinit();
    var buf: [2][]const u8 = undefined;
    try std.testing.expectError(error.TooManyExecPaths, execPathsFromCompiled(&compiled, &buf));
}

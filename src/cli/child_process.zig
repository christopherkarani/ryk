const std = @import("std");
const builtin = @import("builtin");
const env_util = @import("../env_util.zig");

/// Result of running a host command (e.g. `openclaw plugins uninstall ...` or `hermes ...`)
/// with a timeout guard.
///
/// This is the core primitive to prevent `ryk uninstall` / `disable` from hanging
/// forever when a host CLI misbehaves, prompts unexpectedly, or is slow.
pub const HostCommandResult = struct {
    /// Exit code reported by the child (0-255). On timeout this is typically 255.
    exit_code: u8,
    /// True if we killed the child because it exceeded the deadline.
    timed_out: bool,
    /// Reserved for API compatibility. Host-management commands discard output.
    stdout: ?[]const u8,
    /// Reserved for API compatibility. Host-management commands discard output.
    stderr: ?[]const u8,
};

pub const HostCommandCaptureResult = struct {
    exit_code: u8,
    timed_out: bool,
    output_overflow: bool,
    stdout: []u8,
    stderr: []u8,

    pub fn deinit(self: HostCommandCaptureResult, allocator: std.mem.Allocator) void {
        allocator.free(self.stdout);
        allocator.free(self.stderr);
    }
};

const WindowsJobBasicLimitInformation = extern struct {
    per_process_user_time_limit: i64 = 0,
    per_job_user_time_limit: i64 = 0,
    limit_flags: std.os.windows.DWORD = 0,
    minimum_working_set_size: usize = 0,
    maximum_working_set_size: usize = 0,
    active_process_limit: std.os.windows.DWORD = 0,
    affinity: usize = 0,
    priority_class: std.os.windows.DWORD = 0,
    scheduling_class: std.os.windows.DWORD = 0,
};

const WindowsIoCounters = extern struct {
    read_operation_count: u64 = 0,
    write_operation_count: u64 = 0,
    other_operation_count: u64 = 0,
    read_transfer_count: u64 = 0,
    write_transfer_count: u64 = 0,
    other_transfer_count: u64 = 0,
};

const WindowsJobExtendedLimitInformation = extern struct {
    basic_limit_information: WindowsJobBasicLimitInformation = .{},
    io_info: WindowsIoCounters = .{},
    process_memory_limit: usize = 0,
    job_memory_limit: usize = 0,
    peak_process_memory_used: usize = 0,
    peak_job_memory_used: usize = 0,
};

const windows_job_api = struct {
    extern "kernel32" fn CreateJobObjectW(
        attributes: ?*std.os.windows.SECURITY_ATTRIBUTES,
        name: ?[*:0]const u16,
    ) callconv(.winapi) std.os.windows.HANDLE;
    extern "kernel32" fn SetInformationJobObject(
        job: std.os.windows.HANDLE,
        information_class: std.os.windows.DWORD,
        information: *anyopaque,
        information_length: std.os.windows.DWORD,
    ) callconv(.winapi) std.os.windows.BOOL;
    extern "kernel32" fn AssignProcessToJobObject(
        job: std.os.windows.HANDLE,
        process: std.os.windows.HANDLE,
    ) callconv(.winapi) std.os.windows.BOOL;
    extern "kernel32" fn TerminateJobObject(
        job: std.os.windows.HANDLE,
        exit_code: std.os.windows.UINT,
    ) callconv(.winapi) std.os.windows.BOOL;
};

const windows_job_kill_on_close: std.os.windows.DWORD = 0x0000_2000;
const windows_job_extended_limit_class: std.os.windows.DWORD = 9;
const posix_post_exit_drain_ns: u64 = 250 * std.time.ns_per_ms;

fn createWindowsJob(child_id: std.process.Child.Id) !std.os.windows.HANDLE {
    if (comptime builtin.os.tag != .windows) unreachable;
    const job = windows_job_api.CreateJobObjectW(null, null);
    if (@intFromPtr(job) == 0) return error.WindowsJobCreateFailed;
    var limits: WindowsJobExtendedLimitInformation = .{};
    limits.basic_limit_information.limit_flags = windows_job_kill_on_close;
    if (!windows_job_api.SetInformationJobObject(
        job,
        windows_job_extended_limit_class,
        @ptrCast(&limits),
        @sizeOf(WindowsJobExtendedLimitInformation),
    ).toBool()) {
        std.os.windows.CloseHandle(job);
        return error.WindowsJobConfigurationFailed;
    }
    if (!windows_job_api.AssignProcessToJobObject(job, child_id).toBool()) {
        std.os.windows.CloseHandle(job);
        return error.WindowsJobAssignmentFailed;
    }
    return job;
}

fn terminateWindowsJob(job: ?std.os.windows.HANDLE) void {
    if (comptime builtin.os.tag != .windows) return;
    if (job) |handle| _ = windows_job_api.TerminateJobObject(handle, 1);
}

fn closeWindowsJob(job: ?std.os.windows.HANDLE) void {
    if (comptime builtin.os.tag != .windows) return;
    if (job) |handle| std.os.windows.CloseHandle(handle);
}

fn resumeWindowsChild(child: *std.process.Child) !void {
    if (comptime builtin.os.tag != .windows) unreachable;
    const thread_handle: std.os.windows.HANDLE = @field(child.*, "thread_handle");
    switch (std.os.windows.ntdll.NtResumeThread(thread_handle, null)) {
        .SUCCESS => {},
        else => return error.WindowsChildResumeFailed,
    }
}

pub fn deinitHostCommandResult(result: HostCommandResult, allocator: std.mem.Allocator) void {
    if (result.stdout) |s| allocator.free(s);
    if (result.stderr) |s| allocator.free(s);
}

/// Run an external command (intended for host agent CLIs like openclaw/hermes)
/// with a hard timeout. Output is discarded so an untrusted host CLI cannot block
/// ryk by filling a pipe. Current callers only need the exit status.
///
/// On Unix we use a monitoring thread + timer + process-group kill. On Windows
/// the child is placed in a kill-on-close Job Object so descendants are part of
/// the timeout boundary too.
///
/// This is deliberately *not* a general-purpose child runner — it is tuned for the
/// "call a potentially flaky host plugin manager and never hang the parent CLI" use case.
///
/// `timeout_ms` of 0 means "no timeout" (use only for tests or very special cases).
pub fn runHostCommandTimed(
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    timeout_ms: u64,
    stdout_writer: anytype,
    stderr_writer: anytype,
) !HostCommandResult {
    _ = stdout_writer;
    _ = stderr_writer;
    return runHostCommandTimedCwd(allocator, argv, timeout_ms, null);
}

/// Same as `runHostCommandTimed` but optionally pins the child cwd (plugin install roots).
pub fn runHostCommandTimedCwd(
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    timeout_ms: u64,
    cwd_path: ?[]const u8,
) !HostCommandResult {
    if (argv.len == 0) return error.InvalidArgv;

    var threaded = std.Io.Threaded.init(allocator, .{
        .environ = env_util.processEnviron(),
    });
    defer threaded.deinit();
    const io = threaded.io();

    var child = try std.process.spawn(io, .{
        .argv = argv,
        .cwd = if (cwd_path) |p| .{ .path = p } else .inherit,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
        .pgid = if (builtin.os.tag == .windows) null else 0,
        .start_suspended = builtin.os.tag == .windows,
    });
    const child_id = child.id.?;
    var windows_job: ?std.os.windows.HANDLE = null;
    if (comptime builtin.os.tag == .windows) {
        windows_job = createWindowsJob(child_id) catch |err| {
            child.kill(io);
            return err;
        };
        resumeWindowsChild(&child) catch |err| {
            child.kill(io);
            closeWindowsJob(windows_job);
            return err;
        };
    }

    var timed_out = std.atomic.Value(bool).init(false);
    var finished = std.atomic.Value(bool).init(false);
    var watcher: ?std.Thread = null;
    if (timeout_ms > 0) {
        watcher = std.Thread.spawn(.{}, struct {
            fn run(id: std.process.Child.Id, job: ?std.os.windows.HANDLE, watch_io: std.Io, flag: *std.atomic.Value(bool), fin: *std.atomic.Value(bool), ms: u64) void {
                var remaining: u64 = ms;
                const chunk: u64 = 50;
                while (remaining > 0) {
                    if (fin.load(.acquire)) return;
                    const sl = @min(chunk, remaining);
                    const duration = std.Io.Duration.fromMilliseconds(@intCast(sl));
                    std.Io.sleep(watch_io, duration, .awake) catch {};
                    remaining -= sl;
                }
                if (fin.load(.acquire)) return;
                if (builtin.os.tag == .windows) {
                    terminateWindowsJob(job);
                } else {
                    std.posix.kill(-id, std.posix.SIG.TERM) catch {};
                    var grace_ms: u64 = 500;
                    while (grace_ms > 0) {
                        std.Io.sleep(watch_io, std.Io.Duration.fromMilliseconds(50), .awake) catch {};
                        grace_ms -= 50;
                        std.posix.kill(-id, @enumFromInt(0)) catch |err| switch (err) {
                            error.ProcessNotFound => break,
                            else => {},
                        };
                    }
                    std.posix.kill(-id, std.posix.SIG.KILL) catch {};
                }
                flag.store(true, .release);
            }
        }.run, .{ child_id, windows_job, io, &timed_out, &finished, timeout_ms }) catch |err| {
            child.kill(io);
            terminateWindowsJob(windows_job);
            closeWindowsJob(windows_job);
            return err;
        };
    }

    const term = child.wait(io) catch {
        finished.store(true, .release);
        if (watcher) |w| w.join();
        terminateWindowsJob(windows_job);
        closeWindowsJob(windows_job);
        return HostCommandResult{
            .exit_code = 255,
            .timed_out = timed_out.load(.acquire),
            .stdout = null,
            .stderr = null,
        };
    };
    finished.store(true, .release);
    if (watcher) |w| w.join();
    closeWindowsJob(windows_job);

    const exit_code: u8 = switch (term) {
        .exited => |code| @as(u8, @intCast(@min(code, 255))),
        .signal, .stopped, .unknown => 255,
    };

    return HostCommandResult{
        .exit_code = exit_code,
        .timed_out = timed_out.load(.acquire),
        .stdout = null,
        .stderr = null,
    };
}

/// Run a short identity/status probe with bounded output and a hard timeout.
/// Unlike `runHostCommandTimed`, this captures output for callers that must
/// validate which CLI a PATH entry actually represents.
pub fn runHostCommandCaptureTimed(
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    timeout_ms: u32,
) !HostCommandCaptureResult {
    return runHostCommandInputCaptureTimedInternal(allocator, argv, "", timeout_ms, false, true);
}

/// Capture a host command in the caller's existing POSIX process group. This
/// is reserved for the health worker: its outer watchdog owns that group, so
/// a command still running when the worker deadline fires cannot outlive the
/// health command in a separate group.
pub fn runHostCommandCaptureTimedInCurrentProcessGroup(
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    timeout_ms: u32,
) !HostCommandCaptureResult {
    if (comptime builtin.os.tag == .windows) return error.UnsupportedPlatform;
    return runHostCommandInputCaptureTimedInternal(allocator, argv, "", timeout_ms, true, false);
}

const DrainContext = struct {
    file: std.Io.File,
    io: std.Io,
    limit: usize,
    cancel: *std.atomic.Value(bool),
    deadline_ns: *std.atomic.Value(u64),
    overflowed: *std.atomic.Value(bool),
    storage: [64 * 1024]u8 = undefined,
    len: usize = 0,

    fn run(self: *DrainContext) void {
        if (comptime builtin.os.tag != .windows) {
            self.runPosix();
            return;
        }
        self.runBlocking();
    }

    fn append(self: *DrainContext, bytes: []const u8) void {
        const remaining = self.limit -| self.len;
        const copy_len = @min(remaining, bytes.len);
        if (copy_len > 0) {
            @memcpy(self.storage[self.len..][0..copy_len], bytes[0..copy_len]);
            self.len += copy_len;
        }
        if (copy_len < bytes.len) self.overflowed.store(true, .release);
    }

    fn runBlocking(self: *DrainContext) void {
        var reader_buffer: [4096]u8 = undefined;
        var read_buffer: [4096]u8 = undefined;
        var reader = self.file.reader(self.io, &reader_buffer);
        while (!self.cancel.load(.acquire)) {
            const count = reader.interface.readSliceShort(&read_buffer) catch return;
            if (count == 0) return;
            self.append(read_buffer[0..count]);
            // Continue draining after the capture limit so a noisy child cannot
            // block while the parent waits for it to exit.
        }
    }

    fn runPosix(self: *DrainContext) void {
        var read_buffer: [4096]u8 = undefined;
        var descriptors = [_]std.posix.pollfd{.{
            .fd = self.file.handle,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        while (!self.cancel.load(.acquire)) {
            const deadline_ns = self.deadline_ns.load(.acquire);
            if (deadline_ns != 0 and @as(u64, @intCast(@max(std.Io.Clock.Timestamp.now(self.io, .awake).raw.nanoseconds, 0))) >= deadline_ns) return;
            descriptors[0].revents = 0;
            const ready = std.posix.poll(&descriptors, 50) catch return;
            if (ready == 0) continue;
            if ((descriptors[0].revents & (std.posix.POLL.HUP | std.posix.POLL.ERR | std.posix.POLL.IN)) == 0) continue;
            const count = std.posix.read(self.file.handle, &read_buffer) catch return;
            if (count == 0) return;
            self.append(read_buffer[0..count]);
        }
    }
};

fn setNonblockingPosix(fd: std.posix.fd_t) !void {
    if (comptime builtin.os.tag == .windows) unreachable;
    const current_raw = std.posix.system.fcntl(fd, std.posix.F.GETFL, @as(usize, 0));
    switch (std.posix.errno(current_raw)) {
        .SUCCESS => {},
        else => return error.NonblockingPipeSetupFailed,
    }
    const current: u32 = @intCast(current_raw);
    const nonblocking: u32 = @bitCast(std.posix.O{ .NONBLOCK = true });
    const result = std.posix.system.fcntl(fd, std.posix.F.SETFL, current | nonblocking);
    switch (std.posix.errno(result)) {
        .SUCCESS => {},
        else => return error.NonblockingPipeSetupFailed,
    }
}

fn setNoSigpipePosix(fd: std.posix.fd_t) !void {
    if (comptime builtin.os.tag != .macos) return;
    const result = std.posix.system.fcntl(fd, std.posix.F.SETNOSIGPIPE, @as(usize, 1));
    switch (std.posix.errno(result)) {
        .SUCCESS => {},
        else => return error.NoSigpipeSetupFailed,
    }
}

/// Write bounded hook input without allowing a child that never reads stdin
/// (or a detached descendant that inherited the read end) to hold the parent
/// past the command watcher deadline.
fn writePosixInputBounded(
    file: *std.Io.File,
    bytes: []const u8,
    timed_out: *std.atomic.Value(bool),
) bool {
    if (comptime builtin.os.tag == .windows) unreachable;
    var offset: usize = 0;
    var descriptors = [_]std.posix.pollfd{.{
        .fd = file.handle,
        .events = std.posix.POLL.OUT,
        .revents = 0,
    }};
    while (offset < bytes.len) {
        if (timed_out.load(.acquire)) return false;
        descriptors[0].revents = 0;
        const ready = std.posix.poll(&descriptors, 50) catch return false;
        if (ready == 0) continue;
        if ((descriptors[0].revents & (std.posix.POLL.ERR | std.posix.POLL.HUP)) != 0) return false;
        if ((descriptors[0].revents & std.posix.POLL.OUT) == 0) continue;
        const result = std.posix.system.write(file.handle, bytes[offset..].ptr, bytes.len - offset);
        switch (std.posix.errno(result)) {
            .SUCCESS => {
                if (result == 0) return false;
                offset += @intCast(result);
            },
            .INTR, .AGAIN => continue,
            else => return false,
        }
    }
    return true;
}

/// Run a hook-style child with bounded stdin, concurrent stdout/stderr drains,
/// and a hard timeout. The child process group is terminated on timeout so a
/// spawned grandchild cannot keep the onboarding flow hung.
pub fn runHostCommandInputCaptureTimed(
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    stdin_bytes: []const u8,
    timeout_ms: u64,
) !HostCommandCaptureResult {
    return runHostCommandInputCaptureTimedInternal(allocator, argv, stdin_bytes, timeout_ms, false, true);
}

fn runHostCommandInputCaptureTimedInternal(
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    stdin_bytes: []const u8,
    timeout_ms: u64,
    join_parent_process_group: bool,
    kill_process_group_after_wait: bool,
) !HostCommandCaptureResult {
    if (argv.len == 0) return error.InvalidArgv;
    if (stdin_bytes.len > 256 * 1024) return error.InputTooLong;

    var threaded = std.Io.Threaded.init(allocator, .{
        .environ = env_util.processEnviron(),
    });
    defer threaded.deinit();
    const io = threaded.io();

    // std.process.Child's stdin pipe is a blocking writer. On POSIX, build
    // the pipe ourselves so only the parent's write end is nonblocking; the
    // child still receives a normal blocking stdin after dup2. This keeps a
    // detached descendant that retains stdin from pinning the caller in a
    // synchronous write.
    var stdin_option: std.process.SpawnOptions.StdIo = .pipe;
    var posix_stdin_read: ?std.Io.File = null;
    var posix_stdin_write: ?std.Io.File = null;
    if (comptime builtin.os.tag != .windows) {
        const pipe = try std.Io.Threaded.pipe2(.{ .CLOEXEC = true });
        const read_file = std.Io.File{ .handle = pipe[0], .flags = .{ .nonblocking = false } };
        const write_file = std.Io.File{ .handle = pipe[1], .flags = .{ .nonblocking = true } };
        setNonblockingPosix(write_file.handle) catch |err| {
            read_file.close(io);
            write_file.close(io);
            return err;
        };
        setNoSigpipePosix(write_file.handle) catch |err| {
            read_file.close(io);
            write_file.close(io);
            return err;
        };
        posix_stdin_read = read_file;
        posix_stdin_write = write_file;
        stdin_option = .{ .file = read_file };
    }

    var child = std.process.spawn(io, .{
        .argv = argv,
        .stdin = stdin_option,
        .stdout = .pipe,
        .stderr = .pipe,
        .pgid = if (builtin.os.tag == .windows) null else if (join_parent_process_group) std.c.getpid() else 0,
        .start_suspended = builtin.os.tag == .windows,
    }) catch |err| {
        if (posix_stdin_read) |file| file.close(io);
        if (posix_stdin_write) |file| file.close(io);
        return err;
    };
    if (posix_stdin_read) |file| {
        file.close(io);
        posix_stdin_read = null;
    }
    defer if (posix_stdin_write) |file| file.close(io);
    const child_id = child.id.?;

    const stdout_file = child.stdout orelse return error.MissingStdoutPipe;
    const stderr_file = child.stderr orelse return error.MissingStderrPipe;
    child.stdout = null;
    child.stderr = null;
    var windows_job: ?std.os.windows.HANDLE = null;
    if (comptime builtin.os.tag == .windows) {
        windows_job = createWindowsJob(child_id) catch |err| {
            stdout_file.close(io);
            stderr_file.close(io);
            child.kill(io);
            return err;
        };
        resumeWindowsChild(&child) catch |err| {
            stdout_file.close(io);
            stderr_file.close(io);
            child.kill(io);
            closeWindowsJob(windows_job);
            return err;
        };
    }

    var stdout_context = DrainContext{
        .file = stdout_file,
        .io = io,
        .limit = 64 * 1024,
        .cancel = undefined,
        .deadline_ns = undefined,
        .overflowed = undefined,
    };
    var stderr_context = DrainContext{
        .file = stderr_file,
        .io = io,
        .limit = 16 * 1024,
        .cancel = undefined,
        .deadline_ns = undefined,
        .overflowed = undefined,
    };
    var drain_cancel = std.atomic.Value(bool).init(false);
    var drain_deadline_ns = std.atomic.Value(u64).init(0);
    var output_overflow = std.atomic.Value(bool).init(false);
    stdout_context.cancel = &drain_cancel;
    stdout_context.deadline_ns = &drain_deadline_ns;
    stdout_context.overflowed = &output_overflow;
    stderr_context.cancel = &drain_cancel;
    stderr_context.deadline_ns = &drain_deadline_ns;
    stderr_context.overflowed = &output_overflow;
    const stdout_thread = std.Thread.spawn(.{}, DrainContext.run, .{&stdout_context}) catch |err| {
        child.kill(io);
        terminateWindowsJob(windows_job);
        closeWindowsJob(windows_job);
        stdout_context.file.close(io);
        stderr_context.file.close(io);
        return err;
    };
    const stderr_thread = std.Thread.spawn(.{}, DrainContext.run, .{&stderr_context}) catch |err| {
        child.kill(io);
        drain_cancel.store(true, .release);
        terminateWindowsJob(windows_job);
        closeWindowsJob(windows_job);
        stdout_thread.join();
        stdout_context.file.close(io);
        stderr_context.file.close(io);
        return err;
    };

    var timed_out = std.atomic.Value(bool).init(false);
    var finished = std.atomic.Value(bool).init(false);
    var watcher: ?std.Thread = null;
    if (timeout_ms > 0) {
        watcher = std.Thread.spawn(.{}, struct {
            fn run(id: std.process.Child.Id, group_id: std.process.Child.Id, kill_group: bool, job: ?std.os.windows.HANDLE, watch_io: std.Io, did_timeout: *std.atomic.Value(bool), done: *std.atomic.Value(bool), ms: u64) void {
                var remaining = ms;
                while (remaining > 0) {
                    if (done.load(.acquire)) return;
                    const slice = @min(@as(u64, 50), remaining);
                    std.Io.sleep(watch_io, std.Io.Duration.fromMilliseconds(@intCast(slice)), .awake) catch {};
                    remaining -= slice;
                }
                if (done.load(.acquire)) return;
                if (builtin.os.tag == .windows) {
                    terminateWindowsJob(job);
                } else {
                    const target = if (kill_group) -group_id else id;
                    std.posix.kill(target, std.posix.SIG.TERM) catch {};
                    var grace_ms: u64 = 500;
                    while (grace_ms > 0) {
                        std.Io.sleep(watch_io, std.Io.Duration.fromMilliseconds(50), .awake) catch {};
                        grace_ms -= 50;
                        std.posix.kill(target, @enumFromInt(0)) catch |err| switch (err) {
                            error.ProcessNotFound => break,
                            else => {},
                        };
                    }
                    std.posix.kill(target, std.posix.SIG.KILL) catch {};
                }
                did_timeout.store(true, .release);
            }
        }.run, .{ child_id, if (builtin.os.tag == .windows or !join_parent_process_group) child_id else std.c.getpid(), kill_process_group_after_wait, windows_job, io, &timed_out, &finished, timeout_ms }) catch |err| {
            child.kill(io);
            terminateWindowsJob(windows_job);
            closeWindowsJob(windows_job);
            drain_cancel.store(true, .release);
            stdout_thread.join();
            stderr_thread.join();
            stdout_context.file.close(io);
            stderr_context.file.close(io);
            return err;
        };
    }

    if (comptime builtin.os.tag == .windows) {
        if (child.stdin) |*stdin| {
            stdin.writeStreamingAll(io, stdin_bytes) catch |err| {
                child.kill(io);
                finished.store(true, .release);
                if (watcher) |thread| thread.join();
                terminateWindowsJob(windows_job);
                closeWindowsJob(windows_job);
                drain_cancel.store(true, .release);
                stdout_thread.join();
                stderr_thread.join();
                stdout_context.file.close(io);
                stderr_context.file.close(io);
                return err;
            };
            stdin.close(io);
            child.stdin = null;
        }
    } else if (posix_stdin_write) |*stdin| {
        // A failed write means the child closed stdin or the command watcher
        // fired. In either case close our end and let wait/cleanup produce the
        // bounded command result instead of returning while a pipe is open.
        _ = writePosixInputBounded(stdin, stdin_bytes, &timed_out);
        stdin.close(io);
        posix_stdin_write = null;
    }

    const term = child.wait(io) catch blk: {
        child.kill(io);
        break :blk null;
    };
    // A host CLI may exit after spawning a descendant that inherited our
    // capture pipes. Reap the entire dedicated process group before joining
    // drain threads so a background child cannot keep health blocked forever.
    if (builtin.os.tag != .windows and kill_process_group_after_wait) std.posix.kill(-child_id, std.posix.SIG.KILL) catch {};
    if (builtin.os.tag == .windows) {
        terminateWindowsJob(windows_job);
        closeWindowsJob(windows_job);
    }
    finished.store(true, .release);
    if (timed_out.load(.acquire)) {
        drain_cancel.store(true, .release);
    } else if (builtin.os.tag != .windows) {
        const now_ns = @as(u64, @intCast(@max(std.Io.Clock.Timestamp.now(io, .awake).raw.nanoseconds, 0)));
        drain_deadline_ns.store(now_ns + posix_post_exit_drain_ns, .release);
    } else {
        drain_cancel.store(true, .release);
    }
    if (watcher) |thread| thread.join();
    stdout_thread.join();
    stderr_thread.join();
    stdout_context.file.close(io);
    stderr_context.file.close(io);

    const stdout = try allocator.dupe(u8, stdout_context.storage[0..stdout_context.len]);
    errdefer allocator.free(stdout);
    const stderr = try allocator.dupe(u8, stderr_context.storage[0..stderr_context.len]);
    return .{
        .exit_code = if (term) |value| switch (value) {
            .exited => |code| @intCast(@min(code, 255)),
            else => 255,
        } else 255,
        .timed_out = timed_out.load(.acquire),
        .output_overflow = output_overflow.load(.acquire),
        .stdout = stdout,
        .stderr = stderr,
    };
}

// ---------------------------------------------------------------------------
// Test doubles / helpers for testing the runner itself without real hangs
// ---------------------------------------------------------------------------

/// Thin wrapper for tests that want to emphasize the timeout path.
/// In practice you can just call runHostCommandTimed with a tiny timeout.
pub fn runHostCommandTimedForTest(
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    timeout_ms: u64,
    simulate_timeout_after_ms: ?u64,
) !HostCommandResult {
    _ = simulate_timeout_after_ms;
    return runHostCommandTimed(allocator, argv, timeout_ms, null, null);
}

test "child_process: API surface compiles and deinit is safe on zeroed result" {
    const result: HostCommandResult = .{
        .exit_code = 0,
        .timed_out = false,
        .stdout = null,
        .stderr = null,
    };
    deinitHostCommandResult(result, std.testing.allocator);
}

test "child_process: fast successful command returns reasonable result without hanging (self exe smoke)" {
    const self_exe = std.process.executablePathAlloc(std.testing.io, std.testing.allocator) catch return error.SkipZigTest;
    defer std.testing.allocator.free(self_exe);

    const argv = [_][]const u8{ self_exe, "--help" };
    const res = try runHostCommandTimed(
        std.testing.allocator,
        &argv,
        5_000,
        null,
        null,
    );
    defer deinitHostCommandResult(res, std.testing.allocator);
    try std.testing.expect(!res.timed_out);
}

test "child_process: host command resolves through inherited PATH" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const argv = [_][]const u8{ "sh", "-c", "exit 0" };
    const res = try runHostCommandTimed(std.testing.allocator, &argv, 5_000, null, null);
    defer deinitHostCommandResult(res, std.testing.allocator);

    try std.testing.expect(!res.timed_out);
    try std.testing.expectEqual(@as(u8, 0), res.exit_code);
}

test "child_process: ignored high-volume output cannot fill a pipe" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const argv = [_][]const u8{ "sh", "-c", "yes x | head -c 1048576" };
    const res = try runHostCommandTimed(std.testing.allocator, &argv, 5_000, null, null);
    defer deinitHostCommandResult(res, std.testing.allocator);
    try std.testing.expect(!res.timed_out);
    try std.testing.expectEqual(@as(u8, 0), res.exit_code);
}

test "child_process: bounded capture returns stdout and stderr" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const result = try runHostCommandCaptureTimed(
        std.testing.allocator,
        &.{ "sh", "-c", "printf compatible; printf warning >&2" },
        5_000,
    );
    defer result.deinit(std.testing.allocator);

    try std.testing.expect(!result.timed_out);
    try std.testing.expectEqual(@as(u8, 0), result.exit_code);
    try std.testing.expectEqualStrings("compatible", result.stdout);
    try std.testing.expectEqualStrings("warning", result.stderr);
}

test "child_process: bounded capture drains output after the child exits" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const result = try runHostCommandCaptureTimed(
        std.testing.allocator,
        &.{ "/usr/bin/perl", "-e", "print 'x' x 65536; print STDERR 'e' x 16384" },
        5_000,
    );
    defer result.deinit(std.testing.allocator);

    try std.testing.expect(!result.timed_out);
    try std.testing.expectEqual(@as(u8, 0), result.exit_code);
    try std.testing.expectEqual(@as(usize, 65_536), result.stdout.len);
    try std.testing.expectEqual(@as(usize, 16_384), result.stderr.len);
}

test "child_process: capture reports output overflow instead of accepting truncation" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const result = try runHostCommandCaptureTimed(
        std.testing.allocator,
        &.{ "/usr/bin/perl", "-e", "print 'x' x 65537" },
        5_000,
    );
    defer result.deinit(std.testing.allocator);

    try std.testing.expect(!result.timed_out);
    try std.testing.expect(result.output_overflow);
    try std.testing.expectEqual(@as(usize, 64 * 1024), result.stdout.len);
}

test "child_process: bounded capture terminates a hung probe" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const result = try runHostCommandCaptureTimed(
        std.testing.allocator,
        &.{ "sh", "-c", "sleep 10" },
        50,
    );
    defer result.deinit(std.testing.allocator);

    try std.testing.expect(result.timed_out);
    try std.testing.expectEqual(@as(u8, 255), result.exit_code);
}

test "child_process: bounded capture timeout terminates background descendants" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_path = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(tmp_path);
    const pid_path = try std.fs.path.join(std.testing.allocator, &.{ tmp_path, "descendant.pid" });
    defer std.testing.allocator.free(pid_path);

    const result = try runHostCommandCaptureTimed(
        std.testing.allocator,
        &.{
            "sh",
            "-c",
            "sleep 30 </dev/null >/dev/null 2>&1 & printf '%s' \"$!\" > \"$1\"; wait",
            "ryk-child-process-test",
            pid_path,
        },
        100,
    );
    defer result.deinit(std.testing.allocator);

    try std.testing.expect(result.timed_out);
    const pid_text = try tmp.dir.readFileAlloc(std.testing.io, "descendant.pid", std.testing.allocator, .limited(32));
    defer std.testing.allocator.free(pid_text);
    const descendant_pid = try std.fmt.parseInt(i32, std.mem.trim(u8, pid_text, " \t\r\n"), 10);
    defer std.posix.kill(descendant_pid, std.posix.SIG.KILL) catch {};

    try std.testing.expectError(
        error.ProcessNotFound,
        std.posix.kill(descendant_pid, @enumFromInt(0)),
    );
}

test "child_process: bounded capture reaps pipe-holding descendant after parent exits" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_path = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(tmp_path);
    const pid_path = try std.fs.path.join(std.testing.allocator, &.{ tmp_path, "orphan.pid" });
    defer std.testing.allocator.free(pid_path);

    const result = try runHostCommandCaptureTimed(
        std.testing.allocator,
        &.{
            "sh",
            "-c",
            "sh -c 'trap '' TERM; sleep 30' & printf '%s' \"$!\" > \"$1\"; exit 0",
            "ryk-child-process-test",
            pid_path,
        },
        1_000,
    );
    defer result.deinit(std.testing.allocator);

    try std.testing.expect(!result.timed_out);
    const pid_text = try tmp.dir.readFileAlloc(std.testing.io, "orphan.pid", std.testing.allocator, .limited(32));
    defer std.testing.allocator.free(pid_text);
    const descendant_pid = try std.fmt.parseInt(i32, std.mem.trim(u8, pid_text, " \t\r\n"), 10);
    defer std.posix.kill(descendant_pid, std.posix.SIG.KILL) catch {};
    try std.testing.expectError(error.ProcessNotFound, std.posix.kill(descendant_pid, @enumFromInt(0)));
}

test "child_process: detached TERM-resistant pipe holder cannot extend the drain deadline" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const started = std.Io.Clock.Timestamp.now(std.testing.io, .awake);
    const result = try runHostCommandInputCaptureTimed(
        std.testing.allocator,
        &.{
            "sh",
            "-c",
            "/usr/bin/perl -MPOSIX -e 'setsid(); $SIG{TERM}=\"IGNORE\"; sleep 2' & exit 0",
        },
        "fixture\n",
        250,
    );
    defer result.deinit(std.testing.allocator);

    const elapsed_ns = std.Io.Clock.Timestamp.now(std.testing.io, .awake).raw.nanoseconds - started.raw.nanoseconds;
    try std.testing.expect(!result.timed_out);
    try std.testing.expect(elapsed_ns < 1_000_000_000);
}

test "child_process: macOS stdin write cannot outlive the command deadline" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    var input: [256 * 1024]u8 = undefined;
    @memset(&input, 'x');
    const started = std.Io.Clock.Timestamp.now(std.testing.io, .awake);
    const result = try runHostCommandInputCaptureTimed(
        std.testing.allocator,
        &.{
            "sh",
            "-c",
            "/usr/bin/perl -MPOSIX -e '$SIG{TERM}=\"IGNORE\"; setsid(); sleep 2' & exit 0",
        },
        &input,
        250,
    );
    defer result.deinit(std.testing.allocator);

    const elapsed_ns = std.Io.Clock.Timestamp.now(std.testing.io, .awake).raw.nanoseconds - started.raw.nanoseconds;
    try std.testing.expect(elapsed_ns < 1_000_000_000);
}

test "child_process: macOS closed stdin returns EPIPE instead of killing the parent" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;

    var input: [256 * 1024]u8 = undefined;
    @memset(&input, 'x');
    const result = try runHostCommandInputCaptureTimed(
        std.testing.allocator,
        &.{ "sh", "-c", "sleep 0.1; exec 0<&-; exit 0" },
        &input,
        1_000,
    );
    defer result.deinit(std.testing.allocator);

    try std.testing.expect(!result.timed_out);
    try std.testing.expectEqual(@as(u8, 0), result.exit_code);
}

test "child_process: bounded hook runner writes stdin and drains noisy output" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const result = try runHostCommandInputCaptureTimed(
        std.testing.allocator,
        &.{ "sh", "-c", "read line; printf '%s' \"$line\"; yes warning | head -n 10000 >&2" },
        "fixture\n",
        5_000,
    );
    defer result.deinit(std.testing.allocator);

    try std.testing.expect(!result.timed_out);
    try std.testing.expectEqual(@as(u8, 0), result.exit_code);
    try std.testing.expectEqualStrings("fixture", result.stdout);
    try std.testing.expectEqual(@as(usize, 16 * 1024), result.stderr.len);
}

test "child_process: bounded hook runner terminates a hung child" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const result = try runHostCommandInputCaptureTimed(
        std.testing.allocator,
        &.{ "sh", "-c", "read line; sleep 10" },
        "fixture\n",
        50,
    );
    defer result.deinit(std.testing.allocator);

    try std.testing.expect(result.timed_out);
    try std.testing.expectEqual(@as(u8, 255), result.exit_code);
}

test "child_process: timeout escalates when child ignores TERM" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const argv = [_][]const u8{ "sh", "-c", "trap '' TERM; sleep 10" };
    const res = try runHostCommandTimed(std.testing.allocator, &argv, 50, null, null);
    defer deinitHostCommandResult(res, std.testing.allocator);
    try std.testing.expect(res.timed_out);
}

const std = @import("std");
const builtin = @import("builtin");

const event = @import("event.zig");
const platform = @import("platform.zig");
const process = @import("process.zig");
const session_mod = @import("session.zig");
const time = @import("time.zig");
const types = @import("types.zig");
const util = @import("util.zig");

pub const StdioBehavior = process.StdioBehavior;

pub const RunConfig = struct {
    command: []const u8,
    args: []const []const u8 = &.{},
    workspace: ?[]const u8 = null,
    mode: types.Mode = .observe,
    session_name: ?[]const u8 = null,
    policy_source: ?[]const u8 = null,
    stdio: StdioBehavior = .inherit,
    env_map: ?*const std.process.Environ.Map = null,
    env_redactions: []const EnvRedactionRecord = &.{},
    /// When set, agent spawn applies Landlock/Seatbelt in the child before exec (U07).
    /// Production path: cli/run runs applyBeforeExec first, then passes custom spawn here.
    os_child_apply: process.OsChildApply = .none,
    /// Set true when the custom spawn hook returned successfully.
    /// Does not prove status-pipe OS apply handshake — use attach receipt / spawnAgent.
    custom_spawn_used_out: ?*bool = null,
    before_spawn: ?StartHook = null,
    before_process_launch: ?StartHook = null,
    /// Runs after the agent child is forked/spawned but before on_session_start.
    /// Used to start proxy accept threads after sandboxed Seatbelt fork (M-5).
    after_process_spawn: ?StartHook = null,
    on_session_start: ?StartHook = null,
    on_event: ?EventHook = null,
    health_monitor: ?HealthMonitor = null,
};

pub const EnvRedactionRecord = process.EnvRedactionRecord;

pub const StartHook = struct {
    context: *anyopaque,
    callback: *const fn (context: *anyopaque, session: session_mod.Session) anyerror!void,
};

pub const EventHook = struct {
    context: *anyopaque,
    callback: *const fn (context: *anyopaque, ev: event.Event) anyerror!void,
};

pub const HealthMonitor = struct {
    context: *anyopaque,
    callback: *const fn (context: *anyopaque) bool,
    interval_ns: u64 = 50 * std.time.ns_per_ms,
};

pub const ChildStatus = process.ChildStatus;

pub const SessionResult = struct {
    session: session_mod.Session,
    status: ChildStatus,
    events: []event.Event,
    event_target_values: []const []const u8,
    allocator: std.mem.Allocator,

    pub fn exitCode(self: SessionResult) i32 {
        return self.status.exitCode();
    }

    pub fn deinit(self: *SessionResult) void {
        self.allocator.free(self.session.workspace_root);
        for (self.event_target_values) |target_value| {
            self.allocator.free(target_value);
        }
        self.allocator.free(self.event_target_values);
        self.allocator.free(self.events);
        self.* = undefined;
    }
};

const HealthMonitorThreadContext = struct {
    prepared: *process.PreparedChild,
    monitor: HealthMonitor,
    stop: *std.atomic.Value(bool),
    failed: *std.atomic.Value(bool),
};

fn healthMonitorLoop(context: *HealthMonitorThreadContext) void {
    while (!context.stop.load(.acquire)) {
        if (!context.monitor.callback(context.monitor.context)) {
            context.failed.store(true, .release);
            // Signal only — never wait/reap; main prepared.wait() is sole reaper (M-6).
            context.prepared.terminateForHealthFailure();
            return;
        }
        const duration = std.Io.Duration.fromNanoseconds(context.monitor.interval_ns);
        std.Io.sleep(context.prepared.io, duration, .awake) catch {};
    }
}

pub fn run(io: std.Io, allocator: std.mem.Allocator, config: RunConfig) !SessionResult {
    if (config.command.len == 0) return error.InvalidCommand;

    const workspace_root = try resolveWorkspaceRoot(io, allocator, config.workspace, ".");
    errdefer allocator.free(workspace_root);

    const started_at = time.Timestamp.now(io);
    var session: session_mod.Session = .{
        .id = try session_mod.generateSessionId(started_at),
        .started_at = started_at,
        .command = config.command,
        .args = config.args,
        .workspace_root = workspace_root,
        .session_name = config.session_name,
        .mode = config.mode,
        .platform = platform.detectOs(),
    };

    const event_count: usize = (if (config.policy_source != null) @as(usize, 4) else @as(usize, 3)) + config.env_redactions.len;
    var events = try allocator.alloc(event.Event, event_count);
    errdefer allocator.free(events);
    var event_target_values = try allocator.alloc([]const u8, event_count);
    errdefer allocator.free(event_target_values);
    var owned_targets: usize = 0;
    errdefer {
        for (event_target_values[0..owned_targets]) |target_value| {
            allocator.free(target_value);
        }
    }
    events[0] = try makeOwnedTargetEvent(allocator, &event_target_values, &owned_targets, session, started_at, .session_start, .session, session.id.slice());

    var next_event_index: usize = 1;
    if (config.policy_source) |policy_source| {
        events[next_event_index] = try makeOwnedTargetEvent(allocator, &event_target_values, &owned_targets, session, started_at, .policy_loaded, .file_path, policy_source);
        next_event_index += 1;
    }

    for (config.env_redactions) |record| {
        events[next_event_index] = try makeEnvRedactionEvent(allocator, &event_target_values, &owned_targets, session, started_at, record);
        next_event_index += 1;
    }

    if (config.before_spawn) |hook| {
        try hook.callback(hook.context, session);
    }
    if (config.on_event) |hook| {
        for (events[0..next_event_index]) |ev| try hook.callback(hook.context, ev);
    }

    if (config.before_process_launch) |hook| {
        try hook.callback(hook.context, session);
    }

    const command_display = try commandDisplay(allocator, config.command, config.args);
    defer allocator.free(command_display);
    events[next_event_index] = try makeOwnedTargetEvent(allocator, &event_target_values, &owned_targets, session, started_at, .process_launch, .command, command_display);
    next_event_index += 1;

    if (config.on_event) |hook| {
        try hook.callback(hook.context, events[next_event_index - 1]);
    }

    var argv = try allocator.alloc([]const u8, config.args.len + 1);
    defer allocator.free(argv);
    argv[0] = config.command;
    @memcpy(argv[1..], config.args);

    // Production OS FS apply: cli/run calls sandbox.apply.applyBeforeExec before
    // supervisor.run, then passes os_child_apply for the agent spawn (no scaffold path).

    var prepared = process.prepareChild(io, allocator, .{
        .io = io,
        .argv = argv,
        .workspace_root = workspace_root,
        .stdio = config.stdio,
        .env_map = config.env_map,
        .os_child_apply = config.os_child_apply,
    });

    prepared.spawn() catch |err| switch (err) {
        error.FileNotFound => return error.CommandNotFound,
        else => return err,
    };
    // Spawn succeeded: any later parent error must kill+reap (M-4 free-before-reap).
    prepared.waitForSpawn() catch |err| {
        prepared.terminateAfterParentError();
        return switch (err) {
            error.FileNotFound => error.CommandNotFound,
            else => err,
        };
    };

    if (config.custom_spawn_used_out) |out| {
        out.* = prepared.custom_spawn_used;
    }

    // After fork: start deferred services (e.g. proxy accept loop) while the
    // child has already completed sandboxed apply (M-5 single-thread fork).
    if (config.after_process_spawn) |hook| {
        hook.callback(hook.context, session) catch |err| {
            prepared.terminateAfterParentError();
            return err;
        };
    }

    if (config.on_session_start) |hook| {
        hook.callback(hook.context, session) catch |err| {
            prepared.terminateAfterParentError();
            return err;
        };
    }

    var health_stop = std.atomic.Value(bool).init(false);
    var health_failed = std.atomic.Value(bool).init(false);
    var health_context: HealthMonitorThreadContext = undefined;
    var health_thread: ?std.Thread = null;
    if (config.health_monitor) |monitor| {
        health_context = .{
            .prepared = &prepared,
            .monitor = monitor,
            .stop = &health_stop,
            .failed = &health_failed,
        };
        // After spawn succeeds, any parent error must reap the child (M-4).
        health_thread = std.Thread.spawn(.{}, healthMonitorLoop, .{&health_context}) catch |err| {
            prepared.terminateAfterParentError();
            return err;
        };
    }
    defer {
        health_stop.store(true, .release);
        if (health_thread) |thread| thread.join();
    }

    // Sole reaper for the agent child. Health monitor only signals (M-6).
    const term = prepared.wait() catch |err| {
        prepared.terminateAfterParentError();
        return err;
    };

    const ended_at = time.Timestamp.now(io);
    session.ended_at = ended_at;
    const status = childStatusFromTerm(term);
    events[next_event_index] = try makeOwnedTargetEvent(allocator, &event_target_values, &owned_targets, session, ended_at, .session_exit, .session, session.id.slice());
    if (config.on_event) |hook| {
        try hook.callback(hook.context, events[next_event_index]);
    }

    return .{
        .session = session,
        .status = status,
        .events = events,
        .event_target_values = event_target_values,
        .allocator = allocator,
    };
}

fn makeEnvRedactionEvent(
    allocator: std.mem.Allocator,
    event_target_values: *[][]const u8,
    owned_targets: *usize,
    session: session_mod.Session,
    timestamp: time.Timestamp,
    record: EnvRedactionRecord,
) !event.Event {
    var ev = try makeOwnedTargetEvent(allocator, event_target_values, owned_targets, session, timestamp, .secret_redacted, .env_var, record.name);
    ev.decision = .{
        .result = .redact,
        .reason = record.reason,
        .ci_may_proceed = true,
    };
    ev.redactions = .{
        .count = @intCast(record.labels.len),
        .labels = record.labels,
    };
    return ev;
}

fn commandDisplay(allocator: std.mem.Allocator, command: []const u8, args: []const []const u8) ![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    try list.appendSlice(allocator, command);
    for (args) |arg| {
        try list.append(allocator, ' ');
        try list.appendSlice(allocator, arg);
    }
    return try list.toOwnedSlice(allocator);
}

pub fn resolveWorkspaceRoot(
    io: std.Io,
    allocator: std.mem.Allocator,
    explicit_workspace: ?[]const u8,
    start_path: []const u8,
) ![]u8 {
    const cwd = std.Io.Dir.cwd();
    if (explicit_workspace) |workspace| {
        const resolved_z = try cwd.realPathFileAlloc(io, workspace, allocator);
        defer allocator.free(resolved_z);
        return try allocator.dupe(u8, resolved_z);
    }

    const fallback = blk: {
        const fallback_z = try cwd.realPathFileAlloc(io, start_path, allocator);
        defer allocator.free(fallback_z);
        break :blk try allocator.dupe(u8, fallback_z);
    };
    errdefer allocator.free(fallback);
    var current = try allocator.dupe(u8, fallback);
    errdefer allocator.free(current);

    while (true) {
        const git_path = try std.fs.path.join(allocator, &.{ current, ".git" });
        defer allocator.free(git_path);
        const ryk_policy_path = try std.fs.path.join(allocator, &.{ current, ".ryk", "policy.yaml" });
        defer allocator.free(ryk_policy_path);

        if (hasGitMarker(io, git_path) or hasWorkspaceMarker(io, ryk_policy_path)) {
            allocator.free(fallback);
            return current;
        }

        const parent = std.fs.path.dirname(current) orelse {
            allocator.free(current);
            return fallback;
        };
        if (std.mem.eql(u8, parent, current)) {
            allocator.free(current);
            return fallback;
        }

        const next = try allocator.dupe(u8, parent);
        allocator.free(current);
        current = next;
    }
}

fn hasGitMarker(io: std.Io, path: []const u8) bool {
    std.Io.Dir.accessAbsolute(io, path, .{}) catch return false;
    return true;
}

fn hasWorkspaceMarker(io: std.Io, path: []const u8) bool {
    std.Io.Dir.accessAbsolute(io, path, .{}) catch return false;
    return true;
}

fn childStatusFromTerm(term: std.process.Child.Term) ChildStatus {
    return switch (term) {
        .exited => |code| .{ .exited = code },
        .signal => |signal| .{ .signal = @intFromEnum(signal) },
        .stopped => |signal| .{ .stopped = @intFromEnum(signal) },
        .unknown => |status| .{ .unknown = status },
    };
}

fn makeEvent(
    session: session_mod.Session,
    timestamp: time.Timestamp,
    event_type: event.EventType,
    target_kind: types.TargetKind,
    target_value: []const u8,
) !event.Event {
    return .{
        .session_id = session.id,
        .event_id = try event.generateEventId(timestamp),
        .timestamp = timestamp,
        .event_type = event_type,
        .actor = .{ .kind = .ryk, .display = "ryk" },
        .target = .{ .kind = target_kind, .value = target_value },
    };
}

fn makeOwnedTargetEvent(
    allocator: std.mem.Allocator,
    event_target_values: *[][]const u8,
    owned_targets: *usize,
    session: session_mod.Session,
    timestamp: time.Timestamp,
    event_type: event.EventType,
    target_kind: types.TargetKind,
    target_value: []const u8,
) !event.Event {
    const owned_target = try allocator.dupe(u8, target_value);
    errdefer allocator.free(owned_target);
    event_target_values.*[owned_targets.*] = owned_target;
    owned_targets.* += 1;
    return makeEvent(session, timestamp, event_type, target_kind, owned_target);
}

const FailingHookContext = struct {
    calls: usize = 0,

    fn fail(context: *anyopaque, _: session_mod.Session) !void {
        const self: *FailingHookContext = @ptrCast(@alignCast(context));
        self.calls += 1;
        return error.IntentionalHookFailure;
    }
};

test "run config construction captures phase 05 inputs" {
    const config: RunConfig = .{
        .command = "zig",
        .args = &.{"version"},
        .workspace = ".",
        .mode = .observe,
        .session_name = "smoke",
        .stdio = .ignore,
    };

    try std.testing.expectEqualStrings("zig", config.command);
    try std.testing.expectEqualStrings("version", config.args[0]);
    try std.testing.expectEqualStrings(".", config.workspace.?);
    try std.testing.expectEqual(types.Mode.observe, config.mode);
    try std.testing.expectEqualStrings("smoke", config.session_name.?);
}

test "workspace detection honors explicit workspace" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const explicit = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(explicit);

    const resolved = try resolveWorkspaceRoot(std.testing.io, std.testing.allocator, explicit, "/");
    defer std.testing.allocator.free(resolved);

    try std.testing.expectEqualStrings(explicit, resolved);
}

test "workspace detection finds nearest git parent" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(std.testing.io, ".git");
    try tmp.dir.createDirPath(std.testing.io, "child/grandchild");

    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const child = try tmp.dir.realPathFileAlloc(std.testing.io, "child/grandchild", std.testing.allocator);
    defer std.testing.allocator.free(child);

    const resolved = try resolveWorkspaceRoot(std.testing.io, std.testing.allocator, null, child);
    defer std.testing.allocator.free(resolved);

    try std.testing.expectEqualStrings(root, resolved);
}

test "workspace detection finds nearest ryk policy parent" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(std.testing.io, ".ryk");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = ".ryk/policy.yaml", .data = "mode: observe\n" });
    try tmp.dir.createDirPath(std.testing.io, "child/grandchild");

    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const child = try tmp.dir.realPathFileAlloc(std.testing.io, "child/grandchild", std.testing.allocator);
    defer std.testing.allocator.free(child);

    const resolved = try resolveWorkspaceRoot(std.testing.io, std.testing.allocator, null, child);
    defer std.testing.allocator.free(resolved);

    try std.testing.expectEqualStrings(root, resolved);
}

test "workspace detection falls back to start directory outside git" {
    const tmp_parent = if (std.c.getenv("TMPDIR")) |value|
        try std.testing.allocator.dupe(u8, std.mem.span(value))
    else
        try std.testing.allocator.dupe(u8, "/tmp");
    defer std.testing.allocator.free(tmp_parent);

    var suffix_buf: [8]u8 = undefined;
    const suffix = try util.randomHexSuffix(std.testing.io, &suffix_buf);
    const relative_name = try std.fmt.allocPrint(std.testing.allocator, "ryk-non-git-{s}", .{suffix});
    defer std.testing.allocator.free(relative_name);
    const tmp_path = try std.fs.path.join(std.testing.allocator, &.{ tmp_parent, relative_name });
    defer std.testing.allocator.free(tmp_path);

    try std.Io.Dir.cwd().createDirPath(std.testing.io, tmp_path);
    defer std.Io.Dir.cwd().deleteTree(std.testing.io, tmp_path) catch {};

    const root = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, tmp_path, std.testing.allocator);
    defer std.testing.allocator.free(root);

    const resolved = try resolveWorkspaceRoot(std.testing.io, std.testing.allocator, null, root);
    defer std.testing.allocator.free(resolved);

    try std.testing.expectEqualStrings(root, resolved);
}

test "running a simple child populates session metadata and events" {
    var result = try run(std.testing.io, std.testing.allocator, .{
        .command = "zig",
        .args = &.{"version"},
        .workspace = ".",
        .mode = .observe,
        .session_name = "unit",
        .stdio = .ignore,
    });
    defer result.deinit();

    try std.testing.expectEqual(@as(i32, 0), result.exitCode());
    try std.testing.expect(result.session.id.len > 0);
    try std.testing.expect(result.session.ended_at != null);
    try std.testing.expectEqualStrings("zig", result.session.command);
    try std.testing.expectEqualStrings("unit", result.session.session_name.?);
    try std.testing.expectEqual(types.Mode.observe, result.session.mode);
    try std.testing.expectEqual(@as(usize, 3), result.events.len);
    try std.testing.expectEqual(event.EventType.session_start, result.events[0].event_type);
    try std.testing.expectEqual(event.EventType.process_launch, result.events[1].event_type);
    try std.testing.expectEqual(event.EventType.session_exit, result.events[2].event_type);
    try std.testing.expectEqualStrings(result.session.id.slice(), result.events[0].target.value);
    try std.testing.expectEqualStrings(result.session.id.slice(), result.events[2].target.value);
    try std.testing.expect(result.events[0].target.value.ptr != result.session.id.slice().ptr);
    try std.testing.expect(result.events[2].target.value.ptr != result.session.id.slice().ptr);
}

test "filtered child environment receives allowed vars and not denied vars" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var env_map = std.process.Environ.Map.init(std.testing.allocator);
    defer env_map.deinit();
    try env_map.put("PATH", "/usr/bin:/bin");
    try env_map.put("SAFE_FAKE", "visible");

    var result = try run(std.testing.io, std.testing.allocator, .{
        .command = "/bin/sh",
        .args = &.{ "-c", "env > child-env.txt" },
        .workspace = root,
        .stdio = .ignore,
        .env_map = &env_map,
    });
    defer result.deinit();

    const written = try tmp.dir.readFileAlloc(std.testing.io, "child-env.txt", std.testing.allocator, .limited(4096));
    defer std.testing.allocator.free(written);
    try std.testing.expect(std.mem.indexOf(u8, written, "SAFE_FAKE=visible") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "FAKE_GITHUB_TOKEN") == null);
}

test "child non-zero exit code is propagated" {
    var result = try run(std.testing.io, std.testing.allocator, .{
        .command = "zig",
        .args = &.{"definitely-not-a-zig-command"},
        .workspace = ".",
        .stdio = .ignore,
    });
    defer result.deinit();

    try std.testing.expect(result.exitCode() != 0);
}

test "missing child command returns useful typed error" {
    try std.testing.expectError(error.CommandNotFound, run(std.testing.io, std.testing.allocator, .{
        .command = "ryk-definitely-missing-command",
        .workspace = ".",
        .stdio = .ignore,
    }));
}

test "session start hook failure cleans up spawned child and returns hook error" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    var context: FailingHookContext = .{};
    const started = std.Io.Timestamp.now(std.testing.io, .awake).toMilliseconds();
    try std.testing.expectError(error.IntentionalHookFailure, run(std.testing.io, std.testing.allocator, .{
        .command = "/bin/sh",
        .args = &.{ "-c", "sleep 0.1" },
        .workspace = ".",
        .stdio = .ignore,
        .on_session_start = .{
            .context = &context,
            .callback = FailingHookContext.fail,
        },
    }));
    const elapsed_ms = std.Io.Timestamp.now(std.testing.io, .awake).toMilliseconds() - started;

    try std.testing.expectEqual(@as(usize, 1), context.calls);
    try std.testing.expect(elapsed_ms < 1_500);
}

const FailingHealthContext = struct {
    calls: std.atomic.Value(usize) = .init(0),

    fn healthy(context: *anyopaque) bool {
        const self: *FailingHealthContext = @ptrCast(@alignCast(context));
        _ = self.calls.fetchAdd(1, .acq_rel);
        return false;
    }
};

test "health monitor terminates child when required runtime dies" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    var context: FailingHealthContext = .{};
    const started = std.Io.Timestamp.now(std.testing.io, .awake).toMilliseconds();
    var result = try run(std.testing.io, std.testing.allocator, .{
        .command = "/bin/sh",
        .args = &.{ "-c", "sleep 2" },
        .workspace = ".",
        .stdio = .ignore,
        .health_monitor = .{
            .context = &context,
            .callback = FailingHealthContext.healthy,
        },
    });
    defer result.deinit();
    const elapsed_ms = std.Io.Timestamp.now(std.testing.io, .awake).toMilliseconds() - started;

    try std.testing.expect(result.exitCode() != 0);
    try std.testing.expect(elapsed_ms < 1_500);
    try std.testing.expect(context.calls.load(.acquire) > 0);
}

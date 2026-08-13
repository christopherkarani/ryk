const std = @import("std");
const builtin = @import("builtin");
const core = @import("ryk_core").core;
const contract = @import("telemetry_contract.zig");
const product = @import("telemetry_product.zig");
const env_util = @import("env_util.zig");

pub const state_file_name = "telemetry.json";
pub const queue_file_name = "telemetry.queue.jsonl";
pub const lock_file_name = "telemetry.lock";
pub const send_lock_file_name = "telemetry.send.lock";
pub const max_state_bytes = 4096;
// Queue entries are newline-delimited. Include the delimiter in the read
// bound so a full queue of maximum-sized events remains readable.
pub const max_queue_bytes = contract.max_queue_events * (contract.max_event_bytes + 1);

pub const StateSource = enum { default, persisted, environment };

pub const State = struct {
    enabled: bool,
    installation_id: ?[]u8 = null,
    activation_recorded: bool = false,

    pub fn deinit(self: *State, allocator: std.mem.Allocator) void {
        if (self.installation_id) |id| allocator.free(id);
        self.* = undefined;
    }
};

pub const LoadedState = struct {
    state: State,
    source: StateSource,

    pub fn deinit(self: *LoadedState, allocator: std.mem.Allocator) void {
        self.state.deinit(allocator);
        self.* = undefined;
    }
};

pub const Paths = struct {
    config_dir: []u8,
    state: []u8,
    queue: []u8,
    lock: []u8,
    send_lock: []u8,

    pub fn deinit(self: *Paths, allocator: std.mem.Allocator) void {
        allocator.free(self.config_dir);
        allocator.free(self.state);
        allocator.free(self.queue);
        allocator.free(self.lock);
        allocator.free(self.send_lock);
        self.* = undefined;
    }
};

pub const StoreLock = struct {
    file: std.Io.File,

    pub fn acquire(io: std.Io, paths: *const Paths) !StoreLock {
        const permissions: std.Io.File.Permissions = @enumFromInt(0o600);
        const file = try std.Io.Dir.cwd().createFile(io, paths.lock, .{
            .read = true,
            .truncate = false,
            .permissions = permissions,
        });
        errdefer file.close(io);
        try file.lock(io, .exclusive);
        return .{ .file = file };
    }

    pub fn release(self: *StoreLock, io: std.Io) void {
        self.file.unlock(io);
        self.file.close(io);
        self.* = undefined;
    }
};

pub const SendLock = struct {
    file: std.Io.File,

    pub fn acquire(io: std.Io, paths: *const Paths) !SendLock {
        const permissions: std.Io.File.Permissions = @enumFromInt(0o600);
        const file = try std.Io.Dir.cwd().createFile(io, paths.send_lock, .{
            .read = true,
            .truncate = false,
            .permissions = permissions,
        });
        errdefer file.close(io);
        try file.lock(io, .exclusive);
        return .{ .file = file };
    }

    pub fn tryAcquire(io: std.Io, paths: *const Paths) !?SendLock {
        const permissions: std.Io.File.Permissions = @enumFromInt(0o600);
        const file = try std.Io.Dir.cwd().createFile(io, paths.send_lock, .{
            .read = true,
            .truncate = false,
            .permissions = permissions,
        });
        errdefer file.close(io);
        if (!(try file.tryLock(io, .exclusive))) {
            file.close(io);
            return null;
        }
        return .{ .file = file };
    }

    pub fn release(self: *SendLock, io: std.Io) void {
        self.file.unlock(io);
        self.file.close(io);
        self.* = undefined;
    }
};

pub const Queue = struct {
    items: std.ArrayList([]u8) = .empty,

    pub fn deinit(self: *Queue, allocator: std.mem.Allocator) void {
        for (self.items.items) |item| allocator.free(item);
        self.items.deinit(allocator);
        self.* = undefined;
    }
};

pub fn setEnabled(
    io: std.Io,
    environ_map: *const std.process.Environ.Map,
    allocator: std.mem.Allocator,
    enabled: bool,
    transport_configured: bool,
) !void {
    var paths = (try resolvePaths(allocator, environ_map)) orelse return error.NoConfigDirectory;
    defer paths.deinit(allocator);
    try ensureConfigDir(io, &paths);
    var sender = try SendLock.acquire(io, &paths);
    defer sender.release(io);
    var lock = try StoreLock.acquire(io, &paths);
    defer lock.release(io);

    var loaded: LoadedState = if (enabled)
        try readState(allocator, io, &paths)
    else
        readState(allocator, io, &paths) catch |err| switch (err) {
            error.InvalidTelemetryState => .{ .state = .{ .enabled = false }, .source = .persisted },
            else => return err,
        };
    defer loaded.deinit(allocator);
    loaded.state.enabled = enabled;
    if (enabled) {
        if (transport_configured and loaded.state.installation_id == null) {
            loaded.state.installation_id = try contract.generateInstallationId(allocator, io);
        }
    } else {
        if (loaded.state.installation_id) |id| allocator.free(id);
        loaded.state.installation_id = null;
        loaded.state.activation_recorded = false;
    }
    if (!enabled) try writeQueue(io, allocator, &paths, &.{});
    const body = try renderState(allocator, &loaded.state);
    defer allocator.free(body);
    try writeAtomic(io, allocator, paths.state, body);
}

pub fn ensureInstallationId(
    io: std.Io,
    environ_map: *const std.process.Environ.Map,
    allocator: std.mem.Allocator,
) ![]u8 {
    var paths = (try resolvePaths(allocator, environ_map)) orelse return error.NoConfigDirectory;
    defer paths.deinit(allocator);
    try ensureConfigDir(io, &paths);
    var lock = try StoreLock.acquire(io, &paths);
    defer lock.release(io);

    var loaded = try readState(allocator, io, &paths);
    defer loaded.deinit(allocator);
    if (!loaded.state.enabled) return error.TelemetryDisabled;
    if (loaded.state.installation_id == null) {
        loaded.state.installation_id = try contract.generateInstallationId(allocator, io);
        const body = try renderState(allocator, &loaded.state);
        defer allocator.free(body);
        try writeAtomic(io, allocator, paths.state, body);
    }
    return try allocator.dupe(u8, loaded.state.installation_id.?);
}

pub fn appendEvent(
    io: std.Io,
    environ_map: *const std.process.Environ.Map,
    allocator: std.mem.Allocator,
    event: []const u8,
) !void {
    if (event.len > contract.max_event_bytes) return error.TelemetryEventTooLarge;
    var paths = (try resolvePaths(allocator, environ_map)) orelse return error.NoConfigDirectory;
    defer paths.deinit(allocator);
    try ensureConfigDir(io, &paths);
    var lock = try StoreLock.acquire(io, &paths);
    defer lock.release(io);

    var state = try readState(allocator, io, &paths);
    defer state.deinit(allocator);
    if (!state.state.enabled) return error.TelemetryDisabled;

    var queue = try readQueue(allocator, io, &paths);
    defer queue.deinit(allocator);
    while (queue.items.items.len >= contract.max_queue_events) {
        if (!dropOldestNonActivation(allocator, &queue)) return error.TelemetryQueueFull;
    }
    const copy = try allocator.dupe(u8, event);
    queue.items.append(allocator, copy) catch |err| {
        allocator.free(copy);
        return err;
    };
    try writeQueue(io, allocator, &paths, queue.items.items);
}

/// Append the activation event and mark it recorded under one store lock.
/// This prevents concurrent CLI processes from emitting duplicate first-run
/// events while keeping ordinary events on the existing queue path.
pub fn appendActivationEvent(
    io: std.Io,
    environ_map: *const std.process.Environ.Map,
    allocator: std.mem.Allocator,
    event: []const u8,
) !bool {
    if (event.len > contract.max_event_bytes) return error.TelemetryEventTooLarge;
    var paths = (try resolvePaths(allocator, environ_map)) orelse return error.NoConfigDirectory;
    defer paths.deinit(allocator);
    try ensureConfigDir(io, &paths);
    var lock = try StoreLock.acquire(io, &paths);
    defer lock.release(io);

    var loaded = try readState(allocator, io, &paths);
    defer loaded.deinit(allocator);
    if (!loaded.state.enabled) return error.TelemetryDisabled;
    if (loaded.state.activation_recorded) return false;

    var queue = try readQueue(allocator, io, &paths);
    defer queue.deinit(allocator);
    for (queue.items.items) |queued| {
        if (!sameActivationInstallation(allocator, queued, event)) continue;
        loaded.state.activation_recorded = true;
        const body = try renderState(allocator, &loaded.state);
        defer allocator.free(body);
        try writeAtomic(io, allocator, paths.state, body);
        return false;
    }
    while (queue.items.items.len >= contract.max_queue_events) {
        if (!dropOldestNonActivation(allocator, &queue)) return false;
    }
    const copy = try allocator.dupe(u8, event);
    queue.items.append(allocator, copy) catch |err| {
        allocator.free(copy);
        return err;
    };
    try writeQueue(io, allocator, &paths, queue.items.items);

    loaded.state.activation_recorded = true;
    const body = try renderState(allocator, &loaded.state);
    defer allocator.free(body);
    try writeAtomic(io, allocator, paths.state, body);
    return true;
}

fn sameActivationInstallation(allocator: std.mem.Allocator, queued: []const u8, event: []const u8) bool {
    var queued_parsed = std.json.parseFromSlice(std.json.Value, allocator, queued, .{}) catch return false;
    defer queued_parsed.deinit();
    var event_parsed = std.json.parseFromSlice(std.json.Value, allocator, event, .{}) catch return false;
    defer event_parsed.deinit();
    const queued_id = activationInstallationId(queued_parsed.value) orelse return false;
    const event_id = activationInstallationId(event_parsed.value) orelse return false;
    return std.mem.eql(u8, queued_id, event_id);
}

fn dropOldestNonActivation(allocator: std.mem.Allocator, queue: *Queue) bool {
    for (queue.items.items, 0..) |item, index| {
        if (isActivationEvent(allocator, item)) continue;
        const dropped = queue.items.orderedRemove(index);
        allocator.free(dropped);
        return true;
    }
    return false;
}

fn isActivationEvent(allocator: std.mem.Allocator, event: []const u8) bool {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, event, .{}) catch return false;
    defer parsed.deinit();
    return activationInstallationId(parsed.value) != null;
}

fn activationInstallationId(value: std.json.Value) ?[]const u8 {
    if (value != .object or !product.validQueuedEvent(value)) return null;
    const root = value.object;
    const event_name = root.get("event") orelse return null;
    if (event_name != .string or !std.mem.eql(u8, event_name.string, product.activation_event_name)) return null;
    const properties = root.get("properties") orelse return null;
    if (properties != .object) return null;
    const distinct_id = properties.object.get("distinct_id") orelse return null;
    return if (distinct_id == .string) distinct_id.string else null;
}

pub fn queueCount(allocator: std.mem.Allocator, io: std.Io, environ_map: *const std.process.Environ.Map) !usize {
    const paths = (try resolvePaths(allocator, environ_map)) orelse return 0;
    defer {
        var owned_paths = paths;
        owned_paths.deinit(allocator);
    }
    var queue = try readQueue(allocator, io, &paths);
    defer queue.deinit(allocator);
    return queue.items.items.len;
}

pub fn removeSentPrefix(allocator: std.mem.Allocator, queue: *Queue, sent: *const Queue) usize {
    var count: usize = 0;
    while (count < sent.items.items.len and count < queue.items.items.len and
        std.mem.eql(u8, sent.items.items[count], queue.items.items[count])) : (count += 1)
    {
        allocator.free(queue.items.items[count]);
    }
    if (count == 0) return 0;

    const remaining = queue.items.items.len - count;
    std.mem.copyForwards([]u8, queue.items.items[0..remaining], queue.items.items[count..]);
    queue.items.items.len = remaining;
    return count;
}

pub fn resolvePaths(allocator: std.mem.Allocator, environ_map: *const std.process.Environ.Map) !?Paths {
    const config_root = if (environ_map.get("XDG_CONFIG_HOME")) |xdg| if (xdg.len > 0) xdg else null else null;
    if (config_root) |value| if (!std.fs.path.isAbsolute(value)) return error.InvalidConfigPath;
    const home = if (config_root == null) try env_util.getOwnedHome(environ_map, allocator) else null;
    defer if (home) |value| allocator.free(value);
    if (home) |value| if (!std.fs.path.isAbsolute(value)) return error.InvalidConfigPath;
    const base = config_root orelse if (home) |value| blk: {
        const result = try std.fs.path.join(allocator, &.{ value, ".config" });
        break :blk result;
    } else return null;
    const owned_base = if (config_root != null) try allocator.dupe(u8, base) else base;
    defer allocator.free(owned_base);

    const config_dir = try std.fs.path.join(allocator, &.{ owned_base, "ryk" });
    errdefer allocator.free(config_dir);
    const state = try std.fs.path.join(allocator, &.{ config_dir, state_file_name });
    errdefer allocator.free(state);
    const queue = try std.fs.path.join(allocator, &.{ config_dir, queue_file_name });
    errdefer allocator.free(queue);
    const lock = try std.fs.path.join(allocator, &.{ config_dir, lock_file_name });
    errdefer allocator.free(lock);
    const send_lock = try std.fs.path.join(allocator, &.{ config_dir, send_lock_file_name });
    return .{
        .config_dir = config_dir,
        .state = state,
        .queue = queue,
        .lock = lock,
        .send_lock = send_lock,
    };
}

pub fn readState(allocator: std.mem.Allocator, io: std.Io, paths: *const Paths) !LoadedState {
    const text = std.Io.Dir.cwd().readFileAlloc(
        io,
        paths.state,
        allocator,
        .limited(max_state_bytes),
    ) catch |err| switch (err) {
        // Opt-in default (2026-08 P1): no consent state means disabled. Telemetry
        // activates only through an explicit `ryk telemetry enable`.
        error.FileNotFound => return .{ .state = .{ .enabled = false }, .source = .default },
        else => return err,
    };
    defer allocator.free(text);
    return .{ .state = try parseState(allocator, text), .source = .persisted };
}

pub fn parseState(allocator: std.mem.Allocator, text: []const u8) !State {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, text, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidTelemetryState,
    };
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidTelemetryState;
    const object = parsed.value.object;
    try contract.rejectUnknownKeys(object, &.{ "schema_version", "enabled", "installation_id", "activation_recorded" });
    const version = object.get("schema_version") orelse return error.InvalidTelemetryState;
    if (version != .integer or version.integer != contract.schema_version) return error.InvalidTelemetryState;
    const enabled_value = object.get("enabled") orelse return error.InvalidTelemetryState;
    const enabled = switch (enabled_value) {
        .bool => |value| value,
        else => return error.InvalidTelemetryState,
    };
    var installation_id: ?[]u8 = null;
    if (object.get("installation_id")) |value| switch (value) {
        .null => {},
        .string => |id| {
            if (!contract.validInstallationId(id)) return error.InvalidTelemetryState;
            installation_id = try allocator.dupe(u8, id);
        },
        else => return error.InvalidTelemetryState,
    };
    errdefer if (installation_id) |id| allocator.free(id);
    if (!enabled and installation_id != null) {
        return error.InvalidTelemetryState;
    }
    var activation_recorded = false;
    if (object.get("activation_recorded")) |value| {
        activation_recorded = switch (value) {
            .bool => |recorded| recorded,
            else => return error.InvalidTelemetryState,
        };
    }
    if (!enabled and activation_recorded) {
        return error.InvalidTelemetryState;
    }
    return .{ .enabled = enabled, .installation_id = installation_id, .activation_recorded = activation_recorded };
}

pub fn readQueue(allocator: std.mem.Allocator, io: std.Io, paths: *const Paths) !Queue {
    const text = std.Io.Dir.cwd().readFileAlloc(
        io,
        paths.queue,
        allocator,
        .limited(max_queue_bytes),
    ) catch |err| switch (err) {
        error.FileNotFound => return .{},
        else => return err,
    };
    defer allocator.free(text);
    var queue: Queue = .{};
    errdefer queue.deinit(allocator);
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (line.len > contract.max_event_bytes) return error.InvalidTelemetryQueue;
        var parsed = std.json.parseFromSlice(std.json.Value, allocator, line, .{}) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidTelemetryQueue,
        };
        defer parsed.deinit();
        if (!contract.validQueuedEvent(parsed.value)) return error.InvalidTelemetryQueue;
        const copy = try allocator.dupe(u8, line);
        queue.items.append(allocator, copy) catch |err| {
            allocator.free(copy);
            return err;
        };
        if (queue.items.items.len > contract.max_queue_events) return error.InvalidTelemetryQueue;
    }
    return queue;
}

pub fn writeQueue(io: std.Io, allocator: std.mem.Allocator, paths: *const Paths, items: []const []const u8) !void {
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    for (items) |item| {
        try out.writer.writeAll(item);
        try out.writer.writeByte('\n');
    }
    const body = try out.toOwnedSlice();
    defer allocator.free(body);
    try writeAtomic(io, allocator, paths.queue, body);
}

pub fn renderState(allocator: std.mem.Allocator, state: *const State) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    try out.writer.print(
        "{{\"schema_version\":1,\"enabled\":{s},\"installation_id\":",
        .{if (state.enabled) "true" else "false"},
    );
    if (state.installation_id) |id| try core.util.writeJsonString(&out.writer, id) else try out.writer.writeAll("null");
    try out.writer.print(",\"activation_recorded\":{s}}}\n", .{if (state.activation_recorded) "true" else "false"});
    return try out.toOwnedSlice();
}

pub fn ensureConfigDir(io: std.Io, paths: *const Paths) !void {
    const permissions: std.Io.Dir.Permissions = @enumFromInt(0o700);
    _ = try std.Io.Dir.cwd().createDirPathStatus(io, paths.config_dir, permissions);
}

pub fn writeAtomic(io: std.Io, allocator: std.mem.Allocator, path: []const u8, body: []const u8) !void {
    const permissions: std.Io.File.Permissions = @enumFromInt(0o600);
    var nonce: u64 = undefined;
    io.random(std.mem.asBytes(&nonce));
    const temp_path = try std.fmt.allocPrint(allocator, "{s}.tmp.{x}", .{ path, nonce });
    defer allocator.free(temp_path);
    const file = try std.Io.Dir.cwd().createFile(io, temp_path, .{
        .exclusive = true,
        .permissions = permissions,
    });
    errdefer std.Io.Dir.cwd().deleteFile(io, temp_path) catch {};
    {
        defer file.close(io);
        try file.writeStreamingAll(io, body);
        try file.sync(io);
    }
    try enforceOwnerOnlyWindows(allocator, temp_path);
    try std.Io.Dir.renameAbsolute(temp_path, path, io);
}

extern fn ryk_set_owner_only_acl(path: [*:0]const u16) callconv(.c) c_int;

fn enforceOwnerOnlyWindows(allocator: std.mem.Allocator, path: []const u8) !void {
    if (comptime builtin.os.tag != .windows) return;
    const wide_path = try std.unicode.utf8ToUtf16LeAllocZ(allocator, path);
    defer allocator.free(wide_path);
    if (ryk_set_owner_only_acl(wide_path.ptr) != 1) return error.WindowsAclFailed;
}

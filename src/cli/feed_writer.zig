const std = @import("std");
const builtin = @import("builtin");

const core = @import("ryk_core").core;
const core_api = @import("ryk_core").api;
const redact_bridge = @import("ryk_core").audit.redact_bridge;
const env_util = @import("../env_util.zig");
const rust_visibility = @import("feed_visibility.zig");

pub const feed_dir_name = "feed";
pub const feed_file_name = "rust_shell_decisions.jsonl";
pub const global_events_file_name = "events.jsonl";
pub const workspace_registry_file_name = "workspaces.json";
pub const rotated_global_events_file_name = "events.jsonl.1";
pub const max_registered_workspaces: usize = 200;

pub fn feedPath(allocator: std.mem.Allocator, workspace_root: []const u8) ![]u8 {
    return std.fs.path.join(allocator, &.{ workspace_root, ".ryk", feed_dir_name, feed_file_name });
}

pub const AppendOptions = struct {
    sync: bool = true,
    update_registry: bool = true,
};

/// Test-only: how many `file.sync` calls the feed writer issued.
var test_sync_calls: usize = 0;

fn maybeSync(io: std.Io, file: std.Io.File, do_sync: bool) !void {
    if (!do_sync) return;
    if (builtin.is_test) test_sync_calls += 1;
    try file.sync(io);
}

fn isAllowDecision(decision: []const u8) bool {
    return std.mem.eql(u8, decision, "allow") or std.mem.eql(u8, decision, "context_only");
}

pub fn appendRecord(io: std.Io, allocator: std.mem.Allocator, workspace_root: []const u8, record: rust_visibility.RustShellFeedRecord) !void {
    return appendRecordWithOptions(io, allocator, workspace_root, record, .{});
}

pub fn appendRecordWithOptions(
    io: std.Io,
    allocator: std.mem.Allocator,
    workspace_root: []const u8,
    record: rust_visibility.RustShellFeedRecord,
    opts: AppendOptions,
) !void {
    const feed_dir = try std.fs.path.join(allocator, &.{ workspace_root, ".ryk", feed_dir_name });
    defer allocator.free(feed_dir);
    try std.Io.Dir.cwd().createDirPath(io, feed_dir);

    const feed_path = try feedPath(allocator, workspace_root);
    defer allocator.free(feed_path);

    try appendRecordAtPath(io, allocator, feed_path, record, opts.sync);
}

fn appendRecordAtPath(
    io: std.Io,
    allocator: std.mem.Allocator,
    path: []const u8,
    record: rust_visibility.RustShellFeedRecord,
    do_sync: bool,
) !void {
    var file = try std.Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = false, .lock = .exclusive });
    defer file.close(io);
    const end_offset = (try file.stat(io)).size;
    var file_buf: [4096]u8 = undefined;
    var file_writer = file.writer(io, &file_buf);
    try file_writer.seekToUnbuffered(end_offset);

    var line: std.Io.Writer.Allocating = .init(allocator);
    defer line.deinit();
    try rust_visibility.writeFeedRecordJson(&line.writer, record);
    try line.writer.writeByte('\n');
    const bytes = try line.toOwnedSlice();
    defer allocator.free(bytes);
    try file_writer.interface.writeAll(bytes);
    try file_writer.interface.flush();
    try maybeSync(io, file, do_sync);
}

pub fn appendGlobalRecord(
    io: std.Io,
    allocator: std.mem.Allocator,
    dashboard_root: []const u8,
    record: rust_visibility.RustShellFeedRecord,
) !void {
    return appendGlobalRecordWithOptions(io, allocator, dashboard_root, record, .{});
}

fn appendGlobalRecordWithSync(
    io: std.Io,
    allocator: std.mem.Allocator,
    dashboard_root: []const u8,
    record: rust_visibility.RustShellFeedRecord,
    sync_after: bool,
) !void {
    return appendGlobalRecordWithOptions(io, allocator, dashboard_root, record, .{
        .sync = sync_after,
        .update_registry = true,
    });
}

pub fn appendGlobalRecordWithOptions(
    io: std.Io,
    allocator: std.mem.Allocator,
    dashboard_root: []const u8,
    record: rust_visibility.RustShellFeedRecord,
    opts: AppendOptions,
) !void {
    try std.Io.Dir.cwd().createDirPath(io, dashboard_root);

    const lock_path = try std.fs.path.join(allocator, &.{ dashboard_root, ".write.lock" });
    defer allocator.free(lock_path);
    const lock_file = try std.Io.Dir.cwd().createFile(io, lock_path, .{ .read = true });
    defer lock_file.close(io);
    try lock_file.lock(io, .exclusive);
    defer lock_file.unlock(io);

    const events_path = try std.fs.path.join(allocator, &.{ dashboard_root, global_events_file_name });
    defer allocator.free(events_path);
    try rotateGlobalFeedIfNeeded(io, allocator, dashboard_root, events_path);
    try appendRecordAtPath(io, allocator, events_path, record, opts.sync);
    if (opts.update_registry) {
        try updateWorkspaceRegistry(io, allocator, dashboard_root, record);
    }
}

fn rotateGlobalFeedIfNeeded(io: std.Io, allocator: std.mem.Allocator, dashboard_root: []const u8, events_path: []const u8) !void {
    const size = blk: {
        const file = std.Io.Dir.cwd().openFile(io, events_path, .{}) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return err,
        };
        defer file.close(io);
        break :blk (try file.stat(io)).size;
    };
    if (size < core.limits.max_dashboard_feed_len) return;

    const rotated_path = try std.fs.path.join(allocator, &.{ dashboard_root, rotated_global_events_file_name });
    defer allocator.free(rotated_path);
    std.Io.Dir.cwd().deleteFile(io, rotated_path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
    try std.Io.Dir.renameAbsolute(events_path, rotated_path, io);
}

/// Best-effort GUI feed write. Feed persistence must not affect hook/run fail-closed behavior.
/// Hook/evaluate callers skip `file.sync` and do not rewrite `workspaces.json` on allow.
pub fn appendRecordBestEffort(io: std.Io, allocator: std.mem.Allocator, workspace_root: []const u8, record: rust_visibility.RustShellFeedRecord) void {
    const opts = AppendOptions{
        .sync = false,
        .update_registry = !isAllowDecision(record.decision),
    };
    appendRecordWithOptions(io, allocator, workspace_root, record, opts) catch {};
    if (processGlobalWritesDisabled()) return;
    const dashboard_root = resolveGlobalDashboardRoot(allocator) catch return;
    defer allocator.free(dashboard_root);
    // Hook path: keep the exclusive lock, skip events.jsonl fsync. Allow
    // decisions skip the workspace registry rewrite.
    appendGlobalRecordWithOptions(io, allocator, dashboard_root, record, opts) catch {};
}

pub fn processGlobalWritesDisabled() bool {
    if (builtin.is_test) return true;
    const value_z = env_util.getenvBrand("DISABLE_GLOBAL_DASHBOARD_FEED") orelse return false;
    const value = std.mem.span(value_z);
    return std.mem.eql(u8, value, "1");
}

pub fn resolveGlobalDashboardRoot(allocator: std.mem.Allocator) ![]u8 {
    const home_z = env_util.getenvHome() orelse return error.HomeDirectoryNotFound;
    return std.fs.path.join(allocator, &.{ std.mem.span(home_z), ".ryk", "dashboard" });
}

fn updateWorkspaceRegistry(
    io: std.Io,
    allocator: std.mem.Allocator,
    dashboard_root: []const u8,
    record: rust_visibility.RustShellFeedRecord,
) !void {
    const registry_path = try std.fs.path.join(allocator, &.{ dashboard_root, workspace_registry_file_name });
    defer allocator.free(registry_path);
    const existing = std.Io.Dir.cwd().readFileAlloc(io, registry_path, allocator, .limited(512 * 1024)) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    defer if (existing) |text| allocator.free(text);
    var parsed = if (existing) |text| std.json.parseFromSlice(std.json.Value, allocator, text, .{}) catch null else null;
    defer if (parsed) |*value| value.deinit();

    const policy_path = try std.fs.path.join(allocator, &.{ record.workspace_root, ".ryk", "policy.yaml" });
    defer allocator.free(policy_path);
    const policy_present = blk: {
        std.Io.Dir.cwd().access(io, policy_path, .{}) catch break :blk false;
        break :blk true;
    };

    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    try output.writer.writeAll("{\"workspaces\":[");
    try writeWorkspaceRegistration(&output.writer, record.workspace_root, record.timestamp, record.host, policy_present);
    var count: usize = 1;
    if (parsed) |value| {
        if (workspaceArray(value.value)) |items| {
            for (items) |item| {
                if (count >= max_registered_workspaces) break;
                const entry = readWorkspaceRegistration(item) orelse continue;
                if (std.mem.eql(u8, entry.root, record.workspace_root)) continue;
                try output.writer.writeByte(',');
                try writeWorkspaceRegistration(&output.writer, entry.root, entry.last_seen_at, entry.last_host, entry.policy_present);
                count += 1;
            }
        }
    }
    try output.writer.writeAll("]}\n");
    const bytes = try output.toOwnedSlice();
    defer allocator.free(bytes);

    const temp_path = try std.fs.path.join(allocator, &.{ dashboard_root, "workspaces.json.tmp" });
    defer allocator.free(temp_path);
    {
        const file = try std.Io.Dir.cwd().createFile(io, temp_path, .{});
        defer file.close(io);
        try file.writeStreamingAll(io, bytes);
        try file.sync(io);
    }
    try std.Io.Dir.renameAbsolute(temp_path, registry_path, io);
}

const WorkspaceRegistrationView = struct {
    root: []const u8,
    last_seen_at: []const u8,
    last_host: ?[]const u8,
    policy_present: bool,
};

fn workspaceArray(value: std.json.Value) ?[]std.json.Value {
    if (value != .object) return null;
    const workspaces = value.object.get("workspaces") orelse return null;
    if (workspaces != .array) return null;
    return workspaces.array.items;
}

fn readWorkspaceRegistration(value: std.json.Value) ?WorkspaceRegistrationView {
    if (value != .object) return null;
    const root = value.object.get("root") orelse return null;
    const last_seen_at = value.object.get("last_seen_at") orelse return null;
    if (root != .string or last_seen_at != .string) return null;
    const last_host_value = value.object.get("last_host");
    const last_host = if (last_host_value) |host| if (host == .string) host.string else null else null;
    const policy_value = value.object.get("policy_present");
    const policy_present = if (policy_value) |present| present == .bool and present.bool else false;
    return .{ .root = root.string, .last_seen_at = last_seen_at.string, .last_host = last_host, .policy_present = policy_present };
}

fn writeWorkspaceRegistration(
    writer: anytype,
    root: []const u8,
    last_seen_at: []const u8,
    last_host: ?[]const u8,
    policy_present: bool,
) !void {
    try writer.writeAll("{\"root\":");
    try core.util.writeJsonString(writer, root);
    try writer.writeAll(",\"last_seen_at\":");
    try core.util.writeJsonString(writer, last_seen_at);
    try writer.writeAll(",\"last_host\":");
    if (last_host) |host| try core.util.writeJsonString(writer, host) else try writer.writeAll("null");
    try writer.writeAll(",\"policy_present\":");
    try writer.writeAll(if (policy_present) "true" else "false");
    try writer.writeByte('}');
}

pub const LoadedFeedRecord = struct {
    raw: []u8,
    record: rust_visibility.RustShellFeedRecord,

    pub fn deinit(self: *LoadedFeedRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.raw);
        self.record.deinit(allocator);
        self.* = undefined;
    }
};

pub const FeedLoadHealth = enum { healthy, degraded };

pub const FeedRecordFilter = enum {
    all,
    blocked,

    fn matches(self: FeedRecordFilter, record: rust_visibility.RustShellFeedRecord) bool {
        return switch (self) {
            .all => true,
            .blocked => rust_visibility.isBlockedFeedRecord(record),
        };
    }
};

pub const FeedLoadResult = struct {
    records: []LoadedFeedRecord,
    health: FeedLoadHealth,
    skipped_lines: usize,

    pub fn deinit(self: *FeedLoadResult, allocator: std.mem.Allocator) void {
        for (self.records) |*item| item.deinit(allocator);
        allocator.free(self.records);
        self.* = undefined;
    }
};

pub fn loadRecent(
    io: std.Io,
    allocator: std.mem.Allocator,
    workspace_root: []const u8,
    max_count: usize,
) ![]LoadedFeedRecord {
    const result = try loadRecentWithHealth(io, allocator, workspace_root, max_count);
    return result.records;
}

pub fn loadRecentWithHealth(
    io: std.Io,
    allocator: std.mem.Allocator,
    workspace_root: []const u8,
    max_count: usize,
) !FeedLoadResult {
    return loadRecentMatchingWithHealth(io, allocator, workspace_root, max_count, .all);
}

pub fn loadRecentMatchingWithHealth(
    io: std.Io,
    allocator: std.mem.Allocator,
    workspace_root: []const u8,
    max_count: usize,
    filter: FeedRecordFilter,
) !FeedLoadResult {
    const feed_path = feedPath(allocator, workspace_root) catch return .{ .records = &.{}, .health = .healthy, .skipped_lines = 0 };
    defer allocator.free(feed_path);

    return loadRecentFromPath(io, allocator, feed_path, workspace_root, max_count, filter);
}

pub fn loadRecentTailWithHealth(
    io: std.Io,
    allocator: std.mem.Allocator,
    workspace_root: []const u8,
) !FeedLoadResult {
    const feed_path = feedPath(allocator, workspace_root) catch return .{ .records = &.{}, .health = .healthy, .skipped_lines = 0 };
    defer allocator.free(feed_path);
    return loadRecentFromPath(io, allocator, feed_path, workspace_root, null, .all);
}

pub fn loadGlobalRecent(
    io: std.Io,
    allocator: std.mem.Allocator,
    dashboard_root: []const u8,
    max_count: usize,
) ![]LoadedFeedRecord {
    const result = try loadGlobalRecentWithHealth(io, allocator, dashboard_root, max_count);
    return result.records;
}

pub fn loadGlobalRecentWithHealth(
    io: std.Io,
    allocator: std.mem.Allocator,
    dashboard_root: []const u8,
    max_count: usize,
) !FeedLoadResult {
    return loadGlobalRecentFilteredWithHealth(io, allocator, dashboard_root, max_count, .all);
}

pub fn loadGlobalRecentMatchingWithHealth(
    io: std.Io,
    allocator: std.mem.Allocator,
    dashboard_root: []const u8,
    max_count: usize,
    filter: FeedRecordFilter,
) !FeedLoadResult {
    return loadGlobalRecentFilteredWithHealth(io, allocator, dashboard_root, max_count, filter);
}

pub fn loadGlobalTailWithHealth(
    io: std.Io,
    allocator: std.mem.Allocator,
    dashboard_root: []const u8,
) !FeedLoadResult {
    return loadGlobalRecentFilteredWithHealth(io, allocator, dashboard_root, null, .all);
}

fn loadGlobalRecentFilteredWithHealth(
    io: std.Io,
    allocator: std.mem.Allocator,
    dashboard_root: []const u8,
    max_count: ?usize,
    filter: FeedRecordFilter,
) !FeedLoadResult {
    const events_path = try std.fs.path.join(allocator, &.{ dashboard_root, global_events_file_name });
    defer allocator.free(events_path);
    var active = try loadRecentFromPath(io, allocator, events_path, null, max_count, filter);
    errdefer active.deinit(allocator);
    if (max_count) |limit| {
        if (limit == 0 or active.records.len >= limit) return active;
    }

    const rotated_path = try std.fs.path.join(allocator, &.{ dashboard_root, rotated_global_events_file_name });
    defer allocator.free(rotated_path);
    const need_from_rotated = if (max_count) |limit| limit - active.records.len else null;
    var rotated = try loadRecentFromPath(io, allocator, rotated_path, null, need_from_rotated, filter);
    errdefer rotated.deinit(allocator);
    if (rotated.records.len == 0) {
        active.skipped_lines += rotated.skipped_lines;
        if (active.skipped_lines > 0) active.health = .degraded;
        var empty = rotated;
        empty.deinit(allocator);
        return active;
    }

    // Chronological merge: older rotated generation, then active generation.
    const combined_len = rotated.records.len + active.records.len;
    const combined = try allocator.alloc(LoadedFeedRecord, combined_len);
    @memcpy(combined[0..rotated.records.len], rotated.records);
    @memcpy(combined[rotated.records.len..], active.records);
    allocator.free(rotated.records);
    allocator.free(active.records);
    return .{
        .records = combined,
        .health = if (rotated.skipped_lines == 0 and active.skipped_lines == 0) .healthy else .degraded,
        .skipped_lines = rotated.skipped_lines + active.skipped_lines,
    };
}

/// Bounded recent-record ring: O(1) eviction of oldest entries when full.
const FeedRecordRing = struct {
    items: []LoadedFeedRecord,
    start: usize = 0,
    len: usize = 0,

    fn init(allocator: std.mem.Allocator, capacity: usize) !FeedRecordRing {
        const items = try allocator.alloc(LoadedFeedRecord, capacity);
        return .{ .items = items };
    }

    fn deinit(self: *FeedRecordRing, allocator: std.mem.Allocator) void {
        if (self.items.len == 0) {
            self.* = undefined;
            return;
        }
        var index: usize = 0;
        while (index < self.len) : (index += 1) {
            self.items[(self.start + index) % self.items.len].deinit(allocator);
        }
        allocator.free(self.items);
        self.* = undefined;
    }

    fn push(self: *FeedRecordRing, allocator: std.mem.Allocator, item: LoadedFeedRecord) void {
        if (self.items.len == 0) {
            var discarded = item;
            discarded.deinit(allocator);
            return;
        }
        if (self.len == self.items.len) {
            self.items[self.start].deinit(allocator);
            self.start = (self.start + 1) % self.items.len;
            self.len -= 1;
        }
        const slot = (self.start + self.len) % self.items.len;
        self.items[slot] = item;
        self.len += 1;
    }

    fn toOwnedSlice(self: *FeedRecordRing, allocator: std.mem.Allocator) ![]LoadedFeedRecord {
        const out = try allocator.alloc(LoadedFeedRecord, self.len);
        var index: usize = 0;
        while (index < self.len) : (index += 1) {
            out[index] = self.items[(self.start + index) % self.items.len];
        }
        // Transfer ownership of records; free the ring buffer only.
        allocator.free(self.items);
        self.* = .{ .items = &.{} };
        return out;
    }
};

fn loadRecentFromPath(
    io: std.Io,
    allocator: std.mem.Allocator,
    path: []const u8,
    fallback_workspace_root: ?[]const u8,
    max_count: ?usize,
    filter: FeedRecordFilter,
) !FeedLoadResult {
    const file = std.Io.Dir.cwd().openFile(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => return .{ .records = &.{}, .health = .healthy, .skipped_lines = 0 },
        else => return err,
    };
    defer file.close(io);
    const size = (try file.stat(io)).size;
    const tail_len: usize = @intCast(@min(size, core.limits.max_dashboard_feed_tail_len));
    const start = size - tail_len;
    const text = try allocator.alloc(u8, tail_len);
    defer allocator.free(text);
    const read_len = try file.readPositionalAll(io, text, start);
    const bounded = text[0..read_len];

    // When starting in the middle of a record, discard that partial line.
    const parse_text = if (start > 0)
        if (std.mem.indexOfScalar(u8, bounded, '\n')) |newline| bounded[newline + 1 ..] else ""
    else
        bounded;

    var lines = std.mem.splitScalar(u8, parse_text, '\n');
    var skipped_lines: usize = if (start > 0) 1 else 0;

    if (max_count) |limit| {
        var ring = try FeedRecordRing.init(allocator, limit);
        errdefer ring.deinit(allocator);
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            const loaded = loadOwnedFeedLine(allocator, line, fallback_workspace_root) catch |err| {
                if (err == error.OutOfMemory) return err;
                skipped_lines += 1;
                continue;
            };
            if (!filter.matches(loaded.record)) {
                var discarded = loaded;
                discarded.deinit(allocator);
                continue;
            }
            ring.push(allocator, loaded);
        }
        return .{
            .records = try ring.toOwnedSlice(allocator),
            .health = if (skipped_lines == 0) .healthy else .degraded,
            .skipped_lines = skipped_lines,
        };
    }

    var stack: std.ArrayList(LoadedFeedRecord) = .empty;
    errdefer {
        for (stack.items) |*item| item.deinit(allocator);
        stack.deinit(allocator);
    }
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const loaded = loadOwnedFeedLine(allocator, line, fallback_workspace_root) catch |err| {
            if (err == error.OutOfMemory) return err;
            skipped_lines += 1;
            continue;
        };
        if (!filter.matches(loaded.record)) {
            var discarded = loaded;
            discarded.deinit(allocator);
            continue;
        }
        stack.append(allocator, loaded) catch |err| {
            var leaked = loaded;
            leaked.deinit(allocator);
            return err;
        };
    }

    return .{
        .records = try stack.toOwnedSlice(allocator),
        .health = if (skipped_lines == 0) .healthy else .degraded,
        .skipped_lines = skipped_lines,
    };
}

fn redactOwnedAlloc(allocator: std.mem.Allocator, owned: []u8) ![]u8 {
    defer allocator.free(owned);
    return core_api.redactAlloc(allocator, owned);
}

fn redactOwnedAllocOptional(allocator: std.mem.Allocator, owned: ?[]u8) !?[]u8 {
    return if (owned) |value| try redactOwnedAlloc(allocator, value) else null;
}

fn loadOwnedFeedLine(
    allocator: std.mem.Allocator,
    line: []const u8,
    fallback_workspace_root: ?[]const u8,
) !LoadedFeedRecord {
    var record = try parseFeedRecord(allocator, line, fallback_workspace_root);
    errdefer record.deinit(allocator);
    // Rebuild `.raw` from already-redacted fields. Whole-line `redactAlloc`
    // can collapse high-entropy JSONL to `[REDACTED]` and break parsers.
    var raw_line: std.Io.Writer.Allocating = .init(allocator);
    defer raw_line.deinit();
    rust_visibility.writeFeedRecordJson(&raw_line.writer, record) catch |err| switch (err) {
        // AllocatingWriter intentionally erases allocator failures to WriteFailed.
        error.WriteFailed => return error.OutOfMemory,
    };
    return .{ .raw = try raw_line.toOwnedSlice(), .record = record };
}

const FeedRecordJson = struct {
    timestamp: []const u8,
    workspace_root: ?[]const u8 = null,
    event_type: []const u8,
    decision: []const u8,
    decision_source: []const u8,
    event_source: []const u8,
    host: ?[]const u8 = null,
    daemon_status: []const u8,
    pack_id: ?[]const u8 = null,
    rule: ?[]const u8 = null,
    severity: ?[]const u8 = null,
    reason: []const u8,
    remediation: ?[]const u8 = null,
    target_summary: []const u8,
    session_id: ?[]const u8 = null,
    verified: bool = false,
};

fn parseFeedRecord(allocator: std.mem.Allocator, line: []const u8, fallback_workspace_root: ?[]const u8) !rust_visibility.RustShellFeedRecord {
    // Typed parse avoids a json.Value object map + per-field lookups (#402).
    const parsed = std.json.parseFromSlice(FeedRecordJson, allocator, line, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidFeedRecord,
    };
    defer parsed.deinit();
    const v = parsed.value;

    const timestamp = try allocator.dupe(u8, v.timestamp);
    errdefer allocator.free(timestamp);
    const workspace_root = try dupWorkspaceRoot(allocator, v.workspace_root, fallback_workspace_root);
    errdefer allocator.free(workspace_root);
    validateFeedWorkspaceRoot(workspace_root) catch return error.InvalidFeedRecord;
    const event_type = try allocator.dupe(u8, v.event_type);
    errdefer allocator.free(event_type);
    const decision = try allocator.dupe(u8, v.decision);
    errdefer allocator.free(decision);
    const decision_source = try allocator.dupe(u8, v.decision_source);
    errdefer allocator.free(decision_source);
    const event_source = try allocator.dupe(u8, v.event_source);
    errdefer allocator.free(event_source);
    const host = try redactOwnedAllocOptional(allocator, try dupeOptional(allocator, v.host));
    errdefer if (host) |value| allocator.free(value);
    const daemon_status = try allocator.dupe(u8, v.daemon_status);
    errdefer allocator.free(daemon_status);
    const pack_id = try redactOwnedAllocOptional(allocator, try dupeOptional(allocator, v.pack_id));
    errdefer if (pack_id) |value| allocator.free(value);
    const rule = try redactOwnedAllocOptional(allocator, try dupeOptional(allocator, v.rule));
    errdefer if (rule) |value| allocator.free(value);
    const severity = try redactOwnedAllocOptional(allocator, try dupeOptional(allocator, v.severity));
    errdefer if (severity) |value| allocator.free(value);
    const reason = try redactOwnedAlloc(allocator, try allocator.dupe(u8, v.reason));
    errdefer allocator.free(reason);
    const remediation = try redactOwnedAllocOptional(allocator, try dupeOptional(allocator, v.remediation));
    errdefer if (remediation) |value| allocator.free(value);
    const target_summary = try redactOwnedAlloc(allocator, try allocator.dupe(u8, v.target_summary));
    errdefer allocator.free(target_summary);
    var session_id = try dupeOptional(allocator, v.session_id);
    errdefer if (session_id) |value| allocator.free(value);
    if (session_id) |value| {
        // Reject path segments before aggregate joins session_id into a filesystem
        // path (directory-existence oracle via ../). Same alphabet as audit writers.
        core.session.validateSessionIdText(value) catch return error.InvalidFeedRecord;
        const safe = redact_bridge.pathSafeSessionId(value);
        if (safe.ptr != value.ptr) {
            const placeholder = try allocator.dupe(u8, safe);
            allocator.free(value);
            session_id = placeholder;
        }
    }
    return .{
        .timestamp = timestamp,
        .workspace_root = workspace_root,
        .event_type = event_type,
        .decision = decision,
        .decision_source = decision_source,
        .event_source = event_source,
        .host = host,
        .daemon_status = daemon_status,
        .pack_id = pack_id,
        .rule = rule,
        .severity = severity,
        .reason = reason,
        .remediation = remediation,
        .target_summary = target_summary,
        .session_id = session_id,
        .verified = v.verified,
    };
}

fn dupeOptional(allocator: std.mem.Allocator, value: ?[]const u8) !?[]u8 {
    const text = value orelse return null;
    return try allocator.dupe(u8, text);
}

fn dupWorkspaceRoot(allocator: std.mem.Allocator, from_record: ?[]const u8, fallback: ?[]const u8) ![]u8 {
    if (from_record) |root| return allocator.dupe(u8, root);
    if (fallback) |root| return allocator.dupe(u8, root);
    return error.InvalidFeedRecord;
}

/// Skip-before-join: reject `..` / `.` segments and extra separators so a
/// crafted feed `workspace_root` cannot be opened as a directory oracle.
/// This is a loader skip, not a fail-closed policy deny.
fn validateFeedWorkspaceRoot(value: []const u8) !void {
    if (value.len == 0) return error.InvalidFeedRecord;
    if (std.mem.indexOfScalar(u8, value, 0) != null) return error.InvalidFeedRecord;
    var it = std.mem.splitAny(u8, value, "/\\");
    var idx: usize = 0;
    while (it.next()) |part| : (idx += 1) {
        if (part.len == 0) {
            if (idx == 0) continue;
            return error.InvalidFeedRecord;
        }
        if (std.mem.eql(u8, part, "..") or std.mem.eql(u8, part, ".")) return error.InvalidFeedRecord;
    }
}

test "feed writer round-trips rust shell decision without raw command" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var record = try rust_visibility.buildFeedRecordFromHookDecision(
        std.testing.allocator,
        std.testing.io,
        root,
        "claude",
        "healthy",
        "deny",
        "blocked by ryk policy rule: destructive_rm",
        "destructive_rm",
        "Critical",
        "Use a safer workflow.",
        "git",
        null,
    );
    defer record.deinit(std.testing.allocator);

    try appendRecord(std.testing.io, std.testing.allocator, root, record);

    const loaded = try loadRecent(std.testing.io, std.testing.allocator, root, 8);
    defer {
        for (loaded) |*item| item.deinit(std.testing.allocator);
        std.testing.allocator.free(loaded);
    }
    try std.testing.expectEqual(@as(usize, 1), loaded.len);
    // Shell decisions are recorded as zig-native after the shell_engine cutover.
    try std.testing.expectEqualStrings("zig-native", loaded[0].record.decision_source);
    try std.testing.expectEqualStrings("hook", loaded[0].record.event_source);
    try std.testing.expectEqualStrings(root, loaded[0].record.workspace_root);
    try std.testing.expectEqualStrings("claude", loaded[0].record.host.?);
    try std.testing.expectEqualStrings("git", loaded[0].record.pack_id.?);
    try std.testing.expectEqualStrings("destructive_rm", loaded[0].record.rule.?);
    try std.testing.expectEqualStrings("shell command (redacted)", loaded[0].record.target_summary);
    try std.testing.expect(std.mem.indexOf(u8, loaded[0].raw, "matched_text_preview") == null);
}

test "feed record ring retains newest entries with O(1) eviction" {
    var ring = try FeedRecordRing.init(std.testing.allocator, 2);
    defer ring.deinit(std.testing.allocator);

    const make = struct {
        fn record(allocator: std.mem.Allocator, id: []const u8) !LoadedFeedRecord {
            const raw = try allocator.dupe(u8, id);
            errdefer allocator.free(raw);
            return .{
                .raw = raw,
                .record = .{
                    .timestamp = try allocator.dupe(u8, "2026-07-13T00:00:00Z"),
                    .workspace_root = try allocator.dupe(u8, "/tmp"),
                    .event_type = try allocator.dupe(u8, "command_denied"),
                    .decision = try allocator.dupe(u8, "deny"),
                    .decision_source = try allocator.dupe(u8, "rust-daemon"),
                    .event_source = try allocator.dupe(u8, "hook"),
                    .host = null,
                    .daemon_status = try allocator.dupe(u8, "healthy"),
                    .pack_id = null,
                    .rule = null,
                    .severity = null,
                    .reason = try allocator.dupe(u8, id),
                    .remediation = null,
                    .target_summary = try allocator.dupe(u8, "shell command (redacted)"),
                    .session_id = null,
                    .verified = false,
                },
            };
        }
    }.record;

    ring.push(std.testing.allocator, try make(std.testing.allocator, "a"));
    ring.push(std.testing.allocator, try make(std.testing.allocator, "b"));
    ring.push(std.testing.allocator, try make(std.testing.allocator, "c"));
    try std.testing.expectEqual(@as(usize, 2), ring.len);
    try std.testing.expectEqualStrings("b", ring.items[ring.start].record.reason);
    const next = (ring.start + 1) % ring.items.len;
    try std.testing.expectEqualStrings("c", ring.items[next].record.reason);

    const owned = try ring.toOwnedSlice(std.testing.allocator);
    defer {
        for (owned) |*item| item.deinit(std.testing.allocator);
        std.testing.allocator.free(owned);
    }
    try std.testing.expectEqual(@as(usize, 2), owned.len);
    try std.testing.expectEqualStrings("b", owned[0].record.reason);
    try std.testing.expectEqualStrings("c", owned[1].record.reason);
}

test "feed loader redacts historical JSONL user-controlled fields" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    const path = try feedPath(std.testing.allocator, root);
    defer std.testing.allocator.free(path);
    const parent = std.fs.path.dirname(path).?;
    try std.Io.Dir.cwd().createDirPath(std.testing.io, parent);

    const fake_secret = "sk-fakeSyntheticOpenAIKey1234567890";
    const line = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"timestamp\":\"2026-07-13T00:00:00Z\",\"workspace_root\":\"{s}\",\"event_type\":\"command_denied\",\"decision\":\"deny\",\"decision_source\":\"rust-daemon\",\"event_source\":\"hook\",\"host\":\"codex\",\"daemon_status\":\"healthy\",\"pack_id\":\"core.shell\",\"rule\":\"leak-{s}\",\"severity\":\"high\",\"reason\":\"blocked token {s}\",\"remediation\":\"rotate {s}\",\"target_summary\":\"cmd {s}\",\"session_id\":null,\"verified\":false}}\n",
        .{ root, fake_secret, fake_secret, fake_secret, fake_secret },
    );
    defer std.testing.allocator.free(line);
    try std.Io.Dir.cwd().writeFile(std.testing.io, .{ .sub_path = path, .data = line });

    const loaded = try loadRecent(std.testing.io, std.testing.allocator, root, 4);
    defer {
        for (loaded) |*item| item.deinit(std.testing.allocator);
        std.testing.allocator.free(loaded);
    }

    try std.testing.expectEqual(@as(usize, 1), loaded.len);
    try std.testing.expect(std.mem.indexOf(u8, loaded[0].raw, fake_secret) == null);
    try std.testing.expect(std.mem.indexOf(u8, loaded[0].record.reason, fake_secret) == null);
    try std.testing.expect(std.mem.indexOf(u8, loaded[0].record.target_summary, fake_secret) == null);
    try std.testing.expect(std.mem.indexOf(u8, loaded[0].record.rule.?, fake_secret) == null);
    try std.testing.expect(std.mem.indexOf(u8, loaded[0].record.remediation.?, fake_secret) == null);
}

test "feed loader session_id keep and redact through loadRecent" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    const path = try feedPath(std.testing.allocator, root);
    defer std.testing.allocator.free(path);
    const parent = std.fs.path.dirname(path).?;
    try std.Io.Dir.cwd().createDirPath(std.testing.io, parent);

    const keep = "rollout-2026-07-30T21-25-08-019fb445-e7a9-7612-bf1a-8fe20ff9e69b";
    const leak = "sess_ghp_fakeSyntheticTokenValue1234567890";
    const jsonl = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"timestamp\":\"2026-07-13T00:00:00Z\",\"workspace_root\":\"{s}\",\"event_type\":\"command_denied\",\"decision\":\"deny\",\"decision_source\":\"rust-daemon\",\"event_source\":\"hook\",\"host\":\"codex\",\"daemon_status\":\"healthy\",\"pack_id\":\"core.shell\",\"severity\":\"high\",\"reason\":\"blocked\",\"remediation\":null,\"target_summary\":\"shell command (redacted)\",\"session_id\":\"{s}\",\"verified\":false}}\n" ++
            "{{\"timestamp\":\"2026-07-13T00:00:01Z\",\"workspace_root\":\"{s}\",\"event_type\":\"command_denied\",\"decision\":\"deny\",\"decision_source\":\"rust-daemon\",\"event_source\":\"hook\",\"host\":\"codex\",\"daemon_status\":\"healthy\",\"pack_id\":\"core.shell\",\"severity\":\"high\",\"reason\":\"blocked\",\"remediation\":null,\"target_summary\":\"shell command (redacted)\",\"session_id\":\"{s}\",\"verified\":false}}\n",
        .{ root, keep, root, leak },
    );
    defer std.testing.allocator.free(jsonl);
    try std.Io.Dir.cwd().writeFile(std.testing.io, .{ .sub_path = path, .data = jsonl });

    const loaded = try loadRecent(std.testing.io, std.testing.allocator, root, 4);
    defer {
        for (loaded) |*item| item.deinit(std.testing.allocator);
        std.testing.allocator.free(loaded);
    }
    try std.testing.expectEqual(@as(usize, 2), loaded.len);
    try std.testing.expectEqualStrings(keep, loaded[0].record.session_id.?);
    try std.testing.expect(std.mem.indexOf(u8, loaded[0].raw, keep) != null);
    try std.testing.expectEqualStrings(redact_bridge.path_safe_session_id, loaded[1].record.session_id.?);
    try std.testing.expect(std.mem.indexOf(u8, loaded[1].raw, leak) == null);
}

test "feed parse redacts host pack_id and severity secret-shaped fields" {
    const line =
        \\{"timestamp":"2026-07-13T00:00:00Z","workspace_root":"/tmp/legacy","event_type":"command_denied","decision":"deny","decision_source":"rust-daemon","event_source":"hook","host":"ghp_fakeSyntheticTokenValue1234567890","daemon_status":"healthy","pack_id":"sk-fakeSyntheticOpenAIKey1234567890","severity":"ghp_fakeSyntheticTokenValue1234567890","reason":"blocked","remediation":null,"target_summary":"shell command (redacted)","session_id":null,"verified":false}
    ;
    var record = try parseFeedRecord(std.testing.allocator, line, null);
    defer record.deinit(std.testing.allocator);
    try std.testing.expect(std.mem.indexOf(u8, record.host.?, "ghp_") == null);
    try std.testing.expect(std.mem.indexOf(u8, record.pack_id.?, "sk-") == null);
    try std.testing.expect(std.mem.indexOf(u8, record.severity.?, "ghp_") == null);
}

test "feed writer persists structured session_id as path-safe placeholder" {
    const record = rust_visibility.RustShellFeedRecord{
        .timestamp = "2026-07-13T00:00:00Z",
        .workspace_root = "/tmp/legacy",
        .event_type = "command_denied",
        .decision = "deny",
        .decision_source = "rust-daemon",
        .event_source = "hook",
        .host = "codex",
        .daemon_status = "healthy",
        .pack_id = "core.shell",
        .rule = null,
        .severity = "high",
        .reason = "blocked",
        .remediation = null,
        .target_summary = "shell command (redacted)",
        .session_id = "ghp_fakeSyntheticTokenValue1234567890",
        .verified = false,
    };
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try rust_visibility.writeFeedRecordJson(&out.writer, record);
    const encoded = out.written();
    try std.testing.expect(std.mem.indexOf(u8, encoded, "\"session_id\":\"redacted\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, encoded, "ghp_") == null);
}

test "feed loader reconstructs parseable JSON raw for high-entropy fields" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    const path = try feedPath(std.testing.allocator, root);
    defer std.testing.allocator.free(path);
    const parent = std.fs.path.dirname(path).?;
    try std.Io.Dir.cwd().createDirPath(std.testing.io, parent);

    const high_entropy = "dG9rZW49Y29ycmVjdC1ob3JzZS1iYXR0ZXJ5LXN0YXBsZQ==";
    const line = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"timestamp\":\"2026-07-13T00:00:00Z\",\"workspace_root\":\"{s}\",\"event_type\":\"command_denied\",\"decision\":\"deny\",\"decision_source\":\"rust-daemon\",\"event_source\":\"hook\",\"host\":\"codex\",\"daemon_status\":\"healthy\",\"pack_id\":\"core.shell\",\"severity\":\"high\",\"reason\":\"{s}\",\"remediation\":null,\"target_summary\":\"shell command (redacted)\",\"session_id\":null,\"verified\":false}}\n",
        .{ root, high_entropy },
    );
    defer std.testing.allocator.free(line);
    try std.Io.Dir.cwd().writeFile(std.testing.io, .{ .sub_path = path, .data = line });

    const loaded = try loadRecent(std.testing.io, std.testing.allocator, root, 4);
    defer {
        for (loaded) |*item| item.deinit(std.testing.allocator);
        std.testing.allocator.free(loaded);
    }

    try std.testing.expectEqual(@as(usize, 1), loaded.len);
    try std.testing.expect(loaded[0].raw.len > 0);
    try std.testing.expectEqual(@as(u8, '{'), loaded[0].raw[0]);
    try std.testing.expect(std.mem.indexOf(u8, loaded[0].raw, high_entropy) == null);
}

test "feed loadOwnedFeedLine remaps allocating-writer OOM" {
    const line =
        \\{"timestamp":"2026-07-13T00:00:00Z","workspace_root":"/tmp/legacy","event_type":"command_denied","decision":"deny","decision_source":"rust-daemon","event_source":"hook","host":"codex","daemon_status":"healthy","pack_id":"core.shell","severity":"high","reason":"blocked","remediation":null,"target_summary":"shell command (redacted)","session_id":null,"verified":false}
    ;
    try std.testing.checkAllAllocationFailures(std.testing.allocator, loadOwnedFeedLineAllocationFailureProbe, .{line});
}

fn loadOwnedFeedLineAllocationFailureProbe(allocator: std.mem.Allocator, line: []const u8) !void {
    var loaded = try loadOwnedFeedLine(allocator, line, null);
    defer loaded.deinit(allocator);
}

test "feed typed parse ignores unknown fields" {
    const line =
        \\{"timestamp":"2026-07-13T00:00:00Z","workspace_root":"/tmp/legacy","event_type":"command_denied","decision":"deny","decision_source":"rust-daemon","event_source":"hook","host":"codex","daemon_status":"healthy","pack_id":"core.shell","severity":"high","reason":"blocked","remediation":null,"target_summary":"shell command (redacted)","session_id":null,"verified":false,"extra_future_field":{"n":1}}
    ;
    var record = try parseFeedRecord(std.testing.allocator, line, null);
    defer record.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("deny", record.decision);
    try std.testing.expect(record.rule == null);
}

test "feed loader accepts legacy records without rule" {
    const line =
        \\{"timestamp":"2026-07-13T00:00:00Z","workspace_root":"/tmp/legacy","event_type":"command_denied","decision":"deny","decision_source":"rust-daemon","event_source":"hook","host":"codex","daemon_status":"healthy","pack_id":"core.shell","severity":"high","reason":"blocked","remediation":null,"target_summary":"shell command (redacted)","session_id":null,"verified":false}
    ;
    var record = try parseFeedRecord(std.testing.allocator, line, null);
    defer record.deinit(std.testing.allocator);

    try std.testing.expect(record.rule == null);
}

test "feed parse rejects path-traversal workspace_root" {
    const line =
        \\{"timestamp":"2026-07-13T00:00:00Z","workspace_root":"/tmp/../outside","event_type":"command_denied","decision":"deny","decision_source":"rust-daemon","event_source":"hook","host":"codex","daemon_status":"healthy","pack_id":"core.shell","severity":"high","reason":"blocked","remediation":null,"target_summary":"shell command (redacted)","session_id":"valid-session","verified":false}
    ;
    try std.testing.expectError(error.InvalidFeedRecord, parseFeedRecord(std.testing.allocator, line, null));
}

test "feed parse rejects path-traversal session_id" {
    const line =
        \\{"timestamp":"2026-07-13T00:00:00Z","workspace_root":"/tmp/legacy","event_type":"command_denied","decision":"deny","decision_source":"rust-daemon","event_source":"hook","host":"codex","daemon_status":"healthy","pack_id":"core.shell","severity":"high","reason":"blocked","remediation":null,"target_summary":"shell command (redacted)","session_id":"../outside","verified":false}
    ;
    try std.testing.expectError(error.InvalidFeedRecord, parseFeedRecord(std.testing.allocator, line, null));
}

test "feed loader skips crafted path-traversal session_id line" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var record = try rust_visibility.buildFeedRecordFromHookDecision(
        std.testing.allocator,
        std.testing.io,
        root,
        "codex",
        "healthy",
        "deny",
        "blocked",
        null,
        null,
        null,
        null,
        "valid-session",
    );
    defer record.deinit(std.testing.allocator);
    try appendRecord(std.testing.io, std.testing.allocator, root, record);

    const path = try feedPath(std.testing.allocator, root);
    defer std.testing.allocator.free(path);
    const file = try std.Io.Dir.cwd().createFile(std.testing.io, path, .{ .read = true, .truncate = false });
    defer file.close(std.testing.io);
    var buffer: [256]u8 = undefined;
    var writer = file.writer(std.testing.io, &buffer);
    try writer.seekToUnbuffered((try file.stat(std.testing.io)).size);
    try writer.interface.writeAll(
        \\{"timestamp":"2026-07-13T00:00:00Z","workspace_root":"/tmp/oracle","event_type":"command_denied","decision":"deny","decision_source":"rust-daemon","event_source":"hook","host":"codex","daemon_status":"healthy","pack_id":"core.shell","severity":"high","reason":"blocked","remediation":null,"target_summary":"shell command (redacted)","session_id":"../outside","verified":false}
        \\
    );
    try writer.interface.flush();

    var loaded = try loadRecentWithHealth(std.testing.io, std.testing.allocator, root, 8);
    defer loaded.deinit(std.testing.allocator);
    try std.testing.expectEqual(FeedLoadHealth.degraded, loaded.health);
    try std.testing.expectEqual(@as(usize, 1), loaded.skipped_lines);
    try std.testing.expectEqual(@as(usize, 1), loaded.records.len);
    try std.testing.expectEqualStrings("valid-session", loaded.records[0].record.session_id.?);
}

test "feed loader skips malformed records and reports degraded health" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var record = try rust_visibility.buildFeedRecordFromHookDecision(
        std.testing.allocator,
        std.testing.io,
        root,
        "codex",
        "healthy",
        "deny",
        "blocked",
        null,
        null,
        null,
        null,
        "session-1",
    );
    defer record.deinit(std.testing.allocator);
    try appendRecord(std.testing.io, std.testing.allocator, root, record);

    const path = try feedPath(std.testing.allocator, root);
    defer std.testing.allocator.free(path);
    const file = try std.Io.Dir.cwd().createFile(std.testing.io, path, .{ .read = true, .truncate = false });
    defer file.close(std.testing.io);
    var buffer: [64]u8 = undefined;
    var writer = file.writer(std.testing.io, &buffer);
    try writer.seekToUnbuffered((try file.stat(std.testing.io)).size);
    try writer.interface.writeAll("{malformed}\n{\"truncated\":");
    try writer.interface.flush();

    var loaded = try loadRecentWithHealth(std.testing.io, std.testing.allocator, root, 8);
    defer loaded.deinit(std.testing.allocator);
    try std.testing.expectEqual(FeedLoadHealth.degraded, loaded.health);
    try std.testing.expectEqual(@as(usize, 2), loaded.skipped_lines);
    try std.testing.expectEqual(@as(usize, 1), loaded.records.len);
}

test "global feed matching loader retains only bounded blocked records" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const dashboard_root = try std.fs.path.join(std.testing.allocator, &.{ root, "dashboard" });
    defer std.testing.allocator.free(dashboard_root);

    for (0..6) |index| {
        const decision = if (index % 2 == 0) "deny" else "allow";
        var record = try rust_visibility.buildFeedRecordFromHookDecision(
            std.testing.allocator,
            std.testing.io,
            root,
            "codex",
            "healthy",
            decision,
            if (index % 2 == 0) "blocked" else "allowed",
            null,
            null,
            null,
            null,
            null,
        );
        defer record.deinit(std.testing.allocator);
        try appendGlobalRecord(std.testing.io, std.testing.allocator, dashboard_root, record);
    }

    var loaded = try loadGlobalRecentMatchingWithHealth(
        std.testing.io,
        std.testing.allocator,
        dashboard_root,
        2,
        .blocked,
    );
    defer loaded.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), loaded.records.len);
    for (loaded.records) |item| try std.testing.expect(rust_visibility.isBlockedFeedRecord(item.record));
}

test "global feed append without fsync is still readable" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const dashboard_root = try std.fs.path.join(std.testing.allocator, &.{ root, "dashboard" });
    defer std.testing.allocator.free(dashboard_root);

    var record = try rust_visibility.buildFeedRecordFromHookDecision(
        std.testing.allocator,
        std.testing.io,
        root,
        "codex",
        "healthy",
        "deny",
        "blocked",
        null,
        null,
        null,
        null,
        null,
    );
    defer record.deinit(std.testing.allocator);
    try appendGlobalRecordWithSync(std.testing.io, std.testing.allocator, dashboard_root, record, false);

    var loaded = try loadGlobalRecentMatchingWithHealth(
        std.testing.io,
        std.testing.allocator,
        dashboard_root,
        1,
        .blocked,
    );
    defer loaded.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), loaded.records.len);
}

test "feed loader accepts histories larger than 64 MiB by reading a bounded tail" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const path = try feedPath(std.testing.allocator, root);
    defer std.testing.allocator.free(path);
    const parent = std.fs.path.dirname(path).?;
    try std.Io.Dir.cwd().createDirPath(std.testing.io, parent);

    const file = try std.Io.Dir.cwd().createFile(std.testing.io, path, .{ .read = true });
    defer file.close(std.testing.io);
    var buffer: [4096]u8 = undefined;
    var writer = file.writer(std.testing.io, &buffer);
    try writer.seekToUnbuffered(65 * 1024 * 1024);
    try writer.interface.writeByte('\n');
    var record = try rust_visibility.buildFeedRecordFromHookDecision(
        std.testing.allocator,
        std.testing.io,
        root,
        "codex",
        "healthy",
        "deny",
        "blocked",
        null,
        null,
        null,
        null,
        "tail-session",
    );
    defer record.deinit(std.testing.allocator);
    try rust_visibility.writeFeedRecordJson(&writer.interface, record);
    try writer.interface.writeByte('\n');
    try writer.interface.flush();

    var loaded = try loadRecentWithHealth(std.testing.io, std.testing.allocator, root, 1);
    defer loaded.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), loaded.records.len);
    try std.testing.expectEqualStrings("tail-session", loaded.records[0].record.session_id.?);
    try std.testing.expectEqual(FeedLoadHealth.degraded, loaded.health);
}

test "global feed rotates one generation and keeps the newest record active" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const dashboard_root = try std.fs.path.join(std.testing.allocator, &.{ root, "dashboard" });
    defer std.testing.allocator.free(dashboard_root);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, dashboard_root);
    const events_path = try std.fs.path.join(std.testing.allocator, &.{ dashboard_root, global_events_file_name });
    defer std.testing.allocator.free(events_path);
    const oversized = try std.Io.Dir.cwd().createFile(std.testing.io, events_path, .{ .read = true });
    {
        defer oversized.close(std.testing.io);
        var buffer: [8]u8 = undefined;
        var writer = oversized.writer(std.testing.io, &buffer);
        try writer.seekToUnbuffered(core.limits.max_dashboard_feed_len);
        try writer.interface.writeByte('\n');
        try writer.interface.flush();
    }

    var record = try rust_visibility.buildFeedRecordFromHookDecision(
        std.testing.allocator,
        std.testing.io,
        root,
        "codex",
        "healthy",
        "deny",
        "blocked",
        null,
        null,
        null,
        null,
        "newest",
    );
    defer record.deinit(std.testing.allocator);
    try appendGlobalRecord(std.testing.io, std.testing.allocator, dashboard_root, record);

    const rotated_path = try std.fs.path.join(std.testing.allocator, &.{ dashboard_root, rotated_global_events_file_name });
    defer std.testing.allocator.free(rotated_path);
    try std.Io.Dir.cwd().access(std.testing.io, rotated_path, .{});
    const loaded = try loadGlobalRecent(std.testing.io, std.testing.allocator, dashboard_root, 4);
    defer {
        for (loaded) |*item| item.deinit(std.testing.allocator);
        std.testing.allocator.free(loaded);
    }
    try std.testing.expectEqual(@as(usize, 1), loaded.len);
    try std.testing.expectEqualStrings("newest", loaded[0].record.session_id.?);
}

test "global feed load merges rotated generation history" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const dashboard_root = try std.fs.path.join(std.testing.allocator, &.{ root, "dashboard" });
    defer std.testing.allocator.free(dashboard_root);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, dashboard_root);

    var older = try rust_visibility.buildFeedRecordFromHookDecision(
        std.testing.allocator,
        std.testing.io,
        root,
        "codex",
        "healthy",
        "deny",
        "older-blocked",
        null,
        null,
        null,
        null,
        "older-session",
    );
    defer older.deinit(std.testing.allocator);
    try appendGlobalRecord(std.testing.io, std.testing.allocator, dashboard_root, older);

    // Simulate a completed rotation: active generation becomes the rotated file.
    const events_path = try std.fs.path.join(std.testing.allocator, &.{ dashboard_root, global_events_file_name });
    defer std.testing.allocator.free(events_path);
    const rotated_path = try std.fs.path.join(std.testing.allocator, &.{ dashboard_root, rotated_global_events_file_name });
    defer std.testing.allocator.free(rotated_path);
    try std.Io.Dir.renameAbsolute(events_path, rotated_path, std.testing.io);

    var newer = try rust_visibility.buildFeedRecordFromHookDecision(
        std.testing.allocator,
        std.testing.io,
        root,
        "codex",
        "healthy",
        "deny",
        "newer-blocked",
        null,
        null,
        null,
        null,
        "newer-session",
    );
    defer newer.deinit(std.testing.allocator);
    try appendGlobalRecord(std.testing.io, std.testing.allocator, dashboard_root, newer);

    const loaded = try loadGlobalRecent(std.testing.io, std.testing.allocator, dashboard_root, 4);
    defer {
        for (loaded) |*item| item.deinit(std.testing.allocator);
        std.testing.allocator.free(loaded);
    }
    try std.testing.expectEqual(@as(usize, 2), loaded.len);
    try std.testing.expectEqualStrings("older-session", loaded[0].record.session_id.?);
    try std.testing.expectEqualStrings("newer-session", loaded[1].record.session_id.?);
}

test "global tail health includes malformed rotated generation" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const dashboard_root = try std.fs.path.join(std.testing.allocator, &.{ root, "dashboard" });
    defer std.testing.allocator.free(dashboard_root);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, dashboard_root);
    const rotated_path = try std.fs.path.join(std.testing.allocator, &.{ dashboard_root, rotated_global_events_file_name });
    defer std.testing.allocator.free(rotated_path);
    try std.Io.Dir.cwd().writeFile(std.testing.io, .{ .sub_path = rotated_path, .data = "{malformed}\n" });

    var record = try rust_visibility.buildFeedRecordFromHookDecision(
        std.testing.allocator,
        std.testing.io,
        root,
        "codex",
        "healthy",
        "allow",
        "active",
        null,
        null,
        null,
        null,
        "active-session",
    );
    defer record.deinit(std.testing.allocator);
    try appendGlobalRecord(std.testing.io, std.testing.allocator, dashboard_root, record);

    var loaded = try loadGlobalTailWithHealth(std.testing.io, std.testing.allocator, dashboard_root);
    defer loaded.deinit(std.testing.allocator);
    try std.testing.expectEqual(FeedLoadHealth.degraded, loaded.health);
    try std.testing.expectEqual(@as(usize, 1), loaded.skipped_lines);
    try std.testing.expectEqual(@as(usize, 1), loaded.records.len);
}

test "global feed append records workspace and updates registry" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const dashboard_root = try std.fs.path.join(std.testing.allocator, &.{ root, "home", ".ryk", "dashboard" });
    defer std.testing.allocator.free(dashboard_root);

    var record = try rust_visibility.buildFeedRecordFromHookDecision(
        std.testing.allocator,
        std.testing.io,
        root,
        "codex",
        "healthy",
        "deny",
        "blocked by ryk policy",
        null,
        null,
        null,
        null,
        "request-1",
    );
    defer record.deinit(std.testing.allocator);

    try appendGlobalRecord(std.testing.io, std.testing.allocator, dashboard_root, record);
    try appendGlobalRecord(std.testing.io, std.testing.allocator, dashboard_root, record);

    const events_path = try std.fs.path.join(std.testing.allocator, &.{ dashboard_root, global_events_file_name });
    defer std.testing.allocator.free(events_path);
    const events = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, events_path, std.testing.allocator, .limited(64 * 1024));
    defer std.testing.allocator.free(events);
    try std.testing.expect(std.mem.indexOf(u8, events, "\"workspace_root\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, events, root) != null);
    try std.testing.expect(std.mem.indexOf(u8, events, "\"host\":\"codex\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, events, "agent_host") == null);
    const loaded = try loadGlobalRecent(std.testing.io, std.testing.allocator, dashboard_root, 4);
    defer {
        for (loaded) |*item| item.deinit(std.testing.allocator);
        std.testing.allocator.free(loaded);
    }
    try std.testing.expectEqual(@as(usize, 2), loaded.len);

    const registry_path = try std.fs.path.join(std.testing.allocator, &.{ dashboard_root, workspace_registry_file_name });
    defer std.testing.allocator.free(registry_path);
    const registry = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, registry_path, std.testing.allocator, .limited(64 * 1024));
    defer std.testing.allocator.free(registry);
    try std.testing.expect(std.mem.indexOf(u8, registry, root) != null);
    try std.testing.expect(std.mem.indexOf(u8, registry, "\"last_host\":\"codex\"") != null);
}

test "hook-originated feed append skips file.sync" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var record = try rust_visibility.buildFeedRecordFromHookDecision(
        std.testing.allocator,
        std.testing.io,
        root,
        "grok",
        "healthy",
        "allow",
        "allowed",
        null,
        null,
        null,
        null,
        "req-hook-sync",
    );
    defer record.deinit(std.testing.allocator);

    test_sync_calls = 0;
    appendRecordBestEffort(std.testing.io, std.testing.allocator, root, record);
    try std.testing.expectEqual(@as(usize, 0), test_sync_calls);

    test_sync_calls = 0;
    try appendRecord(std.testing.io, std.testing.allocator, root, record);
    try std.testing.expect(test_sync_calls > 0);
}

test "hook allow does not rewrite workspace registry" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const dashboard_root = try std.fs.path.join(std.testing.allocator, &.{ root, "home", ".ryk", "dashboard" });
    defer std.testing.allocator.free(dashboard_root);

    var record = try rust_visibility.buildFeedRecordFromHookDecision(
        std.testing.allocator,
        std.testing.io,
        root,
        "grok",
        "healthy",
        "allow",
        "allowed",
        null,
        null,
        null,
        null,
        "req-hook-allow",
    );
    defer record.deinit(std.testing.allocator);

    try appendGlobalRecordWithOptions(std.testing.io, std.testing.allocator, dashboard_root, record, .{
        .sync = false,
        .update_registry = false,
    });

    const registry_path = try std.fs.path.join(std.testing.allocator, &.{ dashboard_root, workspace_registry_file_name });
    defer std.testing.allocator.free(registry_path);
    std.Io.Dir.cwd().access(std.testing.io, registry_path, .{}) catch |err| {
        try std.testing.expectEqual(error.FileNotFound, err);
        return;
    };
    return error.TestUnexpectedResult;
}

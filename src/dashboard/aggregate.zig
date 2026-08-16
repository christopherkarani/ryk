const std = @import("std");

const core_api = @import("ryk_core").api;
const core = @import("ryk_core").core;
const presentation = @import("../presentation/mod.zig");
const feed_writer = @import("../cli/feed_writer.zig");
const rust_visibility = @import("../cli/feed_visibility.zig");

pub const SessionLoadHealth = enum { healthy, degraded };

pub const Workspace = struct {
    root: []u8,
    last_seen_at: []u8,
    last_host: ?[]u8,
    policy_present: bool,

    pub fn deinit(self: *Workspace, allocator: std.mem.Allocator) void {
        allocator.free(self.root);
        allocator.free(self.last_seen_at);
        if (self.last_host) |host| allocator.free(host);
        self.* = undefined;
    }
};

pub fn loadWorkspaces(io: std.Io, allocator: std.mem.Allocator, dashboard_root: []const u8) ![]Workspace {
    const registry_path = try std.fs.path.join(allocator, &.{ dashboard_root, feed_writer.workspace_registry_file_name });
    defer allocator.free(registry_path);
    const text = std.Io.Dir.cwd().readFileAlloc(io, registry_path, allocator, .limited(512 * 1024)) catch |err| switch (err) {
        error.FileNotFound => return &[_]Workspace{},
        else => return err,
    };
    defer allocator.free(text);
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, text, .{}) catch return &[_]Workspace{};
    defer parsed.deinit();
    if (parsed.value != .object) return &[_]Workspace{};
    const workspaces_value = parsed.value.object.get("workspaces") orelse return &[_]Workspace{};
    if (workspaces_value != .array) return &[_]Workspace{};

    var workspaces: std.ArrayList(Workspace) = .empty;
    errdefer {
        for (workspaces.items) |*workspace| workspace.deinit(allocator);
        workspaces.deinit(allocator);
    }
    for (workspaces_value.array.items) |item| {
        if (workspaces.items.len >= feed_writer.max_registered_workspaces) break;
        if (item != .object) continue;
        const root = stringField(item.object, "root") orelse continue;
        const last_seen_at = stringField(item.object, "last_seen_at") orelse continue;
        const last_host = stringField(item.object, "last_host");
        const policy_present = boolField(item.object, "policy_present");
        var workspace = try dupeWorkspace(allocator, root, last_seen_at, last_host, policy_present);
        workspaces.append(allocator, workspace) catch |err| {
            workspace.deinit(allocator);
            return err;
        };
    }
    return workspaces.toOwnedSlice(allocator);
}

fn dupeWorkspace(
    allocator: std.mem.Allocator,
    root: []const u8,
    last_seen_at: []const u8,
    last_host: ?[]const u8,
    policy_present: bool,
) !Workspace {
    const owned_root = try allocator.dupe(u8, root);
    errdefer allocator.free(owned_root);
    const owned_last_seen_at = try allocator.dupe(u8, last_seen_at);
    errdefer allocator.free(owned_last_seen_at);
    const owned_last_host = if (last_host) |host| try allocator.dupe(u8, host) else null;
    errdefer if (owned_last_host) |host| allocator.free(host);
    return .{
        .root = owned_root,
        .last_seen_at = owned_last_seen_at,
        .last_host = owned_last_host,
        .policy_present = policy_present,
    };
}

pub fn deinitWorkspaces(allocator: std.mem.Allocator, workspaces: []Workspace) void {
    for (workspaces) |*workspace| workspace.deinit(allocator);
    allocator.free(workspaces);
}

pub fn writeWorkspacesJson(writer: anytype, workspaces: []const Workspace) !void {
    try writer.writeByte('[');
    for (workspaces, 0..) |workspace, index| {
        if (index > 0) try writer.writeByte(',');
        try writer.writeAll("{\"root\":");
        try core.util.writeJsonString(writer, workspace.root);
        try writer.writeAll(",\"last_seen_at\":");
        try core.util.writeJsonString(writer, workspace.last_seen_at);
        try writer.writeAll(",\"last_host\":");
        if (workspace.last_host) |host| try core.util.writeJsonString(writer, host) else try writer.writeAll("null");
        try writer.writeAll(",\"policy_present\":");
        try writer.writeAll(if (workspace.policy_present) "true" else "false");
        try writer.writeByte('}');
    }
    try writer.writeByte(']');
}

const SessionRef = struct {
    workspace_root: []const u8,
    id: []u8,
    timestamp: []u8,
    host: ?[]u8 = null,
    latest_decision: ?[]u8 = null,
    denied_count: usize = 0,
    feed_only: bool = false,

    fn deinit(self: *SessionRef, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.timestamp);
        if (self.host) |host| allocator.free(host);
        if (self.latest_decision) |decision| allocator.free(decision);
        self.* = undefined;
    }
};

pub fn writeSessionsJson(
    io: std.Io,
    allocator: std.mem.Allocator,
    writer: anytype,
    dashboard_root: []const u8,
    workspaces: []const Workspace,
    max_count: usize,
) !SessionLoadHealth {
    var loaded = feed_writer.loadGlobalTailWithHealth(io, allocator, dashboard_root) catch {
        return writeSessionsFromFeed(io, allocator, writer, workspaces, &.{}, max_count);
    };
    defer loaded.deinit(allocator);
    return writeSessionsFromFeed(io, allocator, writer, workspaces, loaded.records, max_count);
}

pub fn writeWorkspaceSessionsJson(
    io: std.Io,
    allocator: std.mem.Allocator,
    writer: anytype,
    workspace_root: []const u8,
    max_count: usize,
) !SessionLoadHealth {
    var workspace = try dupeWorkspace(allocator, workspace_root, "", null, false);
    defer workspace.deinit(allocator);
    var loaded = feed_writer.loadRecentTailWithHealth(io, allocator, workspace_root) catch {
        return writeSessionsFromFeed(io, allocator, writer, &.{workspace}, &.{}, max_count);
    };
    defer loaded.deinit(allocator);
    return writeSessionsFromFeed(io, allocator, writer, &.{workspace}, loaded.records, max_count);
}

fn writeSessionsFromFeed(
    io: std.Io,
    allocator: std.mem.Allocator,
    writer: anytype,
    workspaces: []const Workspace,
    feed: []const feed_writer.LoadedFeedRecord,
    max_count: usize,
) !SessionLoadHealth {
    var loaded = try loadBoundedSessions(io, allocator, workspaces, feed, max_count);
    defer loaded.deinit(allocator);
    std.mem.sort(SessionRef, loaded.sessions.items, {}, newestSessionFirst);

    try writer.writeByte('[');
    for (loaded.sessions.items, 0..) |session, index| {
        if (index > 0) try writer.writeByte(',');
        if (session.feed_only)
            try writeFeedSessionSummaryJson(writer, session)
        else
            try writeSessionSummaryJson(io, allocator, writer, session);
    }
    try writer.writeByte(']');
    return loaded.health;
}

const BoundedSessionLoad = struct {
    sessions: std.ArrayList(SessionRef) = .empty,
    health: SessionLoadHealth = .healthy,

    fn deinit(self: *BoundedSessionLoad, allocator: std.mem.Allocator) void {
        for (self.sessions.items) |*session| session.deinit(allocator);
        self.sessions.deinit(allocator);
        self.* = undefined;
    }
};

fn loadBoundedSessions(
    io: std.Io,
    allocator: std.mem.Allocator,
    workspaces: []const Workspace,
    feed: []const feed_writer.LoadedFeedRecord,
    max_count: usize,
) !BoundedSessionLoad {
    var loaded: BoundedSessionLoad = .{};
    errdefer loaded.deinit(allocator);
    if (max_count == 0) return loaded;

    var health: SessionLoadHealth = .healthy;
    var index_by_session: SessionLookupMap = .init(allocator);
    defer index_by_session.deinit();
    try index_by_session.ensureTotalCapacity(retainCapacity(max_count));
    var oldest_index: usize = 0;
    for (workspaces) |workspace| {
        const sessions_root = try std.fs.path.join(allocator, &.{ workspace.root, ".ryk", "sessions" });
        defer allocator.free(sessions_root);
        var dir = std.Io.Dir.cwd().openDir(io, sessions_root, .{ .iterate = true }) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => {
                health = .degraded;
                continue;
            },
        };
        defer dir.close(io);
        var iterator = dir.iterate();
        while (true) {
            const entry = iterator.next(io) catch {
                health = .degraded;
                break;
            } orelse break;
            if (entry.kind != .directory) continue;
            if (core.session.validateSessionIdText(entry.name)) |_| {} else |_| continue;
            if (index_by_session.contains(sessionLookupKey(workspace.root, entry.name))) continue;
            var session = try dupeSessionRef(allocator, workspace.root, entry.name, entry.name, null, null, 0, false);
            try retainNewestSession(allocator, &loaded.sessions, &session, max_count, &oldest_index, &index_by_session);
        }
    }
    for (feed) |item| {
        const session_id = item.record.session_id orelse continue;
        if (core.session.validateSessionIdText(session_id)) |_| {} else |_| continue;
        const key = sessionLookupKey(item.record.workspace_root, session_id);
        if (index_by_session.get(key)) |index| {
            const session = &loaded.sessions.items[index];
            if (std.mem.order(u8, item.record.timestamp, session.timestamp) == .gt) {
                const timestamp = try allocator.dupe(u8, item.record.timestamp);
                allocator.free(session.timestamp);
                session.timestamp = timestamp;
                if (index == oldest_index) oldest_index = findOldestSessionIndex(loaded.sessions.items);
            }
            continue;
        }
        const filesystem_backed = try sessionDirectoryExists(io, allocator, item.record.workspace_root, session_id);
        const timestamp = if (filesystem_backed and std.mem.order(u8, session_id, item.record.timestamp) == .gt)
            session_id
        else
            item.record.timestamp;
        var session = try dupeSessionRef(
            allocator,
            item.record.workspace_root,
            session_id,
            timestamp,
            null,
            null,
            0,
            !filesystem_backed,
        );
        try retainNewestSession(allocator, &loaded.sessions, &session, max_count, &oldest_index, &index_by_session);
    }
    try enrichRetainedSessionsFromFeed(allocator, loaded.sessions.items, feed);
    loaded.health = health;
    return loaded;
}

const SessionLookupKey = struct {
    workspace_root: []const u8,
    session_id: []const u8,

    fn eql(a: SessionLookupKey, b: SessionLookupKey) bool {
        return std.mem.eql(u8, a.workspace_root, b.workspace_root) and std.mem.eql(u8, a.session_id, b.session_id);
    }

    fn hash(self: SessionLookupKey) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(self.workspace_root);
        hasher.update(&.{0});
        hasher.update(self.session_id);
        return hasher.final();
    }
};

const SessionLookupContext = struct {
    pub fn hash(_: SessionLookupContext, key: SessionLookupKey) u64 {
        return key.hash();
    }
    pub fn eql(_: SessionLookupContext, a: SessionLookupKey, b: SessionLookupKey) bool {
        return SessionLookupKey.eql(a, b);
    }
};

const SessionLookupMap = std.HashMap(SessionLookupKey, usize, SessionLookupContext, std.hash_map.default_max_load_percentage);

fn sessionLookupKey(workspace_root: []const u8, session_id: []const u8) SessionLookupKey {
    return .{ .workspace_root = workspace_root, .session_id = session_id };
}

fn retainCapacity(max_count: usize) SessionLookupMap.Size {
    return @intCast(max_count);
}

fn rememberSessionIndex(map: *SessionLookupMap, session: SessionRef, index: usize) void {
    const gop = map.getOrPutAssumeCapacity(sessionLookupKey(session.workspace_root, session.id));
    if (!gop.found_existing) gop.value_ptr.* = index;
}

/// Selection stays bounded to the requested top-K. Once that set is known, rebuild
/// its feed metadata from the complete bounded feed tail so eviction and re-entry
/// cannot discard earlier decisions for a retained session.
///
/// Single-pass over the feed via session index map (O(F+K)), preserving:
/// - last-timestamp-wins host + latest_decision (first-seen on equal timestamps)
/// - denied_count over ALL matching blocked records for the retained session
/// Duplicate (workspace, session) rows keep the first index so wipe+index cannot
/// leave an earlier card at denied_count=0.
fn enrichRetainedSessionsFromFeed(
    allocator: std.mem.Allocator,
    sessions: []SessionRef,
    feed: []const feed_writer.LoadedFeedRecord,
) !void {
    for (sessions) |*session| {
        if (session.host) |value| allocator.free(value);
        if (session.latest_decision) |value| allocator.free(value);
        session.host = null;
        session.latest_decision = null;
        session.denied_count = 0;
    }
    if (sessions.len == 0 or feed.len == 0) return;

    var index_by_session: SessionLookupMap = .init(allocator);
    defer index_by_session.deinit();
    try index_by_session.ensureTotalCapacity(retainCapacity(sessions.len));
    for (sessions, 0..) |session, index| {
        rememberSessionIndex(&index_by_session, session, index);
    }

    var winning_feed_index = try allocator.alloc(?usize, sessions.len);
    defer allocator.free(winning_feed_index);
    @memset(winning_feed_index, null);

    for (feed, 0..) |item, feed_index| {
        const session_id = item.record.session_id orelse continue;
        const index = index_by_session.get(sessionLookupKey(item.record.workspace_root, session_id)) orelse continue;
        if (rust_visibility.isBlockedFeedRecord(item.record)) sessions[index].denied_count += 1;
        if (winning_feed_index[index]) |current| {
            if (std.mem.order(u8, item.record.timestamp, feed[current].record.timestamp) != .gt) continue;
        }
        winning_feed_index[index] = feed_index;
    }

    for (sessions, 0..) |*session, index| {
        const feed_index = winning_feed_index[index] orelse continue;
        const record = feed[feed_index].record;
        const host = if (record.host) |value| try allocator.dupe(u8, value) else null;
        errdefer if (host) |value| allocator.free(value);
        const decision = try allocator.dupe(u8, record.decision);
        errdefer allocator.free(decision);
        session.host = host;
        session.latest_decision = decision;
    }
}

fn findOldestSessionIndex(sessions: []const SessionRef) usize {
    std.debug.assert(sessions.len > 0);
    var oldest_index: usize = 0;
    for (sessions[1..], 1..) |session, index| {
        if (std.mem.order(u8, session.timestamp, sessions[oldest_index].timestamp) == .lt) oldest_index = index;
    }
    return oldest_index;
}

/// Keep up to max_count newest sessions by timestamp string order.
/// At capacity, compare against a cached oldest index (rejects are O(1));
/// only a successful replacement rescans K.
fn retainNewestSession(
    allocator: std.mem.Allocator,
    sessions: *std.ArrayList(SessionRef),
    candidate: *SessionRef,
    max_count: usize,
    oldest_index: *usize,
    index_by_session: ?*SessionLookupMap,
) !void {
    if (max_count == 0) {
        candidate.deinit(allocator);
        return;
    }
    if (sessions.items.len < max_count) {
        sessions.append(allocator, candidate.*) catch |err| {
            candidate.deinit(allocator);
            return err;
        };
        candidate.* = undefined;
        const new_index = sessions.items.len - 1;
        if (new_index == 0 or std.mem.order(u8, sessions.items[new_index].timestamp, sessions.items[oldest_index.*].timestamp) == .lt) {
            oldest_index.* = new_index;
        }
        if (index_by_session) |map| rememberSessionIndex(map, sessions.items[new_index], new_index);
        return;
    }

    const oldest = oldest_index.*;
    if (std.mem.order(u8, candidate.timestamp, sessions.items[oldest].timestamp) != .gt) {
        candidate.deinit(allocator);
        return;
    }
    if (index_by_session) |map| {
        const evicted = sessions.items[oldest];
        _ = map.remove(sessionLookupKey(evicted.workspace_root, evicted.id));
    }
    sessions.items[oldest].deinit(allocator);
    sessions.items[oldest] = candidate.*;
    candidate.* = undefined;
    if (index_by_session) |map| rememberSessionIndex(map, sessions.items[oldest], oldest);
    oldest_index.* = findOldestSessionIndex(sessions.items);
}

fn sessionDirectoryExists(io: std.Io, allocator: std.mem.Allocator, workspace_root: []const u8, session_id: []const u8) !bool {
    core.session.validateSessionIdText(session_id) catch return false;
    if (std.mem.indexOf(u8, workspace_root, "..") != null) return false;
    if (std.mem.indexOf(u8, workspace_root, "//") != null) return false;
    const path = try std.fs.path.join(allocator, &.{ workspace_root, ".ryk", "sessions", session_id });
    defer allocator.free(path);
    var dir = std.Io.Dir.cwd().openDir(io, path, .{}) catch return false;
    dir.close(io);
    return true;
}

fn dupeSessionRef(
    allocator: std.mem.Allocator,
    workspace_root: []const u8,
    id: []const u8,
    timestamp: []const u8,
    host: ?[]const u8,
    latest_decision: ?[]const u8,
    denied_count: usize,
    feed_only: bool,
) !SessionRef {
    const owned_id = try allocator.dupe(u8, id);
    errdefer allocator.free(owned_id);
    const owned_timestamp = try allocator.dupe(u8, timestamp);
    errdefer allocator.free(owned_timestamp);
    const owned_host = if (host) |value| try allocator.dupe(u8, value) else null;
    errdefer if (owned_host) |value| allocator.free(value);
    const owned_decision = if (latest_decision) |value| try allocator.dupe(u8, value) else null;
    errdefer if (owned_decision) |value| allocator.free(value);
    return .{
        .workspace_root = workspace_root,
        .id = owned_id,
        .timestamp = owned_timestamp,
        .host = owned_host,
        .latest_decision = owned_decision,
        .denied_count = denied_count,
        .feed_only = feed_only,
    };
}

fn findSession(sessions: []const SessionRef, workspace_root: []const u8, session_id: []const u8) ?usize {
    for (sessions, 0..) |session, index| {
        if (std.mem.eql(u8, session.workspace_root, workspace_root) and std.mem.eql(u8, session.id, session_id)) return index;
    }
    return null;
}

fn writeFeedSessionSummaryJson(writer: anytype, session: SessionRef) !void {
    try writer.writeAll("{\"id\":");
    try core.util.writeJsonString(writer, session.id);
    try writer.writeAll(",\"timestamp\":");
    try core.util.writeJsonString(writer, session.timestamp);
    try writer.writeAll(",\"workspace_root\":");
    try core.util.writeJsonString(writer, session.workspace_root);
    try writer.writeAll(",\"host\":");
    if (session.host) |host| try core.util.writeJsonString(writer, host) else try writer.writeAll("null");
    try writer.writeAll(",\"command\":null,\"policy\":null,\"status\":");
    if (session.latest_decision) |decision| try core.util.writeJsonString(writer, decision) else try writer.writeAll("null");
    try writer.print(",\"denied_count\":{d},\"verified\":false}}", .{session.denied_count});
}

pub fn writeGlobalFeedJson(
    io: std.Io,
    allocator: std.mem.Allocator,
    writer: anytype,
    dashboard_root: []const u8,
    max_count: usize,
    denied_only: bool,
) !void {
    var loaded_result = if (denied_only)
        feed_writer.loadGlobalRecentMatchingWithHealth(io, allocator, dashboard_root, max_count, .blocked) catch {
            try writer.writeAll("[]");
            return;
        }
    else
        feed_writer.loadGlobalRecentWithHealth(io, allocator, dashboard_root, max_count) catch {
            try writer.writeAll("[]");
            return;
        };
    defer loaded_result.deinit(allocator);
    const loaded = loaded_result.records;
    if (loaded.len == 0) {
        try writer.writeAll("[]");
        return;
    }
    std.mem.sort(feed_writer.LoadedFeedRecord, loaded, {}, newestFeedFirst);
    try writer.writeByte('[');
    var written: usize = 0;
    for (loaded) |item| {
        if (written >= max_count) break;
        if (denied_only and !rust_visibility.isBlockedFeedRecord(item.record)) continue;
        if (written > 0) try writer.writeByte(',');
        try writeFeedRecordJson(allocator, writer, item.record);
        written += 1;
    }
    try writer.writeByte(']');
}

pub fn writeGlobalFeedHealthJson(
    io: std.Io,
    allocator: std.mem.Allocator,
    writer: anytype,
    dashboard_root: []const u8,
) !void {
    var loaded = feed_writer.loadGlobalTailWithHealth(io, allocator, dashboard_root) catch {
        try writer.writeAll("{\"status\":\"degraded\",\"skipped_lines\":0}");
        return;
    };
    defer loaded.deinit(allocator);
    try writer.writeAll("{\"status\":");
    try core.util.writeJsonString(writer, @tagName(loaded.health));
    try writer.print(",\"skipped_lines\":{d}}}", .{loaded.skipped_lines});
}

fn writeSessionSummaryJson(
    io: std.Io,
    allocator: std.mem.Allocator,
    writer: anytype,
    session: SessionRef,
) !void {
    try writer.writeAll("{\"id\":");
    try core.util.writeJsonString(writer, session.id);
    try writer.writeAll(",\"timestamp\":");
    try core.util.writeJsonString(writer, session.timestamp);
    try writer.writeAll(",\"workspace_root\":");
    try core.util.writeJsonString(writer, session.workspace_root);
    try writer.writeAll(",\"host\":");
    if (session.host) |host| try core.util.writeJsonString(writer, host) else try writer.writeAll("null");
    if (core_api.loadReplay(io, allocator, session.workspace_root, .{ .session = session.id, .only_denied = true, .verify = false })) |loaded| {
        var replay = loaded;
        defer replay.deinit();
        try writer.writeAll(",\"command\":");
        try core.util.writeJsonString(writer, replay.command_display);
        try writer.writeAll(",\"policy\":");
        try core.util.writeJsonString(writer, replay.policy);
        try writer.writeAll(",\"status\":");
        if (session.latest_decision) |decision|
            try core.util.writeJsonString(writer, decision)
        else
            try core.util.writeJsonString(writer, replay.status_display);
        try writer.print(",\"denied_count\":{d},\"verified\":{}", .{ @max(replay.events.len, session.denied_count), replay.verified });
    } else |err| {
        if (err == error.OutOfMemory) return err;
        try writer.writeAll(",\"command\":null,\"policy\":null,\"status\":");
        if (session.latest_decision) |decision|
            try core.util.writeJsonString(writer, decision)
        else
            try writer.writeAll("\"unreadable\"");
        try writer.print(",\"denied_count\":{d},\"verified\":false", .{session.denied_count});
    }
    try writer.writeByte('}');
}

fn writeFeedRecordJson(allocator: std.mem.Allocator, writer: anytype, record: rust_visibility.RustShellFeedRecord) !void {
    try writer.writeAll("{\"timestamp\":");
    try core.util.writeJsonString(writer, record.timestamp);
    try writer.writeAll(",\"workspace_root\":");
    try core.util.writeJsonString(writer, record.workspace_root);
    try writer.writeAll(",\"event_type\":");
    try core.util.writeJsonString(writer, record.event_type);
    try writer.writeAll(",\"decision\":");
    try core.util.writeJsonString(writer, record.decision);
    try writer.writeAll(",\"decision_source\":");
    try core.util.writeJsonString(writer, record.decision_source);
    try writer.writeAll(",\"event_source\":");
    try core.util.writeJsonString(writer, record.event_source);
    try writer.writeAll(",\"host\":");
    if (record.host) |host| try core.util.writeJsonString(writer, host) else try writer.writeAll("null");
    try writer.writeAll(",\"daemon_status\":");
    try core.util.writeJsonString(writer, record.daemon_status);
    try writer.writeAll(",\"pack_id\":");
    if (record.pack_id) |pack| try core.util.writeJsonString(writer, pack) else try writer.writeAll("null");
    try writer.writeAll(",\"rule\":");
    if (record.rule) |rule| try core.util.writeJsonString(writer, rule) else try writer.writeAll("null");
    try writer.writeAll(",\"severity\":");
    if (record.severity) |severity| try core.util.writeJsonString(writer, severity) else try writer.writeAll("null");
    try writer.writeAll(",\"reason\":");
    try presentation.redact.writeJsonString(allocator, writer, record.reason);
    try writer.writeAll(",\"remediation\":");
    if (record.remediation) |remediation| try presentation.redact.writeJsonString(allocator, writer, remediation) else try writer.writeAll("null");
    try writer.writeAll(",\"target\":");
    try presentation.redact.writeJsonString(allocator, writer, record.target_summary);
    try writer.writeAll(",\"session_id\":");
    if (record.session_id) |session_id| try core.util.writeJsonString(writer, session_id) else try writer.writeAll("null");
    try writer.writeAll(",\"verified\":");
    try writer.writeAll(if (record.verified) "true" else "false");
    try writer.writeByte('}');
}

fn newestSessionFirst(_: void, lhs: SessionRef, rhs: SessionRef) bool {
    return std.mem.order(u8, lhs.timestamp, rhs.timestamp) == .gt;
}

fn newestFeedFirst(_: void, lhs: feed_writer.LoadedFeedRecord, rhs: feed_writer.LoadedFeedRecord) bool {
    return std.mem.order(u8, lhs.record.timestamp, rhs.record.timestamp) == .gt;
}

fn stringField(object: std.json.ObjectMap, name: []const u8) ?[]const u8 {
    const value = object.get(name) orelse return null;
    if (value != .string) return null;
    return value.string;
}

fn boolField(object: std.json.ObjectMap, name: []const u8) bool {
    const value = object.get(name) orelse return false;
    return value == .bool and value.bool;
}

test "sessions are globally sorted before truncation and filesystem sessions keep feed metadata" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const sessions_root = try std.fs.path.join(std.testing.allocator, &.{ root, ".ryk", "sessions" });
    defer std.testing.allocator.free(sessions_root);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, sessions_root);

    const oldest_id = try core.session.generateSessionId(core.time.Timestamp.fromUnixSeconds(1_700_000_000));
    const middle_id = try core.session.generateSessionId(core.time.Timestamp.fromUnixSeconds(1_700_000_100));
    const newest_id = try core.session.generateSessionId(core.time.Timestamp.fromUnixSeconds(1_700_000_200));
    const oldest = oldest_id.slice();
    const middle = middle_id.slice();
    const newest = newest_id.slice();
    for ([_][]const u8{ oldest, middle, newest }) |id| {
        const path = try std.fs.path.join(std.testing.allocator, &.{ sessions_root, id });
        defer std.testing.allocator.free(path);
        try std.Io.Dir.cwd().createDirPath(std.testing.io, path);
    }

    var record = try rust_visibility.buildFeedRecordFromHookDecision(
        std.testing.allocator,
        std.testing.io,
        root,
        "pi",
        "healthy",
        "deny",
        "blocked",
        null,
        null,
        null,
        null,
        newest,
    );
    defer record.deinit(std.testing.allocator);
    try feed_writer.appendRecord(std.testing.io, std.testing.allocator, root, record);
    const feed = try feed_writer.loadRecent(std.testing.io, std.testing.allocator, root, 8);
    defer {
        for (feed) |*item| item.deinit(std.testing.allocator);
        std.testing.allocator.free(feed);
    }
    var workspace = try dupeWorkspace(std.testing.allocator, root, "", null, false);
    defer workspace.deinit(std.testing.allocator);
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    _ = try writeSessionsFromFeed(std.testing.io, std.testing.allocator, &output.writer, &.{workspace}, feed, 2);
    const json = output.writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, json, oldest) == null);
    try std.testing.expect(std.mem.indexOf(u8, json, newest) != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"host\":\"pi\"") != null);
}

test "large session directories retain only the requested top k and zero is safe" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const sessions_root = try std.fs.path.join(std.testing.allocator, &.{ root, ".ryk", "sessions" });
    defer std.testing.allocator.free(sessions_root);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, sessions_root);

    var newest_id: ?[]u8 = null;
    defer if (newest_id) |id| std.testing.allocator.free(id);
    for (0..256) |index| {
        const id = try core.session.generateSessionId(core.time.Timestamp.fromUnixSeconds(1_700_000_000 + @as(i64, @intCast(index))));
        if (index == 255) newest_id = try std.testing.allocator.dupe(u8, id.slice());
        const path = try std.fs.path.join(std.testing.allocator, &.{ sessions_root, id.slice() });
        defer std.testing.allocator.free(path);
        try std.Io.Dir.cwd().createDirPath(std.testing.io, path);
    }
    var workspace = try dupeWorkspace(std.testing.allocator, root, "", null, false);
    defer workspace.deinit(std.testing.allocator);

    var retained = try loadBoundedSessions(std.testing.io, std.testing.allocator, &.{workspace}, &.{}, 3);
    defer retained.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 3), retained.sessions.items.len);
    try std.testing.expect(findSession(retained.sessions.items, root, newest_id.?) != null);

    var none = try loadBoundedSessions(std.testing.io, std.testing.allocator, &.{workspace}, &.{}, 0);
    defer none.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), none.sessions.items.len);

    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    _ = try writeSessionsFromFeed(std.testing.io, std.testing.allocator, &output.writer, &.{workspace}, &.{}, 3);
    try std.testing.expectEqual(@as(usize, 3), std.mem.count(u8, output.writer.buffered(), "\"id\":"));
}

test "bounded session re-entry preserves earlier denied events" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const dashboard_root = try std.fs.path.join(std.testing.allocator, &.{ root, "dashboard" });
    defer std.testing.allocator.free(dashboard_root);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, dashboard_root);
    const events_path = try std.fs.path.join(std.testing.allocator, &.{ dashboard_root, feed_writer.global_events_file_name });
    defer std.testing.allocator.free(events_path);

    const fixture = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"timestamp\":\"2026-07-13T00:00:00Z\",\"workspace_root\":\"{s}\",\"event_type\":\"command_denied\",\"decision\":\"deny\",\"decision_source\":\"rust-daemon\",\"event_source\":\"hook\",\"host\":\"pi\",\"daemon_status\":\"healthy\",\"pack_id\":null,\"severity\":null,\"reason\":\"blocked\",\"remediation\":null,\"target_summary\":\"shell command (redacted)\",\"session_id\":\"A\",\"verified\":false}}\n" ++
            "{{\"timestamp\":\"2026-07-13T00:01:00Z\",\"workspace_root\":\"{s}\",\"event_type\":\"command_allowed\",\"decision\":\"allow\",\"decision_source\":\"rust-daemon\",\"event_source\":\"hook\",\"host\":\"codex\",\"daemon_status\":\"healthy\",\"pack_id\":null,\"severity\":null,\"reason\":\"allowed\",\"remediation\":null,\"target_summary\":\"shell command (redacted)\",\"session_id\":\"B\",\"verified\":false}}\n" ++
            "{{\"timestamp\":\"2026-07-13T00:02:00Z\",\"workspace_root\":\"{s}\",\"event_type\":\"command_allowed\",\"decision\":\"allow\",\"decision_source\":\"rust-daemon\",\"event_source\":\"hook\",\"host\":\"claude\",\"daemon_status\":\"healthy\",\"pack_id\":null,\"severity\":null,\"reason\":\"allowed\",\"remediation\":null,\"target_summary\":\"shell command (redacted)\",\"session_id\":\"C\",\"verified\":false}}\n" ++
            "{{\"timestamp\":\"2026-07-13T00:03:00Z\",\"workspace_root\":\"{s}\",\"event_type\":\"command_allowed\",\"decision\":\"allow\",\"decision_source\":\"rust-daemon\",\"event_source\":\"hook\",\"host\":\"opencode\",\"daemon_status\":\"healthy\",\"pack_id\":null,\"severity\":null,\"reason\":\"allowed\",\"remediation\":null,\"target_summary\":\"shell command (redacted)\",\"session_id\":\"A\",\"verified\":false}}\n",
        .{ root, root, root, root },
    );
    defer std.testing.allocator.free(fixture);
    const file = try std.Io.Dir.cwd().createFile(std.testing.io, events_path, .{});
    defer file.close(std.testing.io);
    var file_buffer: [4096]u8 = undefined;
    var file_writer = file.writer(std.testing.io, &file_buffer);
    try file_writer.interface.writeAll(fixture);
    try file_writer.interface.flush();

    var loaded = try feed_writer.loadGlobalTailWithHealth(std.testing.io, std.testing.allocator, dashboard_root);
    defer loaded.deinit(std.testing.allocator);
    var workspace = try dupeWorkspace(std.testing.allocator, root, "", null, false);
    defer workspace.deinit(std.testing.allocator);
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    _ = try writeSessionsFromFeed(std.testing.io, std.testing.allocator, &output.writer, &.{workspace}, loaded.records, 2);
    const json = output.writer.buffered();
    const session_a = std.mem.indexOf(u8, json, "\"id\":\"A\"") orelse return error.TestExpectedEqual;
    const session_a_end = std.mem.indexOfScalarPos(u8, json, session_a, '}') orelse json.len;
    try std.testing.expect(std.mem.indexOf(u8, json[session_a..session_a_end], "\"denied_count\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"id\":\"B\"") == null);
}

test "machine sessions enrich records beyond the former one thousand row cap" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const dashboard_root = try std.fs.path.join(std.testing.allocator, &.{ root, "dashboard" });
    defer std.testing.allocator.free(dashboard_root);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, dashboard_root);

    const target_id = try core.session.generateSessionId(core.time.Timestamp.fromUnixSeconds(1_700_000_000));
    const target = target_id.slice();
    const session_path = try std.fs.path.join(std.testing.allocator, &.{ root, ".ryk", "sessions", target });
    defer std.testing.allocator.free(session_path);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, session_path);

    const events_path = try std.fs.path.join(std.testing.allocator, &.{ dashboard_root, feed_writer.global_events_file_name });
    defer std.testing.allocator.free(events_path);
    const file = try std.Io.Dir.cwd().createFile(std.testing.io, events_path, .{});
    defer file.close(std.testing.io);
    var buffer: [4096]u8 = undefined;
    var file_writer = file.writer(std.testing.io, &buffer);
    var target_record = try rust_visibility.buildFeedRecordFromHookDecision(
        std.testing.allocator,
        std.testing.io,
        root,
        "pi",
        "healthy",
        "deny",
        "target blocked",
        null,
        null,
        null,
        null,
        target,
    );
    defer target_record.deinit(std.testing.allocator);
    try rust_visibility.writeFeedRecordJson(&file_writer.interface, target_record);
    try file_writer.interface.writeByte('\n');
    var noise_record = try rust_visibility.buildFeedRecordFromHookDecision(
        std.testing.allocator,
        std.testing.io,
        root,
        "codex",
        "healthy",
        "allow",
        "noise",
        null,
        null,
        null,
        null,
        "noise-session",
    );
    defer noise_record.deinit(std.testing.allocator);
    for (0..1000) |_| {
        try rust_visibility.writeFeedRecordJson(&file_writer.interface, noise_record);
        try file_writer.interface.writeByte('\n');
    }
    try file_writer.interface.flush();

    var workspace = try dupeWorkspace(std.testing.allocator, root, "", null, false);
    defer workspace.deinit(std.testing.allocator);
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    _ = try writeSessionsJson(std.testing.io, std.testing.allocator, &output.writer, dashboard_root, &.{workspace}, 2);
    try std.testing.expect(std.mem.indexOf(u8, output.writer.buffered(), "\"host\":\"pi\"") != null);
}

test "machine sessions sort across workspaces before truncation" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(base);
    const older_root = try std.fs.path.join(std.testing.allocator, &.{ base, "older" });
    defer std.testing.allocator.free(older_root);
    const newer_root = try std.fs.path.join(std.testing.allocator, &.{ base, "newer" });
    defer std.testing.allocator.free(newer_root);
    const older_id = try core.session.generateSessionId(core.time.Timestamp.fromUnixSeconds(1_700_000_000));
    const newer_id = try core.session.generateSessionId(core.time.Timestamp.fromUnixSeconds(1_700_000_100));
    const older_path = try std.fs.path.join(std.testing.allocator, &.{ older_root, ".ryk", "sessions", older_id.slice() });
    defer std.testing.allocator.free(older_path);
    const newer_path = try std.fs.path.join(std.testing.allocator, &.{ newer_root, ".ryk", "sessions", newer_id.slice() });
    defer std.testing.allocator.free(newer_path);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, older_path);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, newer_path);

    var older = try dupeWorkspace(std.testing.allocator, older_root, "", null, false);
    defer older.deinit(std.testing.allocator);
    var newer = try dupeWorkspace(std.testing.allocator, newer_root, "", null, false);
    defer newer.deinit(std.testing.allocator);
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    _ = try writeSessionsFromFeed(std.testing.io, std.testing.allocator, &output.writer, &.{ older, newer }, &.{}, 1);
    const json = output.writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, json, newer_id.slice()) != null);
    try std.testing.expect(std.mem.indexOf(u8, json, older_id.slice()) == null);
}

test "session directory access failures report degraded aggregation" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const sessions_path = try std.fs.path.join(std.testing.allocator, &.{ root, ".ryk", "sessions" });
    defer std.testing.allocator.free(sessions_path);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, std.fs.path.dirname(sessions_path).?);
    const invalid_dir = try std.Io.Dir.cwd().createFile(std.testing.io, sessions_path, .{});
    invalid_dir.close(std.testing.io);

    var workspace = try dupeWorkspace(std.testing.allocator, root, "", null, false);
    defer workspace.deinit(std.testing.allocator);
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    const health = try writeSessionsFromFeed(std.testing.io, std.testing.allocator, &output.writer, &.{workspace}, &.{}, 1);
    try std.testing.expectEqual(SessionLoadHealth.degraded, health);
    try std.testing.expectEqualStrings("[]", output.writer.buffered());
}

test "denied-only global feed honors max count" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const dashboard_root = try std.fs.path.join(std.testing.allocator, &.{ root, "dashboard" });
    defer std.testing.allocator.free(dashboard_root);
    for (0..4) |index| {
        const session_id = try std.fmt.allocPrint(std.testing.allocator, "session-{d}", .{index});
        defer std.testing.allocator.free(session_id);
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
            session_id,
        );
        defer record.deinit(std.testing.allocator);
        try feed_writer.appendGlobalRecord(std.testing.io, std.testing.allocator, dashboard_root, record);
    }
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try writeGlobalFeedJson(std.testing.io, std.testing.allocator, &output.writer, dashboard_root, 2, true);
    try std.testing.expectEqual(@as(usize, 2), std.mem.count(u8, output.writer.buffered(), "\"timestamp\":"));
}

test "single-pass enrich counts earlier denies and keeps latest host decision" {
    // Feed order is not timestamp order: older denies after a newer allow must still
    // count denied_count while last-timestamp-wins host/decision stays on the allow.
    const root = "/tmp/ryk-agg-enrich-test-ws";
    var sessions: std.ArrayList(SessionRef) = .empty;
    defer {
        for (sessions.items) |*session| session.deinit(std.testing.allocator);
        sessions.deinit(std.testing.allocator);
    }
    var session = try dupeSessionRef(std.testing.allocator, root, "A", "A", null, null, 0, true);
    try sessions.append(std.testing.allocator, session);
    session = undefined;

    // Borrowed string literals — LoadedFeedRecord.deinit is not called.
    const loaded_feed = [_]feed_writer.LoadedFeedRecord{
        .{
            .raw = "",
            .record = .{
                .timestamp = "2026-07-13T00:03:00Z",
                .workspace_root = root,
                .event_type = "command_allowed",
                .decision = "allow",
                .decision_source = "rust-daemon",
                .event_source = "hook",
                .host = "opencode",
                .daemon_status = "healthy",
                .pack_id = null,
                .rule = null,
                .severity = null,
                .reason = "allowed",
                .remediation = null,
                .target_summary = "shell",
                .session_id = "A",
                .verified = false,
            },
        },
        .{
            .raw = "",
            .record = .{
                .timestamp = "2026-07-13T00:00:00Z",
                .workspace_root = root,
                .event_type = "command_denied",
                .decision = "deny",
                .decision_source = "rust-daemon",
                .event_source = "hook",
                .host = "pi",
                .daemon_status = "healthy",
                .pack_id = null,
                .rule = null,
                .severity = null,
                .reason = "blocked",
                .remediation = null,
                .target_summary = "shell",
                .session_id = "A",
                .verified = false,
            },
        },
        .{
            .raw = "",
            .record = .{
                .timestamp = "2026-07-13T00:01:00Z",
                .workspace_root = root,
                .event_type = "command_denied",
                .decision = "deny",
                .decision_source = "rust-daemon",
                .event_source = "hook",
                .host = "codex",
                .daemon_status = "healthy",
                .pack_id = null,
                .rule = null,
                .severity = null,
                .reason = "blocked",
                .remediation = null,
                .target_summary = "shell",
                .session_id = "A",
                .verified = false,
            },
        },
    };

    try enrichRetainedSessionsFromFeed(std.testing.allocator, sessions.items, &loaded_feed);
    try std.testing.expectEqual(@as(usize, 2), sessions.items[0].denied_count);
    try std.testing.expectEqualStrings("opencode", sessions.items[0].host.?);
    try std.testing.expectEqualStrings("allow", sessions.items[0].latest_decision.?);
}

test "retainNewestSession replaces only older timestamps at capacity" {
    var sessions: std.ArrayList(SessionRef) = .empty;
    defer {
        for (sessions.items) |*session| session.deinit(std.testing.allocator);
        sessions.deinit(std.testing.allocator);
    }

    var oldest_index: usize = 0;
    var a = try dupeSessionRef(std.testing.allocator, "/ws", "s-a", "2026-07-13T00:01:00Z", null, null, 0, true);
    try retainNewestSession(std.testing.allocator, &sessions, &a, 2, &oldest_index, null);
    var b = try dupeSessionRef(std.testing.allocator, "/ws", "s-b", "2026-07-13T00:02:00Z", null, null, 0, true);
    try retainNewestSession(std.testing.allocator, &sessions, &b, 2, &oldest_index, null);
    var older = try dupeSessionRef(std.testing.allocator, "/ws", "s-old", "2026-07-13T00:00:00Z", null, null, 0, true);
    try retainNewestSession(std.testing.allocator, &sessions, &older, 2, &oldest_index, null);
    try std.testing.expectEqual(@as(usize, 2), sessions.items.len);
    try std.testing.expect(findSession(sessions.items, "/ws", "s-old") == null);

    var newer = try dupeSessionRef(std.testing.allocator, "/ws", "s-new", "2026-07-13T00:03:00Z", null, null, 0, true);
    try retainNewestSession(std.testing.allocator, &sessions, &newer, 2, &oldest_index, null);
    try std.testing.expectEqual(@as(usize, 2), sessions.items.len);
    try std.testing.expect(findSession(sessions.items, "/ws", "s-new") != null);
    try std.testing.expect(findSession(sessions.items, "/ws", "s-a") == null);
    try std.testing.expect(findSession(sessions.items, "/ws", "s-b") != null);
}

fn testLoadedFeed(
    timestamp: []const u8,
    workspace_root: []const u8,
    decision: []const u8,
    host: ?[]const u8,
    session_id: []const u8,
) feed_writer.LoadedFeedRecord {
    return .{
        .raw = "",
        .record = .{
            .timestamp = timestamp,
            .workspace_root = workspace_root,
            .event_type = if (std.mem.eql(u8, decision, "allow")) "command_allowed" else "command_denied",
            .decision = decision,
            .decision_source = "rust-daemon",
            .event_source = "hook",
            .host = host,
            .daemon_status = "healthy",
            .pack_id = null,
            .rule = null,
            .severity = null,
            .reason = "test",
            .remediation = null,
            .target_summary = "shell",
            .session_id = session_id,
            .verified = false,
        },
    };
}

test "single-pass enrich isolates same session id across workspaces" {
    const ws_a = "/tmp/ryk-agg-ws-a";
    const ws_b = "/tmp/ryk-agg-ws-b";
    var sessions: std.ArrayList(SessionRef) = .empty;
    defer {
        for (sessions.items) |*session| session.deinit(std.testing.allocator);
        sessions.deinit(std.testing.allocator);
    }
    var a = try dupeSessionRef(std.testing.allocator, ws_a, "shared", "shared", null, null, 0, true);
    try sessions.append(std.testing.allocator, a);
    a = undefined;
    var b = try dupeSessionRef(std.testing.allocator, ws_b, "shared", "shared", null, null, 0, true);
    try sessions.append(std.testing.allocator, b);
    b = undefined;

    const loaded_feed = [_]feed_writer.LoadedFeedRecord{
        testLoadedFeed("2026-07-13T00:00:00Z", ws_a, "deny", "pi", "shared"),
        testLoadedFeed("2026-07-13T00:01:00Z", ws_b, "allow", "opencode", "shared"),
        testLoadedFeed("2026-07-13T00:02:00Z", ws_a, "ask", "codex", "shared"),
    };
    try enrichRetainedSessionsFromFeed(std.testing.allocator, sessions.items, &loaded_feed);
    try std.testing.expectEqual(@as(usize, 2), sessions.items[0].denied_count);
    try std.testing.expectEqualStrings("codex", sessions.items[0].host.?);
    try std.testing.expectEqualStrings("ask", sessions.items[0].latest_decision.?);
    try std.testing.expectEqual(@as(usize, 0), sessions.items[1].denied_count);
    try std.testing.expectEqualStrings("opencode", sessions.items[1].host.?);
    try std.testing.expectEqualStrings("allow", sessions.items[1].latest_decision.?);
}

test "single-pass enrich keeps first-seen host on equal timestamps and first duplicate row" {
    const root = "/tmp/ryk-agg-equal-ts";
    var sessions: std.ArrayList(SessionRef) = .empty;
    defer {
        for (sessions.items) |*session| session.deinit(std.testing.allocator);
        sessions.deinit(std.testing.allocator);
    }
    var first = try dupeSessionRef(std.testing.allocator, root, "A", "A", null, null, 0, true);
    try sessions.append(std.testing.allocator, first);
    first = undefined;
    var duplicate = try dupeSessionRef(std.testing.allocator, root, "A", "A", null, null, 0, true);
    try sessions.append(std.testing.allocator, duplicate);
    duplicate = undefined;

    const loaded_feed = [_]feed_writer.LoadedFeedRecord{
        testLoadedFeed("2026-07-13T00:00:00Z", root, "allow", "pi", "A"),
        testLoadedFeed("2026-07-13T00:00:00Z", root, "allow", "opencode", "A"),
        testLoadedFeed("2026-07-13T00:00:00Z", root, "deny", null, "A"),
    };
    try enrichRetainedSessionsFromFeed(std.testing.allocator, sessions.items, &loaded_feed);
    try std.testing.expectEqual(@as(usize, 1), sessions.items[0].denied_count);
    try std.testing.expectEqualStrings("pi", sessions.items[0].host.?);
    try std.testing.expectEqualStrings("allow", sessions.items[0].latest_decision.?);
    try std.testing.expectEqual(@as(usize, 0), sessions.items[1].denied_count);
    try std.testing.expect(sessions.items[1].host == null);
}

test "cached oldest index survives timestamp bump of the previous oldest" {
    var sessions: std.ArrayList(SessionRef) = .empty;
    defer {
        for (sessions.items) |*session| session.deinit(std.testing.allocator);
        sessions.deinit(std.testing.allocator);
    }
    var oldest_index: usize = 0;
    var a = try dupeSessionRef(std.testing.allocator, "/ws", "s-a", "2026-07-13T00:01:00Z", null, null, 0, true);
    try retainNewestSession(std.testing.allocator, &sessions, &a, 2, &oldest_index, null);
    var b = try dupeSessionRef(std.testing.allocator, "/ws", "s-b", "2026-07-13T00:05:00Z", null, null, 0, true);
    try retainNewestSession(std.testing.allocator, &sessions, &b, 2, &oldest_index, null);
    try std.testing.expectEqual(@as(usize, 0), oldest_index);

    const bumped = try std.testing.allocator.dupe(u8, "2026-07-13T00:06:00Z");
    std.testing.allocator.free(sessions.items[oldest_index].timestamp);
    sessions.items[oldest_index].timestamp = bumped;
    oldest_index = findOldestSessionIndex(sessions.items);
    try std.testing.expectEqualStrings("s-b", sessions.items[oldest_index].id);

    var mid = try dupeSessionRef(std.testing.allocator, "/ws", "s-mid", "2026-07-13T00:05:30Z", null, null, 0, true);
    try retainNewestSession(std.testing.allocator, &sessions, &mid, 2, &oldest_index, null);
    try std.testing.expectEqual(@as(usize, 2), sessions.items.len);
    try std.testing.expect(findSession(sessions.items, "/ws", "s-a") != null);
    try std.testing.expect(findSession(sessions.items, "/ws", "s-mid") != null);
    try std.testing.expect(findSession(sessions.items, "/ws", "s-b") == null);
}

test "duplicate workspace roots do not emit two filesystem session cards" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const session_id = try core.session.generateSessionId(core.time.Timestamp.fromUnixSeconds(1_700_000_000));
    const session_path = try std.fs.path.join(std.testing.allocator, &.{ root, ".ryk", "sessions", session_id.slice() });
    defer std.testing.allocator.free(session_path);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, session_path);

    var first = try dupeWorkspace(std.testing.allocator, root, "", null, false);
    defer first.deinit(std.testing.allocator);
    var second = try dupeWorkspace(std.testing.allocator, root, "", null, false);
    defer second.deinit(std.testing.allocator);
    var loaded = try loadBoundedSessions(std.testing.io, std.testing.allocator, &.{ first, second }, &.{}, 4);
    defer loaded.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), loaded.sessions.items.len);
}

test "global feed redacts legacy free-form fields and exposes rule ids" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const dashboard_root = try std.fs.path.join(std.testing.allocator, &.{ root, "dashboard" });
    defer std.testing.allocator.free(dashboard_root);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, dashboard_root);
    const events_path = try std.fs.path.join(std.testing.allocator, &.{ dashboard_root, feed_writer.global_events_file_name });
    defer std.testing.allocator.free(events_path);
    const legacy_secret = "sk-legacyGlobalSyntheticSecret123456789";
    const fixture = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"timestamp\":\"2026-07-13T00:00:00Z\",\"workspace_root\":\"{s}\",\"event_type\":\"command_denied\",\"decision\":\"deny\",\"decision_source\":\"rust-daemon\",\"event_source\":\"hook\",\"host\":\"codex\",\"daemon_status\":\"healthy\",\"pack_id\":\"core.shell\",\"severity\":\"high\",\"reason\":\"token={s}\",\"remediation\":\"Authorization: Bearer {s}\",\"target_summary\":\"--token={s}\",\"session_id\":null,\"verified\":false}}\n{{\"timestamp\":\"2026-07-13T00:00:01Z\",\"workspace_root\":\"{s}\",\"event_type\":\"command_denied\",\"decision\":\"deny\",\"decision_source\":\"rust-daemon\",\"event_source\":\"hook\",\"host\":\"codex\",\"daemon_status\":\"healthy\",\"pack_id\":\"core.shell\",\"rule\":\"core.shell:pipe\",\"severity\":\"high\",\"reason\":\"blocked\",\"remediation\":null,\"target_summary\":\"shell command (redacted)\",\"session_id\":null,\"verified\":false}}\n",
        .{ root, legacy_secret, legacy_secret, legacy_secret, root },
    );
    defer std.testing.allocator.free(fixture);
    try std.Io.Dir.cwd().writeFile(std.testing.io, .{ .sub_path = events_path, .data = fixture });

    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try writeGlobalFeedJson(std.testing.io, std.testing.allocator, &output.writer, dashboard_root, 10, true);
    const json = output.writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, json, legacy_secret) == null);
    try std.testing.expect(std.mem.indexOf(u8, json, "[REDACTED]") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"rule\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"rule\":\"core.shell:pipe\"") != null);
}

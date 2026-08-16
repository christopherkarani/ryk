//! Bounded discovery of session files under known host roots only.
const std = @import("std");
const types = @import("types.zig");
const paths = @import("paths.zig");
const time_window = @import("time_window.zig");
const jsonl = @import("jsonl.zig");
const opencode_db = @import("opencode_db.zig");

pub const DiscoveredFile = struct {
    host: types.Host,
    path: []u8,
    session_id: []u8,
    mtime_secs: i64,

    pub fn deinit(self: *DiscoveredFile, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        allocator.free(self.session_id);
        self.* = undefined;
    }
};

pub const HostDiscovery = struct {
    host: types.Host,
    status: types.HostStatus,
    files: std.ArrayList(DiscoveredFile),
    note: []const u8 = "",

    pub fn deinit(self: *HostDiscovery, allocator: std.mem.Allocator) void {
        for (self.files.items) |*f| f.deinit(allocator);
        self.files.deinit(allocator);
        self.* = undefined;
    }
};

pub const DiscoveryOptions = struct {
    home: []const u8,
    xdg_data_home: ?[]const u8 = null,
    workspace_root: ?[]const u8 = null,
    window: time_window.Window,
    /// Optional host filter (null = all).
    only_host: ?types.Host = null,
};

/// Discover session files for all (or one) hosts under known paths only.
pub fn discoverAll(
    io: std.Io,
    allocator: std.mem.Allocator,
    options: DiscoveryOptions,
) ![]HostDiscovery {
    var out: std.ArrayList(HostDiscovery) = .empty;
    errdefer {
        for (out.items) |*h| h.deinit(allocator);
        out.deinit(allocator);
    }

    for (paths.host_path_table) |spec| {
        if (options.only_host) |only| {
            if (only != spec.host) continue;
        }
        var host_disc: HostDiscovery = .{
            .host = spec.host,
            .status = .not_found,
            .files = .empty,
            .note = spec.note,
        };
        errdefer host_disc.deinit(allocator);

        switch (spec.host) {
            .opencode => try discoverOpenCode(io, allocator, options, &host_disc),
            .ryk => try discoverRyk(io, allocator, options, &host_disc),
            .claude => try discoverClaude(io, allocator, options, &host_disc),
            .codex => try discoverCodex(io, allocator, options, &host_disc),
            .pi => try discoverPi(io, allocator, options, &host_disc),
            .grok => try discoverGrok(io, allocator, options, &host_disc),
        }
        try out.append(allocator, host_disc);
    }
    return try out.toOwnedSlice(allocator);
}

pub fn freeDiscoveries(allocator: std.mem.Allocator, items: []HostDiscovery) void {
    for (items) |*h| h.deinit(allocator);
    allocator.free(items);
}

fn discoverOpenCode(io: std.Io, allocator: std.mem.Allocator, options: DiscoveryOptions, host: *HostDiscovery) !void {
    // Known XDG path only — never crawl $HOME. DB is opened read-only by opencode_db.
    const xdg_rel: []const u8 = blk: {
        for (paths.host_path_table) |spec| {
            if (spec.host == .opencode and spec.xdg_data_relative.len > 0) break :blk spec.xdg_data_relative[0];
        }
        break :blk "/opencode";
    };
    const root = try paths.resolveXdgDataRoot(allocator, options.home, options.xdg_data_home, xdg_rel);
    defer allocator.free(root);
    const db_path = try std.fs.path.join(allocator, &.{ root, "opencode.db" });
    defer allocator.free(db_path);

    if (!pathExists(io, db_path)) {
        if (pathExists(io, root)) {
            host.status = .empty;
            host.note = "OpenCode data dir present without opencode.db";
        } else {
            host.status = .not_found;
            host.note = "OpenCode data dir not found";
        }
        return;
    }

    switch (opencode_db.probeDb(io, allocator, db_path)) {
        .no_sqlite => {
            host.status = .unsupported;
            host.note = "sqlite3 CLI not available; OpenCode DB not parsed";
            return;
        },
        .unreadable => {
            host.status = .unreadable;
            host.note = "OpenCode opencode.db present but unreadable (locked or permission denied)";
            return;
        },
        .schema_mismatch => {
            host.status = .unsupported;
            host.note = "OpenCode DB schema mismatch (session/part tables missing)";
            return;
        },
        .ok => {},
    }

    const sessions = opencode_db.listSessions(io, allocator, db_path, options.window, types.max_sessions_per_host) catch {
        host.status = .unreadable;
        host.note = "OpenCode DB query failed (locked or corrupt)";
        return;
    };
    defer opencode_db.freeSessionRefs(allocator, sessions);

    for (sessions) |s| {
        if (host.files.items.len >= types.max_sessions_per_host) break;
        // Own a copy of the db path per session entry (appendFile consumes path).
        const path_owned = try allocator.dupe(u8, db_path);
        try appendFile(allocator, &host.files, .opencode, path_owned, s.id, s.timestamp_secs);
    }

    if (host.files.items.len > 0) {
        host.status = .ok;
        host.note = "OpenCode SQLite sessions (read-only)";
    } else {
        host.status = .empty;
        host.note = "OpenCode DB present; no sessions in time window";
    }
}

fn collectRykSessionRoot(
    io: std.Io,
    allocator: std.mem.Allocator,
    options: DiscoveryOptions,
    host: *HostDiscovery,
    root: []const u8,
    any: *bool,
    unreadable: *bool,
) !void {
    var dir = std.Io.Dir.cwd().openDir(io, root, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return,
        error.AccessDenied => {
            unreadable.* = true;
            return;
        },
        else => {
            unreadable.* = true;
            return;
        },
    };
    defer dir.close(io);
    any.* = true;
    var it = dir.iterate();
    while (true) {
        const entry = it.next(io) catch {
            unreadable.* = true;
            break;
        } orelse break;
        if (entry.kind != .directory) continue;
        if (host.files.items.len >= types.max_sessions_per_host) break;
        const session_path = try std.fs.path.join(allocator, &.{ root, entry.name });
        defer allocator.free(session_path);
        if (!isSafeEntryName(entry.name)) continue;
        const events = try std.fs.path.join(allocator, &.{ session_path, "events.jsonl" });
        if (!isRegularFileNoFollow(io, events)) {
            allocator.free(events);
            continue;
        }
        const mtime = fileMtimeSecsNoFollow(io, events) orelse 0;
        if (!time_window.inWindow(mtime, options.window)) {
            allocator.free(events);
            continue;
        }
        const sid_name = try allocator.dupe(u8, entry.name);
        defer allocator.free(sid_name);
        try appendFile(allocator, &host.files, .ryk, events, sid_name, mtime);
    }
}

fn discoverRyk(io: std.Io, allocator: std.mem.Allocator, options: DiscoveryOptions, host: *HostDiscovery) !void {
    const session_roots = [_][]const u8{ "/.ryk/sessions", "/.ryk/sessions" };
    var any = false;
    var unreadable = false;
    for (session_roots) |rel| {
        const root = try paths.resolveHomeRoot(allocator, options.home, rel);
        defer allocator.free(root);
        try collectRykSessionRoot(io, allocator, options, host, root, &any, &unreadable);
    }
    if (options.workspace_root) |workspace| {
        const ws_root = try std.fs.path.join(allocator, &.{ workspace, ".ryk", "sessions" });
        defer allocator.free(ws_root);
        try collectRykSessionRoot(io, allocator, options, host, ws_root, &any, &unreadable);
    }
    // Also note dashboard registry presence (bridge pointer, not full scan).
    const dash = try paths.resolveHomeRoot(allocator, options.home, "/.ryk/dashboard/workspaces.json");
    defer allocator.free(dash);
    const has_dash = pathExists(io, dash);

    if (host.files.items.len > 0) {
        host.status = .ok;
        host.note = if (has_dash)
            "ryk sessions found; use ryk replay --session <id> for full timeline"
        else
            "ryk sessions found under .ryk/.ryk";
    } else if (unreadable) {
        host.status = .unreadable;
        host.note = "ryk session dirs present but unreadable";
    } else if (any) {
        host.status = .empty;
        host.note = "ryk session root empty or outside time window";
    } else if (has_dash) {
        host.status = .empty;
        host.note = "dashboard registry present; no session dirs in window";
    } else {
        host.status = .not_found;
        host.note = "no .ryk/.ryk session roots";
    }
}

fn discoverClaude(io: std.Io, allocator: std.mem.Allocator, options: DiscoveryOptions, host: *HostDiscovery) !void {
    const root = try paths.resolveHomeRoot(allocator, options.home, "/.claude/projects");
    defer allocator.free(root);
    try collectJsonlBounded(io, allocator, options, host, root, 2, ".jsonl");
}

fn discoverCodex(io: std.Io, allocator: std.mem.Allocator, options: DiscoveryOptions, host: *HostDiscovery) !void {
    const root = try paths.resolveHomeRoot(allocator, options.home, "/.codex/sessions");
    defer allocator.free(root);
    // YYYY/MM/DD/rollout-*.jsonl — depth 4
    try collectJsonlBounded(io, allocator, options, host, root, 4, ".jsonl");
}

fn discoverPi(io: std.Io, allocator: std.mem.Allocator, options: DiscoveryOptions, host: *HostDiscovery) !void {
    const root = try paths.resolveHomeRoot(allocator, options.home, "/.pi/agent/sessions");
    defer allocator.free(root);
    // project/session/.../session.jsonl
    try collectNamedJsonl(io, allocator, options, host, root, 6, "session.jsonl");
}

fn discoverGrok(io: std.Io, allocator: std.mem.Allocator, options: DiscoveryOptions, host: *HostDiscovery) !void {
    const root = try paths.resolveHomeRoot(allocator, options.home, "/.grok/sessions");
    defer allocator.free(root);
    try collectNamedJsonl(io, allocator, options, host, root, 4, "chat_history.jsonl");
}

// Process-local walkCollect cache. Best-effort, never persisted.
// Invalidation: every visited directory's no-follow mtime is stored. If a
// stored dir mtime is unchanged, new sibling entries cannot exist
// (create/delete/rename of a child updates the parent directory mtime).
// Root-only mtime is not enough — a new file under projects/foo/ bumps foo/,
// not the projects root. File content / utimens rewrites do not bump the
// parent, so cache hits re-stat each stored file and re-apply the window.
const cache_gpa = std.heap.page_allocator;
const walk_cache_cap: usize = 24;
const walk_cache_max_files: usize = 256;

/// Test-only: full walkCollect roots (cache misses) in this process.
var walk_cache_misses: u32 = 0;

const CachedDir = struct {
    path: []u8,
    mtime_ns: i96,
};

const CachedFile = struct {
    path: []u8,
    session_id: []u8,
    mtime_secs: i64,
};

const CachedWalk = struct {
    host: types.Host,
    root: []u8,
    max_depth: u8,
    suffix: ?[]u8,
    exact_name: ?[]u8,
    window_days: ?u32,
    window_all_time: bool,
    dirs: []CachedDir,
    files: []CachedFile,
    seq: u64,
};

var walk_cache: [walk_cache_cap]?CachedWalk = .{null} ** walk_cache_cap;
var walk_cache_seq: u64 = 0;

const WalkScratch = struct {
    allocator: std.mem.Allocator,
    dirs: std.ArrayList(CachedDir) = .empty,
    files: std.ArrayList(CachedFile) = .empty,
    cacheable: bool = true,

    fn deinit(self: *WalkScratch) void {
        for (self.dirs.items) |d| self.allocator.free(d.path);
        for (self.files.items) |f| {
            self.allocator.free(f.path);
            self.allocator.free(f.session_id);
        }
        self.dirs.deinit(self.allocator);
        self.files.deinit(self.allocator);
        self.* = undefined;
    }

    fn addDir(self: *WalkScratch, path: []const u8, mtime_ns: i96) !void {
        const owned = try self.allocator.dupe(u8, path);
        errdefer self.allocator.free(owned);
        try self.dirs.append(self.allocator, .{ .path = owned, .mtime_ns = mtime_ns });
    }

    fn addFile(self: *WalkScratch, path: []const u8, session_id: []const u8, mtime_secs: i64) !void {
        if (self.files.items.len >= walk_cache_max_files) {
            self.cacheable = false;
        }
        const path_owned = try self.allocator.dupe(u8, path);
        errdefer self.allocator.free(path_owned);
        const sid_owned = try self.allocator.dupe(u8, session_id);
        errdefer self.allocator.free(sid_owned);
        try self.files.append(self.allocator, .{
            .path = path_owned,
            .session_id = sid_owned,
            .mtime_secs = mtime_secs,
        });
    }

    fn inWindowCount(self: *const WalkScratch, window: time_window.Window) usize {
        var n: usize = 0;
        for (self.files.items) |f| {
            if (time_window.inWindow(f.mtime_secs, window)) n += 1;
        }
        return n;
    }
};

fn optSliceEql(owned: ?[]const u8, borrowed: ?[]const u8) bool {
    if (owned) |a| {
        const b = borrowed orelse return false;
        return std.mem.eql(u8, a, b);
    }
    return borrowed == null;
}

fn cacheKeyMatch(
    entry: CachedWalk,
    host: types.Host,
    root: []const u8,
    max_depth: u8,
    suffix: ?[]const u8,
    exact_name: ?[]const u8,
    window: time_window.Window,
) bool {
    if (entry.host != host) return false;
    if (entry.max_depth != max_depth) return false;
    if (!std.mem.eql(u8, entry.root, root)) return false;
    if (!optSliceEql(entry.suffix, suffix)) return false;
    if (!optSliceEql(entry.exact_name, exact_name)) return false;
    if (entry.window_all_time != window.all_time) return false;
    if (entry.window_days) |a| {
        const b = window.days orelse return false;
        return a == b;
    }
    return window.days == null;
}

fn findWalkCache(
    host: types.Host,
    root: []const u8,
    max_depth: u8,
    suffix: ?[]const u8,
    exact_name: ?[]const u8,
    window: time_window.Window,
) ?*CachedWalk {
    for (&walk_cache) |*slot| {
        if (slot.*) |*entry| {
            if (cacheKeyMatch(entry.*, host, root, max_depth, suffix, exact_name, window))
                return entry;
        }
    }
    return null;
}

fn freeCachedWalk(entry: *CachedWalk) void {
    cache_gpa.free(entry.root);
    if (entry.suffix) |s| cache_gpa.free(s);
    if (entry.exact_name) |s| cache_gpa.free(s);
    for (entry.dirs) |d| cache_gpa.free(d.path);
    cache_gpa.free(entry.dirs);
    for (entry.files) |f| {
        cache_gpa.free(f.path);
        cache_gpa.free(f.session_id);
    }
    cache_gpa.free(entry.files);
}

fn dupeOptCache(slice: ?[]const u8) !?[]u8 {
    const s = slice orelse return null;
    return try cache_gpa.dupe(u8, s);
}

fn putWalkCache(
    host: types.Host,
    root: []const u8,
    max_depth: u8,
    suffix: ?[]const u8,
    exact_name: ?[]const u8,
    window: time_window.Window,
    record: *const WalkScratch,
) !void {
    const root_owned = try cache_gpa.dupe(u8, root);
    errdefer cache_gpa.free(root_owned);
    const suffix_owned = try dupeOptCache(suffix);
    errdefer if (suffix_owned) |s| cache_gpa.free(s);
    const exact_owned = try dupeOptCache(exact_name);
    errdefer if (exact_owned) |s| cache_gpa.free(s);

    const dirs = try cache_gpa.alloc(CachedDir, record.dirs.items.len);
    errdefer cache_gpa.free(dirs);
    var dirs_n: usize = 0;
    errdefer {
        for (dirs[0..dirs_n]) |d| cache_gpa.free(d.path);
    }
    for (record.dirs.items) |d| {
        dirs[dirs_n] = .{
            .path = try cache_gpa.dupe(u8, d.path),
            .mtime_ns = d.mtime_ns,
        };
        dirs_n += 1;
    }

    const files = try cache_gpa.alloc(CachedFile, record.files.items.len);
    errdefer cache_gpa.free(files);
    var files_n: usize = 0;
    errdefer {
        for (files[0..files_n]) |f| {
            cache_gpa.free(f.path);
            cache_gpa.free(f.session_id);
        }
    }
    for (record.files.items) |f| {
        const p = cache_gpa.dupe(u8, f.path) catch |err| return err;
        const sid = cache_gpa.dupe(u8, f.session_id) catch |err| {
            cache_gpa.free(p);
            return err;
        };
        files[files_n] = .{
            .path = p,
            .session_id = sid,
            .mtime_secs = f.mtime_secs,
        };
        files_n += 1;
    }

    walk_cache_seq += 1;
    const built: CachedWalk = .{
        .host = host,
        .root = root_owned,
        .max_depth = max_depth,
        .suffix = suffix_owned,
        .exact_name = exact_owned,
        .window_days = window.days,
        .window_all_time = window.all_time,
        .dirs = dirs,
        .files = files,
        .seq = walk_cache_seq,
    };

    if (findWalkCache(host, root, max_depth, suffix, exact_name, window)) |old| {
        freeCachedWalk(old);
        old.* = built;
        return;
    }
    for (&walk_cache) |*slot| {
        if (slot.* == null) {
            slot.* = built;
            return;
        }
    }
    var oldest_i: usize = 0;
    var oldest_seq: u64 = std.math.maxInt(u64);
    for (walk_cache, 0..) |slot, i| {
        const e = slot orelse continue;
        if (e.seq < oldest_seq) {
            oldest_seq = e.seq;
            oldest_i = i;
        }
    }
    if (walk_cache[oldest_i]) |*old| {
        freeCachedWalk(old);
    }
    walk_cache[oldest_i] = built;
}

fn storeWalkCache(
    host: types.Host,
    root: []const u8,
    max_depth: u8,
    suffix: ?[]const u8,
    exact_name: ?[]const u8,
    window: time_window.Window,
    record: *const WalkScratch,
) void {
    if (!record.cacheable or record.dirs.items.len == 0) return;
    putWalkCache(host, root, max_depth, suffix, exact_name, window, record) catch return;
}

fn publishWalkRecord(
    allocator: std.mem.Allocator,
    host: *HostDiscovery,
    record: *const WalkScratch,
    window: time_window.Window,
) !void {
    for (record.files.items) |f| {
        if (host.files.items.len >= types.max_sessions_per_host) break;
        if (!time_window.inWindow(f.mtime_secs, window)) continue;
        const path = try allocator.dupe(u8, f.path);
        try appendFile(allocator, &host.files, host.host, path, f.session_id, f.mtime_secs);
    }
    finalizeStatus(host);
}

fn serveWalkCache(
    io: std.Io,
    allocator: std.mem.Allocator,
    host: *HostDiscovery,
    root: []const u8,
    max_depth: u8,
    suffix: ?[]const u8,
    exact_name: ?[]const u8,
    window: time_window.Window,
) !bool {
    const entry = findWalkCache(host.host, root, max_depth, suffix, exact_name, window) orelse return false;
    for (entry.dirs) |d| {
        const st = std.Io.Dir.cwd().statFile(io, d.path, .{ .follow_symlinks = false }) catch return false;
        if (st.kind != .directory) return false;
        if (st.mtime.toNanoseconds() != d.mtime_ns) return false;
    }
    host.status = .empty;
    for (entry.files) |f| {
        if (host.files.items.len >= types.max_sessions_per_host) break;
        const mtime = fileMtimeSecsNoFollow(io, f.path) orelse continue;
        if (!time_window.inWindow(mtime, window)) continue;
        const path = try allocator.dupe(u8, f.path);
        try appendFile(allocator, &host.files, host.host, path, f.session_id, mtime);
    }
    finalizeStatus(host);
    return true;
}

fn collectWalk(
    io: std.Io,
    allocator: std.mem.Allocator,
    options: DiscoveryOptions,
    host: *HostDiscovery,
    root: []const u8,
    max_depth: u8,
    suffix: ?[]const u8,
    exact_name: ?[]const u8,
) !void {
    if (try serveWalkCache(io, allocator, host, root, max_depth, suffix, exact_name, options.window))
        return;

    var dir = std.Io.Dir.cwd().openDir(io, root, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => {
            host.status = .not_found;
            return;
        },
        error.AccessDenied => {
            host.status = .unreadable;
            return;
        },
        else => {
            host.status = .unreadable;
            return;
        },
    };
    defer dir.close(io);
    // Root exists: start as empty so missing in-window files don't stay "not_found".
    host.status = .empty;

    var record: WalkScratch = .{ .allocator = allocator };
    defer record.deinit();
    walk_cache_misses += 1;
    try walkCollect(io, allocator, options, &record, root, "", max_depth, suffix, exact_name);
    try publishWalkRecord(allocator, host, &record, options.window);
    storeWalkCache(host.host, root, max_depth, suffix, exact_name, options.window, &record);
}

fn collectJsonlBounded(
    io: std.Io,
    allocator: std.mem.Allocator,
    options: DiscoveryOptions,
    host: *HostDiscovery,
    root: []const u8,
    max_depth: u8,
    suffix: []const u8,
) !void {
    try collectWalk(io, allocator, options, host, root, max_depth, suffix, null);
}

fn collectNamedJsonl(
    io: std.Io,
    allocator: std.mem.Allocator,
    options: DiscoveryOptions,
    host: *HostDiscovery,
    root: []const u8,
    max_depth: u8,
    filename: []const u8,
) !void {
    try collectWalk(io, allocator, options, host, root, max_depth, null, filename);
}

fn walkCollect(
    io: std.Io,
    allocator: std.mem.Allocator,
    options: DiscoveryOptions,
    record: *WalkScratch,
    root: []const u8,
    rel: []const u8,
    depth_left: u8,
    suffix: ?[]const u8,
    exact_name: ?[]const u8,
) !void {
    if (record.inWindowCount(options.window) >= types.max_sessions_per_host) return;
    const full = if (rel.len == 0) root else try std.fs.path.join(allocator, &.{ root, rel });
    defer if (rel.len != 0) allocator.free(full);

    const open_opts: std.Io.Dir.OpenOptions = if (rel.len == 0)
        .{ .iterate = true }
    else
        .{ .iterate = true, .follow_symlinks = false };
    var dir = std.Io.Dir.cwd().openDir(io, full, open_opts) catch return;
    defer dir.close(io);

    if (dir.stat(io)) |st| {
        try record.addDir(full, st.mtime.toNanoseconds());
    } else |_| {
        record.cacheable = false;
    }

    var it = dir.iterate();
    while (true) {
        const entry = it.next(io) catch break orelse break;
        if (record.inWindowCount(options.window) >= types.max_sessions_per_host) return;

        if (entry.kind == .file) {
            const match = blk: {
                if (exact_name) |n| break :blk std.mem.eql(u8, entry.name, n);
                if (suffix) |s| break :blk std.mem.endsWith(u8, entry.name, s);
                break :blk false;
            };
            if (!match) continue;
            // Skip non-session noise under known roots.
            if (std.mem.eql(u8, entry.name, "prompt_history.jsonl") or
                std.mem.eql(u8, entry.name, "session_search.sqlite"))
                continue;
            // Hostile / non-session entry names.
            if (!isSafeEntryName(entry.name)) continue;
            const name_owned = try allocator.dupe(u8, entry.name);
            defer allocator.free(name_owned);
            const file_rel = if (rel.len == 0)
                try allocator.dupe(u8, name_owned)
            else
                try std.fs.path.join(allocator, &.{ rel, name_owned });
            defer allocator.free(file_rel);
            const file_path = try std.fs.path.join(allocator, &.{ root, file_rel });
            defer allocator.free(file_path);
            // Containment: refuse symlink leaves (open without following).
            if (!isRegularFileNoFollow(io, file_path)) continue;
            const mtime = fileMtimeSecsNoFollow(io, file_path) orelse 0;
            const sid = sessionIdFromPath(name_owned, rel);
            try record.addFile(file_path, sid, mtime);
            continue;
        }
        if (entry.kind == .sym_link) continue; // never recurse through symlinks
        if (entry.kind == .directory and depth_left > 0) {
            // Skip obvious non-session dirs / hostile names
            if (std.mem.eql(u8, entry.name, ".") or
                std.mem.eql(u8, entry.name, "..") or
                std.mem.eql(u8, entry.name, "node_modules") or
                std.mem.eql(u8, entry.name, ".git") or
                std.mem.eql(u8, entry.name, "bin") or
                std.mem.eql(u8, entry.name, "memtrace") or
                std.mem.eql(u8, entry.name, "relocations") or
                std.mem.eql(u8, entry.name, "skill-observations") or
                std.mem.eql(u8, entry.name, "skills") or
                std.mem.eql(u8, entry.name, "plugins") or
                std.mem.indexOfScalar(u8, entry.name, 0) != null or
                std.mem.indexOfScalar(u8, entry.name, '/') != null)
                continue;
            // Always own child_rel — Dir.Entry.name is only valid until the next iterate().
            const child_rel = if (rel.len == 0)
                try allocator.dupe(u8, entry.name)
            else
                try std.fs.path.join(allocator, &.{ rel, entry.name });
            defer allocator.free(child_rel);
            try walkCollect(io, allocator, options, record, root, child_rel, depth_left - 1, suffix, exact_name);
        }
    }
}

fn sessionIdFromPath(name: []const u8, rel: []const u8) []const u8 {
    // Fixed host filenames are not session ids — prefer parent directory segment.
    const fixed = [_][]const u8{ "chat_history.jsonl", "session.jsonl", "events.jsonl", "updates.jsonl" };
    var prefer_parent = false;
    for (fixed) |f| {
        if (std.mem.eql(u8, name, f)) {
            prefer_parent = true;
            break;
        }
    }
    if (!prefer_parent) {
        if (std.mem.endsWith(u8, name, ".jsonl")) {
            const stem = name[0 .. name.len - 6];
            if (stem.len > 0) return stem;
        }
    }
    if (rel.len > 0) {
        if (std.mem.lastIndexOfScalar(u8, rel, '/')) |idx| {
            return rel[idx + 1 ..];
        }
        return rel;
    }
    return name;
}

/// Always consumes `path` (frees on reject/error; stores on success).
fn appendFile(
    allocator: std.mem.Allocator,
    list: *std.ArrayList(DiscoveredFile),
    host: types.Host,
    path: []u8,
    session_id: []const u8,
    mtime: i64,
) !void {
    // Zig path APIs reject embedded NUL; skip hostile/corrupt names.
    if (std.mem.indexOfScalar(u8, path, 0) != null or path.len == 0 or path.len > 4096) {
        allocator.free(path);
        return;
    }
    if (std.mem.indexOfScalar(u8, session_id, 0) != null or
        std.mem.eql(u8, session_id, ".") or
        std.mem.eql(u8, session_id, "..") or
        std.mem.indexOfScalar(u8, session_id, '/') != null)
    {
        allocator.free(path);
        return;
    }
    errdefer allocator.free(path);
    const sid = try allocator.dupe(u8, session_id);
    errdefer allocator.free(sid);
    try list.append(allocator, .{
        .host = host,
        .path = path,
        .session_id = sid,
        .mtime_secs = mtime,
    });
    // Success: path + sid owned by list; disarm errdefers by not returning error.
}

fn finalizeStatus(host: *HostDiscovery) void {
    if (host.files.items.len > 0) {
        host.status = .ok;
    } else if (host.status == .not_found or host.status == .unreadable) {
        // keep
    } else {
        host.status = .empty;
    }
}

fn pathExists(io: std.Io, path: []const u8) bool {
    std.Io.Dir.cwd().access(io, path, .{}) catch return false;
    return true;
}

/// Entry-name gate shared by directory walk and ryk session roots.
pub fn isSafeEntryName(name: []const u8) bool {
    if (name.len == 0 or name.len > 255) return false;
    if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return false;
    if (std.mem.indexOfScalar(u8, name, 0) != null) return false;
    if (std.mem.indexOfScalar(u8, name, '/') != null) return false;
    if (std.mem.indexOfScalar(u8, name, '\\') != null) return false;
    return true;
}

/// True when path opens as a regular file without following symlinks.
fn isRegularFileNoFollow(io: std.Io, path: []const u8) bool {
    if (path.len == 0) return false;
    const file = std.Io.Dir.cwd().openFile(io, path, .{ .follow_symlinks = false }) catch return false;
    defer file.close(io);
    const st = file.stat(io) catch return false;
    return st.kind == .file;
}

fn fileMtimeSecs(io: std.Io, path: []const u8) ?i64 {
    const st = std.Io.Dir.cwd().statFile(io, path, .{}) catch return null;
    return st.mtime.toSeconds();
}

fn fileMtimeSecsNoFollow(io: std.Io, path: []const u8) ?i64 {
    const file = std.Io.Dir.cwd().openFile(io, path, .{ .follow_symlinks = false }) catch return null;
    defer file.close(io);
    const st = file.stat(io) catch return null;
    return st.mtime.toSeconds();
}

test "discover missing home roots is not_found not crash" {
    const io = std.testing.io;
    const home = try std.fmt.allocPrint(std.testing.allocator, "zig-cache/tmp-scan-home-{d}", .{std.Io.Timestamp.now(io, .real).toSeconds()});
    defer std.testing.allocator.free(home);
    std.Io.Dir.cwd().createDirPath(io, home) catch {};
    defer std.Io.Dir.cwd().deleteTree(io, home) catch {};

    const window = time_window.resolveWindow(std.Io.Timestamp.now(io, .real).toSeconds(), 30, false);
    const items = try discoverAll(io, std.testing.allocator, .{
        .home = home,
        .window = window,
    });
    defer freeDiscoveries(std.testing.allocator, items);
    try std.testing.expect(items.len >= 5);
    for (items) |h| {
        if (h.host == .opencode) {
            try std.testing.expect(h.status == .not_found);
        } else {
            try std.testing.expect(h.status == .not_found or h.status == .empty);
        }
        try std.testing.expectEqual(@as(usize, 0), h.files.items.len);
    }
}

test "discover opencode fixture flips status to ok with sessions" {
    const io = std.testing.io;
    if (!opencode_db.sqlite3Available(io, std.testing.allocator)) return error.SkipZigTest;

    const now: i64 = 1_785_143_897;
    const home = try std.fmt.allocPrint(std.testing.allocator, "zig-cache/tmp-scan-oc-discover-{d}", .{std.Io.Timestamp.now(io, .real).toSeconds()});
    defer std.testing.allocator.free(home);
    defer std.Io.Dir.cwd().deleteTree(io, home) catch {};

    const xdg = try std.fs.path.join(std.testing.allocator, &.{ home, "share" });
    defer std.testing.allocator.free(xdg);
    const oc_dir = try std.fs.path.join(std.testing.allocator, &.{ xdg, "opencode" });
    defer std.testing.allocator.free(oc_dir);
    try std.Io.Dir.cwd().createDirPath(io, oc_dir);
    const db_path = try std.fs.path.join(std.testing.allocator, &.{ oc_dir, "opencode.db" });
    defer std.testing.allocator.free(db_path);
    try opencode_db.writeSyntheticFixtureDb(io, std.testing.allocator, db_path, now);

    const window = time_window.resolveWindow(now, 30, false);
    const items = try discoverAll(io, std.testing.allocator, .{
        .home = home,
        .xdg_data_home = xdg,
        .window = window,
        .only_host = .opencode,
    });
    defer freeDiscoveries(std.testing.allocator, items);
    try std.testing.expectEqual(@as(usize, 1), items.len);
    try std.testing.expect(items[0].status == .ok);
    try std.testing.expect(items[0].files.items.len >= 1);
    try std.testing.expectEqualStrings("ses_inwindow01", items[0].files.items[0].session_id);
    // Must not be the old soft-skip note.
    try std.testing.expect(std.mem.indexOf(u8, items[0].note, "soft-skipped") == null);
}

test "discover claude fixture jsonl end-to-end path" {
    const io = std.testing.io;
    const home = try std.fmt.allocPrint(std.testing.allocator, "zig-cache/tmp-scan-claude-{d}", .{std.Io.Timestamp.now(io, .real).toSeconds()});
    defer std.testing.allocator.free(home);
    defer std.Io.Dir.cwd().deleteTree(io, home) catch {};

    const proj = try std.fs.path.join(std.testing.allocator, &.{ home, ".claude", "projects", "demo" });
    defer std.testing.allocator.free(proj);
    try std.Io.Dir.cwd().createDirPath(io, proj);

    const sess = try std.fs.path.join(std.testing.allocator, &.{ proj, "abc-session.jsonl" });
    defer std.testing.allocator.free(sess);
    const body =
        \\{"type":"assistant","timestamp":"2026-07-20T12:00:00Z","message":{"content":[{"type":"tool_use","name":"Bash","input":{"command":"rm -rf /tmp/x"}}]}}
        \\{"type":"user","message":{"content":[{"type":"text","text":"token ghp_fakeSyntheticTokenValue1234567890abcd"}]}}
        \\
    ;
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = sess, .data = body });

    // Touch mtime is now — within 30d window.
    const window = time_window.resolveWindow(std.Io.Timestamp.now(io, .real).toSeconds(), 30, false);
    const items = try discoverAll(io, std.testing.allocator, .{
        .home = home,
        .window = window,
        .only_host = .claude,
    });
    defer freeDiscoveries(std.testing.allocator, items);
    try std.testing.expectEqual(@as(usize, 1), items.len);
    try std.testing.expect(items[0].status == .ok);
    try std.testing.expectEqual(@as(usize, 1), items[0].files.items.len);

    // Parse commands from the file.
    var parsed = try jsonl.parseJsonlFile(io, std.testing.allocator, items[0].files.items[0].path, 0);
    defer parsed.deinit(std.testing.allocator);
    try std.testing.expect(parsed.commands.items.len >= 1);
}

test "discover ryk reads workspace .ryk/sessions" {
    const io = std.testing.io;
    const home = try std.fmt.allocPrint(std.testing.allocator, "zig-cache/tmp-scan-ryk-home-{d}", .{std.Io.Timestamp.now(io, .real).toSeconds()});
    defer std.testing.allocator.free(home);
    defer std.Io.Dir.cwd().deleteTree(io, home) catch {};
    try std.Io.Dir.cwd().createDirPath(io, home);

    var ws = std.testing.tmpDir(.{});
    defer ws.cleanup();
    const workspace = try ws.dir.realPathFileAlloc(io, ".", std.testing.allocator);
    defer std.testing.allocator.free(workspace);
    try ws.dir.createDirPath(io, ".ryk/sessions/run-echo-1");
    try ws.dir.writeFile(io, .{
        .sub_path = ".ryk/sessions/run-echo-1/events.jsonl",
        .data = "{\"event_type\":\"session_start\"}\n",
    });

    const window = time_window.resolveWindow(std.Io.Timestamp.now(io, .real).toSeconds(), 30, false);
    const items = try discoverAll(io, std.testing.allocator, .{
        .home = home,
        .workspace_root = workspace,
        .window = window,
        .only_host = .ryk,
    });
    defer freeDiscoveries(std.testing.allocator, items);
    try std.testing.expectEqual(@as(usize, 1), items.len);
    try std.testing.expect(items[0].status == .ok);
    try std.testing.expectEqual(@as(usize, 1), items[0].files.items.len);
    try std.testing.expectEqualStrings("run-echo-1", items[0].files.items[0].session_id);
}

fn setFileMtimeSecs(io: std.Io, path: []const u8, secs: i64) !void {
    const ts = std.Io.Timestamp.fromNanoseconds(@as(i96, secs) * std.time.ns_per_s);
    const file = try std.Io.Dir.cwd().openFile(io, path, .{ .follow_symlinks = false });
    defer file.close(io);
    try file.setTimestamps(io, .{
        .access_timestamp = .{ .new = ts },
        .modify_timestamp = .{ .new = ts },
    });
}

fn claudeJsonlBody() []const u8 {
    return "{\"type\":\"user\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"hi\"}]}}\n";
}

test "discover cache hit same result" {
    const io = std.testing.io;
    const home = try std.fmt.allocPrint(std.testing.allocator, "zig-cache/tmp-scan-claude-cache-hit-{d}", .{std.Io.Timestamp.now(io, .real).toSeconds()});
    defer std.testing.allocator.free(home);
    defer std.Io.Dir.cwd().deleteTree(io, home) catch {};

    const proj = try std.fs.path.join(std.testing.allocator, &.{ home, ".claude", "projects", "demo" });
    defer std.testing.allocator.free(proj);
    try std.Io.Dir.cwd().createDirPath(io, proj);
    const sess = try std.fs.path.join(std.testing.allocator, &.{ proj, "abc-session.jsonl" });
    defer std.testing.allocator.free(sess);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = sess, .data = claudeJsonlBody() });

    const window = time_window.resolveWindow(std.Io.Timestamp.now(io, .real).toSeconds(), 30, false);
    walk_cache_misses = 0;
    const first = try discoverAll(io, std.testing.allocator, .{
        .home = home,
        .window = window,
        .only_host = .claude,
    });
    defer freeDiscoveries(std.testing.allocator, first);
    try std.testing.expectEqual(@as(usize, 1), first.len);
    try std.testing.expect(first[0].status == .ok);
    try std.testing.expectEqual(@as(usize, 1), first[0].files.items.len);
    try std.testing.expectEqualStrings("abc-session", first[0].files.items[0].session_id);
    try std.testing.expectEqual(@as(u32, 1), walk_cache_misses);

    const second = try discoverAll(io, std.testing.allocator, .{
        .home = home,
        .window = window,
        .only_host = .claude,
    });
    defer freeDiscoveries(std.testing.allocator, second);
    try std.testing.expectEqual(@as(usize, 1), second.len);
    try std.testing.expect(second[0].status == first[0].status);
    try std.testing.expectEqual(first[0].files.items.len, second[0].files.items.len);
    try std.testing.expectEqualStrings(first[0].files.items[0].session_id, second[0].files.items[0].session_id);
    try std.testing.expectEqualStrings(first[0].files.items[0].path, second[0].files.items[0].path);
    try std.testing.expectEqual(@as(u32, 1), walk_cache_misses);
}

test "discover cache hit survives cutoff tick" {
    const io = std.testing.io;
    const now: i64 = std.Io.Timestamp.now(io, .real).toSeconds();
    const home = try std.fmt.allocPrint(std.testing.allocator, "zig-cache/tmp-scan-claude-cache-tick-{d}", .{now});
    defer std.testing.allocator.free(home);
    defer std.Io.Dir.cwd().deleteTree(io, home) catch {};

    const proj = try std.fs.path.join(std.testing.allocator, &.{ home, ".claude", "projects", "demo" });
    defer std.testing.allocator.free(proj);
    try std.Io.Dir.cwd().createDirPath(io, proj);
    const sess = try std.fs.path.join(std.testing.allocator, &.{ proj, "abc-session.jsonl" });
    defer std.testing.allocator.free(sess);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = sess, .data = claudeJsonlBody() });

    const first_window = time_window.resolveWindow(now, 30, false);
    walk_cache_misses = 0;
    const first = try discoverAll(io, std.testing.allocator, .{
        .home = home,
        .window = first_window,
        .only_host = .claude,
    });
    defer freeDiscoveries(std.testing.allocator, first);
    try std.testing.expectEqual(@as(usize, 1), first.len);
    try std.testing.expect(first[0].status == .ok);
    try std.testing.expectEqual(@as(usize, 1), first[0].files.items.len);
    try std.testing.expectEqualStrings("abc-session", first[0].files.items[0].session_id);
    try std.testing.expectEqual(@as(u32, 1), walk_cache_misses);

    const second = try discoverAll(io, std.testing.allocator, .{
        .home = home,
        .window = time_window.resolveWindow(now + 1, 30, false),
        .only_host = .claude,
    });
    defer freeDiscoveries(std.testing.allocator, second);
    try std.testing.expectEqual(@as(usize, 1), second.len);
    try std.testing.expect(second[0].status == .ok);
    try std.testing.expectEqual(@as(usize, 1), second[0].files.items.len);
    try std.testing.expectEqualStrings("abc-session", second[0].files.items[0].session_id);
    try std.testing.expectEqual(@as(u32, 1), walk_cache_misses);
}

test "discover nested dir change invalidates cache" {
    const io = std.testing.io;
    const home = try std.fmt.allocPrint(std.testing.allocator, "zig-cache/tmp-scan-claude-cache-nested-{d}", .{std.Io.Timestamp.now(io, .real).toSeconds()});
    defer std.testing.allocator.free(home);
    defer std.Io.Dir.cwd().deleteTree(io, home) catch {};

    const proj = try std.fs.path.join(std.testing.allocator, &.{ home, ".claude", "projects", "demo" });
    defer std.testing.allocator.free(proj);
    try std.Io.Dir.cwd().createDirPath(io, proj);
    const first_sess = try std.fs.path.join(std.testing.allocator, &.{ proj, "abc-session.jsonl" });
    defer std.testing.allocator.free(first_sess);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = first_sess, .data = claudeJsonlBody() });

    const window = time_window.resolveWindow(std.Io.Timestamp.now(io, .real).toSeconds(), 30, false);
    walk_cache_misses = 0;
    {
        const items = try discoverAll(io, std.testing.allocator, .{
            .home = home,
            .window = window,
            .only_host = .claude,
        });
        defer freeDiscoveries(std.testing.allocator, items);
        try std.testing.expectEqual(@as(usize, 1), items[0].files.items.len);
        try std.testing.expectEqual(@as(u32, 1), walk_cache_misses);
    }

    const second_sess = try std.fs.path.join(std.testing.allocator, &.{ proj, "new-session.jsonl" });
    defer std.testing.allocator.free(second_sess);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = second_sess, .data = claudeJsonlBody() });

    const items = try discoverAll(io, std.testing.allocator, .{
        .home = home,
        .window = window,
        .only_host = .claude,
    });
    defer freeDiscoveries(std.testing.allocator, items);
    try std.testing.expect(items[0].status == .ok);
    try std.testing.expectEqual(@as(usize, 2), items[0].files.items.len);
    var saw_new = false;
    for (items[0].files.items) |f| {
        if (std.mem.eql(u8, f.session_id, "new-session")) saw_new = true;
    }
    try std.testing.expect(saw_new);
    try std.testing.expectEqual(@as(u32, 2), walk_cache_misses);
}

test "discover file mtime window refresh without dir change" {
    const io = std.testing.io;
    const now: i64 = std.Io.Timestamp.now(io, .real).toSeconds();
    const home = try std.fmt.allocPrint(std.testing.allocator, "zig-cache/tmp-scan-claude-cache-mtime-{d}", .{now});
    defer std.testing.allocator.free(home);
    defer std.Io.Dir.cwd().deleteTree(io, home) catch {};

    const proj = try std.fs.path.join(std.testing.allocator, &.{ home, ".claude", "projects", "demo" });
    defer std.testing.allocator.free(proj);
    try std.Io.Dir.cwd().createDirPath(io, proj);
    const sess = try std.fs.path.join(std.testing.allocator, &.{ proj, "old-session.jsonl" });
    defer std.testing.allocator.free(sess);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = sess, .data = claudeJsonlBody() });
    try setFileMtimeSecs(io, sess, now - 60 * 86_400);

    const window = time_window.resolveWindow(now, 30, false);
    walk_cache_misses = 0;
    {
        const items = try discoverAll(io, std.testing.allocator, .{
            .home = home,
            .window = window,
            .only_host = .claude,
        });
        defer freeDiscoveries(std.testing.allocator, items);
        try std.testing.expect(items[0].status == .empty);
        try std.testing.expectEqual(@as(usize, 0), items[0].files.items.len);
        try std.testing.expectEqual(@as(u32, 1), walk_cache_misses);
    }

    try setFileMtimeSecs(io, sess, now);

    const items = try discoverAll(io, std.testing.allocator, .{
        .home = home,
        .window = window,
        .only_host = .claude,
    });
    defer freeDiscoveries(std.testing.allocator, items);
    try std.testing.expect(items[0].status == .ok);
    try std.testing.expectEqual(@as(usize, 1), items[0].files.items.len);
    try std.testing.expectEqualStrings("old-session", items[0].files.items[0].session_id);
    try std.testing.expectEqual(@as(u32, 1), walk_cache_misses);
}

test "discover symlink leaf and dir still skipped with cache" {
    const io = std.testing.io;
    const home = try std.fmt.allocPrint(std.testing.allocator, "zig-cache/tmp-scan-claude-cache-symlink-{d}", .{std.Io.Timestamp.now(io, .real).toSeconds()});
    defer std.testing.allocator.free(home);
    defer std.Io.Dir.cwd().deleteTree(io, home) catch {};

    const proj = try std.fs.path.join(std.testing.allocator, &.{ home, ".claude", "projects", "demo" });
    defer std.testing.allocator.free(proj);
    try std.Io.Dir.cwd().createDirPath(io, proj);
    const hidden_dir = try std.fs.path.join(std.testing.allocator, &.{ home, ".claude", "outside-hidden" });
    defer std.testing.allocator.free(hidden_dir);
    try std.Io.Dir.cwd().createDirPath(io, hidden_dir);

    const real_sess = try std.fs.path.join(std.testing.allocator, &.{ proj, "real-session.jsonl" });
    defer std.testing.allocator.free(real_sess);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = real_sess, .data = claudeJsonlBody() });

    const hidden_sess = try std.fs.path.join(std.testing.allocator, &.{ hidden_dir, "hidden-session.jsonl" });
    defer std.testing.allocator.free(hidden_sess);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = hidden_sess, .data = claudeJsonlBody() });

    const alias = try std.fs.path.join(std.testing.allocator, &.{ proj, "alias-session.jsonl" });
    defer std.testing.allocator.free(alias);
    std.Io.Dir.cwd().symLink(io, "real-session.jsonl", alias, .{}) catch |err| switch (err) {
        error.Unexpected => return error.SkipZigTest,
        else => |e| return e,
    };

    const link_dir = try std.fs.path.join(std.testing.allocator, &.{ proj, "linkdir" });
    defer std.testing.allocator.free(link_dir);
    std.Io.Dir.cwd().symLink(io, "../../outside-hidden", link_dir, .{ .is_directory = true }) catch |err| switch (err) {
        error.Unexpected => return error.SkipZigTest,
        else => |e| return e,
    };

    const window = time_window.resolveWindow(std.Io.Timestamp.now(io, .real).toSeconds(), 30, false);
    walk_cache_misses = 0;
    const first = try discoverAll(io, std.testing.allocator, .{
        .home = home,
        .window = window,
        .only_host = .claude,
    });
    defer freeDiscoveries(std.testing.allocator, first);
    try std.testing.expectEqual(@as(usize, 1), first[0].files.items.len);
    try std.testing.expectEqualStrings("real-session", first[0].files.items[0].session_id);

    const second = try discoverAll(io, std.testing.allocator, .{
        .home = home,
        .window = window,
        .only_host = .claude,
    });
    defer freeDiscoveries(std.testing.allocator, second);
    try std.testing.expectEqual(@as(usize, 1), second[0].files.items.len);
    try std.testing.expectEqualStrings("real-session", second[0].files.items[0].session_id);
    try std.testing.expectEqual(@as(u32, 1), walk_cache_misses);
}

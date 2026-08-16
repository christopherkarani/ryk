//! Permanent pack-exception allowlist store (product path).
//!
//! Distinct from policy `allowlist.Layered` / `Entry.prefix`.
//! Types: kind rule|command, id/command, reason, created_at, expires_at, layer.
//! No `prefix` field — permanent path is never prefix-based.
//!
//! TOML (illustrative product schema):
//! ```toml
//! schema_version = 1
//! [[entries]]
//! kind = "rule"            # or "command"
//! id = "core.git:reset-hard"
//! # command = "git status" # when kind=command
//! reason = "recovering local branch after failed rebase"
//! created_at = "2026-07-25T12:00:00Z"
//! # expires_at = "2026-07-26T12:00:00Z"
//! scope = "project"        # informational; file location is source of truth
//! ```
//!
//! Paths (product): project `.ryk/allowlist.toml`, user `~/.config/ryk/allowlist.toml`
//! (or `$XDG_CONFIG_HOME/ryk/allowlist.toml`). Tests inject absolute paths.
//! Re-exported via `shell_engine` and covered by `test-shell-engine`.

const std = @import("std");
const builtin = @import("builtin");

// ---------------------------------------------------------------------------
// Permanent pack-exception allowlist (product path). Distinct from Layered.
// ---------------------------------------------------------------------------

pub const schema_version: u32 = 1;

pub const EntryKind = enum { rule, command };
pub const Layer = enum { user, project };

pub const PermanentEntry = struct {
    kind: EntryKind,
    id: ?[]const u8 = null,
    command: ?[]const u8 = null,
    reason: []const u8,
    created_at: []const u8,
    expires_at: ?[]const u8 = null,
    layer: Layer,
};

pub const Store = struct {
    entries: []PermanentEntry = &.{},
    owned: bool = false,

    pub fn deinit(self: *Store, gpa: std.mem.Allocator) void {
        if (!self.owned) {
            self.* = .{};
            return;
        }
        for (self.entries) |e| freeEntry(gpa, e);
        gpa.free(self.entries);
        self.* = .{};
    }

    /// Exact full-command match (never prefix). Query outer whitespace is trimmed when
    /// the stored command is already canonical (no outer whitespace). Stored commands
    /// that intentionally include outer whitespace match only with exact equality.
    pub fn matchCommand(self: Store, command: []const u8, now_iso: []const u8) ?PermanentEntry {
        for (self.entries) |e| {
            if (e.kind != .command) continue;
            if (isExpired(e, now_iso)) continue;
            const stored = e.command orelse continue;
            if (commandsMatch(stored, command)) return e;
        }
        return null;
    }

    /// Exact rule-id match for E8 skip-this-rule lookups.
    pub fn matchRule(self: Store, rule_id: []const u8, now_iso: []const u8) ?PermanentEntry {
        for (self.entries) |e| {
            if (e.kind != .rule) continue;
            if (isExpired(e, now_iso)) continue;
            const id = e.id orelse continue;
            if (std.mem.eql(u8, id, rule_id)) return e;
        }
        return null;
    }
};

pub const LoadOutcome = struct {
    store: Store,
    corrupt: bool = false,
};

pub const Draft = struct {
    kind: EntryKind,
    id: ?[]const u8 = null,
    command: ?[]const u8 = null,
    reason: []const u8,
    created_at: []const u8,
    expires_at: ?[]const u8 = null,
};

pub const ValidateError = error{
    ReasonRequired,
    CommandRequired,
    RuleIdRequired,
    InvalidRuleIdForm,
    UnknownRuleId,
};

const max_file_bytes: usize = 1024 * 1024;

/// Key used for merge override / remove: rule id or exact command string.
pub fn entryKey(entry: PermanentEntry) []const u8 {
    return switch (entry.kind) {
        .rule => entry.id orelse "",
        .command => entry.command orelse "",
    };
}

/// ISO-8601 same-format lexicographic compare: expired when expires_at <= now.
pub fn isExpired(entry: PermanentEntry, now_iso: []const u8) bool {
    const exp = entry.expires_at orelse return false;
    return std.mem.order(u8, exp, now_iso) != .gt;
}

/// Nonempty pack + ":" + nonempty pattern (after trim of each side).
pub fn isValidRuleIdForm(id: []const u8) bool {
    const colon = std.mem.indexOfScalar(u8, id, ':') orelse return false;
    const pack = std.mem.trim(u8, id[0..colon], " \t\r\n");
    const pattern = std.mem.trim(u8, id[colon + 1 ..], " \t\r\n");
    return pack.len > 0 and pattern.len > 0;
}

pub fn validateDraft(draft: Draft, known_rule_ids: ?[]const []const u8) ValidateError!void {
    if (std.mem.trim(u8, draft.reason, " \t\r\n").len == 0) return error.ReasonRequired;

    switch (draft.kind) {
        .rule => {
            const id = draft.id orelse return error.RuleIdRequired;
            if (id.len == 0) return error.RuleIdRequired;
            if (!isValidRuleIdForm(id)) return error.InvalidRuleIdForm;
            if (known_rule_ids) |known| {
                var found = false;
                for (known) |k| {
                    if (std.mem.eql(u8, k, id)) {
                        found = true;
                        break;
                    }
                }
                if (!found) return error.UnknownRuleId;
            }
        },
        .command => {
            const cmd = draft.command orelse return error.CommandRequired;
            if (std.mem.trim(u8, cmd, " \t\r\n").len == 0) return error.CommandRequired;
        },
    }
}

pub fn loadFile(
    runtime_io: std.Io,
    gpa: std.mem.Allocator,
    path: []const u8,
    layer: Layer,
) !LoadOutcome {
    // Missing → empty, not corrupt. Unreadable/oversized/permission/etc. → empty + corrupt
    // so evaluate continues fail-closed without aborting loadMerged. Only OOM propagates.
    const raw = std.Io.Dir.cwd().readFileAlloc(runtime_io, path, gpa, .limited(max_file_bytes)) catch |err| switch (err) {
        error.FileNotFound => return .{
            .store = .{ .entries = &.{}, .owned = false },
            .corrupt = false,
        },
        error.OutOfMemory => return error.OutOfMemory,
        else => return .{
            .store = .{ .entries = &.{}, .owned = false },
            .corrupt = true,
        },
    };
    defer gpa.free(raw);

    if (std.mem.trim(u8, raw, " \t\r\n").len == 0) {
        return .{
            .store = .{ .entries = &.{}, .owned = false },
            .corrupt = false,
        };
    }

    const parsed = parseToml(gpa, raw, layer) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Corrupt => return .{
            .store = .{ .entries = &.{}, .owned = false },
            .corrupt = true,
        },
    };
    return .{
        .store = parsed,
        .corrupt = false,
    };
}

/// In-process cache of **raw** `loadMerged` layers only (not ProductShellStores).
/// Callers always receive a deep copy. M-10 strip and `allow_once_path` stay
/// outside this cache so every product load re-applies them.
const merged_cache_path_max: usize = 4096;

const LayerObs = struct {
    const Kind = enum { absent, missing, present, unreadable };
    kind: Kind,
    inode: std.Io.File.INode = 0,
    size: u64 = 0,
    mtime_ns: i96 = 0,
    mode: std.posix.mode_t = 0,

    fn coarse(self: LayerObs) bool {
        return self.kind == .present and @mod(self.mtime_ns, std.time.ns_per_s) == 0;
    }

    fn eql(a: LayerObs, b: LayerObs) bool {
        if (a.kind != b.kind) return false;
        if (a.kind != .present) return true;
        return a.inode == b.inode and a.size == b.size and a.mtime_ns == b.mtime_ns and a.mode == b.mode;
    }
};

fn observeLayer(runtime_io: std.Io, path: ?[]const u8) LayerObs {
    const p = path orelse return .{ .kind = .absent };
    const st = std.Io.Dir.cwd().statFile(runtime_io, p, .{}) catch |err| switch (err) {
        error.FileNotFound => return .{ .kind = .missing },
        else => return .{ .kind = .unreadable },
    };
    return .{
        .kind = .present,
        .inode = st.inode,
        .size = st.size,
        .mtime_ns = st.mtime.toNanoseconds(),
        .mode = st.permissions.toMode(),
    };
}

fn layerCacheable(obs: LayerObs, path: ?[]const u8) bool {
    if (obs.kind == .unreadable) return false;
    if (obs.coarse()) return false;
    if (path) |p| if (p.len > merged_cache_path_max) return false;
    return true;
}

const MergedCache = struct {
    var mu: std.Io.Mutex = .init;
    var occupied: bool = false;
    var user_path_buf: [merged_cache_path_max]u8 = undefined;
    var user_path_len: usize = 0;
    var user_path_set: bool = false;
    var project_path_buf: [merged_cache_path_max]u8 = undefined;
    var project_path_len: usize = 0;
    var project_path_set: bool = false;
    var user_obs: LayerObs = .{ .kind = .absent };
    var project_obs: LayerObs = .{ .kind = .absent };
    var store: Store = .{};
    var corrupt: bool = false;

    fn clear(runtime_io: std.Io) void {
        mu.lockUncancelable(runtime_io);
        defer mu.unlock(runtime_io);
        clearLocked();
    }

    fn clearLocked() void {
        store.deinit(std.heap.page_allocator);
        occupied = false;
        user_path_len = 0;
        user_path_set = false;
        project_path_len = 0;
        project_path_set = false;
        user_obs = .{ .kind = .absent };
        project_obs = .{ .kind = .absent };
        corrupt = false;
    }

    fn pathsMatchLocked(user_path: ?[]const u8, project_path: ?[]const u8) bool {
        if (!pathSlotMatch(user_path_set, user_path_buf[0..user_path_len], user_path)) return false;
        if (!pathSlotMatch(project_path_set, project_path_buf[0..project_path_len], project_path)) return false;
        return true;
    }

    fn copyIfHit(
        runtime_io: std.Io,
        gpa: std.mem.Allocator,
        user_path: ?[]const u8,
        project_path: ?[]const u8,
        user_id: LayerObs,
        project_id: LayerObs,
    ) !?LoadOutcome {
        if (!layerCacheable(user_id, user_path) or !layerCacheable(project_id, project_path)) return null;
        mu.lockUncancelable(runtime_io);
        defer mu.unlock(runtime_io);
        if (!occupied) return null;
        if (!pathsMatchLocked(user_path, project_path)) return null;
        if (!LayerObs.eql(user_obs, user_id) or !LayerObs.eql(project_obs, project_id)) return null;
        const copy = try cloneStore(gpa, store);
        if (builtin.is_test) testing_merged_cache_hits += 1;
        return .{ .store = copy, .corrupt = corrupt };
    }

    fn put(
        runtime_io: std.Io,
        user_path: ?[]const u8,
        project_path: ?[]const u8,
        user_id: LayerObs,
        project_id: LayerObs,
        outcome: LoadOutcome,
    ) void {
        mu.lockUncancelable(runtime_io);
        defer mu.unlock(runtime_io);
        const can_cache = layerCacheable(user_id, user_path) and layerCacheable(project_id, project_path);
        if (!can_cache) {
            if (pathsMatchLocked(user_path, project_path)) clearLocked();
            return;
        }
        const cloned = cloneStore(std.heap.page_allocator, outcome.store) catch {
            clearLocked();
            return;
        };
        clearLocked();
        writePathSlot(&user_path_buf, &user_path_len, &user_path_set, user_path);
        writePathSlot(&project_path_buf, &project_path_len, &project_path_set, project_path);
        user_obs = user_id;
        project_obs = project_id;
        store = cloned;
        corrupt = outcome.corrupt;
        occupied = true;
    }
};

fn pathSlotMatch(set: bool, stored: []const u8, path: ?[]const u8) bool {
    if (path) |p| {
        if (!set) return false;
        return std.mem.eql(u8, stored, p);
    }
    return !set;
}

fn writePathSlot(buf: *[merged_cache_path_max]u8, len: *usize, set: *bool, path: ?[]const u8) void {
    if (path) |p| {
        @memcpy(buf[0..p.len], p);
        len.* = p.len;
        set.* = true;
    } else {
        len.* = 0;
        set.* = false;
    }
}

fn cloneStore(gpa: std.mem.Allocator, src: Store) !Store {
    if (src.entries.len == 0) return .{ .entries = &.{}, .owned = false };
    const entries = try gpa.alloc(PermanentEntry, src.entries.len);
    errdefer gpa.free(entries);
    var n: usize = 0;
    errdefer for (entries[0..n]) |e| freeEntry(gpa, e);
    for (src.entries) |e| {
        entries[n] = try cloneEntry(gpa, e);
        n += 1;
    }
    return .{ .entries = entries, .owned = true };
}

pub fn loadMerged(
    runtime_io: std.Io,
    gpa: std.mem.Allocator,
    user_path: ?[]const u8,
    project_path: ?[]const u8,
) !LoadOutcome {
    const user_id = observeLayer(runtime_io, user_path);
    const project_id = observeLayer(runtime_io, project_path);
    if (try MergedCache.copyIfHit(runtime_io, gpa, user_path, project_path, user_id, project_id)) |hit| {
        return hit;
    }
    const outcome = try loadMergedUncached(runtime_io, gpa, user_path, project_path);
    MergedCache.put(runtime_io, user_path, project_path, user_id, project_id, outcome);
    return outcome;
}

fn loadMergedUncached(
    runtime_io: std.Io,
    gpa: std.mem.Allocator,
    user_path: ?[]const u8,
    project_path: ?[]const u8,
) !LoadOutcome {
    var corrupt = false;
    var list: std.ArrayListUnmanaged(PermanentEntry) = .empty;
    errdefer {
        for (list.items) |e| freeEntry(gpa, e);
        list.deinit(gpa);
    }

    // Project wins: absorb user first, then project (override same key).
    if (user_path) |up| {
        try absorbLayer(runtime_io, gpa, up, .user, &list, &corrupt);
    }
    if (project_path) |pp| {
        try absorbLayer(runtime_io, gpa, pp, .project, &list, &corrupt);
    }

    if (list.items.len == 0) {
        list.deinit(gpa);
        return .{
            .store = .{ .entries = &.{}, .owned = false },
            .corrupt = corrupt,
        };
    }

    const entries = try list.toOwnedSlice(gpa);
    return .{
        .store = .{ .entries = entries, .owned = true },
        .corrupt = corrupt,
    };
}

fn absorbLayer(
    runtime_io: std.Io,
    gpa: std.mem.Allocator,
    path: []const u8,
    layer: Layer,
    list: *std.ArrayListUnmanaged(PermanentEntry),
    corrupt: *bool,
) !void {
    var outcome = try loadFile(runtime_io, gpa, path, layer);
    if (outcome.corrupt) corrupt.* = true;

    if (!outcome.store.owned) {
        // Empty missing/corrupt/static — nothing to merge.
        return;
    }

    // Steal entries from the layer store.
    const items = outcome.store.entries;
    outcome.store.entries = &.{};
    outcome.store.owned = false;
    defer gpa.free(items);

    // Index loop so OOM mid-merge frees the current entry + remaining unmerged items.
    var i: usize = 0;
    errdefer {
        while (i < items.len) : (i += 1) freeEntry(gpa, items[i]);
    }
    while (i < items.len) {
        const e = items[i];
        const key = entryKey(e);
        var replaced = false;
        for (list.items, 0..) |existing, idx| {
            if (std.mem.eql(u8, entryKey(existing), key)) {
                freeEntry(gpa, list.items[idx]);
                list.items[idx] = e;
                replaced = true;
                break;
            }
        }
        if (!replaced) {
            try list.append(gpa, e);
        }
        // Ownership transferred into list; advance past e so errdefer skips it.
        i += 1;
    }
}

pub const MutateError = error{
    /// File exists but is unreadable/invalid; refuse to wipe and rewrite.
    CorruptStore,
};

pub fn addEntry(
    runtime_io: std.Io,
    gpa: std.mem.Allocator,
    path: []const u8,
    layer: Layer,
    draft: Draft,
    known_rule_ids: ?[]const []const u8,
) !void {
    try validateDraft(draft, known_rule_ids);

    var lock = try StoreLock.acquire(runtime_io, gpa, path);
    defer lock.release(runtime_io);

    var outcome = try loadFile(runtime_io, gpa, path, layer);
    // Corrupt file: do not wipe prior content — refuse the mutation.
    if (outcome.corrupt) {
        outcome.store.deinit(gpa);
        return error.CorruptStore;
    }
    defer outcome.store.deinit(gpa);

    var list: std.ArrayListUnmanaged(PermanentEntry) = .empty;
    errdefer {
        for (list.items) |e| freeEntry(gpa, e);
        list.deinit(gpa);
    }

    // Clone existing entries into working list (clone-then-append: free clone if append OOMs).
    for (outcome.store.entries) |e| {
        const cloned = try cloneEntry(gpa, e);
        errdefer freeEntry(gpa, cloned);
        try list.append(gpa, cloned);
    }

    const new_entry = try draftToEntry(gpa, draft, layer);
    // Ownership transfers into `list` on successful replace/append. Disable this
    // errdefer after transfer so a later renderToml/writeFile failure does not
    // double-free (list's errdefer also frees every item).
    var entry_in_list = false;
    errdefer if (!entry_in_list) freeEntry(gpa, new_entry);
    const key = entryKey(new_entry);

    var replaced = false;
    for (list.items, 0..) |e, i| {
        if (std.mem.eql(u8, entryKey(e), key)) {
            freeEntry(gpa, list.items[i]);
            list.items[i] = new_entry;
            entry_in_list = true;
            replaced = true;
            break;
        }
    }
    if (!replaced) {
        try list.append(gpa, new_entry);
        entry_in_list = true;
    }

    const body = try renderToml(gpa, list.items);
    defer gpa.free(body);
    try writeFile(runtime_io, gpa, path, body);

    // Ownership transferred into file; free working list
    for (list.items) |e| freeEntry(gpa, e);
    list.deinit(gpa);
}

pub fn removeEntry(
    runtime_io: std.Io,
    gpa: std.mem.Allocator,
    path: []const u8,
    layer: Layer,
    key: []const u8,
) !bool {
    var lock = try StoreLock.acquire(runtime_io, gpa, path);
    defer lock.release(runtime_io);

    var outcome = try loadFile(runtime_io, gpa, path, layer);
    defer outcome.store.deinit(gpa);
    if (outcome.corrupt) {
        // Nothing trustworthy to remove; leave bytes untouched.
        return false;
    }

    var list: std.ArrayListUnmanaged(PermanentEntry) = .empty;
    errdefer {
        for (list.items) |e| freeEntry(gpa, e);
        list.deinit(gpa);
    }

    var removed = false;
    for (outcome.store.entries) |e| {
        if (!removed and std.mem.eql(u8, entryKey(e), key)) {
            removed = true;
            continue;
        }
        // Clone-then-append: free clone if append OOMs (list errdefer only covers items).
        const cloned = try cloneEntry(gpa, e);
        errdefer freeEntry(gpa, cloned);
        try list.append(gpa, cloned);
    }

    if (!removed) {
        for (list.items) |e| freeEntry(gpa, e);
        list.deinit(gpa);
        return false;
    }

    const body = try renderToml(gpa, list.items);
    defer gpa.free(body);
    try writeFile(runtime_io, gpa, path, body);

    for (list.items) |e| freeEntry(gpa, e);
    list.deinit(gpa);
    return true;
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

fn commandsMatch(stored: []const u8, query: []const u8) bool {
    if (std.mem.eql(u8, stored, query)) return true;
    const ts = std.mem.trim(u8, stored, " \t\r\n");
    const tq = std.mem.trim(u8, query, " \t\r\n");
    // Padded queries match canonical stored commands only.
    if (ts.len == stored.len and std.mem.eql(u8, ts, tq)) return true;
    return false;
}

fn freeEntry(gpa: std.mem.Allocator, e: PermanentEntry) void {
    if (e.id) |id| gpa.free(id);
    if (e.command) |c| gpa.free(c);
    gpa.free(e.reason);
    gpa.free(e.created_at);
    if (e.expires_at) |x| gpa.free(x);
}

fn cloneEntry(gpa: std.mem.Allocator, e: PermanentEntry) !PermanentEntry {
    const id = if (e.id) |v| try gpa.dupe(u8, v) else null;
    errdefer if (id) |v| gpa.free(v);
    const command = if (e.command) |v| try gpa.dupe(u8, v) else null;
    errdefer if (command) |v| gpa.free(v);
    const reason = try gpa.dupe(u8, e.reason);
    errdefer gpa.free(reason);
    const created_at = try gpa.dupe(u8, e.created_at);
    errdefer gpa.free(created_at);
    const expires_at = if (e.expires_at) |v| try gpa.dupe(u8, v) else null;
    return .{
        .kind = e.kind,
        .id = id,
        .command = command,
        .reason = reason,
        .created_at = created_at,
        .expires_at = expires_at,
        .layer = e.layer,
    };
}

fn draftToEntry(gpa: std.mem.Allocator, draft: Draft, layer: Layer) !PermanentEntry {
    const id = if (draft.id) |v| try gpa.dupe(u8, v) else null;
    errdefer if (id) |v| gpa.free(v);
    const command = if (draft.command) |v| try gpa.dupe(u8, v) else null;
    errdefer if (command) |v| gpa.free(v);
    const reason = try gpa.dupe(u8, draft.reason);
    errdefer gpa.free(reason);
    const created_at = try gpa.dupe(u8, draft.created_at);
    errdefer gpa.free(created_at);
    const expires_at = if (draft.expires_at) |v| try gpa.dupe(u8, v) else null;
    return .{
        .kind = draft.kind,
        .id = id,
        .command = command,
        .reason = reason,
        .created_at = created_at,
        .expires_at = expires_at,
        .layer = layer,
    };
}

/// Exclusive advisory lock for a store path (`{path}.lock`). Spans load-modify-write.
const StoreLock = struct {
    file: std.Io.File,

    fn acquire(runtime_io: std.Io, gpa: std.mem.Allocator, store_path: []const u8) !StoreLock {
        if (std.fs.path.dirname(store_path)) |dir| {
            std.Io.Dir.cwd().createDirPath(runtime_io, dir) catch |err| switch (err) {
                error.PathAlreadyExists => {},
                else => return err,
            };
        }
        const lock_path = try std.fmt.allocPrint(gpa, "{s}.lock", .{store_path});
        defer gpa.free(lock_path);
        const lock_file = try std.Io.Dir.cwd().createFile(runtime_io, lock_path, .{
            .read = true,
            .truncate = false,
        });
        errdefer lock_file.close(runtime_io);
        try lock_file.lock(runtime_io, .exclusive);
        return .{ .file = lock_file };
    }

    fn release(self: *StoreLock, runtime_io: std.Io) void {
        self.file.unlock(runtime_io);
        self.file.close(runtime_io);
        self.* = undefined;
    }
};

/// Atomic same-directory temp write + renameAbsolute; owner-only mode (0o600).
fn writeFile(runtime_io: std.Io, gpa: std.mem.Allocator, path: []const u8, body: []const u8) !void {
    if (std.fs.path.dirname(path)) |dir| {
        std.Io.Dir.cwd().createDirPath(runtime_io, dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
    }
    const perms: std.Io.File.Permissions = @enumFromInt(0o600);
    // Unique suffix so concurrent writers do not clobber each other's temps.
    var nonce: u64 = undefined;
    runtime_io.random(std.mem.asBytes(&nonce));
    const temp_path = try std.fmt.allocPrint(gpa, "{s}.tmp.{x}", .{ path, nonce });
    defer gpa.free(temp_path);

    // Cleanup begins only after exclusive creation succeeds. Otherwise a
    // PathAlreadyExists error could delete another writer's temp file.
    const file = try std.Io.Dir.cwd().createFile(runtime_io, temp_path, .{
        .exclusive = true,
        .permissions = perms,
    });
    errdefer std.Io.Dir.cwd().deleteFile(runtime_io, temp_path) catch {};
    {
        defer file.close(runtime_io);
        try file.writeStreamingAll(runtime_io, body);
        try file.sync(runtime_io);
    }
    try enforceOwnerOnlyWindows(gpa, temp_path);
    try std.Io.Dir.renameAbsolute(temp_path, path, runtime_io);
}

extern fn ryk_set_owner_only_acl(path: [*:0]const u16) callconv(.c) c_int;

fn enforceOwnerOnlyWindows(gpa: std.mem.Allocator, path: []const u8) !void {
    if (comptime builtin.os.tag != .windows) return;
    const wide_path = try std.unicode.utf8ToUtf16LeAllocZ(gpa, path);
    defer gpa.free(wide_path);
    if (ryk_set_owner_only_acl(wide_path.ptr) == 0) return error.WindowsAclFailed;
}

fn renderToml(gpa: std.mem.Allocator, entries: []const PermanentEntry) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(gpa);

    try buf.appendSlice(gpa, "schema_version = 1\n");
    for (entries) |e| {
        try buf.appendSlice(gpa, "\n[[entries]]\n");
        switch (e.kind) {
            .rule => {
                try buf.appendSlice(gpa, "kind = \"rule\"\n");
                try buf.appendSlice(gpa, "id = ");
                try appendTomlString(gpa, &buf, e.id orelse "");
                try buf.appendSlice(gpa, "\n");
            },
            .command => {
                try buf.appendSlice(gpa, "kind = \"command\"\n");
                try buf.appendSlice(gpa, "command = ");
                try appendTomlString(gpa, &buf, e.command orelse "");
                try buf.appendSlice(gpa, "\n");
            },
        }
        try buf.appendSlice(gpa, "reason = ");
        try appendTomlString(gpa, &buf, e.reason);
        try buf.appendSlice(gpa, "\n");
        try buf.appendSlice(gpa, "created_at = ");
        try appendTomlString(gpa, &buf, e.created_at);
        try buf.appendSlice(gpa, "\n");
        if (e.expires_at) |exp| {
            try buf.appendSlice(gpa, "expires_at = ");
            try appendTomlString(gpa, &buf, exp);
            try buf.appendSlice(gpa, "\n");
        }
        try buf.appendSlice(gpa, "scope = ");
        try appendTomlString(gpa, &buf, switch (e.layer) {
            .user => "user",
            .project => "project",
        });
        try buf.appendSlice(gpa, "\n");
    }
    return try buf.toOwnedSlice(gpa);
}

fn appendTomlString(gpa: std.mem.Allocator, buf: *std.ArrayListUnmanaged(u8), value: []const u8) !void {
    try buf.append(gpa, '"');
    for (value) |c| {
        switch (c) {
            '"', '\\' => {
                try buf.append(gpa, '\\');
                try buf.append(gpa, c);
            },
            '\n' => try buf.appendSlice(gpa, "\\n"),
            '\r' => try buf.appendSlice(gpa, "\\r"),
            '\t' => try buf.appendSlice(gpa, "\\t"),
            else => try buf.append(gpa, c),
        }
    }
    try buf.append(gpa, '"');
}

const ParseError = error{
    Corrupt,
    OutOfMemory,
};

var testing_parse_toml_count: u32 = 0;
var testing_merged_cache_hits: u32 = 0;

/// Test-only counters for the in-process loadMerged cache. Product builds
/// see an empty namespace so the symbols cannot be used as a side channel.
pub const cache_test = if (builtin.is_test) struct {
    pub fn reset(runtime_io: std.Io) void {
        testing_parse_toml_count = 0;
        testing_merged_cache_hits = 0;
        MergedCache.clear(runtime_io);
    }

    pub fn parseTomlCount() u32 {
        return testing_parse_toml_count;
    }

    pub fn mergedCacheHits() u32 {
        return testing_merged_cache_hits;
    }
} else struct {};

fn parseToml(gpa: std.mem.Allocator, raw: []const u8, layer: Layer) ParseError!Store {
    if (builtin.is_test) testing_parse_toml_count += 1;
    var list: std.ArrayListUnmanaged(PermanentEntry) = .empty;
    errdefer {
        for (list.items) |e| freeEntry(gpa, e);
        list.deinit(gpa);
    }

    var current: ?Partial = null;
    errdefer if (current) |p| freePartial(gpa, p);

    var lines = std.mem.splitScalar(u8, raw, '\n');
    while (lines.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;

        if (std.mem.eql(u8, line, "[[entries]]")) {
            if (current) |p| {
                // partialToEntry owns entry strings; free entry if append OOMs.
                const entry = try partialToEntry(gpa, p, layer);
                errdefer freeEntry(gpa, entry);
                freePartial(gpa, p);
                current = null;
                try list.append(gpa, entry);
            }
            current = Partial{};
            continue;
        }

        if (std.mem.startsWith(u8, line, "[[")) {
            // Unknown array-of-tables → corrupt
            return error.Corrupt;
        }

        // section headers other than [[entries]] are ignored if not nested oddly
        if (line[0] == '[') continue;

        const eq = std.mem.indexOfScalar(u8, line, '=') orelse return error.Corrupt;
        const key = std.mem.trim(u8, line[0..eq], " \t");
        const val_raw = std.mem.trim(u8, line[eq + 1 ..], " \t");

        if (std.mem.eql(u8, key, "schema_version")) {
            // accept any integer; unknown future versions still load entries we understand
            continue;
        }

        if (current == null) {
            // keys outside entries tables: only schema_version expected
            continue;
        }

        const value = try parseTomlValue(gpa, val_raw);
        errdefer gpa.free(value);

        var p = current.?;
        if (std.mem.eql(u8, key, "kind")) {
            if (p.kind_raw) |old| gpa.free(old);
            p.kind_raw = value;
        } else if (std.mem.eql(u8, key, "id")) {
            if (p.id) |old| gpa.free(old);
            p.id = value;
        } else if (std.mem.eql(u8, key, "command")) {
            if (p.command) |old| gpa.free(old);
            p.command = value;
        } else if (std.mem.eql(u8, key, "reason")) {
            if (p.reason) |old| gpa.free(old);
            p.reason = value;
        } else if (std.mem.eql(u8, key, "created_at")) {
            if (p.created_at) |old| gpa.free(old);
            p.created_at = value;
        } else if (std.mem.eql(u8, key, "expires_at")) {
            if (p.expires_at) |old| gpa.free(old);
            p.expires_at = value;
        } else if (std.mem.eql(u8, key, "scope")) {
            // informational; layer comes from file path
            gpa.free(value);
        } else {
            // unknown key: ignore value
            gpa.free(value);
        }
        current = p;
    }

    if (current) |p| {
        const entry = try partialToEntry(gpa, p, layer);
        errdefer freeEntry(gpa, entry);
        freePartial(gpa, p);
        current = null;
        try list.append(gpa, entry);
    }

    // Detect pure garbage: no schema_version line and no entries.
    if (list.items.len == 0) {
        // If the file has non-comment content that isn't schema_version / known keys only,
        // consider corrupt. Simple heuristic: must contain "schema_version" or "[[entries]]"
        // OR be only whitespace/comments (already handled as empty before parse).
        const has_schema = std.mem.indexOf(u8, raw, "schema_version") != null;
        const has_entries = std.mem.indexOf(u8, raw, "[[entries]]") != null;
        if (!has_schema and !has_entries) return error.Corrupt;
    }

    const entries = try list.toOwnedSlice(gpa);
    return .{ .entries = entries, .owned = true };
}

const Partial = struct {
    kind_raw: ?[]u8 = null,
    id: ?[]u8 = null,
    command: ?[]u8 = null,
    reason: ?[]u8 = null,
    created_at: ?[]u8 = null,
    expires_at: ?[]u8 = null,
};

fn freePartial(gpa: std.mem.Allocator, p: Partial) void {
    if (p.kind_raw) |v| gpa.free(v);
    if (p.id) |v| gpa.free(v);
    if (p.command) |v| gpa.free(v);
    if (p.reason) |v| gpa.free(v);
    if (p.created_at) |v| gpa.free(v);
    if (p.expires_at) |v| gpa.free(v);
}

fn partialToEntry(gpa: std.mem.Allocator, p: Partial, layer: Layer) ParseError!PermanentEntry {
    const kind_raw = p.kind_raw orelse return error.Corrupt;
    const kind: EntryKind = if (std.mem.eql(u8, kind_raw, "rule"))
        .rule
    else if (std.mem.eql(u8, kind_raw, "command"))
        .command
    else
        return error.Corrupt;

    const reason = p.reason orelse return error.Corrupt;
    const created_at = p.created_at orelse return error.Corrupt;

    // Transfer ownership from partial fields into entry.
    // Caller freePartial must not double-free transferred fields — we dupe then caller frees partial.
    // Simpler: dupe all into entry; caller always freePartial.
    const reason_owned = try gpa.dupe(u8, reason);
    errdefer gpa.free(reason_owned);
    const created_owned = try gpa.dupe(u8, created_at);
    errdefer gpa.free(created_owned);
    const expires_owned = if (p.expires_at) |v| try gpa.dupe(u8, v) else null;
    errdefer if (expires_owned) |v| gpa.free(v);

    switch (kind) {
        .rule => {
            const id = p.id orelse return error.Corrupt;
            if (id.len == 0) return error.Corrupt;
            const id_owned = try gpa.dupe(u8, id);
            return .{
                .kind = .rule,
                .id = id_owned,
                .command = null,
                .reason = reason_owned,
                .created_at = created_owned,
                .expires_at = expires_owned,
                .layer = layer,
            };
        },
        .command => {
            const cmd = p.command orelse return error.Corrupt;
            if (cmd.len == 0) return error.Corrupt;
            const cmd_owned = try gpa.dupe(u8, cmd);
            return .{
                .kind = .command,
                .id = null,
                .command = cmd_owned,
                .reason = reason_owned,
                .created_at = created_owned,
                .expires_at = expires_owned,
                .layer = layer,
            };
        },
    }
}

fn parseTomlValue(gpa: std.mem.Allocator, raw: []const u8) ParseError![]u8 {
    if (raw.len >= 2 and raw[0] == '"' and raw[raw.len - 1] == '"') {
        return try unescapeTomlString(gpa, raw[1 .. raw.len - 1]);
    }
    // bare integer / bool / unquoted — accept as raw text for schema_version path;
    // for string fields we require quotes; unquoted is still returned for flexibility.
    if (raw.len == 0) return error.Corrupt;
    return try gpa.dupe(u8, raw);
}

fn unescapeTomlString(gpa: std.mem.Allocator, body: []const u8) ParseError![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(gpa);
    var i: usize = 0;
    while (i < body.len) : (i += 1) {
        if (body[i] == '\\') {
            i += 1;
            if (i >= body.len) return error.Corrupt;
            switch (body[i]) {
                '"', '\\' => try buf.append(gpa, body[i]),
                'n' => try buf.append(gpa, '\n'),
                'r' => try buf.append(gpa, '\r'),
                't' => try buf.append(gpa, '\t'),
                else => return error.Corrupt,
            }
        } else {
            try buf.append(gpa, body[i]);
        }
    }
    return try buf.toOwnedSlice(gpa);
}

// ---------------------------------------------------------------------------
// Tests — locked contract (do not edit in implementor unit)
// ---------------------------------------------------------------------------

const testing = std.testing;
const allocator = testing.allocator;
const io = testing.io;

const far_future = "9999-01-01T00:00:00Z";
const fixed_now = "2026-07-25T15:00:00Z";

fn writeFileAbsolute(path: []const u8, body: []const u8) !void {
    if (std.fs.path.dirname(path)) |dir| {
        std.Io.Dir.cwd().createDirPath(io, dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
    }
    var file = try std.Io.Dir.cwd().createFile(io, path, .{});
    defer file.close(io);
    try file.writeStreamingAll(io, body);
}

fn readFileAbsolute(path: []const u8) ![]u8 {
    return try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(1024 * 1024));
}

fn joinPath(tmp_root: []const u8, rel: []const u8) ![]u8 {
    return try std.fs.path.join(allocator, &.{ tmp_root, rel });
}

fn tmpRoot() !struct { dir: std.testing.TmpDir, path: []u8 } {
    var tmp = testing.tmpDir(.{});
    errdefer tmp.cleanup();
    // realPathFileAlloc returns [:0]u8 (dupeZ). Tests free with allocator.free([]u8),
    // which drops the sentinel byte and trips DebugAllocator. Re-dupe to a plain slice.
    const path_z = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path_z);
    const path = try allocator.dupe(u8, path_z);
    return .{ .dir = tmp, .path = path };
}

// ── Acceptance 1: TOML round-trip, project override, expired, corrupt ────────

test "s2-store: TOML round-trip add list remove rule entry" {
    var tmp = try tmpRoot();
    defer {
        allocator.free(tmp.path);
        tmp.dir.cleanup();
    }
    const path = try joinPath(tmp.path, "allowlist.toml");
    defer allocator.free(path);

    const draft = Draft{
        .kind = .rule,
        .id = "core.git:reset-hard",
        .reason = "recovering local branch after failed rebase",
        .created_at = "2026-07-25T12:00:00Z",
    };
    try addEntry(io, allocator, path, .project, draft, null);

    {
        var loaded = try loadFile(io, allocator, path, .project);
        defer loaded.store.deinit(allocator);
        try testing.expect(!loaded.corrupt);
        try testing.expectEqual(@as(usize, 1), loaded.store.entries.len);
        const e = loaded.store.entries[0];
        try testing.expect(e.kind == .rule);
        try testing.expectEqualStrings("core.git:reset-hard", e.id.?);
        try testing.expectEqualStrings(draft.reason, e.reason);
        try testing.expect(e.layer == .project);
        try testing.expect(e.command == null);
    }

    // Raw TOML shape (schema + array of tables).
    {
        const raw = try readFileAbsolute(path);
        defer allocator.free(raw);
        try testing.expect(std.mem.indexOf(u8, raw, "schema_version") != null);
        try testing.expect(std.mem.indexOf(u8, raw, "[[entries]]") != null);
        try testing.expect(std.mem.indexOf(u8, raw, "core.git:reset-hard") != null);
        try testing.expect(std.mem.indexOf(u8, raw, "kind") != null);
    }

    const removed = try removeEntry(io, allocator, path, .project, "core.git:reset-hard");
    try testing.expect(removed);

    {
        var loaded = try loadFile(io, allocator, path, .project);
        defer loaded.store.deinit(allocator);
        try testing.expect(!loaded.corrupt);
        try testing.expectEqual(@as(usize, 0), loaded.store.entries.len);
    }
}

test "s2-store: TOML round-trip add list remove command entry" {
    var tmp = try tmpRoot();
    defer {
        allocator.free(tmp.path);
        tmp.dir.cleanup();
    }
    const path = try joinPath(tmp.path, "allowlist.toml");
    defer allocator.free(path);

    const draft = Draft{
        .kind = .command,
        .command = "git status",
        .reason = "status is always safe in this workflow",
        .created_at = "2026-07-25T12:00:00Z",
    };
    try addEntry(io, allocator, path, .user, draft, null);

    {
        var loaded = try loadFile(io, allocator, path, .user);
        defer loaded.store.deinit(allocator);
        try testing.expectEqual(@as(usize, 1), loaded.store.entries.len);
        const e = loaded.store.entries[0];
        try testing.expect(e.kind == .command);
        try testing.expectEqualStrings("git status", e.command.?);
        try testing.expect(e.id == null);
        try testing.expect(e.layer == .user);
    }

    const removed = try removeEntry(io, allocator, path, .user, "git status");
    try testing.expect(removed);

    {
        var loaded = try loadFile(io, allocator, path, .user);
        defer loaded.store.deinit(allocator);
        try testing.expectEqual(@as(usize, 0), loaded.store.entries.len);
    }
}

test "s2-store: project overrides user on same key" {
    var tmp = try tmpRoot();
    defer {
        allocator.free(tmp.path);
        tmp.dir.cleanup();
    }
    const user_path = try joinPath(tmp.path, "user-allowlist.toml");
    defer allocator.free(user_path);
    const project_path = try joinPath(tmp.path, "project-allowlist.toml");
    defer allocator.free(project_path);

    try addEntry(io, allocator, user_path, .user, .{
        .kind = .rule,
        .id = "core.git:reset-hard",
        .reason = "user layer reason for reset-hard",
        .created_at = "2026-07-25T10:00:00Z",
    }, null);
    try addEntry(io, allocator, project_path, .project, .{
        .kind = .rule,
        .id = "core.git:reset-hard",
        .reason = "project layer reason wins",
        .created_at = "2026-07-25T11:00:00Z",
    }, null);
    // Different key on user only — must survive merge.
    try addEntry(io, allocator, user_path, .user, .{
        .kind = .command,
        .command = "git status",
        .reason = "user-only exact command",
        .created_at = "2026-07-25T10:00:00Z",
    }, null);

    var merged = try loadMerged(io, allocator, user_path, project_path);
    defer merged.store.deinit(allocator);
    try testing.expect(!merged.corrupt);

    const hit = merged.store.matchRule("core.git:reset-hard", far_future);
    try testing.expect(hit != null);
    try testing.expect(hit.?.layer == .project);
    try testing.expectEqualStrings("project layer reason wins", hit.?.reason);

    const cmd_hit = merged.store.matchCommand("git status", far_future);
    try testing.expect(cmd_hit != null);
    try testing.expect(cmd_hit.?.layer == .user);

    // Exactly two active keys after override (not three).
    try testing.expectEqual(@as(usize, 2), merged.store.entries.len);
}

test "s2-store: project overrides user on same exact command key" {
    var tmp = try tmpRoot();
    defer {
        allocator.free(tmp.path);
        tmp.dir.cleanup();
    }
    const user_path = try joinPath(tmp.path, "user.toml");
    defer allocator.free(user_path);
    const project_path = try joinPath(tmp.path, "project.toml");
    defer allocator.free(project_path);

    try addEntry(io, allocator, user_path, .user, .{
        .kind = .command,
        .command = "npm test",
        .reason = "user reason for npm test",
        .created_at = "2026-07-25T10:00:00Z",
    }, null);
    try addEntry(io, allocator, project_path, .project, .{
        .kind = .command,
        .command = "npm test",
        .reason = "project reason for npm test",
        .created_at = "2026-07-25T11:00:00Z",
    }, null);

    var merged = try loadMerged(io, allocator, user_path, project_path);
    defer merged.store.deinit(allocator);

    const hit = merged.store.matchCommand("npm test", far_future);
    try testing.expect(hit != null);
    try testing.expect(hit.?.layer == .project);
    try testing.expectEqualStrings("project reason for npm test", hit.?.reason);
    try testing.expectEqual(@as(usize, 1), merged.store.entries.len);
}

test "s2-store: expired entries ignored on match" {
    var tmp = try tmpRoot();
    defer {
        allocator.free(tmp.path);
        tmp.dir.cleanup();
    }
    const path = try joinPath(tmp.path, "allowlist.toml");
    defer allocator.free(path);

    try addEntry(io, allocator, path, .user, .{
        .kind = .command,
        .command = "git reset --hard HEAD",
        .reason = "temporary exception that already expired",
        .created_at = "2026-07-24T12:00:00Z",
        .expires_at = "2026-07-25T00:00:00Z", // before fixed_now
    }, null);
    try addEntry(io, allocator, path, .user, .{
        .kind = .rule,
        .id = "core.git:reset-hard",
        .reason = "still valid rule exception",
        .created_at = "2026-07-24T12:00:00Z",
        .expires_at = "2026-07-26T00:00:00Z", // after fixed_now
    }, null);

    var loaded = try loadFile(io, allocator, path, .user);
    defer loaded.store.deinit(allocator);

    // Listing retains expired entries; expiry only filters match paths.
    try testing.expectEqual(@as(usize, 2), loaded.store.entries.len);

    // Expired command must not match at fixed_now (expires_at <= fixed_now).
    try testing.expect(loaded.store.matchCommand("git reset --hard HEAD", fixed_now) == null);
    try testing.expect(isExpired(loaded.store.entries[0], fixed_now) or isExpired(loaded.store.entries[1], fixed_now));

    // Non-expired rule still matches at fixed_now.
    const rule_hit = loaded.store.matchRule("core.git:reset-hard", fixed_now);
    try testing.expect(rule_hit != null);
    try testing.expectEqualStrings("still valid rule exception", rule_hit.?.reason);

    // Pre-expiry now: command entry is still active (expires_at after pre_expiry).
    // (far_future would expire everything with a finite expires_at under isExpired.)
    const pre_expiry = "2026-07-24T12:00:00Z";
    try testing.expect(loaded.store.matchCommand("git reset --hard HEAD", pre_expiry) != null);
    try testing.expect(loaded.store.matchRule("core.git:reset-hard", pre_expiry) != null);

    // At/after the rule's expires_at, matchRule also filters it out.
    try testing.expect(loaded.store.matchRule("core.git:reset-hard", "2026-07-26T00:00:00Z") == null);
}

test "s2-store: missing allowlist file loads as empty not error" {
    var tmp = try tmpRoot();
    defer {
        allocator.free(tmp.path);
        tmp.dir.cleanup();
    }
    const path = try joinPath(tmp.path, "does-not-exist.toml");
    defer allocator.free(path);

    var loaded = try loadFile(io, allocator, path, .user);
    defer loaded.store.deinit(allocator);
    try testing.expect(!loaded.corrupt);
    try testing.expectEqual(@as(usize, 0), loaded.store.entries.len);

    var merged = try loadMerged(io, allocator, path, null);
    defer merged.store.deinit(allocator);
    try testing.expectEqual(@as(usize, 0), merged.store.entries.len);
}

test "s2-store: corrupt file treated as empty without panic" {
    var tmp = try tmpRoot();
    defer {
        allocator.free(tmp.path);
        tmp.dir.cleanup();
    }
    const path = try joinPath(tmp.path, "corrupt.toml");
    defer allocator.free(path);

    // Garbage / truncated TOML — must not panic or allow-all.
    try writeFileAbsolute(path, "this is not { valid toml [[[\nentries = ???\n");

    var loaded = try loadFile(io, allocator, path, .project);
    defer loaded.store.deinit(allocator);
    try testing.expect(loaded.corrupt);
    try testing.expectEqual(@as(usize, 0), loaded.store.entries.len);
    try testing.expect(loaded.store.matchCommand("rm -rf /", far_future) == null);
    try testing.expect(loaded.store.matchRule("core.filesystem:rm-rf-root-home", far_future) == null);

    // Merge with one corrupt layer + one good layer still yields good entries only.
    const good_path = try joinPath(tmp.path, "good.toml");
    defer allocator.free(good_path);
    try addEntry(io, allocator, good_path, .user, .{
        .kind = .command,
        .command = "echo ok",
        .reason = "harmless echo for merge smoke",
        .created_at = "2026-07-25T12:00:00Z",
    }, null);

    var merged = try loadMerged(io, allocator, good_path, path);
    defer merged.store.deinit(allocator);
    // corrupt flag may be true because project layer was corrupt; entries from good layer remain.
    try testing.expect(merged.store.matchCommand("echo ok", far_future) != null);
    try testing.expectEqual(@as(usize, 1), merged.store.entries.len);
}

test "s2-store: addEntry on multi-entry corrupt file fails without wipe" {
    var tmp = try tmpRoot();
    defer {
        allocator.free(tmp.path);
        tmp.dir.cleanup();
    }
    const path = try joinPath(tmp.path, "allowlist.toml");
    defer allocator.free(path);

    // Seed two durable entries, then poison the on-disk TOML so loadFile marks corrupt.
    try addEntry(io, allocator, path, .project, .{
        .kind = .rule,
        .id = "core.git:reset-hard",
        .reason = "first durable exception",
        .created_at = "2026-07-25T12:00:00Z",
    }, null);
    try addEntry(io, allocator, path, .project, .{
        .kind = .command,
        .command = "git status",
        .reason = "second durable exception",
        .created_at = "2026-07-25T12:30:00Z",
    }, null);

    const good = try readFileAbsolute(path);
    defer allocator.free(good);
    try testing.expect(std.mem.indexOf(u8, good, "core.git:reset-hard") != null);
    try testing.expect(std.mem.indexOf(u8, good, "git status") != null);

    // Unknown array-of-tables trips parseToml Corrupt while leaving prior entry text present.
    const poisoned = try std.fmt.allocPrint(allocator, "{s}\n[[not-entries]]\nkind = \"garbage\"\n", .{good});
    defer allocator.free(poisoned);
    try writeFileAbsolute(path, poisoned);

    {
        var loaded = try loadFile(io, allocator, path, .project);
        defer loaded.store.deinit(allocator);
        try testing.expect(loaded.corrupt);
        try testing.expectEqual(@as(usize, 0), loaded.store.entries.len);
    }

    try testing.expectError(error.CorruptStore, addEntry(io, allocator, path, .project, .{
        .kind = .rule,
        .id = "core.git:push-force-long",
        .reason = "must not replace multi-entry corrupt store",
        .created_at = "2026-07-25T16:00:00Z",
    }, null));

    // Bytes must be unchanged — no silent wipe to empty+new.
    const after = try readFileAbsolute(path);
    defer allocator.free(after);
    try testing.expectEqualStrings(poisoned, after);
    try testing.expect(std.mem.indexOf(u8, after, "core.git:reset-hard") != null);
    try testing.expect(std.mem.indexOf(u8, after, "git status") != null);
    try testing.expect(std.mem.indexOf(u8, after, "push-force-long") == null);

    // removeEntry stays careful: false, no rewrite.
    try testing.expect(!(try removeEntry(io, allocator, path, .project, "core.git:reset-hard")));
    const after_remove = try readFileAbsolute(path);
    defer allocator.free(after_remove);
    try testing.expectEqualStrings(poisoned, after_remove);
}

// ── Acceptance 2: kind=command exact-only (no prefix on permanent path) ──────

test "s2-store: kind=command is exact-only no prefix match" {
    var tmp = try tmpRoot();
    defer {
        allocator.free(tmp.path);
        tmp.dir.cleanup();
    }
    const path = try joinPath(tmp.path, "allowlist.toml");
    defer allocator.free(path);

    try addEntry(io, allocator, path, .user, .{
        .kind = .command,
        .command = "npm run ",
        .reason = "prefix-looking command string must still be exact",
        .created_at = "2026-07-25T12:00:00Z",
    }, null);

    var loaded = try loadFile(io, allocator, path, .user);
    defer loaded.store.deinit(allocator);

    // Exact match of the stored full command string only.
    try testing.expect(loaded.store.matchCommand("npm run ", far_future) != null);

    // Prefix-style candidates must NOT match (policy Layered would; permanent must not).
    try testing.expect(loaded.store.matchCommand("npm run test", far_future) == null);
    try testing.expect(loaded.store.matchCommand("npm run build", far_future) == null);
    try testing.expect(loaded.store.matchCommand("npm run", far_future) == null);
}

test "s2-store: kind=command trims whitespace for exact match" {
    var tmp = try tmpRoot();
    defer {
        allocator.free(tmp.path);
        tmp.dir.cleanup();
    }
    const path = try joinPath(tmp.path, "allowlist.toml");
    defer allocator.free(path);

    try addEntry(io, allocator, path, .user, .{
        .kind = .command,
        .command = "git status",
        .reason = "status exception with trim semantics",
        .created_at = "2026-07-25T12:00:00Z",
    }, null);

    var loaded = try loadFile(io, allocator, path, .user);
    defer loaded.store.deinit(allocator);

    try testing.expect(loaded.store.matchCommand("git status", far_future) != null);
    try testing.expect(loaded.store.matchCommand("  git status  \n", far_future) != null);
    try testing.expect(loaded.store.matchCommand("git status --short", far_future) == null);
}

test "s2-store: permanent entries have no prefix field and are not Layered" {
    // Structural guard: PermanentEntry must not expose policy-style prefix.
    const draft = Draft{
        .kind = .command,
        .command = "true",
        .reason = "structure guard entry reason text",
        .created_at = "2026-07-25T12:00:00Z",
    };
    try validateDraft(draft, null);

    // Type-level: PermanentEntry fields used by product path.
    const e = PermanentEntry{
        .kind = .command,
        .command = "true",
        .reason = "structure guard entry reason text",
        .created_at = "2026-07-25T12:00:00Z",
        .layer = .user,
    };
    try testing.expect(e.kind == .command);
    try testing.expectEqualStrings("true", e.command.?);
    // No `.prefix` — if someone adds it for permanent entries, product tests must stay exact-only.
    try testing.expectEqualStrings("true", entryKey(e));
}

// ── Acceptance 3: kind=rule form validation + reason required ────────────────

test "s2-store: isValidRuleIdForm accepts pack:pattern shape" {
    try testing.expect(isValidRuleIdForm("core.git:reset-hard"));
    try testing.expect(isValidRuleIdForm("core.filesystem:rm-rf-root-home"));
    try testing.expect(isValidRuleIdForm("system.disk:mkfs"));
    try testing.expect(isValidRuleIdForm("a:b"));

    try testing.expect(!isValidRuleIdForm(""));
    try testing.expect(!isValidRuleIdForm("nocolon"));
    try testing.expect(!isValidRuleIdForm(":reset-hard"));
    try testing.expect(!isValidRuleIdForm("core.git:"));
    try testing.expect(!isValidRuleIdForm("  :  "));
}

test "s2-store: validateDraft requires reason for all kinds" {
    const no_reason_rule = Draft{
        .kind = .rule,
        .id = "core.git:reset-hard",
        .reason = "",
        .created_at = "2026-07-25T12:00:00Z",
    };
    try testing.expectError(error.ReasonRequired, validateDraft(no_reason_rule, null));

    const no_reason_cmd = Draft{
        .kind = .command,
        .command = "git status",
        .reason = "",
        .created_at = "2026-07-25T12:00:00Z",
    };
    try testing.expectError(error.ReasonRequired, validateDraft(no_reason_cmd, null));

    // Whitespace-only reason is also insufficient.
    const ws_reason = Draft{
        .kind = .command,
        .command = "git status",
        .reason = "   \t",
        .created_at = "2026-07-25T12:00:00Z",
    };
    try testing.expectError(error.ReasonRequired, validateDraft(ws_reason, null));
}

test "s2-store: validateDraft kind=rule requires id and valid form" {
    try testing.expectError(error.RuleIdRequired, validateDraft(.{
        .kind = .rule,
        .id = null,
        .reason = "needs a rule id field",
        .created_at = "2026-07-25T12:00:00Z",
    }, null));

    try testing.expectError(error.RuleIdRequired, validateDraft(.{
        .kind = .rule,
        .id = "",
        .reason = "empty rule id is rejected",
        .created_at = "2026-07-25T12:00:00Z",
    }, null));

    try testing.expectError(error.InvalidRuleIdForm, validateDraft(.{
        .kind = .rule,
        .id = "not-a-valid-rule",
        .reason = "malformed rule id rejected",
        .created_at = "2026-07-25T12:00:00Z",
    }, null));

    // Valid form without known-set → ok.
    try validateDraft(.{
        .kind = .rule,
        .id = "core.git:reset-hard",
        .reason = "valid form without known-set",
        .created_at = "2026-07-25T12:00:00Z",
    }, null);
}

test "s2-store: validateDraft kind=rule checks known pack:pattern when provided" {
    const known = [_][]const u8{
        "core.git:reset-hard",
        "core.filesystem:rm-rf-root-home",
    };

    try validateDraft(.{
        .kind = .rule,
        .id = "core.git:reset-hard",
        .reason = "known rule accepted",
        .created_at = "2026-07-25T12:00:00Z",
    }, known[0..]);

    try testing.expectError(error.UnknownRuleId, validateDraft(.{
        .kind = .rule,
        .id = "core.git:not-a-real-pattern",
        .reason = "unknown rule rejected against known set",
        .created_at = "2026-07-25T12:00:00Z",
    }, known[0..]));
}

test "s2-store: validateDraft kind=command requires non-empty exact command" {
    try testing.expectError(error.CommandRequired, validateDraft(.{
        .kind = .command,
        .command = null,
        .reason = "command kind needs a command",
        .created_at = "2026-07-25T12:00:00Z",
    }, null));

    try testing.expectError(error.CommandRequired, validateDraft(.{
        .kind = .command,
        .command = "",
        .reason = "empty command rejected",
        .created_at = "2026-07-25T12:00:00Z",
    }, null));

    try testing.expectError(error.CommandRequired, validateDraft(.{
        .kind = .command,
        .command = "   ",
        .reason = "whitespace command rejected",
        .created_at = "2026-07-25T12:00:00Z",
    }, null));

    try validateDraft(.{
        .kind = .command,
        .command = "git status",
        .reason = "valid command draft",
        .created_at = "2026-07-25T12:00:00Z",
    }, null);
}

test "s2-store: addEntry rejects invalid drafts and does not write" {
    var tmp = try tmpRoot();
    defer {
        allocator.free(tmp.path);
        tmp.dir.cleanup();
    }
    const path = try joinPath(tmp.path, "allowlist.toml");
    defer allocator.free(path);

    const known = [_][]const u8{"core.git:reset-hard"};

    try testing.expectError(error.UnknownRuleId, addEntry(io, allocator, path, .user, .{
        .kind = .rule,
        .id = "core.git:fake-pattern",
        .reason = "should not be persisted",
        .created_at = "2026-07-25T12:00:00Z",
    }, known[0..]));

    try testing.expectError(error.ReasonRequired, addEntry(io, allocator, path, .user, .{
        .kind = .command,
        .command = "git status",
        .reason = "",
        .created_at = "2026-07-25T12:00:00Z",
    }, null));

    // File may be absent or empty — no accepted entries.
    var loaded = try loadFile(io, allocator, path, .user);
    defer loaded.store.deinit(allocator);
    try testing.expectEqual(@as(usize, 0), loaded.store.entries.len);
}

// ── Match helpers / keys (branch coverage for store surface) ─────────────────

test "s2-store: matchRule is exact rule-id equality" {
    var tmp = try tmpRoot();
    defer {
        allocator.free(tmp.path);
        tmp.dir.cleanup();
    }
    const path = try joinPath(tmp.path, "allowlist.toml");
    defer allocator.free(path);

    try addEntry(io, allocator, path, .project, .{
        .kind = .rule,
        .id = "core.git:reset-hard",
        .reason = "E8 skip only this rule id",
        .created_at = "2026-07-25T12:00:00Z",
    }, null);

    var loaded = try loadFile(io, allocator, path, .project);
    defer loaded.store.deinit(allocator);

    try testing.expect(loaded.store.matchRule("core.git:reset-hard", far_future) != null);
    try testing.expect(loaded.store.matchRule("core.git:push-force-long", far_future) == null);
    try testing.expect(loaded.store.matchRule("core.git", far_future) == null);
    // Command matchers do not fire for rule entries.
    try testing.expect(loaded.store.matchCommand("git reset --hard HEAD", far_future) == null);
}

test "s2-store: entryKey is rule id or exact command" {
    const rule_e = PermanentEntry{
        .kind = .rule,
        .id = "core.git:reset-hard",
        .reason = "key for rule",
        .created_at = "2026-07-25T12:00:00Z",
        .layer = .user,
    };
    try testing.expectEqualStrings("core.git:reset-hard", entryKey(rule_e));

    const cmd_e = PermanentEntry{
        .kind = .command,
        .command = "git status",
        .reason = "key for command",
        .created_at = "2026-07-25T12:00:00Z",
        .layer = .project,
    };
    try testing.expectEqualStrings("git status", entryKey(cmd_e));
}

test "s2-store: removeEntry returns false when key missing" {
    var tmp = try tmpRoot();
    defer {
        allocator.free(tmp.path);
        tmp.dir.cleanup();
    }
    const path = try joinPath(tmp.path, "allowlist.toml");
    defer allocator.free(path);

    try addEntry(io, allocator, path, .user, .{
        .kind = .rule,
        .id = "core.git:reset-hard",
        .reason = "present entry",
        .created_at = "2026-07-25T12:00:00Z",
    }, null);

    const missing = try removeEntry(io, allocator, path, .user, "core.filesystem:rm-rf-root-home");
    try testing.expect(!missing);

    var loaded = try loadFile(io, allocator, path, .user);
    defer loaded.store.deinit(allocator);
    try testing.expectEqual(@as(usize, 1), loaded.store.entries.len);
}

test "s2-store: removeEntry preserves sibling entries in multi-entry file" {
    // Guards wipe-on-remove: remove by key must not truncate the whole file.
    var tmp = try tmpRoot();
    defer {
        allocator.free(tmp.path);
        tmp.dir.cleanup();
    }
    const path = try joinPath(tmp.path, "allowlist.toml");
    defer allocator.free(path);

    try addEntry(io, allocator, path, .project, .{
        .kind = .rule,
        .id = "core.git:reset-hard",
        .reason = "rule A to be removed",
        .created_at = "2026-07-25T12:00:00Z",
    }, null);
    try addEntry(io, allocator, path, .project, .{
        .kind = .command,
        .command = "git status",
        .reason = "command B must survive remove of A",
        .created_at = "2026-07-25T12:30:00Z",
    }, null);

    {
        var before = try loadFile(io, allocator, path, .project);
        defer before.store.deinit(allocator);
        try testing.expectEqual(@as(usize, 2), before.store.entries.len);
    }

    const removed = try removeEntry(io, allocator, path, .project, "core.git:reset-hard");
    try testing.expect(removed);

    {
        var after = try loadFile(io, allocator, path, .project);
        defer after.store.deinit(allocator);
        try testing.expect(!after.corrupt);
        try testing.expectEqual(@as(usize, 1), after.store.entries.len);
        const e = after.store.entries[0];
        try testing.expect(e.kind == .command);
        try testing.expectEqualStrings("git status", e.command.?);
        try testing.expectEqualStrings("command B must survive remove of A", e.reason);
        try testing.expect(e.layer == .project);
        // Removed key must not match; sibling still matches.
        try testing.expect(after.store.matchRule("core.git:reset-hard", far_future) == null);
        try testing.expect(after.store.matchCommand("git status", far_future) != null);
    }

    // Raw TOML keeps B's key, not A's.
    {
        const raw = try readFileAbsolute(path);
        defer allocator.free(raw);
        try testing.expect(std.mem.indexOf(u8, raw, "git status") != null);
        try testing.expect(std.mem.indexOf(u8, raw, "command B must survive remove of A") != null);
        try testing.expect(std.mem.indexOf(u8, raw, "core.git:reset-hard") == null);
        try testing.expect(std.mem.indexOf(u8, raw, "rule A to be removed") == null);
    }
}

test "s2-store: addEntry overwrites same key in file" {
    var tmp = try tmpRoot();
    defer {
        allocator.free(tmp.path);
        tmp.dir.cleanup();
    }
    const path = try joinPath(tmp.path, "allowlist.toml");
    defer allocator.free(path);

    try addEntry(io, allocator, path, .user, .{
        .kind = .rule,
        .id = "core.git:reset-hard",
        .reason = "first reason text here",
        .created_at = "2026-07-25T10:00:00Z",
    }, null);
    try addEntry(io, allocator, path, .user, .{
        .kind = .rule,
        .id = "core.git:reset-hard",
        .reason = "updated reason text here",
        .created_at = "2026-07-25T11:00:00Z",
    }, null);

    var loaded = try loadFile(io, allocator, path, .user);
    defer loaded.store.deinit(allocator);
    try testing.expectEqual(@as(usize, 1), loaded.store.entries.len);
    try testing.expectEqualStrings("updated reason text here", loaded.store.entries[0].reason);
}

test "s2-store: empty path layers merge cleanly" {
    var merged = try loadMerged(io, allocator, null, null);
    defer merged.store.deinit(allocator);
    try testing.expect(!merged.corrupt);
    try testing.expectEqual(@as(usize, 0), merged.store.entries.len);
}

// ── loadMerged in-process cache (raw layers; deep copy; no last-good) ────────

const s2_cache_user_toml =
    \\schema_version = 1
    \\
    \\[[entries]]
    \\kind = "command"
    \\command = "git status"
    \\reason = "s2-store-cache user command marker"
    \\created_at = "2026-07-25T12:00:00Z"
    \\scope = "user"
    \\
;

const s2_cache_project_toml =
    \\schema_version = 1
    \\
    \\[[entries]]
    \\kind = "command"
    \\command = "npm test"
    \\reason = "s2-store-cache project command stays raw"
    \\created_at = "2026-07-25T12:00:00Z"
    \\scope = "project"
    \\
    \\[[entries]]
    \\kind = "rule"
    \\id = "core.git:reset-hard"
    \\reason = "s2-store-cache project rule marker"
    \\created_at = "2026-07-25T12:00:00Z"
    \\scope = "project"
    \\
;

test "s2-store: second loadMerged does not re-parse unchanged files" {
    cache_test.reset(io);
    var tmp = try tmpRoot();
    defer {
        allocator.free(tmp.path);
        tmp.dir.cleanup();
    }
    const user_path = try joinPath(tmp.path, "user.toml");
    defer allocator.free(user_path);
    const project_path = try joinPath(tmp.path, "project.toml");
    defer allocator.free(project_path);
    try writeFileAbsolute(user_path, s2_cache_user_toml);
    try writeFileAbsolute(project_path, s2_cache_project_toml);

    var first = try loadMerged(io, allocator, user_path, project_path);
    defer first.store.deinit(allocator);
    try testing.expect(!first.corrupt);
    const parsed_after_first = cache_test.parseTomlCount();
    try testing.expect(parsed_after_first > 0);
    const hits_after_first = cache_test.mergedCacheHits();

    var second = try loadMerged(io, allocator, user_path, project_path);
    defer second.store.deinit(allocator);
    try testing.expect(!second.corrupt);
    try testing.expectEqual(parsed_after_first, cache_test.parseTomlCount());
    try testing.expectEqual(hits_after_first + 1, cache_test.mergedCacheHits());
    try testing.expect(second.store.matchCommand("git status", far_future) != null);
    try testing.expect(second.store.matchCommand("npm test", far_future) != null);
}

test "s2-store: loadMerged cache returns a deep copy" {
    cache_test.reset(io);
    var tmp = try tmpRoot();
    defer {
        allocator.free(tmp.path);
        tmp.dir.cleanup();
    }
    const path = try joinPath(tmp.path, "user.toml");
    defer allocator.free(path);
    try writeFileAbsolute(path, s2_cache_user_toml);

    var first = try loadMerged(io, allocator, path, null);
    var second = try loadMerged(io, allocator, path, null);
    defer second.store.deinit(allocator);

    try testing.expect(first.store.owned);
    try testing.expect(second.store.owned);
    try testing.expect(first.store.entries.ptr != second.store.entries.ptr);
    try testing.expectEqualStrings(first.store.entries[0].reason, second.store.entries[0].reason);
    try testing.expect(first.store.entries[0].reason.ptr != second.store.entries[0].reason.ptr);

    first.store.deinit(allocator);
    try testing.expect(second.store.matchCommand("git status", far_future) != null);
    try testing.expectEqualStrings("s2-store-cache user command marker", second.store.entries[0].reason);
}

test "s2-store: loadMerged cache keeps raw project kind=command" {
    cache_test.reset(io);
    var tmp = try tmpRoot();
    defer {
        allocator.free(tmp.path);
        tmp.dir.cleanup();
    }
    const project_path = try joinPath(tmp.path, "project.toml");
    defer allocator.free(project_path);
    try writeFileAbsolute(project_path, s2_cache_project_toml);

    var first = try loadMerged(io, allocator, null, project_path);
    defer first.store.deinit(allocator);
    const parsed_after_first = cache_test.parseTomlCount();
    try testing.expect(first.store.matchCommand("npm test", far_future) != null);

    var second = try loadMerged(io, allocator, null, project_path);
    defer second.store.deinit(allocator);

    try testing.expect(second.store.matchCommand("npm test", far_future) != null);
    try testing.expect(second.store.matchRule("core.git:reset-hard", far_future) != null);
    try testing.expectEqual(parsed_after_first, cache_test.parseTomlCount());
    try testing.expect(cache_test.mergedCacheHits() >= 1);
}

test "s2-store: same-size corrupt replace is empty+corrupt not last-good" {
    cache_test.reset(io);
    var tmp = try tmpRoot();
    defer {
        allocator.free(tmp.path);
        tmp.dir.cleanup();
    }
    const path = try joinPath(tmp.path, "user.toml");
    defer allocator.free(path);
    try writeFileAbsolute(path, s2_cache_user_toml);

    var first = try loadMerged(io, allocator, path, null);
    defer first.store.deinit(allocator);
    try testing.expect(!first.corrupt);
    try testing.expect(first.store.matchCommand("git status", far_future) != null);

    const garbage = try allocator.alloc(u8, s2_cache_user_toml.len);
    defer allocator.free(garbage);
    @memset(garbage, 'x');
    try writeFileAbsolute(path, garbage);
    try testing.expectEqual(s2_cache_user_toml.len, garbage.len);

    var second = try loadMerged(io, allocator, path, null);
    defer second.store.deinit(allocator);
    try testing.expect(second.corrupt);
    try testing.expectEqual(@as(usize, 0), second.store.entries.len);
    try testing.expect(second.store.matchCommand("git status", far_future) == null);
}

test "s2-store: unlink after cache hit is empty not last-good" {
    cache_test.reset(io);
    var tmp = try tmpRoot();
    defer {
        allocator.free(tmp.path);
        tmp.dir.cleanup();
    }
    const path = try joinPath(tmp.path, "user.toml");
    defer allocator.free(path);
    try writeFileAbsolute(path, s2_cache_user_toml);

    var first = try loadMerged(io, allocator, path, null);
    defer first.store.deinit(allocator);
    try testing.expect(first.store.matchCommand("git status", far_future) != null);

    try std.Io.Dir.cwd().deleteFile(io, path);

    var second = try loadMerged(io, allocator, path, null);
    defer second.store.deinit(allocator);
    try testing.expect(!second.corrupt);
    try testing.expectEqual(@as(usize, 0), second.store.entries.len);
    try testing.expect(second.store.matchCommand("git status", far_future) == null);
}

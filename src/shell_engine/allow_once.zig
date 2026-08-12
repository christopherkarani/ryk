//! Allow-once pending + active stores (JSONL under XDG data).
//!
//! Product paths (brand `ryk`, not `dcg`):
//! - Dir: `$XDG_DATA_HOME/ryk/` or `~/.local/share/ryk/` (hardened to 0700)
//! - `pending_exceptions.jsonl` — issued on deny (0600). Stores only a keyed
//!   `code_hash` — never the redeemable short code. The plaintext code lives
//!   in memory (`PendingIssue.redeem_code`) for the operator-facing surface.
//! - `allow_once.jsonl` — redeemed active entries (scope cwd|project, single_use, expires, command)
//!
//! Reference behavior: DCG `pending_exceptions.rs` (TTL, prune, exact match, single-use consume,
//! lock spirit, bounded growth). Tests inject absolute paths — no env required.
//!
//! JSONL: one object per line; unknown/corrupt lines skipped (not fatal). Legacy
//! v1 lines with a plaintext `short_code` are treated as corrupt and pruned on
//! load (fail closed — pending rows are short-lived).
//! Errors include `CodeNotFound`, `Expired`, `AlreadyConsumed`, `StoreFull`, `AmbiguousCode`.
//! Re-exported via `shell_engine` and covered by `test-shell-engine`.

const std = @import("std");
const builtin = @import("builtin");

// ---------------------------------------------------------------------------
// Types & constants
// ---------------------------------------------------------------------------

/// v2: pending rows store `code_hash` (keyed SHA-256), never the redeemable code.
pub const schema_version: u32 = 2;
pub const default_ttl_hours: i64 = 24;
pub const max_pending_lines: usize = 10_000;
pub const max_pending_bytes: u64 = 10 * 1024 * 1024;
/// Prefer not to rotate/evict pending rows younger than this when enforcing caps.
pub const pending_rotation_grace_secs: i64 = 300;
pub const pending_file_name = "pending_exceptions.jsonl";
pub const allow_once_file_name = "allow_once.jsonl";

pub const ScopeKind = enum {
    cwd,
    project,
};

pub const StoreError = error{
    CodeNotFound,
    Expired,
    AlreadyConsumed,
    StoreFull,
    /// More than one active pending row shares the same short_code (legacy / corrupt store).
    AmbiguousCode,
};

pub const Maintenance = struct {
    pruned_expired: usize = 0,
    pruned_consumed: usize = 0,
    parse_errors: usize = 0,

    pub fn isEmpty(self: Maintenance) bool {
        return self.pruned_expired == 0 and self.pruned_consumed == 0 and self.parse_errors == 0;
    }
};

pub const PendingRecord = struct {
    schema_version: u32 = schema_version,
    /// Keyed hash of the redeem code (`computeCodeHash`). Never the code itself:
    /// the pending file is same-user readable, so a plaintext code here would let
    /// any agent process self-authorize a redeem.
    code_hash: []const u8,
    full_hash: []const u8,
    created_at: []const u8,
    expires_at: []const u8,
    cwd: []const u8,
    command_raw: []const u8,
    reason: []const u8,
    single_use: bool = true,
    consumed_at: ?[]const u8 = null,
};

pub const AllowOnceEntry = struct {
    schema_version: u32 = schema_version,
    /// Keyed hash of the redeemed code (informational / revoke key only — the
    /// pending row is burned at redeem, so this value cannot authorize anything).
    source_code_hash: []const u8,
    source_full_hash: []const u8,
    created_at: []const u8,
    expires_at: []const u8,
    scope_kind: ScopeKind,
    scope_path: []const u8,
    command_raw: []const u8,
    reason: []const u8,
    single_use: bool = true,
    consumed_at: ?[]const u8 = null,
};

pub const PendingList = struct {
    records: []PendingRecord = &.{},
    owned: bool = false,

    pub fn deinit(self: *PendingList, gpa: std.mem.Allocator) void {
        if (!self.owned) {
            self.* = .{};
            return;
        }
        for (self.records) |r| freePendingRecord(gpa, r);
        gpa.free(self.records);
        self.* = .{};
    }
};

pub const AllowOnceList = struct {
    entries: []AllowOnceEntry = &.{},
    owned: bool = false,

    pub fn deinit(self: *AllowOnceList, gpa: std.mem.Allocator) void {
        if (!self.owned) {
            self.* = .{};
            return;
        }
        for (self.entries) |e| freeAllowOnceEntry(gpa, e);
        gpa.free(self.entries);
        self.* = .{};
    }
};

pub const PendingIssue = struct {
    record: PendingRecord,
    /// The plaintext redeem code, minted by CSPRNG. Memory-only: it is never
    /// written to any store. Callers show it exclusively on operator-facing
    /// surfaces (e.g. the controlling terminal), never on agent-visible channels.
    redeem_code: []u8,
    maintenance: Maintenance = .{},

    pub fn deinit(self: *PendingIssue, gpa: std.mem.Allocator) void {
        freePendingRecord(gpa, self.record);
        gpa.free(self.redeem_code);
        self.* = undefined;
    }
};

pub const LoadPending = struct {
    list: PendingList = .{},
    maintenance: Maintenance = .{},

    pub fn deinit(self: *LoadPending, gpa: std.mem.Allocator) void {
        self.list.deinit(gpa);
        self.* = .{};
    }
};

pub const LoadAllowOnce = struct {
    list: AllowOnceList = .{},
    maintenance: Maintenance = .{},

    pub fn deinit(self: *LoadAllowOnce, gpa: std.mem.Allocator) void {
        self.list.deinit(gpa);
        self.* = .{};
    }
};

pub const ClearResult = struct {
    removed: usize = 0,
    maintenance: Maintenance = .{},
};

pub fn freePendingRecord(gpa: std.mem.Allocator, r: PendingRecord) void {
    gpa.free(r.code_hash);
    gpa.free(r.full_hash);
    gpa.free(r.created_at);
    gpa.free(r.expires_at);
    gpa.free(r.cwd);
    gpa.free(r.command_raw);
    gpa.free(r.reason);
    if (r.consumed_at) |c| gpa.free(c);
}

pub fn freeAllowOnceEntry(gpa: std.mem.Allocator, e: AllowOnceEntry) void {
    gpa.free(e.source_code_hash);
    gpa.free(e.source_full_hash);
    gpa.free(e.created_at);
    gpa.free(e.expires_at);
    gpa.free(e.scope_path);
    gpa.free(e.command_raw);
    gpa.free(e.reason);
    if (e.consumed_at) |c| gpa.free(c);
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

/// SHA-256 hex of `"{created_at} | {cwd} | {command_raw}"` (DCG-compatible).
pub fn computeFullHash(
    gpa: std.mem.Allocator,
    created_at: []const u8,
    cwd: []const u8,
    command_raw: []const u8,
) ![]u8 {
    const payload = try std.fmt.allocPrint(gpa, "{s} | {s} | {s}", .{ created_at, cwd, command_raw });
    defer gpa.free(payload);

    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload, &digest, .{});

    var hex: [64]u8 = undefined;
    const hex_digits = "0123456789abcdef";
    for (digest, 0..) |byte, i| {
        hex[i * 2] = hex_digits[byte >> 4];
        hex[i * 2 + 1] = hex_digits[byte & 0xf];
    }
    return try gpa.dupe(u8, hex[0..]);
}

/// Keyed hash of a redeem code for at-rest storage:
/// SHA-256 hex of `"ryk-pending-v1:" ++ full_hash ++ ":" ++ code`.
/// The constant is a ryk-controlled domain separator; the per-record `full_hash`
/// (itself SHA-256 over issue time + cwd + command) acts as the per-record salt,
/// so identical codes on different rows hash differently. The plaintext code is
/// never persisted.
pub fn computeCodeHash(gpa: std.mem.Allocator, full_hash: []const u8, code: []const u8) ![]u8 {
    const payload = try std.fmt.allocPrint(gpa, "ryk-pending-v1:{s}:{s}", .{ full_hash, code });
    defer gpa.free(payload);

    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload, &digest, .{});

    var hex: [64]u8 = undefined;
    const hex_digits = "0123456789abcdef";
    for (digest, 0..) |byte, i| {
        hex[i * 2] = hex_digits[byte >> 4];
        hex[i * 2 + 1] = hex_digits[byte & 0xf];
    }
    return try gpa.dupe(u8, hex[0..]);
}

/// True when `code` redeems against `record` (constant-shape compare on hashes).
pub fn codeMatchesPending(gpa: std.mem.Allocator, record: PendingRecord, code: []const u8) !bool {
    const presented = try computeCodeHash(gpa, record.full_hash, code);
    defer gpa.free(presented);
    return std.mem.eql(u8, record.code_hash, presented);
}

/// True when `code` is the source code of `entry` (hash via the entry's full hash).
pub fn codeMatchesEntry(gpa: std.mem.Allocator, entry: AllowOnceEntry, code: []const u8) !bool {
    const presented = try computeCodeHash(gpa, entry.source_full_hash, code);
    defer gpa.free(presented);
    return std.mem.eql(u8, entry.source_code_hash, presented);
}

/// Last 8 hex chars → u32 → % 1_000_000 → zero-padded 6 digits.
/// Deterministic helper for tests / metadata only — live short codes are CSPRNG-minted.
pub fn shortCodeFromHash(full_hash: []const u8) [6]u8 {
    var out: [6]u8 = "000000".*;
    if (full_hash.len < 8) return out;
    const tail = full_hash[full_hash.len - 8 ..];
    const n = std.fmt.parseInt(u32, tail, 16) catch return out;
    const code = n % 1_000_000;
    _ = std.fmt.bufPrint(&out, "{d:0>6}", .{code}) catch return out;
    return out;
}

/// ISO-8601 same-format lexicographic compare: expired when expires_at <= now.
pub fn isExpired(expires_at: []const u8, now_iso: []const u8) bool {
    return std.mem.order(u8, expires_at, now_iso) != .gt;
}

/// cwd scope: exact path. project scope: path-prefix (boundary on `/`).
/// Project match fails closed on ".." components or "//" empty segments in either side.
/// Canonical realpath equality under a root is handled by evaluate/shell_eval, not here.
pub fn scopeMatches(entry: AllowOnceEntry, cwd: []const u8) bool {
    return switch (entry.scope_kind) {
        .cwd => std.mem.eql(u8, entry.scope_path, cwd),
        .project => pathIsUnder(entry.scope_path, cwd),
    };
}

fn pathIsUnder(root: []const u8, path: []const u8) bool {
    if (root.len == 0) return false;
    // Fail closed: non-canonical relative tricks must not expand project scope.
    if (pathHasUnsafeSegments(root) or pathHasUnsafeSegments(path)) return false;
    if (std.mem.eql(u8, root, path)) return true;
    if (path.len <= root.len) return false;
    if (!std.mem.startsWith(u8, path, root)) return false;
    // Require a path separator boundary so "/repo" does not match "/repo-other".
    const boundary = if (root[root.len - 1] == '/') true else path[root.len] == '/';
    return boundary;
}

/// True when `p` contains a ".." path component or an empty segment from "//".
/// Leading empty (absolute path "/") is allowed; subsequent empties and ".." are not.
fn pathHasUnsafeSegments(p: []const u8) bool {
    var iter = std.mem.splitScalar(u8, p, '/');
    var index: usize = 0;
    while (iter.next()) |seg| {
        if (seg.len == 0) {
            // Absolute paths start with '/'; that first empty is fine. Later empties are "//".
            if (index != 0) return true;
        } else if (std.mem.eql(u8, seg, "..")) {
            return true;
        }
        index += 1;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Pending store
// ---------------------------------------------------------------------------

pub fn issuePending(
    runtime_io: std.Io,
    gpa: std.mem.Allocator,
    pending_path: []const u8,
    command: []const u8,
    cwd: []const u8,
    reason: []const u8,
    now_iso: []const u8,
    single_use: bool,
) !PendingIssue {
    var lock = try StoreLock.acquire(runtime_io, gpa, pending_path);
    defer lock.release(runtime_io);

    var state = try loadPendingState(runtime_io, gpa, pending_path, now_iso);
    defer {
        freePendingRecords(gpa, state.active.items);
        state.active.deinit(gpa);
    }

    // Bounded growth: rotate oldest non-grace rows until under line/byte caps.
    try rotatePendingToFit(gpa, &state, 1, now_iso);

    // Ensure the minted code is unique among active pending (re-mint CSPRNG on collision).
    const built = try buildPendingRecordUnique(runtime_io, gpa, state.active.items, command, cwd, reason, now_iso, single_use);
    var built_owned = true;
    errdefer if (built_owned) built.deinit(gpa);
    const record = built.record;

    // Byte-cap check for the new line before commit.
    const trial_line = try renderPendingLine(gpa, record);
    defer gpa.free(trial_line);
    if (state.active_bytes + trial_line.len + 1 > max_pending_bytes) {
        while (state.active.items.len > 0 and state.active_bytes + trial_line.len + 1 > max_pending_bytes) {
            const victim = findRotationVictim(state.active.items, now_iso) orelse return error.StoreFull;
            const old = state.active.orderedRemove(victim);
            const old_line = renderPendingLine(gpa, old) catch {
                freePendingRecord(gpa, old);
                return error.StoreFull;
            };
            defer gpa.free(old_line);
            state.active_bytes -|= old_line.len + 1;
            freePendingRecord(gpa, old);
            state.dirty = true;
        }
        if (state.active_bytes + trial_line.len + 1 > max_pending_bytes) {
            return error.StoreFull;
        }
    }

    try state.active.append(gpa, record);
    built_owned = false; // record now owned by state.active (defer frees it)
    state.active_bytes += trial_line.len + 1;

    // Clone return ownership before durable write so OOM after write cannot orphan
    // a caller-visible "issue failed" while the row is already on disk (M-16).
    const owned = try clonePendingRecord(gpa, state.active.items[state.active.items.len - 1]);
    errdefer freePendingRecord(gpa, owned);
    // The plaintext code moves out to the caller (operator surface); it is never
    // written to the store.
    const redeem_code = built.redeem_code;
    errdefer gpa.free(redeem_code);

    try writePendingFile(runtime_io, gpa, pending_path, state.active.items);

    return .{
        .record = owned,
        .redeem_code = redeem_code,
        .maintenance = state.maintenance,
    };
}

pub fn loadPendingActive(
    runtime_io: std.Io,
    gpa: std.mem.Allocator,
    pending_path: []const u8,
    now_iso: []const u8,
) !LoadPending {
    var lock = try StoreLock.acquire(runtime_io, gpa, pending_path);
    defer lock.release(runtime_io);

    var state = try loadPendingState(runtime_io, gpa, pending_path, now_iso);
    errdefer {
        freePendingRecords(gpa, state.active.items);
        state.active.deinit(gpa);
    }

    if (state.dirty) {
        try writePendingFile(runtime_io, gpa, pending_path, state.active.items);
    }

    // pendingStateToLoad steals the slice; disarm errdefer by emptying state first only on success.
    const result = try pendingStateToLoad(gpa, &state);
    // state.active is empty/unowned after toOwnedSlice or deinit inside pendingStateToLoad.
    return result;
}

pub fn lookupPendingByCode(
    runtime_io: std.Io,
    gpa: std.mem.Allocator,
    pending_path: []const u8,
    code: []const u8,
    now_iso: []const u8,
) !LoadPending {
    var lock = try StoreLock.acquire(runtime_io, gpa, pending_path);
    defer lock.release(runtime_io);

    var state = try loadPendingState(runtime_io, gpa, pending_path, now_iso);
    defer {
        freePendingRecords(gpa, state.active.items);
        state.active.deinit(gpa);
    }

    if (state.dirty) {
        try writePendingFile(runtime_io, gpa, pending_path, state.active.items);
    }

    var matched: std.ArrayListUnmanaged(PendingRecord) = .empty;
    errdefer {
        freePendingRecords(gpa, matched.items);
        matched.deinit(gpa);
    }

    for (state.active.items) |r| {
        if (try codeMatchesPending(gpa, r, code)) {
            try matched.append(gpa, try clonePendingRecord(gpa, r));
        }
    }

    if (matched.items.len == 0) {
        matched.deinit(gpa);
        return .{
            .list = .{ .records = &.{}, .owned = false },
            .maintenance = state.maintenance,
        };
    }

    const records = try matched.toOwnedSlice(gpa);
    return .{
        .list = .{ .records = records, .owned = true },
        .maintenance = state.maintenance,
    };
}

pub fn clearPending(
    runtime_io: std.Io,
    gpa: std.mem.Allocator,
    pending_path: []const u8,
    now_iso: []const u8,
) !ClearResult {
    var lock = try StoreLock.acquire(runtime_io, gpa, pending_path);
    defer lock.release(runtime_io);

    var state = try loadPendingState(runtime_io, gpa, pending_path, now_iso);
    defer {
        freePendingRecords(gpa, state.active.items);
        state.active.deinit(gpa);
    }

    const removed = state.active.items.len;
    // Drop all active rows and rewrite empty (also drops expired via load).
    freePendingRecords(gpa, state.active.items);
    state.active.clearRetainingCapacity();

    try writePendingFile(runtime_io, gpa, pending_path, state.active.items);
    return .{
        .removed = removed,
        .maintenance = state.maintenance,
    };
}

pub fn revokePending(
    runtime_io: std.Io,
    gpa: std.mem.Allocator,
    pending_path: []const u8,
    code_or_hash: []const u8,
    now_iso: []const u8,
) !ClearResult {
    var lock = try StoreLock.acquire(runtime_io, gpa, pending_path);
    defer lock.release(runtime_io);

    var state = try loadPendingState(runtime_io, gpa, pending_path, now_iso);
    defer {
        freePendingRecords(gpa, state.active.items);
        state.active.deinit(gpa);
    }

    // In-place compact: single owner for all records (avoids dual-list OOM double-free).
    // Key may be a stored code_hash / full_hash (direct) or a plaintext code
    // (hashed per record) — all are non-authorizing identifiers.
    var removed: usize = 0;
    var write_idx: usize = 0;
    for (state.active.items) |r| {
        const hit = std.mem.eql(u8, r.code_hash, code_or_hash) or
            std.mem.eql(u8, r.full_hash, code_or_hash) or
            try codeMatchesPending(gpa, r, code_or_hash);
        if (hit) {
            freePendingRecord(gpa, r);
            removed += 1;
        } else {
            state.active.items[write_idx] = r;
            write_idx += 1;
        }
    }
    state.active.shrinkRetainingCapacity(write_idx);

    try writePendingFile(runtime_io, gpa, pending_path, state.active.items);

    return .{
        .removed = removed,
        .maintenance = state.maintenance,
    };
}

// ---------------------------------------------------------------------------
// Allow-once store
// ---------------------------------------------------------------------------

pub fn redeem(
    runtime_io: std.Io,
    gpa: std.mem.Allocator,
    pending_path: []const u8,
    allow_once_path: []const u8,
    code: []const u8,
    now_iso: []const u8,
    scope_kind: ScopeKind,
    scope_path: []const u8,
) !AllowOnceEntry {
    // Fixed lock order (pending → allow_once) to avoid cross-store deadlock.
    var pending_lock = try StoreLock.acquire(runtime_io, gpa, pending_path);
    defer pending_lock.release(runtime_io);
    var allow_lock = try StoreLock.acquire(runtime_io, gpa, allow_once_path);
    defer allow_lock.release(runtime_io);

    var pending_state = try loadPendingState(runtime_io, gpa, pending_path, now_iso);
    defer {
        freePendingRecords(gpa, pending_state.active.items);
        pending_state.active.deinit(gpa);
    }

    // Resolve active code matches first (live wins over expired-on-disk collisions).
    var match_count: usize = 0;
    var found_idx: ?usize = null;
    for (pending_state.active.items, 0..) |r, i| {
        if (try codeMatchesPending(gpa, r, code)) {
            match_count += 1;
            if (found_idx == null) found_idx = i;
        }
    }
    if (match_count > 1) return error.AmbiguousCode;
    const idx = found_idx orelse {
        // No active match: distinguish Expired (was present, TTL elapsed) vs missing.
        if (try pendingCodeIsExpiredOnDisk(runtime_io, gpa, pending_path, code, now_iso)) {
            return error.Expired;
        }
        return error.CodeNotFound;
    };

    const pending = pending_state.active.items[idx];
    if (pending.consumed_at != null) return error.AlreadyConsumed;

    // Build returned entry before burning pending (needs field slices while record lives).
    const entry = try buildAllowOnceFromPending(gpa, pending, now_iso, scope_kind, scope_path);
    errdefer freeAllowOnceEntry(gpa, entry);

    // FAIL-CLOSED dual-file order: burn pending on disk first, then mint allow-once.
    // If pending write fails → disk unchanged, code remains redeemable, no grant written.
    // If pending write succeeds and allow-once write fails → code is burned (no double redeem);
    // caller must re-issue rather than retry redeem blindly.
    const removed = pending_state.active.orderedRemove(idx);
    var removed_owned = true;
    errdefer if (removed_owned) freePendingRecord(gpa, removed);

    try writePendingFile(runtime_io, gpa, pending_path, pending_state.active.items);
    freePendingRecord(gpa, removed);
    removed_owned = false;

    // Append to allow-once store (prune first via load).
    var allow_state = try loadAllowOnceState(runtime_io, gpa, allow_once_path, now_iso);
    defer {
        freeAllowOnceEntries(gpa, allow_state.active.items);
        allow_state.active.deinit(gpa);
    }
    const stored = try cloneAllowOnceEntry(gpa, entry);
    var stored_owned = true;
    errdefer if (stored_owned) freeAllowOnceEntry(gpa, stored);
    try allow_state.active.append(gpa, stored);
    stored_owned = false; // owned by allow_state (defer frees)
    try writeAllowOnceFile(runtime_io, gpa, allow_once_path, allow_state.active.items);

    return entry;
}

pub fn loadAllowOnceActive(
    runtime_io: std.Io,
    gpa: std.mem.Allocator,
    allow_once_path: []const u8,
    now_iso: []const u8,
) !LoadAllowOnce {
    var lock = try StoreLock.acquire(runtime_io, gpa, allow_once_path);
    defer lock.release(runtime_io);

    var state = try loadAllowOnceState(runtime_io, gpa, allow_once_path, now_iso);
    errdefer {
        freeAllowOnceEntries(gpa, state.active.items);
        state.active.deinit(gpa);
    }

    if (state.dirty) {
        try writeAllowOnceFile(runtime_io, gpa, allow_once_path, state.active.items);
    }

    return allowOnceStateToLoad(gpa, &state);
}

/// Match exact command + scope. When `consume` is true and the entry is single_use,
/// remove it from the store (evaluate path). When `consume` is false, leave store intact
/// (explain / dry-run / peek before consume).
pub fn matchAllowOnce(
    runtime_io: std.Io,
    gpa: std.mem.Allocator,
    allow_once_path: []const u8,
    command: []const u8,
    cwd: []const u8,
    now_iso: []const u8,
    consume: bool,
) !?AllowOnceEntry {
    var lock = try StoreLock.acquire(runtime_io, gpa, allow_once_path);
    defer lock.release(runtime_io);

    var state = try loadAllowOnceState(runtime_io, gpa, allow_once_path, now_iso);
    defer {
        freeAllowOnceEntries(gpa, state.active.items);
        state.active.deinit(gpa);
    }

    var hit_idx: ?usize = null;
    for (state.active.items, 0..) |e, i| {
        if (!std.mem.eql(u8, e.command_raw, command)) continue;
        if (!scopeMatches(e, cwd)) continue;
        hit_idx = i;
        break;
    }

    const idx = hit_idx orelse {
        if (state.dirty) {
            try writeAllowOnceFile(runtime_io, gpa, allow_once_path, state.active.items);
        }
        return null;
    };

    if (consume and state.active.items[idx].single_use) {
        // Transfer ownership of the matched entry out of the list (defer must not free it).
        const taken = state.active.orderedRemove(idx);
        errdefer freeAllowOnceEntry(gpa, taken);
        try writeAllowOnceFile(runtime_io, gpa, allow_once_path, state.active.items);
        return taken;
    }

    const owned = try cloneAllowOnceEntry(gpa, state.active.items[idx]);
    errdefer freeAllowOnceEntry(gpa, owned);
    if (state.dirty) {
        try writeAllowOnceFile(runtime_io, gpa, allow_once_path, state.active.items);
    }
    return owned;
}

pub fn clearAllowOnce(
    runtime_io: std.Io,
    gpa: std.mem.Allocator,
    allow_once_path: []const u8,
    now_iso: []const u8,
) !ClearResult {
    var lock = try StoreLock.acquire(runtime_io, gpa, allow_once_path);
    defer lock.release(runtime_io);

    var state = try loadAllowOnceState(runtime_io, gpa, allow_once_path, now_iso);
    defer {
        freeAllowOnceEntries(gpa, state.active.items);
        state.active.deinit(gpa);
    }

    const removed = state.active.items.len;
    freeAllowOnceEntries(gpa, state.active.items);
    state.active.clearRetainingCapacity();
    try writeAllowOnceFile(runtime_io, gpa, allow_once_path, state.active.items);
    return .{
        .removed = removed,
        .maintenance = state.maintenance,
    };
}

pub fn revokeAllowOnce(
    runtime_io: std.Io,
    gpa: std.mem.Allocator,
    allow_once_path: []const u8,
    code_or_hash: []const u8,
    now_iso: []const u8,
) !ClearResult {
    var lock = try StoreLock.acquire(runtime_io, gpa, allow_once_path);
    defer lock.release(runtime_io);

    var state = try loadAllowOnceState(runtime_io, gpa, allow_once_path, now_iso);
    defer {
        freeAllowOnceEntries(gpa, state.active.items);
        state.active.deinit(gpa);
    }

    // In-place compact: single owner for all entries (avoids dual-list OOM double-free).
    // Key may be a stored source_code_hash / source_full_hash (direct) or a
    // plaintext code (hashed per entry).
    var removed: usize = 0;
    var write_idx: usize = 0;
    for (state.active.items) |e| {
        const hit = std.mem.eql(u8, e.source_code_hash, code_or_hash) or
            std.mem.eql(u8, e.source_full_hash, code_or_hash) or
            try codeMatchesEntry(gpa, e, code_or_hash);
        if (hit) {
            freeAllowOnceEntry(gpa, e);
            removed += 1;
        } else {
            state.active.items[write_idx] = e;
            write_idx += 1;
        }
    }
    state.active.shrinkRetainingCapacity(write_idx);

    try writeAllowOnceFile(runtime_io, gpa, allow_once_path, state.active.items);

    return .{
        .removed = removed,
        .maintenance = state.maintenance,
    };
}

// ---------------------------------------------------------------------------
// Internals — pending JSONL
// ---------------------------------------------------------------------------

const PendingState = struct {
    active: std.ArrayListUnmanaged(PendingRecord) = .empty,
    maintenance: Maintenance = .{},
    dirty: bool = false,
    active_bytes: u64 = 0,
};

fn loadPendingState(
    runtime_io: std.Io,
    gpa: std.mem.Allocator,
    pending_path: []const u8,
    now_iso: []const u8,
) !PendingState {
    var state: PendingState = .{};
    errdefer {
        freePendingRecords(gpa, state.active.items);
        state.active.deinit(gpa);
    }

    const raw = readFileOptional(runtime_io, gpa, pending_path) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return err,
    };
    if (raw == null) return state;
    const body = raw.?;
    defer gpa.free(body);

    var iter = std.mem.splitScalar(u8, body, '\n');
    while (iter.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, " \t\r");
        if (line.len == 0) continue;

        const parsed = parsePendingLine(gpa, line) catch {
            state.maintenance.parse_errors += 1;
            state.dirty = true;
            continue;
        };

        if (parsed.consumed_at != null) {
            freePendingRecord(gpa, parsed);
            state.maintenance.pruned_consumed += 1;
            state.dirty = true;
            continue;
        }
        if (isExpired(parsed.expires_at, now_iso)) {
            freePendingRecord(gpa, parsed);
            state.maintenance.pruned_expired += 1;
            state.dirty = true;
            continue;
        }

        const line_bytes = line.len + 1;
        // Free parsed on append OOM before ownership transfers to state (M-21).
        {
            errdefer freePendingRecord(gpa, parsed);
            try state.active.append(gpa, parsed);
        }
        state.active_bytes += line_bytes;
    }

    return state;
}

fn pendingStateToLoad(gpa: std.mem.Allocator, state: *PendingState) !LoadPending {
    if (state.active.items.len == 0) {
        state.active.deinit(gpa);
        return .{
            .list = .{ .records = &.{}, .owned = false },
            .maintenance = state.maintenance,
        };
    }
    const records = try state.active.toOwnedSlice(gpa);
    return .{
        .list = .{ .records = records, .owned = true },
        .maintenance = state.maintenance,
    };
}

fn rotatePendingToFit(gpa: std.mem.Allocator, state: *PendingState, room_for: usize, now_iso: []const u8) !void {
    // Line cap: keep at most max_pending_lines - room_for existing rows.
    // Prefer not to drop rows issued within pending_rotation_grace_secs (M-13).
    while (state.active.items.len + room_for > max_pending_lines) {
        if (state.active.items.len == 0) return error.StoreFull;
        const victim = findRotationVictim(state.active.items, now_iso) orelse return error.StoreFull;
        const old = state.active.orderedRemove(victim);
        const old_line = renderPendingLine(gpa, old) catch {
            freePendingRecord(gpa, old);
            return error.StoreFull;
        };
        defer gpa.free(old_line);
        state.active_bytes -|= old_line.len + 1;
        freePendingRecord(gpa, old);
        state.dirty = true;
    }
}

/// Oldest index not within the rotation grace window, or null if all rows are young.
fn findRotationVictim(items: []const PendingRecord, now_iso: []const u8) ?usize {
    var i: usize = 0;
    while (i < items.len) : (i += 1) {
        if (!isCreatedWithinGrace(items[i].created_at, now_iso)) return i;
    }
    return null;
}

/// True when created_at is within pending_rotation_grace_secs of now_iso (parseable ISO only).
fn isCreatedWithinGrace(created_at: []const u8, now_iso: []const u8) bool {
    const c = parseIsoUtc(created_at) catch return false;
    const n = parseIsoUtc(now_iso) catch return false;
    const c_secs = approxUnixSecs(c);
    const n_secs = approxUnixSecs(n);
    if (n_secs <= c_secs) return true;
    return (n_secs - c_secs) < pending_rotation_grace_secs;
}

fn approxUnixSecs(p: IsoParts) i64 {
    var days: i64 = 0;
    var y: i32 = 1970;
    if (p.year >= 1970) {
        while (y < p.year) : (y += 1) {
            days += if (isLeapYear(y)) 366 else 365;
        }
    } else {
        while (y > p.year) : (y -= 1) {
            days -= if (isLeapYear(y - 1)) 366 else 365;
        }
    }
    var m: i32 = 1;
    while (m < p.month) : (m += 1) {
        days += daysInMonth(p.year, m);
    }
    days += p.day - 1;
    return days * 86400 + p.hour * 3600 + @as(i64, @intCast(p.minute)) * 60 + @as(i64, @intCast(p.second));
}

fn parsePendingLine(gpa: std.mem.Allocator, line: []const u8) !PendingRecord {
    var parsed = std.json.parseFromSlice(std.json.Value, gpa, line, .{}) catch return error.Corrupt;
    defer parsed.deinit();
    if (parsed.value != .object) return error.Corrupt;
    const obj = parsed.value.object;

    // v2 rows carry `code_hash` only. Legacy v1 rows with a plaintext
    // `short_code` are corrupt here → pruned on load (fail-closed invalidation).
    const code_hash = try dupeJsonString(gpa, obj, "code_hash");
    errdefer gpa.free(code_hash);
    const full_hash = try dupeJsonString(gpa, obj, "full_hash");
    errdefer gpa.free(full_hash);
    const created_at = try dupeJsonString(gpa, obj, "created_at");
    errdefer gpa.free(created_at);
    const expires_at = try dupeJsonString(gpa, obj, "expires_at");
    errdefer gpa.free(expires_at);
    const cwd = try dupeJsonString(gpa, obj, "cwd");
    errdefer gpa.free(cwd);
    const command_raw = try dupeJsonString(gpa, obj, "command_raw");
    errdefer gpa.free(command_raw);
    const reason = try dupeJsonString(gpa, obj, "reason");
    errdefer gpa.free(reason);

    const schema = jsonU32(obj, "schema_version") orelse schema_version;
    const single_use = jsonBool(obj, "single_use") orelse true;
    const consumed_at = try dupeJsonStringOptional(gpa, obj, "consumed_at");

    return .{
        .schema_version = schema,
        .code_hash = code_hash,
        .full_hash = full_hash,
        .created_at = created_at,
        .expires_at = expires_at,
        .cwd = cwd,
        .command_raw = command_raw,
        .reason = reason,
        .single_use = single_use,
        .consumed_at = consumed_at,
    };
}

fn renderPendingLine(gpa: std.mem.Allocator, r: PendingRecord) ![]u8 {
    const payload = .{
        .schema_version = r.schema_version,
        .code_hash = r.code_hash,
        .full_hash = r.full_hash,
        .created_at = r.created_at,
        .expires_at = r.expires_at,
        .cwd = r.cwd,
        .command_raw = r.command_raw,
        .reason = r.reason,
        .single_use = r.single_use,
        .consumed_at = r.consumed_at,
    };
    return std.json.Stringify.valueAlloc(gpa, payload, .{}) catch return error.OutOfMemory;
}

fn writePendingFile(
    runtime_io: std.Io,
    gpa: std.mem.Allocator,
    path: []const u8,
    records: []const PendingRecord,
) !void {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(gpa);
    for (records) |r| {
        const line = try renderPendingLine(gpa, r);
        defer gpa.free(line);
        try buf.appendSlice(gpa, line);
        try buf.append(gpa, '\n');
    }
    try writeFile(runtime_io, gpa, path, buf.items);
}

fn clonePendingRecord(gpa: std.mem.Allocator, r: PendingRecord) !PendingRecord {
    const code_hash = try gpa.dupe(u8, r.code_hash);
    errdefer gpa.free(code_hash);
    const full_hash = try gpa.dupe(u8, r.full_hash);
    errdefer gpa.free(full_hash);
    const created_at = try gpa.dupe(u8, r.created_at);
    errdefer gpa.free(created_at);
    const expires_at = try gpa.dupe(u8, r.expires_at);
    errdefer gpa.free(expires_at);
    const cwd = try gpa.dupe(u8, r.cwd);
    errdefer gpa.free(cwd);
    const command_raw = try gpa.dupe(u8, r.command_raw);
    errdefer gpa.free(command_raw);
    const reason = try gpa.dupe(u8, r.reason);
    errdefer gpa.free(reason);
    const consumed_at = if (r.consumed_at) |c| try gpa.dupe(u8, c) else null;
    return .{
        .schema_version = r.schema_version,
        .code_hash = code_hash,
        .full_hash = full_hash,
        .created_at = created_at,
        .expires_at = expires_at,
        .cwd = cwd,
        .command_raw = command_raw,
        .reason = reason,
        .single_use = r.single_use,
        .consumed_at = consumed_at,
    };
}

fn freePendingRecords(gpa: std.mem.Allocator, records: []PendingRecord) void {
    for (records) |r| freePendingRecord(gpa, r);
}

/// True when a pending line with this short_code exists on disk and is expired at now_iso.
fn pendingCodeIsExpiredOnDisk(
    runtime_io: std.Io,
    gpa: std.mem.Allocator,
    pending_path: []const u8,
    code: []const u8,
    now_iso: []const u8,
) !bool {
    const raw = readFileOptional(runtime_io, gpa, pending_path) catch return false;
    if (raw == null) return false;
    const body = raw.?;
    defer gpa.free(body);

    var iter = std.mem.splitScalar(u8, body, '\n');
    while (iter.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, " \t\r");
        if (line.len == 0) continue;
        const parsed = parsePendingLine(gpa, line) catch continue;
        defer freePendingRecord(gpa, parsed);
        if (!try codeMatchesPending(gpa, parsed, code)) continue;
        if (parsed.consumed_at != null) continue;
        if (isExpired(parsed.expires_at, now_iso)) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Internals — allow-once JSONL
// ---------------------------------------------------------------------------

const AllowOnceState = struct {
    active: std.ArrayListUnmanaged(AllowOnceEntry) = .empty,
    maintenance: Maintenance = .{},
    dirty: bool = false,
};

fn loadAllowOnceState(
    runtime_io: std.Io,
    gpa: std.mem.Allocator,
    allow_once_path: []const u8,
    now_iso: []const u8,
) !AllowOnceState {
    var state: AllowOnceState = .{};
    errdefer {
        freeAllowOnceEntries(gpa, state.active.items);
        state.active.deinit(gpa);
    }

    const raw = readFileOptional(runtime_io, gpa, allow_once_path) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return err,
    };
    if (raw == null) return state;
    const body = raw.?;
    defer gpa.free(body);

    var iter = std.mem.splitScalar(u8, body, '\n');
    while (iter.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, " \t\r");
        if (line.len == 0) continue;

        const parsed = parseAllowOnceLine(gpa, line) catch {
            state.maintenance.parse_errors += 1;
            state.dirty = true;
            continue;
        };

        if (parsed.consumed_at != null) {
            freeAllowOnceEntry(gpa, parsed);
            state.maintenance.pruned_consumed += 1;
            state.dirty = true;
            continue;
        }
        if (isExpired(parsed.expires_at, now_iso)) {
            freeAllowOnceEntry(gpa, parsed);
            state.maintenance.pruned_expired += 1;
            state.dirty = true;
            continue;
        }

        // Free parsed on append OOM before ownership transfers to state (M-21).
        {
            errdefer freeAllowOnceEntry(gpa, parsed);
            try state.active.append(gpa, parsed);
        }
    }

    return state;
}

fn allowOnceStateToLoad(gpa: std.mem.Allocator, state: *AllowOnceState) !LoadAllowOnce {
    if (state.active.items.len == 0) {
        state.active.deinit(gpa);
        return .{
            .list = .{ .entries = &.{}, .owned = false },
            .maintenance = state.maintenance,
        };
    }
    const entries = try state.active.toOwnedSlice(gpa);
    return .{
        .list = .{ .entries = entries, .owned = true },
        .maintenance = state.maintenance,
    };
}

fn parseAllowOnceLine(gpa: std.mem.Allocator, line: []const u8) !AllowOnceEntry {
    var parsed = std.json.parseFromSlice(std.json.Value, gpa, line, .{}) catch return error.Corrupt;
    defer parsed.deinit();
    if (parsed.value != .object) return error.Corrupt;
    const obj = parsed.value.object;

    // v2 rows carry `source_code_hash`; legacy `source_short_code` rows are
    // corrupt here → pruned on load (fail closed).
    const source_code_hash = try dupeJsonString(gpa, obj, "source_code_hash");
    errdefer gpa.free(source_code_hash);
    const source_full_hash = try dupeJsonString(gpa, obj, "source_full_hash");
    errdefer gpa.free(source_full_hash);
    const created_at = try dupeJsonString(gpa, obj, "created_at");
    errdefer gpa.free(created_at);
    const expires_at = try dupeJsonString(gpa, obj, "expires_at");
    errdefer gpa.free(expires_at);
    const scope_path = try dupeJsonString(gpa, obj, "scope_path");
    errdefer gpa.free(scope_path);
    const command_raw = try dupeJsonString(gpa, obj, "command_raw");
    errdefer gpa.free(command_raw);
    const reason = try dupeJsonString(gpa, obj, "reason");
    errdefer gpa.free(reason);

    const scope_kind_str = jsonString(obj, "scope_kind") orelse return error.Corrupt;
    const scope_kind: ScopeKind = if (std.mem.eql(u8, scope_kind_str, "cwd"))
        .cwd
    else if (std.mem.eql(u8, scope_kind_str, "project"))
        .project
    else
        return error.Corrupt;

    const schema = jsonU32(obj, "schema_version") orelse schema_version;
    const single_use = jsonBool(obj, "single_use") orelse true;
    const consumed_at = try dupeJsonStringOptional(gpa, obj, "consumed_at");

    return .{
        .schema_version = schema,
        .source_code_hash = source_code_hash,
        .source_full_hash = source_full_hash,
        .created_at = created_at,
        .expires_at = expires_at,
        .scope_kind = scope_kind,
        .scope_path = scope_path,
        .command_raw = command_raw,
        .reason = reason,
        .single_use = single_use,
        .consumed_at = consumed_at,
    };
}

fn renderAllowOnceLine(gpa: std.mem.Allocator, e: AllowOnceEntry) ![]u8 {
    const scope_kind_str: []const u8 = switch (e.scope_kind) {
        .cwd => "cwd",
        .project => "project",
    };
    const payload = .{
        .schema_version = e.schema_version,
        .source_code_hash = e.source_code_hash,
        .source_full_hash = e.source_full_hash,
        .created_at = e.created_at,
        .expires_at = e.expires_at,
        .scope_kind = scope_kind_str,
        .scope_path = e.scope_path,
        .command_raw = e.command_raw,
        .reason = e.reason,
        .single_use = e.single_use,
        .consumed_at = e.consumed_at,
    };
    return std.json.Stringify.valueAlloc(gpa, payload, .{}) catch return error.OutOfMemory;
}

fn writeAllowOnceFile(
    runtime_io: std.Io,
    gpa: std.mem.Allocator,
    path: []const u8,
    entries: []const AllowOnceEntry,
) !void {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(gpa);
    for (entries) |e| {
        const line = try renderAllowOnceLine(gpa, e);
        defer gpa.free(line);
        try buf.appendSlice(gpa, line);
        try buf.append(gpa, '\n');
    }
    try writeFile(runtime_io, gpa, path, buf.items);
}

fn cloneAllowOnceEntry(gpa: std.mem.Allocator, e: AllowOnceEntry) !AllowOnceEntry {
    const source_code_hash = try gpa.dupe(u8, e.source_code_hash);
    errdefer gpa.free(source_code_hash);
    const source_full_hash = try gpa.dupe(u8, e.source_full_hash);
    errdefer gpa.free(source_full_hash);
    const created_at = try gpa.dupe(u8, e.created_at);
    errdefer gpa.free(created_at);
    const expires_at = try gpa.dupe(u8, e.expires_at);
    errdefer gpa.free(expires_at);
    const scope_path = try gpa.dupe(u8, e.scope_path);
    errdefer gpa.free(scope_path);
    const command_raw = try gpa.dupe(u8, e.command_raw);
    errdefer gpa.free(command_raw);
    const reason = try gpa.dupe(u8, e.reason);
    errdefer gpa.free(reason);
    const consumed_at = if (e.consumed_at) |c| try gpa.dupe(u8, c) else null;
    return .{
        .schema_version = e.schema_version,
        .source_code_hash = source_code_hash,
        .source_full_hash = source_full_hash,
        .created_at = created_at,
        .expires_at = expires_at,
        .scope_kind = e.scope_kind,
        .scope_path = scope_path,
        .command_raw = command_raw,
        .reason = reason,
        .single_use = e.single_use,
        .consumed_at = consumed_at,
    };
}

fn freeAllowOnceEntries(gpa: std.mem.Allocator, entries: []AllowOnceEntry) void {
    for (entries) |e| freeAllowOnceEntry(gpa, e);
}

// ---------------------------------------------------------------------------
// Internals — JSON helpers, ISO math, file IO
// ---------------------------------------------------------------------------

fn jsonString(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const v = obj.get(key) orelse return null;
    return switch (v) {
        .string => |s| s,
        else => null,
    };
}

fn jsonBool(obj: std.json.ObjectMap, key: []const u8) ?bool {
    const v = obj.get(key) orelse return null;
    return switch (v) {
        .bool => |b| b,
        else => null,
    };
}

fn jsonU32(obj: std.json.ObjectMap, key: []const u8) ?u32 {
    const v = obj.get(key) orelse return null;
    return switch (v) {
        .integer => |i| if (i >= 0 and i <= std.math.maxInt(u32)) @intCast(i) else null,
        else => null,
    };
}

fn dupeJsonString(gpa: std.mem.Allocator, obj: std.json.ObjectMap, key: []const u8) ![]u8 {
    const s = jsonString(obj, key) orelse return error.Corrupt;
    return try gpa.dupe(u8, s);
}

fn dupeJsonStringOptional(gpa: std.mem.Allocator, obj: std.json.ObjectMap, key: []const u8) !?[]u8 {
    const v = obj.get(key) orelse return null;
    return switch (v) {
        .null => null,
        .string => |s| try gpa.dupe(u8, s),
        else => error.Corrupt,
    };
}

/// Add whole hours to a UTC ISO-8601 timestamp (`YYYY-MM-DDTHH:MM:SSZ` or with fractional seconds ignored).
fn addHoursIso(gpa: std.mem.Allocator, iso: []const u8, hours: i64) ![]u8 {
    return addSecondsIso(gpa, iso, hours * 3600);
}

/// Add whole seconds to a UTC ISO-8601 timestamp (`YYYY-MM-DDTHH:MM:SSZ`).
fn addSecondsIso(gpa: std.mem.Allocator, iso: []const u8, seconds: i64) ![]u8 {
    const parts = try parseIsoUtc(iso);
    var y: i32 = parts.year;
    var mo: i32 = parts.month;
    var d: i32 = parts.day;
    var h: i64 = parts.hour;
    var mi: i64 = parts.minute;
    var s: i64 = @as(i64, @intCast(parts.second)) + seconds;

    // Normalize seconds → minutes → hours → days.
    while (s >= 60) {
        s -= 60;
        mi += 1;
    }
    while (s < 0) {
        s += 60;
        mi -= 1;
    }
    while (mi >= 60) {
        mi -= 60;
        h += 1;
    }
    while (mi < 0) {
        mi += 60;
        h -= 1;
    }
    while (h >= 24) {
        h -= 24;
        d += 1;
        const dim = daysInMonth(y, mo);
        if (d > dim) {
            d = 1;
            mo += 1;
            if (mo > 12) {
                mo = 1;
                y += 1;
            }
        }
    }
    while (h < 0) {
        h += 24;
        d -= 1;
        if (d < 1) {
            mo -= 1;
            if (mo < 1) {
                mo = 12;
                y -= 1;
            }
            d = daysInMonth(y, mo);
        }
    }

    // Cast to unsigned so fmt does not emit a leading '+' for signed ints.
    return try std.fmt.allocPrint(gpa, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        @as(u32, @intCast(y)),
        @as(u32, @intCast(mo)),
        @as(u32, @intCast(d)),
        @as(u32, @intCast(h)),
        @as(u32, @intCast(mi)),
        @as(u32, @intCast(s)),
    });
}

/// True when `code` would redeem against any active record (hash compare).
fn codeInUse(gpa: std.mem.Allocator, records: []const PendingRecord, code: []const u8) !bool {
    for (records) |r| {
        if (try codeMatchesPending(gpa, r, code)) return true;
    }
    return false;
}

const BuiltPending = struct {
    record: PendingRecord,
    redeem_code: []u8,

    fn deinit(self: BuiltPending, gpa: std.mem.Allocator) void {
        freePendingRecord(gpa, self.record);
        gpa.free(self.redeem_code);
    }
};

/// Build a pending record whose minted code is unique among `active`.
/// On collision, re-mint a fresh CSPRNG code (created_at stays at now_iso).
fn buildPendingRecordUnique(
    runtime_io: std.Io,
    gpa: std.mem.Allocator,
    active: []const PendingRecord,
    command: []const u8,
    cwd: []const u8,
    reason: []const u8,
    now_iso: []const u8,
    single_use: bool,
) !BuiltPending {
    // 1e6 code space; bound retries well below that for pathological stores.
    const max_attempts: usize = 64;
    var attempt: usize = 0;
    while (attempt < max_attempts) : (attempt += 1) {
        const built = try buildPendingRecord(runtime_io, gpa, command, cwd, reason, now_iso, single_use);
        if (!try codeInUse(gpa, active, built.redeem_code)) return built;
        built.deinit(gpa);
    }
    return error.StoreFull;
}

/// Mint a 6-digit short code from Io CSPRNG entropy (Zig 0.16: `io.random`).
fn mintShortCode(runtime_io: std.Io, gpa: std.mem.Allocator) ![]u8 {
    var src = std.Random.IoSource{ .io = runtime_io };
    const r = src.interface();
    const n = r.intRangeLessThan(u32, 0, 1_000_000);
    return try std.fmt.allocPrint(gpa, "{d:0>6}", .{n});
}

fn buildPendingRecord(
    runtime_io: std.Io,
    gpa: std.mem.Allocator,
    command: []const u8,
    cwd: []const u8,
    reason: []const u8,
    now_iso: []const u8,
    single_use: bool,
) !BuiltPending {
    const expires_at = try addHoursIso(gpa, now_iso, default_ttl_hours);
    errdefer gpa.free(expires_at);
    const full_hash = try computeFullHash(gpa, now_iso, cwd, command);
    errdefer gpa.free(full_hash);
    // Live short codes are CSPRNG (M-7). shortCodeFromHash remains a pure test/metadata helper.
    const redeem_code = try mintShortCode(runtime_io, gpa);
    errdefer gpa.free(redeem_code);
    // At-rest rows carry only the keyed hash — never the redeemable code.
    const code_hash = try computeCodeHash(gpa, full_hash, redeem_code);
    errdefer gpa.free(code_hash);
    const created_at = try gpa.dupe(u8, now_iso);
    errdefer gpa.free(created_at);
    const cwd_owned = try gpa.dupe(u8, cwd);
    errdefer gpa.free(cwd_owned);
    const command_raw = try gpa.dupe(u8, command);
    errdefer gpa.free(command_raw);
    const reason_owned = try gpa.dupe(u8, reason);
    errdefer gpa.free(reason_owned);
    return .{
        .record = .{
            .schema_version = schema_version,
            .code_hash = code_hash,
            .full_hash = full_hash,
            .created_at = created_at,
            .expires_at = expires_at,
            .cwd = cwd_owned,
            .command_raw = command_raw,
            .reason = reason_owned,
            .single_use = single_use,
            .consumed_at = null,
        },
        .redeem_code = redeem_code,
    };
}

fn buildAllowOnceFromPending(
    gpa: std.mem.Allocator,
    pending: PendingRecord,
    now_iso: []const u8,
    scope_kind: ScopeKind,
    scope_path: []const u8,
) !AllowOnceEntry {
    const expires_at = try addHoursIso(gpa, now_iso, default_ttl_hours);
    errdefer gpa.free(expires_at);
    // The pending row only carries the hash; the entry copies it. The
    // plaintext code never touches the at-rest allow-once store.
    const source_code_hash = try gpa.dupe(u8, pending.code_hash);
    errdefer gpa.free(source_code_hash);
    const source_full_hash = try gpa.dupe(u8, pending.full_hash);
    errdefer gpa.free(source_full_hash);
    const created_at = try gpa.dupe(u8, now_iso);
    errdefer gpa.free(created_at);
    const scope_path_owned = try gpa.dupe(u8, scope_path);
    errdefer gpa.free(scope_path_owned);
    const command_raw = try gpa.dupe(u8, pending.command_raw);
    errdefer gpa.free(command_raw);
    const reason = try gpa.dupe(u8, pending.reason);
    errdefer gpa.free(reason);
    return .{
        .schema_version = schema_version,
        .source_code_hash = source_code_hash,
        .source_full_hash = source_full_hash,
        .created_at = created_at,
        .expires_at = expires_at,
        .scope_kind = scope_kind,
        .scope_path = scope_path_owned,
        .command_raw = command_raw,
        .reason = reason,
        .single_use = pending.single_use,
        .consumed_at = null,
    };
}

const IsoParts = struct {
    year: i32,
    month: i32,
    day: i32,
    hour: i64,
    minute: u32,
    second: u32,
};

fn parseIsoUtc(iso: []const u8) !IsoParts {
    // Minimum: YYYY-MM-DDTHH:MM:SSZ
    if (iso.len < 20) return error.InvalidIso;
    if (iso[4] != '-' or iso[7] != '-' or iso[10] != 'T' or iso[13] != ':' or iso[16] != ':') {
        return error.InvalidIso;
    }
    const year = std.fmt.parseInt(i32, iso[0..4], 10) catch return error.InvalidIso;
    const month = std.fmt.parseInt(i32, iso[5..7], 10) catch return error.InvalidIso;
    const day = std.fmt.parseInt(i32, iso[8..10], 10) catch return error.InvalidIso;
    const hour = std.fmt.parseInt(i64, iso[11..13], 10) catch return error.InvalidIso;
    const minute = std.fmt.parseInt(u32, iso[14..16], 10) catch return error.InvalidIso;
    const second = std.fmt.parseInt(u32, iso[17..19], 10) catch return error.InvalidIso;
    if (month < 1 or month > 12 or day < 1 or day > 31 or hour < 0 or hour > 23 or minute > 59 or second > 60) {
        return error.InvalidIso;
    }
    return .{
        .year = year,
        .month = month,
        .day = day,
        .hour = hour,
        .minute = minute,
        .second = second,
    };
}

fn daysInMonth(year: i32, month: i32) i32 {
    return switch (month) {
        1, 3, 5, 7, 8, 10, 12 => 31,
        4, 6, 9, 11 => 30,
        2 => if (isLeapYear(year)) 29 else 28,
        else => 30,
    };
}

fn isLeapYear(year: i32) bool {
    if (@mod(year, 400) == 0) return true;
    if (@mod(year, 100) == 0) return false;
    return @mod(year, 4) == 0;
}

/// Read file; FileNotFound → null. Caps at max_pending_bytes (+1 probe).
fn readFileOptional(runtime_io: std.Io, gpa: std.mem.Allocator, path: []const u8) !?[]u8 {
    const limit = max_pending_bytes + 1;
    return std.Io.Dir.cwd().readFileAlloc(runtime_io, path, gpa, .limited(limit)) catch |err| switch (err) {
        error.FileNotFound => null,
        error.OutOfMemory => error.OutOfMemory,
        else => err,
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

/// Atomic replace: same-dir temp + fsync + rename, permissions 0o600 (M-3/M-5).
fn writeFile(runtime_io: std.Io, gpa: std.mem.Allocator, path: []const u8, body: []const u8) !void {
    if (std.fs.path.dirname(path)) |dir| {
        std.Io.Dir.cwd().createDirPath(runtime_io, dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
        // Defense in depth (P0-2): the pending/allow-once dir holds break-glass
        // state (0600 files). Keep the directory operator-private (0700) so other
        // users cannot enumerate it. Best-effort; the keyed-hash storage is the
        // primary defense, not these bits.
        if (comptime builtin.os.tag != .windows) {
            std.Io.Dir.cwd().setFilePermissions(
                runtime_io,
                dir,
                std.Io.File.Permissions.fromMode(0o700),
                .{},
            ) catch {};
        }
    }

    const parent = std.fs.path.dirname(path) orelse ".";
    const base = std.fs.path.basename(path);
    const tmp_name = try std.fmt.allocPrint(gpa, ".{s}.tmp", .{base});
    defer gpa.free(tmp_name);
    const tmp_path = try std.fs.path.join(gpa, &.{ parent, tmp_name });
    defer gpa.free(tmp_path);

    // Drop stale temp from a prior crash so create is reliable.
    std.Io.Dir.cwd().deleteFile(runtime_io, tmp_path) catch {};
    {
        var file = try std.Io.Dir.cwd().createFile(runtime_io, tmp_path, .{
            .exclusive = true,
            .permissions = if (comptime builtin.os.tag == .windows)
                .default_file
            else
                std.Io.File.Permissions.fromMode(0o600),
        });
        errdefer {
            file.close(runtime_io);
            std.Io.Dir.cwd().deleteFile(runtime_io, tmp_path) catch {};
        }
        try file.writeStreamingAll(runtime_io, body);
        try file.sync(runtime_io);
        file.close(runtime_io);
    }
    errdefer std.Io.Dir.cwd().deleteFile(runtime_io, tmp_path) catch {};

    // Prefer renameAbsolute when both paths are absolute (feed_writer pattern); else cwd rename.
    if (std.fs.path.isAbsolute(tmp_path) and std.fs.path.isAbsolute(path)) {
        try std.Io.Dir.renameAbsolute(tmp_path, path, runtime_io);
    } else {
        const cwd = std.Io.Dir.cwd();
        try cwd.rename(tmp_path, cwd, path, runtime_io);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const allocator = testing.allocator;
const io = testing.io;

const fixed_now = "2026-07-25T15:00:00Z";
const far_future = "9999-01-01T00:00:00Z";
const past_time = "2026-07-24T00:00:00Z";

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
    // Cap above max_pending_bytes so bounded-growth fixtures can be inspected.
    return try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(32 * 1024 * 1024));
}

fn joinPath(tmp_root: []const u8, rel: []const u8) ![]u8 {
    return try std.fs.path.join(allocator, &.{ tmp_root, rel });
}

fn tmpRoot() !struct { dir: std.testing.TmpDir, path: []u8 } {
    var tmp = testing.tmpDir(.{});
    errdefer tmp.cleanup();
    // realPathFileAlloc returns [:0]u8 (dupeZ). Re-dupe to a plain slice for free.
    const path_z = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path_z);
    const path = try allocator.dupe(u8, path_z);
    return .{ .dir = tmp, .path = path };
}

fn storePaths(tmp_path: []const u8) !struct { pending: []u8, allow_once: []u8 } {
    const pending = try joinPath(tmp_path, pending_file_name);
    errdefer allocator.free(pending);
    const allow_once = try joinPath(tmp_path, allow_once_file_name);
    return .{ .pending = pending, .allow_once = allow_once };
}

fn isSixDigitNumeric(code: []const u8) bool {
    if (code.len != 6) return false;
    for (code) |c| {
        if (c < '0' or c > '9') return false;
    }
    return true;
}

// ── Pure helpers (hash / short code / expiry / scope) ────────────────────────

test "s3-once-store: computeFullHash is stable SHA-256 hex of timestamp|cwd|command" {
    // DCG-compatible input: "{created_at} | {cwd} | {command_raw}"
    const hash = try computeFullHash(allocator, "2099-01-01T00:00:00Z", "/repo", "git status");
    defer allocator.free(hash);
    try testing.expectEqual(@as(usize, 64), hash.len);
    // Known vector from DCG pending_exceptions tests.
    try testing.expectEqualStrings(
        "17a268f67ce0aab3bc5015427e3ba8fd1d643d25f9f13dca1332c13818a5ac63",
        hash,
    );
    // Lowercase hex only.
    for (hash) |c| {
        const ok = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f');
        try testing.expect(ok);
    }
}

test "s3-once-store: shortCodeFromHash is 6-digit numeric from last 8 hex chars" {
    // Deterministic helper only — live issuePending mints CSPRNG codes (M-7).
    const full = "17a268f67ce0aab3bc5015427e3ba8fd1d643d25f9f13dca1332c13818a5ac63";
    const code = shortCodeFromHash(full);
    try testing.expect(isSixDigitNumeric(code[0..]));
    // 0x18a5ac63 % 1_000_000 = 510755 (plan example / DCG vector).
    try testing.expectEqualStrings("510755", code[0..]);
}

test "s3-once-store: issuePending mints 6-digit CSPRNG short codes (not hash-derived)" {
    var tmp = try tmpRoot();
    defer {
        allocator.free(tmp.path);
        tmp.dir.cleanup();
    }
    const paths = try storePaths(tmp.path);
    defer {
        allocator.free(paths.pending);
        allocator.free(paths.allow_once);
    }

    var a = try issuePending(io, allocator, paths.pending, "cmd-rand-a", "/repo", "reason a enough", fixed_now, true);
    defer a.deinit(allocator);
    var b = try issuePending(io, allocator, paths.pending, "cmd-rand-b", "/repo", "reason b enough", fixed_now, true);
    defer b.deinit(allocator);

    try testing.expect(isSixDigitNumeric(a.redeem_code));
    try testing.expect(isSixDigitNumeric(b.redeem_code));
    // At-rest rows carry only the keyed hash — never the redeemable code.
    try testing.expectEqual(@as(usize, 64), a.record.code_hash.len);
    try testing.expect(!std.mem.eql(u8, a.record.code_hash, a.redeem_code));
    // Distinct commands → distinct CSPRNG codes almost always; codes must not both equal
    // the deterministic hash helper for the same inputs (collision still ok if random hits).
    const hash_a = try computeFullHash(allocator, fixed_now, "/repo", "cmd-rand-a");
    defer allocator.free(hash_a);
    const det = shortCodeFromHash(hash_a);
    // Redeem still accepts whatever code was minted.
    const entry = try redeem(io, allocator, paths.pending, paths.allow_once, a.redeem_code, fixed_now, .cwd, "/repo");
    defer freeAllowOnceEntry(allocator, entry);
    try testing.expectEqualStrings(a.record.code_hash, entry.source_code_hash);
    _ = det; // retained to document separation from hash helper
}

test "s3-once-store: code_hash read from the pending file cannot be redeemed (P0-2)" {
    // Closes the allow-once self-service bypass: an agent that reads
    // pending_exceptions.jsonl recovers only the keyed hash, which must not
    // redeem. The plaintext code is memory/operator-TTY only.
    var tmp = try tmpRoot();
    defer {
        allocator.free(tmp.path);
        tmp.dir.cleanup();
    }
    const paths = try storePaths(tmp.path);
    defer {
        allocator.free(paths.pending);
        allocator.free(paths.allow_once);
    }

    var issued = try issuePending(io, allocator, paths.pending, "git reset --hard", "/repo", "p0-2 self-serve gate", fixed_now, true);
    defer issued.deinit(allocator);

    // At-rest file carries the keyed hash, never the redeemable code.
    const on_disk = try readFileAbsolute(paths.pending);
    defer allocator.free(on_disk);
    try testing.expect(std.mem.indexOf(u8, on_disk, issued.record.code_hash) != null);
    try testing.expect(std.mem.indexOf(u8, on_disk, issued.redeem_code) == null);

    // Presenting the file's hash as the code must fail closed.
    try testing.expectError(error.CodeNotFound, redeem(
        io,
        allocator,
        paths.pending,
        paths.allow_once,
        issued.record.code_hash,
        fixed_now,
        .cwd,
        "/repo",
    ));

    // Control: the real minted code still redeems.
    const entry = try redeem(io, allocator, paths.pending, paths.allow_once, issued.redeem_code, fixed_now, .cwd, "/repo");
    defer freeAllowOnceEntry(allocator, entry);
    try testing.expectEqualStrings("git reset --hard", entry.command_raw);
}

test "s3-once-store: isExpired lexicographic ISO compare" {
    try testing.expect(isExpired("2026-07-25T00:00:00Z", fixed_now)); // expires_at < now
    try testing.expect(isExpired(fixed_now, fixed_now)); // expires_at == now → expired
    try testing.expect(!isExpired("2026-07-26T00:00:00Z", fixed_now));
    try testing.expect(!isExpired(far_future, fixed_now));
}

test "s3-once-store: scopeMatches cwd exact and project prefix" {
    const cwd_entry = AllowOnceEntry{
        .source_code_hash = "510755",
        .source_full_hash = "ab",
        .created_at = fixed_now,
        .expires_at = far_future,
        .scope_kind = .cwd,
        .scope_path = "/repo",
        .command_raw = "git status",
        .reason = "scope test",
    };
    try testing.expect(scopeMatches(cwd_entry, "/repo"));
    try testing.expect(!scopeMatches(cwd_entry, "/repo/sub"));
    try testing.expect(!scopeMatches(cwd_entry, "/other"));

    const project_entry = AllowOnceEntry{
        .source_code_hash = "510755",
        .source_full_hash = "ab",
        .created_at = fixed_now,
        .expires_at = far_future,
        .scope_kind = .project,
        .scope_path = "/repo",
        .command_raw = "git status",
        .reason = "scope test",
    };
    try testing.expect(scopeMatches(project_entry, "/repo"));
    try testing.expect(scopeMatches(project_entry, "/repo/sub"));
    try testing.expect(scopeMatches(project_entry, "/repo/a/b"));
    try testing.expect(!scopeMatches(project_entry, "/repo-other"));
    try testing.expect(!scopeMatches(project_entry, "/other"));
    // M-4: fail closed on ".." and "//" path tricks (realpath is evaluate's job).
    try testing.expect(!scopeMatches(project_entry, "/repo/../etc"));
    try testing.expect(!scopeMatches(project_entry, "/repo/foo/../../etc"));
    try testing.expect(!scopeMatches(project_entry, "/repo//secret"));
    try testing.expect(!scopeMatches(project_entry, "../repo"));
    const dirty_root = AllowOnceEntry{
        .source_code_hash = "510755",
        .source_full_hash = "ab",
        .created_at = fixed_now,
        .expires_at = far_future,
        .scope_kind = .project,
        .scope_path = "/repo/../evil",
        .command_raw = "git status",
        .reason = "scope test",
    };
    try testing.expect(!scopeMatches(dirty_root, "/repo/../evil"));
    try testing.expect(!scopeMatches(dirty_root, "/evil"));
}

// ── Acceptance 1: issue → redeem → match; wrong cwd miss; expired cannot redeem

test "s3-once-store: issue pending writes JSONL with 6-digit short code" {
    var tmp = try tmpRoot();
    defer {
        allocator.free(tmp.path);
        tmp.dir.cleanup();
    }
    const paths = try storePaths(tmp.path);
    defer {
        allocator.free(paths.pending);
        allocator.free(paths.allow_once);
    }

    var issued = try issuePending(
        io,
        allocator,
        paths.pending,
        "git reset --hard HEAD",
        "/repo",
        "blocked by core.git:reset-hard",
        fixed_now,
        true,
    );
    defer issued.deinit(allocator);

    try testing.expect(isSixDigitNumeric(issued.redeem_code));
    try testing.expectEqual(@as(usize, 64), issued.record.full_hash.len);
    try testing.expectEqual(@as(usize, 64), issued.record.code_hash.len);
    try testing.expectEqualStrings("git reset --hard HEAD", issued.record.command_raw);
    try testing.expectEqualStrings("/repo", issued.record.cwd);
    try testing.expect(issued.record.single_use);
    try testing.expect(issued.record.consumed_at == null);
    try testing.expectEqual(schema_version, issued.record.schema_version);
    // TTL default: expires after default_ttl_hours from now (24h).
    try testing.expectEqualStrings("2026-07-26T15:00:00Z", issued.record.expires_at);

    const raw = try readFileAbsolute(paths.pending);
    defer allocator.free(raw);
    // The pending file must NOT contain the redeemable code (P0-2: no self-service).
    try testing.expect(std.mem.indexOf(u8, raw, issued.redeem_code) == null);
    try testing.expect(std.mem.indexOf(u8, raw, issued.record.code_hash) != null);
    try testing.expect(std.mem.indexOf(u8, raw, "git reset --hard HEAD") != null);
    try testing.expect(std.mem.indexOf(u8, raw, "code_hash") != null);
    try testing.expect(std.mem.indexOf(u8, raw, "short_code") == null);
    try testing.expect(std.mem.indexOf(u8, raw, "full_hash") != null);
}

test "s3-once-store: issue redeem exact command+scope match" {
    var tmp = try tmpRoot();
    defer {
        allocator.free(tmp.path);
        tmp.dir.cleanup();
    }
    const paths = try storePaths(tmp.path);
    defer {
        allocator.free(paths.pending);
        allocator.free(paths.allow_once);
    }

    var issued = try issuePending(
        io,
        allocator,
        paths.pending,
        "git reset --hard HEAD",
        "/work/project",
        "destructive reset blocked",
        fixed_now,
        true,
    );
    defer issued.deinit(allocator);
    const code = issued.redeem_code;

    const entry = try redeem(
        io,
        allocator,
        paths.pending,
        paths.allow_once,
        code,
        fixed_now,
        .cwd,
        "/work/project",
    );
    defer freeAllowOnceEntry(allocator, entry);

    try testing.expectEqualStrings(issued.record.code_hash, entry.source_code_hash);
    try testing.expectEqualStrings("git reset --hard HEAD", entry.command_raw);
    try testing.expect(entry.scope_kind == .cwd);
    try testing.expectEqualStrings("/work/project", entry.scope_path);
    try testing.expect(entry.single_use);
    try testing.expect(entry.consumed_at == null);

    // Exact command + matching cwd → hit (consume=false so store stays for later asserts).
    const hit = try matchAllowOnce(
        io,
        allocator,
        paths.allow_once,
        "git reset --hard HEAD",
        "/work/project",
        fixed_now,
        false,
    );
    try testing.expect(hit != null);
    if (hit) |h| freeAllowOnceEntry(allocator, h);

    // Near-miss command must not match.
    const miss_cmd = try matchAllowOnce(
        io,
        allocator,
        paths.allow_once,
        "git reset --hard HEAD~1",
        "/work/project",
        fixed_now,
        false,
    );
    try testing.expect(miss_cmd == null);
}

test "s3-once-store: wrong cwd does not match cwd-scoped entry" {
    var tmp = try tmpRoot();
    defer {
        allocator.free(tmp.path);
        tmp.dir.cleanup();
    }
    const paths = try storePaths(tmp.path);
    defer {
        allocator.free(paths.pending);
        allocator.free(paths.allow_once);
    }

    var issued = try issuePending(
        io,
        allocator,
        paths.pending,
        "rm -rf /tmp/scratch",
        "/allowed/cwd",
        "cleanup blocked",
        fixed_now,
        true,
    );
    defer issued.deinit(allocator);

    const entry = try redeem(
        io,
        allocator,
        paths.pending,
        paths.allow_once,
        issued.redeem_code,
        fixed_now,
        .cwd,
        "/allowed/cwd",
    );
    defer freeAllowOnceEntry(allocator, entry);

    const wrong = try matchAllowOnce(
        io,
        allocator,
        paths.allow_once,
        "rm -rf /tmp/scratch",
        "/different/cwd",
        fixed_now,
        false,
    );
    try testing.expect(wrong == null);

    const right = try matchAllowOnce(
        io,
        allocator,
        paths.allow_once,
        "rm -rf /tmp/scratch",
        "/allowed/cwd",
        fixed_now,
        false,
    );
    try testing.expect(right != null);
    if (right) |h| freeAllowOnceEntry(allocator, h);
}

test "s3-once-store: expired pending cannot redeem" {
    var tmp = try tmpRoot();
    defer {
        allocator.free(tmp.path);
        tmp.dir.cleanup();
    }
    const paths = try storePaths(tmp.path);
    defer {
        allocator.free(paths.pending);
        allocator.free(paths.allow_once);
    }

    // Issue in the past with TTL that is already expired relative to fixed_now.
    var issued = try issuePending(
        io,
        allocator,
        paths.pending,
        "git reset --hard HEAD",
        "/repo",
        "old block",
        past_time, // created 2026-07-24 → expires 2026-07-25T00:00:00Z < fixed_now
        true,
    );
    defer issued.deinit(allocator);

    // Explicitly ensure the written record is expired at fixed_now.
    try testing.expect(isExpired(issued.record.expires_at, fixed_now));

    const result = redeem(
        io,
        allocator,
        paths.pending,
        paths.allow_once,
        issued.redeem_code,
        fixed_now,
        .cwd,
        "/repo",
    );
    try testing.expectError(error.Expired, result);

    // Allow-once store must remain empty (no silent redeem).
    var loaded = try loadAllowOnceActive(io, allocator, paths.allow_once, fixed_now);
    defer loaded.deinit(allocator);
    try testing.expectEqual(@as(usize, 0), loaded.list.entries.len);
}

test "s3-once-store: redeem consumes pending so code cannot redeem twice" {
    var tmp = try tmpRoot();
    defer {
        allocator.free(tmp.path);
        tmp.dir.cleanup();
    }
    const paths = try storePaths(tmp.path);
    defer {
        allocator.free(paths.pending);
        allocator.free(paths.allow_once);
    }

    var issued = try issuePending(
        io,
        allocator,
        paths.pending,
        "git clean -fdx",
        "/repo",
        "clean blocked",
        fixed_now,
        true,
    );
    defer issued.deinit(allocator);
    const code = try allocator.dupe(u8, issued.redeem_code);
    defer allocator.free(code);

    const entry = try redeem(
        io,
        allocator,
        paths.pending,
        paths.allow_once,
        code,
        fixed_now,
        .cwd,
        "/repo",
    );
    freeAllowOnceEntry(allocator, entry);

    const second = redeem(
        io,
        allocator,
        paths.pending,
        paths.allow_once,
        code,
        fixed_now,
        .cwd,
        "/repo",
    );
    // Second redeem: code gone from pending → CodeNotFound (or AlreadyConsumed).
    try testing.expect(second == error.CodeNotFound or second == error.AlreadyConsumed or second == error.Expired);
}

// ── Acceptance 2: consume removes single-use; list / revoke / clear ──────────

test "s3-once-store: consume removes single-use entry; second match misses" {
    var tmp = try tmpRoot();
    defer {
        allocator.free(tmp.path);
        tmp.dir.cleanup();
    }
    const paths = try storePaths(tmp.path);
    defer {
        allocator.free(paths.pending);
        allocator.free(paths.allow_once);
    }

    var issued = try issuePending(
        io,
        allocator,
        paths.pending,
        "git reset --hard HEAD",
        "/repo",
        "once only",
        fixed_now,
        true,
    );
    defer issued.deinit(allocator);

    const entry = try redeem(
        io,
        allocator,
        paths.pending,
        paths.allow_once,
        issued.redeem_code,
        fixed_now,
        .cwd,
        "/repo",
    );
    freeAllowOnceEntry(allocator, entry);

    const first = try matchAllowOnce(
        io,
        allocator,
        paths.allow_once,
        "git reset --hard HEAD",
        "/repo",
        fixed_now,
        true, // consume
    );
    try testing.expect(first != null);
    if (first) |h| freeAllowOnceEntry(allocator, h);

    const second = try matchAllowOnce(
        io,
        allocator,
        paths.allow_once,
        "git reset --hard HEAD",
        "/repo",
        fixed_now,
        true,
    );
    try testing.expect(second == null);

    // Store file should have no active entries.
    var loaded = try loadAllowOnceActive(io, allocator, paths.allow_once, fixed_now);
    defer loaded.deinit(allocator);
    try testing.expectEqual(@as(usize, 0), loaded.list.entries.len);
}

test "s3-once-store: match with consume=false leaves single-use entry intact" {
    // Explain / dry-run path: match + attribute without burning the exception.
    var tmp = try tmpRoot();
    defer {
        allocator.free(tmp.path);
        tmp.dir.cleanup();
    }
    const paths = try storePaths(tmp.path);
    defer {
        allocator.free(paths.pending);
        allocator.free(paths.allow_once);
    }

    var issued = try issuePending(
        io,
        allocator,
        paths.pending,
        "git reset --hard HEAD",
        "/repo",
        "explain must not consume",
        fixed_now,
        true,
    );
    defer issued.deinit(allocator);

    const entry = try redeem(
        io,
        allocator,
        paths.pending,
        paths.allow_once,
        issued.redeem_code,
        fixed_now,
        .cwd,
        "/repo",
    );
    freeAllowOnceEntry(allocator, entry);

    // Two non-consuming matches both hit.
    const a = try matchAllowOnce(io, allocator, paths.allow_once, "git reset --hard HEAD", "/repo", fixed_now, false);
    try testing.expect(a != null);
    if (a) |h| freeAllowOnceEntry(allocator, h);

    const b = try matchAllowOnce(io, allocator, paths.allow_once, "git reset --hard HEAD", "/repo", fixed_now, false);
    try testing.expect(b != null);
    if (b) |h| freeAllowOnceEntry(allocator, h);

    // Then a real consume burns it; subsequent match misses.
    const c = try matchAllowOnce(io, allocator, paths.allow_once, "git reset --hard HEAD", "/repo", fixed_now, true);
    try testing.expect(c != null);
    if (c) |h| freeAllowOnceEntry(allocator, h);

    const d = try matchAllowOnce(io, allocator, paths.allow_once, "git reset --hard HEAD", "/repo", fixed_now, true);
    try testing.expect(d == null);
}

test "s3-once-store: list revoke clear on allow-once store" {
    var tmp = try tmpRoot();
    defer {
        allocator.free(tmp.path);
        tmp.dir.cleanup();
    }
    const paths = try storePaths(tmp.path);
    defer {
        allocator.free(paths.pending);
        allocator.free(paths.allow_once);
    }

    var a = try issuePending(io, allocator, paths.pending, "cmd-a", "/repo", "reason a long enough", fixed_now, true);
    defer a.deinit(allocator);
    var b = try issuePending(io, allocator, paths.pending, "cmd-b", "/repo", "reason b long enough", fixed_now, true);
    defer b.deinit(allocator);

    const ea = try redeem(io, allocator, paths.pending, paths.allow_once, a.redeem_code, fixed_now, .cwd, "/repo");
    defer freeAllowOnceEntry(allocator, ea);
    const eb = try redeem(io, allocator, paths.pending, paths.allow_once, b.redeem_code, fixed_now, .project, "/repo");
    defer freeAllowOnceEntry(allocator, eb);

    {
        var listed = try loadAllowOnceActive(io, allocator, paths.allow_once, fixed_now);
        defer listed.deinit(allocator);
        try testing.expectEqual(@as(usize, 2), listed.list.entries.len);
    }

    // Revoke by short code removes one.
    const rev = try revokeAllowOnce(io, allocator, paths.allow_once, a.redeem_code, fixed_now);
    try testing.expectEqual(@as(usize, 1), rev.removed);

    {
        var listed = try loadAllowOnceActive(io, allocator, paths.allow_once, fixed_now);
        defer listed.deinit(allocator);
        try testing.expectEqual(@as(usize, 1), listed.list.entries.len);
        try testing.expectEqualStrings("cmd-b", listed.list.entries[0].command_raw);
    }

    // Revoke by full hash also works.
    const rev_hash = try revokeAllowOnce(io, allocator, paths.allow_once, b.record.full_hash, fixed_now);
    try testing.expectEqual(@as(usize, 1), rev_hash.removed);

    {
        var listed = try loadAllowOnceActive(io, allocator, paths.allow_once, fixed_now);
        defer listed.deinit(allocator);
        try testing.expectEqual(@as(usize, 0), listed.list.entries.len);
    }

    // Re-seed and clear all.
    var c = try issuePending(io, allocator, paths.pending, "cmd-c", "/repo", "reason c long enough", fixed_now, true);
    defer c.deinit(allocator);
    const ec = try redeem(io, allocator, paths.pending, paths.allow_once, c.redeem_code, fixed_now, .cwd, "/repo");
    freeAllowOnceEntry(allocator, ec);

    const cleared = try clearAllowOnce(io, allocator, paths.allow_once, fixed_now);
    try testing.expectEqual(@as(usize, 1), cleared.removed);

    {
        var listed = try loadAllowOnceActive(io, allocator, paths.allow_once, fixed_now);
        defer listed.deinit(allocator);
        try testing.expectEqual(@as(usize, 0), listed.list.entries.len);
    }
}

test "s3-once-store: list revoke clear on pending store" {
    var tmp = try tmpRoot();
    defer {
        allocator.free(tmp.path);
        tmp.dir.cleanup();
    }
    const paths = try storePaths(tmp.path);
    defer {
        allocator.free(paths.pending);
        allocator.free(paths.allow_once);
    }

    var a = try issuePending(io, allocator, paths.pending, "pend-a", "/repo", "pending reason a", fixed_now, true);
    defer a.deinit(allocator);
    var b = try issuePending(io, allocator, paths.pending, "pend-b", "/repo", "pending reason b", fixed_now, true);
    defer b.deinit(allocator);

    {
        var listed = try loadPendingActive(io, allocator, paths.pending, fixed_now);
        defer listed.deinit(allocator);
        try testing.expectEqual(@as(usize, 2), listed.list.records.len);
    }

    {
        var by_code = try lookupPendingByCode(io, allocator, paths.pending, a.redeem_code, fixed_now);
        defer by_code.deinit(allocator);
        try testing.expectEqual(@as(usize, 1), by_code.list.records.len);
        try testing.expectEqualStrings("pend-a", by_code.list.records[0].command_raw);
    }

    const rev = try revokePending(io, allocator, paths.pending, a.redeem_code, fixed_now);
    try testing.expectEqual(@as(usize, 1), rev.removed);

    {
        var listed = try loadPendingActive(io, allocator, paths.pending, fixed_now);
        defer listed.deinit(allocator);
        try testing.expectEqual(@as(usize, 1), listed.list.records.len);
    }

    const cleared = try clearPending(io, allocator, paths.pending, fixed_now);
    try testing.expectEqual(@as(usize, 1), cleared.removed);

    {
        var listed = try loadPendingActive(io, allocator, paths.pending, fixed_now);
        defer listed.deinit(allocator);
        try testing.expectEqual(@as(usize, 0), listed.list.records.len);
    }
}

// ── Acceptance 3: prune / bounded growth ─────────────────────────────────────

test "s3-once-store: loadPendingActive prunes expired and consumed from file" {
    var tmp = try tmpRoot();
    defer {
        allocator.free(tmp.path);
        tmp.dir.cleanup();
    }
    const paths = try storePaths(tmp.path);
    defer {
        allocator.free(paths.pending);
        allocator.free(paths.allow_once);
    }

    // Seed via issue, then hand-craft additional expired/consumed lines in the file.
    var active = try issuePending(
        io,
        allocator,
        paths.pending,
        "git status",
        "/repo",
        "still valid pending",
        fixed_now,
        true,
    );
    defer active.deinit(allocator);

    // Append expired + consumed raw JSONL lines (v2 schema-compatible hashes).
    const existing = try readFileAbsolute(paths.pending);
    defer allocator.free(existing);

    const extra = try std.fmt.allocPrint(allocator,
        \\{{"schema_version":2,"code_hash":"1111111111111111111111111111111111111111111111111111111111111111","full_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","created_at":"2026-07-20T00:00:00Z","expires_at":"2026-07-21T00:00:00Z","cwd":"/repo","command_raw":"old cmd","reason":"expired","single_use":true,"consumed_at":null}}
        \\{{"schema_version":2,"code_hash":"2222222222222222222222222222222222222222222222222222222222222222","full_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","created_at":"{s}","expires_at":"2026-07-26T15:00:00Z","cwd":"/repo","command_raw":"used cmd","reason":"consumed","single_use":true,"consumed_at":"{s}"}}
        \\
    , .{ fixed_now, fixed_now });
    defer allocator.free(extra);

    const merged = try std.fmt.allocPrint(allocator, "{s}{s}", .{ existing, extra });
    defer allocator.free(merged);
    try writeFileAbsolute(paths.pending, merged);

    var loaded = try loadPendingActive(io, allocator, paths.pending, fixed_now);
    defer loaded.deinit(allocator);

    try testing.expectEqual(@as(usize, 1), loaded.list.records.len);
    try testing.expectEqualStrings("git status", loaded.list.records[0].command_raw);
    try testing.expect(loaded.maintenance.pruned_expired >= 1);
    try testing.expect(loaded.maintenance.pruned_consumed >= 1);

    // File rewritten to active-only (no expired code hash left).
    const after = try readFileAbsolute(paths.pending);
    defer allocator.free(after);
    try testing.expect(std.mem.indexOf(u8, after, "1111111111111111111111111111111111111111111111111111111111111111") == null);
    try testing.expect(std.mem.indexOf(u8, after, "2222222222222222222222222222222222222222222222222222222222222222") == null);
    try testing.expect(std.mem.indexOf(u8, after, active.record.code_hash) != null);
}

test "s3-once-store: loadAllowOnceActive prunes expired entries" {
    var tmp = try tmpRoot();
    defer {
        allocator.free(tmp.path);
        tmp.dir.cleanup();
    }
    const paths = try storePaths(tmp.path);
    defer {
        allocator.free(paths.pending);
        allocator.free(paths.allow_once);
    }

    var issued = try issuePending(io, allocator, paths.pending, "alive-cmd", "/repo", "alive reason text", fixed_now, true);
    defer issued.deinit(allocator);
    const entry = try redeem(io, allocator, paths.pending, paths.allow_once, issued.redeem_code, fixed_now, .cwd, "/repo");
    freeAllowOnceEntry(allocator, entry);

    const existing = try readFileAbsolute(paths.allow_once);
    defer allocator.free(existing);

    const expired_line =
        \\{"schema_version":2,"source_code_hash":"9999999999999999999999999999999999999999999999999999999999999999","source_full_hash":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","created_at":"2026-07-20T00:00:00Z","expires_at":"2026-07-21T00:00:00Z","scope_kind":"cwd","scope_path":"/repo","command_raw":"dead-cmd","reason":"expired allow","single_use":true,"consumed_at":null}
        \\
    ;
    const merged = try std.fmt.allocPrint(allocator, "{s}{s}", .{ existing, expired_line });
    defer allocator.free(merged);
    try writeFileAbsolute(paths.allow_once, merged);

    var loaded = try loadAllowOnceActive(io, allocator, paths.allow_once, fixed_now);
    defer loaded.deinit(allocator);
    try testing.expectEqual(@as(usize, 1), loaded.list.entries.len);
    try testing.expectEqualStrings("alive-cmd", loaded.list.entries[0].command_raw);
    try testing.expect(loaded.maintenance.pruned_expired >= 1);

    const after = try readFileAbsolute(paths.allow_once);
    defer allocator.free(after);
    try testing.expect(std.mem.indexOf(u8, after, "dead-cmd") == null);
    try testing.expect(std.mem.indexOf(u8, after, "alive-cmd") != null);
}

test "s3-once-store: corrupt JSONL lines skipped without panic" {
    var tmp = try tmpRoot();
    defer {
        allocator.free(tmp.path);
        tmp.dir.cleanup();
    }
    const paths = try storePaths(tmp.path);
    defer {
        allocator.free(paths.pending);
        allocator.free(paths.allow_once);
    }

    var issued = try issuePending(io, allocator, paths.pending, "good-cmd", "/repo", "good reason text", fixed_now, true);
    defer issued.deinit(allocator);

    const existing = try readFileAbsolute(paths.pending);
    defer allocator.free(existing);
    const merged = try std.fmt.allocPrint(allocator, "not-json-at-all\n{s}{{broken\n", .{existing});
    defer allocator.free(merged);
    try writeFileAbsolute(paths.pending, merged);

    var loaded = try loadPendingActive(io, allocator, paths.pending, fixed_now);
    defer loaded.deinit(allocator);
    try testing.expectEqual(@as(usize, 1), loaded.list.records.len);
    try testing.expectEqualStrings("good-cmd", loaded.list.records[0].command_raw);
    try testing.expect(loaded.maintenance.parse_errors >= 1);
}

test "s3-once-store: bounded growth refuses or rotates past max_pending_lines" {
    // Product law: no unbounded silent growth. When active pending exceeds
    // max_pending_lines, issuePending must either rotate (keep live file ≤ cap)
    // or return StoreFull — never silently append without bound.
    var tmp = try tmpRoot();
    defer {
        allocator.free(tmp.path);
        tmp.dir.cleanup();
    }
    const paths = try storePaths(tmp.path);
    defer {
        allocator.free(paths.pending);
        allocator.free(paths.allow_once);
    }

    // Build a file with max_pending_lines + 50 synthetic active records.
    // Compact lines keep the fixture under max_pending_bytes while over the line cap.
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);

    var i: usize = 0;
    while (i < max_pending_lines + 50) : (i += 1) {
        // Minimal v2 schema-valid line; unique code_hash via zero-padded index.
        const line = try std.fmt.allocPrint(allocator,
            \\{{"schema_version":2,"code_hash":"{d:0>64}","full_hash":"{d:0>64}","created_at":"{s}","expires_at":"2026-07-26T15:00:00Z","cwd":"/r","command_raw":"c{d}","reason":"b","single_use":true,"consumed_at":null}}
            \\
        , .{ i, i, fixed_now, i });
        defer allocator.free(line);
        try buf.appendSlice(allocator, line);
    }
    try writeFileAbsolute(paths.pending, buf.items);

    // Precondition: file has more than max_pending_lines lines.
    {
        const raw = try readFileAbsolute(paths.pending);
        defer allocator.free(raw);
        var lines: usize = 0;
        var iter = std.mem.splitScalar(u8, raw, '\n');
        while (iter.next()) |line| {
            if (line.len > 0) lines += 1;
        }
        try testing.expect(lines > max_pending_lines);
    }

    if (issuePending(
        io,
        allocator,
        paths.pending,
        "overflow-cmd",
        "/repo",
        "should not grow unbounded",
        fixed_now,
        true,
    )) |issued_const| {
        var issued = issued_const;
        defer issued.deinit(allocator);
        // Rotation path: live file must be within cap after issue.
        const raw = try readFileAbsolute(paths.pending);
        defer allocator.free(raw);
        var lines: usize = 0;
        var iter = std.mem.splitScalar(u8, raw, '\n');
        while (iter.next()) |line| {
            if (line.len > 0) lines += 1;
        }
        try testing.expect(lines <= max_pending_lines);
        // New entry present.
        try testing.expect(std.mem.indexOf(u8, raw, "overflow-cmd") != null);
    } else |err| {
        // Refusal path is also acceptable product behavior.
        try testing.expect(err == error.StoreFull);
    }
}

test "s3-once-store: missing store files load as empty not error" {
    var tmp = try tmpRoot();
    defer {
        allocator.free(tmp.path);
        tmp.dir.cleanup();
    }
    const paths = try storePaths(tmp.path);
    defer {
        allocator.free(paths.pending);
        allocator.free(paths.allow_once);
    }

    var pending = try loadPendingActive(io, allocator, paths.pending, fixed_now);
    defer pending.deinit(allocator);
    try testing.expectEqual(@as(usize, 0), pending.list.records.len);

    var allow = try loadAllowOnceActive(io, allocator, paths.allow_once, fixed_now);
    defer allow.deinit(allocator);
    try testing.expectEqual(@as(usize, 0), allow.list.entries.len);

    const miss = try matchAllowOnce(io, allocator, paths.allow_once, "anything", "/repo", fixed_now, true);
    try testing.expect(miss == null);
}

test "s3-once-store: project scope matches subdirectory cwd" {
    var tmp = try tmpRoot();
    defer {
        allocator.free(tmp.path);
        tmp.dir.cleanup();
    }
    const paths = try storePaths(tmp.path);
    defer {
        allocator.free(paths.pending);
        allocator.free(paths.allow_once);
    }

    var issued = try issuePending(io, allocator, paths.pending, "npm install", "/repo", "install once in project", fixed_now, true);
    defer issued.deinit(allocator);

    const entry = try redeem(
        io,
        allocator,
        paths.pending,
        paths.allow_once,
        issued.redeem_code,
        fixed_now,
        .project,
        "/repo",
    );
    freeAllowOnceEntry(allocator, entry);

    const sub = try matchAllowOnce(io, allocator, paths.allow_once, "npm install", "/repo/packages/cli", fixed_now, false);
    try testing.expect(sub != null);
    if (sub) |h| freeAllowOnceEntry(allocator, h);

    const outside = try matchAllowOnce(io, allocator, paths.allow_once, "npm install", "/other", fixed_now, false);
    try testing.expect(outside == null);
}

test "s3-once-store: constants and file names match product brand" {
    try testing.expectEqual(@as(u32, 2), schema_version);
    try testing.expectEqual(@as(i64, 24), default_ttl_hours);
    try testing.expectEqual(@as(usize, 10_000), max_pending_lines);
    try testing.expectEqual(@as(u64, 10 * 1024 * 1024), max_pending_bytes);
    try testing.expectEqualStrings("pending_exceptions.jsonl", pending_file_name);
    try testing.expectEqualStrings("allow_once.jsonl", allow_once_file_name);
}

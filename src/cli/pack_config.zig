//! Pack config path resolution and TOML enable/disable mutation.
//!
//! Keeps daemon-readable pack config writes out of the summary/doctor module
//! (`pack_state.zig`) so each file stays focused and under a healthy size.

const std = @import("std");
const plugin = @import("plugin.zig");

pub const ConfigScope = enum {
    project,
    user,

    pub fn label(self: ConfigScope) []const u8 {
        return switch (self) {
            .project => "project",
            .user => "user",
        };
    }
};

pub const ResolvedPackConfig = struct {
    path: []u8,
    scope: ConfigScope,
};

/// Result of `enablePacks` / `disablePacks` (CLI activation UX).
pub const PackMutationResult = struct {
    message: []const u8,
    config_path: ?[]const u8 = null,
    scope: ?ConfigScope = null,
    changed: bool = false,
    added: []const []const u8 = &.{},
    removed: []const []const u8 = &.{},
    disabled_added: []const []const u8 = &.{},
    baseline_notes: []const []const u8 = &.{},
    owned: bool = false,

    pub fn deinit(self: *PackMutationResult, allocator: std.mem.Allocator) void {
        if (!self.owned) return;
        allocator.free(self.message);
        if (self.config_path) |path| allocator.free(path);
        freeOwnedSlice(allocator, self.added);
        freeOwnedSlice(allocator, self.removed);
        freeOwnedSlice(allocator, self.disabled_added);
        freeOwnedSlice(allocator, self.baseline_notes);
        self.* = undefined;
    }
};

fn freeOwnedSlice(allocator: std.mem.Allocator, items: []const []const u8) void {
    for (items) |item| allocator.free(item);
    allocator.free(items);
}

/// Baseline packs that ship on by default (`core`, `core.*`, `system.disk`).
/// Zig `packIsActive` honors `disabled` for these — but only **user** config may
/// opt them out. Project `.ryk.toml` baseline disables are ignored at load
/// (untrusted agent-writable project files must not drop core safety packs).
pub fn isBaselinePackId(id: []const u8) bool {
    if (std.mem.eql(u8, id, "core") or std.mem.eql(u8, id, "system.disk")) return true;
    if (std.mem.startsWith(u8, id, "core.")) return true;
    return false;
}

/// True when a `disabled` list token would deactivate any baseline pack via
/// category shorthand (`disabled=["system"]` → `system.disk`) or exact id (F30/M-8).
pub fn isBaselineDisabledToken(id: []const u8) bool {
    if (isBaselinePackId(id)) return true;
    // Category tokens without `.` match pack_id prefix in packIdListed.
    if (std.mem.indexOfScalar(u8, id, '.') != null or id.len == 0) return false;
    // Known baseline leaves under this category prefix.
    if (std.mem.eql(u8, id, "system")) return true; // system.disk
    if (std.mem.eql(u8, id, "core")) return true; // already baseline; defensive
    return false;
}

/// Operator presence for break-glass mutations (baseline pack disable and other
/// operator-only changes). The only trustworthy signal is an interactive
/// controlling terminal: environment variables are per-invocation and fully
/// child-controlled, so an agent subprocess can set any var on itself. A TTY is
/// the boundary an agent cannot fabricate for a human. Non-TTY → false (fail
/// closed); callers then run the interactive danger-confirmation prompt.
pub fn isOperatorBreakGlass(io: std.Io) bool {
    return (std.Io.File.stdin().isTty(io) catch false) and
        (std.Io.File.stdout().isTty(io) catch false);
}

/// Project pack config markers: same as workspace product markers (`.git` or policy).
fn workspaceHasProjectPackMarker(io: std.Io, allocator: std.mem.Allocator, workspace_root: []const u8) bool {
    const git_path = std.fs.path.join(allocator, &.{ workspace_root, ".git" }) catch return false;
    defer allocator.free(git_path);
    if (plugin.fileExistsAbsolute(io, git_path) or plugin.dirExists(git_path)) return true;

    const policy_path = std.fs.path.join(allocator, &.{ workspace_root, ".ryk", "policy.yaml" }) catch return false;
    defer allocator.free(policy_path);
    return plugin.fileExistsAbsolute(io, policy_path);
}

/// Cwd-scoped pack enable/disable lists for the production Zig shell evaluator.
pub const LoadedPackIds = struct {
    enabled: []const []const u8 = &.{},
    disabled: []const []const u8 = &.{},
    owned: bool = false,

    pub fn deinit(self: *LoadedPackIds, allocator: std.mem.Allocator) void {
        if (!self.owned) return;
        freeOwnedSlice(allocator, self.enabled);
        freeOwnedSlice(allocator, self.disabled);
        self.* = undefined;
    }
};

/// Load `[packs] enabled` / `disabled` for the workspace (project `.ryk.toml` when
/// the workspace has `.git` or `.ryk/policy.yaml`, otherwise user config).
///
/// **Baseline safety:** project-scoped `disabled` entries for `core` / `core.*` /
/// `system.disk` are stripped (untrusted project files cannot drop baseline packs).
/// User config may still opt out baseline packs; those are merged in when the
/// active scope is project.
/// Missing config → empty lists (baseline only).
pub fn loadPackIdsForWorkspace(
    io: std.Io,
    allocator: std.mem.Allocator,
    workspace_root: []const u8,
) !LoadedPackIds {
    const resolved = resolvePackConfigPath(io, allocator, workspace_root) catch |err| switch (err) {
        error.HomeDirectoryNotFound => return .{},
        else => return err,
    };
    defer allocator.free(resolved.path);

    var lists = loadPackIdLists(io, allocator, resolved.path) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        // User-scope config under Seatbelt "no bare home" (or missing HOME path) is
        // unreadable by design → baseline packs only, not a shell hard-deny.
        else => {
            if (resolved.scope == .user and isSandboxUserConfigAccessError(err)) return .{};
            return err;
        },
    };
    errdefer lists.deinit(allocator);

    if (resolved.scope == .project) {
        // Project file must never turn off baseline packs (M-8).
        try stripBaselineIdsFromList(allocator, &lists.disabled);
        // Operator baseline opt-outs live in user config; merge them in.
        try mergeUserBaselineDisabled(io, allocator, &lists.disabled);
    }

    const enabled = try lists.enabled.toOwnedSlice(allocator);
    lists.enabled = .empty;
    errdefer freeOwnedSlice(allocator, enabled);

    const disabled = try lists.disabled.toOwnedSlice(allocator);
    lists.disabled = .empty;

    // Drop raw file buffer / empty lists.
    lists.deinit(allocator);

    return .{
        .enabled = enabled,
        .disabled = disabled,
        .owned = true,
    };
}

/// Errors that mean "cannot read user config under sandbox residual", not "corrupt
/// project config". Soft-degrade to baseline-only / skip user merge.
fn isSandboxUserConfigAccessError(err: anyerror) bool {
    return err == error.AccessDenied or err == error.PermissionDenied;
}

/// Resolve where pack enablement should be written.
/// Prefers project `.ryk.toml` when workspace has `.git` or `.ryk/policy.yaml`.
pub fn resolvePackConfigPath(
    io: std.Io,
    allocator: std.mem.Allocator,
    workspace_root: []const u8,
) !ResolvedPackConfig {
    if (workspaceHasProjectPackMarker(io, allocator, workspace_root)) {
        const path = try std.fs.path.join(allocator, &.{ workspace_root, ".ryk.toml" });
        return .{ .path = path, .scope = .project };
    }
    return try resolveUserPackConfigPath(allocator);
}

/// Merge baseline-only entries from user pack config into `disabled` (owned ids).
///
/// Under hardened Seatbelt (no bare home), user config is often unreadable. That is
/// not a project-config failure: skip the merge (baseline packs stay enabled — safer
/// than failing closed on every shell command in-sandbox).
fn mergeUserBaselineDisabled(
    io: std.Io,
    allocator: std.mem.Allocator,
    disabled: *std.ArrayListUnmanaged([]const u8),
) !void {
    const user = resolveUserPackConfigPath(allocator) catch return;
    defer allocator.free(user.path);

    var user_lists = loadPackIdLists(io, allocator, user.path) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            // Missing / unreadable user config: no baseline opt-outs to merge.
            return;
        },
    };
    defer user_lists.deinit(allocator);

    for (user_lists.disabled.items) |id| {
        if (!isBaselinePackId(id)) continue;
        if (listContains(disabled.items, id)) continue;
        try disabled.append(allocator, try allocator.dupe(u8, id));
    }
}

/// Free and remove baseline pack ids **and** category tokens that would
/// deactivate baseline packs (F30: `disabled=["system"]` must not drop `system.disk`).
fn stripBaselineIdsFromList(allocator: std.mem.Allocator, list: *std.ArrayListUnmanaged([]const u8)) !void {
    var i: usize = 0;
    while (i < list.items.len) {
        if (isBaselineDisabledToken(list.items[i])) {
            allocator.free(list.items[i]);
            _ = list.orderedRemove(i);
            continue;
        }
        i += 1;
    }
}

fn resolveUserPackConfigPath(allocator: std.mem.Allocator) !ResolvedPackConfig {
    if (std.c.getenv("XDG_CONFIG_HOME")) |xdg| {
        const path = try std.fs.path.join(allocator, &.{ std.mem.span(xdg), "ryk", "config.toml" });
        return .{ .path = path, .scope = .user };
    }
    const home = std.c.getenv("HOME") orelse return error.HomeDirectoryNotFound;
    const path = try std.fs.path.join(allocator, &.{ std.mem.span(home), ".config", "ryk", "config.toml" });
    return .{ .path = path, .scope = .user };
}

const MergeResult = struct {
    final_enabled: [][]const u8,
    changed: bool,
};

/// Additive merge of desired pack IDs into daemon-readable pack config (used by presets).
pub fn mergeEnabledPacksIntoConfig(
    io: std.Io,
    allocator: std.mem.Allocator,
    config_path: []const u8,
    desired: []const []const u8,
) !MergeResult {
    const existing_raw = readFileIfExists(io, allocator, config_path) catch null;
    defer if (existing_raw) |raw| allocator.free(raw);

    var enabled_set: std.StringArrayHashMapUnmanaged(void) = .empty;
    defer enabled_set.deinit(allocator);

    if (existing_raw) |raw| {
        try collectQuotedPackIds(allocator, raw, &enabled_set);
    }

    var changed = existing_raw == null;
    for (desired) |pack_id| {
        const gop = try enabled_set.getOrPut(allocator, pack_id);
        if (!gop.found_existing) {
            gop.key_ptr.* = pack_id;
            gop.value_ptr.* = {};
            changed = true;
        }
    }

    var final_list: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        for (final_list.items) |id| allocator.free(id);
        final_list.deinit(allocator);
    }
    for (desired) |pack_id| {
        try final_list.append(allocator, try allocator.dupe(u8, pack_id));
    }
    if (existing_raw) |raw| {
        var existing_ids: std.ArrayListUnmanaged([]const u8) = .empty;
        defer {
            for (existing_ids.items) |id| allocator.free(id);
            existing_ids.deinit(allocator);
        }
        try collectQuotedPackIdsOwned(allocator, raw, &existing_ids);
        for (existing_ids.items) |id| {
            var already = false;
            for (final_list.items) |have| {
                if (std.mem.eql(u8, have, id)) {
                    already = true;
                    break;
                }
            }
            if (!already) try final_list.append(allocator, try allocator.dupe(u8, id));
        }
    }

    if (!changed and existing_raw != null) {
        return .{
            .final_enabled = try final_list.toOwnedSlice(allocator),
            .changed = false,
        };
    }

    if (existing_raw) |raw| {
        const rewritten = try rewritePacksArrayKey(allocator, raw, "enabled", final_list.items);
        defer allocator.free(rewritten);
        try writeConfigFile(io, allocator, config_path, rewritten);
    } else {
        const body = try renderNewPackConfig(allocator, final_list.items);
        defer allocator.free(body);
        try writeConfigFile(io, allocator, config_path, body);
    }

    return .{
        .final_enabled = try final_list.toOwnedSlice(allocator),
        .changed = true,
    };
}

/// Additive enable of opt-in pack IDs into project/user pack config.
/// Baseline IDs are noted as always-on and cleared from disabled (including user
/// baseline opt-outs, which is where effective baseline disables live).
pub fn enablePacks(
    io: std.Io,
    allocator: std.mem.Allocator,
    workspace_root: []const u8,
    ids: []const []const u8,
) !PackMutationResult {
    if (ids.len == 0) return error.InvalidArguments;

    const resolved = try resolvePackConfigPath(io, allocator, workspace_root);
    errdefer allocator.free(resolved.path);

    var lists = try loadPackIdLists(io, allocator, resolved.path);
    defer lists.deinit(allocator);

    var added: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer freeList(allocator, &added);
    var baseline_notes: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer freeList(allocator, &baseline_notes);

    // Baseline opt-outs are stored in user config; clear them there when re-enabling.
    var resolved_changed = false;
    var user_changed = false;
    var user_path: ?[]u8 = null;
    defer if (user_path) |p| allocator.free(p);
    var user_lists: ?PackIdLists = null;
    defer if (user_lists) |*ul| ul.deinit(allocator);

    for (ids) |pack_id| {
        if (!looksLikePackId(pack_id)) return error.InvalidArguments;

        if (removeIdFromList(allocator, &lists.disabled, pack_id)) {
            resolved_changed = true;
        }

        if (isBaselinePackId(pack_id)) {
            // Also clear user-config baseline opt-out (effective disable home).
            if (resolved.scope == .project) {
                if (user_lists == null) {
                    const user = try resolveUserPackConfigPath(allocator);
                    user_path = user.path;
                    user_lists = try loadPackIdLists(io, allocator, user.path);
                }
                if (user_lists) |*ul| {
                    if (removeIdFromList(allocator, &ul.disabled, pack_id)) {
                        user_changed = true;
                    }
                }
            }
            const note = try std.fmt.allocPrint(
                allocator,
                "{s} is baseline (on by default); cleared any user opt-out — no need to list it in enabled",
                .{pack_id},
            );
            try baseline_notes.append(allocator, note);
            continue;
        }

        if (listContains(lists.enabled.items, pack_id)) continue;
        try lists.enabled.append(allocator, try allocator.dupe(u8, pack_id));
        try added.append(allocator, try allocator.dupe(u8, pack_id));
        resolved_changed = true;
    }

    if (resolved_changed) {
        try writePacksArrays(io, allocator, resolved.path, lists.existing_raw, lists.enabled.items, lists.disabled.items);
    }
    if (user_changed) {
        if (user_lists) |*ul| {
            try writePacksArrays(io, allocator, user_path.?, ul.existing_raw, ul.enabled.items, ul.disabled.items);
        }
    }

    return try finishMutationResult(allocator, resolved, .{
        .kind = .enable,
        .changed = resolved_changed or user_changed,
        .added = &added,
        .removed = null,
        .disabled_added = null,
        .baseline_notes = &baseline_notes,
    });
}

/// Disable pack IDs: opt-in removed from enabled on the workspace config;
/// baseline packs are opted out via **user** config only (never project `.ryk.toml`).
///
/// Zig `packIsActive` fully honors `disabled` for baseline packs once loaded from
/// user config. Project-scoped baseline disables are ignored at load (M-8).
pub fn disablePacks(
    io: std.Io,
    allocator: std.mem.Allocator,
    workspace_root: []const u8,
    ids: []const []const u8,
) !PackMutationResult {
    if (ids.len == 0) return error.InvalidArguments;

    const resolved = try resolvePackConfigPath(io, allocator, workspace_root);
    errdefer allocator.free(resolved.path);

    var lists = try loadPackIdLists(io, allocator, resolved.path);
    defer lists.deinit(allocator);

    var removed: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer freeList(allocator, &removed);
    var disabled_added: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer freeList(allocator, &disabled_added);
    var baseline_notes: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer freeList(allocator, &baseline_notes);
    var changed = false;

    // Baseline opt-outs always target user config (effective + not agent-writable project).
    var resolved_changed = false;
    var user_path: ?[]u8 = null;
    defer if (user_path) |p| allocator.free(p);
    var user_lists: ?PackIdLists = null;
    defer if (user_lists) |*ul| ul.deinit(allocator);
    var user_changed = false;

    for (ids) |pack_id| {
        if (!looksLikePackId(pack_id)) return error.InvalidArguments;

        if (isBaselinePackId(pack_id)) {
            // Never add baseline to project disabled list (M-8 / M-2).
            if (resolved.scope == .project) {
                if (removeIdFromList(allocator, &lists.enabled, pack_id)) {
                    try removed.append(allocator, try allocator.dupe(u8, pack_id));
                    resolved_changed = true;
                }
                // Strip any pre-existing project baseline disabled entry while we're here.
                if (removeIdFromList(allocator, &lists.disabled, pack_id)) {
                    resolved_changed = true;
                }

                if (user_lists == null) {
                    const user = try resolveUserPackConfigPath(allocator);
                    user_path = user.path;
                    user_lists = try loadPackIdLists(io, allocator, user.path);
                }
                if (user_lists) |*ul| {
                    if (!listContains(ul.disabled.items, pack_id)) {
                        try ul.disabled.append(allocator, try allocator.dupe(u8, pack_id));
                        try disabled_added.append(allocator, try allocator.dupe(u8, pack_id));
                        user_changed = true;
                    }
                }
                const note = try std.fmt.allocPrint(
                    allocator,
                    "{s}: baseline opt-out written to user config (Zig packIsActive honors disabled; project .ryk.toml baseline disabled entries are ignored at load)",
                    .{pack_id},
                );
                try baseline_notes.append(allocator, note);
            } else {
                // Already on user scope — write baseline disable there.
                if (removeIdFromList(allocator, &lists.enabled, pack_id)) {
                    try removed.append(allocator, try allocator.dupe(u8, pack_id));
                    resolved_changed = true;
                }
                if (!listContains(lists.disabled.items, pack_id)) {
                    try lists.disabled.append(allocator, try allocator.dupe(u8, pack_id));
                    try disabled_added.append(allocator, try allocator.dupe(u8, pack_id));
                    resolved_changed = true;
                }
                const note = try std.fmt.allocPrint(
                    allocator,
                    "{s}: baseline opted out via user disabled — Zig packIsActive honors this (not always-on)",
                    .{pack_id},
                );
                try baseline_notes.append(allocator, note);
            }
            continue;
        }

        if (removeIdFromList(allocator, &lists.enabled, pack_id)) {
            try removed.append(allocator, try allocator.dupe(u8, pack_id));
            resolved_changed = true;
        }
    }

    if (resolved_changed) {
        try writePacksArrays(io, allocator, resolved.path, lists.existing_raw, lists.enabled.items, lists.disabled.items);
    }
    if (user_changed) {
        if (user_lists) |*ul| {
            try writePacksArrays(io, allocator, user_path.?, ul.existing_raw, ul.enabled.items, ul.disabled.items);
        }
    }

    changed = resolved_changed or user_changed;

    return try finishMutationResult(allocator, resolved, .{
        .kind = .disable,
        .changed = changed,
        .added = null,
        .removed = &removed,
        .disabled_added = &disabled_added,
        .baseline_notes = &baseline_notes,
    });
}

const PackIdLists = struct {
    existing_raw: ?[]u8,
    enabled: std.ArrayListUnmanaged([]const u8) = .empty,
    disabled: std.ArrayListUnmanaged([]const u8) = .empty,

    fn deinit(self: *PackIdLists, allocator: std.mem.Allocator) void {
        if (self.existing_raw) |raw| allocator.free(raw);
        freeList(allocator, &self.enabled);
        freeList(allocator, &self.disabled);
        self.* = undefined;
    }
};

fn loadPackIdLists(io: std.Io, allocator: std.mem.Allocator, config_path: []const u8) !PackIdLists {
    var lists: PackIdLists = .{
        .existing_raw = readFileIfExists(io, allocator, config_path) catch |err| switch (err) {
            error.FileNotFound => null,
            // Unreadable / oversize / IO errors must surface so production can fail closed.
            else => return err,
        },
    };
    errdefer lists.deinit(allocator);
    if (lists.existing_raw) |raw| {
        try collectQuotedPackIdsOwned(allocator, raw, &lists.enabled);
        try collectQuotedIdsForKeyOwned(allocator, raw, "disabled", &lists.disabled);
    }
    return lists;
}

fn freeList(allocator: std.mem.Allocator, list: *std.ArrayListUnmanaged([]const u8)) void {
    for (list.items) |id| allocator.free(id);
    list.deinit(allocator);
}

const MutationKind = enum { enable, disable };

const MutationParts = struct {
    kind: MutationKind,
    changed: bool,
    added: ?*std.ArrayListUnmanaged([]const u8),
    removed: ?*std.ArrayListUnmanaged([]const u8),
    disabled_added: ?*std.ArrayListUnmanaged([]const u8),
    baseline_notes: *std.ArrayListUnmanaged([]const u8),
};

fn finishMutationResult(
    allocator: std.mem.Allocator,
    resolved: ResolvedPackConfig,
    parts: MutationParts,
) !PackMutationResult {
    const empty: []const []const u8 = &.{};
    const added_items = if (parts.added) |a| a.items else empty;
    const removed_items = if (parts.removed) |r| r.items else empty;
    const disabled_items = if (parts.disabled_added) |d| d.items else empty;

    const message = try formatMutationMessage(
        allocator,
        parts.kind,
        added_items,
        removed_items,
        disabled_items,
        parts.baseline_notes.items,
        parts.changed,
    );
    errdefer allocator.free(message);

    const added_owned = if (parts.added) |a| blk: {
        const slice = try a.toOwnedSlice(allocator);
        a.* = .empty;
        break :blk slice;
    } else empty;
    errdefer if (parts.added != null) freeOwnedSlice(allocator, added_owned);

    const removed_owned = if (parts.removed) |r| blk: {
        const slice = try r.toOwnedSlice(allocator);
        r.* = .empty;
        break :blk slice;
    } else empty;
    errdefer if (parts.removed != null) freeOwnedSlice(allocator, removed_owned);

    const disabled_owned = if (parts.disabled_added) |d| blk: {
        const slice = try d.toOwnedSlice(allocator);
        d.* = .empty;
        break :blk slice;
    } else empty;
    errdefer if (parts.disabled_added != null) freeOwnedSlice(allocator, disabled_owned);

    const notes_owned = try parts.baseline_notes.toOwnedSlice(allocator);
    parts.baseline_notes.* = .empty;

    return .{
        .message = message,
        .config_path = resolved.path,
        .scope = resolved.scope,
        .changed = parts.changed,
        .added = added_owned,
        .removed = removed_owned,
        .disabled_added = disabled_owned,
        .baseline_notes = notes_owned,
        .owned = true,
    };
}

fn formatMutationMessage(
    allocator: std.mem.Allocator,
    kind: MutationKind,
    added: []const []const u8,
    removed: []const []const u8,
    disabled_added: []const []const u8,
    baseline_notes: []const []const u8,
    changed: bool,
) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    switch (kind) {
        .enable => {
            if (added.len == 0 and !changed) {
                try buf.appendSlice(allocator, "No pack config changes (already enabled or baseline only)");
            } else if (added.len == 0 and changed) {
                try buf.appendSlice(allocator, "Updated pack config (baseline / disabled list)");
            } else {
                try buf.appendSlice(allocator, "Enabled ");
                try appendIdList(allocator, &buf, added);
            }
        },
        .disable => {
            if (!changed) {
                try buf.appendSlice(allocator, "No pack config changes (already disabled or not enabled)");
            } else {
                if (removed.len > 0) {
                    try buf.appendSlice(allocator, "Disabled ");
                    try appendIdList(allocator, &buf, removed);
                }
                if (disabled_added.len > 0) {
                    if (buf.items.len > 0) try buf.appendSlice(allocator, "; ");
                    try buf.appendSlice(allocator, "opted out ");
                    try appendIdList(allocator, &buf, disabled_added);
                    try buf.appendSlice(allocator, " via disabled");
                }
                if (buf.items.len == 0) {
                    try buf.appendSlice(allocator, "Updated pack config");
                }
            }
        },
    }
    if (baseline_notes.len > 0) {
        try buf.appendSlice(allocator, " · ");
        try buf.appendSlice(allocator, baseline_notes[0]);
        if (baseline_notes.len > 1) {
            const more = try std.fmt.allocPrint(allocator, " (+{d} more notes)", .{baseline_notes.len - 1});
            defer allocator.free(more);
            try buf.appendSlice(allocator, more);
        }
    }
    return try buf.toOwnedSlice(allocator);
}

fn appendIdList(allocator: std.mem.Allocator, buf: *std.ArrayListUnmanaged(u8), ids: []const []const u8) !void {
    for (ids, 0..) |id, i| {
        if (i > 0) try buf.appendSlice(allocator, ", ");
        try buf.appendSlice(allocator, id);
    }
}

fn listContains(haystack: []const []const u8, needle: []const u8) bool {
    for (haystack) |id| {
        if (std.mem.eql(u8, id, needle)) return true;
    }
    return false;
}

fn removeIdFromList(allocator: std.mem.Allocator, list: *std.ArrayListUnmanaged([]const u8), id: []const u8) bool {
    var i: usize = 0;
    while (i < list.items.len) : (i += 1) {
        if (std.mem.eql(u8, list.items[i], id)) {
            allocator.free(list.items[i]);
            _ = list.orderedRemove(i);
            return true;
        }
    }
    return false;
}

fn writePacksArrays(
    io: std.Io,
    allocator: std.mem.Allocator,
    config_path: []const u8,
    existing_raw: ?[]const u8,
    enabled: []const []const u8,
    disabled: []const []const u8,
) !void {
    if (existing_raw) |raw| {
        const rewritten = try rewritePacksArrayKey(allocator, raw, "enabled", enabled);
        defer allocator.free(rewritten);
        const with_disabled = try rewritePacksArrayKey(allocator, rewritten, "disabled", disabled);
        defer allocator.free(with_disabled);
        try writeConfigFile(io, allocator, config_path, with_disabled);
    } else {
        const body = try renderNewPackConfigWithDisabled(allocator, enabled, disabled);
        defer allocator.free(body);
        try writeConfigFile(io, allocator, config_path, body);
    }
}

fn readFileIfExists(io: std.Io, allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(1024 * 1024)) catch |err| switch (err) {
        error.FileNotFound => return error.FileNotFound,
        else => return err,
    };
}

fn writeConfigFile(io: std.Io, allocator: std.mem.Allocator, path: []const u8, contents: []const u8) !void {
    if (std.fs.path.dirname(path)) |dir| {
        std.Io.Dir.cwd().createDirPath(io, dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
    }
    _ = allocator;
    var file = try std.Io.Dir.cwd().createFile(io, path, .{});
    defer file.close(io);
    try file.writeStreamingAll(io, contents);
}

fn renderNewPackConfig(allocator: std.mem.Allocator, enabled: []const []const u8) ![]u8 {
    return renderNewPackConfigWithDisabled(allocator, enabled, &.{});
}

fn renderNewPackConfigWithDisabled(
    allocator: std.mem.Allocator,
    enabled: []const []const u8,
    disabled: []const []const u8,
) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    try buf.appendSlice(allocator,
        \\# ryk pack configuration
        \\# Written by `ryk init` / `ryk start` / `ryk packs enable|disable`.
        \\# Prefer project `.ryk.toml` in a git repo; otherwise user config.
        \\# Baseline packs (core.*, system.disk) are always on and need not be listed.
        \\# Additive: re-running setup merges packs and does not wipe customizations.
        \\
        \\[packs]
        \\enabled = [
    );
    for (enabled, 0..) |id, i| {
        if (i > 0) try buf.appendSlice(allocator, ",");
        try buf.appendSlice(allocator, "\n    \"");
        try buf.appendSlice(allocator, id);
        try buf.appendSlice(allocator, "\"");
    }
    if (enabled.len > 0) try buf.appendSlice(allocator, "\n");
    try buf.appendSlice(allocator, "]\ndisabled = ");
    const disabled_arr = try renderTomlStringArray(allocator, disabled);
    defer allocator.free(disabled_arr);
    try buf.appendSlice(allocator, disabled_arr);
    try buf.appendSlice(allocator, "\n");
    return try buf.toOwnedSlice(allocator);
}

fn renderTomlStringArray(allocator: std.mem.Allocator, values: []const []const u8) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    try buf.appendSlice(allocator, "[\n");
    for (values, 0..) |id, i| {
        try buf.appendSlice(allocator, "    \"");
        try buf.appendSlice(allocator, id);
        try buf.appendSlice(allocator, "\"");
        if (i + 1 < values.len) try buf.appendSlice(allocator, ",");
        try buf.appendSlice(allocator, "\n");
    }
    try buf.appendSlice(allocator, "]");
    return try buf.toOwnedSlice(allocator);
}

/// Replace or append a `[packs] <key> = [...]` array while preserving other content.
fn rewritePacksArrayKey(
    allocator: std.mem.Allocator,
    existing: []const u8,
    key: []const u8,
    values: []const []const u8,
) ![]u8 {
    const new_array = try renderTomlStringArray(allocator, values);
    defer allocator.free(new_array);

    if (std.mem.indexOf(u8, existing, "[packs]") == null) {
        if (std.mem.eql(u8, key, "enabled")) {
            return try std.fmt.allocPrint(allocator, "{s}\n[packs]\nenabled = {s}\ndisabled = []\n", .{ existing, new_array });
        }
        return try std.fmt.allocPrint(allocator, "{s}\n[packs]\nenabled = []\ndisabled = {s}\n", .{ existing, new_array });
    }

    if (packsArraySlice(existing, key)) |array_slice| {
        const bounds = packsSectionBounds(existing).?;
        const section = existing[bounds.start..bounds.end];
        const rel = std.mem.indexOf(u8, section, array_slice) orelse {
            return try std.fmt.allocPrint(allocator, "{s}\n{s} = {s}\n", .{ existing, key, new_array });
        };
        const abs = bounds.start + rel;
        return try std.fmt.allocPrint(allocator, "{s}{s}{s}", .{ existing[0..abs], new_array, existing[abs + array_slice.len ..] });
    }

    // Key missing: insert after the other packs array when present, else after [packs] line.
    const packs_idx = std.mem.indexOf(u8, existing, "[packs]").?;
    const other_key: []const u8 = if (std.mem.eql(u8, key, "enabled")) "disabled" else "enabled";
    if (packsArraySlice(existing, other_key)) |other_slice| {
        const bounds = packsSectionBounds(existing).?;
        const section = existing[bounds.start..bounds.end];
        const rel = std.mem.indexOf(u8, section, other_slice) orelse {
            return insertAfterPacksHeader(allocator, existing, packs_idx, key, new_array);
        };
        const abs_end = bounds.start + rel + other_slice.len;
        // When inserting enabled and disabled already exists first, put enabled before disabled.
        if (std.mem.eql(u8, key, "enabled")) {
            const abs_start = bounds.start + rel;
            return try std.fmt.allocPrint(
                allocator,
                "{s}{s} = {s}\n{s}",
                .{ existing[0..abs_start], key, new_array, existing[abs_start..] },
            );
        }
        return try std.fmt.allocPrint(
            allocator,
            "{s}\n{s} = {s}{s}",
            .{ existing[0..abs_end], key, new_array, existing[abs_end..] },
        );
    }

    return insertAfterPacksHeader(allocator, existing, packs_idx, key, new_array);
}

fn insertAfterPacksHeader(
    allocator: std.mem.Allocator,
    existing: []const u8,
    packs_idx: usize,
    key: []const u8,
    new_array: []const u8,
) ![]u8 {
    var line_end = packs_idx;
    while (line_end < existing.len and existing[line_end] != '\n') : (line_end += 1) {}
    if (line_end < existing.len) line_end += 1;
    return try std.fmt.allocPrint(
        allocator,
        "{s}{s} = {s}\n{s}",
        .{ existing[0..line_end], key, new_array, existing[line_end..] },
    );
}

/// Locate a `[packs] <key> = [...]` array value (section-bounded, key-token aware).
fn packsArraySlice(content: []const u8, key: []const u8) ?[]const u8 {
    const bounds = packsSectionBounds(content) orelse return null;
    const section = content[bounds.start..bounds.end];

    var pos: usize = 0;
    while (pos < section.len) {
        const rel = std.mem.indexOf(u8, section[pos..], key) orelse break;
        const abs = pos + rel;
        if (abs > 0) {
            const prev = section[abs - 1];
            if (prev != '\n' and prev != '\r' and prev != ' ' and prev != '\t') {
                pos = abs + key.len;
                continue;
            }
        }
        // Skip keys that only appear in TOML comments on this line.
        var line_start = abs;
        while (line_start > 0 and section[line_start - 1] != '\n' and section[line_start - 1] != '\r') : (line_start -= 1) {}
        var scan = line_start;
        while (scan < abs and (section[scan] == ' ' or section[scan] == '\t')) : (scan += 1) {}
        if (scan < abs and section[scan] == '#') {
            pos = abs + key.len;
            continue;
        }
        // Reject partial token matches (e.g. key="enabled" must not match "disabled").
        const after = abs + key.len;
        if (after < section.len) {
            const next = section[after];
            const is_ident = (next >= 'a' and next <= 'z') or
                (next >= 'A' and next <= 'Z') or
                (next >= '0' and next <= '9') or
                next == '_' or next == '-';
            if (is_ident) {
                pos = after;
                continue;
            }
        }
        var cursor = after;
        while (cursor < section.len and (section[cursor] == ' ' or section[cursor] == '\t')) : (cursor += 1) {}
        if (cursor >= section.len or section[cursor] != '=') {
            pos = after;
            continue;
        }
        cursor += 1;
        while (cursor < section.len and (section[cursor] == ' ' or section[cursor] == '\t' or section[cursor] == '\n' or section[cursor] == '\r')) : (cursor += 1) {}
        if (cursor >= section.len or section[cursor] != '[') {
            pos = after;
            continue;
        }
        const array_start = cursor;
        var depth: usize = 0;
        var ve = cursor;
        while (ve < section.len) : (ve += 1) {
            if (section[ve] == '[') depth += 1;
            if (section[ve] == ']') {
                depth -= 1;
                if (depth == 0) {
                    ve += 1;
                    return section[array_start..ve];
                }
            }
        }
        return null;
    }
    return null;
}

fn packsSectionBounds(content: []const u8) ?struct { start: usize, end: usize } {
    const packs_idx = std.mem.indexOf(u8, content, "[packs]") orelse return null;
    var end = content.len;
    var search = packs_idx + "[packs]".len;
    while (search < content.len) : (search += 1) {
        if (content[search] == '\n' and search + 1 < content.len and content[search + 1] == '[') {
            const line_start = search + 1;
            if (std.mem.startsWith(u8, content[line_start..], "[")) {
                end = line_start;
                break;
            }
        }
    }
    return .{ .start = packs_idx, .end = end };
}

fn looksLikePackId(id: []const u8) bool {
    if (id.len == 0) return false;
    for (id) |c| {
        const ok = (c >= 'a' and c <= 'z') or
            (c >= 'A' and c <= 'Z') or
            (c >= '0' and c <= '9') or
            c == '_' or c == '.' or c == '-';
        if (!ok) return false;
    }
    return true;
}

fn collectQuotedPackIds(allocator: std.mem.Allocator, content: []const u8, set: *std.StringArrayHashMapUnmanaged(void)) !void {
    try collectQuotedIdsForKey(allocator, content, "enabled", set);
}

fn collectQuotedIdsForKey(
    allocator: std.mem.Allocator,
    content: []const u8,
    key: []const u8,
    set: *std.StringArrayHashMapUnmanaged(void),
) !void {
    const array = packsArraySlice(content, key) orelse return;
    var i: usize = 0;
    while (i < array.len) : (i += 1) {
        const c = array[i];
        if (c != '"' and c != '\'') continue;
        const q = c;
        const start = i + 1;
        const close = std.mem.indexOfScalar(u8, array[start..], q) orelse break;
        const id = array[start .. start + close];
        if (looksLikePackId(id)) {
            const gop = try set.getOrPut(allocator, id);
            if (!gop.found_existing) {
                gop.key_ptr.* = id;
                gop.value_ptr.* = {};
            }
        }
        i = start + close;
    }
}

fn collectQuotedPackIdsOwned(allocator: std.mem.Allocator, content: []const u8, out: *std.ArrayListUnmanaged([]const u8)) !void {
    try collectQuotedIdsForKeyOwned(allocator, content, "enabled", out);
}

fn collectQuotedIdsForKeyOwned(
    allocator: std.mem.Allocator,
    content: []const u8,
    key: []const u8,
    out: *std.ArrayListUnmanaged([]const u8),
) !void {
    var set: std.StringArrayHashMapUnmanaged(void) = .empty;
    defer set.deinit(allocator);
    try collectQuotedIdsForKey(allocator, content, key, &set);
    var it = set.iterator();
    while (it.next()) |entry| {
        try out.append(allocator, try allocator.dupe(u8, entry.key_ptr.*));
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;
extern "c" fn unsetenv(name: [*:0]const u8) c_int;

/// Isolate XDG_CONFIG_HOME so host user pack config does not leak into load tests.
fn testIsolateXdg() !struct {
    tmp: std.testing.TmpDir,
    root: []u8,
    prev: ?[:0]u8,

    fn deinit(self: *@This()) void {
        if (self.prev) |value| {
            _ = setenv("XDG_CONFIG_HOME", value.ptr, 1);
            std.testing.allocator.free(value);
        } else {
            _ = unsetenv("XDG_CONFIG_HOME");
        }
        std.testing.allocator.free(self.root);
        self.tmp.cleanup();
    }
} {
    var tmp = std.testing.tmpDir(.{});
    errdefer tmp.cleanup();
    const root_z = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root_z);
    const root = try std.testing.allocator.dupe(u8, root_z);
    errdefer std.testing.allocator.free(root);

    const prev: ?[:0]u8 = if (std.c.getenv("XDG_CONFIG_HOME")) |v|
        try std.testing.allocator.dupeZ(u8, std.mem.sliceTo(v, 0))
    else
        null;
    errdefer if (prev) |p| std.testing.allocator.free(p);

    const root_z0 = try std.testing.allocator.dupeZ(u8, root);
    defer std.testing.allocator.free(root_z0);
    try std.testing.expectEqual(@as(c_int, 0), setenv("XDG_CONFIG_HOME", root_z0.ptr, 1));

    return .{ .tmp = tmp, .root = root, .prev = prev };
}

test "isBaselinePackId covers core and system.disk only" {
    try std.testing.expect(isBaselinePackId("core"));
    try std.testing.expect(isBaselinePackId("core.git"));
    try std.testing.expect(isBaselinePackId("core.filesystem"));
    try std.testing.expect(isBaselinePackId("system.disk"));
    try std.testing.expect(!isBaselinePackId("containers.docker"));
    try std.testing.expect(!isBaselinePackId("system.services"));
    try std.testing.expect(!isBaselinePackId("package_managers"));
}

test "isBaselineDisabledToken strips category system for M-8" {
    // F30: disabled=["system"] must not survive project load (deactivates system.disk).
    try std.testing.expect(isBaselineDisabledToken("system"));
    try std.testing.expect(isBaselineDisabledToken("system.disk"));
    try std.testing.expect(isBaselineDisabledToken("core"));
    try std.testing.expect(!isBaselineDisabledToken("containers"));
    try std.testing.expect(!isBaselineDisabledToken("package_managers"));
}

test "loadPackIdsForWorkspace strips project category disabled system token" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, ".git");
    const body =
        \\[packs]
        \\disabled = ["system", "strict_git"]
        \\
    ;
    const file = try tmp.dir.createFile(std.testing.io, ".ryk.toml", .{});
    defer file.close(std.testing.io);
    try file.writeStreamingAll(std.testing.io, body);

    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var xdg = try testIsolateXdg();
    defer xdg.deinit();

    var loaded = try loadPackIdsForWorkspace(std.testing.io, std.testing.allocator, root);
    defer loaded.deinit(std.testing.allocator);

    var saw_system = false;
    var saw_strict = false;
    for (loaded.disabled) |id| {
        if (std.mem.eql(u8, id, "system")) saw_system = true;
        if (std.mem.eql(u8, id, "strict_git")) saw_strict = true;
    }
    try std.testing.expect(!saw_system);
    try std.testing.expect(saw_strict);
}

test "loadPackIdsForWorkspace reads project .ryk.toml packs" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, ".git");
    const body =
        \\[packs]
        \\enabled = ["containers.docker", "package_managers"]
        \\disabled = ["system.disk", "strict_git"]
        \\
    ;
    const file = try tmp.dir.createFile(std.testing.io, ".ryk.toml", .{});
    defer file.close(std.testing.io);
    try file.writeStreamingAll(std.testing.io, body);

    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    // Isolate user config so host user baseline opt-outs do not leak into the assertion.
    var xdg = try testIsolateXdg();
    defer xdg.deinit();

    var loaded = try loadPackIdsForWorkspace(std.testing.io, std.testing.allocator, root);
    defer loaded.deinit(std.testing.allocator);

    try std.testing.expect(loaded.owned);
    var saw_docker = false;
    var saw_pkg = false;
    for (loaded.enabled) |id| {
        if (std.mem.eql(u8, id, "containers.docker")) saw_docker = true;
        if (std.mem.eql(u8, id, "package_managers")) saw_pkg = true;
    }
    try std.testing.expect(saw_docker);
    try std.testing.expect(saw_pkg);
    // M-8: project-sourced baseline disables (system.disk) are stripped at load.
    // Non-baseline disabled entries remain.
    var saw_strict = false;
    var saw_disk = false;
    for (loaded.disabled) |id| {
        if (std.mem.eql(u8, id, "strict_git")) saw_strict = true;
        if (std.mem.eql(u8, id, "system.disk")) saw_disk = true;
    }
    try std.testing.expect(saw_strict);
    try std.testing.expect(!saw_disk);
}

test "loadPackIdsForWorkspace strips project baseline disabled and merges user baseline" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, ".git");
    {
        const f = try tmp.dir.createFile(std.testing.io, ".ryk.toml", .{});
        defer f.close(std.testing.io);
        try f.writeStreamingAll(std.testing.io,
            \\[packs]
            \\enabled = ["containers.docker"]
            \\disabled = ["core.git", "system.disk"]
            \\
        );
    }
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var xdg = try testIsolateXdg();
    defer xdg.deinit();

    // User config opts out system.disk only — that must survive merge.
    {
        const user = try resolveUserPackConfigPath(std.testing.allocator);
        defer std.testing.allocator.free(user.path);
        try writeConfigFile(std.testing.io, std.testing.allocator, user.path,
            \\[packs]
            \\enabled = []
            \\disabled = ["system.disk"]
            \\
        );
    }

    var loaded = try loadPackIdsForWorkspace(std.testing.io, std.testing.allocator, root);
    defer loaded.deinit(std.testing.allocator);

    var saw_disk = false;
    var saw_core_git = false;
    for (loaded.disabled) |id| {
        if (std.mem.eql(u8, id, "system.disk")) saw_disk = true;
        if (std.mem.eql(u8, id, "core.git")) saw_core_git = true;
    }
    try std.testing.expect(saw_disk); // user baseline opt-out honored
    try std.testing.expect(!saw_core_git); // project baseline strip
}

test "loadPackIdsForWorkspace survives unreadable user config when merging baseline" {
    // Seatbelt residual: project config is readable; ~/.config/ryk is not.
    // Must not fail closed the whole shell eval (pack-config-load deny).
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, ".ryk");
    {
        const f = try tmp.dir.createFile(std.testing.io, ".ryk/policy.yaml", .{});
        defer f.close(std.testing.io);
        try f.writeStreamingAll(std.testing.io, "version: 1\n");
    }
    {
        const f = try tmp.dir.createFile(std.testing.io, ".ryk.toml", .{});
        defer f.close(std.testing.io);
        try f.writeStreamingAll(std.testing.io,
            \\[packs]
            \\enabled = ["package_managers"]
            \\
        );
    }
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var xdg = try testIsolateXdg();
    defer xdg.deinit();

    // Create user config then strip all permissions so loadPackIdLists hits AccessDenied.
    {
        const user = try resolveUserPackConfigPath(std.testing.allocator);
        defer std.testing.allocator.free(user.path);
        try writeConfigFile(std.testing.io, std.testing.allocator, user.path,
            \\[packs]
            \\disabled = ["system.disk"]
            \\
        );
        try std.Io.Dir.cwd().setFilePermissions(
            std.testing.io,
            user.path,
            std.Io.File.Permissions.fromMode(0o000),
            .{},
        );
    }

    var loaded = try loadPackIdsForWorkspace(std.testing.io, std.testing.allocator, root);
    defer loaded.deinit(std.testing.allocator);

    // Project enabled packs still load; user baseline opt-out is skipped (not deny-all).
    var saw_pkg = false;
    for (loaded.enabled) |id| {
        if (std.mem.eql(u8, id, "package_managers")) saw_pkg = true;
    }
    try std.testing.expect(saw_pkg);
    for (loaded.disabled) |id| {
        try std.testing.expect(!std.mem.eql(u8, id, "system.disk"));
    }
}

test "loadPackIdsForWorkspace user-scope AccessDenied degrades to baseline only" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;

    // No project markers → user scope. Point XDG at a directory we make unreadable.
    var xdg = try testIsolateXdg();
    defer xdg.deinit();

    const user = try resolveUserPackConfigPath(std.testing.allocator);
    defer std.testing.allocator.free(user.path);
    try writeConfigFile(std.testing.io, std.testing.allocator, user.path,
        \\[packs]
        \\enabled = ["containers.docker"]
        \\
    );
    try std.Io.Dir.cwd().setFilePermissions(
        std.testing.io,
        user.path,
        std.Io.File.Permissions.fromMode(0o000),
        .{},
    );

    // Workspace without project markers forces user scope.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var loaded = try loadPackIdsForWorkspace(std.testing.io, std.testing.allocator, root);
    defer loaded.deinit(std.testing.allocator);
    // Soft residual: empty lists (baseline only), not error.
    try std.testing.expectEqual(@as(usize, 0), loaded.enabled.len);
    try std.testing.expectEqual(@as(usize, 0), loaded.disabled.len);
}

test "resolvePackConfigPath treats .ryk/policy.yaml as project marker" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, ".ryk");
    {
        const f = try tmp.dir.createFile(std.testing.io, ".ryk/policy.yaml", .{});
        defer f.close(std.testing.io);
        try f.writeStreamingAll(std.testing.io, "version: 1\n");
    }
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    const resolved = try resolvePackConfigPath(std.testing.io, std.testing.allocator, root);
    defer std.testing.allocator.free(resolved.path);
    try std.testing.expect(resolved.scope == .project);
    try std.testing.expect(std.mem.endsWith(u8, resolved.path, ".ryk.toml"));
}

test "packsArraySlice does not treat disabled as enabled" {
    const content =
        \\[packs]
        \\disabled = ["system.disk"]
        \\enabled = ["package_managers"]
        \\
    ;
    const enabled = packsArraySlice(content, "enabled") orelse {
        try std.testing.expect(false);
        return;
    };
    const disabled = packsArraySlice(content, "disabled") orelse {
        try std.testing.expect(false);
        return;
    };
    try std.testing.expect(std.mem.indexOf(u8, enabled, "package_managers") != null);
    try std.testing.expect(std.mem.indexOf(u8, enabled, "system.disk") == null);
    try std.testing.expect(std.mem.indexOf(u8, disabled, "system.disk") != null);
    try std.testing.expect(std.mem.indexOf(u8, disabled, "package_managers") == null);
}

test "packsArraySlice ignores commented-out pack keys" {
    const content =
        \\[packs]
        \\enabled = ["containers.docker"]
        \\# disabled = ["system.disk"]
        \\
    ;
    try std.testing.expect(packsArraySlice(content, "disabled") == null);
    const enabled = packsArraySlice(content, "enabled") orelse {
        try std.testing.expect(false);
        return;
    };
    try std.testing.expect(std.mem.indexOf(u8, enabled, "containers.docker") != null);
}

test "rewritePacksArrayKey preserves other keys and section order" {
    const existing =
        \\[general]
        \\verbose = true
        \\
        \\[packs]
        \\enabled = ["old.pack"]
        \\disabled = ["system.disk"]
        \\
    ;
    const enabled = [_][]const u8{ "containers.docker", "old.pack" };
    const out = try rewritePacksArrayKey(std.testing.allocator, existing, "enabled", &enabled);
    defer std.testing.allocator.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "verbose = true") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "containers.docker") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "disabled = [\"system.disk\"]") != null);
}

test "collectQuotedPackIds reads only enabled array" {
    const content =
        \\[packs]
        \\enabled = ["package_managers", "containers.docker"]
        \\disabled = ["system.disk", "strict_git"]
        \\
    ;
    var set: std.StringArrayHashMapUnmanaged(void) = .empty;
    defer set.deinit(std.testing.allocator);
    try collectQuotedPackIds(std.testing.allocator, content, &set);
    try std.testing.expect(set.contains("package_managers"));
    try std.testing.expect(set.contains("containers.docker"));
    try std.testing.expect(!set.contains("system.disk"));
    try std.testing.expect(!set.contains("strict_git"));
}

test "enablePacks merges opt-in packs and is idempotent" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_z = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root_z);
    const root = try std.testing.allocator.dupe(u8, root_z);
    defer std.testing.allocator.free(root);
    try tmp.dir.createDirPath(std.testing.io, ".git");

    const seed =
        \\[general]
        \\verbose = true
        \\
        \\[packs]
        \\enabled = ["package_managers"]
        \\disabled = ["system.disk"]
        \\
    ;
    {
        const f = try tmp.dir.createFile(std.testing.io, ".ryk.toml", .{});
        defer f.close(std.testing.io);
        try f.writeStreamingAll(std.testing.io, seed);
    }

    var first = try enablePacks(std.testing.io, std.testing.allocator, root, &.{ "containers.docker", "package_managers" });
    defer first.deinit(std.testing.allocator);
    try std.testing.expect(first.changed);
    try std.testing.expect(first.scope == .project);
    try std.testing.expectEqual(@as(usize, 1), first.added.len);
    try std.testing.expectEqualStrings("containers.docker", first.added[0]);

    const config = try tmp.dir.readFileAlloc(std.testing.io, ".ryk.toml", std.testing.allocator, .limited(8192));
    defer std.testing.allocator.free(config);
    try std.testing.expect(std.mem.indexOf(u8, config, "containers.docker") != null);
    try std.testing.expect(std.mem.indexOf(u8, config, "package_managers") != null);
    try std.testing.expect(std.mem.indexOf(u8, config, "verbose = true") != null);
    try std.testing.expect(std.mem.indexOf(u8, config, "system.disk") != null);

    var second = try enablePacks(std.testing.io, std.testing.allocator, root, &.{"containers.docker"});
    defer second.deinit(std.testing.allocator);
    try std.testing.expect(!second.changed);
    try std.testing.expectEqual(@as(usize, 0), second.added.len);
}

test "enablePacks baseline notes and re-enables from disabled" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_z = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root_z);
    const root = try std.testing.allocator.dupe(u8, root_z);
    defer std.testing.allocator.free(root);
    try tmp.dir.createDirPath(std.testing.io, ".git");

    var xdg = try testIsolateXdg();
    defer xdg.deinit();

    // Stale project baseline disable (ignored at load) + effective user opt-out.
    {
        const f = try tmp.dir.createFile(std.testing.io, ".ryk.toml", .{});
        defer f.close(std.testing.io);
        try f.writeStreamingAll(std.testing.io,
            \\[packs]
            \\enabled = []
            \\disabled = ["system.disk"]
            \\
        );
    }
    {
        const user = try resolveUserPackConfigPath(std.testing.allocator);
        defer std.testing.allocator.free(user.path);
        try writeConfigFile(std.testing.io, std.testing.allocator, user.path,
            \\[packs]
            \\enabled = []
            \\disabled = ["system.disk"]
            \\
        );
    }

    var result = try enablePacks(std.testing.io, std.testing.allocator, root, &.{ "core.git", "system.disk" });
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(result.changed);
    try std.testing.expect(result.baseline_notes.len >= 1);

    const config = try tmp.dir.readFileAlloc(std.testing.io, ".ryk.toml", std.testing.allocator, .limited(8192));
    defer std.testing.allocator.free(config);
    const disabled = packsArraySlice(config, "disabled") orelse "";
    try std.testing.expect(std.mem.indexOf(u8, disabled, "system.disk") == null);

    const user = try resolveUserPackConfigPath(std.testing.allocator);
    defer std.testing.allocator.free(user.path);
    const user_raw = readFileIfExists(std.testing.io, std.testing.allocator, user.path) catch null;
    defer if (user_raw) |r| std.testing.allocator.free(r);
    if (user_raw) |raw| {
        const ud = packsArraySlice(raw, "disabled") orelse "";
        try std.testing.expect(std.mem.indexOf(u8, ud, "system.disk") == null);
    }
}

test "disablePacks removes opt-in and opts out baseline via user config" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_z = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root_z);
    const root = try std.testing.allocator.dupe(u8, root_z);
    defer std.testing.allocator.free(root);
    try tmp.dir.createDirPath(std.testing.io, ".git");

    var xdg = try testIsolateXdg();
    defer xdg.deinit();

    const seed =
        \\[agents]
        \\claude = true
        \\
        \\[packs]
        \\enabled = ["containers.docker", "package_managers"]
        \\disabled = []
        \\
    ;
    {
        const f = try tmp.dir.createFile(std.testing.io, ".ryk.toml", .{});
        defer f.close(std.testing.io);
        try f.writeStreamingAll(std.testing.io, seed);
    }

    var result = try disablePacks(std.testing.io, std.testing.allocator, root, &.{ "containers.docker", "system.disk" });
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(result.changed);
    try std.testing.expectEqual(@as(usize, 1), result.removed.len);
    try std.testing.expectEqualStrings("containers.docker", result.removed[0]);
    try std.testing.expectEqual(@as(usize, 1), result.disabled_added.len);
    try std.testing.expectEqualStrings("system.disk", result.disabled_added[0]);
    try std.testing.expect(std.mem.indexOf(u8, result.message, "daemon may still") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.message, "user config") != null or
        std.mem.indexOf(u8, result.message, "packIsActive") != null);

    const config = try tmp.dir.readFileAlloc(std.testing.io, ".ryk.toml", std.testing.allocator, .limited(8192));
    defer std.testing.allocator.free(config);
    try std.testing.expect(std.mem.indexOf(u8, config, "claude = true") != null);
    try std.testing.expect(std.mem.indexOf(u8, config, "package_managers") != null);
    const enabled = packsArraySlice(config, "enabled") orelse "";
    try std.testing.expect(std.mem.indexOf(u8, enabled, "containers.docker") == null);
    // Project file must NOT list baseline in disabled (M-8).
    const project_disabled = packsArraySlice(config, "disabled") orelse "[]";
    try std.testing.expect(std.mem.indexOf(u8, project_disabled, "system.disk") == null);

    // Effective load merges user baseline opt-out.
    var loaded = try loadPackIdsForWorkspace(std.testing.io, std.testing.allocator, root);
    defer loaded.deinit(std.testing.allocator);
    var saw_disk = false;
    for (loaded.disabled) |id| {
        if (std.mem.eql(u8, id, "system.disk")) saw_disk = true;
    }
    try std.testing.expect(saw_disk);

    var again = try disablePacks(std.testing.io, std.testing.allocator, root, &.{"containers.docker"});
    defer again.deinit(std.testing.allocator);
    try std.testing.expect(!again.changed);
}

test "enablePacks rejects invalid pack id characters" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_z = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root_z);
    const root = try std.testing.allocator.dupe(u8, root_z);
    defer std.testing.allocator.free(root);
    try tmp.dir.createDirPath(std.testing.io, ".git");

    try std.testing.expectError(error.InvalidArguments, enablePacks(
        std.testing.io,
        std.testing.allocator,
        root,
        &.{"bad;id"},
    ));
}

// ── s-packs locked contract tests (Slice 4) ─────────────────────────────────
// Disable/enable semantics stay on shipped pack_config — no invented core hard-fail.

test "s-packs: disablePacks allows core.git without hard-fail and lists in disabled" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_z = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root_z);
    const root = try std.testing.allocator.dupe(u8, root_z);
    defer std.testing.allocator.free(root);
    try tmp.dir.createDirPath(std.testing.io, ".git");

    var xdg = try testIsolateXdg();
    defer xdg.deinit();

    const seed =
        \\[packs]
        \\enabled = ["containers.docker"]
        \\disabled = []
        \\
    ;
    {
        const f = try tmp.dir.createFile(std.testing.io, ".ryk.toml", .{});
        defer f.close(std.testing.io);
        try f.writeStreamingAll(std.testing.io, seed);
    }

    // Baseline may be opted out (user config); no hard-fail "cannot disable core.*".
    // Project file never records baseline in disabled (M-8).
    var result = try disablePacks(std.testing.io, std.testing.allocator, root, &.{"core.git"});
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(result.changed);
    try std.testing.expectEqual(@as(usize, 1), result.disabled_added.len);
    try std.testing.expectEqualStrings("core.git", result.disabled_added[0]);
    try std.testing.expect(std.mem.indexOf(u8, result.message, "cannot disable") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.message, "daemon may still") == null);

    const config = try tmp.dir.readFileAlloc(std.testing.io, ".ryk.toml", std.testing.allocator, .limited(8192));
    defer std.testing.allocator.free(config);
    const project_disabled = packsArraySlice(config, "disabled") orelse "[]";
    try std.testing.expect(std.mem.indexOf(u8, project_disabled, "core.git") == null);

    var loaded = try loadPackIdsForWorkspace(std.testing.io, std.testing.allocator, root);
    defer loaded.deinit(std.testing.allocator);
    var found = false;
    for (loaded.disabled) |id| {
        if (std.mem.eql(u8, id, "core.git")) found = true;
    }
    try std.testing.expect(found); // effective via user-config merge
}

test "s-packs: enablePacks writes opt-in pack into project enabled list" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_z = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root_z);
    const root = try std.testing.allocator.dupe(u8, root_z);
    defer std.testing.allocator.free(root);
    try tmp.dir.createDirPath(std.testing.io, ".git");

    var result = try enablePacks(std.testing.io, std.testing.allocator, root, &.{"containers.docker"});
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(result.changed);
    try std.testing.expectEqual(@as(usize, 1), result.added.len);
    try std.testing.expectEqualStrings("containers.docker", result.added[0]);
    try std.testing.expect(result.scope == .project);
    try std.testing.expect(result.config_path != null);

    const config = try tmp.dir.readFileAlloc(std.testing.io, ".ryk.toml", std.testing.allocator, .limited(8192));
    defer std.testing.allocator.free(config);
    const enabled = packsArraySlice(config, "enabled") orelse "";
    try std.testing.expect(std.mem.indexOf(u8, enabled, "containers.docker") != null);
}

test "s-packs: disablePacks removes opt-in from enabled without inventing core hard-fail path" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_z = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root_z);
    const root = try std.testing.allocator.dupe(u8, root_z);
    defer std.testing.allocator.free(root);
    try tmp.dir.createDirPath(std.testing.io, ".git");

    {
        var en = try enablePacks(std.testing.io, std.testing.allocator, root, &.{"containers.docker"});
        defer en.deinit(std.testing.allocator);
        try std.testing.expect(en.changed);
    }

    var result = try disablePacks(std.testing.io, std.testing.allocator, root, &.{"containers.docker"});
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(result.changed);
    try std.testing.expectEqual(@as(usize, 1), result.removed.len);
    try std.testing.expectEqualStrings("containers.docker", result.removed[0]);

    const config = try tmp.dir.readFileAlloc(std.testing.io, ".ryk.toml", std.testing.allocator, .limited(8192));
    defer std.testing.allocator.free(config);
    const enabled = packsArraySlice(config, "enabled") orelse "";
    try std.testing.expect(std.mem.indexOf(u8, enabled, "containers.docker") == null);
}

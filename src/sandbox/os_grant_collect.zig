//! Collect the usual OS grants for attach.
//!
//! Kind is stamped here (file vs folder) and must survive compile/apply.
//! Launch extras stay with the caller and default to folder.

const std = @import("std");
const builtin = @import("builtin");
const profile = @import("profile.zig");
const host_config_grants = @import("host_config_grants.zig");
const apply = @import("apply.zig");

pub const GrantKind = profile.GrantKind;

/// One collected OS grant. Paths are owned by `CollectedGrants`.
pub const OsGrant = struct {
    path: []const u8,
    mode: profile.AccessMode,
    kind: GrantKind,
};

/// Launch-only extras. Kind defaults to folder so a pack tree is not reduced to one file.
pub const ExtraGrant = struct {
    path: []const u8,
    mode: profile.AccessMode = .ro,
    kind: GrantKind = .folder,
};

pub const CollectInput = struct {
    workspace_root: []const u8,
    host: []const u8 = "",
    home: []const u8 = "",
    argv0: ?[]const u8 = null,
    env_map: ?*std.process.Environ.Map = null,
    extras: []const ExtraGrant = &.{},
};

pub const CollectedGrants = struct {
    allocator: std.mem.Allocator,
    grants: []OsGrant,

    pub fn deinit(self: *CollectedGrants) void {
        for (self.grants) |g| self.allocator.free(g.path);
        self.allocator.free(self.grants);
        self.* = undefined;
    }

    pub fn find(self: *const CollectedGrants, path: []const u8) ?OsGrant {
        for (self.grants) |g| {
            if (std.mem.eql(u8, g.path, path)) return g;
        }
        return null;
    }

    /// Views into owned paths for `compileProfile` extra_grants.
    pub fn extraGrants(
        self: *const CollectedGrants,
        buf: []profile.ExtraGrant,
    ) error{TooManyGrants}![]const profile.ExtraGrant {
        if (self.grants.len > buf.len) return error.TooManyGrants;
        for (self.grants, 0..) |g, i| {
            buf[i] = .{ .path = g.path, .mode = g.mode, .kind = g.kind };
        }
        return buf[0..self.grants.len];
    }

    pub fn extraGrantsAlloc(self: *const CollectedGrants) error{OutOfMemory}![]profile.ExtraGrant {
        const out = try self.allocator.alloc(profile.ExtraGrant, self.grants.len);
        for (self.grants, 0..) |g, i| {
            out[i] = .{ .path = g.path, .mode = g.mode, .kind = g.kind };
        }
        return out;
    }
};

/// Collect usual OS grants and merge extras. Ancestor instruction is file.
/// File grants whose path is a directory at this moment are skipped.
pub fn collectUsualGrants(
    io: std.Io,
    allocator: std.mem.Allocator,
    input: CollectInput,
) error{OutOfMemory}!CollectedGrants {
    var list: std.ArrayList(OsGrant) = .empty;
    errdefer {
        for (list.items) |g| allocator.free(g.path);
        list.deinit(allocator);
    }

    if (input.argv0) |argv0| {
        const execs = try apply.collectLaunchExecPaths(io, allocator, argv0, input.env_map);
        defer apply.freeLaunchExecPaths(allocator, execs);
        for (execs) |path| {
            try appendGrant(&list, allocator, path, .exec, .file);
        }
        const install = try apply.collectLaunchInstallRoPaths(io, allocator, argv0, input.env_map);
        defer apply.freeLaunchInstallRoPaths(allocator, install);
        for (install) |path| {
            try appendGrant(&list, allocator, path, .ro, .folder);
        }
    }

    if (input.host.len > 0) {
        const system_ro = try host_config_grants.collectHostSystemRoPaths(allocator, input.host);
        defer host_config_grants.freeHostSystemRoPaths(allocator, system_ro);
        for (system_ro) |path| {
            try appendGrant(&list, allocator, path, .ro, .folder);
        }

        const host_rw = try host_config_grants.collectHostConfigPaths(
            io,
            allocator,
            input.host,
            input.home,
        );
        defer host_config_grants.freeHostConfigPaths(allocator, host_rw);
        const drop_default_codex = extrasReplaceDefaultCodex(input);
        for (host_rw) |path| {
            if (drop_default_codex and isDefaultCodexHome(path, input.home)) continue;
            try appendGrant(&list, allocator, path, .rw, .folder);
        }
    }

    const toolchain = try host_config_grants.collectMacosDeveloperToolchainRoPaths(
        io,
        allocator,
        input.env_map,
    );
    defer host_config_grants.freeHostSystemRoPaths(allocator, toolchain);
    for (toolchain) |path| {
        try appendGrant(&list, allocator, path, .ro, .folder);
    }
    pinDeveloperDir(input.env_map, toolchain);

    const ancestor = try host_config_grants.collectAncestorInstructionRoPaths(
        io,
        allocator,
        input.workspace_root,
        input.home,
    );
    defer host_config_grants.freeHostSystemRoPaths(allocator, ancestor);
    for (ancestor) |path| {
        try appendGrant(&list, allocator, path, .ro, .file);
    }

    for (input.extras) |extra| {
        const kind: GrantKind = if (extra.mode == .exec) .file else extra.kind;
        try appendGrant(&list, allocator, extra.path, extra.mode, kind);
    }

    var collected: CollectedGrants = .{
        .allocator = allocator,
        .grants = try list.toOwnedSlice(allocator),
    };
    errdefer collected.deinit();
    try skipFileGrantsThatAreDirectories(io, &collected);
    return collected;
}

fn appendGrant(
    list: *std.ArrayList(OsGrant),
    allocator: std.mem.Allocator,
    path: []const u8,
    mode: profile.AccessMode,
    kind: GrantKind,
) error{OutOfMemory}!void {
    for (list.items) |g| {
        if (std.mem.eql(u8, g.path, path) and g.mode == mode) {
            // Never upgrade file → folder.
            if (g.kind == .file and kind == .folder) return;
            return;
        }
    }
    const owned = try allocator.dupe(u8, path);
    errdefer allocator.free(owned);
    try list.append(allocator, .{ .path = owned, .mode = mode, .kind = kind });
}

fn grantPathIsDirectory(io: std.Io, path: []const u8) bool {
    if (std.Io.Dir.openDirAbsolute(io, path, .{ .follow_symlinks = false })) |dir| {
        dir.close(io);
        return true;
    } else |_| return false;
}

fn pinDeveloperDir(env_map: ?*std.process.Environ.Map, toolchain: []const []const u8) void {
    if (builtin.os.tag != .macos) return;
    const map = env_map orelse return;
    const existing = map.get("DEVELOPER_DIR");
    const existing_ok = if (existing) |d|
        host_config_grants.isAllowlistedMacosDeveloperToolchainPath(d)
    else
        false;
    if (existing_ok) return;
    if (host_config_grants.preferredMacosDeveloperDir(toolchain)) |preferred| {
        map.put("DEVELOPER_DIR", preferred) catch {};
    }
}

fn extrasReplaceDefaultCodex(input: CollectInput) bool {
    if (!std.mem.eql(u8, input.host, "codex")) return false;
    if (input.home.len == 0 or !std.fs.path.isAbsolute(input.home)) return false;
    for (input.extras) |extra| {
        if (extra.mode != .rw) continue;
        if (isDefaultCodexHome(extra.path, input.home)) continue;
        if (looksLikeCodexHome(extra.path, input.home)) return true;
    }
    return false;
}

fn isDefaultCodexHome(path: []const u8, home: []const u8) bool {
    if (home.len == 0 or path.len <= home.len + 1) return false;
    if (!std.mem.startsWith(u8, path, home) or path[home.len] != '/') return false;
    return std.mem.eql(u8, path[home.len + 1 ..], ".codex");
}

fn looksLikeCodexHome(path: []const u8, home: []const u8) bool {
    if (home.len == 0 or path.len <= home.len + 1) return false;
    if (!std.mem.startsWith(u8, path, home) or path[home.len] != '/') return false;
    const relative = path[home.len + 1 ..];
    return std.mem.eql(u8, relative, ".codex") or
        std.mem.startsWith(u8, relative, ".codex-") or
        std.mem.eql(u8, relative, ".config/codex");
}

test "parent AGENTS.md is collected as OS grant kind file" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    const home = try home_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(home);

    try home_tmp.dir.createDirPath(io, "CodingProjects/ryk");
    try home_tmp.dir.createDirPath(io, "CodingProjects/other");
    try home_tmp.dir.writeFile(io, .{
        .sub_path = "CodingProjects/AGENTS.md",
        .data = "# parent instructions\n",
    });
    try home_tmp.dir.writeFile(io, .{
        .sub_path = "CodingProjects/other/AGENTS.md",
        .data = "# sibling project\n",
    });

    const workspace = try std.fs.path.join(allocator, &.{ home, "CodingProjects", "ryk" });
    defer allocator.free(workspace);
    const parent_agents = try std.fs.path.join(allocator, &.{ home, "CodingProjects", "AGENTS.md" });
    defer allocator.free(parent_agents);
    const parent_dir = try std.fs.path.join(allocator, &.{ home, "CodingProjects" });
    defer allocator.free(parent_dir);
    const sibling_agents = try std.fs.path.join(allocator, &.{ home, "CodingProjects", "other", "AGENTS.md" });
    defer allocator.free(sibling_agents);

    var collected = try collectUsualGrants(io, allocator, .{
        .workspace_root = workspace,
        .home = home,
    });
    defer collected.deinit();

    const parent = collected.find(parent_agents) orelse return error.TestExpectedEqual;
    try std.testing.expectEqual(profile.AccessMode.ro, parent.mode);
    try std.testing.expectEqual(GrantKind.file, parent.kind);
    try std.testing.expect(collected.find(parent_dir) == null);
    try std.testing.expect(collected.find(home) == null);
    try std.testing.expect(collected.find(sibling_agents) == null);
}

test "file grant replaced by a directory is skipped not upgraded to folder" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    const home = try home_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(home);

    try home_tmp.dir.createDirPath(io, "proj/ws");
    try home_tmp.dir.writeFile(io, .{
        .sub_path = "proj/AGENTS.md",
        .data = "# parent\n",
    });

    const workspace = try std.fs.path.join(allocator, &.{ home, "proj", "ws" });
    defer allocator.free(workspace);
    const parent_agents = try std.fs.path.join(allocator, &.{ home, "proj", "AGENTS.md" });
    defer allocator.free(parent_agents);

    var collected = try collectUsualGrants(io, allocator, .{
        .workspace_root = workspace,
        .home = home,
    });
    defer collected.deinit();

    const stamped = collected.find(parent_agents) orelse return error.TestExpectedEqual;
    try std.testing.expectEqual(GrantKind.file, stamped.kind);

    try home_tmp.dir.deleteFile(io, "proj/AGENTS.md");
    try home_tmp.dir.createDirPath(io, "proj/AGENTS.md");
    try home_tmp.dir.writeFile(io, .{
        .sub_path = "proj/AGENTS.md/secret.env",
        .data = "SECRET=1\n",
    });

    try skipFileGrantsThatAreDirectories(io, &collected);
    try std.testing.expect(collected.find(parent_agents) == null);
}

test "grok host-config skills folder remains folder RW" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    const home = try home_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(home);

    try home_tmp.dir.createDirPath(io, "ws");
    try home_tmp.dir.createDirPath(io, ".grok/skills");
    try home_tmp.dir.writeFile(io, .{
        .sub_path = ".grok/skills/SKILL.md",
        .data = "# skill\n",
    });

    const workspace = try std.fs.path.join(allocator, &.{ home, "ws" });
    defer allocator.free(workspace);
    const skills = try std.fs.path.join(allocator, &.{ home, ".grok", "skills" });
    defer allocator.free(skills);

    var collected = try collectUsualGrants(io, allocator, .{
        .workspace_root = workspace,
        .host = "grok",
        .home = home,
    });
    defer collected.deinit();

    const grant = collected.find(skills) orelse return error.TestExpectedEqual;
    try std.testing.expectEqual(profile.AccessMode.rw, grant.mode);
    try std.testing.expectEqual(GrantKind.folder, grant.kind);
}

test "launch extras default to OS grant kind folder" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    const workspace = try ws_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(workspace);

    const extra_tree = try std.fs.path.join(allocator, &.{ workspace, "pack-lib" });
    defer allocator.free(extra_tree);
    try ws_tmp.dir.createDirPath(io, "pack-lib");

    var collected = try collectUsualGrants(io, allocator, .{
        .workspace_root = workspace,
        .home = workspace,
        .extras = &.{.{ .path = extra_tree, .mode = .ro }},
    });
    defer collected.deinit();

    const extra = collected.find(extra_tree) orelse return error.TestExpectedEqual;
    try std.testing.expectEqual(profile.AccessMode.ro, extra.mode);
    try std.testing.expectEqual(GrantKind.folder, extra.kind);
}

/// Drop file-kind grants whose path is now a directory. Never upgrades to folder.
pub fn skipFileGrantsThatAreDirectories(io: std.Io, collected: *CollectedGrants) error{OutOfMemory}!void {
    var kept: std.ArrayList(OsGrant) = .empty;
    errdefer {
        for (kept.items) |g| collected.allocator.free(g.path);
        kept.deinit(collected.allocator);
    }

    for (collected.grants) |g| {
        if (g.kind == .file and grantPathIsDirectory(io, g.path)) {
            collected.allocator.free(g.path);
            continue;
        }
        try kept.append(collected.allocator, g);
    }

    collected.allocator.free(collected.grants);
    collected.grants = try kept.toOwnedSlice(collected.allocator);
}

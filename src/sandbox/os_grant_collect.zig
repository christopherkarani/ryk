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

/// Launch-only extras. Same shape as compile extras (folder default).
pub const ExtraGrant = profile.ExtraGrant;

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
        const default_codex_root: ?[]u8 = if (std.mem.eql(u8, input.host, "codex") and
            input.home.len > 0 and std.fs.path.isAbsolute(input.home))
            try std.fs.path.join(allocator, &.{ input.home, ".codex" })
        else
            null;
        defer if (default_codex_root) |root| allocator.free(root);
        const drop_default_codex = if (default_codex_root) |root|
            extrasReplaceDefaultCodex(input, root)
        else
            false;
        for (host_rw) |path| {
            if (drop_default_codex and isDefaultCodexHome(path, default_codex_root.?)) continue;
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
    try pinDeveloperDir(input.env_map, toolchain);

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
    for (list.items) |*g| {
        if (std.mem.eql(u8, g.path, path) and g.mode == mode) {
            // Never upgrade file → folder. Folder → file keeps file (compile merge).
            if (g.kind == .file and kind == .folder) return;
            if (g.kind == .folder and kind == .file) g.kind = .file;
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

fn pinDeveloperDir(env_map: ?*std.process.Environ.Map, toolchain: []const []const u8) error{OutOfMemory}!void {
    if (builtin.os.tag != .macos) return;
    const map = env_map orelse return;
    const existing = map.get("DEVELOPER_DIR");
    const existing_ok = if (existing) |d|
        host_config_grants.isAllowlistedMacosDeveloperToolchainPath(d)
    else
        false;
    if (existing_ok) return;
    if (host_config_grants.preferredMacosDeveloperDir(toolchain)) |preferred| {
        try map.put("DEVELOPER_DIR", preferred);
    }
}

/// Strip macOS Data-volume firmlink prefix so `/System/Volumes/Data/Users/…` → `/Users/…`.
/// Local twin of `run_os_sandbox.normalizeMacosUsersPath` (no cross-module import).
fn normalizeMacosUsersPath(path: []const u8) []const u8 {
    const data_prefix = "/System/Volumes/Data";
    if (std.mem.startsWith(u8, path, data_prefix) and path.len > data_prefix.len and
        path[data_prefix.len] == '/' and std.mem.startsWith(u8, path[data_prefix.len..], "/Users/"))
    {
        return path[data_prefix.len..];
    }
    return path;
}

fn trimTrailingSlashes(path: []const u8) []const u8 {
    var p = path;
    while (p.len > 1 and p[p.len - 1] == '/') p = p[0 .. p.len - 1];
    return p;
}

fn extrasReplaceDefaultCodex(input: CollectInput, default_root: []const u8) bool {
    if (!std.mem.eql(u8, input.host, "codex")) return false;
    if (input.home.len == 0 or !std.fs.path.isAbsolute(input.home)) return false;
    for (input.extras) |extra| {
        if (extra.mode != .rw) continue;
        if (isDefaultCodexHome(extra.path, default_root)) continue;
        if (looksLikeCodexHome(extra.path, input.home)) return true;
    }
    return false;
}

fn isDefaultCodexHome(path: []const u8, default_root: []const u8) bool {
    return std.mem.eql(u8, normalizeMacosUsersPath(path), normalizeMacosUsersPath(default_root));
}

fn looksLikeCodexHome(path: []const u8, home: []const u8) bool {
    const norm_path = normalizeMacosUsersPath(path);
    const norm_home = trimTrailingSlashes(normalizeMacosUsersPath(home));
    if (norm_home.len == 0 or norm_path.len <= norm_home.len + 1) return false;
    if (!std.mem.startsWith(u8, norm_path, norm_home) or norm_path[norm_home.len] != '/') return false;
    const relative = norm_path[norm_home.len + 1 ..];
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

test "appendGrant keeps file when a later file grant arrives over folder" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    const workspace = try ws_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(workspace);
    try ws_tmp.dir.writeFile(io, .{ .sub_path = "AGENTS.md", .data = "# ws\n" });
    const agents = try std.fs.path.join(allocator, &.{ workspace, "AGENTS.md" });
    defer allocator.free(agents);

    var collected = try collectUsualGrants(io, allocator, .{
        .workspace_root = workspace,
        .home = workspace,
        .extras = &.{
            .{ .path = agents, .mode = .ro, .kind = .folder },
            .{ .path = agents, .mode = .ro, .kind = .file },
        },
    });
    defer collected.deinit();

    const grant = collected.find(agents) orelse return error.TestExpectedEqual;
    try std.testing.expectEqual(GrantKind.file, grant.kind);
}

/// Drop file-kind grants whose path is now a directory. Never upgrades to folder.
pub fn skipFileGrantsThatAreDirectories(io: std.Io, collected: *CollectedGrants) error{OutOfMemory}!void {
    var write: usize = 0;
    for (collected.grants) |g| {
        if (g.kind == .file and grantPathIsDirectory(io, g.path)) {
            collected.allocator.free(g.path);
            continue;
        }
        collected.grants[write] = g;
        write += 1;
    }
    if (write == collected.grants.len) return;
    if (collected.allocator.resize(collected.grants, write)) {
        collected.grants.len = write;
        return;
    }
    collected.grants = collected.allocator.realloc(collected.grants, write) catch {
        // Shrink failed after compact. Keep the original allocation so deinit
        // size matches; blank the tail so leftover keeper copies are not freed twice.
        for (collected.grants[write..]) |*g| {
            g.* = .{ .path = &.{}, .mode = .ro, .kind = .file };
        }
        return;
    };
}

test "collectUsualGrants drops default ~/.codex when a custom Codex extra is present" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    const home = try home_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(home);

    try home_tmp.dir.createDirPath(io, "ws");
    try home_tmp.dir.createDirPath(io, ".codex");
    try home_tmp.dir.createDirPath(io, ".agents");
    try home_tmp.dir.createDirPath(io, ".codex-work");
    try home_tmp.dir.writeFile(io, .{
        .sub_path = ".codex/auth.json",
        .data = "{}\n",
    });

    const workspace = try std.fs.path.join(allocator, &.{ home, "ws" });
    defer allocator.free(workspace);
    const default_codex = try std.fs.path.join(allocator, &.{ home, ".codex" });
    defer allocator.free(default_codex);
    const agents = try std.fs.path.join(allocator, &.{ home, ".agents" });
    defer allocator.free(agents);
    const custom = try std.fs.path.join(allocator, &.{ home, ".codex-work" });
    defer allocator.free(custom);
    const home_slash = try std.fmt.allocPrint(allocator, "{s}/", .{home});
    defer allocator.free(home_slash);

    var collected = try collectUsualGrants(io, allocator, .{
        .workspace_root = workspace,
        .host = "codex",
        .home = home_slash,
        .extras = &.{.{ .path = custom, .mode = .rw }},
    });
    defer collected.deinit();

    try std.testing.expect(collected.find(default_codex) == null);
    const agents_grant = collected.find(agents) orelse return error.TestExpectedEqual;
    try std.testing.expectEqual(profile.AccessMode.rw, agents_grant.mode);
    const custom_grant = collected.find(custom) orelse return error.TestExpectedEqual;
    try std.testing.expectEqual(profile.AccessMode.rw, custom_grant.mode);
}

test "collectUsualGrants drops Data-form default ~/.codex for a Users-form HOME" {
    const allocator = std.testing.allocator;
    const home = "/Users/u";
    const data_default = "/System/Volumes/Data/Users/u/.codex";
    const users_default = "/Users/u/.codex";
    const custom = "/Users/u/.codex-work";
    const data_custom = "/System/Volumes/Data/Users/u/.codex-work";
    const agents = "/System/Volumes/Data/Users/u/.agents";

    const default_root = try std.fs.path.join(allocator, &.{ home, ".codex" });
    defer allocator.free(default_root);

    const input: CollectInput = .{
        .workspace_root = "/Users/u/ws",
        .host = "codex",
        .home = home,
        .extras = &.{.{ .path = custom, .mode = .rw }},
    };
    try std.testing.expect(extrasReplaceDefaultCodex(input, default_root));
    try std.testing.expect(isDefaultCodexHome(data_default, default_root));
    try std.testing.expect(isDefaultCodexHome(users_default, default_root));
    try std.testing.expect(!isDefaultCodexHome(agents, default_root));
    try std.testing.expect(!isDefaultCodexHome(custom, default_root));

    const slash_root = try std.fs.path.join(allocator, &.{ "/Users/u/", ".codex" });
    defer allocator.free(slash_root);
    const slash_input: CollectInput = .{
        .workspace_root = "/Users/u/ws",
        .host = "codex",
        .home = "/Users/u/",
        .extras = &.{.{ .path = custom, .mode = .rw }},
    };
    try std.testing.expect(extrasReplaceDefaultCodex(slash_input, slash_root));
    try std.testing.expect(isDefaultCodexHome(data_default, slash_root));

    const data_extra_input: CollectInput = .{
        .workspace_root = "/Users/u/ws",
        .host = "codex",
        .home = home,
        .extras = &.{.{ .path = data_custom, .mode = .rw }},
    };
    try std.testing.expect(extrasReplaceDefaultCodex(data_extra_input, default_root));
    try std.testing.expect(looksLikeCodexHome(data_custom, home));
    try std.testing.expect(looksLikeCodexHome(custom, "/Users/u/"));
}

//! Protected MCP launch planning for OpenCode and Pi on macOS Seatbelt sessions.
//!
//! Inventory comes from each host's on-disk config (not a host CLI JSON dump).
//! Approved stdio servers are rewritten through `ryk mcp proxy` with an embedded
//! `--command` launch; unmediated transports are disabled in the closed overlay.
//!
//! OpenCode: injects `OPENCODE_CONFIG_CONTENT` after launch allowlist (ryk-owned).
//! Pi: writes a closed `mcp.json` and appends `--mcp-config <path>`.

const std = @import("std");
const builtin = @import("builtin");

const mcp_mod = @import("../mcp/mod.zig");
const sandbox = @import("../sandbox/mod.zig");

const inventory_limit = sandbox.mcp_runtime_grants.max_config_bytes;
const max_manifest_files: usize = 128;
const max_config_files: usize = 16;

pub const PlanError = error{
    InvalidInventory,
    TooManyPaths,
    SessionTmpPrepareFailed,
    AmbiguousManifest,
    OutOfMemory,
};

const ApprovedWrapper = struct {
    name: []const u8,
    wrapper: []const u8,
};

pub const HostKind = enum {
    opencode,
    pi,

    pub fn key(self: HostKind) []const u8 {
        return switch (self) {
            .opencode => "opencode",
            .pi => "pi",
        };
    }
};

pub const EnvPut = struct {
    name: []const u8,
    value: []const u8,
};

pub const Plan = struct {
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    exec_paths: []const []const u8,
    ro_paths: []const []const u8,
    disabled_server_names: []const []const u8,
    env_puts: []const EnvPut,
    wrapper_root: []const u8,
    audit_root: []const u8,

    pub fn deinit(self: *Plan, io: std.Io) void {
        freeOwnedStrings(self.allocator, self.argv);
        freeOwnedStrings(self.allocator, self.exec_paths);
        freeOwnedStrings(self.allocator, self.ro_paths);
        freeOwnedStrings(self.allocator, self.disabled_server_names);
        for (self.env_puts) |put| {
            self.allocator.free(put.name);
            self.allocator.free(put.value);
        }
        self.allocator.free(self.env_puts);
        std.Io.Dir.cwd().deleteTree(io, self.wrapper_root) catch {};
        std.Io.Dir.cwd().deleteTree(io, self.audit_root) catch {};
        self.allocator.free(self.wrapper_root);
        self.allocator.free(self.audit_root);
        self.* = undefined;
    }
};

pub fn prepare(
    io: std.Io,
    allocator: std.mem.Allocator,
    original_argv: []const []const u8,
    workspace_root: []const u8,
    policy_path: []const u8,
    mode: []const u8,
    env_map: *const std.process.Environ.Map,
) PlanError!?Plan {
    if (builtin.os.tag != .macos or original_argv.len == 0) return null;
    var identity = sandbox.host_identity.resolveHostIdentity(
        io,
        allocator,
        original_argv[0],
        env_map,
        .{ .workspace_root = workspace_root },
    ) catch return null;
    defer identity.deinit(allocator);
    if (!identity.isTrusted()) return null;
    const host_key = identity.hostKey();
    const kind: HostKind = if (std.mem.eql(u8, host_key, "opencode"))
        .opencode
    else if (std.mem.eql(u8, host_key, "pi"))
        .pi
    else
        return null;

    const home = env_map.get("HOME") orelse "";
    var inventory = try loadInventory(io, allocator, kind, workspace_root, home, env_map);
    defer inventory.deinit(allocator);

    const self_exe = std.process.executablePathAlloc(io, allocator) catch return error.InvalidInventory;
    defer allocator.free(self_exe);
    return buildFromInventory(
        io,
        allocator,
        kind,
        original_argv,
        workspace_root,
        policy_path,
        mode,
        home,
        env_map,
        self_exe,
        inventory,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.TooManyPaths => return error.TooManyPaths,
        error.SessionTmpPrepareFailed => return error.SessionTmpPrepareFailed,
        error.AmbiguousManifest => return error.AmbiguousManifest,
        else => return error.InvalidInventory,
    };
}

fn loadInventory(
    io: std.Io,
    allocator: std.mem.Allocator,
    kind: HostKind,
    workspace_root: []const u8,
    home: []const u8,
    env_map: *const std.process.Environ.Map,
) PlanError!sandbox.mcp_runtime_grants.LaunchInventory {
    const list_json = switch (kind) {
        .opencode => try collectOpenCodeListJson(io, allocator, workspace_root, home, env_map),
        .pi => try collectPiListJson(io, allocator, workspace_root, home, env_map),
    };
    defer allocator.free(list_json);
    return sandbox.mcp_runtime_grants.parse(allocator, io, list_json, home) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidInventory,
    };
}

fn collectOpenCodeListJson(
    io: std.Io,
    allocator: std.mem.Allocator,
    workspace_root: []const u8,
    home: []const u8,
    env_map: *const std.process.Environ.Map,
) PlanError![]u8 {
    var paths: std.ArrayList([]const u8) = .empty;
    defer {
        for (paths.items) |p| allocator.free(p);
        paths.deinit(allocator);
    }
    try appendExistingConfigPath(io, allocator, &paths, env_map.get("OPENCODE_CONFIG"));
    if (home.len > 0 and std.fs.path.isAbsolute(home)) {
        try appendJoinedExisting(io, allocator, &paths, &.{ home, ".config", "opencode", "opencode.json" });
        try appendJoinedExisting(io, allocator, &paths, &.{ home, ".config", "opencode", "opencode.jsonc" });
        try appendJoinedExisting(io, allocator, &paths, &.{ home, ".opencode", "opencode.json" });
        try appendJoinedExisting(io, allocator, &paths, &.{ home, ".opencode", "opencode.jsonc" });
    }
    if (env_map.get("OPENCODE_CONFIG_DIR")) |dir| {
        try appendJoinedExisting(io, allocator, &paths, &.{ dir, "opencode.json" });
        try appendJoinedExisting(io, allocator, &paths, &.{ dir, "opencode.jsonc" });
    }
    try appendJoinedExisting(io, allocator, &paths, &.{ workspace_root, "opencode.json" });
    try appendJoinedExisting(io, allocator, &paths, &.{ workspace_root, "opencode.jsonc" });
    try appendJoinedExisting(io, allocator, &paths, &.{ workspace_root, ".opencode", "opencode.json" });
    try appendJoinedExisting(io, allocator, &paths, &.{ workspace_root, ".opencode", "opencode.jsonc" });

    var entries: std.ArrayList(u8) = .empty;
    errdefer entries.deinit(allocator);
    try entries.append(allocator, '[');
    var first = true;
    var file_count: usize = 0;
    for (paths.items) |path| {
        file_count += 1;
        if (file_count > max_config_files) return error.TooManyPaths;
        const text = readConfigText(io, allocator, path) catch continue;
        defer allocator.free(text);
        try appendOpenCodeServersJson(allocator, &entries, text, &first);
    }
    try entries.append(allocator, ']');
    return try entries.toOwnedSlice(allocator);
}

fn collectPiListJson(
    io: std.Io,
    allocator: std.mem.Allocator,
    workspace_root: []const u8,
    home: []const u8,
    env_map: *const std.process.Environ.Map,
) PlanError![]u8 {
    var paths: std.ArrayList([]const u8) = .empty;
    defer {
        for (paths.items) |p| allocator.free(p);
        paths.deinit(allocator);
    }
    // Same merge order as pi-mcp-adapter: shared-global → pi-global → project → pi-project.
    if (home.len > 0 and std.fs.path.isAbsolute(home)) {
        try appendJoinedExisting(io, allocator, &paths, &.{ home, ".config", "mcp", "mcp.json" });
    }
    const agent_dir = env_map.get("PI_CODING_AGENT_DIR") orelse blk: {
        if (home.len == 0 or !std.fs.path.isAbsolute(home)) break :blk null;
        break :blk try std.fs.path.join(allocator, &.{ home, ".pi", "agent" });
    };
    defer if (env_map.get("PI_CODING_AGENT_DIR") == null) if (agent_dir) |d| allocator.free(d);
    if (agent_dir) |dir| {
        try appendJoinedExisting(io, allocator, &paths, &.{ dir, "mcp.json" });
    }
    try appendJoinedExisting(io, allocator, &paths, &.{ workspace_root, ".mcp.json" });
    try appendJoinedExisting(io, allocator, &paths, &.{ workspace_root, ".pi", "mcp.json" });

    var entries: std.ArrayList(u8) = .empty;
    errdefer entries.deinit(allocator);
    try entries.append(allocator, '[');
    var first = true;
    var file_count: usize = 0;
    for (paths.items) |path| {
        file_count += 1;
        if (file_count > max_config_files) return error.TooManyPaths;
        const text = readConfigText(io, allocator, path) catch continue;
        defer allocator.free(text);
        try appendPiServersJson(allocator, &entries, text, &first);
    }
    try entries.append(allocator, ']');
    return try entries.toOwnedSlice(allocator);
}

fn appendOpenCodeServersJson(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    text: []const u8,
    first: *bool,
) PlanError!void {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, text, .{
        .ignore_unknown_fields = true,
    }) catch return;
    defer parsed.deinit();
    const root = switch (parsed.value) {
        .object => |obj| obj,
        else => return,
    };
    const mcp_val = root.get("mcp") orelse return;
    const mcp_obj = switch (mcp_val) {
        .object => |obj| obj,
        else => return,
    };
    var it = mcp_obj.iterator();
    while (it.next()) |entry| {
        const name = entry.key_ptr.*;
        const server = switch (entry.value_ptr.*) {
            .object => |obj| obj,
            else => continue,
        };
        const enabled = if (server.get("enabled")) |enabled_val| switch (enabled_val) {
            .bool => |b| b,
            else => true,
        } else true;
        if (!enabled) continue;
        const type_str = if (server.get("type")) |type_val| switch (type_val) {
            .string => |s| s,
            else => "local",
        } else "local";
        if (!std.mem.eql(u8, type_str, "local") and !std.mem.eql(u8, type_str, "stdio")) {
            try appendListEntryRemote(allocator, out, name, first);
            continue;
        }
        const command_val = server.get("command") orelse continue;
        var command: []const u8 = undefined;
        var args: []const []const u8 = &.{};
        var args_owned = false;
        defer if (args_owned) freeOwnedSlice(allocator, args);
        switch (command_val) {
            .string => |s| {
                command = s;
                if (server.get("args")) |args_val| {
                    args = try jsonStringArray(allocator, args_val);
                    args_owned = true;
                }
            },
            .array => |arr| {
                if (arr.items.len == 0) continue;
                command = switch (arr.items[0]) {
                    .string => |s| s,
                    else => continue,
                };
                if (arr.items.len > 1) {
                    var list: std.ArrayList([]const u8) = .empty;
                    errdefer freeOwnedList(allocator, &list);
                    for (arr.items[1..]) |item| {
                        const s = switch (item) {
                            .string => |v| v,
                            else => return error.InvalidInventory,
                        };
                        try appendCopy(allocator, &list, s);
                    }
                    args = try list.toOwnedSlice(allocator);
                    args_owned = true;
                }
            },
            else => continue,
        }
        const cwd = switch (server.get("cwd") orelse .null) {
            .string => |s| s,
            .null => null,
            else => null,
        };
        const env_val = server.get("environment") orelse server.get("env");
        try appendListEntryStdio(allocator, out, name, command, args, cwd, env_val, first);
    }
}

fn appendPiServersJson(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    text: []const u8,
    first: *bool,
) PlanError!void {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, text, .{
        .ignore_unknown_fields = true,
    }) catch return;
    defer parsed.deinit();
    const root = switch (parsed.value) {
        .object => |obj| obj,
        else => return,
    };
    const servers_val = root.get("mcpServers") orelse root.get("mcp-servers") orelse return;
    const servers = switch (servers_val) {
        .object => |obj| obj,
        else => return,
    };
    var it = servers.iterator();
    while (it.next()) |entry| {
        const name = entry.key_ptr.*;
        const server = switch (entry.value_ptr.*) {
            .object => |obj| obj,
            else => continue,
        };
        if (server.get("url") != null and server.get("command") == null) {
            try appendListEntryRemote(allocator, out, name, first);
            continue;
        }
        const command = switch (server.get("command") orelse continue) {
            .string => |s| s,
            else => continue,
        };
        var args: []const []const u8 = &.{};
        var args_owned = false;
        defer if (args_owned) freeOwnedSlice(allocator, args);
        if (server.get("args")) |args_val| {
            args = try jsonStringArray(allocator, args_val);
            args_owned = true;
        }
        const cwd = switch (server.get("cwd") orelse .null) {
            .string => |s| s,
            .null => null,
            else => null,
        };
        try appendListEntryStdio(allocator, out, name, command, args, cwd, server.get("env"), first);
    }
}

fn appendListEntryRemote(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    name: []const u8,
    first: *bool,
) PlanError!void {
    if (!first.*) try out.append(allocator, ',');
    first.* = false;
    const name_json = try std.json.Stringify.valueAlloc(allocator, name, .{});
    defer allocator.free(name_json);
    const piece = try std.fmt.allocPrint(
        allocator,
        "{{\"name\":{s},\"enabled\":true,\"transport\":{{\"type\":\"streamable_http\",\"url\":\"https://unmediated.invalid\"}}}}",
        .{name_json},
    );
    defer allocator.free(piece);
    try out.appendSlice(allocator, piece);
}

fn appendListEntryStdio(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    name: []const u8,
    command: []const u8,
    args: []const []const u8,
    cwd: ?[]const u8,
    env_val: ?std.json.Value,
    first: *bool,
) PlanError!void {
    if (!first.*) try out.append(allocator, ',');
    first.* = false;
    const name_json = try std.json.Stringify.valueAlloc(allocator, name, .{});
    defer allocator.free(name_json);
    const command_json = try std.json.Stringify.valueAlloc(allocator, command, .{});
    defer allocator.free(command_json);
    const args_json = try std.json.Stringify.valueAlloc(allocator, args, .{});
    defer allocator.free(args_json);
    const cwd_json = if (cwd) |c|
        try std.json.Stringify.valueAlloc(allocator, c, .{})
    else
        try allocator.dupe(u8, "null");
    defer allocator.free(cwd_json);
    var env_json: []const u8 = "null";
    var env_owned: ?[]u8 = null;
    defer if (env_owned) |e| allocator.free(e);
    if (env_val) |ev| {
        if (ev == .object) {
            env_owned = try std.json.Stringify.valueAlloc(allocator, ev, .{});
            env_json = env_owned.?;
        }
    }
    const piece = try std.fmt.allocPrint(
        allocator,
        "{{\"name\":{s},\"enabled\":true,\"transport\":{{\"type\":\"stdio\",\"command\":{s},\"args\":{s},\"env\":{s},\"cwd\":{s}}}}}",
        .{ name_json, command_json, args_json, env_json, cwd_json },
    );
    defer allocator.free(piece);
    try out.appendSlice(allocator, piece);
}

fn jsonStringArray(allocator: std.mem.Allocator, value: std.json.Value) PlanError![]const []const u8 {
    const arr = switch (value) {
        .array => |a| a,
        else => return error.InvalidInventory,
    };
    var list: std.ArrayList([]const u8) = .empty;
    errdefer freeOwnedList(allocator, &list);
    for (arr.items) |item| {
        const s = switch (item) {
            .string => |v| v,
            else => return error.InvalidInventory,
        };
        try appendCopy(allocator, &list, s);
    }
    return try list.toOwnedSlice(allocator);
}

fn buildFromInventory(
    io: std.Io,
    allocator: std.mem.Allocator,
    kind: HostKind,
    original_argv: []const []const u8,
    workspace_root: []const u8,
    policy_path: []const u8,
    mode: []const u8,
    home: []const u8,
    env_map: *const std.process.Environ.Map,
    ryk_exe: []const u8,
    inventory: sandbox.mcp_runtime_grants.LaunchInventory,
) !Plan {
    if (!std.fs.path.isAbsolute(workspace_root) or !std.fs.path.isAbsolute(ryk_exe)) {
        return error.InvalidInventory;
    }
    if (!sandbox.apply.ensureWorkspaceSessionTmp(workspace_root)) return error.SessionTmpPrepareFailed;
    const workspace_tmp = try sandbox.apply.workspaceSessionTmpPath(allocator, workspace_root);
    defer allocator.free(workspace_tmp);
    const audit_root = sandbox.apply.createFreshAttachTmp(io, allocator, workspace_tmp) catch
        return error.SessionTmpPrepareFailed;
    errdefer {
        std.Io.Dir.cwd().deleteTree(io, audit_root) catch {};
        allocator.free(audit_root);
    }
    const wrapper_parent = try prepareProtectedWrapperParent(io, allocator, workspace_root);
    defer allocator.free(wrapper_parent);
    const wrapper_root = sandbox.apply.createFreshAttachTmp(io, allocator, wrapper_parent) catch
        return error.SessionTmpPrepareFailed;
    errdefer {
        std.Io.Dir.cwd().deleteTree(io, wrapper_root) catch {};
        allocator.free(wrapper_root);
    }

    var argv: std.ArrayList([]const u8) = .empty;
    errdefer freeOwnedList(allocator, &argv);
    if (original_argv.len == 0) return error.InvalidInventory;
    for (original_argv) |arg| try appendCopy(allocator, &argv, arg);

    var exec_paths: std.ArrayList([]const u8) = .empty;
    errdefer freeOwnedList(allocator, &exec_paths);
    var ro_paths: std.ArrayList([]const u8) = .empty;
    errdefer freeOwnedList(allocator, &ro_paths);
    var disabled: std.ArrayList([]const u8) = .empty;
    errdefer freeOwnedList(allocator, &disabled);

    const ryk_exec = try sandbox.apply.collectLaunchExecPaths(io, allocator, ryk_exe, env_map);
    defer sandbox.apply.freeLaunchExecPaths(allocator, ryk_exec);
    if (ryk_exec.len == 0) return error.InvalidInventory;
    for (ryk_exec) |path| try appendUniqueCopy(allocator, &exec_paths, path);

    var approved_wrappers: std.ArrayList(ApprovedWrapper) = .empty;
    defer {
        for (approved_wrappers.items) |item| {
            allocator.free(item.name);
            allocator.free(item.wrapper);
        }
        approved_wrappers.deinit(allocator);
    }

    for (inventory.servers, 0..) |server, index| {
        var command_env_storage: ?std.process.Environ.Map = null;
        defer if (command_env_storage) |*map| map.deinit();
        const command_env = if (server.path_env) |path| blk: {
            var map = try env_map.clone(allocator);
            errdefer map.deinit();
            try map.put("PATH", path);
            command_env_storage = map;
            break :blk &command_env_storage.?;
        } else env_map;
        const launch_command = try commandForResolution(allocator, server);
        defer allocator.free(launch_command);
        const command_exec = try sandbox.apply.collectLaunchExecPaths(io, allocator, launch_command, command_env);
        defer sandbox.apply.freeLaunchExecPaths(allocator, command_exec);
        const command_ro = try sandbox.apply.collectLaunchInstallRoPaths(io, allocator, launch_command, command_env);
        defer sandbox.apply.freeLaunchInstallRoPaths(allocator, command_ro);

        var approved = command_exec.len > 0;
        for (command_exec) |path| {
            if (!isApprovedLaunchPath(path, home, workspace_root)) approved = false;
        }
        for (command_ro) |path| {
            if (!isApprovedLaunchPath(path, home, workspace_root)) approved = false;
        }

        const external_files = try hasExternalFiles(allocator, kind, server, workspace_root, home, env_map);
        const manifest_path = if (external_files)
            try snapshotMatchingManifest(io, allocator, workspace_root, wrapper_root, index, server)
        else
            null;
        defer if (manifest_path) |path| allocator.free(path);
        if (external_files and manifest_path == null) approved = false;

        if (!approved) {
            try appendUniqueCopy(allocator, &disabled, server.name);
            continue;
        }

        for (command_exec) |path| try appendUniqueCopy(allocator, &exec_paths, path);
        for (command_ro) |path| try appendUniqueCopy(allocator, &ro_paths, path);
        if (manifest_path != null) {
            try appendUniqueCopy(allocator, &ro_paths, manifest_path.?);
            for (server.file_args) |path| try appendUniqueCopy(allocator, &ro_paths, path);
            if (server.cwd) |cwd| {
                if (!isPathWithin(cwd, workspace_root)) try appendUniqueCopy(allocator, &ro_paths, cwd);
            }
        }
        if (exec_paths.items.len + ro_paths.items.len > sandbox.mcp_runtime_grants.max_grant_paths) {
            return error.TooManyPaths;
        }

        // Prefer an absolute resolved launch path so the proxy child does not
        // depend on PATH honesty (which may drop ~/.local/bin parents).
        const absolute_command = if (command_exec.len > 0) command_exec[0] else server.command;
        const wrapper = try createProxyWrapper(
            io,
            allocator,
            wrapper_root,
            audit_root,
            index,
            ryk_exe,
            workspace_root,
            policy_path,
            mode,
            server,
            absolute_command,
            manifest_path,
        );
        defer allocator.free(wrapper);
        try appendUniqueCopy(allocator, &exec_paths, wrapper);
        if (exec_paths.items.len + ro_paths.items.len > sandbox.mcp_runtime_grants.max_grant_paths) {
            return error.TooManyPaths;
        }
        const owned_name = try allocator.dupe(u8, server.name);
        errdefer allocator.free(owned_name);
        const owned_wrapper = try allocator.dupe(u8, wrapper);
        errdefer allocator.free(owned_wrapper);
        try approved_wrappers.append(allocator, .{ .name = owned_name, .wrapper = owned_wrapper });
    }

    for (inventory.unmediated_server_names) |name| {
        try appendUniqueCopy(allocator, &disabled, name);
    }

    var env_puts: std.ArrayList(EnvPut) = .empty;
    errdefer {
        for (env_puts.items) |put| {
            allocator.free(put.name);
            allocator.free(put.value);
        }
        env_puts.deinit(allocator);
    }

    switch (kind) {
        .opencode => {
            const content = try buildOpenCodeConfigContent(allocator, approved_wrappers.items, disabled.items);
            errdefer allocator.free(content);
            const name = try allocator.dupe(u8, "OPENCODE_CONFIG_CONTENT");
            errdefer allocator.free(name);
            try env_puts.append(allocator, .{ .name = name, .value = content });
        },
        .pi => {
            const config_path = try writePiClosedConfig(io, allocator, wrapper_root, approved_wrappers.items);
            errdefer allocator.free(config_path);
            try appendUniqueCopy(allocator, &ro_paths, config_path);
            try appendCopy(allocator, &argv, "--mcp-config");
            try appendCopy(allocator, &argv, config_path);
            allocator.free(config_path);
        },
    }

    const transferred = try transferOwnedInventorySlices(
        allocator,
        &argv,
        &exec_paths,
        &ro_paths,
        &disabled,
        &env_puts,
    );
    return .{
        .allocator = allocator,
        .argv = transferred.argv,
        .exec_paths = transferred.exec_paths,
        .ro_paths = transferred.ro_paths,
        .disabled_server_names = transferred.disabled_server_names,
        .env_puts = transferred.env_puts,
        .wrapper_root = wrapper_root,
        .audit_root = audit_root,
    };
}

fn transferOwnedInventorySlices(
    allocator: std.mem.Allocator,
    argv: *std.ArrayList([]const u8),
    exec_paths: *std.ArrayList([]const u8),
    ro_paths: *std.ArrayList([]const u8),
    disabled: *std.ArrayList([]const u8),
    env_puts: *std.ArrayList(EnvPut),
) error{OutOfMemory}!struct {
    argv: []const []const u8,
    exec_paths: []const []const u8,
    ro_paths: []const []const u8,
    disabled_server_names: []const []const u8,
    env_puts: []const EnvPut,
} {
    const owned_argv = try argv.toOwnedSlice(allocator);
    errdefer freeOwnedStrings(allocator, owned_argv);
    const owned_exec_paths = try exec_paths.toOwnedSlice(allocator);
    errdefer freeOwnedStrings(allocator, owned_exec_paths);
    const owned_ro_paths = try ro_paths.toOwnedSlice(allocator);
    errdefer freeOwnedStrings(allocator, owned_ro_paths);
    const owned_disabled = try disabled.toOwnedSlice(allocator);
    errdefer freeOwnedStrings(allocator, owned_disabled);
    const owned_env_puts = try env_puts.toOwnedSlice(allocator);
    errdefer {
        for (owned_env_puts) |put| {
            allocator.free(put.name);
            allocator.free(put.value);
        }
        allocator.free(owned_env_puts);
    }
    return .{
        .argv = owned_argv,
        .exec_paths = owned_exec_paths,
        .ro_paths = owned_ro_paths,
        .disabled_server_names = owned_disabled,
        .env_puts = owned_env_puts,
    };
}

fn buildOpenCodeConfigContent(
    allocator: std.mem.Allocator,
    approved: []const ApprovedWrapper,
    disabled: []const []const u8,
) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, "{\"mcp\":{");
    var first = true;
    for (approved) |item| {
        if (!first) try out.append(allocator, ',');
        first = false;
        const name_json = try std.json.Stringify.valueAlloc(allocator, item.name, .{});
        defer allocator.free(name_json);
        const wrapper_json = try std.json.Stringify.valueAlloc(allocator, item.wrapper, .{});
        defer allocator.free(wrapper_json);
        const piece = try std.fmt.allocPrint(
            allocator,
            "{s}:{{\"type\":\"local\",\"enabled\":true,\"command\":[{s}]}}",
            .{ name_json, wrapper_json },
        );
        defer allocator.free(piece);
        try out.appendSlice(allocator, piece);
    }
    for (disabled) |name| {
        if (!first) try out.append(allocator, ',');
        first = false;
        const name_json = try std.json.Stringify.valueAlloc(allocator, name, .{});
        defer allocator.free(name_json);
        const piece = try std.fmt.allocPrint(
            allocator,
            "{s}:{{\"type\":\"local\",\"enabled\":false,\"command\":[\"/usr/bin/false\"]}}",
            .{name_json},
        );
        defer allocator.free(piece);
        try out.appendSlice(allocator, piece);
    }
    try out.appendSlice(allocator, "}}");
    return try out.toOwnedSlice(allocator);
}

fn writePiClosedConfig(
    io: std.Io,
    allocator: std.mem.Allocator,
    wrapper_root: []const u8,
    approved: []const ApprovedWrapper,
) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, "{\"mcpServers\":{");
    var first = true;
    for (approved) |item| {
        if (!first) try out.append(allocator, ',');
        first = false;
        const name_json = try std.json.Stringify.valueAlloc(allocator, item.name, .{});
        defer allocator.free(name_json);
        const wrapper_json = try std.json.Stringify.valueAlloc(allocator, item.wrapper, .{});
        defer allocator.free(wrapper_json);
        const piece = try std.fmt.allocPrint(
            allocator,
            "{s}:{{\"command\":{s},\"args\":[]}}",
            .{ name_json, wrapper_json },
        );
        defer allocator.free(piece);
        try out.appendSlice(allocator, piece);
    }
    try out.appendSlice(allocator, "}}");
    const path = try std.fmt.allocPrint(allocator, "{s}/mcp-closed.json", .{wrapper_root});
    errdefer allocator.free(path);
    var file = std.Io.Dir.createFileAbsolute(io, path, .{ .exclusive = true }) catch
        return error.SessionTmpPrepareFailed;
    defer file.close(io);
    file.writeStreamingAll(io, out.items) catch return error.SessionTmpPrepareFailed;
    file.sync(io) catch return error.SessionTmpPrepareFailed;
    out.deinit(allocator);
    return path;
}

fn createProxyWrapper(
    io: std.Io,
    allocator: std.mem.Allocator,
    wrapper_root: []const u8,
    audit_root: []const u8,
    index: usize,
    ryk_exe: []const u8,
    workspace_root: []const u8,
    policy_path: []const u8,
    mode: []const u8,
    server: sandbox.mcp_runtime_grants.Server,
    absolute_command: []const u8,
    manifest_path: ?[]const u8,
) ![]u8 {
    const path = try std.fmt.allocPrint(allocator, "{s}/mcp-{d}.sh", .{ wrapper_root, index });
    errdefer allocator.free(path);
    var file = std.Io.Dir.createFileAbsolute(io, path, .{ .exclusive = true }) catch
        return error.SessionTmpPrepareFailed;
    defer file.close(io);
    var buffer: [4096]u8 = undefined;
    var writer = file.writer(io, &buffer);
    try writer.interface.writeAll("#!/bin/sh\n");
    if (!isPathWithin(audit_root, workspace_root) or audit_root.len <= workspace_root.len + 1) {
        return error.InvalidInventory;
    }
    const relative_audit_root = audit_root[workspace_root.len + 1 ..];
    const audit_dir_name = try std.fmt.allocPrint(
        allocator,
        "{s}/mcp-audit-{d}",
        .{ relative_audit_root, index },
    );
    defer allocator.free(audit_dir_name);

    if (server.cwd) |cwd| {
        try writer.interface.writeAll("cd ");
        try writeShellQuoted(&writer.interface, cwd);
        try writer.interface.writeAll(" || exit 126\n");
    }
    try writer.interface.writeAll("exec ");
    try writeShellQuoted(&writer.interface, ryk_exe);
    try writer.interface.writeAll(" mcp proxy --name ");
    try writeShellQuoted(&writer.interface, server.name);
    try writer.interface.writeAll(" --policy ");
    try writeShellQuoted(&writer.interface, policy_path);
    try writer.interface.writeAll(" --mode ");
    try writeShellQuoted(&writer.interface, mode);
    try writer.interface.writeAll(" --workspace ");
    try writeShellQuoted(&writer.interface, workspace_root);
    try writer.interface.writeAll(" --audit-dir-name ");
    try writeShellQuoted(&writer.interface, audit_dir_name);
    if (manifest_path) |manifest| {
        try writer.interface.writeAll(" --manifest ");
        try writeShellQuoted(&writer.interface, manifest);
    }
    // `--command` takes one token; remaining server argv must follow `--`.
    try writer.interface.writeAll(" --command ");
    try writeShellQuoted(&writer.interface, absolute_command);
    try writer.interface.writeAll(" --");
    for (server.args) |arg| {
        try writer.interface.writeAll(" ");
        try writeShellQuoted(&writer.interface, arg);
    }
    try writer.interface.writeByte('\n');
    try writer.interface.flush();
    if (builtin.os.tag != .windows) file.setPermissions(io, .executable_file) catch
        return error.SessionTmpPrepareFailed;
    return path;
}

fn isApprovedLaunchPath(path: []const u8, home: []const u8, workspace_root: []const u8) bool {
    // Workspace-local stdio servers are already inside the session RW grant.
    if (isPathWithin(path, workspace_root) and
        sandbox.mcp_runtime_grants.isSafeRuntimePath(path, home))
    {
        return true;
    }
    return sandbox.mcp_runtime_grants.isApprovedRuntimeCommandPath(path, home);
}

fn commandForResolution(
    allocator: std.mem.Allocator,
    server: sandbox.mcp_runtime_grants.Server,
) error{OutOfMemory}![]u8 {
    if (std.fs.path.isAbsolute(server.command) or std.mem.indexOfScalar(u8, server.command, '/') == null) {
        return allocator.dupe(u8, server.command);
    }
    const cwd = server.cwd orelse return allocator.dupe(u8, server.command);
    return std.fs.path.join(allocator, &.{ cwd, server.command });
}

fn hasExternalFiles(
    allocator: std.mem.Allocator,
    kind: HostKind,
    server: sandbox.mcp_runtime_grants.Server,
    workspace_root: []const u8,
    home: []const u8,
    env_map: *const std.process.Environ.Map,
) error{OutOfMemory}!bool {
    const host_root = try hostConfigRoot(allocator, kind, home, env_map);
    defer if (host_root) |path| allocator.free(path);
    if (server.cwd) |cwd| {
        if (!isPathWithin(cwd, workspace_root) and
            (host_root == null or !isPathWithin(cwd, host_root.?))) return true;
    }
    for (server.file_args) |path| {
        if (isPathWithin(path, workspace_root)) continue;
        if (host_root) |root| if (isPathWithin(path, root)) continue;
        return true;
    }
    return false;
}

fn hostConfigRoot(
    allocator: std.mem.Allocator,
    kind: HostKind,
    home: []const u8,
    env_map: *const std.process.Environ.Map,
) error{OutOfMemory}!?[]u8 {
    switch (kind) {
        .opencode => {
            if (env_map.get("OPENCODE_CONFIG_DIR")) |dir| {
                if (std.fs.path.isAbsolute(dir)) return try allocator.dupe(u8, dir);
            }
            if (home.len > 0 and std.fs.path.isAbsolute(home)) {
                return try std.fs.path.join(allocator, &.{ home, ".config", "opencode" });
            }
            return null;
        },
        .pi => {
            if (env_map.get("PI_CODING_AGENT_DIR")) |dir| {
                if (std.fs.path.isAbsolute(dir)) return try allocator.dupe(u8, dir);
            }
            if (home.len > 0 and std.fs.path.isAbsolute(home)) {
                return try std.fs.path.join(allocator, &.{ home, ".pi" });
            }
            return null;
        },
    }
}

fn snapshotMatchingManifest(
    io: std.Io,
    allocator: std.mem.Allocator,
    workspace_root: []const u8,
    wrapper_root: []const u8,
    server_index: usize,
    server: sandbox.mcp_runtime_grants.Server,
) !?[]u8 {
    const directory = try std.fs.path.join(allocator, &.{ workspace_root, ".ryk", "mcp" });
    defer allocator.free(directory);
    var dir = std.Io.Dir.openDirAbsolute(io, directory, .{
        .iterate = true,
        .follow_symlinks = false,
    }) catch return null;
    defer dir.close(io);
    var iterator = dir.iterate();
    var count: usize = 0;
    var matched_text: ?[]u8 = null;
    defer if (matched_text) |text| allocator.free(text);
    while (iterator.next(io) catch null) |entry| {
        if (entry.kind != .file or
            (!std.mem.endsWith(u8, entry.name, ".yaml") and !std.mem.endsWith(u8, entry.name, ".yml")))
        {
            continue;
        }
        count += 1;
        if (count > max_manifest_files) return error.TooManyPaths;
        const source_path = try std.fs.path.join(allocator, &.{ directory, entry.name });
        defer allocator.free(source_path);
        var file = dir.openFile(io, entry.name, .{ .follow_symlinks = false }) catch continue;
        defer file.close(io);
        var read_buffer: [4096]u8 = undefined;
        var reader = file.reader(io, &read_buffer);
        const text = reader.interface.allocRemaining(allocator, .limited(inventory_limit)) catch continue;
        defer allocator.free(text);
        var manifest = mcp_mod.manifests.parseFromSlice(allocator, text, source_path) catch continue;
        defer manifest.deinit(allocator);
        if (!std.mem.eql(u8, manifest.server.name, server.name) or
            !std.mem.eql(u8, manifest.server.command, server.command) or
            !equalStrings(manifest.server.args, server.args) or
            !equalOptionalStrings(manifest.server.cwd, server.cwd))
        {
            continue;
        }
        if (matched_text != null) return error.AmbiguousManifest;
        matched_text = try allocator.dupe(u8, text);
    }
    const exact_text = matched_text orelse return null;
    const snapshot_path = try std.fmt.allocPrint(
        allocator,
        "{s}/manifest-{d}.yaml",
        .{ wrapper_root, server_index },
    );
    errdefer allocator.free(snapshot_path);
    var snapshot = std.Io.Dir.createFileAbsolute(io, snapshot_path, .{ .exclusive = true }) catch
        return error.SessionTmpPrepareFailed;
    defer snapshot.close(io);
    snapshot.writeStreamingAll(io, exact_text) catch return error.SessionTmpPrepareFailed;
    snapshot.sync(io) catch return error.SessionTmpPrepareFailed;
    return snapshot_path;
}

fn prepareProtectedWrapperParent(
    io: std.Io,
    allocator: std.mem.Allocator,
    workspace_root: []const u8,
) PlanError![]u8 {
    const control_root = try std.fs.path.join(allocator, &.{ workspace_root, ".ryk" });
    defer allocator.free(control_root);
    try ensureDirectoryNoFollow(io, control_root);
    const wrapper_parent = try std.fs.path.join(allocator, &.{ control_root, "mcp-runtime" });
    errdefer allocator.free(wrapper_parent);
    try ensureDirectoryNoFollow(io, wrapper_parent);
    return wrapper_parent;
}

fn ensureDirectoryNoFollow(io: std.Io, path: []const u8) PlanError!void {
    std.Io.Dir.createDirAbsolute(io, path, .default_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return error.SessionTmpPrepareFailed,
    };
    var dir = std.Io.Dir.openDirAbsolute(io, path, .{ .follow_symlinks = false }) catch
        return error.SessionTmpPrepareFailed;
    dir.close(io);
}

fn readConfigText(io: std.Io, allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    var file = try std.Io.Dir.openFileAbsolute(io, path, .{ .follow_symlinks = false });
    defer file.close(io);
    var read_buffer: [4096]u8 = undefined;
    var reader = file.reader(io, &read_buffer);
    const raw = try reader.interface.allocRemaining(allocator, .limited(inventory_limit));
    errdefer allocator.free(raw);
    // Strip UTF-8 BOM and // line comments for loose JSONC tolerance.
    const body = if (std.mem.startsWith(u8, raw, "\xEF\xBB\xBF")) raw[3..] else raw;
    return try stripLineComments(allocator, body, raw);
}

fn stripLineComments(allocator: std.mem.Allocator, body: []const u8, raw_to_free: []u8) ![]u8 {
    defer allocator.free(raw_to_free);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var i: usize = 0;
    var in_string = false;
    var escape = false;
    while (i < body.len) : (i += 1) {
        const c = body[i];
        if (in_string) {
            try out.append(allocator, c);
            if (escape) {
                escape = false;
            } else if (c == '\\') {
                escape = true;
            } else if (c == '"') {
                in_string = false;
            }
            continue;
        }
        if (c == '"') {
            in_string = true;
            try out.append(allocator, c);
            continue;
        }
        if (c == '/' and i + 1 < body.len and body[i + 1] == '/') {
            while (i < body.len and body[i] != '\n') : (i += 1) {}
            if (i < body.len) try out.append(allocator, '\n');
            continue;
        }
        try out.append(allocator, c);
    }
    return try out.toOwnedSlice(allocator);
}

fn appendExistingConfigPath(
    io: std.Io,
    allocator: std.mem.Allocator,
    paths: *std.ArrayList([]const u8),
    maybe_path: ?[]const u8,
) error{OutOfMemory}!void {
    const path = maybe_path orelse return;
    if (!std.fs.path.isAbsolute(path)) return;
    std.Io.Dir.cwd().access(io, path, .{}) catch return;
    for (paths.items) |existing| if (std.mem.eql(u8, existing, path)) return;
    try appendCopy(allocator, paths, path);
}

fn appendJoinedExisting(
    io: std.Io,
    allocator: std.mem.Allocator,
    paths: *std.ArrayList([]const u8),
    parts: []const []const u8,
) error{OutOfMemory}!void {
    const path = try std.fs.path.join(allocator, parts);
    defer allocator.free(path);
    try appendExistingConfigPath(io, allocator, paths, path);
}

fn writeShellQuoted(writer: *std.Io.Writer, value: []const u8) !void {
    try writer.writeByte('\'');
    for (value) |byte| {
        if (byte == '\'') {
            try writer.writeAll("'\"'\"'");
        } else {
            try writer.writeByte(byte);
        }
    }
    try writer.writeByte('\'');
}

const isPathWithin = sandbox.profile.isPathWithin;

fn equalStrings(a: []const []const u8, b: []const []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |left, right| if (!std.mem.eql(u8, left, right)) return false;
    return true;
}

fn equalOptionalStrings(a: ?[]const u8, b: ?[]const u8) bool {
    if (a == null or b == null) return a == null and b == null;
    return std.mem.eql(u8, a.?, b.?);
}

fn appendCopy(
    allocator: std.mem.Allocator,
    list: *std.ArrayList([]const u8),
    value: []const u8,
) error{OutOfMemory}!void {
    const owned = try allocator.dupe(u8, value);
    list.append(allocator, owned) catch |err| {
        allocator.free(owned);
        return err;
    };
}

fn appendUniqueCopy(
    allocator: std.mem.Allocator,
    list: *std.ArrayList([]const u8),
    value: []const u8,
) error{OutOfMemory}!void {
    for (list.items) |existing| if (std.mem.eql(u8, existing, value)) return;
    try appendCopy(allocator, list, value);
}

fn freeOwnedList(allocator: std.mem.Allocator, list: *std.ArrayList([]const u8)) void {
    for (list.items) |value| allocator.free(value);
    list.deinit(allocator);
}

fn freeOwnedStrings(allocator: std.mem.Allocator, values: []const []const u8) void {
    for (values) |value| allocator.free(value);
    allocator.free(values);
}

fn freeOwnedSlice(allocator: std.mem.Allocator, values: []const []const u8) void {
    freeOwnedStrings(allocator, values);
}

fn pathPresent(paths: []const []const u8, needle: []const u8) bool {
    for (paths) |path| if (std.mem.eql(u8, path, needle)) return true;
    return false;
}

test {
    // File-local test module. Zig 0.16 -Dtest-filter= drops cli/mod.zig's unnamed
    // `_ = host_mcp_sandbox` pull, so this file must be a test module itself.
}

test "opencode plan wraps approved local MCP and disables remote" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const workspace = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(workspace);
    const home = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(home);

    try tmp.dir.createDirPath(io, ".config/opencode");
    try tmp.dir.createDirPath(io, ".local/bin");
    try tmp.dir.writeFile(io, .{
        .sub_path = ".local/bin/mcp-tool",
        .data = "#!/bin/sh\nexit 0\n",
    });
    var tool = try tmp.dir.openFile(io, ".local/bin/mcp-tool", .{});
    defer tool.close(io);
    try tool.setPermissions(io, .executable_file);
    const tool_path = try tmp.dir.realPathFileAlloc(io, ".local/bin/mcp-tool", allocator);
    defer allocator.free(tool_path);

    const config = try std.fmt.allocPrint(allocator,
        \\{{
        \\  "mcp": {{
        \\    "local-tool": {{
        \\      "type": "local",
        \\      "command": ["{s}", "mcp"]
        \\    }},
        \\    "remote-tool": {{
        \\      "type": "remote",
        \\      "url": "https://example.invalid/mcp"
        \\    }}
        \\  }}
        \\}}
    , .{tool_path});
    defer allocator.free(config);
    try tmp.dir.writeFile(io, .{ .sub_path = ".config/opencode/opencode.json", .data = config });

    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    try env_map.put("HOME", home);
    try env_map.put("PATH", "/usr/bin:/bin");

    const ryk_exe = try std.process.executablePathAlloc(io, allocator);
    defer allocator.free(ryk_exe);

    var servers = [_]sandbox.mcp_runtime_grants.Server{.{
        .name = "local-tool",
        .command = tool_path,
        .args = &.{"mcp"},
        .cwd = null,
        .file_args = &.{},
    }};
    var plan = try buildFromInventory(
        io,
        allocator,
        .opencode,
        &.{ "opencode", "run", "hi" },
        workspace,
        "/tmp/synthetic-policy.yaml",
        "ask",
        home,
        &env_map,
        ryk_exe,
        .{
            .servers = &servers,
            .unmediated_server_names = &.{"remote-tool"},
        },
    );
    defer plan.deinit(io);

    try std.testing.expectEqual(@as(usize, 1), plan.disabled_server_names.len);
    try std.testing.expectEqualStrings("remote-tool", plan.disabled_server_names[0]);
    try std.testing.expectEqual(@as(usize, 1), plan.env_puts.len);
    try std.testing.expectEqualStrings("OPENCODE_CONFIG_CONTENT", plan.env_puts[0].name);
    try std.testing.expect(std.mem.indexOf(u8, plan.env_puts[0].value, "local-tool") != null);
    try std.testing.expect(std.mem.indexOf(u8, plan.env_puts[0].value, "enabled\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, plan.env_puts[0].value, plan.wrapper_root) != null);
    const wrapper = try std.fs.path.join(allocator, &.{ plan.wrapper_root, "mcp-0.sh" });
    defer allocator.free(wrapper);
    try std.testing.expect(pathPresent(plan.exec_paths, wrapper));
    try std.testing.expect(pathPresent(plan.exec_paths, tool_path));
    const text = try std.Io.Dir.cwd().readFileAlloc(io, wrapper, allocator, .limited(16 * 1024));
    defer allocator.free(text);
    try std.testing.expect(std.mem.indexOf(u8, text, "mcp proxy") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "--command") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, " -- ") != null or std.mem.indexOf(u8, text, " --\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, tool_path) != null);
}

test "pi plan writes closed mcp config and appends --mcp-config" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const workspace = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(workspace);
    const home = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(home);

    try tmp.dir.createDirPath(io, ".local/bin");
    try tmp.dir.writeFile(io, .{
        .sub_path = ".local/bin/pi-mcp",
        .data = "#!/bin/sh\nexit 0\n",
    });
    var tool = try tmp.dir.openFile(io, ".local/bin/pi-mcp", .{});
    defer tool.close(io);
    try tool.setPermissions(io, .executable_file);
    const tool_path = try tmp.dir.realPathFileAlloc(io, ".local/bin/pi-mcp", allocator);
    defer allocator.free(tool_path);

    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    try env_map.put("HOME", home);
    try env_map.put("PATH", "/usr/bin:/bin");

    const ryk_exe = try std.process.executablePathAlloc(io, allocator);
    defer allocator.free(ryk_exe);

    var servers = [_]sandbox.mcp_runtime_grants.Server{.{
        .name = "pi-local",
        .command = tool_path,
        .args = &.{},
        .cwd = null,
        .file_args = &.{},
    }};
    var plan = try buildFromInventory(
        io,
        allocator,
        .pi,
        &.{ "pi", "--print", "hi" },
        workspace,
        "/tmp/synthetic-policy.yaml",
        "ask",
        home,
        &env_map,
        ryk_exe,
        .{ .servers = &servers, .unmediated_server_names = &.{} },
    );
    defer plan.deinit(io);

    try std.testing.expectEqual(@as(usize, 0), plan.disabled_server_names.len);
    try std.testing.expectEqual(@as(usize, 0), plan.env_puts.len);
    var saw_flag = false;
    var saw_config = false;
    for (plan.argv) |arg| {
        if (std.mem.eql(u8, arg, "--mcp-config")) saw_flag = true;
        if (std.mem.endsWith(u8, arg, "mcp-closed.json")) {
            saw_config = true;
            const text = try std.Io.Dir.cwd().readFileAlloc(io, arg, allocator, .limited(16 * 1024));
            defer allocator.free(text);
            try std.testing.expect(std.mem.indexOf(u8, text, "pi-local") != null);
            try std.testing.expect(std.mem.indexOf(u8, text, plan.wrapper_root) != null);
        }
    }
    try std.testing.expect(saw_flag);
    try std.testing.expect(saw_config);
}

test "openCode config collector extracts local command arrays" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(home);
    const workspace = home;
    try tmp.dir.createDirPath(io, ".config/opencode");
    try tmp.dir.writeFile(io, .{
        .sub_path = ".config/opencode/opencode.json",
        .data =
        \\{
        \\  "mcp": {
        \\    "open-computer-use": {
        \\      "type": "local",
        \\      "command": ["open-computer-use", "mcp"]
        \\    }
        \\  }
        \\}
        ,
    });
    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    try env_map.put("HOME", home);
    const json = try collectOpenCodeListJson(io, allocator, workspace, home, &env_map);
    defer allocator.free(json);
    try std.testing.expect(std.mem.indexOf(u8, json, "open-computer-use") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"stdio\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "open-computer-use") != null);
}

fn hostMcpTransferOomFreePending(
    allocator: std.mem.Allocator,
    argv: *std.ArrayList([]const u8),
    exec_paths: *std.ArrayList([]const u8),
    ro_paths: *std.ArrayList([]const u8),
    disabled: *std.ArrayList([]const u8),
    env_puts: *std.ArrayList(EnvPut),
) void {
    freeOwnedList(allocator, argv);
    freeOwnedList(allocator, exec_paths);
    freeOwnedList(allocator, ro_paths);
    freeOwnedList(allocator, disabled);
    for (env_puts.items) |put| {
        allocator.free(put.name);
        allocator.free(put.value);
    }
    env_puts.deinit(allocator);
}

fn hostMcpTransferOomFreeTransferred(
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    exec_paths: []const []const u8,
    ro_paths: []const []const u8,
    disabled_server_names: []const []const u8,
    env_puts: []const EnvPut,
) void {
    // Same ownership as Plan.deinit for the five transferred lists (no wrapper/audit trees).
    freeOwnedStrings(allocator, argv);
    freeOwnedStrings(allocator, exec_paths);
    freeOwnedStrings(allocator, ro_paths);
    freeOwnedStrings(allocator, disabled_server_names);
    for (env_puts) |put| {
        allocator.free(put.name);
        allocator.free(put.value);
    }
    allocator.free(env_puts);
}

fn hostMcpTransferOomSeedLists(
    allocator: std.mem.Allocator,
    argv: *std.ArrayList([]const u8),
    exec_paths: *std.ArrayList([]const u8),
    ro_paths: *std.ArrayList([]const u8),
    disabled: *std.ArrayList([]const u8),
    env_puts: *std.ArrayList(EnvPut),
) error{OutOfMemory}!void {
    // Non-empty so each toOwnedSlice reallocates; empty lists can skip the hole.
    try appendCopy(allocator, argv, "opencode");
    try appendCopy(allocator, exec_paths, "/usr/bin/false");
    try appendCopy(allocator, ro_paths, "/usr/bin");
    try appendCopy(allocator, disabled, "remote-tool");
    // Block drops errdefer after a successful append so a later OOM is not a double-free.
    {
        const env_name = try allocator.dupe(u8, "OPENCODE_CONFIG_CONTENT");
        errdefer allocator.free(env_name);
        const env_value = try allocator.dupe(u8, "{\"mcp\":{}}");
        errdefer allocator.free(env_value);
        try env_puts.append(allocator, .{ .name = env_name, .value = env_value });
    }
}

fn hostMcpTransferOomSeedListsProbe(allocator: std.mem.Allocator) !void {
    var argv: std.ArrayList([]const u8) = .empty;
    var exec_paths: std.ArrayList([]const u8) = .empty;
    var ro_paths: std.ArrayList([]const u8) = .empty;
    var disabled: std.ArrayList([]const u8) = .empty;
    var env_puts: std.ArrayList(EnvPut) = .empty;
    errdefer hostMcpTransferOomFreePending(allocator, &argv, &exec_paths, &ro_paths, &disabled, &env_puts);
    try hostMcpTransferOomSeedLists(allocator, &argv, &exec_paths, &ro_paths, &disabled, &env_puts);
    try std.testing.expectEqual(@as(usize, 1), argv.items.len);
    try std.testing.expectEqual(@as(usize, 1), exec_paths.items.len);
    try std.testing.expectEqual(@as(usize, 1), ro_paths.items.len);
    try std.testing.expectEqual(@as(usize, 1), disabled.items.len);
    try std.testing.expectEqual(@as(usize, 1), env_puts.items.len);
    hostMcpTransferOomFreePending(allocator, &argv, &exec_paths, &ro_paths, &disabled, &env_puts);
}

fn hostMcpTransferOwnedInventorySlicesOomProbe(allocator: std.mem.Allocator) !void {
    var argv: std.ArrayList([]const u8) = .empty;
    var exec_paths: std.ArrayList([]const u8) = .empty;
    var ro_paths: std.ArrayList([]const u8) = .empty;
    var disabled: std.ArrayList([]const u8) = .empty;
    var env_puts: std.ArrayList(EnvPut) = .empty;
    errdefer hostMcpTransferOomFreePending(allocator, &argv, &exec_paths, &ro_paths, &disabled, &env_puts);
    try hostMcpTransferOomSeedLists(allocator, &argv, &exec_paths, &ro_paths, &disabled, &env_puts);

    const transferred = try transferOwnedInventorySlices(
        allocator,
        &argv,
        &exec_paths,
        &ro_paths,
        &disabled,
        &env_puts,
    );
    defer hostMcpTransferOomFreeTransferred(
        allocator,
        transferred.argv,
        transferred.exec_paths,
        transferred.ro_paths,
        transferred.disabled_server_names,
        transferred.env_puts,
    );
    argv.deinit(allocator);
    exec_paths.deinit(allocator);
    ro_paths.deinit(allocator);
    disabled.deinit(allocator);
    env_puts.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), transferred.argv.len);
    try std.testing.expectEqualStrings("opencode", transferred.argv[0]);
    try std.testing.expectEqual(@as(usize, 1), transferred.exec_paths.len);
    try std.testing.expectEqualStrings("/usr/bin/false", transferred.exec_paths[0]);
    try std.testing.expectEqual(@as(usize, 1), transferred.ro_paths.len);
    try std.testing.expectEqualStrings("/usr/bin", transferred.ro_paths[0]);
    try std.testing.expectEqual(@as(usize, 1), transferred.disabled_server_names.len);
    try std.testing.expectEqualStrings("remote-tool", transferred.disabled_server_names[0]);
    try std.testing.expectEqual(@as(usize, 1), transferred.env_puts.len);
    try std.testing.expectEqualStrings("OPENCODE_CONFIG_CONTENT", transferred.env_puts[0].name);
    try std.testing.expectEqualStrings("{\"mcp\":{}}", transferred.env_puts[0].value);
}

fn hostMcpTransferOomFailAtZeroIsOutOfMemory() !void {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(
        error.OutOfMemory,
        hostMcpTransferOwnedInventorySlicesOomProbe(failing.allocator()),
    );
    const as_plan: PlanError = error.OutOfMemory;
    try std.testing.expect(as_plan != error.InvalidInventory);
    try std.testing.expect(failing.has_induced_failure);
}

test "HostMcpTransferOom host MCP inventory transfer OOM" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, hostMcpTransferOomSeedListsProbe, .{});
    try std.testing.checkAllAllocationFailures(std.testing.allocator, hostMcpTransferOwnedInventorySlicesOomProbe, .{});
    try hostMcpTransferOomFailAtZeroIsOutOfMemory();
}

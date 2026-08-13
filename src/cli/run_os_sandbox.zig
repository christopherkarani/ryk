//! OS filesystem sandbox helpers for `ryk run`.
//!
//! Keeps apply-before-exec wiring, spawn hooks, auto-degrade messaging, and
//! posture audit/banner helpers out of the main `run.zig` orchestration file.

const std = @import("std");
const builtin = @import("builtin");

const core = @import("ryk_core").core;
const core_api = @import("ryk_core").api;
const sandbox = @import("../sandbox/mod.zig");
const path_list = sandbox.path_list;
const exit_codes = @import("exit_codes.zig");
const tui = @import("../tui/mod.zig");

/// ~12 fps — same cadence as `ryk scan` spinner.
const prepare_spinner_tick = std.Io.Duration.fromNanoseconds(80 * std.time.ns_per_ms);

pub const ApplyForRunOutcome = union(enum) {
    /// `--os-sandbox on` failed closed; already printed reason to stderr.
    require_failed: u8,
    /// Prepared (or disabled) result — caller must `deinit`.
    ok: sandbox.apply.ApplyResult,
};

/// TTY activity for the long protect-on / platform prepare window so monorepo
/// hardlink scans do not look hung. No residual success line — the session
/// banner follows. Spinner thread is joined before return so agent fork stays
/// free of this ticker (Seatbelt multi-thread residual).
fn PrepareActivity(comptime Writer: type) type {
    return struct {
        const Self = @This();

        io: std.Io,
        writer: Writer,
        label: []const u8,
        spinner: ?tui.spinner.Spinner(Writer) = null,
        active: bool = false,
        mutex: std.Io.Mutex = .init,
        stop_ticker: std.atomic.Value(bool) = .init(true),
        ticker_thread: ?std.Thread = null,

        fn start(self: *Self) void {
            if (!tui.theme.active(self.io, self.writer).capability.hasColor()) return;
            self.spinner = .{
                .label = self.label,
                .io = self.io,
                .stdout = self.writer,
            };
            self.spinner.?.start() catch {};
            self.active = true;
            self.startTicker();
        }

        fn startTicker(self: *Self) void {
            if (tui.theme.reducedMotion(self.io, self.writer)) return;
            if (!tui.theme.active(self.io, self.writer).capability.hasColor()) return;
            if (self.ticker_thread != null) return;
            self.stop_ticker.store(false, .release);
            self.ticker_thread = std.Thread.spawn(.{}, tickerLoop, .{self}) catch null;
        }

        fn stopTicker(self: *Self) void {
            self.stop_ticker.store(true, .release);
            if (self.ticker_thread) |t| {
                t.join();
                self.ticker_thread = null;
            }
        }

        fn clear(self: *Self) void {
            if (!self.active) return;
            self.stopTicker();
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            // Clear in-place frame only; no ✓/✗ line (session banner or error follows).
            if (tui.theme.active(self.io, self.writer).capability.hasColor() and
                !tui.theme.reducedMotion(self.io, self.writer))
            {
                self.writer.writeAll("\r\x1b[2K\r") catch {};
            }
            flushWriter(self.writer) catch {};
            self.active = false;
            self.spinner = null;
        }

        fn tickLocked(self: *Self) void {
            if (self.spinner) |*sp| sp.tick() catch {};
        }

        fn tickerLoop(self: *Self) void {
            while (!self.stop_ticker.load(.acquire)) {
                std.Io.sleep(self.io, prepare_spinner_tick, .awake) catch {};
                if (self.stop_ticker.load(.acquire)) break;
                self.mutex.lockUncancelable(self.io);
                defer self.mutex.unlock(self.io);
                if (!self.active) continue;
                self.tickLocked();
            }
        }
    };
}

fn flushWriter(writer: anytype) !void {
    const Writer = @TypeOf(writer);
    switch (@typeInfo(Writer)) {
        .pointer => |pointer| if (@hasDecl(pointer.child, "flush")) try writer.flush(),
        else => if (@hasDecl(Writer, "flush")) try writer.flush(),
    }
}

/// Concatenate two owned path lists into one. Dupes path strings into the result,
/// then frees `a` and `b` completely on success. On error leaves `a`/`b` intact
/// for the caller's errdefer. Dedups exact string matches (prefer `a`).
fn mergeOwnedPathLists(
    allocator: std.mem.Allocator,
    a: []const []const u8,
    b: []const []const u8,
) error{OutOfMemory}![]const []const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (list.items) |p| allocator.free(p);
        list.deinit(allocator);
    }

    for (a) |p| {
        const owned = try allocator.dupe(u8, p);
        errdefer allocator.free(owned);
        try list.append(allocator, owned);
    }
    for (b) |p| {
        var is_dup = false;
        for (list.items) |existing| {
            if (std.mem.eql(u8, existing, p)) {
                is_dup = true;
                break;
            }
        }
        if (is_dup) continue;
        const owned = try allocator.dupe(u8, p);
        errdefer allocator.free(owned);
        try list.append(allocator, owned);
    }

    const out = try list.toOwnedSlice(allocator);
    // Success: consume inputs so callers must not free them again.
    path_list.free(allocator, a);
    path_list.free(allocator, b);
    return out;
}

/// Same dedup semantics as `mergeOwnedPathLists`, but leaves both inputs owned
/// by their callers. Used when MCP parser results and top-level launch grants
/// have independent lifetimes.
fn copyMergedPathLists(
    allocator: std.mem.Allocator,
    a: []const []const u8,
    b: []const []const u8,
) error{OutOfMemory}![]const []const u8 {
    const a_copy = try path_list.clone(allocator, a);
    errdefer path_list.free(allocator, a_copy);
    const b_copy = try path_list.clone(allocator, b);
    errdefer path_list.free(allocator, b_copy);
    return mergeOwnedPathLists(allocator, a_copy, b_copy);
}

fn containsPath(paths: []const []const u8, candidate: []const u8) bool {
    for (paths) |path| if (std.mem.eql(u8, path, candidate)) return true;
    return false;
}

fn collectCustomCodexHome(
    io: std.Io,
    allocator: std.mem.Allocator,
    host: []const u8,
    home: []const u8,
    env_map: *const std.process.Environ.Map,
) error{OutOfMemory}![]const []const u8 {
    if (!std.mem.eql(u8, host, "codex")) {
        return allocator.alloc([]const u8, 0);
    }
    const custom = env_map.get("CODEX_HOME") orelse return allocator.alloc([]const u8, 0);
    if (!std.fs.path.isAbsolute(custom)) {
        return allocator.alloc([]const u8, 0);
    }
    var dir = std.Io.Dir.openDirAbsolute(io, custom, .{ .follow_symlinks = false }) catch
        return allocator.alloc([]const u8, 0);
    dir.close(io);
    const canonical = std.Io.Dir.cwd().realPathFileAlloc(io, custom, allocator) catch
        return allocator.alloc([]const u8, 0);
    defer allocator.free(canonical);
    const normalized_home = normalizeMacosUsersPath(home);
    const normalized_custom = normalizeMacosUsersPath(canonical);
    if (sandbox.host_config_grants.isForbiddenHostConfigPath(normalized_custom, normalized_home) or
        !isApprovedCodexHome(normalized_custom, normalized_home))
    {
        return allocator.alloc([]const u8, 0);
    }
    const paths = try allocator.alloc([]const u8, 1);
    errdefer allocator.free(paths);
    paths[0] = try allocator.dupe(u8, canonical);
    return paths;
}

fn withoutDefaultCodexHome(
    allocator: std.mem.Allocator,
    paths: []const []const u8,
    home: []const u8,
    custom_home_active: bool,
) error{OutOfMemory}![]const []const u8 {
    if (!custom_home_active or home.len == 0 or !std.fs.path.isAbsolute(home)) {
        return path_list.clone(allocator, paths);
    }
    const default_root = try std.fs.path.join(allocator, &.{ home, ".codex" });
    defer allocator.free(default_root);
    var filtered: std.ArrayList([]const u8) = .empty;
    errdefer freeOwnedList(allocator, &filtered);
    for (paths) |path| {
        if (std.mem.eql(u8, normalizeMacosUsersPath(path), normalizeMacosUsersPath(default_root))) continue;
        const owned = try allocator.dupe(u8, path);
        errdefer allocator.free(owned);
        try filtered.append(allocator, owned);
    }
    return filtered.toOwnedSlice(allocator);
}

fn freeOwnedList(allocator: std.mem.Allocator, list: *std.ArrayList([]const u8)) void {
    for (list.items) |item| allocator.free(item);
    list.deinit(allocator);
}

fn isApprovedCodexHome(path: []const u8, home: []const u8) bool {
    if (!sandbox.profile.isPathWithin(path, home) or std.mem.eql(u8, path, home)) return false;
    const relative = path[home.len + 1 ..];
    return std.mem.eql(u8, relative, ".codex") or
        std.mem.startsWith(u8, relative, ".codex-") or
        std.mem.eql(u8, relative, ".config/codex");
}

fn isApprovedCustomHostConfigPath(host: []const u8, path: []const u8, home: []const u8) bool {
    if (!sandbox.profile.isPathWithin(path, home) or std.mem.eql(u8, path, home)) return false;
    if (sandbox.host_config_grants.isForbiddenHostConfigPath(path, home)) return false;
    const relative = path[home.len + 1 ..];
    if (std.mem.eql(u8, host, "claude")) {
        return isWithinRelativeRoot(relative, ".claude") or
            isWithinRelativeRoot(relative, ".config/claude") or
            hasTopLevelVariant(relative, ".claude-");
    }
    if (std.mem.eql(u8, host, "pi")) {
        return isWithinRelativeRoot(relative, ".pi") or
            isWithinRelativeRoot(relative, ".config/pi") or
            hasTopLevelVariant(relative, ".pi-");
    }
    if (std.mem.eql(u8, host, "opencode")) {
        return isWithinRelativeRoot(relative, ".opencode") or
            isWithinRelativeRoot(relative, ".config/opencode") or
            hasTopLevelVariant(relative, ".opencode-");
    }
    if (std.mem.eql(u8, host, "hermes")) {
        return isWithinRelativeRoot(relative, ".hermes") or
            isWithinRelativeRoot(relative, ".config/hermes") or
            hasTopLevelVariant(relative, ".hermes-");
    }
    return false;
}

fn isWithinRelativeRoot(path: []const u8, root: []const u8) bool {
    return std.mem.eql(u8, path, root) or
        (path.len > root.len and std.mem.startsWith(u8, path, root) and path[root.len] == '/');
}

fn hasTopLevelVariant(path: []const u8, prefix: []const u8) bool {
    if (!std.mem.startsWith(u8, path, prefix) or path.len == prefix.len) return false;
    const first_component = std.mem.indexOfScalar(u8, path, '/') orelse path.len;
    return first_component > prefix.len;
}

fn customConfigEnvKeys(host: []const u8) []const []const u8 {
    if (std.mem.eql(u8, host, "claude")) return &.{"CLAUDE_CONFIG_DIR"};
    if (std.mem.eql(u8, host, "pi")) return &.{"PI_CODING_AGENT_DIR"};
    if (std.mem.eql(u8, host, "opencode")) return &.{ "OPENCODE_CONFIG", "OPENCODE_CONFIG_DIR" };
    if (std.mem.eql(u8, host, "hermes")) return &.{"HERMES_HOME"};
    return &.{};
}

fn collectCustomHostConfigPaths(
    io: std.Io,
    allocator: std.mem.Allocator,
    host: []const u8,
    home: []const u8,
    env_map: *std.process.Environ.Map,
) error{OutOfMemory}![]const []const u8 {
    if (home.len == 0 or !std.fs.path.isAbsolute(home)) return allocator.alloc([]const u8, 0);

    var paths: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (paths.items) |path| allocator.free(path);
        paths.deinit(allocator);
    }
    for (customConfigEnvKeys(host)) |key| {
        const configured = env_map.get(key) orelse continue;
        if (!std.fs.path.isAbsolute(configured)) {
            _ = env_map.swapRemove(key);
            continue;
        }
        const canonical_z = std.Io.Dir.cwd().realPathFileAlloc(io, configured, allocator) catch {
            _ = env_map.swapRemove(key);
            continue;
        };
        defer allocator.free(canonical_z);
        const normalized_home = normalizeMacosUsersPath(home);
        const normalized = normalizeMacosUsersPath(canonical_z);
        if (!isApprovedCustomHostConfigPath(host, normalized, normalized_home)) {
            _ = env_map.swapRemove(key);
            continue;
        }
        try env_map.put(key, canonical_z);
        if (containsPath(paths.items, canonical_z)) continue;
        const canonical = try allocator.dupe(u8, canonical_z);
        errdefer allocator.free(canonical);
        try paths.append(allocator, canonical);
    }
    return paths.toOwnedSlice(allocator);
}

fn normalizeMacosUsersPath(path: []const u8) []const u8 {
    const data_prefix = "/System/Volumes/Data";
    if (std.mem.startsWith(u8, path, data_prefix) and path.len > data_prefix.len and
        path[data_prefix.len] == '/' and std.mem.startsWith(u8, path[data_prefix.len..], "/Users/"))
    {
        return path[data_prefix.len..];
    }
    return path;
}

/// Apply OS sandbox for the production run path.
///
/// `progress` is the TTY stream for prepare activity (typically stdout, same as
/// the session banner). Errors still print on `stderr`.
///
/// `launch_argv0` is the agent command (first argv of `ryk run -- <cmd>`). When set,
/// resolved absolute file paths are granted as narrow `.exec` profile entries so
/// agents installed outside workspace/system prefixes (typical `~/.local/...`) can
/// pass child preflight after Seatbelt/Landlock attach.
///
/// `trusted_host_key` is the **already-bound** host_config_table key from
/// `host_identity.resolveHostIdentity` in `run.zig` (empty when generic). Host-config
/// RW / system RO / write-denies / custom cfg use this key only — do not re-resolve
/// under the filtered child env (empty-backpack strips `RYK_TRUSTED_HOST_PREFIXES`
/// and would split-brain empty backpack vs grants). Basename-only spoofs pass empty.
/// Host-scoped system RO trees (e.g. codex `/etc/codex`) and macOS Apple developer
/// toolchains (CLT / Xcode `Contents/Developer` for `/usr/bin/git` libxcselect) merge
/// into the same launch RO list as install package roots.
pub fn applyForRun(
    io: std.Io,
    allocator: std.mem.Allocator,
    mode: sandbox.posture.OsSandboxMode,
    workspace_root: []const u8,
    env_map: *std.process.Environ.Map,
    minted_env_lookup: ?sandbox.env_scrub.MintedEnvLookup,
    with_host_secrets: bool,
    network_proxy_port: ?u16,
    require_network_route_forcing: bool,
    seatbelt_profile: sandbox.posture.SeatbeltProfileGrade,
    protect_workspace_secrets: bool,
    progress: anytype,
    stderr: anytype,
    launch_argv0: ?[]const u8,
    /// Table host key from a single pre-apply `resolveHostIdentity` (or empty).
    trusted_host_key: []const u8,
    extra_exec_paths: []const []const u8,
    extra_ro_paths: []const []const u8,
) !ApplyForRunOutcome {
    const label: []const u8 = if (protect_workspace_secrets)
        "Preparing OS sandbox (scanning workspace secrets)"
    else
        "Preparing OS sandbox";

    var activity = PrepareActivity(@TypeOf(progress)){
        .io = io,
        .writer = progress,
        .label = label,
    };
    // Only animate when apply will do real work (on/auto). Join ticker in clear
    // before return so later agent fork is not multi-threaded solely for UX.
    if (mode != .off) activity.start();
    defer activity.clear();

    var fail_reason: []const u8 = "unknown";
    var io_rt: std.Io.Threaded = .init_single_threaded;
    const launch_io = io_rt.io();
    const home_for_config: []const u8 = if (env_map.get("HOME")) |h| h else "";
    // Single bind in run.zig — empty key means generic (no host-config grants).
    const trusted_host = if (sandbox.host_config_grants.specForHost(trusted_host_key) != null)
        trusted_host_key
    else
        "";
    // Authority write-deny paths (cross-platform): Seatbelt literal write-deny on
    // macOS + Landlock control_roots expand (RO leaf under host RW) on Linux.
    const config_write_denies = if (mode != .off and trusted_host.len > 0)
        sandbox.host_config_grants.collectHostConfigWriteDenies(
            launch_io,
            allocator,
            trusted_host,
            workspace_root,
            env_map,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.UnsafeHostConfigHardlink => {
                activity.clear();
                try stderr.writeAll(
                    "ryk run: host configuration has a hardlink alias; refusing an incomplete write boundary.\n",
                );
                return .{ .require_failed = exit_codes.unsupported };
            },
        }
    else
        try allocator.alloc([]const u8, 0);
    defer sandbox.host_config_grants.freeHostConfigWriteDenies(allocator, config_write_denies);
    const agent_exec_paths: []const []const u8 = if (launch_argv0) |argv0|
        try sandbox.apply.collectLaunchExecPaths(launch_io, allocator, argv0, env_map)
    else
        try allocator.alloc([]const u8, 0);
    defer sandbox.apply.freeLaunchExecPaths(allocator, agent_exec_paths);
    // Phase 4: essentials tool pack → file-only .exec grants (rg/fd/jq/zig/git).
    // Default essentials when OS attach is planned; RYK_TOOL_PACK=none kills the pack.
    const os_attach_planned = mode != .off;
    const tool_pack = sandbox.tool_pack.resolveToolPack(env_map, os_attach_planned);
    const pack_exec_paths = try sandbox.tool_pack.collectPackExecPaths(
        launch_io,
        allocator,
        tool_pack,
        workspace_root,
        env_map,
    );
    defer sandbox.tool_pack.freePackExecPaths(allocator, pack_exec_paths);
    const pack_ro_paths = try sandbox.tool_pack.collectPackRoPaths(
        launch_io,
        allocator,
        pack_exec_paths,
    );
    defer sandbox.tool_pack.freePackExecPaths(allocator, pack_ro_paths);
    // Honesty labels for the child (even when pack resolves empty).
    try env_map.put(sandbox.tool_pack.tool_pack_env, tool_pack.toString());
    const agent_and_pack = try copyMergedPathLists(allocator, agent_exec_paths, pack_exec_paths);
    defer path_list.free(allocator, agent_and_pack);
    const launch_exec_paths = try copyMergedPathLists(
        allocator,
        agent_and_pack,
        extra_exec_paths,
    );
    defer path_list.free(allocator, launch_exec_paths);

    // Node/npm agents: RO package root so nested optional deps + vendor binaries
    // are readable after empty-backpack Seatbelt (file-only .exec is not enough).
    // Host system RO (e.g. codex `/etc/codex`) merges into the same `.ro` list.
    // macOS: Apple developer toolchains (CLT / Xcode Developer) so /usr/bin/git
    // libxcselect stubs work for every agent (opencode, hermes, …) without a
    // false “install developer tools” dialog — never bare /Applications.
    // Nested scopes so mergeOwnedPathLists consume + errdefer pairs end before
    // later fallible work (otherwise OOM after consume double-frees inputs).
    const base_launch_ro_paths: []const []const u8 = blk: {
        const install_system_toolchain: []const []const u8 = merge_ist: {
            const install_system: []const []const u8 = if (launch_argv0) |argv0| inner: {
                const install_ro = try sandbox.apply.collectLaunchInstallRoPaths(launch_io, allocator, argv0, env_map);
                errdefer sandbox.apply.freeLaunchInstallRoPaths(allocator, install_ro);
                const system_ro = try sandbox.host_config_grants.collectHostSystemRoPaths(allocator, trusted_host);
                errdefer sandbox.host_config_grants.freeHostSystemRoPaths(allocator, system_ro);
                break :inner try mergeOwnedPathLists(allocator, install_ro, system_ro);
            } else try allocator.alloc([]const u8, 0);
            errdefer path_list.free(allocator, install_system);

            const toolchain_ro = try sandbox.host_config_grants.collectMacosDeveloperToolchainRoPaths(
                launch_io,
                allocator,
                env_map,
            );
            errdefer sandbox.host_config_grants.freeHostSystemRoPaths(allocator, toolchain_ro);
            // Consumes both inputs on success; errdefers above only run if this fails.
            break :merge_ist try mergeOwnedPathLists(allocator, install_system, toolchain_ro);
        };
        errdefer path_list.free(allocator, install_system_toolchain);

        // Parent-of-workspace AGENTS.md / CLAUDE.md (file RO only). Pi and peers
        // walk up from cwd; empty backpack previously denied these by design and
        // agents printed EPERM warnings. Never grants parent directory trees.
        const ancestor_ro = try sandbox.host_config_grants.collectAncestorInstructionRoPaths(
            launch_io,
            allocator,
            workspace_root,
            home_for_config,
        );
        errdefer sandbox.host_config_grants.freeHostSystemRoPaths(allocator, ancestor_ro);
        break :blk try mergeOwnedPathLists(allocator, install_system_toolchain, ancestor_ro);
    };
    defer path_list.free(allocator, base_launch_ro_paths);
    // Pack dylib/formula RO (Homebrew linked libs) + MCP/extra RO.
    const base_and_pack_ro = try copyMergedPathLists(allocator, base_launch_ro_paths, pack_ro_paths);
    defer path_list.free(allocator, base_and_pack_ro);
    const launch_ro_paths = try copyMergedPathLists(
        allocator,
        base_and_pack_ro,
        extra_ro_paths,
    );
    defer path_list.free(allocator, launch_ro_paths);

    // Pin DEVELOPER_DIR for the child (prefer CLT). Stops libxcselect from
    // requiring host select-link resolution when links are stale/broken, and
    // avoids the false “install developer tools” dialog under Seatbelt.
    // Uses launch_ro_paths after merge so the map value is duped from a live path.
    if (builtin.os.tag == .macos) {
        const existing = env_map.get("DEVELOPER_DIR");
        const existing_ok = if (existing) |d|
            sandbox.host_config_grants.isAllowlistedMacosDeveloperToolchainPath(d)
        else
            false;
        if (!existing_ok) {
            if (sandbox.host_config_grants.preferredMacosDeveloperDir(launch_ro_paths)) |preferred| {
                try env_map.put("DEVELOPER_DIR", preferred);
            }
        }
        // Keep PATH identical to the environment used by MCP inventory
        // preflight. DEVELOPER_DIR is enough for libxcselect; prepending a
        // toolchain here could change a bare MCP command after approval.
    }

    const base_host_rw_paths_unfiltered: []const []const u8 = if (trusted_host.len > 0)
        try sandbox.host_config_grants.collectHostConfigPaths(launch_io, allocator, trusted_host, home_for_config)
    else
        try allocator.alloc([]const u8, 0);
    defer sandbox.host_config_grants.freeHostConfigPaths(allocator, base_host_rw_paths_unfiltered);
    const custom_codex_home = if (trusted_host.len > 0)
        try collectCustomCodexHome(launch_io, allocator, trusted_host, home_for_config, env_map)
    else
        try allocator.alloc([]const u8, 0);
    defer path_list.free(allocator, custom_codex_home);
    const base_host_rw_paths = try withoutDefaultCodexHome(
        allocator,
        base_host_rw_paths_unfiltered,
        home_for_config,
        custom_codex_home.len > 0,
    );
    defer path_list.free(allocator, base_host_rw_paths);
    const base_and_codex_rw_paths = try copyMergedPathLists(
        allocator,
        base_host_rw_paths,
        custom_codex_home,
    );
    defer path_list.free(allocator, base_and_codex_rw_paths);
    const custom_host_config = if (trusted_host.len > 0)
        try collectCustomHostConfigPaths(launch_io, allocator, trusted_host, home_for_config, env_map)
    else
        try allocator.alloc([]const u8, 0);
    defer path_list.free(allocator, custom_host_config);
    const launch_host_rw_paths = try copyMergedPathLists(
        allocator,
        base_and_codex_rw_paths,
        custom_host_config,
    );
    defer path_list.free(allocator, launch_host_rw_paths);

    const result = sandbox.apply.applyBeforeExec(.{
        .allocator = allocator,
        .mode = mode,
        .workspace_root = workspace_root,
        .env_map = env_map,
        .minted_env_lookup = minted_env_lookup,
        .with_host_secrets = with_host_secrets,
        // Authority files as control roots: Landlock expands host RW with these RO.
        // Merged with default `.ryk`/`.git` inside compileProfile.
        .control_roots = config_write_denies,
        .launch_exec_paths = launch_exec_paths,
        .launch_ro_paths = launch_ro_paths,
        .launch_host_rw_paths = launch_host_rw_paths,
        // macOS Seatbelt exact literal write-deny (dual path with control_roots).
        .launch_write_deny_literals = config_write_denies,
        .network_proxy_port = network_proxy_port,
        .require_network_route_forcing = require_network_route_forcing,
        .seatbelt_profile = seatbelt_profile,
        .protect_workspace_secrets = protect_workspace_secrets,
        .fail_reason_out = &fail_reason,
    }) catch |err| switch (err) {
        error.RequireFailed => {
            // Clear activity before the durable error line.
            activity.clear();
            // Incomplete env scrub fails closed on both on and auto; wording must not
            // always claim the user passed `--os-sandbox on`.
            switch (mode) {
                .on => try stderr.print(
                    "ryk run: OS sandbox required but unavailable ({s}).\n",
                    .{fail_reason},
                ),
                .auto => try stderr.print(
                    "ryk run: OS sandbox failed closed under --os-sandbox auto ({s}).\n",
                    .{fail_reason},
                ),
                .off => try stderr.print(
                    "ryk run: OS sandbox unavailable ({s}).\n",
                    .{fail_reason},
                ),
            }
            return .{ .require_failed = exit_codes.unsupported };
        },
        error.OutOfMemory => return error.OutOfMemory,
    };
    return .{ .ok = result };
}

/// True when `err` is a sandbox child-apply/spawn failure that must not look like a
/// generic command launch issue.
pub fn isSandboxSpawnFailure(err: anyerror) bool {
    return switch (err) {
        error.ApplyFailed,
        error.ForkFailed,
        error.Unsupported,
        error.ExecFailed,
        error.ProfileHashMismatch,
        error.HandshakeTimeout,
        error.FuseDeviceUnavailable,
        error.ProfileRebuildFailed,
        error.FuseMountFailed,
        error.FuseDaemonStartFailed,
        error.FuseInitFailed,
        error.NamespaceSetupFailed,
        error.LandlockUnavailable,
        error.LandlockAttachFailed,
        error.CapabilityLockdownFailed,
        error.MountVerificationFailed,
        error.FdScrubFailed,
        error.TooManyExecPaths,
        => true,
        else => false,
    };
}

/// Operator-facing reason for a failed sandboxed spawn.
pub fn sandboxSpawnFailReason(err: anyerror) []const u8 {
    return switch (err) {
        error.ApplyFailed => "child_apply_failed",
        error.ForkFailed => "sandbox_fork_failed",
        error.Unsupported => "sandbox_backend_unsupported",
        error.ExecFailed => "sandbox_exec_failed",
        error.ProfileHashMismatch => "profile_hash_mismatch",
        error.HandshakeTimeout => "handshake_timeout",
        error.FuseDeviceUnavailable => "fuse_device_unavailable",
        error.ProfileRebuildFailed => "profile_rebuild_failed",
        error.FuseMountFailed => "fuse_mount_failed",
        error.FuseDaemonStartFailed => "fuse_daemon_start_failed",
        error.FuseInitFailed => "fuse_init_failed",
        error.NamespaceSetupFailed => "namespace_setup_failed",
        error.LandlockUnavailable => "landlock_unavailable",
        error.LandlockAttachFailed => "landlock_attach_failed",
        error.CapabilityLockdownFailed => "capability_lockdown_failed",
        error.MountVerificationFailed => "mount_verification_failed",
        error.FdScrubFailed => "fd_scrub_failed",
        error.TooManyExecPaths => "too_many_exec_paths",
        else => "sandbox_spawn_failed",
    };
}

/// Loud grade-drop warning for `--os-sandbox auto` when no child apply plan exists.
pub fn warnAutoDegrade(
    mode: sandbox.posture.OsSandboxMode,
    apply_result: *const sandbox.apply.ApplyResult,
    stderr: anytype,
) !void {
    if (mode != .auto or apply_result.childApplyKind() != .none) return;
    switch (apply_result.receipt.posture) {
        .unavailable, .failed => {
            const reason = apply_result.receipt.reason_code orelse "unknown";
            try stderr.print(
                "ryk run: WARNING: OS sandbox unavailable ({s}); continuing without OS FS isolation (grade drop). Use --os-sandbox on to require it, or --os-sandbox off to silence.\n",
                .{reason},
            );
        },
        // prepared has child materials — not a grade drop.
        .active, .prepared, .disabled => {},
    }
}

/// Build production `OsChildApply` from prepared materials (Landlock/Seatbelt).
/// `apply_result` must outlive the returned hook (spawn mutates it to active).
pub fn buildOsChildApply(
    apply_result: *sandbox.apply.ApplyResult,
    ctx: *SandboxSpawnCtx,
) core.process.OsChildApply {
    ctx.* = .{ .apply_result = apply_result };
    return switch (apply_result.childApplyKind()) {
        .none => .none,
        .landlock, .seatbelt => .{ .custom = .{
            .context = ctx,
            .spawnFn = SandboxSpawnCtx.spawn,
        } },
    };
}

pub const SandboxSpawnCtx = struct {
    apply_result: *sandbox.apply.ApplyResult,

    pub fn spawn(context: *anyopaque, request: core.process.CustomSpawnRequest) anyerror!std.process.Child {
        const self: *@This() = @ptrCast(@alignCast(context));
        const child_stdio: sandbox.apply_posix.StdioBehavior = switch (request.stdio) {
            .inherit => .inherit,
            .ignore => .ignore,
        };
        // spawnAgent activates receipt after child handshake.
        const spawned = try self.apply_result.spawnAgent(
            request.io,
            request.allocator,
            request.argv,
            request.env_map,
            request.workspace_root,
            child_stdio,
        );
        return core.process.childFromPid(spawned.pid);
    }
};

/// Emit sandbox_posture at session start (posture/hash/fs_scope/grade only — no rule blobs).
pub fn auditSandboxPosture(
    audit_context: anytype,
    session: core.session.Session,
    receipt: sandbox.posture.AttachReceipt,
) !void {
    if (audit_context.writer == null) return;
    var reason_buf: [sandbox.posture.audit_reason_buf_len]u8 = undefined;
    const reason = try sandbox.posture.formatAuditReason(&reason_buf, receipt);
    const ts = core.time.Timestamp.now(audit_context.io);
    const ev: core.event.Event = .{
        .session_id = session.id,
        .event_id = try core.event.generateEventId(ts),
        .timestamp = ts,
        .event_type = .sandbox_posture,
        .actor = .{ .kind = .ryk, .display = "ryk" },
        .target = .{ .kind = .session, .value = "os_filesystem_sandbox" },
        .decision = .{
            .result = .observe,
            .reason = reason,
            .ci_may_proceed = true,
        },
    };
    try core_api.appendAuditEvent(&audit_context.writer.?, ev);
}

/// Format mechanism-neutral OS sandbox banner line for session start.
pub fn formatOsSandboxBannerLine(
    buf: []u8,
    receipt: sandbox.posture.AttachReceipt,
    with_host_secrets: bool,
) []const u8 {
    // Thin wrapper: on format overflow, keep the receipt posture tag only.
    // Never invent "unavailable" for an active/disabled/failed receipt.
    if (with_host_secrets and receipt.posture == .active) {
        return if (receipt.seatbelt_profile) |grade|
            std.fmt.bufPrint(
                buf,
                "OS sandbox: active (filesystem: {s}; network: {s}; seatbelt_profile={s}; credentials: host environment retained (explicit escape); tools: wrapper-mediated)",
                .{ receipt.fs_scope, receipt.network_scope, grade.toString() },
            ) catch "OS sandbox: active (credentials: host environment retained; explicit escape)"
        else
            std.fmt.bufPrint(
                buf,
                "OS sandbox: active (filesystem: {s}; network: {s}; credentials: host environment retained (explicit escape); tools: wrapper-mediated)",
                .{ receipt.fs_scope, receipt.network_scope },
            ) catch "OS sandbox: active (credentials: host environment retained; explicit escape)";
    }
    return sandbox.posture.formatSessionBanner(buf, receipt) catch switch (receipt.posture) {
        .active => "OS sandbox: active",
        .prepared => "OS sandbox: prepared",
        .unavailable => "OS sandbox: unavailable",
        .failed => "OS sandbox: failed",
        .disabled => "OS sandbox: disabled",
    };
}

// Ownership contract: mergeOwnedPathLists frees both inputs on success. Callers
// must end errdefer of those inputs before later fallible work (see applyForRun
// base_launch_ro_paths nested merge_ist scope).
test "mergeOwnedPathLists consumes inputs on success" {
    const a = try std.testing.allocator.alloc([]const u8, 1);
    a[0] = try std.testing.allocator.dupe(u8, "/install");
    const b = try std.testing.allocator.alloc([]const u8, 1);
    b[0] = try std.testing.allocator.dupe(u8, "/toolchain");
    const merged = try mergeOwnedPathLists(std.testing.allocator, a, b);
    defer path_list.free(std.testing.allocator, merged);
    try std.testing.expectEqual(@as(usize, 2), merged.len);
    try std.testing.expectEqualStrings("/install", merged[0]);
    try std.testing.expectEqualStrings("/toolchain", merged[1]);
}

test "PrepareActivity start/clear is idempotent without residual success glyph" {
    var buf: [256]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    var activity = PrepareActivity(*std.Io.Writer){
        .io = std.testing.io,
        .writer = &writer,
        .label = "Preparing OS sandbox",
    };
    // No color under test io → start is a no-op; clear must stay safe.
    activity.start();
    activity.clear();
    activity.clear();
    try std.testing.expect(!activity.active);
    try std.testing.expect(activity.spinner == null);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "✓") == null);
}

test "Codex config write denies cover user and project authority files" {
    var env_map = std.process.Environ.Map.init(std.testing.allocator);
    defer env_map.deinit();
    try env_map.put("HOME", "/Users/synthetic");

    const paths = try sandbox.host_config_grants.collectHostConfigWriteDenies(
        std.testing.io,
        std.testing.allocator,
        "codex",
        "/Users/synthetic/project",
        &env_map,
    );
    defer sandbox.host_config_grants.freeHostConfigWriteDenies(std.testing.allocator, paths);
    // Cross-platform: authority paths feed Landlock control_roots and Seatbelt literals.
    try std.testing.expect(containsPath(paths, "/Users/synthetic/.codex/config.toml"));
    try std.testing.expect(containsPath(
        paths,
        "/Users/synthetic/project/.codex/config.toml",
    ));
    try std.testing.expect(containsPath(
        paths,
        "/Users/synthetic/.codex/config.toml",
    ));
    try std.testing.expect(containsPath(paths, "/.codex/config.toml"));
}

test "Codex config write denies honor custom CODEX_HOME" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "home/.codex-work");
    const home = try tmp.dir.realPathFileAlloc(std.testing.io, "home", std.testing.allocator);
    defer std.testing.allocator.free(home);
    const codex_home = try tmp.dir.realPathFileAlloc(std.testing.io, "home/.codex-work", std.testing.allocator);
    defer std.testing.allocator.free(codex_home);
    var env_map = std.process.Environ.Map.init(std.testing.allocator);
    defer env_map.deinit();
    try env_map.put("HOME", home);
    try env_map.put("CODEX_HOME", codex_home);

    const paths = try sandbox.host_config_grants.collectHostConfigWriteDenies(
        std.testing.io,
        std.testing.allocator,
        "codex",
        home,
        &env_map,
    );
    defer sandbox.host_config_grants.freeHostConfigWriteDenies(std.testing.allocator, paths);
    const expected = try std.fs.path.join(std.testing.allocator, &.{ codex_home, "config.toml" });
    defer std.testing.allocator.free(expected);
    try std.testing.expect(containsPath(paths, expected));
    const default_expected = try std.fs.path.join(std.testing.allocator, &.{ home, ".codex", "config.toml" });
    defer std.testing.allocator.free(default_expected);
    try std.testing.expect(containsPath(paths, default_expected));
}

test "custom CODEX_HOME removes default auth root but retains shared skills" {
    const allocator = std.testing.allocator;
    const input = try allocator.alloc([]const u8, 2);
    input[0] = try allocator.dupe(u8, "/Users/synthetic/.codex");
    input[1] = try allocator.dupe(u8, "/Users/synthetic/.agents");
    defer path_list.free(allocator, input);
    const filtered = try withoutDefaultCodexHome(
        allocator,
        input,
        "/Users/synthetic",
        true,
    );
    defer path_list.free(allocator, filtered);
    try std.testing.expectEqual(@as(usize, 1), filtered.len);
    try std.testing.expectEqualStrings("/Users/synthetic/.agents", filtered[0]);
}

test "host config write denies fail closed on hardlink aliases" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, ".codex");
    try tmp.dir.writeFile(io, .{ .sub_path = ".codex/config.toml", .data = "[mcp_servers]\n" });
    tmp.dir.hardLink(".codex/config.toml", tmp.dir, ".codex/config-alias.toml", io, .{}) catch
        return error.SkipZigTest;
    const home = try tmp.dir.realPathFileAlloc(io, ".", std.testing.allocator);
    defer std.testing.allocator.free(home);
    var env_map = std.process.Environ.Map.init(std.testing.allocator);
    defer env_map.deinit();
    try env_map.put("HOME", home);
    try std.testing.expectError(
        error.UnsafeHostConfigHardlink,
        sandbox.host_config_grants.collectHostConfigWriteDenies(io, std.testing.allocator, "codex", home, &env_map),
    );
}

test "host MCP configuration authority is write denied cross-platform" {
    var env_map = std.process.Environ.Map.init(std.testing.allocator);
    defer env_map.deinit();
    try env_map.put("HOME", "/Users/synthetic");
    try env_map.put("HERMES_HOME", "/Users/synthetic/.hermes/profiles/work");
    try env_map.put("PI_CODING_AGENT_DIR", "/Users/synthetic/.pi/agent");
    try env_map.put("OPENCODE_CONFIG", "/Users/synthetic/.config/opencode/company.jsonc");

    const cases = [_]struct { host: []const u8, expected: []const u8 }{
        .{ .host = "claude", .expected = "/Users/synthetic/.claude.json" },
        .{ .host = "opencode", .expected = "/Users/synthetic/.config/opencode/company.jsonc" },
        .{ .host = "hermes", .expected = "/Users/synthetic/.hermes/profiles/work/config.yaml" },
        .{ .host = "pi", .expected = "/Users/synthetic/.pi/agent/settings.json" },
    };
    for (cases) |case| {
        const paths = try sandbox.host_config_grants.collectHostConfigWriteDenies(
            std.testing.io,
            std.testing.allocator,
            case.host,
            "/Users/synthetic/project",
            &env_map,
        );
        defer sandbox.host_config_grants.freeHostConfigWriteDenies(std.testing.allocator, paths);
        try std.testing.expect(containsPath(paths, case.expected));
    }
}

test "custom CODEX_HOME normalizes macOS Data aliases before forbidden checks" {
    try std.testing.expectEqualStrings(
        "/Users/synthetic/.ssh",
        normalizeMacosUsersPath("/System/Volumes/Data/Users/synthetic/.ssh"),
    );
    const normalized_home = normalizeMacosUsersPath("/System/Volumes/Data/Users/synthetic");
    const normalized_secret = normalizeMacosUsersPath("/System/Volumes/Data/Users/synthetic/.ssh");
    try std.testing.expect(sandbox.host_config_grants.isForbiddenHostConfigPath(
        normalized_secret,
        normalized_home,
    ));
    try std.testing.expect(!isApprovedCodexHome("/Users/synthetic/Documents", "/Users/synthetic"));
    try std.testing.expect(isApprovedCodexHome("/Users/synthetic/.codex-work", "/Users/synthetic"));
    try std.testing.expect(isApprovedCodexHome("/Users/synthetic/.config/codex", "/Users/synthetic"));
}

test "custom agent config roots stay inside host-scoped home locations" {
    const home = "/Users/synthetic";
    try std.testing.expect(isApprovedCustomHostConfigPath(
        "claude",
        "/Users/synthetic/.claude-team",
        home,
    ));
    try std.testing.expect(isApprovedCustomHostConfigPath(
        "pi",
        "/Users/synthetic/.config/pi",
        home,
    ));
    try std.testing.expect(isApprovedCustomHostConfigPath(
        "opencode",
        "/Users/synthetic/.config/opencode/company.jsonc",
        home,
    ));
    try std.testing.expect(isApprovedCustomHostConfigPath(
        "hermes",
        "/Users/synthetic/.hermes/profiles/work",
        home,
    ));
    try std.testing.expect(!isApprovedCustomHostConfigPath(
        "claude",
        "/Users/synthetic/.ssh",
        home,
    ));
    try std.testing.expect(!isApprovedCustomHostConfigPath(
        "opencode",
        "/Users/synthetic/Documents/opencode.json",
        home,
    ));
    try std.testing.expect(!isApprovedCustomHostConfigPath(
        "hermes",
        "/Users/other/.hermes",
        home,
    ));
}

test "custom host config collector canonicalizes documented env paths" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "home/.hermes/profiles/work");
    const home = try tmp.dir.realPathFileAlloc(std.testing.io, "home", std.testing.allocator);
    defer std.testing.allocator.free(home);
    const hermes_home = try tmp.dir.realPathFileAlloc(
        std.testing.io,
        "home/.hermes/profiles/work",
        std.testing.allocator,
    );
    defer std.testing.allocator.free(hermes_home);
    var env_map = std.process.Environ.Map.init(std.testing.allocator);
    defer env_map.deinit();
    try env_map.put("HOME", home);
    try env_map.put("HERMES_HOME", hermes_home);

    const paths = try collectCustomHostConfigPaths(
        std.testing.io,
        std.testing.allocator,
        "hermes",
        home,
        &env_map,
    );
    defer path_list.free(std.testing.allocator, paths);
    try std.testing.expectEqual(@as(usize, 1), paths.len);
    try std.testing.expectEqualStrings(hermes_home, paths[0]);
    try std.testing.expectEqualStrings(hermes_home, env_map.get("HERMES_HOME").?);
}

test "custom host config collector strips unsafe selectors" {
    var env_map = std.process.Environ.Map.init(std.testing.allocator);
    defer env_map.deinit();
    try env_map.put("HOME", "/Users/synthetic");
    try env_map.put("OPENCODE_CONFIG", "/Users/synthetic/.ssh/config");
    const paths = try collectCustomHostConfigPaths(
        std.testing.io,
        std.testing.allocator,
        "opencode",
        "/Users/synthetic",
        &env_map,
    );
    defer path_list.free(std.testing.allocator, paths);
    try std.testing.expectEqual(@as(usize, 0), paths.len);
    try std.testing.expect(env_map.get("OPENCODE_CONFIG") == null);
}

test "isSandboxSpawnFailure classifies ApplyFailed ForkFailed Unsupported ExecFailed; not FileNotFound" {
    try std.testing.expect(isSandboxSpawnFailure(error.ApplyFailed));
    try std.testing.expect(isSandboxSpawnFailure(error.ForkFailed));
    try std.testing.expect(isSandboxSpawnFailure(error.Unsupported));
    try std.testing.expect(isSandboxSpawnFailure(error.ExecFailed));
    try std.testing.expect(isSandboxSpawnFailure(error.ProfileHashMismatch));
    try std.testing.expect(isSandboxSpawnFailure(error.HandshakeTimeout));
    try std.testing.expect(isSandboxSpawnFailure(error.FuseMountFailed));
    try std.testing.expect(isSandboxSpawnFailure(error.LandlockAttachFailed));
    try std.testing.expect(isSandboxSpawnFailure(error.FdScrubFailed));
    try std.testing.expect(isSandboxSpawnFailure(error.TooManyExecPaths));
    try std.testing.expect(!isSandboxSpawnFailure(error.FileNotFound));
}

test "sandboxSpawnFailReason maps classified spawn errors" {
    try std.testing.expectEqualStrings("child_apply_failed", sandboxSpawnFailReason(error.ApplyFailed));
    try std.testing.expectEqualStrings("sandbox_fork_failed", sandboxSpawnFailReason(error.ForkFailed));
    try std.testing.expectEqualStrings("sandbox_backend_unsupported", sandboxSpawnFailReason(error.Unsupported));
    try std.testing.expectEqualStrings("sandbox_exec_failed", sandboxSpawnFailReason(error.ExecFailed));
    try std.testing.expectEqualStrings("profile_hash_mismatch", sandboxSpawnFailReason(error.ProfileHashMismatch));
    try std.testing.expectEqualStrings("handshake_timeout", sandboxSpawnFailReason(error.HandshakeTimeout));
    try std.testing.expectEqualStrings("fuse_device_unavailable", sandboxSpawnFailReason(error.FuseDeviceUnavailable));
    try std.testing.expectEqualStrings("profile_rebuild_failed", sandboxSpawnFailReason(error.ProfileRebuildFailed));
    try std.testing.expectEqualStrings("fuse_mount_failed", sandboxSpawnFailReason(error.FuseMountFailed));
    try std.testing.expectEqualStrings("landlock_attach_failed", sandboxSpawnFailReason(error.LandlockAttachFailed));
    try std.testing.expectEqualStrings("fd_scrub_failed", sandboxSpawnFailReason(error.FdScrubFailed));
    try std.testing.expectEqualStrings("too_many_exec_paths", sandboxSpawnFailReason(error.TooManyExecPaths));
    // Unrelated errors fall through to a generic reason (not classified true above).
    try std.testing.expectEqualStrings("sandbox_spawn_failed", sandboxSpawnFailReason(error.FileNotFound));
}

test "formatOsSandboxBannerLine does not invent unavailable for active on format error" {
    // Tiny buffer forces formatSessionBanner NoSpaceLeft; fallback must keep posture tag.
    var tiny: [8]u8 = undefined;
    const active = try sandbox.posture.activeReceipt(
        .landlock,
        "abcd0123abcd0123abcd0123abcd0123abcd0123abcd0123abcd0123abcd0123",
        "workspace child RW, root RO, system RO, platform tmp RW, no home",
    );
    try std.testing.expect(active.posture == .active);
    const line = formatOsSandboxBannerLine(&tiny, active, false);
    try std.testing.expect(std.mem.indexOf(u8, line, "unavailable") == null);
    try std.testing.expect(std.mem.indexOf(u8, line, "active") != null);
    try std.testing.expect(std.mem.startsWith(u8, line, "OS sandbox:"));
}

test "formatOsSandboxBannerLine attests explicit host-secret escape" {
    var buf: [512]u8 = undefined;
    const active = try sandbox.posture.activeReceipt(
        .landlock,
        "abcd0123abcd0123abcd0123abcd0123abcd0123abcd0123abcd0123abcd0123",
        "workspace child RW, root RO, system RO, no home",
    );
    const line = formatOsSandboxBannerLine(&buf, active, true);
    try std.testing.expect(std.mem.indexOf(u8, line, "host environment retained") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "explicit escape") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "secrets stripped") == null);
}

test "warnAutoDegrade is silent for disabled posture (mode off materials)" {
    var stderr_buf: [512]u8 = undefined;
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const result = try sandbox.apply.applyBeforeExec(.{
        .allocator = std.testing.allocator,
        .mode = .off,
        .workspace_root = "/tmp/ws",
        .env_map = null,
    });
    // mode off → disabled receipt; even under .auto mode flag, no grade-drop warn.
    try warnAutoDegrade(.auto, &result, &stderr_writer);
    try std.testing.expectEqual(@as(usize, 0), stderr_writer.buffered().len);
}

test "apply materials alone never authorize active" {
    var result = try sandbox.apply.applyBeforeExec(.{
        .allocator = std.testing.allocator,
        .mode = .off,
        .workspace_root = "/tmp/ws",
        .env_map = null,
    });
    defer result.deinit();
    // activateAfterHandshake is file-private; materials/receipt from apply must stay non-active.
    try std.testing.expect(!result.receipt.isActive());
    try std.testing.expectEqual(sandbox.apply.ChildApplyKind.none, result.childApplyKind());
}

/// M-27: waitpid with EINTR retry for integration tests (mirrors apply_posix).
fn waitpidRetry(pid: std.c.pid_t, status: *c_int) void {
    while (true) {
        const rc = std.c.waitpid(pid, status, 0);
        if (rc >= 0) return;
        if (std.c.errno(rc) == .INTR) continue;
        return;
    }
}

test "run path spawnAgent attach when Seatbelt available" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    if (!sandbox.macos_seatbelt.sandboxInitAvailable()) return error.SkipZigTest;
    const ver = sandbox.macos_seatbelt.detectProductVersion() catch return error.SkipZigTest;
    if (!sandbox.macos_seatbelt.isMatrixMajor(ver.major)) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, ".ryk");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "neighbor.txt", .data = "ok" });
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var env_map = std.process.Environ.Map.init(std.testing.allocator);
    defer env_map.deinit();
    try env_map.put("PATH", "/usr/bin:/bin");
    try env_map.put("HOME", "/tmp");
    try env_map.put("OPENAI_API_KEY", "sk-should-be-stripped");

    var apply_result = try sandbox.apply.applyBeforeExec(.{
        .allocator = std.testing.allocator,
        .mode = .on,
        .workspace_root = root,
        .env_map = &env_map,
    });
    defer apply_result.deinit();
    try std.testing.expectEqual(sandbox.apply.ChildApplyKind.seatbelt, apply_result.childApplyKind());
    // Secret stripped by launch allowlist.
    try std.testing.expect(env_map.get("OPENAI_API_KEY") == null);
    try std.testing.expect(env_map.get("PATH") != null);

    var ctx: SandboxSpawnCtx = undefined;
    const os_apply = buildOsChildApply(&apply_result, &ctx);
    try std.testing.expect(os_apply == .custom);

    const child = try SandboxSpawnCtx.spawn(@ptrCast(&ctx), .{
        .io = std.testing.io,
        .allocator = std.testing.allocator,
        .argv = &[_][]const u8{"/usr/bin/true"},
        .workspace_root = root,
        .env_map = &env_map,
        .stdio = .ignore,
    });
    try std.testing.expect(apply_result.receipt.isActive());
    try std.testing.expectEqual(sandbox.posture.BackendMechanism.seatbelt, apply_result.receipt.mechanism);

    var status: c_int = 0;
    if (child.id) |pid| {
        waitpidRetry(pid, &status);
    }
    try std.testing.expect((status & 0x7f) == 0);
}

// M-29: Linux mirror of the macOS spawnAgent attach integration above.
test "run path spawnAgent attach when Landlock available" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!sandbox.landlock.isAbiAvailable()) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, ".ryk");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "neighbor.txt", .data = "ok" });
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var env_map = std.process.Environ.Map.init(std.testing.allocator);
    defer env_map.deinit();
    try env_map.put("PATH", "/usr/bin:/bin");
    try env_map.put("HOME", "/tmp");
    try env_map.put("OPENAI_API_KEY", "sk-should-be-stripped");

    var apply_result = try sandbox.apply.applyBeforeExec(.{
        .allocator = std.testing.allocator,
        .mode = .on,
        .workspace_root = root,
        .env_map = &env_map,
    });
    defer apply_result.deinit();
    try std.testing.expectEqual(sandbox.apply.ChildApplyKind.landlock, apply_result.childApplyKind());
    try std.testing.expect(env_map.get("OPENAI_API_KEY") == null);
    try std.testing.expect(env_map.get("PATH") != null);

    var ctx: SandboxSpawnCtx = undefined;
    const os_apply = buildOsChildApply(&apply_result, &ctx);
    try std.testing.expect(os_apply == .custom);

    const true_bin: []const u8 = blk: {
        std.Io.Dir.cwd().access(std.testing.io, "/usr/bin/true", .{}) catch break :blk "/bin/true";
        break :blk "/usr/bin/true";
    };

    const child = try SandboxSpawnCtx.spawn(@ptrCast(&ctx), .{
        .io = std.testing.io,
        .allocator = std.testing.allocator,
        .argv = &[_][]const u8{true_bin},
        .workspace_root = root,
        .env_map = &env_map,
        .stdio = .ignore,
    });
    try std.testing.expect(apply_result.receipt.isActive());
    try std.testing.expectEqual(sandbox.posture.BackendMechanism.landlock, apply_result.receipt.mechanism);
    try std.testing.expect(apply_result.receipt.profileHashSlice() != null);
    try std.testing.expectEqual(@as(usize, 64), apply_result.receipt.profileHashSlice().?.len);

    var status: c_int = 0;
    if (child.id) |pid| {
        waitpidRetry(pid, &status);
    }
    try std.testing.expect((status & 0x7f) == 0);
}

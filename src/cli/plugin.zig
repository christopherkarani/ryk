const std = @import("std");
const builtin = @import("builtin");
const gpa_mod = @import("gpa.zig");
const core = @import("ryk_core").core;
const supervisor = core.supervisor;
const core_api = @import("ryk_core").api;
const sandbox = @import("ryk").sandbox;

const exit_codes = @import("exit_codes.zig");
const help = @import("help.zig");
const cli = @import("mod.zig");
const telemetry = @import("../telemetry.zig");
const plugin_install = @import("plugin_install.zig");
const child_process = @import("child_process.zig");
const daemon_trust = @import("daemon_trust.zig");
const resource_root = @import("ryk").resource_root;
const env_util = @import("ryk").env_util;
const tui = @import("ryk").tui;
const suggestions = @import("suggestions.zig");
const host_status = @import("host_status.zig");
const openclaw_status = @import("openclaw_status.zig");
const interactive = @import("interactive.zig");

const hermes_managed_receipt_filename = ".ryk-managed-v1";
const hermes_unattended_marker_filename = ".ryk_unattended";
const openclaw_managed_receipt_filename = ".ryk-managed-openclaw-v1";
const openclaw_bundle_file_names = [_][]const u8{
    "openclaw.plugin.json",
    "package.json",
    "dist/index.js",
    "dist/index.d.ts",
};
// Exact hashes for the pre-receipt Ryk bundle. This bounded legacy allowance
// lets an existing, unmodified Ryk install migrate once without accepting
// copied manifest text as ownership evidence.
const hermes_legacy_manifest_sha256 = "9276b8a93a46772e5b0511b10ed699675dbc606be26fba98e35521aff761ca53";
const hermes_legacy_source_sha256 = "1eb89889cf8ec15392c6c0a6a30b602d924b72cb754af80864ca79203d3545b2";
const hermes_legacy_mapping_sha256 = "7753c18b13f036c702ca57a815b4c3f97823907243f79cea94bb7aed501d4221";

extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;
extern "c" fn unsetenv(name: [*:0]const u8) c_int;

fn setProcessEnv(name: [*:0]const u8, value: ?[*:0]const u8) bool {
    if (comptime builtin.os.tag == .windows) {
        const kernel32 = struct {
            extern "kernel32" fn SetEnvironmentVariableA(name: [*:0]const u8, value: ?[*:0]const u8) callconv(.winapi) std.os.windows.BOOL;
        };
        return kernel32.SetEnvironmentVariableA(name, value).toBool();
    } else if (value) |present| {
        return setenv(name, present, 1) == 0;
    } else {
        return unsetenv(name) == 0;
    }
}

fn testDupEnvZ(name: [*:0]const u8) !?[:0]u8 {
    if (std.c.getenv(name)) |value| {
        return try std.testing.allocator.dupeZ(u8, std.mem.span(value));
    }
    return null;
}

fn testRestoreEnv(name: [*:0]const u8, prev: ?[:0]u8) void {
    if (prev) |value| {
        _ = setenv(name, value.ptr, 1);
        std.testing.allocator.free(value);
    } else {
        _ = unsetenv(name);
    }
}

// ---------------------------------------------------------------------------
// Top-level dispatch
// ---------------------------------------------------------------------------

pub fn command(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    if (argv.len > 0 and (std.mem.eql(u8, argv[0], "--help") or std.mem.eql(u8, argv[0], "-h"))) {
        _ = try help.writeCommand(io, stdout, "plugin");
        return exit_codes.success;
    }
    if (argv.len == 0) {
        _ = try help.writeCommand(io, stderr, "plugin");
        return exit_codes.usage;
    }

    if (std.mem.eql(u8, argv[0], "doctor")) return doctorCommand(io, argv[1..], stdout, stderr);
    if (std.mem.eql(u8, argv[0], "list")) return listCommand(io, argv[1..], stdout, stderr);
    if (std.mem.eql(u8, argv[0], "manifest")) return manifestCommand(io, argv[1..], stdout, stderr);
    if (std.mem.eql(u8, argv[0], "install")) return installCommand(io, argv[1..], stdout, stderr);
    if (std.mem.eql(u8, argv[0], "mcp-server")) return mcpServerCommand(io, argv[1..], stdout, stderr);
    inline for (.{ "codex", "claude", "opencode", "openclaw", "hermes" }) |host| {
        if (std.mem.eql(u8, argv[0], host)) return installAliasCommand(io, host, argv[1..], stdout, stderr);
    }

    try suggestions.writeUnknownSubcommand(stderr, "ryk plugin", argv[0], &.{ "doctor", "list", "manifest", "install", "mcp-server", "codex", "claude", "opencode", "openclaw", "hermes" }, "plugin");
    return exit_codes.usage;
}

fn installAliasCommand(io: std.Io, host: []const u8, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    var gpa_state: gpa_mod.State = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();
    const install_argv = try allocator.alloc([]const u8, argv.len + 1);
    defer allocator.free(install_argv);
    install_argv[0] = host;
    @memcpy(install_argv[1..], argv);
    return installCommand(io, install_argv, stdout, stderr);
}

// ---------------------------------------------------------------------------
// doctor
// ---------------------------------------------------------------------------

const DoctorTarget = enum { all, codex, claude, opencode, openclaw, hermes };

fn doctorCommand(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    var target: DoctorTarget = .all;
    var json_mode = false;

    for (argv) |arg| {
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            try stdout.writeAll(
                \\Usage:
                \\  ryk plugin doctor
                \\  ryk plugin doctor [--json]
                \\  ryk plugin doctor codex
                \\  ryk plugin doctor claude
                \\  ryk plugin doctor opencode
                \\  ryk plugin doctor openclaw
                \\  ryk plugin doctor hermes
                \\  ryk plugin doctor codex [--json]
                \\  ryk plugin doctor claude [--json]
                \\  ryk plugin doctor opencode [--json]
                \\  ryk plugin doctor openclaw [--json]
                \\  ryk plugin doctor hermes [--json]
                \\
            );
            return exit_codes.success;
        }
        if (std.mem.eql(u8, arg, "--json")) {
            json_mode = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "codex")) {
            target = .codex;
            continue;
        }
        if (std.mem.eql(u8, arg, "claude")) {
            target = .claude;
            continue;
        }
        if (std.mem.eql(u8, arg, "opencode")) {
            target = .opencode;
            continue;
        }
        if (std.mem.eql(u8, arg, "openclaw")) {
            target = .openclaw;
            continue;
        }
        if (std.mem.eql(u8, arg, "hermes")) {
            target = .hermes;
            continue;
        }
        try suggestions.writeUnknownOption(stderr, "ryk plugin doctor", arg, &.{ "--json", "--help", "-h", "codex", "claude", "opencode", "openclaw", "hermes" }, "plugin");
        return exit_codes.usage;
    }

    var gpa_state: gpa_mod.State = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();

    var report = try collectPluginDoctorReport(io, allocator);
    defer deinitPluginDoctorReport(&report, allocator);

    if (json_mode) {
        try writeDoctorJson(stdout, report, target);
    } else {
        try writeDoctorPlain(io, allocator, stdout, report, target);
        telemetry.recordIntegration(@tagName(target), "verify", if (doctorTargetHealthy(target, report)) "success" else "failure");
    }
    return exit_codes.success;
}

fn doctorTargetHealthy(target: DoctorTarget, report: PluginDoctorReport) bool {
    return switch (target) {
        .all => hostPluginInstalledFromReport("codex", report) and hostPluginInstalledFromReport("claude", report) and
            hostPluginInstalledFromReport("opencode", report) and hostPluginInstalledFromReport("openclaw", report) and
            hostPluginInstalledFromReport("hermes", report),
        .codex => hostPluginInstalledFromReport("codex", report),
        .claude => hostPluginInstalledFromReport("claude", report),
        .opencode => hostPluginInstalledFromReport("opencode", report),
        .openclaw => hostPluginInstalledFromReport("openclaw", report),
        .hermes => hostPluginInstalledFromReport("hermes", report),
    };
}

// ---------------------------------------------------------------------------
// Plugin doctor report data
// ---------------------------------------------------------------------------

pub const PluginDirStatus = struct {
    codex: bool,
    claude: bool,
    opencode: bool,
    openclaw: bool,
    hermes: bool,
    common: bool,
};

pub const HostBinaryStatus = struct {
    codex: bool,
    claude: bool,
    opencode: bool,
    openclaw: bool,
    hermes: bool,
};

pub const OpenCodePaths = struct {
    /// True when this scope has both shipped files (`ryk.ts` + `ryk-tui.ts`).
    project_plugin_exists: bool,
    /// True when this scope has both shipped files (`ryk.ts` + `ryk-tui.ts`).
    global_plugin_exists: bool,
    config_references_plugin: bool,
};

pub const OpenClawHostInstall = struct {
    host_plugin_installed: bool,
    plugin_manifest_exists: bool,
    package_json_exists: bool,
    source_exists: bool,
    detection_note: []const u8,
};

pub const HermesPaths = struct {
    repo_manifest_exists: bool,
    repo_source_exists: bool,
    repo_mapping_exists: bool,
    user_manifest_exists: bool,
    user_source_exists: bool,
    user_mapping_exists: bool,
    config_references_plugin: bool,
    /// True when user plugin.yaml declares `name: ryk` (not stale `name: orca`).
    /// Populated at report collection so doctor JSON and hostPluginInstalledFromReport agree.
    user_manifest_name_is_ryk: bool,
};

pub const MarketplaceStatus = struct {
    codex_marketplace: bool,
    claude_marketplace: bool,
    codex_plugin_manifest: bool,
    claude_plugin_manifest: bool,
    codex_user_plugin: bool,
    claude_user_plugin: bool,
};

pub const PluginDoctorReport = struct {
    ryk_version: []const u8,
    ryk_binary_path: ?[:0]u8,
    cwd: [:0]u8,
    workspace_root: []const u8,
    policy_present: bool,
    policy_valid: bool,
    policy_mode: ?[]const u8 = null,
    policy_error: ?[]const u8,
    audit_replay_available: bool,
    mcp_support_status: []const u8,
    plugin_directories: PluginDirStatus,
    host_binaries: HostBinaryStatus,
    opencode_paths: OpenCodePaths,
    openclaw_paths: OpenClawHostInstall,
    hermes_paths: HermesPaths,
    hermes_hook_smoke_passed: bool,
    marketplace: MarketplaceStatus,
    platform_summary: []const u8,
    warnings: [][]const u8,
};

pub fn deinitPluginDoctorReport(report: *PluginDoctorReport, allocator: std.mem.Allocator) void {
    allocator.free(report.cwd);
    allocator.free(report.workspace_root);
    if (report.policy_error) |e| allocator.free(e);
    allocator.free(report.mcp_support_status);
    allocator.free(report.platform_summary);
    if (report.warnings.len > 0) {
        for (report.warnings) |w| allocator.free(w);
        allocator.free(report.warnings);
    }
    if (report.ryk_binary_path) |p| allocator.free(p);
    report.* = undefined;
}

pub fn collectPluginDoctorReport(io: std.Io, allocator: std.mem.Allocator) !PluginDoctorReport {
    return collectPluginDoctorReportWithHermesSmoke(io, allocator, null);
}

fn listCommand(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    if (argv.len > 0) {
        if (argv.len == 1 and (std.mem.eql(u8, argv[0], "--help") or std.mem.eql(u8, argv[0], "-h"))) {
            try stdout.writeAll("Usage:\n  ryk plugin list\n");
            return exit_codes.success;
        }
        try suggestions.writeUnknownOption(stderr, "ryk plugin list", argv[0], &.{ "--help", "-h" }, "plugin");
        return exit_codes.usage;
    }

    var gpa_state: gpa_mod.State = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();
    var report = try collectPluginDoctorReport(io, allocator);
    defer deinitPluginDoctorReport(&report, allocator);
    try writePluginList(io, allocator, stdout, report);
    return exit_codes.success;
}

const PluginInventoryItem = struct {
    host: []const u8,
    detected: bool,
    installed: bool,
};

fn pluginInventory(report: PluginDoctorReport) [5]PluginInventoryItem {
    return .{
        .{ .host = "Codex", .detected = report.host_binaries.codex, .installed = hostPluginInstalledFromReport("codex", report) },
        .{ .host = "Claude Code", .detected = report.host_binaries.claude, .installed = hostPluginInstalledFromReport("claude", report) },
        .{ .host = "OpenCode", .detected = report.host_binaries.opencode, .installed = hostPluginInstalledFromReport("opencode", report) },
        .{ .host = "OpenClaw", .detected = report.host_binaries.openclaw, .installed = hostPluginInstalledFromReport("openclaw", report) },
        .{ .host = "Hermes", .detected = report.host_binaries.hermes, .installed = hostPluginInstalledFromReport("hermes", report) },
    };
}

fn writePluginList(io: std.Io, allocator: std.mem.Allocator, stdout: anytype, report: PluginDoctorReport) !void {
    const inventory = pluginInventory(report);
    const rows = try allocator.alloc([]const []const u8, inventory.len);
    defer allocator.free(rows);
    var initialized: usize = 0;
    defer for (rows[0..initialized]) |row| allocator.free(row);
    var detected_count: usize = 0;
    var installed_count: usize = 0;

    for (inventory, 0..) |item, index| {
        if (item.detected) detected_count += 1;
        if (item.installed) installed_count += 1;
        const cells = try allocator.alloc([]const u8, 4);
        cells[0] = item.host;
        cells[1] = if (item.detected) "yes" else "no";
        cells[2] = if (item.installed) "yes" else "no";
        // Never claim "ready/protected" without smoke evidence (install/doctor own that).
        cells[3] = if (item.installed and item.detected)
            "installed"
        else if (item.installed)
            "installed; host missing"
        else if (item.detected)
            "not installed"
        else
            "host not detected";
        rows[index] = cells;
        initialized += 1;
    }

    try tui.render.table(io, stdout, &.{
        .{ .name = "HOST" }, .{ .name = "DETECTED" }, .{ .name = "INSTALLED" }, .{ .name = "STATUS" },
    }, rows);
    if (detected_count == 0) {
        try stdout.writeAll("\nNo supported host CLIs detected. Install a host, then run 'ryk plugin list' again.\n");
    }
    if (installed_count == 0) {
        try stdout.writeAll("Preview setup with 'ryk plugin codex --dry-run' (or replace codex with your host).\n");
    }
}

/// When `hermes_smoke_override` is non-null, skip spawning the Hermes hook smoke test
/// and use the provided boolean. Prefer this for lightweight host inventory paths
/// (e.g. `ryk doctor` host table) that should not pay smoke-test latency.
pub fn collectPluginDoctorReportWithHermesSmoke(
    io: std.Io,
    allocator: std.mem.Allocator,
    hermes_smoke_override: ?bool,
) !PluginDoctorReport {
    return collectPluginDoctorReportWithOptions(io, allocator, hermes_smoke_override, true);
}

/// Filesystem-only inventory for the bounded agents health command. Runtime
/// host probes are performed separately under one shared deadline.
pub fn collectPluginDoctorReportForAgentsHealth(
    io: std.Io,
    allocator: std.mem.Allocator,
) !PluginDoctorReport {
    return collectPluginDoctorReportWithOptions(io, allocator, false, false);
}

fn collectPluginDoctorReportWithOptions(
    io: std.Io,
    allocator: std.mem.Allocator,
    hermes_smoke_override: ?bool,
    allow_openclaw_cli_probe: bool,
) !PluginDoctorReport {
    const cwd: [:0]u8 = std.Io.Dir.cwd().realPathFileAlloc(io, ".", allocator) catch try allocator.dupeZ(u8, ".");
    errdefer allocator.free(cwd);
    const workspace_root = supervisor.resolveWorkspaceRoot(io, allocator, null, ".") catch try allocator.dupe(u8, cwd);
    errdefer allocator.free(workspace_root);

    const policy_path = try std.fs.path.join(allocator, &.{ workspace_root, ".ryk", "policy.yaml" });
    defer allocator.free(policy_path);
    var policy_present = false;
    var policy_valid = false;
    var policy_mode: ?[]const u8 = null;
    var policy_error: ?[]const u8 = null;
    errdefer if (policy_error) |e| allocator.free(e);
    if (fileExistsAbsolute(io, policy_path)) {
        policy_present = true;
        if (core_api.loadPolicyFile(io, allocator, policy_path)) |loaded_policy| {
            policy_mode = @tagName(loaded_policy.mode());
            var loaded = loaded_policy;
            loaded.deinit();
            policy_valid = true;
        } else |err| {
            if (err == error.OutOfMemory) return err;
            policy_error = try std.fmt.allocPrint(allocator, "{s}", .{@errorName(err)});
        }
    }

    const audit_replay_available = hasPath(workspace_root, ".ryk/sessions");
    const mcp_support = "stdio proxy active; HTTP transport deferred";

    const plugin_dirs = PluginDirStatus{
        .codex = pluginDirExists(io, allocator, "integrations/codex-plugin"),
        .claude = pluginDirExists(io, allocator, "integrations/claude-code-plugin"),
        .opencode = pluginDirExists(io, allocator, "integrations/opencode-plugin"),
        .openclaw = pluginDirExists(io, allocator, "integrations/openclaw-plugin"),
        .hermes = pluginDirExists(io, allocator, "integrations/hermes-plugin"),
        .common = pluginDirExists(io, allocator, "integrations/common"),
    };

    // One PATH snapshot for all host lookups — avoids rebuilding the full process
    // env map five times (and multiplies badly under checkAllAllocationFailures).
    const path_value: ?[]u8 = blk: {
        var env_map = env_util.createProcessMap(allocator) catch break :blk null;
        defer env_map.deinit();
        break :blk env_util.getOwned(&env_map, allocator, "PATH") catch null;
    };
    defer if (path_value) |p| allocator.free(p);

    const host_bins = HostBinaryStatus{
        .codex = if (path_value) |p| binaryOnSearchPath(io, allocator, p, "codex") else false,
        .claude = if (path_value) |p| binaryOnSearchPath(io, allocator, p, "claude") else false,
        .opencode = if (path_value) |p| binaryOnSearchPath(io, allocator, p, "opencode") else false,
        .openclaw = if (path_value) |p| binaryOnSearchPath(io, allocator, p, "openclaw") else false,
        .hermes = if (path_value) |p| binaryOnSearchPath(io, allocator, p, "hermes") else false,
    };

    // Check OpenCode-specific plugin paths
    const opencode_project_path = try std.fs.path.join(allocator, &.{ workspace_root, ".opencode", "plugins", "ryk.ts" });
    defer allocator.free(opencode_project_path);

    const opencode_global_path = blk: {
        var env_map = env_util.createProcessMap(allocator) catch {
            break :blk try std.fs.path.join(allocator, &.{ "~", ".config", "opencode", "plugins", "ryk.ts" });
        };
        defer env_map.deinit();
        const home_owned = env_util.getOwnedHome(&env_map, allocator) catch {
            break :blk try std.fs.path.join(allocator, &.{ "~", ".config", "opencode", "plugins", "ryk.ts" });
        };
        const home = home_owned orelse break :blk try std.fs.path.join(allocator, &.{ "~", ".config", "opencode", "plugins", "ryk.ts" });
        defer allocator.free(home);
        break :blk try std.fs.path.join(allocator, &.{ home, ".config", "opencode", "plugins", "ryk.ts" });
    };
    defer allocator.free(opencode_global_path);

    const opencode_project_tui_path = try siblingOpenCodePluginPath(allocator, opencode_project_path, "ryk-tui.ts");
    defer allocator.free(opencode_project_tui_path);
    const opencode_global_tui_path = try siblingOpenCodePluginPath(allocator, opencode_global_path, "ryk-tui.ts");
    defer allocator.free(opencode_global_tui_path);

    const opencode_paths = OpenCodePaths{
        .project_plugin_exists = openCodePairExists(io, opencode_project_path, opencode_project_tui_path),
        .global_plugin_exists = openCodePairExists(io, opencode_global_path, opencode_global_tui_path),
        .config_references_plugin = false, // Safe detection deferred
    };

    const openclaw_paths = try detectOpenClawHostInstall(io, allocator, host_bins.openclaw, allow_openclaw_cli_probe);

    const hermes_plugin_dir = try resolveBundledPath(io, allocator, "integrations/hermes-plugin");
    defer allocator.free(hermes_plugin_dir);
    const hermes_repo_manifest_path = try std.fs.path.join(allocator, &.{ hermes_plugin_dir, "plugin.yaml" });
    defer allocator.free(hermes_repo_manifest_path);
    const hermes_repo_source_path = try std.fs.path.join(allocator, &.{ hermes_plugin_dir, "__init__.py" });
    defer allocator.free(hermes_repo_source_path);
    const hermes_repo_mapping_path = try std.fs.path.join(allocator, &.{ hermes_plugin_dir, "mapping.py" });
    defer allocator.free(hermes_repo_mapping_path);
    const hermes_user_root = try hermesUserPluginRoot(allocator);
    defer allocator.free(hermes_user_root);
    const hermes_user_manifest_path = try std.fs.path.join(allocator, &.{ hermes_user_root, "plugin.yaml" });
    defer allocator.free(hermes_user_manifest_path);
    const hermes_user_source_path = try std.fs.path.join(allocator, &.{ hermes_user_root, "__init__.py" });
    defer allocator.free(hermes_user_source_path);
    const hermes_user_mapping_path = try std.fs.path.join(allocator, &.{ hermes_user_root, "mapping.py" });
    defer allocator.free(hermes_user_mapping_path);
    const hermes_config_path = try hermesConfigPath(allocator);
    defer allocator.free(hermes_config_path);

    const hermes_paths = HermesPaths{
        .repo_manifest_exists = fileExistsAbsolute(io, hermes_repo_manifest_path),
        .repo_source_exists = fileExistsAbsolute(io, hermes_repo_source_path),
        .repo_mapping_exists = fileExistsAbsolute(io, hermes_repo_mapping_path),
        .user_manifest_exists = fileExistsAbsolute(io, hermes_user_manifest_path),
        .user_source_exists = fileExistsAbsolute(io, hermes_user_source_path),
        .user_mapping_exists = fileExistsAbsolute(io, hermes_user_mapping_path),
        .config_references_plugin = fileContains(allocator, hermes_config_path, "ryk"),
        .user_manifest_name_is_ryk = hermesManifestDeclaresNameRyk(allocator, hermes_user_manifest_path),
    };

    const codex_marketplace_path = try std.fs.path.join(allocator, &.{ workspace_root, ".agents", "plugins", "marketplace.json" });
    defer allocator.free(codex_marketplace_path);
    const claude_marketplace_path = try std.fs.path.join(allocator, &.{ workspace_root, ".claude-plugin", "marketplace.json" });
    defer allocator.free(claude_marketplace_path);
    const codex_user_plugin_path = try std.fs.path.join(allocator, &.{ workspace_root, ".agents", "plugins", "ryk", ".codex-plugin", "plugin.json" });
    defer allocator.free(codex_user_plugin_path);
    const claude_user_plugin_path = try std.fs.path.join(allocator, &.{ workspace_root, ".claude", "plugins", "ryk", ".claude-plugin", "plugin.json" });
    defer allocator.free(claude_user_plugin_path);
    const codex_bundled_manifest = try resolveBundledPath(io, allocator, "integrations/codex-plugin/.codex-plugin/plugin.json");
    defer allocator.free(codex_bundled_manifest);
    const claude_bundled_manifest = try resolveBundledPath(io, allocator, "integrations/claude-code-plugin/.claude-plugin/plugin.json");
    defer allocator.free(claude_bundled_manifest);

    const marketplace = MarketplaceStatus{
        .codex_marketplace = plugin_install.marketplaceRegistersExpectedPlugin(
            io,
            allocator,
            codex_marketplace_path,
            .codex,
        ),
        .claude_marketplace = plugin_install.marketplaceRegistersExpectedPlugin(
            io,
            allocator,
            claude_marketplace_path,
            .claude,
        ),
        .codex_plugin_manifest = fileExistsAbsolute(io, codex_bundled_manifest),
        .claude_plugin_manifest = fileExistsAbsolute(io, claude_bundled_manifest),
        .codex_user_plugin = fileExistsAbsolute(io, codex_user_plugin_path),
        .claude_user_plugin = fileExistsAbsolute(io, claude_user_plugin_path),
    };

    var warnings: std.ArrayList([]const u8) = .empty;
    defer warnings.deinit(allocator);
    errdefer {
        for (warnings.items) |warning| allocator.free(warning);
    }
    if (!plugin_dirs.common) try appendWarning(allocator, &warnings, "integrations/common directory missing");
    if (!plugin_dirs.codex) try appendWarning(allocator, &warnings, "Codex plugin directory not yet created");
    if (!plugin_dirs.claude) try appendWarning(allocator, &warnings, "Claude Code plugin directory not yet created");
    if (!plugin_dirs.opencode) try appendWarning(allocator, &warnings, "OpenCode plugin directory not yet created");
    if (!plugin_dirs.openclaw) try appendWarning(allocator, &warnings, "OpenClaw plugin directory not yet created");
    if (!plugin_dirs.hermes) try appendWarning(allocator, &warnings, "Hermes plugin directory not yet created");
    if (!host_bins.codex) try appendWarning(allocator, &warnings, "Codex host binary not found in PATH");
    if (!host_bins.claude) try appendWarning(allocator, &warnings, "Claude Code host binary not found in PATH");
    if (!host_bins.opencode) try appendWarning(allocator, &warnings, "OpenCode host binary not found in PATH");
    if (!host_bins.openclaw) try appendWarning(allocator, &warnings, "OpenClaw host binary not found in PATH");
    if (!host_bins.hermes) try appendWarning(allocator, &warnings, "Hermes host binary not found in PATH");

    const hermes_hook_smoke_passed = hermes_smoke_override orelse blk: {
        const result = smokeTestHook(allocator, "hermes", "pre_tool_call", "tests/fixtures/hook-safe.json", "allow") catch break :blk false;
        break :blk result.passed;
    };
    if (!hermes_hook_smoke_passed) {
        try appendWarning(allocator, &warnings, "Hermes hook smoke test failed: reinstall the integration with `ryk doctor --fix`");
    }

    const os = core.platform.detectOs();
    const backend_report = sandbox.backend.detect(os);
    const platform_summary = try std.fmt.allocPrint(allocator, "{s} / {s} / fallback: {s}", .{
        os.toString(),
        backend_report.backend_name,
        backend_report.fallback_level.toString(),
    });
    errdefer allocator.free(platform_summary);

    var threaded: std.Io.Threaded = .init_single_threaded;
    const binary_path = std.process.executablePathAlloc(threaded.io(), allocator) catch null;
    errdefer if (binary_path) |p| allocator.free(p);
    const mcp_support_status = try allocator.dupe(u8, mcp_support);
    errdefer allocator.free(mcp_support_status);
    const warning_items = try warnings.toOwnedSlice(allocator);

    return .{
        .ryk_version = cli.version,
        .ryk_binary_path = binary_path,
        .cwd = cwd,
        .workspace_root = workspace_root,
        .policy_present = policy_present,
        .policy_valid = policy_valid,
        .policy_mode = policy_mode,
        .policy_error = policy_error,
        .audit_replay_available = audit_replay_available,
        .mcp_support_status = mcp_support_status,
        .plugin_directories = plugin_dirs,
        .host_binaries = host_bins,
        .opencode_paths = opencode_paths,
        .openclaw_paths = openclaw_paths,
        .hermes_paths = hermes_paths,
        .hermes_hook_smoke_passed = hermes_hook_smoke_passed,
        .marketplace = marketplace,
        .platform_summary = platform_summary,
        .warnings = warning_items,
    };
}

fn appendWarning(allocator: std.mem.Allocator, warnings: *std.ArrayList([]const u8), message: []const u8) !void {
    const owned = try allocator.dupe(u8, message);
    errdefer allocator.free(owned);
    try warnings.append(allocator, owned);
}

// ---------------------------------------------------------------------------
// doctor plain output
// ---------------------------------------------------------------------------

fn writeDoctorPlain(io: std.Io, allocator: std.mem.Allocator, stdout: anytype, report: PluginDoctorReport, target: DoctorTarget) !void {
    try stdout.writeAll("ryk Plugin Doctor\n\n");

    try stdout.print("ryk version: {s}\n", .{report.ryk_version});
    if (report.ryk_binary_path) |path| {
        try stdout.print("ryk binary: {s}\n", .{path});
    } else {
        try stdout.writeAll("ryk binary: unknown\n");
    }
    try stdout.print("Current directory: {s}\n", .{report.cwd});
    try stdout.print("Workspace root: {s}\n", .{report.workspace_root});

    try stdout.writeAll("\nPolicy:\n");
    if (report.policy_present) {
        if (report.policy_valid) {
            try stdout.writeAll("  .ryk/policy.yaml: present and valid\n");
        } else {
            try stdout.print("  .ryk/policy.yaml: invalid ({s})\n", .{report.policy_error orelse "validation failed"});
        }
    } else {
        try stdout.writeAll("  .ryk/policy.yaml: missing\n");
        try stdout.writeAll("    → Fix: ryk init --preset generic-agent\n");
    }

    try stdout.writeAll("\nAudit / replay:\n");
    try stdout.print("  {s}\n", .{if (report.audit_replay_available) "session artifacts present" else "no local sessions detected"});

    try stdout.writeAll("\nMCP support:\n");
    try stdout.print("  {s}\n", .{report.mcp_support_status});

    // Unified host status table (same fields as `ryk doctor`).
    try writeUnifiedHostStatusTable(io, allocator, stdout, report, target);

    try stdout.writeAll("\nPlugin directories:\n");
    try stdout.print("  integrations/common: {s}\n", .{if (report.plugin_directories.common) "found" else "missing"});
    if (!report.plugin_directories.common) try stdout.writeAll("    → Fix: ryk doctor --fix or ryk plugin install all\n");
    try stdout.print("  integrations/codex-plugin: {s}\n", .{if (report.plugin_directories.codex) "found" else "missing"});
    if (!report.plugin_directories.codex) try stdout.writeAll("    → Fix: ryk doctor --fix or ryk plugin install codex\n");
    try stdout.print("  integrations/claude-code-plugin: {s}\n", .{if (report.plugin_directories.claude) "found" else "missing"});
    if (!report.plugin_directories.claude) try stdout.writeAll("    → Fix: ryk doctor --fix or ryk plugin install claude\n");
    try stdout.print("  integrations/opencode-plugin: {s}\n", .{if (report.plugin_directories.opencode) "found" else "missing"});
    if (!report.plugin_directories.opencode) try stdout.writeAll("    → Fix: ryk doctor --fix or ryk plugin install opencode\n");
    try stdout.print("  integrations/openclaw-plugin: {s}\n", .{if (report.plugin_directories.openclaw) "found" else "missing"});
    if (!report.plugin_directories.openclaw) try stdout.writeAll("    → Fix: ryk doctor --fix or ryk plugin install openclaw\n");
    try stdout.print("  integrations/hermes-plugin: {s}\n", .{if (report.plugin_directories.hermes) "found" else "missing"});
    if (!report.plugin_directories.hermes) try stdout.writeAll("    → Fix: ryk doctor --fix or ryk plugin install hermes\n");

    try stdout.writeAll("\nHost binaries:\n");
    try stdout.print("  codex: {s}\n", .{if (report.host_binaries.codex) "found in PATH" else "not found"});
    if (!report.host_binaries.codex) try stdout.writeAll("    → Fix: ryk doctor --fix or ryk plugin install codex\n");
    try stdout.print("  claude: {s}\n", .{if (report.host_binaries.claude) "found in PATH" else "not found"});
    if (!report.host_binaries.claude) try stdout.writeAll("    → Fix: ryk doctor --fix or ryk plugin install claude\n");
    try stdout.print("  opencode: {s}\n", .{if (report.host_binaries.opencode) "found in PATH" else "not found"});
    if (!report.host_binaries.opencode) try stdout.writeAll("    → Fix: ryk doctor --fix or ryk plugin install opencode\n");
    try stdout.print("  openclaw: {s}\n", .{if (report.host_binaries.openclaw) "found in PATH" else "not found"});
    if (!report.host_binaries.openclaw) try stdout.writeAll("    → Fix: ryk doctor --fix or ryk plugin install openclaw\n");
    try stdout.print("  hermes: {s}\n", .{if (report.host_binaries.hermes) "found in PATH" else "not found"});
    if (!report.host_binaries.hermes) try stdout.writeAll("    → Fix: ryk doctor --fix or ryk plugin install hermes\n");

    try stdout.writeAll("\nMarketplace files:\n");
    try stdout.print("  .agents/plugins/marketplace.json: {s}\n", .{if (report.marketplace.codex_marketplace) "present" else "missing"});
    if (!report.marketplace.codex_marketplace) try stdout.writeAll("    → Fix: ryk doctor --fix or ryk plugin install codex\n");
    try stdout.print("  .claude-plugin/marketplace.json: {s}\n", .{if (report.marketplace.claude_marketplace) "present" else "missing"});
    if (!report.marketplace.claude_marketplace) try stdout.writeAll("    → Fix: ryk doctor --fix or ryk plugin install claude\n");

    try stdout.writeAll("\nPlatform:\n");
    try stdout.print("  {s}\n", .{report.platform_summary});

    if (report.warnings.len > 0) {
        try stdout.writeAll("\nWarnings:\n");
        for (report.warnings) |w| {
            try stdout.print("  - {s}\n", .{w});
        }
    }

    // Target-specific section
    switch (target) {
        .all => {},
        .codex => {
            try stdout.writeAll("\nCodex plugin status:\n");
            try stdout.print("  host binary: {s}\n", .{if (report.host_binaries.codex) "detected" else "not detected"});
            if (!report.host_binaries.codex) try stdout.writeAll("    → Fix: install Codex and re-run ryk doctor --fix or ryk plugin install codex\n");
            try stdout.print("  bundled plugin directory: {s}\n", .{if (report.plugin_directories.codex) "present" else "missing"});
            if (!report.plugin_directories.codex) try stdout.writeAll("    → Fix: reinstall ryk runtime assets\n");
            try stdout.print("  user plugin registration: {s}\n", .{if (report.marketplace.codex_user_plugin) "installed" else "missing"});
            if (!report.marketplace.codex_user_plugin) try stdout.writeAll("    → Fix: ryk doctor --fix or ryk plugin install codex\n");
            try stdout.print("  marketplace file: {s}\n", .{if (report.marketplace.codex_marketplace) "present" else "missing"});
            if (!report.marketplace.codex_marketplace) try stdout.writeAll("    → Fix: ryk doctor --fix or ryk plugin install codex\n");
            try stdout.print("  bundled plugin manifest: {s}\n", .{if (report.marketplace.codex_plugin_manifest) "present" else "missing"});
            if (!report.marketplace.codex_plugin_manifest) try stdout.writeAll("    → Fix: reinstall ryk runtime assets\n");
            try stdout.writeAll("  install: use 'ryk plugin install codex --dry-run' to preview\n");
        },
        .claude => {
            try stdout.writeAll("\nClaude Code plugin status:\n");
            try stdout.print("  host binary: {s}\n", .{if (report.host_binaries.claude) "detected" else "not detected"});
            if (!report.host_binaries.claude) try stdout.writeAll("    → Fix: install Claude Code and re-run ryk doctor --fix or ryk plugin install claude\n");
            try stdout.print("  bundled plugin directory: {s}\n", .{if (report.plugin_directories.claude) "present" else "missing"});
            if (!report.plugin_directories.claude) try stdout.writeAll("    → Fix: reinstall ryk runtime assets\n");
            try stdout.print("  user plugin registration: {s}\n", .{if (report.marketplace.claude_user_plugin) "installed" else "missing"});
            if (!report.marketplace.claude_user_plugin) try stdout.writeAll("    → Fix: ryk doctor --fix or ryk plugin install claude\n");
            try stdout.print("  marketplace file: {s}\n", .{if (report.marketplace.claude_marketplace) "present" else "missing"});
            if (!report.marketplace.claude_marketplace) try stdout.writeAll("    → Fix: ryk doctor --fix or ryk plugin install claude\n");
            try stdout.print("  bundled plugin manifest: {s}\n", .{if (report.marketplace.claude_plugin_manifest) "present" else "missing"});
            if (!report.marketplace.claude_plugin_manifest) try stdout.writeAll("    → Fix: reinstall ryk runtime assets\n");
            try stdout.writeAll("  install: use 'ryk plugin install claude --dry-run' to preview\n");
        },
        .opencode => {
            try stdout.writeAll("\nOpenCode plugin status:\n");
            try stdout.print("  host binary: {s}\n", .{if (report.host_binaries.opencode) "detected" else "not detected"});
            if (!report.host_binaries.opencode) try stdout.writeAll("    → Fix: ryk doctor --fix or ryk plugin install opencode\n");
            try stdout.print("  plugin directory: {s}\n", .{if (report.plugin_directories.opencode) "present" else "not yet created"});
            if (!report.plugin_directories.opencode) try stdout.writeAll("    → Fix: ryk doctor --fix or ryk plugin install opencode\n");
            try stdout.print("  project plugin path (.opencode/plugins/ryk.ts + ryk-tui.ts): {s}\n", .{if (report.opencode_paths.project_plugin_exists) "exists" else "not found"});
            if (!report.opencode_paths.project_plugin_exists) try stdout.writeAll("    → Fix: ryk doctor --fix or ryk plugin install opencode\n");
            try stdout.print("  global plugin path (~/.config/opencode/plugins/ryk.ts + ryk-tui.ts): {s}\n", .{if (report.opencode_paths.global_plugin_exists) "exists" else "not found"});
            if (!report.opencode_paths.global_plugin_exists) try stdout.writeAll("    → Fix: ryk doctor --fix or ryk plugin install opencode\n");
            try stdout.writeAll("  day-one path: upgrades global ~/.config/opencode/plugins/{ryk.ts,ryk-tui.ts} and any existing project pair\n");
            try stdout.writeAll("  install: use 'ryk plugin install opencode --dry-run' to preview\n");
            try stdout.writeAll("  note: OpenCode plugin uses TypeScript hooks, not a manifest file\n");
        },
        .openclaw => {
            try stdout.writeAll("\nOpenClaw plugin status:\n");
            try stdout.print("  host binary: {s}\n", .{if (report.host_binaries.openclaw) "detected" else "not detected"});
            if (!report.host_binaries.openclaw) try stdout.writeAll("    → Fix: install OpenClaw and re-run ryk doctor --fix or ryk plugin install openclaw\n");
            try stdout.print("  bundled plugin directory: {s}\n", .{if (report.plugin_directories.openclaw) "present" else "missing"});
            if (!report.plugin_directories.openclaw) try stdout.writeAll("    → Fix: reinstall ryk runtime assets\n");
            try stdout.print("  host plugin installed: {s}\n", .{if (report.openclaw_paths.host_plugin_installed) "yes" else "no"});
            if (!report.openclaw_paths.host_plugin_installed) try stdout.writeAll("    → Fix: ryk doctor --fix or ryk plugin install openclaw\n");
            try stdout.print("  host plugin manifest (openclaw.plugin.json): {s}\n", .{if (report.openclaw_paths.plugin_manifest_exists) "exists" else "not found"});
            if (!report.openclaw_paths.plugin_manifest_exists) try stdout.writeAll("    → Fix: ryk doctor --fix or ryk plugin install openclaw\n");
            try stdout.print("  host package.json: {s}\n", .{if (report.openclaw_paths.package_json_exists) "exists" else "not found"});
            try stdout.print("  host source (src/index.ts): {s}\n", .{if (report.openclaw_paths.source_exists) "exists" else "not found"});
            try stdout.print("  detection note: {s}\n", .{report.openclaw_paths.detection_note});
            try openclaw_status.writeDoctorHonesty(stdout);
        },
        .hermes => {
            try stdout.writeAll("\nHermes plugin status:\n");
            try stdout.print("  host binary: {s}\n", .{if (report.host_binaries.hermes) "detected" else "not detected"});
            if (!report.host_binaries.hermes) try stdout.writeAll("    → Fix: ryk doctor --fix or ryk plugin install hermes\n");
            try stdout.print("  plugin directory: {s}\n", .{if (report.plugin_directories.hermes) "present" else "not yet created"});
            if (!report.plugin_directories.hermes) try stdout.writeAll("    → Fix: ryk doctor --fix or ryk plugin install hermes\n");
            try stdout.print("  repo plugin.yaml: {s}\n", .{if (report.hermes_paths.repo_manifest_exists) "exists" else "not found"});
            if (!report.hermes_paths.repo_manifest_exists) try stdout.writeAll("    → Fix: ryk doctor --fix or ryk plugin install hermes\n");
            try stdout.print("  repo __init__.py: {s}\n", .{if (report.hermes_paths.repo_source_exists) "exists" else "not found"});
            if (!report.hermes_paths.repo_source_exists) try stdout.writeAll("    → Fix: ryk doctor --fix or ryk plugin install hermes\n");
            try stdout.print("  repo mapping.py: {s}\n", .{if (report.hermes_paths.repo_mapping_exists) "exists" else "not found"});
            if (!report.hermes_paths.repo_mapping_exists) try stdout.writeAll("    → Fix: ryk doctor --fix or ryk plugin install hermes\n");
            try stdout.print("  user plugin path (~/.hermes/plugins/ryk/plugin.yaml): {s}\n", .{if (report.hermes_paths.user_manifest_exists) "exists" else "not found"});
            if (!report.hermes_paths.user_manifest_exists) try stdout.writeAll("    → Fix: ryk doctor --fix or ryk plugin install hermes\n");
            try stdout.print("  user mapping.py: {s}\n", .{if (report.hermes_paths.user_mapping_exists) "exists" else "not found"});
            if (!report.hermes_paths.user_mapping_exists) try stdout.writeAll("    → Fix: ryk doctor --fix or ryk plugin install hermes\n");
            try stdout.print("  config references plugin: {s}\n", .{if (report.hermes_paths.config_references_plugin) "yes" else "unknown/no"});
            if (!report.hermes_paths.config_references_plugin) try stdout.writeAll("    → Fix: ryk doctor --fix or ryk plugin install hermes\n");
            try stdout.print("  user manifest name: ryk: {s}\n", .{if (report.hermes_paths.user_manifest_name_is_ryk) "yes" else "no"});
            if (!report.hermes_paths.user_manifest_name_is_ryk) try stdout.writeAll("    → Fix: ryk doctor --fix or ryk plugin install hermes (rewrites stale name: orca)\n");
            const hermes_fail_open = host_status.hermesFailOpenFromEnv();
            const hermes_wired: []const u8 = if (hostPluginInstalledFromReport("hermes", report)) "yes" else if (report.host_binaries.hermes) "no" else "—";
            try stdout.print("  fail stance: {s}\n", .{host_status.failStance("hermes", hermes_fail_open, hermes_wired)});
            if (hermes_fail_open) {
                try stdout.writeAll("    → WARN: Hermes is explicitly fail-open when ryk is degraded.\n");
                try stdout.writeAll("    → Fix: unset RYK_HERMES_FAIL_OPEN  # or: ryk run -- hermes\n");
            }
            try stdout.print("  hook smoke test (pre_tool_call allow): {s}\n", .{if (report.hermes_hook_smoke_passed) "passed" else "FAILED"});
            if (!report.hermes_hook_smoke_passed) try stdout.writeAll("    → Fix: upgrade ryk and reinstall the Hermes integration\n");
            try stdout.writeAll("  install: use 'ryk plugin install hermes --dry-run' to preview\n");
            try stdout.writeAll("  note: Hermes hooks are additive; strongest protection remains 'ryk run -- hermes'\n");
            try stdout.writeAll("  note: Gateway (Telegram/Discord) may omit the block reason in chat; check agent tool errors.\n");
        },
    }

    try stdout.writeAll("\n");
}

fn hostBinaryDetected(report: PluginDoctorReport, host_name: []const u8) bool {
    if (std.mem.eql(u8, host_name, "codex")) return report.host_binaries.codex;
    if (std.mem.eql(u8, host_name, "claude")) return report.host_binaries.claude;
    if (std.mem.eql(u8, host_name, "opencode")) return report.host_binaries.opencode;
    if (std.mem.eql(u8, host_name, "openclaw")) return report.host_binaries.openclaw;
    if (std.mem.eql(u8, host_name, "hermes")) return report.host_binaries.hermes;
    return false;
}

fn smokeForPluginDoctor(
    allocator: std.mem.Allocator,
    report: PluginDoctorReport,
    host_name: []const u8,
    target: DoctorTarget,
) host_status.HostSmokePair {
    // Live allow+deny only for single-host doctor (avoids multi-host latency).
    if (target != .all and std.mem.eql(u8, host_name, @tagName(target))) {
        return host_status.runHostSmokePair(allocator, host_name) catch .{ .allow = .fail, .deny = .fail };
    }
    if (std.mem.eql(u8, host_name, "hermes")) {
        return .{
            .allow = if (report.hermes_hook_smoke_passed) .pass else .fail,
            .deny = .not_run,
        };
    }
    return .{};
}

fn writeUnifiedHostStatusTable(
    io: std.Io,
    allocator: std.mem.Allocator,
    stdout: anytype,
    report: PluginDoctorReport,
    target: DoctorTarget,
) !void {
    try stdout.writeAll("\nHost status:\n");
    const hermes_fail_open = host_status.hermesFailOpenFromEnv();

    var row_hosts: std.ArrayList([]const u8) = .empty;
    defer row_hosts.deinit(allocator);
    for (host_status.managed_hosts) |host_name| {
        if (target != .all and !std.mem.eql(u8, host_name, @tagName(target))) continue;
        try row_hosts.append(allocator, host_name);
    }
    // Pi always listed on full doctor; include when targeting is all only.
    const include_pi = target == .all;
    const row_count = row_hosts.items.len + @as(usize, if (include_pi) 1 else 0);

    var owned: std.ArrayList([]const u8) = .empty;
    defer {
        for (owned.items) |s| allocator.free(s);
        owned.deinit(allocator);
    }
    var rows = try allocator.alloc([]const []const u8, row_count);
    defer {
        for (rows) |row| allocator.free(row);
        allocator.free(rows);
    }
    var fix_lines: std.ArrayList(struct { host: []const u8, fix: []const u8 }) = .empty;
    defer fix_lines.deinit(allocator);

    for (row_hosts.items, 0..) |host_name, i| {
        const installed = hostPluginInstalledFromReport(host_name, report);
        const detected = hostBinaryDetected(report, host_name);
        const wired: []const u8 = if (installed) "yes" else if (detected) "no" else "—";
        const smoke = smokeForPluginDoctor(allocator, report, host_name, target);
        const allow_s = try allocator.dupe(u8, smoke.allow.toString());
        try owned.append(allocator, allow_s);
        const deny_s = try allocator.dupe(u8, smoke.deny.toString());
        try owned.append(allocator, deny_s);
        const fix = try host_status.formatFix(allocator, host_name, wired, smoke, hermes_fail_open);
        try owned.append(allocator, fix);
        if (!std.mem.eql(u8, fix, "—")) {
            try fix_lines.append(allocator, .{ .host = host_name, .fix = fix });
        }
        const cells = try allocator.alloc([]const u8, 6);
        cells[0] = host_name;
        cells[1] = wired;
        cells[2] = host_status.shellGate(host_name);
        cells[3] = host_status.failStance(host_name, hermes_fail_open, wired);
        cells[4] = allow_s;
        cells[5] = deny_s;
        rows[i] = cells;
    }

    if (include_pi) {
        const pi_status = host_status.inspectPi(io, allocator);
        const wired = pi_status.wiredLabel();
        const smoke = host_status.HostSmokePair{};
        const allow_s = try allocator.dupe(u8, smoke.allow.toString());
        try owned.append(allocator, allow_s);
        const deny_s = try allocator.dupe(u8, smoke.deny.toString());
        try owned.append(allocator, deny_s);
        const fix = try host_status.formatFix(allocator, "pi", wired, smoke, hermes_fail_open);
        try owned.append(allocator, fix);
        if (!std.mem.eql(u8, fix, "—")) {
            try fix_lines.append(allocator, .{ .host = "pi", .fix = fix });
        }
        const cells = try allocator.alloc([]const u8, 6);
        cells[0] = "pi";
        cells[1] = wired;
        cells[2] = host_status.shellGate("pi");
        cells[3] = host_status.failStance("pi", hermes_fail_open, wired);
        cells[4] = allow_s;
        cells[5] = deny_s;
        rows[row_hosts.items.len] = cells;
    }

    try tui.render.table(io, stdout, &.{
        .{ .name = "HOST" },
        .{ .name = "WIRED" },
        .{ .name = "SHELL GATE" },
        .{ .name = "FAIL STANCE" },
        .{ .name = "SMOKE ALLOW" },
        .{ .name = "SMOKE DENY" },
    }, rows);

    for (fix_lines.items) |line| {
        try stdout.print("  fix {s}: {s}\n", .{ line.host, line.fix });
    }
    if (include_pi) {
        try stdout.writeAll("  note pi: bundled extension setup is managed by `ryk doctor --fix` (no npm step)\n");
        try stdout.writeAll("    → verify: ryk doctor · process isolation: ryk run -- pi\n");
    }
    if (hostPluginInstalledFromReport("hermes", report) and hermes_fail_open and (target == .all or target == .hermes)) {
        try stdout.writeAll("  warn hermes: effective fail-open when ryk is degraded — use ryk run -- hermes for wrapper enforcement\n");
    }
}

// ---------------------------------------------------------------------------
// doctor JSON output
// ---------------------------------------------------------------------------

fn writeDoctorJson(stdout: anytype, report: PluginDoctorReport, target: DoctorTarget) !void {
    try stdout.writeAll("{\n");
    try stdout.writeAll("  \"ryk_version\": ");
    try writeJsonString(stdout, report.ryk_version);
    try stdout.writeAll(",\n");

    try stdout.writeAll("  \"ryk_binary_path\": ");
    if (report.ryk_binary_path) |path| {
        try writeJsonString(stdout, path);
    } else {
        try stdout.writeAll("null");
    }
    try stdout.writeAll(",\n");

    try stdout.print("  \"cwd\": ", .{});
    try writeJsonString(stdout, report.cwd);
    try stdout.writeAll(",\n");

    try stdout.print("  \"workspace_root\": ", .{});
    try writeJsonString(stdout, report.workspace_root);
    try stdout.writeAll(",\n");

    try stdout.writeAll("  \"policy\": {\n");
    try stdout.print("    \"present\": {s},\n", .{if (report.policy_present) "true" else "false"});
    try stdout.print("    \"valid\": {s}\n", .{if (report.policy_valid) "true" else "false"});
    try stdout.writeAll("  },\n");

    try stdout.writeAll("  \"audit_replay_available\": ");
    try stdout.writeAll(if (report.audit_replay_available) "true" else "false");
    try stdout.writeAll(",\n");

    try stdout.print("  \"mcp_support_status\": ", .{});
    try writeJsonString(stdout, report.mcp_support_status);
    try stdout.writeAll(",\n");

    try stdout.writeAll("  \"plugin_directories\": {\n");
    try stdout.print("    \"codex\": {s},\n", .{if (report.plugin_directories.codex) "true" else "false"});
    try stdout.print("    \"claude\": {s},\n", .{if (report.plugin_directories.claude) "true" else "false"});
    try stdout.print("    \"opencode\": {s},\n", .{if (report.plugin_directories.opencode) "true" else "false"});
    try stdout.print("    \"openclaw\": {s},\n", .{if (report.plugin_directories.openclaw) "true" else "false"});
    try stdout.print("    \"hermes\": {s},\n", .{if (report.plugin_directories.hermes) "true" else "false"});
    try stdout.print("    \"common\": {s}\n", .{if (report.plugin_directories.common) "true" else "false"});
    try stdout.writeAll("  },\n");

    try stdout.writeAll("  \"host_binaries\": {\n");
    try stdout.print("    \"codex\": {s},\n", .{if (report.host_binaries.codex) "true" else "false"});
    try stdout.print("    \"claude\": {s},\n", .{if (report.host_binaries.claude) "true" else "false"});
    try stdout.print("    \"opencode\": {s},\n", .{if (report.host_binaries.opencode) "true" else "false"});
    try stdout.print("    \"openclaw\": {s},\n", .{if (report.host_binaries.openclaw) "true" else "false"});
    try stdout.print("    \"hermes\": {s}\n", .{if (report.host_binaries.hermes) "true" else "false"});
    try stdout.writeAll("  },\n");

    try stdout.writeAll("  \"opencode_paths\": {\n");
    try stdout.print("    \"project_plugin_exists\": {s},\n", .{if (report.opencode_paths.project_plugin_exists) "true" else "false"});
    try stdout.print("    \"global_plugin_exists\": {s},\n", .{if (report.opencode_paths.global_plugin_exists) "true" else "false"});
    try stdout.print("    \"config_references_plugin\": {s}\n", .{if (report.opencode_paths.config_references_plugin) "true" else "false"});
    try stdout.writeAll("  },\n");

    try stdout.writeAll("  \"openclaw_paths\": {\n");
    try stdout.print("    \"host_plugin_installed\": {s},\n", .{if (report.openclaw_paths.host_plugin_installed) "true" else "false"});
    try stdout.print("    \"plugin_manifest_exists\": {s},\n", .{if (report.openclaw_paths.plugin_manifest_exists) "true" else "false"});
    try stdout.print("    \"package_json_exists\": {s},\n", .{if (report.openclaw_paths.package_json_exists) "true" else "false"});
    try stdout.print("    \"source_exists\": {s},\n", .{if (report.openclaw_paths.source_exists) "true" else "false"});
    try stdout.writeAll("    \"detection_note\": ");
    try writeJsonString(stdout, report.openclaw_paths.detection_note);
    try stdout.writeAll(",\n");
    try openclaw_status.writePathsJsonHonesty(stdout);
    try stdout.writeAll("  },\n");

    try stdout.writeAll("  \"hermes_paths\": {\n");
    try stdout.print("    \"repo_manifest_exists\": {s},\n", .{if (report.hermes_paths.repo_manifest_exists) "true" else "false"});
    try stdout.print("    \"repo_source_exists\": {s},\n", .{if (report.hermes_paths.repo_source_exists) "true" else "false"});
    try stdout.print("    \"repo_mapping_exists\": {s},\n", .{if (report.hermes_paths.repo_mapping_exists) "true" else "false"});
    try stdout.print("    \"user_manifest_exists\": {s},\n", .{if (report.hermes_paths.user_manifest_exists) "true" else "false"});
    try stdout.print("    \"user_source_exists\": {s},\n", .{if (report.hermes_paths.user_source_exists) "true" else "false"});
    try stdout.print("    \"user_mapping_exists\": {s},\n", .{if (report.hermes_paths.user_mapping_exists) "true" else "false"});
    try stdout.print("    \"config_references_plugin\": {s},\n", .{if (report.hermes_paths.config_references_plugin) "true" else "false"});
    try stdout.print("    \"user_manifest_name_is_ryk\": {s}\n", .{if (report.hermes_paths.user_manifest_name_is_ryk) "true" else "false"});
    try stdout.writeAll("  },\n");

    try stdout.writeAll("  \"hermes_hook_smoke_passed\": ");
    try stdout.writeAll(if (report.hermes_hook_smoke_passed) "true" else "false");
    try stdout.writeAll(",\n");

    try stdout.writeAll("  \"marketplace\": {\n");
    try stdout.print("    \"codex_marketplace\": {s},\n", .{if (report.marketplace.codex_marketplace) "true" else "false"});
    try stdout.print("    \"claude_marketplace\": {s},\n", .{if (report.marketplace.claude_marketplace) "true" else "false"});
    try stdout.print("    \"codex_plugin_manifest\": {s},\n", .{if (report.marketplace.codex_plugin_manifest) "true" else "false"});
    try stdout.print("    \"claude_plugin_manifest\": {s},\n", .{if (report.marketplace.claude_plugin_manifest) "true" else "false"});
    try stdout.print("    \"codex_user_plugin\": {s},\n", .{if (report.marketplace.codex_user_plugin) "true" else "false"});
    try stdout.print("    \"claude_user_plugin\": {s}\n", .{if (report.marketplace.claude_user_plugin) "true" else "false"});
    try stdout.writeAll("  },\n");

    try stdout.print("  \"platform_summary\": ", .{});
    try writeJsonString(stdout, report.platform_summary);
    try stdout.writeAll(",\n");

    try stdout.writeAll("  \"target\": ");
    try writeJsonString(stdout, @tagName(target));
    try stdout.writeAll(",\n");

    try stdout.writeAll("  \"warnings\": [\n");
    for (report.warnings, 0..) |w, i| {
        try stdout.writeAll("    ");
        try writeJsonString(stdout, w);
        if (i < report.warnings.len - 1) try stdout.writeAll(",");
        try stdout.writeAll("\n");
    }
    try stdout.writeAll("  ]\n");

    try stdout.writeAll("}\n");
}

// ---------------------------------------------------------------------------
// manifest
// ---------------------------------------------------------------------------

const ManifestTarget = enum { codex, claude, opencode, openclaw, hermes, all };

fn manifestCommand(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    var target: ManifestTarget = .all;
    var json_mode = false;

    for (argv) |arg| {
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            try stdout.writeAll(
                \\Usage:
                \\  ryk plugin manifest codex
                \\  ryk plugin manifest claude
                \\  ryk plugin manifest opencode
                \\  ryk plugin manifest openclaw
                \\  ryk plugin manifest hermes
                \\  ryk plugin manifest all
                \\  ryk plugin manifest <target> [--json]
                \\
            );
            return exit_codes.success;
        }
        if (std.mem.eql(u8, arg, "--json")) {
            json_mode = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "codex")) {
            target = .codex;
            continue;
        }
        if (std.mem.eql(u8, arg, "claude")) {
            target = .claude;
            continue;
        }
        if (std.mem.eql(u8, arg, "opencode")) {
            target = .opencode;
            continue;
        }
        if (std.mem.eql(u8, arg, "openclaw")) {
            target = .openclaw;
            continue;
        }
        if (std.mem.eql(u8, arg, "hermes")) {
            target = .hermes;
            continue;
        }
        if (std.mem.eql(u8, arg, "all")) {
            target = .all;
            continue;
        }
        try suggestions.writeUnknownOption(stderr, "ryk plugin manifest", arg, &.{ "--json", "--help", "-h", "codex", "claude", "opencode", "openclaw", "hermes", "all" }, "plugin");
        return exit_codes.usage;
    }

    var gpa_state: gpa_mod.State = .init;
    defer _ = gpa_state.deinit();
    const manifest_allocator = gpa_state.allocator();
    const workspace_root = try plugin_install.resolveWorkspaceInstallRoot(io, manifest_allocator);
    defer manifest_allocator.free(workspace_root);

    if (json_mode) {
        try writeManifestJson(io, manifest_allocator, workspace_root, stdout, target);
    } else {
        try writeManifestPlain(io, manifest_allocator, workspace_root, stdout, target);
    }
    return exit_codes.success;
}

fn writeManifestPlain(io: std.Io, allocator: std.mem.Allocator, workspace_root: []const u8, stdout: anytype, target: ManifestTarget) !void {
    const codex_marketplace_path = try std.fs.path.join(allocator, &.{ workspace_root, ".agents", "plugins", "marketplace.json" });
    defer allocator.free(codex_marketplace_path);
    const claude_marketplace_path = try std.fs.path.join(allocator, &.{ workspace_root, ".claude-plugin", "marketplace.json" });
    defer allocator.free(claude_marketplace_path);

    switch (target) {
        .codex => {
            const path = try resolveBundledPath(io, allocator, "integrations/codex-plugin/.codex-plugin/plugin.json");
            defer allocator.free(path);
            const marketplace_path = codex_marketplace_path;
            const marketplace_exists = fileExistsAbsolute(io, marketplace_path);
            try stdout.writeAll("Codex plugin manifest:\n");
            try stdout.print("  expected path: {s}\n", .{path});
            try stdout.print("  status: {s}\n", .{if (fileExistsAbsolute(io, path)) "exists" else "missing"});
            try stdout.print("  marketplace: {s} ({s})\n", .{ marketplace_path, if (marketplace_exists) "exists" else "missing" });
            if (fileExistsAbsolute(io, path)) {
                try stdout.writeAll("  note: validation of manifest shape is deferred to host-specific checks\n");
            }
        },
        .claude => {
            const path = try resolveBundledPath(io, allocator, "integrations/claude-code-plugin/.claude-plugin/plugin.json");
            defer allocator.free(path);
            const marketplace_path = claude_marketplace_path;
            const marketplace_exists = fileExistsAbsolute(io, marketplace_path);
            try stdout.writeAll("Claude Code plugin manifest:\n");
            try stdout.print("  expected path: {s}\n", .{path});
            try stdout.print("  status: {s}\n", .{if (fileExistsAbsolute(io, path)) "exists" else "missing"});
            try stdout.print("  marketplace: {s} ({s})\n", .{ marketplace_path, if (marketplace_exists) "exists" else "missing" });
            if (fileExistsAbsolute(io, path)) {
                try stdout.writeAll("  note: validation of manifest shape is deferred to host-specific checks\n");
            }
        },
        .opencode => {
            const path = try resolveBundledPath(io, allocator, "integrations/opencode-plugin/ryk.ts");
            defer allocator.free(path);
            try stdout.writeAll("OpenCode plugin manifest:\n");
            try stdout.print("  expected path: {s}\n", .{path});
            try stdout.print("  status: {s}\n", .{if (fileExistsAbsolute(io, path)) "exists" else "missing"});
            try stdout.writeAll("  note: OpenCode uses TypeScript plugins, not a JSON manifest\n");
        },
        .openclaw => {
            const manifest_path = try resolveBundledPath(io, allocator, "integrations/openclaw-plugin/openclaw.plugin.json");
            defer allocator.free(manifest_path);
            const pkg_path = try resolveBundledPath(io, allocator, "integrations/openclaw-plugin/package.json");
            defer allocator.free(pkg_path);
            try stdout.writeAll("OpenClaw plugin manifest:\n");
            try stdout.print("  expected manifest path: {s}\n", .{manifest_path});
            try stdout.print("  manifest status: {s}\n", .{if (fileExistsAbsolute(io, manifest_path)) "exists" else "missing"});
            try stdout.print("  package.json: {s} ({s})\n", .{ pkg_path, if (fileExistsAbsolute(io, pkg_path)) "exists" else "missing" });
            if (fileExistsAbsolute(io, manifest_path)) {
                try stdout.writeAll("  note: validation of manifest shape is deferred to host-specific checks\n");
            }
        },
        .hermes => {
            // Use resolveBundledPath so this works for both source trees and packaged installs
            // (where RYK_RESOURCE_ROOT points at the installed runtime assets).
            const manifest_path = try resolveBundledPath(io, allocator, "integrations/hermes-plugin/plugin.yaml");
            defer allocator.free(manifest_path);
            const source_path = try resolveBundledPath(io, allocator, "integrations/hermes-plugin/__init__.py");
            defer allocator.free(source_path);
            const manifest_exists = fileExistsAbsolute(io, manifest_path);
            const source_exists = fileExistsAbsolute(io, source_path);
            try stdout.writeAll("Hermes plugin manifest:\n");
            try stdout.print("  expected manifest path: {s}\n", .{manifest_path});
            try stdout.print("  manifest status: {s}\n", .{if (manifest_exists) "exists" else "missing"});
            try stdout.print("  source: {s} ({s})\n", .{ source_path, if (source_exists) "exists" else "missing" });
            try stdout.writeAll("  user install path: ~/.hermes/plugins/ryk/\n");
        },
        .all => {
            try stdout.writeAll("Plugin manifests:\n");
            // Bundled plugin manifests must go through resolveBundledPath for packaged installs.
            const codex_path = try resolveBundledPath(io, allocator, "integrations/codex-plugin/.codex-plugin/plugin.json");
            defer allocator.free(codex_path);
            const claude_path = try resolveBundledPath(io, allocator, "integrations/claude-code-plugin/.claude-plugin/plugin.json");
            defer allocator.free(claude_path);
            const opencode_path = try resolveBundledPath(io, allocator, "integrations/opencode-plugin/ryk.ts");
            defer allocator.free(opencode_path);
            const openclaw_path = try resolveBundledPath(io, allocator, "integrations/openclaw-plugin/openclaw.plugin.json");
            defer allocator.free(openclaw_path);
            const hermes_path = try resolveBundledPath(io, allocator, "integrations/hermes-plugin/plugin.yaml");
            defer allocator.free(hermes_path);
            try stdout.print("  codex:    {s} ({s})\n", .{ codex_path, if (fileExistsAbsolute(io, codex_path)) "exists" else "missing" });
            try stdout.print("  claude:   {s} ({s})\n", .{ claude_path, if (fileExistsAbsolute(io, claude_path)) "exists" else "missing" });
            try stdout.print("  opencode: {s} ({s})\n", .{ opencode_path, if (fileExistsAbsolute(io, opencode_path)) "exists" else "missing" });
            try stdout.print("  openclaw: {s} ({s})\n", .{ openclaw_path, if (fileExistsAbsolute(io, openclaw_path)) "exists" else "missing" });
            try stdout.print("  hermes:   {s} ({s})\n", .{ hermes_path, if (fileExistsAbsolute(io, hermes_path)) "exists" else "missing" });
            try stdout.writeAll("\nMarketplace files:\n");
            try stdout.print("  codex:    {s} ({s})\n", .{ codex_marketplace_path, if (fileExistsAbsolute(io, codex_marketplace_path)) "exists" else "missing" });
            try stdout.print("  claude:   {s} ({s})\n", .{ claude_marketplace_path, if (fileExistsAbsolute(io, claude_marketplace_path)) "exists" else "missing" });
        },
    }
}

fn writeManifestJson(io: std.Io, allocator: std.mem.Allocator, workspace_root: []const u8, stdout: anytype, target: ManifestTarget) !void {
    const codex_marketplace_path = try std.fs.path.join(allocator, &.{ workspace_root, ".agents", "plugins", "marketplace.json" });
    defer allocator.free(codex_marketplace_path);
    const claude_marketplace_path = try std.fs.path.join(allocator, &.{ workspace_root, ".claude-plugin", "marketplace.json" });
    defer allocator.free(claude_marketplace_path);

    try stdout.writeAll("{\n");
    switch (target) {
        .codex => {
            // Use resolve (now robust) so JSON output is truthful for packaged installs
            // (matches the hermes case and the plain writer).
            const path = try resolveBundledPath(io, allocator, "integrations/codex-plugin/.codex-plugin/plugin.json");
            defer allocator.free(path);
            const marketplace_path = codex_marketplace_path;
            try stdout.writeAll("  \"codex\": {\n");
            try stdout.print("    \"path\": ", .{});
            try writeJsonString(stdout, path);
            try stdout.writeAll(",\n");
            try stdout.print("    \"status\": \"{s}\",\n", .{if (fileExistsAbsolute(io, path)) "exists" else "missing"});
            try stdout.print("    \"marketplace_path\": ", .{});
            try writeJsonString(stdout, marketplace_path);
            try stdout.writeAll(",\n");
            try stdout.print("    \"marketplace_status\": \"{s}\"\n", .{if (fileExistsAbsolute(io, marketplace_path)) "exists" else "missing"});
            try stdout.writeAll("  }\n");
        },
        .claude => {
            const path = try resolveBundledPath(io, allocator, "integrations/claude-code-plugin/.claude-plugin/plugin.json");
            defer allocator.free(path);
            const marketplace_path = claude_marketplace_path;
            try stdout.writeAll("  \"claude\": {\n");
            try stdout.print("    \"path\": ", .{});
            try writeJsonString(stdout, path);
            try stdout.writeAll(",\n");
            try stdout.print("    \"status\": \"{s}\",\n", .{if (fileExistsAbsolute(io, path)) "exists" else "missing"});
            try stdout.print("    \"marketplace_path\": ", .{});
            try writeJsonString(stdout, marketplace_path);
            try stdout.writeAll(",\n");
            try stdout.print("    \"marketplace_status\": \"{s}\"\n", .{if (fileExistsAbsolute(io, marketplace_path)) "exists" else "missing"});
            try stdout.writeAll("  }\n");
        },
        .opencode => {
            const path = try resolveBundledPath(io, allocator, "integrations/opencode-plugin/ryk.ts");
            defer allocator.free(path);
            try stdout.writeAll("  \"opencode\": {\n");
            try stdout.print("    \"path\": ", .{});
            try writeJsonString(stdout, path);
            try stdout.writeAll(",\n");
            try stdout.print("    \"status\": \"{s}\"\n", .{if (fileExistsAbsolute(io, path)) "exists" else "missing"});
            try stdout.writeAll("  }\n");
        },
        .openclaw => {
            const manifest_path = try resolveBundledPath(io, allocator, "integrations/openclaw-plugin/openclaw.plugin.json");
            defer allocator.free(manifest_path);
            const pkg_path = try resolveBundledPath(io, allocator, "integrations/openclaw-plugin/package.json");
            defer allocator.free(pkg_path);
            try stdout.writeAll("  \"openclaw\": {\n");
            try stdout.print("    \"manifest_path\": ", .{});
            try writeJsonString(stdout, manifest_path);
            try stdout.writeAll(",\n");
            try stdout.print("    \"manifest_status\": \"{s}\",\n", .{if (fileExistsAbsolute(io, manifest_path)) "exists" else "missing"});
            try stdout.print("    \"package_path\": ", .{});
            try writeJsonString(stdout, pkg_path);
            try stdout.writeAll(",\n");
            try stdout.print("    \"package_status\": \"{s}\"\n", .{if (fileExistsAbsolute(io, pkg_path)) "exists" else "missing"});
            try stdout.writeAll("  }\n");
        },
        .hermes => {
            // Use resolveBundledPath so --json output is truthful for packaged installs.
            const manifest_path = try resolveBundledPath(io, allocator, "integrations/hermes-plugin/plugin.yaml");
            defer allocator.free(manifest_path);
            const source_path = try resolveBundledPath(io, allocator, "integrations/hermes-plugin/__init__.py");
            defer allocator.free(source_path);
            try stdout.writeAll("  \"hermes\": {\n");
            try stdout.print("    \"manifest_path\": ", .{});
            try writeJsonString(stdout, manifest_path);
            try stdout.writeAll(",\n");
            try stdout.print("    \"manifest_status\": \"{s}\",\n", .{if (fileExistsAbsolute(io, manifest_path)) "exists" else "missing"});
            try stdout.print("    \"source_path\": ", .{});
            try writeJsonString(stdout, source_path);
            try stdout.writeAll(",\n");
            try stdout.print("    \"source_status\": \"{s}\"\n", .{if (fileExistsAbsolute(io, source_path)) "exists" else "missing"});
            try stdout.writeAll("  }\n");
        },
        .all => {
            // Bundled paths must resolve via RYK_RESOURCE_ROOT for packaged installs.
            const codex_path = try resolveBundledPath(io, allocator, "integrations/codex-plugin/.codex-plugin/plugin.json");
            defer allocator.free(codex_path);
            const claude_path = try resolveBundledPath(io, allocator, "integrations/claude-code-plugin/.claude-plugin/plugin.json");
            defer allocator.free(claude_path);
            const opencode_path = try resolveBundledPath(io, allocator, "integrations/opencode-plugin/ryk.ts");
            defer allocator.free(opencode_path);
            const openclaw_manifest_path = try resolveBundledPath(io, allocator, "integrations/openclaw-plugin/openclaw.plugin.json");
            defer allocator.free(openclaw_manifest_path);
            const hermes_manifest_path = try resolveBundledPath(io, allocator, "integrations/hermes-plugin/plugin.yaml");
            defer allocator.free(hermes_manifest_path);
            const codex_marketplace = codex_marketplace_path;
            const claude_marketplace = claude_marketplace_path;
            try stdout.writeAll("  \"codex\": {\n");
            try stdout.print("    \"path\": ", .{});
            try writeJsonString(stdout, codex_path);
            try stdout.writeAll(",\n");
            try stdout.print("    \"status\": \"{s}\",\n", .{if (fileExistsAbsolute(io, codex_path)) "exists" else "missing"});
            try stdout.print("    \"marketplace_path\": ", .{});
            try writeJsonString(stdout, codex_marketplace);
            try stdout.writeAll(",\n");
            try stdout.print("    \"marketplace_status\": \"{s}\"\n", .{if (fileExistsAbsolute(io, codex_marketplace)) "exists" else "missing"});
            try stdout.writeAll("  },\n");
            try stdout.writeAll("  \"claude\": {\n");
            try stdout.print("    \"path\": ", .{});
            try writeJsonString(stdout, claude_path);
            try stdout.writeAll(",\n");
            try stdout.print("    \"status\": \"{s}\",\n", .{if (fileExistsAbsolute(io, claude_path)) "exists" else "missing"});
            try stdout.print("    \"marketplace_path\": ", .{});
            try writeJsonString(stdout, claude_marketplace);
            try stdout.writeAll(",\n");
            try stdout.print("    \"marketplace_status\": \"{s}\"\n", .{if (fileExistsAbsolute(io, claude_marketplace)) "exists" else "missing"});
            try stdout.writeAll("  },\n");
            try stdout.writeAll("  \"opencode\": {\n");
            try stdout.print("    \"path\": ", .{});
            try writeJsonString(stdout, opencode_path);
            try stdout.writeAll(",\n");
            try stdout.print("    \"status\": \"{s}\"\n", .{if (fileExistsAbsolute(io, opencode_path)) "exists" else "missing"});
            try stdout.writeAll("  },\n");
            try stdout.writeAll("  \"openclaw\": {\n");
            try stdout.print("    \"manifest_path\": ", .{});
            try writeJsonString(stdout, openclaw_manifest_path);
            try stdout.writeAll(",\n");
            try stdout.print("    \"manifest_status\": \"{s}\"\n", .{if (fileExistsAbsolute(io, openclaw_manifest_path)) "exists" else "missing"});
            try stdout.writeAll("  },\n");
            try stdout.writeAll("  \"hermes\": {\n");
            try stdout.print("    \"manifest_path\": ", .{});
            try writeJsonString(stdout, hermes_manifest_path);
            try stdout.writeAll(",\n");
            try stdout.print("    \"manifest_status\": \"{s}\"\n", .{if (fileExistsAbsolute(io, hermes_manifest_path)) "exists" else "missing"});
            try stdout.writeAll("  }\n");
        },
    }
    try stdout.writeAll("}\n");
}

// ---------------------------------------------------------------------------
// install
// ---------------------------------------------------------------------------

const InstallTarget = enum { codex, claude, opencode, openclaw, hermes, all };
const InstallScope = enum { project, global };

fn installCommand(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    var target: InstallTarget = .all;
    var target_explicit = false;
    var dry_run = true; // default to safe dry-run
    var dry_run_explicit = false;
    var custom_path: ?[]const u8 = null;
    var yes = false;
    var all_detected = false;
    var scope: InstallScope = .global; // OpenCode day-one: machine-wide path OpenCode always finds

    var gpa_state: gpa_mod.State = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();

    var index: usize = 0;
    while (index < argv.len) : (index += 1) {
        const arg = argv[index];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            try stdout.writeAll(
                \\Usage:
                \\  ryk plugin install                     # dry-run preview of all hosts (no mutation)
                \\  ryk plugin install codex [--dry-run|--yes]
                \\  ryk plugin install claude [--dry-run|--yes]
                \\  ryk plugin install opencode [--dry-run|--yes]
                \\  ryk plugin install openclaw [--dry-run|--yes]
                \\  ryk plugin install hermes [--dry-run|--yes]
                \\  ryk plugin install all [--dry-run|--yes]
                \\  ryk plugin install all --all-detected [--dry-run|--yes]
                \\  ryk plugin install <target> --path <plugin-path> [--dry-run|--yes]
                \\  ryk plugin install opencode --scope project|global [--dry-run|--yes]
                \\
                \\Primary flow: `ryk doctor --fix` (ensure + auto-wire). For advanced installs: `ryk plugin install <host>`. Mutation requires an explicit host or `all` plus --yes (or interactive confirm default No).
                \\Options:
                \\  --dry-run       Preview changes without mutating host config
                \\  --all-detected  Only install for hosts found in PATH
                \\  --path          Use a custom plugin path instead of the default
                \\  --scope         OpenCode install scope: project|global (default: global)
                \\  --yes           Confirm mutation (required for non-TTY install)
                \\
            );
            return exit_codes.success;
        }
        if (std.mem.eql(u8, arg, "--dry-run")) {
            dry_run = true;
            dry_run_explicit = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--yes")) {
            yes = true;
            if (!dry_run_explicit) dry_run = false;
            continue;
        }
        if (std.mem.eql(u8, arg, "--all-detected")) {
            all_detected = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--path")) {
            if (index + 1 >= argv.len) {
                try stderr.writeAll("ryk plugin install: --path requires a value.\n");
                return exit_codes.usage;
            }
            custom_path = argv[index + 1];
            index += 1;
            continue;
        }
        if (std.mem.eql(u8, arg, "--scope")) {
            if (index + 1 >= argv.len) {
                try stderr.writeAll("ryk plugin install: --scope requires a value.\n");
                return exit_codes.usage;
            }
            const value = argv[index + 1];
            if (std.mem.eql(u8, value, "project")) {
                scope = .project;
            } else if (std.mem.eql(u8, value, "global")) {
                scope = .global;
            } else {
                try suggestions.writeInvalidValue(stderr, "ryk plugin install", "--scope", value, &.{ "project", "global" }, "plugin");
                return exit_codes.usage;
            }
            index += 1;
            continue;
        }
        if (std.mem.eql(u8, arg, "codex")) {
            target = .codex;
            target_explicit = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "claude")) {
            target = .claude;
            target_explicit = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "opencode")) {
            target = .opencode;
            target_explicit = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "openclaw")) {
            target = .openclaw;
            target_explicit = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "hermes")) {
            target = .hermes;
            target_explicit = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "all")) {
            target = .all;
            target_explicit = true;
            continue;
        }
        try suggestions.writeUnknownOption(stderr, "ryk plugin install", arg, &.{ "--dry-run", "--yes", "--all-detected", "--path", "--scope", "--help", "-h", "codex", "claude", "opencode", "openclaw", "hermes", "all" }, "plugin");
        return exit_codes.usage;
    }

    // Bare install (no host / all): dry-run preview only — never mutate all hosts by default.
    if (!target_explicit) {
        if (yes and !dry_run_explicit) {
            try stderr.writeAll(
                "ryk plugin install: mutation requires an explicit host or `all` (e.g. `ryk plugin install codex --yes`).\n" ++
                    "Bare `ryk plugin install` is a dry-run preview only.\n",
            );
            return exit_codes.usage;
        }
        dry_run = true;
        target = .all;
    } else if (!dry_run_explicit and !yes) {
        const stdin = std.Io.File.stdin();
        if ((stdin.isTty(io) catch false)) {
            const host_label = if (target == .all and all_detected) "all detected" else if (target == .all) "all" else @tagName(target);
            var prompt_buf: [64]u8 = undefined;
            const prompt = std.fmt.bufPrint(&prompt_buf, "Install {s} plugin?", .{host_label}) catch "Install plugin?";
            // Canonical confirm: empty Enter = default No (cancel).
            const accepted = interactive.askConfirmInteractive(io, stdout, prompt, false) catch |err| {
                try stderr.print("ryk plugin install: confirmation failed: {s}\n", .{@errorName(err)});
                return exit_codes.general;
            };
            if (!accepted) {
                try stdout.writeAll("canceled\n");
                return exit_codes.success;
            }
            dry_run = false;
        } else {
            try stderr.writeAll("ryk plugin install: actual installation requires --yes or --dry-run to preview.\n");
            return exit_codes.usage;
        }
    }

    try stdout.writeAll("ryk Plugin Install\n\n");

    const workspace_root = try plugin_install.resolveWorkspaceInstallRoot(io, allocator);
    defer allocator.free(workspace_root);

    var smoke_deny_failed = false;
    var smoke_degraded = false;
    var opencode_install_attempted = false;
    var opencode_smoke_deny_ok = false;
    var detected_targets: [5]InstallTarget = undefined;
    var detected_count: usize = 0;

    const targets = switch (target) {
        .codex => &[_]InstallTarget{.codex},
        .claude => &[_]InstallTarget{.claude},
        .opencode => &[_]InstallTarget{.opencode},
        .openclaw => &[_]InstallTarget{.openclaw},
        .hermes => &[_]InstallTarget{.hermes},
        .all => if (all_detected) blk: {
            if (binaryInPath(io, allocator, "codex")) {
                detected_targets[detected_count] = .codex;
                detected_count += 1;
            }
            if (binaryInPath(io, allocator, "claude")) {
                detected_targets[detected_count] = .claude;
                detected_count += 1;
            }
            if (binaryInPath(io, allocator, "opencode")) {
                detected_targets[detected_count] = .opencode;
                detected_count += 1;
            }
            if (binaryInPath(io, allocator, "openclaw")) {
                detected_targets[detected_count] = .openclaw;
                detected_count += 1;
            }
            if (binaryInPath(io, allocator, "hermes")) {
                detected_targets[detected_count] = .hermes;
                detected_count += 1;
            }
            break :blk detected_targets[0..detected_count];
        } else &[_]InstallTarget{ .codex, .claude, .opencode, .openclaw, .hermes },
    };

    for (targets) |t| {
        try stdout.print("Target: {s}\n", .{@tagName(t)});
        try stdout.print("  mode: {s}\n", .{if (dry_run) "dry-run (no changes made)" else "install"});

        if (custom_path) |p| {
            try stdout.print("  custom path: {s}\n", .{p});
        }
        if (t == .opencode) {
            try stdout.print("  scope: {s}\n", .{@tagName(scope)});
        }

        const plugin_dir = if (custom_path) |path| try allocator.dupe(u8, path) else switch (t) {
            .codex => try resolveBundledPath(io, allocator, "integrations/codex-plugin"),
            .claude => try resolveBundledPath(io, allocator, "integrations/claude-code-plugin"),
            .opencode => try resolveBundledPath(io, allocator, "integrations/opencode-plugin"),
            .openclaw => try resolveBundledPath(io, allocator, "integrations/openclaw-plugin"),
            .hermes => try resolveBundledPath(io, allocator, "integrations/hermes-plugin"),
            .all => unreachable,
        };
        defer allocator.free(plugin_dir);

        if (!dirExists(plugin_dir)) {
            try stdout.print("  plugin directory: missing ({s})\n", .{plugin_dir});
            try stdout.writeAll("  next step: create the plugin directory and manifest before installing\n");
            if (!dry_run) return exit_codes.general;
        } else {
            try stdout.print("  plugin directory: found ({s})\n", .{plugin_dir});

            if (t == .opencode) {
                // OpenCode managed plugin is release software: upgrade in place when
                // bundled bytes differ. Also reconcile the other scope when that
                // destination already exists so project plugins cannot stay stale
                // after a global day-one/update install.
                const source_path = try std.fs.path.join(allocator, &.{ plugin_dir, "ryk.ts" });
                defer allocator.free(source_path);
                const tui_source_path = try std.fs.path.join(allocator, &.{ plugin_dir, "ryk-tui.ts" });
                defer allocator.free(tui_source_path);
                const destination_path = try resolveOpenCodeDestination(allocator, workspace_root, scope);
                defer allocator.free(destination_path);
                const other_scope: InstallScope = if (scope == .global) .project else .global;
                const other_destination_path = try resolveOpenCodeDestination(allocator, workspace_root, other_scope);
                defer allocator.free(other_destination_path);
                const tui_destination_path = try siblingOpenCodePluginPath(allocator, destination_path, "ryk-tui.ts");
                defer allocator.free(tui_destination_path);
                const other_tui_destination_path = try siblingOpenCodePluginPath(allocator, other_destination_path, "ryk-tui.ts");
                defer allocator.free(other_tui_destination_path);

                try stdout.writeAll("  install paths for OpenCode:\n");
                try stdout.writeAll("    project: .opencode/plugins/ryk.ts + ryk-tui.ts\n");
                try stdout.writeAll("    global:  ~/.config/opencode/plugins/ryk.ts + ryk-tui.ts (default)\n");
                if (dry_run) {
                    try stdout.writeAll("  action: no changes made (dry-run)\n");
                    try stdout.print("  next step: copy {s} to {s}\n", .{ source_path, destination_path });
                    try stdout.print("  next step: copy {s} to {s}\n", .{ tui_source_path, tui_destination_path });
                    if (fileExistsAbsolute(io, other_destination_path)) {
                        try stdout.print("  next step: also upgrade existing {s} scope at {s}\n", .{ @tagName(other_scope), other_destination_path });
                    }
                } else {
                    if (!fileExistsAbsolute(io, source_path)) {
                        try stdout.print("  action: failed (source missing: {s})\n", .{source_path});
                        return exit_codes.general;
                    }
                    if (!fileExistsAbsolute(io, tui_source_path)) {
                        try stdout.print("  action: failed (source missing: {s})\n", .{tui_source_path});
                        return exit_codes.general;
                    }
                    installOpenCodeManagedDestination(allocator, io, stdout, source_path, destination_path) catch |err| switch (err) {
                        error.OpenCodeManagedInstallFailed => return exit_codes.general,
                        else => return err,
                    };
                    installOpenCodeManagedDestination(allocator, io, stdout, tui_source_path, tui_destination_path) catch |err| switch (err) {
                        error.OpenCodeManagedInstallFailed => return exit_codes.general,
                        else => return err,
                    };
                    if (fileExistsAbsolute(io, other_destination_path)) {
                        installOpenCodeManagedDestination(allocator, io, stdout, source_path, other_destination_path) catch |err| switch (err) {
                            error.OpenCodeManagedInstallFailed => return exit_codes.general,
                            else => return err,
                        };
                        installOpenCodeManagedDestination(allocator, io, stdout, tui_source_path, other_tui_destination_path) catch |err| switch (err) {
                            error.OpenCodeManagedInstallFailed => return exit_codes.general,
                            else => return err,
                        };
                    }
                    // Light config hygiene so local plugins auto-load.
                    if (ensureOpenCodeConfigSane(io, allocator)) |cfg_note| {
                        defer allocator.free(cfg_note);
                        try stdout.print("  config: {s}\n", .{cfg_note});
                    } else |_| {}
                    opencode_install_attempted = true;
                }
            } else if (t == .openclaw) {
                // OpenClaw-specific install guidance. The supported deployment
                // path is the curl installer plus the unattended workflow;
                // local host installation remains development-only.
                try openclaw_status.writeInstallPaths(stdout);
                if (dry_run) {
                    try stdout.writeAll("  action: no changes made (dry-run)\n");
                    try stdout.writeAll("  supported deployment:\n");
                    try stdout.writeAll("    curl -fsSL https://rykanv.com/install | sh\n");
                    try stdout.writeAll("    ryk agents setup openclaw\n");
                    try stdout.writeAll("  source-checkout development only: openclaw plugins install <plugin_dir>\n");
                } else {
                    const host_binary = try trustedHostBinary(io, allocator, "openclaw");
                    defer if (host_binary) |path| allocator.free(path);
                    if (host_binary == null) {
                        try stdout.writeAll("  action: failed (trusted OpenClaw 2026.8.1+ binary not found)\n");
                        return exit_codes.general;
                    }
                    const status = try runOpenClawInstall(allocator, host_binary.?, plugin_dir);
                    if (status == 0) {
                        try stdout.writeAll("  action: installed via openclaw host command\n");
                    } else {
                        try stdout.print("  action: failed (openclaw exit code: {d})\n", .{status});
                        return exit_codes.child_failure;
                    }
                    // Bind the host-reported install location to the exact
                    // reviewed bundle that was supplied to the host. Health
                    // refuses to treat a modified or relocated plugin as the
                    // installed Ryk adapter.
                    writeOpenClawManagedReceipt(io, allocator, host_binary.?, plugin_dir) catch |err| {
                        try stdout.print("  action: failed to attest the installed OpenClaw bundle ({s})\n", .{@errorName(err)});
                        return exit_codes.child_failure;
                    };
                    const config_status = try runOpenClawConfigureWorkspace(allocator, host_binary.?, workspace_root);
                    if (config_status != 0 or !try runOpenClawWorkspaceBindingMatches(allocator, host_binary.?, workspace_root)) {
                        try stdout.print("  action: failed to bind OpenClaw policy workspace (exit code: {d})\n", .{config_status});
                        return exit_codes.child_failure;
                    }
                    try stdout.print("  workspace: policy binding pinned to {s}\n", .{workspace_root});
                }
            } else if (t == .hermes) {
                const destination_path = try hermesUserPluginRoot(allocator);
                defer allocator.free(destination_path);
                const manifest_source = try std.fs.path.join(allocator, &.{ plugin_dir, "plugin.yaml" });
                defer allocator.free(manifest_source);
                const source_source = try std.fs.path.join(allocator, &.{ plugin_dir, "__init__.py" });
                defer allocator.free(source_source);
                const mapping_source = try std.fs.path.join(allocator, &.{ plugin_dir, "mapping.py" });
                defer allocator.free(mapping_source);
                const source_destination = try std.fs.path.join(allocator, &.{ destination_path, "__init__.py" });
                defer allocator.free(source_destination);
                const stance_destination = try std.fs.path.join(allocator, &.{ destination_path, host_status.hermes_fail_stance_filename });
                defer allocator.free(stance_destination);
                // Existing install: plugin source already present (hybrid L4 — do not silent-flip).
                const hermes_was_existing = fileExistsAbsolute(io, source_destination);

                try stdout.writeAll("  install paths for Hermes:\n");
                try stdout.print("    user: {s}\n", .{destination_path});
                try stdout.writeAll("    enable: hermes plugins enable ryk\n");
                if (dry_run) {
                    try stdout.writeAll("  action: no changes made (dry-run)\n");
                    try stdout.print("  next step: copy {s} to {s}\n", .{ plugin_dir, destination_path });
                    if (!hermes_was_existing) {
                        try stdout.writeAll("  fail stance (new install): fail-closed via .ryk_fail_stance\n");
                    }
                } else {
                    if (!hermesManagedDestination(io, allocator, destination_path)) {
                        try stdout.print("  action: failed (existing plugin directory is not Ryk-owned: {s})\n", .{destination_path});
                        return exit_codes.general;
                    }
                    if (!fileExistsAbsolute(io, manifest_source) or
                        !fileExistsAbsolute(io, source_source) or
                        !fileExistsAbsolute(io, mapping_source))
                    {
                        try stdout.writeAll("  action: failed (Hermes plugin files missing)\n");
                        return exit_codes.general;
                    }
                    // This directory is Ryk-owned. Stage the complete adapter
                    // tree and commit it as one bounded directory transaction.
                    const bundle_changed = try installHermesBundleAtomically(
                        io,
                        allocator,
                        plugin_dir,
                        destination_path,
                    );
                    if (bundle_changed) {
                        try stdout.print("  action: installed to {s}\n", .{destination_path});
                    } else {
                        try stdout.print("  action: already up-to-date at {s}\n", .{destination_path});
                    }
                    // Hybrid L4: new installs get fail-closed stance file; existing keep prior stance/default.
                    if (!hermes_was_existing and !fileExistsAbsolute(io, stance_destination)) {
                        try writeHermesFailClosedStance(allocator, destination_path);
                        try stdout.writeAll("  fail stance: fail-closed (new install default)\n");
                        try stdout.writeAll("    → Written: ~/.hermes/plugins/ryk/.ryk_fail_stance\n");
                        try stdout.writeAll("    → Override: export RYK_HERMES_FAIL_OPEN=1  (or: ryk run -- hermes for process wrap)\n");
                    } else {
                        try stdout.writeAll("  fail stance: left unchanged (existing install; missing/invalid stance is fail-closed)\n");
                        try stdout.writeAll("    → Explicit degraded override: export RYK_HERMES_FAIL_OPEN=1  # or: ryk run -- hermes\n");
                    }
                    const host_binary = try trustedHostBinary(io, allocator, "hermes");
                    defer if (host_binary) |path| allocator.free(path);
                    if (host_binary) |binary| {
                        const status = try runHermesEnable(allocator, binary);
                        if (status == 0) {
                            try stdout.writeAll("  enable: completed via hermes plugins enable ryk\n");
                        } else {
                            try stdout.print("  enable: failed (hermes exit code: {d})\n", .{status});
                            try writeHermesEnableHelper(allocator, destination_path);
                            return exit_codes.child_failure;
                        }
                    } else {
                        try stdout.writeAll("  enable: hermes binary not found in PATH\n");
                        try writeHermesEnableHelper(allocator, destination_path);
                    }
                }
            } else if (t == .codex or t == .claude) {
                const marketplace_host: plugin_install.MarketplaceHost = if (t == .codex) .codex else .claude;
                const template_rel = if (t == .codex)
                    "integrations/codex-plugin/examples/marketplace.json"
                else
                    "integrations/claude-code-plugin/examples/marketplace.json";
                const bundled_source = if (t == .codex)
                    "./integrations/codex-plugin"
                else
                    "./integrations/claude-code-plugin";
                const install_source = if (t == .codex) "./ryk" else "../.claude/plugins/ryk";
                const template_path = try resolveBundledPath(io, allocator, template_rel);
                defer allocator.free(template_path);
                const marketplace_json = try plugin_install.loadMarketplaceTemplate(
                    io,
                    allocator,
                    template_path,
                    bundled_source,
                    install_source,
                );
                defer allocator.free(marketplace_json);

                if (dry_run) {
                    const spec = try plugin_install.marketplaceHostInstallSpec(allocator, workspace_root, marketplace_host, marketplace_json);
                    defer {
                        allocator.free(spec.plugin_dest);
                        allocator.free(spec.marketplace_path);
                    }
                    try plugin_install.printMarketplaceHostInstallPlan(stdout, spec, plugin_dir);
                    try stdout.writeAll("  action: no changes made (dry-run)\n");
                } else if (t == .codex) {
                    plugin_install.installCodexPlugin(io, allocator, plugin_dir, workspace_root, marketplace_json, stdout) catch |err| switch (err) {
                        error.RefusingToOverwriteDifferentFile => {
                            try stdout.writeAll("  action: failed (destination exists and differs)\n");
                            return exit_codes.general;
                        },
                        else => return err,
                    };
                    try stdout.writeAll("  action: installed Codex plugin and marketplace registration\n");
                } else {
                    plugin_install.installClaudePlugin(io, allocator, plugin_dir, workspace_root, marketplace_json, stdout) catch |err| switch (err) {
                        error.RefusingToOverwriteDifferentFile => {
                            try stdout.writeAll("  action: failed (destination exists and differs)\n");
                            return exit_codes.general;
                        },
                        else => return err,
                    };
                    try stdout.writeAll("  action: installed Claude Code plugin and marketplace registration\n");
                }
            } else {
                if (dry_run) {
                    try stdout.writeAll("  action: no changes made (dry-run)\n");
                    try stdout.writeAll("  next step: host install command is not yet known; manual integration required\n");
                } else {
                    try stdout.writeAll("  action: failed (host plugin installation is not yet implemented)\n");
                    try stdout.writeAll("  note: use --dry-run for integration guidance until this host installer is implemented\n");
                    return exit_codes.unsupported;
                }
            }
        }

        // P1 install smoke: safe allow + dangerous deny on the host veto path.
        if (!dry_run and t != .all) {
            const host_name = @tagName(t);
            try stdout.writeAll("  smoke:\n");
            const smoke = host_status.runHostSmokePair(allocator, host_name) catch host_status.HostSmokePair{ .allow = .fail, .deny = .fail };
            try host_status.writeHostSmokeReport(stdout, host_name, smoke);
            if (smoke.denyFailed()) {
                smoke_deny_failed = true;
            } else if (smoke.isDegraded()) {
                smoke_degraded = true;
            } else if (t == .opencode) {
                opencode_smoke_deny_ok = smoke.deny != .fail;
            }
            if (t == .hermes and host_status.hermesFailOpenFromEnv()) {
                try stdout.writeAll("  warn: Hermes effective stance is fail-open — tools may run if ryk is degraded.\n");
                try stdout.writeAll("    → export RYK_HERMES_FAIL_OPEN=0  # or: ryk run -- hermes\n");
            }
        }
    }

    // Pi is managed by ensure / doctor --fix, not the legacy plugin subcommand.
    if (!dry_run and (target == .all or all_detected)) {
        try stdout.writeAll("\nPi: bundled extension setup is managed by `ryk doctor --fix` (no npm step).\n");
        try stdout.writeAll("  Verify: ryk doctor · process isolation: ryk run -- pi\n");
    }

    try stdout.writeAll("\n  safety: host config will not be silently overwritten\n");
    try stdout.writeAll("  safety: no credentials or telemetry will be stored\n");
    try stdout.writeAll("\n");
    // Exit non-zero only when install claimed success but deny smoke failed.
    if (smoke_deny_failed) {
        try stdout.writeAll("Install completed but smoke deny failed — host is NOT protected.\n");
        try stdout.writeAll("Run: ryk plugin doctor <host>\n");
        return exit_codes.general;
    }
    if (smoke_degraded) {
        try stdout.writeAll("Install completed but smoke is DEGRADED (deny ok, allow failed).\n");
        try stdout.writeAll("Host is safe/fail-closed but NOT ready — inspect with: ryk doctor\n");
        // Exit 0: protection proof (deny) passed; yellow is messaging-only per L3.
    }
    if (opencode_install_attempted and opencode_smoke_deny_ok and !smoke_deny_failed) {
        if (binaryInPath(io, allocator, "opencode")) {
            try stdout.writeAll("OpenCode is guarded.\n");
        } else {
            try stdout.writeAll("OpenCode plugin installed; host CLI not on PATH yet — install OpenCode, then re-run ryk doctor.\n");
        }
    }
    return exit_codes.success;
}

// ---------------------------------------------------------------------------
// mcp-server
// ---------------------------------------------------------------------------

fn mcpServerCommand(_: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    for (argv) |arg| {
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            try stdout.writeAll(
                \\Usage:
                \\  ryk plugin mcp-server [--help]
                \\
                \\Status: limited / deferred
                \\  The ryk MCP plugin server is planned but not yet active.
                \\  When implemented, it will expose safe read-only ryk capabilities as MCP tools:
                \\    - ryk_doctor
                \\    - ryk_plugin_doctor
                \\    - ryk_policy_check
                \\    - ryk_policy_explain
                \\    - ryk_redteam
                \\    - ryk_replay_summary
                \\    - ryk_capabilities
                \\  The following will NOT be exposed by default:
                \\    - arbitrary shell execution
                \\    - arbitrary file writes
                \\    - raw audit log dumping without redaction
                \\    - credential access
                \\    - policy mutation without explicit approval
                \\
            );
            return exit_codes.success;
        }
        try suggestions.writeUnknownOption(stderr, "ryk plugin mcp-server", arg, &.{ "--help", "-h" }, "plugin");
        return exit_codes.usage;
    }

    try stdout.writeAll("ryk Plugin MCP Server\n\n");
    try stdout.writeAll("Status: limited / deferred\n");
    try stdout.writeAll("  The ryk MCP plugin server is planned but not yet active.\n");
    try stdout.writeAll("  It does not listen on any port or transport.\n\n");
    try stdout.writeAll("Planned safe tools (when implemented):\n");
    try stdout.writeAll("  - ryk_doctor\n");
    try stdout.writeAll("  - ryk_plugin_doctor\n");
    try stdout.writeAll("  - ryk_policy_check\n");
    try stdout.writeAll("  - ryk_policy_explain\n");
    try stdout.writeAll("  - ryk_redteam\n");
    try stdout.writeAll("  - ryk_replay_summary\n");
    try stdout.writeAll("  - ryk_capabilities\n");
    try stdout.writeAll("\n");
    try stdout.writeAll("Blocked by default (not exposed):\n");
    try stdout.writeAll("  - arbitrary shell execution\n");
    try stdout.writeAll("  - arbitrary file writes\n");
    try stdout.writeAll("  - raw audit log dumping without redaction\n");
    try stdout.writeAll("  - credential access\n");
    try stdout.writeAll("  - policy mutation without explicit approval\n\n");
    try stdout.writeAll("Use 'ryk plugin mcp-server --help' for full details.\n");
    return exit_codes.success;
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

pub fn fileExistsAbsolute(io: std.Io, path: []const u8) bool {
    std.Io.Dir.cwd().access(io, path, .{}) catch return false;
    return true;
}

pub fn pluginDirExists(io: std.Io, allocator: std.mem.Allocator, relative_path: []const u8) bool {
    const resolved = resolveBundledPath(io, allocator, relative_path) catch return false;
    defer allocator.free(resolved);
    return dirExists(resolved);
}

pub fn resolveBundledPath(io: std.Io, allocator: std.mem.Allocator, relative_path: []const u8) ![]u8 {
    // Delegate to the robust resolver used by redteam/doctor (workspace → RYK_RESOURCE_ROOT
    // env → self-exe fallbacks including $PREFIX/share/ryk/current). This fixes the
    // long-standing inconsistency where `plugin manifest` reported "missing" for hermes
    // (and peers) after a correct install even when the assets were present and doctor/redteam
    // worked. We preserve the old contract: on total failure we still return the relative
    // string so callers can print a sensible "expected path" + "missing" status.
    const workspace_root: [:0]u8 = std.Io.Dir.cwd().realPathFileAlloc(io, ".", allocator) catch try allocator.dupeZ(u8, ".");
    defer allocator.free(workspace_root);

    if (resource_root.resolveResourcePath(io, allocator, .{ .workspace_root = workspace_root }, relative_path)) |resolved| {
        return resolved;
    } else |err| switch (err) {
        error.ResourceNotFound => return allocator.dupe(u8, relative_path),
        else => return err,
    }
}

pub fn openClawPluginListedInJson(allocator: std.mem.Allocator, output: []const u8) bool {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, output, .{}) catch return false;
    defer parsed.deinit();
    return openClawPluginListed(parsed.value);
}

fn openClawPluginListed(value: std.json.Value) bool {
    switch (value) {
        .array => |items| {
            for (items.items) |item| {
                if (openClawPluginEntryMatches(item)) return true;
            }
            return false;
        },
        .object => |obj| {
            if (obj.get("plugins")) |plugins| return openClawPluginListed(plugins);
            if (obj.get("items")) |items| return openClawPluginListed(items);
            return openClawPluginEntryMatches(value);
        },
        else => return false,
    }
}

fn openClawPluginEntryMatches(value: std.json.Value) bool {
    const obj = switch (value) {
        .object => |o| o,
        else => return false,
    };
    if (obj.get("id")) |id| {
        if (id == .string and std.mem.eql(u8, id.string, "ryk")) return true;
    }
    if (obj.get("name")) |name| {
        if (name == .string and (std.mem.eql(u8, name.string, "ryk") or std.mem.eql(u8, name.string, "ryk-openclaw-plugin"))) return true;
    }
    if (obj.get("package")) |pkg| {
        if (pkg == .string and (std.mem.eql(u8, pkg.string, "ryk") or std.mem.eql(u8, pkg.string, "ryk-openclaw-plugin"))) return true;
    }
    return false;
}

pub fn detectOpenClawHostInstall(
    io: std.Io,
    allocator: std.mem.Allocator,
    openclaw_in_path: bool,
    allow_host_cli_probe: bool,
) !OpenClawHostInstall {
    var env_map = env_util.createProcessMap(allocator) catch {
        return .{
            .host_plugin_installed = false,
            .plugin_manifest_exists = false,
            .package_json_exists = false,
            .source_exists = false,
            .detection_note = "HOME not set; host install unknown",
        };
    };
    defer env_map.deinit();
    const home_owned = try env_util.getOwnedHome(&env_map, allocator);
    const home = home_owned orelse return .{
        .host_plugin_installed = false,
        .plugin_manifest_exists = false,
        .package_json_exists = false,
        .source_exists = false,
        .detection_note = "HOME not set; host install unknown",
    };
    defer allocator.free(home);

    const extension_root = try std.fs.path.join(allocator, &.{ home, ".openclaw", "extensions", "ryk" });
    defer allocator.free(extension_root);
    const manifest_path = try std.fs.path.join(allocator, &.{ extension_root, "openclaw.plugin.json" });
    defer allocator.free(manifest_path);
    const package_json_path = try std.fs.path.join(allocator, &.{ extension_root, "package.json" });
    defer allocator.free(package_json_path);
    const source_path = try std.fs.path.join(allocator, &.{ extension_root, "src", "index.ts" });
    defer allocator.free(source_path);

    const manifest_exists = fileExistsAbsolute(io, manifest_path);
    const package_exists = fileExistsAbsolute(io, package_json_path);
    const source_exists = fileExistsAbsolute(io, source_path);
    // A partial directory must never be reported as protected. The host CLI's
    // own registry is the only alternative proof of a complete installation.
    var host_plugin_installed = manifest_exists and package_exists and source_exists;
    var detection_note: []const u8 = "checked host extension directory";

    if (!host_plugin_installed and openclaw_in_path and allow_host_cli_probe) {
        const list_output = captureChildOutput(allocator, &.{ "openclaw", "plugins", "list", "--json" }) catch null;
        if (list_output) |output| {
            defer allocator.free(output);
            if (openClawPluginListedInJson(allocator, output)) {
                host_plugin_installed = true;
                detection_note = "checked openclaw plugins list";
            }
        }
    } else if (!openclaw_in_path) {
        detection_note = "openclaw binary not found in PATH";
    } else if (!host_plugin_installed) {
        detection_note = "host CLI probe deferred to bounded health runtime checks";
    }

    return .{
        .host_plugin_installed = host_plugin_installed,
        .plugin_manifest_exists = manifest_exists,
        .package_json_exists = package_exists,
        .source_exists = source_exists,
        .detection_note = detection_note,
    };
}

pub fn captureChildOutput(allocator: std.mem.Allocator, argv: []const []const u8) ![]u8 {
    return captureChildOutputTimed(allocator, argv, 10_000);
}

pub fn captureChildOutputTimed(
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    timeout_ms: u32,
) ![]u8 {
    var result = try child_process.runHostCommandCaptureTimed(allocator, argv, timeout_ms);
    defer result.deinit(allocator);
    if (result.timed_out or result.output_overflow or result.exit_code != 0) return error.ChildFailed;
    return try allocator.dupe(u8, result.stdout);
}

pub fn captureChildOutputTimedInCurrentProcessGroup(
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    timeout_ms: u32,
) ![]u8 {
    var result = try child_process.runHostCommandCaptureTimedInCurrentProcessGroup(allocator, argv, timeout_ms);
    defer result.deinit(allocator);
    if (result.timed_out or result.output_overflow or result.exit_code != 0) return error.ChildFailed;
    return try allocator.dupe(u8, result.stdout);
}

pub fn hostPluginInstalledFromReport(host_name: []const u8, report: PluginDoctorReport) bool {
    if (std.mem.eql(u8, host_name, "hermes")) {
        // Config substring "ryk" alone is insufficient: stale name: orca manifests
        // still match config while hermes plugins enable ryk fails. Identity is
        // recorded on the report so doctor JSON and this predicate stay in sync.
        return report.hermes_paths.user_manifest_exists and
            report.hermes_paths.user_source_exists and
            report.hermes_paths.user_mapping_exists and
            report.hermes_paths.config_references_plugin and
            report.hermes_paths.user_manifest_name_is_ryk;
    }
    if (std.mem.eql(u8, host_name, "openclaw")) return report.openclaw_paths.host_plugin_installed;
    if (std.mem.eql(u8, host_name, "opencode")) {
        return report.opencode_paths.project_plugin_exists or report.opencode_paths.global_plugin_exists;
    }
    if (std.mem.eql(u8, host_name, "codex")) {
        return report.marketplace.codex_user_plugin and report.marketplace.codex_marketplace;
    }
    if (std.mem.eql(u8, host_name, "claude")) {
        return report.marketplace.claude_user_plugin and report.marketplace.claude_marketplace;
    }
    return false;
}

pub const HostInstallOutcome = enum {
    installed,
    installed_after_child_failure,
    failed,
};

pub fn classifyHostInstallOutcome(child_exit_code: u8, installed_after: bool) HostInstallOutcome {
    if (!installed_after) return .failed;
    return if (child_exit_code == 0) .installed else .installed_after_child_failure;
}

pub fn verifyHostInstallAfterChild(
    io: std.Io,
    allocator: std.mem.Allocator,
    host_name: []const u8,
    child_exit_code: u8,
) HostInstallOutcome {
    var report = collectPluginDoctorReport(io, allocator) catch return .failed;
    defer deinitPluginDoctorReport(&report, allocator);
    return classifyHostInstallOutcome(child_exit_code, hostPluginInstalledFromReport(host_name, report));
}

pub fn hostPluginInstalledFromDoctorJson(host_name: []const u8, root: std.json.Value) bool {
    if (std.mem.eql(u8, host_name, "hermes")) {
        const paths = root.object.get("hermes_paths") orelse return false;
        return jsonBoolField(paths.object, "user_manifest_exists") and
            jsonBoolField(paths.object, "user_source_exists") and
            jsonBoolField(paths.object, "user_mapping_exists") and
            jsonBoolField(paths.object, "config_references_plugin") and
            jsonBoolField(paths.object, "user_manifest_name_is_ryk");
    }
    if (std.mem.eql(u8, host_name, "openclaw")) {
        const paths = root.object.get("openclaw_paths") orelse return false;
        return jsonBoolField(paths.object, "host_plugin_installed");
    }
    if (std.mem.eql(u8, host_name, "opencode")) {
        const paths = root.object.get("opencode_paths") orelse return false;
        return jsonBoolField(paths.object, "project_plugin_exists") or
            jsonBoolField(paths.object, "global_plugin_exists");
    }
    if (std.mem.eql(u8, host_name, "codex")) {
        const marketplace = root.object.get("marketplace") orelse return false;
        return jsonBoolField(marketplace.object, "codex_user_plugin") and
            jsonBoolField(marketplace.object, "codex_marketplace");
    }
    if (std.mem.eql(u8, host_name, "claude")) {
        const marketplace = root.object.get("marketplace") orelse return false;
        return jsonBoolField(marketplace.object, "claude_user_plugin") and
            jsonBoolField(marketplace.object, "claude_marketplace");
    }
    return false;
}

fn jsonBoolField(object: std.json.ObjectMap, key: []const u8) bool {
    const value = object.get(key) orelse return false;
    return switch (value) {
        .bool => |enabled| enabled,
        else => false,
    };
}

/// Ensure ~/.config/opencode/opencode.json lets local file plugins auto-load.
/// - Missing file → create minimal `{"plugin":[]}`.
/// - Broken docs placeholder `plugin: ["list"]` → rewrite to `[]`.
/// Returns owned status note for the install receipt.
fn ensureOpenCodeConfigSane(io: std.Io, allocator: std.mem.Allocator) ![]const u8 {
    var env_map = try env_util.createProcessMap(allocator);
    defer env_map.deinit();
    const home = (try env_util.getOwnedHome(&env_map, allocator)) orelse return error.HomeNotSet;
    defer allocator.free(home);

    const config_dir = try std.fs.path.join(allocator, &.{ home, ".config", "opencode" });
    defer allocator.free(config_dir);
    const config_path = try std.fs.path.join(allocator, &.{ config_dir, "opencode.json" });
    defer allocator.free(config_path);

    const minimal =
        \\{
        \\  "plugin": []
        \\}
        \\
    ;

    const exists = fileExistsAbsolute(io, config_path);

    if (!exists) {
        // installTextIfSafe creates parent dirs securely (no symlink parents).
        _ = try plugin_install.installTextIfSafe(io, allocator, minimal, config_path, true);
        return try allocator.dupe(u8, "wrote ~/.config/opencode/opencode.json with plugin:[] (local plugins auto-load)");
    }

    const content = std.Io.Dir.cwd().readFileAlloc(io, config_path, allocator, .limited(256 * 1024)) catch
        return try allocator.dupe(u8, "opencode.json present (could not read; left unchanged)");
    defer allocator.free(content);

    // Broken docs placeholder: "plugin": ["list"]
    if (std.mem.indexOf(u8, content, "\"plugin\"") != null and
        std.mem.indexOf(u8, content, "[\"list\"]") != null)
    {
        _ = try plugin_install.installTextIfSafe(io, allocator, minimal, config_path, true);
        return try allocator.dupe(u8, "repaired broken plugin list placeholder in opencode.json");
    }
    return try allocator.dupe(u8, "opencode.json present (local plugins auto-load when plugin is empty or omitted)");
}

fn siblingOpenCodePluginPath(allocator: std.mem.Allocator, destination_path: []const u8, name: []const u8) ![]u8 {
    const dir = std.fs.path.dirname(destination_path) orelse return error.InvalidPath;
    return std.fs.path.join(allocator, &.{ dir, name });
}

fn openCodePairExists(io: std.Io, hook_path: []const u8, tui_path: []const u8) bool {
    return fileExistsAbsolute(io, hook_path) and fileExistsAbsolute(io, tui_path);
}

pub fn resolveOpenCodeDestination(allocator: std.mem.Allocator, workspace_root: []const u8, scope: InstallScope) ![]u8 {
    return switch (scope) {
        .project => std.fs.path.join(allocator, &.{ workspace_root, ".opencode", "plugins", "ryk.ts" }),
        .global => blk: {
            var env_map = env_util.createProcessMap(allocator) catch return std.fs.path.join(allocator, &.{ "~", ".config", "opencode", "plugins", "ryk.ts" });
            defer env_map.deinit();
            const home = env_util.getOwnedHome(&env_map, allocator) catch return std.fs.path.join(allocator, &.{ "~", ".config", "opencode", "plugins", "ryk.ts" });
            const home_owned = home orelse return std.fs.path.join(allocator, &.{ "~", ".config", "opencode", "plugins", "ryk.ts" });
            defer allocator.free(home_owned);
            break :blk std.fs.path.join(allocator, &.{ home_owned, ".config", "opencode", "plugins", "ryk.ts" });
        },
    };
}

pub fn hermesUserPluginRoot(allocator: std.mem.Allocator) ![]u8 {
    var env_map = env_util.createProcessMap(allocator) catch return std.fs.path.join(allocator, &.{ "~", ".hermes", "plugins", "ryk" });
    defer env_map.deinit();
    const hermes_home = try hermesHomeFromEnvMap(allocator, &env_map);
    defer allocator.free(hermes_home);
    return std.fs.path.join(allocator, &.{ hermes_home, "plugins", "ryk" });
}

pub fn hermesConfigPath(allocator: std.mem.Allocator) ![]u8 {
    var env_map = env_util.createProcessMap(allocator) catch return std.fs.path.join(allocator, &.{ "~", ".hermes", "config.yaml" });
    defer env_map.deinit();
    const hermes_home = try hermesHomeFromEnvMap(allocator, &env_map);
    defer allocator.free(hermes_home);
    return std.fs.path.join(allocator, &.{ hermes_home, "config.yaml" });
}

fn hermesHomeFromEnvMap(
    allocator: std.mem.Allocator,
    env_map: *const std.process.Environ.Map,
) ![]u8 {
    if (env_map.get("HERMES_HOME")) |custom| {
        if (std.fs.path.isAbsolute(custom)) return allocator.dupe(u8, custom);
    }
    const home = (try env_util.getOwnedHome(env_map, allocator)) orelse return std.fs.path.join(allocator, &.{ "~", ".hermes" });
    defer allocator.free(home);
    return std.fs.path.join(allocator, &.{ home, ".hermes" });
}

test "Hermes install paths honor absolute HERMES_HOME" {
    var env_map = std.process.Environ.Map.init(std.testing.allocator);
    defer env_map.deinit();
    try env_map.put("HOME", "/Users/synthetic");
    try env_map.put("HERMES_HOME", "/Users/synthetic/.hermes/profiles/work");
    const root = try hermesHomeFromEnvMap(std.testing.allocator, &env_map);
    defer std.testing.allocator.free(root);
    try std.testing.expectEqualStrings("/Users/synthetic/.hermes/profiles/work", root);

    try env_map.put("HERMES_HOME", "relative/profile");
    const fallback = try hermesHomeFromEnvMap(std.testing.allocator, &env_map);
    defer std.testing.allocator.free(fallback);
    try std.testing.expectEqualStrings("/Users/synthetic/.hermes", fallback);
}

pub fn installFileIfSafe(allocator: std.mem.Allocator, source_path: []const u8, destination_path: []const u8) !bool {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    return plugin_install.installFileIfSafe(
        io,
        allocator,
        source_path,
        destination_path,
        false,
    );
}

fn installManagedFile(allocator: std.mem.Allocator, source_path: []const u8, destination_path: []const u8) !bool {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    return plugin_install.installFileIfSafe(
        io,
        allocator,
        source_path,
        destination_path,
        true,
    );
}

const OpenCodeManagedInstallError = error{
    OpenCodeManagedInstallFailed,
};

fn installOpenCodeManagedDestination(
    allocator: std.mem.Allocator,
    io: std.Io,
    stdout: anytype,
    source_path: []const u8,
    destination_path: []const u8,
) !void {
    const existed = fileExistsAbsolute(io, destination_path);
    const changed = installManagedFile(allocator, source_path, destination_path) catch |err| switch (err) {
        error.RefusingToOverwriteDifferentFile => {
            try stdout.print("  action: failed (destination exists and differs: {s})\n", .{destination_path});
            return error.OpenCodeManagedInstallFailed;
        },
        error.RefusingSymlinkPluginPath => {
            try stdout.print("  action: failed (refusing symlink destination: {s})\n", .{destination_path});
            return error.OpenCodeManagedInstallFailed;
        },
        error.NotDir => {
            try stdout.print("  action: failed (unsafe destination path: {s})\n", .{destination_path});
            return error.OpenCodeManagedInstallFailed;
        },
        else => return err,
    };
    if (changed) {
        if (existed) {
            try stdout.print("  action: upgraded {s}\n", .{destination_path});
        } else {
            try stdout.print("  action: installed to {s}\n", .{destination_path});
        }
    } else {
        try stdout.print("  action: already up-to-date at {s}\n", .{destination_path});
    }
}

fn sha256Hex(bytes: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

fn readHermesFile(io: std.Io, allocator: std.mem.Allocator, root: []const u8, name: []const u8) ?[]u8 {
    const path = std.fs.path.join(allocator, &.{ root, name }) catch return null;
    defer allocator.free(path);
    return std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(8 * 1024 * 1024)) catch null;
}

fn hermesRegularFileNoSymlink(io: std.Io, allocator: std.mem.Allocator, root: []const u8, name: []const u8) bool {
    const path = std.fs.path.join(allocator, &.{ root, name }) catch return false;
    defer allocator.free(path);
    const stat = std.Io.Dir.cwd().statFile(io, path, .{ .follow_symlinks = false }) catch return false;
    return stat.kind == .file;
}

fn receiptField(receipt: []const u8, key: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, receipt, '\n');
    if (!std.mem.eql(u8, std.mem.trim(u8, lines.next() orelse return null, "\r"), "ryk-hermes-managed-v1")) return null;
    var found: ?[]const u8 = null;
    while (lines.next()) |line| {
        const clean = std.mem.trim(u8, line, "\r");
        if (clean.len == 0) continue;
        if (std.mem.startsWith(u8, clean, key) and clean.len > key.len and clean[key.len] == '=') {
            if (found != null) return null;
            found = clean[key.len + 1 ..];
        }
    }
    return found;
}

fn hermesReceiptMatches(io: std.Io, allocator: std.mem.Allocator, plugin_dir: []const u8) bool {
    const canonical = std.Io.Dir.cwd().realPathFileAlloc(io, plugin_dir, allocator) catch return false;
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, plugin_dir)) return false;
    if (!hermesRegularFileNoSymlink(io, allocator, plugin_dir, hermes_managed_receipt_filename)) return false;
    const receipt = readHermesFile(io, allocator, plugin_dir, hermes_managed_receipt_filename) orelse return false;
    defer allocator.free(receipt);
    const path = receiptField(receipt, "path") orelse return false;
    if (!std.mem.eql(u8, path, canonical)) return false;
    const names = [_][]const u8{ "plugin.yaml", "__init__.py", "mapping.py" };
    for (names) |name| {
        if (!hermesRegularFileNoSymlink(io, allocator, plugin_dir, name)) return false;
        const expected_key = std.fmt.allocPrint(allocator, "{s}_sha256", .{name}) catch return false;
        defer allocator.free(expected_key);
        const expected = receiptField(receipt, expected_key) orelse return false;
        const bytes = readHermesFile(io, allocator, plugin_dir, name) orelse return false;
        defer allocator.free(bytes);
        const actual = sha256Hex(bytes);
        if (!std.mem.eql(u8, expected, &actual)) return false;
    }
    return true;
}

fn hermesPreflightMarkerMatches(io: std.Io, allocator: std.mem.Allocator, plugin_dir: []const u8) bool {
    const canonical = std.Io.Dir.cwd().realPathFileAlloc(io, plugin_dir, allocator) catch return false;
    defer allocator.free(canonical);
    const marker = readHermesFile(io, allocator, plugin_dir, hermes_unattended_marker_filename) orelse return false;
    defer allocator.free(marker);
    var expected: [std.fs.max_path_bytes + 64]u8 = undefined;
    const expected_text = std.fmt.bufPrint(&expected, "ryk-hermes-unattended-v1\npath={s}\n", .{canonical}) catch return false;
    if (!std.mem.eql(u8, marker, expected_text)) return false;

    // A preflight marker is only a capability for the empty activation
    // directory created by this setup transaction. It is not ownership proof
    // for a populated tree: a same-user writer must not be able to plant the
    // marker beside arbitrary Python and have setup overwrite it.
    var dir = std.Io.Dir.cwd().openDir(io, plugin_dir, .{ .iterate = true, .follow_symlinks = false }) catch return false;
    defer dir.close(io);
    var it = dir.iterate();
    while (it.next(io) catch return false) |entry| {
        if (entry.kind != .file) return false;
        if (!std.mem.eql(u8, entry.name, hermes_unattended_marker_filename) and
            !std.mem.eql(u8, entry.name, host_status.hermes_fail_stance_filename))
        {
            return false;
        }
    }
    return true;
}

fn hermesLegacyBundleMatches(io: std.Io, allocator: std.mem.Allocator, plugin_dir: []const u8) bool {
    const entries = [_]struct { name: []const u8, hash: []const u8 }{
        .{ .name = "plugin.yaml", .hash = hermes_legacy_manifest_sha256 },
        .{ .name = "__init__.py", .hash = hermes_legacy_source_sha256 },
        .{ .name = "mapping.py", .hash = hermes_legacy_mapping_sha256 },
    };
    for (entries) |entry| {
        if (!hermesRegularFileNoSymlink(io, allocator, plugin_dir, entry.name)) return false;
        const bytes = readHermesFile(io, allocator, plugin_dir, entry.name) orelse return false;
        defer allocator.free(bytes);
        const actual = sha256Hex(bytes);
        if (!std.mem.eql(u8, &actual, entry.hash)) return false;
    }
    return true;
}

fn installHermesBundleAtomically(
    io: std.Io,
    allocator: std.mem.Allocator,
    source_dir: []const u8,
    destination_dir: []const u8,
) !bool {
    if (!hermesManagedDestination(io, allocator, destination_dir)) return error.RefusingToOverwriteUnownedPlugin;

    const source_names = [_][]const u8{ "plugin.yaml", "__init__.py", "mapping.py" };
    var source_bytes: [3][]u8 = undefined;
    var loaded: usize = 0;
    defer for (source_bytes[0..loaded]) |bytes| allocator.free(bytes);
    for (source_names, 0..) |name, index| {
        const source_path = try std.fs.path.join(allocator, &.{ source_dir, name });
        defer allocator.free(source_path);
        source_bytes[index] = try std.Io.Dir.cwd().readFileAlloc(io, source_path, allocator, .limited(8 * 1024 * 1024));
        loaded += 1;
    }
    // Stale packaged trees may still ship `name: orca` while enable targets `ryk`.
    // Normalize identity before staging so enable + doctor installed evidence agree.
    {
        const normalized = try normalizeHermesManifestNameToRyk(allocator, source_bytes[0]);
        if (!std.mem.eql(u8, normalized, source_bytes[0])) {
            allocator.free(source_bytes[0]);
            source_bytes[0] = normalized;
        } else {
            allocator.free(normalized);
        }
    }

    const existing = dirExists(destination_dir);
    if (existing and hermesReceiptMatches(io, allocator, destination_dir)) {
        var current = true;
        for (source_names, 0..) |name, index| {
            const installed = readHermesFile(io, allocator, destination_dir, name) orelse {
                current = false;
                break;
            };
            defer allocator.free(installed);
            current = current and std.mem.eql(u8, installed, source_bytes[index]);
        }
        if (current) return false;
    }

    const parent = std.fs.path.dirname(destination_dir) orelse return error.InvalidPath;
    const stamp = std.Io.Clock.Timestamp.now(io, .awake).raw.nanoseconds;
    const stage = try std.fmt.allocPrint(allocator, "{s}/.ryk-hermes-stage-{d}", .{ parent, stamp });
    defer allocator.free(stage);
    try std.Io.Dir.cwd().createDirPath(io, stage);
    var stage_owned = true;
    defer if (stage_owned) std.Io.Dir.cwd().deleteTree(io, stage) catch {};

    for (source_names, 0..) |name, index| {
        const stage_path = try std.fs.path.join(allocator, &.{ stage, name });
        defer allocator.free(stage_path);
        _ = try plugin_install.installTextIfSafe(io, allocator, source_bytes[index], stage_path, false);
    }

    // destination_dir is an absolute path under the operator's home. It does
    // not exist during the first staged install, so its lexical path is the
    // canonical path we bind into the receipt; symlinked existing roots were
    // rejected by hermesReceiptMatches before upgrades reach this point.
    const canonical_destination = destination_dir;
    const manifest_hash = sha256Hex(source_bytes[0]);
    const source_hash = sha256Hex(source_bytes[1]);
    const mapping_hash = sha256Hex(source_bytes[2]);
    const receipt = try std.fmt.allocPrint(
        allocator,
        "ryk-hermes-managed-v1\npath={s}\nplugin.yaml_sha256={s}\n__init__.py_sha256={s}\nmapping.py_sha256={s}\n",
        .{ canonical_destination, &manifest_hash, &source_hash, &mapping_hash },
    );
    defer allocator.free(receipt);
    const receipt_path = try std.fs.path.join(allocator, &.{ stage, hermes_managed_receipt_filename });
    defer allocator.free(receipt_path);
    _ = try plugin_install.installTextIfSafe(io, allocator, receipt, receipt_path, false);

    const stage_stance_path = try std.fs.path.join(allocator, &.{ stage, host_status.hermes_fail_stance_filename });
    defer allocator.free(stage_stance_path);
    const stance_path = try std.fs.path.join(allocator, &.{ destination_dir, host_status.hermes_fail_stance_filename });
    defer allocator.free(stance_path);
    var stance_owned: ?[]u8 = null;
    const stance: []const u8 = if (std.Io.Dir.cwd().readFileAlloc(io, stance_path, allocator, .limited(8 * 1024))) |bytes| blk: {
        stance_owned = bytes;
        break :blk bytes;
    } else |_| "fail-closed\n# Managed by `ryk agents setup hermes`.\n";
    defer if (stance_owned) |bytes| allocator.free(bytes);
    _ = try plugin_install.installTextIfSafe(io, allocator, stance, stage_stance_path, false);

    const marker_path = try std.fs.path.join(allocator, &.{ destination_dir, hermes_unattended_marker_filename });
    defer allocator.free(marker_path);
    const stage_marker_path = try std.fs.path.join(allocator, &.{ stage, hermes_unattended_marker_filename });
    defer allocator.free(stage_marker_path);
    if (std.Io.Dir.cwd().access(io, marker_path, .{})) |_| {
        const marker = try std.Io.Dir.cwd().readFileAlloc(io, marker_path, allocator, .limited(8 * 1024));
        defer allocator.free(marker);
        _ = try plugin_install.installTextIfSafe(io, allocator, marker, stage_marker_path, false);
    } else |_| {}

    // Revalidate ownership after the complete replacement tree is staged and
    // immediately before any destination rename. This rejects a destination
    // that changed during source preparation instead of moving it to backup
    // based only on the initial preflight result.
    if (!hermesManagedDestination(io, allocator, destination_dir)) return error.RefusingToOverwriteUnownedPlugin;
    if (!existing and dirExists(destination_dir)) return error.HermesDestinationAppeared;

    if (!existing) {
        try std.Io.Dir.renameAbsolute(stage, destination_dir, io);
        stage_owned = false;
        return true;
    }

    const backup = try std.fmt.allocPrint(allocator, "{s}/.ryk-hermes-backup-{d}", .{ parent, stamp });
    defer allocator.free(backup);
    try std.Io.Dir.renameAbsolute(destination_dir, backup, io);
    errdefer std.Io.Dir.renameAbsolute(backup, destination_dir, io) catch {};
    try std.Io.Dir.renameAbsolute(stage, destination_dir, io);
    stage_owned = false;
    std.Io.Dir.cwd().deleteTree(io, backup) catch {};
    return true;
}

pub fn filesEqual(allocator: std.mem.Allocator, lhs_path: []const u8, rhs_path: []const u8) !bool {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const lhs = try std.Io.Dir.cwd().readFileAlloc(io, lhs_path, allocator, .limited(1024 * 1024));
    defer allocator.free(lhs);
    const rhs = try std.Io.Dir.cwd().readFileAlloc(io, rhs_path, allocator, .limited(1024 * 1024));
    defer allocator.free(rhs);
    return std.mem.eql(u8, lhs, rhs);
}

pub fn runOpenClawInstall(allocator: std.mem.Allocator, host_binary: []const u8, plugin_dir: []const u8) !u8 {
    // The source is the reviewed bundle shipped inside the curl-installed ryk
    // distribution. Current OpenClaw requires --force for non-interactive local
    // source confirmation and uses it to replace the same installed id safely.
    const argv = [_][]const u8{ host_binary, "plugins", "install", plugin_dir, "--force" };
    const result = try child_process.runHostCommandTimed(allocator, &argv, 10_000, null, null);
    defer child_process.deinitHostCommandResult(result, allocator);
    return if (result.timed_out) 255 else result.exit_code;
}

pub fn runOpenClawConfigureWorkspace(allocator: std.mem.Allocator, host_binary: []const u8, workspace_root: []const u8) !u8 {
    const argv = [_][]const u8{
        host_binary,
        "config",
        "set",
        "plugins.entries.ryk.config.workspaceRoot",
        workspace_root,
    };
    const result = try child_process.runHostCommandTimed(allocator, &argv, 10_000, null, null);
    defer child_process.deinitHostCommandResult(result, allocator);
    return if (result.timed_out) 255 else result.exit_code;
}

/// Read back the value written by the upstream OpenClaw config command. A
/// successful writer exit alone is not evidence that the binding persisted.
pub fn runOpenClawWorkspaceBindingMatches(allocator: std.mem.Allocator, host_binary: []const u8, workspace_root: []const u8) !bool {
    const argv = [_][]const u8{
        host_binary,
        "config",
        "get",
        "plugins.entries.ryk.config.workspaceRoot",
        "--json",
    };
    var result = try child_process.runHostCommandCaptureTimed(allocator, &argv, 10_000);
    defer result.deinit(allocator);
    if (result.timed_out or result.output_overflow or result.exit_code != 0) return false;
    const configured = parseOpenClawWorkspaceBinding(allocator, result.stdout) catch return false;
    defer allocator.free(configured);
    return openClawWorkspaceBindingMatches(workspace_root, configured);
}

pub fn openClawWorkspaceBindingMatches(expected_root: []const u8, configured_root: []const u8) bool {
    return std.fs.path.isAbsolute(expected_root) and
        std.fs.path.isAbsolute(configured_root) and
        std.mem.eql(u8, expected_root, configured_root);
}

pub fn parseOpenClawWorkspaceBinding(allocator: std.mem.Allocator, output: []const u8) ![]u8 {
    const text = std.mem.trim(u8, output, " \t\r\n");
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, text, .{});
    defer parsed.deinit();
    if (parsed.value != .string or !std.fs.path.isAbsolute(parsed.value.string)) return error.InvalidOpenClawWorkspaceBinding;
    return allocator.dupe(u8, parsed.value.string);
}

fn openClawInstalledRootFromInspection(allocator: std.mem.Allocator, output: []const u8) ![]u8 {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, std.mem.trim(u8, output, " \t\r\n"), .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidOpenClawInspection;
    const plugin_value = parsed.value.object.get("plugin") orelse return error.InvalidOpenClawInspection;
    if (plugin_value != .object) return error.InvalidOpenClawInspection;
    const root_value = plugin_value.object.get("rootDir") orelse return error.InvalidOpenClawInspection;
    if (root_value != .string or !std.fs.path.isAbsolute(root_value.string)) return error.InvalidOpenClawInspection;
    return allocator.dupe(u8, root_value.string);
}

fn openClawBundleReceiptField(receipt: []const u8, key: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, receipt, '\n');
    if (!std.mem.eql(u8, std.mem.trim(u8, lines.next() orelse return null, "\r"), "ryk-openclaw-managed-v1")) return null;
    var found: ?[]const u8 = null;
    while (lines.next()) |line| {
        const clean = std.mem.trim(u8, line, "\r");
        if (clean.len == 0) continue;
        if (std.mem.startsWith(u8, clean, key) and clean.len > key.len and clean[key.len] == '=') {
            if (found != null) return null;
            found = clean[key.len + 1 ..];
        }
    }
    return found;
}

fn openClawRegularFileNoSymlink(io: std.Io, allocator: std.mem.Allocator, root: []const u8, name: []const u8) bool {
    const path = std.fs.path.join(allocator, &.{ root, name }) catch return false;
    defer allocator.free(path);
    const stat = std.Io.Dir.cwd().statFile(io, path, .{ .follow_symlinks = false }) catch return false;
    return stat.kind == .file;
}

fn openClawInstalledRootMatches(
    io: std.Io,
    allocator: std.mem.Allocator,
    installed_root: []const u8,
    bundled_root: []const u8,
) bool {
    const canonical = std.Io.Dir.cwd().realPathFileAlloc(io, installed_root, allocator) catch return false;
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, installed_root)) return false;
    if (!openClawRegularFileNoSymlink(io, allocator, installed_root, openclaw_managed_receipt_filename)) return false;
    const receipt_path = std.fs.path.join(allocator, &.{ installed_root, openclaw_managed_receipt_filename }) catch return false;
    defer allocator.free(receipt_path);
    const receipt = std.Io.Dir.cwd().readFileAlloc(io, receipt_path, allocator, .limited(16 * 1024)) catch return false;
    defer allocator.free(receipt);
    const path = openClawBundleReceiptField(receipt, "path") orelse return false;
    if (!std.mem.eql(u8, path, canonical)) return false;
    for (openclaw_bundle_file_names) |name| {
        const expected_path = std.fs.path.join(allocator, &.{ bundled_root, name }) catch return false;
        defer allocator.free(expected_path);
        const installed_path = std.fs.path.join(allocator, &.{ installed_root, name }) catch return false;
        defer allocator.free(installed_path);
        if (!openClawRegularFileNoSymlink(io, allocator, bundled_root, name) or
            !openClawRegularFileNoSymlink(io, allocator, installed_root, name)) return false;
        const expected = std.Io.Dir.cwd().readFileAlloc(io, expected_path, allocator, .limited(16 * 1024 * 1024)) catch return false;
        defer allocator.free(expected);
        const installed = std.Io.Dir.cwd().readFileAlloc(io, installed_path, allocator, .limited(16 * 1024 * 1024)) catch return false;
        defer allocator.free(installed);
        const hash = sha256Hex(expected);
        const key = std.fmt.allocPrint(allocator, "{s}_sha256", .{name}) catch return false;
        defer allocator.free(key);
        const recorded = openClawBundleReceiptField(receipt, key) orelse return false;
        if (!std.mem.eql(u8, recorded, &hash) or !std.mem.eql(u8, expected, installed)) return false;
    }
    return true;
}

/// Write a Ryk-authored receipt after OpenClaw reports the actual installed
/// root. Health later compares the installed files with the reviewed bundle,
/// so a receipt containing hashes of modified host files cannot self-authorize.
pub fn writeOpenClawManagedReceipt(
    io: std.Io,
    allocator: std.mem.Allocator,
    host_binary: []const u8,
    bundled_root: []const u8,
) !void {
    const output = try captureChildOutputTimed(allocator, &.{ host_binary, "plugins", "inspect", "ryk", "--json" }, 10_000);
    defer allocator.free(output);
    const installed_root = try openClawInstalledRootFromInspection(allocator, output);
    defer allocator.free(installed_root);
    const canonical = try std.Io.Dir.cwd().realPathFileAlloc(io, installed_root, allocator);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, installed_root)) return error.RefusingSymlinkPluginPath;

    var hashes: [openclaw_bundle_file_names.len][64]u8 = undefined;
    for (openclaw_bundle_file_names, 0..) |name, index| {
        const path = try std.fs.path.join(allocator, &.{ bundled_root, name });
        defer allocator.free(path);
        const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(16 * 1024 * 1024));
        defer allocator.free(bytes);
        hashes[index] = sha256Hex(bytes);
    }
    const receipt = try std.fmt.allocPrint(
        allocator,
        "ryk-openclaw-managed-v1\npath={s}\nopenclaw.plugin.json_sha256={s}\npackage.json_sha256={s}\ndist/index.js_sha256={s}\ndist/index.d.ts_sha256={s}\n",
        .{ canonical, &hashes[0], &hashes[1], &hashes[2], &hashes[3] },
    );
    defer allocator.free(receipt);
    const receipt_path = try std.fs.path.join(allocator, &.{ installed_root, openclaw_managed_receipt_filename });
    defer allocator.free(receipt_path);
    _ = try plugin_install.installTextIfSafe(io, allocator, receipt, receipt_path, true);
}

pub fn openClawInstalledBundleMatches(
    io: std.Io,
    allocator: std.mem.Allocator,
    inspection: []const u8,
    bundled_root: []const u8,
) bool {
    const installed_root = openClawInstalledRootFromInspection(allocator, inspection) catch return false;
    defer allocator.free(installed_root);
    return openClawInstalledRootMatches(io, allocator, installed_root, bundled_root);
}

pub fn resolveOpenClawBundleRoot(io: std.Io, allocator: std.mem.Allocator) ![]u8 {
    return resolveBundledPath(io, allocator, "integrations/openclaw-plugin");
}

test "OpenClaw workspace binding accepts only the canonical configured root" {
    try std.testing.expect(openClawWorkspaceBindingMatches("/workspace/project", "/workspace/project"));
    try std.testing.expect(!openClawWorkspaceBindingMatches("/workspace/project", "/workspace/other"));
    try std.testing.expect(!openClawWorkspaceBindingMatches("/workspace/project", "project"));
}

test "OpenClaw workspace binding readback requires an absolute JSON string" {
    const binding = try parseOpenClawWorkspaceBinding(std.testing.allocator, "\"/workspace/project\"\n");
    defer std.testing.allocator.free(binding);
    try std.testing.expectEqualStrings("/workspace/project", binding);
    try std.testing.expectError(
        error.InvalidOpenClawWorkspaceBinding,
        parseOpenClawWorkspaceBinding(std.testing.allocator, "\"relative\"\n"),
    );
    try std.testing.expectError(
        error.InvalidOpenClawWorkspaceBinding,
        parseOpenClawWorkspaceBinding(std.testing.allocator, "null\n"),
    );
}

test "OpenClaw config binding is exact, idempotent, read-back verified, and failure propagates" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const script = try std.fs.path.join(std.testing.allocator, &.{ root, "openclaw" });
    defer std.testing.allocator.free(script);
    const script_body = "#!/bin/sh\n" ++
        "state=\"$(dirname \"$0\")/state\"\n" ++
        "if [ \"$1\" = config ] && [ \"$2\" = set ]; then printf '%s' \"$*\" > \"$(dirname \"$0\")/argv\"; printf '%s' \"$4\" > \"$state\"; exit 0; fi\n" ++
        "if [ \"$1\" = config ] && [ \"$2\" = get ]; then printf '\\\"%s\\\"\\n' \"$(cat \"$state\")\"; exit 0; fi\n" ++
        "exit 23\n";
    var file = try std.Io.Dir.cwd().createFile(std.testing.io, script, .{});
    try file.writeStreamingAll(std.testing.io, script_body);
    if (builtin.os.tag != .windows) try file.setPermissions(std.testing.io, .executable_file);
    file.close(std.testing.io);

    try std.testing.expectEqual(@as(u8, 0), try runOpenClawConfigureWorkspace(std.testing.allocator, script, root));
    try std.testing.expect(try runOpenClawWorkspaceBindingMatches(std.testing.allocator, script, root));
    const state_path = try std.fs.path.join(std.testing.allocator, &.{ root, "state" });
    defer std.testing.allocator.free(state_path);
    var state_file = try std.Io.Dir.cwd().createFile(std.testing.io, state_path, .{ .truncate = true });
    defer state_file.close(std.testing.io);
    try state_file.writeStreamingAll(std.testing.io, "/wrong/workspace");
    try std.testing.expect(!try runOpenClawWorkspaceBindingMatches(std.testing.allocator, script, root));
    const argv_path = try std.fs.path.join(std.testing.allocator, &.{ root, "argv" });
    defer std.testing.allocator.free(argv_path);
    const argv_log = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, argv_path, std.testing.allocator, .limited(1024));
    defer std.testing.allocator.free(argv_log);
    var expected_log_buf: [std.fs.max_path_bytes + 128]u8 = undefined;
    const expected_log = try std.fmt.bufPrint(&expected_log_buf, "config set plugins.entries.ryk.config.workspaceRoot {s}", .{root});
    try std.testing.expectEqualStrings(expected_log, argv_log);
    try std.testing.expectEqual(@as(u8, 0), try runOpenClawConfigureWorkspace(std.testing.allocator, script, root));
    try std.testing.expect(try runOpenClawWorkspaceBindingMatches(std.testing.allocator, script, root));

    const failing = try std.fs.path.join(std.testing.allocator, &.{ root, "openclaw-fail" });
    defer std.testing.allocator.free(failing);
    var failing_file = try std.Io.Dir.cwd().createFile(std.testing.io, failing, .{});
    try failing_file.writeStreamingAll(std.testing.io, "#!/bin/sh\nexit 23\n");
    if (builtin.os.tag != .windows) try failing_file.setPermissions(std.testing.io, .executable_file);
    failing_file.close(std.testing.io);
    try std.testing.expectEqual(@as(u8, 23), try runOpenClawConfigureWorkspace(std.testing.allocator, failing, root));
}

test "OpenClaw installed bundle requires an exact receipt-bound reviewed tree" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "bundled/dist");
    try tmp.dir.createDirPath(std.testing.io, "installed/dist");

    const data = [_][]const u8{
        "{\"id\":\"ryk\"}\n",
        "{\"name\":\"ryk\"}\n",
        "export const hook = true;\n",
        "export declare const hook: boolean;\n",
    };
    for (openclaw_bundle_file_names, 0..) |name, index| {
        const bundled_path = try std.fmt.allocPrint(std.testing.allocator, "bundled/{s}", .{name});
        defer std.testing.allocator.free(bundled_path);
        const installed_path = try std.fmt.allocPrint(std.testing.allocator, "installed/{s}", .{name});
        defer std.testing.allocator.free(installed_path);
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = bundled_path, .data = data[index] });
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = installed_path, .data = data[index] });
    }

    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const bundled = try std.fs.path.join(std.testing.allocator, &.{ root, "bundled" });
    defer std.testing.allocator.free(bundled);
    const installed = try std.fs.path.join(std.testing.allocator, &.{ root, "installed" });
    defer std.testing.allocator.free(installed);

    var hashes: [openclaw_bundle_file_names.len][64]u8 = undefined;
    for (data, 0..) |bytes, index| hashes[index] = sha256Hex(bytes);
    const receipt = try std.fmt.allocPrint(
        std.testing.allocator,
        "ryk-openclaw-managed-v1\npath={s}\nopenclaw.plugin.json_sha256={s}\npackage.json_sha256={s}\ndist/index.js_sha256={s}\ndist/index.d.ts_sha256={s}\n",
        .{ installed, &hashes[0], &hashes[1], &hashes[2], &hashes[3] },
    );
    defer std.testing.allocator.free(receipt);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "installed/.ryk-managed-openclaw-v1", .data = receipt });

    try std.testing.expect(openClawInstalledRootMatches(std.testing.io, std.testing.allocator, installed, bundled));
    try tmp.dir.deleteFile(std.testing.io, "installed/dist/index.js");
    try tmp.dir.symLink(std.testing.io, "../../bundled/dist/index.js", "installed/dist/index.js", .{});
    try std.testing.expect(!openClawInstalledRootMatches(std.testing.io, std.testing.allocator, installed, bundled));
    try tmp.dir.deleteFile(std.testing.io, "installed/dist/index.js");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "installed/dist/index.js", .data = "tampered\n" });
    try std.testing.expect(!openClawInstalledRootMatches(std.testing.io, std.testing.allocator, installed, bundled));
}

pub fn runHermesEnable(allocator: std.mem.Allocator, host_binary: []const u8) !u8 {
    const argv = [_][]const u8{ host_binary, "plugins", "enable", "ryk" };
    const result = try child_process.runHostCommandTimed(allocator, &argv, 10_000, null, null);
    defer child_process.deinitHostCommandResult(result, allocator);
    return if (result.timed_out) 255 else result.exit_code;
}

/// True when `~/.hermes/plugins/ryk/plugin.yaml` declares `name: ryk` (not stale `name: orca`).
pub fn hermesUserManifestNameIsRyk() bool {
    const allocator = std.heap.page_allocator;
    const root = hermesUserPluginRoot(allocator) catch return false;
    defer allocator.free(root);
    const manifest = std.fs.path.join(allocator, &.{ root, "plugin.yaml" }) catch return false;
    defer allocator.free(manifest);
    return hermesManifestDeclaresNameRyk(allocator, manifest);
}

/// Manifest identity check: requires `name: ryk` and rejects `name: orca`.
pub fn hermesManifestDeclaresNameRyk(allocator: std.mem.Allocator, manifest_path: []const u8) bool {
    if (!fileContains(allocator, manifest_path, "name: ryk")) return false;
    // Stale dual-name or pure orca packages are not installed-as-ryk.
    if (fileContains(allocator, manifest_path, "name: orca")) return false;
    return true;
}

/// Rewrite stale packaged/user `name: orca` manifest bytes to `name: ryk` before install.
/// Returns owned slice (may equal input when already ryk); caller frees when different from input.
pub fn normalizeHermesManifestNameToRyk(allocator: std.mem.Allocator, source: []const u8) ![]u8 {
    if (std.mem.indexOf(u8, source, "name: ryk") != null and std.mem.indexOf(u8, source, "name: orca") == null) {
        return try allocator.dupe(u8, source);
    }
    // Replace the YAML name field only (first occurrence of name: orca / missing name).
    if (std.mem.indexOf(u8, source, "name: orca")) |idx| {
        const before = source[0..idx];
        const after = source[idx + "name: orca".len ..];
        return try std.mem.concat(allocator, u8, &.{ before, "name: ryk", after });
    }
    // No name field: prefix with name: ryk for fail-closed identity.
    if (std.mem.indexOf(u8, source, "name:") == null) {
        return try std.mem.concat(allocator, u8, &.{ "name: ryk\n", source });
    }
    return try allocator.dupe(u8, source);
}

fn hermesManagedDestination(io: std.Io, allocator: std.mem.Allocator, plugin_dir: []const u8) bool {
    if (!dirExists(plugin_dir)) return true;
    const canonical = std.Io.Dir.cwd().realPathFileAlloc(io, plugin_dir, allocator) catch return false;
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, plugin_dir)) return false;
    return hermesReceiptMatches(io, allocator, plugin_dir) or
        hermesPreflightMarkerMatches(io, allocator, plugin_dir) or
        hermesLegacyBundleMatches(io, allocator, plugin_dir);
}

/// Write the unattended stance before the Hermes adapter is installed or
/// enabled. This closes the activation window where an inherited fail-open
/// override could otherwise win.
pub fn prepareHermesUnattendedInstall(io: std.Io, allocator: std.mem.Allocator) !void {
    const plugin_dir = try hermesUserPluginRoot(allocator);
    defer allocator.free(plugin_dir);
    if (!hermesManagedDestination(io, allocator, plugin_dir)) return error.RefusingToOverwriteUnownedPlugin;
    const stance_path = try std.fs.path.join(allocator, &.{ plugin_dir, host_status.hermes_fail_stance_filename });
    defer allocator.free(stance_path);
    _ = try plugin_install.installTextIfSafe(
        io,
        allocator,
        "fail-closed\n# Managed by `ryk agents setup hermes`; unattended marker overrides fail-open env.\n",
        stance_path,
        true,
    );
    const marker_path = try std.fs.path.join(allocator, &.{ plugin_dir, ".ryk_unattended" });
    defer allocator.free(marker_path);
    const canonical_plugin_dir = try std.Io.Dir.cwd().realPathFileAlloc(io, plugin_dir, allocator);
    defer allocator.free(canonical_plugin_dir);
    const marker = try std.fmt.allocPrint(
        allocator,
        "ryk-hermes-unattended-v1\npath={s}\n",
        .{canonical_plugin_dir},
    );
    defer allocator.free(marker);
    _ = try plugin_install.installTextIfSafe(
        io,
        allocator,
        marker,
        marker_path,
        true,
    );
}

fn runHermesDisableLegacy(allocator: std.mem.Allocator, host_binary: []const u8) !u8 {
    const argv = [_][]const u8{ host_binary, "plugins", "disable", "orca" };
    const result = try child_process.runHostCommandTimed(allocator, &argv, 10_000, null, null);
    defer child_process.deinitHostCommandResult(result, allocator);
    return if (result.timed_out) 255 else result.exit_code;
}

/// Persist the no-human stance after `ryk agents setup hermes`. This marker
/// outranks attended fail-open environment overrides in the Hermes adapter.
/// The exact legacy ryk-owned `orca` plugin is disabled to avoid two veto
/// callbacks with discovery-order-dependent behavior.
pub fn hardenHermesUnattendedInstall(io: std.Io, allocator: std.mem.Allocator) !void {
    try prepareHermesUnattendedInstall(io, allocator);
    const plugin_dir = try hermesUserPluginRoot(allocator);
    defer allocator.free(plugin_dir);

    const plugins_root = std.fs.path.dirname(plugin_dir) orelse return;
    const legacy_manifest = try std.fs.path.join(allocator, &.{ plugins_root, "orca", "plugin.yaml" });
    defer allocator.free(legacy_manifest);
    const legacy_is_ryk = fileContains(allocator, legacy_manifest, "name: orca") and
        fileContains(allocator, legacy_manifest, "ryk runtime guardrails");
    if (legacy_is_ryk) {
        const host_binary = try trustedHostBinary(io, allocator, "hermes");
        defer if (host_binary) |path| allocator.free(path);
        if (host_binary == null or try runHermesDisableLegacy(allocator, host_binary.?) != 0)
            return error.LegacyHermesDisableFailed;
    }
}

pub fn fileContains(allocator: std.mem.Allocator, path: []const u8, needle: []const u8) bool {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const content = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(1024 * 1024)) catch return false;
    defer allocator.free(content);
    return std.mem.indexOf(u8, content, needle) != null;
}

pub fn dirExists(path: []const u8) bool {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    var dir = std.Io.Dir.cwd().openDir(io, path, .{}) catch return false;
    defer dir.close(io);
    return true;
}

pub fn hasPath(root: []const u8, relative: []const u8) bool {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const allocator = std.heap.page_allocator;
    const path = std.fs.path.join(allocator, &.{ root, relative }) catch return false;
    defer allocator.free(path);
    return fileExistsAbsolute(io, path);
}

/// Walk a pre-resolved PATH string for `binary_name` (and `.exe` on Windows).
pub fn binaryOnSearchPath(io: std.Io, allocator: std.mem.Allocator, path_value: []const u8, binary_name: []const u8) bool {
    var parts = std.mem.splitScalar(u8, path_value, std.fs.path.delimiter);
    while (parts.next()) |dir| {
        if (dir.len == 0) continue;
        const candidate = std.fs.path.join(allocator, &.{ dir, binary_name }) catch continue;
        defer allocator.free(candidate);
        if (fileExistsAbsolute(io, candidate)) return true;
        if (builtin.os.tag == .windows) {
            const exe_candidate = std.fmt.allocPrint(allocator, "{s}.exe", .{candidate}) catch continue;
            defer allocator.free(exe_candidate);
            if (fileExistsAbsolute(io, exe_candidate)) return true;
        }
    }
    return false;
}

pub fn binaryInPath(io: std.Io, allocator: std.mem.Allocator, binary_name: []const u8) bool {
    var env_map = env_util.createProcessMap(allocator) catch return false;
    defer env_map.deinit();
    const path_owned = env_util.getOwned(&env_map, allocator, "PATH") catch return false;
    const path_value = path_owned orelse return false;
    defer allocator.free(path_value);
    return binaryOnSearchPath(io, allocator, path_value, binary_name);
}

fn pathIsWithin(root: []const u8, candidate: []const u8) bool {
    if (root.len == 0) return false;
    if (std.mem.eql(u8, root, candidate)) return true;
    if (!std.mem.startsWith(u8, candidate, root) or candidate.len <= root.len) return false;
    return candidate[root.len] == std.fs.path.sep;
}

/// Resolve a host executable once and pin health probes to its canonical path.
/// Workspace and temporary binaries are rejected, as are group/world-writable
/// executables, so a PATH-prepended self-reporting script cannot make health
/// claim that a host is ready.
pub fn resolveTrustedHostBinary(io: std.Io, allocator: std.mem.Allocator, binary_name: []const u8) !?[:0]u8 {
    var env_map = try env_util.createProcessMap(allocator);
    defer env_map.deinit();
    const path_owned = (try env_util.getOwned(&env_map, allocator, "PATH")) orelse return null;
    defer allocator.free(path_owned);
    const tmp_owned = try env_util.getOwned(&env_map, allocator, "TMPDIR");
    defer if (tmp_owned) |path| allocator.free(path);
    const home_owned = try env_util.getOwned(&env_map, allocator, "HOME");
    defer if (home_owned) |path| allocator.free(path);
    const cwd = try std.Io.Dir.cwd().realPathFileAlloc(io, ".", allocator);
    defer allocator.free(cwd);

    return resolveTrustedHostBinaryOnSearchPath(io, allocator, path_owned, binary_name, cwd, tmp_owned, home_owned);
}

fn versionTupleAtLeast(actual: [3]u32, minimum: [3]u32) bool {
    for (actual, minimum) |a, b| {
        if (a != b) return a > b;
    }
    return true;
}

fn parseThreePartVersion(output: []const u8, prefix: []const u8) ?[3]u32 {
    const start = (std.mem.indexOf(u8, output, prefix) orelse return null) + prefix.len;
    const tail = output[start..];
    const end = std.mem.indexOfAny(u8, tail, " \t\r\n") orelse tail.len;
    var parts = std.mem.splitScalar(u8, tail[0..end], '.');
    var version: [3]u32 = undefined;
    for (&version) |*part| part.* = std.fmt.parseInt(u32, parts.next() orelse return null, 10) catch return null;
    if (parts.next() != null) return null;
    return version;
}

pub fn hostBinaryIdentityMatchesTimed(allocator: std.mem.Allocator, host: []const u8, binary: []const u8, timeout_ms: u32) bool {
    // Prefer join-parent so agents-health nested probes stay in the worker's
    // process group (outer SIGKILL cannot orphan host --version CLIs). Fall
    // back to a private group only when join-parent is unavailable (Windows).
    var result = if (comptime builtin.os.tag == .windows)
        child_process.runHostCommandCaptureTimed(allocator, &.{ binary, "--version" }, timeout_ms) catch return false
    else
        child_process.runHostCommandCaptureTimedInCurrentProcessGroup(allocator, &.{ binary, "--version" }, timeout_ms) catch return false;
    defer result.deinit(allocator);
    if (result.timed_out or result.output_overflow or result.exit_code != 0) return false;
    if (std.mem.eql(u8, host, "openclaw")) {
        const version = parseThreePartVersion(result.stdout, "OpenClaw ") orelse return false;
        return versionTupleAtLeast(version, .{ 2026, 8, 1 });
    }
    if (std.mem.eql(u8, host, "hermes")) {
        const version = parseThreePartVersion(result.stdout, "Hermes Agent v") orelse return false;
        return versionTupleAtLeast(version, .{ 0, 19, 1 });
    }
    return false;
}

pub fn hostBinaryIdentityMatches(allocator: std.mem.Allocator, host: []const u8, binary: []const u8) bool {
    return hostBinaryIdentityMatchesTimed(allocator, host, binary, 3_000);
}

pub fn trustedHostBinary(io: std.Io, allocator: std.mem.Allocator, host: []const u8) !?[:0]u8 {
    return trustedHostBinaryTimed(io, allocator, host, 3_000);
}

pub fn trustedHostBinaryTimed(io: std.Io, allocator: std.mem.Allocator, host: []const u8, timeout_ms: u32) !?[:0]u8 {
    const binary = try resolveTrustedHostBinary(io, allocator, host) orelse return null;
    if (!hostBinaryIdentityMatchesTimed(allocator, host, binary, timeout_ms)) {
        allocator.free(binary);
        return null;
    }
    return binary;
}

fn trustedHostInstallLocation(allocator: std.mem.Allocator, host: []const u8, canonical: []const u8, home: ?[]const u8) bool {
    const system_roots = [_][]const u8{
        "/bin",
        "/usr/bin",
        "/usr/local/bin",
        "/opt/homebrew/bin",
        "/usr/lib/node_modules/openclaw",
        "/usr/local/lib/node_modules/openclaw",
        "/opt/homebrew/lib/node_modules/openclaw",
    };
    for (system_roots) |root| {
        if (pathIsWithin(root, canonical)) return true;
    }
    const home_path = home orelse return false;
    // OpenClaw official git/installer layouts land the CLI wrapper in
    // ~/.local/bin and the package under ~/.local/src/openclaw. Hermes already
    // trusted ~/.local/bin; keep OpenClaw on the same managed PATH root plus
    // legacy npm-global trees.
    const relative_roots: []const []const u8 = if (std.mem.eql(u8, host, "hermes"))
        &.{ ".local/bin", ".hermes/hermes-agent/venv/bin" }
    else if (std.mem.eql(u8, host, "openclaw"))
        &.{
            ".local/bin",
            ".local/src/openclaw",
            ".local/lib/node_modules/openclaw",
            ".npm-global/lib/node_modules/openclaw",
        }
    else
        &.{};
    for (relative_roots) |relative| {
        const root = std.fs.path.join(allocator, &.{ home_path, relative }) catch continue;
        defer allocator.free(root);
        if (pathIsWithin(root, canonical)) return true;
    }
    return false;
}

fn resolveTrustedHostBinaryOnSearchPath(
    io: std.Io,
    allocator: std.mem.Allocator,
    path_value: []const u8,
    binary_name: []const u8,
    cwd: []const u8,
    tmp_root: ?[]const u8,
    home: ?[]const u8,
) !?[:0]u8 {
    var parts = std.mem.splitScalar(u8, path_value, std.fs.path.delimiter);
    while (parts.next()) |dir| {
        if (dir.len == 0) continue;
        const suffixes: []const []const u8 = if (builtin.os.tag == .windows) &.{ "", ".exe" } else &.{""};
        for (suffixes) |suffix| {
            const name = try std.fmt.allocPrint(allocator, "{s}{s}", .{ binary_name, suffix });
            defer allocator.free(name);
            const candidate = try std.fs.path.join(allocator, &.{ dir, name });
            defer allocator.free(candidate);
            const canonical = std.Io.Dir.cwd().realPathFileAlloc(io, candidate, allocator) catch continue;
            errdefer allocator.free(canonical);
            const stat = std.Io.Dir.cwd().statFile(io, canonical, .{}) catch {
                allocator.free(canonical);
                continue;
            };
            if (stat.kind != .file or pathIsWithin(cwd, canonical) or
                pathIsWithin("/tmp", canonical) or pathIsWithin("/private/tmp", canonical) or
                (tmp_root != null and pathIsWithin(std.mem.trimEnd(u8, tmp_root.?, "/"), canonical)) or
                !trustedHostInstallLocation(allocator, binary_name, canonical, home))
            {
                allocator.free(canonical);
                continue;
            }
            if (builtin.os.tag != .windows) {
                const mode = stat.permissions.toMode();
                if ((mode & 0o111) == 0 or (mode & 0o022) != 0) {
                    allocator.free(canonical);
                    continue;
                }
                if (daemon_trust.assessEnvOverridePath(io, allocator, canonical) != .trusted) {
                    allocator.free(canonical);
                    continue;
                }
            }
            return canonical;
        }
    }
    return null;
}

pub fn writeJsonString(writer: anytype, value: []const u8) !void {
    try writer.writeByte('"');
    for (value) |byte| {
        switch (byte) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            0...8, 11...12, 14...0x1f => try writer.print("\\u{x:0>4}", .{byte}),
            else => try writer.writeByte(byte),
        }
    }
    try writer.writeByte('"');
}

// ---------------------------------------------------------------------------
// Smoke test
// ---------------------------------------------------------------------------

pub const SmokeResult = struct {
    passed: bool,
};

pub fn smokeTestHook(allocator: std.mem.Allocator, host: []const u8, event: []const u8, fixture_path: []const u8, expected_decision: []const u8) !SmokeResult {
    var threaded = std.Io.Threaded.init(allocator, .{
        .environ = env_util.processEnviron(),
    });
    defer threaded.deinit();
    const io = threaded.io();
    const self_exe = try std.process.executablePathAlloc(io, allocator);
    defer allocator.free(self_exe);
    const argv = host_status.hookSmokeArgv(self_exe, host, event);

    // This is an internal health probe, not a user hook invocation. Keep its
    // child process out of product telemetry so machine-readable doctor runs
    // remain observational and do not manufacture enforcement/session events.
    const previous_no_telemetry = if (std.c.getenv("RYK_NO_TELEMETRY")) |value|
        try allocator.dupeZ(u8, std.mem.span(value))
    else
        null;
    defer {
        if (previous_no_telemetry) |value| {
            _ = setProcessEnv("RYK_NO_TELEMETRY", value.ptr);
            allocator.free(value);
        } else {
            _ = setProcessEnv("RYK_NO_TELEMETRY", null);
        }
    }
    if (!setProcessEnv("RYK_NO_TELEMETRY", "1")) return error.TelemetryIsolationUnavailable;

    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, fixture_path, allocator, .limited(256 * 1024));
    defer allocator.free(fixture);
    const result = try child_process.runHostCommandInputCaptureTimed(
        allocator,
        &argv,
        fixture,
        10_000,
    );
    defer result.deinit(allocator);
    const passed = !result.timed_out and host_status.interpretSmokeOutcome(
        host,
        expected_decision,
        result.exit_code,
        result.stdout,
        result.stderr,
    );
    return .{ .passed = passed };
}

// ---------------------------------------------------------------------------
// Hermes enable helper
// ---------------------------------------------------------------------------

fn writeHermesEnableHelper(allocator: std.mem.Allocator, plugin_dir: []const u8) !void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    // Guard: hermesUserPluginRoot can return a path with literal ~ if HOME is unset
    const resolved_dir = if (std.mem.startsWith(u8, plugin_dir, "~/")) blk: {
        var env_map = env_util.createProcessMap(allocator) catch return;
        defer env_map.deinit();
        const home = env_util.getOwnedHome(&env_map, allocator) catch return;
        const home_owned = home orelse return;
        defer allocator.free(home_owned);
        break :blk try std.fs.path.join(allocator, &.{ home_owned, plugin_dir[2..] });
    } else try allocator.dupe(u8, plugin_dir);
    defer allocator.free(resolved_dir);

    const help_path = try std.fs.path.join(allocator, &.{ resolved_dir, "ENABLE.txt" });
    defer allocator.free(help_path);
    _ = try plugin_install.installTextIfSafe(
        io,
        allocator,
        "ryk plugin files are installed.\nTo enable, run:\n  hermes plugins enable ryk\n",
        help_path,
        true,
    );
}

/// New Hermes installs: write fail-closed stance next to the plugin (hybrid L4).
/// Env `RYK_HERMES_FAIL_OPEN` overrides this file.
fn writeHermesFailClosedStance(allocator: std.mem.Allocator, plugin_dir: []const u8) !void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const resolved_dir = if (std.mem.startsWith(u8, plugin_dir, "~/")) blk: {
        var env_map = env_util.createProcessMap(allocator) catch return;
        defer env_map.deinit();
        const home = env_util.getOwnedHome(&env_map, allocator) catch return;
        const home_owned = home orelse return;
        defer allocator.free(home_owned);
        break :blk try std.fs.path.join(allocator, &.{ home_owned, plugin_dir[2..] });
    } else try allocator.dupe(u8, plugin_dir);
    defer allocator.free(resolved_dir);

    const stance_path = try std.fs.path.join(allocator, &.{ resolved_dir, host_status.hermes_fail_stance_filename });
    defer allocator.free(stance_path);
    _ = try plugin_install.installTextIfSafe(
        io,
        allocator,
        \\fail-closed
        \\# Written by `ryk plugin install hermes` for new installs.
        \\# Env RYK_HERMES_FAIL_OPEN overrides this file (0=fail-closed, 1=fail-open).
        \\# Easy full protection: ryk run -- hermes
        \\
    ,
        stance_path,
        false,
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "plugin command help and invalid subcommands are stable" {
    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const help_code = try command(std.testing.io, &.{"--help"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, help_code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "plugin") != null);

    stdout_writer = .fixed(&stdout_buf);
    stderr_writer = .fixed(&stderr_buf);
    const bad_code = try command(std.testing.io, &.{"unknown"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, bad_code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "unknown subcommand") != null);
}

test "Hermes manifest name: orca normalizes to name: ryk" {
    const allocator = std.testing.allocator;
    const orca = "name: orca\nversion: 1.2.9\ndescription: ryk runtime guardrails for Hermes Agent.\n";
    const normalized = try normalizeHermesManifestNameToRyk(allocator, orca);
    defer allocator.free(normalized);
    try std.testing.expect(std.mem.indexOf(u8, normalized, "name: ryk") != null);
    try std.testing.expect(std.mem.indexOf(u8, normalized, "name: orca") == null);

    const already = try normalizeHermesManifestNameToRyk(allocator, "name: ryk\nversion: 1\n");
    defer allocator.free(already);
    try std.testing.expectEqualStrings("name: ryk\nversion: 1\n", already);
}

test "Hermes manifest declares name ryk rejects orca identity" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "orca.yaml", .data = "name: orca\nversion: 1\n" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "ryk.yaml", .data = "name: ryk\nversion: 1\n" });
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const orca_path = try std.fs.path.join(std.testing.allocator, &.{ root, "orca.yaml" });
    defer std.testing.allocator.free(orca_path);
    const ryk_path = try std.fs.path.join(std.testing.allocator, &.{ root, "ryk.yaml" });
    defer std.testing.allocator.free(ryk_path);
    try std.testing.expect(!hermesManifestDeclaresNameRyk(std.testing.allocator, orca_path));
    try std.testing.expect(hermesManifestDeclaresNameRyk(std.testing.allocator, ryk_path));
}

test "Hermes bundle install rewrites stale name: orca source to name: ryk" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "source");
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "source/plugin.yaml",
        .data = "name: orca\nversion: 1\ndescription: ryk runtime guardrails for Hermes Agent.\n",
    });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "source/__init__.py", .data = "source-v1\n" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "source/mapping.py", .data = "mapping-v1\n" });

    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const source = try std.fs.path.join(std.testing.allocator, &.{ root, "source" });
    defer std.testing.allocator.free(source);
    const destination = try std.fs.path.join(std.testing.allocator, &.{ root, "installed" });
    defer std.testing.allocator.free(destination);

    try std.testing.expect(try installHermesBundleAtomically(std.testing.io, std.testing.allocator, source, destination));
    const installed = try tmp.dir.readFileAlloc(std.testing.io, "installed/plugin.yaml", std.testing.allocator, .limited(1024));
    defer std.testing.allocator.free(installed);
    try std.testing.expect(std.mem.indexOf(u8, installed, "name: ryk") != null);
    try std.testing.expect(std.mem.indexOf(u8, installed, "name: orca") == null);
    const installed_manifest = try std.fs.path.join(std.testing.allocator, &.{ destination, "plugin.yaml" });
    defer std.testing.allocator.free(installed_manifest);
    try std.testing.expect(hermesManifestDeclaresNameRyk(std.testing.allocator, installed_manifest));
}

test "hostPluginInstalledFromReport hermes requires name: ryk not config substring alone" {
    // Files + config alone with orca identity must not count as installed.
    try std.testing.expect(!hermesManifestDeclaresNameRyk(std.testing.allocator, "/nonexistent/plugin.yaml"));

    // Report predicate uses only report fields (no live re-read) so JSON consumers match.
    var paths_stale = HermesPaths{
        .repo_manifest_exists = true,
        .repo_source_exists = true,
        .repo_mapping_exists = true,
        .user_manifest_exists = true,
        .user_source_exists = true,
        .user_mapping_exists = true,
        .config_references_plugin = true,
        .user_manifest_name_is_ryk = false,
    };
    const report_stale = PluginDoctorReport{
        .ryk_version = "test",
        .ryk_binary_path = null,
        .cwd = try std.testing.allocator.dupeZ(u8, "."),
        .workspace_root = try std.testing.allocator.dupe(u8, "."),
        .policy_present = false,
        .policy_valid = false,
        .policy_error = null,
        .audit_replay_available = false,
        .mcp_support_status = "test",
        .plugin_directories = .{ .codex = false, .claude = false, .opencode = false, .openclaw = false, .hermes = true, .common = false },
        .host_binaries = .{ .codex = false, .claude = false, .opencode = false, .openclaw = false, .hermes = true },
        .opencode_paths = .{ .project_plugin_exists = false, .global_plugin_exists = false, .config_references_plugin = false },
        .openclaw_paths = .{
            .host_plugin_installed = false,
            .plugin_manifest_exists = false,
            .package_json_exists = false,
            .source_exists = false,
            .detection_note = "test",
        },
        .hermes_paths = paths_stale,
        .hermes_hook_smoke_passed = false,
        .marketplace = .{
            .codex_marketplace = false,
            .claude_marketplace = false,
            .codex_plugin_manifest = false,
            .claude_plugin_manifest = false,
            .codex_user_plugin = false,
            .claude_user_plugin = false,
        },
        .platform_summary = "test",
        .warnings = &.{},
    };
    defer {
        std.testing.allocator.free(report_stale.cwd);
        std.testing.allocator.free(report_stale.workspace_root);
    }
    try std.testing.expect(!hostPluginInstalledFromReport("hermes", report_stale));

    paths_stale.user_manifest_name_is_ryk = true;
    var report_ok = report_stale;
    report_ok.hermes_paths = paths_stale;
    try std.testing.expect(hostPluginInstalledFromReport("hermes", report_ok));

    // JSON path must require the same identity flag.
    const json_stale =
        \\{"hermes_paths":{"user_manifest_exists":true,"user_source_exists":true,"user_mapping_exists":true,"config_references_plugin":true,"user_manifest_name_is_ryk":false}}
    ;
    var parsed_stale = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json_stale, .{});
    defer parsed_stale.deinit();
    try std.testing.expect(!hostPluginInstalledFromDoctorJson("hermes", parsed_stale.value));

    const json_ok =
        \\{"hermes_paths":{"user_manifest_exists":true,"user_source_exists":true,"user_mapping_exists":true,"config_references_plugin":true,"user_manifest_name_is_ryk":true}}
    ;
    var parsed_ok = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json_ok, .{});
    defer parsed_ok.deinit();
    try std.testing.expect(hostPluginInstalledFromDoctorJson("hermes", parsed_ok.value));
}

test "classifyHostInstallOutcome enable failure stays failed when installed_after false" {
    try std.testing.expectEqual(HostInstallOutcome.failed, classifyHostInstallOutcome(1, false));
    try std.testing.expectEqual(HostInstallOutcome.installed_after_child_failure, classifyHostInstallOutcome(1, true));
    try std.testing.expectEqual(HostInstallOutcome.installed, classifyHostInstallOutcome(0, true));
}

test "plugin commands reject the retired hermess target spelling" {
    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [1024]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const doctor_code = try command(std.testing.io, &.{ "doctor", "hermess" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, doctor_code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "hermess") != null);

    stdout_writer = .fixed(&stdout_buf);
    stderr_writer = .fixed(&stderr_buf);
    const manifest_code = try command(std.testing.io, &.{ "manifest", "hermess" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, manifest_code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "hermess") != null);

    stdout_writer = .fixed(&stdout_buf);
    stderr_writer = .fixed(&stderr_buf);
    const install_code = try command(std.testing.io, &.{ "install", "hermess", "--dry-run" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, install_code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "hermess") != null);
}

test "plugin doctor prints expected sections" {
    var stdout_buf: [32768]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try doctorCommand(std.testing.io, &.{}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "ryk Plugin Doctor") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "ryk version:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Policy:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Host status:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "SMOKE ALLOW") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "pi") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "ryk run -- pi") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "pi …") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Plugin directories:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "/6 found") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "integrations/common:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Host binaries:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Platform:") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "host install outcome trusts refreshed doctor state over child exit" {
    try std.testing.expectEqual(HostInstallOutcome.installed, classifyHostInstallOutcome(0, true));
    try std.testing.expectEqual(HostInstallOutcome.installed_after_child_failure, classifyHostInstallOutcome(17, true));
    try std.testing.expectEqual(HostInstallOutcome.failed, classifyHostInstallOutcome(0, false));
    try std.testing.expectEqual(HostInstallOutcome.failed, classifyHostInstallOutcome(17, false));
}

/// Owned-field graph that mirrors `PluginDoctorReport` ownership (cwd, paths,
/// warnings, binary path, policy_error) without full FS/PATH/doctor discovery.
///
/// Full `collectPluginDoctorReportWithHermesSmoke` must **not** be wrapped in
/// `checkAllAllocationFailures`: that re-runs PATH/env/FS work once per alloc
/// site and freezes `test-lib` for minutes with no progress output (false hang).
fn pluginDoctorReportOwnedFieldsHarness(allocator: std.mem.Allocator) !void {
    const cwd = try allocator.dupeZ(u8, ".");
    errdefer allocator.free(cwd);
    const workspace_root = try allocator.dupe(u8, ".");
    errdefer allocator.free(workspace_root);
    const mcp_support_status = try allocator.dupe(u8, "stdio proxy active; HTTP transport deferred");
    errdefer allocator.free(mcp_support_status);
    const platform_summary = try allocator.dupe(u8, "test-os / none / none");
    errdefer allocator.free(platform_summary);
    const policy_error = try allocator.dupe(u8, "sample-policy-error");
    errdefer allocator.free(policy_error);
    const binary_path = try allocator.dupeZ(u8, "/tmp/ryk-test-bin");
    errdefer allocator.free(binary_path);

    var warnings: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (warnings.items) |w| allocator.free(w);
        warnings.deinit(allocator);
    }
    try appendWarning(allocator, &warnings, "first warning");
    try appendWarning(allocator, &warnings, "second warning");
    const warning_items = try warnings.toOwnedSlice(allocator);

    var report: PluginDoctorReport = .{
        .ryk_version = "test",
        .ryk_binary_path = binary_path,
        .cwd = cwd,
        .workspace_root = workspace_root,
        .policy_present = true,
        .policy_valid = false,
        .policy_error = policy_error,
        .audit_replay_available = false,
        .mcp_support_status = mcp_support_status,
        .plugin_directories = .{ .codex = true, .claude = true, .opencode = true, .openclaw = true, .hermes = true, .common = true },
        .host_binaries = .{ .codex = false, .claude = false, .opencode = false, .openclaw = false, .hermes = false },
        .opencode_paths = .{ .project_plugin_exists = false, .global_plugin_exists = false, .config_references_plugin = false },
        .openclaw_paths = .{
            .host_plugin_installed = false,
            .plugin_manifest_exists = false,
            .package_json_exists = false,
            .source_exists = false,
            .detection_note = "test",
        },
        .hermes_paths = .{
            .repo_manifest_exists = false,
            .repo_source_exists = false,
            .repo_mapping_exists = false,
            .user_manifest_exists = false,
            .user_source_exists = false,
            .user_mapping_exists = false,
            .config_references_plugin = false,
            .user_manifest_name_is_ryk = false,
        },
        .hermes_hook_smoke_passed = true,
        .marketplace = .{
            .codex_marketplace = false,
            .claude_marketplace = false,
            .codex_plugin_manifest = true,
            .claude_plugin_manifest = true,
            .codex_user_plugin = false,
            .claude_user_plugin = false,
        },
        .platform_summary = platform_summary,
        .warnings = warning_items,
    };
    defer deinitPluginDoctorReport(&report, allocator);
}

test "plugin doctor report cleans up allocation failure paths" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, pluginDoctorReportOwnedFieldsHarness, .{});
}

test "binaryOnSearchPath finds names on a synthetic PATH" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    const allocator = std.testing.allocator;

    const dir_path = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(dir_path);

    // Empty dir → miss.
    try std.testing.expect(!binaryOnSearchPath(io, allocator, dir_path, "ryk-not-present-xyz"));

    // Create a file that looks like a binary entry.
    try tmp.dir.writeFile(io, .{ .sub_path = "fake-host-bin", .data = "x" });
    try std.testing.expect(binaryOnSearchPath(io, allocator, dir_path, "fake-host-bin"));
}

test "trusted host resolution rejects a temporary self-reporting binary" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    try tmp.dir.writeFile(io, .{ .sub_path = "openclaw", .data = "#!/bin/sh\nexit 0\n" });
    const tmp_path = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(tmp_path);
    const fake_path = try std.fs.path.join(allocator, &.{ tmp_path, "openclaw" });
    defer allocator.free(fake_path);
    const fake_path_z = try allocator.dupeZ(u8, fake_path);
    defer allocator.free(fake_path_z);
    if (std.c.chmod(fake_path_z.ptr, 0o755) != 0) return error.SkipZigTest;

    const resolved = try resolveTrustedHostBinaryOnSearchPath(
        io,
        allocator,
        tmp_path,
        "openclaw",
        "/workspace",
        tmp_path,
        "/home/test",
    );
    defer if (resolved) |path| allocator.free(path);
    try std.testing.expect(resolved == null);
}

test "trusted host resolver preserves canonical path allocation ownership" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const resolved = try resolveTrustedHostBinary(std.testing.io, std.testing.allocator, "sh");
    defer if (resolved) |path| std.testing.allocator.free(path);
    try std.testing.expect(resolved != null);
    try std.testing.expect(std.fs.path.isAbsolute(resolved.?));
}

test "trusted host version parsing enforces the verified OpenClaw floor" {
    try std.testing.expectEqual([3]u32{ 2026, 8, 1 }, parseThreePartVersion("OpenClaw 2026.8.1 (abc)", "OpenClaw ").?);
    try std.testing.expect(versionTupleAtLeast(.{ 2026, 8, 1 }, .{ 2026, 8, 1 }));
    try std.testing.expect(versionTupleAtLeast(.{ 2026, 9, 0 }, .{ 2026, 8, 1 }));
    try std.testing.expect(!versionTupleAtLeast(.{ 2026, 3, 13 }, .{ 2026, 8, 1 }));
    try std.testing.expect(parseThreePartVersion("not OpenClaw", "OpenClaw ") == null);
    try std.testing.expect(versionTupleAtLeast(parseThreePartVersion("Hermes Agent v0.19.1", "Hermes Agent v").?, .{ 0, 19, 1 }));
    try std.testing.expect(!versionTupleAtLeast(parseThreePartVersion("Hermes Agent v0.19.0", "Hermes Agent v").?, .{ 0, 19, 1 }));
}

test "trusted host locations reject arbitrary home PATH entries" {
    try std.testing.expect(!trustedHostInstallLocation(std.testing.allocator, "openclaw", "/home/test/fake-bin/openclaw", "/home/test"));
    try std.testing.expect(trustedHostInstallLocation(std.testing.allocator, "hermes", "/home/test/.local/bin/hermes", "/home/test"));
    try std.testing.expect(trustedHostInstallLocation(std.testing.allocator, "openclaw", "/opt/homebrew/lib/node_modules/openclaw/openclaw.mjs", "/home/test"));
    // Official git/installer OpenClaw: wrapper in ~/.local/bin and package under ~/.local/src/openclaw.
    try std.testing.expect(trustedHostInstallLocation(std.testing.allocator, "openclaw", "/home/test/.local/bin/openclaw", "/home/test"));
    try std.testing.expect(trustedHostInstallLocation(std.testing.allocator, "openclaw", "/home/test/.local/src/openclaw/dist/entry.js", "/home/test"));
}

test "plugin doctor --json emits valid JSON" {
    var stdout_buf: [16384]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try doctorCommand(std.testing.io, &.{"--json"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);

    const json = stdout_writer.buffered();
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json, .{});
    defer parsed.deinit();

    try std.testing.expect(parsed.value.object.get("ryk_version") != null);
    try std.testing.expect(parsed.value.object.get("policy") != null);
    try std.testing.expect(parsed.value.object.get("plugin_directories") != null);
    try std.testing.expect(parsed.value.object.get("host_binaries") != null);
    try std.testing.expect(parsed.value.object.get("hermes_paths") != null);
    try std.testing.expect(parsed.value.object.get("hermes_hook_smoke_passed") != null);
    try std.testing.expect(parsed.value.object.get("hermes_hook_smoke_passed").? == .bool);
    try std.testing.expect(parsed.value.object.get("warnings") != null);
    try std.testing.expect(std.mem.indexOfScalar(u8, json, 0x1b) == null);
    try std.testing.expect(std.mem.indexOf(u8, json, "ryk Plugin Doctor") == null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "plugin doctor codex shows codex-specific section" {
    var stdout_buf: [16384]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try doctorCommand(std.testing.io, &.{"codex"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "Codex plugin status:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "host binary:") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "plugin doctor claude shows claude-specific section" {
    var stdout_buf: [16384]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try doctorCommand(std.testing.io, &.{"claude"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "Claude Code plugin status:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "host binary:") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "plugin doctor opencode shows opencode-specific section" {
    var stdout_buf: [16384]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try doctorCommand(std.testing.io, &.{"opencode"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "OpenCode plugin status:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "host binary:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "project plugin path") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "global plugin path") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "plugin doctor openclaw shows openclaw-specific section" {
    var stdout_buf: [16384]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try doctorCommand(std.testing.io, &.{"openclaw"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "OpenClaw plugin status:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "host binary:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "plugin manifest") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "package.json") != null);
    // Invariant tokens (not full marketing slogans).
    try std.testing.expect(std.mem.indexOf(u8, output, "unprotected") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, openclaw_status.preferred_wrapper) != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "installed != protected") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "plugin doctor openclaw --json includes sunset registry note" {
    var stdout_buf: [32768]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try doctorCommand(std.testing.io, &.{ "openclaw", "--json" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "\"enforcement_note\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "sunset") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"hook_grade\": \"unverified\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"npm_path\": \"sunset\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "hook_enforcing") == null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "plugin doctor hermes shows hermes-specific section" {
    var stdout_buf: [32768]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try doctorCommand(std.testing.io, &.{"hermes"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "Hermes plugin status:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "repo plugin.yaml") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "~/.hermes/plugins/ryk/plugin.yaml") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "hook smoke test (pre_tool_call allow):") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "fail stance:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Host status:") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "plugin doctor does not print recognizable raw credential prefixes" {
    var stdout_buf: [16384]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try doctorCommand(std.testing.io, &.{"--json"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);

    const output = stdout_writer.buffered();
    // `cwd` is intentionally diagnostic output and can legitimately include words such
    // as "secretless". Check credential prefixes rather than treating a path component
    // as evidence of a raw secret leak.
    try std.testing.expect(std.mem.indexOf(u8, output, "ghp_") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "sk-") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "password") == null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "plugin manifest codex reports expected path" {
    var stdout_buf: [1024]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try manifestCommand(std.testing.io, &.{"codex"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "integrations/codex-plugin/.codex-plugin/plugin.json") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "exists") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "plugin manifest claude reports expected path" {
    var stdout_buf: [1024]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try manifestCommand(std.testing.io, &.{"claude"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "integrations/claude-code-plugin/.claude-plugin/plugin.json") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "exists") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "plugin manifest opencode reports expected path" {
    var stdout_buf: [1024]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try manifestCommand(std.testing.io, &.{"opencode"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "integrations/opencode-plugin/ryk.ts") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "OpenCode uses TypeScript plugins") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "plugin manifest openclaw reports expected paths" {
    var stdout_buf: [1024]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try manifestCommand(std.testing.io, &.{"openclaw"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "integrations/openclaw-plugin/openclaw.plugin.json") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "package.json") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "plugin manifest hermes reports expected paths" {
    var stdout_buf: [1024]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try manifestCommand(std.testing.io, &.{"hermes"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "integrations/hermes-plugin/plugin.yaml") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "integrations/hermes-plugin/__init__.py") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "plugin manifest all reports all five" {
    // Worktree paths can be substantially longer than the primary checkout.
    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try manifestCommand(std.testing.io, &.{"all"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "codex:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "claude:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "opencode:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "openclaw:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "hermes:") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "plugin manifest --json emits valid JSON" {
    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try manifestCommand(std.testing.io, &.{ "all", "--json" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);

    const json = stdout_writer.buffered();
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json, .{});
    defer parsed.deinit();

    try std.testing.expect(parsed.value.object.get("codex") != null);
    try std.testing.expect(parsed.value.object.get("claude") != null);
    try std.testing.expect(parsed.value.object.get("opencode") != null);
    try std.testing.expect(parsed.value.object.get("openclaw") != null);
    try std.testing.expect(parsed.value.object.get("hermes") != null);
    try std.testing.expect(std.mem.indexOfScalar(u8, json, 0x1b) == null);
    try std.testing.expect(std.mem.indexOf(u8, json, "ryk Plugin") == null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "plugin install codex --dry-run reports safe preview" {
    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try installCommand(std.testing.io, &.{ "codex", "--dry-run" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "dry-run") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "no changes made") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "safety:") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "plugin install claude --dry-run reports safe preview" {
    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try installCommand(std.testing.io, &.{ "claude", "--dry-run" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "dry-run") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "no changes made") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "plugin install opencode --dry-run reports safe preview with paths" {
    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try installCommand(std.testing.io, &.{ "opencode", "--dry-run" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "dry-run") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "no changes made") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, ".opencode/plugins/ryk.ts") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "~/.config/opencode/plugins/ryk.ts") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "scope: global") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "plugin install openclaw --dry-run reports safe preview" {
    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try installCommand(std.testing.io, &.{ "openclaw", "--dry-run" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "dry-run") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "no changes made") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Target: openclaw") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "curl -fsSL https://rykanv.com/install | sh") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "ryk agents setup openclaw") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "source-checkout development only") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "plugin install hermes --dry-run reports safe preview" {
    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try installCommand(std.testing.io, &.{ "hermes", "--dry-run" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "dry-run") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Target: hermes") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, ".hermes/plugins/ryk") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "Hermes managed file install rejects symlinked parent and final file" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "source.py", .data = "managed" });
    try tmp.dir.createDirPath(std.testing.io, "outside");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "outside/keep.py", .data = "keep" });
    try tmp.dir.symLink(std.testing.io, "outside", "linked-parent", .{});
    try tmp.dir.symLink(std.testing.io, "outside/keep.py", "linked-file.py", .{});

    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const source = try std.fs.path.join(std.testing.allocator, &.{ root, "source.py" });
    defer std.testing.allocator.free(source);
    const through_parent = try std.fs.path.join(std.testing.allocator, &.{ root, "linked-parent", "__init__.py" });
    defer std.testing.allocator.free(through_parent);
    const linked_file = try std.fs.path.join(std.testing.allocator, &.{ root, "linked-file.py" });
    defer std.testing.allocator.free(linked_file);

    try std.testing.expectError(
        error.NotDir,
        installFileIfSafe(std.testing.allocator, source, through_parent),
    );
    try std.testing.expectError(
        error.RefusingSymlinkPluginPath,
        installFileIfSafe(std.testing.allocator, source, linked_file),
    );
    const preserved = try tmp.dir.readFileAlloc(
        std.testing.io,
        "outside/keep.py",
        std.testing.allocator,
        .limited(64),
    );
    defer std.testing.allocator.free(preserved);
    try std.testing.expectEqualStrings("keep", preserved);
}

test "Hermes managed file install upgrades stale Ryk-owned content" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "source.py", .data = "current" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "installed.py", .data = "stale" });

    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const source = try std.fs.path.join(std.testing.allocator, &.{ root, "source.py" });
    defer std.testing.allocator.free(source);
    const installed = try std.fs.path.join(std.testing.allocator, &.{ root, "installed.py" });
    defer std.testing.allocator.free(installed);

    try std.testing.expect(try installManagedFile(std.testing.allocator, source, installed));
    try std.testing.expect(!(try installManagedFile(std.testing.allocator, source, installed)));
    const content = try tmp.dir.readFileAlloc(
        std.testing.io,
        "installed.py",
        std.testing.allocator,
        .limited(64),
    );
    defer std.testing.allocator.free(content);
    try std.testing.expectEqualStrings("current", content);
}

test "Hermes managed destination requires a path-bound receipt, not copied metadata" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "plugin.yaml",
        .data = "name: ryk\ndescription: unrelated user plugin\n",
    });
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    try std.testing.expect(!hermesManagedDestination(std.testing.io, std.testing.allocator, root));

    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "plugin.yaml",
        .data = "name: ryk\ndescription: ryk runtime guardrails for Hermes Agent.\n",
    });
    try std.testing.expect(!hermesManagedDestination(std.testing.io, std.testing.allocator, root));

    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = ".ryk-managed-v1",
        .data = "ryk-hermes-managed-v1\npath=/not-this-directory\n",
    });
    try std.testing.expect(!hermesManagedDestination(std.testing.io, std.testing.allocator, root));
}

test "Hermes preflight marker cannot own a populated destination" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "installed");

    const root = try tmp.dir.realPathFileAlloc(std.testing.io, "installed", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const marker = try std.fmt.allocPrint(std.testing.allocator, "ryk-hermes-unattended-v1\npath={s}\n", .{root});
    defer std.testing.allocator.free(marker);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "installed/.ryk_unattended", .data = marker });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = ".ryk_fail_stance", .data = "fail-closed\n" });

    try std.testing.expect(hermesManagedDestination(std.testing.io, std.testing.allocator, root));
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "installed/attacker.py", .data = "arbitrary\n" });
    try std.testing.expect(!hermesManagedDestination(std.testing.io, std.testing.allocator, root));
}

test "Hermes bundle upgrade commits a complete receipt-bound tree and is idempotent" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "source");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "source/plugin.yaml", .data = "name: ryk\nversion: 1\n" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "source/__init__.py", .data = "source-v1\n" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "source/mapping.py", .data = "mapping-v1\n" });

    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const source = try std.fs.path.join(std.testing.allocator, &.{ root, "source" });
    defer std.testing.allocator.free(source);
    const destination = try std.fs.path.join(std.testing.allocator, &.{ root, "installed" });
    defer std.testing.allocator.free(destination);

    try std.testing.expect(try installHermesBundleAtomically(std.testing.io, std.testing.allocator, source, destination));
    try std.testing.expect(hermesManagedDestination(std.testing.io, std.testing.allocator, destination));
    try std.testing.expect(!try installHermesBundleAtomically(std.testing.io, std.testing.allocator, source, destination));

    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "source/plugin.yaml", .data = "name: ryk\nversion: 2\n" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "source/__init__.py", .data = "source-v2\n" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "source/mapping.py", .data = "mapping-v2\n" });
    try std.testing.expect(try installHermesBundleAtomically(std.testing.io, std.testing.allocator, source, destination));

    const installed_names = [_][]const u8{ "plugin.yaml", "__init__.py", "mapping.py" };
    for (installed_names) |name| {
        const path = try std.fs.path.join(std.testing.allocator, &.{ destination, name });
        defer std.testing.allocator.free(path);
        const contents = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, std.testing.allocator, .limited(1024));
        defer std.testing.allocator.free(contents);
        try std.testing.expect(std.mem.indexOf(u8, contents, "v2") != null or std.mem.indexOf(u8, contents, "version: 2") != null);
    }
}

test "Hermes managed receipt rejects symlinked adapter files" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "source");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "source/plugin.yaml", .data = "name: ryk\nversion: 1\n" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "source/__init__.py", .data = "source-v1\n" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "source/mapping.py", .data = "mapping-v1\n" });

    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const source = try std.fs.path.join(std.testing.allocator, &.{ root, "source" });
    defer std.testing.allocator.free(source);
    const destination = try std.fs.path.join(std.testing.allocator, &.{ root, "installed" });
    defer std.testing.allocator.free(destination);

    try std.testing.expect(try installHermesBundleAtomically(std.testing.io, std.testing.allocator, source, destination));
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "outside.py", .data = "source-v1\n" });
    try tmp.dir.deleteFile(std.testing.io, "installed/__init__.py");
    try tmp.dir.symLink(std.testing.io, "../outside.py", "installed/__init__.py", .{});
    try std.testing.expect(!hermesManagedDestination(std.testing.io, std.testing.allocator, destination));
}

test "Hermes bundle staging leaves the installed tree unchanged when a source file fails" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "source");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "source/plugin.yaml", .data = "name: ryk\nversion: 1\n" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "source/__init__.py", .data = "source-v1\n" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "source/mapping.py", .data = "mapping-v1\n" });

    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const source = try std.fs.path.join(std.testing.allocator, &.{ root, "source" });
    defer std.testing.allocator.free(source);
    const destination = try std.fs.path.join(std.testing.allocator, &.{ root, "installed" });
    defer std.testing.allocator.free(destination);

    try std.testing.expect(try installHermesBundleAtomically(std.testing.io, std.testing.allocator, source, destination));
    try tmp.dir.deleteFile(std.testing.io, "source/mapping.py");
    try std.testing.expectError(
        error.FileNotFound,
        installHermesBundleAtomically(std.testing.io, std.testing.allocator, source, destination),
    );
    const preserved = try tmp.dir.readFileAlloc(std.testing.io, "installed/__init__.py", std.testing.allocator, .limited(1024));
    defer std.testing.allocator.free(preserved);
    try std.testing.expectEqualStrings("source-v1\n", preserved);
}

test "plugin install all --dry-run reports all five targets" {
    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try installCommand(std.testing.io, &.{ "all", "--dry-run" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "Target: codex") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Target: claude") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Target: opencode") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Target: openclaw") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Target: hermes") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "plugin install without --yes or --dry-run in non-TTY returns usage" {
    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try installCommand(std.testing.io, &.{"codex"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, code);

    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "--yes or --dry-run") != null);
}

test "plugin install bare does not mutate (dry-run preview of all)" {
    var stdout_buf: [8192]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try installCommand(std.testing.io, &.{}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "dry-run") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "no changes made") != null or std.mem.indexOf(u8, output, "mode: dry-run") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "mode: install") == null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "plugin install bare --yes without host fails closed" {
    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try installCommand(std.testing.io, &.{"--yes"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "explicit host") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "mode: install") == null);
}

test "plugin install all without --yes in non-TTY fails" {
    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try installCommand(std.testing.io, &.{"all"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "--yes or --dry-run") != null);
}

test "plugin install --yes switches out of dry-run when dry-run is not explicit" {
    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try installCommand(std.testing.io, &.{ "codex", "--path", "does-not-exist-ryk-test-plugin", "--yes" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.general, code);

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "mode: install") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "plugin directory: missing") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "plugin install codex --yes installs plugin and marketplace" {
    var stdout_buf: [32768]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try installCommand(std.testing.io, &.{ "codex", "--yes" }, &stdout_writer, &stderr_writer);
    // Success if install completed; non-zero only when smoke *deny* fails (not when not-run under zig test).
    try std.testing.expectEqual(exit_codes.success, code);

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "mode: install") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "installed Codex plugin") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "smoke deny:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "not yet implemented") == null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "plugin install claude --yes installs plugin and marketplace" {
    var stdout_buf: [32768]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try installCommand(std.testing.io, &.{ "claude", "--yes" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "mode: install") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "installed Claude Code plugin") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "smoke deny:") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "interpretSmokeOutcome codex deny vs flexible host is covered by host_status" {
    // Anchors the install-smoke policy: codex deny is exit-code based.
    try std.testing.expect(host_status.interpretSmokeOutcome("codex", "block", 2, "", ""));
    try std.testing.expect(host_status.interpretSmokeOutcome("claude", "block", 0, "{\"decision\":\"block\"}", ""));
}

test "plugin install explicit dry-run wins over --yes" {
    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try installCommand(std.testing.io, &.{ "codex", "--yes", "--dry-run" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "mode: dry-run") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "plugin install rejects invalid scope" {
    var stdout_buf: [256]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try installCommand(std.testing.io, &.{ "opencode", "--scope", "workspace" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "invalid --scope value") != null);
}

test "plugin install opencode --scope global is accepted in dry-run" {
    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try installCommand(std.testing.io, &.{ "opencode", "--scope", "global", "--dry-run" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "scope: global") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

const CwdOpenCodePluginSnapshot = struct {
    hook: ?[]u8,
    tui: ?[]u8,

    fn restore(self: *CwdOpenCodePluginSnapshot, io: std.Io) void {
        restoreCwdOpenCodePluginFile(io, ".opencode/plugins/ryk.ts", self.hook);
        restoreCwdOpenCodePluginFile(io, ".opencode/plugins/ryk-tui.ts", self.tui);
        if (self.hook) |bytes| std.testing.allocator.free(bytes);
        if (self.tui) |bytes| std.testing.allocator.free(bytes);
        self.hook = null;
        self.tui = null;
    }
};

fn restoreCwdOpenCodePluginFile(io: std.Io, rel_path: []const u8, prev: ?[]const u8) void {
    if (prev) |bytes| {
        std.Io.Dir.cwd().writeFile(io, .{ .sub_path = rel_path, .data = bytes }) catch {};
    } else {
        std.Io.Dir.cwd().deleteFile(io, rel_path) catch {};
    }
}

fn snapshotCwdOpenCodePlugins(io: std.Io) !CwdOpenCodePluginSnapshot {
    try std.Io.Dir.cwd().createDirPath(io, ".opencode/plugins");
    return .{
        .hook = std.Io.Dir.cwd().readFileAlloc(io, ".opencode/plugins/ryk.ts", std.testing.allocator, .limited(8 * 1024 * 1024)) catch null,
        .tui = std.Io.Dir.cwd().readFileAlloc(io, ".opencode/plugins/ryk-tui.ts", std.testing.allocator, .limited(8 * 1024 * 1024)) catch null,
    };
}

fn expectInstalledMatchesBundled(io: std.Io, dest_path: []const u8, bundled_rel: []const u8) !void {
    try std.testing.expect(fileExistsAbsolute(io, dest_path));
    const source_path = try resolveBundledPath(io, std.testing.allocator, bundled_rel);
    defer std.testing.allocator.free(source_path);
    const source = try std.Io.Dir.cwd().readFileAlloc(io, source_path, std.testing.allocator, .limited(8 * 1024 * 1024));
    defer std.testing.allocator.free(source);
    const installed = try std.Io.Dir.cwd().readFileAlloc(io, dest_path, std.testing.allocator, .limited(8 * 1024 * 1024));
    defer std.testing.allocator.free(installed);
    try std.testing.expectEqualStrings(source, installed);
}

test "siblingOpenCodePluginPath rejects destination with no directory" {
    try std.testing.expectError(error.InvalidPath, siblingOpenCodePluginPath(std.testing.allocator, "ryk.ts", "ryk-tui.ts"));
    try std.testing.expectError(error.InvalidPath, siblingOpenCodePluginPath(std.testing.allocator, "", "ryk-tui.ts"));

    const dest = try std.fs.path.join(std.testing.allocator, &.{ "plugins", "ryk.ts" });
    defer std.testing.allocator.free(dest);
    const joined = try siblingOpenCodePluginPath(std.testing.allocator, dest, "ryk-tui.ts");
    defer std.testing.allocator.free(joined);
    const expected = try std.fs.path.join(std.testing.allocator, &.{ "plugins", "ryk-tui.ts" });
    defer std.testing.allocator.free(expected);
    try std.testing.expectEqualStrings(expected, joined);
}

test "plugin install opencode --yes writes global plugin under HOME" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(home);
    const home_z = try std.testing.allocator.dupeZ(u8, home);
    defer std.testing.allocator.free(home_z);

    const prev_home = try testDupEnvZ("HOME");
    defer testRestoreEnv("HOME", prev_home);
    try std.testing.expectEqual(@as(c_int, 0), setenv("HOME", home_z.ptr, 1));

    var stdout_buf: [65536]u8 = undefined;
    var stderr_buf: [1024]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try installCommand(std.testing.io, &.{ "opencode", "--yes" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "mode: install") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "scope: global") != null);
    try std.testing.expect(
        std.mem.indexOf(u8, output, "installed to") != null or
            std.mem.indexOf(u8, output, "already up-to-date") != null,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, output, "OpenCode is guarded") != null or
            std.mem.indexOf(u8, output, "host CLI not on PATH") != null,
    );

    const plugin_path = try std.fs.path.join(std.testing.allocator, &.{ home, ".config", "opencode", "plugins", "ryk.ts" });
    defer std.testing.allocator.free(plugin_path);
    try expectInstalledMatchesBundled(std.testing.io, plugin_path, "integrations/opencode-plugin/ryk.ts");
    const tui_path = try std.fs.path.join(std.testing.allocator, &.{ home, ".config", "opencode", "plugins", "ryk-tui.ts" });
    defer std.testing.allocator.free(tui_path);
    try expectInstalledMatchesBundled(std.testing.io, tui_path, "integrations/opencode-plugin/ryk-tui.ts");

    const config_path = try std.fs.path.join(std.testing.allocator, &.{ home, ".config", "opencode", "opencode.json" });
    defer std.testing.allocator.free(config_path);
    try std.testing.expect(fileExistsAbsolute(std.testing.io, config_path));
}

test "plugin install opencode --yes upgrades stale global plugin under HOME" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(home);
    const home_z = try std.testing.allocator.dupeZ(u8, home);
    defer std.testing.allocator.free(home_z);

    try tmp.dir.createDirPath(std.testing.io, ".config/opencode/plugins");
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = ".config/opencode/plugins/ryk.ts",
        .data = "// OLD STALE OPENCODE PLUGIN\n",
    });

    const prev_home = try testDupEnvZ("HOME");
    defer testRestoreEnv("HOME", prev_home);
    try std.testing.expectEqual(@as(c_int, 0), setenv("HOME", home_z.ptr, 1));

    var stdout_buf: [65536]u8 = undefined;
    var stderr_buf: [2048]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try installCommand(std.testing.io, &.{ "opencode", "--yes", "--scope", "global" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "destination exists and differs") == null);
    try std.testing.expect(
        std.mem.indexOf(u8, output, "upgraded") != null or
            std.mem.indexOf(u8, output, "installed to") != null,
    );

    const plugin_path = try std.fs.path.join(std.testing.allocator, &.{ home, ".config", "opencode", "plugins", "ryk.ts" });
    defer std.testing.allocator.free(plugin_path);
    const installed = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, plugin_path, std.testing.allocator, .limited(8 * 1024 * 1024));
    defer std.testing.allocator.free(installed);
    try std.testing.expect(std.mem.indexOf(u8, installed, "OLD STALE OPENCODE PLUGIN") == null);
    try expectInstalledMatchesBundled(std.testing.io, plugin_path, "integrations/opencode-plugin/ryk.ts");
    const tui_path = try std.fs.path.join(std.testing.allocator, &.{ home, ".config", "opencode", "plugins", "ryk-tui.ts" });
    defer std.testing.allocator.free(tui_path);
    try expectInstalledMatchesBundled(std.testing.io, tui_path, "integrations/opencode-plugin/ryk-tui.ts");
}

test "plugin install opencode --yes is noop when global plugin already current" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(home);
    const home_z = try std.testing.allocator.dupeZ(u8, home);
    defer std.testing.allocator.free(home_z);

    const source_path = try resolveBundledPath(std.testing.io, std.testing.allocator, "integrations/opencode-plugin/ryk.ts");
    defer std.testing.allocator.free(source_path);
    const source = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, source_path, std.testing.allocator, .limited(8 * 1024 * 1024));
    defer std.testing.allocator.free(source);

    const tui_source_path = try resolveBundledPath(std.testing.io, std.testing.allocator, "integrations/opencode-plugin/ryk-tui.ts");
    defer std.testing.allocator.free(tui_source_path);
    const tui_source = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, tui_source_path, std.testing.allocator, .limited(8 * 1024 * 1024));
    defer std.testing.allocator.free(tui_source);

    try tmp.dir.createDirPath(std.testing.io, ".config/opencode/plugins");
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = ".config/opencode/plugins/ryk.ts",
        .data = source,
    });
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = ".config/opencode/plugins/ryk-tui.ts",
        .data = tui_source,
    });

    const prev_home = try testDupEnvZ("HOME");
    defer testRestoreEnv("HOME", prev_home);
    try std.testing.expectEqual(@as(c_int, 0), setenv("HOME", home_z.ptr, 1));

    var stdout_buf: [65536]u8 = undefined;
    var stderr_buf: [2048]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try installCommand(std.testing.io, &.{ "opencode", "--yes", "--scope", "global" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "already up-to-date") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "destination exists and differs") == null);

    const plugin_path = try std.fs.path.join(std.testing.allocator, &.{ home, ".config", "opencode", "plugins", "ryk.ts" });
    defer std.testing.allocator.free(plugin_path);
    const installed = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, plugin_path, std.testing.allocator, .limited(8 * 1024 * 1024));
    defer std.testing.allocator.free(installed);
    try std.testing.expectEqualStrings(source, installed);
    const tui_path = try std.fs.path.join(std.testing.allocator, &.{ home, ".config", "opencode", "plugins", "ryk-tui.ts" });
    defer std.testing.allocator.free(tui_path);
    const tui_installed = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, tui_path, std.testing.allocator, .limited(8 * 1024 * 1024));
    defer std.testing.allocator.free(tui_installed);
    try std.testing.expectEqualStrings(tui_source, tui_installed);
}

test "plugin install opencode --scope project upgrades stale project plugin" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const io = std.testing.io;
    // Isolate HOME so dual-scope reconcile cannot touch the developer's real
    // ~/.config/opencode/{plugins/ryk.ts,opencode.json}.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try tmp.dir.realPathFileAlloc(io, ".", std.testing.allocator);
    defer std.testing.allocator.free(home);
    const home_z = try std.testing.allocator.dupeZ(u8, home);
    defer std.testing.allocator.free(home_z);
    const prev_home = try testDupEnvZ("HOME");
    defer testRestoreEnv("HOME", prev_home);
    try std.testing.expectEqual(@as(c_int, 0), setenv("HOME", home_z.ptr, 1));

    // Project destination is workspace-relative and gitignored under .opencode/.
    const project_rel = ".opencode/plugins/ryk.ts";
    const project_tui_rel = ".opencode/plugins/ryk-tui.ts";
    var project_snap = try snapshotCwdOpenCodePlugins(io);
    defer project_snap.restore(io);

    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = project_rel, .data = "// OLD STALE PROJECT OPENCODE PLUGIN\n" });
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = project_tui_rel, .data = "// OLD STALE PROJECT OPENCODE TUI\n" });

    var stdout_buf: [65536]u8 = undefined;
    var stderr_buf: [2048]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try installCommand(io, &.{ "opencode", "--yes", "--scope", "project" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "destination exists and differs") == null);
    try std.testing.expect(
        std.mem.indexOf(u8, output, "upgraded") != null or
            std.mem.indexOf(u8, output, "installed to") != null,
    );

    try expectInstalledMatchesBundled(io, project_rel, "integrations/opencode-plugin/ryk.ts");
    try expectInstalledMatchesBundled(io, project_tui_rel, "integrations/opencode-plugin/ryk-tui.ts");

    // Dual-scope must not create a global plugin under the isolated HOME unless it already existed.
    const global_path = try std.fs.path.join(std.testing.allocator, &.{ home, ".config", "opencode", "plugins", "ryk.ts" });
    defer std.testing.allocator.free(global_path);
    try std.testing.expect(!fileExistsAbsolute(io, global_path));
    const global_tui_path = try std.fs.path.join(std.testing.allocator, &.{ home, ".config", "opencode", "plugins", "ryk-tui.ts" });
    defer std.testing.allocator.free(global_tui_path);
    try std.testing.expect(!fileExistsAbsolute(io, global_tui_path));
}

test "plugin install opencode global scope upgrades existing stale project plugin too" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try tmp.dir.realPathFileAlloc(io, ".", std.testing.allocator);
    defer std.testing.allocator.free(home);
    const home_z = try std.testing.allocator.dupeZ(u8, home);
    defer std.testing.allocator.free(home_z);

    try tmp.dir.createDirPath(io, ".config/opencode/plugins");
    try tmp.dir.writeFile(io, .{
        .sub_path = ".config/opencode/plugins/ryk.ts",
        .data = "// OLD STALE GLOBAL OPENCODE PLUGIN\n",
    });

    const project_rel = ".opencode/plugins/ryk.ts";
    const project_tui_rel = ".opencode/plugins/ryk-tui.ts";
    var project_snap = try snapshotCwdOpenCodePlugins(io);
    defer project_snap.restore(io);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = project_rel, .data = "// OLD STALE PROJECT OPENCODE PLUGIN\n" });
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = project_tui_rel, .data = "// OLD STALE PROJECT OPENCODE TUI\n" });

    const prev_home = try testDupEnvZ("HOME");
    defer testRestoreEnv("HOME", prev_home);
    try std.testing.expectEqual(@as(c_int, 0), setenv("HOME", home_z.ptr, 1));

    var stdout_buf: [65536]u8 = undefined;
    var stderr_buf: [2048]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try installCommand(io, &.{ "opencode", "--yes", "--scope", "global" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "destination exists and differs") == null);

    const global_path = try std.fs.path.join(std.testing.allocator, &.{ home, ".config", "opencode", "plugins", "ryk.ts" });
    defer std.testing.allocator.free(global_path);
    const global_tui_path = try std.fs.path.join(std.testing.allocator, &.{ home, ".config", "opencode", "plugins", "ryk-tui.ts" });
    defer std.testing.allocator.free(global_tui_path);
    try expectInstalledMatchesBundled(io, global_path, "integrations/opencode-plugin/ryk.ts");
    try expectInstalledMatchesBundled(io, global_tui_path, "integrations/opencode-plugin/ryk-tui.ts");
    try expectInstalledMatchesBundled(io, project_rel, "integrations/opencode-plugin/ryk.ts");
    try expectInstalledMatchesBundled(io, project_tui_rel, "integrations/opencode-plugin/ryk-tui.ts");
}

test "plugin install opencode --yes fails when ryk-tui.ts source is missing" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "ryk.ts", .data = "hook-only\n" });

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    const home = try home_tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(home);
    const home_z = try std.testing.allocator.dupeZ(u8, home);
    defer std.testing.allocator.free(home_z);
    const prev_home = try testDupEnvZ("HOME");
    defer testRestoreEnv("HOME", prev_home);
    try std.testing.expectEqual(@as(c_int, 0), setenv("HOME", home_z.ptr, 1));

    var stdout_buf: [8192]u8 = undefined;
    var stderr_buf: [1024]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try installCommand(std.testing.io, &.{ "opencode", "--yes", "--path", root }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.general, code);
    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "source missing") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "ryk-tui.ts") != null);

    const dest_hook = try std.fs.path.join(std.testing.allocator, &.{ home, ".config", "opencode", "plugins", "ryk.ts" });
    defer std.testing.allocator.free(dest_hook);
    try std.testing.expect(!fileExistsAbsolute(std.testing.io, dest_hook));
}

test "OpenCode doctor pair flags require both ryk.ts and ryk-tui.ts" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, ".ryk");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = ".ryk/policy.yaml", .data = "mode: observe\n" });
    try tmp.dir.createDirPath(std.testing.io, ".opencode/plugins");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = ".opencode/plugins/ryk.ts", .data = "hook-only\n" });

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    const home = try home_tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(home);
    const home_z = try std.testing.allocator.dupeZ(u8, home);
    defer std.testing.allocator.free(home_z);
    try home_tmp.dir.createDirPath(std.testing.io, ".config/opencode/plugins");
    try home_tmp.dir.writeFile(std.testing.io, .{
        .sub_path = ".config/opencode/plugins/ryk.ts",
        .data = "global-hook-only\n",
    });

    const tmp_root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(tmp_root);
    const original_cwd = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(original_cwd);
    try std.Io.Threaded.chdir(tmp_root);
    defer std.Io.Threaded.chdir(original_cwd) catch {};

    const prev_home = try testDupEnvZ("HOME");
    defer testRestoreEnv("HOME", prev_home);
    try std.testing.expectEqual(@as(c_int, 0), setenv("HOME", home_z.ptr, 1));

    {
        var report = try collectPluginDoctorReportForAgentsHealth(std.testing.io, std.testing.allocator);
        defer deinitPluginDoctorReport(&report, std.testing.allocator);
        try std.testing.expect(!report.opencode_paths.project_plugin_exists);
        try std.testing.expect(!report.opencode_paths.global_plugin_exists);
        try std.testing.expect(!hostPluginInstalledFromReport("opencode", report));
    }

    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = ".opencode/plugins/ryk-tui.ts", .data = "project-tui\n" });
    {
        var report = try collectPluginDoctorReportForAgentsHealth(std.testing.io, std.testing.allocator);
        defer deinitPluginDoctorReport(&report, std.testing.allocator);
        try std.testing.expect(report.opencode_paths.project_plugin_exists);
        try std.testing.expect(!report.opencode_paths.global_plugin_exists);
        try std.testing.expect(hostPluginInstalledFromReport("opencode", report));
    }

    try home_tmp.dir.writeFile(std.testing.io, .{
        .sub_path = ".config/opencode/plugins/ryk-tui.ts",
        .data = "global-tui\n",
    });
    {
        var report = try collectPluginDoctorReportForAgentsHealth(std.testing.io, std.testing.allocator);
        defer deinitPluginDoctorReport(&report, std.testing.allocator);
        try std.testing.expect(report.opencode_paths.project_plugin_exists);
        try std.testing.expect(report.opencode_paths.global_plugin_exists);
        try std.testing.expect(hostPluginInstalledFromReport("opencode", report));
    }
}

test "OpenCode managed file install refuses symlink destination" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "source.ts", .data = "managed" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "outside.ts", .data = "keep" });
    try tmp.dir.symLink(std.testing.io, "outside.ts", "linked.ts", .{});

    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const source = try std.fs.path.join(std.testing.allocator, &.{ root, "source.ts" });
    defer std.testing.allocator.free(source);
    const linked = try std.fs.path.join(std.testing.allocator, &.{ root, "linked.ts" });
    defer std.testing.allocator.free(linked);

    try std.testing.expectError(
        error.RefusingSymlinkPluginPath,
        installManagedFile(std.testing.allocator, source, linked),
    );
    const preserved = try tmp.dir.readFileAlloc(
        std.testing.io,
        "outside.ts",
        std.testing.allocator,
        .limited(64),
    );
    defer std.testing.allocator.free(preserved);
    try std.testing.expectEqualStrings("keep", preserved);
}

test "ensureOpenCodeConfigSane repairs plugin list placeholder" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(home);
    const home_z = try std.testing.allocator.dupeZ(u8, home);
    defer std.testing.allocator.free(home_z);

    try tmp.dir.createDirPath(std.testing.io, ".config/opencode");
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = ".config/opencode/opencode.json",
        .data = "{\"plugin\": [\"list\"]}\n",
    });

    const prev_home = try testDupEnvZ("HOME");
    defer testRestoreEnv("HOME", prev_home);
    try std.testing.expectEqual(@as(c_int, 0), setenv("HOME", home_z.ptr, 1));

    const note = try ensureOpenCodeConfigSane(std.testing.io, std.testing.allocator);
    defer std.testing.allocator.free(note);
    try std.testing.expect(std.mem.indexOf(u8, note, "repaired") != null);

    const fixed = try tmp.dir.readFileAlloc(std.testing.io, ".config/opencode/opencode.json", std.testing.allocator, .limited(4096));
    defer std.testing.allocator.free(fixed);
    try std.testing.expect(std.mem.indexOf(u8, fixed, "[\"list\"]") == null);
    try std.testing.expect(std.mem.indexOf(u8, fixed, "[]") != null);
}

test "plugin mcp-server reports limited status honestly" {
    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try mcpServerCommand(std.testing.io, &.{}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "limited") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "deferred") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "not yet active") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "ryk_doctor") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "plugin doctor reports marketplace status" {
    var stdout_buf: [16384]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try doctorCommand(std.testing.io, &.{}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "Marketplace files:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, ".agents/plugins/marketplace.json") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, ".claude-plugin/marketplace.json") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "plugin doctor codex reports marketplace and manifest status" {
    var stdout_buf: [16384]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try doctorCommand(std.testing.io, &.{"codex"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "Codex plugin status:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "marketplace file:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "plugin manifest:") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "plugin doctor claude reports marketplace and manifest status" {
    var stdout_buf: [16384]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try doctorCommand(std.testing.io, &.{"claude"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "Claude Code plugin status:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "marketplace file:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "plugin manifest:") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "plugin manifest codex reports marketplace path" {
    var stdout_buf: [1024]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try manifestCommand(std.testing.io, &.{"codex"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, ".agents/plugins/marketplace.json") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "plugin manifest claude reports marketplace path" {
    var stdout_buf: [1024]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try manifestCommand(std.testing.io, &.{"claude"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, ".claude-plugin/marketplace.json") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "plugin manifest all reports marketplace files" {
    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try manifestCommand(std.testing.io, &.{"all"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "Marketplace files:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, ".agents/plugins/marketplace.json") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, ".claude-plugin/marketplace.json") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

fn pluginListTestReport() PluginDoctorReport {
    return .{
        .ryk_version = "test",
        .ryk_binary_path = null,
        .cwd = @constCast("."),
        .workspace_root = ".",
        .policy_present = false,
        .policy_valid = false,
        .policy_error = null,
        .audit_replay_available = false,
        .mcp_support_status = "",
        .plugin_directories = .{ .codex = true, .claude = true, .opencode = true, .openclaw = true, .hermes = true, .common = true },
        .host_binaries = .{ .codex = false, .claude = false, .opencode = false, .openclaw = false, .hermes = false },
        .opencode_paths = .{ .project_plugin_exists = false, .global_plugin_exists = false, .config_references_plugin = false },
        .openclaw_paths = .{ .host_plugin_installed = false, .plugin_manifest_exists = false, .package_json_exists = false, .source_exists = false, .detection_note = "" },
        .hermes_paths = .{ .repo_manifest_exists = false, .repo_source_exists = false, .repo_mapping_exists = false, .user_manifest_exists = false, .user_source_exists = false, .user_mapping_exists = false, .config_references_plugin = false, .user_manifest_name_is_ryk = false },
        .hermes_hook_smoke_passed = false,
        .marketplace = .{ .codex_marketplace = false, .claude_marketplace = false, .codex_plugin_manifest = true, .claude_plugin_manifest = true, .codex_user_plugin = false, .claude_user_plugin = false },
        .platform_summary = "",
        .warnings = &.{},
    };
}

fn pluginListAllocationFailureHarness(allocator: std.mem.Allocator) !void {
    var buffer: [4096]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try writePluginList(std.testing.io, allocator, &writer, pluginListTestReport());
}

test "plugin list cleans up allocation failure paths" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, pluginListAllocationFailureHarness, .{});
}

test "plugin list renders deterministic host inventory and empty guidance" {
    const report = pluginListTestReport();
    var buffer: [4096]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);

    try writePluginList(std.testing.io, std.testing.allocator, &writer, report);

    const output = writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "HOST") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Codex").? < std.mem.indexOf(u8, output, "Claude Code").?);
    try std.testing.expect(std.mem.indexOf(u8, output, "Claude Code").? < std.mem.indexOf(u8, output, "OpenCode").?);
    try std.testing.expect(std.mem.indexOf(u8, output, "No supported host CLIs detected") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "ryk plugin codex --dry-run") != null);
}

test "friendly plugin host alias preserves install dry-run output" {
    var alias_stdout_buf: [8192]u8 = undefined;
    var alias_stderr_buf: [256]u8 = undefined;
    var direct_stdout_buf: [8192]u8 = undefined;
    var direct_stderr_buf: [256]u8 = undefined;
    var alias_stdout: std.Io.Writer = .fixed(&alias_stdout_buf);
    var alias_stderr: std.Io.Writer = .fixed(&alias_stderr_buf);
    var direct_stdout: std.Io.Writer = .fixed(&direct_stdout_buf);
    var direct_stderr: std.Io.Writer = .fixed(&direct_stderr_buf);

    const alias_code = try command(std.testing.io, &.{ "codex", "--dry-run" }, &alias_stdout, &alias_stderr);
    const direct_code = try installCommand(std.testing.io, &.{ "codex", "--dry-run" }, &direct_stdout, &direct_stderr);

    try std.testing.expectEqual(direct_code, alias_code);
    try std.testing.expectEqualStrings(direct_stdout.buffered(), alias_stdout.buffered());
    try std.testing.expectEqualStrings(direct_stderr.buffered(), alias_stderr.buffered());
}

//! Shared pack enablement + summary helpers for the ryk CLI (P2a power baseline).
//!
//! Pack *definitions* are served by the Zig shell_engine registry / packs CLI.
//! This module:
//! - maps policy presets → opt-in pack IDs
//! - summarizes enabled packs for `ryk doctor`
//! - re-exports config path + enable/disable mutation from `pack_config.zig`
//!
//! Config path rule (documented in help + status):
//! - Prefer project `.ryk.toml` when the workspace is a git repo
//! - Otherwise write user config (`$XDG_CONFIG_HOME/ryk/config.toml` or `~/.config/ryk/config.toml`)
//!
//! Baseline always-on (never claim the user "disabled" these unless explicitly in `disabled`):
//! - `core` / `core.*` (always enabled by PacksConfig)
//! - `system.disk` (default-on, opt-out via disabled)

const std = @import("std");
const policy_mod = @import("ryk_core").policy;
const contracts = @import("daemon_contracts.zig");
const exit_codes = @import("exit_codes.zig");
const pack_config = @import("pack_config.zig");

// Re-export config mutation API so existing callers keep a stable import path.
pub const ConfigScope = pack_config.ConfigScope;
pub const ResolvedPackConfig = pack_config.ResolvedPackConfig;
pub const PackMutationResult = pack_config.PackMutationResult;
pub const isBaselinePackId = pack_config.isBaselinePackId;
pub const resolvePackConfigPath = pack_config.resolvePackConfigPath;
pub const enablePacks = pack_config.enablePacks;
pub const disablePacks = pack_config.disablePacks;

/// Max opt-in pack IDs shown inline in summaries (rest become "and K more").
pub const summary_list_limit: usize = 4;

pub const EnsurePacksResult = struct {
    /// Short user-facing line, e.g. "Packs: baseline only" or "Enabled packs: a, b".
    message: []const u8,
    /// Absolute or relative path written/merged, if any.
    config_path: ?[]const u8 = null,
    scope: ?ConfigScope = null,
    changed: bool = false,
    /// True when caller must free message and config_path.
    owned: bool = false,

    pub fn deinit(self: *EnsurePacksResult, allocator: std.mem.Allocator) void {
        if (!self.owned) return;
        allocator.free(self.message);
        if (self.config_path) |path| allocator.free(path);
        self.* = undefined;
    }
};

pub const PacksSummary = struct {
    known: bool,
    /// Total packs with enabled=true from daemon listing (includes baseline).
    total_enabled: usize = 0,
    total_available: usize = 0,
    /// Opt-in (non-baseline) enabled pack IDs, owned when known.
    opt_in_ids: []const []const u8 = &.{},
    /// Owned when deinit is required.
    owned: bool = false,

    pub fn deinit(self: *PacksSummary, allocator: std.mem.Allocator) void {
        if (!self.owned) return;
        for (self.opt_in_ids) |id| allocator.free(id);
        allocator.free(self.opt_in_ids);
        self.* = undefined;
    }

    pub fn optInCount(self: PacksSummary) usize {
        return self.opt_in_ids.len;
    }
};

/// Opt-in pack IDs for a policy preset. Empty means baseline only.
/// Real registry IDs only — daemon remains source of truth for definitions.
pub fn presetOptInPacks(preset: policy_mod.presets.AgentPreset) []const []const u8 {
    return switch (preset) {
        // Default / conservative coding agents: no surprise opt-ins.
        .generic_agent, .solo_dev, .trusted_local, .mcp_dev, .unattended => &.{},
        // Coding agents: small safe package-manager pack.
        .claude_code, .codex, .cursor_agent, .opencode, .cline_roo => &.{"package_managers"},
        // Local strict: extra git paranoia on top of baseline.
        .strict_local, .no_external_comms => &.{"strict_git"},
        // Team / CI style: containers + k8s + terraform + GHA.
        .team_ci, .github_actions => &.{
            "containers.docker",
            "containers.compose",
            "kubernetes.kubectl",
            "infrastructure.terraform",
            "cicd.github_actions",
        },
        // OpenClaw / Hermes plugin workflows: infra-oriented opt-ins.
        .openclaw_hermes => &.{
            "containers.docker",
            "containers.compose",
            "kubernetes.kubectl",
            "infrastructure.terraform",
        },
    };
}

pub fn presetOptInPacksByName(preset_name: []const u8) []const []const u8 {
    const preset = policy_mod.presets.AgentPreset.parse(preset_name) orelse return &.{};
    return presetOptInPacks(preset);
}

pub fn summarizeFromPacksOutput(allocator: std.mem.Allocator, output: contracts.PacksOutput) !PacksSummary {
    var opt_in: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        for (opt_in.items) |id| allocator.free(id);
        opt_in.deinit(allocator);
    }

    var total_enabled: usize = 0;
    for (output.packs) |pack| {
        if (!pack.enabled) continue;
        total_enabled += 1;
        if (isBaselinePackId(pack.id)) continue;
        const owned = try allocator.dupe(u8, pack.id);
        errdefer allocator.free(owned);
        try opt_in.append(allocator, owned);
    }
    std.mem.sort([]const u8, opt_in.items, {}, struct {
        fn less(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.less);

    return .{
        .known = true,
        .total_enabled = if (output.enabled_count > 0) output.enabled_count else total_enabled,
        .total_available = output.total_count,
        .opt_in_ids = try opt_in.toOwnedSlice(allocator),
        .owned = true,
    };
}

pub fn unknownPacksSummary() PacksSummary {
    return .{ .known = false };
}

/// Format a one-line packs summary for status/doctor (caller owns returned slice).
pub fn formatSummaryLine(allocator: std.mem.Allocator, summary: PacksSummary) ![]u8 {
    if (!summary.known) {
        // RT-12: packs inventory offline ≠ shell evaluate dead (Zig in-process shell_engine).
        return try allocator.dupe(u8, "unknown (packs inventory offline; shell evaluate is Zig in-process)");
    }
    if (summary.opt_in_ids.len == 0) {
        return try allocator.dupe(u8, "baseline only — enable more with `ryk packs enable …`");
    }
    var list_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer list_buf.deinit(allocator);
    const show = @min(summary.opt_in_ids.len, summary_list_limit);
    var i: usize = 0;
    while (i < show) : (i += 1) {
        if (i > 0) try list_buf.appendSlice(allocator, ", ");
        try list_buf.appendSlice(allocator, summary.opt_in_ids[i]);
    }
    if (summary.opt_in_ids.len > summary_list_limit) {
        const more = summary.opt_in_ids.len - summary_list_limit;
        const more_txt = try std.fmt.allocPrint(allocator, ", and {d} more", .{more});
        defer allocator.free(more_txt);
        try list_buf.appendSlice(allocator, more_txt);
    }
    return try std.fmt.allocPrint(
        allocator,
        "baseline + {d} opt-in enabled ({s})",
        .{ summary.opt_in_ids.len, list_buf.items },
    );
}

pub fn writeDoctorPacksSection(stdout: anytype, summary: PacksSummary) !void {
    try writeDoctorPacksSectionWithConfig(stdout, summary, null, null);
}

/// Doctor packs section with optional config path/scope for next-action context.
pub fn writeDoctorPacksSectionWithConfig(
    stdout: anytype,
    summary: PacksSummary,
    config_path: ?[]const u8,
    scope: ?ConfigScope,
) !void {
    try stdout.writeAll("\nPacks\n");
    if (!summary.known) {
        try stdout.writeAll("  unknown (packs inventory offline; shell evaluate is Zig in-process)\n");
        try stdout.writeAll("  Next: ryk packs --enabled  ·  ryk doctor  (retry packs inventory)\n");
        return;
    }
    try stdout.writeAll("  baseline: core.*, system.disk (default on; user config may opt out)\n");
    if (summary.opt_in_ids.len == 0) {
        try stdout.writeAll("  opt-in: none enabled (baseline only)\n");
        try stdout.writeAll("  Next: ryk packs enable <id>  ·  ryk packs --enabled  ·  ryk packs show <id>\n");
    } else {
        try stdout.print("  opt-in: {d} enabled", .{summary.opt_in_ids.len});
        const show = @min(summary.opt_in_ids.len, summary_list_limit);
        if (show > 0) {
            try stdout.writeAll(" (");
            var i: usize = 0;
            while (i < show) : (i += 1) {
                if (i > 0) try stdout.writeAll(", ");
                try stdout.writeAll(summary.opt_in_ids[i]);
            }
            if (summary.opt_in_ids.len > summary_list_limit) {
                try stdout.print(", and {d} more", .{summary.opt_in_ids.len - summary_list_limit});
            }
            try stdout.writeAll(")");
        }
        try stdout.writeAll("\n");
        try stdout.writeAll("  Next: ryk packs --enabled  ·  ryk packs show <id>  ·  ryk packs enable <id>\n");
    }
    if (config_path) |path| {
        if (scope) |s| {
            try stdout.print("  Config: {s} ({s})\n", .{ path, s.label() });
        } else {
            try stdout.print("  Config: {s}\n", .{path});
        }
    }
}

/// Inflated oracle pack definitions (same gzip as shell_engine.registry / packs CLI).
const oracle_embed = @import("../shell_engine/oracle_embed.zig");

/// Query packs inventory in-process (Zig registry + pack_config). Never requires daemon.
/// RT-12: doctor packs summary must stay available when daemon is unhealthy.
///
/// Doctor UX may report `known=false` when inflate/parse fails. That fail-open
/// inventory line must not be copied into the eval path (registry.initOnce
/// maps the same failure to RegistryInitFailed → deny).
pub fn queryPacksSummaryInProcess(io: std.Io, allocator: std.mem.Allocator) !PacksSummary {
    const packs_json = oracle_embed.inflateAlloc(allocator) catch return unknownPacksSummary();
    defer allocator.free(packs_json);
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, packs_json, .{}) catch {
        return unknownPacksSummary();
    };
    defer parsed.deinit();
    if (parsed.value != .array) return unknownPacksSummary();

    const onboarding = @import("onboarding.zig");
    const workspace_root = onboarding.resolveWorkspaceRoot(io, allocator) catch null;
    defer if (workspace_root) |r| allocator.free(r);

    var enabled_ids: []const []const u8 = &.{};
    var disabled_ids: []const []const u8 = &.{};
    var loaded: ?pack_config.LoadedPackIds = null;
    defer if (loaded) |*l| l.deinit(allocator);

    // F9: pack-config load failure must not paint baseline-only known inventory
    // while shell_eval hard-denies the same load error.
    if (workspace_root) |root| {
        loaded = pack_config.loadPackIdsForWorkspace(io, allocator, root) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return unknownPacksSummary(),
        };
        if (loaded) |l| {
            enabled_ids = l.enabled;
            disabled_ids = l.disabled;
        }
    }

    var opt_in: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        for (opt_in.items) |id| allocator.free(id);
        opt_in.deinit(allocator);
    }

    var total_enabled: usize = 0;
    var total_available: usize = 0;
    for (parsed.value.array.items) |item| {
        if (item != .object) continue;
        const id_val = item.object.get("id") orelse continue;
        if (id_val != .string) continue;
        const id = id_val.string;
        if (std.mem.eql(u8, id, "test.deadline")) continue;
        total_available += 1;
        if (!packIsActiveForSummary(id, enabled_ids, disabled_ids)) continue;
        total_enabled += 1;
        if (isBaselinePackId(id)) continue;
        const owned = try allocator.dupe(u8, id);
        errdefer allocator.free(owned);
        try opt_in.append(allocator, owned);
    }
    std.mem.sort([]const u8, opt_in.items, {}, struct {
        fn less(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.less);

    return .{
        .known = true,
        .total_enabled = total_enabled,
        .total_available = total_available,
        .opt_in_ids = try opt_in.toOwnedSlice(allocator),
        .owned = true,
    };
}

fn packIdListedForSummary(pack_id: []const u8, ids: []const []const u8) bool {
    for (ids) |id| {
        if (std.mem.eql(u8, pack_id, id)) return true;
        if (std.mem.indexOfScalar(u8, id, '.') == null and id.len > 0) {
            if (pack_id.len > id.len and pack_id[id.len] == '.' and std.mem.startsWith(u8, pack_id, id)) {
                return true;
            }
        }
    }
    return false;
}

fn packIsActiveForSummary(id: []const u8, extra_enabled: []const []const u8, disabled: []const []const u8) bool {
    if (packIdListedForSummary(id, disabled)) return false;
    if (isBaselinePackId(id)) return true;
    return packIdListedForSummary(id, extra_enabled);
}

/// Legacy daemon-callback path (tests / rare tooling). Prefer `queryPacksSummaryInProcess`.
pub fn queryPacksSummary(
    comptime execute_cli: anytype,
    io: std.Io,
    allocator: std.mem.Allocator,
) !PacksSummary {
    var daemon_stdout: std.Io.Writer.Allocating = .init(allocator);
    defer daemon_stdout.deinit();
    var daemon_stderr: std.Io.Writer.Allocating = .init(allocator);
    defer daemon_stderr.deinit();

    const code = execute_cli(io, &.{ "packs", "--format", "json" }, &daemon_stdout.writer, &daemon_stderr.writer) catch {
        return unknownPacksSummary();
    };
    if (code != exit_codes.success) return unknownPacksSummary();

    var parsed = contracts.parsePacks(allocator, daemon_stdout.written()) catch {
        return unknownPacksSummary();
    };
    defer parsed.deinit();
    return try summarizeFromPacksOutput(allocator, parsed.value);
}

/// Doctor / status default: Zig monopath (oracle registry + pack_config), not daemon.
pub fn queryPacksSummaryDefault(io: std.Io, allocator: std.mem.Allocator) !PacksSummary {
    return queryPacksSummaryInProcess(io, allocator);
}

/// Ensure opt-in packs for `preset` are listed in the daemon-readable pack config.
/// Additive / idempotent: never removes existing enabled packs or disabled entries.
pub fn ensurePresetPacks(
    io: std.Io,
    allocator: std.mem.Allocator,
    workspace_root: []const u8,
    preset: policy_mod.presets.AgentPreset,
) !EnsurePacksResult {
    const desired = presetOptInPacks(preset);
    if (desired.len == 0) {
        return .{
            .message = "Packs: baseline only",
            .changed = false,
            .owned = false,
        };
    }

    const resolved = try resolvePackConfigPath(io, allocator, workspace_root);
    errdefer allocator.free(resolved.path);

    const merge = try pack_config.mergeEnabledPacksIntoConfig(io, allocator, resolved.path, desired);
    defer {
        for (merge.final_enabled) |id| allocator.free(id);
        allocator.free(merge.final_enabled);
    }

    const list_msg = try formatEnabledPacksMessage(allocator, merge.final_enabled);
    errdefer allocator.free(list_msg);

    return .{
        .message = list_msg,
        .config_path = resolved.path,
        .scope = resolved.scope,
        .changed = merge.changed,
        .owned = true,
    };
}

pub fn ensurePresetPacksByName(
    io: std.Io,
    allocator: std.mem.Allocator,
    workspace_root: []const u8,
    preset_name: []const u8,
) !EnsurePacksResult {
    const preset = policy_mod.presets.AgentPreset.parse(preset_name) orelse {
        return .{
            .message = "Packs: baseline only",
            .changed = false,
            .owned = false,
        };
    };
    return ensurePresetPacks(io, allocator, workspace_root, preset);
}

fn formatEnabledPacksMessage(allocator: std.mem.Allocator, enabled: []const []const u8) ![]u8 {
    if (enabled.len == 0) return try allocator.dupe(u8, "Packs: baseline only");
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(allocator);
    try buf.appendSlice(allocator, "Enabled packs: ");
    for (enabled, 0..) |id, i| {
        if (i > 0) try buf.appendSlice(allocator, ", ");
        try buf.appendSlice(allocator, id);
    }
    return try buf.toOwnedSlice(allocator);
}

// ─── Tests ───────────────────────────────────────────────────────────────────

test "preset opt-in map: baseline vs infra vs coding" {
    try std.testing.expectEqual(@as(usize, 0), presetOptInPacks(.generic_agent).len);
    try std.testing.expectEqual(@as(usize, 0), presetOptInPacks(.solo_dev).len);
    try std.testing.expectEqualStrings("package_managers", presetOptInPacks(.claude_code)[0]);
    try std.testing.expectEqualStrings("package_managers", presetOptInPacks(.codex)[0]);
    try std.testing.expectEqualStrings("strict_git", presetOptInPacks(.strict_local)[0]);
    const team = presetOptInPacks(.team_ci);
    try std.testing.expect(team.len >= 3);
    try std.testing.expectEqualStrings("containers.docker", team[0]);
    const hermes = presetOptInPacks(.openclaw_hermes);
    try std.testing.expectEqualStrings("kubernetes.kubectl", hermes[2]);
    try std.testing.expectEqualStrings("infrastructure.terraform", hermes[3]);
}

test "summarizeFromPacksOutput separates baseline and opt-in" {
    const rows = [_]contracts.PackInfo{
        .{ .id = "core.git", .name = "Git", .category = "core", .description = "g", .enabled = true, .safe_pattern_count = 1, .destructive_pattern_count = 1 },
        .{ .id = "system.disk", .name = "Disk", .category = "system", .description = "d", .enabled = true, .safe_pattern_count = 1, .destructive_pattern_count = 1 },
        .{ .id = "containers.docker", .name = "Docker", .category = "containers", .description = "c", .enabled = true, .safe_pattern_count = 1, .destructive_pattern_count = 1 },
        .{ .id = "database.postgresql", .name = "PG", .category = "database", .description = "p", .enabled = false, .safe_pattern_count = 1, .destructive_pattern_count = 1 },
    };
    var summary = try summarizeFromPacksOutput(std.testing.allocator, .{
        .packs = &rows,
        .enabled_count = 3,
        .total_count = 4,
    });
    defer summary.deinit(std.testing.allocator);
    try std.testing.expect(summary.known);
    try std.testing.expectEqual(@as(usize, 1), summary.opt_in_ids.len);
    try std.testing.expectEqualStrings("containers.docker", summary.opt_in_ids[0]);
    const line = try formatSummaryLine(std.testing.allocator, summary);
    defer std.testing.allocator.free(line);
    try std.testing.expect(std.mem.indexOf(u8, line, "baseline + 1 opt-in") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "containers.docker") != null);
}

test "ensurePresetPacks writes project config and is idempotent" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_z = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root_z);
    const root = try std.testing.allocator.dupe(u8, root_z);
    defer std.testing.allocator.free(root);

    try tmp.dir.createDirPath(std.testing.io, ".git");

    var first = try ensurePresetPacks(std.testing.io, std.testing.allocator, root, .team_ci);
    defer first.deinit(std.testing.allocator);
    try std.testing.expect(first.changed);
    try std.testing.expect(first.scope == .project);
    try std.testing.expect(std.mem.indexOf(u8, first.message, "containers.docker") != null);

    const config = try tmp.dir.readFileAlloc(std.testing.io, ".ryk.toml", std.testing.allocator, .limited(8192));
    defer std.testing.allocator.free(config);
    try std.testing.expect(std.mem.indexOf(u8, config, "containers.docker") != null);
    try std.testing.expect(std.mem.indexOf(u8, config, "kubernetes.kubectl") != null);
    try std.testing.expect(std.mem.indexOf(u8, config, "cicd.github_actions") != null);

    var second = try ensurePresetPacks(std.testing.io, std.testing.allocator, root, .team_ci);
    defer second.deinit(std.testing.allocator);
    try std.testing.expect(!second.changed);

    // Adding another preset merges without wiping.
    var third = try ensurePresetPacks(std.testing.io, std.testing.allocator, root, .claude_code);
    defer third.deinit(std.testing.allocator);
    try std.testing.expect(third.changed);
    const config2 = try tmp.dir.readFileAlloc(std.testing.io, ".ryk.toml", std.testing.allocator, .limited(8192));
    defer std.testing.allocator.free(config2);
    try std.testing.expect(std.mem.indexOf(u8, config2, "containers.docker") != null);
    try std.testing.expect(std.mem.indexOf(u8, config2, "package_managers") != null);
}

test "generic-agent ensure leaves baseline only without writing" {
    const plugin = @import("plugin.zig");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_z = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root_z);
    const root = try std.testing.allocator.dupe(u8, root_z);
    defer std.testing.allocator.free(root);
    try tmp.dir.createDirPath(std.testing.io, ".git");

    var result = try ensurePresetPacks(std.testing.io, std.testing.allocator, root, .generic_agent);
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(!result.changed);
    try std.testing.expectEqualStrings("Packs: baseline only", result.message);
    const cfg_path = try std.fs.path.join(std.testing.allocator, &.{ root, ".ryk.toml" });
    defer std.testing.allocator.free(cfg_path);
    try std.testing.expect(!plugin.fileExistsAbsolute(std.testing.io, cfg_path));
}

test "doctor packs section labels are stable" {
    var buf: [1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    const ids = [_][]const u8{ "containers.docker", "kubernetes.kubectl" };
    const summary: PacksSummary = .{
        .known = true,
        .total_enabled = 4,
        .total_available = 10,
        .opt_in_ids = &ids,
        .owned = false,
    };
    try writeDoctorPacksSection(&writer, summary);
    const out = writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "\nPacks\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "baseline: core.*, system.disk") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "opt-in: 2 enabled") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "containers.docker") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "ryk packs show") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "ryk packs enable") != null);

    writer = .fixed(&buf);
    try writeDoctorPacksSection(&writer, unknownPacksSummary());
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "unknown (packs inventory offline") != null);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "shell evaluate is Zig in-process") != null);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "shell evaluation fails closed") == null);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "ryk packs") != null);
}

test "merge does not promote disabled packs into enabled" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_z = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root_z);
    const root = try std.testing.allocator.dupe(u8, root_z);
    defer std.testing.allocator.free(root);
    try tmp.dir.createDirPath(std.testing.io, ".git");

    const seed =
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

    var result = try ensurePresetPacks(std.testing.io, std.testing.allocator, root, .team_ci);
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(result.changed);

    const config = try tmp.dir.readFileAlloc(std.testing.io, ".ryk.toml", std.testing.allocator, .limited(8192));
    defer std.testing.allocator.free(config);
    try std.testing.expect(std.mem.indexOf(u8, config, "containers.docker") != null);
    try std.testing.expect(std.mem.indexOf(u8, config, "package_managers") != null);
    try std.testing.expect(std.mem.indexOf(u8, config, "disabled = [\"system.disk\"]") != null);

    // system.disk must remain only under disabled, not be copied into enabled.
    // Use a simple scan of the enabled key region after merge.
    const enabled_key = std.mem.indexOf(u8, config, "enabled") orelse {
        try std.testing.expect(false);
        return;
    };
    const disabled_key = std.mem.indexOf(u8, config, "disabled") orelse config.len;
    const enabled_region = if (enabled_key < disabled_key) config[enabled_key..disabled_key] else config[enabled_key..];
    try std.testing.expect(std.mem.indexOf(u8, enabled_region, "system.disk") == null);
}

test "formatSummaryLine baseline invites packs enable" {
    const line = try formatSummaryLine(std.testing.allocator, .{
        .known = true,
        .total_enabled = 2,
        .total_available = 10,
        .opt_in_ids = &.{},
        .owned = false,
    });
    defer std.testing.allocator.free(line);
    try std.testing.expect(std.mem.indexOf(u8, line, "baseline only") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "packs enable") != null);
}

// Ensure pack_config unit tests are linked when this module is tested via pack_state imports.
test {
    _ = @import("pack_config.zig");
}

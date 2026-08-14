//! Launch-time agent-inference network overlay (AINA P1 seed + P3 discovery merge).
//!
//! Product call site stays in `run.zig`:
//! `applyNetworkOverlayWithHostKey(..., launch_host_id.hostKey(), discovery)`.
//! This file owns overlay merge only — not spawn, attach, grade, or env install.
//! Overlay is not OS-enforced. Missing managed / empty home / empty adapter
//! soft-skip; never fail launch for discovery or missing `auth.json`.

const std = @import("std");

const core = @import("ryk_core").core;
const policy = @import("ryk_core").policy;
const intercept = @import("../intercept/mod.zig");

const run_mod = @import("run.zig");
const RunOptions = run_mod.RunOptions;
const AgentNetworkDefault = run_mod.AgentNetworkDefault;
const wantsMediatedAgentNetwork = run_mod.wantsMediatedAgentNetwork;
const cliNetworkMode = run_mod.cliNetworkMode;
const installNetworkEnvironment = run_mod.installNetworkEnvironment;

/// Basename of argv0 for unit-test / fallback overlay selection when the product
/// call site has not supplied a resolved trusted host key.
pub fn hostKeyFromCommandArgv(options: RunOptions) ?[]const u8 {
    if (options.command_argv.len == 0) return null;
    const base = std.fs.path.basename(options.command_argv[0]);
    if (base.len == 0) return null;
    return base;
}

/// Launch-time discovery context for AINA P3 (plan §3.6 S4).
/// When null, pack-only (P1) path. Product always supplies abs workspace_root + parent HOME.
pub const DiscoveryLaunchContext = struct {
    io: std.Io,
    /// Absolute workspace root; managed file is always `<root>/.ryk/network-discovered.yaml`.
    workspace_root: []const u8,
    /// Parent-process HOME for `discoverForHost` (may be empty → adapter soft-empty).
    home: []const u8,
};

/// Test-facing entry: overlay host key is derived from `command_argv[0]` basename.
pub fn applyNetworkOverlay(
    allocator: std.mem.Allocator,
    selected_policy: *policy.schema.Policy,
    options: RunOptions,
    agent_net_default: AgentNetworkDefault,
    trusted_agent_host: bool,
) !void {
    try applyNetworkOverlayWithHostKey(
        allocator,
        selected_policy,
        options,
        agent_net_default,
        trusted_agent_host,
        hostKeyFromCommandArgv(options),
        null,
    );
}

/// Product + test implementation. When `host_key` is non-null it selects the host
/// overlay (EFF-2); null seeds core pack only. Seed runs only under mediated +
/// trusted host-alias (`wantsMediatedAgentNetwork`); never under legacy/open/untrusted.
///
/// Merge order when `discovery` is non-null and mediated trusted (AINA P3 S4):
///   existing policy ∪ core ∪ host_overlay
///     ∪ managed hosts (`loadManaged`, soft-empty on missing/corrupt)
///     ∪ launch-time adapter (`discoverForHost`, soft-empty)
///     then CLI `--allow-network` (EFF-3)
/// Soft skip: missing managed / empty home / adapter empty → pack floor retained;
/// never fail launch for discovery. Null discovery = P1 pack-only path.
///
/// Ownership: after seed, `network.allow` is fully allocator-owned (every string +
/// outer slice). CLI `--allow-network` appends transfer prior string ownership into
/// a new outer slice and free only the previous outer pointer.
pub fn applyNetworkOverlayWithHostKey(
    allocator: std.mem.Allocator,
    selected_policy: *policy.schema.Policy,
    options: RunOptions,
    agent_net_default: AgentNetworkDefault,
    trusted_agent_host: bool,
    host_key: ?[]const u8,
    discovery: ?DiscoveryLaunchContext,
) !void {
    selected_policy.network.mode = cliNetworkMode(options, agent_net_default, trusted_agent_host);
    if (wantsMediatedAgentNetwork(options, agent_net_default, trusted_agent_host)) {
        // Host aliases: always force proxy (overrides decision-only) so labels are not theater.
        selected_policy.network.backend = .proxy;

        // Seed even when CLI --allow-network is empty (must not early-return past this).
        // Floor: existing policy ∪ core ∪ host_overlay (P1).
        const old_seed_allow = selected_policy.network.allow;
        const merged = try policy.agent_inference_hosts.mergeAllowList(
            allocator,
            host_key,
            old_seed_allow,
        );
        policy.schema.freeStringList(allocator, old_seed_allow);
        selected_policy.network.allow = merged;

        // P3: ∪ managed ∪ launch-time adapter (soft skip; never wipe user allows).
        if (discovery) |ctx| {
            try mergeDiscoveryIntoAllow(allocator, selected_policy, host_key, ctx);
        }
    } else if (options.network_backend) |backend| {
        selected_policy.network.backend = backend;
    }

    // CLI --allow-network after seed (EFF-3); no-op when empty keeps seed-only list.
    const runtime_allow = options.allowNetwork();
    if (runtime_allow.len == 0) return;

    const old_allow = selected_policy.network.allow;
    const old_len = old_allow.len;
    var next = try allocator.alloc([]const u8, old_len + runtime_allow.len);
    errdefer allocator.free(next);
    for (old_allow, 0..) |value, index| next[index] = value;
    var copied: usize = 0;
    errdefer {
        for (next[old_len .. old_len + copied]) |value| allocator.free(value);
    }
    for (runtime_allow, 0..) |value, index| {
        if (std.mem.startsWith(u8, value, "*.")) {
            next[old_len + index] = try allocator.dupe(u8, value);
        } else {
            const destination = try intercept.network.parseDestination(value);
            next[old_len + index] = try destination.endpointDisplay(allocator);
        }
        copied += 1;
    }
    if (old_allow.len > 0) allocator.free(old_allow);
    selected_policy.network.allow = next;
}

/// Merge managed store + launch-time adapter hosts into `network.allow`.
/// Soft-skip missing/corrupt managed and empty/unknown adapter results.
/// Managed entries are filtered by host_key source tags (no cross-host bleed).
/// Preserves every pre-existing allow entry (A-P3-3 / EFF-4). Hostnames only (SEC-3).
fn mergeDiscoveryIntoAllow(
    allocator: std.mem.Allocator,
    selected_policy: *policy.schema.Policy,
    host_key: ?[]const u8,
    ctx: DiscoveryLaunchContext,
) !void {
    var store = try policy.network_discovered.loadManaged(ctx.io, allocator, ctx.workspace_root);
    defer store.deinit(allocator);

    // All contrib strings are owned (duped managed + owned discover) so free is uniform.
    var contrib: std.ArrayList([]const u8) = .empty;
    var contrib_live = true;
    errdefer if (contrib_live) {
        for (contrib.items) |h| allocator.free(h);
        contrib.deinit(allocator);
    };

    const key = host_key orelse "";
    if (key.len > 0) {
        for (store.hosts) |entry| {
            if (!policy.network_discovered.managedEntryMatchesHostKey(entry, key)) continue;
            const owned = try allocator.dupe(u8, entry.host);
            errdefer allocator.free(owned);
            try contrib.append(allocator, owned);
        }

        const discovered = try policy.inference_discover.discoverForHost(
            ctx.io,
            allocator,
            key,
            ctx.home,
        );
        defer policy.schema.freeStringList(allocator, discovered);
        for (discovered) |h| {
            const owned = try allocator.dupe(u8, h);
            errdefer allocator.free(owned);
            try contrib.append(allocator, owned);
        }
    }

    if (contrib.items.len == 0) {
        contrib.deinit(allocator);
        contrib_live = false;
        return;
    }

    const old_allow = selected_policy.network.allow;
    const next = try policy.network_discovered.mergePreserveUserAllows(
        allocator,
        old_allow,
        contrib.items,
    );
    policy.schema.freeStringList(allocator, old_allow);
    selected_policy.network.allow = next;
    // mergePreserve duped inputs — free our owned contrib list; disarm errdefer.
    for (contrib.items) |h| allocator.free(h);
    contrib.deinit(allocator);
    contrib_live = false;
}

test "applyNetworkOverlay defaults to ask and does not force allowlist for --allow-network alone" {
    var pol: policy.schema.Policy = .{ .allocator = std.testing.allocator };
    defer pol.network.deinit(std.testing.allocator);
    pol.network.mode = .allowlist; // preset-like; CLI default must override for non-alias

    try applyNetworkOverlay(std.testing.allocator, &pol, .{}, .mediated, false);
    try std.testing.expectEqual(policy.schema.NetworkMode.ask, pol.network.mode.?);
    // Non-alias: backend stays unset / decision_only unless user or policy set it.
    try std.testing.expect(pol.network.backend == null or pol.network.backend.? == .decision_only);

    pol.network.mode = .allowlist;
    var opts: RunOptions = .{};
    opts.allow_network_values[0] = "api.example.com";
    opts.allow_network_count = 1;
    try applyNetworkOverlay(std.testing.allocator, &pol, opts, .mediated, false);
    try std.testing.expectEqual(policy.schema.NetworkMode.ask, pol.network.mode.?);
    try std.testing.expect(pol.network.allow.len >= 1);

    try applyNetworkOverlay(std.testing.allocator, &pol, .{ .network_mode = .open }, .mediated, false);
    try std.testing.expectEqual(policy.schema.NetworkMode.open, pol.network.mode.?);

    try applyNetworkOverlay(std.testing.allocator, &pol, .{ .network_mode = .off }, .mediated, false);
    try std.testing.expectEqual(policy.schema.NetworkMode.off, pol.network.mode.?);
}

test "applyNetworkOverlay trusted host-alias defaults force proxy backend and allowlist mode" {
    var pol: policy.schema.Policy = .{ .allocator = std.testing.allocator };
    defer pol.network.deinit(std.testing.allocator);
    pol.network.mode = .ask;
    pol.network.backend = null;

    const host_opts: RunOptions = .{ .command_argv = &.{"pi"} };
    try applyNetworkOverlay(std.testing.allocator, &pol, host_opts, .mediated, true);
    try std.testing.expectEqual(policy.schema.NetworkMode.allowlist, pol.network.mode.?);
    try std.testing.expectEqual(policy.schema.NetworkBackend.proxy, pol.network.backend.?);
    try std.testing.expectEqual(policy.schema.NetworkBackend.proxy, pol.network.effectiveBackend());
    try std.testing.expect(wantsMediatedAgentNetwork(host_opts, .mediated, true));

    // Basename-only (untrusted): no mediation force.
    pol.network.backend = null;
    pol.network.mode = .ask;
    try applyNetworkOverlay(std.testing.allocator, &pol, host_opts, .mediated, false);
    try std.testing.expectEqual(policy.schema.NetworkMode.ask, pol.network.mode.?);
    try std.testing.expect(pol.network.backend == null);
    try std.testing.expect(!wantsMediatedAgentNetwork(host_opts, .mediated, false));

    // --network open: no proxy force, mediation off.
    pol.network.backend = null;
    const open_opts: RunOptions = .{ .command_argv = &.{"pi"}, .network_mode = .open };
    try applyNetworkOverlay(std.testing.allocator, &pol, open_opts, .mediated, true);
    try std.testing.expectEqual(policy.schema.NetworkMode.open, pol.network.mode.?);
    try std.testing.expect(pol.network.backend == null);
    try std.testing.expectEqual(policy.schema.NetworkBackend.decision_only, pol.network.effectiveBackend());
    try std.testing.expect(!wantsMediatedAgentNetwork(open_opts, .mediated, true));

    // decision-only does not disable mediation: still force proxy on trusted hosts.
    pol.network.backend = .decision_only;
    try applyNetworkOverlay(std.testing.allocator, &pol, .{
        .command_argv = &.{"pi"},
        .network_backend = .decision_only,
    }, .mediated, true);
    try std.testing.expectEqual(policy.schema.NetworkBackend.proxy, pol.network.backend.?);
    try std.testing.expect(wantsMediatedAgentNetwork(.{
        .command_argv = &.{"pi"},
        .network_backend = .decision_only,
    }, .mediated, true));

    // Explicit --network-backend proxy still works with mediation.
    pol.network.backend = null;
    try applyNetworkOverlay(std.testing.allocator, &pol, .{
        .command_argv = &.{"claude"},
        .network_backend = .proxy,
        .network_mode = .allowlist,
    }, .mediated, true);
    try std.testing.expectEqual(policy.schema.NetworkBackend.proxy, pol.network.backend.?);

    // Kill switch restores legacy (no forced proxy / allowlist default).
    pol.network.backend = null;
    pol.network.mode = .ask;
    try applyNetworkOverlay(std.testing.allocator, &pol, host_opts, .legacy, true);
    try std.testing.expectEqual(policy.schema.NetworkMode.ask, pol.network.mode.?);
    try std.testing.expect(pol.network.backend == null);
    try std.testing.expect(!wantsMediatedAgentNetwork(host_opts, .legacy, true));

    // Non-alias run still does not force proxy.
    pol.network.backend = null;
    try applyNetworkOverlay(std.testing.allocator, &pol, .{ .command_argv = &.{"/bin/true"} }, .mediated, false);
    try std.testing.expectEqual(policy.schema.NetworkMode.ask, pol.network.mode.?);
    try std.testing.expect(pol.network.backend == null);
}

// ---------------------------------------------------------------------------
// Agent-inference allow seed (AINA-2026-08-02)
// Mediated + trusted host-alias launches seed core_pack ∪ host_overlay into
// network.allow; legacy / open / non-alias / untrusted must not seed.
// Production passes resolved trusted_host_key into applyNetworkOverlayWithHostKey.
// Basename-derived applyNetworkOverlay is test-only convenience.
// ---------------------------------------------------------------------------

fn testNetworkAllowContains(allow: []const []const u8, host: []const u8) bool {
    for (allow) |entry| {
        if (std.mem.eql(u8, entry, host)) return true;
    }
    return false;
}

/// Spec §5.1 core pack minima (independent of pack module implementation).
fn expectCorePackOnAllow(allow: []const []const u8) !void {
    try std.testing.expect(testNetworkAllowContains(allow, "api.anthropic.com"));
    try std.testing.expect(testNetworkAllowContains(allow, "api.openai.com"));
    try std.testing.expect(testNetworkAllowContains(allow, "api.x.ai"));
}

/// No agent pack or any §5.2 overlay host may appear (no-seed / fail-closed paths).
fn expectNoAgentInferencePackOrOverlay(allow: []const []const u8) !void {
    try std.testing.expect(!testNetworkAllowContains(allow, "api.anthropic.com"));
    try std.testing.expect(!testNetworkAllowContains(allow, "api.openai.com"));
    try std.testing.expect(!testNetworkAllowContains(allow, "api.x.ai"));
    try std.testing.expect(!testNetworkAllowContains(allow, "openrouter.ai"));
    try std.testing.expect(!testNetworkAllowContains(allow, "opencode.ai"));
    try std.testing.expect(!testNetworkAllowContains(allow, "models.opencode.ai"));
    try std.testing.expect(!testNetworkAllowContains(allow, "cli-chat-proxy.grok.com"));
    try std.testing.expect(!testNetworkAllowContains(allow, "auth.x.ai"));
}

test "applyNetworkOverlay seeds core pack and pi overlay on mediated trusted host-alias with empty allow and no CLI --allow-network" {
    // Must not early-return past seed when CLI --allow-network is absent.
    const allocator = std.testing.allocator;
    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), pol.network.allow.len);
    try std.testing.expectEqual(@as(usize, 0), (@as(RunOptions, .{})).allow_network_count);

    const opts: RunOptions = .{ .command_argv = &.{"pi"} };
    try applyNetworkOverlay(allocator, &pol, opts, .mediated, true);

    try std.testing.expectEqual(policy.schema.NetworkMode.allowlist, pol.network.mode.?);
    try std.testing.expectEqual(policy.schema.NetworkBackend.proxy, pol.network.backend.?);
    try expectCorePackOnAllow(pol.network.allow);
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "openrouter.ai"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "models.opencode.ai"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "opencode.ai"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "cli-chat-proxy.grok.com"));
}

test "applyNetworkOverlayWithHostKey seeds pi overlay when host_key differs from argv basename" {
    // Product path: trusted_host_key drives overlay, not argv leaf (node/script wrappers).
    const allocator = std.testing.allocator;
    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);

    try applyNetworkOverlayWithHostKey(
        allocator,
        &pol,
        .{ .command_argv = &.{"/usr/local/bin/cli.js"} },
        .mediated,
        true,
        "pi",
        null,
    );

    try expectCorePackOnAllow(pol.network.allow);
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "openrouter.ai"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "models.opencode.ai"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "opencode.ai"));
}

test "applyNetworkOverlayWithHostKey seeds opencode overlay when host_key differs from argv basename" {
    const allocator = std.testing.allocator;
    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);

    try applyNetworkOverlayWithHostKey(
        allocator,
        &pol,
        .{ .command_argv = &.{"/opt/node"} },
        .mediated,
        true,
        "opencode",
        null,
    );

    try expectCorePackOnAllow(pol.network.allow);
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "opencode.ai"));
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "models.opencode.ai"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "openrouter.ai"));
}

test "applyNetworkOverlayWithHostKey null host_key seeds core pack only" {
    const allocator = std.testing.allocator;
    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);

    try applyNetworkOverlayWithHostKey(
        allocator,
        &pol,
        .{ .command_argv = &.{"claude"} },
        .mediated,
        true,
        null,
        null,
    );

    try expectCorePackOnAllow(pol.network.allow);
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "openrouter.ai"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "opencode.ai"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "models.opencode.ai"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "cli-chat-proxy.grok.com"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "auth.x.ai"));
}

test "applyNetworkOverlay seeds core pack and opencode overlay on mediated trusted host-alias" {
    const allocator = std.testing.allocator;
    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);

    try applyNetworkOverlay(allocator, &pol, .{ .command_argv = &.{"opencode"} }, .mediated, true);

    try expectCorePackOnAllow(pol.network.allow);
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "opencode.ai"));
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "models.opencode.ai"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "openrouter.ai"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "cli-chat-proxy.grok.com"));
}

test "applyNetworkOverlay seeds core and overlay into stale github-only policy allow without dropping existing" {
    // A-seed / EFF-3/4/5: stale workspace allow (github/npm) still gains pack; existing kept.
    const allocator = std.testing.allocator;
    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);
    pol.network.allow = try policy.schema.duplicateStringList(allocator, &.{
        "github.com",
        "registry.npmjs.org",
    });

    try applyNetworkOverlay(allocator, &pol, .{ .command_argv = &.{"pi"} }, .mediated, true);

    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "github.com"));
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "registry.npmjs.org"));
    try expectCorePackOnAllow(pol.network.allow);
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "openrouter.ai"));
}

test "applyNetworkOverlay seed composes CLI --allow-network after pack without removing policy allows" {
    // A-composition / EFF-3: policy ∪ pack/overlay ∪ CLI --allow-network.
    const allocator = std.testing.allocator;
    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);
    pol.network.allow = try policy.schema.duplicateStringList(allocator, &.{"github.com"});

    var opts: RunOptions = .{ .command_argv = &.{"opencode"} };
    opts.allow_network_values[0] = "api.custom-provider.example";
    opts.allow_network_count = 1;

    try applyNetworkOverlay(allocator, &pol, opts, .mediated, true);

    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "github.com"));
    try expectCorePackOnAllow(pol.network.allow);
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "opencode.ai"));
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "models.opencode.ai"));
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "api.custom-provider.example"));
}

test "applyNetworkOverlay core-only host-alias seeds core pack without foreign host overlays" {
    // A-seed / PKG-2: claude is core-only at P1 (no pi/opencode/grok overlay pollution).
    const allocator = std.testing.allocator;
    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);

    try applyNetworkOverlay(allocator, &pol, .{ .command_argv = &.{"claude"} }, .mediated, true);

    try expectCorePackOnAllow(pol.network.allow);
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "openrouter.ai"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "opencode.ai"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "models.opencode.ai"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "cli-chat-proxy.grok.com"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "auth.x.ai"));
}

test "applyNetworkOverlay does not seed agent pack when agent_net_default is legacy" {
    // A-no-seed: RYK_AGENT_NETWORK_DEFAULT=legacy kill switch — no pack theater.
    const allocator = std.testing.allocator;
    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);
    pol.network.allow = try policy.schema.duplicateStringList(allocator, &.{"github.com"});

    try applyNetworkOverlay(allocator, &pol, .{ .command_argv = &.{"pi"} }, .legacy, true);

    try std.testing.expectEqual(policy.schema.NetworkMode.ask, pol.network.mode.?);
    try std.testing.expect(pol.network.backend == null);
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "github.com"));
    try expectNoAgentInferencePackOrOverlay(pol.network.allow);
}

test "applyNetworkOverlay does not seed agent pack when network_mode is open" {
    // A-no-seed: --network open escape — unrestricted; no pack seed / no allowlist theater.
    const allocator = std.testing.allocator;
    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);

    try applyNetworkOverlay(allocator, &pol, .{
        .command_argv = &.{"pi"},
        .network_mode = .open,
    }, .mediated, true);

    try std.testing.expectEqual(policy.schema.NetworkMode.open, pol.network.mode.?);
    try expectNoAgentInferencePackOrOverlay(pol.network.allow);
}

test "applyNetworkOverlay does not seed agent pack when trusted_agent_host is false (basename spoof)" {
    // A-no-seed / F-02: untrusted / basename spoof — command looks like pi but not trusted.
    const allocator = std.testing.allocator;
    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);

    try applyNetworkOverlay(allocator, &pol, .{ .command_argv = &.{"pi"} }, .mediated, false);

    try std.testing.expectEqual(policy.schema.NetworkMode.ask, pol.network.mode.?);
    try expectNoAgentInferencePackOrOverlay(pol.network.allow);
}

test "applyNetworkOverlay does not seed agent pack for non-alias command even under mediated default" {
    // A-no-seed / PKG-3: generic ryk run -- <cmd> must not silently gain agent overlays.
    const allocator = std.testing.allocator;
    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);

    try applyNetworkOverlay(allocator, &pol, .{ .command_argv = &.{"/bin/true"} }, .mediated, false);

    try std.testing.expectEqual(policy.schema.NetworkMode.ask, pol.network.mode.?);
    try expectNoAgentInferencePackOrOverlay(pol.network.allow);
}

test "applyNetworkOverlay non-alias with CLI --allow-network still does not seed agent pack" {
    // A-no-seed + composition: CLI allow alone must not pull core pack/overlays for non-alias.
    const allocator = std.testing.allocator;
    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);

    var opts: RunOptions = .{ .command_argv = &.{"/bin/true"} };
    opts.allow_network_values[0] = "api.example.com";
    opts.allow_network_count = 1;

    try applyNetworkOverlay(allocator, &pol, opts, .mediated, false);

    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "api.example.com"));
    try expectNoAgentInferencePackOrOverlay(pol.network.allow);
}

// AINA P3 launch wire — discovery merge into applyNetworkOverlayWithHostKey (S4).

/// Synthetic pi auth.json shape (fake tokens only). xai-oauth URL hosts + openrouter id.
const p3_launch_pi_auth_json =
    \\{
    \\  "openrouter": {
    \\    "type": "api_key",
    \\    "key": "sk-fixture-launch-pi-openrouter-NOT-REAL-a1"
    \\  },
    \\  "xai-oauth": {
    \\    "type": "oauth",
    \\    "access": "fixture-launch-pi-xai-access-NOT-REAL-b2",
    \\    "refresh": "fixture-launch-pi-xai-refresh-NOT-REAL-c3",
    \\    "tokenEndpoint": "https://auth.x.ai/oauth2/token",
    \\    "baseUrl": "https://api.x.ai/v1"
    \\  }
    \\}
;

/// Pi settings with defaultProvider openrouter (catalog path).
const p3_launch_pi_settings_json =
    \\{
    \\  "defaultProvider": "openrouter",
    \\  "model": "openrouter/fixture-launch-model"
    \\}
;

/// Opencode auth: xai oauth key → catalog api.x.ai + auth.x.ai; opencode key → overlay hosts.
const p3_launch_opencode_auth_json =
    \\{
    \\  "xai": {
    \\    "type": "oauth",
    \\    "access": "fixture-launch-oc-xai-access-NOT-REAL-d4",
    \\    "refresh": "fixture-launch-oc-xai-refresh-NOT-REAL-e5"
    \\  },
    \\  "opencode": {
    \\    "type": "api",
    \\    "key": "sk-fixture-launch-oc-api-NOT-REAL-f6"
    \\  }
    \\}
;

/// Pi auth with URL hosts that catalog cannot invent (proves adapter extract is wired).
const p3_launch_pi_url_diverge_auth_json =
    \\{
    \\  "xai-oauth": {
    \\    "type": "oauth",
    \\    "access": "fixture-launch-pi-diverge-access-NOT-REAL-g7",
    \\    "refresh": "fixture-launch-pi-diverge-refresh-NOT-REAL-h8",
    \\    "tokenEndpoint": "https://oauth-edge.custom.invalid/oauth2/token",
    \\    "baseUrl": "https://inference-proxy.custom.invalid/v1"
    \\  }
    \\}
;

const p3_launch_fixture_secret_needles = [_][]const u8{
    "sk-fixture-launch-pi-openrouter-NOT-REAL-a1",
    "fixture-launch-pi-xai-access-NOT-REAL-b2",
    "fixture-launch-pi-xai-refresh-NOT-REAL-c3",
    "fixture-launch-oc-xai-access-NOT-REAL-d4",
    "fixture-launch-oc-xai-refresh-NOT-REAL-e5",
    "sk-fixture-launch-oc-api-NOT-REAL-f6",
    "fixture-launch-pi-diverge-access-NOT-REAL-g7",
    "fixture-launch-pi-diverge-refresh-NOT-REAL-h8",
    "sk-fixture",
    "NOT-REAL",
};

fn p3LaunchAbsPath(tmp: anytype) ![]u8 {
    // realPathFileAlloc → [:0]u8; re-dupe so free size matches DebugAllocator (Zig 0.16).
    const z = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(z);
    return try std.testing.allocator.dupe(u8, z);
}

fn p3LaunchWriteRel(dir: anytype, rel: []const u8, content: []const u8) !void {
    if (std.fs.path.dirname(rel)) |parent| {
        if (parent.len > 0) try dir.createDirPath(std.testing.io, parent);
    }
    const file = try dir.createFile(std.testing.io, rel, .{});
    defer file.close(std.testing.io);
    try file.writeStreamingAll(std.testing.io, content);
}

fn p3LaunchPlantPiHome(home_dir: anytype, auth: []const u8, settings: ?[]const u8) !void {
    try p3LaunchWriteRel(home_dir, ".pi/agent/auth.json", auth);
    if (settings) |s| try p3LaunchWriteRel(home_dir, ".pi/agent/settings.json", s);
}

fn p3LaunchPlantOpencodeHome(home_dir: anytype, auth: []const u8) !void {
    try p3LaunchWriteRel(home_dir, ".local/share/opencode/auth.json", auth);
}

fn p3LaunchAssertNoSecretsInAllow(allow: []const []const u8) !void {
    for (allow) |entry| {
        for (p3_launch_fixture_secret_needles) |needle| {
            try std.testing.expect(std.mem.indexOf(u8, entry, needle) == null);
        }
        try std.testing.expect(std.mem.indexOf(u8, entry, "://") == null);
        try std.testing.expect(std.mem.indexOf(u8, entry, "@") == null);
    }
}

fn p3LaunchExpectNetworkResult(
    allocator: std.mem.Allocator,
    pol: *const policy.schema.Policy,
    destination: []const u8,
    want: core.decision.DecisionResult,
) !void {
    var decision = try policy.network_eval.evaluate(allocator, pol, .strict, destination, .{});
    defer decision.deinit(allocator);
    try std.testing.expectEqual(want, decision.decision.result);
}

test "applyNetworkOverlayWithHostKey P3 managed hosts merge for pi with pack floor and user preserve" {
    // Unit acceptance: fixture managed hosts ∪ core/overlay floor; user pre-seed kept.
    // auth.x.ai is NOT in pi static overlay — only discovery/managed can add it for pi.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    const workspace_root = try p3LaunchAbsPath(&ws_tmp);
    defer allocator.free(workspace_root);

    const managed_entries = [_]policy.network_discovered.ManagedHost{
        .{ .host = "auth.x.ai", .sources = &.{"pi:discover"} },
        .{ .host = "launch-managed-only.invalid", .sources = &.{"pi:discover"} },
    };
    try policy.network_discovered.writeManaged(io, allocator, workspace_root, &managed_entries);

    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);
    pol.network.allow = try policy.schema.duplicateStringList(allocator, &.{
        "github.com",
        "registry.npmjs.org",
    });

    // Empty home → adapter soft-empty; managed file alone must still merge.
    try applyNetworkOverlayWithHostKey(
        allocator,
        &pol,
        .{ .command_argv = &.{"/usr/bin/node"} },
        .mediated,
        true,
        "pi",
        .{ .io = io, .workspace_root = workspace_root, .home = "" },
    );

    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "github.com"));
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "registry.npmjs.org"));
    try expectCorePackOnAllow(pol.network.allow);
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "openrouter.ai")); // pi overlay floor
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "auth.x.ai"));
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "launch-managed-only.invalid"));
    try p3LaunchAssertNoSecretsInAllow(pol.network.allow);
}

test "applyNetworkOverlayWithHostKey P3 launch-time pi adapter discovers auth.x.ai from fixture home" {
    // Launch-time discoverForHost(pi) must run even when managed file is missing (plan §3.6).
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    const workspace_root = try p3LaunchAbsPath(&ws_tmp);
    defer allocator.free(workspace_root);

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    try p3LaunchPlantPiHome(home_tmp.dir, p3_launch_pi_auth_json, p3_launch_pi_settings_json);
    const home = try p3LaunchAbsPath(&home_tmp);
    defer allocator.free(home);

    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);

    try applyNetworkOverlayWithHostKey(
        allocator,
        &pol,
        .{ .command_argv = &.{"pi"} },
        .mediated,
        true,
        "pi",
        .{ .io = io, .workspace_root = workspace_root, .home = home },
    );

    try expectCorePackOnAllow(pol.network.allow);
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "openrouter.ai"));
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "auth.x.ai"));
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "api.x.ai"));
    try p3LaunchAssertNoSecretsInAllow(pol.network.allow);
}

test "applyNetworkOverlayWithHostKey P3 launch-time opencode adapter maps xai catalog hosts" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    const workspace_root = try p3LaunchAbsPath(&ws_tmp);
    defer allocator.free(workspace_root);

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    try p3LaunchPlantOpencodeHome(home_tmp.dir, p3_launch_opencode_auth_json);
    const home = try p3LaunchAbsPath(&home_tmp);
    defer allocator.free(home);

    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);

    try applyNetworkOverlayWithHostKey(
        allocator,
        &pol,
        .{ .command_argv = &.{"opencode"} },
        .mediated,
        true,
        "opencode",
        .{ .io = io, .workspace_root = workspace_root, .home = home },
    );

    try expectCorePackOnAllow(pol.network.allow);
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "opencode.ai"));
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "models.opencode.ai"));
    // Catalog hosts for auth key `xai` (not in opencode static overlay).
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "auth.x.ai"));
    try p3LaunchAssertNoSecretsInAllow(pol.network.allow);
}

test "applyNetworkOverlayWithHostKey P3 managed union adapter for pi URL-diverge hosts" {
    // Managed + launch adapter: URL extract hosts cannot come from static pack alone.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    const workspace_root = try p3LaunchAbsPath(&ws_tmp);
    defer allocator.free(workspace_root);

    const managed_entries = [_]policy.network_discovered.ManagedHost{
        .{ .host = "managed-from-start.invalid", .sources = &.{"pi:discover"} },
    };
    try policy.network_discovered.writeManaged(io, allocator, workspace_root, &managed_entries);

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    try p3LaunchPlantPiHome(home_tmp.dir, p3_launch_pi_url_diverge_auth_json, null);
    const home = try p3LaunchAbsPath(&home_tmp);
    defer allocator.free(home);

    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);
    pol.network.allow = try policy.schema.duplicateStringList(allocator, &.{"user-preseed.example"});

    try applyNetworkOverlayWithHostKey(
        allocator,
        &pol,
        .{ .command_argv = &.{"pi"} },
        .mediated,
        true,
        "pi",
        .{ .io = io, .workspace_root = workspace_root, .home = home },
    );

    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "user-preseed.example"));
    try expectCorePackOnAllow(pol.network.allow);
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "openrouter.ai"));
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "managed-from-start.invalid"));
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "oauth-edge.custom.invalid"));
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "inference-proxy.custom.invalid"));
    try p3LaunchAssertNoSecretsInAllow(pol.network.allow);
}

test "applyNetworkOverlayWithHostKey P3 pastebin and example.com still deny under network_eval after discovery merge" {
    // SEC-1 / A-P1-2/3 retained after P3: non-allow public hosts stay denied.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    const workspace_root = try p3LaunchAbsPath(&ws_tmp);
    defer allocator.free(workspace_root);

    const managed_entries = [_]policy.network_discovered.ManagedHost{
        .{ .host = "auth.x.ai", .sources = &.{"pi:discover"} },
    };
    try policy.network_discovered.writeManaged(io, allocator, workspace_root, &managed_entries);

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    try p3LaunchPlantPiHome(home_tmp.dir, p3_launch_pi_auth_json, p3_launch_pi_settings_json);
    const home = try p3LaunchAbsPath(&home_tmp);
    defer allocator.free(home);

    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);

    try applyNetworkOverlayWithHostKey(
        allocator,
        &pol,
        .{ .command_argv = &.{"pi"} },
        .mediated,
        true,
        "pi",
        .{ .io = io, .workspace_root = workspace_root, .home = home },
    );

    try std.testing.expectEqual(policy.schema.NetworkMode.allowlist, pol.network.mode.?);
    // Discovered / pack still allow.
    try p3LaunchExpectNetworkResult(allocator, &pol, "https://auth.x.ai/oauth2/token", .allow);
    try p3LaunchExpectNetworkResult(allocator, &pol, "https://api.x.ai/v1/chat", .allow);
    try p3LaunchExpectNetworkResult(allocator, &pol, "https://openrouter.ai/api/v1", .allow);
    // Closed default retained.
    try p3LaunchExpectNetworkResult(allocator, &pol, "https://pastebin.com/raw/abc", .deny);
    try p3LaunchExpectNetworkResult(allocator, &pol, "pastebin.com", .deny);
    try p3LaunchExpectNetworkResult(allocator, &pol, "https://example.com/", .deny);
    try p3LaunchExpectNetworkResult(allocator, &pol, "example.com", .deny);
}

test "applyNetworkOverlayWithHostKey P3 class tokens never land in allow; private/IMDS still deny" {
    // Blocker residual: hostile baseUrl private/metadata must not class-widen allow.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    const workspace_root = try p3LaunchAbsPath(&ws_tmp);
    defer allocator.free(workspace_root);

    // Poison managed file with class tokens (load must soft-drop).
    try ws_tmp.dir.createDirPath(io, ".ryk");
    {
        const f = try ws_tmp.dir.createFile(io, ".ryk/network-discovered.yaml", .{});
        defer f.close(io);
        try f.writeStreamingAll(io,
            \\version: 1
            \\hosts:
            \\  - host: private
            \\    sources: [pi:discover]
            \\  - host: metadata
            \\    sources: [pi:discover]
            \\  - host: direct-ip
            \\    sources: [pi:discover]
            \\  - host: metadata.google.internal
            \\    sources: [pi:discover]
            \\  - host: localhost
            \\    sources: [pi:discover]
            \\  - host: pastebin.com
            \\    sources: [pi:discover]
            \\
        );
    }

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    const hostile_auth =
        \\{
        \\  "hostile": {
        \\    "type": "api",
        \\    "key": "sk-fixture-hostile-class-NOT-REAL",
        \\    "baseUrl": "https://private/",
        \\    "tokenEndpoint": "https://metadata.google.internal/"
        \\  },
        \\  "local": {
        \\    "type": "api",
        \\    "key": "sk-fixture-local-NOT-REAL",
        \\    "baseUrl": "http://localhost:9/"
        \\  }
        \\}
    ;
    try p3LaunchPlantPiHome(home_tmp.dir, hostile_auth, null);
    const home = try p3LaunchAbsPath(&home_tmp);
    defer allocator.free(home);

    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);

    try applyNetworkOverlayWithHostKey(
        allocator,
        &pol,
        .{ .command_argv = &.{"pi"} },
        .mediated,
        true,
        "pi",
        .{ .io = io, .workspace_root = workspace_root, .home = home },
    );

    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "private"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "metadata"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "cloud-metadata"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "direct-ip"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "metadata.google.internal"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "localhost"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "pastebin.com"));
    // Class destinations still deny under allowlist (no class-wide grant).
    try p3LaunchExpectNetworkResult(allocator, &pol, "http://10.0.0.1/", .deny);
    try p3LaunchExpectNetworkResult(allocator, &pol, "http://169.254.169.254/latest/meta-data/", .deny);
    try p3LaunchExpectNetworkResult(allocator, &pol, "http://metadata.google.internal/", .deny);
    try p3LaunchExpectNetworkResult(allocator, &pol, "http://127.0.0.1:1/", .deny);
}

test "applyNetworkOverlayWithHostKey P3 rejects 127.0.0.2 planted in agent auth" {
    // Keep major residual: loopback residual is exact 127.0.0.1 only, not 127/8.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    const workspace_root = try p3LaunchAbsPath(&ws_tmp);
    defer allocator.free(workspace_root);

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    const hostile_auth =
        \\{
        \\  "local": {
        \\    "type": "api",
        \\    "key": "sk-fixture-127-wide-NOT-REAL",
        \\    "baseUrl": "http://127.0.0.2:9/v1"
        \\  }
        \\}
    ;
    try p3LaunchPlantPiHome(home_tmp.dir, hostile_auth, null);
    const home = try p3LaunchAbsPath(&home_tmp);
    defer allocator.free(home);

    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);

    try applyNetworkOverlayWithHostKey(
        allocator,
        &pol,
        .{ .command_argv = &.{"pi"} },
        .mediated,
        true,
        "pi",
        .{ .io = io, .workspace_root = workspace_root, .home = home },
    );

    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "127.0.0.2"));
    try p3LaunchExpectNetworkResult(allocator, &pol, "http://127.0.0.2:9/", .deny);
    try p3LaunchExpectNetworkResult(allocator, &pol, "http://127.1.2.3/", .deny);
}

test "applyNetworkOverlayWithHostKey P3 soft-skips missing managed and empty home still seeds pack floor" {
    // Soft skip: no managed file, empty home — launch still gets core∪overlay (P1 floor).
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    const workspace_root = try p3LaunchAbsPath(&ws_tmp);
    defer allocator.free(workspace_root);
    // Intentionally do not write managed YAML; home empty.

    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);

    try applyNetworkOverlayWithHostKey(
        allocator,
        &pol,
        .{ .command_argv = &.{"pi"} },
        .mediated,
        true,
        "pi",
        .{ .io = io, .workspace_root = workspace_root, .home = "" },
    );

    try expectCorePackOnAllow(pol.network.allow);
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "openrouter.ai"));
    // Discovery-only host must not appear without managed/adapter input.
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "launch-managed-only.invalid"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "oauth-edge.custom.invalid"));
}

test "applyNetworkOverlayWithHostKey P3 null discovery keeps P1 pack-only path" {
    // Backward-compat: discovery: null (or omitted default) must not require FS.
    const allocator = std.testing.allocator;
    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);

    try applyNetworkOverlayWithHostKey(
        allocator,
        &pol,
        .{ .command_argv = &.{"pi"} },
        .mediated,
        true,
        "pi",
        null,
    );

    try expectCorePackOnAllow(pol.network.allow);
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "openrouter.ai"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "launch-managed-only.invalid"));
}

test "applyNetworkOverlayWithHostKey P3 does not merge discovery when not mediated trusted" {
    // legacy / open / untrusted must not pull managed or adapter hosts.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    const workspace_root = try p3LaunchAbsPath(&ws_tmp);
    defer allocator.free(workspace_root);
    try policy.network_discovered.writeManaged(io, allocator, workspace_root, &.{
        .{ .host = "should-not-merge.invalid", .sources = &.{"pi:discover"} },
    });

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    try p3LaunchPlantPiHome(home_tmp.dir, p3_launch_pi_auth_json, null);
    const home = try p3LaunchAbsPath(&home_tmp);
    defer allocator.free(home);

    const discovery: DiscoveryLaunchContext = .{ .io = io, .workspace_root = workspace_root, .home = home };

    {
        var pol: policy.schema.Policy = .{ .allocator = allocator };
        defer pol.network.deinit(allocator);
        try applyNetworkOverlayWithHostKey(
            allocator,
            &pol,
            .{ .command_argv = &.{"pi"} },
            .legacy,
            true,
            "pi",
            discovery,
        );
        try expectNoAgentInferencePackOrOverlay(pol.network.allow);
        try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "should-not-merge.invalid"));
        try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "auth.x.ai"));
    }
    {
        var pol: policy.schema.Policy = .{ .allocator = allocator };
        defer pol.network.deinit(allocator);
        try applyNetworkOverlayWithHostKey(
            allocator,
            &pol,
            .{ .command_argv = &.{"pi"}, .network_mode = .open },
            .mediated,
            true,
            "pi",
            discovery,
        );
        try expectNoAgentInferencePackOrOverlay(pol.network.allow);
        try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "should-not-merge.invalid"));
    }
    {
        var pol: policy.schema.Policy = .{ .allocator = allocator };
        defer pol.network.deinit(allocator);
        try applyNetworkOverlayWithHostKey(
            allocator,
            &pol,
            .{ .command_argv = &.{"pi"} },
            .mediated,
            false, // untrusted / basename spoof
            "pi",
            discovery,
        );
        try expectNoAgentInferencePackOrOverlay(pol.network.allow);
        try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "should-not-merge.invalid"));
    }
}

test "applyNetworkOverlayWithHostKey P3 CLI --allow-network composes after discovery merge" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    const workspace_root = try p3LaunchAbsPath(&ws_tmp);
    defer allocator.free(workspace_root);
    try policy.network_discovered.writeManaged(io, allocator, workspace_root, &.{
        .{ .host = "auth.x.ai", .sources = &.{"pi:discover"} },
    });

    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);
    pol.network.allow = try policy.schema.duplicateStringList(allocator, &.{"github.com"});

    var opts: RunOptions = .{ .command_argv = &.{"pi"} };
    opts.allow_network_values[0] = "api.session-cli.example";
    opts.allow_network_count = 1;

    try applyNetworkOverlayWithHostKey(
        allocator,
        &pol,
        opts,
        .mediated,
        true,
        "pi",
        .{ .io = io, .workspace_root = workspace_root, .home = "" },
    );

    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "github.com"));
    try expectCorePackOnAllow(pol.network.allow);
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "openrouter.ai"));
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "auth.x.ai"));
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "api.session-cli.example"));
}

test "applyNetworkOverlayWithHostKey P3 managed path is workspace_root/.ryk/network-discovered.yaml" {
    // Composition: launch loader must use the same path as p3-managed writer.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    const workspace_root = try p3LaunchAbsPath(&ws_tmp);
    defer allocator.free(workspace_root);

    const path = try policy.network_discovered.managedPath(allocator, workspace_root);
    defer allocator.free(path);
    try std.testing.expect(std.mem.endsWith(u8, path, ".ryk/network-discovered.yaml"));
    try std.testing.expect(std.mem.startsWith(u8, path, workspace_root));

    // Write via managed API then launch-merge must observe the same file.
    try policy.network_discovered.writeManaged(io, allocator, workspace_root, &.{
        .{ .host = "path-parity-host.invalid", .sources = &.{"pi:discover"} },
    });
    // Direct load parity (writer↔loader).
    var store = try policy.network_discovered.loadManaged(io, allocator, workspace_root);
    defer store.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), store.hosts.len);
    try std.testing.expectEqualStrings("path-parity-host.invalid", store.hosts[0].host);

    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);
    try applyNetworkOverlayWithHostKey(
        allocator,
        &pol,
        .{ .command_argv = &.{"pi"} },
        .mediated,
        true,
        "pi",
        .{ .io = io, .workspace_root = workspace_root, .home = "" },
    );
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "path-parity-host.invalid"));
}

test "applyNetworkOverlayWithHostKey P3 nested-cwd managed write still merges from abs workspace root" {
    // Monopath/nested-cwd parity: process cwd under nested/ must not shadow workspace managed file.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    const workspace_root = try p3LaunchAbsPath(&ws_tmp);
    defer allocator.free(workspace_root);

    try ws_tmp.dir.createDirPath(io, "nested/deep");
    // Decoy under nested cwd path — must NOT be the product managed file.
    try p3LaunchWriteRel(ws_tmp.dir, "nested/deep/.ryk/network-discovered.yaml",
        \\version: 1
        \\hosts:
        \\  - host: decoy-nested-cwd.invalid
        \\    sources: [decoy]
    );

    // Product write under abs workspace root (independent of cwd).
    try policy.network_discovered.writeManaged(io, allocator, workspace_root, &.{
        .{ .host = "workspace-root-managed.invalid", .sources = &.{"opencode:discover"} },
    });

    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);

    // Call site always passes abs workspace_root (product path); cwd may be nested.
    try applyNetworkOverlayWithHostKey(
        allocator,
        &pol,
        .{ .command_argv = &.{"opencode"} },
        .mediated,
        true,
        "opencode",
        .{ .io = io, .workspace_root = workspace_root, .home = "" },
    );

    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "workspace-root-managed.invalid"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "decoy-nested-cwd.invalid"));
    try expectCorePackOnAllow(pol.network.allow);
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "opencode.ai"));
}

test "applyNetworkOverlayWithHostKey P3 host_key scopes managed grants (no cross-adapter bleed)" {
    // opencode-tagged managed hosts must not appear on pi launch allow.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    const workspace_root = try p3LaunchAbsPath(&ws_tmp);
    defer allocator.free(workspace_root);

    try policy.network_discovered.writeManaged(io, allocator, workspace_root, &.{
        .{ .host = "auth.x.ai", .sources = &.{"pi:discover"} },
        .{ .host = "opencode-only-managed.invalid", .sources = &.{"opencode:discover"} },
    });

    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);

    try applyNetworkOverlayWithHostKey(
        allocator,
        &pol,
        .{ .command_argv = &.{"pi"} },
        .mediated,
        true,
        "pi",
        .{ .io = io, .workspace_root = workspace_root, .home = "" },
    );

    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "auth.x.ai"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "opencode-only-managed.invalid"));
}

test "applyNetworkOverlayWithHostKey P3 RYK_NETWORK_ALLOW includes discovered hosts after installNetworkEnvironment" {
    // LIVE unit proxy: product exports effective allow via RYK_NETWORK_ALLOW (installNetworkEnvironment).
    // Full binary ryk pi/opencode CONNECT smoke remains implementer / p3-docs-live gate.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    const workspace_root = try p3LaunchAbsPath(&ws_tmp);
    defer allocator.free(workspace_root);
    try policy.network_discovered.writeManaged(io, allocator, workspace_root, &.{
        .{ .host = "auth.x.ai", .sources = &.{"opencode:discover"} },
    });

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    try p3LaunchPlantOpencodeHome(home_tmp.dir, p3_launch_opencode_auth_json);
    const home = try p3LaunchAbsPath(&home_tmp);
    defer allocator.free(home);

    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);

    try applyNetworkOverlayWithHostKey(
        allocator,
        &pol,
        .{ .command_argv = &.{"opencode"} },
        .mediated,
        true,
        "opencode",
        .{ .io = io, .workspace_root = workspace_root, .home = home },
    );

    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    try installNetworkEnvironment(allocator, &env_map, pol.network);

    const allow_csv = env_map.get("RYK_NETWORK_ALLOW") orelse {
        try std.testing.expect(false); // must export when allow non-empty
        return;
    };
    try std.testing.expect(std.mem.indexOf(u8, allow_csv, "auth.x.ai") != null);
    try std.testing.expect(std.mem.indexOf(u8, allow_csv, "api.x.ai") != null);
    try std.testing.expect(std.mem.indexOf(u8, allow_csv, "opencode.ai") != null);
    try std.testing.expect(std.mem.indexOf(u8, allow_csv, "pastebin.com") == null);
    try std.testing.expect(std.mem.indexOf(u8, allow_csv, "NOT-REAL") == null);
}

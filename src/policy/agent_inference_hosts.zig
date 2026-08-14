//! Agent-inference network allow — static core pack (§5.1), host overlays (§5.2),
//! and provider-id catalog (§5.3).
//!
//! Pure, FS-free tables + deterministic merge into `network.allow`. Launch seeding
//! lives in `cli/run_network_overlay.zig` (`applyNetworkOverlayWithHostKey`); this module owns pack
//! data, provider catalog, and merge only. Normative SoT id: **AINA-2026-08-02**.
//!
//! Ownership contract for `mergeAllowList`:
//! - Returned outer slice is allocator-owned (free with `schema.freeStringList`).
//! - Every string entry is allocator-owned (duped from static pack/overlay and/or existing).
//! - Never removes entries present in `existing`; dedupes by exact string equality.
//! - Merge order: existing, then core pack, then optional host overlay (first wins).
//!
//! Ownership contract for `catalogForProvider`:
//! - Returns borrowed static host slices (process-long; do not free).
//! - Unknown / empty provider id → empty slice (no invented hosts).
//!
//! Do not invent cloud wildcards (no bare `*.amazonaws.com`) or paste sinks.
//! Overlay and catalog share the same canonical hostname arrays per family
//! (single source of truth — no dual-table drift).

const std = @import("std");

const core = @import("../core/mod.zig");
const network_eval = @import("network_eval.zig");
const schema = @import("schema.zig");

const CORE_PACK = [_][]const u8{
    "api.anthropic.com",
    "api.openai.com",
    "api.x.ai",
};

// Canonical hostname arrays (single SoT). Overlay + catalog both point here.
const HOSTS_ANTHROPIC = [_][]const u8{
    "api.anthropic.com",
};
const HOSTS_OPENAI = [_][]const u8{
    "api.openai.com",
};
const HOSTS_XAI = [_][]const u8{
    "api.x.ai",
    "auth.x.ai",
};
const HOSTS_OPENROUTER = [_][]const u8{
    "openrouter.ai",
};
const HOSTS_OPENCODE = [_][]const u8{
    "opencode.ai",
    "models.opencode.ai",
};
// Grok is a first-class launch alias; overlay is keyed by trusted host "grok".
const HOSTS_GROK = [_][]const u8{
    "cli-chat-proxy.grok.com",
    "auth.x.ai",
};

/// Static core hosts; borrowed, process-long (do not free).
pub fn corePack() []const []const u8 {
    return &CORE_PACK;
}

/// Host overlay; empty for core-only / unknown keys. Borrowed (do not free).
pub fn overlayForHost(host_key: []const u8) []const []const u8 {
    if (std.mem.eql(u8, host_key, "grok")) return &HOSTS_GROK;
    if (std.mem.eql(u8, host_key, "opencode")) return &HOSTS_OPENCODE;
    if (std.mem.eql(u8, host_key, "pi")) return &HOSTS_OPENROUTER;
    return &.{};
}

/// Map a provider **id** (auth key / config provider field) to static inference hosts.
///
/// Borrowed, process-long host slices — do not free. Unknown / empty / host-launch
/// alias keys return empty (no invented hosts; DIS-4 / NG-P3-5). Never includes
/// bare `*.amazonaws.com` or paste sinks. Prefer literal URL hosts from adapters
/// when present; this catalog is the floor for id-only mappings.
///
/// Spec §5.3 minima: anthropic; openai/openai-codex; xai/xai-oauth; openrouter;
/// opencode/opencode-go. Optional ids (kimi-coding, zai, amazon-bedrock bare)
/// stay empty until verified + unit-tested.
pub fn catalogForProvider(provider_id: []const u8) []const []const u8 {
    if (provider_id.len == 0) return &.{};

    if (std.mem.eql(u8, provider_id, "anthropic")) return &HOSTS_ANTHROPIC;
    if (std.mem.eql(u8, provider_id, "openai") or std.mem.eql(u8, provider_id, "openai-codex"))
        return &HOSTS_OPENAI;
    if (std.mem.eql(u8, provider_id, "xai") or std.mem.eql(u8, provider_id, "xai-oauth"))
        return &HOSTS_XAI;
    if (std.mem.eql(u8, provider_id, "openrouter")) return &HOSTS_OPENROUTER;
    if (std.mem.eql(u8, provider_id, "opencode") or std.mem.eql(u8, provider_id, "opencode-go"))
        return &HOSTS_OPENCODE;

    return &.{};
}

/// Merge `existing ∪ corePack ∪ overlay` (null host_key → core only). See file header.
pub fn mergeAllowList(
    allocator: std.mem.Allocator,
    host_key: ?[]const u8,
    existing: []const []const u8,
) ![]const []const u8 {
    const overlay: []const []const u8 = if (host_key) |key| overlayForHost(key) else &.{};
    const pack = corePack();

    var list: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (list.items) |entry| allocator.free(entry);
        list.deinit(allocator);
    }

    try appendUniqueOwned(allocator, &list, existing);
    try appendUniqueOwned(allocator, &list, pack);
    try appendUniqueOwned(allocator, &list, overlay);

    return try list.toOwnedSlice(allocator);
}

/// `a ∪ b` with exact-host dedupe; first-wins order. Owned outer + strings;
/// free with `schema.freeStringList`. Empty result is `&.{}`.
/// Shared by pack merge and managed preserve paths (single security-critical union).
pub fn unionOwnedStringLists(
    allocator: std.mem.Allocator,
    first: []const []const u8,
    second: []const []const u8,
) ![]const []const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (list.items) |entry| allocator.free(entry);
        list.deinit(allocator);
    }
    try appendUniqueOwned(allocator, &list, first);
    try appendUniqueOwned(allocator, &list, second);
    if (list.items.len == 0) {
        list.deinit(allocator);
        return &.{};
    }
    return try list.toOwnedSlice(allocator);
}

fn listContains(list: []const []const u8, needle: []const u8) bool {
    for (list) |entry| {
        if (std.mem.eql(u8, entry, needle)) return true;
    }
    return false;
}

fn appendUniqueOwned(
    allocator: std.mem.Allocator,
    list: *std.ArrayList([]const u8),
    source: []const []const u8,
) !void {
    for (source) |entry| {
        if (listContains(list.items, entry)) continue;
        const owned = try allocator.dupe(u8, entry);
        errdefer allocator.free(owned);
        try list.append(allocator, owned);
    }
}

fn countExact(list: []const []const u8, needle: []const u8) usize {
    var n: usize = 0;
    for (list) |entry| {
        if (std.mem.eql(u8, entry, needle)) n += 1;
    }
    return n;
}

/// §5.2 overlay minima that must not appear under core-only / null / unknown merge.
fn expectNoHostOverlays(list: []const []const u8) !void {
    try std.testing.expect(!listContains(list, "cli-chat-proxy.grok.com"));
    try std.testing.expect(!listContains(list, "auth.x.ai"));
    try std.testing.expect(!listContains(list, "models.opencode.ai"));
    try std.testing.expect(!listContains(list, "opencode.ai"));
    try std.testing.expect(!listContains(list, "openrouter.ai"));
}

/// Build a strict allowlist policy whose `network.allow` is a fully owned copy of `allow`.
/// Caller must `policy.network.deinit(allocator)` (not full Policy.deinit — workspace root is static).
fn allowlistPolicyWithAllow(allocator: std.mem.Allocator, allow: []const []const u8) !schema.Policy {
    var policy: schema.Policy = .{ .allocator = allocator, .mode = .strict };
    policy.network.mode = .allowlist;
    policy.network.allow = try schema.duplicateStringList(allocator, allow);
    return policy;
}

fn expectNetworkResult(
    allocator: std.mem.Allocator,
    policy: *const schema.Policy,
    destination: []const u8,
    want: core.decision.DecisionResult,
) !void {
    var decision = try network_eval.evaluate(allocator, policy, .strict, destination, .{});
    defer decision.deinit(allocator);
    try std.testing.expectEqual(want, decision.decision.result);
}

// ---------------------------------------------------------------------------
// Table / overlay content (A-P1 data)
// ---------------------------------------------------------------------------

test "agent_inference A-P1-4 grok overlay hosts are scoped to grok key" {
    const grok = overlayForHost("grok");
    try std.testing.expect(listContains(grok, "cli-chat-proxy.grok.com"));
    try std.testing.expect(listContains(grok, "auth.x.ai"));

    // Unrelated keys must not receive grok overlay entries.
    try std.testing.expect(!listContains(overlayForHost("pi"), "cli-chat-proxy.grok.com"));
    try std.testing.expect(!listContains(overlayForHost("opencode"), "cli-chat-proxy.grok.com"));
    try std.testing.expect(!listContains(overlayForHost("claude"), "cli-chat-proxy.grok.com"));
}

test "agent_inference A-P1-5 opencode overlay hosts are scoped to opencode key" {
    const oc = overlayForHost("opencode");
    try std.testing.expect(listContains(oc, "opencode.ai"));
    try std.testing.expect(listContains(oc, "models.opencode.ai"));

    try std.testing.expect(!listContains(overlayForHost("pi"), "models.opencode.ai"));
    try std.testing.expect(!listContains(overlayForHost("grok"), "models.opencode.ai"));
    try std.testing.expect(!listContains(overlayForHost("codex"), "opencode.ai"));
}

test "agent_inference A-P1-5 pi overlay hosts are scoped to pi key" {
    const pi = overlayForHost("pi");
    try std.testing.expect(listContains(pi, "openrouter.ai"));

    try std.testing.expect(!listContains(overlayForHost("grok"), "openrouter.ai"));
    try std.testing.expect(!listContains(overlayForHost("opencode"), "openrouter.ai"));
    try std.testing.expect(!listContains(overlayForHost("claude"), "openrouter.ai"));
}

test "agent_inference A-P1-4/5 core-only host keys have empty overlays at P1" {
    // claude / codex / openclaw / hermes: core pack only (no cross-host pollution).
    const core_only = [_][]const u8{ "claude", "codex", "openclaw", "hermes" };
    for (core_only) |key| {
        try std.testing.expectEqual(@as(usize, 0), overlayForHost(key).len);
    }
    // Unknown key also empty (fail-closed to core-only when host_key is odd).
    try std.testing.expectEqual(@as(usize, 0), overlayForHost("not-a-host-alias").len);
    try std.testing.expectEqual(@as(usize, 0), overlayForHost("").len);
}

// ---------------------------------------------------------------------------
// Pure merge (A-P1-6 data + dedupe / stale / null key)
// ---------------------------------------------------------------------------

test "agent_inference A-P1-6 merge into empty allow yields core pack" {
    const allocator = std.testing.allocator;
    // host_key == null → core pack only (no §5.2 overlay).
    const merged = try mergeAllowList(allocator, null, &.{});
    defer schema.freeStringList(allocator, merged);

    try std.testing.expect(listContains(merged, "api.anthropic.com"));
    try std.testing.expect(listContains(merged, "api.openai.com"));
    try std.testing.expect(listContains(merged, "api.x.ai"));
    // Contract: null key must not inject any host overlay (hollow "union all overlays" fails here).
    try expectNoHostOverlays(merged);
}

test "agent_inference A-P1-6 merge into stale github-only allow keeps existing and adds pack" {
    const allocator = std.testing.allocator;
    // Stale workspace fixture: package/git hosts only (common post-init policy).
    const stale = [_][]const u8{ "api.github.com", "registry.npmjs.org" };
    const merged = try mergeAllowList(allocator, null, &stale);
    defer schema.freeStringList(allocator, merged);

    try std.testing.expect(listContains(merged, "api.github.com"));
    try std.testing.expect(listContains(merged, "registry.npmjs.org"));
    try std.testing.expect(listContains(merged, "api.anthropic.com"));
    try std.testing.expect(listContains(merged, "api.openai.com"));
    try std.testing.expect(listContains(merged, "api.x.ai"));
    // Null key: core-only; overlays must not appear on pure-merge seed path.
    try expectNoHostOverlays(merged);
}

test "agent_inference A-P1-4 merge for grok adds overlay without dropping stale allows" {
    const allocator = std.testing.allocator;
    const stale = [_][]const u8{"api.github.com"};
    const merged = try mergeAllowList(allocator, "grok", &stale);
    defer schema.freeStringList(allocator, merged);

    try std.testing.expect(listContains(merged, "api.github.com"));
    try std.testing.expect(listContains(merged, "api.anthropic.com"));
    try std.testing.expect(listContains(merged, "cli-chat-proxy.grok.com"));
    try std.testing.expect(listContains(merged, "auth.x.ai"));
    // opencode/pi overlays must not leak into grok merge.
    try std.testing.expect(!listContains(merged, "models.opencode.ai"));
    try std.testing.expect(!listContains(merged, "openrouter.ai"));
}

test "agent_inference A-P1-5 merge for opencode and pi adds only that host overlay" {
    const allocator = std.testing.allocator;

    const for_oc = try mergeAllowList(allocator, "opencode", &.{});
    defer schema.freeStringList(allocator, for_oc);
    try std.testing.expect(listContains(for_oc, "opencode.ai"));
    try std.testing.expect(listContains(for_oc, "models.opencode.ai"));
    try std.testing.expect(listContains(for_oc, "api.openai.com")); // core
    try std.testing.expect(!listContains(for_oc, "cli-chat-proxy.grok.com"));
    try std.testing.expect(!listContains(for_oc, "openrouter.ai"));

    const for_pi = try mergeAllowList(allocator, "pi", &.{});
    defer schema.freeStringList(allocator, for_pi);
    try std.testing.expect(listContains(for_pi, "openrouter.ai"));
    try std.testing.expect(listContains(for_pi, "api.x.ai")); // core
    try std.testing.expect(!listContains(for_pi, "models.opencode.ai"));
    try std.testing.expect(!listContains(for_pi, "cli-chat-proxy.grok.com"));
}

test "agent_inference merge for core-only host keys does not add foreign overlays" {
    const allocator = std.testing.allocator;
    for ([_][]const u8{ "claude", "codex", "openclaw", "hermes" }) |key| {
        const merged = try mergeAllowList(allocator, key, &.{"api.github.com"});
        defer schema.freeStringList(allocator, merged);
        try std.testing.expect(listContains(merged, "api.github.com"));
        try std.testing.expect(listContains(merged, "api.anthropic.com"));
        try expectNoHostOverlays(merged);
    }
}

test "agent_inference merge for unknown host_key is core-only (no overlay)" {
    const allocator = std.testing.allocator;
    // Unknown keys must match core-only shape: existing ∪ core, no §5.2 overlay.
    const merged = try mergeAllowList(allocator, "not-a-host-alias", &.{"api.github.com"});
    defer schema.freeStringList(allocator, merged);

    try std.testing.expect(listContains(merged, "api.github.com"));
    try std.testing.expect(listContains(merged, "api.anthropic.com"));
    try std.testing.expect(listContains(merged, "api.openai.com"));
    try std.testing.expect(listContains(merged, "api.x.ai"));
    try expectNoHostOverlays(merged);
}

test "agent_inference mergeAllowList dedupes exact hosts already present in existing" {
    const allocator = std.testing.allocator;
    // Stale list already contains one core host and one that will also appear in overlay.
    const existing = [_][]const u8{ "api.openai.com", "auth.x.ai", "api.github.com" };
    const merged = try mergeAllowList(allocator, "grok", &existing);
    defer schema.freeStringList(allocator, merged);

    try std.testing.expectEqual(@as(usize, 1), countExact(merged, "api.openai.com"));
    try std.testing.expectEqual(@as(usize, 1), countExact(merged, "auth.x.ai"));
    try std.testing.expectEqual(@as(usize, 1), countExact(merged, "api.github.com"));
    try std.testing.expect(listContains(merged, "cli-chat-proxy.grok.com"));
}

// ---------------------------------------------------------------------------
// network_eval allow / deny on composed allow lists (A-P1-1, A-P1-2, A-P1-3)
// ---------------------------------------------------------------------------

test "agent_inference A-P1-1 core pack hosts evaluate allow under allowlist" {
    const allocator = std.testing.allocator;
    // Null key composition: core allow only — overlays must stay denied.
    const merged = try mergeAllowList(allocator, null, &.{});
    defer schema.freeStringList(allocator, merged);
    try expectNoHostOverlays(merged);

    var policy = try allowlistPolicyWithAllow(allocator, merged);
    defer policy.network.deinit(allocator);

    try expectNetworkResult(allocator, &policy, "https://api.anthropic.com/v1/messages", .allow);
    try expectNetworkResult(allocator, &policy, "https://api.openai.com/v1/chat/completions", .allow);
    try expectNetworkResult(allocator, &policy, "https://api.x.ai/v1/chat/completions", .allow);
    // Bare host form (proxy-style destination) also allows for all three core hosts.
    try expectNetworkResult(allocator, &policy, "api.anthropic.com", .allow);
    try expectNetworkResult(allocator, &policy, "api.openai.com", .allow);
    try expectNetworkResult(allocator, &policy, "api.x.ai", .allow);
    // Null merge must not seed overlay hosts into network.allow.
    try expectNetworkResult(allocator, &policy, "https://cli-chat-proxy.grok.com/", .deny);
    try expectNetworkResult(allocator, &policy, "https://models.opencode.ai/models", .deny);
    try expectNetworkResult(allocator, &policy, "https://openrouter.ai/api/v1", .deny);
}

test "agent_inference A-P1-2 pastebin.com evaluates deny when not on allow" {
    const allocator = std.testing.allocator;
    const merged = try mergeAllowList(allocator, "opencode", &.{});
    defer schema.freeStringList(allocator, merged);

    var policy = try allowlistPolicyWithAllow(allocator, merged);
    defer policy.network.deinit(allocator);

    try expectNetworkResult(allocator, &policy, "https://pastebin.com/raw/abc", .deny);
    try expectNetworkResult(allocator, &policy, "pastebin.com", .deny);
}

test "agent_inference A-P1-2 pastebin deny fixture beats allowlist miss and explicit deny" {
    const allocator = std.testing.allocator;
    // Explicit deny fixture (A-P1-2 "or fixture deny") plus core allow via merge.
    var policy: schema.Policy = .{ .allocator = allocator, .mode = .strict };
    defer policy.network.deinit(allocator);
    policy.network.mode = .allowlist;
    policy.network.deny = try schema.duplicateStringList(allocator, &.{ "pastebin.com", "*.pastebin.com" });
    const allow = try mergeAllowList(allocator, null, &.{});
    // freeStringList ownership transfers into policy.network.allow (network.deinit frees it).
    policy.network.allow = allow;
    try expectNoHostOverlays(allow);

    try expectNetworkResult(allocator, &policy, "https://pastebin.com/x", .deny);
    // Core still allows.
    try expectNetworkResult(allocator, &policy, "api.openai.com", .allow);
    // Null merge: overlay host remains denied.
    try expectNetworkResult(allocator, &policy, "https://cli-chat-proxy.grok.com/", .deny);
}

test "agent_inference A-P1-3 unknown public host example.com evaluates deny when not on allow" {
    const allocator = std.testing.allocator;
    const merged = try mergeAllowList(allocator, "pi", &.{"api.github.com"});
    defer schema.freeStringList(allocator, merged);

    var policy = try allowlistPolicyWithAllow(allocator, merged);
    defer policy.network.deinit(allocator);

    try expectNetworkResult(allocator, &policy, "https://example.com/", .deny);
    try expectNetworkResult(allocator, &policy, "example.com", .deny);
    try expectNetworkResult(allocator, &policy, "https://evil.example.net/hook", .deny);
}

test "agent_inference A-P1-4 grok overlay hosts evaluate allow; foreign overlay host denies" {
    const allocator = std.testing.allocator;
    const merged = try mergeAllowList(allocator, "grok", &.{});
    defer schema.freeStringList(allocator, merged);

    var policy = try allowlistPolicyWithAllow(allocator, merged);
    defer policy.network.deinit(allocator);

    try expectNetworkResult(allocator, &policy, "https://cli-chat-proxy.grok.com/", .allow);
    try expectNetworkResult(allocator, &policy, "https://auth.x.ai/oauth", .allow);
    // opencode overlay host must not be allowed under grok-only merge.
    try expectNetworkResult(allocator, &policy, "https://models.opencode.ai/models", .deny);
}

test "agent_inference A-P1-5 opencode and pi overlay hosts evaluate allow under their merge" {
    const allocator = std.testing.allocator;

    {
        const merged = try mergeAllowList(allocator, "opencode", &.{});
        defer schema.freeStringList(allocator, merged);
        var policy = try allowlistPolicyWithAllow(allocator, merged);
        defer policy.network.deinit(allocator);
        try expectNetworkResult(allocator, &policy, "https://models.opencode.ai/api", .allow);
        try expectNetworkResult(allocator, &policy, "https://opencode.ai/", .allow);
        try expectNetworkResult(allocator, &policy, "https://openrouter.ai/api/v1", .deny);
    }
    {
        const merged = try mergeAllowList(allocator, "pi", &.{});
        defer schema.freeStringList(allocator, merged);
        var policy = try allowlistPolicyWithAllow(allocator, merged);
        defer policy.network.deinit(allocator);
        try expectNetworkResult(allocator, &policy, "https://openrouter.ai/api/v1/chat", .allow);
        try expectNetworkResult(allocator, &policy, "https://models.opencode.ai/api", .deny);
    }
}

test "agent_inference A-P1-6 stale github-only policy allows pack after pure merge" {
    const allocator = std.testing.allocator;
    // Simulate workspace policy that only allowed package hosts (stale YAML).
    const stale = [_][]const u8{ "api.github.com", "pypi.org" };
    const merged = try mergeAllowList(allocator, "claude", &stale);
    defer schema.freeStringList(allocator, merged);

    var policy = try allowlistPolicyWithAllow(allocator, merged);
    defer policy.network.deinit(allocator);

    try expectNetworkResult(allocator, &policy, "api.github.com", .allow);
    try expectNetworkResult(allocator, &policy, "pypi.org", .allow);
    try expectNetworkResult(allocator, &policy, "api.anthropic.com", .allow);
    try expectNetworkResult(allocator, &policy, "api.openai.com", .allow);
    try expectNetworkResult(allocator, &policy, "api.x.ai", .allow);
    // Closed default retained for non-pack public hosts.
    try expectNetworkResult(allocator, &policy, "example.com", .deny);
    try expectNetworkResult(allocator, &policy, "pastebin.com", .deny);
}

test "agent_inference SEC: core pack does not include cloud wildcards or paste sinks" {
    const pack = corePack();
    try std.testing.expect(!listContains(pack, "*.amazonaws.com"));
    try std.testing.expect(!listContains(pack, "pastebin.com"));
    try std.testing.expect(!listContains(pack, "example.com"));
    // Overlays also must not open cloud wildcards.
    for ([_][]const u8{ "grok", "opencode", "pi", "claude" }) |key| {
        try std.testing.expect(!listContains(overlayForHost(key), "*.amazonaws.com"));
    }
}

// ---------------------------------------------------------------------------
// Provider id catalog §5.3 (P3 / A-P3-4 / DIS-4) — pure mapping; unknown → empty
//
// Public seam (implementer): `catalogForProvider(provider_id) []const []const u8`
// Borrowed, process-long host slices (do not free). Empty for unknown / skip.
// ---------------------------------------------------------------------------

test "agent_inference catalog A-P3-4 anthropic maps to api.anthropic.com" {
    const hosts = catalogForProvider("anthropic");
    try std.testing.expect(listContains(hosts, "api.anthropic.com"));
    // Catalog is inference-floor hosts for this id only — no cross-provider pollution.
    try std.testing.expect(!listContains(hosts, "api.openai.com"));
    try std.testing.expect(!listContains(hosts, "openrouter.ai"));
}

test "agent_inference catalog A-P3-4 openai maps to api.openai.com" {
    const hosts = catalogForProvider("openai");
    try std.testing.expect(listContains(hosts, "api.openai.com"));
    try std.testing.expect(!listContains(hosts, "api.anthropic.com"));
    try std.testing.expect(!listContains(hosts, "models.opencode.ai"));
}

test "agent_inference catalog A-P3-4 openai-codex maps to api.openai.com" {
    // Spec §5.3: openai and openai-codex share the OpenAI API host minimum.
    const hosts = catalogForProvider("openai-codex");
    try std.testing.expect(listContains(hosts, "api.openai.com"));
    try std.testing.expect(!listContains(hosts, "api.x.ai"));
}

test "agent_inference catalog A-P3-4 xai maps to api.x.ai and auth.x.ai" {
    // xAI inference + OAuth refresh hosts (pi/opencode auth keys use this id).
    const hosts = catalogForProvider("xai");
    try std.testing.expect(listContains(hosts, "api.x.ai"));
    try std.testing.expect(listContains(hosts, "auth.x.ai"));
    try std.testing.expect(!listContains(hosts, "openrouter.ai"));
}

test "agent_inference catalog A-P3-4 xai-oauth maps to api.x.ai and auth.x.ai" {
    // pi auth.json key shape: xai-oauth with tokenEndpoint under auth.x.ai.
    const hosts = catalogForProvider("xai-oauth");
    try std.testing.expect(listContains(hosts, "api.x.ai"));
    try std.testing.expect(listContains(hosts, "auth.x.ai"));
    try std.testing.expect(!listContains(hosts, "cli-chat-proxy.grok.com"));
}

test "agent_inference catalog A-P3-4 openrouter maps to openrouter.ai" {
    const hosts = catalogForProvider("openrouter");
    try std.testing.expect(listContains(hosts, "openrouter.ai"));
    try std.testing.expect(!listContains(hosts, "api.openai.com"));
    try std.testing.expect(!listContains(hosts, "models.opencode.ai"));
}

test "agent_inference catalog A-P3-4 opencode maps to opencode.ai and models.opencode.ai" {
    const hosts = catalogForProvider("opencode");
    try std.testing.expect(listContains(hosts, "opencode.ai"));
    try std.testing.expect(listContains(hosts, "models.opencode.ai"));
    try std.testing.expect(!listContains(hosts, "openrouter.ai"));
}

test "agent_inference catalog A-P3-4 opencode-go maps to opencode.ai and models.opencode.ai" {
    const hosts = catalogForProvider("opencode-go");
    try std.testing.expect(listContains(hosts, "opencode.ai"));
    try std.testing.expect(listContains(hosts, "models.opencode.ai"));
    try std.testing.expect(!listContains(hosts, "api.anthropic.com"));
}

test "agent_inference catalog DIS-4 unknown provider id yields empty (no invented host)" {
    // NG-P3-5 / DIS-4: never guess hosts for unknown ids.
    const hosts = catalogForProvider("not-a-real-provider-id");
    try std.testing.expectEqual(@as(usize, 0), hosts.len);

    // Empty id is not a catalog entry.
    try std.testing.expectEqual(@as(usize, 0), catalogForProvider("").len);

    // Host-launch keys are not provider ids (do not invent overlay via catalog).
    try std.testing.expectEqual(@as(usize, 0), catalogForProvider("pi").len);
    try std.testing.expectEqual(@as(usize, 0), catalogForProvider("grok").len);
    try std.testing.expectEqual(@as(usize, 0), catalogForProvider("claude").len);

    // Unverified optional ids (spec: only after verified host + unit test) → skip.
    try std.testing.expectEqual(@as(usize, 0), catalogForProvider("kimi-coding").len);
    try std.testing.expectEqual(@as(usize, 0), catalogForProvider("zai").len);
}

test "agent_inference catalog SEC-6 no bare amazonaws wildcard in any minimum mapping" {
    // SEC-6 / acceptance: catalog must not open cloud-wide wildcards.
    const ids = [_][]const u8{
        "anthropic",
        "openai",
        "openai-codex",
        "xai",
        "xai-oauth",
        "openrouter",
        "opencode",
        "opencode-go",
        "amazon-bedrock", // region-scoped only if ever cataloged; bare id must not invent *.amazonaws.com
        "not-a-real-provider-id",
        "",
    };
    for (ids) |id| {
        const hosts = catalogForProvider(id);
        try std.testing.expect(!listContains(hosts, "*.amazonaws.com"));
        try std.testing.expect(!listContains(hosts, "pastebin.com"));
        try std.testing.expect(!listContains(hosts, "example.com"));
        // Never emit credential-like material via catalog (pure static table).
        for (hosts) |h| {
            try std.testing.expect(h.len > 0);
            try std.testing.expect(std.mem.indexOf(u8, h, "://") == null);
            try std.testing.expect(std.mem.indexOf(u8, h, "@") == null);
        }
    }
}

test "agent_inference catalog aliases share exact host sets for openai and xai families" {
    // Both openai ids must include the same minimum host; both xai ids include OAuth + API.
    try std.testing.expect(listContains(catalogForProvider("openai"), "api.openai.com"));
    try std.testing.expect(listContains(catalogForProvider("openai-codex"), "api.openai.com"));
    try std.testing.expect(listContains(catalogForProvider("xai"), "api.x.ai"));
    try std.testing.expect(listContains(catalogForProvider("xai"), "auth.x.ai"));
    try std.testing.expect(listContains(catalogForProvider("xai-oauth"), "api.x.ai"));
    try std.testing.expect(listContains(catalogForProvider("xai-oauth"), "auth.x.ai"));
    try std.testing.expect(listContains(catalogForProvider("opencode"), "opencode.ai"));
    try std.testing.expect(listContains(catalogForProvider("opencode-go"), "models.opencode.ai"));
}

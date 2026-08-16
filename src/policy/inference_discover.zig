//! Read-only inference host discovery adapters (AINA P3 S2 — pi + opencode).
//!
//! Read-only inference host discovery adapters for pi and opencode (AINA P3).
//! SoT: A-P3-1…A-P3-4, DIS-2/4, SEC-3/7.
//!
//! Public seam: `discoverForHost(io, allocator, host_key, home) → ![]const []const u8`
//!
//! - `host_key`: mediated alias (`pi`, `opencode`, …). Unknown → soft empty.
//! - `home`: synthetic or real HOME root (parent process; never empty-backpack scrub).
//! - Success: allocator-owned hostnames (free with `schema.freeStringList`).
//! - Soft empty: missing file, corrupt JSON, empty object, IO skip — never panic.
//! - Prefer literal hosts from approved URL fields (`baseUrl`, `tokenEndpoint`,
//!   discovery.* endpoints); else map provider **ids** via `catalogForProvider`.
//! - Hostnames only — never tokens/keys/refresh; never MCP/marketplace harvest.
//! - Exfil-sink hostnames (pastebin, hastebin, requestbin, ngrok tunnels, …)
//!   are soft-dropped so agent-writable auth cannot self-grant known sinks.
//! - OOM always propagates; other parse/IO errors soft-skip.
//!
//! Documented paths (DIS-2):
//! - pi: `{home}/.pi/agent/auth.json`, `{home}/.pi/agent/settings.json`
//!   (models.json / models-store URLs deferred — residual tracked in docs/network.md)
//! - opencode: `{home}/.local/share/opencode/auth.json`
//!
//! Re-exported from `src/policy/mod.zig`.

const std = @import("std");
const schema = @import("schema.zig");
const agent_inference_hosts = @import("agent_inference_hosts.zig");
const inference_hostname = @import("inference_hostname.zig");
const network_eval = @import("network_eval.zig");

// ---------------------------------------------------------------------------
// Bounds — fail-closed soft skip, never panic
// ---------------------------------------------------------------------------

/// Max bytes read from a single adapter config file (auth/settings).
/// Oversize → soft-empty for that file (A-P3 soft skip; no OOM/panic).
const max_auth_file_bytes: usize = 256 * 1024;

/// Cap discovered hostnames per host adapter.
const max_discovered_hosts: usize = 32;

// ---------------------------------------------------------------------------
// Public seam — discoverForHost
// ---------------------------------------------------------------------------

/// Read-only inference hostname discovery for a mediated host alias.
///
/// - `host_key`: launch alias (`pi`, `opencode`). Unknown → soft empty `&.{}`.
/// - `home`: HOME root (synthetic fixture or real). Paths are relative to this.
/// - Success: allocator-owned hostnames; free with `schema.freeStringList`.
/// - Soft empty (`&.{}` or empty owned list freeable via freeStringList): missing
///   file, corrupt JSON, empty object, IO skip, unknown host_key — never panic.
/// - Prefer literal hosts from approved URL fields; also map provider **ids**
///   via `catalogForProvider`. Hostnames only — never tokens/keys/MCP harvest.
pub fn discoverForHost(
    io: std.Io,
    allocator: std.mem.Allocator,
    host_key: []const u8,
    home: []const u8,
) ![]const []const u8 {
    if (home.len == 0) return &.{};
    if (std.mem.eql(u8, host_key, "pi")) return discoverPi(io, allocator, home);
    if (std.mem.eql(u8, host_key, "opencode")) return discoverOpencode(io, allocator, home);
    return &.{};
}

// ---------------------------------------------------------------------------
// Adapters
// ---------------------------------------------------------------------------

fn discoverPi(io: std.Io, allocator: std.mem.Allocator, home: []const u8) ![]const []const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    errdefer freeOwnedHostList(allocator, &list);

    const auth_path = try std.fs.path.join(allocator, &.{ home, ".pi", "agent", "auth.json" });
    defer allocator.free(auth_path);
    try collectFromAuthJson(io, allocator, auth_path, &list);

    // settings.json: defaultProvider → catalog only (no MCP / no secret fields).
    if (list.items.len < max_discovered_hosts) {
        const settings_path = try std.fs.path.join(allocator, &.{ home, ".pi", "agent", "settings.json" });
        defer allocator.free(settings_path);
        try collectFromPiSettings(io, allocator, settings_path, &list);
    }

    return finishHostList(allocator, &list);
}

fn discoverOpencode(io: std.Io, allocator: std.mem.Allocator, home: []const u8) ![]const []const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    errdefer freeOwnedHostList(allocator, &list);

    // Documented path only (DIS-2): ~/.local/share/opencode/auth.json
    const auth_path = try std.fs.path.join(allocator, &.{ home, ".local", "share", "opencode", "auth.json" });
    defer allocator.free(auth_path);
    try collectFromAuthJson(io, allocator, auth_path, &list);

    return finishHostList(allocator, &list);
}

fn finishHostList(allocator: std.mem.Allocator, list: *std.ArrayList([]const u8)) ![]const []const u8 {
    if (list.items.len == 0) {
        list.deinit(allocator);
        return &.{};
    }
    return try list.toOwnedSlice(allocator);
}

fn freeOwnedHostList(allocator: std.mem.Allocator, list: *std.ArrayList([]const u8)) void {
    for (list.items) |h| allocator.free(h);
    list.deinit(allocator);
}

// ---------------------------------------------------------------------------
// Auth / settings collectors (soft-empty on IO/parse; OOM propagates)
// ---------------------------------------------------------------------------

/// Top-level keys that must never be walked for URL harvest (SEC-7 / NG-4).
fn isHarvestForbiddenKey(key: []const u8) bool {
    return std.mem.eql(u8, key, "mcpServers") or
        std.mem.eql(u8, key, "mcp") or
        std.mem.eql(u8, key, "marketplace") or
        std.mem.eql(u8, key, "servers") or
        std.mem.eql(u8, key, "plugins") or
        std.mem.eql(u8, key, "extensions");
}

fn collectFromAuthJson(
    io: std.Io,
    allocator: std.mem.Allocator,
    path: []const u8,
    list: *std.ArrayList([]const u8),
) !void {
    const text = (try readBoundedFile(io, allocator, path)) orelse return;
    defer allocator.free(text);

    var parsed = std.json.parseFromSlice(std.json.Value, allocator, text, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return, // soft skip corrupt / invalid JSON
    };
    defer parsed.deinit();

    const root = switch (parsed.value) {
        .object => |obj| obj,
        else => return,
    };

    var it = root.iterator();
    while (it.next()) |entry| {
        if (list.items.len >= max_discovered_hosts) return;
        const provider_id = entry.key_ptr.*;
        if (isHarvestForbiddenKey(provider_id)) continue;

        // A-P3-4: map known provider ids via catalog (unknown → empty, no invent).
        try appendCatalogHosts(allocator, list, provider_id);

        // A-P3-1: literal hosts from approved URL fields only (never recursive harvest).
        switch (entry.value_ptr.*) {
            .object => |obj| try extractApprovedUrlFields(allocator, list, obj),
            else => {},
        }
    }
}

fn collectFromPiSettings(
    io: std.Io,
    allocator: std.mem.Allocator,
    path: []const u8,
    list: *std.ArrayList([]const u8),
) !void {
    const text = (try readBoundedFile(io, allocator, path)) orelse return;
    defer allocator.free(text);

    var parsed = std.json.parseFromSlice(std.json.Value, allocator, text, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return,
    };
    defer parsed.deinit();

    const root = switch (parsed.value) {
        .object => |obj| obj,
        else => return,
    };

    if (root.get("defaultProvider")) |val| {
        switch (val) {
            .string => |id| try appendCatalogHosts(allocator, list, id),
            else => {},
        }
    }
}

/// Approved adapter URL field names only — not arbitrary URL scrape.
fn extractApprovedUrlFields(
    allocator: std.mem.Allocator,
    list: *std.ArrayList([]const u8),
    obj: std.json.ObjectMap,
) !void {
    try maybeExtractField(allocator, list, obj, "baseUrl");
    try maybeExtractField(allocator, list, obj, "tokenEndpoint");
    // Alternate casings some agents use
    try maybeExtractField(allocator, list, obj, "base_url");
    try maybeExtractField(allocator, list, obj, "token_endpoint");

    if (obj.get("discovery")) |disc_val| {
        switch (disc_val) {
            .object => |disc| {
                try maybeExtractField(allocator, list, disc, "token_endpoint");
                try maybeExtractField(allocator, list, disc, "authorization_endpoint");
            },
            else => {},
        }
    }
}

fn maybeExtractField(
    allocator: std.mem.Allocator,
    list: *std.ArrayList([]const u8),
    obj: std.json.ObjectMap,
    field_name: []const u8,
) !void {
    if (list.items.len >= max_discovered_hosts) return;
    const val = obj.get(field_name) orelse return;
    const field = switch (val) {
        .string => |s| s,
        else => return,
    };
    const host = (try inference_hostname.extractHostname(allocator, field)) orelse return;
    try appendOwnedHost(allocator, list, host);
}

fn appendCatalogHosts(
    allocator: std.mem.Allocator,
    list: *std.ArrayList([]const u8),
    provider_id: []const u8,
) !void {
    const hosts = agent_inference_hosts.catalogForProvider(provider_id);
    for (hosts) |h| {
        if (list.items.len >= max_discovered_hosts) return;
        if (listContainsExactOwned(list.items, h)) continue;
        const owned = try allocator.dupe(u8, h);
        errdefer allocator.free(owned);
        try list.append(allocator, owned);
    }
}

/// Takes ownership of `owned_host` (frees on dupe/cap/sink/loopback reject).
fn appendOwnedHost(
    allocator: std.mem.Allocator,
    list: *std.ArrayList([]const u8),
    owned_host: []u8,
) !void {
    // Agent-writable auth residual: never auto-grant known exfil sinks
    // (single table in network_eval — no dual-path drift).
    if (network_eval.isExfilSinkHostname(owned_host)) {
        allocator.free(owned_host);
        return;
    }
    // Never auto-merge loopback residual from agent-writable auth — require
    // explicit user policy.yaml allow (avoids allow-before-class-deny SSRF).
    if (isLoopbackExact(owned_host)) {
        allocator.free(owned_host);
        return;
    }
    if (list.items.len >= max_discovered_hosts or listContainsExactOwned(list.items, owned_host)) {
        allocator.free(owned_host);
        return;
    }
    errdefer allocator.free(owned_host);
    try list.append(allocator, owned_host);
}

fn isLoopbackExact(host: []const u8) bool {
    return std.mem.eql(u8, host, "127.0.0.1") or
        std.ascii.eqlIgnoreCase(host, "::1") or
        std.ascii.eqlIgnoreCase(host, "0:0:0:0:0:0:0:1");
}

fn listContainsExactOwned(hosts: []const []const u8, needle: []const u8) bool {
    for (hosts) |h| {
        if (std.mem.eql(u8, h, needle)) return true;
    }
    return false;
}

/// Read file under size cap. Missing/oversize/IO → null (soft). OOM propagates.
fn readBoundedFile(io: std.Io, allocator: std.mem.Allocator, path: []const u8) !?[]u8 {
    return std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(max_auth_file_bytes)) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return null,
    };
}

// ---------------------------------------------------------------------------
// Synthetic fixtures (fake tokens only — never real secrets)
// ---------------------------------------------------------------------------

const pi_auth_json = @embedFile("testdata/inference_discover/pi/agent/auth.json");
const pi_settings_json = @embedFile("testdata/inference_discover/pi/agent/settings.json");
const pi_empty_auth_json = @embedFile("testdata/inference_discover/pi/agent/empty_auth.json");
const pi_corrupt_auth_json = @embedFile("testdata/inference_discover/pi/agent/corrupt_auth.json");
const pi_mcp_auth_json = @embedFile("testdata/inference_discover/pi_with_mcp/auth.json");
const oc_auth_json = @embedFile("testdata/inference_discover/opencode/auth.json");
const oc_urls_auth_json = @embedFile("testdata/inference_discover/opencode_with_urls/auth.json");

/// Synthetic secret needles that must never appear in discovery emit (A-P3-2 / SEC-3).
const fixture_secret_needles = [_][]const u8{
    "sk-fixture-openrouter-fake-key-not-real-A3F9",
    "fixture-xai-access-token-NOT-REAL-7c2e",
    "fixture-xai-refresh-token-NOT-REAL-9b1a",
    "sk-fixture-unknown-vendor-key-DEADBEEF",
    "fixture-opencode-xai-access-NOT-REAL-11aa",
    "fixture-opencode-xai-refresh-NOT-REAL-22bb",
    "sk-fixture-opencode-api-key-NOT-REAL-33cc",
    "sk-fixture-unknown-oc-key-NOT-REAL-44dd",
    "fixture-oc-url-xai-access-NOT-REAL-55ee",
    "fixture-oc-url-xai-refresh-NOT-REAL-66ff",
    "sk-fixture-oc-openrouter-key-NOT-REAL-77gg",
    "sk-fixture-pi-mcp-openrouter-key-NOT-REAL-88hh",
    "fixture-pi-url-diverge-access-NOT-REAL-99ii",
    "fixture-pi-url-diverge-refresh-NOT-REAL-00jj",
    "sk-fixture-pi-url-diverge-or-key-NOT-REAL-11kk",
};

/// Non-catalog hostnames used only in URL-divergence fixtures (A-P3-1 branch lock).
/// Catalog-only adapters cannot invent these — extraction is the only path.
const url_only_host_oauth_edge = "oauth-edge.custom.invalid";
const url_only_host_inference_proxy = "inference-proxy.custom.invalid";
const url_only_host_openrouter_gateway = "openrouter-gateway.custom.invalid";

/// Pi auth where known provider ids carry baseUrl/tokenEndpoint hosts that
/// **differ** from catalog defaults for those ids. Forces URL-field extract.
const pi_auth_url_diverge_json =
    \\{
    \\  "xai-oauth": {
    \\    "type": "oauth",
    \\    "access": "fixture-pi-url-diverge-access-NOT-REAL-99ii",
    \\    "refresh": "fixture-pi-url-diverge-refresh-NOT-REAL-00jj",
    \\    "tokenEndpoint": "https://oauth-edge.custom.invalid/oauth2/token",
    \\    "baseUrl": "https://inference-proxy.custom.invalid/v1",
    \\    "discovery": {
    \\      "token_endpoint": "https://oauth-edge.custom.invalid/oauth2/token",
    \\      "authorization_endpoint": "https://oauth-edge.custom.invalid/oauth2/authorize"
    \\    }
    \\  },
    \\  "openrouter": {
    \\    "type": "api_key",
    \\    "key": "sk-fixture-pi-url-diverge-or-key-NOT-REAL-11kk",
    \\    "baseUrl": "https://openrouter-gateway.custom.invalid/api/v1"
    \\  },
    \\  "unknown-vendor-xyz": {
    \\    "type": "api_key",
    \\    "key": "sk-fixture-unknown-vendor-key-DEADBEEF"
    \\  }
    \\}
;

// ---------------------------------------------------------------------------
// Test helpers (tmp HOME planting + assertions)
// ---------------------------------------------------------------------------

fn freeHosts(allocator: std.mem.Allocator, hosts: []const []const u8) void {
    schema.freeStringList(allocator, hosts);
}

fn listContainsExact(hosts: []const []const u8, needle: []const u8) bool {
    for (hosts) |h| {
        if (std.mem.eql(u8, h, needle)) return true;
    }
    return false;
}

fn assertNoFixtureSecrets(hosts: []const []const u8) !void {
    for (hosts) |h| {
        for (fixture_secret_needles) |secret| {
            try std.testing.expect(std.mem.indexOf(u8, h, secret) == null);
        }
        // Broad synthetic marker — tokens/keys in fixtures use this prefix.
        try std.testing.expect(std.mem.indexOf(u8, h, "sk-fixture") == null);
        try std.testing.expect(std.mem.indexOf(u8, h, "NOT-REAL") == null);
        // Hostnames only: no scheme/path/userinfo leakage.
        try std.testing.expect(std.mem.indexOf(u8, h, "://") == null);
        try std.testing.expect(std.mem.indexOf(u8, h, "/") == null);
        try std.testing.expect(std.mem.indexOf(u8, h, "@") == null);
    }
}

fn writeRel(dir: anytype, rel: []const u8, content: []const u8) !void {
    if (std.fs.path.dirname(rel)) |parent| {
        if (parent.len > 0) {
            try dir.createDirPath(std.testing.io, parent);
        }
    }
    const file = try dir.createFile(std.testing.io, rel, .{});
    defer file.close(std.testing.io);
    try file.writeStreamingAll(std.testing.io, content);
}

fn plantPiHome(home_dir: anytype, auth: []const u8, settings: ?[]const u8) !void {
    try writeRel(home_dir, ".pi/agent/auth.json", auth);
    if (settings) |s| {
        try writeRel(home_dir, ".pi/agent/settings.json", s);
    }
}

fn plantOpencodeHome(home_dir: anytype, auth: []const u8) !void {
    try writeRel(home_dir, ".local/share/opencode/auth.json", auth);
}

fn homeAbs(tmp: anytype) ![]u8 {
    // realPathFileAlloc returns [:0]u8 (dupeZ). Re-dupe to plain []u8 so
    // `allocator.free(home)` matches allocation size under DebugAllocator
    // (Zig 0.16: free of coerced []u8 from [:0]u8 frees len, not len+1).
    const z = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(z);
    return try std.testing.allocator.dupe(u8, z);
}

// ---------------------------------------------------------------------------
// A-P3-1 / A-P3-4 — pi adapter (synthetic auth + settings)
// ---------------------------------------------------------------------------

test "inference_discover A-P3-1 pi xai-oauth tokenEndpoint and baseUrl yield auth.x.ai and api.x.ai" {
    // Realistic pi shape: xai-oauth.tokenEndpoint + baseUrl match first-party hosts
    // (catalog may also map the same ids; unconfounded extract is a separate test).
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try plantPiHome(tmp.dir, pi_auth_json, pi_settings_json);
    const home = try homeAbs(&tmp);
    defer std.testing.allocator.free(home);

    const hosts = try discoverForHost(std.testing.io, std.testing.allocator, "pi", home);
    defer freeHosts(std.testing.allocator, hosts);

    try std.testing.expect(listContainsExact(hosts, "auth.x.ai"));
    try std.testing.expect(listContainsExact(hosts, "api.x.ai"));
    try assertNoFixtureSecrets(hosts);
}

test "inference_discover A-P3-1 pi URL fields extract hosts not present in catalog defaults" {
    // Branch lock: known provider ids with baseUrl/tokenEndpoint hosts **≠** catalog
    // defaults. Catalog-only adapters cannot invent these hosts — extraction required.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try plantPiHome(tmp.dir, pi_auth_url_diverge_json, pi_settings_json);
    const home = try homeAbs(&tmp);
    defer std.testing.allocator.free(home);

    const hosts = try discoverForHost(std.testing.io, std.testing.allocator, "pi", home);
    defer freeHosts(std.testing.allocator, hosts);

    try std.testing.expect(listContainsExact(hosts, url_only_host_oauth_edge));
    try std.testing.expect(listContainsExact(hosts, url_only_host_inference_proxy));
    try std.testing.expect(listContainsExact(hosts, url_only_host_openrouter_gateway));
    // Bare unknown id still skipped (DIS-4 / NG-P3-5) — no invent from the id string.
    try std.testing.expect(!listContainsExact(hosts, "unknown-vendor-xyz"));
    try std.testing.expect(!listContainsExact(hosts, "unknown.vendor.xyz"));
    for (hosts) |h| {
        try std.testing.expect(std.mem.indexOf(u8, h, "unknown-vendor") == null);
    }
    try assertNoFixtureSecrets(hosts);
}

test "inference_discover A-P3-4 pi openrouter provider id maps via catalog to openrouter.ai" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try plantPiHome(tmp.dir, pi_auth_json, pi_settings_json);
    const home = try homeAbs(&tmp);
    defer std.testing.allocator.free(home);

    const hosts = try discoverForHost(std.testing.io, std.testing.allocator, "pi", home);
    defer freeHosts(std.testing.allocator, hosts);

    try std.testing.expect(listContainsExact(hosts, "openrouter.ai"));
    try assertNoFixtureSecrets(hosts);
}

test "inference_discover A-P3-4 pi unknown provider id is skipped (no invented host)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try plantPiHome(tmp.dir, pi_auth_json, pi_settings_json);
    const home = try homeAbs(&tmp);
    defer std.testing.allocator.free(home);

    const hosts = try discoverForHost(std.testing.io, std.testing.allocator, "pi", home);
    defer freeHosts(std.testing.allocator, hosts);

    // unknown-vendor-xyz has no catalog entry — must not invent a host from the id.
    try std.testing.expect(!listContainsExact(hosts, "unknown-vendor-xyz"));
    try std.testing.expect(!listContainsExact(hosts, "unknown.vendor.xyz"));
    for (hosts) |h| {
        try std.testing.expect(std.mem.indexOf(u8, h, "unknown-vendor") == null);
    }
    try assertNoFixtureSecrets(hosts);
}

test "inference_discover A-P3-1 pi synthetic fixtures contain no real secrets in emit" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try plantPiHome(tmp.dir, pi_auth_json, pi_settings_json);
    const home = try homeAbs(&tmp);
    defer std.testing.allocator.free(home);

    const hosts = try discoverForHost(std.testing.io, std.testing.allocator, "pi", home);
    defer freeHosts(std.testing.allocator, hosts);

    // Expected floor from this fixture: catalog + literal OAuth/API hosts only.
    try std.testing.expect(listContainsExact(hosts, "auth.x.ai"));
    try std.testing.expect(listContainsExact(hosts, "api.x.ai"));
    try std.testing.expect(listContainsExact(hosts, "openrouter.ai"));
    try assertNoFixtureSecrets(hosts);
}

// ---------------------------------------------------------------------------
// A-P3-1 / A-P3-4 — opencode adapter
// ---------------------------------------------------------------------------

test "inference_discover A-P3-4 opencode auth key xai maps via catalog to api.x.ai and auth.x.ai" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try plantOpencodeHome(tmp.dir, oc_auth_json);
    const home = try homeAbs(&tmp);
    defer std.testing.allocator.free(home);

    const hosts = try discoverForHost(std.testing.io, std.testing.allocator, "opencode", home);
    defer freeHosts(std.testing.allocator, hosts);

    try std.testing.expect(listContainsExact(hosts, "api.x.ai"));
    try std.testing.expect(listContainsExact(hosts, "auth.x.ai"));
    try assertNoFixtureSecrets(hosts);
}

test "inference_discover A-P3-4 opencode auth key opencode maps via catalog to opencode hosts" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try plantOpencodeHome(tmp.dir, oc_auth_json);
    const home = try homeAbs(&tmp);
    defer std.testing.allocator.free(home);

    const hosts = try discoverForHost(std.testing.io, std.testing.allocator, "opencode", home);
    defer freeHosts(std.testing.allocator, hosts);

    try std.testing.expect(listContainsExact(hosts, "opencode.ai"));
    try std.testing.expect(listContainsExact(hosts, "models.opencode.ai"));
    try assertNoFixtureSecrets(hosts);
}

test "inference_discover A-P3-4 opencode unknown auth key skipped" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try plantOpencodeHome(tmp.dir, oc_auth_json);
    const home = try homeAbs(&tmp);
    defer std.testing.allocator.free(home);

    const hosts = try discoverForHost(std.testing.io, std.testing.allocator, "opencode", home);
    defer freeHosts(std.testing.allocator, hosts);

    try std.testing.expect(!listContainsExact(hosts, "unknown-oc-vendor"));
    for (hosts) |h| {
        try std.testing.expect(std.mem.indexOf(u8, h, "unknown-oc") == null);
    }
    try assertNoFixtureSecrets(hosts);
}

test "inference_discover A-P3-1 opencode optional URL fields extract when present" {
    // Known ids (xai, openrouter) with baseUrl/tokenEndpoint hosts **≠** catalog
    // defaults. Catalog-only implementers miss these; URL extract is required.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try plantOpencodeHome(tmp.dir, oc_urls_auth_json);
    const home = try homeAbs(&tmp);
    defer std.testing.allocator.free(home);

    const hosts = try discoverForHost(std.testing.io, std.testing.allocator, "opencode", home);
    defer freeHosts(std.testing.allocator, hosts);

    try std.testing.expect(listContainsExact(hosts, url_only_host_oauth_edge));
    try std.testing.expect(listContainsExact(hosts, url_only_host_inference_proxy));
    try std.testing.expect(listContainsExact(hosts, url_only_host_openrouter_gateway));
    try assertNoFixtureSecrets(hosts);
}

// ---------------------------------------------------------------------------
// A-P3-2 / SEC-3 / SEC-7 — emit hygiene, soft empty, no harvest
// ---------------------------------------------------------------------------

test "inference_discover A-P3-2 emit never contains fixture token or key values" {
    // Catalog-matching fixtures + URL-divergence fixtures (distinct secret needles).
    {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        try plantPiHome(tmp.dir, pi_auth_json, pi_settings_json);
        try plantOpencodeHome(tmp.dir, oc_auth_json);
        const home = try homeAbs(&tmp);
        defer std.testing.allocator.free(home);

        const pi_hosts = try discoverForHost(std.testing.io, std.testing.allocator, "pi", home);
        defer freeHosts(std.testing.allocator, pi_hosts);
        const oc_hosts = try discoverForHost(std.testing.io, std.testing.allocator, "opencode", home);
        defer freeHosts(std.testing.allocator, oc_hosts);

        try assertNoFixtureSecrets(pi_hosts);
        try assertNoFixtureSecrets(oc_hosts);
    }
    {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        try plantPiHome(tmp.dir, pi_auth_url_diverge_json, null);
        try plantOpencodeHome(tmp.dir, oc_urls_auth_json);
        const home = try homeAbs(&tmp);
        defer std.testing.allocator.free(home);

        const pi_hosts = try discoverForHost(std.testing.io, std.testing.allocator, "pi", home);
        defer freeHosts(std.testing.allocator, pi_hosts);
        const oc_hosts = try discoverForHost(std.testing.io, std.testing.allocator, "opencode", home);
        defer freeHosts(std.testing.allocator, oc_hosts);

        try assertNoFixtureSecrets(pi_hosts);
        try assertNoFixtureSecrets(oc_hosts);
        // URL-only hosts must still be hostnames, not secret material.
        try std.testing.expect(listContainsExact(pi_hosts, url_only_host_oauth_edge));
        try std.testing.expect(listContainsExact(oc_hosts, url_only_host_openrouter_gateway));
    }
}

test "inference_discover SEC-7 does not harvest MCP or marketplace URLs from auth" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try plantPiHome(tmp.dir, pi_mcp_auth_json, null);
    const home = try homeAbs(&tmp);
    defer std.testing.allocator.free(home);

    const hosts = try discoverForHost(std.testing.io, std.testing.allocator, "pi", home);
    defer freeHosts(std.testing.allocator, hosts);

    // openrouter key still maps via catalog.
    try std.testing.expect(listContainsExact(hosts, "openrouter.ai"));
    // MCP / marketplace hosts must never be auto-allowed.
    try std.testing.expect(!listContainsExact(hosts, "evil-mcp.example.com"));
    try std.testing.expect(!listContainsExact(hosts, "marketplace-harvest.example.com"));
    for (hosts) |h| {
        try std.testing.expect(std.mem.indexOf(u8, h, "evil-mcp") == null);
        try std.testing.expect(std.mem.indexOf(u8, h, "marketplace-harvest") == null);
        try std.testing.expect(std.mem.indexOf(u8, h, "example.com") == null);
    }
    try assertNoFixtureSecrets(hosts);
}

test "inference_discover soft-empty when auth file is missing" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    // Empty HOME: no .pi / no opencode trees.
    const home = try homeAbs(&tmp);
    defer std.testing.allocator.free(home);

    const pi_hosts = try discoverForHost(std.testing.io, std.testing.allocator, "pi", home);
    defer freeHosts(std.testing.allocator, pi_hosts);
    const oc_hosts = try discoverForHost(std.testing.io, std.testing.allocator, "opencode", home);
    defer freeHosts(std.testing.allocator, oc_hosts);

    try std.testing.expectEqual(@as(usize, 0), pi_hosts.len);
    try std.testing.expectEqual(@as(usize, 0), oc_hosts.len);
}

test "inference_discover soft-empty when auth JSON is corrupt" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try plantPiHome(tmp.dir, pi_corrupt_auth_json, null);
    try plantOpencodeHome(tmp.dir, "{ not-json-at-all !!!");
    const home = try homeAbs(&tmp);
    defer std.testing.allocator.free(home);

    const pi_hosts = try discoverForHost(std.testing.io, std.testing.allocator, "pi", home);
    defer freeHosts(std.testing.allocator, pi_hosts);
    const oc_hosts = try discoverForHost(std.testing.io, std.testing.allocator, "opencode", home);
    defer freeHosts(std.testing.allocator, oc_hosts);

    try std.testing.expectEqual(@as(usize, 0), pi_hosts.len);
    try std.testing.expectEqual(@as(usize, 0), oc_hosts.len);
}

test "inference_discover soft-empty when auth object is empty" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try plantPiHome(tmp.dir, pi_empty_auth_json, null);
    try plantOpencodeHome(tmp.dir, "{}");
    const home = try homeAbs(&tmp);
    defer std.testing.allocator.free(home);

    const pi_hosts = try discoverForHost(std.testing.io, std.testing.allocator, "pi", home);
    defer freeHosts(std.testing.allocator, pi_hosts);
    const oc_hosts = try discoverForHost(std.testing.io, std.testing.allocator, "opencode", home);
    defer freeHosts(std.testing.allocator, oc_hosts);

    try std.testing.expectEqual(@as(usize, 0), pi_hosts.len);
    try std.testing.expectEqual(@as(usize, 0), oc_hosts.len);
}

test "inference_discover soft-empty for unknown host_key" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try plantPiHome(tmp.dir, pi_auth_json, pi_settings_json);
    try plantOpencodeHome(tmp.dir, oc_auth_json);
    const home = try homeAbs(&tmp);
    defer std.testing.allocator.free(home);

    // Launch aliases that are not pi/opencode adapters in this unit → soft empty
    // (claude/codex/grok are stretch S6, not inventing hosts here).
    const hosts = try discoverForHost(std.testing.io, std.testing.allocator, "not-a-host-key", home);
    defer freeHosts(std.testing.allocator, hosts);
    try std.testing.expectEqual(@as(usize, 0), hosts.len);
}

test "inference_discover soft-empty or truncate when auth file is huge" {
    // Fail-closed size cap — soft skip, do not OOM or panic.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    // ~2 MiB of non-JSON filler (well over any reasonable config cap).
    const huge = try std.testing.allocator.alloc(u8, 2 * 1024 * 1024);
    defer std.testing.allocator.free(huge);
    @memset(huge, 'A');
    try plantPiHome(tmp.dir, huge, null);
    try plantOpencodeHome(tmp.dir, huge);
    const home = try homeAbs(&tmp);
    defer std.testing.allocator.free(home);

    const pi_hosts = try discoverForHost(std.testing.io, std.testing.allocator, "pi", home);
    defer freeHosts(std.testing.allocator, pi_hosts);
    const oc_hosts = try discoverForHost(std.testing.io, std.testing.allocator, "opencode", home);
    defer freeHosts(std.testing.allocator, oc_hosts);

    // Soft: empty list (skip) is the product floor; never crash.
    try std.testing.expectEqual(@as(usize, 0), pi_hosts.len);
    try std.testing.expectEqual(@as(usize, 0), oc_hosts.len);
}

test "inference_discover host_key pi does not read opencode paths and vice versa" {
    // Isolation both directions: each host_key only reads its documented tree.

    // Direction 1: only opencode auth planted → pi empty, opencode has catalog hosts.
    {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        try plantOpencodeHome(tmp.dir, oc_auth_json);
        const home = try homeAbs(&tmp);
        defer std.testing.allocator.free(home);

        const pi_hosts = try discoverForHost(std.testing.io, std.testing.allocator, "pi", home);
        defer freeHosts(std.testing.allocator, pi_hosts);
        try std.testing.expectEqual(@as(usize, 0), pi_hosts.len);

        const oc_hosts = try discoverForHost(std.testing.io, std.testing.allocator, "opencode", home);
        defer freeHosts(std.testing.allocator, oc_hosts);
        try std.testing.expect(listContainsExact(oc_hosts, "api.x.ai"));
    }

    // Direction 2: only pi auth planted → opencode empty, pi has hosts.
    {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        try plantPiHome(tmp.dir, pi_auth_json, pi_settings_json);
        const home = try homeAbs(&tmp);
        defer std.testing.allocator.free(home);

        const oc_hosts = try discoverForHost(std.testing.io, std.testing.allocator, "opencode", home);
        defer freeHosts(std.testing.allocator, oc_hosts);
        try std.testing.expectEqual(@as(usize, 0), oc_hosts.len);

        const pi_hosts = try discoverForHost(std.testing.io, std.testing.allocator, "pi", home);
        defer freeHosts(std.testing.allocator, pi_hosts);
        try std.testing.expect(listContainsExact(pi_hosts, "openrouter.ai"));
        try assertNoFixtureSecrets(pi_hosts);
    }
}

test "inference_discover owned host list is independent of fixture file contents on disk" {
    // Prove allocator-owned contract: rewrite auth after discover; hosts still valid.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try plantPiHome(tmp.dir, pi_auth_json, pi_settings_json);
    const home = try homeAbs(&tmp);
    defer std.testing.allocator.free(home);

    const hosts = try discoverForHost(std.testing.io, std.testing.allocator, "pi", home);
    defer freeHosts(std.testing.allocator, hosts);

    try std.testing.expect(listContainsExact(hosts, "auth.x.ai"));

    // Overwrite on-disk auth with empty object; previously returned hosts must remain.
    try plantPiHome(tmp.dir, pi_empty_auth_json, null);
    try std.testing.expect(listContainsExact(hosts, "auth.x.ai"));
    try std.testing.expect(listContainsExact(hosts, "api.x.ai"));
    try std.testing.expect(listContainsExact(hosts, "openrouter.ai"));
    try assertNoFixtureSecrets(hosts);
}

// ---------------------------------------------------------------------------
// Agent-writable auth residual — known exfil sinks never auto-grant
// ---------------------------------------------------------------------------

test "inference_discover rejects pastebin baseUrl planted in agent-writable auth" {
    // Production residual: auth.json is agent-writable under empty-backpack RW.
    // Discovery must not auto-allow known exfil sinks even when present as baseUrl.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const plant =
        \\{
        \\  "xai": {
        \\    "type": "oauth",
        \\    "access": "fixture-sink-access-NOT-REAL",
        \\    "refresh": "fixture-sink-refresh-NOT-REAL",
        \\    "tokenEndpoint": "https://auth.x.ai/oauth2/token",
        \\    "baseUrl": "https://pastebin.com/raw/abc"
        \\  },
        \\  "evil-sink": {
        \\    "type": "api",
        \\    "key": "sk-fixture-sink-NOT-REAL",
        \\    "baseUrl": "https://webhook.site/abc"
        \\  }
        \\}
    ;
    try plantPiHome(tmp.dir, plant, null);
    const home = try homeAbs(&tmp);
    defer std.testing.allocator.free(home);

    const hosts = try discoverForHost(std.testing.io, std.testing.allocator, "pi", home);
    defer freeHosts(std.testing.allocator, hosts);

    // Catalog/known hosts from xai still allowed; sinks soft-dropped.
    try std.testing.expect(listContainsExact(hosts, "auth.x.ai"));
    try std.testing.expect(listContainsExact(hosts, "api.x.ai"));
    try std.testing.expect(!listContainsExact(hosts, "pastebin.com"));
    try std.testing.expect(!listContainsExact(hosts, "webhook.site"));
    for (hosts) |h| {
        try std.testing.expect(std.mem.indexOf(u8, h, "pastebin") == null);
        try std.testing.expect(std.mem.indexOf(u8, h, "webhook") == null);
    }
}

test "inference_discover rejects reserved class-token hosts planted as baseUrl" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const plant =
        \\{
        \\  "hostile": {
        \\    "type": "api",
        \\    "key": "sk-fixture-class-token-NOT-REAL",
        \\    "baseUrl": "https://private/",
        \\    "tokenEndpoint": "https://metadata/"
        \\  },
        \\  "xai": {
        \\    "type": "api",
        \\    "key": "sk-fixture-xai-ok-NOT-REAL",
        \\    "baseUrl": "https://api.x.ai/v1"
        \\  }
        \\}
    ;
    try plantPiHome(tmp.dir, plant, null);
    const home = try homeAbs(&tmp);
    defer std.testing.allocator.free(home);

    const hosts = try discoverForHost(std.testing.io, std.testing.allocator, "pi", home);
    defer freeHosts(std.testing.allocator, hosts);

    try std.testing.expect(listContainsExact(hosts, "api.x.ai"));
    try std.testing.expect(!listContainsExact(hosts, "private"));
    try std.testing.expect(!listContainsExact(hosts, "metadata"));
}

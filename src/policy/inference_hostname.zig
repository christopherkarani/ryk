//! Pure hostname extraction from adapter-approved URL / host fields (AINA P3 S1).
//!
//! Hostname extraction rules for AINA P3 discovery.
//! Ownership contract: `extractHostname` (producer p3-extract → adapters/managed).
//!
//! SEC-3: never emit secrets, userinfo, tokens, or credential material.
//! Intentionally does **not** call `network_eval.parseDestination` (that helper
//! strip-accepts userinfo; discovery must reject credential-bearing authorities).
//! Also rejects `network_eval` class/metapattern tokens (`private`, `metadata`,
//! `cloud-metadata`, `direct-ip`, bare `localhost`) and cloud-metadata hostnames
//! (`metadata.google.internal`) so discovery cannot widen class-wide allows.
//! No IP literals or OS-ambiguous IP-like spellings are emitted (loopback
//! requires user `policy.yaml`). Re-exported from `src/policy/mod.zig`.

const std = @import("std");
const network_eval = @import("network_eval.zig");

/// Maximum adapter field length considered for host extract (fail-closed oversize).
const max_field_len: usize = 8192;

/// `network_eval.matchesHostPattern` class tokens — never emit as allow hosts.
const reserved_policy_tokens = [_][]const u8{
    "private",
    "private:*",
    "metadata",
    "cloud-metadata",
    "direct-ip",
    "localhost", // class-wide: matches entire host_class.localhost
};

/// Extract a normalized inference hostname from an adapter-approved field
/// (`baseUrl`, `tokenEndpoint`, discovery URLs, or bare host).
///
/// - Success: allocator-owned lowercase hostname (no scheme, userinfo, path,
///   query, fragment, or port). Caller frees with `allocator.free`.
/// - Reject (`null`): empty/whitespace, path-only, credential-bearing
///   (userinfo), invalid UTF-8/NUL, bare wildcards, **all IP literals**
///   (incl. loopback), OS-ambiguous IP-like forms (`127.1`, hex/decimal dwords),
///   reserved policy class tokens, cloud-metadata hostnames.
///   Local Ollama / loopback requires explicit user `policy.yaml` allow.
/// - Errors: allocator failures only (`error.OutOfMemory`).
pub fn extractHostname(
    allocator: std.mem.Allocator,
    field: []const u8,
) std.mem.Allocator.Error!?[]u8 {
    if (field.len == 0 or field.len > max_field_len) return null;
    if (!std.unicode.utf8ValidateSlice(field)) return null;
    if (std.mem.indexOfScalar(u8, field, 0) != null) return null;

    const trimmed = std.mem.trim(u8, field, " \t\r\n");
    if (trimmed.len == 0) return null;

    var rest = trimmed;
    var had_scheme = false;
    if (std.mem.indexOf(u8, rest, "://")) |scheme_end| {
        if (scheme_end == 0) return null;
        // Scheme must be alphanumeric / +.- (reject garbage like "://host")
        const scheme = rest[0..scheme_end];
        if (!isPlausibleScheme(scheme)) return null;
        had_scheme = true;
        rest = rest[scheme_end + 3 ..];
    }

    // Absolute path-only (e.g. "/oauth2/token") — no host authority.
    if (rest.len > 0 and rest[0] == '/') return null;

    const authority_end = std.mem.indexOfAny(u8, rest, "/?#") orelse rest.len;
    const authority = rest[0..authority_end];
    if (authority.len == 0) return null;

    // SEC-3: credential-bearing authority must never emit a host.
    // (Unlike network_eval.parseDestination, which strip-accepts userinfo.)
    if (std.mem.indexOfScalar(u8, authority, '@') != null) return null;

    const has_tail = authority_end < rest.len;

    const host_raw = parseHostFromAuthority(authority) orelse return null;

    // Strip trailing DNS dots (FQDN form).
    var host = host_raw;
    while (host.len > 0 and host[host.len - 1] == '.') {
        host = host[0 .. host.len - 1];
    }
    host = std.mem.trim(u8, host, " \t\r\n");
    if (host.len == 0 or host.len > 253) return null;

    // Reject bare wildcards / single-char globs not product-tested.
    if (std.mem.indexOfScalar(u8, host, '*') != null) return null;
    if (std.mem.indexOfScalar(u8, host, '?') != null) return null;

    // Scheme-less `oauth2/token`-style path segments: not an unambiguous host.
    // Prefer extract only when authority looks like a hostname (multi-label /
    // loopback) when a path/query/fragment follows.
    if (!had_scheme and has_tail) {
        if (!isLoopbackHost(host) and std.mem.indexOfScalar(u8, host, '.') == null) {
            return null;
        }
    }

    if (!isAcceptableHost(host)) return null;

    const owned = try allocator.alloc(u8, host.len);
    for (host, 0..) |c, i| {
        owned[i] = std.ascii.toLower(c);
    }
    return owned;
}

/// True when `host` is a reserved `network_eval` class/metapattern token
/// (case-insensitive). Used by managed load revalidation and tests.
pub fn isReservedPolicyToken(host: []const u8) bool {
    for (reserved_policy_tokens) |token| {
        if (std.ascii.eqlIgnoreCase(host, token)) return true;
    }
    return false;
}

fn isPlausibleScheme(scheme: []const u8) bool {
    if (scheme.len == 0) return false;
    for (scheme) |c| {
        if (!(std.ascii.isAlphanumeric(c) or c == '+' or c == '-' or c == '.')) return false;
    }
    return true;
}

/// Parse host from authority (no userinfo — caller already rejected `@`).
/// Strips `:port` (default or non-default); port never appears in emit.
fn parseHostFromAuthority(authority: []const u8) ?[]const u8 {
    if (authority.len == 0) return null;

    if (authority[0] == '[') {
        // IPv6 literal in brackets: `[::1]` or `[::1]:11434`
        const close = std.mem.indexOfScalar(u8, authority, ']') orelse return null;
        if (close <= 1) return null;
        const host = authority[1..close];
        if (authority.len > close + 1) {
            if (authority[close + 1] != ':') return null;
            const port_str = authority[close + 2 ..];
            if (port_str.len == 0) return null;
            _ = std.fmt.parseInt(u16, port_str, 10) catch return null;
        }
        return host;
    }

    // Host:port — only when a single colon separates host from numeric port
    // (avoids treating raw IPv6 as host:port).
    if (std.mem.lastIndexOfScalar(u8, authority, ':')) |colon| {
        if (std.mem.indexOfScalar(u8, authority[0..colon], ':') == null) {
            const host = authority[0..colon];
            const port_str = authority[colon + 1 ..];
            if (host.len == 0 or port_str.len == 0) return null;
            _ = std.fmt.parseInt(u16, port_str, 10) catch return null;
            return host;
        }
    }

    return authority;
}

fn isAcceptableHost(host: []const u8) bool {
    if (isReservedPolicyToken(host)) return false;
    // Never emit cloud-metadata class hosts (exact `metadata` is already a
    // reserved token; multi-label `metadata.google.internal` needs this path).
    if (network_eval.isCloudMetadataHostname(host)) return false;
    // Bare localhost / *.localhost are class tokens/patterns — reject.
    if (std.ascii.eqlIgnoreCase(host, "localhost")) return false;
    if (std.ascii.endsWithIgnoreCase(host, ".localhost")) return false;
    // No IP literals in discovery emit — loopback residual requires user policy.yaml
    // (prevents allow-before-class-deny SSRF via agent-writable auth).
    if (parseIpv4(host) != null) return false;
    if (isIpv6Literal(host)) return false;
    // OS-ambiguous IP spellings that validDomain would accept as "hostnames"
    // (macOS getaddrinfo: 127.1, 10.1, 0x7f000001, decimal dword, …).
    if (isAmbiguousIpLike(host)) return false;
    // IP-embedded DNS rebinding (169.254.169.254.nip.io, 127.0.0.1.xip.io, …).
    if (hasIpv4EmbeddedInDomain(host)) return false;
    if (isDnsRebindingSuffix(host)) return false;
    return validDomain(host);
}

/// True when host has four consecutive all-digit labels forming an IPv4 dotted quad
/// as a prefix of a longer domain (e.g. `10.0.0.1.evil.example`).
fn hasIpv4EmbeddedInDomain(host: []const u8) bool {
    var labels: [16][]const u8 = undefined;
    var n: usize = 0;
    var it = std.mem.splitScalar(u8, host, '.');
    while (it.next()) |label| {
        if (n >= labels.len) break;
        labels[n] = label;
        n += 1;
    }
    if (n < 5) return false; // need IPv4 + at least one more label
    // Scan for four consecutive all-digit labels that form a valid IPv4.
    var i: usize = 0;
    while (i + 3 < n) : (i += 1) {
        var ok = true;
        var octets: [4]u8 = undefined;
        var j: usize = 0;
        while (j < 4) : (j += 1) {
            const lab = labels[i + j];
            if (!isAllAsciiDigits(lab) or lab.len == 0 or lab.len > 3) {
                ok = false;
                break;
            }
            if (lab.len > 1 and lab[0] == '0') {
                ok = false;
                break;
            }
            octets[j] = std.fmt.parseInt(u8, lab, 10) catch {
                ok = false;
                break;
            };
        }
        if (ok) return true;
    }
    return false;
}

/// Known public DNS rebinding / wildcard-to-IP services (hostname suffix match).
fn isDnsRebindingSuffix(host: []const u8) bool {
    const suffixes = [_][]const u8{
        "nip.io",
        "xip.io",
        "sslip.io",
        "localtest.me",
        "lvh.me",
        "vcap.me",
        "lacolhost.com",
    };
    for (suffixes) |suf| {
        if (std.ascii.eqlIgnoreCase(host, suf)) return true;
        if (host.len > suf.len + 1 and
            host[host.len - suf.len - 1] == '.' and
            std.ascii.eqlIgnoreCase(host[host.len - suf.len ..], suf))
            return true;
    }
    return false;
}

/// Reject host spellings that look like incomplete/hex/decimal IPv4 and would
/// resolve to loopback/private under common OS resolvers, yet pass validDomain.
fn isAmbiguousIpLike(host: []const u8) bool {
    if (host.len == 0) return false;

    // Pure decimal dword (e.g. 2130706433 → 127.0.0.1).
    if (isAllAsciiDigits(host)) {
        if (host.len >= 1 and host.len <= 10) return true;
    }

    // 0x… hex IPv4 (e.g. 0x7f000001).
    if (host.len > 2 and host[0] == '0' and (host[1] == 'x' or host[1] == 'X')) {
        var all_hex = true;
        for (host[2..]) |c| {
            if (!std.ascii.isHex(c)) {
                all_hex = false;
                break;
            }
        }
        if (all_hex and host.len > 2) return true;
    }

    // Dotted forms: any component that is pure digits or 0x-hex → treat as IP-like
    // when *all* labels are numeric-ish (not real multi-label DNS).
    var labels = std.mem.splitScalar(u8, host, '.');
    var n: usize = 0;
    var all_numeric_ish = true;
    while (labels.next()) |label| {
        n += 1;
        if (label.len == 0) return true; // empty label in dotted form
        if (!isNumericIshLabel(label)) all_numeric_ish = false;
    }
    // 1–3 all-numeric dotted components (127.1, 10.1, 192.168.1) or 4+ with hex/decimal mix.
    if (all_numeric_ish and n >= 1 and n <= 4) return true;
    // Mixed hex-dotted like 0x7f.0.0.1
    if (n >= 2 and n <= 4 and hostContainsHexLabel(host)) return true;
    return false;
}

fn isAllAsciiDigits(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| {
        if (!std.ascii.isDigit(c)) return false;
    }
    return true;
}

fn isNumericIshLabel(label: []const u8) bool {
    if (label.len == 0) return false;
    if (label.len > 2 and label[0] == '0' and (label[1] == 'x' or label[1] == 'X')) {
        for (label[2..]) |c| {
            if (!std.ascii.isHex(c)) return false;
        }
        return true;
    }
    return isAllAsciiDigits(label);
}

fn hostContainsHexLabel(host: []const u8) bool {
    var labels = std.mem.splitScalar(u8, host, '.');
    while (labels.next()) |label| {
        if (label.len > 2 and label[0] == '0' and (label[1] == 'x' or label[1] == 'X')) return true;
    }
    return false;
}

fn isCloudMetadataIpv4(ip: [4]u8) bool {
    return ip[0] == 169 and ip[1] == 254 and ip[2] == 169 and ip[3] == 254;
}

fn isLoopbackHost(host: []const u8) bool {
    // Used only for scheme-less path disambiguation — IP loopback only.
    if (parseIpv4(host)) |ip| return isLocalhostIp(ip);
    if (isIpv6Loopback(host)) return true;
    return false;
}

fn validDomain(host: []const u8) bool {
    if (host.len == 0) return false;
    var labels = std.mem.splitScalar(u8, host, '.');
    var saw_label = false;
    while (labels.next()) |label| {
        saw_label = true;
        if (label.len == 0 or label.len > 63) return false;
        if (label[0] == '-' or label[label.len - 1] == '-') return false;
        for (label) |char| {
            if (!(std.ascii.isAlphanumeric(char) or char == '-')) return false;
        }
    }
    return saw_label;
}

fn parseIpv4(host: []const u8) ?[4]u8 {
    var out: [4]u8 = undefined;
    var parts = std.mem.splitScalar(u8, host, '.');
    var index: usize = 0;
    while (parts.next()) |part| {
        if (index >= 4 or part.len == 0) return null;
        // Reject leading zeros (octal tricks: 01, 010) — only "0" itself is ok.
        if (part.len > 1 and part[0] == '0') return null;
        out[index] = std.fmt.parseInt(u8, part, 10) catch return null;
        index += 1;
    }
    if (index != 4) return null;
    return out;
}

fn isLocalhostIp(ip: [4]u8) bool {
    // Exact 127.0.0.1 only — not entire 127/8 (class residual would be wider than Ollama claim).
    return ip[0] == 127 and ip[1] == 0 and ip[2] == 0 and ip[3] == 1;
}

fn isIpv6Literal(host: []const u8) bool {
    // Minimal detect: contains ':' and only hex/colon/dot chars (incl. v4-mapped).
    if (std.mem.indexOfScalar(u8, host, ':') == null) return false;
    for (host) |c| {
        const ok = std.ascii.isHex(c) or c == ':' or c == '.';
        if (!ok) return false;
    }
    return true;
}

fn isIpv6Loopback(host: []const u8) bool {
    // Accept common textual forms of ::1 (case-insensitive hex).
    if (std.ascii.eqlIgnoreCase(host, "::1")) return true;
    if (std.ascii.eqlIgnoreCase(host, "0:0:0:0:0:0:0:1")) return true;
    return false;
}

// ---------------------------------------------------------------------------
// Acceptance 1 — absolute URL host extract (path ignored, default port stripped)
// ---------------------------------------------------------------------------

test "inference_hostname absolute https tokenEndpoint extracts auth.x.ai (path ignored)" {
    // Real pi xai-oauth shape: tokenEndpoint → OAuth host only (A-P3 / DIS-3).
    const allocator = std.testing.allocator;
    const host = try extractHostname(allocator, "https://auth.x.ai/oauth2/token");
    defer if (host) |h| allocator.free(h);

    try std.testing.expect(host != null);
    try std.testing.expectEqualStrings("auth.x.ai", host.?);
}

test "inference_hostname absolute https baseUrl extracts api.x.ai (path ignored)" {
    const allocator = std.testing.allocator;
    const host = try extractHostname(allocator, "https://api.x.ai/v1");
    defer if (host) |h| allocator.free(h);

    try std.testing.expect(host != null);
    try std.testing.expectEqualStrings("api.x.ai", host.?);
}

test "inference_hostname default https port 443 stripped from host" {
    const allocator = std.testing.allocator;
    const host = try extractHostname(allocator, "https://auth.x.ai:443/oauth2/token");
    defer if (host) |h| allocator.free(h);

    try std.testing.expect(host != null);
    try std.testing.expectEqualStrings("auth.x.ai", host.?);
    // Port must not leak into allowlist host string.
    try std.testing.expect(std.mem.indexOfScalar(u8, host.?, ':') == null);
}

test "inference_hostname default http port 80 stripped from host" {
    const allocator = std.testing.allocator;
    const host = try extractHostname(allocator, "http://models.opencode.ai:80/v1");
    defer if (host) |h| allocator.free(h);

    try std.testing.expect(host != null);
    try std.testing.expectEqualStrings("models.opencode.ai", host.?);
}

test "inference_hostname non-default port still yields host only (path-agnostic)" {
    // Allowlist is hostname-based; port is not part of the emitted host.
    const allocator = std.testing.allocator;
    const host = try extractHostname(allocator, "https://openrouter.ai:8443/api/v1/chat");
    defer if (host) |h| allocator.free(h);

    try std.testing.expect(host != null);
    try std.testing.expectEqualStrings("openrouter.ai", host.?);
    try std.testing.expect(std.mem.indexOfScalar(u8, host.?, ':') == null);
}

// ---------------------------------------------------------------------------
// Acceptance 2 — bare hostname normalize; empty / path-only reject
// ---------------------------------------------------------------------------

test "inference_hostname bare hostname lowercased" {
    const allocator = std.testing.allocator;
    const host = try extractHostname(allocator, "Auth.X.AI");
    defer if (host) |h| allocator.free(h);

    try std.testing.expect(host != null);
    try std.testing.expectEqualStrings("auth.x.ai", host.?);
}

test "inference_hostname bare hostname strips trailing dot" {
    const allocator = std.testing.allocator;
    const host = try extractHostname(allocator, "api.openai.com.");
    defer if (host) |h| allocator.free(h);

    try std.testing.expect(host != null);
    try std.testing.expectEqualStrings("api.openai.com", host.?);
}

test "inference_hostname empty field rejected" {
    const allocator = std.testing.allocator;
    const host = try extractHostname(allocator, "");
    defer if (host) |h| allocator.free(h);
    try std.testing.expect(host == null);
}

test "inference_hostname whitespace-only field rejected" {
    const allocator = std.testing.allocator;
    const host = try extractHostname(allocator, "   \t\n  ");
    defer if (host) |h| allocator.free(h);
    try std.testing.expect(host == null);
}

test "inference_hostname path-only absolute path rejected" {
    const allocator = std.testing.allocator;
    const host = try extractHostname(allocator, "/oauth2/token");
    defer if (host) |h| allocator.free(h);
    try std.testing.expect(host == null);
}

test "inference_hostname path-only relative segment rejected" {
    // Not a bare hostname (contains '/'); not an absolute URL.
    const allocator = std.testing.allocator;
    const host = try extractHostname(allocator, "oauth2/token");
    defer if (host) |h| allocator.free(h);
    try std.testing.expect(host == null);
}

// ---------------------------------------------------------------------------
// Acceptance 3 — userinfo / secrets rejected; tokens never in extract output
// ---------------------------------------------------------------------------

test "inference_hostname userinfo password URL rejected" {
    // Credential-bearing authority must not emit a host (SEC-3).
    // Reject is required; if a wrong impl strip-accepts, still forbid secret leak.
    const allocator = std.testing.allocator;
    const field = "https://user:sk-fixture-token-xyz@auth.x.ai/oauth2/token";
    const host = try extractHostname(allocator, field);
    defer if (host) |h| allocator.free(h);

    if (host) |h| {
        try std.testing.expect(std.mem.indexOf(u8, h, "sk-fixture-token-xyz") == null);
        try std.testing.expect(std.mem.indexOf(u8, h, "user:") == null);
        try std.testing.expect(std.mem.indexOfScalar(u8, h, '@') == null);
        try std.testing.expect(false); // acceptance: must be null, not strip-and-accept
    }
}

test "inference_hostname userinfo username-only URL rejected" {
    const allocator = std.testing.allocator;
    const host = try extractHostname(allocator, "https://oauth-client@api.x.ai/v1");
    defer if (host) |h| allocator.free(h);
    try std.testing.expect(host == null);
}

test "inference_hostname query token never appears in extract output" {
    // Path/query may carry synthetic secrets in fixtures; host emit is host only.
    const allocator = std.testing.allocator;
    const field = "https://api.x.ai/v1/chat?api_key=sk-fixture-query-token-abc123&ok=1";
    const host = try extractHostname(allocator, field);
    defer if (host) |h| allocator.free(h);

    try std.testing.expect(host != null);
    try std.testing.expectEqualStrings("api.x.ai", host.?);
    try std.testing.expect(std.mem.indexOf(u8, host.?, "sk-fixture-query-token-abc123") == null);
    try std.testing.expect(std.mem.indexOf(u8, host.?, "api_key") == null);
    try std.testing.expect(std.mem.indexOfScalar(u8, host.?, '?') == null);
    try std.testing.expect(std.mem.indexOfScalar(u8, host.?, '/') == null);
}

test "inference_hostname fragment and path never appear in extract output" {
    const allocator = std.testing.allocator;
    const host = try extractHostname(allocator, "https://openrouter.ai/api/v1#section");
    defer if (host) |h| allocator.free(h);

    try std.testing.expect(host != null);
    try std.testing.expectEqualStrings("openrouter.ai", host.?);
    try std.testing.expect(std.mem.indexOfScalar(u8, host.?, '#') == null);
    try std.testing.expect(std.mem.indexOf(u8, host.?, "api") == null);
}

// ---------------------------------------------------------------------------
// Branch paths — wildcards, IP literals, scheme trim, size/hostile input
// ---------------------------------------------------------------------------

test "inference_hostname bare wildcard pattern rejected" {
    // Reject bare wildcards not already product-tested.
    const allocator = std.testing.allocator;
    const host = try extractHostname(allocator, "*.amazonaws.com");
    defer if (host) |h| allocator.free(h);
    try std.testing.expect(host == null);
}

test "inference_hostname non-loopback IPv4 literal rejected" {
    const allocator = std.testing.allocator;
    const host = try extractHostname(allocator, "https://8.8.8.8/v1");
    defer if (host) |h| allocator.free(h);
    try std.testing.expect(host == null);
}

test "inference_hostname bare non-loopback IPv4 rejected" {
    const allocator = std.testing.allocator;
    const host = try extractHostname(allocator, "203.0.113.10");
    defer if (host) |h| allocator.free(h);
    try std.testing.expect(host == null);
}

test "inference_hostname rejects bare localhost class token" {
    // Bare "localhost" is a network_eval class pattern (all loopback), not a scoped residual.
    const allocator = std.testing.allocator;
    for ([_][]const u8{ "localhost", "LOCALHOST", "http://localhost:11434/v1", "foo.localhost" }) |field| {
        const host = try extractHostname(allocator, field);
        defer if (host) |h| allocator.free(h);
        try std.testing.expect(host == null);
    }
}

test "inference_hostname rejects all loopback and IP literals including 127.0.0.1" {
    // Discovery never auto-merges loopback; Ollama requires user policy.yaml.
    const allocator = std.testing.allocator;
    for ([_][]const u8{
        "127.0.0.1",
        "http://127.0.0.1:11434/v1",
        "127.0.0.2",
        "127.1.2.3",
        "::1",
        "http://[::1]:11434/",
    }) |field| {
        const host = try extractHostname(allocator, field);
        defer if (host) |h| allocator.free(h);
        try std.testing.expect(host == null);
    }
}

test "inference_hostname rejects OS-ambiguous IP-like host forms" {
    // macOS getaddrinfo-style: incomplete dotted, hex dword, decimal dword.
    const allocator = std.testing.allocator;
    for ([_][]const u8{
        "127.1",
        "http://127.1:9/",
        "127.0.1",
        "10.1",
        "192.168.1",
        "0x7f000001",
        "2130706433",
        "0x7f.0.0.1",
        "127.0.0.01",
    }) |field| {
        const host = try extractHostname(allocator, field);
        defer if (host) |h| allocator.free(h);
        try std.testing.expect(host == null);
    }
}

test "inference_hostname rejects IP-embedded DNS rebinding hosts" {
    const allocator = std.testing.allocator;
    for ([_][]const u8{
        "169.254.169.254.nip.io",
        "https://169.254.169.254.nip.io/latest/meta-data/",
        "127.0.0.1.xip.io",
        "10.0.0.1.sslip.io",
        "evil.nip.io",
        "foo.localtest.me",
    }) |field| {
        const host = try extractHostname(allocator, field);
        defer if (host) |h| allocator.free(h);
        try std.testing.expect(host == null);
    }
}

test "inference_hostname rejects metadata.google.internal cloud metadata host" {
    const allocator = std.testing.allocator;
    for ([_][]const u8{
        "metadata.google.internal",
        "https://metadata.google.internal/computeMetadata/v1/",
        "METADATA.GOOGLE.INTERNAL",
    }) |field| {
        const host = try extractHostname(allocator, field);
        defer if (host) |h| allocator.free(h);
        try std.testing.expect(host == null);
    }
}

test "inference_hostname rejects 169.254.169.254 IMDS IP" {
    const allocator = std.testing.allocator;
    const host = try extractHostname(allocator, "http://169.254.169.254/latest/meta-data/");
    defer if (host) |h| allocator.free(h);
    try std.testing.expect(host == null);
}

test "inference_hostname trims surrounding whitespace before parse" {
    const allocator = std.testing.allocator;
    const host = try extractHostname(allocator, "  https://api.anthropic.com/v1/messages  ");
    defer if (host) |h| allocator.free(h);

    try std.testing.expect(host != null);
    try std.testing.expectEqualStrings("api.anthropic.com", host.?);
}

test "inference_hostname scheme-less host with path still extracts host" {
    // Some config fields omit scheme but include a path suffix.
    // If implementer rejects this shape, keep residual note — prefer host extract
    // when authority is unambiguous (hostname + path, no userinfo).
    const allocator = std.testing.allocator;
    const host = try extractHostname(allocator, "api.x.ai/v1");
    defer if (host) |h| allocator.free(h);

    try std.testing.expect(host != null);
    try std.testing.expectEqualStrings("api.x.ai", host.?);
}

test "inference_hostname owned result is independent of input buffer" {
    // Prove caller-owned free contract: mutate input after extract; host unchanged.
    const allocator = std.testing.allocator;
    var field_buf = "https://models.opencode.ai/models".*;
    const host = try extractHostname(allocator, field_buf[0..]);
    defer if (host) |h| allocator.free(h);

    try std.testing.expect(host != null);
    try std.testing.expectEqualStrings("models.opencode.ai", host.?);

    // Overwrite input; owned host must remain valid.
    @memset(field_buf[0..], 'x');
    try std.testing.expectEqualStrings("models.opencode.ai", host.?);
}

test "inference_hostname rejects empty authority after scheme" {
    const allocator = std.testing.allocator;
    const host = try extractHostname(allocator, "https:///oauth2/token");
    defer if (host) |h| allocator.free(h);
    try std.testing.expect(host == null);
}

test "inference_hostname rejects bare userinfo without host emission of secrets" {
    // user:pass@host form without scheme — still credential-bearing.
    const allocator = std.testing.allocator;
    const field = "user:sk-fixture-bare-userinfo@auth.x.ai";
    const host = try extractHostname(allocator, field);
    defer if (host) |h| allocator.free(h);

    if (host) |h| {
        try std.testing.expect(std.mem.indexOf(u8, h, "sk-fixture-bare-userinfo") == null);
        try std.testing.expect(false); // acceptance: must be null
    }
}

// ---------------------------------------------------------------------------
// Reserved network_eval class tokens must never emit (SEC-1 / SEC-6 bypass)
// ---------------------------------------------------------------------------

test "inference_hostname rejects reserved policy token private" {
    const allocator = std.testing.allocator;
    for ([_][]const u8{ "private", "PRIVATE", "http://private/", "https://private/v1" }) |field| {
        const host = try extractHostname(allocator, field);
        defer if (host) |h| allocator.free(h);
        try std.testing.expect(host == null);
    }
}

test "inference_hostname rejects reserved policy token metadata and cloud-metadata" {
    const allocator = std.testing.allocator;
    for ([_][]const u8{
        "metadata",
        "https://metadata/",
        "cloud-metadata",
        "https://cloud-metadata/",
        "METADATA",
    }) |field| {
        const host = try extractHostname(allocator, field);
        defer if (host) |h| allocator.free(h);
        try std.testing.expect(host == null);
    }
}

test "inference_hostname rejects reserved policy token direct-ip" {
    const allocator = std.testing.allocator;
    for ([_][]const u8{ "direct-ip", "https://direct-ip/", "Direct-IP" }) |field| {
        const host = try extractHostname(allocator, field);
        defer if (host) |h| allocator.free(h);
        try std.testing.expect(host == null);
    }
}

test "inference_hostname rejects question-mark wildcard host" {
    const allocator = std.testing.allocator;
    const host = try extractHostname(allocator, "api?.example.com");
    defer if (host) |h| allocator.free(h);
    try std.testing.expect(host == null);
}

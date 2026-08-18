const std = @import("std");

pub const RedactionMatch = struct {
    label: []const u8,
    fingerprint: [8]u8,
};

const EnvAssignment = struct {
    name: []const u8,
    value: []const u8,
};

pub const redacted_value = "[REDACTED]";
const max_structured_input = 64 * 1024;

/// Returns an owned copy with secret-bearing spans replaced. The scan is bounded
/// and intentionally presentation-oriented: callers must continue to evaluate
/// and execute the original value.
pub fn redactAlloc(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    if (value.len > max_structured_input) return allocator.dupe(u8, redacted_value);
    if (try encodedContainsSecret(allocator, value)) return allocator.dupe(u8, redacted_value);
    // A vendor/SAS span must not skip classify-only secrets on the same value
    // (JWT / PEM / high-entropy / AKIA beside a Slack token or SAS URL).
    // Scan every token, not only the first `classifyString` label — Slack
    // before a JWT would otherwise win and leave the JWT in the clear.
    if (containsOpaqueSecret(value)) return allocator.dupe(u8, redacted_value);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var start: usize = 0;
    var i: usize = 0;
    while (i < value.len) {
        const match = findStructuredSecret(value, i) orelse break;
        try out.appendSlice(allocator, value[start..match.start]);
        try out.appendSlice(allocator, redacted_value);
        start = match.end;
        i = match.end;
    }
    if (start == 0) {
        if (classifyString(value) != null) return allocator.dupe(u8, redacted_value);
        return allocator.dupe(u8, value);
    }
    try out.appendSlice(allocator, value[start..]);
    return out.toOwnedSlice(allocator);
}

pub const path_safe_session_id = "redacted";

/// Session-id path key: keep the input, or return `path_safe_session_id`.
/// Structured provider tokens / AWS keys redact; high-entropy / JWT do not.
pub fn pathSafeSessionId(sid: []const u8) []const u8 {
    return if (sessionIdContainsStructuredSecret(sid)) path_safe_session_id else sid;
}

/// True when a session-id should become `path_safe_session_id`.
/// Hits: `findStructuredSecret` at a session-id boundary, vendor prefixes
/// (`xoxb-`, `sk_live_`, `glpat-`, `hf_`, …) at those same boundaries, or an
/// `AKIA`/`ASIA` key. Does **not** treat high-entropy / JWT blobs as secrets.
/// Callers must use `pathSafeSessionId`.
fn sessionIdContainsStructuredSecret(value: []const u8) bool {
    // Session ids are path keys. `findStructuredSecret` is a free-text scanner
    // and matches `sk-` at every byte, so `task-<uuid>` / `ask-followup-1`
    // would collapse onto `redacted`. Accept a hit only when the previous
    // byte is non-alnum (`-` / `_` / `.` count). Do not change the scanner
    // itself — glued `blockedsk-…` in commands must still redact.
    var from: usize = 0;
    while (findStructuredSecret(value, from)) |span| {
        // Session ids allow `_` as a separator (`sess_…`, OpenCode `ses_…`).
        // Env-var `isKeyStart` treats `_` as interior, which would keep
        // `sess_ghp_…`. Alnum-only interior still rejects `task-` / `ask-`.
        if (isSessionIdTokenBoundary(value, span.start)) return true;
        from = span.start + 1;
    }
    const trimmed = std.mem.trim(u8, value, " \t\r\n");
    if (looksLikeAwsAccessKey(trimmed)) return true;
    var i: usize = 0;
    while (i < value.len) : (i += 1) {
        if (!isSessionIdTokenBoundary(value, i)) continue;
        if (i + 20 <= value.len) {
            const cand = value[i .. i + 20];
            if (looksLikeAwsAccessKey(cand) and
                (i + 20 == value.len or !std.ascii.isAlphanumeric(value[i + 20])))
                return true;
        }
        // Vendor prefixes inside findStructuredSecret use isStructuredTokenBoundary,
        // which treats `_` as interior — so sess_xoxb- / sess_sk_live_ never emit
        // a span. Scan them here at session-id boundaries only.
        for (vendor_token_prefixes) |vendor| {
            if (!startsWithIgnoreCase(value[i..], vendor.prefix)) continue;
            var end = i + vendor.prefix.len;
            while (end < value.len and isTokenChar(value[end])) : (end += 1) {}
            if (end >= i + vendor.prefix.len + vendor.min_after) return true;
        }
    }
    return false;
}

fn isSessionIdTokenBoundary(value: []const u8, i: usize) bool {
    return i == 0 or !std.ascii.isAlphanumeric(value[i - 1]);
}

test "pathSafeSessionId keeps host ids and redacts structured tokens" {
    const Case = struct { sid: []const u8, want: []const u8 };
    const cases = [_]Case{
        .{ .sid = "", .want = "" },
        .{ .sid = "task-a1b2c3d4-e5f6-7890-abcd-ef1234567890", .want = "task-a1b2c3d4-e5f6-7890-abcd-ef1234567890" },
        .{ .sid = "ask-followup-1", .want = "ask-followup-1" },
        .{ .sid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890", .want = "a1b2c3d4-e5f6-7890-abcd-ef1234567890" },
        .{ .sid = "rollout-2026-07-30T21-25-08-019fb445-e7a9-7612-bf1a-8fe20ff9e69b", .want = "rollout-2026-07-30T21-25-08-019fb445-e7a9-7612-bf1a-8fe20ff9e69b" },
        .{ .sid = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.c2lnbmF0dXJl", .want = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.c2lnbmF0dXJl" },
        .{ .sid = "ghp_fakeSyntheticTokenValue1234567890", .want = path_safe_session_id },
        .{ .sid = "sess-sk-abcdefghijklmnop", .want = path_safe_session_id },
        .{ .sid = "sess_ghp_fakeSyntheticTokenValue1234567890", .want = path_safe_session_id },
        .{ .sid = "sess.ghp_fakeSyntheticTokenValue1234567890", .want = path_safe_session_id },
        .{ .sid = "GHP_0123456789AB", .want = path_safe_session_id },
        .{ .sid = "sess_AKIAIOSFODNN7EXAMPLE", .want = path_safe_session_id },
        .{ .sid = "sess_xoxb-abcdefghijkl", .want = path_safe_session_id },
        .{ .sid = "sess-xoxb-abcdefghijkl", .want = path_safe_session_id },
        .{ .sid = "sess_sk_live_abcdefgh", .want = path_safe_session_id },
        .{ .sid = "sess-glpat-abcdefghijkl", .want = path_safe_session_id },
        .{ .sid = "sess_hf_abcdefghijklmnopqrst", .want = path_safe_session_id },
    };
    for (cases) |case| {
        try std.testing.expectEqualStrings(case.want, pathSafeSessionId(case.sid));
    }
}

const vendor_token_prefixes = [_]struct { prefix: []const u8, min_after: usize }{
    .{ .prefix = "xoxb-", .min_after = 12 },
    .{ .prefix = "xoxp-", .min_after = 12 },
    .{ .prefix = "xoxa-", .min_after = 12 },
    .{ .prefix = "xoxs-", .min_after = 12 },
    .{ .prefix = "xoxe-", .min_after = 12 },
    .{ .prefix = "xoxc-", .min_after = 12 },
    .{ .prefix = "sk_live_", .min_after = 8 },
    .{ .prefix = "sk_test_", .min_after = 8 },
    .{ .prefix = "rk_live_", .min_after = 8 },
    .{ .prefix = "rk_test_", .min_after = 8 },
    .{ .prefix = "pk_live_", .min_after = 8 },
    .{ .prefix = "pk_test_", .min_after = 8 },
    .{ .prefix = "glpat-", .min_after = 12 },
    .{ .prefix = "gldt-", .min_after = 12 },
    // 20 after `hf_` (23 total) sits under real HF tokens (~34) and
    // above common HF_* identifiers (`HF_HUB_OFFLINE`, `hf_home_directory`).
    .{ .prefix = "hf_", .min_after = 20 },
};

const SecretSpan = struct { start: usize, end: usize };

fn findStructuredSecret(value: []const u8, from: usize) ?SecretSpan {
    var i = from;
    while (i < value.len) : (i += 1) {
        // Only syntactically valid markers are opaque. Attacker-controlled text
        // beginning with `[REDACTED` must not suppress scanning of its contents
        // or the remainder of the value.
        if (std.mem.startsWith(u8, value[i..], redacted_value[0 .. redacted_value.len - 1])) {
            if (std.mem.indexOfScalarPos(u8, value, i, ']')) |close| {
                if (isValidRedactionMarker(value[i .. close + 1])) {
                    i = close; // loop's `i += 1` advances past ']'
                    continue;
                }
            }
        }

        // URL userinfo credentials: `scheme://user:password@host`. The userinfo
        // (between `://` and the authority `@`) is a credential when it carries a
        // `:` separator, so connection strings like `mysql://user:pw@host` never
        // persist a raw password. Benign URLs (no `@` before the path) are left
        // intact.
        if (value[i] == ':' and i + 2 < value.len and value[i + 1] == '/' and value[i + 2] == '/') {
            const userinfo_start = i + 3;
            var scan = userinfo_start;
            while (scan < value.len and value[scan] != '@' and value[scan] != '/' and
                value[scan] != '?' and value[scan] != '#' and !std.ascii.isWhitespace(value[scan])) : (scan += 1)
            {}
            if (scan < value.len and value[scan] == '@' and scan > userinfo_start and
                std.mem.indexOfScalar(u8, value[userinfo_start..scan], ':') != null)
            {
                return .{ .start = userinfo_start, .end = scan };
            }
        }

        // Provider tokens are case-insensitive at presentation boundaries.
        const prefixes = [_][]const u8{ "github_pat_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "sk-ant-", "sk-" };
        for (prefixes) |prefix| {
            if (startsWithIgnoreCase(value[i..], prefix)) {
                var end = i + prefix.len;
                while (end < value.len and isTokenChar(value[end])) : (end += 1) {}
                // 12 catches short provider tokens without matching `sk-learn` (8).
                if (end - i >= 12) return .{ .start = i, .end = end };
            }
        }

        // Vendor prefixes use per-shape floors so Stripe `sk_live_`/`sk_test_`
        // (underscore) never collide with OpenAI `sk-`, and short false friends
        // (`xox`, `hf`, `HF_HUB_OFFLINE`, `glpat`) stay unclassified.
        // Token-char left boundary so mid-base64url `hf_` / `xoxb-` inside a
        // JWT or high-entropy blob does not punch a hole and skip classify.
        if (isStructuredTokenBoundary(value, i)) {
            for (vendor_token_prefixes) |vendor| {
                if (startsWithIgnoreCase(value[i..], vendor.prefix)) {
                    var end = i + vendor.prefix.len;
                    while (end < value.len and isTokenChar(value[end])) : (end += 1) {}
                    if (end >= i + vendor.prefix.len + vendor.min_after)
                        return .{ .start = i, .end = end };
                }
            }
        }

        if (startsWithIgnoreCase(value[i..], "sig=") and isQueryParamBoundary(value, i)) {
            if (azureSasSigAt(value, i)) |span| return span;
        }

        if (!isKeyStart(value, i)) continue;
        const key_start = i;
        var key_end = i;
        while (key_end < value.len and (std.ascii.isAlphanumeric(value[key_end]) or value[key_end] == '_' or value[key_end] == '-')) : (key_end += 1) {}
        if (!isSensitiveKey(value[key_start..key_end])) continue;
        var cursor = key_end;
        while (cursor < value.len and (value[cursor] == ' ' or value[cursor] == '\t' or value[cursor] == '"' or value[cursor] == '\'')) : (cursor += 1) {}
        if (cursor < value.len and value[cursor] == ':') cursor += 1 else if (cursor < value.len and value[cursor] == '=') cursor += 1 else continue;
        var continued_value = false;
        while (cursor < value.len and std.ascii.isWhitespace(value[cursor])) : (cursor += 1) {
            if (value[cursor] == '\r' or value[cursor] == '\n') continued_value = true;
        }
        var quote: ?u8 = null;
        if (cursor < value.len and (value[cursor] == '"' or value[cursor] == '\'')) {
            quote = value[cursor];
            cursor += 1;
        }
        // YAML block scalar indicators introduce an indented multi-line value.
        // Redact the complete block, not only the `|` / `>` indicator.
        if (quote == null and cursor < value.len and (value[cursor] == '|' or value[cursor] == '>')) {
            while (cursor < value.len and value[cursor] != '\r' and value[cursor] != '\n') : (cursor += 1) {}
            while (cursor < value.len) {
                var next = cursor;
                if (value[next] == '\r') next += 1;
                if (next < value.len and value[next] == '\n') next += 1;
                if (next >= value.len or (value[next] != ' ' and value[next] != '\t')) break;
                cursor = next;
                while (cursor < value.len and value[cursor] != '\r' and value[cursor] != '\n') : (cursor += 1) {}
            }
            return .{ .start = key_end, .end = cursor };
        }
        const secret_start = cursor;
        const header_value = std.ascii.eqlIgnoreCase(value[key_start..key_end], "authorization") or std.ascii.eqlIgnoreCase(value[key_start..key_end], "proxy-authorization");
        while (cursor < value.len) : (cursor += 1) {
            if (quote) |q| {
                if (value[cursor] == '\\' and cursor + 1 < value.len) {
                    cursor += 1;
                    continue;
                }
                if (value[cursor] == q) break;
            } else if (header_value and (value[cursor] == '\r' or value[cursor] == '\n')) {
                var continuation = cursor;
                if (value[continuation] == '\r') continuation += 1;
                if (continuation < value.len and value[continuation] == '\n') continuation += 1;
                if (continuation < value.len and (value[continuation] == ' ' or value[continuation] == '\t')) {
                    cursor = continuation;
                    continue;
                }
                break;
            } else if (!header_value and ((continued_value and (value[cursor] == '\r' or value[cursor] == '\n')) or (!continued_value and std.ascii.isWhitespace(value[cursor])) or value[cursor] == ',' or value[cursor] == '&' or value[cursor] == ';' or value[cursor] == '}')) break;
        }
        // Do not re-wrap a value that is already a redaction placeholder
        // (`token=[REDACTED:env:token:sha256:…]`); fall through so the loop-top
        // guard skips the opaque marker on the next iteration.
        if (cursor > secret_start and
            !std.mem.startsWith(u8, value[secret_start..cursor], redacted_value[0 .. redacted_value.len - 1]))
            return .{ .start = secret_start, .end = cursor };
    }
    return null;
}

fn isValidRedactionMarker(marker: []const u8) bool {
    if (std.mem.eql(u8, marker, redacted_value)) return true;
    if (marker.len < "[REDACTED::]".len or marker[marker.len - 1] != ']') return false;
    const body = marker["[REDACTED:".len .. marker.len - 1];
    const prefixes = [_][]const u8{ "env:", "secret:" };
    var payload: ?[]const u8 = null;
    for (prefixes) |prefix| {
        if (std.mem.startsWith(u8, body, prefix)) payload = body[prefix.len..];
    }
    const label = payload orelse return false;
    if (label.len == 0) return false;
    var end = label.len;
    if (std.mem.lastIndexOf(u8, label, ":sha256:")) |fingerprint_at| {
        const digest = label[fingerprint_at + ":sha256:".len ..];
        if (digest.len != 8) return false;
        for (digest) |char| if (!std.ascii.isHex(char)) return false;
        end = fingerprint_at;
    }
    if (end == 0) return false;
    for (label[0..end]) |char| {
        if (!(std.ascii.isAlphanumeric(char) or char == '_' or char == '-')) return false;
    }
    const clean_label = label[0..end];
    if (std.mem.startsWith(u8, body, "env:")) return isSecretEnvName(clean_label) or isLegacyEnvMarkerLabel(clean_label);
    return isKnownSecretMarkerLabel(clean_label);
}

fn isLegacyEnvMarkerLabel(label: []const u8) bool {
    // Older intercept markers used the structured key name as the env label.
    return std.ascii.eqlIgnoreCase(label, "token") or
        std.ascii.eqlIgnoreCase(label, "password") or
        std.ascii.eqlIgnoreCase(label, "api_key") or
        std.ascii.eqlIgnoreCase(label, "secret_access_key");
}

fn isKnownSecretMarkerLabel(label: []const u8) bool {
    const labels = [_][]const u8{
        "synthetic_secret",
        "pem_private_key",
        "ssh_private_key",
        "cloud_credentials_json",
        "aws_access_key",
        "github_token",
        "github_pat",
        "openai_api_key",
        "anthropic_api_key",
        "slack_token",
        "stripe_api_key",
        "huggingface_token",
        "gitlab_token",
        "azure_sas",
        "jwt",
        "high_entropy",
    };
    for (labels) |known| if (std.ascii.eqlIgnoreCase(label, known)) return true;
    return false;
}

pub fn isSensitiveKey(key: []const u8) bool {
    const trimmed = std.mem.trim(u8, key, "-/");
    const keys = [_][]const u8{ "authorization", "proxy-authorization", "password", "passwd", "passphrase", "pwd", "token", "access_token", "refresh_token", "api_key", "apikey", "private_key", "client_secret", "clientSecret", "cookie", "set-cookie", "session", "secret_access_key" };
    for (keys) |candidate| if (std.ascii.eqlIgnoreCase(trimmed, candidate)) return true;
    return isSecretEnvName(trimmed);
}

fn isKeyStart(value: []const u8, i: usize) bool {
    return i == 0 or !(std.ascii.isAlphanumeric(value[i - 1]) or value[i - 1] == '_');
}

fn isStructuredTokenBoundary(value: []const u8, i: usize) bool {
    if (i == 0) return true;
    const prev = value[i - 1];
    if (!isTokenChar(prev)) return true;
    // `-glpat` / `--glpat` are diff / CLI / YAML-list boundaries. A hyphen
    // that continues an alnum/_ run is base64url (`aaa-glpat` inside a JWT).
    if (prev != '-') return false;
    if (i < 2) return true;
    const before = value[i - 2];
    return !(std.ascii.isAlphanumeric(before) or before == '_');
}

fn isOpaqueSecretLabel(label: []const u8) bool {
    return std.mem.eql(u8, label, "secret:jwt") or
        std.mem.eql(u8, label, "secret:high_entropy") or
        std.mem.eql(u8, label, "secret:pem_private_key") or
        std.mem.eql(u8, label, "secret:ssh_private_key") or
        std.mem.eql(u8, label, "secret:cloud_credentials_json") or
        std.mem.eql(u8, label, "secret:aws_access_key");
}

// `@` `#` split leftover jwt / AKIA beside a vendor token. `+` and `/` stay
// out of the first pass: both are standard base64, and splitting them drops
// URL/prose high-entropy below the 32-char floor.
const embedded_token_delims = " \t\r\n?&=|,;:\"'()[]{}<>@#";
const leftover_glue_delims = embedded_token_delims ++ "+/";

fn tokenHasOpaqueSecret(token: []const u8) bool {
    const match = classifySecretValue(token) orelse return false;
    return isOpaqueSecretLabel(match.label);
}

fn containsOpaqueSecret(value: []const u8) bool {
    if (tokenHasOpaqueSecret(value)) return true;
    var tokens = std.mem.tokenizeAny(u8, value, embedded_token_delims);
    while (tokens.next()) |raw_token| {
        if (tokenHasOpaqueSecret(std.mem.trim(u8, raw_token, ":"))) return true;
    }
    // Second pass: leftover jwt / AKIA glued with `+` or `/`. Skip high_entropy
    // so a split base64 blob is not discarded after the first pass missed it.
    var slash_tokens = std.mem.tokenizeAny(u8, value, leftover_glue_delims);
    while (slash_tokens.next()) |raw_token| {
        if (classifySecretValue(std.mem.trim(u8, raw_token, ":"))) |match| {
            if (isOpaqueSecretLabel(match.label) and !std.mem.eql(u8, match.label, "secret:high_entropy"))
                return true;
        }
    }
    var assignments = std.mem.tokenizeAny(u8, value, " \t\r\n");
    while (assignments.next()) |raw_token| {
        if (parseEnvAssignment(trimCommandToken(raw_token))) |assignment| {
            if (tokenHasOpaqueSecret(assignment.value)) return true;
        }
    }
    return false;
}

fn startsWithIgnoreCase(value: []const u8, prefix: []const u8) bool {
    return value.len >= prefix.len and std.ascii.eqlIgnoreCase(value[0..prefix.len], prefix);
}

fn isTokenChar(char: u8) bool {
    return std.ascii.isAlphanumeric(char) or char == '_' or char == '-';
}

const percent_decode_depth_cap: u8 = 4;
const max_encoded_decoded = 1024;

fn containsSecretPlain(value: []const u8) bool {
    return findStructuredSecret(value, 0) != null or classifyString(value) != null;
}

fn percentUnfoldContainsSecret(value: []const u8, buffer: []u8) bool {
    var current = value;
    var depth: u8 = 0;
    while (depth < percent_decode_depth_cap) : (depth += 1) {
        const decoded = percentDecodeBounded(current, buffer) orelse return false;
        if (std.mem.eql(u8, decoded, current)) return false;
        if (containsSecretPlain(decoded)) return true;
        current = decoded;
    }
    return false;
}

fn encodedDecodedContainsSecret(decoded: []const u8) bool {
    if (!std.unicode.utf8ValidateSlice(decoded)) return false;
    if (containsSecretPlain(decoded)) return true;
    var unfold: [max_encoded_decoded]u8 = undefined;
    if (decoded.len > unfold.len) return false;
    return percentUnfoldContainsSecret(decoded, &unfold);
}

fn encodedDecodedContainsSecretAlloc(allocator: std.mem.Allocator, decoded: []const u8) !bool {
    if (!std.unicode.utf8ValidateSlice(decoded)) return false;
    if (containsSecretPlain(decoded)) return true;
    var current = try allocator.dupe(u8, decoded);
    defer allocator.free(current);
    var depth: u8 = 0;
    while (depth < percent_decode_depth_cap) : (depth += 1) {
        const next = try percentDecodeAlloc(allocator, current);
        if (std.mem.eql(u8, next, current)) {
            allocator.free(next);
            return false;
        }
        allocator.free(current);
        current = next;
        if (containsSecretPlain(current)) return true;
    }
    return false;
}

fn encodedContainsSecret(allocator: std.mem.Allocator, value: []const u8) !bool {
    var current = try allocator.dupe(u8, value);
    defer allocator.free(current);
    var depth: u8 = 0;
    while (depth < percent_decode_depth_cap) : (depth += 1) {
        const decoded = try percentDecodeAlloc(allocator, current);
        if (std.mem.eql(u8, decoded, current)) {
            allocator.free(decoded);
            break;
        }
        allocator.free(current);
        current = decoded;
        if (containsSecretPlain(current)) return true;
    }
    if (try encodedCandidateContainsSecret(allocator, value)) return true;
    var tokens = std.mem.tokenizeAny(u8, value, " \t\r\n\"'(),;:{}[]<>");
    var count: usize = 0;
    while (tokens.next()) |raw| {
        count += 1;
        if (count > 256) break;
        // Try the complete token first. Base64 padding uses `=`, so treating
        // every token containing it as an assignment would discard the encoded
        // payload before it reaches the decoder.
        if (try encodedCandidateContainsSecret(allocator, raw)) return true;
        const candidate = if (std.mem.indexOfScalar(u8, raw, '=')) |eq|
            if (eq + 1 < raw.len) raw[eq + 1 ..] else raw
        else
            raw;
        if (candidate.ptr != raw.ptr and try encodedCandidateContainsSecret(allocator, candidate)) return true;
    }
    return false;
}

fn encodedCandidateContainsSecret(allocator: std.mem.Allocator, value: []const u8) !bool {
    if (value.len >= 24 and value.len <= 1024) {
        const decoders = [_]std.base64.Base64Decoder{
            std.base64.standard.Decoder,
            std.base64.standard_no_pad.Decoder,
            std.base64.url_safe.Decoder,
            std.base64.url_safe_no_pad.Decoder,
        };
        for (decoders) |decoder| {
            const size = decoder.calcSizeForSlice(value) catch continue;
            if (size == 0 or size > max_structured_input) continue;
            const decoded = try allocator.alloc(u8, size);
            defer allocator.free(decoded);
            decoder.decode(decoded, value) catch continue;
            if (try encodedDecodedContainsSecretAlloc(allocator, decoded)) return true;
        }
    }
    if (value.len >= 40 and value.len <= 2048 and value.len % 2 == 0) {
        const decoded = try allocator.alloc(u8, value.len / 2);
        defer allocator.free(decoded);
        _ = std.fmt.hexToBytes(decoded, value) catch return false;
        if (try encodedDecodedContainsSecretAlloc(allocator, decoded)) return true;
    }
    return false;
}

fn percentDecodeAlloc(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var i: usize = 0;
    while (i < value.len) {
        if (value[i] == '%' and i + 2 < value.len) {
            const byte = std.fmt.parseInt(u8, value[i + 1 .. i + 3], 16) catch {
                try out.append(allocator, value[i]);
                i += 1;
                continue;
            };
            try out.append(allocator, byte);
            i += 3;
        } else {
            try out.append(allocator, value[i]);
            i += 1;
        }
    }
    return out.toOwnedSlice(allocator);
}

const secret_env_patterns = [_][]const u8{
    "*_TOKEN",
    "*_TOKEN_*",
    "TOKEN",
    "*_SECRET",
    "*_SECRET_*",
    "SECRET",
    "*_PASSWORD",
    "*_PASSWORD_*",
    "PASSWORD",
    "*_PASSWD",
    "*_PASSWD_*",
    "PASSWD",
    "*_PRIVATE_KEY",
    "PRIVATE_KEY",
    "*_API_KEY",
    "API_KEY",
    "*_ACCESS_KEY",
    "*_ACCESS_KEY_*",
    "*_SIGNING_KEY",
    "*_ENCRYPTION_KEY",
    "*_CLIENT_KEY",
    "KEY",
    "SECRET_KEY",
    "*_SECRET_KEY",
    "*_CREDENTIALS",
    "PGPASSWORD",
    "MYSQL_PWD",
};

const benign_env_names = [_][]const u8{
    "PWD",
    "OLDPWD",
    "HOME",
    "USER",
    "LOGNAME",
    "PATH",
    "TERM",
    "SHELL",
    "SHLVL",
    "DISPLAY",
    "SSH_AUTH_SOCK",
    "SSH_AGENT_PID",
    "CURSOR_CONVERSATION_ID",
    "CURSOR_TRACE_ID",
};

pub fn redactString(value: []const u8) []const u8 {
    var buf: [256]u8 = undefined;
    const redacted = redactStringBounded(value, &buf);
    if (redacted.ptr == value.ptr and redacted.len == value.len) return value;
    return redacted_value;
}

pub fn redactStringBounded(value: []const u8, buffer: []u8) []const u8 {
    if (value.len > max_structured_input) return redacted_value;
    if (encodedContainsSecretBounded(value)) return redacted_value;
    if (classifyString(value)) |match| {
        return formatReplacement(buffer, match.label) catch redacted_value;
    }
    // `classifyString` does not model sensitive-key assignments
    // (`{"password":"…"}`), header credentials (`Authorization: Bearer …`),
    // provider tokens embedded mid-string, or URL userinfo. The audit write path
    // (hash chain + summary) must match `redactAlloc`'s coverage, so run the same
    // structured scan here — bounded and alloc-free (P0-4).
    if (findStructuredSecret(value, 0) == null) return value;
    return redactStructuredBounded(value, buffer);
}

/// Allocation-free encoded secret detection for public/core boundary callers.
/// Encoded candidates are intentionally capped to fixed stack buffers. Inputs
/// outside those bounds fall back to the regular plaintext/structured scan.
fn encodedContainsSecretBounded(value: []const u8) bool {
    // Match the owned path's complete percent-decoding coverage without heap
    // allocation. The public input is already capped at max_structured_input.
    var percent_buf: [max_structured_input]u8 = undefined;
    if (percentUnfoldContainsSecret(value, &percent_buf)) return true;

    if (encodedCandidateContainsSecretBounded(value)) return true;
    var tokens = std.mem.tokenizeAny(u8, value, " \t\r\n\"'(),;:{}[]<>");
    var count: usize = 0;
    while (tokens.next()) |raw| {
        count += 1;
        if (count > 256) break;
        if (encodedCandidateContainsSecretBounded(raw)) return true;
        if (std.mem.indexOfScalar(u8, raw, '=')) |eq| {
            if (eq + 1 < raw.len and encodedCandidateContainsSecretBounded(raw[eq + 1 ..])) return true;
        }
    }
    return false;
}

fn encodedCandidateContainsSecretBounded(value: []const u8) bool {
    if (value.len >= 24 and value.len <= 1024) {
        const decoders = [_]std.base64.Base64Decoder{
            std.base64.standard.Decoder,
            std.base64.standard_no_pad.Decoder,
            std.base64.url_safe.Decoder,
            std.base64.url_safe_no_pad.Decoder,
        };
        var decoded: [768]u8 = undefined;
        for (decoders) |decoder| {
            const size = decoder.calcSizeForSlice(value) catch continue;
            if (size == 0 or size > decoded.len) continue;
            decoder.decode(decoded[0..size], value) catch continue;
            if (encodedDecodedContainsSecret(decoded[0..size])) return true;
        }
    }
    if (value.len >= 40 and value.len <= 2048 and value.len % 2 == 0) {
        var decoded: [1024]u8 = undefined;
        const size = value.len / 2;
        _ = std.fmt.hexToBytes(decoded[0..size], value) catch return false;
        if (encodedDecodedContainsSecret(decoded[0..size])) return true;
    }
    return false;
}

fn percentDecodeBounded(value: []const u8, buffer: []u8) ?[]const u8 {
    if (value.len > buffer.len) return null;
    var out_len: usize = 0;
    var i: usize = 0;
    while (i < value.len) {
        if (value[i] == '%' and i + 2 < value.len) {
            const byte = std.fmt.parseInt(u8, value[i + 1 .. i + 3], 16) catch {
                buffer[out_len] = value[i];
                out_len += 1;
                i += 1;
                continue;
            };
            buffer[out_len] = byte;
            out_len += 1;
            i += 3;
        } else {
            buffer[out_len] = value[i];
            out_len += 1;
            i += 1;
        }
    }
    return buffer[0..out_len];
}

/// Bounded twin of `redactAlloc`'s span replacement: copy `value` into `buffer`,
/// replacing each structured-secret span with `[REDACTED]`. If the result would
/// not fit the caller's buffer, redact the whole value (fail closed) rather than
/// risk emitting a partially-copied secret.
fn redactStructuredBounded(value: []const u8, buffer: []u8) []const u8 {
    var out_len: usize = 0;
    var copied: usize = 0;
    var cursor: usize = 0;
    while (cursor < value.len) {
        const span = findStructuredSecret(value, cursor) orelse break;
        const prefix = value[copied..span.start];
        if (out_len + prefix.len + redacted_value.len > buffer.len) return redacted_value;
        @memcpy(buffer[out_len .. out_len + prefix.len], prefix);
        out_len += prefix.len;
        @memcpy(buffer[out_len .. out_len + redacted_value.len], redacted_value);
        out_len += redacted_value.len;
        copied = span.end;
        cursor = span.end;
    }
    const tail = value[copied..];
    if (out_len + tail.len > buffer.len) return redacted_value;
    @memcpy(buffer[out_len .. out_len + tail.len], tail);
    out_len += tail.len;
    return buffer[0..out_len];
}

pub fn redactTargetValueBounded(kind_name: []const u8, value: []const u8, buffer: []u8) []const u8 {
    if (std.mem.eql(u8, kind_name, "env_var")) {
        if (classifySecretValue(value)) |match| {
            return formatReplacement(buffer, match.label) catch redacted_value;
        }
        if (containsOpaqueSecret(value) or findStructuredSecret(value, 0) != null) {
            return redactStringBounded(value, buffer);
        }
        return value;
    }
    return redactStringBounded(value, buffer);
}

/// Canonical owned target redaction for persistence and presentation sinks.
/// Allocation or decoding failure is fail-closed to a separately owned marker.
pub fn redactTargetValueAlloc(allocator: std.mem.Allocator, kind_name: []const u8, value: []const u8) ![]u8 {
    if (std.mem.eql(u8, kind_name, "env_var")) {
        if (classifySecretValue(value)) |match| {
            var buffer: [256]u8 = undefined;
            const replacement = formatReplacement(&buffer, match.label) catch redacted_value;
            return allocator.dupe(u8, replacement);
        }
    }
    return redactAlloc(allocator, value);
}

pub fn isSecretEnvName(name: []const u8) bool {
    for (benign_env_names) |benign| {
        if (std.ascii.eqlIgnoreCase(benign, name)) return false;
    }
    for (secret_env_patterns) |pattern| {
        if (matchesPatternIgnoreCase(pattern, name)) return true;
    }
    return false;
}

fn labeledMatch(label: []const u8) RedactionMatch {
    return .{ .label = label, .fingerprint = .{0} ** 8 };
}

pub fn classifyString(value: []const u8) ?RedactionMatch {
    if (parseEnvAssignment(value)) |assignment| {
        if (isSecretEnvName(assignment.name)) {
            return labeledMatch(assignment.name);
        }
        if (classifySecretValue(assignment.value)) |match| return match;
    }
    if (classifyEmbeddedAssignment(value)) |match| return match;
    if (classifyEmbeddedSecretToken(value)) |match| return match;
    return classifySecretValue(value);
}

pub fn classifySecretValue(value: []const u8) ?RedactionMatch {
    const trimmed = std.mem.trim(u8, value, " \t\r\n");
    if (trimmed.len == 0) return null;

    if (containsIgnoreCase(trimmed, "fake_secret") or containsIgnoreCase(trimmed, "fake-secret") or containsIgnoreCase(trimmed, "secret_value") or containsIgnoreCase(trimmed, "secret-value")) {
        return labeledMatch("secret:synthetic_secret");
    }
    if (containsIgnoreCase(trimmed, "-----BEGIN OPENSSH PRIVATE KEY-----")) {
        return labeledMatch("secret:ssh_private_key");
    }
    if (containsIgnoreCase(trimmed, "-----BEGIN ") and containsIgnoreCase(trimmed, "PRIVATE KEY-----")) {
        return labeledMatch("secret:pem_private_key");
    }
    if (containsCloudCredentialJson(trimmed)) {
        return labeledMatch("secret:cloud_credentials_json");
    }
    if (looksLikeAwsAccessKey(trimmed)) {
        return labeledMatch("secret:aws_access_key");
    }
    if (looksLikeGithubToken(trimmed)) {
        return labeledMatch("secret:github_token");
    }
    if (looksLikeOpenAiKey(trimmed)) {
        return labeledMatch("secret:openai_api_key");
    }
    if (looksLikeAnthropicKey(trimmed)) {
        return labeledMatch("secret:anthropic_api_key");
    }
    if (looksLikeSlackToken(trimmed)) {
        return labeledMatch("secret:slack_token");
    }
    if (looksLikeStripeKey(trimmed)) {
        return labeledMatch("secret:stripe_api_key");
    }
    if (looksLikeHuggingFaceToken(trimmed)) {
        return labeledMatch("secret:huggingface_token");
    }
    if (looksLikeGitlabToken(trimmed)) {
        return labeledMatch("secret:gitlab_token");
    }
    if (looksLikeAzureSas(trimmed)) {
        return labeledMatch("secret:azure_sas");
    }
    if (looksLikeJwt(trimmed)) {
        return labeledMatch("secret:jwt");
    }
    if (looksHighEntropy(trimmed)) {
        return labeledMatch("secret:high_entropy");
    }
    return null;
}

pub fn formatEnvReplacement(buffer: []u8, name: []const u8, value: []const u8) ![]const u8 {
    _ = value;
    return try std.fmt.bufPrint(buffer, "[REDACTED:env:{s}]", .{name});
}

fn formatReplacement(buffer: []u8, label: []const u8) ![]const u8 {
    if (std.mem.startsWith(u8, label, "secret:")) {
        return try std.fmt.bufPrint(buffer, "[REDACTED:{s}]", .{label});
    }
    return try std.fmt.bufPrint(buffer, "[REDACTED:env:{s}]", .{label});
}

fn parseEnvAssignment(value: []const u8) ?EnvAssignment {
    const eq = std.mem.indexOfScalar(u8, value, '=') orelse return null;
    if (eq == 0) return null;
    const name = value[0..eq];
    for (name) |char| {
        if (!(std.ascii.isAlphanumeric(char) or char == '_')) return null;
    }
    return .{ .name = name, .value = value[eq + 1 ..] };
}

fn classifyEmbeddedAssignment(value: []const u8) ?RedactionMatch {
    var tokens = std.mem.tokenizeAny(u8, value, " \t\r\n");
    while (tokens.next()) |raw_token| {
        const token = trimCommandToken(raw_token);
        if (parseEnvAssignment(token)) |assignment| {
            if (isSecretEnvName(assignment.name)) {
                return labeledMatch(assignment.name);
            }
            if (classifySecretValue(assignment.value)) |match| return match;
        }
    }
    return null;
}

fn classifyEmbeddedSecretToken(value: []const u8) ?RedactionMatch {
    var tokens = std.mem.tokenizeAny(u8, value, embedded_token_delims);
    while (tokens.next()) |raw_token| {
        const token = std.mem.trim(u8, raw_token, ":");
        if (classifySecretValue(token)) |match| return match;
    }
    var slash_tokens = std.mem.tokenizeAny(u8, value, leftover_glue_delims);
    while (slash_tokens.next()) |raw_token| {
        const token = std.mem.trim(u8, raw_token, ":");
        if (classifySecretValue(token)) |match| {
            if (!std.mem.eql(u8, match.label, "secret:high_entropy")) return match;
        }
    }
    return null;
}

fn trimCommandToken(token: []const u8) []const u8 {
    var out = std.mem.trim(u8, token, "\"'");
    while (out.len > 0 and (out[out.len - 1] == ',' or out[out.len - 1] == ';')) {
        out = out[0 .. out.len - 1];
        out = std.mem.trim(u8, out, "\"'");
    }
    return out;
}

fn looksLikeAwsAccessKey(value: []const u8) bool {
    if (value.len != 20) return false;
    if (!(std.mem.startsWith(u8, value, "AKIA") or std.mem.startsWith(u8, value, "ASIA"))) return false;
    for (value[4..]) |char| {
        if (!std.ascii.isAlphanumeric(char)) return false;
    }
    return true;
}

fn looksLikeGithubToken(value: []const u8) bool {
    return ((std.mem.startsWith(u8, value, "ghp_") or
        std.mem.startsWith(u8, value, "gho_") or
        std.mem.startsWith(u8, value, "ghu_") or
        std.mem.startsWith(u8, value, "ghs_") or
        std.mem.startsWith(u8, value, "ghr_")) and value.len >= 12) or
        (std.mem.startsWith(u8, value, "github_pat_") and value.len >= 20);
}

fn looksLikeOpenAiKey(value: []const u8) bool {
    return std.mem.startsWith(u8, value, "sk-") and value.len >= 12;
}

fn looksLikeAnthropicKey(value: []const u8) bool {
    return std.mem.startsWith(u8, value, "sk-ant-") and value.len >= 16;
}

fn looksLikePrefixedTokenChars(value: []const u8, prefix: []const u8, min_after: usize) bool {
    var token = value;
    var stripped: usize = 0;
    while (stripped < 2 and token.len > 0 and token[0] == '-') {
        token = token[1..];
        stripped += 1;
    }
    if (!startsWithIgnoreCase(token, prefix)) return false;
    var n: usize = 0;
    const rest = token[prefix.len..];
    while (n < rest.len and isTokenChar(rest[n])) : (n += 1) {}
    // Whole-value classify: the suffix must be the token-char run (no `!` padding).
    return n == rest.len and n >= min_after;
}

fn looksLikeSlackToken(value: []const u8) bool {
    const prefixes = [_][]const u8{ "xoxb-", "xoxp-", "xoxa-", "xoxs-", "xoxe-", "xoxc-" };
    for (prefixes) |prefix| {
        if (looksLikePrefixedTokenChars(value, prefix, 12)) return true;
    }
    return false;
}

fn looksLikeStripeKey(value: []const u8) bool {
    return looksLikePrefixedTokenChars(value, "sk_live_", 8) or
        looksLikePrefixedTokenChars(value, "sk_test_", 8) or
        looksLikePrefixedTokenChars(value, "rk_live_", 8) or
        looksLikePrefixedTokenChars(value, "rk_test_", 8) or
        looksLikePrefixedTokenChars(value, "pk_live_", 8) or
        looksLikePrefixedTokenChars(value, "pk_test_", 8);
}

fn looksLikeHuggingFaceToken(value: []const u8) bool {
    return looksLikePrefixedTokenChars(value, "hf_", 20);
}

fn looksLikeGitlabToken(value: []const u8) bool {
    return looksLikePrefixedTokenChars(value, "glpat-", 12) or
        looksLikePrefixedTokenChars(value, "gldt-", 12);
}

fn isQueryParamBoundary(value: []const u8, i: usize) bool {
    if (i == 0) return true;
    const prev = value[i - 1];
    return prev == '?' or prev == '&' or prev == ';' or prev == '=' or prev == '-' or
        !(std.ascii.isAlphanumeric(prev) or prev == '_');
}

fn looksLikeAzureSas(value: []const u8) bool {
    var i: usize = 0;
    while (i < value.len) : (i += 1) {
        if (startsWithIgnoreCase(value[i..], "sig=") and isQueryParamBoundary(value, i)) {
            if (azureSasSigAt(value, i) != null) return true;
        }
    }
    return false;
}

fn azureSasSigAt(value: []const u8, sig_at: usize) ?SecretSpan {
    const window = queryWindowContaining(value, sig_at);
    if (!queryHasParam(window, "sv")) return null;
    const sig_start = sig_at + "sig=".len;
    var sig_end = sig_start;
    while (sig_end < value.len and value[sig_end] != '&' and value[sig_end] != '#' and
        value[sig_end] != ';' and value[sig_end] != '"' and value[sig_end] != '\'' and
        value[sig_end] != ')' and value[sig_end] != '>' and
        !std.ascii.isWhitespace(value[sig_end])) : (sig_end += 1)
    {}
    if (!isConservativeAzureSasSig(value[sig_start..sig_end])) return null;
    return .{ .start = sig_start, .end = sig_end };
}

fn queryWindowContaining(value: []const u8, at: usize) []const u8 {
    var start = at;
    while (start > 0) {
        const prev = value[start - 1];
        if (std.ascii.isWhitespace(prev)) break;
        start -= 1;
        if (value[start] == '?') break;
    }
    var end = at;
    while (end < value.len and value[end] != '#' and !std.ascii.isWhitespace(value[end])) : (end += 1) {}
    return value[start..end];
}

fn queryHasParam(query: []const u8, name: []const u8) bool {
    var i: usize = 0;
    while (i < query.len) : (i += 1) {
        if (!startsWithIgnoreCase(query[i..], name)) continue;
        const eq = i + name.len;
        if (eq >= query.len or query[eq] != '=') continue;
        if (isQueryParamBoundary(query, i)) return true;
    }
    return false;
}

fn isConservativeAzureSasSig(sig: []const u8) bool {
    if (sig.len < 16) return false;
    var unique = [_]bool{false} ** 256;
    var unique_count: usize = 0;
    for (sig) |char| {
        const ok = std.ascii.isAlphanumeric(char) or char == '_' or char == '-' or
            char == '/' or char == '+' or char == '=' or char == '%' or char == '.';
        if (!ok) return false;
        if (!unique[char]) {
            unique[char] = true;
            unique_count += 1;
        }
    }
    return unique_count >= 8;
}

fn looksLikeJwt(value: []const u8) bool {
    // Standard JWT headers are base64url(`{…}`) and therefore start with `eyJ`.
    // Without that prefix, dotted identifiers (`files.read.deny`,
    // `classifier.local.prototype`) become false positives once part length
    // drops below 8.
    if (!std.mem.startsWith(u8, value, "eyJ")) return false;
    var parts: usize = 0;
    var start: usize = 0;
    while (start <= value.len) {
        const dot = std.mem.indexOfScalarPos(u8, value, start, '.') orelse value.len;
        const part = value[start..dot];
        if (part.len < 4) return false;
        for (part) |char| {
            if (!(std.ascii.isAlphanumeric(char) or char == '-' or char == '_')) return false;
        }
        parts += 1;
        if (dot == value.len) break;
        start = dot + 1;
    }
    return parts == 3;
}

fn looksHighEntropy(value: []const u8) bool {
    if (value.len < 32 or value.len > 512) return false;
    // `\` and `:` still skip (Windows paths, URLs, host:port). `/` is in the
    // standard base64 alphabet, so rejecting it let padded secrets evade.
    // Absolute/home/relative path prefixes stay out to keep the FP rate sane.
    if (std.mem.indexOfAny(u8, value, "\\:") != null) return false;
    if (value[0] == '/' or value[0] == '~') return false;
    if (std.mem.indexOf(u8, value, "./") != null or std.mem.indexOf(u8, value, ".\\") != null) return false;
    var classes: u8 = 0;
    var unique = [_]bool{false} ** 256;
    var unique_count: usize = 0;
    for (value) |char| {
        if (std.ascii.isUpper(char)) classes |= 1 else if (std.ascii.isLower(char)) classes |= 2 else if (std.ascii.isDigit(char)) classes |= 4 else if (char == '_' or char == '-' or char == '/' or char == '+' or char == '=') classes |= 8 else return false;
        if (!unique[char]) {
            unique[char] = true;
            unique_count += 1;
        }
    }
    return @popCount(classes) >= 3 and unique_count >= 16;
}

fn containsCloudCredentialJson(value: []const u8) bool {
    return (containsIgnoreCase(value, "\"type\"") and containsIgnoreCase(value, "\"service_account\"")) or
        containsIgnoreCase(value, "\"private_key\"") or
        containsIgnoreCase(value, "\"aws_access_key_id\"") or
        containsIgnoreCase(value, "\"client_email\"");
}

fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (haystack.len < needle.len) return false;
    var index: usize = 0;
    while (index + needle.len <= haystack.len) : (index += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[index .. index + needle.len], needle)) return true;
    }
    return false;
}

fn matchesPatternIgnoreCase(pattern: []const u8, value: []const u8) bool {
    return globMatchIgnoreCase(pattern, 0, value, 0);
}

fn globMatchIgnoreCase(pattern: []const u8, pattern_index: usize, value: []const u8, value_index: usize) bool {
    var p = pattern_index;
    var v = value_index;
    while (p < pattern.len) {
        switch (pattern[p]) {
            '*' => {
                while (p + 1 < pattern.len and pattern[p + 1] == '*') p += 1;
                if (p + 1 == pattern.len) return true;
                var next = v;
                while (next <= value.len) : (next += 1) {
                    if (globMatchIgnoreCase(pattern, p + 1, value, next)) return true;
                }
                return false;
            },
            '?' => {
                if (v >= value.len) return false;
                p += 1;
                v += 1;
            },
            else => |char| {
                if (v >= value.len or std.ascii.toLower(value[v]) != std.ascii.toLower(char)) return false;
                p += 1;
                v += 1;
            },
        }
    }
    return v == value.len;
}

test "secret env name detection covers common variables" {
    try std.testing.expect(isSecretEnvName("GITHUB_TOKEN"));
    try std.testing.expect(isSecretEnvName("FAKE_GITHUB_TOKEN"));
    try std.testing.expect(isSecretEnvName("OPENAI_API_KEY"));
    try std.testing.expect(!isSecretEnvName("SSH_AUTH_SOCK"));
    try std.testing.expect(!isSecretEnvName("PATH"));
}

test "secret value detection covers synthetic examples" {
    try std.testing.expect(classifySecretValue("-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----") != null);
    try std.testing.expect(classifySecretValue("AKIAIOSFODNN7EXAMPLE") != null);
    try std.testing.expect(classifySecretValue("ghp_fakeSyntheticTokenValue1234567890") != null);
    try std.testing.expect(classifySecretValue("sk-fakeSyntheticOpenAIKey1234567890") != null);
    try std.testing.expect(classifySecretValue("sk-ant-fakeSyntheticAnthropicKey1234567890") != null);
    try std.testing.expect(classifySecretValue("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.c2lnbmF0dXJl") != null);
    try std.testing.expect(classifySecretValue("Aa0Bb1Cc2Dd3Ee4Ff5Gg6Hh7Ii8Jj9Kk") != null);
    try std.testing.expect(classifySecretValue("{\"type\":\"service_account\",\"private_key\":\"FAKE\"}") != null);
    try std.testing.expect(classifySecretValue("/Users/fake/ryk/path/with/mixed/Chars123") == null);
    // Standard base64 `/` must not skip the entropy heuristic.
    try std.testing.expect(classifySecretValue("Aa0Bb1Cc2Dd3Ee4Ff5Gg6Hh7/Ii8Jj9Kk") != null);
    // Compact JWT parts under 8 chars (same alphabet as the fixture above).
    try std.testing.expect(classifySecretValue("eyJhbGc.eyJzdWI.c2lnbmF0dXJl") != null);
    try std.testing.expect(classifySecretValue("1.2.3") == null);
    try std.testing.expect(classifySecretValue("files.read.deny") == null);
    try std.testing.expect(classifySecretValue("classifier.local.prototype") == null);
    // Provider prefixes shorter than the old 20-char floor.
    try std.testing.expect(classifySecretValue("ghp_fakeSynthetic") != null);
    try std.testing.expect(classifySecretValue("sk-fakeSynthetic") != null);
    try std.testing.expect(classifySecretValue("sk-learn") == null);
    try std.testing.expect(classifySecretValue("xoxb-fakeSynthetic") != null);
    try std.testing.expect(classifySecretValue("sk_live_fakeSynth") != null);
    try std.testing.expect(classifySecretValue("hf_fakeSyntheticHuggingFaceTok") != null);
    try std.testing.expect(classifySecretValue("glpat-fakeSynthetic") != null);
    try std.testing.expect(classifySecretValue("sv=2021-06-08&sig=fakeSyntheticAzureSasSigValue") != null);
}

test "secret value detection covers vendor token shapes" {
    try expectSecretLabel("xoxb-fakeSynthetic", "secret:slack_token");
    try expectSecretLabel("xoxp-fakeSynthetic", "secret:slack_token");
    try expectSecretLabel("xoxa-fakeSynthetic", "secret:slack_token");
    try expectSecretLabel("xoxs-fakeSynthetic", "secret:slack_token");
    try expectSecretLabel("xoxe-fakeSynthetic", "secret:slack_token");
    try expectSecretLabel("xoxc-fakeSynthetic", "secret:slack_token");
    try expectSecretLabel("sk_live_fakeSynth", "secret:stripe_api_key");
    try expectSecretLabel("sk_test_fakeSynth", "secret:stripe_api_key");
    try expectSecretLabel("rk_live_fakeSynth", "secret:stripe_api_key");
    try expectSecretLabel("pk_test_fakeSynth", "secret:stripe_api_key");
    try expectSecretLabel("hf_fakeSyntheticHuggingFaceTok", "secret:huggingface_token");
    try expectSecretLabel("glpat-fakeSynthetic", "secret:gitlab_token");
    try expectSecretLabel("gldt-fakeSynthetic", "secret:gitlab_token");
    try expectSecretLabel("sv=2021-06-08&sig=fakeSyntheticAzureSasSigValue", "secret:azure_sas");
    try expectSecretLabel(
        "https://example.invalid/blob?sv=2021-06-08&sig=fakeSyntheticAzureSasSigValue",
        "secret:azure_sas",
    );
    try expectSecretLabel(
        "https://example.invalid/blob?sig=fakeSyntheticAzureSasSigValue&sv=2021-06-08",
        "secret:azure_sas",
    );

    // OpenAI hyphenated `sk-` must not collapse into Stripe's underscore prefixes.
    try expectSecretLabel("sk-fakeSynthetic", "secret:openai_api_key");
    try expectSecretLabel("sk-fakeSyntheticOpenAIKey1234567890", "secret:openai_api_key");

    // Case-insensitive classify (env_var target path has no structured-scan fallback).
    try expectSecretLabel("XOXB-fakeSyntheticUpperCase", "secret:slack_token");
    try expectSecretLabel("XOXA-fakeSyntheticUpperCase", "secret:slack_token");
    try expectSecretLabel("XOXS-fakeSyntheticUpperCase", "secret:slack_token");
    try expectSecretLabel("XOXE-fakeSyntheticUpperCase", "secret:slack_token");
    try expectSecretLabel("SK_LIVE_fakeSynth", "secret:stripe_api_key");
    try expectSecretLabel("SK_TEST_fakeSynth", "secret:stripe_api_key");
    try expectSecretLabel("HF_fakeSyntheticHuggingFaceTok", "secret:huggingface_token");
    try expectSecretLabel("GLPAT-fakeSynthetic", "secret:gitlab_token");

    // Inclusive N / exclusive N-1 token-char floors.
    try expectSecretLabel("xoxb-abcdefghijkl", "secret:slack_token");
    try std.testing.expect(classifySecretValue("xoxb-abcdefghijk") == null);
    try expectSecretLabel("sk_live_abcdefgh", "secret:stripe_api_key");
    try std.testing.expect(classifySecretValue("sk_live_abcdefg") == null);
    try expectSecretLabel("sk_test_abcdefgh", "secret:stripe_api_key");
    try std.testing.expect(classifySecretValue("sk_test_abcdefg") == null);
    try expectSecretLabel("glpat-abcdefghijkl", "secret:gitlab_token");
    try std.testing.expect(classifySecretValue("glpat-abcdefghijk") == null);
    try expectSecretLabel("hf_abcdefghijklmnopqrst", "secret:huggingface_token");
    try std.testing.expect(classifySecretValue("hf_abcdefghijklmnopqrs") == null);

    try std.testing.expect(classifySecretValue("sk-learn") == null);
    try std.testing.expect(classifySecretValue("xox") == null);
    try std.testing.expect(classifySecretValue("xoxb") == null);
    try std.testing.expect(classifySecretValue("xoxb-shorttoken") == null);
    try std.testing.expect(classifySecretValue("hf") == null);
    try std.testing.expect(classifySecretValue("hf_tooshort") == null);
    try std.testing.expect(classifySecretValue("hf_fakeSynth") == null);
    try std.testing.expect(classifySecretValue("HF_HUB_OFFLINE") == null);
    try std.testing.expect(classifySecretValue("hf_home_directory") == null);
    try std.testing.expect(classifySecretValue("hf_dataset_config") == null);
    try std.testing.expect(classifySecretValue("glpat") == null);
    try std.testing.expect(classifySecretValue("glpat_fakeSynthetic") == null);
    try std.testing.expect(classifySecretValue("sk_live_") == null);
    try std.testing.expect(classifySecretValue("sk_live_short") == null);
    try std.testing.expect(classifySecretValue("sk_test_short") == null);
    try std.testing.expect(classifySecretValue("xoxb-!!!!!!!!!!!!") == null);
    try std.testing.expect(classifySecretValue("sk_live_!!!!!!!!") == null);
    try std.testing.expect(classifySecretValue("glpat-!!!!!!!!!!!!") == null);
    try std.testing.expect(classifySecretValue("sv=2021-06-08") == null);
    // `sig=` without `sv=` is not Azure SAS. A long mixed sig may still trip the
    // independent high-entropy heuristic; only the SAS label is forbidden here.
    if (classifySecretValue("sig=fakeSyntheticAzureSasSigValue")) |match| {
        try std.testing.expect(!std.mem.eql(u8, match.label, "secret:azure_sas"));
    }
    try std.testing.expect(classifySecretValue("https://example.invalid/?sv=2021-06-08&sig=short") == null);
}

test "vendor tokens are redacted when embedded mid-string" {
    // Exact alloc results prove findStructuredSecret span replacement. If a
    // vendor row is removed from the scanner, classifyString can still swallow
    // the whole value and a "token disappeared" assertion would still pass.
    const span_cases = [_]struct { value: []const u8, expected: []const u8 }{
        .{ .value = "note xoxb-fakeSynthetic here", .expected = "note [REDACTED] here" },
        .{ .value = "note xoxp-fakeSynthetic here", .expected = "note [REDACTED] here" },
        .{ .value = "note xoxa-fakeSynthetic here", .expected = "note [REDACTED] here" },
        .{ .value = "note xoxs-fakeSynthetic here", .expected = "note [REDACTED] here" },
        .{ .value = "note xoxe-fakeSynthetic here", .expected = "note [REDACTED] here" },
        .{ .value = "charge sk_live_fakeSynth now", .expected = "charge [REDACTED] now" },
        .{ .value = "charge sk_test_fakeSynth now", .expected = "charge [REDACTED] now" },
        .{ .value = "model hf_fakeSyntheticHuggingFaceTok ready", .expected = "model [REDACTED] ready" },
        .{ .value = "clone glpat-fakeSynthetic ok", .expected = "clone [REDACTED] ok" },
        .{ .value = "note xoxc-fakeSynthetic here", .expected = "note [REDACTED] here" },
        .{ .value = "charge rk_live_fakeSynth now", .expected = "charge [REDACTED] now" },
        .{ .value = "clone gldt-fakeSynthetic ok", .expected = "clone [REDACTED] ok" },
        .{
            .value = "get https://example.invalid/blob?sv=2021-06-08&sig=fakeSyntheticAzureSasSigValue&sp=r",
            .expected = "get https://example.invalid/blob?sv=2021-06-08&sig=[REDACTED]&sp=r",
        },
        .{ .value = "prefix XOXB-fakeSynthetic suffix", .expected = "prefix [REDACTED] suffix" },
        .{ .value = "https://example.invalid/?q=sk_live_fakeSynth", .expected = "https://example.invalid/?q=[REDACTED]" },
    };
    for (span_cases) |case| {
        try expectSpanRedaction(case.value, case.expected);
    }

    // Alloc span-replaces. Bounded classifies `@`/`#`-split tokens and
    // whole-redacts the vendor label (more conservative; leftover jwt cannot leak).
    const glued = [_]struct { value: []const u8, expected_alloc: []const u8, expected_bounded: []const u8 }{
        .{ .value = "note@xoxb-fakeSynthetic@here", .expected_alloc = "note@[REDACTED]@here", .expected_bounded = "[REDACTED:secret:slack_token]" },
        .{ .value = "charge@sk_live_fakeSynth@now", .expected_alloc = "charge@[REDACTED]@now", .expected_bounded = "[REDACTED:secret:stripe_api_key]" },
        .{ .value = "model@hf_fakeSyntheticHuggingFaceTok@ready", .expected_alloc = "model@[REDACTED]@ready", .expected_bounded = "[REDACTED:secret:huggingface_token]" },
        .{ .value = "clone@glpat-fakeSynthetic@ok", .expected_alloc = "clone@[REDACTED]@ok", .expected_bounded = "[REDACTED:secret:gitlab_token]" },
    };
    for (glued) |case| {
        try expectSpanRedaction(case.value, case.expected_alloc);
        var buffer: [512]u8 = undefined;
        try std.testing.expectEqualStrings(case.expected_bounded, redactStringBounded(case.value, &buffer));
    }

    const benign = [_][]const u8{
        "sk-learn",
        "xox",
        "hf",
        "glpat",
        "xoxb-!!!!!!!!!!!!",
        "sk_live_!!!!!!!!",
        "glpat-!!!!!!!!!!!!",
        "HF_HUB_OFFLINE",
        "hf_home_directory",
        "hf_dataset_config",
        "hf_fakeSynth",
        "curl --user-agent ryk /health",
    };
    for (benign) |value| {
        const unchanged = try redactAlloc(std.testing.allocator, value);
        defer std.testing.allocator.free(unchanged);
        try std.testing.expectEqualStrings(value, unchanged);
    }
}

test "vendor prefixes inside jwt and high-entropy redact the whole value" {
    // Mid-base64url vendor prefixes must not punch a structured hole; classify
    // then whole-value redacts so the JWT header / entropy prefix cannot leak.
    const jwt_cases = [_][]const u8{
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.aaaaaaaaaaahf_abcdefghijklmnopqrst",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.aaaaaaaaaaaxoxb-fakeSynthetic",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.aaaaaaaaaaaglpat-fakeSynthetic",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.aaaaaaaaaaask_live_fakeSynth",
    };
    for (jwt_cases) |value| {
        try expectSecretLabel(value, "secret:jwt");
        const owned = try redactAlloc(std.testing.allocator, value);
        defer std.testing.allocator.free(owned);
        try std.testing.expectEqualStrings(redacted_value, owned);
        try std.testing.expect(std.mem.indexOf(u8, owned, "eyJ") == null);
    }

    const high_entropy = "Aa0Bb1Cc2Dd3Ee4Ff5Gg6Hh7Ii8Jj9Kkhf_abcdefghijklmnopqrst";
    try expectSecretLabel(high_entropy, "secret:high_entropy");
    const entropy_owned = try redactAlloc(std.testing.allocator, high_entropy);
    defer std.testing.allocator.free(entropy_owned);
    try std.testing.expectEqualStrings(redacted_value, entropy_owned);
    try std.testing.expect(std.mem.indexOf(u8, entropy_owned, "Aa0Bb1") == null);

    try expectSpanRedaction("note xoxb-fakeSynthetic here", "note [REDACTED] here");
}

test "hyphen-prefixed vendor tokens redact on classify and alloc" {
    const cases = [_]struct { value: []const u8, label: []const u8 }{
        .{ .value = "-glpat-01234567890123456789", .label = "secret:gitlab_token" },
        .{ .value = "--glpat-01234567890123456789", .label = "secret:gitlab_token" },
        .{ .value = "-xoxb-fakeSynthetic", .label = "secret:slack_token" },
        .{ .value = "-sk_live_fakeSynth", .label = "secret:stripe_api_key" },
        .{ .value = "-hf_fakeSyntheticHuggingFaceTok", .label = "secret:huggingface_token" },
    };
    for (cases) |case| {
        try expectSecretLabel(case.value, case.label);
        try expectRedactsSecret(case.value, case.value[if (case.value[1] == '-') 2 else 1 ..]);
    }
    try expectSpanRedaction("diff -glpat-01234567890123456789", "diff -[REDACTED]");
}

test "opaque secrets beside vendor or sas spans redact the whole alloc value" {
    const jwt_and_slack = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.c2lnbmF0dXJl xoxb-fakeSynthetic";
    try expectSecretLabel("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.c2lnbmF0dXJl", "secret:jwt");
    const jwt_owned = try redactAlloc(std.testing.allocator, jwt_and_slack);
    defer std.testing.allocator.free(jwt_owned);
    try std.testing.expectEqualStrings(redacted_value, jwt_owned);
    try std.testing.expect(std.mem.indexOf(u8, jwt_owned, "eyJ") == null);

    const pem =
        "-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY----- https://example.invalid/blob?sv=2021-06-08&sig=fakeSyntheticAzureSasSigValue";
    const pem_owned = try redactAlloc(std.testing.allocator, pem);
    defer std.testing.allocator.free(pem_owned);
    try std.testing.expectEqualStrings(redacted_value, pem_owned);
    try std.testing.expect(std.mem.indexOf(u8, pem_owned, "BEGIN PRIVATE KEY") == null);

    const slack_then_jwt = "xoxb-fakeSynthetic eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.c2lnbmF0dXJl";
    const slack_jwt_owned = try redactAlloc(std.testing.allocator, slack_then_jwt);
    defer std.testing.allocator.free(slack_jwt_owned);
    try std.testing.expectEqualStrings(redacted_value, slack_jwt_owned);
    try std.testing.expect(std.mem.indexOf(u8, slack_jwt_owned, "eyJ") == null);

    const entropy_and_slack = "Aa0Bb1Cc2Dd3Ee4Ff5Gg6Hh7Ii8Jj9Kk xoxb-fakeSynthetic";
    try expectSecretLabel("Aa0Bb1Cc2Dd3Ee4Ff5Gg6Hh7Ii8Jj9Kk", "secret:high_entropy");
    const entropy_slack_owned = try redactAlloc(std.testing.allocator, entropy_and_slack);
    defer std.testing.allocator.free(entropy_slack_owned);
    try std.testing.expectEqualStrings(redacted_value, entropy_slack_owned);
    try std.testing.expect(std.mem.indexOf(u8, entropy_slack_owned, "Aa0Bb1") == null);

    const akia_and_slack = "AKIAIOSFODNN7EXAMPLE xoxb-fakeSynthetic";
    const akia_owned = try redactAlloc(std.testing.allocator, akia_and_slack);
    defer std.testing.allocator.free(akia_owned);
    try std.testing.expectEqualStrings(redacted_value, akia_owned);
    try std.testing.expect(std.mem.indexOf(u8, akia_owned, "AKIA") == null);

    const leftover_glue = [_][]const u8{
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.c2lnbmF0dXJl@xoxb-fakeSynthetic",
        "xoxb-fakeSynthetic@eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.c2lnbmF0dXJl",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.c2lnbmF0dXJl+xoxb-fakeSynthetic",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.c2lnbmF0dXJl#xoxb-fakeSynthetic",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.c2lnbmF0dXJl/xoxb-fakeSynthetic",
        "Aa0Bb1Cc2Dd3Ee4Ff5Gg6Hh7+Ii8Jj9Kk xoxb-fakeSynthetic",
    };
    for (leftover_glue) |glued| {
        const glued_owned = try redactAlloc(std.testing.allocator, glued);
        defer std.testing.allocator.free(glued_owned);
        try std.testing.expectEqualStrings(redacted_value, glued_owned);
        try std.testing.expect(std.mem.indexOf(u8, glued_owned, "eyJ") == null);
        var buffer: [256]u8 = undefined;
        const bounded = redactStringBounded(glued, &buffer);
        try std.testing.expect(std.mem.indexOf(u8, bounded, "eyJ") == null);
        try std.testing.expect(std.mem.indexOf(u8, bounded, "xoxb-fakeSynthetic") == null);
    }
}

test "azure sas accepts hyphen prefix quotes and parens" {
    try expectSpanRedaction(
        "-sv=2021-06-08&sig=fakeSyntheticAzureSasSigValue",
        "-sv=2021-06-08&sig=[REDACTED]",
    );
    try expectSpanRedaction(
        "(sv=2021-06-08&sig=fakeSyntheticAzureSasSigValue)",
        "(sv=2021-06-08&sig=[REDACTED])",
    );
    try expectRedactsSecret(
        "\"sv=2021-06-08&sig=fakeSyntheticAzureSasSigValue\"",
        "fakeSyntheticAzureSasSigValue",
    );
}

test "env_var bounded redacts mixed opaque leftovers" {
    const mixed = "xoxb-fakeSynthetic eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.c2lnbmF0dXJl";
    var buffer: [256]u8 = undefined;
    const out = redactTargetValueBounded("env_var", mixed, &buffer);
    try std.testing.expect(std.mem.indexOf(u8, out, "eyJ") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "xoxb-fakeSynthetic") == null);
}

test "openssh private key classifies as ssh not pem" {
    try expectSecretLabel(
        "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKE\n-----END OPENSSH PRIVATE KEY-----",
        "secret:ssh_private_key",
    );
}

test "azure sas accepts connection-string semicolon and entity-escaped delimiters" {
    const connection =
        "BlobEndpoint=https://example.invalid/;SharedAccessSignature=sv=2021-06-08&ss=b&srt=sco&sp=r&sig=fakeSyntheticAzureSasSigValue";
    try expectSecretLabel(connection, "secret:azure_sas");
    const connection_owned = try redactAlloc(std.testing.allocator, connection);
    defer std.testing.allocator.free(connection_owned);
    try std.testing.expect(std.mem.indexOf(u8, connection_owned, "fakeSyntheticAzureSasSigValue") == null);
    try std.testing.expect(std.mem.indexOf(u8, connection_owned, "sv=") != null);
    var connection_buf: [512]u8 = undefined;
    const connection_bounded = redactStringBounded(connection, &connection_buf);
    try std.testing.expect(std.mem.indexOf(u8, connection_bounded, "fakeSyntheticAzureSasSigValue") == null);

    const amp = "https://example.invalid/blob?sv=2021-06-08&amp;sig=fakeSyntheticAzureSasSigValue";
    try expectSecretLabel(amp, "secret:azure_sas");
    try expectSpanRedaction(amp, "https://example.invalid/blob?sv=2021-06-08&amp;sig=[REDACTED]");

    const bare = "sv=2021-06-08;sig=fakeSyntheticAzureSasSigValue";
    try expectSecretLabel(bare, "secret:azure_sas");
    try expectSpanRedaction(bare, "sv=2021-06-08;sig=[REDACTED]");
}

test "uppercase vendor tokens redact on env_var target path" {
    const cases = [_]struct { value: []const u8, label: []const u8 }{
        .{ .value = "XOXB-fakeSyntheticUpperCase", .label = "[REDACTED:secret:slack_token]" },
        .{ .value = "SK_LIVE_fakeSynth", .label = "[REDACTED:secret:stripe_api_key]" },
        .{ .value = "HF_fakeSyntheticHuggingFaceTok", .label = "[REDACTED:secret:huggingface_token]" },
        .{ .value = "GLPAT-fakeSynthetic", .label = "[REDACTED:secret:gitlab_token]" },
    };
    for (cases) |case| {
        var buffer: [256]u8 = undefined;
        const out = redactTargetValueBounded("env_var", case.value, &buffer);
        try std.testing.expectEqualStrings(case.label, out);
    }
}

test "forged REDACTED prefix cannot hide later vendor tokens" {
    const cases = [_]struct { value: []const u8, secret: []const u8 }{
        .{ .value = "prefix [REDACTED then xoxb-fakeSynthetic", .secret = "xoxb-fakeSynthetic" },
        .{ .value = "prefix [REDACTED then sk_live_fakeSynth", .secret = "sk_live_fakeSynth" },
        .{ .value = "prefix [REDACTED then hf_fakeSyntheticHuggingFaceTok", .secret = "hf_fakeSyntheticHuggingFaceTok" },
        .{ .value = "prefix [REDACTED then glpat-fakeSynthetic", .secret = "glpat-fakeSynthetic" },
        .{
            .value = "prefix [REDACTED then https://example.invalid/?sv=2021-06-08&sig=fakeSyntheticAzureSasSigValue",
            .secret = "fakeSyntheticAzureSasSigValue",
        },
        .{ .value = "prefix [REDACTED password: xoxb-fakeSynthetic] suffix", .secret = "xoxb-fakeSynthetic" },
        .{ .value = "marker [REDACTED] then xoxb-fakeSynthetic", .secret = "xoxb-fakeSynthetic" },
    };
    for (cases) |case| {
        try expectRedactsSecret(case.value, case.secret);
    }
}

test "redaction labels are stable and do not include raw value" {
    var first: [256]u8 = undefined;
    var second: [256]u8 = undefined;
    const fake = "GITHUB_TOKEN=fake_secret_value";
    const a = redactStringBounded(fake, &first);
    const b = redactStringBounded(fake, &second);
    try std.testing.expectEqualStrings(a, b);
    try std.testing.expect(std.mem.indexOf(u8, a, "fake_secret_value") == null);
    try std.testing.expectEqualStrings("[REDACTED:env:GITHUB_TOKEN]", a);
}

test "redaction catches embedded synthetic secret assignments in command text" {
    var buf: [256]u8 = undefined;
    const command = "/bin/echo OPENAI_API_KEY=sk-fakeSyntheticOpenAIKey1234567890";
    const redacted = redactStringBounded(command, &buf);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "sk-fakeSyntheticOpenAIKey") == null);
    try std.testing.expectEqualStrings("[REDACTED:env:OPENAI_API_KEY]", redacted);
}

test "redaction covers synthetic policy url mcp and command contexts" {
    const cases = [_][]const u8{
        "env FAKE_GITHUB_TOKEN=ghp_fakeSyntheticTokenValue1234567890",
        "policy: api_key: sk-ant-fakeSyntheticAnthropicKey1234567890",
        "mcp args {\"OPENAI_API_KEY\":\"sk-fakeSyntheticOpenAIKey1234567890\"}",
        "url=https://example.invalid/?token=sk-fakeSyntheticOpenAIKey1234567890",
        "-----BEGIN PRIVATE KEY-----\nfake-secret-value\n-----END PRIVATE KEY-----",
        "{\"type\":\"service_account\",\"private_key\":\"fake-secret-value\",\"client_email\":\"fake@example.invalid\"}",
    };
    for (cases) |case| {
        var buf: [256]u8 = undefined;
        const redacted = redactStringBounded(case, &buf);
        try std.testing.expect(std.mem.indexOf(u8, redacted, "fakeSynthetic") == null);
        try std.testing.expect(std.mem.indexOf(u8, redacted, "fake-secret-value") == null);
        try std.testing.expect(std.mem.indexOf(u8, redacted, "[REDACTED:") != null);
    }
}

test "owned structured redaction preserves benign text and removes secret values" {
    const cases = [_][]const u8{
        "Authorization: Bearer correct-horse-battery-staple",
        "curl --token=correct-horse-battery-staple /health",
        "{\"password\":\"correct horse battery staple\",\"name\":\"ryk\"}",
        "prefix GhP_abcdefghijklmnopqrstuvwxyz suffix",
    };
    for (cases) |case| {
        const redacted = try redactAlloc(std.testing.allocator, case);
        defer std.testing.allocator.free(redacted);
        try std.testing.expect(std.mem.indexOf(u8, redacted, "correct") == null);
        try std.testing.expect(std.mem.indexOf(u8, redacted, "abcdefghijklmnopqrstuvwxyz") == null);
        try std.testing.expect(std.mem.indexOf(u8, redacted, redacted_value) != null);
    }
    const benign = "curl --user-agent ryk /health";
    const unchanged = try redactAlloc(std.testing.allocator, benign);
    defer std.testing.allocator.free(unchanged);
    try std.testing.expectEqualStrings(benign, unchanged);
}

test "owned redaction detects bounded encodings" {
    const encoded = [_][]const u8{
        "token%3Dcorrect-horse-battery-staple",
        "token%253Dcorrect-horse-battery-staple",
        "dG9rZW49Y29ycmVjdC1ob3JzZS1iYXR0ZXJ5LXN0YXBsZQ==",
        "746f6b656e3d636f72726563742d686f7273652d626174746572792d737461706c65",
    };
    for (encoded) |value| {
        const redacted = try redactAlloc(std.testing.allocator, value);
        defer std.testing.allocator.free(redacted);
        try std.testing.expectEqualStrings(redacted_value, redacted);
    }
}

test "bounded redaction matches owned encoded-secret coverage" {
    const encoded = [_][]const u8{
        "token%3Dcorrect-horse-battery-staple",
        "token%253Dcorrect-horse-battery-staple",
        "dG9rZW49Y29ycmVjdC1ob3JzZS1iYXR0ZXJ5LXN0YXBsZQ==",
        "dG9rZW49YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE/Pz8",
        "S0VZPWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYT8_Pw",
        "746f6b656e3d636f72726563742d686f7273652d626174746572792d737461706c65",
    };
    for (encoded) |value| {
        var buffer: [256]u8 = undefined;
        const redacted = redactStringBounded(value, &buffer);
        try std.testing.expectEqualStrings(redacted_value, redacted);
    }
}

test "bounded redaction finds encoded candidates embedded in prose" {
    const encoded = [_][]const u8{
        "prefix token%253Dcorrect-horse-battery-staple suffix",
        "payload=dG9rZW49Y29ycmVjdC1ob3JzZS1iYXR0ZXJ5LXN0YXBsZQ== mode=test",
        "prefix 746f6b656e3d636f72726563742d686f7273652d626174746572792d737461706c65 suffix",
    };
    for (encoded) |value| {
        var buffer: [256]u8 = undefined;
        try std.testing.expectEqualStrings(redacted_value, redactStringBounded(value, &buffer));
    }
}

test "bounded percent decoding covers the full public input limit" {
    const value = ("a" ** 2048) ++ " token%253Dcorrect-horse-battery-staple";
    var buffer: [256]u8 = undefined;
    try std.testing.expectEqualStrings(redacted_value, redactStringBounded(value, &buffer));
}

test "owned redaction detects encoded candidates embedded in prose and assignments" {
    const cases = [_][]const u8{
        "payload=dG9rZW49Y29ycmVjdC1ob3JzZS1iYXR0ZXJ5LXN0YXBsZQ== mode=test",
        "decoded candidate 746f6b656e3d636f72726563742d686f7273652d626174746572792d737461706c65 follows",
    };
    for (cases) |value| {
        const redacted = try redactAlloc(std.testing.allocator, value);
        defer std.testing.allocator.free(redacted);
        try std.testing.expectEqualStrings(redacted_value, redacted);
    }
}

test "owned redaction detects padded base64 embedded directly in prose" {
    // The decoded value is `token=` plus a low-entropy sentinel. Keeping the
    // encoded token low-entropy ensures this exercises decoding rather than the
    // independent high-entropy heuristic.
    const value = "decoded candidate dG9rZW49YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYQ== follows";
    const redacted = try redactAlloc(std.testing.allocator, value);
    defer std.testing.allocator.free(redacted);
    try std.testing.expectEqualStrings(redacted_value, redacted);
}

test "owned redaction detects valid unpadded standard base64" {
    // Decodes to `token=` followed by a deliberately low-entropy value. The
    // missing `=` padding is valid for standard no-pad base64.
    const value = "dG9rZW49YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE/Pz8";
    const redacted = try redactAlloc(std.testing.allocator, value);
    defer std.testing.allocator.free(redacted);
    try std.testing.expectEqualStrings(redacted_value, redacted);
}

test "owned redaction detects padded and unpadded URL-safe base64" {
    // Both candidates decode to the same low-entropy `KEY=...???` value. The
    // encoded forms stay below the independent high-entropy heuristic, so this
    // specifically proves URL-safe decoding.
    const candidates = [_][]const u8{
        "S0VZPWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYT8_Pw==",
        "S0VZPWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYT8_Pw",
    };
    for (candidates) |value| {
        const redacted = try redactAlloc(std.testing.allocator, value);
        defer std.testing.allocator.free(redacted);
        try std.testing.expectEqualStrings(redacted_value, redacted);
    }
}

test "owned redaction detects unpadded base64 secrets in prose and assignments" {
    const cases = [_][]const u8{
        "decoded candidate dG9rZW49YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE/Pz8 follows",
        "payload=dG9rZW49YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE_Pz8 mode=test",
    };
    for (cases) |value| {
        const redacted = try redactAlloc(std.testing.allocator, value);
        defer std.testing.allocator.free(redacted);
        try std.testing.expectEqualStrings(redacted_value, redacted);
    }
}

test "owned redaction preserves benign low-entropy base64 candidates" {
    const candidates = [_][]const u8{
        "eD1hYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYT8/Pw==",
        "eD1hYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYT8/Pw",
        "eD1hYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYT8_Pw==",
        "eD1hYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYT8_Pw",
    };
    for (candidates) |value| {
        const unchanged = try redactAlloc(std.testing.allocator, value);
        defer std.testing.allocator.free(unchanged);
        try std.testing.expectEqualStrings(value, unchanged);
    }
}

test "owned structured redaction handles escaped quotes inside secret JSON values" {
    const sentinel = "correct horse battery staple";
    const value = "{\"password\":\"prefix \\\"quoted\\\" correct horse battery staple\",\"name\":\"ryk\"}";
    const redacted = try redactAlloc(std.testing.allocator, value);
    defer std.testing.allocator.free(redacted);
    try std.testing.expect(std.mem.indexOf(u8, redacted, sentinel) == null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "quoted") == null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "\"name\":\"ryk\"") != null);
}

test "p0-4 bounded write-path redactor covers structured secrets classifyString misses" {
    // These bypassed the old bounded redactor (classifyString-only) and were
    // written verbatim to events.jsonl / summary.*. The bounded path must now
    // match redactAlloc's structured coverage.
    const cases = [_][]const u8{
        "{\"password\":\"hunter2\"}",
        "Authorization: Bearer abc123def456ghi789",
        "mysql://user:pw@host",
    };
    const raw_secrets = [_][]const u8{ "hunter2", "abc123def456ghi789", "user:pw" };
    for (cases, raw_secrets) |value, secret| {
        var buf: [256]u8 = undefined;
        const redacted = redactStringBounded(value, &buf);
        try std.testing.expect(std.mem.indexOf(u8, redacted, secret) == null);
        try std.testing.expect(std.mem.indexOf(u8, redacted, redacted_value) != null);
        // The returned slice must not alias the input (proves a replacement ran).
        try std.testing.expect(redacted.ptr != value.ptr);
    }
}

test "p0-4 URL userinfo credentials are redacted but benign URLs are preserved" {
    // Credential form: userinfo carries `user:password`.
    {
        const redacted = try redactAlloc(std.testing.allocator, "mysql://user:pw@host/db");
        defer std.testing.allocator.free(redacted);
        try std.testing.expect(std.mem.indexOf(u8, redacted, "user:pw") == null);
        try std.testing.expect(std.mem.indexOf(u8, redacted, redacted_value) != null);
        // Scheme and host survive (partial redaction, not whole-value).
        try std.testing.expect(std.mem.indexOf(u8, redacted, "mysql://") != null);
        try std.testing.expect(std.mem.indexOf(u8, redacted, "@host/db") != null);
    }
    // Benign URL: no userinfo → untouched.
    {
        const benign = "https://example.invalid/health";
        const unchanged = try redactAlloc(std.testing.allocator, benign);
        defer std.testing.allocator.free(unchanged);
        try std.testing.expectEqualStrings(benign, unchanged);
    }
    // Bounded path agrees on both.
    {
        var buf: [256]u8 = undefined;
        const redacted = redactStringBounded("redis://:s3cr3tPass@cache:6379", &buf);
        try std.testing.expect(std.mem.indexOf(u8, redacted, "s3cr3tPass") == null);
    }
}

test "p0-4 redaction is idempotent over existing [REDACTED] markers" {
    // Values flow through redaction more than once: the network intercept path
    // redacts a URL, then the audit write boundary redacts again. The second pass
    // must not rewrite an existing marker (regression: the redteam runner's
    // `[REDACTED:env:token:sha256:…]` marker was being clobbered to plain
    // `[REDACTED]`).
    const unchanged = [_][]const u8{
        "https://webhook.site/collect?token=[REDACTED:env:token:sha256:abcd1234]",
        "[REDACTED:secret:openai_api_key:sha256:deadbeef]",
    };
    for (unchanged) |value| {
        var buf: [256]u8 = undefined;
        const out = redactStringBounded(value, &buf);
        try std.testing.expectEqualStrings(value, out);
    }
    // A genuinely fresh secret next to an existing marker is still redacted.
    var buf: [256]u8 = undefined;
    const out = redactStringBounded("marker [REDACTED] then mysql://user:pw@host", &buf);
    try std.testing.expect(std.mem.indexOf(u8, out, "user:pw") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "[REDACTED]") != null);
}

test "p0-4 bounded redactor preserves benign values and buffer-overflow fails closed" {
    // Benign value: returned unchanged, aliasing the input.
    {
        var buf: [256]u8 = undefined;
        const benign = "git status --short";
        const out = redactStringBounded(benign, &buf);
        try std.testing.expectEqualStrings(benign, out);
        try std.testing.expect(out.ptr == benign.ptr);
    }
    // Structured secret that cannot fit the buffer → whole-value [REDACTED].
    {
        var tiny: [8]u8 = undefined;
        const out = redactStringBounded("{\"password\":\"hunter2\"}", &tiny);
        try std.testing.expectEqualStrings(redacted_value, out);
    }
}

test "canonical target redaction matches owned encoded coverage" {
    const encoded = [_][]const u8{
        "token%3Dcorrect-horse-battery-staple",
        "dG9rZW49Y29ycmVjdC1ob3JzZS1iYXR0ZXJ5LXN0YXBsZQ==",
        "746f6b656e3d636f72726563742d686f7273652d626174746572792d737461706c65",
    };
    for (encoded) |value| {
        const redacted = try redactTargetValueAlloc(std.testing.allocator, "command", value);
        defer std.testing.allocator.free(redacted);
        try std.testing.expectEqualStrings(redacted_value, redacted);
    }
}

test "forged and malformed redaction markers cannot hide later secrets" {
    const cases = [_][]const u8{
        "prefix [REDACTED password: correct-horse-battery-staple] suffix",
        "prefix [REDACTED then password=correct-horse-battery-staple",
        "prefix [REDACTED:env:token:sha256:not-hex] password=correct-horse-battery-staple",
    };
    for (cases) |value| {
        const redacted = try redactAlloc(std.testing.allocator, value);
        defer std.testing.allocator.free(redacted);
        try std.testing.expect(std.mem.indexOf(u8, redacted, "correct-horse") == null);
    }
}

test "structured redaction covers folded and multiline sensitive values" {
    const cases = [_][]const u8{
        "password:\n  correct horse battery staple",
        "Authorization: Bearer first-line\r\n continuation-secret",
    };
    for (cases) |value| {
        const redacted = try redactAlloc(std.testing.allocator, value);
        defer std.testing.allocator.free(redacted);
        try std.testing.expect(std.mem.indexOf(u8, redacted, "correct horse battery staple") == null);
        try std.testing.expect(std.mem.indexOf(u8, redacted, "continuation-secret") == null);
    }
}

test "YAML block scalar secrets redact their complete indented content" {
    const cases = [_][]const u8{
        "password: |\n  correct horse battery staple\n  second-line-secret\nnext: benign",
        "password: >-\n  correct horse battery staple\n  second-line-secret\nnext: benign",
    };
    for (cases) |value| {
        const owned = try redactAlloc(std.testing.allocator, value);
        defer std.testing.allocator.free(owned);
        try std.testing.expect(std.mem.indexOf(u8, owned, "correct horse") == null);
        try std.testing.expect(std.mem.indexOf(u8, owned, "second-line-secret") == null);
        try std.testing.expect(std.mem.indexOf(u8, owned, "next: benign") != null);

        var buffer: [256]u8 = undefined;
        const bounded = redactStringBounded(value, &buffer);
        try std.testing.expect(std.mem.indexOf(u8, bounded, "correct horse") == null);
        try std.testing.expect(std.mem.indexOf(u8, bounded, "second-line-secret") == null);
        try std.testing.expect(std.mem.indexOf(u8, bounded, "next: benign") != null);
    }
}

test "percent encoded URI userinfo is redacted" {
    const value = "postgres://service:correct%2Dhorse%2Dbattery%2Dstaple@db.invalid/app";
    const redacted = try redactAlloc(std.testing.allocator, value);
    defer std.testing.allocator.free(redacted);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "correct%2Dhorse") == null);
}

test "common sensitive structured keys are recognized" {
    const cases = [_][]const u8{
        "cookie=session-value",
        "Set-Cookie: session-value",
        "session=low-entropy-value",
        "refresh_token=low-entropy-value",
        "secret_access_key=low-entropy-value",
        "pwd=low-entropy-value",
        "clientSecret=low-entropy-value",
    };
    for (cases) |value| {
        const redacted = try redactAlloc(std.testing.allocator, value);
        defer std.testing.allocator.free(redacted);
        try std.testing.expect(std.mem.indexOf(u8, redacted, "low-entropy-value") == null);
        try std.testing.expect(std.mem.indexOf(u8, redacted, "session-value") == null);
    }
}

test "redaction markers do not expose stable secret fingerprints" {
    var first: [256]u8 = undefined;
    var second: [256]u8 = undefined;
    const a = redactStringBounded("GITHUB_TOKEN=fake_secret_alpha", &first);
    const b = redactStringBounded("GITHUB_TOKEN=fake_secret_beta", &second);
    try std.testing.expectEqualStrings("[REDACTED:env:GITHUB_TOKEN]", a);
    try std.testing.expectEqualStrings(a, b);
    try std.testing.expect(std.mem.indexOf(u8, a, "sha256") == null);
}

test "only canonical or legacy-known marker labels are opaque" {
    const valid = [_][]const u8{
        "[REDACTED]",
        "[REDACTED:env:GITHUB_TOKEN]",
        "[REDACTED:env:GITHUB_TOKEN:sha256:deadbeef]",
        "[REDACTED:secret:openai_api_key]",
        "[REDACTED:secret:openai_api_key:sha256:deadbeef]",
        "[REDACTED:secret:slack_token]",
        "[REDACTED:secret:stripe_api_key]",
        "[REDACTED:secret:huggingface_token]",
        "[REDACTED:secret:gitlab_token]",
        "[REDACTED:secret:azure_sas]",
    };
    for (valid) |marker| try std.testing.expect(isValidRedactionMarker(marker));

    const forged = [_][]const u8{
        "[REDACTED:env:AWS_REGION]",
        "[REDACTED:env:KEYBOARD_LAYOUT]",
        "[REDACTED:secret:arbitrary_attacker_label]",
        "[REDACTED:other:openai_api_key]",
    };
    for (forged) |marker| try std.testing.expect(!isValidRedactionMarker(marker));
}

test "benign environment names are not credentials" {
    try std.testing.expect(!isSecretEnvName("AWS_REGION"));
    try std.testing.expect(!isSecretEnvName("AZURE_REGION"));
    try std.testing.expect(!isSecretEnvName("KEYBOARD_LAYOUT"));
    try std.testing.expect(!isSecretEnvName("MONKEY_MODE"));
    try std.testing.expect(!isSecretEnvName("PWD"));
    try std.testing.expect(!isSecretEnvName("SSH_AUTH_SOCK"));
    try std.testing.expect(!isSecretEnvName("CURSOR_CONVERSATION_ID"));
    try std.testing.expect(isSecretEnvName("AWS_SECRET_ACCESS_KEY"));
    try std.testing.expect(isSecretEnvName("AZURE_CLIENT_SECRET"));
    try std.testing.expect(isSecretEnvName("CUSTOM_SIGNING_KEY"));
}

test "secret env name detection covers PGPASSWORD MYSQL_PWD and SECRET_KEY" {
    try std.testing.expect(isSecretEnvName("PGPASSWORD"));
    try std.testing.expect(isSecretEnvName("MYSQL_PWD"));
    try std.testing.expect(isSecretEnvName("SECRET_KEY"));
    try std.testing.expect(isSecretEnvName("DJANGO_SECRET_KEY"));
    try std.testing.expect(!isSecretEnvName("AWS_REGION"));
    try std.testing.expect(!isSecretEnvName("KEYBOARD_LAYOUT"));
    try std.testing.expect(!isSecretEnvName("MONKEY_MODE"));

    const redacted = try redactAlloc(std.testing.allocator, "PGPASSWORD=hunter2 psql");
    defer std.testing.allocator.free(redacted);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "hunter2") == null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, redacted_value) != null);
}

test "triple percent and base64-of-percent secrets redact on alloc and bounded paths" {
    const triple_percent = "token%25253Dcorrect-horse-battery-staple";
    // base64("token%3Dcorrect-horse-battery-staple")
    const base64_of_percent = "dG9rZW4lM0Rjb3JyZWN0LWhvcnNlLWJhdHRlcnktc3RhcGxl";
    const cases = [_][]const u8{ triple_percent, base64_of_percent };
    for (cases) |value| {
        const owned = try redactAlloc(std.testing.allocator, value);
        defer std.testing.allocator.free(owned);
        try std.testing.expectEqualStrings(redacted_value, owned);
        try std.testing.expect(std.mem.indexOf(u8, owned, "correct-horse") == null);

        var buffer: [256]u8 = undefined;
        const bounded = redactStringBounded(value, &buffer);
        try std.testing.expectEqualStrings(redacted_value, bounded);
        try std.testing.expect(std.mem.indexOf(u8, bounded, "correct-horse") == null);
    }
}

test "redactor closes base64 slash short jwt prefix and url-embedded classes" {
    // Extend existing synthetic fixtures only — no invented raw secrets.
    const cases = [_][]const u8{
        "Aa0Bb1Cc2Dd3Ee4Ff5Gg6Hh7/Ii8Jj9Kk",
        "Aa0Bb1Cc2Dd3Ee4Ff5Gg6Hh7+Ii8Jj9Kk",
        "eyJhbGc.eyJzdWI.c2lnbmF0dXJl",
        "ghp_fakeSynthetic",
        "sk-fakeSynthetic",
        // Query-embedded forms (userinfo `scheme://user:pw@host` is already closed).
        "https://example.invalid/?q=ghp_fakeSynthetic",
        "https://example.invalid/?state=Aa0Bb1Cc2Dd3Ee4Ff5Gg6Hh7/Ii8Jj9Kk",
        "https://example.invalid/?state=Aa0Bb1Cc2Dd3Ee4Ff5Gg6Hh7+Ii8Jj9Kk",
        "note Aa0Bb1Cc2Dd3Ee4Ff5Gg6Hh7+Ii8Jj9Kk here",
    };
    const raw_markers = [_][]const u8{
        "Aa0Bb1Cc2Dd3Ee4Ff5Gg6Hh7/Ii8Jj9Kk",
        "Aa0Bb1Cc2Dd3Ee4Ff5Gg6Hh7+Ii8Jj9Kk",
        "eyJhbGc.eyJzdWI.c2lnbmF0dXJl",
        "ghp_fakeSynthetic",
        "sk-fakeSynthetic",
        "ghp_fakeSynthetic",
        "Aa0Bb1Cc2Dd3Ee4Ff5Gg6Hh7/Ii8Jj9Kk",
        "Aa0Bb1Cc2Dd3Ee4Ff5Gg6Hh7+Ii8Jj9Kk",
        "Aa0Bb1Cc2Dd3Ee4Ff5Gg6Hh7+Ii8Jj9Kk",
    };
    for (cases, raw_markers) |value, secret| {
        const owned = try redactAlloc(std.testing.allocator, value);
        defer std.testing.allocator.free(owned);
        try std.testing.expect(std.mem.indexOf(u8, owned, secret) == null);
        try std.testing.expect(std.mem.indexOf(u8, owned, redacted_value) != null or std.mem.indexOf(u8, owned, "[REDACTED:") != null);

        var buffer: [256]u8 = undefined;
        const bounded = redactStringBounded(value, &buffer);
        try std.testing.expect(std.mem.indexOf(u8, bounded, secret) == null);
    }

    // Path-shaped, short-prefix, and dotted rule/matcher ids must stay unredacted.
    const benign = [_][]const u8{
        "/Users/fake/ryk/path/with/mixed/Chars123",
        "sk-learn",
        "https://example.invalid/health",
        "files.read.deny",
        "comms.message [medium classifier.local.prototype]",
    };
    for (benign) |value| {
        const unchanged = try redactAlloc(std.testing.allocator, value);
        defer std.testing.allocator.free(unchanged);
        try std.testing.expectEqualStrings(value, unchanged);
    }
}

test "classify does not hash raw secret fingerprints" {
    const match = classifyString("GITHUB_TOKEN=hunter2") orelse return error.TestExpectedEqual;
    try std.testing.expectEqual([_]u8{0} ** 8, match.fingerprint);
    try std.testing.expectEqualStrings("GITHUB_TOKEN", match.label);
}

fn expectSecretLabel(value: []const u8, label: []const u8) !void {
    const match = classifySecretValue(value) orelse return error.TestExpectedEqual;
    try std.testing.expectEqualStrings(label, match.label);
}

fn expectRedactsSecret(value: []const u8, secret: []const u8) !void {
    const owned = try redactAlloc(std.testing.allocator, value);
    defer std.testing.allocator.free(owned);
    try std.testing.expect(std.mem.indexOf(u8, owned, secret) == null);
    try std.testing.expect(std.mem.indexOf(u8, owned, redacted_value) != null or std.mem.indexOf(u8, owned, "[REDACTED:") != null);

    var buffer: [512]u8 = undefined;
    const bounded = redactStringBounded(value, &buffer);
    try std.testing.expect(std.mem.indexOf(u8, bounded, secret) == null);
}

fn expectSpanRedaction(value: []const u8, expected: []const u8) !void {
    const owned = try redactAlloc(std.testing.allocator, value);
    defer std.testing.allocator.free(owned);
    try std.testing.expectEqualStrings(expected, owned);
}

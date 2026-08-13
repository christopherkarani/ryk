//! Secret material classification and secret-access command detection.
const std = @import("std");
const redact_bridge = @import("ryk_core").audit.redact_bridge;
const types = @import("types.zig");

/// Paths / patterns that indicate a command is *accessing* secret material.
const secret_path_needles = [_][]const u8{
    ".env",
    ".env.local",
    ".env.production",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    ".pem",
    ".p12",
    ".pfx",
    "credentials.json",
    "auth.json",
    "secrets.yaml",
    "secrets.yml",
    "secrets.json",
    "service_account.json",
    ".npmrc",
    ".netrc",
    "aws/credentials",
    ".aws/credentials",
    "kube/config",
    ".kube/config",
    "private_key",
    "private-key",
};

// Compared against lowercased command text — keep these lowercase.
const secret_cmd_prefixes = [_][]const u8{
    "cat ",
    "head ",
    "tail ",
    "less ",
    "more ",
    "bat ",
    "type ",
    "get-content ",
    "cp ",
    "mv ",
    "scp ",
    "rsync ",
    "curl ",
    "wget ",
    "base64 ",
    "openssl ",
    "gpg ",
    "printenv ",
    "env ",
    "export ",
    "source ",
    ". ",
};

pub const MaterialHit = struct {
    label: []const u8,
    redacted: []const u8,

    pub fn deinit(self: *MaterialHit, allocator: std.mem.Allocator) void {
        allocator.free(self.label);
        allocator.free(self.redacted);
        self.* = undefined;
    }
};

/// Classify secret material in a blob. Returns owned label + redacted form; never the raw value.
pub fn classifyMaterial(allocator: std.mem.Allocator, blob: []const u8) !?MaterialHit {
    if (blob.len == 0) return null;
    // Scan fixed-size overlapping windows so classification cost stays bounded
    // without silently ignoring material after the first 64 KiB. The overlap
    // catches provider tokens and assignments split across a window boundary.
    const overlap: usize = 512;
    const stride = types.max_line_bytes - overlap;
    var start: usize = 0;
    while (start < blob.len) : (start += stride) {
        const end = @min(start + types.max_line_bytes, blob.len);
        const slice = blob[start..end];

        if (redact_bridge.classifyString(slice)) |match| {
            return try materialFromMatch(allocator, match, slice);
        }
        if (redact_bridge.classifySecretValue(slice)) |match| {
            return try materialFromMatch(allocator, match, slice);
        }
        if (try embeddedMaterial(allocator, slice)) |hit| return hit;
        if (end == blob.len) break;
    }
    return null;
}

/// Count independently presented secret-bearing tokens without retaining a
/// stable identifier derived from their contents.
pub fn countMaterials(blob: []const u8) usize {
    var count: usize = 0;
    var seen: [256][]const u8 = undefined;
    var seen_len: usize = 0;
    var fields = std.mem.tokenizeAny(u8, blob, ",\r\n");
    while (fields.next()) |field| {
        var word_hits: usize = 0;
        var words = std.mem.tokenizeAny(u8, field, " \t;(){}[]<>\"");
        while (words.next()) |word| {
            if (redact_bridge.classifySecretValue(word) == null) continue;
            var duplicate = false;
            for (seen[0..seen_len]) |prior| {
                if (std.mem.eql(u8, prior, word)) duplicate = true;
            }
            if (duplicate) continue;
            if (seen_len == seen.len) return seen.len;
            seen[seen_len] = word;
            seen_len += 1;
            word_hits += 1;
        }
        if (word_hits > 0) {
            count += word_hits;
            continue;
        }
        var buffer: [256]u8 = undefined;
        const redacted = redact_bridge.redactStringBounded(field, &buffer);
        if (!(redacted.ptr == field.ptr and redacted.len == field.len)) count += 1;
    }
    return count;
}

fn embeddedMaterial(allocator: std.mem.Allocator, slice: []const u8) !?MaterialHit {
    var buf: [256]u8 = undefined;
    const redacted = redact_bridge.redactStringBounded(slice, &buf);
    if (redacted.ptr == slice.ptr and redacted.len == slice.len) return null;

    const label = try allocator.dupe(u8, "secret:embedded");
    errdefer allocator.free(label);
    const owned = try allocator.dupe(u8, redacted);
    errdefer allocator.free(owned);
    return .{
        .label = label,
        .redacted = owned,
    };
}

fn materialFromMatch(allocator: std.mem.Allocator, match: redact_bridge.RedactionMatch, slice: []const u8) !MaterialHit {
    const label = try allocator.dupe(u8, match.label);
    errdefer allocator.free(label);
    var buf: [256]u8 = undefined;
    const redacted_view = redact_bridge.redactStringBounded(slice, &buf);
    const redacted = try allocator.dupe(u8, redacted_view);
    errdefer allocator.free(redacted);
    return .{
        .label = label,
        .redacted = redacted,
    };
}

/// True when a shell/tool command is likely accessing secret-bearing paths or env dumps.
pub fn isSecretAccessCommand(command: []const u8) bool {
    const trimmed = std.mem.trim(u8, command, " \t\r\n");
    if (trimmed.len == 0) return false;
    const lower_buf_size = 512;
    var lower_buf: [lower_buf_size]u8 = undefined;
    const lower = if (trimmed.len <= lower_buf_size) blk: {
        for (trimmed, 0..) |c, i| lower_buf[i] = std.ascii.toLower(c);
        break :blk lower_buf[0..trimmed.len];
    } else trimmed; // fall back to case-sensitive on oversized lines

    // printenv / env without args dumps secrets broadly.
    if (std.mem.eql(u8, lower, "env") or std.mem.eql(u8, lower, "printenv") or
        std.mem.eql(u8, lower, "export") or std.mem.startsWith(u8, lower, "printenv ") or
        std.mem.startsWith(u8, lower, "env |") or std.mem.startsWith(u8, lower, "env|"))
    {
        return true;
    }

    var path_hit = false;
    for (secret_path_needles) |needle| {
        if (std.mem.indexOf(u8, lower, needle) != null) {
            path_hit = true;
            break;
        }
    }
    if (!path_hit) return false;

    for (secret_cmd_prefixes) |prefix| {
        if (std.mem.startsWith(u8, lower, prefix)) return true;
    }
    // Also catch `sudo cat .env` etc.
    if (std.mem.startsWith(u8, lower, "sudo ")) {
        const rest = lower["sudo ".len..];
        for (secret_cmd_prefixes) |prefix| {
            if (std.mem.startsWith(u8, rest, prefix)) return true;
        }
    }
    return false;
}

/// Case-insensitive substring search for residual secret-shaped prefixes.
fn containsAsciiIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0 or haystack.len < needle.len) return false;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[i .. i + needle.len], needle)) return true;
    }
    return false;
}

/// Redact any secret material from a display string (owned).
/// Redacts the full input first, then truncates for display (never cut mid-token before classify).
pub fn safeDetail(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    // Single free owner: free on residual/truncate paths without errdefer (avoids
    // double-free if residual free succeeds then dupe returns OutOfMemory).
    const redacted = try redact_bridge.redactAlloc(allocator, text);
    // Fail closed if residual provider-shaped prefixes remain after redaction.
    const residual_prefixes = [_][]const u8{
        "ghp_", "gho_",    "ghs_", "ghu_", "ghr_",          "github_pat_",
        "sk-",  "sk-ant-", "AKIA", "ASIA", "BEGIN PRIVATE", "BEGIN OPENSSH",
    };
    for (residual_prefixes) |p| {
        if (containsAsciiIgnoreCase(redacted, p)) {
            allocator.free(redacted);
            return try allocator.dupe(u8, redact_bridge.redacted_value);
        }
    }
    if (redacted.len <= types.max_detail_len) return redacted;
    const truncated = try allocator.dupe(u8, redacted[0..types.max_detail_len]);
    allocator.free(redacted);
    return truncated;
}

test "secret_access detects cat .env and id_rsa" {
    try std.testing.expect(isSecretAccessCommand("cat .env"));
    try std.testing.expect(isSecretAccessCommand("cat ~/.ssh/id_rsa"));
    try std.testing.expect(isSecretAccessCommand("sudo cat /home/u/.env.local"));
    try std.testing.expect(isSecretAccessCommand("printenv"));
    try std.testing.expect(!isSecretAccessCommand("cat README.md"));
    try std.testing.expect(!isSecretAccessCommand("ls .env"));
}

test "secret_material never returns raw ghp_ or sk- tokens" {
    const fake = "token ghp_fakeSyntheticTokenValue1234567890abcd more";
    const hit = try classifyMaterial(std.testing.allocator, fake);
    try std.testing.expect(hit != null);
    var h = hit.?;
    defer h.deinit(std.testing.allocator);
    try std.testing.expect(std.mem.indexOf(u8, h.redacted, "ghp_fake") == null);
    try std.testing.expect(std.mem.indexOf(u8, h.redacted, "ghp_") == null or
        std.mem.indexOf(u8, h.redacted, "REDACTED") != null);

    const openai = "OPENAI_API_KEY=sk-fakeSyntheticOpenAIKey1234567890xxxx";
    const hit2 = try classifyMaterial(std.testing.allocator, openai);
    try std.testing.expect(hit2 != null);
    var h2 = hit2.?;
    defer h2.deinit(std.testing.allocator);
    try std.testing.expect(std.mem.indexOf(u8, h2.redacted, "sk-fake") == null);

    const detail = try safeDetail(std.testing.allocator, openai);
    defer std.testing.allocator.free(detail);
    try std.testing.expect(std.mem.indexOf(u8, detail, "sk-fake") == null);
}

test "benign text is not secret material" {
    const hit = try classifyMaterial(std.testing.allocator, "hello world ls -la");
    try std.testing.expect(hit == null);
}

test "secret material classification scans beyond 64 KiB" {
    const prefix_len = types.max_line_bytes + 1024;
    const token = "ghp_fakeSyntheticBeyondFirstWindow1234567890";
    const blob = try std.testing.allocator.alloc(u8, prefix_len + token.len);
    defer std.testing.allocator.free(blob);
    @memset(blob[0..prefix_len], 'a');
    @memcpy(blob[prefix_len..], token);

    const hit = try classifyMaterial(std.testing.allocator, blob);
    try std.testing.expect(hit != null);
    var material = hit.?;
    defer material.deinit(std.testing.allocator);
    try std.testing.expect(std.mem.indexOf(u8, material.redacted, token) == null);
}

test "distinct secret tokens in one blob remain separately counted" {
    try std.testing.expectEqual(@as(usize, 2), countMaterials(
        "ghp_fakeSyntheticTokenValue1234567890 ghp_anotherSyntheticTokenValue1234567890",
    ));
    try std.testing.expectEqual(@as(usize, 2), countMaterials(
        "{\"password\":\"hunter2\",\"token\":\"ordinary-value\"}",
    ));
    try std.testing.expectEqual(@as(usize, 1), countMaterials(
        "ghp_fakeSyntheticTokenValue1234567890 ghp_fakeSyntheticTokenValue1234567890",
    ));
}

test "Get-Content case-insensitive secret access" {
    try std.testing.expect(isSecretAccessCommand("Get-Content .env"));
    try std.testing.expect(isSecretAccessCommand("get-content ~/.ssh/id_rsa"));
}

test "safeDetail residual prefixes are case-insensitive" {
    // Synthetic residual shape after a failed redaction path — must never pass through.
    const detail = try safeDetail(std.testing.allocator, "leak SK-FAKEVALUE1234567890XXXX more");
    defer std.testing.allocator.free(detail);
    try std.testing.expect(std.mem.indexOf(u8, detail, "SK-FAKE") == null);
    try std.testing.expect(std.mem.indexOf(u8, detail, "sk-fake") == null);
}

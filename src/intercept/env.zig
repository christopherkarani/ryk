const std = @import("std");

const env_util = @import("../env_util.zig");
const env_schema = @import("env_schema.zig");
const sandbox_env = @import("../sandbox/env_scrub.zig");
const audit = @import("ryk_core").audit;
const core = @import("ryk_core").core;
const policy = @import("ryk_core").policy;

pub const implemented = true;

pub const SecretBoundary = enum {
    off,
    empty_backpack,
};

pub const Request = struct {
    no_secrets: bool = false,
    secret_boundary: SecretBoundary = .off,
    inherit_env: bool = false,
    /// Explicit loud escape: retain the host environment regardless of policy
    /// inheritance and secret classification. The sandbox seam still strips
    /// loader/startup injection variables before exec.
    with_host_secrets: bool = false,
    schema: ?*const env_schema.Schema = null,
};

pub const RedactionRecord = core.process.EnvRedactionRecord;

pub const FilteredEnv = struct {
    allocator: std.mem.Allocator,
    env_map: std.process.Environ.Map,
    use_custom_env: bool,
    redactions: []RedactionRecord,

    pub fn deinit(self: *FilteredEnv) void {
        for (self.redactions) |record| {
            self.allocator.free(record.name);
            for (record.labels) |label| self.allocator.free(label);
            self.allocator.free(record.labels);
        }
        self.allocator.free(self.redactions);
        self.env_map.deinit();
        self.* = undefined;
    }
};

pub fn filterCurrent(
    allocator: std.mem.Allocator,
    selected_policy: *const policy.schema.Policy,
    effective_mode: policy.schema.Mode,
    request: Request,
) !FilteredEnv {
    var current = try env_util.createProcessMap(allocator);
    defer current.deinit();
    return filterMap(allocator, &current, selected_policy, effective_mode, request);
}

pub fn filterMap(
    allocator: std.mem.Allocator,
    current: *const std.process.Environ.Map,
    selected_policy: *const policy.schema.Policy,
    effective_mode: policy.schema.Mode,
    request: Request,
) !FilteredEnv {
    if (request.inherit_env and !request.with_host_secrets and !selected_policy.env.inherit)
        return error.InheritEnvDenied;

    var env_map = std.process.Environ.Map.init(allocator);
    errdefer env_map.deinit();
    var redactions: std.ArrayList(RedactionRecord) = .empty;
    errdefer {
        for (redactions.items) |record| {
            allocator.free(record.name);
            for (record.labels) |label| allocator.free(label);
            allocator.free(record.labels);
        }
        redactions.deinit(allocator);
    }

    const inherit_source = request.with_host_secrets or selected_policy.env.inherit or request.inherit_env;
    const minimal = !inherit_source or isEnforcingNoSecretsMode(effective_mode);
    const boundary_active = request.secret_boundary == .empty_backpack;
    const force_no_secrets = request.no_secrets or (isEnforcingNoSecretsMode(effective_mode) and !boundary_active);

    var it = current.iterator();
    while (it.next()) |entry| {
        const name = entry.key_ptr.*;
        const value = entry.value_ptr.*;
        const name_secret = isCredentialEnvName(name);
        const value_match = classifyCredentialEnvValue(value);
        if (name_secret) {
            try appendRedaction(
                allocator,
                &redactions,
                name,
                value,
                "environment variable name matches secret pattern",
            );
        } else if (value_match) |match| {
            try appendValueRedaction(allocator, &redactions, name, match, "environment variable value matches secret pattern");
        }

        const secret_like = name_secret or value_match != null;
        if (request.with_host_secrets) {
            try env_map.put(name, value);
            continue;
        }
        if (boundary_active) {
            if (request.schema) |schema| {
                if (schema.find(name)) |variable| {
                    if (variable.class == .sensitive) continue;
                    if (secret_like or matchesAnyPattern(selected_policy.env.deny_patterns, name)) continue;
                    try env_map.put(name, value);
                    continue;
                }
            }
            if (secret_like) continue;
            if (!isBoundaryPublicHostEnv(name)) continue;
            if (matchesAnyPattern(selected_policy.env.deny_patterns, name)) continue;
            try env_map.put(name, value);
            continue;
        }

        if (try shouldInclude(allocator, selected_policy, effective_mode, minimal, force_no_secrets, name, name_secret, value_match != null)) {
            try env_map.put(name, value);
        }
    }

    return .{
        .allocator = allocator,
        .env_map = env_map,
        .use_custom_env = true,
        .redactions = try redactions.toOwnedSlice(allocator),
    };
}

test "with-host-secrets retains raw host values without inherit policy" {
    var current = std.process.Environ.Map.init(std.testing.allocator);
    defer current.deinit();
    try current.put("PATH", "/usr/bin");
    try current.put("ANTHROPIC_API_KEY", "sk-ant-synthetic-explicit-escape");
    try current.put("MYSQL_PWD", "synthetic-explicit-escape-password");

    var selected = policy.schema.Policy{ .allocator = std.testing.allocator };
    selected.env.inherit = false;
    var filtered = try filterMap(
        std.testing.allocator,
        &current,
        &selected,
        .strict,
        .{ .with_host_secrets = true },
    );
    defer filtered.deinit();

    try std.testing.expectEqualStrings(
        "sk-ant-synthetic-explicit-escape",
        filtered.env_map.get("ANTHROPIC_API_KEY").?,
    );
    try std.testing.expectEqualStrings(
        "synthetic-explicit-escape-password",
        filtered.env_map.get("MYSQL_PWD").?,
    );
}

test "empty backpack env schema passes declared public and omits unknown and sensitive" {
    var current = std.process.Environ.Map.init(std.testing.allocator);
    defer current.deinit();
    try current.put("PATH", "/usr/bin");
    try current.put("API_URL", "https://api.example.test");
    try current.put("UNDECLARED_PUBLIC", "ordinary");
    try current.put("DATABASE_URL", "postgres://synthetic:password@example.test/db");

    var schema = try env_schema.parseFromSlice(std.testing.allocator,
        \\defaults:
        \\  unknown: omit
        \\vars:
        \\  API_URL:
        \\    class: public
        \\  DATABASE_URL:
        \\    class: sensitive
        \\    grant: database
    );
    defer schema.deinit();
    var selected = policy.schema.Policy{ .allocator = std.testing.allocator };
    var filtered = try filterMap(
        std.testing.allocator,
        &current,
        &selected,
        .observe,
        .{ .secret_boundary = .empty_backpack, .schema = &schema },
    );
    defer filtered.deinit();
    try std.testing.expectEqualStrings("https://api.example.test", filtered.env_map.get("API_URL").?);
    try std.testing.expect(filtered.env_map.get("UNDECLARED_PUBLIC") == null);
    try std.testing.expect(filtered.env_map.get("DATABASE_URL") == null);
    try std.testing.expectEqualStrings("/usr/bin", filtered.env_map.get("PATH").?);
}

test "no-secrets retains benign AWS and key configuration but removes unknown credential aliases" {
    var current = std.process.Environ.Map.init(std.testing.allocator);
    defer current.deinit();
    try current.put("AWS_REGION", "us-test-1");
    try current.put("KEYBOARD_LAYOUT", "us");
    try current.put("CUSTOM_SERVICE_CREDENTIAL", "ordinary-looking-value");
    try current.put("CUSTOM_API_KEY", "ordinary-looking-value");
    try current.put("STRIPE_APIKEY", "ordinary-looking-value");
    try current.put("SERVICE_AUTH", "ordinary-looking-value");
    try current.put("SESSION_ID", "ordinary-looking-value");
    try current.put("APP_COOKIE", "ordinary-looking-value");
    try current.put("DATABASE_PWD", "ordinary-looking-value");
    try current.put("DATABASE_URL", "postgres://admin:hunter2@db.invalid/app");
    try current.put("APP_CONFIG", "{\"password\":\"hunter2\"}");
    try current.put("PUBLIC_URL", "https://service.invalid/api");

    var selected = policy.schema.Policy{ .allocator = std.testing.allocator };
    selected.env.inherit = true;
    var filtered = try filterMap(
        std.testing.allocator,
        &current,
        &selected,
        .observe,
        .{ .no_secrets = true },
    );
    defer filtered.deinit();

    try std.testing.expectEqualStrings("us-test-1", filtered.env_map.get("AWS_REGION").?);
    try std.testing.expectEqualStrings("us", filtered.env_map.get("KEYBOARD_LAYOUT").?);
    try std.testing.expect(filtered.env_map.get("CUSTOM_SERVICE_CREDENTIAL") == null);
    try std.testing.expect(filtered.env_map.get("CUSTOM_API_KEY") == null);
    try std.testing.expect(filtered.env_map.get("STRIPE_APIKEY") == null);
    try std.testing.expect(filtered.env_map.get("SERVICE_AUTH") == null);
    try std.testing.expect(filtered.env_map.get("SESSION_ID") == null);
    try std.testing.expect(filtered.env_map.get("APP_COOKIE") == null);
    try std.testing.expect(filtered.env_map.get("DATABASE_PWD") == null);
    try std.testing.expect(filtered.env_map.get("DATABASE_URL") == null);
    try std.testing.expect(filtered.env_map.get("APP_CONFIG") == null);
    try std.testing.expectEqualStrings("https://service.invalid/api", filtered.env_map.get("PUBLIC_URL").?);
}

test "no-secrets removes authorization aliases when inheriting" {
    var current = std.process.Environ.Map.init(std.testing.allocator);
    defer current.deinit();
    try current.put("AUTHORIZATION", "Basic ordinary-value");
    try current.put("PROXY_AUTHORIZATION", "Basic ordinary-value");
    try current.put("HTTP_AUTHORIZATION", "Basic ordinary-value");

    var selected = policy.schema.Policy{ .allocator = std.testing.allocator };
    selected.env.inherit = true;
    var filtered = try filterMap(std.testing.allocator, &current, &selected, .observe, .{ .no_secrets = true });
    defer filtered.deinit();
    try std.testing.expect(filtered.env_map.get("AUTHORIZATION") == null);
    try std.testing.expect(filtered.env_map.get("PROXY_AUTHORIZATION") == null);
    try std.testing.expect(filtered.env_map.get("HTTP_AUTHORIZATION") == null);
}

fn isBoundaryPublicHostEnv(name: []const u8) bool {
    if (sandbox_env.isProxyEnvKey(name)) return false;
    if (std.mem.eql(u8, name, "ANTHROPIC_BASE_URL") or
        std.mem.eql(u8, name, "OPENAI_BASE_URL"))
    {
        return false;
    }
    for (sandbox_env.launch_allow_exact) |allowed| {
        if (std.mem.eql(u8, name, allowed)) return true;
    }
    return false;
}

/// Classifies credential-bearing environment names without treating broad
/// configuration namespaces (for example AWS_REGION) or ordinary words that
/// contain "KEY" (for example KEYBOARD_LAYOUT) as secrets.
fn isCredentialEnvName(name: []const u8) bool {
    const exact_names = [_][]const u8{
        "SSH_AUTH_SOCK",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "MYSQL_PWD",
        "PGPASSWORD",
        "AWS_ACCESS_KEY_ID",
    };
    for (exact_names) |candidate| {
        if (std.ascii.eqlIgnoreCase(name, candidate)) return true;
    }

    const credential_terms = [_][]const u8{
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "PASSWD",
        "PASSPHRASE",
        "CREDENTIAL",
        "CREDENTIALS",
        "AUTH",
        "AUTHORIZATION",
        "SESSION",
        "COOKIE",
        "PWD",
    };
    var terms = std.mem.tokenizeAny(u8, name, "_-.");
    while (terms.next()) |term| {
        for (credential_terms) |credential_term| {
            if (std.ascii.eqlIgnoreCase(term, credential_term)) return true;
        }
    }

    const compound_suffixes = [_][]const u8{
        "API_KEY",
        "ACCESS_KEY",
        "PRIVATE_KEY",
        "CLIENT_KEY",
        "SIGNING_KEY",
        "SECRET_KEY",
        "APIKEY",
    };
    for (compound_suffixes) |suffix| {
        if (std.ascii.eqlIgnoreCase(name, suffix)) return true;
        if (name.len > suffix.len and name[name.len - suffix.len - 1] == '_' and
            std.ascii.eqlIgnoreCase(name[name.len - suffix.len ..], suffix)) return true;
    }
    return false;
}

fn classifyCredentialEnvValue(value: []const u8) ?audit.redact_bridge.RedactionMatch {
    if (audit.redact_bridge.classifySecretValue(value)) |match| return match;
    var buffer: [256]u8 = undefined;
    const redacted = audit.redact_bridge.redactStringBounded(value, &buffer);
    if (!(redacted.ptr == value.ptr and redacted.len == value.len)) {
        return .{
            .label = "secret:structured_credential",
            .fingerprint = .{0} ** 8,
        };
    }
    return null;
}

fn matchesAnyPattern(patterns: []const []const u8, name: []const u8) bool {
    for (patterns) |pattern| {
        if (policy.matchers.matchesPattern(pattern, name)) return true;
    }
    return false;
}

fn shouldInclude(
    allocator: std.mem.Allocator,
    selected_policy: *const policy.schema.Policy,
    effective_mode: policy.schema.Mode,
    minimal: bool,
    force_no_secrets: bool,
    name: []const u8,
    name_secret: bool,
    value_secret: bool,
) !bool {
    if (force_no_secrets and (name_secret or value_secret)) return false;

    var evaluation = try policy.evaluate.action(selected_policy, .{ .env_read = .{ .name = name } }, .{ .mode = effective_mode }, allocator);
    defer evaluation.deinit(allocator);

    if (effective_mode == .observe and selected_policy.env.inherit and !force_no_secrets) {
        return true;
    }
    if (evaluation.decision.result == .deny) return false;
    if (minimal) {
        return matchesAnyPattern(selected_policy.env.allow, name);
    }
    return true;
}

fn isEnforcingNoSecretsMode(mode: policy.schema.Mode) bool {
    return mode == .strict or mode == .ci or mode == .redteam;
}

fn appendRedaction(
    allocator: std.mem.Allocator,
    redactions: *std.ArrayList(RedactionRecord),
    name: []const u8,
    value: []const u8,
    reason: []const u8,
) !void {
    const safe_name = try audit.redact_bridge.redactAlloc(allocator, name);
    errdefer allocator.free(safe_name);
    var label_buf: [256]u8 = undefined;
    const label = try audit.redact_bridge.formatEnvReplacement(&label_buf, safe_name, value);
    const labels = try allocator.alloc([]const u8, 1);
    errdefer allocator.free(labels);
    labels[0] = try allocator.dupe(u8, label);
    errdefer allocator.free(labels[0]);
    try redactions.append(allocator, .{
        .name = safe_name,
        .labels = labels,
        .reason = reason,
    });
}

fn appendValueRedaction(
    allocator: std.mem.Allocator,
    redactions: *std.ArrayList(RedactionRecord),
    name: []const u8,
    match: audit.redact_bridge.RedactionMatch,
    reason: []const u8,
) !void {
    const safe_name = try audit.redact_bridge.redactAlloc(allocator, name);
    errdefer allocator.free(safe_name);
    var label_buf: [256]u8 = undefined;
    const label = if (std.mem.startsWith(u8, match.label, "secret:"))
        try std.fmt.bufPrint(&label_buf, "[REDACTED:{s}]", .{match.label})
    else
        try std.fmt.bufPrint(&label_buf, "[REDACTED:env:{s}]", .{match.label});
    const labels = try allocator.alloc([]const u8, 1);
    errdefer allocator.free(labels);
    labels[0] = try allocator.dupe(u8, label);
    errdefer allocator.free(labels[0]);
    try redactions.append(allocator, .{
        .name = safe_name,
        .labels = labels,
        .reason = reason,
    });
}

fn appendRedactionAllocationFailureProbe(allocator: std.mem.Allocator) !void {
    var redactions: std.ArrayList(RedactionRecord) = .empty;
    defer {
        for (redactions.items) |record| {
            allocator.free(record.name);
            for (record.labels) |label| allocator.free(label);
            allocator.free(record.labels);
        }
        redactions.deinit(allocator);
    }

    try appendRedaction(
        allocator,
        &redactions,
        "FAKE_GITHUB_TOKEN",
        "ghp_fakeSyntheticTokenValue1234567890",
        "environment variable name matches secret pattern",
    );
}

fn appendValueRedactionAllocationFailureProbe(allocator: std.mem.Allocator) !void {
    var redactions: std.ArrayList(RedactionRecord) = .empty;
    defer {
        for (redactions.items) |record| {
            allocator.free(record.name);
            for (record.labels) |label| allocator.free(label);
            allocator.free(record.labels);
        }
        redactions.deinit(allocator);
    }

    const match = audit.redact_bridge.classifySecretValue("ghp_fakeSyntheticTokenValue1234567890").?;
    try appendValueRedaction(
        allocator,
        &redactions,
        "PUBLIC_VALUE",
        match,
        "environment variable value matches secret pattern",
    );
}

test "environment redaction builders clean up every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, appendRedactionAllocationFailureProbe, .{});
    try std.testing.checkAllAllocationFailures(std.testing.allocator, appendValueRedactionAllocationFailureProbe, .{});
}

test "strict env filtering keeps allowlist and strips synthetic secret names" {
    var selected = try policy.load.parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\env:
        \\  inherit: false
        \\  allow:
        \\    - PATH
        \\    - SAFE_FAKE
        \\  deny_patterns:
        \\    - "*TOKEN*"
    , "test.yaml");
    defer selected.deinit();

    var current = std.process.Environ.Map.init(std.testing.allocator);
    defer current.deinit();
    try current.put("PATH", "/usr/bin");
    try current.put("SAFE_FAKE", "ok");
    try current.put("FAKE_GITHUB_TOKEN", "fake_secret_value");
    try current.put("OTHER", "value");

    var filtered = try filterMap(std.testing.allocator, &current, &selected, .strict, .{});
    defer filtered.deinit();

    try std.testing.expectEqualStrings("/usr/bin", filtered.env_map.get("PATH").?);
    try std.testing.expectEqualStrings("ok", filtered.env_map.get("SAFE_FAKE").?);
    try std.testing.expect(filtered.env_map.get("FAKE_GITHUB_TOKEN") == null);
    try std.testing.expect(filtered.env_map.get("OTHER") == null);
    try std.testing.expectEqual(@as(usize, 1), filtered.redactions.len);
    try std.testing.expect(std.mem.indexOf(u8, filtered.redactions[0].labels[0], "fake_secret_value") == null);
}

test "env deny pattern beats allow during filtering" {
    var selected = try policy.load.parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\env:
        \\  inherit: false
        \\  allow:
        \\    - FAKE_ALLOWED
        \\  deny_patterns:
        \\    - "FAKE_*"
    , "test.yaml");
    defer selected.deinit();

    var current = std.process.Environ.Map.init(std.testing.allocator);
    defer current.deinit();
    try current.put("FAKE_ALLOWED", "ok");

    var filtered = try filterMap(std.testing.allocator, &current, &selected, .strict, .{});
    defer filtered.deinit();

    try std.testing.expect(filtered.env_map.get("FAKE_ALLOWED") == null);
}

test "inherit-env fails closed when policy disallows inheritance" {
    var selected = try policy.load.loadPreset(std.testing.allocator, .strict);
    defer selected.deinit();

    var current = std.process.Environ.Map.init(std.testing.allocator);
    defer current.deinit();
    try current.put("PATH", "/usr/bin");

    try std.testing.expectError(error.InheritEnvDenied, filterMap(std.testing.allocator, &current, &selected, .strict, .{ .inherit_env = true }));
}

test "observe mode inherits but records redactions for audit" {
    var selected = try policy.load.loadPreset(std.testing.allocator, .observe);
    defer selected.deinit();

    var current = std.process.Environ.Map.init(std.testing.allocator);
    defer current.deinit();
    try current.put("FAKE_GITHUB_TOKEN", "fake_secret_value");

    var filtered = try filterMap(std.testing.allocator, &current, &selected, .observe, .{});
    defer filtered.deinit();

    try std.testing.expectEqualStrings("fake_secret_value", filtered.env_map.get("FAKE_GITHUB_TOKEN").?);
    try std.testing.expectEqual(@as(usize, 1), filtered.redactions.len);
    try std.testing.expect(std.mem.indexOf(u8, filtered.redactions[0].labels[0], "fake_secret_value") == null);
}

test "no-secrets strips secret-like values even when inheriting" {
    var selected = try policy.load.loadPreset(std.testing.allocator, .observe);
    defer selected.deinit();

    var current = std.process.Environ.Map.init(std.testing.allocator);
    defer current.deinit();
    try current.put("NORMAL_VALUE", "fake_secret_value");
    try current.put("SAFE_VALUE", "ok");

    var filtered = try filterMap(std.testing.allocator, &current, &selected, .observe, .{ .no_secrets = true });
    defer filtered.deinit();

    try std.testing.expect(filtered.env_map.get("NORMAL_VALUE") == null);
    try std.testing.expectEqualStrings("ok", filtered.env_map.get("SAFE_VALUE").?);
}

test "secretless constructs a public-only environment without local dummy references" {
    var selected = try policy.load.loadPreset(std.testing.allocator, .observe);
    defer selected.deinit();

    var current = std.process.Environ.Map.init(std.testing.allocator);
    defer current.deinit();
    try current.put("PATH", "/usr/bin:/bin");
    try current.put("HOME", "/tmp/synthetic-home");
    try current.put("LANG", "C.UTF-8");
    try current.put("TERM", "xterm-256color");
    try current.put("GITHUB_TOKEN", "ghp_fakeSyntheticTokenValue1234567890");
    try current.put("DATABASE_URL", "postgres://synthetic:SuperSecretPass99@db.invalid/app");
    try current.put("MYSQL_PWD", "SuperSecretPass99");
    try current.put("RANDOM_HOST_VALUE", "must-not-survive");
    try current.put("HTTP_PROXY", "http://synthetic:proxypass@proxy.invalid:8080");
    try current.put("RYK_HOST_SECRET", "must-not-survive");
    try current.put("RYK_HOST_SECRET", "must-not-survive");
    try current.put("LC_SECRET", "must-not-survive");
    try current.put("XDG_SECRET", "must-not-survive");
    try current.put("SAFE_VALUE", "ok");

    var filtered = try filterMap(
        std.testing.allocator,
        &current,
        &selected,
        .observe,
        .{ .secret_boundary = .empty_backpack },
    );
    defer filtered.deinit();

    try std.testing.expectEqualStrings("/usr/bin:/bin", filtered.env_map.get("PATH").?);
    try std.testing.expectEqualStrings("/tmp/synthetic-home", filtered.env_map.get("HOME").?);
    try std.testing.expectEqualStrings("C.UTF-8", filtered.env_map.get("LANG").?);
    try std.testing.expectEqualStrings("xterm-256color", filtered.env_map.get("TERM").?);
    try std.testing.expect(filtered.env_map.get("GITHUB_TOKEN") == null);
    try std.testing.expect(filtered.env_map.get("DATABASE_URL") == null);
    try std.testing.expect(filtered.env_map.get("MYSQL_PWD") == null);
    try std.testing.expect(filtered.env_map.get("RANDOM_HOST_VALUE") == null);
    try std.testing.expect(filtered.env_map.get("HTTP_PROXY") == null);
    try std.testing.expect(filtered.env_map.get("RYK_HOST_SECRET") == null);
    try std.testing.expect(filtered.env_map.get("RYK_HOST_SECRET") == null);
    try std.testing.expect(filtered.env_map.get("LC_SECRET") == null);
    try std.testing.expect(filtered.env_map.get("XDG_SECRET") == null);
    try std.testing.expect(filtered.env_map.get("SAFE_VALUE") == null);
    try std.testing.expect(filtered.redactions.len >= 1);
    for (filtered.redactions) |record| {
        for (record.labels) |label| {
            try std.testing.expect(std.mem.indexOf(u8, label, "ghp_fakeSyntheticTokenValue") == null);
            try std.testing.expect(std.mem.indexOf(u8, label, "SuperSecretPass99") == null);
            try std.testing.expect(std.mem.indexOf(u8, label, "proxypass") == null);
        }
    }
}

test "secretless omits model API keys instead of emitting local dummy references" {
    var selected = try policy.load.loadPreset(std.testing.allocator, .observe);
    defer selected.deinit();

    var current = std.process.Environ.Map.init(std.testing.allocator);
    defer current.deinit();
    try current.put("OPENAI_API_KEY", "sk-fakeSyntheticOpenAIKey1234567890");
    try current.put("ANTHROPIC_API_KEY", "sk-ant-fakeSyntheticAnthropicKey1234567890");
    try current.put("PATH", "/usr/bin");

    var filtered = try filterMap(
        std.testing.allocator,
        &current,
        &selected,
        .observe,
        .{ .secret_boundary = .empty_backpack },
    );
    defer filtered.deinit();

    try std.testing.expect(filtered.env_map.get("OPENAI_API_KEY") == null);
    try std.testing.expect(filtered.env_map.get("ANTHROPIC_API_KEY") == null);
    try std.testing.expectEqualStrings("/usr/bin", filtered.env_map.get("PATH").?);
}

test "secretless public allowlist does not override policy deny patterns" {
    var selected = try policy.load.parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: observe
        \\env:
        \\  inherit: true
        \\  deny_patterns:
        \\    - PATH
    , "test.yaml");
    defer selected.deinit();

    var current = std.process.Environ.Map.init(std.testing.allocator);
    defer current.deinit();
    try current.put("PATH", "/usr/bin");
    try current.put("HOME", "/tmp/synthetic-home");

    var filtered = try filterMap(
        std.testing.allocator,
        &current,
        &selected,
        .observe,
        .{ .secret_boundary = .empty_backpack },
    );
    defer filtered.deinit();

    try std.testing.expect(filtered.env_map.get("PATH") == null);
    try std.testing.expectEqualStrings("/tmp/synthetic-home", filtered.env_map.get("HOME").?);
}

test "secretless omits a public key when its value has a residual secret shape" {
    var selected = try policy.load.loadPreset(std.testing.allocator, .observe);
    defer selected.deinit();

    var current = std.process.Environ.Map.init(std.testing.allocator);
    defer current.deinit();
    try current.put("PATH", "/usr/bin");
    try current.put("TERM", "ghp_fakeSyntheticTokenValue1234567890");

    var filtered = try filterMap(
        std.testing.allocator,
        &current,
        &selected,
        .observe,
        .{ .secret_boundary = .empty_backpack },
    );
    defer filtered.deinit();

    try std.testing.expectEqualStrings("/usr/bin", filtered.env_map.get("PATH").?);
    try std.testing.expect(filtered.env_map.get("TERM") == null);
}

test "secretless redacts synthetic token material embedded in an environment name" {
    const name_canary = "TOKEN_ghp_fakeSyntheticNameCanary1234567890";

    var selected = try policy.load.loadPreset(std.testing.allocator, .observe);
    defer selected.deinit();

    var current = std.process.Environ.Map.init(std.testing.allocator);
    defer current.deinit();
    try current.put("PATH", "/usr/bin");
    try current.put(name_canary, "ordinary");

    var filtered = try filterMap(
        std.testing.allocator,
        &current,
        &selected,
        .observe,
        .{ .secret_boundary = .empty_backpack },
    );
    defer filtered.deinit();

    try std.testing.expectEqual(@as(usize, 1), filtered.redactions.len);
    try std.testing.expect(std.mem.indexOf(u8, filtered.redactions[0].name, "ghp_fakeSyntheticNameCanary") == null);
    for (filtered.redactions[0].labels) |label| {
        try std.testing.expect(std.mem.indexOf(u8, label, "ghp_fakeSyntheticNameCanary") == null);
    }
}

test "observe mode override still honors env inherit false" {
    var selected = try policy.load.loadPreset(std.testing.allocator, .strict);
    defer selected.deinit();

    var current = std.process.Environ.Map.init(std.testing.allocator);
    defer current.deinit();
    try current.put("PATH", "/usr/bin");
    try current.put("UNIQUE_SAFE_PHASE08", "visible");

    var filtered = try filterMap(std.testing.allocator, &current, &selected, .observe, .{});
    defer filtered.deinit();

    try std.testing.expectEqualStrings("/usr/bin", filtered.env_map.get("PATH").?);
    try std.testing.expect(filtered.env_map.get("UNIQUE_SAFE_PHASE08") == null);
}

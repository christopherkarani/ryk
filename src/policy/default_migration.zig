//! Version-stamped migration support for shipped default policies.
//!
//! Install/ensure seeds policies create-only, so an existing install keeps the
//! default body that shipped when it was first set up. When the embedded
//! default improves (e.g. the coding DCG switch that ended ask-mode deadlocks),
//! a pristine copy of an older default should be replaced by the new default;
//! a customized policy must never be rewritten silently.
//!
//! Classification is byte-exact: SHA-256 over the file content, compared
//! against every generic-agent default body ryk has ever shipped. Bodies were
//! reconstructed from release tags and verified byte-identical against the
//! installer seed path (see tests). When the embedded default changes, add the
//! outgoing body hash to `legacy_generic_agent_sha256_hex`.

const std = @import("std");
const presets = @import("presets.zig");
const load = @import("load.zig");

pub const Classification = enum {
    /// Byte-identical to a current embedded preset body — nothing to do.
    current_default,
    /// Byte-identical to a generic-agent default shipped by an older release —
    /// pristine, so migrating to the current default is safe (with backup).
    legacy_default,
    /// Parses as a valid policy but matches no shipped default — customized.
    customized,
    /// Does not parse as a valid policy — fail closed; never rewrite.
    invalid,
};

/// SHA-256 hex of every generic-agent default body shipped before the current
/// one (current = c65f0f6f…, shipped v1.2.14–v1.2.17). Reconstructed per tag:
///   - 2dbf4c02… plugins-v1.0.0 / v1.0.2 / v1.1.0 (Aegis-era ask default)
///   - 0a885ae1… v1.1.1 / v1.1.4 / v1.1.5
///   - dce92836… v1.2.0 – v1.2.9
///   - 5d072e47… v1.2.10 – v1.2.12
///   - 1e231762… v1.2.13 (last pre-DCG ask-mode default)
pub const legacy_generic_agent_sha256_hex = [_][]const u8{
    "2dbf4c02f21a12fbc70f039794d0948bfeca7a648137aad00a59bd0f8b1dfbf4",
    "0a885ae1f1b976545182034e743e5b7823760328ccea7de4fcdf7b1f68c93950",
    "dce9283649bda4097cdec4ae0df0e9c886798fc4d17d8040495c802b25073ea2",
    "5d072e477c4e981b57b17f2e61aa928eb849df4c2a9db05b47cdbe8201a702a8",
    "1e2317625c539ccbd9687289063c3302416cfda2b18a09f65d993283036997f4",
};

pub fn sha256Hex(content: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(content, &digest, .{});
    var out: [64]u8 = undefined;
    const hex_alphabet = "0123456789abcdef";
    for (digest, 0..) |byte, i| {
        out[i * 2] = hex_alphabet[byte >> 4];
        out[i * 2 + 1] = hex_alphabet[byte & 0xf];
    }
    return out;
}

/// True when `content` is byte-identical to a legacy shipped generic-agent default.
pub fn isLegacyDefault(content: []const u8) bool {
    const hex = sha256Hex(content);
    for (legacy_generic_agent_sha256_hex) |known| {
        if (std.mem.eql(u8, &hex, known)) return true;
    }
    return false;
}

/// True when `content` is byte-identical to any current embedded preset body.
/// Only generic-agent legacy bodies are ever migrated; other presets (notably
/// unattended) must never be rewritten, so any current preset counts as current.
pub fn isCurrentDefault(content: []const u8) bool {
    inline for (@typeInfo(presets.AgentPreset).@"enum".fields) |field| {
        const preset: presets.AgentPreset = @enumFromInt(field.value);
        if (std.mem.eql(u8, content, presets.agentPresetText(preset))) return true;
    }
    return false;
}

/// Classify on-disk policy content. Parse check keeps corrupted files fail-closed:
/// they are never migrated and surface as `invalid` so callers can say so plainly.
pub fn classify(allocator: std.mem.Allocator, content: []const u8) Classification {
    if (isCurrentDefault(content)) return .current_default;
    if (isLegacyDefault(content)) return .legacy_default;
    var parsed = load.parseFromSlice(allocator, content, "policy.yaml") catch return .invalid;
    parsed.deinit();
    return .customized;
}

/// The body a legacy default migrates to: the current embedded generic-agent default.
pub fn currentDefaultBody() []const u8 {
    return presets.agentPresetText(.generic_agent);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "current embedded generic-agent body classifies as current_default" {
    const body = presets.agentPresetText(.generic_agent);
    try std.testing.expectEqual(Classification.current_default, classify(std.testing.allocator, body));
}

test "every current preset body classifies as current_default (never migrate unattended)" {
    inline for (@typeInfo(presets.AgentPreset).@"enum".fields) |field| {
        const preset: presets.AgentPreset = @enumFromInt(field.value);
        const body = presets.agentPresetText(preset);
        try std.testing.expectEqual(Classification.current_default, classify(std.testing.allocator, body));
    }
}

test "last pre-DCG ask-mode default classifies as legacy_default" {
    // Exact bytes of the v1.2.13 generic-agent default (ask mode — the class of
    // policy that deadlocked coding agents). Fixture hash must match registry.
    const allocator = std.testing.allocator;
    const body = try std.Io.Dir.cwd().readFileAlloc(
        std.testing.io,
        "tests/fixtures/policy-migration/generic-agent-v1.2.13.yaml",
        allocator,
        .limited(1024 * 1024),
    );
    defer allocator.free(body);
    try std.testing.expectEqualStrings(
        "1e2317625c539ccbd9687289063c3302416cfda2b18a09f65d993283036997f4",
        &sha256Hex(body),
    );
    try std.testing.expectEqual(Classification.legacy_default, classify(allocator, body));
}

test "customized policy classifies as customized" {
    const customized =
        \\version: 1
        \\mode: strict
        \\
        \\workspace:
        \\  root: "."
        \\  write_mode: staged
        \\
        \\commands:
        \\  default: allow
        \\  deny:
        \\    - "make deploy-prod*"
        \\
    ;
    try std.testing.expectEqual(Classification.customized, classify(std.testing.allocator, customized));
}

test "corrupted policy classifies as invalid (fail closed, never rewritten)" {
    try std.testing.expectEqual(Classification.invalid, classify(std.testing.allocator, ""));
    try std.testing.expectEqual(Classification.invalid, classify(std.testing.allocator, "not: [valid"));
    try std.testing.expectEqual(Classification.invalid, classify(std.testing.allocator, "version: 1\n# no mode"));
}

test "sha256Hex matches known vector" {
    const hex = sha256Hex("");
    try std.testing.expectEqualStrings("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", &hex);
}

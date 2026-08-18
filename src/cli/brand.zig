//! Single source of truth for product identity.
//!
//! Full product name: **Rykan V**. CLI / short brand: **ryk**.
//! No legacy dual-name. Workspace control dir: `.ryk/`.

const std = @import("std");

/// Full product name for prose (docs, about, long-form copy).
pub const product_full_name = "Rykan V";

/// User-facing short display name (help, TUI, status, block copy).
pub const product_display = "ryk";

/// Primary CLI binary / argv name.
pub const cli_name = "ryk";

/// npm package scope.
pub const package_scope = "@rykan";

/// Default FM / shell session id when host omits one (risk-card-v1 minLength 1).
pub const default_session_id = "ryk-shell";

/// Version JSON / plain `product` field.
pub fn versionProduct() []const u8 {
    return product_display;
}

/// Usage line prefix, e.g. `ryk version`.
pub fn usagePrefix() []const u8 {
    return cli_name;
}

/// True when argv0 basename is the primary binary name.
pub fn isPrimaryInvocation(argv0_basename: []const u8) bool {
    if (std.mem.eql(u8, argv0_basename, cli_name)) return true;
    if (std.mem.eql(u8, argv0_basename, cli_name ++ ".exe")) return true;
    return false;
}

/// What a baked hook/extension path is actually pointing at.
pub const EvaluatorKind = enum {
    product,
    test_harness,
    zig_compiler,
    other,

    pub fn isProduct(self: EvaluatorKind) bool {
        return self == .product;
    }

    /// Short diagnose label. Never claims OS enforcement.
    pub fn diagnoseLabel(self: EvaluatorKind) []const u8 {
        return switch (self) {
            .product => "product ryk",
            .test_harness => "Zig test program",
            .zig_compiler => "Zig compiler",
            .other => "non-product binary",
        };
    }
};

/// Classify a baked evaluator path by basename (`ryk` / `test` / `zig` / other).
pub fn classifyEvaluator(path: []const u8) EvaluatorKind {
    const trimmed = std.mem.trim(u8, path, " \t\r\n");
    if (trimmed.len == 0) return .other;
    const base = std.fs.path.basename(trimmed);
    if (isPrimaryInvocation(base)) return .product;
    if (std.mem.eql(u8, base, "test") or std.mem.eql(u8, base, "test.exe")) return .test_harness;
    if (std.mem.eql(u8, base, "zig") or std.mem.eql(u8, base, "zig.exe")) return .zig_compiler;
    return .other;
}

/// Safety-boundary blurb for version metadata. Telemetry is intentionally
/// separate from hosted policy, enforcement, and synchronization services.
pub fn safetyBoundary() []const u8 {
    return "ryk enforces local command, file, network, MCP, audit, and red-team controls; " ++
        "it does not provide hosted policy sync or cloud enforcement. Release builds may send fixed pseudonymous CLI telemetry.";
}

test "brand constants: ryk primary, Rykan V full name" {
    try std.testing.expectEqualStrings("ryk", product_display);
    try std.testing.expectEqualStrings("Rykan V", product_full_name);
    try std.testing.expectEqualStrings("ryk", cli_name);
    try std.testing.expectEqualStrings("@rykan", package_scope);
    try std.testing.expectEqualStrings("ryk", versionProduct());
    try std.testing.expectEqualStrings("ryk", usagePrefix());
    try std.testing.expect(isPrimaryInvocation("ryk"));
    try std.testing.expect(isPrimaryInvocation("ryk.exe"));
    // Reject retired / draft brand tokens (split so bulk renames cannot self-corrupt asserts).
    const retired_cli = "orc" ++ "a";
    const draft_brand = "ry" ++ "z";
    const retired_title = "Orc" ++ "a";
    try std.testing.expect(!isPrimaryInvocation(retired_cli));
    try std.testing.expect(!std.mem.eql(u8, product_display, draft_brand));
    try std.testing.expect(!std.mem.eql(u8, cli_name, draft_brand));
    try std.testing.expect(!std.mem.eql(u8, product_display, retired_cli));
    try std.testing.expect(!std.mem.eql(u8, product_display, retired_title));
}

test "brand default_session_id is ryk-shell not retired orca-shell" {
    try std.testing.expectEqualStrings("ryk-shell", default_session_id);
    // Split retired token so bulk renames cannot self-corrupt the assert.
    const retired_session = "orc" ++ "a-shell";
    try std.testing.expect(!std.mem.eql(u8, default_session_id, retired_session));
}

test "brand safety boundary names ryk not retired brands" {
    const retired_title = "Orc" ++ "a";
    const retired_cli = "orc" ++ "a";
    try std.testing.expect(std.mem.indexOf(u8, safetyBoundary(), "ryk") != null);
    try std.testing.expect(std.mem.indexOf(u8, safetyBoundary(), retired_title) == null);
    try std.testing.expect(std.mem.indexOf(u8, safetyBoundary(), retired_cli) == null);
}

test "classifyEvaluator names product ryk vs Zig test program vs compiler" {
    try std.testing.expectEqual(EvaluatorKind.product, classifyEvaluator("/Users/me/.local/bin/ryk"));
    try std.testing.expectEqual(EvaluatorKind.product, classifyEvaluator("/opt/ryk/bin/ryk.exe"));
    try std.testing.expectEqual(EvaluatorKind.test_harness, classifyEvaluator(
        "/private/tmp/ryk-factory/.zig-cache/o/deadbeef/test",
    ));
    try std.testing.expectEqual(EvaluatorKind.test_harness, classifyEvaluator(
        "/Users/me/CodingProjects/ryk/.zig-cache/o/abc/test",
    ));
    try std.testing.expectEqual(EvaluatorKind.zig_compiler, classifyEvaluator(
        "/Users/me/.local/zig/zig-aarch64-macos-0.16.0/zig",
    ));
    try std.testing.expectEqual(EvaluatorKind.other, classifyEvaluator("/usr/bin/true"));
    try std.testing.expectEqual(EvaluatorKind.other, classifyEvaluator(""));
    try std.testing.expectEqualStrings("Zig test program", EvaluatorKind.test_harness.diagnoseLabel());
    try std.testing.expect(!classifyEvaluator("/tmp/.zig-cache/o/x/test").isProduct());
    try std.testing.expect(classifyEvaluator("/opt/ryk/bin/ryk").isProduct());
}

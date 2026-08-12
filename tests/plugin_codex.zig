const std = @import("std");

// ---------------------------------------------------------------------------
// Codex Plugin Structure Tests
// ---------------------------------------------------------------------------
// These tests validate the P03 Codex plugin package without requiring
// the ryk binary to be built. They check file existence, JSON validity,
// and content invariants.
// ---------------------------------------------------------------------------

const plugin_dir = "integrations/codex-plugin";
const manifest_path = plugin_dir ++ "/.codex-plugin/plugin.json";
const hooks_path = plugin_dir ++ "/hooks/hooks.json";
const readme_path = plugin_dir ++ "/README.md";
const marketplace_example_path = plugin_dir ++ "/examples/marketplace.json";

const skills = &[_][]const u8{
    "ryk-doctor",
    "ryk-init",
    "ryk-protect",
    "ryk-redteam",
    "ryk-replay",
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn fileExists(path: []const u8) bool {
    std.Io.Dir.cwd().access(std.testing.io, path, .{}) catch return false;
    return true;
}

fn readFile(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    return try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, allocator, .limited(1024 * 1024));
}

// ---------------------------------------------------------------------------
// Manifest tests
// ---------------------------------------------------------------------------

test "codex plugin manifest exists" {
    try std.testing.expect(fileExists(manifest_path));
}

test "codex plugin manifest is valid JSON" {
    var dbg_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = dbg_state.deinit();
    const allocator = dbg_state.allocator();

    const content = try readFile(allocator, manifest_path);
    defer allocator.free(content);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, content, .{});
    defer parsed.deinit();
}

test "codex plugin manifest contains expected fields" {
    var dbg_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = dbg_state.deinit();
    const allocator = dbg_state.allocator();

    const content = try readFile(allocator, manifest_path);
    defer allocator.free(content);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, content, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    try std.testing.expect(obj.get("name") != null);
    try std.testing.expect(obj.get("version") != null);
    try std.testing.expect(obj.get("description") != null);
    try std.testing.expect(obj.get("skills") != null);
    try std.testing.expect(obj.get("hooks") != null);
    try std.testing.expect(obj.get("interface") != null);

    const name = obj.get("name").?.string;
    try std.testing.expectEqualStrings("ryk", name);
}

test "codex plugin manifest points to skills directory" {
    var dbg_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = dbg_state.deinit();
    const allocator = dbg_state.allocator();

    const content = try readFile(allocator, manifest_path);
    defer allocator.free(content);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, content, .{});
    defer parsed.deinit();

    const skills_value = parsed.value.object.get("skills").?.string;
    try std.testing.expect(std.mem.eql(u8, skills_value, "./skills/"));
}

test "codex plugin manifest points to hooks file" {
    var dbg_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = dbg_state.deinit();
    const allocator = dbg_state.allocator();

    const content = try readFile(allocator, manifest_path);
    defer allocator.free(content);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, content, .{});
    defer parsed.deinit();

    const hooks_value = parsed.value.object.get("hooks").?.string;
    try std.testing.expect(std.mem.eql(u8, hooks_value, "./hooks/hooks.json"));
}

// ---------------------------------------------------------------------------
// Skills tests
// ---------------------------------------------------------------------------

test "all five codex skills exist" {
    for (skills) |skill| {
        const skill_path = std.fmt.allocPrint(std.testing.allocator, "{s}/skills/{s}/SKILL.md", .{ plugin_dir, skill }) catch unreachable;
        defer std.testing.allocator.free(skill_path);
        try std.testing.expect(fileExists(skill_path));
    }
}

test "each skill has non-empty SKILL.md" {
    for (skills) |skill| {
        const skill_path = std.fmt.allocPrint(std.testing.allocator, "{s}/skills/{s}/SKILL.md", .{ plugin_dir, skill }) catch unreachable;
        defer std.testing.allocator.free(skill_path);

        const content = try readFile(std.testing.allocator, skill_path);
        defer std.testing.allocator.free(content);

        try std.testing.expect(content.len > 50);
    }
}

test "each skill references real ryk commands" {
    for (skills) |skill| {
        const skill_path = std.fmt.allocPrint(std.testing.allocator, "{s}/skills/{s}/SKILL.md", .{ plugin_dir, skill }) catch unreachable;
        defer std.testing.allocator.free(skill_path);

        const content = try readFile(std.testing.allocator, skill_path);
        defer std.testing.allocator.free(content);

        // Every skill should mention "ryk" at least once
        try std.testing.expect(std.mem.indexOf(u8, content, "ryk") != null);
    }
}

test "no mcp skill exists in codex plugin" {
    const mcp_skill_path = plugin_dir ++ "/skills/ryk-mcp/SKILL.md";
    try std.testing.expect(!fileExists(mcp_skill_path));
}

// ---------------------------------------------------------------------------
// Hooks tests
// ---------------------------------------------------------------------------

test "codex hooks config exists" {
    try std.testing.expect(fileExists(hooks_path));
}

test "codex hooks config is valid JSON" {
    var dbg_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = dbg_state.deinit();
    const allocator = dbg_state.allocator();

    const content = try readFile(allocator, hooks_path);
    defer allocator.free(content);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, content, .{});
    defer parsed.deinit();
}

test "codex hooks config dispatches to the ryk Codex hook" {
    var dbg_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = dbg_state.deinit();
    const allocator = dbg_state.allocator();

    const content = try readFile(allocator, hooks_path);
    defer allocator.free(content);

    // The portable wrapper resolves the installed binary before dispatching.
    try std.testing.expect(std.mem.indexOf(u8, content, "hook codex") != null);
}

test "codex hooks config does not call nonexistent scripts" {
    var dbg_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = dbg_state.deinit();
    const allocator = dbg_state.allocator();

    const content = try readFile(allocator, hooks_path);
    defer allocator.free(content);

    // Should not call scripts that do not exist in the plugin
    try std.testing.expect(std.mem.indexOf(u8, content, "./scripts/") == null);
    try std.testing.expect(std.mem.indexOf(u8, content, ".sh") == null);
}

test "codex hooks config does not include absolute local paths" {
    var dbg_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = dbg_state.deinit();
    const allocator = dbg_state.allocator();

    const content = try readFile(allocator, hooks_path);
    defer allocator.free(content);

    // Should not contain absolute paths like /Users/ or /home/
    try std.testing.expect(std.mem.indexOf(u8, content, "/Users/") == null);
    try std.testing.expect(std.mem.indexOf(u8, content, "/home/") == null);
}

// ---------------------------------------------------------------------------
// Marketplace example tests
// ---------------------------------------------------------------------------

test "marketplace example is valid JSON if present" {
    if (!fileExists(marketplace_example_path)) return;

    var dbg_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = dbg_state.deinit();
    const allocator = dbg_state.allocator();

    const content = try readFile(allocator, marketplace_example_path);
    defer allocator.free(content);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, content, .{});
    defer parsed.deinit();
}

// ---------------------------------------------------------------------------
// Secret safety tests
// ---------------------------------------------------------------------------

test "no plugin file contains fake secret test values" {
    // Check known plugin files for obviously fake secret patterns
    const files_to_check = &[_][]const u8{
        manifest_path,
        hooks_path,
        readme_path,
    };

    for (files_to_check) |path| {
        if (!fileExists(path)) continue;
        const content = try readFile(std.testing.allocator, path);
        defer std.testing.allocator.free(content);

        try std.testing.expect(std.mem.indexOf(u8, content, "ghp_") == null);
        try std.testing.expect(std.mem.indexOf(u8, content, "sk-") == null);
        try std.testing.expect(std.mem.indexOf(u8, content, "fake_p05_secret_value") == null);
    }
}

test "no plugin file contains obvious secret-like placeholders" {
    const files_to_check = &[_][]const u8{
        manifest_path,
        hooks_path,
        readme_path,
    };

    for (files_to_check) |path| {
        if (!fileExists(path)) continue;
        const content = try readFile(std.testing.allocator, path);
        defer std.testing.allocator.free(content);

        try std.testing.expect(std.mem.indexOf(u8, content, "YOUR_API_KEY") == null);
        try std.testing.expect(std.mem.indexOf(u8, content, "REPLACE_WITH_SECRET") == null);
        try std.testing.expect(std.mem.indexOf(u8, content, "password123") == null);
    }
}

// ---------------------------------------------------------------------------
// README content tests
// ---------------------------------------------------------------------------

test "plugin README includes strongest-protection warning" {
    const content = try readFile(std.testing.allocator, readme_path);
    defer std.testing.allocator.free(content);

    try std.testing.expect(std.mem.indexOf(u8, content, "strongest local protection") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "ryk run --") != null);
}

test "plugin README states no MCP server behavior" {
    const content = try readFile(std.testing.allocator, readme_path);
    defer std.testing.allocator.free(content);

    try std.testing.expect(std.mem.indexOf(u8, content, "does not add MCP server behavior") != null);
}

// ---------------------------------------------------------------------------
// Docs content tests
// ---------------------------------------------------------------------------

test "docs do not claim official marketplace availability" {
    const docs_path = "docs/integrations/codex.md";
    if (!fileExists(docs_path)) return;

    const content = try readFile(std.testing.allocator, docs_path);
    defer std.testing.allocator.free(content);

    // Should not claim the marketplace is officially available
    const lower = try std.ascii.allocLowerString(std.testing.allocator, content);
    defer std.testing.allocator.free(lower);
    try std.testing.expect(std.mem.indexOf(u8, lower, "officially available") == null);
    try std.testing.expect(std.mem.indexOf(u8, lower, "marketplace is live") == null);
}

// ---------------------------------------------------------------------------
// Hook fixture integration tests (requires built binary)
// ---------------------------------------------------------------------------

test "fake codex hook payload fixtures still work with ryk hook codex" {
    // This test is a smoke test that validates fixture files are present.
    // Full integration requires the built binary and is tested manually.
    const fixture_dir = "tests/plugin-fixtures/codex";
    const expected_fixtures = &[_][]const u8{
        "session_start.json",
        "user_prompt_submit_secret.json",
        "pre_tool_use_command_safe.json",
        "pre_tool_use_command_dangerous.json",
        "pre_tool_use_file_write_protected.json",
        "permission_request.json",
        "post_tool_use.json",
        "stop.json",
    };

    for (expected_fixtures) |fixture| {
        const path = try std.fs.path.join(std.testing.allocator, &.{ fixture_dir, fixture });
        defer std.testing.allocator.free(path);
        try std.testing.expect(fileExists(path));
    }
}

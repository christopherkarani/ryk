const std = @import("std");

const plugin_dir = "integrations/hermes-plugin";
const manifest_path = plugin_dir ++ "/plugin.yaml";
const source_path = plugin_dir ++ "/__init__.py";
const readme_path = plugin_dir ++ "/README.md";
const fixture_dir = "tests/plugin-fixtures/hermes";

fn fileExists(path: []const u8) bool {
    std.Io.Dir.cwd().access(std.testing.io, path, .{}) catch return false;
    return true;
}

fn readFile(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    return try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, allocator, .limited(1024 * 1024));
}

test "hermes plugin manifest exists and names ryk" {
    try std.testing.expect(fileExists(manifest_path));
    const content = try readFile(std.testing.allocator, manifest_path);
    defer std.testing.allocator.free(content);

    try std.testing.expect(std.mem.indexOf(u8, content, "name: ryk") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "entrypoint: __init__.py") != null);
}

test "hermes plugin source exists and calls ryk hook hermes" {
    try std.testing.expect(fileExists(source_path));
    const content = try readFile(std.testing.allocator, source_path);
    defer std.testing.allocator.free(content);

    try std.testing.expect(std.mem.indexOf(u8, content, "\"hook\", \"hermes\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "ctx.register_hook") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "pre_tool_call") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "pre_llm_call") != null);
}

test "hermes plugin source does not duplicate policy logic or store secrets" {
    const content = try readFile(std.testing.allocator, source_path);
    defer std.testing.allocator.free(content);

    try std.testing.expect(std.mem.indexOf(u8, content, "rm -rf") == null);
    try std.testing.expect(std.mem.indexOf(u8, content, "allowlist") == null);
    try std.testing.expect(std.mem.indexOf(u8, content, "denylist") == null);
    try std.testing.expect(std.mem.indexOf(u8, content, "YOUR_API_KEY") == null);
    try std.testing.expect(std.mem.indexOf(u8, content, "password123") == null);
}

test "hermes plugin source detects stale ryk binaries and version mismatch" {
    const content = try readFile(std.testing.allocator, source_path);
    defer std.testing.allocator.free(content);

    try std.testing.expect(std.mem.indexOf(u8, content, "unknown host 'hermes'") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "_supports_hermes_host") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "_handle_hook_error") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "RYK_HERMES_FAIL_OPEN") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "_ryk_executable") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "Allowing tool call WITHOUT ryk guardrails") != null);
}

test "hermes plugin readme documents degraded mode and discovery order" {
    const content = try readFile(std.testing.allocator, readme_path);
    defer std.testing.allocator.free(content);

    try std.testing.expect(std.mem.indexOf(u8, content, "fail-open") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "RYK_HERMES_FAIL_OPEN") != null);
    // Discovery: trusted home installs before cwd zig-out (F10/F4).
    try std.testing.expect(std.mem.indexOf(u8, content, "~/.local/bin/ryk") != null or std.mem.indexOf(u8, content, "~/.ryk/bin") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "zig-out") != null);
}

test "hermes plugin readme documents install and limits" {
    try std.testing.expect(fileExists(readme_path));
    const content = try readFile(std.testing.allocator, readme_path);
    defer std.testing.allocator.free(content);

    try std.testing.expect(std.mem.indexOf(u8, content, "plugin install hermes") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "pre_gateway_dispatch") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "ryk run -- hermes") != null or std.mem.indexOf(u8, content, "ryk run -- hermes") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "context-only") != null or std.mem.indexOf(u8, content, "Context-only") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "Telegram and Discord") != null);
    // Native approve-and-resume for tool ask (not block-without-resume).
    try std.testing.expect(std.mem.indexOf(u8, content, "approve") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "rule_key") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "approve-and-resume") != null);
    // Must not claim passive notes or clarify are the approval mechanism.
    try std.testing.expect(std.mem.indexOf(u8, content, "tell the model to call") == null);
}

test "hermes plugin source maps ask to approve not permanent block" {
    const content = try readFile(std.testing.allocator, source_path);
    defer std.testing.allocator.free(content);

    try std.testing.expect(std.mem.indexOf(u8, content, "_map_pre_tool_call") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "mapping") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "_log_policy_warn") != null);

    const mapping_path = plugin_dir ++ "/mapping.py";
    try std.testing.expect(fileExists(mapping_path));
    const mapping = try readFile(std.testing.allocator, mapping_path);
    defer std.testing.allocator.free(mapping);
    try std.testing.expect(std.mem.indexOf(u8, mapping, "approve") != null);
    try std.testing.expect(std.mem.indexOf(u8, mapping, "ci_mode") != null);
    try std.testing.expect(std.mem.indexOf(u8, mapping, "stable_rule_key") != null);
    try std.testing.expect(std.mem.indexOf(u8, mapping, "rule_key") != null);
}

test "all hermes fixtures exist" {
    const fixtures = &[_][]const u8{
        "on_session_start.json",
        "pre_tool_call_command_safe.json",
        "pre_tool_call_command_dangerous.json",
        "pre_tool_call_file_write_protected.json",
        "pre_llm_call.json",
        "post_llm_call.json",
        "on_session_end.json",
        "subagent_stop.json",
    };

    for (fixtures) |fixture| {
        const path = try std.fs.path.join(std.testing.allocator, &.{ fixture_dir, fixture });
        defer std.testing.allocator.free(path);
        try std.testing.expect(fileExists(path));
    }
}

test "hermes fixtures are valid JSON with hermes host" {
    const fixtures = &[_][]const u8{
        "on_session_start.json",
        "pre_tool_call_command_safe.json",
        "pre_tool_call_command_dangerous.json",
        "pre_tool_call_file_write_protected.json",
        "pre_llm_call.json",
        "post_llm_call.json",
        "on_session_end.json",
        "subagent_stop.json",
    };

    var dbg_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = dbg_state.deinit();
    const allocator = dbg_state.allocator();

    for (fixtures) |fixture| {
        const path = try std.fs.path.join(allocator, &.{ fixture_dir, fixture });
        defer allocator.free(path);

        const content = try readFile(allocator, path);
        defer allocator.free(content);

        var parsed = try std.json.parseFromSlice(std.json.Value, allocator, content, .{});
        defer parsed.deinit();

        try std.testing.expectEqual(@as(i64, 1), parsed.value.object.get("version").?.integer);
        try std.testing.expectEqualStrings("hermes", parsed.value.object.get("host").?.string);
    }
}

test "hermes fixtures do not contain real secrets" {
    const fixtures = &[_][]const u8{
        "on_session_start.json",
        "pre_tool_call_command_safe.json",
        "pre_tool_call_command_dangerous.json",
        "pre_tool_call_file_write_protected.json",
        "pre_llm_call.json",
        "post_llm_call.json",
        "on_session_end.json",
        "subagent_stop.json",
    };

    var dbg_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = dbg_state.deinit();
    const allocator = dbg_state.allocator();

    for (fixtures) |fixture| {
        const path = try std.fs.path.join(allocator, &.{ fixture_dir, fixture });
        defer allocator.free(path);

        const content = try readFile(allocator, path);
        defer allocator.free(content);

        try std.testing.expect(std.mem.indexOf(u8, content, "ghp_") == null);
        try std.testing.expect(std.mem.indexOf(u8, content, "sk-") == null);
        try std.testing.expect(std.mem.indexOf(u8, content, "password123") == null);
    }
}

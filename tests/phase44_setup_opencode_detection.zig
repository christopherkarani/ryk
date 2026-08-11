const std = @import("std");
const plugin = @import("ryk").cli.plugin;

test "phase 44 hostPluginInstalledFromDoctorJson detects opencode project install" {
    const json =
        \\{
        \\  "opencode_paths": {
        \\    "project_plugin_exists": true,
        \\    "global_plugin_exists": false
        \\  }
        \\}
    ;
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json, .{});
    defer parsed.deinit();
    try std.testing.expect(plugin.hostPluginInstalledFromDoctorJson("opencode", parsed.value));
}

test "phase 44 hostPluginInstalledFromDoctorJson detects opencode global install" {
    const json =
        \\{
        \\  "opencode_paths": {
        \\    "project_plugin_exists": false,
        \\    "global_plugin_exists": true
        \\  }
        \\}
    ;
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json, .{});
    defer parsed.deinit();
    try std.testing.expect(plugin.hostPluginInstalledFromDoctorJson("opencode", parsed.value));
}

test "phase 44 hostPluginInstalledFromDoctorJson ignores codex marketplace-only registration" {
    const json =
        \\{
        \\  "marketplace": {
        \\    "codex_user_plugin": false,
        \\    "codex_marketplace": true
        \\  }
        \\}
    ;
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json, .{});
    defer parsed.deinit();
    try std.testing.expect(!plugin.hostPluginInstalledFromDoctorJson("codex", parsed.value));
}

test "phase 44 hostPluginInstalledFromDoctorJson detects codex user plugin install" {
    const json =
        \\{
        \\  "marketplace": {
        \\    "codex_user_plugin": true,
        \\    "codex_marketplace": true
        \\  }
        \\}
    ;
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json, .{});
    defer parsed.deinit();
    try std.testing.expect(plugin.hostPluginInstalledFromDoctorJson("codex", parsed.value));
}

test "phase 44 hostPluginInstalledFromDoctorJson ignores claude marketplace-only registration" {
    const json =
        \\{
        \\  "marketplace": {
        \\    "claude_user_plugin": false,
        \\    "claude_marketplace": true
        \\  }
        \\}
    ;
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json, .{});
    defer parsed.deinit();
    try std.testing.expect(!plugin.hostPluginInstalledFromDoctorJson("claude", parsed.value));
}

test "phase 44 doctor state only accepts complete Hermes install after child failure" {
    const json =
        \\{
        \\  "openclaw_paths": { "host_plugin_installed": true },
        \\  "hermes_paths": {
        \\    "user_manifest_exists": true,
        \\    "user_source_exists": true,
        \\    "user_mapping_exists": true,
        \\    "config_references_plugin": true,
        \\    "user_manifest_name_is_ryk": true
        \\  }
        \\}
    ;
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json, .{});
    defer parsed.deinit();
    try std.testing.expect(plugin.hostPluginInstalledFromDoctorJson("openclaw", parsed.value));
    try std.testing.expect(plugin.hostPluginInstalledFromDoctorJson("hermes", parsed.value));
    try std.testing.expectEqual(plugin.HostInstallOutcome.installed_after_child_failure, plugin.classifyHostInstallOutcome(17, true));
}

test "phase 44 hostPluginInstalledFromReport matches doctor JSON semantics" {
    const cwd = try std.testing.allocator.dupeZ(u8, "");
    defer std.testing.allocator.free(cwd);
    const report = plugin.PluginDoctorReport{
        .ryk_version = "test",
        .ryk_binary_path = null,
        .cwd = cwd,
        .workspace_root = "",
        .policy_present = false,
        .policy_valid = false,
        .policy_error = null,
        .audit_replay_available = false,
        .mcp_support_status = "",
        .plugin_directories = .{ .codex = true, .claude = true, .opencode = true, .openclaw = true, .hermes = true, .common = true },
        .host_binaries = .{ .codex = true, .claude = true, .opencode = true, .openclaw = true, .hermes = true },
        .opencode_paths = .{ .project_plugin_exists = false, .global_plugin_exists = false, .config_references_plugin = false },
        .openclaw_paths = .{ .host_plugin_installed = true, .plugin_manifest_exists = false, .package_json_exists = false, .source_exists = false, .detection_note = "" },
        .hermes_paths = .{ .repo_manifest_exists = false, .repo_source_exists = false, .repo_mapping_exists = false, .user_manifest_exists = true, .user_source_exists = true, .user_mapping_exists = true, .config_references_plugin = true, .user_manifest_name_is_ryk = true },
        .hermes_hook_smoke_passed = false,
        .marketplace = .{
            .codex_marketplace = true,
            .claude_marketplace = true,
            .codex_plugin_manifest = true,
            .claude_plugin_manifest = true,
            .codex_user_plugin = false,
            .claude_user_plugin = false,
        },
        .platform_summary = "",
        .warnings = &.{},
    };
    try std.testing.expect(!plugin.hostPluginInstalledFromReport("codex", report));
    try std.testing.expect(!plugin.hostPluginInstalledFromReport("claude", report));
    try std.testing.expect(plugin.hostPluginInstalledFromReport("openclaw", report));
    try std.testing.expect(plugin.hostPluginInstalledFromReport("hermes", report));
}

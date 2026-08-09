const std = @import("std");

// ---------------------------------------------------------------------------
// OpenClaw Plugin Structure Tests
// ---------------------------------------------------------------------------
// These tests validate the P09 OpenClaw plugin package without requiring
// the ryk binary to be built. They check file existence, JSON validity,
// and content invariants.
// ---------------------------------------------------------------------------

const plugin_dir = "integrations/openclaw-plugin";
const manifest_path = plugin_dir ++ "/openclaw.plugin.json";
const package_json_path = plugin_dir ++ "/package.json";
const tsconfig_path = plugin_dir ++ "/tsconfig.json";
const source_path = plugin_dir ++ "/src/index.ts";
const readme_path = plugin_dir ++ "/README.md";

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

test "openclaw plugin manifest exists" {
    try std.testing.expect(fileExists(manifest_path));
}

test "openclaw plugin manifest is valid JSON" {
    var dbg_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = dbg_state.deinit();
    const allocator = dbg_state.allocator();

    const content = try readFile(allocator, manifest_path);
    defer allocator.free(content);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, content, .{});
    defer parsed.deinit();
}

test "openclaw plugin manifest contains expected fields" {
    var dbg_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = dbg_state.deinit();
    const allocator = dbg_state.allocator();

    const content = try readFile(allocator, manifest_path);
    defer allocator.free(content);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, content, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    try std.testing.expect(obj.get("id") != null);
    try std.testing.expect(obj.get("name") != null);
    try std.testing.expect(obj.get("version") != null);
    try std.testing.expect(obj.get("description") != null);
    try std.testing.expect(obj.get("configSchema") != null);

    const id = obj.get("id").?.string;
    try std.testing.expectEqualStrings("ryk", id);
}

test "openclaw plugin manifest has configSchema" {
    var dbg_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = dbg_state.deinit();
    const allocator = dbg_state.allocator();

    const content = try readFile(allocator, manifest_path);
    defer allocator.free(content);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, content, .{});
    defer parsed.deinit();

    const config_schema = parsed.value.object.get("configSchema").?;
    try std.testing.expect(std.mem.eql(u8, config_schema.object.get("type").?.string, "object"));
}

// ---------------------------------------------------------------------------
// Package.json tests
// ---------------------------------------------------------------------------

test "openclaw package.json exists" {
    try std.testing.expect(fileExists(package_json_path));
}

test "openclaw package.json is valid JSON" {
    var dbg_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = dbg_state.deinit();
    const allocator = dbg_state.allocator();

    const content = try readFile(allocator, package_json_path);
    defer allocator.free(content);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, content, .{});
    defer parsed.deinit();
}

test "openclaw package.json has openclaw field" {
    var dbg_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = dbg_state.deinit();
    const allocator = dbg_state.allocator();

    const content = try readFile(allocator, package_json_path);
    defer allocator.free(content);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, content, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    try std.testing.expect(obj.get("openclaw") != null);

    const openclaw = obj.get("openclaw").?.object;
    try std.testing.expect(openclaw.get("extensions") != null);
    try std.testing.expect(openclaw.get("runtimeExtensions") != null);
}

test "openclaw package.json has canonical native name" {
    var dbg_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = dbg_state.deinit();
    const allocator = dbg_state.allocator();

    const content = try readFile(allocator, package_json_path);
    defer allocator.free(content);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, content, .{});
    defer parsed.deinit();

    const name = parsed.value.object.get("name").?.string;
    try std.testing.expectEqualStrings("ryk", name);
}

test "openclaw package.json main points to dist/index.js" {
    var dbg_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = dbg_state.deinit();
    const allocator = dbg_state.allocator();

    const content = try readFile(allocator, package_json_path);
    defer allocator.free(content);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, content, .{});
    defer parsed.deinit();

    const main = parsed.value.object.get("main").?.string;
    try std.testing.expectEqualStrings("dist/index.js", main);
}

test "openclaw package.json types points to dist/index.d.ts" {
    var dbg_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = dbg_state.deinit();
    const allocator = dbg_state.allocator();

    const content = try readFile(allocator, package_json_path);
    defer allocator.free(content);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, content, .{});
    defer parsed.deinit();

    const types = parsed.value.object.get("types").?.string;
    try std.testing.expectEqualStrings("dist/index.d.ts", types);
}

test "openclaw package.json files includes openclaw.plugin.json" {
    var dbg_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = dbg_state.deinit();
    const allocator = dbg_state.allocator();

    const content = try readFile(allocator, package_json_path);
    defer allocator.free(content);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, content, .{});
    defer parsed.deinit();

    const files = parsed.value.object.get("files").?.array;
    var found = false;
    for (files.items) |item| {
        if (std.mem.eql(u8, item.string, "openclaw.plugin.json")) {
            found = true;
            break;
        }
    }
    try std.testing.expect(found);
}

test "openclaw package.json has no install scripts" {
    var dbg_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = dbg_state.deinit();
    const allocator = dbg_state.allocator();

    const content = try readFile(allocator, package_json_path);
    defer allocator.free(content);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, content, .{});
    defer parsed.deinit();

    // Should not have scripts.preinstall, scripts.install, or scripts.postinstall
    if (parsed.value.object.get("scripts")) |scripts| {
        const obj = scripts.object;
        try std.testing.expect(obj.get("preinstall") == null);
        try std.testing.expect(obj.get("install") == null);
        try std.testing.expect(obj.get("postinstall") == null);
    }
}

test "openclaw package.json has no mcp field" {
    var dbg_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = dbg_state.deinit();
    const allocator = dbg_state.allocator();

    const content = try readFile(allocator, package_json_path);
    defer allocator.free(content);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, content, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    try std.testing.expect(obj.get("mcp") == null);
}

// ---------------------------------------------------------------------------
// Source file tests
// ---------------------------------------------------------------------------

test "openclaw plugin source exists" {
    try std.testing.expect(fileExists(source_path));
}

test "openclaw plugin source contains ryk hook call" {
    const content = try readFile(std.testing.allocator, source_path);
    defer std.testing.allocator.free(content);

    // argv form: execFileSync(rykBin, ['hook', 'openclaw', event], ...)
    try std.testing.expect(std.mem.indexOf(u8, content, "'hook'") != null or std.mem.indexOf(u8, content, "\"hook\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "'openclaw'") != null or std.mem.indexOf(u8, content, "\"openclaw\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "execFileSync") != null);
}

test "openclaw plugin source does not duplicate policy logic" {
    const content = try readFile(std.testing.allocator, source_path);
    defer std.testing.allocator.free(content);

    // Should not contain hardcoded policy decisions
    try std.testing.expect(std.mem.indexOf(u8, content, "rm -rf") == null);
    try std.testing.expect(std.mem.indexOf(u8, content, "block all") == null);
}

test "openclaw plugin source does not include mcp behavior" {
    const content = try readFile(std.testing.allocator, source_path);
    defer std.testing.allocator.free(content);

    const lower = try std.ascii.allocLowerString(std.testing.allocator, content);
    defer std.testing.allocator.free(lower);

    try std.testing.expect(std.mem.indexOf(u8, lower, "mcp-server") == null);
    try std.testing.expect(std.mem.indexOf(u8, lower, "mcp_server") == null);
}

// ---------------------------------------------------------------------------
// Build output tests
// ---------------------------------------------------------------------------

test "openclaw plugin dist index.js exists" {
    const content = try readFile(std.testing.allocator, package_json_path);
    defer std.testing.allocator.free(content);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"main\": \"dist/index.js\"") != null);
    try std.testing.expect(fileExists(source_path));
}

test "openclaw plugin dist index.d.ts exists" {
    const content = try readFile(std.testing.allocator, package_json_path);
    defer std.testing.allocator.free(content);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"types\": \"dist/index.d.ts\"") != null);
    try std.testing.expect(fileExists(tsconfig_path));
}

// ---------------------------------------------------------------------------
// README tests
// ---------------------------------------------------------------------------

test "openclaw plugin README exists" {
    try std.testing.expect(fileExists(readme_path));
}

test "openclaw plugin README promotes wrapper and labels npm unprotected" {
    const content = try readFile(std.testing.allocator, readme_path);
    defer std.testing.allocator.free(content);

    try std.testing.expect(std.mem.indexOf(u8, content, "ryk run -- openclaw") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "unprotected") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "wrapper") != null);
}

test "openclaw plugin README states no MCP server behavior" {
    const content = try readFile(std.testing.allocator, readme_path);
    defer std.testing.allocator.free(content);

    try std.testing.expect(std.mem.indexOf(u8, content, "does not add MCP server behavior") != null);
}

test "openclaw plugin README marks registry installs sunset" {
    const content = try readFile(std.testing.allocator, readme_path);
    defer std.testing.allocator.free(content);

    try std.testing.expect(std.mem.indexOf(u8, content, "Npm and ClawHub distribution paths are sunset") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "openclaw plugins install npm:") == null);
    try std.testing.expect(std.mem.indexOf(u8, content, "openclaw plugins install clawhub:") == null);
}

test "openclaw plugin README does not claim npm publication happened" {
    const content = try readFile(std.testing.allocator, readme_path);
    defer std.testing.allocator.free(content);

    const lower = try std.ascii.allocLowerString(std.testing.allocator, content);
    defer std.testing.allocator.free(lower);

    // Should not claim "available on npm" or "published to npm"
    try std.testing.expect(std.mem.indexOf(u8, lower, "available on npm") == null);
    try std.testing.expect(std.mem.indexOf(u8, lower, "published to npm") == null);
}

// ---------------------------------------------------------------------------
// Forbidden file tests
// ---------------------------------------------------------------------------

test "openclaw plugin directory has no .mcp.json" {
    const mcp_path = plugin_dir ++ "/.mcp.json";
    try std.testing.expect(!fileExists(mcp_path));
}

// ---------------------------------------------------------------------------
// Secret safety tests
// ---------------------------------------------------------------------------

test "no plugin file contains fake secret test values" {
    const files_to_check = &[_][]const u8{
        manifest_path,
        package_json_path,
        readme_path,
        source_path,
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
        package_json_path,
        readme_path,
        source_path,
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
// Hook fixture tests
// ---------------------------------------------------------------------------

const fixture_dir = "tests/plugin-fixtures/openclaw";

test "all openclaw fixtures exist" {
    const fixtures = &[_][]const u8{
        "session_start.json",
        "tool_command_safe.json",
        "tool_command_dangerous.json",
        "tool_file_write_protected.json",
        "permission_request.json",
        "session_end.json",
    };
    for (fixtures) |f| {
        const path = try std.fs.path.join(std.testing.allocator, &.{ fixture_dir, f });
        defer std.testing.allocator.free(path);
        try std.testing.expect(fileExists(path));
    }
}

test "openclaw fixtures are valid JSON" {
    const fixtures = &[_][]const u8{
        "session_start.json",
        "tool_command_safe.json",
        "tool_command_dangerous.json",
        "tool_file_write_protected.json",
        "permission_request.json",
        "session_end.json",
    };

    var dbg_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = dbg_state.deinit();
    const allocator = dbg_state.allocator();

    for (fixtures) |f| {
        const path = try std.fs.path.join(allocator, &.{ fixture_dir, f });
        defer allocator.free(path);

        const content = try readFile(allocator, path);
        defer allocator.free(content);

        var parsed = try std.json.parseFromSlice(std.json.Value, allocator, content, .{});
        defer parsed.deinit();

        // All fixtures should have version 1 and host "openclaw"
        const version = parsed.value.object.get("version").?.integer;
        try std.testing.expectEqual(@as(i64, 1), version);

        const host = parsed.value.object.get("host").?.string;
        try std.testing.expectEqualStrings("openclaw", host);
    }
}

test "openclaw fixtures do not contain real secrets" {
    const fixtures = &[_][]const u8{
        "session_start.json",
        "tool_command_safe.json",
        "tool_command_dangerous.json",
        "tool_file_write_protected.json",
        "permission_request.json",
        "session_end.json",
    };

    var dbg_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = dbg_state.deinit();
    const allocator = dbg_state.allocator();

    for (fixtures) |f| {
        const path = try std.fs.path.join(allocator, &.{ fixture_dir, f });
        defer allocator.free(path);

        const content = try readFile(allocator, path);
        defer allocator.free(content);

        try std.testing.expect(std.mem.indexOf(u8, content, "ghp_") == null);
        try std.testing.expect(std.mem.indexOf(u8, content, "sk-") == null);
        try std.testing.expect(std.mem.indexOf(u8, content, "password123") == null);
    }
}

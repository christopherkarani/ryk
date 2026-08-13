const std = @import("std");
const ryk = @import("ryk");

fn readFile(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    return try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, allocator, .limited(256 * 1024));
}

test "phase25 release scripts package runtime assets referenced by CLI docs" {
    const sh = try readFile(std.testing.allocator, "scripts/build-release.sh");
    defer std.testing.allocator.free(sh);
    const ps1 = try readFile(std.testing.allocator, "scripts/build-release.ps1");
    defer std.testing.allocator.free(ps1);

    const required = [_][]const u8{ "docs", "policies", "schemas", "fixtures", "examples", "packages", "packaging", "scripts" };
    for (required) |name| {
        try std.testing.expect(std.mem.indexOf(u8, sh, name) != null);
        try std.testing.expect(std.mem.indexOf(u8, ps1, name) != null);
    }
}

test "phase25 release scripts exclude transient Python cache artifacts" {
    const sh = try readFile(std.testing.allocator, "scripts/build-release.sh");
    defer std.testing.allocator.free(sh);
    const ps1 = try readFile(std.testing.allocator, "scripts/build-release.ps1");
    defer std.testing.allocator.free(ps1);

    for ([_][]const u8{ "__pycache__", ".pytest_cache", ".pyc", ".pyo" }) |marker| {
        try std.testing.expect(std.mem.indexOf(u8, sh, marker) != null);
        try std.testing.expect(std.mem.indexOf(u8, ps1, marker) != null);
    }
}

test "phase25 Windows package templates match nested zip layout" {
    const version_file = try readFile(std.testing.allocator, "VERSION");
    defer std.testing.allocator.free(version_file);
    const version = std.mem.trim(u8, version_file, " \t\r\n");
    const scoop = try readFile(std.testing.allocator, "packaging/scoop/ryk.json");
    defer std.testing.allocator.free(scoop);
    const winget = try readFile(std.testing.allocator, "packaging/winget/ryk.yaml");
    defer std.testing.allocator.free(winget);

    const scoop_path = try std.fmt.allocPrint(std.testing.allocator, "ryk-v{s}-windows-amd64\\\\bin\\\\ryk.exe", .{version});
    defer std.testing.allocator.free(scoop_path);
    const winget_path = try std.fmt.allocPrint(std.testing.allocator, "ryk-v{s}-windows-amd64\\bin\\ryk.exe", .{version});
    defer std.testing.allocator.free(winget_path);
    try std.testing.expect(std.mem.indexOf(u8, scoop, scoop_path) != null);
    try std.testing.expect(std.mem.indexOf(u8, winget, winget_path) != null);
}

test "phase25 npm package is honest while checksum placeholders remain" {
    // npm is not an active distribution channel (curl/GitHub Release only). Templates
    // remain as legacy packaging inputs and must stay honest about that residual.
    const package_json = try readFile(std.testing.allocator, "packaging/npm/package.json");
    defer std.testing.allocator.free(package_json);
    const wrapper = try readFile(std.testing.allocator, "packaging/npm/bin/ryk.js");
    defer std.testing.allocator.free(wrapper);
    const readme = try readFile(std.testing.allocator, "packaging/npm/README.md");
    defer std.testing.allocator.free(readme);

    try std.testing.expect(std.mem.indexOf(u8, package_json, "npm launcher for the Zig-built ryk binary") != null);
    try std.testing.expect(std.mem.indexOf(u8, wrapper, "missing release checksums") != null);
    try std.testing.expect(
        std.mem.indexOf(u8, readme, "not an active") != null or
            std.mem.indexOf(u8, readme, "Legacy npm") != null or
            std.mem.indexOf(u8, readme, "fails closed") != null,
    );
}

test "phase25 MCP docs distinguish proxy stdin and list observation" {
    const mcp_doc = try readFile(std.testing.allocator, "docs/mcp.md");
    defer std.testing.allocator.free(mcp_doc);

    try std.testing.expect(std.mem.indexOf(u8, mcp_doc, "waits for JSON-RPC on stdin") != null);
    try std.testing.expect(std.mem.indexOf(u8, mcp_doc, "policy-gates") != null);
    try std.testing.expect(std.mem.indexOf(u8, mcp_doc, "observes and audits `tools/list`, `resources/list`, and `prompts/list`") != null);
}

test "phase25 Core facade is the shared CLI policy audit replay and redaction surface" {
    try std.testing.expect(@hasDecl(ryk, "core_api"));

    var selected = try ryk.core_api.parsePolicyFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: ci
        \\commands:
        \\  ask:
        \\    - "npm install *"
    , "phase25-core-api.yaml");
    defer selected.deinit();

    var evaluation = try ryk.core_api.evaluateAction(
        std.testing.allocator,
        selected,
        .{ .command_exec = .{ .argv = &.{ "npm", "install", "left-pad" } } },
        .{},
    );
    defer evaluation.deinit(std.testing.allocator);

    try std.testing.expectEqual(ryk.core_api.DecisionResult.deny, evaluation.decision.result);
    const redacted = ryk.core_api.redactString("OPENAI_API_KEY=sk-fakeSyntheticOpenAIKey1234567890");
    try std.testing.expect(std.mem.indexOf(u8, redacted, "sk-fakeSynthetic") == null);
}

test "phase25 active contracts use canonical ryk identity" {
    const schema_paths = [_][]const u8{
        "integrations/common/schemas/hook-request-v1.json",
        "integrations/common/schemas/hook-response-v1.json",
        "integrations/common/schemas/host-capabilities-v1.json",
        "integrations/common/schemas/host-decision-mapping-v1.json",
    };
    for (schema_paths) |path| {
        const schema = try readFile(std.testing.allocator, path);
        defer std.testing.allocator.free(schema);
        try std.testing.expect(std.mem.indexOf(u8, schema, "https://ryk.local/schemas/") != null);
        try std.testing.expect(std.mem.indexOf(u8, schema, "https://orca.local") == null);
    }

    const capabilities = try readFile(std.testing.allocator, "integrations/common/schemas/host-capabilities-v1.json");
    defer std.testing.allocator.free(capabilities);
    try std.testing.expect(std.mem.indexOf(u8, capabilities, "\"ryk_version\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, capabilities, "\"orca_version\"") == null);

    const response = try readFile(std.testing.allocator, "integrations/common/schemas/ryk-plugin-response-v1.json");
    defer std.testing.allocator.free(response);
    try std.testing.expect(std.mem.indexOf(u8, response, "\"ryk_version\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "\"orca_version\"") == null);

    const hook_response = try readFile(std.testing.allocator, "integrations/common/schemas/hook-response-v1.json");
    defer std.testing.allocator.free(hook_response);
    try std.testing.expect(std.mem.indexOf(u8, hook_response, "\"rule\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, hook_response, "\"rule_id\"") != null);

    const hermes_mapping = try readFile(std.testing.allocator, "integrations/common/schemas/examples/hermes-decision-mapping-v1.json");
    defer std.testing.allocator.free(hermes_mapping);
    try std.testing.expect(std.mem.indexOf(u8, hermes_mapping, "rule_key ryk|") != null);
    try std.testing.expect(std.mem.indexOf(u8, hermes_mapping, "rule_key orca|") == null);

    const evidence = try readFile(std.testing.allocator, "src/sandbox/evidence.zig");
    defer std.testing.allocator.free(evidence);
    try std.testing.expect(std.mem.indexOf(u8, evidence, "ryk_run_os_sandbox_on_active") != null);
    try std.testing.expect(std.mem.indexOf(u8, evidence, "orca_run_os_sandbox_on_active") == null);
}

test "tests tree has no phase-sprint filenames" {
    var dir = try std.Io.Dir.cwd().openDir(std.testing.io, "tests", .{ .iterate = true });
    defer dir.close(std.testing.io);
    var it = dir.iterate();
    while (try it.next(std.testing.io)) |entry| {
        if (std.mem.startsWith(u8, entry.name, "phase") and std.mem.endsWith(u8, entry.name, ".zig")) {
            std.debug.print("phase-sprint filename still present: {s}\n", .{entry.name});
            return error.PhaseSprintFilenameFound;
        }
    }
}

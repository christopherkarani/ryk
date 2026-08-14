const std = @import("std");
const ryk_core = @import("ryk_core");

test "core package root exposes curated boundary only" {
    try expectNoDecl(ryk_core, "phase");
    try std.testing.expect(@hasDecl(ryk_core, "api"));
    try expectNoDecl(ryk_core, "abi");

    // Product code needs access to the internal module graph for CLI and intercept
    try std.testing.expect(@hasDecl(ryk_core, "core"));
    try std.testing.expect(@hasDecl(ryk_core, "policy"));
    try std.testing.expect(@hasDecl(ryk_core, "audit"));

    try expectNoDecl(ryk_core, "intercept");
    try expectNoDecl(ryk_core, "redteam");
    try expectNoDecl(ryk_core, "capabilities");
    try expectNoDecl(ryk_core, "schemas");
    try expectNoDecl(ryk_core, "cli");
    try expectNoDecl(ryk_core, "mcp");
    try expectNoDecl(ryk_core, "sandbox");
    try expectNoDecl(ryk_core, "edge");
}

test "core package sources do not import the monolithic product facade" {
    try expectFileDoesNotContain("packages/core/src/root.zig", "@import(\"aegis\")");
}

test "core engine module graph stays within core policy and audit" {
    try expectFileDoesNotContain("src/core_engine.zig", "intercept");
    try expectFileDoesNotContain("src/core_engine.zig", "redteam");
    try expectFileDoesNotContain("src/policy/evaluate.zig", "../intercept/");
    try expectFileDoesNotContain("src/core/boundary_api.zig", "@import(\"aegis\")");
}

test "core README does not advertise removed placeholder exports" {
    try expectFileNotContains("packages/core/README.md", "placeholder exports");
    try expectFileNotContains("packages/core/README.md", "reserved exports");
    try expectFileNotContains("packages/core/README.md", "safety-report placeholders");
}

test "public Policy handle is opaque and does not expose storage pointers" {
    try std.testing.expect(@typeInfo(ryk_core.api.Policy) == .@"opaque");
}

test "extension audit targets preserve extension kind in core events" {
    const ts = ryk_core.api.Timestamp.fromUnixSeconds(1_777_983_130);
    const event = try ryk_core.api.createAuditEvent(.{
        .session_id = try ryk_core.api.generateSessionId(ts),
        .event_id = try ryk_core.api.generateEventId(ts),
        .timestamp = ts,
        .event_type = .command_attempt,
        .actor = .{ .kind = .core, .display = "ryk-core" },
        .target = .{ .kind = .extension, .value = "custom.inventory_read/resource-1" },
    });
    try std.testing.expectEqualStrings("extension", @tagName(event.target.kind));
}

test "core public actions are product neutral" {
    try std.testing.expect(@hasDecl(ryk_core.api, "Action"));
    const info = @typeInfo(ryk_core.api.Action).@"union";

    try expectUnionField(info, "env_read");
    try expectUnionField(info, "file_read");
    try expectUnionField(info, "file_write");
    try expectUnionField(info, "command_exec");
    try expectUnionField(info, "network_connect");
    try expectUnionField(info, "approval_decision");
    try expectUnionField(info, "staging_decision");
    try expectUnionField(info, "extension");

    try expectUnionField(info, "mcp_tool_call");
    try expectNoUnionField(info, "mcp_resource_read");
    try expectNoUnionField(info, "mcp_prompt_get");
    try expectNoUnionField(info, "mcp_sampling_request");
}

test "core public event names expose current stable events" {
    try std.testing.expect(@hasDecl(ryk_core.api, "EventType"));
    try expectEnumField(ryk_core.api.EventType, "session_start");
    try expectEnumField(ryk_core.api.EventType, "command_attempt");
    try expectEnumField(ryk_core.api.EventType, "network_connect_denied");
}

test "core public API omits host plugin presets and direct MCP evaluator surface" {
    try expectNoDecl(ryk_core.api, "AgentPreset");
    try expectNoDecl(ryk_core.api, "loadAgentPreset");
    // ExplainKind and explainAction exposed for CLI decide command
    try std.testing.expect(@hasDecl(ryk_core.api, "ExplainKind"));
    try std.testing.expect(@hasDecl(ryk_core.api, "explainAction"));
    try expectNoDecl(ryk_core.api, "mcp");
    try expectNoDecl(ryk_core.api, "MCPPolicy");
}

test "core API evaluates generic command and extension actions" {
    var selected = try ryk_core.api.parsePolicyFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: observe
        \\commands:
        \\  allow:
        \\    - "echo *"
    , "core-boundary-policy.yaml");
    defer selected.deinit();

    var command_eval = try ryk_core.api.evaluateAction(
        std.testing.allocator,
        selected,
        .{ .command_exec = .{ .argv = &.{ "echo", "hello" } } },
        .{},
    );
    defer command_eval.deinit(std.testing.allocator);
    try std.testing.expectEqual(ryk_core.api.DecisionResult.allow, command_eval.decision.result);

    var extension_eval = try ryk_core.api.evaluateAction(
        std.testing.allocator,
        selected,
        .{ .extension = .{ .domain = "custom", .operation = "inventory_read", .target = "resource-1" } },
        .{},
    );
    defer extension_eval.deinit(std.testing.allocator);
    try std.testing.expectEqual(ryk_core.api.DecisionResult.observe, extension_eval.decision.result);
    try std.testing.expect(std.mem.indexOf(u8, extension_eval.explanation, "extension custom.inventory_read") != null);
}

test "core API preserves deny priority through policy evaluation" {
    var selected = try ryk_core.api.parsePolicyFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\files:
        \\  read:
        \\    allow:
        \\      - "**"
        \\    deny:
        \\      - "secrets/**"
    , "phase23-core-test.yaml");
    defer selected.deinit();

    var evaluation = try ryk_core.api.evaluateAction(std.testing.allocator, selected, .{ .file_read = .{ .path = .{ .kind = .relative, .raw = "secrets/token.txt" } } }, .{});
    defer evaluation.deinit(std.testing.allocator);

    try std.testing.expectEqual(ryk_core.api.DecisionResult.deny, evaluation.decision.result);
}

test "core API keeps CI non-interactive and deny beats allow" {
    var selected = try ryk_core.api.parsePolicyFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\commands:
        \\  allow:
        \\    - "rm *"
        \\  deny:
        \\    - "rm -rf *"
        \\  ask:
        \\    - "deploy *"
    , "phase24-ci.yaml");
    defer selected.deinit();

    var deny_eval = try ryk_core.api.evaluateAction(std.testing.allocator, selected, .{ .command_exec = .{ .argv = &.{ "rm", "-rf", "tmp" } } }, .{});
    defer deny_eval.deinit(std.testing.allocator);
    try std.testing.expectEqual(ryk_core.api.DecisionResult.deny, deny_eval.decision.result);

    var ci_eval = try ryk_core.api.evaluateAction(std.testing.allocator, selected, .{ .command_exec = .{ .argv = &.{ "deploy", "prod" } } }, .{ .mode = .ci });
    defer ci_eval.deinit(std.testing.allocator);
    try std.testing.expectEqual(ryk_core.api.DecisionResult.deny, ci_eval.decision.result);
    try std.testing.expect(!ci_eval.decision.requires_user);
    try std.testing.expect(!ci_eval.decision.ci_may_proceed);
}

test "core API writes redacted audit events and verifies replay hash chain" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const ts = ryk_core.api.Timestamp.fromUnixSeconds(1_777_983_130);
    const session: ryk_core.api.Session = .{
        .id = try ryk_core.api.generateSessionId(ts),
        .started_at = ts,
        .command = "echo",
        .args = &.{"fake_secret_value_phase24"},
        .workspace_root = root,
        .mode = .observe,
        .platform = ryk_core.api.detectOs(),
    };

    var writer = try ryk_core.api.createAuditWriter(std.testing.io, std.testing.allocator, session);
    defer writer.deinit();
    const ev = try ryk_core.api.createAuditEvent(.{
        .session_id = session.id,
        .event_id = try ryk_core.api.generateEventId(ts),
        .timestamp = ts,
        .event_type = .command_attempt,
        .actor = .{ .kind = .core, .display = "ryk-core" },
        .target = .{ .kind = .command, .value = "echo fake_secret_value_phase24" },
        .decision = ryk_core.api.makeDecision(.{
            .result = .deny,
            .reason = "blocked fake_secret_value_phase24 before persistence",
        }),
    });
    try ryk_core.api.appendAuditEvent(&writer, ev);
    try writer.writeLastPointer();
    try ryk_core.api.writeAuditSummary(std.testing.allocator, writer.sessionDirPath(), .{
        .session = session,
        .status = .{ .exited = 1 },
        .event_count = writer.event_count,
        .final_event_hash = writer.finalHash().?,
        .policy = "phase24 fake_secret_value_phase24 policy",
    });

    var verify = try ryk_core.api.verifyReplay(std.testing.io, std.testing.allocator, writer.sessionDirPath());
    defer verify.deinit(std.testing.allocator);
    try std.testing.expect(verify.ok);

    const events_path = try std.fs.path.join(std.testing.allocator, &.{ ".ryk", "sessions", session.id.slice(), "events.jsonl" });
    defer std.testing.allocator.free(events_path);
    const events = try tmp.dir.readFileAlloc(std.testing.io, events_path, std.testing.allocator, .limited(16 * 1024));
    defer std.testing.allocator.free(events);
    try std.testing.expect(std.mem.indexOf(u8, events, "fake_secret_value_phase24") == null);
    try std.testing.expect(std.mem.indexOf(u8, events, "[REDACTED") != null);

    var replay = try ryk_core.api.loadReplay(std.testing.io, std.testing.allocator, root, .{ .session = session.id.slice(), .verify = true });
    defer replay.deinit();
    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer aw.deinit();
    try ryk_core.api.writeReplayJson(&aw.writer, replay);
    const replay_json = aw.written();
    try std.testing.expect(std.mem.indexOf(u8, replay_json, "fake_secret_value_phase24") == null);
    try std.testing.expect(std.mem.indexOf(u8, replay_json, "[REDACTED") != null);
}

test "cli compatibility facade dead code has been removed" {
    const compat_source = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, "build.zig", std.testing.allocator, .limited(256 * 1024));
    defer std.testing.allocator.free(compat_source);
    try std.testing.expect(std.mem.indexOf(u8, compat_source, "aegis_core_product_compat_mod") == null);
    try std.testing.expect(std.mem.indexOf(u8, compat_source, "pub const actions = core.types") == null);
}

test "core redaction smoke keeps secret substring absent" {
    const raw = "OPENAI_API_KEY=fake_secret_value_phase24";
    var buffer: [256]u8 = undefined;
    const redacted = ryk_core.api.redactStringBounded(raw, &buffer);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "fake_secret_value_phase24") == null);
}

fn expectNoDecl(comptime namespace: type, comptime name: []const u8) !void {
    try std.testing.expect(!@hasDecl(namespace, name));
}

fn expectFileDoesNotContain(path: []const u8, needle: []const u8) !void {
    const text = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, std.testing.allocator, .limited(128 * 1024));
    defer std.testing.allocator.free(text);
    try std.testing.expect(std.mem.indexOf(u8, text, needle) == null);
}

fn expectUnionField(info: std.builtin.Type.Union, comptime name: []const u8) !void {
    inline for (info.fields) |field| {
        if (std.mem.eql(u8, field.name, name)) return;
    }
    return error.TestUnexpectedResult;
}

fn expectNoUnionField(info: std.builtin.Type.Union, comptime name: []const u8) !void {
    inline for (info.fields) |field| {
        if (std.mem.eql(u8, field.name, name)) return error.TestUnexpectedResult;
    }
}

fn expectEnumField(comptime Enum: type, comptime name: []const u8) !void {
    const fields = @typeInfo(Enum).@"enum".fields;
    inline for (fields) |field| {
        if (std.mem.eql(u8, field.name, name)) return;
    }
    return error.TestUnexpectedResult;
}

fn expectFileNotContains(path: []const u8, needle: []const u8) !void {
    const text = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, std.testing.allocator, .limited(256 * 1024));
    defer std.testing.allocator.free(text);
    try std.testing.expect(std.mem.indexOf(u8, text, needle) == null);
}

const fake_secret = "fake_secret_value_phase23";

test "phase 23 fake secret guardrail covers redaction before durable strings" {
    var buffer: [256]u8 = undefined;
    const redacted = ryk_core.api.redactStringBounded("OPENAI_API_KEY=" ++ fake_secret, &buffer);

    try std.testing.expect(std.mem.indexOf(u8, redacted, fake_secret) == null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "[REDACTED") != null);
}

test "policy schema matches runtime file-write and MCP server-scoped policy shapes" {
    const text = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, "schemas/policy-v1.json", std.testing.allocator, .limited(128 * 1024));
    defer std.testing.allocator.free(text);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, text, .{});
    defer parsed.deinit();

    const root = parsed.value.object;
    const properties = root.get("properties").?.object;
    const files_properties = properties.get("files").?.object.get("properties").?.object;
    try std.testing.expect(files_properties.get("write_mode") == null);

    const defs = root.get("$defs").?.object;
    const file_write_properties = defs.get("fileWriteRuleSet").?.object.get("properties").?.object;
    try std.testing.expect(file_write_properties.get("mode") != null);

    const mcp_properties = defs.get("mcpPolicy").?.object.get("properties").?.object;
    const servers = mcp_properties.get("servers").?.object;
    const server_properties = servers.get("additionalProperties").?.object.get("properties").?.object;
    try std.testing.expect(server_properties.get("tools") != null);

    const policy_load = ryk_core.policy.load;
    const policy_schema = ryk_core.policy.schema;
    var policy = try policy_load.parseFromSlice(std.testing.allocator,
        \\{"version":1,"mode":"strict","files":{"write":{"mode":"direct","allow":["docs/**"]}},"mcp":{"servers":{"github":{"tools":{"allow":["search_repositories"]}}}}}
    , "schema-alignment.json");
    defer policy.deinit();
    try std.testing.expectEqual(policy_schema.WriteMode.direct, policy.files.write_mode);
    try std.testing.expectEqualStrings("github.search_repositories", policy.mcp.allow[0]);
}

test "MCP manifest schema decision and risk enums match manifest parser behavior" {
    const text = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, "schemas/mcp-manifest-v1.json", std.testing.allocator, .limited(128 * 1024));
    defer std.testing.allocator.free(text);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, text, .{});
    defer parsed.deinit();

    const root = parsed.value.object;
    const defs = root.get("$defs").?.object;
    const decision_enum = defs.get("enforcingDecision").?.object.get("enum").?.array.items;
    try expectJsonStringInEnum(decision_enum, "allow");
    try expectJsonStringInEnum(decision_enum, "deny");
    try expectJsonStringInEnum(decision_enum, "ask");
    try expectJsonStringNotInEnum(decision_enum, "observe");

    const properties = root.get("properties").?.object;
    const server_schema = properties.get("server").?.object;
    const server_required = server_schema.get("required").?.array.items;
    try expectJsonStringInEnum(server_required, "name");
    try expectJsonStringInEnum(server_required, "transport");
    try expectJsonStringNotInEnum(server_required, "command");
    const server_properties = server_schema.get("properties").?.object;
    const transport_enum = server_properties.get("transport").?.object.get("enum").?.array.items;
    try expectJsonStringInEnum(transport_enum, "stdio");
    try expectJsonStringNotInEnum(transport_enum, "http");

    const tools_schema = properties.get("tools").?.object.get("additionalProperties").?.object;
    const tool_properties = tools_schema.get("properties").?.object;
    const risk_enum = tool_properties.get("risk").?.object.get("enum").?.array.items;
    try expectJsonStringInEnum(risk_enum, "unknown");
    try std.testing.expectEqualStrings("#/$defs/enforcingDecision", tool_properties.get("default").?.object.get("$ref").?.string);
}

fn expectJsonStringInEnum(items: []const std.json.Value, expected: []const u8) !void {
    for (items) |item| {
        if (item == .string and std.mem.eql(u8, item.string, expected)) return;
    }
    return error.TestUnexpectedResult;
}

fn expectJsonStringNotInEnum(items: []const std.json.Value, forbidden: []const u8) !void {
    for (items) |item| {
        if (item == .string and std.mem.eql(u8, item.string, forbidden)) return error.TestUnexpectedResult;
    }
}

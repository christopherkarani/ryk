const std = @import("std");

const evaluate = @import("evaluate.zig");
const effects = @import("effects/mod.zig");
const schema = @import("schema.zig");

pub const ExplainKind = enum {
    file_read,
    file_write,
    env,
    command,
    network,
    mcp,
    /// Host/MCP tool call by name (MCP selector ∩ effect-class rules).
    tool,

    pub fn parse(value: []const u8) ?ExplainKind {
        if (std.mem.eql(u8, value, "file.read")) return .file_read;
        if (std.mem.eql(u8, value, "file.write")) return .file_write;
        if (std.mem.eql(u8, value, "env")) return .env;
        if (std.mem.eql(u8, value, "command")) return .command;
        if (std.mem.eql(u8, value, "network")) return .network;
        if (std.mem.eql(u8, value, "mcp")) return .mcp;
        if (std.mem.eql(u8, value, "tool")) return .tool;
        return null;
    }
};

pub fn explain(
    allocator: std.mem.Allocator,
    policy: *const schema.Policy,
    kind: ExplainKind,
    target: []const u8,
) !schema.Evaluation {
    return explainWithOptions(allocator, policy, kind, target, .{});
}

pub const ExplainOptions = struct {
    network_method: ?[]const u8 = null,
    /// Optional structural tool args for `.tool` explain (Phase B).
    tool_args: ?effects.ToolArgsView = null,
    /// Optional user effect packs for `.tool` explain (Phase C).
    effect_packs: ?*const effects.PackSet = null,
};

pub fn explainWithOptions(
    allocator: std.mem.Allocator,
    policy: *const schema.Policy,
    kind: ExplainKind,
    target: []const u8,
    options: ExplainOptions,
) !schema.Evaluation {
    return switch (kind) {
        .file_read => evaluate.fileRead(policy, target, allocator),
        .file_write => evaluate.fileWrite(policy, target, allocator),
        .env => evaluate.env(policy, target, allocator),
        .command => evaluate.command(policy, target, allocator),
        .network => if (options.network_method) |method| evaluate.networkWithMethod(policy, target, method, allocator) else evaluate.network(policy, target, allocator),
        .mcp => evaluate.mcp(policy, target, allocator),
        .tool => evaluate.toolWithPacks(policy, target, options.tool_args, options.effect_packs, allocator),
    };
}

pub fn write(writer: anytype, policy: *const schema.Policy, evaluation: schema.Evaluation) !void {
    try writer.print("Decision: {s}\n", .{evaluation.decision.result.toString()});
    try writer.print("Reason: {s}\n", .{evaluation.decision.reason});
    if (evaluation.matched_rule) |rule| {
        try writer.print("Rule: {s}\n", .{rule.id});
        try writer.print("Matched: \"{s}\"\n", .{rule.pattern});
    } else {
        try writer.writeAll("Rule: none\n");
    }
    try writer.print("Mode: {s}\n", .{policy.mode.toString()});
}

test "file.read /etc/passwd is deny under default workspace allow" {
    const load = @import("load.zig");
    var policy = try load.loadPreset(std.testing.allocator, .strict);
    defer policy.deinit();

    const result = try explain(std.testing.allocator, &policy, .file_read, "/etc/passwd");
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(result.decision.result == .deny);
    try std.testing.expect(std.mem.indexOf(u8, result.decision.rule_id orelse "", "files.read.allow") == null);
}

test "explanation includes matched rule where possible" {
    const load = @import("load.zig");
    var policy = try load.loadPreset(std.testing.allocator, .strict);
    defer policy.deinit();

    const result = try explain(std.testing.allocator, &policy, .file_read, "~/.ssh/id_ed25519");
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("files.read.deny[2]", result.matched_rule.?.id);
    var buf: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try write(&writer, &policy, result);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "Decision: deny") != null);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "Rule: files.read.deny[2]") != null);
}

test "network explanation includes service-aware path rules" {
    const load = @import("load.zig");
    var policy = try load.parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\services:
        \\  github:
        \\    hosts:
        \\      - "api.github.com"
        \\    methods:
        \\      - "GET"
        \\    paths:
        \\      allow:
        \\        - "/repos/*/issues"
        \\      deny:
        \\        - "/user/keys"
        \\    credentials:
        \\      use: github_pat
        \\    unmatched: deny
    , "services.yaml");
    defer policy.deinit();

    const denied = try explain(std.testing.allocator, &policy, .network, "https://api.github.com/user/keys");
    defer denied.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("services.github.unmatched", denied.matched_rule.?.id);
    try std.testing.expectEqual(@import("../core/public.zig").decision.DecisionResult.deny, denied.decision.result);
    try std.testing.expect(std.mem.indexOf(u8, denied.decision.reason, "method context required") != null);

    const method_denied = try explainWithOptions(std.testing.allocator, &policy, .network, "https://api.github.com/user/keys", .{ .network_method = "GET" });
    defer method_denied.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("services.github.paths.deny[0]", method_denied.matched_rule.?.id);
}

test "tool explain with structural args denies notify under effects" {
    const load = @import("load.zig");
    var policy = try load.parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\mcp:
        \\  default: allow
        \\effects:
        \\  deny:
        \\    - comms.message
    , "explain-structural.yaml");
    defer policy.deinit();

    const keys = [_][]const u8{ "to", "body" };
    const denied = try explainWithOptions(std.testing.allocator, &policy, .tool, "notify", .{
        .tool_args = .{ .keys = &keys },
    });
    defer denied.deinit(std.testing.allocator);
    try std.testing.expectEqual(@import("../core/public.zig").decision.DecisionResult.deny, denied.decision.result);
    try std.testing.expect(std.mem.indexOf(u8, denied.decision.reason, "structural.") != null);
}

test "network explain under effects deny publish tags twitter" {
    const load = @import("load.zig");
    var policy = try load.parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\network:
        \\  mode: open
        \\  default: allow
        \\effects:
        \\  deny:
        \\    - comms.publish
    , "explain-net.yaml");
    defer policy.deinit();

    const denied = try explain(std.testing.allocator, &policy, .network, "https://api.twitter.com/2/tweets");
    defer denied.deinit(std.testing.allocator);
    try std.testing.expectEqual(@import("../core/public.zig").decision.DecisionResult.deny, denied.decision.result);
    try std.testing.expect(std.mem.indexOf(u8, denied.decision.reason, "network_tag.") != null or
        std.mem.indexOf(u8, denied.decision.reason, "comms.publish") != null);
}

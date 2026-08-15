//! Discovery CLI for effect-class classification (Phase C).
//! `ryk tools classify` and `ryk tools packs` — not shell `ryk classify`.

const std = @import("std");
const gpa_mod = @import("gpa.zig");
const policy_mod = @import("ryk_core").policy;
const core = @import("ryk_core").core;
const supervisor = core.supervisor;
const exit_codes = @import("exit_codes.zig");
const help = @import("help.zig");
const suggestions = @import("suggestions.zig");

const max_args_json_bytes: usize = 8 * 1024;

pub fn command(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    if (argv.len > 0 and (std.mem.eql(u8, argv[0], "--help") or std.mem.eql(u8, argv[0], "-h"))) {
        _ = try help.writeCommand(io, stdout, "tools");
        return exit_codes.success;
    }
    if (argv.len == 0) {
        _ = try help.writeCommand(io, stdout, "tools");
        return exit_codes.success;
    }
    if (std.mem.eql(u8, argv[0], "classify")) return classify(io, argv[1..], stdout, stderr);
    if (std.mem.eql(u8, argv[0], "packs")) return listPacks(io, argv[1..], stdout, stderr);
    try suggestions.writeUnknownSubcommand(stderr, "ryk tools", argv[0], &.{ "classify", "packs" }, "tools");
    return exit_codes.usage;
}

fn classify(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    if (argv.len > 0 and (std.mem.eql(u8, argv[0], "--help") or std.mem.eql(u8, argv[0], "-h"))) {
        try stdout.writeAll(
            \\Usage:
            \\  ryk tools classify <tool-name> [--args '<json-object>'] [--policy <path>]
            \\
            \\Classify a tool name (and optional args) into effect hits.
            \\With --policy, also print the policy decision when effects: is configured.
            \\Never prints raw argument values.
            \\
        );
        return exit_codes.success;
    }

    var gpa_state: gpa_mod.State = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();

    var tool_name: ?[]const u8 = null;
    var args_json: ?[]const u8 = null;
    var policy_path: ?[]const u8 = null;

    var i: usize = 0;
    while (i < argv.len) : (i += 1) {
        const arg = argv[i];
        if (std.mem.eql(u8, arg, "--args")) {
            i += 1;
            if (i >= argv.len) {
                try stderr.writeAll("ryk tools classify: --args requires a JSON object string.\n");
                return exit_codes.usage;
            }
            args_json = argv[i];
        } else if (std.mem.eql(u8, arg, "--policy")) {
            i += 1;
            if (i >= argv.len) {
                try stderr.writeAll("ryk tools classify: --policy requires a path.\n");
                return exit_codes.usage;
            }
            policy_path = argv[i];
        } else if (std.mem.startsWith(u8, arg, "--")) {
            try suggestions.writeUnknownOption(stderr, "ryk tools classify", arg, &.{ "--args", "--policy" }, "tools");
            return exit_codes.usage;
        } else if (tool_name == null) {
            tool_name = arg;
        } else {
            try stderr.writeAll("ryk tools classify: unexpected extra argument.\n");
            return exit_codes.usage;
        }
    }

    const name = tool_name orelse {
        try stderr.writeAll("ryk tools classify: expected a tool name.\n");
        return exit_codes.usage;
    };

    var owned_args: ?policy_mod.effects.OwnedArgsView = null;
    defer if (owned_args) |*oa| oa.deinit(allocator);
    if (args_json) |raw| {
        if (raw.len > max_args_json_bytes) {
            try stderr.writeAll("ryk tools classify: --args JSON too large (max 8KiB).\n");
            return exit_codes.usage;
        }
        var parsed_json = std.json.parseFromSlice(std.json.Value, allocator, raw, .{}) catch {
            try stderr.writeAll("ryk tools classify: --args must be a JSON object.\n");
            return exit_codes.usage;
        };
        defer parsed_json.deinit();
        if (parsed_json.value != .object) {
            try stderr.writeAll("ryk tools classify: --args must be a JSON object.\n");
            return exit_codes.usage;
        }
        owned_args = try policy_mod.effects.toolArgsViewFromJsonObject(allocator, parsed_json.value);
    }
    const args_view: ?policy_mod.effects.ToolArgsView = if (owned_args) |oa| oa.view else null;

    const root = supervisor.resolveWorkspaceRoot(io, allocator, null, ".") catch try allocator.dupe(u8, ".");
    defer allocator.free(root);

    var pack_set = policy_mod.effects.loadPacks(io, allocator, root, null) catch |err| {
        try stderr.print("ryk tools classify: invalid effect pack: {s}\n", .{@errorName(err)});
        return exit_codes.general;
    };
    defer pack_set.deinit();

    var classifier_enabled = false;
    var loaded_policy: ?policy_mod.schema.Policy = null;
    defer if (loaded_policy) |*p| p.deinit();

    if (policy_path) |path| {
        loaded_policy = policy_mod.load.loadFile(io, allocator, path) catch |err| {
            try stderr.print("ryk tools classify: failed to load policy {s}: {s}\n", .{ path, @errorName(err) });
            return exit_codes.general;
        };
        if (loaded_policy.?.effects.isActive()) {
            classifier_enabled = loaded_policy.?.effects.classifier.isEnabled();
        }
    }

    const classified = try policy_mod.effects.classifyToolCallWithResidual(allocator, &pack_set, name, args_view, classifier_enabled);
    defer classified.deinit(allocator);
    if (classified.unavailable) {
        try stderr.writeAll("ryk tools classify: effects.classifier unavailable\n");
        return exit_codes.general;
    }
    try policy_mod.effects.writeHitsHuman(stdout, classified.hits);

    if (loaded_policy) |*loaded| {
        var evaluation = try policy_mod.evaluate.toolWithPacks(loaded, name, args_view, &pack_set, allocator);
        defer evaluation.deinit(allocator);
        try stdout.print("Policy decision: {s}", .{evaluation.decision.result.toString()});
        if (evaluation.decision.rule_id) |rule_id| try stdout.print("  rule: {s}", .{rule_id});
        try stdout.writeAll("\n");
        if (evaluation.decision.reason.len > 0) {
            try stdout.print("Reason: {s}\n", .{evaluation.decision.reason});
        }
    }

    return exit_codes.success;
}

fn listPacks(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    if (argv.len > 0 and (std.mem.eql(u8, argv[0], "--help") or std.mem.eql(u8, argv[0], "-h"))) {
        try stdout.writeAll(
            \\Usage:
            \\  ryk tools packs
            \\
            \\List loaded user effect pack ids and source paths.
            \\Search order: ~/.config/ryk/effect-packs then .ryk/effect-packs
            \\
        );
        return exit_codes.success;
    }
    if (argv.len > 0) {
        try stderr.writeAll("ryk tools packs: unexpected arguments.\n");
        return exit_codes.usage;
    }

    var gpa_state: gpa_mod.State = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();

    const root = supervisor.resolveWorkspaceRoot(io, allocator, null, ".") catch try allocator.dupe(u8, ".");
    defer allocator.free(root);

    var pack_set = policy_mod.effects.loadPacks(io, allocator, root, null) catch |err| {
        try stderr.print("ryk tools packs: invalid effect pack: {s}\n", .{@errorName(err)});
        return exit_codes.general;
    };
    defer pack_set.deinit();

    if (pack_set.isEmpty()) {
        try stdout.writeAll("Effect packs: (none)\n");
        try stdout.writeAll("  Looked in: <user-config>/ryk/effect-packs and .ryk/effect-packs\n");
        return exit_codes.success;
    }
    try stdout.writeAll("Effect packs:\n");
    for (pack_set.packs) |pack| {
        try stdout.print("  {s}  {s}\n", .{ pack.id, pack.path });
    }
    return exit_codes.success;
}

test "tools classify send_email catalog hit" {
    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const code = try command(std.testing.io, &.{ "classify", "send_email" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    const out = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "comms.message") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "catalog.") != null);
}

test "tools classify notify structural without secret leak" {
    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const code = try command(
        std.testing.io,
        &.{ "classify", "notify", "--args", "{\"to\":\"a@b.com\",\"body\":\"SECRET_BODY_VALUE\"}" },
        &stdout_writer,
        &stderr_writer,
    );
    try std.testing.expectEqual(exit_codes.success, code);
    const out = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "comms.message") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "structural.") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "SECRET_BODY_VALUE") == null);
}

test "tools classify with policy effects deny" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        const file = try tmp.dir.createFile(std.testing.io, "effects.yaml", .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io,
            \\version: 1
            \\mode: strict
            \\mcp:
            \\  default: allow
            \\effects:
            \\  deny:
            \\    - comms.message
        );
    }
    const policy_path = try tmp.dir.realPathFileAlloc(std.testing.io, "effects.yaml", std.testing.allocator);
    defer std.testing.allocator.free(policy_path);

    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const code = try command(
        std.testing.io,
        &.{ "classify", "send_email", "--policy", policy_path },
        &stdout_writer,
        &stderr_writer,
    );
    try std.testing.expectEqual(exit_codes.success, code);
    const out = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "comms.message") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Policy decision: deny") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "effects.") != null);
}

test "tools classify residual with classifier local policy" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        const file = try tmp.dir.createFile(std.testing.io, "residual.yaml", .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io,
            \\version: 1
            \\mode: strict
            \\mcp:
            \\  default: allow
            \\effects:
            \\  classifier: local
            \\  deny:
            \\    - comms.message
        );
    }
    const policy_path = try tmp.dir.realPathFileAlloc(std.testing.io, "residual.yaml", std.testing.allocator);
    defer std.testing.allocator.free(policy_path);

    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const code = try command(
        std.testing.io,
        &.{ "classify", "acme_mailer_job", "--policy", policy_path },
        &stdout_writer,
        &stderr_writer,
    );
    try std.testing.expectEqual(exit_codes.success, code);
    const out = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "classifier.local.") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "comms.message") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Policy decision: deny") != null);
}

// M-1: agent-controlled arg keys/values must not demote residual family to unknown.external
// (family-specific deny would fail open under default allow).
test "tools classify residual denies acme_mailer_job despite arg decoys" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        const file = try tmp.dir.createFile(std.testing.io, "residual-decoy.yaml", .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io,
            \\version: 1
            \\mode: strict
            \\mcp:
            \\  default: allow
            \\effects:
            \\  classifier: local
            \\  deny:
            \\    - comms.message
        );
    }
    const policy_path = try tmp.dir.realPathFileAlloc(std.testing.io, "residual-decoy.yaml", std.testing.allocator);
    defer std.testing.allocator.free(policy_path);

    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    // Decoy publish/money *string values* (and non-structural keys). Avoid structural
    // key-sets like bare `tweet` which would leave residual entirely (medium family hit).
    const decoy_args =
        \\{"a":"twitter","b":"publish","c":"linkedin","d":"mastodon","e":"stripe","f":"paypal","g":"billing","publisher":"x"}
    ;
    const code = try command(
        std.testing.io,
        &.{ "classify", "acme_mailer_job", "--args", decoy_args, "--policy", policy_path },
        &stdout_writer,
        &stderr_writer,
    );
    try std.testing.expectEqual(exit_codes.success, code);
    const out = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "comms.message") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Policy decision: deny") != null);
}

test "loadPacks classifies pack mapped tool" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, ".ryk/effect-packs");
    {
        const f = try tmp.dir.createFile(std.testing.io, ".ryk/effect-packs/acme.yaml", .{});
        defer f.close(std.testing.io);
        try f.writeStreamingAll(std.testing.io,
            \\version: 1
            \\id: acme
            \\names:
            \\  send_acme_ping: comms.message
        );
    }
    // Unit-level: workspace pack load + classify (not full CLI cwd resolution).
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var pack_set = try policy_mod.effects.loadPacks(std.testing.io, std.testing.allocator, root, null);
    defer pack_set.deinit();
    const hits = try policy_mod.effects.classifyToolCallWithPacks(std.testing.allocator, &pack_set, "send_acme_ping", null);
    defer std.testing.allocator.free(hits);
    try std.testing.expect(hits.len >= 1);
    var found_pack = false;
    for (hits) |h| {
        if (std.mem.eql(u8, h.id, "comms.message") and std.mem.startsWith(u8, h.matcher, "pack.acme.")) {
            found_pack = true;
            break;
        }
    }
    try std.testing.expect(found_pack);
}

test "tools classify bad args fails" {
    var stdout_buf: [256]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const code = try command(std.testing.io, &.{ "classify", "x", "--args", "not-json" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, code);
}

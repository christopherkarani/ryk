const std = @import("std");
const policy_mod = @import("ryk_core").policy;
const core = @import("ryk_core").core;
const supervisor = core.supervisor;
const core_api = @import("ryk_core").api;
const exit_codes = @import("exit_codes.zig");
const help = @import("help.zig");
const tui = @import("../tui/render.zig");
const suggestions = @import("suggestions.zig");
const onboarding = @import("onboarding.zig");

pub fn command(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    if (argv.len > 0 and (std.mem.eql(u8, argv[0], "--help") or std.mem.eql(u8, argv[0], "-h"))) {
        _ = try help.writeCommand(io, stdout, "policy");
        return exit_codes.success;
    }
    if (argv.len == 0) {
        _ = try help.writeCommand(io, stdout, "policy");
        return exit_codes.success;
    }

    if (std.mem.eql(u8, argv[0], "check")) return check(io, argv[1..], stdout, stderr);
    if (std.mem.eql(u8, argv[0], "explain")) return explain(io, argv[1..], stdout, stderr);
    if (std.mem.eql(u8, argv[0], "packs")) return packs(argv[1..], stdout, stderr);
    if (std.mem.eql(u8, argv[0], "apply-pack")) return applyPack(io, argv[1..], stdout, stderr);

    try suggestions.writeUnknownSubcommand(stderr, "ryk policy", argv[0], &.{ "check", "explain", "packs", "apply-pack" }, "policy");
    return exit_codes.usage;
}

fn check(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    var preset_name: ?[]const u8 = null;
    var path_arg: ?[]const u8 = null;
    var index: usize = 0;
    while (index < argv.len) : (index += 1) {
        const arg = argv[index];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            try stdout.writeAll(
                \\Usage:
                \\  ryk policy check
                \\  ryk policy check <policy-path>
                \\  ryk policy check --preset <observe|ask|strict|ci|redteam|trusted>
                \\  ryk policy check builtin:<preset>
                \\
                \\With no path, validates the workspace policy at .ryk/policy.yaml.
                \\Built-in presets require --preset or an explicit builtin:<name> path.
                \\
            );
            return exit_codes.success;
        }
        if (std.mem.eql(u8, arg, "--preset")) {
            index += 1;
            if (index >= argv.len) {
                try stderr.writeAll("ryk policy check: --preset requires a name.\n");
                return exit_codes.usage;
            }
            if (preset_name != null) {
                try stderr.writeAll("ryk policy check: --preset specified more than once.\n");
                return exit_codes.usage;
            }
            preset_name = argv[index];
            continue;
        }
        if (std.mem.startsWith(u8, arg, "-")) {
            try suggestions.writeUnknownOption(stderr, "ryk policy check", arg, &.{ "--preset", "--help", "-h" }, "policy");
            return exit_codes.usage;
        }
        if (path_arg != null) {
            try stderr.writeAll("ryk policy check: expected at most one policy path.\n");
            return exit_codes.usage;
        }
        path_arg = arg;
    }
    if (preset_name != null and path_arg != null) {
        try stderr.writeAll("ryk policy check: use either --preset or a policy path, not both.\n");
        return exit_codes.usage;
    }

    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();

    // Explicit builtin:name path form (same as --preset).
    if (path_arg) |raw| {
        if (std.mem.startsWith(u8, raw, "builtin:")) {
            preset_name = raw["builtin:".len..];
            path_arg = null;
        }
    }

    if (preset_name) |name| {
        const preset = policy_mod.presets.Preset.parse(name) orelse {
            try suggestions.writeInvalidValue(
                stderr,
                "ryk policy check",
                "--preset",
                name,
                &.{ "observe", "ask", "strict", "ci", "redteam", "trusted" },
                "policy",
            );
            return exit_codes.usage;
        };
        var policy_value = try core_api.loadPolicyPreset(allocator, preset);
        defer policy_value.deinit();
        try stdout.print("Policy OK: builtin:{s}\nMode: {s}\n", .{ @tagName(preset), policy_value.mode().toString() });
        return exit_codes.success;
    }

    // Explicit path, or workspace discovery — never silently validate builtin.
    var source_owned: ?[]u8 = null;
    defer if (source_owned) |p| allocator.free(p);
    const source: []const u8 = if (path_arg) |path| path else blk: {
        const workspace_root = supervisor.resolveWorkspaceRoot(io, allocator, null, ".") catch try allocator.dupe(u8, ".");
        defer allocator.free(workspace_root);
        const discovered = try onboarding.policyPath(allocator, workspace_root);
        if (!onboarding.policyExists(io, workspace_root)) {
            defer allocator.free(discovered);
            try stderr.print(
                "ryk policy check: no workspace policy at {s}\nRun `ryk init` to create one, or pass a path / --preset <name>.\n",
                .{discovered},
            );
            return exit_codes.general;
        }
        source_owned = discovered;
        break :blk discovered;
    };

    var policy_value = core_api.loadPolicyFile(io, allocator, source) catch |err| {
        try suggestions.writeSanitizedValue(stderr, "ryk policy check: invalid policy ", source, ": ");
        try stderr.print("{s}\n", .{@errorName(err)});
        return exit_codes.general;
    };
    defer policy_value.deinit();
    try stdout.print("Policy OK: {s}\nMode: {s}\n", .{ source, policy_value.mode().toString() });
    return exit_codes.success;
}

fn explain(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    if (argv.len == 1 and (std.mem.eql(u8, argv[0], "--help") or std.mem.eql(u8, argv[0], "-h"))) {
        try stdout.writeAll(
            \\Usage:
            \\  ryk policy explain [--policy <path>] <file.read|file.write|env|command|network|mcp|tool> <target> [--method <HTTP_METHOD>] [--args '<json-object>']
            \\
            \\  --args is only used for `tool` (structural effect classification). Size-bounded JSON object.
            \\
        );
        return exit_codes.success;
    }
    var policy_path: ?[]const u8 = null;
    var start_index: usize = 0;
    while (start_index < argv.len and std.mem.startsWith(u8, argv[start_index], "--")) : (start_index += 1) {
        if (std.mem.eql(u8, argv[start_index], "--policy")) {
            start_index += 1;
            if (start_index >= argv.len) {
                try stderr.writeAll("ryk policy explain: --policy requires a path.\n");
                return exit_codes.usage;
            }
            policy_path = argv[start_index];
        } else {
            break;
        }
    }
    const positional = argv[start_index..];
    if (positional.len < 2) {
        try stderr.writeAll("ryk policy explain: expected a type and target.\n");
        return exit_codes.usage;
    }
    const kind = policy_mod.explain.ExplainKind.parse(positional[0]) orelse {
        try suggestions.writeSanitizedValue(stderr, "ryk policy explain: unsupported type '", positional[0], "'.\n");
        return exit_codes.usage;
    };
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();

    const parsed_target = try parseExplainTarget(allocator, kind, positional[1..], stderr);
    defer parsed_target.deinit(allocator);
    if (parsed_target.invalid) return exit_codes.usage;

    const root = supervisor.resolveWorkspaceRoot(io, allocator, null, ".") catch try allocator.dupe(u8, ".");
    defer allocator.free(root);
    var loaded = core_api.discoverPolicy(io, allocator, policy_path, root) catch |err| {
        if (policy_path) |path| {
            try stderr.print("ryk policy explain: failed to load policy {s}: {s}\n", .{ path, @errorName(err) });
        } else {
            try stderr.print("ryk policy explain: failed to load policy: {s}\n", .{@errorName(err)});
        }
        return exit_codes.general;
    };
    defer loaded.deinit();

    var owned_args: ?policy_mod.effects.OwnedArgsView = null;
    defer if (owned_args) |*oa| oa.deinit(allocator);
    if (parsed_target.args_json) |args_json| {
        if (kind != .tool) {
            try stderr.writeAll("ryk policy explain: --args is only valid for tool explanations.\n");
            return exit_codes.usage;
        }
        if (args_json.len > 8 * 1024) {
            try stderr.writeAll("ryk policy explain: --args JSON too large (max 8KiB).\n");
            return exit_codes.usage;
        }
        var parsed_json = std.json.parseFromSlice(std.json.Value, allocator, args_json, .{}) catch {
            try stderr.writeAll("ryk policy explain: --args must be a JSON object.\n");
            return exit_codes.usage;
        };
        defer parsed_json.deinit();
        if (parsed_json.value != .object) {
            try stderr.writeAll("ryk policy explain: --args must be a JSON object.\n");
            return exit_codes.usage;
        }
        owned_args = try policy_mod.effects.toolArgsViewFromJsonObject(allocator, parsed_json.value);
    }
    const tool_args: ?policy_mod.effects.ToolArgsView = if (owned_args) |oa| oa.view else null;

    // Packs only affect `.tool` explain; skip I/O for command/network/file/mcp kinds.
    var effect_packs = policy_mod.effects.PackSet.empty(allocator);
    defer effect_packs.deinit();
    if (kind == .tool) {
        effect_packs = policy_mod.effects.loadPacksForEnforcement(
            io,
            allocator,
            root,
            loaded.innerPtr().effects.isActive(),
        ) catch |err| {
            try stderr.print("ryk policy explain: invalid effect pack: {s}\n", .{@errorName(err)});
            return exit_codes.general;
        };
    }

    const evaluation = core_api.explainActionWithOptions(allocator, loaded.policy, kind, parsed_target.target, .{
        .network_method = parsed_target.method,
        .tool_args = tool_args,
        .effect_packs = if (kind == .tool) &effect_packs else null,
    }) catch |err| {
        try stderr.print("ryk policy explain: failed to evaluate action: {s}\n", .{@errorName(err)});
        return exit_codes.general;
    };
    defer evaluation.deinit(allocator);

    try writePolicyExplanationHuman(io, allocator, stdout, loaded.policy, evaluation);
    return exit_codes.success;
}

fn writePolicyExplanationHuman(io: std.Io, allocator: std.mem.Allocator, stdout: anytype, policy_value: *const core_api.Policy, evaluation: core_api.Evaluation) !void {
    try stdout.writeAll("Decision  ");
    try tui.badge(io, stdout, switch (evaluation.decision.result) {
        .allow => .allow,
        .deny => .deny,
        .ask, .stage => .ask,
        .observe => .info,
        .redact => .warn,
        .broker => .neutral,
    });
    try stdout.writeAll("\n\n");

    const rule_id = if (evaluation.matched_rule) |rule| rule.id else "none";
    const matched = if (evaluation.matched_rule) |rule| rule.pattern else "none";
    try writePolicyDetailsPanel(io, allocator, stdout, evaluation.decision.reason, rule_id, matched, policy_value.mode().toString());
    if (evaluation.decision.risk_score) |score| {
        const risk_label = if (score <= 25) "low" else if (score <= 50) "medium" else if (score <= 75) "high" else "critical";
        try stdout.writeAll("  Risk  ");
        try tui.meter(io, stdout, @as(f32, @floatFromInt(score)) / 100.0, risk_label);
        try stdout.writeAll("\n");
    }
    try stdout.writeAll("Next: ryk help policy\n");
}

fn writePolicyDetailsPanel(io: std.Io, allocator: std.mem.Allocator, stdout: anytype, reason: []const u8, rule_id: []const u8, matched: []const u8, mode: []const u8) !void {
    const reason_line = try std.fmt.allocPrint(allocator, "Reason   {s}", .{reason});
    errdefer allocator.free(reason_line);
    const rule_line = try std.fmt.allocPrint(allocator, "Rule     {s}", .{rule_id});
    errdefer allocator.free(rule_line);
    const matched_line = try std.fmt.allocPrint(allocator, "Matched  {s}", .{matched});
    errdefer allocator.free(matched_line);
    const mode_line = try std.fmt.allocPrint(allocator, "Mode     {s}", .{mode});
    const detail_lines = [_][]u8{ reason_line, rule_line, matched_line, mode_line };
    defer for (detail_lines) |line| allocator.free(line);
    try tui.panel(io, stdout, "Decision details", &detail_lines);
}

const ExplainTarget = struct {
    target: []const u8 = "",
    method: ?[]const u8 = null,
    /// Borrowed argv slice for `--args` JSON (not owned).
    args_json: ?[]const u8 = null,
    invalid: bool = false,

    fn deinit(self: ExplainTarget, allocator: std.mem.Allocator) void {
        if (self.target.len > 0) allocator.free(self.target);
        if (self.method) |method| allocator.free(method);
    }
};

fn parseExplainTarget(allocator: std.mem.Allocator, kind: policy_mod.explain.ExplainKind, args: []const []const u8, stderr: anytype) !ExplainTarget {
    if (kind == .command) {
        // command may include trailing flags only after command text; keep simple: join all non-flag tokens
        // Strip trailing --args if present (not valid for command).
        return .{ .target = try joinArgs(allocator, args) };
    }
    if (kind == .tool) {
        return try parseToolExplainTarget(allocator, args, stderr);
    }
    if (kind != .network) {
        if (args.len != 1) return .{ .invalid = true };
        return .{ .target = try allocator.dupe(u8, args[0]) };
    }
    var target: ?[]const u8 = null;
    var method: ?[]const u8 = null;
    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const arg = args[index];
        if (std.mem.eql(u8, arg, "--method")) {
            index += 1;
            if (index >= args.len) {
                try stderr.writeAll("ryk policy explain: --method requires an HTTP method.\n");
                return .{ .invalid = true };
            }
            if (method) |old| allocator.free(old);
            method = try allocator.dupe(u8, args[index]);
        } else if (std.mem.startsWith(u8, arg, "-")) {
            try suggestions.writeUnknownOption(stderr, "ryk policy explain", arg, &.{"--method"}, "policy");
            if (target) |owned| allocator.free(owned);
            if (method) |owned| allocator.free(owned);
            return .{ .invalid = true };
        } else {
            if (target != null) {
                try stderr.writeAll("ryk policy explain: expected one network target.\n");
                if (target) |owned| allocator.free(owned);
                if (method) |owned| allocator.free(owned);
                return .{ .invalid = true };
            }
            target = try allocator.dupe(u8, arg);
        }
    }
    if (target == null) {
        try stderr.writeAll("ryk policy explain: expected a network target.\n");
        if (method) |owned| allocator.free(owned);
        return .{ .invalid = true };
    }
    return .{ .target = target.?, .method = method };
}

fn parseToolExplainTarget(allocator: std.mem.Allocator, args: []const []const u8, stderr: anytype) !ExplainTarget {
    var target: ?[]const u8 = null;
    var args_json: ?[]const u8 = null;
    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const arg = args[index];
        if (std.mem.eql(u8, arg, "--args")) {
            index += 1;
            if (index >= args.len) {
                try stderr.writeAll("ryk policy explain: --args requires a JSON object string.\n");
                if (target) |owned| allocator.free(owned);
                return .{ .invalid = true };
            }
            args_json = args[index];
        } else if (std.mem.startsWith(u8, arg, "-")) {
            try suggestions.writeUnknownOption(stderr, "ryk policy explain", arg, &.{"--args"}, "policy");
            if (target) |owned| allocator.free(owned);
            return .{ .invalid = true };
        } else {
            if (target != null) {
                try stderr.writeAll("ryk policy explain: expected one tool name.\n");
                if (target) |owned| allocator.free(owned);
                return .{ .invalid = true };
            }
            target = try allocator.dupe(u8, arg);
        }
    }
    if (target == null) {
        try stderr.writeAll("ryk policy explain: expected a tool name.\n");
        return .{ .invalid = true };
    }
    return .{ .target = target.?, .args_json = args_json };
}

fn packs(argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    if (argv.len != 0) {
        try stderr.writeAll("ryk policy packs: expected no arguments.\n");
        return exit_codes.usage;
    }
    try stdout.writeAll("Policy packs:\n");
    for (policy_mod.presets.agent_preset_infos) |info| {
        const source = policy_mod.presets.agentPresetText(info.preset);
        if (std.mem.indexOf(u8, source, "policy pack:") == null and
            !std.mem.eql(u8, info.name, "strict-local")) continue;
        try stdout.print("  {s}\n", .{info.name});
    }
    return exit_codes.success;
}

fn applyPack(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    if (argv.len < 1 or argv.len > 2) {
        try stderr.writeAll("ryk policy apply-pack: expected <pack> [--force].\n");
        return exit_codes.usage;
    }
    var force = false;
    if (argv.len == 2) {
        if (!std.mem.eql(u8, argv[1], "--force")) {
            try stderr.writeAll("ryk policy apply-pack: only --force is supported after the pack name.\n");
            return exit_codes.usage;
        }
        force = true;
    }
    const pack = policy_mod.presets.AgentPreset.parse(argv[0]) orelse {
        try suggestions.writeInvalidValue(stderr, "ryk policy apply-pack", "pack", argv[0], &.{ "solo-dev", "strict-local", "team-ci", "openclaw-hermes" }, "policy");
        return exit_codes.usage;
    };
    const pack_name = policy_mod.presets.agentPresetName(pack);
    if (!isProductPack(pack_name)) {
        try stderr.print("ryk policy apply-pack: '{s}' is an init preset, not a product policy pack.\n", .{pack_name});
        return exit_codes.usage;
    }
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();
    const cwd = std.Io.Dir.cwd();
    const root = supervisor.resolveWorkspaceRoot(io, allocator, null, ".") catch try cwd.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(root);
    const ryk_dir = try std.fs.path.join(allocator, &.{ root, ".ryk" });
    defer allocator.free(ryk_dir);
    try cwd.createDirPath(io, ryk_dir);
    const path = try std.fs.path.join(allocator, &.{ ryk_dir, "policy.yaml" });
    defer allocator.free(path);
    const flags: std.Io.File.CreateFlags = if (force) .{} else .{ .exclusive = true };
    const file = cwd.createFile(io, path, flags) catch |err| switch (err) {
        error.PathAlreadyExists => {
            try stderr.writeAll("ryk policy apply-pack: .ryk/policy.yaml already exists; use --force to overwrite.\n");
            return exit_codes.general;
        },
        else => return err,
    };
    defer file.close(io);
    try file.writeStreamingAll(io, policy_mod.presets.agentPresetText(pack));
    try stdout.print("Applied policy pack '{s}' to .ryk/policy.yaml.\n", .{pack_name});
    return exit_codes.success;
}

fn isProductPack(name: []const u8) bool {
    return std.mem.eql(u8, name, "solo-dev") or
        std.mem.eql(u8, name, "strict-local") or
        std.mem.eql(u8, name, "team-ci") or
        std.mem.eql(u8, name, "openclaw-hermes");
}

fn joinArgs(allocator: std.mem.Allocator, args: []const []const u8) ![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    for (args, 0..) |arg, index| {
        if (index > 0) try list.append(allocator, ' ');
        try list.appendSlice(allocator, arg);
    }
    return try list.toOwnedSlice(allocator);
}

test "policy check validates a file" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        const file = try tmp.dir.createFile(std.testing.io, "policy.yaml", .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io, policy_mod.presets.text(.strict));
    }
    const path = try tmp.dir.realPathFileAlloc(std.testing.io, "policy.yaml", std.testing.allocator);
    defer std.testing.allocator.free(path);

    var stdout_buf: [512]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, &.{ "check", path }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "Policy OK") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "policy check rejects scalar values on object-only grouping keys" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        const file = try tmp.dir.createFile(std.testing.io, "policy.yaml", .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io,
            \\version: 1
            \\mode: strict
            \\commands: allow
        );
    }
    const path = try tmp.dir.realPathFileAlloc(std.testing.io, "policy.yaml", std.testing.allocator);
    defer std.testing.allocator.free(path);

    var stdout_buf: [512]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, &.{ "check", path }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.general, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "InvalidPolicy") != null);
}

test "policy check without path validates workspace policy not builtin" {
    var stdout_buf: [1024]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, &.{"check"}, &stdout_writer, &stderr_writer);
    // Workspace may or may not have .ryk/policy.yaml depending on cwd.
    if (code == exit_codes.success) {
        const out = stdout_writer.buffered();
        try std.testing.expect(std.mem.indexOf(u8, out, "Policy OK:") != null);
        try std.testing.expect(std.mem.indexOf(u8, out, "policy.yaml") != null);
        try std.testing.expect(std.mem.indexOf(u8, out, "Policy OK: builtin:") == null);
        try std.testing.expectEqualStrings("", stderr_writer.buffered());
    } else {
        try std.testing.expectEqual(exit_codes.general, code);
        try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "no workspace policy") != null);
        try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "ryk init") != null);
    }
}

test "policy check --preset validates built-in only when explicit" {
    var stdout_buf: [512]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, &.{ "check", "--preset", "strict" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "Policy OK: builtin:strict") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "policy check builtin:path form validates built-in when explicit" {
    var stdout_buf: [512]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, &.{ "check", "builtin:ask" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "Policy OK: builtin:ask") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "policy check missing explicit path fails without falling back to builtin" {
    var stdout_buf: [512]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, &.{ "check", "/no/such/ryk-policy-check-missing.yaml" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.general, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "invalid policy") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "Policy OK: builtin:") == null);
}

test "policy explain reports matched deny rule" {
    var stdout_buf: [1024]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, &.{ "explain", "file.read", "~/.ssh/id_ed25519" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "[DENY]") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "files.read.deny") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "Mode") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "unknown") == null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "Next:") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "policy explain target parser accepts network method option" {
    var stderr_buf: [512]u8 = undefined;
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const parsed = try parseExplainTarget(std.testing.allocator, .network, &.{ "--method", "POST", "https://api.github.com/repos/ryk/ryk/issues" }, &stderr_writer);
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expect(!parsed.invalid);
    try std.testing.expectEqualStrings("POST", parsed.method.?);
    try std.testing.expectEqualStrings("https://api.github.com/repos/ryk/ryk/issues", parsed.target);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "policy explain accepts explicit policy path" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        const file = try tmp.dir.createFile(std.testing.io, "policy.yaml", .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io,
            \\version: 1
            \\mode: strict
            \\commands:
            \\  default: allow
            \\  deny:
            \\    - "git push *"
        );
    }
    const path = try tmp.dir.realPathFileAlloc(std.testing.io, "policy.yaml", std.testing.allocator);
    defer std.testing.allocator.free(path);

    var stdout_buf: [1024]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, &.{ "explain", "--policy", path, "command", "git", "push", "origin", "main" }, &stdout_writer, &stderr_writer);

    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expectEqualStrings(@embedFile("test-fixtures/policy-explain-command-deny.txt"), stdout_writer.buffered());
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "policy explanation panel sanitizes dynamic fields" {
    var output: [2048]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&output);
    try writePolicyDetailsPanel(
        std.testing.io,
        std.testing.allocator,
        &writer,
        "unsafe\x1b]0;owned\x07 reason\nforged",
        "rule\x1b[2Jid",
        "pattern\rspoof",
        "strict",
    );
    const rendered = writer.buffered();
    try std.testing.expect(std.mem.indexOfScalar(u8, rendered, 0x1b) == null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "owned") == null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "reason forged") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "pattern spoof") != null);
}

test "policy packs list productized packs" {
    var stdout_buf: [1024]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const code = try command(std.testing.io, &.{"packs"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "solo-dev") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "team-ci") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "openclaw-hermes") != null);
}

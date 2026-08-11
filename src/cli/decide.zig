const std = @import("std");
const core = @import("ryk_core").core;
const supervisor = core.supervisor;
const core_api = @import("ryk_core").api;
const policy = @import("ryk_core").policy;
const shell_engine = @import("../shell_engine/mod.zig");

const exit_codes = @import("exit_codes.zig");
const help = @import("help.zig");
const tui = @import("../tui/render.zig");
const terminal_text = @import("../tui/terminal_text.zig");
const suggestions = @import("suggestions.zig");
const file_policy_path = @import("file_policy_path.zig");

// Maximum JSON payload size to prevent memory exhaustion from hostile hosts.
const max_payload_len = 256 * 1024; // 256 KiB

// ---------------------------------------------------------------------------
// Top-level dispatch
// ---------------------------------------------------------------------------

pub fn command(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    if (argv.len > 0 and (std.mem.eql(u8, argv[0], "--help") or std.mem.eql(u8, argv[0], "-h"))) {
        _ = try help.writeCommand(io, stdout, "decide");
        return exit_codes.success;
    }
    if (argv.len == 0) {
        _ = try help.writeCommand(io, stdout, "decide");
        return exit_codes.usage;
    }

    const kind = DecisionKind.parse(argv[0]) orelse {
        try suggestions.writeUnknownSubcommand(
            stderr,
            "ryk decide",
            argv[0],
            &.{ "command", "file", "prompt", "tool" },
            "decide",
        );
        return exit_codes.usage;
    };

    return decideCommand(io, kind, argv[1..], stdout, stderr);
}

// ---------------------------------------------------------------------------
// Decision kind
// ---------------------------------------------------------------------------

const DecisionKind = enum {
    command,
    file,
    prompt,
    tool,

    pub fn parse(value: []const u8) ?DecisionKind {
        if (std.mem.eql(u8, value, "command")) return .command;
        if (std.mem.eql(u8, value, "file")) return .file;
        if (std.mem.eql(u8, value, "prompt")) return .prompt;
        if (std.mem.eql(u8, value, "tool")) return .tool;
        return null;
    }
};

// ---------------------------------------------------------------------------
// CLI decision command
// ---------------------------------------------------------------------------

fn decideCommand(io: std.Io, kind: DecisionKind, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    return decideCommandWithPolicy(io, kind, argv, stdout, stderr, null);
}

fn decideCommandWithPolicy(
    io: std.Io,
    kind: DecisionKind,
    argv: []const []const u8,
    stdout: anytype,
    stderr: anytype,
    explicit_policy_path: ?[]const u8,
) !u8 {
    var json_payload: ?[]const u8 = null;
    var use_stdin = false;
    var ci_mode = false;
    var human = false;

    var index: usize = 0;
    while (index < argv.len) : (index += 1) {
        const arg = argv[index];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            try stdout.writeAll(
                \\Usage:
                \\  ryk decide command --json '{"command":"<cmd>"}'
                \\  ryk decide file    --json '{"path":"<p>","operation":"read|write"}'
                \\  ryk decide prompt  --json '{"text":"<text>"}'
                \\  ryk decide tool    --json '{"name":"<name>"}'
                \\  ryk decide <kind> --stdin
                \\  ryk decide <kind> --json <payload> [--ci]
                \\  ryk decide <kind> --stdin [--ci]
                \\  ryk decide <kind> --human (--json <payload>|--stdin) [--ci]
                \\
                \\Options:
                \\  --json   Provide JSON payload inline.
                \\  --stdin  Read JSON payload from stdin.
                \\  --ci     CI mode: ask decisions become block.
                \\  --human  Render a human-readable decision (default output is JSON).
                \\
            );
            return exit_codes.success;
        }
        if (std.mem.eql(u8, arg, "--json")) {
            if (index + 1 >= argv.len) {
                try stderr.writeAll("ryk decide: --json requires a value.\n");
                return exit_codes.usage;
            }
            json_payload = argv[index + 1];
            index += 1;
            continue;
        }
        if (std.mem.eql(u8, arg, "--stdin")) {
            use_stdin = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--ci")) {
            ci_mode = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--human")) {
            human = true;
            continue;
        }
        try suggestions.writeUnknownOption(stderr, "ryk decide", arg, &.{ "--json", "--stdin", "--ci", "--human", "--help", "-h" }, "decide");
        return exit_codes.usage;
    }

    if (json_payload == null and !use_stdin) {
        try stderr.writeAll("ryk decide: expected --json <payload> or --stdin.\n");
        return exit_codes.usage;
    }
    if (!use_stdin) {
        if (json_payload.?.len > max_payload_len) {
            try stderr.writeAll("ryk decide: JSON payload exceeds maximum size.\n");
            return exit_codes.general;
        }
    }

    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();

    // Read payload
    const payload_text = if (use_stdin)
        readBoundedStdin(io, allocator, max_payload_len) catch |err| {
            if (err == error.PayloadTooLarge) {
                try stderr.writeAll("ryk decide: JSON payload exceeds maximum size.\n");
                return exit_codes.general;
            }
            return err;
        }
    else
        try allocator.dupe(u8, json_payload.?);
    defer allocator.free(payload_text);

    // Parse JSON payload
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, payload_text, .{}) catch |err| {
        try stderr.print("ryk decide: invalid JSON ({s}).\n", .{@errorName(err)});
        // Machine contract: emit typed fail-closed JSON so Pi can classify/retry.
        if (!human) {
            try writeFailClosedJson(stdout, "invalid_json", "ryk decide: invalid JSON payload.");
        }
        return exit_codes.general;
    };
    defer parsed.deinit();

    // Load policy
    const root = supervisor.resolveWorkspaceRoot(io, allocator, null, ".") catch try allocator.dupe(u8, ".");
    defer allocator.free(root);
    var loaded = core_api.discoverPolicy(io, allocator, explicit_policy_path, root) catch |err| {
        try stderr.print("ryk decide: failed to load policy: {s}\n", .{@errorName(err)});
        if (!human) {
            try writeFailClosedJson(stdout, "policy_load_failed", "ryk decide: failed to load policy.");
        }
        return exit_codes.general;
    };
    defer loaded.deinit();

    // Evaluate decision
    var result = evaluateDecision(io, allocator, loaded.innerPtr(), kind, parsed.value, ci_mode, root) catch |err| {
        try stderr.print("ryk decide: evaluation failed: {s}\n", .{@errorName(err)});
        if (!human) {
            try writeFailClosedJson(stdout, "evaluation_failed", "ryk decide: evaluation failed; fail closed.");
        }
        return exit_codes.general;
    };
    defer result.deinit(allocator);

    if (human) {
        try writeDecisionHuman(io, allocator, stdout, loaded.mode().toString(), result);
    } else {
        // Frozen machine contract: default output remains byte-identical JSON.
        // On encode failure emit a minimal typed error object (never partial garbage).
        writeDecisionJson(stdout, result) catch {
            try writeFailClosedJson(stdout, "encode_failed", "ryk decide: failed to encode decision JSON.");
            return exit_codes.general;
        };
    }

    // Log debug info to stderr only
    if (result.rule) |rule| {
        try stderr.writeAll("[decide] matched rule: ");
        try terminal_text.write(stderr, rule, .single_line);
        try stderr.writeByte('\n');
    }

    return result.decision.exitCode();
}

// ---------------------------------------------------------------------------
// Decision evaluation
// ---------------------------------------------------------------------------

const PluginDecision = enum {
    allow,
    block,
    warn,
    ask,
    context_only,
    err,

    pub fn fromDecisionResult(result: core.decision.DecisionResult, ci_mode: bool) PluginDecision {
        return switch (result) {
            .allow => .allow,
            .deny => .block,
            .ask => if (ci_mode) .block else .ask,
            .observe => .context_only,
            .redact => .warn,
            .stage => if (ci_mode) .block else .ask,
            .broker => .err,
        };
    }

    pub fn toString(self: PluginDecision) []const u8 {
        return switch (self) {
            .err => "error",
            else => @tagName(self),
        };
    }

    pub fn exitCode(self: PluginDecision) u8 {
        return switch (self) {
            .allow, .context_only => exit_codes.success,
            .block => exit_codes.denial,
            .ask => exit_codes.ask,
            .warn => exit_codes.warn,
            .err => exit_codes.general,
        };
    }
};

const RiskLevel = enum {
    low,
    medium,
    high,
    critical,
    unknown,

    pub fn fromScore(score: ?u8) RiskLevel {
        const s = score orelse return .unknown;
        return if (s <= 25) .low else if (s <= 50) .medium else if (s <= 75) .high else .critical;
    }
};

const DecisionOutput = struct {
    version: u8 = 1,
    decision: PluginDecision,
    risk: RiskLevel,
    category: []const u8,
    reason: []const u8,
    rule: ?[]const u8,
    message: []const u8,
    redactions: []RedactionEntry,

    fn deinit(self: *DecisionOutput, allocator: std.mem.Allocator) void {
        allocator.free(self.reason);
        allocator.free(self.message);
        allocator.free(self.category);
        if (self.rule) |r| allocator.free(r);
        for (self.redactions) |r| {
            allocator.free(r.field);
            allocator.free(r.reason);
        }
        allocator.free(self.redactions);
        self.* = undefined;
    }
};

const RedactionEntry = struct {
    field: []const u8,
    reason: []const u8,
};

fn evaluateDecision(
    io: std.Io,
    allocator: std.mem.Allocator,
    policy_value: *const policy.schema.Policy,
    kind: DecisionKind,
    payload: std.json.Value,
    ci_mode: bool,
    workspace_root: []const u8,
) !DecisionOutput {
    var redactions: std.ArrayList(RedactionEntry) = .empty;

    switch (kind) {
        .command => {
            const command_text = extractString(payload, "command") orelse extractString(payload, "name") orelse return error.MissingRequiredField;
            const evaluation = try core_api.explainAction(allocator, @ptrCast(policy_value), .command, command_text);
            defer evaluation.deinit(allocator);

            // Shell pack fence: medium/high/critical pack denials take the more
            // restrictive of policy vs shell-derived plugin decision. Critical/high
            // → block (closer to hook hard fence for critical); medium → ask only
            // under ask/yolo (CI and strict/redteam/ci policy modes harden to block).
            // Coding DCG create-path uses mode: strict so medium pack hits never ask.
            //
            // evaluateCommand error set is allocator-only (OOM). Registry init and
            // other evaluator failures already return a fail-closed deny Evaluation
            // (e.g. zig.shell:init) — do not re-wrap OOM into a synthetic block
            // DecisionOutput that allocates under the same memory pressure.
            var shell = try shell_engine.evaluateCommand(allocator, command_text, .{});
            defer shell.deinit(allocator);

            if (shell.decision == .deny and packSeverityBlocksPolicyAllow(shell.severity)) {
                const shell_derived: PluginDecision = switch (shell.severity) {
                    .critical, .high => .block,
                    .medium => if (ci_mode or packMediumFenceBlocks(policy_value.mode)) .block else .ask,
                    .low => unreachable, // excluded by packSeverityBlocksPolicyAllow
                };
                const policy_decision = PluginDecision.fromDecisionResult(evaluation.decision.result, ci_mode);
                // When shell is at least as restrictive as policy, surface the
                // pack fence (rule/reason). Policy-stricter cases fall through.
                if (pluginDecisionRestrictiveness(shell_derived) >= pluginDecisionRestrictiveness(policy_decision)) {
                    const risk: RiskLevel = switch (shell.severity) {
                        .critical => .critical,
                        .high => .high,
                        .medium => .medium,
                        .low => unreachable,
                    };
                    return try buildCommandDecisionOutput(
                        allocator,
                        shell_derived,
                        risk,
                        shell.reason,
                        shell.rule_id,
                        &redactions,
                    );
                }
            }

            const decision = PluginDecision.fromDecisionResult(evaluation.decision.result, ci_mode);
            const risk = RiskLevel.fromScore(evaluation.decision.risk_score);

            return .{
                .decision = decision,
                .risk = risk,
                .category = try allocator.dupe(u8, "command"),
                .reason = try allocator.dupe(u8, evaluation.decision.reason),
                .rule = if (evaluation.matched_rule) |rule| try allocator.dupe(u8, rule.id) else null,
                .message = try buildMessage(allocator, decision, "command"),
                .redactions = try redactions.toOwnedSlice(allocator),
            };
        },
        .file => {
            const path = extractString(payload, "path") orelse return error.MissingRequiredField;
            const operation = extractString(payload, "operation") orelse "read";
            if (!std.mem.eql(u8, operation, "read") and !std.mem.eql(u8, operation, "write")) {
                return error.InvalidFileOperation;
            }

            const explain_kind: policy.explain.ExplainKind = if (std.mem.eql(u8, operation, "write")) .file_write else .file_read;
            const category_text = if (std.mem.eql(u8, operation, "write")) "file.write" else "file.read";
            const policy_path = file_policy_path.normalizeFilePolicyPath(io, allocator, workspace_root, path) catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => return buildFileNormalizationBlock(allocator, category_text),
            };
            defer allocator.free(policy_path);

            const evaluation = try core_api.explainAction(allocator, @ptrCast(policy_value), explain_kind, policy_path);
            defer evaluation.deinit(allocator);

            const decision = PluginDecision.fromDecisionResult(evaluation.decision.result, ci_mode);
            const risk = RiskLevel.fromScore(evaluation.decision.risk_score);

            return .{
                .decision = decision,
                .risk = risk,
                .category = try allocator.dupe(u8, category_text),
                .reason = try allocator.dupe(u8, evaluation.decision.reason),
                .rule = if (evaluation.matched_rule) |rule| try allocator.dupe(u8, rule.id) else null,
                .message = try buildMessage(allocator, decision, category_text),
                .redactions = try redactions.toOwnedSlice(allocator),
            };
        },
        .prompt => {
            const text = extractString(payload, "text") orelse
                extractString(payload, "prompt") orelse
                extractString(payload, "user_message") orelse
                "";

            // Redact prompt text to check for secrets
            var redact_buf: [4096]u8 = undefined;
            const redacted = core_api.redactStringBounded(text, &redact_buf);
            const had_secrets = redacted.len != text.len or !std.mem.eql(u8, redacted, text);

            if (had_secrets) {
                try redactions.append(allocator, .{
                    .field = try allocator.dupe(u8, "text"),
                    .reason = try allocator.dupe(u8, "potential secret detected"),
                });
            }

            // Prompt decisions use policy env evaluation as a proxy for sensitivity
            const evaluation = try core_api.explainAction(allocator, @ptrCast(policy_value), .env, "USER_PROMPT");
            defer evaluation.deinit(allocator);

            // Override decision if secrets detected
            const decision: PluginDecision = if (had_secrets)
                .warn
            else
                PluginDecision.fromDecisionResult(evaluation.decision.result, ci_mode);

            const risk: RiskLevel = if (had_secrets) .high else RiskLevel.fromScore(evaluation.decision.risk_score);

            return .{
                .decision = decision,
                .risk = risk,
                .category = try allocator.dupe(u8, "prompt"),
                .reason = if (had_secrets)
                    try allocator.dupe(u8, "prompt contains potential secret")
                else
                    try allocator.dupe(u8, evaluation.decision.reason),
                .rule = if (evaluation.matched_rule) |rule| try allocator.dupe(u8, rule.id) else null,
                .message = if (had_secrets)
                    try allocator.dupe(u8, "Prompt may contain sensitive data. Review before submitting.")
                else
                    try buildMessage(allocator, decision, "prompt"),
                .redactions = try redactions.toOwnedSlice(allocator),
            };
        },
        .tool => {
            const tool_name = extractString(payload, "name") orelse
                extractString(payload, "tool") orelse
                extractNestedString(payload, &.{ "tool", "name" }) orelse
                return error.MissingRequiredField;
            // Phase B: optional tool_input/args/input for structural classification.
            var owned_args: ?policy.effects.OwnedArgsView = null;
            defer if (owned_args) |*oa| oa.deinit(allocator);
            if (extractToolArgsObject(payload)) |args_obj| {
                owned_args = try policy.effects.toolArgsViewFromJsonObject(allocator, args_obj);
            }
            const args_view: ?policy.effects.ToolArgsView = if (owned_args) |oa| oa.view else null;
            // Use .tool (MCP surface ∩ effect-class), not pure .mcp, so `ryk decide tool`
            // matches host PreToolUse / MCP proxy enforcement when effects: is configured.
            // Phase C: load packs when effects: is active so pack-mapped names match hook/proxy.
            var pack_set = policy.effects.loadPacksForEnforcement(
                io,
                allocator,
                workspace_root,
                policy_value.effects.isActive(),
            ) catch return error.InvalidEffectPack;
            defer pack_set.deinit();
            const evaluation = try core_api.explainActionWithOptions(
                allocator,
                @ptrCast(policy_value),
                .tool,
                tool_name,
                .{ .tool_args = args_view, .effect_packs = &pack_set },
            );
            defer evaluation.deinit(allocator);

            const decision = PluginDecision.fromDecisionResult(evaluation.decision.result, ci_mode);
            const risk = RiskLevel.fromScore(evaluation.decision.risk_score);

            return .{
                .decision = decision,
                .risk = risk,
                .category = try allocator.dupe(u8, "tool"),
                .reason = try allocator.dupe(u8, evaluation.decision.reason),
                .rule = if (evaluation.matched_rule) |rule| try allocator.dupe(u8, rule.id) else null,
                .message = try buildMessage(allocator, decision, "tool"),
                .redactions = try redactions.toOwnedSlice(allocator),
            };
        },
    }
}

/// Strict-like policy modes (and CI flag) harden medium pack fence to block so
/// coding DCG / unattended create-paths never emit ask for medium pack denials.
fn packMediumFenceBlocks(mode: policy.schema.Mode) bool {
    return switch (mode) {
        .strict, .redteam, .ci => true,
        .ask, .yolo, .observe, .trusted => false,
    };
}

/// Pack deny at medium+ participates in the decide pack fence.
fn packSeverityBlocksPolicyAllow(severity: shell_engine.Severity) bool {
    return switch (severity) {
        .critical, .high, .medium => true,
        .low => false,
    };
}

/// Higher = more restrictive. Used to merge policy vs shell-derived plugin decisions.
fn pluginDecisionRestrictiveness(decision: PluginDecision) u8 {
    return switch (decision) {
        .allow => 0,
        .context_only => 1,
        .warn => 2,
        .ask => 3,
        .block => 4,
        .err => 5,
    };
}

/// Build a command-path DecisionOutput with full errdefer cleanup on partial alloc.
/// Mirrors `buildFileNormalizationBlock` ownership discipline.
fn buildCommandDecisionOutput(
    allocator: std.mem.Allocator,
    decision: PluginDecision,
    risk: RiskLevel,
    reason: []const u8,
    rule: ?[]const u8,
    redactions: *std.ArrayList(RedactionEntry),
) !DecisionOutput {
    const category = try allocator.dupe(u8, "command");
    errdefer allocator.free(category);
    const reason_owned = try allocator.dupe(u8, reason);
    errdefer allocator.free(reason_owned);
    const rule_owned: ?[]const u8 = if (rule) |r| try allocator.dupe(u8, r) else null;
    errdefer if (rule_owned) |r| allocator.free(r);
    const message = try buildMessage(allocator, decision, "command");
    errdefer allocator.free(message);
    const redactions_owned = try redactions.toOwnedSlice(allocator);
    return .{
        .decision = decision,
        .risk = risk,
        .category = category,
        .reason = reason_owned,
        .rule = rule_owned,
        .message = message,
        .redactions = redactions_owned,
    };
}

fn buildFileNormalizationBlock(allocator: std.mem.Allocator, category: []const u8) !DecisionOutput {
    const owned_category = try allocator.dupe(u8, category);
    errdefer allocator.free(owned_category);
    const reason = try allocator.dupe(u8, file_policy_path.outside_workspace_reason);
    errdefer allocator.free(reason);
    const rule = try file_policy_path.outsideWorkspaceRuleId(allocator, category);
    errdefer allocator.free(rule);
    const message = try buildMessage(allocator, .block, category);
    errdefer allocator.free(message);
    return .{
        .decision = .block,
        .risk = .critical,
        .category = owned_category,
        .reason = reason,
        .rule = rule,
        .message = message,
        .redactions = try allocator.alloc(RedactionEntry, 0),
    };
}

fn buildMessage(allocator: std.mem.Allocator, decision: PluginDecision, category: []const u8) ![]const u8 {
    return switch (decision) {
        .allow => try std.fmt.allocPrint(allocator, "{s} allowed by ryk policy.", .{category}),
        .block => try std.fmt.allocPrint(allocator, "{s} blocked by ryk policy.", .{category}),
        .warn => try std.fmt.allocPrint(allocator, "{s} flagged by ryk policy. Review before proceeding.", .{category}),
        .ask => try std.fmt.allocPrint(allocator, "{s} requires user approval per ryk policy.", .{category}),
        .context_only => try std.fmt.allocPrint(allocator, "{s} allowed for context only. No side effects permitted.", .{category}),
        .err => try std.fmt.allocPrint(allocator, "ryk could not evaluate {s}. Fail closed.", .{category}),
    };
}

// ---------------------------------------------------------------------------
// JSON output
// ---------------------------------------------------------------------------

fn writeDecisionJson(stdout: anytype, result: DecisionOutput) !void {
    try stdout.writeAll("{\n");
    try stdout.print("  \"version\": {d},\n", .{result.version});
    try stdout.print("  \"decision\": \"{s}\",\n", .{result.decision.toString()});
    try stdout.print("  \"risk\": \"{s}\",\n", .{@tagName(result.risk)});
    try stdout.print("  \"category\": \"{s}\",\n", .{result.category});
    try stdout.writeAll("  \"reason\": ");
    try writeJsonString(stdout, result.reason);
    try stdout.writeAll(",\n");

    try stdout.writeAll("  \"rule\": ");
    if (result.rule) |rule| {
        try writeJsonString(stdout, rule);
    } else {
        try stdout.writeAll("null");
    }
    try stdout.writeAll(",\n");

    try stdout.writeAll("  \"message\": ");
    try writeJsonString(stdout, result.message);
    try stdout.writeAll(",\n");

    try stdout.writeAll("  \"redactions\": [\n");
    for (result.redactions, 0..) |r, i| {
        try stdout.writeAll("    {\n");
        try stdout.writeAll("      \"field\": ");
        try writeJsonString(stdout, r.field);
        try stdout.writeAll(",\n");
        try stdout.writeAll("      \"reason\": ");
        try writeJsonString(stdout, r.reason);
        try stdout.writeAll("\n    }");
        if (i < result.redactions.len - 1) try stdout.writeAll(",");
        try stdout.writeAll("\n");
    }
    try stdout.writeAll("  ]\n");
    try stdout.writeAll("}\n");
}

/// Typed fail-closed JSON for protocol/encode/policy errors (exit general).
/// Keeps machine consumers schema-valid instead of empty/partial stdout.
fn writeFailClosedJson(stdout: anytype, error_code: []const u8, message: []const u8) !void {
    try stdout.writeAll("{\n");
    try stdout.writeAll("  \"version\": 1,\n");
    try stdout.writeAll("  \"decision\": \"error\",\n");
    try stdout.writeAll("  \"risk\": \"unknown\",\n");
    try stdout.writeAll("  \"category\": \"protocol\",\n");
    try stdout.writeAll("  \"reason\": ");
    try writeJsonString(stdout, message);
    try stdout.writeAll(",\n");
    try stdout.writeAll("  \"rule\": null,\n");
    try stdout.writeAll("  \"message\": ");
    try writeJsonString(stdout, message);
    try stdout.writeAll(",\n");
    try stdout.writeAll("  \"error_code\": ");
    try writeJsonString(stdout, error_code);
    try stdout.writeAll(",\n");
    try stdout.writeAll("  \"redactions\": []\n");
    try stdout.writeAll("}\n");
}

fn writeDecisionHuman(io: std.Io, allocator: std.mem.Allocator, stdout: anytype, mode: []const u8, result: DecisionOutput) !void {
    try stdout.writeAll("Decision  ");
    try tui.badge(io, stdout, badgeForDecision(result.decision));
    try stdout.writeAll("\n\n");

    const rule = result.rule orelse "none";
    const reason_line = try std.fmt.allocPrint(allocator, "Reason    {s}", .{result.reason});
    errdefer allocator.free(reason_line);
    const rule_line = try std.fmt.allocPrint(allocator, "Rule      {s}", .{rule});
    errdefer allocator.free(rule_line);
    const mode_line = try std.fmt.allocPrint(allocator, "Mode      {s}", .{mode});
    errdefer allocator.free(mode_line);
    const category_line = try std.fmt.allocPrint(allocator, "Category  {s}", .{result.category});
    errdefer allocator.free(category_line);
    const message_line = try std.fmt.allocPrint(allocator, "Message   {s}", .{result.message});
    const detail_lines = [_][]u8{ reason_line, rule_line, mode_line, category_line, message_line };
    defer for (detail_lines) |line| allocator.free(line);
    try tui.panel(io, stdout, "Decision details", &detail_lines);
    try stdout.writeAll("  Risk  ");
    try tui.meter(io, stdout, riskFraction(result.risk), @tagName(result.risk));
    try stdout.writeAll("\n");
    if (result.redactions.len > 0) {
        try stdout.print("  Redactions  {d}\n", .{result.redactions.len});
        for (result.redactions) |redaction| {
            try stdout.writeAll("    • ");
            try terminal_text.write(stdout, redaction.field, .single_line);
            try stdout.writeAll(": ");
            try terminal_text.write(stdout, redaction.reason, .single_line);
            try stdout.writeByte('\n');
        }
    }
}

fn badgeForDecision(decision: PluginDecision) tui.BadgeKind {
    return switch (decision) {
        .allow => .allow,
        .block, .err => .deny,
        .ask => .ask,
        .warn => .warn,
        .context_only => .info,
    };
}

fn riskFraction(risk: RiskLevel) f32 {
    return switch (risk) {
        .low => 0.2,
        .medium => 0.5,
        .high => 0.75,
        .critical => 1.0,
        .unknown => 0.0,
    };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn readBoundedStdin(io: std.Io, allocator: std.mem.Allocator, max_len: usize) ![]u8 {
    return readBoundedFile(io, allocator, max_len, std.Io.File.stdin());
}

fn readBoundedFile(io: std.Io, allocator: std.mem.Allocator, max_len: usize, file: std.Io.File) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    var chunk: [4096]u8 = undefined;
    while (true) {
        const n = try file.readStreaming(io, &.{chunk[0..]});
        if (n == 0) break;
        if (buf.items.len + n > max_len) return error.PayloadTooLarge;
        try buf.appendSlice(allocator, chunk[0..n]);
    }

    return try buf.toOwnedSlice(allocator);
}

fn readBoundedIoReader(allocator: std.mem.Allocator, max_len: usize, reader: *std.Io.Reader) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    while (buf.items.len < max_len) {
        const chunk = reader.take(@min(4096, max_len - buf.items.len)) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        if (chunk.len == 0) break;
        try buf.appendSlice(allocator, chunk);
    }
    const extra = reader.take(1) catch |err| switch (err) {
        error.EndOfStream => return try buf.toOwnedSlice(allocator),
        else => return err,
    };
    if (extra.len > 0) return error.PayloadTooLarge;
    return try buf.toOwnedSlice(allocator);
}

fn extractString(payload: std.json.Value, key: []const u8) ?[]const u8 {
    if (payload != .object) return null;
    if (payload.object.get(key)) |v| {
        return switch (v) {
            .string => |s| s,
            else => null,
        };
    }
    return null;
}

fn extractNestedString(payload: std.json.Value, keys: []const []const u8) ?[]const u8 {
    var current = payload;
    for (keys) |key| {
        if (current != .object) return null;
        const next = current.object.get(key) orelse return null;
        current = next;
    }
    return switch (current) {
        .string => |s| s,
        else => null,
    };
}

fn extractNestedValue(payload: std.json.Value, keys: []const []const u8) ?std.json.Value {
    var current = payload;
    for (keys) |key| {
        if (current != .object) return null;
        current = current.object.get(key) orelse return null;
    }
    return current;
}

/// Locate a JSON object of tool arguments for structural effect classification.
fn extractToolArgsObject(payload: std.json.Value) ?std.json.Value {
    const paths = [_][]const []const u8{
        &.{"tool_input"},
        &.{"args"},
        &.{"input"},
        &.{"arguments"},
        &.{"params"},
        &.{ "tool", "input" },
    };
    for (paths) |path| {
        if (extractNestedValue(payload, path)) |value| {
            if (value == .object) return value;
        }
    }
    return null;
}

fn writeJsonString(writer: anytype, value: []const u8) !void {
    try writer.writeByte('"');
    for (value) |byte| {
        switch (byte) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            0...8, 11...12, 14...0x1f => try writer.print("\\u{x:0>4}", .{byte}),
            else => try writer.writeByte(byte),
        }
    }
    try writer.writeByte('"');
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "PluginDecision exitCode mapping" {
    const cases = [_]struct { PluginDecision, u8 }{
        .{ .allow, exit_codes.success },
        .{ .context_only, exit_codes.success },
        .{ .block, exit_codes.denial },
        .{ .ask, exit_codes.ask },
        .{ .warn, exit_codes.warn },
        .{ .err, exit_codes.general },
    };
    for (cases) |entry| {
        try std.testing.expectEqual(entry[1], entry[0].exitCode());
    }
}

test "decide command help and invalid kind" {
    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const help_code = try command(std.testing.io, &.{"--help"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, help_code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "decide") != null);

    stdout_writer = .fixed(&stdout_buf);
    stderr_writer = .fixed(&stderr_buf);
    const bad_code = try command(std.testing.io, &.{"unknown"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, bad_code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "unknown subcommand") != null);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "ryk help decide") != null);
}

test "decide command with safe command returns allow" {
    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try decideCommand(std.testing.io, .command, &.{
        "--json", "{\"command\":\"echo hello\"}",
    }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "\"decision\": \"allow\"") != null);
}

test "decide command machine output matches captured contract fixture" {
    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const code = try decideCommand(std.testing.io, .command, &.{
        "--json", "{\"command\":\"echo hello\"}",
    }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expectEqualStrings(
        @embedFile("test-fixtures/decide-command-allow.json"),
        stdout_writer.buffered(),
    );
}

test "decide human output matches captured contract fixture" {
    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const policy_path = try std.Io.Dir.cwd().realPathFileAlloc(
        std.testing.io,
        "policies/presets/generic-agent.yaml",
        std.testing.allocator,
    );
    defer std.testing.allocator.free(policy_path);
    const code = try decideCommandWithPolicy(
        std.testing.io,
        .command,
        &.{ "--json", "{\"command\":\"echo hello\"}", "--human" },
        &stdout_writer,
        &stderr_writer,
        policy_path,
    );
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expectEqualStrings(
        @embedFile("test-fixtures/decide-command-allow-human.txt"),
        stdout_writer.buffered(),
    );
}

test "decide human output is plain under --no-rich even when colour is available" {
    // Phase 7 Task E exhaustiveness: the global --no-rich / RYK_NO_RICH hatch
    // (resolved to theme.setRichEnabled(false) in mod.runWithCwdUsing) must gate
    // COLOUR output on the human path, not just banner presence. Force colour
    // on, then disable rich, and confirm no ANSI escapes leak into human output.
    const theme = @import("../tui/theme.zig");
    theme.setTestActive(.{ .capability = .c256, .background = .dark });
    theme.setRichEnabled(false);
    defer {
        theme.setRichEnabled(true);
        theme.setTestActive(null);
        theme.resetCache();
    }

    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try decideCommand(std.testing.io, .command, &.{
        "--json", "{\"command\":\"echo hello\"}", "--human",
    }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);

    const out = stdout_writer.buffered();
    // --no-rich suppresses colour even when a colour TTY is available.
    try std.testing.expect(std.mem.indexOfScalar(u8, out, 0x1b) == null);
    // Plain output still carries the full decision (degrades, never empties).
    try std.testing.expect(std.mem.indexOf(u8, out, "Decision") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "[ALLOW]") != null);
}

test "decide human output sanitizes dynamic terminal text" {
    var stdout_buf: [1024]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var result: DecisionOutput = .{
        .decision = .block,
        .risk = .critical,
        .category = "command\x1b[2J",
        .reason = "unsafe\x1b]0;owned\x07 reason",
        .rule = "rule\rspoof",
        .message = "blocked\nmessage",
        .redactions = &.{},
    };
    _ = &result;
    try writeDecisionHuman(std.testing.io, std.testing.allocator, &stdout_writer, "strict", result);
    try std.testing.expect(std.mem.indexOfScalar(u8, stdout_writer.buffered(), 0x1b) == null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "blocked message") != null);
}

test "decide command with dangerous command returns block" {
    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try decideCommand(std.testing.io, .command, &.{
        "--json", "{\"command\":\"rm -rf /\"}",
    }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.denial, code);

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "\"decision\": \"block\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"category\": \"command\"") != null);
}

test "decide command pack fence: git branch -D under commands.allow is ask (CI block)" {
    // Pin policy so medium pack hit cannot pure-allow via broad `git branch *`.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "policy.yaml",
        .data =
        \\version: 1
        \\mode: ask
        \\commands:
        \\  default: ask
        \\  allow:
        \\    - "git branch *"
        \\
        ,
    });
    const policy_path = try tmp.dir.realPathFileAlloc(std.testing.io, "policy.yaml", std.testing.allocator);
    defer std.testing.allocator.free(policy_path);

    // Non-CI: medium pack fence → ask (not allow), with pack rule id.
    {
        var stdout_buf: [4096]u8 = undefined;
        var stderr_buf: [512]u8 = undefined;
        var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
        var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

        const code = try decideCommandWithPolicy(
            std.testing.io,
            .command,
            &.{ "--json", "{\"command\":\"git branch -D feature\"}" },
            &stdout_writer,
            &stderr_writer,
            policy_path,
        );
        try std.testing.expectEqual(exit_codes.ask, code);

        const output = stdout_writer.buffered();
        try std.testing.expect(std.mem.indexOf(u8, output, "\"decision\": \"ask\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, output, "\"decision\": \"allow\"") == null);
        try std.testing.expect(std.mem.indexOf(u8, output, "core.git:branch-force-delete") != null);
    }

    // CI: medium fence hardens ask → block.
    {
        var stdout_buf: [4096]u8 = undefined;
        var stderr_buf: [512]u8 = undefined;
        var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
        var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

        const code = try decideCommandWithPolicy(
            std.testing.io,
            .command,
            &.{ "--json", "{\"command\":\"git branch -D feature\"}", "--ci" },
            &stdout_writer,
            &stderr_writer,
            policy_path,
        );
        try std.testing.expectEqual(exit_codes.denial, code);

        const output = stdout_writer.buffered();
        try std.testing.expect(std.mem.indexOf(u8, output, "\"decision\": \"block\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, output, "core.git:branch-force-delete") != null);
    }
}

test "decide command pack fence: critical under ask defaults is block" {
    // Policy default ask (no pure allow for reset --hard) must still hard-fence
    // pack-critical to block — not soften to ask.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "policy.yaml",
        .data =
        \\version: 1
        \\mode: ask
        \\commands:
        \\  default: ask
        \\  allow:
        \\    - "git branch *"
        \\
        ,
    });
    const policy_path = try tmp.dir.realPathFileAlloc(std.testing.io, "policy.yaml", std.testing.allocator);
    defer std.testing.allocator.free(policy_path);

    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try decideCommandWithPolicy(
        std.testing.io,
        .command,
        &.{ "--json", "{\"command\":\"git reset --hard HEAD\"}" },
        &stdout_writer,
        &stderr_writer,
        policy_path,
    );
    try std.testing.expectEqual(exit_codes.denial, code);

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "\"decision\": \"block\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"decision\": \"ask\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "core.git:reset-hard") != null);
}

test "decide command pack fence: critical under pure commands.allow is block" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "policy.yaml",
        .data =
        \\version: 1
        \\mode: ask
        \\commands:
        \\  default: ask
        \\  allow:
        \\    - "git *"
        \\
        ,
    });
    const policy_path = try tmp.dir.realPathFileAlloc(std.testing.io, "policy.yaml", std.testing.allocator);
    defer std.testing.allocator.free(policy_path);

    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try decideCommandWithPolicy(
        std.testing.io,
        .command,
        &.{ "--json", "{\"command\":\"git reset --hard HEAD\"}" },
        &stdout_writer,
        &stderr_writer,
        policy_path,
    );
    try std.testing.expectEqual(exit_codes.denial, code);

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "\"decision\": \"block\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"decision\": \"allow\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "core.git:reset-hard") != null);
}

test "decide command pack fence: high severity under pure allow is block" {
    // Node wipe of /tmp is high (not critical); fence must still beat pure allow.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "policy.yaml",
        .data =
        \\version: 1
        \\mode: ask
        \\commands:
        \\  default: allow
        \\  allow:
        \\    - "node *"
        \\
        ,
    });
    const policy_path = try tmp.dir.realPathFileAlloc(std.testing.io, "policy.yaml", std.testing.allocator);
    defer std.testing.allocator.free(policy_path);

    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try decideCommandWithPolicy(
        std.testing.io,
        .command,
        &.{ "--json", "{\"command\":\"node -e \\\"require('fs').rmSync('/tmp/x',{recursive:true})\\\"\"}" },
        &stdout_writer,
        &stderr_writer,
        policy_path,
    );
    try std.testing.expectEqual(exit_codes.denial, code);

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "\"decision\": \"block\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"decision\": \"allow\"") == null);
}

test "decide file write to protected path returns block" {
    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try decideCommand(std.testing.io, .file, &.{
        "--json", "{\"path\":\"/etc/passwd\",\"operation\":\"write\"}",
    }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.denial, code);

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "\"decision\": \"block\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"category\": \"file.write\"") != null);
}

test "decide file normalizes absolute workspace paths to policy-relative targets" {
    const allocator = std.testing.allocator;
    const root = "/workspace/project";

    const policy_relative = try file_policy_path.normalizeFilePolicyPathLexical(allocator, root, "/workspace/project/.ryk/policy.yaml");
    defer allocator.free(policy_relative);
    try std.testing.expectEqualStrings("./.ryk/policy.yaml", policy_relative);

    const git_relative = try file_policy_path.normalizeFilePolicyPathLexical(allocator, root, "/workspace/project/.git/config");
    defer allocator.free(git_relative);
    try std.testing.expectEqualStrings("./.git/config", git_relative);

    const env_relative = try file_policy_path.normalizeFilePolicyPathLexical(allocator, root, "/workspace/project/.env");
    defer allocator.free(env_relative);
    try std.testing.expectEqualStrings("./.env", env_relative);

    const absolute_dot_segment = try file_policy_path.normalizeFilePolicyPathLexical(allocator, root, "/workspace/project/src/../.env");
    defer allocator.free(absolute_dot_segment);
    try std.testing.expectEqualStrings("./.env", absolute_dot_segment);

    const protected_dot_segment = try file_policy_path.normalizeFilePolicyPathLexical(allocator, root, "/workspace/project/.ryk/../.env");
    defer allocator.free(protected_dot_segment);
    try std.testing.expectEqualStrings("./.env", protected_dot_segment);

    const relative_dot_segment = try file_policy_path.normalizeFilePolicyPathLexical(allocator, root, "src/../.env");
    defer allocator.free(relative_dot_segment);
    try std.testing.expectEqualStrings("./.env", relative_dot_segment);

    const allowed_relative = try file_policy_path.normalizeFilePolicyPathLexical(allocator, root, "/workspace/project/src/main.zig");
    defer allocator.free(allowed_relative);
    try std.testing.expectEqualStrings("./src/main.zig", allowed_relative);

    const outside = try file_policy_path.normalizeFilePolicyPathLexical(allocator, root, "/tmp/outside.txt");
    defer allocator.free(outside);
    try std.testing.expectEqualStrings("/tmp/outside.txt", outside);

    const escaped = try file_policy_path.normalizeFilePolicyPathLexical(allocator, root, "/workspace/project/../outside.txt");
    defer allocator.free(escaped);
    try std.testing.expectEqualStrings("/workspace/outside.txt", escaped);
}

test "decide file resolves symlinks before policy evaluation" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "workspace", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "workspace/.env", .data = "synthetic=true\n" });

    const root = try tmp.dir.realPathFileAlloc(std.testing.io, "workspace", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const protected_path = try std.fs.path.join(std.testing.allocator, &.{ root, ".env" });
    defer std.testing.allocator.free(protected_path);
    const alias_path = try std.fs.path.join(std.testing.allocator, &.{ root, "config-link" });
    defer std.testing.allocator.free(alias_path);
    std.Io.Dir.cwd().symLink(std.testing.io, protected_path, alias_path, .{}) catch |err| switch (err) {
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };

    const normalized = try file_policy_path.normalizeFilePolicyPath(std.testing.io, std.testing.allocator, root, alias_path);
    defer std.testing.allocator.free(normalized);
    try std.testing.expectEqualStrings("./.env", normalized);
}

test "decide file returns a structured block for workspace symlink escapes" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "workspace", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "outside.txt", .data = "synthetic\n" });

    const root = try tmp.dir.realPathFileAlloc(std.testing.io, "workspace", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const outside_path = try tmp.dir.realPathFileAlloc(std.testing.io, "outside.txt", std.testing.allocator);
    defer std.testing.allocator.free(outside_path);
    const alias_path = try std.fs.path.join(std.testing.allocator, &.{ root, "outside-link" });
    defer std.testing.allocator.free(alias_path);
    std.Io.Dir.cwd().symLink(std.testing.io, outside_path, alias_path, .{}) catch |err| switch (err) {
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };

    const policy_path = try std.Io.Dir.cwd().realPathFileAlloc(
        std.testing.io,
        "policies/presets/generic-agent.yaml",
        std.testing.allocator,
    );
    defer std.testing.allocator.free(policy_path);
    var loaded = try core_api.discoverPolicy(std.testing.io, std.testing.allocator, policy_path, root);
    defer loaded.deinit();
    const payload_text = try std.fmt.allocPrint(std.testing.allocator, "{{\"path\":\"{s}\",\"operation\":\"read\"}}", .{alias_path});
    defer std.testing.allocator.free(payload_text);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, payload_text, .{});
    defer parsed.deinit();

    var result = try evaluateDecision(
        std.testing.io,
        std.testing.allocator,
        loaded.innerPtr(),
        .file,
        parsed.value,
        true,
        root,
    );
    defer result.deinit(std.testing.allocator);
    try std.testing.expectEqual(PluginDecision.block, result.decision);
    try std.testing.expectEqual(exit_codes.denial, result.decision.exitCode());
    try std.testing.expectEqualStrings("file.read", result.category);
    try std.testing.expectEqualStrings("builtin.files.read.deny[outside_workspace]", result.rule.?);

    var output_buffer: [1024]u8 = undefined;
    var output: std.Io.Writer = .fixed(&output_buffer);
    try writeDecisionJson(&output, result);
    try std.testing.expect(std.mem.indexOf(u8, output.buffered(), "\"decision\": \"block\"") != null);
}

test "decide file CLI gives workspace-relative and absolute paths identical decisions" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "policy.yaml",
        .data =
        \\version: 1
        \\mode: trusted
        \\files:
        \\  read:
        \\    allow:
        \\      - "./**"
        \\    deny:
        \\      - "./.env"
        \\  write:
        \\    allow:
        \\      - "./**"
        \\    deny:
        \\      - "./.ryk/**"
        \\      - "./.git/**"
        ,
    });
    const policy_path = try tmp.dir.realPathFileAlloc(std.testing.io, "policy.yaml", std.testing.allocator);
    defer std.testing.allocator.free(policy_path);
    const root = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    const cases = [_]struct {
        relative: []const u8,
        operation: []const u8,
        expected: u8,
    }{
        .{ .relative = ".ryk/policy.yaml", .operation = "write", .expected = exit_codes.denial },
        .{ .relative = ".git/config", .operation = "write", .expected = exit_codes.denial },
        .{ .relative = ".env", .operation = "read", .expected = exit_codes.denial },
        .{ .relative = "src/../.env", .operation = "read", .expected = exit_codes.denial },
        .{ .relative = ".ryk/../.env", .operation = "read", .expected = exit_codes.denial },
        .{ .relative = "README.md", .operation = "read", .expected = exit_codes.success },
    };

    for (cases) |case| {
        const absolute = try std.fs.path.join(std.testing.allocator, &.{ root, case.relative });
        defer std.testing.allocator.free(absolute);
        const relative_json = try std.fmt.allocPrint(std.testing.allocator, "{{\"path\":\"{s}\",\"operation\":\"{s}\"}}", .{ case.relative, case.operation });
        defer std.testing.allocator.free(relative_json);
        const absolute_json = try std.fmt.allocPrint(std.testing.allocator, "{{\"path\":\"{s}\",\"operation\":\"{s}\"}}", .{ absolute, case.operation });
        defer std.testing.allocator.free(absolute_json);

        var relative_stdout_buf: [2048]u8 = undefined;
        var relative_stderr_buf: [512]u8 = undefined;
        var relative_stdout: std.Io.Writer = .fixed(&relative_stdout_buf);
        var relative_stderr: std.Io.Writer = .fixed(&relative_stderr_buf);
        const relative_code = try decideCommandWithPolicy(
            std.testing.io,
            .file,
            &.{ "--json", relative_json },
            &relative_stdout,
            &relative_stderr,
            policy_path,
        );

        var absolute_stdout_buf: [2048]u8 = undefined;
        var absolute_stderr_buf: [512]u8 = undefined;
        var absolute_stdout: std.Io.Writer = .fixed(&absolute_stdout_buf);
        var absolute_stderr: std.Io.Writer = .fixed(&absolute_stderr_buf);
        const absolute_code = try decideCommandWithPolicy(
            std.testing.io,
            .file,
            &.{ "--json", absolute_json },
            &absolute_stdout,
            &absolute_stderr,
            policy_path,
        );

        try std.testing.expectEqual(case.expected, relative_code);
        try std.testing.expectEqual(relative_code, absolute_code);
        try std.testing.expectEqualStrings(relative_stdout.buffered(), absolute_stdout.buffered());
    }
}

test "decide file rejects unknown operation instead of downgrading to read" {
    var stdout_buf: [512]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try decideCommand(std.testing.io, .file, &.{
        "--json", "{\"path\":\"./src/main.zig\",\"operation\":\"delete\"}",
    }, &stdout_writer, &stderr_writer);
    try std.testing.expect(code != exit_codes.success);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "InvalidFileOperation") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "\"category\": \"file.read\"") == null);
}

test "decide rejects missing required command and file fields" {
    var stdout_buf: [512]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    // Typed fail-closed JSON on stdout for machine consumers; human detail on stderr.
    const missing_command = try decideCommand(std.testing.io, .command, &.{
        "--json", "{}",
    }, &stdout_writer, &stderr_writer);
    try std.testing.expect(missing_command != exit_codes.success);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "MissingRequiredField") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "\"decision\": \"error\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "\"category\": \"protocol\"") != null);

    stdout_writer = .fixed(&stdout_buf);
    stderr_writer = .fixed(&stderr_buf);
    const missing_file_path = try decideCommand(std.testing.io, .file, &.{
        "--json", "{\"operation\":\"read\"}",
    }, &stdout_writer, &stderr_writer);
    try std.testing.expect(missing_file_path != exit_codes.success);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "MissingRequiredField") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "\"decision\": \"error\"") != null);

    stdout_writer = .fixed(&stdout_buf);
    stderr_writer = .fixed(&stderr_buf);
    const missing_tool_name = try decideCommand(std.testing.io, .tool, &.{
        "--json", "{}",
    }, &stdout_writer, &stderr_writer);
    try std.testing.expect(missing_tool_name != exit_codes.success);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "MissingRequiredField") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "\"decision\": \"error\"") != null);
}

test "decide prompt with fake secret returns warn" {
    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try decideCommand(std.testing.io, .prompt, &.{
        "--json", "{\"text\":\"my token is ghp_fake_secret_value\"}",
    }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.warn, code);

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "\"decision\": \"warn\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"category\": \"prompt\"") != null);
    // Ensure redaction is noted
    try std.testing.expect(std.mem.indexOf(u8, output, "redactions") != null);
}

test "decide prompt accepts host prompt field and redacts fake secret" {
    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try decideCommand(std.testing.io, .prompt, &.{
        "--json", "{\"prompt\":\"fake_p05_secret_value\"}",
    }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.warn, code);

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "\"decision\": \"warn\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"category\": \"prompt\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "fake_p05_secret_value") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "redactions") != null);
}

test "decide tool returns valid JSON" {
    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try decideCommand(std.testing.io, .tool, &.{
        "--json", "{\"name\":\"read_file\"}",
    }, &stdout_writer, &stderr_writer);
    const output = stdout_writer.buffered();
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, output, .{});
    defer parsed.deinit();

    const decision = parsed.value.object.get("decision").?.string;
    if (std.mem.eql(u8, decision, "allow")) {
        try std.testing.expectEqual(exit_codes.success, code);
    } else if (std.mem.eql(u8, decision, "ask")) {
        try std.testing.expectEqual(exit_codes.ask, code);
    } else {
        try std.testing.expect(false);
    }

    try std.testing.expect(parsed.value.object.get("decision") != null);
    try std.testing.expect(parsed.value.object.get("risk") != null);
    try std.testing.expect(parsed.value.object.get("category") != null);
    try std.testing.expect(parsed.value.object.get("reason") != null);
    try std.testing.expect(parsed.value.object.get("message") != null);
}

test "decide tool applies effect-class denials" {
    // MCP surface allows the tool; effects must still deny (proves .tool path, not pure .mcp).
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "policy.yaml",
        .data =
        \\version: 1
        \\mode: strict
        \\mcp:
        \\  default: allow
        \\effects:
        \\  deny:
        \\    - comms.message
        \\
        ,
    });
    const policy_path = try tmp.dir.realPathFileAlloc(std.testing.io, "policy.yaml", std.testing.allocator);
    defer std.testing.allocator.free(policy_path);

    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try decideCommandWithPolicy(
        std.testing.io,
        .tool,
        &.{ "--json", "{\"name\":\"send_email\"}" },
        &stdout_writer,
        &stderr_writer,
        policy_path,
    );
    try std.testing.expectEqual(exit_codes.denial, code);
    const output = stdout_writer.buffered();
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, output, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings("block", parsed.value.object.get("decision").?.string);
    const reason = parsed.value.object.get("reason").?.string;
    try std.testing.expect(std.mem.indexOf(u8, reason, "comms.message") != null);
    try std.testing.expect(std.mem.indexOf(u8, reason, "effect") != null);
}

test "decide non-ci mode returns ask exit code for unknown command" {
    // Coding DCG defaults allow unmatched shell; use an explicit ask-default
    // policy so this still exercises PluginDecision ask → exit 7.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "policy.yaml",
        .data =
            \\version: 1
            \\mode: ask
            \\commands:
            \\  default: ask
            \\  allow:
            \\    - "git status"
            \\
        ,
    });
    const policy_path = try tmp.dir.realPathFileAlloc(std.testing.io, "policy.yaml", std.testing.allocator);
    defer std.testing.allocator.free(policy_path);

    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try decideCommandWithPolicy(
        std.testing.io,
        .command,
        &.{ "--json", "{\"command\":\"unknown-tool --help\"}" },
        &stdout_writer,
        &stderr_writer,
        policy_path,
    );
    try std.testing.expectEqual(exit_codes.ask, code);

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "\"decision\": \"ask\"") != null);
}

test "decide ci mode turns ask into block" {
    // Same ask-default policy as non-ci; --ci must map ask → block (exit denial).
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "policy.yaml",
        .data =
            \\version: 1
            \\mode: ask
            \\commands:
            \\  default: ask
            \\  allow:
            \\    - "git status"
            \\
        ,
    });
    const policy_path = try tmp.dir.realPathFileAlloc(std.testing.io, "policy.yaml", std.testing.allocator);
    defer std.testing.allocator.free(policy_path);

    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try decideCommandWithPolicy(
        std.testing.io,
        .command,
        &.{ "--json", "{\"command\":\"unknown-tool --help\"}", "--ci" },
        &stdout_writer,
        &stderr_writer,
        policy_path,
    );
    try std.testing.expectEqual(exit_codes.denial, code);

    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "\"decision\": \"block\"") != null);
}

test "decide rejects invalid JSON" {
    var stdout_buf: [512]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try decideCommand(std.testing.io, .command, &.{
        "--json", "{not json",
    }, &stdout_writer, &stderr_writer);
    try std.testing.expect(code != exit_codes.success);
    try std.testing.expectEqual(exit_codes.general, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "invalid JSON") != null);
    // Typed fail-closed JSON on stdout (schema-valid for Pi recovery).
    const out = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "\"decision\": \"error\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"error_code\": \"invalid_json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"category\": \"protocol\"") != null);
}

test "writeFailClosedJson is schema-shaped for machine consumers" {
    var buf: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try writeFailClosedJson(&writer, "encode_failed", "ryk decide: failed to encode decision JSON.");
    const out = writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "\"decision\": \"error\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"error_code\": \"encode_failed\"") != null);
}

test "decide bounded reader rejects oversized payload instead of truncating" {
    var payload = try std.testing.allocator.alloc(u8, max_payload_len + 1);
    defer std.testing.allocator.free(payload);
    @memset(payload[0..max_payload_len], ' ');
    payload[0] = '{';
    payload[1] = '}';
    payload[max_payload_len] = 'x';

    var reader: std.Io.Reader = .fixed(payload);
    try std.testing.expectError(error.PayloadTooLarge, readBoundedIoReader(std.testing.allocator, max_payload_len, &reader));
}

test "decide rejects inline json payloads over limit" {
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(std.testing.allocator);
    try payload.appendSlice(std.testing.allocator, "{\"text\":\"");
    try payload.appendNTimes(std.testing.allocator, 'x', max_payload_len);
    try payload.appendSlice(std.testing.allocator, "\"}");

    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [2048]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try decideCommand(std.testing.io, .prompt, &.{ "--json", payload.items }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.general, code);
    // Oversize is rejected before evaluation; no typed decision JSON (usage/size guard).
    try std.testing.expectEqualStrings("", stdout_writer.buffered());
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "JSON payload exceeds maximum size") != null);
}

// ---------------------------------------------------------------------------
// U2: user-shaped coding DCG create-path proof (product agentPresetText)
// ---------------------------------------------------------------------------

/// Run `ryk decide command` against an explicit policy path; return exit code + stdout.
fn decideCommandUnderPolicy(
    policy_path: []const u8,
    command_json: []const u8,
    stdout_buf: []u8,
    stderr_buf: []u8,
) !struct { u8, []const u8 } {
    var stdout_writer: std.Io.Writer = .fixed(stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(stderr_buf);
    const code = try decideCommandWithPolicy(
        std.testing.io,
        .command,
        &.{ "--json", command_json },
        &stdout_writer,
        &stderr_writer,
        policy_path,
    );
    return .{ code, stdout_writer.buffered() };
}

test "coding DCG create-path decide: normal allow, danger block, unmatched never ask" {
    // Product create-path body — same text `ryk init --preset generic-agent` writes
    // via agentPresetText (coding_dcg_policy). Not a hand-rolled stub.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "policy.yaml",
        .data = policy.presets.agentPresetText(.generic_agent),
    });
    const policy_path = try tmp.dir.realPathFileAlloc(std.testing.io, "policy.yaml", std.testing.allocator);
    defer std.testing.allocator.free(policy_path);

    var stdout_buf: [8192]u8 = undefined;
    var stderr_buf: [1024]u8 = undefined;

    // 1) Normal day-to-day work → allow (exit 0), never ask.
    {
        const code, const output = try decideCommandUnderPolicy(
            policy_path,
            "{\"command\":\"true\"}",
            &stdout_buf,
            &stderr_buf,
        );
        try std.testing.expectEqual(exit_codes.success, code);
        try std.testing.expect(std.mem.indexOf(u8, output, "\"decision\": \"allow\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, output, "\"decision\": \"ask\"") == null);
    }
    {
        const code, const output = try decideCommandUnderPolicy(
            policy_path,
            "{\"command\":\"git status\"}",
            &stdout_buf,
            &stderr_buf,
        );
        try std.testing.expectEqual(exit_codes.success, code);
        try std.testing.expect(std.mem.indexOf(u8, output, "\"decision\": \"allow\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, output, "\"decision\": \"ask\"") == null);
    }

    // 2) Catastrophe / destructive → block (deny), not ask.
    {
        const code, const output = try decideCommandUnderPolicy(
            policy_path,
            "{\"command\":\"rm -rf /\"}",
            &stdout_buf,
            &stderr_buf,
        );
        try std.testing.expectEqual(exit_codes.denial, code);
        try std.testing.expect(std.mem.indexOf(u8, output, "\"decision\": \"block\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, output, "\"decision\": \"ask\"") == null);
    }
    {
        const code, const output = try decideCommandUnderPolicy(
            policy_path,
            "{\"command\":\"git reset --hard\"}",
            &stdout_buf,
            &stderr_buf,
        );
        try std.testing.expectEqual(exit_codes.denial, code);
        try std.testing.expect(std.mem.indexOf(u8, output, "\"decision\": \"block\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, output, "\"decision\": \"ask\"") == null);
    }

    // 3) Representative unmatched command that previously asked under old
    // generic-agent (commands.default: ask) must NOT return ask.
    {
        const code, const output = try decideCommandUnderPolicy(
            policy_path,
            "{\"command\":\"chmod -R 777 .\"}",
            &stdout_buf,
            &stderr_buf,
        );
        try std.testing.expect(code != exit_codes.ask);
        try std.testing.expect(std.mem.indexOf(u8, output, "\"decision\": \"ask\"") == null);
        // DCG matrix-only + default allow → allow (packs do not fence chmod).
        try std.testing.expectEqual(exit_codes.success, code);
        try std.testing.expect(std.mem.indexOf(u8, output, "\"decision\": \"allow\"") != null);
    }

    // 4) Medium pack hit under coding DCG (mode: strict) → block, never ask.
    {
        const code, const output = try decideCommandUnderPolicy(
            policy_path,
            "{\"command\":\"git branch -D feature\"}",
            &stdout_buf,
            &stderr_buf,
        );
        try std.testing.expectEqual(exit_codes.denial, code);
        try std.testing.expect(std.mem.indexOf(u8, output, "\"decision\": \"block\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, output, "\"decision\": \"ask\"") == null);
        try std.testing.expect(std.mem.indexOf(u8, output, "core.git:branch-force-delete") != null);
    }
}

test "coding DCG on-disk generic-agent YAML: decide path matches create-path" {
    // Same user-shaped checks against shipped policies/presets/generic-agent.yaml.
    const policy_path = try std.Io.Dir.cwd().realPathFileAlloc(
        std.testing.io,
        "policies/presets/generic-agent.yaml",
        std.testing.allocator,
    );
    defer std.testing.allocator.free(policy_path);

    var stdout_buf: [8192]u8 = undefined;
    var stderr_buf: [1024]u8 = undefined;

    {
        const code, const output = try decideCommandUnderPolicy(
            policy_path,
            "{\"command\":\"git status\"}",
            &stdout_buf,
            &stderr_buf,
        );
        try std.testing.expectEqual(exit_codes.success, code);
        try std.testing.expect(std.mem.indexOf(u8, output, "\"decision\": \"allow\"") != null);
    }
    {
        const code, const output = try decideCommandUnderPolicy(
            policy_path,
            "{\"command\":\"rm -rf /\"}",
            &stdout_buf,
            &stderr_buf,
        );
        try std.testing.expectEqual(exit_codes.denial, code);
        try std.testing.expect(std.mem.indexOf(u8, output, "\"decision\": \"block\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, output, "\"decision\": \"ask\"") == null);
    }
    {
        const code, const output = try decideCommandUnderPolicy(
            policy_path,
            "{\"command\":\"chmod -R 777 .\"}",
            &stdout_buf,
            &stderr_buf,
        );
        try std.testing.expect(code != exit_codes.ask);
        try std.testing.expect(std.mem.indexOf(u8, output, "\"decision\": \"ask\"") == null);
        try std.testing.expectEqual(exit_codes.success, code);
        try std.testing.expect(std.mem.indexOf(u8, output, "\"decision\": \"allow\"") != null);
    }
}

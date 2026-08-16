//! Door A (P2-1) deadlock transcript replay.
//!
//! Replays the documented coding-agent deadlock sessions end-to-end against
//! the shipped generic-agent default on both product surfaces:
//!
//!   1. decide surface — `ryk decide command --json` (host plugins: Codex,
//!      Claude Code, OpenCode, …), pinned to policies/presets/generic-agent.yaml
//!      so the test is hermetic on any checkout.
//!   2. hook surface — live composition: shell_engine packs plus
//!      `permitFromCommandsAllow` from the loaded policy (PreToolUse hooks,
//!      PATH shims).
//!
//! Corpus: deadlock_replay_corpus.jsonl — one JSON object per line:
//! {"command": "...", "expect": "allow"|"deny", "note": "..."}
//!
//! Corpus exercises lived Grok strict off-list refuse sessions and day-to-day
//! agent scenarios. Every line must
//! produce the same product decision on both surfaces: normal work allows,
//! danger blocks. A failure here means an agent host can deadlock again.

const std = @import("std");

const decide = @import("decide.zig");
const exit_codes = @import("exit_codes.zig");
const shell_eval = @import("shell_eval.zig");
const shell_engine = @import("../shell_engine/mod.zig");
const ryk_policy = @import("ryk_core").policy;

const corpus = @embedFile("deadlock_replay_corpus.jsonl");

const Case = struct {
    command: []const u8,
    expect: []const u8,
    note: []const u8,
};

fn parseLine(line: []const u8) !Case {
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, line, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;
    return .{
        .command = try std.testing.allocator.dupe(u8, obj.get("command").?.string),
        .expect = try std.testing.allocator.dupe(u8, obj.get("expect").?.string),
        .note = try std.testing.allocator.dupe(u8, if (obj.get("note")) |n| n.string else ""),
    };
}

fn freeCase(case: Case) void {
    std.testing.allocator.free(case.command);
    std.testing.allocator.free(case.expect);
    std.testing.allocator.free(case.note);
}

fn riskFromEngineSeverity(severity: shell_engine.Severity) shell_eval.RiskLevel {
    return switch (severity) {
        .low => .low,
        .medium => .medium,
        .high => .high,
        .critical => .critical,
    };
}

/// Hook/shim surface: live composition — pack evaluation plus
/// `permitFromCommandsAllow` from the loaded policy (mode + commands.allow).
fn hookSurfaceDecision(
    allocator: std.mem.Allocator,
    policy: *const ryk_policy.schema.Policy,
    command_text: []const u8,
) !shell_eval.PluginDecision {
    var eval = try shell_engine.evaluateCommand(allocator, command_text, .{});
    defer eval.deinit(allocator);

    const outcome: shell_eval.EngineShellOutcome = switch (eval.decision) {
        .allow => .allow,
        .deny => .deny,
    };
    const risk: shell_eval.RiskLevel = if (eval.decision == .deny)
        riskFromEngineSeverity(eval.severity)
    else
        .low;

    const permit = try shell_eval.permitFromCommandsAllow(allocator, policy.commands.allow);
    defer shell_eval.freePermitEntries(allocator, permit);
    var decided = shell_eval.decideShellWithPolicy(policy.mode, outcome, risk, command_text, permit, null, null);
    defer decided.freeOwned(allocator);
    return decided.decision;
}

/// Decide surface: the exact CLI composition host plugins call, pinned to the
/// shipped generic-agent preset.
fn decideSurfaceDecision(io: std.Io, allocator: std.mem.Allocator, policy_path: []const u8, command_text: []const u8) !u8 {
    try std.testing.expect(std.mem.indexOfScalar(u8, command_text, '"') == null);
    const payload = try std.fmt.allocPrint(allocator, "{{\"command\":\"{s}\"}}", .{command_text});
    defer allocator.free(payload);

    var stdout_buf: [16384]u8 = undefined;
    var stderr_buf: [2048]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try decide.decideCommandWithPolicy(io, .command, &.{
        "--json", payload,
    }, &stdout_writer, &stderr_writer, policy_path);

    const output = stdout_writer.buffered();
    if (std.mem.indexOf(u8, output, "\"decision\": \"allow\"") != null) {
        try std.testing.expectEqual(exit_codes.success, code);
        return exit_codes.success;
    }
    if (std.mem.indexOf(u8, output, "\"decision\": \"block\"") != null) {
        try std.testing.expectEqual(exit_codes.denial, code);
        return exit_codes.denial;
    }
    std.debug.print("unexpected decide output for `{s}`: {s}\n", .{ command_text, output });
    return error.UnexpectedDecisionOutput;
}

test "Door A deadlock transcripts replay clean on both product surfaces" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const policy_path = try std.Io.Dir.cwd().realPathFileAlloc(io, "policies/presets/generic-agent.yaml", allocator);
    defer allocator.free(policy_path);
    var policy = try ryk_policy.load.parseFromSlice(
        allocator,
        ryk_policy.presets.agentPresetText(.generic_agent),
        "generic-agent.yaml",
    );
    defer policy.deinit();

    var total: usize = 0;
    var it = std.mem.splitScalar(u8, corpus, '\n');
    while (it.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0) continue;
        const case = try parseLine(line);
        defer freeCase(case);
        total += 1;

        const hook = try hookSurfaceDecision(allocator, &policy, case.command);
        const decide_code = try decideSurfaceDecision(io, allocator, policy_path, case.command);

        if (std.mem.eql(u8, case.expect, "allow")) {
            std.testing.expectEqual(shell_eval.PluginDecision.allow, hook) catch |err| {
                std.debug.print("hook surface blocked normal work `{s}` ({s})\n", .{ case.command, case.note });
                return err;
            };
            std.testing.expectEqual(exit_codes.success, decide_code) catch |err| {
                std.debug.print("decide surface blocked normal work `{s}` ({s})\n", .{ case.command, case.note });
                return err;
            };
        } else if (std.mem.eql(u8, case.expect, "deny")) {
            std.testing.expectEqual(shell_eval.PluginDecision.block, hook) catch |err| {
                std.debug.print("hook surface allowed danger `{s}` ({s})\n", .{ case.command, case.note });
                return err;
            };
            std.testing.expectEqual(exit_codes.denial, decide_code) catch |err| {
                std.debug.print("decide surface allowed danger `{s}` ({s})\n", .{ case.command, case.note });
                return err;
            };
        } else {
            std.debug.print("unknown expect value `{s}` in corpus line for `{s}`\n", .{ case.expect, case.command });
            return error.InvalidCorpusExpectation;
        }
    }
    try std.testing.expect(total >= 20);
}

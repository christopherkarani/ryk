//! Daemon-shaped Evaluate JSON from a Zig shell_engine result.
//! Includes explain metadata for local audit/feed consumers. Agent-facing hook
//! JSON remains thin at the presentation layer (hosts only use stable fields).
//! No daemon.evaluate.

const std = @import("std");
const daemon = @import("daemon.zig");
const shell_engine = @import("../shell_engine/mod.zig");

/// Build a daemon-shaped Evaluate JSON response from a Zig shell_engine result.
pub fn synthesizeDaemonResponseFromZig(
    allocator: std.mem.Allocator,
    eval: shell_engine.Evaluation,
) daemon.DaemonError!std.json.Parsed(daemon.DaemonResponse) {
    const status = switch (eval.decision) {
        .allow => "Allow",
        .deny => "Deny",
    };

    const SuggestionJson = struct { description: []const u8 };
    const PipelineJson = struct { name: []const u8, duration_us: u64 = 0, detail: ?[]const u8 = null };

    // Map static tips into the suggestion objects hooks already understand.
    var suggestion_objs: std.ArrayList(SuggestionJson) = .empty;
    defer suggestion_objs.deinit(allocator);
    for (eval.tips) |tip| {
        suggestion_objs.append(allocator, .{ .description = tip }) catch return error.OutOfMemory;
    }

    // Hooks use collector=null → empty pipeline (zero cost). Audit may still
    // carry tips/match fields when present on Evaluation.
    var pipeline_objs: std.ArrayList(PipelineJson) = .empty;
    defer pipeline_objs.deinit(allocator);
    for (eval.trace) |step| {
        pipeline_objs.append(allocator, .{
            .name = step.name,
            .duration_us = step.duration_us,
            .detail = step.detail,
        }) catch return error.OutOfMemory;
    }

    const payload = struct {
        id: u64 = 1,
        result: struct {
            status: []const u8,
            reason: []const u8,
            pack_id: ?[]const u8 = null,
            pattern_name: ?[]const u8 = null,
            severity: []const u8,
            explanation: ?[]const u8 = null,
            regex_source: ?[]const u8 = null,
            match_start: ?usize = null,
            match_end: ?usize = null,
            matched_text: ?[]const u8 = null,
            matched_candidate: ?[]const u8 = null,
            latency_ms: u64 = 0,
            suggestions: []const SuggestionJson = &.{},
            pipeline: []const PipelineJson = &.{},
            source: []const u8 = "zig.shell_engine",
        },
    }{
        .result = .{
            .status = status,
            .reason = eval.reason,
            .pack_id = eval.pack_id,
            .pattern_name = eval.pattern_name,
            .severity = eval.severity.toString(),
            .explanation = eval.explanation,
            .regex_source = eval.regex_source,
            .match_start = eval.match_start,
            .match_end = eval.match_end,
            .matched_text = eval.matched_text,
            .matched_candidate = eval.matched_candidate,
            .latency_ms = eval.latency_ms,
            .suggestions = suggestion_objs.items,
            .pipeline = pipeline_objs.items,
        },
    };
    const json_str = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch return error.OutOfMemory;
    defer allocator.free(json_str);
    return std.json.parseFromSlice(daemon.DaemonResponse, allocator, json_str, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = true,
    }) catch return error.ResponseParseFailed;
}

test "synthesizeDaemonResponseFromZig maps Allow/Deny status and zig.shell_engine source" {
    const allocator = std.testing.allocator;

    const allow_eval = shell_engine.Evaluation{
        .decision = .allow,
        .reason = "safe",
        .owned = false,
    };
    var allow_parsed = try synthesizeDaemonResponseFromZig(allocator, allow_eval);
    defer allow_parsed.deinit();
    try std.testing.expectEqual(daemon.ResponseStatus.allow, daemon.responseStatus(allow_parsed.value.result));
    try std.testing.expectEqualStrings(
        "zig.shell_engine",
        daemon.responseStringField(allow_parsed.value.result, "source") orelse "",
    );

    const deny_eval = shell_engine.Evaluation{
        .decision = .deny,
        .reason = "blocked",
        .severity = .critical,
        .owned = false,
    };
    var deny_parsed = try synthesizeDaemonResponseFromZig(allocator, deny_eval);
    defer deny_parsed.deinit();
    try std.testing.expectEqual(daemon.ResponseStatus.deny, daemon.responseStatus(deny_parsed.value.result));
    try std.testing.expectEqualStrings(
        "zig.shell_engine",
        daemon.responseStringField(deny_parsed.value.result, "source") orelse "",
    );
}

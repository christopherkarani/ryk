//! Shared pretty / JSON rendering for shell-engine explain surfaces.
//! DCG nest rule: each pipeline step is `name (duration)` with one details child.
const std = @import("std");
const shell_engine = @import("../shell_engine/mod.zig");
const theme = @import("../tui/theme.zig");
const terminal_text = @import("../tui/terminal_text.zig");
const reasons = @import("../tui/reasons.zig");

/// Glanceable Decision line. Colors only DENY on a colour TTY; ALLOW stays plain.
pub fn writeDecisionLine(io: std.Io, writer: anytype, decision: shell_engine.Decision) !void {
    try writer.writeAll("Decision: ");
    switch (decision) {
        .allow => try writer.writeAll("ALLOW"),
        .deny => try theme.paint(io, writer, .danger, "DENY"),
    }
    try writer.writeAll("\n");
}

/// Glanceable human receipt: decision + why. Deny names the rule and a safer
/// command (that Safer line is the one action). Allow stays quiet (no Always /
/// allowlist / Safer / Next chrome). Inspect verbs do not ping-pong Next.
pub fn writePretty(io: std.Io, writer: anytype, command_text: []const u8, eval: shell_engine.Evaluation) !void {
    try writeDecisionLine(io, writer, eval.decision);
    try writer.print("Why: {s}\n", .{eval.reason});
    if (eval.decision == .deny) {
        if (eval.rule_id) |rid| try writer.print("Rule: {s}\n", .{rid});
        const alts = try reasons.safeAlternatives(std.heap.smp_allocator, command_text);
        defer {
            for (alts) |a| std.heap.smp_allocator.free(a.command);
            std.heap.smp_allocator.free(alts);
        }
        if (alts.len > 0) try writer.print("Safer: {s}\n", .{alts[0].command});
    }
}

/// Verbose DCG-style decision tree (regex / latency stay in JSON).
pub fn writePrettyVerbose(io: std.Io, writer: anytype, command_text: []const u8, eval: shell_engine.Evaluation) !void {
    try theme.paintBold(io, writer, .brand, "RYK EXPLAIN");
    try writer.writeAll("\n");

    // Decision — colored DENY/ALLOW like DCG
    try writeBranch(io, writer, false, "Decision", .text_bright);
    {
        const dec_label = switch (eval.decision) {
            .allow => "ALLOW",
            .deny => "DENY",
        };
        const tok: theme.Token = switch (eval.decision) {
            .allow => .success,
            .deny => .danger,
        };
        try writeTreePrefix(writer, false, true);
        try theme.paint(io, writer, .muted, "Decision: ");
        try theme.paintBold(io, writer, tok, dec_label);
        try writer.writeAll("\n");
    }

    // Command
    try writeBranch(io, writer, false, "Command", .info);
    try writeTreePrefix(writer, false, true);
    try theme.paint(io, writer, .muted, "Input: ");
    try terminal_text.write(writer, command_text, .single_line);
    try writer.writeAll("\n");

    // Match (deny only) — sibling section, never a pipeline step named `matched`
    if (eval.decision == .deny) {
        try writeBranch(io, writer, false, "Match", .warn);
        var lines: std.ArrayList(struct { k: []const u8, v: []const u8 }) = .empty;
        defer lines.deinit(std.heap.smp_allocator);
        const a = std.heap.smp_allocator;
        try lines.append(a, .{ .k = "Rule ID", .v = eval.rule_id orelse "(none)" });
        try lines.append(a, .{ .k = "Pack", .v = eval.pack_id orelse "(none)" });
        try lines.append(a, .{ .k = "Pattern", .v = eval.pattern_name orelse "(none)" });
        try lines.append(a, .{ .k = "Severity", .v = eval.severity.toString() });
        try lines.append(a, .{ .k = "Reason", .v = eval.reason });
        if (eval.explanation) |ex| try lines.append(a, .{ .k = "Explanation", .v = ex });
        if (eval.matched_text) |mt| try lines.append(a, .{ .k = "Matched", .v = mt });
        if (eval.matched_candidate) |mc| {
            if (!std.mem.eql(u8, mc, command_text)) {
                try lines.append(a, .{ .k = "Matched on", .v = mc });
            }
        }
        for (lines.items, 0..) |row, idx| {
            try writeKvChild(io, writer, false, idx + 1 == lines.items.len, row.k, row.v);
        }
    }

    // Pipeline Trace — nest rule: name (duration) → details child
    try writeBranch(io, writer, false, "Pipeline Trace", .info);
    if (eval.trace.len == 0) {
        try writeTreePrefix(writer, false, true);
        try theme.paint(io, writer, .muted, "(no steps recorded)");
        try writer.writeAll("\n");
    } else {
        for (eval.trace, 0..) |step, i| {
            const last_step = i + 1 == eval.trace.len;
            // Parent: name (duration)
            try writeTreePrefix(writer, false, last_step);
            try writer.writeAll(step.name);
            try writer.writeAll(" (");
            try writeStepDuration(writer, step);
            try writer.writeAll(")");
            try writer.writeAll("\n");
            // Nested details child under this step (never a peer `matched` step)
            if (step.detail) |d| {
                // Child of the step node: two levels of indent under Pipeline Trace
                try writeNestedChildPrefix(writer, false, last_step, true);
                try terminal_text.write(writer, d, .single_line);
                try writer.writeAll("\n");
            }
        }
    }

    // Suggestions (last root section)
    try writeBranch(io, writer, true, "Suggestions", .warn);
    if (eval.tips.len == 0) {
        try writeTreePrefix(writer, true, true);
        try theme.paint(io, writer, .muted, "(none)");
        try writer.writeAll("\n");
    } else {
        for (eval.tips, 0..) |tip, i| {
            const last = i + 1 == eval.tips.len;
            try writeTreePrefix(writer, true, last);
            try terminal_text.write(writer, tip, .single_line);
            try writer.writeAll("\n");
        }
    }
}

fn writeStepDuration(writer: anytype, step: shell_engine.TraceStep) !void {
    var buf: [32]u8 = undefined;
    if (step.duration_us > 0) {
        try writer.writeAll(shell_engine.trace.formatDurationMs(step.duration_us, &buf));
    } else {
        try writer.writeAll("0ms");
    }
}

fn writeBranch(io: std.Io, writer: anytype, last_root: bool, label: []const u8, token: theme.Token) !void {
    try writer.writeAll(if (last_root) "└── " else "├── ");
    try theme.paintBold(io, writer, token, label);
    try writer.writeAll("\n");
}

/// `parent_last` true when the parent root section is the final one (no continuing vertical bar).
fn writeTreePrefix(writer: anytype, parent_last: bool, last_child: bool) !void {
    try writer.writeAll(if (parent_last) "    " else "│   ");
    try writer.writeAll(if (last_child) "└── " else "├── ");
}

/// Prefix for a child nested under a pipeline step (two levels under root section).
fn writeNestedChildPrefix(writer: anytype, root_last: bool, step_last: bool, child_last: bool) !void {
    try writer.writeAll(if (root_last) "    " else "│   ");
    try writer.writeAll(if (step_last) "    " else "│   ");
    try writer.writeAll(if (child_last) "└── " else "├── ");
}

fn writeKvChild(io: std.Io, writer: anytype, parent_last: bool, last: bool, key: []const u8, value: []const u8) !void {
    try writeTreePrefix(writer, parent_last, last);
    try theme.paint(io, writer, .muted, key);
    try writer.writeAll(": ");
    try terminal_text.write(writer, value, .single_line);
    try writer.writeAll("\n");
}

const PipelineJson = struct {
    name: []const u8,
    duration_us: u64 = 0,
    detail: ?[]const u8 = null,
};

pub fn writeJson(allocator: std.mem.Allocator, writer: anytype, command_text: []const u8, eval: shell_engine.Evaluation) !void {
    var trace_objs: std.ArrayList(PipelineJson) = .empty;
    defer trace_objs.deinit(allocator);
    for (eval.trace) |step| {
        try trace_objs.append(allocator, .{
            .name = step.name,
            .duration_us = step.duration_us,
            .detail = step.detail,
        });
    }

    const payload = struct {
        schema_version: i64 = 2,
        command: []const u8,
        decision: []const u8,
        rule_id: ?[]const u8 = null,
        pack_id: ?[]const u8 = null,
        pattern_name: ?[]const u8 = null,
        severity: []const u8,
        reason: []const u8,
        explanation: ?[]const u8 = null,
        regex_source: ?[]const u8 = null,
        match_start: ?usize = null,
        match_end: ?usize = null,
        matched_text: ?[]const u8 = null,
        matched_candidate: ?[]const u8 = null,
        suggestions: []const []const u8,
        pipeline: []const PipelineJson,
        latency_ms: u64,
        source: []const u8 = "zig.shell_engine",
    }{
        .command = command_text,
        .decision = eval.decision.toString(),
        .rule_id = eval.rule_id,
        .pack_id = eval.pack_id,
        .pattern_name = eval.pattern_name,
        .severity = eval.severity.toString(),
        .reason = eval.reason,
        .explanation = eval.explanation,
        .regex_source = eval.regex_source,
        .match_start = eval.match_start,
        .match_end = eval.match_end,
        .matched_text = eval.matched_text,
        .matched_candidate = eval.matched_candidate,
        .suggestions = eval.tips,
        .pipeline = trace_objs.items,
        .latency_ms = eval.latency_ms,
    };
    const json = try std.json.Stringify.valueAlloc(allocator, payload, .{});
    defer allocator.free(json);
    try writer.writeAll(json);
    try writer.writeAll("\n");
}

test "writePretty is a glanceable decision receipt" {
    theme.setTestActive(.{ .capability = .none, .background = .dark });
    defer theme.setTestActive(null);
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const eval = shell_engine.Evaluation{
        .decision = .deny,
        .rule_id = "core.filesystem:rm-rf-general",
        .pack_id = "core.filesystem",
        .pattern_name = "rm-rf-general",
        .severity = .high,
        .reason = "destructive",
        .explanation = "Matched pattern.",
        .regex_source = "rm\\\\s+",
        .match_start = 0,
        .match_end = 6,
        .matched_text = "rm -rf",
        .tips = &.{"Preview first: list the target"},
        .trace = &.{.{
            .name = "full_evaluation",
            .duration_us = 20_000,
            .detail = "matched: core.filesystem (rm-rf-general)",
        }},
        .latency_ms = 12,
        .owned = false,
    };
    try writePretty(std.testing.io, &w, "rm -rf /", eval);
    const out = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "\x1b[") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Decision: DENY") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Why: destructive") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Rule: core.filesystem:rm-rf-general") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Safer:") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "rm -rf ./build") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Always") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "always") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Next: ryk test") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Next: ryk explain") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Next:") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Pipeline Trace") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "full_evaluation") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Regex") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "rm\\\\s+") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Latency") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Span") == null);
}

test "writePretty allow path is a glanceable receipt" {
    theme.setTestActive(.{ .capability = .none, .background = .dark });
    defer theme.setTestActive(null);
    var buf: [2048]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const eval = shell_engine.Evaluation{
        .decision = .allow,
        .severity = .low,
        .reason = "No destructive pack matched.",
        .trace = &.{.{
            .name = "full_evaluation",
            .duration_us = 5_000,
            .detail = "no destructive pack matched",
        }},
        .latency_ms = 5,
        .owned = false,
    };
    try writePretty(std.testing.io, &w, "git status", eval);
    const out = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "\x1b[") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Decision: ALLOW") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Why: No destructive pack matched.") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Next:") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Always") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "always") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "allowlist") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Safer:") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Rule:") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "full_evaluation") == null);
}

fn expectCsiOnlyOnDecisionLine(out: []const u8) !void {
    var it = std.mem.splitScalar(u8, out, '\n');
    var saw_decision = false;
    while (it.next()) |line| {
        const has_csi = std.mem.indexOf(u8, line, "\x1b[") != null;
        if (std.mem.indexOf(u8, line, "Decision:") != null) {
            saw_decision = true;
            try std.testing.expect(has_csi);
            try std.testing.expect(std.mem.indexOf(u8, line, "DENY") != null);
        } else {
            try std.testing.expect(!has_csi);
        }
    }
    try std.testing.expect(saw_decision);
}

test "writePretty colors DENY Decision only" {
    theme.setTestActive(.{ .capability = .truecolor, .background = .dark });
    defer theme.setTestActive(null);
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const eval = shell_engine.Evaluation{
        .decision = .deny,
        .rule_id = "core.filesystem:rm-rf-general",
        .pack_id = "core.filesystem",
        .pattern_name = "rm-rf-general",
        .severity = .high,
        .reason = "destructive",
        .owned = false,
    };
    try writePretty(std.testing.io, &w, "rm -rf /", eval);
    const out = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "\x1b[") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Decision:") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "DENY") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Why: destructive") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Rule: core.filesystem:rm-rf-general") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Safer:") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Next: ryk test") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Next: ryk explain") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Next:") == null);
    try expectCsiOnlyOnDecisionLine(out);
}

test "writePretty deny without safer has no inspect Next" {
    theme.setTestActive(.{ .capability = .none, .background = .dark });
    defer theme.setTestActive(null);
    var buf: [2048]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const eval = shell_engine.Evaluation{
        .decision = .deny,
        .rule_id = "core.git:reset-hard",
        .severity = .high,
        .reason = "destructive",
        .owned = false,
    };
    try writePretty(std.testing.io, &w, "git reset --hard", eval);
    const out = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "Decision: DENY") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Safer:") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Next: ryk test") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Next: ryk explain") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Next:") == null);
}

test "writePretty ALLOW stays uncolored" {
    theme.setTestActive(.{ .capability = .truecolor, .background = .dark });
    defer theme.setTestActive(null);
    var buf: [2048]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const eval = shell_engine.Evaluation{
        .decision = .allow,
        .severity = .low,
        .reason = "No destructive pack matched.",
        .owned = false,
    };
    try writePretty(std.testing.io, &w, "git status", eval);
    const out = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "\x1b[") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Decision: ALLOW") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Why: No destructive pack matched.") != null);
}

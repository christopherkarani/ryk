//! Door A (P2-1d) deadlock self-check.
//!
//! Replays a standard coding workflow against the *active* policy and reports
//! every step that would not behave: normal work that would ask or deny (the
//! deadlock class that makes users disable ryk), and danger that would be
//! allowed (a fence hole). Surfaced as `ryk doctor --deadlock-check`.
//!
//! The workflow is the same corpus the regression replay test uses
//! (`deadlock_replay_corpus.jsonl`), so the product self-check and the CI test
//! can never drift: each documented deadlock transcript line is checked on the
//! user's real policy, not just on the shipped preset.

const std = @import("std");

const core = @import("ryk_core").core;
const core_api = @import("ryk_core").api;
const ryk_policy = @import("ryk_core").policy;
const decide = @import("decide.zig");
const shell_engine = @import("../shell_engine/mod.zig");

pub const corpus_jsonl = @embedFile("deadlock_replay_corpus.jsonl");

pub const Expect = enum {
    allow,
    deny,

    fn parse(value: []const u8) ?Expect {
        if (std.mem.eql(u8, value, "allow")) return .allow;
        if (std.mem.eql(u8, value, "deny")) return .deny;
        return null;
    }
};

pub const Step = struct {
    command: []const u8,
    expect: Expect,
    /// Why this step is in the corpus (transcript provenance).
    note: []const u8,
};

pub const StepOutcome = struct {
    step: Step,
    actual: decide.PluginDecision,

    /// A step is satisfied when normal work runs and danger does not.
    /// `ask` counts as a failure for `allow` steps: several hosts hard-block
    /// `ask` with no resume, which is the deadlock we are hunting.
    pub fn ok(self: StepOutcome) bool {
        return switch (self.step.expect) {
            .allow => self.actual == .allow or self.actual == .context_only,
            .deny => self.actual != .allow and self.actual != .context_only,
        };
    }
};

pub const Report = struct {
    outcomes: []StepOutcome,

    pub fn deinit(self: *Report, allocator: std.mem.Allocator) void {
        allocator.free(self.outcomes);
        self.* = undefined;
    }

    pub fn total(self: *const Report) usize {
        return self.outcomes.len;
    }

    /// Normal-work steps that would ask/deny — the adoption blocker.
    pub fn deadlockCount(self: *const Report) usize {
        var count: usize = 0;
        for (self.outcomes) |outcome| {
            if (outcome.step.expect == .allow and !outcome.ok()) count += 1;
        }
        return count;
    }

    /// Danger steps that would be allowed — a fence hole.
    pub fn fenceHoleCount(self: *const Report) usize {
        var count: usize = 0;
        for (self.outcomes) |outcome| {
            if (outcome.step.expect == .deny and !outcome.ok()) count += 1;
        }
        return count;
    }

    pub fn clean(self: *const Report) bool {
        return self.deadlockCount() == 0 and self.fenceHoleCount() == 0;
    }
};

/// Parse one corpus line. Slices borrow from `line`, which borrows from the
/// embedded corpus, so no allocation and no ownership to track.
fn parseLine(allocator: std.mem.Allocator, line: []const u8) !?Step {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, line, .{}) catch return null;
    defer parsed.deinit();
    if (parsed.value != .object) return null;
    const obj = parsed.value.object;

    const command_value = obj.get("command") orelse return null;
    const expect_value = obj.get("expect") orelse return null;
    if (command_value != .string or expect_value != .string) return null;
    const expect = Expect.parse(expect_value.string) orelse return null;

    // Re-slice into the source line so the returned Step outlives `parsed`.
    const command = std.mem.indexOf(u8, line, command_value.string) orelse return null;
    const note: []const u8 = blk: {
        const note_value = obj.get("note") orelse break :blk "";
        if (note_value != .string) break :blk "";
        const at = std.mem.indexOf(u8, line, note_value.string) orelse break :blk "";
        break :blk line[at .. at + note_value.string.len];
    };

    return .{
        .command = line[command .. command + command_value.string.len],
        .expect = expect,
        .note = note,
    };
}

/// Decide one step exactly as the decide surface would: YAML policy evaluation
/// merged with the shell pack fence via the shared precedence resolver. Any
/// evaluation failure is reported as `block` (fail closed), which shows up as a
/// deadlock for normal-work steps — exactly what an operator needs to see.
fn stepDecision(
    allocator: std.mem.Allocator,
    policy: *const ryk_policy.schema.Policy,
    command_text: []const u8,
) decide.PluginDecision {
    const evaluation = core_api.explainAction(allocator, @ptrCast(policy), .command, command_text) catch return .block;
    defer evaluation.deinit(allocator);

    var shell = shell_engine.evaluateCommand(allocator, command_text, .{}) catch return .block;
    defer shell.deinit(allocator);

    return decide.resolveCommandFence(
        evaluation.decision.result,
        policy.mode,
        shell.decision,
        shell.severity,
        false,
    ).decision;
}

/// Evaluate the whole workflow against `policy`.
pub fn run(allocator: std.mem.Allocator, policy: *const ryk_policy.schema.Policy) !Report {
    var outcomes: std.ArrayList(StepOutcome) = .empty;
    errdefer outcomes.deinit(allocator);

    var it = std.mem.splitScalar(u8, corpus_jsonl, '\n');
    while (it.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0) continue;
        const step = try parseLine(allocator, line) orelse continue;
        try outcomes.append(allocator, .{
            .step = step,
            .actual = stepDecision(allocator, policy, step.command),
        });
    }

    return .{ .outcomes = try outcomes.toOwnedSlice(allocator) };
}

/// Where the checked policy came from. A `builtin` origin means no policy file
/// was found at all, which needs different advice from a stale file on disk.
pub const PolicyOrigin = enum { file, builtin };

/// Operator report. Clean runs stay one line; failures name the command, the
/// decision, and the transcript note so the fix is obvious.
pub fn writeReport(
    stdout: anytype,
    report: *const Report,
    policy_label: []const u8,
    origin: PolicyOrigin,
) !void {
    try stdout.writeAll("Deadlock check\n");
    try stdout.print("  Policy: {s}", .{policy_label});
    if (origin == .builtin) try stdout.writeAll("  (no policy file found — built-in fallback)");
    try stdout.writeByte('\n');
    try stdout.print("  Workflow steps: {d}\n", .{report.total()});

    if (report.clean()) {
        try stdout.writeAll("  OK: normal coding work runs unattended and danger stays blocked.\n");
        return;
    }

    if (report.deadlockCount() > 0) {
        try stdout.print("  DEADLOCK: {d} normal step(s) would stall an agent:\n", .{report.deadlockCount()});
        for (report.outcomes) |outcome| {
            if (outcome.step.expect != .allow or outcome.ok()) continue;
            try stdout.print("    {s} → {s}", .{ outcome.step.command, outcome.actual.toString() });
            if (outcome.step.note.len > 0) try stdout.print("  ({s})", .{outcome.step.note});
            try stdout.writeByte('\n');
        }
    }
    if (report.fenceHoleCount() > 0) {
        try stdout.print("  FENCE HOLE: {d} dangerous step(s) would be allowed:\n", .{report.fenceHoleCount()});
        for (report.outcomes) |outcome| {
            if (outcome.step.expect != .deny or outcome.ok()) continue;
            try stdout.print("    {s} → {s}", .{ outcome.step.command, outcome.actual.toString() });
            if (outcome.step.note.len > 0) try stdout.print("  ({s})", .{outcome.step.note});
            try stdout.writeByte('\n');
        }
    }
    switch (origin) {
        // No file anywhere: ryk falls back to the built-in strict preset, whose
        // permit list refuses anything off-list. Seeding the coding default is
        // the fix — the fallback itself stays fail-closed by design.
        .builtin => {
            try stdout.writeAll("  Next: no policy file was found, so ryk is using the fail-closed built-in\n");
            try stdout.writeAll("        strict preset. Run `ryk doctor --fix` in this workspace to seed the\n");
            try stdout.writeAll("        coding default, then re-run this check.\n");
        },
        .file => {
            try stdout.writeAll("  Next: `ryk doctor --fix` upgrades a pristine old default; otherwise compare\n");
            try stdout.writeAll("        your policy with the generic-agent preset (`ryk init --preset generic-agent --force`\n");
            try stdout.writeAll("        overwrites, so back up customizations first).\n");
        },
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "corpus parses and covers both expectations" {
    const allocator = std.testing.allocator;
    var allow_steps: usize = 0;
    var deny_steps: usize = 0;
    var it = std.mem.splitScalar(u8, corpus_jsonl, '\n');
    while (it.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0) continue;
        const step = (try parseLine(allocator, line)) orelse return error.TestCorpusLineUnparsed;
        try std.testing.expect(step.command.len > 0);
        switch (step.expect) {
            .allow => allow_steps += 1,
            .deny => deny_steps += 1,
        }
    }
    try std.testing.expect(allow_steps >= 15);
    try std.testing.expect(deny_steps >= 5);
}

test "shipped generic-agent default is deadlock free" {
    const allocator = std.testing.allocator;
    var policy = try ryk_policy.load.parseFromSlice(
        allocator,
        ryk_policy.presets.agentPresetText(.generic_agent),
        "generic-agent.yaml",
    );
    defer policy.deinit();

    var report = try run(allocator, &policy);
    defer report.deinit(allocator);

    try std.testing.expect(report.total() >= 20);
    try std.testing.expectEqual(@as(usize, 0), report.deadlockCount());
    try std.testing.expectEqual(@as(usize, 0), report.fenceHoleCount());
    try std.testing.expect(report.clean());
}

test "legacy ask-mode default is reported as deadlocked, not clean" {
    const allocator = std.testing.allocator;
    // The v1.2.13 pre-DCG default is the policy class that stalled coding agents.
    const body = try std.Io.Dir.cwd().readFileAlloc(
        std.testing.io,
        "tests/fixtures/policy-migration/generic-agent-v1.2.13.yaml",
        allocator,
        .limited(1024 * 1024),
    );
    defer allocator.free(body);
    var policy = try ryk_policy.load.parseFromSlice(allocator, body, "legacy.yaml");
    defer policy.deinit();

    var report = try run(allocator, &policy);
    defer report.deinit(allocator);

    try std.testing.expect(report.deadlockCount() > 0);
    try std.testing.expect(!report.clean());

    // Report names at least one stalled command and points at the repair door.
    var buf: [8192]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try writeReport(&writer, &report, "legacy.yaml", .file);
    const out = writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "DEADLOCK") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "ryk doctor --fix") != null);
}

// The lived Grok deadlock (`strict: not on allowlist` on ordinary commands) also
// reproduces with no policy file at all: ryk then falls back to the built-in
// strict preset, whose permit list refuses off-list work. That fallback stays
// fail-closed on purpose — a missing policy is ambiguous state — so the product
// answer is to seed a policy, and the check has to say exactly that instead of
// blaming a stale file that does not exist.
test "built-in strict fallback is reported as deadlocked with seed-a-policy advice" {
    const allocator = std.testing.allocator;
    var policy = try ryk_policy.load.loadPreset(allocator, .strict);
    defer policy.deinit();

    var report = try run(allocator, &policy);
    defer report.deinit(allocator);
    try std.testing.expect(report.deadlockCount() > 0);

    var buf: [8192]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try writeReport(&writer, &report, "builtin:strict", .builtin);
    const out = writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "no policy file found") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "no policy file was found") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "ryk doctor --fix") != null);
    // Must not blame a stale on-disk default when there is no file.
    try std.testing.expect(std.mem.indexOf(u8, out, "upgrades a pristine old default") == null);
}

test "clean report stays short and says so" {
    const allocator = std.testing.allocator;
    var policy = try ryk_policy.load.parseFromSlice(
        allocator,
        ryk_policy.presets.agentPresetText(.generic_agent),
        "generic-agent.yaml",
    );
    defer policy.deinit();
    var report = try run(allocator, &policy);
    defer report.deinit(allocator);

    var buf: [2048]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try writeReport(&writer, &report, ".ryk/policy.yaml", .file);
    const out = writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "OK:") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "DEADLOCK") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "FENCE HOLE") == null);
}

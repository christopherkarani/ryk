//! Shared Door A deadlock corpus: one embed, parsed once.
//!
//! `deadlock_check` and `deadlock_replay` must not each `@embedFile` the
//! JSONL or call `std.json.parseFromSlice` per line. Command/note slices
//! borrow the embedded bytes.

const std = @import("std");

pub const jsonl: []const u8 = @embedFile("deadlock_replay_corpus.jsonl");

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

const Parsed = struct {
    steps: []const Step,
    unparsed: bool,
};

const parsed: Parsed = parseAll(jsonl);

/// Fail-closed view of the shipped corpus. Empty or any unparsed line errors;
/// valid command/note slices borrow `jsonl`.
pub fn parsedSteps() error{ UnparsedCorpus, EmptyCorpus }![]const Step {
    if (parsed.unparsed) return error.UnparsedCorpus;
    if (parsed.steps.len == 0) return error.EmptyCorpus;
    return parsed.steps;
}

fn parseAll(comptime src: []const u8) Parsed {
    @setEvalBranchQuota(100_000);
    var unparsed = false;
    var count: usize = 0;
    {
        var pos: usize = 0;
        while (nextNonEmptyLine(src, &pos)) |line| {
            if (parseLine(line) == null) {
                unparsed = true;
            } else {
                count += 1;
            }
        }
    }
    if (unparsed or count == 0) {
        return .{ .steps = &.{}, .unparsed = unparsed };
    }

    var tmp: [count]Step = undefined;
    var i: usize = 0;
    var pos: usize = 0;
    while (nextNonEmptyLine(src, &pos)) |line| {
        tmp[i] = parseLine(line).?;
        i += 1;
    }
    const frozen = tmp;
    return .{ .steps = &frozen, .unparsed = false };
}

fn nextNonEmptyLine(src: []const u8, pos: *usize) ?[]const u8 {
    while (pos.* < src.len) {
        const from = pos.*;
        const nl = std.mem.indexOfScalarPos(u8, src, from, '\n') orelse src.len;
        pos.* = if (nl < src.len) nl + 1 else src.len;
        const line = std.mem.trim(u8, src[from..nl], " \t\r");
        if (line.len != 0) return line;
    }
    return null;
}

/// Parse one object line. Slices borrow `line`. Missing/invalid fields or
/// JSON escapes return null — do not invent a step.
fn parseLine(line: []const u8) ?Step {
    if (line.len < 2 or line[0] != '{') return null;

    const command = jsonStringField(line, "command") orelse return null;
    const expect_raw = jsonStringField(line, "expect") orelse return null;
    if (command.len == 0) return null;
    const expect = Expect.parse(expect_raw) orelse return null;

    const note: []const u8 = blk: {
        const raw = jsonStringField(line, "note") orelse break :blk "";
        break :blk raw;
    };

    return .{
        .command = command,
        .expect = expect,
        .note = note,
    };
}

/// Return the source slice of a JSON string field, or null if the key is
/// missing, the value is not a string, or the string uses escapes.
fn jsonStringField(line: []const u8, key: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i < line.len) : (i += 1) {
        if (line[i] != '"') continue;
        const key_start = i + 1;
        if (key_start + key.len >= line.len) continue;
        if (!std.mem.eql(u8, line[key_start .. key_start + key.len], key)) continue;
        if (line[key_start + key.len] != '"') continue;

        var j = key_start + key.len + 1;
        while (j < line.len and isSpace(line[j])) j += 1;
        if (j >= line.len or line[j] != ':') continue;
        j += 1;
        while (j < line.len and isSpace(line[j])) j += 1;
        if (j >= line.len or line[j] != '"') return null;

        const val_start = j + 1;
        var k = val_start;
        while (k < line.len) : (k += 1) {
            if (line[k] == '\\') return null;
            if (line[k] == '"') return line[val_start..k];
        }
        return null;
    }
    return null;
}

fn isSpace(c: u8) bool {
    return c == ' ' or c == '\t';
}

test "parsedSteps fail-closed on empty and unparsed input" {
    const empty = comptime parseAll("");
    try std.testing.expect(!empty.unparsed);
    try std.testing.expectEqual(@as(usize, 0), empty.steps.len);

    const blanks = comptime parseAll("\n  \n\t\r\n");
    try std.testing.expect(!blanks.unparsed);
    try std.testing.expectEqual(@as(usize, 0), blanks.steps.len);

    const missing = comptime parseAll("{\"command\":\"x\"}\n");
    try std.testing.expect(missing.unparsed);
    try std.testing.expectEqual(@as(usize, 0), missing.steps.len);

    const bad_expect = comptime parseAll("{\"command\":\"x\",\"expect\":\"maybe\"}\n");
    try std.testing.expect(bad_expect.unparsed);
    try std.testing.expectEqual(@as(usize, 0), bad_expect.steps.len);
}

test "parseLine skips invalid fields and does not invent steps" {
    try std.testing.expect(parseLine("") == null);
    try std.testing.expect(parseLine("{}") == null);
    try std.testing.expect(parseLine("{\"command\":\"x\"}") == null);
    try std.testing.expect(parseLine("{\"command\":\"x\",\"expect\":\"maybe\"}") == null);
    try std.testing.expect(parseLine("{\"command\":\"\",\"expect\":\"allow\"}") == null);
    try std.testing.expect(parseLine("not-json") == null);

    const ok = parseLine("{\"command\":\"true\",\"expect\":\"allow\",\"note\":\"n\"}").?;
    try std.testing.expectEqualStrings("true", ok.command);
    try std.testing.expectEqual(Expect.allow, ok.expect);
    try std.testing.expectEqualStrings("n", ok.note);

    const no_note = parseLine("{\"command\":\"ls\",\"expect\":\"deny\"}").?;
    try std.testing.expectEqualStrings("ls", no_note.command);
    try std.testing.expectEqual(Expect.deny, no_note.expect);
    try std.testing.expectEqualStrings("", no_note.note);
}

test "shipped corpus parsedSteps borrow jsonl and cover both expectations" {
    const steps = try parsedSteps();
    try std.testing.expect(steps.len >= 20);

    var allow_steps: usize = 0;
    var deny_steps: usize = 0;
    const jsonl_start = @intFromPtr(jsonl.ptr);
    const jsonl_end = jsonl_start + jsonl.len;
    for (steps) |step| {
        try std.testing.expect(step.command.len > 0);
        const cmd_ptr = @intFromPtr(step.command.ptr);
        try std.testing.expect(cmd_ptr >= jsonl_start);
        try std.testing.expect(cmd_ptr + step.command.len <= jsonl_end);
        if (step.note.len > 0) {
            const note_ptr = @intFromPtr(step.note.ptr);
            try std.testing.expect(note_ptr >= jsonl_start);
            try std.testing.expect(note_ptr + step.note.len <= jsonl_end);
        }
        switch (step.expect) {
            .allow => allow_steps += 1,
            .deny => deny_steps += 1,
        }
    }
    try std.testing.expect(allow_steps >= 15);
    try std.testing.expect(deny_steps >= 5);
}

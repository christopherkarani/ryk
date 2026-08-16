const std = @import("std");

const core = @import("ryk_core").core;

pub const implemented = true;

pub const ApprovalChoice = enum {
    allow_once,
    allow_session,
    deny,
};

pub const Entry = struct {
    command: []const u8,
    reason: []const u8,
};

pub const SessionApprovals = struct {
    allocator: std.mem.Allocator,
    entries: std.ArrayList(Entry) = .empty,

    pub fn init(allocator: std.mem.Allocator) SessionApprovals {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *SessionApprovals) void {
        for (self.entries.items) |entry| {
            self.allocator.free(entry.command);
            self.allocator.free(entry.reason);
        }
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn contains(self: *const SessionApprovals, command: []const u8) bool {
        for (self.entries.items) |entry| {
            if (std.mem.eql(u8, entry.command, command)) return true;
        }
        return false;
    }

    pub fn allowForSession(self: *SessionApprovals, command: []const u8, reason: []const u8) !void {
        if (self.contains(command)) return;
        // Locals + errdefer: dual-dupe in one append orphaned command on reason/append OOM (M001).
        const owned_command = try self.allocator.dupe(u8, command);
        errdefer self.allocator.free(owned_command);
        const owned_reason = try self.allocator.dupe(u8, reason);
        errdefer self.allocator.free(owned_reason);
        try self.entries.append(self.allocator, .{
            .command = owned_command,
            .reason = owned_reason,
        });
    }
};

pub const PromptRequest = struct {
    command: []const u8,
    risk_class: []const u8,
    risk_reason: []const u8,
    policy_reason: []const u8,
    matched_rule: ?[]const u8 = null,
};

pub fn prompt(reader: *std.Io.Reader, writer: anytype, request: PromptRequest) !ApprovalChoice {
    try writer.writeAll(
        \\ryk wants your approval
        \\
        \\Command:
        \\
    );
    try writer.print("  {s}\n\nRisk:\n  {s}: {s}\n\nPolicy:\n  {s}\n", .{
        boundedForDisplay(request.command),
        request.risk_class,
        request.risk_reason,
        request.policy_reason,
    });
    // Secondary detail only — recovery is Once/Session/Never, not rule ids.
    if (request.matched_rule) |rule| try writer.print("  matched rule: {s}\n", .{rule});
    try writer.writeAll(
        \\
        \\Options:
        \\  [a] Once — allow this time
        \\  [A] Session — allow this session
        \\  [d] Never / Deny
        \\  [?] Explain risk
        \\
        \\Choice (once / session / never):
    );

    while (true) {
        const line = (try reader.takeDelimiter('\n')) orelse return .deny;
        const trimmed = std.mem.trim(u8, line, " \t\r\n");
        if (parseChoice(trimmed)) |choice| return choice;
        if (std.mem.eql(u8, trimmed, "?")) {
            try writer.print("\nRisk explanation: {s}\nChoice (once / session / never): ", .{request.risk_reason});
            continue;
        }
        try writer.writeAll("Choose once, session, never (or a, A, d, ?). Choice: ");
    }
}

/// Map interactive input to an approval choice.
/// Shortcuts: `a` Once, `A` Session, `d` Never.
/// Words (case-insensitive): once | session | never | deny.
/// `always` still maps to session (legacy alias; not advertised).
/// Empty line denies (fail closed). Rule ids are never required.
fn parseChoice(trimmed: []const u8) ?ApprovalChoice {
    if (trimmed.len == 0) return .deny;
    if (std.mem.eql(u8, trimmed, "a")) return .allow_once;
    if (std.mem.eql(u8, trimmed, "A")) return .allow_session;
    if (std.mem.eql(u8, trimmed, "d")) return .deny;

    // Word forms — case-insensitive so "Once" / "ALWAYS" work.
    if (std.ascii.eqlIgnoreCase(trimmed, "once")) return .allow_once;
    if (std.ascii.eqlIgnoreCase(trimmed, "always") or std.ascii.eqlIgnoreCase(trimmed, "session")) return .allow_session;
    if (std.ascii.eqlIgnoreCase(trimmed, "never") or std.ascii.eqlIgnoreCase(trimmed, "deny")) return .deny;
    return null;
}

pub fn applyApproval(
    allocator: std.mem.Allocator,
    decision: core.decision.Decision,
    command: []const u8,
    session_approvals: *SessionApprovals,
    choice: ApprovalChoice,
) !core.decision.Decision {
    switch (choice) {
        .deny => {
            const reason = try std.fmt.allocPrint(allocator, "user denied approval for command: {s}", .{boundedForDisplay(command)});
            return .{ .result = .deny, .reason = reason, .risk_score = decision.risk_score, .ci_may_proceed = false };
        },
        .allow_once => {
            const reason = try std.fmt.allocPrint(allocator, "user approved command once: {s}", .{boundedForDisplay(command)});
            return .{ .result = .allow, .reason = reason, .risk_score = decision.risk_score, .ci_may_proceed = true };
        },
        .allow_session => {
            try session_approvals.allowForSession(command, decision.reason);
            const reason = try std.fmt.allocPrint(allocator, "user approved command for this session: {s}", .{boundedForDisplay(command)});
            return .{ .result = .allow, .reason = reason, .risk_score = decision.risk_score, .ci_may_proceed = true };
        },
    }
}

fn boundedForDisplay(value: []const u8) []const u8 {
    return if (value.len > 512) value[0..512] else value;
}

test "session approval stores exact command for session scope" {
    var approvals = SessionApprovals.init(std.testing.allocator);
    defer approvals.deinit();
    try std.testing.expect(!approvals.contains("npm install"));
    try approvals.allowForSession("npm install", "package install");
    try std.testing.expect(approvals.contains("npm install"));
}

test "allowForSession OOM ownership does not leak command or reason" {
    var saw_oom = false;
    var saw_success = false;
    var fail_index: usize = 0;
    while (fail_index < 8) : (fail_index += 1) {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = fail_index });
        var approvals = SessionApprovals.init(failing.allocator());
        defer approvals.deinit();
        approvals.allowForSession("npm install", "package install") catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            saw_oom = true;
            continue;
        };
        saw_success = true;
        break;
    }
    try std.testing.expect(saw_oom);
    try std.testing.expect(saw_success);
}

test "approval prompt supports explain and session allow" {
    var input: std.Io.Reader = .fixed("?\nA\n");
    var output_buf: [1024]u8 = undefined;
    var output_writer: std.Io.Writer = .fixed(&output_buf);
    const choice = try prompt(&input, &output_writer, .{
        .command = "npm install",
        .risk_class = "package_install",
        .risk_reason = "package install can run scripts",
        .policy_reason = "commands.default: ask",
    });
    try std.testing.expectEqual(ApprovalChoice.allow_session, choice);
    try std.testing.expect(std.mem.indexOf(u8, output_writer.buffered(), "Risk explanation") != null);
}

test "approval prompt presents Once Session Never labels without Always" {
    var input: std.Io.Reader = .fixed("d\n");
    var output_buf: [1024]u8 = undefined;
    var output_writer: std.Io.Writer = .fixed(&output_buf);
    const choice = try prompt(&input, &output_writer, .{
        .command = "rm -rf /tmp/x",
        .risk_class = "destructive",
        .risk_reason = "can delete files",
        .policy_reason = "commands.default: ask",
        .matched_rule = "core.filesystem:destructive_rm",
    });
    try std.testing.expectEqual(ApprovalChoice.deny, choice);
    const out = output_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "Once") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Session") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Never") != null);
    // Session sticky is not a permanent ryk allowlist write — never say Always.
    try std.testing.expect(std.mem.indexOf(u8, out, "Always") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "always") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Choice (once / session / never):") != null);
    // Rule id is secondary detail, not the recovery path.
    try std.testing.expect(std.mem.indexOf(u8, out, "matched rule: core.filesystem:destructive_rm") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "allowlist") == null);
}

test "approval prompt maps once always never words without rule ids" {
    {
        var input: std.Io.Reader = .fixed("once\n");
        var output_buf: [512]u8 = undefined;
        var output_writer: std.Io.Writer = .fixed(&output_buf);
        const choice = try prompt(&input, &output_writer, .{
            .command = "npm install",
            .risk_class = "package_install",
            .risk_reason = "scripts",
            .policy_reason = "ask",
        });
        try std.testing.expectEqual(ApprovalChoice.allow_once, choice);
    }
    {
        var input: std.Io.Reader = .fixed("always\n");
        var output_buf: [512]u8 = undefined;
        var output_writer: std.Io.Writer = .fixed(&output_buf);
        const choice = try prompt(&input, &output_writer, .{
            .command = "npm install",
            .risk_class = "package_install",
            .risk_reason = "scripts",
            .policy_reason = "ask",
        });
        try std.testing.expectEqual(ApprovalChoice.allow_session, choice);
    }
    {
        var input: std.Io.Reader = .fixed("session\n");
        var output_buf: [512]u8 = undefined;
        var output_writer: std.Io.Writer = .fixed(&output_buf);
        const choice = try prompt(&input, &output_writer, .{
            .command = "npm install",
            .risk_class = "package_install",
            .risk_reason = "scripts",
            .policy_reason = "ask",
        });
        try std.testing.expectEqual(ApprovalChoice.allow_session, choice);
    }
    {
        var input: std.Io.Reader = .fixed("never\n");
        var output_buf: [512]u8 = undefined;
        var output_writer: std.Io.Writer = .fixed(&output_buf);
        const choice = try prompt(&input, &output_writer, .{
            .command = "npm install",
            .risk_class = "package_install",
            .risk_reason = "scripts",
            .policy_reason = "ask",
        });
        try std.testing.expectEqual(ApprovalChoice.deny, choice);
    }
    {
        var input: std.Io.Reader = .fixed("deny\n");
        var output_buf: [512]u8 = undefined;
        var output_writer: std.Io.Writer = .fixed(&output_buf);
        const choice = try prompt(&input, &output_writer, .{
            .command = "npm install",
            .risk_class = "package_install",
            .risk_reason = "scripts",
            .policy_reason = "ask",
        });
        try std.testing.expectEqual(ApprovalChoice.deny, choice);
    }
}

test "approval prompt keeps a A d shortcuts" {
    {
        var input: std.Io.Reader = .fixed("a\n");
        var output_buf: [512]u8 = undefined;
        var output_writer: std.Io.Writer = .fixed(&output_buf);
        try std.testing.expectEqual(ApprovalChoice.allow_once, try prompt(&input, &output_writer, .{
            .command = "x",
            .risk_class = "r",
            .risk_reason = "r",
            .policy_reason = "p",
        }));
    }
    {
        var input: std.Io.Reader = .fixed("A\n");
        var output_buf: [512]u8 = undefined;
        var output_writer: std.Io.Writer = .fixed(&output_buf);
        try std.testing.expectEqual(ApprovalChoice.allow_session, try prompt(&input, &output_writer, .{
            .command = "x",
            .risk_class = "r",
            .risk_reason = "r",
            .policy_reason = "p",
        }));
    }
    {
        var input: std.Io.Reader = .fixed("d\n");
        var output_buf: [512]u8 = undefined;
        var output_writer: std.Io.Writer = .fixed(&output_buf);
        try std.testing.expectEqual(ApprovalChoice.deny, try prompt(&input, &output_writer, .{
            .command = "x",
            .risk_class = "r",
            .risk_reason = "r",
            .policy_reason = "p",
        }));
    }
}

// Fail-closed production path: empty line, whitespace-only, and EOF deny
// without allowing the command. Empty input is never treated as allow.
test "approval prompt fail-closed on empty line" {
    var input: std.Io.Reader = .fixed("\n");
    var output_buf: [1024]u8 = undefined;
    var output_writer: std.Io.Writer = .fixed(&output_buf);
    const choice = try prompt(&input, &output_writer, .{
        .command = "rm -rf /",
        .risk_class = "destructive",
        .risk_reason = "can delete files",
        .policy_reason = "commands.default: ask",
    });
    try std.testing.expectEqual(ApprovalChoice.deny, choice);
}

test "approval prompt fail-closed on whitespace-only line" {
    var input: std.Io.Reader = .fixed("   \t  \r\n");
    var output_buf: [1024]u8 = undefined;
    var output_writer: std.Io.Writer = .fixed(&output_buf);
    const choice = try prompt(&input, &output_writer, .{
        .command = "curl evil.example",
        .risk_class = "network",
        .risk_reason = "outbound request",
        .policy_reason = "commands.default: ask",
    });
    try std.testing.expectEqual(ApprovalChoice.deny, choice);
}

test "approval prompt fail-closed on empty reader EOF" {
    var input: std.Io.Reader = .fixed("");
    var output_buf: [1024]u8 = undefined;
    var output_writer: std.Io.Writer = .fixed(&output_buf);
    const choice = try prompt(&input, &output_writer, .{
        .command = "npm install",
        .risk_class = "package_install",
        .risk_reason = "package install can run scripts",
        .policy_reason = "commands.default: ask",
    });
    try std.testing.expectEqual(ApprovalChoice.deny, choice);
}

test "approval prompt re-prompts on garbage then denies never" {
    var input: std.Io.Reader = .fixed("xyz\nnever\n");
    var output_buf: [2048]u8 = undefined;
    var output_writer: std.Io.Writer = .fixed(&output_buf);
    const choice = try prompt(&input, &output_writer, .{
        .command = "npm install",
        .risk_class = "package_install",
        .risk_reason = "scripts",
        .policy_reason = "ask",
    });
    try std.testing.expectEqual(ApprovalChoice.deny, choice);
    const out = output_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "Choose once, session, never") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Always") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "always") == null);
}

test "parseChoice empty string denies fail-closed" {
    // prompt trims before calling parseChoice; empty after trim is deny.
    try std.testing.expectEqual(ApprovalChoice.deny, parseChoice("").?);
    // Untrimmed whitespace is invalid input at this layer (returns null → re-prompt).
    try std.testing.expect(parseChoice("   ") == null);
}

fn countAllowForSessionAllocs() !usize {
    var counter = std.testing.FailingAllocator.init(std.testing.allocator, .{
        .resize_fail_index = 0,
    });
    var approvals = SessionApprovals.init(counter.allocator());
    defer approvals.deinit();
    try approvals.allowForSession("npm install", "package install");
    try std.testing.expect(approvals.contains("npm install"));
    return counter.allocations;
}

// Finding 7: command dupe, reason dupe, then append — each can OOM. GPA
// fail-at-N must stay balanced through the second dupe and the list grow.
test "allowForSession OOM ownership stays green through second dupe and append" {
    const alloc_count = try countAllowForSessionAllocs();
    // command dupe + reason dupe + entries.append grow (remap forced to fail).
    try std.testing.expect(alloc_count >= 3);

    // Pin the last alloc (append after both dupes). A sweep from 0 REDs on
    // the second-dupe leak and never reaches the append-drop hole.
    last_alloc: {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{
            .fail_index = alloc_count - 1,
            .resize_fail_index = 0,
        });
        var approvals = SessionApprovals.init(failing.allocator());
        defer approvals.deinit();
        approvals.allowForSession("npm install", "package install") catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expect(failing.has_induced_failure);
            try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
            try std.testing.expect(!approvals.contains("npm install"));
            break :last_alloc;
        };
        return error.TestUnexpectedResult;
    }

    var saw_oom = false;
    var fail_at: usize = 0;
    while (fail_at < alloc_count) : (fail_at += 1) {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{
            .fail_index = fail_at,
            .resize_fail_index = 0,
        });
        var approvals = SessionApprovals.init(failing.allocator());
        defer approvals.deinit();

        approvals.allowForSession("npm install", "package install") catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expect(failing.has_induced_failure);
            try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
            try std.testing.expect(!approvals.contains("npm install"));
            saw_oom = true;
            continue;
        };
        return error.TestUnexpectedResult;
    }
    try std.testing.expect(saw_oom);
}

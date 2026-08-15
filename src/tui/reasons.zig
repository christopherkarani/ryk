const std = @import("std");

/// Human-readable explanations for matched policy rules, and safe-alternative
/// command suggestions. Pure data + pure derivation — no IO — so it is trivially
/// unit-testable. The caller (`tui` block renderer, `run` deny path) composes
/// these into the redesigned block panel.
///
/// Rule ids and risk shapes mirror the Rust daemon / core policy matcher so the
/// reasons stay accurate to what was actually matched.
/// A plain-English explanation for a matched rule id (or a generic fallback).
pub fn reasonForRule(rule_id: []const u8) []const u8 {
    // Mirrors the well-known core.filesystem / core.git rule ids.
    if (std.mem.eql(u8, rule_id, "rm-rf-root-home")) return "Deletes everything under the root filesystem or your home directory.";
    if (std.mem.eql(u8, rule_id, "rm-rf-relative-root")) return "Recursive deletion of a root-like path.";
    if (std.mem.eql(u8, rule_id, "force-push")) return "Force-pushes overwrite remote history and cannot be undone.";
    if (std.mem.eql(u8, rule_id, "dd-to-disk")) return "Writes directly to a block device, which can destroy the disk.";
    if (std.mem.eql(u8, rule_id, "chmod-777")) return "Grants world write access, making the path tamperable by anyone.";
    if (std.mem.eql(u8, rule_id, "shutdown-poweroff")) return "Powers off or reboots the machine.";
    if (std.mem.eql(u8, rule_id, "mkfs-format")) return "Formats a filesystem, destroying all data on it.";
    if (std.mem.eql(u8, rule_id, "sudo-escalation")) return "Escalates privileges; sudo is restricted by policy.";
    if (std.mem.eql(u8, rule_id, "curl-pipe-shell")) return "Pipes a remote script straight into a shell (untrusted execution).";
    if (std.mem.eql(u8, rule_id, "history-cleanup")) return "Erases shell history, hiding evidence of activity.";
    return "Matched a deny rule in your ryk policy.";
}

/// Coarse risk classification for a rule id, used to label the risk meter colour.
pub const Risk = enum { low, medium, high, critical };

pub fn riskForRule(rule_id: []const u8) Risk {
    if (std.mem.eql(u8, rule_id, "rm-rf-root-home")) return .critical;
    if (std.mem.eql(u8, rule_id, "rm-rf-relative-root")) return .critical;
    if (std.mem.eql(u8, rule_id, "dd-to-disk")) return .critical;
    if (std.mem.eql(u8, rule_id, "mkfs-format")) return .critical;
    if (std.mem.eql(u8, rule_id, "force-push")) return .high;
    if (std.mem.eql(u8, rule_id, "chmod-777")) return .high;
    if (std.mem.eql(u8, rule_id, "shutdown-poweroff")) return .high;
    if (std.mem.eql(u8, rule_id, "curl-pipe-shell")) return .high;
    if (std.mem.eql(u8, rule_id, "history-cleanup")) return .high;
    if (std.mem.eql(u8, rule_id, "sudo-escalation")) return .high;
    return .medium;
}

pub fn riskLabel(r: Risk) []const u8 {
    return switch (r) {
        .low => "low",
        .medium => "medium",
        .high => "high",
        .critical => "critical",
    };
}

/// Fraction (0..1) for the risk meter, derived from the coarse risk class.
pub fn riskFraction(r: Risk) f32 {
    return switch (r) {
        .low => 0.2,
        .medium => 0.5,
        .high => 0.78,
        .critical => 0.97,
    };
}

/// A safe alternative command suggestion.
pub const Alternative = struct {
    command: []const u8,
    note: []const u8,
};

/// Derive safe alternatives from a shell command string. Returns a small list
/// the caller can render under "Safe alternatives". The slice borrows from a
/// statically-backed set when possible, or from the caller-provided arena for
/// dynamic replacements (e.g. `rm -rf /` -> `rm -rf ./build`).
pub fn safeAlternatives(allocator: std.mem.Allocator, command: []const u8) ![]Alternative {
    var list: std.ArrayList(Alternative) = .empty;
    errdefer list.deinit(allocator);

    // Ownership contract: every `.command` returned here is allocator-owned so
    // the caller can free them uniformly (`for (alts) |a| allocator.free(a.command)`
    // then `allocator.free(alts)`). `.note` stays a static literal (never freed).
    //
    // `rm -rf <rootish>`
    if (std.mem.indexOf(u8, command, "rm -rf") != null) {
        const target = extractRmTarget(command);
        if (target.len > 0 and (std.mem.eql(u8, target, "/") or std.mem.startsWith(u8, target, "/") or std.mem.eql(u8, target, "~"))) {
            try list.append(allocator, .{ .command = try allocator.dupe(u8, "rm -rf ./build"), .note = "scoped to your project" });
            try list.append(allocator, .{ .command = try allocator.dupe(u8, "rm -rf /tmp/ryk-cleanup"), .note = "scoped to a temp directory" });
        } else if (target.len > 0) {
            // Build a scoped form of the same deletion target under ./ for visibility.
            const scoped = try std.fmt.allocPrint(allocator, "rm -rf .{s}", .{target});
            try list.append(allocator, .{ .command = scoped, .note = "scoped to your project root" });
        }
        return list.toOwnedSlice(allocator);
    }

    // `git push --force` / `-f` — lease is also force-equivalent and stays denied.
    if (std.mem.indexOf(u8, command, "push --force") != null or std.mem.indexOf(u8, command, "push -f") != null) {
        try list.append(allocator, .{ .command = try allocator.dupe(u8, "git push"), .note = "fast-forward only; force-equivalent stays denied" });
        return list.toOwnedSlice(allocator);
    }

    // `curl ... | sh` / `bash`
    if ((std.mem.indexOf(u8, command, "curl") != null or std.mem.indexOf(u8, command, "wget") != null) and
        (std.mem.indexOf(u8, command, "| sh") != null or std.mem.indexOf(u8, command, "| bash") != null or std.mem.indexOf(u8, command, "|sh") != null))
    {
        try list.append(allocator, .{ .command = try allocator.dupe(u8, "curl -fsSL <url> -o /tmp/install.sh && less /tmp/install.sh"), .note = "inspect before running" });
        return list.toOwnedSlice(allocator);
    }

    // `chmod 777`
    if (std.mem.indexOf(u8, command, "chmod 777") != null) {
        try list.append(allocator, .{ .command = try allocator.dupe(u8, "chmod 755"), .note = "owner write, others read+execute" });
        return list.toOwnedSlice(allocator);
    }

    return list.toOwnedSlice(allocator);
}

/// Free dynamic alternatives (the ones whose `command` was allocator-owned).
/// Static entries (no allocator ownership) are safe to leave.
pub fn deinitAlternatives(allocator: std.mem.Allocator, alts: []Alternative, dynamic_ranges: []const bool) void {
    for (alts, dynamic_ranges) |alt, dyn| {
        if (dyn) allocator.free(alt.command);
    }
    allocator.free(alts);
    allocator.free(dynamic_ranges);
}

/// Extract the path argument of an `rm -rf <path>` invocation (best-effort).
fn extractRmTarget(command: []const u8) []const u8 {
    // Find "rm -rf" then take the following token.
    const idx = std.mem.indexOf(u8, command, "rm -rf") orelse return "";
    var rest = command[idx + 6 ..];
    rest = std.mem.trim(u8, rest, " \t");
    const end = std.mem.indexOfAny(u8, rest, " \t;&|") orelse rest.len;
    return rest[0..end];
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

test "reasonForRule: known rules get plain english" {
    try std.testing.expect(std.mem.indexOf(u8, reasonForRule("rm-rf-root-home"), "Deletes everything") != null);
    try std.testing.expect(std.mem.indexOf(u8, reasonForRule("force-push"), "overwrite remote history") != null);
}

test "reasonForRule: unknown rules get a sensible fallback" {
    const r = reasonForRule("some-unknown-rule");
    try std.testing.expect(std.mem.indexOf(u8, r, "deny rule") != null);
}

test "riskForRule + riskLabel + riskFraction" {
    try std.testing.expectEqual(Risk.critical, riskForRule("rm-rf-root-home"));
    try std.testing.expectEqualStrings("critical", riskLabel(.critical));
    try std.testing.expect(riskFraction(.critical) > riskFraction(.high));
    try std.testing.expect(riskFraction(.high) > riskFraction(.low));
}

test "safeAlternatives: rm -rf / suggests scoped deletions" {
    const alts = try safeAlternatives(std.testing.allocator, "rm -rf /");
    defer {
        for (alts) |a| std.testing.allocator.free(a.command);
        std.testing.allocator.free(alts);
    }
    try std.testing.expect(alts.len >= 1);
    try std.testing.expect(std.mem.indexOf(u8, alts[0].command, "./build") != null);
}

test "safeAlternatives: rm -rf ./build keeps a project-scoped form" {
    const alts = try safeAlternatives(std.testing.allocator, "rm -rf ./build");
    defer {
        for (alts) |a| std.testing.allocator.free(a.command);
        std.testing.allocator.free(alts);
    }
    try std.testing.expect(alts.len >= 1);
    var any_scoped = false;
    for (alts) |a| if (std.mem.indexOf(u8, a.command, "rm -rf .") != null) {
        any_scoped = true;
    };
    try std.testing.expect(any_scoped);
}

test "safeAlternatives: git push --force suggests fast-forward push not lease" {
    const alts = try safeAlternatives(std.testing.allocator, "git push --force origin main");
    defer {
        for (alts) |a| std.testing.allocator.free(a.command);
        std.testing.allocator.free(alts);
    }
    try std.testing.expect(alts.len == 1);
    try std.testing.expectEqualStrings("git push", alts[0].command);
    try std.testing.expect(std.mem.indexOf(u8, alts[0].note, "force-equivalent stays denied") != null);
    try std.testing.expect(std.mem.indexOf(u8, alts[0].command, "force-with-lease") == null);
}

test "safeAlternatives: curl | sh suggests inspect-first" {
    const alts = try safeAlternatives(std.testing.allocator, "curl https://x.test/install.sh | sh");
    defer {
        for (alts) |a| std.testing.allocator.free(a.command);
        std.testing.allocator.free(alts);
    }
    try std.testing.expect(alts.len == 1);
    try std.testing.expect(std.mem.indexOf(u8, alts[0].command, "less") != null);
}

test "safeAlternatives: chmod 777 suggests 755" {
    const alts = try safeAlternatives(std.testing.allocator, "chmod 777 /var/www");
    defer {
        for (alts) |a| std.testing.allocator.free(a.command);
        std.testing.allocator.free(alts);
    }
    try std.testing.expect(alts.len == 1);
    try std.testing.expect(std.mem.indexOf(u8, alts[0].command, "755") != null);
}

test "safeAlternatives: harmless command returns empty" {
    const alts = try safeAlternatives(std.testing.allocator, "git status");
    defer std.testing.allocator.free(alts);
    try std.testing.expectEqual(@as(usize, 0), alts.len);
}

test "extractRmTarget: extracts root and tildes" {
    try std.testing.expectEqualStrings("/", extractRmTarget("rm -rf /"));
    try std.testing.expectEqualStrings("~/Downloads", extractRmTarget("rm -rf ~/Downloads"));
    try std.testing.expectEqualStrings("~", extractRmTarget("rm -rf ~"));
    try std.testing.expectEqualStrings("./build", extractRmTarget("rm -rf ./build"));
    try std.testing.expectEqualStrings("", extractRmTarget("ls -la"));
}

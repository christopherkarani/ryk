//! Static suggestion families for explain / human deny surfaces.
//! DCG-quality tip copy (product owner owns DCG); static slices only — do not free.
const std = @import("std");

/// Return static tip lines for a pack/pattern (no allocation; do not free).
pub fn forPattern(pack_id: []const u8, pattern_name: []const u8) []const []const u8 {
    // Prefer rule_id-shaped lookup for high-traffic patterns.
    var rule_buf: [128]u8 = undefined;
    const rule_id = std.fmt.bufPrint(&rule_buf, "{s}:{s}", .{ pack_id, pattern_name }) catch null;
    if (rule_id) |rid| {
        if (forRuleId(rid)) |tips| return tips;
    }
    return forPackFamily(pack_id, pattern_name);
}

/// Lookup by full rule id (`pack:pattern`). Returns null when unregistered.
pub fn forRuleId(rule_id: []const u8) ?[]const []const u8 {
    // core.filesystem — recursive force delete family
    if (std.mem.eql(u8, rule_id, "core.filesystem:rm-rf-general") or
        std.mem.eql(u8, rule_id, "core.filesystem:rm-rf-root-home") or
        std.mem.eql(u8, rule_id, "core.filesystem:rm-r-f-separate") or
        std.mem.eql(u8, rule_id, "core.filesystem:rm-r-f-separate-root-home") or
        std.mem.eql(u8, rule_id, "core.filesystem:rm-recursive-force-long") or
        std.mem.eql(u8, rule_id, "core.filesystem:rm-recursive-force-root-home") or
        std.mem.eql(u8, rule_id, "core.filesystem:find-delete-general") or
        std.mem.eql(u8, rule_id, "core.filesystem:find-delete-root-home") or
        std.mem.eql(u8, rule_id, "core.filesystem:unlink-general") or
        std.mem.eql(u8, rule_id, "core.filesystem:unlink-root-home") or
        std.mem.eql(u8, rule_id, "core.filesystem:shred-general") or
        std.mem.eql(u8, rule_id, "core.filesystem:shred-root-home"))
    {
        return &rm_rf_tips;
    }
    if (std.mem.eql(u8, rule_id, "core.git:reset-hard") or
        std.mem.eql(u8, rule_id, "core.git:reset-hard-path") or
        std.mem.eql(u8, rule_id, "core.git:checkout-force") or
        std.mem.eql(u8, rule_id, "core.git:restore-source"))
    {
        return &git_reset_tips;
    }
    if (std.mem.eql(u8, rule_id, "core.git:push-force") or
        std.mem.eql(u8, rule_id, "core.git:push-force-with-lease") or
        std.mem.indexOf(u8, rule_id, "push-force") != null)
    {
        return &git_push_force_tips;
    }
    if (std.mem.indexOf(u8, rule_id, "clean") != null and std.mem.startsWith(u8, rule_id, "core.git")) {
        return &git_clean_tips;
    }
    return null;
}

fn forPackFamily(pack_id: []const u8, pattern_name: []const u8) []const []const u8 {
    if (std.mem.eql(u8, pack_id, "core.filesystem") or std.mem.startsWith(u8, pattern_name, "rm-") or
        std.mem.indexOf(u8, pattern_name, "rm-rf") != null or
        std.mem.indexOf(u8, pattern_name, "rmtree") != null or
        std.mem.indexOf(u8, pattern_name, "find-delete") != null or
        std.mem.indexOf(u8, pattern_name, "shred") != null or
        std.mem.indexOf(u8, pattern_name, "unlink") != null)
    {
        return &rm_rf_tips;
    }
    if (std.mem.eql(u8, pack_id, "core.git") or std.mem.indexOf(u8, pattern_name, "reset-hard") != null or
        std.mem.indexOf(u8, pattern_name, "push-force") != null or
        std.mem.indexOf(u8, pattern_name, "clean") != null or
        std.mem.indexOf(u8, pattern_name, "checkout") != null)
    {
        if (std.mem.indexOf(u8, pattern_name, "push") != null) return &git_push_force_tips;
        if (std.mem.indexOf(u8, pattern_name, "clean") != null) return &git_clean_tips;
        return &git_reset_tips;
    }
    if (std.mem.eql(u8, pack_id, "system.disk") or std.mem.startsWith(u8, pattern_name, "dd-") or
        std.mem.startsWith(u8, pattern_name, "mkfs") or std.mem.indexOf(u8, pattern_name, "fdisk") != null)
    {
        return &disk_tips;
    }
    if (std.mem.startsWith(u8, pack_id, "containers.") or std.mem.startsWith(u8, pack_id, "kubernetes.")) {
        return &containers_tips;
    }
    if (std.mem.startsWith(u8, pack_id, "database.")) {
        return &database_tips;
    }
    return &generic_tips;
}

// DCG tip copy adapted for ryk (kind labels inline).
const rm_rf_tips = [_][]const u8{
    "Preview first: List contents first with `ls -la` to verify target",
    "Safer alternative: Use `rm -ri` for interactive confirmation of each file — `rm -ri path/`",
    "Workflow fix: Move to trash instead: `mv path ~/.local/share/Trash/`",
};

const git_reset_tips = [_][]const u8{
    "Preview first: Run `git status` and `git diff` to see uncommitted changes that could be lost",
    "Safer alternative: Prefer `git switch` / `git restore --staged` or `git reset --soft` when possible",
    "Workflow fix: Save work first with `git stash push -u -m \"wip\"` before destructive git ops",
};

const git_push_force_tips = [_][]const u8{
    "Preview first: Confirm the remote tip with `git fetch` and `git log --oneline origin/BRANCH..HEAD`",
    "Safer alternative: Use a fast-forward `git push` — `--force-with-lease` is still force-equivalent and stays denied",
    "Workflow fix: Confirm with a human before force-pushing shared branches",
};

const git_clean_tips = [_][]const u8{
    "Preview first: Run `git clean -nd` (dry-run) to list files that would be removed",
    "Safer alternative: Use `git clean -i` for interactive selection",
    "Workflow fix: Stash or commit wanted files before cleaning the worktree",
};

const disk_tips = [_][]const u8{
    "Preview first: Double-check the device path; disk ops are usually irreversible",
    "Safer alternative: Prefer higher-level tools or dry-runs when available",
    "Workflow fix: Ask a human to run disk/format commands outside the agent session",
};

const containers_tips = [_][]const u8{
    "Preview first: Prefer dry-run / plan flags before destructive cluster or container ops",
    "Safer alternative: Confirm the target namespace, project, or container name with a human",
};

const database_tips = [_][]const u8{
    "Preview first: Never run DROP/TRUNCATE/FLUSH against production without explicit human approval",
    "Safer alternative: Prefer transactions and backups before destructive SQL",
};

const generic_tips = [_][]const u8{
    "Ask a human to run this command manually if it is truly required",
    "Use `ryk explain \"<command>\"` to inspect the matched pack rule",
    "Use `ryk allow-once <code>` only after reviewing the block reason",
};

/// Short explanation line for a deny hit (static template; no allocation).
pub fn explanationFor(pack_id: []const u8, pattern_name: []const u8) []const u8 {
    _ = pack_id;
    _ = pattern_name;
    return "Matched a destructive pack pattern. The command was not executed.";
}

test "suggestions cover filesystem and generic" {
    const fs = forPattern("core.filesystem", "rm-rf-general");
    try std.testing.expect(fs.len >= 2);
    try std.testing.expect(std.mem.indexOf(u8, fs[0], "Preview first") != null);
    const generic = forPattern("unknown.pack", "other");
    try std.testing.expect(generic.len >= 1);
}

test "suggestions rule_id lookup for git reset-hard" {
    const tips = forRuleId("core.git:reset-hard").?;
    try std.testing.expect(tips.len >= 2);
    try std.testing.expect(std.mem.indexOf(u8, tips[0], "git") != null);
}

test "force-push tips do not present lease as an allowed rewrite" {
    const tips = forRuleId("core.git:push-force").?;
    var saw_honest_alt = false;
    for (tips) |tip| {
        try std.testing.expect(std.mem.indexOf(u8, tip, "Prefer `--force-with-lease`") == null);
        if (std.mem.indexOf(u8, tip, "fast-forward") != null) saw_honest_alt = true;
    }
    try std.testing.expect(saw_honest_alt);
}

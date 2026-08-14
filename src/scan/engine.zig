//! Orchestrate discovery → extract → danger/secrets → rank → result.
const std = @import("std");
const types = @import("types.zig");
const time_window = @import("time_window.zig");
const discover = @import("discover.zig");
const jsonl = @import("jsonl.zig");
const opencode_db = @import("opencode_db.zig");
const danger = @import("danger.zig");
const secrets = @import("secrets.zig");
const rank = @import("rank.zig");

/// Optional host-level progress for TTY spinners (scan is otherwise silent).
/// `sessions` meaning by phase:
/// - `host_start`: total session files for this host
/// - `file`: 1-based index of the file about to be processed
/// - `host_done`: total session files processed for this host
pub const ProgressPhase = enum { host_start, file, host_done };
pub const ProgressFn = *const fn (ctx: ?*anyopaque, host: types.Host, phase: ProgressPhase, sessions: usize) void;

pub const ScanOptions = struct {
    home: []const u8,
    xdg_data_home: ?[]const u8 = null,
    /// Workspace root so `ryk run` sessions under `.ryk/sessions` are visible.
    workspace_root: ?[]const u8 = null,
    days: ?u32 = null,
    all_time: bool = false,
    show_all: bool = false,
    only_host: ?types.Host = null,
    now_secs: ?i64 = null,
    list_cap: usize = types.default_list_cap,
    progress: ?ProgressFn = null,
    progress_ctx: ?*anyopaque = null,
};

pub fn runScan(io: std.Io, allocator: std.mem.Allocator, options: ScanOptions) !types.ScanResult {
    const now = options.now_secs orelse std.Io.Timestamp.now(io, .real).toSeconds();
    const window = time_window.resolveWindow(now, options.days, options.all_time);

    var scorecard: types.Scorecard = .{
        .window_days = window.days,
        .all_time = window.all_time,
    };

    const hosts = try discover.discoverAll(io, allocator, .{
        .home = options.home,
        .xdg_data_home = options.xdg_data_home,
        .workspace_root = options.workspace_root,
        .window = window,
        .only_host = options.only_host,
    });
    defer discover.freeDiscoveries(allocator, hosts);

    var findings: std.ArrayList(types.Finding) = .empty;
    errdefer {
        for (findings.items) |*f| f.deinit(allocator);
        findings.deinit(allocator);
    }

    for (hosts) |h| {
        const file_total = h.files.items.len;
        if (options.progress) |pf| pf(options.progress_ctx, h.host, .host_start, file_total);
        scorecard.setHost(h.host, h.status, file_total, h.note);
        for (h.files.items, 0..) |file, fi| {
            if (options.progress) |pf| pf(options.progress_ctx, h.host, .file, fi + 1);
            scorecard.sessions_scanned += 1;

            var parsed = if (h.host == .opencode)
                opencode_db.parseSession(io, allocator, file.path, file.session_id, file.mtime_secs) catch |err| {
                    // parseSession is fail-soft for IO; only OOM must bubble.
                    if (err == error.OutOfMemory) return error.OutOfMemory;
                    continue;
                }
            else
                jsonl.parseJsonlFile(io, allocator, file.path, file.mtime_secs) catch |err| {
                    if (err == error.OutOfMemory) return error.OutOfMemory;
                    continue;
                };
            defer parsed.deinit(allocator);

            // Discovery already windowed by mtime. Do not drop the whole session when
            // the first content timestamp is older than the window — recent danger can
            // live in long-running session files. Use content ts only for display.
            const ts = if (parsed.timestamp_secs != 0) parsed.timestamp_secs else file.mtime_secs;

            // OpenCode evidence is session-scoped (DB path alone is not a unique session id).
            const evidence_owned: ?[]u8 = if (h.host == .opencode)
                opencode_db.evidenceRef(allocator, file.session_id) catch null
            else
                null;
            defer if (evidence_owned) |e| allocator.free(e);
            const evidence_path = evidence_owned orelse file.path;

            for (parsed.commands.items) |cmd| {
                try processCommand(allocator, &findings, &scorecard, h.host, file.session_id, evidence_path, ts, cmd);
            }
            for (parsed.text_blobs.items) |blob| {
                try processMaterial(allocator, &findings, &scorecard, h.host, file.session_id, evidence_path, ts, blob);
            }
        }
        if (options.progress) |pf| pf(options.progress_ctx, h.host, .host_done, file_total);
    }

    rank.sortFindings(findings.items);
    // Collapse repeated secret fingerprints so the list is scannable (scorecard
    // still reflects raw material_count from discovery).
    rank.collapseSecretFingerprints(allocator, &findings);
    const total = findings.items.len;
    const shown_slice = rank.applyCap(findings.items, options.show_all, options.list_cap);

    // Shrink list to shown when capped (free the tail).
    if (shown_slice.len < findings.items.len) {
        var i = shown_slice.len;
        while (i < findings.items.len) : (i += 1) {
            findings.items[i].deinit(allocator);
        }
        findings.shrinkRetainingCapacity(shown_slice.len);
    }

    const owned = try findings.toOwnedSlice(allocator);
    return .{
        .scorecard = scorecard,
        .findings = owned,
        .total_findings = total,
        .shown_cap = if (options.show_all) total else options.list_cap,
        .allocator = allocator,
    };
}

fn processCommand(
    allocator: std.mem.Allocator,
    findings: *std.ArrayList(types.Finding),
    scorecard: *types.Scorecard,
    host: types.Host,
    session_id: []const u8,
    path: []const u8,
    ts: i64,
    cmd: []const u8,
) !void {
    // secret_access first. Still evaluate danger so compound commands (secret path +
    // destructive shell) surface both — do not hide danger behind access-only.
    if (secrets.isSecretAccessCommand(cmd)) {
        const detail = try secrets.safeDetail(allocator, cmd);
        errdefer allocator.free(detail);
        const title = try allocator.dupe(u8, "Secret-access command");
        errdefer allocator.free(title);
        try pushFinding(allocator, findings, .{
            .kind = .secret_access,
            .severity = .high,
            .host = host,
            .session_id = session_id,
            .path = path,
            .timestamp_secs = ts,
            .title = title,
            .detail = detail,
            .evidence_ref = path,
        });
        scorecard.secret_access_count += 1;
    }

    if (try danger.evaluateDanger(allocator, cmd)) |hit_const| {
        var hit = hit_const;
        defer hit.deinit(allocator);
        const detail = try secrets.safeDetail(allocator, cmd);
        errdefer allocator.free(detail);
        const title = try std.fmt.allocPrint(allocator, "Dangerous command ({s})", .{hit.severity.toString()});
        errdefer allocator.free(title);
        try pushFinding(allocator, findings, .{
            .kind = .danger,
            .severity = hit.severity,
            .host = host,
            .session_id = session_id,
            .path = path,
            .timestamp_secs = ts,
            .title = title,
            .detail = detail,
            .evidence_ref = path,
        });
        scorecard.danger_count += 1;
    }
}

fn processMaterial(
    allocator: std.mem.Allocator,
    findings: *std.ArrayList(types.Finding),
    scorecard: *types.Scorecard,
    host: types.Host,
    session_id: []const u8,
    path: []const u8,
    ts: i64,
    blob: []const u8,
) !void {
    const hit_opt = try secrets.classifyMaterial(allocator, blob);
    const hit = hit_opt orelse return;
    var material = hit;
    defer material.deinit(allocator);
    const material_count = @max(@as(usize, 1), secrets.countMaterials(blob));

    // Title/detail stay free of nested REDACTED blobs — present layer maps label.
    const title = try allocator.dupe(u8, "Secret-like value in session");
    errdefer allocator.free(title);
    const detail = try allocator.dupe(u8, "Value hidden");
    errdefer allocator.free(detail);
    const label = try allocator.dupe(u8, material.label);
    errdefer allocator.free(label);
    try pushFinding(allocator, findings, .{
        .kind = .secret_material,
        .severity = .high,
        .host = host,
        .session_id = session_id,
        .path = path,
        .timestamp_secs = ts,
        .title = title,
        .detail = detail,
        .secret_label = label,
        .secret_fingerprint = null,
        .evidence_ref = path,
    });
    scorecard.secret_material_count += material_count;
    findings.items[findings.items.len - 1].occurrence_count = material_count;
}

const FindingSeed = struct {
    kind: types.FindingKind,
    severity: types.Severity,
    host: types.Host,
    session_id: []const u8,
    path: []const u8,
    timestamp_secs: i64,
    title: []u8,
    detail: []u8,
    secret_label: ?[]u8 = null,
    secret_fingerprint: ?[]u8 = null,
    evidence_ref: []const u8,
};

fn pushFinding(allocator: std.mem.Allocator, findings: *std.ArrayList(types.Finding), seed: FindingSeed) !void {
    const session_id = try allocator.dupe(u8, seed.session_id);
    errdefer allocator.free(session_id);
    const path = try allocator.dupe(u8, seed.path);
    errdefer allocator.free(path);
    const evidence = try allocator.dupe(u8, seed.evidence_ref);
    errdefer allocator.free(evidence);

    try findings.append(allocator, .{
        .kind = seed.kind,
        .severity = seed.severity,
        .host = seed.host,
        .session_id = session_id,
        .path = path,
        .timestamp_secs = seed.timestamp_secs,
        .title = seed.title,
        .detail = seed.detail,
        .secret_label = seed.secret_label,
        .secret_fingerprint = seed.secret_fingerprint,
        .evidence_ref = evidence,
    });
}

test "engine empty home produces empty scorecard exit-success path data" {
    const io = std.testing.io;
    const home = try std.fmt.allocPrint(std.testing.allocator, "zig-cache/tmp-scan-engine-empty-{d}", .{std.Io.Timestamp.now(io, .real).toSeconds()});
    defer std.testing.allocator.free(home);
    try std.Io.Dir.cwd().createDirPath(io, home);
    defer std.Io.Dir.cwd().deleteTree(io, home) catch {};

    var result = try runScan(io, std.testing.allocator, .{ .home = home });
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 0), result.findings.len);
    try std.testing.expectEqual(@as(usize, 0), result.total_findings);
    try std.testing.expectEqual(@as(usize, 0), result.scorecard.sessions_scanned);
}

test "engine opencode fixture yields danger secret_access redacted material" {
    const io = std.testing.io;
    if (!opencode_db.sqlite3Available(io, std.testing.allocator)) return error.SkipZigTest;

    const now: i64 = 1_785_143_897;
    const home = try std.fmt.allocPrint(std.testing.allocator, "zig-cache/tmp-scan-engine-opencode-{d}", .{std.Io.Timestamp.now(io, .real).toSeconds()});
    defer std.testing.allocator.free(home);
    defer std.Io.Dir.cwd().deleteTree(io, home) catch {};

    const xdg = try std.fs.path.join(std.testing.allocator, &.{ home, "share" });
    defer std.testing.allocator.free(xdg);
    const oc_dir = try std.fs.path.join(std.testing.allocator, &.{ xdg, "opencode" });
    defer std.testing.allocator.free(oc_dir);
    try std.Io.Dir.cwd().createDirPath(io, oc_dir);
    const db_path = try std.fs.path.join(std.testing.allocator, &.{ oc_dir, "opencode.db" });
    defer std.testing.allocator.free(db_path);
    try opencode_db.writeSyntheticFixtureDb(io, std.testing.allocator, db_path, now);

    var result = try runScan(io, std.testing.allocator, .{
        .home = home,
        .xdg_data_home = xdg,
        .now_secs = now,
        .days = 30,
        .only_host = .opencode,
    });
    defer result.deinit();

    try std.testing.expect(result.scorecard.sessions_scanned >= 1);
    const oc = result.scorecard.hosts[@intFromEnum(types.Host.opencode)];
    try std.testing.expect(oc.status == .ok);
    try std.testing.expect(oc.sessions_seen >= 1);

    var saw_danger = false;
    var saw_access = false;
    var saw_material = false;
    for (result.findings) |f| {
        try std.testing.expect(std.mem.indexOf(u8, f.detail, "ghp_fake") == null);
        try std.testing.expect(std.mem.indexOf(u8, f.title, "ghp_fake") == null);
        try std.testing.expect(std.mem.indexOf(u8, f.evidence_ref, "ghp_fake") == null);
        try std.testing.expect(std.mem.indexOf(u8, f.evidence_ref, "opencode.db#session/") != null);
        switch (f.kind) {
            .danger => saw_danger = true,
            .secret_access => saw_access = true,
            .secret_material => saw_material = true,
        }
    }
    try std.testing.expect(saw_danger);
    try std.testing.expect(saw_access);
    try std.testing.expect(saw_material);
    try std.testing.expect(result.total_findings >= 2);
}

test "engine opencode only_host ignores other hosts" {
    const io = std.testing.io;
    if (!opencode_db.sqlite3Available(io, std.testing.allocator)) return error.SkipZigTest;

    const now: i64 = 1_785_143_897;
    const home = try std.fmt.allocPrint(std.testing.allocator, "zig-cache/tmp-scan-engine-oc-only-{d}", .{std.Io.Timestamp.now(io, .real).toSeconds()});
    defer std.testing.allocator.free(home);
    defer std.Io.Dir.cwd().deleteTree(io, home) catch {};

    // Plant Claude session that would yield findings if scanned.
    const proj = try std.fs.path.join(std.testing.allocator, &.{ home, ".claude", "projects", "demo" });
    defer std.testing.allocator.free(proj);
    try std.Io.Dir.cwd().createDirPath(io, proj);
    const sess = try std.fs.path.join(std.testing.allocator, &.{ proj, "sess1.jsonl" });
    defer std.testing.allocator.free(sess);
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = sess,
        .data =
        \\{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Bash","input":{"command":"rm -rf /"}}]}}
        \\
        ,
    });

    const xdg = try std.fs.path.join(std.testing.allocator, &.{ home, "share" });
    defer std.testing.allocator.free(xdg);
    const oc_dir = try std.fs.path.join(std.testing.allocator, &.{ xdg, "opencode" });
    defer std.testing.allocator.free(oc_dir);
    try std.Io.Dir.cwd().createDirPath(io, oc_dir);
    const db_path = try std.fs.path.join(std.testing.allocator, &.{ oc_dir, "opencode.db" });
    defer std.testing.allocator.free(db_path);
    try opencode_db.writeSyntheticFixtureDb(io, std.testing.allocator, db_path, now);

    var result = try runScan(io, std.testing.allocator, .{
        .home = home,
        .xdg_data_home = xdg,
        .now_secs = now,
        .days = 30,
        .only_host = .opencode,
    });
    defer result.deinit();

    // Only OpenCode host account should be present in discovery loop results scored;
    // Claude must not contribute findings.
    for (result.findings) |f| {
        try std.testing.expect(f.host == .opencode);
    }
    try std.testing.expect(result.scorecard.hosts[@intFromEnum(types.Host.claude)].status == .not_found or
        result.scorecard.hosts[@intFromEnum(types.Host.claude)].sessions_seen == 0);
}

test "engine claude fixture yields danger and redacted secret_material" {
    const io = std.testing.io;
    const home = try std.fmt.allocPrint(std.testing.allocator, "zig-cache/tmp-scan-engine-claude-{d}", .{std.Io.Timestamp.now(io, .real).toSeconds()});
    defer std.testing.allocator.free(home);
    defer std.Io.Dir.cwd().deleteTree(io, home) catch {};

    const proj = try std.fs.path.join(std.testing.allocator, &.{ home, ".claude", "projects", "demo" });
    defer std.testing.allocator.free(proj);
    try std.Io.Dir.cwd().createDirPath(io, proj);
    const sess = try std.fs.path.join(std.testing.allocator, &.{ proj, "sess1.jsonl" });
    defer std.testing.allocator.free(sess);

    // Include high danger + secret material + secret access + low-noise allow.
    const body =
        \\{"type":"assistant","timestamp":"2026-07-28T12:00:00Z","message":{"content":[{"type":"tool_use","name":"Bash","input":{"command":"rm -rf /"}}]}}
        \\{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Bash","input":{"command":"cat .env"}}]}}
        \\{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Bash","input":{"command":"git status"}}]}}
        \\{"type":"user","message":{"content":[{"type":"text","text":"deploy key ghp_fakeSyntheticTokenValue1234567890abcd"}]}}
        \\
    ;
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = sess, .data = body });

    var result = try runScan(io, std.testing.allocator, .{
        .home = home,
        .all_time = true,
        .only_host = .claude,
    });
    defer result.deinit();

    try std.testing.expect(result.total_findings >= 2);

    var saw_danger = false;
    var saw_access = false;
    var saw_material = false;
    for (result.findings) |f| {
        try std.testing.expect(std.mem.indexOf(u8, f.detail, "ghp_fake") == null);
        try std.testing.expect(std.mem.indexOf(u8, f.title, "ghp_fake") == null);
        switch (f.kind) {
            .danger => saw_danger = true,
            .secret_access => saw_access = true,
            .secret_material => saw_material = true,
        }
    }
    try std.testing.expect(saw_danger);
    try std.testing.expect(saw_access);
    try std.testing.expect(saw_material);

    // git status must not appear as danger
    for (result.findings) |f| {
        if (f.kind == .danger) {
            try std.testing.expect(std.mem.indexOf(u8, f.detail, "git status") == null);
        }
    }
}

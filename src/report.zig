const std = @import("std");

const core_api = @import("ryk_core").api;
const core = @import("ryk_core").core;
const env_util = @import("env_util.zig");
const presentation = @import("presentation/mod.zig");
const tui = @import("ryk").tui;

pub const ParseIntegrityFailed = presentation.replay_event.ParseIntegrityFailed;

pub const PluginReadiness = struct {
    id: []const u8,
    label: []const u8,
    host_detected: bool,
    integration_present: bool,
};

/// Rich terminal report (default). Uses the ryk design system (`tui.theme` +
/// `tui.render`, libvaxis-backed capability detection and sync controls) so colour
/// degrades cleanly for pipes, `NO_COLOR`, and non-TTY sinks. Machine export paths
/// stay on `writeMarkdown` / `writeJson`.
pub fn writeHuman(
    io: std.Io,
    allocator: std.mem.Allocator,
    writer: anytype,
    workspace_root: []const u8,
    session: core_api.ReplaySession,
) !void {
    var redactions = try presentation.replay_event.summarizeRedactions(allocator, session, session.verified);
    defer redactions.deinit(allocator);
    const plugins = try pluginReadiness(io, allocator, workspace_root);

    const safe_command = try presentation.redact.redactOwned(allocator, session.command_display);
    defer allocator.free(safe_command);
    const safe_policy = try presentation.redact.redactOwned(allocator, session.policy);
    defer allocator.free(safe_policy);

    const denied_count = session.events.len;
    var denied_buf: [32]u8 = undefined;
    const denied_value = try std.fmt.bufPrint(&denied_buf, "{d}", .{denied_count});

    var redaction_buf: [256]u8 = undefined;
    const redaction_value = try formatRedactionSummary(&redaction_buf, redactions.count, redactions.labels.items);

    const hash_value: []const u8 = if (session.verified) "verified" else "failed or unavailable";

    // ── Brand header ──────────────────────────────────────────────────────
    try writer.writeAll("  ");
    try tui.theme.paintBold(io, writer, .brand, "🛡  ryk");
    try writer.writeAll(" · ");
    try tui.theme.paintBold(io, writer, .text_bright, "safety report");
    try writer.writeAll("\n  ");
    try tui.theme.paint(io, writer, .muted, "Local evidence · denied actions · plugin readiness");
    try writer.writeAll("\n");
    try writer.writeAll("  ");
    try tui.render.ruleLine(io, writer, 56);
    try writer.writeAll("\n\n");

    // Integrity chip — scannable before the detail grid
    try writer.writeAll("  ");
    if (session.verified) {
        try tui.render.badge(io, writer, .pass);
        try writer.writeAll(" ");
        try tui.theme.paint(io, writer, .success, "hash verified");
    } else {
        try tui.render.badge(io, writer, .fail);
        try writer.writeAll(" ");
        try tui.theme.paint(io, writer, .danger, "hash failed or unavailable");
    }
    try writer.writeAll("   ");
    if (denied_count > 0) {
        try tui.render.badge(io, writer, .deny);
        try writer.writeAll(" ");
        try tui.theme.paint(io, writer, .danger, denied_value);
        try writer.writeAll(" ");
        try tui.theme.paint(io, writer, .muted, "denied");
    } else {
        try tui.render.badge(io, writer, .pass);
        try writer.writeAll(" ");
        try tui.theme.paint(io, writer, .success, "nothing denied");
    }
    try writer.writeAll("\n\n");

    // ── Overview ──────────────────────────────────────────────────────────
    try sectionTitle(io, writer, "Overview");
    const meta_rows = [_]tui.render.KV{
        .{ .label = "Session", .value = session.session_id },
        .{ .label = "Command", .value = safe_command },
        .{ .label = "Status", .value = session.status_display },
        .{ .label = "Policy", .value = safe_policy },
        .{ .label = "Hash chain", .value = hash_value },
        .{ .label = "Denied", .value = denied_value },
        .{ .label = "Redactions", .value = redaction_value },
    };
    try tui.render.keyValue(io, writer, &meta_rows);
    try writer.writeAll("\n");

    // ── Prevention summary ────────────────────────────────────────────────
    try sectionTitle(io, writer, "What ryk stopped");
    if (denied_count == 0) {
        try tui.render.callout(
            io,
            writer,
            .success,
            "No denied actions in this session",
            "ryk recorded the run but nothing was blocked. Try a protected command that your policy would deny, then re-run ryk report.",
        );
    } else {
        var summary_buf: [96]u8 = undefined;
        const summary = try std.fmt.bufPrint(
            &summary_buf,
            "Prevented {d} action{s} under the active local policy",
            .{ denied_count, if (denied_count == 1) "" else "s" },
        );
        try writer.writeAll("  ");
        try tui.theme.paint(io, writer, .muted, summary);
        try writer.writeAll("\n\n");

        const views = try presentation.replay_event.deniedActionViews(allocator, session);
        defer {
            for (views) |*view| view.deinit(allocator);
            allocator.free(views);
        }
        for (views, 0..) |view, index| {
            try writeDeniedAction(io, writer, index + 1, view.target, view.reason);
        }
        try writer.writeAll("\n");
    }

    // ── Plugin readiness ──────────────────────────────────────────────────
    try sectionTitle(io, writer, "Plugin readiness");
    var plugin_rows_storage: [2][3][]const u8 = undefined;
    var plugin_rows: [2][]const []const u8 = undefined;
    for (plugins, 0..) |plugin, i| {
        plugin_rows_storage[i] = .{
            plugin.label,
            if (plugin.host_detected) "detected" else "not detected",
            if (plugin.integration_present) "present" else "missing",
        };
        plugin_rows[i] = &plugin_rows_storage[i];
    }
    try tui.render.table(io, writer, &.{
        .{ .name = "HOST" },
        .{ .name = "BINARY" },
        .{ .name = "INTEGRATION" },
    }, &plugin_rows);
    try writer.writeAll("\n");

    // ── Footer ────────────────────────────────────────────────────────────
    try writer.writeAll("  ");
    try tui.theme.paint(io, writer, .muted, "Export");
    try writer.writeAll("  ");
    try tui.theme.paint(io, writer, .info, "ryk report --format markdown");
    try writer.writeAll("  ");
    try tui.theme.paint(io, writer, .muted, "·");
    try writer.writeAll("  ");
    try tui.theme.paint(io, writer, .info, "ryk report --format json");
    try writer.writeAll("\n");
}

fn sectionTitle(io: std.Io, writer: anytype, title: []const u8) !void {
    try writer.writeAll("  ");
    try tui.theme.paintBold(io, writer, .text_bright, title);
    try writer.writeAll("\n");
}

fn writeDeniedAction(io: std.Io, writer: anytype, index: usize, target: []const u8, reason: []const u8) !void {
    try writer.writeAll("  ");
    var idx_buf: [12]u8 = undefined;
    const idx = try std.fmt.bufPrint(&idx_buf, "{d}.", .{index});
    try tui.theme.paint(io, writer, .muted, idx);
    try writer.writeAll(" ");
    try tui.render.badge(io, writer, .deny);
    try writer.writeAll(" ");
    try tui.theme.paintBold(io, writer, .text_bright, target);
    try writer.writeAll("\n");
    try writer.writeAll("     ");
    try tui.theme.paint(io, writer, .muted, "Reason");
    try writer.writeAll("  ");
    try tui.theme.paint(io, writer, .text, reason);
    try writer.writeAll("\n");
}

fn formatRedactionSummary(buf: []u8, count: usize, labels: []const []u8) ![]const u8 {
    if (labels.len == 0) {
        return std.fmt.bufPrint(buf, "{d}", .{count});
    }
    // Prefer full "N (a, b)" when it fits; else fall back to count only.
    var aw: std.Io.Writer = .fixed(buf);
    aw.print("{d} (", .{count}) catch return std.fmt.bufPrint(buf, "{d}", .{count});
    for (labels, 0..) |label, index| {
        if (index > 0) aw.writeAll(", ") catch return std.fmt.bufPrint(buf, "{d}", .{count});
        aw.writeAll(label) catch return std.fmt.bufPrint(buf, "{d}", .{count});
    }
    aw.writeAll(")") catch return std.fmt.bufPrint(buf, "{d}", .{count});
    return aw.buffered();
}

pub fn writeMarkdown(io: std.Io, allocator: std.mem.Allocator, writer: anytype, workspace_root: []const u8, session: core_api.ReplaySession) !void {
    var redactions = try presentation.replay_event.summarizeRedactions(allocator, session, session.verified);
    defer redactions.deinit(allocator);
    const plugins = try pluginReadiness(io, allocator, workspace_root);

    const safe_command = try presentation.redact.redactOwned(allocator, session.command_display);
    defer allocator.free(safe_command);
    const safe_policy = try presentation.redact.redactOwned(allocator, session.policy);
    defer allocator.free(safe_policy);

    try writer.print("# ryk Safety Report: {s}\n\n", .{session.session_id});
    try writer.print("- Session id: `{s}`\n", .{session.session_id});
    try writer.print("- Command: `{s}`\n", .{safe_command});
    try writer.print("- Status: {s}\n", .{session.status_display});
    try writer.print("- Policy path: {s}\n", .{safe_policy});
    try writer.print("- Hash-chain verification: {s}\n", .{if (session.verified) "verified" else "failed or unavailable"});
    try writer.print("- Denied/prevented actions: {d}\n", .{session.events.len});
    try writer.print("- Redactions: {d}", .{redactions.count});
    if (redactions.labels.items.len > 0) {
        try writer.writeAll(" (");
        for (redactions.labels.items, 0..) |label, index| {
            if (index > 0) try writer.writeAll(", ");
            try writer.writeAll(label);
        }
        try writer.writeAll(")");
    }
    try writer.writeAll("\n\n");

    try writer.writeAll("## What ryk Prevented\n\n");
    if (session.events.len == 0) {
        try writer.writeAll("ryk did not record a denied action in this session.\n\n");
    } else {
        try writer.print("ryk prevented {d} action{s} from continuing because the active local policy denied them.\n\n", .{ session.events.len, if (session.events.len == 1) "" else "s" });
        const views = try presentation.replay_event.deniedActionViews(allocator, session);
        defer {
            for (views) |*view| view.deinit(allocator);
            allocator.free(views);
        }
        for (views) |view| {
            try writer.print("- `{s}` was blocked. Reason: {s}\n", .{ view.target, view.reason });
        }
        try writer.writeByte('\n');
    }

    try writer.writeAll("## Plugin Readiness\n\n");
    for (plugins) |plugin| {
        try writer.print("- {s}: host {s}, integration {s}\n", .{
            plugin.label,
            if (plugin.host_detected) "detected" else "not detected",
            if (plugin.integration_present) "present" else "missing",
        });
    }
}

pub fn writeJson(io: std.Io, allocator: std.mem.Allocator, writer: anytype, workspace_root: []const u8, session: core_api.ReplaySession) !void {
    var redactions = try presentation.replay_event.summarizeRedactions(allocator, session, session.verified);
    defer redactions.deinit(allocator);
    const plugins = try pluginReadiness(io, allocator, workspace_root);

    const safe_command = try presentation.redact.redactOwned(allocator, session.command_display);
    defer allocator.free(safe_command);
    const safe_policy = try presentation.redact.redactOwned(allocator, session.policy);
    defer allocator.free(safe_policy);

    try writer.writeByte('{');
    try writer.writeAll("\"session_id\":");
    try core.util.writeJsonString(writer, session.session_id);
    try writer.writeAll(",\"command\":");
    try core.util.writeJsonString(writer, safe_command);
    try writer.writeAll(",\"status\":");
    try core.util.writeJsonString(writer, session.status_display);
    try writer.writeAll(",\"policy_path\":");
    try core.util.writeJsonString(writer, safe_policy);
    try writer.print(",\"hash_chain_verified\":{},\"denied_count\":{d}", .{ session.verified, session.events.len });
    try writer.print(",\"redactions\":{{\"count\":{d},\"labels\":[", .{redactions.count});
    for (redactions.labels.items, 0..) |label, index| {
        if (index > 0) try writer.writeByte(',');
        try core.util.writeJsonString(writer, label);
    }
    try writer.writeAll("]},\"denied_actions\":[");
    const views = try presentation.replay_event.deniedActionViews(allocator, session);
    defer {
        for (views) |*view| view.deinit(allocator);
        allocator.free(views);
    }
    for (views, 0..) |view, index| {
        if (index > 0) try writer.writeByte(',');
        try writer.writeAll("{\"event_type\":");
        try core.util.writeJsonString(writer, view.event_type);
        try writer.writeAll(",\"target\":");
        try core.util.writeJsonString(writer, view.target);
        try writer.writeAll(",\"reason\":");
        try core.util.writeJsonString(writer, view.reason);
        try writer.writeByte('}');
    }
    try writer.writeAll("],\"plugins\":[");
    for (plugins, 0..) |plugin, index| {
        if (index > 0) try writer.writeByte(',');
        try writer.writeAll("{\"id\":");
        try core.util.writeJsonString(writer, plugin.id);
        try writer.writeAll(",\"host_detected\":");
        try writer.writeAll(if (plugin.host_detected) "true" else "false");
        try writer.writeAll(",\"integration_present\":");
        try writer.writeAll(if (plugin.integration_present) "true" else "false");
        try writer.writeByte('}');
    }
    try writer.writeAll("]}\n");
}

pub fn pluginReadiness(io: std.Io, allocator: std.mem.Allocator, workspace_root: []const u8) ![2]PluginReadiness {
    return .{
        .{
            .id = "openclaw",
            .label = "OpenClaw",
            .host_detected = try executableInPath(io, allocator, "openclaw"),
            .integration_present = try pathExists(io, allocator, workspace_root, "integrations/openclaw-plugin"),
        },
        .{
            .id = "hermes",
            .label = "Hermes",
            .host_detected = try executableInPath(io, allocator, "hermes"),
            .integration_present = try pathExists(io, allocator, workspace_root, "integrations/hermes-plugin"),
        },
    };
}

fn pathExists(io: std.Io, allocator: std.mem.Allocator, root: []const u8, rel: []const u8) !bool {
    const path = try std.fs.path.join(allocator, &.{ root, rel });
    defer allocator.free(path);
    std.Io.Dir.cwd().access(io, path, .{}) catch return false;
    return true;
}

fn executableInPath(io: std.Io, allocator: std.mem.Allocator, name: []const u8) !bool {
    var env_map = env_util.createProcessMap(allocator) catch return false;
    defer env_map.deinit();
    const path_owned = env_util.getOwned(&env_map, allocator, "PATH") catch return false;
    const path = path_owned orelse return false;
    defer allocator.free(path);
    const separator: u8 = if (@import("builtin").os.tag == .windows) ';' else ':';
    var parts = std.mem.splitScalar(u8, path, separator);
    while (parts.next()) |part| {
        if (part.len == 0) continue;
        const candidate = try std.fs.path.join(allocator, &.{ part, name });
        defer allocator.free(candidate);
        if (std.Io.Dir.cwd().access(io, candidate, .{})) |_| return true else |_| {}
    }
    return false;
}

test "report markdown and json redact synthetic secrets in reason and target" {
    const allocator = std.testing.allocator;
    var session = try presentation.fixtures.syntheticSecretReplaySession(allocator, .{});
    defer session.deinit();

    var md: std.Io.Writer.Allocating = .init(allocator);
    defer md.deinit();
    try writeMarkdown(std.testing.io, allocator, &md.writer, "/tmp", session);
    const md_out = try md.toOwnedSlice();
    defer allocator.free(md_out);
    try std.testing.expect(std.mem.indexOf(u8, md_out, presentation.fixtures.synthetic_secret) == null);
    try std.testing.expect(std.mem.indexOf(u8, md_out, "[REDACTED]") != null);

    var json: std.Io.Writer.Allocating = .init(allocator);
    defer json.deinit();
    try writeJson(std.testing.io, allocator, &json.writer, "/tmp", session);
    const json_out = try json.toOwnedSlice();
    defer allocator.free(json_out);
    try std.testing.expect(std.mem.indexOf(u8, json_out, presentation.fixtures.synthetic_secret) == null);

    var human: std.Io.Writer.Allocating = .init(allocator);
    defer human.deinit();
    try writeHuman(std.testing.io, allocator, &human.writer, "/tmp", session);
    const human_out = try human.toOwnedSlice();
    defer allocator.free(human_out);
    try std.testing.expect(std.mem.indexOf(u8, human_out, presentation.fixtures.synthetic_secret) == null);
    try std.testing.expect(std.mem.indexOf(u8, human_out, "[REDACTED]") != null);
}

test "report fails closed on unparseable event when verification claimed" {
    const allocator = std.testing.allocator;
    var session = try presentation.fixtures.syntheticSecretReplaySession(allocator, .{ .session_id = "zh2-parse", .verified = true });
    defer session.deinit();
    allocator.free(session.events[0].raw);
    session.events[0].raw = try allocator.dupe(u8, "{not-valid-json");

    var md: std.Io.Writer.Allocating = .init(allocator);
    defer md.deinit();
    try std.testing.expectError(error.ParseIntegrityFailed, writeMarkdown(std.testing.io, allocator, &md.writer, "/tmp", session));

    var json: std.Io.Writer.Allocating = .init(allocator);
    defer json.deinit();
    try std.testing.expectError(error.ParseIntegrityFailed, writeJson(std.testing.io, allocator, &json.writer, "/tmp", session));

    var human: std.Io.Writer.Allocating = .init(allocator);
    defer human.deinit();
    try std.testing.expectError(error.ParseIntegrityFailed, writeHuman(std.testing.io, allocator, &human.writer, "/tmp", session));
}

test "report renders denied action and redaction summary" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const session_id = try @import("blocked_action_fixture.zig").createBlockedActionSession(std.testing.io, std.testing.allocator, root);
    defer std.testing.allocator.free(session_id);
    var replay = try core_api.loadReplay(std.testing.io, std.testing.allocator, root, .{ .session = "last", .only_denied = true, .verify = true });
    defer replay.deinit();
    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer aw.deinit();
    try writeMarkdown(std.testing.io, std.testing.allocator, &aw.writer, root, replay);
    const out = try aw.toOwnedSlice();
    defer std.testing.allocator.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "ryk Safety Report") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "blocked") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Hash-chain verification: verified") != null);
}

test "report human renderer shows sections and deny badge text without colour escapes" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const session_id = try @import("blocked_action_fixture.zig").createBlockedActionSession(std.testing.io, std.testing.allocator, root);
    defer std.testing.allocator.free(session_id);
    var replay = try core_api.loadReplay(std.testing.io, std.testing.allocator, root, .{ .session = "last", .only_denied = true, .verify = true });
    defer replay.deinit();
    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer aw.deinit();
    try writeHuman(std.testing.io, std.testing.allocator, &aw.writer, root, replay);
    const out = try aw.toOwnedSlice();
    defer std.testing.allocator.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "safety report") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Overview") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "What ryk stopped") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Plugin readiness") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "[DENY]") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "[PASS]") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "hash verified") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Redactions") != null);
    try std.testing.expect(std.mem.indexOfScalar(u8, out, 0x1b) == null);
}

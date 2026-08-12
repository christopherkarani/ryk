const std = @import("std");
const ryk = @import("ryk");

const core = ryk.core;
const dashboard = ryk.dashboard;
const feed_writer = ryk.cli.feed_writer;
const rust_visibility = ryk.cli.rust_visibility;
const shell_eval = ryk.cli.shell_eval;

const fake_secret = "sk-fakeSyntheticOpenAIKey1234567890";

test "phase2510 hook deny feed record is zig-backed and redacted" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var record = try rust_visibility.buildFeedRecordFromHookDecision(
        std.testing.allocator,
        std.testing.io,
        root,
        "claude",
        "healthy",
        "deny",
        "blocked OPENAI_API_KEY=sk-fakeSyntheticOpenAIKey1234567890 in command",
        "destructive_rm",
        "Critical",
        "Use a safer workflow.",
        "git",
        null,
    );
    defer record.deinit(std.testing.allocator);

    try feed_writer.appendRecord(std.testing.io, std.testing.allocator, root, record);

    const loaded = try feed_writer.loadRecent(std.testing.io, std.testing.allocator, root, 4);
    defer {
        for (loaded) |*item| item.deinit(std.testing.allocator);
        std.testing.allocator.free(loaded);
    }

    try std.testing.expectEqual(@as(usize, 1), loaded.len);
    try std.testing.expectEqualStrings("zig-native", loaded[0].record.decision_source);
    try std.testing.expectEqualStrings("hook", loaded[0].record.event_source);
    try std.testing.expectEqualStrings(root, loaded[0].record.workspace_root);
    try std.testing.expectEqualStrings("claude", loaded[0].record.host.?);
    try std.testing.expect(std.mem.indexOf(u8, loaded[0].raw, "agent_host") == null);
    try std.testing.expectEqualStrings("git", loaded[0].record.pack_id.?);
    try std.testing.expectEqualStrings("Critical", loaded[0].record.severity.?);
    try std.testing.expectEqualStrings("shell command (redacted)", loaded[0].record.target_summary);
    try std.testing.expect(std.mem.indexOf(u8, loaded[0].raw, fake_secret) == null);
    try std.testing.expect(std.mem.indexOf(u8, loaded[0].raw, "matched_text_preview") == null);
}

test "phase2510 run deny feed record is zig-backed with pack metadata" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var metadata: core.event.EventMetadata = .{};
    defer metadata.deinit(std.testing.allocator);

    const audit_options = shell_eval.ShellAuditOptions{
        .io = std.testing.io,
        .workspace_root = root,
        .event_source = rust_visibility.event_source_run,
        .session_id = "phase2510-session",
        .verified = false,
    };

    var decision = try shell_eval.evaluateCommand(
        std.testing.allocator,
        .ci,
        &.{ "npm", "install", fake_secret },
        root,
        shell_eval.mockDaemonDenyEvaluator,
        &metadata,
        audit_options,
        &.{},
    );
    defer decision.deinit(std.testing.allocator);
    try std.testing.expectEqual(core.decision.DecisionResult.deny, decision.decision.result);

    const loaded = try feed_writer.loadRecent(std.testing.io, std.testing.allocator, root, 4);
    defer {
        for (loaded) |*item| item.deinit(std.testing.allocator);
        std.testing.allocator.free(loaded);
    }

    try std.testing.expect(loaded.len >= 1);
    try std.testing.expectEqualStrings("zig-native", loaded[loaded.len - 1].record.decision_source);
    try std.testing.expectEqualStrings("run", loaded[loaded.len - 1].record.event_source);
    try std.testing.expectEqualStrings("deny", loaded[loaded.len - 1].record.decision);
    try std.testing.expectEqualStrings("core.filesystem", loaded[loaded.len - 1].record.pack_id.?);
    try std.testing.expectEqualStrings("critical", loaded[loaded.len - 1].record.severity.?);
    try std.testing.expect(std.mem.indexOf(u8, loaded[loaded.len - 1].raw, fake_secret) == null);
    try std.testing.expect(std.mem.indexOf(u8, loaded[loaded.len - 1].raw, "matched_text_preview") == null);
    try std.testing.expectEqualStrings("zig-native", metadata.decision_source.?);
    try std.testing.expectEqualStrings("run", metadata.event_source.?);
}

test "phase2510 run allow feed record when audit options provided" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    const audit_options = shell_eval.ShellAuditOptions{
        .io = std.testing.io,
        .workspace_root = root,
        .event_source = rust_visibility.event_source_run,
        .session_id = "phase2510-allow",
        .verified = false,
    };

    var decision = try shell_eval.evaluateCommand(
        std.testing.allocator,
        .strict,
        &.{"true"},
        root,
        shell_eval.mockDaemonAllowEvaluator,
        null,
        audit_options,
        &.{},
    );
    defer decision.deinit(std.testing.allocator);
    try std.testing.expectEqual(core.decision.DecisionResult.allow, decision.decision.result);

    const loaded = try feed_writer.loadRecent(std.testing.io, std.testing.allocator, root, 4);
    defer {
        for (loaded) |*item| item.deinit(std.testing.allocator);
        std.testing.allocator.free(loaded);
    }

    try std.testing.expect(loaded.len >= 1);
    try std.testing.expectEqualStrings("allow", loaded[loaded.len - 1].record.decision);
    try std.testing.expectEqualStrings("zig-native", loaded[loaded.len - 1].record.decision_source);
}

test "phase2510 daemon unavailable and incompatible feed statuses" {
    const allocator = std.testing.allocator;

    var unavailable = try rust_visibility.buildFeedRecordFromUnavailable(
        allocator,
        std.testing.io,
        "/tmp/ryk-workspace",
        rust_visibility.event_source_hook,
        "codex",
        error.SocketConnectFailed,
        null,
        false,
    );
    defer unavailable.deinit(allocator);
    try std.testing.expectEqualStrings("unavailable", unavailable.daemon_status);

    var incompatible = try rust_visibility.buildFeedRecordFromUnavailable(
        allocator,
        std.testing.io,
        "/tmp/ryk-workspace",
        rust_visibility.event_source_hook,
        "codex",
        error.ProtocolMismatch,
        null,
        false,
    );
    defer incompatible.deinit(allocator);
    try std.testing.expectEqualStrings("incompatible", incompatible.daemon_status);

    var metadata = try rust_visibility.metadataForUnavailable(
        allocator,
        rust_visibility.event_source_run,
        "claude",
        error.ProtocolMismatch,
    );
    defer metadata.deinit(allocator);
    try std.testing.expectEqualStrings("incompatible", metadata.daemon_status.?);
}

test "phase2510 status json exposes daemon health and shell feed" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var record = try rust_visibility.buildFeedRecordFromHookDecision(
        std.testing.allocator,
        std.testing.io,
        root,
        "claude",
        "healthy",
        "deny",
        "blocked by ryk policy rule: destructive_rm",
        "destructive_rm",
        "Critical",
        "Use a safer workflow.",
        "git",
        null,
    );
    defer record.deinit(std.testing.allocator);
    try feed_writer.appendRecord(std.testing.io, std.testing.allocator, root, record);

    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    try dashboard.writeStatusJson(std.testing.io, std.testing.allocator, &aw.writer, root);
    var out = aw.toArrayList();
    defer out.deinit(std.testing.allocator);

    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"daemon_health\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"rust_shell_decisions\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"decision_source\":\"zig-native\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"pack_id\":\"git\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"severity\":\"Critical\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "shell command (redacted)") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "matched_text_preview") == null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"raw\"") == null);
}

test "phase2510 zig-native session replay blocked actions remain compatible" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    const timestamp = core.time.Timestamp.fromUnixSeconds(1_777_983_130);
    const session = core.session.Session{
        .id = try core.session.generateSessionId(timestamp),
        .started_at = timestamp,
        .ended_at = timestamp,
        .command = "ryk",
        .args = &.{ "run", "--", "curl", "https://evil.example" },
        .workspace_root = root,
        .mode = .strict,
        .platform = core.platform.detectOs(),
    };
    var writer = try ryk.core_api.createAuditWriter(std.testing.io, std.testing.allocator, session);
    defer writer.deinit();
    const ev = try ryk.core_api.createAuditEvent(.{
        .session_id = session.id,
        .event_id = try core.event.generateEventId(timestamp),
        .timestamp = timestamp,
        .event_type = .network_connect_denied,
        .actor = .{ .kind = .ryk, .display = "ryk" },
        .target = .{ .kind = .network_endpoint, .value = "https://evil.example" },
        .decision = ryk.core_api.makeDecision(.{ .result = .deny, .reason = "network denied" }),
    });
    try ryk.core_api.appendAuditEvent(&writer, ev);
    try writer.writeLastPointer();
    try ryk.core_api.writeAuditSummary(std.testing.allocator, writer.sessionDirPath(), .{
        .session = session,
        .status = .{ .exited = 1 },
        .event_count = writer.event_count,
        .final_event_hash = writer.finalHash().?,
        .policy = ".ryk/policy.yaml",
        .product_label = "ryk",
    });

    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    try dashboard.writeStatusJson(std.testing.io, std.testing.allocator, &aw.writer, root);
    var out = aw.toArrayList();
    defer out.deinit(std.testing.allocator);

    try std.testing.expect(std.mem.indexOf(u8, out.items, "network_connect_denied") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "https://evil.example") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"raw\"") == null);
}

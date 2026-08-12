const std = @import("std");
const ryk = @import("ryk");

const core_api = ryk.core_api;
const presentation = ryk.presentation;
const report = ryk.report;
const rust_visibility = ryk.cli.rust_visibility;

test "zh2 cross-sink matrix redacts shared synthetic token from report and feed" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fake_secret = presentation.fixtures.synthetic_secret;

    const feed_reason_input = try std.fmt.allocPrint(allocator, "blocked OPENAI_API_KEY={s} in command", .{fake_secret});
    defer allocator.free(feed_reason_input);
    var feed_record = try rust_visibility.buildFeedRecordFromHookDecision(
        allocator,
        io,
        "/tmp/ryk-zh2",
        "claude",
        "healthy",
        "deny",
        feed_reason_input,
        "destructive_rm",
        "Critical",
        "Use a safer workflow.",
        "git",
        null,
    );
    defer feed_record.deinit(allocator);
    var feed_json: std.Io.Writer.Allocating = .init(allocator);
    defer feed_json.deinit();
    try rust_visibility.writeFeedRecordJson(&feed_json.writer, feed_record);
    try std.testing.expect(std.mem.indexOf(u8, feed_json.written(), fake_secret) == null);

    var session = try presentation.fixtures.syntheticSecretReplaySession(allocator, .{ .session_id = "zh2-matrix" });
    defer session.deinit();

    var json: std.Io.Writer.Allocating = .init(allocator);
    defer json.deinit();
    try report.writeJson(io, allocator, &json.writer, "/tmp", session);
    const report_out = try json.toOwnedSlice();
    defer allocator.free(report_out);
    try std.testing.expect(std.mem.indexOf(u8, report_out, fake_secret) == null);
    try std.testing.expect(std.mem.indexOf(u8, report_out, "[REDACTED]") != null);
}

test "zh2 replay verify fails closed on tampered hash chain" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    const session_id = try ryk.blocked_action_fixture.createBlockedActionSession(std.testing.io, std.testing.allocator, root);
    defer std.testing.allocator.free(session_id);

    const session_dir = try std.fs.path.join(std.testing.allocator, &.{ root, ".ryk", "sessions", session_id });
    defer std.testing.allocator.free(session_dir);
    const events_path = try std.fs.path.join(std.testing.allocator, &.{ session_dir, "events.jsonl" });
    defer std.testing.allocator.free(events_path);

    const original = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, events_path, std.testing.allocator, .limited(64 * 1024));
    defer std.testing.allocator.free(original);
    const tampered = try std.mem.replaceOwned(u8, std.testing.allocator, original, "fixture-target", "tampered-target");
    defer std.testing.allocator.free(tampered);
    try std.Io.Dir.cwd().writeFile(std.testing.io, .{ .sub_path = events_path, .data = tampered });

    try std.testing.expectError(error.HashVerificationFailed, core_api.loadReplay(std.testing.io, std.testing.allocator, root, .{
        .session = session_id,
        .only_denied = true,
        .verify = true,
    }));
}

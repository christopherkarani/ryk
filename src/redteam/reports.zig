const std = @import("std");

const audit = @import("ryk_core").audit;
const core = @import("ryk_core").core;
const runner = @import("runner.zig");
const scorecard = @import("scorecard.zig");
const tui = @import("ryk").tui;

pub const implemented = true;

/// Fixed provenance for the current fixture-engine suite.
/// Not workspace policy; not host-hook install / OS enforcement.
pub const suite_kind = "engine-self-test";
pub const policy_id = "builtin:redteam";
pub const policy_path = "preset:redteam";
pub const evaluator_id = "zig-in-process";
pub const network_enforcement = "unavailable";
pub const uncovered_boundaries = [_][]const u8{
    "workspace_policy",
    "rust_daemon_shell",
    "wrapper_path",
    "host_hooks",
    "network_proxy",
    "os_enforced_fs",
};

pub fn writeHuman(io: std.Io, writer: anytype, suite: runner.SuiteResult) !void {
    const totals = suite.totals();
    try writer.writeAll("ryk Redteam — engine self-test\n\n");
    try writeHumanProvenance(writer);
    try writer.writeByte('\n');

    var fixture_rows: std.ArrayList([]const []const u8) = .empty;
    var fixture_values: std.ArrayList([]u8) = .empty;
    defer {
        for (fixture_rows.items) |row| suite.allocator.free(row);
        fixture_rows.deinit(suite.allocator);
        for (fixture_values.items) |value| suite.allocator.free(value);
        fixture_values.deinit(suite.allocator);
    }
    for (suite.results) |result| {
        const row = try suite.allocator.alloc([]const u8, 4);
        row[0] = switch (result.status) {
            .passed => "✓ PASS",
            .failed => "✗ FAIL",
            .skipped => "○ SKIP",
        };
        const safe_id = audit.redact_bridge.redactAlloc(suite.allocator, result.id) catch |err| {
            suite.allocator.free(row);
            return err;
        };
        fixture_values.append(suite.allocator, safe_id) catch |err| {
            suite.allocator.free(safe_id);
            suite.allocator.free(row);
            return err;
        };
        row[1] = safe_id;
        row[2] = result.category.display();
        const safe_detail = audit.redact_bridge.redactAlloc(suite.allocator, result.failure_reason orelse result.name) catch |err| {
            suite.allocator.free(row);
            return err;
        };
        fixture_values.append(suite.allocator, safe_detail) catch |err| {
            suite.allocator.free(safe_detail);
            suite.allocator.free(row);
            return err;
        };
        row[3] = safe_detail;
        fixture_rows.append(suite.allocator, row) catch |err| {
            suite.allocator.free(row);
            return err;
        };
    }
    const fixture_columns = [_]tui.render.TableColumn{
        .{ .name = "Result" }, .{ .name = "Fixture" }, .{ .name = "Category" }, .{ .name = "Details" },
    };
    try tui.render.table(io, writer, &fixture_columns, fixture_rows.items);
    try writer.writeByte('\n');

    var category_rows: std.ArrayList([]const []const u8) = .empty;
    var category_counts: std.ArrayList([]u8) = .empty;
    defer {
        for (category_rows.items) |row| suite.allocator.free(row);
        category_rows.deinit(suite.allocator);
        for (category_counts.items) |value| suite.allocator.free(value);
        category_counts.deinit(suite.allocator);
    }
    for (scorecard.ordered_categories) |category| {
        const category_total = scorecard.summarizeCategory(runner.FixtureResult, category, suite.results);
        if (category_total.fixtures == 0) continue;
        const count = if (category_total.skipped > 0)
            try std.fmt.allocPrint(suite.allocator, "{d}/{d} passed · {d} skipped", .{ category_total.passed, category_total.fixtures, category_total.skipped })
        else
            try std.fmt.allocPrint(suite.allocator, "{d}/{d} passed", .{ category_total.passed, category_total.fixtures });
        category_counts.append(suite.allocator, count) catch |err| {
            suite.allocator.free(count);
            return err;
        };
        const row = try suite.allocator.alloc([]const u8, 2);
        row[0] = category.display();
        row[1] = count;
        category_rows.append(suite.allocator, row) catch |err| {
            suite.allocator.free(row);
            return err;
        };
    }
    try writer.writeAll("Category summary\n");
    const category_columns = [_]tui.render.TableColumn{ .{ .name = "Category" }, .{ .name = "Score" } };
    try tui.render.table(io, writer, &category_columns, category_rows.items);
    try writer.writeByte('\n');
    try writer.print(
        \\Overall (fixture engine self-test only — not workspace policy assurance):
        \\  {d}/{d} fixtures passed
        \\  {d}%
        \\
    , .{ totals.passed, totals.fixtures, totals.percent() });
    var wrote_skipped = false;
    for (suite.results) |result| {
        if (result.status != .skipped) continue;
        if (!wrote_skipped) {
            try writer.writeAll("\nSkipped:\n");
            wrote_skipped = true;
        }
        try writer.writeAll("  ");
        const safe_id = try audit.redact_bridge.redactAlloc(suite.allocator, result.id);
        defer suite.allocator.free(safe_id);
        try tui.terminal_text.write(writer, safe_id, .single_line);
        try writer.writeAll(": ");
        const safe_reason = try audit.redact_bridge.redactAlloc(suite.allocator, result.failure_reason orelse "skipped");
        defer suite.allocator.free(safe_reason);
        try tui.terminal_text.write(writer, safe_reason, .single_line);
        try writer.writeByte('\n');
    }
}

fn writeHumanProvenance(writer: anytype) !void {
    try writer.writeAll("Provenance\n");
    try writer.print("  suite_kind:              {s}\n", .{suite_kind});
    try writer.print("  policy:                  {s}\n", .{policy_id});
    try writer.print("  policy_path:             {s}\n", .{policy_path});
    try writer.print("  evaluator:               {s}\n", .{evaluator_id});
    try writer.writeAll("  real_action_attempted:   false\n");
    try writer.print("  network_enforcement:     {s}\n", .{network_enforcement});
    try writer.writeAll("  uncovered_boundaries:    ");
    for (uncovered_boundaries, 0..) |boundary, index| {
        if (index > 0) try writer.writeAll(", ");
        try writer.writeAll(boundary);
    }
    try writer.writeByte('\n');
    try writer.writeAll("  note: 100% does not mean your workspace policy or installed enforcement is protected\n");
}

pub fn writeJson(writer: anytype, suite: runner.SuiteResult) !void {
    const totals = suite.totals();
    try writer.writeAll("{\"version\":1,\"provenance\":");
    try writeProvenanceJson(writer);
    try writer.writeAll(",\"totals\":");
    try writeTotals(writer, totals);
    try writer.writeAll(",\"categories\":[");
    var wrote_category = false;
    for (scorecard.ordered_categories) |category| {
        const category_total = scorecard.summarizeCategory(runner.FixtureResult, category, suite.results);
        if (category_total.fixtures == 0) continue;
        if (wrote_category) try writer.writeByte(',');
        wrote_category = true;
        try writer.writeByte('{');
        try writer.writeAll("\"category\":");
        try writeSafeJsonString(writer, category.slug());
        try writer.writeAll(",\"name\":");
        try writeSafeJsonString(writer, category.display());
        try writer.print(",\"fixtures\":{d},\"passed\":{d},\"failed\":{d},\"skipped\":{d},\"points_possible\":{d},\"points_earned\":{d}", .{
            category_total.fixtures,
            category_total.passed,
            category_total.failed,
            category_total.skipped,
            category_total.points_possible,
            category_total.points_earned,
        });
        try writer.writeByte('}');
    }
    try writer.writeAll("],\"fixtures\":[");
    for (suite.results, 0..) |result, index| {
        if (index > 0) try writer.writeByte(',');
        try writeFixtureResult(writer, result);
    }
    try writer.writeAll("]}\n");
}

fn writeProvenanceJson(writer: anytype) !void {
    try writer.writeAll("{\"suite_kind\":");
    try writeSafeJsonString(writer, suite_kind);
    try writer.writeAll(",\"policy\":");
    try writeSafeJsonString(writer, policy_id);
    try writer.writeAll(",\"policy_path\":");
    try writeSafeJsonString(writer, policy_path);
    try writer.writeAll(",\"evaluator\":");
    try writeSafeJsonString(writer, evaluator_id);
    try writer.writeAll(",\"real_action_attempted\":false,\"network_enforcement\":");
    try writeSafeJsonString(writer, network_enforcement);
    try writer.writeAll(",\"uncovered_boundaries\":[");
    for (uncovered_boundaries, 0..) |boundary, index| {
        if (index > 0) try writer.writeByte(',');
        try writeSafeJsonString(writer, boundary);
    }
    try writer.writeAll("]}");
}

fn writeTotals(writer: anytype, totals: scorecard.Totals) !void {
    try writer.print("{{\"fixtures\":{d},\"passed\":{d},\"failed\":{d},\"skipped\":{d},\"points_possible\":{d},\"points_earned\":{d},\"percent\":{d}}}", .{
        totals.fixtures,
        totals.passed,
        totals.failed,
        totals.skipped,
        totals.points_possible,
        totals.points_earned,
        totals.percent(),
    });
}

fn writeFixtureResult(writer: anytype, result: runner.FixtureResult) !void {
    try writer.writeByte('{');
    try writer.writeAll("\"id\":");
    try writeSafeJsonString(writer, result.id);
    try writer.writeAll(",\"name\":");
    try writeSafeJsonString(writer, result.name);
    try writer.writeAll(",\"category\":");
    try writeSafeJsonString(writer, result.category.slug());
    try writer.writeAll(",\"status\":");
    try writeSafeJsonString(writer, result.status.toString());
    try writer.print(",\"pass\":{},\"required\":{},\"points_possible\":{d},\"points_earned\":{d}", .{
        result.status == .passed,
        result.required,
        result.points_possible,
        result.points_earned,
    });
    try writer.writeAll(",\"missing_capabilities\":[");
    for (result.missing_capabilities, 0..) |capability, index| {
        if (index > 0) try writer.writeByte(',');
        try writeSafeJsonString(writer, capability);
    }
    try writer.writeByte(']');
    try writer.writeAll(",\"expected_checks\":[");
    for (result.checks, 0..) |check, index| {
        if (index > 0) try writer.writeByte(',');
        try writer.writeByte('{');
        try writer.writeAll("\"expected\":");
        try writeSafeJsonString(writer, check.expected);
        try writer.print(",\"passed\":{}", .{check.passed});
        try writer.writeAll(",\"observed\":");
        try writeSafeJsonString(writer, check.observed);
        try writer.writeByte('}');
    }
    try writer.writeAll("],\"actual_observed\":[");
    for (result.observations, 0..) |observed, index| {
        if (index > 0) try writer.writeByte(',');
        try writer.writeByte('{');
        try writer.writeAll("\"action\":");
        try writeSafeJsonString(writer, observed.action);
        try writer.writeAll(",\"event_type\":");
        try writeSafeJsonString(writer, observed.event_type);
        try writer.writeAll(",\"decision\":");
        try writeSafeJsonString(writer, observed.decision);
        try writer.writeAll(",\"summary\":");
        try writeSafeJsonString(writer, observed.summary);
        try writer.writeByte('}');
    }
    try writer.writeAll("],\"failure_reason\":");
    if (result.failure_reason) |reason| try writeSafeJsonString(writer, reason) else try writer.writeAll("null");
    try writer.writeByte('}');
}

fn writeSafeJsonString(writer: anytype, value: []const u8) !void {
    var buf: [512]u8 = undefined;
    try core.util.writeJsonString(writer, audit.redact_bridge.redactStringBounded(value, &buf));
}

test "redteam json output is machine readable" {
    const allocator = std.testing.allocator;
    var checks = try allocator.alloc(runner.CheckResult, 1);
    checks[0] = .{ .expected = try allocator.dupe(u8, "file.read:.env"), .passed = true, .observed = try allocator.dupe(u8, "blocked") };
    var observations = try allocator.alloc(runner.Observation, 1);
    observations[0] = .{
        .action = try allocator.dupe(u8, "file.read:.env"),
        .event_type = try allocator.dupe(u8, "file_read_denied"),
        .decision = try allocator.dupe(u8, "deny"),
        .summary = try allocator.dupe(u8, "matched rule"),
    };
    var results = try allocator.alloc(runner.FixtureResult, 1);
    results[0] = .{
        .allocator = allocator,
        .id = try allocator.dupe(u8, "secret-env-read-basic"),
        .name = try allocator.dupe(u8, "Agent attempts to read .env"),
        .category = .secret_exfil,
        .status = .passed,
        .required = true,
        .points_possible = 10,
        .points_earned = 10,
        .checks = checks,
        .observations = observations,
    };
    var suite: runner.SuiteResult = .{ .allocator = allocator, .results = results };
    defer suite.deinit();

    var out_writer: std.Io.Writer.Allocating = .init(allocator);
    defer out_writer.deinit();
    try writeJson(&out_writer.writer, suite);
    const out = try out_writer.toOwnedSlice();
    defer allocator.free(out);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, out, .{});
    defer parsed.deinit();
    try std.testing.expect(parsed.value.object.get("fixtures") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"points_earned\":10") != null);
    const provenance = parsed.value.object.get("provenance") orelse {
        try std.testing.expect(false);
        unreachable;
    };
    try std.testing.expectEqualStrings(suite_kind, provenance.object.get("suite_kind").?.string);
    try std.testing.expectEqualStrings(policy_id, provenance.object.get("policy").?.string);
    try std.testing.expectEqualStrings(policy_path, provenance.object.get("policy_path").?.string);
    try std.testing.expectEqualStrings(evaluator_id, provenance.object.get("evaluator").?.string);
    try std.testing.expect(provenance.object.get("real_action_attempted").?.bool == false);
    try std.testing.expectEqualStrings(network_enforcement, provenance.object.get("network_enforcement").?.string);
    const boundaries = provenance.object.get("uncovered_boundaries").?.array;
    try std.testing.expect(boundaries.items.len >= 4);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"real_action_attempted\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "rust_daemon_shell") != null);
    // Additive provenance must not break version for existing consumers.
    try std.testing.expectEqual(@as(i64, 1), parsed.value.object.get("version").?.integer);
}

test "redteam human output renders fixture and category scorecard tables" {
    const allocator = std.testing.allocator;
    var results = try allocator.alloc(runner.FixtureResult, 1);
    results[0] = .{
        .allocator = allocator,
        .id = try allocator.dupe(u8, "hostile\x1b[2Jfixture"),
        .name = try allocator.dupe(u8, "Blocks a dangerous read"),
        .category = .secret_exfil,
        .status = .failed,
        .required = true,
        .points_possible = 10,
        .points_earned = 0,
        .checks = &.{},
        .observations = &.{},
        .failure_reason = try allocator.dupe(u8, "unexpected\nterminal line"),
    };
    var suite: runner.SuiteResult = .{ .allocator = allocator, .results = results };
    defer suite.deinit();

    var output: [4096]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&output);
    try writeHuman(std.testing.io, &writer, suite);
    const rendered = writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, rendered, "ryk Redteam — engine self-test") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "Provenance") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "engine-self-test") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "builtin:redteam") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "zig-in-process") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "real_action_attempted:   false") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "Result") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "✗ FAIL") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "Category summary") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "0/1 passed") != null);
    try std.testing.expect(std.mem.indexOfScalar(u8, rendered, 0x1b) == null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "unexpected terminal line") != null);
}

test "redteam human and json output redact every attacker controlled field" {
    const allocator = std.testing.allocator;
    const synthetic_secret = "ghp_syntheticRedteamSecret123456";
    var checks = try allocator.alloc(runner.CheckResult, 1);
    checks[0] = .{ .expected = try std.fmt.allocPrint(allocator, "password={s}", .{synthetic_secret}), .passed = false, .observed = try allocator.dupe(u8, synthetic_secret) };
    var observations = try allocator.alloc(runner.Observation, 1);
    observations[0] = .{
        .action = try allocator.dupe(u8, synthetic_secret),
        .event_type = try allocator.dupe(u8, synthetic_secret),
        .decision = try allocator.dupe(u8, synthetic_secret),
        .summary = try allocator.dupe(u8, synthetic_secret),
    };
    var missing = try allocator.alloc([]const u8, 1);
    missing[0] = try allocator.dupe(u8, synthetic_secret);
    var results = try allocator.alloc(runner.FixtureResult, 1);
    results[0] = .{
        .allocator = allocator,
        .id = try allocator.dupe(u8, synthetic_secret),
        .name = try allocator.dupe(u8, synthetic_secret),
        .category = .secret_exfil,
        .status = .failed,
        .required = true,
        .points_possible = 10,
        .points_earned = 0,
        .checks = checks,
        .observations = observations,
        .missing_capabilities = missing,
        .failure_reason = try allocator.dupe(u8, synthetic_secret),
    };
    var suite: runner.SuiteResult = .{ .allocator = allocator, .results = results };
    defer suite.deinit();

    var human_writer: std.Io.Writer.Allocating = .init(allocator);
    defer human_writer.deinit();
    try writeHuman(std.testing.io, &human_writer.writer, suite);
    const human = try human_writer.toOwnedSlice();
    defer allocator.free(human);

    var json_writer: std.Io.Writer.Allocating = .init(allocator);
    defer json_writer.deinit();
    try writeJson(&json_writer.writer, suite);
    const json = try json_writer.toOwnedSlice();
    defer allocator.free(json);

    try std.testing.expect(std.mem.indexOf(u8, human, synthetic_secret) == null);
    try std.testing.expect(std.mem.indexOf(u8, json, synthetic_secret) == null);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();
}

test "redteam json remains structured when attacker fields exceed redaction scan bound" {
    const allocator = std.testing.allocator;
    const huge_name = try allocator.alloc(u8, 70 * 1024);
    @memset(huge_name, 'x');
    var results = try allocator.alloc(runner.FixtureResult, 1);
    results[0] = .{
        .allocator = allocator,
        .id = try allocator.dupe(u8, "large-custom-fixture"),
        .name = huge_name,
        .category = .secret_exfil,
        .status = .passed,
        .required = true,
        .points_possible = 1,
        .points_earned = 1,
        .checks = &.{},
        .observations = &.{},
    };
    var suite: runner.SuiteResult = .{ .allocator = allocator, .results = results };
    defer suite.deinit();

    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();
    try writeJson(&out.writer, suite);
    const rendered = try out.toOwnedSlice();
    defer allocator.free(rendered);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, rendered, .{});
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 1), parsed.value.object.get("fixtures").?.array.items.len);
    try std.testing.expectEqualStrings("[REDACTED]", parsed.value.object.get("fixtures").?.array.items[0].object.get("name").?.string);
}

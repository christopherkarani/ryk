const std = @import("std");

const core = @import("../core/public.zig");
const redact_bridge = @import("redact_bridge.zig");

pub const hex_hash_len = 64;
pub const HashHex = [hex_hash_len]u8;

pub fn eventHash(previous_hash: ?[]const u8, canonical_event_without_hash: []const u8) HashHex {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    if (previous_hash) |hash| hasher.update(hash);
    hasher.update(canonical_event_without_hash);

    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return std.fmt.bytesToHex(digest, .lower);
}

/// Compatibility wrapper for callers that rely on the allocation-free public
/// serializer. Encoded-secret parity is provided by the bounded redactor.
pub fn writeCanonicalEventWithoutHash(writer: anytype, ev: core.event.Event, previous_hash: ?[]const u8) !void {
    try writeEventFieldsBounded(writer, ev, previous_hash, null);
}

pub fn writeCanonicalEventWithoutHashAlloc(allocator: std.mem.Allocator, writer: anytype, ev: core.event.Event, previous_hash: ?[]const u8) !void {
    try writeEventFields(allocator, writer, ev, previous_hash, null);
}

/// Compatibility wrapper retaining the established no-allocator API.
pub fn writeEventJsonLine(writer: anytype, ev: core.event.Event, previous_hash: ?[]const u8, event_hash_value: []const u8) !void {
    try writeEventFieldsBounded(writer, ev, previous_hash, event_hash_value);
    try writer.writeByte('\n');
}

pub fn writeEventJsonLineAlloc(allocator: std.mem.Allocator, writer: anytype, ev: core.event.Event, previous_hash: ?[]const u8, event_hash_value: []const u8) !void {
    try writeEventFields(allocator, writer, ev, previous_hash, event_hash_value);
    try writer.writeByte('\n');
}

fn writeEventFieldsBounded(writer: anytype, ev: core.event.Event, previous_hash: ?[]const u8, event_hash_value: ?[]const u8) !void {
    var timestamp_buf: [32]u8 = undefined;
    const timestamp = try ev.timestamp.formatIso(&timestamp_buf);

    try writer.writeByte('{');
    try writer.print("\"version\":{d}", .{ev.schema_version});
    try writer.writeAll(",\"session_id\":");
    try core.util.writeJsonString(writer, ev.session_id.slice());
    try writer.writeAll(",\"event_id\":");
    try core.util.writeJsonString(writer, ev.event_id.slice());
    try writer.writeAll(",\"timestamp\":");
    try core.util.writeJsonString(writer, timestamp);
    try writer.writeAll(",\"type\":");
    try core.util.writeJsonString(writer, ev.event_type.toString());
    try writer.writeAll(",\"actor\":");
    try writeActorBounded(writer, ev.actor);
    try writer.writeAll(",\"target\":");
    try writeTargetBounded(writer, ev.target);
    try writer.writeAll(",\"decision\":");
    try writeDecisionBounded(writer, ev.decision);
    try writer.writeAll(",\"redactions\":");
    try writeRedactionsBounded(writer, ev.redactions);
    if (!ev.metadata.isEmpty()) {
        try writer.writeAll(",\"metadata\":");
        try writeMetadataBounded(writer, ev.metadata);
    }
    try writer.writeAll(",\"previous_hash\":");
    try writeNullableRawString(writer, previous_hash);
    if (event_hash_value) |hash| {
        try writer.writeAll(",\"event_hash\":");
        try core.util.writeJsonString(writer, hash);
    }
    try writer.writeByte('}');
}

fn writeActorBounded(writer: anytype, actor: core.types.Actor) !void {
    try writer.writeByte('{');
    try writer.writeAll("\"kind\":");
    try core.util.writeJsonString(writer, @tagName(actor.kind));
    try writer.writeAll(",\"id\":");
    try writeNullableStringBounded(writer, actor.id);
    try writer.writeAll(",\"display\":");
    try writeNullableStringBounded(writer, actor.display);
    try writer.writeByte('}');
}

fn writeTargetBounded(writer: anytype, target: core.types.Target) !void {
    try writer.writeByte('{');
    try writer.writeAll("\"kind\":");
    try core.util.writeJsonString(writer, @tagName(target.kind));
    try writer.writeAll(",\"value\":");
    var buffer: [512]u8 = undefined;
    try core.util.writeJsonString(writer, redact_bridge.redactTargetValueBounded(@tagName(target.kind), target.value, &buffer));
    try writer.writeByte('}');
}

fn writeDecisionBounded(writer: anytype, maybe_decision: ?core.decision.Decision) !void {
    const decision = maybe_decision orelse return writer.writeAll("null");
    try writer.writeByte('{');
    try writer.writeAll("\"result\":");
    try core.util.writeJsonString(writer, decision.result.toString());
    try writer.writeAll(",\"rule_id\":");
    try writeNullableStringBounded(writer, decision.rule_id);
    try writer.writeAll(",\"reason\":");
    var reason_buf: [512]u8 = undefined;
    try core.util.writeJsonString(writer, redact_bridge.redactStringBounded(decision.reason, &reason_buf));
    try writer.writeAll(",\"risk_score\":");
    if (decision.risk_score) |score| try writer.print("{d}", .{score}) else try writer.writeAll("null");
    try writer.print(",\"requires_user\":{},\"ci_may_proceed\":{}", .{ decision.requires_user, decision.ci_may_proceed });
    try writer.writeByte('}');
}

fn writeRedactionsBounded(writer: anytype, redactions: core.event.RedactionSummary) !void {
    try writer.print("{{\"count\":{d},\"labels\":[", .{redactions.count});
    for (redactions.labels, 0..) |label, index| {
        if (index > 0) try writer.writeByte(',');
        var buffer: [512]u8 = undefined;
        try core.util.writeJsonString(writer, redact_bridge.redactStringBounded(label, &buffer));
    }
    try writer.writeAll("]}");
}

fn writeMetadataBounded(writer: anytype, metadata: core.event.EventMetadata) !void {
    try writer.writeByte('{');
    var wrote = false;
    inline for (.{
        .{ "decision_source", metadata.decision_source }, .{ "event_source", metadata.event_source },
        .{ "host", metadata.host },                       .{ "daemon_status", metadata.daemon_status },
        .{ "pack_id", metadata.pack_id },                 .{ "severity", metadata.severity },
        .{ "remediation", metadata.remediation },
    }) |field| if (field[1]) |value| {
        if (wrote) try writer.writeByte(',');
        try core.util.writeJsonString(writer, field[0]);
        try writer.writeByte(':');
        var buffer: [512]u8 = undefined;
        try core.util.writeJsonString(writer, redact_bridge.redactStringBounded(value, &buffer));
        wrote = true;
    };
    try writer.writeByte('}');
}

fn writeNullableStringBounded(writer: anytype, value: ?[]const u8) !void {
    if (value) |string| {
        var buffer: [512]u8 = undefined;
        try core.util.writeJsonString(writer, redact_bridge.redactStringBounded(string, &buffer));
    } else try writer.writeAll("null");
}

fn writeEventFields(allocator: std.mem.Allocator, writer: anytype, ev: core.event.Event, previous_hash: ?[]const u8, event_hash_value: ?[]const u8) !void {
    var timestamp_buf: [32]u8 = undefined;
    const timestamp = try ev.timestamp.formatIso(&timestamp_buf);

    try writer.writeByte('{');
    try writer.print("\"version\":{d}", .{ev.schema_version});
    try writer.writeAll(",\"session_id\":");
    try core.util.writeJsonString(writer, ev.session_id.slice());
    try writer.writeAll(",\"event_id\":");
    try core.util.writeJsonString(writer, ev.event_id.slice());
    try writer.writeAll(",\"timestamp\":");
    try core.util.writeJsonString(writer, timestamp);
    try writer.writeAll(",\"type\":");
    try core.util.writeJsonString(writer, ev.event_type.toString());
    try writer.writeAll(",\"actor\":");
    try writeActor(allocator, writer, ev.actor);
    try writer.writeAll(",\"target\":");
    try writeTarget(allocator, writer, ev.target);
    try writer.writeAll(",\"decision\":");
    try writeDecision(allocator, writer, ev.decision);
    try writer.writeAll(",\"redactions\":");
    try writeRedactions(allocator, writer, ev.redactions);
    if (!ev.metadata.isEmpty()) {
        try writer.writeAll(",\"metadata\":");
        try writeMetadata(allocator, writer, ev.metadata);
    }
    try writer.writeAll(",\"previous_hash\":");
    try writeNullableRawString(writer, previous_hash);
    if (event_hash_value) |hash| {
        try writer.writeAll(",\"event_hash\":");
        try core.util.writeJsonString(writer, hash);
    }
    try writer.writeByte('}');
}

fn writeActor(allocator: std.mem.Allocator, writer: anytype, actor: core.types.Actor) !void {
    try writer.writeByte('{');
    try writer.writeAll("\"kind\":");
    try core.util.writeJsonString(writer, @tagName(actor.kind));
    try writer.writeAll(",\"id\":");
    try writeNullableString(allocator, writer, actor.id);
    try writer.writeAll(",\"display\":");
    try writeNullableString(allocator, writer, actor.display);
    try writer.writeByte('}');
}

fn writeTarget(allocator: std.mem.Allocator, writer: anytype, target: core.types.Target) !void {
    try writer.writeByte('{');
    try writer.writeAll("\"kind\":");
    try core.util.writeJsonString(writer, @tagName(target.kind));
    try writer.writeAll(",\"value\":");
    const redacted = redact_bridge.redactTargetValueAlloc(allocator, @tagName(target.kind), target.value) catch redacted_bridge_fallback;
    defer if (redacted.ptr != redacted_bridge_fallback.ptr) allocator.free(redacted);
    try core.util.writeJsonString(writer, redacted);
    try writer.writeByte('}');
}

fn writeDecision(allocator: std.mem.Allocator, writer: anytype, maybe_decision: ?core.decision.Decision) !void {
    const decision = maybe_decision orelse {
        try writer.writeAll("null");
        return;
    };
    try writer.writeByte('{');
    try writer.writeAll("\"result\":");
    try core.util.writeJsonString(writer, decision.result.toString());
    try writer.writeAll(",\"rule_id\":");
    try writeNullableString(allocator, writer, decision.rule_id);
    try writer.writeAll(",\"reason\":");
    try writeRedactedString(allocator, writer, decision.reason);
    try writer.writeAll(",\"risk_score\":");
    if (decision.risk_score) |score| {
        try writer.print("{d}", .{score});
    } else {
        try writer.writeAll("null");
    }
    try writer.print(",\"requires_user\":{},\"ci_may_proceed\":{}", .{ decision.requires_user, decision.ci_may_proceed });
    try writer.writeByte('}');
}

fn writeRedactions(allocator: std.mem.Allocator, writer: anytype, redactions: core.event.RedactionSummary) !void {
    try writer.print("{{\"count\":{d},\"labels\":[", .{redactions.count});
    for (redactions.labels, 0..) |label, index| {
        if (index > 0) try writer.writeByte(',');
        try writeRedactedString(allocator, writer, label);
    }
    try writer.writeAll("]}");
}

fn writeMetadata(allocator: std.mem.Allocator, writer: anytype, metadata: core.event.EventMetadata) !void {
    try writer.writeByte('{');
    var wrote_field = false;
    inline for (.{
        .{ "decision_source", metadata.decision_source },
        .{ "event_source", metadata.event_source },
        .{ "host", metadata.host },
        .{ "daemon_status", metadata.daemon_status },
        .{ "pack_id", metadata.pack_id },
        .{ "severity", metadata.severity },
        .{ "remediation", metadata.remediation },
    }) |field| {
        if (field[1]) |value| {
            if (wrote_field) try writer.writeByte(',');
            try writer.writeAll("\"");
            try writer.writeAll(field[0]);
            try writer.writeAll("\":");
            try writeRedactedString(allocator, writer, value);
            wrote_field = true;
        }
    }
    try writer.writeByte('}');
}

fn writeNullableString(allocator: std.mem.Allocator, writer: anytype, value: ?[]const u8) !void {
    if (value) |string| {
        try writeRedactedString(allocator, writer, string);
    } else {
        try writer.writeAll("null");
    }
}

const redacted_bridge_fallback = redact_bridge.redacted_value;

fn writeRedactedString(allocator: std.mem.Allocator, writer: anytype, value: []const u8) !void {
    const redacted = redact_bridge.redactAlloc(allocator, value) catch redacted_bridge_fallback;
    defer if (redacted.ptr != redacted_bridge_fallback.ptr) allocator.free(redacted);
    try core.util.writeJsonString(writer, redacted);
}

fn writeNullableRawString(writer: anytype, value: ?[]const u8) !void {
    if (value) |string| {
        try core.util.writeJsonString(writer, string);
    } else {
        try writer.writeAll("null");
    }
}

pub fn canonicalEventAlloc(allocator: std.mem.Allocator, ev: core.event.Event, previous_hash: ?[]const u8) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();
    try writeCanonicalEventWithoutHashAlloc(allocator, &out.writer, ev, previous_hash);
    return try out.toOwnedSlice();
}

/// Build the persisted row from the exact canonical bytes that were hashed.
/// This prevents a second redaction/serialization pass from producing bytes
/// that differ from the hash input.
pub fn eventJsonLineFromCanonicalAlloc(allocator: std.mem.Allocator, canonical: []const u8, event_hash_value: []const u8) ![]u8 {
    if (canonical.len == 0 or canonical[canonical.len - 1] != '}') return error.InvalidCanonicalEvent;
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    try out.writer.writeAll(canonical[0 .. canonical.len - 1]);
    try out.writer.writeAll(",\"event_hash\":");
    try core.util.writeJsonString(&out.writer, event_hash_value);
    try out.writer.writeAll("}\n");
    return try out.toOwnedSlice();
}

test "event serialization is deterministic and excludes event_hash from hash input" {
    const ts = core.time.Timestamp.fromUnixSeconds(1_777_983_130);
    const sid = try core.session.generateSessionId(ts);
    var eid: core.event.EventId = .{ .value = undefined, .len = 0 };
    const eid_text = try std.fmt.bufPrint(&eid.value, "evt_000001", .{});
    eid.len = eid_text.len;
    const ev: core.event.Event = .{
        .session_id = sid,
        .event_id = eid,
        .timestamp = ts,
        .event_type = .process_launch,
        .actor = .{ .kind = .ryk, .display = "ryk" },
        .target = .{ .kind = .command, .value = "echo hello" },
    };

    const first = try canonicalEventAlloc(std.testing.allocator, ev, null);
    defer std.testing.allocator.free(first);
    const second = try canonicalEventAlloc(std.testing.allocator, ev, null);
    defer std.testing.allocator.free(second);

    try std.testing.expectEqualStrings(first, second);
    try std.testing.expect(std.mem.indexOf(u8, first, "event_hash") == null);
    const hash = eventHash(null, first);
    try std.testing.expectEqual(@as(usize, hex_hash_len), hash.len);
}

test "persisted event line contains the exact canonical hash input" {
    const ts = core.time.Timestamp.fromUnixSeconds(1_777_983_130);
    const sid = try core.session.generateSessionId(ts);
    var eid: core.event.EventId = .{ .value = undefined, .len = 0 };
    eid.len = (try std.fmt.bufPrint(&eid.value, "evt_exact_bytes", .{})).len;
    const ev: core.event.Event = .{
        .session_id = sid,
        .event_id = eid,
        .timestamp = ts,
        .event_type = .process_launch,
        .actor = .{ .kind = .ryk, .display = "password=correct-horse-battery-staple" },
        .target = .{ .kind = .command, .value = "token%253Dcorrect-horse-battery-staple" },
    };
    const canonical = try canonicalEventAlloc(std.testing.allocator, ev, null);
    defer std.testing.allocator.free(canonical);
    const hash = eventHash(null, canonical);
    const line = try eventJsonLineFromCanonicalAlloc(std.testing.allocator, canonical, &hash);
    defer std.testing.allocator.free(line);
    try std.testing.expectEqualStrings(canonical[0 .. canonical.len - 1], line[0 .. canonical.len - 1]);
    try std.testing.expect(std.mem.indexOf(u8, line, "correct-horse") == null);
    try std.testing.expect(std.mem.endsWith(u8, line, "\"}\n"));
}

test "redaction labels are redacted at the audit serialization boundary" {
    const ts = core.time.Timestamp.fromUnixSeconds(1_777_983_130);
    const sid = try core.session.generateSessionId(ts);
    var eid: core.event.EventId = .{ .value = undefined, .len = 0 };
    const eid_text = try std.fmt.bufPrint(&eid.value, "evt_000001", .{});
    eid.len = eid_text.len;
    const labels = [_][]const u8{"fake_secret_value"};
    const ev: core.event.Event = .{
        .session_id = sid,
        .event_id = eid,
        .timestamp = ts,
        .event_type = .secret_redacted,
        .actor = .{ .kind = .ryk, .display = "ryk" },
        .target = .{ .kind = .command, .value = "echo ok" },
        .redactions = .{ .count = 1, .labels = &labels },
    };

    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try writeEventJsonLineAlloc(std.testing.allocator, &out.writer, ev, null, "abc");
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "fake_secret_value") == null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), redact_bridge.redacted_value) != null);
}

test "sandbox_posture serializes posture hash and fs_scope without full profile" {
    const ts = core.time.Timestamp.fromUnixSeconds(1_777_983_130);
    const sid = try core.session.generateSessionId(ts);
    var eid: core.event.EventId = .{ .value = undefined, .len = 0 };
    const eid_text = try std.fmt.bufPrint(&eid.value, "evt_sandbox_posture", .{});
    eid.len = eid_text.len;
    const reason = "posture=active; profile_hash=abcd1234; fs_scope=workspace RW, system RO, no home";
    const ev: core.event.Event = .{
        .session_id = sid,
        .event_id = eid,
        .timestamp = ts,
        .event_type = .sandbox_posture,
        .actor = .{ .kind = .ryk, .display = "ryk" },
        .target = .{ .kind = .session, .value = "os_filesystem_sandbox" },
        .decision = .{
            .result = .observe,
            .reason = reason,
            .ci_may_proceed = true,
        },
    };

    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try writeEventJsonLineAlloc(std.testing.allocator, &out.writer, ev, null, "deadbeef");
    const line = out.written();
    try std.testing.expect(std.mem.indexOf(u8, line, "\"type\":\"sandbox_posture\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "posture=active") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "profile_hash=abcd1234") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "fs_scope=workspace RW") != null);
    // Full profile / SBPL / landlock rule blobs must not appear.
    try std.testing.expect(std.mem.indexOf(u8, line, "(version 1)") == null);
    try std.testing.expect(std.mem.indexOf(u8, line, "allow default") == null);
    try std.testing.expect(std.mem.indexOf(u8, line, "LANDLOCK") == null);
}

// os_fs_deny remains a reserved EventType (see core/event.zig toString test).
// Dedicated hash_chain serialization coverage deferred until emission exists.

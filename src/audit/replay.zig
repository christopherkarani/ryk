const std = @import("std");

const core = @import("../core/public.zig");
const hash_chain = @import("hash_chain.zig");
const redact_bridge = @import("redact_bridge.zig");
const audit_summary = @import("summary.zig");

pub const ParseIntegrityFailed = error{ParseIntegrityFailed};

pub const ReplayOptions = struct {
    session: []const u8 = "last",
    only_denied: bool = false,
    verify: bool = false,
    audit_dir_name: []const u8 = ".ryk",
};

pub const ReplayEvent = struct {
    raw: []u8,
    timestamp: []u8,
    event_type: []u8,
    target_value: []u8,
    decision_result: ?[]u8,

    pub fn deinit(self: ReplayEvent, allocator: std.mem.Allocator) void {
        allocator.free(self.raw);
        allocator.free(self.timestamp);
        allocator.free(self.event_type);
        allocator.free(self.target_value);
        if (self.decision_result) |value| allocator.free(value);
    }

    /// True when the event is a denial for filtering / human emphasis.
    /// Matches `only_denied` load-path semantics: type ends with `_denied`, or
    /// decision result is `deny` (covers non-`*_denied` types that still deny).
    pub fn isDenied(self: ReplayEvent) bool {
        return isDeniedFields(self.event_type, self.decision_result);
    }
};

/// Shared deny classifier for event type + optional decision result strings.
/// Used by JSON load filtering and by CLI human/TUI replay rendering.
pub fn isDeniedFields(event_type: []const u8, decision_result: ?[]const u8) bool {
    if (std.mem.endsWith(u8, event_type, "_denied")) return true;
    if (decision_result) |result| return std.mem.eql(u8, result, "deny");
    return false;
}

pub const ReplaySession = struct {
    allocator: std.mem.Allocator,
    session_id: []u8,
    session_dir_path: []u8,
    command_display: []u8,
    policy: []u8,
    status_display: []u8,
    events: []ReplayEvent,
    verified: bool = false,

    pub fn deinit(self: *ReplaySession) void {
        for (self.events) |ev| ev.deinit(self.allocator);
        self.allocator.free(self.events);
        self.allocator.free(self.session_id);
        self.allocator.free(self.session_dir_path);
        self.allocator.free(self.command_display);
        self.allocator.free(self.policy);
        self.allocator.free(self.status_display);
        self.* = undefined;
    }
};

/// Host conversation ids are 36-char UUIDs (`8-4-4-4-12` hex). Ryk session ids
/// are `timestamp_hex` (e.g. `2026-05-05T12-12-10Z_abcd`). Different namespace.
pub fn looksLikeHostConversationId(value: []const u8) bool {
    if (value.len != 36) return false;
    for (value, 0..) |char, index| {
        switch (index) {
            8, 13, 18, 23 => if (char != '-') return false,
            else => if (!std.ascii.isHex(char)) return false,
        }
    }
    return true;
}

pub fn load(io: std.Io, allocator: std.mem.Allocator, workspace_root: []const u8, options: ReplayOptions) !ReplaySession {
    const session_id = try resolveSessionId(io, allocator, workspace_root, options.session, options.audit_dir_name);
    errdefer allocator.free(session_id);
    const session_dir_path = try std.fs.path.join(allocator, &.{ workspace_root, options.audit_dir_name, "sessions", session_id });
    errdefer allocator.free(session_dir_path);

    if (looksLikeHostConversationId(session_id)) {
        std.Io.Dir.cwd().access(io, session_dir_path, .{}) catch |err| switch (err) {
            error.FileNotFound => return error.HostConversationIdNotARykSession,
            else => return err,
        };
    }

    const verify_result = try verifySessionDir(io, allocator, session_dir_path);
    defer verify_result.deinit(allocator);
    if (options.verify and !verify_result.ok) return error.HashVerificationFailed;

    const events = try loadEvents(io, allocator, session_dir_path, options.only_denied);
    errdefer {
        for (events) |ev| ev.deinit(allocator);
        allocator.free(events);
    }
    // In-progress sessions have events.jsonl + `.ryk/last` before summary.json exists.
    const summary = readSummaryFields(io, allocator, session_dir_path) catch |err| switch (err) {
        error.FileNotFound => SummaryFields{
            .command_display = try allocator.dupe(u8, "-"),
            .policy = try allocator.dupe(u8, "-"),
            .status_display = try allocator.dupe(u8, "-"),
        },
        else => return err,
    };
    errdefer summary.deinit(allocator);

    return .{
        .allocator = allocator,
        .session_id = session_id,
        .session_dir_path = session_dir_path,
        .command_display = summary.command_display,
        .policy = summary.policy,
        .status_display = summary.status_display,
        .events = events,
        .verified = verify_result.ok,
    };
}

pub fn writeHuman(writer: anytype, session: ReplaySession, show_verify: bool) !void {
    try writer.print(
        \\Session: {s}
        \\Command: {s}
        \\Policy: {s}
        \\Status: {s}
        \\
    , .{
        session.session_id,
        session.command_display,
        session.policy,
        session.status_display,
    });

    for (session.events) |ev| {
        try writer.print("{s}  {s}", .{ eventTime(ev.timestamp), ev.event_type });
        if (ev.target_value.len > 0) try writer.print("     {s}", .{ev.target_value});
        try writer.writeByte('\n');
    }
    if (show_verify) {
        try writer.print("\nHash chain: {s}\n", .{if (session.verified) "verified" else "not verified"});
    }
}

pub fn writeJson(writer: anytype, session: ReplaySession) !void {
    try writer.writeByte('[');
    for (session.events, 0..) |ev, index| {
        if (index > 0) try writer.writeByte(',');
        try writer.writeAll(ev.raw);
    }
    try writer.writeAll("]\n");
}

pub const VerifyResult = struct {
    ok: bool,
    reason: ?[]u8 = null,

    pub fn deinit(self: VerifyResult, allocator: std.mem.Allocator) void {
        if (self.reason) |reason| allocator.free(reason);
    }
};

pub fn verifySessionDir(io: std.Io, allocator: std.mem.Allocator, session_dir_path: []const u8) !VerifyResult {
    const events_path = try std.fs.path.join(allocator, &.{ session_dir_path, "events.jsonl" });
    defer allocator.free(events_path);
    const events_text = try std.Io.Dir.cwd().readFileAlloc(io, events_path, allocator, std.Io.Limit.limited(core.limits.max_audit_log_len));
    defer allocator.free(events_text);

    var previous_hash: ?hash_chain.HashHex = null;
    var last_hash: ?hash_chain.HashHex = null;
    var event_count: usize = 0;
    var lines = std.mem.splitScalar(u8, events_text, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var parsed = std.json.parseFromSlice(std.json.Value, allocator, line, .{}) catch {
            return fail(allocator, "invalid event JSON");
        };
        defer parsed.deinit();
        const object = expectObject(parsed.value) catch return fail(allocator, "malformed event");

        const previous_value = object.get("previous_hash") orelse return fail(allocator, "missing previous_hash");
        var expected_previous: ?[]const u8 = null;
        if (previous_hash) |*hash| expected_previous = hash[0..];
        if (!jsonNullableStringEquals(previous_value, expected_previous)) {
            return fail(allocator, "invalid previous_hash");
        }

        const canonical = canonicalFromJsonValue(allocator, parsed.value) catch |err| switch (err) {
            error.InvalidEventSchema => return fail(allocator, "malformed event"),
            else => return err,
        };
        defer allocator.free(canonical);
        const computed = hash_chain.eventHash(expected_previous, canonical);
        const event_hash_value = object.get("event_hash") orelse return fail(allocator, "missing event_hash");
        if (event_hash_value != .string or !std.mem.eql(u8, event_hash_value.string, &computed)) {
            return fail(allocator, "invalid event_hash");
        }

        previous_hash = computed;
        last_hash = computed;
        event_count += 1;
    }

    const summary_integrity = readSummaryIntegrity(io, allocator, session_dir_path) catch |err| switch (err) {
        error.FileNotFound => return fail(allocator, "missing summary.json"),
        error.InvalidEventSchema => return fail(allocator, "malformed summary.json"),
        else => return err,
    };
    defer summary_integrity.deinit(allocator);
    if (summary_integrity.event_count != event_count) return fail(allocator, "summary event count mismatch");
    if (last_hash) |hash| {
        if (!std.mem.eql(u8, summary_integrity.final_event_hash, &hash)) return fail(allocator, "summary final hash mismatch");
    } else if (summary_integrity.final_event_hash.len != 0) {
        return fail(allocator, "summary final hash mismatch");
    }

    return .{ .ok = true };
}

fn fail(allocator: std.mem.Allocator, reason: []const u8) !VerifyResult {
    return .{ .ok = false, .reason = try allocator.dupe(u8, reason) };
}

pub fn canonicalFromJsonValue(allocator: std.mem.Allocator, value: std.json.Value) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    const writer = &out.writer;
    const object = try expectObject(value);
    try rejectUnknownKeys(object, &.{
        "version",
        "session_id",
        "event_id",
        "timestamp",
        "type",
        "actor",
        "target",
        "decision",
        "redactions",
        "metadata",
        "previous_hash",
        "event_hash",
    });
    if (object.get("event_hash")) |event_hash| _ = try expectString(event_hash);

    try writer.writeByte('{');
    try writer.print("\"version\":{d}", .{try expectInteger(try requiredField(object, "version"))});
    try writeStringField(writer, "session_id", try requiredField(object, "session_id"));
    try writeStringField(writer, "event_id", try requiredField(object, "event_id"));
    try writeStringField(writer, "timestamp", try requiredField(object, "timestamp"));
    try writeStringField(writer, "type", try requiredField(object, "type"));
    try writer.writeAll(",\"actor\":");
    try writeActorValue(writer, try requiredField(object, "actor"));
    try writer.writeAll(",\"target\":");
    try writeTargetValue(writer, try requiredField(object, "target"));
    try writer.writeAll(",\"decision\":");
    try writeDecisionValue(writer, try requiredField(object, "decision"));
    try writer.writeAll(",\"redactions\":");
    try writeRedactionsValue(writer, try requiredField(object, "redactions"));
    if (object.get("metadata")) |metadata| {
        if (metadata != .null) {
            try writer.writeAll(",\"metadata\":");
            try writeMetadataValue(writer, metadata);
        }
    }
    try writer.writeAll(",\"previous_hash\":");
    try writeNullableValue(writer, try requiredField(object, "previous_hash"));
    try writer.writeByte('}');
    return try out.toOwnedSlice();
}

fn writeStringField(writer: anytype, name: []const u8, value: std.json.Value) !void {
    try writer.writeByte(',');
    try core.util.writeJsonString(writer, name);
    try writer.writeByte(':');
    try core.util.writeJsonString(writer, try expectString(value));
}

fn writeActorValue(writer: anytype, value: std.json.Value) !void {
    const object = try expectObject(value);
    try rejectUnknownKeys(object, &.{ "kind", "id", "display" });
    try writer.writeByte('{');
    try writer.writeAll("\"kind\":");
    try core.util.writeJsonString(writer, try expectString(try requiredField(object, "kind")));
    try writer.writeAll(",\"id\":");
    try writeNullableValue(writer, try requiredField(object, "id"));
    try writer.writeAll(",\"display\":");
    try writeNullableValue(writer, try requiredField(object, "display"));
    try writer.writeByte('}');
}

fn writeTargetValue(writer: anytype, value: std.json.Value) !void {
    const object = try expectObject(value);
    try rejectUnknownKeys(object, &.{ "kind", "value" });
    try writer.writeByte('{');
    try writer.writeAll("\"kind\":");
    try core.util.writeJsonString(writer, try expectString(try requiredField(object, "kind")));
    try writer.writeAll(",\"value\":");
    try core.util.writeJsonString(writer, try expectString(try requiredField(object, "value")));
    try writer.writeByte('}');
}

fn writeDecisionValue(writer: anytype, value: std.json.Value) !void {
    if (value == .null) {
        try writer.writeAll("null");
        return;
    }
    const object = try expectObject(value);
    try rejectUnknownKeys(object, &.{ "result", "rule_id", "reason", "risk_score", "requires_user", "ci_may_proceed" });
    try writer.writeByte('{');
    try writer.writeAll("\"result\":");
    try core.util.writeJsonString(writer, try expectString(try requiredField(object, "result")));
    try writer.writeAll(",\"rule_id\":");
    try writeNullableValue(writer, try requiredField(object, "rule_id"));
    try writer.writeAll(",\"reason\":");
    try core.util.writeJsonString(writer, try expectString(try requiredField(object, "reason")));
    try writer.writeAll(",\"risk_score\":");
    const risk = try requiredField(object, "risk_score");
    if (risk == .null) try writer.writeAll("null") else try writer.print("{d}", .{try expectInteger(risk)});
    try writer.print(",\"requires_user\":{},\"ci_may_proceed\":{}", .{
        try expectBool(try requiredField(object, "requires_user")),
        try expectBool(try requiredField(object, "ci_may_proceed")),
    });
    try writer.writeByte('}');
}

fn writeRedactionsValue(writer: anytype, value: std.json.Value) !void {
    const object = try expectObject(value);
    try rejectUnknownKeys(object, &.{ "count", "labels" });
    try writer.print("{{\"count\":{d},\"labels\":[", .{try expectInteger(try requiredField(object, "count"))});
    const labels = try expectArray(try requiredField(object, "labels"));
    for (labels.items, 0..) |label, index| {
        if (index > 0) try writer.writeByte(',');
        try core.util.writeJsonString(writer, try expectString(label));
    }
    try writer.writeAll("]}");
}

fn writeMetadataValue(writer: anytype, value: std.json.Value) !void {
    const object = try expectObject(value);
    try rejectUnknownKeys(object, &.{
        "decision_source",
        "event_source",
        "host",
        "daemon_status",
        "pack_id",
        "severity",
        "remediation",
    });
    const field_names = [_][]const u8{
        "decision_source",
        "event_source",
        "host",
        "daemon_status",
        "pack_id",
        "severity",
        "remediation",
    };
    try writer.writeByte('{');
    var wrote_field = false;
    for (field_names) |field_name| {
        if (object.get(field_name)) |field_value| {
            if (field_value == .null) continue;
            if (wrote_field) try writer.writeByte(',');
            try writer.writeAll("\"");
            try writer.writeAll(field_name);
            try writer.writeAll("\":");
            try core.util.writeJsonString(writer, try expectString(field_value));
            wrote_field = true;
        }
    }
    try writer.writeByte('}');
}

fn writeNullableValue(writer: anytype, value: std.json.Value) !void {
    if (value == .null) {
        try writer.writeAll("null");
    } else {
        try core.util.writeJsonString(writer, try expectString(value));
    }
}

fn expectObject(value: std.json.Value) !std.json.ObjectMap {
    return switch (value) {
        .object => |object| object,
        else => error.InvalidEventSchema,
    };
}

fn expectArray(value: std.json.Value) !std.json.Array {
    return switch (value) {
        .array => |array| array,
        else => error.InvalidEventSchema,
    };
}

fn expectString(value: std.json.Value) ![]const u8 {
    return switch (value) {
        .string => |string| string,
        else => error.InvalidEventSchema,
    };
}

fn expectInteger(value: std.json.Value) !i64 {
    return switch (value) {
        .integer => |integer| integer,
        else => error.InvalidEventSchema,
    };
}

fn expectBool(value: std.json.Value) !bool {
    return switch (value) {
        .bool => |boolean| boolean,
        else => error.InvalidEventSchema,
    };
}

fn requiredField(object: std.json.ObjectMap, name: []const u8) !std.json.Value {
    return object.get(name) orelse error.InvalidEventSchema;
}

fn rejectUnknownKeys(object: std.json.ObjectMap, allowed: []const []const u8) !void {
    var iterator = object.iterator();
    while (iterator.next()) |entry| {
        var known = false;
        for (allowed) |name| {
            if (std.mem.eql(u8, entry.key_ptr.*, name)) {
                known = true;
                break;
            }
        }
        if (!known) return error.InvalidEventSchema;
    }
}

fn jsonNullableStringEquals(value: std.json.Value, expected: ?[]const u8) bool {
    if (expected) |string| return value == .string and std.mem.eql(u8, value.string, string);
    return value == .null;
}

fn resolveSessionId(io: std.Io, allocator: std.mem.Allocator, workspace_root: []const u8, requested: []const u8, audit_dir_name: []const u8) ![]u8 {
    if (!std.mem.eql(u8, requested, "last")) {
        try validateSessionId(requested);
        return try allocator.dupe(u8, requested);
    }
    const last_path = try std.fs.path.join(allocator, &.{ workspace_root, audit_dir_name, "last" });
    defer allocator.free(last_path);
    const text = try std.Io.Dir.cwd().readFileAlloc(io, last_path, allocator, std.Io.Limit.limited(core.limits.max_session_id_len + 2));
    defer allocator.free(text);
    const trimmed = std.mem.trim(u8, text, " \t\r\n");
    try validateSessionId(trimmed);
    return try allocator.dupe(u8, trimmed);
}

fn validateSessionId(value: []const u8) !void {
    try core.session.validateSessionIdText(value);
}

fn loadEvents(io: std.Io, allocator: std.mem.Allocator, session_dir_path: []const u8, only_denied: bool) ![]ReplayEvent {
    const events_path = try std.fs.path.join(allocator, &.{ session_dir_path, "events.jsonl" });
    defer allocator.free(events_path);
    const events_text = try std.Io.Dir.cwd().readFileAlloc(io, events_path, allocator, std.Io.Limit.limited(core.limits.max_audit_log_len));
    defer allocator.free(events_text);

    var list: std.ArrayList(ReplayEvent) = .empty;
    errdefer {
        for (list.items) |ev| ev.deinit(allocator);
        list.deinit(allocator);
    }

    var lines = std.mem.splitScalar(u8, events_text, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var parsed = try std.json.parseFromSlice(std.json.Value, allocator, line, .{});
        defer parsed.deinit();
        if (only_denied and !isDenied(parsed.value)) continue;
        const event = try eventFromJson(allocator, line, parsed.value);
        list.append(allocator, event) catch |err| {
            event.deinit(allocator);
            return err;
        };
    }

    return try list.toOwnedSlice(allocator);
}

fn eventFromJson(allocator: std.mem.Allocator, raw: []const u8, value: std.json.Value) !ReplayEvent {
    _ = raw;
    const object = try expectObject(value);
    const target = try expectObject(try requiredField(object, "target"));
    const decision_result = decisionResultFromValue(allocator, try requiredField(object, "decision")) catch |err| switch (err) {
        error.InvalidEventSchema => null,
        else => return err,
    };
    errdefer if (decision_result) |value_text| allocator.free(value_text);
    const canonical_raw = try presentationJsonAlloc(allocator, value);
    errdefer allocator.free(canonical_raw);
    const timestamp = redact_bridge.redactAlloc(allocator, try expectString(try requiredField(object, "timestamp"))) catch
        try allocator.dupe(u8, redact_bridge.redacted_value);
    errdefer allocator.free(timestamp);
    const event_type = redact_bridge.redactAlloc(allocator, try expectString(try requiredField(object, "type"))) catch
        try allocator.dupe(u8, redact_bridge.redacted_value);
    errdefer allocator.free(event_type);
    const target_value = redact_bridge.redactAlloc(allocator, try expectString(try requiredField(target, "value"))) catch
        try allocator.dupe(u8, redact_bridge.redacted_value);
    return .{
        .raw = canonical_raw,
        .timestamp = timestamp,
        .event_type = event_type,
        .target_value = target_value,
        .decision_result = decision_result,
    };
}

fn presentationJsonAlloc(allocator: std.mem.Allocator, value: std.json.Value) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    try writePresentationJsonValue(allocator, &out.writer, value);
    return try out.toOwnedSlice();
}

fn writePresentationJsonValue(allocator: std.mem.Allocator, writer: anytype, value: std.json.Value) !void {
    switch (value) {
        .null => try writer.writeAll("null"),
        .bool => |boolean| try writer.print("{}", .{boolean}),
        .integer => |integer| try writer.print("{d}", .{integer}),
        .float => |float| try writer.print("{d}", .{float}),
        .number_string => |number| try writer.writeAll(number),
        .string => |string| {
            const redacted = redact_bridge.redactAlloc(allocator, string) catch redact_bridge.redacted_value;
            defer if (redacted.ptr != redact_bridge.redacted_value.ptr) allocator.free(redacted);
            try core.util.writeJsonString(writer, redacted);
        },
        .array => |array| {
            try writer.writeByte('[');
            for (array.items, 0..) |item, index| {
                if (index > 0) try writer.writeByte(',');
                try writePresentationJsonValue(allocator, writer, item);
            }
            try writer.writeByte(']');
        },
        .object => |object| {
            try writer.writeByte('{');
            var iterator = object.iterator();
            var index: usize = 0;
            while (iterator.next()) |entry| : (index += 1) {
                if (index > 0) try writer.writeByte(',');
                try core.util.writeJsonString(writer, entry.key_ptr.*);
                try writer.writeByte(':');
                try writePresentationJsonValue(allocator, writer, entry.value_ptr.*);
            }
            try writer.writeByte('}');
        },
    }
}

fn isDenied(value: std.json.Value) bool {
    const object = expectObject(value) catch return false;
    const event_type = expectString(requiredField(object, "type") catch return false) catch return false;
    var decision_result: ?[]const u8 = null;
    if (object.get("decision")) |decision| {
        if (decision != .null) {
            if (expectObject(decision)) |decision_object| {
                if (decision_object.get("result")) |result| {
                    if (result == .string) decision_result = result.string;
                }
            } else |_| {}
        }
    }
    return isDeniedFields(event_type, decision_result);
}

fn decisionResultFromValue(allocator: std.mem.Allocator, value: std.json.Value) !?[]u8 {
    if (value == .null) return null;
    const object = try expectObject(value);
    const result = object.get("result") orelse return null;
    if (result != .string) return null;
    return redact_bridge.redactAlloc(allocator, result.string) catch
        try allocator.dupe(u8, redact_bridge.redacted_value);
}

const SummaryFields = struct {
    command_display: []u8,
    policy: []u8,
    status_display: []u8,

    fn deinit(self: SummaryFields, allocator: std.mem.Allocator) void {
        allocator.free(self.command_display);
        allocator.free(self.policy);
        allocator.free(self.status_display);
    }
};

fn readSummaryFields(io: std.Io, allocator: std.mem.Allocator, session_dir_path: []const u8) !SummaryFields {
    const summary_path = try std.fs.path.join(allocator, &.{ session_dir_path, "summary.json" });
    defer allocator.free(summary_path);
    const text = try std.Io.Dir.cwd().readFileAlloc(io, summary_path, allocator, std.Io.Limit.limited(core.limits.max_event_field_len));
    defer allocator.free(text);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, text, .{});
    defer parsed.deinit();
    const object = try expectObject(parsed.value);
    const canonical = try audit_summary.canonicalFromJsonValue(allocator, parsed.value);
    defer allocator.free(canonical);

    const command_display = try commandDisplayFromSummary(allocator, try expectArray(try requiredField(object, "command")));
    errdefer allocator.free(command_display);
    const policy = redact_bridge.redactAlloc(allocator, try expectString(try requiredField(object, "policy"))) catch
        try allocator.dupe(u8, redact_bridge.redacted_value);
    errdefer allocator.free(policy);
    const status_display = try statusDisplayFromSummary(allocator, try requiredField(object, "status"));
    errdefer allocator.free(status_display);
    return .{ .command_display = command_display, .policy = policy, .status_display = status_display };
}

const SummaryIntegrity = struct {
    event_count: usize,
    final_event_hash: []u8,

    fn deinit(self: SummaryIntegrity, allocator: std.mem.Allocator) void {
        allocator.free(self.final_event_hash);
    }
};

fn readSummaryIntegrity(io: std.Io, allocator: std.mem.Allocator, session_dir_path: []const u8) !SummaryIntegrity {
    const summary_path = try std.fs.path.join(allocator, &.{ session_dir_path, "summary.json" });
    defer allocator.free(summary_path);
    const text = try std.Io.Dir.cwd().readFileAlloc(io, summary_path, allocator, std.Io.Limit.limited(core.limits.max_event_field_len));
    defer allocator.free(text);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, text, .{});
    defer parsed.deinit();
    const object = try expectObject(parsed.value);
    const canonical = try audit_summary.canonicalFromJsonValue(allocator, parsed.value);
    defer allocator.free(canonical);
    const computed_summary_hash = audit_summary.summaryHash(canonical);
    const summary_hash_value = try expectString(try requiredField(object, "summary_hash"));
    if (!std.mem.eql(u8, summary_hash_value, &computed_summary_hash)) return error.InvalidEventSchema;
    const count = try expectInteger(try requiredField(object, "event_count"));
    if (count < 0) return error.InvalidEventSchema;
    return .{
        .event_count = @intCast(count),
        .final_event_hash = try allocator.dupe(u8, try expectString(try requiredField(object, "final_event_hash"))),
    };
}

fn commandDisplayFromSummary(allocator: std.mem.Allocator, command_array: std.json.Array) ![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    for (command_array.items, 0..) |item, index| {
        if (index > 0) try list.append(allocator, ' ');
        const redacted = redact_bridge.redactAlloc(allocator, try expectString(item)) catch redact_bridge.redacted_value;
        defer if (redacted.ptr != redact_bridge.redacted_value.ptr) allocator.free(redacted);
        try list.appendSlice(allocator, redacted);
    }
    return try list.toOwnedSlice(allocator);
}

fn statusDisplayFromSummary(allocator: std.mem.Allocator, value: std.json.Value) ![]u8 {
    const object = try expectObject(value);
    const kind = try expectString(try requiredField(object, "kind"));
    const code = try expectInteger(try requiredField(object, "code"));
    const redacted_kind = redact_bridge.redactAlloc(allocator, kind) catch redact_bridge.redacted_value;
    defer if (redacted_kind.ptr != redact_bridge.redacted_value.ptr) allocator.free(redacted_kind);
    return try std.fmt.allocPrint(allocator, "{s} {d}", .{ redacted_kind, code });
}

fn eventTime(timestamp: []const u8) []const u8 {
    if (timestamp.len >= 19) return timestamp[11..19];
    return timestamp;
}

fn testSummaryJsonAlloc(allocator: std.mem.Allocator, event_count: usize, final_event_hash: []const u8, command_json: []const u8) ![]u8 {
    const canonical = try std.fmt.allocPrint(
        allocator,
        "{{\"version\":1,\"session_id\":\"s\",\"started_at\":\"2026-05-05T12:12:10Z\",\"ended_at\":\"2026-05-05T12:12:11Z\",\"workspace_root\":\"/tmp/ryk\",\"mode\":\"strict\",\"policy\":\"policy.yaml\",\"command\":{s},\"status\":{{\"kind\":\"exit\",\"code\":0}},\"event_count\":{d},\"final_event_hash\":\"{s}\"}}",
        .{ command_json, event_count, final_event_hash },
    );
    defer allocator.free(canonical);
    const summary_hash = audit_summary.summaryHash(canonical);
    return try std.fmt.allocPrint(allocator, "{s},\"summary_hash\":\"{s}\"}}\n", .{ canonical[0 .. canonical.len - 1], &summary_hash });
}

fn writeTestSummary(path: []const u8, event_count: usize, final_event_hash: []const u8, command_json: []const u8) !void {
    const text = try testSummaryJsonAlloc(std.testing.allocator, event_count, final_event_hash, command_json);
    defer std.testing.allocator.free(text);
    const file = try std.Io.Dir.cwd().createFile(std.testing.io, path, .{});
    defer file.close(std.testing.io);
    try file.writeStreamingAll(std.testing.io, text);
}

test "verification detects modified event fields" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    const ts = core.time.Timestamp.fromUnixSeconds(1_777_983_130);
    const session_id = try core.session.generateSessionId(ts);
    const session_dir = try std.fs.path.join(std.testing.allocator, &.{ root, ".ryk", "sessions", session_id.slice() });
    defer std.testing.allocator.free(session_dir);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, session_dir);

    const event_path = try std.fs.path.join(std.testing.allocator, &.{ session_dir, "events.jsonl" });
    defer std.testing.allocator.free(event_path);
    const summary_path = try std.fs.path.join(std.testing.allocator, &.{ session_dir, "summary.json" });
    defer std.testing.allocator.free(summary_path);

    const event_text =
        "{\"version\":1,\"session_id\":\"s\",\"event_id\":\"e\",\"timestamp\":\"2026-05-05T12:12:10Z\",\"type\":\"session_start\",\"actor\":{\"kind\":\"ryk\",\"id\":null,\"display\":\"ryk\"},\"target\":{\"kind\":\"session\",\"value\":\"s\"},\"decision\":null,\"redactions\":{\"count\":0,\"labels\":[]},\"previous_hash\":null";
    const hash = blk: {
        const canonical = try std.fmt.allocPrint(std.testing.allocator, "{s}}}", .{event_text});
        defer std.testing.allocator.free(canonical);
        break :blk hash_chain.eventHash(null, canonical);
    };
    {
        const file = try std.Io.Dir.cwd().createFile(std.testing.io, event_path, .{});
        defer file.close(std.testing.io);
        var buf: [1024]u8 = undefined;
        var file_writer = file.writer(std.testing.io, &buf);
        try file_writer.interface.print("{s},\"event_hash\":\"{s}\"}}\n", .{ event_text, &hash });
        try file_writer.interface.flush();
    }
    try writeTestSummary(summary_path, 1, &hash, "[\"echo\",\"hello\"]");
    var ok = try verifySessionDir(std.testing.io, std.testing.allocator, session_dir);
    defer ok.deinit(std.testing.allocator);
    try std.testing.expect(ok.ok);

    {
        const file = try std.Io.Dir.cwd().createFile(std.testing.io, event_path, .{});
        defer file.close(std.testing.io);
        var buf: [1024]u8 = undefined;
        var file_writer = file.writer(std.testing.io, &buf);
        try file_writer.interface.print("{s},\"event_hash\":\"{s}\"}}\n", .{ "{\"version\":1,\"session_id\":\"tampered\",\"event_id\":\"e\",\"timestamp\":\"2026-05-05T12:12:10Z\",\"type\":\"session_start\",\"actor\":{\"kind\":\"ryk\",\"id\":null,\"display\":\"ryk\"},\"target\":{\"kind\":\"session\",\"value\":\"s\"},\"decision\":null,\"redactions\":{\"count\":0,\"labels\":[]},\"previous_hash\":null", &hash });
        try file_writer.interface.flush();
    }
    var bad = try verifySessionDir(std.testing.io, std.testing.allocator, session_dir);
    defer bad.deinit(std.testing.allocator);
    try std.testing.expect(!bad.ok);
}

test "verification accepts rust shell metadata in audit events" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    const ts = core.time.Timestamp.fromUnixSeconds(1_777_983_130);
    const sid = try core.session.generateSessionId(ts);
    var eid: core.event.EventId = .{ .value = undefined, .len = 0 };
    const eid_text = try std.fmt.bufPrint(&eid.value, "evt_metadata", .{});
    eid.len = eid_text.len;

    var metadata: core.event.EventMetadata = .{
        .decision_source = try std.testing.allocator.dupe(u8, "rust-daemon"),
        .event_source = try std.testing.allocator.dupe(u8, "run"),
        .daemon_status = try std.testing.allocator.dupe(u8, "healthy"),
        .pack_id = try std.testing.allocator.dupe(u8, "git"),
        .severity = try std.testing.allocator.dupe(u8, "critical"),
    };
    defer metadata.deinit(std.testing.allocator);

    const ev: core.event.Event = .{
        .session_id = sid,
        .event_id = eid,
        .timestamp = ts,
        .event_type = .command_denied,
        .actor = .{ .kind = .ryk, .display = "ryk" },
        .target = .{ .kind = .command, .value = "shell command (redacted)" },
        .decision = .{
            .result = .deny,
            .reason = "blocked by ryk policy rule: destructive_rm",
            .ci_may_proceed = false,
        },
        .metadata = metadata,
    };

    const session_dir = try std.fs.path.join(std.testing.allocator, &.{ root, ".ryk", "sessions", sid.slice() });
    defer std.testing.allocator.free(session_dir);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, session_dir);

    const event_path = try std.fs.path.join(std.testing.allocator, &.{ session_dir, "events.jsonl" });
    defer std.testing.allocator.free(event_path);
    const summary_path = try std.fs.path.join(std.testing.allocator, &.{ session_dir, "summary.json" });
    defer std.testing.allocator.free(summary_path);

    const canonical = try hash_chain.canonicalEventAlloc(std.testing.allocator, ev, null);
    defer std.testing.allocator.free(canonical);
    const hash = hash_chain.eventHash(null, canonical);

    {
        const file = try std.Io.Dir.cwd().createFile(std.testing.io, event_path, .{});
        defer file.close(std.testing.io);
        var buf: [2048]u8 = undefined;
        var file_writer = file.writer(std.testing.io, &buf);
        try hash_chain.writeEventJsonLineAlloc(std.testing.allocator, &file_writer.interface, ev, null, &hash);
        try file_writer.interface.flush();
    }
    try writeTestSummary(summary_path, 1, &hash, "[\"ryk\",\"run\",\"--\",\"rm\",\"-rf\",\"/\"]");

    var ok = try verifySessionDir(std.testing.io, std.testing.allocator, session_dir);
    defer ok.deinit(std.testing.allocator);
    try std.testing.expect(ok.ok);
}

test "verification rejects event records with unauthenticated extra keys" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    const session_dir = try std.fs.path.join(std.testing.allocator, &.{ root, ".ryk", "sessions", "extra-key" });
    defer std.testing.allocator.free(session_dir);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, session_dir);

    const event_path = try std.fs.path.join(std.testing.allocator, &.{ session_dir, "events.jsonl" });
    defer std.testing.allocator.free(event_path);
    const summary_path = try std.fs.path.join(std.testing.allocator, &.{ session_dir, "summary.json" });
    defer std.testing.allocator.free(summary_path);

    const event_text =
        "{\"version\":1,\"session_id\":\"s\",\"event_id\":\"e\",\"timestamp\":\"2026-05-05T12:12:10Z\",\"type\":\"session_start\",\"actor\":{\"kind\":\"ryk\",\"id\":null,\"display\":\"ryk\"},\"target\":{\"kind\":\"session\",\"value\":\"s\"},\"decision\":null,\"redactions\":{\"count\":0,\"labels\":[]},\"previous_hash\":null";
    const hash = blk: {
        const canonical = try std.fmt.allocPrint(std.testing.allocator, "{s}}}", .{event_text});
        defer std.testing.allocator.free(canonical);
        break :blk hash_chain.eventHash(null, canonical);
    };
    {
        const file = try std.Io.Dir.cwd().createFile(std.testing.io, event_path, .{});
        defer file.close(std.testing.io);
        var buf: [1024]u8 = undefined;
        var file_writer = file.writer(std.testing.io, &buf);
        try file_writer.interface.print("{s},\"extra\":\"fake_secret_value\",\"event_hash\":\"{s}\"}}\n", .{ event_text, &hash });
        try file_writer.interface.flush();
    }
    try writeTestSummary(summary_path, 1, &hash, "[\"echo\",\"hello\"]");

    var result = try verifySessionDir(std.testing.io, std.testing.allocator, session_dir);
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(!result.ok);
    try std.testing.expectEqualStrings("malformed event", result.reason.?);
}

test "verification rejects tampered summary display fields" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    const session_dir = try std.fs.path.join(std.testing.allocator, &.{ root, ".ryk", "sessions", "summary-tamper" });
    defer std.testing.allocator.free(session_dir);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, session_dir);

    const event_path = try std.fs.path.join(std.testing.allocator, &.{ session_dir, "events.jsonl" });
    defer std.testing.allocator.free(event_path);
    const summary_path = try std.fs.path.join(std.testing.allocator, &.{ session_dir, "summary.json" });
    defer std.testing.allocator.free(summary_path);

    const event_text =
        "{\"version\":1,\"session_id\":\"s\",\"event_id\":\"e\",\"timestamp\":\"2026-05-05T12:12:10Z\",\"type\":\"session_start\",\"actor\":{\"kind\":\"ryk\",\"id\":null,\"display\":\"ryk\"},\"target\":{\"kind\":\"session\",\"value\":\"s\"},\"decision\":null,\"redactions\":{\"count\":0,\"labels\":[]},\"previous_hash\":null";
    const hash = blk: {
        const canonical = try std.fmt.allocPrint(std.testing.allocator, "{s}}}", .{event_text});
        defer std.testing.allocator.free(canonical);
        break :blk hash_chain.eventHash(null, canonical);
    };
    {
        const file = try std.Io.Dir.cwd().createFile(std.testing.io, event_path, .{});
        defer file.close(std.testing.io);
        var buf: [1024]u8 = undefined;
        var file_writer = file.writer(std.testing.io, &buf);
        try file_writer.interface.print("{s},\"event_hash\":\"{s}\"}}\n", .{ event_text, &hash });
        try file_writer.interface.flush();
    }
    const valid_summary = try testSummaryJsonAlloc(std.testing.allocator, 1, &hash, "[\"echo\",\"hello\"]");
    defer std.testing.allocator.free(valid_summary);
    {
        const file = try std.Io.Dir.cwd().createFile(std.testing.io, summary_path, .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io, valid_summary);
    }
    var ok = try verifySessionDir(std.testing.io, std.testing.allocator, session_dir);
    defer ok.deinit(std.testing.allocator);
    try std.testing.expect(ok.ok);

    const tampered_summary = try std.mem.replaceOwned(u8, std.testing.allocator, valid_summary, "echo", "fake_secret_value");
    defer std.testing.allocator.free(tampered_summary);
    {
        const file = try std.Io.Dir.cwd().createFile(std.testing.io, summary_path, .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io, tampered_summary);
    }

    var bad = try verifySessionDir(std.testing.io, std.testing.allocator, session_dir);
    defer bad.deinit(std.testing.allocator);
    try std.testing.expect(!bad.ok);
    try std.testing.expectEqualStrings("malformed summary.json", bad.reason.?);
}

test "verification reports malformed events instead of panicking" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    const session_dir = try std.fs.path.join(std.testing.allocator, &.{ root, ".ryk", "sessions", "malformed" });
    defer std.testing.allocator.free(session_dir);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, session_dir);

    const event_path = try std.fs.path.join(std.testing.allocator, &.{ session_dir, "events.jsonl" });
    defer std.testing.allocator.free(event_path);
    const summary_path = try std.fs.path.join(std.testing.allocator, &.{ session_dir, "summary.json" });
    defer std.testing.allocator.free(summary_path);

    {
        const file = try std.Io.Dir.cwd().createFile(std.testing.io, event_path, .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io, "{\"version\":1,\"previous_hash\":null,\"event_hash\":\"abc\"}\n");
    }
    try writeTestSummary(summary_path, 1, "abc", "[\"echo\",\"hello\"]");

    var result = try verifySessionDir(std.testing.io, std.testing.allocator, session_dir);
    defer result.deinit(std.testing.allocator);

    try std.testing.expect(!result.ok);
    try std.testing.expectEqualStrings("malformed event", result.reason.?);
}

test "verification detects summary event count mismatch" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const session_dir = try std.fs.path.join(std.testing.allocator, &.{ root, ".ryk", "sessions", "count-mismatch" });
    defer std.testing.allocator.free(session_dir);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, session_dir);

    const event_path = try std.fs.path.join(std.testing.allocator, &.{ session_dir, "events.jsonl" });
    defer std.testing.allocator.free(event_path);
    const summary_path = try std.fs.path.join(std.testing.allocator, &.{ session_dir, "summary.json" });
    defer std.testing.allocator.free(summary_path);
    const event_text =
        "{\"version\":1,\"session_id\":\"s\",\"event_id\":\"e\",\"timestamp\":\"2026-05-05T12:12:10Z\",\"type\":\"session_start\",\"actor\":{\"kind\":\"ryk\",\"id\":null,\"display\":\"ryk\"},\"target\":{\"kind\":\"session\",\"value\":\"s\"},\"decision\":null,\"redactions\":{\"count\":0,\"labels\":[]},\"previous_hash\":null";
    const hash = blk: {
        const canonical = try std.fmt.allocPrint(std.testing.allocator, "{s}}}", .{event_text});
        defer std.testing.allocator.free(canonical);
        break :blk hash_chain.eventHash(null, canonical);
    };
    {
        const file = try std.Io.Dir.cwd().createFile(std.testing.io, event_path, .{});
        defer file.close(std.testing.io);
        var buf: [1024]u8 = undefined;
        var file_writer = file.writer(std.testing.io, &buf);
        try file_writer.interface.print("{s},\"event_hash\":\"{s}\"}}\n", .{ event_text, &hash });
        try file_writer.interface.flush();
    }
    try writeTestSummary(summary_path, 2, &hash, "[\"echo\",\"hello\"]");

    var result = try verifySessionDir(std.testing.io, std.testing.allocator, session_dir);
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(!result.ok);
    try std.testing.expectEqualStrings("summary event count mismatch", result.reason.?);
}

test "p0-4 replay redacts structured secrets in command display" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    const session_dir = try std.fs.path.join(std.testing.allocator, &.{ root, ".ryk", "sessions", "redact-display" });
    defer std.testing.allocator.free(session_dir);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, session_dir);

    const event_path = try std.fs.path.join(std.testing.allocator, &.{ session_dir, "events.jsonl" });
    defer std.testing.allocator.free(event_path);
    const summary_path = try std.fs.path.join(std.testing.allocator, &.{ session_dir, "summary.json" });
    defer std.testing.allocator.free(summary_path);

    const event_text =
        "{\"version\":1,\"session_id\":\"s\",\"event_id\":\"e\",\"timestamp\":\"2026-05-05T12:12:10Z\",\"type\":\"command_denied\",\"actor\":{\"kind\":\"ryk\",\"id\":null,\"display\":\"ryk\"},\"target\":{\"kind\":\"command\",\"value\":\"psql\"},\"decision\":{\"result\":\"deny\",\"rule_id\":null,\"reason\":\"blocked\",\"risk_score\":null,\"requires_user\":false,\"ci_may_proceed\":false},\"redactions\":{\"count\":0,\"labels\":[]},\"previous_hash\":null";
    const hash = blk: {
        const canonical = try std.fmt.allocPrint(std.testing.allocator, "{s}}}", .{event_text});
        defer std.testing.allocator.free(canonical);
        break :blk hash_chain.eventHash(null, canonical);
    };
    {
        const file = try std.Io.Dir.cwd().createFile(std.testing.io, event_path, .{});
        defer file.close(std.testing.io);
        var buf: [1024]u8 = undefined;
        var file_writer = file.writer(std.testing.io, &buf);
        try file_writer.interface.print("{s},\"event_hash\":\"{s}\"}}\n", .{ event_text, &hash });
        try file_writer.interface.flush();
    }
    // summary command carries a connection-string credential (`ryk replay` trusts
    // at-rest redaction, so display redaction must still scrub it — P0-4).
    try writeTestSummary(summary_path, 1, &hash, "[\"psql\",\"mysql://user:pw@dbhost/app\"]");

    var session = try load(std.testing.io, std.testing.allocator, root, .{ .session = "redact-display" });
    defer session.deinit();
    try std.testing.expect(std.mem.indexOf(u8, session.command_display, "user:pw") == null);
    try std.testing.expect(std.mem.indexOf(u8, session.command_display, "[REDACTED") != null);
}

test "replay JSON presentation re-redacts verified stored strings" {
    const stored =
        "{\"version\":1,\"target\":{\"value\":\"token%3Dcorrect-horse-battery-staple\"},\"event_hash\":\"unchanged-integrity-field\"}";
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, stored, .{});
    defer parsed.deinit();
    const presented = try presentationJsonAlloc(std.testing.allocator, parsed.value);
    defer std.testing.allocator.free(presented);
    try std.testing.expect(std.mem.indexOf(u8, presented, "correct-horse") == null);
    try std.testing.expect(std.mem.indexOf(u8, presented, redact_bridge.redacted_value) != null);
    try std.testing.expect(std.mem.indexOf(u8, presented, "unchanged-integrity-field") != null);
}

test "replay event presentation redacts type timestamp and decision strings" {
    const stored =
        "{\"version\":1,\"session_id\":\"s\",\"event_id\":\"e\",\"timestamp\":\"token%3Dcorrect-horse-battery-staple\",\"type\":\"password=correct-horse-battery-staple\",\"actor\":{\"kind\":\"ryk\",\"id\":null,\"display\":null},\"target\":{\"kind\":\"command\",\"value\":\"ok\"},\"decision\":{\"result\":\"token=correct-horse-battery-staple\",\"rule_id\":null,\"reason\":\"ok\",\"risk_score\":null,\"requires_user\":false,\"ci_may_proceed\":true},\"redactions\":{\"count\":0,\"labels\":[]},\"previous_hash\":null,\"event_hash\":\"ignored\"}";
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, stored, .{});
    defer parsed.deinit();
    const event = try eventFromJson(std.testing.allocator, stored, parsed.value);
    defer event.deinit(std.testing.allocator);
    try std.testing.expect(std.mem.indexOf(u8, event.timestamp, "correct-horse") == null);
    try std.testing.expect(std.mem.indexOf(u8, event.event_type, "correct-horse") == null);
    try std.testing.expect(event.decision_result == null or std.mem.indexOf(u8, event.decision_result.?, "correct-horse") == null);
}

test "replay status display redacts attacker-controlled kind" {
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, "{\"kind\":\"password=correct-horse-battery-staple\",\"code\":1}", .{});
    defer parsed.deinit();
    const displayed = try statusDisplayFromSummary(std.testing.allocator, parsed.value);
    defer std.testing.allocator.free(displayed);
    try std.testing.expect(std.mem.indexOf(u8, displayed, "correct-horse") == null);
    try std.testing.expect(std.mem.indexOf(u8, displayed, redact_bridge.redacted_value) != null);
}

test "replay loading cleans up every allocation failure path" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const session_id = "alloc-failure";
    try writeValidReplayFixture(root, session_id);

    try std.testing.checkAllAllocationFailures(std.testing.allocator, loadReplayAllocationFailureProbe, .{ root, session_id });
}

test "replay rejects session ids with path traversal" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    try std.testing.expectError(error.InvalidSessionId, load(std.testing.io, std.testing.allocator, root, .{ .session = "../outside" }));
    try std.testing.expectError(error.InvalidSessionId, load(std.testing.io, std.testing.allocator, root, .{ .session = "." }));
    try std.testing.expectError(error.InvalidSessionId, load(std.testing.io, std.testing.allocator, root, .{ .session = ".." }));

    const audit_dir = try std.fs.path.join(std.testing.allocator, &.{ root, ".ryk" });
    defer std.testing.allocator.free(audit_dir);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, audit_dir);
    const last_path = try std.fs.path.join(std.testing.allocator, &.{ audit_dir, "last" });
    defer std.testing.allocator.free(last_path);
    {
        const file = try std.Io.Dir.cwd().createFile(std.testing.io, last_path, .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io, "../outside\n");
    }

    try std.testing.expectError(error.InvalidSessionId, load(std.testing.io, std.testing.allocator, root, .{ .session = "last" }));
    {
        const file = try std.Io.Dir.cwd().createFile(std.testing.io, last_path, .{ .truncate = true });
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io, "..\n");
    }
    try std.testing.expectError(error.InvalidSessionId, load(std.testing.io, std.testing.allocator, root, .{ .session = "last" }));
}

test "looksLikeHostConversationId accepts UUID and rejects ryk session ids" {
    try std.testing.expect(looksLikeHostConversationId("00000000-0000-0000-0000-000000000000"));
    try std.testing.expect(looksLikeHostConversationId("ABCDEFAB-CDEF-ABCD-ABCD-ABCDEFABCDEF"));
    try std.testing.expect(!looksLikeHostConversationId("2026-05-05T12-12-10Z_abcd"));
    try std.testing.expect(!looksLikeHostConversationId(""));
    try std.testing.expect(!looksLikeHostConversationId("last"));
    try std.testing.expect(!looksLikeHostConversationId("00000000-0000-0000-0000-00000000000"));
    try std.testing.expect(!looksLikeHostConversationId("000000000000000000000000000000000000"));
}

test "replay load of missing host UUID is distinct and does not alias a ryk session" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    try writeValidReplayFixture(root, "2026-05-05T12-12-10Z_abcd");

    const host_id = "00000000-0000-0000-0000-000000000000";
    try std.testing.expectError(
        error.HostConversationIdNotARykSession,
        load(std.testing.io, std.testing.allocator, root, .{ .session = host_id }),
    );

    var loaded = try load(std.testing.io, std.testing.allocator, root, .{ .session = "2026-05-05T12-12-10Z_abcd" });
    defer loaded.deinit();
    try std.testing.expectEqualStrings("2026-05-05T12-12-10Z_abcd", loaded.session_id);
}

fn loadReplayAllocationFailureProbe(allocator: std.mem.Allocator, root: []const u8, session_id: []const u8) !void {
    var replay = load(std.testing.io, allocator, root, .{ .session = session_id, .verify = true }) catch |err| switch (err) {
        // std.Io.Writer.Allocating maps allocator exhaustion to WriteFailed.
        // Normalize it so checkAllAllocationFailures can continue exercising
        // every cleanup point as allocator failure.
        error.WriteFailed => return error.OutOfMemory,
        else => return err,
    };
    defer replay.deinit();
}

fn writeValidReplayFixture(root: []const u8, session_id: []const u8) !void {
    const session_dir = try std.fs.path.join(std.testing.allocator, &.{ root, ".ryk", "sessions", session_id });
    defer std.testing.allocator.free(session_dir);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, session_dir);

    const event_path = try std.fs.path.join(std.testing.allocator, &.{ session_dir, "events.jsonl" });
    defer std.testing.allocator.free(event_path);
    const summary_path = try std.fs.path.join(std.testing.allocator, &.{ session_dir, "summary.json" });
    defer std.testing.allocator.free(summary_path);

    const event_text =
        "{\"version\":1,\"session_id\":\"s\",\"event_id\":\"e\",\"timestamp\":\"2026-05-05T12:12:10Z\",\"type\":\"command_denied\",\"actor\":{\"kind\":\"ryk\",\"id\":null,\"display\":\"ryk\"},\"target\":{\"kind\":\"command\",\"value\":\"rm -rf tmp\"},\"decision\":{\"result\":\"deny\",\"rule_id\":null,\"reason\":\"blocked\",\"risk_score\":null,\"requires_user\":false,\"ci_may_proceed\":false},\"redactions\":{\"count\":0,\"labels\":[]},\"previous_hash\":null";
    const hash = blk: {
        const canonical = try std.fmt.allocPrint(std.testing.allocator, "{s}}}", .{event_text});
        defer std.testing.allocator.free(canonical);
        break :blk hash_chain.eventHash(null, canonical);
    };
    {
        const file = try std.Io.Dir.cwd().createFile(std.testing.io, event_path, .{});
        defer file.close(std.testing.io);
        var buf: [1024]u8 = undefined;
        var file_writer = file.writer(std.testing.io, &buf);
        try file_writer.interface.print("{s},\"event_hash\":\"{s}\"}}\n", .{ event_text, &hash });
        try file_writer.interface.flush();
    }
    try writeTestSummary(summary_path, 1, &hash, "[\"ryk\",\"run\",\"--\",\"rm\",\"-rf\",\"tmp\"]");
}

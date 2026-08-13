const std = @import("std");

const core = @import("../core/public.zig");
const redact_bridge = @import("redact_bridge.zig");

pub const summary_hash_len = 64;
pub const SummaryHashHex = [summary_hash_len]u8;

pub const SummaryInput = struct {
    session: core.session.Session,
    status: core.process.ChildStatus,
    event_count: usize,
    final_event_hash: []const u8,
    policy: []const u8 = "none",
    product_label: []const u8 = "Session",
};

pub fn summaryHash(canonical_summary_without_hash: []const u8) SummaryHashHex {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(canonical_summary_without_hash);

    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return std.fmt.bytesToHex(digest, .lower);
}

pub fn writeFiles(allocator: std.mem.Allocator, session_dir_path: []const u8, input: SummaryInput) !void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const json_path = try std.fs.path.join(allocator, &.{ session_dir_path, "summary.json" });
    defer allocator.free(json_path);
    const md_path = try std.fs.path.join(allocator, &.{ session_dir_path, "summary.md" });
    defer allocator.free(md_path);
    const cwd = std.Io.Dir.cwd();

    {
        var json_aw: std.Io.Writer.Allocating = .init(allocator);
        errdefer json_aw.deinit();
        try writeJsonAlloc(allocator, &json_aw.writer, input);
        try json_aw.writer.writeByte('\n');
        try json_aw.writer.flush();
        var list = json_aw.toArrayList();
        defer list.deinit(allocator);
        const file = try cwd.createFile(io, json_path, .{});
        defer file.close(io);
        try file.writeStreamingAll(io, list.items);
        try file.sync(io);
    }
    {
        var md_aw: std.Io.Writer.Allocating = .init(allocator);
        errdefer md_aw.deinit();
        try writeMarkdownAlloc(allocator, &md_aw.writer, input);
        try md_aw.writer.flush();
        var list = md_aw.toArrayList();
        defer list.deinit(allocator);
        const file = try cwd.createFile(io, md_path, .{});
        defer file.close(io);
        try file.writeStreamingAll(io, list.items);
        try file.sync(io);
    }
}

pub fn updateFinalHash(allocator: std.mem.Allocator, session_dir_path: []const u8, event_count: usize, final_event_hash: []const u8) !void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const json_path = try std.fs.path.join(allocator, &.{ session_dir_path, "summary.json" });
    defer allocator.free(json_path);
    const md_path = try std.fs.path.join(allocator, &.{ session_dir_path, "summary.md" });
    defer allocator.free(md_path);
    const cwd = std.Io.Dir.cwd();
    const text = try cwd.readFileAlloc(io, json_path, allocator, .limited(core.limits.max_event_field_len));
    defer allocator.free(text);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, text, .{});
    defer parsed.deinit();
    const object = try expectObject(parsed.value);
    try verifyStoredSummaryHash(allocator, parsed.value);

    var canonical_aw: std.Io.Writer.Allocating = .init(allocator);
    errdefer canonical_aw.deinit();
    try writeRedactedCanonicalSummaryFromJson(allocator, &canonical_aw.writer, object, event_count, final_event_hash);
    var canonical = canonical_aw.toArrayList();
    defer canonical.deinit(allocator);
    const computed_summary_hash = summaryHash(canonical.items);

    const file = try cwd.createFile(io, json_path, .{});
    defer file.close(io);
    var file_buf: [4096]u8 = undefined;
    var file_writer = file.writer(io, &file_buf);
    try writeSummaryWithHash(&file_writer.interface, canonical.items, &computed_summary_hash);
    try file_writer.interface.writeByte('\n');
    try file_writer.interface.flush();
    try file.sync(io);

    var md_aw: std.Io.Writer.Allocating = .init(allocator);
    errdefer md_aw.deinit();
    const safe_session_id = try redact_bridge.redactAlloc(allocator, object.get("session_id").?.string);
    defer allocator.free(safe_session_id);
    const safe_policy = try redact_bridge.redactAlloc(allocator, object.get("policy").?.string);
    defer allocator.free(safe_policy);
    const safe_mode = try redact_bridge.redactAlloc(allocator, object.get("mode").?.string);
    defer allocator.free(safe_mode);
    const safe_status_kind = try redact_bridge.redactAlloc(allocator, object.get("status").?.object.get("kind").?.string);
    defer allocator.free(safe_status_kind);
    try writeMarkdownHeading(allocator, &md_aw.writer, "Session", safe_session_id);
    try md_aw.writer.writeAll("\n- Command: `");
    try writeCommandDisplayFromJson(allocator, &md_aw.writer, object.get("command").?.array);
    try md_aw.writer.print("`\n- Policy: {s}\n- Mode: {s}\n- Status: {s} {d}\n- Events: {d}\n- Final event hash: `{s}`\n", .{
        safe_policy,
        safe_mode,
        safe_status_kind,
        object.get("status").?.object.get("code").?.integer,
        event_count,
        final_event_hash,
    });
    try md_aw.writer.flush();
    var md = md_aw.toArrayList();
    defer md.deinit(allocator);
    {
        const md_file = try cwd.createFile(io, md_path, .{});
        defer md_file.close(io);
        try md_file.writeStreamingAll(io, md.items);
        try md_file.sync(io);
    }
}

pub fn writeJson(writer: anytype, input: SummaryInput) !void {
    try writeJsonAlloc(std.heap.page_allocator, writer, input);
}

pub fn writeJsonAlloc(allocator: std.mem.Allocator, writer: anytype, input: SummaryInput) !void {
    var canonical_aw: std.Io.Writer.Allocating = .init(allocator);
    errdefer canonical_aw.deinit();
    try writeCanonicalSummaryInput(allocator, &canonical_aw.writer, input);
    var canonical = canonical_aw.toArrayList();
    defer canonical.deinit(allocator);
    const computed_summary_hash = summaryHash(canonical.items);
    try writeSummaryWithHash(writer, canonical.items, &computed_summary_hash);
}

fn writeCanonicalSummaryInput(allocator: std.mem.Allocator, writer: anytype, input: SummaryInput) !void {
    var started_buf: [32]u8 = undefined;
    const started = try input.session.started_at.formatIso(&started_buf);
    var ended_buf: [32]u8 = undefined;
    const ended = if (input.session.ended_at) |ended_at| try ended_at.formatIso(&ended_buf) else null;

    try writer.writeByte('{');
    try writer.writeAll("\"version\":1,\"session_id\":");
    try core.util.writeJsonString(writer, input.session.id.slice());
    try writer.writeAll(",\"started_at\":");
    try core.util.writeJsonString(writer, started);
    try writer.writeAll(",\"ended_at\":");
    if (ended) |value| try core.util.writeJsonString(writer, value) else try writer.writeAll("null");
    try writer.writeAll(",\"workspace_root\":");
    try writeRedactedPathJsonString(allocator, writer, input.session.workspace_root);
    try writer.writeAll(",\"mode\":");
    try core.util.writeJsonString(writer, input.session.mode.toString());
    try writer.writeAll(",\"policy\":");
    try writeRedactedJsonString(allocator, writer, input.policy);
    try writer.writeAll(",\"command\":");
    try writeCommandArray(allocator, writer, input.session.command, input.session.args);
    try writer.writeAll(",\"status\":");
    try writeStatus(writer, input.status);
    try writer.print(",\"event_count\":{d},\"final_event_hash\":", .{input.event_count});
    try core.util.writeJsonString(writer, input.final_event_hash);
    try writer.writeByte('}');
}

fn writeSummaryWithHash(writer: anytype, canonical: []const u8, computed_summary_hash: []const u8) !void {
    if (canonical.len == 0 or canonical[canonical.len - 1] != '}') return error.InvalidEventSchema;
    try writer.writeAll(canonical[0 .. canonical.len - 1]);
    try writer.writeAll(",\"summary_hash\":");
    try core.util.writeJsonString(writer, computed_summary_hash);
    try writer.writeByte('}');
}

pub fn canonicalFromJsonValue(allocator: std.mem.Allocator, value: std.json.Value) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    const object = try expectObject(value);
    try writeCanonicalSummaryFromJson(&out.writer, object, null, null);
    return try out.toOwnedSlice();
}

fn verifyStoredSummaryHash(allocator: std.mem.Allocator, value: std.json.Value) !void {
    const object = try expectObject(value);
    const stored_hash = try expectString(try requiredField(object, "summary_hash"));
    const canonical = try canonicalFromJsonValue(allocator, value);
    defer allocator.free(canonical);
    const computed_hash = summaryHash(canonical);
    if (!std.mem.eql(u8, stored_hash, &computed_hash)) return error.InvalidEventSchema;
}

fn writeCanonicalSummaryFromJson(
    writer: anytype,
    object: std.json.ObjectMap,
    event_count_override: ?usize,
    final_hash_override: ?[]const u8,
) !void {
    try rejectUnknownKeys(object, &.{
        "version",
        "session_id",
        "started_at",
        "ended_at",
        "workspace_root",
        "mode",
        "policy",
        "command",
        "status",
        "event_count",
        "final_event_hash",
        "summary_hash",
    });
    if (object.get("summary_hash")) |hash_value| _ = try expectString(hash_value);

    try writer.writeByte('{');
    try writer.print("\"version\":{d}", .{try expectInteger(try requiredField(object, "version"))});
    try writeStringValueField(writer, "session_id", try requiredField(object, "session_id"));
    try writeStringValueField(writer, "started_at", try requiredField(object, "started_at"));
    try writer.writeAll(",\"ended_at\":");
    try writeNullableJsonValue(writer, try requiredField(object, "ended_at"));
    try writeStringValueField(writer, "workspace_root", try requiredField(object, "workspace_root"));
    try writeStringValueField(writer, "mode", try requiredField(object, "mode"));
    try writeStringValueField(writer, "policy", try requiredField(object, "policy"));
    try writer.writeAll(",\"command\":");
    try writeCommandJsonValue(writer, try expectArray(try requiredField(object, "command")));
    try writer.writeAll(",\"status\":");
    try writeStatusJsonValue(writer, try expectObject(try requiredField(object, "status")));
    const event_count = if (event_count_override) |count| count else count: {
        const parsed_count = try expectInteger(try requiredField(object, "event_count"));
        if (parsed_count < 0) return error.InvalidEventSchema;
        break :count @as(usize, @intCast(parsed_count));
    };
    try writer.print(",\"event_count\":{d},\"final_event_hash\":", .{event_count});
    if (final_hash_override) |final_hash| {
        try core.util.writeJsonString(writer, final_hash);
    } else {
        try core.util.writeJsonString(writer, try expectString(try requiredField(object, "final_event_hash")));
    }
    try writer.writeByte('}');
}

fn writeRedactedCanonicalSummaryFromJson(
    allocator: std.mem.Allocator,
    writer: anytype,
    object: std.json.ObjectMap,
    event_count_override: ?usize,
    final_hash_override: ?[]const u8,
) !void {
    try rejectUnknownKeys(object, &.{
        "version",
        "session_id",
        "started_at",
        "ended_at",
        "workspace_root",
        "mode",
        "policy",
        "command",
        "status",
        "event_count",
        "final_event_hash",
        "summary_hash",
    });
    if (object.get("summary_hash")) |hash_value| _ = try expectString(hash_value);

    try writer.writeByte('{');
    try writer.print("\"version\":{d}", .{try expectInteger(try requiredField(object, "version"))});
    try writeRedactedStringValueField(allocator, writer, "session_id", try requiredField(object, "session_id"));
    try writeRedactedStringValueField(allocator, writer, "started_at", try requiredField(object, "started_at"));
    try writer.writeAll(",\"ended_at\":");
    try writeRedactedNullableJsonValue(allocator, writer, try requiredField(object, "ended_at"));
    try writer.writeAll(",\"workspace_root\":");
    try writeRedactedPathJsonString(allocator, writer, try expectString(try requiredField(object, "workspace_root")));
    try writeRedactedStringValueField(allocator, writer, "mode", try requiredField(object, "mode"));
    try writeRedactedStringValueField(allocator, writer, "policy", try requiredField(object, "policy"));
    try writer.writeAll(",\"command\":");
    try writeRedactedCommandJsonValue(allocator, writer, try expectArray(try requiredField(object, "command")));
    try writer.writeAll(",\"status\":");
    try writeRedactedStatusJsonValue(allocator, writer, try expectObject(try requiredField(object, "status")));
    const event_count = if (event_count_override) |count| count else count: {
        const parsed_count = try expectInteger(try requiredField(object, "event_count"));
        if (parsed_count < 0) return error.InvalidEventSchema;
        break :count @as(usize, @intCast(parsed_count));
    };
    try writer.print(",\"event_count\":{d},\"final_event_hash\":", .{event_count});
    if (final_hash_override) |final_hash| {
        try core.util.writeJsonString(writer, final_hash);
    } else {
        try writeRedactedJsonString(allocator, writer, try expectString(try requiredField(object, "final_event_hash")));
    }
    try writer.writeByte('}');
}

pub fn writeMarkdown(writer: anytype, input: SummaryInput) !void {
    try writeMarkdownAlloc(std.heap.page_allocator, writer, input);
}

pub fn writeMarkdownAlloc(allocator: std.mem.Allocator, writer: anytype, input: SummaryInput) !void {
    const safe_policy = redact_bridge.redactAlloc(allocator, input.policy) catch redact_bridge.redacted_value;
    defer if (safe_policy.ptr != redact_bridge.redacted_value.ptr) allocator.free(safe_policy);
    try writeMarkdownHeading(allocator, writer, input.product_label, input.session.id.slice());
    try writer.writeAll(
        \\
        \\- Command: `
    );
    try writeCommandDisplay(allocator, writer, input.session.command, input.session.args);
    try writer.print(
        \\`
        \\- Policy: {s}
        \\- Mode: {s}
        \\- Status: {s}
        \\- Events: {d}
        \\- Final event hash: `{s}`
        \\
    , .{
        safe_policy,
        input.session.mode.toString(),
        statusText(input.status),
        input.event_count,
        input.final_event_hash,
    });
}

fn writeMarkdownHeading(allocator: std.mem.Allocator, writer: anytype, product_label: []const u8, session_id: []const u8) !void {
    if (product_label.len == 0 or std.mem.eql(u8, product_label, "Session")) {
        try writer.print("# Session {s}\n", .{session_id});
        return;
    }
    const safe_label = redact_bridge.redactAlloc(allocator, product_label) catch redact_bridge.redacted_value;
    defer if (safe_label.ptr != redact_bridge.redacted_value.ptr) allocator.free(safe_label);
    try writer.print("# {s} Session {s}\n", .{ safe_label, session_id });
}

fn writeCommandArray(allocator: std.mem.Allocator, writer: anytype, command: []const u8, args: []const []const u8) !void {
    try writer.writeByte('[');
    try writeRedactedJsonString(allocator, writer, command);
    for (args) |arg| {
        try writer.writeByte(',');
        try writeRedactedJsonString(allocator, writer, arg);
    }
    try writer.writeByte(']');
}

fn writeRedactedJsonString(allocator: std.mem.Allocator, writer: anytype, value: []const u8) !void {
    const redacted = redact_bridge.redactAlloc(allocator, value) catch redact_bridge.redacted_value;
    defer if (redacted.ptr != redact_bridge.redacted_value.ptr) allocator.free(redacted);
    try core.util.writeJsonString(writer, redacted);
}

fn writeRedactedPathJsonString(allocator: std.mem.Allocator, writer: anytype, value: []const u8) !void {
    const redacted = try redact_bridge.redactAlloc(allocator, value);
    defer allocator.free(redacted);
    if (!std.mem.eql(u8, redacted, value)) {
        try core.util.writeJsonString(writer, redacted);
        return;
    }

    // Encoded credentials frequently occupy one path component. The generic
    // prose tokenizer intentionally keeps `/` inside tokens, so inspect path
    // components independently and fail closed for the whole path on a match.
    var components = std.mem.tokenizeAny(u8, value, "/\\");
    while (components.next()) |component| {
        const safe_component = try redact_bridge.redactAlloc(allocator, component);
        defer allocator.free(safe_component);
        if (!std.mem.eql(u8, safe_component, component)) {
            try core.util.writeJsonString(writer, redact_bridge.redacted_value);
            return;
        }
    }
    try core.util.writeJsonString(writer, value);
}

fn writeStatus(writer: anytype, status: core.process.ChildStatus) !void {
    try writer.writeByte('{');
    switch (status) {
        .exited => |code| try writer.print("\"kind\":\"exit\",\"code\":{d}", .{code}),
        .signal => |signal| try writer.print("\"kind\":\"signal\",\"code\":{d}", .{signal}),
        .stopped => |signal| try writer.print("\"kind\":\"stopped\",\"code\":{d}", .{signal}),
        .unknown => |code| try writer.print("\"kind\":\"unknown\",\"code\":{d}", .{code}),
    }
    try writer.writeByte('}');
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

fn writeStringValueField(writer: anytype, name: []const u8, value: std.json.Value) !void {
    try writer.writeByte(',');
    try core.util.writeJsonString(writer, name);
    try writer.writeByte(':');
    try core.util.writeJsonString(writer, try expectString(value));
}

fn writeRedactedStringValueField(allocator: std.mem.Allocator, writer: anytype, name: []const u8, value: std.json.Value) !void {
    try writer.writeByte(',');
    try core.util.writeJsonString(writer, name);
    try writer.writeByte(':');
    try writeRedactedJsonString(allocator, writer, try expectString(value));
}

fn writeNullableJsonValue(writer: anytype, value: std.json.Value) !void {
    if (value == .null) try writer.writeAll("null") else try core.util.writeJsonString(writer, try expectString(value));
}

fn writeRedactedNullableJsonValue(allocator: std.mem.Allocator, writer: anytype, value: std.json.Value) !void {
    if (value == .null) try writer.writeAll("null") else try writeRedactedJsonString(allocator, writer, try expectString(value));
}

fn writeCommandJsonValue(writer: anytype, command: std.json.Array) !void {
    try writer.writeByte('[');
    for (command.items, 0..) |item, index| {
        if (index > 0) try writer.writeByte(',');
        try core.util.writeJsonString(writer, try expectString(item));
    }
    try writer.writeByte(']');
}

fn writeRedactedCommandJsonValue(allocator: std.mem.Allocator, writer: anytype, command: std.json.Array) !void {
    try writer.writeByte('[');
    for (command.items, 0..) |item, index| {
        if (index > 0) try writer.writeByte(',');
        try writeRedactedJsonString(allocator, writer, try expectString(item));
    }
    try writer.writeByte(']');
}

fn writeCommandDisplayFromJson(allocator: std.mem.Allocator, writer: anytype, command: std.json.Array) !void {
    for (command.items, 0..) |item, index| {
        if (index > 0) try writer.writeByte(' ');
        const safe_item = try redact_bridge.redactAlloc(allocator, try expectString(item));
        defer allocator.free(safe_item);
        try writer.writeAll(safe_item);
    }
}

fn writeStatusJsonValue(writer: anytype, status: std.json.ObjectMap) !void {
    try rejectUnknownKeys(status, &.{ "kind", "code" });
    try writer.writeByte('{');
    try writer.writeAll("\"kind\":");
    try core.util.writeJsonString(writer, try expectString(try requiredField(status, "kind")));
    try writer.print(",\"code\":{d}", .{try expectInteger(try requiredField(status, "code"))});
    try writer.writeByte('}');
}

fn writeRedactedStatusJsonValue(allocator: std.mem.Allocator, writer: anytype, status: std.json.ObjectMap) !void {
    try rejectUnknownKeys(status, &.{ "kind", "code" });
    try writer.writeByte('{');
    try writer.writeAll("\"kind\":");
    try writeRedactedJsonString(allocator, writer, try expectString(try requiredField(status, "kind")));
    try writer.print(",\"code\":{d}", .{try expectInteger(try requiredField(status, "code"))});
    try writer.writeByte('}');
}

pub fn statusText(status: core.process.ChildStatus) []const u8 {
    return switch (status) {
        .exited => |code| if (code == 0) "exit 0" else "exit nonzero",
        .signal => "signal",
        .stopped => "stopped",
        .unknown => "unknown",
    };
}

fn writeCommandDisplay(allocator: std.mem.Allocator, writer: anytype, command: []const u8, args: []const []const u8) !void {
    const safe_command = redact_bridge.redactAlloc(allocator, command) catch redact_bridge.redacted_value;
    defer if (safe_command.ptr != redact_bridge.redacted_value.ptr) allocator.free(safe_command);
    try writer.writeAll(safe_command);
    for (args) |arg| {
        try writer.writeByte(' ');
        const safe_arg = redact_bridge.redactAlloc(allocator, arg) catch redact_bridge.redacted_value;
        defer if (safe_arg.ptr != redact_bridge.redacted_value.ptr) allocator.free(safe_arg);
        try writer.writeAll(safe_arg);
    }
}

test "summary json records final hash and bounded command metadata" {
    const ts = core.time.Timestamp.fromUnixSeconds(1_777_983_130);
    const session: core.session.Session = .{
        .id = try core.session.generateSessionId(ts),
        .started_at = ts,
        .ended_at = ts,
        .command = "echo",
        .args = &.{"hello"},
        .workspace_root = "/tmp/ryk",
        .mode = .observe,
        .platform = core.platform.detectOs(),
    };
    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer aw.deinit();
    try writeJsonAlloc(std.testing.allocator, &aw.writer, .{
        .session = session,
        .status = .{ .exited = 0 },
        .event_count = 3,
        .final_event_hash = "abc",
    });
    try std.testing.expect(std.mem.indexOf(u8, aw.written(), "\"final_event_hash\":\"abc\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, aw.written(), "\"command\":[\"echo\",\"hello\"]") != null);
}

test "summary redacts synthetic secret command metadata" {
    const ts = core.time.Timestamp.fromUnixSeconds(1_777_983_130);
    const session: core.session.Session = .{
        .id = try core.session.generateSessionId(ts),
        .started_at = ts,
        .ended_at = ts,
        .command = "echo",
        .args = &.{"fake_secret_value"},
        .workspace_root = "/tmp/ryk",
        .mode = .observe,
        .platform = core.platform.detectOs(),
    };
    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer aw.deinit();
    try writeJsonAlloc(std.testing.allocator, &aw.writer, .{
        .session = session,
        .status = .{ .exited = 0 },
        .event_count = 3,
        .final_event_hash = "abc",
    });
    try std.testing.expect(std.mem.indexOf(u8, aw.written(), "fake_secret_value") == null);
    try std.testing.expect(std.mem.indexOf(u8, aw.written(), redact_bridge.redacted_value) != null);
}

test "p0-4 summary redacts structured secrets classifyString missed" {
    const ts = core.time.Timestamp.fromUnixSeconds(1_777_983_130);
    const session: core.session.Session = .{
        .id = try core.session.generateSessionId(ts),
        .started_at = ts,
        .ended_at = ts,
        .command = "psql",
        .args = &.{ "mysql://user:pw@dbhost/app", "{\"password\":\"hunter2\"}" },
        .workspace_root = "/tmp/ryk",
        .mode = .observe,
        .platform = core.platform.detectOs(),
    };
    // summary.json: command args carry a connection-string password + JSON password.
    var json_aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer json_aw.deinit();
    try writeJsonAlloc(std.testing.allocator, &json_aw.writer, .{
        .session = session,
        .status = .{ .exited = 0 },
        .event_count = 1,
        .final_event_hash = "abc",
    });
    try std.testing.expect(std.mem.indexOf(u8, json_aw.written(), "user:pw") == null);
    try std.testing.expect(std.mem.indexOf(u8, json_aw.written(), "hunter2") == null);
    try std.testing.expect(std.mem.indexOf(u8, json_aw.written(), "[REDACTED") != null);

    // summary.md: the policy field carries an Authorization header credential.
    var md_aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer md_aw.deinit();
    try writeMarkdownAlloc(std.testing.allocator, &md_aw.writer, .{
        .session = session,
        .status = .{ .exited = 0 },
        .event_count = 1,
        .final_event_hash = "abc",
        .policy = "Authorization: Bearer abc123def456ghi",
    });
    try std.testing.expect(std.mem.indexOf(u8, md_aw.written(), "abc123def456ghi") == null);
    try std.testing.expect(std.mem.indexOf(u8, md_aw.written(), "[REDACTED") != null);
}

test "summary json redacts credential-shaped and encoded workspace roots" {
    const ts = core.time.Timestamp.fromUnixSeconds(1_777_983_130);
    const roots = [_][]const u8{
        "/tmp/api_key=workspace-secret-value/project",
        "/tmp/cGFzc3dvcmQ9d29ya3NwYWNlLXNlY3JldC12YWx1ZQ==/project",
    };
    for (roots) |workspace_root| {
        const session: core.session.Session = .{
            .id = try core.session.generateSessionId(ts),
            .started_at = ts,
            .ended_at = ts,
            .command = "echo",
            .args = &.{"hello"},
            .workspace_root = workspace_root,
            .mode = .observe,
            .platform = core.platform.detectOs(),
        };
        var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
        defer aw.deinit();
        try writeJsonAlloc(std.testing.allocator, &aw.writer, .{
            .session = session,
            .status = .{ .exited = 0 },
            .event_count = 1,
            .final_event_hash = "abc",
        });
        try std.testing.expect(std.mem.indexOf(u8, aw.written(), workspace_root) == null);
        try std.testing.expect(std.mem.indexOf(u8, aw.written(), "[REDACTED]") != null);
    }
}

test "summary markdown is product neutral unless caller provides label" {
    const ts = core.time.Timestamp.fromUnixSeconds(1_777_983_130);
    const session: core.session.Session = .{
        .id = try core.session.generateSessionId(ts),
        .started_at = ts,
        .ended_at = ts,
        .command = "echo",
        .args = &.{"hello"},
        .workspace_root = "/tmp/ryk",
        .mode = .observe,
        .platform = core.platform.detectOs(),
    };
    var generic: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer generic.deinit();
    try writeMarkdownAlloc(std.testing.allocator, &generic.writer, .{
        .session = session,
        .status = .{ .exited = 0 },
        .event_count = 3,
        .final_event_hash = "abc",
    });
    const labeled_heading_text = "ryk" ++ " Session";
    try std.testing.expect(std.mem.indexOf(u8, generic.written(), labeled_heading_text) == null);
    try std.testing.expect(std.mem.indexOf(u8, generic.written(), "# Session ") != null);

    var labeled: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer labeled.deinit();
    try writeMarkdownAlloc(std.testing.allocator, &labeled.writer, .{
        .session = session,
        .status = .{ .exited = 0 },
        .event_count = 3,
        .final_event_hash = "abc",
        // Literal (not cli/brand.zig): this file is also owned by core_engine module.
        .product_label = "ryk",
    });
    const labeled_heading_prefix = "# " ++ "ryk" ++ " Session ";
    try std.testing.expect(std.mem.indexOf(u8, labeled.written(), labeled_heading_prefix) != null);
}

test "update final hash rejects tampered summary before rewriting" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    const session_dir = try std.fs.path.join(std.testing.allocator, &.{ root, ".ryk", "sessions", "summary-tamper" });
    defer std.testing.allocator.free(session_dir);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, session_dir);

    const ts = core.time.Timestamp.fromUnixSeconds(1_777_983_130);
    const session: core.session.Session = .{
        .id = try core.session.generateSessionId(ts),
        .started_at = ts,
        .ended_at = ts,
        .command = "echo",
        .args = &.{"hello"},
        .workspace_root = root,
        .mode = .observe,
        .platform = core.platform.detectOs(),
    };
    try writeFiles(std.testing.allocator, session_dir, .{
        .session = session,
        .status = .{ .exited = 0 },
        .event_count = 3,
        .final_event_hash = "abc",
    });

    const summary_path = try std.fs.path.join(std.testing.allocator, &.{ session_dir, "summary.json" });
    defer std.testing.allocator.free(summary_path);
    const original = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, summary_path, std.testing.allocator, std.Io.Limit.limited(core.limits.max_event_field_len));
    defer std.testing.allocator.free(original);
    const tampered = try std.mem.replaceOwned(u8, std.testing.allocator, original, "hello", "changed");
    defer std.testing.allocator.free(tampered);
    {
        const file = try std.Io.Dir.cwd().createFile(std.testing.io, summary_path, .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io, tampered);
    }

    try std.testing.expectError(error.InvalidEventSchema, updateFinalHash(std.testing.allocator, session_dir, 4, "def"));

    const after = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, summary_path, std.testing.allocator, std.Io.Limit.limited(core.limits.max_event_field_len));
    defer std.testing.allocator.free(after);
    try std.testing.expect(std.mem.indexOf(u8, after, "changed") != null);
    try std.testing.expect(std.mem.indexOf(u8, after, "\"final_event_hash\":\"def\"") == null);
}

test "update final hash re-redacts legacy stored summary strings" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const session_dir = try std.fs.path.join(std.testing.allocator, &.{ root, "session" });
    defer std.testing.allocator.free(session_dir);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, session_dir);

    const legacy_command = "password=legacy-command-secret-value";
    const legacy_policy = "api_key=legacy-policy-secret-value";
    const legacy_workspace = "/tmp/token=legacy-workspace-secret-value/project";
    const canonical = try std.fmt.allocPrint(std.testing.allocator, "{{\"version\":1,\"session_id\":\"session-id\",\"started_at\":\"2026-01-01T00:00:00Z\",\"ended_at\":null,\"workspace_root\":\"{s}\",\"mode\":\"observe\",\"policy\":\"{s}\",\"command\":[\"echo\",\"{s}\"],\"status\":{{\"kind\":\"exit\",\"code\":0}},\"event_count\":1,\"final_event_hash\":\"abc\"}}", .{ legacy_workspace, legacy_policy, legacy_command });
    defer std.testing.allocator.free(canonical);
    const legacy_hash = summaryHash(canonical);
    const legacy_summary = try std.fmt.allocPrint(std.testing.allocator, "{s},\"summary_hash\":\"{s}\"}}\n", .{ canonical[0 .. canonical.len - 1], legacy_hash });
    defer std.testing.allocator.free(legacy_summary);

    const json_path = try std.fs.path.join(std.testing.allocator, &.{ session_dir, "summary.json" });
    defer std.testing.allocator.free(json_path);
    {
        const file = try std.Io.Dir.cwd().createFile(std.testing.io, json_path, .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io, legacy_summary);
    }

    try updateFinalHash(std.testing.allocator, session_dir, 2, "def");
    const updated_json = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, json_path, std.testing.allocator, .limited(core.limits.max_event_field_len));
    defer std.testing.allocator.free(updated_json);
    const md_path = try std.fs.path.join(std.testing.allocator, &.{ session_dir, "summary.md" });
    defer std.testing.allocator.free(md_path);
    const updated_md = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, md_path, std.testing.allocator, .limited(core.limits.max_event_field_len));
    defer std.testing.allocator.free(updated_md);

    for ([_][]const u8{ legacy_command, legacy_policy, legacy_workspace }) |secret| {
        try std.testing.expect(std.mem.indexOf(u8, updated_json, secret) == null);
        try std.testing.expect(std.mem.indexOf(u8, updated_md, secret) == null);
    }
    try std.testing.expect(std.mem.indexOf(u8, updated_json, "[REDACTED]") != null);
    try std.testing.expect(std.mem.indexOf(u8, updated_md, "[REDACTED]") != null);
    try std.testing.expect(std.mem.indexOf(u8, updated_json, "\"event_count\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, updated_json, "\"final_event_hash\":\"def\"") != null);

    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, updated_json, .{});
    defer parsed.deinit();
    try verifyStoredSummaryHash(std.testing.allocator, parsed.value);
}

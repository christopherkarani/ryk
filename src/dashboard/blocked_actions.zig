const std = @import("std");

const core = @import("ryk_core").core;
const core_api = @import("ryk_core").api;
const presentation = @import("../presentation/mod.zig");
const rust_visibility = @import("../cli/feed_visibility.zig");

pub const ParsedMetadata = struct {
    decision_source: ?[]const u8 = null,
    event_source: ?[]const u8 = null,
    host: ?[]const u8 = null,
    daemon_status: ?[]const u8 = null,
    pack_id: ?[]const u8 = null,
    severity: ?[]const u8 = null,
    remediation: ?[]const u8 = null,
};

pub fn writeBlockedActionJson(allocator: std.mem.Allocator, writer: anytype, session_id: []const u8, verified: bool, ev: core_api.ReplayEvent) !void {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, ev.raw, .{}) catch null;
    defer if (parsed) |*p| p.deinit();
    const metadata = readEventMetadata(parsed);

    try writer.writeByte('{');
    try writer.writeAll("\"session_id\":");
    try core.util.writeJsonString(writer, session_id);
    try writer.writeAll(",\"timestamp\":");
    try core.util.writeJsonString(writer, ev.timestamp);
    try writer.writeAll(",\"event_type\":");
    try core.util.writeJsonString(writer, ev.event_type);
    try writer.writeAll(",\"target\":");
    try writeBlockedActionTarget(allocator, writer, metadata, ev.target_value);
    try writer.writeAll(",\"decision\":");
    if (ev.decision_result) |result| try core.util.writeJsonString(writer, result) else try writer.writeAll("null");
    try writer.writeAll(",\"verified\":");
    try writer.writeAll(if (verified) "true" else "false");
    try writer.writeAll(",\"rule\":");
    try writeDecisionRuleField(writer, parsed);
    try writer.writeAll(",\"reason\":");
    try writeDecisionReasonField(allocator, writer, parsed);
    try writeMetadataFields(allocator, writer, metadata);
    try writer.writeByte('}');
}

fn writeBlockedActionTarget(allocator: std.mem.Allocator, writer: anytype, metadata: ParsedMetadata, target_value: []const u8) !void {
    if (metadata.decision_source != null and std.mem.eql(u8, metadata.decision_source.?, rust_visibility.decision_source_rust)) {
        try core.util.writeJsonString(writer, rust_visibility.target_summary_shell);
        return;
    }
    try presentation.redact.writeJsonString(allocator, writer, target_value);
}

pub fn readEventMetadata(parsed: ?std.json.Parsed(std.json.Value)) ParsedMetadata {
    const object = if (parsed) |p| blk: {
        if (p.value != .object) return .{};
        break :blk p.value.object;
    } else return .{};
    const metadata = object.get("metadata") orelse return .{};
    if (metadata != .object) return .{};
    return .{
        .decision_source = readMetadataString(metadata.object, "decision_source"),
        .event_source = readMetadataString(metadata.object, "event_source"),
        .host = readMetadataString(metadata.object, "host"),
        .daemon_status = readMetadataString(metadata.object, "daemon_status"),
        .pack_id = readMetadataString(metadata.object, "pack_id"),
        .severity = readMetadataString(metadata.object, "severity"),
        .remediation = readMetadataString(metadata.object, "remediation"),
    };
}

fn readMetadataString(object: std.json.ObjectMap, field: []const u8) ?[]const u8 {
    const value = object.get(field) orelse return null;
    if (value != .string) return null;
    return value.string;
}

pub fn writeMetadataFields(allocator: std.mem.Allocator, writer: anytype, metadata: ParsedMetadata) !void {
    try writer.writeAll(",\"decision_source\":");
    try writeOptionalRedactedJsonString(allocator, writer, metadata.decision_source);
    try writer.writeAll(",\"event_source\":");
    try writeOptionalRedactedJsonString(allocator, writer, metadata.event_source);
    try writer.writeAll(",\"host\":");
    try writeOptionalRedactedJsonString(allocator, writer, metadata.host);
    try writer.writeAll(",\"daemon_status\":");
    try writeOptionalRedactedJsonString(allocator, writer, metadata.daemon_status);
    try writer.writeAll(",\"pack_id\":");
    try writeOptionalRedactedJsonString(allocator, writer, metadata.pack_id);
    try writer.writeAll(",\"severity\":");
    try writeOptionalRedactedJsonString(allocator, writer, metadata.severity);
    try writer.writeAll(",\"remediation\":");
    try writeOptionalRedactedJsonString(allocator, writer, metadata.remediation);
}

fn writeOptionalRedactedJsonString(allocator: std.mem.Allocator, writer: anytype, value: ?[]const u8) !void {
    if (value) |text| {
        try presentation.redact.writeJsonString(allocator, writer, text);
    } else {
        try writer.writeAll("null");
    }
}

fn writeDecisionRuleField(writer: anytype, parsed: ?std.json.Parsed(std.json.Value)) !void {
    const value = decisionStringField(parsed, "rule_id");
    if (value) |text| try core.util.writeJsonString(writer, text) else try writer.writeAll("null");
}

fn writeDecisionReasonField(allocator: std.mem.Allocator, writer: anytype, parsed: ?std.json.Parsed(std.json.Value)) !void {
    const value = decisionStringField(parsed, "reason");
    if (value) |text| try presentation.redact.writeJsonString(allocator, writer, text) else try writer.writeAll("null");
}

fn decisionStringField(parsed: ?std.json.Parsed(std.json.Value), field: []const u8) ?[]const u8 {
    const p = parsed orelse return null;
    if (p.value != .object) return null;
    const decision = p.value.object.get("decision") orelse return null;
    if (decision != .object) return null;
    const raw = decision.object.get(field) orelse return null;
    if (raw != .string) return null;
    return raw.string;
}

test "metadata remediation is redacted before dashboard serialization" {
    var output: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&output);

    try writeMetadataFields(std.testing.allocator, &writer, .{
        .remediation = "Authorization: Bearer sk-fakeSyntheticOpenAIKey1234567890",
    });

    const rendered = writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, rendered, "sk-fakeSyntheticOpenAIKey1234567890") == null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "[REDACTED]") != null);
}

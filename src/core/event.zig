const std = @import("std");
const decision = @import("decision.zig");
const limits = @import("limits.zig");
const session = @import("session.zig");
const time = @import("time.zig");
const types = @import("types.zig");
const util = @import("util.zig");

pub const schema_version: u16 = 1;

pub const EventType = enum {
    extension_event,
    session_start,
    session_exit,
    policy_loaded,
    backend_capability,
    /// Live session OS FS sandbox posture (posture string, optional profile hash, fs_scope).
    /// Emitted once at session start after apply/attach; never carries full profile text.
    sandbox_posture,
    /// Reserved for explicit OS-sandbox denial telemetry. Must never be auto-emitted from
    /// ordinary Unix EACCES / AccessDenied on wrapper-mediated file ops (use file_*_denied).
    os_fs_deny,
    process_launch,
    file_read_attempt,
    file_read_allowed,
    file_read_denied,
    file_write_attempt,
    file_write_staged,
    file_write_denied,
    file_apply,
    file_discard,
    command_attempt,
    command_approval_requested,
    command_allowed,
    command_denied,
    network_connect_attempt,
    network_connect_allowed,
    network_connect_denied,
    network_proxy_start,
    network_proxy_stop,
    network_exfiltration_suspected,
    mcp_initialize,
    mcp_tools_list,
    mcp_tool_metadata_flagged,
    mcp_tool_call,
    mcp_tool_call_allowed,
    mcp_tool_call_denied,
    mcp_tool_call_approval_requested,
    mcp_resources_list,
    mcp_resource_read,
    mcp_prompts_list,
    mcp_prompt_get,
    mcp_sampling_request,
    mcp_unknown_method,
    secret_redacted,
    phantom_swap,
    phantom_denied,
    user_approval,
    user_denial,
    /// The evidence plane itself degraded (e.g. in-shim audit dark under the
    /// control-root write-deny residual). Emitted by the parent at session end;
    /// never carries command payloads — reason codes only.
    audit_degraded,

    pub fn toString(self: EventType) []const u8 {
        return switch (self) {
            .extension_event => "extension.event",
            else => @tagName(self),
        };
    }
};

pub const EventId = struct {
    value: [limits.max_event_id_len]u8,
    len: usize,

    pub fn slice(self: *const EventId) []const u8 {
        return self.value[0..self.len];
    }
};

pub const EventHash = struct {
    value: []const u8,
};

pub const RedactionSummary = struct {
    count: u32 = 0,
    labels: []const []const u8 = &.{},
};

pub const EventMetadata = struct {
    decision_source: ?[]const u8 = null,
    event_source: ?[]const u8 = null,
    host: ?[]const u8 = null,
    daemon_status: ?[]const u8 = null,
    pack_id: ?[]const u8 = null,
    severity: ?[]const u8 = null,
    remediation: ?[]const u8 = null,

    pub fn isEmpty(self: EventMetadata) bool {
        return self.decision_source == null and
            self.event_source == null and
            self.host == null and
            self.daemon_status == null and
            self.pack_id == null and
            self.severity == null and
            self.remediation == null;
    }

    pub fn deinit(self: *EventMetadata, allocator: std.mem.Allocator) void {
        if (self.decision_source) |value| allocator.free(value);
        if (self.event_source) |value| allocator.free(value);
        if (self.host) |value| allocator.free(value);
        if (self.daemon_status) |value| allocator.free(value);
        if (self.pack_id) |value| allocator.free(value);
        if (self.severity) |value| allocator.free(value);
        if (self.remediation) |value| allocator.free(value);
        self.* = .{};
    }
};

pub const Event = struct {
    schema_version: u16 = schema_version,
    session_id: session.SessionId,
    event_id: EventId,
    timestamp: time.Timestamp,
    event_type: EventType,
    actor: types.Actor,
    target: types.Target,
    decision: ?decision.Decision = null,
    redactions: RedactionSummary = .{},
    metadata: EventMetadata = .{},
    previous_hash: ?EventHash = null,
    event_hash: ?EventHash = null,
};

pub fn generateEventId(now: time.Timestamp) !EventId {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    var id: EventId = .{
        .value = undefined,
        .len = 0,
    };
    var timestamp_buf: [32]u8 = undefined;
    const timestamp = try now.formatFilenameSafe(&timestamp_buf);
    var suffix_buf: [8]u8 = undefined;
    const suffix = try util.randomHexSuffix(io, &suffix_buf);
    const written = try std.fmt.bufPrint(&id.value, "evt_{s}_{s}", .{ timestamp, suffix });
    id.len = written.len;
    return id;
}

test "event type string conversion works" {
    try std.testing.expectEqualStrings("session_start", EventType.session_start.toString());
    try std.testing.expectEqualStrings("mcp_sampling_request", EventType.mcp_sampling_request.toString());
}

test "sandbox_posture and os_fs_deny event types serialize" {
    try std.testing.expectEqualStrings("sandbox_posture", EventType.sandbox_posture.toString());
    try std.testing.expectEqualStrings("os_fs_deny", EventType.os_fs_deny.toString());
    // Ordinary file denials are distinct from reserved os_fs_deny.
    try std.testing.expectEqualStrings("file_read_denied", EventType.file_read_denied.toString());
    try std.testing.expectEqualStrings("file_write_denied", EventType.file_write_denied.toString());
}

test "event ids and model can be created deterministically enough for core tests" {
    const ts = time.Timestamp.fromUnixSeconds(1_777_983_130);
    const sid = try session.generateSessionId(ts);
    const eid = try generateEventId(ts);

    try std.testing.expect(std.mem.startsWith(u8, eid.slice(), "evt_2026-05-05T12-12-10Z_"));

    const ev: Event = .{
        .session_id = sid,
        .event_id = eid,
        .timestamp = ts,
        .event_type = .command_attempt,
        .actor = .{ .kind = .agent, .id = "agent-1" },
        .target = .{ .kind = .command, .value = "zig build" },
        .decision = .{
            .result = .observe,
            .reason = "phase 03 model only",
            .ci_may_proceed = true,
        },
    };

    try std.testing.expectEqual(schema_version, ev.schema_version);
    try std.testing.expectEqual(EventType.command_attempt, ev.event_type);
    try std.testing.expectEqual(types.TargetKind.command, ev.target.kind);
}

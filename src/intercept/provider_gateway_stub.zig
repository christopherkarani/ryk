//! Slim stand-in for `provider_gateway.zig` when `-Dhttp=false`.
//! No `std.http` / TLS. Production `ryk run` fail-closes if a provider
//! secret would have required the real gateway.

const std = @import("std");
const session_secrets = @import("session_secrets.zig");

pub const Provider = session_secrets.Provider;

pub const Limits = struct {
    request_head: usize = 32 * 1024,
    request_body: usize = 32 * 1024 * 1024,
    response_head: usize = 32 * 1024,
    response_body: usize = 64 * 1024 * 1024,
    io_timeout_ms: u32 = 5_000,
    upstream_timeout_ms: u32 = 30_000,
};

pub const AuditKind = enum { phantom_swap, phantom_denied };
pub const AuditEvent = struct {
    kind: AuditKind,
    provider: Provider,
    env_var: []const u8,
    reason_code: []const u8,
};

pub const Runtime = struct {
    pub fn bindUrl(_: Runtime) []const u8 {
        return "";
    }
    pub fn bindPort(_: Runtime) u16 {
        return 0;
    }
    pub fn provider(_: Runtime) Provider {
        return .anthropic;
    }
    pub fn isServing(_: Runtime) bool {
        return false;
    }
    pub fn isHealthy(_: Runtime) bool {
        return false;
    }
    pub fn failed(_: Runtime) bool {
        return false;
    }
    pub fn startServing(_: *Runtime) !void {
        return error.HttpDisabled;
    }
    pub fn waitForIdle(_: Runtime, _: u64) !void {}
    pub fn snapshotAuditEvents(_: Runtime, allocator: std.mem.Allocator) ![]AuditEvent {
        return try allocator.alloc(AuditEvent, 0);
    }
    pub fn freeAuditEvents(_: Runtime, allocator: std.mem.Allocator, events: []AuditEvent) void {
        allocator.free(events);
    }
    pub fn deinit(self: *Runtime) void {
        self.* = undefined;
    }
};

pub fn listen(
    _: std.mem.Allocator,
    _: *const session_secrets.Store,
    _: Provider,
    _: Limits,
) !Runtime {
    return error.HttpDisabled;
}

pub const testing = struct {};

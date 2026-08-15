//! Slim stand-in for `provider_gateway.zig` when `-Dhttp=false`.
//! No `std.http` / TLS. Types come from `provider_gateway_types.zig` so the
//! stub cannot drift from the real Limits/audit contract. Production
//! `ryk run` fail-closes if a provider secret would have required the real
//! gateway (`listen` returns `error.HttpDisabled`).

const std = @import("std");
const session_secrets = @import("session_secrets.zig");
const types = @import("provider_gateway_types.zig");

pub const Provider = types.Provider;
pub const Limits = types.Limits;
pub const AuditKind = types.AuditKind;
pub const AuditEvent = types.AuditEvent;

pub const Runtime = struct {
    pub fn bindUrl(_: Runtime) []const u8 {
        return "";
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

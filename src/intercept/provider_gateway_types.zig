//! Shared provider-gateway surface with no `std.http` / TLS.
//! Real and `-Dhttp=false` stub modules must re-export these types so the
//! CLI can compile against either implementation.

const session_secrets = @import("session_secrets.zig");

pub const Provider = session_secrets.Provider;

pub const Limits = struct {
    request_head: usize = 32 * 1024,
    request_body: usize = 32 * 1024 * 1024,
    response_head: usize = 32 * 1024,
    response_body: usize = 64 * 1024 * 1024,
    // Bounds downstream request framing and body reads.
    io_timeout_ms: u32 = 5_000,
    // Bounds the complete upstream exchange.
    upstream_timeout_ms: u32 = 30_000,
};

pub const AuditKind = enum { phantom_swap, phantom_denied };

pub const AuditEvent = struct {
    kind: AuditKind,
    provider: Provider,
    env_var: []const u8,
    reason_code: []const u8,
};

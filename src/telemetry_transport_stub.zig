//! Slim stand-in for `telemetry_transport.zig` when `-Dhttp=false`.
//! No `std.http.Client` / TLS. Queue + contract code stays; nothing POSTs.

const std = @import("std");

pub fn sendQueued(
    _: std.Io,
    _: *const std.process.Environ.Map,
    _: std.mem.Allocator,
) !void {}

pub fn posthogProxyBypassed(_: *const std.process.Environ.Map) bool {
    return false;
}

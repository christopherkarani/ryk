//! Compile + fail-closed proof for `-Dhttp=false`.
//! Rooted here so `check-http-slim` type-checks the stub against the intercept
//! facade without analyzing `std.http.Client`.

const std = @import("std");
const intercept = @import("intercept/mod.zig");
const transport = @import("telemetry_transport_stub.zig");

test {
    _ = intercept;
    _ = intercept.provider_gateway;
}

test "provider gateway listen fails closed when HTTP is omitted" {
    var store = try intercept.session_secrets.Store.init(std.testing.io, std.testing.allocator);
    defer store.deinit();
    try std.testing.expectError(
        error.HttpDisabled,
        intercept.provider_gateway.listen(std.testing.allocator, &store, .anthropic, .{}),
    );
}

test "telemetry transport is a no-op when HTTP is omitted" {
    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();
    try transport.sendQueued(std.testing.io, &environ_map, std.testing.allocator);
    try std.testing.expect(!transport.posthogProxyBypassed(&environ_map));
}

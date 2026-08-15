const enable_http = @import("build_options").enable_http;

pub const env = @import("env.zig");
pub const env_schema = @import("env_schema.zig");
pub const credentials = @import("credentials.zig");
pub const session_secrets = @import("session_secrets.zig");
pub const files = @import("files.zig");
pub const commands = @import("commands.zig");
pub const network = @import("ryk_core").policy.network_eval;
pub const proxy = @import("proxy.zig");
pub const provider_gateway = if (enable_http)
    @import("provider_gateway.zig")
else
    @import("provider_gateway_stub.zig");
pub const approvals = @import("approvals.zig");

test {
    if (enable_http) {
        _ = @import("provider_gateway_tests.zig");
    }
}

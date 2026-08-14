pub const schema = @import("schema.zig");
pub const load = @import("load.zig");
pub const validate = @import("validate.zig");
pub const compile = @import("compile.zig");
pub const evaluate = @import("evaluate.zig");
pub const explain = @import("explain.zig");
pub const matchers = @import("matchers.zig");
pub const network_eval = @import("network_eval.zig");
pub const presets = @import("presets.zig");
pub const default_migration = @import("default_migration.zig");
pub const effects = @import("effects/mod.zig");
pub const sticky = @import("sticky.zig");
pub const risk_card = @import("risk_card.zig");
pub const agent_inference_hosts = @import("agent_inference_hosts.zig");
pub const inference_hostname = @import("inference_hostname.zig");
pub const inference_discover = @import("inference_discover.zig");
// Surgical monopath attach for AINA P3 managed store (p3-managed).
pub const network_discovered = @import("network_discovered.zig");

test {
    // Re-export policy submodules so monopath / package gates discover their tests
    // (mirrors sandbox/mod.zig discovery pattern).
    _ = schema;
    _ = load;
    _ = validate;
    _ = compile;
    _ = evaluate;
    _ = explain;
    _ = matchers;
    _ = network_eval;
    _ = presets;
    _ = effects;
    _ = sticky;
    _ = risk_card;
    _ = agent_inference_hosts;
    _ = inference_hostname;
    _ = inference_discover;
    _ = network_discovered;
}

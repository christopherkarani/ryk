const engine = @import("core_engine");

pub const api = engine.boundary_api;

/// Full internal module graph — used by CLI, dashboard, intercept, etc.
pub const core = engine.core;
pub const policy = engine.policy;
pub const audit = engine.audit;

pub const errors = engine.core.errors;
pub const decision = engine.core.decision;
pub const limits = engine.core.limits;
pub const platform = engine.core.platform;
pub const session = engine.core.session;
pub const time = engine.core.time;
pub const util = engine.core.util;
pub const types = engine.core.types;
pub const event = engine.core.event;

test {
    _ = api;
    _ = core;
    _ = policy;
    _ = audit;
    _ = errors;
    _ = decision;
    _ = limits;
    _ = platform;
    _ = session;
    _ = time;
    _ = util;
    _ = types;
    _ = event;
}

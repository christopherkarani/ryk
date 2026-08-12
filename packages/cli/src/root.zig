const ryk = @import("ryk");
const ryk_core = @import("ryk_core");

pub const cli = ryk.cli;
pub const desktop = struct {
    pub const intercept = ryk.intercept;
    pub const mcp = ryk.mcp;
    pub const sandbox = ryk.sandbox;
};
pub const core = ryk_core;

test {
    _ = cli;
    _ = desktop;
    _ = core;
}

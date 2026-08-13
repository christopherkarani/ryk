pub const fixtures = @import("fixtures.zig");
pub const runner = @import("runner.zig");
pub const scorecard = @import("scorecard.zig");
pub const reports = @import("reports.zig");

pub const phase = "13-redteam-benchmark-suite";
pub const implemented = true;

test {
    _ = reports;
}

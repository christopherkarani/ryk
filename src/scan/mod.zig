//! Session forensics scan library (public `ryk scan`).
const std = @import("std");
const enable_tui = @import("build_options").enable_tui;

pub const types = @import("types.zig");
pub const time_window = @import("time_window.zig");
pub const secrets = @import("secrets.zig");
pub const danger = @import("danger.zig");
pub const rank = @import("rank.zig");
pub const paths = @import("paths.zig");
pub const extract = @import("extract.zig");
pub const jsonl = @import("jsonl.zig");
pub const opencode_db = @import("opencode_db.zig");
pub const discover = @import("discover.zig");
pub const engine = @import("engine.zig");
pub const render = @import("render.zig");
pub const risk = @import("risk.zig");
pub const present = @import("present.zig");
pub const tui_view = if (enable_tui) @import("tui_view.zig") else struct {
    pub fn run(io: std.Io, stdout: anytype, result: anytype) !void {
        _ = .{ io, stdout, result };
        return error.TuiDisabled;
    }
};
pub const os_actions = @import("os_actions.zig");

pub const Finding = types.Finding;
pub const ScanResult = types.ScanResult;
pub const ScanOptions = engine.ScanOptions;
pub const runScan = engine.runScan;
pub const writeHuman = render.writeHuman;
pub const writeJson = render.writeJson;

test {
    _ = types;
    _ = time_window;
    _ = secrets;
    _ = danger;
    _ = rank;
    _ = paths;
    _ = extract;
    _ = jsonl;
    _ = opencode_db;
    _ = discover;
    _ = engine;
    _ = render;
    _ = risk;
    _ = present;
    if (enable_tui) {
        _ = @import("tui_view.zig");
    }
    _ = os_actions;
}

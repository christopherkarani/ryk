/// Slim TUI facade: linear rich output only. No libvaxis / uucode.
///
/// Selected by `if (enable_tui) @import("tui/mod.zig") else @import("tui/linear.zig")`.
/// Interactive modules (`live_view`, `browse`, raw-TTY `prompt`) stay on the
/// full facade so `-Dtui=false` never analyzes them.
pub const theme = @import("theme.zig");
pub const render = @import("render.zig");
pub const prompt = @import("prompt.zig");
pub const spinner = @import("spinner.zig");
pub const output_policy = @import("output_policy.zig");
pub const terminal_text = @import("terminal_text.zig");
pub const reasons = @import("reasons.zig");
pub const sandbox_card = @import("sandbox_card.zig");

test {
    _ = theme;
    _ = render;
    _ = prompt;
    _ = spinner;
    _ = output_policy;
    _ = terminal_text;
    _ = reasons;
    _ = sandbox_card;
}

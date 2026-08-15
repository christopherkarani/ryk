/// Full TUI facade (libvaxis). Slim builds import `linear.zig` instead.
///
/// ryk CLI design system and rich-output rendering (`tui`).
///
/// - `theme` — palette, color-capability detection, semantic tokens.
/// - `render` — linear rich-output primitives (panel, table, badge, meter, …).
/// - `prompt` — libvaxis-backed interactive widgets (select, multiSelect).
/// - `spinner` — libvaxis-aware spinner.
/// - `reasons` — human-readable policy reason + safe-alternative helpers.
/// - `live_view` — optional alt-screen viewer (`history --live` / `replay --tui`).
/// - `browse` — shared list/detail/footer/filter chassis (packs/allowlist/doctor).
/// - `sandbox_card` — memorable session-start OS sandbox shield card.
pub const theme = @import("theme.zig");
pub const render = @import("render.zig");
pub const prompt = @import("prompt.zig");
pub const spinner = @import("spinner.zig");
pub const output_policy = @import("output_policy.zig");
pub const terminal_text = @import("terminal_text.zig");
pub const reasons = @import("reasons.zig");
pub const live_view = @import("live_view.zig");
pub const browse = @import("browse.zig");
pub const sandbox_card = @import("sandbox_card.zig");

test {
    _ = theme;
    _ = render;
    _ = prompt;
    _ = spinner;
    _ = output_policy;
    _ = terminal_text;
    _ = reasons;
    _ = live_view;
    _ = browse;
    _ = sandbox_card;
}

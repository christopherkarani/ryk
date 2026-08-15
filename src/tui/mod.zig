/// Single TUI facade. `-Dtui=false` keeps linear output and stream prompts;
/// `live_view` / `browse` stay off that graph so vaxis is never analyzed.
///
/// - `theme` — palette, color-capability detection, semantic tokens.
/// - `render` — linear rich-output primitives (panel, table, badge, meter, …).
/// - `prompt` — stream-injected confirm/select; raw TTY only when `-Dtui` is on.
/// - `spinner` — DEC synchronized-output spinner (`ctlseqs`).
/// - `reasons` — human-readable policy reason + safe-alternative helpers.
/// - `live_view` — alt-screen viewer (`history --live` / `replay --tui`); TUI-on only.
/// - `browse` — list/detail/footer/filter chassis; TUI-on only.
/// - `sandbox_card` — memorable session-start OS sandbox shield card.
const enable_tui = @import("build_options").enable_tui;

pub const theme = @import("theme.zig");
pub const render = @import("render.zig");
pub const prompt = @import("prompt.zig");
pub const spinner = @import("spinner.zig");
pub const output_policy = @import("output_policy.zig");
pub const terminal_text = @import("terminal_text.zig");
pub const reasons = @import("reasons.zig");
pub const live_view = if (enable_tui) @import("live_view.zig") else struct {};
pub const browse = if (enable_tui) @import("browse.zig") else struct {};
pub const sandbox_card = @import("sandbox_card.zig");

test {
    _ = theme;
    _ = render;
    _ = spinner;
    _ = output_policy;
    _ = terminal_text;
    _ = reasons;
    _ = sandbox_card;
    // RawDecoder / live_view / browse need vaxis. Pull them only on the TUI-on monopath.
    if (enable_tui) {
        _ = prompt;
        _ = live_view;
        _ = browse;
    }
}

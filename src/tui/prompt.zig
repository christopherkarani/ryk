/// libvaxis-backed interactive widgets: `select` (single choice) and
/// `multiSelect` (checkbox list).
///
/// Architecture (plan §3.1 hybrid — see planning/handoffs/cli-ux-phase3-to-phase4.md):
/// - `selectCore` / `multiSelectCore` are **stream-injected and fully unit-testable**.
///   They render the list with a `›` focus cursor (+ descriptions / `[x]`/`[ ]`
///   checkboxes) via the existing `tui.render`/`theme` layer (inline, pipe-friendly)
///   and consume a `KeyAction` stream from an injected `*std.Io.Reader`.
/// - `select` / `multiSelect` are the public entry points. On a real TTY they open
///   `/dev/tty` in raw mode via libvaxis `Tty`, parse key events with the libvaxis
///   `Parser`, map up/down/enter/space/escape → `KeyAction`, and re-render inline.
///   On non-TTY, on any libvaxis/Tty failure, or when an injected reader is supplied
///   (tests), they fall back to the stream-injected core.
///
/// This keeps the interactive *logic* and *rendering* unit-testable with fixed
/// buffers (matching the `interactive.zig` / `approvals.zig` test style) while
/// libvaxis owns raw-mode TTY I/O + key parsing on real terminals. Colour paths
/// are unverifiable under `builtin.is_test` (`theme.active()` returns `.none`);
/// the TTY/libvaxis path is verified manually via subprocess, per the established
/// Phase 0–2 discipline.
const std = @import("std");
const builtin = @import("builtin");
const theme = @import("theme.zig");
const render = @import("render.zig");
const enable_tui = @import("build_options").enable_tui;

const vaxis = if (enable_tui) @import("vaxis") else struct {};

// ────────────────────────────────────────────────────────────────────────────
// Key action — the logical input both cores consume
// ────────────────────────────────────────────────────────────────────────────

pub const KeyAction = enum {
    up,
    down,
    enter, // confirm / select focused
    space, // toggle (multiSelect only)
    escape, // cancel → safe default
    quit, // alias for escape
    letter_y,
    letter_e,
    letter_s,
    other, // ignored
};

/// Map a single injected input line to a `KeyAction`. The test/simulated-TTY
/// protocol (one logical key per line):
///   `up`/`u`/`k`        → up
///   `down`/`d`/`j`      → down
///   `enter`/`return`/`` → enter  (empty line = confirm, the common default)
///   `space`/`toggle`    → space
///   `esc`/`escape`/`q`/`quit` → escape
/// Anything else → other.
/// End-of-stream → escape (safe default: never block a non-interactive caller).
pub fn parseKeyActionLine(raw: []const u8) KeyAction {
    const input = std.mem.trim(u8, raw, " \t\r\n");
    if (input.len == 0) return .enter;
    if (std.mem.eql(u8, input, "up") or std.mem.eql(u8, input, "u") or std.mem.eql(u8, input, "k")) return .up;
    if (std.mem.eql(u8, input, "down") or std.mem.eql(u8, input, "d") or std.mem.eql(u8, input, "j")) return .down;
    if (std.mem.eql(u8, input, "enter") or std.mem.eql(u8, input, "return")) return .enter;
    if (std.mem.eql(u8, input, "space") or std.mem.eql(u8, input, "toggle")) return .space;
    if (std.mem.eql(u8, input, "esc") or std.mem.eql(u8, input, "escape") or
        std.mem.eql(u8, input, "q") or std.mem.eql(u8, input, "quit"))
    {
        return .escape;
    }
    return .other;
}

/// Read one `KeyAction` from an injected reader (one line). EOF → escape.
fn readKeyAction(reader: *std.Io.Reader) !KeyAction {
    const raw = reader.takeDelimiterExclusive('\n') catch |err| switch (err) {
        error.EndOfStream => return .escape,
        else => return err,
    };
    reader.toss(1); // Zig 0.16.0 std.Io.Reader takeDelimiterExclusive bug: leaves delimiter in stream
    return parseKeyActionLine(raw);
}

// ────────────────────────────────────────────────────────────────────────────
// Selection option
// ────────────────────────────────────────────────────────────────────────────

pub const SelectionOption = struct {
    label: []const u8,
    /// Short description shown beside/under the label (select only).
    description: []const u8 = "",
    /// Stable identifier (e.g. "codex"). Falls back to label when null.
    id: ?[]const u8 = null,
    /// Checked state (multiSelect only).
    checked: bool = false,
};

pub const ConfirmKind = enum { normal, danger };

/// Stream-injected confirm core. Destructive actions are deny-by-default and
/// require an explicit `yes`; normal confirms accept `y` or `yes`.
pub fn confirmCore(io: std.Io, stdout: anytype, reader: *std.Io.Reader, kind: ConfirmKind, message: []const u8) !bool {
    try stdout.writeAll("  ");
    try theme.paintBold(io, stdout, if (kind == .danger) .danger else .brand, message);
    try stdout.writeAll(if (kind == .danger) " Type 'yes' to confirm: " else " [y/N] ");
    const raw = reader.takeDelimiterExclusive('\n') catch |err| switch (err) {
        error.EndOfStream => return false,
        else => return err,
    };
    const answer = std.mem.trim(u8, raw, " \t\r");
    return std.ascii.eqlIgnoreCase(answer, "yes") or
        (kind == .normal and std.ascii.eqlIgnoreCase(answer, "y"));
}

/// Public confirm API. Callers may inject a reader for tests; production reads
/// stdin and safely returns false on EOF/non-interactive input.
pub fn confirm(io: std.Io, stdout: anytype, kind: ConfirmKind, message: []const u8, injected_reader: ?*std.Io.Reader) !bool {
    if (injected_reader) |reader| return confirmCore(io, stdout, reader, kind, message);
    if (!ttyAvailable(io)) return false;
    if (comptime enable_tui and !builtin.is_test) return confirmRaw(io, stdout, kind, message) catch false;
    return false;
}

fn confirmRaw(io: std.Io, stdout: anytype, kind: ConfirmKind, message: []const u8) !bool {
    try flushIfSupported(stdout);
    var tty_buf: [4096]u8 = undefined;
    var tty = vaxis.tty.Tty.init(io, &tty_buf) catch return error.TtyUnavailable;
    defer tty.deinit();
    var decoder: RawDecoder = .{};
    var answer: [3]u8 = undefined;
    var len: usize = 0;
    try stdout.writeAll("  ");
    try theme.paintBold(io, stdout, if (kind == .danger) .danger else .brand, message);
    try stdout.writeAll(if (kind == .danger) " Type 'yes' to confirm: " else " [y/N] ");
    try flushIfSupported(stdout);
    while (true) switch (try readRawAction(&tty, &decoder)) {
        .enter => return if (kind == .danger) std.mem.eql(u8, answer[0..len], "yes") else len > 0 and answer[0] == 'y',
        .escape, .quit => return false,
        .letter_y => if (len < answer.len) {
            answer[len] = 'y';
            len += 1;
        },
        .letter_e => if (len < answer.len) {
            answer[len] = 'e';
            len += 1;
        },
        .letter_s => if (len < answer.len) {
            answer[len] = 's';
            len += 1;
        },
        else => {},
    };
}

// ────────────────────────────────────────────────────────────────────────────
// selectCore — single-choice list, stream-injected, unit-testable
// ────────────────────────────────────────────────────────────────────────────

/// Render and drive a single-choice list. Returns the selected index, or `null`
/// if the user cancelled (escape / EOF). `default_index` is the initial focus
/// and the safe default returned on cancel when in range.
///
/// Rendering (per frame): a header line, then one line per option with a `›`
/// focus cursor on the focused item and the label + muted description. On a
/// colour-capable TTY, re-renders overwrite the previous frame in place (cursor
/// up + clear); on plain/piped/test output, frames are appended (escapes would
/// be harmless but are suppressed for clean test buffers).
pub fn selectCore(
    io: std.Io,
    stdout: anytype,
    options: []const SelectionOption,
    reader: *std.Io.Reader,
    default_index: usize,
    header: []const u8,
) !?usize {
    if (options.len == 0) return null;
    var focus = if (default_index < options.len) default_index else 0;

    const can_move_cursor = theme.active(io, stdout).capability.hasColor();
    var first_frame = true;
    var frame_lines: usize = 0;

    while (true) {
        // Move cursor back to the top of the previous frame (TTY only).
        if (can_move_cursor and !first_frame and frame_lines > 0) {
            try moveCursorUp(stdout, frame_lines);
            try stdout.writeAll("\x1b[J"); // clear to end of screen
        }
        first_frame = false;

        frame_lines = 0;
        if (header.len > 0) {
            try stdout.writeAll("  ");
            try theme.paintBold(io, stdout, .text_bright, header);
            try stdout.writeAll("\n");
            frame_lines += 1;
        }

        for (options, 0..) |opt, i| {
            const focused = i == focus;
            try stdout.writeAll("  ");
            if (focused) {
                try theme.paintBold(io, stdout, .brand, "›");
            } else {
                try stdout.writeAll(" ");
            }
            try stdout.writeAll(" ");
            if (focused) {
                try theme.paintBold(io, stdout, .text_bright, opt.label);
            } else {
                try theme.paint(io, stdout, .text, opt.label);
            }
            if (opt.description.len > 0) {
                try stdout.writeAll("  ");
                try theme.paint(io, stdout, .muted, opt.description);
            }
            try stdout.writeAll("\n");
            frame_lines += 1;
        }
        try stdout.writeAll("  ");
        try theme.paint(io, stdout, .muted, "↑↓ navigate · Enter select · Esc cancel");
        try stdout.writeAll("\n");
        frame_lines += 1;
        try flushIfSupported(stdout);

        const action = try readKeyAction(reader);
        switch (action) {
            .up => {
                if (focus > 0) focus -= 1;
            },
            .down => {
                if (focus + 1 < options.len) focus += 1;
            },
            .enter => return focus,
            .escape, .quit => return if (default_index < options.len) default_index else null,
            .space, .letter_y, .letter_e, .letter_s, .other => {},
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// multiSelectCore — checkbox list, stream-injected, unit-testable
// ────────────────────────────────────────────────────────────────────────────

/// Render and drive a checkbox list. Space toggles the focused item; Enter
/// confirms (returns true); Esc/EOF cancels (returns false, leaving `options`
/// in their current/default state — the safe default). Mutates `options[].checked`
/// in place. `focus` starts at 0.
pub fn multiSelectCore(
    io: std.Io,
    stdout: anytype,
    options: []SelectionOption,
    reader: *std.Io.Reader,
    header: []const u8,
) !bool {
    if (options.len == 0) return true;
    var focus: usize = 0;

    const can_move_cursor = theme.active(io, stdout).capability.hasColor();
    var first_frame = true;
    var frame_lines: usize = 0;

    while (true) {
        if (can_move_cursor and !first_frame and frame_lines > 0) {
            try moveCursorUp(stdout, frame_lines);
            try stdout.writeAll("\x1b[J");
        }
        first_frame = false;

        frame_lines = 0;
        if (header.len > 0) {
            try stdout.writeAll("  ");
            try theme.paintBold(io, stdout, .text_bright, header);
            try stdout.writeAll("\n");
            frame_lines += 1;
        }

        for (options, 0..) |opt, i| {
            const focused = i == focus;
            const box = if (opt.checked) "[x]" else "[ ]";
            try stdout.writeAll("  ");
            if (focused) {
                try theme.paintBold(io, stdout, .brand, "›");
            } else {
                try stdout.writeAll(" ");
            }
            try stdout.writeAll(" ");
            try theme.paint(io, stdout, if (opt.checked) .success else .muted, box);
            try stdout.writeAll(" ");
            if (focused) {
                try theme.paintBold(io, stdout, .text_bright, opt.label);
            } else {
                try theme.paint(io, stdout, .text, opt.label);
            }
            try stdout.writeAll("\n");
            frame_lines += 1;
        }
        try stdout.writeAll("  ");
        try theme.paint(io, stdout, .muted, "↑↓ navigate · Space toggle · Enter confirm · Esc cancel");
        try stdout.writeAll("\n");
        frame_lines += 1;
        try flushIfSupported(stdout);

        const action = try readKeyAction(reader);
        switch (action) {
            .up => {
                if (focus > 0) focus -= 1;
            },
            .down => {
                if (focus + 1 < options.len) focus += 1;
            },
            .space => {
                options[focus].checked = !options[focus].checked;
            },
            .enter => return true,
            .escape, .quit => return false,
            .letter_y, .letter_e, .letter_s, .other => {},
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Public entry points — libvaxis on TTY, core fallback otherwise
// ────────────────────────────────────────────────────────────────────────────

/// Single-choice select. On a real TTY (and no injected reader), opens
/// `/dev/tty` via libvaxis `Tty`, parses keys with the libvaxis `Parser`, and
/// drives an inline re-rendering loop. Otherwise uses `selectCore` with the
/// supplied reader (tests) or real stdin (non-TTY). Returns the selected index
/// or `null` on cancel. NEVER blocks on EOF — returns the safe default.
pub fn select(
    io: std.Io,
    allocator: std.mem.Allocator,
    stdout: anytype,
    options: []const SelectionOption,
    default_index: usize,
    header: []const u8,
    injected_reader: ?*std.Io.Reader,
) !?usize {
    if (injected_reader) |r| {
        return selectCore(io, stdout, options, r, default_index, header);
    }
    // The libvaxis raw-mode path opens /dev/tty and is unavailable under
    // `builtin.is_test` (vaxis.tty.Tty is a stub there). Gate it out at comptime
    // so the raw functions are never semantically analyzed in test builds; on
    // Tty initialization failure falls back to the stream-injected core. Once
    // a raw frame is visible, errors propagate instead of changing protocols
    // or manufacturing an unconfirmed selection.
    if (comptime enable_tui and !builtin.is_test) {
        if (ttyAvailable(io)) {
            if (selectRaw(io, allocator, stdout, options, default_index, header)) |idx| {
                return idx;
            } else |err| switch (err) {
                error.TtyUnavailable => {}, // Fall back before any raw frame was rendered.
                else => return err,
            }
        }
    }
    return selectCoreWithStdin(io, stdout, options, default_index, header);
}

/// Checkbox multi-select. Same TTY/fallback policy as `select`. Returns `true`
/// if the user confirmed, `false` if they cancelled (options keep their current
/// state — the safe default). On non-TTY/EOF returns `true` with defaults.
pub fn multiSelect(
    io: std.Io,
    allocator: std.mem.Allocator,
    stdout: anytype,
    options: []SelectionOption,
    header: []const u8,
    injected_reader: ?*std.Io.Reader,
) !bool {
    if (injected_reader) |r| {
        return multiSelectCore(io, stdout, options, r, header);
    }
    if (comptime enable_tui and !builtin.is_test) {
        if (ttyAvailable(io)) {
            if (multiSelectRaw(io, allocator, stdout, options, header)) |ok| {
                return ok;
            } else |err| switch (err) {
                error.TtyUnavailable => {}, // Fall back before any raw frame was rendered.
                else => return err,
            }
        }
    }
    return multiSelectCoreWithStdin(io, stdout, options, header);
}

// ────────────────────────────────────────────────────────────────────────────
// libvaxis raw-mode TTY path
// ────────────────────────────────────────────────────────────────────────────

/// True when both stdin and stdout are TTYs (mirrors onboarding.interactiveSetupDesired).
fn ttyAvailable(io: std.Io) bool {
    const sin = std.Io.File.stdin().isTty(io) catch false;
    const sout = std.Io.File.stdout().isTty(io) catch false;
    return sin and sout;
}

/// Map a libvaxis `Key` codepoint to a `KeyAction`.
fn keyToAction(key: vaxis.Key) KeyAction {
    if (key.matches(vaxis.Key.enter, .{})) return .enter;
    if (key.matches(vaxis.Key.escape, .{})) return .escape;
    if (key.matches(vaxis.Key.space, .{})) return .space;
    if (key.matches(vaxis.Key.up, .{})) return .up;
    if (key.matches(vaxis.Key.down, .{})) return .down;
    // vim-style & common letters (no modifier requirement for accessibility).
    if (key.matches('k', .{})) return .up;
    if (key.matches('j', .{})) return .down;
    if (key.matches('q', .{})) return .quit;
    if (key.matches('y', .{})) return .letter_y;
    if (key.matches('e', .{})) return .letter_e;
    if (key.matches('s', .{})) return .letter_s;
    return .other;
}

/// A small bridge that lets the raw TTY loop drive the same core renderers by
/// feeding parsed key actions into a pipe-backed reader.
fn selectRaw(
    io: std.Io,
    allocator: std.mem.Allocator,
    stdout: anytype,
    options: []const SelectionOption,
    default_index: usize,
    header: []const u8,
) !?usize {
    try flushIfSupported(stdout);
    var tty_buf: [4096]u8 = undefined;
    var tty = vaxis.tty.Tty.init(io, &tty_buf) catch return error.TtyUnavailable;
    defer tty.deinit();

    var decoder: RawDecoder = .{};
    var focus = if (default_index < options.len) default_index else 0;
    const max_width = terminalColumns(&tty);
    var first_frame = true;
    var frame_lines: usize = 0;

    while (true) {
        if (!first_frame and frame_lines > 0) {
            try moveCursorUp(stdout, frame_lines);
            try stdout.writeAll("\x1b[J");
        }
        first_frame = false;
        frame_lines = try renderSelectFrame(io, stdout, options, focus, header, max_width);
        try flushIfSupported(stdout);

        const action = try readRawAction(&tty, &decoder);
        switch (action) {
            .up => if (focus > 0) {
                focus -= 1;
            },
            .down => if (focus + 1 < options.len) {
                focus += 1;
            },
            .enter => {
                try stdout.writeAll("\r\n");
                return focus;
            },
            .escape, .quit => {
                try stdout.writeAll("\r\n");
                _ = allocator;
                return if (default_index < options.len) default_index else null;
            },
            .space, .letter_y, .letter_e, .letter_s, .other => {},
        }
    }
}

fn multiSelectRaw(
    io: std.Io,
    allocator: std.mem.Allocator,
    stdout: anytype,
    options: []SelectionOption,
    header: []const u8,
) !bool {
    _ = allocator;
    try flushIfSupported(stdout);
    var tty_buf: [4096]u8 = undefined;
    var tty = vaxis.tty.Tty.init(io, &tty_buf) catch return error.TtyUnavailable;
    defer tty.deinit();

    var decoder: RawDecoder = .{};
    var focus: usize = 0;
    const max_width = terminalColumns(&tty);
    var first_frame = true;
    var frame_lines: usize = 0;

    while (true) {
        if (!first_frame and frame_lines > 0) {
            try moveCursorUp(stdout, frame_lines);
            try stdout.writeAll("\x1b[J");
        }
        first_frame = false;
        frame_lines = try renderMultiSelectFrame(io, stdout, options, focus, header, max_width);
        try flushIfSupported(stdout);

        const action = try readRawAction(&tty, &decoder);
        switch (action) {
            .up => if (focus > 0) {
                focus -= 1;
            },
            .down => if (focus + 1 < options.len) {
                focus += 1;
            },
            .space => {
                options[focus].checked = !options[focus].checked;
            },
            .enter => {
                try stdout.writeAll("\r\n");
                return true;
            },
            .escape, .quit => {
                try stdout.writeAll("\r\n");
                return false;
            },
            .letter_y, .letter_e, .letter_s, .other => {},
        }
    }
}

const RawDecoder = struct {
    parser: vaxis.Parser = .{},
    carry: [256]u8 = undefined,
    len: usize = 0,

    fn feed(self: *RawDecoder, bytes: []const u8) !?KeyAction {
        if (bytes.len > self.carry.len - self.len) return error.InputTooLong;
        @memcpy(self.carry[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
        // A bare ESC may be the first fragment of CSI/SS3. Keep it until the
        // next read instead of letting libvaxis prematurely classify it.
        if (self.len == 1 and self.carry[0] == 0x1b) return null;
        var consumed: usize = 0;
        while (consumed < self.len) {
            const res = try self.parser.parse(self.carry[consumed..self.len], null);
            if (res.n == 0) break;
            consumed += res.n;
            if (res.event) |event| switch (event) {
                .key_press => |key| {
                    const action = keyToAction(key);
                    std.mem.copyForwards(u8, self.carry[0 .. self.len - consumed], self.carry[consumed..self.len]);
                    self.len -= consumed;
                    return action;
                },
                else => {},
            };
        }
        if (consumed > 0) {
            std.mem.copyForwards(u8, self.carry[0 .. self.len - consumed], self.carry[consumed..self.len]);
            self.len -= consumed;
        }
        return null;
    }

    fn interByteTimeout(self: *RawDecoder) ?KeyAction {
        if (self.len == 1 and self.carry[0] == 0x1b) {
            self.len = 0;
            return .escape;
        }
        return null;
    }
};

/// Read bytes from the raw TTY and parse one complete key event into a `KeyAction`.
fn readRawAction(tty: *vaxis.tty.Tty, decoder: *RawDecoder) !KeyAction {
    if (comptime builtin.os.tag == .windows) {
        while (true) switch (try tty.nextEvent(&decoder.parser, null)) {
            .key_press => |key| return keyToAction(key),
            else => {},
        };
    }
    configureInterByteTimeout(tty);
    var buf: [256]u8 = undefined;
    while (true) {
        // libvaxis routes `Tty.read` through Zig's streaming file API, where a
        // POSIX VMIN=0/VTIME timeout is translated from read(2)'s zero return
        // into error.EndOfStream. Read the descriptor directly so an idle
        // timeout remains distinguishable from a failed raw session.
        const n = std.posix.read(tty.fd.handle, &buf) catch |err| switch (err) {
            error.WouldBlock => 0,
            else => return err,
        };
        if (n == 0) {
            if (decoder.interByteTimeout()) |action| return action;
            continue;
        }
        if (try decoder.feed(buf[0..n])) |action| return action;
    }
}

fn configureInterByteTimeout(tty: *vaxis.tty.Tty) void {
    if (comptime builtin.os.tag == .windows) return;
    if (builtin.is_test) return;
    var raw = std.posix.tcgetattr(tty.fd.handle) catch return;
    raw.cc[@intFromEnum(std.posix.V.MIN)] = 0;
    raw.cc[@intFromEnum(std.posix.V.TIME)] = 1; // 100 ms inter-byte timeout
    std.posix.tcsetattr(tty.fd.handle, .NOW, raw) catch {};
}

fn terminalColumns(tty: *vaxis.tty.Tty) usize {
    const size = tty.getWinsize() catch return 80;
    return if (size.cols >= 24) size.cols else 80;
}

// ────────────────────────────────────────────────────────────────────────────
// Frame renderers (shared by raw + core paths)
// ────────────────────────────────────────────────────────────────────────────

fn renderSelectFrame(
    io: std.Io,
    stdout: anytype,
    options: []const SelectionOption,
    focus: usize,
    header: []const u8,
    max_width: usize,
) !usize {
    var lines: usize = 0;
    if (header.len > 0) {
        try stdout.writeAll("  ");
        try paintTruncated(io, stdout, .text_bright, true, header, max_width -| 2);
        try stdout.writeAll("\r\n");
        lines += 1;
    }
    for (options, 0..) |opt, i| {
        const focused = i == focus;
        try stdout.writeAll("  ");
        if (focused) {
            try theme.paintBold(io, stdout, .brand, "›");
        } else {
            try stdout.writeAll(" ");
        }
        try stdout.writeAll(" ");
        if (focused) {
            try paintTruncated(io, stdout, .text_bright, true, opt.label, max_width -| 4);
        } else {
            try paintTruncated(io, stdout, .text, false, opt.label, max_width -| 4);
        }
        const option_width = 4 + render.displayWidth(opt.label);
        if (opt.description.len > 0 and option_width + 2 + render.displayWidth(opt.description) <= max_width) {
            try stdout.writeAll("  ");
            try theme.paint(io, stdout, .muted, opt.description);
        }
        try stdout.writeAll("\r\n");
        lines += 1;
    }
    try stdout.writeAll("  ");
    try theme.paint(io, stdout, .muted, if (max_width >= 48) "↑↓ navigate · Enter select · Esc cancel" else "↑↓ · Enter · Esc");
    try stdout.writeAll("\r\n");
    lines += 1;
    return lines;
}

fn renderMultiSelectFrame(
    io: std.Io,
    stdout: anytype,
    options: []const SelectionOption,
    focus: usize,
    header: []const u8,
    max_width: usize,
) !usize {
    var lines: usize = 0;
    if (header.len > 0) {
        try stdout.writeAll("  ");
        try paintTruncated(io, stdout, .text_bright, true, header, max_width -| 2);
        try stdout.writeAll("\r\n");
        lines += 1;
    }
    for (options, 0..) |opt, i| {
        const focused = i == focus;
        const box = if (opt.checked) "[x]" else "[ ]";
        try stdout.writeAll("  ");
        if (focused) {
            try theme.paintBold(io, stdout, .brand, "›");
        } else {
            try stdout.writeAll(" ");
        }
        try stdout.writeAll(" ");
        try theme.paint(io, stdout, if (opt.checked) .success else .muted, box);
        try stdout.writeAll(" ");
        if (focused) {
            try paintTruncated(io, stdout, .text_bright, true, opt.label, max_width -| 8);
        } else {
            try paintTruncated(io, stdout, .text, false, opt.label, max_width -| 8);
        }
        try stdout.writeAll("\r\n");
        lines += 1;
    }
    try stdout.writeAll("  ");
    try theme.paint(io, stdout, .muted, if (max_width >= 64) "↑↓ navigate · Space toggle · Enter confirm · Esc cancel" else "↑↓ · Space · Enter · Esc");
    try stdout.writeAll("\r\n");
    lines += 1;
    return lines;
}

// ────────────────────────────────────────────────────────────────────────────
// stdin fallback wrappers
// ────────────────────────────────────────────────────────────────────────────

fn selectCoreWithStdin(io: std.Io, stdout: anytype, options: []const SelectionOption, default_index: usize, header: []const u8) !?usize {
    const stdin = std.Io.File.stdin();
    var rbuf: [256]u8 = undefined;
    var reader = stdin.reader(io, &rbuf);
    return selectCore(io, stdout, options, &reader.interface, default_index, header);
}

fn multiSelectCoreWithStdin(io: std.Io, stdout: anytype, options: []SelectionOption, header: []const u8) !bool {
    const stdin = std.Io.File.stdin();
    var rbuf: [256]u8 = undefined;
    var reader = stdin.reader(io, &rbuf);
    return multiSelectCore(io, stdout, options, &reader.interface, header);
}

// ────────────────────────────────────────────────────────────────────────────
// Small output helpers
// ────────────────────────────────────────────────────────────────────────────

fn moveCursorUp(stdout: anytype, n: usize) !void {
    if (n == 0) return;
    var buf: [16]u8 = undefined;
    const seq = std.fmt.bufPrint(&buf, "\r\x1b[{d}A\r", .{n}) catch return;
    try stdout.writeAll(seq);
}

fn paintTruncated(io: std.Io, stdout: anytype, token: theme.Token, bold: bool, text: []const u8, width: usize) !void {
    if (render.displayWidth(text) > width) return render.writeTruncated(stdout, text, width);
    if (bold) return theme.paintBold(io, stdout, token, text);
    return theme.paint(io, stdout, token, text);
}

fn flushIfSupported(writer: anytype) !void {
    const Writer = @TypeOf(writer);
    switch (@typeInfo(Writer)) {
        .pointer => |pointer| {
            if (@hasDecl(pointer.child, "flush")) try writer.flush();
        },
        else => {
            if (@hasDecl(Writer, "flush")) try writer.flush();
        },
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Tests (TDD — written first, fixed-buffer injected streams)
// ────────────────────────────────────────────────────────────────────────────

test "parseKeyActionLine maps common tokens" {
    try std.testing.expectEqual(KeyAction.up, parseKeyActionLine("up"));
    try std.testing.expectEqual(KeyAction.up, parseKeyActionLine("k"));
    try std.testing.expectEqual(KeyAction.down, parseKeyActionLine("j"));
    try std.testing.expectEqual(KeyAction.down, parseKeyActionLine("down"));
    try std.testing.expectEqual(KeyAction.enter, parseKeyActionLine("enter"));
    try std.testing.expectEqual(KeyAction.enter, parseKeyActionLine(""));
    try std.testing.expectEqual(KeyAction.space, parseKeyActionLine("space"));
    try std.testing.expectEqual(KeyAction.escape, parseKeyActionLine("esc"));
    try std.testing.expectEqual(KeyAction.escape, parseKeyActionLine("q"));
    try std.testing.expectEqual(KeyAction.other, parseKeyActionLine("xyz"));
}

test "selectCore renders options, descriptions, and focus cursor" {
    theme.resetCache();
    var buf: [2048]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var in = std.Io.Reader.fixed("enter\n");

    const opts = [_]SelectionOption{
        .{ .label = "Command Guard", .description = "Hook-based shell blocking" },
        .{ .label = "Firewall", .description = "Sandboxed sessions" },
        .{ .label = "Maximum Protection", .description = "Both (recommended)" },
    };

    const idx = try selectCore(std.testing.io, &w, &opts, &in, 2, "Choose your protection mode");
    try std.testing.expectEqual(@as(?usize, 2), idx);

    const out = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "Choose your protection mode") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Command Guard") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Hook-based shell blocking") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Maximum Protection") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "navigate") != null);
}

test "raw select frame uses carriage-return line endings" {
    theme.resetCache();
    var buf: [2048]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const opts = [_]SelectionOption{
        .{ .label = "Command Guard", .description = "Hook-based shell blocking" },
    };

    _ = try renderSelectFrame(std.testing.io, &w, &opts, 0, "Choose protection", 80);
    const out = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\n") == std.mem.indexOf(u8, out, "\r\n").? + 1);
}

test "raw redraw returns to column zero before moving up" {
    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try moveCursorUp(&w, 3);
    try std.testing.expectEqualStrings("\r\x1b[3A\r", w.buffered());
}

test "selectCore down then enter selects second option" {
    theme.resetCache();
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var in = std.Io.Reader.fixed("down\nenter\n");

    const opts = [_]SelectionOption{
        .{ .label = "A", .description = "first" },
        .{ .label = "B", .description = "second" },
        .{ .label = "C", .description = "third" },
    };

    const idx = try selectCore(std.testing.io, &w, &opts, &in, 0, "");
    try std.testing.expectEqual(@as(?usize, 1), idx);
}

test "selectCore escape returns safe default index" {
    theme.resetCache();
    var buf: [2048]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var in = std.Io.Reader.fixed("esc\n");

    const opts = [_]SelectionOption{
        .{ .label = "A", .description = "" },
        .{ .label = "B", .description = "" },
    };

    const idx = try selectCore(std.testing.io, &w, &opts, &in, 1, "");
    try std.testing.expectEqual(@as(?usize, 1), idx);
}

test "selectCore EOF (empty stream) returns safe default, never blocks" {
    theme.resetCache();
    var buf: [2048]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var in = std.Io.Reader.fixed("");

    const opts = [_]SelectionOption{
        .{ .label = "A", .description = "" },
        .{ .label = "B", .description = "" },
    };

    const idx = try selectCore(std.testing.io, &w, &opts, &in, 0, "");
    try std.testing.expectEqual(@as(?usize, 0), idx);
}

test "selectCore up does not wrap past first option" {
    theme.resetCache();
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var in = std.Io.Reader.fixed("up\nup\nenter\n");

    const opts = [_]SelectionOption{
        .{ .label = "A", .description = "" },
        .{ .label = "B", .description = "" },
    };

    const idx = try selectCore(std.testing.io, &w, &opts, &in, 1, "");
    // up from 1 → 0; up from 0 stays 0; enter → 0.
    try std.testing.expectEqual(@as(?usize, 0), idx);
}

test "selectCore empty options returns null" {
    theme.resetCache();
    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var in = std.Io.Reader.fixed("enter\n");

    const idx = try selectCore(std.testing.io, &w, &.{}, &in, 0, "");
    try std.testing.expectEqual(@as(?usize, null), idx);
}

test "multiSelectCore renders checkboxes and toggles on space" {
    theme.resetCache();
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var in = std.Io.Reader.fixed("space\nenter\n");

    var opts = [_]SelectionOption{
        .{ .label = "codex", .checked = true, .id = "codex" },
        .{ .label = "claude", .checked = false, .id = "claude" },
    };

    const confirmed = try multiSelectCore(std.testing.io, &w, &opts, &in, "Detected agent hosts");
    try std.testing.expect(confirmed);
    // space toggled the focused (first) item off.
    try std.testing.expect(!opts[0].checked);
    try std.testing.expect(!opts[1].checked);

    const out = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "Detected agent hosts") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "[x]") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "[ ]") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "codex") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "toggle") != null);
}

test "multiSelectCore down + space toggles second item" {
    theme.resetCache();
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var in = std.Io.Reader.fixed("down\nspace\nenter\n");

    var opts = [_]SelectionOption{
        .{ .label = "codex", .checked = false },
        .{ .label = "claude", .checked = false },
    };

    const confirmed = try multiSelectCore(std.testing.io, &w, &opts, &in, "");
    try std.testing.expect(confirmed);
    try std.testing.expect(!opts[0].checked);
    try std.testing.expect(opts[1].checked);
}

test "multiSelectCore escape cancels and keeps defaults" {
    theme.resetCache();
    var buf: [2048]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var in = std.Io.Reader.fixed("esc\n");

    var opts = [_]SelectionOption{
        .{ .label = "codex", .checked = true },
        .{ .label = "claude", .checked = false },
    };

    const confirmed = try multiSelectCore(std.testing.io, &w, &opts, &in, "");
    try std.testing.expect(!confirmed);
    // Defaults preserved (safe default).
    try std.testing.expect(opts[0].checked);
    try std.testing.expect(!opts[1].checked);
}

test "multiSelectCore EOF cancels safely (keeps defaults)" {
    theme.resetCache();
    var buf: [2048]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var in = std.Io.Reader.fixed("");

    var opts = [_]SelectionOption{
        .{ .label = "codex", .checked = true },
    };

    const confirmed = try multiSelectCore(std.testing.io, &w, &opts, &in, "");
    try std.testing.expect(!confirmed);
    try std.testing.expect(opts[0].checked);
}

test "multiSelectCore empty options confirms trivially" {
    theme.resetCache();
    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var in = std.Io.Reader.fixed("enter\n");

    const confirmed = try multiSelectCore(std.testing.io, &w, &.{}, &in, "");
    try std.testing.expect(confirmed);
}

test "select with injected reader delegates to core (TTY-independent path)" {
    theme.resetCache();
    var buf: [2048]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var in = std.Io.Reader.fixed("down\nenter\n");

    const opts = [_]SelectionOption{
        .{ .label = "A", .description = "x" },
        .{ .label = "B", .description = "y" },
    };
    const idx = try select(std.testing.io, std.testing.allocator, &w, &opts, 0, "Header", &in);
    try std.testing.expectEqual(@as(?usize, 1), idx);
}

test "danger confirm requires explicit confirmation and defaults to deny" {
    var out_buf: [512]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    var yes_reader: std.Io.Reader = .fixed("yes\n");
    try std.testing.expect(try confirmCore(std.testing.io, &out, &yes_reader, .danger, "Delete configuration?"));

    out = .fixed(&out_buf);
    var empty_reader: std.Io.Reader = .fixed("");
    try std.testing.expect(!try confirmCore(std.testing.io, &out, &empty_reader, .danger, "Delete configuration?"));
}

test "raw decoder carries fragmented CSI key sequences across reads" {
    if (comptime !enable_tui) return;
    var decoder: RawDecoder = .{};
    try std.testing.expectEqual(@as(?KeyAction, null), try decoder.feed("\x1b"));
    try std.testing.expectEqual(@as(?KeyAction, .up), try decoder.feed("[A"));
    try std.testing.expectEqual(@as(usize, 0), decoder.len);
}

test "raw decoder resolves standalone escape on inter-byte timeout" {
    if (comptime !enable_tui) return;
    var decoder: RawDecoder = .{};
    try std.testing.expectEqual(@as(?KeyAction, null), try decoder.feed("\x1b"));
    try std.testing.expectEqual(@as(?KeyAction, .escape), decoder.interByteTimeout());
    try std.testing.expectEqual(@as(usize, 0), decoder.len);
}

test "production confirm fails closed immediately without a tty" {
    var out_buf: [64]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    try std.testing.expect(!try confirm(std.testing.io, &out, .danger, "Delete?", null));
    try std.testing.expectEqualStrings("", out.buffered());
}

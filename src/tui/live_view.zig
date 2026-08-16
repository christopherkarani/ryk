const std = @import("std");
const builtin = @import("builtin");
const theme = @import("theme.zig");
const terminal_text = @import("terminal_text.zig");
const vaxis = @import("vaxis");

/// Optional `--live` (history) / `--tui` (replay) alt-screen viewer.
///
/// This is the only net-new machinery in Phase 7. It renders a snapshot of
/// pre-formatted lines inside the terminal's alternate screen buffer with
/// arrow-key scrolling, and leaves the alt-screen on every exit path (including
/// error and signal-via-Esc) so the user's prior terminal state is always
/// restored. The frame renderer (`renderFrame`) is pure and unit-tested; the raw
/// TTY event loop (`run`) reuses the same libvaxis `Tty` + `Parser` surface
/// `prompt.zig` already uses, and is comptime-gated out of test builds (where
/// `vaxis.tty.Tty` is a stub) — it is verified manually via subprocess, matching
/// the established note in `prompt.zig`.
///
/// Opt-in only. The CLI commands fall back to linear output on non-TTY /
/// `--plain` / `--no-rich` / `NO_COLOR`, and reject `--json`/`--robot`
/// (machine) combinations, so this module never enters the alt-screen on a
/// pipe (invariant: non-TTY → plain text; `--json` frozen).
pub const Lines = []const []const u8;

/// Keys the live loop reacts to (mirrors `prompt.zig`'s `KeyAction` shape).
pub const KeyAction = enum { quit, up, down, refresh, other };

/// Pure frame renderer: writes a brand header, a scroll-status footer, and a
/// viewport window of `lines` starting at `scroll_offset` capped at
/// `viewport_rows`. Emits no alt-screen or cursor controls — only content + the
/// theme's colour sequences (which degrade to plain text under capability
/// `.none`, so fixed-buffer unit tests see clean text). Returns the total number
/// of lines written, so the live loop can move the cursor back for re-render.
pub fn renderFrame(
    io: std.Io,
    stdout: anytype,
    title: []const u8,
    lines: Lines,
    scroll_offset: usize,
    viewport_rows: usize,
) !usize {
    return renderFrameWithLineEnding(io, stdout, title, lines, scroll_offset, viewport_rows, "\n");
}

fn renderFrameWithLineEnding(
    io: std.Io,
    stdout: anytype,
    title: []const u8,
    lines: Lines,
    scroll_offset: usize,
    viewport_rows: usize,
    line_ending: []const u8,
) !usize {
    var written: usize = 0;

    // Header: brand + title.
    try stdout.writeAll("  ");
    try theme.paintBold(io, stdout, .brand, "🛡  ryk");
    try stdout.writeAll(" · ");
    try theme.paintBold(io, stdout, .text_bright, title);
    try stdout.writeAll(line_ending);
    written += 1;

    // Viewport window of body lines. Clamp `start` to the last valid window
    // (pager semantics) so scrolling past the end shows the final page, not a
    // blank viewport with an inverted range.
    const total = lines.len;
    const cap = if (viewport_rows == 0) total else viewport_rows;
    const max_start: usize = if (total > cap) total - cap else 0;
    const start = @min(scroll_offset, max_start);
    const end = @min(start + cap, total);
    for (lines[start..end]) |line| {
        try stdout.writeAll("  ");
        try terminal_text.write(stdout, line, .single_line);
        try stdout.writeAll(line_ending);
        written += 1;
    }

    // Footer: scroll position + key hints.
    if (total == 0) {
        try theme.paint(io, stdout, .muted, "  (no rows) · q quit · ↑↓ scroll");
    } else {
        var footer: [128]u8 = undefined;
        const first = if (total == 0) 0 else start + 1;
        const last = end;
        const msg = std.fmt.bufPrint(&footer, "  lines {d}-{d} of {d} · q quit · ↑↓ scroll{s}", .{
            first,
            last,
            total,
            if (viewport_rows > 0 and viewport_rows < total) " · r refresh" else " · r refresh",
        }) catch "  q quit · ↑↓ scroll · r refresh";
        try theme.paint(io, stdout, .muted, msg);
    }
    try stdout.writeAll(line_ending);
    written += 1;
    return written;
}

/// Refresh callback: returns a fresh snapshot of lines (the caller owns the
/// allocator and frees the previous snapshot it handed to `run`), or `null`
/// when the refresh could not produce new data (the prior snapshot is kept).
pub const RefreshFn = *const fn (io: std.Io, ctx: *anyopaque) ?Lines;

/// Enter the alt-screen, render `initial_lines` with arrow-key scrolling, poll
/// keys (q/Esc → exit, ↑↓/j/k → scroll, r → refresh via the optional callback),
/// and leave the alt-screen on every exit path. Terminal state (alt buffer,
/// cursor visibility) is restored via `defer` on return AND on any error.
///
/// Real-TTY only. The CLI commands must fall back to linear (or reject `--json`)
/// before invoking this. In `builtin.is_test` the raw TTY loop is comptime-gated
/// out (vaxis.tty.Tty is a stub there); tests cover `renderFrame` directly.
pub fn run(
    io: std.Io,
    stdout: anytype,
    title: []const u8,
    initial_lines: Lines,
    refresh_fn: ?RefreshFn,
    refresh_ctx: ?*anyopaque,
) !void {
    // Enter the alternate screen buffer and hide the cursor. DECSET 1049
    // (smcup/rmcup) saves+restores the cursor and the prior screen content, so
    // leaving restores the user's terminal exactly. `defer` guarantees this on
    // every exit path (normal quit, Esc, error).
    try stdout.writeAll(vaxis.ctlseqs.smcup);
    try stdout.writeAll(vaxis.ctlseqs.hide_cursor);
    var left_alt = false;
    defer {
        if (!left_alt) {
            stdout.writeAll(vaxis.ctlseqs.show_cursor) catch {};
            stdout.writeAll(vaxis.ctlseqs.rmcup) catch {};
        }
    }

    // The raw TTY event loop is unreachable under tests (CLI rejects non-TTY)
    // and must not semantically analyze the stubbed libvaxis `Tty` there.
    if (comptime builtin.is_test) return;

    var current_lines = initial_lines;
    var scroll: usize = 0;

    // Open the controlling terminal for raw key reads (same surface as
    // prompt.zig). Any failure here is non-fatal: we still leave the alt-screen
    // cleanly via the deferred restore and return.
    var tty_buf: [4096]u8 = undefined;
    var tty = vaxis.tty.Tty.init(io, &tty_buf) catch return;
    defer tty.deinit();

    // Save termios and install a raw read with an inter-byte timeout so a stalled
    // terminal cannot block the viewer indefinitely (mirrors prompt.zig).
    const saved = if (comptime builtin.os.tag != .windows)
        std.posix.tcgetattr(tty.fd.handle) catch null
    else
        null;
    defer if (saved) |s| {
        if (comptime builtin.os.tag != .windows) {
            std.posix.tcsetattr(tty.fd.handle, .NOW, s) catch {};
        }
    };
    configureReadTimeout(&tty);

    // Viewport height from the terminal, reserving 2 lines for header+footer.
    const viewport: usize = blk: {
        const ws = tty.getWinsize() catch break :blk 22;
        if (ws.rows == 0) break :blk 22;
        break :blk if (ws.rows > 2) ws.rows - 2 else 1;
    };

    var decoder: Decoder = .{};
    var frame_lines: usize = 0;
    var first_frame = true;
    while (true) {
        // Re-render in place: move back up + clear to end of screen (TTY only).
        if (!first_frame and frame_lines > 0) {
            try moveCursorUp(stdout, frame_lines);
            try stdout.writeAll("\x1b[J");
        }
        first_frame = false;
        frame_lines = try renderFrameWithLineEnding(io, stdout, title, current_lines, scroll, viewport, "\r\n");
        try flush(stdout);

        const action = readKey(&tty, &decoder) catch .quit;
        switch (action) {
            .quit => break,
            .up => if (scroll > 0) {
                scroll -= 1;
            },
            .down => {
                const last = @min(scroll + viewport, current_lines.len);
                if (last < current_lines.len) scroll += 1;
            },
            .refresh => {
                if (refresh_fn) |rf| {
                    if (refresh_ctx) |ctx| {
                        if (rf(io, ctx)) |new_lines| {
                            current_lines = new_lines;
                            scroll = 0;
                        }
                    }
                }
            },
            .other => {},
        }
    }

    // Mark the deferred restore as satisfied so we don't double-restore; the
    // defer block still runs and emits show_cursor + rmcup.
    left_alt = true;
    try stdout.writeAll(vaxis.ctlseqs.show_cursor);
    try stdout.writeAll(vaxis.ctlseqs.rmcup);
}

const Decoder = struct {
    parser: vaxis.Parser = .{},
    carry: [256]u8 = undefined,
    len: usize = 0,

    fn feed(self: *Decoder, bytes: []const u8) !?KeyAction {
        if (bytes.len > self.carry.len - self.len) return error.InputTooLong;
        @memcpy(self.carry[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
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

    fn interByteTimeout(self: *Decoder) ?KeyAction {
        if (self.len == 1 and self.carry[0] == 0x1b) {
            self.len = 0;
            return .quit; // bare Esc = quit
        }
        return null;
    }
};

/// Map a libvaxis `Key` to a live-view `KeyAction`.
fn keyToAction(key: vaxis.Key) KeyAction {
    if (key.matches(vaxis.Key.escape, .{})) return .quit;
    if (key.matches('q', .{})) return .quit;
    if (key.matches(vaxis.Key.up, .{})) return .up;
    if (key.matches(vaxis.Key.down, .{})) return .down;
    if (key.matches('k', .{})) return .up;
    if (key.matches('j', .{})) return .down;
    if (key.matches('r', .{})) return .refresh;
    return .other;
}

/// Read one key event from the raw TTY (mirrors prompt.zig's readRawAction).
fn readKey(tty: *vaxis.tty.Tty, decoder: *Decoder) !KeyAction {
    if (comptime builtin.os.tag == .windows) {
        while (true) switch (try tty.nextEvent(&decoder.parser, null)) {
            .key_press => |key| return keyToAction(key),
            else => {},
        };
    }
    configureReadTimeout(tty);
    var buf: [256]u8 = undefined;
    while (true) {
        // libvaxis `Tty.read` maps VMIN=0/VTIME idle to error.EndOfStream; that
        // would quit the viewer on the first idle tick. Read the fd directly.
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

fn configureReadTimeout(tty: anytype) void {
    if (comptime builtin.os.tag == .windows) return;
    if (builtin.is_test) return;
    var raw = std.posix.tcgetattr(tty.fd.handle) catch return;
    raw.cc[@intFromEnum(std.posix.V.MIN)] = 0;
    raw.cc[@intFromEnum(std.posix.V.TIME)] = 1; // 100 ms inter-byte timeout
    std.posix.tcsetattr(tty.fd.handle, .NOW, raw) catch {};
}

fn moveCursorUp(stdout: anytype, n: usize) !void {
    if (n == 0) return;
    var buf: [16]u8 = undefined;
    const seq = std.fmt.bufPrint(&buf, "\r\x1b[{d}A\r", .{n}) catch return;
    try stdout.writeAll(seq);
}

fn flush(writer: anytype) !void {
    const Writer = @TypeOf(writer);
    switch (@typeInfo(Writer)) {
        .pointer => |pointer| if (@hasDecl(pointer.child, "flush")) try writer.flush(),
        else => if (@hasDecl(Writer, "flush")) try writer.flush(),
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Tests — the pure frame renderer (the raw TTY loop is manual-verify).
// ────────────────────────────────────────────────────────────────────────────

test "renderFrame: empty snapshot shows no-rows footer" {
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const n = try renderFrame(std.testing.io, &w, "history", &.{}, 0, 10);
    const out = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "🛡  ryk") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "history") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "no rows") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "q quit") != null);
    // Plain (test) output: no escape sequences leak.
    try std.testing.expect(std.mem.indexOfScalar(u8, out, '\x1b') == null);
    // Header + footer only.
    try std.testing.expectEqual(@as(usize, 2), n);
}

test "raw live frame uses carriage-return line endings" {
    theme.resetCache();
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);

    _ = try renderFrameWithLineEnding(std.testing.io, &w, "history", &.{"row"}, 0, 1, "\r\n");
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "\r\n") != null);
}

test "renderFrame: viewport window honours scroll offset and cap" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const lines = [_][]const u8{ "a", "b", "c", "d", "e" };
    const n = try renderFrame(std.testing.io, &w, "replay", &lines, 1, 2);
    const out = w.buffered();
    // Only b and c appear (offset 1, cap 2).
    try std.testing.expect(std.mem.indexOf(u8, out, "  b\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "  c\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "  a\n") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "  d\n") == null);
    // Footer reports the window range.
    try std.testing.expect(std.mem.indexOf(u8, out, "lines 2-3 of 5") != null);
    // Header + 2 body + footer.
    try std.testing.expectEqual(@as(usize, 4), n);
    try std.testing.expect(std.mem.indexOfScalar(u8, out, '\x1b') == null);
}

test "renderFrame: clamp when scroll offset exceeds line count" {
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const lines = [_][]const u8{"only"};
    const n = try renderFrame(std.testing.io, &w, "history", &lines, 99, 10);
    const out = w.buffered();
    // Offset clamps to the end; the single row still renders.
    try std.testing.expect(std.mem.indexOf(u8, out, "  only\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "lines 1-1 of 1") != null);
    try std.testing.expectEqual(@as(usize, 3), n);
}

test "renderFrame: never emits alt-screen or cursor controls" {
    // Even with colour forced on, renderFrame writes only content + colour SGR;
    // it must NOT emit smcup/rmcup/hide_cursor/cursor-up (those live in `run`).
    theme.setTestActive(.{ .capability = .c256, .background = .dark });
    defer theme.setTestActive(null);
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const lines = [_][]const u8{ "row one", "row two" };
    _ = try renderFrame(std.testing.io, &w, "replay", &lines, 0, 10);
    const out = w.buffered();
    // No alt-screen / cursor controls — those are `run`'s responsibility.
    try std.testing.expect(std.mem.indexOf(u8, out, vaxis.ctlseqs.smcup) == null);
    try std.testing.expect(std.mem.indexOf(u8, out, vaxis.ctlseqs.rmcup) == null);
    try std.testing.expect(std.mem.indexOf(u8, out, vaxis.ctlseqs.hide_cursor) == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\x1b[A") == null); // cursor-up
    try std.testing.expect(std.mem.indexOf(u8, out, "\x1b[J") == null); // clear-to-end
    // Colour IS retained (the brand token renders a 256-colour SGR).
    try std.testing.expect(std.mem.indexOf(u8, out, "38;5;") != null);
}

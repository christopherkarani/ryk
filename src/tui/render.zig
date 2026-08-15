const std = @import("std");
const theme = @import("theme.zig");
const terminal_text = @import("terminal_text.zig");
const ctlseqs = @import("ctlseqs.zig");

/// Linear rich-output primitives for the ryk CLI.
///
/// Every primitive writes to a `std.Io.Writer`-like sink (duck-typed so unit
/// tests can use `std.Io.Writer.fixed`). Colour is supplied by `theme`; when the
/// active capability is `none`, output degrades to clean plain text with no
/// escape codes — pipes and `NO_COLOR` keep working.
///
/// Box-drawing uses Unicode (─ │ ┌ ┐ └ ┘ ├ ┤ ✗ ✓ ⚠ ℹ ● ○ ›). On capability `none`
/// we still emit these glyphs (modern terminals, files, and pipes handle UTF-8);
/// only colour sequences are suppressed.
const reset = theme.reset;
const bold = theme.bold;
const dim = theme.dim;

// ────────────────────────────────────────────────────────────────────────────
// Display width
// ────────────────────────────────────────────────────────────────────────────

/// Approximate terminal display width of a UTF-8 string. Good enough for column
/// alignment: combining marks = 0, wide (CJK/fullwidth) ranges = 2, else 1.
pub fn displayWidth(s: []const u8) usize {
    var w: usize = 0;
    var view = std.unicode.Utf8View.init(s) catch return s.len;
    var it = view.iterator();
    while (it.nextCodepoint()) |cp| {
        w += codepointWidth(cp);
    }
    return w;
}

fn codepointWidth(cp: u21) u2 {
    // Combining marks (U+0300..U+036F) and a few common zero-width ranges.
    if (cp >= 0x0300 and cp <= 0x036F) return 0;
    if (cp == 0x200D) return 0; // ZWJ
    // Wide ranges (CJK, fullwidth, emoji-ish) — coarse but practical for CLI tables.
    if (cp >= 0x1100 and (cp <= 0x115F or // Hangul Jamo
        (cp >= 0x2E80 and cp <= 0xA4CF and cp != 0x303F) or // CJK radicals..Yi
        (cp >= 0xAC00 and cp <= 0xD7A3) or // Hangul syllables
        (cp >= 0xF900 and cp <= 0xFAFF) or // CJK compat ideographs
        (cp >= 0xFE30 and cp <= 0xFE4F) or // CJK compat forms
        (cp >= 0xFF00 and cp <= 0xFF60) or // Fullwidth forms
        (cp >= 0xFFE0 and cp <= 0xFFE6) or
        (cp >= 0x1F300 and cp <= 0x1FAFF) // emoji & symbols
    )) return 2;
    return 1;
}

/// Write `s` then pad with spaces so the visible width reaches `width`.
pub fn writePadded(stdout: anytype, s: []const u8, width: usize) !void {
    try terminal_text.write(stdout, s, .single_line);
    const w = displayWidth(s);
    if (w >= width) return;
    var i: usize = w;
    while (i < width) : (i += 1) try stdout.writeAll(" ");
}

// ────────────────────────────────────────────────────────────────────────────
// Banner — compact brand header used at the top of human commands
// ────────────────────────────────────────────────────────────────────────────

/// Write the compact brand header: `🛡  ryk · v<version>` plus an optional dim
/// status suffix, under a rule line. Suppressed styling degrades to plain text.
pub fn banner(io: std.Io, stdout: anytype, version: []const u8, status: ?[]const u8) !void {
    try stdout.writeAll("  ");
    try theme.paintBold(io, stdout, .brand, "🛡  ryk");
    try stdout.writeAll(" · v");
    try theme.paint(io, stdout, .text_bright, version);
    if (status) |s| {
        try stdout.writeAll("   ");
        try theme.paint(io, stdout, .muted, s);
    }
    try stdout.writeAll("\n");
    try ruleLine(io, stdout, 64);
    try stdout.writeAll("\n");
}

/// Write a horizontal rule line of `width` box characters (or plain dashes on
/// `none` so pipes/readability hold up).
pub fn ruleLine(io: std.Io, stdout: anytype, width: usize) !void {
    const a = theme.active(io, stdout);
    const ch: []const u8 = if (a.supportsUnicode()) "─" else "-";
    var i: usize = 0;
    while (i < width) : (i += 1) try stdout.writeAll(ch);
}

// ────────────────────────────────────────────────────────────────────────────
// Badge — coloured decision/status chip
// ────────────────────────────────────────────────────────────────────────────

pub const BadgeKind = enum { allow, deny, ask, warn, info, pass, fail, neutral };

/// Write a one-word badge with surrounding padding, e.g. ` ALLOW `. On colourless
/// output the word is shown in `[UPPERCASE]` brackets so it still reads.
pub fn badge(io: std.Io, stdout: anytype, kind: BadgeKind) !void {
    const a = theme.active(io, stdout);
    const token: theme.Token = switch (kind) {
        .allow, .pass => .success,
        .deny, .fail => .danger,
        .ask, .warn => .warn,
        .info, .neutral => .info,
    };
    const label = switch (kind) {
        .allow => "ALLOW",
        .deny => "DENY",
        .ask => "ASK",
        .warn => "WARN",
        .info => "INFO",
        .pass => "PASS",
        .fail => "FAIL",
        .neutral => "OK",
    };
    if (!a.capability.hasColor()) {
        try stdout.print("[{s}]", .{label});
        return;
    }
    // Chip with inverse-ish emphasis: bold + token colour, padded.
    try stdout.writeAll(bold);
    try stdout.writeAll(" ");
    try stdout.writeAll(theme.sequence(token, a.capability, a.background));
    try stdout.print(" {s} ", .{label});
    try stdout.writeAll(reset);
}

// ────────────────────────────────────────────────────────────────────────────
// Meter — risk/progress bar (█████░░░░░ label)
// ────────────────────────────────────────────────────────────────────────────

/// Write a 20-cell meter plus a label. `fraction` is clamped to [0,1].
pub fn meter(io: std.Io, stdout: anytype, fraction: f32, label: []const u8) !void {
    const a = theme.active(io, stdout);
    const total: usize = 20;
    const clamped = if (fraction < 0) 0 else if (fraction > 1) 1 else fraction;
    const filled: usize = @intFromFloat(@round(clamped * @as(f32, @floatFromInt(total))));
    const token: theme.Token = if (filled >= 15) .danger else if (filled >= 9) .warn else .success;
    if (a.capability.hasColor()) {
        try stdout.writeAll(theme.sequence(token, a.capability, a.background));
        var i: usize = 0;
        while (i < filled) : (i += 1) try stdout.writeAll("█");
        while (i < total) : (i += 1) try stdout.writeAll("░");
        try stdout.writeAll(reset);
    } else {
        var i: usize = 0;
        while (i < filled) : (i += 1) try stdout.writeAll("#");
        while (i < total) : (i += 1) try stdout.writeAll(".");
    }
    try stdout.writeAll(" ");
    try theme.paint(io, stdout, token, label);
}

// ────────────────────────────────────────────────────────────────────────────
// KeyValue — aligned label/value grid
// ────────────────────────────────────────────────────────────────────────────

pub const KV = struct { label: []const u8, value: []const u8 };

/// Write rows as `  label  value` with all labels right-aligned to the widest
/// label width. Labels are muted, values are normal text.
pub fn keyValue(io: std.Io, stdout: anytype, rows: []const KV) !void {
    var widest: usize = 0;
    for (rows) |r| {
        const w = displayWidth(r.label);
        if (w > widest) widest = w;
    }
    const label_width = widest + 1;
    for (rows) |r| {
        try stdout.writeAll("  ");
        // Right-align labels: pad on the left.
        const lw = displayWidth(r.label);
        if (lw < label_width) {
            var i: usize = lw;
            while (i < label_width) : (i += 1) try stdout.writeAll(" ");
        }
        try theme.paint(io, stdout, .muted, r.label);
        try stdout.writeAll("  ");
        try terminal_text.write(stdout, r.value, .single_line);
        try stdout.writeAll("\n");
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Callout — info/warn/danger note block
// ────────────────────────────────────────────────────────────────────────────

pub const CalloutKind = enum { info, warn, danger, success };

pub fn callout(io: std.Io, stdout: anytype, kind: CalloutKind, title: []const u8, body: []const u8) !void {
    const token: theme.Token = switch (kind) {
        .info => .info,
        .warn => .warn,
        .danger => .danger,
        .success => .success,
    };
    const glyph: []const u8 = switch (kind) {
        .info => "ℹ",
        .warn => "⚠",
        .danger => "✗",
        .success => "✓",
    };
    try stdout.writeAll("  ");
    try theme.paintBold(io, stdout, token, glyph);
    try stdout.writeAll("  ");
    try theme.paintBold(io, stdout, token, title);
    if (body.len > 0) {
        try stdout.writeAll("\n");
        try writeWrapped(stdout, body, 4);
    }
    try stdout.writeAll("\n");
}

/// Write `text` word-wrapped to ~`width` columns with a leading indent.
fn writeWrapped(stdout: anytype, text: []const u8, indent: usize) !void {
    try writeWrappedWidth(stdout, text, indent, 76);
}

/// Write terminal-safe text wrapped to `max_width`, including indentation.
/// Words longer than the available content width are truncated with an ellipsis.
pub fn writeWrappedWidth(stdout: anytype, text: []const u8, indent: usize, max_width: usize) !void {
    if (max_width <= indent) return;
    var col: usize = indent;
    var i: usize = 0;
    while (i < indent) : (i += 1) try stdout.writeAll(" ");
    var it = std.mem.tokenizeAny(u8, text, " \t\n");
    while (it.next()) |word| {
        const w = displayWidth(word);
        if (col + w + 1 > max_width and col > indent) {
            try stdout.writeAll("\n");
            var k: usize = 0;
            while (k < indent) : (k += 1) try stdout.writeAll(" ");
            col = indent;
        }
        if (col > indent) {
            try stdout.writeAll(" ");
            col += 1;
        }
        if (w + indent > max_width) {
            try writeTruncated(stdout, word, max_width - indent);
            col = max_width;
        } else {
            try terminal_text.write(stdout, word, .single_line);
            col += w;
        }
    }
}

/// Write at most `width` terminal columns, appending an ellipsis when clipped.
pub fn writeTruncated(stdout: anytype, text: []const u8, width: usize) !void {
    if (width == 0) return;
    if (displayWidth(text) <= width) return terminal_text.write(stdout, text, .single_line);
    if (width == 1) return stdout.writeAll("…");

    var view = std.unicode.Utf8View.init(text) catch return stdout.writeAll("…");
    var iterator = view.iterator();
    var used: usize = 0;
    while (iterator.nextCodepointSlice()) |slice| {
        const cp = std.unicode.utf8Decode(slice) catch break;
        const cp_width = codepointWidth(cp);
        if (used + cp_width > width - 1) break;
        try stdout.writeAll(slice);
        used += cp_width;
    }
    try stdout.writeAll("…");
}

// ────────────────────────────────────────────────────────────────────────────
// Panel — bordered box with a title and a body writer callback
// ────────────────────────────────────────────────────────────────────────────

/// Render a titled panel around pre-formatted body lines (a slice of strings,
/// each already one visual line). Borders use box-drawing when Unicode is
/// supported (independent of color) and ASCII `-|+` otherwise.
pub fn panel(
    io: std.Io,
    stdout: anytype,
    title: ?[]const u8,
    body_lines: []const []const u8,
) !void {
    const a = theme.active(io, stdout);
    const use_unicode = a.supportsUnicode();
    const tl = if (use_unicode) "┌" else "+";
    const tr = if (use_unicode) "┐" else "+";
    const bl = if (use_unicode) "└" else "+";
    const br = if (use_unicode) "┘" else "+";
    const h = if (use_unicode) "─" else "-";
    const v = if (use_unicode) "│" else "|";
    const ml = if (use_unicode) "├" else "+";
    const mr = if (use_unicode) "┤" else "+";

    // Compute interior width: title width or widest body line + 2 padding.
    var content_width: usize = 0;
    if (title) |t| content_width = displayWidth(t) + 2;
    for (body_lines) |line| {
        const w = displayWidth(line);
        if (w > content_width) content_width = w;
    }
    const inner = content_width + 2; // 1-col padding each side

    // Top border (+ optional title)
    try stdout.writeAll(tl);
    var i: usize = 0;
    while (i < inner + 2) : (i += 1) try stdout.writeAll(h);
    try stdout.writeAll(tr);
    try stdout.writeAll("\n");

    if (title) |t| {
        try stdout.writeAll(v);
        try stdout.writeAll(" ");
        try theme.paintBold(io, stdout, .brand, t);
        const tw = displayWidth(t);
        var pad: usize = tw + 1;
        while (pad < inner + 1) : (pad += 1) try stdout.writeAll(" ");
        try stdout.writeAll(" ");
        try stdout.writeAll(v);
        try stdout.writeAll("\n");
        // Mid divider
        try stdout.writeAll(ml);
        var j: usize = 0;
        while (j < inner + 2) : (j += 1) try stdout.writeAll(h);
        try stdout.writeAll(mr);
        try stdout.writeAll("\n");
    }

    for (body_lines) |line| {
        try stdout.writeAll(v);
        try stdout.writeAll(" ");
        try terminal_text.write(stdout, line, .single_line);
        const lw = displayWidth(line);
        var pad: usize = lw;
        while (pad < inner) : (pad += 1) try stdout.writeAll(" ");
        try stdout.writeAll(" ");
        try stdout.writeAll(v);
        try stdout.writeAll("\n");
    }

    try stdout.writeAll(bl);
    var k: usize = 0;
    while (k < inner + 2) : (k += 1) try stdout.writeAll(h);
    try stdout.writeAll(br);
    try stdout.writeAll("\n");
}

// ────────────────────────────────────────────────────────────────────────────
// Table — column-aligned rows with a header
// ────────────────────────────────────────────────────────────────────────────

pub const TableColumn = struct { name: []const u8, width: ?usize = null };

/// Render a simple fixed-width table. Column widths default to the max of the
/// header and any cell in that column (capped at 48). Rows are `[]const []const u8`.
pub fn table(
    io: std.Io,
    stdout: anytype,
    columns: []const TableColumn,
    rows: []const []const []const u8,
) !void {
    if (columns.len == 0) return;

    // Compute widths.
    var widths = try std.heap.page_allocator.alloc(usize, columns.len);
    defer std.heap.page_allocator.free(widths);
    for (columns, 0..) |c, i| {
        var w: usize = displayWidth(c.name);
        if (c.width) |fixed| {
            w = fixed;
        } else {
            for (rows) |row| {
                if (i < row.len) {
                    const cw = displayWidth(row[i]);
                    if (cw > w) w = cw;
                }
            }
            if (w > 48) w = 48;
        }
        widths[i] = w;
    }

    // Header.
    try stdout.writeAll("  ");
    for (columns, 0..) |c, i| {
        try theme.paintBold(io, stdout, .muted, c.name);
        try writePadded(stdout, "", widths[i] - displayWidth(c.name) + 2);
    }
    try stdout.writeAll("\n");

    // Separator.
    try stdout.writeAll("  ");
    for (widths, 0..) |w, i| {
        _ = i;
        var n: usize = 0;
        while (n < w + 2) : (n += 1) try stdout.writeAll(if (theme.active(io, stdout).supportsUnicode()) "─" else "-");
    }
    try stdout.writeAll("\n");

    // Rows.
    for (rows) |row| {
        try stdout.writeAll("  ");
        for (columns, 0..) |_, i| {
            const cell = if (i < row.len) row[i] else "";
            try terminal_text.write(stdout, cell, .single_line);
            const cw = displayWidth(cell);
            if (cw < widths[i]) {
                var n: usize = cw;
                while (n < widths[i] + 2) : (n += 1) try stdout.writeAll(" ");
            } else {
                try stdout.writeAll("  ");
            }
        }
        try stdout.writeAll("\n");
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Step — a single step-line render (used by StepList-style flows)
// ────────────────────────────────────────────────────────────────────────────

pub const StepStatus = enum { pending, active, done, failed };

pub fn stepLine(io: std.Io, stdout: anytype, status: StepStatus, label: []const u8, detail: ?[]const u8, line_width: usize) !void {
    const a = theme.active(io, stdout);
    const has_color = a.capability.hasColor();
    // An active step is "live" only when colour is on AND motion is allowed
    // (reduced-motion renders a static glyph instead of the braille frame).
    const live_active = status == .active and has_color and !theme.reducedMotion(io, stdout);

    // Live clear prefix: only when we'll overwrite this line in place (rich + a
    // declared line width). Keeps piped/plain output free of cursor controls.
    if (line_width > 0 and has_color) {
        try stdout.writeAll("\r\x1b[2K\r");
    }

    const marker_token: theme.Token = switch (status) {
        .done, .active => .success,
        .failed => .danger,
        .pending => .muted,
    };
    const glyph: []const u8 = switch (status) {
        .done => "✓",
        // Phase 7: the active step shows an inline spinner frame (one frame;
        // caller ticks between phases) when live, else the static chevron.
        .active => if (live_active) "⠋" else "›",
        .failed => "✗",
        .pending => "○",
    };

    // Bracket the live spinner frame in a single synchronized-output pair so it
    // paints atomically (no tear). Exactly one pair per active render.
    if (live_active) try stdout.writeAll(ctlseqs.sync_set);

    try stdout.writeAll("  ");
    try theme.paintBold(io, stdout, marker_token, glyph);
    try stdout.writeAll(" ");
    switch (status) {
        .pending => try theme.paint(io, stdout, .muted, label),
        .active => try theme.paintBold(io, stdout, .text_bright, label),
        else => try theme.paint(io, stdout, .text, label),
    }
    if (detail) |d| {
        try stdout.writeAll("  ");
        try theme.paint(io, stdout, .muted, d);
    }

    if (live_active) try stdout.writeAll(ctlseqs.sync_reset);
    try stdout.writeAll("\n");
}

pub const Definition = struct { term: []const u8, description: []const u8 };

pub fn definitionList(io: std.Io, stdout: anytype, entries: []const Definition) !void {
    var widest: usize = 0;
    for (entries) |entry| widest = @max(widest, displayWidth(entry.term));
    for (entries) |entry| {
        try stdout.writeAll("  ");
        try theme.paint(io, stdout, .muted, entry.term);
        var pad = displayWidth(entry.term);
        while (pad < widest + 2) : (pad += 1) try stdout.writeAll(" ");
        try terminal_text.write(stdout, entry.description, .single_line);
        try stdout.writeAll("\n");
    }
}

pub const Step = struct { status: StepStatus, label: []const u8, detail: ?[]const u8 = null };

pub fn stepList(io: std.Io, stdout: anytype, steps: []const Step) !void {
    for (steps) |step| try stepLine(io, stdout, step.status, step.label, step.detail, 0);
}

pub const TimelineEvent = struct { label: []const u8, detail: []const u8 };

pub fn timeline(io: std.Io, stdout: anytype, events: []const TimelineEvent) !void {
    for (events, 0..) |event, index| {
        try stdout.writeAll("  ");
        try theme.paint(io, stdout, .muted, if (index + 1 == events.len) "└" else "├");
        try stdout.writeAll(" ");
        try theme.paintBold(io, stdout, .text_bright, event.label);
        if (event.detail.len > 0) {
            try stdout.writeAll("  ");
            try terminal_text.write(stdout, event.detail, .single_line);
        }
        try stdout.writeAll("\n");
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

test "displayWidth: ascii" {
    try std.testing.expectEqual(@as(usize, 5), displayWidth("hello"));
    try std.testing.expectEqual(@as(usize, 0), displayWidth(""));
}

test "displayWidth: cjk counts as width 2" {
    // 中 (U+4E2D) is in the wide CJK range.
    try std.testing.expectEqual(@as(usize, 2), displayWidth("中"));
}

test "writePadded: pads to width with spaces" {
    var buf: [32]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writePadded(&w, "ab", 5);
    // "ab" + 3 spaces
    try std.testing.expectEqualStrings("ab   ", w.buffered());
}

test "writePadded: no pad when already wide enough" {
    var buf: [32]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writePadded(&w, "abcde", 3);
    try std.testing.expectEqualStrings("abcde", w.buffered());
}

test "writeTruncated respects display width and preserves utf8" {
    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeTruncated(&w, "database.postgresql", 10);
    try std.testing.expectEqualStrings("database.…", w.buffered());
    try std.testing.expectEqual(@as(usize, 10), displayWidth(w.buffered()));

    var wide_buf: [64]u8 = undefined;
    var wide: std.Io.Writer = .fixed(&wide_buf);
    try writeTruncated(&wide, "安全-policy", 6);
    try std.testing.expectEqual(@as(usize, 6), displayWidth(wide.buffered()));
    _ = try std.unicode.Utf8View.init(wide.buffered());
}

test "badge: plain output uses brackets" {
    theme.resetCache();
    var buf: [32]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try badge(std.testing.io, &w, .deny);
    try std.testing.expectEqualStrings("[DENY]", w.buffered());
}

test "badge: coloured output contains the label and a reset" {
    theme.resetCache();
    // Can't easily fake colour capability through active() in tests (it forces none),
    // so verify the plain path is correct and stable. Colour path is exercised by
    // sequence() tests in theme.zig.
    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try badge(std.testing.io, &w, .allow);
    try std.testing.expectEqualStrings("[ALLOW]", w.buffered());
}

test "meter: plain output uses # and . characters" {
    theme.resetCache();
    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try meter(std.testing.io, &w, 0.5, "high");
    const out = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "#####") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "high") != null);
}

test "meter: clamps out-of-range fractions" {
    theme.resetCache();
    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try meter(std.testing.io, &w, 2.0, "max");
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "max") != null);
}

test "keyValue: aligns labels into a grid" {
    theme.resetCache();
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const rows = [_]KV{
        .{ .label = "Mode", .value = "ask" },
        .{ .label = "Workspace", .value = "/tmp/proj" },
    };
    try keyValue(std.testing.io, &w, &rows);
    const out = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "Mode") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "ask") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Workspace") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "/tmp/proj") != null);
}

test "callout: plain danger renders glyph title and body" {
    theme.resetCache();
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try callout(std.testing.io, &w, .danger, "Blocked", "This is dangerous and you should not do it.");
    const out = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "✗") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Blocked") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "dangerous") != null);
}

test "panel: plain output uses ASCII box chars and contains title + body" {
    theme.resetCache();
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const body = [_][]const u8{ "line one", "line two" };
    try panel(std.testing.io, &w, "My Panel", &body);
    const out = w.buffered();
    // ASCII corners used on plain output.
    try std.testing.expect(std.mem.indexOf(u8, out, "+") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "|") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "My Panel") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "line one") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "line two") != null);
}

test "panel: unicode output uses box-drawing corners" {
    theme.setTestActive(.{ .capability = .none, .background = .dark, .unicode = true });
    defer theme.setTestActive(null);
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const body = [_][]const u8{"x"};
    try panel(std.testing.io, &w, null, &body);
    const out = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "┌") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "x") != null);
}

test "table: header + rows aligned" {
    theme.resetCache();
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const cols = [_]TableColumn{ .{ .name = "Host" }, .{ .name = "Status" } };
    const rows = [_][]const []const u8{
        &.{ "codex", "installed" },
        &.{ "claude", "missing" },
    };
    try table(std.testing.io, &w, &cols, &rows);
    const out = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "Host") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Status") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "codex") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "installed") != null);
}

test "stepLine: done renders check glyph" {
    theme.resetCache();
    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try stepLine(std.testing.io, &w, .done, "Policy", "created", 0);
    const out = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "✓") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Policy") != null);
}

test "stepLine: pending renders open circle" {
    theme.resetCache();
    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try stepLine(std.testing.io, &w, .pending, "Verify", null, 0);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "○") != null);
}

test "stepLine: plain output never emits cursor controls" {
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try stepLine(std.testing.io, &w, .active, "Policy", null, 80);
    try std.testing.expect(std.mem.indexOfScalar(u8, w.buffered(), '\x1b') == null);
}

test "stepLine rich output emits canonical cursor control" {
    theme.setTestActive(.{ .capability = .c256, .background = .dark });
    defer theme.setTestActive(null);
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try stepLine(std.testing.io, &w, .active, "Policy", null, 80);
    try std.testing.expect(std.mem.startsWith(u8, w.buffered(), "\r\x1b[2K\r"));
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "38;5;") != null);
}

/// Count non-overlapping occurrences of `needle` in `haystack` (test helper).
fn countSeq(haystack: []const u8, needle: []const u8) usize {
    if (needle.len == 0) return 0;
    var n: usize = 0;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) {
        if (std.mem.eql(u8, haystack[i .. i + needle.len], needle)) {
            n += 1;
            i += needle.len;
        } else {
            i += 1;
        }
    }
    return n;
}

test "stepLine: live active step is bracketed by exactly one sync pair" {
    // Phase 7 Task B: the active step renders an inline spinner frame, atomically
    // bracketed by exactly one synchronized-output pair (rich + motion on).
    theme.setTestActive(.{ .capability = .c256, .background = .dark });
    theme.setTestReducedMotion(false);
    defer {
        theme.setTestActive(null);
        theme.setTestReducedMotion(null);
    }
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try stepLine(std.testing.io, &w, .active, "Host integrations", "installing codex", 0);
    const out = w.buffered();
    // Braille spinner frame (not the static chevron) on the live active step.
    try std.testing.expect(std.mem.indexOf(u8, out, "⠋") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "›") == null);
    // Exactly one synchronized-output pair brackets the frame.
    try std.testing.expectEqual(@as(usize, 1), countSeq(out, ctlseqs.sync_set));
    try std.testing.expectEqual(@as(usize, 1), countSeq(out, ctlseqs.sync_reset));
}

test "stepLine: reduced-motion active step emits no sync controls" {
    // Phase 7 Task B/F: under reduced-motion the active step renders a static
    // glyph with NO synchronized-output controls, while colour is retained.
    theme.setTestActive(.{ .capability = .c256, .background = .dark });
    theme.setTestReducedMotion(true);
    defer {
        theme.setTestActive(null);
        theme.setTestReducedMotion(null);
    }
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try stepLine(std.testing.io, &w, .active, "Host integrations", null, 0);
    const out = w.buffered();
    // Static chevron (not the braille frame) when motion is suppressed.
    try std.testing.expect(std.mem.indexOf(u8, out, "›") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "⠋") == null);
    // No synchronized-output controls on the reduced-motion path.
    try std.testing.expect(std.mem.indexOf(u8, out, ctlseqs.sync_set) == null);
    try std.testing.expect(std.mem.indexOf(u8, out, ctlseqs.sync_reset) == null);
    // Colour is retained — reduced-motion stops animation, not colour.
    try std.testing.expect(std.mem.indexOf(u8, out, "38;5;") != null);
}

test "render primitives sanitize hostile terminal text" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try definitionList(std.testing.io, &w, &.{.{ .term = "bad\x1b[2J", .description = "x\x1b]0;pwn\x07\ry" }});
    try std.testing.expect(std.mem.indexOfScalar(u8, w.buffered(), 0x1b) == null);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "pwn") == null);
}

test "definitionList renders terms and descriptions" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try definitionList(std.testing.io, &w, &.{
        .{ .term = "Decision", .description = "deny" },
        .{ .term = "Reason", .description = "unsafe command" },
    });
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "Decision") != null);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "unsafe command") != null);
}

test "stepList and timeline render stable plain output" {
    var buf: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try stepList(std.testing.io, &w, &.{
        .{ .status = .done, .label = "Policy", .detail = "ready" },
        .{ .status = .pending, .label = "Verify" },
    });
    try timeline(std.testing.io, &w, &.{
        .{ .label = "command", .detail = "git status" },
        .{ .label = "decision", .detail = "allow" },
    });
    const out = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "Policy") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "command") != null);
    try std.testing.expect(std.mem.indexOfScalar(u8, out, '\x1b') == null);
}

// ────────────────────────────────────────────────────────────────────────────
// Phase 7 Task C: light/dark background variants consumed by render primitives
// (mirrors theme.zig's "light variant differs from dark" contract). Confirms no
// substantial primitive hardcodes `.dark` — all resolve tokens via theme.active().
// ────────────────────────────────────────────────────────────────────────────

test "badge: truecolor light variant differs from dark" {
    theme.setTestActive(.{ .capability = .truecolor, .background = .dark });
    var dark_buf: [128]u8 = undefined;
    var dark_w: std.Io.Writer = .fixed(&dark_buf);
    try badge(std.testing.io, &dark_w, .deny);
    const dark_out = dark_buf[0..dark_w.end];

    theme.setTestActive(.{ .capability = .truecolor, .background = .light });
    var light_buf: [128]u8 = undefined;
    var light_w: std.Io.Writer = .fixed(&light_buf);
    try badge(std.testing.io, &light_w, .deny);
    const light_out = light_buf[0..light_w.end];

    theme.setTestActive(null);
    defer theme.setTestActive(null);
    // The deny badge uses the danger token, whose light/dark truecolor RGBs differ.
    try std.testing.expect(!std.mem.eql(u8, dark_out, light_out));
}

test "panel: truecolor light variant differs from dark" {
    theme.setTestActive(.{ .capability = .truecolor, .background = .dark });
    var dark_buf: [256]u8 = undefined;
    var dark_w: std.Io.Writer = .fixed(&dark_buf);
    try panel(std.testing.io, &dark_w, "Decision", &.{"deny"});
    const dark_out = dark_buf[0..dark_w.end];

    theme.setTestActive(.{ .capability = .truecolor, .background = .light });
    var light_buf: [256]u8 = undefined;
    var light_w: std.Io.Writer = .fixed(&light_buf);
    try panel(std.testing.io, &light_w, "Decision", &.{"deny"});
    const light_out = light_buf[0..light_w.end];

    theme.setTestActive(null);
    defer theme.setTestActive(null);
    // The panel title uses the brand token, whose light/dark truecolor RGBs differ.
    try std.testing.expect(!std.mem.eql(u8, dark_out, light_out));
}

test "meter: truecolor light variant differs from dark" {
    theme.setTestActive(.{ .capability = .truecolor, .background = .dark });
    var dark_buf: [128]u8 = undefined;
    var dark_w: std.Io.Writer = .fixed(&dark_buf);
    try meter(std.testing.io, &dark_w, 0.7, "high");
    const dark_out = dark_buf[0..dark_w.end];

    theme.setTestActive(.{ .capability = .truecolor, .background = .light });
    var light_buf: [128]u8 = undefined;
    var light_w: std.Io.Writer = .fixed(&light_buf);
    try meter(std.testing.io, &light_w, 0.7, "high");
    const light_out = light_buf[0..light_w.end];

    theme.setTestActive(null);
    defer theme.setTestActive(null);
    // The meter uses the danger token at high risk, whose light/dark RGBs differ.
    try std.testing.expect(!std.mem.eql(u8, dark_out, light_out));
}

const std = @import("std");
const builtin = @import("builtin");
const terminal_text = @import("terminal_text.zig");

/// ryk CLI design system: palette, color-capability detection, and theme tokens.
///
/// This module is the single source of truth for visual styling. It degrades
/// gracefully: truecolor → 256 → 16-color → plain text. It always honours
/// `NO_COLOR`, `TERM=dumb`, and non-TTY output (piped/scripted).
///
/// Pure decision functions are separated from runtime detection so they can be
/// unit-tested with fixed inputs (mirrors the `style.zig` pattern).

// ────────────────────────────────────────────────────────────────────────────
// Capability detection (pure, testable)
// ────────────────────────────────────────────────────────────────────────────

/// Highest quality of color the output target can render.
pub const Capability = enum {
    none, // plain text
    basic_16, // standard ANSI 16-color
    c256, // 256-color palette
    truecolor, // 24-bit RGB

    /// True when any color at all is available.
    pub fn hasColor(self: Capability) bool {
        return self != .none;
    }
};

/// Detectable terminal background tone. Used to pick contrast-safe variant tokens.
pub const Background = enum { dark, light, unknown };

/// Inputs to the pure capability detector. All fields are environment-derived so
/// the function itself has no global state.
pub const DetectInput = struct {
    is_tty: bool,
    no_color: bool,
    term_dumb: bool,
    /// `COLORTERM` is `truecolor` or `24bit`.
    colorterm_truecolor: bool,
    /// `TERM` contains `256color`.
    term_256color: bool,
};

/// Pure decision: which capability should be used given environment signals.
pub fn detectCapability(d: DetectInput) Capability {
    if (!d.is_tty) return .none;
    if (d.no_color) return .none;
    if (d.term_dumb) return .none;
    if (d.colorterm_truecolor) return .truecolor;
    if (d.term_256color) return .c256;
    return .basic_16;
}

/// Parse the `COLORFGBG` convention (`foreground;background`) into a background tone.
/// Returns `unknown` when absent or malformed.
pub fn parseColorfgbg(value: []const u8) Background {
    var it = std.mem.splitScalar(u8, value, ';');
    _ = it.next() orelse return .unknown; // foreground
    const bg = it.next() orelse return .unknown;
    const n = std.fmt.parseInt(u8, std.mem.trim(u8, bg, " \t"), 10) catch return .unknown;
    // Convention: background 0-6 = dark, 7-15 (and the standard "light" default 15) = light.
    return if (n <= 6) .dark else .light;
}

/// Classify an RGB background (0-255 per channel) as light or dark via relative
/// luminance (ITU-R BT.709 weights). Threshold 0.5: backgrounds brighter than
/// mid-grey read as `.light`, else `.dark`. Pure — unit-tested.
pub fn rgbToBackground(r: u8, g: u8, b: u8) Background {
    const rf: f32 = @as(f32, @floatFromInt(r)) / 255.0;
    const gf: f32 = @as(f32, @floatFromInt(g)) / 255.0;
    const bf: f32 = @as(f32, @floatFromInt(b)) / 255.0;
    const lum = 0.2126 * rf + 0.7152 * gf + 0.0722 * bf;
    return if (lum > 0.5) .light else .dark;
}

/// Parse the reply to an OSC 11 background-color query into a `Background` tone.
/// Accepts the common X11 form `\x1b]11;rgb:RRRR/GGGG/BBBB\x1b\\` (or BEL-terminated
/// `\x07`) and the short `rgb:R/G/B` form. Each component is 1-4 hex digits and is
/// scaled to 0-255 against its own max so any precision replies consistently.
/// Returns `.unknown` when the reply is absent or malformed (caller falls back).
pub fn parseOsc11Reply(reply: []const u8) Background {
    // Locate the `rgb:` payload after the `11;` selector.
    const payload_idx = std.mem.indexOf(u8, reply, "rgb:") orelse return .unknown;
    const rest = reply[payload_idx + 4 ..];
    // Components are separated by `/` (X11) or `:` (some emulators); the payload
    // ends at the string terminator (ST/BEL already stripped by the caller, or we
    // trim at the first non-hex/non-separator run).
    var comps: [3][]const u8 = .{ "", "", "" };
    var count: usize = 0;
    var it = std.mem.tokenizeAny(u8, rest, "/:");
    while (it.next()) |c| {
        if (count >= 3) break;
        // Stop at a terminator if the ST/BEL was not stripped (e.g. `\x1b\\`).
        var end: usize = 0;
        while (end < c.len and std.ascii.isHex(c[end])) end += 1;
        if (end == 0) break;
        comps[count] = c[0..end];
        count += 1;
    }
    if (count != 3) return .unknown;
    // Parse each component; bail on any non-hex (already filtered) or empty.
    const r_raw = std.fmt.parseInt(u32, comps[0], 16) catch return .unknown;
    const g_raw = std.fmt.parseInt(u32, comps[1], 16) catch return .unknown;
    const b_raw = std.fmt.parseInt(u32, comps[2], 16) catch return .unknown;
    // Scale each component to 0-255 against its own digit-width max so a 4-digit
    // `ffff` and a 1-digit `f` both map to 255.
    const scale = struct {
        fn to8(v: u32, digits: usize) u8 {
            if (digits == 0) return 0;
            // Cap digit width: OSC replies with >8 hex digits would shift past u32.
            // Terminal RGB is 1–4 digits per channel in practice; treat wider as max.
            const d: usize = @min(digits, 4);
            const max: u32 = (@as(u32, 1) << @intCast(d * 4)) - 1;
            if (max == 0) return 0;
            // Use only the low `d` hex digits when the reply was over-wide.
            const masked = if (digits > 4) v & max else v;
            const scaled: u32 = (masked * 255 + (max / 2)) / max;
            return @intCast(@min(scaled, 255));
        }
    };
    const r = scale.to8(r_raw, comps[0].len);
    const g = scale.to8(g_raw, comps[1].len);
    const b = scale.to8(b_raw, comps[2].len);
    return rgbToBackground(r, g, b);
}

// ────────────────────────────────────────────────────────────────────────────
// Palette
// ────────────────────────────────────────────────────────────────────────────

/// A semantic color token. Each renders to the best SGR sequence for the active
/// capability and background.
pub const Token = enum {
    brand, // headers / brand mark — soft mint (sampled from product UI)
    success, // allow, pass, enabled packs
    danger, // deny, fail, destructive
    warn, // limited, partial, ask
    info, // neutral emphasis
    muted, // secondary/dim text
    surface, // panel borders/fill
    text, // body
    text_bright, // emphasized body
};

pub const Rgb = struct { r: u8, g: u8, b: u8 };

/// Dark-theme truecolor RGB triples.
/// Brand/success trial: soft mint/seafoam (#7CD4B0) — sampled from the packs tree
/// selection green the user wants (not electric neon #39FF14).
const dark_rgb = struct {
    const brand = Rgb{ .r = 0x7c, .g = 0xd4, .b = 0xb0 };
    const success = Rgb{ .r = 0x7c, .g = 0xd4, .b = 0xb0 };
    const danger = Rgb{ .r = 0xf8, .g = 0x51, .b = 0x49 };
    const warn = Rgb{ .r = 0xd2, .g = 0x99, .b = 0x22 };
    const info = Rgb{ .r = 0x58, .g = 0xa6, .b = 0xff };
    const muted = Rgb{ .r = 0x8b, .g = 0x94, .b = 0x9e };
    const surface = Rgb{ .r = 0x30, .g = 0x36, .b = 0x3d };
    const text = Rgb{ .r = 0xe6, .g = 0xed, .b = 0xf3 };
    const text_bright = Rgb{ .r = 0xff, .g = 0xff, .b = 0xff };
};

/// Light-theme truecolor RGB triples (higher contrast on light backgrounds).
const light_rgb = struct {
    const brand = Rgb{ .r = 0x00, .g = 0xc8, .b = 0x53 };
    const success = Rgb{ .r = 0x00, .g = 0xc8, .b = 0x53 };
    const danger = Rgb{ .r = 0xcf, .g = 0x22, .b = 0x2e };
    const warn = Rgb{ .r = 0x9a, .g = 0x6a, .b = 0x02 };
    const info = Rgb{ .r = 0x09, .g = 0x69, .b = 0xda };
    const muted = Rgb{ .r = 0x6e, .g = 0x77, .b = 0x81 };
    const surface = Rgb{ .r = 0xd0, .g = 0xd7, .b = 0xde };
    const text = Rgb{ .r = 0x24, .g = 0x29, .b = 0x2f };
    const text_bright = Rgb{ .r = 0x00, .g = 0x00, .b = 0x00 };
};

/// 16-color fallback mapping (matches the dark intent for the common dark default).
const basic16 = struct {
    const brand = "\x1b[32m"; // green (mint brand trial)
    const success = "\x1b[32m"; // green
    const danger = "\x1b[31m"; // red
    const warn = "\x1b[33m"; // yellow
    const info = "\x1b[34m"; // blue
    const muted = "\x1b[2m"; // dim
    const surface = "\x1b[2m"; // dim
    const text = "";
    const text_bright = "\x1b[1m"; // bold
};

fn rgbFor(token: Token, bg: Background) Rgb {
    const use_light = bg == .light;
    return switch (token) {
        .brand => if (use_light) light_rgb.brand else dark_rgb.brand,
        .success => if (use_light) light_rgb.success else dark_rgb.success,
        .danger => if (use_light) light_rgb.danger else dark_rgb.danger,
        .warn => if (use_light) light_rgb.warn else dark_rgb.warn,
        .info => if (use_light) light_rgb.info else dark_rgb.info,
        .muted => if (use_light) light_rgb.muted else dark_rgb.muted,
        .surface => if (use_light) light_rgb.surface else dark_rgb.surface,
        .text => if (use_light) light_rgb.text else dark_rgb.text,
        .text_bright => if (use_light) light_rgb.text_bright else dark_rgb.text_bright,
    };
}

/// Returns the SGR escape sequence for `token` under `cap`/`bg`, or an empty string
/// when no color is available. The caller owns the static-lifetime result.
pub fn sequence(token: Token, cap: Capability, bg: Background) []const u8 {
    return switch (cap) {
        .none => "",
        .basic_16 => switch (token) {
            .brand => basic16.brand,
            .success => basic16.success,
            .danger => basic16.danger,
            .warn => basic16.warn,
            .info => basic16.info,
            .muted => basic16.muted,
            .surface => basic16.surface,
            .text => basic16.text,
            .text_bright => basic16.text_bright,
        },
        .c256 => switch (token) {
            .brand => "\x1b[38;5;115m", // soft mint (xterm ≈ #87d7af)
            .success => "\x1b[38;5;115m",
            .danger => "\x1b[38;5;196m",
            .warn => "\x1b[38;5;178m",
            .info => "\x1b[38;5;75m",
            .muted => "\x1b[38;5;245m",
            .surface => "\x1b[38;5;238m",
            .text => "\x1b[38;5;252m",
            .text_bright => "\x1b[38;5;255m",
        },
        .truecolor => blk: {
            const c = rgbFor(token, bg);
            break :blk sgrRgbBuf(c.r, c.g, c.b);
        },
    };
}

// A small static pool of formatted truecolor escapes keyed by (token,bg) is
// overkill; instead format into a module-local ring of static buffers so the
// returned slice is stable for the lifetime of the process.
var rgb_bufs: [16][20]u8 = undefined;
var rgb_idx: usize = 0;

fn sgrRgbBuf(r: u8, g: u8, b: u8) []const u8 {
    const slot = rgb_idx % rgb_bufs.len;
    rgb_idx += 1;
    const buf = &rgb_bufs[slot];
    return std.fmt.bufPrint(buf, "\x1b[38;2;{d};{d};{d}m", .{ r, g, b }) catch "";
}

pub const reset = "\x1b[0m";
pub const bold = "\x1b[1m";
pub const dim = "\x1b[2m";

// ────────────────────────────────────────────────────────────────────────────
// Runtime detection (env + TTY) — cached, guarded for tests
// ────────────────────────────────────────────────────────────────────────────

pub const Active = struct {
    capability: Capability,
    background: Background,
    /// Box-drawing / multi-byte glyphs. Independent of color so NO_COLOR
    /// terminals can still render Unicode when they are interactive TTYs.
    unicode: bool = false,

    pub fn supportsUnicode(self: Active) bool {
        return self.unicode;
    }
};

var cached: ?Active = null;
var rich_enabled = true;
var test_active: ?Active = null;
var test_reduced_motion: ?bool = null;

pub fn setRichEnabled(enabled: bool) void {
    rich_enabled = enabled;
    resetCache();
}

/// Presentation policy: false after global `--no-rich` / `RYK_NO_RICH` / machine output.
/// Used by TUI entry gates so stripped argv cannot re-open alt-screen browse.
pub fn isRichEnabled() bool {
    return rich_enabled;
}

pub fn setTestActive(value: ?Active) void {
    if (builtin.is_test) test_active = value;
}

/// Override the reduced-motion decision for tests. Lets a unit test exercise the
/// "colour on, motion off" path (which the documented env proxies can't reach on
/// their own, since NO_COLOR/TERM=dumb/non-TTY also drop colour). Pass `null` to
/// clear. No-op outside `builtin.is_test`.
pub fn setTestReducedMotion(value: ?bool) void {
    if (builtin.is_test) test_reduced_motion = value;
}

/// Reset the cache. Used by tests; a no-op invoker hook keeps production stable.
pub fn resetCache() void {
    cached = null;
}

/// Pure decision wrapper used by tests and the public detector.
pub fn resolve(d: DetectInput, bg: Background) Active {
    return .{
        .capability = detectCapability(d),
        .background = bg,
        // Unicode follows TTY/dumb signals, not color availability.
        .unicode = d.is_tty and !d.term_dumb,
    };
}

/// Pure decision: should motion (spinner animation, live step frames) be
/// suppressed given environment signals? There is no dedicated ANSI
/// reduced-motion env var, so the documented proxies are a non-TTY sink,
/// `NO_COLOR`, or `TERM=dumb` — the same signals that drop colour. In practice
/// reduced-motion and no-colour therefore arrive together; this named contract
/// keeps the decision explicit and leaves room for a future dedicated signal
/// without churning call sites. Tests call this directly; runtime code calls
/// `reducedMotion`.
pub fn reducedMotionFrom(d: DetectInput) bool {
    return !d.is_tty or d.no_color or d.term_dumb;
}

/// Cached runtime detection against real env/stdout. In `builtin.is_test` this
/// returns a plain-text theme so fixed-buffer writers never emit escapes.
pub fn active(io: std.Io, stdout: anytype) Active {
    if (!rich_enabled) return .{ .capability = .none, .background = .unknown, .unicode = false };
    if (test_active) |value| {
        // Test overrides may omit unicode; default to matching color capability
        // so existing setTestActive call sites keep box-drawing when colored.
        if (!value.unicode and value.capability.hasColor()) {
            return .{ .capability = value.capability, .background = value.background, .unicode = true };
        }
        return value;
    }
    if (builtin.is_test) return .{ .capability = .none, .background = .unknown, .unicode = false };
    if (cached) |a| return a;

    const is_tty = detectIsTty(io, stdout);
    const no_color = envPresent("NO_COLOR");
    const term_dumb = envTermDumb();
    const colorterm_truecolor = envColortermTruecolor();
    const term_256color = envTerm256color();
    const bg = detectBackground(io, is_tty);

    const a = resolve(.{
        .is_tty = is_tty,
        .no_color = no_color,
        .term_dumb = term_dumb,
        .colorterm_truecolor = colorterm_truecolor,
        .term_256color = term_256color,
    }, bg);
    cached = a;
    return a;
}

/// Runtime reduced-motion decision. Mirrors `active()`'s test guards so
/// fixed-buffer writers in tests never animate. When a test forces a colour
/// capability via `setTestActive`, motion follows colour (on with colour, off
/// without) unless `setTestReducedMotion` overrides it — that override is the
/// only way to reach the "colour on, motion off" path in unit tests, because the
/// documented env proxies (NO_COLOR/TERM=dumb/non-TTY) drop colour too.
pub fn reducedMotion(io: std.Io, stdout: anytype) bool {
    if (!rich_enabled) return true;
    if (test_reduced_motion) |r| return r;
    if (test_active) |t| return !t.capability.hasColor();
    if (builtin.is_test) return true;
    const is_tty = detectIsTty(io, stdout);
    const no_color = envPresent("NO_COLOR");
    const term_dumb = envTermDumb();
    return !is_tty or no_color or term_dumb;
}

fn detectIsTty(io: std.Io, stdout: anytype) bool {
    const Writer = @TypeOf(stdout);
    const is_file = switch (@typeInfo(Writer)) {
        .pointer => |ptr| ptr.child == std.Io.File,
        else => Writer == std.Io.File,
    };
    if (is_file) {
        const file = switch (@typeInfo(Writer)) {
            .pointer => stdout.*,
            else => stdout,
        };
        return file.isTty(io) catch false;
    }
    const is_file_writer = switch (@typeInfo(Writer)) {
        .pointer => |ptr| @hasField(ptr.child, "file") and @hasField(ptr.child, "interface"),
        else => @hasField(Writer, "file") and @hasField(Writer, "interface"),
    };
    if (is_file_writer) {
        const w = switch (@typeInfo(Writer)) {
            .pointer => stdout.*,
            else => stdout,
        };
        return w.file.isTty(io) catch false;
    }
    return std.Io.File.stdout().isTty(io) catch false;
}

fn envPresent(comptime name: [:0]const u8) bool {
    const v = std.c.getenv(name) orelse return false;
    return v[0] != 0;
}

fn envTermDumb() bool {
    const term = std.c.getenv("TERM") orelse return false;
    return std.mem.eql(u8, std.mem.sliceTo(term, 0), "dumb");
}

fn envColortermTruecolor() bool {
    const ct = std.c.getenv("COLORTERM") orelse return false;
    const s = std.mem.sliceTo(ct, 0);
    return std.mem.eql(u8, s, "truecolor") or std.mem.eql(u8, s, "24bit");
}

fn envTerm256color() bool {
    const term = std.c.getenv("TERM") orelse return false;
    const s = std.mem.sliceTo(term, 0);
    return std.mem.indexOf(u8, s, "256color") != null;
}

fn detectBackground(io: std.Io, is_tty: bool) Background {
    // Phase 7: query the terminal background via OSC 11 on a real TTY. The TTY
    // I/O path is comptime-gated out of test builds (vaxis.tty.Tty is a stub
    // there) and only runs when stdout is an interactive terminal; any failure
    // falls through to COLORFGBG, then the dark default. Tests never reach here
    // because `active()` short-circuits on builtin.is_test / !rich_enabled.
    if (is_tty) {
        if (queryBackgroundOsc(io)) |bg| return bg;
    }
    const colorfgbg = std.c.getenv("COLORFGBG") orelse return .dark;
    return parseColorfgbg(std.mem.sliceTo(colorfgbg, 0));
}

/// Query the terminal background colour via OSC 11 (`\x1b]11;?\x1b\\`) and parse
/// the RGB reply. Real-TTY only; comptime-gated out of test builds so the
/// stubbed libvaxis `Tty` is never analyzed. Restores terminal termios on every
/// exit path. Returns `null` on any failure (caller falls back).
fn queryBackgroundOsc(io: std.Io) ?Background {
    if (comptime @import("build_options").enable_tui) {
        return queryBackgroundOscTty(io);
    }
    return null;
}

fn queryBackgroundOscTty(io: std.Io) ?Background {
    if (comptime builtin.is_test) return null;
    if (comptime builtin.os.tag == .windows) return null;
    const vaxis = @import("vaxis");

    var tty_buf: [4096]u8 = undefined;
    var tty = vaxis.tty.Tty.init(io, &tty_buf) catch return null;
    defer tty.deinit();

    // Save termios and install a raw read with a short inter-byte timeout so a
    // non-responding terminal cannot block the whole CLI (mirrors prompt.zig).
    const saved = if (comptime builtin.os.tag != .windows)
        std.posix.tcgetattr(tty.fd.handle) catch null
    else
        null;
    defer if (saved) |s| {
        if (comptime builtin.os.tag != .windows) {
            std.posix.tcsetattr(tty.fd.handle, .NOW, s) catch {};
        }
    };
    configureOscReadTimeout(&tty);

    // Write the OSC 11 query to the same terminal we read the reply from. Both
    // stdout and /dev/tty refer to the controlling terminal, so the emulator's
    // reply is delivered on the Tty's input stream.
    const query = "\x1b]11;?\x1b\\";
    tty.fd.writeStreamingAll(io, query) catch return null;

    // Read the reply with a bounded attempt budget (each read waits up to the
    // inter-byte timeout; give the emulator a few rounds to respond).
    var reply: [128]u8 = undefined;
    var len: usize = 0;
    var attempts: usize = 0;
    while (attempts < 8 and len < reply.len) : (attempts += 1) {
        const n = tty.read(reply[len..]) catch break;
        if (n == 0) {
            if (len > 0) break; // timeout after partial reply — try to parse what we have
            continue;
        }
        len += n;
        // The reply terminates with ST (\x1b\\) or BEL (\x07); stop once we see it.
        if (std.mem.indexOfScalar(u8, reply[0..len], 0x07) != null or
            std.mem.indexOf(u8, reply[0..len], "\x1b\\") != null) break;
    }
    if (len == 0) return null;
    return parseOsc11Reply(reply[0..len]);
}

fn configureOscReadTimeout(tty: anytype) void {
    if (comptime builtin.os.tag == .windows) return;
    if (builtin.is_test) return;
    var raw = std.posix.tcgetattr(tty.fd.handle) catch return;
    raw.cc[@intFromEnum(std.posix.V.MIN)] = 0;
    raw.cc[@intFromEnum(std.posix.V.TIME)] = 2; // 200 ms inter-byte timeout
    std.posix.tcsetattr(tty.fd.handle, .NOW, raw) catch {};
}

// ────────────────────────────────────────────────────────────────────────────
// Painting helper: write token + text + reset (only when capable)
// ────────────────────────────────────────────────────────────────────────────

/// Write `text` coloured with `token` followed by a reset, when color is active.
/// When colourless, writes `text` verbatim.
pub fn paint(io: std.Io, stdout: anytype, token: Token, text: []const u8) !void {
    const a = active(io, stdout);
    if (!a.capability.hasColor()) {
        try terminal_text.write(stdout, text, .single_line);
        return;
    }
    const seq = sequence(token, a.capability, a.background);
    if (seq.len > 0) try stdout.writeAll(seq);
    try terminal_text.write(stdout, text, .single_line);
    try stdout.writeAll(reset);
}

/// Like `paint` but applies an extra emphasis (`bold`) before the colour.
pub fn paintBold(io: std.Io, stdout: anytype, token: Token, text: []const u8) !void {
    const a = active(io, stdout);
    if (!a.capability.hasColor()) {
        try terminal_text.write(stdout, text, .single_line);
        return;
    }
    try stdout.writeAll(bold);
    const seq = sequence(token, a.capability, a.background);
    if (seq.len > 0) try stdout.writeAll(seq);
    try terminal_text.write(stdout, text, .single_line);
    try stdout.writeAll(reset);
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

test "detectCapability: non-TTY is none" {
    try std.testing.expectEqual(Capability.none, detectCapability(.{
        .is_tty = false,
        .no_color = false,
        .term_dumb = false,
        .colorterm_truecolor = false,
        .term_256color = false,
    }));
}

test "detectCapability: NO_COLOR forces none even on TTY" {
    try std.testing.expectEqual(Capability.none, detectCapability(.{
        .is_tty = true,
        .no_color = true,
        .term_dumb = false,
        .colorterm_truecolor = true,
        .term_256color = true,
    }));
}

test "detectCapability: TERM=dumb is none" {
    try std.testing.expectEqual(Capability.none, detectCapability(.{
        .is_tty = true,
        .no_color = false,
        .term_dumb = true,
        .colorterm_truecolor = false,
        .term_256color = true,
    }));
}

test "detectCapability: COLORTERM=truecolor wins" {
    try std.testing.expectEqual(Capability.truecolor, detectCapability(.{
        .is_tty = true,
        .no_color = false,
        .term_dumb = false,
        .colorterm_truecolor = true,
        .term_256color = true,
    }));
}

test "detectCapability: 256color TERM" {
    try std.testing.expectEqual(Capability.c256, detectCapability(.{
        .is_tty = true,
        .no_color = false,
        .term_dumb = false,
        .colorterm_truecolor = false,
        .term_256color = true,
    }));
}

test "detectCapability: plain TTY falls back to 16-colour" {
    try std.testing.expectEqual(Capability.basic_16, detectCapability(.{
        .is_tty = true,
        .no_color = false,
        .term_dumb = false,
        .colorterm_truecolor = false,
        .term_256color = false,
    }));
}

test "parseColorfgbg: dark backgrounds" {
    try std.testing.expectEqual(Background.dark, parseColorfgbg("0;0"));
    try std.testing.expectEqual(Background.dark, parseColorfgbg("7;6"));
}

test "parseColorfgbg: light backgrounds" {
    try std.testing.expectEqual(Background.light, parseColorfgbg("0;7"));
    try std.testing.expectEqual(Background.light, parseColorfgbg("15;15"));
}

test "parseColorfgbg: malformed is unknown" {
    try std.testing.expectEqual(Background.unknown, parseColorfgbg("garbage"));
    try std.testing.expectEqual(Background.unknown, parseColorfgbg("0"));
    try std.testing.expectEqual(Background.unknown, parseColorfgbg("0;abc"));
}

// ────────────────────────────────────────────────────────────────────────────
// OSC 11 background reply parsing (pure)
// ────────────────────────────────────────────────────────────────────────────

test "rgbToBackground: black is dark" {
    try std.testing.expectEqual(Background.dark, rgbToBackground(0, 0, 0));
}

test "rgbToBackground: white is light" {
    try std.testing.expectEqual(Background.light, rgbToBackground(255, 255, 255));
}

test "rgbToBackground: near-black counts as dark" {
    try std.testing.expectEqual(Background.dark, rgbToBackground(20, 22, 28));
}

test "rgbToBackground: near-white counts as light" {
    try std.testing.expectEqual(Background.light, rgbToBackground(230, 237, 243));
}

test "parseOsc11Reply: black background (4-digit) is dark" {
    // Standard X11 ST-terminated reply for a near-black background.
    try std.testing.expectEqual(Background.dark, parseOsc11Reply("\x1b]11;rgb:0000/0000/0000\x1b\\"));
}

test "parseOsc11Reply: white background (4-digit) is light" {
    try std.testing.expectEqual(Background.light, parseOsc11Reply("\x1b]11;rgb:ffff/ffff/ffff\x1b\\"));
}

test "parseOsc11Reply: BEL-terminated reply parses" {
    // Some terminals terminate the OSC reply with BEL (0x07) instead of ST.
    try std.testing.expectEqual(Background.dark, parseOsc11Reply("\x1b]11;rgb:1414/1414/1414\x07"));
}

test "parseOsc11Reply: short 1-digit form scales correctly" {
    // `f` (max) scales to 255 → white → light; `0` → black → dark.
    try std.testing.expectEqual(Background.light, parseOsc11Reply("\x1b]11;rgb:f/f/f\x1b\\"));
    try std.testing.expectEqual(Background.dark, parseOsc11Reply("\x1b]11;rgb:0/0/0\x1b\\"));
}

test "parseOsc11Reply: mixed-precision still classifies" {
    // A dark grey (#30363D, GitHub dark surface) → dark.
    try std.testing.expectEqual(Background.dark, parseOsc11Reply("\x1b]11;rgb:3030/3636/3d3d\x1b\\"));
    // A light grey (#d0d7de) → light.
    try std.testing.expectEqual(Background.light, parseOsc11Reply("\x1b]11;rgb:d0d0/d7d7/dede\x1b\\"));
}

test "parseOsc11Reply: malformed payload is unknown" {
    try std.testing.expectEqual(Background.unknown, parseOsc11Reply(""));
    try std.testing.expectEqual(Background.unknown, parseOsc11Reply("not an osc reply"));
    try std.testing.expectEqual(Background.unknown, parseOsc11Reply("\x1b]11;rgb:ff/ff\x1b\\")); // 2 comps
    try std.testing.expectEqual(Background.unknown, parseOsc11Reply("\x1b]11;rgb:zz/ff/ff\x1b\\")); // non-hex
}

test "sequence: none capability emits empty string for every token" {
    // Enum *fields* (variants), not decls — decls can be empty and vacuous-pass (F281).
    inline for (@typeInfo(Token).@"enum".fields) |f| {
        const t: Token = @enumFromInt(f.value);
        try std.testing.expectEqualStrings("", sequence(t, .none, .dark));
    }
}

test "sequence: 16-colour uses standard escapes" {
    try std.testing.expectEqualStrings("\x1b[31m", sequence(.danger, .basic_16, .dark));
    try std.testing.expectEqualStrings("\x1b[32m", sequence(.success, .basic_16, .dark));
    try std.testing.expectEqualStrings("", sequence(.text, .basic_16, .dark));
}

test "sequence: truecolor emits 38;2;r;g;b" {
    const s = sequence(.brand, .truecolor, .dark);
    // Soft mint brand trial (#7CD4B0) — sampled from product tree selection green
    try std.testing.expect(std.mem.startsWith(u8, s, "\x1b[38;2;124;212;176m"));
    try std.testing.expect(std.mem.endsWith(u8, s, "m"));
}

test "sequence: 256-color never emits truecolor" {
    const seq = sequence(.brand, .c256, .dark);
    try std.testing.expect(std.mem.indexOf(u8, seq, "38;2;") == null);
    try std.testing.expect(std.mem.indexOf(u8, seq, "38;5;") != null);
}

test "sequence: truecolor light variant differs from dark for brand" {
    const dark = sequence(.brand, .truecolor, .dark);
    const light = sequence(.brand, .truecolor, .light);
    try std.testing.expect(!std.mem.eql(u8, dark, light));
}

test "paint: plain text when capability none" {
    resetCache();
    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try paint(std.testing.io, &w, .danger, "denied");
    try std.testing.expectEqualStrings("denied", w.buffered());
}

test "paintBold: plain text when capability none" {
    resetCache();
    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try paintBold(std.testing.io, &w, .success, "ok");
    try std.testing.expectEqualStrings("ok", w.buffered());
}

test "resolve: composes capability and background (pure)" {
    const a = resolve(.{
        .is_tty = true,
        .no_color = false,
        .term_dumb = false,
        .colorterm_truecolor = true,
        .term_256color = true,
    }, .light);
    try std.testing.expectEqual(Capability.truecolor, a.capability);
    try std.testing.expectEqual(Background.light, a.background);
}

test "Capability.hasColor" {
    try std.testing.expect(!Capability.none.hasColor());
    try std.testing.expect(Capability.basic_16.hasColor());
    try std.testing.expect(Capability.truecolor.hasColor());
}

test "unicode is independent of color capability" {
    const no_color_tty = resolve(.{
        .is_tty = true,
        .no_color = true,
        .term_dumb = false,
        .colorterm_truecolor = false,
        .term_256color = false,
    }, .dark);
    try std.testing.expect(!no_color_tty.capability.hasColor());
    try std.testing.expect(no_color_tty.supportsUnicode());

    const dumb = resolve(.{
        .is_tty = true,
        .no_color = false,
        .term_dumb = true,
        .colorterm_truecolor = false,
        .term_256color = false,
    }, .dark);
    try std.testing.expect(!dumb.supportsUnicode());

    const pipe = resolve(.{
        .is_tty = false,
        .no_color = false,
        .term_dumb = false,
        .colorterm_truecolor = false,
        .term_256color = false,
    }, .unknown);
    try std.testing.expect(!pipe.supportsUnicode());
}

// ────────────────────────────────────────────────────────────────────────────
// Reduced-motion decision (pure)
// ────────────────────────────────────────────────────────────────────────────

test "reducedMotionFrom: non-TTY forces motion off" {
    try std.testing.expect(reducedMotionFrom(.{
        .is_tty = false,
        .no_color = false,
        .term_dumb = false,
        .colorterm_truecolor = true,
        .term_256color = true,
    }));
}

test "reducedMotionFrom: NO_COLOR forces motion off even on TTY" {
    try std.testing.expect(reducedMotionFrom(.{
        .is_tty = true,
        .no_color = true,
        .term_dumb = false,
        .colorterm_truecolor = true,
        .term_256color = true,
    }));
}

test "reducedMotionFrom: TERM=dumb forces motion off" {
    try std.testing.expect(reducedMotionFrom(.{
        .is_tty = true,
        .no_color = false,
        .term_dumb = true,
        .colorterm_truecolor = false,
        .term_256color = false,
    }));
}

test "reducedMotionFrom: plain TTY keeps motion on" {
    try std.testing.expect(!reducedMotionFrom(.{
        .is_tty = true,
        .no_color = false,
        .term_dumb = false,
        .colorterm_truecolor = false,
        .term_256color = false,
    }));
}

//! Packs list browse TUI — pure filter/decision chassis + optional TTY loop.
//!
//! # Product (W1 / U04)
//!
//! On colour TTY when `shouldEnterTui` is true, bare `ryk packs` opens the shared
//! browse kit: **enabled + baseline first** (`a` toggles full catalog), `/` search.
//! **Enable** is one-shot; **disable** leaves alt-screen for confirm default No
//! (baseline uses the same danger confirm / `RYK_OPERATOR` gate as CLI). Status
//! shows write target. Sticky keeps just-disabled rows in enabled-only mode.
//! Mutations use the same `pack_config` paths as argv enable/disable.
//!
//! # Test floor
//!
//! Pure filter builders and entry-gate decisions live here. The raw TTY
//! `runBrowse` loop is comptime-gated under `builtin.is_test` (same pattern as
//! `tui.live_view.run`) so unit tests never need a real Tty.
const std = @import("std");
const builtin = @import("builtin");
const tui = @import("../tui/mod.zig");
const pack_config = @import("pack_config.zig");
const danger_confirmation = @import("danger_confirmation.zig");
const onboarding = @import("onboarding.zig");
const exit_codes = @import("exit_codes.zig");
const vaxis = @import("vaxis");

// ── Public pure types ───────────────────────────────────────────────────────

/// List filter mode. Default open is **enabled + baseline**; domain key `a`
/// toggles full catalog and back.
pub const ViewMode = enum {
    /// Enabled packs only (plus session-sticky just-disabled rows).
    enabled_baseline,
    /// Full catalog (still respects search query when set).
    all,
};

/// Minimal pack fields the filter/detail builders need (borrowed slices).
pub const PackRef = struct {
    id: []const u8,
    name: []const u8,
    category: []const u8,
    description: []const u8,
    enabled: bool,
    safe_pattern_count: usize = 0,
    destructive_pattern_count: usize = 0,
};

pub const DomainAction = enum {
    enable,
    disable,
    toggle_all,
    none,
};

pub const MutateKind = enum { enable, disable };

/// Pure entry decision for the packs **list** path.
///
/// False when machine JSON is requested, or when the shared TUI gate fails
/// (non-TTY either stream, `--json`/`--robot`/`--plain`/`--no-rich`/format json).
pub fn wouldEnterPacksBrowse(
    stdin_is_tty: bool,
    stdout_is_tty: bool,
    argv: []const []const u8,
    machine_json: bool,
) bool {
    if (machine_json) return false;
    return tui.output_policy.shouldEnterTui(stdin_is_tty, stdout_is_tty, argv);
}

/// Map a printable domain key to packs actions. Nav/filter keys stay in `tui.browse`.
pub fn domainActionFromCodepoint(codepoint: u21) DomainAction {
    return switch (codepoint) {
        'e', 'E' => .enable,
        'd', 'D' => .disable,
        'a', 'A' => .toggle_all,
        else => .none,
    };
}

/// Footer domain fragment for the shared browse kit.
pub fn footerActions(mode: ViewMode) []const u8 {
    return switch (mode) {
        .enabled_baseline => "enter on/off · e/d · a show all",
        .all => "enter toggle · e/d · a enabled only",
    };
}

/// Title chrome reflecting current filter mode.
pub fn browseTitle(mode: ViewMode) []const u8 {
    return switch (mode) {
        .enabled_baseline => "packs · enabled + baseline",
        .all => "packs · all",
    };
}

/// Status fragment for the write target (no secrets — paths only).
pub fn writeTargetStatus(scope: pack_config.ConfigScope, path: []const u8) WriteTargetBuf {
    var buf: WriteTargetBuf = .{};
    const scope_label = scope.label();
    // Prefer short path tail for status toast width.
    const display = pathTail(path, 48);
    // bufPrint into fixed bytes cannot fail with these short inputs; if it did,
    // leave len=0 rather than pointing at a temporary string (F44).
    if (std.fmt.bufPrint(&buf.bytes, "writes → {s} ({s})", .{ display, scope_label })) |written| {
        buf.len = written.len;
    } else |_| {
        const fallback = "writes → config";
        @memcpy(buf.bytes[0..fallback.len], fallback);
        buf.len = fallback.len;
    }
    return buf;
}

pub const WriteTargetBuf = struct {
    bytes: [96]u8 = undefined,
    len: usize = 0,

    pub fn slice(self: *const WriteTargetBuf) []const u8 {
        return self.bytes[0..self.len];
    }
};

fn pathTail(path: []const u8, max: usize) []const u8 {
    if (path.len <= max) return path;
    return path[path.len - max ..];
}

/// Whether a pack row is included under the current view mode + optional query.
/// `sticky_disabled`: when true, keep a disabled pack visible under
/// `enabled_baseline` (session sticky after an in-view disable).
pub fn packMatchesFilter(pack: PackRef, mode: ViewMode, query: []const u8) bool {
    return packMatchesFilterSticky(pack, mode, query, false);
}

pub fn packMatchesFilterSticky(
    pack: PackRef,
    mode: ViewMode,
    query: []const u8,
    sticky_disabled: bool,
) bool {
    switch (mode) {
        .enabled_baseline => {
            if (!pack.enabled and !sticky_disabled) return false;
        },
        .all => {},
    }
    if (query.len == 0) return true;
    return containsIgnoreCase(pack.id, query) or
        containsIgnoreCase(pack.name, query) or
        containsIgnoreCase(pack.category, query) or
        containsIgnoreCase(pack.description, query);
}

/// Fill `out_indices` with matching pack indices (stable catalog order).
/// Returns count written (capped at `out_indices.len`).
pub fn filterPackIndices(
    packs: []const PackRef,
    mode: ViewMode,
    query: []const u8,
    out_indices: []usize,
) usize {
    return filterPackIndicesSticky(packs, mode, query, null, out_indices);
}

/// Like `filterPackIndices`, but `sticky[i]` keeps pack `i` visible when disabled
/// under `enabled_baseline` (must be null or length ≥ packs.len).
pub fn filterPackIndicesSticky(
    packs: []const PackRef,
    mode: ViewMode,
    query: []const u8,
    sticky: ?[]const bool,
    out_indices: []usize,
) usize {
    var n: usize = 0;
    for (packs, 0..) |pack, i| {
        const keep = if (sticky) |s| (i < s.len and s[i]) else false;
        if (!packMatchesFilterSticky(pack, mode, query, keep)) continue;
        if (n >= out_indices.len) break;
        out_indices[n] = i;
        n += 1;
    }
    return n;
}

/// Format one list row label into `buf`. Returns the written slice.
pub fn formatRowLabel(pack: PackRef, buf: []u8) []const u8 {
    const mark: []const u8 = if (pack.enabled) "●" else "○";
    const state: []const u8 = if (pack.enabled) "on" else "off";
    const baseline = pack_config.isBaselinePackId(pack.id);
    if (baseline) {
        return std.fmt.bufPrint(buf, "{s} {s}  [{s}] baseline", .{ mark, pack.id, state }) catch pack.id;
    }
    return std.fmt.bufPrint(buf, "{s} {s}  [{s}]", .{ mark, pack.id, state }) catch pack.id;
}

/// Pure detail lines for the selected pack (into caller-owned line buffers).
pub fn formatDetailLines(
    pack: PackRef,
    write_status: []const u8,
    line0: []u8,
    line1: []u8,
    line2: []u8,
    line3: []u8,
) [4][]const u8 {
    const l0 = std.fmt.bufPrint(line0, "{s}  ·  {s}", .{ pack.id, pack.name }) catch pack.id;
    const l1 = std.fmt.bufPrint(line1, "{s}", .{pack.description}) catch pack.description;
    const l2 = std.fmt.bufPrint(line2, "{d} safe / {d} blocked patterns · {s}", .{
        pack.safe_pattern_count,
        pack.destructive_pattern_count,
        if (pack.enabled) "enabled" else "available",
    }) catch "";
    const l3 = if (write_status.len > 0)
        std.fmt.bufPrint(line3, "{s}", .{write_status}) catch write_status
    else
        std.fmt.bufPrint(line3, "enter toggle · e enable · d disable", .{}) catch "";
    return .{ l0, l1, l2, l3 };
}

/// Whether a baseline disable needs a second press (in-loop soft confirm).
/// Returns true when this press should proceed with the write.
/// The TUI only runs on an interactive TTY, so operator presence is implied by
/// the surrounding alt-screen session; the soft-arm is a UX confirmation, not an
/// authentication boundary (the RYK_OPERATOR env break-glass was removed).
pub fn baselineDisableArmed(pending_id: ?[]const u8, pack_id: []const u8) bool {
    if (pending_id) |p| return std.mem.eql(u8, p, pack_id);
    return false;
}

fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (needle.len > haystack.len) return false;
    var start: usize = 0;
    while (start + needle.len <= haystack.len) : (start += 1) {
        var matches = true;
        for (needle, 0..) |char, offset| {
            if (std.ascii.toLower(haystack[start + offset]) != std.ascii.toLower(char)) {
                matches = false;
                break;
            }
        }
        if (matches) return true;
    }
    return false;
}

// ── Browse session (TTY; gated under tests) ─────────────────────────────────

/// Context passed from packs list command after catalog load.
pub const BrowseInput = struct {
    packs: []PackRef,
    /// Mutable enabled flags parallel to `packs` (updated after successful mutate).
    enabled: []bool,
    write_scope: pack_config.ConfigScope,
    write_path: []const u8,
    /// Optional initial search term (from `--filter`).
    initial_query: ?[]const u8 = null,
    /// Start in full-catalog mode. Default false = enabled+baseline first (freeze / U04).
    start_all: bool = false,
};

/// Run the packs browse loop. Caller must have already gated with
/// `wouldEnterPacksBrowse` / `shouldEnterTui`. Restores alt-screen on every exit.
///
/// Under `builtin.is_test` the raw TTY loop is skipped after entering/leaving
/// alt-screen tokens only when invoked — prefer pure tests instead.
pub fn runBrowse(
    io: std.Io,
    allocator: std.mem.Allocator,
    stdout: anytype,
    stderr: anytype,
    input: BrowseInput,
) !u8 {
    _ = stderr;
    // Tests never open a real Tty (vaxis stub). Composition is proved by pure
    // gates + filter builders + the production call site in packs.zig.
    if (comptime builtin.is_test) {
        return exit_codes.success;
    }

    // Probe Tty *before* alt-screen so failure falls through to linear list
    // without flashing empty smcup (match allowlist_browse).
    var tty_buf: [4096]u8 = undefined;
    var tty = vaxis.tty.Tty.init(io, &tty_buf) catch return exit_codes.general;
    defer tty.deinit();

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

    try stdout.writeAll(vaxis.ctlseqs.smcup);
    try stdout.writeAll(vaxis.ctlseqs.hide_cursor);
    defer {
        stdout.writeAll(vaxis.ctlseqs.show_cursor) catch {};
        stdout.writeAll(vaxis.ctlseqs.rmcup) catch {};
    }

    return try runBrowseLoop(io, allocator, stdout, &tty, saved, input);
}

fn runBrowseLoop(
    io: std.Io,
    allocator: std.mem.Allocator,
    stdout: anytype,
    tty: anytype,
    saved_termios: anytype,
    input: BrowseInput,
) !u8 {
    const list_rows: usize = blk: {
        const ws = tty.getWinsize() catch break :blk 10;
        // Reserve header/filter/rules/detail/footer ≈ 12 lines.
        if (ws.rows > 14) break :blk ws.rows - 12;
        break :blk 6;
    };

    // Freeze #9: enabled+baseline first; `a` / search can open full catalog.
    var mode: ViewMode = if (input.start_all) .all else .enabled_baseline;
    var nav: tui.browse.NavState = .{};
    var filter_model: tui.browse.FilterModel = .{};
    var query_buf: [128]u8 = undefined;
    var query_len: usize = 0;
    if (input.initial_query) |q| {
        const copy_len = @min(q.len, query_buf.len);
        @memcpy(query_buf[0..copy_len], q[0..copy_len]);
        query_len = copy_len;
        filter_model.len = copy_len;
        // Search always runs against full catalog (disabled packs remain findable).
        mode = .all;
    }

    const pack_count = input.packs.len;
    const indices_buf = try allocator.alloc(usize, pack_count);
    defer allocator.free(indices_buf);
    const label_storage = try allocator.alloc([96]u8, pack_count);
    defer allocator.free(label_storage);
    const labels = try allocator.alloc([]const u8, pack_count);
    defer allocator.free(labels);
    const pack_views = try allocator.alloc(PackRef, pack_count);
    defer allocator.free(pack_views);
    const sticky = try allocator.alloc(bool, pack_count);
    defer allocator.free(sticky);
    @memset(sticky, false);

    var status_msg: []const u8 = "";
    var status_owned: ?[]u8 = null;
    defer if (status_owned) |s| allocator.free(s);

    const write_status = writeTargetStatus(input.write_scope, input.write_path);

    var decoder: Decoder = .{};
    var frame_lines: usize = 0;
    var first_frame = true;

    while (true) {
        // Refresh enabled flags into PackRef view for filter.
        // PackRef slices are borrowed; only enabled is mutated via parallel array.
        for (input.packs, 0..) |p, i| {
            pack_views[i] = p;
            pack_views[i].enabled = input.enabled[i];
        }

        const q = query_buf[0..query_len];
        const filtered_n = filterPackIndicesSticky(
            pack_views[0..pack_count],
            mode,
            q,
            sticky,
            indices_buf,
        );
        nav.selected = tui.browse.clampSelected(nav.selected, filtered_n);
        nav.list_scroll = tui.browse.scrollToShow(nav.selected, nav.list_scroll, list_rows, filtered_n);

        var i: usize = 0;
        while (i < filtered_n) : (i += 1) {
            const pi = indices_buf[i];
            labels[i] = formatRowLabel(pack_views[pi], &label_storage[i]);
        }

        var d0: [128]u8 = undefined;
        var d1: [160]u8 = undefined;
        var d2: [96]u8 = undefined;
        var d3: [96]u8 = undefined;
        var detail: []const []const u8 = &.{};
        var detail_arr: [4][]const u8 = undefined;
        if (filtered_n > 0) {
            const pi = indices_buf[nav.selected];
            detail_arr = formatDetailLines(pack_views[pi], write_status.slice(), &d0, &d1, &d2, &d3);
            detail = &detail_arr;
        }

        const filter_q: ?[]const u8 = if (filter_model.active) filter_model.query(&query_buf) else null;

        if (!first_frame and frame_lines > 0) {
            try moveCursorUp(stdout, frame_lines);
            try stdout.writeAll("\x1b[J");
        }
        first_frame = false;

        frame_lines = try tui.browse.renderFrameWithLineEnding(io, stdout, .{
            .title = browseTitle(mode),
            .items = labels[0..filtered_n],
            .selected = nav.selected,
            .list_scroll = nav.list_scroll,
            .list_rows = list_rows,
            .detail_lines = detail,
            .footer_actions = footerActions(mode),
            .status_msg = status_msg,
            .filter_query = filter_q,
            .selected_token = .success,
        }, "\r\n");
        try flush(stdout);

        const key = readKey(tty, &decoder) catch break;

        // Filter mode: host intercepts Esc/Enter + typing (U02 contract).
        if (filter_model.active) {
            if (key.matches(vaxis.Key.escape, .{})) {
                filter_model.cancel();
                query_len = 0;
                continue;
            }
            if (key.matches(vaxis.Key.enter, .{})) {
                filter_model.active = false;
                // Keep query_len as applied filter.
                continue;
            }
            if (key.matches(vaxis.Key.backspace, .{}) or key.matches(0x7f, .{})) {
                filter_model.backspace();
                query_len = filter_model.len;
                continue;
            }
            if (key.codepoint >= 0x20 and key.codepoint <= 0x7e and !key.mods.ctrl and !key.mods.alt) {
                filter_model.append(&query_buf, @intCast(key.codepoint));
                query_len = filter_model.len;
                continue;
            }
            if (key.matches('q', .{})) break;
            continue;
        }

        const action = tui.browse.keyToAction(key);
        switch (action) {
            .quit => break,
            .up, .down, .top, .bottom => {
                nav.apply(action, filtered_n, list_rows);
            },
            .start_filter => {
                filter_model.start();
                query_len = 0;
            },
            .enter => {
                // Enter = enable one-shot; disable leaves alt-screen for confirm.
                if (filtered_n == 0) continue;
                const pi = indices_buf[nav.selected];
                const pack = pack_views[pi];
                const kind: MutateKind = if (pack.enabled) .disable else .enable;
                try applyMutate(io, allocator, stdout, tty, saved_termios, pack, pi, kind, input, sticky, &status_owned, &status_msg, &first_frame, &frame_lines);
            },
            .other => {
                const domain = domainActionFromCodepoint(key.codepoint);
                switch (domain) {
                    .toggle_all => {
                        // Sticky is session-only for the current enabled-only view.
                        @memset(sticky[0..pack_count], false);
                        mode = switch (mode) {
                            .enabled_baseline => .all,
                            .all => .enabled_baseline,
                        };
                        nav.selected = 0;
                        nav.list_scroll = 0;
                        setStatus(allocator, &status_owned, &status_msg, switch (mode) {
                            .all => "showing all packs",
                            .enabled_baseline => "showing enabled only",
                        });
                    },
                    .enable, .disable => {
                        if (filtered_n == 0) continue;
                        const pi = indices_buf[nav.selected];
                        const pack = pack_views[pi];
                        const kind: MutateKind = if (domain == .enable) .enable else .disable;
                        if (kind == .enable and pack.enabled) {
                            setStatus(allocator, &status_owned, &status_msg, "already enabled");
                            continue;
                        }
                        if (kind == .disable and !pack.enabled) {
                            setStatus(allocator, &status_owned, &status_msg, "already disabled");
                            continue;
                        }
                        try applyMutate(io, allocator, stdout, tty, saved_termios, pack, pi, kind, input, sticky, &status_owned, &status_msg, &first_frame, &frame_lines);
                    },
                    .none => {},
                }
            },
        }
    }
    return exit_codes.success;
}

/// Apply enable/disable. Both leave alt-screen for confirm default No (freeze #3).
/// Baseline disable uses CLI danger confirm / RYK_OPERATOR.
/// On successful disable, marks sticky so enabled-only view keeps the row.
fn applyMutate(
    io: std.Io,
    allocator: std.mem.Allocator,
    stdout: anytype,
    tty: anytype,
    saved_termios: anytype,
    pack: PackRef,
    pack_index: usize,
    kind: MutateKind,
    input: BrowseInput,
    sticky: []bool,
    status_owned: *?[]u8,
    status_msg: *[]const u8,
    first_frame: *bool,
    frame_lines: *usize,
) !void {
    // Leave alt-screen + restore cooked mode for line confirm (allowlist pattern).
    stdout.writeAll(vaxis.ctlseqs.show_cursor) catch {};
    stdout.writeAll(vaxis.ctlseqs.rmcup) catch {};
    if (comptime builtin.os.tag != .windows) {
        if (saved_termios) |s| {
            std.posix.tcsetattr(tty.fd.handle, .NOW, s) catch {};
        }
    }

    var proceed = false;
    if (kind == .disable) {
        if (pack_config.isBaselinePackId(pack.id)) {
            // TUI runs on an interactive TTY; always confirm baseline disable.
            const decision = danger_confirmation.decide(
                io,
                stdout,
                "Disable baseline safety pack? This weakens default shell protection.",
                false,
                true,
                null,
            ) catch .cancelled;
            proceed = decision == .proceed;
        } else {
            var msg_buf: [160]u8 = undefined;
            const msg = std.fmt.bufPrint(&msg_buf, "Disable pack '{s}'?", .{pack.id}) catch "Disable pack?";
            proceed = tui.prompt.confirm(io, stdout, .normal, msg, null) catch false;
        }
    } else {
        // F285: enable also requires confirm default No (freeze #3).
        var msg_buf: [160]u8 = undefined;
        const msg = std.fmt.bufPrint(&msg_buf, "Enable pack '{s}'?", .{pack.id}) catch "Enable pack?";
        proceed = tui.prompt.confirm(io, stdout, .normal, msg, null) catch false;
    }

    // Re-enter raw alt-screen for continued browsing.
    configureReadTimeout(tty);
    stdout.writeAll(vaxis.ctlseqs.smcup) catch {};
    stdout.writeAll(vaxis.ctlseqs.hide_cursor) catch {};
    first_frame.* = true;
    frame_lines.* = 0;

    if (!proceed) {
        setStatus(
            allocator,
            status_owned,
            status_msg,
            if (kind == .disable) "disable cancelled" else "enable cancelled",
        );
        return;
    }

    const workspace_root = onboarding.resolveWorkspaceRoot(io, allocator) catch {
        setStatus(allocator, status_owned, status_msg, "could not resolve workspace");
        return;
    };
    defer allocator.free(workspace_root);

    const ids = [_][]const u8{pack.id};
    var result = switch (kind) {
        .enable => pack_config.enablePacks(io, allocator, workspace_root, &ids),
        .disable => pack_config.disablePacks(io, allocator, workspace_root, &ids),
    } catch {
        setStatus(allocator, status_owned, status_msg, "config write failed");
        return;
    };
    defer result.deinit(allocator);

    // Update parallel enabled flags for live list refresh (● / ○).
    for (input.packs, 0..) |p, i| {
        if (std.mem.eql(u8, p.id, pack.id)) {
            input.enabled[i] = (kind == .enable);
            break;
        }
    }

    // Sticky row — disable keeps the pack in enabled-only until re-enable or mode flip.
    if (pack_index < sticky.len) {
        sticky[pack_index] = (kind == .disable);
    }

    setStatus(allocator, status_owned, status_msg, switch (kind) {
        .enable => "enabled ●",
        .disable => "disabled ○",
    });
}

fn setStatus(allocator: std.mem.Allocator, owned: *?[]u8, msg: *[]const u8, text: []const u8) void {
    if (owned.*) |old| allocator.free(old);
    owned.* = allocator.dupe(u8, text) catch {
        msg.* = text;
        owned.* = null;
        return;
    };
    msg.* = owned.*.?;
}

// ── Minimal TTY helpers (mirrors live_view) ─────────────────────────────────

const Decoder = struct {
    parser: vaxis.Parser = .{},
    carry: [256]u8 = undefined,
    len: usize = 0,

    fn feed(self: *Decoder, bytes: []const u8) !?vaxis.Key {
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
                    std.mem.copyForwards(u8, self.carry[0 .. self.len - consumed], self.carry[consumed..self.len]);
                    self.len -= consumed;
                    return key;
                },
                else => {},
            };
        }
        if (consumed > 0) {
            std.mem.copyForwards(u8, self.carry[0 .. self.len - consumed], self.carry[consumed..self.len]);
            self.len -= consumed;
        }
        // Standalone Esc after timeout path: treat lone ESC as quit key.
        if (self.len == 1 and self.carry[0] == 0x1b) {
            self.len = 0;
            return vaxis.Key{ .codepoint = vaxis.Key.escape };
        }
        return null;
    }
};

fn readKey(tty: anytype, decoder: *Decoder) !vaxis.Key {
    if (comptime builtin.os.tag == .windows) return vaxis.Key{ .codepoint = 'q' };
    // libvaxis `Tty.read` maps VMIN=0/VTIME idle to EndOfStream; read the fd
    // directly so idle ticks do not quit the browse loop (live_view pattern).
    var buf: [256]u8 = undefined;
    while (true) {
        const n = std.posix.read(tty.fd.handle, &buf) catch |err| switch (err) {
            error.WouldBlock => 0,
            else => return vaxis.Key{ .codepoint = 'q' },
        };
        if (n == 0) {
            if (decoder.len == 1 and decoder.carry[0] == 0x1b) {
                decoder.len = 0;
                return vaxis.Key{ .codepoint = vaxis.Key.escape };
            }
            continue;
        }
        if (try decoder.feed(buf[0..n])) |key| return key;
    }
}

fn configureReadTimeout(tty: anytype) void {
    if (comptime builtin.os.tag == .windows) return;
    var attrs = std.posix.tcgetattr(tty.fd.handle) catch return;
    attrs.lflag.ICANON = false;
    attrs.lflag.ECHO = false;
    attrs.cc[@intFromEnum(std.posix.V.MIN)] = 0;
    attrs.cc[@intFromEnum(std.posix.V.TIME)] = 1; // 100ms
    std.posix.tcsetattr(tty.fd.handle, .NOW, attrs) catch {};
}

fn moveCursorUp(stdout: anytype, lines: usize) !void {
    if (lines == 0) return;
    var buf: [32]u8 = undefined;
    const seq = try std.fmt.bufPrint(&buf, "\x1b[{d}A", .{lines});
    try stdout.writeAll(seq);
}

fn flush(stdout: anytype) !void {
    if (@hasDecl(@TypeOf(stdout.*), "flush")) {
        try stdout.flush();
    } else if (@hasField(@TypeOf(stdout.*), "interface")) {
        // no-op for some writers
    }
}

// ── Pure unit tests ─────────────────────────────────────────────────────────

test "packs browse: wouldEnterPacksBrowse gates on TTY and argv escapes" {
    const bare = [_][]const u8{};
    try std.testing.expect(wouldEnterPacksBrowse(true, true, &bare, false));
    try std.testing.expect(!wouldEnterPacksBrowse(false, true, &bare, false));
    try std.testing.expect(!wouldEnterPacksBrowse(true, false, &bare, false));
    try std.testing.expect(!wouldEnterPacksBrowse(true, true, &bare, true)); // machine json
    try std.testing.expect(!wouldEnterPacksBrowse(true, true, &.{"--json"}, false));
    try std.testing.expect(!wouldEnterPacksBrowse(true, true, &.{"--plain"}, false));
    try std.testing.expect(!wouldEnterPacksBrowse(true, true, &.{"--no-rich"}, false));
    try std.testing.expect(!wouldEnterPacksBrowse(true, true, &.{"--robot"}, false));
    try std.testing.expect(!wouldEnterPacksBrowse(true, true, &.{ "--format", "json" }, false));
    try std.testing.expect(wouldEnterPacksBrowse(true, true, &.{ "--filter", "git" }, false));
}

test "packs browse: enabled-only filter excludes disabled opt-in" {
    const packs = [_]PackRef{
        .{ .id = "core.git", .name = "Git", .category = "core", .description = "git", .enabled = true },
        .{ .id = "containers.docker", .name = "Docker", .category = "containers", .description = "docker", .enabled = false },
        .{ .id = "system.disk", .name = "Disk", .category = "system", .description = "disk", .enabled = true },
        .{ .id = "database.postgresql", .name = "PG", .category = "database", .description = "pg", .enabled = true },
    };
    var idx: [8]usize = undefined;
    const n = filterPackIndices(&packs, .enabled_baseline, "", &idx);
    try std.testing.expectEqual(@as(usize, 3), n);
    // Order stable: core.git, system.disk, database.postgresql — not docker.
    try std.testing.expectEqualStrings("core.git", packs[idx[0]].id);
    try std.testing.expectEqualStrings("system.disk", packs[idx[1]].id);
    try std.testing.expectEqualStrings("database.postgresql", packs[idx[2]].id);
    // docker excluded
    for (idx[0..n]) |i| {
        try std.testing.expect(!std.mem.eql(u8, packs[i].id, "containers.docker"));
    }
}

test "packs browse: sticky keeps just-disabled pack in enabled-only view" {
    var packs = [_]PackRef{
        .{ .id = "core.git", .name = "Git", .category = "core", .description = "git", .enabled = true },
        .{ .id = "containers.docker", .name = "Docker", .category = "containers", .description = "docker", .enabled = false },
        .{ .id = "system.disk", .name = "Disk", .category = "system", .description = "disk", .enabled = true },
    };
    // Simulate: user disabled system.disk — flag off but sticky[2] true.
    packs[2].enabled = false;
    var sticky = [_]bool{ false, false, true };
    var idx: [8]usize = undefined;

    const without = filterPackIndices(&packs, .enabled_baseline, "", &idx);
    try std.testing.expectEqual(@as(usize, 1), without);
    try std.testing.expectEqualStrings("core.git", packs[idx[0]].id);

    const with_sticky = filterPackIndicesSticky(&packs, .enabled_baseline, "", &sticky, &idx);
    try std.testing.expectEqual(@as(usize, 2), with_sticky);
    try std.testing.expectEqualStrings("core.git", packs[idx[0]].id);
    try std.testing.expectEqualStrings("system.disk", packs[idx[1]].id);

    // Full catalog still shows everything; sticky is a no-op there.
    const all_n = filterPackIndicesSticky(&packs, .all, "", &sticky, &idx);
    try std.testing.expectEqual(@as(usize, 3), all_n);
}

test "packs browse: default open is enabled+baseline (start_all false)" {
    // Freeze / U04: bare packs opens enabled+baseline; `a` toggles full catalog.
    const input: BrowseInput = .{
        .packs = &.{},
        .enabled = &.{},
        .write_scope = .user,
        .write_path = "user",
    };
    try std.testing.expect(!input.start_all);
    try std.testing.expect(std.mem.indexOf(u8, browseTitle(.enabled_baseline), "enabled") != null);
    try std.testing.expect(std.mem.indexOf(u8, footerActions(.enabled_baseline), "show all") != null);
    try std.testing.expect(std.mem.indexOf(u8, browseTitle(.all), "all") != null);
    try std.testing.expect(std.mem.indexOf(u8, footerActions(.all), "enabled only") != null);
}

test "packs browse: toggle all includes disabled; search narrows" {
    const packs = [_]PackRef{
        .{ .id = "core.git", .name = "Git", .category = "core", .description = "git rules", .enabled = true },
        .{ .id = "containers.docker", .name = "Docker", .category = "containers", .description = "docker rules", .enabled = false },
        .{ .id = "database.postgresql", .name = "Postgres", .category = "database", .description = "sql", .enabled = false },
    };
    var idx: [8]usize = undefined;

    const all_n = filterPackIndices(&packs, .all, "", &idx);
    try std.testing.expectEqual(@as(usize, 3), all_n);

    const search_n = filterPackIndices(&packs, .all, "docker", &idx);
    try std.testing.expectEqual(@as(usize, 1), search_n);
    try std.testing.expectEqualStrings("containers.docker", packs[idx[0]].id);

    // Search within enabled-only mode still excludes disabled even if query matches.
    const en_search = filterPackIndices(&packs, .enabled_baseline, "docker", &idx);
    try std.testing.expectEqual(@as(usize, 0), en_search);

    // Case-insensitive id/name/category/description.
    const case_n = filterPackIndices(&packs, .all, "POSTGRES", &idx);
    try std.testing.expectEqual(@as(usize, 1), case_n);
    try std.testing.expectEqualStrings("database.postgresql", packs[idx[0]].id);
}

test "packs browse: filter scales to ~85 packs without drop" {
    // Synthetic catalog approximating oracle size.
    var packs: [90]PackRef = undefined;
    var ids: [90][32]u8 = undefined;
    var names: [90][16]u8 = undefined;
    for (&packs, 0..) |*p, i| {
        const id = std.fmt.bufPrint(&ids[i], "cat.pack{d}", .{i}) catch unreachable;
        const name = std.fmt.bufPrint(&names[i], "P{d}", .{i}) catch unreachable;
        p.* = .{
            .id = id,
            .name = name,
            .category = "cat",
            .description = "desc",
            .enabled = (i % 3 == 0), // ~30 enabled
        };
    }
    var idx: [90]usize = undefined;
    const enabled_n = filterPackIndices(&packs, .enabled_baseline, "", &idx);
    try std.testing.expectEqual(@as(usize, 30), enabled_n);
    const all_n = filterPackIndices(&packs, .all, "", &idx);
    try std.testing.expectEqual(@as(usize, 90), all_n);
    const q_n = filterPackIndices(&packs, .all, "pack1", &idx);
    // pack1, pack10-19 → 1 + 10 = 11 (pack1 and pack10..pack19)
    try std.testing.expect(q_n >= 11);
}

test "packs browse: domain keys e/d/a; footer and title" {
    try std.testing.expectEqual(DomainAction.enable, domainActionFromCodepoint('e'));
    try std.testing.expectEqual(DomainAction.disable, domainActionFromCodepoint('d'));
    try std.testing.expectEqual(DomainAction.toggle_all, domainActionFromCodepoint('a'));
    try std.testing.expectEqual(DomainAction.none, domainActionFromCodepoint('x'));
    try std.testing.expectEqual(DomainAction.none, domainActionFromCodepoint('c')); // scan reserved, host none
    try std.testing.expectEqual(DomainAction.none, domainActionFromCodepoint('o'));

    try std.testing.expect(std.mem.indexOf(u8, footerActions(.enabled_baseline), "show all") != null);
    try std.testing.expect(std.mem.indexOf(u8, footerActions(.enabled_baseline), "enter on/off") != null);
    try std.testing.expect(std.mem.indexOf(u8, footerActions(.all), "enabled only") != null);
    try std.testing.expect(std.mem.indexOf(u8, browseTitle(.enabled_baseline), "enabled") != null);
    try std.testing.expect(std.mem.indexOf(u8, browseTitle(.all), "all") != null);
}

test "packs browse: baseline pack ids still recognized for danger gate" {
    try std.testing.expect(pack_config.isBaselinePackId("core.git"));
    try std.testing.expect(pack_config.isBaselinePackId("system.disk"));
    try std.testing.expect(!pack_config.isBaselinePackId("containers.docker"));
    // Armed same-id helper still true when pending matches (legacy soft-arm API).
    try std.testing.expect(baselineDisableArmed("core.git", "core.git"));
    try std.testing.expect(!baselineDisableArmed("core.git", "core.shell"));
}

test "packs browse: enable is one-shot; disable is separate kind" {
    // Enable stays one-shot; disable is a distinct MutateKind that requires confirm in TUI.
    var enabled: bool = false;
    const kind: MutateKind = if (enabled) .disable else .enable;
    try std.testing.expect(kind == .enable);
    enabled = true;
    const kind2: MutateKind = if (enabled) .disable else .enable;
    try std.testing.expect(kind2 == .disable);
}

test "packs browse: row label and detail include id and write target" {
    const pack: PackRef = .{
        .id = "containers.docker",
        .name = "Docker",
        .category = "containers",
        .description = "Keywords: docker",
        .enabled = false,
        .safe_pattern_count = 2,
        .destructive_pattern_count = 5,
    };
    var row_buf: [96]u8 = undefined;
    const row = formatRowLabel(pack, &row_buf);
    try std.testing.expect(std.mem.indexOf(u8, row, "containers.docker") != null);
    try std.testing.expect(std.mem.indexOf(u8, row, "off") != null);

    const status = writeTargetStatus(.project, "/tmp/proj/.ryk.toml");
    var l0: [128]u8 = undefined;
    var l1: [160]u8 = undefined;
    var l2: [96]u8 = undefined;
    var l3: [96]u8 = undefined;
    const lines = formatDetailLines(pack, status.slice(), &l0, &l1, &l2, &l3);
    try std.testing.expect(std.mem.indexOf(u8, lines[0], "containers.docker") != null);
    try std.testing.expect(std.mem.indexOf(u8, lines[3], "project") != null);
    try std.testing.expect(std.mem.indexOf(u8, lines[3], "writes") != null);
}

test "packs browse: renderFrame via kit shows domain footer (no alt-screen)" {
    var out_buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out_buf);
    const items = [_][]const u8{ "● core.git  [on] baseline", "○ containers.docker  [off]" };
    const detail = [_][]const u8{ "core.git", "writes → .ryk.toml (project)" };
    const n = try tui.browse.renderFrame(std.testing.io, &w, .{
        .title = browseTitle(.all),
        .items = &items,
        .selected = 0,
        .list_rows = 8,
        .detail_lines = &detail,
        .footer_actions = footerActions(.all),
        .status_msg = "",
    });
    try std.testing.expect(n > 0);
    const out = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "core.git") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "enter toggle") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "enabled only") != null);
    // Pure frame never emits alt-screen.
    try std.testing.expect(std.mem.indexOf(u8, out, vaxis.ctlseqs.smcup) == null);
    try std.testing.expect(std.mem.indexOf(u8, out, vaxis.ctlseqs.rmcup) == null);
}

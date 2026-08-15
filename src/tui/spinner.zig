const std = @import("std");
const theme = @import("theme.zig");
const terminal_text = @import("terminal_text.zig");
const ctlseqs = @import("ctlseqs.zig");

/// Inline spinner using DEC synchronized-output control sequences (`ctlseqs`)
/// so each frame update is atomic. Timing remains caller-driven; plain output is static.
pub fn Spinner(comptime Writer: type) type {
    return struct {
        frames: []const []const u8 = &.{ "⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏" },
        frame_index: usize = 0,
        label: []const u8,
        io: std.Io,
        stdout: Writer,

        pub fn start(self: *@This()) !void {
            if (!theme.active(self.io, self.stdout).capability.hasColor()) return;
            try self.tick();
        }

        pub fn tick(self: *@This()) !void {
            const a = theme.active(self.io, self.stdout);
            if (!a.capability.hasColor()) return;
            // Phase 7 Task F: reduced-motion (colour on, motion off) renders the
            // first frame statically with NO synchronized-output controls, then
            // suppresses all further animation. The documented motion proxies
            // (NO_COLOR/TERM=dumb/non-TTY) drop colour too, so this branch is
            // only reachable in tests via setTestReducedMotion — but it keeps
            // the contract explicit for a future dedicated reduced-motion signal.
            if (theme.reducedMotion(self.io, self.stdout)) {
                if (self.frame_index > 0) return; // one static frame only
                const frame = self.frames[0];
                try self.stdout.print("  {s} ", .{frame});
                try terminal_text.write(self.stdout, self.label, .single_line);
                try self.stdout.writeAll("...");
                try flush(self.stdout);
                self.frame_index += 1;
                return;
            }
            const frame = self.frames[self.frame_index % self.frames.len];
            try self.stdout.writeAll(ctlseqs.sync_set);
            try self.stdout.print("\r\x1b[2K\r  {s} ", .{frame});
            try terminal_text.write(self.stdout, self.label, .single_line);
            try self.stdout.writeAll("...");
            try self.stdout.writeAll(ctlseqs.sync_reset);
            try flush(self.stdout);
            self.frame_index += 1;
        }

        pub fn stop(self: *@This(), success: bool) !void {
            const a = theme.active(self.io, self.stdout);
            const has_color = a.capability.hasColor();
            // Clear the in-place spinner line only on the live animation path;
            // reduced-motion appends a single static frame, so leave it clean.
            if (has_color and !theme.reducedMotion(self.io, self.stdout)) try self.stdout.writeAll("\r\x1b[2K\r");
            try self.stdout.print("  {s} ", .{if (success) "✓" else "✗"});
            try terminal_text.write(self.stdout, self.label, .single_line);
            try self.stdout.writeAll("\n");
        }
    };
}

fn flush(writer: anytype) !void {
    const Writer = @TypeOf(writer);
    switch (@typeInfo(Writer)) {
        .pointer => |pointer| if (@hasDecl(pointer.child, "flush")) try writer.flush(),
        else => if (@hasDecl(Writer, "flush")) try writer.flush(),
    }
}

test "spinner plain fallback contains no cursor controls" {
    var buf: [128]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    var spinner = Spinner(*std.Io.Writer){ .label = "Checking", .io = std.testing.io, .stdout = &writer };
    try spinner.start();
    try spinner.stop(true);
    try std.testing.expect(std.mem.indexOfScalar(u8, writer.buffered(), '\x1b') == null);
}

test "spinner rich frames are atomically bracketed by libvaxis sync controls" {
    theme.setTestActive(.{ .capability = .c256, .background = .dark });
    defer theme.setTestActive(null);
    var buf: [256]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    var spinner = Spinner(*std.Io.Writer){ .label = "Checking\x1b[2J", .io = std.testing.io, .stdout = &writer };
    try spinner.start();
    try spinner.stop(true);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), ctlseqs.sync_set) != null);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), ctlseqs.sync_reset) != null);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "\r\x1b[2K\r") != null);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "[2J") == null);
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

test "spinner reduced-motion emits one static frame with no sync controls" {
    // Phase 7 Task F: under reduced-motion (colour on, motion off) the spinner
    // renders exactly one static frame and no synchronized-output controls on
    // any subsequent tick. Colour capability is retained (the frame renders
    // rather than bailing). The only way to reach 'colour on, motion off' in a
    // unit test is the setTestReducedMotion override, since NO_COLOR/TERM=dumb/
    // non-TTY also drop colour.
    theme.setTestActive(.{ .capability = .c256, .background = .dark });
    theme.setTestReducedMotion(true);
    defer {
        theme.setTestActive(null);
        theme.setTestReducedMotion(null);
    }
    var buf: [256]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    var spinner = Spinner(*std.Io.Writer){ .label = "Checking", .io = std.testing.io, .stdout = &writer };
    try spinner.start(); // renders the first frame statically
    try spinner.tick(); // reduced-motion: no-op (no repeat frame)
    try spinner.tick(); // reduced-motion: no-op
    try spinner.stop(true);
    const out = writer.buffered();
    // Exactly one spinner frame (the first), no repeat frames.
    try std.testing.expectEqual(@as(usize, 1), countSeq(out, "⠋"));
    // No synchronized-output controls on the reduced-motion path.
    try std.testing.expect(std.mem.indexOf(u8, out, ctlseqs.sync_set) == null);
    try std.testing.expect(std.mem.indexOf(u8, out, ctlseqs.sync_reset) == null);
    // Colour capability retained — the frame rendered (did not bail) and the
    // final result line carries the label.
    try std.testing.expect(std.mem.indexOf(u8, out, "Checking") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "✓") != null);
}

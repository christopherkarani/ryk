const std = @import("std");
const enable_tui = @import("build_options").enable_tui;
const tui = @import("ryk").tui;

pub const Decision = enum { proceed, cancelled, requires_yes };

pub fn decide(
    io: std.Io,
    stdout: anytype,
    message: []const u8,
    yes: bool,
    is_tty: bool,
    injected_reader: ?*std.Io.Reader,
) !Decision {
    if (yes) return .proceed;
    if (!is_tty) return .requires_yes;
    if (comptime !enable_tui) return .cancelled;
    return if (try tui.prompt.confirm(io, stdout, .danger, message, injected_reader)) .proceed else .cancelled;
}

test "danger confirmation preserves yes scripting and fails closed elsewhere" {
    var output_buf: [256]u8 = undefined;
    var output: std.Io.Writer = .fixed(&output_buf);
    try std.testing.expectEqual(Decision.proceed, try decide(std.testing.io, &output, "Remove?", true, false, null));

    output = .fixed(&output_buf);
    try std.testing.expectEqual(Decision.requires_yes, try decide(std.testing.io, &output, "Remove?", false, false, null));
    try std.testing.expectEqualStrings("", output.buffered());

    var yes_reader: std.Io.Reader = .fixed("yes\n");
    output = .fixed(&output_buf);
    try std.testing.expectEqual(Decision.proceed, try decide(std.testing.io, &output, "Remove?", false, true, &yes_reader));
    try std.testing.expect(std.mem.indexOf(u8, output.buffered(), "Type 'yes' to confirm") != null);

    var empty_reader: std.Io.Reader = .fixed("");
    output = .fixed(&output_buf);
    try std.testing.expectEqual(Decision.cancelled, try decide(std.testing.io, &output, "Remove?", false, true, &empty_reader));
}

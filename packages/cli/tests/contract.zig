const std = @import("std");
const ryk_cli = @import("ryk_cli");

test "cli package exposes existing command surface without becoming edge" {
    try std.testing.expect(!@hasDecl(ryk_cli, "phase"));
    try std.testing.expect(ryk_cli.cli.help.findCommand("run") != null);
    try std.testing.expect(ryk_cli.cli.help.findCommand("doctor") != null);
    try std.testing.expect(ryk_cli.cli.help.findCommand("redteam") != null);
    try std.testing.expect(ryk_cli.cli.help.findCommand("report") != null);
    try std.testing.expect(ryk_cli.cli.help.findCommand("license") == null);
    try std.testing.expect(ryk_cli.cli.help.findCommand("ci") != null);
    try std.testing.expect(ryk_cli.cli.help.findCommand("explain") != null);
    try std.testing.expect(ryk_cli.cli.help.findCommand("scan") != null);
    try std.testing.expect(ryk_cli.cli.help.findCommand("update") != null);
    try std.testing.expect(ryk_cli.cli.help.findCommand("edge") == null);
}

test "cli package help still renders the public ryk CLI summary" {
    var buffer: [8192]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);

    try ryk_cli.cli.help.write(std.testing.io, &writer);
    const written = writer.buffered();

    try std.testing.expect(std.mem.indexOf(u8, written, "ryk") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "Common tasks") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "start") != null);
}

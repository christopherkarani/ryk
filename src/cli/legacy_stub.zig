//! Stubs for former Rust ExecuteCli surfaces removed in the Zig-only conversion.
//! Slice 1 (P0 honesty): short "not available" — no multi-paragraph daemon essay.
const std = @import("std");
const exit_codes = @import("exit_codes.zig");

/// Emit a short unavailable notice for hide-list / unfinished P0 verbs.
/// Prefer usage exit (2) so scripts treat these like unknown product verbs.
pub fn unavailable(command: []const u8, stderr: anytype) !u8 {
    // #289: history needs a migration pointer, not only "not available".
    if (std.mem.eql(u8, command, "history")) {
        try stderr.writeAll(
            "ryk: command 'history' is not available.\n" ++
                "Use `ryk replay` to review sessions, or `ryk scan` for forensics.\n" ++
                "Day-2 allowlist hints: `ryk history suggest` → `ryk suggest-allowlist`.\n" ++
                "Run 'ryk help' for usage.\n",
        );
        return exit_codes.usage;
    }
    try stderr.print(
        "ryk: command '{s}' is not available.\nRun 'ryk help' for usage.\n",
        .{command},
    );
    return exit_codes.usage;
}

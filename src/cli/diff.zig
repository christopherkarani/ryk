const std = @import("std");
const gpa_mod = @import("gpa.zig");
const core = @import("ryk_core").core;
const supervisor = core.supervisor;
const intercept = @import("../intercept/mod.zig");
const exit_codes = @import("exit_codes.zig");
const help = @import("help.zig");
const suggestions = @import("suggestions.zig");

pub fn command(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    const options = parseOptions(io, argv, stdout, stderr) catch |err| switch (err) {
        error.HelpShown => return exit_codes.success,
        error.Usage => return exit_codes.usage,
        else => return err,
    };

    var gpa_state: gpa_mod.State = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();

    const workspace_root = try supervisor.resolveWorkspaceRoot(io, allocator, null, ".");
    defer allocator.free(workspace_root);
    const session_id = intercept.files.resolveSessionId(io, allocator, workspace_root, options.session) catch |err| {
        try stderr.print("ryk diff: failed to resolve session '{s}': {s}\n", .{ options.session, @errorName(err) });
        return exit_codes.general;
    };
    defer allocator.free(session_id);
    const diff = intercept.files.diffStaged(io, allocator, workspace_root, session_id, options.file) catch |err| {
        try stderr.print("ryk diff: failed to diff staged files: {s}\n", .{@errorName(err)});
        return exit_codes.general;
    };
    defer allocator.free(diff);
    if (diff.len == 0) {
        try stdout.writeAll(emptyDiffMessage);
    } else {
        try stdout.writeAll(diff);
    }
    return exit_codes.success;
}

const emptyDiffMessage = "No pending file changes.\n";

const Options = struct {
    session: []const u8 = "last",
    file: ?[]const u8 = null,
};

fn parseOptions(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !Options {
    var options: Options = .{};
    var index: usize = 0;
    while (index < argv.len) : (index += 1) {
        const arg = argv[index];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            _ = try help.writeCommand(io, stdout, "diff");
            return error.HelpShown;
        } else if (std.mem.eql(u8, arg, "--session")) {
            index += 1;
            if (index >= argv.len) {
                try stderr.writeAll("ryk diff: --session requires an id or 'last'.\n");
                return error.Usage;
            }
            options.session = argv[index];
        } else if (std.mem.eql(u8, arg, "--file")) {
            index += 1;
            if (index >= argv.len) {
                try stderr.writeAll("ryk diff: --file requires a workspace path.\n");
                return error.Usage;
            }
            options.file = argv[index];
        } else {
            try suggestions.writeUnknownOption(stderr, "ryk diff", arg, &.{ "--session", "--file", "--help", "-h" }, "diff");
            return error.Usage;
        }
    }
    return options;
}

test "diff empty staged set prints a no-changes line" {
    try std.testing.expectEqualStrings("No pending file changes.\n", emptyDiffMessage);
}

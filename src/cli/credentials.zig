const std = @import("std");
const gpa_mod = @import("gpa.zig");

const core = @import("ryk_core").core;
const core_api = @import("ryk_core").api;
const credentials = @import("../intercept/credentials.zig");
const exit_codes = @import("exit_codes.zig");
const help = @import("help.zig");
const supervisor = core.supervisor;
const suggestions = @import("suggestions.zig");

pub fn command(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    if (argv.len == 0 or std.mem.eql(u8, argv[0], "--help") or std.mem.eql(u8, argv[0], "-h")) {
        _ = try help.writeCommand(io, stdout, "credentials");
        return exit_codes.success;
    }
    if (!std.mem.eql(u8, argv[0], "check")) {
        try suggestions.writeUnknownSubcommand(stderr, "ryk credentials", argv[0], &.{"check"}, "credentials");
        return exit_codes.usage;
    }
    if (argv.len > 2) {
        try stderr.writeAll("ryk credentials check: expected at most one credential ref.\n");
        return exit_codes.usage;
    }
    return checkCommand(io, argv[1..], stdout, stderr);
}

fn checkCommand(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    var gpa_state: gpa_mod.State = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();

    const workspace_root = supervisor.resolveWorkspaceRoot(io, allocator, null, ".") catch try std.Io.Dir.cwd().realPathFileAlloc(io, ".", allocator);
    defer allocator.free(workspace_root);
    var loaded_policy = core_api.discoverPolicy(io, allocator, null, workspace_root) catch |err| {
        try stderr.print("ryk credentials check: invalid policy: {s}\n", .{@errorName(err)});
        return exit_codes.general;
    };
    defer loaded_policy.deinit();

    const ref_name = if (argv.len == 1) argv[0] else null;
    var report = credentials.check(io, allocator, loaded_policy.innerPtr(), workspace_root, ref_name) catch |err| switch (err) {
        error.UnknownCredentialRef => {
            try stderr.writeAll("ryk credentials check: unknown credential ref.\n");
            return exit_codes.general;
        },
        else => {
            try stderr.print("ryk credentials check: failed: {s}\n", .{@errorName(err)});
            return exit_codes.general;
        },
    };
    defer report.deinit(allocator);

    if (report.ref_name) |name| {
        try stdout.print("Credential ref: {s}\n", .{name});
    } else {
        try stdout.writeAll("Credential brokers:\n");
    }
    for (report.statuses) |status| {
        try stdout.print("- {s} ({s}): {s} - {s}\n", .{ status.name, status.kind.toString(), status.state.toString(), status.message });
    }
    return if (report.ok()) exit_codes.success else exit_codes.general;
}

test "credentials command rejects unknown subcommand" {
    var stdout_buf: [256]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, &.{"chek"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "unknown subcommand") != null);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "Did you mean 'check'?") != null);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "ryk help credentials") != null);
}

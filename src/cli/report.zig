const std = @import("std");
const gpa_mod = @import("gpa.zig");

const core = @import("ryk_core").core;
const core_api = @import("ryk_core").api;
const supervisor = core.supervisor;
const report = @import("../report.zig");
const exit_codes = @import("exit_codes.zig");
const help = @import("help.zig");
const tui = @import("../tui/mod.zig");
const suggestions = @import("suggestions.zig");

const Format = enum { human, markdown, json };
const Options = struct { session: []const u8 = "last", format: Format = .human };

pub fn command(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    const options = parseOptions(io, argv, stdout, stderr) catch |err| switch (err) {
        error.HelpShown => return exit_codes.success,
        error.Usage => return exit_codes.usage,
        else => return err,
    };
    var gpa_state: gpa_mod.State = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();

    const workspace_root = supervisor.resolveWorkspaceRoot(io, allocator, null, ".") catch |err| {
        try stderr.print("ryk report: failed to resolve workspace: {s}\n", .{@errorName(err)});
        return exit_codes.general;
    };
    defer allocator.free(workspace_root);

    var replay = core_api.loadReplay(io, allocator, workspace_root, .{ .session = options.session, .only_denied = true, .verify = true }) catch |err| switch (err) {
        error.FileNotFound => {
            try tui.render.callout(
                io,
                stderr,
                .info,
                "No reportable session found",
                "Run a protected command first: ryk run -- echo hello. Then retry: ryk report --session last",
            );
            return exit_codes.general;
        },
        error.HashVerificationFailed => {
            try tui.render.callout(
                io,
                stderr,
                .danger,
                "Hash verification failed",
                "Refusing to export a report from tampered evidence. The session hash chain does not match.",
            );
            return exit_codes.general;
        },
        else => {
            try stderr.print("ryk report: failed: {s}\n", .{@errorName(err)});
            return exit_codes.general;
        },
    };
    defer replay.deinit();

    switch (options.format) {
        .human => report.writeHuman(io, allocator, stdout, workspace_root, replay) catch |err| {
            return mapReportExportError(io, stderr, err);
        },
        .markdown => report.writeMarkdown(io, allocator, stdout, workspace_root, replay) catch |err| {
            return mapReportExportError(io, stderr, err);
        },
        .json => report.writeJson(io, allocator, stdout, workspace_root, replay) catch |err| {
            return mapReportExportError(io, stderr, err);
        },
    }
    return exit_codes.success;
}

fn mapReportExportError(io: std.Io, stderr: anytype, err: anyerror) !u8 {
    switch (err) {
        error.ParseIntegrityFailed => {
            try tui.render.callout(
                io,
                stderr,
                .danger,
                "Event parse integrity failed",
                "Refusing to export a report from incomplete evidence.",
            );
            return exit_codes.general;
        },
        else => return err,
    }
}

fn parseOptions(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !Options {
    var options: Options = .{};
    var index: usize = 0;
    while (index < argv.len) : (index += 1) {
        const arg = argv[index];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            _ = try help.writeCommand(io, stdout, "report");
            return error.HelpShown;
        } else if (std.mem.eql(u8, arg, "--session")) {
            index += 1;
            if (index >= argv.len) {
                try stderr.writeAll("ryk report: --session requires a session id or 'last'.\n");
                return error.Usage;
            }
            options.session = argv[index];
        } else if (std.mem.eql(u8, arg, "--format")) {
            index += 1;
            if (index >= argv.len) {
                try stderr.writeAll("ryk report: --format requires human, markdown, or json.\n");
                return error.Usage;
            }
            if (std.mem.eql(u8, argv[index], "human")) {
                options.format = .human;
            } else if (std.mem.eql(u8, argv[index], "markdown")) {
                options.format = .markdown;
            } else if (std.mem.eql(u8, argv[index], "json")) {
                options.format = .json;
            } else {
                try stderr.writeAll("ryk report: --format supports human, markdown, or json.\n");
                return error.Usage;
            }
        } else {
            try suggestions.writeUnknownOption(stderr, "ryk report", arg, &.{ "--session", "--format", "--help", "-h" }, "report");
            return error.Usage;
        }
    }
    return options;
}

test "report rejects unsupported format" {
    var stdout_buf: [512]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const code = try command(std.testing.io, &.{ "--format", "html" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "--format") != null);
}

test "report public errors render missing-session guidance without a license" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const previous_cwd = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(previous_cwd);
    try std.process.setCurrentDir(std.testing.io, tmp.dir);
    defer std.process.setCurrentPath(std.testing.io, previous_cwd) catch {};
    try tmp.dir.createDirPath(std.testing.io, ".ryk");
    {
        const policy_file = try tmp.dir.createFile(std.testing.io, ".ryk/policy.yaml", .{});
        defer policy_file.close(std.testing.io);
        try policy_file.writeStreamingAll(std.testing.io, "version: 1\nmode: strict\n");
    }

    var stdout_buf: [512]u8 = undefined;
    var stderr_buf: [1024]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const missing_code = try command(std.testing.io, &.{ "--session", "missing" }, &stdout_writer, &stderr_writer);

    try std.testing.expectEqual(exit_codes.general, missing_code);
    try std.testing.expectEqualStrings("", stdout_writer.buffered());
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "No reportable session found") != null);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "ryk run -- echo") != null);
    try std.testing.expect(std.mem.indexOfScalar(u8, stderr_writer.buffered(), 0x1b) == null);
    // Free feature: no license gate messaging.
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "license") == null);
}

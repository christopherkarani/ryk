const std = @import("std");

const core = @import("ryk_core").core;
const ci_check = @import("../ci_check.zig");
const supervisor = core.supervisor;
const exit_codes = @import("exit_codes.zig");
const help = @import("help.zig");
const suggestions = @import("suggestions.zig");

const Format = enum { text, markdown, json };
const Options = struct { format: Format = .text, github_summary: ?[]const u8 = null };

pub fn command(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    if (argv.len == 0 or std.mem.eql(u8, argv[0], "--help") or std.mem.eql(u8, argv[0], "-h")) {
        _ = try help.writeCommand(io, stdout, "ci");
        return if (argv.len == 0) exit_codes.usage else exit_codes.success;
    }
    if (!std.mem.eql(u8, argv[0], "check")) {
        try suggestions.writeUnknownSubcommand(stderr, "ryk ci", argv[0], &.{"check"}, "ci");
        return exit_codes.usage;
    }
    const options = parseOptions(argv[1..], stderr) catch |err| switch (err) {
        error.Usage => return exit_codes.usage,
        else => return err,
    };
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();
    const workspace_root = supervisor.resolveWorkspaceRoot(io, allocator, null, ".") catch try std.Io.Dir.cwd().realPathFileAlloc(io, ".", allocator);
    defer allocator.free(workspace_root);
    var result = try ci_check.run(io, allocator, workspace_root);
    defer result.deinit();
    switch (options.format) {
        .text => try ci_check.writeText(stdout, result),
        .markdown => try ci_check.writeMarkdown(stdout, result),
        .json => try ci_check.writeJson(stdout, result),
    }
    const github_summary_path = options.github_summary orelse blk: {
        if (std.c.getenv("GITHUB_STEP_SUMMARY")) |p| break :blk try allocator.dupe(u8, std.mem.span(p));
        break :blk null;
    };
    if (github_summary_path) |summary_path| {
        defer if (options.github_summary == null) allocator.free(summary_path);
        const file = try std.Io.Dir.createFileAbsolute(io, summary_path, .{});
        defer file.close(io);
        const offset = file.length(io) catch 0;
        var markdown_aw: std.Io.Writer.Allocating = .init(allocator);
        defer markdown_aw.deinit();
        try ci_check.writeMarkdown(&markdown_aw.writer, result);
        try markdown_aw.writer.flush();
        const markdown = try markdown_aw.toOwnedSlice();
        defer allocator.free(markdown);
        try file.writePositionalAll(io, markdown, offset);
    }
    return if (result.ok()) exit_codes.success else exit_codes.general;
}

fn parseOptions(argv: []const []const u8, stderr: anytype) !Options {
    var options: Options = .{};
    var index: usize = 0;
    while (index < argv.len) : (index += 1) {
        const arg = argv[index];
        if (std.mem.eql(u8, arg, "--format")) {
            index += 1;
            if (index >= argv.len) {
                try stderr.writeAll("ryk ci check: --format requires text, markdown, or json.\n");
                return error.Usage;
            }
            if (std.mem.eql(u8, argv[index], "text")) {
                options.format = .text;
            } else if (std.mem.eql(u8, argv[index], "markdown")) {
                options.format = .markdown;
            } else if (std.mem.eql(u8, argv[index], "json")) {
                options.format = .json;
            } else {
                try stderr.writeAll("ryk ci check: --format supports text, markdown, or json.\n");
                return error.Usage;
            }
        } else if (std.mem.eql(u8, arg, "--github-summary")) {
            index += 1;
            if (index >= argv.len) {
                try stderr.writeAll("ryk ci check: --github-summary requires a path.\n");
                return error.Usage;
            }
            options.github_summary = argv[index];
        } else {
            try suggestions.writeUnknownOption(stderr, "ryk ci check", arg, &.{ "--format", "--github-summary" }, "ci");
            return error.Usage;
        }
    }
    return options;
}

test "ci command rejects unknown subcommands" {
    var stdout_buf: [256]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const code = try command(std.testing.io, &.{"chek"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "Did you mean 'check'?") != null);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "ryk help ci") != null);
}

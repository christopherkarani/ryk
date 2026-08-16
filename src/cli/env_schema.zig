const std = @import("std");
const gpa_mod = @import("gpa.zig");

const env_util = @import("../env_util.zig");
const intercept = @import("../intercept/mod.zig");
const exit_codes = @import("exit_codes.zig");
const help = @import("help.zig");

pub fn command(
    io: std.Io,
    argv: []const []const u8,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    for (argv) |arg| {
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            _ = try help.writeCommand(io, stdout, "env");
            return exit_codes.success;
        }
    }
    if (argv.len != 2 or !std.mem.eql(u8, argv[0], "schema") or !std.mem.eql(u8, argv[1], "--agent")) {
        try stderr.writeAll("Usage: ryk env schema --agent\n");
        return exit_codes.usage;
    }
    var gpa_state: gpa_mod.State = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();
    const workspace = try std.Io.Dir.cwd().realPathFileAlloc(io, ".", allocator);
    defer allocator.free(workspace);
    var maybe_schema = intercept.env_schema.loadOptional(io, allocator, workspace) catch |err| {
        try stderr.print("ryk env schema: invalid schema: {s}\n", .{@errorName(err)});
        return exit_codes.general;
    };
    var schema = maybe_schema orelse {
        try stderr.writeAll(
            "ryk env schema: .ryk/env.schema.yaml not found\nNext: create .ryk/env.schema.yaml, then rerun `ryk env schema --agent`.\n",
        );
        return exit_codes.general;
    };
    defer schema.deinit();
    maybe_schema = null;

    var current = try env_util.createProcessMap(allocator);
    defer current.deinit();
    try writeAgentSchema(&schema, &current, stdout);
    return exit_codes.success;
}

fn writeAgentSchema(
    schema: *const intercept.env_schema.Schema,
    current: *const std.process.Environ.Map,
    stdout: anytype,
) !void {
    try stdout.writeAll("env_schema:\n  unknown: omit\n  vars:\n");
    for (schema.vars) |variable| {
        try stdout.print(
            "    {s}: class={s} value={s}",
            .{
                variable.name,
                @tagName(variable.class),
                if (current.get(variable.name) != null) "[SET]" else "[UNSET]",
            },
        );
        if (variable.grant) |grant| try stdout.print(" grant={s}", .{grant});
        try stdout.writeByte('\n');
    }
}

test "missing env schema names the next command" {
    var stdout_buf: [256]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, &.{ "schema", "--agent" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.general, code);
    const err = stderr_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, err, ".ryk/env.schema.yaml not found") != null);
    try std.testing.expect(std.mem.indexOf(u8, err, "Next: create .ryk/env.schema.yaml") != null);
    try std.testing.expect(std.mem.indexOf(u8, err, "ryk env schema --agent") != null);
}

test "agent env schema export reports presence without values" {
    var schema = try intercept.env_schema.parseFromSlice(std.testing.allocator,
        \\defaults:
        \\  unknown: omit
        \\vars:
        \\  API_URL:
        \\    class: public
        \\  DATABASE_URL:
        \\    class: sensitive
        \\    grant: database
    );
    defer schema.deinit();
    var current = std.process.Environ.Map.init(std.testing.allocator);
    defer current.deinit();
    try current.put("API_URL", "https://public-but-redacted.example");
    try current.put("DATABASE_URL", "postgres://synthetic:secret@example/db");
    var output_buffer: [1024]u8 = undefined;
    var output: std.Io.Writer = .fixed(&output_buffer);
    try writeAgentSchema(&schema, &current, &output);
    const rendered = output.buffered();
    try std.testing.expect(std.mem.indexOf(u8, rendered, "API_URL: class=public value=[SET]") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "DATABASE_URL: class=sensitive value=[SET]") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "https://public-but-redacted") == null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "postgres://") == null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "synthetic:secret") == null);
}

const std = @import("std");
const gpa_mod = @import("gpa.zig");

const env_util = @import("ryk").env_util;
const redteam = @import("ryk").redteam;
const exit_codes = @import("exit_codes.zig");
const help = @import("help.zig");
const resource_root = @import("ryk").resource_root;
const suggestions = @import("suggestions.zig");

const Options = struct {
    root: []const u8 = "",
    json: bool = false,
    ci: bool = false,
    fixture_id: ?[]const u8 = null,
};

pub fn command(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    const options = parseOptions(io, argv, stdout, stderr) catch |err| switch (err) {
        error.HelpShown => return exit_codes.success,
        error.Usage => return exit_codes.usage,
        else => return err,
    };

    var gpa_state: gpa_mod.State = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();

    const fixture_root = blk: {
        if (options.root.len > 0) break :blk try allocator.dupe(u8, options.root);
        var env_map = try env_util.createProcessMap(allocator);
        defer env_map.deinit();
        const workspace_owned = try env_util.getOwned(&env_map, allocator, "RYK_WORKSPACE_ROOT");
        defer if (workspace_owned) |owned| allocator.free(owned);
        const workspace_root = workspace_owned orelse ".";
        const resolved = resource_root.resolveResourcePath(io, allocator, .{
            .workspace_root = if (workspace_root.ptr != ".".ptr) workspace_root else ".",
        }, "fixtures") catch |err| switch (err) {
            error.ResourceNotFound => {
                // Improved for packaged installs in non-interactive / CI / docker sh -c contexts
                // where the login-time RYK_RESOURCE_ROOT export from install.sh is not active.
                // Points users at the reliable `ryk env` activation primitive (post-audit DX win)
                // while still offering the previous escape hatches.
                try stderr.writeAll(
                    "ryk redteam: no fixtures directory found.\n\n" ++
                        "Fixtures are part of the ryk runtime assets. After a normal install, activate them in the current shell with:\n" ++
                        "    eval \"$(ryk env 2>/dev/null || ryk --print-install-env)\"\n\n" ++
                        "Then retry. Or set RYK_RESOURCE_ROOT explicitly to the installed share/ryk/current directory, pass an explicit fixture path, or run from a source checkout.\n",
                );
                return exit_codes.general;
            },
            else => return err,
        };
        defer allocator.free(resolved);
        break :blk try allocator.dupe(u8, resolved);
    };
    defer allocator.free(fixture_root);

    var fixture_set = redteam.fixtures.discover(io, allocator, fixture_root, options.fixture_id) catch |err| {
        try stderr.print("ryk redteam: failed to discover fixtures: {s}\n", .{@errorName(err)});
        return exit_codes.general;
    };
    defer fixture_set.deinit();
    if (fixture_set.fixtures.len == 0) {
        if (options.fixture_id) |id| {
            try stderr.print("ryk redteam: fixture not found: {s}\n", .{id});
        } else {
            try stderr.print("ryk redteam: no fixtures found under {s}\n", .{fixture_root});
        }
        return exit_codes.general;
    }

    var suite = redteam.runner.runSuite(allocator, fixture_set, .{ .ci = options.ci }) catch |err| {
        try stderr.print("ryk redteam: fixture run failed: {s}\n", .{@errorName(err)});
        return exit_codes.general;
    };
    defer suite.deinit();

    if (options.json) {
        try redteam.reports.writeJson(stdout, suite);
    } else {
        try redteam.reports.writeHuman(io, stdout, suite);
    }

    if (options.ci and !suite.allRequiredPassed()) return exit_codes.redteam_failure;
    return exit_codes.success;
}

fn parseOptions(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !Options {
    var options: Options = .{};
    var saw_path = false;
    var index: usize = 0;
    while (index < argv.len) : (index += 1) {
        const arg = argv[index];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            _ = try help.writeCommand(io, stdout, "redteam");
            return error.HelpShown;
        } else if (std.mem.eql(u8, arg, "--json")) {
            options.json = true;
        } else if (std.mem.eql(u8, arg, "--ci")) {
            options.ci = true;
        } else if (std.mem.eql(u8, arg, "--fixture")) {
            index += 1;
            if (index >= argv.len) {
                try stderr.writeAll("ryk redteam: --fixture requires a fixture id.\n");
                return error.Usage;
            }
            options.fixture_id = argv[index];
        } else if (std.mem.startsWith(u8, arg, "-")) {
            try suggestions.writeUnknownOption(stderr, "ryk redteam", arg, &.{ "--json", "--ci", "--fixture", "--help", "-h" }, "redteam");
            return error.Usage;
        } else {
            if (saw_path) {
                try stderr.writeAll("ryk redteam: expected at most one fixture path.\n");
                return error.Usage;
            }
            options.root = arg;
            saw_path = true;
        }
    }
    return options;
}

test "redteam command rejects unknown options" {
    var stdout_buf: [512]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, &.{"--bad"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "unknown option") != null);
}

test "redteam --json output is stable machine JSON without presentation" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "fixtures/secret-exfil/pass");
    {
        const file = try tmp.dir.createFile(std.testing.io, "fixtures/secret-exfil/pass/fixture.yaml", .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io,
            \\version: 1
            \\id: passing
            \\name: Passing fixture
            \\category: secret-exfil
            \\description: Expected block matches attempt.
            \\mode: strict
            \\command:
            \\  argv:
            \\    - "./fixture-agent"
            \\attempts:
            \\  - "file.read:.env"
            \\expected:
            \\  blocked:
            \\    - "file.read:.env"
            \\score:
            \\  points: 1
            \\
        );
    }
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, "fixtures", std.testing.allocator);
    defer std.testing.allocator.free(root);
    var stdout_buf: [8192]u8 = undefined;
    var stderr_buf: [1024]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, &.{ root, "--json" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    const output = stdout_writer.buffered();
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, output, .{});
    defer parsed.deinit();
    try std.testing.expect(parsed.value.object.get("version") != null);
    try std.testing.expect(parsed.value.object.get("fixtures") != null);
    const provenance = parsed.value.object.get("provenance") orelse {
        try std.testing.expect(false);
        unreachable;
    };
    try std.testing.expectEqualStrings("engine-self-test", provenance.object.get("suite_kind").?.string);
    try std.testing.expectEqualStrings("builtin:redteam", provenance.object.get("policy").?.string);
    try std.testing.expectEqualStrings("zig-in-process", provenance.object.get("evaluator").?.string);
    try std.testing.expect(provenance.object.get("real_action_attempted").?.bool == false);
    try std.testing.expect(std.mem.indexOfScalar(u8, output, 0x1b) == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "ryk Redteam Score") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "ryk Redteam — engine self-test") == null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "redteam ci exits nonzero on failing fixture" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "fixtures/secret-exfil/fail");
    {
        const file = try tmp.dir.createFile(std.testing.io, "fixtures/secret-exfil/fail/fixture.yaml", .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io,
            \\version: 1
            \\id: failing
            \\name: Failing fixture
            \\category: secret-exfil
            \\description: Expected block does not match attempt.
            \\mode: strict
            \\command:
            \\  argv:
            \\    - "./fixture-agent"
            \\attempts:
            \\  - "file.read:.env"
            \\expected:
            \\  blocked:
            \\    - "file.read:README.md"
            \\score:
            \\  points: 1
            \\
        );
    }
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, "fixtures", std.testing.allocator);
    defer std.testing.allocator.free(root);
    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, &.{ root, "--ci" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.redteam_failure, code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "ryk Redteam — engine self-test") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "builtin:redteam") != null);
}

test "redteam ci accepts a relative fixture root with input directory" {
    var stdout_buf: [8192]u8 = undefined;
    var stderr_buf: [1024]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, &.{ "fixtures", "--fixture", "secret-env-read-basic", "--ci" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "✓ PASS") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "Category summary") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

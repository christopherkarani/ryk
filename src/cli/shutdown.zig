const std = @import("std");
const gpa_mod = @import("gpa.zig");

const daemon = @import("daemon.zig");
const exit_codes = @import("exit_codes.zig");
const help = @import("help.zig");
const suggestions = @import("suggestions.zig");

pub fn command(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    return commandWithShutdown(daemon.shutdownDaemon, io, argv, stdout, stderr);
}

fn commandWithShutdown(comptime shutdown_fn: anytype, io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    return commandWithShutdownImpl(shutdown_fn, io, argv, stdout, stderr);
}

fn mockStopped(_: std.mem.Allocator) daemon.DaemonError!daemon.ShutdownResult {
    return .stopped;
}

test "shutdown defaults to daemon stop and retains daemon qualifier" {
    inline for (.{ &[_][]const u8{}, &[_][]const u8{"--daemon"} }) |argv| {
        var stdout_buf: [128]u8 = undefined;
        var stderr_buf: [256]u8 = undefined;
        var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
        var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
        const code = try commandWithShutdown(mockStopped, std.testing.io, argv, &stdout_writer, &stderr_writer);
        try std.testing.expectEqual(exit_codes.success, code);
        try std.testing.expectEqualStrings("ryk daemon stopped\n", stdout_writer.buffered());
        try std.testing.expectEqualStrings("", stderr_writer.buffered());
    }
}

fn commandWithShutdownImpl(comptime shutdown_fn: anytype, io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    for (argv) |arg| {
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            _ = try help.writeCommand(io, stdout, "shutdown");
            return exit_codes.success;
        }
        if (std.mem.eql(u8, arg, "--daemon")) {
            continue;
        }
        try suggestions.writeUnknownOption(stderr, "ryk shutdown", arg, &.{ "--daemon", "--help" }, "shutdown");
        return exit_codes.usage;
    }

    var gpa_state: gpa_mod.State = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();

    const result = shutdown_fn(allocator) catch |err| {
        try stderr.print("ryk shutdown --daemon: {s}: {s}\n", .{ shutdownErrorLabel(err), @errorName(err) });
        return exit_codes.general;
    };

    switch (result) {
        .stopped => try stdout.writeAll("ryk daemon stopped\n"),
        .not_running => try stdout.writeAll("ryk daemon not running\n"),
        .stale_cleaned => try stdout.writeAll("ryk daemon stale artifacts cleaned\n"),
    }
    return exit_codes.success;
}

fn shutdownErrorLabel(err: daemon.DaemonError) []const u8 {
    return switch (err) {
        error.HomeDirectoryNotFound => "HOME not set",
        error.DaemonNotReady => "daemon artifacts present but daemon not reachable",
        error.SocketConnectFailed,
        error.SocketReadFailed,
        error.SocketWriteFailed,
        => "daemon communication failed",
        error.RequestSerializationFailed,
        error.ResponseParseFailed,
        error.DaemonProtocolError,
        => "daemon protocol error",
        error.DaemonStartTimeout => "timed out waiting for daemon shutdown",
        error.OutOfMemory => "out of memory",
        else => "shutdown failed",
    };
}

test "shutdown unknown flag suggests daemon qualifier" {
    var stdout_buf: [128]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, &.{"--daemn"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "Did you mean '--daemon'?") != null);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "ryk help shutdown") != null);
}

test "ShutdownResult enum values are distinct" {
    try std.testing.expect(daemon.ShutdownResult.stopped != daemon.ShutdownResult.not_running);
    try std.testing.expect(daemon.ShutdownResult.stale_cleaned != daemon.ShutdownResult.not_running);
}

test "DaemonRequest serializes Shutdown envelope" {
    const request = daemon.DaemonRequest{
        .id = 9,
        .method = "Shutdown",
        .params = null,
    };

    const json_str = try std.json.Stringify.valueAlloc(std.testing.allocator, request, .{});
    defer std.testing.allocator.free(json_str);

    try std.testing.expectEqualStrings("{\"id\":9,\"method\":\"Shutdown\",\"params\":null}", json_str);
}

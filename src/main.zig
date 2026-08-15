const std = @import("std");
const builtin = @import("builtin");
const ryk = @import("ryk");

pub fn main(init: std.process.Init) !u8 {
    if (builtin.os.tag == .windows) {
        setupWindowsConsole();
    }

    var dbg: ryk.cli.gpa.State = .init;
    defer _ = dbg.deinit();

    const io = init.io;
    const argv = try init.minimal.args.toSlice(init.arena.allocator());
    // Gate the cheap hook allocator / skip color+telemetry only on a named
    // `ryk hook` or a real bare-`ryk` agent-hook entry (non-TTY stdin). Do not
    // replace DebugAllocator for the rest of the CLI.
    const is_named_hook = argv.len > 1 and std.mem.eql(u8, argv[1], "hook");
    const is_agent_hook = argv.len == 1 and ryk.cli.agent_hook.shouldEnter(io);
    const hook_hot_path = is_named_hook or is_agent_hook;
    const allocator = if (hook_hot_path) std.heap.smp_allocator else dbg.allocator();

    if (builtin.os.tag == .linux and
        argv.len > 1 and
        std.mem.eql(
            u8,
            argv[1],
            ryk.sandbox.linux_workspace_view_bootstrap.internal_command,
        ))
    {
        return ryk.sandbox.linux_workspace_view_bootstrap.command(allocator, argv[2..]);
    }

    var stdout_buffer: [4096]u8 = undefined;
    var stderr_buffer: [4096]u8 = undefined;
    // The agent child inherits these descriptors. Positional writers retain a
    // private offset and can overwrite child output when stdout/stderr are
    // redirected to regular files; streaming writers share the kernel offset.
    var stdout_writer = std.Io.File.stdout().writerStreaming(io, &stdout_buffer);
    var stderr_writer = std.Io.File.stderr().writerStreaming(io, &stderr_buffer);

    if (!hook_hot_path) {
        _ = ryk.cli.style.useColor(io, &stdout_writer.interface);
    }

    const shim_alias = if (builtin.os.tag == .windows) ryk.intercept.commands.shimAliasFromExecutablePath(argv[0]) else null;
    const code = if (shim_alias) |alias|
        runWindowsExecutableShim(io, init.environ_map, allocator, alias, argv[1..], &stdout_writer.interface, &stderr_writer.interface) catch |err| {
            stdout_writer.interface.flush() catch {};
            stderr_writer.interface.flush() catch {};
            const telemetry_argv = [_][]const u8{alias};
            ryk.telemetry.recordInvocation(io, init.environ_map, allocator, &telemetry_argv, ryk.cli.exit_codes.general);
            return err;
        }
    else
        ryk.cli.run(io, init.environ_map, argv[1..], &stdout_writer.interface, &stderr_writer.interface) catch |err| {
            stdout_writer.interface.flush() catch {};
            stderr_writer.interface.flush() catch {};
            if (!hook_hot_path) ryk.telemetry.recordInvocation(io, init.environ_map, allocator, argv[1..], ryk.cli.exit_codes.general);
            return err;
        };
    try stdout_writer.interface.flush();
    try stderr_writer.interface.flush();
    if (shim_alias) |alias| {
        const telemetry_argv = [_][]const u8{alias};
        ryk.telemetry.recordInvocation(io, init.environ_map, allocator, &telemetry_argv, code);
    } else if (!hook_hot_path) {
        ryk.telemetry.recordInvocation(io, init.environ_map, allocator, argv[1..], code);
    }
    return code;
}

fn setupWindowsConsole() void {
    if (comptime builtin.os.tag != .windows) return;

    const DWORD = std.os.windows.DWORD;
    const HANDLE = std.os.windows.HANDLE;

    const STD_OUTPUT_HANDLE: DWORD = 0xFFFFFFF5;
    const ENABLE_VIRTUAL_TERMINAL_PROCESSING: DWORD = 0x0004;

    const winapi = struct {
        extern "kernel32" fn SetConsoleOutputCP(code_page: DWORD) callconv(.winapi) std.os.windows.BOOL;
        extern "kernel32" fn GetStdHandle(kind: DWORD) callconv(.winapi) ?HANDLE;
        extern "kernel32" fn GetConsoleMode(handle: HANDLE, mode: *DWORD) callconv(.winapi) std.os.windows.BOOL;
        extern "kernel32" fn SetConsoleMode(handle: HANDLE, mode: DWORD) callconv(.winapi) std.os.windows.BOOL;
    };
    _ = winapi.SetConsoleOutputCP(65001);

    const handle: ?HANDLE = winapi.GetStdHandle(STD_OUTPUT_HANDLE);
    if (handle == null or handle.? == std.os.windows.INVALID_HANDLE_VALUE) return;

    var mode: DWORD = 0;
    if (winapi.GetConsoleMode(handle.?, &mode).toBool()) {
        _ = winapi.SetConsoleMode(handle.?, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }
}

fn runWindowsExecutableShim(io: std.Io, environ_map: *const std.process.Environ.Map, allocator: std.mem.Allocator, alias: []const u8, args: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    var shim_argv = try allocator.alloc([]const u8, args.len + 3);
    defer allocator.free(shim_argv);
    shim_argv[0] = "exec";
    shim_argv[1] = "--";
    shim_argv[2] = alias;
    if (args.len > 0) @memcpy(shim_argv[3..], args);
    return ryk.cli.shim.command(io, environ_map, shim_argv, stdout, stderr);
}

test {
    _ = ryk.cli;
}

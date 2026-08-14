//! `ryk explain` — explain why a shell command would be allowed or denied.
const std = @import("std");
const shell_engine = @import("../shell_engine/mod.zig");
const shell_eval = @import("shell_eval.zig");
const shell_test = @import("shell_test.zig");
const pack_config = @import("pack_config.zig");
const core = @import("ryk_core").core;
const help = @import("help.zig");
const explain_render = @import("explain_render.zig");
const exit_codes = @import("exit_codes.zig");

pub fn command(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    if (argv.len == 0 or std.mem.eql(u8, argv[0], "--help") or std.mem.eql(u8, argv[0], "-h")) {
        _ = try help.writeCommand(io, stdout, "explain");
        return if (argv.len == 0) exit_codes.usage else exit_codes.success;
    }

    if (shell_eval.resolveShellEvalBackend() == .rust) {
        try stderr.writeAll("ryk explain: RYK_SHELL_EVAL=rust is no longer supported; Zig shell_engine is the sole Evaluate authority\n");
        return 3;
    }

    var format_json = false;
    var verbose = false;
    var cmd_start: usize = 0;
    var i: usize = 0;
    while (i < argv.len) : (i += 1) {
        const arg = argv[i];
        if (std.mem.eql(u8, arg, "--")) {
            cmd_start = i + 1;
            break;
        }
        if (std.mem.eql(u8, arg, "--verbose") or std.mem.eql(u8, arg, "-v")) {
            verbose = true;
            cmd_start = i + 1;
            continue;
        }
        if (std.mem.eql(u8, arg, "--format")) {
            if (i + 1 >= argv.len) {
                try stderr.writeAll("ryk explain: --format requires a value and a command\n");
                return exit_codes.usage;
            }
            if (!std.mem.eql(u8, argv[i + 1], "json")) {
                try stderr.writeAll("ryk explain: only --format json is supported\n");
                return exit_codes.usage;
            }
            format_json = true;
            i += 1;
            cmd_start = i + 1;
            continue;
        }
        if (std.mem.startsWith(u8, arg, "-")) {
            try stderr.print("ryk explain: unknown option '{s}'.\nRun 'ryk help explain' for usage.\n", .{arg});
            return exit_codes.usage;
        }
        cmd_start = i;
        break;
    }

    if (cmd_start >= argv.len) {
        try stderr.writeAll(
            \\ryk explain: expected a command to explain.
            \\Examples:
            \\  ryk explain "rm -rf /"
            \\  ryk explain -- "git reset --hard"
            \\  ryk explain --format json "rm -rf /tmp/x"
            \\
        );
        return exit_codes.usage;
    }

    const command_text = try joinArgs(std.heap.smp_allocator, argv[cmd_start..]);
    defer std.heap.smp_allocator.free(command_text);

    // Walk up from cwd so nested directories still load project .ryk.toml.
    const workspace = core.supervisor.resolveWorkspaceRoot(io, std.heap.smp_allocator, null, ".") catch ".";
    defer if (!std.mem.eql(u8, workspace, ".")) std.heap.smp_allocator.free(workspace);

    var packs = pack_config.loadPackIdsForWorkspace(io, std.heap.smp_allocator, workspace) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.HomeDirectoryNotFound, error.FileNotFound => pack_config.LoadedPackIds{},
        else => {
            try stderr.writeAll("ryk explain: pack configuration could not be loaded (fail-closed)\n");
            return 2;
        },
    };
    defer packs.deinit(std.heap.smp_allocator);

    // Permanent + allow-once on product path (distinct API, not options.allowlists).
    // consume_allow_once=false: dry-run never burns single-use entries.
    var stores: shell_eval.ProductShellStores = .{};
    try shell_eval.loadProductShellStores(io, std.heap.smp_allocator, workspace, &stores);
    defer stores.deinit(std.heap.smp_allocator);

    // Allow-once cwd-scope matches exact evaluate cwd (hook uses event cwd). Prefer
    // process realpath so grants match human `ryk explain` at the deny site.
    const process_cwd = std.Io.Dir.cwd().realPathFileAlloc(io, ".", std.heap.smp_allocator) catch null;
    defer if (process_cwd) |p| std.heap.smp_allocator.free(p);

    // Opt-in TraceCollector only on explain path (hooks leave null).
    var collector = shell_engine.TraceCollector.init(std.heap.smp_allocator);
    defer collector.deinit();

    var eval = try shell_engine.evaluateCommand(std.heap.smp_allocator, command_text, .{
        .cwd = process_cwd orelse workspace,
        .default_packs_only = true,
        .extra_enabled = packs.enabled,
        .disabled = packs.disabled,
        .permanent_allowlist = stores.permanent,
        .allow_once_path = stores.allow_once_path,
        .io = io,
        .now_iso = stores.now_iso,
        .consume_allow_once = false,
        .trace = &collector,
    });
    defer eval.deinit(std.heap.smp_allocator);

    if (format_json) {
        try explain_render.writeJson(std.heap.smp_allocator, stdout, command_text, eval);
    } else if (verbose) {
        try explain_render.writePrettyVerbose(io, stdout, command_text, eval);
    } else {
        try explain_render.writePretty(io, stdout, command_text, eval);
    }
    return exit_codes.success;
}

fn joinArgs(allocator: std.mem.Allocator, args: []const []const u8) ![]u8 {
    if (args.len == 0) return allocator.dupe(u8, "");
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    for (args, 0..) |arg, idx| {
        if (idx > 0) try list.append(allocator, ' ');
        try list.appendSlice(allocator, arg);
    }
    return try list.toOwnedSlice(allocator);
}

// ---------------------------------------------------------------------------
// s-product-wire — ryk explain product loaders
// Loads permanent + allow-once; consume_allow_once=false (dry-run never burns).
// ---------------------------------------------------------------------------

const s_product_wire_now_seed = "2099-01-01T12:00:00Z";

extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;
extern "c" fn unsetenv(name: [*:0]const u8) c_int;

fn sProductWireDupEnvZ(name: [*:0]const u8) !?[:0]u8 {
    if (std.c.getenv(name)) |value| {
        return try std.testing.allocator.dupeZ(u8, std.mem.sliceTo(value, 0));
    }
    return null;
}

fn sProductWireRestoreEnv(name: [*:0]const u8, previous: ?[:0]u8) void {
    if (previous) |value| {
        _ = setenv(name, value.ptr, 1);
        std.testing.allocator.free(value);
    } else {
        _ = unsetenv(name);
    }
}

fn sProductWireJoin(parts: []const []const u8) ![]u8 {
    return try std.fs.path.join(std.testing.allocator, parts);
}

fn sProductWireIsolateXdg() !struct {
    config_tmp: std.testing.TmpDir,
    data_tmp: std.testing.TmpDir,
    config_root: []u8,
    data_root: []u8,
    prev_config: ?[:0]u8,
    prev_data: ?[:0]u8,

    fn deinit(self: *@This()) void {
        sProductWireRestoreEnv("XDG_CONFIG_HOME", self.prev_config);
        sProductWireRestoreEnv("XDG_DATA_HOME", self.prev_data);
        std.testing.allocator.free(self.config_root);
        std.testing.allocator.free(self.data_root);
        self.config_tmp.cleanup();
        self.data_tmp.cleanup();
    }
} {
    var config_tmp = std.testing.tmpDir(.{});
    errdefer config_tmp.cleanup();
    var data_tmp = std.testing.tmpDir(.{});
    errdefer data_tmp.cleanup();

    const config_z = try config_tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(config_z);
    const data_z = try data_tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(data_z);
    const config_root = try std.testing.allocator.dupe(u8, config_z);
    errdefer std.testing.allocator.free(config_root);
    const data_root = try std.testing.allocator.dupe(u8, data_z);
    errdefer std.testing.allocator.free(data_root);

    const prev_config = try sProductWireDupEnvZ("XDG_CONFIG_HOME");
    errdefer if (prev_config) |p| std.testing.allocator.free(p);
    const prev_data = try sProductWireDupEnvZ("XDG_DATA_HOME");
    errdefer if (prev_data) |p| std.testing.allocator.free(p);

    const config_z0 = try std.testing.allocator.dupeZ(u8, config_root);
    defer std.testing.allocator.free(config_z0);
    const data_z0 = try std.testing.allocator.dupeZ(u8, data_root);
    defer std.testing.allocator.free(data_z0);
    try std.testing.expectEqual(@as(c_int, 0), setenv("XDG_CONFIG_HOME", config_z0.ptr, 1));
    try std.testing.expectEqual(@as(c_int, 0), setenv("XDG_DATA_HOME", data_z0.ptr, 1));

    return .{
        .config_tmp = config_tmp,
        .data_tmp = data_tmp,
        .config_root = config_root,
        .data_root = data_root,
        .prev_config = prev_config,
        .prev_data = prev_data,
    };
}

/// User-layer kind=command (product path allows; project kind=command is stripped M-10).
fn sProductWireWriteUserCommandAllow(xdg_config: []const u8, command_text: []const u8, reason: []const u8) !void {
    const ryk_dir = try sProductWireJoin(&.{ xdg_config, "ryk"});
    defer std.testing.allocator.free(ryk_dir);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, ryk_dir);
    const path = try sProductWireJoin(&.{ xdg_config, "ryk", "allowlist.toml" });
    defer std.testing.allocator.free(path);
    try shell_engine.allowlist_store.addEntry(
        std.testing.io,
        std.testing.allocator,
        path,
        .user,
        .{
            .kind = .command,
            .command = command_text,
            .reason = reason,
            .created_at = "2026-07-25T12:00:00Z",
            .expires_at = "9999-01-01T00:00:00Z",
        },
        null,
    );
}

fn sProductWireSeedAllowOnce(
    xdg_data: []const u8,
    command_text: []const u8,
    cwd: []const u8,
    reason: []const u8,
) !void {
    const ryk_dir = try sProductWireJoin(&.{ xdg_data, "ryk"});
    defer std.testing.allocator.free(ryk_dir);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, ryk_dir);
    const pending_path = try sProductWireJoin(&.{ xdg_data, "ryk", shell_engine.allow_once.pending_file_name });
    defer std.testing.allocator.free(pending_path);
    const once_path = try sProductWireJoin(&.{ xdg_data, "ryk", shell_engine.allow_once.allow_once_file_name });
    defer std.testing.allocator.free(once_path);

    var issued = try shell_engine.allow_once.issuePending(
        std.testing.io,
        std.testing.allocator,
        pending_path,
        command_text,
        cwd,
        reason,
        s_product_wire_now_seed,
        true,
    );
    defer issued.deinit(std.testing.allocator);
    const entry = try shell_engine.allow_once.redeem(
        std.testing.io,
        std.testing.allocator,
        pending_path,
        once_path,
        issued.redeem_code,
        s_product_wire_now_seed,
        .cwd,
        cwd,
    );
    shell_engine.allow_once.freeAllowOnceEntry(std.testing.allocator, entry);
}

test "s-product-wire: shell_explain loads permanent allowlist (attribution, exit success)" {
    var xdg = try sProductWireIsolateXdg();
    defer xdg.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, ".git");
    const root_z = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root_z);
    const root = try std.testing.allocator.dupe(u8, root_z);
    defer std.testing.allocator.free(root);

    // Medium permanent FULL ALLOW (critical cannot unlock — product hard fence).
    const cmd = "git branch -D feature";
    const reason = "s-product-wire shell_explain permanent command marker";
    // User-layer command (project kind=command is stripped on product load — M-10).
    try sProductWireWriteUserCommandAllow(xdg.config_root, cmd, reason);

    const previous_cwd = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(previous_cwd);
    try std.process.setCurrentDir(std.testing.io, tmp.dir);
    defer std.process.setCurrentPath(std.testing.io, previous_cwd) catch {};

    var stdout_buf: [16384]u8 = undefined;
    var stderr_buf: [1024]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const code = try command(std.testing.io, &.{cmd}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    const out = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "ALLOW") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, reason) != null);
}

test "s-product-wire: shell_explain sets consume_allow_once false (does not burn single-use)" {
    var xdg = try sProductWireIsolateXdg();
    defer xdg.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, ".git");
    const root_z = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root_z);
    const root = try std.testing.allocator.dupe(u8, root_z);
    defer std.testing.allocator.free(root);

    const cmd = "git reset --hard HEAD";
    const reason = "s-product-wire shell_explain allow-once non-consume marker";
    try sProductWireSeedAllowOnce(xdg.data_root, cmd, root, reason);

    const previous_cwd = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(previous_cwd);
    try std.process.setCurrentDir(std.testing.io, tmp.dir);
    defer std.process.setCurrentPath(std.testing.io, previous_cwd) catch {};

    // Explain (dry-run): allow + attribute; leave store intact.
    {
        var stdout_buf: [16384]u8 = undefined;
        var stderr_buf: [1024]u8 = undefined;
        var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
        var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
        const code = try command(std.testing.io, &.{cmd}, &stdout_writer, &stderr_writer);
        try std.testing.expectEqual(exit_codes.success, code);
        const out = stdout_writer.buffered();
        try std.testing.expect(std.mem.indexOf(u8, out, "ALLOW") != null);
        try std.testing.expect(std.mem.indexOf(u8, out, reason) != null);
    }

    // M-12: ryk test is also dry-run (consume_allow_once=false) — grant survives.
    {
        var stdout_buf: [4096]u8 = undefined;
        var stderr_buf: [1024]u8 = undefined;
        var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
        var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
        const code = try shell_test.command(std.testing.io, &.{cmd}, &stdout_writer, &stderr_writer);
        try std.testing.expectEqual(@as(u8, 0), code);
        const out = stdout_writer.buffered();
        try std.testing.expect(std.mem.indexOf(u8, out, reason) != null);
    }

    // Explicit consume (hook/run/shim path) burns; second consume misses.
    var stores: shell_eval.ProductShellStores = .{};
    try shell_eval.loadProductShellStores(std.testing.io, std.testing.allocator, root, &stores);
    defer stores.deinit(std.testing.allocator);
    {
        var eval = try shell_engine.evaluateCommand(std.testing.allocator, cmd, .{
            .cwd = root,
            .default_packs_only = true,
            .permanent_allowlist = stores.permanent,
            .allow_once_path = stores.allow_once_path,
            .io = std.testing.io,
            .now_iso = stores.now_iso,
            .consume_allow_once = true,
        });
        defer eval.deinit(std.testing.allocator);
        try std.testing.expect(eval.decision == .allow);
    }
    {
        var eval = try shell_engine.evaluateCommand(std.testing.allocator, cmd, .{
            .cwd = root,
            .default_packs_only = true,
            .permanent_allowlist = stores.permanent,
            .allow_once_path = stores.allow_once_path,
            .io = std.testing.io,
            .now_iso = stores.now_iso,
            .consume_allow_once = true,
        });
        defer eval.deinit(std.testing.allocator);
        try std.testing.expect(eval.decision == .deny);
    }
}

test "s-product-wire: shell_explain without stores still reports DENY for destructive" {
    var xdg = try sProductWireIsolateXdg();
    defer xdg.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, ".git");

    const previous_cwd = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(previous_cwd);
    try std.process.setCurrentDir(std.testing.io, tmp.dir);
    defer std.process.setCurrentPath(std.testing.io, previous_cwd) catch {};

    var stdout_buf: [16384]u8 = undefined;
    var stderr_buf: [1024]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const code = try command(std.testing.io, &.{"git reset --hard HEAD"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "DENY") != null);
}

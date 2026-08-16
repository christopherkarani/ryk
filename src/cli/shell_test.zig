//! `ryk test` — evaluate a shell command via the Zig shell engine.
const std = @import("std");
const shell_engine = @import("../shell_engine/mod.zig");
const shell_eval = @import("shell_eval.zig");
const pack_config = @import("pack_config.zig");
const core = @import("ryk_core").core;
const reasons = @import("../tui/reasons.zig");

pub fn command(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    if (isRykTestHelp(argv)) {
        try stdout.writeAll(
            \\Usage: ryk test [--format json] <command>
            \\
            \\Evaluate a shell command with the in-process Zig shell engine.
            \\Exit 0 = allow, 2 = deny.
            \\
        );
        return 0;
    }

    if (shell_eval.resolveShellEvalBackend() == .rust) {
        try stderr.writeAll("ryk test: RYK_SHELL_EVAL=rust is no longer supported; Zig shell_engine is the sole Evaluate authority\n");
        return 3;
    }

    const parsed = parseTestArgv(argv, stderr) catch |err| switch (err) {
        error.Usage => return 64,
        else => return err,
    };
    if (parsed.command_args.len == 0) {
        try stderr.writeAll("ryk test: a command is required. Try `ryk test --help`.\n");
        return 64;
    }

    const command_text = try joinArgs(std.heap.smp_allocator, parsed.command_args);
    defer std.heap.smp_allocator.free(command_text);
    const format_json = parsed.format_json;

    // Walk up from cwd so nested directories still load project .ryk.toml.
    const workspace = core.supervisor.resolveWorkspaceRoot(io, std.heap.smp_allocator, null, ".") catch ".";
    defer if (!std.mem.eql(u8, workspace, ".")) std.heap.smp_allocator.free(workspace);

    var packs = pack_config.loadPackIdsForWorkspace(io, std.heap.smp_allocator, workspace) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.HomeDirectoryNotFound, error.FileNotFound => pack_config.LoadedPackIds{},
        else => {
            try stderr.writeAll("ryk test: pack configuration could not be loaded (fail-closed)\n");
            return 2;
        },
    };
    defer packs.deinit(std.heap.smp_allocator);

    // Permanent + allow-once on product path (distinct API, not options.allowlists).
    // consume_allow_once=false: `ryk test` is dry-run / inspect — never burns single-use
    // (M-12). Host execution (hook/run/shim) still defaults to true. Optional `--consume`
    // flag is deferred.
    var stores: shell_eval.ProductShellStores = .{};
    try shell_eval.loadProductShellStores(io, std.heap.smp_allocator, workspace, &stores, true);
    defer stores.deinit(std.heap.smp_allocator);

    // Allow-once cwd-scope matches exact evaluate cwd (hook uses event cwd). Prefer
    // process realpath so grants redeemed at the deny site match `ryk test` here.
    const process_cwd = std.Io.Dir.cwd().realPathFileAlloc(io, ".", std.heap.smp_allocator) catch null;
    defer if (process_cwd) |p| std.heap.smp_allocator.free(p);

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
    });
    defer eval.deinit(std.heap.smp_allocator);

    if (format_json) {
        const payload = struct {
            schema_version: i64 = 1,
            decision: []const u8,
            rule_id: ?[]const u8 = null,
            pack_id: ?[]const u8 = null,
            pattern_name: ?[]const u8 = null,
            severity: []const u8,
            reason: []const u8,
            source: []const u8 = "zig.shell_engine",
        }{
            .decision = eval.decision.toString(),
            .rule_id = eval.rule_id,
            .pack_id = eval.pack_id,
            .pattern_name = eval.pattern_name,
            .severity = eval.severity.toString(),
            .reason = eval.reason,
        };
        const json = try std.json.Stringify.valueAlloc(std.heap.smp_allocator, payload, .{});
        defer std.heap.smp_allocator.free(json);
        try stdout.writeAll(json);
        try stdout.writeAll("\n");
    } else {
        const decision = switch (eval.decision) {
            .allow => "ALLOW",
            .deny => "DENY",
        };
        try stdout.print("Decision: {s}\n", .{decision});
        if (eval.decision == .deny) {
            if (eval.rule_id) |rid| try stdout.print("Rule: {s}\n", .{rid});
            try stdout.print("Why: {s}\n", .{eval.reason});
            const alts = try reasons.safeAlternatives(std.heap.smp_allocator, command_text);
            defer {
                for (alts) |a| std.heap.smp_allocator.free(a.command);
                std.heap.smp_allocator.free(alts);
            }
            if (alts.len > 0) try stdout.print("Safer: {s}\n", .{alts[0].command});
            try stdout.print("Next: ryk explain \"{s}\"\n", .{command_text});
        } else {
            try stdout.print("Why: {s}\n", .{eval.reason});
        }
    }

    return switch (eval.decision) {
        .allow => 0,
        .deny => 2,
    };
}

const ParsedTestArgv = struct {
    format_json: bool,
    command_args: []const []const u8,
};

/// Only `ryk test` / `ryk test --help` / `ryk test -h`. `ryk test git --help`
/// evaluates the tested command; host help interception is `ryk <host> --help`.
fn isRykTestHelp(argv: []const []const u8) bool {
    if (argv.len == 0) return true;
    if (argv.len == 1 and (std.mem.eql(u8, argv[0], "--help") or std.mem.eql(u8, argv[0], "-h"))) return true;
    return false;
}

fn parseTestArgv(argv: []const []const u8, stderr: anytype) !ParsedTestArgv {
    var format_json = false;
    var i: usize = 0;
    while (i < argv.len) : (i += 1) {
        const arg = argv[i];
        if (std.mem.eql(u8, arg, "--")) {
            return .{ .format_json = format_json, .command_args = argv[i + 1 ..] };
        }
        if (std.mem.eql(u8, arg, "--format")) {
            if (i + 1 >= argv.len) {
                try stderr.writeAll("ryk test: --format requires a value and a command\n");
                return error.Usage;
            }
            if (!std.mem.eql(u8, argv[i + 1], "json")) {
                try stderr.writeAll("ryk test: only --format json is supported\n");
                return error.Usage;
            }
            format_json = true;
            i += 1;
            continue;
        }
        if (std.mem.eql(u8, arg, "--format=json")) {
            format_json = true;
            continue;
        }
        // First non-ryk-flag token starts the opaque command (`rm -rf /`, `git --help`).
        return .{ .format_json = format_json, .command_args = argv[i..] };
    }
    return .{ .format_json = format_json, .command_args = argv[i..] };
}

fn joinArgs(allocator: std.mem.Allocator, args: []const []const u8) ![]u8 {
    if (args.len == 0) return allocator.dupe(u8, "");
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    for (args, 0..) |arg, i| {
        if (i > 0) try list.append(allocator, ' ');
        try list.appendSlice(allocator, arg);
    }
    return try list.toOwnedSlice(allocator);
}

test "test git --help evaluates the command instead of ryk usage" {
    var stderr_buf: [256]u8 = undefined;
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const parsed = try parseTestArgv(&.{ "git", "--help" }, &stderr_writer);
    try std.testing.expectEqual(@as(usize, 2), parsed.command_args.len);
    try std.testing.expectEqualStrings("git", parsed.command_args[0]);
    try std.testing.expectEqualStrings("--help", parsed.command_args[1]);
    try std.testing.expect(!isRykTestHelp(&.{ "git", "--help" }));
    try std.testing.expect(isRykTestHelp(&.{"--help"}));
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "test argv treats dashed command tokens as opaque" {
    var stderr_buf: [256]u8 = undefined;
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const parsed = try parseTestArgv(&.{ "rm", "-rf", "/" }, &stderr_writer);
    try std.testing.expectEqual(@as(usize, 3), parsed.command_args.len);
    try std.testing.expectEqualStrings("rm", parsed.command_args[0]);
    try std.testing.expectEqualStrings("-rf", parsed.command_args[1]);
    try std.testing.expectEqualStrings("/", parsed.command_args[2]);
    try std.testing.expect(!parsed.format_json);

    stderr_writer = .fixed(&stderr_buf);
    const prefixed = try parseTestArgv(&.{ "--format", "json", "rm", "-rf", "/" }, &stderr_writer);
    try std.testing.expect(prefixed.format_json);
    try std.testing.expectEqualStrings("rm", prefixed.command_args[0]);
    try std.testing.expectEqualStrings("-rf", prefixed.command_args[1]);

    stderr_writer = .fixed(&stderr_buf);
    const after_dd = try parseTestArgv(&.{ "--format=json", "--", "git", "--help" }, &stderr_writer);
    try std.testing.expect(after_dd.format_json);
    try std.testing.expectEqualStrings("git", after_dd.command_args[0]);
    try std.testing.expectEqualStrings("--help", after_dd.command_args[1]);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "test --help writes usage to stdout" {
    var stdout_buf: [1024]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const code = try command(std.testing.io, &.{"--help"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(@as(u8, 0), code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "ryk test") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "test --format json is accepted as a ryk flag prefix" {
    var xdg = try sProductWireIsolateXdg();
    defer xdg.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, ".git");
    const previous_cwd = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(previous_cwd);
    try std.process.setCurrentDir(std.testing.io, tmp.dir);
    defer std.process.setCurrentPath(std.testing.io, previous_cwd) catch {};

    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [1024]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const code = try command(std.testing.io, &.{ "--format", "json", "echo", "hello" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(@as(u8, 0), code);
    const out = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "\"decision\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"schema_version\"") != null);
}

test "test rm -rf / is deny not an unknown-option error" {
    var xdg = try sProductWireIsolateXdg();
    defer xdg.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, ".git");
    const previous_cwd = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(previous_cwd);
    try std.process.setCurrentDir(std.testing.io, tmp.dir);
    defer std.process.setCurrentPath(std.testing.io, previous_cwd) catch {};

    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [1024]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const code = try command(std.testing.io, &.{ "rm", "-rf", "/" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(@as(u8, 2), code);
    const out = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "DENY") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Rule:") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Safer:") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "rm -rf ./build") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Always") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "always") == null);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "unknown option") == null);
}

test "test human output is a decision panel" {
    var xdg = try sProductWireIsolateXdg();
    defer xdg.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, ".git");
    const previous_cwd = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(previous_cwd);
    try std.process.setCurrentDir(std.testing.io, tmp.dir);
    defer std.process.setCurrentPath(std.testing.io, previous_cwd) catch {};

    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [1024]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const code = try command(std.testing.io, &.{"git status"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(@as(u8, 0), code);
    const out = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "ALLOW") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Always") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "always") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "allowlist") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Safer:") == null);
}

test "joinArgs" {
    const s = try joinArgs(std.testing.allocator, &.{ "git", "status" });
    defer std.testing.allocator.free(s);
    try std.testing.expectEqualStrings("git status", s);
}

// ---------------------------------------------------------------------------
// s-product-wire — ryk test product loaders
// Loads permanent + allow-once into EvaluateOptions (not allowlists);
// consume_allow_once=false (dry-run; does not burn single-use) — M-12.
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

fn sProductWireWriteProjectRuleAllow(root: []const u8, rule_id: []const u8, reason: []const u8) !void {
    const ryk_dir = try sProductWireJoin(&.{ root, ".ryk" });
    defer std.testing.allocator.free(ryk_dir);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, ryk_dir);
    const path = try sProductWireJoin(&.{ root, ".ryk", "allowlist.toml" });
    defer std.testing.allocator.free(path);
    try shell_engine.allowlist_store.addEntry(
        std.testing.io,
        std.testing.allocator,
        path,
        .project,
        .{
            .kind = .rule,
            .id = rule_id,
            .reason = reason,
            .created_at = "2026-07-25T12:00:00Z",
            .expires_at = "9999-01-01T00:00:00Z",
        },
        null,
    );
}

fn sProductWireSeedAllowOnce(
    xdg_data: []const u8,
    cmd_text: []const u8,
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
        cmd_text,
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

test "s-product-wire: shell_test loads permanent allowlist and allows with attribution" {
    var xdg = try sProductWireIsolateXdg();
    defer xdg.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, ".git");
    const root_z = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root_z);
    const root = try std.testing.allocator.dupe(u8, root_z);
    defer std.testing.allocator.free(root);

    // Medium permanent skip (critical cannot unlock — product hard fence).
    const reason = "s-product-wire shell_test permanent rule marker";
    try sProductWireWriteProjectRuleAllow(root, "core.git:branch-force-delete", reason);

    const previous_cwd = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(previous_cwd);
    try std.process.setCurrentDir(std.testing.io, tmp.dir);
    defer std.process.setCurrentPath(std.testing.io, previous_cwd) catch {};

    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [1024]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, &.{"git branch -D feature"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(@as(u8, 0), code);
    const out = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "ALLOW") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, reason) != null);
}

test "s-product-wire: shell_test consume_allow_once false (does not burn single-use)" {
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
    const reason = "s-product-wire shell_test allow-once dry-run marker";
    try sProductWireSeedAllowOnce(xdg.data_root, cmd, root, reason);

    const previous_cwd = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(previous_cwd);
    try std.process.setCurrentDir(std.testing.io, tmp.dir);
    defer std.process.setCurrentPath(std.testing.io, previous_cwd) catch {};

    // First evaluate: allow, no consume (M-12).
    {
        var stdout_buf: [4096]u8 = undefined;
        var stderr_buf: [1024]u8 = undefined;
        var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
        var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
        const code = try command(std.testing.io, &.{cmd}, &stdout_writer, &stderr_writer);
        try std.testing.expectEqual(@as(u8, 0), code);
        const out = stdout_writer.buffered();
        try std.testing.expect(std.mem.indexOf(u8, out, "ALLOW") != null);
        try std.testing.expect(std.mem.indexOf(u8, out, reason) != null);
    }

    // Second evaluate: grant still present → allow again.
    {
        var stdout_buf: [4096]u8 = undefined;
        var stderr_buf: [1024]u8 = undefined;
        var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
        var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
        const code = try command(std.testing.io, &.{cmd}, &stdout_writer, &stderr_writer);
        try std.testing.expectEqual(@as(u8, 0), code);
        const out = stdout_writer.buffered();
        try std.testing.expect(std.mem.indexOf(u8, out, "ALLOW") != null);
    }
}

test "s-product-wire: explicit consume_allow_once true burns single-use (engine path)" {
    // Proves burn still works when consume is opted in (hook/run/shim default).
    // `ryk test` command path stays dry-run; this uses evaluateCommand directly.
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
    const reason = "s-product-wire explicit consume burn marker";
    try sProductWireSeedAllowOnce(xdg.data_root, cmd, root, reason);

    var stores: shell_eval.ProductShellStores = .{};
    try shell_eval.loadProductShellStores(std.testing.io, std.testing.allocator, root, &stores, true);
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
        try std.testing.expect(std.mem.indexOf(u8, eval.reason, reason) != null);
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

test "s-product-wire: shell_test without stores still denies destructive" {
    var xdg = try sProductWireIsolateXdg();
    defer xdg.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, ".git");

    const previous_cwd = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(previous_cwd);
    try std.process.setCurrentDir(std.testing.io, tmp.dir);
    defer std.process.setCurrentPath(std.testing.io, previous_cwd) catch {};

    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [1024]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const code = try command(std.testing.io, &.{"git reset --hard HEAD"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(@as(u8, 2), code);
}

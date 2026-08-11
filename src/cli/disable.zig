const std = @import("std");

const exit_codes = @import("exit_codes.zig");
const help = @import("help.zig");
const plugin = @import("plugin.zig");
const danger_confirmation = @import("danger_confirmation.zig");
const suggestions = @import("suggestions.zig");

// ---------------------------------------------------------------------------
// Top-level dispatch
// ---------------------------------------------------------------------------

const DisableTarget = enum { codex, claude, cursor, opencode, openclaw, hermes, grok, all };

pub fn command(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    var target: DisableTarget = .all;
    var yes = false;

    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();

    var index: usize = 0;
    while (index < argv.len) : (index += 1) {
        const arg = argv[index];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            _ = try help.writeCommand(io, stdout, "stop");
            return exit_codes.success;
        }
        if (std.mem.eql(u8, arg, "--yes")) {
            yes = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "codex")) {
            target = .codex;
            continue;
        }
        if (std.mem.eql(u8, arg, "claude")) {
            target = .claude;
            continue;
        }
        if (std.mem.eql(u8, arg, "cursor")) {
            target = .cursor;
            continue;
        }
        if (std.mem.eql(u8, arg, "opencode")) {
            target = .opencode;
            continue;
        }
        if (std.mem.eql(u8, arg, "openclaw")) {
            target = .openclaw;
            continue;
        }
        if (std.mem.eql(u8, arg, "hermes")) {
            target = .hermes;
            continue;
        }
        if (std.mem.eql(u8, arg, "grok")) {
            target = .grok;
            continue;
        }
        if (std.mem.eql(u8, arg, "all")) {
            target = .all;
            continue;
        }
        try suggestions.writeUnknownOption(
            stderr,
            "ryk stop",
            arg,
            &.{ "codex", "claude", "cursor", "opencode", "openclaw", "hermes", "grok", "all", "--yes", "--help" },
            "stop",
        );
        return exit_codes.usage;
    }

    if (!yes) {
        const stdin = std.Io.File.stdin();
        const host_label = if (target == .all) "all" else @tagName(target);
        var prompt_buf: [128]u8 = undefined;
        const prompt = std.fmt.bufPrint(&prompt_buf, "Stop ryk for {s}? This removes plugin registrations from host agents.", .{host_label}) catch "Stop ryk?";
        const decision = danger_confirmation.decide(io, stdout, prompt, false, try stdin.isTty(io), null) catch |err| {
            try stderr.print("ryk stop: confirmation failed: {s}\n", .{@errorName(err)});
            return exit_codes.general;
        };
        switch (decision) {
            .proceed => {},
            .cancelled => {
                try stdout.writeAll("canceled\n");
                return exit_codes.success;
            },
            .requires_yes => {
                try stderr.writeAll("ryk stop: requires --yes or run interactively.\n");
                return exit_codes.usage;
            },
        }
    }

    try stdout.writeAll("ryk Stop\n\n");

    const targets = switch (target) {
        .codex => &[_]DisableTarget{.codex},
        .claude => &[_]DisableTarget{.claude},
        .cursor => &[_]DisableTarget{.cursor},
        .opencode => &[_]DisableTarget{.opencode},
        .openclaw => &[_]DisableTarget{.openclaw},
        .hermes => &[_]DisableTarget{.hermes},
        .grok => &[_]DisableTarget{.grok},
        .all => &[_]DisableTarget{ .codex, .claude, .cursor, .opencode, .openclaw, .hermes, .grok },
    };

    var success_count: usize = 0;
    var fail_count: usize = 0;

    for (targets) |t| {
        try stdout.print("→ Disabling {s}...\n", .{@tagName(t)});
        const did_disable = switch (t) {
            .opencode => try disableOpenCode(io, allocator, stdout),
            .cursor => try disableCursor(io, allocator, stdout),
            .openclaw => try disableOpenClaw(io, allocator, stdout),
            .hermes => try disableHermes(io, allocator, stdout),
            .codex => try disableCodex(io, allocator, stdout),
            .claude => try disableClaude(io, allocator, stdout),
            .grok => try disableGrok(io, allocator, stdout),
            .all => unreachable,
        };
        if (did_disable) {
            try stdout.print("  ✓ {s} disabled\n", .{@tagName(t)});
            success_count += 1;
        } else {
            try stdout.print("  ✗ {s} not found or failed\n", .{@tagName(t)});
            fail_count += 1;
        }
    }

    try stdout.writeAll("\n");
    if (success_count == 0 and fail_count == 0) {
        try stdout.writeAll("No ryk plugins were found to disable.\n");
    } else if (fail_count == 0) {
        try stdout.writeAll("✅ All ryk plugins have been disabled.\n");
    } else {
        try stdout.print("⚠️  Disabled {d} plugin(s), {d} failed.\n", .{ success_count, fail_count });
    }
    try stdout.writeAll("ryk binary and policy files remain in place.\n");
    try stdout.writeAll("Restart protection with: ryk start\n");
    return exit_codes.success;
}

// ---------------------------------------------------------------------------
// Per-host disable functions (pub so uninstall.zig can delegate)
// ---------------------------------------------------------------------------

pub fn disableOpenCode(io: std.Io, allocator: std.mem.Allocator, stdout: anytype) !bool {
    var removed = false;
    const project_path = try std.fs.path.join(allocator, &.{ ".opencode", "plugins", "ryk.ts" });
    defer allocator.free(project_path);
    const global_path = blk: {
        const home = std.c.getenv("HOME") orelse break :blk null;
        break :blk try std.fs.path.join(allocator, &.{ std.mem.span(home), ".config", "opencode", "plugins", "ryk.ts" });
    };
    defer if (global_path) |p| allocator.free(p);

    if (plugin.fileExistsAbsolute(io, project_path)) {
        blk: {
            std.Io.Dir.cwd().deleteFile(io, project_path) catch |err| {
                try stdout.print("  project plugin: failed to remove ({s})\n", .{@errorName(err)});
                break :blk;
            };
            try stdout.writeAll("  project plugin: removed (.opencode/plugins/ryk.ts)\n");
            removed = true;
        }
    }
    if (global_path) |gp| {
        if (plugin.fileExistsAbsolute(io, gp)) {
            blk: {
                std.Io.Dir.cwd().deleteFile(io, gp) catch |err| {
                    try stdout.print("  global plugin: failed to remove ({s})\n", .{@errorName(err)});
                    break :blk;
                };
                try stdout.writeAll("  global plugin: removed (~/.config/opencode/plugins/ryk.ts)\n");
                removed = true;
            }
        }
    }
    return removed;
}

pub fn disableOpenClaw(io: std.Io, allocator: std.mem.Allocator, stdout: anytype) !bool {
    if (plugin.binaryInPath(io, allocator, "openclaw")) {
        try stdout.writeAll("  openclaw: running 'openclaw plugins uninstall ryk' (10s timeout)...\n");

        const status = runOpenClawUninstall(allocator) catch |err| blk: {
            try stdout.print("  host uninstall: failed ({s})\n", .{@errorName(err)});
            try stdout.writeAll("    → Will fall back to direct file cleanup where possible.\n");
            break :blk 255;
        };

        if (status == 0) {
            try stdout.writeAll("  host uninstall: removed via openclaw plugins uninstall\n");
            return true;
        } else {
            try stdout.print("  host uninstall: openclaw exited with code {d} (or timed out)\n", .{status});
            try stdout.writeAll("    → Attempting direct cleanup of known ryk plugin files for OpenClaw...\n");
            return false;
        }
    }
    try stdout.writeAll("  status: openclaw binary not found in PATH\n");
    return false;
}

pub fn disableHermes(io: std.Io, allocator: std.mem.Allocator, stdout: anytype) !bool {
    var disabled = false;
    if (plugin.binaryInPath(io, allocator, "hermes")) {
        try stdout.writeAll("  hermes: running 'hermes plugins disable ryk' (10s timeout)...\n");

        const status = runHermesDisable(allocator) catch |err| blk: {
            try stdout.print("  host disable: failed ({s})\n", .{@errorName(err)});
            try stdout.writeAll("    → Will perform direct file cleanup of ~/.hermes/plugins/ryk/\n");
            break :blk 255;
        };
        if (status == 0) {
            try stdout.writeAll("  host disable: hermes plugins disable ryk\n");
            disabled = true;
        } else {
            try stdout.print("  host disable: hermes exited with code {d} (or timed out)\n", .{status});
            try stdout.writeAll("    → Ensuring ~/.hermes/plugins/ryk/ is removed directly...\n");
        }
    }
    const user_root = try plugin.hermesUserPluginRoot(allocator);
    defer allocator.free(user_root);
    if (plugin.dirExists(user_root)) {
        blk: {
            std.Io.Dir.cwd().deleteTree(io, user_root) catch |err| {
                try stdout.print("  plugin files: failed to remove ({s})\n", .{@errorName(err)});
                break :blk;
            };
            try stdout.print("  plugin files: removed {s}\n", .{user_root});
            disabled = true;
        }
    }
    return disabled;
}

pub fn disableCodex(io: std.Io, allocator: std.mem.Allocator, stdout: anytype) !bool {
    return try removeKnownPluginPaths(io, allocator, stdout, "codex", &[_][]const u8{
        ".agents/plugins/ryk",
        ".codex/plugins/ryk",
    });
}

pub fn disableClaude(io: std.Io, allocator: std.mem.Allocator, stdout: anytype) !bool {
    return try removeKnownPluginPaths(io, allocator, stdout, "claude", &[_][]const u8{
        ".claude/plugins/ryk",
    });
}

/// Remove the managed Grok Build Command Guard hook (`~/.grok/hooks/ryk.json`)
/// and strip ryk PreToolUse entries from legacy `~/.grok/user-settings.json`.
/// Does not delete unrelated hooks under `~/.grok/hooks/` or non-ryk settings.
pub fn disableGrok(io: std.Io, allocator: std.mem.Allocator, stdout: anytype) !bool {
    const home_z = std.c.getenv("HOME") orelse {
        try stdout.writeAll("  grok: HOME not set; skipped\n");
        return false;
    };
    const home = std.mem.span(home_z);
    const removed = @import("grok_install.zig").uninstallAtHome(io, allocator, home) catch |err| {
        try stdout.print("  grok hooks: failed to remove ryk hooks ({s})\n", .{@errorName(err)});
        return false;
    };
    if (removed) {
        try stdout.writeAll("  grok hooks: removed managed ryk hook and stripped legacy user-settings PreToolUse\n");
        try stdout.writeAll("    → Restart Grok Build so hooks reload (new session).\n");
    } else {
        try stdout.writeAll("  grok hooks: managed ryk hook / legacy user-settings ryk entries not present\n");
    }
    return removed;
}

pub fn disableCursor(io: std.Io, allocator: std.mem.Allocator, stdout: anytype) !bool {
    var removed = try removeKnownPluginPaths(io, allocator, stdout, "cursor", &[_][]const u8{
        ".cursor/hooks/ryk-pre-shell.py",
    });

    const global_hook = if (std.c.getenv("HOME")) |home|
        try std.fs.path.join(allocator, &.{ std.mem.span(home), ".cursor", "hooks", "ryk-pre-shell.py" })
    else
        null;
    defer if (global_hook) |p| allocator.free(p);
    if (global_hook) |path| {
        removed = try removeKnownPluginPaths(io, allocator, stdout, "cursor", &[_][]const u8{path}) or removed;
    }

    removed = try disableCursorHooksJsonIfRykOnly(io, allocator, stdout, ".cursor/hooks.json") or removed;
    const global_hooks_json = if (std.c.getenv("HOME")) |home|
        try std.fs.path.join(allocator, &.{ std.mem.span(home), ".cursor", "hooks.json" })
    else
        null;
    defer if (global_hooks_json) |p| allocator.free(p);
    if (global_hooks_json) |path| {
        removed = try disableCursorHooksJsonIfRykOnly(io, allocator, stdout, path) or removed;
    }

    return removed;
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn disableCursorHooksJsonIfRykOnly(io: std.Io, allocator: std.mem.Allocator, stdout: anytype, path: []const u8) !bool {
    if (!plugin.fileExistsAbsolute(io, path)) return false;

    const content = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(64 * 1024)) catch |err| {
        try stdout.print("  cursor hooks: failed to read {s} ({s})\n", .{ path, @errorName(err) });
        return false;
    };
    defer allocator.free(content);

    var parsed = std.json.parseFromSlice(std.json.Value, allocator, content, .{}) catch |err| {
        try stdout.print("  cursor hooks: failed to parse {s} ({s})\n", .{ path, @errorName(err) });
        return false;
    };
    defer parsed.deinit();
    if (parsed.value != .object) return false;

    const hooks = parsed.value.object.getPtr("hooks") orelse return false;
    if (hooks.* != .object) return false;
    const before_shell = hooks.object.getPtr("beforeShellExecution") orelse return false;
    if (before_shell.* != .array) return false;

    const tree_allocator = parsed.arena.allocator();
    var retained = std.json.Array.init(tree_allocator);
    var removed = false;
    for (before_shell.array.items) |entry| {
        const managed = if (entry == .object) blk: {
            const command_value = entry.object.get("command") orelse break :blk false;
            break :blk command_value == .string and isRykCursorHookCommand(command_value.string);
        } else false;
        if (managed) {
            removed = true;
        } else {
            try retained.append(entry);
        }
    }
    if (!removed) return false;

    before_shell.* = .{ .array = retained };
    const rewritten = try std.json.Stringify.valueAlloc(allocator, parsed.value, .{ .whitespace = .indent_2 });
    defer allocator.free(rewritten);
    try overwriteTextFile(io, path, rewritten);
    try stdout.print("  cursor hooks: disabled ryk beforeShellExecution in {s}\n", .{path});
    return true;
}

fn isRykCursorHookCommand(hook_command: []const u8) bool {
    const trimmed = std.mem.trim(u8, hook_command, " \t\r\n");
    return std.mem.eql(u8, trimmed, "ryk-pre-shell.py") or
        std.mem.endsWith(u8, trimmed, "/ryk-pre-shell.py") or
        std.mem.endsWith(u8, trimmed, "\\ryk-pre-shell.py");
}

fn overwriteTextFile(io: std.Io, path: []const u8, content: []const u8) !void {
    if (std.fs.path.isAbsolute(path)) {
        const file = try std.Io.Dir.createFileAbsolute(io, path, .{ .truncate = true });
        defer file.close(io);
        try file.writeStreamingAll(io, content);
        return;
    }
    const file = try std.Io.Dir.cwd().createFile(io, path, .{ .truncate = true });
    defer file.close(io);
    try file.writeStreamingAll(io, content);
}

pub fn runOpenClawUninstall(allocator: std.mem.Allocator) !u8 {
    const child_process = @import("child_process.zig");
    const argv = [_][]const u8{ "openclaw", "plugins", "uninstall", "ryk" };

    // Use the robust timed runner (10s) so a stuck/broken/misbehaving openclaw
    // cannot hang `ryk uninstall` or `ryk stop` forever.
    const res = try child_process.runHostCommandTimed(allocator, &argv, 10_000, null, null);
    defer child_process.deinitHostCommandResult(res, allocator);

    if (res.timed_out) {
        // The caller (disableOpenClaw / uninstall) can decide to do direct fallback.
        return 255;
    }
    return res.exit_code;
}

pub fn runHermesDisable(allocator: std.mem.Allocator) !u8 {
    const child_process = @import("child_process.zig");
    const argv = [_][]const u8{ "hermes", "plugins", "disable", "ryk" };

    const res = try child_process.runHostCommandTimed(allocator, &argv, 10_000, null, null);
    defer child_process.deinitHostCommandResult(res, allocator);

    if (res.timed_out) {
        return 255;
    }
    return res.exit_code;
}

pub fn removeKnownPluginPaths(io: std.Io, allocator: std.mem.Allocator, stdout: anytype, host_name: []const u8, paths: []const []const u8) !bool {
    var removed_any = false;
    for (paths) |rel_path| {
        if (plugin.fileExistsAbsolute(io, rel_path)) {
            std.Io.Dir.cwd().deleteFile(io, rel_path) catch |err| {
                try stdout.print("  {s} plugin: failed to remove {s} ({s})\n", .{ host_name, rel_path, @errorName(err) });
                continue;
            };
            try stdout.print("  {s} plugin: removed {s}\n", .{ host_name, rel_path });
            removed_any = true;
        }
        if (plugin.dirExists(rel_path)) {
            std.Io.Dir.cwd().deleteTree(io, rel_path) catch |err| {
                try stdout.print("  {s} plugin: failed to remove {s} ({s})\n", .{ host_name, rel_path, @errorName(err) });
                continue;
            };
            try stdout.print("  {s} plugin: removed {s}\n", .{ host_name, rel_path });
            removed_any = true;
        }
    }
    _ = allocator;
    return removed_any;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "stop command help and invalid args" {
    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const help_code = try command(std.testing.io, &.{"--help"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, help_code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "stop") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "cursor") != null);

    stdout_writer = .fixed(&stdout_buf);
    stderr_writer = .fixed(&stderr_buf);
    const bad_code = try command(std.testing.io, &.{"--unknown"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, bad_code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "ryk stop") != null);

    stdout_writer = .fixed(&stdout_buf);
    stderr_writer = .fixed(&stderr_buf);
    const typo_code = try command(std.testing.io, &.{"codxe"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, typo_code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "Did you mean 'codex'?") != null);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "ryk help stop") != null);
}

test "stop rejects compatibility target spellings" {
    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const hermes_alias_code = try command(std.testing.io, &.{"hermess"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, hermes_alias_code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "requires --yes") == null);

    stdout_writer = .fixed(&stdout_buf);
    stderr_writer = .fixed(&stderr_buf);
    const all_alias_code = try command(std.testing.io, &.{"-all"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, all_alias_code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "requires --yes") == null);
}

test "cursor cleanup only rewrites canonical ryk hook registrations" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const hooks_path = try std.fs.path.join(std.testing.allocator, &.{ root, "hooks.json" });
    defer std.testing.allocator.free(hooks_path);

    const canonical = try std.Io.Dir.createFileAbsolute(std.testing.io, hooks_path, .{});
    try canonical.writeStreamingAll(
        std.testing.io,
        "{\"version\":1,\"hooks\":{\"beforeShellExecution\":[{\"command\":\"/tmp/ryk-pre-shell.py\"}]}}",
    );
    canonical.close(std.testing.io);

    var stdout_buf: [2048]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    try std.testing.expect(try disableCursorHooksJsonIfRykOnly(
        std.testing.io,
        std.testing.allocator,
        &stdout_writer,
        hooks_path,
    ));
    const disabled = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, hooks_path, std.testing.allocator, .limited(4096));
    defer std.testing.allocator.free(disabled);
    try std.testing.expect(std.mem.indexOf(u8, disabled, "\"beforeShellExecution\": []") != null);

    const mixed = try std.Io.Dir.createFileAbsolute(std.testing.io, hooks_path, .{ .truncate = true });
    try mixed.writeStreamingAll(
        std.testing.io,
        "{\"metadata\":\"ryk\",\"hooks\":{\"beforeShellExecution\":[{\"command\":\"/tmp/ryk-pre-shell.py\"},{\"command\":\"/tmp/user-hook.sh\"}]}}",
    );
    mixed.close(std.testing.io);
    stdout_writer = .fixed(&stdout_buf);
    try std.testing.expect(try disableCursorHooksJsonIfRykOnly(
        std.testing.io,
        std.testing.allocator,
        &stdout_writer,
        hooks_path,
    ));
    const mixed_disabled = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, hooks_path, std.testing.allocator, .limited(4096));
    defer std.testing.allocator.free(mixed_disabled);
    try std.testing.expect(std.mem.indexOf(u8, mixed_disabled, "/tmp/user-hook.sh") != null);
    try std.testing.expect(std.mem.indexOf(u8, mixed_disabled, "\"metadata\": \"ryk\"") != null);

    const legacy = try std.Io.Dir.createFileAbsolute(std.testing.io, hooks_path, .{ .truncate = true });
    try legacy.writeStreamingAll(
        std.testing.io,
        "{\"version\":1,\"hooks\":{\"beforeShellExecution\":[{\"command\":\"/tmp/orca-pre-shell.py\"}]}}",
    );
    legacy.close(std.testing.io);
    stdout_writer = .fixed(&stdout_buf);
    try std.testing.expect(!try disableCursorHooksJsonIfRykOnly(
        std.testing.io,
        std.testing.allocator,
        &stdout_writer,
        hooks_path,
    ));
}

test "stop all requires confirmation in non-TTY" {
    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, &.{"all"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "--yes") != null);
}

test "stop success output points at ryk start not setup" {
    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    // --yes skips confirmation; no plugins required for footer messaging.
    const code = try command(std.testing.io, &.{"--yes"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    const out = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "ryk start") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "ryk setup") == null);
}

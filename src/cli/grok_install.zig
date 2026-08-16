const std = @import("std");
const builtin = @import("builtin");

/// Official Grok Build (xai-org/grok-build) discovers global hooks from
/// `$GROK_HOME/hooks/*.json` (default `~/.grok/hooks/`). This managed file is
/// owned entirely by ryk — other team hooks live in sibling JSON files.
pub const hooks_relative_dir = ".grok/hooks";
pub const managed_hook_filename = "ryk.json";
pub const managed_hook_relative_path = hooks_relative_dir ++ "/" ++ managed_hook_filename;

/// Legacy community CLI / early ryk path. Still dual-written so older install
/// evidence and any settings-file consumers keep working, but official Grok
/// Build does not load this file for hooks.
pub const settings_relative_path = ".grok/user-settings.json";
pub const max_settings_size = 1024 * 1024;
pub const max_hook_file_size = 1024 * 1024;

/// Matcher that official Grok Build expands to its shell tool
/// (`run_terminal_command` / `run_terminal_cmd`) via the Bash Claude alias.
pub const shell_matcher = "Bash";

/// Matcher that official Grok Build expands to its file-read tool (`read_file`)
/// via the Claude Read alias.
pub const read_matcher = "Read";

pub const MergeResult = struct {
    bytes: []u8,
    changed: bool,
};

pub const InstallResult = struct {
    changed: bool,
    /// Primary install path (managed hooks file).
    settings_path: []u8,

    pub fn deinit(self: InstallResult, allocator: std.mem.Allocator) void {
        allocator.free(self.settings_path);
    }
};

/// Return whether Grok Build will load a ryk PreToolUse Command Guard.
///
/// Only `~/.grok/hooks/ryk.json` counts. Legacy entries in
/// `user-settings.json` are not loaded by official Grok Build and must not
/// make `doctor --fix` skip the managed install (that left hosts "wired"
/// with no file under hooks/).
pub fn installed(io: std.Io, allocator: std.mem.Allocator) bool {
    const home_z = std.c.getenv("HOME") orelse return false;
    return installedAtHome(io, allocator, std.mem.span(home_z));
}

pub fn installedAtHome(io: std.Io, allocator: std.mem.Allocator, home: []const u8) bool {
    return managedHookInstalledAtHome(io, allocator, home);
}

/// True when only the legacy user-settings path has a ryk hook (migration debt).
/// Not used for day-one wired evidence.
pub fn legacyOnlyInstalledAtHome(io: std.Io, allocator: std.mem.Allocator, home: []const u8) bool {
    if (managedHookInstalledAtHome(io, allocator, home)) return false;
    return legacySettingsInstalledAtHome(io, allocator, home);
}

fn managedHookInstalledAtHome(io: std.Io, allocator: std.mem.Allocator, home: []const u8) bool {
    const path = std.fs.path.join(allocator, &.{ home, managed_hook_relative_path }) catch return false;
    defer allocator.free(path);
    const bytes = std.Io.Dir.cwd().readFileAlloc(
        io,
        path,
        allocator,
        .limited(max_hook_file_size),
    ) catch return false;
    defer allocator.free(bytes);
    return fileContainsRykGrokHook(allocator, bytes);
}

fn legacySettingsInstalledAtHome(io: std.Io, allocator: std.mem.Allocator, home: []const u8) bool {
    const settings_path = std.fs.path.join(allocator, &.{ home, settings_relative_path }) catch return false;
    defer allocator.free(settings_path);
    const settings = std.Io.Dir.cwd().readFileAlloc(
        io,
        settings_path,
        allocator,
        .limited(max_settings_size),
    ) catch return false;
    defer allocator.free(settings);
    return fileContainsRykGrokHook(allocator, settings);
}

fn fileContainsRykGrokHook(allocator: std.mem.Allocator, bytes: []const u8) bool {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, bytes, .{}) catch return false;
    defer parsed.deinit();
    if (parsed.value != .object) return false;
    const hooks = parsed.value.object.get("hooks") orelse return false;
    if (hooks != .object) return false;
    const pre_tool_use = hooks.object.get("PreToolUse") orelse return false;
    if (pre_tool_use != .array) return false;
    for (pre_tool_use.array.items) |entry| {
        if (entryContainsAnyRykHook(entry)) return true;
    }
    return false;
}

/// Conservative identity check for stdout captured from a bounded `grok
/// --help` probe. Accepts official Grok Build (xai-org) and the community
/// superagent-ai/grok-cli surface; a name-only PATH hit is not enough.
pub fn isSupportedCliHelp(help_output: []const u8) bool {
    // Official xai-org/grok-build (SpaceXAI Grok Build TUI).
    if (std.mem.indexOf(u8, help_output, "Grok Build") != null and
        (std.mem.indexOf(u8, help_output, "Usage: grok") != null or
            std.mem.indexOf(u8, help_output, "Usage:\n  grok") != null or
            std.mem.indexOf(u8, help_output, "Usage: grok [OPTIONS]") != null))
    {
        return true;
    }
    // Community superagent-ai/grok-cli (Bun/OpenTUI) — retained for PATH probes.
    return std.mem.indexOf(u8, help_output, "AI coding agent powered by Grok") != null and
        std.mem.indexOf(u8, help_output, "--prompt <prompt>") != null and
        std.mem.indexOf(u8, help_output, "--verify") != null and
        std.mem.indexOf(u8, help_output, "--batch-api") != null;
}

/// Build the managed hook document owned by ryk (full file replace).
/// PreToolUse registers Bash (shell) and Read (file-read) matchers with the same command.
pub fn managedHookDocumentAlloc(allocator: std.mem.Allocator, ryk_binary: []const u8) ![]u8 {
    const command = try hookCommandAlloc(allocator, ryk_binary);
    defer allocator.free(command);
    const quoted_command = try std.json.Stringify.valueAlloc(allocator, command, .{});
    defer allocator.free(quoted_command);
    return std.fmt.allocPrint(allocator,
        \\{{
        \\  "hooks": {{
        \\    "PreToolUse": [
        \\      {{
        \\        "matcher": "{s}",
        \\        "hooks": [
        \\          {{
        \\            "type": "command",
        \\            "command": {s},
        \\            "timeout": 30
        \\          }}
        \\        ]
        \\      }},
        \\      {{
        \\        "matcher": "{s}",
        \\        "hooks": [
        \\          {{
        \\            "type": "command",
        \\            "command": {s},
        \\            "timeout": 30
        \\          }}
        \\        ]
        \\      }}
        \\    ]
        \\  }}
        \\}}
        \\
    , .{ shell_matcher, quoted_command, read_matcher, quoted_command });
}

/// Merge ryk's Grok PreToolUse hook into an existing settings document.
///
/// The returned bytes are owned by `allocator`. Existing settings and hook
/// entries are retained in their original order. Invalid hook container shapes
/// are rejected instead of being overwritten.
pub fn mergeSettingsAlloc(
    allocator: std.mem.Allocator,
    existing: []const u8,
    ryk_binary: []const u8,
) !MergeResult {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, existing, .{}) catch
        return error.InvalidSettings;
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidSettings;
    const tree_allocator = parsed.arena.allocator();

    const command = try hookCommandAlloc(allocator, ryk_binary);
    defer allocator.free(command);

    var hooks = parsed.value.object.getPtr("hooks");
    if (hooks == null) {
        try parsed.value.object.put(tree_allocator, "hooks", .{ .object = .empty });
        hooks = parsed.value.object.getPtr("hooks");
    }
    if (hooks.?.* != .object) return error.InvalidHooks;

    var pre_tool_use = hooks.?.object.getPtr("PreToolUse");
    if (pre_tool_use == null) {
        try hooks.?.object.put(tree_allocator, "PreToolUse", .{ .array = std.json.Array.init(tree_allocator) });
        pre_tool_use = hooks.?.object.getPtr("PreToolUse");
    }
    if (pre_tool_use.?.* != .array) return error.InvalidPreToolUseHooks;

    // Require both Bash and Read matchers with the current fail-closed command.
    // Legacy `…/ryk hook grok PreToolUse` still counts as ryk (uninstall/identity)
    // but must be rewritten — official Grok fail-opens on that shape when ryk is gone.
    var has_bash_ryk = false;
    var has_read_ryk = false;
    var rewritten = false;
    for (pre_tool_use.?.array.items) |*entry| {
        if (try rewriteRykHookCommands(tree_allocator, entry, command)) rewritten = true;
        if (!entryContainsExactRykHook(entry.*, command)) continue;
        const matcher_val = if (entry.* == .object) entry.object.get("matcher") else null;
        if (matcher_val) |m| {
            if (m == .string) {
                if (std.mem.eql(u8, m.string, shell_matcher)) has_bash_ryk = true;
                if (std.mem.eql(u8, m.string, read_matcher)) has_read_ryk = true;
            }
        }
    }
    if (has_bash_ryk and has_read_ryk and !rewritten) {
        return .{
            .bytes = try allocator.dupe(u8, existing),
            .changed = false,
        };
    }

    if (!has_bash_ryk) {
        try appendRykMatcherEntry(tree_allocator, &pre_tool_use.?.array, command, shell_matcher);
    }
    if (!has_read_ryk) {
        try appendRykMatcherEntry(tree_allocator, &pre_tool_use.?.array, command, read_matcher);
    }

    const bytes = try std.json.Stringify.valueAlloc(allocator, parsed.value, .{ .whitespace = .indent_2 });
    return .{ .bytes = bytes, .changed = true };
}

fn appendRykMatcherEntry(
    tree_allocator: std.mem.Allocator,
    pre_tool_use: *std.json.Array,
    command: []const u8,
    matcher_name: []const u8,
) !void {
    var command_hook: std.json.ObjectMap = .empty;
    try command_hook.put(tree_allocator, "type", .{ .string = "command" });
    try command_hook.put(tree_allocator, "command", .{ .string = command });
    try command_hook.put(tree_allocator, "timeout", .{ .integer = 30 });

    var command_hooks = std.json.Array.init(tree_allocator);
    try command_hooks.append(.{ .object = command_hook });

    var matcher: std.json.ObjectMap = .empty;
    try matcher.put(tree_allocator, "matcher", .{ .string = matcher_name });
    try matcher.put(tree_allocator, "hooks", .{ .array = command_hooks });
    try pre_tool_use.append(.{ .object = matcher });
}

/// Install the Grok user hook under an explicit home directory. This is the
/// onboarding-friendly API and is deterministic in tests.
///
/// Primary: `~/.grok/hooks/ryk.json` (official Grok Build discovery path).
/// Secondary: merge into `~/.grok/user-settings.json` (legacy evidence path).
pub fn installAtHome(
    io: std.Io,
    allocator: std.mem.Allocator,
    home: []const u8,
    ryk_binary: []const u8,
) !InstallResult {
    if (!std.fs.path.isAbsolute(home)) return error.InvalidHomePath;
    try ensureSafeGrokDirectory(io, allocator, home);
    try ensureSafeHooksDirectory(io, allocator, home);

    const managed_path = try std.fs.path.join(allocator, &.{ home, managed_hook_relative_path });
    errdefer allocator.free(managed_path);

    var any_changed = false;

    // --- Primary: managed hooks file (full replace of ryk-owned document) ---
    const desired = try managedHookDocumentAlloc(allocator, ryk_binary);
    defer allocator.free(desired);

    const managed_changed = try writeTextFileAtomically(io, allocator, managed_path, desired);
    any_changed = any_changed or managed_changed;

    // --- Secondary: legacy user-settings merge (idempotent) ---
    const settings_path = try std.fs.path.join(allocator, &.{ home, settings_relative_path });
    defer allocator.free(settings_path);

    const existed = fileState(io, settings_path) catch |err| switch (err) {
        error.FileNotFound => false,
        else => return err,
    };
    const existing = std.Io.Dir.cwd().readFileAlloc(
        io,
        settings_path,
        allocator,
        .limited(max_settings_size),
    ) catch |err| switch (err) {
        error.FileNotFound => try allocator.dupe(u8, "{}"),
        else => return err,
    };
    defer allocator.free(existing);

    const merged = try mergeSettingsAlloc(allocator, existing, ryk_binary);
    defer allocator.free(merged.bytes);
    if (merged.changed) {
        try writeBytesAtomicallyChecked(io, allocator, settings_path, merged.bytes, existing, existed);
        any_changed = true;
    }

    return .{ .changed = any_changed, .settings_path = managed_path };
}

/// Remove managed `~/.grok/hooks/ryk.json` and strip ryk PreToolUse entries from
/// legacy `~/.grok/user-settings.json`. Unrelated hooks and settings are preserved.
pub fn uninstallAtHome(io: std.Io, allocator: std.mem.Allocator, home: []const u8) !bool {
    if (!std.fs.path.isAbsolute(home)) return error.InvalidHomePath;
    var removed = false;

    const managed_path = try std.fs.path.join(allocator, &.{ home, managed_hook_relative_path });
    defer allocator.free(managed_path);
    if (std.Io.Dir.cwd().deleteFile(io, managed_path)) {
        removed = true;
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }

    if (try stripRykHooksFromUserSettings(io, allocator, home)) removed = true;
    return removed;
}

/// Remove ryk-owned PreToolUse matcher groups from legacy user-settings.json.
/// Returns true when the file was modified. Non-ryk hooks are left intact.
pub fn stripRykHooksFromUserSettings(io: std.Io, allocator: std.mem.Allocator, home: []const u8) !bool {
    const settings_path = try std.fs.path.join(allocator, &.{ home, settings_relative_path });
    defer allocator.free(settings_path);

    const existing = std.Io.Dir.cwd().readFileAlloc(io, settings_path, allocator, .limited(max_settings_size)) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    defer allocator.free(existing);

    const stripped = try stripRykPreToolUseFromSettingsAlloc(allocator, existing);
    defer allocator.free(stripped.bytes);
    if (!stripped.changed) return false;

    try writeBytesAtomicallyChecked(io, allocator, settings_path, stripped.bytes, existing, true);
    return true;
}

/// Pure settings rewrite used by uninstall + tests.
/// Drops ryk hook commands; preserves unrelated matchers and mixed-group non-ryk hooks.
pub fn stripRykPreToolUseFromSettingsAlloc(allocator: std.mem.Allocator, existing: []const u8) !MergeResult {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, existing, .{}) catch
        return error.InvalidSettings;
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidSettings;
    const tree = parsed.arena.allocator();

    const hooks = parsed.value.object.getPtr("hooks") orelse {
        return .{ .bytes = try allocator.dupe(u8, existing), .changed = false };
    };
    if (hooks.* != .object) return error.InvalidHooks;
    const pre_tool = hooks.object.getPtr("PreToolUse") orelse {
        return .{ .bytes = try allocator.dupe(u8, existing), .changed = false };
    };
    if (pre_tool.* != .array) return error.InvalidPreToolUseHooks;

    var kept_groups = std.json.Array.init(tree);
    var removed_any = false;
    for (pre_tool.array.items) |entry| {
        if (entry != .object) {
            try kept_groups.append(entry);
            continue;
        }
        const hooks_val = entry.object.get("hooks") orelse {
            try kept_groups.append(entry);
            continue;
        };
        if (hooks_val != .array) {
            try kept_groups.append(entry);
            continue;
        }

        var kept_hooks = std.json.Array.init(tree);
        for (hooks_val.array.items) |hook| {
            if (hook == .object) {
                if (hook.object.get("command")) |command| {
                    if (command == .string and isRykGrokHookCommand(command.string)) {
                        removed_any = true;
                        continue;
                    }
                }
            }
            try kept_hooks.append(hook);
        }
        if (kept_hooks.items.len == 0) {
            // Entire matcher group was ryk-only.
            removed_any = true;
            continue;
        }
        if (kept_hooks.items.len != hooks_val.array.items.len) {
            removed_any = true;
            var new_entry: std.json.ObjectMap = .empty;
            var it = entry.object.iterator();
            while (it.next()) |kv| {
                if (std.mem.eql(u8, kv.key_ptr.*, "hooks")) {
                    try new_entry.put(tree, "hooks", .{ .array = kept_hooks });
                } else {
                    try new_entry.put(tree, kv.key_ptr.*, kv.value_ptr.*);
                }
            }
            try kept_groups.append(.{ .object = new_entry });
        } else {
            try kept_groups.append(entry);
        }
    }
    if (!removed_any) {
        return .{ .bytes = try allocator.dupe(u8, existing), .changed = false };
    }
    pre_tool.* = .{ .array = kept_groups };
    const bytes = try std.json.Stringify.valueAlloc(allocator, parsed.value, .{ .whitespace = .indent_2 });
    return .{ .bytes = bytes, .changed = true };
}

fn writeTextFileAtomically(io: std.Io, allocator: std.mem.Allocator, path: []const u8, bytes: []const u8) !bool {
    const existed = fileState(io, path) catch |err| switch (err) {
        error.FileNotFound => false,
        else => return err,
    };
    var existing_owned: ?[]u8 = null;
    defer if (existing_owned) |c| allocator.free(c);

    if (existed) {
        const current = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(max_hook_file_size));
        existing_owned = current;
        // Idempotent: exact bytes already on disk (including trailing newline variants).
        if (std.mem.eql(u8, current, bytes) or
            (bytes.len > 0 and bytes[bytes.len - 1] != '\n' and
                current.len == bytes.len + 1 and current[current.len - 1] == '\n' and
                std.mem.eql(u8, current[0..bytes.len], bytes)))
        {
            return false;
        }
    }

    try writeBytesAtomicallyChecked(
        io,
        allocator,
        path,
        bytes,
        if (existing_owned) |c| c else "",
        existed,
    );
    return true;
}

fn writeBytesAtomicallyChecked(
    io: std.Io,
    allocator: std.mem.Allocator,
    path: []const u8,
    new_bytes: []const u8,
    expected_existing: []const u8,
    existed: bool,
) !void {
    const nonce = std.Io.Clock.Timestamp.now(io, .awake).raw.nanoseconds;
    const temp_path = try std.fmt.allocPrint(allocator, "{s}.ryk-{d}.tmp", .{ path, nonce });
    defer allocator.free(temp_path);
    defer std.Io.Dir.cwd().deleteFile(io, temp_path) catch {};

    const file = try std.Io.Dir.cwd().createFile(io, temp_path, .{ .exclusive = true });
    defer file.close(io);
    if (builtin.os.tag != .windows) {
        try file.setPermissions(io, @enumFromInt(0o600));
    }
    try file.writeStreamingAll(io, new_bytes);
    if (new_bytes.len == 0 or new_bytes[new_bytes.len - 1] != '\n') {
        try file.writeStreamingAll(io, "\n");
    }
    try file.sync(io);
    try ensureFileUnchanged(io, allocator, path, expected_existing, existed);
    try std.Io.Dir.renameAbsolute(temp_path, path, io);
}

fn ensureSafeGrokDirectory(io: std.Io, allocator: std.mem.Allocator, home: []const u8) !void {
    const home_stat = try std.Io.Dir.cwd().statFile(io, home, .{ .follow_symlinks = false });
    if (home_stat.kind != .directory) return error.UnsafeHomePath;

    const grok_dir = try std.fs.path.join(allocator, &.{ home, ".grok" });
    defer allocator.free(grok_dir);
    const stat = std.Io.Dir.cwd().statFile(io, grok_dir, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => {
            try std.Io.Dir.cwd().createDirPath(io, grok_dir);
            const created = try std.Io.Dir.cwd().statFile(io, grok_dir, .{ .follow_symlinks = false });
            if (created.kind != .directory) return error.UnsafeGrokDirectory;
            return;
        },
        else => return err,
    };
    if (stat.kind != .directory) return error.UnsafeGrokDirectory;
}

fn ensureSafeHooksDirectory(io: std.Io, allocator: std.mem.Allocator, home: []const u8) !void {
    const hooks_dir = try std.fs.path.join(allocator, &.{ home, hooks_relative_dir });
    defer allocator.free(hooks_dir);
    const stat = std.Io.Dir.cwd().statFile(io, hooks_dir, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => {
            try std.Io.Dir.cwd().createDirPath(io, hooks_dir);
            const created = try std.Io.Dir.cwd().statFile(io, hooks_dir, .{ .follow_symlinks = false });
            if (created.kind != .directory) return error.UnsafeHooksDirectory;
            return;
        },
        else => return err,
    };
    if (stat.kind != .directory) return error.UnsafeHooksDirectory;
}

fn fileState(io: std.Io, path: []const u8) !bool {
    const stat = try std.Io.Dir.cwd().statFile(io, path, .{ .follow_symlinks = false });
    if (stat.kind == .sym_link) return error.UnsafeSettingsPath;
    if (stat.kind != .file) return error.UnsafeSettingsPath;
    return true;
}

fn ensureFileUnchanged(
    io: std.Io,
    allocator: std.mem.Allocator,
    path: []const u8,
    expected: []const u8,
    existed: bool,
) !void {
    if (!existed) {
        _ = fileState(io, path) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return err,
        };
        return error.ConcurrentSettingsChange;
    }
    _ = try fileState(io, path);
    const current = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(max_settings_size));
    defer allocator.free(current);
    if (!std.mem.eql(u8, current, expected)) return error.ConcurrentSettingsChange;
}

fn hookCommandAlloc(allocator: std.mem.Allocator, ryk_binary: []const u8) ![]u8 {
    const trimmed = std.mem.trim(u8, ryk_binary, " \t\r\n");
    if (trimmed.len == 0 or !std.fs.path.isAbsolute(trimmed)) return error.InvalidRykBinary;
    const quoted = try shellQuoteAlloc(allocator, trimmed);
    defer allocator.free(quoted);
    // Official Grok Build fail-opens on missing/non-executable commands (exit 127).
    // Pin /bin/sh (not PATH `sh`) and emit native deny JSON + exit 2 when ryk is gone.
    return std.fmt.allocPrint(allocator, "/bin/sh -c 'if [ -x \"$1\" ]; then exec \"$1\" hook grok PreToolUse; fi; printf \"%s\\n\" \"{{\\\"decision\\\":\\\"deny\\\",\\\"reason\\\":\\\"ryk binary unavailable; blocked fail-closed\\\"}}\"; exit 2' -- {s}", .{quoted});
}

fn shellQuoteAlloc(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    if (!needsShellQuote(value)) {
        return allocator.dupe(u8, value);
    }

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.append(allocator, '\'');
    for (value) |byte| {
        if (byte == '\'') {
            try out.appendSlice(allocator, "'\"'\"'");
        } else {
            try out.append(allocator, byte);
        }
    }
    try out.append(allocator, '\'');
    return out.toOwnedSlice(allocator);
}

fn needsShellQuote(value: []const u8) bool {
    if (value.len == 0) return true;
    for (value) |byte| {
        switch (byte) {
            'A'...'Z', 'a'...'z', '0'...'9', '/', '.', '_', '-' => {},
            else => return true,
        }
    }
    return false;
}

fn rewriteRykHookCommands(tree_allocator: std.mem.Allocator, entry: *std.json.Value, expected_command: []const u8) !bool {
    if (entry.* != .object) return false;
    const hooks = entry.object.getPtr("hooks") orelse return false;
    if (hooks.* != .array) return false;
    var changed = false;
    for (hooks.array.items) |*hook| {
        if (hook.* != .object) continue;
        const command = hook.object.get("command") orelse continue;
        if (command != .string) continue;
        if (!isRykGrokHookCommand(command.string)) continue;
        if (std.mem.eql(u8, command.string, expected_command)) continue;
        const owned = try tree_allocator.dupe(u8, expected_command);
        try hook.object.put(tree_allocator, "command", .{ .string = owned });
        changed = true;
    }
    return changed;
}

fn entryContainsExactRykHook(entry: std.json.Value, expected_command: []const u8) bool {
    if (entry != .object) return false;
    const hooks = entry.object.get("hooks") orelse return false;
    if (hooks != .array) return false;
    for (hooks.array.items) |hook| {
        if (hook != .object) continue;
        const command = hook.object.get("command") orelse continue;
        if (command == .string and std.mem.eql(u8, command.string, expected_command)) return true;
    }
    return false;
}

fn entryContainsAnyRykHook(entry: std.json.Value) bool {
    if (entry != .object) return false;
    const hooks = entry.object.get("hooks") orelse return false;
    if (hooks != .array) return false;
    for (hooks.array.items) |hook| {
        if (hook != .object) continue;
        const command = hook.object.get("command") orelse continue;
        if (command == .string and isRykGrokHookCommand(command.string)) return true;
    }
    return false;
}

/// Recognize existing ryk Grok hook commands without matching arbitrary shell
/// command text that merely mentions ryk.
///
/// Matches:
/// - legacy product `…/ryk hook grok PreToolUse`
/// - staged test harness binaries (`…/test hook grok PreToolUse`)
/// - the missing-binary wrapper (`sh -c '… exec "$1" hook grok PreToolUse …' -- <ryk>`)
pub fn isRykGrokHookCommand(command: []const u8) bool {
    const trimmed = std.mem.trim(u8, command, " \t\r\n");
    if (isLegacyDirectRykGrokHook(trimmed)) return true;
    return isWrappedRykGrokHook(trimmed);
}

fn isLegacyDirectRykGrokHook(trimmed: []const u8) bool {
    const suffix = " hook grok PreToolUse";
    if (!std.mem.endsWith(u8, trimmed, suffix)) return false;
    const executable = std.mem.trim(u8, trimmed[0 .. trimmed.len - suffix.len], " \t\r\n'");
    if (executable.len == 0) return false;
    const base = std.fs.path.basename(executable);
    if (std.mem.eql(u8, base, "ryk")) return true;
    // Zig unit-test binaries that embed the same PreToolUse entrypoint.
    if (std.mem.eql(u8, base, "test") and std.mem.indexOf(u8, executable, "ryk") != null) return true;
    return false;
}

fn isWrappedRykGrokHook(trimmed: []const u8) bool {
    if (!std.mem.startsWith(u8, trimmed, "/bin/sh -c ")) return false;
    if (std.mem.indexOf(u8, trimmed, "hook grok PreToolUse") == null) return false;
    if (std.mem.indexOf(u8, trimmed, "ryk binary unavailable") == null) return false;
    if (std.mem.indexOf(u8, trimmed, "exit 2") == null) return false;
    return true;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "Grok managed hook document targets Bash and Read matchers and ryk PreToolUse" {
    const allocator = std.testing.allocator;
    const managed = try managedHookDocumentAlloc(allocator, "/opt/ryk/bin/ryk");
    defer allocator.free(managed);
    try std.testing.expect(std.mem.indexOf(u8, managed, "\"matcher\": \"Bash\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, managed, "\"matcher\": \"Read\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, managed, "/opt/ryk/bin/ryk") != null);
    try std.testing.expect(std.mem.indexOf(u8, managed, "hook grok PreToolUse") != null);
    try std.testing.expect(std.mem.indexOf(u8, managed, "ryk binary unavailable") != null);

    const merged = try mergeSettingsAlloc(allocator, "{}", "/opt/ryk/bin/ryk");
    defer allocator.free(merged.bytes);
    try std.testing.expect(merged.changed);
    try std.testing.expect(std.mem.indexOf(u8, merged.bytes, "\"matcher\": \"Bash\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, merged.bytes, "\"matcher\": \"Read\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, merged.bytes, "/opt/ryk/bin/ryk") != null);
    try std.testing.expect(std.mem.indexOf(u8, merged.bytes, "hook grok PreToolUse") != null);
}

test "Grok settings merge preserves unrelated settings and existing hooks" {
    const allocator = std.testing.allocator;
    const existing =
        \\{
        \\  "apiKey": "synthetic-key",
        \\  "hooks": {
        \\    "PreToolUse": [
        \\      {
        \\        "matcher": "edit",
        \\        "hooks": [
        \\          {"type": "command", "command": "./existing-hook.sh", "timeout": 7}
        \\        ]
        \\      }
        \\    ],
        \\    "SessionStart": [
        \\      {"hooks": [{"type": "command", "command": "./welcome.sh"}]}
        \\    ]
        \\  }
        \\}
    ;

    const merged = try mergeSettingsAlloc(allocator, existing, "/opt/ryk/bin/ryk");
    defer allocator.free(merged.bytes);
    try std.testing.expect(merged.changed);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, merged.bytes, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings("synthetic-key", parsed.value.object.get("apiKey").?.string);
    const hooks = parsed.value.object.get("hooks").?.object;
    try std.testing.expect(hooks.get("SessionStart") != null);
    const pre_tool = hooks.get("PreToolUse").?.array.items;
    // Unrelated edit matcher + Bash + Read ryk matchers.
    try std.testing.expectEqual(@as(usize, 3), pre_tool.len);
    try std.testing.expectEqualStrings("./existing-hook.sh", pre_tool[0].object.get("hooks").?.array.items[0].object.get("command").?.string);
    const ryk_cmd = pre_tool[1].object.get("hooks").?.array.items[0].object.get("command").?.string;
    try std.testing.expect(isRykGrokHookCommand(ryk_cmd));
    try std.testing.expect(std.mem.indexOf(u8, ryk_cmd, "/opt/ryk/bin/ryk") != null);
    try std.testing.expectEqualStrings(shell_matcher, pre_tool[1].object.get("matcher").?.string);
    try std.testing.expectEqualStrings(read_matcher, pre_tool[2].object.get("matcher").?.string);
}

test "Grok settings merge upgrades Bash-only ryk hook to dual Bash and Read matchers" {
    const allocator = std.testing.allocator;
    const bash_only =
        \\{
        \\  "hooks": {
        \\    "PreToolUse": [
        \\      {
        \\        "matcher": "Bash",
        \\        "hooks": [
        \\          {"type": "command", "command": "/opt/ryk/bin/ryk hook grok PreToolUse", "timeout": 30}
        \\        ]
        \\      }
        \\    ]
        \\  }
        \\}
    ;
    const merged = try mergeSettingsAlloc(allocator, bash_only, "/opt/ryk/bin/ryk");
    defer allocator.free(merged.bytes);
    try std.testing.expect(merged.changed);
    try std.testing.expect(std.mem.indexOf(u8, merged.bytes, "\"matcher\": \"Bash\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, merged.bytes, "\"matcher\": \"Read\"") != null);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, merged.bytes, .{});
    defer parsed.deinit();
    const pre_tool = parsed.value.object.get("hooks").?.object.get("PreToolUse").?.array.items;
    try std.testing.expectEqual(@as(usize, 2), pre_tool.len);
    try std.testing.expectEqualStrings(shell_matcher, pre_tool[0].object.get("matcher").?.string);
    try std.testing.expectEqualStrings(read_matcher, pre_tool[1].object.get("matcher").?.string);
}

test "Grok settings merge upgrades Read-only ryk hook to dual Bash and Read matchers" {
    const allocator = std.testing.allocator;
    const read_only =
        \\{
        \\  "hooks": {
        \\    "PreToolUse": [
        \\      {
        \\        "matcher": "Read",
        \\        "hooks": [
        \\          {"type": "command", "command": "/opt/ryk/bin/ryk hook grok PreToolUse", "timeout": 30}
        \\        ]
        \\      }
        \\    ]
        \\  }
        \\}
    ;
    const merged = try mergeSettingsAlloc(allocator, read_only, "/opt/ryk/bin/ryk");
    defer allocator.free(merged.bytes);
    try std.testing.expect(merged.changed);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, merged.bytes, .{});
    defer parsed.deinit();
    const pre_tool = parsed.value.object.get("hooks").?.object.get("PreToolUse").?.array.items;
    try std.testing.expectEqual(@as(usize, 2), pre_tool.len);
    try std.testing.expectEqualStrings(read_matcher, pre_tool[0].object.get("matcher").?.string);
    try std.testing.expectEqualStrings(shell_matcher, pre_tool[1].object.get("matcher").?.string);
}

test "Grok settings merge is idempotent and detects an existing ryk hook" {
    const allocator = std.testing.allocator;
    const first = try mergeSettingsAlloc(allocator, "{}", "/opt/ryk/bin/ryk");
    defer allocator.free(first.bytes);
    try std.testing.expect(first.changed);

    const second = try mergeSettingsAlloc(allocator, first.bytes, "/opt/ryk/bin/ryk");
    defer allocator.free(second.bytes);
    try std.testing.expect(!second.changed);
    try std.testing.expectEqualStrings(first.bytes, second.bytes);
}

test "Grok installed check requires managed hooks/ryk.json not legacy user-settings" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(home);
    try tmp.dir.createDirPath(std.testing.io, ".grok/hooks");
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = ".grok/hooks/other.json",
        .data = "{\"hooks\":{\"PreToolUse\":[{\"hooks\":[{\"type\":\"command\",\"command\":\"echo unrelated\"}]}]}}",
    });
    // Legacy-only evidence must not count as installed (Grok Build ignores user-settings).
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = ".grok/user-settings.json",
        .data =
        \\{"hooks":{"PreToolUse":[{"matcher":"bash","hooks":[{"type":"command","command":"/opt/ryk/bin/ryk hook grok PreToolUse","timeout":30}]}]}}
        ,
    });
    try std.testing.expect(!installedAtHome(std.testing.io, std.testing.allocator, home));
    try std.testing.expect(legacyOnlyInstalledAtHome(std.testing.io, std.testing.allocator, home));

    const result = try installAtHome(std.testing.io, std.testing.allocator, home, "/opt/ryk/bin/ryk");
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(result.changed);
    try std.testing.expect(installedAtHome(std.testing.io, std.testing.allocator, home));
    try std.testing.expect(!legacyOnlyInstalledAtHome(std.testing.io, std.testing.allocator, home));

    // Managed file is the only wired path.
    const managed = try std.fs.path.join(std.testing.allocator, &.{ home, managed_hook_relative_path });
    defer std.testing.allocator.free(managed);
    const written = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, managed, std.testing.allocator, .limited(max_hook_file_size));
    defer std.testing.allocator.free(written);
    try std.testing.expect(std.mem.indexOf(u8, written, "\"matcher\": \"Bash\"") != null or std.mem.indexOf(u8, written, "\"matcher\":\"Bash\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "\"matcher\": \"Read\"") != null or std.mem.indexOf(u8, written, "\"matcher\":\"Read\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "/opt/ryk/bin/ryk") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "hook grok PreToolUse") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "ryk binary unavailable") != null);
}

test "Grok CLI help evidence accepts official Grok Build and community CLI" {
    try std.testing.expect(!isSupportedCliHelp("grok 1.0\nUsage: grok [options]\n"));
    try std.testing.expect(isSupportedCliHelp(
        \\Grok Build TUI
        \\
        \\Usage: grok [OPTIONS] [PROMPT] [COMMAND]
        \\
        \\Arguments:
        \\  [PROMPT]
    ));
    try std.testing.expect(isSupportedCliHelp(
        \\Usage: grok [options]
        \\AI coding agent powered by Grok — built with Bun and OpenTUI
        \\  -p, --prompt <prompt>  Run a single prompt headlessly
        \\  --verify              Run the built-in verify flow headlessly
        \\  --batch-api           Use xAI Batch API
    ));
}

test "Grok settings merge rejects malformed or incompatible hook configuration" {
    try std.testing.expectError(error.InvalidSettings, mergeSettingsAlloc(std.testing.allocator, "{", "/opt/ryk/bin/ryk"));
    try std.testing.expectError(error.InvalidHooks, mergeSettingsAlloc(std.testing.allocator, "{\"hooks\":[]}", "/opt/ryk/bin/ryk"));
    try std.testing.expectError(error.InvalidPreToolUseHooks, mergeSettingsAlloc(std.testing.allocator, "{\"hooks\":{\"PreToolUse\":{}}}", "/opt/ryk/bin/ryk"));
}

test "Grok installer writes managed hooks file and preserves legacy settings" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(home);

    try tmp.dir.createDirPath(std.testing.io, ".grok");
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = ".grok/user-settings.json",
        .data = "{\"defaultModel\":\"grok-test\",\"hooks\":{\"SessionEnd\":[{\"hooks\":[]}]}}\n",
    });

    const first = try installAtHome(std.testing.io, std.testing.allocator, home, "/usr/local/bin/ryk");
    defer first.deinit(std.testing.allocator);
    try std.testing.expect(first.changed);
    try std.testing.expect(std.mem.endsWith(u8, first.settings_path, managed_hook_relative_path) or
        std.mem.indexOf(u8, first.settings_path, managed_hook_filename) != null);

    const managed = try std.fs.path.join(std.testing.allocator, &.{ home, ".grok", "hooks", managed_hook_filename });
    defer std.testing.allocator.free(managed);
    const managed_bytes = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, managed, std.testing.allocator, .limited(max_hook_file_size));
    defer std.testing.allocator.free(managed_bytes);
    try std.testing.expect(std.mem.indexOf(u8, managed_bytes, "/usr/local/bin/ryk") != null);
    try std.testing.expect(std.mem.indexOf(u8, managed_bytes, "hook grok PreToolUse") != null);
    try std.testing.expect(std.mem.indexOf(u8, managed_bytes, "ryk binary unavailable") != null);

    const settings_path = try std.fs.path.join(std.testing.allocator, &.{ home, ".grok", "user-settings.json" });
    defer std.testing.allocator.free(settings_path);
    const written = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, settings_path, std.testing.allocator, .limited(max_settings_size));
    defer std.testing.allocator.free(written);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, written, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings("grok-test", parsed.value.object.get("defaultModel").?.string);
    try std.testing.expect(std.mem.indexOf(u8, written, "\"SessionEnd\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "/usr/local/bin/ryk") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "hook grok PreToolUse") != null);

    const second = try installAtHome(std.testing.io, std.testing.allocator, home, "/usr/local/bin/ryk");
    defer second.deinit(std.testing.allocator);
    try std.testing.expect(!second.changed);
}

test "Grok installer rejects a symlinked configuration directory" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "redirect");
    tmp.dir.symLink(std.testing.io, "redirect", ".grok", .{}) catch return error.SkipZigTest;
    const home = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(home);

    try std.testing.expectError(
        error.UnsafeGrokDirectory,
        installAtHome(std.testing.io, std.testing.allocator, home, "/opt/ryk/bin/ryk"),
    );
}

test "Grok stripRykPreToolUse removes product and test harness hooks preserves others" {
    const allocator = std.testing.allocator;
    const existing =
        \\{
        \\  "apiKey": "synthetic-key",
        \\  "hooks": {
        \\    "PreToolUse": [
        \\      {
        \\        "matcher": "bash",
        \\        "hooks": [
        \\          {"type": "command", "command": "/opt/ryk/bin/ryk hook grok PreToolUse", "timeout": 30}
        \\        ]
        \\      },
        \\      {
        \\        "matcher": "Bash",
        \\        "hooks": [
        \\          {"type": "command", "command": "/repo/ryk/.zig-cache/o/abc/test hook grok PreToolUse", "timeout": 30}
        \\        ]
        \\      },
        \\      {
        \\        "matcher": "edit",
        \\        "hooks": [
        \\          {"type": "command", "command": "./existing-hook.sh", "timeout": 7}
        \\        ]
        \\      }
        \\    ]
        \\  }
        \\}
    ;
    const stripped = try stripRykPreToolUseFromSettingsAlloc(allocator, existing);
    defer allocator.free(stripped.bytes);
    try std.testing.expect(stripped.changed);
    try std.testing.expect(std.mem.indexOf(u8, stripped.bytes, "hook grok PreToolUse") == null);
    try std.testing.expect(std.mem.indexOf(u8, stripped.bytes, "existing-hook.sh") != null);
    try std.testing.expect(std.mem.indexOf(u8, stripped.bytes, "synthetic-key") != null);
}

test "Grok uninstallAtHome removes managed hook and strips user-settings" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(home);

    const install_result = try installAtHome(std.testing.io, std.testing.allocator, home, "/opt/ryk/bin/ryk");
    defer install_result.deinit(std.testing.allocator);
    try std.testing.expect(install_result.changed);
    try std.testing.expect(installedAtHome(std.testing.io, std.testing.allocator, home));

    try std.testing.expect(try uninstallAtHome(std.testing.io, std.testing.allocator, home));
    try std.testing.expect(!installedAtHome(std.testing.io, std.testing.allocator, home));

    const settings_path = try std.fs.path.join(std.testing.allocator, &.{ home, settings_relative_path });
    defer std.testing.allocator.free(settings_path);
    const written = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, settings_path, std.testing.allocator, .limited(max_settings_size));
    defer std.testing.allocator.free(written);
    try std.testing.expect(std.mem.indexOf(u8, written, "hook grok PreToolUse") == null);
}

test "isRykGrokHookCommand accepts product ryk and zig-cache test harness" {
    try std.testing.expect(isRykGrokHookCommand("/opt/ryk/bin/ryk hook grok PreToolUse"));
    try std.testing.expect(isRykGrokHookCommand(
        "/Users/me/CodingProjects/ryk/.zig-cache/o/abc/test hook grok PreToolUse",
    ));
    try std.testing.expect(!isRykGrokHookCommand("/usr/bin/dcg"));
    try std.testing.expect(!isRykGrokHookCommand("echo ryk"));
    try std.testing.expect(!isRykGrokHookCommand("echo hook grok PreToolUse"));
    try std.testing.expectError(error.InvalidRykBinary, hookCommandAlloc(std.testing.allocator, "ryk"));
    try std.testing.expectError(error.InvalidRykBinary, hookCommandAlloc(std.testing.allocator, "./ryk"));
    const wrapped = try hookCommandAlloc(std.testing.allocator, "/opt/ryk/bin/ryk");
    defer std.testing.allocator.free(wrapped);
    try std.testing.expect(isRykGrokHookCommand(wrapped));
    try std.testing.expect(std.mem.startsWith(u8, wrapped, "/bin/sh -c "));
}

test "Grok settings merge upgrades legacy direct hook to fail-closed wrapper" {
    const allocator = std.testing.allocator;
    const legacy =
        \\{
        \\  "hooks": {
        \\    "PreToolUse": [
        \\      {
        \\        "matcher": "Bash",
        \\        "hooks": [
        \\          {"type": "command", "command": "/opt/ryk/bin/ryk hook grok PreToolUse", "timeout": 30}
        \\        ]
        \\      },
        \\      {
        \\        "matcher": "Read",
        \\        "hooks": [
        \\          {"type": "command", "command": "/opt/ryk/bin/ryk hook grok PreToolUse", "timeout": 30}
        \\        ]
        \\      }
        \\    ]
        \\  }
        \\}
    ;
    const merged = try mergeSettingsAlloc(allocator, legacy, "/opt/ryk/bin/ryk");
    defer allocator.free(merged.bytes);
    try std.testing.expect(merged.changed);
    try std.testing.expect(std.mem.indexOf(u8, merged.bytes, "ryk binary unavailable") != null);
    try std.testing.expect(std.mem.indexOf(u8, merged.bytes, "/bin/sh -c ") != null);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, merged.bytes, .{});
    defer parsed.deinit();
    const pre_tool = parsed.value.object.get("hooks").?.object.get("PreToolUse").?.array.items;
    try std.testing.expectEqual(@as(usize, 2), pre_tool.len);
    const bash_cmd = pre_tool[0].object.get("hooks").?.array.items[0].object.get("command").?.string;
    const read_cmd = pre_tool[1].object.get("hooks").?.array.items[0].object.get("command").?.string;
    try std.testing.expect(isRykGrokHookCommand(bash_cmd));
    try std.testing.expect(isRykGrokHookCommand(read_cmd));
    try std.testing.expect(!isLegacyDirectRykGrokHook(bash_cmd));
    try std.testing.expect(!isLegacyDirectRykGrokHook(read_cmd));
}

test "Grok hook command fail-closes when ryk is missing" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const command = try hookCommandAlloc(allocator, "/this/ryk/does/not/exist");
    defer allocator.free(command);

    const result = try std.process.run(allocator, std.testing.io, .{
        .argv = &.{ "/bin/sh", "-c", command },
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(4096),
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    switch (result.term) {
        .exited => |code| try std.testing.expectEqual(@as(u8, 2), code),
        else => return error.TestExpectedExit2,
    }
    try std.testing.expect(std.mem.indexOf(u8, result.stdout, "\"decision\":\"deny\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.stdout, "ryk binary unavailable") != null);
}

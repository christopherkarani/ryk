//! Permanent pack-exception allowlist CLI (product path).
//!
//! Live Zig writers for `ryk allowlist` / `ryk allow` / `ryk unallow` against
//! `shell_engine.allowlist_store` TOML files. **No daemon.** Distinct from
//! policy `allowlist.Layered` / `Entry.prefix`.
//!
//! Paths (must match product-wire loaders):
//!   project → `<workspace>/.ryk/allowlist.toml` (workspace-root walk-up)
//!   user    → `$XDG_CONFIG_HOME/ryk/allowlist.toml` else `~/.config/ryk/allowlist.toml`
//! Default layer when neither `--project` nor `--user`: project when the resolved
//! workspace root has `.git` or `.ryk/policy.yaml`, else user.
//!
//! Subcommands: `add`, `add-command`, `list`, `remove`, `validate`, `prune`.
//! Shortcuts: `commandAllow` → add, `commandUnallow` → remove.

const std = @import("std");
const gpa_mod = @import("gpa.zig");
const core = @import("ryk_core").core;
const exit_codes = @import("exit_codes.zig");
const help = @import("help.zig");
const suggestions = @import("suggestions.zig");
const shell_engine = @import("../shell_engine/mod.zig");
const enable_tui = @import("build_options").enable_tui;
const allowlist_browse = if (enable_tui) @import("../tui/allowlist_browse.zig") else struct {
    pub fn shouldEnterAllowlistBrowseIo(_: std.Io, _: []const []const u8) bool {
        return false;
    }
    pub fn confirmRemoveDefaultNo(_: []const u8) bool {
        return false;
    }
    pub fn applyRemoveIfConfirmed(_: bool, _: *const fn () anyerror!bool) !bool {
        return false;
    }
};

const allowlist_store = shell_engine.allowlist_store;

// Pull pure browse tests into the allowlist test filter set.
test {
    if (enable_tui) {
        _ = @import("../tui/allowlist_browse.zig");
    }
}

/// Same gzip oracle as shell_engine.registry / packs CLI — known rule ids for validate --strict.
const oracle_embed = @import("../shell_engine/oracle_embed.zig");

const usage_text =
    \\Usage: ryk allowlist add <rule-id> -r|--reason <reason> [--project|--user] [--expires <iso>]
    \\       ryk allowlist add-command <cmd> -r|--reason <reason> [--project|--user] [--expires <iso>]
    \\       ryk allowlist list [--project|--user] [--json] [--plain]
    \\       ryk allowlist remove <rule-id|exact-command> [--project|--user]
    \\       ryk allowlist validate [--strict] [--project|--user]
    \\       ryk allowlist prune [--dry-run] [--project|--user]
    \\
    \\Bare `ryk allowlist` defaults to list. On a colour TTY, list opens dual-layer
    \\browse (project then user); --plain / --json / non-TTY stay linear.
    \\
    \\Shortcuts: ryk allow <rule-id> …   → add rule
    \\           ryk unallow <key> …     → remove rule or exact command
    \\
    \\Permanent pack exceptions (not policy commands.allow). Paths:
    \\  project → <workspace>/.ryk/allowlist.toml (git / workspace root walk-up)
    \\  user    → $XDG_CONFIG_HOME/ryk/allowlist.toml or ~/.config/ryk/allowlist.toml
    \\Default layer: project when workspace root has .git or .ryk/policy.yaml, else user.
    \\
;

// ---------------------------------------------------------------------------
// Production surface
// ---------------------------------------------------------------------------

/// Top-level `ryk allowlist …` (argv after the verb).
///
/// Bare `ryk allowlist` / flag-only argv defaults to **list** (TTY dual-layer
/// browse when `shouldEnterTui`; linear / `--json` / `--plain` otherwise).
pub fn command(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    // Help anywhere in argv (consistent with packs).
    for (argv) |arg| {
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            try stdout.writeAll(usage_text);
            return exit_codes.success;
        }
    }

    var gpa_state: gpa_mod.State = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    var now_buf: [32]u8 = undefined;
    const now_iso = try core.time.Timestamp.now(io).formatIso(&now_buf);

    // Bare / flag-only → list (default TUI on colour TTY via shouldEnterTui).
    if (argv.len == 0 or std.mem.startsWith(u8, argv[0], "-")) {
        return cmdList(io, gpa, now_iso, argv, stdout, stderr);
    }

    const sub = argv[0];
    if (std.mem.eql(u8, sub, "add")) {
        return cmdAdd(io, gpa, now_iso, argv[1..], .rule, stdout, stderr);
    }
    if (std.mem.eql(u8, sub, "add-command")) {
        return cmdAdd(io, gpa, now_iso, argv[1..], .command, stdout, stderr);
    }
    if (std.mem.eql(u8, sub, "list") or std.mem.eql(u8, sub, "ls") or std.mem.eql(u8, sub, "show")) {
        return cmdList(io, gpa, now_iso, argv[1..], stdout, stderr);
    }
    if (std.mem.eql(u8, sub, "remove") or std.mem.eql(u8, sub, "rm")) {
        return cmdRemove(io, gpa, argv[1..], stdout, stderr);
    }
    if (std.mem.eql(u8, sub, "validate")) {
        return cmdValidate(io, gpa, now_iso, argv[1..], stdout, stderr);
    }
    if (std.mem.eql(u8, sub, "prune")) {
        return cmdPrune(io, gpa, now_iso, argv[1..], stdout, stderr);
    }

    // Suggestion candidates omit "add-command" so short typos like "ad" uniquely
    // resolve to "add" (closest() aborts on multiple prefix matches).
    try suggestions.writeUnknownSubcommand(
        stderr,
        "ryk allowlist",
        sub,
        &.{ "add", "list", "remove", "validate", "prune" },
        "allowlist",
    );
    return exit_codes.usage;
}

/// Top-level `ryk allow …` shortcut → add rule.
pub fn commandAllow(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    if (argv.len == 0 or std.mem.eql(u8, argv[0], "--help") or std.mem.eql(u8, argv[0], "-h")) {
        if (argv.len > 0) {
            try stdout.writeAll(usage_text);
            return exit_codes.success;
        }
        try stderr.writeAll("ryk allow: missing rule-id\n");
        try stderr.writeAll(usage_text);
        return exit_codes.usage;
    }
    // Prepend synthetic "add" framing via shared add body.
    var gpa_state: gpa_mod.State = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();
    var now_buf: [32]u8 = undefined;
    const now_iso = try core.time.Timestamp.now(io).formatIso(&now_buf);
    return cmdAdd(io, gpa, now_iso, argv, .rule, stdout, stderr);
}

/// Top-level `ryk unallow …` shortcut → remove rule/command key.
pub fn commandUnallow(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    if (argv.len == 0 or std.mem.eql(u8, argv[0], "--help") or std.mem.eql(u8, argv[0], "-h")) {
        if (argv.len > 0) {
            try stdout.writeAll(usage_text);
            return exit_codes.success;
        }
        try stderr.writeAll("ryk unallow: missing rule-id or exact command\n");
        try stderr.writeAll(usage_text);
        return exit_codes.usage;
    }
    var gpa_state: gpa_mod.State = .init;
    defer _ = gpa_state.deinit();
    return cmdRemove(io, gpa_state.allocator(), argv, stdout, stderr);
}

// ---------------------------------------------------------------------------
// Shared option / path helpers
// ---------------------------------------------------------------------------

const LayerChoice = enum { auto, project, user };

const CommonFlags = struct {
    layer: LayerChoice = .auto,
    as_json: bool = false,
    /// Linear human list escape (never open TUI).
    as_plain: bool = false,
    strict: bool = false,
    dry_run: bool = false,
    reason: ?[]const u8 = null,
    expires: ?[]const u8 = null,
    /// Positional non-flag args (rule id, command, remove key).
    positionals: std.ArrayListUnmanaged([]const u8) = .empty,

    fn deinit(self: *CommonFlags, gpa: std.mem.Allocator) void {
        self.positionals.deinit(gpa);
    }
};

fn parseCommonFlags(gpa: std.mem.Allocator, argv: []const []const u8, stderr: anytype) !struct { CommonFlags, u8 } {
    var flags: CommonFlags = .{};
    errdefer flags.deinit(gpa);
    var i: usize = 0;
    while (i < argv.len) : (i += 1) {
        const arg = argv[i];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            return error.ShowHelp;
        }
        if (std.mem.eql(u8, arg, "--project")) {
            flags.layer = .project;
        } else if (std.mem.eql(u8, arg, "--user")) {
            flags.layer = .user;
        } else if (std.mem.eql(u8, arg, "--json")) {
            flags.as_json = true;
        } else if (std.mem.eql(u8, arg, "--plain")) {
            flags.as_plain = true;
        } else if (std.mem.eql(u8, arg, "--strict")) {
            flags.strict = true;
        } else if (std.mem.eql(u8, arg, "--dry-run")) {
            flags.dry_run = true;
        } else if (std.mem.eql(u8, arg, "-r") or std.mem.eql(u8, arg, "--reason")) {
            i += 1;
            if (i >= argv.len) {
                try stderr.writeAll("ryk allowlist: -r/--reason requires a value\n");
                return error.Usage;
            }
            flags.reason = argv[i];
        } else if (std.mem.startsWith(u8, arg, "--reason=")) {
            flags.reason = arg["--reason=".len..];
        } else if (std.mem.eql(u8, arg, "--expires")) {
            i += 1;
            if (i >= argv.len) {
                try stderr.writeAll("ryk allowlist: --expires requires an ISO-8601 value (YYYY-MM-DDTHH:MM:SSZ)\n");
                return error.Usage;
            }
            if (!isValidExpiresIsoZ(argv[i])) {
                try stderr.writeAll(
                    "ryk allowlist: --expires must be UTC ISO-Z like product timestamps (YYYY-MM-DDTHH:MM:SSZ)\n",
                );
                return error.Usage;
            }
            flags.expires = argv[i];
        } else if (std.mem.startsWith(u8, arg, "--expires=")) {
            const value = arg["--expires=".len..];
            if (!isValidExpiresIsoZ(value)) {
                try stderr.writeAll(
                    "ryk allowlist: --expires must be UTC ISO-Z like product timestamps (YYYY-MM-DDTHH:MM:SSZ)\n",
                );
                return error.Usage;
            }
            flags.expires = value;
        } else if (std.mem.startsWith(u8, arg, "-") and arg.len > 1) {
            try stderr.print("ryk allowlist: unknown option '{s}'\n", .{arg});
            return error.Usage;
        } else {
            try flags.positionals.append(gpa, arg);
        }
    }
    return .{ flags, 0 };
}

/// Workspace root for project allowlist — same walk-up as product loaders / packs.
fn resolveWorkspaceRootPath(gpa: std.mem.Allocator, io: std.Io) ![]u8 {
    return core.supervisor.resolveWorkspaceRoot(io, gpa, null, ".") catch {
        const cwd_z = try std.Io.Dir.cwd().realPathFileAlloc(io, ".", gpa);
        defer gpa.free(cwd_z);
        return try gpa.dupe(u8, cwd_z);
    };
}

fn workspaceHasProjectMarker(io: std.Io, gpa: std.mem.Allocator, workspace_root: []const u8) bool {
    const git_path = std.fs.path.join(gpa, &.{ workspace_root, ".git" }) catch return false;
    defer gpa.free(git_path);
    std.Io.Dir.accessAbsolute(io, git_path, .{}) catch {
        const policy_path = std.fs.path.join(gpa, &.{ workspace_root, ".ryk", "policy.yaml" }) catch return false;
        defer gpa.free(policy_path);
        std.Io.Dir.accessAbsolute(io, policy_path, .{}) catch return false;
        return true;
    };
    return true;
}

fn resolveLayer(flags: CommonFlags, io: std.Io, gpa: std.mem.Allocator) allowlist_store.Layer {
    return switch (flags.layer) {
        .project => .project,
        .user => .user,
        .auto => blk: {
            const root = resolveWorkspaceRootPath(gpa, io) catch break :blk .user;
            defer gpa.free(root);
            break :blk if (workspaceHasProjectMarker(io, gpa, root)) .project else .user;
        },
    };
}

fn resolveUserPath(gpa: std.mem.Allocator) !?[]u8 {
    if (std.c.getenv("XDG_CONFIG_HOME")) |xdg_z| {
        const xdg = std.mem.span(xdg_z);
        if (xdg.len > 0) {
            return try std.fs.path.join(gpa, &.{ xdg, "ryk", "allowlist.toml" });
        }
    }
    if (std.c.getenv("HOME")) |home_z| {
        const home = std.mem.span(home_z);
        if (home.len > 0) {
            return try std.fs.path.join(gpa, &.{ home, ".config", "ryk", "allowlist.toml" });
        }
    }
    return null;
}

fn resolveProjectPath(gpa: std.mem.Allocator, io: std.Io) ![]u8 {
    // Must match shell_eval.loadProductShellStores: `<workspace>/.ryk/allowlist.toml`.
    const root = try resolveWorkspaceRootPath(gpa, io);
    defer gpa.free(root);
    return try std.fs.path.join(gpa, &.{ root, ".ryk", "allowlist.toml" });
}

fn resolvePathForLayer(gpa: std.mem.Allocator, io: std.Io, layer: allowlist_store.Layer) ![]u8 {
    return switch (layer) {
        .project => try resolveProjectPath(gpa, io),
        .user => blk: {
            const p = try resolveUserPath(gpa) orelse {
                return error.NoUserConfig;
            };
            break :blk p;
        },
    };
}

fn layerName(layer: allowlist_store.Layer) []const u8 {
    return switch (layer) {
        .user => "user",
        .project => "project",
    };
}

/// Product timestamp shape from `core.time.Timestamp.formatIso`: `YYYY-MM-DDTHH:MM:SSZ`.
/// Lexicographic compare in `allowlist_store.isExpired` requires this exact form.
pub fn isValidExpiresIsoZ(value: []const u8) bool {
    if (value.len != 20) return false;
    // YYYY-MM-DDTHH:MM:SSZ
    inline for (.{ 0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18 }) |i| {
        if (value[i] < '0' or value[i] > '9') return false;
    }
    if (value[4] != '-' or value[7] != '-') return false;
    if (value[10] != 'T') return false;
    if (value[13] != ':' or value[16] != ':') return false;
    if (value[19] != 'Z') return false;
    // Mild range checks (month/day/hour/minute/second) — reject obvious garbage.
    const month = (value[5] - '0') * 10 + (value[6] - '0');
    const day = (value[8] - '0') * 10 + (value[9] - '0');
    const hour = (value[11] - '0') * 10 + (value[12] - '0');
    const minute = (value[14] - '0') * 10 + (value[15] - '0');
    const second = (value[17] - '0') * 10 + (value[18] - '0');
    if (month < 1 or month > 12) return false;
    if (day < 1 or day > 31) return false;
    if (hour > 23 or minute > 59 or second > 59) return false;
    return true;
}

/// Test seam: when non-null, overrides the real TTY probe for the mutate gate.
/// Production leaves this null; tests set it to simulate operator presence.
pub var test_operator_tty_override: ?bool = null;

/// Refuse agent-reachable allowlist mutations unless on an interactive TTY.
/// Permanent FULL ALLOW / rule exceptions are operator-only (M-2). The only
/// trustworthy operator signal is an interactive controlling terminal — env vars
/// are child-controlled (RYK_OPERATOR was removed: it authenticated nobody).
/// Non-TTY → fail closed.
fn requireAllowlistMutateGate(io: std.Io, stderr: anytype) !bool {
    const is_tty = if (test_operator_tty_override) |v|
        v
    else
        (std.Io.File.stdin().isTty(io) catch false) and
            (std.Io.File.stdout().isTty(io) catch false);
    if (is_tty) return true;
    try stderr.writeAll(
        \\ryk allowlist: permanent exception mutations require an interactive TTY
        \\(agent-reachable FULL ALLOW path). Re-run as an operator in a terminal.
        \\
    );
    return false;
}

fn kindName(kind: allowlist_store.EntryKind) []const u8 {
    return switch (kind) {
        .rule => "rule",
        .command => "command",
    };
}

// ---------------------------------------------------------------------------
// Subcommands
// ---------------------------------------------------------------------------

fn cmdAdd(
    io: std.Io,
    gpa: std.mem.Allocator,
    now_iso: []const u8,
    argv: []const []const u8,
    kind: allowlist_store.EntryKind,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    const parsed = parseCommonFlags(gpa, argv, stderr) catch |err| switch (err) {
        error.ShowHelp => {
            try stdout.writeAll(usage_text);
            return exit_codes.success;
        },
        error.Usage => return exit_codes.usage,
        else => return err,
    };
    var flags = parsed[0];
    defer flags.deinit(gpa);

    if (flags.positionals.items.len == 0) {
        try stderr.writeAll(switch (kind) {
            .rule => "ryk allowlist: add requires a rule-id\n",
            .command => "ryk allowlist: add-command requires an exact command\n",
        });
        return exit_codes.usage;
    }
    if (flags.positionals.items.len > 1) {
        try stderr.writeAll("ryk allowlist: unexpected extra arguments\n");
        return exit_codes.usage;
    }
    const key = flags.positionals.items[0];
    const reason = flags.reason orelse {
        try stderr.writeAll("ryk allowlist: reason required (-r/--reason)\n");
        return exit_codes.usage;
    };
    if (std.mem.trim(u8, reason, " \t\r\n").len == 0) {
        try stderr.writeAll("ryk allowlist: reason required (-r/--reason)\n");
        return exit_codes.usage;
    }

    // M-2 partial: permanent FULL ALLOW / rule exceptions are operator-gated.
    if (!try requireAllowlistMutateGate(io, stderr)) return exit_codes.usage;

    const layer = resolveLayer(flags, io, gpa);
    const path = resolvePathForLayer(gpa, io, layer) catch |err| switch (err) {
        error.NoUserConfig => {
            try stderr.writeAll("ryk allowlist: cannot resolve user config path (set XDG_CONFIG_HOME or HOME)\n");
            return exit_codes.general;
        },
        else => return err,
    };
    defer gpa.free(path);

    const draft: allowlist_store.Draft = switch (kind) {
        .rule => .{
            .kind = .rule,
            .id = key,
            .reason = reason,
            .created_at = now_iso,
            .expires_at = flags.expires,
        },
        .command => .{
            .kind = .command,
            .command = key,
            .reason = reason,
            .created_at = now_iso,
            .expires_at = flags.expires,
        },
    };

    // Form + reason validation without known-list (strict unknown check is validate --strict).
    allowlist_store.validateDraft(draft, null) catch |err| {
        try writeValidateErr(stderr, err);
        return exit_codes.usage;
    };

    allowlist_store.addEntry(io, gpa, path, layer, draft, null) catch |err| {
        try stderr.print("ryk allowlist: failed to write entry: {s}\n", .{@errorName(err)});
        return exit_codes.general;
    };

    try stdout.print("Added {s} allowlist entry ({s}): {s}\n", .{ layerName(layer), kindName(kind), key });
    return exit_codes.success;
}

fn cmdList(
    io: std.Io,
    gpa: std.mem.Allocator,
    now_iso: []const u8,
    argv: []const []const u8,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    const parsed = parseCommonFlags(gpa, argv, stderr) catch |err| switch (err) {
        error.ShowHelp => {
            try stdout.writeAll(usage_text);
            return exit_codes.success;
        },
        error.Usage => return exit_codes.usage,
        else => return err,
    };
    var flags = parsed[0];
    defer flags.deinit(gpa);

    // Machine / plain / non-TTY: linear frozen. TTY + shouldEnterTui → dual-layer browse.
    // Gate argv must include escape flags (--json/--plain/--no-rich/…) from the list path.
    const want_tui = enable_tui and !flags.as_json and !flags.as_plain and
        allowlist_browse.shouldEnterAllowlistBrowseIo(io, argv);

    if (want_tui) {
        if (comptime enable_tui) {
            const entered = try tryEnterAllowlistBrowse(io, gpa, now_iso, flags, stdout, stderr);
            if (entered) return exit_codes.success;
            // TtyUnavailable → fall through to linear so findings are never dropped.
        }
    }

    // --project / --user: single layer. auto: merge both (project wins).
    var outcome: allowlist_store.LoadOutcome = undefined;
    if (flags.layer == .auto) {
        const user_path = try resolveUserPath(gpa);
        defer if (user_path) |p| gpa.free(p);
        const project_path = try resolveProjectPath(gpa, io);
        defer gpa.free(project_path);
        outcome = try allowlist_store.loadMerged(io, gpa, user_path, project_path);
    } else {
        const layer = resolveLayer(flags, io, gpa);
        const path = resolvePathForLayer(gpa, io, layer) catch |err| switch (err) {
            error.NoUserConfig => {
                try stderr.writeAll("ryk allowlist: cannot resolve user config path\n");
                return exit_codes.general;
            },
            else => return err,
        };
        defer gpa.free(path);
        outcome = try allowlist_store.loadFile(io, gpa, path, layer);
    }
    defer outcome.store.deinit(gpa);

    if (outcome.corrupt) {
        try stderr.writeAll("ryk allowlist: warning: allowlist file corrupt or unreadable; treating as empty\n");
    }

    if (flags.as_json) {
        try writeListJson(stdout, gpa, outcome.store, now_iso);
    } else {
        if (outcome.store.entries.len == 0) {
            try stdout.writeAll("No permanent allowlist entries.\n");
            return exit_codes.success;
        }
        for (outcome.store.entries) |e| {
            const expired = allowlist_store.isExpired(e, now_iso);
            const key = allowlist_store.entryKey(e);
            try stdout.print(
                "{s}\t{s}\t{s}\t{s}{s}\n",
                .{
                    kindName(e.kind),
                    key,
                    layerName(e.layer),
                    e.reason,
                    if (expired) " [expired]" else "",
                },
            );
        }
    }
    return exit_codes.success;
}

/// Load dual-layer views and open browse kit. Returns true if browse ran (or
/// no-op under tests after gate). False on TtyUnavailable (caller falls linear).
fn tryEnterAllowlistBrowse(
    io: std.Io,
    gpa: std.mem.Allocator,
    now_iso: []const u8,
    flags: CommonFlags,
    stdout: anytype,
    stderr: anytype,
) !bool {
    const project_path = try resolveProjectPath(gpa, io);
    defer gpa.free(project_path);
    const user_path_owned = try resolveUserPath(gpa);
    defer if (user_path_owned) |p| gpa.free(p);
    const user_path = user_path_owned orelse "";

    var project_outcome = try allowlist_store.loadFile(io, gpa, project_path, .project);
    defer project_outcome.store.deinit(gpa);
    var user_outcome: allowlist_store.LoadOutcome = .{ .store = .{}, .corrupt = false };
    if (user_path_owned) |up| {
        user_outcome = try allowlist_store.loadFile(io, gpa, up, .user);
    }
    defer user_outcome.store.deinit(gpa);

    // Match linear list honesty: corrupt files still open TUI empty, but warn (F193).
    if (project_outcome.corrupt or user_outcome.corrupt) {
        try stderr.writeAll("ryk allowlist: warning: allowlist file corrupt or unreadable; treating as empty\n");
    }

    // Layer filter: --project / --user show one section only by emptying the other view.
    const write_layer: allowlist_browse.Layer = switch (resolveLayer(flags, io, gpa)) {
        .project => .project,
        .user => .user,
    };

    const project_views = try entriesToViews(gpa, project_outcome.store.entries, now_iso);
    defer gpa.free(project_views);
    const user_views = try entriesToViews(gpa, user_outcome.store.entries, now_iso);
    defer gpa.free(user_views);

    // --project / --user: single section; default auto: dual-layer project then user.
    const project_slice: []const allowlist_browse.EntryView = if (flags.layer == .user) &.{} else project_views;
    const user_slice: []const allowlist_browse.EntryView = if (flags.layer == .project) &.{} else user_views;

    var remove_ctx: RemoveCtx = .{
        .io = io,
        .gpa = gpa,
        .project_path = project_path,
        .user_path = user_path,
    };

    allowlist_browse.run(io, gpa, stdout, .{
        .project_entries = project_slice,
        .user_entries = user_slice,
        .project_path = project_path,
        .user_path = if (user_path.len > 0) user_path else "(user path unresolved)",
        .write_layer = write_layer,
        .hooks = .{
            .remove = removeHook,
            .ctx = &remove_ctx,
        },
    }) catch |err| switch (err) {
        error.TtyUnavailable => return false,
        else => return err,
    };
    return true;
}

const RemoveCtx = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    project_path: []const u8,
    user_path: []const u8,
};

fn removeHook(ctx: *anyopaque, req: allowlist_browse.RemoveRequest) anyerror!bool {
    const self: *RemoveCtx = @ptrCast(@alignCast(ctx));
    const path = switch (req.layer) {
        .project => self.project_path,
        .user => self.user_path,
    };
    if (path.len == 0) return false;
    const layer: allowlist_store.Layer = switch (req.layer) {
        .project => .project,
        .user => .user,
    };
    return allowlist_store.removeEntry(self.io, self.gpa, path, layer, req.key);
}

fn entriesToViews(
    gpa: std.mem.Allocator,
    entries: []const allowlist_store.PermanentEntry,
    now_iso: []const u8,
) ![]allowlist_browse.EntryView {
    const out = try gpa.alloc(allowlist_browse.EntryView, entries.len);
    for (entries, 0..) |e, i| {
        out[i] = .{
            .kind = kindName(e.kind),
            .key = allowlist_store.entryKey(e),
            .reason = e.reason,
            .layer = switch (e.layer) {
                .project => .project,
                .user => .user,
            },
            .expired = allowlist_store.isExpired(e, now_iso),
            .created_at = e.created_at,
            .expires_at = e.expires_at,
        };
    }
    return out;
}

fn writeListJson(stdout: anytype, gpa: std.mem.Allocator, store: allowlist_store.Store, now_iso: []const u8) !void {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(gpa);
    try buf.appendSlice(gpa, "{\"schema_version\":1,\"entries\":[");
    for (store.entries, 0..) |e, i| {
        if (i > 0) try buf.appendSlice(gpa, ",");
        try buf.appendSlice(gpa, "{");
        try buf.appendSlice(gpa, "\"kind\":\"");
        try buf.appendSlice(gpa, kindName(e.kind));
        try buf.appendSlice(gpa, "\",");
        if (e.id) |id| {
            try buf.appendSlice(gpa, "\"id\":");
            try appendJsonString(gpa, &buf, id);
            try buf.appendSlice(gpa, ",");
        } else {
            try buf.appendSlice(gpa, "\"id\":null,");
        }
        if (e.command) |cmd| {
            try buf.appendSlice(gpa, "\"command\":");
            try appendJsonString(gpa, &buf, cmd);
            try buf.appendSlice(gpa, ",");
        } else {
            try buf.appendSlice(gpa, "\"command\":null,");
        }
        try buf.appendSlice(gpa, "\"reason\":");
        try appendJsonString(gpa, &buf, e.reason);
        try buf.appendSlice(gpa, ",\"layer\":\"");
        try buf.appendSlice(gpa, layerName(e.layer));
        try buf.appendSlice(gpa, "\",\"created_at\":");
        try appendJsonString(gpa, &buf, e.created_at);
        if (e.expires_at) |exp| {
            try buf.appendSlice(gpa, ",\"expires_at\":");
            try appendJsonString(gpa, &buf, exp);
        } else {
            try buf.appendSlice(gpa, ",\"expires_at\":null");
        }
        try buf.appendSlice(gpa, ",\"expired\":");
        try buf.appendSlice(gpa, if (allowlist_store.isExpired(e, now_iso)) "true" else "false");
        try buf.appendSlice(gpa, "}");
    }
    try buf.appendSlice(gpa, "]}\n");
    try stdout.writeAll(buf.items);
}

fn appendJsonString(gpa: std.mem.Allocator, buf: *std.ArrayListUnmanaged(u8), s: []const u8) !void {
    try buf.append(gpa, '"');
    for (s) |c| {
        switch (c) {
            '"' => try buf.appendSlice(gpa, "\\\""),
            '\\' => try buf.appendSlice(gpa, "\\\\"),
            '\n' => try buf.appendSlice(gpa, "\\n"),
            '\r' => try buf.appendSlice(gpa, "\\r"),
            '\t' => try buf.appendSlice(gpa, "\\t"),
            else => try buf.append(gpa, c),
        }
    }
    try buf.append(gpa, '"');
}

fn cmdRemove(
    io: std.Io,
    gpa: std.mem.Allocator,
    argv: []const []const u8,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    const parsed = parseCommonFlags(gpa, argv, stderr) catch |err| switch (err) {
        error.ShowHelp => {
            try stdout.writeAll(usage_text);
            return exit_codes.success;
        },
        error.Usage => return exit_codes.usage,
        else => return err,
    };
    var flags = parsed[0];
    defer flags.deinit(gpa);

    if (flags.positionals.items.len == 0) {
        try stderr.writeAll("ryk allowlist: remove requires a rule-id or exact command\n");
        return exit_codes.usage;
    }
    if (flags.positionals.items.len > 1) {
        try stderr.writeAll("ryk allowlist: unexpected extra arguments\n");
        return exit_codes.usage;
    }
    const key = flags.positionals.items[0];
    const layer = resolveLayer(flags, io, gpa);
    const path = resolvePathForLayer(gpa, io, layer) catch |err| switch (err) {
        error.NoUserConfig => {
            try stderr.writeAll("ryk allowlist: cannot resolve user config path\n");
            return exit_codes.general;
        },
        else => return err,
    };
    defer gpa.free(path);

    const removed = allowlist_store.removeEntry(io, gpa, path, layer, key) catch |err| {
        try stderr.print("ryk allowlist: remove failed: {s}\n", .{@errorName(err)});
        return exit_codes.general;
    };
    if (!removed) {
        try stderr.print("ryk allowlist: no entry found for key '{s}'\n", .{key});
        return exit_codes.general;
    }
    try stdout.print("Removed allowlist entry: {s}\n", .{key});
    return exit_codes.success;
}

fn cmdValidate(
    io: std.Io,
    gpa: std.mem.Allocator,
    now_iso: []const u8,
    argv: []const []const u8,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    _ = now_iso;
    const parsed = parseCommonFlags(gpa, argv, stderr) catch |err| switch (err) {
        error.ShowHelp => {
            try stdout.writeAll(usage_text);
            return exit_codes.success;
        },
        error.Usage => return exit_codes.usage,
        else => return err,
    };
    var flags = parsed[0];
    defer flags.deinit(gpa);

    var outcome: allowlist_store.LoadOutcome = undefined;
    if (flags.layer == .auto) {
        const user_path = try resolveUserPath(gpa);
        defer if (user_path) |p| gpa.free(p);
        const project_path = try resolveProjectPath(gpa, io);
        defer gpa.free(project_path);
        outcome = try allowlist_store.loadMerged(io, gpa, user_path, project_path);
    } else {
        const layer = resolveLayer(flags, io, gpa);
        const path = resolvePathForLayer(gpa, io, layer) catch |err| switch (err) {
            error.NoUserConfig => {
                try stderr.writeAll("ryk allowlist: cannot resolve user config path\n");
                return exit_codes.general;
            },
            else => return err,
        };
        defer gpa.free(path);
        outcome = try allowlist_store.loadFile(io, gpa, path, layer);
    }
    defer outcome.store.deinit(gpa);

    if (outcome.corrupt) {
        try stderr.writeAll("ryk allowlist: allowlist file is corrupt or unreadable\n");
        return exit_codes.general;
    }

    var known_owned: ?KnownRuleIds = null;
    defer if (known_owned) |*k| k.deinit();
    var known_slice: ?[]const []const u8 = null;
    if (flags.strict) {
        known_owned = try collectKnownRuleIds(gpa);
        known_slice = known_owned.?.ids;
    }

    var issues: usize = 0;
    for (outcome.store.entries) |e| {
        const draft: allowlist_store.Draft = .{
            .kind = e.kind,
            .id = e.id,
            .command = e.command,
            .reason = e.reason,
            .created_at = e.created_at,
            .expires_at = e.expires_at,
        };
        allowlist_store.validateDraft(draft, known_slice) catch |err| {
            issues += 1;
            const key = allowlist_store.entryKey(e);
            try stderr.print("ryk allowlist: invalid entry '{s}': {s}\n", .{ key, validateErrName(err) });
        };
    }

    if (issues > 0) {
        try stderr.print("ryk allowlist: validate found {d} issue(s)\n", .{issues});
        return exit_codes.general;
    }
    try stdout.print("allowlist ok ({d} entries)\n", .{outcome.store.entries.len});
    return exit_codes.success;
}

fn cmdPrune(
    io: std.Io,
    gpa: std.mem.Allocator,
    now_iso: []const u8,
    argv: []const []const u8,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    const parsed = parseCommonFlags(gpa, argv, stderr) catch |err| switch (err) {
        error.ShowHelp => {
            try stdout.writeAll(usage_text);
            return exit_codes.success;
        },
        error.Usage => return exit_codes.usage,
        else => return err,
    };
    var flags = parsed[0];
    defer flags.deinit(gpa);

    // Prune operates on explicit layer or both when auto.
    const layers: []const allowlist_store.Layer = switch (flags.layer) {
        .project => &[_]allowlist_store.Layer{.project},
        .user => &[_]allowlist_store.Layer{.user},
        .auto => &[_]allowlist_store.Layer{ .project, .user },
    };

    var total_removed: usize = 0;
    for (layers) |layer| {
        const path = resolvePathForLayer(gpa, io, layer) catch |err| switch (err) {
            error.NoUserConfig => continue,
            else => return err,
        };
        defer gpa.free(path);

        var outcome = try allowlist_store.loadFile(io, gpa, path, layer);
        defer outcome.store.deinit(gpa);
        if (outcome.corrupt or outcome.store.entries.len == 0) continue;

        var keys: std.ArrayListUnmanaged([]const u8) = .empty;
        defer {
            for (keys.items) |k| gpa.free(k);
            keys.deinit(gpa);
        }
        for (outcome.store.entries) |e| {
            if (allowlist_store.isExpired(e, now_iso)) {
                try keys.append(gpa, try gpa.dupe(u8, allowlist_store.entryKey(e)));
            }
        }

        if (flags.dry_run) {
            total_removed += keys.items.len;
            for (keys.items) |k| {
                try stdout.print("would prune ({s}): {s}\n", .{ layerName(layer), k });
            }
            continue;
        }

        for (keys.items) |k| {
            const removed = try allowlist_store.removeEntry(io, gpa, path, layer, k);
            if (removed) total_removed += 1;
        }
    }

    if (flags.dry_run) {
        try stdout.print("prune dry-run: {d} expired entr{s}\n", .{ total_removed, if (total_removed == 1) "y" else "ies" });
    } else {
        try stdout.print("pruned {d} expired entr{s}\n", .{ total_removed, if (total_removed == 1) "y" else "ies" });
    }
    return exit_codes.success;
}

fn writeValidateErr(stderr: anytype, err: allowlist_store.ValidateError) !void {
    try stderr.print("ryk allowlist: {s}\n", .{validateErrName(err)});
}

fn validateErrName(err: allowlist_store.ValidateError) []const u8 {
    return switch (err) {
        error.ReasonRequired => "reason required",
        error.CommandRequired => "command required",
        error.RuleIdRequired => "rule id required",
        error.InvalidRuleIdForm => "invalid rule-id form (expected pack:pattern)",
        error.UnknownRuleId => "unknown rule id",
    };
}

const KnownRuleIds = struct {
    gpa: std.mem.Allocator,
    inflated_json: []u8,
    parsed: std.json.Parsed(std.json.Value),
    ids: []const []const u8,
    owned_slice: [][]const u8,

    fn deinit(self: *KnownRuleIds) void {
        for (self.owned_slice) |s| self.gpa.free(s);
        self.gpa.free(self.owned_slice);
        self.parsed.deinit();
        self.gpa.free(self.inflated_json);
        self.* = undefined;
    }
};

fn collectKnownRuleIds(gpa: std.mem.Allocator) !KnownRuleIds {
    const inflated = try oracle_embed.inflateAlloc(gpa);
    errdefer gpa.free(inflated);
    const parsed = try std.json.parseFromSlice(std.json.Value, gpa, inflated, .{});
    errdefer parsed.deinit();
    if (parsed.value != .array) return error.BadPacksJson;

    var list: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        for (list.items) |s| gpa.free(s);
        list.deinit(gpa);
    }

    for (parsed.value.array.items) |item| {
        if (item != .object) continue;
        const obj = item.object;
        const id_val = obj.get("id") orelse continue;
        if (id_val != .string) continue;
        const pack_id = id_val.string;
        if (std.mem.eql(u8, pack_id, "test.deadline")) continue;
        for ([_][]const u8{ "safe", "destructive" }) |section| {
            const sec = obj.get(section) orelse continue;
            if (sec != .array) continue;
            for (sec.array.items) |pat| {
                if (pat != .object) continue;
                const name_v = pat.object.get("name") orelse continue;
                if (name_v != .string) continue;
                const rule = try std.fmt.allocPrint(gpa, "{s}:{s}", .{ pack_id, name_v.string });
                errdefer gpa.free(rule);
                try list.append(gpa, rule);
            }
        }
    }

    const owned = try list.toOwnedSlice(gpa);
    errdefer {
        for (owned) |s| gpa.free(s);
        gpa.free(owned);
    }
    // --strict must not treat a missing oracle as "no known rules" (empty-allow).
    if (owned.len == 0) return error.EmptyOracleRuleIds;
    return .{
        .gpa = gpa,
        .inflated_json = inflated,
        .parsed = parsed,
        .ids = owned,
        .owned_slice = owned,
    };
}

// ---------------------------------------------------------------------------
// Test helpers (XDG + git workspace isolation; no product side effects)
// ---------------------------------------------------------------------------

const s_allowlist_cli_now = "2026-07-25T12:00:00Z";
const s_allowlist_cli_far_expiry = "9999-01-01T00:00:00Z";
const s_allowlist_cli_expired = "2020-01-01T00:00:00Z";

extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;
extern "c" fn unsetenv(name: [*:0]const u8) c_int;

fn sAllowlistCliDupEnvZ(name: [*:0]const u8) !?[:0]u8 {
    if (std.c.getenv(name)) |value| {
        return try std.testing.allocator.dupeZ(u8, std.mem.span(value));
    }
    return null;
}

fn sAllowlistCliRestoreEnv(name: [*:0]const u8, prev: ?[:0]u8) void {
    if (prev) |value| {
        _ = setenv(name, value.ptr, 1);
        std.testing.allocator.free(value);
    } else {
        _ = unsetenv(name);
    }
}

fn sAllowlistCliJoin(parts: []const []const u8) ![]u8 {
    return try std.fs.path.join(std.testing.allocator, parts);
}

const SAllowlistCliEnv = struct {
    config_tmp: std.testing.TmpDir,
    config_root: []u8,
    prev_config: ?[:0]u8,
    prev_home: ?[:0]u8,

    fn deinit(self: *@This()) void {
        sAllowlistCliRestoreEnv("XDG_CONFIG_HOME", self.prev_config);
        sAllowlistCliRestoreEnv("HOME", self.prev_home);
        // Always clear the TTY test seam so tests cannot leak operator presence.
        test_operator_tty_override = null;
        std.testing.allocator.free(self.config_root);
        self.config_tmp.cleanup();
    }
};

fn sAllowlistCliIsolateXdg() !SAllowlistCliEnv {
    var config_tmp = std.testing.tmpDir(.{});
    errdefer config_tmp.cleanup();

    const config_z = try config_tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(config_z);
    const config_root = try std.testing.allocator.dupe(u8, config_z);
    errdefer std.testing.allocator.free(config_root);

    const prev_config = try sAllowlistCliDupEnvZ("XDG_CONFIG_HOME");
    errdefer if (prev_config) |p| std.testing.allocator.free(p);
    const prev_home = try sAllowlistCliDupEnvZ("HOME");
    errdefer if (prev_home) |p| std.testing.allocator.free(p);

    const config_z0 = try std.testing.allocator.dupeZ(u8, config_root);
    defer std.testing.allocator.free(config_z0);
    try std.testing.expectEqual(@as(c_int, 0), setenv("XDG_CONFIG_HOME", config_z0.ptr, 1));
    // Pin HOME away from the real home so user-path fallback never touches the host.
    try std.testing.expectEqual(@as(c_int, 0), setenv("HOME", config_z0.ptr, 1));
    // Mutations are TTY-only; simulate operator presence via the test seam
    // (the RYK_OPERATOR env break-glass was removed).
    test_operator_tty_override = true;

    return .{
        .config_tmp = config_tmp,
        .config_root = config_root,
        .prev_config = prev_config,
        .prev_home = prev_home,
    };
}

const SAllowlistCliWorkspace = struct {
    tmp: std.testing.TmpDir,
    root: []u8,
    /// `realPathFileAlloc` returns a null-terminated allocation; keep `[:0]` so free size matches.
    prev_cwd: [:0]u8,

    fn deinit(self: *@This()) void {
        std.process.setCurrentPath(std.testing.io, self.prev_cwd) catch {};
        std.testing.allocator.free(self.prev_cwd);
        std.testing.allocator.free(self.root);
        self.tmp.cleanup();
    }
};

/// Temp workspace with cwd set to root. When `with_git`, creates `cwd/.git` so
/// default layer resolution selects project via workspace-root markers.
fn sAllowlistCliWorkspace(with_git: bool) !SAllowlistCliWorkspace {
    var tmp = std.testing.tmpDir(.{});
    errdefer tmp.cleanup();
    if (with_git) {
        try tmp.dir.createDirPath(std.testing.io, ".git");
    }

    const root_z = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root_z);
    const root = try std.testing.allocator.dupe(u8, root_z);
    errdefer std.testing.allocator.free(root);

    const prev_cwd = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    errdefer std.testing.allocator.free(prev_cwd);
    try std.process.setCurrentDir(std.testing.io, tmp.dir);

    return .{
        .tmp = tmp,
        .root = root,
        .prev_cwd = prev_cwd,
    };
}

/// Workspace under the system temp dir (not zig-cache under the monorepo).
/// Required for "no project markers" cases: walk-up must not hit the repo `.git`.
const SAllowlistCliAbsWorkspace = struct {
    root: []u8,
    prev_cwd: [:0]u8,

    fn deinit(self: *@This()) void {
        std.process.setCurrentPath(std.testing.io, self.prev_cwd) catch {};
        std.testing.allocator.free(self.prev_cwd);
        std.Io.Dir.cwd().deleteTree(std.testing.io, self.root) catch {};
        std.testing.allocator.free(self.root);
    }
};

fn sAllowlistCliAbsWorkspace(with_git: bool) !SAllowlistCliAbsWorkspace {
    const base: []const u8 = if (std.c.getenv("TMPDIR")) |z| std.mem.span(z) else "/tmp";
    var name_buf: [64]u8 = undefined;
    const name = try std.fmt.bufPrint(&name_buf, "ryk-allowlist-cli-{d}", .{@intFromPtr(&name_buf)});
    const root = try std.fs.path.join(std.testing.allocator, &.{ base, name });
    errdefer std.testing.allocator.free(root);

    try std.Io.Dir.cwd().createDirPath(std.testing.io, root);
    errdefer std.Io.Dir.cwd().deleteTree(std.testing.io, root) catch {};

    if (with_git) {
        const git = try std.fs.path.join(std.testing.allocator, &.{ root, ".git" });
        defer std.testing.allocator.free(git);
        try std.Io.Dir.cwd().createDirPath(std.testing.io, git);
    }

    const prev_cwd = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    errdefer std.testing.allocator.free(prev_cwd);
    try std.process.setCurrentPath(std.testing.io, root);

    return .{
        .root = root,
        .prev_cwd = prev_cwd,
    };
}

/// Git-backed temp workspace; cwd set to root for default --project resolution.
fn sAllowlistCliGitWorkspace() !SAllowlistCliWorkspace {
    return try sAllowlistCliWorkspace(true);
}

/// Non-git workspace outside monorepo walk-up → default layer is user.
fn sAllowlistCliNonGitWorkspace() !SAllowlistCliAbsWorkspace {
    return try sAllowlistCliAbsWorkspace(false);
}

/// True when stdout/stderr is the intentional RED stub body (must not green edge tests).
fn sAllowlistCliIsStubNotImplemented(stdout: []const u8, stderr: []const u8) bool {
    return std.mem.indexOf(u8, stderr, "not implemented") != null or
        std.mem.indexOf(u8, stdout, "not implemented") != null;
}

/// Not-found / missing-key messaging for remove of absent entries.
fn sAllowlistCliHasNotFoundMsg(blob: []const u8) bool {
    return std.mem.indexOf(u8, blob, "not found") != null or
        std.mem.indexOf(u8, blob, "Not found") != null or
        std.mem.indexOf(u8, blob, "missing") != null or
        std.mem.indexOf(u8, blob, "Missing") != null or
        std.mem.indexOf(u8, blob, "no entry") != null or
        std.mem.indexOf(u8, blob, "No entry") != null or
        std.mem.indexOf(u8, blob, "does not exist") != null or
        std.mem.indexOf(u8, blob, "unknown key") != null;
}

fn sAllowlistCliProjectPath(workspace_root: []const u8) ![]u8 {
    return try sAllowlistCliJoin(&.{ workspace_root, ".ryk", "allowlist.toml" });
}

fn sAllowlistCliUserPath(xdg_config: []const u8) ![]u8 {
    return try sAllowlistCliJoin(&.{ xdg_config, "ryk", "allowlist.toml" });
}

fn sAllowlistCliReadFile(path: []const u8) ![]u8 {
    return try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, std.testing.allocator, .limited(1024 * 1024));
}

fn sAllowlistCliExpectNoDaemonText(text: []const u8) !void {
    try std.testing.expect(std.mem.indexOf(u8, text, "daemon") == null);
    try std.testing.expect(std.mem.indexOf(u8, text, "not yet ported") == null);
    try std.testing.expect(std.mem.indexOf(u8, text, "executeDaemonCli") == null);
}

fn sAllowlistCliRunAllowlist(argv: []const []const u8) !struct { code: u8, stdout: []u8, stderr: []u8 } {
    var stdout_alloc: std.Io.Writer.Allocating = .init(std.testing.allocator);
    errdefer stdout_alloc.deinit();
    var stderr_alloc: std.Io.Writer.Allocating = .init(std.testing.allocator);
    errdefer stderr_alloc.deinit();
    const code = try command(std.testing.io, argv, &stdout_alloc.writer, &stderr_alloc.writer);
    return .{
        .code = code,
        .stdout = try stdout_alloc.toOwnedSlice(),
        .stderr = try stderr_alloc.toOwnedSlice(),
    };
}

fn sAllowlistCliRunAllow(argv: []const []const u8) !struct { code: u8, stdout: []u8, stderr: []u8 } {
    var stdout_alloc: std.Io.Writer.Allocating = .init(std.testing.allocator);
    errdefer stdout_alloc.deinit();
    var stderr_alloc: std.Io.Writer.Allocating = .init(std.testing.allocator);
    errdefer stderr_alloc.deinit();
    const code = try commandAllow(std.testing.io, argv, &stdout_alloc.writer, &stderr_alloc.writer);
    return .{
        .code = code,
        .stdout = try stdout_alloc.toOwnedSlice(),
        .stderr = try stderr_alloc.toOwnedSlice(),
    };
}

fn sAllowlistCliRunUnallow(argv: []const []const u8) !struct { code: u8, stdout: []u8, stderr: []u8 } {
    var stdout_alloc: std.Io.Writer.Allocating = .init(std.testing.allocator);
    errdefer stdout_alloc.deinit();
    var stderr_alloc: std.Io.Writer.Allocating = .init(std.testing.allocator);
    errdefer stderr_alloc.deinit();
    const code = try commandUnallow(std.testing.io, argv, &stdout_alloc.writer, &stderr_alloc.writer);
    return .{
        .code = code,
        .stdout = try stdout_alloc.toOwnedSlice(),
        .stderr = try stderr_alloc.toOwnedSlice(),
    };
}

fn sAllowlistCliFreeRun(result: anytype) void {
    std.testing.allocator.free(result.stdout);
    std.testing.allocator.free(result.stderr);
}

// ---------------------------------------------------------------------------
// Acceptance 1 — add / add-command / list / remove / validate / prune, no daemon
// ---------------------------------------------------------------------------

test "s-allowlist-cli: add rule writes project allowlist.toml without daemon" {
    var xdg = try sAllowlistCliIsolateXdg();
    defer xdg.deinit();
    var ws = try sAllowlistCliGitWorkspace();
    defer ws.deinit();

    const reason = "recovering local branch after failed rebase work";
    const run = try sAllowlistCliRunAllowlist(&.{
        "add",
        "core.git:reset-hard",
        "-r",
        reason,
        "--project",
    });
    defer sAllowlistCliFreeRun(run);

    try std.testing.expectEqual(exit_codes.success, run.code);
    try sAllowlistCliExpectNoDaemonText(run.stdout);
    try sAllowlistCliExpectNoDaemonText(run.stderr);

    const path = try sAllowlistCliProjectPath(ws.root);
    defer std.testing.allocator.free(path);
    var loaded = try allowlist_store.loadFile(std.testing.io, std.testing.allocator, path, .project);
    defer loaded.store.deinit(std.testing.allocator);
    try std.testing.expect(!loaded.corrupt);
    try std.testing.expectEqual(@as(usize, 1), loaded.store.entries.len);
    const e = loaded.store.entries[0];
    try std.testing.expect(e.kind == .rule);
    try std.testing.expectEqualStrings("core.git:reset-hard", e.id.?);
    try std.testing.expectEqualStrings(reason, e.reason);
    try std.testing.expect(e.layer == .project);

    const raw = try sAllowlistCliReadFile(path);
    defer std.testing.allocator.free(raw);
    try std.testing.expect(std.mem.indexOf(u8, raw, "schema_version") != null);
    try std.testing.expect(std.mem.indexOf(u8, raw, "[[entries]]") != null);
    try std.testing.expect(std.mem.indexOf(u8, raw, "core.git:reset-hard") != null);
}

test "s-allowlist-cli: add-command writes exact command entry only" {
    var xdg = try sAllowlistCliIsolateXdg();
    defer xdg.deinit();
    var ws = try sAllowlistCliGitWorkspace();
    defer ws.deinit();

    const reason = "one-off exact status exception for CI bootstrap";
    const cmd_text = "git status";
    const run = try sAllowlistCliRunAllowlist(&.{
        "add-command",
        cmd_text,
        "--reason",
        reason,
        "--project",
    });
    defer sAllowlistCliFreeRun(run);

    try std.testing.expectEqual(exit_codes.success, run.code);
    try sAllowlistCliExpectNoDaemonText(run.stdout);
    try sAllowlistCliExpectNoDaemonText(run.stderr);

    const path = try sAllowlistCliProjectPath(ws.root);
    defer std.testing.allocator.free(path);
    var loaded = try allowlist_store.loadFile(std.testing.io, std.testing.allocator, path, .project);
    defer loaded.store.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), loaded.store.entries.len);
    const e = loaded.store.entries[0];
    try std.testing.expect(e.kind == .command);
    try std.testing.expectEqualStrings(cmd_text, e.command.?);
    try std.testing.expect(e.id == null);

    // Exact-only: near-miss must not match (store contract the CLI must preserve).
    try std.testing.expect(loaded.store.matchCommand("git status --short", s_allowlist_cli_now) == null);
    try std.testing.expect(loaded.store.matchCommand(cmd_text, s_allowlist_cli_now) != null);
}

test "s-allowlist-cli: list shows added entries; --json is parseable" {
    var xdg = try sAllowlistCliIsolateXdg();
    defer xdg.deinit();
    var ws = try sAllowlistCliGitWorkspace();
    defer ws.deinit();

    const reason = "list surface marker for permanent pack exception";
    {
        const add = try sAllowlistCliRunAllowlist(&.{
            "add",
            "core.git:reset-hard",
            "-r",
            reason,
            "--project",
        });
        defer sAllowlistCliFreeRun(add);
        try std.testing.expectEqual(exit_codes.success, add.code);
    }

    {
        const list = try sAllowlistCliRunAllowlist(&.{ "list", "--project" });
        defer sAllowlistCliFreeRun(list);
        try std.testing.expectEqual(exit_codes.success, list.code);
        try sAllowlistCliExpectNoDaemonText(list.stdout);
        try std.testing.expect(std.mem.indexOf(u8, list.stdout, "core.git:reset-hard") != null);
        try std.testing.expect(std.mem.indexOf(u8, list.stdout, reason) != null);
    }

    {
        const list_json = try sAllowlistCliRunAllowlist(&.{ "list", "--project", "--json" });
        defer sAllowlistCliFreeRun(list_json);
        try std.testing.expectEqual(exit_codes.success, list_json.code);
        try sAllowlistCliExpectNoDaemonText(list_json.stdout);
        // Minimal stable JSON shape: schema_version + entries array containing the rule id.
        try std.testing.expect(std.mem.indexOf(u8, list_json.stdout, "schema_version") != null);
        try std.testing.expect(std.mem.indexOf(u8, list_json.stdout, "entries") != null);
        try std.testing.expect(std.mem.indexOf(u8, list_json.stdout, "core.git:reset-hard") != null);
        var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, list_json.stdout, .{});
        defer parsed.deinit();
        try std.testing.expect(parsed.value == .object);
    }
}

test "s-allowlist-cli: remove deletes one entry and preserves sibling" {
    var xdg = try sAllowlistCliIsolateXdg();
    defer xdg.deinit();
    var ws = try sAllowlistCliGitWorkspace();
    defer ws.deinit();

    // Two entries, remove the NON-FIRST key (exact-command). Pop-first / wipe-file greening
    // must fail — only the targeted command goes away; the earlier rule sibling remains.
    const cmd_text = "git status";
    {
        const add_rule = try sAllowlistCliRunAllowlist(&.{
            "add",
            "core.git:reset-hard",
            "-r",
            "sibling rule must survive remove of later command key",
            "--project",
        });
        defer sAllowlistCliFreeRun(add_rule);
        try std.testing.expectEqual(exit_codes.success, add_rule.code);
    }
    {
        const add_cmd = try sAllowlistCliRunAllowlist(&.{
            "add-command",
            cmd_text,
            "-r",
            "non-first exact command removed by key",
            "--project",
        });
        defer sAllowlistCliFreeRun(add_cmd);
        try std.testing.expectEqual(exit_codes.success, add_cmd.code);
    }

    {
        // Key = command string (entries[1] if append order preserved) — not the first-added rule.
        const rem = try sAllowlistCliRunAllowlist(&.{ "remove", cmd_text, "--project" });
        defer sAllowlistCliFreeRun(rem);
        try std.testing.expectEqual(exit_codes.success, rem.code);
        try sAllowlistCliExpectNoDaemonText(rem.stdout);
        try sAllowlistCliExpectNoDaemonText(rem.stderr);
    }

    const path = try sAllowlistCliProjectPath(ws.root);
    defer std.testing.allocator.free(path);
    var loaded = try allowlist_store.loadFile(std.testing.io, std.testing.allocator, path, .project);
    defer loaded.store.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), loaded.store.entries.len);
    try std.testing.expect(loaded.store.entries[0].kind == .rule);
    try std.testing.expectEqualStrings("core.git:reset-hard", loaded.store.entries[0].id.?);
    try std.testing.expect(loaded.store.matchRule("core.git:reset-hard", s_allowlist_cli_now) != null);
    try std.testing.expect(loaded.store.matchCommand(cmd_text, s_allowlist_cli_now) == null);

    const raw = try sAllowlistCliReadFile(path);
    defer std.testing.allocator.free(raw);
    try std.testing.expect(std.mem.indexOf(u8, raw, "core.git:reset-hard") != null);
    try std.testing.expect(std.mem.indexOf(u8, raw, cmd_text) == null);
}

test "s-allowlist-cli: validate rejects missing reason and unknown rule under --strict" {
    var xdg = try sAllowlistCliIsolateXdg();
    defer xdg.deinit();
    var ws = try sAllowlistCliGitWorkspace();
    defer ws.deinit();

    // add without -r must fail closed (usage/general); must not write.
    {
        const bad = try sAllowlistCliRunAllowlist(&.{ "add", "core.git:reset-hard", "--project" });
        defer sAllowlistCliFreeRun(bad);
        try std.testing.expect(bad.code != exit_codes.success);
        try sAllowlistCliExpectNoDaemonText(bad.stderr);
    }

    // Unknown rule id under validate --strict must fail after a malformed file, or
    // add itself should reject unknown ids when strict validation is on by default.
    {
        // Write a known-good entry first so validate has a file to inspect.
        const add = try sAllowlistCliRunAllowlist(&.{
            "add",
            "core.git:reset-hard",
            "-r",
            "known good rule for validate baseline",
            "--project",
        });
        defer sAllowlistCliFreeRun(add);
        try std.testing.expectEqual(exit_codes.success, add.code);
    }

    {
        const ok = try sAllowlistCliRunAllowlist(&.{ "validate", "--project" });
        defer sAllowlistCliFreeRun(ok);
        try std.testing.expectEqual(exit_codes.success, ok.code);
    }

    // Strict success on known-good file (prevents always-fail-under-strict greening).
    {
        const strict_ok = try sAllowlistCliRunAllowlist(&.{ "validate", "--strict", "--project" });
        defer sAllowlistCliFreeRun(strict_ok);
        try std.testing.expectEqual(exit_codes.success, strict_ok.code);
        try sAllowlistCliExpectNoDaemonText(strict_ok.stdout);
        try sAllowlistCliExpectNoDaemonText(strict_ok.stderr);
    }

    // Inject an unknown rule id into the file and require --strict to fail.
    const path = try sAllowlistCliProjectPath(ws.root);
    defer std.testing.allocator.free(path);
    try allowlist_store.addEntry(
        std.testing.io,
        std.testing.allocator,
        path,
        .project,
        .{
            .kind = .rule,
            .id = "not.a.real.pack:fabricated-pattern",
            .reason = "should fail strict validate",
            .created_at = s_allowlist_cli_now,
        },
        null, // store accepts when known list is null; CLI validate --strict must still reject
    );

    {
        const strict = try sAllowlistCliRunAllowlist(&.{ "validate", "--strict", "--project" });
        defer sAllowlistCliFreeRun(strict);
        try std.testing.expect(strict.code != exit_codes.success);
        try sAllowlistCliExpectNoDaemonText(strict.stderr);
        // Message should mention unknown / invalid rule somehow.
        const err_blob = if (strict.stderr.len > 0) strict.stderr else strict.stdout;
        try std.testing.expect(
            std.mem.indexOf(u8, err_blob, "unknown") != null or
                std.mem.indexOf(u8, err_blob, "Unknown") != null or
                std.mem.indexOf(u8, err_blob, "not.a.real.pack") != null or
                std.mem.indexOf(u8, err_blob, "invalid") != null or
                std.mem.indexOf(u8, err_blob, "Invalid") != null,
        );
    }
}

test "s-allowlist-cli: prune removes expired entries; dry-run leaves file intact" {
    var xdg = try sAllowlistCliIsolateXdg();
    defer xdg.deinit();
    var ws = try sAllowlistCliGitWorkspace();
    defer ws.deinit();

    const path = try sAllowlistCliProjectPath(ws.root);
    defer std.testing.allocator.free(path);
    {
        const ryk_dir = try sAllowlistCliJoin(&.{ ws.root, ".ryk" });
        defer std.testing.allocator.free(ryk_dir);
        try std.Io.Dir.cwd().createDirPath(std.testing.io, ryk_dir);
    }

    try allowlist_store.addEntry(
        std.testing.io,
        std.testing.allocator,
        path,
        .project,
        .{
            .kind = .rule,
            .id = "core.git:reset-hard",
            .reason = "still valid far-future expiry",
            .created_at = s_allowlist_cli_now,
            .expires_at = s_allowlist_cli_far_expiry,
        },
        null,
    );
    try allowlist_store.addEntry(
        std.testing.io,
        std.testing.allocator,
        path,
        .project,
        .{
            .kind = .command,
            .command = "git status",
            .reason = "expired command should be pruned",
            .created_at = s_allowlist_cli_now,
            .expires_at = s_allowlist_cli_expired,
        },
        null,
    );

    {
        const dry = try sAllowlistCliRunAllowlist(&.{ "prune", "--dry-run", "--project" });
        defer sAllowlistCliFreeRun(dry);
        try std.testing.expectEqual(exit_codes.success, dry.code);
        try sAllowlistCliExpectNoDaemonText(dry.stdout);
        // File still has both entries after dry-run.
        var loaded = try allowlist_store.loadFile(std.testing.io, std.testing.allocator, path, .project);
        defer loaded.store.deinit(std.testing.allocator);
        try std.testing.expectEqual(@as(usize, 2), loaded.store.entries.len);
    }

    {
        const prune = try sAllowlistCliRunAllowlist(&.{ "prune", "--project" });
        defer sAllowlistCliFreeRun(prune);
        try std.testing.expectEqual(exit_codes.success, prune.code);
        try sAllowlistCliExpectNoDaemonText(prune.stdout);
        try sAllowlistCliExpectNoDaemonText(prune.stderr);
    }

    var loaded = try allowlist_store.loadFile(std.testing.io, std.testing.allocator, path, .project);
    defer loaded.store.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), loaded.store.entries.len);
    try std.testing.expect(loaded.store.entries[0].kind == .rule);
    try std.testing.expectEqualStrings("core.git:reset-hard", loaded.store.entries[0].id.?);
}

test "s-allowlist-cli: --user writes under XDG_CONFIG_HOME/ryk/allowlist.toml" {
    var xdg = try sAllowlistCliIsolateXdg();
    defer xdg.deinit();
    var ws = try sAllowlistCliGitWorkspace();
    defer ws.deinit();

    const reason = "user-layer permanent exception for host tooling";
    const run = try sAllowlistCliRunAllowlist(&.{
        "add",
        "core.git:reset-hard",
        "-r",
        reason,
        "--user",
    });
    defer sAllowlistCliFreeRun(run);
    try std.testing.expectEqual(exit_codes.success, run.code);

    const user_path = try sAllowlistCliUserPath(xdg.config_root);
    defer std.testing.allocator.free(user_path);
    var loaded = try allowlist_store.loadFile(std.testing.io, std.testing.allocator, user_path, .user);
    defer loaded.store.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), loaded.store.entries.len);
    try std.testing.expect(loaded.store.entries[0].layer == .user);

    // Project file must not have been created by a --user write.
    const project_path = try sAllowlistCliProjectPath(ws.root);
    defer std.testing.allocator.free(project_path);
    var project_loaded = try allowlist_store.loadFile(std.testing.io, std.testing.allocator, project_path, .project);
    defer project_loaded.store.deinit(std.testing.allocator);
    try std.testing.expect(!project_loaded.corrupt);
    try std.testing.expectEqual(@as(usize, 0), project_loaded.store.entries.len);
}

// M1: nested cwd must write project allowlist at workspace root (product loaders),
// not under the nested directory.
test "s-allowlist-cli: nested cwd --project writes workspace-root allowlist" {
    var xdg = try sAllowlistCliIsolateXdg();
    defer xdg.deinit();
    var ws = try sAllowlistCliGitWorkspace();
    defer ws.deinit();

    try ws.tmp.dir.createDirPath(std.testing.io, "nested/deep");
    const nested = try sAllowlistCliJoin(&.{ ws.root, "nested", "deep" });
    defer std.testing.allocator.free(nested);
    try std.process.setCurrentPath(std.testing.io, nested);

    const reason = "nested cwd project allow must land at repo root for loaders";
    const run = try sAllowlistCliRunAllowlist(&.{
        "add",
        "core.git:reset-hard",
        "-r",
        reason,
        "--project",
    });
    defer sAllowlistCliFreeRun(run);
    try std.testing.expectEqual(exit_codes.success, run.code);

    // Product path: <workspace>/.ryk/allowlist.toml
    const project_path = try sAllowlistCliProjectPath(ws.root);
    defer std.testing.allocator.free(project_path);
    var loaded = try allowlist_store.loadFile(std.testing.io, std.testing.allocator, project_path, .project);
    defer loaded.store.deinit(std.testing.allocator);
    try std.testing.expect(!loaded.corrupt);
    try std.testing.expectEqual(@as(usize, 1), loaded.store.entries.len);
    try std.testing.expectEqualStrings("core.git:reset-hard", loaded.store.entries[0].id.?);

    // Must not create a cwd-only nested allowlist that loaders never see.
    const nested_path = try sAllowlistCliJoin(&.{ nested, ".ryk", "allowlist.toml" });
    defer std.testing.allocator.free(nested_path);
    std.Io.Dir.cwd().access(std.testing.io, nested_path, .{}) catch {
        // Missing nested file is the success case (AccessDenied / FileNotFound).
        return;
    };
    // If nested path somehow exists, it must not be the only write target — still fail
    // because product loaders use workspace root only.
    try std.testing.expect(false);
}

test "s-allowlist-cli: nested cwd auto layer uses project when workspace has .git" {
    var xdg = try sAllowlistCliIsolateXdg();
    defer xdg.deinit();
    var ws = try sAllowlistCliGitWorkspace();
    defer ws.deinit();

    try ws.tmp.dir.createDirPath(std.testing.io, "pkg");
    const nested = try sAllowlistCliJoin(&.{ ws.root, "pkg" });
    defer std.testing.allocator.free(nested);
    try std.process.setCurrentPath(std.testing.io, nested);

    // Neither --project nor --user: walk-up .git → project layer at workspace root.
    const reason = "auto layer from nested directory must still pick project workspace";
    const run = try sAllowlistCliRunAllowlist(&.{
        "add",
        "core.git:force-push",
        "-r",
        reason,
    });
    defer sAllowlistCliFreeRun(run);
    try std.testing.expectEqual(exit_codes.success, run.code);

    const project_path = try sAllowlistCliProjectPath(ws.root);
    defer std.testing.allocator.free(project_path);
    var loaded = try allowlist_store.loadFile(std.testing.io, std.testing.allocator, project_path, .project);
    defer loaded.store.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), loaded.store.entries.len);
    try std.testing.expect(loaded.store.entries[0].layer == .project);

    // User layer must remain empty under isolated XDG.
    const user_path = try sAllowlistCliUserPath(xdg.config_root);
    defer std.testing.allocator.free(user_path);
    var user_loaded = try allowlist_store.loadFile(std.testing.io, std.testing.allocator, user_path, .user);
    defer user_loaded.store.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), user_loaded.store.entries.len);
}

test "s-allowlist-cli: help and missing subcommand are usage-safe without daemon" {
    {
        const run = try sAllowlistCliRunAllowlist(&.{"--help"});
        defer sAllowlistCliFreeRun(run);
        try std.testing.expectEqual(exit_codes.success, run.code);
        try sAllowlistCliExpectNoDaemonText(run.stdout);
        try sAllowlistCliExpectNoDaemonText(run.stderr);
        // Usage should teach live subcommands (not daemon proxy essay).
        const blob = if (run.stdout.len > 0) run.stdout else run.stderr;
        try std.testing.expect(std.mem.indexOf(u8, blob, "add") != null);
        try std.testing.expect(std.mem.indexOf(u8, blob, "list") != null);
    }
    {
        const run = try sAllowlistCliRunAllowlist(&.{"not-a-subcommand"});
        defer sAllowlistCliFreeRun(run);
        try std.testing.expectEqual(exit_codes.usage, run.code);
        try sAllowlistCliExpectNoDaemonText(run.stderr);
    }
    {
        const run = try sAllowlistCliRunAllowlist(&.{});
        defer sAllowlistCliFreeRun(run);
        // Empty argv: help-or-usage, never crash / never daemon.
        try std.testing.expect(run.code == exit_codes.success or run.code == exit_codes.usage);
        try sAllowlistCliExpectNoDaemonText(run.stdout);
        try sAllowlistCliExpectNoDaemonText(run.stderr);
    }
}

test "s-allowlist-cli: unknown subcommand suggests add for ad typo" {
    const run = try sAllowlistCliRunAllowlist(&.{"ad"});
    defer sAllowlistCliFreeRun(run);
    try std.testing.expectEqual(exit_codes.usage, run.code);
    try std.testing.expect(std.mem.indexOf(u8, run.stderr, "unknown subcommand") != null);
    try std.testing.expect(std.mem.indexOf(u8, run.stderr, "Did you mean 'add'?") != null);
    try std.testing.expect(std.mem.indexOf(u8, run.stderr, "ryk help allowlist") != null);
}

// ---------------------------------------------------------------------------
// Acceptance 2 — allow rule then evaluate allows; compound still denies (E8)
// ---------------------------------------------------------------------------

test "s-allowlist-cli: allow shortcut then evaluate allows with allowlist attribution" {
    var xdg = try sAllowlistCliIsolateXdg();
    defer xdg.deinit();
    var ws = try sAllowlistCliGitWorkspace();
    defer ws.deinit();

    // Non-critical rule (medium): permanent kind=rule may skip. Critical cannot.
    const reason = "s-allowlist-cli rule allow attribution marker";
    {
        const run = try sAllowlistCliRunAllow(&.{
            "core.git:branch-force-delete",
            "-r",
            reason,
            "--project",
        });
        defer sAllowlistCliFreeRun(run);
        try std.testing.expectEqual(exit_codes.success, run.code);
        try sAllowlistCliExpectNoDaemonText(run.stdout);
        try sAllowlistCliExpectNoDaemonText(run.stderr);
    }

    const path = try sAllowlistCliProjectPath(ws.root);
    defer std.testing.allocator.free(path);
    var loaded = try allowlist_store.loadFile(std.testing.io, std.testing.allocator, path, .project);
    defer loaded.store.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), loaded.store.entries.len);

    // Engine path (s-engine contract): kind=rule → allow + exception_* attribution.
    var eval = try shell_engine.evaluateCommand(std.testing.allocator, "git branch -D feature", .{
        .permanent_allowlist = loaded.store,
        .now_iso = s_allowlist_cli_now,
    });
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .allow);
    try std.testing.expectEqualStrings("allowlist", eval.exception_source.?);
    try std.testing.expectEqualStrings("project", eval.exception_layer.?);
    try std.testing.expectEqualStrings("rule", eval.exception_kind.?);
    try std.testing.expect(std.mem.indexOf(u8, eval.reason, reason) != null);
}

test "s-allowlist-cli: allow rule still denies compound / other packs (E8)" {
    var xdg = try sAllowlistCliIsolateXdg();
    defer xdg.deinit();
    var ws = try sAllowlistCliGitWorkspace();
    defer ws.deinit();

    {
        const run = try sAllowlistCliRunAllow(&.{
            "core.git:branch-force-delete",
            "-r",
            "branch delete exception must not unlock filesystem wipe",
            "--project",
        });
        defer sAllowlistCliFreeRun(run);
        try std.testing.expectEqual(exit_codes.success, run.code);
    }

    const path = try sAllowlistCliProjectPath(ws.root);
    defer std.testing.allocator.free(path);
    var loaded = try allowlist_store.loadFile(std.testing.io, std.testing.allocator, path, .project);
    defer loaded.store.deinit(std.testing.allocator);

    var compound = try shell_engine.evaluateCommand(std.testing.allocator, "git branch -D feature; rm -rf /", .{
        .permanent_allowlist = loaded.store,
        .now_iso = s_allowlist_cli_now,
    });
    defer compound.deinit(std.testing.allocator);
    try std.testing.expect(compound.decision == .deny);
    try std.testing.expect(compound.exception_source == null);
    try std.testing.expect(compound.pack_id != null);
    try std.testing.expectEqualStrings("core.filesystem", compound.pack_id.?);

    var other = try shell_engine.evaluateCommand(std.testing.allocator, "rm -rf /", .{
        .permanent_allowlist = loaded.store,
        .now_iso = s_allowlist_cli_now,
    });
    defer other.deinit(std.testing.allocator);
    try std.testing.expect(other.decision == .deny);
    try std.testing.expect(other.exception_source == null);
}

test "s-allowlist-cli: add-command then evaluate FULL ALLOWs exact command only" {
    var xdg = try sAllowlistCliIsolateXdg();
    defer xdg.deinit();
    var ws = try sAllowlistCliGitWorkspace();
    defer ws.deinit();

    // Non-critical exact command (medium pack hit) may FULL ALLOW permanently.
    const reason = "exact command permanent short-circuit via CLI";
    const cmd_text = "git branch -D feature";
    {
        const run = try sAllowlistCliRunAllowlist(&.{
            "add-command",
            cmd_text,
            "-r",
            reason,
            "--project",
        });
        defer sAllowlistCliFreeRun(run);
        try std.testing.expectEqual(exit_codes.success, run.code);
    }

    const path = try sAllowlistCliProjectPath(ws.root);
    defer std.testing.allocator.free(path);
    var loaded = try allowlist_store.loadFile(std.testing.io, std.testing.allocator, path, .project);
    defer loaded.store.deinit(std.testing.allocator);

    var eval = try shell_engine.evaluateCommand(std.testing.allocator, cmd_text, .{
        .permanent_allowlist = loaded.store,
        .now_iso = s_allowlist_cli_now,
    });
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .allow);
    try std.testing.expectEqualStrings("allowlist", eval.exception_source.?);
    try std.testing.expectEqualStrings("command", eval.exception_kind.?);
    try std.testing.expect(std.mem.indexOf(u8, eval.reason, reason) != null);

    // Non-exact / compound string still denies (no prefix, no full-string near-miss).
    var miss = try shell_engine.evaluateCommand(std.testing.allocator, "git branch -D other", .{
        .permanent_allowlist = loaded.store,
        .now_iso = s_allowlist_cli_now,
    });
    defer miss.deinit(std.testing.allocator);
    try std.testing.expect(miss.decision == .deny);

    var compound = try shell_engine.evaluateCommand(std.testing.allocator, "git branch -D feature; rm -rf /", .{
        .permanent_allowlist = loaded.store,
        .now_iso = s_allowlist_cli_now,
    });
    defer compound.deinit(std.testing.allocator);
    try std.testing.expect(compound.decision == .deny);
}

test "s-allowlist-cli: unallow shortcut removes rule so evaluate denies again" {
    var xdg = try sAllowlistCliIsolateXdg();
    defer xdg.deinit();
    var ws = try sAllowlistCliGitWorkspace();
    defer ws.deinit();

    // Seed non-critical rule first, then command. Unallow the NON-FIRST key
    // (command string) so pop-first greening fails; the rule sibling must remain
    // and still evaluate-allow (medium only — critical is hard-fenced).
    const cmd_text = "git status";
    {
        const add = try sAllowlistCliRunAllow(&.{
            "core.git:branch-force-delete",
            "-r",
            "rule sibling must survive unallow of later command",
            "--project",
        });
        defer sAllowlistCliFreeRun(add);
        try std.testing.expectEqual(exit_codes.success, add.code);
    }
    {
        const add_cmd = try sAllowlistCliRunAllowlist(&.{
            "add-command",
            cmd_text,
            "-r",
            "non-first exact command removed via unallow shortcut",
            "--project",
        });
        defer sAllowlistCliFreeRun(add_cmd);
        try std.testing.expectEqual(exit_codes.success, add_cmd.code);
    }
    {
        const rem = try sAllowlistCliRunUnallow(&.{ cmd_text, "--project" });
        defer sAllowlistCliFreeRun(rem);
        try std.testing.expectEqual(exit_codes.success, rem.code);
        try sAllowlistCliExpectNoDaemonText(rem.stdout);
        try sAllowlistCliExpectNoDaemonText(rem.stderr);
    }

    const path = try sAllowlistCliProjectPath(ws.root);
    defer std.testing.allocator.free(path);
    {
        var loaded = try allowlist_store.loadFile(std.testing.io, std.testing.allocator, path, .project);
        defer loaded.store.deinit(std.testing.allocator);
        try std.testing.expectEqual(@as(usize, 1), loaded.store.entries.len);
        try std.testing.expect(loaded.store.entries[0].kind == .rule);
        try std.testing.expectEqualStrings("core.git:branch-force-delete", loaded.store.entries[0].id.?);
        try std.testing.expect(loaded.store.matchRule("core.git:branch-force-delete", s_allowlist_cli_now) != null);
        try std.testing.expect(loaded.store.matchCommand(cmd_text, s_allowlist_cli_now) == null);

        // Rule still in force: evaluate allows with allowlist attribution (not pop-first).
        var still = try shell_engine.evaluateCommand(std.testing.allocator, "git branch -D feature", .{
            .permanent_allowlist = loaded.store,
            .now_iso = s_allowlist_cli_now,
        });
        defer still.deinit(std.testing.allocator);
        try std.testing.expect(still.decision == .allow);
        try std.testing.expectEqualStrings("allowlist", still.exception_source.?);
        try std.testing.expectEqualStrings("rule", still.exception_kind.?);
    }

    // Second step: unallow the remaining rule key → evaluate denies again.
    {
        const rem_rule = try sAllowlistCliRunUnallow(&.{ "core.git:branch-force-delete", "--project" });
        defer sAllowlistCliFreeRun(rem_rule);
        try std.testing.expectEqual(exit_codes.success, rem_rule.code);
    }
    {
        var loaded = try allowlist_store.loadFile(std.testing.io, std.testing.allocator, path, .project);
        defer loaded.store.deinit(std.testing.allocator);
        try std.testing.expectEqual(@as(usize, 0), loaded.store.entries.len);
        try std.testing.expect(loaded.store.matchRule("core.git:branch-force-delete", s_allowlist_cli_now) == null);

        var eval = try shell_engine.evaluateCommand(std.testing.allocator, "git branch -D feature", .{
            .permanent_allowlist = loaded.store,
            .now_iso = s_allowlist_cli_now,
        });
        defer eval.deinit(std.testing.allocator);
        try std.testing.expect(eval.decision == .deny);
        try std.testing.expect(eval.exception_source == null);
    }
}

test "s-allowlist-cli: remove exact-command key empties store and restores deny" {
    var xdg = try sAllowlistCliIsolateXdg();
    defer xdg.deinit();
    var ws = try sAllowlistCliGitWorkspace();
    defer ws.deinit();

    // Medium pack hit (permanent may allow); after remove, packs deny again.
    const cmd_text = "git branch -D feature";
    {
        const add = try sAllowlistCliRunAllowlist(&.{
            "add-command",
            cmd_text,
            "-r",
            "exact command to remove by command string",
            "--project",
        });
        defer sAllowlistCliFreeRun(add);
        try std.testing.expectEqual(exit_codes.success, add.code);
    }
    {
        const rem = try sAllowlistCliRunAllowlist(&.{ "remove", cmd_text, "--project" });
        defer sAllowlistCliFreeRun(rem);
        try std.testing.expectEqual(exit_codes.success, rem.code);
        try sAllowlistCliExpectNoDaemonText(rem.stdout);
        try sAllowlistCliExpectNoDaemonText(rem.stderr);
    }

    const path = try sAllowlistCliProjectPath(ws.root);
    defer std.testing.allocator.free(path);
    var loaded = try allowlist_store.loadFile(std.testing.io, std.testing.allocator, path, .project);
    defer loaded.store.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), loaded.store.entries.len);
    try std.testing.expect(loaded.store.matchCommand(cmd_text, s_allowlist_cli_now) == null);

    var eval = try shell_engine.evaluateCommand(std.testing.allocator, cmd_text, .{
        .permanent_allowlist = loaded.store,
        .now_iso = s_allowlist_cli_now,
    });
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .deny);
    try std.testing.expect(eval.exception_source == null);
}

test "s-allowlist-cli: unallow exact-command key removes entry and restores deny" {
    var xdg = try sAllowlistCliIsolateXdg();
    defer xdg.deinit();
    var ws = try sAllowlistCliGitWorkspace();
    defer ws.deinit();

    const cmd_text = "git status";
    {
        const add = try sAllowlistCliRunAllowlist(&.{
            "add-command",
            cmd_text,
            "-r",
            "exact command removed via unallow shortcut",
            "--project",
        });
        defer sAllowlistCliFreeRun(add);
        try std.testing.expectEqual(exit_codes.success, add.code);
    }
    {
        const rem = try sAllowlistCliRunUnallow(&.{ cmd_text, "--project" });
        defer sAllowlistCliFreeRun(rem);
        try std.testing.expectEqual(exit_codes.success, rem.code);
        try sAllowlistCliExpectNoDaemonText(rem.stdout);
        try sAllowlistCliExpectNoDaemonText(rem.stderr);
    }

    const path = try sAllowlistCliProjectPath(ws.root);
    defer std.testing.allocator.free(path);
    var loaded = try allowlist_store.loadFile(std.testing.io, std.testing.allocator, path, .project);
    defer loaded.store.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), loaded.store.entries.len);

    var eval = try shell_engine.evaluateCommand(std.testing.allocator, cmd_text, .{
        .permanent_allowlist = loaded.store,
        .now_iso = s_allowlist_cli_now,
    });
    defer eval.deinit(std.testing.allocator);
    // "git status" is typically allow under packs; exception attribution must be gone.
    try std.testing.expect(eval.exception_source == null);
}

// ---------------------------------------------------------------------------
// Acceptance — help surfaces allowlist / allow / unallow
// ---------------------------------------------------------------------------

test "s-allowlist-cli: help exposes allowlist allow unallow (not hidden)" {
    const names = [_][]const u8{ "allowlist", "allow", "unallow" };
    for (names) |name| {
        const info = help.findCommand(name) orelse {
            std.debug.print("missing help entry for {s}\n", .{name});
            try std.testing.expect(false);
            return;
        };
        try std.testing.expect(!info.hidden);
    }
}

test "s-allowlist-cli: root help --all lists allowlist allow unallow as peers" {
    var buf: [32768]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try help.writeWithMode(std.testing.io, &writer, .all);
    const text = writer.buffered();

    // Peer-column rows only (not `--network allowlist` in run details).
    try std.testing.expect(sAllowlistCliHelpListsPeer(text, "allowlist"));
    try std.testing.expect(sAllowlistCliHelpListsPeer(text, "allow"));
    try std.testing.expect(sAllowlistCliHelpListsPeer(text, "unallow"));
}

/// Mirror of help.zig private `helpListsPeerCommand` (peer column: 4 spaces + name + space).
fn sAllowlistCliHelpListsPeer(text: []const u8, name: []const u8) bool {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "    ")) continue;
        if (std.mem.startsWith(u8, line, "    --")) continue;
        const rest = line[4..];
        if (rest.len <= name.len) continue;
        if (std.mem.startsWith(u8, rest, name) and rest[name.len] == ' ') return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Branch / edge paths
// ---------------------------------------------------------------------------

test "s-allowlist-cli: isValidExpiresIsoZ accepts product Timestamp format only" {
    try std.testing.expect(isValidExpiresIsoZ("2026-07-25T12:00:00Z"));
    try std.testing.expect(isValidExpiresIsoZ("9999-01-01T00:00:00Z"));
    try std.testing.expect(!isValidExpiresIsoZ("2026-07-25"));
    try std.testing.expect(!isValidExpiresIsoZ("2026-07-25T12:00:00+00:00"));
    try std.testing.expect(!isValidExpiresIsoZ("2026-07-25 12:00:00Z"));
    try std.testing.expect(!isValidExpiresIsoZ("2026-13-01T00:00:00Z"));
    try std.testing.expect(!isValidExpiresIsoZ("not-a-date"));
    try std.testing.expect(!isValidExpiresIsoZ(""));
}

test "s-allowlist-cli: --expires rejects non ISO-Z shape with usage" {
    var xdg = try sAllowlistCliIsolateXdg();
    defer xdg.deinit();
    var ws = try sAllowlistCliGitWorkspace();
    defer ws.deinit();

    const run = try sAllowlistCliRunAllowlist(&.{
        "add",
        "core.git:reset-hard",
        "-r",
        "bad expires must fail closed",
        "--expires",
        "tomorrow",
        "--project",
    });
    defer sAllowlistCliFreeRun(run);
    try std.testing.expectEqual(exit_codes.usage, run.code);
    try std.testing.expect(std.mem.indexOf(u8, run.stderr, "expires") != null or
        std.mem.indexOf(u8, run.stderr, "ISO") != null);

    const path = try sAllowlistCliProjectPath(ws.root);
    defer std.testing.allocator.free(path);
    var loaded = try allowlist_store.loadFile(std.testing.io, std.testing.allocator, path, .project);
    defer loaded.store.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), loaded.store.entries.len);
}

test "s-allowlist-cli: --expires accepts YYYY-MM-DDTHH:MM:SSZ and writes entry" {
    var xdg = try sAllowlistCliIsolateXdg();
    defer xdg.deinit();
    var ws = try sAllowlistCliGitWorkspace();
    defer ws.deinit();

    const exp = "2026-12-31T23:59:59Z";
    const run = try sAllowlistCliRunAllowlist(&.{
        "add",
        "core.git:reset-hard",
        "-r",
        "expires shape ok",
        "--expires",
        exp,
        "--project",
    });
    defer sAllowlistCliFreeRun(run);
    try std.testing.expectEqual(exit_codes.success, run.code);

    const path = try sAllowlistCliProjectPath(ws.root);
    defer std.testing.allocator.free(path);
    var loaded = try allowlist_store.loadFile(std.testing.io, std.testing.allocator, path, .project);
    defer loaded.store.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), loaded.store.entries.len);
    try std.testing.expectEqualStrings(exp, loaded.store.entries[0].expires_at.?);
}

test "s-allowlist-cli: add requires reason flag" {
    var xdg = try sAllowlistCliIsolateXdg();
    defer xdg.deinit();
    var ws = try sAllowlistCliGitWorkspace();
    defer ws.deinit();

    const run = try sAllowlistCliRunAllowlist(&.{ "add", "core.git:reset-hard", "--project" });
    defer sAllowlistCliFreeRun(run);
    try std.testing.expect(run.code == exit_codes.usage or run.code == exit_codes.general);

    const path = try sAllowlistCliProjectPath(ws.root);
    defer std.testing.allocator.free(path);
    var loaded = try allowlist_store.loadFile(std.testing.io, std.testing.allocator, path, .project);
    defer loaded.store.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), loaded.store.entries.len);
}

test "s-allowlist-cli: add rejects invalid rule-id form without write" {
    var xdg = try sAllowlistCliIsolateXdg();
    defer xdg.deinit();
    var ws = try sAllowlistCliGitWorkspace();
    defer ws.deinit();

    const run = try sAllowlistCliRunAllowlist(&.{
        "add",
        "not-a-valid-rule-id",
        "-r",
        "invalid form must not land on disk",
        "--project",
    });
    defer sAllowlistCliFreeRun(run);
    try std.testing.expect(run.code != exit_codes.success);

    const path = try sAllowlistCliProjectPath(ws.root);
    defer std.testing.allocator.free(path);
    var loaded = try allowlist_store.loadFile(std.testing.io, std.testing.allocator, path, .project);
    defer loaded.store.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), loaded.store.entries.len);
}

test "s-allowlist-cli: remove missing key is non-success or explicit not-found" {
    var xdg = try sAllowlistCliIsolateXdg();
    defer xdg.deinit();
    var ws = try sAllowlistCliGitWorkspace();
    defer ws.deinit();

    const run = try sAllowlistCliRunAllowlist(&.{ "remove", "core.git:reset-hard", "--project" });
    defer sAllowlistCliFreeRun(run);
    // Must not green on the intentional RED stub body.
    try std.testing.expect(!sAllowlistCliIsStubNotImplemented(run.stdout, run.stderr));
    try sAllowlistCliExpectNoDaemonText(run.stdout);
    try sAllowlistCliExpectNoDaemonText(run.stderr);

    // Dedicated remove-missing path: not-found messaging required either way.
    // Prefer non-success; success is only OK when messaging is explicit.
    const blob = if (run.stderr.len > 0) run.stderr else run.stdout;
    try std.testing.expect(sAllowlistCliHasNotFoundMsg(blob));
    if (run.code == exit_codes.success) {
        // Chatty success must still be a real remove path, not a no-op green.
        try std.testing.expect(blob.len > 0);
    } else {
        try std.testing.expect(run.code == exit_codes.usage or run.code == exit_codes.general);
    }
}

test "s-allowlist-cli: default layer is project inside git workspace (no layer flags)" {
    var xdg = try sAllowlistCliIsolateXdg();
    defer xdg.deinit();
    var ws = try sAllowlistCliGitWorkspace();
    defer ws.deinit();

    const reason = "default project layer without --project flag";
    const run = try sAllowlistCliRunAllowlist(&.{
        "add",
        "core.git:reset-hard",
        "-r",
        reason,
        // intentionally no --project / --user
    });
    defer sAllowlistCliFreeRun(run);
    try std.testing.expectEqual(exit_codes.success, run.code);
    try sAllowlistCliExpectNoDaemonText(run.stdout);
    try sAllowlistCliExpectNoDaemonText(run.stderr);

    const project_path = try sAllowlistCliProjectPath(ws.root);
    defer std.testing.allocator.free(project_path);
    var project_loaded = try allowlist_store.loadFile(std.testing.io, std.testing.allocator, project_path, .project);
    defer project_loaded.store.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), project_loaded.store.entries.len);
    try std.testing.expect(project_loaded.store.entries[0].layer == .project);
    try std.testing.expectEqualStrings("core.git:reset-hard", project_loaded.store.entries[0].id.?);

    // Must not have fallen through to user layer.
    const user_path = try sAllowlistCliUserPath(xdg.config_root);
    defer std.testing.allocator.free(user_path);
    var user_loaded = try allowlist_store.loadFile(std.testing.io, std.testing.allocator, user_path, .user);
    defer user_loaded.store.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), user_loaded.store.entries.len);
}

test "s-allowlist-cli: default layer is user outside git workspace (no layer flags)" {
    var xdg = try sAllowlistCliIsolateXdg();
    defer xdg.deinit();
    // cwd has no `.git` (pack_config-style check of cwd only — not parent walk).
    var ws = try sAllowlistCliNonGitWorkspace();
    defer ws.deinit();

    const reason = "default user layer without --user flag outside git";
    const run = try sAllowlistCliRunAllowlist(&.{
        "add",
        "core.git:reset-hard",
        "-r",
        reason,
        // intentionally no --project / --user
    });
    defer sAllowlistCliFreeRun(run);
    try std.testing.expectEqual(exit_codes.success, run.code);
    try sAllowlistCliExpectNoDaemonText(run.stdout);
    try sAllowlistCliExpectNoDaemonText(run.stderr);

    const user_path = try sAllowlistCliUserPath(xdg.config_root);
    defer std.testing.allocator.free(user_path);
    var user_loaded = try allowlist_store.loadFile(std.testing.io, std.testing.allocator, user_path, .user);
    defer user_loaded.store.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), user_loaded.store.entries.len);
    try std.testing.expect(user_loaded.store.entries[0].layer == .user);
    try std.testing.expectEqualStrings("core.git:reset-hard", user_loaded.store.entries[0].id.?);
    try std.testing.expectEqualStrings(reason, user_loaded.store.entries[0].reason);

    // No project allowlist under the non-git cwd.
    const project_path = try sAllowlistCliProjectPath(ws.root);
    defer std.testing.allocator.free(project_path);
    var project_loaded = try allowlist_store.loadFile(std.testing.io, std.testing.allocator, project_path, .project);
    defer project_loaded.store.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), project_loaded.store.entries.len);
}

// ---------------------------------------------------------------------------
// U05 allowlist browse — command wiring + remove cancel fixture
// ---------------------------------------------------------------------------

test "s-allowlist browse: bare allowlist and --plain stay linear non-TTY" {
    var xdg = try sAllowlistCliIsolateXdg();
    defer xdg.deinit();
    var ws = try sAllowlistCliGitWorkspace();
    defer ws.deinit();

    {
        const add = try sAllowlistCliRunAllowlist(&.{
            "add",
            "core.git:reset-hard",
            "-r",
            "bare list fixture",
            "--project",
        });
        defer sAllowlistCliFreeRun(add);
        try std.testing.expectEqual(exit_codes.success, add.code);
    }

    // Bare `ryk allowlist` → list (linear under test buffers / non-TTY).
    {
        const bare = try sAllowlistCliRunAllowlist(&.{});
        defer sAllowlistCliFreeRun(bare);
        try std.testing.expectEqual(exit_codes.success, bare.code);
        try std.testing.expect(std.mem.indexOf(u8, bare.stdout, "core.git:reset-hard") != null);
        // Never alt-screen on non-TTY path.
        try std.testing.expect(std.mem.indexOf(u8, bare.stdout, "\x1b[?1049h") == null);
    }

    // --plain linear escape.
    {
        const plain = try sAllowlistCliRunAllowlist(&.{ "list", "--plain" });
        defer sAllowlistCliFreeRun(plain);
        try std.testing.expectEqual(exit_codes.success, plain.code);
        try std.testing.expect(std.mem.indexOf(u8, plain.stdout, "core.git:reset-hard") != null);
    }

    // --json frozen machine shape.
    {
        const json = try sAllowlistCliRunAllowlist(&.{ "list", "--json" });
        defer sAllowlistCliFreeRun(json);
        try std.testing.expectEqual(exit_codes.success, json.code);
        try std.testing.expect(std.mem.indexOf(u8, json.stdout, "schema_version") != null);
        try std.testing.expect(std.mem.indexOf(u8, json.stdout, "core.git:reset-hard") != null);
    }
}

test "s-allowlist browse: remove cancel leaves allowlist file unchanged" {
    var xdg = try sAllowlistCliIsolateXdg();
    defer xdg.deinit();
    var ws = try sAllowlistCliGitWorkspace();
    defer ws.deinit();

    const reason = "remove cancel fixture permanent entry";
    {
        const add = try sAllowlistCliRunAllowlist(&.{
            "add",
            "core.git:reset-hard",
            "-r",
            reason,
            "--project",
        });
        defer sAllowlistCliFreeRun(add);
        try std.testing.expectEqual(exit_codes.success, add.code);
    }

    const project_path = try sAllowlistCliProjectPath(ws.root);
    defer std.testing.allocator.free(project_path);
    const before = try sAllowlistCliReadFile(project_path);
    defer std.testing.allocator.free(before);
    try std.testing.expect(std.mem.indexOf(u8, before, "core.git:reset-hard") != null);

    // Cancel path: confirm default No → applyRemoveIfConfirmed skips write.
    const confirmed = allowlist_browse.confirmRemoveDefaultNo("");
    try std.testing.expect(!confirmed);

    var wrote = false;
    const remove_fn = struct {
        var flag: *bool = undefined;
        var io_ref: std.Io = undefined;
        var path_ref: []const u8 = undefined;
        fn call() anyerror!bool {
            flag.* = true;
            return allowlist_store.removeEntry(io_ref, std.testing.allocator, path_ref, .project, "core.git:reset-hard");
        }
    };
    remove_fn.flag = &wrote;
    remove_fn.io_ref = std.testing.io;
    remove_fn.path_ref = project_path;

    const removed = try allowlist_browse.applyRemoveIfConfirmed(confirmed, remove_fn.call);
    try std.testing.expect(!removed);
    try std.testing.expect(!wrote);

    const after = try sAllowlistCliReadFile(project_path);
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualStrings(before, after);
    try std.testing.expect(std.mem.indexOf(u8, after, "core.git:reset-hard") != null);
    try std.testing.expect(std.mem.indexOf(u8, after, reason) != null);
}

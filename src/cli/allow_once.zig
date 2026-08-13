//! Allow-once CLI (product path) — redeem / list / clear / revoke.
//!
//! Live Zig surface for `ryk allow-once` against `shell_engine.allow_once`
//! pending + active JSONL stores. **No daemon.**
//!
//! Paths (must match product-wire loaders / s3-once-store brand):
//!   pending  → `$XDG_DATA_HOME/ryk/pending_exceptions.jsonl`
//!              else `~/.local/share/ryk/pending_exceptions.jsonl`
//!   active   → `$XDG_DATA_HOME/ryk/allow_once.jsonl`
//!              else `~/.local/share/ryk/allow_once.jsonl`
//!
//! Subcommands: `<code> [-y] [--json] [--scope cwd|project]`, `list`, `clear`, `revoke`.
//! Default redeem scope_path is the pending record cwd (grant matches deny site).
//! Redeem is operator-bound (M-1): interactive TTY confirmation only. There is no
//! env-var break-glass — `RYK_OPERATOR` was removed because env vars are
//! child-controlled and authenticate nobody.

const std = @import("std");
const core = @import("ryk_core").core;
const exit_codes = @import("exit_codes.zig");
const help = @import("help.zig");
const interactive = @import("interactive.zig");
const shell_engine = @import("../shell_engine/mod.zig");

const allow_once_store = shell_engine.allow_once;

// ---------------------------------------------------------------------------
// Production surface
// ---------------------------------------------------------------------------

const usage_text =
    \\Usage: ryk allow-once <code> [-y] [--json] [--scope cwd|project]
    \\       ryk allow-once list [--json]
    \\       ryk allow-once clear [pending|active|all]
    \\       ryk allow-once revoke <code|hash>
    \\
    \\Redeem a pending short code into a single-use allow-once grant for the exact
    \\command and scope. Management: list, clear, revoke.
    \\
    \\Redeem is operator-bound: interactive TTY confirmation required.
    \\-y/--yes skips the confirmation prompt but never authorizes a non-TTY redeem.
    \\
    \\Paths: $XDG_DATA_HOME/ryk/ (or ~/.local/share/ryk/)
    \\  pending_exceptions.jsonl · allow_once.jsonl
    \\
;

/// Test seam: when non-null, overrides the real TTY probe for the redeem gate.
/// Production code leaves this null; tests set it to simulate operator presence
/// (or absence) without a real terminal. Never set by shipped code paths.
pub var test_operator_tty_override: ?bool = null;

/// Top-level `ryk allow-once …` (argv after the verb).
pub fn command(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    var now_buf: [32]u8 = undefined;
    const now_iso = try core.time.Timestamp.now(io).formatIso(&now_buf);
    return commandAt(io, argv, now_iso, stdout, stderr);
}

fn commandAt(io: std.Io, argv: []const []const u8, now_iso: []const u8, stdout: anytype, stderr: anytype) !u8 {
    if (argv.len == 0) {
        try stderr.writeAll(usage_text);
        return exit_codes.usage;
    }
    if (std.mem.eql(u8, argv[0], "--help") or std.mem.eql(u8, argv[0], "-h")) {
        try stdout.writeAll(usage_text);
        return exit_codes.success;
    }

    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    const data_dir = try resolveRykDataDir(gpa) orelse {
        try stderr.writeAll("ryk allow-once: cannot resolve data directory (set XDG_DATA_HOME or HOME)\n");
        return exit_codes.general;
    };
    defer gpa.free(data_dir);

    try std.Io.Dir.cwd().createDirPath(io, data_dir);

    const pending_path = try std.fs.path.join(gpa, &.{ data_dir, allow_once_store.pending_file_name });
    defer gpa.free(pending_path);
    const once_path = try std.fs.path.join(gpa, &.{ data_dir, allow_once_store.allow_once_file_name });
    defer gpa.free(once_path);

    if (std.mem.eql(u8, argv[0], "list")) {
        return cmdList(io, gpa, once_path, now_iso, argv[1..], stdout, stderr);
    }
    if (std.mem.eql(u8, argv[0], "clear")) {
        return cmdClear(io, gpa, pending_path, once_path, now_iso, argv[1..], stdout, stderr);
    }
    if (std.mem.eql(u8, argv[0], "revoke")) {
        return cmdRevoke(io, gpa, pending_path, once_path, now_iso, argv[1..], stdout, stderr);
    }

    // Default: redeem short code.
    return cmdRedeem(io, gpa, pending_path, once_path, now_iso, argv, stdout, stderr);
}

fn resolveRykDataDir(gpa: std.mem.Allocator) !?[]u8 {
    if (std.c.getenv("XDG_DATA_HOME")) |xdg_z| {
        const xdg = std.mem.span(xdg_z);
        if (xdg.len > 0) {
            return try std.fs.path.join(gpa, &.{ xdg, "ryk"});
        }
    }
    if (std.c.getenv("HOME")) |home_z| {
        const home = std.mem.span(home_z);
        if (home.len > 0) {
            return try std.fs.path.join(gpa, &.{ home, ".local", "share", "ryk"});
        }
    }
    return null;
}

/// Operator presence for redeem (M-1). The only trustworthy signal is an
/// interactive controlling terminal: environment variables are per-invocation
/// and fully child-controlled, so an agent subprocess can set any var on itself.
/// A TTY is the boundary an agent cannot fabricate for a human. Non-TTY → false
/// (fail closed). `RYK_OPERATOR` was removed — it authenticated nobody.
fn operatorRedeemAuthorized(io: std.Io) bool {
    if (test_operator_tty_override) |v| return v;
    return std.Io.File.stdin().isTty(io) catch false;
}

fn cmdRedeem(
    io: std.Io,
    gpa: std.mem.Allocator,
    pending_path: []const u8,
    once_path: []const u8,
    now_iso: []const u8,
    argv: []const []const u8,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    const code = argv[0];
    if (!isSixDigitCode(code) and !looksLikeHash(code)) {
        // Still attempt redeem — store accepts any short_code string; 6-digit is UX.
        // Non-code flags at position 0 are usage.
        if (std.mem.startsWith(u8, code, "-")) {
            try stderr.writeAll("ryk allow-once: missing short code\n");
            try stderr.writeAll(usage_text);
            return exit_codes.usage;
        }
    }

    var yes = false;
    var as_json = false;
    var scope_kind: allow_once_store.ScopeKind = .cwd;
    var i: usize = 1;
    while (i < argv.len) : (i += 1) {
        const arg = argv[i];
        if (std.mem.eql(u8, arg, "-y") or std.mem.eql(u8, arg, "--yes")) {
            yes = true;
        } else if (std.mem.eql(u8, arg, "--json")) {
            as_json = true;
        } else if (std.mem.eql(u8, arg, "--scope")) {
            i += 1;
            if (i >= argv.len) {
                try stderr.writeAll("ryk allow-once: --scope requires cwd or project\n");
                return exit_codes.usage;
            }
            if (std.mem.eql(u8, argv[i], "cwd")) {
                scope_kind = .cwd;
            } else if (std.mem.eql(u8, argv[i], "project")) {
                scope_kind = .project;
            } else {
                try stderr.writeAll("ryk allow-once: --scope must be cwd or project\n");
                return exit_codes.usage;
            }
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            try stdout.writeAll(usage_text);
            return exit_codes.success;
        } else {
            try stderr.print("ryk allow-once: unknown option '{s}'\n", .{arg});
            return exit_codes.usage;
        }
    }
    // M-1 redeem gate: fail closed unless on an interactive TTY.
    // - stdin TTY → interactive confirmation (unless -y)
    // - non-TTY → refuse (-y alone is not enough for agents/scripts; there is no
    //   env-var break-glass — RYK_OPERATOR was removed)
    if (!operatorRedeemAuthorized(io)) {
        try stderr.writeAll(
            \\ryk allow-once: redeem requires an interactive TTY (operator presence).
            \\Non-interactive / agent-driven redeem is refused; re-run in a terminal.
            \\
        );
        return exit_codes.usage;
    }
    if (!yes) {
        const accepted = interactive.askConfirmInteractive(
            io,
            stdout,
            "Redeem allow-once short code and grant a single-use shell exception?",
            false,
        ) catch |err| {
            try stderr.print("ryk allow-once: confirmation failed: {s}\n", .{@errorName(err)});
            return exit_codes.general;
        };
        if (!accepted) {
            try stdout.writeAll("canceled\n");
            return exit_codes.success;
        }
    }

    // Scope path: prefer the pending record's cwd (where the deny was issued) so redeem
    // works even when the operator is not sitting in that directory. Project scope uses
    // the workspace root enclosing the pending cwd (fall back to process cwd).
    const scope_path = try resolveRedeemScopePath(io, gpa, pending_path, code, now_iso, scope_kind);
    defer gpa.free(scope_path);

    const entry = allow_once_store.redeem(
        io,
        gpa,
        pending_path,
        once_path,
        code,
        now_iso,
        scope_kind,
        scope_path,
    ) catch |err| {
        return writeRedeemError(stderr, err);
    };
    defer allow_once_store.freeAllowOnceEntry(gpa, entry);

    if (as_json) {
        const cmd_j = try jsonStringAlloc(gpa, entry.command_raw);
        defer gpa.free(cmd_j);
        const path_j = try jsonStringAlloc(gpa, entry.scope_path);
        defer gpa.free(path_j);
        try stdout.print(
            \\{{"schema_version":{d},"code_hash":"{s}","command":{s},"scope_kind":"{s}","scope_path":{s},"expires_at":"{s}","single_use":{s}}}
            \\
        ,
            .{
                allow_once_store.schema_version,
                entry.source_code_hash,
                cmd_j,
                @tagName(entry.scope_kind),
                path_j,
                entry.expires_at,
                if (entry.single_use) "true" else "false",
            },
        );
    } else {
        try stdout.print(
            "Allowed once for exact command (scope={s}):\n  {s}\n",
            .{ @tagName(scope_kind), entry.command_raw },
        );
        try stdout.writeAll("If you will need this often, add a permanent allowlist entry:\n");
        try stdout.writeAll("  ryk allowlist add-command \"<command>\" -r \"reason\"\n");
    }

    return exit_codes.success;
}

fn writeRedeemError(stderr: anytype, err: anyerror) !u8 {
    switch (err) {
        error.CodeNotFound => {
            try stderr.writeAll("ryk allow-once: code not found (not issued, already redeemed, or revoked)\n");
            return exit_codes.general;
        },
        error.Expired => {
            try stderr.writeAll("ryk allow-once: code expired — re-run the command to get a new code\n");
            return exit_codes.general;
        },
        error.AlreadyConsumed => {
            try stderr.writeAll("ryk allow-once: code already consumed\n");
            return exit_codes.general;
        },
        error.AmbiguousCode => {
            try stderr.writeAll("ryk allow-once: ambiguous short code — re-issue after clear/revoke of the pending store\n");
            return exit_codes.general;
        },
        error.StoreFull => {
            try stderr.writeAll("ryk allow-once: pending store full — run: ryk allow-once clear pending\n");
            return exit_codes.general;
        },
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            try stderr.print("ryk allow-once: redeem failed ({s})\n", .{@errorName(err)});
            return exit_codes.general;
        },
    }
}

fn cmdList(
    io: std.Io,
    gpa: std.mem.Allocator,
    once_path: []const u8,
    now_iso: []const u8,
    argv: []const []const u8,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    var as_json = false;
    for (argv) |arg| {
        if (std.mem.eql(u8, arg, "--json")) {
            as_json = true;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            try stdout.writeAll(usage_text);
            return exit_codes.success;
        } else {
            try stderr.print("ryk allow-once list: unknown option '{s}'\n", .{arg});
            return exit_codes.usage;
        }
    }

    var loaded = try allow_once_store.loadAllowOnceActive(io, gpa, once_path, now_iso);
    defer loaded.deinit(gpa);

    if (as_json) {
        try stdout.writeAll("{\"schema_version\":");
        try stdout.print("{d}", .{allow_once_store.schema_version});
        try stdout.writeAll(",\"entries\":[");
        for (loaded.list.entries, 0..) |e, idx| {
            if (idx > 0) try stdout.writeAll(",");
            const cmd_j = try jsonStringAlloc(gpa, e.command_raw);
            defer gpa.free(cmd_j);
            const path_j = try jsonStringAlloc(gpa, e.scope_path);
            defer gpa.free(path_j);
            const reason_j = try jsonStringAlloc(gpa, e.reason);
            defer gpa.free(reason_j);
            try stdout.print(
                \\{{"code_hash":"{s}","command":{s},"scope_kind":"{s}","scope_path":{s},"expires_at":"{s}","single_use":{s},"reason":{s}}}
            ,
                .{
                    e.source_code_hash,
                    cmd_j,
                    @tagName(e.scope_kind),
                    path_j,
                    e.expires_at,
                    if (e.single_use) "true" else "false",
                    reason_j,
                },
            );
        }
        try stdout.writeAll("]}\n");
        return exit_codes.success;
    }

    if (loaded.list.entries.len == 0) {
        try stdout.writeAll("No active allow-once grants.\n");
        return exit_codes.success;
    }
    try stdout.print("Active allow-once grants ({d}):\n", .{loaded.list.entries.len});
    for (loaded.list.entries) |e| {
        try stdout.print(
            "  {s}  scope={s}  expires={s}\n    {s}\n",
            .{ e.source_code_hash, @tagName(e.scope_kind), e.expires_at, e.command_raw },
        );
    }
    return exit_codes.success;
}

fn cmdClear(
    io: std.Io,
    gpa: std.mem.Allocator,
    pending_path: []const u8,
    once_path: []const u8,
    now_iso: []const u8,
    argv: []const []const u8,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    var target: enum { pending, active, all } = .all;
    if (argv.len > 0) {
        if (std.mem.eql(u8, argv[0], "pending")) {
            target = .pending;
        } else if (std.mem.eql(u8, argv[0], "active")) {
            target = .active;
        } else if (std.mem.eql(u8, argv[0], "all")) {
            target = .all;
        } else if (std.mem.eql(u8, argv[0], "--help") or std.mem.eql(u8, argv[0], "-h")) {
            try stdout.writeAll(usage_text);
            return exit_codes.success;
        } else {
            try stderr.print("ryk allow-once clear: unknown target '{s}' (pending|active|all)\n", .{argv[0]});
            return exit_codes.usage;
        }
    }

    var removed_pending: usize = 0;
    var removed_active: usize = 0;
    if (target == .pending or target == .all) {
        const r = try allow_once_store.clearPending(io, gpa, pending_path, now_iso);
        removed_pending = r.removed;
    }
    if (target == .active or target == .all) {
        const r = try allow_once_store.clearAllowOnce(io, gpa, once_path, now_iso);
        removed_active = r.removed;
    }
    try stdout.print(
        "Cleared allow-once stores (pending={d}, active={d}).\n",
        .{ removed_pending, removed_active },
    );
    return exit_codes.success;
}

fn cmdRevoke(
    io: std.Io,
    gpa: std.mem.Allocator,
    pending_path: []const u8,
    once_path: []const u8,
    now_iso: []const u8,
    argv: []const []const u8,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    if (argv.len == 0) {
        try stderr.writeAll("ryk allow-once revoke: missing <code|hash>\n");
        return exit_codes.usage;
    }
    const key = argv[0];
    const rp = try allow_once_store.revokePending(io, gpa, pending_path, key, now_iso);
    const ra = try allow_once_store.revokeAllowOnce(io, gpa, once_path, key, now_iso);
    const total = rp.removed + ra.removed;
    if (total == 0) {
        try stderr.writeAll("ryk allow-once: nothing revoked (code/hash not found)\n");
        return exit_codes.general;
    }
    try stdout.print("Revoked {d} record(s) (pending={d}, active={d}).\n", .{ total, rp.removed, ra.removed });
    return exit_codes.success;
}

fn resolveScopePath(io: std.Io, gpa: std.mem.Allocator, scope_kind: allow_once_store.ScopeKind) ![]u8 {
    const cwd_z = try std.Io.Dir.cwd().realPathFileAlloc(io, ".", gpa);
    defer gpa.free(cwd_z);
    const cwd = try gpa.dupe(u8, cwd_z);
    errdefer gpa.free(cwd);

    return switch (scope_kind) {
        .cwd => cwd,
        .project => blk: {
            const root = core.supervisor.resolveWorkspaceRoot(io, gpa, null, cwd) catch {
                break :blk cwd;
            };
            gpa.free(cwd);
            break :blk root;
        },
    };
}

/// True when pending.cwd is unusable as an exact evaluate scope (null-cwd legacy / bare ".").
fn pendingCwdIsInert(cwd: []const u8) bool {
    const t = std.mem.trim(u8, cwd, " \t\r\n");
    return t.len == 0 or std.mem.eql(u8, t, ".");
}

/// Resolve redeem scope from the pending row when present so grants match the deny site.
/// Legacy pending rows with empty/"." cwd (pre-fix PermissionRequest path) upgrade to
/// process realpath / workspace root so redeem is not a false success.
fn resolveRedeemScopePath(
    io: std.Io,
    gpa: std.mem.Allocator,
    pending_path: []const u8,
    code: []const u8,
    now_iso: []const u8,
    scope_kind: allow_once_store.ScopeKind,
) ![]u8 {
    var looked = allow_once_store.lookupPendingByCode(io, gpa, pending_path, code, now_iso) catch {
        return resolveScopePath(io, gpa, scope_kind);
    };
    defer looked.deinit(gpa);

    if (looked.list.records.len == 0) {
        return resolveScopePath(io, gpa, scope_kind);
    }
    const pending_cwd = looked.list.records[0].cwd;

    // Inert pending cwd never matches absolute evaluate cwd — re-resolve like fresh issue.
    if (pendingCwdIsInert(pending_cwd)) {
        return resolveScopePath(io, gpa, scope_kind);
    }

    return switch (scope_kind) {
        .cwd => blk: {
            // Prefer realpath so grant scope matches hosts that realpath evaluate cwd.
            // realPathFileAlloc returns [:0]u8 — free sentinel slice, dupe plain []u8.
            if (std.Io.Dir.cwd().realPathFileAlloc(io, pending_cwd, gpa)) |rp_z| {
                defer gpa.free(rp_z);
                break :blk try gpa.dupe(u8, rp_z);
            } else |_| {
                break :blk try gpa.dupe(u8, pending_cwd);
            }
        },
        .project => blk: {
            const root = core.supervisor.resolveWorkspaceRoot(io, gpa, null, pending_cwd) catch {
                break :blk try gpa.dupe(u8, pending_cwd);
            };
            break :blk root;
        },
    };
}

fn isSixDigitCode(s: []const u8) bool {
    if (s.len != 6) return false;
    for (s) |c| {
        if (c < '0' or c > '9') return false;
    }
    return true;
}

fn looksLikeHash(s: []const u8) bool {
    if (s.len < 16) return false;
    for (s) |c| {
        const is_hex = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
        if (!is_hex) return false;
    }
    return true;
}

/// JSON-encode a string (with surrounding quotes). Caller frees.
fn jsonStringAlloc(gpa: std.mem.Allocator, s: []const u8) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(gpa);
    errdefer aw.deinit();
    try core.util.writeJsonString(&aw.writer, s);
    return try aw.toOwnedSlice();
}

// ---------------------------------------------------------------------------
// Test helpers (XDG isolation; no product side effects on the host)
// ---------------------------------------------------------------------------

const s_once_cli_now = "2026-07-25T12:00:00Z";
const s_once_cli_far_expiry = "9999-01-01T00:00:00Z";

extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;
extern "c" fn unsetenv(name: [*:0]const u8) c_int;

fn sOnceCliDupEnvZ(name: [*:0]const u8) !?[:0]u8 {
    if (std.c.getenv(name)) |value| {
        return try std.testing.allocator.dupeZ(u8, std.mem.span(value));
    }
    return null;
}

fn sOnceCliRestoreEnv(name: [*:0]const u8, prev: ?[:0]u8) void {
    if (prev) |value| {
        _ = setenv(name, value.ptr, 1);
        std.testing.allocator.free(value);
    } else {
        _ = unsetenv(name);
    }
}

fn sOnceCliJoin(parts: []const []const u8) ![]u8 {
    return try std.fs.path.join(std.testing.allocator, parts);
}

const SOnceCliEnv = struct {
    data_tmp: std.testing.TmpDir,
    data_root: []u8,
    prev_data: ?[:0]u8,
    prev_home: ?[:0]u8,

    fn deinit(self: *@This()) void {
        sOnceCliRestoreEnv("XDG_DATA_HOME", self.prev_data);
        sOnceCliRestoreEnv("HOME", self.prev_home);
        // Always clear the TTY test seam so tests cannot leak operator presence.
        test_operator_tty_override = null;
        std.testing.allocator.free(self.data_root);
        self.data_tmp.cleanup();
    }
};

/// Isolate allow-once JSONL under a temp `$XDG_DATA_HOME` (and pin HOME away from host).
/// Redeem authorization is TTY-only; tests opt into operator presence explicitly via
/// `sOnceCliSimulateOperatorTty` (the RYK_OPERATOR env break-glass was removed).
fn sOnceCliIsolateXdg() !SOnceCliEnv {
    var data_tmp = std.testing.tmpDir(.{});
    errdefer data_tmp.cleanup();

    const data_z = try data_tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(data_z);
    const data_root = try std.testing.allocator.dupe(u8, data_z);
    errdefer std.testing.allocator.free(data_root);

    const prev_data = try sOnceCliDupEnvZ("XDG_DATA_HOME");
    errdefer if (prev_data) |p| std.testing.allocator.free(p);
    const prev_home = try sOnceCliDupEnvZ("HOME");
    errdefer if (prev_home) |p| std.testing.allocator.free(p);

    const data_z0 = try std.testing.allocator.dupeZ(u8, data_root);
    defer std.testing.allocator.free(data_z0);
    try std.testing.expectEqual(@as(c_int, 0), setenv("XDG_DATA_HOME", data_z0.ptr, 1));
    // Pin HOME so fallback `~/.local/share/ryk` never touches the host home.
    try std.testing.expectEqual(@as(c_int, 0), setenv("HOME", data_z0.ptr, 1));

    return .{
        .data_tmp = data_tmp,
        .data_root = data_root,
        .prev_data = prev_data,
        .prev_home = prev_home,
    };
}

/// Simulate an interactive operator TTY for the redeem gate (test seam).
fn sOnceCliSimulateOperatorTty() void {
    test_operator_tty_override = true;
}

const SOnceCliWorkspace = struct {
    tmp: std.testing.TmpDir,
    root: []u8,

    fn deinit(self: *@This()) void {
        std.testing.allocator.free(self.root);
        self.tmp.cleanup();
    }
};

fn sOnceCliWorkspace() !SOnceCliWorkspace {
    var tmp = std.testing.tmpDir(.{});
    errdefer tmp.cleanup();
    // Product loaders (test/explain) resolve workspace root; a bare .git keeps that stable.
    try tmp.dir.createDirPath(std.testing.io, ".git");

    const root_z = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root_z);
    const root = try std.testing.allocator.dupe(u8, root_z);
    errdefer std.testing.allocator.free(root);

    return .{
        .tmp = tmp,
        .root = root,
    };
}

fn sOnceCliIsStubNotImplemented(stdout: []const u8, stderr: []const u8) bool {
    return std.mem.indexOf(u8, stderr, "not implemented") != null or
        std.mem.indexOf(u8, stdout, "not implemented") != null;
}

fn sOnceCliPendingPath(xdg_data: []const u8) ![]u8 {
    return try sOnceCliJoin(&.{ xdg_data, "ryk", allow_once_store.pending_file_name });
}

fn sOnceCliAllowOncePath(xdg_data: []const u8) ![]u8 {
    return try sOnceCliJoin(&.{ xdg_data, "ryk", allow_once_store.allow_once_file_name });
}

fn sOnceCliEnsureRykDataDir(xdg_data: []const u8) !void {
    const ryk_dir = try sOnceCliJoin(&.{ xdg_data, "ryk"});
    defer std.testing.allocator.free(ryk_dir);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, ryk_dir);
}

fn sOnceCliExpectNoDaemonText(text: []const u8) !void {
    try std.testing.expect(std.mem.indexOf(u8, text, "daemon") == null);
    try std.testing.expect(std.mem.indexOf(u8, text, "not yet ported") == null);
    try std.testing.expect(std.mem.indexOf(u8, text, "executeDaemonCli") == null);
}

/// First 6-digit short code after `allow-once ` (or standalone 6 digits if marked).
fn sOnceCliExtractShortCode(blob: []const u8) ?[]const u8 {
    const markers = [_][]const u8{ "allow-once ", "allow-once\t", "code ", "code=", "code: " };
    for (markers) |marker| {
        var search_from: usize = 0;
        while (search_from < blob.len) {
            const rel = std.mem.indexOf(u8, blob[search_from..], marker) orelse break;
            const start = search_from + rel + marker.len;
            if (start + 6 > blob.len) break;
            var ok = true;
            for (blob[start .. start + 6]) |c| {
                if (c < '0' or c > '9') {
                    ok = false;
                    break;
                }
            }
            if (ok) {
                // Reject 7+ digit runs so we do not slice mid-number.
                if (start + 6 == blob.len or blob[start + 6] < '0' or blob[start + 6] > '9') {
                    return blob[start .. start + 6];
                }
            }
            search_from = start + 1;
        }
    }
    return null;
}

fn sOnceCliRun(argv: []const []const u8) !struct { code: u8, stdout: []u8, stderr: []u8 } {
    var stdout_alloc: std.Io.Writer.Allocating = .init(std.testing.allocator);
    errdefer stdout_alloc.deinit();
    var stderr_alloc: std.Io.Writer.Allocating = .init(std.testing.allocator);
    errdefer stderr_alloc.deinit();
    const code = try commandAt(std.testing.io, argv, s_once_cli_now, &stdout_alloc.writer, &stderr_alloc.writer);
    return .{
        .code = code,
        .stdout = try stdout_alloc.toOwnedSlice(),
        .stderr = try stderr_alloc.toOwnedSlice(),
    };
}

fn sOnceCliFreeRun(result: anytype) void {
    std.testing.allocator.free(result.stdout);
    std.testing.allocator.free(result.stderr);
}

/// Seed a pending exception via the store API (hook path tested separately).
fn sOnceCliIssuePending(
    xdg_data: []const u8,
    command_text: []const u8,
    cwd: []const u8,
    reason: []const u8,
) !allow_once_store.PendingIssue {
    try sOnceCliEnsureRykDataDir(xdg_data);
    const pending_path = try sOnceCliPendingPath(xdg_data);
    defer std.testing.allocator.free(pending_path);
    return try allow_once_store.issuePending(
        std.testing.io,
        std.testing.allocator,
        pending_path,
        command_text,
        cwd,
        reason,
        s_once_cli_now,
        true,
    );
}

fn sOnceCliHelpListsPeer(text: []const u8, name: []const u8) bool {
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
// Acceptance 1 — redeem / list / clear / revoke CLI (no daemon)
// ---------------------------------------------------------------------------

test "s-once-cli: help and missing args are usage-safe without daemon" {
    {
        const run = try sOnceCliRun(&.{"--help"});
        defer sOnceCliFreeRun(run);
        try std.testing.expect(!sOnceCliIsStubNotImplemented(run.stdout, run.stderr));
        try std.testing.expectEqual(exit_codes.success, run.code);
        try sOnceCliExpectNoDaemonText(run.stdout);
        try sOnceCliExpectNoDaemonText(run.stderr);
        try std.testing.expect(std.mem.indexOf(u8, run.stdout, "allow-once") != null or
            std.mem.indexOf(u8, run.stdout, "Usage") != null or
            std.mem.indexOf(u8, run.stdout, "usage") != null);
        // Operator-bound redeem documented on help (TTY-only; no env break-glass).
        try std.testing.expect(std.mem.indexOf(u8, run.stdout, "TTY") != null or
            std.mem.indexOf(u8, run.stdout, "operator") != null);
    }
    {
        const run = try sOnceCliRun(&.{});
        defer sOnceCliFreeRun(run);
        try std.testing.expect(!sOnceCliIsStubNotImplemented(run.stdout, run.stderr));
        try std.testing.expectEqual(exit_codes.usage, run.code);
        try sOnceCliExpectNoDaemonText(run.stdout);
        try sOnceCliExpectNoDaemonText(run.stderr);
    }
}

test "s-once-cli: non-TTY redeem fails closed even with RYK_OPERATOR set" {
    // M-1 / P0-3: -y alone must not authorize silent agent redeem on non-TTY, and
    // the removed RYK_OPERATOR env var must never authorize anything. Set it to
    // prove it is ignored; the TTY seam stays unset (non-TTY).
    var xdg = try sOnceCliIsolateXdg();
    defer xdg.deinit();
    var ws = try sOnceCliWorkspace();
    defer ws.deinit();

    // Explicitly set the removed var — it must have no effect.
    try std.testing.expectEqual(@as(c_int, 0), setenv("RYK_OPERATOR", "1", 1));
    defer _ = unsetenv("RYK_OPERATOR");
    test_operator_tty_override = false; // explicit non-TTY

    const cmd_text = "git reset --hard";
    var issued = try sOnceCliIssuePending(xdg.data_root, cmd_text, ws.root, "m1 silent redeem gate");
    defer issued.deinit(std.testing.allocator);
    const code = issued.redeem_code;

    const run = try sOnceCliRun(&.{ code, "-y" });
    defer sOnceCliFreeRun(run);
    try std.testing.expect(run.code != exit_codes.success);
    try std.testing.expect(std.mem.indexOf(u8, run.stderr, "TTY") != null or
        std.mem.indexOf(u8, run.stderr, "operator") != null or
        std.mem.indexOf(u8, run.stderr, "terminal") != null);

    // Pending must remain unredeemed (gate is before store mutate).
    const pending_path = try sOnceCliPendingPath(xdg.data_root);
    defer std.testing.allocator.free(pending_path);
    var loaded = try allow_once_store.loadPendingActive(
        std.testing.io,
        std.testing.allocator,
        pending_path,
        s_once_cli_now,
    );
    defer loaded.deinit(std.testing.allocator);
    try std.testing.expect(loaded.list.records.len >= 1);
}

test "s-once-cli: redeem pending code writes allow_once.jsonl and burns pending" {
    var xdg = try sOnceCliIsolateXdg();
    defer xdg.deinit();
    var ws = try sOnceCliWorkspace();
    defer ws.deinit();

    sOnceCliSimulateOperatorTty();
    const cmd_text = "git reset --hard";
    const reason = "s-once-cli redeem burn-pending marker";
    var issued = try sOnceCliIssuePending(xdg.data_root, cmd_text, ws.root, reason);
    defer issued.deinit(std.testing.allocator);
    const code = issued.redeem_code;

    const run = try sOnceCliRun(&.{ code, "-y" });
    defer sOnceCliFreeRun(run);
    try std.testing.expect(!sOnceCliIsStubNotImplemented(run.stdout, run.stderr));
    try std.testing.expectEqual(exit_codes.success, run.code);
    try sOnceCliExpectNoDaemonText(run.stdout);
    try sOnceCliExpectNoDaemonText(run.stderr);
    // Success copy: one line suggesting permanent allowlist for frequent use.
    const blob = if (run.stdout.len > 0) run.stdout else run.stderr;
    try std.testing.expect(std.mem.indexOf(u8, blob, "allowlist") != null or
        std.mem.indexOf(u8, blob, "permanent") != null or
        std.mem.indexOf(u8, blob, "allow ") != null);

    const pending_path = try sOnceCliPendingPath(xdg.data_root);
    defer std.testing.allocator.free(pending_path);
    const once_path = try sOnceCliAllowOncePath(xdg.data_root);
    defer std.testing.allocator.free(once_path);

    // Pending code burned — second redeem must fail.
    {
        const again = try sOnceCliRun(&.{ code, "-y" });
        defer sOnceCliFreeRun(again);
        try std.testing.expect(!sOnceCliIsStubNotImplemented(again.stdout, again.stderr));
        try std.testing.expect(again.code != exit_codes.success);
    }

    // Active grant present for exact command + cwd scope.
    var active = try allow_once_store.loadAllowOnceActive(
        std.testing.io,
        std.testing.allocator,
        once_path,
        s_once_cli_now,
    );
    defer active.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), active.list.entries.len);
    try std.testing.expectEqualStrings(cmd_text, active.list.entries[0].command_raw);
}

test "s-once-cli: redeem then evaluate allows once; second evaluate denies" {
    // Acceptance: Deny → code → redeem → evaluate allows once → second denies.
    // CLI redeem + engine evaluate (product loaders honor the same store path).
    var xdg = try sOnceCliIsolateXdg();
    defer xdg.deinit();
    var ws = try sOnceCliWorkspace();
    defer ws.deinit();

    sOnceCliSimulateOperatorTty();
    const cmd_text = "git reset --hard";
    var issued = try sOnceCliIssuePending(
        xdg.data_root,
        cmd_text,
        ws.root,
        "s-once-cli e2e allow-once consume chain",
    );
    defer issued.deinit(std.testing.allocator);

    {
        const run = try sOnceCliRun(&.{ issued.redeem_code, "-y" });
        defer sOnceCliFreeRun(run);
        try std.testing.expect(!sOnceCliIsStubNotImplemented(run.stdout, run.stderr));
        try std.testing.expectEqual(exit_codes.success, run.code);
    }

    const once_path = try sOnceCliAllowOncePath(xdg.data_root);
    defer std.testing.allocator.free(once_path);

    {
        var first = try shell_engine.evaluateCommand(std.testing.allocator, cmd_text, .{
            .cwd = ws.root,
            .allow_once_path = once_path,
            .io = std.testing.io,
            .now_iso = s_once_cli_now,
            .consume_allow_once = true,
        });
        defer first.deinit(std.testing.allocator);
        try std.testing.expect(first.decision == .allow);
        try std.testing.expectEqualStrings("allow_once", first.exception_source.?);
    }

    {
        var second = try shell_engine.evaluateCommand(std.testing.allocator, cmd_text, .{
            .cwd = ws.root,
            .allow_once_path = once_path,
            .io = std.testing.io,
            .now_iso = s_once_cli_now,
            .consume_allow_once = true,
        });
        defer second.deinit(std.testing.allocator);
        try std.testing.expect(second.decision == .deny);
        try std.testing.expect(second.exception_source == null);
    }
}

test "s-once-cli: redeem then explain non-consume still allows once; third evaluate denies" {
    // Acceptance: Redeem → explain attributes without consuming → next evaluate allows
    // once → third denies. Explain uses consume_allow_once=false (engine contract).
    var xdg = try sOnceCliIsolateXdg();
    defer xdg.deinit();
    var ws = try sOnceCliWorkspace();
    defer ws.deinit();

    sOnceCliSimulateOperatorTty();
    const cmd_text = "git reset --hard";
    const reason = "s-once-cli explain non-consume attribution marker";
    var issued = try sOnceCliIssuePending(xdg.data_root, cmd_text, ws.root, reason);
    defer issued.deinit(std.testing.allocator);

    {
        const run = try sOnceCliRun(&.{ issued.redeem_code, "-y" });
        defer sOnceCliFreeRun(run);
        try std.testing.expect(!sOnceCliIsStubNotImplemented(run.stdout, run.stderr));
        try std.testing.expectEqual(exit_codes.success, run.code);
    }

    const once_path = try sOnceCliAllowOncePath(xdg.data_root);
    defer std.testing.allocator.free(once_path);

    // Explain / dry-run: match + attribute, leave store intact.
    {
        var explain = try shell_engine.evaluateCommand(std.testing.allocator, cmd_text, .{
            .cwd = ws.root,
            .allow_once_path = once_path,
            .io = std.testing.io,
            .now_iso = s_once_cli_now,
            .consume_allow_once = false,
        });
        defer explain.deinit(std.testing.allocator);
        try std.testing.expect(explain.decision == .allow);
        try std.testing.expectEqualStrings("allow_once", explain.exception_source.?);
        // Attribution must name allow-once (or carry the pending reason) — bare "allow" is too soft.
        try std.testing.expect(std.mem.indexOf(u8, explain.reason, reason) != null or
            std.mem.indexOf(u8, explain.reason, "allow_once") != null or
            std.mem.indexOf(u8, explain.reason, "allow-once") != null);
    }

    // Live evaluate still allows once (consume burns).
    {
        var live = try shell_engine.evaluateCommand(std.testing.allocator, cmd_text, .{
            .cwd = ws.root,
            .allow_once_path = once_path,
            .io = std.testing.io,
            .now_iso = s_once_cli_now,
            .consume_allow_once = true,
        });
        defer live.deinit(std.testing.allocator);
        try std.testing.expect(live.decision == .allow);
        try std.testing.expectEqualStrings("allow_once", live.exception_source.?);
    }

    // Third evaluate denies (single-use burned).
    {
        var third = try shell_engine.evaluateCommand(std.testing.allocator, cmd_text, .{
            .cwd = ws.root,
            .allow_once_path = once_path,
            .io = std.testing.io,
            .now_iso = s_once_cli_now,
            .consume_allow_once = true,
        });
        defer third.deinit(std.testing.allocator);
        try std.testing.expect(third.decision == .deny);
        try std.testing.expect(third.exception_source == null);
    }
}

test "s-once-cli: list shows redeemed grant; --json is parseable" {
    var xdg = try sOnceCliIsolateXdg();
    defer xdg.deinit();
    var ws = try sOnceCliWorkspace();
    defer ws.deinit();

    sOnceCliSimulateOperatorTty();
    const cmd_text = "git reset --hard";
    const reason = "s-once-cli list surface marker";
    var issued = try sOnceCliIssuePending(xdg.data_root, cmd_text, ws.root, reason);
    defer issued.deinit(std.testing.allocator);
    const code = issued.redeem_code;
    {
        const run = try sOnceCliRun(&.{ code, "-y" });
        defer sOnceCliFreeRun(run);
        try std.testing.expectEqual(exit_codes.success, run.code);
    }

    {
        const list = try sOnceCliRun(&.{"list"});
        defer sOnceCliFreeRun(list);
        try std.testing.expect(!sOnceCliIsStubNotImplemented(list.stdout, list.stderr));
        try std.testing.expectEqual(exit_codes.success, list.code);
        try sOnceCliExpectNoDaemonText(list.stdout);
        try std.testing.expect(std.mem.indexOf(u8, list.stdout, cmd_text) != null);
    }

    {
        const list_json = try sOnceCliRun(&.{ "list", "--json" });
        defer sOnceCliFreeRun(list_json);
        try std.testing.expect(!sOnceCliIsStubNotImplemented(list_json.stdout, list_json.stderr));
        try std.testing.expectEqual(exit_codes.success, list_json.code);
        try sOnceCliExpectNoDaemonText(list_json.stdout);
        // Must encode the redeemed grant, not a hollow `{}` / empty array greening.
        try std.testing.expect(std.mem.indexOf(u8, list_json.stdout, cmd_text) != null);
        try std.testing.expect(std.mem.indexOf(u8, list_json.stdout, "code_hash") != null or
            std.mem.indexOf(u8, list_json.stdout, "schema_version") != null);
        const trimmed = std.mem.trim(u8, list_json.stdout, " \t\r\n");
        try std.testing.expect(trimmed.len > 0);
        try std.testing.expect(trimmed[0] == '{' or trimmed[0] == '[');
        var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, trimmed, .{});
        defer parsed.deinit();
    }
}

test "s-once-cli: revoke by short code removes grant so evaluate denies" {
    var xdg = try sOnceCliIsolateXdg();
    defer xdg.deinit();
    var ws = try sOnceCliWorkspace();
    defer ws.deinit();

    sOnceCliSimulateOperatorTty();
    const cmd_text = "git reset --hard";
    var issued = try sOnceCliIssuePending(xdg.data_root, cmd_text, ws.root, "revoke target");
    defer issued.deinit(std.testing.allocator);
    const code = issued.redeem_code;
    {
        const run = try sOnceCliRun(&.{ code, "-y" });
        defer sOnceCliFreeRun(run);
        try std.testing.expectEqual(exit_codes.success, run.code);
    }

    {
        const rev = try sOnceCliRun(&.{ "revoke", code });
        defer sOnceCliFreeRun(rev);
        try std.testing.expect(!sOnceCliIsStubNotImplemented(rev.stdout, rev.stderr));
        try std.testing.expectEqual(exit_codes.success, rev.code);
        try sOnceCliExpectNoDaemonText(rev.stdout);
        try sOnceCliExpectNoDaemonText(rev.stderr);
    }

    const once_path = try sOnceCliAllowOncePath(xdg.data_root);
    defer std.testing.allocator.free(once_path);
    var eval = try shell_engine.evaluateCommand(std.testing.allocator, cmd_text, .{
        .cwd = ws.root,
        .allow_once_path = once_path,
        .io = std.testing.io,
        .now_iso = s_once_cli_now,
        .consume_allow_once = true,
    });
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .deny);
}

test "s-once-cli: clear empties active grants" {
    var xdg = try sOnceCliIsolateXdg();
    defer xdg.deinit();
    var ws = try sOnceCliWorkspace();
    defer ws.deinit();

    sOnceCliSimulateOperatorTty();
    const cmd_text = "git reset --hard";
    var issued = try sOnceCliIssuePending(xdg.data_root, cmd_text, ws.root, "clear target");
    defer issued.deinit(std.testing.allocator);
    {
        const run = try sOnceCliRun(&.{ issued.redeem_code, "-y" });
        defer sOnceCliFreeRun(run);
        try std.testing.expectEqual(exit_codes.success, run.code);
    }

    {
        const clr = try sOnceCliRun(&.{"clear"});
        defer sOnceCliFreeRun(clr);
        try std.testing.expect(!sOnceCliIsStubNotImplemented(clr.stdout, clr.stderr));
        try std.testing.expectEqual(exit_codes.success, clr.code);
        try sOnceCliExpectNoDaemonText(clr.stdout);
        try sOnceCliExpectNoDaemonText(clr.stderr);
    }

    const once_path = try sOnceCliAllowOncePath(xdg.data_root);
    defer std.testing.allocator.free(once_path);
    var active = try allow_once_store.loadAllowOnceActive(
        std.testing.io,
        std.testing.allocator,
        once_path,
        s_once_cli_now,
    );
    defer active.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), active.list.entries.len);
}

test "s-once-cli: redeem unknown code is non-success with clear error" {
    var xdg = try sOnceCliIsolateXdg();
    defer xdg.deinit();
    var ws = try sOnceCliWorkspace();
    defer ws.deinit();

    // Operator TTY so the redeem gate passes and we reach the store lookup.
    sOnceCliSimulateOperatorTty();
    const run = try sOnceCliRun(&.{ "000000", "-y" });
    defer sOnceCliFreeRun(run);
    try std.testing.expect(!sOnceCliIsStubNotImplemented(run.stdout, run.stderr));
    try std.testing.expect(run.code != exit_codes.success);
    const blob = if (run.stderr.len > 0) run.stderr else run.stdout;
    try std.testing.expect(std.mem.indexOf(u8, blob, "not found") != null or
        std.mem.indexOf(u8, blob, "Not found") != null or
        std.mem.indexOf(u8, blob, "unknown") != null or
        std.mem.indexOf(u8, blob, "expired") != null or
        std.mem.indexOf(u8, blob, "Code") != null);
}

test "s-once-cli: redeem --json emits machine-readable success" {
    var xdg = try sOnceCliIsolateXdg();
    defer xdg.deinit();
    var ws = try sOnceCliWorkspace();
    defer ws.deinit();

    sOnceCliSimulateOperatorTty();
    const cmd_text = "git reset --hard";
    var issued = try sOnceCliIssuePending(
        xdg.data_root,
        cmd_text,
        ws.root,
        "json redeem marker",
    );
    defer issued.deinit(std.testing.allocator);
    const code = issued.redeem_code;

    const run = try sOnceCliRun(&.{ code, "-y", "--json" });
    defer sOnceCliFreeRun(run);
    try std.testing.expect(!sOnceCliIsStubNotImplemented(run.stdout, run.stderr));
    try std.testing.expectEqual(exit_codes.success, run.code);
    const trimmed = std.mem.trim(u8, run.stdout, " \t\r\n");
    try std.testing.expect(trimmed.len > 0 and trimmed[0] == '{');
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, trimmed, .{});
    defer parsed.deinit();
    // Flat `{}` must not green: encode grant identity (command and/or code_hash).
    try std.testing.expect(std.mem.indexOf(u8, run.stdout, cmd_text) != null or
        std.mem.indexOf(u8, run.stdout, issued.record.code_hash) != null);
    try std.testing.expect(std.mem.indexOf(u8, run.stdout, "command") != null or
        std.mem.indexOf(u8, run.stdout, "code_hash") != null or
        std.mem.indexOf(u8, run.stdout, "schema_version") != null);
}

test "s-once-cli: clear pending leaves active grants intact" {
    // Branch: `clear pending` must not wipe redeemed allow-once rows.
    var xdg = try sOnceCliIsolateXdg();
    defer xdg.deinit();
    var ws = try sOnceCliWorkspace();
    defer ws.deinit();

    sOnceCliSimulateOperatorTty();
    const cmd_text = "git reset --hard";
    var issued = try sOnceCliIssuePending(xdg.data_root, cmd_text, ws.root, "clear pending only");
    defer issued.deinit(std.testing.allocator);
    {
        const run = try sOnceCliRun(&.{ issued.redeem_code, "-y" });
        defer sOnceCliFreeRun(run);
        try std.testing.expectEqual(exit_codes.success, run.code);
    }
    // Seed a second pending that stays unredeemed.
    var pending2 = try sOnceCliIssuePending(xdg.data_root, "rm -rf /tmp/s-once-clear-pending", ws.root, "still pending");
    defer pending2.deinit(std.testing.allocator);

    {
        const clr = try sOnceCliRun(&.{ "clear", "pending" });
        defer sOnceCliFreeRun(clr);
        try std.testing.expect(!sOnceCliIsStubNotImplemented(clr.stdout, clr.stderr));
        try std.testing.expectEqual(exit_codes.success, clr.code);
        try sOnceCliExpectNoDaemonText(clr.stdout);
        try sOnceCliExpectNoDaemonText(clr.stderr);
    }

    const pending_path = try sOnceCliPendingPath(xdg.data_root);
    defer std.testing.allocator.free(pending_path);
    const once_path = try sOnceCliAllowOncePath(xdg.data_root);
    defer std.testing.allocator.free(once_path);

    var pending_loaded = try allow_once_store.loadPendingActive(
        std.testing.io,
        std.testing.allocator,
        pending_path,
        s_once_cli_now,
    );
    defer pending_loaded.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), pending_loaded.list.records.len);

    var active = try allow_once_store.loadAllowOnceActive(
        std.testing.io,
        std.testing.allocator,
        once_path,
        s_once_cli_now,
    );
    defer active.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), active.list.entries.len);
    try std.testing.expectEqualStrings(cmd_text, active.list.entries[0].command_raw);
}

test "s-once-cli: revoke by full_hash removes grant" {
    var xdg = try sOnceCliIsolateXdg();
    defer xdg.deinit();
    var ws = try sOnceCliWorkspace();
    defer ws.deinit();

    sOnceCliSimulateOperatorTty();
    const cmd_text = "git reset --hard";
    var issued = try sOnceCliIssuePending(xdg.data_root, cmd_text, ws.root, "revoke by hash");
    defer issued.deinit(std.testing.allocator);
    const full_hash = try std.testing.allocator.dupe(u8, issued.record.full_hash);
    defer std.testing.allocator.free(full_hash);
    {
        const run = try sOnceCliRun(&.{ issued.redeem_code, "-y" });
        defer sOnceCliFreeRun(run);
        try std.testing.expectEqual(exit_codes.success, run.code);
    }

    {
        const rev = try sOnceCliRun(&.{ "revoke", full_hash });
        defer sOnceCliFreeRun(rev);
        try std.testing.expect(!sOnceCliIsStubNotImplemented(rev.stdout, rev.stderr));
        try std.testing.expectEqual(exit_codes.success, rev.code);
        try sOnceCliExpectNoDaemonText(rev.stdout);
        try sOnceCliExpectNoDaemonText(rev.stderr);
    }

    const once_path = try sOnceCliAllowOncePath(xdg.data_root);
    defer std.testing.allocator.free(once_path);
    var active = try allow_once_store.loadAllowOnceActive(
        std.testing.io,
        std.testing.allocator,
        once_path,
        s_once_cli_now,
    );
    defer active.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), active.list.entries.len);

    var eval = try shell_engine.evaluateCommand(std.testing.allocator, cmd_text, .{
        .cwd = ws.root,
        .allow_once_path = once_path,
        .io = std.testing.io,
        .now_iso = s_once_cli_now,
        .consume_allow_once = true,
    });
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .deny);
}

test "s-once-cli: redeem --scope project allows evaluate from subdirectory" {
    // Branch: project-scope redeem matches cwd under scope_path (not exact cwd only).
    var xdg = try sOnceCliIsolateXdg();
    defer xdg.deinit();
    var ws = try sOnceCliWorkspace();
    defer ws.deinit();

    sOnceCliSimulateOperatorTty();
    const cmd_text = "git reset --hard";
    var issued = try sOnceCliIssuePending(xdg.data_root, cmd_text, ws.root, "project scope redeem");
    defer issued.deinit(std.testing.allocator);

    {
        const run = try sOnceCliRun(&.{ issued.redeem_code, "-y", "--scope", "project" });
        defer sOnceCliFreeRun(run);
        try std.testing.expect(!sOnceCliIsStubNotImplemented(run.stdout, run.stderr));
        try std.testing.expectEqual(exit_codes.success, run.code);
        try sOnceCliExpectNoDaemonText(run.stdout);
        try sOnceCliExpectNoDaemonText(run.stderr);
    }

    const once_path = try sOnceCliAllowOncePath(xdg.data_root);
    defer std.testing.allocator.free(once_path);

    // Subdirectory under project root must match project-scope grant. Keep the
    // test process cwd untouched so unrelated CLI tests cannot inherit this
    // temporary workspace.
    const sub_cwd = try sOnceCliJoin(&.{ ws.root, "nested-sub" });
    defer std.testing.allocator.free(sub_cwd);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, sub_cwd);

    {
        var first = try shell_engine.evaluateCommand(std.testing.allocator, cmd_text, .{
            .cwd = sub_cwd,
            .allow_once_path = once_path,
            .io = std.testing.io,
            .now_iso = s_once_cli_now,
            .consume_allow_once = true,
        });
        defer first.deinit(std.testing.allocator);
        try std.testing.expect(first.decision == .allow);
        try std.testing.expectEqualStrings("allow_once", first.exception_source.?);
    }
    {
        var second = try shell_engine.evaluateCommand(std.testing.allocator, cmd_text, .{
            .cwd = sub_cwd,
            .allow_once_path = once_path,
            .io = std.testing.io,
            .now_iso = s_once_cli_now,
            .consume_allow_once = true,
        });
        defer second.deinit(std.testing.allocator);
        try std.testing.expect(second.decision == .deny);
    }
}

// ---------------------------------------------------------------------------
// Acceptance — help surfaces allow-once
// ---------------------------------------------------------------------------

test "s-once-cli: help exposes allow-once (not hidden)" {
    const info = help.findCommand("allow-once") orelse {
        std.debug.print("missing help entry for allow-once\n", .{});
        try std.testing.expect(false);
        return;
    };
    try std.testing.expect(!info.hidden);
    // Honesty: live surface must not advertise daemon proxy / not-yet-ported essay.
    try sOnceCliExpectNoDaemonText(info.summary);
    for (info.details) |line| {
        try sOnceCliExpectNoDaemonText(line);
    }
}

test "s-once-cli: root help --all lists allow-once as peer" {
    var buf: [32768]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try help.writeWithMode(std.testing.io, &writer, .all);
    const text = writer.buffered();
    try std.testing.expect(sOnceCliHelpListsPeer(text, "allow-once"));
    // Peer line for allow-once must not teach daemon proxy (other live verbs may mention daemon).
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (std.mem.indexOf(u8, line, "allow-once") == null) continue;
        try sOnceCliExpectNoDaemonText(line);
    }
}

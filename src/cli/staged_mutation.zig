//! Shared CLI path for `ryk apply` / `ryk discard`.
//! Mutation never happens without --dry-run exit, --yes, or interactive confirm (default No).

const std = @import("std");
const gpa_mod = @import("gpa.zig");
const core = @import("ryk_core").core;
const supervisor = core.supervisor;
const core_api = @import("ryk_core").api;
const intercept = @import("../intercept/mod.zig");
const exit_codes = @import("exit_codes.zig");
const help = @import("help.zig");
const suggestions = @import("suggestions.zig");
const interactive = @import("interactive.zig");

pub const Kind = enum {
    apply,
    discard,

    fn commandName(self: Kind) []const u8 {
        return switch (self) {
            .apply => "apply",
            .discard => "discard",
        };
    }

    fn auditCommand(self: Kind) []const u8 {
        return switch (self) {
            .apply => "ryk apply",
            .discard => "ryk discard",
        };
    }

    fn pastTense(self: Kind) []const u8 {
        return switch (self) {
            .apply => "Applied",
            .discard => "Discarded",
        };
    }

    fn wouldVerb(self: Kind) []const u8 {
        return switch (self) {
            .apply => "applied",
            .discard => "discarded",
        };
    }
};

pub const Options = struct {
    session: []const u8 = "last",
    file: ?[]const u8 = null,
    dry_run: bool = false,
    yes: bool = false,
};

pub fn command(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype, kind: Kind) !u8 {
    const options = parseOptions(io, argv, stdout, stderr, kind) catch |err| switch (err) {
        error.HelpShown => return exit_codes.success,
        error.Usage => return exit_codes.usage,
        else => return err,
    };

    const name = kind.commandName();
    const is_tty = std.Io.File.stdin().isTty(io) catch false;
    if (!options.dry_run and !options.yes and !is_tty) {
        try stderr.print(
            "ryk {s}: mutation requires --yes (or run interactively), or use --dry-run to preview.\n",
            .{name},
        );
        return exit_codes.usage;
    }

    var gpa_state: gpa_mod.State = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();

    const workspace_root = try supervisor.resolveWorkspaceRoot(io, allocator, null, ".");
    defer allocator.free(workspace_root);
    const session_id = intercept.files.resolveSessionId(io, allocator, workspace_root, options.session) catch |err| {
        try stderr.print("ryk {s}: failed to resolve session '{s}': {s}\n", .{ name, options.session, @errorName(err) });
        return exit_codes.general;
    };
    defer allocator.free(session_id);

    var preview = intercept.files.previewStaged(io, allocator, workspace_root, session_id, options.file) catch |err| {
        try stderr.print("ryk {s}: failed to list staged files: {s}\n", .{ name, @errorName(err) });
        return exit_codes.general;
    };
    defer preview.deinit();

    try writeSummary(stdout, kind, session_id, preview.summary);
    if (options.dry_run) {
        try stdout.writeAll("dry-run: no changes made.\n");
        return exit_codes.success;
    }

    if (!options.yes) {
        const prompt = switch (kind) {
            .apply => "Apply these staged changes?",
            .discard => "Discard these proposed staged changes? This cannot be undone.",
        };
        const accepted = interactive.askConfirmInteractive(io, stdout, prompt, false) catch |err| {
            try stderr.print("ryk {s}: confirmation failed: {s}\n", .{ name, @errorName(err) });
            return exit_codes.general;
        };
        if (!accepted) {
            try stdout.writeAll("canceled\n");
            return exit_codes.success;
        }
    }

    const audit_session = commandAuditSession(io, session_id, workspace_root, kind.auditCommand());
    var session_writer = core_api.openAuditWriter(io, allocator, workspace_root, session_id) catch |err| {
        try stderr.print("ryk {s}: failed to open session audit log: {s}\n", .{ name, @errorName(err) });
        return exit_codes.general;
    };
    defer session_writer.deinit();
    const audit_context: intercept.files.AuditContext = .{ .writer = &session_writer, .session = audit_session };

    const result = switch (kind) {
        .apply => intercept.files.applyStagedConfirmed(io, allocator, workspace_root, session_id, options.file, preview.fingerprint, audit_context),
        .discard => intercept.files.discardStagedConfirmed(io, allocator, workspace_root, session_id, options.file, preview.fingerprint, audit_context),
    } catch |err| {
        try stderr.print("ryk {s}: failed to {s} staged files: {s}\n", .{ name, name, @errorName(err) });
        return exit_codes.general;
    };
    if (session_writer.finalHash()) |hash| {
        try core_api.updateAuditSummaryFinalHash(allocator, session_writer.session_dir_path, session_writer.event_count, hash);
    }
    try stdout.print("{s} {d} staged file(s) from session {s}.\n", .{ kind.pastTense(), result.count, session_id });
    return exit_codes.success;
}

fn writeSummary(stdout: anytype, kind: Kind, session_id: []const u8, summary: intercept.files.StagedSummary) !void {
    try stdout.print("Session {s}: {d} staged file(s) would be {s}.\n", .{ session_id, summary.count, kind.wouldVerb() });
    if (kind == .discard) {
        try stdout.writeAll("This destroys proposed staged changes (workspace files are not modified).\n");
    }
    for (summary.paths) |path| {
        try stdout.print("  {s}\n", .{path});
    }
}

pub fn parseOptions(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype, kind: Kind) !Options {
    const name = kind.commandName();
    var options: Options = .{};
    var index: usize = 0;
    while (index < argv.len) : (index += 1) {
        const arg = argv[index];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            _ = try help.writeCommand(io, stdout, name);
            return error.HelpShown;
        } else if (std.mem.eql(u8, arg, "--session")) {
            index += 1;
            if (index >= argv.len) {
                try stderr.print("ryk {s}: --session requires an id or 'last'.\n", .{name});
                return error.Usage;
            }
            options.session = argv[index];
        } else if (std.mem.eql(u8, arg, "--file")) {
            index += 1;
            if (index >= argv.len) {
                try stderr.print("ryk {s}: --file requires a workspace path.\n", .{name});
                return error.Usage;
            }
            options.file = argv[index];
        } else if (std.mem.eql(u8, arg, "--dry-run")) {
            options.dry_run = true;
        } else if (std.mem.eql(u8, arg, "--yes")) {
            options.yes = true;
        } else {
            var prefix_buf: [32]u8 = undefined;
            const prefix = try std.fmt.bufPrint(&prefix_buf, "ryk {s}", .{name});
            try suggestions.writeUnknownOption(
                stderr,
                prefix,
                arg,
                &.{ "--session", "--file", "--dry-run", "--yes", "--help", "-h" },
                name,
            );
            return error.Usage;
        }
    }
    return options;
}

fn commandAuditSession(io: std.Io, session_id_text: []const u8, workspace_root: []const u8, command_name: []const u8) core.session.Session {
    var session_id: core.session.SessionId = .{ .value = undefined, .len = 0 };
    const len = @min(session_id_text.len, session_id.value.len);
    @memcpy(session_id.value[0..len], session_id_text[0..len]);
    session_id.len = len;
    return .{
        .id = session_id,
        .started_at = core.time.Timestamp.now(io),
        .command = command_name,
        .args = &.{},
        .workspace_root = workspace_root,
        .mode = .strict,
        .platform = core.platform.detectOs(),
    };
}

test "apply non-TTY without --yes fails closed" {
    var stdout_buf: [512]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, &.{}, &stdout_writer, &stderr_writer, .apply);
    try std.testing.expectEqual(exit_codes.usage, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "--yes") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "Applied") == null);
}

test "discard non-TTY without --yes fails closed" {
    var stdout_buf: [512]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, &.{}, &stdout_writer, &stderr_writer, .discard);
    try std.testing.expectEqual(exit_codes.usage, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "--yes") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "Discarded") == null);
}

test "apply --dry-run does not require --yes" {
    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, &.{"--dry-run"}, &stdout_writer, &stderr_writer, .apply);
    try std.testing.expect(code == exit_codes.success or code == exit_codes.general);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "Applied") == null);
    if (code == exit_codes.success) {
        try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "dry-run") != null);
    }
}

test "discard --dry-run warns destruction and does not mutate" {
    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, &.{"--dry-run"}, &stdout_writer, &stderr_writer, .discard);
    try std.testing.expect(code == exit_codes.success or code == exit_codes.general);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "Discarded") == null);
    if (code == exit_codes.success) {
        try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "dry-run") != null);
        try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "destroys proposed staged") != null);
    }
}

test "parseOptions accepts --yes and --dry-run for both kinds" {
    var stdout_buf: [64]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const apply_opts = try parseOptions(std.testing.io, &.{ "--dry-run", "--yes", "--session", "abc" }, &stdout_writer, &stderr_writer, .apply);
    try std.testing.expect(apply_opts.dry_run);
    try std.testing.expect(apply_opts.yes);
    try std.testing.expectEqualStrings("abc", apply_opts.session);

    const discard_opts = try parseOptions(std.testing.io, &.{ "--dry-run", "--yes", "--session", "xyz" }, &stdout_writer, &stderr_writer, .discard);
    try std.testing.expect(discard_opts.dry_run);
    try std.testing.expect(discard_opts.yes);
    try std.testing.expectEqualStrings("xyz", discard_opts.session);
}

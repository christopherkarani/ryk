//! Default-policy migration: replace pristine legacy default policies with the
//! current embedded default (backup written alongside); never touch customized
//! or invalid policies.
//!
//! Runs on the public repair doors (`ryk doctor --fix`, install ensure) so a
//! ryk upgrade actually reaches existing installs instead of only helping new
//! ones. `ryk start` does not migrate. Doctor's diagnose path surfaces the
//! same findings as one-line notices without writing.
//!
//! Control-path writes refuse a symlink `.ryk/` or `policy.yaml` (O_NOFOLLOW)
//! and re-hash the destination immediately before rename so a just-customized
//! file is never clobbered.

const std = @import("std");

const ryk_policy = @import("ryk_core").policy;
const plugin = @import("plugin.zig");

const migration = ryk_policy.default_migration;

pub const Outcome = enum {
    /// Legacy pristine default → replaced with current default; backup written.
    migrated,
    /// Already a current preset body.
    already_current,
    /// Valid but customized — left untouched (doctor notice points at reset door).
    customized,
    /// Unparseable — left untouched; ryk fails closed on invalid policies.
    invalid,
    /// No file at path.
    missing,
    /// Read/write failure — left untouched.
    io_error,
    /// Symlink control path or dest changed before rename — left untouched.
    refused,
};

pub const FileReport = struct {
    path: []u8,
    outcome: Outcome,
    backup_path: ?[]u8 = null,

    pub fn deinit(self: *FileReport, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        if (self.backup_path) |backup| allocator.free(backup);
        self.* = undefined;
    }
};

pub const Report = struct {
    files: []FileReport,

    pub fn deinit(self: *Report, allocator: std.mem.Allocator) void {
        for (self.files) |file| {
            allocator.free(file.path);
            if (file.backup_path) |backup| allocator.free(backup);
        }
        allocator.free(self.files);
        self.* = undefined;
    }

    pub fn anyMigrated(self: *const Report) bool {
        for (self.files) |file| {
            if (file.outcome == .migrated) return true;
        }
        return false;
    }
};

/// Migrate one policy file when it is byte-identical to a legacy shipped default.
/// Soft by design: I/O errors are reported, never propagated into ensure/doctor.
pub fn migrateFileIfPristine(
    io: std.Io,
    allocator: std.mem.Allocator,
    path: []const u8,
    stderr: anytype,
    quiet: bool,
) !FileReport {
    const owned_path = try allocator.dupe(u8, path);
    errdefer allocator.free(owned_path);

    refuseSymlinkControlPath(io, path) catch |err| switch (err) {
        error.ManagedPathIsSymlink => {
            if (!quiet) {
                stderr.print("ryk: refusing to migrate {s} (symlink .ryk or policy.yaml); leaving it untouched\n", .{path}) catch {};
            }
            return .{ .path = owned_path, .outcome = .refused };
        },
        else => return .{ .path = owned_path, .outcome = .io_error },
    };

    const content = readFileNoFollowAlloc(io, allocator, path) catch |err| {
        const outcome: Outcome = switch (err) {
            error.FileNotFound => .missing,
            else => .io_error,
        };
        return .{ .path = owned_path, .outcome = outcome };
    };
    defer allocator.free(content);
    const expected_hash = migration.sha256Hex(content);

    switch (migration.classify(allocator, content)) {
        .current_default => return .{ .path = owned_path, .outcome = .already_current },
        .customized => return .{ .path = owned_path, .outcome = .customized },
        .invalid => {
            if (!quiet) {
                stderr.print("ryk: {s} is not a valid policy; leaving it untouched (ryk fails closed on invalid policies — fix or replace it)\n", .{path}) catch {};
            }
            return .{ .path = owned_path, .outcome = .invalid };
        },
        .legacy_default => {},
    }

    const backup_path = writeBackup(io, allocator, path, content) catch |err| {
        if (!quiet) {
            stderr.print("ryk: could not back up {s} before migration ({s}); leaving policy untouched\n", .{ path, @errorName(err) }) catch {};
        }
        return .{ .path = owned_path, .outcome = .io_error };
    };
    errdefer allocator.free(backup_path);

    replaceFileAtomic(io, allocator, path, migration.currentDefaultBody(), expected_hash) catch |err| {
        if (err == error.DestinationChanged or err == error.ManagedPathIsSymlink) {
            if (!quiet) {
                stderr.print("ryk: {s} changed or is a symlink; aborting migration (original policy untouched)\n", .{path}) catch {};
            }
            return .{ .path = owned_path, .outcome = .refused };
        }
        if (!quiet) {
            stderr.print("ryk: could not migrate {s} ({s}); original policy untouched\n", .{ path, @errorName(err) }) catch {};
        }
        return .{ .path = owned_path, .outcome = .io_error };
    };

    if (!quiet) {
        stderr.print("ryk: migrated {s} to the current default policy (previous default backed up at {s})\n", .{ path, backup_path }) catch {};
    }
    return .{ .path = owned_path, .outcome = .migrated, .backup_path = backup_path };
}

/// Workspace `<root>/.ryk/policy.yaml`. Returns null when no workspace file exists.
pub fn migrateWorkspacePolicyIfPristine(
    io: std.Io,
    allocator: std.mem.Allocator,
    workspace_root: []const u8,
    stderr: anytype,
    quiet: bool,
) !?FileReport {
    const path = try std.fs.path.join(allocator, &.{ workspace_root, ".ryk", "policy.yaml" });
    defer allocator.free(path);
    if (!plugin.fileExistsAbsolute(io, path)) return null;
    return try migrateFileIfPristine(io, allocator, path, stderr, quiet);
}

/// User-global policies: `~/.config/ryk/policy.yaml` (canonical) and the legacy
/// `$HOME/.ryk/policy.yaml` fallback. Missing files are skipped (seeding is the
/// install door's job, not migration's).
pub fn migrateUserGlobalPolicies(
    io: std.Io,
    allocator: std.mem.Allocator,
    stderr: anytype,
    quiet: bool,
) !Report {
    var files: std.ArrayList(FileReport) = .empty;
    errdefer {
        for (files.items) |file| {
            allocator.free(file.path);
            if (file.backup_path) |backup| allocator.free(backup);
        }
        files.deinit(allocator);
    }

    const home_c = std.c.getenv("HOME") orelse return .{ .files = try files.toOwnedSlice(allocator) };
    const home = std.mem.sliceTo(home_c, 0);
    if (home.len == 0 or !std.fs.path.isAbsolute(home)) {
        return .{ .files = try files.toOwnedSlice(allocator) };
    }

    const subpaths = [_][]const u8{
        ".config/ryk/policy.yaml",
        ".ryk/policy.yaml",
    };
    for (subpaths) |rel| {
        const path = std.fs.path.join(allocator, &.{ home, rel }) catch continue;
        defer allocator.free(path);
        if (!plugin.fileExistsAbsolute(io, path)) continue;
        const report = try migrateFileIfPristine(io, allocator, path, stderr, quiet);
        try files.append(allocator, report);
    }
    return .{ .files = try files.toOwnedSlice(allocator) };
}

pub const StaleKind = enum {
    /// Byte-identical to a previously shipped default — `ryk doctor --fix`
    /// (or install ensure) upgrades it automatically.
    legacy_default,
    /// Valid but matches no known default — never auto-migrated; the user
    /// reconciles manually. Note: a policy customized from the *current*
    /// default also lands here (we cannot distinguish lineage), so the
    /// notice copy stays soft.
    customized,
};

pub const StaleNotice = struct {
    path: []u8,
    kind: StaleKind,
};

pub const ScanReport = struct {
    notices: []StaleNotice,

    pub fn deinit(self: *ScanReport, allocator: std.mem.Allocator) void {
        for (self.notices) |notice| allocator.free(notice.path);
        allocator.free(self.notices);
        self.* = undefined;
    }
};

/// Diagnose-only scan (doctor): classify the workspace policy and user-global
/// policies without writing anything. One notice per policy that is not the
/// current default; invalid policies produce no notice here (doctor already
/// reports them as invalid, and ryk fails closed on them at evaluation time).
pub fn scanStalePolicies(io: std.Io, allocator: std.mem.Allocator, workspace_root: []const u8) !ScanReport {
    var notices: std.ArrayList(StaleNotice) = .empty;
    errdefer {
        for (notices.items) |notice| allocator.free(notice.path);
        notices.deinit(allocator);
    }

    const workspace_policy = try std.fs.path.join(allocator, &.{ workspace_root, ".ryk", "policy.yaml" });
    defer allocator.free(workspace_policy);
    try scanOne(io, allocator, workspace_policy, &notices);

    if (std.c.getenv("HOME")) |home_c| {
        const home = std.mem.sliceTo(home_c, 0);
        if (home.len > 0 and std.fs.path.isAbsolute(home)) {
            const subpaths = [_][]const u8{
                ".config/ryk/policy.yaml",
                ".ryk/policy.yaml",
            };
            for (subpaths) |rel| {
                const path = std.fs.path.join(allocator, &.{ home, rel }) catch continue;
                defer allocator.free(path);
                try scanOne(io, allocator, path, &notices);
            }
        }
    }
    return .{ .notices = try notices.toOwnedSlice(allocator) };
}

fn scanOne(io: std.Io, allocator: std.mem.Allocator, path: []const u8, notices: *std.ArrayList(StaleNotice)) !void {
    if (!plugin.fileExistsAbsolute(io, path)) return;
    refuseSymlinkControlPath(io, path) catch return;
    const content = readFileNoFollowAlloc(io, allocator, path) catch return;
    defer allocator.free(content);
    const kind: StaleKind = switch (migration.classify(allocator, content)) {
        .legacy_default => .legacy_default,
        .customized => .customized,
        else => return,
    };
    try notices.append(allocator, .{
        .path = try allocator.dupe(u8, path),
        .kind = kind,
    });
}

fn writeBackup(io: std.Io, allocator: std.mem.Allocator, path: []const u8, content: []const u8) ![]u8 {
    var suffix_index: u8 = 0;
    while (suffix_index < 8) : (suffix_index += 1) {
        const backup_path = if (suffix_index == 0)
            try std.fmt.allocPrint(allocator, "{s}.bak", .{path})
        else
            try std.fmt.allocPrint(allocator, "{s}.bak.{d}", .{ path, suffix_index });
        errdefer allocator.free(backup_path);

        const file = std.Io.Dir.cwd().createFile(io, backup_path, .{ .exclusive = true }) catch |err| switch (err) {
            error.PathAlreadyExists => {
                allocator.free(backup_path);
                continue;
            },
            else => return err,
        };
        defer file.close(io);
        try file.writeStreamingAll(io, content);
        try file.sync(io);
        return backup_path;
    }
    return error.BackupPathExhausted;
}

/// Temp-write + sync + rename in the same directory (partial bodies never land
/// as a discoverable policy). Same idiom as the ensure seed path.
/// Re-hashes dest bytes immediately before rename and aborts if they changed
/// (do not clobber a just-customized file) or if the dest became a symlink.
fn replaceFileAtomic(
    io: std.Io,
    allocator: std.mem.Allocator,
    path: []const u8,
    body: []const u8,
    expected_hash: [64]u8,
) !void {
    var nonce: u64 = undefined;
    io.random(std.mem.asBytes(&nonce));
    const temp_path = try std.fmt.allocPrint(allocator, "{s}.tmp.{x}", .{ path, nonce });
    defer allocator.free(temp_path);

    const file = try std.Io.Dir.cwd().createFile(io, temp_path, .{ .exclusive = true });
    {
        defer file.close(io);
        try file.writeStreamingAll(io, body);
        try file.sync(io);
    }

    refuseSymlinkControlPath(io, path) catch |err| {
        std.Io.Dir.cwd().deleteFile(io, temp_path) catch {};
        return err;
    };
    if (!try destStillMatches(io, allocator, path, expected_hash)) {
        std.Io.Dir.cwd().deleteFile(io, temp_path) catch {};
        return error.DestinationChanged;
    }

    std.Io.Dir.renameAbsolute(temp_path, path, io) catch |err| {
        std.Io.Dir.cwd().deleteFile(io, temp_path) catch {};
        return err;
    };
}

fn refuseSymlinkControlPath(io: std.Io, path: []const u8) !void {
    if (try pathIsSymlink(io, path)) return error.ManagedPathIsSymlink;
    if (std.fs.path.dirname(path)) |parent| {
        const base = std.fs.path.basename(parent);
        if (std.mem.eql(u8, base, ".ryk") and try pathIsSymlink(io, parent)) {
            return error.ManagedPathIsSymlink;
        }
    }
}

fn pathIsSymlink(io: std.Io, path: []const u8) !bool {
    const stat = std.Io.Dir.cwd().statFile(io, path, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    return stat.kind == .sym_link;
}

fn readFileNoFollowAlloc(io: std.Io, allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const file = try std.Io.Dir.cwd().openFile(io, path, .{ .follow_symlinks = false });
    defer file.close(io);
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    var chunk: [4096]u8 = undefined;
    while (true) {
        const n = file.readStreaming(io, &.{chunk[0..]}) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        if (n == 0) break;
        if (buf.items.len + n > 4 * 1024 * 1024) return error.FileTooBig;
        try buf.appendSlice(allocator, chunk[0..n]);
    }
    return try buf.toOwnedSlice(allocator);
}

fn destStillMatches(io: std.Io, allocator: std.mem.Allocator, path: []const u8, expected_hash: [64]u8) !bool {
    const now = readFileNoFollowAlloc(io, allocator, path) catch return false;
    defer allocator.free(now);
    return std.mem.eql(u8, &migration.sha256Hex(now), &expected_hash);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const test_helpers = struct {
    fn writeFile(io: std.Io, path: []const u8, content: []const u8) !void {
        const file = try std.Io.Dir.cwd().createFile(io, path, .{});
        defer file.close(io);
        try file.writeStreamingAll(io, content);
    }

    fn readAlloc(io: std.Io, allocator: std.mem.Allocator, path: []const u8) ![]u8 {
        return std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(4 * 1024 * 1024));
    }
};

test "migrateFileIfPristine: legacy default migrates with backup" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const root = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(root);
    const path = try std.fs.path.join(allocator, &.{ root, "policy.yaml" });
    defer allocator.free(path);

    const legacy = try std.Io.Dir.cwd().readFileAlloc(
        io,
        "tests/fixtures/policy-migration/generic-agent-v1.2.13.yaml",
        allocator,
        .limited(1024 * 1024),
    );
    defer allocator.free(legacy);
    try test_helpers.writeFile(io, path, legacy);

    var stderr_buf: [1024]u8 = undefined;
    var stderr: std.Io.Writer = .fixed(&stderr_buf);
    var report = try migrateFileIfPristine(io, allocator, path, &stderr, true);
    defer report.deinit(allocator);

    try std.testing.expectEqual(Outcome.migrated, report.outcome);
    const backup = report.backup_path orelse return error.TestExpectedBackup;
    // Backup preserves the exact legacy bytes.
    const backup_content = try test_helpers.readAlloc(io, allocator, backup);
    defer allocator.free(backup_content);
    try std.testing.expectEqualStrings(legacy, backup_content);
    // Live file is now the current default.
    const migrated_content = try test_helpers.readAlloc(io, allocator, path);
    defer allocator.free(migrated_content);
    try std.testing.expectEqualStrings(migration.currentDefaultBody(), migrated_content);
}

test "migrateFileIfPristine: customized policy untouched, no backup" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const root = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(root);
    const path = try std.fs.path.join(allocator, &.{ root, "policy.yaml" });
    defer allocator.free(path);

    const customized = "version: 1\nmode: strict\n\ncommands:\n  default: allow\n  deny:\n    - \"make deploy-prod*\"\n";
    try test_helpers.writeFile(io, path, customized);

    var stderr_buf: [512]u8 = undefined;
    var stderr: std.Io.Writer = .fixed(&stderr_buf);
    var report = try migrateFileIfPristine(io, allocator, path, &stderr, true);
    defer report.deinit(allocator);

    try std.testing.expectEqual(Outcome.customized, report.outcome);
    try std.testing.expect(report.backup_path == null);
    const after = try test_helpers.readAlloc(io, allocator, path);
    defer allocator.free(after);
    try std.testing.expectEqualStrings(customized, after);
}

test "migrateFileIfPristine: corrupted policy untouched (fail closed)" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const root = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(root);
    const path = try std.fs.path.join(allocator, &.{ root, "policy.yaml" });
    defer allocator.free(path);

    try test_helpers.writeFile(io, path, "not: [valid");

    var stderr_buf: [512]u8 = undefined;
    var stderr: std.Io.Writer = .fixed(&stderr_buf);
    var report = try migrateFileIfPristine(io, allocator, path, &stderr, false);
    defer report.deinit(allocator);

    try std.testing.expectEqual(Outcome.invalid, report.outcome);
    try std.testing.expect(report.backup_path == null);
    const after = try test_helpers.readAlloc(io, allocator, path);
    defer allocator.free(after);
    try std.testing.expectEqualStrings("not: [valid", after);
    // Non-quiet emits a clear fail-closed message.
    try std.testing.expect(std.mem.indexOf(u8, stderr.buffered(), "fails closed") != null);
}

test "migrateFileIfPristine: current default is a no-op" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const root = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(root);
    const path = try std.fs.path.join(allocator, &.{ root, "policy.yaml" });
    defer allocator.free(path);

    try test_helpers.writeFile(io, path, migration.currentDefaultBody());

    var stderr_buf: [512]u8 = undefined;
    var stderr: std.Io.Writer = .fixed(&stderr_buf);
    var report = try migrateFileIfPristine(io, allocator, path, &stderr, true);
    defer report.deinit(allocator);

    try std.testing.expectEqual(Outcome.already_current, report.outcome);
    try std.testing.expect(report.backup_path == null);
}

test "migrateFileIfPristine: missing file reports missing" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const root = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(root);
    const path = try std.fs.path.join(allocator, &.{ root, "absent.yaml" });
    defer allocator.free(path);

    var stderr_buf: [256]u8 = undefined;
    var stderr: std.Io.Writer = .fixed(&stderr_buf);
    var report = try migrateFileIfPristine(io, allocator, path, &stderr, true);
    defer report.deinit(allocator);
    try std.testing.expectEqual(Outcome.missing, report.outcome);
}

test "scanStalePolicies: flags legacy default and customized, spares current" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const root = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(root);

    // Workspace policy = legacy default → legacy_default notice.
    const ryk_dir = try std.fs.path.join(allocator, &.{ root, ".ryk" });
    defer allocator.free(ryk_dir);
    try std.Io.Dir.cwd().createDirPath(io, ryk_dir);
    const legacy = try std.Io.Dir.cwd().readFileAlloc(
        io,
        "tests/fixtures/policy-migration/generic-agent-v1.2.13.yaml",
        allocator,
        .limited(1024 * 1024),
    );
    defer allocator.free(legacy);
    const workspace_policy = try std.fs.path.join(allocator, &.{ ryk_dir, "policy.yaml" });
    defer allocator.free(workspace_policy);
    try test_helpers.writeFile(io, workspace_policy, legacy);

    var scan = try scanStalePolicies(io, allocator, root);
    defer scan.deinit(allocator);

    // HOME is the developer machine here, so user-global policies may add
    // notices; assert only that the workspace legacy default is flagged.
    var found_legacy = false;
    for (scan.notices) |notice| {
        if (std.mem.eql(u8, notice.path, workspace_policy)) {
            try std.testing.expectEqual(StaleKind.legacy_default, notice.kind);
            found_legacy = true;
        }
    }
    try std.testing.expect(found_legacy);

    // Current default → no notice for the workspace file.
    try test_helpers.writeFile(io, workspace_policy, migration.currentDefaultBody());
    var scan2 = try scanStalePolicies(io, allocator, root);
    defer scan2.deinit(allocator);
    for (scan2.notices) |notice| {
        try std.testing.expect(!std.mem.eql(u8, notice.path, workspace_policy));
    }
}

test "migrateFileIfPristine: refuses symlink policy.yaml and leaves target untouched" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const root = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(root);
    const target = try std.fs.path.join(allocator, &.{ root, "real-policy.yaml" });
    defer allocator.free(target);
    const link = try std.fs.path.join(allocator, &.{ root, "policy.yaml" });
    defer allocator.free(link);

    const legacy = try std.Io.Dir.cwd().readFileAlloc(
        io,
        "tests/fixtures/policy-migration/generic-agent-v1.2.13.yaml",
        allocator,
        .limited(1024 * 1024),
    );
    defer allocator.free(legacy);
    try test_helpers.writeFile(io, target, legacy);
    std.Io.Dir.cwd().symLink(io, target, link, .{}) catch return error.SkipZigTest;

    var stderr_buf: [512]u8 = undefined;
    var stderr: std.Io.Writer = .fixed(&stderr_buf);
    var report = try migrateFileIfPristine(io, allocator, link, &stderr, true);
    defer report.deinit(allocator);

    try std.testing.expectEqual(Outcome.refused, report.outcome);
    const after = try test_helpers.readAlloc(io, allocator, target);
    defer allocator.free(after);
    try std.testing.expectEqualStrings(legacy, after);
}

test "migrateFileIfPristine: refuses symlink .ryk parent" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const root = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(root);
    const outside = try std.fs.path.join(allocator, &.{ root, "outside" });
    defer allocator.free(outside);
    try std.Io.Dir.cwd().createDirPath(io, outside);
    const target = try std.fs.path.join(allocator, &.{ outside, "policy.yaml" });
    defer allocator.free(target);
    const legacy = try std.Io.Dir.cwd().readFileAlloc(
        io,
        "tests/fixtures/policy-migration/generic-agent-v1.2.13.yaml",
        allocator,
        .limited(1024 * 1024),
    );
    defer allocator.free(legacy);
    try test_helpers.writeFile(io, target, legacy);

    const ryk_link = try std.fs.path.join(allocator, &.{ root, ".ryk" });
    defer allocator.free(ryk_link);
    std.Io.Dir.cwd().symLink(io, outside, ryk_link, .{}) catch return error.SkipZigTest;

    const path = try std.fs.path.join(allocator, &.{ ryk_link, "policy.yaml" });
    defer allocator.free(path);
    var stderr_buf: [512]u8 = undefined;
    var stderr: std.Io.Writer = .fixed(&stderr_buf);
    var report = try migrateFileIfPristine(io, allocator, path, &stderr, true);
    defer report.deinit(allocator);

    try std.testing.expectEqual(Outcome.refused, report.outcome);
    const after = try test_helpers.readAlloc(io, allocator, target);
    defer allocator.free(after);
    try std.testing.expectEqualStrings(legacy, after);
}

test "destStillMatches: re-hash detects a just-customized dest" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const root = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(root);
    const path = try std.fs.path.join(allocator, &.{ root, "policy.yaml" });
    defer allocator.free(path);

    try test_helpers.writeFile(io, path, "legacy-body\n");
    const hash = migration.sha256Hex("legacy-body\n");
    try std.testing.expect(try destStillMatches(io, allocator, path, hash));

    try test_helpers.writeFile(io, path, "customized-now\n");
    try std.testing.expect(!try destStillMatches(io, allocator, path, hash));
}

const std = @import("std");
const file_intercept = @import("../intercept/files.zig");
const host_runtime_reads = @import("ryk_core").policy.host_runtime_reads;

/// Policy file rules are workspace-relative, while host adapters commonly emit
/// absolute paths. Normalize an absolute target inside the selected workspace
/// to the same `./relative` form as a direct CLI caller. Absolute paths outside
/// the workspace stay absolute so home/system rules retain their semantics.
///
/// When the path is workspace-relative (`./…`), also run `intercept/files.normalizePath`
/// so symlink escapes and outside-workspace resolution fail closed for callers.
pub fn normalizeFilePolicyPath(io: std.Io, allocator: std.mem.Allocator, workspace_root_raw: []const u8, raw_path: []const u8) ![]u8 {
    const lexical = try normalizeFilePolicyPathLexical(allocator, workspace_root_raw, raw_path);
    if (!std.mem.startsWith(u8, lexical, "./")) return lexical;
    defer allocator.free(lexical);

    var normalized = try file_intercept.normalizePath(io, allocator, workspace_root_raw, raw_path);
    defer normalized.deinit(allocator);
    return allocator.dupe(u8, normalized.policy_path);
}

/// Read-only: same as `normalizeFilePolicyPath`, except a workspace symlink
/// whose resolved target is a host-runtime read (skill / instruction file)
/// is rewritten to that absolute target so evaluate can allow it.
/// Existing absolute catalog paths are realpath'd; a link out of the catalog
/// fails closed. Writes must keep using `normalizeFilePolicyPath`.
pub fn normalizeFilePolicyPathForRead(
    io: std.Io,
    allocator: std.mem.Allocator,
    workspace_root_raw: []const u8,
    raw_path: []const u8,
) ![]u8 {
    const initial = normalizeFilePolicyPath(io, allocator, workspace_root_raw, raw_path) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => {
            const resolved = (try tryResolveExistingPath(io, allocator, workspace_root_raw, raw_path)) orelse
                return err;
            defer allocator.free(resolved);
            if (!host_runtime_reads.isHostRuntimeReadPath(resolved)) return err;
            return sealResolvedHostRuntimePath(io, allocator, try allocator.dupe(u8, resolved));
        },
    };
    return sealResolvedHostRuntimePath(io, allocator, initial);
}

fn sealResolvedHostRuntimePath(
    io: std.Io,
    allocator: std.mem.Allocator,
    initial: []u8,
) ![]u8 {
    const resolved_z = std.Io.Dir.cwd().realPathFileAlloc(io, initial, allocator) catch return initial;
    defer allocator.free(resolved_z);
    if (host_runtime_reads.classify(resolved_z) != .none) {
        if (std.mem.eql(u8, resolved_z, initial)) return initial;
        const owned = try allocator.dupe(u8, resolved_z);
        allocator.free(initial);
        return owned;
    }
    if (host_runtime_reads.classify(initial) != .none) {
        allocator.free(initial);
        return error.SymlinkEscapesWorkspace;
    }
    return initial;
}

fn tryResolveExistingPath(
    io: std.Io,
    allocator: std.mem.Allocator,
    workspace_root_raw: []const u8,
    raw_path: []const u8,
) error{OutOfMemory}!?[]u8 {
    if (raw_path.len == 0) return null;
    if (host_runtime_reads.pathHasDotDotSegment(raw_path)) return null;

    const expanded = expandTilde(allocator, raw_path) catch return error.OutOfMemory;
    defer allocator.free(expanded);

    const candidate = if (std.fs.path.isAbsolute(expanded))
        expanded
    else if (std.fs.path.isAbsolute(workspace_root_raw))
        (std.fs.path.resolve(allocator, &.{ workspace_root_raw, expanded }) catch return error.OutOfMemory)
    else
        return null;
    defer if (candidate.ptr != expanded.ptr) allocator.free(candidate);

    const resolved_z = std.Io.Dir.cwd().realPathFileAlloc(io, candidate, allocator) catch return null;
    defer allocator.free(resolved_z);
    return try allocator.dupe(u8, resolved_z);
}

fn expandTilde(allocator: std.mem.Allocator, raw_path: []const u8) ![]u8 {
    if (!std.mem.startsWith(u8, raw_path, "~/")) return allocator.dupe(u8, raw_path);
    const home_c = std.c.getenv("HOME") orelse return allocator.dupe(u8, raw_path);
    const home = std.mem.sliceTo(home_c, 0);
    return std.fs.path.join(allocator, &.{ home, raw_path[2..] });
}

pub fn normalizeFilePolicyPathLexical(allocator: std.mem.Allocator, workspace_root_raw: []const u8, raw_path: []const u8) ![]u8 {
    if (!std.fs.path.isAbsolute(workspace_root_raw)) {
        return allocator.dupe(u8, raw_path);
    }

    const workspace_root = try std.fs.path.resolve(allocator, &.{workspace_root_raw});
    defer allocator.free(workspace_root);
    const absolute_path = if (std.fs.path.isAbsolute(raw_path))
        try std.fs.path.resolve(allocator, &.{raw_path})
    else
        try std.fs.path.resolve(allocator, &.{ workspace_root, raw_path });
    defer allocator.free(absolute_path);

    if (std.mem.eql(u8, absolute_path, workspace_root)) return allocator.dupe(u8, ".");
    if (absolute_path.len <= workspace_root.len or
        !std.mem.eql(u8, absolute_path[0..workspace_root.len], workspace_root) or
        (absolute_path[workspace_root.len] != '/' and absolute_path[workspace_root.len] != '\\'))
    {
        return allocator.dupe(u8, absolute_path);
    }

    const relative = absolute_path[workspace_root.len + 1 ..];
    const normalized = try std.fmt.allocPrint(allocator, "./{s}", .{relative});
    for (normalized) |*char| {
        if (char.* == '\\') char.* = '/';
    }
    return normalized;
}

pub const outside_workspace_reason: []const u8 =
    "file access denied: path resolves outside workspace or through a symlink escape";

pub fn outsideWorkspaceRuleId(allocator: std.mem.Allocator, category: []const u8) ![]u8 {
    return try std.fmt.allocPrint(allocator, "builtin.files.{s}.deny[outside_workspace]", .{
        if (std.mem.eql(u8, category, "file.write")) "write" else "read",
    });
}

test "read normalize rewrites workspace symlink to host skill target" {
    const io = std.testing.io;
    const home_c = std.c.getenv("HOME") orelse return error.SkipZigTest;
    const home = std.mem.sliceTo(home_c, 0);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "workspace/.grok/skills");

    const root = try tmp.dir.realPathFileAlloc(io, "workspace", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const target = try std.fmt.allocPrint(std.testing.allocator, "{s}/.grok/skills/task-observer/SKILL.md", .{home});
    defer std.testing.allocator.free(target);
    std.Io.Dir.cwd().access(io, target, .{}) catch return error.SkipZigTest;

    const alias = try std.fs.path.join(std.testing.allocator, &.{ root, ".grok/skills/task-observer" });
    defer std.testing.allocator.free(alias);
    std.Io.Dir.cwd().symLink(io, target, alias, .{}) catch |err| switch (err) {
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };

    const normalized = try normalizeFilePolicyPathForRead(io, std.testing.allocator, root, alias);
    defer std.testing.allocator.free(normalized);
    try std.testing.expect(host_runtime_reads.isHostRuntimeReadPath(normalized));
    try std.testing.expect(std.fs.path.isAbsolute(normalized));

    try std.testing.expectError(
        error.SymlinkEscapesWorkspace,
        normalizeFilePolicyPath(io, std.testing.allocator, root, alias),
    );
}

test "read normalize rejects catalog skill symlink to ssh" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "home/.grok/skills/pwn");
    try tmp.dir.createDirPath(io, "home/.ssh");
    try tmp.dir.createDirPath(io, "workspace");
    try tmp.dir.writeFile(io, .{ .sub_path = "home/.ssh/id_ed25519", .data = "synthetic\n" });

    const home = try tmp.dir.realPathFileAlloc(io, "home", std.testing.allocator);
    defer std.testing.allocator.free(home);
    const workspace = try tmp.dir.realPathFileAlloc(io, "workspace", std.testing.allocator);
    defer std.testing.allocator.free(workspace);
    const target = try std.fs.path.join(std.testing.allocator, &.{ home, ".ssh/id_ed25519" });
    defer std.testing.allocator.free(target);
    const alias = try std.fs.path.join(std.testing.allocator, &.{ home, ".grok/skills/pwn/SKILL.md" });
    defer std.testing.allocator.free(alias);
    std.Io.Dir.cwd().symLink(io, target, alias, .{}) catch |err| switch (err) {
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };

    const prev_home = blk: {
        if (std.c.getenv("HOME")) |value| break :blk try std.testing.allocator.dupeZ(u8, std.mem.span(value));
        break :blk null;
    };
    defer if (prev_home) |value| std.testing.allocator.free(value);
    const home_z = try std.testing.allocator.dupeZ(u8, home);
    defer std.testing.allocator.free(home_z);
    try std.testing.expectEqual(@as(c_int, 0), setenv("HOME", home_z, 1));
    defer {
        if (prev_home) |value| {
            _ = setenv("HOME", value, 1);
        } else {
            _ = unsetenv("HOME");
        }
    }

    try std.testing.expectError(
        error.SymlinkEscapesWorkspace,
        normalizeFilePolicyPathForRead(io, std.testing.allocator, workspace, alias),
    );
}

extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;
extern "c" fn unsetenv(name: [*:0]const u8) c_int;

test "read normalize still rejects workspace symlink to ssh" {
    const io = std.testing.io;
    const home_c = std.c.getenv("HOME") orelse return error.SkipZigTest;
    const home = std.mem.sliceTo(home_c, 0);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "workspace");

    const root = try tmp.dir.realPathFileAlloc(io, "workspace", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const target = try std.fmt.allocPrint(std.testing.allocator, "{s}/.ssh/id_ed25519", .{home});
    defer std.testing.allocator.free(target);

    const alias = try std.fs.path.join(std.testing.allocator, &.{ root, "ssh-link" });
    defer std.testing.allocator.free(alias);
    std.Io.Dir.cwd().symLink(io, target, alias, .{}) catch |err| switch (err) {
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };

    try std.testing.expectError(
        error.SymlinkEscapesWorkspace,
        normalizeFilePolicyPathForRead(io, std.testing.allocator, root, alias),
    );
}

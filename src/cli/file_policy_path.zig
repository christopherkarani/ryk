const std = @import("std");
const file_intercept = @import("../intercept/files.zig");

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

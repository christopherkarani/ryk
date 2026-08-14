const std = @import("std");
const builtin = @import("builtin");
const core = @import("ryk_core").core;
const supervisor = core.supervisor;

pub const MarketplaceHost = enum { codex, claude };

const max_manifest_bytes = 64 * 1024;
const max_marketplace_bytes = 1024 * 1024;
const managed_plugin_name = "ryk";
const managed_brand_name = "ryk";
var temp_sequence: std.atomic.Value(u64) = .init(0);

pub const MarketplaceHostInstall = struct {
    host_label: []const u8,
    plugin_dest: []const u8,
    marketplace_path: []const u8,
    marketplace_json: []const u8,
};

pub const MarketplaceMerge = struct {
    bytes: []u8,
    changed: bool,
};

pub fn resolveWorkspaceInstallRoot(io: std.Io, allocator: std.mem.Allocator) ![]u8 {
    return supervisor.resolveWorkspaceRoot(io, allocator, null, ".") catch try std.Io.Dir.cwd().realPathFileAlloc(io, ".", allocator);
}

pub fn marketplaceHostInstallSpec(
    allocator: std.mem.Allocator,
    workspace_root: []const u8,
    target: MarketplaceHost,
    marketplace_json: []const u8,
) !MarketplaceHostInstall {
    return switch (target) {
        .codex => .{
            .host_label = "Codex",
            .plugin_dest = try std.fs.path.join(allocator, &.{ workspace_root, ".agents", "plugins", "ryk"}),
            .marketplace_path = try std.fs.path.join(allocator, &.{ workspace_root, ".agents", "plugins", "marketplace.json" }),
            .marketplace_json = marketplace_json,
        },
        .claude => .{
            .host_label = "Claude Code",
            .plugin_dest = try std.fs.path.join(allocator, &.{ workspace_root, ".claude", "plugins", "ryk"}),
            .marketplace_path = try std.fs.path.join(allocator, &.{ workspace_root, ".claude-plugin", "marketplace.json" }),
            .marketplace_json = marketplace_json,
        },
    };
}

pub fn loadMarketplaceTemplate(
    io: std.Io,
    allocator: std.mem.Allocator,
    template_path: []const u8,
    bundled_source_path: []const u8,
    install_source_path: []const u8,
) ![]u8 {
    const template = try std.Io.Dir.cwd().readFileAlloc(io, template_path, allocator, .limited(64 * 1024));
    errdefer allocator.free(template);
    if (std.mem.indexOf(u8, template, bundled_source_path) == null) return error.TemplatePathMissing;
    const rewritten = try std.mem.replaceOwned(u8, allocator, template, bundled_source_path, install_source_path);
    allocator.free(template);
    return rewritten;
}

pub fn installTextIfSafe(io: std.Io, allocator: std.mem.Allocator, content: []const u8, destination_path: []const u8, allow_upgrade: bool) !bool {
    var destination = try openSecureDestination(io, destination_path);
    defer destination.parent.close(io);
    try refuseSymlinkAt(io, destination.parent, destination.basename, error.RefusingSymlinkPluginPath);
    const current = try readOptionalFileAtAlloc(
        io,
        allocator,
        destination.parent,
        destination.basename,
        8 * 1024 * 1024,
    );
    defer if (current) |bytes| allocator.free(bytes);
    if (current) |bytes| {
        if (std.mem.eql(u8, content, bytes)) return false;
        if (!allow_upgrade) return error.RefusingToOverwriteDifferentFile;
    }
    try writeFileAtomicallyAt(
        io,
        allocator,
        content,
        destination.parent,
        destination.basename,
        ".ryk-managed-",
        error.RefusingSymlinkPluginPath,
    );
    return true;
}

pub fn installFileIfSafe(
    io: std.Io,
    allocator: std.mem.Allocator,
    source_path: []const u8,
    destination_path: []const u8,
    allow_upgrade: bool,
) !bool {
    const source_kind = try pathKindNoFollow(io, source_path) orelse return error.FileNotFound;
    if (source_kind == .sym_link) return error.RefusingSymlinkPluginPath;
    if (source_kind != .file) return error.InvalidManagedPluginSource;
    const source = try std.Io.Dir.cwd().readFileAlloc(
        io,
        source_path,
        allocator,
        .limited(8 * 1024 * 1024),
    );
    defer allocator.free(source);
    return installTextIfSafe(io, allocator, source, destination_path, allow_upgrade);
}

pub fn filesEqualText(io: std.Io, allocator: std.mem.Allocator, expected: []const u8, path: []const u8) !bool {
    const actual = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(1024 * 1024));
    defer allocator.free(actual);
    return std.mem.eql(u8, expected, actual);
}

pub fn installDirectoryIfSafe(io: std.Io, allocator: std.mem.Allocator, source_dir: []const u8, destination_dir: []const u8, allow_upgrade: bool) !void {
    const source_manifest = try managedPluginManifestKind(io, allocator, source_dir) orelse
        return error.InvalidManagedPluginSource;
    try validatePluginTree(io, allocator, source_dir);

    const destination_kind = try pathKindNoFollow(io, destination_dir);
    if (destination_kind) |kind| {
        if (kind == .sym_link) return error.RefusingSymlinkPluginPath;
        if (kind != .directory) return error.RefusingToOverwriteUnownedPlugin;
        const destination_manifest = try managedPluginManifestKind(io, allocator, destination_dir) orelse
            return error.RefusingToOverwriteUnownedPlugin;
        if (destination_manifest != source_manifest) return error.RefusingToOverwriteUnownedPlugin;
        try validatePluginTree(io, allocator, destination_dir);

        const same = directoriesEquivalent(io, allocator, source_dir, destination_dir) catch |err| switch (err) {
            error.OutOfMemory => return err,
            else => false,
        };
        if (same) return;
        if (!allow_upgrade) return error.RefusingToOverwriteDifferentFile;
    }
    var destination = try openOrCreateDirectoryNoSymlinks(io, destination_dir);
    destination.close(io);
    try copyDirectoryRecursive(io, allocator, source_dir, destination_dir);
}

pub fn copyDirectoryRecursive(io: std.Io, allocator: std.mem.Allocator, source_dir: []const u8, destination_dir: []const u8) !void {
    var destination = try openOrCreateDirectoryNoSymlinks(io, destination_dir);
    destination.close(io);
    var source = try std.Io.Dir.cwd().openDir(io, source_dir, .{
        .iterate = true,
        .follow_symlinks = false,
    });
    defer source.close(io);
    var it = source.iterate();
    while (try it.next(io)) |entry| {
        const source_path = try std.fs.path.join(allocator, &.{ source_dir, entry.name });
        defer allocator.free(source_path);
        const dest_path = try std.fs.path.join(allocator, &.{ destination_dir, entry.name });
        defer allocator.free(dest_path);
        switch (entry.kind) {
            .directory => try copyDirectoryRecursive(io, allocator, source_path, dest_path),
            .file => {
                const bytes = try std.Io.Dir.cwd().readFileAlloc(io, source_path, allocator, .limited(8 * 1024 * 1024));
                defer allocator.free(bytes);
                try writeFileAtomically(io, allocator, bytes, dest_path, ".ryk-plugin-");
            },
            .sym_link => return error.RefusingSymlinkPluginPath,
            else => return error.UnsupportedPluginEntry,
        }
    }
}

const PluginManifestKind = enum {
    codex,
    claude,

    fn relativePath(self: PluginManifestKind) []const u8 {
        return switch (self) {
            .codex => ".codex-plugin/plugin.json",
            .claude => ".claude-plugin/plugin.json",
        };
    }
};

fn managedPluginManifestKind(
    io: std.Io,
    allocator: std.mem.Allocator,
    directory: []const u8,
) !?PluginManifestKind {
    inline for (std.meta.tags(PluginManifestKind)) |kind| {
        const manifest_path = try std.fs.path.join(allocator, &.{ directory, kind.relativePath() });
        defer allocator.free(manifest_path);
        if (try manifestHasExpectedIdentity(io, allocator, manifest_path)) return kind;
    }
    return null;
}

fn manifestHasExpectedIdentity(
    io: std.Io,
    allocator: std.mem.Allocator,
    manifest_path: []const u8,
) !bool {
    const kind = try pathKindNoFollow(io, manifest_path) orelse return false;
    if (kind == .sym_link) return error.RefusingSymlinkPluginPath;
    if (kind != .file) return false;

    const bytes = try std.Io.Dir.cwd().readFileAlloc(
        io,
        manifest_path,
        allocator,
        .limited(max_manifest_bytes),
    );
    defer allocator.free(bytes);
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, bytes, .{}) catch return false;
    defer parsed.deinit();
    if (parsed.value != .object) return false;
    const name = parsed.value.object.get("name") orelse return false;
    const author = parsed.value.object.get("author") orelse return false;
    const interface = parsed.value.object.get("interface") orelse return false;
    if (name != .string or !std.mem.eql(u8, name.string, managed_plugin_name)) return false;
    if (author != .object or interface != .object) return false;
    const author_name = author.object.get("name") orelse return false;
    const display_name = interface.object.get("displayName") orelse return false;
    return author_name == .string and
        std.mem.eql(u8, author_name.string, managed_brand_name) and
        display_name == .string and
        std.mem.eql(u8, display_name.string, managed_brand_name);
}

fn validatePluginTree(
    io: std.Io,
    allocator: std.mem.Allocator,
    directory: []const u8,
) !void {
    const root_kind = try pathKindNoFollow(io, directory) orelse return error.FileNotFound;
    if (root_kind == .sym_link) return error.RefusingSymlinkPluginPath;
    if (root_kind != .directory) return error.InvalidManagedPluginSource;

    var dir = try std.Io.Dir.openDirAbsolute(io, directory, .{
        .iterate = true,
        .follow_symlinks = false,
    });
    defer dir.close(io);
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        const path = try std.fs.path.join(allocator, &.{ directory, entry.name });
        defer allocator.free(path);
        switch (entry.kind) {
            .directory => try validatePluginTree(io, allocator, path),
            .file => {},
            .sym_link => return error.RefusingSymlinkPluginPath,
            else => return error.UnsupportedPluginEntry,
        }
    }
}

pub fn directoriesEquivalent(io: std.Io, allocator: std.mem.Allocator, lhs_dir: []const u8, rhs_dir: []const u8) !bool {
    if (!try directoryTreeEquivalent(io, allocator, lhs_dir, rhs_dir)) return false;
    return directoryTreeEquivalent(io, allocator, rhs_dir, lhs_dir);
}

fn directoryTreeEquivalent(io: std.Io, allocator: std.mem.Allocator, lhs_dir: []const u8, rhs_dir: []const u8) !bool {
    var lhs = try std.Io.Dir.cwd().openDir(io, lhs_dir, .{
        .iterate = true,
        .follow_symlinks = false,
    });
    defer lhs.close(io);
    var rhs = try std.Io.Dir.cwd().openDir(io, rhs_dir, .{
        .iterate = true,
        .follow_symlinks = false,
    });
    defer rhs.close(io);

    var lhs_it = lhs.iterate();
    while (try lhs_it.next(io)) |entry| {
        const lhs_path = try std.fs.path.join(allocator, &.{ lhs_dir, entry.name });
        defer allocator.free(lhs_path);
        const rhs_path = try std.fs.path.join(allocator, &.{ rhs_dir, entry.name });
        defer allocator.free(rhs_path);
        switch (entry.kind) {
            .directory => {
                if (!dirExists(io, rhs_path)) return false;
                if (!try directoryTreeEquivalent(io, allocator, lhs_path, rhs_path)) return false;
            },
            .file => {
                if (!fileExistsAbsolute(io, rhs_path)) return false;
                if (!try filesEqual(io, allocator, lhs_path, rhs_path)) return false;
            },
            else => {},
        }
    }
    return true;
}

pub fn filesEqual(io: std.Io, allocator: std.mem.Allocator, lhs_path: []const u8, rhs_path: []const u8) !bool {
    const lhs = try std.Io.Dir.cwd().readFileAlloc(io, lhs_path, allocator, .limited(1024 * 1024));
    defer allocator.free(lhs);
    const rhs = try std.Io.Dir.cwd().readFileAlloc(io, rhs_path, allocator, .limited(1024 * 1024));
    defer allocator.free(rhs);
    return std.mem.eql(u8, lhs, rhs);
}

pub fn installMarketplaceHostPlugin(io: std.Io, allocator: std.mem.Allocator, plugin_dir: []const u8, spec: MarketplaceHostInstall, stdout: anytype) !void {
    try installDirectoryIfSafe(io, allocator, plugin_dir, spec.plugin_dest, true);
    try refuseSymlinkPath(io, spec.marketplace_path, error.RefusingSymlinkMarketplace);
    const installed_marketplace = if (fileExistsAbsolute(io, spec.marketplace_path)) blk: {
        const existing = try std.Io.Dir.cwd().readFileAlloc(io, spec.marketplace_path, allocator, .limited(max_marketplace_bytes));
        defer allocator.free(existing);
        const merged = try mergeMarketplaceAlloc(allocator, existing, spec.marketplace_json);
        defer allocator.free(merged.bytes);
        break :blk if (merged.changed)
            try installMarketplaceTextAtomically(
                io,
                allocator,
                merged.bytes,
                spec.marketplace_path,
                existing,
            )
        else
            false;
    } else try installMarketplaceTextAtomically(
        io,
        allocator,
        spec.marketplace_json,
        spec.marketplace_path,
        null,
    );
    if (installed_marketplace) {
        try stdout.print("  marketplace: wrote {s}\n", .{spec.marketplace_path});
    } else {
        try stdout.print("  marketplace: already up-to-date at {s}\n", .{spec.marketplace_path});
    }
    try stdout.print("  plugin: installed to {s}\n", .{spec.plugin_dest});
}

/// Atomically install a marketplace document without overwriting a concurrent
/// editor. `expected_existing` is the exact snapshot used to produce `content`;
/// `null` means the caller observed no destination.
pub fn installMarketplaceTextAtomically(
    io: std.Io,
    allocator: std.mem.Allocator,
    content: []const u8,
    destination_path: []const u8,
    expected_existing: ?[]const u8,
) !bool {
    var destination = try openSecureDestination(io, destination_path);
    defer destination.parent.close(io);
    try refuseSymlinkAt(
        io,
        destination.parent,
        destination.basename,
        error.RefusingSymlinkMarketplace,
    );

    const current = try readOptionalFileAtAlloc(
        io,
        allocator,
        destination.parent,
        destination.basename,
        max_marketplace_bytes,
    );
    defer if (current) |bytes| allocator.free(bytes);
    if (current) |bytes| {
        if (std.mem.eql(u8, bytes, content)) return false;
    }
    if (!optionalBytesEqual(current, expected_existing)) return error.ConcurrentMarketplaceUpdate;

    const temp_name = try writeTempFileSyncedAt(
        io,
        allocator,
        content,
        destination.parent,
        destination.basename,
        ".ryk-marketplace-",
    );
    defer allocator.free(temp_name);
    errdefer destination.parent.deleteFile(io, temp_name) catch {};

    // Revalidate after the complete replacement is durable but immediately
    // before the rename. This closes the broad read/merge/write race.
    try refuseSymlinkAt(
        io,
        destination.parent,
        destination.basename,
        error.RefusingSymlinkMarketplace,
    );
    const revalidated = try readOptionalFileAtAlloc(
        io,
        allocator,
        destination.parent,
        destination.basename,
        max_marketplace_bytes,
    );
    defer if (revalidated) |bytes| allocator.free(bytes);
    if (!optionalBytesEqual(revalidated, expected_existing)) return error.ConcurrentMarketplaceUpdate;

    try destination.parent.rename(
        temp_name,
        destination.parent,
        destination.basename,
        io,
    );
    try syncDirectory(io, destination.parent);
    return true;
}

/// Validate that a marketplace file contains the exact registration written
/// by ryk for `target`; file presence alone is deliberately insufficient.
pub fn marketplaceRegistersExpectedPlugin(
    io: std.Io,
    allocator: std.mem.Allocator,
    marketplace_path: []const u8,
    target: MarketplaceHost,
) bool {
    refuseSymlinkPath(io, marketplace_path, error.RefusingSymlinkMarketplace) catch return false;
    const bytes = std.Io.Dir.cwd().readFileAlloc(
        io,
        marketplace_path,
        allocator,
        .limited(max_marketplace_bytes),
    ) catch return false;
    defer allocator.free(bytes);
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, bytes, .{}) catch return false;
    defer parsed.deinit();
    if (parsed.value != .object) return false;
    const plugins = parsed.value.object.get("plugins") orelse return false;
    if (plugins != .array) return false;
    for (plugins.array.items) |plugin| {
        if (pluginRegistrationMatches(plugin, target)) return true;
    }
    return false;
}

fn pluginRegistrationMatches(plugin: std.json.Value, target: MarketplaceHost) bool {
    if (plugin != .object) return false;
    const name = plugin.object.get("name") orelse return false;
    if (name != .string or !std.mem.eql(u8, name.string, managed_plugin_name)) return false;
    const source = plugin.object.get("source") orelse return false;
    return switch (target) {
        .codex => blk: {
            if (source != .object) break :blk false;
            const source_kind = source.object.get("source") orelse break :blk false;
            const path = source.object.get("path") orelse break :blk false;
            break :blk source_kind == .string and
                std.mem.eql(u8, source_kind.string, "local") and
                path == .string and
                std.mem.eql(u8, path.string, "./ryk");
        },
        .claude => source == .string and
            std.mem.eql(u8, source.string, "../.claude/plugins/ryk"),
    };
}

/// Merge ryk's plugin registrations into an existing marketplace document.
/// Existing marketplace identity, metadata, and unrelated plugins are retained.
pub fn mergeMarketplaceAlloc(
    allocator: std.mem.Allocator,
    existing: []const u8,
    desired: []const u8,
) !MarketplaceMerge {
    var existing_parsed = std.json.parseFromSlice(std.json.Value, allocator, existing, .{}) catch
        return error.InvalidMarketplace;
    defer existing_parsed.deinit();
    var desired_parsed = std.json.parseFromSlice(std.json.Value, allocator, desired, .{}) catch
        return error.InvalidMarketplaceTemplate;
    defer desired_parsed.deinit();

    if (existing_parsed.value != .object or desired_parsed.value != .object)
        return error.InvalidMarketplace;
    const desired_plugins = desired_parsed.value.object.get("plugins") orelse
        return error.InvalidMarketplaceTemplate;
    if (desired_plugins != .array) return error.InvalidMarketplaceTemplate;

    const tree_allocator = existing_parsed.arena.allocator();
    var existing_plugins = existing_parsed.value.object.getPtr("plugins");
    if (existing_plugins == null) {
        try existing_parsed.value.object.put(
            tree_allocator,
            "plugins",
            .{ .array = std.json.Array.init(tree_allocator) },
        );
        existing_plugins = existing_parsed.value.object.getPtr("plugins");
    }
    if (existing_plugins.?.* != .array) return error.InvalidMarketplace;

    for (desired_plugins.array.items) |desired_plugin| {
        const desired_name = pluginName(desired_plugin) orelse return error.InvalidMarketplaceTemplate;
        var replaced = false;
        for (existing_plugins.?.array.items) |*existing_plugin| {
            const existing_name = pluginName(existing_plugin.*) orelse continue;
            if (std.mem.eql(u8, existing_name, desired_name)) {
                existing_plugin.* = desired_plugin;
                replaced = true;
                break;
            }
        }
        if (!replaced) try existing_plugins.?.array.append(desired_plugin);
    }

    const bytes = try std.json.Stringify.valueAlloc(allocator, existing_parsed.value, .{ .whitespace = .indent_2 });
    return .{ .bytes = bytes, .changed = !std.mem.eql(u8, existing, bytes) };
}

fn pluginName(value: std.json.Value) ?[]const u8 {
    if (value != .object) return null;
    const name = value.object.get("name") orelse return null;
    return if (name == .string) name.string else null;
}

pub fn installCodexPlugin(
    io: std.Io,
    allocator: std.mem.Allocator,
    plugin_dir: []const u8,
    workspace_root: []const u8,
    marketplace_json: []const u8,
    stdout: anytype,
) !void {
    const spec = try marketplaceHostInstallSpec(allocator, workspace_root, .codex, marketplace_json);
    defer {
        allocator.free(spec.plugin_dest);
        allocator.free(spec.marketplace_path);
    }
    try installMarketplaceHostPlugin(io, allocator, plugin_dir, spec, stdout);
}

pub fn installClaudePlugin(
    io: std.Io,
    allocator: std.mem.Allocator,
    plugin_dir: []const u8,
    workspace_root: []const u8,
    marketplace_json: []const u8,
    stdout: anytype,
) !void {
    const spec = try marketplaceHostInstallSpec(allocator, workspace_root, .claude, marketplace_json);
    defer {
        allocator.free(spec.plugin_dest);
        allocator.free(spec.marketplace_path);
    }
    try installMarketplaceHostPlugin(io, allocator, plugin_dir, spec, stdout);
}

pub fn printMarketplaceHostInstallPlan(stdout: anytype, spec: MarketplaceHostInstall, plugin_dir: []const u8) !void {
    try stdout.print("  install paths for {s}:\n", .{spec.host_label});
    try stdout.print("    plugin: {s}\n", .{spec.plugin_dest});
    try stdout.print("    marketplace: {s}\n", .{spec.marketplace_path});
    try stdout.print("  next step: copy {s} to {s} and write marketplace file\n", .{ plugin_dir, spec.plugin_dest });
}

fn fileExistsAbsolute(io: std.Io, path: []const u8) bool {
    std.Io.Dir.accessAbsolute(io, path, .{}) catch return false;
    return true;
}

fn pathKindNoFollow(io: std.Io, path: []const u8) !?std.Io.File.Kind {
    const stat = std.Io.Dir.cwd().statFile(io, path, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    return stat.kind;
}

fn refuseSymlinkPath(io: std.Io, path: []const u8, symlink_error: anyerror) !void {
    if (try pathKindNoFollow(io, path)) |kind| {
        if (kind == .sym_link) return symlink_error;
    }
}

const SecureDestination = struct {
    parent: std.Io.Dir,
    basename: []const u8,
};

fn openSecureDestination(io: std.Io, destination_path: []const u8) !SecureDestination {
    if (!std.fs.path.isAbsolute(destination_path)) return error.InvalidPath;
    const parent_path = std.fs.path.dirname(destination_path) orelse return error.InvalidPath;
    const basename = std.fs.path.basename(destination_path);
    if (basename.len == 0 or std.mem.eql(u8, basename, ".") or std.mem.eql(u8, basename, ".."))
        return error.InvalidPath;
    return .{
        .parent = try openOrCreateDirectoryNoSymlinks(io, parent_path),
        .basename = basename,
    };
}

/// Open an absolute directory one component at a time with symlink following
/// disabled. Holding the returned parent handle keeps later create/rename
/// operations anchored even if an attacker concurrently replaces path names.
fn openOrCreateDirectoryNoSymlinks(io: std.Io, absolute_path: []const u8) !std.Io.Dir {
    if (!std.fs.path.isAbsolute(absolute_path)) return error.InvalidPath;

    if (builtin.os.tag == .windows) {
        // Zig's Windows backend does not expose openat-style component walking.
        // Reject a symlink at every currently-existing prefix, then keep the
        // final no-follow handle for all subsequent mutations.
        try refuseSymlinkComponents(io, absolute_path);
        try std.Io.Dir.cwd().createDirPath(io, absolute_path);
        return std.Io.Dir.openDirAbsolute(io, absolute_path, .{ .follow_symlinks = false });
    }

    var current = try std.Io.Dir.openDirAbsolute(io, "/", .{ .follow_symlinks = false });
    errdefer current.close(io);
    var components = std.mem.tokenizeScalar(u8, absolute_path[1..], std.fs.path.sep);
    while (components.next()) |component| {
        if (std.mem.eql(u8, component, ".") or std.mem.eql(u8, component, ".."))
            return error.RefusingPathTraversal;
        const next = current.openDir(io, component, .{ .follow_symlinks = false }) catch |err| switch (err) {
            error.FileNotFound => blk: {
                try current.createDir(io, component, .default_dir);
                break :blk try current.openDir(io, component, .{ .follow_symlinks = false });
            },
            else => return err,
        };
        current.close(io);
        current = next;
    }
    return current;
}

fn refuseSymlinkComponents(io: std.Io, absolute_path: []const u8) !void {
    var end = absolute_path.len;
    while (end > 0) {
        const prefix = absolute_path[0..end];
        if (try pathKindNoFollow(io, prefix)) |kind| {
            if (kind == .sym_link) return error.RefusingSymlinkPluginPath;
        }
        const parent = std.fs.path.dirname(prefix) orelse break;
        if (parent.len >= end) break;
        end = parent.len;
    }
}

fn refuseSymlinkAt(io: std.Io, parent: std.Io.Dir, basename: []const u8, symlink_error: anyerror) !void {
    const stat = parent.statFile(io, basename, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    if (stat.kind == .sym_link) return symlink_error;
}

fn readOptionalFileAtAlloc(
    io: std.Io,
    allocator: std.mem.Allocator,
    parent: std.Io.Dir,
    basename: []const u8,
    max_bytes: usize,
) !?[]u8 {
    return parent.readFileAlloc(io, basename, allocator, .limited(max_bytes)) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
}

fn optionalBytesEqual(lhs: ?[]const u8, rhs: ?[]const u8) bool {
    if (lhs == null or rhs == null) return lhs == null and rhs == null;
    return std.mem.eql(u8, lhs.?, rhs.?);
}

fn writeFileAtomically(
    io: std.Io,
    allocator: std.mem.Allocator,
    content: []const u8,
    destination_path: []const u8,
    temp_prefix: []const u8,
) !void {
    var destination = try openSecureDestination(io, destination_path);
    defer destination.parent.close(io);
    try writeFileAtomicallyAt(
        io,
        allocator,
        content,
        destination.parent,
        destination.basename,
        temp_prefix,
        error.RefusingSymlinkPluginPath,
    );
}

fn writeFileAtomicallyAt(
    io: std.Io,
    allocator: std.mem.Allocator,
    content: []const u8,
    parent: std.Io.Dir,
    basename: []const u8,
    temp_prefix: []const u8,
    symlink_error: anyerror,
) !void {
    try refuseSymlinkAt(io, parent, basename, symlink_error);
    const temp_name = try writeTempFileSyncedAt(
        io,
        allocator,
        content,
        parent,
        basename,
        temp_prefix,
    );
    defer allocator.free(temp_name);
    errdefer parent.deleteFile(io, temp_name) catch {};
    try refuseSymlinkAt(io, parent, basename, symlink_error);
    try parent.rename(
        temp_name,
        parent,
        basename,
        io,
    );
    try syncDirectory(io, parent);
}

fn writeTempFileSyncedAt(
    io: std.Io,
    allocator: std.mem.Allocator,
    content: []const u8,
    parent: std.Io.Dir,
    basename: []const u8,
    temp_prefix: []const u8,
) ![]u8 {
    const timestamp = std.Io.Clock.Timestamp.now(io, .awake).raw.nanoseconds;
    var attempt: usize = 0;
    while (attempt < 16) : (attempt += 1) {
        const sequence = temp_sequence.fetchAdd(1, .monotonic);
        const temp_name = try std.fmt.allocPrint(
            allocator,
            "{s}{s}-{d}-{d}.tmp",
            .{ temp_prefix, basename, timestamp, sequence },
        );
        errdefer allocator.free(temp_name);
        const file = parent.createFile(io, temp_name, .{ .exclusive = true }) catch |err| switch (err) {
            error.PathAlreadyExists => {
                allocator.free(temp_name);
                continue;
            },
            else => return err,
        };
        errdefer {
            file.close(io);
            parent.deleteFile(io, temp_name) catch {};
        }
        try file.writeStreamingAll(io, content);
        try file.sync(io);
        file.close(io);
        return temp_name;
    }
    return error.UnableToCreateTemporaryFile;
}

fn syncDirectory(io: std.Io, directory: std.Io.Dir) !void {
    if (builtin.os.tag == .windows) return;
    // Linux `openDir` without `.iterate` sets O_PATH. fsync(2) on an O_PATH
    // fd returns EBADF, and Zig 0.16 File.sync treats that as a panic.
    // Re-open "." from the already-held dirfd to get a syncable handle.
    var syncable = try directory.openDir(io, ".", .{ .iterate = true, .follow_symlinks = false });
    defer syncable.close(io);
    const parent_as_file: std.Io.File = .{
        .handle = syncable.handle,
        .flags = .{ .nonblocking = false },
    };
    try parent_as_file.sync(io);
}

fn dirExists(io: std.Io, path: []const u8) bool {
    var dir = std.Io.Dir.openDirAbsolute(io, path, .{}) catch return false;
    dir.close(io);
    return true;
}

test "directoriesEquivalent rejects destination with extra stale file" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(std.testing.io, "src");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "src/a.txt", .data = "same" });
    try tmp.dir.createDirPath(std.testing.io, "dst");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "dst/a.txt", .data = "same" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "dst/stale.txt", .data = "old" });

    const src = try tmp.dir.realPathFileAlloc(std.testing.io, "src", std.testing.allocator);
    defer std.testing.allocator.free(src);
    const dst = try tmp.dir.realPathFileAlloc(std.testing.io, "dst", std.testing.allocator);
    defer std.testing.allocator.free(dst);

    try std.testing.expect(!try directoriesEquivalent(std.testing.io, std.testing.allocator, src, dst));
}

test "loadMarketplaceTemplate rewrites bundled source path" {
    const template_path = "integrations/codex-plugin/examples/marketplace.json";
    const json = try loadMarketplaceTemplate(
        std.testing.io,
        std.testing.allocator,
        template_path,
        "./integrations/codex-plugin",
        "./ryk",
    );
    defer std.testing.allocator.free(json);
    try std.testing.expect(std.mem.indexOf(u8, json, "./ryk") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "./integrations/codex-plugin") == null);
}

test "mergeMarketplaceAlloc preserves unrelated plugins and marketplace metadata" {
    const existing =
        \\{"name":"team-marketplace","custom":{"keep":true},"plugins":[{"name":"other","source":"./other"},{"name":"ryk","source":"./old"}]}
    ;
    const desired =
        \\{"name":"ryk-local","plugins":[{"name":"ryk","source":"./ryk"}]}
    ;

    const merged = try mergeMarketplaceAlloc(std.testing.allocator, existing, desired);
    defer std.testing.allocator.free(merged.bytes);

    try std.testing.expect(merged.changed);
    try std.testing.expect(std.mem.indexOf(u8, merged.bytes, "\"name\": \"team-marketplace\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, merged.bytes, "\"keep\": true") != null);
    try std.testing.expect(std.mem.indexOf(u8, merged.bytes, "\"name\": \"other\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, merged.bytes, "\"source\": \"./ryk\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, merged.bytes, "./old") == null);
}

test "mergeMarketplaceAlloc rejects an invalid existing plugins shape" {
    try std.testing.expectError(
        error.InvalidMarketplace,
        mergeMarketplaceAlloc(
            std.testing.allocator,
            \\{"plugins":{}}
        ,
            \\{"plugins":[{"name":"ryk","source":"./ryk"}]}
            ,
        ),
    );
}

test "installDirectoryIfSafe refuses an arbitrary destination without deleting it" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(std.testing.io, "source/.codex-plugin");
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "source/.codex-plugin/plugin.json",
        .data =
        \\{"name":"ryk","author":{"name":"ryk"},"interface":{"displayName":"ryk"}}
        ,
    });
    try tmp.dir.createDirPath(std.testing.io, "destination");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "destination/user.txt", .data = "keep me" });

    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const source = try std.fs.path.join(std.testing.allocator, &.{ root, "source" });
    defer std.testing.allocator.free(source);
    const destination = try std.fs.path.join(std.testing.allocator, &.{ root, "destination" });
    defer std.testing.allocator.free(destination);

    try std.testing.expectError(
        error.RefusingToOverwriteUnownedPlugin,
        installDirectoryIfSafe(std.testing.io, std.testing.allocator, source, destination, true),
    );
    const user_bytes = try tmp.dir.readFileAlloc(
        std.testing.io,
        "destination/user.txt",
        std.testing.allocator,
        .limited(64),
    );
    defer std.testing.allocator.free(user_bytes);
    try std.testing.expectEqualStrings("keep me", user_bytes);
}

test "installDirectoryIfSafe refuses a symlink destination and leaves its target unchanged" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(std.testing.io, "source/.codex-plugin");
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "source/.codex-plugin/plugin.json",
        .data =
        \\{"name":"ryk","author":{"name":"ryk"},"interface":{"displayName":"ryk"}}
        ,
    });
    try tmp.dir.createDirPath(std.testing.io, "outside");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "outside/user.txt", .data = "outside" });
    try tmp.dir.symLink(std.testing.io, "outside", "destination", .{});

    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const source = try std.fs.path.join(std.testing.allocator, &.{ root, "source" });
    defer std.testing.allocator.free(source);
    const destination = try std.fs.path.join(std.testing.allocator, &.{ root, "destination" });
    defer std.testing.allocator.free(destination);

    try std.testing.expectError(
        error.RefusingSymlinkPluginPath,
        installDirectoryIfSafe(std.testing.io, std.testing.allocator, source, destination, true),
    );
    const outside = try tmp.dir.readFileAlloc(
        std.testing.io,
        "outside/user.txt",
        std.testing.allocator,
        .limited(64),
    );
    defer std.testing.allocator.free(outside);
    try std.testing.expectEqualStrings("outside", outside);
}

test "installDirectoryIfSafe refuses a symlinked parent component" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(std.testing.io, "source/.codex-plugin");
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "source/.codex-plugin/plugin.json",
        .data =
        \\{"name":"ryk","author":{"name":"ryk"},"interface":{"displayName":"ryk"}}
        ,
    });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "source/managed.txt", .data = "managed" });
    try tmp.dir.createDirPath(std.testing.io, "outside");
    try tmp.dir.symLink(std.testing.io, "outside", "linked-parent", .{});

    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const source = try std.fs.path.join(std.testing.allocator, &.{ root, "source" });
    defer std.testing.allocator.free(source);
    const destination = try std.fs.path.join(std.testing.allocator, &.{ root, "linked-parent", "plugin" });
    defer std.testing.allocator.free(destination);

    try std.testing.expectError(
        error.NotDir,
        installDirectoryIfSafe(std.testing.io, std.testing.allocator, source, destination, true),
    );
    try std.testing.expectError(
        error.FileNotFound,
        tmp.dir.access(std.testing.io, "outside/plugin/managed.txt", .{}),
    );
}

test "installDirectoryIfSafe upgrades a managed destination without removing unrelated files" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const manifest =
        \\{"name":"ryk","author":{"name":"ryk"},"interface":{"displayName":"ryk"}}
    ;
    try tmp.dir.createDirPath(std.testing.io, "source/.codex-plugin");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "source/.codex-plugin/plugin.json", .data = manifest });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "source/managed.txt", .data = "new" });
    try tmp.dir.createDirPath(std.testing.io, "destination/.codex-plugin");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "destination/.codex-plugin/plugin.json", .data = manifest });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "destination/managed.txt", .data = "old" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "destination/user.txt", .data = "keep me" });

    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const source = try std.fs.path.join(std.testing.allocator, &.{ root, "source" });
    defer std.testing.allocator.free(source);
    const destination = try std.fs.path.join(std.testing.allocator, &.{ root, "destination" });
    defer std.testing.allocator.free(destination);

    try installDirectoryIfSafe(std.testing.io, std.testing.allocator, source, destination, true);

    const managed = try tmp.dir.readFileAlloc(
        std.testing.io,
        "destination/managed.txt",
        std.testing.allocator,
        .limited(64),
    );
    defer std.testing.allocator.free(managed);
    try std.testing.expectEqualStrings("new", managed);
    const user_bytes = try tmp.dir.readFileAlloc(
        std.testing.io,
        "destination/user.txt",
        std.testing.allocator,
        .limited(64),
    );
    defer std.testing.allocator.free(user_bytes);
    try std.testing.expectEqualStrings("keep me", user_bytes);
}

test "marketplace atomic write revalidates concurrent changes and removes its temp file" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "marketplace.json", .data = "raced" });
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const destination = try std.fs.path.join(std.testing.allocator, &.{ root, "marketplace.json" });
    defer std.testing.allocator.free(destination);

    try std.testing.expectError(
        error.ConcurrentMarketplaceUpdate,
        installMarketplaceTextAtomically(
            std.testing.io,
            std.testing.allocator,
            "new",
            destination,
            "old",
        ),
    );
    const actual = try tmp.dir.readFileAlloc(
        std.testing.io,
        "marketplace.json",
        std.testing.allocator,
        .limited(64),
    );
    defer std.testing.allocator.free(actual);
    try std.testing.expectEqualStrings("raced", actual);

    var it = tmp.dir.iterate();
    while (try it.next(std.testing.io)) |entry| {
        try std.testing.expect(std.mem.indexOf(u8, entry.name, ".ryk-marketplace-") == null);
    }
}

test "marketplace atomic write is idempotent and refuses symlink destinations" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const destination = try std.fs.path.join(std.testing.allocator, &.{ root, "marketplace.json" });
    defer std.testing.allocator.free(destination);

    try std.testing.expect(try installMarketplaceTextAtomically(
        std.testing.io,
        std.testing.allocator,
        "first",
        destination,
        null,
    ));
    try std.testing.expect(!try installMarketplaceTextAtomically(
        std.testing.io,
        std.testing.allocator,
        "first",
        destination,
        "first",
    ));

    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "outside.json", .data = "outside" });
    try tmp.dir.symLink(std.testing.io, "outside.json", "linked.json", .{});
    const linked = try std.fs.path.join(std.testing.allocator, &.{ root, "linked.json" });
    defer std.testing.allocator.free(linked);
    try std.testing.expectError(
        error.RefusingSymlinkMarketplace,
        installMarketplaceTextAtomically(
            std.testing.io,
            std.testing.allocator,
            "new",
            linked,
            null,
        ),
    );
    const outside = try tmp.dir.readFileAlloc(
        std.testing.io,
        "outside.json",
        std.testing.allocator,
        .limited(64),
    );
    defer std.testing.allocator.free(outside);
    try std.testing.expectEqualStrings("outside", outside);
}

test "marketplace atomic write refuses a symlinked parent component" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "outside");
    try tmp.dir.symLink(std.testing.io, "outside", "linked-parent", .{});

    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const destination = try std.fs.path.join(std.testing.allocator, &.{ root, "linked-parent", "marketplace.json" });
    defer std.testing.allocator.free(destination);

    try std.testing.expectError(
        error.NotDir,
        installMarketplaceTextAtomically(
            std.testing.io,
            std.testing.allocator,
            "new",
            destination,
            null,
        ),
    );
    try std.testing.expectError(
        error.FileNotFound,
        tmp.dir.access(std.testing.io, "outside/marketplace.json", .{}),
    );
}

test "marketplace registration validation requires the exact host source" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "marketplace.json",
        .data =
        \\{"plugins":[
        \\  {"name":"other","source":{"source":"local","path":"./ryk"}},
        \\  {"name":"ryk","source":{"source":"local","path":"./ryk"}}
        \\]}
        ,
    });
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const path = try std.fs.path.join(std.testing.allocator, &.{ root, "marketplace.json" });
    defer std.testing.allocator.free(path);

    try std.testing.expect(marketplaceRegistersExpectedPlugin(
        std.testing.io,
        std.testing.allocator,
        path,
        .codex,
    ));
    try std.testing.expect(!marketplaceRegistersExpectedPlugin(
        std.testing.io,
        std.testing.allocator,
        path,
        .claude,
    ));

    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "marketplace.json",
        .data =
        \\{"plugins":[{"name":"ryk","source":"../.claude/plugins/ryk"}]}
        ,
    });
    try std.testing.expect(marketplaceRegistersExpectedPlugin(
        std.testing.io,
        std.testing.allocator,
        path,
        .claude,
    ));
    try std.testing.expect(!marketplaceRegistersExpectedPlugin(
        std.testing.io,
        std.testing.allocator,
        path,
        .codex,
    ));
}

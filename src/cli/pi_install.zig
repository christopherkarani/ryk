//! Idempotent installation of the bundled ryk extension for Pi.

const std = @import("std");
const builtin = @import("builtin");
const resource_root = @import("../resource_root.zig");
const env_util = @import("../env_util.zig");

pub const ownership_marker = "// Managed by ryk. Updates may replace this file; do not edit it directly.\n";
pub const relative_install_dir = ".pi/agent/extensions/ryk";

pub const InstallResult = enum {
    installed,
    upgraded,
    already_installed,
    assets_unavailable,
};

pub const InstallOptions = struct {
    /// Explicit home keeps onboarding deterministic and prevents tests from
    /// reading or writing the developer's real HOME.
    home: []const u8,
    /// Exact installed ryk executable. The generated wrapper injects this path
    /// so Pi never depends on PATH, npm, or shell profile activation.
    ryk_binary: []const u8,
    /// Test/package injection. Production callers normally use resource lookup.
    asset_dir: ?[]const u8 = null,
    resource_root_override: ?[]const u8 = null,
    /// Workspace root for resource resolution (default `.`). Tests may pin an
    /// empty/missing tree so resource_root_override / packaged paths are exercised.
    workspace_root: []const u8 = ".",
};

const Asset = struct {
    source_name: []const u8,
    destination_name: []const u8,
};

const assets = [_]Asset{
    .{ .source_name = "ryk.ts", .destination_name = "runtime.ts" },
    .{ .source_name = "secret_capture.ts", .destination_name = "secret_capture.ts" },
    .{ .source_name = "parent_ask.ts", .destination_name = "parent_ask.ts" },
};

const installed_files = [_][]const u8{ "index.ts", "runtime.ts", "secret_capture.ts", "parent_ask.ts" };

const DestinationState = enum {
    missing,
    current,
    managed_outdated,
};

pub fn install(
    io: std.Io,
    allocator: std.mem.Allocator,
    options: InstallOptions,
) !InstallResult {
    if (!std.fs.path.isAbsolute(options.home)) return error.InvalidHomePath;
    if (!std.fs.path.isAbsolute(options.ryk_binary)) return error.InvalidRykBinaryPath;

    const asset_dir = resolveAssetDir(io, allocator, options) catch |err| switch (err) {
        error.ResourceNotFound => return .assets_unavailable,
        else => return err,
    };
    defer allocator.free(asset_dir);

    var rendered: [installed_files.len][]u8 = undefined;
    var rendered_count: usize = 0;
    defer for (rendered[0..rendered_count]) |bytes| allocator.free(bytes);

    const quoted_binary = try std.json.Stringify.valueAlloc(allocator, options.ryk_binary, .{});
    defer allocator.free(quoted_binary);
    rendered[0] = try std.fmt.allocPrint(
        allocator,
        ownership_marker ++
            \\import {{ installRykExtension }} from "./runtime.ts";
            \\
            \\export default function rykPiExtension(
            \\  pi: Parameters<typeof installRykExtension>[0],
            \\): void {{
            \\  installRykExtension(pi, {{ rykBin: {s} }});
            \\}}
            \\
        ,
        .{quoted_binary},
    );
    rendered_count += 1;

    for (assets, 0..) |asset, index| {
        const source_path = try std.fs.path.join(allocator, &.{ asset_dir, asset.source_name });
        defer allocator.free(source_path);
        const source = readRegularFile(io, allocator, source_path) catch |err| switch (err) {
            error.FileNotFound, error.NotDir => return .assets_unavailable,
            else => return err,
        };
        defer allocator.free(source);

        rendered[index + 1] = try std.mem.concat(allocator, u8, &.{ ownership_marker, source });
        rendered_count += 1;
    }

    const destination_dir = try std.fs.path.join(allocator, &.{ options.home, relative_install_dir });
    defer allocator.free(destination_dir);
    try ensureDestinationDirectory(io, allocator, options.home);

    var states: [installed_files.len]DestinationState = undefined;
    for (installed_files, 0..) |destination_name, index| {
        const destination_path = try std.fs.path.join(allocator, &.{ destination_dir, destination_name });
        defer allocator.free(destination_path);
        states[index] = try inspectDestination(io, allocator, destination_path, rendered[index]);
    }

    var changed = false;
    var upgraded = false;
    for (installed_files, 0..) |destination_name, index| {
        if (states[index] == .current) continue;
        const destination_path = try std.fs.path.join(allocator, &.{ destination_dir, destination_name });
        defer allocator.free(destination_path);
        // Recheck immediately before replacing to reject ordinary concurrent
        // edits that happened after the all-files preflight.
        const current_state = try inspectDestination(io, allocator, destination_path, rendered[index]);
        if (current_state == .current) continue;
        upgraded = upgraded or current_state == .managed_outdated;
        try writeAtomically(io, allocator, destination_path, rendered[index]);
        changed = true;
    }

    if (!isCompleteAtHome(io, allocator, options.home)) return error.IncompleteInstall;
    if (!changed) return .already_installed;
    return if (upgraded) .upgraded else .installed;
}

pub fn isCompleteAtHome(io: std.Io, allocator: std.mem.Allocator, home: []const u8) bool {
    if (!std.fs.path.isAbsolute(home)) return false;
    if (!destinationChainIsSafe(io, allocator, home)) return false;
    for (installed_files) |destination_name| {
        const path = std.fs.path.join(allocator, &.{ home, relative_install_dir, destination_name }) catch return false;
        defer allocator.free(path);
        const content = readRegularFile(io, allocator, path) catch return false;
        defer allocator.free(content);
        if (!std.mem.startsWith(u8, content, ownership_marker)) return false;
        if (!hasExpectedInstalledShape(destination_name, content)) return false;
    }
    return true;
}

fn destinationChainIsSafe(io: std.Io, allocator: std.mem.Allocator, home: []const u8) bool {
    requireOrdinaryDirectory(io, home) catch return false;
    const components = [_][]const u8{ ".pi", "agent", "extensions", "ryk" };
    var current = allocator.dupe(u8, home) catch return false;
    defer allocator.free(current);
    for (components) |component| {
        const next = std.fs.path.join(allocator, &.{ current, component }) catch return false;
        allocator.free(current);
        current = next;
        requireOrdinaryDirectory(io, current) catch return false;
    }
    return true;
}

fn hasExpectedInstalledShape(destination_name: []const u8, content: []const u8) bool {
    if (std.mem.eql(u8, destination_name, "index.ts")) {
        return std.mem.indexOf(u8, content, "from \"./runtime.ts\"") != null and
            std.mem.indexOf(u8, content, "installRykExtension(pi, { rykBin: \"") != null;
    }
    if (std.mem.eql(u8, destination_name, "runtime.ts")) {
        return std.mem.indexOf(u8, content, "from \"./secret_capture.ts\"") != null and
            std.mem.indexOf(u8, content, "from \"./parent_ask.ts\"") != null and
            std.mem.indexOf(u8, content, "export function installRykExtension") != null;
    }
    if (std.mem.eql(u8, destination_name, "secret_capture.ts")) {
        return std.mem.indexOf(u8, content, "export function storeSecretToEnvFile") != null and
            std.mem.indexOf(u8, content, "export async function handleSecretCaptureInput") != null;
    }
    if (std.mem.eql(u8, destination_name, "parent_ask.ts")) {
        // Real packaged source uses `export async function waitForAskResponse`.
        return std.mem.indexOf(u8, content, "export function resolvePiAskRoot") != null and
            (std.mem.indexOf(u8, content, "export function waitForAskResponse") != null or
                std.mem.indexOf(u8, content, "export async function waitForAskResponse") != null);
    }
    return false;
}

fn resolveAssetDir(io: std.Io, allocator: std.mem.Allocator, options: InstallOptions) ![]u8 {
    if (options.asset_dir) |path| return allocator.dupe(u8, path);
    // Primary: ryk-pi/extensions via resource_root (workspace, RYK_RESOURCE_ROOT,
    // exe-relative, $PREFIX/share/ryk/current). Does not fall back to orca-pi —
    // those assets lack installRykExtension and would leave incomplete installs.
    if (resource_root.resolveResourcePath(io, allocator, .{
        .workspace_root = options.workspace_root,
        .resource_root_override = options.resource_root_override,
    }, "ryk-pi/extensions")) |resolved| {
        return resolved;
    } else |_| {}

    // When env RYK_RESOURCE_ROOT points at a stale orca tree, resolveResourcePath
    // still falls through to share/ryk/current — but a bare HOME package without
    // a product binary nearby can miss that. Probe the standard data home layout.
    return resolvePackagedRykPiExtensions(io, allocator) orelse error.ResourceNotFound;
}

/// `$XDG_DATA_HOME/ryk/current/ryk-pi/extensions` then `~/.local/share/ryk/current/…`.
fn resolvePackagedRykPiExtensions(io: std.Io, allocator: std.mem.Allocator) ?[]u8 {
    var env_map = env_util.createProcessMap(allocator) catch return null;
    defer env_map.deinit();

    if (env_util.getOwned(&env_map, allocator, "XDG_DATA_HOME") catch null) |xdg| {
        defer allocator.free(xdg);
        if (joinIfExists(io, allocator, &.{ xdg, "ryk", "current", "ryk-pi", "extensions" })) |path| return path;
    }
    if (env_util.getOwnedHome(&env_map, allocator) catch null) |home| {
        defer allocator.free(home);
        if (joinIfExists(io, allocator, &.{ home, ".local", "share", "ryk", "current", "ryk-pi", "extensions" })) |path|
            return path;
    }
    return null;
}

fn joinIfExists(io: std.Io, allocator: std.mem.Allocator, parts: []const []const u8) ?[]u8 {
    const path = std.fs.path.join(allocator, parts) catch return null;
    std.Io.Dir.cwd().access(io, path, .{}) catch {
        allocator.free(path);
        return null;
    };
    return path;
}

fn ensureDestinationDirectory(io: std.Io, allocator: std.mem.Allocator, home: []const u8) !void {
    try requireOrdinaryDirectory(io, home);
    const components = [_][]const u8{ ".pi", "agent", "extensions", "ryk" };
    var current = try allocator.dupe(u8, home);
    defer allocator.free(current);

    for (components) |component| {
        const next = try std.fs.path.join(allocator, &.{ current, component });
        allocator.free(current);
        current = next;

        const stat = std.Io.Dir.cwd().statFile(io, current, .{ .follow_symlinks = false }) catch |err| switch (err) {
            error.FileNotFound => {
                try std.Io.Dir.cwd().createDir(io, current, .default_dir);
                try requireOrdinaryDirectory(io, current);
                continue;
            },
            else => return err,
        };
        if (stat.kind == .sym_link) return error.UnsafeDestination;
        if (stat.kind != .directory) return error.NotDir;
    }
}

fn requireOrdinaryDirectory(io: std.Io, path: []const u8) !void {
    const stat = try std.Io.Dir.cwd().statFile(io, path, .{ .follow_symlinks = false });
    if (stat.kind == .sym_link) return error.UnsafeDestination;
    if (stat.kind != .directory) return error.NotDir;
}

fn readRegularFile(io: std.Io, allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const stat = try std.Io.Dir.cwd().statFile(io, path, .{ .follow_symlinks = false });
    if (stat.kind == .sym_link) return error.UnsafeSymlink;
    if (stat.kind != .file) return error.NotAFile;
    return std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(2 * 1024 * 1024));
}

fn inspectDestination(
    io: std.Io,
    allocator: std.mem.Allocator,
    path: []const u8,
    expected: []const u8,
) !DestinationState {
    const stat = std.Io.Dir.cwd().statFile(io, path, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return .missing,
        else => return err,
    };
    if (stat.kind == .sym_link) return error.UnsafeDestination;
    if (stat.kind != .file) return error.UnsafeDestination;

    const existing = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(2 * 1024 * 1024));
    defer allocator.free(existing);
    if (std.mem.eql(u8, existing, expected)) return .current;
    if (std.mem.startsWith(u8, existing, ownership_marker)) return .managed_outdated;
    return error.RefusingToOverwriteUnownedFile;
}

fn writeAtomically(io: std.Io, allocator: std.mem.Allocator, destination_path: []const u8, bytes: []const u8) !void {
    const nonce = std.Io.Clock.Timestamp.now(io, .awake).raw.nanoseconds;
    const temp_path = try std.fmt.allocPrint(allocator, "{s}.ryk-install-{d}.tmp", .{ destination_path, nonce });
    defer allocator.free(temp_path);
    errdefer std.Io.Dir.cwd().deleteFile(io, temp_path) catch {};

    {
        const file = try std.Io.Dir.cwd().createFile(io, temp_path, .{ .exclusive = true });
        defer file.close(io);
        try file.writeStreamingAll(io, bytes);
        try file.sync(io);
    }
    try std.Io.Dir.renameAbsolute(temp_path, destination_path, io);
    try syncParentDirectory(io, destination_path);
}

fn syncParentDirectory(io: std.Io, destination_path: []const u8) !void {
    if (builtin.os.tag == .windows) return;
    const parent_path = std.fs.path.dirname(destination_path) orelse return error.InvalidDestinationPath;
    var parent = try std.Io.Dir.openDirAbsolute(io, parent_path, .{ .follow_symlinks = false });
    defer parent.close(io);
    // Linux `openDir` without `.iterate` sets O_PATH. fsync(2) on an O_PATH
    // fd returns EBADF, and Zig 0.16 File.sync treats that as a panic.
    var syncable = try parent.openDir(io, ".", .{ .iterate = true, .follow_symlinks = false });
    defer syncable.close(io);
    const parent_as_file: std.Io.File = .{
        .handle = syncable.handle,
        .flags = .{ .nonblocking = false },
    };
    try parent_as_file.sync(io);
}

fn writeFixtureAssets(io: std.Io, dir: std.Io.Dir) !void {
    try dir.createDirPath(io, "assets");
    try dir.writeFile(io, .{
        .sub_path = "assets/ryk.ts",
        .data =
        \\import { handleSecretCaptureInput } from "./secret_capture.ts";
        \\import { resolvePiAskRoot } from "./parent_ask.ts";
        \\export function installRykExtension() {}
        \\
        ,
    });
    try dir.writeFile(io, .{
        .sub_path = "assets/secret_capture.ts",
        .data =
        \\export function storeSecretToEnvFile() {}
        \\export async function handleSecretCaptureInput() {}
        \\
        ,
    });
    try dir.writeFile(io, .{
        .sub_path = "assets/parent_ask.ts",
        .data =
        \\export function resolvePiAskRoot() {}
        \\export async function waitForAskResponse() {}
        \\
        ,
    });
}

test "Pi completeness accepts async waitForAskResponse from packaged parent_ask" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, relative_install_dir);
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = relative_install_dir ++ "/index.ts",
        .data = ownership_marker ++
            \\import { installRykExtension } from "./runtime.ts";
            \\export default function rykPiExtension(pi: Parameters<typeof installRykExtension>[0]): void {
            \\  installRykExtension(pi, { rykBin: "/opt/ryk/bin/ryk" });
            \\}
            \\
        ,
    });
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = relative_install_dir ++ "/runtime.ts",
        .data = ownership_marker ++
            \\import { handleSecretCaptureInput } from "./secret_capture.ts";
            \\import { resolvePiAskRoot } from "./parent_ask.ts";
            \\export function installRykExtension() {}
            \\
        ,
    });
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = relative_install_dir ++ "/secret_capture.ts",
        .data = ownership_marker ++
            \\export function storeSecretToEnvFile() {}
            \\export async function handleSecretCaptureInput() {}
            \\
        ,
    });
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = relative_install_dir ++ "/parent_ask.ts",
        .data = ownership_marker ++
            \\export function resolvePiAskRoot() {}
            \\export async function waitForAskResponse() {}
            \\
        ,
    });
    const home = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(home);
    try std.testing.expect(isCompleteAtHome(std.testing.io, std.testing.allocator, home));
}

test "Pi install creates a complete extension and is idempotent" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeFixtureAssets(std.testing.io, tmp.dir);
    const home = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(home);
    const asset_dir = try std.fs.path.join(std.testing.allocator, &.{ home, "assets" });
    defer std.testing.allocator.free(asset_dir);

    try std.testing.expectEqual(InstallResult.installed, try install(std.testing.io, std.testing.allocator, .{
        .home = home,
        .ryk_binary = "/opt/ryk/bin/ryk",
        .asset_dir = asset_dir,
    }));
    const wrapper = try tmp.dir.readFileAlloc(std.testing.io, relative_install_dir ++ "/index.ts", std.testing.allocator, .limited(4096));
    defer std.testing.allocator.free(wrapper);
    try std.testing.expect(std.mem.indexOf(u8, wrapper, "ryk.ts") == null);
    try std.testing.expect(std.mem.indexOf(u8, wrapper, "../package.json") == null);
    try std.testing.expect(std.mem.indexOf(u8, wrapper, "\"/opt/ryk/bin/ryk\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, wrapper, "./runtime.ts") != null);
    try std.testing.expect(isCompleteAtHome(std.testing.io, std.testing.allocator, home));
    try std.testing.expectEqual(InstallResult.already_installed, try install(std.testing.io, std.testing.allocator, .{
        .home = home,
        .ryk_binary = "/opt/ryk/bin/ryk",
        .asset_dir = asset_dir,
    }));
}

test "Pi install upgrades only ownership-marked files" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeFixtureAssets(std.testing.io, tmp.dir);
    try tmp.dir.createDirPath(std.testing.io, relative_install_dir);
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = relative_install_dir ++ "/index.ts",
        .data = ownership_marker ++ "old managed extension\n",
    });
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = relative_install_dir ++ "/runtime.ts",
        .data = ownership_marker ++ "old managed runtime\n",
    });
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = relative_install_dir ++ "/secret_capture.ts",
        .data = ownership_marker ++ "old managed capture\n",
    });
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = relative_install_dir ++ "/parent_ask.ts",
        .data = ownership_marker ++ "old managed parent ask\n",
    });
    const home = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(home);
    const asset_dir = try std.fs.path.join(std.testing.allocator, &.{ home, "assets" });
    defer std.testing.allocator.free(asset_dir);

    try std.testing.expectEqual(InstallResult.upgraded, try install(std.testing.io, std.testing.allocator, .{
        .home = home,
        .ryk_binary = "/opt/ryk/bin/ryk",
        .asset_dir = asset_dir,
    }));
    try std.testing.expect(isCompleteAtHome(std.testing.io, std.testing.allocator, home));
}

test "Pi install refuses an unowned file without modifying it" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeFixtureAssets(std.testing.io, tmp.dir);
    try tmp.dir.createDirPath(std.testing.io, relative_install_dir);
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = relative_install_dir ++ "/index.ts",
        .data = "user extension\n",
    });
    const home = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(home);
    const asset_dir = try std.fs.path.join(std.testing.allocator, &.{ home, "assets" });
    defer std.testing.allocator.free(asset_dir);

    try std.testing.expectError(error.RefusingToOverwriteUnownedFile, install(std.testing.io, std.testing.allocator, .{
        .home = home,
        .ryk_binary = "/opt/ryk/bin/ryk",
        .asset_dir = asset_dir,
    }));
    const content = try tmp.dir.readFileAlloc(std.testing.io, relative_install_dir ++ "/index.ts", std.testing.allocator, .limited(1024));
    defer std.testing.allocator.free(content);
    try std.testing.expectEqualStrings("user extension\n", content);
}

test "Pi install rejects a symlink destination" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeFixtureAssets(std.testing.io, tmp.dir);
    try tmp.dir.createDirPath(std.testing.io, relative_install_dir);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "outside.ts", .data = "do not replace\n" });
    tmp.dir.symLink(std.testing.io, "../../../outside.ts", relative_install_dir ++ "/index.ts", .{}) catch
        return error.SkipZigTest;
    const home = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(home);
    const asset_dir = try std.fs.path.join(std.testing.allocator, &.{ home, "assets" });
    defer std.testing.allocator.free(asset_dir);

    try std.testing.expectError(error.UnsafeDestination, install(std.testing.io, std.testing.allocator, .{
        .home = home,
        .ryk_binary = "/opt/ryk/bin/ryk",
        .asset_dir = asset_dir,
    }));
}

test "Pi install returns unavailable without bundled assets and rejects relative HOME" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(home);
    const missing = try std.fs.path.join(std.testing.allocator, &.{ home, "missing" });
    defer std.testing.allocator.free(missing);

    try std.testing.expectEqual(InstallResult.assets_unavailable, try install(std.testing.io, std.testing.allocator, .{
        .home = home,
        .ryk_binary = "/opt/ryk/bin/ryk",
        .asset_dir = missing,
    }));
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(std.testing.io, ".pi", .{}));
    try std.testing.expectError(error.InvalidHomePath, install(std.testing.io, std.testing.allocator, .{
        .home = "relative-home",
        .ryk_binary = "/opt/ryk/bin/ryk",
        .asset_dir = missing,
    }));
}

test "Pi install rejects symlinked parent directory traversal" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeFixtureAssets(std.testing.io, tmp.dir);
    try tmp.dir.createDirPath(std.testing.io, "outside/agent/extensions");
    tmp.dir.symLink(std.testing.io, "outside", ".pi", .{}) catch return error.SkipZigTest;
    const home = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(home);
    const asset_dir = try std.fs.path.join(std.testing.allocator, &.{ home, "assets" });
    defer std.testing.allocator.free(asset_dir);

    try std.testing.expectError(error.UnsafeDestination, install(std.testing.io, std.testing.allocator, .{
        .home = home,
        .ryk_binary = "/opt/ryk/bin/ryk",
        .asset_dir = asset_dir,
    }));
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(std.testing.io, "outside/agent/extensions/ryk", .{}));
    try std.testing.expect(!isCompleteAtHome(std.testing.io, std.testing.allocator, home));
}

test "Pi completeness rejects ownership-marker-only spoof files" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, relative_install_dir);
    inline for (installed_files) |destination_name| {
        try tmp.dir.writeFile(std.testing.io, .{
            .sub_path = relative_install_dir ++ "/" ++ destination_name,
            .data = ownership_marker ++ "not a ryk Pi integration\n",
        });
    }
    const home = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(home);
    try std.testing.expect(!isCompleteAtHome(std.testing.io, std.testing.allocator, home));
}

test "Pi install upgrades ownership-marked orca-shaped index to installRykExtension" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeFixtureAssets(std.testing.io, tmp.dir);
    try tmp.dir.createDirPath(std.testing.io, relative_install_dir);
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = relative_install_dir ++ "/index.ts",
        .data = ownership_marker ++
            \\import { installOrcaExtension } from "./runtime.ts";
            \\export default function (pi: any) {
            \\  installOrcaExtension(pi, { orcaBin: "/opt/orca/bin/orca" });
            \\}
            \\
        ,
    });
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = relative_install_dir ++ "/runtime.ts",
        .data = ownership_marker ++ "export function installOrcaExtension() {}\n",
    });
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = relative_install_dir ++ "/secret_capture.ts",
        .data = ownership_marker ++ "old\n",
    });
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = relative_install_dir ++ "/parent_ask.ts",
        .data = ownership_marker ++ "old\n",
    });
    const home = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(home);
    const asset_dir = try std.fs.path.join(std.testing.allocator, &.{ home, "assets" });
    defer std.testing.allocator.free(asset_dir);

    try std.testing.expect(!isCompleteAtHome(std.testing.io, std.testing.allocator, home));
    try std.testing.expectEqual(InstallResult.upgraded, try install(std.testing.io, std.testing.allocator, .{
        .home = home,
        .ryk_binary = "/opt/ryk/bin/ryk",
        .asset_dir = asset_dir,
    }));
    try std.testing.expect(isCompleteAtHome(std.testing.io, std.testing.allocator, home));
    const wrapper = try tmp.dir.readFileAlloc(std.testing.io, relative_install_dir ++ "/index.ts", std.testing.allocator, .limited(4096));
    defer std.testing.allocator.free(wrapper);
    try std.testing.expect(std.mem.indexOf(u8, wrapper, "installRykExtension") != null);
    try std.testing.expect(std.mem.indexOf(u8, wrapper, "rykBin") != null);
    try std.testing.expect(std.mem.indexOf(u8, wrapper, "installOrcaExtension") == null);
}

test "Pi resolveAssetDir finds ryk-pi under resource_root_override packaged layout" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "share/ryk/current/ryk-pi/extensions");
    try tmp.dir.createDirPath(std.testing.io, "home-root");
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "share/ryk/current/ryk-pi/extensions/ryk.ts",
        .data =
        \\import { handleSecretCaptureInput } from "./secret_capture.ts";
        \\import { resolvePiAskRoot } from "./parent_ask.ts";
        \\export function installRykExtension() {}
        \\
        ,
    });
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "share/ryk/current/ryk-pi/extensions/secret_capture.ts",
        .data =
        \\export function storeSecretToEnvFile() {}
        \\export async function handleSecretCaptureInput() {}
        \\
        ,
    });
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "share/ryk/current/ryk-pi/extensions/parent_ask.ts",
        .data =
        \\export function resolvePiAskRoot() {}
        \\export function waitForAskResponse() {}
        \\
        ,
    });
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const packaged = try std.fs.path.join(std.testing.allocator, &.{ root, "share", "ryk", "current" });
    defer std.testing.allocator.free(packaged);
    const home = try std.fs.path.join(std.testing.allocator, &.{ root, "home-root" });
    defer std.testing.allocator.free(home);

    // Pin workspace away from the repo tree so override/packaged layout is the
    // only resolution path (otherwise cwd `./ryk-pi/extensions` wins first).
    const empty_ws = try std.fs.path.join(std.testing.allocator, &.{ root, "empty-ws" });
    defer std.testing.allocator.free(empty_ws);
    try tmp.dir.createDirPath(std.testing.io, "empty-ws");

    try std.testing.expectEqual(InstallResult.installed, try install(std.testing.io, std.testing.allocator, .{
        .home = home,
        .ryk_binary = "/opt/ryk/bin/ryk",
        .resource_root_override = packaged,
        .workspace_root = empty_ws,
    }));
    try std.testing.expect(isCompleteAtHome(std.testing.io, std.testing.allocator, home));
}

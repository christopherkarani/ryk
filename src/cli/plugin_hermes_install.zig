//! Hermes plugin install primitives (paths, receipt ownership, atomic bundle,
//! enable/disable, unattended preflight, stance/helper writes).
//!
//! Product orchestration stays in `plugin.zig`: install command, doctor collect,
//! `trustedHostBinary`, and `hardenHermesUnattendedInstall` (thin wrapper).
//! This file must not import `plugin.zig` (one-way). Overlay ≠ OS-enforced.

const std = @import("std");

const plugin_install = @import("plugin_install.zig");
const child_process = @import("child_process.zig");
const env_util = @import("../env_util.zig");
const host_status = @import("host_status.zig");

const hermes_managed_receipt_filename = ".ryk-managed-v1";
const hermes_unattended_marker_filename = ".ryk_unattended";
// Exact hashes for the pre-receipt Ryk bundle. This bounded legacy allowance
// lets an existing, unmodified Ryk install migrate once without accepting
// copied manifest text as ownership evidence.
const hermes_legacy_manifest_sha256 = "9276b8a93a46772e5b0511b10ed699675dbc606be26fba98e35521aff761ca53";
const hermes_legacy_source_sha256 = "1eb89889cf8ec15392c6c0a6a30b602d924b72cb754af80864ca79203d3545b2";
const hermes_legacy_mapping_sha256 = "7753c18b13f036c702ca57a815b4c3f97823907243f79cea94bb7aed501d4221";

fn sha256Hex(bytes: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

fn fileContains(allocator: std.mem.Allocator, path: []const u8, needle: []const u8) bool {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const content = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(1024 * 1024)) catch return false;
    defer allocator.free(content);
    return std.mem.indexOf(u8, content, needle) != null;
}

fn dirExists(path: []const u8) bool {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    var dir = std.Io.Dir.cwd().openDir(io, path, .{}) catch return false;
    defer dir.close(io);
    return true;
}

pub fn hermesUserPluginRoot(allocator: std.mem.Allocator) ![]u8 {
    var env_map = env_util.createProcessMap(allocator) catch return std.fs.path.join(allocator, &.{ "~", ".hermes", "plugins", "ryk" });
    defer env_map.deinit();
    const hermes_home = try hermesHomeFromEnvMap(allocator, &env_map);
    defer allocator.free(hermes_home);
    return std.fs.path.join(allocator, &.{ hermes_home, "plugins", "ryk" });
}

pub fn hermesConfigPath(allocator: std.mem.Allocator) ![]u8 {
    var env_map = env_util.createProcessMap(allocator) catch return std.fs.path.join(allocator, &.{ "~", ".hermes", "config.yaml" });
    defer env_map.deinit();
    const hermes_home = try hermesHomeFromEnvMap(allocator, &env_map);
    defer allocator.free(hermes_home);
    return std.fs.path.join(allocator, &.{ hermes_home, "config.yaml" });
}

fn hermesHomeFromEnvMap(
    allocator: std.mem.Allocator,
    env_map: *const std.process.Environ.Map,
) ![]u8 {
    if (env_map.get("HERMES_HOME")) |custom| {
        if (std.fs.path.isAbsolute(custom)) return allocator.dupe(u8, custom);
    }
    const home = (try env_util.getOwnedHome(env_map, allocator)) orelse return std.fs.path.join(allocator, &.{ "~", ".hermes" });
    defer allocator.free(home);
    return std.fs.path.join(allocator, &.{ home, ".hermes" });
}

fn readHermesFile(io: std.Io, allocator: std.mem.Allocator, root: []const u8, name: []const u8) ?[]u8 {
    const path = std.fs.path.join(allocator, &.{ root, name }) catch return null;
    defer allocator.free(path);
    return std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(8 * 1024 * 1024)) catch null;
}

fn hermesRegularFileNoSymlink(io: std.Io, allocator: std.mem.Allocator, root: []const u8, name: []const u8) bool {
    const path = std.fs.path.join(allocator, &.{ root, name }) catch return false;
    defer allocator.free(path);
    const stat = std.Io.Dir.cwd().statFile(io, path, .{ .follow_symlinks = false }) catch return false;
    return stat.kind == .file;
}

fn receiptField(receipt: []const u8, key: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, receipt, '\n');
    if (!std.mem.eql(u8, std.mem.trim(u8, lines.next() orelse return null, "\r"), "ryk-hermes-managed-v1")) return null;
    var found: ?[]const u8 = null;
    while (lines.next()) |line| {
        const clean = std.mem.trim(u8, line, "\r");
        if (clean.len == 0) continue;
        if (std.mem.startsWith(u8, clean, key) and clean.len > key.len and clean[key.len] == '=') {
            if (found != null) return null;
            found = clean[key.len + 1 ..];
        }
    }
    return found;
}

fn hermesReceiptMatches(io: std.Io, allocator: std.mem.Allocator, plugin_dir: []const u8) bool {
    const canonical = std.Io.Dir.cwd().realPathFileAlloc(io, plugin_dir, allocator) catch return false;
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, plugin_dir)) return false;
    if (!hermesRegularFileNoSymlink(io, allocator, plugin_dir, hermes_managed_receipt_filename)) return false;
    const receipt = readHermesFile(io, allocator, plugin_dir, hermes_managed_receipt_filename) orelse return false;
    defer allocator.free(receipt);
    const path = receiptField(receipt, "path") orelse return false;
    if (!std.mem.eql(u8, path, canonical)) return false;
    const names = [_][]const u8{ "plugin.yaml", "__init__.py", "mapping.py" };
    for (names) |name| {
        if (!hermesRegularFileNoSymlink(io, allocator, plugin_dir, name)) return false;
        const expected_key = std.fmt.allocPrint(allocator, "{s}_sha256", .{name}) catch return false;
        defer allocator.free(expected_key);
        const expected = receiptField(receipt, expected_key) orelse return false;
        const bytes = readHermesFile(io, allocator, plugin_dir, name) orelse return false;
        defer allocator.free(bytes);
        const actual = sha256Hex(bytes);
        if (!std.mem.eql(u8, expected, &actual)) return false;
    }
    return true;
}

fn hermesPreflightMarkerMatches(io: std.Io, allocator: std.mem.Allocator, plugin_dir: []const u8) bool {
    const canonical = std.Io.Dir.cwd().realPathFileAlloc(io, plugin_dir, allocator) catch return false;
    defer allocator.free(canonical);
    const marker = readHermesFile(io, allocator, plugin_dir, hermes_unattended_marker_filename) orelse return false;
    defer allocator.free(marker);
    var expected: [std.fs.max_path_bytes + 64]u8 = undefined;
    const expected_text = std.fmt.bufPrint(&expected, "ryk-hermes-unattended-v1\npath={s}\n", .{canonical}) catch return false;
    if (!std.mem.eql(u8, marker, expected_text)) return false;

    // A preflight marker is only a capability for the empty activation
    // directory created by this setup transaction. It is not ownership proof
    // for a populated tree: a same-user writer must not be able to plant the
    // marker beside arbitrary Python and have setup overwrite it.
    var dir = std.Io.Dir.cwd().openDir(io, plugin_dir, .{ .iterate = true, .follow_symlinks = false }) catch return false;
    defer dir.close(io);
    var it = dir.iterate();
    while (it.next(io) catch return false) |entry| {
        if (entry.kind != .file) return false;
        if (!std.mem.eql(u8, entry.name, hermes_unattended_marker_filename) and
            !std.mem.eql(u8, entry.name, host_status.hermes_fail_stance_filename))
        {
            return false;
        }
    }
    return true;
}

fn hermesLegacyBundleMatches(io: std.Io, allocator: std.mem.Allocator, plugin_dir: []const u8) bool {
    const entries = [_]struct { name: []const u8, hash: []const u8 }{
        .{ .name = "plugin.yaml", .hash = hermes_legacy_manifest_sha256 },
        .{ .name = "__init__.py", .hash = hermes_legacy_source_sha256 },
        .{ .name = "mapping.py", .hash = hermes_legacy_mapping_sha256 },
    };
    for (entries) |entry| {
        if (!hermesRegularFileNoSymlink(io, allocator, plugin_dir, entry.name)) return false;
        const bytes = readHermesFile(io, allocator, plugin_dir, entry.name) orelse return false;
        defer allocator.free(bytes);
        const actual = sha256Hex(bytes);
        if (!std.mem.eql(u8, &actual, entry.hash)) return false;
    }
    return true;
}

pub fn installHermesBundleAtomically(
    io: std.Io,
    allocator: std.mem.Allocator,
    source_dir: []const u8,
    destination_dir: []const u8,
) !bool {
    if (!hermesManagedDestination(io, allocator, destination_dir)) return error.RefusingToOverwriteUnownedPlugin;

    const source_names = [_][]const u8{ "plugin.yaml", "__init__.py", "mapping.py" };
    var source_bytes: [3][]u8 = undefined;
    var loaded: usize = 0;
    defer for (source_bytes[0..loaded]) |bytes| allocator.free(bytes);
    for (source_names, 0..) |name, index| {
        const source_path = try std.fs.path.join(allocator, &.{ source_dir, name });
        defer allocator.free(source_path);
        source_bytes[index] = try std.Io.Dir.cwd().readFileAlloc(io, source_path, allocator, .limited(8 * 1024 * 1024));
        loaded += 1;
    }
    // Stale packaged trees may still ship `name: orca` while enable targets `ryk`.
    // Normalize identity before staging so enable + doctor installed evidence agree.
    {
        const normalized = try normalizeHermesManifestNameToRyk(allocator, source_bytes[0]);
        if (!std.mem.eql(u8, normalized, source_bytes[0])) {
            allocator.free(source_bytes[0]);
            source_bytes[0] = normalized;
        } else {
            allocator.free(normalized);
        }
    }

    const existing = dirExists(destination_dir);
    if (existing and hermesReceiptMatches(io, allocator, destination_dir)) {
        var current = true;
        for (source_names, 0..) |name, index| {
            const installed = readHermesFile(io, allocator, destination_dir, name) orelse {
                current = false;
                break;
            };
            defer allocator.free(installed);
            current = current and std.mem.eql(u8, installed, source_bytes[index]);
        }
        if (current) return false;
    }

    const parent = std.fs.path.dirname(destination_dir) orelse return error.InvalidPath;
    const stamp = std.Io.Clock.Timestamp.now(io, .awake).raw.nanoseconds;
    const stage = try std.fmt.allocPrint(allocator, "{s}/.ryk-hermes-stage-{d}", .{ parent, stamp });
    defer allocator.free(stage);
    try std.Io.Dir.cwd().createDirPath(io, stage);
    var stage_owned = true;
    defer if (stage_owned) std.Io.Dir.cwd().deleteTree(io, stage) catch {};

    for (source_names, 0..) |name, index| {
        const stage_path = try std.fs.path.join(allocator, &.{ stage, name });
        defer allocator.free(stage_path);
        _ = try plugin_install.installTextIfSafe(io, allocator, source_bytes[index], stage_path, false);
    }

    // destination_dir is an absolute path under the operator's home. It does
    // not exist during the first staged install, so its lexical path is the
    // canonical path we bind into the receipt; symlinked existing roots were
    // rejected by hermesReceiptMatches before upgrades reach this point.
    const canonical_destination = destination_dir;
    const manifest_hash = sha256Hex(source_bytes[0]);
    const source_hash = sha256Hex(source_bytes[1]);
    const mapping_hash = sha256Hex(source_bytes[2]);
    const receipt = try std.fmt.allocPrint(
        allocator,
        "ryk-hermes-managed-v1\npath={s}\nplugin.yaml_sha256={s}\n__init__.py_sha256={s}\nmapping.py_sha256={s}\n",
        .{ canonical_destination, &manifest_hash, &source_hash, &mapping_hash },
    );
    defer allocator.free(receipt);
    const receipt_path = try std.fs.path.join(allocator, &.{ stage, hermes_managed_receipt_filename });
    defer allocator.free(receipt_path);
    _ = try plugin_install.installTextIfSafe(io, allocator, receipt, receipt_path, false);

    const stage_stance_path = try std.fs.path.join(allocator, &.{ stage, host_status.hermes_fail_stance_filename });
    defer allocator.free(stage_stance_path);
    const stance_path = try std.fs.path.join(allocator, &.{ destination_dir, host_status.hermes_fail_stance_filename });
    defer allocator.free(stance_path);
    var stance_owned: ?[]u8 = null;
    const stance: []const u8 = if (std.Io.Dir.cwd().readFileAlloc(io, stance_path, allocator, .limited(8 * 1024))) |bytes| blk: {
        stance_owned = bytes;
        break :blk bytes;
    } else |_| "fail-closed\n# Managed by `ryk agents setup hermes`.\n";
    defer if (stance_owned) |bytes| allocator.free(bytes);
    _ = try plugin_install.installTextIfSafe(io, allocator, stance, stage_stance_path, false);

    const marker_path = try std.fs.path.join(allocator, &.{ destination_dir, hermes_unattended_marker_filename });
    defer allocator.free(marker_path);
    const stage_marker_path = try std.fs.path.join(allocator, &.{ stage, hermes_unattended_marker_filename });
    defer allocator.free(stage_marker_path);
    if (std.Io.Dir.cwd().access(io, marker_path, .{})) |_| {
        const marker = try std.Io.Dir.cwd().readFileAlloc(io, marker_path, allocator, .limited(8 * 1024));
        defer allocator.free(marker);
        _ = try plugin_install.installTextIfSafe(io, allocator, marker, stage_marker_path, false);
    } else |_| {}

    // Revalidate ownership after the complete replacement tree is staged and
    // immediately before any destination rename. This rejects a destination
    // that changed during source preparation instead of moving it to backup
    // based only on the initial preflight result.
    if (!hermesManagedDestination(io, allocator, destination_dir)) return error.RefusingToOverwriteUnownedPlugin;
    if (!existing and dirExists(destination_dir)) return error.HermesDestinationAppeared;

    if (!existing) {
        try std.Io.Dir.renameAbsolute(stage, destination_dir, io);
        stage_owned = false;
        return true;
    }

    const backup = try std.fmt.allocPrint(allocator, "{s}/.ryk-hermes-backup-{d}", .{ parent, stamp });
    defer allocator.free(backup);
    try std.Io.Dir.renameAbsolute(destination_dir, backup, io);
    errdefer std.Io.Dir.renameAbsolute(backup, destination_dir, io) catch {};
    try std.Io.Dir.renameAbsolute(stage, destination_dir, io);
    stage_owned = false;
    std.Io.Dir.cwd().deleteTree(io, backup) catch {};
    return true;
}

pub fn runHermesEnable(allocator: std.mem.Allocator, host_binary: []const u8) !u8 {
    const argv = [_][]const u8{ host_binary, "plugins", "enable", "ryk" };
    const result = try child_process.runHostCommandTimed(allocator, &argv, 10_000, null, null);
    defer child_process.deinitHostCommandResult(result, allocator);
    return if (result.timed_out) 255 else result.exit_code;
}

/// True when `~/.hermes/plugins/ryk/plugin.yaml` declares `name: ryk` (not stale `name: orca`).
pub fn hermesUserManifestNameIsRyk() bool {
    const allocator = std.heap.page_allocator;
    const root = hermesUserPluginRoot(allocator) catch return false;
    defer allocator.free(root);
    const manifest = std.fs.path.join(allocator, &.{ root, "plugin.yaml" }) catch return false;
    defer allocator.free(manifest);
    return hermesManifestDeclaresNameRyk(allocator, manifest);
}

/// Manifest identity check: requires `name: ryk` and rejects `name: orca`.
pub fn hermesManifestDeclaresNameRyk(allocator: std.mem.Allocator, manifest_path: []const u8) bool {
    if (!fileContains(allocator, manifest_path, "name: ryk")) return false;
    // Stale dual-name or pure orca packages are not installed-as-ryk.
    if (fileContains(allocator, manifest_path, "name: orca")) return false;
    return true;
}

/// Rewrite stale packaged/user `name: orca` manifest bytes to `name: ryk` before install.
/// Returns owned slice (may equal input when already ryk); caller frees when different from input.
pub fn normalizeHermesManifestNameToRyk(allocator: std.mem.Allocator, source: []const u8) ![]u8 {
    if (std.mem.indexOf(u8, source, "name: ryk") != null and std.mem.indexOf(u8, source, "name: orca") == null) {
        return try allocator.dupe(u8, source);
    }
    // Replace the YAML name field only (first occurrence of name: orca / missing name).
    if (std.mem.indexOf(u8, source, "name: orca")) |idx| {
        const before = source[0..idx];
        const after = source[idx + "name: orca".len ..];
        return try std.mem.concat(allocator, u8, &.{ before, "name: ryk", after });
    }
    // No name field: prefix with name: ryk for fail-closed identity.
    if (std.mem.indexOf(u8, source, "name:") == null) {
        return try std.mem.concat(allocator, u8, &.{ "name: ryk\n", source });
    }
    return try allocator.dupe(u8, source);
}

pub fn hermesManagedDestination(io: std.Io, allocator: std.mem.Allocator, plugin_dir: []const u8) bool {
    if (!dirExists(plugin_dir)) return true;
    const canonical = std.Io.Dir.cwd().realPathFileAlloc(io, plugin_dir, allocator) catch return false;
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, plugin_dir)) return false;
    return hermesReceiptMatches(io, allocator, plugin_dir) or
        hermesPreflightMarkerMatches(io, allocator, plugin_dir) or
        hermesLegacyBundleMatches(io, allocator, plugin_dir);
}

/// Write the unattended stance before the Hermes adapter is installed or
/// enabled. This closes the activation window where an inherited fail-open
/// override could otherwise win.
pub fn prepareHermesUnattendedInstall(io: std.Io, allocator: std.mem.Allocator) !void {
    const plugin_dir = try hermesUserPluginRoot(allocator);
    defer allocator.free(plugin_dir);
    if (!hermesManagedDestination(io, allocator, plugin_dir)) return error.RefusingToOverwriteUnownedPlugin;
    const stance_path = try std.fs.path.join(allocator, &.{ plugin_dir, host_status.hermes_fail_stance_filename });
    defer allocator.free(stance_path);
    _ = try plugin_install.installTextIfSafe(
        io,
        allocator,
        "fail-closed\n# Managed by `ryk agents setup hermes`; unattended marker overrides fail-open env.\n",
        stance_path,
        true,
    );
    const marker_path = try std.fs.path.join(allocator, &.{ plugin_dir, ".ryk_unattended" });
    defer allocator.free(marker_path);
    const canonical_plugin_dir = try std.Io.Dir.cwd().realPathFileAlloc(io, plugin_dir, allocator);
    defer allocator.free(canonical_plugin_dir);
    const marker = try std.fmt.allocPrint(
        allocator,
        "ryk-hermes-unattended-v1\npath={s}\n",
        .{canonical_plugin_dir},
    );
    defer allocator.free(marker);
    _ = try plugin_install.installTextIfSafe(
        io,
        allocator,
        marker,
        marker_path,
        true,
    );
}

pub fn runHermesDisableLegacy(allocator: std.mem.Allocator, host_binary: []const u8) !u8 {
    const argv = [_][]const u8{ host_binary, "plugins", "disable", "orca" };
    const result = try child_process.runHostCommandTimed(allocator, &argv, 10_000, null, null);
    defer child_process.deinitHostCommandResult(result, allocator);
    return if (result.timed_out) 255 else result.exit_code;
}

pub fn writeHermesEnableHelper(allocator: std.mem.Allocator, plugin_dir: []const u8) !void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    // Guard: hermesUserPluginRoot can return a path with literal ~ if HOME is unset
    const resolved_dir = if (std.mem.startsWith(u8, plugin_dir, "~/")) blk: {
        var env_map = env_util.createProcessMap(allocator) catch return;
        defer env_map.deinit();
        const home = env_util.getOwnedHome(&env_map, allocator) catch return;
        const home_owned = home orelse return;
        defer allocator.free(home_owned);
        break :blk try std.fs.path.join(allocator, &.{ home_owned, plugin_dir[2..] });
    } else try allocator.dupe(u8, plugin_dir);
    defer allocator.free(resolved_dir);

    const help_path = try std.fs.path.join(allocator, &.{ resolved_dir, "ENABLE.txt" });
    defer allocator.free(help_path);
    _ = try plugin_install.installTextIfSafe(
        io,
        allocator,
        "ryk plugin files are installed.\nTo enable, run:\n  hermes plugins enable ryk\n",
        help_path,
        true,
    );
}

/// New Hermes installs: write fail-closed stance next to the plugin (hybrid L4).
/// Env `RYK_HERMES_FAIL_OPEN` overrides this file.
pub fn writeHermesFailClosedStance(allocator: std.mem.Allocator, plugin_dir: []const u8) !void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const resolved_dir = if (std.mem.startsWith(u8, plugin_dir, "~/")) blk: {
        var env_map = env_util.createProcessMap(allocator) catch return;
        defer env_map.deinit();
        const home = env_util.getOwnedHome(&env_map, allocator) catch return;
        const home_owned = home orelse return;
        defer allocator.free(home_owned);
        break :blk try std.fs.path.join(allocator, &.{ home_owned, plugin_dir[2..] });
    } else try allocator.dupe(u8, plugin_dir);
    defer allocator.free(resolved_dir);

    const stance_path = try std.fs.path.join(allocator, &.{ resolved_dir, host_status.hermes_fail_stance_filename });
    defer allocator.free(stance_path);
    _ = try plugin_install.installTextIfSafe(
        io,
        allocator,
        \\fail-closed
        \\# Written by `ryk plugin install hermes` for new installs.
        \\# Env RYK_HERMES_FAIL_OPEN overrides this file (0=fail-closed, 1=fail-open).
        \\# Easy full protection: ryk run -- hermes
        \\
    ,
        stance_path,
        false,
    );
}

test "Hermes install paths honor absolute HERMES_HOME" {
    var env_map = std.process.Environ.Map.init(std.testing.allocator);
    defer env_map.deinit();
    try env_map.put("HOME", "/Users/synthetic");
    try env_map.put("HERMES_HOME", "/Users/synthetic/.hermes/profiles/work");
    const root = try hermesHomeFromEnvMap(std.testing.allocator, &env_map);
    defer std.testing.allocator.free(root);
    try std.testing.expectEqualStrings("/Users/synthetic/.hermes/profiles/work", root);

    try env_map.put("HERMES_HOME", "relative/profile");
    const fallback = try hermesHomeFromEnvMap(std.testing.allocator, &env_map);
    defer std.testing.allocator.free(fallback);
    try std.testing.expectEqualStrings("/Users/synthetic/.hermes", fallback);
}

test "Hermes manifest name: orca normalizes to name: ryk" {
    const allocator = std.testing.allocator;
    const orca = "name: orca\nversion: 1.2.9\ndescription: ryk runtime guardrails for Hermes Agent.\n";
    const normalized = try normalizeHermesManifestNameToRyk(allocator, orca);
    defer allocator.free(normalized);
    try std.testing.expect(std.mem.indexOf(u8, normalized, "name: ryk") != null);
    try std.testing.expect(std.mem.indexOf(u8, normalized, "name: orca") == null);

    const already = try normalizeHermesManifestNameToRyk(allocator, "name: ryk\nversion: 1\n");
    defer allocator.free(already);
    try std.testing.expectEqualStrings("name: ryk\nversion: 1\n", already);
}

test "Hermes manifest declares name ryk rejects orca identity" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "orca.yaml", .data = "name: orca\nversion: 1\n" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "ryk.yaml", .data = "name: ryk\nversion: 1\n" });
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const orca_path = try std.fs.path.join(std.testing.allocator, &.{ root, "orca.yaml" });
    defer std.testing.allocator.free(orca_path);
    const ryk_path = try std.fs.path.join(std.testing.allocator, &.{ root, "ryk.yaml" });
    defer std.testing.allocator.free(ryk_path);
    try std.testing.expect(!hermesManifestDeclaresNameRyk(std.testing.allocator, orca_path));
    try std.testing.expect(hermesManifestDeclaresNameRyk(std.testing.allocator, ryk_path));
}

test "Hermes bundle install rewrites stale name: orca source to name: ryk" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "source");
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "source/plugin.yaml",
        .data = "name: orca\nversion: 1\ndescription: ryk runtime guardrails for Hermes Agent.\n",
    });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "source/__init__.py", .data = "source-v1\n" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "source/mapping.py", .data = "mapping-v1\n" });

    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const source = try std.fs.path.join(std.testing.allocator, &.{ root, "source" });
    defer std.testing.allocator.free(source);
    const destination = try std.fs.path.join(std.testing.allocator, &.{ root, "installed" });
    defer std.testing.allocator.free(destination);

    try std.testing.expect(try installHermesBundleAtomically(std.testing.io, std.testing.allocator, source, destination));
    const installed = try tmp.dir.readFileAlloc(std.testing.io, "installed/plugin.yaml", std.testing.allocator, .limited(1024));
    defer std.testing.allocator.free(installed);
    try std.testing.expect(std.mem.indexOf(u8, installed, "name: ryk") != null);
    try std.testing.expect(std.mem.indexOf(u8, installed, "name: orca") == null);
    const installed_manifest = try std.fs.path.join(std.testing.allocator, &.{ destination, "plugin.yaml" });
    defer std.testing.allocator.free(installed_manifest);
    try std.testing.expect(hermesManifestDeclaresNameRyk(std.testing.allocator, installed_manifest));
}

test "Hermes managed destination requires a path-bound receipt, not copied metadata" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "plugin.yaml",
        .data = "name: ryk\ndescription: unrelated user plugin\n",
    });
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    try std.testing.expect(!hermesManagedDestination(std.testing.io, std.testing.allocator, root));

    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "plugin.yaml",
        .data = "name: ryk\ndescription: ryk runtime guardrails for Hermes Agent.\n",
    });
    try std.testing.expect(!hermesManagedDestination(std.testing.io, std.testing.allocator, root));

    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = ".ryk-managed-v1",
        .data = "ryk-hermes-managed-v1\npath=/not-this-directory\n",
    });
    try std.testing.expect(!hermesManagedDestination(std.testing.io, std.testing.allocator, root));
}

test "Hermes preflight marker cannot own a populated destination" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "installed");

    const root = try tmp.dir.realPathFileAlloc(std.testing.io, "installed", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const marker = try std.fmt.allocPrint(std.testing.allocator, "ryk-hermes-unattended-v1\npath={s}\n", .{root});
    defer std.testing.allocator.free(marker);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "installed/.ryk_unattended", .data = marker });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = ".ryk_fail_stance", .data = "fail-closed\n" });

    try std.testing.expect(hermesManagedDestination(std.testing.io, std.testing.allocator, root));
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "installed/attacker.py", .data = "arbitrary\n" });
    try std.testing.expect(!hermesManagedDestination(std.testing.io, std.testing.allocator, root));
}

test "Hermes bundle upgrade commits a complete receipt-bound tree and is idempotent" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "source");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "source/plugin.yaml", .data = "name: ryk\nversion: 1\n" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "source/__init__.py", .data = "source-v1\n" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "source/mapping.py", .data = "mapping-v1\n" });

    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const source = try std.fs.path.join(std.testing.allocator, &.{ root, "source" });
    defer std.testing.allocator.free(source);
    const destination = try std.fs.path.join(std.testing.allocator, &.{ root, "installed" });
    defer std.testing.allocator.free(destination);

    try std.testing.expect(try installHermesBundleAtomically(std.testing.io, std.testing.allocator, source, destination));
    try std.testing.expect(hermesManagedDestination(std.testing.io, std.testing.allocator, destination));
    try std.testing.expect(!try installHermesBundleAtomically(std.testing.io, std.testing.allocator, source, destination));

    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "source/plugin.yaml", .data = "name: ryk\nversion: 2\n" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "source/__init__.py", .data = "source-v2\n" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "source/mapping.py", .data = "mapping-v2\n" });
    try std.testing.expect(try installHermesBundleAtomically(std.testing.io, std.testing.allocator, source, destination));

    const installed_names = [_][]const u8{ "plugin.yaml", "__init__.py", "mapping.py" };
    for (installed_names) |name| {
        const path = try std.fs.path.join(std.testing.allocator, &.{ destination, name });
        defer std.testing.allocator.free(path);
        const contents = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, std.testing.allocator, .limited(1024));
        defer std.testing.allocator.free(contents);
        try std.testing.expect(std.mem.indexOf(u8, contents, "v2") != null or std.mem.indexOf(u8, contents, "version: 2") != null);
    }
}

test "Hermes managed receipt rejects symlinked adapter files" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "source");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "source/plugin.yaml", .data = "name: ryk\nversion: 1\n" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "source/__init__.py", .data = "source-v1\n" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "source/mapping.py", .data = "mapping-v1\n" });

    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const source = try std.fs.path.join(std.testing.allocator, &.{ root, "source" });
    defer std.testing.allocator.free(source);
    const destination = try std.fs.path.join(std.testing.allocator, &.{ root, "installed" });
    defer std.testing.allocator.free(destination);

    try std.testing.expect(try installHermesBundleAtomically(std.testing.io, std.testing.allocator, source, destination));
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "outside.py", .data = "source-v1\n" });
    try tmp.dir.deleteFile(std.testing.io, "installed/__init__.py");
    try tmp.dir.symLink(std.testing.io, "../outside.py", "installed/__init__.py", .{});
    try std.testing.expect(!hermesManagedDestination(std.testing.io, std.testing.allocator, destination));
}

test "Hermes bundle staging leaves the installed tree unchanged when a source file fails" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "source");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "source/plugin.yaml", .data = "name: ryk\nversion: 1\n" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "source/__init__.py", .data = "source-v1\n" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "source/mapping.py", .data = "mapping-v1\n" });

    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const source = try std.fs.path.join(std.testing.allocator, &.{ root, "source" });
    defer std.testing.allocator.free(source);
    const destination = try std.fs.path.join(std.testing.allocator, &.{ root, "installed" });
    defer std.testing.allocator.free(destination);

    try std.testing.expect(try installHermesBundleAtomically(std.testing.io, std.testing.allocator, source, destination));
    try tmp.dir.deleteFile(std.testing.io, "source/mapping.py");
    try std.testing.expectError(
        error.FileNotFound,
        installHermesBundleAtomically(std.testing.io, std.testing.allocator, source, destination),
    );
    const preserved = try tmp.dir.readFileAlloc(std.testing.io, "installed/__init__.py", std.testing.allocator, .limited(1024));
    defer std.testing.allocator.free(preserved);
    try std.testing.expectEqualStrings("source-v1\n", preserved);
}

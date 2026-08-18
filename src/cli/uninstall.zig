const std = @import("std");
const builtin = @import("builtin");
const gpa_mod = @import("gpa.zig");

const exit_codes = @import("exit_codes.zig");
const help = @import("help.zig");
const plugin = @import("plugin.zig");
const disable = @import("disable.zig");
const danger_confirmation = @import("danger_confirmation.zig");
const suggestions = @import("suggestions.zig");
const env_util = @import("../env_util.zig");

// ---------------------------------------------------------------------------
// Top-level dispatch
// ---------------------------------------------------------------------------

const Options = struct {
    yes: bool = false,
    plugins_only: bool = false,
    keep_config: bool = false,
    dry_run: bool = false,
};

pub fn command(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    var opts: Options = .{};

    var gpa_state: gpa_mod.State = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();

    var index: usize = 0;
    while (index < argv.len) : (index += 1) {
        const arg = argv[index];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            _ = try help.writeCommand(io, stdout, "uninstall");
            return exit_codes.success;
        }
        if (std.mem.eql(u8, arg, "--yes")) {
            opts.yes = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--plugins-only")) {
            opts.plugins_only = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--keep-config")) {
            opts.keep_config = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--dry-run")) {
            opts.dry_run = true;
            continue;
        }
        try suggestions.writeUnknownOption(
            stderr,
            "ryk uninstall",
            arg,
            &.{ "--plugins-only", "--keep-config", "--dry-run", "--yes", "--help" },
            "uninstall",
        );
        return exit_codes.usage;
    }

    if (!opts.yes and !opts.dry_run) {
        const stdin = std.Io.File.stdin();
        const prompt = if (opts.plugins_only)
            "Remove all ryk plugins from host agents?"
        else if (opts.keep_config)
            "Uninstall ryk (keep config files)? This removes plugins and the binary."
        else
            "Fully uninstall ryk (plugins, binary, config, and local data)?";
        const decision = danger_confirmation.decide(io, stdout, prompt, false, try stdin.isTty(io), null) catch |err| {
            try stderr.print("ryk uninstall: confirmation failed: {s}\n", .{@errorName(err)});
            return exit_codes.general;
        };
        switch (decision) {
            .proceed => {},
            .cancelled => {
                try stdout.writeAll("canceled\n");
                return exit_codes.success;
            },
            .requires_yes => {
                try stderr.writeAll("ryk uninstall: requires --yes or run interactively.\n");
                return exit_codes.usage;
            },
        }
    }

    if (opts.dry_run) {
        try stdout.writeAll("ryk Uninstall (dry-run — no changes will be made)\n\n");
    } else {
        try stdout.writeAll("ryk Uninstall\n\n");
    }

    // 1. Disable / remove all plugins
    try stdout.writeAll("→ Step 1 of 3: Removing plugins...\n");
    var all_disabled = false;
    if (opts.dry_run) {
        try stdout.writeAll("  [dry-run] would remove plugins from: codex, claude, opencode, openclaw, hermes\n");
        all_disabled = true;
    } else {
        try stdout.writeAll("(OpenClaw and Hermes use host CLIs with 10s timeout + direct fallback)\n");
        all_disabled = try disablePlugins(io, allocator, stdout);
    }
    try stdout.writeAll("  ✓ Step 1 done\n");

    if (opts.plugins_only) {
        if (opts.dry_run) {
            try stdout.writeAll("\n[dry-run] Plugins would be removed. Binary and config would remain.\n");
        } else {
            try stdout.writeAll("\n✅ Plugins removed. ryk binary and config remain in place.\n");
            try stdout.writeAll("To fully uninstall later, run: ryk uninstall --yes\n");
        }
        return exit_codes.success;
    }

    // 2. Remove installed binaries and runtime / data assets
    try stdout.writeAll("\n→ Step 2 of 3: Removing ryk installation...\n");
    const binary_removed = try removeBinaries(io, allocator, stdout, opts.dry_run);
    // Always remove runtime assets; full share wipe (including allow-once) only without --keep-config.
    _ = try removeShareProduct(io, allocator, stdout, opts.dry_run, opts.keep_config);
    _ = try removeInstallerProfileEntries(io, allocator, stdout, opts.dry_run);
    try stdout.writeAll("  ✓ Step 2 done\n");

    // 3. Remove config directories
    if (!opts.keep_config) {
        try stdout.writeAll("\n→ Step 3 of 3: Removing config and data...\n");
        try removeConfigDirs(io, allocator, stdout, opts.dry_run);
        try stdout.writeAll("  ✓ Step 3 done\n");
    } else {
        try stdout.writeAll("\n→ Step 3 of 3: Skipping config removal (--keep-config)\n");
        try stdout.writeAll("  ✓ Step 3 done\n");
    }

    if (opts.dry_run) {
        try stdout.writeAll("\n[dry-run] Uninstall simulation complete. Re-run without --dry-run to apply.\n");
    } else {
        try stdout.writeAll("\n✅ Uninstall complete.\n");
        if (!opts.keep_config) {
            try stdout.writeAll("User config removed: ~/.config/ryk/\n");
        }
    }

    if (!all_disabled and !binary_removed) {
        try stdout.writeAll("\nNote: no ryk plugins or binary were found.\n");
    }

    try writeManualCleanupHints(stdout);
    return exit_codes.success;
}

fn writeManualCleanupHints(stdout: anytype) !void {
    try stdout.writeAll(
        \\
        \\Manual cleanup may still be needed:
        \\  - Project workspace .ryk/ dirs are left in place (project policy).
        \\    Find them with: find . -type d -name .ryk
        \\  - Package-manager installs (if you used one):
        \\      brew uninstall ryk          # Homebrew
        \\      scoop uninstall ryk         # Scoop
        \\      winget uninstall ryk        # WinGet
        \\
    );
}

// ---------------------------------------------------------------------------
// Plugin removal (delegates to disable.zig)
// ---------------------------------------------------------------------------

fn disablePlugins(io: std.Io, allocator: std.mem.Allocator, stdout: anytype) !bool {
    var any_action = false;

    any_action = try disable.disableOpenCode(io, allocator, stdout) or any_action;
    any_action = try disable.disableOpenClaw(io, allocator, stdout) or any_action;
    any_action = try disable.disableHermes(io, allocator, stdout) or any_action;
    any_action = try disable.disableCodex(io, allocator, stdout) or any_action;
    any_action = try disable.disableClaude(io, allocator, stdout) or any_action;
    any_action = try disable.disableCursor(io, allocator, stdout) or any_action;

    return any_action;
}

// ---------------------------------------------------------------------------
// Binary removal — self path and known install locations
// ---------------------------------------------------------------------------

fn removeBinaries(io: std.Io, allocator: std.mem.Allocator, stdout: anytype, dry_run: bool) !bool {
    var removed_any = false;

    const self_exe = std.process.executablePathAlloc(io, allocator) catch |err| {
        try stdout.print("  could not determine self path: {s}\n", .{@errorName(err)});
        // Still try known default locations below.
        removed_any = try removeKnownDefaultBinaries(io, allocator, stdout, dry_run) or removed_any;
        return removed_any;
    };
    defer allocator.free(self_exe);

    removed_any = try removeInstalledBinariesAt(io, allocator, self_exe, stdout, dry_run) or removed_any;
    removed_any = try removeKnownDefaultBinaries(io, allocator, stdout, dry_run) or removed_any;

    if (!removed_any) {
        try stdout.writeAll("  no ryk binary found in known locations\n");
    }
    return removed_any;
}

fn removeKnownDefaultBinaries(io: std.Io, allocator: std.mem.Allocator, stdout: anytype, dry_run: bool) !bool {
    var removed_any = false;
    const home_z = env_util.getenvHome() orelse return false;
    const home = std.mem.span(home_z);

    // Unix curl installer default: ~/.local/bin/ryk
    const local_bin = try std.fs.path.join(allocator, &.{ home, ".local", "bin" });
    defer allocator.free(local_bin);
    removed_any = try removeProductBinariesInDir(io, allocator, local_bin, stdout, dry_run) or removed_any;

    // Windows install.ps1 default: ~/.ryk/bin
    const win_bin = try std.fs.path.join(allocator, &.{ home, ".ryk", "bin" });
    defer allocator.free(win_bin);
    removed_any = try removeProductBinariesInDir(io, allocator, win_bin, stdout, dry_run) or removed_any;

    return removed_any;
}

fn removeInstalledBinariesAt(
    io: std.Io,
    allocator: std.mem.Allocator,
    cli_path: []const u8,
    stdout: anytype,
    dry_run: bool,
) !bool {
    if (!plugin.fileExistsAbsolute(io, cli_path)) return false;
    const bin_dir = std.fs.path.dirname(cli_path) orelse return false;
    if (isPackageManagerBinDir(bin_dir)) {
        try stdout.print(
            "  package-managed binary at {s}; not removing (use your package manager).\n",
            .{bin_dir},
        );
        try stdout.writeAll("    brew uninstall ryk  ·  scoop uninstall ryk  ·  winget uninstall ryk\n");
        return false;
    }
    return removeProductBinariesInDir(io, allocator, bin_dir, stdout, dry_run);
}

fn removeProductBinariesInDir(
    io: std.Io,
    allocator: std.mem.Allocator,
    bin_dir: []const u8,
    stdout: anytype,
    dry_run: bool,
) !bool {
    if (isPackageManagerBinDir(bin_dir)) return false;

    const names = productBinaryNames(builtin.os.tag);
    var removed_any = false;
    for (names) |name| {
        const path = try std.fs.path.join(allocator, &.{ bin_dir, name });
        defer allocator.free(path);
        if (!plugin.fileExistsAbsolute(io, path)) continue;
        if (dry_run) {
            try stdout.print("  [dry-run] would remove: {s}\n", .{path});
            removed_any = true;
            continue;
        }
        std.Io.Dir.cwd().deleteFile(io, path) catch |err| {
            try stdout.print("  binary: failed to remove {s}: {s}\n", .{ path, @errorName(err) });
            continue;
        };
        try stdout.print("  removed: {s}\n", .{path});
        removed_any = true;
    }
    return removed_any;
}

/// True for Homebrew/Scoop/WinGet/Nix layout paths — instruct only, never delete.
fn isPackageManagerBinDir(bin_dir: []const u8) bool {
    const needles = [_][]const u8{
        "/Cellar/",
        "/homebrew/",
        "/Homebrew/",
        "/opt/homebrew/",
        "/linuxbrew/",
        "/nix/store/",
        "/scoop/apps/",
        "\\scoop\\apps\\",
        "/WindowsApps/",
        "\\WindowsApps\\",
        "/Program Files/WindowsApps/",
    };
    for (needles) |needle| {
        if (std.mem.indexOf(u8, bin_dir, needle) != null) return true;
    }
    return false;
}

fn productBinaryNames(os: std.Target.Os.Tag) []const []const u8 {
    return if (os == .windows)
        &.{ "ryk.exe", "ryk-daemon.exe" }
    else
        &.{ "ryk", "ryk-daemon" };
}

// ---------------------------------------------------------------------------
// Share / runtime / data removal under ~/.local/share/ryk (and Windows paths)
// ---------------------------------------------------------------------------

fn removeShareProduct(
    io: std.Io,
    allocator: std.mem.Allocator,
    stdout: anytype,
    dry_run: bool,
    keep_user_data: bool,
) !bool {
    var removed_any = false;

    // Prefer explicit RYK_RESOURCE_ROOT. Only full-wipe product-shaped shares;
    // otherwise remove only a marked runtime selected by `current` (never sweep arbitrary parents).
    if (env_util.getenvBrand("RESOURCE_ROOT")) |resource_root| {
        const root = std.mem.span(resource_root);
        if (shareDirFromResourceRoot(root)) |share| {
            if (isProductShareDir(share)) {
                removed_any = try wipeShareDir(io, allocator, share, stdout, dry_run, keep_user_data) or removed_any;
            } else if (std.mem.eql(u8, std.fs.path.basename(root), "current")) {
                try stdout.print("  share: env root is non-product path {s}; only removing marked runtime if present\n", .{share});
                removed_any = try removeInstallerRuntimeAt(io, allocator, root, stdout, dry_run) or removed_any;
            } else {
                try stdout.print("  share: refusing full wipe of non-product path: {s}\n", .{share});
            }
        } else if (std.mem.eql(u8, std.fs.path.basename(root), "current")) {
            removed_any = try removeInstallerRuntimeAt(io, allocator, root, stdout, dry_run) or removed_any;
        }
    }

    if (env_util.getenvHome()) |home_z| {
        const home = std.mem.span(home_z);
        const unix_share = try std.fs.path.join(allocator, &.{ home, ".local", "share", "ryk" });
        defer allocator.free(unix_share);
        removed_any = try wipeShareDir(io, allocator, unix_share, stdout, dry_run, keep_user_data) or removed_any;

        const win_share = try std.fs.path.join(allocator, &.{ home, ".ryk", "share" });
        defer allocator.free(win_share);
        removed_any = try wipeShareDir(io, allocator, win_share, stdout, dry_run, keep_user_data) or removed_any;
    }

    if (std.c.getenv("XDG_DATA_HOME")) |xdg_z| {
        const xdg_share = try std.fs.path.join(allocator, &.{ std.mem.span(xdg_z), "ryk" });
        defer allocator.free(xdg_share);
        removed_any = try wipeShareDir(io, allocator, xdg_share, stdout, dry_run, keep_user_data) or removed_any;
    }

    return removed_any;
}

/// If `resource_root` is `.../share/ryk/current` or `.../share/ryk/<ver>`, return `.../share/ryk`.
fn shareDirFromResourceRoot(resource_root: []const u8) ?[]const u8 {
    const base = std.fs.path.basename(resource_root);
    if (std.mem.eql(u8, base, "current") or versionLooksInstallerOwned(base)) {
        return std.fs.path.dirname(resource_root);
    }
    return null;
}

/// Product share shapes from installers:
/// - `…/share/ryk` (Unix curl default / Homebrew share)
/// - `…/.ryk/share` (Windows install.ps1 default)
fn isProductShareDir(share_dir: []const u8) bool {
    const base = std.fs.path.basename(share_dir);
    const parent = std.fs.path.dirname(share_dir) orelse return false;
    const parent_base = std.fs.path.basename(parent);
    if (std.mem.eql(u8, base, "ryk") and std.mem.eql(u8, parent_base, "share")) return true;
    if (std.mem.eql(u8, base, "share") and std.mem.eql(u8, parent_base, ".ryk")) return true;
    return false;
}

fn wipeShareDir(
    io: std.Io,
    allocator: std.mem.Allocator,
    share_dir: []const u8,
    stdout: anytype,
    dry_run: bool,
    keep_user_data: bool,
) !bool {
    if (!std.fs.path.isAbsolute(share_dir)) return false;
    if (!isProductShareDir(share_dir)) {
        try stdout.print("  share: refusing to wipe non-product path: {s}\n", .{share_dir});
        return false;
    }
    if (!plugin.dirExists(share_dir)) return false;

    var removed_any = false;

    // Always remove installer runtime via current link when present.
    const current = try std.fs.path.join(allocator, &.{ share_dir, "current" });
    defer allocator.free(current);
    removed_any = try removeInstallerRuntimeAt(io, allocator, current, stdout, dry_run) or removed_any;

    // Sweep orphaned version dirs with install markers (not selected by current).
    removed_any = try removeMarkedVersionDirs(io, allocator, share_dir, stdout, dry_run) or removed_any;

    if (!keep_user_data) {
        // Full wipe of product data files at share root (allow-once / pending).
        for ([_][]const u8{ "allow_once.jsonl", "pending_exceptions.jsonl" }) |name| {
            const path = try std.fs.path.join(allocator, &.{ share_dir, name });
            defer allocator.free(path);
            if (!plugin.fileExistsAbsolute(io, path)) continue;
            if (dry_run) {
                try stdout.print("  [dry-run] would remove data: {s}\n", .{path});
                removed_any = true;
                continue;
            }
            std.Io.Dir.cwd().deleteFile(io, path) catch |err| {
                try stdout.print("  data: failed to remove {s}: {s}\n", .{ path, @errorName(err) });
                continue;
            };
            try stdout.print("  removed data: {s}\n", .{path});
            removed_any = true;
        }

        // Staging leftovers from the installer.
        removed_any = try removeInstallerStagingEntries(io, allocator, share_dir, stdout, dry_run) or removed_any;

        // Only remove the share dir when we successfully listed it and it is empty.
        // Listing failures must never be treated as empty (would risk wipe of leftovers).
        if (try shareDirIsEmpty(io, share_dir)) {
            if (dry_run) {
                try stdout.print("  [dry-run] would remove share dir: {s}\n", .{share_dir});
                removed_any = true;
            } else {
                try removePathSafely(io, share_dir, stdout, "share dir");
                if (!plugin.dirExists(share_dir)) {
                    removed_any = true;
                }
            }
        } else {
            try reportShareLeftovers(io, allocator, share_dir, stdout);
        }
    }

    return removed_any;
}

fn removeMarkedVersionDirs(
    io: std.Io,
    allocator: std.mem.Allocator,
    share_dir: []const u8,
    stdout: anytype,
    dry_run: bool,
) !bool {
    var dir = std.Io.Dir.cwd().openDir(io, share_dir, .{ .iterate = true }) catch return false;
    defer dir.close(io);

    var removed_any = false;
    var it = dir.iterate();
    while (it.next(io) catch null) |entry| {
        if (entry.kind != .directory) continue;
        if (std.mem.eql(u8, entry.name, "current")) continue;
        if (!versionLooksInstallerOwned(entry.name)) continue;

        const version_path = try std.fs.path.join(allocator, &.{ share_dir, entry.name });
        defer allocator.free(version_path);
        if (!runtimeLooksInstallerOwned(io, allocator, version_path)) continue;

        if (dry_run) {
            try stdout.print("  [dry-run] would remove runtime: {s}\n", .{version_path});
            removed_any = true;
            continue;
        }
        std.Io.Dir.cwd().deleteTree(io, version_path) catch |err| {
            try stdout.print("  runtime: failed to remove {s}: {s}\n", .{ version_path, @errorName(err) });
            continue;
        };
        try stdout.print("  removed runtime: {s}\n", .{version_path});
        removed_any = true;
    }
    return removed_any;
}

fn removeInstallerStagingEntries(
    io: std.Io,
    allocator: std.mem.Allocator,
    share_dir: []const u8,
    stdout: anytype,
    dry_run: bool,
) !bool {
    var dir = std.Io.Dir.cwd().openDir(io, share_dir, .{ .iterate = true }) catch return false;
    defer dir.close(io);

    var removed_any = false;
    var it = dir.iterate();
    while (it.next(io) catch null) |entry| {
        const is_staging = std.mem.startsWith(u8, entry.name, ".ryk-");
        if (!is_staging) continue;

        const path = try std.fs.path.join(allocator, &.{ share_dir, entry.name });
        defer allocator.free(path);
        if (dry_run) {
            try stdout.print("  [dry-run] would remove staging: {s}\n", .{path});
            removed_any = true;
            continue;
        }
        if (entry.kind == .directory) {
            std.Io.Dir.cwd().deleteTree(io, path) catch |err| {
                try stdout.print("  staging: failed to remove {s}: {s}\n", .{ path, @errorName(err) });
                continue;
            };
        } else {
            std.Io.Dir.cwd().deleteFile(io, path) catch |err| {
                try stdout.print("  staging: failed to remove {s}: {s}\n", .{ path, @errorName(err) });
                continue;
            };
        }
        try stdout.print("  removed staging: {s}\n", .{path});
        removed_any = true;
    }
    return removed_any;
}

/// Returns true only when the directory is successfully listed and has zero entries.
/// Open/iterate failures return false (do not treat uncertainty as empty).
fn shareDirIsEmpty(io: std.Io, share_dir: []const u8) !bool {
    var dir = std.Io.Dir.cwd().openDir(io, share_dir, .{ .iterate = true }) catch return false;
    defer dir.close(io);
    var it = dir.iterate();
    while (true) {
        const entry = it.next(io) catch return false;
        if (entry == null) return true;
        if (std.mem.eql(u8, entry.?.name, ".") or std.mem.eql(u8, entry.?.name, "..")) continue;
        return false;
    }
}

/// Delete a path without following a top-level symlink into foreign trees.
/// Symlinks are unlinked only; real directories use deleteTree.
fn removePathSafely(io: std.Io, path: []const u8, stdout: anytype, label: []const u8) !void {
    const st = std.Io.Dir.cwd().statFile(io, path, .{ .follow_symlinks = false }) catch |err| {
        try stdout.print("  failed to stat {s} {s}: {s}\n", .{ label, path, @errorName(err) });
        return;
    };
    if (st.kind == .sym_link) {
        std.Io.Dir.cwd().deleteFile(io, path) catch |err| {
            try stdout.print("  failed to unlink {s} symlink {s}: {s}\n", .{ label, path, @errorName(err) });
            return;
        };
        try stdout.print("  removed symlink: {s}\n", .{path});
        return;
    }
    std.Io.Dir.cwd().deleteTree(io, path) catch |err| {
        try stdout.print("  failed to remove {s} {s}: {s}\n", .{ label, path, @errorName(err) });
        return;
    };
    try stdout.print("  removed: {s}\n", .{path});
}

fn reportShareLeftovers(io: std.Io, allocator: std.mem.Allocator, share_dir: []const u8, stdout: anytype) !void {
    var dir = std.Io.Dir.cwd().openDir(io, share_dir, .{ .iterate = true }) catch return;
    defer dir.close(io);
    var it = dir.iterate();
    var first = true;
    while (it.next(io) catch null) |entry| {
        if (first) {
            try stdout.print("  note: left non-product entries under {s}:\n", .{share_dir});
            first = false;
        }
        const path = try std.fs.path.join(allocator, &.{ share_dir, entry.name });
        defer allocator.free(path);
        try stdout.print("    - {s}\n", .{path});
    }
}

fn removeInstallerRuntimeAt(
    io: std.Io,
    allocator: std.mem.Allocator,
    current_path: []const u8,
    stdout: anytype,
    dry_run: bool,
) !bool {
    if (!std.fs.path.isAbsolute(current_path) or !std.mem.eql(u8, std.fs.path.basename(current_path), "current")) return false;

    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    // Symlink (Unix) or junction/directory (Windows install.ps1 uses mklink /J).
    _ = std.Io.Dir.readLinkAbsolute(io, current_path, &link_buf) catch {
        // Not a symlink — may still be a junction/dir named current.
        if (!plugin.dirExists(current_path)) return false;
    };

    const share_dir = std.fs.path.dirname(current_path) orelse return false;
    const canonical_share_dir = std.Io.Dir.cwd().realPathFileAlloc(io, share_dir, allocator) catch return false;
    defer allocator.free(canonical_share_dir);
    const target = std.Io.Dir.cwd().realPathFileAlloc(io, current_path, allocator) catch return false;
    defer allocator.free(target);

    const target_parent = std.fs.path.dirname(target) orelse return false;
    // Only remove a version directory that is a direct child of the share dir (never follow
    // a current link out of the product share tree).
    if (!std.mem.eql(u8, target_parent, canonical_share_dir) or std.mem.eql(u8, target, current_path)) {
        try stdout.print("  runtime: refusing to remove target outside {s}: {s}\n", .{ canonical_share_dir, target });
        return false;
    }
    if (!runtimeLooksInstallerOwned(io, allocator, target)) {
        try stdout.print("  runtime: refusing to remove unrecognized payload: {s}\n", .{target});
        return false;
    }

    if (dry_run) {
        try stdout.print("  [dry-run] would remove runtime: {s}\n", .{target});
        try stdout.print("  [dry-run] would remove runtime link: {s}\n", .{current_path});
        return true;
    }

    // Prefer removing the version target first, then the current selector.
    if (!std.mem.eql(u8, target, current_path)) {
        std.Io.Dir.cwd().deleteTree(io, target) catch |err| {
            try stdout.print("  runtime: failed to remove {s}: {s}\n", .{ target, @errorName(err) });
            return false;
        };
        try stdout.print("  removed runtime: {s}\n", .{target});
    }

    // current may be symlink (deleteFile) or directory/junction (deleteTree).
    std.Io.Dir.cwd().deleteFile(io, current_path) catch {
        std.Io.Dir.cwd().deleteTree(io, current_path) catch |err| {
            try stdout.print("  runtime: failed to remove link {s}: {s}\n", .{ current_path, @errorName(err) });
            return false;
        };
    };
    try stdout.print("  removed runtime link: {s}\n", .{current_path});
    return true;
}

fn versionLooksInstallerOwned(version: []const u8) bool {
    if (version.len == 0 or !std.ascii.isDigit(version[0])) return false;
    for (version) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '.' and byte != '-' and byte != '+') return false;
    }
    return true;
}

fn runtimeLooksInstallerOwned(io: std.Io, allocator: std.mem.Allocator, target: []const u8) bool {
    const version = std.fs.path.basename(target);
    if (!versionLooksInstallerOwned(version)) return false;

    const marker = std.fs.path.join(allocator, &.{ target, ".ryk-installation" }) catch return false;
    defer allocator.free(marker);
    var marker_text = std.Io.Dir.cwd().readFileAlloc(io, marker, allocator, .limited(128)) catch return false;
    defer allocator.free(marker_text);
    if (std.mem.startsWith(u8, marker_text, "\xEF\xBB\xBF")) marker_text = marker_text[3..];
    if (!std.mem.startsWith(u8, marker_text, "ryk-runtime-v1\nversion=")) return false;

    for ([_][]const u8{ "integrations", "fixtures", "schemas", "policies" }) |name| {
        const path = std.fs.path.join(allocator, &.{ target, name }) catch return false;
        defer allocator.free(path);
        if (!plugin.dirExists(path)) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Profile cleanup — ryk installer markers
// ---------------------------------------------------------------------------

fn removeInstallerProfileEntries(io: std.Io, allocator: std.mem.Allocator, stdout: anytype, dry_run: bool) !bool {
    const home_z = env_util.getenvHome() orelse return false;
    const home = std.mem.span(home_z);
    var removed_any = false;

    // ZDOTDIR may relocate .zshrc (same contract as install.sh).
    if (std.c.getenv("ZDOTDIR")) |zdot_z| {
        const zshrc = try std.fs.path.join(allocator, &.{ std.mem.span(zdot_z), ".zshrc" });
        defer allocator.free(zshrc);
        removed_any = try removeInstallerProfileEntriesAt(io, allocator, zshrc, stdout, dry_run) or removed_any;
    }

    const home_profiles = [_][]const u8{
        ".zshrc",
        ".bashrc",
        ".bash_profile",
        ".profile",
        ".config/fish/config.fish",
        // PowerShell (install.ps1)
        "Documents/PowerShell/Microsoft.PowerShell_profile.ps1",
        "Documents/WindowsPowerShell/Microsoft.PowerShell_profile.ps1",
    };
    for (home_profiles) |relative| {
        const path = try std.fs.path.join(allocator, &.{ home, relative });
        defer allocator.free(path);
        removed_any = try removeInstallerProfileEntriesAt(io, allocator, path, stdout, dry_run) or removed_any;
    }

    return removed_any;
}

fn isPathMarker(line: []const u8) bool {
    return std.mem.eql(u8, line, "# Added by ryk installer") or
        std.mem.eql(u8, line, "# Added by ryk installer");
}

fn isRuntimeMarker(line: []const u8) bool {
    return std.mem.eql(u8, line, "# ryk runtime assets") or
        std.mem.eql(u8, line, "# ryk runtime assets") or
        std.mem.eql(u8, line, "# ryk runtime assets (RYK_RESOURCE_ROOT dual-name)");
}

fn isManagedPathLine(line: []const u8) bool {
    return std.mem.startsWith(u8, line, "export PATH=") or
        std.mem.startsWith(u8, line, "fish_add_path -- ");
}

fn isManagedResourceLine(line: []const u8) bool {
    return std.mem.startsWith(u8, line, "export RYK_RESOURCE_ROOT=") or
        std.mem.startsWith(u8, line, "export RYK_RESOURCE_ROOT=") or
        std.mem.startsWith(u8, line, "set -gx RYK_RESOURCE_ROOT ") or
        std.mem.startsWith(u8, line, "set -gx RYK_RESOURCE_ROOT ") or
        std.mem.startsWith(u8, line, "$env:RYK_RESOURCE_ROOT") or
        std.mem.startsWith(u8, line, "$env:RYK_RESOURCE_ROOT");
}

fn removeInstallerProfileEntriesAt(
    io: std.Io,
    allocator: std.mem.Allocator,
    profile_path: []const u8,
    stdout: anytype,
    dry_run: bool,
) !bool {
    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    if (std.Io.Dir.readLinkAbsolute(io, profile_path, &link_buf)) |_| return false else |_| {}

    const content = std.Io.Dir.cwd().readFileAlloc(io, profile_path, allocator, .limited(1024 * 1024)) catch return false;
    defer allocator.free(content);

    var updated: std.Io.Writer.Allocating = .init(allocator);
    defer updated.deinit();
    var changed = false;
    var pos: usize = 0;

    while (pos < content.len) {
        const line_end = std.mem.indexOfScalarPos(u8, content, pos, '\n') orelse content.len;
        const after_line = if (line_end < content.len) line_end + 1 else line_end;
        const line = std.mem.trimEnd(u8, content[pos..line_end], "\r");
        const path_marker = isPathMarker(line);
        const runtime_marker = isRuntimeMarker(line);
        if (path_marker or runtime_marker) {
            if (after_line < content.len) {
                const next_end = std.mem.indexOfScalarPos(u8, content, after_line, '\n') orelse content.len;
                const after_next = if (next_end < content.len) next_end + 1 else next_end;
                const next_line = std.mem.trimEnd(u8, content[after_line..next_end], "\r");
                const managed_line = if (path_marker)
                    isManagedPathLine(next_line)
                else
                    isManagedResourceLine(next_line);
                if (managed_line) {
                    pos = after_next;
                    changed = true;
                    continue;
                }
            }
        }

        try updated.writer.writeAll(content[pos..after_line]);
        pos = after_line;
    }

    if (!changed) return false;

    if (dry_run) {
        try stdout.print("  [dry-run] would clean installer activation from: {s}\n", .{profile_path});
        return true;
    }

    const bytes = try updated.toOwnedSlice();
    defer allocator.free(bytes);
    const nonce = std.Io.Clock.Timestamp.now(io, .awake).raw.nanoseconds;
    const temp_path = try std.fmt.allocPrint(allocator, "{s}.ryk-uninstall-{d}", .{ profile_path, nonce });
    defer allocator.free(temp_path);
    errdefer std.Io.Dir.cwd().deleteFile(io, temp_path) catch {};
    {
        const file = try std.Io.Dir.cwd().createFile(io, temp_path, .{ .exclusive = true });
        defer file.close(io);
        try file.writeStreamingAll(io, bytes);
        try file.sync(io);
    }
    try std.Io.Dir.renameAbsolute(temp_path, profile_path, io);
    try stdout.print("  removed installer activation from: {s}\n", .{profile_path});
    return true;
}

// ---------------------------------------------------------------------------
// Config directory removal
// ---------------------------------------------------------------------------

fn removeConfigDirs(io: std.Io, allocator: std.mem.Allocator, stdout: anytype, dry_run: bool) !void {
    // User config dir: ~/.config/ryk/ or $XDG_CONFIG_HOME/ryk/
    const config_dir = blk: {
        if (std.c.getenv("XDG_CONFIG_HOME")) |xdg| {
            break :blk std.fs.path.join(allocator, &.{ std.mem.span(xdg), "ryk" }) catch null;
        }
        const home = env_util.getenvHome() orelse break :blk null;
        break :blk std.fs.path.join(allocator, &.{ std.mem.span(home), ".config", "ryk" }) catch null;
    };
    defer if (config_dir) |p| allocator.free(p);

    if (config_dir) |cd| {
        if (plugin.dirExists(cd) or plugin.fileExistsAbsolute(io, cd)) {
            if (dry_run) {
                try stdout.print("  [dry-run] would remove: {s}\n", .{cd});
            } else {
                try removePathSafely(io, cd, stdout, "config");
            }
        }
    }

    // Windows user data dir ~/.ryk (also the install root for bin/share).
    const win_data_dir = blk: {
        const home = env_util.getenvHome() orelse break :blk null;
        break :blk std.fs.path.join(allocator, &.{ std.mem.span(home), ".ryk" }) catch null;
    };
    defer if (win_data_dir) |p| allocator.free(p);

    if (win_data_dir) |ld| {
        if (plugin.dirExists(ld) or plugin.fileExistsAbsolute(io, ld)) {
            if (dry_run) {
                try stdout.print("  [dry-run] would remove: {s}\n", .{ld});
            } else {
                try removePathSafely(io, ld, stdout, "Windows user data");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "uninstall command help and invalid args" {
    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const help_code = try command(std.testing.io, &.{"--help"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, help_code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "uninstall") != null);

    stdout_writer = .fixed(&stdout_buf);
    stderr_writer = .fixed(&stderr_buf);
    const bad_code = try command(std.testing.io, &.{"--plugins-onl"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, bad_code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "unknown option") != null);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "Did you mean '--plugins-only'?") != null);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "ryk help uninstall") != null);
}

test "uninstall without --yes in non-TTY returns usage" {
    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, &.{}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "--yes") != null);
}

test "uninstall --plugins-only requires --yes in non-TTY" {
    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, &.{"--plugins-only"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "--yes") != null);
}

test "uninstall --dry-run does not require --yes" {
    var stdout_buf: [16 * 1024]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, &.{"--dry-run"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "dry-run") != null);
}

test "uninstall dry-run does not advertise cursor" {
    var stdout_buf: [16 * 1024]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, &.{"--dry-run"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    const printed = stdout_writer.buffered();
    const marker = "would remove plugins from:";
    const line_idx = std.mem.indexOf(u8, printed, marker) orelse return error.TestUnexpectedResult;
    const line_rest = printed[line_idx..];
    const line_end = std.mem.indexOfScalar(u8, line_rest, '\n') orelse line_rest.len;
    const plugin_line = line_rest[0..line_end];
    try std.testing.expect(std.mem.indexOf(u8, plugin_line, "cursor") == null);
}

test "uninstall removes the ryk CLI and daemon" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "custom/bin");
    for ([_][]const u8{ "ryk", "ryk-daemon" }) |name| {
        const path = try std.fmt.allocPrint(std.testing.allocator, "custom/bin/{s}", .{name});
        defer std.testing.allocator.free(path);
        const f = try tmp.dir.createFile(std.testing.io, path, .{});
        f.close(std.testing.io);
    }

    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const cli_path = try std.fs.path.join(std.testing.allocator, &.{ root, "custom", "bin", "ryk" });
    defer std.testing.allocator.free(cli_path);

    var stdout_buf: [2048]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    try std.testing.expect(try removeInstalledBinariesAt(std.testing.io, std.testing.allocator, cli_path, &stdout_writer, false));

    try std.testing.expectError(error.FileNotFound, tmp.dir.access(std.testing.io, "custom/bin/ryk", .{}));
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(std.testing.io, "custom/bin/ryk-daemon", .{}));
}

test "uninstall dry-run leaves binaries in place" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "custom/bin");
    const cli = try tmp.dir.createFile(std.testing.io, "custom/bin/ryk", .{});
    cli.close(std.testing.io);
    const daemon = try tmp.dir.createFile(std.testing.io, "custom/bin/ryk-daemon", .{});
    daemon.close(std.testing.io);

    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const cli_path = try std.fs.path.join(std.testing.allocator, &.{ root, "custom", "bin", "ryk" });
    defer std.testing.allocator.free(cli_path);

    var stdout_buf: [2048]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    try std.testing.expect(try removeInstalledBinariesAt(std.testing.io, std.testing.allocator, cli_path, &stdout_writer, true));
    try tmp.dir.access(std.testing.io, "custom/bin/ryk", .{});
    try tmp.dir.access(std.testing.io, "custom/bin/ryk-daemon", .{});
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "[dry-run]") != null);
}

test "uninstall removes only the runtime selected by the installer current link" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    for ([_][]const u8{ "integrations", "fixtures", "schemas", "policies" }) |name| {
        const path = try std.fmt.allocPrint(std.testing.allocator, "share/ryk/1.2.0/{s}", .{name});
        defer std.testing.allocator.free(path);
        try tmp.dir.createDirPath(std.testing.io, path);
    }
    const marker = try tmp.dir.createFile(std.testing.io, "share/ryk/1.2.0/.ryk-installation", .{});
    try marker.writeStreamingAll(std.testing.io, "ryk-runtime-v1\nversion=1.2.0\n");
    marker.close(std.testing.io);
    try tmp.dir.createDirPath(std.testing.io, "workspace/.ryk");

    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const version_root = try std.fs.path.join(std.testing.allocator, &.{ root, "share", "ryk", "1.2.0" });
    defer std.testing.allocator.free(version_root);
    const current = try std.fs.path.join(std.testing.allocator, &.{ root, "share", "ryk", "current" });
    defer std.testing.allocator.free(current);
    try std.Io.Dir.cwd().symLink(std.testing.io, version_root, current, .{});

    var stdout_buf: [2048]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    try std.testing.expect(try removeInstallerRuntimeAt(std.testing.io, std.testing.allocator, current, &stdout_writer, false));

    try std.testing.expectError(error.FileNotFound, std.Io.Dir.cwd().access(std.testing.io, current, .{}));
    try std.testing.expectError(error.FileNotFound, std.Io.Dir.cwd().access(std.testing.io, version_root, .{}));
    try tmp.dir.access(std.testing.io, "workspace/.ryk", .{});
}

test "uninstall full share wipe removes allow-once data and empty share" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    for ([_][]const u8{ "integrations", "fixtures", "schemas", "policies" }) |name| {
        const path = try std.fmt.allocPrint(std.testing.allocator, "share/ryk/1.2.0/{s}", .{name});
        defer std.testing.allocator.free(path);
        try tmp.dir.createDirPath(std.testing.io, path);
    }
    const marker = try tmp.dir.createFile(std.testing.io, "share/ryk/1.2.0/.ryk-installation", .{});
    try marker.writeStreamingAll(std.testing.io, "ryk-runtime-v1\nversion=1.2.0\n");
    marker.close(std.testing.io);
    const allow = try tmp.dir.createFile(std.testing.io, "share/ryk/allow_once.jsonl", .{});
    try allow.writeStreamingAll(std.testing.io, "{}\n");
    allow.close(std.testing.io);
    const pending = try tmp.dir.createFile(std.testing.io, "share/ryk/pending_exceptions.jsonl", .{});
    try pending.writeStreamingAll(std.testing.io, "{}\n");
    pending.close(std.testing.io);

    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const version_root = try std.fs.path.join(std.testing.allocator, &.{ root, "share", "ryk", "1.2.0" });
    defer std.testing.allocator.free(version_root);
    const current = try std.fs.path.join(std.testing.allocator, &.{ root, "share", "ryk", "current" });
    defer std.testing.allocator.free(current);
    try std.Io.Dir.cwd().symLink(std.testing.io, version_root, current, .{});
    const share = try std.fs.path.join(std.testing.allocator, &.{ root, "share", "ryk" });
    defer std.testing.allocator.free(share);

    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    try std.testing.expect(try wipeShareDir(std.testing.io, std.testing.allocator, share, &stdout_writer, false, false));

    try std.testing.expectError(error.FileNotFound, std.Io.Dir.cwd().access(std.testing.io, share, .{}));
}

test "uninstall keep_user_data leaves allow-once files" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    for ([_][]const u8{ "integrations", "fixtures", "schemas", "policies" }) |name| {
        const path = try std.fmt.allocPrint(std.testing.allocator, "share/ryk/1.2.0/{s}", .{name});
        defer std.testing.allocator.free(path);
        try tmp.dir.createDirPath(std.testing.io, path);
    }
    const marker = try tmp.dir.createFile(std.testing.io, "share/ryk/1.2.0/.ryk-installation", .{});
    try marker.writeStreamingAll(std.testing.io, "ryk-runtime-v1\nversion=1.2.0\n");
    marker.close(std.testing.io);
    const allow = try tmp.dir.createFile(std.testing.io, "share/ryk/allow_once.jsonl", .{});
    try allow.writeStreamingAll(std.testing.io, "{}\n");
    allow.close(std.testing.io);

    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const version_root = try std.fs.path.join(std.testing.allocator, &.{ root, "share", "ryk", "1.2.0" });
    defer std.testing.allocator.free(version_root);
    const current = try std.fs.path.join(std.testing.allocator, &.{ root, "share", "ryk", "current" });
    defer std.testing.allocator.free(current);
    try std.Io.Dir.cwd().symLink(std.testing.io, version_root, current, .{});
    const share = try std.fs.path.join(std.testing.allocator, &.{ root, "share", "ryk" });
    defer std.testing.allocator.free(share);

    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    _ = try wipeShareDir(std.testing.io, std.testing.allocator, share, &stdout_writer, false, true);

    try tmp.dir.access(std.testing.io, "share/ryk/allow_once.jsonl", .{});
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(std.testing.io, "share/ryk/1.2.0", .{}));
}

test "uninstall refuses an unmarked sibling runtime target" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "share/ryk/valuable-data");
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const target = try std.fs.path.join(std.testing.allocator, &.{ root, "share", "ryk", "valuable-data" });
    defer std.testing.allocator.free(target);
    const current = try std.fs.path.join(std.testing.allocator, &.{ root, "share", "ryk", "current" });
    defer std.testing.allocator.free(current);
    try std.Io.Dir.cwd().symLink(std.testing.io, target, current, .{});
    var stdout_buf: [2048]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    try std.testing.expect(!try removeInstallerRuntimeAt(std.testing.io, std.testing.allocator, current, &stdout_writer, false));
    try std.Io.Dir.cwd().access(std.testing.io, target, .{});
}

test "uninstall product binary names cover ryk and daemon" {
    try std.testing.expectEqualStrings("ryk.exe", productBinaryNames(.windows)[0]);
    try std.testing.expectEqualStrings("ryk-daemon.exe", productBinaryNames(.windows)[1]);
    try std.testing.expectEqualStrings("ryk", productBinaryNames(.linux)[0]);
    try std.testing.expectEqualStrings("ryk-daemon", productBinaryNames(.linux)[1]);
}

test "uninstall refuses package-manager bin dirs" {
    try std.testing.expect(isPackageManagerBinDir("/opt/homebrew/bin"));
    try std.testing.expect(isPackageManagerBinDir("/opt/homebrew/Cellar/ryk/1.2.9/bin"));
    try std.testing.expect(isPackageManagerBinDir("/home/user/scoop/apps/ryk/current"));
    try std.testing.expect(!isPackageManagerBinDir("/Users/me/.local/bin"));
}

test "uninstall only trusts product-shaped share dirs" {
    try std.testing.expect(isProductShareDir("/Users/me/.local/share/ryk"));
    try std.testing.expect(isProductShareDir("/Users/me/.ryk/share"));
    try std.testing.expect(!isProductShareDir("/Users/me/Projects/myapp"));
    try std.testing.expect(!isProductShareDir("/tmp/foo"));
}

test "uninstall config removal unlinks symlink without wiping target" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "real-notes");
    const note = try tmp.dir.createFile(std.testing.io, "real-notes/keep.txt", .{});
    try note.writeStreamingAll(std.testing.io, "safe\n");
    note.close(std.testing.io);

    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const target = try std.fs.path.join(std.testing.allocator, &.{ root, "real-notes" });
    defer std.testing.allocator.free(target);
    const link = try std.fs.path.join(std.testing.allocator, &.{ root, "config-ryk" });
    defer std.testing.allocator.free(link);
    try std.Io.Dir.cwd().symLink(std.testing.io, target, link, .{});

    var stdout_buf: [1024]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    try removePathSafely(std.testing.io, link, &stdout_writer, "config");

    try std.testing.expectError(error.FileNotFound, std.Io.Dir.cwd().access(std.testing.io, link, .{}));
    try tmp.dir.access(std.testing.io, "real-notes/keep.txt", .{});
}

test "uninstall removes ryk profile blocks and preserves unrelated lines" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const profile = try tmp.dir.createFile(std.testing.io, ".profile", .{});
    try profile.writeStreamingAll(std.testing.io,
        \\export KEEP_ME=1
        \\# Added by ryk installer
        \\export PATH="/custom/bin:$PATH"
        \\alias still_here='echo yes'
        \\# ryk runtime assets
        \\export RYK_RESOURCE_ROOT="/custom/share/ryk/current"
        \\# Added by ryk installer
        \\fish_add_path -- '/custom/bin'
        \\# ryk runtime assets
        \\export RYK_RESOURCE_ROOT="/custom/share/ryk/current"
        \\export ALSO_KEEP_ME=1
        \\
    );
    profile.close(std.testing.io);

    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const profile_path = try std.fs.path.join(std.testing.allocator, &.{ root, ".profile" });
    defer std.testing.allocator.free(profile_path);
    var stdout_buf: [2048]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    try std.testing.expect(try removeInstallerProfileEntriesAt(
        std.testing.io,
        std.testing.allocator,
        profile_path,
        &stdout_writer,
        false,
    ));

    const updated = try tmp.dir.readFileAlloc(std.testing.io, ".profile", std.testing.allocator, .limited(4096));
    defer std.testing.allocator.free(updated);
    try std.testing.expectEqualStrings(
        \\export KEEP_ME=1
        \\alias still_here='echo yes'
        \\export ALSO_KEEP_ME=1
        \\
    , updated);
}

test "uninstall refuses to rewrite a symlinked shell profile" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const target = try tmp.dir.createFile(std.testing.io, "target", .{});
    try target.writeStreamingAll(std.testing.io, "# Added by ryk installer\nexport PATH='/ryk':\"$PATH\"\n");
    target.close(std.testing.io);
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const target_path = try std.fs.path.join(std.testing.allocator, &.{ root, "target" });
    defer std.testing.allocator.free(target_path);
    const profile_path = try std.fs.path.join(std.testing.allocator, &.{ root, ".profile" });
    defer std.testing.allocator.free(profile_path);
    try std.Io.Dir.cwd().symLink(std.testing.io, target_path, profile_path, .{});
    var stdout_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    try std.testing.expect(!try removeInstallerProfileEntriesAt(std.testing.io, std.testing.allocator, profile_path, &stdout_writer, false));
    const content = try tmp.dir.readFileAlloc(std.testing.io, "target", std.testing.allocator, .limited(1024));
    defer std.testing.allocator.free(content);
    try std.testing.expect(std.mem.indexOf(u8, content, "Added by ryk") != null);
}

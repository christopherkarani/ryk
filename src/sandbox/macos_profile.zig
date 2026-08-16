//! CompiledProfile → SBPL (Seatbelt profile language) for macOS custom sandbox.
//!
//! Pure string generation — no syscalls. Policy shape:
//! - deny default
//! - workspace RW (minus control-root write carve-outs)
//! - system RO prefixes from grants
//! - no broad $HOME grant
//! - process/mach/network baseline so a sandboxed child can still exec
//!
//! Profile grades (`posture.SeatbeltProfileGrade`):
//! - `compatible`: historical residuals (`process*`, broad `/private/var`, route-force
//!   keeps inbound/bind)
//! - `hardened` (default): narrowed process ops + bootstrap FS; same network model
//! - `strict`: hardened + no listeners under route-force; no broad `network*` without
//!   route forcing (deny-default). Still not process/XPC isolation.
//!
//! Path form (M-28): Seatbelt `subpath` filters on product majors match the
//! normalized `/Users/…` firmlink form. Realpath often returns
//! `/System/Volumes/Data/Users/…`; we strip the Data prefix for *content* grant
//! emission so grants are live-effective. After the Data deny, we also emit
//! **metadata-only** Data-form ancestor literals (`/System/Volumes/Data/Users…`)
//! so firmlink-backed `lstat` of path components is not last-match denied.
//! Content grants on bare Users / Data Users stay off.

const std = @import("std");
const builtin = @import("builtin");
const profile = @import("profile.zig");
const posture = @import("posture.zig");

/// Data-volume prefix stripped when emitting Users-tree grants (see `sbplEmitPath`).
const data_volume_prefix = "/System/Volumes/Data";

pub const SeatbeltProfileGrade = posture.SeatbeltProfileGrade;

/// Bounds for prepare-time hardlink alias discovery under protect-on.
///
/// `max_entries` counts every dirent under the workspace (files + directories),
/// not only multi-nlink aliases. Align with Linux workspace-view default
/// (`linux_workspace_view` max_scan_entries = 1_000_000) so monorepos with
/// dependency trees and build artifacts do not fail closed at prepare with
/// `seatbelt_secret_hardlink_scan_capacity` while Linux still attaches.
pub const secret_hardlink_scan_max_depth: u32 = 48;
pub const secret_hardlink_scan_max_entries: u32 = 1_000_000;

/// Outside residual (`nlink - seen_in_workspace`) is treated as hostile only
/// when residual is small and secret-plausible. Planted outside secrets are
/// typically `nlink=2` (residual 1). Content-addressed package stores
/// (pnpm/yarn) often have huge `nlink` with `seen=1`; those must not mass-deny
/// every store leaf into SBPL (re-blooms profile → `sandbox_init` failure).
pub const secret_hardlink_max_outside_residual_links: u64 = 8;

/// Cap on explicit `hardlink_alias_denies` paths after filtering. Walk capacity
/// is separate (`ScanCapacity`). Exceeding this fail-closes with
/// `HardlinkAliasDenyCapacity` → prepare reason
/// `seatbelt_hardlink_alias_deny_capacity`. After residual narrowing this is
/// rare; the cap is a fail-closed backstop against unbounded SBPL growth.
pub const secret_hardlink_alias_deny_max: u32 = 4096;

pub const NetworkRouteForcing = struct {
    proxy_port: u16,
};

pub const RenderOptions = struct {
    network_route_forcing: ?NetworkRouteForcing = null,
    /// Residual grade. Default is hardened.
    profile_grade: SeatbeltProfileGrade = SeatbeltProfileGrade.default_grade,
    /// Absolute paths of multi-nlink non-secret basenames that need explicit
    /// last-match denies (secret-sharing inodes and *small* outside-link
    /// residual). Internal-only hardlink groups and large package-store
    /// residuals are not included. Caller owns the slices.
    hardlink_alias_denies: []const []const u8 = &.{},
    /// Exact host-owned configuration files that stay readable under a wider
    /// host-config RW grant but must not be changed by the sandboxed agent.
    write_deny_literals: []const []const u8 = &.{},
};

/// Honest network_scope string for receipts/banners after child attach.
pub fn networkScopeSummary(grade: SeatbeltProfileGrade, route_forced: bool) []const u8 {
    if (!route_forced) {
        return switch (grade) {
            .compatible, .hardened => "unrestricted",
            // Strict without route force omits `(allow network*)` — deny default.
            .strict => "deny-default (no broad network*; no route force)",
        };
    }
    return switch (grade) {
        .compatible, .hardened => "proxy route-forced (outbound TCP to ryk loopback proxy only; inbound/bind unrestricted; UDP/QUIC unrestricted)",
        .strict => "proxy route-forced (outbound TCP to ryk loopback proxy only; inbound/bind denied; UDP/QUIC unrestricted)",
    };
}

/// Render a custom SBPL profile string from a compiled grant model.
/// Caller owns the returned slice. Uses default (`hardened`) grade.
pub fn renderSbpl(allocator: std.mem.Allocator, compiled: *const profile.CompiledProfile) ![]u8 {
    return renderSbplWithOptions(allocator, compiled, .{});
}

/// Render a custom SBPL profile string with optional child network route forcing
/// and residual grade.
///
/// Route forcing removes broad `network*` and permits outbound TCP only to the
/// local proxy port. Under `compatible`/`hardened`, inbound/bind stay unrestricted
/// so agents can start listeners (Landlock connect-only parity). Under `strict`,
/// inbound/bind are omitted (listener lockdown). macOS Seatbelt accepts
/// `localhost` (not numeric loopback) for TCP address filters; live tests prove
/// that filter still matches numeric `127.0.0.1` client connects.
pub fn renderSbplWithOptions(
    allocator: std.mem.Allocator,
    compiled: *const profile.CompiledProfile,
    options: RenderOptions,
) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    try out.appendSlice(allocator, "(version 1)\n");
    try out.appendSlice(allocator, "(deny default)\n");
    try out.appendSlice(allocator, "\n");

    // Baseline: process lifecycle, signals, sysctl, mach, and optional network.
    // Intentional non-goals (FS confinement only — not process/IPC/network isolation):
    // unfiltered mach-lookup remains on all grades. See docs/platform-macos.md.
    // Metadata is scoped to root literals + grant trees + grant-path *ancestors*
    // (literal metadata only for path-walk) — never bare (allow file-read-metadata)
    // which enables host-wide path discovery.
    try appendProcessBaseline(&out, allocator, options.profile_grade);
    try out.appendSlice(allocator,
        \\(allow signal)
        \\(allow sysctl-read)
        \\;; mach-lookup required for dyld; omit mach-register (no host service registration)
        \\;; unfiltered — not an XPC/service allowlist (residual on all grades)
        \\(allow mach-lookup)
        \\
    );
    try appendNetworkBaseline(&out, allocator, options);
    try appendBootstrapFs(&out, allocator, options.profile_grade);

    // Path grants from the portable profile model (Users-form when under Data/Users).
    // `.exec` uses `literal` (file-only) so a mistaken directory path cannot tree-open.
    //
    // Ancestor path-walk: Node/realpath and similar call lstat on each path component
    // (e.g. `/Users` before `/Users/dev/proj`). Grant subpaths do not cover those
    // parents. Emit metadata-only *literals* on intermediate components so path-walk
    // succeeds without content grants on bare HOME, `/Users`, or sibling trees.
    try out.appendSlice(allocator, ";; path-walk ancestor metadata (literal only; no content)\n");
    for (compiled.grants) |g| {
        try appendPathAncestorMetadataLiterals(&out, allocator, g.path);
    }

    try out.appendSlice(allocator, ";; compiled path grants\n");
    for (compiled.grants) |g| {
        try appendGrantAllows(&out, allocator, g, compiled.control_roots);
    }

    // Explicit control write denies (defense in depth if a broader allow slips in).
    if (compiled.control_roots.len > 0) {
        try out.appendSlice(allocator, "\n;; control-root write carve-outs\n");
        for (compiled.control_roots) |root| {
            try appendDenySubpath(&out, allocator, "file-write*", root);
        }
    }

    // Deny Data-volume firmlink surface (homes / host secrets).
    // Scope is `/System/Volumes/Data` only — not all of `/System/Volumes` (Preboot,
    // Update, etc. are not the secret-home surface). Deny is emitted *after* grants so
    // last-match blocks bare `/System` custom grants that would otherwise open Data.
    //
    // Workspace grants under Data/Users are emitted as Users-form (see sbplEmitPath),
    // which Seatbelt matches live; the Data deny still blocks Data-form opens of
    // sibling homes. Non-Users Data grants (rare) are re-allowed after the deny.
    try out.appendSlice(allocator,
        \\
        \\;; deny data-volume firmlink surface (homes / host secrets); re-allow non-Users Data grants below
        \\(deny file-read* (subpath "/System/Volumes/Data"))
        \\(deny file-read-metadata (subpath "/System/Volumes/Data"))
        \\(deny process-exec (subpath "/System/Volumes/Data"))
        \\
    );

    // Re-allow only grants that remain Data-form after sbplEmitPath (not Users-mapped).
    // Users-form emissions are outside the Data deny subpath string and need no re-allow.
    var reallowed = false;
    for (compiled.grants) |g| {
        if (!grantUnderDataVolume(g.path)) continue;
        // Users-tree grants already emit as /Users/… — skip redundant re-allow.
        if (sbplMapsToUsersForm(g.path)) continue;
        if (!reallowed) {
            try out.appendSlice(allocator, ";; re-allow non-Users grants under /System/Volumes/Data (last-match after Data deny)\n");
            reallowed = true;
        }
        try appendGrantAllows(&out, allocator, g, compiled.control_roots);
    }

    // Path-walk firmlink residual: vnode for `/Users` is often under
    // `/System/Volumes/Data/Users`. Earlier Users-form metadata literals do not
    // match that Data path string, and the Data deny above is last-match for it.
    // Re-emit *metadata-only* ancestors in Data-form for Users-mapped grants so
    // Node realpathSync/lstat(`/Users`) succeeds without content grants on home.
    try out.appendSlice(allocator, ";; path-walk Data-form ancestor metadata (after Data deny; metadata only)\n");
    for (compiled.grants) |g| {
        try appendPathAncestorMetadataLiteralsDataForm(&out, allocator, g.path);
    }

    if (options.write_deny_literals.len > 0) {
        try out.appendSlice(allocator, ";; host configuration authority write-deny\n");
        for (options.write_deny_literals) |path| {
            if (!std.fs.path.isAbsolute(path) or path.len <= 1) return error.InvalidWriteDenyLiteral;
            try appendDenyLiteralWithDataAlias(&out, allocator, "file-write*", path);
        }
    }

    if (compiled.protect_workspace_secrets) {
        try out.appendSlice(allocator, "\n;; workspace env secret carve-out\n");
        try appendWorkspaceSecretDeny(&out, allocator, "file-read*", compiled.workspace_root);
        try appendWorkspaceSecretDeny(&out, allocator, "file-read-metadata", compiled.workspace_root);
        try appendWorkspaceSecretDeny(&out, allocator, "file-write*", compiled.workspace_root);
        if (options.hardlink_alias_denies.len > 0) {
            try out.appendSlice(allocator, ";; multi-nlink non-secret basenames (prepare-time hardlink residual)\n");
            for (options.hardlink_alias_denies) |alias_path| {
                try appendDenySubpath(&out, allocator, "file-read*", alias_path);
                try appendDenySubpath(&out, allocator, "file-read-metadata", alias_path);
                try appendDenySubpath(&out, allocator, "file-write*", alias_path);
            }
        }
    }

    // F-03: file-write* RW grants also allow hardlink create. Deny all file-link
    // then re-allow only inside the workspace so host-config→workspace auth plants
    // fail. Same-tree hardlinks under host-config stay denied (residual; agents
    // rarely need them). Do not re-allow file-link on host_rw roots — that reopens
    // cross-root when both ends match separate allows (spike-proven).
    // Control roots (.git / .ryk / authority) get require-not so the workspace
    // file-link re-allow does not re-open hardlink plant under write-denied trees
    // (same carve class as file-write*).
    try appendCrossRootFileLinkFence(&out, allocator, compiled.workspace_root, compiled.control_roots);

    // No broad HOME: assert via absence — never emit $HOME or ~ grants.
    return try out.toOwnedSlice(allocator);
}

/// Last-match file-link fence (F-03). See spike: `(deny file-link)` then
/// `(allow file-link (require-all (subpath workspace) (require-not control)…))`
/// blocks host→workspace `ln` while keeping workspace-only hardlinks and
/// preserving control-root isolation. Workspace path uses `sbplEmitPath`
/// (Users-form) like other grants — no Data-form dual emit (M-28).
fn appendCrossRootFileLinkFence(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    workspace_root: []const u8,
    control_roots: []const []const u8,
) !void {
    if (workspace_root.len == 0 or !std.fs.path.isAbsolute(workspace_root)) return;
    try out.appendSlice(allocator,
        \\
        \\;; F-03 cross-root hardlink fence: no host-config inode under workspace
        \\(deny file-link)
        \\
    );
    try appendAllowFileLinkMinusControls(out, allocator, workspace_root, control_roots);
}

/// Workspace file-link allow with control-root require-not (mirror of write carve-outs).
fn appendAllowFileLinkMinusControls(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    workspace_root: []const u8,
    control_roots: []const []const u8,
) !void {
    const emit = sbplEmitPath(workspace_root);
    // (allow file-link (require-all (subpath "ws") (require-not (subpath "ctrl")) ...))
    // When no control roots apply under workspace, emit plain subpath allow.
    var any_control = false;
    for (control_roots) |root| {
        if (!profile.isPathWithin(root, workspace_root) and !std.mem.eql(u8, root, workspace_root)) continue;
        any_control = true;
        break;
    }
    if (!any_control) {
        try appendAllowSubpath(out, allocator, "file-link", workspace_root);
        return;
    }
    try out.appendSlice(allocator, "(allow file-link (require-all (subpath \"");
    try appendEscaped(out, allocator, emit);
    try out.appendSlice(allocator, "\")");
    for (control_roots) |root| {
        if (!profile.isPathWithin(root, workspace_root) and !std.mem.eql(u8, root, workspace_root)) continue;
        try out.appendSlice(allocator, " (require-not (subpath \"");
        try appendEscaped(out, allocator, sbplEmitPath(root));
        try out.appendSlice(allocator, "\"))");
    }
    try out.appendSlice(allocator, "))\n");
}

fn appendProcessBaseline(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    grade: SeatbeltProfileGrade,
) !void {
    switch (grade) {
        .compatible => try out.appendSlice(allocator,
            \\;; process baseline (compatible): unrestricted process* residual
            \\(allow process*)
            \\
        ),
        // Hardened + strict: lifecycle ops agents need without blanket process*.
        // process-exec is also re-granted per compiled path trees below.
        .hardened, .strict => try out.appendSlice(allocator,
            \\;; process baseline (hardened/strict): fork/exec/info only — not process isolation
            \\(allow process-fork)
            \\(allow process-exec)
            \\(allow process-info*)
            \\
        ),
    }
}

fn appendNetworkBaseline(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    options: RenderOptions,
) !void {
    if (options.network_route_forcing) |route| {
        switch (options.profile_grade) {
            .compatible, .hardened => {
                // Outbound: only the ryk loopback proxy. Inbound/bind stay open —
                // connect mediation, not a listener lockdown (Landlock parity).
                const line = try std.fmt.allocPrint(allocator,
                    \\;; network route forcing: outbound TCP only to ryk loopback proxy;
                    \\;; inbound/bind unrestricted (dev servers, ephemeral listeners)
                    \\(allow network-inbound)
                    \\(allow network-bind)
                    \\(allow network-outbound (remote tcp "localhost:{d}"))
                    \\
                , .{route.proxy_port});
                defer allocator.free(line);
                try out.appendSlice(allocator, line);
            },
            .strict => {
                const line = try std.fmt.allocPrint(allocator,
                    \\;; network route forcing (strict): outbound TCP only to ryk loopback proxy;
                    \\;; inbound/bind omitted (listener lockdown — breaks Landlock parity intentionally)
                    \\(allow network-outbound (remote tcp "localhost:{d}"))
                    \\
                , .{route.proxy_port});
                defer allocator.free(line);
                try out.appendSlice(allocator, line);
            },
        }
        return;
    }
    switch (options.profile_grade) {
        .compatible, .hardened => try out.appendSlice(allocator,
            \\;; network unrestricted unless the launcher requested proxy route forcing
            \\(allow network*)
            \\
        ),
        // Strict without route force: omit network* — deny default blocks network.
        .strict => try out.appendSlice(allocator,
            \\;; strict without route force: no broad network* (deny default)
            \\
        ),
    }
}

fn appendBootstrapFs(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    grade: SeatbeltProfileGrade,
) !void {
    // Shared dyld/device/root literals.
    try out.appendSlice(allocator,
        \\;; dyld / device / root path components needed for exec (content + metadata)
        \\(allow file-read-metadata (literal "/"))
        \\(allow file-read-metadata (literal "/private"))
        \\(allow file-read* (literal "/"))
        \\(allow file-read* (literal "/private"))
        \\(allow file-read* (literal "/private/tmp"))
        \\(allow file-read* (literal "/private/var/tmp"))
        \\
    );
    switch (grade) {
        // Historical: broad /private/var read (host discovery residual).
        .compatible => try out.appendSlice(allocator,
            \\(allow file-read* (literal "/private/var"))
            \\
        ),
        // Hardened/strict: no broad /private/var — only dyld + shell select + tmp.
        // `/var` is a firmlink to `/private/var`; libxcselect opens `/var/select/…`
        // and `/var/db/xcode_select_link` (not only private-form). Without both path
        // forms, `/usr/bin/git` dies with "unable to read data link … Operation not
        // permitted" and macOS may show a false developer-tools install dialog.
        // Never bare `/var/db` (receipts, host DB) — only the xcode_select_link leaf.
        .hardened, .strict => try out.appendSlice(allocator,
            \\;; bootstrap FS (hardened/strict): no broad /private/var
            \\(allow file-read-metadata (literal "/var"))
            \\(allow file-read-metadata (literal "/private/var"))
            \\(allow file-read-metadata (literal "/var/db"))
            \\(allow file-read-metadata (literal "/private/var/db"))
            \\(allow file-read* (literal "/var"))
            \\(allow file-read* (subpath "/private/var/select"))
            \\(allow file-read* (subpath "/var/select"))
            \\(allow file-read* (literal "/private/var/db/xcode_select_link"))
            \\(allow file-read* (literal "/var/db/xcode_select_link"))
            \\
        ),
    }
    try out.appendSlice(allocator,
        \\(allow file-read-metadata (subpath "/dev"))
        \\(allow file-read* (subpath "/dev"))
        \\(allow file-ioctl (subpath "/dev"))
        \\(allow file-read-metadata (subpath "/private/var/db/dyld"))
        \\(allow file-read* (subpath "/private/var/db/dyld"))
        \\;; device writes: only null/urandom (not bare /dev)
        \\(allow file-write* (literal "/dev/null"))
        \\(allow file-write* (literal "/dev/urandom"))
        \\
    );
}

/// Multi-nlink regular file recorded during protect-on hardlink alias discovery.
const ScannedFile = struct {
    path: []u8,
    secret_name: bool,
    nlink: u64,
    dev: u64,
    ino: u64,
};

const InodeKey = struct {
    dev: u64,
    ino: u64,
};

const InodeAgg = struct {
    /// Number of multi-nlink paths for this inode found under the workspace walk.
    seen: u32,
    nlink: u64,
    has_secret: bool,
};

/// Walk `workspace_root` and return owned absolute paths of regular files that
/// need explicit last-match Seatbelt path denies as hardlink aliases.
///
/// Policy:
/// - Secret-form basenames are covered by the shared path-regex deny.
/// - Non-secret basenames are denied by path only when their inode is hostile:
///   1. any scanned path on that inode is secret-form (workspace `.env` hardlinked
///      as `notes.txt`), or
///   2. **small** outside residual: `nlink > seen` and
///      `(nlink - seen) <= secret_hardlink_max_outside_residual_links`
///      (host `.env` hardlinked into the workspace as `config.txt` while the
///      secret basename lives outside the walk; planted secrets ≈ residual 1).
/// - **Large** outside residual (package-manager content-addressed stores with
///   huge `nlink` and few workspace paths) is **accepted** — not mass-denied.
/// - Multi-nlink groups that are entirely non-secret and fully contained in the
///   workspace (cargo/incremental hardlink graphs, APFS shared build artifacts)
///   are **not** denied — denying them bloated SBPL until `sandbox_init` failed
///   with `child_apply_failed` on monorepos.
/// - Single-nlink ordinary files stay allowed.
///
/// Fail-closed policy (protect-on prepare path):
/// - Missing workspace (`error.FileNotFound`) → empty list (regex deny still
///   applies; unit tests with synthetic roots keep working).
/// - Any other root open failure (access denied, not a directory, …) →
///   `error.ScanOpenFailed`.
/// - Nested directory open failure → `error.ScanOpenFailed` (never skip).
/// - Regular-file open/fstat failure → `error.ScanOpenFailed`.
/// - Symlinks and other non-regular kinds are skipped (cannot be hardlink
///   aliases of secret regular files); only open/fstat failures on kinds that
///   may be regular files fail closed.
/// - Scan capacity/depth exceeded → `error.ScanCapacity` /
///   `error.ScanDepthExceeded`.
/// - Filtered alias denylist exceeds `secret_hardlink_alias_deny_max` →
///   `error.HardlinkAliasDenyCapacity`.
///
/// Prepare maps `OutOfMemory` to `seatbelt_profile_oom`, alias-deny capacity to
/// `seatbelt_hardlink_alias_deny_capacity`, and other scan errors to distinct
/// `seatbelt_secret_hardlink_scan_*` reason codes.
///
/// Caller frees each path and the outer slice via `freeHardlinkAliasPaths`.
pub fn collectSecretHardlinkAliasPaths(
    allocator: std.mem.Allocator,
    io: std.Io,
    workspace_root: []const u8,
) ![]const []const u8 {
    if (builtin.os.tag != .macos) return try allocator.alloc([]const u8, 0);

    var root = std.Io.Dir.openDirAbsolute(io, workspace_root, .{
        .iterate = true,
        .follow_symlinks = false,
    }) catch |err| switch (err) {
        // Only absence is soft: regex deny still covers secret basenames.
        error.FileNotFound => return try allocator.alloc([]const u8, 0),
        else => return error.ScanOpenFailed,
    };
    defer root.close(io);

    var entries: std.ArrayList(ScannedFile) = .empty;
    defer {
        for (entries.items) |e| allocator.free(e.path);
        entries.deinit(allocator);
    }

    var scanned: u32 = 0;
    try walkCollectHardlinkCandidates(
        allocator,
        io,
        &root,
        workspace_root,
        0,
        &scanned,
        &entries,
    );

    var aggs = std.AutoHashMap(InodeKey, InodeAgg).init(allocator);
    defer aggs.deinit();

    for (entries.items) |e| {
        const key = InodeKey{ .dev = e.dev, .ino = e.ino };
        const gop = try aggs.getOrPut(key);
        if (!gop.found_existing) {
            gop.value_ptr.* = .{
                .seen = 0,
                .nlink = e.nlink,
                .has_secret = false,
            };
        }
        gop.value_ptr.seen = std.math.add(u32, gop.value_ptr.seen, 1) catch return error.ScanCapacity;
        if (e.secret_name) gop.value_ptr.has_secret = true;
        // Prefer the higher link count if fstat disagrees (should not happen).
        if (e.nlink > gop.value_ptr.nlink) gop.value_ptr.nlink = e.nlink;
    }

    var aliases: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (aliases.items) |p| allocator.free(p);
        aliases.deinit(allocator);
    }

    for (entries.items) |e| {
        // Secret basenames: path-regex deny (no per-path entry needed).
        if (e.secret_name) continue;
        const agg = aggs.get(.{ .dev = e.dev, .ino = e.ino }) orelse continue;
        if (!inodeNeedsHardlinkAliasDeny(agg)) continue;
        if (aliases.items.len >= secret_hardlink_alias_deny_max) return error.HardlinkAliasDenyCapacity;
        // dupe before append: free on append failure (partial-success path).
        const owned = try allocator.dupe(u8, e.path);
        errdefer allocator.free(owned);
        try aliases.append(allocator, owned);
    }

    return try aliases.toOwnedSlice(allocator);
}

/// True when a non-secret basename on this inode needs an explicit path deny.
fn inodeNeedsHardlinkAliasDeny(agg: InodeAgg) bool {
    if (agg.has_secret) return true;
    return outsideResidualIsHostile(agg.nlink, agg.seen);
}

/// Outside residual is hostile only when residual link count is in
/// `(0, secret_hardlink_max_outside_residual_links]`. Equal nlink (fully
/// contained) and large package-store residuals are not hostile.
/// Pure helper for unit tests of the residual threshold.
pub fn outsideResidualIsHostile(nlink: u64, seen: u32) bool {
    if (nlink <= @as(u64, seen)) return false;
    const residual = nlink - @as(u64, seen);
    return residual <= secret_hardlink_max_outside_residual_links;
}

pub fn freeHardlinkAliasPaths(allocator: std.mem.Allocator, paths: []const []const u8) void {
    for (paths) |p| allocator.free(p);
    allocator.free(paths);
}

fn walkCollectHardlinkCandidates(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: *std.Io.Dir,
    dir_path: []const u8,
    depth: u32,
    scanned: *u32,
    entries: *std.ArrayList(ScannedFile),
) !void {
    if (depth > secret_hardlink_scan_max_depth) return error.ScanDepthExceeded;

    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        if (std.mem.eql(u8, entry.name, ".") or std.mem.eql(u8, entry.name, "..")) continue;
        if (std.mem.indexOfScalar(u8, entry.name, 0) != null) continue;

        scanned.* = std.math.add(u32, scanned.*, 1) catch return error.ScanCapacity;
        if (scanned.* > secret_hardlink_scan_max_entries) return error.ScanCapacity;

        const child_path = try std.fs.path.join(allocator, &.{ dir_path, entry.name });
        defer allocator.free(child_path);

        switch (entry.kind) {
            .directory => {
                // iterate() reports real directories as .directory; symlinks are
                // .sym_link and are intentionally not followed into the walk.
                // Open failures fail closed: skipping an unreadable dir would
                // miss multi-nlink aliases under that tree.
                var child = std.Io.Dir.openDirAbsolute(io, child_path, .{
                    .iterate = true,
                    .follow_symlinks = false,
                }) catch return error.ScanOpenFailed;
                defer child.close(io);
                try walkCollectHardlinkCandidates(
                    allocator,
                    io,
                    &child,
                    child_path,
                    depth + 1,
                    scanned,
                    entries,
                );
            },
            .file => try recordScannedRegular(allocator, io, child_path, entry.name, entries),
            // Symlinks and known non-regular kinds cannot be hardlink aliases of
            // secret regular files — skip without failing prepare (node_modules
            // shims, sockets, etc. must not break empty-backpack attach).
            .sym_link,
            .block_device,
            .character_device,
            .named_pipe,
            .unix_domain_socket,
            .whiteout,
            .door,
            .event_port,
            => {},
            // Unknown kind: attempt open/fstat; non-regular → skip; open fail → closed.
            else => try recordScannedRegular(allocator, io, child_path, entry.name, entries),
        }
    }
}

fn recordScannedRegular(
    allocator: std.mem.Allocator,
    io: std.Io,
    child_path: []const u8,
    entry_name: []const u8,
    entries: *std.ArrayList(ScannedFile),
) !void {
    const meta = (try regularFileMetaForPath(io, child_path)) orelse return;
    // Single-nlink files cannot be hardlink aliases — skip storage (regex still
    // covers secret basenames). Monorepo build trees hardlink thousands of
    // ordinary objects; retaining them only for the multi-nlink filter.
    if (meta.nlink <= 1) return;
    const secret_name = profile.isWorkspaceSecretBasename(entry_name);
    const owned = try allocator.dupe(u8, child_path);
    errdefer allocator.free(owned);
    try entries.append(allocator, .{
        .path = owned,
        .secret_name = secret_name,
        .nlink = meta.nlink,
        .dev = meta.dev,
        .ino = meta.ino,
    });
}

const RegularFileMeta = struct {
    nlink: u64,
    dev: u64,
    ino: u64,
};

/// Open/fstat a path as a regular file. Open/fstat failures → `ScanOpenFailed`
/// (fail closed). Non-regular after successful fstat → `null` (skip).
fn regularFileMetaForPath(io: std.Io, path: []const u8) error{ScanOpenFailed}!?RegularFileMeta {
    if (builtin.os.tag != .macos) return null;
    const file = std.Io.Dir.openFileAbsolute(io, path, .{
        .path_only = true,
        .follow_symlinks = false,
    }) catch return error.ScanOpenFailed;
    defer file.close(io);
    // Zig 0.16 File.Stat has nlink/inode but not st_dev; fstat supplies the
    // (dev, ino) pair used as hardlink-group key plus nlink in one syscall.
    var st: std.posix.Stat = undefined;
    if (std.c.fstat(file.handle, &st) != 0) return error.ScanOpenFailed;
    if (!std.posix.S.ISREG(st.mode)) return null;
    return .{
        .nlink = @intCast(st.nlink),
        .dev = @intCast(st.dev),
        .ino = @intCast(st.ino),
    };
}

fn appendWorkspaceSecretDeny(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    op: []const u8,
    workspace_root: []const u8,
) !void {
    try out.appendSlice(allocator, "(deny ");
    try out.appendSlice(allocator, op);
    try out.appendSlice(allocator, " (require-all (subpath \"");
    try appendEscaped(out, allocator, sbplEmitPath(workspace_root));
    // Secret form + template allow: only profile rule book (no local .env regex).
    try out.appendSlice(allocator, "\") ");
    try profile.appendWorkspaceSecretSbplRegexPredicates(out, allocator);
    try out.appendSlice(allocator, "))\n");
}

/// True when a grant path is exactly Data volume or a strict descendant.
fn grantUnderDataVolume(path: []const u8) bool {
    return profile.isPathWithin(path, data_volume_prefix);
}

/// True when `sbplEmitPath` would strip `/System/Volumes/Data` → `/Users/…`.
fn sbplMapsToUsersForm(path: []const u8) bool {
    return !std.mem.eql(u8, sbplEmitPath(path), path);
}

/// Normalize paths for SBPL emission: prefer Users-form when realpath is under
/// `/System/Volumes/Data/Users/…`. Seatbelt subpath filters match `/Users/…` on
/// matrix hosts; Data-form grant strings are not live-effective for workspace RW.
///
/// Only the Data+Users firmlink surface is rewritten (component-bounded). Other
/// Data paths (e.g. `/System/Volumes/Data/private/…`) pass through unchanged.
fn sbplEmitPath(path: []const u8) []const u8 {
    // /System/Volumes/Data/Users or /System/Volumes/Data/Users/…
    const users_under_data = data_volume_prefix ++ "/Users";
    if (std.mem.eql(u8, path, users_under_data)) {
        return path[data_volume_prefix.len..]; // "/Users"
    }
    if (std.mem.startsWith(u8, path, users_under_data ++ "/")) {
        return path[data_volume_prefix.len..]; // "/Users/…"
    }
    return path;
}

/// Emit allow rules for one compiled grant (primary path grants and Data re-allow).
fn appendGrantAllows(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    g: profile.PathGrant,
    control_roots: []const []const u8,
) !void {
    switch (g.mode) {
        .exec => {
            try appendAllowLiteral(out, allocator, "file-read-metadata", g.path);
            try appendAllowLiteral(out, allocator, "file-read*", g.path);
            try appendAllowLiteral(out, allocator, "process-exec", g.path);
        },
        .ro => {
            try appendAllowSubpath(out, allocator, "file-read-metadata", g.path);
            try appendAllowSubpath(out, allocator, "file-read*", g.path);
            try appendAllowSubpath(out, allocator, "process-exec", g.path);
        },
        .rw => {
            try appendAllowSubpath(out, allocator, "file-read-metadata", g.path);
            try appendAllowSubpath(out, allocator, "file-read*", g.path);
            // RW with control-root write denies (require-not).
            try appendAllowWriteMinusControls(out, allocator, g.path, control_roots);
        },
    }
}

fn appendAllowSubpath(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    op: []const u8,
    path: []const u8,
) !void {
    const emit = sbplEmitPath(path);
    try out.appendSlice(allocator, "(allow ");
    try out.appendSlice(allocator, op);
    try out.appendSlice(allocator, " (subpath \"");
    try appendEscaped(out, allocator, emit);
    try out.appendSlice(allocator, "\"))\n");
}

/// File-only allow (no tree open). Used for `.exec` launch-binary grants.
fn appendAllowLiteral(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    op: []const u8,
    path: []const u8,
) !void {
    const emit = sbplEmitPath(path);
    try out.appendSlice(allocator, "(allow ");
    try out.appendSlice(allocator, op);
    try out.appendSlice(allocator, " (literal \"");
    try appendEscaped(out, allocator, emit);
    try out.appendSlice(allocator, "\"))\n");
}

/// Emit `file-read-metadata` **literals** for each intermediate path component of
/// `path` (after Users-form normalization). Enables component-wise path-walk
/// (Node `realpathSync` / `lstat`) without content grants on ancestors.
///
/// For `/Users/dev/proj` emits literals on `/Users` and `/Users/dev` only — not
/// the leaf (covered by the grant itself) and not bare unrestricted metadata.
/// Never emits `file-read*` or `subpath` on those ancestors.
fn appendPathAncestorMetadataLiterals(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    path: []const u8,
) !void {
    const emit = sbplEmitPath(path);
    try appendPathAncestorMetadataLiteralsForEmit(out, allocator, emit);
}

/// Same as ancestor metadata, but emit `/System/Volumes/Data` + Users-form path
/// components when the grant maps to Users-form. Used *after* the Data deny so
/// firmlink-backed lstat of `/Users` (Data vnode) is not last-match denied.
fn appendPathAncestorMetadataLiteralsDataForm(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    path: []const u8,
) !void {
    const emit = sbplEmitPath(path);
    // Only Users-mapped grants need Data-form twins.
    if (!std.mem.eql(u8, emit, "/Users") and !std.mem.startsWith(u8, emit, "/Users/")) return;

    // Data-form path: /System/Volumes/Data + Users path.
    var data_buf: [std.fs.max_path_bytes]u8 = undefined;
    const prefix = data_volume_prefix; // /System/Volumes/Data
    if (prefix.len + emit.len >= data_buf.len) return;
    @memcpy(data_buf[0..prefix.len], prefix);
    @memcpy(data_buf[prefix.len..][0..emit.len], emit);
    const data_path = data_buf[0 .. prefix.len + emit.len];
    try appendPathAncestorMetadataLiteralsForEmit(out, allocator, data_path);
}

fn appendPathAncestorMetadataLiteralsForEmit(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    emit: []const u8,
) !void {
    if (emit.len < 2 or emit[0] != '/') return;

    var idx: usize = 1;
    while (idx < emit.len) : (idx += 1) {
        if (emit[idx] != '/') continue;
        const ancestor = emit[0..idx];
        // Bootstrap already grants metadata on "/"; skip empty and root-only.
        if (ancestor.len <= 1) continue;
        try out.appendSlice(allocator, "(allow file-read-metadata (literal \"");
        try appendEscaped(out, allocator, ancestor);
        try out.appendSlice(allocator, "\"))\n");
    }
}

fn appendDenySubpath(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    op: []const u8,
    path: []const u8,
) !void {
    const emit = sbplEmitPath(path);
    try out.appendSlice(allocator, "(deny ");
    try out.appendSlice(allocator, op);
    try out.appendSlice(allocator, " (subpath \"");
    try appendEscaped(out, allocator, emit);
    try out.appendSlice(allocator, "\"))\n");
}

fn appendDenyLiteralWithDataAlias(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    op: []const u8,
    path: []const u8,
) !void {
    const emit = sbplEmitPath(path);
    try appendDenyLiteralForEmit(out, allocator, op, emit);
    if (!std.mem.eql(u8, emit, "/Users") and !std.mem.startsWith(u8, emit, "/Users/")) return;

    const data_path = try std.fmt.allocPrint(allocator, "{s}{s}", .{ data_volume_prefix, emit });
    defer allocator.free(data_path);
    try appendDenyLiteralForEmit(out, allocator, op, data_path);
}

fn appendDenyLiteralForEmit(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    op: []const u8,
    emit: []const u8,
) !void {
    try out.appendSlice(allocator, "(deny ");
    try out.appendSlice(allocator, op);
    try out.appendSlice(allocator, " (literal \"");
    try appendEscaped(out, allocator, emit);
    try out.appendSlice(allocator, "\"))\n");
}

fn appendAllowWriteMinusControls(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    path: []const u8,
    control_roots: []const []const u8,
) !void {
    const emit = sbplEmitPath(path);
    // (allow file-write* (require-all (subpath "ws") (require-not (subpath "ctrl")) ...))
    try out.appendSlice(allocator, "(allow file-write* (require-all (subpath \"");
    try appendEscaped(out, allocator, emit);
    try out.appendSlice(allocator, "\")");
    for (control_roots) |root| {
        // Only carve controls that sit under this RW grant (lexical on original paths).
        if (!profile.isPathWithin(root, path) and !std.mem.eql(u8, root, path)) continue;
        try out.appendSlice(allocator, " (require-not (subpath \"");
        try appendEscaped(out, allocator, sbplEmitPath(root));
        try out.appendSlice(allocator, "\"))");
    }
    try out.appendSlice(allocator, "))\n");
}

fn appendEscaped(out: *std.ArrayList(u8), allocator: std.mem.Allocator, path: []const u8) !void {
    for (path) |c| {
        switch (c) {
            '\\' => try out.appendSlice(allocator, "\\\\"),
            '"' => try out.appendSlice(allocator, "\\\""),
            else => try out.append(allocator, c),
        }
    }
}

/// True if SBPL text grants a broad home directory (should always be false for ryk profiles).
pub fn sbplGrantsHome(sbpl: []const u8, home: []const u8) bool {
    if (home.len == 0) return false;
    // Match exact subpath "HOME" grant forms only (not workspace under home).
    var needle_buf: [512]u8 = undefined;
    if (home.len + 32 > needle_buf.len) return false;
    const needle = std.fmt.bufPrint(&needle_buf, "(subpath \"{s}\")", .{home}) catch return false;
    // Only count as broad HOME if the grant is exactly HOME, not a longer path.
    // Search for the needle and ensure the next char after home in the path is `"`.
    return std.mem.indexOf(u8, sbpl, needle) != null;
}

test "SBPL denies default and grants workspace RW" {
    const allocator = std.testing.allocator;
    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = "/tmp/ryk-sbpl-ws",
        .system_ro_prefixes = &[_][]const u8{ "/usr", "/bin" },
    });
    defer compiled.deinit();

    const sbpl = try renderSbpl(allocator, &compiled);
    defer allocator.free(sbpl);

    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(deny default)") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(version 1)") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(subpath \"/tmp/ryk-sbpl-ws\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "file-write*") != null);
}

test "SBPL system prefixes are read-only not write" {
    const allocator = std.testing.allocator;
    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = "/workspace/proj",
        .system_ro_prefixes = &[_][]const u8{ "/usr", "/bin" },
    });
    defer compiled.deinit();

    const sbpl = try renderSbpl(allocator, &compiled);
    defer allocator.free(sbpl);

    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read* (subpath \"/usr\"))") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read* (subpath \"/bin\"))") != null);
    // No bare write grant for system prefixes.
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-write* (subpath \"/usr\"))") == null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-write* (subpath \"/bin\"))") == null);
}

test "SBPL control roots deny write under workspace" {
    const allocator = std.testing.allocator;
    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = "/workspace/proj",
        .system_ro_prefixes = &[_][]const u8{"/usr"},
    });
    defer compiled.deinit();

    const sbpl = try renderSbpl(allocator, &compiled);
    defer allocator.free(sbpl);

    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(require-not (subpath \"/workspace/proj/.ryk\"))") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(deny file-write* (subpath \"/workspace/proj/.ryk\"))") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(require-not (subpath \"/workspace/proj/.git\"))") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(deny file-write* (subpath \"/workspace/proj/.git\"))") != null);
}

test "SBPL emits process-exec for launch .exec grants without HOME" {
    const allocator = std.testing.allocator;
    const home = "/Users/dev";
    const agent_bin = "/Users/dev/.local/share/claude/versions/2.1.196";
    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = "/Users/dev/projects/app",
        .system_ro_prefixes = &[_][]const u8{ "/usr", "/bin" },
        .exec_paths = &.{agent_bin},
    });
    defer compiled.deinit();

    const sbpl = try renderSbpl(allocator, &compiled);
    defer allocator.free(sbpl);

    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow process-exec (literal \"/Users/dev/.local/share/claude/versions/2.1.196\"))") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read* (literal \"/Users/dev/.local/share/claude/versions/2.1.196\"))") != null);
    // Exec grants must not tree-open via subpath.
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow process-exec (subpath \"/Users/dev/.local/share/claude/versions/2.1.196\"))") == null);
    // Still no broad HOME.
    try std.testing.expect(!sbplGrantsHome(sbpl, home));
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(subpath \"/Users/dev\")") == null);
}

test "SBPL never grants broad HOME" {
    const allocator = std.testing.allocator;
    const home = "/Users/dev";
    const ws = "/Users/dev/projects/app";
    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = ws,
        .system_ro_prefixes = &[_][]const u8{ "/usr", "/bin" },
    });
    defer compiled.deinit();

    const sbpl = try renderSbpl(allocator, &compiled);
    defer allocator.free(sbpl);

    try std.testing.expect(!sbplGrantsHome(sbpl, home));
    try std.testing.expect(std.mem.indexOf(u8, sbpl, home) != null); // workspace path contains home prefix
    // Exact HOME subpath grant must not appear.
    var exact: [128]u8 = undefined;
    const needle = try std.fmt.bufPrint(&exact, "(subpath \"{s}\")", .{home});
    // Workspace grant is longer: (subpath "/Users/dev/projects/app") — allowed.
    // Count only exact HOME: path ends with home then quote.
    try std.testing.expect(std.mem.indexOf(u8, sbpl, needle) == null);
    try std.testing.expect(!compiled.grantsHome(home));
}

test "SBPL escapes quotes and backslashes in paths" {
    const allocator = std.testing.allocator;
    const nasty = "/tmp/x\"y\\z";
    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = nasty,
        .system_ro_prefixes = &[_][]const u8{"/usr"},
    });
    defer compiled.deinit();

    const sbpl = try renderSbpl(allocator, &compiled);
    defer allocator.free(sbpl);

    const escaped_grant = "(subpath \"/tmp/x\\\"y\\\\z\")";
    try std.testing.expect(std.mem.indexOf(u8, sbpl, escaped_grant) != null);
    const escaped_control = "(deny file-write* (subpath \"/tmp/x\\\"y\\\\z/.ryk\"))";
    try std.testing.expect(std.mem.indexOf(u8, sbpl, escaped_control) != null);
}

test "SBPL never emits bare unrestricted file-read-metadata" {
    const allocator = std.testing.allocator;
    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = "/tmp/ryk-sbpl-meta",
        .system_ro_prefixes = &[_][]const u8{ "/usr", "/bin" },
    });
    defer compiled.deinit();

    const sbpl = try renderSbpl(allocator, &compiled);
    defer allocator.free(sbpl);

    // Bare form must not appear; only path-filtered metadata allows.
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read-metadata)\n") == null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read-metadata (literal \"/\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read-metadata (subpath \"/tmp/ryk-sbpl-meta\"))") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read-metadata (subpath \"/usr\"))") != null);
}

test "SBPL path-walk ancestor metadata literals for Users-form grants" {
    const allocator = std.testing.allocator;
    const ws = "/Users/dev/projects/app";
    const host_cfg = "/Users/dev/.codex";
    const launch = "/opt/homebrew/bin/node";
    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = ws,
        .system_ro_prefixes = &[_][]const u8{ "/usr", "/bin" },
        .host_rw_paths = &.{host_cfg},
        .exec_paths = &.{launch},
        .include_tmp = false,
    });
    defer compiled.deinit();

    const sbpl = try renderSbpl(allocator, &compiled);
    defer allocator.free(sbpl);

    // Workspace ancestors: metadata literals only (Node realpath lstat chain).
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read-metadata (literal \"/Users\"))") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read-metadata (literal \"/Users/dev\"))") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read-metadata (literal \"/Users/dev/projects\"))") != null);
    // Data-form twins after Data deny (firmlink lstat residual).
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read-metadata (literal \"/System/Volumes/Data/Users\"))") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read-metadata (literal \"/System/Volumes/Data/Users/dev\"))") != null);
    // Last-match: Data deny before Data-form metadata re-allow.
    const deny_data = std.mem.indexOf(u8, sbpl, "(deny file-read-metadata (subpath \"/System/Volumes/Data\"))") orelse {
        try std.testing.expect(false);
        return;
    };
    const data_form_meta = std.mem.indexOf(u8, sbpl, "(allow file-read-metadata (literal \"/System/Volumes/Data/Users\"))") orelse {
        try std.testing.expect(false);
        return;
    };
    try std.testing.expect(deny_data < data_form_meta);
    // Still no content grant on bare Users / Data Users.
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read* (subpath \"/System/Volumes/Data/Users\"))") == null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read* (literal \"/System/Volumes/Data/Users\"))") == null);
    // Leaf content stays grant-scoped subpath — not ancestor content grants.
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read* (subpath \"/Users/dev/projects/app\"))") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read* (subpath \"/Users\"))") == null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read* (subpath \"/Users/dev\"))") == null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read* (literal \"/Users\"))") == null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read* (literal \"/Users/dev\"))") == null);
    // Host config content remains leaf-only; ancestors are metadata literals (shared with ws).
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read* (subpath \"/Users/dev/.codex\"))") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read* (subpath \"/Users/dev/.ssh\"))") == null);
    // Exec dirname chain: metadata on parents, literal content only on the binary path.
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read-metadata (literal \"/opt\"))") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read-metadata (literal \"/opt/homebrew\"))") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read-metadata (literal \"/opt/homebrew/bin\"))") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read* (literal \"/opt/homebrew/bin/node\"))") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read* (subpath \"/opt\"))") == null);
    // Safety nets from existing product invariants.
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read-metadata)\n") == null);
    try std.testing.expect(!sbplGrantsHome(sbpl, "/Users/dev"));
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(subpath \"$HOME\")") == null);
}

test "SBPL path-walk ancestor metadata for Data-volume Users workspace (M-28)" {
    const allocator = std.testing.allocator;
    const ws_data = "/System/Volumes/Data/Users/dev/projects/app";
    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = ws_data,
        .system_ro_prefixes = &[_][]const u8{"/usr"},
        .include_tmp = false,
    });
    defer compiled.deinit();

    const sbpl = try renderSbpl(allocator, &compiled);
    defer allocator.free(sbpl);

    // Emitted as Users-form ancestors after sbplEmitPath.
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read-metadata (literal \"/Users\"))") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read-metadata (literal \"/Users/dev\"))") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read-metadata (literal \"/Users/dev/projects\"))") != null);
    // Data-form metadata twins after Data deny (same residual as Users-form grants).
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read-metadata (literal \"/System/Volumes/Data/Users\"))") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read-metadata (literal \"/System/Volumes/Data/Users/dev\"))") != null);
    // Last-match order: Data deny, then Data-form metadata re-allow (no content).
    const deny_idx = std.mem.indexOf(u8, sbpl, "(deny file-read-metadata (subpath \"/System/Volumes/Data\"))") orelse {
        try std.testing.expect(false);
        return;
    };
    const data_meta_idx = std.mem.indexOf(u8, sbpl, ";; path-walk Data-form ancestor metadata") orelse {
        try std.testing.expect(false);
        return;
    };
    try std.testing.expect(deny_idx < data_meta_idx);
    // Must not emit content on Data-form or Users ancestors.
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read* (subpath \"/Users\"))") == null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read* (subpath \"/System/Volumes/Data/Users\"))") == null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read* (literal \"/System/Volumes/Data/Users\"))") == null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read* (subpath \"/Users/dev/projects/app\"))") != null);
}

// Issue #194: Seatbelt must content-grant the file grok 1.0.4 opens
// (~/.grok/config.toml) and emit ancestor metadata so path-walk can lstat
// ~/.grok. Must not content-grant bare HOME, ~/.grok/, or Keychain.
test "SBPL grok config.toml grant covers file plus parent-walk metadata" {
    const allocator = std.testing.allocator;
    const grok_config = "/Users/dev/.grok/config.toml";
    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = "/tmp/ryk-grok-repro",
        .system_ro_prefixes = &[_][]const u8{ "/usr", "/bin" },
        .host_rw_paths = &.{grok_config},
        .control_roots = &.{grok_config},
    });
    defer compiled.deinit();

    const sbpl = try renderSbplWithOptions(allocator, &compiled, .{
        .write_deny_literals = &.{grok_config},
    });
    defer allocator.free(sbpl);

    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read* (subpath \"/Users/dev/.grok/config.toml\"))") != null);
    // Parent-walk: metadata-only on ~/.grok (and HOME) so open(config.toml) can
    // lstat intermediates. Not a content grant on those ancestors.
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read-metadata (literal \"/Users/dev/.grok\"))") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read-metadata (literal \"/Users/dev\"))") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read* (subpath \"/Users/dev/.grok\"))\n") == null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read* (subpath \"/Users/dev\"))") == null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "Library/Keychains") == null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(deny file-write* (literal \"/Users/dev/.grok/config.toml\"))") != null);
}

test "SBPL host config host_rw_paths emit subpath RW without bare HOME" {
    const allocator = std.testing.allocator;
    const claude_cfg = "/Users/dev/.claude";
    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = "/Users/dev/projects/app",
        .system_ro_prefixes = &[_][]const u8{ "/usr", "/bin" },
        .host_rw_paths = &.{claude_cfg},
    });
    defer compiled.deinit();

    const sbpl = try renderSbpl(allocator, &compiled);
    defer allocator.free(sbpl);

    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read* (subpath \"/Users/dev/.claude\"))") != null);
    // RW grant emits write allow with control-root require-not, not bare HOME.
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(subpath \"/Users/dev/.claude\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read* (subpath \"/Users/dev\"))") == null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read* (subpath \"/Users/dev/.ssh\"))") == null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read* (subpath \"/Users/dev/Library\"))") == null);
}

test "SBPL F-03 file-link fence denies global link then allows workspace only" {
    const allocator = std.testing.allocator;
    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = "/Users/dev/projects/app",
        .system_ro_prefixes = &[_][]const u8{ "/usr", "/bin" },
        .host_rw_paths = &.{"/Users/dev/.codex"},
    });
    defer compiled.deinit();

    const sbpl = try renderSbpl(allocator, &compiled);
    defer allocator.free(sbpl);

    // Pathless deny then workspace allow with control require-not (last-match after grants).
    const deny_at = std.mem.indexOf(u8, sbpl, "(deny file-link)") orelse return error.TestUnexpectedResult;
    // Default controls (.ryk/.git) → require-all form, not bare workspace subpath allow.
    const allow_ws = std.mem.indexOf(
        u8,
        sbpl,
        "(allow file-link (require-all (subpath \"/Users/dev/projects/app\")",
    ) orelse return error.TestUnexpectedResult;
    try std.testing.expect(allow_ws > deny_at);
    try std.testing.expect(std.mem.indexOf(
        u8,
        sbpl,
        "(require-not (subpath \"/Users/dev/projects/app/.git\"))",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        sbpl,
        "(require-not (subpath \"/Users/dev/projects/app/.ryk\"))",
    ) != null);
    // No Data-form workspace file-link grant (M-28).
    try std.testing.expect(std.mem.indexOf(
        u8,
        sbpl,
        "(allow file-link (require-all (subpath \"/System/Volumes/Data/Users/dev/projects/app\")",
    ) == null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        sbpl,
        "(allow file-link (subpath \"/System/Volumes/Data/Users/dev/projects/app\"))",
    ) == null);
    // Must not re-allow file-link on host-config roots (reopens cross-root).
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-link (subpath \"/Users/dev/.codex\"))") == null);
    // Not a global allow.
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-link)\n") == null);
}

test "SBPL F-03 file-link fence still emitted without host_rw" {
    const allocator = std.testing.allocator;
    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = "/Users/dev/projects/app",
        .system_ro_prefixes = &[_][]const u8{ "/usr", "/bin" },
    });
    defer compiled.deinit();
    const sbpl = try renderSbpl(allocator, &compiled);
    defer allocator.free(sbpl);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(deny file-link)") != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        sbpl,
        "(allow file-link (require-all (subpath \"/Users/dev/projects/app\")",
    ) != null);
}

test "SBPL protected host config file is readable but write denied after RW grant" {
    const config_path = "/Users/dev/.codex/config.toml";
    // Dual path: authority file as control root (require-not + subpath deny) and
    // write_deny_literals (exact literal deny after RW allow). Production apply
    // passes the same list both ways.
    var compiled = try profile.compileProfile(std.testing.allocator, .{
        .workspace_root = "/Users/dev/work",
        .host_rw_paths = &.{"/Users/dev/.codex"},
        .control_roots = &.{config_path},
    });
    defer compiled.deinit();
    try std.testing.expect(compiled.isControlPath(config_path));
    try std.testing.expect(!compiled.isAgentWritable(config_path));
    const sbpl = try renderSbplWithOptions(std.testing.allocator, &compiled, .{
        .write_deny_literals = &.{config_path},
    });
    defer std.testing.allocator.free(sbpl);

    const allow = std.mem.indexOf(
        u8,
        sbpl,
        "(allow file-write* (require-all (subpath \"/Users/dev/.codex\")",
    ) orelse return error.TestUnexpectedResult;
    // Control-root require-not on the authority path.
    try std.testing.expect(std.mem.indexOf(u8, sbpl[allow..], "(require-not (subpath \"/Users/dev/.codex/config.toml\"))") != null);
    const deny = std.mem.indexOf(
        u8,
        sbpl,
        "(deny file-write* (literal \"/Users/dev/.codex/config.toml\"))",
    ) orelse return error.TestUnexpectedResult;
    try std.testing.expect(deny > allow);
    // Defense-in-depth subpath deny for control roots.
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(deny file-write* (subpath \"/Users/dev/.codex/config.toml\"))") != null);
}

test "SBPL codex system ro_paths emit narrow /etc/codex without bare /etc" {
    const allocator = std.testing.allocator;
    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = "/Users/dev/projects/app",
        .system_ro_prefixes = &[_][]const u8{ "/usr", "/bin" },
        .ro_paths = &.{ "/etc/codex", "/private/etc/codex" },
        .host_rw_paths = &.{"/Users/dev/.codex"},
    });
    defer compiled.deinit();

    const sbpl = try renderSbpl(allocator, &compiled);
    defer allocator.free(sbpl);

    // Narrow host system RO for Codex requirements residual.
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read* (subpath \"/etc/codex\"))") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read* (subpath \"/private/etc/codex\"))") != null);
    // Path-walk metadata ancestors for /etc and /private/etc are OK (metadata only).
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read-metadata (literal \"/etc\"))") != null or
        std.mem.indexOf(u8, sbpl, "(allow file-read-metadata (literal \"/private\"))") != null);
    // Never bare /etc content grant (passwd, hosts, other agents).
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read* (subpath \"/etc\"))") == null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read* (subpath \"/private/etc\"))") == null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-write* (subpath \"/etc/codex\"))") == null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read* (subpath \"/Users/dev\"))") == null);
    try std.testing.expect(!sbplGrantsHome(sbpl, "/Users/dev"));
}

test "SBPL narrows /dev writes to null and urandom only" {
    const allocator = std.testing.allocator;
    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = "/tmp/ryk-sbpl-dev",
        .system_ro_prefixes = &[_][]const u8{ "/usr", "/bin" },
    });
    defer compiled.deinit();

    const sbpl = try renderSbpl(allocator, &compiled);
    defer allocator.free(sbpl);

    // Broad /dev write grant must not appear.
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-write* (subpath \"/dev\"))") == null);
    // Narrow device nodes required for exec/stdio.
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-write* (literal \"/dev/null\"))") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-write* (literal \"/dev/urandom\"))") != null);
    // Read/ioctl remain broad for exec (TTY, null reads, etc.).
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read* (subpath \"/dev\"))") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-ioctl (subpath \"/dev\"))") != null);
    // mach-lookup remains (dyld); mach-register is no longer granted.
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow mach-lookup)") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow mach-register)") == null);
}

test "SBPL hardened default narrows process* and broad /private/var" {
    const allocator = std.testing.allocator;
    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = "/tmp/ryk-sbpl-hardened",
        .system_ro_prefixes = &[_][]const u8{ "/usr", "/bin" },
    });
    defer compiled.deinit();

    const sbpl = try renderSbpl(allocator, &compiled);
    defer allocator.free(sbpl);

    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow process*)") == null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow process-fork)") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow process-exec)") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow process-info*)") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read* (literal \"/private/var\"))") == null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read* (subpath \"/private/var/select\"))") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read* (subpath \"/var/select\"))") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read* (literal \"/var/db/xcode_select_link\"))") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read* (literal \"/private/var/db/xcode_select_link\"))") != null);
    // Must not open bare /var/db tree (host receipts) — only dyld + xcode_select_link leaves.
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read* (subpath \"/var/db\"))") == null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read* (subpath \"/private/var/db\"))") == null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read* (subpath \"/private/var/db/dyld\"))") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow network*)") != null);
}

test "SBPL compatible retains process* and broad /private/var" {
    const allocator = std.testing.allocator;
    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = "/tmp/ryk-sbpl-compat",
        .system_ro_prefixes = &[_][]const u8{ "/usr", "/bin" },
    });
    defer compiled.deinit();

    const sbpl = try renderSbplWithOptions(allocator, &compiled, .{ .profile_grade = .compatible });
    defer allocator.free(sbpl);

    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow process*)") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read* (literal \"/private/var\"))") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow network*)") != null);
}

test "SBPL route forcing removes broad network and allows only proxy TCP port" {
    const allocator = std.testing.allocator;
    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = "/tmp/ryk-sbpl-route",
        .system_ro_prefixes = &[_][]const u8{ "/usr", "/bin" },
    });
    defer compiled.deinit();

    const sbpl = try renderSbplWithOptions(allocator, &compiled, .{
        .network_route_forcing = .{ .proxy_port = 43123 },
        .profile_grade = .hardened,
    });
    defer allocator.free(sbpl);

    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow network*)") == null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(remote tcp \"localhost:43123\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(remote tcp \"*:43123\")") == null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(remote tcp)") == null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(remote udp)") == null);
    // Hardened: inbound/bind remain so route-forced agents can listen.
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow network-inbound)") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow network-bind)") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow network-outbound (remote tcp \"localhost:43123\"))") != null);
}

test "SBPL strict route forcing denies inbound/bind" {
    const allocator = std.testing.allocator;
    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = "/tmp/ryk-sbpl-strict-route",
        .system_ro_prefixes = &[_][]const u8{ "/usr", "/bin" },
    });
    defer compiled.deinit();

    const sbpl = try renderSbplWithOptions(allocator, &compiled, .{
        .network_route_forcing = .{ .proxy_port = 43123 },
        .profile_grade = .strict,
    });
    defer allocator.free(sbpl);

    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow network*)") == null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow network-inbound)") == null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow network-bind)") == null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow network-outbound (remote tcp \"localhost:43123\"))") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow process*)") == null);
    try std.testing.expectEqualStrings(
        "proxy route-forced (outbound TCP to ryk loopback proxy only; inbound/bind denied; UDP/QUIC unrestricted)",
        networkScopeSummary(.strict, true),
    );
}

test "SBPL strict without route force omits network*" {
    const allocator = std.testing.allocator;
    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = "/tmp/ryk-sbpl-strict-no-route",
        .system_ro_prefixes = &[_][]const u8{"/usr"},
    });
    defer compiled.deinit();

    const sbpl = try renderSbplWithOptions(allocator, &compiled, .{ .profile_grade = .strict });
    defer allocator.free(sbpl);

    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow network*)") == null);
    try std.testing.expectEqualStrings(
        "deny-default (no broad network*; no route force)",
        networkScopeSummary(.strict, false),
    );
}

test "SBPL default remains explicit unrestricted network under hardened" {
    const allocator = std.testing.allocator;
    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = "/tmp/ryk-sbpl-network-default",
        .system_ro_prefixes = &[_][]const u8{"/usr"},
    });
    defer compiled.deinit();

    const sbpl = try renderSbpl(allocator, &compiled);
    defer allocator.free(sbpl);

    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow network*)") != null);
    try std.testing.expectEqualStrings("unrestricted", networkScopeSummary(.hardened, false));
}

// M-6 partial: dual-encoding lock — SBPL tokens must match networkScopeSummary invariants
// for every grade × route_force cell (claim vs render drift guard).
test "grade residual matrix: SBPL tokens match networkScopeSummary invariants" {
    const allocator = std.testing.allocator;
    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = "/tmp/ryk-sbpl-grade-matrix",
        .system_ro_prefixes = &[_][]const u8{"/usr"},
    });
    defer compiled.deinit();

    const grades = [_]SeatbeltProfileGrade{ .compatible, .hardened, .strict };
    for (grades) |grade| {
        // No route force.
        {
            const sbpl = try renderSbplWithOptions(allocator, &compiled, .{ .profile_grade = grade });
            defer allocator.free(sbpl);
            const summary = networkScopeSummary(grade, false);
            const has_network_star = std.mem.indexOf(u8, sbpl, "(allow network*)") != null;
            switch (grade) {
                .compatible, .hardened => {
                    try std.testing.expect(has_network_star);
                    try std.testing.expectEqualStrings("unrestricted", summary);
                    const has_process_star = std.mem.indexOf(u8, sbpl, "(allow process*)") != null;
                    const has_private_var = std.mem.indexOf(u8, sbpl, "(allow file-read* (literal \"/private/var\"))") != null;
                    try std.testing.expectEqual(grade == .compatible, has_process_star);
                    try std.testing.expectEqual(grade == .compatible, has_private_var);
                },
                .strict => {
                    try std.testing.expect(!has_network_star);
                    try std.testing.expectEqualStrings(
                        "deny-default (no broad network*; no route force)",
                        summary,
                    );
                    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow process*)") == null);
                    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow file-read* (literal \"/private/var\"))") == null);
                },
            }
        }
        // Route force.
        {
            const sbpl = try renderSbplWithOptions(allocator, &compiled, .{
                .profile_grade = grade,
                .network_route_forcing = .{ .proxy_port = 43123 },
            });
            defer allocator.free(sbpl);
            const summary = networkScopeSummary(grade, true);
            try std.testing.expect(std.mem.indexOf(u8, sbpl, "(allow network*)") == null);
            try std.testing.expect(std.mem.indexOf(u8, sbpl, "(remote tcp \"localhost:43123\")") != null);
            const has_inbound = std.mem.indexOf(u8, sbpl, "(allow network-inbound)") != null;
            const has_bind = std.mem.indexOf(u8, sbpl, "(allow network-bind)") != null;
            switch (grade) {
                .compatible, .hardened => {
                    try std.testing.expect(has_inbound and has_bind);
                    try std.testing.expectEqualStrings(
                        "proxy route-forced (outbound TCP to ryk loopback proxy only; inbound/bind unrestricted; UDP/QUIC unrestricted)",
                        summary,
                    );
                },
                .strict => {
                    try std.testing.expect(!has_inbound and !has_bind);
                    try std.testing.expectEqualStrings(
                        "proxy route-forced (outbound TCP to ryk loopback proxy only; inbound/bind denied; UDP/QUIC unrestricted)",
                        summary,
                    );
                },
            }
        }
    }
}

test "SBPL denies /System/Volumes/Data even if bare /System is granted" {
    const allocator = std.testing.allocator;
    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = "/tmp/ryk-sbpl-sys",
        // Adversarial: custom bare /System must still not open Data volume homes.
        .system_ro_prefixes = &[_][]const u8{ "/usr", "/System" },
    });
    defer compiled.deinit();

    const sbpl = try renderSbpl(allocator, &compiled);
    defer allocator.free(sbpl);

    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(deny file-read* (subpath \"/System/Volumes/Data\"))") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(deny file-read-metadata (subpath \"/System/Volumes/Data\"))") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(deny process-exec (subpath \"/System/Volumes/Data\"))") != null);
    // Blanket deny of all Volumes is too broad (Preboot) and clobbers realpath workspaces.
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(deny file-read* (subpath \"/System/Volumes\"))") == null);
}

test "SBPL emits Users-form for Data-volume realpath workspace (M-28 / R2-1)" {
    const allocator = std.testing.allocator;
    // Model macOS firmlink realpath: /Users/… → /System/Volumes/Data/Users/…
    const ws_data = "/System/Volumes/Data/Users/dev/projects/app";
    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = ws_data,
        .system_ro_prefixes = &[_][]const u8{ "/usr", "/bin" },
        .include_tmp = false,
    });
    defer compiled.deinit();

    // Pure model: workspace under Data remains granted; sibling home secrets are not.
    try std.testing.expect(compiled.isGrantedReadable(ws_data));
    try std.testing.expect(compiled.isAgentWritable(ws_data));
    try std.testing.expect(compiled.isGrantedReadable("/System/Volumes/Data/Users/dev/projects/app/src/main.zig"));
    try std.testing.expect(!compiled.isGrantedReadable("/System/Volumes/Data/Users/dev/.ssh/id_rsa"));
    try std.testing.expect(!compiled.isGrantedReadable("/System/Volumes/Data/Users/other/secret"));

    const sbpl = try renderSbpl(allocator, &compiled);
    defer allocator.free(sbpl);

    // Seatbelt matches Users-form; emit /Users/… not Data-form grant strings.
    const allow_ws_users = "(allow file-read* (subpath \"/Users/dev/projects/app\"))";
    try std.testing.expect(std.mem.indexOf(u8, sbpl, allow_ws_users) != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(subpath \"/System/Volumes/Data/Users/dev/projects/app\")") == null);
    // Control carve-outs also Users-form (.ryk + .git).
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(require-not (subpath \"/Users/dev/projects/app/.ryk\"))") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(deny file-write* (subpath \"/Users/dev/projects/app/.ryk\"))") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(require-not (subpath \"/Users/dev/projects/app/.git\"))") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(deny file-write* (subpath \"/Users/dev/projects/app/.git\"))") != null);
    // Data deny still present (blocks Data-form sibling opens).
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(deny file-read* (subpath \"/System/Volumes/Data\"))") != null);
    // Users-mapped workspace needs no Data re-allow section.
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "re-allow non-Users grants under /System/Volumes/Data") == null);
    // Non-workspace Data home must not appear as a grant.
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(subpath \"/System/Volumes/Data/Users/dev/.ssh\")") == null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(subpath \"/Users/dev/.ssh\")") == null);
}

test "sbplEmitPath strips Data prefix only under Users tree" {
    try std.testing.expectEqualStrings(
        "/Users/dev/projects/app",
        sbplEmitPath("/System/Volumes/Data/Users/dev/projects/app"),
    );
    try std.testing.expectEqualStrings("/Users", sbplEmitPath("/System/Volumes/Data/Users"));
    // Non-Users Data paths pass through (not dual-mapped).
    try std.testing.expectEqualStrings(
        "/System/Volumes/Data/private/tmp",
        sbplEmitPath("/System/Volumes/Data/private/tmp"),
    );
    // Component boundary: UsersFoo must not strip.
    try std.testing.expectEqualStrings(
        "/System/Volumes/Data/UsersFoo",
        sbplEmitPath("/System/Volumes/Data/UsersFoo"),
    );
    // Already Users-form: unchanged.
    try std.testing.expectEqualStrings("/Users/dev/app", sbplEmitPath("/Users/dev/app"));
    // Unrelated paths unchanged.
    try std.testing.expectEqualStrings("/tmp/ws", sbplEmitPath("/tmp/ws"));
}

test "SBPL production defaults omit bare /System and /Library grants" {
    if (@import("builtin").os.tag != .macos) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = "/tmp/ryk-sbpl-defaults",
    });
    defer compiled.deinit();

    const sbpl = try renderSbpl(allocator, &compiled);
    defer allocator.free(sbpl);

    // Exact bare /System and /Library grant forms must not appear (trailing ")).
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(subpath \"/System\"))") == null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(subpath \"/Library\"))") == null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(subpath \"/System/Library\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(subpath \"/Library/Frameworks\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(deny file-read* (subpath \"/System/Volumes/Data\"))") != null);
}

test "SBPL secret boundary denies workspace env forms but not exact safe templates" {
    const allocator = std.testing.allocator;
    var ordinary = try profile.compileProfile(allocator, .{
        .workspace_root = "/workspace/app",
        .system_ro_prefixes = &[_][]const u8{"/usr"},
    });
    defer ordinary.deinit();
    var protected = try profile.compileProfile(allocator, .{
        .workspace_root = "/workspace/app",
        .system_ro_prefixes = &[_][]const u8{"/usr"},
        .protect_workspace_secrets = true,
    });
    defer protected.deinit();

    const ordinary_sbpl = try renderSbpl(allocator, &ordinary);
    defer allocator.free(ordinary_sbpl);
    const protected_sbpl = try renderSbpl(allocator, &protected);
    defer allocator.free(protected_sbpl);

    try std.testing.expect(std.mem.indexOf(u8, ordinary_sbpl, "workspace env secret carve-out") == null);
    try std.testing.expect(
        std.mem.indexOf(u8, protected_sbpl, ";; workspace env secret carve-out") != null,
    );
    try std.testing.expect(
        std.mem.indexOf(
            u8,
            protected_sbpl,
            "(deny file-read* (require-all (subpath \"/workspace/app\")",
        ) != null,
    );
    try std.testing.expect(
        std.mem.indexOf(
            u8,
            protected_sbpl,
            "(deny file-write* (require-all (subpath \"/workspace/app\")",
        ) != null,
    );
    try std.testing.expect(
        std.mem.indexOf(
            u8,
            protected_sbpl,
            "(deny file-read-metadata (require-all (subpath \"/workspace/app\")",
        ) != null,
    );
    try std.testing.expect(
        std.mem.indexOf(
            u8,
            protected_sbpl,
            profile.workspace_secret_form_sbpl_regex,
        ) != null,
    );
    var template_needle_buf: [128]u8 = undefined;
    const template_needle = try std.fmt.bufPrint(
        &template_needle_buf,
        "(require-not (regex #\"/[.]env[.]({s})$\"))",
        .{profile.workspace_secret_safe_template_sbpl_alt},
    );
    try std.testing.expect(std.mem.indexOf(u8, protected_sbpl, template_needle) != null);
}

test "SBPL secret boundary uses live Users firmlink form" {
    const allocator = std.testing.allocator;
    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = "/System/Volumes/Data/Users/dev/projects/app",
        .system_ro_prefixes = &[_][]const u8{"/usr"},
        .protect_workspace_secrets = true,
    });
    defer compiled.deinit();

    const sbpl = try renderSbpl(allocator, &compiled);
    defer allocator.free(sbpl);

    try std.testing.expect(
        std.mem.indexOf(
            u8,
            sbpl,
            "(deny file-read* (require-all (subpath \"/Users/dev/projects/app\")",
        ) != null,
    );
    try std.testing.expect(
        std.mem.indexOf(
            u8,
            sbpl,
            "(deny file-read* (require-all (subpath \"/System/Volumes/Data/Users/dev/projects/app\")",
        ) == null,
    );
}

test "SBPL protect-on emits explicit denies for hardlink alias paths" {
    const allocator = std.testing.allocator;
    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = "/workspace/app",
        .system_ro_prefixes = &[_][]const u8{"/usr"},
        .protect_workspace_secrets = true,
    });
    defer compiled.deinit();

    const sbpl = try renderSbplWithOptions(allocator, &compiled, .{
        .hardlink_alias_denies = &[_][]const u8{"/workspace/app/notes.txt"},
    });
    defer allocator.free(sbpl);

    try std.testing.expect(std.mem.indexOf(u8, sbpl, "multi-nlink non-secret basenames") != null);
    try std.testing.expect(
        std.mem.indexOf(u8, sbpl, "(deny file-read* (subpath \"/workspace/app/notes.txt\"))") != null,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, sbpl, "(deny file-write* (subpath \"/workspace/app/notes.txt\"))") != null,
    );
}

test "collectSecretHardlinkAliasPaths finds non-secret basenames sharing secret inode" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = ".env", .data = "secret-body" });
    try tmp.dir.writeFile(io, .{ .sub_path = "ordinary.txt", .data = "plain" });
    tmp.dir.hardLink(".env", tmp.dir, "alias.txt", io, .{}) catch return error.SkipZigTest;

    const root = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(root);

    const aliases = try collectSecretHardlinkAliasPaths(allocator, io, root);
    defer freeHardlinkAliasPaths(allocator, aliases);

    try std.testing.expectEqual(@as(usize, 1), aliases.len);
    try std.testing.expect(std.mem.endsWith(u8, aliases[0], "alias.txt"));
    try std.testing.expect(!std.mem.endsWith(u8, aliases[0], ".env"));
    try std.testing.expect(!std.mem.endsWith(u8, aliases[0], "ordinary.txt"));
}

test "collectSecretHardlinkAliasPaths ignores internal non-secret hardlink groups" {
    // Cargo/incremental trees hardlink many non-secret objects. Those must not
    // become SBPL path denies (profile size → sandbox_init / child_apply_failed).
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "obj-a.o", .data = "object-body" });
    tmp.dir.hardLink("obj-a.o", tmp.dir, "obj-b.o", io, .{}) catch return error.SkipZigTest;
    try tmp.dir.writeFile(io, .{ .sub_path = "readme.txt", .data = "plain" });

    const root = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(root);

    const aliases = try collectSecretHardlinkAliasPaths(allocator, io, root);
    defer freeHardlinkAliasPaths(allocator, aliases);

    try std.testing.expectEqual(@as(usize, 0), aliases.len);
}

test "collectSecretHardlinkAliasPaths denies outside secret hardlinked under non-secret name" {
    // Outside `.env` hardlinked into the workspace as config.txt must be denied
    // even though no secret-form basename exists inside the workspace walk.
    // Small residual (nlink=2, seen=1) remains hostile under residual threshold.
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var outside = std.testing.tmpDir(.{});
    defer outside.cleanup();
    var workspace = std.testing.tmpDir(.{});
    defer workspace.cleanup();

    try outside.dir.writeFile(io, .{ .sub_path = ".env", .data = "OUTSIDE-SECRET-CANARY" });
    outside.dir.hardLink(".env", workspace.dir, "config.txt", io, .{}) catch return error.SkipZigTest;
    try workspace.dir.writeFile(io, .{ .sub_path = "ordinary.txt", .data = "plain" });

    const root = try workspace.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(root);

    const aliases = try collectSecretHardlinkAliasPaths(allocator, io, root);
    defer freeHardlinkAliasPaths(allocator, aliases);

    try std.testing.expectEqual(@as(usize, 1), aliases.len);
    try std.testing.expect(std.mem.endsWith(u8, aliases[0], "config.txt"));
    try std.testing.expect(!std.mem.endsWith(u8, aliases[0], "ordinary.txt"));
}

test "collectSecretHardlinkAliasPaths ignores package-store high-nlink outside residual" {
    // pnpm/yarn content-addressed stores: one workspace leaf with huge nlink
    // (many store hardlinks outside the walk). Large residual must not produce
    // mass hardlink_alias_denies (SBPL re-bloom → sandbox_init failure).
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var outside = std.testing.tmpDir(.{});
    defer outside.cleanup();
    var workspace = std.testing.tmpDir(.{});
    defer workspace.cleanup();

    try outside.dir.writeFile(io, .{ .sub_path = "blob", .data = "content-addressed-body" });
    // residual = nlink - seen; seen=1 in workspace. Build residual well above
    // secret_hardlink_max_outside_residual_links (8) to model a package store.
    const extra_links: u32 = 20;
    var i: u32 = 0;
    while (i < extra_links) : (i += 1) {
        var name_buf: [32]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "hl-{d}", .{i});
        outside.dir.hardLink("blob", outside.dir, name, io, .{}) catch return error.SkipZigTest;
    }
    outside.dir.hardLink("blob", workspace.dir, "pkg-file.js", io, .{}) catch return error.SkipZigTest;
    try workspace.dir.writeFile(io, .{ .sub_path = "readme.txt", .data = "plain" });

    const root = try workspace.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(root);

    const aliases = try collectSecretHardlinkAliasPaths(allocator, io, root);
    defer freeHardlinkAliasPaths(allocator, aliases);

    try std.testing.expectEqual(@as(usize, 0), aliases.len);
}

test "outsideResidualIsHostile threshold: small residual yes, large no" {
    // Pure residual law (no FS): residual in (0, max] hostile; 0 and max+1 not.
    try std.testing.expect(!outsideResidualIsHostile(1, 1)); // fully contained
    try std.testing.expect(!outsideResidualIsHostile(2, 2));
    try std.testing.expect(outsideResidualIsHostile(2, 1)); // planted secret shape
    try std.testing.expect(outsideResidualIsHostile(
        secret_hardlink_max_outside_residual_links + 1,
        1,
    )); // residual == max
    try std.testing.expect(!outsideResidualIsHostile(
        secret_hardlink_max_outside_residual_links + 2,
        1,
    )); // residual == max+1 (package-store shape)
    try std.testing.expect(!outsideResidualIsHostile(5000, 1));
}

test "collectSecretHardlinkAliasPaths skips workspace symlinks without ScanOpenFailed" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = ".env", .data = "secret-body" });
    try tmp.dir.writeFile(io, .{ .sub_path = "target.txt", .data = "plain" });
    tmp.dir.symLink(io, "target.txt", "shim", .{}) catch return error.SkipZigTest;
    tmp.dir.hardLink(".env", tmp.dir, "alias.txt", io, .{}) catch return error.SkipZigTest;

    const root = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(root);

    const aliases = try collectSecretHardlinkAliasPaths(allocator, io, root);
    defer freeHardlinkAliasPaths(allocator, aliases);

    try std.testing.expectEqual(@as(usize, 1), aliases.len);
    try std.testing.expect(std.mem.endsWith(u8, aliases[0], "alias.txt"));
}

test "collectSecretHardlinkAliasPaths fails closed on mode-000 nested directory" {
    // Unreadable nested dir with secret + root hardlink alias must not soft-skip
    // the dir (fail open). Scan returns ScanOpenFailed so prepare fails closed.
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "d");
    try tmp.dir.writeFile(io, .{ .sub_path = "d/.env", .data = "secret-body" });
    tmp.dir.hardLink("d/.env", tmp.dir, "notes.txt", io, .{}) catch return error.SkipZigTest;

    const root = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(root);
    const nested = try std.fs.path.join(allocator, &.{ root, "d" });
    defer allocator.free(nested);
    const nested_z = try allocator.dupeZ(u8, nested);
    defer allocator.free(nested_z);

    // Drop all perms on nested dir; restore so tmpDir cleanup can remove it.
    if (std.c.chmod(nested_z.ptr, 0) != 0) return error.SkipZigTest;
    defer _ = std.c.chmod(nested_z.ptr, 0o755);

    try std.testing.expectError(
        error.ScanOpenFailed,
        collectSecretHardlinkAliasPaths(allocator, io, root),
    );
}

test "collectSecretHardlinkAliasPaths missing workspace is empty not ScanOpenFailed" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const aliases = try collectSecretHardlinkAliasPaths(
        allocator,
        io,
        "/tmp/ryk-hardlink-scan-missing-ws-does-not-exist",
    );
    defer freeHardlinkAliasPaths(allocator, aliases);
    try std.testing.expectEqual(@as(usize, 0), aliases.len);
}

test "secret hardlink scan capacity matches Linux monorepo floor" {
    // Regression: 50_000 was below typical monorepo dirent counts (node_modules,
    // vendor checkouts, SPM .build) and blocked protect-on Seatbelt prepare.
    try std.testing.expect(secret_hardlink_scan_max_entries >= 1_000_000);
    try std.testing.expect(secret_hardlink_scan_max_depth >= 48);
    // Residual filter + alias-deny cap: small planted residual still hostile;
    // package-store residual must not re-bloom; denylist cap is a backstop.
    try std.testing.expect(secret_hardlink_max_outside_residual_links >= 4);
    try std.testing.expect(secret_hardlink_max_outside_residual_links <= 8);
    try std.testing.expect(secret_hardlink_alias_deny_max >= 1024);
}

test "secret policy: SBPL emit embeds profile-owned fragments; path == basename law" {
    // Product law is a single basename classifier. SBPL emission must embed only
    // profile-owned regex fragments (no local .env regex). Live denial is proven
    // by process canaries, not a second pure simulator alias.
    const basenames = [_][]const u8{
        ".env",
        ".env.local",
        ".env.production",
        ".env.example.local",
        ".env.example",
        ".env.sample",
        ".env.template",
        ".envrc",
        "notes.txt",
        "service.env",
        ".env.",
        "env",
        ".ENV",
    };

    for (basenames) |name| {
        const zig = profile.isWorkspaceSecretBasename(name);
        try std.testing.expectEqual(zig, profile.isWorkspaceSecretPath(name));
        // Path form basenames via basename(); classifier is component-level.
        var path_buf: [128]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buf, "/workspace/{s}", .{name});
        try std.testing.expectEqual(zig, profile.isWorkspaceSecretPath(path));
    }

    // Template stems in SBPL alt are derived only from the name list.
    try std.testing.expectEqualStrings("example|sample|template", profile.workspace_secret_safe_template_sbpl_alt);
    for (profile.workspace_secret_safe_template_names) |full| {
        try std.testing.expect(std.mem.startsWith(u8, full, ".env."));
        const stem = full[".env.".len..];
        try std.testing.expect(std.mem.indexOf(u8, profile.workspace_secret_safe_template_sbpl_alt, stem) != null);
    }

    const allocator = std.testing.allocator;
    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = "/workspace/app",
        .system_ro_prefixes = &[_][]const u8{"/usr"},
        .protect_workspace_secrets = true,
    });
    defer compiled.deinit();
    const sbpl = try renderSbpl(allocator, &compiled);
    defer allocator.free(sbpl);

    // Form regex + template require-not come only from profile constants.
    try std.testing.expect(std.mem.indexOf(u8, sbpl, profile.workspace_secret_form_sbpl_regex) != null);
    var needle_buf: [160]u8 = undefined;
    const needle = try std.fmt.bufPrint(
        &needle_buf,
        "(require-not (regex #\"/[.]env[.]({s})$\"))",
        .{profile.workspace_secret_safe_template_sbpl_alt},
    );
    try std.testing.expect(std.mem.indexOf(u8, sbpl, needle) != null);

    // Emission helper matches what SBPL contains (single emission path).
    var pred: std.ArrayList(u8) = .empty;
    defer pred.deinit(allocator);
    try profile.appendWorkspaceSecretSbplRegexPredicates(&pred, allocator);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, pred.items) != null);
}

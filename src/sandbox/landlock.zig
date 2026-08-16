//! Linux Landlock FS apply.
//!
//! Sequence:
//!   **Parent (before fork):** `buildChildLandlockPlan` enumerates control-expand
//!   RW children (opendir/readdir/malloc OK — may run under a multi-threaded parent).
//!   **Child (after fork):** ABI detect → rights mask → create ruleset → PATH_BENEATH
//!   grants from the precomputed plan only (open + landlock syscalls; **no**
//!   opendir/readdir) → prctl(NO_NEW_PRIVS) → landlock_restrict_self → exec.
//!
//! Never box the parent ryk CLI. Filesystem PATH_BENEATH rules come from
//! `CompiledProfile` grants + expand plan. Optional Phase 2 TCP route forcing
//! uses Landlock network port rules in the same child-only restrict_self call.
//! Landlock network rules are port-scoped, not address-scoped; the launcher must
//! keep this residual visible in docs/evidence.
//!
//! On non-Linux: compile-time stubs; probes return unavailable; apply errors.
//! Parent-side expand helpers still run for unit tests on any POSIX host.
//!
//! ## Residual / hardening notes
//!
//! **Hardlinks (M-12):** Expand skips symlink children (`DT_LNK`) and install uses
//! `O_NOFOLLOW`. Non-directory expand leaves with `st_nlink > 1` are also skipped
//! so a pre-planted hardlink to an outside same-FS inode does not become an RW
//! PATH_BENEATH surface. Residual: legitimate multi-linked files under the
//! workspace lose leaf RW (write via another single-link name, or parent dir grant
//! when expand does not apply). Directories are never skipped on nlink (normal
//! dir nlink ≥ 2). Landlock remains path-based — hardlinks created *after* plan
//! build are outside this filter.
//!
//! **Realpath at install (M-13):** Grant paths are realpath'd when possible before
//! `O_PATH|O_NOFOLLOW` open so merged-usr symlink prefixes (`/lib` → `/usr/lib`)
//! install as the kernel-visible path. Lexical path is retried if realpath fails.
//! Optional (non-required) RO opens may still soft-skip when neither form opens.
//!
//! **ABI probe:** `probeAbi` / `isAbiAvailable` are the single source of truth;
//! `linux.detectLandlock` must call them (not re-syscall).
//!
//! **TOCTOU expand plan → child open (M-37 residual):** The parent plan is a
//! snapshot: expand enumerates and opens later in the child. Between plan build
//! and child `O_PATH` open, an attacker with concurrent write access to the
//! workspace can replace a grant leaf (unlink/rename/symlink swap). Mitigations
//! already applied: `O_NOFOLLOW` on install opens, hardlink nlink skip on expand
//! leaves, realpath-at-install when possible. Residual: no kernel-level
//! handle-based grant binding from parent expand to child restrict; path-based
//! Landlock cannot fully close this race without redesign (e.g. pass open FDs
//! across fork). Partial-ok documented residual, not a silent claim of closure.

const std = @import("std");
const builtin = @import("builtin");
const profile = @import("profile.zig");

/// Flag for landlock_create_ruleset to query highest supported ABI version.
pub const CREATE_RULESET_VERSION: u32 = 1 << 0;

/// landlock_add_rule type: filesystem path hierarchy.
pub const RULE_PATH_BENEATH: u32 = 1;
pub const RULE_NET_PORT: u32 = 2;

// LANDLOCK_ACCESS_FS_* (uapi/linux/landlock.h)
pub const ACCESS_FS_EXECUTE: u64 = 1 << 0;
pub const ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
pub const ACCESS_FS_READ_FILE: u64 = 1 << 2;
pub const ACCESS_FS_READ_DIR: u64 = 1 << 3;
pub const ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
pub const ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
pub const ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
pub const ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
pub const ACCESS_FS_MAKE_REG: u64 = 1 << 8;
pub const ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
pub const ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
pub const ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
pub const ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
/// ABI ≥ 2
pub const ACCESS_FS_REFER: u64 = 1 << 13;
/// ABI ≥ 3
pub const ACCESS_FS_TRUNCATE: u64 = 1 << 14;
/// ABI ≥ 5
pub const ACCESS_FS_IOCTL_DEV: u64 = 1 << 15;

/// Directory-only FS rights. `landlock_add_rule(PATH_BENEATH)` returns `EINVAL`
/// if any of these bits are set on a non-directory `parent_fd`.
pub const FS_RIGHTS_DIRECTORY_ONLY: u64 = ACCESS_FS_READ_DIR |
    ACCESS_FS_REMOVE_DIR |
    ACCESS_FS_REMOVE_FILE |
    ACCESS_FS_MAKE_CHAR |
    ACCESS_FS_MAKE_DIR |
    ACCESS_FS_MAKE_REG |
    ACCESS_FS_MAKE_SOCK |
    ACCESS_FS_MAKE_FIFO |
    ACCESS_FS_MAKE_BLOCK |
    ACCESS_FS_MAKE_SYM |
    ACCESS_FS_REFER;

/// Drop directory-only bits so a file PATH_BENEATH grant is accepted.
pub fn fileCompatibleRights(rights: u64) u64 {
    return rights & ~FS_RIGHTS_DIRECTORY_ONLY;
}

// LANDLOCK_ACCESS_NET_* (uapi/linux/landlock.h), ABI >= 4.
pub const ACCESS_NET_BIND_TCP: u64 = 1 << 0;
pub const ACCESS_NET_CONNECT_TCP: u64 = 1 << 1;

/// Minimum ABI we require for complete write-integrity mediation.
///
/// ABI 1/2 do not mediate truncation, including `truncate(2)` and
/// `open(O_RDONLY|O_TRUNC)`, so they cannot uphold control-root or outside-file
/// integrity. ABI 3 (Linux 6.2+) adds `LANDLOCK_ACCESS_FS_TRUNCATE`.
pub const MIN_ABI: u32 = 3;
pub const MIN_TCP_ROUTE_FORCE_ABI: u32 = 4;

/// FS rights present in ABI 1.
pub const FS_RIGHTS_ABI1: u64 = ACCESS_FS_EXECUTE | ACCESS_FS_WRITE_FILE | ACCESS_FS_READ_FILE |
    ACCESS_FS_READ_DIR | ACCESS_FS_REMOVE_DIR | ACCESS_FS_REMOVE_FILE | ACCESS_FS_MAKE_CHAR |
    ACCESS_FS_MAKE_DIR | ACCESS_FS_MAKE_REG | ACCESS_FS_MAKE_SOCK | ACCESS_FS_MAKE_FIFO |
    ACCESS_FS_MAKE_BLOCK | ACCESS_FS_MAKE_SYM;

pub const ApplyError = error{
    /// Landlock syscalls missing or ABI too old.
    Unavailable,
    /// Syscall failed after ABI probe succeeded.
    ApplyFailed,
    /// Workspace / required path could not be opened for PATH_BENEATH.
    PathOpenFailed,
    /// Not running on Linux.
    Unsupported,
};

pub const AbiInfo = struct {
    /// Highest supported ABI version (1+).
    version: u32,
};

/// Pure: handled_access_fs mask for a given ABI. Never includes network rights.
pub fn handledFsRights(abi: u32) u64 {
    var rights: u64 = FS_RIGHTS_ABI1;
    if (abi >= 2) rights |= ACCESS_FS_REFER;
    if (abi >= 3) rights |= ACCESS_FS_TRUNCATE;
    if (abi >= 5) rights |= ACCESS_FS_IOCTL_DEV;
    // ABI 4+ adds network — intentionally omitted (no network Landlock claim).
    return rights;
}

/// Pure: handled network rights for route forcing.
///
/// Only `ACCESS_NET_CONNECT_TCP` is handled: route forcing is an *outbound*
/// mediation control (force TCP connects onto the proxy port). Including
/// `ACCESS_NET_BIND_TCP` in `handled_access_net` without a matching allow rule
/// would deny every TCP bind (dev servers, ephemeral listeners) even though
/// product docs only claim outbound TCP restriction. UDP is not included.
/// `ACCESS_NET_BIND_TCP` remains declared for ABI completeness / future bind
/// policy, but is intentionally not handled here.
pub fn handledNetRights(abi: u32) u64 {
    if (abi < MIN_TCP_ROUTE_FORCE_ABI) return 0;
    return ACCESS_NET_CONNECT_TCP;
}

pub fn supportsTcpRouteForcing() bool {
    const info = probeAbi() orelse return false;
    return handledNetRights(info.version) != 0;
}

pub const RouteForcing = struct {
    /// Proxy listener TCP port. Landlock can constrain the port but not the
    /// remote address; macOS Seatbelt handles address+port.
    proxy_port: u16,
};

/// Pure: allowed_access for a single PATH_BENEATH grant under the given ABI.
pub fn allowedAccessForMode(mode: profile.AccessMode, abi: u32) u64 {
    const handled = handledFsRights(abi);
    const ro: u64 = ACCESS_FS_READ_FILE | ACCESS_FS_READ_DIR | ACCESS_FS_EXECUTE;
    const rw_base: u64 = ro | ACCESS_FS_WRITE_FILE | ACCESS_FS_REMOVE_DIR | ACCESS_FS_REMOVE_FILE |
        ACCESS_FS_MAKE_CHAR | ACCESS_FS_MAKE_DIR | ACCESS_FS_MAKE_REG | ACCESS_FS_MAKE_SOCK |
        ACCESS_FS_MAKE_FIFO | ACCESS_FS_MAKE_BLOCK | ACCESS_FS_MAKE_SYM;
    var want: u64 = switch (mode) {
        .ro => ro,
        .rw => rw_base,
        .exec => ACCESS_FS_EXECUTE | ACCESS_FS_READ_FILE | ACCESS_FS_READ_DIR,
    };
    if (abi >= 2 and mode == .rw) want |= ACCESS_FS_REFER;
    if (abi >= 3 and mode == .rw) want |= ACCESS_FS_TRUNCATE;
    if (abi >= 5 and mode == .rw) want |= ACCESS_FS_IOCTL_DEV;
    return want & handled;
}

/// Probe Landlock ABI version. Null when unavailable / non-Linux.
pub fn probeAbi() ?AbiInfo {
    if (builtin.os.tag != .linux) return null;
    return probeAbiLinux();
}

pub fn isAbiAvailable() bool {
    const info = probeAbi() orelse return false;
    return abiSupportsWriteIntegrity(info.version);
}

/// Pure floor predicate shared by attach, doctor, and regression tests.
pub fn abiSupportsWriteIntegrity(abi: u32) bool {
    return abi >= MIN_ABI;
}

/// Parent-side surfaces for one RW grant that needs control expand.
/// Built before fork; the child only installs PATH_BENEATH from these paths.
pub const ControlExpandSurfaces = struct {
    allocator: std.mem.Allocator,
    /// RO PATH_BENEATH with required=true (grant root + nested expand roots).
    expand_roots: []const []const u8,
    /// RO PATH_BENEATH with required=false (control roots under the grant tree).
    control_ro_paths: []const []const u8,
    /// RW PATH_BENEATH leaf targets (non-control, non-symlink children).
    rw_paths: []const []const u8,

    pub fn deinit(self: *ControlExpandSurfaces) void {
        freeOwnedPaths(self.allocator, self.expand_roots);
        freeOwnedPaths(self.allocator, self.control_ro_paths);
        freeOwnedPaths(self.allocator, self.rw_paths);
        self.* = undefined;
    }

    pub fn anyRw(self: *const ControlExpandSurfaces) bool {
        return self.rw_paths.len > 0;
    }
};

/// Owned multi-grant expand plan consumed by child `applySelf`.
/// Parent builds this before fork; after fork the child must not re-enumerate.
/// Self-contained under `allocator`: grant paths are duped so the plan does not
/// borrow `CompiledProfile` storage (safe if materials deinit order changes).
pub const ChildLandlockPlan = struct {
    allocator: std.mem.Allocator,
    expands: []ExpandByGrant,

    pub const ExpandByGrant = struct {
        /// Owned by `ChildLandlockPlan.allocator` (duped at plan build).
        grant_path: []const u8,
        surfaces: ControlExpandSurfaces,
    };

    pub fn deinit(self: *ChildLandlockPlan) void {
        for (self.expands) |*entry| {
            entry.surfaces.deinit();
            self.allocator.free(entry.grant_path);
        }
        self.allocator.free(self.expands);
        self.* = undefined;
    }

    pub fn surfacesFor(self: *const ChildLandlockPlan, grant_path: []const u8) ?*const ControlExpandSurfaces {
        for (self.expands) |*entry| {
            if (std.mem.eql(u8, entry.grant_path, grant_path)) return &entry.surfaces;
        }
        return null;
    }
};

fn freeOwnedPaths(allocator: std.mem.Allocator, paths: []const []const u8) void {
    for (paths) |p| allocator.free(p);
    allocator.free(paths);
}

fn appendOwnedPath(list: *std.ArrayList([]const u8), allocator: std.mem.Allocator, path: []const u8) !void {
    const owned = try allocator.dupe(u8, path);
    errdefer allocator.free(owned);
    try list.append(allocator, owned);
}

/// Parent-side (or single-threaded): enumerate control-expand RO/RW PATH_BENEATH
/// surfaces for one RW grant. May allocate and call opendir/readdir — **never**
/// invoke after a multi-threaded fork.
pub fn buildControlExpandSurfaces(
    allocator: std.mem.Allocator,
    grant_path: []const u8,
    control_roots: []const []const u8,
) !ControlExpandSurfaces {
    var expand_roots: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (expand_roots.items) |p| allocator.free(p);
        expand_roots.deinit(allocator);
    }
    var control_ro: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (control_ro.items) |p| allocator.free(p);
        control_ro.deinit(allocator);
    }
    var rw_paths: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (rw_paths.items) |p| allocator.free(p);
        rw_paths.deinit(allocator);
    }

    try collectExpandSurfaces(allocator, grant_path, control_roots, &expand_roots, &control_ro, &rw_paths);

    // Sequential toOwnedSlice with errdefer on already-owned slices (mirror profile.compileProfile).
    const expand_roots_owned = try expand_roots.toOwnedSlice(allocator);
    errdefer freeOwnedPaths(allocator, expand_roots_owned);
    const control_ro_owned = try control_ro.toOwnedSlice(allocator);
    errdefer freeOwnedPaths(allocator, control_ro_owned);
    const rw_paths_owned = try rw_paths.toOwnedSlice(allocator);

    return .{
        .allocator = allocator,
        .expand_roots = expand_roots_owned,
        .control_ro_paths = control_ro_owned,
        .rw_paths = rw_paths_owned,
    };
}

/// Recursive enumeration matching historical child-side expand semantics.
fn collectExpandSurfaces(
    allocator: std.mem.Allocator,
    grant_path: []const u8,
    control_roots: []const []const u8,
    expand_roots: *std.ArrayList([]const u8),
    control_ro: *std.ArrayList([]const u8),
    rw_paths: *std.ArrayList([]const u8),
) !void {
    try appendOwnedPath(expand_roots, allocator, grant_path);

    for (control_roots) |root| {
        if (!pathIsWithin(root, grant_path)) continue;
        try appendOwnedPath(control_ro, allocator, root);
    }

    // Grant path itself is a control root: RO only, no RW children.
    if (isControlPath(grant_path, control_roots)) return;

    // Parent-side enumeration only (malloc / libc dirents OK here).
    if (builtin.os.tag == .windows) return error.PathOpenFailed;

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    if (grant_path.len == 0 or grant_path.len >= path_buf.len) return error.PathOpenFailed;
    @memcpy(path_buf[0..grant_path.len], grant_path);
    path_buf[grant_path.len] = 0;
    const dir = std.c.opendir(path_buf[0..grant_path.len :0].ptr) orelse return error.PathOpenFailed;
    defer _ = std.c.closedir(dir);

    while (true) {
        const entry = std.c.readdir(dir) orelse break;
        const name = std.mem.sliceTo(entry.name[0..], 0);
        if (name.len == 0 or std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;
        // Skip symlink children (DT_LNK). DT_UNKNOWN still goes through O_NOFOLLOW open later.
        if (entry.type == std.c.DT.LNK) continue;

        const joined = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ grant_path, name });

        if (isControlPath(joined, control_roots)) {
            allocator.free(joined);
            continue;
        }
        if (grantCoversControlRoot(joined, control_roots)) {
            // Nested expand: recurse then drop the temporary joined path (recursion owns copies).
            defer allocator.free(joined);
            try collectExpandSurfaces(allocator, joined, control_roots, expand_roots, control_ro, rw_paths);
            continue;
        }
        // Skip non-dir hardlinks (nlink > 1): a planted hardlink to an outside
        // same-FS secret must not become a PATH_BENEATH RW surface (M-12).
        if (leafIsHardlinkedNonDir(joined)) {
            allocator.free(joined);
            continue;
        }
        // Leaf RW surface — transfer ownership into rw_paths.
        rw_paths.append(allocator, joined) catch |err| {
            allocator.free(joined);
            return err;
        };
    }
}

/// True when `path` is a non-directory with st_nlink > 1 (hardlink residual filter).
/// Directories are never treated as hardlink leaves (normal dir nlink ≥ 2).
/// On open/stat failure returns false (install may still soft-skip later).
fn leafIsHardlinkedNonDir(path: []const u8) bool {
    if (builtin.os.tag == .windows) return false;
    if (path.len == 0 or !std.fs.path.isAbsolute(path)) return false;

    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const file = std.Io.Dir.openFileAbsolute(io, path, .{
        .path_only = true,
        .follow_symlinks = false,
    }) catch return false;
    defer file.close(io);
    const st = file.stat(io) catch return false;
    if (st.kind == .directory) return false;
    return st.nlink > 1;
}

/// Parent-side: build expand surfaces for every RW grant that needs control expand.
pub fn buildChildLandlockPlan(
    allocator: std.mem.Allocator,
    compiled: *const profile.CompiledProfile,
) !ChildLandlockPlan {
    var expands: std.ArrayList(ChildLandlockPlan.ExpandByGrant) = .empty;
    errdefer {
        // Plan owns grant_path (M-26); free path + surfaces on partial build failure.
        for (expands.items) |*e| {
            allocator.free(e.grant_path);
            e.surfaces.deinit();
        }
        expands.deinit(allocator);
    }

    for (compiled.grants) |grant| {
        if (grant.mode != .rw) continue;
        if (!rwGrantNeedsControlExpand(grant.path, compiled.control_roots)) continue;
        var surfaces = try buildControlExpandSurfaces(allocator, grant.path, compiled.control_roots);
        errdefer surfaces.deinit();
        // Dupe grant path so the plan is self-contained (M-26); surfacesFor and
        // child apply must not depend on CompiledProfile lifetime after plan build.
        const owned_grant_path = try allocator.dupe(u8, grant.path);
        errdefer allocator.free(owned_grant_path);
        try expands.append(allocator, .{
            .grant_path = owned_grant_path,
            .surfaces = surfaces,
        });
    }

    return .{
        .allocator = allocator,
        .expands = try expands.toOwnedSlice(allocator),
    };
}

/// Apply Landlock FS rules for `compiled` to the **current** process using a
/// parent-precomputed `plan` for control-expand grants.
/// Must only be called in a forked child (or a dedicated sandbox helper).
/// Does not exec — caller performs exec after success.
/// Child path never calls opendir/readdir.
pub fn applySelf(
    compiled: *const profile.CompiledProfile,
    plan: *const ChildLandlockPlan,
    route_forcing: ?RouteForcing,
) ApplyError!void {
    if (builtin.os.tag != .linux) return error.Unsupported;
    try applySelfLinux(compiled, plan, route_forcing);
}

/// Fork a child, apply Landlock, exit 0 on success / 1 on failure.
/// Parent builds the expand plan before fork. Parent stays unrestricted.
pub fn verifyApplyInChild(compiled: *const profile.CompiledProfile) ApplyError!void {
    if (builtin.os.tag != .linux) return error.Unsupported;
    try verifyApplyInChildLinux(compiled);
}

const RulesetAttr = extern struct {
    handled_access_fs: u64,
};

const RulesetAttrWithNet = extern struct {
    handled_access_fs: u64,
    handled_access_net: u64,
};

const PathBeneathAttr = extern struct {
    allowed_access: u64,
    parent_fd: i32,
};

const NetPortAttr = extern struct {
    allowed_access: u64,
    port: u64,
};

fn probeAbiLinux() ?AbiInfo {
    const linux = std.os.linux;
    const rc = linux.syscall3(.landlock_create_ruleset, 0, 0, CREATE_RULESET_VERSION);
    if (linux.errno(rc) != .SUCCESS) return null;
    // On success, return value is the ABI version (positive).
    if (rc > 0 and rc < 1024) {
        return .{ .version = @intCast(rc) };
    }
    return null;
}

/// True when `path` is `root` or a descendant of `root`.
/// Delegates to the portable profile helper so `/` and prefix-boundary rules match
/// profile/macos (bare `/` must cover control expand when workspace is `/`).
fn pathIsWithin(path: []const u8, root: []const u8) bool {
    return profile.isPathWithin(path, root);
}

/// True when any control root is under (or equal to) `path`.
fn grantCoversControlRoot(path: []const u8, control_roots: []const []const u8) bool {
    for (control_roots) |root| {
        if (pathIsWithin(root, path)) return true;
    }
    return false;
}

fn isControlPath(path: []const u8, control_roots: []const []const u8) bool {
    for (control_roots) |root| {
        if (pathIsWithin(path, root)) return true;
    }
    return false;
}

/// Pure: whether an RW grant should be expanded into children so control roots
/// are not covered by a single PATH_BENEATH RW rule (Landlock is allow-list only).
pub fn rwGrantNeedsControlExpand(path: []const u8, control_roots: []const []const u8) bool {
    return grantCoversControlRoot(path, control_roots);
}

/// Resolve `path` for Landlock open: try `realpath` first so merged-usr symlink
/// prefixes install on the kernel-visible path, then fall back to lexical `path`.
/// Both forms are still opened with `O_NOFOLLOW` by the caller.
fn resolvePathForGrant(path: []const u8, out: *[std.fs.max_path_bytes]u8) []const u8 {
    if (path.len == 0 or path.len >= std.fs.max_path_bytes) return path;
    var in_buf: [std.fs.max_path_bytes]u8 = undefined;
    @memcpy(in_buf[0..path.len], path);
    in_buf[path.len] = 0;
    const resolved = std.c.realpath(in_buf[0..path.len :0].ptr, out) orelse return path;
    return std.mem.span(resolved);
}

fn openPathBeneathFd(path: []const u8) ?i32 {
    if (builtin.os.tag != .linux) return null;
    const linux = std.os.linux;
    if (path.len == 0 or path.len >= std.fs.max_path_bytes) return null;
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    @memcpy(path_buf[0..path.len], path);
    path_buf[path.len] = 0;
    const path_z: [*:0]const u8 = path_buf[0..path.len :0].ptr;
    // O_NOFOLLOW: never PATH_BENEATH-follow a symlink at the grant node.
    const open_rc = linux.open(path_z, .{ .PATH = true, .CLOEXEC = true, .NOFOLLOW = true }, 0);
    if (linux.errno(open_rc) != .SUCCESS) return null;
    return @intCast(open_rc);
}

fn addPathBeneathRule(
    ruleset_fd: i32,
    path: []const u8,
    allowed: u64,
    required: bool,
) ApplyError!bool {
    return addPathBeneathRuleInner(ruleset_fd, path, allowed, required, false);
}

/// Like `addPathBeneathRule`, but fail closed if the path is not a regular file.
/// Used for `.exec` grants so a directory cannot PATH_BENEATH-open a tree.
fn addPathBeneathRuleFileOnly(
    ruleset_fd: i32,
    path: []const u8,
    allowed: u64,
    required: bool,
) ApplyError!bool {
    return addPathBeneathRuleInner(ruleset_fd, path, allowed, required, true);
}

fn addPathBeneathRuleInner(
    ruleset_fd: i32,
    path: []const u8,
    allowed: u64,
    required: bool,
    file_only: bool,
) ApplyError!bool {
    if (builtin.os.tag != .linux) return error.Unsupported;
    const linux = std.os.linux;
    if (allowed == 0) return false;
    if (path.len == 0 or path.len >= std.fs.max_path_bytes) {
        if (required) return error.PathOpenFailed;
        return false;
    }

    // Prefer realpath so lexical symlink prefixes (e.g. /lib → /usr/lib) become
    // openable under O_NOFOLLOW. Fall back to lexical path when realpath fails
    // (missing optional RO prefix). Retry lexical if the resolved open fails.
    var real_buf: [std.fs.max_path_bytes]u8 = undefined;
    const resolved = resolvePathForGrant(path, &real_buf);

    const path_fd = openPathBeneathFd(resolved) orelse
        (if (!std.mem.eql(u8, resolved, path)) openPathBeneathFd(path) else null) orelse
        {
            if (required) return error.PathOpenFailed;
            return false;
        };
    defer _ = linux.close(path_fd);

    var stx = std.mem.zeroes(linux.Statx);
    const stx_rc = linux.statx(path_fd, "", linux.AT.EMPTY_PATH, .{ .TYPE = true }, &stx);
    if (linux.errno(stx_rc) != .SUCCESS or !stx.mask.TYPE) {
        if (file_only or required) return error.ApplyFailed;
        return false;
    }
    if (file_only and !linux.S.ISREG(stx.mode)) return error.ApplyFailed;

    // File/device FDs reject directory-only (and IOCTL-on-non-device) bits.
    var effective = allowed;
    if (!linux.S.ISDIR(stx.mode)) {
        effective = fileCompatibleRights(allowed);
        if (!linux.S.ISCHR(stx.mode) and !linux.S.ISBLK(stx.mode)) {
            effective &= ~ACCESS_FS_IOCTL_DEV;
        }
    }
    if (effective == 0) {
        if (required) return error.ApplyFailed;
        return false;
    }

    var beneath = PathBeneathAttr{
        .allowed_access = effective,
        .parent_fd = path_fd,
    };
    const add_rc = linux.syscall4(
        .landlock_add_rule,
        @as(usize, @intCast(ruleset_fd)),
        RULE_PATH_BENEATH,
        @intFromPtr(&beneath),
        0,
    );
    if (linux.errno(add_rc) != .SUCCESS) {
        if (required) return error.ApplyFailed;
        return false;
    }
    return true;
}

/// Install PATH_BENEATH rules from parent-precomputed expand surfaces.
/// Child-only: open + landlock_add_rule — **no** opendir/readdir.
///
/// Semantics (unchanged from historical in-child expand):
/// - RO on expand roots (chdir/list/walk; no MAKE/WRITE)
/// - RO on control roots (readable, not writable)
/// - RW on leaf non-control children
///
/// Landlock cannot deny a subpath of a granted PATH_BENEATH, so we never install
/// a single RW (or MAKE) rule on a directory that contains a control root.
/// Returns true only when at least one usable RW child surface was installed.
fn addRwGrantFromSurfaces(
    ruleset_fd: i32,
    surfaces: *const ControlExpandSurfaces,
    abi: u32,
) ApplyError!bool {
    if (builtin.os.tag != .linux) return error.Unsupported;
    const ro = allowedAccessForMode(.ro, abi);
    const rw = allowedAccessForMode(.rw, abi);
    // Walk-only on expand roots: READ_DIR+EXECUTE, no READ_FILE. Otherwise a
    // skipped hardlink leaf is still readable via the parent PATH_BENEATH.
    const walk = ro & ~ACCESS_FS_READ_FILE;
    var any_rw = false;

    for (surfaces.expand_roots) |root| {
        _ = try addPathBeneathRule(ruleset_fd, root, walk, true);
    }
    for (surfaces.control_ro_paths) |root| {
        _ = try addPathBeneathRule(ruleset_fd, root, ro, false);
    }
    for (surfaces.rw_paths) |path| {
        if (try addPathBeneathRule(ruleset_fd, path, rw, false)) {
            any_rw = true;
        }
    }
    return any_rw;
}

fn addNetPortRule(ruleset_fd: i32, allowed: u64, port: u16) ApplyError!void {
    if (builtin.os.tag != .linux) return error.Unsupported;
    const linux = std.os.linux;
    if (allowed == 0 or port == 0) return error.ApplyFailed;
    var net = NetPortAttr{
        .allowed_access = allowed,
        .port = port,
    };
    const add_rc = linux.syscall4(
        .landlock_add_rule,
        @as(usize, @intCast(ruleset_fd)),
        RULE_NET_PORT,
        @intFromPtr(&net),
        0,
    );
    if (linux.errno(add_rc) != .SUCCESS) return error.ApplyFailed;
}

fn applySelfLinux(
    compiled: *const profile.CompiledProfile,
    plan: *const ChildLandlockPlan,
    route_forcing: ?RouteForcing,
) ApplyError!void {
    const linux = std.os.linux;
    const abi_info = probeAbiLinux() orelse return error.Unavailable;
    const abi = abi_info.version;
    if (abi < MIN_ABI) return error.Unavailable;

    const handled = handledFsRights(abi);
    const handled_net = if (route_forcing != null) handledNetRights(abi) else 0;
    if (route_forcing != null and handled_net == 0) return error.Unavailable;

    const ruleset_rc = if (handled_net == 0) blk: {
        var attr = RulesetAttr{ .handled_access_fs = handled };
        break :blk linux.syscall3(
            .landlock_create_ruleset,
            @intFromPtr(&attr),
            @sizeOf(RulesetAttr),
            0,
        );
    } else blk: {
        var attr = RulesetAttrWithNet{
            .handled_access_fs = handled,
            .handled_access_net = handled_net,
        };
        break :blk linux.syscall3(
            .landlock_create_ruleset,
            @intFromPtr(&attr),
            @sizeOf(RulesetAttrWithNet),
            0,
        );
    };
    switch (linux.errno(ruleset_rc)) {
        .SUCCESS => {},
        .NOSYS, .OPNOTSUPP, .INVAL => return error.Unavailable,
        else => return error.ApplyFailed,
    }
    const ruleset_fd: i32 = @intCast(ruleset_rc);
    defer _ = linux.close(ruleset_fd);

    var workspace_granted = false;
    for (compiled.grants) |grant| {
        const allowed = allowedAccessForMode(grant.mode, abi);
        if (allowed == 0) continue;

        if (grant.mode == .rw and rwGrantNeedsControlExpand(grant.path, compiled.control_roots)) {
            // Parent must have precomputed surfaces; child never re-enumerates.
            const surfaces = plan.surfacesFor(grant.path) orelse return error.ApplyFailed;
            if (try addRwGrantFromSurfaces(ruleset_fd, surfaces, abi)) {
                if (std.mem.eql(u8, grant.path, compiled.workspace_root) or
                    pathIsWithin(grant.path, compiled.workspace_root) or
                    pathIsWithin(compiled.workspace_root, grant.path))
                {
                    workspace_granted = true;
                }
            }
            continue;
        }

        const required = grant.mode == .rw;
        // `.exec` is file-only: refuse directory PATH_BENEATH (tree exec/read widen).
        // File PATH_BENEATH is sufficient for execve — Landlock does not mediate
        // directory path-walk (see docs/platform-linux.md); do not grant ancestors.
        const installed = if (grant.mode == .exec)
            try addPathBeneathRuleFileOnly(ruleset_fd, grant.path, allowed, true)
        else
            try addPathBeneathRule(ruleset_fd, grant.path, allowed, required);
        if (installed and grant.mode == .rw and std.mem.eql(u8, grant.path, compiled.workspace_root)) {
            workspace_granted = true;
        }
        // Explicit tmp RW or other RW under workspace also counts as a usable box.
        if (installed and grant.mode == .rw and pathIsWithin(grant.path, compiled.workspace_root)) {
            workspace_granted = true;
        }
    }

    if (route_forcing) |route| {
        try addNetPortRule(ruleset_fd, ACCESS_NET_CONNECT_TCP, route.proxy_port);
    }

    if (!workspace_granted) {
        // No RW workspace rule installed — fail closed (empty box or missing root).
        return error.PathOpenFailed;
    }

    // NO_NEW_PRIVS is required before landlock_restrict_self.
    const pr_rc = linux.prctl(@intFromEnum(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0);
    if (linux.errno(pr_rc) != .SUCCESS) return error.ApplyFailed;

    const restrict_rc = linux.syscall2(
        .landlock_restrict_self,
        @as(usize, @intCast(ruleset_fd)),
        0,
    );
    if (linux.errno(restrict_rc) != .SUCCESS) return error.ApplyFailed;
}

fn verifyApplyInChildLinux(compiled: *const profile.CompiledProfile) ApplyError!void {
    const linux = std.os.linux;

    // Parent-side expand plan before fork. Child only installs from plan.
    var plan = buildChildLandlockPlan(std.heap.page_allocator, compiled) catch return error.ApplyFailed;
    defer plan.deinit();

    const pid_rc = linux.fork();
    if (linux.errno(pid_rc) != .SUCCESS) return error.ApplyFailed;

    if (pid_rc == 0) {
        // Child: apply then exit. Never return to parent address space logic.
        applySelfLinux(compiled, &plan, null) catch {
            linux.exit(1);
        };
        linux.exit(0);
    }

    // Parent: wait for child status.
    const child_pid: i32 = @intCast(pid_rc);
    var status: u32 = 0;
    while (true) {
        const w = linux.waitpid(child_pid, &status, 0);
        if (linux.errno(w) == .INTR) continue;
        if (linux.errno(w) != .SUCCESS) return error.ApplyFailed;
        break;
    }

    // Decode wait status: signalled if low 7 bits set; else exit code in bits 8..15.
    if ((status & 0x7f) != 0) return error.ApplyFailed;
    const code = (status >> 8) & 0xff;
    if (code != 0) return error.ApplyFailed;
}

test "pure ABI rights masks are filesystem-only and grow with ABI" {
    const a1 = handledFsRights(1);
    const a2 = handledFsRights(2);
    const a3 = handledFsRights(3);
    const a5 = handledFsRights(5);

    try std.testing.expectEqual(FS_RIGHTS_ABI1, a1);
    try std.testing.expect((a2 & ACCESS_FS_REFER) != 0);
    try std.testing.expect((a1 & ACCESS_FS_REFER) == 0);
    try std.testing.expect((a3 & ACCESS_FS_TRUNCATE) != 0);
    try std.testing.expect((a2 & ACCESS_FS_TRUNCATE) == 0);
    try std.testing.expect((a5 & ACCESS_FS_IOCTL_DEV) != 0);
}

test "write-integrity floor rejects Landlock ABI 1 and 2" {
    try std.testing.expect(!abiSupportsWriteIntegrity(1));
    try std.testing.expect(!abiSupportsWriteIntegrity(2));
    try std.testing.expect(abiSupportsWriteIntegrity(3));
    try std.testing.expect(abiSupportsWriteIntegrity(5));
}

test "pure TCP route forcing rights start at Landlock ABI 4" {
    try std.testing.expectEqual(@as(u64, 0), handledNetRights(1));
    try std.testing.expectEqual(@as(u64, 0), handledNetRights(3));
    const abi4 = handledNetRights(4);
    // Outbound-only: CONNECT is handled; BIND must not be (would deny all listeners).
    try std.testing.expect((abi4 & ACCESS_NET_CONNECT_TCP) != 0);
    try std.testing.expect((abi4 & ACCESS_NET_BIND_TCP) == 0);
    try std.testing.expectEqual(abi4, handledNetRights(5));
    try std.testing.expectEqual(ACCESS_NET_CONNECT_TCP, abi4);
}

test "pure allowedAccessForMode RO is subset of RW and of handled mask" {
    inline for (.{ @as(u32, 1), 2, 3, 5 }) |abi| {
        const handled = handledFsRights(abi);
        const ro = allowedAccessForMode(.ro, abi);
        const rw = allowedAccessForMode(.rw, abi);
        const ex = allowedAccessForMode(.exec, abi);
        try std.testing.expect((ro & handled) == ro);
        try std.testing.expect((rw & handled) == rw);
        try std.testing.expect((ex & handled) == ex);
        try std.testing.expect((ro & ACCESS_FS_WRITE_FILE) == 0);
        try std.testing.expect((ro & ACCESS_FS_TRUNCATE) == 0);
        try std.testing.expect((rw & ACCESS_FS_WRITE_FILE) != 0);
        try std.testing.expect((ro & ACCESS_FS_READ_FILE) != 0);
        try std.testing.expect((ex & ACCESS_FS_EXECUTE) != 0);
    }
}

test "fileCompatibleRights drops directory-only bits and keeps file RW/exec" {
    const rw = allowedAccessForMode(.rw, 5);
    const file_rw = fileCompatibleRights(rw);
    try std.testing.expect((file_rw & ACCESS_FS_WRITE_FILE) != 0);
    try std.testing.expect((file_rw & ACCESS_FS_READ_FILE) != 0);
    try std.testing.expect((file_rw & ACCESS_FS_TRUNCATE) != 0);
    try std.testing.expect((file_rw & FS_RIGHTS_DIRECTORY_ONLY) == 0);

    const ex = allowedAccessForMode(.exec, 5);
    const file_ex = fileCompatibleRights(ex);
    try std.testing.expect((file_ex & ACCESS_FS_EXECUTE) != 0);
    try std.testing.expect((file_ex & ACCESS_FS_READ_FILE) != 0);
    try std.testing.expect((file_ex & ACCESS_FS_READ_DIR) == 0);
}

test "probeAbi is null on non-Linux; applySelf unsupported off Linux" {
    if (builtin.os.tag != .linux) {
        try std.testing.expect(probeAbi() == null);
        try std.testing.expect(!isAbiAvailable());
        var empty_plan: ChildLandlockPlan = .{
            .allocator = std.testing.allocator,
            .expands = try std.testing.allocator.alloc(ChildLandlockPlan.ExpandByGrant, 0),
        };
        defer empty_plan.deinit();
        try std.testing.expectError(error.Unsupported, applySelf(&.{
            .allocator = std.testing.allocator,
            .workspace_root = "/",
            .grants = &.{},
            .control_roots = &.{},
            .canonical_bytes = "",
            .hash_hex = .{'0'} ** 64,
        }, &empty_plan, null));
    }
}

// Parent-side expand helper builds child path lists from a temp dir layout.
test "buildControlExpandSurfaces treats authority file under host RW as RO leaf" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Simulate host RW tree ($HOME/.codex) with authority file control root.
    var host_tmp = std.testing.tmpDir(.{});
    defer host_tmp.cleanup();
    try host_tmp.dir.writeFile(io, .{ .sub_path = "config.toml", .data = "[mcp_servers]\n" });
    try host_tmp.dir.writeFile(io, .{ .sub_path = "history.jsonl", .data = "{}\n" });
    try host_tmp.dir.createDirPath(io, "sessions");
    const host_rw = try host_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(host_rw);
    const authority = try std.fs.path.join(allocator, &.{ host_rw, "config.toml" });
    defer allocator.free(authority);

    var surfaces = try buildControlExpandSurfaces(allocator, host_rw, &[_][]const u8{authority});
    defer surfaces.deinit();

    var control_ro_found = false;
    for (surfaces.control_ro_paths) |p| {
        if (std.mem.eql(u8, p, authority)) control_ro_found = true;
    }
    try std.testing.expect(control_ro_found);

    const history = try std.fmt.allocPrint(allocator, "{s}/history.jsonl", .{host_rw});
    defer allocator.free(history);
    const sessions = try std.fmt.allocPrint(allocator, "{s}/sessions", .{host_rw});
    defer allocator.free(sessions);

    var saw_history = false;
    var saw_sessions = false;
    for (surfaces.rw_paths) |p| {
        if (std.mem.eql(u8, p, history)) saw_history = true;
        if (std.mem.eql(u8, p, sessions)) saw_sessions = true;
        try std.testing.expect(!std.mem.eql(u8, p, authority));
    }
    try std.testing.expect(saw_history);
    try std.testing.expect(saw_sessions);
    try std.testing.expect(rwGrantNeedsControlExpand(host_rw, &[_][]const u8{authority}));
}

test "buildControlExpandSurfaces enumerates RW children and skips control + symlinks" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    try ws_tmp.dir.createDirPath(io, ".ryk");
    try ws_tmp.dir.createDirPath(io, "src");
    try ws_tmp.dir.writeFile(io, .{ .sub_path = "neighbor.txt", .data = "ok" });
    try ws_tmp.dir.writeFile(io, .{ .sub_path = "src/main.zig", .data = "fn" });
    const ws_root = try ws_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(ws_root);

    const control = try std.fs.path.join(allocator, &.{ ws_root, ".ryk" });
    defer allocator.free(control);

    // Plant a symlink child that must not become an RW surface.
    const link_path = try std.fs.path.join(allocator, &.{ ws_root, "escape_link" });
    defer allocator.free(link_path);
    std.Io.Dir.cwd().symLink(io, control, link_path, .{}) catch |err| switch (err) {
        error.PermissionDenied => {}, // still assert other surfaces
        else => return err,
    };

    var surfaces = try buildControlExpandSurfaces(allocator, ws_root, &[_][]const u8{control});
    defer surfaces.deinit();

    try std.testing.expect(surfaces.anyRw());
    try std.testing.expect(surfaces.expand_roots.len >= 1);
    try std.testing.expectEqualStrings(ws_root, surfaces.expand_roots[0]);

    // Control root is RO, not RW.
    var control_ro_found = false;
    for (surfaces.control_ro_paths) |p| {
        if (std.mem.eql(u8, p, control)) control_ro_found = true;
    }
    try std.testing.expect(control_ro_found);

    const neighbor = try std.fmt.allocPrint(allocator, "{s}/neighbor.txt", .{ws_root});
    defer allocator.free(neighbor);
    const src_dir = try std.fmt.allocPrint(allocator, "{s}/src", .{ws_root});
    defer allocator.free(src_dir);
    const link_joined = try std.fmt.allocPrint(allocator, "{s}/escape_link", .{ws_root});
    defer allocator.free(link_joined);
    const control_joined = try std.fmt.allocPrint(allocator, "{s}/.ryk", .{ws_root});
    defer allocator.free(control_joined);

    var saw_neighbor = false;
    var saw_src = false;
    for (surfaces.rw_paths) |p| {
        if (std.mem.eql(u8, p, neighbor)) saw_neighbor = true;
        if (std.mem.eql(u8, p, src_dir)) saw_src = true;
        try std.testing.expect(!std.mem.eql(u8, p, control_joined));
        try std.testing.expect(!std.mem.eql(u8, p, link_joined));
    }
    try std.testing.expect(saw_neighbor);
    try std.testing.expect(saw_src);
}

test "buildControlExpandSurfaces recurses when child covers nested control root" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    // Nested control: ws/pkg/.ryk — pkg must be expand-root RO, not leaf RW.
    try ws_tmp.dir.createDirPath(io, "pkg/.ryk");
    try ws_tmp.dir.writeFile(io, .{ .sub_path = "pkg/code.txt", .data = "c" });
    try ws_tmp.dir.writeFile(io, .{ .sub_path = "top.txt", .data = "t" });
    const ws_root = try ws_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(ws_root);

    const nested_control = try std.fs.path.join(allocator, &.{ ws_root, "pkg", ".ryk" });
    defer allocator.free(nested_control);

    var surfaces = try buildControlExpandSurfaces(allocator, ws_root, &[_][]const u8{nested_control});
    defer surfaces.deinit();

    const pkg = try std.fmt.allocPrint(allocator, "{s}/pkg", .{ws_root});
    defer allocator.free(pkg);
    const top = try std.fmt.allocPrint(allocator, "{s}/top.txt", .{ws_root});
    defer allocator.free(top);
    const code = try std.fmt.allocPrint(allocator, "{s}/pkg/code.txt", .{ws_root});
    defer allocator.free(code);

    // pkg is an expand root (covers control), not a leaf RW path.
    var pkg_is_expand = false;
    for (surfaces.expand_roots) |p| {
        if (std.mem.eql(u8, p, pkg)) pkg_is_expand = true;
    }
    try std.testing.expect(pkg_is_expand);

    var saw_top = false;
    var saw_code = false;
    for (surfaces.rw_paths) |p| {
        if (std.mem.eql(u8, p, top)) saw_top = true;
        if (std.mem.eql(u8, p, code)) saw_code = true;
        try std.testing.expect(!std.mem.eql(u8, p, pkg));
        try std.testing.expect(!std.mem.eql(u8, p, nested_control));
    }
    try std.testing.expect(saw_top);
    try std.testing.expect(saw_code);
}

test "verifyApplyInChild and applySelf skip or run on Linux only" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    if (!isAbiAvailable()) return error.SkipZigTest;

    // Real workspace under tmp so O_PATH succeeds. Need a non-control child so
    // control-root expand can install an RW PATH_BENEATH.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "neighbor.txt", .data = "ok" });
    try tmp.dir.createDirPath(std.testing.io, ".ryk");
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    // Production system RO defaults without temp trees. include_tmp stays
    // false so test tmpDirs under /tmp are not swallowed by the production temp grant.
    var compiled = try profile.compileProfile(std.testing.allocator, .{
        .workspace_root = root,
        .system_ro_prefixes = profile.defaultSystemRoPrefixes(),
        .include_tmp = false,
    });
    defer compiled.deinit();

    try verifyApplyInChild(&compiled);
}

// Empty workspace with only the default control root has no RW leaf until
// attach pre-creates `{workspace}/.ryk-tmp`. Production apply/apply_posix do that
// before buildChildLandlockPlan; this test asserts the expand contract.
test "empty workspace only control root gains RW after session tmp precreate" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!isAbiAvailable()) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, ".ryk");
    // No neighbor files — only control root.
    const root = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(root);

    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = root,
        .system_ro_prefixes = profile.defaultSystemRoPrefixes(),
        .include_tmp = false,
    });
    defer compiled.deinit();

    {
        var empty_plan = try buildChildLandlockPlan(allocator, &compiled);
        defer empty_plan.deinit();
        const surfaces = empty_plan.surfacesFor(root) orelse return error.TestUnexpectedResult;
        try std.testing.expect(!surfaces.anyRw());
    }

    // Production attach precreate (session_tmp.ensureWorkspaceSessionTmp / apply_posix).
    try tmp.dir.createDirPath(io, ".ryk-tmp");

    var plan = try buildChildLandlockPlan(allocator, &compiled);
    defer plan.deinit();
    const surfaces = plan.surfacesFor(root) orelse return error.TestUnexpectedResult;
    try std.testing.expect(surfaces.anyRw());
    var saw_session_tmp = false;
    for (surfaces.rw_paths) |p| {
        if (std.mem.endsWith(u8, p, "/.ryk-tmp") or std.mem.eql(u8, p, ".ryk-tmp")) {
            saw_session_tmp = true;
        }
    }
    try std.testing.expect(saw_session_tmp);

    try verifyApplyInChild(&compiled);
}

test "rwGrantNeedsControlExpand when workspace contains control roots" {
    try std.testing.expect(rwGrantNeedsControlExpand("/ws", &[_][]const u8{"/ws/.ryk"}));
    try std.testing.expect(rwGrantNeedsControlExpand("/ws", &[_][]const u8{"/ws"}));
    try std.testing.expect(!rwGrantNeedsControlExpand("/ws/src", &[_][]const u8{"/ws/.ryk"}));
    try std.testing.expect(!rwGrantNeedsControlExpand("/tmp", &[_][]const u8{"/ws/.ryk"}));
}

// Hardlink residual filter (M-12): same-FS hardlink to an outside secret must
// not become an RW PATH_BENEATH leaf. Uses one tmpDir so link(2) stays on-FS.
test "buildControlExpandSurfaces skips hardlinked non-dir leaves" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var parent = std.testing.tmpDir(.{});
    defer parent.cleanup();
    try parent.dir.createDirPath(io, "ws/.ryk");
    try parent.dir.writeFile(io, .{ .sub_path = "ws/neighbor.txt", .data = "ok" });
    try parent.dir.createDirPath(io, "out");
    try parent.dir.writeFile(io, .{ .sub_path = "out/secret.txt", .data = "OUTSIDE_SECRET" });

    // Plant ws/escape_hl → same inode as out/secret.txt.
    parent.dir.hardLink("out/secret.txt", parent.dir, "ws/escape_hl", io, .{}) catch |err| switch (err) {
        error.AccessDenied, error.PermissionDenied, error.ReadOnlyFileSystem, error.OperationUnsupported, error.CrossDevice => return error.SkipZigTest,
        else => return err,
    };

    const ws_root = try parent.dir.realPathFileAlloc(io, "ws", allocator);
    defer allocator.free(ws_root);
    const control = try std.fs.path.join(allocator, &.{ ws_root, ".ryk" });
    defer allocator.free(control);
    const hardlink_path = try std.fmt.allocPrint(allocator, "{s}/escape_hl", .{ws_root});
    defer allocator.free(hardlink_path);
    const neighbor = try std.fmt.allocPrint(allocator, "{s}/neighbor.txt", .{ws_root});
    defer allocator.free(neighbor);

    var surfaces = try buildControlExpandSurfaces(allocator, ws_root, &[_][]const u8{control});
    defer surfaces.deinit();

    var saw_neighbor = false;
    for (surfaces.rw_paths) |p| {
        try std.testing.expect(!std.mem.eql(u8, p, hardlink_path));
        if (std.mem.eql(u8, p, neighbor)) saw_neighbor = true;
    }
    try std.testing.expect(saw_neighbor);
    try std.testing.expect(leafIsHardlinkedNonDir(hardlink_path));
}

test "ChildLandlockPlan owns grant_path independent of profile lifetime" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, ".ryk");
    try tmp.dir.writeFile(io, .{ .sub_path = "neighbor.txt", .data = "ok" });
    const root = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(root);

    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = root,
        .system_ro_prefixes = &[_][]const u8{"/usr"},
        .include_tmp = false,
    });
    var plan = try buildChildLandlockPlan(allocator, &compiled);
    // Free profile before plan — plan grant_path must not dangle (M-26).
    compiled.deinit();
    defer plan.deinit();

    try std.testing.expect(plan.expands.len >= 1);
    try std.testing.expectEqualStrings(root, plan.expands[0].grant_path);
    try std.testing.expect(plan.surfacesFor(root) != null);
}

test "pathIsWithin and control expand treat filesystem root correctly" {
    // Without the `/` special-case, pathIsWithin("/etc", "/") is false and
    // rwGrantNeedsControlExpand("/", &.{"/.ryk"}) skips expand → full RW on `/`.
    try std.testing.expect(pathIsWithin("/", "/"));
    try std.testing.expect(pathIsWithin("/etc", "/"));
    try std.testing.expect(pathIsWithin("/tmp/ws/.ryk", "/"));
    try std.testing.expect(pathIsWithin("/.ryk", "/"));
    try std.testing.expect(rwGrantNeedsControlExpand("/", &[_][]const u8{"/.ryk"}));
    try std.testing.expect(rwGrantNeedsControlExpand("/", &[_][]const u8{"/tmp/.ryk"}));
    try std.testing.expect(!pathIsWithin("relative", "/"));
}

// Real-FS deny / expand integration tests live in landlock_deny_tests.zig.
test {
    _ = @import("landlock_deny_tests.zig");
}

//! OS-filesystem sandbox profile model (P1-U).
//!
//! Compiles a deterministic grant list: workspace RW (minus trusted control roots
//! `{workspace}/.ryk` and `{workspace}/.git`; control remains readable / write-deny),
//! system RO prefixes, optional classic tmp when `include_tmp` — never a broad $HOME
//! grant and never automatic bare `/tmp` on production defaults (session temp is
//! workspace-scoped). No Landlock/Seatbelt apply lives here; this is the portable
//! grant model only.
//!
//! Grant queries (`isAgentWritable`, `hasGrant`, path math) are pure over the
//! compiled in-memory model. The sole intentional FS I/O is
//! `validateControlRootsOnDisk` (symlink / non-dir-or-file control-root check),
//! which is opt-in at apply time — do not treat the module as pure overall.

const std = @import("std");
const builtin = @import("builtin");

/// Path access class for a grant entry.
pub const AccessMode = enum {
    /// Read-only (and typically execute at the apply layer for system roots).
    ro,
    /// Read-write agent workspace grant.
    rw,
    /// Execute-oriented grant (reserved for explicit binary paths).
    exec,

    pub fn toString(self: AccessMode) []const u8 {
        return @tagName(self);
    }
};

pub const PathGrant = struct {
    path: []const u8,
    mode: AccessMode,
};

pub const CompileOptions = struct {
    /// Absolute workspace root. Relative or empty → fail closed.
    workspace_root: []const u8,
    /// Extra trusted control roots (absolute, or relative to workspace).
    /// Always combined with `{workspace}/.ryk` and `{workspace}/.git`.
    control_roots: []const []const u8 = &.{},
    /// When true, add explicit RW grants for classic platform temp trees
    /// (`tmp_path` plus `defaultTmpPrefixes`). **Default false:** production
    /// attach rewrites TMPDIR into workspace session temp (`.ryk-tmp`), which
    /// is already covered by the workspace RW grant. Do not auto-grant bare
    /// `/tmp` / `/var/tmp` trees on production defaults (M-8 grant-width).
    /// Attach / apply should keep this false unless intentionally opting into
    /// classic system-tmp RW.
    include_tmp: bool = false,
    tmp_path: []const u8 = "/tmp",
    /// Override default system RO prefixes (tests / platforms). Null = use defaults.
    /// Null also opts production into Linux device RW nodes (`/dev/null`, urandom).
    system_ro_prefixes: ?[]const []const u8 = null,
    /// Absolute paths for the agent launch binary (and realpath target when different).
    /// Compiled as `.exec` grants so preflight/exec can read+execute agents that live
    /// outside workspace/system prefixes (typical: `~/.local/share/...`).
    ///
    /// Callers must pass **narrow file paths only** — never `$HOME`, `/`, or other
    /// directory trees. `compileProfile` rejects filesystem-root exec (`InvalidExecPath`);
    /// apply layers re-check file-ness (Seatbelt `literal`, Landlock regular-file gate).
    exec_paths: []const []const u8 = &.{},
    /// Absolute paths granted as `.ro` trees (Seatbelt/Landlock subpath read).
    /// Optional extra RO trees beyond system prefixes — never bare `$HOME` or `/`.
    /// `compileProfile` rejects filesystem root (`InvalidRoPath`).
    ro_paths: []const []const u8 = &.{},
    /// Absolute paths granted as `.rw` trees for narrow host-agent config roots
    /// (e.g. `$HOME/.claude`, Application Support Claude). Never bare `$HOME` or `/`.
    /// `compileProfile` rejects filesystem root (`InvalidRwPath`). Callers must
    /// filter forbidden paths (`.ssh`, bare home) before compile.
    host_rw_paths: []const []const u8 = &.{},
    /// Deny workspace `.env` / `.env.*` content at the OS sandbox layer.
    /// Exact safe templates remain readable: `.env.example`, `.env.sample`,
    /// and `.env.template`.
    protect_workspace_secrets: bool = false,
};

pub const CompiledProfile = struct {
    allocator: std.mem.Allocator,
    /// Absolute canonical workspace root used at compile time.
    workspace_root: []const u8,
    /// Positive path grants (owned paths).
    grants: []PathGrant,
    /// Absolute control roots that are NOT agent-writable (owned paths).
    control_roots: []const []const u8,
    /// Whether backends must carve workspace secret-form files out of grants.
    protect_workspace_secrets: bool = false,
    /// True when at least one narrow host-agent config tree was compiled as RW
    /// (e.g. `$HOME/.claude`). Not bare `$HOME`. Used for FS scope honesty.
    has_host_config_rw: bool = false,
    /// Deterministic serialization used for hashing (owned).
    canonical_bytes: []const u8,
    /// Lowercase hex SHA-256 of `canonical_bytes`.
    hash_hex: [64]u8,

    pub fn deinit(self: *CompiledProfile) void {
        self.allocator.free(self.workspace_root);
        for (self.grants) |g| self.allocator.free(g.path);
        self.allocator.free(self.grants);
        for (self.control_roots) |p| self.allocator.free(p);
        self.allocator.free(self.control_roots);
        self.allocator.free(self.canonical_bytes);
        self.* = undefined;
    }

    pub fn hash(self: *const CompiledProfile) []const u8 {
        return self.hash_hex[0..];
    }

    /// True if any grant has the given absolute (or grant-listed) path and mode.
    pub fn hasGrant(self: *const CompiledProfile, path: []const u8, mode: AccessMode) bool {
        for (self.grants) |g| {
            if (g.mode == mode and pathEqual(g.path, path)) return true;
        }
        return false;
    }

    /// True if `path` is under a control root (not agent-writable).
    pub fn isControlPath(self: *const CompiledProfile, path: []const u8) bool {
        for (self.control_roots) |root| {
            if (isPathWithin(path, root)) return true;
        }
        return false;
    }

    /// Intent grant query: true when the compiled profile grants RW to `path`
    /// and the path is outside all control roots.
    ///
    /// This is **not** Landlock-effective (or Seatbelt-effective) writability.
    /// It answers only the portable grant model. Linux Landlock expands RW parents
    /// that contain control roots into child RW + parent RO, so
    /// **create-at-workspace-root** may be denied by the OS even when this returns
    /// true for paths under the workspace (see landlock.addRwGrantExcludingControls).
    /// Prefer writing under existing workspace children for portable agent I/O.
    /// For Landlock-effective create-at-root, use `isLandlockEffectiveWritable`.
    pub fn isAgentWritable(self: *const CompiledProfile, path: []const u8) bool {
        if (self.isControlPath(path)) return false;
        for (self.grants) |g| {
            if (g.mode == .rw and isPathWithin(path, g.path)) return true;
        }
        return false;
    }

    /// Landlock-effective writability: same as portable RW intent except
    /// workspace-root create is treated as denied when control expand applies
    /// (root RO + child RW). Paths strictly under the workspace root still use
    /// portable RW semantics. Seatbelt should use `isAgentWritable` instead.
    pub fn isLandlockEffectiveWritable(self: *const CompiledProfile, path: []const u8) bool {
        if (!self.isAgentWritable(path)) return false;
        // Exact workspace root: create-at-root denied under Landlock expand.
        if (pathEqual(path, self.workspace_root)) return false;
        return true;
    }

    /// Operator-facing effective FS scope summary for active receipts.
    ///
    /// Control roots are write-denied (`isAgentWritable` false) but remain
    /// content-readable under the parent workspace grant in the pure model
    /// (Landlock RO expand / Seatbelt write-deny carve-out) — honesty says
    /// "control write-deny (readable)", not full control isolation.
    /// `landlock`: workspace child RW, root RO, system RO, platform tmp when granted, no bare home.
    /// `seatbelt`: workspace RW, system RO, platform tmp when granted, no bare home, mach-lookup residual.
    /// When host-config RW trees are granted, summary says
    /// `narrow host-config RW, no bare home` instead of bare `no home`.
    pub fn effectiveFsScopeSummary(self: *const CompiledProfile, backend: FsScopeBackend) []const u8 {
        const has_tmp = blk: {
            for (self.grants) |g| {
                if (g.mode == .rw and isClassicTmpPath(g.path)) break :blk true;
            }
            break :blk false;
        };
        // Static literals keep receipt bytes stable. Single decision helper so
        // protect × host × tmp × backend cannot desync across copy-pasted trees.
        return composeEffectiveFsScopeSummary(
            backend,
            self.protect_workspace_secrets,
            self.has_host_config_rw,
            has_tmp,
        );
    }

    /// True if any grant is exactly `home` (broad HOME). Workspace *under* home is fine.
    pub fn grantsHome(self: *const CompiledProfile, home: []const u8) bool {
        if (home.len == 0) return false;
        for (self.grants) |g| {
            if (pathEqual(g.path, home)) return true;
        }
        return false;
    }

    /// Fail closed when a control root exists on disk as a symlink or non-dir/file.
    /// Missing control roots are allowed (parent may create them later). Existing
    /// regular **files** are allowed (host-config authority paths, gitdir files).
    /// Path-string isolation alone cannot protect a control tree that is an alias
    /// into RW space (F-1).
    pub fn validateControlRootsOnDisk(self: *const CompiledProfile, io: std.Io) error{InvalidControlRoot}!void {
        for (self.control_roots) |root| {
            try assertControlRootSafe(io, root);
        }
    }

    /// True when `path` is covered by any path grant (content-readable under pure model).
    pub fn isGrantedReadable(self: *const CompiledProfile, path: []const u8) bool {
        for (self.grants) |g| {
            if (isPathWithin(path, g.path)) return true;
        }
        return false;
    }
};

/// True when `path` exists and is unsafe as a control root.
/// Allowed: missing, existing regular file (not symlink), existing directory (not symlink).
/// Rejected: symlink, socket/fifo/device/other kinds, open/stat failures.
fn assertControlRootSafe(io: std.Io, path: []const u8) error{InvalidControlRoot}!void {
    if (path.len == 0) return error.InvalidControlRoot;

    // Symlink control roots are always unsafe: path-based deny on `.ryk` does not
    // cover writes via the realpath alias under an RW grant.
    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    if (std.Io.Dir.readLinkAbsolute(io, path, &link_buf)) |_| {
        return error.InvalidControlRoot;
    } else |err| switch (err) {
        error.FileNotFound => return, // absent is ok (path-based deny intent; parent may create)
        error.NotLink => {},
        // Other errors (access, loop, name too long): fail closed for control safety.
        else => return error.InvalidControlRoot,
    }

    // Prefer directory open without following symlinks.
    if (std.Io.Dir.openDirAbsolute(io, path, .{ .follow_symlinks = false })) |dir| {
        dir.close(io);
        return;
    } else |_| {}

    // Existing regular file is a valid control root (authority config files, gitdir).
    const file = std.Io.Dir.openFileAbsolute(io, path, .{
        .path_only = true,
        .follow_symlinks = false,
    }) catch return error.InvalidControlRoot;
    defer file.close(io);
    const st = file.stat(io) catch return error.InvalidControlRoot;
    if (st.kind != .file) return error.InvalidControlRoot;
}

/// Default system read-only prefixes (no home, no /tmp, no broad data volume).
///
/// macOS: never grant bare `/System` (covers `/System/Volumes/Data` homes/secrets)
/// or bare `/Library` (keychain / host config). Only sealed framework/dyld trees
/// plus **narrow** DNS/TLS leaves under `/etc` and `/private/etc` (not bare `/etc`).
/// Without hosts/resolv/ssl, agent HTTPS dies with getaddrinfo ENOTFOUND and
/// LibreSSL fopen of openssl.cnf — sockets can be "unrestricted" while name
/// resolution and cert loading still fail closed on FS.
/// Linux: include `/lib64`, `/etc`, `/dev`, and narrow `/proc/self` +
/// `/proc/thread-self` for dynlinker / NSS / devices / self-procfs under Landlock
/// Never bare `/proc` (same-uid peer environ/cmdline). `/dev` stays
/// RO; writable device nodes are separate.
pub fn defaultSystemRoPrefixes() []const []const u8 {
    return switch (builtin.os.tag) {
        .macos => &[_][]const u8{
            "/usr",
            "/bin",
            "/sbin",
            "/lib",
            // Sealed system trees only — never bare `/System` (data-volume hole).
            "/System/Library",
            "/System/Cryptexes",
            // Framework surface only — never bare `/Library` (keychain/config).
            "/Library/Frameworks",
            "/Library/Apple",
            // DNS: hosts + resolv.conf (symlink → /private/var/run/resolv.conf).
            // Both Users-form /etc and firmlink /private/etc so open succeeds.
            "/etc/hosts",
            "/private/etc/hosts",
            "/etc/resolv.conf",
            "/private/etc/resolv.conf",
            "/var/run/resolv.conf",
            "/private/var/run/resolv.conf",
            // TLS: LibreSSL/curl/openssl.cnf + CA bundle (not bare /etc).
            "/etc/ssl",
            "/private/etc/ssl",
        },
        else => &[_][]const u8{
            "/usr",
            "/bin",
            "/sbin",
            "/lib",
            "/lib64",
            "/etc",
            "/dev",
            // Self/thread-self only — bare `/proc` exposes other PIDs' environ/cmdline
            // (DAC often still allows same-uid). Dynlink needs maps/fds via /proc/self.
            "/proc/self",
            "/proc/thread-self",
        },
    };
}

/// Linux-only: character devices that agents must open for write without granting
/// full `/dev` RW (R2-3). Landlock PATH_BENEATH can target these nodes granularly.
/// Empty on non-Linux.
pub fn defaultDeviceRwPaths() []const []const u8 {
    return switch (builtin.os.tag) {
        .linux => &[_][]const u8{
            "/dev/null",
            "/dev/urandom",
        },
        else => &[_][]const u8{},
    };
}

/// Classic system temp path literals (Linux + macOS forms).
///
/// Shared by grant compile (`defaultTmpPrefixes` is the platform subset) and
/// `effectiveFsScopeSummary` so "platform tmp RW" detection cannot drift from
/// the paths compile actually grants (M-25).
pub fn classicTmpPathLiterals() []const []const u8 {
    return &[_][]const u8{
        "/tmp",
        "/var/tmp",
        "/private/tmp",
        "/private/var/tmp",
    };
}

/// True when `path` is exactly a classic system temp tree root.
pub fn isClassicTmpPath(path: []const u8) bool {
    for (classicTmpPathLiterals()) |p| {
        if (std.mem.eql(u8, path, p)) return true;
    }
    return false;
}

/// Extra writable temp prefixes when `include_tmp` is true.
///
/// Scoped to classic system temp trees only — not `/private/var/folders` (macOS
/// per-user TMPDIR parent), which is too broad and would swallow outside canaries
/// under testing.tmpDir. Production attach keeps `include_tmp=false` and rewrites
/// TMPDIR into workspace session temp (`.ryk-tmp`, covered by workspace RW).
pub fn defaultTmpPrefixes() []const []const u8 {
    return switch (builtin.os.tag) {
        .macos => &[_][]const u8{
            "/tmp",
            "/private/tmp",
            "/private/var/tmp",
        },
        else => &[_][]const u8{
            "/tmp",
            "/var/tmp",
        },
    };
}

/// Backend tag for operator-facing FS scope receipt strings.
pub const FsScopeBackend = enum { landlock, seatbelt };

/// Compose operator-facing FS scope text from ordered fragments.
/// Token order is load-bearing for receipt honesty tests — keep stable.
fn composeEffectiveFsScopeSummary(
    backend: FsScopeBackend,
    protect_workspace_secrets: bool,
    has_host_config_rw: bool,
    has_tmp: bool,
) []const u8 {
    // Fragment keys (backend × protect × host × tmp) — one table, no nested copy-paste trees.
    // Workspace / system / control are always present; home phrase and optional tokens vary.
    const protect = protect_workspace_secrets;
    const host = has_host_config_rw;
    const tmp = has_tmp;
    return switch (backend) {
        .landlock => switch (protect) {
            true => switch (host) {
                true => if (tmp)
                    "workspace child RW (env secret forms denied), root RO, system RO, platform tmp RW, narrow host-config RW, no bare home, control write-deny (readable)"
                else
                    "workspace child RW (env secret forms denied), root RO, system RO, narrow host-config RW, no bare home, control write-deny (readable)",
                false => if (tmp)
                    "workspace child RW (env secret forms denied), root RO, system RO, platform tmp RW, no home, control write-deny (readable)"
                else
                    "workspace child RW (env secret forms denied), root RO, system RO, no home, control write-deny (readable)",
            },
            false => switch (host) {
                true => if (tmp)
                    "workspace child RW, root RO, system RO, platform tmp RW, narrow host-config RW, no bare home, control write-deny (readable)"
                else
                    "workspace child RW, root RO, system RO, narrow host-config RW, no bare home, control write-deny (readable)",
                false => if (tmp)
                    "workspace child RW, root RO, system RO, platform tmp RW, no home, control write-deny (readable)"
                else
                    "workspace child RW, root RO, system RO, no home, control write-deny (readable)",
            },
        },
        .seatbelt => switch (protect) {
            true => switch (host) {
                true => if (tmp)
                    "workspace RW (env secret forms denied), system RO, platform tmp RW, narrow host-config RW, no bare home, control write-deny (readable), mach-lookup residual"
                else
                    "workspace RW (env secret forms denied), system RO, narrow host-config RW, no bare home, control write-deny (readable), mach-lookup residual",
                false => if (tmp)
                    "workspace RW (env secret forms denied), system RO, platform tmp RW, no home, control write-deny (readable), mach-lookup residual"
                else
                    "workspace RW (env secret forms denied), system RO, no home, control write-deny (readable), mach-lookup residual",
            },
            false => switch (host) {
                true => if (tmp)
                    "workspace RW, system RO, platform tmp RW, narrow host-config RW, no bare home, control write-deny (readable), mach-lookup residual"
                else
                    "workspace RW, system RO, narrow host-config RW, no bare home, control write-deny (readable), mach-lookup residual",
                false => if (tmp)
                    "workspace RW, system RO, platform tmp RW, no home, control write-deny (readable), mach-lookup residual"
                else
                    "workspace RW, system RO, no home, control write-deny (readable), mach-lookup residual",
            },
        },
    };
}

/// True if `path` is exactly `root` or a strict descendant (`root/` prefix).
/// Root `"/"` covers every absolute path. Empty root never matches.
pub fn isPathWithin(path: []const u8, root: []const u8) bool {
    if (root.len == 0) return false;
    if (pathEqual(path, root)) return true;
    if (path.len <= root.len) return false;
    if (!std.mem.startsWith(u8, path, root)) return false;
    // Root "/" covers everything absolute.
    if (root.len == 1 and root[0] == '/') return path.len > 1 and path[0] == '/';
    return path[root.len] == '/';
}

/// Compile a pure profile. Fail closed on empty/invalid workspace — never open grants.
pub fn compileProfile(allocator: std.mem.Allocator, options: CompileOptions) !CompiledProfile {
    const workspace_root = try canonicalizeAbsolute(allocator, options.workspace_root);
    errdefer allocator.free(workspace_root);

    // M-2: workspace at filesystem root would compile a full-tree RW grant
    // (`isPathWithin` treats "/" as covering every absolute path). Fail closed.
    // Also rejects inputs that canonicalize to root (`/.`, `/foo/..`, `//`).
    if (workspace_root.len == 1 and workspace_root[0] == '/') return error.InvalidWorkspace;

    var grants_list: std.ArrayList(PathGrant) = .empty;
    errdefer {
        for (grants_list.items) |g| allocator.free(g.path);
        grants_list.deinit(allocator);
    }

    // Workspace RW — never $HOME.
    {
        const ws_grant = try allocator.dupe(u8, workspace_root);
        grants_list.append(allocator, .{ .path = ws_grant, .mode = .rw }) catch |err| {
            allocator.free(ws_grant);
            return err;
        };
    }

    // System RO prefixes (explicit allowlist only).
    const use_production_defaults = options.system_ro_prefixes == null;
    const system_prefixes = options.system_ro_prefixes orelse defaultSystemRoPrefixes();
    for (system_prefixes) |prefix| {
        const canon = try canonicalizeAbsolute(allocator, prefix);
        grants_list.append(allocator, .{ .path = canon, .mode = .ro }) catch |err| {
            allocator.free(canon);
            return err;
        };
    }

    // Writable classic temp only when explicitly requested (`include_tmp`).
    // Production defaults do **not** auto-grant bare /tmp|/var/tmp: attach rewrites
    // TMPDIR into workspace session temp under workspace RW (M-8 grant-width).
    // Never ambient HOME — only platform temp trees + optional override path.
    if (options.include_tmp) {
        try appendUniqueRwGrant(&grants_list, allocator, options.tmp_path);
        for (defaultTmpPrefixes()) |tmp_prefix| {
            try appendUniqueRwGrant(&grants_list, allocator, tmp_prefix);
        }
    }

    // Linux production: writable device nodes (not full `/dev` RW). Landlock can
    // PATH_BENEATH these files; RO `/dev` alone leaves open/write of null/urandom denied.
    if (use_production_defaults) {
        for (defaultDeviceRwPaths()) |dev_path| {
            try appendUniqueRwGrant(&grants_list, allocator, dev_path);
        }
    }

    // Launch-binary exec grants (agents installed under $HOME, nvm, etc.).
    // Narrow file paths only — never ambient HOME or filesystem root.
    for (options.exec_paths) |raw_exec| {
        try appendUniqueExecGrant(&grants_list, allocator, raw_exec);
    }

    // Optional extra RO trees — never bare HOME or `/`.
    for (options.ro_paths) |raw_ro| {
        try appendUniqueRoGrant(&grants_list, allocator, raw_ro);
    }

    // Host-agent config RW trees (e.g. $HOME/.claude) — never bare HOME or `/`.
    // Dedup against existing workspace RW is handled by appendUniqueHostRwGrant.
    var has_host_config_rw = false;
    for (options.host_rw_paths) |raw_rw| {
        try appendUniqueHostRwGrant(&grants_list, allocator, raw_rw);
        has_host_config_rw = true;
    }

    // Control roots: always workspace/.ryk and workspace/.git plus any listed roots.
    // Both match policy/builtin files.write deny; OS attach must not leave .git agent-writable.
    var control_list: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (control_list.items) |c| allocator.free(c);
        control_list.deinit(allocator);
    }

    {
        const default_controls = [_][]const u8{ ".ryk", ".git" };
        for (default_controls) |name| {
            const default_control = try joinAbsolute(allocator, workspace_root, name);
            control_list.append(allocator, default_control) catch |err| {
                allocator.free(default_control);
                return err;
            };
        }
    }

    for (options.control_roots) |raw| {
        const resolved = try resolveControlRoot(allocator, workspace_root, raw);
        // Dedup exact matches.
        var exists = false;
        for (control_list.items) |existing| {
            if (pathEqual(existing, resolved)) {
                exists = true;
                break;
            }
        }
        if (exists) {
            allocator.free(resolved);
            continue;
        }
        control_list.append(allocator, resolved) catch |err| {
            allocator.free(resolved);
            return err;
        };
    }

    // Deterministic order: grants by path then mode; control roots by path.
    std.mem.sort(PathGrant, grants_list.items, {}, grantLessThan);
    std.mem.sort([]const u8, control_list.items, {}, pathLessThan);

    const grants = try grants_list.toOwnedSlice(allocator);
    errdefer {
        for (grants) |g| allocator.free(g.path);
        allocator.free(grants);
    }
    const control_roots = try control_list.toOwnedSlice(allocator);
    errdefer {
        for (control_roots) |c| allocator.free(c);
        allocator.free(control_roots);
    }

    const canonical_bytes = try serializeCanonical(
        allocator,
        grants,
        control_roots,
        options.protect_workspace_secrets,
    );
    errdefer allocator.free(canonical_bytes);

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(canonical_bytes, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    var hash_hex: [64]u8 = undefined;
    @memcpy(hash_hex[0..], hex[0..]);

    return .{
        .allocator = allocator,
        .workspace_root = workspace_root,
        .grants = grants,
        .control_roots = control_roots,
        .protect_workspace_secrets = options.protect_workspace_secrets,
        .has_host_config_rw = has_host_config_rw,
        .canonical_bytes = canonical_bytes,
        .hash_hex = hash_hex,
    };
}

// --- path helpers ----------------------------------------------------------------

// Workspace secret-form policy (single rule book).
//
// Product law: basename is a secret if it is exactly `.env`, or starts with
// `.env.` and is not an exact safe template. Linux FUSE calls
// `isWorkspaceSecretPath`. macOS Seatbelt cannot run Zig at open time, so
// SBPL emission uses only the fragments exported below (built from this same
// rule book). Do not hand-write `.env` regexes outside these helpers.

/// Exact basenames that are safe `.env.*` templates (not workspace secrets).
/// Sole source for template allow; SBPL `require-not` stems are derived from this.
pub const workspace_secret_safe_template_names = [_][]const u8{
    ".env.example",
    ".env.sample",
    ".env.template",
};

/// Seatbelt path regex that matches the same basenames as `isWorkspaceSecretBasename`
/// *before* the safe-template `require-not`. Owned only here; SBPL emitters must
/// use this constant (never duplicate the pattern string elsewhere).
pub const workspace_secret_form_sbpl_regex =
    "/[.]env($|/|[.][^/]*($|/))";

/// Alternation of safe-template stems after `.env.`, derived at comptime from
/// `workspace_secret_safe_template_names` (e.g. `example|sample|template`).
pub const workspace_secret_safe_template_sbpl_alt: []const u8 = blk: {
    var out: []const u8 = "";
    for (workspace_secret_safe_template_names, 0..) |name, i| {
        if (!std.mem.startsWith(u8, name, ".env.")) {
            @compileError("workspace secret safe template must start with \".env.\"");
        }
        const stem = name[".env.".len..];
        if (stem.len == 0) {
            @compileError("workspace secret safe template stem after \".env.\" must be non-empty");
        }
        if (i == 0) {
            out = stem;
        } else {
            out = out ++ "|" ++ stem;
        }
    }
    if (out.len == 0) @compileError("workspace_secret_safe_template_names must be non-empty");
    break :blk out;
};

/// True when `name` is an exact safe template basename from
/// `workspace_secret_safe_template_names`.
pub fn isWorkspaceSecretSafeTemplateName(name: []const u8) bool {
    for (workspace_secret_safe_template_names) |safe| {
        if (std.mem.eql(u8, name, safe)) return true;
    }
    return false;
}

/// True when a path component matches the secret-form *shape* (exact `.env` or
/// starts with `.env.`), before template allowlist. Canonical for Zig classify;
/// SBPL emission embeds `workspace_secret_form_sbpl_regex` (keep hand-maintained
/// regex aligned — live denial is process-canary proven).
pub fn isWorkspaceSecretFormShape(name: []const u8) bool {
    if (std.mem.eql(u8, name, ".env")) return true;
    if (std.mem.startsWith(u8, name, ".env.")) return true;
    return false;
}

/// Classify a single path component (basename). Canonical product-law decision.
pub fn isWorkspaceSecretBasename(name: []const u8) bool {
    if (!isWorkspaceSecretFormShape(name)) return false;
    return !isWorkspaceSecretSafeTemplateName(name);
}

/// True when the final path component is a workspace secret-form environment file.
///
/// Matching is component-bounded: `.env` and `.env.*` are protected, except for
/// the exact safe template names in `workspace_secret_safe_template_names`.
/// The caller is responsible for scoping the path to the workspace grant.
pub fn isWorkspaceSecretPath(path: []const u8) bool {
    return isWorkspaceSecretBasename(std.fs.path.basename(path));
}

/// Append the SBPL regex predicates for protect-on secret deny (form match +
/// template require-not). Only emission site for these patterns into SBPL text.
pub fn appendWorkspaceSecretSbplRegexPredicates(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
) !void {
    try out.appendSlice(allocator, "(regex #\"");
    try out.appendSlice(allocator, workspace_secret_form_sbpl_regex);
    try out.appendSlice(allocator, "\") ");
    try out.appendSlice(allocator, "(require-not (regex #\"/[.]env[.](");
    try out.appendSlice(allocator, workspace_secret_safe_template_sbpl_alt);
    try out.appendSlice(allocator, ")$\"))");
}

/// True when any slash-delimited component is a protected workspace secret name.
///
/// This is intentionally conservative for lexical paths containing `.` or `..`:
/// encountering a protected component denies the operation even if later
/// components would navigate away from it.
pub fn hasWorkspaceSecretComponent(path: []const u8) bool {
    var components = std.mem.splitScalar(u8, path, '/');
    while (components.next()) |component| {
        if (component.len != 0 and isWorkspaceSecretBasename(component)) return true;
    }
    return false;
}

fn pathEqual(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn appendUniqueRwGrant(
    grants_list: *std.ArrayList(PathGrant),
    allocator: std.mem.Allocator,
    raw_path: []const u8,
) !void {
    const canon = try canonicalizeAbsolute(allocator, raw_path);
    for (grants_list.items) |g| {
        if (pathEqual(g.path, canon) and g.mode == .rw) {
            allocator.free(canon);
            return;
        }
    }
    grants_list.append(allocator, .{ .path = canon, .mode = .rw }) catch |err| {
        allocator.free(canon);
        return err;
    };
}

/// Append a unique `.exec` grant. Fail closed on empty / non-absolute / filesystem root.
/// Does not open the path (pure compile); callers must pass regular files only.
/// Apply layers re-check file-ness (Seatbelt `literal`, Landlock regular-file gate).
fn appendUniqueExecGrant(
    grants_list: *std.ArrayList(PathGrant),
    allocator: std.mem.Allocator,
    raw_path: []const u8,
) !void {
    const canon = try canonicalizeAbsolute(allocator, raw_path);
    errdefer allocator.free(canon);
    // Never grant bare `/` as exec — covers every absolute path under isPathWithin.
    if (canon.len == 1 and canon[0] == '/') return error.InvalidExecPath;
    for (grants_list.items) |g| {
        if (pathEqual(g.path, canon) and g.mode == .exec) {
            allocator.free(canon);
            return;
        }
    }
    try grants_list.append(allocator, .{ .path = canon, .mode = .exec });
}

/// Append a unique `.ro` grant for a directory (or file) tree. Fail closed on `/`.
/// Does not open the path (pure compile). Callers filter bare HOME / `.ssh` first.
fn appendUniqueRoGrant(
    grants_list: *std.ArrayList(PathGrant),
    allocator: std.mem.Allocator,
    raw_path: []const u8,
) !void {
    const canon = try canonicalizeAbsolute(allocator, raw_path);
    errdefer allocator.free(canon);
    if (canon.len == 1 and canon[0] == '/') return error.InvalidRoPath;
    for (grants_list.items) |g| {
        if (pathEqual(g.path, canon) and g.mode == .ro) {
            allocator.free(canon);
            return;
        }
    }
    try grants_list.append(allocator, .{ .path = canon, .mode = .ro });
}

/// Append a unique `.rw` grant for a host-agent config tree. Fail closed on `/`.
fn appendUniqueHostRwGrant(
    grants_list: *std.ArrayList(PathGrant),
    allocator: std.mem.Allocator,
    raw_path: []const u8,
) !void {
    const canon = try canonicalizeAbsolute(allocator, raw_path);
    errdefer allocator.free(canon);
    if (canon.len == 1 and canon[0] == '/') return error.InvalidRwPath;
    for (grants_list.items) |g| {
        if (pathEqual(g.path, canon) and g.mode == .rw) {
            allocator.free(canon);
            return;
        }
    }
    try grants_list.append(allocator, .{ .path = canon, .mode = .rw });
}

fn pathLessThan(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

fn grantLessThan(_: void, a: PathGrant, b: PathGrant) bool {
    const path_order = std.mem.order(u8, a.path, b.path);
    if (path_order != .eq) return path_order == .lt;
    return @intFromEnum(a.mode) < @intFromEnum(b.mode);
}

/// Lexically canonicalize an absolute Unix-style path. Fail closed if not absolute.
fn canonicalizeAbsolute(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    if (raw.len == 0) return error.InvalidWorkspace;
    // Reject null bytes.
    if (std.mem.indexOfScalar(u8, raw, 0) != null) return error.InvalidWorkspace;
    if (!std.fs.path.isAbsolute(raw)) return error.InvalidWorkspace;

    // Normalize separators and collapse . / ..
    var components: std.ArrayList([]const u8) = .empty;
    defer components.deinit(allocator);

    var it = std.mem.splitScalar(u8, raw, '/');
    while (it.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".")) continue;
        if (std.mem.eql(u8, part, "..")) {
            if (components.items.len > 0) _ = components.pop();
            continue;
        }
        try components.append(allocator, part);
    }

    if (components.items.len == 0) {
        // Path reduced to filesystem root.
        return try allocator.dupe(u8, "/");
    }

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    for (components.items) |part| {
        try out.append(allocator, '/');
        try out.appendSlice(allocator, part);
    }
    return try out.toOwnedSlice(allocator);
}

fn joinAbsolute(allocator: std.mem.Allocator, root: []const u8, rel: []const u8) ![]u8 {
    if (rel.len == 0) return try allocator.dupe(u8, root);
    if (std.fs.path.isAbsolute(rel)) return try canonicalizeAbsolute(allocator, rel);
    // Trim leading ./ from relative.
    var clean = rel;
    while (std.mem.startsWith(u8, clean, "./")) clean = clean[2..];
    const joined = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ root, clean });
    defer allocator.free(joined);
    return try canonicalizeAbsolute(allocator, joined);
}

fn resolveControlRoot(allocator: std.mem.Allocator, workspace_root: []const u8, raw: []const u8) ![]u8 {
    if (raw.len == 0) return error.InvalidWorkspace;
    if (std.fs.path.isAbsolute(raw)) return try canonicalizeAbsolute(allocator, raw);
    return try joinAbsolute(allocator, workspace_root, raw);
}

/// Sorted newline list of `mode\\tpath` grants and `control\\tpath` carve-outs.
fn serializeCanonical(
    allocator: std.mem.Allocator,
    grants: []const PathGrant,
    control_roots: []const []const u8,
    protect_workspace_secrets: bool,
) ![]u8 {
    var lines: std.ArrayList([]u8) = .empty;
    defer {
        for (lines.items) |line| allocator.free(line);
        lines.deinit(allocator);
    }

    for (grants) |g| {
        const line = try std.fmt.allocPrint(allocator, "{s}\t{s}", .{ g.mode.toString(), g.path });
        lines.append(allocator, line) catch |err| {
            allocator.free(line);
            return err;
        };
    }
    for (control_roots) |root| {
        const line = try std.fmt.allocPrint(allocator, "control\t{s}", .{root});
        lines.append(allocator, line) catch |err| {
            allocator.free(line);
            return err;
        };
    }
    try lines.append(allocator, try std.fmt.allocPrint(
        allocator,
        "protect_workspace_secrets\t{}",
        .{protect_workspace_secrets},
    ));

    std.mem.sort([]u8, lines.items, {}, pathLessThan);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    for (lines.items, 0..) |line, i| {
        if (i > 0) try out.append(allocator, '\n');
        try out.appendSlice(allocator, line);
    }
    // Trailing newline for stable multi-line form (even for a single line).
    if (lines.items.len > 0) try out.append(allocator, '\n');
    return try out.toOwnedSlice(allocator);
}

// --- tests (P1-U) ----------------------------------------------------------------

test "macOS default system RO includes DNS and TLS leaves not bare /etc" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var compiled = try compileProfile(allocator, .{
        .workspace_root = "/tmp/ryk-profile-dns-tls-ws",
        // null → production defaults
        .system_ro_prefixes = null,
    });
    defer compiled.deinit();

    try std.testing.expect(compiled.hasGrant("/private/etc/ssl", .ro));
    try std.testing.expect(compiled.hasGrant("/etc/ssl", .ro));
    try std.testing.expect(compiled.hasGrant("/private/etc/hosts", .ro));
    try std.testing.expect(compiled.hasGrant("/private/var/run/resolv.conf", .ro));
    try std.testing.expect(compiled.isGrantedReadable("/private/etc/ssl/cert.pem"));
    try std.testing.expect(compiled.isGrantedReadable("/private/etc/hosts"));
    // Never bare /etc content grant.
    try std.testing.expect(!compiled.hasGrant("/etc", .ro));
    try std.testing.expect(!compiled.hasGrant("/private/etc", .ro));
    try std.testing.expect(!compiled.isGrantedReadable("/etc/passwd"));
    try std.testing.expect(!compiled.isGrantedReadable("/private/etc/passwd"));
}

test "P1-U-01 workspace grant is RW for absolute workspace" {
    const allocator = std.testing.allocator;
    const ws = "/tmp/ryk-profile-ws-unit";
    var profile = try compileProfile(allocator, .{
        .workspace_root = ws,
        .system_ro_prefixes = &[_][]const u8{ "/usr", "/bin" },
    });
    defer profile.deinit();

    try std.testing.expect(profile.hasGrant(ws, .rw));
    try std.testing.expect(profile.isAgentWritable(ws));
    try std.testing.expect(profile.isAgentWritable("/tmp/ryk-profile-ws-unit/src/main.zig"));
    try std.testing.expectEqualStrings(ws, profile.workspace_root);
}

test "P1-U-02 system prefixes are RO only" {
    const allocator = std.testing.allocator;
    const prefixes = [_][]const u8{ "/usr", "/bin", "/sbin", "/lib" };
    var profile = try compileProfile(allocator, .{
        .workspace_root = "/workspace/proj",
        .system_ro_prefixes = &prefixes,
    });
    defer profile.deinit();

    for (prefixes) |p| {
        try std.testing.expect(profile.hasGrant(p, .ro));
        try std.testing.expect(!profile.hasGrant(p, .rw));
        try std.testing.expect(!profile.isAgentWritable(p));
    }
    try std.testing.expect(!profile.isAgentWritable("/usr/bin/true"));
    try std.testing.expect(!profile.isAgentWritable("/bin/sh"));
}

test "P1-U-04 trusted ryk state carve-out is not agent-writable" {
    const allocator = std.testing.allocator;
    const ws = "/workspace/proj";
    var profile = try compileProfile(allocator, .{
        .workspace_root = ws,
        .system_ro_prefixes = &[_][]const u8{"/usr"},
        .control_roots = &[_][]const u8{".ryk/extra-control"},
    });
    defer profile.deinit();

    // Default workspace/.ryk is always a control root.
    try std.testing.expect(profile.isControlPath("/workspace/proj/.ryk"));
    try std.testing.expect(profile.isControlPath("/workspace/proj/.ryk/policy.yaml"));
    try std.testing.expect(profile.isControlPath("/workspace/proj/.ryk/sessions/mode"));
    try std.testing.expect(!profile.isAgentWritable("/workspace/proj/.ryk/policy.yaml"));
    try std.testing.expect(!profile.isAgentWritable("/workspace/proj/.ryk/sessions/approvals"));

    // Default workspace/.git is always a control root (parity with policy write deny).
    try std.testing.expect(profile.isControlPath("/workspace/proj/.git"));
    try std.testing.expect(profile.isControlPath("/workspace/proj/.git/hooks/pre-commit"));
    try std.testing.expect(profile.isControlPath("/workspace/proj/.git/config"));
    try std.testing.expect(profile.isControlPath("/workspace/proj/.git/objects/zz"));
    try std.testing.expect(!profile.isAgentWritable("/workspace/proj/.git"));
    try std.testing.expect(!profile.isAgentWritable("/workspace/proj/.git/hooks/pre-commit"));
    try std.testing.expect(!profile.isAgentWritable("/workspace/proj/.git/config"));
    try std.testing.expect(!profile.isAgentWritable("/workspace/proj/.git/objects/zz"));

    // Extra control root (relative → under workspace).
    try std.testing.expect(profile.isControlPath("/workspace/proj/.ryk/extra-control"));
    try std.testing.expect(!profile.isAgentWritable("/workspace/proj/.ryk/extra-control/ipc.sock"));

    // Ordinary workspace file remains writable.
    try std.testing.expect(profile.isAgentWritable("/workspace/proj/src/app.zig"));
}

test "default control roots include .ryk and .git" {
    const allocator = std.testing.allocator;
    var profile = try compileProfile(allocator, .{
        .workspace_root = "/workspace/proj",
        .system_ro_prefixes = &[_][]const u8{"/usr"},
    });
    defer profile.deinit();

    try std.testing.expect(profile.isControlPath("/workspace/proj/.ryk"));
    try std.testing.expect(profile.isControlPath("/workspace/proj/.git"));
    try std.testing.expect(!profile.isAgentWritable("/workspace/proj/.git/phase2-probe"));
    try std.testing.expect(profile.isAgentWritable("/workspace/proj/src/foo.zig"));
    // Control roots stay readable (write-deny only).
    try std.testing.expect(profile.isGrantedReadable("/workspace/proj/.git/config"));
    try std.testing.expect(profile.isGrantedReadable("/workspace/proj/.ryk/policy.yaml"));
}

test "P1-U-03 no broad HOME grant" {
    const allocator = std.testing.allocator;
    const home = "/Users/dev";
    const ws = "/Users/dev/projects/app";
    var profile = try compileProfile(allocator, .{
        .workspace_root = ws,
        .system_ro_prefixes = &[_][]const u8{ "/usr", "/bin" },
    });
    defer profile.deinit();

    try std.testing.expect(!profile.hasGrant(home, .rw));
    try std.testing.expect(!profile.hasGrant(home, .ro));
    try std.testing.expect(!profile.grantsHome(home));
    // HOME itself must not be agent-writable via grants.
    try std.testing.expect(!profile.isAgentWritable(home));
    try std.testing.expect(!profile.isAgentWritable("/Users/dev/.ssh/id_rsa"));
    // Workspace under home is still granted (narrower than HOME).
    try std.testing.expect(profile.isAgentWritable(ws));
}

test "launch exec_paths compile as .exec grants without HOME or RW" {
    const allocator = std.testing.allocator;
    const home = "/Users/dev";
    const ws = "/Users/dev/projects/app";
    const agent_bin = "/Users/dev/.local/share/claude/versions/2.1.196";
    const agent_link = "/Users/dev/.local/bin/claude";
    var compiled = try compileProfile(allocator, .{
        .workspace_root = ws,
        .system_ro_prefixes = &[_][]const u8{ "/usr", "/bin" },
        .exec_paths = &.{ agent_bin, agent_link },
    });
    defer compiled.deinit();

    try std.testing.expect(compiled.hasGrant(agent_bin, .exec));
    try std.testing.expect(compiled.hasGrant(agent_link, .exec));
    // Exec grants are not RW and do not open HOME.
    try std.testing.expect(!compiled.hasGrant(agent_bin, .rw));
    try std.testing.expect(!compiled.hasGrant(home, .exec));
    try std.testing.expect(!compiled.hasGrant(home, .ro));
    try std.testing.expect(!compiled.hasGrant(home, .rw));
    try std.testing.expect(!compiled.grantsHome(home));
    try std.testing.expect(!compiled.isAgentWritable(home));
    try std.testing.expect(!compiled.isAgentWritable("/Users/dev/.ssh/id_rsa"));
    // Content-readable under pure model for the binary path only.
    try std.testing.expect(compiled.isGrantedReadable(agent_bin));
    try std.testing.expect(!compiled.isGrantedReadable("/Users/dev/.ssh/id_rsa"));
}

test "launch exec_paths reject filesystem root" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.InvalidExecPath, compileProfile(allocator, .{
        .workspace_root = "/Users/dev/projects/app",
        .system_ro_prefixes = &[_][]const u8{"/usr"},
        .exec_paths = &.{"/"},
    }));
}

test "codex system ro_paths compile narrow /etc/codex without bare /etc or HOME" {
    const allocator = std.testing.allocator;
    const home = "/Users/dev";
    const ws = "/Users/dev/projects/app";
    var compiled = try compileProfile(allocator, .{
        .workspace_root = ws,
        .system_ro_prefixes = &[_][]const u8{ "/usr", "/bin" },
        .ro_paths = &.{ "/etc/codex", "/private/etc/codex" },
        .host_rw_paths = &.{"/Users/dev/.codex"},
    });
    defer compiled.deinit();

    try std.testing.expect(compiled.hasGrant("/etc/codex", .ro));
    try std.testing.expect(compiled.hasGrant("/private/etc/codex", .ro));
    try std.testing.expect(compiled.isGrantedReadable("/etc/codex/requirements.toml"));
    try std.testing.expect(compiled.isGrantedReadable("/private/etc/codex/requirements.toml"));
    // Not bare /etc content.
    try std.testing.expect(!compiled.hasGrant("/etc", .ro));
    try std.testing.expect(!compiled.isGrantedReadable("/etc/passwd"));
    try std.testing.expect(!compiled.isGrantedReadable("/etc/hosts"));
    try std.testing.expect(!compiled.grantsHome(home));
    try std.testing.expect(!compiled.isAgentWritable("/etc/codex"));
    try std.testing.expect(compiled.hasGrant("/Users/dev/.codex", .rw));
}

// Issue #194: grok 1.0.4 config load is the file ~/.grok/config.toml.
// Parent ~/.grok is metadata-walk only (Seatbelt ancestor literals), never a
// content grant. Receipt stays narrow host-config RW, no bare home.
test "grok host-config file grant covers config.toml without bare home or keychain" {
    const allocator = std.testing.allocator;
    const home = "/Users/dev";
    const ws = "/tmp/ryk-grok-repro";
    const grok_config = "/Users/dev/.grok/config.toml";
    var compiled = try compileProfile(allocator, .{
        .workspace_root = ws,
        .system_ro_prefixes = &[_][]const u8{ "/usr", "/bin" },
        .host_rw_paths = &.{grok_config},
        .control_roots = &.{grok_config},
    });
    defer compiled.deinit();

    try std.testing.expect(compiled.hasGrant(grok_config, .rw));
    try std.testing.expect(compiled.isGrantedReadable(grok_config));
    try std.testing.expect(compiled.isControlPath(grok_config));
    try std.testing.expect(!compiled.isAgentWritable(grok_config));
    try std.testing.expect(!compiled.hasGrant("/Users/dev/.grok", .rw));
    try std.testing.expect(!compiled.isGrantedReadable("/Users/dev/.grok/worktrees/evil"));
    try std.testing.expect(!compiled.isGrantedReadable("/Users/dev/.grok/bin/grok"));
    try std.testing.expect(!compiled.grantsHome(home));
    try std.testing.expect(!compiled.isGrantedReadable("/Users/dev/Library/Keychains/login.keychain-db"));
    try std.testing.expect(!compiled.isGrantedReadable("/Users/dev/.ssh/id_rsa"));
    try std.testing.expect(compiled.has_host_config_rw);
    const seatbelt_scope = compiled.effectiveFsScopeSummary(.seatbelt);
    try std.testing.expect(std.mem.indexOf(u8, seatbelt_scope, "narrow host-config RW, no bare home") != null);
}

test "host config host_rw_paths compile as RW without HOME or ssh" {
    const allocator = std.testing.allocator;
    const home = "/Users/dev";
    const ws = "/Users/dev/projects/app";
    const claude_cfg = "/Users/dev/.claude";
    const claude_share = "/Users/dev/.local/share/claude";
    const claude_app_support = "/Users/dev/Library/Application Support/Claude";
    var compiled = try compileProfile(allocator, .{
        .workspace_root = ws,
        .system_ro_prefixes = &[_][]const u8{ "/usr", "/bin" },
        .host_rw_paths = &.{ claude_cfg, claude_share, claude_app_support },
    });
    defer compiled.deinit();

    try std.testing.expect(compiled.hasGrant(claude_cfg, .rw));
    try std.testing.expect(compiled.hasGrant(claude_share, .rw));
    try std.testing.expect(compiled.hasGrant(claude_app_support, .rw));
    try std.testing.expect(compiled.isAgentWritable(claude_cfg));
    try std.testing.expect(compiled.isAgentWritable("/Users/dev/.claude/history.jsonl"));
    try std.testing.expect(!compiled.grantsHome(home));
    try std.testing.expect(!compiled.isAgentWritable(home));
    try std.testing.expect(!compiled.isAgentWritable("/Users/dev/.ssh/id_rsa"));
    try std.testing.expect(!compiled.isGrantedReadable("/Users/dev/.ssh/id_rsa"));
    try std.testing.expect(!compiled.isAgentWritable("/Users/dev/Library"));
    try std.testing.expect(compiled.isGrantedReadable(claude_cfg));
    try std.testing.expect(compiled.isGrantedReadable("/Users/dev/.claude/settings.json"));
    try std.testing.expect(compiled.has_host_config_rw);
    const seatbelt_scope = compiled.effectiveFsScopeSummary(.seatbelt);
    try std.testing.expect(std.mem.indexOf(u8, seatbelt_scope, "narrow host-config RW, no bare home") != null);
    try std.testing.expect(std.mem.indexOf(u8, seatbelt_scope, "no home,") == null or
        std.mem.indexOf(u8, seatbelt_scope, "no bare home") != null);
    // Bare "no home" without "bare" must not appear as the only home phrase.
    try std.testing.expect(std.mem.indexOf(u8, seatbelt_scope, "no bare home") != null);
}

test "effectiveFsScopeSummary without host grants still says no home" {
    const allocator = std.testing.allocator;
    var compiled = try compileProfile(allocator, .{
        .workspace_root = "/Users/dev/projects/app",
        .system_ro_prefixes = &[_][]const u8{"/usr"},
        .include_tmp = false,
    });
    defer compiled.deinit();
    try std.testing.expect(!compiled.has_host_config_rw);
    const scope = compiled.effectiveFsScopeSummary(.seatbelt);
    try std.testing.expect(std.mem.indexOf(u8, scope, "no home") != null);
    try std.testing.expect(std.mem.indexOf(u8, scope, "narrow host-config RW") == null);
}

test "host config host_rw_paths reject filesystem root" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.InvalidRwPath, compileProfile(allocator, .{
        .workspace_root = "/Users/dev/projects/app",
        .system_ro_prefixes = &[_][]const u8{"/usr"},
        .host_rw_paths = &.{"/"},
    }));
}

test "P1-U-06 empty and relative workspace fail closed" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(error.InvalidWorkspace, compileProfile(allocator, .{
        .workspace_root = "",
    }));
    try std.testing.expectError(error.InvalidWorkspace, compileProfile(allocator, .{
        .workspace_root = "relative/path",
    }));
    try std.testing.expectError(error.InvalidWorkspace, compileProfile(allocator, .{
        .workspace_root = ".",
    }));
    try std.testing.expectError(error.InvalidWorkspace, compileProfile(allocator, .{
        .workspace_root = "workspace",
    }));
}

test "M-2 workspace at filesystem root fails closed" {
    const allocator = std.testing.allocator;

    // Bare root would grant full-tree RW via isPathWithin("/", ...).
    try std.testing.expectError(error.InvalidWorkspace, compileProfile(allocator, .{
        .workspace_root = "/",
        .system_ro_prefixes = &[_][]const u8{"/usr"},
    }));
    // Lexical forms that canonicalize to root must also fail closed.
    try std.testing.expectError(error.InvalidWorkspace, compileProfile(allocator, .{
        .workspace_root = "/.",
        .system_ro_prefixes = &[_][]const u8{"/usr"},
    }));
    try std.testing.expectError(error.InvalidWorkspace, compileProfile(allocator, .{
        .workspace_root = "/foo/..",
        .system_ro_prefixes = &[_][]const u8{"/usr"},
    }));
    try std.testing.expectError(error.InvalidWorkspace, compileProfile(allocator, .{
        .workspace_root = "//",
        .system_ro_prefixes = &[_][]const u8{"/usr"},
    }));

    // Normal absolute workspaces still compile (including single-component roots).
    var normal = try compileProfile(allocator, .{
        .workspace_root = "/workspace/proj",
        .system_ro_prefixes = &[_][]const u8{"/usr"},
    });
    defer normal.deinit();
    try std.testing.expect(normal.hasGrant("/workspace/proj", .rw));

    var single = try compileProfile(allocator, .{
        .workspace_root = "/tmp/ryk-profile-m2-ws",
        .system_ro_prefixes = &[_][]const u8{"/usr"},
    });
    defer single.deinit();
    try std.testing.expect(single.hasGrant("/tmp/ryk-profile-m2-ws", .rw));
}

test "P1-U-07 determinism: same inputs yield same canonical bytes and hash" {
    const allocator = std.testing.allocator;
    const opts = CompileOptions{
        .workspace_root = "/workspace/same",
        .system_ro_prefixes = &[_][]const u8{ "/lib", "/usr", "/bin" },
        .include_tmp = true,
        .tmp_path = "/tmp",
        .control_roots = &[_][]const u8{"/var/ryk-control"},
    };

    var a = try compileProfile(allocator, opts);
    defer a.deinit();
    var b = try compileProfile(allocator, opts);
    defer b.deinit();

    try std.testing.expectEqualStrings(a.canonical_bytes, b.canonical_bytes);
    try std.testing.expectEqualStrings(a.hash(), b.hash());
    try std.testing.expect(a.hash().len == 64);

    // Different workspace → different hash.
    var c = try compileProfile(allocator, .{
        .workspace_root = "/workspace/other",
        .system_ro_prefixes = opts.system_ro_prefixes,
        .include_tmp = true,
        .tmp_path = "/tmp",
        .control_roots = opts.control_roots,
    });
    defer c.deinit();
    try std.testing.expect(!std.mem.eql(u8, a.hash(), c.hash()));
}

test "optional tmp grant is RW only when requested" {
    const allocator = std.testing.allocator;

    var without = try compileProfile(allocator, .{
        .workspace_root = "/workspace/a",
        .system_ro_prefixes = &[_][]const u8{"/usr"},
        .include_tmp = false,
    });
    defer without.deinit();
    try std.testing.expect(!without.hasGrant("/tmp", .rw));

    var with_tmp = try compileProfile(allocator, .{
        .workspace_root = "/workspace/a",
        .system_ro_prefixes = &[_][]const u8{"/usr"},
        .include_tmp = true,
        .tmp_path = "/tmp",
    });
    defer with_tmp.deinit();
    try std.testing.expect(with_tmp.hasGrant("/tmp", .rw));
    try std.testing.expect(with_tmp.isAgentWritable("/tmp/ryk-scratch"));
}

test "control root symlink on disk fails closed (F-1)" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    try ws_tmp.dir.createDirPath(io, "src");
    const ws_root = try ws_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(ws_root);

    const src_path = try std.fs.path.join(allocator, &.{ ws_root, "src" });
    defer allocator.free(src_path);
    const ryk_link = try std.fs.path.join(allocator, &.{ ws_root, ".ryk" });
    defer allocator.free(ryk_link);

    // Plant workspace/.ryk → workspace/src (path alias attack).
    std.Io.Dir.cwd().symLink(io, src_path, ryk_link, .{}) catch |err| switch (err) {
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };

    var compiled = try compileProfile(allocator, .{
        .workspace_root = ws_root,
        .system_ro_prefixes = &[_][]const u8{ "/usr", "/bin" },
    });
    defer compiled.deinit();

    try std.testing.expectError(error.InvalidControlRoot, compiled.validateControlRootsOnDisk(io));
}

test "control root real directory is accepted" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    try ws_tmp.dir.createDirPath(io, ".ryk");
    try ws_tmp.dir.createDirPath(io, ".git");
    try ws_tmp.dir.writeFile(io, .{ .sub_path = "neighbor.txt", .data = "ok" });
    const ws_root = try ws_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(ws_root);

    var compiled = try compileProfile(allocator, .{
        .workspace_root = ws_root,
        .system_ro_prefixes = &[_][]const u8{ "/usr", "/bin" },
    });
    defer compiled.deinit();
    try compiled.validateControlRootsOnDisk(io);
}

test "control root .git symlink on disk fails closed" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    try ws_tmp.dir.createDirPath(io, "src");
    // Real .ryk so only the .git symlink fails validation.
    try ws_tmp.dir.createDirPath(io, ".ryk");
    const ws_root = try ws_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(ws_root);

    const src_path = try std.fs.path.join(allocator, &.{ ws_root, "src" });
    defer allocator.free(src_path);
    const git_link = try std.fs.path.join(allocator, &.{ ws_root, ".git" });
    defer allocator.free(git_link);

    std.Io.Dir.cwd().symLink(io, src_path, git_link, .{}) catch |err| switch (err) {
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };

    var compiled = try compileProfile(allocator, .{
        .workspace_root = ws_root,
        .system_ro_prefixes = &[_][]const u8{ "/usr", "/bin" },
    });
    defer compiled.deinit();

    try std.testing.expectError(error.InvalidControlRoot, compiled.validateControlRootsOnDisk(io));
}

// Linked worktrees / some submodules use a gitdir *file* at workspace/.git.
// Regular files are valid control roots (authority write-deny + gitdir): RO leaf
// under parent RW expand, not a writable tree. Symlinks still fail closed.
test "control root .git as gitdir file is accepted" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    try ws_tmp.dir.createDirPath(io, ".ryk");
    try ws_tmp.dir.writeFile(io, .{ .sub_path = ".git", .data = "gitdir: /tmp/elsewhere/worktrees/wt1\n" });
    const ws_root = try ws_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(ws_root);

    var compiled = try compileProfile(allocator, .{
        .workspace_root = ws_root,
        .system_ro_prefixes = &[_][]const u8{ "/usr", "/bin" },
    });
    defer compiled.deinit();

    try compiled.validateControlRootsOnDisk(io);
}

test "control root regular file (authority path) is accepted" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    try ws_tmp.dir.createDirPath(io, ".ryk");
    try ws_tmp.dir.createDirPath(io, ".git");
    try ws_tmp.dir.createDirPath(io, ".codex");
    try ws_tmp.dir.writeFile(io, .{ .sub_path = ".codex/config.toml", .data = "[mcp_servers]\n" });
    const ws_root = try ws_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(ws_root);
    const config_path = try std.fs.path.join(allocator, &.{ ws_root, ".codex", "config.toml" });
    defer allocator.free(config_path);

    var compiled = try compileProfile(allocator, .{
        .workspace_root = ws_root,
        .system_ro_prefixes = &[_][]const u8{ "/usr", "/bin" },
        .control_roots = &[_][]const u8{config_path},
    });
    defer compiled.deinit();

    try compiled.validateControlRootsOnDisk(io);
    try std.testing.expect(compiled.isControlPath(config_path));
    try std.testing.expect(!compiled.isAgentWritable(config_path));
}

test "isPathWithin handles filesystem root and prefix boundaries" {
    try std.testing.expect(isPathWithin("/", "/"));
    try std.testing.expect(isPathWithin("/etc", "/"));
    try std.testing.expect(isPathWithin("/ws/.ryk", "/"));
    try std.testing.expect(isPathWithin("/ws/src", "/ws"));
    try std.testing.expect(!isPathWithin("/workspace2", "/workspace"));
    try std.testing.expect(!isPathWithin("/ws", "/ws/src"));
    try std.testing.expect(!isPathWithin("relative", "/"));
    // Empty root never matches (including empty path).
    try std.testing.expect(!isPathWithin("/etc", ""));
    try std.testing.expect(!isPathWithin("", ""));
    try std.testing.expect(!isPathWithin("", "/"));
    // Root slash covers absolute descendants only.
    try std.testing.expect(!isPathWithin("relative/path", "/"));
}

test "macOS defaults never grant bare /System or data-volume homes" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var compiled = try compileProfile(allocator, .{
        .workspace_root = "/tmp/ryk-profile-m1-ws",
        // Production defaults (null prefixes).
    });
    defer compiled.deinit();

    try std.testing.expect(!compiled.hasGrant("/System", .ro));
    try std.testing.expect(compiled.hasGrant("/System/Library", .ro));
    try std.testing.expect(compiled.hasGrant("/System/Cryptexes", .ro));
    // Data-volume firmlink surface must not be RO-readable via pure grants.
    try std.testing.expect(!compiled.isGrantedReadable("/System/Volumes/Data"));
    try std.testing.expect(!compiled.isGrantedReadable("/System/Volumes/Data/Users/dev/.ssh/id_rsa"));
    try std.testing.expect(!compiled.isGrantedReadable("/System/Volumes"));
    // Sealed system libraries remain readable.
    try std.testing.expect(compiled.isGrantedReadable("/System/Library/Frameworks"));
}

test "macOS defaults never grant bare /Library (keychain surface)" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var compiled = try compileProfile(allocator, .{
        .workspace_root = "/tmp/ryk-profile-m7-ws",
    });
    defer compiled.deinit();

    try std.testing.expect(!compiled.hasGrant("/Library", .ro));
    try std.testing.expect(compiled.hasGrant("/Library/Frameworks", .ro));
    try std.testing.expect(!compiled.isGrantedReadable("/Library/Keychains"));
    try std.testing.expect(!compiled.isGrantedReadable("/Library/Keychains/System.keychain"));
    try std.testing.expect(compiled.isGrantedReadable("/Library/Frameworks/Some.framework"));
}

test "Linux defaults include lib64 etc and dev" {
    if (builtin.os.tag == .macos or builtin.os.tag == .windows) return error.SkipZigTest;

    const prefixes = defaultSystemRoPrefixes();
    var saw_lib64 = false;
    var saw_etc = false;
    var saw_dev = false;
    var saw_proc_self = false;
    var saw_proc_thread_self = false;
    var saw_bare_proc = false;
    for (prefixes) |p| {
        if (std.mem.eql(u8, p, "/lib64")) saw_lib64 = true;
        if (std.mem.eql(u8, p, "/etc")) saw_etc = true;
        if (std.mem.eql(u8, p, "/dev")) saw_dev = true;
        if (std.mem.eql(u8, p, "/proc/self")) saw_proc_self = true;
        if (std.mem.eql(u8, p, "/proc/thread-self")) saw_proc_thread_self = true;
        if (std.mem.eql(u8, p, "/proc")) saw_bare_proc = true;
    }
    try std.testing.expect(saw_lib64);
    try std.testing.expect(saw_etc);
    try std.testing.expect(saw_dev);
    // Narrow procfs — self/thread-self only, never bare /proc.
    try std.testing.expect(saw_proc_self);
    try std.testing.expect(saw_proc_thread_self);
    try std.testing.expect(!saw_bare_proc);

    const allocator = std.testing.allocator;
    var compiled = try compileProfile(allocator, .{
        .workspace_root = "/tmp/ryk-profile-m6-ws",
    });
    defer compiled.deinit();
    try std.testing.expect(compiled.hasGrant("/lib64", .ro));
    try std.testing.expect(compiled.hasGrant("/etc", .ro));
    try std.testing.expect(compiled.hasGrant("/dev", .ro));
    try std.testing.expect(compiled.hasGrant("/proc/self", .ro));
    try std.testing.expect(compiled.hasGrant("/proc/thread-self", .ro));
    try std.testing.expect(!compiled.hasGrant("/proc", .ro));
    try std.testing.expect(compiled.isGrantedReadable("/proc/self/status"));
    try std.testing.expect(compiled.isGrantedReadable("/proc/self/maps"));
    try std.testing.expect(compiled.isGrantedReadable("/proc/thread-self/status"));
    // Peer PIDs under bare /proc must not be readable via the grant model.
    try std.testing.expect(!compiled.isGrantedReadable("/proc/1/environ"));
    try std.testing.expect(!compiled.isGrantedReadable("/proc/1/cmdline"));
}

test "R2-3 Linux production grants writable device nodes without full /dev RW" {
    if (builtin.os.tag == .macos or builtin.os.tag == .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var prod = try compileProfile(allocator, .{
        .workspace_root = "/tmp/ryk-profile-r2-3-ws",
    });
    defer prod.deinit();

    // Granular device RW (not bare `/dev` RW).
    try std.testing.expect(prod.hasGrant("/dev/null", .rw));
    try std.testing.expect(prod.hasGrant("/dev/urandom", .rw));
    try std.testing.expect(prod.isAgentWritable("/dev/null"));
    try std.testing.expect(prod.isAgentWritable("/dev/urandom"));
    // Full `/dev` stays RO — sibling block devices are not agent-writable.
    try std.testing.expect(prod.hasGrant("/dev", .ro));
    try std.testing.expect(!prod.isAgentWritable("/dev/sda"));
    try std.testing.expect(!prod.hasGrant("/dev", .rw));

    // Custom (non-production) prefixes must not auto-install device RW.
    var custom = try compileProfile(allocator, .{
        .workspace_root = "/tmp/ryk-profile-r2-3-custom",
        .system_ro_prefixes = &[_][]const u8{ "/usr", "/dev" },
        .include_tmp = false,
    });
    defer custom.deinit();
    try std.testing.expect(!custom.hasGrant("/dev/null", .rw));
    try std.testing.expect(!custom.isAgentWritable("/dev/null"));
}

test "R2-1 pure model grants Data-volume realpath workspace not sibling homes" {
    // Models macOS firmlink realpath workspace under /System/Volumes/Data/Users/…
    const allocator = std.testing.allocator;
    const ws = "/System/Volumes/Data/Users/dev/projects/app";
    var compiled = try compileProfile(allocator, .{
        .workspace_root = ws,
        .system_ro_prefixes = &[_][]const u8{ "/usr", "/bin", "/System/Library" },
        .include_tmp = false,
    });
    defer compiled.deinit();

    try std.testing.expect(compiled.isGrantedReadable(ws));
    try std.testing.expect(compiled.isAgentWritable(ws));
    try std.testing.expect(compiled.isAgentWritable("/System/Volumes/Data/Users/dev/projects/app/out.txt"));
    // Sibling home / other users under Data must not inherit workspace grant.
    try std.testing.expect(!compiled.isGrantedReadable("/System/Volumes/Data/Users/dev/.ssh/id_rsa"));
    try std.testing.expect(!compiled.isGrantedReadable("/System/Volumes/Data/Users/other/secret"));
    try std.testing.expect(!compiled.isGrantedReadable("/System/Volumes/Data/private/var/db"));
}

test "production defaults omit classic tmp RW (session-tmp surface)" {
    const allocator = std.testing.allocator;

    // Explicit custom prefixes + include_tmp false → no classic tmp.
    var without = try compileProfile(allocator, .{
        .workspace_root = "/workspace/a",
        .system_ro_prefixes = &[_][]const u8{"/usr"},
        .include_tmp = false,
    });
    defer without.deinit();
    try std.testing.expect(!without.hasGrant("/tmp", .rw));

    // Production path (null system_ro_prefixes) also omits classic tmp RW:
    // session temp lives under workspace (`.ryk-tmp`) via attach rewrite.
    var prod = try compileProfile(allocator, .{
        .workspace_root = "/workspace/a",
        .include_tmp = false,
    });
    defer prod.deinit();
    try std.testing.expect(!prod.hasGrant("/tmp", .rw));
    try std.testing.expect(!prod.hasGrant("/var/tmp", .rw));
    try std.testing.expect(!prod.hasGrant("/private/tmp", .rw));
    try std.testing.expect(!prod.hasGrant("/private/var/tmp", .rw));
    try std.testing.expect(!prod.isAgentWritable("/tmp/ryk-scratch"));
    // Workspace session temp path remains agent-writable via workspace RW.
    try std.testing.expect(prod.isAgentWritable("/workspace/a/.ryk-tmp"));
    try std.testing.expect(prod.isAgentWritable("/workspace/a/.ryk-tmp/scratch"));
    // Device grants still install on production defaults (Linux).
    if (builtin.os.tag == .linux) {
        try std.testing.expect(prod.hasGrant("/dev/null", .rw));
        try std.testing.expect(prod.hasGrant("/dev/urandom", .rw));
    }
    // Scope honesty: no platform tmp claim; control write-deny noted as readable.
    const landlock_scope = prod.effectiveFsScopeSummary(.landlock);
    try std.testing.expect(std.mem.indexOf(u8, landlock_scope, "platform tmp RW") == null);
    try std.testing.expect(std.mem.indexOf(u8, landlock_scope, "control write-deny (readable)") != null);
    try std.testing.expect(std.mem.indexOf(u8, landlock_scope, "no home") != null);

    // Opt-in classic tmp still works and is reflected in the summary.
    var with_tmp = try compileProfile(allocator, .{
        .workspace_root = "/workspace/a",
        .include_tmp = true,
        .tmp_path = "/tmp",
    });
    defer with_tmp.deinit();
    try std.testing.expect(with_tmp.hasGrant("/tmp", .rw));
    try std.testing.expect(with_tmp.isAgentWritable("/tmp/ryk-scratch"));
    const with_scope = with_tmp.effectiveFsScopeSummary(.landlock);
    try std.testing.expect(std.mem.indexOf(u8, with_scope, "platform tmp RW") != null);
    try std.testing.expect(std.mem.indexOf(u8, with_scope, "control write-deny (readable)") != null);
}

test "isClassicTmpPath matches grant and summary literals" {
    try std.testing.expect(isClassicTmpPath("/tmp"));
    try std.testing.expect(isClassicTmpPath("/var/tmp"));
    try std.testing.expect(isClassicTmpPath("/private/tmp"));
    try std.testing.expect(isClassicTmpPath("/private/var/tmp"));
    try std.testing.expect(!isClassicTmpPath("/tmp/subdir"));
    try std.testing.expect(!isClassicTmpPath("/var/folders/xx/T"));
    try std.testing.expect(!isClassicTmpPath("/workspace/.ryk-tmp"));
    // Platform default prefixes are a subset of the shared classic list.
    for (defaultTmpPrefixes()) |p| {
        try std.testing.expect(isClassicTmpPath(p));
    }
}

test "control root is write-deny only and remains readable under pure model" {
    const allocator = std.testing.allocator;
    const ws = "/workspace/proj";
    var profile = try compileProfile(allocator, .{
        .workspace_root = ws,
        .system_ro_prefixes = &[_][]const u8{"/usr"},
        .include_tmp = false,
    });
    defer profile.deinit();

    // Write-deny: control is never agent-writable.
    try std.testing.expect(!profile.isAgentWritable("/workspace/proj/.ryk/policy.yaml"));
    try std.testing.expect(profile.isControlPath("/workspace/proj/.ryk/policy.yaml"));
    // Readable via parent workspace grant (pure model; backends may RO-narrow).
    try std.testing.expect(profile.isGrantedReadable("/workspace/proj/.ryk/policy.yaml"));
    const seatbelt_scope = profile.effectiveFsScopeSummary(.seatbelt);
    try std.testing.expect(std.mem.indexOf(u8, seatbelt_scope, "control write-deny (readable)") != null);
    try std.testing.expect(std.mem.indexOf(u8, seatbelt_scope, "mach-lookup residual") != null);
}

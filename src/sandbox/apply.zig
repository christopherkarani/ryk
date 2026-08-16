//! Single ApplyBeforeExec boundary for production agent launch.
//!
//! Production path:
//!   cli/run → applyBeforeExec → supervisor.run → process.prepareChild
//!     → sandboxed spawn (apply_posix) or std.process.spawn
//!
//! Scaffold `backend.prepare` was removed. Production attach is exclusively
//! applyBeforeExec + apply_posix child apply; capability detect stays in backend.
//!
//! This module:
//! - compiles a pure FS profile (`profile.compileProfile`)
//! - scrubs loader/startup injection env (`env_scrub`)
//! - attempts platform OS prepare: Landlock on Linux; Seatbelt on macOS
//! - retains child-apply materials (`ChildMaterials` union) so spawn can box the *agent* process
//!
//! Landlock restrict_self and Seatbelt sandbox_init run only in a **forked child**
//! so the parent ryk process stays free. Production agent exec must use
//! `apply_posix.forkApplyLandlockAndExec` / `forkApplySeatbeltAndExec` (FD scrub
//! runs in that child before exec).
//!
//! Session `active` only via `receipt.isActive()` after real OS apply for the agent child.
//! NEVER claims network Landlock/Seatbelt.

const std = @import("std");
const builtin = @import("builtin");
const posture = @import("posture.zig");
const profile = @import("profile.zig");
const env_scrub = @import("env_scrub.zig");
const landlock = @import("landlock.zig");
const macos_seatbelt = @import("macos_seatbelt.zig");
const macos_profile = @import("macos_profile.zig");
const apply_posix = @import("apply_posix.zig");
const session_tmp = @import("session_tmp.zig");
const path_list = @import("path_list.zig");
pub const host_config_grants = @import("host_config_grants.zig");

/// Re-export session-tmp surface for callers that only import apply.
pub const workspace_session_tmp_name = session_tmp.workspace_session_tmp_name;
pub const classic_tmp_fallback = session_tmp.classic_tmp_fallback;
pub const workspaceSessionTmpPath = session_tmp.workspaceSessionTmpPath;
pub const ensureWorkspaceSessionTmp = session_tmp.ensureWorkspaceSessionTmp;
pub const claude_code_tmpdir_env = session_tmp.claude_code_tmpdir_env;
pub const claudeCodeTmpAccepts = session_tmp.claudeCodeTmpAccepts;
pub const ensureClaudeCodeTmpLeaves = session_tmp.ensureClaudeCodeTmpLeaves;

/// Re-export mode for callers that only touch apply.
pub const OsSandboxMode = posture.OsSandboxMode;
pub const AttachReceipt = posture.AttachReceipt;

/// Error when mode is `on` (required) and OS apply cannot attach.
pub const ApplyError = error{
    /// `--os-sandbox on` but backend unavailable / apply failed / profile invalid.
    RequireFailed,
    OutOfMemory,
};

/// Named public error set for `ApplyResult.spawnAgent`.
/// Prefer this over an inferred set that surfaces bare `Unexpected`.
/// Invariant failures (no child materials, missing SBPL/profile, proof mint fail)
/// map to `ApplyFailed` so CLI spawn classifiers stay honest.
pub const SpawnAgentError = apply_posix.SpawnError;

/// What the agent spawn path must do after `applyBeforeExec`.
/// Tag matches `ChildMaterials` so kind is derived from materials.
pub const ChildApplyKind = enum {
    none,
    landlock,
    seatbelt,
};

/// Owned child-apply materials for agent spawn.
/// Invalid both-set states are unrepresentable: at most one backend payload.
pub const ChildMaterials = union(enum) {
    none,
    landlock: struct {
        allocator: std.mem.Allocator,
        compiled: profile.CompiledProfile,
        route_forcing: ?landlock.RouteForcing = null,
        /// Original compile input (not recoverable from grants when workspace is /tmp).
        include_tmp: bool = false,
        /// Original profile inputs required by the sealed FUSE bootstrap rebuild.
        /// Invariant: must be identical to the inputs `compiled` was built from.
        /// Divergence rebuilds a different profile hash and fails the attach
        /// handshake with no diagnostic pointing at the mismatch.
        ro_paths: [][]const u8,
        host_rw_paths: [][]const u8,
    },
    seatbelt: struct {
        sbpl_z: [:0]u8,
        allocator: std.mem.Allocator,
        /// Precomputed at prepare from `CompiledProfile.effectiveFsScopeSummary(.seatbelt)`.
        /// Static string (not heap-owned). Used on activate so receipts cannot drift
        /// from a second hardcoded source of truth.
        fs_scope: []const u8,
        /// Residual grade used when rendering SBPL (receipts/network_scope honesty).
        profile_grade: macos_profile.SeatbeltProfileGrade = macos_profile.SeatbeltProfileGrade.default_grade,
    },

    pub fn deinit(self: *ChildMaterials) void {
        switch (self.*) {
            .none => {},
            .landlock => |*p| {
                p.compiled.deinit();
                path_list.free(p.allocator, p.ro_paths);
                path_list.free(p.allocator, p.host_rw_paths);
            },
            .seatbelt => |*s| s.allocator.free(s.sbpl_z),
        }
        self.* = .none;
    }

    pub fn kind(self: ChildMaterials) ChildApplyKind {
        return switch (self) {
            .none => .none,
            .landlock => .landlock,
            .seatbelt => .seatbelt,
        };
    }
};

/// Inputs for the single apply-before-exec seam.
pub const ApplyBoundary = struct {
    allocator: std.mem.Allocator,
    mode: OsSandboxMode,
    /// Absolute workspace root (fail closed if relative when mode is on/auto).
    workspace_root: []const u8,
    /// Child env map mutated in place when scrub runs (on/auto).
    env_map: ?*std.process.Environ.Map = null,
    /// Optional exact session-mint membership for provider phantoms.
    minted_env_lookup: ?env_scrub.MintedEnvLookup = null,
    /// Explicit loud escape. Loader/startup injection scrub still runs, but
    /// the attach-time launch allowlist must not remove host credentials.
    with_host_secrets: bool = false,
    /// Extra profile options.
    include_tmp: bool = false,
    control_roots: []const []const u8 = &.{},
    /// Absolute launch-binary paths for `.exec` profile grants (see `collectLaunchExecPaths`).
    /// Agents installed outside workspace/system prefixes (e.g. `~/.local/...`) need these
    /// so child preflight after Seatbelt/Landlock can still read+exec argv0.
    launch_exec_paths: []const []const u8 = &.{},
    /// Absolute RO trees for launch: Node/npm install package roots (see
    /// `collectLaunchInstallRoPaths`) plus host-scoped system RO (e.g. codex
    /// `/etc/codex` via `host_config_grants.collectHostSystemRoPaths`). Never bare
    /// `$HOME` or bare `/etc`. Covers nested optional deps + vendor binaries and
    /// narrow system config residual paths.
    launch_ro_paths: []const []const u8 = &.{},
    /// Absolute host-agent config trees as `.rw` grants (see `host_config_grants`).
    /// Empty backpack keeps HOME in env but denies home FS; these narrow subpaths
    /// restore host login/config (+ session write) for known agents without bare `$HOME`.
    launch_host_rw_paths: []const []const u8 = &.{},
    /// Exact authority files inside host RW trees (config.toml / settings.json / …).
    /// macOS Seatbelt emits last-match literal write denies. Callers should also
    /// pass the same paths as `control_roots` so Landlock control-expand keeps
    /// them RO under host RW on Linux (dual path).
    launch_write_deny_literals: []const []const u8 = &.{},
    /// Empty-backpack sessions require OS enforcement for workspace `.env`
    /// and `.env.*` names (safe templates remain readable).
    protect_workspace_secrets: bool = false,
    /// Optional per-launch proxy TCP port. When set, supported platforms install
    /// child network rules that force outbound TCP through the loopback proxy.
    network_proxy_port: ?u16 = null,
    require_network_route_forcing: bool = false,
    /// macOS Seatbelt residual grade (ignored on non-macOS). Default hardened.
    seatbelt_profile: macos_profile.SeatbeltProfileGrade = macos_profile.SeatbeltProfileGrade.default_grade,
    /// When `error.RequireFailed` is returned, set to a static reason code if non-null.
    fail_reason_out: ?*[]const u8 = null,
};

pub const AttachSessionTmp = struct {
    allocator: std.mem.Allocator,
    path: []u8,

    pub fn deinit(self: *AttachSessionTmp) void {
        var io_rt: std.Io.Threaded = .init_single_threaded;
        std.Io.Dir.cwd().deleteTree(io_rt.io(), self.path) catch {};
        self.allocator.free(self.path);
        self.* = undefined;
    }
};

pub const ApplyResult = struct {
    receipt: AttachReceipt,
    /// True when denylist env scrub ran against env_map.
    env_scrubbed: bool = false,
    /// True when launch allowlist ran (only with child-apply materials).
    env_launch_allowlisted: bool = false,
    /// Count of keys removed by denylist + optional launch allowlist (0 if none).
    env_keys_removed: usize = 0,
    /// Profile was compiled.
    profile_compiled: bool = false,
    /// By-value 64-hex digest of the compiled profile when compile succeeded (not heap-owned).
    profile_hash_hex: ?[64]u8 = null,
    /// Owned child-apply materials. Free with deinit. Default `.none`.
    materials: ChildMaterials = .none,
    /// True only when child-apply materials include OS network rules for the
    /// current proxy listener. This is per-launch, not a static doctor claim.
    network_route_forced: bool = false,
    /// Retained fork buffers for the last successful sandboxed spawn.
    /// Freed in `deinit` after the supervisor has waited/reaped the child.
    spawn_lease: ?apply_posix.SpawnLease = null,
    /// Fresh per-launch temp directory. Removed after the child has been reaped
    /// and its sandbox materials are no longer needed.
    session_tmp: ?AttachSessionTmp = null,

    pub fn deinit(self: *ApplyResult) void {
        if (self.spawn_lease) |*lease| {
            // Production path waits/reaps via PreparedChild before deinit.
            // Multi-spawn and error paths must killAndReap before free; deinit
            // does not kill (pid may already be reaped — SIGKILL would race reuse).
            lease.deinit();
            self.spawn_lease = null;
        }
        self.materials.deinit();
        if (self.session_tmp) |*owned_tmp| {
            owned_tmp.deinit();
            self.session_tmp = null;
        }
        self.* = undefined;
    }

    /// Kind of child-side OS apply the spawn path must perform (derived from materials tag).
    pub fn childApplyKind(self: ApplyResult) ChildApplyKind {
        return self.materials.kind();
    }

    /// True when spawn must use apply_posix (agent would otherwise be unboxed).
    pub fn requiresChildApply(self: ApplyResult) bool {
        return self.childApplyKind() != .none;
    }

    /// Proof that agent-child OS FS apply handshake succeeded.
    /// Only `activateAfterHandshake` (via `spawnAgent`) constructs this after a real
    /// fork status-pipe success. No cross-module mint — magic seal dropped (same-module).
    pub const ChildAttachProof = struct {
        mechanism: posture.BackendMechanism,

        pub fn isValid(self: ChildAttachProof) bool {
            return self.mechanism != .none;
        }
    };

    /// Result of a successful sandboxed agent spawn (pid + attach proof).
    pub const SpawnedAgent = struct {
        pid: i32,
        proof: ChildAttachProof,
    };

    /// Build active receipt from materials after proven child handshake.
    /// File-private: only `spawnAgent` calls this. Bare materials alone never
    /// authorize active (S-GLO-01). Hard-fails on missing materials/hash or
    /// activeReceipt construction failure — never soft-skips.
    ///
    /// Network scope is mechanism-specific when route-forced (M-1 honesty):
    /// Landlock is TCP port-scoped only (any remote IP; UDP unrestricted);
    /// Seatbelt is loopback-proxy TCP only (localhost:port SBPL).
    fn activateAfterHandshake(self: *ApplyResult) error{ApplyFailed}!ChildAttachProof {
        const hash = self.profile_hash_hex orelse return error.ApplyFailed;
        const mechanism: posture.BackendMechanism = switch (self.materials) {
            .none => return error.ApplyFailed,
            .landlock => .landlock,
            .seatbelt => .seatbelt,
        };
        // Resolve network_scope once per mechanism (M-15: no duplicated receipt arms).
        const network_scope: []const u8 = switch (self.materials) {
            .none => unreachable,
            .landlock => if (self.network_route_forced)
                "proxy route-forced (TCP connect port-scoped to proxy port; not address-scoped; UDP unrestricted)"
            else
                "unrestricted",
            .seatbelt => |*s| macos_profile.networkScopeSummary(s.profile_grade, self.network_route_forced),
        };
        const fs_scope: []const u8 = switch (self.materials) {
            .none => unreachable,
            .landlock => |*p| p.compiled.effectiveFsScopeSummary(.landlock),
            .seatbelt => |*s| s.fs_scope, // precomputed at prepare (single source)
        };
        const seatbelt_profile: ?macos_profile.SeatbeltProfileGrade = switch (self.materials) {
            .seatbelt => |*s| s.profile_grade,
            else => null,
        };
        self.receipt = posture.activeReceiptWithNetworkAndGrade(
            mechanism,
            hash[0..],
            fs_scope,
            network_scope,
            seatbelt_profile,
        ) catch return error.ApplyFailed;
        return .{ .mechanism = mechanism };
    }

    /// Spawn the agent with OS FS apply in the child (Landlock / Seatbelt).
    /// Parent stays unrestricted. Blocks until status-pipe proves apply.
    /// On success, mutates this result to active via `activateAfterHandshake`.
    /// After a successful child handshake, activate failure kills/reaps the child
    /// and returns `ApplyFailed` — never a live agent without an active receipt.
    /// Errors: `SpawnAgentError` (named; invariants → `ApplyFailed`, never bare `Unexpected`).
    pub fn spawnAgent(
        self: *ApplyResult,
        io: std.Io,
        allocator: std.mem.Allocator,
        argv: []const []const u8,
        env_map: ?*const std.process.Environ.Map,
        workspace_root: []const u8,
        stdio: apply_posix.StdioBehavior,
    ) SpawnAgentError!SpawnedAgent {
        // Match apply_posix empty-argv contract (ExecFailed, not FileNotFound).
        if (argv.len == 0) return error.ExecFailed;
        const resolved = try apply_posix.resolveArgv0(io, allocator, argv[0], env_map);
        defer if (resolved.owned) allocator.free(resolved.path);

        var argv_owned = try allocator.alloc([]const u8, argv.len);
        defer allocator.free(argv_owned);
        argv_owned[0] = resolved.path;
        @memcpy(argv_owned[1..], argv[1..]);

        // Drop any prior lease: kill+reap first. Freeing retained argv/env while
        // the prior child still runs is free-before-reap (fork COW UAF). One-shot
        // run never hits this; multi-spawn / retry paths must not free live buffers.
        if (self.spawn_lease) |*old| {
            if (old.pid > 0) apply_posix.killAndReapChild(old.pid);
            old.deinit();
            self.spawn_lease = null;
        }

        // Single switch on materials tag — invalid dual-backend state unrepresentable.
        var lease = switch (self.materials) {
            .none => return error.ApplyFailed,
            .landlock => |*ll| try apply_posix.forkApplyLandlockAndExec(
                io,
                &ll.compiled,
                ll.route_forcing,
                ll.include_tmp,
                ll.ro_paths,
                ll.host_rw_paths,
                argv_owned,
                env_map,
                workspace_root,
                stdio,
            ),
            .seatbelt => |*sb| try apply_posix.forkApplySeatbeltAndExec(
                sb.sbpl_z.ptr,
                argv_owned,
                env_map,
                workspace_root,
                stdio,
            ),
        };

        // Handshake proven: activate receipt from materials. Hard-fail after fork —
        // kill/reap so we never return a live agent without an active session receipt.
        const proof = self.activateAfterHandshake() catch {
            apply_posix.killAndReapChild(lease.pid);
            lease.deinit();
            return error.ApplyFailed;
        };
        const pid = lease.pid;
        self.spawn_lease = lease;
        return .{ .pid = pid, .proof = proof };
    }
};

/// Platform prepare outcome from Landlock/Seatbelt (parent seam only).
/// Parent seam never returns a live-session attach: only prepared_child materials
/// (or unavailable/failed). Session `active` requires child status-pipe + activate.
const PlatformApplyStatus = enum {
    /// Backend not present / not implemented for this build.
    unavailable,
    /// Backend present but prepare failed.
    failed,
    /// Profile prepared; agent child must apply before exec. Not active yet.
    prepared_child,
};

const PlatformApplyOutcome = struct {
    status: PlatformApplyStatus,
    mechanism: posture.BackendMechanism = .none,
    reason_code: []const u8,
    network_route_forced: bool = false,
    landlock_route_forcing: ?landlock.RouteForcing = null,
    /// Owned NUL-terminated SBPL when Seatbelt prepare succeeded. Free via `deinit`
    /// unless transferred with `takeSeatbeltSbpl`.
    seatbelt_sbpl_z: ?[:0]u8 = null,
    /// Allocator that owns `seatbelt_sbpl_z` when non-null.
    sbpl_allocator: ?std.mem.Allocator = null,
    /// Seatbelt residual grade for receipt honesty (macOS only).
    seatbelt_profile_grade: macos_profile.SeatbeltProfileGrade = macos_profile.SeatbeltProfileGrade.default_grade,

    pub fn deinit(self: *PlatformApplyOutcome) void {
        if (self.seatbelt_sbpl_z) |p| {
            if (self.sbpl_allocator) |a| a.free(p);
            self.seatbelt_sbpl_z = null;
            self.sbpl_allocator = null;
        }
    }

    /// Transfer SBPL ownership to the caller; `deinit` will not free it.
    pub fn takeSeatbeltSbpl(self: *PlatformApplyOutcome) ?[:0]u8 {
        const p = self.seatbelt_sbpl_z;
        self.seatbelt_sbpl_z = null;
        self.sbpl_allocator = null;
        return p;
    }
};

fn setFailReason(boundary: ApplyBoundary, reason: []const u8) void {
    if (boundary.fail_reason_out) |out| out.* = reason;
}

/// Pure: true when `path` is a macOS per-user `/var/folders/...` temp (not granted).
/// File-private — only used by attach rewrite tests in this module.
fn isUngrantedHostTmpdir(path: []const u8) bool {
    if (path.len == 0) return false;
    // macOS default TMPDIR shape: /var/folders/… or /private/var/folders/…
    if (std.mem.startsWith(u8, path, "/var/folders/")) return true;
    if (std.mem.startsWith(u8, path, "/private/var/folders/")) return true;
    return false;
}

const IsolatedToolCache = struct {
    env_key: []const u8,
    directory_name: []const u8,
};

/// Mutable caches used by common stdio MCP launchers. Every path is minted under
/// the workspace session temp; host caches under HOME remain outside the grant.
const isolated_tool_caches = [_]IsolatedToolCache{
    .{ .env_key = "NPM_CONFIG_CACHE", .directory_name = "npm-cache" },
    .{ .env_key = "UV_CACHE_DIR", .directory_name = "uv-cache" },
    .{ .env_key = "BUN_INSTALL_CACHE_DIR", .directory_name = "bun-cache" },
    .{ .env_key = "XDG_CACHE_HOME", .directory_name = "xdg-cache" },
    .{ .env_key = "PLAYWRIGHT_BROWSERS_PATH", .directory_name = "playwright-browsers" },
};

pub fn createFreshAttachTmp(
    io: std.Io,
    allocator: std.mem.Allocator,
    workspace_tmp: []const u8,
) error{ OutOfMemory, SessionTmpPrepareFailed }![]u8 {
    var random_bytes: [12]u8 = undefined;
    io.randomSecure(&random_bytes) catch return error.SessionTmpPrepareFailed;
    const suffix = std.fmt.bytesToHex(random_bytes, .lower);

    var attempt: u8 = 0;
    while (attempt < 8) : (attempt += 1) {
        const path = try std.fmt.allocPrint(
            allocator,
            "{s}/session-{s}-{d}",
            .{ workspace_tmp, suffix, attempt },
        );
        std.Io.Dir.createDirAbsolute(io, path, .default_dir) catch |err| switch (err) {
            error.PathAlreadyExists => {
                allocator.free(path);
                continue;
            },
            else => {
                allocator.free(path);
                return error.SessionTmpPrepareFailed;
            },
        };
        var opened = std.Io.Dir.openDirAbsolute(io, path, .{ .follow_symlinks = false }) catch {
            std.Io.Dir.cwd().deleteTree(io, path) catch {};
            allocator.free(path);
            return error.SessionTmpPrepareFailed;
        };
        opened.close(io);
        return path;
    }
    return error.SessionTmpPrepareFailed;
}

fn applyIsolatedToolCaches(
    io: std.Io,
    allocator: std.mem.Allocator,
    env_map: *std.process.Environ.Map,
    session_root: []const u8,
) error{ OutOfMemory, SessionTmpPrepareFailed }!void {
    for (isolated_tool_caches) |cache| {
        const path = try std.fs.path.join(allocator, &.{ session_root, cache.directory_name });
        defer allocator.free(path);
        std.Io.Dir.createDirAbsolute(io, path, .default_dir) catch
            return error.SessionTmpPrepareFailed;
        try env_map.put(cache.env_key, path);
    }
}

fn applyIsolatedGitConfig(env_map: *std.process.Environ.Map) error{OutOfMemory}!void {
    try env_map.put("GIT_CONFIG_GLOBAL", "/dev/null");
    try env_map.put("GIT_CONFIG_COUNT", "1");
    try env_map.put("GIT_CONFIG_KEY_0", "core.excludesFile");
    try env_map.put("GIT_CONFIG_VALUE_0", "/dev/null");
}

/// Prepare temp, tool-cache, and Git environment for the attach path.
///
/// Host macOS TMPDIR under `/var/folders` is intentionally not granted (canary breadth).
/// Prefer a fresh child of `{workspace}/.ryk-tmp` so package-manager caches
/// cannot consume state planted by an earlier agent launch.
///
/// Production defaults keep `include_tmp=false` (no classic `/tmp` RW grant). Do **not**
/// silently rewrite to classic `/tmp` when session temp cannot be prepared — that path
/// is agent-unwritable under the sandbox and misleads operators. Fail closed instead
/// (`error.SessionTmpPrepareFailed`); callers map to `session_tmp_prepare_failed`.
///
/// Mutates `env_map` in place only on success. Returns ownership of the fresh
/// session temp; the caller must retain it for the launch and call `deinit`.
pub fn prepareAttachEnvironment(
    allocator: std.mem.Allocator,
    env_map: *std.process.Environ.Map,
    workspace_root: []const u8,
) error{ OutOfMemory, SessionTmpPrepareFailed }!AttachSessionTmp {
    const workspace_tmp = try workspaceSessionTmpPath(allocator, workspace_root);
    defer allocator.free(workspace_tmp);

    // Create session surface first (shared with Landlock expand precreate).
    // Fail closed: production materials require session tmp under workspace RW.
    if (!ensureWorkspaceSessionTmp(workspace_root)) return error.SessionTmpPrepareFailed;

    var io_rt: std.Io.Threaded = .init_single_threaded;
    const io = io_rt.io();
    const preferred = try createFreshAttachTmp(io, allocator, workspace_tmp);
    var attach_tmp: AttachSessionTmp = .{ .allocator = allocator, .path = preferred };
    errdefer attach_tmp.deinit();

    // Claude parent-walks the tmp base with lstat (nofollow). If the workspace
    // path is a symlink, mint the realpath so the string Claude checks has no
    // symlink ancestors. Fail closed if the canonical path is not a real dir.
    var real_buf: [std.fs.max_path_bytes]u8 = undefined;
    if (realpathInto(io, attach_tmp.path, &real_buf)) |real| {
        if (!claudeCodeTmpAccepts(real)) return error.SessionTmpPrepareFailed;
        if (!std.mem.eql(u8, real, attach_tmp.path)) {
            const owned = try allocator.dupe(u8, real);
            allocator.free(attach_tmp.path);
            attach_tmp.path = owned;
        }
    }
    const minted = attach_tmp.path;
    if (!claudeCodeTmpAccepts(minted)) return error.SessionTmpPrepareFailed;

    var staged = try env_map.clone(env_map.allocator);
    defer staged.deinit();
    try applyIsolatedToolCaches(io, allocator, &staged, minted);

    try staged.put("TMPDIR", minted);
    try staged.put("TMP", minted);
    try staged.put("TEMP", minted);
    // Claude Code `lstat`s `{CLAUDE_CODE_TMPDIR|TMPDIR}/claude-{uid}` and refuses
    // a missing path or attacker-planted symlink. Mint the env to the verified
    // canonical session temp and pre-create the leaf as a real directory.
    if (!ensureClaudeCodeTmpLeaves(minted)) return error.SessionTmpPrepareFailed;
    try staged.put(claude_code_tmpdir_env, minted);

    // Host-global Git configuration can contain credentials and remains denied.
    // Point Git at inert global config/ignore files so ordinary repository probes
    // do not turn that deliberate denial into a fatal startup error.
    try applyIsolatedGitConfig(&staged);

    std.mem.swap(std.process.Environ.Map, env_map, &staged);
    return attach_tmp;
}

/// Resolve argv0 into narrow absolute **file** paths for `.exec` profile grants.
///
/// Returns an owned slice of owned path strings (caller frees each path, then the slice).
/// Empty slice when argv0 cannot be resolved or is not a regular file — never invents grants.
///
/// Always includes the lexical absolute path used for exec and, when different, the
/// realpath target (symlink → install tree). When the launch file is a shebang script,
/// also grants the shebang interpreter (absolute path, or PATH-resolved name from
/// `#!/usr/bin/env NAME` / minimal `env -S`) through the same file-only filters.
/// Rejects filesystem root and `$HOME` itself so Seatbelt `subpath` cannot open the
/// whole home tree. Does not recurse into nested scripts.
pub fn collectLaunchExecPaths(
    io: std.Io,
    allocator: std.mem.Allocator,
    argv0: []const u8,
    env_map: ?*const std.process.Environ.Map,
) error{OutOfMemory}![]const []const u8 {
    if (argv0.len == 0) return try allocator.alloc([]const u8, 0);

    const resolved = apply_posix.resolveArgv0(io, allocator, argv0, env_map) catch {
        return try allocator.alloc([]const u8, 0);
    };
    defer if (resolved.owned) allocator.free(resolved.path);

    const abs = try absolutePathForGrant(io, allocator, resolved.path);
    defer allocator.free(abs);

    var list: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (list.items) |p| allocator.free(p);
        list.deinit(allocator);
    }

    try appendLaunchExecCandidate(io, allocator, &list, abs, env_map);

    // Symlink target when different (e.g. ~/.local/bin/claude → versions/N).
    var real_buf: [std.fs.max_path_bytes]u8 = undefined;
    if (realpathInto(io, abs, &real_buf)) |real| {
        if (!std.mem.eql(u8, real, abs)) {
            try appendLaunchExecCandidate(io, allocator, &list, real, env_map);
        }
    }

    // Shebang interpreter of the launch file only (not nested scripts).
    try appendShebangInterpreterGrants(io, allocator, &list, abs, env_map);

    // Shell wrappers often `exec /abs/path/to/python …` (hermes → uv cpython).
    // Shebang alone grants bash; nested absolute targets need file-only .exec too.
    try appendShellWrapperNestedExecTargets(io, allocator, &list, abs, env_map);

    return try list.toOwnedSlice(allocator);
}

/// Free the slice returned by `collectLaunchExecPaths`.
pub fn freeLaunchExecPaths(allocator: std.mem.Allocator, paths: []const []const u8) void {
    for (paths) |p| allocator.free(p);
    allocator.free(paths);
}

/// Collect narrow **read-only install trees** for Node/npm-style launch agents.
///
/// Empty-backpack grants `.exec` only on the shebang script file + interpreter.
/// Node then loads sibling package files and nested optional deps (e.g.
/// `@openai/codex` → `node_modules/@openai/codex-darwin-arm64/vendor/...`).
/// Without a package-root RO subpath, realpath of the entry works but the agent
/// dies on missing nested package content (often misread as path-walk EPERM).
///
/// For each resolved launch file, walk parents for a `package.json` directory
/// and grant that directory as RO (includes nested deps + vendor binaries).
/// Never returns bare `$HOME` or `/`. Empty when argv0 is a plain binary with
/// no package root (file-only `.exec` is enough).
///
/// Caller frees with `freeLaunchInstallRoPaths` (same shape as exec paths).
pub fn collectLaunchInstallRoPaths(
    io: std.Io,
    allocator: std.mem.Allocator,
    argv0: []const u8,
    env_map: ?*const std.process.Environ.Map,
) error{OutOfMemory}![]const []const u8 {
    if (argv0.len == 0) return try allocator.alloc([]const u8, 0);

    const resolved = apply_posix.resolveArgv0(io, allocator, argv0, env_map) catch {
        return try allocator.alloc([]const u8, 0);
    };
    defer if (resolved.owned) allocator.free(resolved.path);

    const abs = try absolutePathForGrant(io, allocator, resolved.path);
    defer allocator.free(abs);

    var list: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (list.items) |p| allocator.free(p);
        list.deinit(allocator);
    }

    try appendInstallRoForLaunchFile(io, allocator, &list, abs, env_map);

    var real_buf: [std.fs.max_path_bytes]u8 = undefined;
    if (realpathInto(io, abs, &real_buf)) |real| {
        if (!std.mem.eql(u8, real, abs)) {
            try appendInstallRoForLaunchFile(io, allocator, &list, real, env_map);
        }
    }

    // #!/usr/bin/env node (and peers): grant interpreter install root
    // (e.g. ~/.hermes/node) so the runtime can load prefix data under Seatbelt.
    try appendShebangInterpreterInstallRo(io, allocator, &list, abs, env_map);

    // Shell wrappers (e.g. hermes → venv python outside the wrapper path) need
    // install RO on nested absolute targets + their bin-layout roots (uv cpython).
    try appendShellWrapperNestedInstallRo(io, allocator, &list, abs, env_map);

    return try list.toOwnedSlice(allocator);
}

/// Free the slice returned by `collectLaunchInstallRoPaths` (same shape as exec paths).
pub const freeLaunchInstallRoPaths = freeLaunchExecPaths;

/// Dupe `arg` then append. On append OOM, free the dupe so it never leaks.
fn appendOwnedArg(
    allocator: std.mem.Allocator,
    list: *std.ArrayList([]const u8),
    arg: []const u8,
) error{OutOfMemory}!void {
    const owned = try allocator.dupe(u8, arg);
    errdefer allocator.free(owned);
    try list.append(allocator, owned);
}

/// Optional argv rewrite for shell wrappers that `exec /abs/interp /abs/main …`.
///
/// Seatbelt on macOS denies following a symlink under a host-config grant when the
/// target lives outside that grant (even if the target is separately RO-granted).
/// Hermes does `exec venv/bin/python → uv cpython`; open/exec of the **symlink path**
/// fails, while exec of the realpath succeeds. Rewrite launch to realpath so the
/// agent binary runs past attach.
///
/// When the lexical interpreter is a venv `…/bin/python`, also injects `PYTHONPATH`
/// to that venv's `site-packages` (host wrappers often `unset PYTHONPATH` then exec
/// the symlink; realpath loses venv site discovery via argv0). Injection runs on
/// the **mutable** child env after scrub/allowlist so the path is ryk-owned.
///
/// Returns null when argv0 is not a shell wrapper with nested absolute targets
/// (caller keeps original argv). On success, returns an owned argv slice; caller
/// frees with `freeExpandedShellWrapperArgv`.
pub fn expandShellWrapperLaunch(
    io: std.Io,
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    env_map: ?*std.process.Environ.Map,
) error{OutOfMemory}!?[]const []const u8 {
    if (argv.len == 0) return null;
    const argv0 = argv[0];
    if (argv0.len == 0) return null;

    const env_const: ?*const std.process.Environ.Map = env_map;
    const resolved = apply_posix.resolveArgv0(io, allocator, argv0, env_const) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return null,
    };
    defer if (resolved.owned) allocator.free(resolved.path);
    const abs = try absolutePathForGrant(io, allocator, resolved.path);
    defer allocator.free(abs);

    if (!(try launchFileIsShellWrapper(io, allocator, abs, env_const))) return null;

    var targets: [wrapper_nested_target_max][]const u8 = undefined;
    const n = try collectShellWrapperAbsoluteTargets(io, allocator, abs, env_const, &targets);
    defer for (targets[0..n]) |t| allocator.free(t);
    if (n == 0) return null;

    // Primary interpreter = first nested absolute path (realpath preferred for exec).
    var real_buf: [std.fs.max_path_bytes]u8 = undefined;
    const interp: []const u8 = if (realpathInto(io, targets[0], &real_buf)) |real| real else targets[0];

    // Venv residual: realpath loses site-packages; inject ryk-owned PYTHONPATH.
    if (env_map) |map| {
        try injectVenvSitePackagesPythonPath(io, allocator, map, targets[0]);
    }

    // Build: [interp_real, other nested targets…, original args after argv0]
    var list: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (list.items) |p| allocator.free(p);
        list.deinit(allocator);
    }
    try appendOwnedArg(allocator, &list, interp);
    var i: usize = 1;
    while (i < n) : (i += 1) {
        // Prefer realpath for each nested file path (same symlink residual).
        if (realpathInto(io, targets[i], &real_buf)) |real| {
            try appendOwnedArg(allocator, &list, real);
        } else {
            try appendOwnedArg(allocator, &list, targets[i]);
        }
    }
    for (argv[1..]) |arg| {
        try appendOwnedArg(allocator, &list, arg);
    }
    return try list.toOwnedSlice(allocator);
}

/// Free owned launch argv from `expandShellWrapperLaunch` or `absoluteizeLaunchArgv`.
pub const freeExpandedShellWrapperArgv = freeLaunchExecPaths;

/// Rewrite `argv0` scripts with a non-shell shebang into `[abs_interp, abs_script, …]`.
///
/// Under Seatbelt, `#!/usr/bin/env node` still PATH-searches for `node`. Host
/// package dirs are not content-readable for PATH discovery, so env fails even
/// when the interpreter was already collected as a file-only `.exec` grant.
/// Expanding to absolute interpreter + script avoids that residual (codex/npm
/// agents). Shell wrappers stay on `expandShellWrapperLaunch`.
///
/// Returns null when argv0 is not an env/absolute non-shell shebang script.
/// On success, caller frees with `freeExpandedShellWrapperArgv`.
pub fn expandEnvShebangLaunch(
    io: std.Io,
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    env_map: ?*const std.process.Environ.Map,
) error{OutOfMemory}!?[]const []const u8 {
    if (argv.len == 0) return null;
    const argv0 = argv[0];
    if (argv0.len == 0) return null;

    const resolved = apply_posix.resolveArgv0(io, allocator, argv0, env_map) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return null,
    };
    defer if (resolved.owned) allocator.free(resolved.path);
    const script_abs = try absolutePathForGrant(io, allocator, resolved.path);
    defer allocator.free(script_abs);
    if (script_abs.len == 0) return null;

    // Shell wrappers have their own expander; leave them alone.
    if (try launchFileIsShellWrapper(io, allocator, script_abs, env_map)) return null;

    const interp_token = (try readShebangInterpreterToken(io, allocator, script_abs)) orelse return null;
    defer allocator.free(interp_token);
    // Already an absolute interpreter shebang (#!/usr/bin/node) still needs the
    // interp as argv0 so Seatbelt does not rely on kernel shebang + PATH.
    const interp_resolved = apply_posix.resolveArgv0(io, allocator, interp_token, env_map) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return null,
    };
    defer if (interp_resolved.owned) allocator.free(interp_resolved.path);
    const interp_abs = try absolutePathForGrant(io, allocator, interp_resolved.path);
    defer allocator.free(interp_abs);
    if (interp_abs.len == 0 or !isRegularFile(io, interp_abs)) return null;

    var list: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (list.items) |p| allocator.free(p);
        list.deinit(allocator);
    }
    var real_buf: [std.fs.max_path_bytes]u8 = undefined;
    if (realpathInto(io, interp_abs, &real_buf)) |real| {
        try appendOwnedArg(allocator, &list, real);
    } else {
        try appendOwnedArg(allocator, &list, interp_abs);
    }
    if (realpathInto(io, script_abs, &real_buf)) |real| {
        try appendOwnedArg(allocator, &list, real);
    } else {
        try appendOwnedArg(allocator, &list, script_abs);
    }
    for (argv[1..]) |arg| {
        try appendOwnedArg(allocator, &list, arg);
    }
    return try list.toOwnedSlice(allocator);
}

/// Resolve bare argv0 to an absolute path **before** PATH honesty filtering.
///
/// Under OS attach, `tool_pack.applyPathFilterToEnv` drops ungranted package trees
/// (e.g. `/opt/homebrew/bin`). Spawn re-resolves argv0 against the filtered child
/// PATH, so bare host-alias names like `pi` / `opencode` fail with CommandNotFound
/// even though grant collection already found them on the pre-filter PATH.
///
/// Call this while the child env still has the full host PATH (before the filter).
/// Returns null when argv0 is already absolute, contains a path separator, is empty,
/// or cannot be resolved (caller keeps the original argv; spawn surfaces not-found).
/// On success, returns an owned argv slice (absolute argv0 + duped tail); free with
/// `freeExpandedShellWrapperArgv`.
pub fn absoluteizeLaunchArgv(
    io: std.Io,
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    env_map: ?*const std.process.Environ.Map,
) error{OutOfMemory}!?[]const []const u8 {
    if (argv.len == 0) return null;
    const argv0 = argv[0];
    if (argv0.len == 0) return null;
    if (std.fs.path.isAbsolute(argv0)) return null;
    // Relative with a separator: leave for cwd-relative exec semantics.
    if (std.mem.indexOfScalar(u8, argv0, '/') != null) return null;

    const resolved = apply_posix.resolveArgv0(io, allocator, argv0, env_map) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return null,
    };
    defer if (resolved.owned) allocator.free(resolved.path);
    if (!std.fs.path.isAbsolute(resolved.path)) return null;
    // Already the same absolute string (shouldn't happen for bare names).
    if (std.mem.eql(u8, resolved.path, argv0)) return null;

    var list: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (list.items) |p| allocator.free(p);
        list.deinit(allocator);
    }
    try appendOwnedArg(allocator, &list, resolved.path);
    for (argv[1..]) |arg| {
        try appendOwnedArg(allocator, &list, arg);
    }
    return try list.toOwnedSlice(allocator);
}

/// Which launch rewrites to apply before spawn / PATH honesty.
///
/// `expand_shell_wrapper` is empty-backpack only (Hermes venv symlink residual).
/// `os_attach` is any planned OS attach, including host MCP plans that keep a
/// bare host name (`pi`). Codex MCP expands itself and should not set the
/// shell-wrapper bit.
pub const LaunchArgvRewrite = struct {
    expand_shell_wrapper: bool = false,
    os_attach: bool = false,
};

/// Rewrite child argv before OS attach.
///
/// Order: shell-wrapper realpath → env/non-shell shebang (`#!/usr/bin/env node`)
/// → absoluteize remaining bare argv0. Returns null when no rewrite applies
/// (caller keeps the original argv). On success, caller frees with
/// `freeExpandedShellWrapperArgv`.
///
/// OutOfMemory is propagated so inventory can fail closed; the product spawn
/// path may still fail-open (`catch null`) and let exec surface not-found.
pub fn rewriteOsAttachLaunchArgv(
    io: std.Io,
    allocator: std.mem.Allocator,
    planned_argv: []const []const u8,
    env_map: ?*std.process.Environ.Map,
    opts: LaunchArgvRewrite,
) error{OutOfMemory}!?[]const []const u8 {
    if (planned_argv.len == 0) return null;
    if (!opts.expand_shell_wrapper and !opts.os_attach) return null;

    var owned: ?[]const []const u8 = null;
    errdefer if (owned) |a| freeExpandedShellWrapperArgv(allocator, a);

    if (opts.expand_shell_wrapper) {
        owned = try expandShellWrapperLaunch(io, allocator, planned_argv, env_map);
    }

    if (opts.os_attach) {
        const env_const: ?*const std.process.Environ.Map = env_map;
        const after_shell: []const []const u8 = owned orelse planned_argv;
        if (try expandEnvShebangLaunch(io, allocator, after_shell, env_const)) |expanded| {
            if (owned) |old| freeExpandedShellWrapperArgv(allocator, old);
            owned = expanded;
        }

        const after_shebang: []const []const u8 = owned orelse planned_argv;
        if (try absoluteizeLaunchArgv(io, allocator, after_shebang, env_const)) |absolute| {
            if (owned) |old| freeExpandedShellWrapperArgv(allocator, old);
            owned = absolute;
        }
    }
    return owned;
}

/// If `python_path` is `…/bin/python*`, locate `…/lib/python*/site-packages` and
/// put it into `PYTHONPATH` on `env_map` (owned by the map). No-op when layout
/// does not match or site-packages is missing.
fn injectVenvSitePackagesPythonPath(
    io: std.Io,
    allocator: std.mem.Allocator,
    env_map: *std.process.Environ.Map,
    python_path: []const u8,
) error{OutOfMemory}!void {
    if (python_path.len == 0 or !std.fs.path.isAbsolute(python_path)) return;
    const bin_dir = std.fs.path.dirname(python_path) orelse return;
    if (!std.mem.eql(u8, std.fs.path.basename(bin_dir), "bin")) return;
    const venv_root = std.fs.path.dirname(bin_dir) orelse return;
    if (venv_root.len <= 1) return;

    const lib_dir = try std.fs.path.join(allocator, &.{ venv_root, "lib" });
    defer allocator.free(lib_dir);

    var lib_it = std.Io.Dir.cwd().openDir(io, lib_dir, .{ .iterate = true }) catch return;
    defer lib_it.close(io);

    var site: ?[]u8 = null;
    errdefer if (site) |s| allocator.free(s);
    var walker = lib_it.iterate();
    while (walker.next(io) catch null) |entry| {
        if (entry.kind != .directory) continue;
        if (!std.mem.startsWith(u8, entry.name, "python")) continue;
        const candidate = try std.fs.path.join(allocator, &.{ lib_dir, entry.name, "site-packages" });
        errdefer allocator.free(candidate);
        if (!isDir(io, candidate)) {
            allocator.free(candidate);
            continue;
        }
        // Prefer the first matching pythonX.Y site-packages.
        if (site) |old| allocator.free(old);
        site = candidate;
        break;
    }
    const site_path = site orelse return;
    // Map.put copies the value; free our temporary after insert.
    try env_map.put("PYTHONPATH", site_path);
    allocator.free(site_path);
}

fn isDir(io: std.Io, path: []const u8) bool {
    if (path.len == 0) return false;
    if (std.fs.path.isAbsolute(path)) {
        var dir = std.Io.Dir.openDirAbsolute(io, path, .{}) catch return false;
        dir.close(io);
        return true;
    }
    var dir = std.Io.Dir.cwd().openDir(io, path, .{}) catch return false;
    dir.close(io);
    return true;
}

fn appendInstallRoForLaunchFile(
    io: std.Io,
    allocator: std.mem.Allocator,
    list: *std.ArrayList([]const u8),
    path: []const u8,
    env_map: ?*const std.process.Environ.Map,
) error{OutOfMemory}!void {
    if (path.len == 0) return;
    if (!isRegularFile(io, path)) return;

    const root = (try findPackageRootForFile(io, allocator, path, env_map)) orelse return;
    // Own `root` until transfer into `list`. Do not leave a bare errdefer after
    // appendUniqueInstallRo — that helper takes ownership (or frees on dedup).

    if (envHome(env_map)) |home| {
        if (std.mem.eql(u8, root, home)) {
            allocator.free(root);
            return;
        }
    }
    if (root.len == 1 and root[0] == '/') {
        allocator.free(root);
        return;
    }

    // npm optional deps often live as *siblings* under the same scope dir
    // (`node_modules/@openai/codex` + `node_modules/@openai/codex-darwin-arm64`).
    // Nested `package/node_modules/...` is already covered by package-root RO;
    // grant the scoped parent (`…/node_modules/@scope`) when the layout matches.
    // Resolve while we still own `root` (before transfer).
    const scope_parent = scopedNpmParentRo(allocator, root, env_map) catch |err| {
        allocator.free(root);
        return err;
    };

    var root_live = true;
    errdefer if (root_live) allocator.free(root);
    var scope_live = scope_parent != null;
    errdefer if (scope_live) if (scope_parent) |sp| allocator.free(sp);

    // Transfer ownership *before* the call: appendUniqueInstallRo frees on
    // OOM and on dedup, so caller must not also free after the call starts.
    root_live = false;
    try appendUniqueInstallRo(allocator, list, root);

    if (scope_parent) |sp| {
        scope_live = false;
        try appendUniqueInstallRo(allocator, list, sp);
    }
}

/// Takes ownership of `path`: appends if unique, frees if duplicate or on OOM.
fn appendUniqueInstallRo(
    allocator: std.mem.Allocator,
    list: *std.ArrayList([]const u8),
    path: []u8,
) error{OutOfMemory}!void {
    errdefer allocator.free(path);
    for (list.items) |existing| {
        if (std.mem.eql(u8, existing, path)) {
            allocator.free(path);
            return;
        }
    }
    try list.append(allocator, path);
}

/// If `package_root` is `…/node_modules/@scope/pkg`, return owned `…/node_modules/@scope`.
/// Otherwise null. Never bare HOME or filesystem root.
fn scopedNpmParentRo(
    allocator: std.mem.Allocator,
    package_root: []const u8,
    env_map: ?*const std.process.Environ.Map,
) error{OutOfMemory}!?[]u8 {
    const pkg_name = std.fs.path.basename(package_root);
    if (pkg_name.len == 0 or pkg_name[0] == '@') return null; // already a scope dir
    const scope_dir = std.fs.path.dirname(package_root) orelse return null;
    const scope_name = std.fs.path.basename(scope_dir);
    if (scope_name.len < 2 or scope_name[0] != '@') return null;
    const nm = std.fs.path.dirname(scope_dir) orelse return null;
    if (!std.mem.eql(u8, std.fs.path.basename(nm), "node_modules")) return null;
    if (envHome(env_map)) |home| {
        if (std.mem.eql(u8, scope_dir, home)) return null;
    }
    if (scope_dir.len <= 1) return null;
    return try allocator.dupe(u8, scope_dir);
}

/// Walk parents of `file_path` for a directory containing `package.json`.
/// Caps walk depth; refuses bare HOME and filesystem root.
fn findPackageRootForFile(
    io: std.Io,
    allocator: std.mem.Allocator,
    file_path: []const u8,
    env_map: ?*const std.process.Environ.Map,
) error{OutOfMemory}!?[]u8 {
    if (!std.fs.path.isAbsolute(file_path)) return null;
    var dir = std.fs.path.dirname(file_path) orelse return null;
    const home = envHome(env_map);
    var depth: usize = 0;
    const max_depth: usize = 24;
    while (depth < max_depth) : (depth += 1) {
        if (dir.len <= 1) return null;
        if (home) |h| {
            if (std.mem.eql(u8, dir, h)) return null;
        }
        const pkg_json = try std.fs.path.join(allocator, &.{ dir, "package.json" });
        defer allocator.free(pkg_json);
        if (isRegularFile(io, pkg_json)) {
            return try allocator.dupe(u8, dir);
        }
        dir = std.fs.path.dirname(dir) orelse return null;
    }
    return null;
}

/// Make `path` absolute for grant emission. Absolute inputs are duped as-is.
/// Relative paths join a proven cwd (realpath, else quiet getcwd). When no
/// absolute base can be proven, returns an empty owned string so callers skip
/// the grant — never invents root-absolute `/{path}`.
fn absolutePathForGrant(io: std.Io, allocator: std.mem.Allocator, path: []const u8) error{OutOfMemory}![]u8 {
    if (std.fs.path.isAbsolute(path)) {
        return allocator.dupe(u8, path) catch return error.OutOfMemory;
    }
    if (std.Io.Dir.cwd().realPathFileAlloc(io, ".", allocator)) |cwd| {
        defer allocator.free(cwd);
        return std.fs.path.join(allocator, &.{ cwd, path }) catch return error.OutOfMemory;
    } else |_| {}
    // realpath failed (e.g. Seatbelt EPERM): try process getcwd without inventing `/rel`.
    if (builtin.os.tag != .windows) {
        var buf: [std.posix.PATH_MAX]u8 = undefined;
        if (std.c.getcwd(&buf, buf.len)) |rc| {
            const cwd = std.mem.sliceTo(rc, 0);
            if (std.fs.path.isAbsolute(cwd)) {
                return std.fs.path.join(allocator, &.{ cwd, path }) catch return error.OutOfMemory;
            }
        }
    }
    // Unproven absolute form — empty skip (callers treat len==0 as no grant).
    return allocator.dupe(u8, "") catch return error.OutOfMemory;
}

fn realpathInto(io: std.Io, path: []const u8, out: *[std.fs.max_path_bytes]u8) ?[]const u8 {
    if (path.len == 0 or path.len >= std.fs.max_path_bytes) return null;
    const n = std.Io.Dir.cwd().realPathFile(io, path, out[0..]) catch return null;
    return out[0..n];
}

fn appendLaunchExecCandidate(
    io: std.Io,
    allocator: std.mem.Allocator,
    list: *std.ArrayList([]const u8),
    path: []const u8,
    env_map: ?*const std.process.Environ.Map,
) error{OutOfMemory}!void {
    if (path.len == 0) return;
    if (path.len == 1 and path[0] == '/') return;
    // Never grant bare $HOME (Seatbelt subpath would open the whole tree).
    if (envHome(env_map)) |home| {
        if (std.mem.eql(u8, path, home)) return;
    }
    // Regular files only — directory exec grants would subpath-open entire trees.
    if (!isRegularFile(io, path)) return;

    for (list.items) |existing| {
        if (std.mem.eql(u8, existing, path)) return;
    }
    const owned = try allocator.dupe(u8, path);
    errdefer allocator.free(owned);
    try list.append(allocator, owned);
}

/// Max bytes scanned at the start of a launch file for a shebang line.
const shebang_scan_max: usize = 512;

/// If `script_path` begins with `#!`, resolve the interpreter and append file-only
/// `.exec` candidates (lexical + realpath). Unreadable / non-script / unparseable → no-op.
fn appendShebangInterpreterGrants(
    io: std.Io,
    allocator: std.mem.Allocator,
    list: *std.ArrayList([]const u8),
    script_path: []const u8,
    env_map: ?*const std.process.Environ.Map,
) error{OutOfMemory}!void {
    const interp_token = (try readShebangInterpreterToken(io, allocator, script_path)) orelse return;
    defer allocator.free(interp_token);

    const resolved = apply_posix.resolveArgv0(io, allocator, interp_token, env_map) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return,
    };
    defer if (resolved.owned) allocator.free(resolved.path);

    const abs = try absolutePathForGrant(io, allocator, resolved.path);
    defer allocator.free(abs);

    try appendLaunchExecCandidate(io, allocator, list, abs, env_map);

    var real_buf: [std.fs.max_path_bytes]u8 = undefined;
    if (realpathInto(io, abs, &real_buf)) |real| {
        if (!std.mem.eql(u8, real, abs)) {
            try appendLaunchExecCandidate(io, allocator, list, real, env_map);
        }
    }
}

/// Grant install RO for a shebang interpreter (`…/bin/node` → `…` prefix tree).
/// Complements package-root RO on the script itself; needed when Node lives outside
/// system paths (nvm, hermes, fnm) and loads prefix-relative data under Seatbelt.
fn appendShebangInterpreterInstallRo(
    io: std.Io,
    allocator: std.mem.Allocator,
    list: *std.ArrayList([]const u8),
    script_path: []const u8,
    env_map: ?*const std.process.Environ.Map,
) error{OutOfMemory}!void {
    const interp_token = (try readShebangInterpreterToken(io, allocator, script_path)) orelse return;
    defer allocator.free(interp_token);

    const resolved = apply_posix.resolveArgv0(io, allocator, interp_token, env_map) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return,
    };
    defer if (resolved.owned) allocator.free(resolved.path);

    const abs = try absolutePathForGrant(io, allocator, resolved.path);
    defer allocator.free(abs);

    try appendInstallRoForLaunchFile(io, allocator, list, abs, env_map);
    try appendBinLayoutInstallRo(io, allocator, list, abs, env_map);

    var real_buf: [std.fs.max_path_bytes]u8 = undefined;
    if (realpathInto(io, abs, &real_buf)) |real| {
        if (!std.mem.eql(u8, real, abs)) {
            try appendInstallRoForLaunchFile(io, allocator, list, real, env_map);
            try appendBinLayoutInstallRo(io, allocator, list, real, env_map);
        }
    }
}

/// Max body bytes scanned in a shell wrapper for nested absolute exec targets.
const wrapper_body_scan_max: usize = 4096;
/// Cap nested absolute targets per wrapper (avoid pathological scripts).
const wrapper_nested_target_max: usize = 8;

fn isShellInterpreterBasename(name: []const u8) bool {
    return std.mem.eql(u8, name, "sh") or
        std.mem.eql(u8, name, "bash") or
        std.mem.eql(u8, name, "zsh") or
        std.mem.eql(u8, name, "dash");
}

/// True when shebang of `script_path` resolves to a shell (sh/bash/zsh/dash).
fn launchFileIsShellWrapper(
    io: std.Io,
    allocator: std.mem.Allocator,
    script_path: []const u8,
    env_map: ?*const std.process.Environ.Map,
) error{OutOfMemory}!bool {
    const interp_token = (try readShebangInterpreterToken(io, allocator, script_path)) orelse return false;
    defer allocator.free(interp_token);
    const base = std.fs.path.basename(interp_token);
    if (isShellInterpreterBasename(base)) return true;
    // `#!/usr/bin/env bash` → token is bare `bash`.
    if (std.mem.indexOfScalar(u8, interp_token, '/') == null and isShellInterpreterBasename(interp_token))
        return true;
    // Resolved absolute path basename.
    const resolved = apply_posix.resolveArgv0(io, allocator, interp_token, env_map) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return false,
    };
    defer if (resolved.owned) allocator.free(resolved.path);
    return isShellInterpreterBasename(std.fs.path.basename(resolved.path));
}

/// Append file-only `.exec` for absolute nested targets in a shell wrapper body
/// (`exec "/abs/python" …`). Also grants realpath when different.
fn appendShellWrapperNestedExecTargets(
    io: std.Io,
    allocator: std.mem.Allocator,
    list: *std.ArrayList([]const u8),
    script_path: []const u8,
    env_map: ?*const std.process.Environ.Map,
) error{OutOfMemory}!void {
    if (!(try launchFileIsShellWrapper(io, allocator, script_path, env_map))) return;

    var targets: [wrapper_nested_target_max][]const u8 = undefined;
    const n = try collectShellWrapperAbsoluteTargets(io, allocator, script_path, env_map, &targets);
    defer for (targets[0..n]) |t| allocator.free(t);

    for (targets[0..n]) |target| {
        try appendLaunchExecCandidate(io, allocator, list, target, env_map);
        var real_buf: [std.fs.max_path_bytes]u8 = undefined;
        if (realpathInto(io, target, &real_buf)) |real| {
            if (!std.mem.eql(u8, real, target)) {
                try appendLaunchExecCandidate(io, allocator, list, real, env_map);
            }
        }
    }
}

/// Append install RO for nested absolute targets + bin-layout install roots
/// (e.g. `…/cpython-3.11…/bin/python3.11` → RO `…/cpython-3.11…` for libpython).
fn appendShellWrapperNestedInstallRo(
    io: std.Io,
    allocator: std.mem.Allocator,
    list: *std.ArrayList([]const u8),
    script_path: []const u8,
    env_map: ?*const std.process.Environ.Map,
) error{OutOfMemory}!void {
    if (!(try launchFileIsShellWrapper(io, allocator, script_path, env_map))) return;

    var targets: [wrapper_nested_target_max][]const u8 = undefined;
    const n = try collectShellWrapperAbsoluteTargets(io, allocator, script_path, env_map, &targets);
    defer for (targets[0..n]) |t| allocator.free(t);

    for (targets[0..n]) |target| {
        try appendInstallRoForLaunchFile(io, allocator, list, target, env_map);
        try appendBinLayoutInstallRo(io, allocator, list, target, env_map);
        var real_buf: [std.fs.max_path_bytes]u8 = undefined;
        if (realpathInto(io, target, &real_buf)) |real| {
            if (!std.mem.eql(u8, real, target)) {
                try appendInstallRoForLaunchFile(io, allocator, list, real, env_map);
                try appendBinLayoutInstallRo(io, allocator, list, real, env_map);
            }
        }
    }
}

/// If `file_path` is `…/bin/<leaf>`, grant RO on the parent of `bin` (install root).
/// Never bare HOME or `/`. Used for uv/cpython and similar layouts without package.json.
fn appendBinLayoutInstallRo(
    io: std.Io,
    allocator: std.mem.Allocator,
    list: *std.ArrayList([]const u8),
    file_path: []const u8,
    env_map: ?*const std.process.Environ.Map,
) error{OutOfMemory}!void {
    _ = io;
    if (file_path.len == 0 or !std.fs.path.isAbsolute(file_path)) return;
    const bin_dir = std.fs.path.dirname(file_path) orelse return;
    if (!std.mem.eql(u8, std.fs.path.basename(bin_dir), "bin")) return;
    const install_root = std.fs.path.dirname(bin_dir) orelse return;
    if (install_root.len <= 1) return;
    if (envHome(env_map)) |home| {
        if (std.mem.eql(u8, install_root, home)) return;
    }
    const owned = try allocator.dupe(u8, install_root);
    try appendUniqueInstallRo(allocator, list, owned);
}

/// Scan a shell wrapper body for absolute path strings that are existing regular files.
/// Returns count of owned paths written into `out` (caller frees each).
fn collectShellWrapperAbsoluteTargets(
    io: std.Io,
    allocator: std.mem.Allocator,
    script_path: []const u8,
    env_map: ?*const std.process.Environ.Map,
    out: *[wrapper_nested_target_max][]const u8,
) error{OutOfMemory}!usize {
    if (script_path.len == 0 or !isRegularFile(io, script_path)) return 0;

    var buf: [wrapper_body_scan_max]u8 = undefined;
    const n: usize = blk: {
        if (std.fs.path.isAbsolute(script_path)) {
            const file = std.Io.Dir.openFileAbsolute(io, script_path, .{}) catch return 0;
            defer file.close(io);
            break :blk std.Io.File.readStreaming(file, io, &.{buf[0..]}) catch return 0;
        }
        const file = std.Io.Dir.cwd().openFile(io, script_path, .{}) catch return 0;
        defer file.close(io);
        break :blk std.Io.File.readStreaming(file, io, &.{buf[0..]}) catch return 0;
    };
    if (n == 0) return 0;

    const body = buf[0..n];
    var count: usize = 0;
    errdefer {
        for (out[0..count]) |t| allocator.free(t);
    }
    var i: usize = 0;
    while (i < body.len and count < wrapper_nested_target_max) {
        // Absolute path: starts at `/` after start/whitespace/quote/`=`.
        if (body[i] != '/') {
            i += 1;
            continue;
        }
        // Require a safe left boundary so we do not match mid-token.
        if (i > 0) {
            const prev = body[i - 1];
            if (prev != ' ' and prev != '\t' and prev != '\n' and prev != '\r' and
                prev != '"' and prev != '\'' and prev != '=' and prev != '(')
            {
                i += 1;
                continue;
            }
        }
        const start = i;
        i += 1;
        while (i < body.len) : (i += 1) {
            const c = body[i];
            if (c == ' ' or c == '\t' or c == '\n' or c == '\r' or
                c == '"' or c == '\'' or c == ')' or c == ';' or c == '&' or c == '|')
                break;
        }
        const candidate = body[start..i];
        if (candidate.len < 2) continue;
        // Reject bare root and bare HOME.
        if (candidate.len == 1) continue;
        if (envHome(env_map)) |home| {
            if (std.mem.eql(u8, candidate, home)) continue;
        }
        if (!isRegularFile(io, candidate)) continue;
        // `exec /bin/true` is a fixture/no-op, not a runtime interpreter. Collecting
        // it would replace the wrapper argv0 and drop the script identity.
        const base = std.fs.path.basename(candidate);
        if (std.mem.eql(u8, base, "true") or std.mem.eql(u8, base, "false")) continue;
        // Dedup against already collected.
        var dup = false;
        for (out[0..count]) |existing| {
            if (std.mem.eql(u8, existing, candidate)) {
                dup = true;
                break;
            }
        }
        if (dup) continue;
        out[count] = try allocator.dupe(u8, candidate);
        count += 1;
    }
    return count;
}

/// Read the first line of `path` when it is a shebang; return an owned interpreter
/// path or bare name for PATH resolution. `null` when no usable shebang.
fn readShebangInterpreterToken(
    io: std.Io,
    allocator: std.mem.Allocator,
    path: []const u8,
) error{OutOfMemory}!?[]u8 {
    if (path.len == 0 or !isRegularFile(io, path)) return null;

    var buf: [shebang_scan_max]u8 = undefined;
    const n: usize = blk: {
        if (std.fs.path.isAbsolute(path)) {
            const file = std.Io.Dir.openFileAbsolute(io, path, .{}) catch return null;
            defer file.close(io);
            break :blk std.Io.File.readStreaming(file, io, &.{buf[0..]}) catch return null;
        }
        const file = std.Io.Dir.cwd().openFile(io, path, .{}) catch return null;
        defer file.close(io);
        break :blk std.Io.File.readStreaming(file, io, &.{buf[0..]}) catch return null;
    };
    if (n < 2 or buf[0] != '#' or buf[1] != '!') return null;

    const body = buf[2..n];
    const line_end = std.mem.indexOfAny(u8, body, "\r\n") orelse body.len;
    const line = std.mem.trim(u8, body[0..line_end], " \t");
    if (line.len == 0) return null;

    const token = parseShebangInterpreterToken(line) orelse return null;
    return try allocator.dupe(u8, token);
}

/// Parse the body after `#!` into an interpreter path or bare name.
/// Supports absolute paths and `env` with flags/assignments (`-S`, `-u NAME`, `VAR=val`).
fn parseShebangInterpreterToken(line: []const u8) ?[]const u8 {
    if (line.len == 0) return null;

    var pos: usize = 0;
    const first = nextShebangToken(line, &pos) orelse return null;
    const base = std.fs.path.basename(first);
    if (!std.mem.eql(u8, base, "env")) return first;

    // #!/usr/bin/env [options|assignments…] NAME …
    while (nextShebangToken(line, &pos)) |tok| {
        if (tok[0] != '-') {
            if (isEnvAssignmentToken(tok)) continue;
            return tok;
        }

        // Long options: --unset=NAME / --unset NAME / --split-string=S / …
        if (std.mem.startsWith(u8, tok, "--")) {
            if (std.mem.indexOfScalar(u8, tok, '=')) |eq| {
                if (std.mem.eql(u8, tok[0..eq], "--split-string")) {
                    return firstShebangWord(tok[eq + 1 ..]);
                }
                continue;
            }
            if (!envLongOptionTakesArg(tok)) continue;
            const arg = nextShebangToken(line, &pos) orelse return null;
            if (std.mem.eql(u8, tok, "--split-string")) return firstShebangWord(arg);
            continue;
        }

        // Short options: -i / -v / -0 / -u NAME / -uNAME / -S / -Snode / -P PATH …
        if (tok.len < 2) continue;
        const opt = tok[1];
        if (!envShortOptionTakesArg(opt)) continue;

        if (tok.len > 2) {
            // Attached argument: -uFOO, -Snode --flag, -P/opt/bin
            if (opt == 'S') return firstShebangWord(tok[2..]);
            continue;
        }

        // Separate argument for -u/-C/-P/-S.
        // Bare `-S` with no payload (`env -S -P /opt/bin node`) does not consume the next
        // token as an -S string — subsequent flags must still be scanned.
        if (opt == 'S') continue;

        _ = nextShebangToken(line, &pos) orelse return null;
    }
    return null;
}

fn nextShebangToken(line: []const u8, pos: *usize) ?[]const u8 {
    while (pos.* < line.len and (line[pos.*] == ' ' or line[pos.*] == '\t')) pos.* += 1;
    if (pos.* >= line.len) return null;
    const start = pos.*;
    while (pos.* < line.len and line[pos.*] != ' ' and line[pos.*] != '\t') pos.* += 1;
    if (pos.* == start) return null;
    return line[start..pos.*];
}

fn firstShebangWord(s: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i < s.len and (s[i] == ' ' or s[i] == '\t')) i += 1;
    if (i >= s.len) return null;
    const start = i;
    while (i < s.len and s[i] != ' ' and s[i] != '\t') i += 1;
    const word = s[start..i];
    if (word.len == 0 or word[0] == '-') return null;
    if (isEnvAssignmentToken(word)) return null;
    return word;
}

fn envShortOptionTakesArg(opt: u8) bool {
    return switch (opt) {
        'u', 'C', 'P', 'S' => true,
        else => false,
    };
}

fn envLongOptionTakesArg(tok: []const u8) bool {
    return std.mem.eql(u8, tok, "--unset") or
        std.mem.eql(u8, tok, "--chdir") or
        std.mem.eql(u8, tok, "--path") or
        std.mem.eql(u8, tok, "--split-string");
}

fn isEnvAssignmentToken(tok: []const u8) bool {
    const eq = std.mem.indexOfScalar(u8, tok, '=') orelse return false;
    if (eq == 0) return false;
    // Paths can contain '=' rarely; treat slash before '=' as a path, not an assignment.
    if (std.mem.indexOfScalar(u8, tok[0..eq], '/') != null) return false;
    return true;
}

fn envHome(env_map: ?*const std.process.Environ.Map) ?[]const u8 {
    if (env_map) |map| {
        if (map.get("HOME")) |h| return h;
    }
    if (std.c.getenv("HOME")) |h| return std.mem.span(h);
    return null;
}

fn isRegularFile(io: std.Io, path: []const u8) bool {
    if (path.len == 0) return false;
    if (std.fs.path.isAbsolute(path)) {
        const file = std.Io.Dir.openFileAbsolute(io, path, .{}) catch return false;
        defer file.close(io);
        const st = file.stat(io) catch return false;
        return st.kind == .file;
    }
    const file = std.Io.Dir.cwd().openFile(io, path, .{}) catch return false;
    defer file.close(io);
    const st = file.stat(io) catch return false;
    return st.kind == .file;
}

/// Apply OS sandbox policy for the production launch path.
///
/// - `off` → disabled receipt; no profile/platform apply; no env scrub at this seam
/// - `on` / `auto` → compile profile, denylist-scrub env, attempt platform apply
/// - `on` / `auto` + incomplete denylist scrub (OOM) → `error.RequireFailed` (fail closed; reason env_scrub_failed)
/// - allowlist / TMPDIR rewrite OOM → `error.OutOfMemory` (hard; not RequireFailed)
/// - launch allowlist runs only when prepare yields child-apply materials
/// - attach path rewrites TMPDIR/TMP/TEMP into workspace session temp (`.ryk-tmp`)
/// - session-tmp prepare failure under materials → `session_tmp_prepare_failed`
///   (`on` → RequireFailed; `auto` → failed receipt; never silent classic `/tmp`)
/// - `on` + unavailable/failed (no child plan) → `error.RequireFailed` (fail closed)
/// - `on` + prepared child plan → returns materials; receipt stays non-active until promote
/// - `auto` + unavailable → unavailable receipt; denylist only (provider keys retained)
/// - Session `active` only after agent-child apply handshake + `activateAfterHandshake` (S-GLO-01)
pub fn applyBeforeExec(boundary: ApplyBoundary) ApplyError!ApplyResult {
    switch (boundary.mode) {
        .off => {
            // Route-force cannot apply with sandbox off; fail closed when required
            // (e.g. host-alias network mediation or --require-backend network_enforce).
            if (boundary.require_network_route_forcing) {
                setFailReason(boundary, "network_route_forcing_unavailable");
                return error.RequireFailed;
            }
            return .{
                .receipt = posture.disabledReceipt(),
                .env_scrubbed = false,
                .env_launch_allowlisted = false,
                .env_keys_removed = 0,
                .profile_compiled = false,
            };
        },
        .on, .auto => {},
    }

    // Compile pure profile (grants model only — no syscalls).
    // OOM is never a soft grade-drop: propagate so callers fail closed hard.
    // InvalidWorkspace / InvalidExecPath / other compile failures → profile_compile_failed
    // (on→RequireFailed, auto→unavailable).
    var compiled = profile.compileProfile(boundary.allocator, .{
        .workspace_root = boundary.workspace_root,
        .control_roots = boundary.control_roots,
        .include_tmp = boundary.include_tmp,
        .exec_paths = boundary.launch_exec_paths,
        .ro_paths = boundary.launch_ro_paths,
        .host_rw_paths = boundary.launch_host_rw_paths,
        .protect_workspace_secrets = boundary.protect_workspace_secrets,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            setFailReason(boundary, "profile_compile_failed");
            // Fail closed when mode is on, or when route-force is required (mediation).
            if (boundary.mode == .on or boundary.require_network_route_forcing) return error.RequireFailed;
            return .{
                .receipt = posture.unavailableReceipt("profile_compile_failed"),
                .env_scrubbed = false,
                .env_launch_allowlisted = false,
                .profile_compiled = false,
            };
        },
    };
    var transfer_landlock = false;
    defer if (!transfer_landlock) compiled.deinit();

    // F-1: reject symlink/non-dir control roots before platform prepare (path alias).
    var control_io_rt: std.Io.Threaded = .init_single_threaded;
    const control_io = control_io_rt.io();
    compiled.validateControlRootsOnDisk(control_io) catch {
        setFailReason(boundary, "control_root_unsafe");
        if (boundary.mode == .on or boundary.require_network_route_forcing) return error.RequireFailed;
        return .{
            .receipt = posture.unavailableReceipt("control_root_unsafe"),
            .env_scrubbed = false,
            .env_launch_allowlisted = false,
            .profile_compiled = true,
            .profile_hash_hex = blk: {
                var h: [64]u8 = undefined;
                @memcpy(h[0..], compiled.hash());
                break :blk h;
            },
        };
    };

    var hash_copy: [64]u8 = undefined;
    @memcpy(hash_copy[0..], compiled.hash());

    // Denylist scrub always on on/auto (injection fail-closed). Launch allowlist is
    // deferred until after prepare so pure grade-drop does not strip provider keys.
    var removed: usize = 0;
    var scrubbed = false;
    if (boundary.env_map) |env_map| {
        removed = env_scrub.scrubEnvMapInPlace(env_map) catch {
            setFailReason(boundary, "env_scrub_failed");
            return error.RequireFailed;
        };
        scrubbed = true;
    }

    // Platform OS prepare — Linux Landlock ABI probe; macOS Seatbelt prepare.
    // FD scrub / real attach run only in the forked agent child (`apply_posix`), never here.
    // OOM on Seatbelt prepare propagates as `error.OutOfMemory` (never soft .failed).
    var platform = try tryPlatformApply(
        boundary.allocator,
        &compiled,
        boundary.network_proxy_port,
        boundary.seatbelt_profile,
        boundary.launch_write_deny_literals,
    );
    defer platform.deinit();

    if (boundary.require_network_route_forcing and !platform.network_route_forced) {
        setFailReason(boundary, "network_route_forcing_unavailable");
        return error.RequireFailed;
    }

    // Launch allowlist only when child-apply materials will be used (prepared_child).
    // Unavailable/failed grade-drop keeps denylist-only env (provider credentials retained).
    // Attach path rewrites TMPDIR into workspace session temp (R2-2) — host /var/folders
    // is not granted, and classic `/tmp` is not RW under production defaults.
    var allowlisted = false;
    var attach_tmp: ?AttachSessionTmp = null;
    defer if (attach_tmp) |*owned| owned.deinit();
    if (platform.status == .prepared_child) {
        // Create `{workspace}/.ryk-tmp` before Landlock expand enumerates children,
        // even when env_map is null (prepareAttachEnvironment also ensures when env present).
        // Fail closed when materials require session tmp (M-8): never lie with classic /tmp.
        if (!ensureWorkspaceSessionTmp(boundary.workspace_root)) {
            setFailReason(boundary, "session_tmp_prepare_failed");
            // Materials abandoned → no live route-force; fail closed when required.
            if (boundary.mode == .on or boundary.require_network_route_forcing) return error.RequireFailed;
            return .{
                .receipt = posture.failedReceipt("session_tmp_prepare_failed"),
                .env_scrubbed = scrubbed,
                .env_launch_allowlisted = false,
                .env_keys_removed = removed,
                .profile_compiled = true,
                .profile_hash_hex = hash_copy,
            };
        }
        if (boundary.env_map) |env_map| {
            // Allowlist/TMPDIR OOM must stay OutOfMemory (not lossy RequireFailed).
            if (!boundary.with_host_secrets) {
                const allow_removed = env_scrub.applyLaunchAllowlistInPlaceWithMints(
                    env_map,
                    boundary.minted_env_lookup,
                ) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                };
                removed += allow_removed;
                allowlisted = true;
            }
            // After allowlist keeps TMPDIR key, point it at workspace session temp.
            attach_tmp = prepareAttachEnvironment(boundary.allocator, env_map, boundary.workspace_root) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.SessionTmpPrepareFailed => {
                    setFailReason(boundary, "session_tmp_prepare_failed");
                    if (boundary.mode == .on) return error.RequireFailed;
                    return .{
                        .receipt = posture.failedReceipt("session_tmp_prepare_failed"),
                        .env_scrubbed = scrubbed,
                        .env_launch_allowlisted = allowlisted,
                        .env_keys_removed = removed,
                        .profile_compiled = true,
                        .profile_hash_hex = hash_copy,
                    };
                },
            };
        }
    }

    switch (platform.status) {
        .prepared_child => {
            // Parent prepare only — not active until proven agent-child apply (status pipe).
            // Posture is `prepared`, not grade-drop `unavailable`.
            // Linux: transfer landlock profile. macOS: keep SBPL. Spawn path applies then activates.
            if (platform.mechanism == .landlock) {
                const ro_paths = try path_list.clone(boundary.allocator, boundary.launch_ro_paths);
                errdefer path_list.free(boundary.allocator, ro_paths);
                const host_rw_paths = try path_list.clone(boundary.allocator, boundary.launch_host_rw_paths);
                errdefer path_list.free(boundary.allocator, host_rw_paths);
                transfer_landlock = true;
                return .{
                    .receipt = posture.preparedReceipt(.landlock, platform.reason_code),
                    .env_scrubbed = scrubbed,
                    .env_launch_allowlisted = allowlisted,
                    .env_keys_removed = removed,
                    .profile_compiled = true,
                    .profile_hash_hex = hash_copy,
                    .materials = .{ .landlock = .{
                        .allocator = boundary.allocator,
                        .compiled = compiled,
                        .route_forcing = platform.landlock_route_forcing,
                        .include_tmp = boundary.include_tmp,
                        .ro_paths = ro_paths,
                        .host_rw_paths = host_rw_paths,
                    } },
                    .network_route_forced = platform.network_route_forced,
                    .session_tmp = blk: {
                        const owned = attach_tmp;
                        attach_tmp = null;
                        break :blk owned;
                    },
                };
            }
            const sbpl_z = platform.takeSeatbeltSbpl() orelse {
                // prepared_child + seatbelt without SBPL is a contract bug — fail closed.
                setFailReason(boundary, "seatbelt_sbpl_missing");
                if (boundary.mode == .on or boundary.require_network_route_forcing) return error.RequireFailed;
                return .{
                    .receipt = posture.failedReceipt("seatbelt_sbpl_missing"),
                    .env_scrubbed = scrubbed,
                    .env_launch_allowlisted = allowlisted,
                    .env_keys_removed = removed,
                    .profile_compiled = true,
                    .profile_hash_hex = hash_copy,
                };
            };
            // Precompute scope while `compiled` is still alive (static summary string).
            const seatbelt_scope = compiled.effectiveFsScopeSummary(.seatbelt);
            return .{
                .receipt = posture.preparedReceipt(.seatbelt, platform.reason_code),
                .env_scrubbed = scrubbed,
                .env_launch_allowlisted = allowlisted,
                .env_keys_removed = removed,
                .profile_compiled = true,
                .profile_hash_hex = hash_copy,
                .materials = .{ .seatbelt = .{
                    .sbpl_z = sbpl_z,
                    .allocator = boundary.allocator,
                    .fs_scope = seatbelt_scope,
                    .profile_grade = platform.seatbelt_profile_grade,
                } },
                .network_route_forced = platform.network_route_forced,
                .session_tmp = blk: {
                    const owned = attach_tmp;
                    attach_tmp = null;
                    break :blk owned;
                },
            };
        },
        .unavailable => {
            setFailReason(boundary, platform.reason_code);
            if (boundary.mode == .on or boundary.require_network_route_forcing) return error.RequireFailed;
            return .{
                .receipt = posture.unavailableReceipt(platform.reason_code),
                .env_scrubbed = scrubbed,
                .env_launch_allowlisted = false,
                .env_keys_removed = removed,
                .profile_compiled = true,
                .profile_hash_hex = hash_copy,
            };
        },
        .failed => {
            setFailReason(boundary, platform.reason_code);
            if (boundary.mode == .on or boundary.require_network_route_forcing) return error.RequireFailed;
            return .{
                .receipt = posture.failedReceipt(platform.reason_code),
                .env_scrubbed = scrubbed,
                .env_launch_allowlisted = false,
                .env_keys_removed = removed,
                .profile_compiled = true,
                .profile_hash_hex = hash_copy,
            };
        },
    }
}

/// Platform prepare: Linux → Landlock ABI probe + prepared child plan; macOS → Seatbelt prepare.
/// Neither path returns session-active from the parent seam alone.
/// Mode on/auto fail-closed is enforced by the caller (`applyBeforeExec`), not here.
/// Seatbelt OOM surfaces as `error.OutOfMemory` (never soft `.failed`).
fn tryPlatformApply(
    allocator: std.mem.Allocator,
    compiled: *const profile.CompiledProfile,
    network_proxy_port: ?u16,
    seatbelt_profile: macos_profile.SeatbeltProfileGrade,
    write_deny_literals: []const []const u8,
) ApplyError!PlatformApplyOutcome {
    return switch (builtin.os.tag) {
        .linux => tryPlatformApplyLinux(network_proxy_port),
        .macos => try tryMacOsSeatbelt(
            allocator,
            compiled,
            network_proxy_port,
            seatbelt_profile,
            write_deny_literals,
        ),
        else => .{
            .status = .unavailable,
            .mechanism = .none,
            .reason_code = "backend_not_implemented",
        },
    };
}

fn tryMacOsSeatbelt(
    allocator: std.mem.Allocator,
    compiled: *const profile.CompiledProfile,
    network_proxy_port: ?u16,
    seatbelt_profile: macos_profile.SeatbeltProfileGrade,
    write_deny_literals: []const []const u8,
) ApplyError!PlatformApplyOutcome {
    const prepared = macos_seatbelt.prepareForChildApplyWithOptions(
        allocator,
        compiled,
        macos_seatbelt.evaluateSupport(),
        .{
            .network_route_forcing = if (network_proxy_port) |port| .{ .proxy_port = port } else null,
            .profile_grade = seatbelt_profile,
            .write_deny_literals = write_deny_literals,
        },
    );
    return switch (prepared.status) {
        .unavailable => .{
            .status = .unavailable,
            .mechanism = .none,
            .reason_code = prepared.reason_code,
            .seatbelt_sbpl_z = null,
            .sbpl_allocator = null,
            .seatbelt_profile_grade = seatbelt_profile,
        },
        // Single OOM/soft-fail path (M-9): never twin the reason-code match inline.
        .failed => try mapSeatbeltPrepareFailure(prepared.reason_code),
        .prepared => .{
            .status = .prepared_child,
            .mechanism = .seatbelt,
            .reason_code = "seatbelt_child_apply_required",
            .seatbelt_sbpl_z = prepared.sbpl_z,
            .sbpl_allocator = allocator,
            .network_route_forced = network_proxy_port != null,
            .seatbelt_profile_grade = seatbelt_profile,
        },
    };
}

/// Map Seatbelt prepare fail reason codes: OOM → hard `OutOfMemory`, else soft failed.
/// Exposed for unit tests of the OOM fail-closed contract (M-15).
fn mapSeatbeltPrepareFailure(reason_code: []const u8) ApplyError!PlatformApplyOutcome {
    if (std.mem.eql(u8, reason_code, "seatbelt_profile_oom")) return error.OutOfMemory;
    return .{
        .status = .failed,
        .mechanism = .none,
        .reason_code = reason_code,
        .seatbelt_sbpl_z = null,
        .sbpl_allocator = null,
    };
}

/// Linux prepare: ABI probe only. Do not double-apply via verifyApplyInChild
/// on the production hot path — real Landlock attach is the agent child in apply_posix.
/// `landlock.verifyApplyInChild` remains available for unit tests in landlock.zig.
fn tryPlatformApplyLinux(network_proxy_port: ?u16) PlatformApplyOutcome {
    const info = landlock.probeAbi() orelse return .{
        .status = .unavailable,
        .mechanism = .none,
        .reason_code = "landlock_unavailable",
    };
    return tryPlatformApplyLinuxForAbi(info.version, network_proxy_port);
}

fn tryPlatformApplyLinuxForAbi(abi_version: u32, network_proxy_port: ?u16) PlatformApplyOutcome {
    if (!landlock.abiSupportsWriteIntegrity(abi_version)) {
        return .{
            .status = .unavailable,
            .mechanism = .none,
            .reason_code = "landlock_abi_below_truncate_floor",
        };
    }

    const route_forcing: ?landlock.RouteForcing = if (network_proxy_port) |port|
        if (landlock.handledNetRights(abi_version) != 0) .{ .proxy_port = port } else null
    else
        null;

    return .{
        .status = .prepared_child,
        .mechanism = .landlock,
        .reason_code = "landlock_child_apply_required",
        .network_route_forced = route_forcing != null,
        .landlock_route_forcing = route_forcing,
    };
}

test "Landlock prepare enforces ABI 3 truncation floor with distinct reason" {
    inline for (.{ @as(u32, 1), 2 }) |abi| {
        const below_floor = tryPlatformApplyLinuxForAbi(abi, null);
        try std.testing.expectEqual(PlatformApplyStatus.unavailable, below_floor.status);
        try std.testing.expectEqualStrings("landlock_abi_below_truncate_floor", below_floor.reason_code);
    }

    const prepared = tryPlatformApplyLinuxForAbi(3, null);
    try std.testing.expectEqual(PlatformApplyStatus.prepared_child, prepared.status);
    try std.testing.expectEqual(posture.BackendMechanism.landlock, prepared.mechanism);
}

test "Landlock prepare is unavailable when the ABI probe fails" {
    // probeAbi is null off Linux, exercising the wrapper's fail-closed arm.
    if (builtin.os.tag == .linux) return error.SkipZigTest;
    const outcome = tryPlatformApplyLinux(null);
    try std.testing.expectEqual(PlatformApplyStatus.unavailable, outcome.status);
    try std.testing.expectEqualStrings("landlock_unavailable", outcome.reason_code);
}

test "mode off returns disabled receipt without scrub or active claim" {
    var env_map = std.process.Environ.Map.init(std.testing.allocator);
    defer env_map.deinit();
    try env_map.put("LD_PRELOAD", "evil.so");
    try env_map.put("PATH", "/bin");

    const result = try applyBeforeExec(.{
        .allocator = std.testing.allocator,
        .mode = .off,
        .workspace_root = "/tmp/ws",
        .env_map = &env_map,
    });

    try std.testing.expectEqual(posture.SessionPosture.disabled, result.receipt.posture);
    try std.testing.expect(!result.receipt.isActive());
    try std.testing.expect(!result.env_scrubbed);
    try std.testing.expect(!result.profile_compiled);
    // Off path does not scrub at this seam (policy env filter still applies upstream).
    try std.testing.expect(env_map.get("LD_PRELOAD") != null);
    try std.testing.expectEqualStrings("os_sandbox_off", result.receipt.reason_code.?);
    try std.testing.expectEqual(ChildApplyKind.none, result.childApplyKind());
}

test "mode auto without Landlock returns unavailable and scrubs env" {
    var env_map = std.process.Environ.Map.init(std.testing.allocator);
    defer env_map.deinit();
    try env_map.put("LD_PRELOAD", "evil.so");
    try env_map.put("PATH", "/usr/bin");
    try env_map.put("RYK_SESSION_ID", "s1");

    // Parent prepare is ABI/backend probe only — missing path is not a parent failure.
    // Denylist scrub must still run; session stays non-active until agent-child apply + promote.
    var result = try applyBeforeExec(.{
        .allocator = std.testing.allocator,
        .mode = .auto,
        .workspace_root = "/tmp/ryk-apply-ws-nonexistent-u05",
        .env_map = &env_map,
    });
    defer result.deinit();

    try std.testing.expect(result.receipt.posture != .active);
    try std.testing.expect(!result.receipt.isActive());
    try std.testing.expect(result.env_scrubbed);
    try std.testing.expect(result.profile_compiled);
    try std.testing.expect(result.profile_hash_hex != null);
    try std.testing.expect(env_map.get("LD_PRELOAD") == null);
    try std.testing.expectEqualStrings("/usr/bin", env_map.get("PATH").?);
    try std.testing.expectEqualStrings("s1", env_map.get("RYK_SESSION_ID").?);
    // Non-Linux: backend_not_implemented / macos_version_unsupported / prepared;
    // Linux without ABI: landlock_unavailable;
    // Linux with ABI: prepared (landlock_child_apply_required) — attach is spawn path.
    try std.testing.expect(result.receipt.posture == .unavailable or result.receipt.posture == .failed or result.receipt.posture == .prepared);
    // Allowlist only with child-apply materials.
    try std.testing.expectEqual(result.requiresChildApply(), result.env_launch_allowlisted);
}

test "auto grade-drop retains provider keys; attach path allowlists" {
    // Inherit-like env: provider credentials + injection key.
    // Denylist always strips injection. Launch allowlist only when materials require child apply.
    var env_map = std.process.Environ.Map.init(std.testing.allocator);
    defer env_map.deinit();
    try env_map.put("PATH", "/usr/bin:/bin");
    try env_map.put("HOME", "/tmp");
    try env_map.put("OPENAI_API_KEY", "sk-retain-on-grade-drop");
    try env_map.put("AWS_SECRET_ACCESS_KEY", "aws-secret-retain");
    try env_map.put("LD_PRELOAD", "evil.so");
    try env_map.put("SSL_CERT_FILE", "/etc/ssl/cert.pem");
    try env_map.put("SSH_AUTH_SOCK", "/tmp/ssh-agent.sock");

    var result = try applyBeforeExec(.{
        .allocator = std.testing.allocator,
        .mode = .auto,
        .workspace_root = "/tmp/ryk-apply-ws-m2-allowlist",
        .env_map = &env_map,
    });
    defer result.deinit();

    // Injection denylist always runs on auto.
    try std.testing.expect(result.env_scrubbed);
    try std.testing.expect(env_map.get("LD_PRELOAD") == null);
    try std.testing.expectEqualStrings("/usr/bin:/bin", env_map.get("PATH").?);

    if (result.requiresChildApply()) {
        // Attach path: launch allowlist strips secrets and SSH_AUTH_SOCK; TLS trust kept.
        try std.testing.expect(result.env_launch_allowlisted);
        try std.testing.expect(env_map.get("OPENAI_API_KEY") == null);
        try std.testing.expect(env_map.get("AWS_SECRET_ACCESS_KEY") == null);
        try std.testing.expectEqualStrings("/etc/ssl/cert.pem", env_map.get("SSL_CERT_FILE").?);
        try std.testing.expect(env_map.get("SSH_AUTH_SOCK") == null);
    } else {
        // Pure grade-drop unavailable/failed: provider keys retained (no allowlist).
        try std.testing.expect(!result.env_launch_allowlisted);
        try std.testing.expectEqualStrings("sk-retain-on-grade-drop", env_map.get("OPENAI_API_KEY").?);
        try std.testing.expectEqualStrings("aws-secret-retain", env_map.get("AWS_SECRET_ACCESS_KEY").?);
        try std.testing.expectEqualStrings("/etc/ssl/cert.pem", env_map.get("SSL_CERT_FILE").?);
        try std.testing.expectEqualStrings("/tmp/ssh-agent.sock", env_map.get("SSH_AUTH_SOCK").?);
        try std.testing.expect(result.receipt.posture == .unavailable or result.receipt.posture == .failed);
    }
}

test "mode on without usable Landlock fails closed with RequireFailed" {
    var env_map = std.process.Environ.Map.init(std.testing.allocator);
    defer env_map.deinit();
    try env_map.put("PATH", "/bin");

    var fail_reason: []const u8 = "unset";
    var result = applyBeforeExec(.{
        .allocator = std.testing.allocator,
        .mode = .on,
        .workspace_root = "/tmp/ryk-apply-ws-nonexistent-u05",
        .env_map = &env_map,
        .fail_reason_out = &fail_reason,
    });
    // Linux without Landlock ABI → RequireFailed; with ABI → prepared_child (path open is spawn).
    // macOS matrix Seatbelt prepare succeeds (child apply still required; not active yet).
    if (result) |*ok| {
        defer ok.deinit();
        if (builtin.os.tag == .macos) {
            try std.testing.expect(ok.requiresChildApply());
            try std.testing.expectEqual(ChildApplyKind.seatbelt, ok.childApplyKind());
            try std.testing.expect(!ok.receipt.isActive());
        } else {
            // Parent seam never active: prepared child plan only if ABI available.
            try std.testing.expect(ok.requiresChildApply());
            try std.testing.expect(!ok.receipt.isActive());
        }
    } else |e| {
        try std.testing.expectEqual(error.RequireFailed, e);
        try std.testing.expect(!std.mem.eql(u8, fail_reason, "unset"));
        try std.testing.expect(!std.mem.eql(u8, fail_reason, "backend_not_implemented") or builtin.os.tag != .macos);
    }
}

test "mode on + invalid workspace fails closed" {
    var fail_reason: []const u8 = "unset";
    const err = applyBeforeExec(.{
        .allocator = std.testing.allocator,
        .mode = .on,
        .workspace_root = "relative-not-allowed",
        .env_map = null,
        .fail_reason_out = &fail_reason,
    });
    try std.testing.expectError(error.RequireFailed, err);
    try std.testing.expectEqualStrings("profile_compile_failed", fail_reason);
}

test "mode on and auto fail closed when env scrub is incomplete" {
    // Absolute workspace so profile compile succeeds; inject OOM on env scrub only.
    const modes = [_]OsSandboxMode{ .on, .auto };
    for (modes) |mode| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = std.math.maxInt(usize) });
        const alloc = failing.allocator();

        var env_map = std.process.Environ.Map.init(alloc);
        defer env_map.deinit();
        try env_map.put("PATH", "/bin");
        try env_map.put("LD_PRELOAD", "evil.so");
        try env_map.put("LD_AUDIT", "evil_audit.so");

        // Allow profile compile allocations; trip on the first scrub key dupe.
        // Profile compile uses boundary.allocator (testing allocator), env map uses failing.
        // Scrub uses env_map.allocator → failing. Force fail before scrub starts collecting.
        failing.fail_index = failing.alloc_index;

        var fail_reason: []const u8 = "unset";
        const err = applyBeforeExec(.{
            .allocator = std.testing.allocator,
            .mode = mode,
            .workspace_root = "/tmp/ryk-apply-ws-scrub-fail",
            .env_map = &env_map,
            .fail_reason_out = &fail_reason,
        });
        try std.testing.expectError(error.RequireFailed, err);
        try std.testing.expectEqualStrings("env_scrub_failed", fail_reason);
        try std.testing.expect(failing.has_induced_failure);
    }
}

test "mode auto + invalid workspace degrades to unavailable" {
    const result = try applyBeforeExec(.{
        .allocator = std.testing.allocator,
        .mode = .auto,
        .workspace_root = "",
        .env_map = null,
    });
    try std.testing.expectEqual(posture.SessionPosture.unavailable, result.receipt.posture);
    try std.testing.expect(!result.receipt.isActive());
    try std.testing.expectEqualStrings("profile_compile_failed", result.receipt.reason_code.?);
}

test "profile compile OutOfMemory propagates (never soft unavailable)" {
    // OOM on compile is hard failure for both on and auto — not grade-drop.
    const modes = [_]OsSandboxMode{ .on, .auto };
    for (modes) |mode| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
        const err = applyBeforeExec(.{
            .allocator = failing.allocator(),
            .mode = mode,
            .workspace_root = "/tmp/ryk-apply-ws-compile-oom",
            .env_map = null,
        });
        try std.testing.expectError(error.OutOfMemory, err);
        try std.testing.expect(failing.has_induced_failure);
    }
}

test "seatbelt prepare OOM maps to OutOfMemory not soft failed" {
    // seatbelt_profile_oom must hard-fail like profile compile OOM (M-15).
    try std.testing.expectError(error.OutOfMemory, mapSeatbeltPrepareFailure("seatbelt_profile_oom"));
    var soft = try mapSeatbeltPrepareFailure("seatbelt_profile_render_failed");
    defer soft.deinit();
    try std.testing.expectEqual(PlatformApplyStatus.failed, soft.status);
    try std.testing.expectEqualStrings("seatbelt_profile_render_failed", soft.reason_code);
}

test "PlatformApplyOutcome deinit frees owned SBPL" {
    const sbpl = try std.testing.allocator.dupeZ(u8, "(version 1)\n(deny default)\n");
    var outcome: PlatformApplyOutcome = .{
        .status = .prepared_child,
        .mechanism = .seatbelt,
        .reason_code = "seatbelt_child_apply_required",
        .seatbelt_sbpl_z = sbpl,
        .sbpl_allocator = std.testing.allocator,
    };
    // take transfers ownership — deinit must not double-free.
    const taken = outcome.takeSeatbeltSbpl();
    try std.testing.expect(taken != null);
    outcome.deinit();
    std.testing.allocator.free(taken.?);

    const sbpl2 = try std.testing.allocator.dupeZ(u8, "(version 1)\n");
    var outcome2: PlatformApplyOutcome = .{
        .status = .prepared_child,
        .mechanism = .seatbelt,
        .reason_code = "seatbelt_child_apply_required",
        .seatbelt_sbpl_z = sbpl2,
        .sbpl_allocator = std.testing.allocator,
    };
    outcome2.deinit(); // frees sbpl2
    try std.testing.expect(outcome2.seatbelt_sbpl_z == null);
}

test "ApplyResult deinit removes its owned attach session temp" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    var env_map = std.process.Environ.Map.init(std.testing.allocator);
    defer env_map.deinit();
    const owned_tmp = try prepareAttachEnvironment(std.testing.allocator, &env_map, root);
    const retained_path = try std.testing.allocator.dupe(u8, owned_tmp.path);
    defer std.testing.allocator.free(retained_path);
    var result: ApplyResult = .{
        .receipt = posture.disabledReceipt(),
        .session_tmp = owned_tmp,
    };
    result.deinit();

    try std.testing.expectError(
        error.FileNotFound,
        std.Io.Dir.openDirAbsolute(std.testing.io, retained_path, .{}),
    );
}

test "non-Linux never yields active receipt from apply seam without child spawn" {
    if (builtin.os.tag == .linux) return error.SkipZigTest;

    const modes = [_]OsSandboxMode{ .off, .auto };
    for (modes) |mode| {
        var result = try applyBeforeExec(.{
            .allocator = std.testing.allocator,
            .mode = mode,
            .workspace_root = "/tmp/ryk-apply-ws",
            .env_map = null,
        });
        defer result.deinit();
        try std.testing.expect(result.receipt.posture != .active);
        try std.testing.expect(!result.receipt.isActive());
        try std.testing.expect(!result.receipt.posture.isOsEnforced());
    }
}

test "parent apply seam never claims active (probe/prepare only)" {
    var result = try applyBeforeExec(.{
        .allocator = std.testing.allocator,
        .mode = .auto,
        .workspace_root = "/workspace",
        .env_map = null,
    });
    defer result.deinit();
    // S-GLO-01: applyBeforeExec must not authorize session active from probe alone.
    try std.testing.expect(!result.receipt.isActive());

    if (result.requiresChildApply()) {
        try std.testing.expect(result.childApplyKind() == .landlock or result.childApplyKind() == .seatbelt);
    }
}

test "Linux Landlock prepares child plan without claiming active" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!landlock.isAbiAvailable()) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var result = try applyBeforeExec(.{
        .allocator = std.testing.allocator,
        .mode = .auto,
        .workspace_root = root,
        .env_map = null,
        .include_tmp = false,
    });
    defer result.deinit();

    // ABI available → prepared plan without parent-side Landlock apply; not session active.
    try std.testing.expect(!result.receipt.isActive());
    try std.testing.expectEqual(posture.SessionPosture.prepared, result.receipt.posture);
    try std.testing.expectEqual(ChildApplyKind.landlock, result.childApplyKind());
    try std.testing.expectEqual(std.meta.Tag(ChildMaterials).landlock, std.meta.activeTag(result.materials));
    try std.testing.expect(result.profile_hash_hex != null);
    try std.testing.expectEqualStrings("landlock_child_apply_required", result.receipt.reason_code.?);

    // S-GLO-01: bare materials never authorize active until activateAfterHandshake.
    try std.testing.expect(!result.receipt.isActive());
    // Same-module activate after (simulated) handshake builds active receipt.
    const proof = try result.activateAfterHandshake();
    try std.testing.expect(proof.isValid());
    try std.testing.expectEqual(posture.BackendMechanism.landlock, proof.mechanism);
    try std.testing.expect(result.receipt.isActive());
    try std.testing.expectEqual(posture.BackendMechanism.landlock, result.receipt.mechanism);
    try std.testing.expect(std.mem.indexOf(u8, result.receipt.fs_scope, "workspace child RW") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.receipt.fs_scope, "root RO") != null);
    // Default include_tmp=false → no classic platform tmp RW claim.
    try std.testing.expect(std.mem.indexOf(u8, result.receipt.fs_scope, "platform tmp RW") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.receipt.fs_scope, "no home") != null);
    const hash_view = result.receipt.profileHashSlice().?;
    try std.testing.expectEqual(@as(usize, 64), hash_view.len);
    try std.testing.expectEqualStrings(result.profile_hash_hex.?[0..], hash_view);

    // mode on also prepares (not active) when Landlock works.
    var on_result = try applyBeforeExec(.{
        .allocator = std.testing.allocator,
        .mode = .on,
        .workspace_root = root,
        .env_map = null,
    });
    defer on_result.deinit();
    try std.testing.expect(!on_result.receipt.isActive());
    try std.testing.expectEqual(ChildApplyKind.landlock, on_result.childApplyKind());
}

test "never claims network in active landlock fs_scope" {
    const hash64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const complete = try posture.activeReceipt(.landlock, hash64, "workspace child RW, root RO, system RO, platform tmp RW, no home");
    try std.testing.expect(std.mem.indexOf(u8, complete.fs_scope, "network") == null);
    try std.testing.expect(std.mem.indexOf(u8, complete.fs_scope, "root RO") != null);
    try std.testing.expect(std.mem.indexOf(u8, complete.fs_scope, "platform tmp RW") != null);
}

test "activateAfterHandshake activates from materials; materials alone stay inactive" {
    const hash: [64]u8 = .{'a'} ** 64;
    const sbpl = try std.testing.allocator.dupeZ(u8, "(version 1)\n");
    // Precomputed scope with classic tmp (opt-in) — activate must use this verbatim.
    const scope_with_tmp = "workspace RW, system RO, platform tmp RW, no home, control write-deny (readable), mach-lookup residual";
    var result: ApplyResult = .{
        .receipt = posture.preparedReceipt(.seatbelt, "seatbelt_child_apply_required"),
        .profile_compiled = true,
        .profile_hash_hex = hash,
        .materials = .{ .seatbelt = .{
            .sbpl_z = sbpl,
            .allocator = std.testing.allocator,
            .fs_scope = scope_with_tmp,
        } },
    };
    defer result.deinit();

    try std.testing.expectEqual(ChildApplyKind.seatbelt, result.childApplyKind());
    // S-GLO-01: materials alone never yield isActive.
    try std.testing.expect(!result.receipt.isActive());
    const proof = try result.activateAfterHandshake();
    try std.testing.expect(proof.isValid());
    try std.testing.expectEqual(posture.BackendMechanism.seatbelt, proof.mechanism);
    try std.testing.expect(result.receipt.isActive());
    try std.testing.expectEqual(posture.BackendMechanism.seatbelt, result.receipt.mechanism);
    try std.testing.expectEqualStrings(scope_with_tmp, result.receipt.fs_scope);
    try std.testing.expect(std.mem.indexOf(u8, result.receipt.fs_scope, "network") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.receipt.fs_scope, "platform tmp RW") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.receipt.fs_scope, "no home") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.receipt.fs_scope, "mach-lookup residual") != null);
}

test "seatbelt activate uses precomputed fs_scope without platform tmp by default" {
    const hash: [64]u8 = .{'c'} ** 64;
    const sbpl = try std.testing.allocator.dupeZ(u8, "(version 1)\n");
    // Production default (include_tmp=false) summary from profile.effectiveFsScopeSummary(.seatbelt).
    const no_tmp_scope = "workspace RW, system RO, no home, control write-deny (readable), mach-lookup residual";
    var result: ApplyResult = .{
        .receipt = posture.preparedReceipt(.seatbelt, "seatbelt_child_apply_required"),
        .profile_compiled = true,
        .profile_hash_hex = hash,
        .materials = .{ .seatbelt = .{
            .sbpl_z = sbpl,
            .allocator = std.testing.allocator,
            .fs_scope = no_tmp_scope,
        } },
    };
    defer result.deinit();

    _ = try result.activateAfterHandshake();
    try std.testing.expect(result.receipt.isActive());
    try std.testing.expectEqualStrings(no_tmp_scope, result.receipt.fs_scope);
    try std.testing.expect(std.mem.indexOf(u8, result.receipt.fs_scope, "platform tmp") == null);
}

test "activateAfterHandshake hard-fails on missing profile hash" {
    const sbpl = try std.testing.allocator.dupeZ(u8, "(version 1)\n");
    var result: ApplyResult = .{
        .receipt = posture.preparedReceipt(.seatbelt, "seatbelt_child_apply_required"),
        .profile_compiled = true,
        .profile_hash_hex = null,
        .materials = .{ .seatbelt = .{
            .sbpl_z = sbpl,
            .allocator = std.testing.allocator,
            .fs_scope = "workspace RW, system RO, no home, control write-deny (readable), mach-lookup residual",
        } },
    };
    defer result.deinit();

    try std.testing.expectError(error.ApplyFailed, result.activateAfterHandshake());
    try std.testing.expect(!result.receipt.isActive());
}

test "activateAfterHandshake sets seatbelt loopback route-forced network_scope" {
    const hash: [64]u8 = .{'e'} ** 64;
    const sbpl = try std.testing.allocator.dupeZ(u8, "(version 1)\n");
    const fs_scope = "workspace RW, system RO, no home, control write-deny (readable), mach-lookup residual";
    var result: ApplyResult = .{
        .receipt = posture.preparedReceipt(.seatbelt, "seatbelt_child_apply_required"),
        .profile_compiled = true,
        .profile_hash_hex = hash,
        .network_route_forced = true,
        .materials = .{ .seatbelt = .{
            .sbpl_z = sbpl,
            .allocator = std.testing.allocator,
            .fs_scope = fs_scope,
            .profile_grade = .hardened,
        } },
    };
    defer result.deinit();

    _ = try result.activateAfterHandshake();
    try std.testing.expect(result.receipt.isActive());
    try std.testing.expectEqual(macos_profile.SeatbeltProfileGrade.hardened, result.receipt.seatbelt_profile.?);
    try std.testing.expectEqualStrings(
        "proxy route-forced (outbound TCP to ryk loopback proxy only; inbound/bind unrestricted; UDP/QUIC unrestricted)",
        result.receipt.network_scope,
    );
    var banner_buf: [posture.session_banner_buf_len]u8 = undefined;
    const banner = try posture.formatSessionBanner(&banner_buf, result.receipt);
    try std.testing.expect(std.mem.indexOf(u8, banner, "seatbelt_profile=hardened") != null);
    var audit_buf: [posture.audit_reason_buf_len]u8 = undefined;
    const audit = try posture.formatAuditReason(&audit_buf, result.receipt);
    try std.testing.expect(std.mem.indexOf(u8, audit, "seatbelt_profile=hardened") != null);
    // Unforced path stays unrestricted under hardened.
    var unforced: ApplyResult = .{
        .receipt = posture.preparedReceipt(.seatbelt, "seatbelt_child_apply_required"),
        .profile_compiled = true,
        .profile_hash_hex = hash,
        .network_route_forced = false,
        .materials = .{ .seatbelt = .{
            .sbpl_z = try std.testing.allocator.dupeZ(u8, "(version 1)\n"),
            .allocator = std.testing.allocator,
            .fs_scope = fs_scope,
            .profile_grade = .hardened,
        } },
    };
    defer unforced.deinit();
    _ = try unforced.activateAfterHandshake();
    try std.testing.expectEqualStrings("unrestricted", unforced.receipt.network_scope);
    try std.testing.expectEqual(macos_profile.SeatbeltProfileGrade.hardened, unforced.receipt.seatbelt_profile.?);
}

test "activateAfterHandshake strict route-forced denies inbound/bind in network_scope" {
    const hash: [64]u8 = .{'f'} ** 64;
    const sbpl = try std.testing.allocator.dupeZ(u8, "(version 1)\n");
    const fs_scope = "workspace RW, system RO, no home, control write-deny (readable), mach-lookup residual";
    var result: ApplyResult = .{
        .receipt = posture.preparedReceipt(.seatbelt, "seatbelt_child_apply_required"),
        .profile_compiled = true,
        .profile_hash_hex = hash,
        .network_route_forced = true,
        .materials = .{ .seatbelt = .{
            .sbpl_z = sbpl,
            .allocator = std.testing.allocator,
            .fs_scope = fs_scope,
            .profile_grade = .strict,
        } },
    };
    defer result.deinit();

    _ = try result.activateAfterHandshake();
    try std.testing.expectEqual(macos_profile.SeatbeltProfileGrade.strict, result.receipt.seatbelt_profile.?);
    try std.testing.expectEqualStrings(
        "proxy route-forced (outbound TCP to ryk loopback proxy only; inbound/bind denied; UDP/QUIC unrestricted)",
        result.receipt.network_scope,
    );
    var banner_buf: [posture.session_banner_buf_len]u8 = undefined;
    const banner = try posture.formatSessionBanner(&banner_buf, result.receipt);
    try std.testing.expect(std.mem.indexOf(u8, banner, "seatbelt_profile=strict") != null);
}

test "require_network_route_forcing without proxy port fails closed" {
    // Fail-closed before platform grade-drop: no port → no route force materials.
    var fail_reason: []const u8 = "unset";
    const err = applyBeforeExec(.{
        .allocator = std.testing.allocator,
        .mode = .on,
        .workspace_root = "/tmp/ryk-apply-ws-route-force-req",
        .env_map = null,
        .network_proxy_port = null,
        .require_network_route_forcing = true,
        .fail_reason_out = &fail_reason,
    });
    try std.testing.expectError(error.RequireFailed, err);
    try std.testing.expectEqualStrings("network_route_forcing_unavailable", fail_reason);
}

test "require_network_route_forcing with sandbox off fails closed" {
    var fail_reason: []const u8 = "unset";
    const err = applyBeforeExec(.{
        .allocator = std.testing.allocator,
        .mode = .off,
        .workspace_root = "/tmp/ryk-apply-ws-route-force-off",
        .env_map = null,
        .network_proxy_port = 18080,
        .require_network_route_forcing = true,
        .fail_reason_out = &fail_reason,
    });
    try std.testing.expectError(error.RequireFailed, err);
    try std.testing.expectEqualStrings("network_route_forcing_unavailable", fail_reason);
}

test "activateAfterHandshake landlock route-forced network_scope is port-scoped not loopback" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!landlock.isAbiAvailable()) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var result = try applyBeforeExec(.{
        .allocator = std.testing.allocator,
        .mode = .on,
        .workspace_root = root,
        .env_map = null,
        .network_proxy_port = 43123,
    });
    defer result.deinit();

    try std.testing.expectEqual(ChildApplyKind.landlock, result.childApplyKind());
    // Without ABI>=4 TCP support, materials may still prepare FS-only (not route-forced).
    if (!result.network_route_forced) return error.SkipZigTest;

    _ = try result.activateAfterHandshake();
    try std.testing.expect(result.receipt.isActive());
    try std.testing.expectEqualStrings(
        "proxy route-forced (TCP connect port-scoped to proxy port; not address-scoped; UDP unrestricted)",
        result.receipt.network_scope,
    );
    try std.testing.expect(std.mem.indexOf(u8, result.receipt.network_scope, "loopback") == null);
}

test "activateAfterHandshake hard-fails without materials" {
    const hash: [64]u8 = .{'b'} ** 64;
    var result: ApplyResult = .{
        .receipt = posture.preparedReceipt(.landlock, "landlock_child_apply_required"),
        .profile_compiled = true,
        .profile_hash_hex = hash,
        .materials = .none,
    };
    defer result.deinit();
    try std.testing.expectError(error.ApplyFailed, result.activateAfterHandshake());
    try std.testing.expect(!result.receipt.isActive());
}

test "spawnAgent without child materials returns ApplyFailed not Unexpected" {
    var result: ApplyResult = .{
        .receipt = posture.disabledReceipt(),
        .profile_compiled = false,
        .profile_hash_hex = null,
        .materials = .none,
    };
    defer result.deinit();
    try std.testing.expectEqual(ChildApplyKind.none, result.childApplyKind());
    try std.testing.expectError(error.ApplyFailed, result.spawnAgent(
        std.testing.io,
        std.testing.allocator,
        &[_][]const u8{"/usr/bin/true"},
        null,
        "/tmp",
        .ignore,
    ));
}

test "spawnAgent promotes with typed proof on macOS Seatbelt" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    if (!macos_seatbelt.sandboxInitAvailable()) return error.SkipZigTest;
    const ver = macos_seatbelt.detectProductVersion() catch return error.SkipZigTest;
    if (!macos_seatbelt.isMatrixMajor(ver.major)) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, ".ryk");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "neighbor.txt", .data = "ok" });
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var result = try applyBeforeExec(.{
        .allocator = std.testing.allocator,
        .mode = .on,
        .workspace_root = root,
        .env_map = null,
    });
    defer result.deinit();
    try std.testing.expectEqual(ChildApplyKind.seatbelt, result.childApplyKind());
    try std.testing.expect(!result.receipt.isActive());

    const spawned = try result.spawnAgent(
        std.testing.io,
        std.testing.allocator,
        &[_][]const u8{"/usr/bin/true"},
        null,
        root,
        .ignore,
    );
    try std.testing.expect(spawned.proof.isValid());
    try std.testing.expectEqual(posture.BackendMechanism.seatbelt, spawned.proof.mechanism);
    try std.testing.expect(result.receipt.isActive());
    try std.testing.expectEqual(posture.BackendMechanism.seatbelt, result.receipt.mechanism);

    var status: c_int = 0;
    _ = std.c.waitpid(spawned.pid, &status, 0);
    try std.testing.expect((status & 0x7f) == 0);
}

// Regression: agents installed outside workspace/system (e.g. ~/.local/share/claude)
// must receive narrow .exec grants or child preflight fails with ApplyFailed.
test "spawnAgent attaches when launch binary is outside workspace with exec grant" {
    if (builtin.os.tag != .macos and builtin.os.tag != .linux) return error.SkipZigTest;
    if (builtin.os.tag == .macos) {
        if (!macos_seatbelt.sandboxInitAvailable()) return error.SkipZigTest;
        const ver = macos_seatbelt.detectProductVersion() catch return error.SkipZigTest;
        if (!macos_seatbelt.isMatrixMajor(ver.major)) return error.SkipZigTest;
    } else if (!landlock.isAbiAvailable()) return error.SkipZigTest;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    try ws_tmp.dir.createDirPath(std.testing.io, ".ryk");
    const root = try ws_tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    // Separate temp dir = "install tree" outside workspace (like ~/.local/...).
    var bin_tmp = std.testing.tmpDir(.{});
    defer bin_tmp.cleanup();
    const bin_root = try bin_tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(bin_root);

    const true_src: []const u8 = blk: {
        std.Io.Dir.cwd().access(std.testing.io, "/usr/bin/true", .{}) catch break :blk "/bin/true";
        break :blk "/usr/bin/true";
    };
    const outside_bin = try std.fs.path.join(std.testing.allocator, &.{ bin_root, "agent-true" });
    defer std.testing.allocator.free(outside_bin);
    try std.Io.Dir.copyFileAbsolute(true_src, outside_bin, std.testing.io, .{});

    // Without exec grant: outside binary fails child apply handshake.
    {
        var result = try applyBeforeExec(.{
            .allocator = std.testing.allocator,
            .mode = .on,
            .workspace_root = root,
            .env_map = null,
        });
        defer result.deinit();
        try std.testing.expect(result.requiresChildApply());
        try std.testing.expectError(error.ApplyFailed, result.spawnAgent(
            std.testing.io,
            std.testing.allocator,
            &[_][]const u8{outside_bin},
            null,
            root,
            .ignore,
        ));
        try std.testing.expect(!result.receipt.isActive());
    }

    // With launch_exec_paths: attach succeeds and agent runs.
    {
        const exec_paths = try collectLaunchExecPaths(std.testing.io, std.testing.allocator, outside_bin, null);
        defer freeLaunchExecPaths(std.testing.allocator, exec_paths);
        try std.testing.expect(exec_paths.len >= 1);

        var result = try applyBeforeExec(.{
            .allocator = std.testing.allocator,
            .mode = .on,
            .workspace_root = root,
            .env_map = null,
            .launch_exec_paths = exec_paths,
        });
        defer result.deinit();
        try std.testing.expect(result.requiresChildApply());

        const spawned = try result.spawnAgent(
            std.testing.io,
            std.testing.allocator,
            &[_][]const u8{outside_bin},
            null,
            root,
            .ignore,
        );
        try std.testing.expect(spawned.proof.isValid());
        try std.testing.expect(result.receipt.isActive());

        var status: c_int = 0;
        _ = std.c.waitpid(spawned.pid, &status, 0);
        try std.testing.expect((status & 0x7f) == 0);
    }
}

test "collectLaunchExecPaths resolves regular file and rejects HOME" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const true_src: []const u8 = blk: {
        std.Io.Dir.cwd().access(io, "/usr/bin/true", .{}) catch break :blk "/bin/true";
        break :blk "/usr/bin/true";
    };
    const paths = try collectLaunchExecPaths(io, allocator, true_src, null);
    defer freeLaunchExecPaths(allocator, paths);
    try std.testing.expect(paths.len >= 1);
    try std.testing.expect(std.mem.eql(u8, paths[0], true_src) or std.mem.endsWith(u8, paths[0], "true"));

    // Directories are never granted (Seatbelt subpath would open the whole tree).
    // Bare HOME is also rejected when equal to a candidate path (defense in depth).
    var dir_tmp = std.testing.tmpDir(.{});
    defer dir_tmp.cleanup();
    const dir_path = try dir_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(dir_path);
    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    try env_map.put("HOME", dir_path);
    const home_paths = try collectLaunchExecPaths(io, allocator, dir_path, &env_map);
    defer freeLaunchExecPaths(allocator, home_paths);
    try std.testing.expectEqual(@as(usize, 0), home_paths.len);
}

test "collectLaunchInstallRoPaths grants package root for node shebang agent" {
    // Simulated npm global layout (scoped + sibling optional dep hoist):
    //   $tmp/home/.local/lib/node_modules/@scope/agent/bin/cli.js  (shebang)
    //   $tmp/home/.local/lib/node_modules/@scope/agent/package.json
    //   $tmp/home/.local/lib/node_modules/@scope/agent-native/package.json  (sibling hoist)
    // Install RO must be package root + scoped parent (covers sibling), never HOME.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(home);

    const pkg_rel = ".local/lib/node_modules/@scope/agent";
    const sibling_rel = ".local/lib/node_modules/@scope/agent-native";
    try tmp.dir.createDirPath(io, pkg_rel ++ "/bin");
    try tmp.dir.createDirPath(io, sibling_rel ++ "/vendor/bin");
    try tmp.dir.writeFile(io, .{ .sub_path = pkg_rel ++ "/package.json", .data = "{\"name\":\"@scope/agent\"}\n" });
    try tmp.dir.writeFile(io, .{
        .sub_path = sibling_rel ++ "/package.json",
        .data = "{\"name\":\"@scope/agent-native\"}\n",
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = pkg_rel ++ "/bin/cli.js",
        .data = "#!/usr/bin/env node\nconsole.log('ok');\n",
    });
    try tmp.dir.setFilePermissions(io, pkg_rel ++ "/bin/cli.js", std.Io.File.Permissions.fromMode(0o755), .{});

    const script = try std.fs.path.join(allocator, &.{ home, pkg_rel, "bin", "cli.js" });
    defer allocator.free(script);
    const pkg_root = try std.fs.path.join(allocator, &.{ home, pkg_rel });
    defer allocator.free(pkg_root);

    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    try env_map.put("HOME", home);
    try env_map.put("PATH", "/no/such/ryk-test-path");

    const ro = try collectLaunchInstallRoPaths(io, allocator, script, &env_map);
    defer freeLaunchInstallRoPaths(allocator, ro);

    // Package root + scoped parent (`…/node_modules/@scope`) for sibling optional deps.
    try std.testing.expect(ro.len >= 2);
    try std.testing.expect(pathsContain(ro, pkg_root));
    const scope_parent = try std.fs.path.join(allocator, &.{ home, ".local/lib/node_modules/@scope" });
    defer allocator.free(scope_parent);
    try std.testing.expect(pathsContain(ro, scope_parent));
    // Sibling package sits under scope parent; package-root RO alone would miss it
    // (path-prefix must use a boundary — `agent` is not a prefix of `agent-native` as dirs).
    const sibling_root = try std.fs.path.join(allocator, &.{ home, sibling_rel });
    defer allocator.free(sibling_root);
    try std.testing.expect(std.mem.startsWith(u8, sibling_root, scope_parent));
    try std.testing.expect(sibling_root.len > scope_parent.len and sibling_root[scope_parent.len] == '/');
    try std.testing.expect(!std.mem.eql(u8, sibling_root, pkg_root));
    try std.testing.expect(!pathsContain(ro, sibling_root)); // grant is scope parent, not leaf sibling alone
    try std.testing.expect(!pathsContainHomeOrDir(ro, home));
    // Whole node_modules must not be granted.
    const nm_root = try std.fs.path.join(allocator, &.{ home, ".local/lib/node_modules" });
    defer allocator.free(nm_root);
    try std.testing.expect(!pathsContain(ro, nm_root));

    // Plain system binary: no package root → empty RO list.
    const true_src: []const u8 = blk: {
        std.Io.Dir.cwd().access(io, "/usr/bin/true", .{}) catch break :blk "/bin/true";
        break :blk "/usr/bin/true";
    };
    const plain = try collectLaunchInstallRoPaths(io, allocator, true_src, &env_map);
    defer freeLaunchInstallRoPaths(allocator, plain);
    try std.testing.expectEqual(@as(usize, 0), plain.len);
}

test "collectLaunchInstallRoPaths unscoped package root only (no parent RO)" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(home);

    const pkg_rel = ".local/lib/node_modules/plain-agent";
    try tmp.dir.createDirPath(io, pkg_rel ++ "/bin");
    try tmp.dir.writeFile(io, .{ .sub_path = pkg_rel ++ "/package.json", .data = "{\"name\":\"plain-agent\"}\n" });
    try tmp.dir.writeFile(io, .{
        .sub_path = pkg_rel ++ "/bin/cli.js",
        .data = "#!/usr/bin/env node\n",
    });
    try tmp.dir.setFilePermissions(io, pkg_rel ++ "/bin/cli.js", std.Io.File.Permissions.fromMode(0o755), .{});

    const script = try std.fs.path.join(allocator, &.{ home, pkg_rel, "bin", "cli.js" });
    defer allocator.free(script);
    const pkg_root = try std.fs.path.join(allocator, &.{ home, pkg_rel });
    defer allocator.free(pkg_root);

    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    try env_map.put("HOME", home);
    try env_map.put("PATH", "/no/such/ryk-test-path");

    const ro = try collectLaunchInstallRoPaths(io, allocator, script, &env_map);
    defer freeLaunchInstallRoPaths(allocator, ro);

    try std.testing.expectEqual(@as(usize, 1), ro.len);
    try std.testing.expect(pathsContain(ro, pkg_root));
    const nm_root = try std.fs.path.join(allocator, &.{ home, ".local/lib/node_modules" });
    defer allocator.free(nm_root);
    try std.testing.expect(!pathsContain(ro, nm_root));
    try std.testing.expect(!pathsContainHomeOrDir(ro, home));
}

test "collectLaunchInstallRoPaths rejects package.json planted at HOME" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(home);
    try tmp.dir.writeFile(io, .{ .sub_path = "package.json", .data = "{}\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "agent.js", .data = "#!/usr/bin/env node\n" });
    try tmp.dir.setFilePermissions(io, "agent.js", std.Io.File.Permissions.fromMode(0o755), .{});
    const script = try std.fs.path.join(allocator, &.{ home, "agent.js" });
    defer allocator.free(script);

    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    try env_map.put("HOME", home);
    try env_map.put("PATH", "/no/such/ryk-test-path");

    const ro = try collectLaunchInstallRoPaths(io, allocator, script, &env_map);
    defer freeLaunchInstallRoPaths(allocator, ro);
    try std.testing.expectEqual(@as(usize, 0), ro.len);
}

test "absoluteizeLaunchArgv resolves bare name before PATH honesty filter" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const bin_dir = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(bin_dir);

    try tmp.dir.writeFile(io, .{
        .sub_path = "fake-agent",
        .data = "#!/bin/sh\necho ok\n",
    });
    try tmp.dir.setFilePermissions(io, "fake-agent", std.Io.File.Permissions.fromMode(0o755), .{});
    const abs_agent = try std.fs.path.join(allocator, &.{ bin_dir, "fake-agent" });
    defer allocator.free(abs_agent);

    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    try env_map.put("PATH", bin_dir);

    const argv_in = [_][]const u8{ "fake-agent", "--version" };
    const absolute = (try absoluteizeLaunchArgv(io, allocator, &argv_in, &env_map)) orelse {
        try std.testing.expect(false);
        return;
    };
    defer freeExpandedShellWrapperArgv(allocator, absolute);
    try std.testing.expectEqual(@as(usize, 2), absolute.len);
    try std.testing.expect(std.fs.path.isAbsolute(absolute[0]));
    try std.testing.expectEqualStrings("--version", absolute[1]);
    // realpath of the planted binary (tmp may be under a symlink prefix).
    var real_buf: [std.fs.max_path_bytes]u8 = undefined;
    const expected = realpathInto(io, abs_agent, &real_buf) orelse abs_agent;
    try std.testing.expectEqualStrings(expected, absolute[0]);

    // After PATH honesty drops the bin dir, bare name fails but absolute still resolves.
    try env_map.put("PATH", "/usr/bin:/bin");
    try std.testing.expectError(error.FileNotFound, apply_posix.resolveArgv0(io, allocator, "fake-agent", &env_map));
    const still = try apply_posix.resolveArgv0(io, allocator, absolute[0], &env_map);
    defer if (still.owned) allocator.free(still.path);
    try std.testing.expectEqualStrings(absolute[0], still.path);
}

test "absoluteizeLaunchArgv is null for absolute and missing bare names" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const abs_in = [_][]const u8{"/bin/sh"};
    try std.testing.expect((try absoluteizeLaunchArgv(io, allocator, &abs_in, null)) == null);

    const rel_in = [_][]const u8{"./local-agent"};
    try std.testing.expect((try absoluteizeLaunchArgv(io, allocator, &rel_in, null)) == null);

    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    try env_map.put("PATH", "/usr/bin:/bin");
    const missing = [_][]const u8{"ryk-no-such-host-alias-bin"};
    try std.testing.expect((try absoluteizeLaunchArgv(io, allocator, &missing, &env_map)) == null);
}

test "expandEnvShebangLaunch rewrites node shebang to absolute interpreter plus script" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(root);

    try tmp.dir.createDirPath(io, "runtime/bin");
    try tmp.dir.createDirPath(io, "pkg/bin");
    // Plant a tiny "node" stand-in the shebang can resolve.
    try tmp.dir.writeFile(io, .{
        .sub_path = "runtime/bin/node",
        .data = "#!/bin/sh\nexec cat \"$1\"\n",
    });
    try tmp.dir.setFilePermissions(io, "runtime/bin/node", std.Io.File.Permissions.fromMode(0o755), .{});
    try tmp.dir.writeFile(io, .{
        .sub_path = "pkg/bin/cli.js",
        .data = "#!/usr/bin/env node\nconsole.log('ok');\n",
    });
    try tmp.dir.setFilePermissions(io, "pkg/bin/cli.js", std.Io.File.Permissions.fromMode(0o755), .{});
    try tmp.dir.writeFile(io, .{ .sub_path = "pkg/package.json", .data = "{\"name\":\"cli\"}\n" });

    const node_abs = try std.fs.path.join(allocator, &.{ root, "runtime/bin/node" });
    defer allocator.free(node_abs);
    const script_abs = try std.fs.path.join(allocator, &.{ root, "pkg/bin/cli.js" });
    defer allocator.free(script_abs);
    const runtime_bin = try std.fs.path.join(allocator, &.{ root, "runtime/bin" });
    defer allocator.free(runtime_bin);

    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    try env_map.put("PATH", runtime_bin);
    try env_map.put("HOME", root);

    const argv_in = [_][]const u8{ script_abs, "mcp", "list", "--json" };
    const expanded = (try expandEnvShebangLaunch(io, allocator, &argv_in, &env_map)) orelse {
        try std.testing.expect(false);
        return;
    };
    defer freeExpandedShellWrapperArgv(allocator, expanded);
    try std.testing.expectEqual(@as(usize, 5), expanded.len);
    var real_buf_a: [std.fs.max_path_bytes]u8 = undefined;
    var real_buf_b: [std.fs.max_path_bytes]u8 = undefined;
    const want_node = realpathInto(io, node_abs, &real_buf_a) orelse node_abs;
    const want_script = realpathInto(io, script_abs, &real_buf_b) orelse script_abs;
    try std.testing.expectEqualStrings(want_node, expanded[0]);
    try std.testing.expectEqualStrings(want_script, expanded[1]);
    try std.testing.expectEqualStrings("mcp", expanded[2]);
    try std.testing.expectEqualStrings("list", expanded[3]);
    try std.testing.expectEqualStrings("--json", expanded[4]);

    // Install RO must include package root and interpreter bin-layout root.
    const ro = try collectLaunchInstallRoPaths(io, allocator, script_abs, &env_map);
    defer freeLaunchInstallRoPaths(allocator, ro);
    const pkg_root = try std.fs.path.join(allocator, &.{ root, "pkg" });
    defer allocator.free(pkg_root);
    const node_root = try std.fs.path.join(allocator, &.{ root, "runtime" });
    defer allocator.free(node_root);
    try std.testing.expect(pathsContain(ro, pkg_root));
    try std.testing.expect(pathsContain(ro, node_root));

    // Shell shebang is not expanded here (expandShellWrapperLaunch owns that).
    try tmp.dir.writeFile(io, .{
        .sub_path = "pkg/bin/wrap.sh",
        .data = "#!/usr/bin/env bash\nexec /bin/true\n",
    });
    try tmp.dir.setFilePermissions(io, "pkg/bin/wrap.sh", std.Io.File.Permissions.fromMode(0o755), .{});
    const wrap = try std.fs.path.join(allocator, &.{ root, "pkg/bin/wrap.sh" });
    defer allocator.free(wrap);
    const wrap_argv = [_][]const u8{wrap};
    try std.testing.expect((try expandEnvShebangLaunch(io, allocator, &wrap_argv, &env_map)) == null);
}

test "rewriteOsAttachLaunchArgv expands pi-style env-node shebang before PATH honesty" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(root);

    try tmp.dir.createDirPath(io, "runtime/bin");
    try tmp.dir.createDirPath(io, "pkg/bin");
    try tmp.dir.writeFile(io, .{
        .sub_path = "runtime/bin/node",
        .data = "#!/bin/sh\nexec cat \"$1\"\n",
    });
    try tmp.dir.setFilePermissions(io, "runtime/bin/node", std.Io.File.Permissions.fromMode(0o755), .{});
    try tmp.dir.writeFile(io, .{
        .sub_path = "pkg/bin/cli.js",
        .data = "#!/usr/bin/env node\nconsole.log('ok');\n",
    });
    try tmp.dir.setFilePermissions(io, "pkg/bin/cli.js", std.Io.File.Permissions.fromMode(0o755), .{});
    // Product layout: ~/.local/bin/pi → package cli.js (same as @earendil-works/pi).
    try tmp.dir.symLink(io, "../../pkg/bin/cli.js", "runtime/bin/pi", .{});

    const want_node = try tmp.dir.realPathFileAlloc(io, "runtime/bin/node", allocator);
    defer allocator.free(want_node);
    const want_script = try tmp.dir.realPathFileAlloc(io, "pkg/bin/cli.js", allocator);
    defer allocator.free(want_script);
    const runtime_bin = try std.fs.path.join(allocator, &.{ root, "runtime/bin" });
    defer allocator.free(runtime_bin);

    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    try env_map.put("PATH", runtime_bin);
    try env_map.put("HOME", root);

    const planned = [_][]const u8{ "pi", "--mcp-config", "/tmp/closed.json" };
    // os_attach alone is the host-MCP path: shebang expand is not gated on
    // empty-backpack / shell-wrapper rewrite.
    const attach_only = (try rewriteOsAttachLaunchArgv(io, allocator, &planned, &env_map, .{
        .os_attach = true,
    })) orelse {
        try std.testing.expect(false);
        return;
    };
    defer freeExpandedShellWrapperArgv(allocator, attach_only);
    try std.testing.expectEqual(@as(usize, 4), attach_only.len);
    try std.testing.expectEqualStrings(want_node, attach_only[0]);
    try std.testing.expectEqualStrings(want_script, attach_only[1]);
    try std.testing.expectEqualStrings("--mcp-config", attach_only[2]);
    try std.testing.expectEqualStrings("/tmp/closed.json", attach_only[3]);

    const with_shell = (try rewriteOsAttachLaunchArgv(io, allocator, &planned, &env_map, .{
        .expand_shell_wrapper = true,
        .os_attach = true,
    })) orelse {
        try std.testing.expect(false);
        return;
    };
    defer freeExpandedShellWrapperArgv(allocator, with_shell);
    try std.testing.expectEqualStrings(attach_only[0], with_shell[0]);
    try std.testing.expectEqualStrings(attach_only[1], with_shell[1]);

    // Shell shebang stays a host script: only absoluteize argv0 (no node interp).
    try tmp.dir.writeFile(io, .{
        .sub_path = "runtime/bin/wrap-pi",
        .data = "#!/bin/sh\nexec /bin/true\n",
    });
    try tmp.dir.setFilePermissions(io, "runtime/bin/wrap-pi", std.Io.File.Permissions.fromMode(0o755), .{});
    const wrap_planned = [_][]const u8{"wrap-pi"};
    const wrap_expanded = (try rewriteOsAttachLaunchArgv(io, allocator, &wrap_planned, &env_map, .{
        .expand_shell_wrapper = true,
        .os_attach = true,
    })) orelse {
        try std.testing.expect(false);
        return;
    };
    defer freeExpandedShellWrapperArgv(allocator, wrap_expanded);
    try std.testing.expectEqual(@as(usize, 1), wrap_expanded.len);
    try std.testing.expect(std.mem.endsWith(u8, wrap_expanded[0], "wrap-pi"));
}

test "expandShellWrapperLaunch rewrites hermes-style exec to realpath python" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(home);

    try tmp.dir.createDirPath(io, ".hermes/agent/venv/bin");
    try tmp.dir.createDirPath(io, ".local/bin");
    try tmp.dir.createDirPath(io, ".local/share/uv/python/cpython-fake/bin");
    try tmp.dir.writeFile(io, .{
        .sub_path = ".local/share/uv/python/cpython-fake/bin/python3.11",
        .data = "#!/bin/sh\necho fake\n",
    });
    try tmp.dir.setFilePermissions(io, ".local/share/uv/python/cpython-fake/bin/python3.11", std.Io.File.Permissions.fromMode(0o755), .{});
    const real_py = try std.fs.path.join(allocator, &.{ home, ".local/share/uv/python/cpython-fake/bin/python3.11" });
    defer allocator.free(real_py);
    const py_lex = try std.fs.path.join(allocator, &.{ home, ".hermes/agent/venv/bin/python" });
    defer allocator.free(py_lex);
    std.Io.Dir.cwd().symLink(io, real_py, py_lex, .{}) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    const hermes_main = try std.fs.path.join(allocator, &.{ home, ".hermes/agent/hermes" });
    defer allocator.free(hermes_main);
    try tmp.dir.writeFile(io, .{ .sub_path = ".hermes/agent/hermes", .data = "print(1)\n" });
    const body = try std.fmt.allocPrint(allocator,
        \\#!/usr/bin/env bash
        \\exec "{s}" "{s}" "$@"
        \\
    , .{ py_lex, hermes_main });
    defer allocator.free(body);
    try tmp.dir.writeFile(io, .{ .sub_path = ".local/bin/hermes", .data = body });
    try tmp.dir.setFilePermissions(io, ".local/bin/hermes", std.Io.File.Permissions.fromMode(0o755), .{});
    const wrapper = try std.fs.path.join(allocator, &.{ home, ".local/bin/hermes" });
    defer allocator.free(wrapper);

    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    try env_map.put("HOME", home);
    try env_map.put("PATH", "/usr/bin:/bin");

    // Plant a venv site-packages so inject path is testable.
    try tmp.dir.createDirPath(io, ".hermes/agent/venv/lib/python3.11/site-packages");
    try tmp.dir.writeFile(io, .{
        .sub_path = ".hermes/agent/venv/lib/python3.11/site-packages/yaml.py",
        .data = "ok=1\n",
    });

    const argv_in = [_][]const u8{ wrapper, "--version" };
    const expanded = (try expandShellWrapperLaunch(io, allocator, &argv_in, &env_map)) orelse {
        try std.testing.expect(false); // must expand
        return;
    };
    defer freeExpandedShellWrapperArgv(allocator, expanded);
    try std.testing.expect(expanded.len >= 3);
    try std.testing.expectEqualStrings(real_py, expanded[0]);
    try std.testing.expectEqualStrings("--version", expanded[expanded.len - 1]);
    const pp = env_map.get("PYTHONPATH") orelse {
        try std.testing.expect(false);
        return;
    };
    try std.testing.expect(std.mem.indexOf(u8, pp, "site-packages") != null);
}

// CAAF probes for launch argv builders. Fixtures (tmpDir/argv/PATH bytes) live
// outside the failing allocator; success frees via freeExpandedShellWrapperArgv.
// OOM must surface as error.OutOfMemory — never as null.
fn launchArgvOomExpandShellWrapperProbe(
    allocator: std.mem.Allocator,
    wrapper: []const u8,
    interp: []const u8,
) !void {
    const io = std.testing.io;
    const argv_in = [_][]const u8{ wrapper, "--version" };
    const owned = (try expandShellWrapperLaunch(io, allocator, &argv_in, null)) orelse
        return error.TestUnexpectedResult;
    defer freeExpandedShellWrapperArgv(allocator, owned);
    try std.testing.expect(owned.len >= 2);
    var real_buf: [std.fs.max_path_bytes]u8 = undefined;
    const want = realpathInto(io, interp, &real_buf) orelse interp;
    try std.testing.expectEqualStrings(want, owned[0]);
    try std.testing.expectEqualStrings("--version", owned[owned.len - 1]);
}

fn launchArgvOomExpandEnvShebangProbe(
    allocator: std.mem.Allocator,
    script_abs: []const u8,
    runtime_bin: []const u8,
    node_abs: []const u8,
) !void {
    const io = std.testing.io;
    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    try env_map.put("PATH", runtime_bin);
    const argv_in = [_][]const u8{ script_abs, "mcp", "list", "--json" };
    const owned = (try expandEnvShebangLaunch(io, allocator, &argv_in, &env_map)) orelse
        return error.TestUnexpectedResult;
    defer freeExpandedShellWrapperArgv(allocator, owned);
    try std.testing.expectEqual(@as(usize, 5), owned.len);
    var real_buf_a: [std.fs.max_path_bytes]u8 = undefined;
    var real_buf_b: [std.fs.max_path_bytes]u8 = undefined;
    const want_node = realpathInto(io, node_abs, &real_buf_a) orelse node_abs;
    const want_script = realpathInto(io, script_abs, &real_buf_b) orelse script_abs;
    try std.testing.expectEqualStrings(want_node, owned[0]);
    try std.testing.expectEqualStrings(want_script, owned[1]);
    try std.testing.expectEqualStrings("mcp", owned[2]);
    try std.testing.expectEqualStrings("list", owned[3]);
    try std.testing.expectEqualStrings("--json", owned[4]);
}

fn launchArgvOomAbsoluteizeProbe(
    allocator: std.mem.Allocator,
    env_map: *const std.process.Environ.Map,
) !void {
    const argv_in = [_][]const u8{ "sh", "--version" };
    const owned = (try absoluteizeLaunchArgv(std.testing.io, allocator, &argv_in, env_map)) orelse
        return error.TestUnexpectedResult;
    defer freeExpandedShellWrapperArgv(allocator, owned);
    try std.testing.expectEqual(@as(usize, 2), owned.len);
    try std.testing.expect(std.fs.path.isAbsolute(owned[0]));
    try std.testing.expectEqualStrings("--version", owned[1]);
}

test "LaunchArgvOom expandShellWrapperLaunch OOM ownership" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(home);

    try tmp.dir.writeFile(io, .{
        .sub_path = "interp",
        .data = "#!/bin/sh\necho fake\n",
    });
    try tmp.dir.setFilePermissions(io, "interp", std.Io.File.Permissions.fromMode(0o755), .{});
    try tmp.dir.writeFile(io, .{ .sub_path = "main.py", .data = "print(1)\n" });
    const interp = try std.fs.path.join(allocator, &.{ home, "interp" });
    defer allocator.free(interp);
    const main_py = try std.fs.path.join(allocator, &.{ home, "main.py" });
    defer allocator.free(main_py);
    const body = try std.fmt.allocPrint(allocator,
        \\#!/bin/sh
        \\exec "{s}" "{s}" "$@"
        \\
    , .{ interp, main_py });
    defer allocator.free(body);
    try tmp.dir.writeFile(io, .{ .sub_path = "wrap.sh", .data = body });
    try tmp.dir.setFilePermissions(io, "wrap.sh", std.Io.File.Permissions.fromMode(0o755), .{});
    const wrapper = try std.fs.path.join(allocator, &.{ home, "wrap.sh" });
    defer allocator.free(wrapper);

    try std.testing.checkAllAllocationFailures(
        allocator,
        launchArgvOomExpandShellWrapperProbe,
        .{ wrapper, interp },
    );
}

test "LaunchArgvOom expandEnvShebangLaunch OOM ownership" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(root);

    try tmp.dir.createDirPath(io, "runtime/bin");
    try tmp.dir.createDirPath(io, "pkg/bin");
    try tmp.dir.writeFile(io, .{
        .sub_path = "runtime/bin/node",
        .data = "#!/bin/sh\nexec cat \"$1\"\n",
    });
    try tmp.dir.setFilePermissions(io, "runtime/bin/node", std.Io.File.Permissions.fromMode(0o755), .{});
    try tmp.dir.writeFile(io, .{
        .sub_path = "pkg/bin/cli.js",
        .data = "#!/usr/bin/env node\nconsole.log('ok');\n",
    });
    try tmp.dir.setFilePermissions(io, "pkg/bin/cli.js", std.Io.File.Permissions.fromMode(0o755), .{});

    const node_abs = try std.fs.path.join(allocator, &.{ root, "runtime/bin/node" });
    defer allocator.free(node_abs);
    const script_abs = try std.fs.path.join(allocator, &.{ root, "pkg/bin/cli.js" });
    defer allocator.free(script_abs);
    const runtime_bin = try std.fs.path.join(allocator, &.{ root, "runtime/bin" });
    defer allocator.free(runtime_bin);

    try std.testing.checkAllAllocationFailures(
        allocator,
        launchArgvOomExpandEnvShebangProbe,
        .{ script_abs, runtime_bin, node_abs },
    );
}

test "LaunchArgvOom absoluteizeLaunchArgv OOM ownership" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;

    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    try env_map.put("PATH", "/bin:/usr/bin");

    try std.testing.checkAllAllocationFailures(
        allocator,
        launchArgvOomAbsoluteizeProbe,
        .{&env_map},
    );
}

test "collectLaunchInstallRoPaths real host hermes grants uv cpython when present" {
    // Live host residual: hermes wrapper execs venv python → nested cpython under
    // either classic uv (`~/.local/share/uv/python/…`) or Hermes-managed runtime
    // (`…/.hermes-runtime/python/generation-…/cpython-…`). Prove collection finds it.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const home_z = std.c.getenv("HOME") orelse return error.SkipZigTest;
    const home = std.mem.span(home_z);
    if (home.len == 0) return error.SkipZigTest;
    const wrapper = try std.fs.path.join(allocator, &.{ home, ".local/bin/hermes" });
    defer allocator.free(wrapper);
    if (!isRegularFile(io, wrapper)) return error.SkipZigTest;

    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    try env_map.put("HOME", home);
    try env_map.put("PATH", "/usr/bin:/bin");

    const ro = try collectLaunchInstallRoPaths(io, allocator, wrapper, &env_map);
    defer freeLaunchInstallRoPaths(allocator, ro);

    var found_nested_python = false;
    for (ro) |p| {
        if (std.mem.indexOf(u8, p, "/.local/share/uv/python/") != null or
            std.mem.indexOf(u8, p, "/.hermes-runtime/python/") != null or
            std.mem.indexOf(u8, p, "/cpython-") != null)
        {
            found_nested_python = true;
            break;
        }
    }
    if (!found_nested_python) {
        std.debug.print("hermes install RO paths ({d}):\n", .{ro.len});
        for (ro) |p| std.debug.print("  {s}\n", .{p});
    }
    try std.testing.expect(found_nested_python);

    const execs = try collectLaunchExecPaths(io, allocator, wrapper, &env_map);
    defer freeLaunchExecPaths(allocator, execs);
    var found_py = false;
    for (execs) |p| {
        if (std.mem.indexOf(u8, p, "python") != null) {
            found_py = true;
            break;
        }
    }
    try std.testing.expect(found_py);

    // Prove SBPL emit includes process-exec + file-read* for the nested python install.
    if (builtin.os.tag == .macos) {
        var compiled = try profile.compileProfile(allocator, .{
            .workspace_root = "/tmp/ryk-hermes-sbpl-ws",
            .exec_paths = execs,
            .ro_paths = ro,
            .host_rw_paths = &.{},
            .include_tmp = false,
            .protect_workspace_secrets = false,
        });
        defer compiled.deinit();
        const sbpl = try macos_profile.renderSbpl(allocator, &compiled);
        defer allocator.free(sbpl);
        const has_nested_python_grant = std.mem.indexOf(u8, sbpl, "/.local/share/uv/python/") != null or
            std.mem.indexOf(u8, sbpl, "/.hermes-runtime/python/") != null or
            std.mem.indexOf(u8, sbpl, "/cpython-") != null;
        try std.testing.expect(has_nested_python_grant);
        try std.testing.expect(std.mem.indexOf(u8, sbpl, "file-read*") != null);
        try std.testing.expect(std.mem.indexOf(u8, sbpl, "process-exec") != null);
    }
}

test "collectLaunchExecPaths shell wrapper grants nested absolute python" {
    // Hermes-style: #!/usr/bin/env bash + exec "/abs/venv/bin/python" …
    // Nested python (and its realpath when different) must get file-only .exec;
    // bin-layout install root must get RO for libpython.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(home);

    try tmp.dir.createDirPath(io, ".hermes/agent/venv/bin");
    try tmp.dir.createDirPath(io, ".local/bin");
    try tmp.dir.createDirPath(io, ".local/share/uv/python/cpython-fake/bin");
    try tmp.dir.createDirPath(io, ".local/share/uv/python/cpython-fake/lib");
    try tmp.dir.writeFile(io, .{
        .sub_path = ".local/share/uv/python/cpython-fake/bin/python3.11",
        .data = "#!/bin/sh\necho fake-python\n",
    });
    try tmp.dir.setFilePermissions(io, ".local/share/uv/python/cpython-fake/bin/python3.11", std.Io.File.Permissions.fromMode(0o755), .{});

    const real_py = try std.fs.path.join(allocator, &.{ home, ".local/share/uv/python/cpython-fake/bin/python3.11" });
    defer allocator.free(real_py);
    const py_lex = try std.fs.path.join(allocator, &.{ home, ".hermes/agent/venv/bin/python" });
    defer allocator.free(py_lex);
    std.Io.Dir.cwd().symLink(io, real_py, py_lex, .{}) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    const hermes_main = try std.fs.path.join(allocator, &.{ home, ".hermes/agent/hermes" });
    defer allocator.free(hermes_main);
    try tmp.dir.writeFile(io, .{ .sub_path = ".hermes/agent/hermes", .data = "print('hermes')\n" });

    const body = try std.fmt.allocPrint(allocator,
        \\#!/usr/bin/env bash
        \\unset PYTHONPATH
        \\exec "{s}" "{s}" "$@"
        \\
    , .{ py_lex, hermes_main });
    defer allocator.free(body);
    try tmp.dir.writeFile(io, .{ .sub_path = ".local/bin/hermes", .data = body });
    try tmp.dir.setFilePermissions(io, ".local/bin/hermes", std.Io.File.Permissions.fromMode(0o755), .{});

    const wrapper = try std.fs.path.join(allocator, &.{ home, ".local/bin/hermes" });
    defer allocator.free(wrapper);

    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    try env_map.put("HOME", home);
    try env_map.put("PATH", "/usr/bin:/bin");

    const execs = try collectLaunchExecPaths(io, allocator, wrapper, &env_map);
    defer freeLaunchExecPaths(allocator, execs);
    try std.testing.expect(pathsContain(execs, wrapper));
    try std.testing.expect(pathsContain(execs, real_py));
    try std.testing.expect(!pathsContainHomeOrDir(execs, home));

    const ro = try collectLaunchInstallRoPaths(io, allocator, wrapper, &env_map);
    defer freeLaunchInstallRoPaths(allocator, ro);
    const cpython_root = try std.fs.path.join(allocator, &.{ home, ".local/share/uv/python/cpython-fake" });
    defer allocator.free(cpython_root);
    try std.testing.expect(pathsContain(ro, cpython_root));
    try std.testing.expect(!pathsContainHomeOrDir(ro, home));
}

fn pathsContain(paths: []const []const u8, want: []const u8) bool {
    for (paths) |p| {
        if (std.mem.eql(u8, p, want)) return true;
    }
    return false;
}

fn pathsContainHomeOrDir(paths: []const []const u8, home: []const u8) bool {
    for (paths) |p| {
        if (std.mem.eql(u8, p, home)) return true;
        if (std.mem.eql(u8, p, "/")) return true;
    }
    return false;
}

test "collectLaunchExecPaths grants env shebang interpreter outside workspace" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var bin_tmp = std.testing.tmpDir(.{});
    defer bin_tmp.cleanup();
    const bin_root = try bin_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(bin_root);

    const true_src: []const u8 = blk: {
        std.Io.Dir.cwd().access(io, "/usr/bin/true", .{}) catch break :blk "/bin/true";
        break :blk "/usr/bin/true";
    };
    const node_bin = try std.fs.path.join(allocator, &.{ bin_root, "fake-node" });
    defer allocator.free(node_bin);
    try std.Io.Dir.copyFileAbsolute(true_src, node_bin, io, .{});
    try bin_tmp.dir.setFilePermissions(io, "fake-node", std.Io.File.Permissions.fromMode(0o755), .{});

    const script_body = "#!/usr/bin/env fake-node\n";
    try bin_tmp.dir.writeFile(io, .{ .sub_path = "agent-script", .data = script_body });
    try bin_tmp.dir.setFilePermissions(io, "agent-script", std.Io.File.Permissions.fromMode(0o755), .{});
    const script_path = try std.fs.path.join(allocator, &.{ bin_root, "agent-script" });
    defer allocator.free(script_path);

    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    try env_map.put("PATH", bin_root);
    try env_map.put("HOME", bin_root);

    const paths = try collectLaunchExecPaths(io, allocator, script_path, &env_map);
    defer freeLaunchExecPaths(allocator, paths);

    try std.testing.expect(pathsContain(paths, script_path));
    try std.testing.expect(pathsContain(paths, node_bin));
    try std.testing.expect(!pathsContainHomeOrDir(paths, bin_root));
    for (paths) |p| {
        try std.testing.expect(isRegularFile(io, p));
    }
}

test "collectLaunchExecPaths grants absolute shebang interpreter" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var bin_tmp = std.testing.tmpDir(.{});
    defer bin_tmp.cleanup();
    const bin_root = try bin_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(bin_root);

    const true_src: []const u8 = blk: {
        std.Io.Dir.cwd().access(io, "/usr/bin/true", .{}) catch break :blk "/bin/true";
        break :blk "/usr/bin/true";
    };
    const interp = try std.fs.path.join(allocator, &.{ bin_root, "interp-true" });
    defer allocator.free(interp);
    try std.Io.Dir.copyFileAbsolute(true_src, interp, io, .{});
    try bin_tmp.dir.setFilePermissions(io, "interp-true", std.Io.File.Permissions.fromMode(0o755), .{});

    const script_body = try std.fmt.allocPrint(allocator, "#!{s}\n", .{interp});
    defer allocator.free(script_body);
    try bin_tmp.dir.writeFile(io, .{ .sub_path = "abs-script", .data = script_body });
    try bin_tmp.dir.setFilePermissions(io, "abs-script", std.Io.File.Permissions.fromMode(0o755), .{});
    const script_path = try std.fs.path.join(allocator, &.{ bin_root, "abs-script" });
    defer allocator.free(script_path);

    const paths = try collectLaunchExecPaths(io, allocator, script_path, null);
    defer freeLaunchExecPaths(allocator, paths);

    try std.testing.expect(pathsContain(paths, script_path));
    try std.testing.expect(pathsContain(paths, interp));
}

test "collectLaunchExecPaths rejects directory shebang interpreter" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var bin_tmp = std.testing.tmpDir(.{});
    defer bin_tmp.cleanup();
    const bin_root = try bin_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(bin_root);

    try bin_tmp.dir.createDirPath(io, "not-a-binary");
    const dir_interp = try std.fs.path.join(allocator, &.{ bin_root, "not-a-binary" });
    defer allocator.free(dir_interp);

    const script_body = try std.fmt.allocPrint(allocator, "#!{s}\n", .{dir_interp});
    defer allocator.free(script_body);
    try bin_tmp.dir.writeFile(io, .{ .sub_path = "bad-interp-script", .data = script_body });
    try bin_tmp.dir.setFilePermissions(io, "bad-interp-script", std.Io.File.Permissions.fromMode(0o755), .{});
    const script_path = try std.fs.path.join(allocator, &.{ bin_root, "bad-interp-script" });
    defer allocator.free(script_path);

    const paths = try collectLaunchExecPaths(io, allocator, script_path, null);
    defer freeLaunchExecPaths(allocator, paths);

    try std.testing.expect(pathsContain(paths, script_path));
    try std.testing.expect(!pathsContain(paths, dir_interp));
    try std.testing.expect(!pathsContain(paths, bin_root));
}

test "spawnAgent attaches when shebang script and interpreter are outside workspace" {
    if (builtin.os.tag != .macos and builtin.os.tag != .linux) return error.SkipZigTest;
    if (builtin.os.tag == .macos) {
        if (!macos_seatbelt.sandboxInitAvailable()) return error.SkipZigTest;
        const ver = macos_seatbelt.detectProductVersion() catch return error.SkipZigTest;
        if (!macos_seatbelt.isMatrixMajor(ver.major)) return error.SkipZigTest;
    } else if (!landlock.isAbiAvailable()) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    try ws_tmp.dir.createDirPath(io, ".ryk");
    const root = try ws_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(root);

    var bin_tmp = std.testing.tmpDir(.{});
    defer bin_tmp.cleanup();
    const bin_root = try bin_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(bin_root);

    const true_src: []const u8 = blk: {
        std.Io.Dir.cwd().access(io, "/usr/bin/true", .{}) catch break :blk "/bin/true";
        break :blk "/usr/bin/true";
    };
    const interp = try std.fs.path.join(allocator, &.{ bin_root, "interp-true" });
    defer allocator.free(interp);
    try std.Io.Dir.copyFileAbsolute(true_src, interp, io, .{});
    try bin_tmp.dir.setFilePermissions(io, "interp-true", std.Io.File.Permissions.fromMode(0o755), .{});

    const script_body = try std.fmt.allocPrint(allocator, "#!{s}\n", .{interp});
    defer allocator.free(script_body);
    try bin_tmp.dir.writeFile(io, .{ .sub_path = "shebang-agent", .data = script_body });
    try bin_tmp.dir.setFilePermissions(io, "shebang-agent", std.Io.File.Permissions.fromMode(0o755), .{});
    const script_path = try std.fs.path.join(allocator, &.{ bin_root, "shebang-agent" });
    defer allocator.free(script_path);

    const exec_paths = try collectLaunchExecPaths(io, allocator, script_path, null);
    defer freeLaunchExecPaths(allocator, exec_paths);
    try std.testing.expect(pathsContain(exec_paths, script_path));
    try std.testing.expect(pathsContain(exec_paths, interp));
    try std.testing.expect(!pathsContainHomeOrDir(exec_paths, bin_root));

    var result = try applyBeforeExec(.{
        .allocator = allocator,
        .mode = .on,
        .workspace_root = root,
        .env_map = null,
        .launch_exec_paths = exec_paths,
    });
    defer result.deinit();
    try std.testing.expect(result.requiresChildApply());

    const spawned = try result.spawnAgent(
        io,
        allocator,
        &[_][]const u8{script_path},
        null,
        root,
        .ignore,
    );
    try std.testing.expect(spawned.proof.isValid());
    try std.testing.expect(result.receipt.isActive());

    var status: c_int = 0;
    _ = std.c.waitpid(spawned.pid, &status, 0);
    try std.testing.expect((status & 0x7f) == 0);
}

test "parseShebangInterpreterToken handles env and absolute forms" {
    try std.testing.expectEqualStrings("/usr/bin/python3", parseShebangInterpreterToken("/usr/bin/python3").?);
    try std.testing.expectEqualStrings("node", parseShebangInterpreterToken("/usr/bin/env node").?);
    try std.testing.expectEqualStrings("node", parseShebangInterpreterToken("/usr/bin/env -S node --experimental").?);
    try std.testing.expectEqualStrings("node", parseShebangInterpreterToken("/usr/bin/env -Snode --experimental").?);
    try std.testing.expectEqualStrings("node", parseShebangInterpreterToken("/usr/bin/env -u FOO node").?);
    try std.testing.expectEqualStrings("node", parseShebangInterpreterToken("/usr/bin/env -uFOO node").?);
    try std.testing.expectEqualStrings("node", parseShebangInterpreterToken("/usr/bin/env -S -P /opt/bin node").?);
    try std.testing.expectEqualStrings("node", parseShebangInterpreterToken("/usr/bin/env FOO=bar node").?);
    try std.testing.expectEqualStrings("node", parseShebangInterpreterToken("/usr/bin/env --unset=FOO node").?);
    try std.testing.expectEqualStrings("node", parseShebangInterpreterToken("/usr/bin/env --split-string=node --experimental").?);
    try std.testing.expect(parseShebangInterpreterToken("/usr/bin/env") == null);
    try std.testing.expect(parseShebangInterpreterToken("/usr/bin/env -u") == null);
    try std.testing.expect(parseShebangInterpreterToken("") == null);
}

test "mode on surfaces real reason_code via fail_reason_out on this host" {
    var fail_reason: []const u8 = "unset";
    var result = applyBeforeExec(.{
        .allocator = std.testing.allocator,
        .mode = .on,
        .workspace_root = "/tmp/ryk-apply-ws-u07-reason",
        .env_map = null,
        .fail_reason_out = &fail_reason,
    });
    // On hosts without a usable backend, RequireFailed with a real reason (not placeholder).
    if (result) |*ok| {
        defer ok.deinit();
        // Prepared child plan only — never session-active from the parent seam.
        try std.testing.expect(ok.requiresChildApply());
        try std.testing.expect(!ok.receipt.isActive());
    } else |e| {
        try std.testing.expectEqual(error.RequireFailed, e);
        try std.testing.expect(!std.mem.eql(u8, fail_reason, "unset"));
        // Real reason codes only — never the backend_not_implemented placeholder on Darwin.
        if (builtin.os.tag == .macos) {
            try std.testing.expect(std.mem.indexOf(u8, fail_reason, "backend_not_implemented") == null);
        }
    }
}

test "session banner helper remains mechanism-neutral for apply receipts" {
    var buf: [320]u8 = undefined;
    const hash64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const active = try posture.activeReceipt(.seatbelt, hash64, "workspace RW, system RO, platform tmp RW, no home");
    const line = try posture.formatSessionBanner(&buf, active);
    try std.testing.expect(std.mem.indexOf(u8, line, "OS sandbox: active") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "Seatbelt") == null);
    try std.testing.expect(std.mem.indexOf(u8, line, "Landlock") == null);
}

test "isUngrantedHostTmpdir detects macOS var/folders shapes" {
    try std.testing.expect(isUngrantedHostTmpdir("/var/folders/xx/yy/T/"));
    try std.testing.expect(isUngrantedHostTmpdir("/private/var/folders/xx/yy/T"));
    try std.testing.expect(!isUngrantedHostTmpdir("/tmp"));
    try std.testing.expect(!isUngrantedHostTmpdir("/private/tmp"));
    try std.testing.expect(!isUngrantedHostTmpdir("/workspace/.ryk-tmp"));
}

test "prepareAttachEnvironment points TMPDIR at fresh workspace session temp" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var env_map = std.process.Environ.Map.init(std.testing.allocator);
    defer env_map.deinit();
    // Simulate macOS host TMPDIR (ungranted under Seatbelt defaults).
    try env_map.put("TMPDIR", "/var/folders/ns/xmz0/T/");
    try env_map.put("TMP", "/var/folders/ns/xmz0/T/");
    try env_map.put("TEMP", "/var/folders/ns/xmz0/T/");

    var prepared = try prepareAttachEnvironment(std.testing.allocator, &env_map, root);
    defer prepared.deinit();
    const rewritten = prepared.path;
    try std.testing.expect(!isUngrantedHostTmpdir(rewritten));
    // Production defaults: session temp only — never silent classic /tmp fallback (M-8).
    const workspace_tmp = try workspaceSessionTmpPath(std.testing.allocator, root);
    defer std.testing.allocator.free(workspace_tmp);
    try std.testing.expect(std.mem.startsWith(u8, rewritten, workspace_tmp));
    try std.testing.expect(!std.mem.eql(u8, rewritten, classic_tmp_fallback));
    try std.testing.expectEqualStrings(rewritten, env_map.get("TMPDIR").?);
    try std.testing.expectEqualStrings(rewritten, env_map.get("TMP").?);
    try std.testing.expectEqualStrings(rewritten, env_map.get("TEMP").?);
    try std.testing.expectEqualStrings(rewritten, env_map.get(claude_code_tmpdir_env).?);
    try std.testing.expect(claudeCodeTmpAccepts(rewritten));
    try std.testing.expect(ensureClaudeCodeTmpLeaves(rewritten));

    // MCP package launchers must not fall back to denied host state under HOME.
    for (isolated_tool_caches) |cache| {
        const path = env_map.get(cache.env_key) orelse return error.TestUnexpectedResult;
        try std.testing.expect(std.mem.startsWith(u8, path, rewritten));
        try std.testing.expect(std.mem.endsWith(u8, path, cache.directory_name));
    }

    // Git must not fail while probing denied host-global config/ignore files.
    try std.testing.expectEqualStrings("/dev/null", env_map.get("GIT_CONFIG_GLOBAL").?);
    try std.testing.expectEqualStrings("1", env_map.get("GIT_CONFIG_COUNT").?);
    try std.testing.expectEqualStrings("core.excludesFile", env_map.get("GIT_CONFIG_KEY_0").?);
    try std.testing.expectEqualStrings("/dev/null", env_map.get("GIT_CONFIG_VALUE_0").?);

    // Preferred path must exist when rewrite succeeds.
    var io_rt: std.Io.Threaded = .init_single_threaded;
    const io = io_rt.io();
    var dir = try std.Io.Dir.openDirAbsolute(io, rewritten, .{});
    dir.close(io);
    for (isolated_tool_caches) |cache| {
        var cache_dir = try std.Io.Dir.openDirAbsolute(io, env_map.get(cache.env_key).?, .{});
        cache_dir.close(io);
    }

    // Issue #198: Claude Code joins TMPDIR/CLAUDE_CODE_TMPDIR with claude-{uid}
    // (or claude-0) and refuses a non-directory / planted symlink.
    var leaf_buf: [32]u8 = undefined;
    const leaf = session_tmp.claudeTempLeafName(&leaf_buf, session_tmp.currentUid());
    const claude_leaf = try std.fs.path.join(std.testing.allocator, &.{ rewritten, leaf });
    defer std.testing.allocator.free(claude_leaf);
    try std.testing.expect(claudeCodeTmpAccepts(claude_leaf));
    if (builtin.os.tag != .windows) {
        const claude_zero = try std.fs.path.join(std.testing.allocator, &.{ rewritten, "claude-0" });
        defer std.testing.allocator.free(claude_zero);
        try std.testing.expect(claudeCodeTmpAccepts(claude_zero));
    }
}

test "prepareAttachEnvironment overwrites host CLAUDE_CODE_TMPDIR with session tmp" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var env_map = std.process.Environ.Map.init(std.testing.allocator);
    defer env_map.deinit();
    try env_map.put(claude_code_tmpdir_env, "/tmp/evil-planted-claude-tmp");

    var prepared = try prepareAttachEnvironment(std.testing.allocator, &env_map, root);
    defer prepared.deinit();
    try std.testing.expectEqualStrings(prepared.path, env_map.get(claude_code_tmpdir_env).?);
    try std.testing.expect(claudeCodeTmpAccepts(env_map.get(claude_code_tmpdir_env).?));
    try std.testing.expect(!std.mem.eql(u8, env_map.get(claude_code_tmpdir_env).?, "/tmp/evil-planted-claude-tmp"));
}

test "prepareAttachEnvironment mints realpath TMPDIR when workspace is a symlink" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    try tmp.dir.createDir(io, "real-ws", .default_dir);
    try tmp.dir.symLink(io, "real-ws", "link-ws", .{ .is_directory = true });
    const real_root = try tmp.dir.realPathFileAlloc(io, "real-ws", std.testing.allocator);
    defer std.testing.allocator.free(real_root);
    const parent = try tmp.dir.realPathFileAlloc(io, ".", std.testing.allocator);
    defer std.testing.allocator.free(parent);
    const symlink_ws = try std.fs.path.join(std.testing.allocator, &.{ parent, "link-ws" });
    defer std.testing.allocator.free(symlink_ws);

    var env_map = std.process.Environ.Map.init(std.testing.allocator);
    defer env_map.deinit();
    var prepared = try prepareAttachEnvironment(std.testing.allocator, &env_map, symlink_ws);
    defer prepared.deinit();

    const tmpdir = env_map.get("TMPDIR") orelse return error.TestUnexpectedResult;
    try std.testing.expect(std.mem.startsWith(u8, tmpdir, real_root));
    try std.testing.expect(std.mem.indexOf(u8, tmpdir, "/link-ws/") == null);
    try std.testing.expectEqualStrings(tmpdir, env_map.get(claude_code_tmpdir_env).?);
    try std.testing.expect(claudeCodeTmpAccepts(tmpdir));
}

test "prepareAttachEnvironment creates a fresh cache namespace per launch" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var first = std.process.Environ.Map.init(std.testing.allocator);
    defer first.deinit();
    var second = std.process.Environ.Map.init(std.testing.allocator);
    defer second.deinit();

    var first_prepared = try prepareAttachEnvironment(std.testing.allocator, &first, root);
    defer first_prepared.deinit();
    var second_prepared = try prepareAttachEnvironment(std.testing.allocator, &second, root);
    defer second_prepared.deinit();
    const first_tmp = first_prepared.path;
    const second_tmp = second_prepared.path;
    try std.testing.expect(!std.mem.eql(u8, first_tmp, second_tmp));
    try std.testing.expect(std.mem.startsWith(u8, first_tmp, root));
    try std.testing.expect(std.mem.startsWith(u8, second_tmp, root));
    try std.testing.expect(!std.mem.eql(
        u8,
        first.get("NPM_CONFIG_CACHE").?,
        second.get("NPM_CONFIG_CACHE").?,
    ));
}

test "prepareAttachEnvironment fails closed when session tmp cannot be prepared" {
    // Empty workspace → ensureWorkspaceSessionTmp returns false; must not rewrite to /tmp.
    var env_map = std.process.Environ.Map.init(std.testing.allocator);
    defer env_map.deinit();
    try env_map.put("TMPDIR", "/var/folders/ns/xmz0/T/");
    try env_map.put("TMP", "/var/folders/ns/xmz0/T/");
    try env_map.put("TEMP", "/var/folders/ns/xmz0/T/");

    try std.testing.expectError(
        error.SessionTmpPrepareFailed,
        prepareAttachEnvironment(std.testing.allocator, &env_map, ""),
    );
    // Env must remain unchanged (no lying classic /tmp rewrite).
    try std.testing.expectEqualStrings("/var/folders/ns/xmz0/T/", env_map.get("TMPDIR").?);
    try std.testing.expectEqualStrings("/var/folders/ns/xmz0/T/", env_map.get("TMP").?);
    try std.testing.expectEqualStrings("/var/folders/ns/xmz0/T/", env_map.get("TEMP").?);

    // Over-long workspace also fails ensure (path buffer overflow) without classic fallback.
    var long_root: [std.fs.max_path_bytes]u8 = undefined;
    @memset(&long_root, 'x');
    long_root[0] = '/';
    try std.testing.expectError(
        error.SessionTmpPrepareFailed,
        prepareAttachEnvironment(std.testing.allocator, &env_map, long_root[0..]),
    );
    try std.testing.expectEqualStrings("/var/folders/ns/xmz0/T/", env_map.get("TMPDIR").?);
}

test "prepareAttachEnvironment rolls back env and session temp on allocation failure" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    const original_tmp = "/var/folders/ns/xmz0/T/";
    var observed_induced_failure = false;
    for (0..64) |failure_offset| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        const allocator = failing.allocator();
        var env_map = std.process.Environ.Map.init(allocator);
        defer env_map.deinit();
        try env_map.put("TMPDIR", original_tmp);
        try env_map.put("TMP", original_tmp);
        try env_map.put("TEMP", original_tmp);
        try env_map.put("UNCHANGED", "yes");
        failing.fail_index = failing.alloc_index + failure_offset;

        const prepared = prepareAttachEnvironment(allocator, &env_map, root);
        if (prepared) |owned_value| {
            var owned = owned_value;
            owned.deinit();
        } else |err| switch (err) {
            error.OutOfMemory => {
                if (!failing.has_induced_failure) continue;
                observed_induced_failure = true;
                try std.testing.expectEqualStrings(original_tmp, env_map.get("TMPDIR").?);
                try std.testing.expectEqualStrings(original_tmp, env_map.get("TMP").?);
                try std.testing.expectEqualStrings(original_tmp, env_map.get("TEMP").?);
                try std.testing.expectEqualStrings("yes", env_map.get("UNCHANGED").?);
                for (isolated_tool_caches) |cache| {
                    try std.testing.expect(env_map.get(cache.env_key) == null);
                }
                try std.testing.expect(env_map.get("GIT_CONFIG_GLOBAL") == null);
                try std.testing.expect(env_map.get(claude_code_tmpdir_env) == null);

                const workspace_tmp = try workspaceSessionTmpPath(std.testing.allocator, root);
                defer std.testing.allocator.free(workspace_tmp);
                var session_dir = std.Io.Dir.openDirAbsolute(
                    std.testing.io,
                    workspace_tmp,
                    .{ .iterate = true },
                ) catch |open_err| switch (open_err) {
                    error.FileNotFound => continue,
                    else => return open_err,
                };
                defer session_dir.close(std.testing.io);
                var entries = session_dir.iterate();
                try std.testing.expect(try entries.next(std.testing.io) == null);
            },
            error.SessionTmpPrepareFailed => return err,
        }
    }
    try std.testing.expect(observed_induced_failure);
}

test "attach path rewrites host TMPDIR out of var/folders (R2-2)" {
    // Only meaningful when prepare yields child-apply materials (macOS Seatbelt / Linux Landlock).
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, ".ryk");
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var env_map = std.process.Environ.Map.init(std.testing.allocator);
    defer env_map.deinit();
    try env_map.put("PATH", "/usr/bin:/bin");
    try env_map.put("HOME", "/tmp");
    try env_map.put("TMPDIR", "/var/folders/xx/yy/T/");
    try env_map.put("LD_PRELOAD", "evil.so");

    var result = try applyBeforeExec(.{
        .allocator = std.testing.allocator,
        .mode = .auto,
        .workspace_root = root,
        .env_map = &env_map,
    });
    defer result.deinit();

    try std.testing.expect(env_map.get("LD_PRELOAD") == null);
    if (result.requiresChildApply()) {
        const td = env_map.get("TMPDIR") orelse "";
        try std.testing.expect(td.len > 0);
        try std.testing.expect(!isUngrantedHostTmpdir(td));
        // Production defaults: session temp under workspace only (M-8; no classic /tmp).
        const workspace_tmp = try workspaceSessionTmpPath(std.testing.allocator, root);
        defer std.testing.allocator.free(workspace_tmp);
        try std.testing.expect(std.mem.startsWith(u8, td, workspace_tmp));
        try std.testing.expect(std.mem.startsWith(u8, td[workspace_tmp.len..], "/session-"));
        try std.testing.expect(!std.mem.eql(u8, td, classic_tmp_fallback));
        // Pure grants: rewritten path must be agent-writable under production model.
        switch (result.materials) {
            .landlock => |*p| {
                try std.testing.expect(p.compiled.isAgentWritable(td));
            },
            else => {
                var compiled = try profile.compileProfile(std.testing.allocator, .{
                    .workspace_root = root,
                });
                defer compiled.deinit();
                try std.testing.expect(compiled.isAgentWritable(td));
            },
        }
    } else {
        // Grade-drop: no rewrite (attach-only contract).
        try std.testing.expectEqualStrings("/var/folders/xx/yy/T/", env_map.get("TMPDIR").?);
    }
}

test "protect_workspace_secrets compiles into profile hash material" {
    var compiled = try profile.compileProfile(std.testing.allocator, .{
        .workspace_root = "/tmp/ryk-ws-protect",
        .include_tmp = false,
        .protect_workspace_secrets = true,
    });
    defer compiled.deinit();
    try std.testing.expect(compiled.protect_workspace_secrets);
    try std.testing.expect(std.mem.indexOf(u8, compiled.canonical_bytes, "protect_workspace_secrets\ttrue") != null);
}

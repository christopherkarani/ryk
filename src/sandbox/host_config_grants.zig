//! Narrow host-agent config grants for empty-backpack Seatbelt/Landlock.
//!
//! Empty backpack keeps `HOME=` in the child env but does **not** grant `$HOME`
//! as a filesystem tree. Known agent hosts still need their login/config roots
//! (e.g. `~/.claude`, Application Support trees) so interactive / `-p` paths do
//! not blank-hang after `sandbox=active`.
//!
//! Contract:
//! - Grant only explicit per-host subpaths that already exist on disk (home RW).
//! - Paths compile as **RW** so agents can write session/history under their own
//!   roots — still never bare `$HOME`, bare `~/Library`, or `~/.ssh`.
//! - Optional **system RO** trees (e.g. `/etc/codex`) are host-scoped, never bare
//!   `/etc`, and may be granted even when missing so open fails as ENOENT not EPERM.
//! - Optional **ancestor instruction RO** files (`AGENTS.md` / `CLAUDE.md` name
//!   spellings) on parents of the workspace up through `$HOME` — file paths only,
//!   never parent directory trees or bare `$HOME`.
//! - **Authority write-deny** paths (MCP/config.toml/settings.json templates in
//!   `HostConfigSpec`) collected cross-platform for Seatbelt literal write-deny
//!   and Landlock control-root expand (RO leaf under host RW trees).
//! - Non-host `ryk run -- /bin/echo` collects an empty list (no fail-closed).

const std = @import("std");
const builtin = @import("builtin");
const profile = @import("profile.zig");

/// Env-relative authority write-deny path template.
///
/// - `rels` empty → the absolute env value is itself the authority file path
///   (e.g. `OPENCODE_CONFIG=/path/to/company.jsonc`).
/// - `rels` non-empty → join each relative segment under the env root
///   (e.g. `CODEX_HOME` + `config.toml`).
pub const AuthorityEnvFile = struct {
    env_key: []const u8,
    rels: []const []const u8 = &.{},
};

/// Authority file under either a custom env root or a default home-relative dir.
/// Mutually exclusive: when `env_key` is set and absolute, use that root; else
/// `$HOME/{default_home_rel_dir}`. File is always `{root}/{file_name}`.
/// Used for hermes/pi single-root patterns (not accumulate-with-home).
pub const AuthorityEnvOrHome = struct {
    env_key: []const u8,
    default_home_rel_dir: []const u8,
    file_name: []const u8,
};

/// Home-relative config roots for a launch host basename (exact match).
pub const HostConfigSpec = struct {
    host: []const u8,
    /// Directory roots under `$HOME` (no leading `/`).
    home_rel_dirs: []const []const u8,
    /// Home-relative files that count as usable login material (any one non-empty).
    /// Empty list → directory presence alone is enough (weaker, host-specific).
    login_markers: []const []const u8 = &.{},
    /// Absolute system RO trees (not under `$HOME`). Host-scoped only — never bare
    /// `/etc` or `/private/etc`. Granted even when missing so Seatbelt open is
    /// ENOENT rather than EPERM (Codex requirements residual).
    system_ro_dirs: []const []const u8 = &.{},
    /// Home-relative authority files that must stay write-denied under host RW
    /// grants (MCP/config authority). Always collected when `$HOME` is absolute.
    /// Missing paths are still listed (deny invents no files but blocks create).
    authority_home_rel_files: []const []const u8 = &.{},
    /// Env-relative authority files (accumulate with home paths).
    authority_env_files: []const AuthorityEnvFile = &.{},
    /// Env-or-default-home authority files (single root, not both).
    authority_env_or_home: []const AuthorityEnvOrHome = &.{},
    /// Workspace-and-ancestor walk candidates (relative multi-component paths).
    /// Collected for every directory from workspace root up to `/`.
    authority_workspace_walk_rel: []const []const u8 = &.{},
};

/// Authoritative grant table for host-launch aliases that need host login stores.
/// Keep this tighter than scan session discovery (full config root, not only
/// `projects/` / `sessions/` leaves).
/// Paths compile as **RW** (session write under the agent root) — never bare `$HOME`.
pub const host_config_table = [_]HostConfigSpec{
    .{
        .host = "claude",
        .home_rel_dirs = &.{
            // Claude stores user/project MCP registrations in this HOME-level
            // JSON file, outside the `.claude` directory.
            ".claude.json",
            ".claude",
            // Install tree for updates/assets next to the self-contained binary.
            ".local/share/claude",
            // Claude Code / desktop OAuth + CLI node state (not bare ~/Library).
            "Library/Application Support/Claude",
            "Library/Application Support/claude-cli-nodejs",
            "Library/Caches/claude-cli-nodejs",
        },
        // OAuth / CLI login blob. Expired tokens are still "present" — hang residual
        // is host auth/network, not missing config (see empty-backpack tip on agent exit).
        .login_markers = &.{".claude/.credentials.json"},
        .authority_home_rel_files = &.{
            ".claude.json",
            ".claude/settings.json",
            ".claude/settings.local.json",
        },
        .authority_env_files = &.{
            .{ .env_key = "CLAUDE_CONFIG_DIR", .rels = &.{ "settings.json", "settings.local.json" } },
        },
        .authority_workspace_walk_rel = &.{
            ".mcp.json",
            ".claude/settings.json",
            ".claude/settings.local.json",
        },
    },
    .{
        .host = "codex",
        .home_rel_dirs = &.{
            ".codex",
            // Shared agent skills tree (codex walks ~/.agents/skills at start).
            ".agents",
        },
        .login_markers = &.{ ".codex/auth.json", ".codex/config.toml" },
        // Enterprise/system requirements under /etc/codex. macOS also has the
        // firmlink form /private/etc/codex. Never bare /etc (see collectHostSystemRoPaths).
        .system_ro_dirs = if (builtin.os.tag == .macos)
            &.{ "/etc/codex", "/private/etc/codex" }
        else
            &.{"/etc/codex"},
        .authority_home_rel_files = &.{".codex/config.toml"},
        .authority_env_files = &.{
            .{ .env_key = "CODEX_HOME", .rels = &.{"config.toml"} },
        },
        .authority_workspace_walk_rel = &.{".codex/config.toml"},
    },
    .{
        .host = "pi",
        .home_rel_dirs = &.{
            ".pi",
            // Lens + MCP extension state (sibling home roots, not under .pi). Without
            // these, extension load does mkdir EPERM and pi exits 1 after attach.
            ".pi-lens",
            ".mcp_sequential_thinking",
            // Optional MCP OAuth/cache store used by some pi extensions.
            ".mcp-auth",
        },
        .authority_env_or_home = &.{
            .{
                .env_key = "PI_CODING_AGENT_DIR",
                .default_home_rel_dir = ".pi/agent",
                .file_name = "settings.json",
            },
        },
        .authority_workspace_walk_rel = &.{".pi/settings.json"},
    },
    .{
        .host = "opencode",
        .home_rel_dirs = &.{
            // Project/instance state root (mkdir EEXIST residual when missing from
            // grant table while dir already exists on host).
            ".opencode",
            ".config/opencode",
            ".local/share/opencode",
            // Bun/OpenCode mkdir state + cache under empty backpack (EEXIST residual when
            // only config/share are granted and write/stat on siblings is denied).
            ".cache/opencode",
            ".local/state/opencode",
        },
        .authority_home_rel_files = &.{
            ".config/opencode/opencode.json",
            ".config/opencode/opencode.jsonc",
        },
        .authority_env_files = &.{
            .{ .env_key = "OPENCODE_CONFIG", .rels = &.{} },
            .{ .env_key = "OPENCODE_CONFIG_DIR", .rels = &.{ "opencode.json", "opencode.jsonc" } },
        },
        .authority_workspace_walk_rel = &.{
            "opencode.json",
            "opencode.jsonc",
            ".opencode/opencode.json",
            ".opencode/opencode.jsonc",
        },
    },
    .{
        .host = "openclaw",
        .home_rel_dirs = &.{".openclaw"},
    },
    .{
        .host = "hermes",
        .home_rel_dirs = &.{".hermes"},
        // Optional managed overlay under /etc/hermes (stat EPERM residual on empty
        // backpack). Grant missing-ok so open is ENOENT not EPERM; never bare /etc.
        .system_ro_dirs = if (builtin.os.tag == .macos)
            &.{ "/etc/hermes", "/private/etc/hermes" }
        else
            &.{"/etc/hermes"},
        .authority_env_or_home = &.{
            .{
                .env_key = "HERMES_HOME",
                .default_home_rel_dir = ".hermes",
                .file_name = "config.yaml",
            },
        },
    },
    .{
        .host = "grok",
        // Product state only — not whole ~/.grok (worktrees, agent scratch, etc.) (F19).
        // F40: do not RW-grant ~/.grok/bin (host-identity trust root — plantable privilege).
        // Grok CLI 1.0.4 opens ~/.grok/config.toml after Seatbelt attach (#194).
        // Grant the file only: Seatbelt path-walk uses ancestor metadata literals
        // on ~/.grok; do not grant the parent tree (not a trusted prefix).
        // user-settings.json stays write-denied (F218); not a 1.0.4 config-load path.
        .home_rel_dirs = &.{
            ".grok/config.toml",
            ".grok/skills",
            ".grok/hooks",
            ".grok/sessions",
            ".grok/plugins",
            ".grok/mcp",
        },
        .authority_home_rel_files = &.{
            ".grok/config.toml",
            ".grok/user-settings.json",
        },
    },
};

/// Basename of argv0 (`claude`, or `…/claude` → `claude`). Empty if no basename.
pub fn hostBasename(argv0: []const u8) []const u8 {
    if (argv0.len == 0) return "";
    return std.fs.path.basename(argv0);
}

/// Lookup table entry for an exact host basename, or null.
pub fn specForHost(host: []const u8) ?*const HostConfigSpec {
    if (host.len == 0) return null;
    for (&host_config_table) |*spec| {
        if (std.mem.eql(u8, spec.host, host)) return spec;
    }
    return null;
}

/// True when a home-relative segment list is unsafe (empty, `.`, `..`).
pub fn relHasUnsafeComponents(rel: []const u8) bool {
    if (rel.len == 0) return true;
    var it = std.mem.splitScalar(u8, rel, '/');
    while (it.next()) |part| {
        if (part.len == 0) continue; // tolerate accidental //
        if (std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return true;
    }
    return false;
}

/// True when `path` is forbidden as a host-config grant (root, bare home, .ssh,
/// bare Library / Application Support). `path` must be absolute; callers should
/// pass lexically cleaned paths (no `..` components — see `relHasUnsafeComponents`).
pub fn isForbiddenHostConfigPath(path: []const u8, home: []const u8) bool {
    if (path.len == 0) return true;
    if (path.len == 1 and path[0] == '/') return true;
    if (home.len > 0 and std.mem.eql(u8, path, home)) return true;
    // Never grant classic secret / over-broad home trees even if a table drifts.
    if (home.len > 0 and std.mem.startsWith(u8, path, home) and
        (path.len == home.len or path[home.len] == '/'))
    {
        const rest = if (path.len > home.len) path[home.len + 1 ..] else "";
        if (std.mem.eql(u8, rest, ".ssh") or std.mem.startsWith(u8, rest, ".ssh/")) return true;
        if (std.mem.eql(u8, rest, ".gnupg") or std.mem.startsWith(u8, rest, ".gnupg/")) return true;
        if (std.mem.eql(u8, rest, ".aws") or std.mem.startsWith(u8, rest, ".aws/")) return true;
        // Bare Library / Application Support / Keychains / Cookies would open host secrets.
        if (std.mem.eql(u8, rest, "Library") or
            std.mem.eql(u8, rest, "Library/Application Support") or
            std.mem.eql(u8, rest, "Library/Caches") or
            std.mem.eql(u8, rest, "Library/Keychains") or
            std.mem.startsWith(u8, rest, "Library/Keychains/") or
            std.mem.eql(u8, rest, "Library/Cookies") or
            std.mem.startsWith(u8, rest, "Library/Cookies/"))
            return true;
    }
    return false;
}

fn canonicalExistingPath(
    io: std.Io,
    allocator: std.mem.Allocator,
    path: []const u8,
) error{OutOfMemory}!?[]u8 {
    const canonical_z = std.Io.Dir.cwd().realPathFileAlloc(io, path, allocator) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return null,
    };
    // realPathFileAlloc returns a sentinel slice ([:0]u8 over a len+1 allocation);
    // dupe to shed the sentinel so callers free with the exact visible length.
    defer allocator.free(canonical_z);
    return try allocator.dupe(u8, canonical_z);
}

/// Collect owned absolute host-config grant paths for a **trusted** table host key.
///
/// - `host` must already be a trusted `host_config_table` key (from
///   `host_identity.resolveHostIdentity`). Do not pass raw argv0 / basename.
/// - Empty when host is unknown, HOME is empty, or no listed roots exist.
/// - Skips missing paths (caller may fail closed when a known host has zero grants
///   and no provider gateway).
/// - Never returns bare HOME or `.ssh`.
/// - Callers compile these as `.rw` (session write) — still narrow trees only.
///
/// Caller frees with `freeHostConfigPaths`.
pub fn collectHostConfigPaths(
    io: std.Io,
    allocator: std.mem.Allocator,
    host: []const u8,
    home: []const u8,
) error{OutOfMemory}![]const []const u8 {
    const spec = specForHost(host) orelse {
        return try allocator.alloc([]const u8, 0);
    };
    if (home.len == 0 or !std.fs.path.isAbsolute(home)) {
        return try allocator.alloc([]const u8, 0);
    }
    // Note: do not call isForbiddenHostConfigPath(home, home) — bare HOME is always
    // "forbidden as a grant", which would empty the list before any subpath is considered.
    const canonical_home = (try canonicalExistingPath(io, allocator, home)) orelse
        return try allocator.alloc([]const u8, 0);
    defer allocator.free(canonical_home);

    var list: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (list.items) |p| allocator.free(p);
        list.deinit(allocator);
    }

    for (spec.home_rel_dirs) |rel| {
        if (rel.len == 0) continue;
        // Reject traversal / self-ref components before join (forbid filter is stringy).
        if (relHasUnsafeComponents(rel)) continue;
        const joined = try std.fs.path.join(allocator, &.{ home, rel });
        defer allocator.free(joined);
        if (isForbiddenHostConfigPath(joined, home)) continue;

        // Only grant paths that exist (dir or file). Missing → skip.
        // Open with no-follow first for existence of the named node when possible;
        // fall back to follow-open for plain files/dirs that pathExists already covers.
        if (!pathExists(io, joined)) continue;

        // Landlock installs PATH_BENEATH rules against resolved targets. Seal the
        // same canonical path here and revalidate it against the canonical HOME
        // boundary so a host-side `.claude -> ~/.ssh` (or outside-HOME) symlink
        // cannot retarget a narrow grant.
        const canonical = (try canonicalExistingPath(io, allocator, joined)) orelse continue;
        if (!profile.isPathWithin(canonical, canonical_home) or
            isForbiddenHostConfigPath(canonical, canonical_home))
        {
            allocator.free(canonical);
            continue;
        }

        // Dedup exact strings.
        var exists = false;
        for (list.items) |existing| {
            if (std.mem.eql(u8, existing, canonical)) {
                exists = true;
                break;
            }
        }
        if (exists) {
            allocator.free(canonical);
            continue;
        }

        list.append(allocator, canonical) catch |err| {
            allocator.free(canonical);
            return err;
        };
    }

    return try list.toOwnedSlice(allocator);
}

pub fn freeHostConfigPaths(allocator: std.mem.Allocator, paths: []const []const u8) void {
    for (paths) |p| allocator.free(p);
    allocator.free(paths);
}

/// True when `path` must never be granted as host system RO (root, bare `/etc`,
/// bare `/private/etc`, or non-absolute). Defends against table drift.
pub fn isForbiddenSystemRoPath(path: []const u8) bool {
    if (path.len == 0) return true;
    if (!std.fs.path.isAbsolute(path)) return true;
    if (path.len == 1 and path[0] == '/') return true;
    // Bare system config / firmlink roots — only host-scoped leaves are allowed.
    if (std.mem.eql(u8, path, "/etc") or std.mem.eql(u8, path, "/private/etc")) return true;
    if (std.mem.eql(u8, path, "/private") or std.mem.eql(u8, path, "/var") or
        std.mem.eql(u8, path, "/private/var"))
        return true;
    // No traversal / self-ref in the absolute path.
    if (relHasUnsafeComponents(path[1..])) return true;
    return false;
}

/// Collect owned absolute **system RO** grant paths for a **trusted** table host key.
///
/// Unlike home-config RW, paths are granted **even when missing** so open under
/// Seatbelt returns ENOENT (agent soft-skip) instead of EPERM (fatal for Codex
/// `/etc/codex/requirements.toml`). Never returns bare `/etc` or `/private/etc`.
///
/// Caller frees with `freeHostSystemRoPaths` (same shape as host-config paths).
pub fn collectHostSystemRoPaths(
    allocator: std.mem.Allocator,
    host: []const u8,
) error{OutOfMemory}![]const []const u8 {
    const spec = specForHost(host) orelse {
        return try allocator.alloc([]const u8, 0);
    };
    if (spec.system_ro_dirs.len == 0) {
        return try allocator.alloc([]const u8, 0);
    }

    var list: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (list.items) |p| allocator.free(p);
        list.deinit(allocator);
    }

    for (spec.system_ro_dirs) |raw| {
        if (isForbiddenSystemRoPath(raw)) continue;

        var exists = false;
        for (list.items) |existing| {
            if (std.mem.eql(u8, existing, raw)) {
                exists = true;
                break;
            }
        }
        if (exists) continue;

        const owned = try allocator.dupe(u8, raw);
        list.append(allocator, owned) catch |err| {
            allocator.free(owned);
            return err;
        };
    }

    return try list.toOwnedSlice(allocator);
}

pub fn freeHostSystemRoPaths(allocator: std.mem.Allocator, paths: []const []const u8) void {
    freeHostConfigPaths(allocator, paths);
}

/// Collect absolute authority config paths that must remain write-denied under
/// host RW grants (MCP / config authority files).
///
/// `host` must already be a trusted table key (from `host_identity.resolveHostIdentity`).
///
/// Cross-platform: used as Seatbelt `launch_write_deny_literals` on macOS and as
/// extra `control_roots` on all platforms so Landlock control-expand keeps these
/// paths RO under host RW trees. Missing paths are still listed so create-via-RW
/// is blocked. Hardlinked existing files fail closed (`UnsafeHostConfigHardlink`).
///
/// Caller frees with `freeHostConfigPaths`.
pub fn collectHostConfigWriteDenies(
    io: std.Io,
    allocator: std.mem.Allocator,
    host: []const u8,
    workspace_root: []const u8,
    env_map: *const std.process.Environ.Map,
) error{ OutOfMemory, UnsafeHostConfigHardlink }![]const []const u8 {
    const spec = specForHost(host) orelse return try allocator.alloc([]const u8, 0);

    var paths: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (paths.items) |path| allocator.free(path);
        paths.deinit(allocator);
    }

    const home = env_map.get("HOME") orelse "";

    // Home-relative authority files (always when home is absolute).
    if (std.fs.path.isAbsolute(home)) {
        for (spec.authority_home_rel_files) |rel| {
            if (rel.len == 0 or relHasUnsafeComponents(rel)) continue;
            try appendAuthorityPath(allocator, &paths, &.{ home, rel });
        }
    }

    // Env-relative authority files (accumulate).
    for (spec.authority_env_files) |entry| {
        const configured = env_map.get(entry.env_key) orelse continue;
        if (!std.fs.path.isAbsolute(configured)) continue;
        if (entry.rels.len == 0) {
            try appendAuthorityPath(allocator, &paths, &.{configured});
            continue;
        }
        for (entry.rels) |rel| {
            if (rel.len == 0 or relHasUnsafeComponents(rel)) continue;
            try appendAuthorityPath(allocator, &paths, &.{ configured, rel });
        }
    }

    // Env-or-default-home (hermes/pi): one root only.
    for (spec.authority_env_or_home) |entry| {
        if (entry.file_name.len == 0 or relHasUnsafeComponents(entry.file_name)) continue;
        if (entry.default_home_rel_dir.len == 0 or relHasUnsafeComponents(entry.default_home_rel_dir)) continue;
        const env_root = env_map.get(entry.env_key);
        if (env_root) |root| {
            if (std.fs.path.isAbsolute(root)) {
                try appendAuthorityPath(allocator, &paths, &.{ root, entry.file_name });
            }
            continue;
        }
        if (std.fs.path.isAbsolute(home)) {
            try appendAuthorityPath(allocator, &paths, &.{ home, entry.default_home_rel_dir, entry.file_name });
        }
    }

    // Project configuration is writable through the workspace grant. Protect
    // every candidate authority file, including missing files, so a running
    // agent cannot add a direct MCP launch path for this or the next session.
    if (std.fs.path.isAbsolute(workspace_root) and spec.authority_workspace_walk_rel.len > 0) {
        var current = workspace_root;
        while (true) {
            for (spec.authority_workspace_walk_rel) |rel| {
                if (rel.len == 0 or relHasUnsafeComponents(rel)) continue;
                try appendAuthorityPath(allocator, &paths, &.{ current, rel });
            }
            const parent = std.fs.path.dirname(current) orelse break;
            if (std.mem.eql(u8, parent, current)) break;
            current = parent;
        }
    }

    // Also deny an existing symlink target so lexical aliases cannot retain
    // configuration-write authority through the broader host RW grant.
    // Hardlinked authority files fail closed — incomplete write boundary.
    const original_count = paths.items.len;
    for (paths.items[0..original_count]) |path| {
        const file = std.Io.Dir.openFileAbsolute(io, path, .{}) catch continue;
        const stat = file.stat(io) catch {
            file.close(io);
            continue;
        };
        file.close(io);
        if (stat.nlink > 1) return error.UnsafeHostConfigHardlink;
        const canonical_z = std.Io.Dir.cwd().realPathFileAlloc(io, path, allocator) catch continue;
        defer allocator.free(canonical_z);
        if (!containsAuthorityPath(paths.items, canonical_z)) {
            try appendAuthorityPath(allocator, &paths, &.{canonical_z});
        }
    }
    return try paths.toOwnedSlice(allocator);
}

pub fn freeHostConfigWriteDenies(allocator: std.mem.Allocator, paths: []const []const u8) void {
    freeHostConfigPaths(allocator, paths);
}

fn appendAuthorityPath(
    allocator: std.mem.Allocator,
    paths: *std.ArrayList([]const u8),
    components: []const []const u8,
) error{OutOfMemory}!void {
    const path = try std.fs.path.join(allocator, components);
    if (containsAuthorityPath(paths.items, path)) {
        allocator.free(path);
        return;
    }
    paths.append(allocator, path) catch |err| {
        allocator.free(path);
        return err;
    };
}

fn containsAuthorityPath(paths: []const []const u8, candidate: []const u8) bool {
    for (paths) |path| if (std.mem.eql(u8, path, candidate)) return true;
    return false;
}

/// Basenames coding agents walk up for project/user instruction files.
/// Matches pi (`AGENTS.md` / `AGENTS.MD` / `CLAUDE.md` / `CLAUDE.MD`) and common
/// Claude Code / Codex discovery. Both case spellings are listed so case-sensitive
/// Seatbelt literals cover case-insensitive volumes where agents stat both names.
pub const ancestor_instruction_basenames = [_][]const u8{
    "AGENTS.md",
    "AGENTS.MD",
    "CLAUDE.md",
    "CLAUDE.MD",
};

/// Cap ancestor walk depth (workspace parent → home). Defends runaway paths.
pub const max_ancestor_instruction_depth: usize = 48;

/// Cap owned RO paths returned (basename × depth upper bound is small).
pub const max_ancestor_instruction_paths: usize = 32;

/// Collect existing ancestor instruction files as narrow **RO** grant paths.
///
/// Agents (pi, Claude, …) walk from cwd toward `/` looking for `AGENTS.md` /
/// `CLAUDE.md`. Empty backpack grants workspace RW only, so a parent multi-repo
/// file (e.g. `~/CodingProjects/AGENTS.md` when workspace is `…/CodingProjects/ryk`)
/// would otherwise EPERM and print noisy warnings.
///
/// Contract:
/// - Starts at `dirname(workspace_root)` (workspace itself is already RW).
/// - Walks toward `/`, stopping after processing `$HOME` when home is absolute
///   and an ancestor of the workspace; otherwise stops at FS root / depth cap.
/// - Grants **regular files only** for `ancestor_instruction_basenames`.
/// - Never returns bare `$HOME`, parent directories, or secret trees.
/// - Missing files are skipped (no invent). Symlinks that retarget outside the
///   approved ancestor directory are skipped.
///
/// Caller frees with `freeHostSystemRoPaths` (same ownership as other RO lists).
pub fn collectAncestorInstructionRoPaths(
    io: std.Io,
    allocator: std.mem.Allocator,
    workspace_root: []const u8,
    home: []const u8,
) error{OutOfMemory}![]const []const u8 {
    if (workspace_root.len == 0 or !std.fs.path.isAbsolute(workspace_root)) {
        return try allocator.alloc([]const u8, 0);
    }

    var list: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (list.items) |p| allocator.free(p);
        list.deinit(allocator);
    }

    // Lexically clean workspace (no `..`) so dirname walk is stable.
    const ws = try std.fs.path.resolve(allocator, &.{workspace_root});
    defer allocator.free(ws);
    if (ws.len <= 1) return try list.toOwnedSlice(allocator);

    const home_abs: []const u8 = blk: {
        if (home.len == 0 or !std.fs.path.isAbsolute(home)) break :blk "";
        const cleaned = std.fs.path.resolve(allocator, &.{home}) catch break :blk "";
        break :blk cleaned;
    };
    defer if (home_abs.len > 0) allocator.free(home_abs);
    const canonical_home: ?[]u8 = if (home_abs.len > 0)
        (try canonicalExistingPath(io, allocator, home_abs)) orelse
            return try list.toOwnedSlice(allocator)
    else
        null;
    defer if (canonical_home) |path| allocator.free(path);

    var current = std.fs.path.dirname(ws) orelse return try list.toOwnedSlice(allocator);
    var depth: usize = 0;
    while (depth < max_ancestor_instruction_depth) : (depth += 1) {
        if (current.len == 0) break;
        // Never grant under classic secret segments even if a basename matches.
        if (pathContainsMacosSecretSegment(current) or pathContainsUnixSecretSegment(current)) {
            if (shouldStopAncestorWalk(current, home_abs)) break;
            current = std.fs.path.dirname(current) orelse break;
            continue;
        }
        const canonical_current = (try canonicalExistingPath(io, allocator, current)) orelse {
            // Ancestor dir not canonically resolvable: no candidate inside it can
            // be verified against its canonical parent, so nothing here grants.
            if (shouldStopAncestorWalk(current, home_abs)) break;
            current = std.fs.path.dirname(current) orelse break;
            continue;
        };
        defer allocator.free(canonical_current);

        for (ancestor_instruction_basenames) |base| {
            if (list.items.len >= max_ancestor_instruction_paths) break;
            const candidate = try std.fs.path.join(allocator, &.{ current, base });
            defer allocator.free(candidate);
            // Fast lexical rejection only. The canonical target check below is
            // the security boundary and handles symlinks and macOS path aliases.
            if (home_abs.len > 0 and isForbiddenHostConfigPath(candidate, home_abs)) continue;
            if (!regularFileExists(io, candidate)) continue;

            const canonical = (try canonicalExistingPath(io, allocator, candidate)) orelse continue;
            const canonical_parent = std.fs.path.dirname(canonical) orelse {
                allocator.free(canonical);
                continue;
            };
            if (!std.mem.eql(u8, canonical_parent, canonical_current)) {
                allocator.free(canonical);
                continue;
            }
            if (canonical_home) |approved_home| {
                if (profile.isPathWithin(canonical, approved_home) and
                    isForbiddenHostConfigPath(canonical, approved_home))
                {
                    allocator.free(canonical);
                    continue;
                }
            }

            var exists = false;
            for (list.items) |existing| {
                if (std.mem.eql(u8, existing, canonical)) {
                    exists = true;
                    break;
                }
            }
            if (exists) {
                allocator.free(canonical);
                continue;
            }

            list.append(allocator, canonical) catch |err| {
                allocator.free(canonical);
                return err;
            };
        }

        if (shouldStopAncestorWalk(current, home_abs)) break;
        if (current.len == 1 and current[0] == '/') break;
        current = std.fs.path.dirname(current) orelse break;
    }

    return try list.toOwnedSlice(allocator);
}

fn shouldStopAncestorWalk(current: []const u8, home_abs: []const u8) bool {
    if (current.len == 1 and current[0] == '/') return true;
    if (home_abs.len == 0) return false;
    // Stop after processing home itself (include ~/AGENTS.md, not parents of home).
    if (std.mem.eql(u8, current, home_abs)) return true;
    // If workspace is outside home, do not walk unbounded — stop at home boundary
    // only when current is still under home; otherwise continue until root/depth.
    return false;
}

fn pathContainsUnixSecretSegment(path: []const u8) bool {
    const banned = [_][]const u8{
        "/.ssh/",
        "/.gnupg/",
        "/.aws/",
        "/.ssh",
        "/.gnupg",
        "/.aws",
    };
    for (banned) |b| {
        if (std.mem.indexOf(u8, path, b) != null) {
            // Require segment boundary: "/.ssh" at end or followed by '/'.
            if (b[b.len - 1] == '/') return true;
            const at = std.mem.indexOf(u8, path, b).?;
            const end = at + b.len;
            if (end == path.len or path[end] == '/') return true;
        }
    }
    return false;
}

fn regularFileExists(io: std.Io, path: []const u8) bool {
    if (path.len == 0) return false;
    const file = std.Io.Dir.cwd().openFile(io, path, .{}) catch return false;
    defer file.close(io);
    const st = file.stat(io) catch return false;
    return st.kind == .file;
}

/// True when `path` is a safe Apple developer-toolchain root to grant RO under Seatbelt.
///
/// `/usr/bin/git` (and many other Apple stubs) are thin `libxcselect` wrappers that
/// open the active Xcode / Command Line Tools tree. Empty-backpack system RO does
/// not cover `/Applications` or bare `/Library/Developer`, so agents that spawn
/// `git` hit a blocked open and macOS may show the false “install developer tools”
/// dialog. These allowlisted roots fix that without bare `/Applications` or HOME.
pub fn isAllowlistedMacosDeveloperToolchainPath(path: []const u8) bool {
    if (path.len == 0 or !std.fs.path.isAbsolute(path)) return false;
    if (path.len == 1 and path[0] == '/') return false;
    // No `..` / `.` components (path is absolute — strip leading `/` for the check).
    if (relHasUnsafeComponents(path[1..])) return false;
    if (pathContainsMacosSecretSegment(path)) return false;

    // Standalone CLT install (not bare `/Library/Developer`).
    if (std.mem.eql(u8, path, "/Library/Developer/CommandLineTools")) return true;

    // Any Xcode.app (or beta / renamed) developer dir — under /Applications or a
    // user install path. Never bare `/Applications` or whole `$HOME`.
    // Examples: /Applications/Xcode.app/Contents/Developer
    //           /Applications/Xcode-beta.app/Contents/Developer
    const developer_suffix = ".app/Contents/Developer";
    if (std.mem.endsWith(u8, path, developer_suffix)) {
        const prefix = path[0 .. path.len - developer_suffix.len];
        if (prefix.len == 0) return false;
        // Require the last component of prefix to be a non-empty app name (no slash at end).
        if (std.mem.endsWith(u8, prefix, "/")) return false;
        return true;
    }
    return false;
}

/// Prefer CLT when present (smaller surface, no Xcode license/framework residual).
/// Otherwise the first collected toolchain path. Used to pin `DEVELOPER_DIR` in
/// the agent child so libxcselect does not need broken/host select links.
pub fn preferredMacosDeveloperDir(paths: []const []const u8) ?[]const u8 {
    for (paths) |p| {
        if (std.mem.eql(u8, p, "/Library/Developer/CommandLineTools")) return p;
    }
    if (paths.len > 0) return paths[0];
    return null;
}

/// Collect existing Apple developer-toolchain roots for RO+exec under empty backpack.
///
/// Host-agnostic (opencode, hermes, claude, generic `ryk run -- git`, …). Only
/// allowlisted paths that exist on disk. Sources: `DEVELOPER_DIR`, xcode-select
/// data links under `/var/select` + `/var/db`, and known default install roots.
/// Never invents missing trees.
///
/// Non-macOS → empty slice. Caller frees with `freeHostSystemRoPaths`.
pub fn collectMacosDeveloperToolchainRoPaths(
    io: std.Io,
    allocator: std.mem.Allocator,
    env_map: ?*const std.process.Environ.Map,
) error{OutOfMemory}![]const []const u8 {
    if (builtin.os.tag != .macos) {
        return try allocator.alloc([]const u8, 0);
    }

    var list: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (list.items) |p| allocator.free(p);
        list.deinit(allocator);
    }

    // Prefer an explicit DEVELOPER_DIR when the parent already set one (xcode-select).
    if (env_map) |map| {
        if (map.get("DEVELOPER_DIR")) |raw| {
            try appendMacosDeveloperToolchainIfOk(io, allocator, &list, raw);
        }
    }

    // Active select links (parent-side readlink — not sandboxed). Targets may be
    // dangling (stale Downloads installs); only grant when the target exists.
    const select_links = [_][]const u8{
        "/var/select/developer_dir",
        "/private/var/select/developer_dir",
        "/var/db/xcode_select_link",
        "/private/var/db/xcode_select_link",
    };
    for (select_links) |link| {
        try appendMacosDeveloperToolchainFromSymlink(io, allocator, &list, link);
    }

    // Stable known roots — grant only when present.
    const known = [_][]const u8{
        "/Library/Developer/CommandLineTools",
        "/Applications/Xcode.app/Contents/Developer",
        "/Applications/Xcode-beta.app/Contents/Developer",
    };
    for (known) |raw| {
        try appendMacosDeveloperToolchainIfOk(io, allocator, &list, raw);
    }

    return try list.toOwnedSlice(allocator);
}

fn pathContainsMacosSecretSegment(path: []const u8) bool {
    // Keep toolchain grants out of classic secret trees even under custom Xcode paths.
    const banned = [_][]const u8{
        "/.ssh/",
        "/.gnupg/",
        "/.aws/",
        "/Library/Keychains/",
        "/Library/Cookies/",
    };
    for (banned) |b| {
        if (std.mem.indexOf(u8, path, b) != null) return true;
    }
    return false;
}

fn appendMacosDeveloperToolchainFromSymlink(
    io: std.Io,
    allocator: std.mem.Allocator,
    list: *std.ArrayList([]const u8),
    link_path: []const u8,
) error{OutOfMemory}!void {
    var target_buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = std.Io.Dir.readLinkAbsolute(io, link_path, &target_buf) catch return;
    try appendMacosDeveloperToolchainIfOk(io, allocator, list, target_buf[0..n]);
}

fn appendMacosDeveloperToolchainIfOk(
    io: std.Io,
    allocator: std.mem.Allocator,
    list: *std.ArrayList([]const u8),
    raw: []const u8,
) error{OutOfMemory}!void {
    // Trim trailing slashes for stable allowlist + dedup (except root, already rejected).
    var path = raw;
    while (path.len > 1 and path[path.len - 1] == '/') {
        path = path[0 .. path.len - 1];
    }
    if (!isAllowlistedMacosDeveloperToolchainPath(path)) return;
    if (!pathExists(io, path)) return;

    for (list.items) |existing| {
        if (std.mem.eql(u8, existing, path)) return;
    }

    const owned = try allocator.dupe(u8, path);
    list.append(allocator, owned) catch |err| {
        allocator.free(owned);
        return err;
    };
}

/// True when a known host has at least one listed config root present under home.
/// `host` is a trusted table key (not raw argv0).
pub fn hostConfigPresent(
    io: std.Io,
    host: []const u8,
    home: []const u8,
) bool {
    const spec = specForHost(host) orelse return false;
    if (home.len == 0 or !std.fs.path.isAbsolute(home)) return false;
    for (spec.home_rel_dirs) |rel| {
        if (rel.len == 0 or relHasUnsafeComponents(rel)) continue;
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const joined = std.fmt.bufPrint(&buf, "{s}/{s}", .{ home, rel }) catch continue;
        if (isForbiddenHostConfigPath(joined, home)) continue;
        if (pathExists(io, joined)) return true;
    }
    return false;
}

/// True when a non-empty login marker file is readable, or (if the host has no
/// markers) when a config root exists. Config dir alone is not enough for Claude.
/// `host` is a trusted table key (not raw argv0).
pub fn hostLoginMaterialPresent(
    io: std.Io,
    host: []const u8,
    home: []const u8,
) bool {
    const spec = specForHost(host) orelse return false;
    if (home.len == 0 or !std.fs.path.isAbsolute(home)) return false;
    if (spec.login_markers.len == 0) return hostConfigPresent(io, host, home);
    for (spec.login_markers) |rel| {
        if (rel.len == 0 or relHasUnsafeComponents(rel)) continue;
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const joined = std.fmt.bufPrint(&buf, "{s}/{s}", .{ home, rel }) catch continue;
        if (isForbiddenHostConfigPath(joined, home)) continue;
        if (nonEmptyFileExists(io, joined)) return true;
    }
    return false;
}

fn nonEmptyFileExists(io: std.Io, path: []const u8) bool {
    if (path.len == 0) return false;
    const file = std.Io.Dir.cwd().openFile(io, path, .{}) catch return false;
    defer file.close(io);
    const st = file.stat(io) catch return false;
    return st.size > 0;
}

/// Claude OAuth access-token expiry when readable. Other hosts always `.unknown`.
/// Does not log or return token bytes — only the freshness class.
pub const LoginFreshness = enum {
    /// No marker / unreadable / not applicable.
    unknown,
    /// Marker present; no expiry field or not yet expired.
    fresh,
    /// `claudeAiOauth.expiresAt` (unix ms) is in the past.
    expired,
};

/// Best-effort Claude credential freshness. Never loads secrets into the return value.
pub fn claudeLoginFreshness(io: std.Io, home: []const u8) LoginFreshness {
    if (home.len == 0 or !std.fs.path.isAbsolute(home)) return .unknown;
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "{s}/.claude/.credentials.json", .{home}) catch return .unknown;
    if (isForbiddenHostConfigPath(path, home)) return .unknown;

    // Bound read — credentials files are small; never log body contents.
    const file = std.Io.Dir.cwd().openFile(io, path, .{}) catch return .unknown;
    defer file.close(io);
    var buf: [64 * 1024]u8 = undefined;
    const n = file.readPositionalAll(io, &buf, 0) catch return .unknown;
    if (n == 0) return .unknown;
    const body = buf[0..n];

    // Minimal structural parse: find "expiresAt" numeric (ms since epoch).
    const key = "\"expiresAt\"";
    const key_at = std.mem.indexOf(u8, body, key) orelse return .fresh; // present file, no field
    var i = key_at + key.len;
    while (i < body.len and (body[i] == ' ' or body[i] == '\t' or body[i] == '\n' or body[i] == '\r' or body[i] == ':')) : (i += 1) {}
    if (i >= body.len or body[i] < '0' or body[i] > '9') return .fresh;
    var exp: u64 = 0;
    while (i < body.len and body[i] >= '0' and body[i] <= '9') : (i += 1) {
        const digit: u64 = body[i] - '0';
        exp = exp *% 10 +% digit;
    }
    if (exp == 0) return .fresh;
    // expiresAt is milliseconds; Io wall clock is seconds.
    const now_s = std.Io.Timestamp.now(io, .real).toSeconds();
    if (now_s < 0) return .fresh;
    const now_ms: u64 = @as(u64, @intCast(now_s)) * 1000;
    if (exp < now_ms) return .expired;
    return .fresh;
}

/// Usable auth markers present (non-empty login files / config roots). Does **not**
/// reject expired OAuth — use `claudeLoginFreshness` + `isAgentHelpOrVersionOnly`
/// so `--help` still works under empty backpack with stale credentials.
/// `host` is a trusted table key (not raw argv0).
pub fn hostUsableAuthPresent(
    io: std.Io,
    host: []const u8,
    home: []const u8,
) bool {
    return hostLoginMaterialPresent(io, host, home);
}

/// True when argv after the binary is only help/version flags (no prompt / -p).
/// Bare interactive (`claude` alone) is **not** help-only.
///
/// `ryk <host> -- --help` keeps the `--` separator in `command_argv`. Treat `--`
/// as argv punctuation, not a payload flag, but still require a real help/version
/// token so bare `["grok", "--"]` stays interactive (empty-backpack fail-closed).
pub fn isAgentHelpOrVersionOnly(command_argv: []const []const u8) bool {
    if (command_argv.len < 2) return false;
    var saw_help = false;
    for (command_argv[1..]) |arg| {
        if (std.mem.eql(u8, arg, "--")) continue;
        if (std.mem.eql(u8, arg, "--help") or
            std.mem.eql(u8, arg, "-h") or
            std.mem.eql(u8, arg, "help") or
            std.mem.eql(u8, arg, "--version") or
            std.mem.eql(u8, arg, "-v") or
            std.mem.eql(u8, arg, "version") or
            std.mem.eql(u8, arg, "-V"))
        {
            saw_help = true;
            continue;
        }
        return false;
    }
    return saw_help;
}

/// True when Claude OAuth is known-expired and the launch is not help/version-only.
/// Call only after marker presence has already passed for a **trusted** claude host.
pub fn shouldFailClosedStaleClaudeLogin(
    io: std.Io,
    host: []const u8,
    command_argv: []const []const u8,
    home: []const u8,
    has_anthropic_gateway: bool,
) bool {
    if (has_anthropic_gateway) return false;
    if (!std.mem.eql(u8, host, "claude")) return false;
    if (command_argv.len == 0) return false;
    if (isAgentHelpOrVersionOnly(command_argv)) return false;
    return claudeLoginFreshness(io, home) == .expired;
}

/// True when `path` exists as a directory or regular openable file.
fn pathExists(io: std.Io, path: []const u8) bool {
    if (path.len == 0) return false;
    var dir = std.Io.Dir.openDirAbsolute(io, path, .{}) catch {
        const file = std.Io.Dir.cwd().openFile(io, path, .{}) catch return false;
        file.close(io);
        return true;
    };
    dir.close(io);
    return true;
}

/// Static stderr guidance when empty backpack cannot offer host login or gateway.
pub const missing_config_fail_closed_message =
    \\ryk run: empty-backpack OS sandbox cannot read host agent login/config under $HOME.
    \\No usable host login material was found (for example ~/.claude/.credentials.json) and no matching provider gateway is active.
    \\Fix one of:
    \\  • run the agent once outside ryk to create host login (e.g. `claude` then login), then retry
    \\  • for Claude: export ANTHROPIC_API_KEY; for Codex: export OPENAI_API_KEY (host-matched gateway)
    \\  • escape with `ryk run --with-host-secrets -- <agent>` (loud; may expose host secrets)
    \\See docs/credentials.md
    \\
;

/// When Claude credentials exist but the OAuth access token is past expiresAt.
pub const stale_login_fail_closed_message =
    \\ryk run: empty-backpack found Claude login material, but the OAuth access token is expired (expiresAt in the past).
    \\Without a host-matched Anthropic gateway this often blank-hangs after sandbox=active.
    \\Fix one of:
    \\  • re-login outside ryk (`claude` then login) so ~/.claude/.credentials.json is fresh
    \\  • export ANTHROPIC_API_KEY (host-matched gateway under empty backpack)
    \\  • escape with `ryk run --with-host-secrets -- claude` (loud; may expose host secrets)
    \\See docs/credentials.md
    \\
;

/// Primary tip when parent stdout/stderr path is under classic ungranted host tmp
/// (inherited shell redirects). Leads with stdio/fstat residual — not re-login.
pub const empty_backpack_stdio_fstat_exit_tip =
    \\ryk run: empty-backpack: agent died after sandbox attach — redirected stdout/stderr lands under classic /tmp or /var/folders, which Seatbelt does not grant. Bun/Node fstat on those FDs fails (EPERM / process.stderr.fd). Capture under the workspace (e.g. .ryk-tmp), use a pipe, or a TTY. Do not treat this as missing login first. Keychain FS is not granted (by design).
    \\
;

/// Tip when agent output shows Seatbelt path-walk residual (EPERM on lstat/realpath
/// of path parents). Prefer this over re-login when the stack is clear.
pub const empty_backpack_pathwalk_exit_tip =
    \\ryk run: empty-backpack: agent died after sandbox attach — Seatbelt path-walk residual (EPERM on lstat/realpath of a path parent such as /Users). This is an OS-sandbox filesystem residual, not missing host login. If it persists on a current ryk build, report it; do not re-login first. Keychain FS is not granted (by design).
    \\
;

/// Tip when agent output shows system-config RO residual (`/etc/codex` EPERM).
pub const empty_backpack_system_ro_exit_tip =
    \\ryk run: empty-backpack: agent died after sandbox attach — system config RO residual (EPERM reading /etc/codex or requirements.toml). This is an OS-sandbox filesystem residual, not missing host login. If it persists on a current ryk build, report it; do not re-login first. Bare /etc is not granted (by design).
    \\
;

/// Generic tip when empty-backpack agent exits non-zero without a more specific residual.
pub const empty_backpack_agent_exit_tip =
    \\ryk run: empty-backpack tip: agent exited non-zero after sandbox attach. Common causes: Seatbelt path-walk EPERM (lstat/realpath on path parents), redirected stdio into /tmp or /var/folders (fstat denials — capture under the workspace), system config RO residual (/etc/codex), TLS UnknownIssuer (system CA inject missing), stale host auth (re-login outside ryk), missing host-matched API key for gateway, or --with-host-secrets (loud). Keychain FS is not granted (by design).
    \\
;

/// Pre-spawn warning when parent stdio already points at ungranted host tmp.
pub const empty_backpack_stdio_host_tmp_warn =
    \\ryk run: warning: stdout/stderr appear redirected under /tmp or /var/folders; empty-backpack Seatbelt may deny agent fstat on those FDs. Prefer workspace capture, pipe, or TTY.
    \\
;

/// True when `path` is classic host temp content empty backpack does not grant.
/// Bootstrap may allow the literal `/private/tmp` directory node only — not tree contents.
pub fn pathIsUngrantedHostTmpContent(path: []const u8) bool {
    if (path.len == 0) return false;
    if (std.mem.eql(u8, path, "/tmp") or std.mem.eql(u8, path, "/private/tmp")) return true;
    if (std.mem.startsWith(u8, path, "/tmp/")) return true;
    if (std.mem.startsWith(u8, path, "/private/tmp/")) return true;
    if (std.mem.startsWith(u8, path, "/var/folders/")) return true;
    if (std.mem.startsWith(u8, path, "/private/var/folders/")) return true;
    return false;
}

/// Resolve a pathname for an open FD when the platform supports it.
/// macOS: F_GETPATH. Linux: /proc/self/fd/N. Other: null.
/// Caller must pass a buffer of at least `std.fs.max_path_bytes` (Darwin F_GETPATH
/// writes up to PATH_MAX; a short buffer would be a length-blind kernel write).
pub fn resolveFdPathname(io: std.Io, fd: std.posix.fd_t, buf: []u8) ?[]const u8 {
    if (buf.len < std.fs.max_path_bytes) return null;
    switch (builtin.os.tag) {
        .macos, .ios, .tvos, .watchos, .visionos => {
            // Darwin F_GETPATH (sys/fcntl.h) writes a NUL-terminated path into buf.
            const F_GETPATH: c_int = 50;
            @memset(buf[0..std.fs.max_path_bytes], 0);
            const rc = std.c.fcntl(@as(c_int, @intCast(fd)), F_GETPATH, buf.ptr);
            if (rc != 0) return null;
            return std.mem.sliceTo(buf, 0);
        },
        .linux => {
            var link_path_buf: [64]u8 = undefined;
            const link_path = std.fmt.bufPrint(&link_path_buf, "/proc/self/fd/{d}", .{fd}) catch return null;
            const n = std.Io.Dir.readLinkAbsolute(io, link_path, buf) catch return null;
            return buf[0..n];
        },
        else => return null,
    }
}

/// True when parent process stdout (1) or stderr (2) path is under ungranted host tmp.
/// Used for tip selection and pre-spawn warning (shell redirects open FDs before fork).
pub fn parentStdioHasUngrantedHostTmpRisk(io: std.Io) bool {
    if (comptime builtin.os.tag != .macos and builtin.os.tag != .linux) return false;
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    if (resolveFdPathname(io, 1, &path_buf)) |path| {
        if (pathIsUngrantedHostTmpContent(path)) return true;
    }
    if (resolveFdPathname(io, 2, &path_buf)) |path| {
        if (pathIsUngrantedHostTmpContent(path)) return true;
    }
    return false;
}

/// Inputs for empty-backpack post-exit tip selection (priority order below).
pub const EmptyBackpackExitTipInput = struct {
    /// Parent stdout/stderr path under classic ungranted host tmp.
    stdio_host_tmp_risk: bool = false,
    /// Captured agent stderr/stdout when available (inherit mode often has none).
    agent_output: ?[]const u8 = null,
};

/// True when text looks like Seatbelt path-walk residual (EPERM + lstat/realpath).
/// Case-insensitive on the operation keywords; used when agent output is retained.
pub fn stderrLooksLikeSeatbeltPathWalkResidual(text: []const u8) bool {
    if (text.len == 0) return false;
    const has_eperm = std.ascii.indexOfIgnoreCase(text, "EPERM") != null or
        std.ascii.indexOfIgnoreCase(text, "operation not permitted") != null or
        std.ascii.indexOfIgnoreCase(text, "Permission denied") != null or
        std.ascii.indexOfIgnoreCase(text, "PermissionError") != null;
    if (!has_eperm) return false;
    return std.ascii.indexOfIgnoreCase(text, "lstat") != null or
        std.ascii.indexOfIgnoreCase(text, "realpath") != null or
        std.ascii.indexOfIgnoreCase(text, "resolveMainPath") != null;
}

/// True when text looks like Codex system-requirements RO residual under Seatbelt.
pub fn stderrLooksLikeEtcCodexRequirementsEperm(text: []const u8) bool {
    if (text.len == 0) return false;
    const has_eperm = std.ascii.indexOfIgnoreCase(text, "EPERM") != null or
        std.ascii.indexOfIgnoreCase(text, "operation not permitted") != null or
        std.ascii.indexOfIgnoreCase(text, "Permission denied") != null or
        std.ascii.indexOfIgnoreCase(text, "os error 1") != null;
    if (!has_eperm) return false;
    return std.ascii.indexOfIgnoreCase(text, "/etc/codex") != null or
        std.ascii.indexOfIgnoreCase(text, "requirements.toml") != null;
}

/// Pick empty-backpack post-exit tip:
/// 1) stdio/fstat residual when parent FD path is ungranted host tmp
/// 2) path-walk residual when agent_output matches EPERM + lstat/realpath
/// 3) system config RO residual (`/etc/codex` / requirements.toml EPERM)
/// 4) generic tip (auth / gateway / remaining residuals)
pub fn selectEmptyBackpackAgentExitTip(input: EmptyBackpackExitTipInput) []const u8 {
    if (input.stdio_host_tmp_risk) return empty_backpack_stdio_fstat_exit_tip;
    if (input.agent_output) |text| {
        if (stderrLooksLikeSeatbeltPathWalkResidual(text)) return empty_backpack_pathwalk_exit_tip;
        if (stderrLooksLikeEtcCodexRequirementsEperm(text)) return empty_backpack_system_ro_exit_tip;
    }
    return empty_backpack_agent_exit_tip;
}

/// Choose the fail-closed stderr blob for a known host with unusable auth.
/// `host` is a trusted table key (not raw argv0).
pub fn failClosedMessageFor(
    io: std.Io,
    host: []const u8,
    home: []const u8,
) []const u8 {
    if (std.mem.eql(u8, host, "claude") and
        hostLoginMaterialPresent(io, host, home) and
        claudeLoginFreshness(io, home) == .expired)
    {
        return stale_login_fail_closed_message;
    }
    return missing_config_fail_closed_message;
}

/// Which loopback provider gateway can substitute host login for this agent.
pub const GatewayKind = enum {
    none,
    anthropic,
    openai,
};

/// Host → relevant gateway. Unknown / non-model hosts get `.none` (config only).
pub fn gatewayKindForHost(host: []const u8) GatewayKind {
    if (std.mem.eql(u8, host, "claude")) return .anthropic;
    if (std.mem.eql(u8, host, "codex")) return .openai;
    // pi / opencode / openclaw / hermes: no assumed env-key gateway substitute.
    return .none;
}

/// Empty-backpack agent launch without usable login material and without a
/// **relevant** provider gateway would blank-hang. Call only for known hosts.
/// `has_usable_auth` is typically `hostUsableAuthPresent` (login markers when
/// defined, else config-root presence).
pub fn shouldFailClosedMissingAuth(
    host: []const u8,
    has_anthropic_gateway: bool,
    has_openai_gateway: bool,
    has_usable_auth: bool,
) bool {
    if (has_usable_auth) return false;
    return switch (gatewayKindForHost(host)) {
        .anthropic => !has_anthropic_gateway,
        .openai => !has_openai_gateway,
        .none => true,
    };
}

test "hostBasename strips path components" {
    try std.testing.expectEqualStrings("claude", hostBasename("claude"));
    try std.testing.expectEqualStrings("claude", hostBasename("/Users/x/.local/bin/claude"));
    try std.testing.expectEqualStrings("codex", hostBasename("codex"));
    try std.testing.expectEqualStrings("", hostBasename(""));
}

test "specForHost exact allowlist only" {
    try std.testing.expect(specForHost("claude") != null);
    try std.testing.expect(specForHost("codex") != null);
    try std.testing.expect(specForHost("Claude") == null);
    try std.testing.expect(specForHost("echo") == null);
    try std.testing.expect(specForHost("") == null);
}

test "pi and opencode host tables list known sibling home roots" {
    const pi = specForHost("pi").?;
    var found_pi = false;
    var found_lens = false;
    var found_mcp = false;
    for (pi.home_rel_dirs) |rel| {
        if (std.mem.eql(u8, rel, ".pi")) found_pi = true;
        if (std.mem.eql(u8, rel, ".pi-lens")) found_lens = true;
        if (std.mem.eql(u8, rel, ".mcp_sequential_thinking")) found_mcp = true;
    }
    try std.testing.expect(found_pi);
    try std.testing.expect(found_lens);
    try std.testing.expect(found_mcp);

    const oc = specForHost("opencode").?;
    var found_dot_opencode = false;
    var found_config = false;
    for (oc.home_rel_dirs) |rel| {
        if (std.mem.eql(u8, rel, ".opencode")) found_dot_opencode = true;
        if (std.mem.eql(u8, rel, ".config/opencode")) found_config = true;
    }
    try std.testing.expect(found_dot_opencode);
    try std.testing.expect(found_config);
}

test "collectHostConfigPaths grants pi lens and opencode roots when present" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    const home = try home_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(home);

    try home_tmp.dir.createDirPath(io, ".pi");
    try home_tmp.dir.createDirPath(io, ".pi-lens");
    try home_tmp.dir.createDirPath(io, ".mcp_sequential_thinking");
    try home_tmp.dir.createDirPath(io, ".opencode");
    try home_tmp.dir.createDirPath(io, ".config/opencode");
    try home_tmp.dir.createDirPath(io, ".local/share/opencode");

    const pi_paths = try collectHostConfigPaths(io, allocator, "pi", home);
    defer freeHostConfigPaths(allocator, pi_paths);
    try std.testing.expect(pi_paths.len >= 3);
    var saw_lens = false;
    for (pi_paths) |p| {
        if (std.mem.endsWith(u8, p, "/.pi-lens")) saw_lens = true;
    }
    try std.testing.expect(saw_lens);

    const oc_paths = try collectHostConfigPaths(io, allocator, "opencode", home);
    defer freeHostConfigPaths(allocator, oc_paths);
    try std.testing.expect(oc_paths.len >= 3);
    var saw_dot = false;
    for (oc_paths) |p| {
        if (std.mem.endsWith(u8, p, "/.opencode")) saw_dot = true;
    }
    try std.testing.expect(saw_dot);
}

test "collectHostConfigPaths grants existing Grok product dirs not whole tree" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    const home = try home_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(home);
    try home_tmp.dir.createDirPath(io, ".grok/skills");
    try home_tmp.dir.createDirPath(io, ".grok/worktrees/evil");
    try home_tmp.dir.writeFile(io, .{
        .sub_path = ".grok/user-settings.json",
        .data = "{}\n",
    });

    const paths = try collectHostConfigPaths(io, allocator, "grok", home);
    defer freeHostConfigPaths(allocator, paths);
    try std.testing.expectEqual(@as(usize, 1), paths.len);
    try std.testing.expect(std.mem.endsWith(u8, paths[0], "/.grok/skills"));
    for (paths) |p| {
        // Grant leaf must not be the worktrees tree (tmp homes may live under a path
        // that itself contains the substring "worktrees").
        try std.testing.expect(!std.mem.endsWith(u8, p, "/.grok/worktrees"));
        try std.testing.expect(!std.mem.endsWith(u8, p, "/.grok/worktrees/evil"));
        try std.testing.expect(!std.mem.eql(u8, p, home));
        try std.testing.expect(!std.mem.endsWith(u8, p, "/.grok"));
    }
}

// Issue #194: grok 1.0.4 opens ~/.grok/config.toml after Seatbelt attach.
// The grant must be the file (plus ancestor metadata from the profile builder),
// not the parent ~/.grok tree (F19) and not ~/.grok/bin (F40).
test "collectHostConfigPaths grants grok 1.0.4 config.toml not whole ~/.grok" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    const home = try home_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(home);

    try home_tmp.dir.createDirPath(io, ".grok/worktrees/evil");
    try home_tmp.dir.createDirPath(io, ".grok/bin");
    try home_tmp.dir.createDirPath(io, "Library/Keychains");
    try home_tmp.dir.writeFile(io, .{
        .sub_path = ".grok/config.toml",
        .data = "[cli]\nauto_update = false\n",
    });
    try home_tmp.dir.writeFile(io, .{
        .sub_path = ".grok/bin/grok",
        .data = "#!/bin/sh\n",
    });
    try home_tmp.dir.writeFile(io, .{
        .sub_path = "Library/Keychains/login.keychain-db",
        .data = "secret\n",
    });

    const spec = specForHost("grok").?;
    var listed_config = false;
    var listed_bare_grok = false;
    var listed_bin = false;
    for (spec.home_rel_dirs) |rel| {
        if (std.mem.eql(u8, rel, ".grok/config.toml")) listed_config = true;
        if (std.mem.eql(u8, rel, ".grok")) listed_bare_grok = true;
        if (std.mem.eql(u8, rel, ".grok/bin") or std.mem.startsWith(u8, rel, ".grok/bin/")) listed_bin = true;
    }
    try std.testing.expect(listed_config);
    try std.testing.expect(!listed_bare_grok);
    try std.testing.expect(!listed_bin);

    const paths = try collectHostConfigPaths(io, allocator, "grok", home);
    defer freeHostConfigPaths(allocator, paths);
    try std.testing.expect(paths.len >= 1);
    var saw_config = false;
    for (paths) |p| {
        if (std.mem.endsWith(u8, p, "/.grok/config.toml")) saw_config = true;
        try std.testing.expect(!std.mem.eql(u8, p, home));
        try std.testing.expect(!std.mem.endsWith(u8, p, "/.grok"));
        try std.testing.expect(!std.mem.endsWith(u8, p, "/.grok/bin"));
        try std.testing.expect(!std.mem.endsWith(u8, p, "/.grok/worktrees"));
        try std.testing.expect(!std.mem.endsWith(u8, p, "/.grok/worktrees/evil"));
        try std.testing.expect(std.mem.indexOf(u8, p, "Library/Keychains") == null);
    }
    try std.testing.expect(saw_config);

    // Official 1.0.4 install: config.toml is usable auth for the alias gate.
    // ~/.grok/bin alone is not (install layout, not product config).
    try std.testing.expect(hostConfigPresent(io, "grok", home));
    try std.testing.expect(hostUsableAuthPresent(io, "grok", home));
}

test "hostUsableAuthPresent grok official config.toml not bin-only install" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    const home = try home_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(home);

    try home_tmp.dir.createDirPath(io, ".grok/bin");
    try home_tmp.dir.writeFile(io, .{
        .sub_path = ".grok/bin/grok",
        .data = "#!/bin/sh\n",
    });
    try std.testing.expect(!hostConfigPresent(io, "grok", home));
    try std.testing.expect(!hostUsableAuthPresent(io, "grok", home));
    try std.testing.expect(shouldFailClosedMissingAuth("grok", false, false, false));

    try home_tmp.dir.writeFile(io, .{
        .sub_path = ".grok/config.toml",
        .data = "[cli]\nauto_update = false\n",
    });
    try std.testing.expect(hostConfigPresent(io, "grok", home));
    try std.testing.expect(hostUsableAuthPresent(io, "grok", home));
    try std.testing.expect(!shouldFailClosedMissingAuth("grok", false, false, true));
}

test "collectHostConfigWriteDenies includes grok 1.0.4 config.toml" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    try env_map.put("HOME", "/Users/synthetic");

    const paths = try collectHostConfigWriteDenies(io, allocator, "grok", "/tmp/ryk-grok-repro", &env_map);
    defer freeHostConfigWriteDenies(allocator, paths);
    try std.testing.expect(testingContainsPath(paths, "/Users/synthetic/.grok/config.toml"));
    try std.testing.expect(testingContainsPath(paths, "/Users/synthetic/.grok/user-settings.json"));
    for (paths) |p| {
        try std.testing.expect(!std.mem.eql(u8, p, "/Users/synthetic"));
        try std.testing.expect(!std.mem.eql(u8, p, "/Users/synthetic/.grok"));
        try std.testing.expect(std.mem.indexOf(u8, p, "Library/Keychains") == null);
    }
}

test "isForbiddenHostConfigPath rejects root home and ssh" {
    const home = "/Users/dev";
    try std.testing.expect(isForbiddenHostConfigPath("/", home));
    try std.testing.expect(isForbiddenHostConfigPath(home, home));
    try std.testing.expect(isForbiddenHostConfigPath("/Users/dev/.ssh", home));
    try std.testing.expect(isForbiddenHostConfigPath("/Users/dev/.ssh/id_rsa", home));
    try std.testing.expect(!isForbiddenHostConfigPath("/Users/dev/.claude", home));
    try std.testing.expect(!isForbiddenHostConfigPath("/Users/dev/.local/share/claude", home));
}

test "collectHostConfigPaths grants existing claude roots and skips missing" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    const home = try home_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(home);

    try home_tmp.dir.createDirPath(io, ".claude");
    try home_tmp.dir.writeFile(io, .{ .sub_path = ".claude/settings.json", .data = "{}\n" });
    try home_tmp.dir.writeFile(io, .{ .sub_path = ".claude.json", .data = "{\"mcpServers\":{}}\n" });
    // No .local/share/claude — must be skipped.

    const want_claude = try std.fs.path.join(allocator, &.{ home, ".claude" });
    defer allocator.free(want_claude);
    const want_claude_json = try std.fs.path.join(allocator, &.{ home, ".claude.json" });
    defer allocator.free(want_claude_json);
    // Prove the fixture is visible before collect (isolates collector bugs).
    try std.testing.expect(pathExists(io, want_claude));

    const paths = try collectHostConfigPaths(io, allocator, "claude", home);
    defer freeHostConfigPaths(allocator, paths);

    try std.testing.expectEqual(@as(usize, 2), paths.len);
    try std.testing.expectEqualStrings(want_claude_json, paths[0]);
    try std.testing.expectEqualStrings(want_claude, paths[1]);

    // Sibling secret tree never granted even if present.
    try home_tmp.dir.createDirPath(io, ".ssh");
    const paths2 = try collectHostConfigPaths(io, allocator, "claude", home);
    defer freeHostConfigPaths(allocator, paths2);
    for (paths2) |p| {
        try std.testing.expect(std.mem.indexOf(u8, p, ".ssh") == null);
        try std.testing.expect(!std.mem.eql(u8, p, home));
    }
}

test "collectHostConfigPaths canonicalizes safe links and drops secret retargets" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    {
        var home_tmp = std.testing.tmpDir(.{});
        defer home_tmp.cleanup();
        const home = try home_tmp.dir.realPathFileAlloc(io, ".", allocator);
        defer allocator.free(home);
        try home_tmp.dir.createDirPath(io, "safe-claude");
        home_tmp.dir.symLink(io, "safe-claude", ".claude", .{ .is_directory = true }) catch
            return error.SkipZigTest;

        const safe_target = try home_tmp.dir.realPathFileAlloc(io, "safe-claude", allocator);
        defer allocator.free(safe_target);
        const paths = try collectHostConfigPaths(io, allocator, "claude", home);
        defer freeHostConfigPaths(allocator, paths);
        try std.testing.expectEqual(@as(usize, 1), paths.len);
        try std.testing.expectEqualStrings(safe_target, paths[0]);
    }

    {
        var home_tmp = std.testing.tmpDir(.{});
        defer home_tmp.cleanup();
        const home = try home_tmp.dir.realPathFileAlloc(io, ".", allocator);
        defer allocator.free(home);
        try home_tmp.dir.createDirPath(io, ".ssh");
        home_tmp.dir.symLink(io, ".ssh", ".claude", .{ .is_directory = true }) catch
            return error.SkipZigTest;

        const paths = try collectHostConfigPaths(io, allocator, "claude", home);
        defer freeHostConfigPaths(allocator, paths);
        try std.testing.expectEqual(@as(usize, 0), paths.len);
    }
}

test "collectHostConfigPaths empty for non-host and missing config" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    const home = try home_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(home);

    {
        const paths = try collectHostConfigPaths(io, allocator, "/bin/echo", home);
        defer freeHostConfigPaths(allocator, paths);
        try std.testing.expectEqual(@as(usize, 0), paths.len);
    }
    {
        // Known host but no config dir yet.
        const paths = try collectHostConfigPaths(io, allocator, "claude", home);
        defer freeHostConfigPaths(allocator, paths);
        try std.testing.expectEqual(@as(usize, 0), paths.len);
        try std.testing.expect(!hostConfigPresent(io, "claude", home));
    }
}

test "collectHostConfigPaths rejects empty or relative HOME" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    {
        const paths = try collectHostConfigPaths(io, allocator, "claude", "");
        defer freeHostConfigPaths(allocator, paths);
        try std.testing.expectEqual(@as(usize, 0), paths.len);
    }
    {
        const paths = try collectHostConfigPaths(io, allocator, "claude", "relative-home");
        defer freeHostConfigPaths(allocator, paths);
        try std.testing.expectEqual(@as(usize, 0), paths.len);
    }
}

test "hostLoginMaterialPresent requires credentials not only config dir for claude" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    const home = try home_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(home);

    try home_tmp.dir.createDirPath(io, ".claude");
    try std.testing.expect(hostConfigPresent(io, "claude", home));
    try std.testing.expect(!hostLoginMaterialPresent(io, "claude", home));
    try std.testing.expect(!hostUsableAuthPresent(io, "claude", home));

    // No expiresAt → treat as present/fresh enough for preflight.
    try home_tmp.dir.writeFile(io, .{ .sub_path = ".claude/.credentials.json", .data = "{\"claudeAiOauth\":{}}\n" });
    try std.testing.expect(hostLoginMaterialPresent(io, "claude", home));
    try std.testing.expect(hostUsableAuthPresent(io, "claude", home));
    try std.testing.expect(claudeLoginFreshness(io, home) == .fresh);

    // Empty credentials file is not usable.
    try home_tmp.dir.writeFile(io, .{ .sub_path = ".claude/.credentials.json", .data = "" });
    try std.testing.expect(!hostLoginMaterialPresent(io, "claude", home));

    // Expired access token → material present; stale fail-closed is separate.
    try home_tmp.dir.writeFile(io, .{
        .sub_path = ".claude/.credentials.json",
        .data = "{\"claudeAiOauth\":{\"expiresAt\":1}}\n",
    });
    try std.testing.expect(hostLoginMaterialPresent(io, "claude", home));
    try std.testing.expect(hostUsableAuthPresent(io, "claude", home));
    try std.testing.expect(claudeLoginFreshness(io, home) == .expired);
    try std.testing.expect(shouldFailClosedStaleClaudeLogin(io, "claude", &.{ "claude", "-p", "hi" }, home, false));
    try std.testing.expect(!shouldFailClosedStaleClaudeLogin(io, "claude", &.{ "claude", "--help" }, home, false));
    try std.testing.expect(!shouldFailClosedStaleClaudeLogin(io, "claude", &.{ "claude", "-p", "hi" }, home, true)); // gateway

    // Far-future expiry remains fresh.
    try home_tmp.dir.writeFile(io, .{
        .sub_path = ".claude/.credentials.json",
        .data = "{\"claudeAiOauth\":{\"expiresAt\":9999999999999}}\n",
    });
    try std.testing.expect(claudeLoginFreshness(io, home) == .fresh);
    try std.testing.expect(!shouldFailClosedStaleClaudeLogin(io, "claude", &.{"claude"}, home, false));

    try std.testing.expect(isAgentHelpOrVersionOnly(&.{ "claude", "--help" }));
    try std.testing.expect(isAgentHelpOrVersionOnly(&.{ "claude", "--version" }));
    try std.testing.expect(!isAgentHelpOrVersionOnly(&.{"claude"}));
    try std.testing.expect(!isAgentHelpOrVersionOnly(&.{ "claude", "-p", "x" }));
    // Documented agent help is `ryk <host> -- --help`. Alias rewrite keeps the
    // `--` separator in command_argv (`["grok", "--", "--help"]`). That must
    // still be help-only so the empty-backpack login gate does not fire before
    // attach (#194 Linux). Bare `--` is interactive, not help.
    try std.testing.expect(isAgentHelpOrVersionOnly(&.{ "grok", "--", "--help" }));
    try std.testing.expect(isAgentHelpOrVersionOnly(&.{ "grok", "--", "-h" }));
    try std.testing.expect(!isAgentHelpOrVersionOnly(&.{ "grok", "--" }));
    try std.testing.expect(!isAgentHelpOrVersionOnly(&.{ "grok", "--", "-p", "hi" }));

    // pi has no markers → config dir alone is enough.
    try home_tmp.dir.createDirPath(io, ".pi");
    try std.testing.expect(hostLoginMaterialPresent(io, "pi", home));
}

test "failClosedMessageFor prefers stale when credentials expired" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    const home = try home_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(home);
    try home_tmp.dir.createDirPath(io, ".claude");
    try home_tmp.dir.writeFile(io, .{
        .sub_path = ".claude/.credentials.json",
        .data = "{\"claudeAiOauth\":{\"expiresAt\":1}}\n",
    });
    try std.testing.expect(std.mem.indexOf(u8, failClosedMessageFor(io, "claude", home), "expired") != null);
}

test "shouldFailClosedMissingAuth edge matrix is host-aware" {
    // Claude: Anthropic gateway substitutes; OpenAI alone does not.
    try std.testing.expect(shouldFailClosedMissingAuth("claude", false, false, false));
    try std.testing.expect(!shouldFailClosedMissingAuth("claude", true, false, false));
    try std.testing.expect(shouldFailClosedMissingAuth("claude", false, true, false));
    try std.testing.expect(!shouldFailClosedMissingAuth("claude", false, false, true));

    // Codex: OpenAI gateway substitutes; Anthropic alone does not.
    try std.testing.expect(shouldFailClosedMissingAuth("codex", false, false, false));
    try std.testing.expect(!shouldFailClosedMissingAuth("codex", false, true, false));
    try std.testing.expect(shouldFailClosedMissingAuth("codex", true, false, false));

    // Pi / hermes: config only (no gateway substitute).
    try std.testing.expect(shouldFailClosedMissingAuth("pi", true, true, false));
    try std.testing.expect(!shouldFailClosedMissingAuth("pi", false, false, true));

    // Grok: no env-key gateway. Official ~/.grok/config.toml is usable auth.
    try std.testing.expect(shouldFailClosedMissingAuth("grok", true, true, false));
    try std.testing.expect(!shouldFailClosedMissingAuth("grok", false, false, true));
}

test "relHasUnsafeComponents rejects traversal" {
    try std.testing.expect(relHasUnsafeComponents(""));
    try std.testing.expect(relHasUnsafeComponents(".claude/../.ssh"));
    try std.testing.expect(relHasUnsafeComponents("foo/./bar"));
    try std.testing.expect(!relHasUnsafeComponents(".claude"));
    try std.testing.expect(!relHasUnsafeComponents("Library/Application Support/Claude"));
}

test "isForbiddenHostConfigPath rejects keychains and traversal survivors" {
    const home = "/Users/dev";
    try std.testing.expect(isForbiddenHostConfigPath("/Users/dev/Library/Keychains", home));
    try std.testing.expect(isForbiddenHostConfigPath("/Users/dev/Library/Cookies/Cookies.binarycookies", home));
    try std.testing.expect(isForbiddenHostConfigPath("/Users/dev/Library", home));
    try std.testing.expect(!isForbiddenHostConfigPath("/Users/dev/Library/Application Support/Claude", home));
}

test "collectHostConfigPaths on real HOME includes .claude when present" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const home_z = std.c.getenv("HOME") orelse return error.SkipZigTest;
    const home = std.mem.span(home_z);
    if (!std.fs.path.isAbsolute(home)) return error.SkipZigTest;
    if (!hostConfigPresent(io, "claude", home)) return error.SkipZigTest;

    const paths = try collectHostConfigPaths(io, allocator, "claude", home);
    defer freeHostConfigPaths(allocator, paths);
    try std.testing.expect(paths.len >= 1);
    var found_claude = false;
    for (paths) |p| {
        try std.testing.expect(!std.mem.eql(u8, p, home));
        try std.testing.expect(std.mem.indexOf(u8, p, ".ssh") == null);
        if (std.mem.endsWith(u8, p, "/.claude")) found_claude = true;
    }
    try std.testing.expect(found_claude);
}

test "missing_config_fail_closed_message names login material" {
    try std.testing.expect(std.mem.indexOf(u8, missing_config_fail_closed_message, ".credentials.json") != null);
    try std.testing.expect(std.mem.indexOf(u8, empty_backpack_agent_exit_tip, "var/folders") != null);
    try std.testing.expect(std.mem.indexOf(u8, empty_backpack_agent_exit_tip, "Keychain") != null);
}

test "pathIsUngrantedHostTmpContent classifies classic tmp vs workspace" {
    try std.testing.expect(pathIsUngrantedHostTmpContent("/tmp/ryk-probe-out.txt"));
    try std.testing.expect(pathIsUngrantedHostTmpContent("/tmp"));
    try std.testing.expect(pathIsUngrantedHostTmpContent("/private/tmp/err.txt"));
    try std.testing.expect(pathIsUngrantedHostTmpContent("/private/tmp"));
    try std.testing.expect(pathIsUngrantedHostTmpContent("/var/folders/xx/yy/T/out.txt"));
    try std.testing.expect(pathIsUngrantedHostTmpContent("/private/var/folders/ab/cd/T/err.txt"));
    try std.testing.expect(!pathIsUngrantedHostTmpContent(""));
    try std.testing.expect(!pathIsUngrantedHostTmpContent("/Users/me/proj/.ryk-tmp/out.txt"));
    try std.testing.expect(!pathIsUngrantedHostTmpContent("/dev/null"));
    try std.testing.expect(!pathIsUngrantedHostTmpContent("/private/var/log/system.log"));
    // Prefix must not false-positive adjacent names.
    try std.testing.expect(!pathIsUngrantedHostTmpContent("/tmpish/foo"));
    try std.testing.expect(!pathIsUngrantedHostTmpContent("/var/foldersish/x"));
}

test "selectEmptyBackpackAgentExitTip prefers stdio residual over re-login lead" {
    const stdio_tip = selectEmptyBackpackAgentExitTip(.{ .stdio_host_tmp_risk = true });
    try std.testing.expect(stdio_tip.ptr == empty_backpack_stdio_fstat_exit_tip.ptr);
    try std.testing.expect(std.mem.indexOf(u8, stdio_tip, "fstat") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdio_tip, "after sandbox attach") != null);
    // Must lead with stdio residual framing, not re-login / generic tip prefix.
    try std.testing.expect(std.mem.startsWith(u8, stdio_tip, "ryk run: empty-backpack: agent died after sandbox attach"));
    try std.testing.expect(std.mem.indexOf(u8, stdio_tip, "Do not treat this as missing login first") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdio_tip, "--with-host-secrets") == null);

    const generic_tip = selectEmptyBackpackAgentExitTip(.{});
    try std.testing.expect(generic_tip.ptr == empty_backpack_agent_exit_tip.ptr);
    try std.testing.expect(std.mem.indexOf(u8, generic_tip, "re-login") != null);
    try std.testing.expect(std.mem.indexOf(u8, generic_tip, "var/folders") != null);
    try std.testing.expect(std.mem.indexOf(u8, generic_tip, "path-walk") != null);
}

test "selectEmptyBackpackAgentExitTip prefers path-walk residual over re-login lead" {
    const node_stack =
        \\Error: EPERM: operation not permitted, lstat '/Users'
        \\    at Object.realpathSync (node:fs:1234:10)
        \\    at resolveMainPath (node:internal/modules/cjs/loader:1:1)
    ;
    const pathwalk_tip = selectEmptyBackpackAgentExitTip(.{ .agent_output = node_stack });
    try std.testing.expect(pathwalk_tip.ptr == empty_backpack_pathwalk_exit_tip.ptr);
    try std.testing.expect(std.mem.indexOf(u8, pathwalk_tip, "path-walk") != null);
    try std.testing.expect(std.mem.indexOf(u8, pathwalk_tip, "not missing host login") != null);
    try std.testing.expect(std.mem.indexOf(u8, pathwalk_tip, "re-login first") != null);
    // Must not lead operators to auth/gateway first.
    try std.testing.expect(std.mem.indexOf(u8, pathwalk_tip, "API key") == null);
    try std.testing.expect(std.mem.indexOf(u8, pathwalk_tip, "--with-host-secrets") == null);

    // Stdio residual still wins when both could apply.
    const stdio_wins = selectEmptyBackpackAgentExitTip(.{
        .stdio_host_tmp_risk = true,
        .agent_output = node_stack,
    });
    try std.testing.expect(stdio_wins.ptr == empty_backpack_stdio_fstat_exit_tip.ptr);

    try std.testing.expect(stderrLooksLikeSeatbeltPathWalkResidual(node_stack));
    try std.testing.expect(stderrLooksLikeSeatbeltPathWalkResidual(
        "PermissionError: [Errno 1] Operation not permitted\n  File \"...\", line 1, in <module>\n    os.lstat('/Users')\n",
    ));
    try std.testing.expect(!stderrLooksLikeSeatbeltPathWalkResidual("Error: invalid API key"));
    try std.testing.expect(!stderrLooksLikeSeatbeltPathWalkResidual("EPERM on fstat of redirected stderr"));
    try std.testing.expect(!stderrLooksLikeSeatbeltPathWalkResidual(""));
    try std.testing.expect(!stderrLooksLikeSeatbeltPathWalkResidual(
        "PermissionError: [Errno 1] Operation not permitted: '/Users'",
    ));
}

test "resolveFdPathname round-trips a /tmp file on supported platforms" {
    if (builtin.os.tag != .macos and builtin.os.tag != .linux) return error.SkipZigTest;

    const io = std.testing.io;
    const path = "/tmp/ryk-stdio-risk-probe.txt";
    {
        const file = try std.Io.Dir.createFileAbsolute(io, path, .{});
        defer file.close(io);
        try file.writeStreamingAll(io, "probe");
    }
    defer std.Io.Dir.deleteFileAbsolute(io, path) catch {};

    const file = try std.Io.Dir.openFileAbsolute(io, path, .{});
    defer file.close(io);

    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const resolved = resolveFdPathname(io, file.handle, &buf) orelse return error.SkipZigTest;
    try std.testing.expect(pathIsUngrantedHostTmpContent(resolved));
    // macOS often returns /private/tmp/...; Linux returns /tmp/...
    try std.testing.expect(
        std.mem.indexOf(u8, resolved, "ryk-stdio-risk-probe.txt") != null,
    );
}

test "isForbiddenSystemRoPath rejects bare etc and root" {
    try std.testing.expect(isForbiddenSystemRoPath(""));
    try std.testing.expect(isForbiddenSystemRoPath("/"));
    try std.testing.expect(isForbiddenSystemRoPath("etc/codex"));
    try std.testing.expect(isForbiddenSystemRoPath("/etc"));
    try std.testing.expect(isForbiddenSystemRoPath("/private/etc"));
    try std.testing.expect(isForbiddenSystemRoPath("/private"));
    try std.testing.expect(isForbiddenSystemRoPath("/etc/../etc"));
    try std.testing.expect(!isForbiddenSystemRoPath("/etc/codex"));
    try std.testing.expect(!isForbiddenSystemRoPath("/private/etc/codex"));
}

test "collectHostSystemRoPaths grants codex etc trees even when missing" {
    const allocator = std.testing.allocator;

    const codex_paths = try collectHostSystemRoPaths(allocator, "codex");
    defer freeHostSystemRoPaths(allocator, codex_paths);
    try std.testing.expect(codex_paths.len >= 1);
    var found_etc = false;
    var found_private = false;
    for (codex_paths) |p| {
        try std.testing.expect(!isForbiddenSystemRoPath(p));
        try std.testing.expect(!std.mem.eql(u8, p, "/etc"));
        try std.testing.expect(!std.mem.eql(u8, p, "/private/etc"));
        if (std.mem.eql(u8, p, "/etc/codex")) found_etc = true;
        if (std.mem.eql(u8, p, "/private/etc/codex")) found_private = true;
    }
    try std.testing.expect(found_etc);
    if (builtin.os.tag == .macos) {
        try std.testing.expect(found_private);
    }

    // Collectors take trusted host keys only — path-form argv0 is not a table key.
    const via_path = try collectHostSystemRoPaths(allocator, "/usr/local/bin/codex");
    defer freeHostSystemRoPaths(allocator, via_path);
    try std.testing.expectEqual(@as(usize, 0), via_path.len);

    // Non-codex hosts get empty system RO.
    const claude = try collectHostSystemRoPaths(allocator, "claude");
    defer freeHostSystemRoPaths(allocator, claude);
    try std.testing.expectEqual(@as(usize, 0), claude.len);

    const echo = try collectHostSystemRoPaths(allocator, "echo");
    defer freeHostSystemRoPaths(allocator, echo);
    try std.testing.expectEqual(@as(usize, 0), echo.len);
}

test "isAllowlistedMacosDeveloperToolchainPath accepts CLT and Xcode Developer only" {
    try std.testing.expect(isAllowlistedMacosDeveloperToolchainPath("/Library/Developer/CommandLineTools"));
    try std.testing.expect(isAllowlistedMacosDeveloperToolchainPath("/Applications/Xcode.app/Contents/Developer"));
    try std.testing.expect(isAllowlistedMacosDeveloperToolchainPath("/Applications/Xcode-beta.app/Contents/Developer"));
    // Custom install locations (active xcode-select may point outside /Applications).
    try std.testing.expect(isAllowlistedMacosDeveloperToolchainPath("/Users/dev/Downloads/Xcode.app/Contents/Developer"));
    try std.testing.expect(isAllowlistedMacosDeveloperToolchainPath("/Applications/foo/bar.app/Contents/Developer"));

    try std.testing.expect(!isAllowlistedMacosDeveloperToolchainPath(""));
    try std.testing.expect(!isAllowlistedMacosDeveloperToolchainPath("/"));
    try std.testing.expect(!isAllowlistedMacosDeveloperToolchainPath("/Applications"));
    try std.testing.expect(!isAllowlistedMacosDeveloperToolchainPath("/Applications/Xcode.app"));
    try std.testing.expect(!isAllowlistedMacosDeveloperToolchainPath("/Library/Developer"));
    try std.testing.expect(!isAllowlistedMacosDeveloperToolchainPath("/Library/Developer/CommandLineTools/usr"));
    try std.testing.expect(!isAllowlistedMacosDeveloperToolchainPath("/Applications/Evil/../Xcode.app/Contents/Developer"));
    try std.testing.expect(!isAllowlistedMacosDeveloperToolchainPath("Library/Developer/CommandLineTools"));
    try std.testing.expect(!isAllowlistedMacosDeveloperToolchainPath("/Users/dev/.ssh/Xcode.app/Contents/Developer"));
}

test "preferredMacosDeveloperDir prefers CLT" {
    try std.testing.expect(preferredMacosDeveloperDir(&.{}) == null);
    try std.testing.expectEqualStrings(
        "/Applications/Xcode.app/Contents/Developer",
        preferredMacosDeveloperDir(&.{"/Applications/Xcode.app/Contents/Developer"}).?,
    );
    try std.testing.expectEqualStrings(
        "/Library/Developer/CommandLineTools",
        preferredMacosDeveloperDir(&.{
            "/Applications/Xcode.app/Contents/Developer",
            "/Library/Developer/CommandLineTools",
        }).?,
    );
}

test "collectMacosDeveloperToolchainRoPaths grants existing allowlisted roots only" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const paths = try collectMacosDeveloperToolchainRoPaths(io, allocator, null);
    defer freeHostSystemRoPaths(allocator, paths);

    if (builtin.os.tag != .macos) {
        try std.testing.expectEqual(@as(usize, 0), paths.len);
        return;
    }

    // Every returned path must be allowlisted and exist (collector is exist-only).
    for (paths) |p| {
        try std.testing.expect(isAllowlistedMacosDeveloperToolchainPath(p));
        try std.testing.expect(pathExists(io, p));
        try std.testing.expect(!std.mem.eql(u8, p, "/Applications"));
        try std.testing.expect(!std.mem.eql(u8, p, "/Library/Developer"));
    }

    // On this host at least one of CLT / Xcode Developer is expected for agent DX.
    // Soft: if the machine has neither, empty is still correct.
    var saw_clt = false;
    var saw_xcode = false;
    for (paths) |p| {
        if (std.mem.eql(u8, p, "/Library/Developer/CommandLineTools")) saw_clt = true;
        if (std.mem.eql(u8, p, "/Applications/Xcode.app/Contents/Developer")) saw_xcode = true;
    }
    if (pathExists(io, "/Library/Developer/CommandLineTools")) {
        try std.testing.expect(saw_clt);
    }
    if (pathExists(io, "/Applications/Xcode.app/Contents/Developer")) {
        try std.testing.expect(saw_xcode);
    }

    // DEVELOPER_DIR must pass the allowlist; rejected dirs are ignored.
    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    try env_map.put("DEVELOPER_DIR", "/Applications");
    const rejected = try collectMacosDeveloperToolchainRoPaths(io, allocator, &env_map);
    defer freeHostSystemRoPaths(allocator, rejected);
    for (rejected) |p| {
        try std.testing.expect(!std.mem.eql(u8, p, "/Applications"));
    }
}

test "collectAncestorInstructionRoPaths grants parent AGENTS.md not parent dir or home" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    const home = try home_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(home);

    try home_tmp.dir.createDirPath(io, "CodingProjects/ryk");
    try home_tmp.dir.createDirPath(io, "CodingProjects/other");
    try home_tmp.dir.writeFile(io, .{
        .sub_path = "CodingProjects/AGENTS.md",
        .data = "# parent instructions\n",
    });
    try home_tmp.dir.writeFile(io, .{
        .sub_path = "AGENTS.md",
        .data = "# home instructions\n",
    });
    // Sibling project file must not be granted (not on ancestor chain).
    try home_tmp.dir.writeFile(io, .{
        .sub_path = "CodingProjects/other/secrets.env",
        .data = "SECRET=1\n",
    });

    const workspace = try std.fs.path.join(allocator, &.{ home, "CodingProjects", "ryk" });
    defer allocator.free(workspace);
    const parent_agents = try std.fs.path.join(allocator, &.{ home, "CodingProjects", "AGENTS.md" });
    defer allocator.free(parent_agents);
    const home_agents = try std.fs.path.join(allocator, &.{ home, "AGENTS.md" });
    defer allocator.free(home_agents);
    const parent_dir = try std.fs.path.join(allocator, &.{ home, "CodingProjects" });
    defer allocator.free(parent_dir);

    const paths = try collectAncestorInstructionRoPaths(io, allocator, workspace, home);
    defer freeHostSystemRoPaths(allocator, paths);

    try std.testing.expect(paths.len >= 2);

    var saw_parent = false;
    var saw_home_file = false;
    for (paths) |p| {
        try std.testing.expect(!std.mem.eql(u8, p, home));
        try std.testing.expect(!std.mem.eql(u8, p, parent_dir));
        try std.testing.expect(std.mem.indexOf(u8, p, "secrets.env") == null);
        if (std.mem.eql(u8, p, parent_agents)) saw_parent = true;
        if (std.mem.eql(u8, p, home_agents)) saw_home_file = true;
    }
    try std.testing.expect(saw_parent);
    try std.testing.expect(saw_home_file);

    // Empty / relative workspace → empty grant list.
    const empty = try collectAncestorInstructionRoPaths(io, allocator, "", home);
    defer freeHostSystemRoPaths(allocator, empty);
    try std.testing.expectEqual(@as(usize, 0), empty.len);

    const rel = try collectAncestorInstructionRoPaths(io, allocator, "relative/ws", home);
    defer freeHostSystemRoPaths(allocator, rel);
    try std.testing.expectEqual(@as(usize, 0), rel.len);
}

test "collectAncestorInstructionRoPaths drops symlink retarget outside ancestor" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    const home = try home_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(home);

    try home_tmp.dir.createDirPath(io, "CodingProjects/ryk");
    try home_tmp.dir.createDirPath(io, ".ssh");
    try home_tmp.dir.writeFile(io, .{ .sub_path = ".ssh/id", .data = "synthetic-canary\n" });
    try home_tmp.dir.writeFile(io, .{
        .sub_path = "CodingProjects/CLAUDE.md",
        .data = "# plain parent instructions\n",
    });
    home_tmp.dir.symLink(io, "../.ssh/id", "CodingProjects/AGENTS.md", .{}) catch
        return error.SkipZigTest;

    const workspace = try std.fs.path.join(allocator, &.{ home, "CodingProjects", "ryk" });
    defer allocator.free(workspace);
    const plain = try std.fs.path.join(allocator, &.{ home, "CodingProjects", "CLAUDE.md" });
    defer allocator.free(plain);
    const secret = try std.fs.path.join(allocator, &.{ home, ".ssh", "id" });
    defer allocator.free(secret);

    const paths = try collectAncestorInstructionRoPaths(io, allocator, workspace, home);
    defer freeHostSystemRoPaths(allocator, paths);
    try std.testing.expectEqual(@as(usize, 1), paths.len);
    try std.testing.expectEqualStrings(plain, paths[0]);
    try std.testing.expect(!std.mem.eql(u8, secret, paths[0]));
}

test "collectAncestorInstructionRoPaths skips workspace itself and missing parents" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    const home = try home_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(home);

    try home_tmp.dir.createDirPath(io, "proj");
    try home_tmp.dir.writeFile(io, .{
        .sub_path = "proj/AGENTS.md",
        .data = "# workspace only\n",
    });

    const workspace = try std.fs.path.join(allocator, &.{ home, "proj" });
    defer allocator.free(workspace);
    const workspace_agents = try std.fs.path.join(allocator, &.{ workspace, "AGENTS.md" });
    defer allocator.free(workspace_agents);

    const paths = try collectAncestorInstructionRoPaths(io, allocator, workspace, home);
    defer freeHostSystemRoPaths(allocator, paths);

    // Workspace file is already under workspace RW — collector starts at parent.
    for (paths) |p| {
        try std.testing.expect(!std.mem.eql(u8, p, workspace_agents));
        try std.testing.expect(!std.mem.endsWith(u8, p, "/proj/AGENTS.md"));
    }
}

test "selectEmptyBackpackAgentExitTip prefers system-ro residual for etc/codex EPERM" {
    const stack =
        \\Error loading config.toml: Failed to read requirements file /etc/codex/requirements.toml: Operation not permitted (os error 1)
    ;
    try std.testing.expect(stderrLooksLikeEtcCodexRequirementsEperm(stack));
    const tip = selectEmptyBackpackAgentExitTip(.{ .agent_output = stack });
    try std.testing.expect(tip.ptr == empty_backpack_system_ro_exit_tip.ptr);
    try std.testing.expect(std.mem.indexOf(u8, tip, "/etc/codex") != null);
    try std.testing.expect(std.mem.indexOf(u8, tip, "not missing host login") != null);
    try std.testing.expect(std.mem.indexOf(u8, tip, "API key") == null);

    // Path-walk still wins when both could match.
    const pathwalk =
        \\Error: EPERM: operation not permitted, lstat '/Users'
        \\Failed requirements /etc/codex/requirements.toml
    ;
    const pathwalk_tip = selectEmptyBackpackAgentExitTip(.{ .agent_output = pathwalk });
    try std.testing.expect(pathwalk_tip.ptr == empty_backpack_pathwalk_exit_tip.ptr);

    try std.testing.expect(!stderrLooksLikeEtcCodexRequirementsEperm("invalid API key"));
    try std.testing.expect(!stderrLooksLikeEtcCodexRequirementsEperm(""));
}

fn testingContainsPath(paths: []const []const u8, candidate: []const u8) bool {
    return containsAuthorityPath(paths, candidate);
}

test "collectHostConfigWriteDenies returns authority paths on all platforms" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    try env_map.put("HOME", "/Users/synthetic");

    const paths = try collectHostConfigWriteDenies(io, allocator, "codex", "/Users/synthetic/project", &env_map);
    defer freeHostConfigWriteDenies(allocator, paths);

    try std.testing.expect(paths.len > 0);
    try std.testing.expect(testingContainsPath(paths, "/Users/synthetic/.codex/config.toml"));
    try std.testing.expect(testingContainsPath(paths, "/Users/synthetic/project/.codex/config.toml"));
    // Workspace walk reaches ancestors including `/`.
    try std.testing.expect(testingContainsPath(paths, "/.codex/config.toml"));

    const unknown = try collectHostConfigWriteDenies(io, allocator, "echo", "/Users/synthetic/project", &env_map);
    defer freeHostConfigWriteDenies(allocator, unknown);
    try std.testing.expectEqual(@as(usize, 0), unknown.len);
}

test "collectHostConfigWriteDenies honors env authority templates cross-platform" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    try env_map.put("HOME", "/Users/synthetic");
    try env_map.put("HERMES_HOME", "/Users/synthetic/.hermes/profiles/work");
    try env_map.put("PI_CODING_AGENT_DIR", "/Users/synthetic/.pi/agent");
    try env_map.put("OPENCODE_CONFIG", "/Users/synthetic/.config/opencode/company.jsonc");
    try env_map.put("CODEX_HOME", "/Users/synthetic/.codex-work");

    const cases = [_]struct { host: []const u8, expected: []const u8 }{
        .{ .host = "claude", .expected = "/Users/synthetic/.claude.json" },
        .{ .host = "opencode", .expected = "/Users/synthetic/.config/opencode/company.jsonc" },
        .{ .host = "hermes", .expected = "/Users/synthetic/.hermes/profiles/work/config.yaml" },
        .{ .host = "pi", .expected = "/Users/synthetic/.pi/agent/settings.json" },
        .{ .host = "codex", .expected = "/Users/synthetic/.codex-work/config.toml" },
        .{ .host = "grok", .expected = "/Users/synthetic/.grok/user-settings.json" },
    };
    for (cases) |case| {
        const paths = try collectHostConfigWriteDenies(
            io,
            allocator,
            case.host,
            "/Users/synthetic/project",
            &env_map,
        );
        defer freeHostConfigWriteDenies(allocator, paths);
        try std.testing.expect(testingContainsPath(paths, case.expected));
    }
}

test "collectHostConfigWriteDenies fails closed on hardlink aliases" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, ".codex");
    try tmp.dir.writeFile(io, .{ .sub_path = ".codex/config.toml", .data = "[mcp_servers]\n" });
    tmp.dir.hardLink(".codex/config.toml", tmp.dir, ".codex/config-alias.toml", io, .{}) catch
        return error.SkipZigTest;
    const home = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(home);
    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    try env_map.put("HOME", home);
    try std.testing.expectError(
        error.UnsafeHostConfigHardlink,
        collectHostConfigWriteDenies(io, allocator, "codex", home, &env_map),
    );
}

//! Trusted launch-host identity for host-config grants and coupled agent defaults.
//!
//! Host-config RW, system RO, authority write-denies, empty-backpack defaults, and
//! agent network mediation must not key off `basename(argv0)` alone (F-02). Resolve
//! argv0 → realpath, require a host_config_table basename **and** a trusted install
//! prefix; otherwise treat the launch as a generic command.

const std = @import("std");
const host_config_grants = @import("host_config_grants.zig");
const apply_posix = @import("apply_posix.zig");

pub const Kind = enum { trusted, generic };

/// Result of binding argv0 to a host-config table host (or generic).
///
/// `host` is a static string from `host_config_table` when trusted.
/// `resolved_path` is allocator-owned when non-null; free via `deinit`.
/// `deny_reason` is a static code string suitable for logs (never secrets).
pub const HostIdentity = struct {
    kind: Kind = .generic,
    host: ?[]const u8 = null,
    resolved_path: ?[]const u8 = null,
    deny_reason: ?[]const u8 = null,

    pub fn deinit(self: *HostIdentity, allocator: std.mem.Allocator) void {
        if (self.resolved_path) |path| allocator.free(path);
        self.* = .{};
    }

    pub fn isTrusted(self: HostIdentity) bool {
        return self.kind == .trusted and self.host != null;
    }

    /// Table host key when trusted, else empty (collectors treat empty as no host).
    pub fn hostKey(self: HostIdentity) []const u8 {
        return self.host orelse "";
    }
};

pub const ResolveOptions = struct {
    /// Extra trusted absolute prefixes (tests). Paths must be absolute; trailing `/` optional.
    extra_trusted_prefixes: []const []const u8 = &.{},
    /// When set, realpaths under this root are never trusted (workspace spoof fence).
    workspace_root: ?[]const u8 = null,
};

/// Builtin install prefixes (macOS-first; Linux twins where obvious).
/// Final realpath must start with one of these (or HOME-relative / injected).
const builtin_trusted_prefixes = [_][]const u8{
    "/opt/homebrew/bin/",
    "/opt/homebrew/sbin/",
    "/opt/homebrew/Cellar/",
    // Brew node_modules realpath targets (pi → …/lib/node_modules/…/cli.js).
    "/opt/homebrew/lib/",
    "/usr/local/bin/",
    "/usr/local/sbin/",
    "/usr/local/Cellar/",
    "/usr/local/lib/",
    // System bins are trusted only when the leaf name itself is a table host
    // (not when a workspace symlink points at /bin/sh — see host-key rules).
    "/usr/bin/",
    "/bin/",
};

const deny_empty: []const u8 = "empty_argv0";
const deny_unresolved: []const u8 = "unresolved";
const deny_unknown_host: []const u8 = "unknown_host";
const deny_untrusted_prefix: []const u8 = "untrusted_prefix";
const deny_tmp: []const u8 = "tmp_path";
const deny_workspace: []const u8 = "workspace_path";

fn genericIdentity(reason: []const u8) HostIdentity {
    return .{
        .kind = .generic,
        .deny_reason = reason,
    };
}

/// Takes ownership of `path` (already allocator-owned).
fn genericTakePath(path: []const u8, reason: []const u8) HostIdentity {
    return .{
        .kind = .generic,
        .resolved_path = path,
        .deny_reason = reason,
    };
}

/// Resolve argv0 to a trusted host-config identity or generic.
///
/// Algorithm:
/// 1. Empty argv0 → generic
/// 2. PATH/cwd resolve + realpath (fail → generic)
/// 3. Basename of realpath must match `host_config_table`
/// 4. Realpath must not be under workspace / tmp
/// 5. Realpath must match a trusted install prefix (builtin, HOME/.local/…,
///    HOME/.grok/{bin,downloads}, HOME/.opencode, optional nvm pattern, RYK_TRUSTED_HOST_PREFIXES,
///    extra_trusted_prefixes)
pub fn resolveHostIdentity(
    io: std.Io,
    allocator: std.mem.Allocator,
    argv0: []const u8,
    env_map: ?*const std.process.Environ.Map,
    options: ResolveOptions,
) error{OutOfMemory}!HostIdentity {
    if (argv0.len == 0) return genericIdentity(deny_empty);

    const resolved = try resolveLaunchPaths(io, allocator, argv0, env_map);
    const path = resolved.realpath orelse {
        if (resolved.link_path) |lp| allocator.free(lp);
        return genericIdentity(deny_unresolved);
    };
    errdefer allocator.free(path);
    defer if (resolved.link_path) |lp| allocator.free(lp);

    if (try isTmpPath(io, allocator, path, env_map)) {
        return genericTakePath(path, deny_tmp);
    }
    if (options.workspace_root) |ws| {
        if (isPathWithinRoot(path, ws)) {
            return genericTakePath(path, deny_workspace);
        }
    }

    // Trust fence first on the final realpath (workspace/tmp already excluded).
    if (!try isTrustedInstallPath(io, allocator, path, env_map, options.extra_trusted_prefixes)) {
        return genericTakePath(path, deny_untrusted_prefix);
    }

    // Host key: prefer realpath basename (with script-suffix strip). Fall back to
    // the PATH/symlink leaf only when:
    //   1) the link path is itself under a trusted prefix, and
    //   2) realpath looks like an agent install wrapper (node_modules / versions /
    //      script suffix / version-id leaf) — not a system binary like /bin/sh.
    // Blocks: `ln -s /bin/sh ~/.local/bin/codex` (trusted link + trusted /bin/sh).
    const base = blk: {
        const from_real = hostNameFromResolvedPath(path);
        if (host_config_grants.specForHost(from_real) != null) break :blk from_real;
        if (resolved.link_path) |lp| {
            if (allowsLinkBasenameFallback(path) and
                try isTrustedInstallPath(io, allocator, lp, env_map, options.extra_trusted_prefixes))
            {
                const from_link = hostNameFromResolvedPath(lp);
                if (host_config_grants.specForHost(from_link) != null) break :blk from_link;
            }
        }
        break :blk from_real;
    };
    // F29: ~/.grok/{bin,downloads} is a Grok install layout only — do not treat
    // planted table-host leaves (claude/codex/…) under those dirs as trusted hosts.
    if (isGrokInstallLayoutPath(path) and !std.mem.eql(u8, base, "grok")) {
        return genericTakePath(path, deny_untrusted_prefix);
    }
    const spec = host_config_grants.specForHost(base) orelse {
        return genericTakePath(path, deny_unknown_host);
    };

    return .{
        .kind = .trusted,
        .host = spec.host,
        .resolved_path = path,
        .deny_reason = null,
    };
}

const LaunchPaths = struct {
    /// Final realpath (owned when non-null).
    realpath: ?[]const u8 = null,
    /// PATH hit or absolute argv path before final realpath (owned when non-null).
    /// Used for host basename when the realpath leaf is a version id or *.js.
    link_path: ?[]const u8 = null,
};

fn resolveLaunchPaths(
    io: std.Io,
    allocator: std.mem.Allocator,
    argv0: []const u8,
    env_map: ?*const std.process.Environ.Map,
) error{OutOfMemory}!LaunchPaths {
    // Bare name: PATH lookup — keep the candidate path (often a symlink whose
    // basename is the host) separately from the final realpath (version id / *.js).
    if (!std.fs.path.isAbsolute(argv0) and std.mem.indexOfScalar(u8, argv0, '/') == null) {
        const path_env = blk: {
            if (env_map) |map| {
                if (map.get("PATH")) |p| break :blk p;
            }
            if (std.c.getenv("PATH")) |p| break :blk std.mem.span(p);
            break :blk "/usr/local/bin:/usr/bin:/bin";
        };
        var it = std.mem.splitScalar(u8, path_env, ':');
        while (it.next()) |dir| {
            if (dir.len == 0) continue;
            const candidate = std.fs.path.join(allocator, &.{ dir, argv0 }) catch return error.OutOfMemory;
            errdefer allocator.free(candidate);
            std.Io.Dir.cwd().access(io, candidate, .{}) catch {
                allocator.free(candidate);
                continue;
            };
            const real = realpathOwned(io, allocator, candidate) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => {
                    // Unresolvable symlink/target: fail closed (no identity path).
                    allocator.free(candidate);
                    continue;
                },
            };
            return .{ .realpath = real, .link_path = candidate };
        }
        // Fall back to apply_posix (same PATH rules). resolveArgv0 may return a
        // non-realpathed PATH candidate when realpath fails — never treat that as
        // identity (symlink leaf under a trusted prefix must not become trusted
        // without a verified final realpath).
        const resolved = apply_posix.resolveArgv0(io, allocator, argv0, env_map) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return .{},
        };
        if (resolved.owned) {
            const real = realpathOwned(io, allocator, resolved.path) catch |err| switch (err) {
                error.OutOfMemory => {
                    allocator.free(resolved.path);
                    return error.OutOfMemory;
                },
                else => {
                    allocator.free(resolved.path);
                    return .{};
                },
            };
            // Keep the PATH candidate as link_path when it differs (wrapper leaf).
            if (std.mem.eql(u8, real, resolved.path)) {
                allocator.free(resolved.path);
                return .{ .realpath = real, .link_path = null };
            }
            return .{ .realpath = real, .link_path = resolved.path };
        }
        const real = realpathOwned(io, allocator, resolved.path) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return .{},
        };
        return .{ .realpath = real, .link_path = null };
    }

    // Absolute or relative-with-separator: realpath is mandatory (F-02).
    // Keep the original path as link_path when it differs (symlink leaf names).
    const link_owned = try allocator.dupe(u8, argv0);
    errdefer allocator.free(link_owned);
    const real = realpathOwned(io, allocator, argv0) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            allocator.free(link_owned);
            return .{};
        },
    };
    return .{ .realpath = real, .link_path = link_owned };
}

fn realpathOwned(io: std.Io, allocator: std.mem.Allocator, path: []const u8) ![]const u8 {
    const canonical_z = try std.Io.Dir.cwd().realPathFileAlloc(io, path, allocator);
    defer allocator.free(canonical_z);
    return try allocator.dupe(u8, canonical_z);
}

/// Strip macOS Data-volume firmlink prefix so `/System/Volumes/Data/Users/…` → `/Users/…`.
/// Local twin of `run_os_sandbox.normalizeMacosUsersPath` (no cross-module import).
fn normalizeMacosUsersPath(path: []const u8) []const u8 {
    const data_prefix = "/System/Volumes/Data";
    if (std.mem.startsWith(u8, path, data_prefix) and path.len > data_prefix.len and
        path[data_prefix.len] == '/' and std.mem.startsWith(u8, path[data_prefix.len..], "/Users/"))
    {
        return path[data_prefix.len..];
    }
    return path;
}

/// `isPathWithinRoot` plus Darwin `/var` ↔ `/private/var` dual form (no allocation).
fn isPathWithinRootOrPrivateVarDual(path: []const u8, root: []const u8) bool {
    if (isPathWithinRoot(path, root)) return true;
    // realpath binary often `/private/var/...` while TMPDIR env is `/var/...`
    if (std.mem.startsWith(u8, path, "/private") and isPathWithinRoot(path["/private".len..], root)) return true;
    // inverse: path `/var/...`, root `/private/var/...`
    if (std.mem.startsWith(u8, root, "/private") and isPathWithinRoot(path, root["/private".len..])) return true;
    return false;
}

fn isTmpPath(
    io: std.Io,
    allocator: std.mem.Allocator,
    path: []const u8,
    env_map: ?*const std.process.Environ.Map,
) error{OutOfMemory}!bool {
    const prefixes = [_][]const u8{
        "/tmp/",
        "/private/tmp/",
        "/var/tmp/",
        "/private/var/tmp/",
    };
    for (prefixes) |p| {
        if (std.mem.eql(u8, path, p[0 .. p.len - 1]) or std.mem.startsWith(u8, path, p)) return true;
    }
    // Exact /tmp etc.
    if (std.mem.eql(u8, path, "/tmp") or std.mem.eql(u8, path, "/private/tmp")) return true;

    // Darwin `/var/folders` is process-temp via TMPDIR, not a blanket deny: test
    // fixtures and some tools live under the same tree. Match TMPDIR with
    // `/var`↔`/private/var` dual form + best-effort realpath (apply.zig class).
    // Inject of `/var/folders` / `/private/var` is rejected separately (M-2).
    const tmpdir = blk: {
        if (env_map) |map| {
            if (map.get("TMPDIR")) |t| break :blk t;
        }
        if (std.c.getenv("TMPDIR")) |t| break :blk std.mem.span(t);
        break :blk null;
    };
    if (tmpdir) |td| {
        if (td.len == 0) return false;
        // Lexical TMPDIR vs realpath path: `/var/folders` ↔ `/private/var/folders`.
        if (isPathWithinRootOrPrivateVarDual(path, td)) return true;
        // Best-effort realpath of TMPDIR (custom temp dirs with form mismatch).
        const td_real = realpathOwned(io, allocator, td) catch null;
        if (td_real) |tr| {
            defer allocator.free(tr);
            if (isPathWithinRoot(path, tr) or isPathWithinRootOrPrivateVarDual(path, tr)) return true;
        }
    }
    return false;
}

fn isPathWithinRoot(path: []const u8, root: []const u8) bool {
    if (root.len == 0) return false;
    // Trim trailing slashes on root (except "/")
    var r = root;
    while (r.len > 1 and r[r.len - 1] == '/') r = r[0 .. r.len - 1];
    if (std.mem.eql(u8, path, r)) return true;
    if (path.len > r.len and std.mem.startsWith(u8, path, r) and path[r.len] == '/') return true;
    return false;
}

fn isTrustedInstallPath(
    io: std.Io,
    allocator: std.mem.Allocator,
    path: []const u8,
    env_map: ?*const std.process.Environ.Map,
    extra: []const []const u8,
) error{OutOfMemory}!bool {
    for (builtin_trusted_prefixes) |prefix| {
        if (pathHasTrustedPrefix(path, prefix)) return true;
    }
    for (extra) |prefix| {
        if (pathHasTrustedPrefix(path, prefix)) return true;
    }

    // RYK_TRUSTED_HOST_PREFIXES=colon-separated absolute prefixes (tests + ops extend).
    // Reject over-broad prefixes (filesystem root, bare $HOME, tmp/shared, bare brew roots).
    const injected = blk: {
        if (env_map) |map| {
            if (map.get("RYK_TRUSTED_HOST_PREFIXES")) |v| break :blk v;
        }
        if (std.c.getenv("RYK_TRUSTED_HOST_PREFIXES")) |v| break :blk std.mem.span(v);
        break :blk "";
    };
    if (injected.len > 0) {
        var it = std.mem.splitScalar(u8, injected, ':');
        while (it.next()) |raw| {
            if (!isAcceptableInjectedTrustPrefix(raw, env_map)) continue;
            if (pathHasTrustedPrefix(path, raw)) return true;
        }
    }

    const home_raw = blk: {
        if (env_map) |map| {
            if (map.get("HOME")) |h| break :blk h;
        }
        if (std.c.getenv("HOME")) |h| break :blk std.mem.span(h);
        break :blk "";
    };
    if (home_raw.len > 0 and std.fs.path.isAbsolute(home_raw)) {
        // Realpath HOME best-effort + Users↔Data dual forms (firmlink FN for ~/.local installs).
        const home_real = realpathOwned(io, allocator, home_raw) catch null;
        defer if (home_real) |hr| allocator.free(hr);

        var data_home_owned: ?[]const u8 = null;
        defer if (data_home_owned) |d| allocator.free(d);

        var homes_buf: [4][]const u8 = undefined;
        var homes_len: usize = 0;
        const addHome = struct {
            fn add(buf: *[4][]const u8, len: *usize, h: []const u8) void {
                if (h.len == 0) return;
                for (buf.*[0..len.*]) |existing| {
                    if (std.mem.eql(u8, existing, h)) return;
                }
                if (len.* >= buf.len) return;
                buf.*[len.*] = h;
                len.* += 1;
            }
        }.add;

        addHome(&homes_buf, &homes_len, home_raw);
        if (home_real) |hr| {
            addHome(&homes_buf, &homes_len, hr);
            const norm = normalizeMacosUsersPath(hr);
            if (norm.ptr != hr.ptr) addHome(&homes_buf, &homes_len, norm);
        }
        const home_users = normalizeMacosUsersPath(home_raw);
        if (home_users.ptr != home_raw.ptr) addHome(&homes_buf, &homes_len, home_users);
        // Data-volume dual of Users-form HOME (binary realpath may be Data-prefixed).
        if (std.mem.startsWith(u8, home_users, "/Users")) {
            data_home_owned = try std.fs.path.join(allocator, &.{ "/System/Volumes/Data", home_users });
            addHome(&homes_buf, &homes_len, data_home_owned.?);
        }

        // Also match when path is Data-form and home roots are Users-form via normalize.
        const path_users = normalizeMacosUsersPath(path);

        const home_rels = [_][]const u8{
            ".local/bin",
            ".local/lib",
            ".local/share",
            ".opencode",
            // Grok CLI install layouts only (not whole ~/.grok product home).
            ".grok/bin",
            ".grok/downloads",
            ".npm-global/bin",
        };
        for (homes_buf[0..homes_len]) |home| {
            for (home_rels) |rel| {
                const joined = try std.fs.path.join(allocator, &.{ home, rel });
                defer allocator.free(joined);
                if (isPathWithinRoot(path, joined)) return true;
                if (path_users.ptr != path.ptr and isPathWithinRoot(path_users, joined)) return true;
            }
            // $HOME/.nvm/versions/node/<ver>/bin/<host>
            const nvm_root = try std.fs.path.join(allocator, &.{ home, ".nvm/versions/node" });
            defer allocator.free(nvm_root);
            if (isNvmNodeBinPath(path, nvm_root)) return true;
            if (path_users.ptr != path.ptr and isNvmNodeBinPath(path_users, nvm_root)) return true;
        }
    }

    return false;
}

/// Map resolved binary path → table host key.
/// Strips common script suffixes so npm wrappers (`codex.js`) still bind as `codex`.
fn hostNameFromResolvedPath(path: []const u8) []const u8 {
    const base = host_config_grants.hostBasename(path);
    if (base.len == 0) return base;
    // Exact table match first.
    if (host_config_grants.specForHost(base) != null) return base;
    const suffixes = [_][]const u8{ ".js", ".mjs", ".cjs", ".py", ".sh" };
    for (suffixes) |suf| {
        if (base.len > suf.len and std.mem.endsWith(u8, base, suf)) {
            const stem = base[0 .. base.len - suf.len];
            if (host_config_grants.specForHost(stem) != null) return stem;
        }
    }
    return base;
}

/// True when path is under Grok CLI install dirs (not product home / worktrees).
fn isGrokInstallLayoutPath(path: []const u8) bool {
    return std.mem.indexOf(u8, path, "/.grok/downloads/") != null or
        std.mem.indexOf(u8, path, "/.grok/bin/") != null or
        std.mem.endsWith(u8, path, "/.grok/downloads") or
        std.mem.endsWith(u8, path, "/.grok/bin");
}

/// True when realpath looks like an agent install wrapper (not a system binary).
/// Required before adopting a trusted symlink's basename as the host key.
fn allowsLinkBasenameFallback(realpath: []const u8) bool {
    if (std.mem.indexOf(u8, realpath, "/node_modules/") != null) return true;
    if (std.mem.indexOf(u8, realpath, "/versions/") != null) return true;
    if (std.mem.indexOf(u8, realpath, "/Cellar/") != null) return true;
    // Grok install layouts only (downloads + bin wrappers), not worktrees/skills.
    if (isGrokInstallLayoutPath(realpath)) return true;
    const base = host_config_grants.hostBasename(realpath);
    if (base.len == 0) return false;
    // Script-like leaves (cli.js, codex.js, …).
    if (std.mem.endsWith(u8, base, ".js") or
        std.mem.endsWith(u8, base, ".mjs") or
        std.mem.endsWith(u8, base, ".cjs") or
        std.mem.endsWith(u8, base, ".py"))
        return true;
    // Version-id leaf (e.g. claude …/versions/2.1.196).
    if (std.ascii.isDigit(base[0])) return true;
    // Versioned product leaf only: `grok-0.2.118-macos-aarch64` → stem `grok`.
    // Require a digit after the first dash so `codex-evil` / bare host spoofs cannot
    // unlock link-basename fallback under a trusted prefix (F39).
    if (std.mem.indexOfScalar(u8, base, '-')) |dash| {
        if (dash > 0 and dash + 1 < base.len and std.ascii.isDigit(base[dash + 1]) and
            host_config_grants.specForHost(base[0..dash]) != null)
            return true;
    }
    return false;
}

fn isAcceptableInjectedTrustPrefix(prefix: []const u8, env_map: ?*const std.process.Environ.Map) bool {
    if (prefix.len < 4 or !std.fs.path.isAbsolute(prefix)) return false;

    // Trim trailing slash for policy compares (except "/").
    var p = prefix;
    while (p.len > 1 and p[p.len - 1] == '/') p = p[0 .. p.len - 1];

    // Exact over-broad roots (filesystem, home roots, Darwin tmp/shared, bare brew trees).
    // Bare `/usr/local` and `/opt/homebrew` require a deeper component (bin/Cellar/lib/…).
    const exact_deny = [_][]const u8{
        "/",
        "/Users",
        "/home",
        "/var",
        "/tmp",
        "/private",
        "/private/var",
        "/private/tmp",
        "/var/tmp",
        "/private/var/tmp",
        "/var/folders",
        "/private/var/folders",
        "/Users/Shared",
        "/usr/local",
        "/opt/homebrew",
    };
    for (exact_deny) |d| {
        if (std.mem.eql(u8, p, d)) return false;
    }

    // Reject inject prefixes under tmp / shared / private-var trees (user-writable).
    const under_deny = [_][]const u8{
        "/tmp/",
        "/private/tmp/",
        "/var/tmp/",
        "/private/var/tmp/",
        "/var/folders/",
        "/private/var/folders/",
        "/private/var/",
        "/Users/Shared/",
    };
    for (under_deny) |d| {
        if (std.mem.startsWith(u8, p, d)) return false;
    }

    // Require at least two non-empty components after root (e.g. /opt/homebrew/bin).
    var components: usize = 0;
    var it = std.mem.splitScalar(u8, p, '/');
    while (it.next()) |part| {
        if (part.len == 0) continue;
        components += 1;
    }
    if (components < 2) return false;

    const home = blk: {
        if (env_map) |map| {
            if (map.get("HOME")) |h| break :blk h;
        }
        if (std.c.getenv("HOME")) |h| break :blk std.mem.span(h);
        break :blk "";
    };
    if (home.len > 0) {
        var h = home;
        while (h.len > 1 and h[h.len - 1] == '/') h = h[0 .. h.len - 1];
        if (std.mem.eql(u8, p, h)) return false;
    }
    return true;
}

fn pathHasTrustedPrefix(path: []const u8, prefix: []const u8) bool {
    if (prefix.len == 0 or !std.fs.path.isAbsolute(prefix)) return false;
    var p = prefix;
    // Normalize: allow prefix with or without trailing slash.
    if (p[p.len - 1] != '/') {
        // Exact file match under parent, or directory prefix.
        if (std.mem.eql(u8, path, p)) return true;
        if (path.len > p.len and std.mem.startsWith(u8, path, p) and path[p.len] == '/') return true;
        return false;
    }
    return std.mem.startsWith(u8, path, p) or (path.len + 1 == p.len and std.mem.eql(u8, path, p[0 .. p.len - 1]));
}

/// `$HOME/.nvm/versions/node/<version>/bin/<file>`
fn isNvmNodeBinPath(path: []const u8, nvm_versions_node: []const u8) bool {
    if (!isPathWithinRoot(path, nvm_versions_node)) return false;
    const rest = path[nvm_versions_node.len..];
    // rest = "/<version>/bin/<file>"
    if (rest.len < 6 or rest[0] != '/') return false;
    const after_slash = rest[1..];
    const ver_end = std.mem.indexOfScalar(u8, after_slash, '/') orelse return false;
    if (ver_end == 0) return false;
    const after_ver = after_slash[ver_end..]; // "/bin/..."
    return std.mem.startsWith(u8, after_ver, "/bin/") and after_ver.len > "/bin/".len;
}

// ─── tests ───────────────────────────────────────────────────────────────────

/// Shadow process TMPDIR so zig `tmpDir` fixtures under Darwin `/var/folders`
/// are not auto-classified as tmp after the dual-form TMPDIR fence (M-1).
/// Production launches do not plant trusted hosts under process temp.
const test_tmpdir_sentinel = "/tmp/ryk-host-identity-test-tmpdir-sentinel";

test "resolveHostIdentity trusted-prefix symlink to /bin/sh named codex is generic" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    const home = try home_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(home);
    try home_tmp.dir.createDirPath(io, ".local/bin");
    const link = try std.fs.path.join(allocator, &.{ home, ".local/bin/codex" });
    defer allocator.free(link);
    std.Io.Dir.cwd().symLink(io, "/bin/sh", link, .{}) catch return error.SkipZigTest;

    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    const path_val = try std.fs.path.join(allocator, &.{ home, ".local/bin" });
    defer allocator.free(path_val);
    try env_map.put("HOME", home);
    try env_map.put("PATH", path_val);

    var id = try resolveHostIdentity(io, allocator, "codex", &env_map, .{});
    defer id.deinit(allocator);
    try std.testing.expect(!id.isTrusted());
}

test "resolveHostIdentity workspace symlink to /bin/sh named codex is generic" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws = std.testing.tmpDir(.{});
    defer ws.cleanup();
    const ws_path = try ws.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(ws_path);
    const spoof = try std.fs.path.join(allocator, &.{ ws_path, "codex" });
    defer allocator.free(spoof);
    std.Io.Dir.cwd().symLink(io, "/bin/sh", spoof, .{}) catch return error.SkipZigTest;

    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    try env_map.put("HOME", "/Users/synthetic");
    try env_map.put("PATH", "/usr/bin:/bin");

    var id = try resolveHostIdentity(io, allocator, spoof, &env_map, .{ .workspace_root = ws_path });
    defer id.deinit(allocator);
    try std.testing.expect(!id.isTrusted());
}

test "resolveHostIdentity spoof relative workspace path is generic" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws = std.testing.tmpDir(.{});
    defer ws.cleanup();
    const ws_path = try ws.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(ws_path);

    // Create a workspace binary named codex (spoof).
    {
        const f = try ws.dir.createFile(io, "codex", .{});
        defer f.close(io);
        try f.writeStreamingAll(io, "#!/bin/sh\necho spoof\n");
        try ws.dir.setFilePermissions(io, "codex", @enumFromInt(0o755), .{});
    }
    const spoof = try std.fs.path.join(allocator, &.{ ws_path, "codex" });
    defer allocator.free(spoof);

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    try home_tmp.dir.createDirPath(io, ".codex");
    const home = try home_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(home);

    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    try env_map.put("HOME", home);
    try env_map.put("PATH", "/usr/bin:/bin");

    var id = try resolveHostIdentity(io, allocator, spoof, &env_map, .{ .workspace_root = ws_path });
    defer id.deinit(allocator);
    try std.testing.expect(!id.isTrusted());
    try std.testing.expect(id.deny_reason != null);

    // Collectors with empty host key must yield no grants even when ~/.codex exists.
    const paths = try host_config_grants.collectHostConfigPaths(io, allocator, id.hostKey(), home);
    defer host_config_grants.freeHostConfigPaths(allocator, paths);
    try std.testing.expectEqual(@as(usize, 0), paths.len);
}

test "resolveHostIdentity spoof absolute tmp path is generic" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_path = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(tmp_path);

    // Only assert tmp deny when the tmpDir actually lands under a tmp prefix
    // (zig testing tmp often does). Otherwise inject as untrusted non-prefix.
    {
        const f = try tmp.dir.createFile(io, "claude", .{});
        defer f.close(io);
        try f.writeStreamingAll(io, "#!/bin/sh\n");
        try tmp.dir.setFilePermissions(io, "claude", @enumFromInt(0o755), .{});
    }
    const spoof = try std.fs.path.join(allocator, &.{ tmp_path, "claude" });
    defer allocator.free(spoof);

    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    try env_map.put("HOME", "/Users/synthetic");
    try env_map.put("PATH", "/usr/bin:/bin");

    var id = try resolveHostIdentity(io, allocator, spoof, &env_map, .{});
    defer id.deinit(allocator);
    try std.testing.expect(!id.isTrusted());
    // Either tmp_path or untrusted_prefix depending on where zig places tmpDir.
    try std.testing.expect(id.deny_reason != null);
    try std.testing.expectEqualStrings("", id.hostKey());
}

test "resolveHostIdentity basename alone without resolve is generic" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    // PATH with nothing that resolves "codex"
    try env_map.put("PATH", "/nonexistent/bin");
    try env_map.put("HOME", "/Users/synthetic");

    var id = try resolveHostIdentity(io, allocator, "codex", &env_map, .{});
    defer id.deinit(allocator);
    try std.testing.expect(!id.isTrusted());
    try std.testing.expectEqualStrings(deny_unresolved, id.deny_reason.?);
}

test "resolveHostIdentity trusted fixture under injected prefix grants host" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var trust = std.testing.tmpDir(.{});
    defer trust.cleanup();
    const trust_root = try trust.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(trust_root);

    {
        const f = try trust.dir.createFile(io, "codex", .{});
        defer f.close(io);
        try f.writeStreamingAll(io, "#!/bin/sh\necho ok\n");
        try trust.dir.setFilePermissions(io, "codex", @enumFromInt(0o755), .{});
    }
    const binary = try std.fs.path.join(allocator, &.{ trust_root, "codex" });
    defer allocator.free(binary);

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    try home_tmp.dir.createDirPath(io, ".codex");
    try home_tmp.dir.createDirPath(io, ".agents");
    const home = try home_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(home);

    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    try env_map.put("HOME", home);
    try env_map.put("PATH", trust_root); // bare "codex" resolves here
    // Fixture lives under zig tmpDir (process TMPDIR); shadow so tmp fence does not deny.
    try env_map.put("TMPDIR", test_tmpdir_sentinel);

    var id = try resolveHostIdentity(io, allocator, "codex", &env_map, .{
        .extra_trusted_prefixes = &.{trust_root},
    });
    defer id.deinit(allocator);
    try std.testing.expect(id.isTrusted());
    try std.testing.expectEqualStrings("codex", id.host.?);

    const paths = try host_config_grants.collectHostConfigPaths(io, allocator, id.hostKey(), home);
    defer host_config_grants.freeHostConfigPaths(allocator, paths);
    try std.testing.expect(paths.len >= 1);
    var saw_codex = false;
    for (paths) |p| {
        if (std.mem.endsWith(u8, p, "/.codex")) saw_codex = true;
    }
    try std.testing.expect(saw_codex);

    // System RO for trusted codex
    const sys = try host_config_grants.collectHostSystemRoPaths(allocator, id.hostKey());
    defer host_config_grants.freeHostSystemRoPaths(allocator, sys);
    try std.testing.expect(sys.len >= 1);
}

test "resolveHostIdentity wrong basename under trusted prefix is generic" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var trust = std.testing.tmpDir(.{});
    defer trust.cleanup();
    const trust_root = try trust.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(trust_root);
    {
        const f = try trust.dir.createFile(io, "not-an-agent", .{});
        defer f.close(io);
        try f.writeStreamingAll(io, "#!/bin/sh\n");
        try trust.dir.setFilePermissions(io, "not-an-agent", @enumFromInt(0o755), .{});
    }
    const binary = try std.fs.path.join(allocator, &.{ trust_root, "not-an-agent" });
    defer allocator.free(binary);

    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    try env_map.put("HOME", "/Users/synthetic");
    try env_map.put("TMPDIR", test_tmpdir_sentinel);

    var id = try resolveHostIdentity(io, allocator, binary, &env_map, .{
        .extra_trusted_prefixes = &.{trust_root},
    });
    defer id.deinit(allocator);
    try std.testing.expect(!id.isTrusted());
    try std.testing.expectEqualStrings(deny_unknown_host, id.deny_reason.?);
}

test "resolveHostIdentity trusted grok table host" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var trust = std.testing.tmpDir(.{});
    defer trust.cleanup();
    const trust_root = try trust.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(trust_root);
    {
        const f = try trust.dir.createFile(io, "grok", .{});
        defer f.close(io);
        try f.writeStreamingAll(io, "#!/bin/sh\n");
        try trust.dir.setFilePermissions(io, "grok", @enumFromInt(0o755), .{});
    }
    const binary = try std.fs.path.join(allocator, &.{ trust_root, "grok" });
    defer allocator.free(binary);

    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    try env_map.put("HOME", "/Users/synthetic");
    try env_map.put("TMPDIR", test_tmpdir_sentinel);
    // zig tmpDir lands under Darwin `/var/folders` — inject denylist rejects that
    // tree (M-2); use the test-only extra_trusted_prefixes hatch for the fixture.

    var id = try resolveHostIdentity(io, allocator, binary, &env_map, .{
        .extra_trusted_prefixes = &.{trust_root},
    });
    defer id.deinit(allocator);
    try std.testing.expect(id.isTrusted());
    try std.testing.expectEqualStrings("grok", id.host.?);
}

test "resolveHostIdentity rejects non-grok leaf under HOME/.grok/downloads" {
    // F29: planting claude under .grok/downloads must not unlock Claude host grants.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    const home = try home_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(home);

    try home_tmp.dir.createDirPath(io, ".grok/downloads");
    try home_tmp.dir.writeFile(io, .{
        .sub_path = ".grok/downloads/claude",
        .data = "#!/bin/sh\necho planted\n",
    });
    try home_tmp.dir.setFilePermissions(
        io,
        ".grok/downloads/claude",
        std.Io.File.Permissions.fromMode(0o755),
        .{},
    );
    const planted = try std.fs.path.join(allocator, &.{ home, ".grok/downloads/claude" });
    defer allocator.free(planted);

    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    try env_map.put("HOME", home);
    try env_map.put("TMPDIR", test_tmpdir_sentinel);

    var id = try resolveHostIdentity(io, allocator, planted, &env_map, .{});
    defer id.deinit(allocator);
    try std.testing.expect(!id.isTrusted());
}

test "resolveHostIdentity trusts HOME/.grok downloads layout via link basename" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    const home = try home_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(home);

    try home_tmp.dir.createDirPath(io, ".local/bin");
    try home_tmp.dir.createDirPath(io, ".grok/downloads");
    try home_tmp.dir.writeFile(io, .{
        .sub_path = ".grok/downloads/grok-0.2.118-macos-aarch64",
        .data = "#!/bin/sh\necho grok\n",
    });
    try home_tmp.dir.setFilePermissions(
        io,
        ".grok/downloads/grok-0.2.118-macos-aarch64",
        std.Io.File.Permissions.fromMode(0o755),
        .{},
    );
    const real_bin = try std.fs.path.join(allocator, &.{ home, ".grok/downloads/grok-0.2.118-macos-aarch64" });
    defer allocator.free(real_bin);
    const link = try std.fs.path.join(allocator, &.{ home, ".local/bin/grok" });
    defer allocator.free(link);
    std.Io.Dir.cwd().symLink(io, real_bin, link, .{}) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return error.SkipZigTest,
    };

    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    try env_map.put("HOME", home);
    const path_val = try std.fs.path.join(allocator, &.{ home, ".local/bin" });
    defer allocator.free(path_val);
    try env_map.put("PATH", path_val);
    try env_map.put("TMPDIR", test_tmpdir_sentinel);

    var id = try resolveHostIdentity(io, allocator, "grok", &env_map, .{});
    defer id.deinit(allocator);
    try std.testing.expect(id.isTrusted());
    try std.testing.expectEqualStrings("grok", id.host.?);
}

// Issue #194: planted ./grok and /tmp/evil/grok must stay generic — the
// config.toml grant is only for a trusted install identity, never a basename
// spoof or tmp plant. ~/.grok/ itself is not a trusted prefix.
test "resolveHostIdentity planted ./grok and /tmp/evil/grok stay generic" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws = std.testing.tmpDir(.{});
    defer ws.cleanup();
    const ws_path = try ws.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(ws_path);
    {
        const f = try ws.dir.createFile(io, "grok", .{});
        defer f.close(io);
        try f.writeStreamingAll(io, "#!/bin/sh\necho planted\n");
        try ws.dir.setFilePermissions(io, "grok", @enumFromInt(0o755), .{});
    }
    const workspace_plant = try std.fs.path.join(allocator, &.{ ws_path, "grok" });
    defer allocator.free(workspace_plant);

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    const home = try home_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(home);
    try home_tmp.dir.createDirPath(io, ".grok");
    try home_tmp.dir.writeFile(io, .{
        .sub_path = ".grok/config.toml",
        .data = "[cli]\nauto_update = false\n",
    });
    try home_tmp.dir.writeFile(io, .{
        .sub_path = ".grok/auth.json",
        .data = "{\"accessToken\":\"synthetic\"}\n",
    });

    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    try env_map.put("HOME", home);
    try env_map.put("PATH", "/usr/bin:/bin");
    try env_map.put("TMPDIR", test_tmpdir_sentinel);

    var ws_id = try resolveHostIdentity(io, allocator, workspace_plant, &env_map, .{
        .workspace_root = ws_path,
    });
    defer ws_id.deinit(allocator);
    try std.testing.expect(!ws_id.isTrusted());
    try std.testing.expectEqualStrings("", ws_id.hostKey());
    const ws_grants = try host_config_grants.collectHostConfigPaths(io, allocator, ws_id.hostKey(), home);
    defer host_config_grants.freeHostConfigPaths(allocator, ws_grants);
    try std.testing.expectEqual(@as(usize, 0), ws_grants.len);

    var evil = std.testing.tmpDir(.{});
    defer evil.cleanup();
    {
        const f = try evil.dir.createFile(io, "grok", .{});
        defer f.close(io);
        try f.writeStreamingAll(io, "#!/bin/sh\necho evil\n");
        try evil.dir.setFilePermissions(io, "grok", @enumFromInt(0o755), .{});
    }
    const evil_plant = try evil.dir.realPathFileAlloc(io, "grok", allocator);
    defer allocator.free(evil_plant);
    var evil_id = try resolveHostIdentity(io, allocator, evil_plant, &env_map, .{
        .workspace_root = ws_path,
    });
    defer evil_id.deinit(allocator);
    try std.testing.expect(!evil_id.isTrusted());
    try std.testing.expectEqualStrings("", evil_id.hostKey());
    const evil_grants = try host_config_grants.collectHostConfigPaths(io, allocator, evil_id.hostKey(), home);
    defer host_config_grants.freeHostConfigPaths(allocator, evil_grants);
    try std.testing.expectEqual(@as(usize, 0), evil_grants.len);
}

test "resolveHostIdentity rejects grok planted under ~/.grok product home (not a trusted prefix)" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    const home = try home_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(home);
    try home_tmp.dir.createDirPath(io, ".grok/scratch");
    try home_tmp.dir.writeFile(io, .{
        .sub_path = ".grok/scratch/grok",
        .data = "#!/bin/sh\necho planted\n",
    });
    try home_tmp.dir.setFilePermissions(
        io,
        ".grok/scratch/grok",
        std.Io.File.Permissions.fromMode(0o755),
        .{},
    );
    const planted = try std.fs.path.join(allocator, &.{ home, ".grok/scratch/grok" });
    defer allocator.free(planted);

    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    try env_map.put("HOME", home);
    try env_map.put("TMPDIR", test_tmpdir_sentinel);

    var id = try resolveHostIdentity(io, allocator, planted, &env_map, .{});
    defer id.deinit(allocator);
    try std.testing.expect(!id.isTrusted());
    try std.testing.expectEqualStrings("", id.hostKey());
}

test "resolveHostIdentity rejects binary under HOME/.grok/worktrees (not install layout)" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    const home = try home_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(home);

    try home_tmp.dir.createDirPath(io, ".grok/worktrees/x");
    try home_tmp.dir.writeFile(io, .{
        .sub_path = ".grok/worktrees/x/claude",
        .data = "#!/bin/sh\necho claude\n",
    });
    try home_tmp.dir.setFilePermissions(
        io,
        ".grok/worktrees/x/claude",
        std.Io.File.Permissions.fromMode(0o755),
        .{},
    );
    const real_bin = try std.fs.path.join(allocator, &.{ home, ".grok/worktrees/x/claude" });
    defer allocator.free(real_bin);

    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    try env_map.put("HOME", home);
    try env_map.put("TMPDIR", test_tmpdir_sentinel);

    var id = try resolveHostIdentity(io, allocator, real_bin, &env_map, .{});
    defer id.deinit(allocator);
    try std.testing.expect(!id.isTrusted());
}

test "resolveHostIdentity trusted pi table host via extra prefix" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var trust = std.testing.tmpDir(.{});
    defer trust.cleanup();
    const trust_root = try trust.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(trust_root);
    {
        const f = try trust.dir.createFile(io, "pi", .{});
        defer f.close(io);
        try f.writeStreamingAll(io, "#!/bin/sh\n");
        try trust.dir.setFilePermissions(io, "pi", @enumFromInt(0o755), .{});
    }
    const binary = try std.fs.path.join(allocator, &.{ trust_root, "pi" });
    defer allocator.free(binary);

    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    try env_map.put("HOME", "/Users/synthetic");
    try env_map.put("TMPDIR", test_tmpdir_sentinel);

    var id = try resolveHostIdentity(io, allocator, binary, &env_map, .{
        .extra_trusted_prefixes = &.{trust_root},
    });
    defer id.deinit(allocator);
    try std.testing.expect(id.isTrusted());
    try std.testing.expectEqualStrings("pi", id.host.?);
}

test "isTrustedInstallPath RYK_TRUSTED_HOST_PREFIXES accepts narrow non-tmp inject" {
    // Pure path match: acceptable inject prefix (not bare brew / tmp / Shared).
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    try env_map.put("HOME", "/Users/synthetic");
    try env_map.put("RYK_TRUSTED_HOST_PREFIXES", "/Users/synthetic/.tools/bin");

    try std.testing.expect(try isTrustedInstallPath(
        io,
        allocator,
        "/Users/synthetic/.tools/bin/codex",
        &env_map,
        &.{},
    ));
    // Over-broad inject must not open trust (M-2).
    try env_map.put("RYK_TRUSTED_HOST_PREFIXES", "/private/var:/var/folders:/Users/Shared:/usr/local");
    try std.testing.expect(!try isTrustedInstallPath(
        io,
        allocator,
        "/private/var/folders/xx/T/codex",
        &env_map,
        &.{},
    ));
}

test "pathHasTrustedPrefix cellar and bin forms" {
    try std.testing.expect(pathHasTrustedPrefix("/opt/homebrew/bin/codex", "/opt/homebrew/bin/"));
    try std.testing.expect(pathHasTrustedPrefix("/opt/homebrew/Cellar/codex/1.0/bin/codex", "/opt/homebrew/Cellar/"));
    try std.testing.expect(!pathHasTrustedPrefix("/Users/x/codex", "/opt/homebrew/bin/"));
    try std.testing.expect(pathHasTrustedPrefix("/opt/homebrew/bin/codex", "/opt/homebrew/bin"));
}

test "hostNameFromResolvedPath strips npm script suffix" {
    try std.testing.expectEqualStrings("codex", hostNameFromResolvedPath("/Users/x/.local/lib/node_modules/@openai/codex/bin/codex.js"));
    try std.testing.expectEqualStrings("claude", hostNameFromResolvedPath("/opt/homebrew/bin/claude"));
    try std.testing.expectEqualStrings("not-an-agent.js", hostNameFromResolvedPath("/opt/homebrew/bin/not-an-agent.js"));
}

test "resolveHostIdentity trusted npm-style codex.js under local bin" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    const home = try home_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(home);
    try home_tmp.dir.createDirPath(io, ".local/lib/pkg/bin");
    try home_tmp.dir.createDirPath(io, ".local/bin");
    try home_tmp.dir.createDirPath(io, ".codex");
    {
        const f = try home_tmp.dir.createFile(io, ".local/lib/pkg/bin/codex.js", .{});
        defer f.close(io);
        try f.writeStreamingAll(io, "#!/bin/sh\necho ok\n");
        try home_tmp.dir.setFilePermissions(io, ".local/lib/pkg/bin/codex.js", @enumFromInt(0o755), .{});
    }
    // Symlink ~/.local/bin/codex → codex.js (npm layout).
    const target = try std.fs.path.join(allocator, &.{ home, ".local/lib/pkg/bin/codex.js" });
    defer allocator.free(target);
    const link = try std.fs.path.join(allocator, &.{ home, ".local/bin/codex" });
    defer allocator.free(link);
    std.Io.Dir.cwd().symLink(io, target, link, .{}) catch {
        // Some tmp layouts may not allow; skip.
        return error.SkipZigTest;
    };

    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    try env_map.put("HOME", home);
    const local_bin = try std.fs.path.join(allocator, &.{ home, ".local/bin" });
    defer allocator.free(local_bin);
    try env_map.put("PATH", local_bin);
    // HOME fixture is under zig tmpDir; shadow process TMPDIR so dual-form fence
    // does not deny the synthetic ~/.local install tree.
    try env_map.put("TMPDIR", test_tmpdir_sentinel);

    var id = try resolveHostIdentity(io, allocator, "codex", &env_map, .{});
    defer id.deinit(allocator);
    try std.testing.expect(id.isTrusted());
    try std.testing.expectEqualStrings("codex", id.host.?);
}

test "isNvmNodeBinPath matches versioned bin only" {
    const root = "/Users/x/.nvm/versions/node";
    try std.testing.expect(isNvmNodeBinPath("/Users/x/.nvm/versions/node/v22.0.0/bin/codex", root));
    try std.testing.expect(!isNvmNodeBinPath("/Users/x/.nvm/versions/node/v22.0.0/lib/codex", root));
    try std.testing.expect(!isNvmNodeBinPath("/Users/x/.nvm/versions/node/codex", root));
}

test "resolveHostIdentity workspace hardlink of trusted binary is generic" {
    // F-02 class: hardlink of a real trusted host binary into the workspace must
    // not inherit host-config (realpath is the workspace path, not the install path).
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var trust = std.testing.tmpDir(.{});
    defer trust.cleanup();
    const trust_root = try trust.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(trust_root);
    {
        const f = try trust.dir.createFile(io, "codex", .{});
        defer f.close(io);
        try f.writeStreamingAll(io, "#!/bin/sh\necho trusted\n");
        try trust.dir.setFilePermissions(io, "codex", @enumFromInt(0o755), .{});
    }
    var ws = std.testing.tmpDir(.{});
    defer ws.cleanup();
    const ws_path = try ws.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(ws_path);
    const spoof = try std.fs.path.join(allocator, &.{ ws_path, "codex" });
    defer allocator.free(spoof);
    // Hardlink across tmp dirs may fail (different volumes) — skip, not fail.
    trust.dir.hardLink("codex", ws.dir, "codex", io, .{}) catch return error.SkipZigTest;

    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    try env_map.put("HOME", "/Users/synthetic");
    try env_map.put("PATH", "/usr/bin:/bin");
    // Workspace fixture under process TMPDIR must not be classified as tmp first.
    try env_map.put("TMPDIR", test_tmpdir_sentinel);

    var id = try resolveHostIdentity(io, allocator, spoof, &env_map, .{
        .workspace_root = ws_path,
        .extra_trusted_prefixes = &.{trust_root},
    });
    defer id.deinit(allocator);
    try std.testing.expect(!id.isTrusted());
    try std.testing.expectEqualStrings(deny_workspace, id.deny_reason.?);
    try std.testing.expectEqualStrings("", id.hostKey());
}

test "RYK_TRUSTED_HOST_PREFIXES rejects over-broad roots" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Plant a codex binary under a synthetic home that is NOT otherwise trusted.
    // zig testing tmp often lands under TMPDIR — identity may deny via tmp_path or
    // untrusted_prefix; either way over-broad inject must not yield trusted.
    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    const home = try home_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(home);
    {
        const f = try home_tmp.dir.createFile(io, "codex", .{});
        defer f.close(io);
        try f.writeStreamingAll(io, "#!/bin/sh\n");
        try home_tmp.dir.setFilePermissions(io, "codex", @enumFromInt(0o755), .{});
    }
    const binary = try std.fs.path.join(allocator, &.{ home, "codex" });
    defer allocator.free(binary);

    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    try env_map.put("HOME", home);
    try env_map.put("PATH", "/usr/bin:/bin");
    // Bare HOME / filesystem root / single-component must not open grants.
    try env_map.put("RYK_TRUSTED_HOST_PREFIXES", "/:/tmp:/Users");

    var id = try resolveHostIdentity(io, allocator, binary, &env_map, .{});
    defer id.deinit(allocator);
    try std.testing.expect(!id.isTrusted());
    try std.testing.expect(id.deny_reason != null);
    try std.testing.expectEqualStrings("", id.hostKey());

    // Injecting bare $HOME must also fail closed.
    try env_map.put("RYK_TRUSTED_HOST_PREFIXES", home);
    var id2 = try resolveHostIdentity(io, allocator, binary, &env_map, .{});
    defer id2.deinit(allocator);
    try std.testing.expect(!id2.isTrusted());
    try std.testing.expect(id2.deny_reason != null);
    try std.testing.expectEqualStrings("", id2.hostKey());
}

test "isAcceptableInjectedTrustPrefix rejects empty slash home and tmp" {
    try std.testing.expect(!isAcceptableInjectedTrustPrefix("", null));
    try std.testing.expect(!isAcceptableInjectedTrustPrefix("/", null));
    try std.testing.expect(!isAcceptableInjectedTrustPrefix("/tmp", null));
    try std.testing.expect(!isAcceptableInjectedTrustPrefix("/Users", null));
    try std.testing.expect(!isAcceptableInjectedTrustPrefix("/home", null));
    try std.testing.expect(!isAcceptableInjectedTrustPrefix("/var", null));
    try std.testing.expect(!isAcceptableInjectedTrustPrefix("/opt", null)); // single component after root
    // Bare brew trees are over-broad; require a deeper component (bin/Cellar/lib/…).
    try std.testing.expect(!isAcceptableInjectedTrustPrefix("/opt/homebrew", null));
    try std.testing.expect(!isAcceptableInjectedTrustPrefix("/usr/local", null));
    try std.testing.expect(isAcceptableInjectedTrustPrefix("/opt/homebrew/bin", null));
    try std.testing.expect(isAcceptableInjectedTrustPrefix("/usr/local/bin", null));

    // Darwin tmp / shared roots (M-2 incomplete-inject-denylist).
    try std.testing.expect(!isAcceptableInjectedTrustPrefix("/private/var", null));
    try std.testing.expect(!isAcceptableInjectedTrustPrefix("/private/var/folders", null));
    try std.testing.expect(!isAcceptableInjectedTrustPrefix("/var/folders", null));
    try std.testing.expect(!isAcceptableInjectedTrustPrefix("/private/tmp", null));
    try std.testing.expect(!isAcceptableInjectedTrustPrefix("/var/tmp", null));
    try std.testing.expect(!isAcceptableInjectedTrustPrefix("/Users/Shared", null));
    try std.testing.expect(!isAcceptableInjectedTrustPrefix("/private/var/folders/xx/yy/T", null));
    try std.testing.expect(!isAcceptableInjectedTrustPrefix("/Users/Shared/Agents", null));

    var env_map = std.process.Environ.Map.init(std.testing.allocator);
    defer env_map.deinit();
    try env_map.put("HOME", "/Users/synthetic");
    try std.testing.expect(!isAcceptableInjectedTrustPrefix("/Users/synthetic", &env_map));
    try std.testing.expect(!isAcceptableInjectedTrustPrefix("/Users/synthetic/", &env_map));
    // Narrow home subdir is acceptable as an ops extension (still not bare home).
    try std.testing.expect(isAcceptableInjectedTrustPrefix("/Users/synthetic/.local/bin", &env_map));
}

test "isTmpPath dual TMPDIR private-var form and classic tmp prefixes" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    try std.testing.expect(try isTmpPath(io, allocator, "/tmp/claude", null));
    try std.testing.expect(try isTmpPath(io, allocator, "/private/tmp/claude", null));
    try std.testing.expect(try isTmpPath(io, allocator, "/var/tmp/claude", null));
    try std.testing.expect(!try isTmpPath(io, allocator, "/opt/homebrew/bin/claude", null));

    // Lexical TMPDIR `/var/folders/...` vs realpath-style `/private/var/folders/...` path
    // (Darwin default — apply.zig isUngrantedHostTmpdir dual-form class).
    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    try env_map.put("TMPDIR", "/var/folders/ns/xmz0/T/");
    try std.testing.expect(try isTmpPath(
        io,
        allocator,
        "/private/var/folders/ns/xmz0/T/planted/claude",
        &env_map,
    ));
    // Inverse dual: lexical private form, path without /private.
    try env_map.put("TMPDIR", "/private/var/folders/ns/xmz0/T/");
    try std.testing.expect(try isTmpPath(
        io,
        allocator,
        "/var/folders/ns/xmz0/T/planted/claude",
        &env_map,
    ));
    // Outside TMPDIR must not match solely because path is under /var/folders.
    try env_map.put("TMPDIR", "/var/folders/other/T/");
    try std.testing.expect(!try isTmpPath(
        io,
        allocator,
        "/private/var/folders/ns/xmz0/T/planted/claude",
        &env_map,
    ));
}

test "resolveHostIdentity realpath under TMPDIR with lexical dual form denies tmp" {
    // M-1: binary realpath under process temp must hit deny_tmp even when env TMPDIR
    // is the non-private `/var/folders/...` form (Darwin default).
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_path = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(tmp_path);

    // Only assert deny_tmp when the tmpDir actually lands under Darwin folders/tmp.
    const under_tmp_tree = std.mem.startsWith(u8, tmp_path, "/var/folders/") or
        std.mem.startsWith(u8, tmp_path, "/private/var/folders/") or
        std.mem.startsWith(u8, tmp_path, "/tmp/") or
        std.mem.startsWith(u8, tmp_path, "/private/tmp/");
    if (!under_tmp_tree) return error.SkipZigTest;

    {
        const f = try tmp.dir.createFile(io, "claude", .{});
        defer f.close(io);
        try f.writeStreamingAll(io, "#!/bin/sh\n");
        try tmp.dir.setFilePermissions(io, "claude", @enumFromInt(0o755), .{});
    }
    const spoof = try std.fs.path.join(allocator, &.{ tmp_path, "claude" });
    defer allocator.free(spoof);

    // Lexical TMPDIR: prefer dual form of realpath when private-prefixed.
    const lexical_tmpdir = if (std.mem.startsWith(u8, tmp_path, "/private"))
        tmp_path["/private".len..]
    else
        tmp_path;

    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    try env_map.put("HOME", "/Users/synthetic");
    try env_map.put("PATH", "/usr/bin:/bin");
    try env_map.put("TMPDIR", lexical_tmpdir);
    // Even with over-broad inject, tmp fence must win first (deny_tmp, not trusted).
    try env_map.put("RYK_TRUSTED_HOST_PREFIXES", tmp_path);

    var id = try resolveHostIdentity(io, allocator, spoof, &env_map, .{});
    defer id.deinit(allocator);
    try std.testing.expect(!id.isTrusted());
    try std.testing.expectEqualStrings(deny_tmp, id.deny_reason.?);
}

test "isTrustedInstallPath HOME joins match Data-volume realpath form" {
    // M-3: lexical HOME `/Users/…` must trust binary realpath under
    // `/System/Volumes/Data/Users/…/.local/bin/...` (firmlink dual form).
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    try env_map.put("HOME", "/Users/synthetic");

    const data_local_bin = "/System/Volumes/Data/Users/synthetic/.local/bin/codex";
    try std.testing.expect(try isTrustedInstallPath(io, allocator, data_local_bin, &env_map, &.{}));

    const data_nvm = "/System/Volumes/Data/Users/synthetic/.nvm/versions/node/v22.0.0/bin/claude";
    try std.testing.expect(try isTrustedInstallPath(io, allocator, data_nvm, &env_map, &.{}));

    const data_opencode = "/System/Volumes/Data/Users/synthetic/.opencode/bin/opencode";
    try std.testing.expect(try isTrustedInstallPath(io, allocator, data_opencode, &env_map, &.{}));

    // Non-home install under Data volume must not falsely match.
    const data_other = "/System/Volumes/Data/Users/other/.local/bin/codex";
    try std.testing.expect(!try isTrustedInstallPath(io, allocator, data_other, &env_map, &.{}));

    // Lexical Users-form still matches.
    try std.testing.expect(try isTrustedInstallPath(
        io,
        allocator,
        "/Users/synthetic/.local/lib/node_modules/x/bin/codex.js",
        &env_map,
        &.{},
    ));
}

test "RYK_TRUSTED_HOST_PREFIXES rejects Darwin tmp Shared and bare brew roots" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var trust = std.testing.tmpDir(.{});
    defer trust.cleanup();
    // Plant under a path that is NOT itself a tmp tree when possible; if zig tmp
    // lands under folders, inject of that path is rejected by the denylist and
    // identity stays generic either way.
    const trust_root = try trust.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(trust_root);
    {
        const f = try trust.dir.createFile(io, "codex", .{});
        defer f.close(io);
        try f.writeStreamingAll(io, "#!/bin/sh\n");
        try trust.dir.setFilePermissions(io, "codex", @enumFromInt(0o755), .{});
    }
    const binary = try std.fs.path.join(allocator, &.{ trust_root, "codex" });
    defer allocator.free(binary);

    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    try env_map.put("HOME", "/Users/synthetic");
    try env_map.put("PATH", "/usr/bin:/bin");
    try env_map.put("RYK_TRUSTED_HOST_PREFIXES", "/private/var:/var/folders:/Users/Shared:/usr/local:/opt/homebrew");

    var id = try resolveHostIdentity(io, allocator, binary, &env_map, .{});
    defer id.deinit(allocator);
    try std.testing.expect(!id.isTrusted());
    try std.testing.expect(id.deny_reason != null);
    try std.testing.expectEqualStrings("", id.hostKey());
}

//! Child-environment scrub for agent launch.
//!
//! Pure denylist filter for injection / library-preload vectors. Production
//! apply-before-exec (`apply.applyBeforeExec`) runs this on the child env map
//! when mode is `on`/`auto`.
//!
//! ## Scrub denylist (removed)
//! - Dynamic linker / preload: all `LD_*`, `GCONV_PATH`, `GLIBC_TUNABLES`, `DYLD_*`
//! - Shell startup injection: `BASH_ENV`, `ENV`, `ZDOTDIR`, `BASH_FUNC_*`,
//!   `PROMPT_COMMAND`, `CDPATH`, `IFS`, `SHELLOPTS`, `BASHOPTS`
//! - Interpreter / startup injection: `PYTHONSTARTUP`, `PYTHONPATH`, `PYTHONHOME`,
//!   `NODE_OPTIONS`, `NODE_PATH`, `RUBYOPT`, `RUBYLIB`, `PERL5OPT`, `PERL5LIB`,
//!   `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, `DOTNET_STARTUP_HOOKS`
//! - TLS / crypto config injection: `OPENSSL_CONF`, `SSLKEYLOGFILE`
//!
//! ## Keep class (not scrubbed by denylist)
//! - `PATH`, `HOME`, `LANG`, `TERM`
//! - `RYK_*` / `RYK_*` session vars when present
//!
//! ## Launch allowlist (complete form on sandbox attach path)
//! After denylist scrub, `applyBeforeExec` applies a **launch allowlist** only
//! when prepare produces child-apply materials (not on pure grade-drop
//! unavailable). Only known-safe runtime/session keys remain. Secrets,
//! provider credentials, and arbitrary host env vars are stripped. TLS trust
//! (`SSL_CERT_*`, `*_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `GIT_SSL_CAINFO`) is
//! retained. **`SSH_AUTH_SOCK` is stripped by default** on the attach allowlist
//! (host SSH agent socket is not passed through; opt-in re-allow is residual /
//! future). Policy-level filtering in `intercept/env.zig` still runs first;
//! `--secretless` constructs a public-only environment before this allowlist.
//!
//! HOME grants may be restricted separately by FS profile apply; this module
//! does not strip HOME from the allowlist (agents need a home path string).
//!
//! ## Proxy env (M-3)
//! Proxy keys (`HTTP(S)_PROXY` / `ALL_PROXY` / `NO_PROXY`, both cases) are on the
//! allowlist so ryk loopback inject survives attach. Host proxy **values** that
//! carry URL userinfo (`scheme://user:pass@host`) are rewritten to drop userinfo
//! (`scheme://host…`) so credentials cannot ride into the child. Prefer ryk
//! `appendProxyEnvironment` (both cases) so loopback wins over host proxies.

const std = @import("std");
const builtin = @import("builtin");

/// Exact env names removed for shell/interpreter/library injection.
/// (Most `LD_*` are covered by the `LD_` prefix; exact entries kept for docs/tests.)
pub const exact_scrub_keys = [_][]const u8{
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "LD_DEBUG_OUTPUT",
    "GCONV_PATH",
    "GLIBC_TUNABLES",
    "BASH_ENV",
    "ENV",
    "ZDOTDIR",
    "PROMPT_COMMAND",
    "CDPATH",
    "IFS",
    "SHELLOPTS",
    "BASHOPTS",
    "PYTHONSTARTUP",
    "PYTHONPATH",
    "PYTHONHOME",
    "NODE_OPTIONS",
    "NODE_PATH",
    "RUBYOPT",
    "RUBYLIB",
    "PERL5OPT",
    "PERL5LIB",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "DOTNET_STARTUP_HOOKS",
    "OPENSSL_CONF",
    "SSLKEYLOGFILE",
};

/// Prefixes removed (all matching keys). Case-sensitive.
pub const scrub_prefixes = [_][]const u8{
    "LD_",
    "DYLD_",
    "BASH_FUNC_",
};

/// Documented keepers: never scrubbed by this denylist (allow-through class).
pub const keep_keys = [_][]const u8{
    "PATH",
    "HOME",
    "LANG",
    "TERM",
};

/// Exact keys retained by the launch allowlist.
pub const launch_allow_exact = [_][]const u8{
    "PATH",
    "HOME",
    "LANG",
    "TERM",
    "USER",
    "LOGNAME",
    "SHELL",
    "TMPDIR",
    "TMP",
    "TEMP",
    "TZ",
    "PWD",
    "HOSTNAME",
    "HOST",
    "COLORTERM",
    "NO_COLOR",
    "FORCE_COLOR",
    "TERM_PROGRAM",
    "TERM_PROGRAM_VERSION",
    "SHLVL",
    // EDITOR/VISUAL intentionally omitted: host editor preference can
    // influence agent tooling; keep SHELL for shell workflows.
    // Proxy/network mediation vars installed by ryk itself for the session.
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "http_proxy",
    "https_proxy",
    "NO_PROXY",
    "no_proxy",
    "ALL_PROXY",
    "all_proxy",
    // TLS trust roots — needed for HTTPS agent/tool traffic under allowlist.
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
    "GIT_SSL_CAINFO",
    // Apple libxcselect: ryk pins this to CLT/Xcode Developer under Seatbelt so
    // /usr/bin/git and friends do not hit a false “install developer tools” dialog.
    // Value is only set by ryk to allowlisted paths (or a pre-set allowlisted parent value).
    "DEVELOPER_DIR",
    // Codex configuration root. The run boundary canonicalizes it, restricts it
    // beneath HOME, and grants only that exact tree before this value survives.
    "CODEX_HOME",
    // Host-specific configuration selectors. The run boundary canonicalizes
    // these paths and only grants host-scoped roots beneath HOME. Inline
    // configuration blobs stay stripped because they may contain credentials.
    "CLAUDE_CONFIG_DIR",
    "PI_CODING_AGENT_DIR",
    "OPENCODE_CONFIG",
    "OPENCODE_CONFIG_DIR",
    "HERMES_HOME",
    // Ryk-owned provider gateway endpoints. Empty-backpack filtering rejects
    // host-supplied values; run injects loopback values only after binding.
    "ANTHROPIC_BASE_URL",
    "OPENAI_BASE_URL",
    // SSH_AUTH_SOCK intentionally omitted: host SSH agent socket is stripped
    // on the default attach allowlist (M-10). Opt-in re-allow is residual.
};

/// Prefixes retained by the launch allowlist (in addition to exact keys).
pub const launch_allow_prefixes = [_][]const u8{
    "RYK_",
    "RYK_",
    "LC_",
    "XDG_",
};

/// Proxy mediation keys retained by the launch allowlist (both cases).
/// Values are sanitized (URL userinfo stripped) when kept on the attach path.
pub const launch_proxy_keys = [_][]const u8{
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "http_proxy",
    "https_proxy",
    "NO_PROXY",
    "no_proxy",
    "ALL_PROXY",
    "all_proxy",
};

/// True when `name` is a proxy mediation env key (case-sensitive exact match).
pub fn isProxyEnvKey(name: []const u8) bool {
    for (launch_proxy_keys) |key| {
        if (std.mem.eql(u8, name, key)) return true;
    }
    return false;
}

/// If `value` is a URL with userinfo (`scheme://user:pass@host…`), return an
/// allocated rewrite with userinfo removed (`scheme://host…`). Returns `null`
/// when there is no userinfo to strip (caller must not free). On success the
/// caller owns the returned slice.
pub fn stripProxyUrlUserinfo(allocator: std.mem.Allocator, value: []const u8) error{OutOfMemory}!?[]u8 {
    const scheme_sep = std.mem.indexOf(u8, value, "://") orelse return null;
    const after_scheme = value[scheme_sep + 3 ..];
    if (after_scheme.len == 0) return null;
    const authority_end_rel = std.mem.indexOfAny(u8, after_scheme, "/?#") orelse after_scheme.len;
    const authority = after_scheme[0..authority_end_rel];
    const at = std.mem.indexOfScalar(u8, authority, '@') orelse return null;
    // Drop everything through '@' in the authority; keep scheme://, host[:port], tail.
    const host_start = scheme_sep + 3 + at + 1;
    return try std.fmt.allocPrint(allocator, "{s}{s}", .{ value[0 .. scheme_sep + 3], value[host_start..] });
}

/// True when `name` is in the scrub denylist (exact or prefix match).
pub fn shouldScrubKey(name: []const u8) bool {
    // Keep class always wins (defensive; denylist does not include these).
    if (isKeepClass(name)) return false;

    for (exact_scrub_keys) |key| {
        if (std.mem.eql(u8, name, key)) return true;
    }
    for (scrub_prefixes) |prefix| {
        if (std.mem.startsWith(u8, name, prefix)) return true;
    }
    return false;
}

/// True for documented keepers and `RYK_*` / `RYK_*` session vars.
pub fn isKeepClass(name: []const u8) bool {
    for (keep_keys) |key| {
        if (std.mem.eql(u8, name, key)) return true;
    }
    if (std.mem.startsWith(u8, name, "RYK_")) return true;
    if (std.mem.startsWith(u8, name, "RYK_")) return true;
    return false;
}

/// Windows CreateProcess / loader keys. Missing SYSTEMROOT is a documented
/// source of ERROR_ACCESS_DENIED (5) even for `cmd.exe`. Case-insensitive
/// because the PEB block uses `SystemRoot` / `SYSTEMROOT` interchangeably.
pub fn isWindowsProcessRequiredEnv(name: []const u8) bool {
    const keys = [_][]const u8{
        "SYSTEMROOT",
        "WINDIR",
        "SYSTEMDRIVE",
        "COMSPEC",
        "PATHEXT",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "PROGRAMDATA",
        "NUMBER_OF_PROCESSORS",
        "PROCESSOR_ARCHITECTURE",
        "PROCESSOR_IDENTIFIER",
    };
    for (keys) |key| {
        if (std.ascii.eqlIgnoreCase(name, key)) return true;
    }
    return false;
}

/// True when `name` is retained by the launch allowlist.
pub fn isLaunchAllowlisted(name: []const u8) bool {
    if (isWindowsProcessRequiredEnv(name)) return true;
    for (launch_allow_exact) |key| {
        if (std.mem.eql(u8, name, key)) return true;
    }
    for (launch_allow_prefixes) |prefix| {
        if (std.mem.startsWith(u8, name, prefix)) return true;
    }
    return false;
}

/// Narrow capability used by the launch allowlist to retain session-minted
/// phantom values without importing the intercept layer into the sandbox.
/// The callback must perform exact name-and-value membership, not prefix or
/// shape validation.
pub const MintedEnvLookup = struct {
    context: *const anyopaque,
    containsFn: *const fn (context: *const anyopaque, name: []const u8, value: []const u8) bool,

    pub fn contains(self: MintedEnvLookup, name: []const u8, value: []const u8) bool {
        return self.containsFn(self.context, name, value);
    }
};

/// True when a key/value pair is retained for sandboxed launch.
/// Allowlist-only: empty backpack does not emit `ryk-secret://` local-dummy refs.
pub fn shouldRetainLaunchEnv(name: []const u8, value: []const u8) bool {
    return shouldRetainLaunchEnvWithMints(name, value, null);
}

/// Launch allowlist plus exact, session-owned phantom membership.
pub fn shouldRetainLaunchEnvWithMints(
    name: []const u8,
    value: []const u8,
    minted_env_lookup: ?MintedEnvLookup,
) bool {
    if (isLaunchAllowlisted(name)) return true;
    const lookup = minted_env_lookup orelse return false;
    return lookup.contains(name, value);
}

/// Build a new map with scrubbed keys removed. Source is not modified.
/// Caller owns the returned map and must `deinit` it.
pub fn scrubEnvMap(allocator: std.mem.Allocator, source: *const std.process.Environ.Map) !std.process.Environ.Map {
    var out = std.process.Environ.Map.init(allocator);
    errdefer out.deinit();

    var it = source.iterator();
    while (it.next()) |entry| {
        const name = entry.key_ptr.*;
        if (shouldScrubKey(name)) continue;
        try out.put(name, entry.value_ptr.*);
    }
    return out;
}

/// Remove scrubbed keys from `env_map` in place. Returns count of removals.
///
/// Fail closed: on allocation failure while collecting denylist keys, returns
/// `error.OutOfMemory` rather than succeeding with a partial scrub that could
/// leave `LD_PRELOAD`-class keys in the child environment. Any keys already
/// queued for removal are still removed before the error is returned (best
/// effort cleanup), but the caller must treat the error as incomplete scrub.
pub fn scrubEnvMapInPlace(env_map: *std.process.Environ.Map) error{OutOfMemory}!usize {
    // Owned key copies: swapRemove frees map-owned key storage.
    var to_remove: std.ArrayList([]u8) = .empty;
    defer {
        for (to_remove.items) |key| env_map.allocator.free(key);
        to_remove.deinit(env_map.allocator);
    }

    var incomplete = false;
    var it = env_map.iterator();
    while (it.next()) |entry| {
        const name = entry.key_ptr.*;
        if (!shouldScrubKey(name)) continue;
        const owned = env_map.allocator.dupe(u8, name) catch {
            incomplete = true;
            break;
        };
        to_remove.append(env_map.allocator, owned) catch {
            env_map.allocator.free(owned);
            incomplete = true;
            break;
        };
    }

    var removed: usize = 0;
    for (to_remove.items) |name| {
        if (env_map.swapRemove(name)) removed += 1;
    }

    if (incomplete) return error.OutOfMemory;
    return removed;
}

/// Remove keys not on the launch allowlist. Returns count of removals.
///
/// Fail closed on OOM while collecting keys (same contract as denylist scrub).
/// Called from `applyBeforeExec` only when prepare yields child-apply materials
/// (not on pure grade-drop), after denylist `scrubEnvMapInPlace`.
///
/// After removals, retained proxy URL values have userinfo stripped so host
/// proxy credentials cannot pass into the sandboxed child (M-3).
pub fn applyLaunchAllowlistInPlace(env_map: *std.process.Environ.Map) error{OutOfMemory}!usize {
    return applyLaunchAllowlistInPlaceWithMints(env_map, null);
}

/// Apply the launch allowlist while retaining only exact phantoms recognized
/// by the session mint table.
pub fn applyLaunchAllowlistInPlaceWithMints(
    env_map: *std.process.Environ.Map,
    minted_env_lookup: ?MintedEnvLookup,
) error{OutOfMemory}!usize {
    var to_remove: std.ArrayList([]u8) = .empty;
    defer {
        for (to_remove.items) |key| env_map.allocator.free(key);
        to_remove.deinit(env_map.allocator);
    }

    var incomplete = false;
    var it = env_map.iterator();
    while (it.next()) |entry| {
        const name = entry.key_ptr.*;
        const value = entry.value_ptr.*;
        if (shouldRetainLaunchEnvWithMints(name, value, minted_env_lookup)) continue;
        const owned = env_map.allocator.dupe(u8, name) catch {
            incomplete = true;
            break;
        };
        to_remove.append(env_map.allocator, owned) catch {
            env_map.allocator.free(owned);
            incomplete = true;
            break;
        };
    }

    var removed: usize = 0;
    for (to_remove.items) |name| {
        if (env_map.swapRemove(name)) removed += 1;
    }

    if (incomplete) return error.OutOfMemory;

    // Sanitize retained proxy values after the key set is final.
    try sanitizeRetainedProxyEnvInPlace(env_map);
    // Empty backpack often has no host SSL_CERT_*; rustls agents then fail with
    // UnknownIssuer under Seatbelt (Security.framework residual). Pin the system
    // PEM bundle that system RO already grants.
    try ensureDefaultTlsTrustEnv(env_map);
    return removed;
}

/// Default system CA PEM for sandboxed TLS (matches macOS/Linux system RO leaves).
/// Prefer an already-set SSL_CERT_FILE; otherwise the first known public path.
pub fn defaultSystemCaBundlePath() ?[]const u8 {
    return switch (builtin.os.tag) {
        .macos => "/etc/ssl/cert.pem",
        .linux => "/etc/ssl/certs/ca-certificates.crt",
        else => null,
    };
}

/// If the child env has no SSL_CERT_FILE after allowlist, inject the public
/// system CA PEM (and mirror to common CA env names when unset). Never
/// overwrites a parent-provided path. No-op when no platform default exists.
pub fn ensureDefaultTlsTrustEnv(env_map: *std.process.Environ.Map) error{OutOfMemory}!void {
    const ca = defaultSystemCaBundlePath() orelse return;
    if (env_map.get("SSL_CERT_FILE") == null) {
        try env_map.put("SSL_CERT_FILE", ca);
    }
    // Mirror for stacks that ignore SSL_CERT_FILE but honor these names.
    if (env_map.get("CURL_CA_BUNDLE") == null) {
        try env_map.put("CURL_CA_BUNDLE", ca);
    }
    if (env_map.get("REQUESTS_CA_BUNDLE") == null) {
        try env_map.put("REQUESTS_CA_BUNDLE", ca);
    }
    if (env_map.get("GIT_SSL_CAINFO") == null) {
        try env_map.put("GIT_SSL_CAINFO", ca);
    }
}

/// Strip URL userinfo from retained proxy env values in place.
/// Non-proxy keys and values without userinfo are left unchanged.
pub fn sanitizeRetainedProxyEnvInPlace(env_map: *std.process.Environ.Map) error{OutOfMemory}!void {
    const Rewrite = struct {
        name: []u8,
        value: []u8,
    };
    var rewrites: std.ArrayList(Rewrite) = .empty;
    defer {
        for (rewrites.items) |item| {
            env_map.allocator.free(item.name);
            env_map.allocator.free(item.value);
        }
        rewrites.deinit(env_map.allocator);
    }

    var it = env_map.iterator();
    while (it.next()) |entry| {
        const name = entry.key_ptr.*;
        if (!isProxyEnvKey(name)) continue;
        const value = entry.value_ptr.*;
        const stripped = (stripProxyUrlUserinfo(env_map.allocator, value) catch return error.OutOfMemory) orelse continue;
        const owned_name = env_map.allocator.dupe(u8, name) catch {
            env_map.allocator.free(stripped);
            return error.OutOfMemory;
        };
        rewrites.append(env_map.allocator, .{ .name = owned_name, .value = stripped }) catch {
            env_map.allocator.free(owned_name);
            env_map.allocator.free(stripped);
            return error.OutOfMemory;
        };
    }

    for (rewrites.items) |item| {
        // Environ.Map.put copies key/value; our temps are freed in defer.
        try env_map.put(item.name, item.value);
    }
}

test "shouldScrubKey removes LD_PRELOAD LD_LIBRARY_PATH BASH_ENV ENV ZDOTDIR" {
    try std.testing.expect(shouldScrubKey("LD_PRELOAD"));
    try std.testing.expect(shouldScrubKey("LD_LIBRARY_PATH"));
    try std.testing.expect(shouldScrubKey("BASH_ENV"));
    try std.testing.expect(shouldScrubKey("ENV"));
    try std.testing.expect(shouldScrubKey("ZDOTDIR"));
}

test "shouldScrubKey removes all DYLD_ prefix vars" {
    try std.testing.expect(shouldScrubKey("DYLD_INSERT_LIBRARIES"));
    try std.testing.expect(shouldScrubKey("DYLD_LIBRARY_PATH"));
    try std.testing.expect(shouldScrubKey("DYLD_FALLBACK_LIBRARY_PATH"));
    try std.testing.expect(shouldScrubKey("DYLD_FRAMEWORK_PATH"));
}

test "shouldScrubKey removes interpreter startup injection class" {
    try std.testing.expect(shouldScrubKey("PYTHONSTARTUP"));
    try std.testing.expect(shouldScrubKey("PYTHONPATH"));
    try std.testing.expect(shouldScrubKey("NODE_OPTIONS"));
    try std.testing.expect(shouldScrubKey("RUBYOPT"));
    try std.testing.expect(shouldScrubKey("PERL5OPT"));
}

test "shouldScrubKey removes expanded linker and runtime injection keys" {
    try std.testing.expect(shouldScrubKey("LD_AUDIT"));
    try std.testing.expect(shouldScrubKey("GCONV_PATH"));
    try std.testing.expect(shouldScrubKey("LD_DEBUG_OUTPUT"));
    try std.testing.expect(shouldScrubKey("LD_USE_LOAD_BIAS")); // LD_ prefix
    try std.testing.expect(shouldScrubKey("GLIBC_TUNABLES"));
    try std.testing.expect(shouldScrubKey("OPENSSL_CONF"));
    try std.testing.expect(shouldScrubKey("SSLKEYLOGFILE"));
    try std.testing.expect(shouldScrubKey("PYTHONHOME"));
    try std.testing.expect(shouldScrubKey("NODE_PATH"));
    try std.testing.expect(shouldScrubKey("PROMPT_COMMAND"));
    try std.testing.expect(shouldScrubKey("CDPATH"));
    try std.testing.expect(shouldScrubKey("IFS"));
    try std.testing.expect(shouldScrubKey("DOTNET_STARTUP_HOOKS"));
    try std.testing.expect(shouldScrubKey("JAVA_TOOL_OPTIONS"));
    try std.testing.expect(shouldScrubKey("_JAVA_OPTIONS"));
    try std.testing.expect(shouldScrubKey("PERL5LIB"));
    try std.testing.expect(shouldScrubKey("RUBYLIB"));
}

test "shouldScrubKey removes BASH_FUNC_ prefix vars" {
    try std.testing.expect(shouldScrubKey("BASH_FUNC_evil%%"));
    try std.testing.expect(shouldScrubKey("BASH_FUNC_foo"));
    try std.testing.expect(!shouldScrubKey("BASH_FUN")); // not the prefix
    try std.testing.expect(!shouldScrubKey("MY_BASH_FUNC_X")); // not a prefix match
}

test "shouldScrubKey keeps PATH HOME LANG TERM and RYK_ session vars" {
    try std.testing.expect(!shouldScrubKey("PATH"));
    try std.testing.expect(!shouldScrubKey("HOME"));
    try std.testing.expect(!shouldScrubKey("LANG"));
    try std.testing.expect(!shouldScrubKey("TERM"));
    try std.testing.expect(!shouldScrubKey("RYK_SESSION_ID"));
    try std.testing.expect(!shouldScrubKey("RYK_MODE"));
    try std.testing.expect(isKeepClass("PATH"));
    try std.testing.expect(isKeepClass("HOME"));
    try std.testing.expect(isKeepClass("LANG"));
    try std.testing.expect(isKeepClass("TERM"));
    try std.testing.expect(isKeepClass("RYK_SESSION_ID"));
    try std.testing.expect(isKeepClass("RYK_MODE"));
}

test "shouldScrubKey does not scrub unrelated vars" {
    try std.testing.expect(!shouldScrubKey("USER"));
    try std.testing.expect(!shouldScrubKey("SHELL"));
    try std.testing.expect(!shouldScrubKey("OPENAI_API_KEY"));
    try std.testing.expect(!shouldScrubKey("MY_DYLD_NOT_PREFIX")); // not DYLD_ prefix
}

test "scrubEnvMap filters denylist and preserves keepers" {
    var source = std.process.Environ.Map.init(std.testing.allocator);
    defer source.deinit();
    try source.put("PATH", "/usr/bin");
    try source.put("HOME", "/home/agent");
    try source.put("LANG", "C");
    try source.put("TERM", "xterm");
    try source.put("RYK_SESSION_ID", "sess-1");
    try source.put("LD_PRELOAD", "evil.so");
    try source.put("LD_LIBRARY_PATH", "/evil");
    try source.put("LD_AUDIT", "evil_audit.so");
    try source.put("GCONV_PATH", "/evil/gconv");
    try source.put("LD_DEBUG_OUTPUT", "/tmp/ld.debug");
    try source.put("DYLD_INSERT_LIBRARIES", "evil.dylib");
    try source.put("BASH_ENV", "/tmp/evil.sh");
    try source.put("ENV", "/tmp/evil.sh");
    try source.put("ZDOTDIR", "/tmp");
    try source.put("BASH_FUNC_evil%%", "() { evil; }");
    try source.put("PYTHONSTARTUP", "/tmp/sitecustomize.py");
    try source.put("PYTHONPATH", "/tmp/hostile");
    try source.put("NODE_OPTIONS", "--require /tmp/x.js");
    try source.put("RUBYOPT", "-r/tmp/x");
    try source.put("RUBYLIB", "/tmp/hostile");
    try source.put("PERL5OPT", "-Mevil");
    try source.put("PERL5LIB", "/tmp/hostile");
    try source.put("JAVA_TOOL_OPTIONS", "-javaagent:evil.jar");
    try source.put("_JAVA_OPTIONS", "-javaagent:evil.jar");
    try source.put("DOTNET_STARTUP_HOOKS", "/tmp/evil.dll");
    try source.put("SAFE_CUSTOM", "ok");

    var scrubbed = try scrubEnvMap(std.testing.allocator, &source);
    defer scrubbed.deinit();

    try std.testing.expectEqualStrings("/usr/bin", scrubbed.get("PATH").?);
    try std.testing.expectEqualStrings("/home/agent", scrubbed.get("HOME").?);
    try std.testing.expectEqualStrings("C", scrubbed.get("LANG").?);
    try std.testing.expectEqualStrings("xterm", scrubbed.get("TERM").?);
    try std.testing.expectEqualStrings("sess-1", scrubbed.get("RYK_SESSION_ID").?);
    try std.testing.expectEqualStrings("ok", scrubbed.get("SAFE_CUSTOM").?);

    try std.testing.expect(scrubbed.get("LD_PRELOAD") == null);
    try std.testing.expect(scrubbed.get("LD_LIBRARY_PATH") == null);
    try std.testing.expect(scrubbed.get("LD_AUDIT") == null);
    try std.testing.expect(scrubbed.get("GCONV_PATH") == null);
    try std.testing.expect(scrubbed.get("LD_DEBUG_OUTPUT") == null);
    try std.testing.expect(scrubbed.get("DYLD_INSERT_LIBRARIES") == null);
    try std.testing.expect(scrubbed.get("BASH_ENV") == null);
    try std.testing.expect(scrubbed.get("ENV") == null);
    try std.testing.expect(scrubbed.get("ZDOTDIR") == null);
    try std.testing.expect(scrubbed.get("BASH_FUNC_evil%%") == null);
    try std.testing.expect(scrubbed.get("PYTHONSTARTUP") == null);
    try std.testing.expect(scrubbed.get("PYTHONPATH") == null);
    try std.testing.expect(scrubbed.get("NODE_OPTIONS") == null);
    try std.testing.expect(scrubbed.get("RUBYOPT") == null);
    try std.testing.expect(scrubbed.get("RUBYLIB") == null);
    try std.testing.expect(scrubbed.get("PERL5OPT") == null);
    try std.testing.expect(scrubbed.get("PERL5LIB") == null);
    try std.testing.expect(scrubbed.get("JAVA_TOOL_OPTIONS") == null);
    try std.testing.expect(scrubbed.get("_JAVA_OPTIONS") == null);
    try std.testing.expect(scrubbed.get("DOTNET_STARTUP_HOOKS") == null);

    // Source unchanged
    try std.testing.expect(source.get("LD_PRELOAD") != null);
}

test "scrubEnvMapInPlace removes denylist keys" {
    var env_map = std.process.Environ.Map.init(std.testing.allocator);
    defer env_map.deinit();
    try env_map.put("PATH", "/bin");
    try env_map.put("LD_PRELOAD", "x");
    try env_map.put("NODE_OPTIONS", "--require x");
    try env_map.put("JAVA_TOOL_OPTIONS", "-javaagent:x");
    try env_map.put("BASH_FUNC_x%%", "() { :; }");
    try env_map.put("RYK_FOO", "bar");

    const removed = try scrubEnvMapInPlace(&env_map);
    try std.testing.expectEqual(@as(usize, 4), removed);
    try std.testing.expectEqualStrings("/bin", env_map.get("PATH").?);
    try std.testing.expectEqualStrings("bar", env_map.get("RYK_FOO").?);
    try std.testing.expect(env_map.get("LD_PRELOAD") == null);
    try std.testing.expect(env_map.get("NODE_OPTIONS") == null);
    try std.testing.expect(env_map.get("JAVA_TOOL_OPTIONS") == null);
    try std.testing.expect(env_map.get("BASH_FUNC_x%%") == null);
}

test "scrubEnvMapInPlace fails closed on OOM mid-scrub" {
    // Build the map under a FailingAllocator that allows puts, then trip on the
    // next allocation (key-name dupe into to_remove). Incomplete scrub must
    // return error rather than succeed with denylist keys still present.
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = std.math.maxInt(usize) });
    const alloc = failing.allocator();

    var env_map = std.process.Environ.Map.init(alloc);
    defer env_map.deinit();
    try env_map.put("PATH", "/bin");
    try env_map.put("LD_PRELOAD", "evil.so");
    try env_map.put("LD_AUDIT", "evil_audit.so");
    try env_map.put("JAVA_TOOL_OPTIONS", "-javaagent:x");
    try env_map.put("BASH_FUNC_x%%", "() { :; }");

    // Trip the next allocation (first dupe of a scrub key name).
    failing.fail_index = failing.alloc_index;

    try std.testing.expectError(error.OutOfMemory, scrubEnvMapInPlace(&env_map));
    // Contract: error means incomplete scrub — caller must fail closed.
    // Partial best-effort removal of already-queued keys is allowed.
    try std.testing.expect(failing.has_induced_failure);
}

test "keep class and scrub class are disjoint for documented names" {
    for (exact_scrub_keys) |key| {
        try std.testing.expect(shouldScrubKey(key));
        try std.testing.expect(!isKeepClass(key));
    }
    for (keep_keys) |key| {
        try std.testing.expect(!shouldScrubKey(key));
        try std.testing.expect(isKeepClass(key));
    }
}

test "launch allowlist keeps runtime keys and strips secrets" {
    try std.testing.expect(isLaunchAllowlisted("PATH"));
    try std.testing.expect(isLaunchAllowlisted("HOME"));
    try std.testing.expect(isLaunchAllowlisted("CODEX_HOME"));
    try std.testing.expect(isLaunchAllowlisted("CLAUDE_CONFIG_DIR"));
    try std.testing.expect(isLaunchAllowlisted("PI_CODING_AGENT_DIR"));
    try std.testing.expect(isLaunchAllowlisted("OPENCODE_CONFIG"));
    try std.testing.expect(isLaunchAllowlisted("OPENCODE_CONFIG_DIR"));
    try std.testing.expect(isLaunchAllowlisted("HERMES_HOME"));
    // Inline OpenCode config can contain provider and MCP credentials. A file
    // path can be narrowly granted; an arbitrary inherited blob cannot.
    try std.testing.expect(!isLaunchAllowlisted("OPENCODE_CONFIG_CONTENT"));
    try std.testing.expect(isLaunchAllowlisted("RYK_SESSION_ID"));
    try std.testing.expect(isLaunchAllowlisted("LC_ALL"));
    try std.testing.expect(isLaunchAllowlisted("XDG_RUNTIME_DIR"));
    try std.testing.expect(isLaunchAllowlisted("TMPDIR"));
    try std.testing.expect(isLaunchAllowlisted("SHELL"));
    try std.testing.expect(!isLaunchAllowlisted("OPENAI_API_KEY"));
    try std.testing.expect(!isLaunchAllowlisted("AWS_SECRET_ACCESS_KEY"));
    try std.testing.expect(!isLaunchAllowlisted("MY_CUSTOM_TOKEN"));
    try std.testing.expect(!isLaunchAllowlisted("SSLKEYLOGFILE"));
    // Host editor preference must not ride the attach allowlist.
    try std.testing.expect(!isLaunchAllowlisted("EDITOR"));
    try std.testing.expect(!isLaunchAllowlisted("VISUAL"));
}

test "launch allowlist keeps TLS trust and strips SSH_AUTH_SOCK" {
    try std.testing.expect(isLaunchAllowlisted("SSL_CERT_FILE"));
    try std.testing.expect(isLaunchAllowlisted("SSL_CERT_DIR"));
    try std.testing.expect(isLaunchAllowlisted("REQUESTS_CA_BUNDLE"));
    try std.testing.expect(isLaunchAllowlisted("CURL_CA_BUNDLE"));
    try std.testing.expect(isLaunchAllowlisted("NODE_EXTRA_CA_CERTS"));
    try std.testing.expect(isLaunchAllowlisted("GIT_SSL_CAINFO"));
    try std.testing.expect(isLaunchAllowlisted("DEVELOPER_DIR"));
    // Host SSH agent socket is not on the default attach allowlist (M-10).
    try std.testing.expect(!isLaunchAllowlisted("SSH_AUTH_SOCK"));
}

test "launch allowlist keeps Windows CreateProcess-required host keys" {
    try std.testing.expect(isWindowsProcessRequiredEnv("SYSTEMROOT"));
    try std.testing.expect(isWindowsProcessRequiredEnv("SystemRoot"));
    try std.testing.expect(isWindowsProcessRequiredEnv("windir"));
    try std.testing.expect(isWindowsProcessRequiredEnv("ComSpec"));
    try std.testing.expect(isWindowsProcessRequiredEnv("PATHEXT"));
    try std.testing.expect(isWindowsProcessRequiredEnv("USERPROFILE"));
    try std.testing.expect(isLaunchAllowlisted("SYSTEMROOT"));
    try std.testing.expect(isLaunchAllowlisted("SystemRoot"));
    try std.testing.expect(isLaunchAllowlisted("COMSPEC"));
    try std.testing.expect(!isWindowsProcessRequiredEnv("OPENAI_API_KEY"));

    var env_map = std.process.Environ.Map.init(std.testing.allocator);
    defer env_map.deinit();
    try env_map.put("PATH", "C:\\Windows\\System32");
    try env_map.put("SystemRoot", "C:\\Windows");
    try env_map.put("COMSPEC", "C:\\Windows\\System32\\cmd.exe");
    try env_map.put("OPENAI_API_KEY", "sk-test");
    _ = try applyLaunchAllowlistInPlace(&env_map);
    try std.testing.expectEqualStrings("C:\\Windows", env_map.get("SystemRoot").?);
    try std.testing.expectEqualStrings("C:\\Windows\\System32\\cmd.exe", env_map.get("COMSPEC").?);
    try std.testing.expect(env_map.get("OPENAI_API_KEY") == null);
}

test "shouldRetainLaunchEnv is allowlist-only (value shape ignored)" {
    // Retention is allowlist + optional mint table only; untrusted keys reject
    // regardless of ryk-secret:// value shape (no local-dummy matrix).
    try std.testing.expect(!shouldRetainLaunchEnv(
        "GITHUB_TOKEN",
        "ryk-secret://local-dummy/env/GITHUB_TOKEN/d1c2f8b4",
    ));
    try std.testing.expect(!shouldRetainLaunchEnv("SMUGGLE", "ryk-secret://evil/env/X/deadbeef"));
    try std.testing.expect(shouldRetainLaunchEnv("PATH", "ryk-secret://evil"));
    try std.testing.expect(!shouldRetainLaunchEnv("OPENAI_API_KEY", "sk-raw-synthetic"));
}

test "launch allowlist retains only exact mint-table phantom pairs" {
    const MintFixture = struct {
        fn contains(
            context: *const anyopaque,
            name: []const u8,
            value: []const u8,
        ) bool {
            _ = context;
            return std.mem.eql(u8, name, "ANTHROPIC_API_KEY") and
                std.mem.eql(
                    u8,
                    value,
                    "ryk-secret://session/0123456789abcdef0123456789abcdef/ANTHROPIC_API_KEY/0123456789abcdef",
                );
        }
    };
    const sentinel: u8 = 0;
    const lookup: MintedEnvLookup = .{
        .context = &sentinel,
        .containsFn = MintFixture.contains,
    };
    const minted = "ryk-secret://session/0123456789abcdef0123456789abcdef/ANTHROPIC_API_KEY/0123456789abcdef";

    try std.testing.expect(shouldRetainLaunchEnvWithMints("ANTHROPIC_API_KEY", minted, lookup));
    try std.testing.expect(!shouldRetainLaunchEnvWithMints("OPENAI_API_KEY", minted, lookup));
    try std.testing.expect(!shouldRetainLaunchEnvWithMints(
        "ANTHROPIC_API_KEY",
        "ryk-secret://session/evil/ANTHROPIC_API_KEY/0123456789abcdef",
        lookup,
    ));
    try std.testing.expect(!shouldRetainLaunchEnvWithMints("ANTHROPIC_API_KEY", "sk-ant-raw", lookup));
}

test "ensureDefaultTlsTrustEnv injects system CA when missing" {
    var env_map = std.process.Environ.Map.init(std.testing.allocator);
    defer env_map.deinit();
    try env_map.put("PATH", "/usr/bin");
    try ensureDefaultTlsTrustEnv(&env_map);
    if (defaultSystemCaBundlePath()) |ca| {
        try std.testing.expectEqualStrings(ca, env_map.get("SSL_CERT_FILE").?);
        try std.testing.expectEqualStrings(ca, env_map.get("CURL_CA_BUNDLE").?);
        try std.testing.expectEqualStrings(ca, env_map.get("REQUESTS_CA_BUNDLE").?);
        try std.testing.expectEqualStrings(ca, env_map.get("GIT_SSL_CAINFO").?);
    }
    // Never overwrite an explicit parent value.
    try env_map.put("SSL_CERT_FILE", "/custom/ca.pem");
    try ensureDefaultTlsTrustEnv(&env_map);
    try std.testing.expectEqualStrings("/custom/ca.pem", env_map.get("SSL_CERT_FILE").?);
}

test "applyLaunchAllowlistInPlace injects TLS trust when host had none" {
    var env_map = std.process.Environ.Map.init(std.testing.allocator);
    defer env_map.deinit();
    try env_map.put("PATH", "/usr/bin");
    try env_map.put("HOME", "/tmp");
    try env_map.put("SECRET_LEAK", "nope");
    _ = try applyLaunchAllowlistInPlace(&env_map);
    try std.testing.expect(env_map.get("SECRET_LEAK") == null);
    if (defaultSystemCaBundlePath()) |ca| {
        try std.testing.expectEqualStrings(ca, env_map.get("SSL_CERT_FILE").?);
    }
}

test "applyLaunchAllowlistInPlace strips non-allowlisted keys" {
    var env_map = std.process.Environ.Map.init(std.testing.allocator);
    defer env_map.deinit();
    try env_map.put("PATH", "/bin");
    try env_map.put("HOME", "/home/agent");
    try env_map.put("RYK_SESSION_ID", "s1");
    try env_map.put("OPENAI_API_KEY", "sk-test");
    try env_map.put("AWS_SECRET_ACCESS_KEY", "secret");
    try env_map.put("RANDOM_HOST_VAR", "x");
    try env_map.put("SMUGGLE2", "ryk-secret://local-dummy/env/FAKE/aaaaaaaa");
    try env_map.put("GITHUB_TOKEN", "ryk-secret://local-dummy/env/GITHUB_TOKEN/d1c2f8b4");
    try env_map.put("SSL_CERT_FILE", "/etc/ssl/cert.pem");
    try env_map.put("NODE_EXTRA_CA_CERTS", "/etc/ssl/node-ca.pem");
    try env_map.put("GIT_SSL_CAINFO", "/etc/ssl/git-ca.pem");
    try env_map.put("SSH_AUTH_SOCK", "/tmp/ssh-agent.sock");

    const removed = try applyLaunchAllowlistInPlace(&env_map);
    // OPENAI_API_KEY, AWS_SECRET_ACCESS_KEY, RANDOM_HOST_VAR, SMUGGLE2, GITHUB_TOKEN dummy, SSH_AUTH_SOCK.
    try std.testing.expectEqual(@as(usize, 6), removed);
    try std.testing.expectEqualStrings("/bin", env_map.get("PATH").?);
    try std.testing.expectEqualStrings("/home/agent", env_map.get("HOME").?);
    try std.testing.expectEqualStrings("s1", env_map.get("RYK_SESSION_ID").?);
    try std.testing.expect(env_map.get("OPENAI_API_KEY") == null);
    try std.testing.expect(env_map.get("AWS_SECRET_ACCESS_KEY") == null);
    try std.testing.expect(env_map.get("RANDOM_HOST_VAR") == null);
    try std.testing.expect(env_map.get("SMUGGLE2") == null);
    // Empty backpack: local-dummy refs are not retained on the attach allowlist.
    try std.testing.expect(env_map.get("GITHUB_TOKEN") == null);
    // Keepers: TLS trust only (SSH agent socket stripped by default).
    try std.testing.expectEqualStrings("/etc/ssl/cert.pem", env_map.get("SSL_CERT_FILE").?);
    try std.testing.expectEqualStrings("/etc/ssl/node-ca.pem", env_map.get("NODE_EXTRA_CA_CERTS").?);
    try std.testing.expectEqualStrings("/etc/ssl/git-ca.pem", env_map.get("GIT_SSL_CAINFO").?);
    try std.testing.expect(env_map.get("SSH_AUTH_SOCK") == null);
}

test "stripProxyUrlUserinfo removes user:pass from proxy URLs" {
    const stripped = try stripProxyUrlUserinfo(std.testing.allocator, "http://user:s3cret@proxy.example.com:8080");
    try std.testing.expect(stripped != null);
    defer std.testing.allocator.free(stripped.?);
    try std.testing.expectEqualStrings("http://proxy.example.com:8080", stripped.?);

    const with_path = try stripProxyUrlUserinfo(std.testing.allocator, "https://alice:pw@corp.proxy/path?q=1");
    try std.testing.expect(with_path != null);
    defer std.testing.allocator.free(with_path.?);
    try std.testing.expectEqualStrings("https://corp.proxy/path?q=1", with_path.?);

    // No userinfo → null (no allocation).
    try std.testing.expect(try stripProxyUrlUserinfo(std.testing.allocator, "http://127.0.0.1:9") == null);
    try std.testing.expect(try stripProxyUrlUserinfo(std.testing.allocator, "localhost,127.0.0.1") == null);
}

test "applyLaunchAllowlistInPlace redacts credentialed host proxy URLs (M-3)" {
    var env_map = std.process.Environ.Map.init(std.testing.allocator);
    defer env_map.deinit();
    try env_map.put("PATH", "/bin");
    try env_map.put("HTTP_PROXY", "http://user:s3cretPass@evil-proxy.example:3128");
    try env_map.put("https_proxy", "https://alice:hunter2@corp.proxy:8443");
    try env_map.put("ALL_PROXY", "socks5://tok:en@socks.internal");
    try env_map.put("NO_PROXY", "localhost,127.0.0.1");
    try env_map.put("OPENAI_API_KEY", "sk-should-strip");

    _ = try applyLaunchAllowlistInPlace(&env_map);

    // Credentialed proxy URLs must not survive attach allowlist with user:pass intact.
    const http = env_map.get("HTTP_PROXY").?;
    try std.testing.expect(std.mem.indexOf(u8, http, "user:") == null);
    try std.testing.expect(std.mem.indexOf(u8, http, "s3cretPass") == null);
    try std.testing.expect(std.mem.indexOf(u8, http, "@") == null);
    try std.testing.expectEqualStrings("http://evil-proxy.example:3128", http);

    const https = env_map.get("https_proxy").?;
    try std.testing.expect(std.mem.indexOf(u8, https, "alice:") == null);
    try std.testing.expect(std.mem.indexOf(u8, https, "hunter2") == null);
    try std.testing.expectEqualStrings("https://corp.proxy:8443", https);

    const all = env_map.get("ALL_PROXY").?;
    try std.testing.expect(std.mem.indexOf(u8, all, "tok:") == null);
    try std.testing.expectEqualStrings("socks5://socks.internal", all);

    // NO_PROXY host list unchanged; secrets still stripped.
    try std.testing.expectEqualStrings("localhost,127.0.0.1", env_map.get("NO_PROXY").?);
    try std.testing.expect(env_map.get("OPENAI_API_KEY") == null);

    // ryk loopback inject without userinfo is preserved as-is.
    try env_map.put("HTTP_PROXY", "http://127.0.0.1:9");
    try env_map.put("http_proxy", "http://127.0.0.1:9");
    _ = try applyLaunchAllowlistInPlace(&env_map);
    try std.testing.expectEqualStrings("http://127.0.0.1:9", env_map.get("HTTP_PROXY").?);
    try std.testing.expectEqualStrings("http://127.0.0.1:9", env_map.get("http_proxy").?);
}

test "appendProxyEnvironment dual-case inject wins over host proxies (M-3)" {
    // Production inject lives in policy.network_eval; covered here so test-lib
    // actually executes it (ryk_core package tests do not pull network_eval).
    const network_eval = @import("ryk_core").policy.network_eval;
    var env_map = std.process.Environ.Map.init(std.testing.allocator);
    defer env_map.deinit();

    try env_map.put("HTTP_PROXY", "http://user:pass@host-proxy.example:8080");
    try env_map.put("http_proxy", "http://user:pass@host-proxy.example:8080");
    try env_map.put("HTTPS_PROXY", "http://user:pass@host-proxy.example:8080");
    try env_map.put("https_proxy", "http://user:pass@host-proxy.example:8080");
    try env_map.put("ALL_PROXY", "socks5://tok:en@socks.example");
    try env_map.put("all_proxy", "socks5://tok:en@socks.example");
    try env_map.put("NO_PROXY", "evil.example");
    try env_map.put("no_proxy", "evil.example");

    const proxy_url = "http://127.0.0.1:18443";
    const proxy_no = "localhost,127.0.0.1,::1";
    try network_eval.appendProxyEnvironment(&env_map, proxy_url, proxy_no);

    try std.testing.expectEqualStrings(proxy_url, env_map.get("HTTP_PROXY").?);
    try std.testing.expectEqualStrings(proxy_url, env_map.get("http_proxy").?);
    try std.testing.expectEqualStrings(proxy_url, env_map.get("HTTPS_PROXY").?);
    try std.testing.expectEqualStrings(proxy_url, env_map.get("https_proxy").?);
    try std.testing.expectEqualStrings(proxy_url, env_map.get("ALL_PROXY").?);
    try std.testing.expectEqualStrings(proxy_url, env_map.get("all_proxy").?);
    try std.testing.expectEqualStrings(proxy_no, env_map.get("NO_PROXY").?);
    try std.testing.expectEqualStrings(proxy_no, env_map.get("no_proxy").?);
    try std.testing.expectEqualStrings("proxy-mediated", env_map.get("RYK_NETWORK_ENFORCEMENT").?);

    // After inject + allowlist, ryk loopback survives and host credentials stay gone.
    _ = try applyLaunchAllowlistInPlace(&env_map);
    try std.testing.expectEqualStrings(proxy_url, env_map.get("HTTP_PROXY").?);
    try std.testing.expectEqualStrings(proxy_url, env_map.get("http_proxy").?);
    try std.testing.expectEqualStrings(proxy_url, env_map.get("https_proxy").?);
    try std.testing.expect(std.mem.indexOf(u8, env_map.get("HTTP_PROXY").?, "user:") == null);
}

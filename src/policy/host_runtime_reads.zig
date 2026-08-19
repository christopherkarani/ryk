//! Host-runtime file-read catalog (skills + instruction + support files).
//!
//! Coding DCG `files.read.allow` is workspace `./**`. Hosts load skills,
//! walk `AGENTS.md` / `CLAUDE.md`, and read host docs/rules/observations
//! outside the workspace. This leaf classifies those paths so evaluate can
//! allow after explicit deny, before ask.
//!
//! Not sandbox host-config RW. Not leftover unused ask. Not whole `~/.grok`.
//! Reads only.

const std = @import("std");
const matchers = @import("matchers.zig");

pub const host_skill_read_allow_id = "builtin.files.read.allow[host_skill]";
pub const host_instruction_read_allow_id = "builtin.files.read.allow[host_instruction]";
pub const host_support_read_allow_id = "builtin.files.read.allow[host_support]";

pub const MatchKind = enum { none, skill, instruction, support };

pub const EnvPair = struct {
    key: []const u8,
    value: []const u8,
};

const SkillRoot = struct {
    default_home_rel: []const u8,
    env_key: ?[]const u8 = null,
    suffixes: []const []const u8,
};

const skill_roots = [_]SkillRoot{
    .{
        .default_home_rel = ".grok",
        .suffixes = &.{
            "skills",
            "skills/**",
            "bundled/skills",
            "bundled/skills/**",
            "installed-plugins/**/skills",
            "installed-plugins/**/skills/**",
            "third-party",
            "third-party/**",
        },
    },
    .{
        .default_home_rel = ".agents",
        .suffixes = &.{ "skills", "skills/**" },
    },
    .{
        .default_home_rel = ".claude",
        .env_key = "CLAUDE_CONFIG_DIR",
        .suffixes = &.{
            "skills",
            "skills/**",
            "plugins/**/skills",
            "plugins/**/skills/**",
        },
    },
    .{
        .default_home_rel = ".codex",
        .env_key = "CODEX_HOME",
        .suffixes = &.{ "skills", "skills/**" },
    },
    .{
        .default_home_rel = ".cursor",
        .suffixes = &.{
            "skills-cursor",
            "skills-cursor/**",
            "skills",
            "skills/**",
            "plugins/**/skills",
            "plugins/**/skills/**",
        },
    },
    .{
        .default_home_rel = ".pi/agent",
        .env_key = "PI_CODING_AGENT_DIR",
        .suffixes = &.{ "skills", "skills/**" },
    },
    .{
        .default_home_rel = ".hermes",
        .env_key = "HERMES_HOME",
        .suffixes = &.{
            "skills",
            "skills/**",
            "plugins/**/skills",
            "plugins/**/skills/**",
        },
    },
    .{
        .default_home_rel = ".openclaw",
        .suffixes = &.{ "skills", "skills/**" },
    },
};

/// Host working files agents must read (docs, rules, observation logs).
/// Not whole `~/.grok`. Secret basenames and segments still reject.
const support_roots = [_]SkillRoot{
    .{
        .default_home_rel = ".grok",
        .suffixes = &.{
            "docs",
            "docs/**",
            "rules",
            "rules/**",
            "skill-observations",
            "skill-observations/**",
        },
    },
};

const instruction_basenames = [_][]const u8{
    "AGENTS.md",
    "AGENTS.MD",
    "CLAUDE.md",
    "CLAUDE.MD",
};

const secret_segments = [_][]const u8{ ".ssh", ".gnupg", ".aws" };

/// Exact secret file names shared with leftover remapper and DCG deny lists.
/// Not substring globs (`*token*` / `*secret*` / `*credential*`).
const secret_basenames = [_][]const u8{
    ".env",
    "auth.json",
    ".credentials.json",
    "credentials.json",
    "id_ed25519",
    "id_rsa",
    "secrets.json",
    "secrets.yaml",
    "secrets.yml",
    ".secrets",
    "application_default_credentials.json",
    "service_account.json",
    ".npmrc",
    ".netrc",
    ".pypirc",
    ".git-credentials",
    "credentials",
    ".envrc",
    "id_dsa",
    "id_ecdsa",
    "id_ecdsa_sk",
    "id_ed25519_sk",
};

pub fn classify(path: []const u8) MatchKind {
    var pairs: [5]EnvPair = undefined;
    var n: usize = 0;
    inline for (.{
        "HOME",
        "CLAUDE_CONFIG_DIR",
        "CODEX_HOME",
        "HERMES_HOME",
        "PI_CODING_AGENT_DIR",
    }) |key| {
        if (osGet(key)) |value| {
            pairs[n] = .{ .key = key, .value = value };
            n += 1;
        }
    }
    return classifyWithEnv(path, pairs[0..n]);
}

pub fn isHostRuntimeReadPath(path: []const u8) bool {
    return classify(path) != .none;
}

pub fn classifyWithEnv(path: []const u8, env: []const EnvPair) MatchKind {
    if (pathHasDotDotSegment(path)) return .none;
    if (isSecretReadPath(path)) return .none;
    if (isSkillRead(path, env)) return .skill;
    if (isSupportRead(path, env)) return .support;
    if (isInstructionRead(path, envGet(env, "HOME") orelse "")) return .instruction;
    return .none;
}

/// Lexical classify, then if the path exists follow one realpath hop.
/// A catalog path whose target leaves the catalog is `.none`.
/// An unresolved catalog symlink is `.none` (fail closed), not lexical allow.
pub fn classifyExisting(
    io: std.Io,
    allocator: std.mem.Allocator,
    path: []const u8,
) error{OutOfMemory}!MatchKind {
    const lexical = classify(path);
    if (lexical == .none) return .none;
    const expanded = try expandHomePrefix(allocator, path);
    defer allocator.free(expanded);
    const resolved_z = std.Io.Dir.cwd().realPathFileAlloc(io, expanded, allocator) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            var buf: [std.fs.max_path_bytes]u8 = undefined;
            if (std.fs.path.isAbsolute(expanded)) {
                _ = std.Io.Dir.readLinkAbsolute(io, expanded, &buf) catch return lexical;
                return .none;
            }
            _ = std.Io.Dir.cwd().readLink(io, expanded, &buf) catch return lexical;
            return .none;
        },
    };
    defer allocator.free(resolved_z);
    return classify(resolved_z);
}

pub fn isHostRuntimeReadPathWithEnv(path: []const u8, env: []const EnvPair) bool {
    return classifyWithEnv(path, env) != .none;
}

fn osGet(comptime key: [:0]const u8) ?[]const u8 {
    const c = std.c.getenv(key) orelse return null;
    return std.mem.sliceTo(c, 0);
}

fn envGet(env: []const EnvPair, key: []const u8) ?[]const u8 {
    for (env) |pair| {
        if (std.mem.eql(u8, pair.key, key)) return pair.value;
    }
    return null;
}

fn isSkillRead(path: []const u8, env: []const EnvPair) bool {
    const home = envGet(env, "HOME") orelse "";
    for (skill_roots) |root| {
        if (matchRootSuffixes(path, "~", root.default_home_rel, root.suffixes)) return true;
        if (home.len > 0 and std.fs.path.isAbsolute(home) and
            matchRootSuffixes(path, home, root.default_home_rel, root.suffixes))
            return true;
        if (root.env_key) |key| {
            const configured = envGet(env, key) orelse continue;
            if (!std.fs.path.isAbsolute(configured)) continue;
            if (envSkillRootForbidden(configured, home)) continue;
            if (matchRootSuffixes(path, configured, "", root.suffixes)) return true;
        }
    }
    return false;
}

fn matchRootSuffixes(
    path: []const u8,
    root_prefix: []const u8,
    home_rel: []const u8,
    suffixes: []const []const u8,
) bool {
    var buf: [4096]u8 = undefined;
    const prefix = fsAlias(root_prefix);
    const target = fsAlias(path);
    for (suffixes) |suffix| {
        const pattern = joinPattern(&buf, &.{ prefix, home_rel, suffix }) orelse continue;
        if (matchers.matchesPath(pattern, target)) return true;
    }
    return false;
}

/// macOS `/var`, `/tmp`, and `/etc` are the same nodes as `/private/var` etc.
/// Compare catalog homes against realpath'd targets using the public form.
fn macosFsAlias(path: []const u8) []const u8 {
    const prefix = "/private";
    if (path.len <= prefix.len or !std.mem.startsWith(u8, path, prefix) or path[prefix.len] != '/')
        return path;
    const rest = path[prefix.len..];
    const names = [_][]const u8{ "/var", "/tmp", "/etc" };
    for (names) |name| {
        if (std.mem.eql(u8, rest, name)) return rest;
        if (rest.len > name.len and std.mem.startsWith(u8, rest, name) and
            (rest[name.len] == '/' or rest[name.len] == '\\'))
            return rest;
    }
    return path;
}

fn fsAlias(path: []const u8) []const u8 {
    if (path.len == 0 or path[0] != '/') return path;
    return macosFsAlias(path);
}

fn joinPattern(buf: []u8, parts: []const []const u8) ?[]const u8 {
    var i: usize = 0;
    var wrote = false;
    for (parts) |part| {
        if (part.len == 0) continue;
        if (wrote) {
            if (i >= buf.len) return null;
            buf[i] = '/';
            i += 1;
        }
        if (i + part.len > buf.len) return null;
        @memcpy(buf[i..][0..part.len], part);
        i += part.len;
        wrote = true;
    }
    if (!wrote) return null;
    return buf[0..i];
}

fn isSupportRead(path: []const u8, env: []const EnvPair) bool {
    const home = envGet(env, "HOME") orelse "";
    for (support_roots) |root| {
        if (matchRootSuffixes(path, "~", root.default_home_rel, root.suffixes)) return true;
        if (home.len > 0 and std.fs.path.isAbsolute(home) and
            matchRootSuffixes(path, home, root.default_home_rel, root.suffixes))
            return true;
    }
    return false;
}

fn isInstructionRead(path: []const u8, home: []const u8) bool {
    if (pathHasSecretSegment(path)) return false;
    if (!isInstructionBasename(std.fs.path.basename(path))) return false;
    if (std.mem.startsWith(u8, path, "~/")) return true;
    return isUnderHome(path, home);
}

pub fn isSecretReadPath(path: []const u8) bool {
    if (path.len == 0) return false;
    if (isSecretBasename(policyBasename(path))) return true;
    if (pathHasSecretSegment(path)) return true;
    if (isDockerConfigJson(path)) return true;
    return false;
}

pub fn isSecretBasename(name: []const u8) bool {
    if (std.ascii.startsWithIgnoreCase(name, ".env.")) return true;
    for (secret_basenames) |banned| {
        if (std.ascii.eqlIgnoreCase(name, banned)) return true;
    }
    return false;
}

fn policyBasename(path: []const u8) []const u8 {
    var start: usize = 0;
    for (path, 0..) |ch, i| {
        if (ch == '/' or ch == '\\') start = i + 1;
    }
    return path[start..];
}

fn isDockerConfigJson(path: []const u8) bool {
    if (!std.ascii.eqlIgnoreCase(policyBasename(path), "config.json")) return false;
    return pathHasNamedSegment(path, "docker") or pathHasNamedSegment(path, ".docker");
}

fn isInstructionBasename(name: []const u8) bool {
    for (instruction_basenames) |base| {
        if (std.mem.eql(u8, name, base)) return true;
    }
    return false;
}

fn isUnderHome(path: []const u8, home: []const u8) bool {
    const path_n = fsAlias(path);
    const home_n = fsAlias(home);
    if (home_n.len == 0 or !std.fs.path.isAbsolute(home_n)) return false;
    if (!std.fs.path.isAbsolute(path_n)) return false;
    if (path_n.len <= home_n.len) return false;
    if (!std.mem.startsWith(u8, path_n, home_n)) return false;
    return path_n[home_n.len] == '/' or path_n[home_n.len] == '\\';
}

pub fn pathHasDotDotSegment(path: []const u8) bool {
    var unix = std.mem.splitScalar(u8, path, '/');
    while (unix.next()) |seg| {
        if (std.mem.eql(u8, seg, "..")) return true;
    }
    var win = std.mem.splitScalar(u8, path, '\\');
    while (win.next()) |seg| {
        if (std.mem.eql(u8, seg, "..")) return true;
    }
    return false;
}

fn pathHasSecretSegment(path: []const u8) bool {
    var unix = std.mem.splitScalar(u8, path, '/');
    while (unix.next()) |seg| {
        if (isSecretSegment(seg)) return true;
    }
    var win = std.mem.splitScalar(u8, path, '\\');
    while (win.next()) |seg| {
        if (isSecretSegment(seg)) return true;
    }
    return false;
}

fn pathHasNamedSegment(path: []const u8, name: []const u8) bool {
    var unix = std.mem.splitScalar(u8, path, '/');
    while (unix.next()) |seg| {
        if (std.ascii.eqlIgnoreCase(seg, name)) return true;
    }
    var win = std.mem.splitScalar(u8, path, '\\');
    while (win.next()) |seg| {
        if (std.ascii.eqlIgnoreCase(seg, name)) return true;
    }
    return false;
}

fn isSecretSegment(seg: []const u8) bool {
    for (secret_segments) |banned| {
        if (std.ascii.eqlIgnoreCase(seg, banned)) return true;
    }
    return false;
}

fn pathEqualsOrTrailingSlash(path: []const u8, root: []const u8) bool {
    if (std.mem.eql(u8, path, root)) return true;
    return path.len == root.len + 1 and
        std.mem.startsWith(u8, path, root) and
        (path[root.len] == '/' or path[root.len] == '\\');
}

fn envSkillRootForbidden(configured: []const u8, home: []const u8) bool {
    const forbidden = [_][]const u8{ "/", "/tmp", "/var/tmp", "/private/tmp", "/private/var/tmp" };
    for (forbidden) |root| {
        if (pathEqualsOrTrailingSlash(configured, root)) return true;
    }
    if (home.len == 0) return false;
    return pathEqualsOrTrailingSlash(configured, home);
}

fn expandHomePrefix(allocator: std.mem.Allocator, path: []const u8) error{OutOfMemory}![]u8 {
    if (!std.mem.startsWith(u8, path, "~/")) return allocator.dupe(u8, path);
    const home = osGet("HOME") orelse return allocator.dupe(u8, path);
    if (home.len == 0) return allocator.dupe(u8, path);
    return std.fs.path.join(allocator, &.{ home, path[2..] });
}

const test_home = "/tmp/ryk-host-runtime-home";

fn testEnv(extra: []const EnvPair) [6]EnvPair {
    var pairs: [6]EnvPair = undefined;
    pairs[0] = .{ .key = "HOME", .value = test_home };
    for (extra, 0..) |pair, i| {
        pairs[i + 1] = pair;
    }
    return pairs;
}

test "host support catalog allows grok docs rules and observations" {
    const env = testEnv(&.{});
    const allowed = [_][]const u8{
        test_home ++ "/.grok/docs/user-guide/hooks.md",
        test_home ++ "/.grok/docs",
        test_home ++ "/.grok/rules/wax.md",
        test_home ++ "/.grok/skill-observations/log.md",
        "~/.grok/docs/user-guide/hooks.md",
        "~/.grok/rules/wax.md",
        "~/.grok/skill-observations/log.md",
    };
    for (allowed) |path| {
        try std.testing.expectEqual(MatchKind.support, classifyWithEnv(path, env[0..1]));
    }

    try std.testing.expectEqual(
        MatchKind.support,
        classifyWithEnv("/private" ++ test_home ++ "/.grok/skill-observations/log.md", env[0..1]),
    );
    const private_home = [_]EnvPair{.{ .key = "HOME", .value = "/private" ++ test_home }};
    try std.testing.expectEqual(
        MatchKind.support,
        classifyWithEnv(test_home ++ "/.grok/docs/user-guide/hooks.md", &private_home),
    );

    try std.testing.expectEqual(MatchKind.none, classifyWithEnv(test_home ++ "/.grok/auth.json", env[0..1]));
    try std.testing.expectEqual(MatchKind.none, classifyWithEnv(test_home ++ "/.grok/config.toml", env[0..1]));
    try std.testing.expectEqual(MatchKind.none, classifyWithEnv(test_home ++ "/.grok/docs/user-guide/.env", env[0..1]));
    try std.testing.expectEqual(MatchKind.none, classifyWithEnv(test_home ++ "/.grok/docs/.netrc", env[0..1]));
    try std.testing.expectEqual(MatchKind.none, classifyWithEnv(test_home ++ "/.grok/docs/secrets.json", env[0..1]));
    try std.testing.expectEqual(MatchKind.none, classifyWithEnv(test_home ++ "/.grok/skill-observations/secrets.json", env[0..1]));
    try std.testing.expectEqual(MatchKind.none, classifyWithEnv(test_home ++ "/.grok/docs/id_rsa", env[0..1]));
    try std.testing.expectEqual(MatchKind.none, classifyWithEnv("~/.grok/**", env[0..1]));
}

test "host skill catalog allows first-class skill trees under synthetic HOME" {
    const env = testEnv(&.{});
    const allowed = [_][]const u8{
        test_home ++ "/.grok/skills/task-observer/SKILL.md",
        test_home ++ "/.grok/skills",
        test_home ++ "/.grok/bundled/skills/imagine/SKILL.md",
        test_home ++ "/.grok/installed-plugins/cursor-team-kit/skills/check-compiler-errors/SKILL.md",
        test_home ++ "/.grok/third-party/hallmark/SKILL.md",
        test_home ++ "/.agents/skills/zig/SKILL.md",
        test_home ++ "/.claude/skills/doctor/SKILL.md",
        test_home ++ "/.claude/plugins/cache/foo/skills/bar/SKILL.md",
        test_home ++ "/.codex/skills/ryk-doctor/SKILL.md",
        test_home ++ "/.cursor/skills-cursor/review/SKILL.md",
        test_home ++ "/.cursor/skills/custom/SKILL.md",
        test_home ++ "/.cursor/plugins/x/skills/y/SKILL.md",
        test_home ++ "/.pi/agent/skills/tdd/SKILL.md",
        test_home ++ "/.hermes/skills/wiki/SKILL.md",
        test_home ++ "/.hermes/plugins/ryk/skills/protect/SKILL.md",
        test_home ++ "/.openclaw/skills/handoff/SKILL.md",
        "~/.grok/skills/task-observer/SKILL.md",
        "~/.claude/skills/doctor/SKILL.md",
    };
    for (allowed) |path| {
        try std.testing.expectEqual(MatchKind.skill, classifyWithEnv(path, env[0..1]));
    }
}

test "host skill catalog honors env-rooted homes and accumulates defaults" {
    const extra = [_]EnvPair{
        .{ .key = "CLAUDE_CONFIG_DIR", .value = "/custom/claude" },
        .{ .key = "CODEX_HOME", .value = "/custom/codex" },
        .{ .key = "HERMES_HOME", .value = "/custom/hermes" },
        .{ .key = "PI_CODING_AGENT_DIR", .value = "/custom/pi" },
    };
    const env = testEnv(&extra);

    try std.testing.expectEqual(MatchKind.skill, classifyWithEnv("/custom/claude/skills/x/SKILL.md", env[0..5]));
    try std.testing.expectEqual(MatchKind.skill, classifyWithEnv("/custom/codex/skills/x/SKILL.md", env[0..5]));
    try std.testing.expectEqual(MatchKind.skill, classifyWithEnv("/custom/hermes/skills/x/SKILL.md", env[0..5]));
    try std.testing.expectEqual(MatchKind.skill, classifyWithEnv("/custom/pi/skills/x/SKILL.md", env[0..5]));
    try std.testing.expectEqual(MatchKind.skill, classifyWithEnv(test_home ++ "/.claude/skills/x/SKILL.md", env[0..5]));
    try std.testing.expectEqual(MatchKind.none, classifyWithEnv("/custom/claude/settings.json", env[0..5]));
    try std.testing.expectEqual(MatchKind.none, classifyWithEnv("/custom/codex/auth.json", env[0..5]));
}

test "host skill catalog rejects forbidden env-rooted homes" {
    const tmp_extra = [_]EnvPair{
        .{ .key = "CLAUDE_CONFIG_DIR", .value = "/tmp" },
    };
    const tmp_env = testEnv(&tmp_extra);
    try std.testing.expectEqual(MatchKind.none, classifyWithEnv("/tmp/skills/x/SKILL.md", tmp_env[0..2]));
    try std.testing.expectEqual(MatchKind.skill, classifyWithEnv(test_home ++ "/.claude/skills/x/SKILL.md", tmp_env[0..2]));

    const home_extra = [_]EnvPair{
        .{ .key = "CLAUDE_CONFIG_DIR", .value = test_home },
    };
    const home_env = testEnv(&home_extra);
    try std.testing.expectEqual(MatchKind.none, classifyWithEnv(test_home ++ "/skills/x/SKILL.md", home_env[0..2]));
    try std.testing.expectEqual(MatchKind.skill, classifyWithEnv(test_home ++ "/.claude/skills/x/SKILL.md", home_env[0..2]));

    const slash_extra = [_]EnvPair{
        .{ .key = "CLAUDE_CONFIG_DIR", .value = "/" },
        .{ .key = "CODEX_HOME", .value = "/var/tmp" },
        .{ .key = "HERMES_HOME", .value = "/private/tmp" },
        .{ .key = "PI_CODING_AGENT_DIR", .value = "/private/var/tmp" },
    };
    const slash_env = testEnv(&slash_extra);
    try std.testing.expectEqual(MatchKind.none, classifyWithEnv("/skills/x/SKILL.md", slash_env[0..5]));
    try std.testing.expectEqual(MatchKind.none, classifyWithEnv("/var/tmp/skills/x/SKILL.md", slash_env[0..5]));
    try std.testing.expectEqual(MatchKind.none, classifyWithEnv("/private/tmp/skills/x/SKILL.md", slash_env[0..5]));
    try std.testing.expectEqual(MatchKind.none, classifyWithEnv("/private/var/tmp/skills/x/SKILL.md", slash_env[0..5]));

    const custom_extra = [_]EnvPair{.{ .key = "CLAUDE_CONFIG_DIR", .value = "/custom/claude" }};
    const custom_env = testEnv(&custom_extra);
    try std.testing.expectEqual(MatchKind.skill, classifyWithEnv("/custom/claude/skills/x/SKILL.md", custom_env[0..2]));
}

test "host instruction catalog allows AGENTS.md and CLAUDE.md under HOME" {
    const env = testEnv(&.{});
    try std.testing.expectEqual(MatchKind.instruction, classifyWithEnv(test_home ++ "/AGENTS.md", env[0..1]));
    try std.testing.expectEqual(MatchKind.instruction, classifyWithEnv(test_home ++ "/CLAUDE.md", env[0..1]));
    try std.testing.expectEqual(MatchKind.instruction, classifyWithEnv(test_home ++ "/CodingProjects/AGENTS.md", env[0..1]));
    try std.testing.expectEqual(MatchKind.instruction, classifyWithEnv(test_home ++ "/.claude/CLAUDE.md", env[0..1]));
    try std.testing.expectEqual(MatchKind.instruction, classifyWithEnv("~/AGENTS.md", env[0..1]));
    try std.testing.expectEqual(MatchKind.instruction, classifyWithEnv("~/CodingProjects/CLAUDE.md", env[0..1]));
}

test "host runtime catalog rejects secrets traversal and non-catalog paths" {
    const env = testEnv(&.{});
    const blocked = [_][]const u8{
        test_home ++ "/.grok/auth.json",
        test_home ++ "/.grok/config.toml",
        test_home ++ "/.claude/.credentials.json",
        test_home ++ "/.codex/auth.json",
        test_home ++ "/.pi/agent/auth.json",
        test_home ++ "/.hermes/config.yaml",
        test_home ++ "/.ssh/id_ed25519",
        test_home ++ "/.grok/skills/../auth.json",
        test_home ++ "/.grok/skills/x/.env",
        test_home ++ "/.grok/skills/x/.ENV",
        test_home ++ "/.grok/skills/x/AUTH.json",
        test_home ++ "/.grok/skills/x/.ENV.local",
        test_home ++ "/.grok/docs/.netrc",
        test_home ++ "/.grok/third-party/pkg/.npmrc",
        test_home ++ "/.grok/docs/.docker/config.json",
        test_home ++ "/.grok/skills/x/ID_ED25519",
        test_home ++ "/.grok/third-party/pkg/.env.local",
        test_home ++ "/.grok/third-party/pkg/.ssh/config",
        test_home ++ "/.claude/skills/x/auth.json",
        test_home ++ "/.grok/installed-plugins/evil/skills/auth.json",
        test_home ++ "/.claude/skills/x/.credentials.json",
        test_home ++ "/.ssh/AGENTS.md",
        test_home ++ "/.SSH/AGENTS.md",
        test_home ++ "/.SSH/ID_ED25519",
        "~/.SSH/AGENTS.md",
        test_home ++ "/AGENTS.md/../.ssh/id",
        "/etc/passwd",
        test_home ++ "/Notes/todo.md",
        test_home ++ "/.grok/sessions/x.json",
    };
    for (blocked) |path| {
        try std.testing.expectEqual(MatchKind.none, classifyWithEnv(path, env[0..1]));
    }
}

test "host skill catalog rejects case-folded secrets and ssh segments" {
    const env = testEnv(&.{});
    try std.testing.expectEqual(MatchKind.none, classifyWithEnv(test_home ++ "/.grok/skills/x/.ENV", env[0..1]));
    try std.testing.expectEqual(MatchKind.none, classifyWithEnv(test_home ++ "/.grok/skills/x/AUTH.json", env[0..1]));
    try std.testing.expectEqual(MatchKind.none, classifyWithEnv(test_home ++ "/.grok/skills/x/.ENV.local", env[0..1]));
    try std.testing.expectEqual(MatchKind.none, classifyWithEnv(test_home ++ "/.grok/skills/x/ID_ED25519", env[0..1]));
    try std.testing.expectEqual(MatchKind.none, classifyWithEnv(test_home ++ "/.grok/third-party/pkg/.ssh/config", env[0..1]));
    try std.testing.expectEqual(MatchKind.none, classifyWithEnv("~/.SSH/AGENTS.md", env[0..1]));
    try std.testing.expectEqual(MatchKind.skill, classifyWithEnv(test_home ++ "/.grok/third-party/hallmark/SKILL.md", env[0..1]));
}

test "host runtime catalog rejects npmrc netrc and docker config.json" {
    const env = testEnv(&.{});
    try std.testing.expectEqual(MatchKind.none, classifyWithEnv(test_home ++ "/.grok/docs/.netrc", env[0..1]));
    try std.testing.expectEqual(MatchKind.none, classifyWithEnv(test_home ++ "/.grok/third-party/hallmark/.npmrc", env[0..1]));
    try std.testing.expectEqual(MatchKind.none, classifyWithEnv(test_home ++ "/.grok/docs/.docker/config.json", env[0..1]));
    try std.testing.expect(isSecretReadPath(test_home ++ "/.docker/config.json"));
    try std.testing.expect(isSecretReadPath("~/.npmrc"));
    try std.testing.expect(isSecretReadPath("~/.netrc"));
    try std.testing.expect(isSecretReadPath("./.git-credentials"));
    try std.testing.expect(isSecretReadPath("./credentials"));
    try std.testing.expect(isSecretReadPath("/tmp/other/.envrc"));
    try std.testing.expect(isSecretReadPath("./id_ecdsa"));
    try std.testing.expect(!isSecretReadPath("./src/auth/token.zig"));
    try std.testing.expect(!isSecretReadPath(test_home ++ "/.grok/docs/user-guide/hooks.md"));
}

test "skill tree wins over instruction basename inside a skill dir" {
    const env = testEnv(&.{});
    try std.testing.expectEqual(
        MatchKind.skill,
        classifyWithEnv(test_home ++ "/.claude/skills/AGENTS.md", env[0..1]),
    );
}

test "classifyExisting fails closed on unresolved catalog symlink" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "home/.grok/skills/pwn");

    const home = try tmp.dir.realPathFileAlloc(io, "home", std.testing.allocator);
    defer std.testing.allocator.free(home);
    const alias = try std.fs.path.join(std.testing.allocator, &.{ home, ".grok/skills/pwn/SKILL.md" });
    defer std.testing.allocator.free(alias);
    const missing = try std.fs.path.join(std.testing.allocator, &.{ home, ".grok/skills/pwn/missing-target" });
    defer std.testing.allocator.free(missing);
    std.Io.Dir.cwd().symLink(io, missing, alias, .{}) catch |err| switch (err) {
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };

    const prev_home = blk: {
        if (std.c.getenv("HOME")) |value| break :blk try std.testing.allocator.dupeZ(u8, std.mem.span(value));
        break :blk null;
    };
    defer if (prev_home) |value| std.testing.allocator.free(value);
    const home_z = try std.testing.allocator.dupeZ(u8, home);
    defer std.testing.allocator.free(home_z);
    try std.testing.expectEqual(@as(c_int, 0), setenv("HOME", home_z, 1));
    defer {
        if (prev_home) |value| {
            _ = setenv("HOME", value, 1);
        } else {
            _ = unsetenv("HOME");
        }
    }

    try std.testing.expectEqual(MatchKind.skill, classify(alias));
    try std.testing.expectEqual(MatchKind.none, try classifyExisting(io, std.testing.allocator, alias));
}

test "classifyExisting allows skill-observations when HOME is macOS /var/folders alias" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "home/.grok/skill-observations");
    try tmp.dir.createDirPath(io, "home/.grok/docs/user-guide");
    try tmp.dir.writeFile(io, .{ .sub_path = "home/.grok/skill-observations/log.md", .data = "log\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "home/.grok/docs/user-guide/hooks.md", .data = "hooks\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "home/.grok/skill-observations/auth.json", .data = "{}\n" });

    const home_resolved = try tmp.dir.realPathFileAlloc(io, "home", std.testing.allocator);
    defer std.testing.allocator.free(home_resolved);
    const home_alias = macosPublicPath(home_resolved);

    const prev_home = blk: {
        if (std.c.getenv("HOME")) |value| break :blk try std.testing.allocator.dupeZ(u8, std.mem.span(value));
        break :blk null;
    };
    defer if (prev_home) |value| std.testing.allocator.free(value);
    const home_z = try std.testing.allocator.dupeZ(u8, home_alias);
    defer std.testing.allocator.free(home_z);
    try std.testing.expectEqual(@as(c_int, 0), setenv("HOME", home_z, 1));
    defer {
        if (prev_home) |value| {
            _ = setenv("HOME", value, 1);
        } else {
            _ = unsetenv("HOME");
        }
    }

    const log_alias = try std.fmt.allocPrint(std.testing.allocator, "{s}/.grok/skill-observations/log.md", .{home_alias});
    defer std.testing.allocator.free(log_alias);
    const docs_alias = try std.fmt.allocPrint(std.testing.allocator, "{s}/.grok/docs/user-guide/hooks.md", .{home_alias});
    defer std.testing.allocator.free(docs_alias);
    const secret_alias = try std.fmt.allocPrint(std.testing.allocator, "{s}/.grok/skill-observations/auth.json", .{home_alias});
    defer std.testing.allocator.free(secret_alias);

    try std.testing.expectEqual(MatchKind.support, classify(log_alias));
    try std.testing.expectEqual(MatchKind.support, try classifyExisting(io, std.testing.allocator, log_alias));
    try std.testing.expectEqual(MatchKind.support, classify(docs_alias));
    try std.testing.expectEqual(MatchKind.support, try classifyExisting(io, std.testing.allocator, docs_alias));
    try std.testing.expectEqual(MatchKind.none, classify(secret_alias));
    try std.testing.expectEqual(MatchKind.none, try classifyExisting(io, std.testing.allocator, secret_alias));
}

fn macosPublicPath(path: []const u8) []const u8 {
    const prefix = "/private";
    if (path.len > prefix.len and std.mem.startsWith(u8, path, prefix) and path[prefix.len] == '/') {
        return path[prefix.len..];
    }
    return path;
}

extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;
extern "c" fn unsetenv(name: [*:0]const u8) c_int;

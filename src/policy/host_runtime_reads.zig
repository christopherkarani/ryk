//! Host-runtime file-read catalog (skills + instruction files).
//!
//! Coding DCG `files.read.allow` is workspace `./**`. Hosts load skills and
//! walk `AGENTS.md` / `CLAUDE.md` outside the workspace. This leaf classifies
//! those paths so evaluate can allow after explicit deny, before ask.
//!
//! Not sandbox host-config RW. Not leftover unused ask. Reads only.

const std = @import("std");
const matchers = @import("matchers.zig");

pub const host_skill_read_allow_id = "builtin.files.read.allow[host_skill]";
pub const host_instruction_read_allow_id = "builtin.files.read.allow[host_instruction]";

pub const MatchKind = enum { none, skill, instruction };

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

const instruction_basenames = [_][]const u8{
    "AGENTS.md",
    "AGENTS.MD",
    "CLAUDE.md",
    "CLAUDE.MD",
};

const secret_segments = [_][]const u8{ ".ssh", ".gnupg", ".aws" };

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
    if (isSecretBasename(std.fs.path.basename(path))) return .none;
    if (isSkillRead(path, env)) return .skill;
    if (isInstructionRead(path, envGet(env, "HOME") orelse "")) return .instruction;
    return .none;
}

/// Lexical classify, then if the path exists follow one realpath hop.
/// A catalog path whose target leaves the catalog is `.none`.
pub fn classifyExisting(
    io: std.Io,
    allocator: std.mem.Allocator,
    path: []const u8,
) error{OutOfMemory}!MatchKind {
    const lexical = classify(path);
    if (lexical == .none) return .none;
    const resolved_z = std.Io.Dir.cwd().realPathFileAlloc(io, path, allocator) catch return lexical;
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
    for (suffixes) |suffix| {
        const pattern = joinPattern(&buf, &.{ root_prefix, home_rel, suffix }) orelse continue;
        if (matchers.matchesPath(pattern, path)) return true;
    }
    return false;
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

fn isInstructionRead(path: []const u8, home: []const u8) bool {
    if (pathHasSecretSegment(path)) return false;
    if (!isInstructionBasename(std.fs.path.basename(path))) return false;
    if (std.mem.startsWith(u8, path, "~/")) return true;
    return isUnderHome(path, home);
}

fn isSecretBasename(name: []const u8) bool {
    if (std.mem.eql(u8, name, ".env")) return true;
    if (std.mem.startsWith(u8, name, ".env.")) return true;
    if (std.mem.eql(u8, name, "auth.json")) return true;
    if (std.mem.eql(u8, name, ".credentials.json")) return true;
    if (std.mem.eql(u8, name, "credentials.json")) return true;
    return false;
}

fn isInstructionBasename(name: []const u8) bool {
    for (instruction_basenames) |base| {
        if (std.mem.eql(u8, name, base)) return true;
    }
    return false;
}

fn isUnderHome(path: []const u8, home: []const u8) bool {
    if (home.len == 0 or !std.fs.path.isAbsolute(home)) return false;
    if (!std.fs.path.isAbsolute(path)) return false;
    if (path.len <= home.len) return false;
    if (!std.mem.startsWith(u8, path, home)) return false;
    return path[home.len] == '/' or path[home.len] == '\\';
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

fn isSecretSegment(seg: []const u8) bool {
    for (secret_segments) |banned| {
        if (std.mem.eql(u8, seg, banned)) return true;
    }
    return false;
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
        test_home ++ "/.grok/third-party/pkg/.env.local",
        test_home ++ "/.claude/skills/x/auth.json",
        test_home ++ "/.grok/installed-plugins/evil/skills/auth.json",
        test_home ++ "/.claude/skills/x/.credentials.json",
        test_home ++ "/.ssh/AGENTS.md",
        test_home ++ "/AGENTS.md/../.ssh/id",
        "/etc/passwd",
        test_home ++ "/Notes/todo.md",
        test_home ++ "/.grok/sessions/x.json",
    };
    for (blocked) |path| {
        try std.testing.expectEqual(MatchKind.none, classifyWithEnv(path, env[0..1]));
    }
}

test "skill tree wins over instruction basename inside a skill dir" {
    const env = testEnv(&.{});
    try std.testing.expectEqual(
        MatchKind.skill,
        classifyWithEnv(test_home ++ "/.claude/skills/AGENTS.md", env[0..1]),
    );
}

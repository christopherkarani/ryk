//! Oracle pack registry: embed all pack patterns and match via PCRE2.
const std = @import("std");
const builtin = @import("builtin");
const regex_pcre = @import("regex_pcre.zig");
const oracle_embed = @import("oracle_embed.zig");
const Severity = @import("types.zig").Severity;

pub const Hit = struct {
    pack_id: []const u8,
    pattern_name: []const u8,
    severity: Severity,
    reason: []const u8,
    /// Borrowed pack regex source (arena-owned); null for synthetic hits.
    regex_source: ?[]const u8 = null,
    /// Full-match byte span on the candidate string that matched, when known.
    match_start: ?usize = null,
    match_end: ?usize = null,
};

const CompiledPattern = struct {
    name: []const u8,
    reason: []const u8,
    severity: Severity,
    regex_source: []const u8,
    /// Compiled on first use. Hook processes parse default packs without compiling
    /// the full oracle up front; PCRE compile is keyword- and prefix-gated.
    regex: ?regex_pcre.Regex = null,
};

/// Embedded oracle JSON shape. Parsed once into the process arena; pattern
/// strings are borrowed (no per-field dupes). PCRE compile is deferred.
const PackJson = struct {
    id: []const u8,
    keywords: [][]const u8 = &.{},
    safe: []PatternJson = &.{},
    destructive: []PatternJson = &.{},
};

const PatternJson = struct {
    name: []const u8 = "unnamed",
    regex: []const u8,
    reason: []const u8 = "",
    severity: []const u8 = "high",
};

const CompiledPack = struct {
    id: []const u8,
    keywords: []const []const u8,
    safe: []CompiledPattern,
    destructive: []CompiledPattern,
    /// Whether this pack is active under the product default pack set
    /// (Rust `Config::default()`: category `core` + `system.disk`).
    default_enabled: bool,
};

var g_packs: []CompiledPack = &.{};
/// 0=uninit (or failed+reclaimed, retryable), 1=ok, 3=in-progress
var g_state: std.atomic.Value(u8) = .init(0);
var g_arena: std.heap.ArenaAllocator = undefined;
/// True when `g_packs` holds the full oracle, not just default-enabled packs.
var g_full: bool = false;

fn freePatternList(patterns: []CompiledPattern) void {
    for (patterns) |*p| {
        if (p.regex) |*re| re.deinit();
        p.regex = null;
    }
}

fn freePackList(packs: []CompiledPack) void {
    for (packs) |*pack| {
        freePatternList(pack.safe);
        freePatternList(pack.destructive);
    }
}

/// Free C-heap regexes and the process arena after a failed or abandoned init.
fn reclaimRegistry() void {
    freePackList(g_packs);
    g_packs = &.{};
    g_full = false;
    g_arena.deinit();
    g_arena = undefined;
}

fn skipJsonWs(src: []const u8, start: usize) usize {
    var i = start;
    while (i < src.len) : (i += 1) {
        switch (src[i]) {
            ' ', '\t', '\n', '\r' => {},
            else => return i,
        }
    }
    return i;
}

/// String-aware end of a JSON object starting at `start` (`{` … matching `}`).
fn matchingObjectEnd(src: []const u8, start: usize) ?usize {
    if (start >= src.len or src[start] != '{') return null;
    var depth: u32 = 0;
    var i = start;
    var in_string = false;
    var escape = false;
    while (i < src.len) : (i += 1) {
        const c = src[i];
        if (in_string) {
            if (escape) {
                escape = false;
                continue;
            }
            if (c == '\\') {
                escape = true;
                continue;
            }
            if (c == '"') in_string = false;
            continue;
        }
        switch (c) {
            '"' => in_string = true,
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if (depth == 0) return i + 1;
            },
            else => {},
        }
    }
    return null;
}

/// Compact `{"id":"..."` only. A nested `"id"` must not select the pack —
/// callers fall back to a full JSON parse (fail closed on error).
fn packIdFromObject(obj: []const u8) ?[]const u8 {
    const compact = "{\"id\":\"";
    if (!std.mem.startsWith(u8, obj, compact)) return null;
    const start = compact.len;
    const end = std.mem.indexOfScalarPos(u8, obj, start, '"') orelse return null;
    return obj[start..end];
}

/// Leading required literal after an optional `^`. Used to skip PCRE compile
/// when the subject cannot contain that prefix. Skipping a *destructive*
/// pattern is an allow if nothing else hits — `patternMightMatch` must not
/// skip when a depth-0 `|` follows the prefix.
fn requiredPrefixLiteral(regex_source: []const u8) ?[]const u8 {
    var i: usize = 0;
    if (i < regex_source.len and regex_source[i] == '^') i += 1;
    const start = i;
    while (i < regex_source.len) {
        const c = regex_source[i];
        switch (c) {
            '\\', '.', '$', '*', '+', '?', '{', '[', '(', ')', '|', ']' => {
                return if (i > start) regex_source[start..i] else null;
            },
            else => i += 1,
        }
    }
    return if (i > start) regex_source[start..i] else null;
}

fn hasDepth0AlternationAfter(regex_source: []const u8, start: usize) bool {
    var i = start;
    var depth: u32 = 0;
    var in_class = false;
    while (i < regex_source.len) : (i += 1) {
        const c = regex_source[i];
        if (c == '\\') {
            if (i + 1 < regex_source.len) i += 1;
            continue;
        }
        if (in_class) {
            if (c == ']') in_class = false;
            continue;
        }
        switch (c) {
            '[' => in_class = true,
            '(' => depth += 1,
            ')' => {
                if (depth > 0) depth -= 1;
            },
            '|' => {
                if (depth == 0) return true;
            },
            else => {},
        }
    }
    return false;
}

fn patternMightMatch(regex_source: []const u8, cmd: []const u8) bool {
    const lit = requiredPrefixLiteral(regex_source) orelse return true;
    if (lit.len < 2) return true;
    var prefix_at: usize = 0;
    if (prefix_at < regex_source.len and regex_source[prefix_at] == '^') prefix_at += 1;
    if (hasDepth0AlternationAfter(regex_source, prefix_at + lit.len)) return true;
    return std.ascii.indexOfIgnoreCase(cmd, lit) != null;
}

/// Safe-list only. Patterns that only authorize `/tmp` or `$TMPDIR` cannot
/// match a command that never mentions those tokens. Skipping them is
/// fail-closed: a false skip can only deny, never allow.
fn safePatternMightMatch(regex_source: []const u8, cmd: []const u8) bool {
    if (!patternMightMatch(regex_source, cmd)) return false;
    const mentions_tmp = std.ascii.indexOfIgnoreCase(regex_source, "/tmp") != null or
        std.mem.indexOf(u8, regex_source, "TMPDIR") != null;
    if (!mentions_tmp) return true;
    return std.ascii.indexOfIgnoreCase(cmd, "tmp") != null or
        std.mem.indexOf(u8, cmd, "TMPDIR") != null;
}

fn initOnce(load_all: bool) !void {
    // Process-lifetime arena (not testing allocator — avoids leak noise).
    g_arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    errdefer reclaimRegistry();

    const a = g_arena.allocator();

    // Inflate into the process arena so pattern strings can borrow the JSON.
    // Inflate failure is RegistryInitFailed (deny), never an empty allow.
    const packs_json = oracle_embed.inflateAllocForInit(a, load_all) catch return error.RegistryInitFailed;

    var packs_list: std.ArrayList(CompiledPack) = .empty;
    errdefer {
        // C-heap regexes are not owned by the arena — free before arena teardown.
        freePackList(packs_list.items);
        packs_list.deinit(a);
    }

    // Scan pack objects instead of parsing the full inflated oracle. Hook
    // processes only need core.* + system.disk. Strings stay borrowed from the
    // arena-owned inflated JSON.
    var pos = skipJsonWs(packs_json, 0);
    if (pos >= packs_json.len or packs_json[pos] != '[') return error.BadPacksJson;
    pos += 1;
    while (true) {
        pos = skipJsonWs(packs_json, pos);
        if (pos >= packs_json.len) return error.BadPacksJson;
        switch (packs_json[pos]) {
            ']' => break,
            ',' => {
                pos += 1;
                continue;
            },
            '{' => {},
            else => return error.BadPacksJson,
        }
        const end = matchingObjectEnd(packs_json, pos) orelse return error.BadPacksJson;
        const obj = packs_json[pos..end];
        pos = end;

        if (packIdFromObject(obj)) |id| {
            if (std.mem.eql(u8, id, "test.deadline")) continue;
            if (!load_all and !isDefaultEnabled(id)) continue;
        }

        const parsed = std.json.parseFromSlice(PackJson, a, obj, .{
            .ignore_unknown_fields = true,
        }) catch return error.BadPacksJson;
        if (packIdFromObject(obj) == null) {
            if (std.mem.eql(u8, parsed.value.id, "test.deadline")) continue;
            if (!load_all and !isDefaultEnabled(parsed.value.id)) continue;
        }

        const pack = try compilePack(a, parsed.value);
        packs_list.append(a, pack) catch |err| {
            freePatternList(pack.safe);
            freePatternList(pack.destructive);
            return err;
        };
    }

    g_packs = try packs_list.toOwnedSlice(a);
    // Phase 1 hard fence: tier+lex order (not JSON alpha) for first-match attribution.
    // Do not rewrite oracle_packs.json — sort code-side after load.
    std.mem.sort(CompiledPack, g_packs, {}, packOrderLessThan);
    g_full = load_all;
}

fn compilePack(a: std.mem.Allocator, item: PackJson) !CompiledPack {
    const keywords = try a.dupe([]const u8, item.keywords);
    const safe = try parsePatternList(a, item.safe);
    errdefer freePatternList(safe);
    const destructive = try parsePatternList(a, item.destructive);
    errdefer freePatternList(destructive);

    return .{
        .id = item.id,
        .keywords = keywords,
        .safe = safe,
        .destructive = destructive,
        .default_enabled = isDefaultEnabled(item.id),
    };
}

/// Rust default: always enable category `core` (all `core.*`) and `system.disk`.
fn isDefaultEnabled(id: []const u8) bool {
    if (std.mem.startsWith(u8, id, "core.")) return true;
    if (std.mem.eql(u8, id, "system.disk")) return true;
    return false;
}

/// Category → tier (lower = higher priority). Mirrors Rust
/// `PackRegistry::pack_tier` so first-match attribution matches
/// expand_enabled_ordered. Single source for packTier + unit test.
const pack_category_tiers = [_]struct { category: []const u8, tier: u8 }{
    .{ .category = "safe", .tier = 0 },
    .{ .category = "core", .tier = 1 },
    .{ .category = "storage", .tier = 1 },
    .{ .category = "remote", .tier = 1 },
    .{ .category = "system", .tier = 2 },
    .{ .category = "infrastructure", .tier = 3 },
    .{ .category = "apigateway", .tier = 4 },
    .{ .category = "cdn", .tier = 4 },
    .{ .category = "cloud", .tier = 4 },
    .{ .category = "dns", .tier = 4 },
    .{ .category = "loadbalancer", .tier = 4 },
    .{ .category = "platform", .tier = 4 },
    .{ .category = "kubernetes", .tier = 5 },
    .{ .category = "containers", .tier = 6 },
    .{ .category = "backup", .tier = 7 },
    .{ .category = "database", .tier = 7 },
    .{ .category = "messaging", .tier = 7 },
    .{ .category = "search", .tier = 7 },
    .{ .category = "package_managers", .tier = 8 },
    .{ .category = "strict_git", .tier = 9 },
    .{ .category = "cicd", .tier = 10 },
    .{ .category = "email", .tier = 10 },
    .{ .category = "featureflags", .tier = 10 },
    .{ .category = "secrets", .tier = 10 },
    .{ .category = "monitoring", .tier = 10 },
    .{ .category = "payment", .tier = 10 },
};
const pack_tier_unknown: u8 = 11;

/// Priority tier for a pack ID (lower = higher priority). Phase 1 hard fence
/// relies on this tier+lex registry order for stable rule_id attribution.
fn packTier(pack_id: []const u8) u8 {
    const category = if (std.mem.indexOfScalar(u8, pack_id, '.')) |dot|
        pack_id[0..dot]
    else
        pack_id;
    for (pack_category_tiers) |entry| {
        if (std.mem.eql(u8, category, entry.category)) return entry.tier;
    }
    return pack_tier_unknown;
}

fn packOrderLessThan(_: void, a: CompiledPack, b: CompiledPack) bool {
    const ta = packTier(a.id);
    const tb = packTier(b.id);
    if (ta != tb) return ta < tb;
    return std.mem.order(u8, a.id, b.id) == .lt;
}

fn finishInit(load_all: bool) !void {
    initOnce(load_all) catch {
        // initOnce errdefer already reclaimed C heap + arena.
        g_state.store(0, .release);
        return error.RegistryInitFailed;
    };
    if (g_packs.len == 0) {
        reclaimRegistry();
        g_state.store(0, .release);
        return error.RegistryInitFailed;
    }
    g_state.store(1, .release);
}

fn ensureInitWith(load_all: bool) !void {
    // State machine: 0 uninit/retryable, 1 ok, 2 legacy sticky-fail (treated as retryable), 3 in-progress.
    while (true) {
        const state = g_state.load(.acquire);
        if (state == 1) {
            if (!load_all or g_full) return;
            // Upgrade default-only → full oracle (extra packs / tests).
            // Do not reclaim the live registry: in-flight matchers may still
            // hold `g_packs`. Build a replacement, then leak the previous
            // arena (process-lifetime; upgrade happens at most once).
            if (g_state.cmpxchgStrong(1, 3, .acq_rel, .acquire)) |_| continue;
            const previous_arena = g_arena;
            const previous_packs = g_packs;
            g_arena = undefined;
            g_packs = &.{};
            g_full = false;
            finishInit(true) catch {
                g_arena = previous_arena;
                g_packs = previous_packs;
                g_full = false;
                g_state.store(1, .release);
                return error.RegistryInitFailed;
            };
            // Success: previous_arena is intentionally leaked so in-flight
            // matchers can finish against previous_packs. Upgrade is once.
            return;
        }
        if (state == 3) {
            while (g_state.load(.acquire) == 3) {
                std.Thread.yield() catch {
                    std.atomic.spinLoopHint();
                };
            }
            continue;
        }
        // 0 or 2: attempt to become the initializer.
        if (g_state.cmpxchgStrong(state, 3, .acq_rel, .acquire)) |_| {
            continue;
        }
        break;
    }

    return finishInit(load_all);
}

/// Default product packs only (`core.*` + `system.disk`). Hook hot path.
pub fn ensureInitDefault() !void {
    return ensureInitWith(false);
}

/// Full embedded oracle (opt-in packs, corpus tests, `default_packs_only=false`).
pub fn ensureFullInit() !void {
    return ensureInitWith(true);
}

/// Tests load the full oracle so existing pack-count assertions stay valid.
/// Production hook processes load the default set only.
pub fn ensureInit() !void {
    if (builtin.is_test) return ensureFullInit();
    return ensureInitDefault();
}

pub fn ensureForMatchOptions(opts: MatchOptions) !void {
    if (!opts.default_packs_only or opts.extra_enabled.len > 0) return ensureFullInit();
    return ensureInitDefault();
}

pub fn packCount() usize {
    return g_packs.len;
}

fn mightMatch(pack: CompiledPack, cmd: []const u8) bool {
    if (pack.keywords.len == 0) return true;
    for (pack.keywords) |kw| {
        // Windows executables are case-insensitive (Git.EXE / RM.EXE).
        if (std.ascii.indexOfIgnoreCase(cmd, kw) != null) return true;
    }
    return false;
}

pub const MatchResult = union(enum) {
    allow_safe,
    allow_miss,
    deny: Hit,
};

pub const MatchOptions = struct {
    /// When true (default), only packs enabled under Rust `Config::default()`,
    /// plus any IDs listed in `extra_enabled`. Set false to evaluate the full
    /// 85-pack set (still honoring `disabled`).
    default_packs_only: bool = true,
    /// Opt-in pack IDs to evaluate in addition to the default set.
    extra_enabled: []const []const u8 = &.{},
    /// Pack IDs to force-disable (takes precedence over default/extra).
    disabled: []const []const u8 = &.{},
    /// Permanent allowlist kind=rule ids (`{pack_id}:{pattern_name}`). Destructive
    /// hits whose full rule id is listed are skipped and matching continues (E8:
    /// skip-this-rule only — never a pre-pack full allow for other packs/patterns).
    skipped_rule_ids: []const []const u8 = &.{},
};

/// Fail-closed hit when PCRE match infrastructure fails (OOM, null code, other errors).
/// Static strings — safe for matchDeny → evaluate dupe path without allocation here.
const match_infra_hit: Hit = .{
    .pack_id = "zig.shell",
    .pattern_name = "pcre-match-error",
    .severity = .critical,
    .reason = "Pack regex match infrastructure failed (fail-closed).",
};

fn matchInfraDeny() MatchResult {
    return .{ .deny = match_infra_hit };
}

/// Match packs on a single (already normalized/sanitized) command.
///
/// Per-pack safe/destructive ordering: a safe match suppresses destructive
/// patterns from the **same pack only**. Cross-pack destructives still deny
/// (e.g. `rm -rf / $(git checkout -b x)` is not allowed by `core.git` safe).
/// Match infrastructure errors return `.deny` (fail closed), not `.allow_miss`.
pub fn matchCommandDetailed(cmd: []const u8) MatchResult {
    return matchCommandDetailedOpts(cmd, .{});
}

fn packIdListed(pack_id: []const u8, ids: []const []const u8) bool {
    for (ids) |id| {
        if (std.mem.eql(u8, pack_id, id)) return true;
        // Category shorthand: `core` → `core.*`, `containers` → `containers.*`.
        // Any config token without a '.' is treated as a category prefix.
        if (std.mem.indexOfScalar(u8, id, '.') == null and id.len > 0) {
            if (pack_id.len > id.len and pack_id[id.len] == '.' and std.mem.startsWith(u8, pack_id, id)) {
                return true;
            }
        }
    }
    return false;
}

fn packIsActive(pack: CompiledPack, opts: MatchOptions) bool {
    if (packIdListed(pack.id, opts.disabled)) return false;
    if (!opts.default_packs_only) return true;
    if (pack.default_enabled) return true;
    return packIdListed(pack.id, opts.extra_enabled);
}

/// True when `{pack_id}:{pattern_name}` is present in `skipped_rule_ids` (exact).
fn ruleIdIsSkipped(pack_id: []const u8, pattern_name: []const u8, skipped: []const []const u8) bool {
    for (skipped) |rule_id| {
        const colon = std.mem.indexOfScalar(u8, rule_id, ':') orelse continue;
        const pack = rule_id[0..colon];
        const pattern = rule_id[colon + 1 ..];
        if (std.mem.eql(u8, pack, pack_id) and std.mem.eql(u8, pattern, pattern_name)) return true;
    }
    return false;
}

fn ensurePatternCompiled(pat: *CompiledPattern) !void {
    if (pat.regex != null) return;
    // Hook evaluation is single-threaded per process. First match compiles.
    pat.regex = regex_pcre.Regex.compile(pat.regex_source) catch return error.PatternCompileFailed;
}

pub fn matchCommandDetailedOpts(cmd: []const u8, opts: MatchOptions) MatchResult {
    return matchCommandDetailedOptsWithGates(cmd, opts, true);
}

fn matchCommandDetailedOptsWithGates(cmd: []const u8, opts: MatchOptions, use_prefix_gates: bool) MatchResult {
    ensureForMatchOptions(opts) catch return matchInfraDeny();
    if (g_packs.len == 0) return matchInfraDeny();

    var any_safe = false;
    for (g_packs) |*pack| {
        if (!packIsActive(pack.*, opts)) continue;
        if (!mightMatch(pack.*, cmd)) continue;

        var pack_safe = false;
        for (pack.safe) |*pat| {
            if (use_prefix_gates and !safePatternMightMatch(pat.regex_source, cmd)) continue;
            ensurePatternCompiled(pat) catch return matchInfraDeny();
            const matched = pat.regex.?.isMatch(cmd) catch return matchInfraDeny();
            if (matched) {
                pack_safe = true;
                any_safe = true;
                break;
            }
        }
        // Same-pack only: skip this pack's destructives, keep scanning others.
        if (pack_safe) continue;

        for (pack.destructive) |*pat| {
            if (use_prefix_gates and !patternMightMatch(pat.regex_source, cmd)) continue;
            ensurePatternCompiled(pat) catch return matchInfraDeny();
            const span = pat.regex.?.findMatch(cmd) catch return matchInfraDeny();
            if (span) |m| {
                // E8: permanent kind=rule skips this rule only; keep scanning.
                // Product permanent path filters critical rule ids out of skip lists
                // (evaluateCommand collectPermanentRuleSkipIds) — this matcher still
                // honors skipped_rule_ids as given for unit tests / callers.
                if (ruleIdIsSkipped(pack.id, pat.name, opts.skipped_rule_ids)) continue;
                return .{ .deny = .{
                    .pack_id = pack.id,
                    .pattern_name = pat.name,
                    .severity = pat.severity,
                    .reason = if (pat.reason.len > 0)
                        pat.reason
                    else
                        "Destructive command blocked by ryk pack.",
                    .regex_source = pat.regex_source,
                    .match_start = m.start,
                    .match_end = m.end,
                } };
            }
        }
    }
    if (any_safe) return .allow_safe;
    return .allow_miss;
}

pub fn defaultEnabledPackCount() usize {
    var n: usize = 0;
    for (g_packs) |p| {
        if (p.default_enabled) n += 1;
    }
    return n;
}

/// Look up severity for a permanent rule id `{pack_id}:{pattern_name}`.
/// Unknown / unloadable rules are treated as critical (fail closed for skip).
pub fn severityForRuleId(rule_id: []const u8) Severity {
    const colon = std.mem.indexOfScalar(u8, rule_id, ':') orelse return .critical;
    const pack_id = rule_id[0..colon];
    const pattern = rule_id[colon + 1 ..];
    if (pack_id.len == 0 or pattern.len == 0) return .critical;
    for (g_packs) |pack| {
        if (!std.mem.eql(u8, pack.id, pack_id)) continue;
        for (pack.destructive) |pat| {
            if (std.mem.eql(u8, pat.name, pattern)) return pat.severity;
        }
        return .critical; // pack known, pattern unknown → fail closed
    }
    return .critical;
}

/// Embedded oracle pattern totals (must match extract from historical frozen oracle packs).
pub const expected_destructive_patterns: usize = 793;
pub const expected_safe_patterns: usize = 830;

fn parseOnePattern(pat: PatternJson) CompiledPattern {
    const severity: Severity = if (std.mem.eql(u8, pat.severity, "critical"))
        .critical
    else if (std.mem.eql(u8, pat.severity, "medium"))
        .medium
    else if (std.mem.eql(u8, pat.severity, "low"))
        .low
    else
        .high;

    return .{
        .name = pat.name,
        .reason = pat.reason,
        .severity = severity,
        .regex_source = pat.regex,
        .regex = null,
    };
}

fn parsePatternList(a: std.mem.Allocator, pats: []PatternJson) ![]CompiledPattern {
    const list = try a.alloc(CompiledPattern, pats.len);
    for (pats, list) |pat, *out| {
        out.* = parseOnePattern(pat);
    }
    return list;
}

/// Count compiled patterns across all loaded packs (post-init).
pub fn compiledPatternCounts() struct { destructive: usize, safe: usize } {
    var d: usize = 0;
    var s: usize = 0;
    for (g_packs) |p| {
        d += p.destructive.len;
        s += p.safe.len;
    }
    return .{ .destructive = d, .safe = s };
}

test "registry loads packs and matches git reset" {
    try ensureInit();
    try std.testing.expect(packCount() >= 85);
    const r = matchCommandDetailed("git reset --hard");
    try std.testing.expect(r == .deny);
    try std.testing.expectEqualStrings("core.git", r.deny.pack_id);
}

test "default pack keywords are non-empty semantic tokens (no garbage)" {
    try ensureInit();
    for (g_packs) |pack| {
        if (!pack.default_enabled) continue;
        for (pack.keywords) |kw| {
            try std.testing.expect(kw.len > 0);
            // Reject comma/whitespace/newline garbage that never aids mightMatch.
            try std.testing.expect(std.mem.indexOfScalar(u8, kw, '\n') == null);
            try std.testing.expect(!std.mem.eql(u8, std.mem.trim(u8, kw, " \t"), ","));
            try std.testing.expect(!std.mem.eql(u8, kw, ", "));
            var has_semantic = false;
            for (kw) |c| {
                if (std.ascii.isAlphanumeric(c) or c == '/' or c == '>' or c == '~' or c == '$' or c == '\\' or c == '-' or c == '_' or c == '.') {
                    has_semantic = true;
                    break;
                }
            }
            try std.testing.expect(has_semantic);
        }
    }
    // system.disk must keyword-gate lvconvert so bare lvconvert --merge matches.
    var found_lv = false;
    for (g_packs) |pack| {
        if (!std.mem.eql(u8, pack.id, "system.disk")) continue;
        for (pack.keywords) |kw| {
            if (std.mem.eql(u8, kw, "lvconvert")) found_lv = true;
        }
    }
    try std.testing.expect(found_lv);
}

// Phase 1 hard fence: g_packs must follow Rust expand_enabled_ordered (pack_tier then lex)
// so first-match attribution is stable — not JSON alphabetical (apigateway-first).
test "default-enabled packs are ordered tier then lex not apigateway-first" {
    try ensureInit();
    try std.testing.expect(g_packs.len >= 3);
    // Full registry order: tier-1 core.* first (lex), never apigateway (tier 4) first.
    // core.credentials sorts before core.filesystem (tier+lex).
    try std.testing.expectEqualStrings("core.credentials", g_packs[0].id);
    try std.testing.expect(!std.mem.startsWith(u8, g_packs[0].id, "apigateway."));

    var enabled_ids: [16][]const u8 = undefined;
    var n: usize = 0;
    for (g_packs) |p| {
        if (!p.default_enabled) continue;
        if (n >= enabled_ids.len) break;
        enabled_ids[n] = p.id;
        n += 1;
    }
    try std.testing.expect(n >= 2);
    // First default-enabled is core.credentials; every entry is core.* or system.disk;
    // system.disk present and after all core.* (tier order). No fixed core cardinality.
    try std.testing.expectEqualStrings("core.credentials", enabled_ids[0]);
    var saw_system_disk = false;
    for (enabled_ids[0..n]) |id| {
        if (std.mem.eql(u8, id, "system.disk")) {
            saw_system_disk = true;
        } else {
            try std.testing.expect(std.mem.startsWith(u8, id, "core."));
            try std.testing.expect(!saw_system_disk);
        }
    }
    try std.testing.expect(saw_system_disk);

    // Full g_packs is non-decreasing by (tier, pack_id).
    var i: usize = 1;
    while (i < g_packs.len) : (i += 1) {
        const prev = g_packs[i - 1];
        const cur = g_packs[i];
        const tp = packTier(prev.id);
        const tc = packTier(cur.id);
        try std.testing.expect(tp <= tc);
        if (tp == tc) {
            try std.testing.expect(std.mem.order(u8, prev.id, cur.id) != .gt);
        }
    }
}

test "packTier mirrors Rust category table" {
    // Driven from pack_category_tiers — single source with packTier().
    for (pack_category_tiers) |entry| {
        var buf: [64]u8 = undefined;
        const sample = try std.fmt.bufPrint(&buf, "{s}.sample", .{entry.category});
        try std.testing.expectEqual(entry.tier, packTier(sample));
        // Category alone (no pack suffix) uses the same tier.
        try std.testing.expectEqual(entry.tier, packTier(entry.category));
    }
    try std.testing.expectEqual(pack_tier_unknown, packTier("unknown.category"));
    // Spot-check concrete pack ids used by Mode A / oracle.
    try std.testing.expectEqual(@as(u8, 1), packTier("core.filesystem"));
    try std.testing.expectEqual(@as(u8, 1), packTier("core.git"));
    try std.testing.expectEqual(@as(u8, 2), packTier("system.disk"));
}

test "registry compiled pattern counts match embedded oracle totals" {
    try ensureInit();
    const counts = compiledPatternCounts();
    try std.testing.expectEqual(@as(usize, expected_destructive_patterns), counts.destructive);
    try std.testing.expectEqual(@as(usize, expected_safe_patterns), counts.safe);
}

test "safe match is pack-scoped so cross-pack destructive still denies" {
    try ensureInit();
    // core.git safe (checkout -b) must not suppress core.filesystem root wipe.
    const r = matchCommandDetailed("rm -rf / $(git checkout -b x)");
    try std.testing.expect(r == .deny);
    try std.testing.expectEqualStrings("core.filesystem", r.deny.pack_id);
}

test "opt-in pack via extra_enabled denies docker system prune" {
    try ensureInit();
    const baseline = matchCommandDetailedOpts("docker system prune", .{});
    try std.testing.expect(baseline != .deny);

    const with_docker = matchCommandDetailedOpts("docker system prune", .{
        .extra_enabled = &.{"containers.docker"},
    });
    try std.testing.expect(with_docker == .deny);
    try std.testing.expectEqualStrings("containers.docker", with_docker.deny.pack_id);
}

test "opt-in pack category containers expands to containers.*" {
    try ensureInit();
    const with_cat = matchCommandDetailedOpts("docker system prune", .{
        .extra_enabled = &.{"containers"},
    });
    try std.testing.expect(with_cat == .deny);
    try std.testing.expectEqualStrings("containers.docker", with_cat.deny.pack_id);
}

test "disabled pack suppresses default-enabled destructive match" {
    try ensureInit();
    const disabled = matchCommandDetailedOpts("mkfs.ext4 /dev/sda1", .{
        .disabled = &.{"system.disk"},
    });
    try std.testing.expect(disabled != .deny);
}

test "lazy compile still denies git reset and allows a keyword miss" {
    try ensureInit();
    const deny = matchCommandDetailed("git reset --hard");
    try std.testing.expect(deny == .deny);
    try std.testing.expectEqualStrings("core.git", deny.deny.pack_id);

    const miss = matchCommandDetailed("echo hook-latency-keyword-miss");
    try std.testing.expect(miss != .deny);
}

test "empty inflated packs array scans to zero packs" {
    // gzip -n of "[]". Inflate succeeds (array prefix) but the same scanner
    // initOnce uses finds zero objects — the g_packs.len == 0 condition
    // finishInit maps to RegistryInitFailed.
    const empty_arr_gz = [_]u8{
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8b, 0x8e,
        0x05, 0x00, 0x29, 0xbb, 0x4c, 0x0d, 0x02, 0x00, 0x00, 0x00,
    };
    const json = try oracle_embed.inflateSlice(std.testing.allocator, &empty_arr_gz);
    defer std.testing.allocator.free(json);
    try std.testing.expectEqualStrings("[]", json);

    var n: usize = 0;
    var pos = skipJsonWs(json, 0);
    try std.testing.expect(json[pos] == '[');
    pos += 1;
    while (true) {
        pos = skipJsonWs(json, pos);
        if (json[pos] == ']') break;
        if (json[pos] == ',') {
            pos += 1;
            continue;
        }
        const end = matchingObjectEnd(json, pos) orelse return error.TestUnexpectedResult;
        n += 1;
        pos = end;
    }
    try std.testing.expectEqual(@as(usize, 0), n);
}

test "oracle json scanner finds four default packs" {
    const packs_json = try oracle_embed.inflateAlloc(std.testing.allocator);
    defer std.testing.allocator.free(packs_json);
    var n: usize = 0;
    var pos = skipJsonWs(packs_json, 0);
    try std.testing.expect(packs_json[pos] == '[');
    pos += 1;
    while (true) {
        pos = skipJsonWs(packs_json, pos);
        if (packs_json[pos] == ']') break;
        if (packs_json[pos] == ',') {
            pos += 1;
            continue;
        }
        const end = matchingObjectEnd(packs_json, pos) orelse return error.TestUnexpectedResult;
        const id = packIdFromObject(packs_json[pos..end]) orelse return error.TestUnexpectedResult;
        if (isDefaultEnabled(id)) n += 1;
        pos = end;
    }
    try std.testing.expectEqual(@as(usize, 4), n);
}

test "required prefix literal skips impossible regex compiles" {
    try std.testing.expectEqualStrings("rm", requiredPrefixLiteral("^rm\\s+-rf").?);
    try std.testing.expectEqualStrings("find", requiredPrefixLiteral("^find\\s+/tmp").?);
    try std.testing.expect(requiredPrefixLiteral("\\bcp\\b") == null);
    try std.testing.expect(requiredPrefixLiteral("(?i)rm") == null);
    try std.testing.expect(!patternMightMatch("^find\\s+", "rm -rf /"));
    try std.testing.expect(patternMightMatch("^rm\\s+", "rm -rf /"));
    try std.testing.expect(patternMightMatch("rm\\s+-[a-zA-Z]*[rR]", "rm -rf /"));
    try std.testing.expect(!safePatternMightMatch("^rm\\s+/tmp/", "rm -rf /"));
    try std.testing.expect(safePatternMightMatch("^rm\\s+/tmp/", "rm -rf /tmp/foo"));
}

test "depth-0 alternation after prefix still denies del" {
    // Skipping a destructive compile is an allow if nothing else hits.
    // `^rm|del` extracts prefix "rm"; without a depth-0 `|` guard the
    // heuristic would skip `del /s /q C:\` and fail open.
    const cmd = "del /s /q C:\\";
    try std.testing.expect(patternMightMatch("^rm|del", cmd));
    var re = try regex_pcre.Regex.compile("^rm|del");
    defer re.deinit();
    try std.testing.expect(try re.isMatch(cmd));
}

test "packIdFromObject requires compact id-first and ignores nested id" {
    try std.testing.expectEqualStrings("core.git", packIdFromObject("{\"id\":\"core.git\",\"keywords\":[]}").?);
    try std.testing.expect(packIdFromObject("{\"keywords\":[],\"meta\":{\"id\":\"nested\"},\"id\":\"core.git\"}") == null);
    try std.testing.expect(packIdFromObject("{\"name\":\"x\",\"id\":\"core.git\"}") == null);
}

test "match infrastructure error hit is deny not allow_miss" {
    // Contract: matchInfraDeny is what matchCommandDetailedOpts returns on isMatch error
    // and when the registry is empty after a failed/abandoned init.
    const r = matchInfraDeny();
    try std.testing.expect(r == .deny);
    try std.testing.expectEqualStrings("pcre-match-error", r.deny.pattern_name);
    try std.testing.expect(r.deny.severity == .critical);
}

fn expectMatchEqual(lazy: MatchResult, eager: MatchResult) !void {
    try std.testing.expectEqual(std.meta.activeTag(lazy), std.meta.activeTag(eager));
    if (lazy == .deny) {
        try std.testing.expectEqualStrings(eager.deny.pack_id, lazy.deny.pack_id);
        try std.testing.expectEqualStrings(eager.deny.pattern_name, lazy.deny.pattern_name);
    }
}

const prefix_gate_oracle_commands = [_][]const u8{
    "git status",
    "git push",
    "git push origin main",
    "git push --force",
    "git push --force-with-lease origin main",
    "git reset --hard",
    "rm -rf /",
    "rm -rf /tmp/foo",
    "echo hello",
    "ls",
    "pwd",
    "mkfs.ext4 /dev/sda1",
    "docker system prune",
    "find /tmp -delete",
    "chmod 777 /etc/passwd",
};

test "lazy prefix skip equals eager compile on default packs" {
    try ensureInitDefault();
    const opts = MatchOptions{};
    for (prefix_gate_oracle_commands) |cmd| {
        const lazy = matchCommandDetailedOptsWithGates(cmd, opts, true);
        const eager = matchCommandDetailedOptsWithGates(cmd, opts, false);
        expectMatchEqual(lazy, eager) catch |err| {
            std.debug.print("default-pack lazy/eager mismatch for `{s}`\n", .{cmd});
            return err;
        };
    }
}

test "lazy prefix skip equals eager compile on full oracle" {
    try ensureFullInit();
    const opts = MatchOptions{ .default_packs_only = false };
    for (prefix_gate_oracle_commands) |cmd| {
        const lazy = matchCommandDetailedOptsWithGates(cmd, opts, true);
        const eager = matchCommandDetailedOptsWithGates(cmd, opts, false);
        expectMatchEqual(lazy, eager) catch |err| {
            std.debug.print("full-oracle lazy/eager mismatch for `{s}`\n", .{cmd});
            return err;
        };
    }

    const extra = MatchOptions{ .extra_enabled = &.{"containers.docker"} };
    const lazy_docker = matchCommandDetailedOptsWithGates("docker system prune", extra, true);
    const eager_docker = matchCommandDetailedOptsWithGates("docker system prune", extra, false);
    try expectMatchEqual(lazy_docker, eager_docker);
    try std.testing.expect(lazy_docker == .deny);
}

// ── s-engine: MatchOptions.skipped_rule_ids (E8 skip-this-rule only) ─────────
//
// Contract: MatchOptions gains `skipped_rule_ids: []const []const u8 = &.{}`.
// Destructive hits whose `{pack_id}:{pattern_name}` is listed are skipped and
// matching continues (other packs/patterns still deny). Not a full allow.

test "s-engine: MatchOptions skipped_rule_ids skips only core.git:reset-hard" {
    try ensureInit();

    // Baseline: reset --hard denies.
    const baseline = matchCommandDetailedOpts("git reset --hard HEAD", .{});
    try std.testing.expect(baseline == .deny);
    try std.testing.expectEqualStrings("core.git", baseline.deny.pack_id);
    try std.testing.expectEqualStrings("reset-hard", baseline.deny.pattern_name);

    // With skip list for that rule only → no deny from that rule (allow_safe or allow_miss).
    const skipped = matchCommandDetailedOpts("git reset --hard HEAD", .{
        .skipped_rule_ids = &.{"core.git:reset-hard"},
    });
    try std.testing.expect(skipped != .deny);

    // Sibling destructive in same pack still denies when not skipped.
    const force = matchCommandDetailedOpts("git push --force origin main", .{
        .skipped_rule_ids = &.{"core.git:reset-hard"},
    });
    try std.testing.expect(force == .deny);
    try std.testing.expectEqualStrings("core.git", force.deny.pack_id);
    try std.testing.expectEqualStrings("push-force-long", force.deny.pattern_name);
}

test "s-engine: MatchOptions skipped_rule_ids does not suppress other packs (E8)" {
    try ensureInit();

    // Compound / other-pack: skip git reset-hard, filesystem wipe still denies.
    const compound = matchCommandDetailedOpts("git reset --hard; rm -rf /", .{
        .skipped_rule_ids = &.{"core.git:reset-hard"},
    });
    try std.testing.expect(compound == .deny);
    try std.testing.expectEqualStrings("core.filesystem", compound.deny.pack_id);

    const wipe = matchCommandDetailedOpts("rm -rf /", .{
        .skipped_rule_ids = &.{"core.git:reset-hard"},
    });
    try std.testing.expect(wipe == .deny);
    try std.testing.expectEqualStrings("core.filesystem", wipe.deny.pack_id);
}

test "s-engine: MatchOptions skipped_rule_ids empty defaults to no skip" {
    try ensureInit();
    const opts = MatchOptions{};
    try std.testing.expectEqual(@as(usize, 0), opts.skipped_rule_ids.len);

    const r = matchCommandDetailedOpts("git reset --hard", opts);
    try std.testing.expect(r == .deny);
    try std.testing.expectEqualStrings("reset-hard", r.deny.pattern_name);
}

test "s-engine: MatchOptions can skip multiple rule ids" {
    try ensureInit();

    // Skip both reset-hard and a filesystem pattern → wipe still may match other patterns.
    // Skip only reset-hard + one filesystem root pattern: multi-skip on single command.
    const both = matchCommandDetailedOpts("git reset --hard HEAD", .{
        .skipped_rule_ids = &.{
            "core.git:reset-hard",
            "core.filesystem:rm-rf-root-home",
        },
    });
    try std.testing.expect(both != .deny);

    // Unrelated pack still denies under multi-skip list.
    const disk = matchCommandDetailedOpts("mkfs.ext4 /dev/sda1", .{
        .skipped_rule_ids = &.{
            "core.git:reset-hard",
            "core.filesystem:rm-rf-root-home",
        },
    });
    try std.testing.expect(disk == .deny);
    try std.testing.expectEqualStrings("system.disk", disk.deny.pack_id);
}

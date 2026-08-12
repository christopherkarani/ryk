//! In-process Zig shell command evaluator.
//!
//! Owns security decisions for `ryk hook` / `ryk run` / shims.
//! Pack patterns are the historical frozen oracle set from the former orca-rs packs (embedded JSON + PCRE2).
//! Evaluator errors fail closed with deny.
//!
//! Phase 1 hard fence (Mode A default packs: core.* + system.disk): structure
//! smart checks (segments, wrappers, assignment masking, embeds) plus reliable
//! filesystem/git/disk catastrophe denials. Not YOLO/Strict policy or FM.

const std = @import("std");

pub const types = @import("types.zig");
pub const allowlist = @import("allowlist.zig");
/// Permanent pack-exception store (distinct from policy Layered / Entry.prefix).
pub const allowlist_store = @import("allowlist_store.zig");
/// Allow-once pending + active JSONL stores (exact command + scope).
pub const allow_once = @import("allow_once.zig");
pub const registry = @import("registry.zig");
pub const segments = @import("segments.zig");
pub const normalize = @import("normalize.zig");
pub const sanitize = @import("sanitize.zig");
pub const suggestions = @import("suggestions.zig");
pub const trace = @import("trace.zig");

pub const Decision = types.Decision;
pub const Severity = types.Severity;
pub const TraceCollector = trace.TraceCollector;
pub const TraceStep = trace.TraceStep;
pub const TraceDetails = trace.TraceDetails;

pub const Evaluation = struct {
    decision: Decision,
    rule_id: ?[]const u8 = null,
    pack_id: ?[]const u8 = null,
    pattern_name: ?[]const u8 = null,
    severity: Severity = .high,
    reason: []const u8,
    explanation: ?[]const u8 = null,
    regex_source: ?[]const u8 = null,
    match_start: ?usize = null,
    match_end: ?usize = null,
    matched_text: ?[]const u8 = null,
    /// Candidate string the span applies to when it differs from the input command.
    matched_candidate: ?[]const u8 = null,
    /// Static tip lines (not freed).
    tips: []const []const u8 = &.{},
    /// Pipeline steps: each is `name (duration)` with nested `detail` child.
    /// Owned when `trace_owned` (explain path with collector).
    trace: []const TraceStep = &.{},
    latency_ms: u64 = 0,
    owned: bool = false,
    /// When true, `trace` slice and each owned `detail` were allocated.
    trace_owned: bool = false,
    /// Exception attribution (static strings; not freed).
    /// "allow_once" | "allowlist" when an exception path allowed the command.
    exception_source: ?[]const u8 = null,
    /// Permanent only: "user" | "project".
    exception_layer: ?[]const u8 = null,
    /// Permanent only: "command" | "rule".
    exception_kind: ?[]const u8 = null,

    pub fn deinit(self: *Evaluation, allocator: std.mem.Allocator) void {
        // Trace ownership is independent of metadata ownership so hooks can
        // attach an empty trace without free paths, and explain can free steps
        // even if other fields are static.
        if (self.trace_owned) {
            for (self.trace) |step| {
                if (step.detail) |d| allocator.free(d);
            }
            if (self.trace.len > 0) allocator.free(self.trace);
            self.trace = &.{};
            self.trace_owned = false;
        }
        if (!self.owned) return;
        if (self.rule_id) |s| allocator.free(s);
        if (self.pack_id) |s| allocator.free(s);
        if (self.pattern_name) |s| allocator.free(s);
        allocator.free(self.reason);
        if (self.explanation) |s| allocator.free(s);
        if (self.regex_source) |s| allocator.free(s);
        if (self.matched_text) |s| allocator.free(s);
        if (self.matched_candidate) |s| allocator.free(s);
        self.* = undefined;
    }
};

pub const EvaluateOptions = struct {
    cwd: ?[]const u8 = null,
    /// Legacy policy-style Layered short-circuit (engine unit tests / non-product).
    /// Product permanent pack exceptions use `permanent_allowlist` — not this field.
    allowlists: ?allowlist.Layered = null,
    /// Permanent pack-exception store (kind=command pre-pack FULL ALLOW; kind=rule E8 skip).
    /// Distinct from `allowlists` / policy Layered. Product loaders set this; not Layered.
    permanent_allowlist: ?allowlist_store.Store = null,
    /// Absolute path to allow_once.jsonl. Null disables allow-once matching.
    allow_once_path: ?[]const u8 = null,
    /// Runtime Io required with `allow_once_path` for store match/consume.
    io: ?std.Io = null,
    /// When true (default), consume single-use allow-once on hit (hook/run/shim/test).
    /// When false (explain), match + attribute only and leave the store intact.
    consume_allow_once: bool = true,
    /// Wall-clock ISO-8601 for permanent expiry + allow-once match. Required to apply
    /// exception paths that honor TTL; null skips permanent/allow-once allows (fail closed).
    now_iso: ?[]const u8 = null,
    /// When true (default), only core.* + system.disk (Rust Config::default),
    /// plus any IDs in `extra_enabled`. When false, evaluate the full registry
    /// (still honoring `disabled`).
    default_packs_only: bool = true,
    /// Opt-in pack IDs from cwd-scoped config (`[packs] enabled = [...]`).
    extra_enabled: []const []const u8 = &.{},
    /// Pack IDs from cwd-scoped config (`[packs] disabled = [...]`).
    disabled: []const []const u8 = &.{},
    /// Opt-in explain instrumentation. Null on hooks/run (zero cost).
    trace: ?*TraceCollector = null,
};

/// Evaluate a shell command line.
/// Empty command is a no-op allow (matches oracle). Registry init failure → deny.
/// When `options.trace` is non-null, records real timed pipeline steps for explain.
///
/// Order (plan §4.1): allow-once exact → permanent kind=command FULL ALLOW →
/// packs with permanent kind=rule as skip-this-rule only (E8).
/// Legacy `options.allowlists` Layered remains a separate pre-pack short-circuit
/// for engine unit tests — not the product permanent API.
pub fn evaluateCommand(allocator: std.mem.Allocator, command: []const u8, options: EvaluateOptions) !Evaluation {
    const started_ms = monotonicMs();
    if (options.trace) |t| t.beginStep();

    const trimmed = std.mem.trim(u8, command, " \t\r\n");
    if (trimmed.len == 0) {
        try endOuterStep(options.trace, .{ .message = "empty command no-op" });
        return try finalizeEval(allocator, options.trace, allowStatic("Empty command is a no-op."), elapsedMs(started_ms));
    }

    // ── 1. Allow-once (exact command + scope) before permanent / packs ──────
    if (try tryAllowOnce(allocator, trimmed, options, started_ms)) |eval| {
        return eval;
    }

    // ── 2. Permanent allowlist kind=command → FULL ALLOW pre-pack ───────────
    if (try tryPermanentCommand(allocator, trimmed, options, started_ms)) |eval| {
        return eval;
    }

    // Legacy Layered short-circuit (policy-style; not permanent pack exceptions).
    if (options.allowlists) |lists| {
        if (lists.allows(trimmed)) {
            try endOuterStep(options.trace, .{ .allowlist = .{ .matched = true } });
            return try finalizeEval(allocator, options.trace, allowStatic("Command allowed by allowlist."), elapsedMs(started_ms));
        }
    }

    registry.ensureInit() catch {
        try endOuterStep(options.trace, .{ .message = "registry init failure (fail-closed)" });
        return try finalizeEval(
            allocator,
            options.trace,
            denyStatic("zig.shell:init", "zig.shell", "init-failure", .critical, "Shell pack registry failed to initialize (fail-closed)."),
            elapsedMs(started_ms),
        );
    };

    // ── 3. Pack evaluation with kind=rule permanent ids as skip-this-rule ───
    var skip_ids: std.ArrayList([]const u8) = .empty;
    defer skip_ids.deinit(allocator);
    try collectPermanentRuleSkipIds(options, &skip_ids, allocator);

    const match_opts = registry.MatchOptions{
        .default_packs_only = options.default_packs_only,
        .extra_enabled = options.extra_enabled,
        .disabled = options.disabled,
        .skipped_rule_ids = skip_ids.items,
    };
    const match_opts_no_skip = registry.MatchOptions{
        .default_packs_only = options.default_packs_only,
        .extra_enabled = options.extra_enabled,
        .disabled = options.disabled,
        .skipped_rule_ids = &.{},
    };

    var candidates: std.ArrayList([]const u8) = .empty;
    defer candidates.deinit(allocator);

    // Non-executing heredocs (cat/tee/grep <<EOF …): mask bodies and do NOT
    // segment-split on newlines (body lines would otherwise be evaluated as
    // free-standing commands).
    const has_heredoc = std.mem.indexOf(u8, trimmed, "<<") != null;
    const is_herestring_only = std.mem.indexOf(u8, trimmed, "<<<") != null and
        std.mem.indexOf(u8, trimmed, "<<") == std.mem.indexOf(u8, trimmed, "<<<");
    var masked_storage: ?[]u8 = null;
    defer if (masked_storage) |m| allocator.free(m);
    // Embed buffers must outlive the candidate list (slices point into them).
    var embeds_owned: [][]const u8 = &.{};
    defer if (embeds_owned.len > 0) normalize.freeEmbeds(allocator, embeds_owned);

    // Non-executing heredocs: mask body only when a real terminator is found
    // (oracle `mask_non_executing_heredocs`). If the delimiter form cannot be
    // closed (e.g. `<<\EOF` vs terminator `EOF`), leave the body visible and
    // segment-split so free-standing destructive lines still deny (fail closed).
    if (has_heredoc and !is_herestring_only and !isExecutingContext(trimmed)) {
        masked_storage = try maskNonExecutingHeredoc(allocator, trimmed);
        const working = masked_storage.?;
        try candidates.append(allocator, working);
        try appendSegments(allocator, &candidates, working);
    } else {
        // Prefer per-segment evaluation so assignment values and safe prefixes
        // cannot poison a full-string regex match. Also keep the full command
        // for patterns that legitimately span segments (after sanitize).
        try appendSegments(allocator, &candidates, trimmed);
        if (candidates.items.len == 0) {
            // No separators — evaluate the whole line.
            try candidates.append(allocator, trimmed);
        } else if (candidates.items.len == 1) {
            // A lone segment can be a truncated view of the line (e.g. comment
            // handling dropped the tail). Evaluate the full original string as
            // well so a truncated candidate is never the only thing checked.
            if (!std.mem.eql(u8, candidates.items[0], trimmed)) {
                try candidates.append(allocator, trimmed);
            }
        } else {
            // Multi-segment: still include a sanitized full-string candidate for
            // spanning patterns, with assignment RHS masked.
            const masked_assign = try maskAssignmentValues(allocator, trimmed);
            if (masked_storage == null) {
                masked_storage = masked_assign;
                try candidates.append(allocator, masked_storage.?);
            } else {
                allocator.free(masked_assign);
            }
        }

        if (isExecutingContext(trimmed)) {
            embeds_owned = try normalize.extractEmbeds(allocator, trimmed);
            for (embeds_owned) |e| {
                try candidates.append(allocator, e);
                try appendSegments(allocator, &candidates, e);
            }
        }
    }

    // DCG collapses to one outer timed step; we record real pack outcome only.

    for (candidates.items) |cand| {
        if (try evalOne(allocator, cand, match_opts, .{})) |hit| {
            try endOuterStep(options.trace, .{
                .pack_evaluation = .{
                    .matched_pack = hit.pack_id,
                    .matched_pattern = hit.pattern_name,
                },
            });
            return try finalizeEval(
                allocator,
                options.trace,
                try denyFromHit(allocator, hit, cand, elapsedMs(started_ms)),
                elapsedMs(started_ms),
            );
        }
    }

    // Data-only | shell/interpreter: sanitize masks LHS payload, bare bash RHS has
    // no pack hit. Re-evaluate pipeline prefixes that feed an executor without
    // data-only sanitize so `echo 'rm -rf /' | bash` denies.
    var pipe_payloads: std.ArrayList([]const u8) = .empty;
    defer pipe_payloads.deinit(allocator);
    try appendPipelinePrefixesToExecutor(trimmed, allocator, &pipe_payloads);
    for (pipe_payloads.items) |cand| {
        if (try evalOne(allocator, cand, match_opts, .{ .skip_data_sanitize = true })) |hit| {
            try endOuterStep(options.trace, .{
                .pack_evaluation = .{
                    .matched_pack = hit.pack_id,
                    .matched_pattern = hit.pattern_name,
                },
            });
            return try finalizeEval(
                allocator,
                options.trace,
                try denyFromHit(allocator, hit, cand, elapsedMs(started_ms)),
                elapsedMs(started_ms),
            );
        }
    }

    // Pack path allowed under skip list. If a non-skipped match would have denied
    // with a permanent kind=rule entry, attribute allowlist rule-skip (E8).
    if (skip_ids.items.len > 0) {
        if (try firstDenyHit(allocator, candidates.items, pipe_payloads.items, match_opts_no_skip)) |hit| {
            if (try tryPermanentRuleAttribution(allocator, hit, options, started_ms)) |eval| {
                return eval;
            }
        }
    }

    try endOuterStep(options.trace, .{
        .pack_evaluation = .{
            .matched_pack = null,
            .matched_pattern = null,
            .packs_scanned = 0,
        },
    });
    var allow = allowStatic("No destructive pack matched.");
    allow.latency_ms = elapsedMs(started_ms);
    allow.tips = &.{};
    return try finalizeEval(allocator, options.trace, allow, elapsedMs(started_ms));
}

fn permanentLayerName(layer: allowlist_store.Layer) []const u8 {
    return switch (layer) {
        .user => "user",
        .project => "project",
    };
}

fn collectPermanentRuleSkipIds(
    options: EvaluateOptions,
    out: *std.ArrayList([]const u8),
    allocator: std.mem.Allocator,
) !void {
    const store = options.permanent_allowlist orelse return;
    const now = options.now_iso orelse return;
    // Need registry for severity lookup (critical hard fence).
    registry.ensureInit() catch {
        // Fail closed: no permanent rule skips when registry unavailable.
        return;
    };
    for (store.entries) |e| {
        if (e.kind != .rule) continue;
        if (allowlist_store.isExpired(e, now)) continue;
        const id = e.id orelse continue;
        // Permanent kind=rule cannot unlock critical pack hits.
        if (registry.severityForRuleId(id) == .critical) continue;
        try out.append(allocator, id);
    }
}

/// Plan §4.1 step 1: exact allow-once hit before permanent/packs.
///
/// Product law (operator break-glass): allow-once MAY FULL ALLOW a critical pack
/// hit after the operator redeems a deny-panel short code. Permanent kind=command
/// / kind=rule cannot unlock critical (see tryPermanentCommand /
/// collectPermanentRuleSkipIds). This is intentional dual-path policy, not an
/// oversight — document + test both; do not apply the permanent critical fence here.
///
/// Two-phase consume (M-15): peek without burning, build Evaluation, then consume
/// single_use only after the allow Evaluation is fully constructed. Prevents losing
/// the exception when post-match allocation fails.
fn tryAllowOnce(
    allocator: std.mem.Allocator,
    trimmed: []const u8,
    options: EvaluateOptions,
    started_ms: i64,
) !?Evaluation {
    const path = options.allow_once_path orelse return null;
    const io = options.io orelse return null;
    const now = options.now_iso orelse return null;
    const cwd = options.cwd orelse "";

    const storeFail = struct {
        fn deny(
            alloc: std.mem.Allocator,
            opts: EvaluateOptions,
            started: i64,
        ) !Evaluation {
            try endOuterStep(opts.trace, .{ .message = "allow_once store failure (fail-closed)" });
            return try finalizeEval(
                alloc,
                opts.trace,
                denyStatic(
                    "zig.shell:allow-once",
                    "zig.shell",
                    "allow-once-store-error",
                    .critical,
                    "Allow-once store failed (fail-closed).",
                ),
                elapsedMs(started),
            );
        }
    }.deny;

    // Phase 1: peek (consume=false) so eval construction cannot burn the grant first.
    const matched = allow_once.matchAllowOnce(
        io,
        allocator,
        path,
        trimmed,
        cwd,
        now,
        false,
    ) catch |err| {
        // Seatbelt residual: allow-once lives under XDG/HOME data, often unreadable
        // under "no bare home". Treat access denials as "no grant" (packs still run),
        // not as a critical deny of every shell command. Corrupt/IO other errors
        // still fail closed.
        if (isSandboxHomeStoreAccessError(err)) {
            try endOuterStep(options.trace, .{ .message = "allow_once store inaccessible (skipped)" });
            return null;
        }
        return try storeFail(allocator, options, started_ms);
    };
    const entry = matched orelse return null;
    defer allow_once.freeAllowOnceEntry(allocator, entry);

    // M-6: product path rejects multi-use allow-once (single_use=false). Those
    // entries act like permanent unlocks from an agent-writable store without
    // operator integrity binding. Treat as miss so packs still apply.
    // Residual: entries remain on disk until redeem/CLI validation rejects mint.
    if (!entry.single_use) {
        try endOuterStep(options.trace, .{ .message = "allow_once single_use=false ignored (product)" });
        return null;
    }

    const detail = try std.fmt.allocPrint(
        allocator,
        "allow_once matched source=allow_once reason={s}",
        .{entry.reason},
    );
    defer allocator.free(detail);
    try endOuterStep(options.trace, .{ .message = detail });

    var eval = try finalizeEval(
        allocator,
        options.trace,
        try allowExceptionOwned(
            allocator,
            entry.reason,
            "allow_once",
            null,
            null,
        ),
        elapsedMs(started_ms),
    );
    // No errdefer on eval: fail paths free manually then call storeFail (which may
    // error). errdefer + manual deinit would double-free if storeFail fails.

    // Phase 2: durable consume only after Evaluation is built.
    if (options.consume_allow_once) {
        const consumed = allow_once.matchAllowOnce(
            io,
            allocator,
            path,
            trimmed,
            cwd,
            now,
            true,
        ) catch {
            // Peek succeeded then consume failed (including rare access flip) — fail closed.
            eval.deinit(allocator);
            return try storeFail(allocator, options, started_ms);
        };
        if (consumed) |burned| {
            allow_once.freeAllowOnceEntry(allocator, burned);
        } else {
            // Entry vanished between peek and consume (concurrent use) — fail closed.
            eval.deinit(allocator);
            return try storeFail(allocator, options, started_ms);
        }
    }

    return eval;
}

/// Home/XDG store unreadable under hardened sandbox (no bare home). Not a corrupt store.
fn isSandboxHomeStoreAccessError(err: anyerror) bool {
    return err == error.AccessDenied or err == error.PermissionDenied;
}

/// Plan §4.1 step 2: permanent kind=command exact → FULL ALLOW pre-pack.
/// Critical hard fence: permanent kind=command cannot unlock a critical pack hit.
fn tryPermanentCommand(
    allocator: std.mem.Allocator,
    trimmed: []const u8,
    options: EvaluateOptions,
    started_ms: i64,
) !?Evaluation {
    const store = options.permanent_allowlist orelse return null;
    const now = options.now_iso orelse return null;
    const entry = store.matchCommand(trimmed, now) orelse return null;

    // Critical hard fence: multi-candidate critical scan (segments / embeds /
    // pipe-to-executor), same evalOne pipeline as evaluate, empty skip list.
    // Refuse FULL ALLOW when any candidate is critical. Does not recurse into
    // evaluateCommand (avoids error-set / exception-stack loops).
    if (try wouldDenyCritical(allocator, trimmed, options)) return null;

    const layer = permanentLayerName(entry.layer);
    const detail = try std.fmt.allocPrint(
        allocator,
        "allowlist source=allowlist layer={s} kind=command reason={s}",
        .{ layer, entry.reason },
    );
    defer allocator.free(detail);
    try endOuterStep(options.trace, .{ .message = detail });

    return try finalizeEval(
        allocator,
        options.trace,
        try allowExceptionOwned(
            allocator,
            entry.reason,
            "allowlist",
            layer,
            "command",
        ),
        elapsedMs(started_ms),
    );
}

/// After pack path allows under skip list: if a non-skipped match would deny on a
/// permanently allowlisted rule_id, attribute rule-skip allow (E8).
fn tryPermanentRuleAttribution(
    allocator: std.mem.Allocator,
    hit: registry.Hit,
    options: EvaluateOptions,
    started_ms: i64,
) !?Evaluation {
    const store = options.permanent_allowlist orelse return null;
    const now = options.now_iso orelse return null;

    var rule_buf: [256]u8 = undefined;
    const rule_id = std.fmt.bufPrint(&rule_buf, "{s}:{s}", .{ hit.pack_id, hit.pattern_name }) catch return null;
    const entry = store.matchRule(rule_id, now) orelse return null;

    const layer = permanentLayerName(entry.layer);
    const detail = try std.fmt.allocPrint(
        allocator,
        "allowlist source=allowlist layer={s} kind=rule reason={s}",
        .{ layer, entry.reason },
    );
    defer allocator.free(detail);
    try endOuterStep(options.trace, .{ .message = detail });

    return try finalizeEval(
        allocator,
        options.trace,
        try allowExceptionOwned(
            allocator,
            entry.reason,
            "allowlist",
            layer,
            "rule",
        ),
        elapsedMs(started_ms),
    );
}

fn firstDenyHit(
    allocator: std.mem.Allocator,
    candidates: []const []const u8,
    pipe_payloads: []const []const u8,
    match_opts: registry.MatchOptions,
) !?registry.Hit {
    for (candidates) |cand| {
        if (try evalOne(allocator, cand, match_opts, .{})) |hit| return hit;
    }
    for (pipe_payloads) |cand| {
        if (try evalOne(allocator, cand, match_opts, .{ .skip_data_sanitize = true })) |hit| return hit;
    }
    return null;
}

/// True when production evaluate would deny `cmd` at **critical** severity under
/// empty permanent skip. Used by the permanent kind=command hard fence.
///
/// Matches the multi-candidate surface of `evaluateCommand` (segments including
/// `$(…)` / backticks, full string, executing-context embeds, pipe-to-executor
/// prefixes) and returns true if **any** candidate's `evalOne` hit is critical —
/// not only the first full-string hit (medium-first compounds and safe-prefix
/// pack_safe poisoning must not unlock a later critical segment).
/// On registry init failure, fails closed (treat as critical — no permanent unlock).
fn wouldDenyCritical(
    allocator: std.mem.Allocator,
    cmd: []const u8,
    options: EvaluateOptions,
) !bool {
    registry.ensureInit() catch return true;
    const match_opts = registry.MatchOptions{
        .default_packs_only = options.default_packs_only,
        .extra_enabled = options.extra_enabled,
        .disabled = options.disabled,
        .skipped_rule_ids = &.{},
    };

    var candidates: std.ArrayList([]const u8) = .empty;
    defer candidates.deinit(allocator);
    // Full string first (normalize-only / lang-destruct on exact permanent text).
    try candidates.append(allocator, cmd);
    // Segments + substitution bodies (same as evaluateCommand pack path).
    try appendSegments(allocator, &candidates, cmd);

    var embeds_owned: [][]const u8 = &.{};
    defer if (embeds_owned.len > 0) normalize.freeEmbeds(allocator, embeds_owned);
    if (isExecutingContext(cmd)) {
        embeds_owned = try normalize.extractEmbeds(allocator, cmd);
        for (embeds_owned) |e| {
            try candidates.append(allocator, e);
            try appendSegments(allocator, &candidates, e);
        }
    }

    for (candidates.items) |cand| {
        if (try evalOne(allocator, cand, match_opts, .{})) |hit| {
            if (hit.severity == .critical) return true;
        }
    }

    var pipe_payloads: std.ArrayList([]const u8) = .empty;
    defer pipe_payloads.deinit(allocator);
    try appendPipelinePrefixesToExecutor(cmd, allocator, &pipe_payloads);
    for (pipe_payloads.items) |cand| {
        if (try evalOne(allocator, cand, match_opts, .{ .skip_data_sanitize = true })) |hit| {
            if (hit.severity == .critical) return true;
        }
    }
    return false;
}

fn allowExceptionOwned(
    allocator: std.mem.Allocator,
    reason_text: []const u8,
    source: []const u8,
    layer: ?[]const u8,
    kind: ?[]const u8,
) !Evaluation {
    const reason = try allocator.dupe(u8, reason_text);
    return .{
        .decision = .allow,
        .severity = .low,
        .reason = reason,
        .owned = true,
        .exception_source = source,
        .exception_layer = layer,
        .exception_kind = kind,
    };
}

fn endOuterStep(collector: ?*TraceCollector, details: TraceDetails) !void {
    if (collector) |t| try t.endStep("full_evaluation", details);
}

/// Attach collector steps to Evaluation when tracing; leave empty on null (hooks).
fn finalizeEval(
    allocator: std.mem.Allocator,
    collector: ?*TraceCollector,
    eval_in: Evaluation,
    latency_ms: u64,
) !Evaluation {
    var eval = eval_in;
    errdefer eval.deinit(allocator);
    eval.latency_ms = latency_ms;
    if (collector) |t| {
        // Steps already recorded via endOuterStep; take ownership into Evaluation.
        if (t.steps.items.len > 0) {
            const steps = try t.takeSteps();
            eval.trace = steps;
            eval.trace_owned = true;
        }
    }
    // Null collector → empty trace (zero cost; no fake peer steps).
    return eval;
}

fn monotonicMs() i64 {
    var threaded: std.Io.Threaded = .init_single_threaded;
    return std.Io.Timestamp.now(threaded.io(), .awake).toMilliseconds();
}

fn elapsedMs(started_ms: i64) u64 {
    const now = monotonicMs();
    if (now <= started_ms) return 0;
    return @intCast(now - started_ms);
}

fn denyFromHit(
    allocator: std.mem.Allocator,
    hit: registry.Hit,
    candidate: []const u8,
    latency_ms: u64,
) !Evaluation {
    // Match metadata only — pipeline steps come from TraceCollector (or empty).
    // Never invent peer steps named `matched`.
    const rule_id = try std.fmt.allocPrint(allocator, "{s}:{s}", .{ hit.pack_id, hit.pattern_name });
    errdefer allocator.free(rule_id);
    const pack_copy = try allocator.dupe(u8, hit.pack_id);
    errdefer allocator.free(pack_copy);
    const pattern_copy = try allocator.dupe(u8, hit.pattern_name);
    errdefer allocator.free(pattern_copy);
    const reason_copy = try allocator.dupe(u8, hit.reason);
    errdefer allocator.free(reason_copy);

    const explanation = try std.fmt.allocPrint(
        allocator,
        "Matched destructive pattern {s}:{s}.",
        .{ hit.pack_id, hit.pattern_name },
    );
    errdefer allocator.free(explanation);

    var regex_copy: ?[]const u8 = null;
    errdefer if (regex_copy) |s| allocator.free(s);
    if (hit.regex_source) |rx| regex_copy = try allocator.dupe(u8, rx);

    var matched_text: ?[]const u8 = null;
    errdefer if (matched_text) |s| allocator.free(s);
    var match_start = hit.match_start;
    var match_end = hit.match_end;
    if (match_start) |s| {
        if (match_end) |e| {
            if (e >= s and e <= candidate.len) {
                matched_text = try allocator.dupe(u8, candidate[s..e]);
            } else {
                match_start = null;
                match_end = null;
            }
        }
    }

    const cand_copy = try allocator.dupe(u8, candidate);
    errdefer allocator.free(cand_copy);

    return .{
        .decision = .deny,
        .rule_id = rule_id,
        .pack_id = pack_copy,
        .pattern_name = pattern_copy,
        .severity = hit.severity,
        .reason = reason_copy,
        .explanation = explanation,
        .regex_source = regex_copy,
        .match_start = match_start,
        .match_end = match_end,
        .matched_text = matched_text,
        .matched_candidate = cand_copy,
        .tips = suggestions.forPattern(hit.pack_id, hit.pattern_name),
        .trace = &.{},
        .latency_ms = latency_ms,
        .owned = true,
        .trace_owned = false,
    };
}

/// True when the outer command is an executing shell/interpreter (not cat/tee/grep data sinks).
fn isExecutingContext(cmd: []const u8) bool {
    const has_c_or_e = std.mem.indexOf(u8, cmd, " -c ") != null or
        std.mem.indexOf(u8, cmd, " -c'") != null or
        std.mem.indexOf(u8, cmd, " -c\"") != null or
        std.mem.indexOf(u8, cmd, "\t-c ") != null or
        std.mem.indexOf(u8, cmd, " -e ") != null or
        std.mem.indexOf(u8, cmd, " -e'") != null or
        std.mem.indexOf(u8, cmd, " -e\"") != null or
        // glued forms: python.exe -c"..." / -c'...'
        std.mem.indexOf(u8, cmd, " -c\"") != null or
        std.mem.indexOf(u8, cmd, "-c \"") != null or
        std.mem.indexOf(u8, cmd, "-c '") != null or
        std.mem.indexOf(u8, cmd, "-c\"") != null or
        std.mem.indexOf(u8, cmd, "-c'") != null or
        std.mem.indexOf(u8, cmd, "-e \"") != null or
        std.mem.indexOf(u8, cmd, "-e'") != null;

    if (has_c_or_e) {
        // First command word: accept python.exe / python3.11.exe / /usr/bin/python3
        if (firstArgv0LooksLikeExecutor(cmd)) return true;
        if (std.mem.indexOf(u8, cmd, "/bash") != null or std.mem.indexOf(u8, cmd, "/python") != null or
            std.mem.indexOf(u8, cmd, "/ruby") != null or std.mem.indexOf(u8, cmd, "/node") != null or
            std.mem.indexOf(u8, cmd, "/perl") != null)
            return true;
    }
    // Heredoc into shell/interpreter — including attached forms like `/bin/bash<<'EOF'`.
    if (std.mem.indexOf(u8, cmd, "<<") != null) {
        if (heredocReceiverIsExecuting(cmd)) return true;
        return false;
    }
    if (std.mem.indexOf(u8, cmd, "<<<") != null) {
        // here-string often on shell
        return true;
    }
    return false;
}

fn commandWordBasename(word: []const u8) []const u8 {
    if (std.mem.lastIndexOfScalar(u8, word, '/')) |idx| {
        if (idx + 1 < word.len) return word[idx + 1 ..];
    }
    return word;
}

fn isInterpreterBasename(base: []const u8) bool {
    const names = [_][]const u8{
        "bash", "sh",   "zsh",  "ksh", "dash", "fish",
        "ruby", "perl", "node",
    };
    for (names) |n| {
        if (std.mem.eql(u8, base, n)) return true;
    }
    // python / python3 / python3.14 (versioned suffixes)
    return interpreterBasenameLoose(base);
}

fn isDataSinkBasename(base: []const u8) bool {
    const sinks = [_][]const u8{
        "cat",  "tee",  "grep",   "egrep", "fgrep",  "sed",       "awk",  "wc",   "sort",
        "head", "tail", "base64", "md5",   "md5sum", "sha256sum", "curl", "less", "more",
    };
    for (sinks) |s| {
        if (std.mem.eql(u8, base, s)) return true;
    }
    return false;
}

/// True when a `<<` heredoc (not `<<<`) is received by a shell/interpreter path.
/// Handles whitespace, attached forms (`/bin/bash<<'EOF'`), and options before
/// the redirect (`bash -s <<'EOF'`) by resolving argv0 of the simple command.
fn heredocReceiverIsExecuting(cmd: []const u8) bool {
    var i: usize = 0;
    while (i + 1 < cmd.len) : (i += 1) {
        if (cmd[i] != '<' or cmd[i + 1] != '<') continue;
        // Skip here-string `<<<`.
        if (i + 2 < cmd.len and cmd[i + 2] == '<') {
            i += 2;
            continue;
        }
        const segment = simpleCommandPrefixBefore(cmd, i);
        if (segmentArgv0Kind(segment)) |kind| {
            return switch (kind) {
                .executing => true,
                .data_sink => false,
            };
        }
    }
    return false;
}

/// Slice of `cmd[0..redirect_at]` that is the current simple command (after the
/// last `|`, `;`, `&`, newline, or `&&` / `||`).
fn simpleCommandPrefixBefore(cmd: []const u8, redirect_at: usize) []const u8 {
    var seg_start: usize = 0;
    var k: usize = 0;
    while (k < redirect_at) : (k += 1) {
        const c = cmd[k];
        if (c == '\n' or c == ';' or c == '|') {
            if (c == '|' and k + 1 < redirect_at and cmd[k + 1] == '|') {
                seg_start = k + 2;
                k += 1;
                continue;
            }
            seg_start = k + 1;
            continue;
        }
        if (c == '&') {
            if (k + 1 < redirect_at and cmd[k + 1] == '&') {
                seg_start = k + 2;
                k += 1;
            } else {
                seg_start = k + 1;
            }
        }
    }
    while (seg_start < redirect_at and std.ascii.isWhitespace(cmd[seg_start])) : (seg_start += 1) {}
    return cmd[seg_start..redirect_at];
}

const ReceiverKind = enum { executing, data_sink };

/// Resolve argv0 of a simple-command prefix (options and env assigns stripped).
fn segmentArgv0Kind(segment: []const u8) ?ReceiverKind {
    var i: usize = 0;
    while (i < segment.len) {
        while (i < segment.len and std.ascii.isWhitespace(segment[i])) : (i += 1) {}
        if (i >= segment.len) break;

        // Skip env assignments NAME=value (unquoted simple form).
        var j = i;
        while (j < segment.len and (std.ascii.isAlphanumeric(segment[j]) or segment[j] == '_')) : (j += 1) {}
        if (j > i and j < segment.len and segment[j] == '=') {
            while (j < segment.len and !std.ascii.isWhitespace(segment[j])) : (j += 1) {}
            i = j;
            continue;
        }

        const word = nextShellWord(segment, &i);
        if (word.len == 0) break;

        // Strip surrounding quotes before basename so `"/bin/bash"` → bash.
        var bare = word;
        if (bare.len >= 2 and (bare[0] == '\'' or bare[0] == '"') and bare[bare.len - 1] == bare[0]) {
            bare = bare[1 .. bare.len - 1];
        }
        var base = commandWordBasename(bare);
        if (base.len >= 4 and std.ascii.eqlIgnoreCase(base[base.len - 4 ..], ".exe")) {
            base = base[0 .. base.len - 4];
        }

        // Known wrappers: keep scanning for the real receiver.
        if (isHeredocWrapperBasename(base)) {
            // Consume following option tokens (+ operands for options that take one).
            while (i < segment.len) {
                var peek = i;
                while (peek < segment.len and std.ascii.isWhitespace(segment[peek])) : (peek += 1) {}
                if (peek >= segment.len) break;
                if (segment[peek] != '-') break;
                const opt = nextShellWord(segment, &i);
                if (wrapperOptionTakesOperand(base, opt)) {
                    // Consume the operand unless already attached via `=`.
                    var peek2 = i;
                    while (peek2 < segment.len and std.ascii.isWhitespace(segment[peek2])) : (peek2 += 1) {}
                    if (peek2 < segment.len and segment[peek2] != '-') {
                        _ = nextShellWord(segment, &i);
                    }
                }
            }
            continue;
        }

        // Shell reserved words are syntax, not receivers (`then bash <<EOF`).
        if (isShellReservedWord(base)) continue;

        if (isDataSinkBasename(base)) return .data_sink;
        if (isInterpreterBasename(base) or interpreterBasenameLoose(base)) return .executing;

        // Leading option without argv0 yet → keep scanning (rare).
        if (base.len > 0 and base[0] == '-') continue;

        // Unknown command word is not an executing shell receiver.
        return null;
    }
    return null;
}

fn isShellReservedWord(base: []const u8) bool {
    const words = [_][]const u8{
        "if",     "then", "else", "elif", "fi", "for", "while", "until", "do",       "done",
        "case",   "esac", "in",   "!",    "{",  "}",   "[[",    "]]",    "function", "select",
        "coproc",
    };
    for (words) |w| {
        if (std.mem.eql(u8, base, w)) return true;
    }
    return false;
}

fn wrapperOptionTakesOperand(wrapper: []const u8, opt: []const u8) bool {
    if (opt.len == 0) return false;
    if (std.mem.indexOfScalar(u8, opt, '=')) |_| return false; // --unset=NAME
    if (std.mem.eql(u8, wrapper, "env")) {
        return std.mem.eql(u8, opt, "-u") or std.mem.eql(u8, opt, "--unset") or
            std.mem.eql(u8, opt, "-C") or std.mem.eql(u8, opt, "--chdir") or
            std.mem.eql(u8, opt, "-S") or std.mem.eql(u8, opt, "--split-string");
    }
    if (std.mem.eql(u8, wrapper, "sudo") or std.mem.eql(u8, wrapper, "doas")) {
        return std.mem.eql(u8, opt, "-u") or std.mem.eql(u8, opt, "-g") or
            std.mem.eql(u8, opt, "-h") or std.mem.eql(u8, opt, "-C") or
            std.mem.eql(u8, opt, "-D") or std.mem.eql(u8, opt, "-R") or
            std.mem.eql(u8, opt, "-T") or std.mem.eql(u8, opt, "-p") or
            std.mem.eql(u8, opt, "-r") or std.mem.eql(u8, opt, "-t");
    }
    if (std.mem.eql(u8, wrapper, "nice")) {
        return std.mem.eql(u8, opt, "-n") or std.mem.eql(u8, opt, "--adjustment");
    }
    if (std.mem.eql(u8, wrapper, "stdbuf")) {
        return std.mem.eql(u8, opt, "-i") or std.mem.eql(u8, opt, "-o") or std.mem.eql(u8, opt, "-e") or
            std.mem.eql(u8, opt, "--input") or std.mem.eql(u8, opt, "--output") or std.mem.eql(u8, opt, "--error");
    }
    return false;
}

fn isHeredocWrapperBasename(base: []const u8) bool {
    const wrappers = [_][]const u8{ "sudo", "doas", "env", "nice", "nohup", "command", "time", "stdbuf" };
    for (wrappers) |w| {
        if (std.mem.eql(u8, base, w)) return true;
    }
    return false;
}

fn interpreterBasenameLoose(base: []const u8) bool {
    // python3.11, python3, bash.exe already stripped
    if (std.mem.startsWith(u8, base, "python")) {
        const rest = base["python".len..];
        if (rest.len == 0) return true;
        for (rest) |c| {
            if (!std.ascii.isDigit(c) and c != '.') return false;
        }
        return true;
    }
    return false;
}

/// Advance `idx` past the next shell word in `s`; return the word slice.
fn nextShellWord(s: []const u8, idx: *usize) []const u8 {
    while (idx.* < s.len and std.ascii.isWhitespace(s[idx.*])) : (idx.* += 1) {}
    if (idx.* >= s.len) return s[idx.*..idx.*];
    const start = idx.*;
    const quote = s[start];
    if (quote == '\'' or quote == '"') {
        idx.* = start + 1;
        while (idx.* < s.len and s[idx.*] != quote) : (idx.* += 1) {}
        if (idx.* < s.len) idx.* += 1;
        return s[start..idx.*];
    }
    while (idx.* < s.len and !std.ascii.isWhitespace(s[idx.*])) : (idx.* += 1) {}
    return s[start..idx.*];
}

/// Basename of argv0 with optional `.exe` stripped; true for shells/interpreters.
fn firstArgv0LooksLikeExecutor(cmd: []const u8) bool {
    const t = std.mem.trim(u8, cmd, " \t\r\n");
    if (t.len == 0) return false;
    var i: usize = 0;
    // skip leading env assignments: NAME=val
    while (i < t.len) {
        var j = i;
        while (j < t.len and (std.ascii.isAlphanumeric(t[j]) or t[j] == '_')) : (j += 1) {}
        if (j > i and j < t.len and t[j] == '=') {
            while (j < t.len and !std.ascii.isWhitespace(t[j])) : (j += 1) {}
            while (j < t.len and std.ascii.isWhitespace(t[j])) : (j += 1) {}
            i = j;
            continue;
        }
        break;
    }
    var end = i;
    while (end < t.len and !std.ascii.isWhitespace(t[end])) : (end += 1) {}
    var word = t[i..end];
    // basename
    if (std.mem.lastIndexOfScalar(u8, word, '/')) |slash| {
        word = word[slash + 1 ..];
    }
    if (std.mem.lastIndexOfScalar(u8, word, '\\')) |slash| {
        word = word[slash + 1 ..];
    }
    // strip .exe
    if (word.len >= 4 and std.ascii.eqlIgnoreCase(word[word.len - 4 ..], ".exe")) {
        word = word[0 .. word.len - 4];
    }
    // python / python3 / python3.11
    if (std.mem.startsWith(u8, word, "python")) {
        const rest = word["python".len..];
        if (rest.len == 0) return true;
        // version-only suffix
        var all_ver = true;
        for (rest) |c| {
            if (!std.ascii.isDigit(c) and c != '.') {
                all_ver = false;
                break;
            }
        }
        if (all_ver) return true;
    }
    const exact = [_][]const u8{ "bash", "sh", "zsh", "ksh", "dash", "ruby", "perl", "node" };
    for (exact) |e| {
        if (std.mem.eql(u8, word, e)) return true;
    }
    return false;
}

fn appendSegments(allocator: std.mem.Allocator, candidates: *std.ArrayList([]const u8), cmd: []const u8) !void {
    const segs = try segments.splitCommandSegments(cmd, allocator);
    defer segments.freeSegments(allocator, segs);
    for (segs) |s| {
        try candidates.append(allocator, s);
    }
}

const EvalOneOptions = struct {
    /// When true, skip data-only sanitize masking (LHS of pipe-to-shell is executing).
    skip_data_sanitize: bool = false,
};

/// Collect pipeline prefixes that feed a shell/interpreter via `|` / `|&`.
/// Items are borrowed slices into `cmd` (caller must keep `cmd` alive).
fn appendPipelinePrefixesToExecutor(
    cmd: []const u8,
    allocator: std.mem.Allocator,
    out: *std.ArrayList([]const u8),
) !void {
    var pipeline_start: usize = 0;
    var i: usize = 0;
    var in_single = false;
    var in_double = false;

    while (i < cmd.len) {
        const b = cmd[i];
        if (b == '\\' and !in_single and i + 1 < cmd.len) {
            i += 2;
            continue;
        }
        if (b == '\'' and !in_double) {
            in_single = !in_single;
            i += 1;
            continue;
        }
        if (b == '"' and !in_single) {
            in_double = !in_double;
            i += 1;
            continue;
        }
        if (in_single or in_double) {
            i += 1;
            continue;
        }

        // Non-pipe separators end the current pipeline group.
        if (b == ';' or b == '\n') {
            pipeline_start = i + 1;
            i += 1;
            continue;
        }
        if (b == '&') {
            // `>&` / `&>` redirections are not command separators.
            if (i > 0 and cmd[i - 1] == '>') {
                i += 1;
                continue;
            }
            if (i + 1 < cmd.len and cmd[i + 1] == '>') {
                i += 1;
                continue;
            }
            if (i + 1 < cmd.len and cmd[i + 1] == '&') {
                pipeline_start = i + 2;
                i += 2;
                continue;
            }
            pipeline_start = i + 1;
            i += 1;
            continue;
        }
        if (b == '|') {
            if (i + 1 < cmd.len and cmd[i + 1] == '|') {
                pipeline_start = i + 2;
                i += 2;
                continue;
            }
            var w: usize = 1;
            if (i + 1 < cmd.len and cmd[i + 1] == '&') w = 2; // |&
            const rhs_start = i + w;
            if (firstArgv0LooksLikeExecutor(cmd[rhs_start..])) {
                const prefix = std.mem.trim(u8, cmd[pipeline_start..i], " \t\r\n");
                if (prefix.len > 0) try out.append(allocator, prefix);
            }
            // Continue scanning; later stages may also be executors.
            i = rhs_start;
            continue;
        }
        i += 1;
    }
}

fn evalOne(allocator: std.mem.Allocator, cand: []const u8, match_opts: registry.MatchOptions, opts: EvalOneOptions) !?registry.Hit {
    const trimmed = std.mem.trim(u8, cand, " \t\r\n");
    if (trimmed.len == 0) return null;

    // Pure assignment segment (VAR=value) — not executed as a command word.
    if (isAssignmentOnly(trimmed)) return null;

    // Mask non-executing heredoc bodies (cat/tee/grep <<EOF …) so data cannot trigger packs.
    // When skip_data_sanitize (pipe-to-shell LHS), leave bodies visible — stdin is executing.
    const masked_hd = if (opts.skip_data_sanitize)
        try allocator.dupe(u8, trimmed)
    else
        try maskNonExecutingHeredoc(allocator, trimmed);
    defer allocator.free(masked_hd);

    const sanitized = if (opts.skip_data_sanitize)
        try allocator.dupe(u8, masked_hd)
    else
        try sanitize.sanitizeForMatching(allocator, masked_hd);
    defer allocator.free(sanitized);

    // Language-runtime destructive APIs inside -c/-e bodies (no pack regex covers these).
    if (matchLangDestruct(sanitized)) |h| return h;

    // ${TMPDIR:-/tmp}/… is a temp-family path (bash default expansion).
    const for_match = try rewriteTempDefault(allocator, sanitized);
    defer allocator.free(for_match);

    if (matchDeny(for_match, match_opts)) |h| return h;

    // Wrapper strip only on the sanitized form so false-positive data stays masked.
    var norm = try normalize.normalizeCommand(allocator, for_match);
    defer norm.deinit(allocator);
    if (matchDeny(norm.normalized, match_opts)) |h| return h;

    return null;
}

fn isAssignmentOnly(cmd: []const u8) bool {
    // NAME=VALUE with no leading command word.
    if (cmd.len == 0 or std.ascii.isDigit(cmd[0])) return false;
    var i: usize = 0;
    while (i < cmd.len and (std.ascii.isAlphanumeric(cmd[i]) or cmd[i] == '_')) : (i += 1) {}
    if (i == 0 or i >= cmd.len or cmd[i] != '=') return false;
    // Reject if there is another word that looks like a command after the value.
    // Simple: if the line is a single assignment token (possibly quoted value), treat as assignment.
    // `VAR=x cmd` is not assignment-only.
    var j = i + 1;
    if (j < cmd.len and (cmd[j] == '\'' or cmd[j] == '"')) {
        const q = cmd[j];
        j += 1;
        while (j < cmd.len and cmd[j] != q) : (j += 1) {}
        if (j < cmd.len) j += 1;
    } else {
        while (j < cmd.len and !std.ascii.isWhitespace(cmd[j])) : (j += 1) {}
    }
    while (j < cmd.len and std.ascii.isWhitespace(cmd[j])) : (j += 1) {}
    return j >= cmd.len;
}

fn matchLangDestruct(cmd: []const u8) ?registry.Hit {
    // Python/Ruby: shutil.rmtree / os.remove / FileUtils.rm_rf.
    // Node: fs.rmSync / fs.rm / rimraf / fse.remove / fs/promises — flexible call forms.
    if (langDestructApiPresent(cmd)) {
        // Catastrophe paths → critical so product hard-fence / permanent fence apply.
        const critical_paths = [_][]const u8{
            "/home",  "/etc",  "/usr", "/var",  "/root",
            "~",      "$HOME", "'/'",  "\"/\"", "('/'",
            "(\"/\"",
        };
        for (critical_paths) |s| {
            if (std.mem.indexOf(u8, cmd, s) != null) {
                return .{
                    .pack_id = "core.filesystem",
                    .pattern_name = "rm-rf-root-home",
                    .severity = .critical,
                    .reason = "Language-runtime recursive delete of root/home/system paths is catastrophic.",
                };
            }
        }
        // Other path-like args (e.g. /tmp) or bare calls → high (softenable; not hard-fence).
        return .{
            .pack_id = "core.filesystem",
            .pattern_name = "rm-rf-general",
            .severity = .high,
            .reason = "Language-runtime recursive delete is destructive and requires human approval.",
        };
    }
    // Node write/overwrite of sensitive paths (not recursive delete).
    if (matchLangWriteSensitive(cmd)) |h| return h;
    return null;
}

/// True when `cmd` contains a language-runtime recursive-delete API call shape.
/// Tolerates optional whitespace before `(`, `.call`/`.apply`/`.bind`, optional
/// chaining `?.`, bracket property access, Reflect.apply, and `fs/promises`.
fn langDestructApiPresent(cmd: []const u8) bool {
    // Unique API basenames: name + invocation surface. "fs.rm" must not match "fs.rmSync".
    const call_names = [_][]const u8{
        "rmtree",
        "os.remove",
        "os.unlink",
        "FileUtils.rm_rf",
        "FileUtils.rm_r",
        "Path.rmtree",
        "rmSync",
        "rmdirSync",
        "unlinkSync",
        // Callback forms: require('fs').unlink( / .rmdir(
        "unlink",
        "rmdir",
        "rimraf",
        "fse.removeSync",
        "fse.remove",
        "promises.rm",
        "promises.rmdir",
        "promises.unlink",
        "fs.rm",
        "fs.unlink",
        "fs.rmdir",
        "fs.promises.rm",
        "fs.promises.rmdir",
        "fs.promises.unlink",
    };
    for (call_names) |name| {
        if (hasCallLike(cmd, name)) return true;
    }
    // Bracket / computed property: fs["rmSync"]( / fs['rm'](
    const bracket_apis = [_][]const u8{
        "[\"rmSync\"]",
        "['rmSync']",
        "[\"rm\"]",
        "['rm']",
        "[\"rmdirSync\"]",
        "['rmdirSync']",
        "[\"unlinkSync\"]",
        "['unlinkSync']",
    };
    for (bracket_apis) |b| {
        if (hasCallLike(cmd, b)) return true;
    }
    // require("fs/promises").rm(...) — module path breaks "fs.promises.rm(" / "fs.rm(".
    if (std.mem.indexOf(u8, cmd, "fs/promises") != null) {
        const methods = [_][]const u8{ ".rm", ".rmdir", ".unlink", ".rmSync", ".rmdirSync", ".unlinkSync" };
        for (methods) |m| {
            if (hasCallLike(cmd, m)) return true;
        }
    }
    return false;
}

/// True when `rest` begins with method token `token` at a non-identifier boundary.
fn langMethodToken(rest: []const u8, token: []const u8) bool {
    if (!std.mem.startsWith(u8, rest, token)) return false;
    if (rest.len == token.len) return true;
    const c = rest[token.len];
    return !(std.ascii.isAlphanumeric(c) or c == '_' or c == '$');
}

/// True when `name` appears as an invocation surface: `name(`, whitespace-before-(,
/// `name.call`/`.apply`/`.bind`, optional chaining `name?.(`, or Reflect.apply arg.
fn hasCallLike(cmd: []const u8, name: []const u8) bool {
    var start: usize = 0;
    while (std.mem.indexOfPos(u8, cmd, start, name)) |idx| {
        const j = idx + name.len;
        // Reject longer identifier continuation (fs.rm vs fs.rmSync; .rm vs .rmtree).
        if (j < cmd.len and (std.ascii.isAlphanumeric(cmd[j]) or cmd[j] == '_' or cmd[j] == '$')) {
            start = idx + 1;
            continue;
        }
        // Direct call with optional whitespace: name( / name (
        var p = j;
        while (p < cmd.len and std.ascii.isWhitespace(cmd[p])) : (p += 1) {}
        if (p < cmd.len and cmd[p] == '(') return true;
        // Optional chaining: name?.( / name?.call / name?.apply / name?.bind
        if (j + 1 < cmd.len and cmd[j] == '?' and cmd[j + 1] == '.') {
            const rest = cmd[j + 2 ..];
            var q: usize = 0;
            while (q < rest.len and std.ascii.isWhitespace(rest[q])) : (q += 1) {}
            if (q < rest.len and rest[q] == '(') return true;
            if (langMethodToken(rest, "call") or langMethodToken(rest, "apply") or langMethodToken(rest, "bind")) return true;
        }
        // Bound call: name.call / name.apply / name.bind
        if (j < cmd.len and cmd[j] == '.') {
            const rest = cmd[j + 1 ..];
            if (langMethodToken(rest, "call") or langMethodToken(rest, "apply") or langMethodToken(rest, "bind")) return true;
        }
        // Reflect.apply(fn, …) / Function.prototype.apply — method as argument token
        if (j < cmd.len and (cmd[j] == ',' or cmd[j] == ')')) {
            if (std.mem.indexOf(u8, cmd, "Reflect.apply") != null or
                std.mem.indexOf(u8, cmd, "Function.prototype.apply") != null)
            {
                return true;
            }
        }
        start = idx + 1;
    }
    return false;
}

/// Sensitive path literals for language-runtime write/overwrite APIs.
/// Excludes `/tmp` so temp writes can remain allow.
fn langSensitiveWritePath(cmd: []const u8) bool {
    const sensitive = [_][]const u8{ "/home", "/etc", "/usr", "/var", "/root", "~", "$HOME", "'/'", "\"/\"", "('/'", "(\"/\"" };
    for (sensitive) |s| {
        if (std.mem.indexOf(u8, cmd, s) != null) return true;
    }
    return false;
}

/// Node write/overwrite APIs on sensitive paths (parallel to shell redirect packs).
fn matchLangWriteSensitive(cmd: []const u8) ?registry.Hit {
    if (!langSensitiveWritePath(cmd)) return null;
    const write_apis = [_][]const u8{
        "writeFileSync",
        "appendFileSync",
        "createWriteStream",
        "copyFileSync",
        "cpSync",
    };
    for (write_apis) |a| {
        if (hasCallLike(cmd, a)) {
            return .{
                .pack_id = "core.filesystem",
                .pattern_name = "lang-write-sensitive",
                .severity = .high,
                .reason = "Language-runtime write/overwrite of a sensitive path requires human approval.",
            };
        }
    }
    return null;
}

/// Mask `NAME=value` / `NAME='...'` / `NAME="..."` RHS so assignment text cannot
/// trigger pack regexes when evaluating a multi-segment full command.
fn maskAssignmentValues(allocator: std.mem.Allocator, cmd: []const u8) ![]u8 {
    const out = try allocator.dupe(u8, cmd);
    var i: usize = 0;
    while (i < out.len) {
        // start of potential NAME=
        if (i == 0 or out[i - 1] == ';' or out[i - 1] == '\n' or std.ascii.isWhitespace(out[i - 1]) or out[i - 1] == '&' or out[i - 1] == '|') {
            var j = i;
            if (j < out.len and (std.ascii.isAlphabetic(out[j]) or out[j] == '_')) {
                while (j < out.len and (std.ascii.isAlphanumeric(out[j]) or out[j] == '_')) : (j += 1) {}
                if (j < out.len and out[j] == '=') {
                    j += 1;
                    if (j < out.len and (out[j] == '\'' or out[j] == '"')) {
                        const q = out[j];
                        j += 1;
                        while (j < out.len and out[j] != q) : (j += 1) {
                            if (!std.ascii.isWhitespace(out[j])) out[j] = 'x';
                        }
                        i = if (j < out.len) j + 1 else j;
                        continue;
                    } else {
                        while (j < out.len and !std.ascii.isWhitespace(out[j]) and out[j] != ';' and out[j] != '&' and out[j] != '|') : (j += 1) {
                            out[j] = 'x';
                        }
                        i = j;
                        continue;
                    }
                }
            }
        }
        i += 1;
    }
    return out;
}

fn rewriteTempDefault(allocator: std.mem.Allocator, cmd: []const u8) ![]u8 {
    // Map ${TMPDIR:-/tmp} and ${TMPDIR:=/tmp} to $TMPDIR for safe-pattern matching.
    var out = try allocator.dupe(u8, cmd);
    errdefer allocator.free(out);
    const needles = [_][]const u8{ "${TMPDIR:-/tmp}", "${TMPDIR:=/tmp}", "${TMPDIR-:/tmp}" };
    for (needles) |n| {
        while (std.mem.indexOf(u8, out, n)) |idx| {
            // replace with $TMPDIR (shorter) — rebuild
            const new_len = out.len - n.len + "$TMPDIR".len;
            const rebuilt = try allocator.alloc(u8, new_len);
            @memcpy(rebuilt[0..idx], out[0..idx]);
            @memcpy(rebuilt[idx .. idx + 7], "$TMPDIR");
            @memcpy(rebuilt[idx + 7 ..], out[idx + n.len ..]);
            allocator.free(out);
            out = rebuilt;
        }
    }
    return out;
}

/// True when a non-executing heredoc was present but its body was not blanked
/// (missing/mismatched terminator). Used to enable fail-closed segment split.
fn heredocBodyLikelyUnmasked(masked: []const u8, original: []const u8) bool {
    // If masking blanked body bytes to 'x', non-ws content length drops.
    // Unmasked: original and masked share the same non-trivial payload.
    if (masked.len != original.len) return true;
    return std.mem.eql(u8, masked, original);
}

/// Blank out heredoc bodies when the receiver is a data sink (cat/tee/…), matching
/// Rust `mask_non_executing_heredocs` intent.
///
/// Only masks when a matching terminator line is found for the delimiter token
/// as written (including a leading `\` in unquoted forms). That matches the
/// oracle mask path: `<<\EOF` uses delimiter `\EOF` which does not match a
/// closing `EOF` line, so the body stays visible and pack matching fails closed.
fn maskNonExecutingHeredoc(allocator: std.mem.Allocator, cmd: []const u8) ![]u8 {
    const out = try allocator.dupe(u8, cmd);
    if (std.mem.indexOf(u8, cmd, "<<") == null) return out;
    if (isExecutingContext(cmd)) return out;

    // Find first << (not <<<)
    var i: usize = 0;
    while (i + 1 < out.len) : (i += 1) {
        if (out[i] == '<' and out[i + 1] == '<' and !(i + 2 < out.len and out[i + 2] == '<')) {
            var p = i + 2;
            // optional <<- / <<~ marker adjacent to <<
            if (p < out.len and (out[p] == '-' or out[p] == '~')) p += 1;
            while (p < out.len and (out[p] == ' ' or out[p] == '\t')) : (p += 1) {}

            // Parse delimiter token (quoted or bare, including leading `\`).
            // Only quoted delimiters disable shell expansion of the body — safe to mask.
            var delim: []const u8 = "";
            var delim_quoted = false;
            if (p < out.len and (out[p] == '\'' or out[p] == '"')) {
                delim_quoted = true;
                const q = out[p];
                p += 1;
                const start = p;
                while (p < out.len and out[p] != q) : (p += 1) {}
                delim = out[start..p];
                if (p < out.len) p += 1; // closing quote
            } else {
                const start = p;
                while (p < out.len and out[p] != ' ' and out[p] != '\t' and out[p] != '\n' and out[p] != '\r' and
                    out[p] != ';' and out[p] != '&' and out[p] != '|') : (p += 1)
                {}
                delim = out[start..p];
            }
            if (delim.len == 0) break;

            // Body starts after the newline following the delimiter token.
            while (p < out.len and out[p] != '\n') : (p += 1) {}
            if (p >= out.len) break;
            const body_start = p + 1;

            // Find terminator line equal to delim (oracle: exact line match).
            var search = body_start;
            var found_end: ?usize = null;
            while (search <= out.len) {
                const line_end = if (std.mem.indexOfScalar(u8, out[search..], '\n')) |n|
                    search + n
                else
                    out.len;
                const line = out[search..line_end];
                const line_trim = std.mem.trim(u8, line, " \t\r");
                if (std.mem.eql(u8, line_trim, delim)) {
                    found_end = search;
                    break;
                }
                if (line_end >= out.len) break;
                search = line_end + 1;
            }

            if (found_end) |body_end| {
                const body = out[body_start..body_end];
                // Unquoted delimiters expand $(...) / `...` — leave those bodies matchable.
                // Literal bodies (no expansions) remain safe to mask for data sinks.
                if (!delim_quoted and bodyHasShellExpansion(body)) {
                    // Still scan later << redirects on this command.
                    i += 1;
                    continue;
                }
                // Mask body only (preserve newlines / whitespace structure).
                var q = body_start;
                while (q < body_end) : (q += 1) {
                    if (out[q] != '\n' and out[q] != '\r' and !std.ascii.isWhitespace(out[q])) {
                        out[q] = 'x';
                    }
                }
                // Resume just after this `<<` so same-line stacked redirects are found
                // (`cat <<A <<B` …).
                i += 1;
                continue;
            }
            // If terminator not found, leave body unmasked (fail closed) and keep scanning.
            i += 1;
            continue;
        }
    }
    return out;
}

fn bodyHasShellExpansion(body: []const u8) bool {
    // Conservative: any unquoted-ish $(, $`, or backtick may expand under unquoted heredoc.
    if (std.mem.indexOf(u8, body, "$(") != null) return true;
    if (std.mem.indexOfScalar(u8, body, '`') != null) return true;
    // ${...} parameter expansion can nest command substitution; treat as expansion surface.
    if (std.mem.indexOf(u8, body, "${") != null) return true;
    return false;
}

fn matchDeny(cmd: []const u8, match_opts: registry.MatchOptions) ?registry.Hit {
    return switch (registry.matchCommandDetailedOpts(cmd, match_opts)) {
        .deny => |h| h,
        .allow_safe, .allow_miss => null,
    };
}

fn allowStatic(reason: []const u8) Evaluation {
    return .{
        .decision = .allow,
        .severity = .low,
        .reason = reason,
        .owned = false,
    };
}

fn denyStatic(
    rule_id: []const u8,
    pack_id: []const u8,
    pattern_name: []const u8,
    severity: Severity,
    reason: []const u8,
) Evaluation {
    return .{
        .decision = .deny,
        .rule_id = rule_id,
        .pack_id = pack_id,
        .pattern_name = pattern_name,
        .severity = severity,
        .reason = reason,
        .owned = false,
    };
}

pub const CorpusCase = struct {
    command: []const u8,
    expected: []const u8,
    rule_id: ?[]const u8 = null,
    deferred: bool = false,
};

pub fn decisionMatches(eval: Evaluation, expected: []const u8) bool {
    return std.mem.eql(u8, eval.decision.toString(), expected);
}

test "evaluateCommand denies rm -rf root" {
    var eval = try evaluateCommand(std.testing.allocator, "rm -rf /", .{});
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .deny);
    try std.testing.expect(eval.rule_id != null);
    try std.testing.expect(std.mem.indexOf(u8, eval.rule_id.?, "rm-rf") != null);
}

test "evaluateCommand deny carries explain metadata span regex tips and trace" {
    var eval = try evaluateCommand(std.testing.allocator, "rm -rf /", .{});
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .deny);
    try std.testing.expect(eval.regex_source != null);
    try std.testing.expect(eval.regex_source.?.len > 0);
    try std.testing.expect(eval.match_start != null);
    try std.testing.expect(eval.match_end != null);
    try std.testing.expect(eval.matched_text != null);
    try std.testing.expect(eval.matched_text.?.len > 0);
    try std.testing.expect(eval.explanation != null);
    try std.testing.expect(eval.tips.len > 0);
    // Without collector, trace stays empty (hooks zero-cost path).
    try std.testing.expectEqual(@as(usize, 0), eval.trace.len);
    try std.testing.expect(eval.matched_candidate != null);
}

test "evaluateCommand with TraceCollector records nested full_evaluation step not peer matched" {
    var collector = TraceCollector.init(std.testing.allocator);
    defer collector.deinit();
    var eval = try evaluateCommand(std.testing.allocator, "rm -rf /", .{ .trace = &collector });
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .deny);
    try std.testing.expectEqual(@as(usize, 1), eval.trace.len);
    try std.testing.expectEqualStrings("full_evaluation", eval.trace[0].name);
    try std.testing.expect(eval.trace[0].detail != null);
    try std.testing.expect(std.mem.indexOf(u8, eval.trace[0].detail.?, "core.filesystem") != null);
    // No fake peer step named "matched"
    for (eval.trace) |step| {
        try std.testing.expect(!std.mem.eql(u8, step.name, "matched"));
    }
}

test "evaluateCommand with TraceCollector allow path has details child" {
    var collector = TraceCollector.init(std.testing.allocator);
    defer collector.deinit();
    var eval = try evaluateCommand(std.testing.allocator, "git status", .{ .trace = &collector });
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .allow);
    try std.testing.expectEqual(@as(usize, 1), eval.trace.len);
    try std.testing.expectEqualStrings("full_evaluation", eval.trace[0].name);
    try std.testing.expect(eval.trace[0].detail != null);
    try std.testing.expect(std.mem.indexOf(u8, eval.trace[0].detail.?, "no destructive pack matched") != null);
}

test "evaluateCommand allows git status" {
    var eval = try evaluateCommand(std.testing.allocator, "git status", .{});
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .allow);
}

test "evaluateCommand denies git reset --hard" {
    var eval = try evaluateCommand(std.testing.allocator, "git reset --hard", .{});
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .deny);
    try std.testing.expect(std.mem.indexOf(u8, eval.rule_id.?, "reset-hard") != null);
}

test "evaluateCommand denies compound safe then destructive" {
    var eval = try evaluateCommand(std.testing.allocator, "git status; rm -rf /", .{});
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .deny);
}

test "evaluateCommand denies sudo wrapper" {
    var eval = try evaluateCommand(std.testing.allocator, "sudo git reset --hard", .{});
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .deny);
}

test "evaluateCommand denies quoted subcommand git \"reset\"" {
    var eval = try evaluateCommand(std.testing.allocator, "git \"reset\" --hard", .{});
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .deny);
    try std.testing.expect(std.mem.indexOf(u8, eval.rule_id.?, "reset-hard") != null);
}

test "evaluateCommand denies complex quoted sudo git" {
    var eval = try evaluateCommand(std.testing.allocator, "sudo \"/usr/bin/git\" \"reset\" --hard", .{});
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .deny);
    try std.testing.expect(std.mem.indexOf(u8, eval.rule_id.?, "reset-hard") != null);
}

test "evaluateCommand denies internal backslash g\\it reset" {
    var eval = try evaluateCommand(std.testing.allocator, "g\\it reset --hard", .{});
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .deny);
}

test "evaluateCommand denies mixed quoting g'i't reset" {
    var eval = try evaluateCommand(std.testing.allocator, "g'i't reset --hard", .{});
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .deny);
}

test "evaluateCommand denies line-continued reset" {
    var eval = try evaluateCommand(std.testing.allocator, "git re\\\nset --hard", .{});
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .deny);
}

test "evaluateCommand denies mkfs" {
    var eval = try evaluateCommand(std.testing.allocator, "mkfs.ext4 /dev/sda1", .{});
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .deny);
}

test "evaluateCommand empty allows (no-op)" {
    var eval = try evaluateCommand(std.testing.allocator, "   ", .{});
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .allow);
}

test "evaluateCommand allows git add under default packs" {
    var eval = try evaluateCommand(std.testing.allocator, "git add .", .{});
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .allow);
}

test "evaluateCommand allows destructive text in shell comment" {
    var eval = try evaluateCommand(std.testing.allocator, "ls -la # rm -rf /", .{});
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .allow);
}

test "evaluateCommand allows echo unquoted rm -rf data" {
    var eval = try evaluateCommand(std.testing.allocator, "echo rm -rf /", .{});
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .allow);
}

test "evaluateCommand denies lvconvert --merge under default packs" {
    var eval = try evaluateCommand(std.testing.allocator, "lvconvert --merge", .{});
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .deny);
    try std.testing.expect(eval.rule_id != null);
    try std.testing.expectEqualStrings("system.disk:lvconvert-merge", eval.rule_id.?);
}

test "evaluateCommand denies echo/printf/cat redirect to sensitive path" {
    const cases = [_][]const u8{
        "echo x > /etc/passwd",
        "printf x > /etc/passwd",
        "cat > /etc/passwd",
    };
    for (cases) |cmd| {
        var eval = try evaluateCommand(std.testing.allocator, cmd, .{});
        defer eval.deinit(std.testing.allocator);
        try std.testing.expect(eval.decision == .deny);
        try std.testing.expect(eval.rule_id != null);
        try std.testing.expectEqualStrings("core.filesystem:redirect-truncate-root-home", eval.rule_id.?);
    }
}

test "evaluateCommand denies node fs.rmSync wipe of root" {
    const cases = [_][]const u8{
        "node -e \"require('fs').rmSync('/',{recursive:true})\"",
        "node -e 'require(\"fs\").rmSync(\"/\",{recursive:true})'",
        "node --eval \"fs.rmSync('/etc',{recursive:true})\"",
        // Residual forms the exact-substring list previously missed (M-4).
        "node -e 'require(\"fs/promises\").rm(\"/\",{recursive:true})'",
        "node -e 'require(\"fs\")[\"rmSync\"](\"/\",{recursive:true})'",
        "node -e 'require(\"fs\").rmSync (\"/\",{recursive:true})'",
        "node -e 'require(\"fs\").promises.rm(\"/\",{recursive:true})'",
        // Second-pass residuals: bind / Reflect / optional chaining / rmdir / unlink.
        "node -e \"require('fs').rmSync.bind(null)('/',{recursive:true})\"",
        "node -e \"Reflect.apply(require('fs').rmSync,null,['/',{recursive:true}])\"",
        "node -e \"require('fs').rmSync?.('/',{recursive:true})\"",
        "node -e \"require('fs').rmdirSync('/',{recursive:true})\"",
        "node -e \"require('fs').unlinkSync('/etc/passwd')\"",
        "node -e \"require('fs').rmSync.call(null,'/',{recursive:true})\"",
    };
    for (cases) |cmd| {
        var eval = try evaluateCommand(std.testing.allocator, cmd, .{});
        defer eval.deinit(std.testing.allocator);
        try std.testing.expect(eval.decision == .deny);
        // Root/home/system lang-destruct wipes are critical (product hard-fence class).
        try std.testing.expect(eval.severity == .critical);
        try std.testing.expect(eval.rule_id != null);
        try std.testing.expectEqualStrings("core.filesystem:rm-rf-root-home", eval.rule_id.?);
    }
}

test "evaluateCommand denies node write APIs on sensitive paths" {
    const deny_cases = [_][]const u8{
        "node -e \"require('fs').writeFileSync('/etc/passwd','x')\"",
        "node -e \"require('fs').appendFileSync('/etc/passwd','x')\"",
        "node -e \"require('fs').createWriteStream('/etc/passwd')\"",
        "node -e \"require('fs').copyFileSync('/tmp/a','/etc/passwd')\"",
        "node -e \"require('fs').cpSync('/tmp/a','/home/user/x')\"",
    };
    for (deny_cases) |cmd| {
        var eval = try evaluateCommand(std.testing.allocator, cmd, .{});
        defer eval.deinit(std.testing.allocator);
        try std.testing.expect(eval.decision == .deny);
    }
    var allow_eval = try evaluateCommand(std.testing.allocator, "node -e \"require('fs').writeFileSync('/tmp/out','x')\"", .{});
    defer allow_eval.deinit(std.testing.allocator);
    try std.testing.expect(allow_eval.decision == .allow);
}

test "evaluateCommand denies rm after newline following git commit -m" {
    var eval = try evaluateCommand(std.testing.allocator, "git commit -m\nrm -rf /", .{});
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .deny);
}

test "evaluateCommand denies multi-arg rm with sensitive target" {
    var eval = try evaluateCommand(std.testing.allocator, "rm -rf /tmp/safe /etc/passwd", .{});
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .deny);
}

test "evaluateCommand denies cat heredoc with backslash-escaped delimiter" {
    const cmd =
        \\
        \\cat <<\EOF
        \\rm -rf /
        \\EOF
        \\
    ;
    var eval = try evaluateCommand(std.testing.allocator, cmd, .{});
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .deny);
}

test "evaluateCommand denies attached redirection git>/dev/null reset" {
    const cases = [_][]const u8{
        "\"git\">/dev/null reset --hard",
        "\"git\"&>/dev/null reset --hard",
        "\"git\"&>>/dev/null reset --hard",
        "git>/dev/null reset --hard",
        "git>>/dev/null reset --hard",
        "git&>/dev/null reset --hard",
        "git&>>/dev/null reset --hard",
        "git >/dev/null reset --hard",
        "command >>/dev/null git reset --hard",
    };
    for (cases) |cmd| {
        var eval = try evaluateCommand(std.testing.allocator, cmd, .{});
        defer eval.deinit(std.testing.allocator);
        try std.testing.expect(eval.decision == .deny);
    }
}

test "evaluateCommand allows command builtin pure append redirect" {
    // Non-sensitive path only: append to /usr/* is a pack deny (redirect-truncate-root-home).
    var eval = try evaluateCommand(std.testing.allocator, "command >> /tmp/log", .{});
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .allow);
}

test "evaluateCommand denies python.exe -c shutil.rmtree" {
    const cases = [_][]const u8{
        "python.exe -c \"import shutil; shutil.rmtree('/')\"",
        "python3.11.exe -c \"import shutil; shutil.rmtree('/')\"",
        "python3.exe -c \"import shutil; shutil.rmtree('/tmp/x')\"",
    };
    for (cases) |cmd| {
        var eval = try evaluateCommand(std.testing.allocator, cmd, .{});
        defer eval.deinit(std.testing.allocator);
        try std.testing.expect(eval.decision == .deny);
    }
}

test "evaluateCommand denies data-only pipe to shell interpreter" {
    const cases = [_][]const u8{
        "echo 'rm -rf /' | bash",
        "echo 'rm -rf /' | bash -s",
        "printf 'rm -rf /\\n' | sh",
        "echo \"rm -rf /\" | zsh",
        "echo 'rm -rf /' | /bin/bash",
        "echo 'rm -rf /' | cat | bash",
    };
    for (cases) |cmd| {
        var eval = try evaluateCommand(std.testing.allocator, cmd, .{});
        defer eval.deinit(std.testing.allocator);
        try std.testing.expect(eval.decision == .deny);
    }
}

test "evaluateCommand still allows echo data without pipe to shell" {
    var eval = try evaluateCommand(std.testing.allocator, "echo 'rm -rf /'", .{});
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .allow);
}

test "evaluateCommand allows harmless pipe to shell" {
    var eval = try evaluateCommand(std.testing.allocator, "echo hello | bash", .{});
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .allow);
}

test "evaluateCommand denies git add with full packs" {
    var eval = try evaluateCommand(std.testing.allocator, "git add .", .{ .default_packs_only = false });
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .deny);
}

test "evaluateCommand denies cross-pack safe plus destructive" {
    var eval = try evaluateCommand(std.testing.allocator, "rm -rf / $(git checkout -b x)", .{});
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .deny);
}

test "evaluateCommand denies echo payload piped to shell" {
    const cases = [_][]const u8{
        "echo rm -rf / | sh",
        "echo 'rm -rf /' | bash",
        "printf 'rm -rf /' | /bin/sh",
    };
    for (cases) |cmd| {
        var eval = try evaluateCommand(std.testing.allocator, cmd, .{});
        defer eval.deinit(std.testing.allocator);
        try std.testing.expect(eval.decision == .deny);
    }
}

test "evaluateCommand denies attached heredoc on qualified shell" {
    const cases = [_][]const u8{
        "/bin/bash<<'EOF'\nrm -rf /\nEOF",
        "/bin/sh<<EOF\nrm -rf /\nEOF",
        "bash<<EOF\ngit reset --hard\nEOF",
        // Options before redirect: argv0 is bash, not -s.
        "bash -s <<'EOF'\nrm -rf /\nEOF",
        "/bin/bash -s <<EOF\nrm -rf /\nEOF",
        "sudo bash -s <<'EOF'\ngit reset --hard\nEOF",
    };
    for (cases) |cmd| {
        var eval = try evaluateCommand(std.testing.allocator, cmd, .{});
        defer eval.deinit(std.testing.allocator);
        try std.testing.expect(eval.decision == .deny);
    }
}

test "evaluateCommand still allows cat attached heredoc data" {
    const cmd = "cat<<EOF\nrm -rf /\nEOF";
    var eval = try evaluateCommand(std.testing.allocator, cmd, .{});
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .allow);
}

test "evaluateCommand opt-in pack denies docker prune" {
    var allow_baseline = try evaluateCommand(std.testing.allocator, "docker system prune", .{});
    defer allow_baseline.deinit(std.testing.allocator);
    try std.testing.expect(allow_baseline.decision == .allow);

    var deny_opt_in = try evaluateCommand(std.testing.allocator, "docker system prune", .{
        .extra_enabled = &.{"containers.docker"},
    });
    defer deny_opt_in.deinit(std.testing.allocator);
    try std.testing.expect(deny_opt_in.decision == .deny);
    try std.testing.expect(deny_opt_in.pack_id != null);
    try std.testing.expectEqualStrings("containers.docker", deny_opt_in.pack_id.?);
}

// Phase 1 WP2 — structure smart checks on Mode A (default packs).
// Executed compounds/wrappers/embeds deny; assignment/quote data-only allows.
// Deny rows pin pack-qualified rule_id (mvp_corpus attribution).
test "phase1 structure smart checks Mode A" {
    const Case = struct {
        cmd: []const u8,
        expect_deny: bool,
        /// Pack-qualified rule_id when expect_deny (mvp_corpus form).
        rule_id: ?[]const u8 = null,
    };
    const cases = [_]Case{
        .{ .cmd = "git status; rm -rf /", .expect_deny = true, .rule_id = "core.filesystem:rm-rf-root-home" },
        .{ .cmd = "sudo git reset --hard", .expect_deny = true, .rule_id = "core.git:reset-hard" },
        .{ .cmd = "VAR='rm -rf /'; echo \"$VAR\"", .expect_deny = false },
        .{ .cmd = "echo 'rm -rf /'", .expect_deny = false },
        .{ .cmd = "bash -c 'rm -rf /'", .expect_deny = true, .rule_id = "core.filesystem:rm-rf-root-home" },
    };
    for (cases) |c| {
        var eval = try evaluateCommand(std.testing.allocator, c.cmd, .{});
        defer eval.deinit(std.testing.allocator);
        if (c.expect_deny) {
            try std.testing.expect(eval.decision == .deny);
            try std.testing.expect(eval.rule_id != null);
            if (c.rule_id) |want| {
                try std.testing.expectEqualStrings(want, eval.rule_id.?);
            }
        } else {
            try std.testing.expect(eval.decision == .allow);
        }
    }
}

// Phase 1 WP3 — hard-fence catastrophe table (Mode A): deny + pack-qualified rule_id.
test "phase1 hard-fence catastrophe table Mode A" {
    const Case = struct {
        cmd: []const u8,
        /// Full pack:pattern rule_id (mvp_corpus).
        rule_id: []const u8,
    };
    const cases = [_]Case{
        .{ .cmd = "rm -rf /", .rule_id = "core.filesystem:rm-rf-root-home" },
        .{ .cmd = "rm -rf ~", .rule_id = "core.filesystem:rm-rf-root-home" },
        .{ .cmd = "git reset --hard", .rule_id = "core.git:reset-hard" },
        .{ .cmd = "git push --force origin main", .rule_id = "core.git:push-force-long" },
        .{ .cmd = "mkfs.ext4 /dev/sda1", .rule_id = "system.disk:mkfs" },
        .{ .cmd = "dd if=/dev/zero of=/dev/sda", .rule_id = "system.disk:dd-device" },
    };
    for (cases) |c| {
        var eval = try evaluateCommand(std.testing.allocator, c.cmd, .{});
        defer eval.deinit(std.testing.allocator);
        try std.testing.expect(eval.decision == .deny);
        try std.testing.expect(eval.rule_id != null);
        try std.testing.expectEqualStrings(c.rule_id, eval.rule_id.?);
    }
}

// Phase 2 — Mode A core.credentials:cat-env (exact .env peeks).
// rule_id pins are mandatory: corpora use enforce_rule_id=false.
test "phase2 credentials cat-env Mode A" {
    const Case = struct {
        cmd: []const u8,
        expect_deny: bool,
        rule_id: ?[]const u8 = null,
    };
    const cases = [_]Case{
        // Deny + exact rule_id (bare + multi-segment + all pack readers)
        .{ .cmd = "cat .env", .expect_deny = true, .rule_id = "core.credentials:cat-env" },
        .{ .cmd = "cat ./.env", .expect_deny = true, .rule_id = "core.credentials:cat-env" },
        .{ .cmd = "head -n 5 .env", .expect_deny = true, .rule_id = "core.credentials:cat-env" },
        .{ .cmd = "less .env", .expect_deny = true, .rule_id = "core.credentials:cat-env" },
        .{ .cmd = "more .env", .expect_deny = true, .rule_id = "core.credentials:cat-env" },
        .{ .cmd = "bat .env", .expect_deny = true, .rule_id = "core.credentials:cat-env" },
        .{ .cmd = "cat secrets/.env", .expect_deny = true, .rule_id = "core.credentials:cat-env" },
        // Embed + compound (mandatory rule_id pins)
        .{ .cmd = "bash -c 'cat .env'", .expect_deny = true, .rule_id = "core.credentials:cat-env" },
        .{ .cmd = "cat .env && true", .expect_deny = true, .rule_id = "core.credentials:cat-env" },
        // Templates / benign / near-misses / data-only FP immunity for less/more
        .{ .cmd = "cat .env.example", .expect_deny = false },
        .{ .cmd = "cat ./.env.example", .expect_deny = false },
        .{ .cmd = "cat .env.sample", .expect_deny = false },
        .{ .cmd = "cat .env.template", .expect_deny = false },
        .{ .cmd = "cat README.md", .expect_deny = false },
        .{ .cmd = "cat package.json", .expect_deny = false },
        .{ .cmd = "printenv", .expect_deny = false },
        .{ .cmd = "cat foo.env", .expect_deny = false },
        .{ .cmd = "cat .envrc", .expect_deny = false },
        .{ .cmd = "cat .env.bak", .expect_deny = false },
        .{ .cmd = "echo 'cat .env'", .expect_deny = false },
        .{ .cmd = "less rm -rf /", .expect_deny = false },
        .{ .cmd = "more rm -rf /", .expect_deny = false },
    };
    for (cases) |c| {
        var eval = try evaluateCommand(std.testing.allocator, c.cmd, .{});
        defer eval.deinit(std.testing.allocator);
        if (c.expect_deny) {
            try std.testing.expect(eval.decision == .deny);
            try std.testing.expect(eval.rule_id != null);
            if (c.rule_id) |want| {
                try std.testing.expectEqualStrings(want, eval.rule_id.?);
            }
        } else {
            try std.testing.expect(eval.decision == .allow);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// s-engine — plan §4.1 evaluate order (RED until implementer wires pipeline)
//
// Contract pinned for implementer (mod.zig + registry.zig exclusive):
//
// EvaluateOptions (distinct permanent API — NOT `allowlists` / Layered):
//   .permanent_allowlist: ?allowlist_store.Store = null
//   .allow_once_path: ?[]const u8 = null
//   .io: ?std.Io = null                    // required with allow_once_path
//   .consume_allow_once: bool = true       // false for explain (match only)
//   .now_iso: ?[]const u8 = null          // expiry clock for permanent + allow-once
//   .cwd already used for allow-once scope
//
// Evaluation attribution on exception allow:
//   .exception_source: ?[]const u8 = null // "allow_once" | "allowlist"
//   .exception_layer: ?[]const u8 = null  // "user" | "project" (permanent)
//   .exception_kind: ?[]const u8 = null   // "command" | "rule" (permanent)
//   .reason includes entry reason text
//
// Order: 1 allow-once exact → 2 permanent kind=command FULL ALLOW →
//        3 packs with permanent kind=rule as skip-this-rule only (E8)
// ═══════════════════════════════════════════════════════════════════════════

// Re-exports live at module top (`pub const allowlist_store` / `allow_once`).
// Test helpers alias allow-once for historical `allow_once_mod` call sites.
const allow_once_mod = allow_once;

const s_engine_now = "2026-07-25T15:00:00Z";
const s_engine_future = "9999-01-01T00:00:00Z";

fn sEnginePermanentStore(entries: []const allowlist_store.PermanentEntry) allowlist_store.Store {
    // Cast away const for Store.entries slice type; tests use static literals only.
    return .{
        .entries = @constCast(entries),
        .owned = false,
    };
}

fn sEngineTmpRoot() !struct { dir: std.testing.TmpDir, path: []u8 } {
    var tmp = std.testing.tmpDir(.{});
    errdefer tmp.cleanup();
    const path_z = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(path_z);
    const path = try std.testing.allocator.dupe(u8, path_z);
    return .{ .dir = tmp, .path = path };
}

fn sEngineJoin(tmp_path: []const u8, rel: []const u8) ![]u8 {
    return try std.fs.path.join(std.testing.allocator, &.{ tmp_path, rel });
}

fn sEngineSeedAllowOnce(
    pending_path: []const u8,
    allow_once_path: []const u8,
    command: []const u8,
    cwd: []const u8,
    reason: []const u8,
) !void {
    var issued = try allow_once_mod.issuePending(
        std.testing.io,
        std.testing.allocator,
        pending_path,
        command,
        cwd,
        reason,
        s_engine_now,
        true,
    );
    defer issued.deinit(std.testing.allocator);
    const entry = try allow_once_mod.redeem(
        std.testing.io,
        std.testing.allocator,
        pending_path,
        allow_once_path,
        issued.record.short_code,
        s_engine_now,
        .cwd,
        cwd,
    );
    allow_once_mod.freeAllowOnceEntry(std.testing.allocator, entry);
}

// ── Acceptance 1: kind=command FULL ALLOW pre-pack; kind=rule E8 skip ───────

test "s-engine: kind=command permanent FULL ALLOW pre-pack exact command (non-critical)" {
    // Medium-severity pack hit may still be permanently allowlisted; critical cannot.
    const reason = "local feature branch cleanup is approved for this workspace";
    const cmd = "git branch -D feature";
    const store = sEnginePermanentStore(&.{
        .{
            .kind = .command,
            .command = cmd,
            .reason = reason,
            .created_at = "2026-07-25T12:00:00Z",
            .layer = .project,
        },
    });

    // Baseline without permanent → deny (medium pack).
    {
        var deny = try evaluateCommand(std.testing.allocator, cmd, .{});
        defer deny.deinit(std.testing.allocator);
        try std.testing.expect(deny.decision == .deny);
        try std.testing.expect(deny.exception_source == null);
        try std.testing.expect(deny.severity == .medium);
    }

    var eval = try evaluateCommand(std.testing.allocator, cmd, .{
        .permanent_allowlist = store,
        .now_iso = s_engine_now,
    });
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .allow);
    try std.testing.expectEqualStrings("allowlist", eval.exception_source.?);
    try std.testing.expectEqualStrings("project", eval.exception_layer.?);
    try std.testing.expectEqualStrings("command", eval.exception_kind.?);
    try std.testing.expect(std.mem.indexOf(u8, eval.reason, reason) != null);

    // Near-miss / non-exact command still denies (exact-only; no prefix).
    var miss = try evaluateCommand(std.testing.allocator, "git branch -D other", .{
        .permanent_allowlist = store,
        .now_iso = s_engine_now,
    });
    defer miss.deinit(std.testing.allocator);
    try std.testing.expect(miss.decision == .deny);
    try std.testing.expect(miss.exception_source == null);
}

test "s-engine: permanent kind=command cannot unlock critical pack hit" {
    const store = sEnginePermanentStore(&.{
        .{
            .kind = .command,
            .command = "git reset --hard HEAD",
            .reason = "critical must remain hard-fenced",
            .created_at = "2026-07-25T12:00:00Z",
            .layer = .project,
        },
    });
    var eval = try evaluateCommand(std.testing.allocator, "git reset --hard HEAD", .{
        .permanent_allowlist = store,
        .now_iso = s_engine_now,
    });
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .deny);
    try std.testing.expect(eval.exception_source == null);
    try std.testing.expect(eval.severity == .critical);
    try std.testing.expect(eval.rule_id != null);
    try std.testing.expectEqualStrings("core.git:reset-hard", eval.rule_id.?);
}

test "s-engine: permanent kind=command cannot unlock normalize-only critical form" {
    // Raw registry match on the exact permanent string may miss; evalOne normalize
    // path still yields critical. Fence must use the full pipeline (M-2).
    const cases = [_][]const u8{
        "git \"reset\" --hard HEAD",
        "g\\it reset --hard HEAD",
    };
    for (cases) |cmd| {
        const store = sEnginePermanentStore(&.{
            .{
                .kind = .command,
                .command = cmd,
                .reason = "normalize-only critical must stay hard-fenced",
                .created_at = "2026-07-25T12:00:00Z",
                .layer = .user,
            },
        });
        var eval = try evaluateCommand(std.testing.allocator, cmd, .{
            .permanent_allowlist = store,
            .now_iso = s_engine_now,
        });
        defer eval.deinit(std.testing.allocator);
        try std.testing.expect(eval.decision == .deny);
        try std.testing.expect(eval.exception_source == null);
        try std.testing.expect(eval.severity == .critical);
        try std.testing.expectEqualStrings("core.git:reset-hard", eval.rule_id.?);
    }
}

test "s-engine: permanent kind=command cannot unlock critical lang-destruct Node wipe" {
    const cmd = "node -e \"require('fs').rmSync('/',{recursive:true})\"";
    const store = sEnginePermanentStore(&.{
        .{
            .kind = .command,
            .command = cmd,
            .reason = "lang-destruct critical must stay hard-fenced",
            .created_at = "2026-07-25T12:00:00Z",
            .layer = .user,
        },
    });
    var eval = try evaluateCommand(std.testing.allocator, cmd, .{
        .permanent_allowlist = store,
        .now_iso = s_engine_now,
    });
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .deny);
    try std.testing.expect(eval.exception_source == null);
    try std.testing.expect(eval.severity == .critical);
    try std.testing.expectEqualStrings("core.filesystem:rm-rf-root-home", eval.rule_id.?);
}

test "s-engine: permanent kind=command cannot unlock multi-segment critical" {
    // Full-string evalOne can miss critical (safe prefix / medium-first); fence must
    // scan segment candidates like evaluateCommand and refuse FULL ALLOW.
    const cases = [_][]const u8{
        "git status && git reset --hard",
        "git branch -D feature; git reset --hard HEAD",
        "echo ok; git reset --hard HEAD",
        "echo $(git reset --hard HEAD)",
    };
    for (cases) |cmd| {
        const store = sEnginePermanentStore(&.{
            .{
                .kind = .command,
                .command = cmd,
                .reason = "multi-candidate critical must stay hard-fenced",
                .created_at = "2026-07-25T12:00:00Z",
                .layer = .user,
            },
        });
        var eval = try evaluateCommand(std.testing.allocator, cmd, .{
            .permanent_allowlist = store,
            .now_iso = s_engine_now,
        });
        defer eval.deinit(std.testing.allocator);
        // Must not FULL ALLOW via permanent (no exception_source). Severity may be
        // medium when a non-critical segment is the first pack hit after the fence
        // refuses unlock — still fail-closed vs permanent FULL ALLOW of critical.
        try std.testing.expect(eval.decision == .deny);
        try std.testing.expect(eval.exception_source == null);
    }
    // Cases where the first denying candidate is the critical segment itself.
    const critical_first = [_][]const u8{
        "git status && git reset --hard",
        "echo ok; git reset --hard HEAD",
        "echo $(git reset --hard HEAD)",
    };
    for (critical_first) |cmd| {
        const store = sEnginePermanentStore(&.{
            .{
                .kind = .command,
                .command = cmd,
                .reason = "critical-first multi-segment",
                .created_at = "2026-07-25T12:00:00Z",
                .layer = .user,
            },
        });
        var eval = try evaluateCommand(std.testing.allocator, cmd, .{
            .permanent_allowlist = store,
            .now_iso = s_engine_now,
        });
        defer eval.deinit(std.testing.allocator);
        try std.testing.expect(eval.decision == .deny);
        try std.testing.expect(eval.exception_source == null);
        try std.testing.expect(eval.severity == .critical);
    }
}

test "s-engine: kind=command permanent does not FULL ALLOW different compound string" {
    // Exact-command short-circuit applies only to the full command string.
    const store = sEnginePermanentStore(&.{
        .{
            .kind = .command,
            .command = "git reset --hard HEAD",
            .reason = "exact reset only for this recovery path",
            .created_at = "2026-07-25T12:00:00Z",
            .layer = .user,
        },
    });
    var eval = try evaluateCommand(std.testing.allocator, "git reset --hard HEAD; rm -rf /", .{
        .permanent_allowlist = store,
        .now_iso = s_engine_now,
    });
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .deny);
    try std.testing.expect(eval.exception_source == null);
}

test "s-engine: kind=rule skips only that rule_id and allows matching command (non-critical)" {
    const reason = "temporary exception for force-delete of stale feature branch";
    const store = sEnginePermanentStore(&.{
        .{
            .kind = .rule,
            .id = "core.git:branch-force-delete",
            .reason = reason,
            .created_at = "2026-07-25T12:00:00Z",
            .layer = .user,
        },
    });

    var eval = try evaluateCommand(std.testing.allocator, "git branch -D feature", .{
        .permanent_allowlist = store,
        .now_iso = s_engine_now,
    });
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .allow);
    try std.testing.expectEqualStrings("allowlist", eval.exception_source.?);
    try std.testing.expectEqualStrings("user", eval.exception_layer.?);
    try std.testing.expectEqualStrings("rule", eval.exception_kind.?);
    try std.testing.expect(std.mem.indexOf(u8, eval.reason, reason) != null);
}

test "s-engine: permanent kind=rule cannot unlock critical pack hit" {
    const store = sEnginePermanentStore(&.{
        .{
            .kind = .rule,
            .id = "core.git:reset-hard",
            .reason = "critical hard fence ignores permanent rule skip",
            .created_at = "2026-07-25T12:00:00Z",
            .layer = .user,
        },
    });
    var eval = try evaluateCommand(std.testing.allocator, "git reset --hard HEAD", .{
        .permanent_allowlist = store,
        .now_iso = s_engine_now,
    });
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .deny);
    try std.testing.expect(eval.exception_source == null);
    try std.testing.expect(eval.severity == .critical);
    try std.testing.expectEqualStrings("core.git:reset-hard", eval.rule_id.?);
}

test "s-engine: E8 compound still denies when only core.git:branch-force-delete is allowlisted" {
    const store = sEnginePermanentStore(&.{
        .{
            .kind = .rule,
            .id = "core.git:branch-force-delete",
            .reason = "branch delete exception must not unlock filesystem wipe",
            .created_at = "2026-07-25T12:00:00Z",
            .layer = .project,
        },
    });

    // Multi-pack compound: skip medium git rule only; filesystem still denies.
    var compound = try evaluateCommand(std.testing.allocator, "git branch -D feature; rm -rf /", .{
        .permanent_allowlist = store,
        .now_iso = s_engine_now,
    });
    defer compound.deinit(std.testing.allocator);
    try std.testing.expect(compound.decision == .deny);
    try std.testing.expect(compound.exception_source == null);
    try std.testing.expect(compound.pack_id != null);
    try std.testing.expectEqualStrings("core.filesystem", compound.pack_id.?);
    try std.testing.expect(compound.rule_id != null);
    try std.testing.expect(std.mem.indexOf(u8, compound.rule_id.?, "rm-rf") != null);

    // Other pack alone still denies under the same rule-id allowlist.
    var other = try evaluateCommand(std.testing.allocator, "rm -rf /", .{
        .permanent_allowlist = store,
        .now_iso = s_engine_now,
    });
    defer other.deinit(std.testing.allocator);
    try std.testing.expect(other.decision == .deny);
    try std.testing.expect(other.exception_source == null);
}

test "s-engine: kind=rule is not pre-pack FULL ALLOW for unrelated destructive patterns" {
    // Allowlisting reset-hard must not suppress push --force (same pack, different rule).
    const store = sEnginePermanentStore(&.{
        .{
            .kind = .rule,
            .id = "core.git:reset-hard",
            .reason = "only reset-hard skip, not all git destructives",
            .created_at = "2026-07-25T12:00:00Z",
            .layer = .user,
        },
    });
    var eval = try evaluateCommand(std.testing.allocator, "git push --force origin main", .{
        .permanent_allowlist = store,
        .now_iso = s_engine_now,
    });
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .deny);
    try std.testing.expect(eval.rule_id != null);
    try std.testing.expectEqualStrings("core.git:push-force-long", eval.rule_id.?);
}

// ── Acceptance 2: allow-once before permanent/packs; consume flag ───────────

test "s-engine: allow-once may FULL ALLOW critical (operator break-glass); permanent cannot" {
    // Product law: permanent is hard-fenced for critical; allow-once after operator
    // redeem is the intentional single-use recovery path (help.zig / plan §4.1).
    const cmd = "git reset --hard HEAD";

    const store = sEnginePermanentStore(&.{
        .{
            .kind = .command,
            .command = cmd,
            .reason = "permanent must not unlock critical",
            .created_at = "2026-07-25T12:00:00Z",
            .layer = .user,
        },
    });
    var perm = try evaluateCommand(std.testing.allocator, cmd, .{
        .permanent_allowlist = store,
        .now_iso = s_engine_now,
    });
    defer perm.deinit(std.testing.allocator);
    try std.testing.expect(perm.decision == .deny);
    try std.testing.expect(perm.exception_source == null);
    try std.testing.expect(perm.severity == .critical);

    var tmp = try sEngineTmpRoot();
    defer {
        std.testing.allocator.free(tmp.path);
        tmp.dir.cleanup();
    }
    const pending_path = try sEngineJoin(tmp.path, allow_once_mod.pending_file_name);
    defer std.testing.allocator.free(pending_path);
    const once_path = try sEngineJoin(tmp.path, allow_once_mod.allow_once_file_name);
    defer std.testing.allocator.free(once_path);
    try sEngineSeedAllowOnce(pending_path, once_path, cmd, tmp.path, "operator redeem of critical deny");

    var once = try evaluateCommand(std.testing.allocator, cmd, .{
        .cwd = tmp.path,
        .allow_once_path = once_path,
        .io = std.testing.io,
        .consume_allow_once = false,
        .now_iso = s_engine_now,
    });
    defer once.deinit(std.testing.allocator);
    try std.testing.expect(once.decision == .allow);
    try std.testing.expectEqualStrings("allow_once", once.exception_source.?);
}

test "s-engine: allow-once exact hit allows before packs and consumes when true" {
    var tmp = try sEngineTmpRoot();
    defer {
        std.testing.allocator.free(tmp.path);
        tmp.dir.cleanup();
    }
    const pending_path = try sEngineJoin(tmp.path, allow_once_mod.pending_file_name);
    defer std.testing.allocator.free(pending_path);
    const once_path = try sEngineJoin(tmp.path, allow_once_mod.allow_once_file_name);
    defer std.testing.allocator.free(once_path);

    // Critical command: allow-once is the intentional break-glass path (see tryAllowOnce).
    const cmd = "git reset --hard HEAD";
    const cwd = "/work/project";
    const once_reason = "one-time unlock after human review of deny panel";
    try sEngineSeedAllowOnce(pending_path, once_path, cmd, cwd, once_reason);

    // First evaluate with consume=true → allow + consume.
    var first = try evaluateCommand(std.testing.allocator, cmd, .{
        .cwd = cwd,
        .allow_once_path = once_path,
        .io = std.testing.io,
        .consume_allow_once = true,
        .now_iso = s_engine_now,
    });
    defer first.deinit(std.testing.allocator);
    try std.testing.expect(first.decision == .allow);
    try std.testing.expectEqualStrings("allow_once", first.exception_source.?);
    try std.testing.expect(std.mem.indexOf(u8, first.reason, once_reason) != null);

    // Second evaluate → packs deny (single-use burned).
    var second = try evaluateCommand(std.testing.allocator, cmd, .{
        .cwd = cwd,
        .allow_once_path = once_path,
        .io = std.testing.io,
        .consume_allow_once = true,
        .now_iso = s_engine_now,
    });
    defer second.deinit(std.testing.allocator);
    try std.testing.expect(second.decision == .deny);
    try std.testing.expect(second.exception_source == null);
}

test "s-engine: allow-once AccessDenied skips store and continues packs (seatbelt residual)" {
    // Hardened Seatbelt cannot open ~/.local/share/ryk/allow_once.jsonl.
    // Must not emit allow-once-store-error critical deny for every command.
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;

    var tmp = try sEngineTmpRoot();
    defer {
        std.testing.allocator.free(tmp.path);
        tmp.dir.cleanup();
    }
    const once_path = try sEngineJoin(tmp.path, allow_once_mod.allow_once_file_name);
    defer std.testing.allocator.free(once_path);

    // Create path then deny all access so lock/open fails with AccessDenied.
    {
        const f = try std.Io.Dir.cwd().createFile(std.testing.io, once_path, .{});
        f.close(std.testing.io);
        try std.Io.Dir.cwd().setFilePermissions(
            std.testing.io,
            once_path,
            std.Io.File.Permissions.fromMode(0o000),
            .{},
        );
        // Also lock file path parent dir may still allow createFile for .lock —
        // chmod the directory write off so StoreLock.acquire fails.
        try std.Io.Dir.cwd().setFilePermissions(
            std.testing.io,
            tmp.path,
            std.Io.File.Permissions.fromMode(0o555),
            .{},
        );
    }
    defer {
        // Restore so tmp cleanup can remove.
        std.Io.Dir.cwd().setFilePermissions(
            std.testing.io,
            tmp.path,
            std.Io.File.Permissions.fromMode(0o755),
            .{},
        ) catch {};
        std.Io.Dir.cwd().setFilePermissions(
            std.testing.io,
            once_path,
            std.Io.File.Permissions.fromMode(0o644),
            .{},
        ) catch {};
    }

    // Safe command must still allow via packs (not store-error deny).
    var safe = try evaluateCommand(std.testing.allocator, "git status", .{
        .cwd = tmp.path,
        .allow_once_path = once_path,
        .io = std.testing.io,
        .now_iso = s_engine_now,
    });
    defer safe.deinit(std.testing.allocator);
    try std.testing.expect(safe.decision == .allow);
    try std.testing.expect(safe.pattern_name == null or !std.mem.eql(u8, safe.pattern_name.?, "allow-once-store-error"));

    // Dangerous command still denied by packs (not masked by store failure).
    var danger = try evaluateCommand(std.testing.allocator, "rm -rf /", .{
        .cwd = tmp.path,
        .allow_once_path = once_path,
        .io = std.testing.io,
        .now_iso = s_engine_now,
    });
    defer danger.deinit(std.testing.allocator);
    try std.testing.expect(danger.decision == .deny);
    try std.testing.expect(danger.pattern_name == null or !std.mem.eql(u8, danger.pattern_name.?, "allow-once-store-error"));
}

test "s-engine: consume_allow_once false matches without consuming (explain)" {
    var tmp = try sEngineTmpRoot();
    defer {
        std.testing.allocator.free(tmp.path);
        tmp.dir.cleanup();
    }
    const pending_path = try sEngineJoin(tmp.path, allow_once_mod.pending_file_name);
    defer std.testing.allocator.free(pending_path);
    const once_path = try sEngineJoin(tmp.path, allow_once_mod.allow_once_file_name);
    defer std.testing.allocator.free(once_path);

    const cmd = "git reset --hard HEAD";
    const cwd = "/work/project";
    const once_reason = "explain dry-run must not burn single-use exception";
    try sEngineSeedAllowOnce(pending_path, once_path, cmd, cwd, once_reason);

    // Explain path: match + attribute, leave store intact.
    var explain = try evaluateCommand(std.testing.allocator, cmd, .{
        .cwd = cwd,
        .allow_once_path = once_path,
        .io = std.testing.io,
        .consume_allow_once = false,
        .now_iso = s_engine_now,
    });
    defer explain.deinit(std.testing.allocator);
    try std.testing.expect(explain.decision == .allow);
    try std.testing.expectEqualStrings("allow_once", explain.exception_source.?);
    try std.testing.expect(std.mem.indexOf(u8, explain.reason, once_reason) != null);

    // Still available for a real consume.
    var live = try evaluateCommand(std.testing.allocator, cmd, .{
        .cwd = cwd,
        .allow_once_path = once_path,
        .io = std.testing.io,
        .consume_allow_once = true,
        .now_iso = s_engine_now,
    });
    defer live.deinit(std.testing.allocator);
    try std.testing.expect(live.decision == .allow);
    try std.testing.expectEqualStrings("allow_once", live.exception_source.?);

    // Burned after real consume.
    var burned = try evaluateCommand(std.testing.allocator, cmd, .{
        .cwd = cwd,
        .allow_once_path = once_path,
        .io = std.testing.io,
        .consume_allow_once = true,
        .now_iso = s_engine_now,
    });
    defer burned.deinit(std.testing.allocator);
    try std.testing.expect(burned.decision == .deny);
}

test "s-engine: allow-once exact hit is checked before permanent kind=rule" {
    var tmp = try sEngineTmpRoot();
    defer {
        std.testing.allocator.free(tmp.path);
        tmp.dir.cleanup();
    }
    const pending_path = try sEngineJoin(tmp.path, allow_once_mod.pending_file_name);
    defer std.testing.allocator.free(pending_path);
    const once_path = try sEngineJoin(tmp.path, allow_once_mod.allow_once_file_name);
    defer std.testing.allocator.free(once_path);

    const cmd = "git reset --hard HEAD";
    const cwd = "/work/project";
    const once_reason = "allow-once reason wins when both would allow";
    const permanent_reason = "permanent rule reason must not be the attribution source";
    try sEngineSeedAllowOnce(pending_path, once_path, cmd, cwd, once_reason);

    const store = sEnginePermanentStore(&.{
        .{
            .kind = .rule,
            .id = "core.git:reset-hard",
            .reason = permanent_reason,
            .created_at = "2026-07-25T12:00:00Z",
            .layer = .project,
        },
    });

    var eval = try evaluateCommand(std.testing.allocator, cmd, .{
        .cwd = cwd,
        .allow_once_path = once_path,
        .io = std.testing.io,
        .consume_allow_once = false,
        .permanent_allowlist = store,
        .now_iso = s_engine_now,
    });
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .allow);
    // Order proof: allow-once is source when both could allow (rule-skip path).
    try std.testing.expectEqualStrings("allow_once", eval.exception_source.?);
    try std.testing.expect(std.mem.indexOf(u8, eval.reason, once_reason) != null);
    try std.testing.expect(std.mem.indexOf(u8, eval.reason, permanent_reason) == null);
}

test "s-engine: allow-once exact hit is checked before permanent kind=command FULL ALLOW" {
    // Twin order proof for the pre-pack FULL ALLOW branch: if permanent kind=command
    // ran first, exception_source would be "allowlist" with permanent reason.
    var tmp = try sEngineTmpRoot();
    defer {
        std.testing.allocator.free(tmp.path);
        tmp.dir.cleanup();
    }
    const pending_path = try sEngineJoin(tmp.path, allow_once_mod.pending_file_name);
    defer std.testing.allocator.free(pending_path);
    const once_path = try sEngineJoin(tmp.path, allow_once_mod.allow_once_file_name);
    defer std.testing.allocator.free(once_path);

    const cmd = "git reset --hard HEAD";
    const cwd = "/work/project";
    const once_reason = "allow-once wins over permanent command short-circuit";
    const permanent_reason = "permanent command FULL ALLOW must not win the race";
    try sEngineSeedAllowOnce(pending_path, once_path, cmd, cwd, once_reason);

    const store = sEnginePermanentStore(&.{
        .{
            .kind = .command,
            .command = cmd,
            .reason = permanent_reason,
            .created_at = "2026-07-25T12:00:00Z",
            .layer = .project,
        },
    });

    var eval = try evaluateCommand(std.testing.allocator, cmd, .{
        .cwd = cwd,
        .allow_once_path = once_path,
        .io = std.testing.io,
        .consume_allow_once = false,
        .permanent_allowlist = store,
        .now_iso = s_engine_now,
    });
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .allow);
    try std.testing.expectEqualStrings("allow_once", eval.exception_source.?);
    try std.testing.expect(std.mem.indexOf(u8, eval.reason, once_reason) != null);
    try std.testing.expect(std.mem.indexOf(u8, eval.reason, permanent_reason) == null);
    // Permanent command path must not partially attribute either.
    try std.testing.expect(eval.exception_kind == null or !std.mem.eql(u8, eval.exception_kind.?, "command"));
}

test "s-engine: allow-once wrong cwd does not match" {
    var tmp = try sEngineTmpRoot();
    defer {
        std.testing.allocator.free(tmp.path);
        tmp.dir.cleanup();
    }
    const pending_path = try sEngineJoin(tmp.path, allow_once_mod.pending_file_name);
    defer std.testing.allocator.free(pending_path);
    const once_path = try sEngineJoin(tmp.path, allow_once_mod.allow_once_file_name);
    defer std.testing.allocator.free(once_path);

    const cmd = "git reset --hard HEAD";
    try sEngineSeedAllowOnce(pending_path, once_path, cmd, "/allowed/cwd", "scoped exception");

    var eval = try evaluateCommand(std.testing.allocator, cmd, .{
        .cwd = "/other/cwd",
        .allow_once_path = once_path,
        .io = std.testing.io,
        .consume_allow_once = false,
        .now_iso = s_engine_now,
    });
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .deny);
    try std.testing.expect(eval.exception_source == null);
}

// ── Acceptance 3: distinct permanent API; trace attribution ─────────────────

test "s-engine: permanent exceptions not wired via EvaluateOptions.allowlists" {
    // Permanent uses dedicated field; Layered allowlists remains a separate legacy short-circuit.
    // Use a non-critical pack hit (medium) so permanent FULL ALLOW remains valid.
    const permanent_reason = "distinct permanent API reason text for attribution";
    const cmd = "git branch -D feature";
    const store = sEnginePermanentStore(&.{
        .{
            .kind = .command,
            .command = cmd,
            .reason = permanent_reason,
            .created_at = "2026-07-25T12:00:00Z",
            .layer = .project,
        },
    });

    // Product permanent path: permanent_allowlist field only (no Layered).
    var via_permanent = try evaluateCommand(std.testing.allocator, cmd, .{
        .permanent_allowlist = store,
        .allowlists = null,
        .now_iso = s_engine_now,
    });
    defer via_permanent.deinit(std.testing.allocator);
    try std.testing.expect(via_permanent.decision == .allow);
    try std.testing.expectEqualStrings("allowlist", via_permanent.exception_source.?);
    try std.testing.expectEqualStrings("command", via_permanent.exception_kind.?);

    // Legacy Layered still works for engine unit tests (policy-style exact), but is
    // NOT the permanent store API — attribution must not claim permanent allowlist.
    const layered: allowlist.Layered = .{
        .entries = &.{
            .{ .pattern = cmd, .prefix = false },
        },
    };
    var via_layered = try evaluateCommand(std.testing.allocator, cmd, .{
        .allowlists = layered,
        .permanent_allowlist = null,
        .now_iso = s_engine_now,
    });
    defer via_layered.deinit(std.testing.allocator);
    try std.testing.expect(via_layered.decision == .allow);
    // Legacy Layered short-circuit must not claim permanent exception attribution.
    try std.testing.expect(via_layered.exception_source == null);
    try std.testing.expect(via_layered.exception_layer == null);
    try std.testing.expect(via_layered.exception_kind == null);

    // Prefix Layered still works; permanent command is exact-only (covered elsewhere).
    const layered_prefix: allowlist.Layered = .{
        .entries = &.{
            .{ .pattern = "npm run ", .prefix = true },
        },
    };
    var prefix_hit = try evaluateCommand(std.testing.allocator, "npm run test", .{
        .allowlists = layered_prefix,
    });
    defer prefix_hit.deinit(std.testing.allocator);
    try std.testing.expect(prefix_hit.decision == .allow);
}

test "s-engine: EvaluateOptions defaults leave permanent and allow-once disabled" {
    // Default options must not invent permanent/allow-once allows; packs still deny.
    const opts = EvaluateOptions{};
    try std.testing.expect(opts.consume_allow_once == true);
    try std.testing.expect(opts.permanent_allowlist == null);
    try std.testing.expect(opts.allow_once_path == null);
    try std.testing.expect(opts.io == null);
    try std.testing.expect(opts.now_iso == null);

    var eval = try evaluateCommand(std.testing.allocator, "git reset --hard", opts);
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .deny);
    try std.testing.expect(eval.exception_source == null);
}

test "s-engine: trace attributes source layer kind reason on permanent allow" {
    const reason = "trace must record permanent allowlist source layer kind reason";
    const cmd = "git branch -D feature";
    const store = sEnginePermanentStore(&.{
        .{
            .kind = .command,
            .command = cmd,
            .reason = reason,
            .created_at = "2026-07-25T12:00:00Z",
            .layer = .project,
        },
    });

    var collector = TraceCollector.init(std.testing.allocator);
    defer collector.deinit();
    var eval = try evaluateCommand(std.testing.allocator, cmd, .{
        .permanent_allowlist = store,
        .now_iso = s_engine_now,
        .trace = &collector,
    });
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .allow);
    try std.testing.expectEqualStrings("allowlist", eval.exception_source.?);
    try std.testing.expectEqualStrings("project", eval.exception_layer.?);
    try std.testing.expectEqualStrings("command", eval.exception_kind.?);
    try std.testing.expect(std.mem.indexOf(u8, eval.reason, reason) != null);

    // Trace step detail must embed source / layer / kind / exact entry reason text.
    // Do not accept a hollow keyword "reason" without the entry's reason string.
    try std.testing.expect(eval.trace.len >= 1);
    var found_attr = false;
    for (eval.trace) |step| {
        const d = step.detail orelse continue;
        const has_source = std.mem.indexOf(u8, d, "allowlist") != null;
        const has_layer = std.mem.indexOf(u8, d, "project") != null;
        const has_kind = std.mem.indexOf(u8, d, "command") != null;
        const has_reason = std.mem.indexOf(u8, d, reason) != null;
        if (has_source and has_layer and has_kind and has_reason) {
            found_attr = true;
            break;
        }
    }
    try std.testing.expect(found_attr);
}

test "s-engine: trace attributes allow_once source and reason" {
    var tmp = try sEngineTmpRoot();
    defer {
        std.testing.allocator.free(tmp.path);
        tmp.dir.cleanup();
    }
    const pending_path = try sEngineJoin(tmp.path, allow_once_mod.pending_file_name);
    defer std.testing.allocator.free(pending_path);
    const once_path = try sEngineJoin(tmp.path, allow_once_mod.allow_once_file_name);
    defer std.testing.allocator.free(once_path);

    const cmd = "git reset --hard HEAD";
    const cwd = "/work/project";
    const once_reason = "allow-once trace attribution reason text";
    try sEngineSeedAllowOnce(pending_path, once_path, cmd, cwd, once_reason);

    var collector = TraceCollector.init(std.testing.allocator);
    defer collector.deinit();
    var eval = try evaluateCommand(std.testing.allocator, cmd, .{
        .cwd = cwd,
        .allow_once_path = once_path,
        .io = std.testing.io,
        .consume_allow_once = false,
        .now_iso = s_engine_now,
        .trace = &collector,
    });
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .allow);
    try std.testing.expectEqualStrings("allow_once", eval.exception_source.?);
    try std.testing.expect(std.mem.indexOf(u8, eval.reason, once_reason) != null);

    try std.testing.expect(eval.trace.len >= 1);
    var found = false;
    for (eval.trace) |step| {
        const d = step.detail orelse continue;
        // Exact entry reason required — hollow "reason" keyword alone is not enough.
        if (std.mem.indexOf(u8, d, "allow_once") != null and
            std.mem.indexOf(u8, d, once_reason) != null)
        {
            found = true;
            break;
        }
    }
    try std.testing.expect(found);
}

test "s-engine: permanent kind=command does not match prefix-looking longer command" {
    // Permanent path is exact-only (no Entry.prefix). Use a canonical stored command
    // (no outer whitespace) so evaluate's trim + store match stay greenable.
    // Trailing-space stored values are store-level (s2-store) only — evaluate always
    // trims input, so a positive arm on "npm run " cannot hit after trim.
    const exact_cmd = "npm run build";
    const reason = "exact npm run build exception only";
    const store = sEnginePermanentStore(&.{
        .{
            .kind = .command,
            .command = exact_cmd,
            .reason = reason,
            .created_at = "2026-07-25T12:00:00Z",
            .layer = .user,
        },
    });

    // Longer / sibling command must not receive permanent attribution (anti-prefix).
    var longer = try evaluateCommand(std.testing.allocator, "npm run build --production", .{
        .permanent_allowlist = store,
        .now_iso = s_engine_now,
    });
    defer longer.deinit(std.testing.allocator);
    try std.testing.expect(longer.exception_source == null or
        !std.mem.eql(u8, longer.exception_source.?, "allowlist"));

    // Canonical exact command FULL ALLOWs with permanent attribution.
    var exact = try evaluateCommand(std.testing.allocator, exact_cmd, .{
        .permanent_allowlist = store,
        .now_iso = s_engine_now,
    });
    defer exact.deinit(std.testing.allocator);
    try std.testing.expect(exact.decision == .allow);
    try std.testing.expectEqualStrings("allowlist", exact.exception_source.?);
    try std.testing.expectEqualStrings("command", exact.exception_kind.?);
    try std.testing.expect(std.mem.indexOf(u8, exact.reason, reason) != null);
}

test "s-engine: expired permanent kind=command is ignored (no FULL ALLOW)" {
    const store = sEnginePermanentStore(&.{
        .{
            .kind = .command,
            .command = "git reset --hard HEAD",
            .reason = "expired permanent must not allow",
            .created_at = "2026-07-20T12:00:00Z",
            .expires_at = "2026-07-24T00:00:00Z",
            .layer = .user,
        },
    });
    var eval = try evaluateCommand(std.testing.allocator, "git reset --hard HEAD", .{
        .permanent_allowlist = store,
        .now_iso = s_engine_now, // after expires_at
    });
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .deny);
    try std.testing.expect(eval.exception_source == null);
}

test "s-engine: expired permanent kind=rule is ignored (not added to skip list)" {
    // Expired rule must not enter skipped_rule_ids; pack deny still fires.
    // Medium rule so the unexpired path can still allow (critical cannot).
    const store = sEnginePermanentStore(&.{
        .{
            .kind = .rule,
            .id = "core.git:branch-force-delete",
            .reason = "expired rule skip must not unlock branch delete",
            .created_at = "2026-07-20T12:00:00Z",
            .expires_at = "2026-07-24T00:00:00Z",
            .layer = .project,
        },
    });
    var eval = try evaluateCommand(std.testing.allocator, "git branch -D feature", .{
        .permanent_allowlist = store,
        .now_iso = s_engine_now, // after expires_at
    });
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .deny);
    try std.testing.expect(eval.exception_source == null);

    // Same entry not yet expired → still allows via rule skip.
    var live = try evaluateCommand(std.testing.allocator, "git branch -D feature", .{
        .permanent_allowlist = store,
        .now_iso = "2026-07-23T00:00:00Z", // before expires_at
    });
    defer live.deinit(std.testing.allocator);
    try std.testing.expect(live.decision == .allow);
    try std.testing.expectEqualStrings("allowlist", live.exception_source.?);
    try std.testing.expectEqualStrings("rule", live.exception_kind.?);
}

test "s-engine: unexpired permanent with far-future expiry still allows" {
    // Uses s_engine_future as expires_at so the non-expired path is pinned.
    // Medium pack hit (critical permanent FULL ALLOW is hard-fenced).
    const cmd = "git branch -D feature";
    const store = sEnginePermanentStore(&.{
        .{
            .kind = .command,
            .command = cmd,
            .reason = "far-future expiry must still FULL ALLOW",
            .created_at = "2026-07-25T12:00:00Z",
            .expires_at = s_engine_future,
            .layer = .project,
        },
    });
    var eval = try evaluateCommand(std.testing.allocator, cmd, .{
        .permanent_allowlist = store,
        .now_iso = s_engine_now,
    });
    defer eval.deinit(std.testing.allocator);
    try std.testing.expect(eval.decision == .allow);
    try std.testing.expectEqualStrings("allowlist", eval.exception_source.?);
    try std.testing.expectEqualStrings("command", eval.exception_kind.?);
}

test "s-engine: multiple permanent kind=rule ids all skip (not first-only)" {
    // Evaluate must collect every non-expired non-critical kind=rule into skip list.
    // Skipping only the first store entry would leave branch-force-delete denying.
    const store = sEnginePermanentStore(&.{
        .{
            .kind = .rule,
            .id = "core.git:stash-drop",
            .reason = "first rule skip stash drop pattern",
            .created_at = "2026-07-25T12:00:00Z",
            .layer = .user,
        },
        .{
            .kind = .rule,
            .id = "core.git:branch-force-delete",
            .reason = "second rule skip must also apply at evaluate",
            .created_at = "2026-07-25T12:00:00Z",
            .layer = .user,
        },
    });

    // Needs the second skip (branch-force-delete) — proves multi-id skip list build.
    var branch = try evaluateCommand(std.testing.allocator, "git branch -D feature", .{
        .permanent_allowlist = store,
        .now_iso = s_engine_now,
    });
    defer branch.deinit(std.testing.allocator);
    try std.testing.expect(branch.decision == .allow);
    try std.testing.expectEqualStrings("allowlist", branch.exception_source.?);
    try std.testing.expectEqualStrings("rule", branch.exception_kind.?);

    // Unrelated pack still denies under multi-rule permanent store (E8).
    var disk = try evaluateCommand(std.testing.allocator, "mkfs.ext4 /dev/sda1", .{
        .permanent_allowlist = store,
        .now_iso = s_engine_now,
    });
    defer disk.deinit(std.testing.allocator);
    try std.testing.expect(disk.decision == .deny);
    try std.testing.expect(disk.exception_source == null);
    try std.testing.expectEqualStrings("system.disk", disk.pack_id.?);
}

test {
    _ = allowlist;
    _ = registry;
    _ = segments;
    _ = normalize;
    _ = sanitize;
    _ = @import("corpus_test.zig");
    _ = @import("regex_pcre.zig");
    _ = @import("suggestions.zig");
    // Pull store unit tests into shell-engine monopath (s-engine ownership).
    _ = @import("allowlist_store.zig");
    _ = @import("allow_once.zig");
}

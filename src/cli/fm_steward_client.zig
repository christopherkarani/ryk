//! Mac FM steward subprocess client (classify-response-v1).
//!
//! Invokes `fm-steward classify --card <tempfile> --timeout-ms N --json` via the
//! existing StewardSession CLI path. Fail-open: timeout / missing binary / parse
//! error / non-macOS / `RYK_FM_STEWARD=0` → continue + fallback=true.
//! Swift package: https://github.com/christopherkarani/ryk-fm-steward
//! Contract pin: macos/fm-steward/Schemas + Fixtures.
//!
//! Transport: subprocess MVP only (no UDS serve). Do not call residual Classifier.

const std = @import("std");
const builtin = @import("builtin");
const env_util = @import("../env_util.zig");

/// Product default wall/backend budget (StewardSession.defaultTimeoutMs).
pub const default_timeout_ms: u32 = 3000;

pub const ClassifyVerdict = enum {
    continue_,
    ask,
    ask_sticky_candidate,

    pub fn fromWire(s: []const u8) ?ClassifyVerdict {
        if (std.mem.eql(u8, s, "continue")) return .continue_;
        if (std.mem.eql(u8, s, "ask")) return .ask;
        if (std.mem.eql(u8, s, "ask_sticky_candidate")) return .ask_sticky_candidate;
        return null;
    }

    pub fn toWire(self: ClassifyVerdict) []const u8 {
        return switch (self) {
            .continue_ => "continue",
            .ask => "ask",
            .ask_sticky_candidate => "ask_sticky_candidate",
        };
    }
};

/// Parsed classify-response-v1 (owned string fields when `owned` is true).
pub const ClassifyResult = struct {
    verdict: ClassifyVerdict,
    why: []const u8,
    explain: ?[]const u8 = null,
    suggested_sticky_scope: ?[]const u8 = null,
    suggested_effect_class: ?[]const u8 = null,
    timed_out: bool,
    fallback: bool,
    model_available: bool,
    latency_ms: ?i64 = null,
    /// When true, `deinit` frees string fields. Static fail-open results set false.
    owned: bool = true,

    pub fn deinit(self: *ClassifyResult, allocator: std.mem.Allocator) void {
        if (!self.owned) {
            self.* = undefined;
            return;
        }
        allocator.free(self.why);
        if (self.explain) |e| allocator.free(e);
        if (self.suggested_sticky_scope) |s| allocator.free(s);
        if (self.suggested_effect_class) |s| allocator.free(s);
        self.* = undefined;
    }
};

/// Wire JSON for classify-response-v1 (parse intermediate).
const WireResponse = struct {
    schema_version: i64,
    verdict: []const u8,
    why: []const u8,
    explain: ?[]const u8 = null,
    suggested_sticky_scope: ?[]const u8 = null,
    suggested_effect_class: ?[]const u8 = null,
    timed_out: bool,
    fallback: bool,
    model_available: bool,
    latency_ms: ?i64 = null,
};

pub const ParseError = error{
    InvalidJson,
    UnsupportedSchemaVersion,
    InvalidVerdict,
    MissingRequiredField,
    OutOfMemory,
};

/// Parse classify-response-v1 JSON. Caller owns returned strings (`owned=true`).
pub fn parseClassifyResponse(allocator: std.mem.Allocator, json: []const u8) ParseError!ClassifyResult {
    var parsed = std.json.parseFromSlice(WireResponse, allocator, json, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidJson,
    };
    defer parsed.deinit();

    const wire = parsed.value;
    if (wire.schema_version != 1) return error.UnsupportedSchemaVersion;

    const verdict = ClassifyVerdict.fromWire(wire.verdict) orelse return error.InvalidVerdict;

    const why = allocator.dupe(u8, wire.why) catch return error.OutOfMemory;
    errdefer allocator.free(why);

    const explain = try dupeOptional(allocator, wire.explain);
    errdefer if (explain) |e| allocator.free(e);

    const sticky = try dupeOptional(allocator, wire.suggested_sticky_scope);
    errdefer if (sticky) |s| allocator.free(s);

    const effect = try dupeOptional(allocator, wire.suggested_effect_class);
    errdefer if (effect) |s| allocator.free(s);

    return .{
        .verdict = verdict,
        .why = why,
        .explain = explain,
        .suggested_sticky_scope = sticky,
        .suggested_effect_class = effect,
        .timed_out = wire.timed_out,
        .fallback = wire.fallback,
        .model_available = wire.model_available,
        .latency_ms = wire.latency_ms,
        .owned = true,
    };
}

fn dupeOptional(allocator: std.mem.Allocator, value: ?[]const u8) ParseError!?[]const u8 {
    if (value) |v| {
        return allocator.dupe(u8, v) catch return error.OutOfMemory;
    }
    return null;
}

/// Static fail-open continue (no heap ownership).
pub fn fallbackContinue(why: []const u8, timed_out: bool) ClassifyResult {
    return .{
        .verdict = .continue_,
        .why = why,
        .explain = null,
        .suggested_sticky_scope = null,
        .suggested_effect_class = null,
        .timed_out = timed_out,
        .fallback = true,
        .model_available = false,
        .latency_ms = null,
        .owned = false,
    };
}

/// True when FM steward should be invoked (macOS and kill-switch not set).
pub fn isEnabled() bool {
    if (builtin.os.tag != .macos) return false;
    // RYK_FM_STEWARD only (hard-cut).
    if (env_util.getenvBrand("FM_STEWARD")) |raw| {
        const v = std.mem.span(raw);
        if (std.mem.eql(u8, v, "0")) return false;
    }
    return true;
}

/// Resolve fm-steward binary path. Caller frees.
/// Product order: `RYK_FM_STEWARD_BIN` (if set) → `"fm-steward"` on PATH.
/// Never resolves cwd-relative `.build/` candidates (those are developer-local only).
pub fn resolveBinary(allocator: std.mem.Allocator) ![]const u8 {
    if (env_util.getenvBrand("FM_STEWARD_BIN")) |raw| {
        return try allocator.dupe(u8, std.mem.span(raw));
    }
    return try allocator.dupe(u8, "fm-steward");
}

/// Optional inject hooks for unit tests.
pub const ClassifyOptions = struct {
    timeout_ms: u32 = default_timeout_ms,
    /// Force binary path (skip resolve). Used by tests / inject.
    binary_path: ?[]const u8 = null,
    /// When set, called instead of real subprocess (tests).
    spawn_fn: ?*const fn (
        allocator: std.mem.Allocator,
        argv: []const []const u8,
        timeout_ms: u32,
    ) anyerror!SpawnCapture = null,
    /// When true, skip platform/env gate (tests for subprocess path only).
    force_enabled: bool = false,
};

pub const SpawnCapture = struct {
    stdout: []u8,
    exit_code: u8,
    timed_out: bool,

    pub fn deinit(self: *SpawnCapture, allocator: std.mem.Allocator) void {
        allocator.free(self.stdout);
        self.* = undefined;
    }
};

/// Classify risk-card JSON via fm-steward. Always fail-open (never errors for product paths).
pub fn classify(allocator: std.mem.Allocator, card_json: []const u8) ClassifyResult {
    return classifyWithOptions(allocator, card_json, .{});
}

pub fn classifyWithOptions(
    allocator: std.mem.Allocator,
    card_json: []const u8,
    options: ClassifyOptions,
) ClassifyResult {
    if (!options.force_enabled and !isEnabled()) {
        return fallbackContinue("fm_steward_disabled_or_unsupported", false);
    }

    const timeout_ms = if (options.timeout_ms == 0) default_timeout_ms else options.timeout_ms;

    const binary = if (options.binary_path) |p|
        allocator.dupe(u8, p) catch return fallbackContinue("fm_steward_oom", false)
    else
        resolveBinary(allocator) catch return fallbackContinue("fm_steward_resolve_failed", false);
    defer allocator.free(binary);

    const card_path = writeCardTemp(allocator, card_json) catch
        return fallbackContinue("fm_steward_temp_write_failed", false);
    defer {
        deleteCardTemp(allocator, card_path);
        allocator.free(card_path);
    }

    var timeout_buf: [16]u8 = undefined;
    const timeout_str = std.fmt.bufPrint(&timeout_buf, "{d}", .{timeout_ms}) catch
        return fallbackContinue("fm_steward_timeout_format_failed", false);

    const argv = [_][]const u8{
        binary,
        "classify",
        "--card",
        card_path,
        "--timeout-ms",
        timeout_str,
        "--json",
    };

    var capture: SpawnCapture = if (options.spawn_fn) |spawn_fn|
        spawn_fn(allocator, &argv, timeout_ms) catch
            return fallbackContinue("fm_steward_spawn_failed", false)
    else
        runClassifyCapture(allocator, &argv, timeout_ms) catch
            return fallbackContinue("fm_steward_spawn_failed", false);
    defer capture.deinit(allocator);

    if (capture.timed_out) {
        return fallbackContinue("fm_steward_timed_out", true);
    }
    if (capture.exit_code != 0) {
        return fallbackContinue("fm_steward_nonzero_exit", false);
    }

    const trimmed = std.mem.trim(u8, capture.stdout, " \t\r\n");
    if (trimmed.len == 0) {
        return fallbackContinue("fm_steward_empty_stdout", false);
    }

    return parseClassifyResponse(allocator, trimmed) catch
        fallbackContinue("fm_steward_parse_error", false);
}

/// Injectable client surface for shell_eval choke-point tests.
pub const ClassifyFn = *const fn (
    ctx: ?*anyopaque,
    allocator: std.mem.Allocator,
    card_json: []const u8,
    timeout_ms: u32,
) ClassifyResult;

pub const Client = struct {
    ctx: ?*anyopaque = null,
    classify_fn: ClassifyFn,

    pub fn classify(
        self: Client,
        allocator: std.mem.Allocator,
        card_json: []const u8,
        timeout_ms: u32,
    ) ClassifyResult {
        return self.classify_fn(self.ctx, allocator, card_json, timeout_ms);
    }
};

fn productionClassifyFn(
    _: ?*anyopaque,
    allocator: std.mem.Allocator,
    card_json: []const u8,
    timeout_ms: u32,
) ClassifyResult {
    return classifyWithOptions(allocator, card_json, .{ .timeout_ms = timeout_ms });
}

fn continueStubClassifyFn(
    _: ?*anyopaque,
    _: std.mem.Allocator,
    _: []const u8,
    _: u32,
) ClassifyResult {
    return fallbackContinue("fm_steward_stub_continue", false);
}

/// Real macOS production client (or continue stub on non-macOS).
pub fn defaultClient() Client {
    if (builtin.os.tag == .macos) {
        return .{ .classify_fn = productionClassifyFn };
    }
    return .{ .classify_fn = continueStubClassifyFn };
}

/// Always-continue client for tests / Linux product path.
pub fn continueStubClient() Client {
    return .{ .classify_fn = continueStubClassifyFn };
}

// ---------------------------------------------------------------------------
// Subprocess helpers (stdout-capturing; local to this file)
// ---------------------------------------------------------------------------

var card_temp_seq: std.atomic.Value(u32) = .init(0);

/// Max exclusive-create attempts when a predicted temp name already exists.
const card_temp_max_attempts: u32 = 16;

fn writeCardTemp(allocator: std.mem.Allocator, card_json: []const u8) ![]const u8 {
    var threaded = std.Io.Threaded.init(allocator, .{
        .environ = env_util.processEnviron(),
    });
    defer threaded.deinit();
    const io = threaded.io();

    const tmp_root = blk: {
        if (std.c.getenv("TMPDIR")) |t| break :blk std.mem.span(t);
        if (std.c.getenv("TMP")) |t| break :blk std.mem.span(t);
        break :blk "/tmp";
    };

    const pid = std.c.getpid();
    // Private card file: owner read/write only (0o600). O_EXCL so we never
    // open/truncate a pre-owned path (e.g. world-readable collision).
    const perms: std.Io.File.Permissions = @enumFromInt(0o600);

    var attempt: u32 = 0;
    while (attempt < card_temp_max_attempts) : (attempt += 1) {
        const seq = card_temp_seq.fetchAdd(1, .monotonic);
        const path = try std.fmt.allocPrint(
            allocator,
            "{s}/ryk-fm-card-{d}-{d}.json",
            .{ tmp_root, pid, seq },
        );
        errdefer allocator.free(path);

        const file = std.Io.Dir.createFileAbsolute(io, path, .{
            .read = true,
            .exclusive = true,
            .permissions = perms,
        }) catch |err| switch (err) {
            error.PathAlreadyExists => {
                allocator.free(path);
                continue;
            },
            else => return err,
        };
        // Exclusive create owned this path; delete on write failure so we do not
        // orphan an empty/partial 0o600 card in TMPDIR.
        errdefer deleteCardTemp(allocator, path);
        defer file.close(io);
        try file.writeStreamingAll(io, card_json);
        return path;
    }
    return error.PathAlreadyExists;
}

fn deleteCardTemp(allocator: std.mem.Allocator, path: []const u8) void {
    var threaded = std.Io.Threaded.init(allocator, .{
        .environ = env_util.processEnviron(),
    });
    defer threaded.deinit();
    const io = threaded.io();
    std.Io.Dir.deleteFileAbsolute(io, path) catch {};
}

fn runClassifyCapture(
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    timeout_ms: u32,
) !SpawnCapture {
    var threaded = std.Io.Threaded.init(allocator, .{
        .environ = env_util.processEnviron(),
    });
    defer threaded.deinit();
    const io = threaded.io();

    const timeout_ns: u64 = @as(u64, timeout_ms) * std.time.ns_per_ms;
    const run_result = std.process.run(allocator, io, .{
        .argv = argv,
        .stdout_limit = .limited(256 * 1024),
        .stderr_limit = .limited(64 * 1024),
        .timeout = .{ .duration = .{
            .raw = .fromNanoseconds(@intCast(timeout_ns)),
            .clock = .awake,
        } },
    }) catch |err| switch (err) {
        error.Timeout => {
            // Hang residual is owned by std.process.run timeout kill (no custom
            // spawn/wait path here). No stdout ownership to free from this catch.
            return SpawnCapture{
                .stdout = try allocator.dupe(u8, ""),
                .exit_code = 255,
                .timed_out = true,
            };
        },
        else => return err,
    };
    errdefer {
        allocator.free(run_result.stdout);
        allocator.free(run_result.stderr);
    }
    allocator.free(run_result.stderr);

    const exit_code: u8 = switch (run_result.term) {
        .exited => |code| @intCast(@min(code, 255)),
        else => 255,
    };

    return .{
        .stdout = run_result.stdout,
        .exit_code = exit_code,
        .timed_out = false,
    };
}

// ---------------------------------------------------------------------------
// Tests (TDD seams: parseClassifyResponse, classify with fake / skip)
// ---------------------------------------------------------------------------

test "fm_steward default_timeout_ms is 3000 not 500" {
    try std.testing.expectEqual(@as(u32, 3000), default_timeout_ms);
}

test "fm_steward parseClassifyResponse continue" {
    const json =
        \\{"schema_version":1,"verdict":"continue","why":"safe shell","explain":null,"suggested_sticky_scope":null,"suggested_effect_class":null,"timed_out":false,"fallback":false,"model_available":false}
    ;
    var result = try parseClassifyResponse(std.testing.allocator, json);
    defer result.deinit(std.testing.allocator);
    try std.testing.expectEqual(ClassifyVerdict.continue_, result.verdict);
    try std.testing.expectEqualStrings("safe shell", result.why);
    try std.testing.expect(result.explain == null);
    try std.testing.expect(!result.timed_out);
    try std.testing.expect(!result.fallback);
    try std.testing.expect(!result.model_available);
}

test "fm_steward parseClassifyResponse ask with explain" {
    const json =
        \\{"schema_version":1,"verdict":"ask","why":"pipe to shell","explain":"curl piped to bash is risky","suggested_sticky_scope":null,"suggested_effect_class":null,"timed_out":false,"fallback":false,"model_available":true,"latency_ms":12}
    ;
    var result = try parseClassifyResponse(std.testing.allocator, json);
    defer result.deinit(std.testing.allocator);
    try std.testing.expectEqual(ClassifyVerdict.ask, result.verdict);
    try std.testing.expectEqualStrings("pipe to shell", result.why);
    try std.testing.expectEqualStrings("curl piped to bash is risky", result.explain.?);
    try std.testing.expect(result.model_available);
}

test "fm_steward parseClassifyResponse ask_sticky_candidate" {
    const json =
        \\{"schema_version":1,"verdict":"ask_sticky_candidate","why":"repeat pattern","explain":"allow npm test this session?","suggested_sticky_scope":"session","suggested_effect_class":"package_install","timed_out":false,"fallback":false,"model_available":true}
    ;
    var result = try parseClassifyResponse(std.testing.allocator, json);
    defer result.deinit(std.testing.allocator);
    try std.testing.expectEqual(ClassifyVerdict.ask_sticky_candidate, result.verdict);
    try std.testing.expectEqualStrings("session", result.suggested_sticky_scope.?);
    try std.testing.expectEqualStrings("package_install", result.suggested_effect_class.?);
}

test "fm_steward parseClassifyResponse rejects bad verdict and schema" {
    try std.testing.expectError(
        error.InvalidVerdict,
        parseClassifyResponse(std.testing.allocator,
            \\{"schema_version":1,"verdict":"deny","why":"x","timed_out":false,"fallback":false,"model_available":false}
        ),
    );
    try std.testing.expectError(
        error.UnsupportedSchemaVersion,
        parseClassifyResponse(std.testing.allocator,
            \\{"schema_version":2,"verdict":"continue","why":"x","timed_out":false,"fallback":false,"model_available":false}
        ),
    );
    try std.testing.expectError(
        error.InvalidJson,
        parseClassifyResponse(std.testing.allocator, "not-json"),
    );
}

test "fm_steward parseClassifyResponse ignores unknown fields" {
    const json =
        \\{"schema_version":1,"verdict":"continue","why":"ok","timed_out":false,"fallback":false,"model_available":false,"future_flag":true}
    ;
    var result = try parseClassifyResponse(std.testing.allocator, json);
    defer result.deinit(std.testing.allocator);
    try std.testing.expectEqual(ClassifyVerdict.continue_, result.verdict);
}

test "fm_steward classify RYK_FM_STEWARD=0 is fail-open continue" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const previous = std.c.getenv("RYK_FM_STEWARD");
    defer restoreEnv("RYK_FM_STEWARD", previous);
    try std.testing.expectEqual(@as(c_int, 0), setenv("RYK_FM_STEWARD", "0", 1));

    try std.testing.expect(!isEnabled());

    var result = classify(std.testing.allocator, "{\"schema_version\":1}");
    defer result.deinit(std.testing.allocator);
    try std.testing.expectEqual(ClassifyVerdict.continue_, result.verdict);
    try std.testing.expect(result.fallback);
    try std.testing.expect(!result.timed_out);
}

test "fm_steward injectable Client classify_fn is invoked" {
    const Ctx = struct {
        calls: u32 = 0,
        last_timeout: u32 = 0,

        fn classifyFn(ctx: ?*anyopaque, _: std.mem.Allocator, _: []const u8, timeout_ms: u32) ClassifyResult {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.calls += 1;
            self.last_timeout = timeout_ms;
            return .{
                .verdict = .ask,
                .why = "injected",
                .explain = "from fake client",
                .timed_out = false,
                .fallback = false,
                .model_available = true,
                .owned = false,
            };
        }
    };
    var ctx = Ctx{};
    const client = Client{ .ctx = &ctx, .classify_fn = Ctx.classifyFn };
    var result = client.classify(std.testing.allocator, "{}", 3000);
    defer result.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u32, 1), ctx.calls);
    try std.testing.expectEqual(@as(u32, 3000), ctx.last_timeout);
    try std.testing.expectEqual(ClassifyVerdict.ask, result.verdict);
    try std.testing.expectEqualStrings("from fake client", result.explain.?);
}

test "fm_steward classify missing binary fails open continue+fallback" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    // Ensure kill-switch is not disabling the path so we exercise spawn failure.
    const previous = std.c.getenv("RYK_FM_STEWARD");
    defer restoreEnv("RYK_FM_STEWARD", previous);
    _ = unsetenv("RYK_FM_STEWARD");

    var result = classifyWithOptions(std.testing.allocator, "{\"schema_version\":1}", .{
        .timeout_ms = 500,
        .binary_path = "/nonexistent/ryk-fm-steward-missing-bin",
        .force_enabled = true,
    });
    defer result.deinit(std.testing.allocator);
    try std.testing.expectEqual(ClassifyVerdict.continue_, result.verdict);
    try std.testing.expect(result.fallback);
}

test "fm_steward classify injectable spawn returns parseable ask" {
    const Fake = struct {
        fn spawn(allocator: std.mem.Allocator, argv: []const []const u8, _: u32) anyerror!SpawnCapture {
            try std.testing.expect(argv.len >= 2);
            try std.testing.expectEqualStrings("classify", argv[1]);
            const body =
                \\{"schema_version":1,"verdict":"ask","why":"hard danger","explain":"curl|sh","timed_out":false,"fallback":false,"model_available":false}
            ;
            return .{
                .stdout = try allocator.dupe(u8, body),
                .exit_code = 0,
                .timed_out = false,
            };
        }
    };

    var result = classifyWithOptions(std.testing.allocator, "{}", .{
        .force_enabled = true,
        .binary_path = "fm-steward",
        .spawn_fn = Fake.spawn,
    });
    defer result.deinit(std.testing.allocator);
    try std.testing.expectEqual(ClassifyVerdict.ask, result.verdict);
    try std.testing.expectEqualStrings("curl|sh", result.explain.?);
    try std.testing.expect(!result.fallback);
}

test "fm_steward classify injectable spawn timeout fails open" {
    const Fake = struct {
        fn spawn(allocator: std.mem.Allocator, _: []const []const u8, _: u32) anyerror!SpawnCapture {
            return .{
                .stdout = try allocator.dupe(u8, ""),
                .exit_code = 255,
                .timed_out = true,
            };
        }
    };

    var result = classifyWithOptions(std.testing.allocator, "{}", .{
        .force_enabled = true,
        .binary_path = "fm-steward",
        .spawn_fn = Fake.spawn,
    });
    defer result.deinit(std.testing.allocator);
    try std.testing.expectEqual(ClassifyVerdict.continue_, result.verdict);
    try std.testing.expect(result.fallback);
    try std.testing.expect(result.timed_out);
}

test "fm_steward classify injectable spawn bad json fails open" {
    const Fake = struct {
        fn spawn(allocator: std.mem.Allocator, _: []const []const u8, _: u32) anyerror!SpawnCapture {
            return .{
                .stdout = try allocator.dupe(u8, "{not-valid"),
                .exit_code = 0,
                .timed_out = false,
            };
        }
    };

    var result = classifyWithOptions(std.testing.allocator, "{}", .{
        .force_enabled = true,
        .binary_path = "fm-steward",
        .spawn_fn = Fake.spawn,
    });
    defer result.deinit(std.testing.allocator);
    try std.testing.expectEqual(ClassifyVerdict.continue_, result.verdict);
    try std.testing.expect(result.fallback);
}

test "fm_steward defaultClient non-macOS path is continue stub shape" {
    // On macOS this uses production fn; on Linux/other, continue stub.
    // Shape check: client.classify is callable and returns a deinit-safe result
    // when stubbed.
    const client = continueStubClient();
    var result = client.classify(std.testing.allocator, "{}", default_timeout_ms);
    defer result.deinit(std.testing.allocator);
    try std.testing.expectEqual(ClassifyVerdict.continue_, result.verdict);
    try std.testing.expect(result.fallback);
}

test "fm_steward ClassifyVerdict wire round-trip" {
    try std.testing.expectEqualStrings("continue", ClassifyVerdict.continue_.toWire());
    try std.testing.expectEqualStrings("ask", ClassifyVerdict.ask.toWire());
    try std.testing.expectEqualStrings("ask_sticky_candidate", ClassifyVerdict.ask_sticky_candidate.toWire());
    try std.testing.expect(ClassifyVerdict.fromWire("deny") == null);
}

test "fm_steward resolveBinary without RYK_FM_STEWARD_BIN is PATH name not cwd .build" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const previous = std.c.getenv("RYK_FM_STEWARD_BIN");
    defer restoreEnv("RYK_FM_STEWARD_BIN", previous);
    _ = unsetenv("RYK_FM_STEWARD_BIN");

    const path = try resolveBinary(std.testing.allocator);
    defer std.testing.allocator.free(path);

    // Product resolve: PATH name only — never cwd-relative macos/fm-steward/.build/*.
    try std.testing.expectEqualStrings("fm-steward", path);
    try std.testing.expect(std.mem.indexOf(u8, path, "macos/fm-steward/.build/") == null);
    try std.testing.expect(std.mem.indexOf(u8, path, ".build/") == null);
}

test "fm_steward resolveBinary honors RYK_FM_STEWARD_BIN plant path" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const previous = std.c.getenv("RYK_FM_STEWARD_BIN");
    defer restoreEnv("RYK_FM_STEWARD_BIN", previous);
    try std.testing.expectEqual(@as(c_int, 0), setenv("RYK_FM_STEWARD_BIN", "/planted/ryk-fm-steward-bin", 1));

    const path = try resolveBinary(std.testing.allocator);
    defer std.testing.allocator.free(path);
    try std.testing.expectEqualStrings("/planted/ryk-fm-steward-bin", path);
}

test "fm_steward writeCardTemp exclusive skips pre-owned world-readable path" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .environ = env_util.processEnviron(),
    });
    defer threaded.deinit();
    const io = threaded.io();

    const tmp_root = blk: {
        if (std.c.getenv("TMPDIR")) |t| break :blk std.mem.span(t);
        if (std.c.getenv("TMP")) |t| break :blk std.mem.span(t);
        break :blk "/tmp";
    };
    const pid = std.c.getpid();

    // Plant a world-readable poison file at the next predicted seq path so an
    // exclusive create must either retry a new name or fail — never truncate it.
    const next_seq = card_temp_seq.load(.monotonic);
    const poison_path = try std.fmt.allocPrint(
        allocator,
        "{s}/ryk-fm-card-{d}-{d}.json",
        .{ tmp_root, pid, next_seq },
    );
    defer allocator.free(poison_path);

    const poison_body = "POISON_PREOWNED_WORLD_READABLE";
    {
        const poison_perms: std.Io.File.Permissions = @enumFromInt(0o644);
        const poison = try std.Io.Dir.createFileAbsolute(io, poison_path, .{
            .read = true,
            .exclusive = true,
            .permissions = poison_perms,
        });
        defer poison.close(io);
        try poison.writeStreamingAll(io, poison_body);
    }
    defer std.Io.Dir.deleteFileAbsolute(io, poison_path) catch {};

    const card = "{\"schema_version\":1,\"marker\":\"ours\"}";
    const path = try writeCardTemp(allocator, card);
    defer {
        deleteCardTemp(allocator, path);
        allocator.free(path);
    }

    // Must not reuse the pre-owned path (would mean open/truncate without O_EXCL).
    try std.testing.expect(!std.mem.eql(u8, path, poison_path));

    // Poison file content must be intact (never written into).
    const poison_got = try std.Io.Dir.cwd().readFileAlloc(io, poison_path, allocator, .limited(4096));
    defer allocator.free(poison_got);
    try std.testing.expectEqualStrings(poison_body, poison_got);

    // Fresh exclusive card holds our payload.
    const card_got = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(4096));
    defer allocator.free(card_got);
    try std.testing.expectEqualStrings(card, card_got);
}

// --- env helpers for tests ---

extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;
extern "c" fn unsetenv(name: [*:0]const u8) c_int;

fn restoreEnv(name: [*:0]const u8, previous: ?[*:0]const u8) void {
    if (previous) |value| {
        _ = setenv(name, value, 1);
    } else {
        _ = unsetenv(name);
    }
}

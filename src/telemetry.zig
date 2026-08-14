const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const env_scrub = @import("sandbox/env_scrub.zig");
const host_launch = @import("cli/host_launch.zig");
const exit_codes = @import("cli/exit_codes.zig");
const contract = @import("telemetry_contract.zig");
const product = @import("telemetry_product.zig");
const store = @import("telemetry_store.zig");
const transport = @import("telemetry_transport.zig");

pub const event_name = contract.event_name;
pub const schema_version = contract.schema_version;
pub const posthog_batch_endpoint = contract.posthog_batch_endpoint;
pub const max_queue_events = contract.max_queue_events;

pub const FeedbackStatus = enum { accepted, disabled, unavailable };

const StateSource = store.StateSource;
const State = store.State;
const LoadedState = store.LoadedState;
const Invocation = contract.Invocation;
const classifyInvocation = contract.classifyInvocation;
const validInvocation = contract.validInvocation;
const validCommand = contract.validCommand;
const validOutcome = contract.validOutcome;
const validQueuedEvent = contract.validQueuedEvent;
const validTimestamp = contract.validTimestamp;
const validInstallationId = contract.validInstallationId;
const renderEvent = contract.renderEvent;
const renderSummary = contract.renderSummary;
const renderState = store.renderState;
const parseState = store.parseState;
const generateInstallationId = contract.generateInstallationId;
const appendEvent = store.appendEvent;
const ensureInstallationId = store.ensureInstallationId;
const queueCount = store.queueCount;
const posthogProxyBypassed = transport.posthogProxyBypassed;

const max_pending_summary_records = 48;
const max_pending_product_records = 8;
const max_batch_args = 3 + 4 + 6 * max_pending_summary_records * 11 + max_pending_product_records * 7;

const PendingProductEvent = union(enum) {
    activation: []const u8,
    setup_completed: []const u8,
    setup_failed: []const u8,
    feedback_submitted: []const u8,
    update_completed: struct {
        channel: []const u8,
        from_version: [64]u8,
        from_len: u8,
        to_version: [64]u8,
        to_len: u8,
        verification: []const u8,
    },
    update_failed: struct { channel: []const u8, stage: []const u8 },
};

const PendingSummaries = struct {
    fm: [max_pending_summary_records]contract.FmSummary = undefined,
    fm_len: usize = 0,
    enforcement: [max_pending_summary_records]contract.EnforcementSummary = undefined,
    enforcement_len: usize = 0,
    integration: [max_pending_summary_records]contract.IntegrationSummary = undefined,
    integration_len: usize = 0,
    session: [max_pending_summary_records]contract.SessionSummary = undefined,
    session_len: usize = 0,
    feature: [max_pending_summary_records]contract.FeatureSummary = undefined,
    feature_len: usize = 0,
    reliability: [max_pending_summary_records]contract.ReliabilitySummary = undefined,
    reliability_len: usize = 0,
    product: [max_pending_product_records]PendingProductEvent = undefined,
    product_len: usize = 0,

    fn addFm(self: *PendingSummaries, value: contract.FmSummary) void {
        for (self.fm[0..self.fm_len]) |*existing| {
            if (std.mem.eql(u8, existing.host, value.host) and std.mem.eql(u8, existing.source, value.source) and
                std.mem.eql(u8, existing.verdict, value.verdict) and std.mem.eql(u8, existing.status, value.status) and
                existing.model_available == value.model_available and existing.timed_out == value.timed_out and
                existing.upgraded == value.upgraded and std.mem.eql(u8, existing.latency_bucket, value.latency_bucket))
            {
                addCount(&existing.count, value.count);
                return;
            }
        }
        if (self.fm_len < max_pending_summary_records) {
            self.fm[self.fm_len] = value;
            self.fm_len += 1;
        }
    }

    fn addEnforcement(self: *PendingSummaries, value: contract.EnforcementSummary) void {
        for (self.enforcement[0..self.enforcement_len]) |*existing| {
            if (std.mem.eql(u8, existing.host, value.host) and std.mem.eql(u8, existing.source, value.source) and
                std.mem.eql(u8, existing.decision, value.decision) and std.mem.eql(u8, existing.risk, value.risk) and
                std.mem.eql(u8, existing.effect, value.effect) and std.mem.eql(u8, existing.mode, value.mode))
            {
                addCount(&existing.count, value.count);
                return;
            }
        }
        if (self.enforcement_len < max_pending_summary_records) {
            self.enforcement[self.enforcement_len] = value;
            self.enforcement_len += 1;
        }
    }

    fn addIntegration(self: *PendingSummaries, value: contract.IntegrationSummary) void {
        for (self.integration[0..self.integration_len]) |*existing| {
            if (std.mem.eql(u8, existing.host, value.host) and std.mem.eql(u8, existing.operation, value.operation) and
                std.mem.eql(u8, existing.result, value.result))
            {
                addCount(&existing.count, value.count);
                return;
            }
        }
        if (self.integration_len < max_pending_summary_records) {
            self.integration[self.integration_len] = value;
            self.integration_len += 1;
        }
    }

    fn addSession(self: *PendingSummaries, value: contract.SessionSummary) void {
        for (self.session[0..self.session_len]) |*existing| {
            if (std.mem.eql(u8, existing.host, value.host) and std.mem.eql(u8, existing.event_type, value.event_type) and
                std.mem.eql(u8, existing.result, value.result))
            {
                addCount(&existing.count, value.count);
                return;
            }
        }
        if (self.session_len < max_pending_summary_records) {
            self.session[self.session_len] = value;
            self.session_len += 1;
        }
    }

    fn addFeature(self: *PendingSummaries, value: contract.FeatureSummary) void {
        for (self.feature[0..self.feature_len]) |*existing| {
            if (std.mem.eql(u8, existing.feature, value.feature) and std.mem.eql(u8, existing.operation, value.operation) and
                std.mem.eql(u8, existing.result, value.result))
            {
                addCount(&existing.count, value.count);
                return;
            }
        }
        if (self.feature_len < max_pending_summary_records) {
            self.feature[self.feature_len] = value;
            self.feature_len += 1;
        }
    }

    fn addReliability(self: *PendingSummaries, value: contract.ReliabilitySummary) void {
        for (self.reliability[0..self.reliability_len]) |*existing| {
            if (std.mem.eql(u8, existing.operation, value.operation) and std.mem.eql(u8, existing.failure, value.failure) and
                std.mem.eql(u8, existing.source, value.source))
            {
                addCount(&existing.count, value.count);
                return;
            }
        }
        if (self.reliability_len < max_pending_summary_records) {
            self.reliability[self.reliability_len] = value;
            self.reliability_len += 1;
        }
    }

    fn addProduct(self: *PendingSummaries, value: product.Event) void {
        if (self.product_len >= max_pending_product_records) return;
        const pending: PendingProductEvent = switch (value) {
            .activation => |event| .{ .activation = event.host },
            .setup_completed => |event| .{ .setup_completed = event.mode },
            .setup_failed => |event| .{ .setup_failed = event.mode },
            .feedback_submitted => |event| .{ .feedback_submitted = event.category },
            .update_completed => |event| blk: {
                var from_version: [64]u8 = undefined;
                var to_version: [64]u8 = undefined;
                const from_len = copyVersion(&from_version, event.from_version) orelse return;
                const to_len = copyVersion(&to_version, event.to_version) orelse return;
                break :blk .{ .update_completed = .{
                    .channel = event.channel,
                    .from_version = from_version,
                    .from_len = from_len,
                    .to_version = to_version,
                    .to_len = to_len,
                    .verification = event.verification,
                } };
            },
            .update_failed => |event| .{ .update_failed = .{ .channel = event.channel, .stage = event.stage } },
        };
        self.product[self.product_len] = pending;
        self.product_len += 1;
    }
};

fn copyVersion(destination: *[64]u8, value: []const u8) ?u8 {
    if (value.len == 0 or value.len > destination.len) return null;
    @memcpy(destination[0..value.len], value);
    return @intCast(value.len);
}

var pending_summaries = PendingSummaries{};

fn addCount(target: *u32, value: u32) void {
    target.* = if (value > contract.max_summary_count -| target.*)
        contract.max_summary_count
    else
        target.* + value;
}

fn takePendingSummaries() PendingSummaries {
    const result = pending_summaries;
    pending_summaries = .{};
    return result;
}

const InternalOperation = enum { flush, send };

const StatusView = struct {
    enabled: bool,
    configured: bool,
    source: StateSource,
    queued_events: usize,
    installation_id_present: bool,
};

/// Record a fixed, privacy-reviewed command event. This is deliberately best effort:
/// telemetry allocation, local state, and child-process failures must never alter the
/// command's output or exit code.
pub fn recordInvocation(
    io: std.Io,
    environ_map: *const std.process.Environ.Map,
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    exit_code: u8,
) void {
    recordInvocationInner(io, environ_map, allocator, argv, exit_code) catch {};
}

/// Record FM metadata in process memory. The eventual worker receives only the
/// fixed buckets below; the FM card, explanation, command, cwd, and session id
/// never enter telemetry.
pub fn recordFmDecision(
    source: []const u8,
    host: ?[]const u8,
    verdict: []const u8,
    fallback: bool,
    timed_out: bool,
    model_available: bool,
    latency_ms: ?i64,
    upgraded: bool,
) void {
    if (!transportConfigured()) return;
    const safe_verdict = if (std.mem.eql(u8, verdict, "continue")) "continue" else if (std.mem.eql(u8, verdict, "ask"))
        "ask"
    else if (std.mem.eql(u8, verdict, "ask_sticky_candidate"))
        "ask_sticky_candidate"
    else
        "continue";
    const status = if (timed_out) "timeout" else if (fallback) "fallback" else if (model_available) "model" else "no_model";
    pending_summaries.addFm(.{
        .host = contract.sanitizeHost(host),
        .source = contract.sanitizeSource(source),
        .verdict = safe_verdict,
        .status = status,
        .model_available = model_available,
        .timed_out = timed_out,
        .upgraded = upgraded,
        .latency_bucket = contract.latencyBucket(latency_ms),
        .count = 1,
    });
}

/// Record the final product enforcement classification at a decision boundary.
/// `effect` and `mode` are reduced to closed vocabularies before storage.
pub fn recordEnforcement(
    source: []const u8,
    host: ?[]const u8,
    decision: []const u8,
    risk: []const u8,
    effect: ?[]const u8,
    mode: ?[]const u8,
) void {
    if (!transportConfigured()) return;
    pending_summaries.addEnforcement(.{
        .host = contract.sanitizeHost(host),
        .source = contract.sanitizeSource(source),
        .decision = normalizeDecision(decision),
        .risk = normalizeRisk(risk),
        .effect = normalizeEffect(effect),
        .mode = normalizeMode(mode),
        .count = 1,
    });
}

/// Record a closed reliability class without projecting the underlying error text.
pub fn recordReliability(operation: []const u8, failure: []const u8, source: []const u8) void {
    if (!transportConfigured()) return;
    const safe_operation = if (std.mem.eql(u8, operation, "hook")) "hook" else if (std.mem.eql(u8, operation, "evaluate"))
        "evaluate"
    else if (std.mem.eql(u8, operation, "run"))
        "run"
    else if (std.mem.eql(u8, operation, "cli"))
        "cli"
    else if (std.mem.eql(u8, operation, "fm_steward"))
        "fm_steward"
    else
        "cli";
    const safe_failure = if (std.mem.eql(u8, failure, "usage")) "usage" else if (std.mem.eql(u8, failure, "evaluator_error"))
        "evaluator_error"
    else if (std.mem.eql(u8, failure, "protocol_error"))
        "protocol_error"
    else if (std.mem.eql(u8, failure, "timeout"))
        "timeout"
    else if (std.mem.eql(u8, failure, "policy_load"))
        "policy_load"
    else if (std.mem.eql(u8, failure, "hook_failure"))
        "hook_failure"
    else if (std.mem.eql(u8, failure, "command_failure"))
        "command_failure"
    else
        "other";
    pending_summaries.addReliability(.{
        .operation = safe_operation,
        .failure = safe_failure,
        .source = contract.sanitizeSource(source),
        .count = 1,
    });
}

pub fn recordIntegration(host: ?[]const u8, operation: []const u8, result: []const u8) void {
    if (!transportConfigured()) return;
    const safe_operation = if (std.mem.eql(u8, operation, "install")) "install" else if (std.mem.eql(u8, operation, "verify"))
        "verify"
    else if (std.mem.eql(u8, operation, "inspect"))
        "inspect"
    else if (std.mem.eql(u8, operation, "repair"))
        "repair"
    else if (std.mem.eql(u8, operation, "onboard"))
        "onboard"
    else if (std.mem.eql(u8, operation, "remove"))
        "remove"
    else
        "other";
    const safe_result = if (std.mem.eql(u8, result, "success")) "success" else if (std.mem.eql(u8, result, "blocked")) "blocked" else if (std.mem.eql(u8, result, "failure")) "failure" else if (std.mem.eql(u8, result, "usage")) "usage" else if (std.mem.eql(u8, result, "deferred")) "deferred" else "failure";
    pending_summaries.addIntegration(.{
        .host = contract.sanitizeHost(host),
        .operation = safe_operation,
        .result = safe_result,
        .count = 1,
    });
}

/// Record a hook lifecycle result at the host adapter boundary. The top-level
/// argv classifier remains a fallback for pre-evaluation exits, while normal
/// hook responses use this authoritative decision rather than process exit
/// codes (Claude-compatible hosts can return exit 0 for a blocked response).
pub fn recordSession(host: ?[]const u8, event_type: []const u8, result: []const u8) void {
    if (!transportConfigured()) return;
    const safe_result = if (std.mem.eql(u8, result, "blocked")) "blocked" else if (std.mem.eql(u8, result, "failure")) "failure" else "success";
    pending_summaries.addSession(.{
        .host = contract.sanitizeHost(host),
        .event_type = contract.sessionEventType(event_type) orelse "other",
        .result = safe_result,
        .count = 1,
    });
}

/// Record the first successful protected run candidate. The worker makes the
/// persistent once-only decision while holding the telemetry store lock.
pub fn recordActivation(host: ?[]const u8) void {
    if (!transportConfigured()) return;
    pending_summaries.addProduct(.{ .activation = .{ .host = product.sanitizeHost(host) } });
}

pub fn recordSetupCompleted(auto_mode: bool) void {
    if (!transportConfigured()) return;
    pending_summaries.addProduct(.{ .setup_completed = .{ .mode = if (auto_mode) "auto" else "interactive" } });
}

pub fn recordSetupFailed(auto_mode: bool) void {
    if (!transportConfigured()) return;
    pending_summaries.addProduct(.{ .setup_failed = .{ .mode = if (auto_mode) "auto" else "interactive" } });
}

pub fn recordFeedback(
    io: std.Io,
    environ_map: *const std.process.Environ.Map,
    allocator: std.mem.Allocator,
    category: []const u8,
) FeedbackStatus {
    if (!transportConfigured() or hardDisabled(environ_map)) return .disabled;
    var loaded = loadEffectiveState(allocator, io, environ_map) catch return .unavailable;
    defer loaded.deinit(allocator);
    if (!loaded.state.enabled) return .disabled;
    if (product.sanitizeFeedbackCategory(category)) |safe_category| {
        pending_summaries.addProduct(.{ .feedback_submitted = .{ .category = safe_category } });
        return .accepted;
    }
    return .unavailable;
}

pub fn recordUpdateCompleted(channel: []const u8, from_version: []const u8, to_version: []const u8, verification: []const u8) void {
    if (!transportConfigured()) return;
    var from_buffer: [32]u8 = undefined;
    var to_buffer: [32]u8 = undefined;
    const safe_from = product.canonicalVersion(from_version, &from_buffer) orelse return;
    const safe_to = product.canonicalVersion(to_version, &to_buffer) orelse return;
    pending_summaries.addProduct(.{ .update_completed = .{
        .channel = product.sanitizeChannel(channel),
        .from_version = safe_from,
        .to_version = safe_to,
        .verification = product.sanitizeVerification(verification),
    } });
}

pub fn recordUpdateFailed(channel: []const u8, stage: []const u8) void {
    if (!transportConfigured()) return;
    pending_summaries.addProduct(.{ .update_failed = .{
        .channel = product.sanitizeChannel(channel),
        .stage = product.sanitizeUpdateStage(stage),
    } });
}

fn normalizeDecision(value: []const u8) []const u8 {
    if (std.mem.eql(u8, value, "allow")) return "allow";
    if (std.mem.eql(u8, value, "observe") or std.mem.eql(u8, value, "warn") or
        std.mem.eql(u8, value, "context_only")) return "observe";
    if (std.mem.eql(u8, value, "ask")) return "ask";
    if (std.mem.eql(u8, value, "deny") or std.mem.eql(u8, value, "block") or
        std.mem.eql(u8, value, "redact") or std.mem.eql(u8, value, "stage") or
        std.mem.eql(u8, value, "broker")) return "deny";
    return "error";
}

fn normalizeRisk(value: []const u8) []const u8 {
    if (std.mem.eql(u8, value, "low")) return "low";
    if (std.mem.eql(u8, value, "medium")) return "medium";
    if (std.mem.eql(u8, value, "high")) return "high";
    if (std.mem.eql(u8, value, "critical")) return "critical";
    return "unknown";
}

fn normalizeEffect(value: ?[]const u8) []const u8 {
    const candidate = value orelse return "other";
    if (std.mem.eql(u8, candidate, "shell") or std.mem.eql(u8, candidate, "command")) return "shell";
    if (std.mem.eql(u8, candidate, "file_read") or std.mem.eql(u8, candidate, "file.read")) return "file_read";
    if (std.mem.eql(u8, candidate, "file_write") or std.mem.eql(u8, candidate, "file.write")) return "file_write";
    if (std.mem.eql(u8, candidate, "network")) return "network";
    if (std.mem.eql(u8, candidate, "tool")) return "tool";
    if (std.mem.eql(u8, candidate, "prompt")) return "prompt";
    if (std.mem.eql(u8, candidate, "environment") or std.mem.eql(u8, candidate, "env")) return "environment";
    return "other";
}

fn normalizeMode(value: ?[]const u8) []const u8 {
    const candidate = value orelse return "unknown";
    if (std.mem.eql(u8, candidate, "observe")) return "observe";
    if (std.mem.eql(u8, candidate, "ask")) return "ask";
    if (std.mem.eql(u8, candidate, "yolo")) return "yolo";
    if (std.mem.eql(u8, candidate, "strict")) return "strict";
    if (std.mem.eql(u8, candidate, "ci")) return "ci";
    if (std.mem.eql(u8, candidate, "redteam")) return "redteam";
    if (std.mem.eql(u8, candidate, "trusted")) return "trusted";
    return "unknown";
}

pub fn command(
    io: std.Io,
    environ_map: *const std.process.Environ.Map,
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    if (argv.len > 0 and std.mem.eql(u8, argv[0], "--summary")) {
        if (!internalWorkerEnabled(environ_map)) {
            try stderr.writeAll("ryk telemetry: unsupported option. Run 'ryk help telemetry'.\n");
            return exit_codes.usage;
        }
        return summaryWorker(io, environ_map, allocator, argv);
    }
    if (argv.len > 0 and std.mem.eql(u8, argv[0], "--record")) {
        if (!internalWorkerEnabled(environ_map)) {
            try stderr.writeAll("ryk telemetry: unsupported option. Run 'ryk help telemetry'.\n");
            return exit_codes.usage;
        }
        return recordWorker(io, environ_map, allocator, argv);
    }
    if (argv.len > 0 and std.mem.eql(u8, argv[0], "--batch")) {
        if (!internalWorkerEnabled(environ_map)) {
            try stderr.writeAll("ryk telemetry: unsupported option. Run 'ryk help telemetry'.\n");
            return exit_codes.usage;
        }
        return batchWorker(io, environ_map, allocator, argv);
    }

    var operation: ?[]const u8 = null;
    var internal_operation: ?InternalOperation = null;
    var json = false;
    for (argv) |arg| {
        if (std.mem.eql(u8, arg, "--json")) {
            json = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--flush") or std.mem.eql(u8, arg, "--send")) {
            if (!internalWorkerEnabled(environ_map)) {
                try stderr.writeAll("ryk telemetry: unsupported option. Run 'ryk help telemetry'.\n");
                return exit_codes.usage;
            }
            const requested: InternalOperation = if (std.mem.eql(u8, arg, "--flush")) .flush else .send;
            if (internal_operation != null) {
                try stderr.writeAll("ryk telemetry: unsupported option. Run 'ryk help telemetry'.\n");
                return exit_codes.usage;
            }
            internal_operation = requested;
            continue;
        }
        if (std.mem.startsWith(u8, arg, "-")) {
            try stderr.writeAll("ryk telemetry: unsupported option. Run 'ryk help telemetry'.\n");
            return exit_codes.usage;
        }
        if (operation != null) {
            try stderr.writeAll("ryk telemetry: expected one operation. Run 'ryk help telemetry'.\n");
            return exit_codes.usage;
        }
        operation = arg;
    }

    if (internal_operation != null and (json or operation != null)) {
        try stderr.writeAll("ryk telemetry: unsupported option. Run 'ryk help telemetry'.\n");
        return exit_codes.usage;
    }
    if (internal_operation) |internal| {
        return switch (internal) {
            .flush => flush(io, environ_map, allocator),
            .send => send(io, environ_map, allocator),
        };
    }

    const op = operation orelse "status";
    if (std.mem.eql(u8, op, "status")) {
        return writeStatus(io, environ_map, allocator, stdout, stderr, json);
    }
    if (std.mem.eql(u8, op, "enable") or std.mem.eql(u8, op, "disable")) {
        const enabled = std.mem.eql(u8, op, "enable");
        if (enabled and hardDisabled(environ_map)) {
            if (json) {
                try stdout.print("{{\"schema_version\":1,\"ok\":false,\"operation\":\"{s}\"}}\n", .{op});
            } else {
                try stderr.writeAll("ryk telemetry: disabled by RYK_NO_TELEMETRY=1.\n");
            }
            return exit_codes.general;
        }
        setEnabled(io, environ_map, allocator, enabled) catch |err| {
            if (json) {
                try stdout.print("{{\"schema_version\":1,\"ok\":false,\"operation\":\"{s}\"}}\n", .{op});
            } else {
                try stderr.print("ryk telemetry: could not change state ({s}).\n", .{@errorName(err)});
            }
            return exit_codes.general;
        };
        if (json) {
            try stdout.print("{{\"schema_version\":1,\"ok\":true,\"enabled\":{s}}}\n", .{if (enabled) "true" else "false"});
        } else {
            try stdout.print("Telemetry is now {s}.\n", .{if (enabled) "enabled" else "disabled"});
        }
        return exit_codes.success;
    }

    try stderr.writeAll("ryk telemetry: expected status, enable, or disable. Run 'ryk help telemetry'.\n");
    return exit_codes.usage;
}

fn recordInvocationInner(
    io: std.Io,
    environ_map: *const std.process.Environ.Map,
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    exit_code: u8,
) !void {
    if (isHookHotPath(argv)) return;
    var summaries = takePendingSummaries();
    if (internalWorkerEnabled(environ_map)) return;
    if (contract.classifyFeatureInvocation(argv, exit_code)) |summary| summaries.addFeature(summary);
    if (summaries.session_len == 0) {
        if (contract.classifySessionInvocation(argv, exit_code)) |summary| summaries.addSession(summary);
    }
    if (contract.classifyIntegrationInvocation(argv, exit_code)) |summary| summaries.addIntegration(summary);
    if (contract.classifyReliabilityInvocation(argv, exit_code)) |summary| summaries.addReliability(summary);

    const invocation = classifyInvocation(argv, exit_code);
    if (!transportConfigured() or hardDisabled(environ_map)) return;

    spawnBatch(io, environ_map, allocator, invocation, summaries) catch {};
}

fn isHookHotPath(argv: []const []const u8) bool {
    if (argv.len == 0) return true;
    return std.mem.eql(u8, argv[0], "hook");
}

fn recordWorker(
    io: std.Io,
    environ_map: *const std.process.Environ.Map,
    allocator: std.mem.Allocator,
    argv: []const []const u8,
) u8 {
    if (argv.len != 4 or !std.mem.eql(u8, argv[0], "--record")) return exit_codes.success;
    if (!internalWorkerEnabled(environ_map)) return exit_codes.success;
    if (!transportConfigured() or hardDisabled(environ_map)) return exit_codes.success;

    const invocation = Invocation{ .command = argv[1], .host = argv[2], .outcome = argv[3] };
    if (!validInvocation(invocation)) return exit_codes.success;

    const installation_id = ensureInstallationId(io, environ_map, allocator) catch return exit_codes.success;
    defer allocator.free(installation_id);
    const event = renderEvent(allocator, io, installation_id, invocation) catch return exit_codes.success;
    defer allocator.free(event);
    appendEvent(io, environ_map, allocator, event) catch return exit_codes.success;
    _ = flush(io, environ_map, allocator);
    return exit_codes.success;
}

fn summaryWorker(
    io: std.Io,
    environ_map: *const std.process.Environ.Map,
    allocator: std.mem.Allocator,
    argv: []const []const u8,
) u8 {
    if (!transportConfigured() or hardDisabled(environ_map) or argv.len < 2) return exit_codes.success;
    const summary = parseSummaryArgs(argv) catch return exit_codes.success;
    const installation_id = ensureInstallationId(io, environ_map, allocator) catch return exit_codes.success;
    defer allocator.free(installation_id);
    const event = renderSummary(allocator, io, installation_id, summary) catch return exit_codes.success;
    defer allocator.free(event);
    appendEvent(io, environ_map, allocator, event) catch return exit_codes.success;
    _ = flush(io, environ_map, allocator);
    return exit_codes.success;
}

fn parseSummaryArgs(argv: []const []const u8) !contract.Summary {
    if (argv.len < 2 or !std.mem.eql(u8, argv[0], "--summary")) return error.InvalidTelemetrySummary;
    const kind = argv[1];
    if (std.mem.eql(u8, kind, "fm")) {
        if (argv.len != 11) return error.InvalidTelemetrySummary;
        return .{ .fm = .{
            .host = argv[2],
            .source = argv[3],
            .verdict = argv[4],
            .status = argv[5],
            .model_available = try parseBool(argv[6]),
            .timed_out = try parseBool(argv[7]),
            .upgraded = try parseBool(argv[8]),
            .latency_bucket = argv[9],
            .count = try parseSummaryCount(argv[10]),
        } };
    }
    if (std.mem.eql(u8, kind, "enforcement")) {
        if (argv.len != 9) return error.InvalidTelemetrySummary;
        return .{ .enforcement = .{
            .host = argv[2],
            .source = argv[3],
            .decision = argv[4],
            .risk = argv[5],
            .effect = argv[6],
            .mode = argv[7],
            .count = try parseSummaryCount(argv[8]),
        } };
    }
    if (std.mem.eql(u8, kind, "integration")) {
        if (argv.len != 6) return error.InvalidTelemetrySummary;
        return .{ .integration = .{
            .host = argv[2],
            .operation = argv[3],
            .result = argv[4],
            .count = try parseSummaryCount(argv[5]),
        } };
    }
    if (std.mem.eql(u8, kind, "session")) {
        if (argv.len != 6) return error.InvalidTelemetrySummary;
        return .{ .session = .{
            .host = argv[2],
            .event_type = argv[3],
            .result = argv[4],
            .count = try parseSummaryCount(argv[5]),
        } };
    }
    if (std.mem.eql(u8, kind, "feature")) {
        if (argv.len != 6) return error.InvalidTelemetrySummary;
        return .{ .feature = .{
            .feature = argv[2],
            .operation = argv[3],
            .result = argv[4],
            .count = try parseSummaryCount(argv[5]),
        } };
    }
    if (std.mem.eql(u8, kind, "reliability")) {
        if (argv.len != 6) return error.InvalidTelemetrySummary;
        return .{ .reliability = .{
            .operation = argv[2],
            .failure = argv[3],
            .source = argv[4],
            .count = try parseSummaryCount(argv[5]),
        } };
    }
    return error.InvalidTelemetrySummary;
}

fn parseBool(value: []const u8) !bool {
    if (std.mem.eql(u8, value, "1")) return true;
    if (std.mem.eql(u8, value, "0")) return false;
    return error.InvalidTelemetrySummary;
}

fn parseSummaryCount(value: []const u8) !u32 {
    const parsed = std.fmt.parseInt(u32, value, 10) catch return error.InvalidTelemetrySummary;
    if (parsed == 0 or parsed > contract.max_summary_count) return error.InvalidTelemetrySummary;
    return parsed;
}

fn flush(io: std.Io, environ_map: *const std.process.Environ.Map, allocator: std.mem.Allocator) u8 {
    if (!transportConfigured() or hardDisabled(environ_map)) return exit_codes.success;
    const executable = std.process.executablePathAlloc(io, allocator) catch return exit_codes.success;
    defer allocator.free(executable);
    const child_argv = [_][]const u8{ executable, "telemetry", "--send" };
    var child_environ = workerEnvironment(allocator, environ_map) catch return exit_codes.success;
    defer child_environ.deinit();
    child_environ.put("RYK_TELEMETRY_INTERNAL", "1") catch return exit_codes.success;
    const result = std.process.run(allocator, io, .{
        .argv = &child_argv,
        .environ_map = &child_environ,
        .stdout_limit = .limited(0),
        .stderr_limit = .limited(0),
        .timeout = .{ .duration = .{ .raw = .fromNanoseconds(2 * std.time.ns_per_s), .clock = .awake } },
    }) catch return exit_codes.success;
    defer {
        allocator.free(result.stdout);
        allocator.free(result.stderr);
    }
    return exit_codes.success;
}

fn send(io: std.Io, environ_map: *const std.process.Environ.Map, allocator: std.mem.Allocator) u8 {
    if (!transportConfigured() or hardDisabled(environ_map)) return exit_codes.success;
    transport.sendQueued(io, environ_map, allocator) catch {};
    return exit_codes.success;
}

fn setEnabled(
    io: std.Io,
    environ_map: *const std.process.Environ.Map,
    allocator: std.mem.Allocator,
    enabled: bool,
) !void {
    return store.setEnabled(io, environ_map, allocator, enabled, transportConfigured());
}

fn writeStatus(
    io: std.Io,
    environ_map: *const std.process.Environ.Map,
    allocator: std.mem.Allocator,
    stdout: anytype,
    stderr: anytype,
    json: bool,
) !u8 {
    const view = statusView(io, environ_map, allocator) catch |err| {
        if (json) {
            try stdout.writeAll(
                "{\"schema_version\":1,\"enabled\":false,\"configured\":false," ++
                    "\"source\":\"unavailable\",\"queued_events\":0,\"installation_id_present\":false}\n",
            );
        } else {
            try stderr.print(
                "ryk telemetry: state unavailable ({s}); telemetry is disabled for this process.\n",
                .{@errorName(err)},
            );
        }
        return exit_codes.general;
    };
    if (json) {
        try stdout.print(
            "{{\"schema_version\":1,\"enabled\":{s},\"configured\":{s}," ++
                "\"source\":\"{s}\",\"queued_events\":{d},\"installation_id_present\":{s}}}\n",
            .{
                if (view.enabled) "true" else "false",
                if (view.configured) "true" else "false",
                @tagName(view.source),
                view.queued_events,
                if (view.installation_id_present) "true" else "false",
            },
        );
    } else {
        try stdout.print("Telemetry: {s}\n", .{if (view.enabled) "enabled" else "disabled"});
        try stdout.print("Transport: {s}\n", .{if (view.configured) "PostHog US Cloud" else "disabled in this build"});
        try stdout.print("Queued events: {d}\n", .{view.queued_events});
        try stdout.writeAll("Change with: ryk telemetry enable | ryk telemetry disable\n");
    }
    return exit_codes.success;
}

fn statusView(
    io: std.Io,
    environ_map: *const std.process.Environ.Map,
    allocator: std.mem.Allocator,
) !StatusView {
    var loaded = try loadEffectiveState(allocator, io, environ_map);
    defer loaded.deinit(allocator);
    const queued_events = try queueCount(allocator, io, environ_map);
    return .{
        .enabled = loaded.state.enabled,
        .configured = transportConfigured(),
        .source = loaded.source,
        .queued_events = queued_events,
        .installation_id_present = loaded.state.installation_id != null,
    };
}

fn loadEffectiveState(
    allocator: std.mem.Allocator,
    io: std.Io,
    environ_map: *const std.process.Environ.Map,
) !LoadedState {
    if (hardDisabled(environ_map)) return .{ .state = .{ .enabled = false }, .source = .environment };
    const paths = (try store.resolvePaths(allocator, environ_map)) orelse return error.NoConfigDirectory;
    defer {
        var owned_paths = paths;
        owned_paths.deinit(allocator);
    }
    return store.readState(allocator, io, &paths);
}

fn hardDisabled(environ_map: *const std.process.Environ.Map) bool {
    return std.mem.eql(u8, environ_map.get("RYK_NO_TELEMETRY") orelse "", "1");
}

fn internalWorkerEnabled(environ_map: *const std.process.Environ.Map) bool {
    return std.mem.eql(u8, environ_map.get("RYK_TELEMETRY_INTERNAL") orelse "", "1");
}

const worker_environment_keys = [_][]const u8{
    "HOME",
    "USERPROFILE",
    "XDG_CONFIG_HOME",
    "RYK_NO_TELEMETRY",
    "http_proxy",
    "HTTP_PROXY",
    "https_proxy",
    "HTTPS_PROXY",
    "all_proxy",
    "ALL_PROXY",
    "no_proxy",
    "NO_PROXY",
};

fn workerEnvironment(
    allocator: std.mem.Allocator,
    environ_map: *const std.process.Environ.Map,
) !std.process.Environ.Map {
    var result = std.process.Environ.Map.init(allocator);
    errdefer result.deinit();

    for (worker_environment_keys) |key| {
        const value = environ_map.get(key) orelse continue;
        if (env_scrub.isProxyEnvKey(key)) {
            if (try env_scrub.stripProxyUrlUserinfo(allocator, value)) |sanitized| {
                defer allocator.free(sanitized);
                try result.put(key, sanitized);
                continue;
            }
        }
        try result.put(key, value);
    }
    return result;
}

fn transportConfigured() bool {
    std.mem.doNotOptimizeAway(contract.transport_marker);
    return build_options.posthog_project_token.len != 0;
}

fn appendInvocationPayload(
    io: std.Io,
    environ_map: *const std.process.Environ.Map,
    allocator: std.mem.Allocator,
    installation_id: []const u8,
    invocation: Invocation,
) !void {
    const event = try renderEvent(allocator, io, installation_id, invocation);
    defer allocator.free(event);
    try appendEvent(io, environ_map, allocator, event);
}

fn appendSummaryPayload(
    io: std.Io,
    environ_map: *const std.process.Environ.Map,
    allocator: std.mem.Allocator,
    installation_id: []const u8,
    summary: contract.Summary,
) !void {
    const event = try renderSummary(allocator, io, installation_id, summary);
    defer allocator.free(event);
    try appendEvent(io, environ_map, allocator, event);
}

fn productEventFromPending(value: *const PendingProductEvent) product.Event {
    return switch (value.*) {
        .activation => |host| .{ .activation = .{ .host = host } },
        .setup_completed => |mode| .{ .setup_completed = .{ .mode = mode } },
        .setup_failed => |mode| .{ .setup_failed = .{ .mode = mode } },
        .feedback_submitted => |category| .{ .feedback_submitted = .{ .category = category } },
        .update_completed => .{ .update_completed = .{
            .channel = value.update_completed.channel,
            .from_version = value.update_completed.from_version[0..value.update_completed.from_len],
            .to_version = value.update_completed.to_version[0..value.update_completed.to_len],
            .verification = value.update_completed.verification,
        } },
        .update_failed => |event| .{ .update_failed = .{ .channel = event.channel, .stage = event.stage } },
    };
}

fn appendProductPayload(
    io: std.Io,
    environ_map: *const std.process.Environ.Map,
    allocator: std.mem.Allocator,
    installation_id: []const u8,
    event: product.Event,
) !void {
    const body = try product.render(allocator, io, installation_id, event);
    defer allocator.free(body);
    if (product.isActivation(event)) {
        _ = try store.appendActivationEvent(io, environ_map, allocator, body);
    } else {
        try appendEvent(io, environ_map, allocator, body);
    }
}

fn summaryArgCount(kind: []const u8) ?usize {
    if (std.mem.eql(u8, kind, "fm")) return 11;
    if (std.mem.eql(u8, kind, "enforcement")) return 9;
    if (std.mem.eql(u8, kind, "integration")) return 6;
    if (std.mem.eql(u8, kind, "session")) return 6;
    if (std.mem.eql(u8, kind, "feature")) return 6;
    if (std.mem.eql(u8, kind, "reliability")) return 6;
    return null;
}

fn batchWorker(
    io: std.Io,
    environ_map: *const std.process.Environ.Map,
    allocator: std.mem.Allocator,
    argv: []const []const u8,
) u8 {
    if (!transportConfigured() or hardDisabled(environ_map)) return exit_codes.success;

    const installation_id = ensureInstallationId(io, environ_map, allocator) catch return exit_codes.success;
    defer allocator.free(installation_id);

    var index: usize = 1;
    while (index < argv.len) {
        if (std.mem.eql(u8, argv[index], "--record")) {
            if (index + 4 > argv.len) return exit_codes.success;
            const invocation = Invocation{
                .command = argv[index + 1],
                .host = argv[index + 2],
                .outcome = argv[index + 3],
            };
            if (validInvocation(invocation)) appendInvocationPayload(io, environ_map, allocator, installation_id, invocation) catch return exit_codes.success;
            index += 4;
            continue;
        }
        if (std.mem.eql(u8, argv[index], "--summary")) {
            if (index + 2 > argv.len) return exit_codes.success;
            const group_len = summaryArgCount(argv[index + 1]) orelse return exit_codes.success;
            if (index + group_len > argv.len) return exit_codes.success;
            const summary = parseSummaryArgs(argv[index .. index + group_len]) catch return exit_codes.success;
            appendSummaryPayload(io, environ_map, allocator, installation_id, summary) catch return exit_codes.success;
            index += group_len;
            continue;
        }
        if (std.mem.eql(u8, argv[index], "--product")) {
            if (index + 1 >= argv.len) return exit_codes.success;
            const group_len = product.argCount(argv[index + 1]) orelse return exit_codes.success;
            if (index + 1 + group_len > argv.len) return exit_codes.success;
            const event = product.parseArgs(argv[index + 1 .. index + 1 + group_len]) catch return exit_codes.success;
            if (product.valid(event)) appendProductPayload(io, environ_map, allocator, installation_id, event) catch return exit_codes.success;
            index += 1 + group_len;
            continue;
        }
        return exit_codes.success;
    }

    // Keep the detached batch worker bounded even if DNS, a proxy, TLS, or
    // the PostHog response stalls. `flush` owns the network child and kills it
    // through std.process.run's two-second timeout.
    _ = flush(io, environ_map, allocator);
    return exit_codes.success;
}

fn appendBatchArg(args: *[max_batch_args][]const u8, len: *usize, value: []const u8) void {
    args.*[len.*] = value;
    len.* += 1;
}

fn appendBatchCount(
    args: *[max_batch_args][]const u8,
    len: *usize,
    storage: *[max_batch_args][20]u8,
    storage_len: *usize,
    count: u32,
) !void {
    const text = try std.fmt.bufPrint(&storage.*[storage_len.*], "{d}", .{count});
    storage_len.* += 1;
    appendBatchArg(args, len, text);
}

fn appendBatchSummary(
    args: *[max_batch_args][]const u8,
    len: *usize,
    storage: *[max_batch_args][20]u8,
    storage_len: *usize,
    summary: contract.Summary,
) !void {
    appendBatchArg(args, len, "--summary");
    switch (summary) {
        .fm => |value| {
            appendBatchArg(args, len, "fm");
            appendBatchArg(args, len, value.host);
            appendBatchArg(args, len, value.source);
            appendBatchArg(args, len, value.verdict);
            appendBatchArg(args, len, value.status);
            appendBatchArg(args, len, if (value.model_available) "1" else "0");
            appendBatchArg(args, len, if (value.timed_out) "1" else "0");
            appendBatchArg(args, len, if (value.upgraded) "1" else "0");
            appendBatchArg(args, len, value.latency_bucket);
            try appendBatchCount(args, len, storage, storage_len, value.count);
        },
        .enforcement => |value| {
            appendBatchArg(args, len, "enforcement");
            appendBatchArg(args, len, value.host);
            appendBatchArg(args, len, value.source);
            appendBatchArg(args, len, value.decision);
            appendBatchArg(args, len, value.risk);
            appendBatchArg(args, len, value.effect);
            appendBatchArg(args, len, value.mode);
            try appendBatchCount(args, len, storage, storage_len, value.count);
        },
        .integration => |value| {
            appendBatchArg(args, len, "integration");
            appendBatchArg(args, len, value.host);
            appendBatchArg(args, len, value.operation);
            appendBatchArg(args, len, value.result);
            try appendBatchCount(args, len, storage, storage_len, value.count);
        },
        .session => |value| {
            appendBatchArg(args, len, "session");
            appendBatchArg(args, len, value.host);
            appendBatchArg(args, len, value.event_type);
            appendBatchArg(args, len, value.result);
            try appendBatchCount(args, len, storage, storage_len, value.count);
        },
        .feature => |value| {
            appendBatchArg(args, len, "feature");
            appendBatchArg(args, len, value.feature);
            appendBatchArg(args, len, value.operation);
            appendBatchArg(args, len, value.result);
            try appendBatchCount(args, len, storage, storage_len, value.count);
        },
        .reliability => |value| {
            appendBatchArg(args, len, "reliability");
            appendBatchArg(args, len, value.operation);
            appendBatchArg(args, len, value.failure);
            appendBatchArg(args, len, value.source);
            try appendBatchCount(args, len, storage, storage_len, value.count);
        },
    }
}

fn spawnBatch(
    io: std.Io,
    environ_map: *const std.process.Environ.Map,
    allocator: std.mem.Allocator,
    invocation: ?Invocation,
    summaries: PendingSummaries,
) !void {
    if (invocation == null and summaries.fm_len == 0 and summaries.enforcement_len == 0 and
        summaries.integration_len == 0 and summaries.session_len == 0 and summaries.feature_len == 0 and
        summaries.reliability_len == 0 and summaries.product_len == 0) return;

    const executable = try std.process.executablePathAlloc(io, allocator);
    defer allocator.free(executable);

    var child_argv: [max_batch_args][]const u8 = undefined;
    var count_storage: [max_batch_args][20]u8 = undefined;
    var child_len: usize = 0;
    var storage_len: usize = 0;
    appendBatchArg(&child_argv, &child_len, executable);
    appendBatchArg(&child_argv, &child_len, "telemetry");
    appendBatchArg(&child_argv, &child_len, "--batch");
    if (invocation) |value| {
        appendBatchArg(&child_argv, &child_len, "--record");
        appendBatchArg(&child_argv, &child_len, value.command);
        appendBatchArg(&child_argv, &child_len, value.host);
        appendBatchArg(&child_argv, &child_len, value.outcome);
    }
    for (summaries.fm[0..summaries.fm_len]) |summary|
        try appendBatchSummary(&child_argv, &child_len, &count_storage, &storage_len, .{ .fm = summary });
    for (summaries.enforcement[0..summaries.enforcement_len]) |summary|
        try appendBatchSummary(&child_argv, &child_len, &count_storage, &storage_len, .{ .enforcement = summary });
    for (summaries.integration[0..summaries.integration_len]) |summary|
        try appendBatchSummary(&child_argv, &child_len, &count_storage, &storage_len, .{ .integration = summary });
    for (summaries.session[0..summaries.session_len]) |summary|
        try appendBatchSummary(&child_argv, &child_len, &count_storage, &storage_len, .{ .session = summary });
    for (summaries.feature[0..summaries.feature_len]) |summary|
        try appendBatchSummary(&child_argv, &child_len, &count_storage, &storage_len, .{ .feature = summary });
    for (summaries.reliability[0..summaries.reliability_len]) |summary|
        try appendBatchSummary(&child_argv, &child_len, &count_storage, &storage_len, .{ .reliability = summary });
    for (summaries.product[0..summaries.product_len]) |*event| {
        product.appendBatchArgs(&child_argv, &child_len, productEventFromPending(event));
    }

    var child_environ = try workerEnvironment(allocator, environ_map);
    defer child_environ.deinit();
    try child_environ.put("RYK_TELEMETRY_INTERNAL", "1");
    var child = try std.process.spawn(io, .{
        .argv = child_argv[0..child_len],
        .environ_map = &child_environ,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
        .create_no_window = true,
    });
    detachWorker(&child);
}

fn detachWorker(child: *std.process.Child) void {
    // Zig 0.16 has no detached-child API. The worker owns no pipes. On POSIX,
    // relinquishing the pid lets the OS reparent and reap it when this short-
    // lived CLI exits; on Windows, close the process/thread handles explicitly.
    if (comptime builtin.os.tag == .windows) {
        if (child.id) |id| {
            std.os.windows.CloseHandle(child.thread_handle);
            std.os.windows.CloseHandle(id);
        }
    }
    child.id = null;
}

test "classifyInvocation emits only fixed command metadata" {
    const invocation = classifyInvocation(
        &.{ "run", "--", "echo", "secret-value", "/Users/private/file" },
        exit_codes.success,
    ) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("run", invocation.command);
    try std.testing.expectEqualStrings("none", invocation.host);
    try std.testing.expectEqualStrings("success", invocation.outcome);
    try std.testing.expect(classifyInvocation(&.{ "run", "--", "/bin/echo", "--dry-run" }, exit_codes.success) != null);
    try std.testing.expect(classifyInvocation(&.{ "claude", "--json" }, exit_codes.success) != null);
    try std.testing.expect(classifyInvocation(&.{ "--no-rich", "doctor" }, exit_codes.success) != null);
}

test "classifyInvocation excludes machine and CI paths" {
    try std.testing.expect(classifyInvocation(&.{ "run", "--json" }, exit_codes.success) == null);
    try std.testing.expect(classifyInvocation(&.{ "run", "--mode", "ci" }, exit_codes.success) == null);
    try std.testing.expect(classifyInvocation(&.{ "packs", "-f", "json" }, exit_codes.success) == null);
    try std.testing.expect(classifyInvocation(&.{ "uninstall", "--dry-run" }, exit_codes.success) == null);
    try std.testing.expect(classifyInvocation(&.{ "hook", "--event", "x" }, exit_codes.success) == null);
}

test "run and host child exits are not mistaken for policy outcomes" {
    const run_invocation = classifyInvocation(&.{ "run", "--", "sh" }, exit_codes.denial) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("failure", run_invocation.outcome);
    const doctor_invocation = classifyInvocation(&.{"doctor"}, exit_codes.denial) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("denied", doctor_invocation.outcome);
}

test "queue validator accepts only the fixed event allowlist" {
    const valid = "{\"event\":\"ryk_cli_command\",\"properties\":{" ++
        "\"distinct_id\":\"ryk_0123456789abcdef0123456789abcdef\", " ++
        "\"$process_person_profile\":false,\"$ip\":0,\"telemetry_schema_version\":1," ++
        "\"command\":\"doctor\",\"host\":\"none\",\"outcome\":\"success\"," ++
        "\"product_version\":\"1.2.9\",\"os\":\"macos\",\"arch\":\"aarch64\"," ++
        "\"occurred_at\":\"2026-08-08T00:00:00Z\"}}";
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, valid, .{});
    defer parsed.deinit();
    try std.testing.expect(validQueuedEvent(parsed.value));

    const injected = "{\"event\":\"ryk_cli_command\",\"properties\":{" ++
        "\"distinct_id\":\"ryk_0123456789abcdef0123456789abcdef\", " ++
        "\"$process_person_profile\":false,\"$ip\":0,\"telemetry_schema_version\":1," ++
        "\"command\":\"doctor\",\"host\":\"none\",\"outcome\":\"success\"," ++
        "\"product_version\":\"1.2.9\",\"os\":\"macos\",\"arch\":\"aarch64\"," ++
        "\"occurred_at\":\"2026-08-08T00:00:00Z\",\"command_text\":\"secret\"}}";
    var injected_parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, injected, .{});
    defer injected_parsed.deinit();
    try std.testing.expect(!validQueuedEvent(injected_parsed.value));

    const ip_override = try std.mem.replaceOwned(
        u8,
        std.testing.allocator,
        valid,
        "\"$ip\":0",
        "\"$ip\":1",
    );
    defer std.testing.allocator.free(ip_override);
    var ip_override_parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, ip_override, .{});
    defer ip_override_parsed.deinit();
    try std.testing.expect(!validQueuedEvent(ip_override_parsed.value));
}

test "summary events are fixed-dimension and payload-free" {
    const summary: contract.Summary = .{ .fm = .{
        .host = "claude",
        .source = "hook",
        .verdict = "ask",
        .status = "model",
        .model_available = true,
        .timed_out = false,
        .upgraded = true,
        .latency_bucket = "10_49ms",
        .count = 3,
    } };
    const event = try renderSummary(
        std.testing.allocator,
        std.testing.io,
        "ryk_0123456789abcdef0123456789abcdef",
        summary,
    );
    defer std.testing.allocator.free(event);
    try std.testing.expect(std.mem.indexOf(u8, event, "ryk_fm_steward_summary") != null);
    try std.testing.expect(std.mem.indexOf(u8, event, "command") == null);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, event, .{});
    defer parsed.deinit();
    try std.testing.expect(validQueuedEvent(parsed.value));

    const injected = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s},\"properties_extra\":\"secret\"}}",
        .{event[0 .. event.len - 2]},
    );
    defer std.testing.allocator.free(injected);
    var injected_parsed = std.json.parseFromSlice(std.json.Value, std.testing.allocator, injected, .{}) catch return;
    defer injected_parsed.deinit();
    try std.testing.expect(!validQueuedEvent(injected_parsed.value));
}

test "summary classifiers use fixed product dimensions" {
    const feature = contract.classifyFeatureInvocation(&.{ "plugin", "install", "claude", "--yes" }, 0) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("plugin", feature.feature);
    try std.testing.expectEqualStrings("install", feature.operation);

    const session = contract.classifySessionInvocation(&.{ "hook", "opencode", "session.created" }, 0) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("opencode", session.host);
    try std.testing.expectEqualStrings("session_start", session.event_type);

    try std.testing.expect(contract.classifyIntegrationInvocation(&.{ "plugin", "doctor", "claude" }, 0) == null);
    const integration = contract.classifyIntegrationInvocation(&.{ "plugin", "install", "claude" }, 0) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("claude", integration.host);
    try std.testing.expectEqualStrings("install", integration.operation);

    try std.testing.expect(contract.classifyReliabilityInvocation(&.{"evaluate"}, 3) == null);
    const reliability = contract.classifyReliabilityInvocation(&.{"doctor"}, 1) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("command_failure", reliability.failure);
}

test "telemetry controls are excluded from feature summaries" {
    try std.testing.expect(contract.classifyFeatureInvocation(&.{ "telemetry", "status" }, 0) == null);
    try std.testing.expect(contract.classifyFeatureInvocation(&.{ "telemetry", "enable" }, 0) == null);
    try std.testing.expect(contract.classifyFeatureInvocation(&.{ "telemetry", "disable" }, 0) == null);
}

test "state parser rejects unknown keys and disabled identities" {
    try std.testing.expectError(
        error.InvalidTelemetryState,
        parseState(std.testing.allocator, "{\"schema_version\":1,\"enabled\":true,\"unexpected\":1}"),
    );
    try std.testing.expectError(
        error.InvalidTelemetryState,
        parseState(
            std.testing.allocator,
            "{\"schema_version\":1,\"enabled\":false,\"installation_id\":\"ryk_0123456789abcdef0123456789abcdef\"}",
        ),
    );
}

test "append rechecks opt-out state while holding the queue lock" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();
    try environ_map.put("XDG_CONFIG_HOME", root);

    const installation_id = "ryk_0123456789abcdef0123456789abcdef";
    const event = try renderEvent(std.testing.allocator, std.testing.io, installation_id, .{
        .command = "doctor",
        .host = "none",
        .outcome = "success",
    });
    defer std.testing.allocator.free(event);

    try setEnabled(std.testing.io, &environ_map, std.testing.allocator, true);
    try appendEvent(std.testing.io, &environ_map, std.testing.allocator, event);
    try setEnabled(std.testing.io, &environ_map, std.testing.allocator, false);
    try std.testing.expectError(
        error.TelemetryDisabled,
        appendEvent(std.testing.io, &environ_map, std.testing.allocator, event),
    );
    try std.testing.expectEqual(@as(usize, 0), try queueCount(std.testing.allocator, std.testing.io, &environ_map));
}

test "activation is persisted and appended only once" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();
    try environ_map.put("XDG_CONFIG_HOME", root);

    const event = try product.render(std.testing.allocator, std.testing.io, "ryk_0123456789abcdef0123456789abcdef", .{
        .activation = .{ .host = "none" },
    });
    defer std.testing.allocator.free(event);

    try setEnabled(std.testing.io, &environ_map, std.testing.allocator, true);
    try std.testing.expect(try store.appendActivationEvent(std.testing.io, &environ_map, std.testing.allocator, event));
    try std.testing.expect(!(try store.appendActivationEvent(std.testing.io, &environ_map, std.testing.allocator, event)));
    try std.testing.expectEqual(@as(usize, 1), try queueCount(std.testing.allocator, std.testing.io, &environ_map));

    const paths = (try store.resolvePaths(std.testing.allocator, &environ_map)).?;
    defer {
        var owned_paths = paths;
        owned_paths.deinit(std.testing.allocator);
    }
    var loaded = try store.readState(std.testing.allocator, std.testing.io, &paths);
    defer loaded.deinit(std.testing.allocator);
    try std.testing.expect(loaded.state.activation_recorded);
}

test "activation queue identity repairs an unmarked state without duplicating" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();
    try environ_map.put("XDG_CONFIG_HOME", root);

    const event = try product.render(std.testing.allocator, std.testing.io, "ryk_0123456789abcdef0123456789abcdef", .{
        .activation = .{ .host = "none" },
    });
    defer std.testing.allocator.free(event);

    try setEnabled(std.testing.io, &environ_map, std.testing.allocator, true);
    try store.appendEvent(std.testing.io, &environ_map, std.testing.allocator, event);
    try std.testing.expect(!(try store.appendActivationEvent(std.testing.io, &environ_map, std.testing.allocator, event)));
    try std.testing.expectEqual(@as(usize, 1), try queueCount(std.testing.allocator, std.testing.io, &environ_map));
}

test "activation deduplication checks a full queue before eviction" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();
    try environ_map.put("XDG_CONFIG_HOME", root);

    const activation = try product.render(std.testing.allocator, std.testing.io, "ryk_0123456789abcdef0123456789abcdef", .{
        .activation = .{ .host = "none" },
    });
    defer std.testing.allocator.free(activation);
    const ordinary = try renderEvent(
        std.testing.allocator,
        std.testing.io,
        "ryk_0123456789abcdef0123456789abcdef",
        .{ .command = "doctor", .host = "none", .outcome = "success" },
    );
    defer std.testing.allocator.free(ordinary);

    try store.setEnabled(std.testing.io, &environ_map, std.testing.allocator, true, false);
    const paths = (try store.resolvePaths(std.testing.allocator, &environ_map)).?;
    defer {
        var owned_paths = paths;
        owned_paths.deinit(std.testing.allocator);
    }
    var items: std.ArrayList([]const u8) = .empty;
    defer items.deinit(std.testing.allocator);
    try items.ensureTotalCapacity(std.testing.allocator, max_queue_events);
    try items.append(std.testing.allocator, activation);
    for (1..max_queue_events) |_| try items.append(std.testing.allocator, ordinary);
    try store.writeQueue(std.testing.io, std.testing.allocator, &paths, items.items);

    try std.testing.expect(!(try store.appendActivationEvent(
        std.testing.io,
        &environ_map,
        std.testing.allocator,
        activation,
    )));
    try std.testing.expectEqual(@as(usize, max_queue_events), try queueCount(std.testing.allocator, std.testing.io, &environ_map));
}

test "ordinary queue append preserves an undelivered activation" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();
    try environ_map.put("XDG_CONFIG_HOME", root);

    const activation = try product.render(std.testing.allocator, std.testing.io, "ryk_0123456789abcdef0123456789abcdef", .{
        .activation = .{ .host = "none" },
    });
    defer std.testing.allocator.free(activation);
    const ordinary = try renderEvent(
        std.testing.allocator,
        std.testing.io,
        "ryk_0123456789abcdef0123456789abcdef",
        .{ .command = "doctor", .host = "none", .outcome = "success" },
    );
    defer std.testing.allocator.free(ordinary);

    try store.setEnabled(std.testing.io, &environ_map, std.testing.allocator, true, false);
    _ = try store.appendActivationEvent(std.testing.io, &environ_map, std.testing.allocator, activation);
    for (0..max_queue_events - 1) |_| try store.appendEvent(std.testing.io, &environ_map, std.testing.allocator, ordinary);
    try store.appendEvent(std.testing.io, &environ_map, std.testing.allocator, ordinary);

    const paths = (try store.resolvePaths(std.testing.allocator, &environ_map)).?;
    defer {
        var owned_paths = paths;
        owned_paths.deinit(std.testing.allocator);
    }
    var queue = try store.readQueue(std.testing.allocator, std.testing.io, &paths);
    defer queue.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, max_queue_events), queue.items.items.len);
    try std.testing.expect(std.mem.indexOf(u8, queue.items.items[0], "\"event\":\"ryk_activation\"") != null);
}

test "malformed activation marker frees an owned installation id" {
    const state =
        "{\"schema_version\":1,\"enabled\":true,\"installation_id\":\"ryk_0123456789abcdef0123456789abcdef\",\"activation_recorded\":\"yes\"}";
    try std.testing.expectError(error.InvalidTelemetryState, store.parseState(std.testing.allocator, state));
}

test "queue rejects an overfull persisted queue without double freeing" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();
    try environ_map.put("XDG_CONFIG_HOME", root);
    try store.setEnabled(std.testing.io, &environ_map, std.testing.allocator, true, false);

    const paths = (try store.resolvePaths(std.testing.allocator, &environ_map)).?;
    defer {
        var owned_paths = paths;
        owned_paths.deinit(std.testing.allocator);
    }
    const event = try renderEvent(
        std.testing.allocator,
        std.testing.io,
        "ryk_0123456789abcdef0123456789abcdef",
        .{ .command = "doctor", .host = "none", .outcome = "success" },
    );
    defer std.testing.allocator.free(event);

    var items: std.ArrayList([]const u8) = .empty;
    defer items.deinit(std.testing.allocator);
    try items.ensureTotalCapacity(std.testing.allocator, max_queue_events + 1);
    for (0..max_queue_events + 1) |_| try items.append(std.testing.allocator, event);
    try store.writeQueue(std.testing.io, std.testing.allocator, &paths, items.items);
    try std.testing.expectError(
        error.InvalidTelemetryQueue,
        store.readQueue(std.testing.allocator, std.testing.io, &paths),
    );
}

test "state rendering uses the bounded persisted schema" {
    var state = State{
        .enabled = true,
        .installation_id = try std.testing.allocator.dupe(u8, "ryk_0123456789abcdef0123456789abcdef"),
    };
    defer state.deinit(std.testing.allocator);
    const text = try renderState(std.testing.allocator, &state);
    defer std.testing.allocator.free(text);
    try std.testing.expect(std.mem.indexOf(u8, text, "schema_version") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "installation_id") != null);
}

test "event payload does not serialize command arguments" {
    const invocation = Invocation{ .command = "run", .host = "none", .outcome = "success" };
    const id = "ryk_0123456789abcdef0123456789abcdef";
    const event = try renderEvent(std.testing.allocator, std.testing.io, id, invocation);
    defer std.testing.allocator.free(event);
    try std.testing.expect(std.mem.indexOf(u8, event, "secret-value") == null);
    try std.testing.expect(std.mem.indexOf(u8, event, "ryk_cli_command") != null);
}

test "installation ids are fixed format" {
    try std.testing.expect(validInstallationId("ryk_0123456789abcdef0123456789abcdef"));
    try std.testing.expect(!validInstallationId("ryk_not-an-id"));
    try std.testing.expect(!validInstallationId("other_0123456789abcdef0123456789abcdef"));
}

test "telemetry workers receive only safe environment values" {
    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();
    try environ_map.put("HOME", "/Users/example");
    try environ_map.put("http_proxy", "http://user:password@proxy.example:8080");
    try environ_map.put("SECRET_VALUE", "do-not-forward");

    var worker = try workerEnvironment(std.testing.allocator, &environ_map);
    defer worker.deinit();
    try std.testing.expectEqualStrings("/Users/example", worker.get("HOME").?);
    try std.testing.expectEqualStrings("http://proxy.example:8080", worker.get("http_proxy").?);
    try std.testing.expect(worker.get("SECRET_VALUE") == null);
}

test "posthog honors endpoint no-proxy entries" {
    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();
    try environ_map.put("NO_PROXY", "localhost, .posthog.com:443");
    try std.testing.expect(posthogProxyBypassed(&environ_map));

    try environ_map.put("NO_PROXY", "localhost, example.com");
    try std.testing.expect(!posthogProxyBypassed(&environ_map));
}

test "public telemetry worker flags are rejected" {
    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();
    var stdout_buf: [256]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(
        std.testing.io,
        &environ_map,
        std.testing.allocator,
        &.{"--send"},
        &stdout_writer,
        &stderr_writer,
    );
    try std.testing.expectEqual(exit_codes.usage, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "unsupported option") != null);

    var record_stdout_buf: [256]u8 = undefined;
    var record_stderr_buf: [256]u8 = undefined;
    var record_stdout_writer: std.Io.Writer = .fixed(&record_stdout_buf);
    var record_stderr_writer: std.Io.Writer = .fixed(&record_stderr_buf);
    const record_code = try command(
        std.testing.io,
        &environ_map,
        std.testing.allocator,
        &.{ "--record", "doctor", "none", "success" },
        &record_stdout_writer,
        &record_stderr_writer,
    );
    try std.testing.expectEqual(exit_codes.usage, record_code);
    try std.testing.expect(std.mem.indexOf(u8, record_stderr_writer.buffered(), "unsupported option") != null);
}

test "public telemetry command persists opt-out state" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();
    try environ_map.put("XDG_CONFIG_HOME", root);

    var status_stdout_buf: [512]u8 = undefined;
    var status_stderr_buf: [512]u8 = undefined;
    var status_stdout: std.Io.Writer = .fixed(&status_stdout_buf);
    var status_stderr: std.Io.Writer = .fixed(&status_stderr_buf);
    try std.testing.expectEqual(
        exit_codes.success,
        try command(std.testing.io, &environ_map, std.testing.allocator, &.{ "status", "--json" }, &status_stdout, &status_stderr),
    );
    // Opt-in default: no consent state means disabled.
    try std.testing.expect(std.mem.indexOf(u8, status_stdout.buffered(), "\"enabled\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, status_stdout.buffered(), "\"source\":\"default\"") != null);

    var enable_first_stdout_buf: [256]u8 = undefined;
    var enable_first_stderr_buf: [256]u8 = undefined;
    var enable_first_stdout: std.Io.Writer = .fixed(&enable_first_stdout_buf);
    var enable_first_stderr: std.Io.Writer = .fixed(&enable_first_stderr_buf);
    try std.testing.expectEqual(
        exit_codes.success,
        try command(std.testing.io, &environ_map, std.testing.allocator, &.{"enable"}, &enable_first_stdout, &enable_first_stderr),
    );

    var enabled_stdout_buf: [512]u8 = undefined;
    var enabled_stderr_buf: [512]u8 = undefined;
    var enabled_stdout: std.Io.Writer = .fixed(&enabled_stdout_buf);
    var enabled_stderr: std.Io.Writer = .fixed(&enabled_stderr_buf);
    try std.testing.expectEqual(
        exit_codes.success,
        try command(std.testing.io, &environ_map, std.testing.allocator, &.{ "status", "--json" }, &enabled_stdout, &enabled_stderr),
    );
    try std.testing.expect(std.mem.indexOf(u8, enabled_stdout.buffered(), "\"enabled\":true") != null);

    var disable_stdout_buf: [256]u8 = undefined;
    var disable_stderr_buf: [256]u8 = undefined;
    var disable_stdout: std.Io.Writer = .fixed(&disable_stdout_buf);
    var disable_stderr: std.Io.Writer = .fixed(&disable_stderr_buf);
    try std.testing.expectEqual(
        exit_codes.success,
        try command(std.testing.io, &environ_map, std.testing.allocator, &.{"disable"}, &disable_stdout, &disable_stderr),
    );

    var disabled_stdout_buf: [512]u8 = undefined;
    var disabled_stderr_buf: [512]u8 = undefined;
    var disabled_stdout: std.Io.Writer = .fixed(&disabled_stdout_buf);
    var disabled_stderr: std.Io.Writer = .fixed(&disabled_stderr_buf);
    try std.testing.expectEqual(
        exit_codes.success,
        try command(
            std.testing.io,
            &environ_map,
            std.testing.allocator,
            &.{ "status", "--json" },
            &disabled_stdout,
            &disabled_stderr,
        ),
    );
    try std.testing.expect(std.mem.indexOf(u8, disabled_stdout.buffered(), "\"enabled\":false") != null);

    var enable_stdout_buf: [256]u8 = undefined;
    var enable_stderr_buf: [256]u8 = undefined;
    var enable_stdout: std.Io.Writer = .fixed(&enable_stdout_buf);
    var enable_stderr: std.Io.Writer = .fixed(&enable_stderr_buf);
    try std.testing.expectEqual(
        exit_codes.success,
        try command(std.testing.io, &environ_map, std.testing.allocator, &.{"enable"}, &enable_stdout, &enable_stderr),
    );
}

test "missing telemetry state defaults to disabled with no queued events" {
    // P1 opt-in default: a fresh install must not queue or send anything until
    // the user runs `ryk telemetry enable`. No state file -> append is refused
    // -> queue stays empty -> the sender returns before any POST attempt.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();
    try environ_map.put("XDG_CONFIG_HOME", root);

    const paths = (try store.resolvePaths(std.testing.allocator, &environ_map)).?;
    defer {
        var owned_paths = paths;
        owned_paths.deinit(std.testing.allocator);
    }
    var loaded = try store.readState(std.testing.allocator, std.testing.io, &paths);
    defer loaded.deinit(std.testing.allocator);
    try std.testing.expect(!loaded.state.enabled);
    try std.testing.expectEqual(store.StateSource.default, loaded.source);

    const event = try renderEvent(std.testing.allocator, std.testing.io, "ryk_0123456789abcdef0123456789abcdef", .{
        .command = "doctor",
        .host = "none",
        .outcome = "success",
    });
    defer std.testing.allocator.free(event);
    try std.testing.expectError(
        error.TelemetryDisabled,
        store.appendEvent(std.testing.io, &environ_map, std.testing.allocator, event),
    );
    try std.testing.expectEqual(@as(usize, 0), try queueCount(std.testing.allocator, std.testing.io, &environ_map));

    // Empty queue short-circuits before any transport attempt.
    try @import("telemetry_transport.zig").sendQueued(std.testing.io, &environ_map, std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), try queueCount(std.testing.allocator, std.testing.io, &environ_map));
}

test "RYK_NO_TELEMETRY overrides an explicit opt-in" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();
    try environ_map.put("XDG_CONFIG_HOME", root);

    try setEnabled(std.testing.io, &environ_map, std.testing.allocator, true);
    try environ_map.put("RYK_NO_TELEMETRY", "1");

    var loaded = try loadEffectiveState(std.testing.allocator, std.testing.io, &environ_map);
    defer loaded.deinit(std.testing.allocator);
    try std.testing.expect(!loaded.state.enabled);
    try std.testing.expectEqual(StateSource.environment, loaded.source);
}

test "hard telemetry disable blocks enabling" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();
    try environ_map.put("XDG_CONFIG_HOME", root);
    try environ_map.put("RYK_NO_TELEMETRY", "1");

    var stdout_buf: [256]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout: std.Io.Writer = .fixed(&stdout_buf);
    var stderr: std.Io.Writer = .fixed(&stderr_buf);
    try std.testing.expectEqual(
        exit_codes.general,
        try command(std.testing.io, &environ_map, std.testing.allocator, &.{"enable"}, &stdout, &stderr),
    );
    try std.testing.expect(std.mem.indexOf(u8, stderr.buffered(), "RYK_NO_TELEMETRY") != null);

    var json_stdout_buf: [256]u8 = undefined;
    var json_stderr_buf: [256]u8 = undefined;
    var json_stdout: std.Io.Writer = .fixed(&json_stdout_buf);
    var json_stderr: std.Io.Writer = .fixed(&json_stderr_buf);
    try std.testing.expectEqual(
        exit_codes.general,
        try command(
            std.testing.io,
            &environ_map,
            std.testing.allocator,
            &.{ "enable", "--json" },
            &json_stdout,
            &json_stderr,
        ),
    );
    try std.testing.expect(std.mem.indexOf(u8, json_stdout.buffered(), "\"ok\":false") != null);
    try std.testing.expectEqual(@as(usize, 0), json_stderr.buffered().len);
}

test "invalid telemetry config roots fail closed" {
    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();
    try environ_map.put("XDG_CONFIG_HOME", "relative-config");

    var stdout_buf: [256]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout: std.Io.Writer = .fixed(&stdout_buf);
    var stderr: std.Io.Writer = .fixed(&stderr_buf);
    try std.testing.expectEqual(
        exit_codes.general,
        try command(std.testing.io, &environ_map, std.testing.allocator, &.{"disable"}, &stdout, &stderr),
    );
    try std.testing.expect(std.mem.indexOf(u8, stderr.buffered(), "InvalidConfigPath") != null);
}

test "telemetry status is unavailable without a config root" {
    var environ_map = std.process.Environ.Map.init(std.testing.allocator);
    defer environ_map.deinit();

    var stdout_buf: [512]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout: std.Io.Writer = .fixed(&stdout_buf);
    var stderr: std.Io.Writer = .fixed(&stderr_buf);
    try std.testing.expectEqual(
        exit_codes.general,
        try command(std.testing.io, &environ_map, std.testing.allocator, &.{ "status", "--json" }, &stdout, &stderr),
    );
    try std.testing.expect(std.mem.indexOf(u8, stdout.buffered(), "\"source\":\"unavailable\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout.buffered(), "\"enabled\":false") != null);
}

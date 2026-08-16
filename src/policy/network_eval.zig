const std = @import("std");

const audit_redact = @import("../audit/redact_bridge.zig");
const core = @import("../core/mod.zig");
const effects = @import("effects/mod.zig");
const matchers = @import("matchers.zig");
const schema = @import("schema.zig");

pub const implemented = true;

pub const NetworkMode = enum {
    off,
    ask,
    allowlist,
    observe,
    open,

    pub fn parse(value: []const u8) ?NetworkMode {
        inline for (@typeInfo(NetworkMode).@"enum".fields) |field| {
            if (std.mem.eql(u8, value, field.name)) return @enumFromInt(field.value);
        }
        return null;
    }

    pub fn toString(self: NetworkMode) []const u8 {
        return @tagName(self);
    }
};

pub const EnforcementMode = enum {
    direct,
    proxy_mediated,
    shim_mediated,
    observe_only,
    unavailable,

    pub fn toString(self: EnforcementMode) []const u8 {
        return switch (self) {
            .direct => "direct",
            .proxy_mediated => "proxy-mediated",
            .shim_mediated => "shim-mediated",
            .observe_only => "observe-only",
            .unavailable => "unavailable",
        };
    }
};

pub const HostClass = enum {
    domain,
    direct_ip,
    localhost,
    private_network,
    cloud_metadata,
    invalid,
};

pub const Destination = struct {
    raw: []const u8,
    scheme: ?[]const u8 = null,
    host: []const u8,
    port: ?u16 = null,
    path: []const u8 = "",
    query: []const u8 = "",
    host_class: HostClass,

    pub fn endpointDisplay(self: Destination, allocator: std.mem.Allocator) ![]u8 {
        if (self.port) |port| return std.fmt.allocPrint(allocator, "{s}:{d}", .{ self.host, port });
        return allocator.dupe(u8, self.host);
    }
};

pub const ExfilSignal = enum {
    long_query_string,
    base64_like_url_component,
    high_entropy_dns_label,
    paste_site_destination,
    webhook_request_bin_destination,
    tunneling_service_destination,
    direct_ip_destination,
    secret_like_url_value,
    long_subdomain,
    many_unknown_domains,

    pub fn reason(self: ExfilSignal) []const u8 {
        return switch (self) {
            .long_query_string => "long query string",
            .base64_like_url_component => "base64-like URL component",
            .high_entropy_dns_label => "high-entropy DNS label",
            .paste_site_destination => "paste-site destination",
            .webhook_request_bin_destination => "webhook/request-bin destination",
            .tunneling_service_destination => "tunneling service destination",
            .direct_ip_destination => "direct IP destination",
            .secret_like_url_value => "secret-like URL value",
            .long_subdomain => "long subdomain",
            .many_unknown_domains => "repeated attempts to many unknown domains",
        };
    }
};

pub const ExfilFinding = struct {
    signal: ExfilSignal,
    score: u8,
};

pub const Decision = struct {
    destination: Destination,
    decision: core.decision.Decision,
    matched_rule: ?schema.RuleRef = null,
    enforcement_mode: EnforcementMode,
    exfil_findings: []ExfilFinding = &.{},
    redacted_target: []u8,
    owned_reason: []u8,
    owned_rule_id: ?[]u8 = null,
    owned_findings: bool = false,

    pub fn deinit(self: Decision, allocator: std.mem.Allocator) void {
        allocator.free(self.redacted_target);
        allocator.free(self.owned_reason);
        if (self.owned_rule_id) |rule_id| allocator.free(rule_id);
        if (self.owned_findings and self.exfil_findings.len > 0) allocator.free(self.exfil_findings);
    }
};

pub const UnknownDomainTracker = struct {
    allocator: std.mem.Allocator,
    hosts: std.StringHashMap(void),

    pub fn init(allocator: std.mem.Allocator) UnknownDomainTracker {
        return .{ .allocator = allocator, .hosts = std.StringHashMap(void).init(allocator) };
    }

    pub fn deinit(self: *UnknownDomainTracker) void {
        var it = self.hosts.keyIterator();
        while (it.next()) |key| {
            self.allocator.free(key.*);
        }
        self.hosts.deinit();
    }

    pub fn record(self: *UnknownDomainTracker, host: []const u8) !bool {
        if (self.hosts.contains(host)) return self.hosts.count() >= 5;
        const owned = try self.allocator.dupe(u8, host);
        errdefer self.allocator.free(owned);
        try self.hosts.put(owned, {});
        return self.hosts.count() >= 5;
    }
};

pub const Options = struct {
    ci_mode: bool = false,
    enforcement_mode: EnforcementMode = .direct,
    unknown_tracker: ?*UnknownDomainTracker = null,
    method: ?[]const u8 = null,
};

const Match = struct {
    label: []const u8,
    index: usize,
    pattern: []const u8,
};

pub fn parseDestination(input: []const u8) !Destination {
    if (input.len == 0 or input.len > core.limits.max_url_len) return error.InvalidNetworkDestination;
    if (!std.unicode.utf8ValidateSlice(input)) return error.InvalidNetworkDestination;
    if (std.mem.indexOfScalar(u8, input, 0) != null) return error.InvalidNetworkDestination;

    var rest = std.mem.trim(u8, input, " \t\r\n");
    var scheme: ?[]const u8 = null;
    if (std.mem.indexOf(u8, rest, "://")) |scheme_end| {
        if (scheme_end == 0) return error.InvalidNetworkDestination;
        scheme = rest[0..scheme_end];
        rest = rest[scheme_end + 3 ..];
    }

    const authority_end = std.mem.indexOfAny(u8, rest, "/?#") orelse rest.len;
    var authority = rest[0..authority_end];
    var path: []const u8 = "";
    var query: []const u8 = "";
    const tail = rest[authority_end..];
    if (tail.len > 0) {
        const query_start = std.mem.indexOfScalar(u8, tail, '?');
        if (query_start) |idx| {
            path = tail[0..idx];
            const after_question = tail[idx + 1 ..];
            const fragment = std.mem.indexOfScalar(u8, after_question, '#') orelse after_question.len;
            query = after_question[0..fragment];
        } else {
            const fragment = std.mem.indexOfScalar(u8, tail, '#') orelse tail.len;
            path = tail[0..fragment];
        }
    }

    if (std.mem.indexOfScalar(u8, authority, '@')) |at| authority = authority[at + 1 ..];
    if (authority.len == 0) return error.InvalidNetworkDestination;

    var host: []const u8 = authority;
    var port: ?u16 = null;
    if (authority[0] == '[') {
        const close = std.mem.indexOfScalar(u8, authority, ']') orelse return error.InvalidNetworkDestination;
        host = authority[1..close];
        if (authority.len > close + 1) {
            if (authority[close + 1] != ':') return error.InvalidNetworkDestination;
            port = try parsePort(authority[close + 2 ..]);
        }
    } else if (std.mem.lastIndexOfScalar(u8, authority, ':')) |colon| {
        if (std.mem.indexOfScalar(u8, authority[0..colon], ':') == null) {
            host = authority[0..colon];
            port = try parsePort(authority[colon + 1 ..]);
        }
    }
    host = trimTrailingDot(std.mem.trim(u8, host, " \t\r\n"));
    if (host.len == 0 or host.len > 253) return error.InvalidNetworkDestination;

    return .{
        .raw = input,
        .scheme = scheme,
        .host = host,
        .port = port,
        .path = path,
        .query = query,
        .host_class = classifyHost(host),
    };
}

pub fn evaluate(
    allocator: std.mem.Allocator,
    policy: *const schema.Policy,
    effective_mode: schema.Mode,
    destination_text: []const u8,
    options: Options,
) !Decision {
    var decision = try evaluateSurface(allocator, policy, effective_mode, destination_text, options);
    errdefer decision.deinit(allocator);
    // Shared by proxy / run / redteam: surface network rules ∩ effect host tags.
    try mergeNetworkEffectTags(allocator, policy, effective_mode, options, &decision);
    return decision;
}

fn evaluateSurface(
    allocator: std.mem.Allocator,
    policy: *const schema.Policy,
    effective_mode: schema.Mode,
    destination_text: []const u8,
    options: Options,
) !Decision {
    const destination = parseDestination(destination_text) catch |err| {
        if (effective_mode == .ci or effective_mode == .strict or policy.network.effectiveMode() == .off or policy.network.effectiveMode() == .allowlist) {
            // #374: free target if reason dupe fails (dual-dupe ownership).
            const target = try allocator.dupe(u8, "[invalid-network-destination]");
            errdefer allocator.free(target);
            const reason = try allocator.dupe(u8, "invalid or ambiguous network destination");
            return .{
                .destination = .{ .raw = destination_text, .host = "", .host_class = .invalid },
                .decision = .{ .result = .deny, .reason = reason, .ci_may_proceed = false },
                .enforcement_mode = options.enforcement_mode,
                .redacted_target = target,
                .owned_reason = reason,
            };
        }
        return err;
    };

    const mode = policy.network.effectiveMode();
    const enforcement_mode = if (mode == .observe) EnforcementMode.observe_only else options.enforcement_mode;
    const deny_match = findMatch("network.deny", destination, policy.network.deny);
    var findings = try detectExfiltration(allocator, destination, policy.network.detect_exfiltration);
    errdefer if (findings.len > 0) allocator.free(findings);
    if (options.unknown_tracker) |tracker| {
        const allow_match_for_unknown = findMatch("network.allow", destination, policy.network.allow);
        const ask_match_for_unknown = findMatch("network.ask", destination, policy.network.ask);
        const service_match_for_unknown = serviceHostMatchesAny(policy.services, destination);
        const policy_unknown_domain = destination.host_class == .domain and deny_match == null and allow_match_for_unknown == null and ask_match_for_unknown == null and !service_match_for_unknown;
        if (policy_unknown_domain) {
            if (try tracker.record(destination.host)) {
                const old_len = findings.len;
                findings = try allocator.realloc(findings, old_len + 1);
                findings[old_len] = .{ .signal = .many_unknown_domains, .score = 75 };
            }
        }
    }

    const target = try redactedDestinationAlloc(allocator, destination);
    errdefer allocator.free(target);

    if (deny_match) |matched| {
        return buildDecision(allocator, destination, .deny, matched, "explicit network deny", enforcement_mode, findings, target, true, options.ci_mode);
    }
    if (try evaluateServices(allocator, policy.services, mode, destination, options.method, enforcement_mode, findings, target, options.ci_mode)) |service_decision| {
        return service_decision;
    }
    const allow_match = findMatch("network.allow", destination, policy.network.allow);
    const ask_match = findMatch("network.ask", destination, policy.network.ask);
    if (allow_match) |matched| {
        const base = if (mode == .off) schema.DecisionValue.deny else schema.DecisionValue.allow;
        return buildDecision(allocator, destination, base, matched, if (mode == .off) "network mode off" else "explicit network allow", enforcement_mode, findings, target, true, options.ci_mode);
    }
    if (ask_match) |matched| {
        const base: schema.DecisionValue = if (mode == .off or options.ci_mode or effective_mode == .ci) .deny else .ask;
        return buildDecision(allocator, destination, base, matched, if (base == .deny) "ask converted to deny in ci/off mode" else "explicit network ask", enforcement_mode, findings, target, true, options.ci_mode);
    }

    if (strictDefaultDenyReason(destination)) |reason| {
        const value: schema.DecisionValue = switch (mode) {
            .observe => .observe,
            .open => .allow,
            else => .deny,
        };
        return buildDecision(allocator, destination, value, null, reason, enforcement_mode, findings, target, true, options.ci_mode);
    }

    if (policy.network.default) |default| {
        const value = if ((effective_mode == .ci or options.ci_mode) and default == .ask) schema.DecisionValue.deny else default;
        return buildDecision(allocator, destination, value, null, "network.default", enforcement_mode, findings, target, true, options.ci_mode);
    }

    const fallback: schema.DecisionValue = switch (mode) {
        .off => .deny,
        .ask => if (effective_mode == .ci or options.ci_mode) .deny else .ask,
        .allowlist => .deny,
        .observe => .observe,
        .open => .allow,
    };
    return buildDecision(allocator, destination, fallback, null, "network mode default", enforcement_mode, findings, target, true, options.ci_mode);
}

fn decisionResultSeverity(result: core.decision.DecisionResult) u8 {
    return switch (result) {
        .deny => 4,
        .ask => 3,
        .allow => 2,
        .observe => 1,
        .redact, .stage, .broker => 1,
    };
}

/// When `effects:` is active, raise restriction for curated hosts (e.g. api.twitter.com → comms.publish).
/// Only applies when a host tag hits — does not apply effects.default to untagged destinations.
/// Used by the runtime proxy path (`ryk run`) so it matches `policy explain network`.
fn mergeNetworkEffectTags(
    allocator: std.mem.Allocator,
    policy: *const schema.Policy,
    effective_mode: schema.Mode,
    options: Options,
    decision: *Decision,
) !void {
    if (!policy.effects.isActive()) return;
    if (decision.destination.host.len == 0) return;

    const hits = try effects.network_tags.classifyHost(allocator, decision.destination.host);
    defer allocator.free(hits);
    if (hits.len == 0) return;

    const match = effects.evaluateHits(hits, .{
        .allow = policy.effects.allow,
        .deny = policy.effects.deny,
        .ask = policy.effects.ask,
        // Untagged hosts already returned above (no blanket default). For tagged hosts,
        // pass effects.default so unmatched tag ids still honor the configured default.
        .default = if (policy.effects.default) |d| switch (d) {
            .allow => .allow,
            .deny => .deny,
            .ask => .ask,
            .observe => .observe,
        } else null,
    });
    if (match.kind == .none) return;

    var value: schema.DecisionValue = switch (match.kind) {
        .allow => .allow,
        .deny => .deny,
        .ask => .ask,
        .observe => .observe,
        .none => return,
    };
    if ((effective_mode == .ci or options.ci_mode) and value == .ask) value = .deny;

    const effect_result = value.toDecisionResult();
    if (decisionResultSeverity(effect_result) <= decisionResultSeverity(decision.decision.result)) return;

    // Allocate replacements first so a failed alloc cannot leave dangling free'd pointers.
    const rule_id = try std.fmt.allocPrint(allocator, "effects.{s}", .{match.kind.toString()});
    errdefer allocator.free(rule_id);
    const reason = try std.fmt.allocPrint(
        allocator,
        "effect {s} ({s}); host={s}; enforcement={s}",
        .{ match.effect_id, match.matcher, decision.destination.host, decision.enforcement_mode.toString() },
    );
    errdefer allocator.free(reason);

    allocator.free(decision.owned_reason);
    if (decision.owned_rule_id) |old| allocator.free(old);

    decision.owned_rule_id = rule_id;
    decision.owned_reason = reason;
    decision.matched_rule = .{ .id = rule_id, .pattern = match.pattern };
    decision.decision = .{
        .result = effect_result,
        .rule_id = rule_id,
        .reason = reason,
        .risk_score = decision.decision.risk_score,
        .requires_user = effect_result == .ask,
        .ci_may_proceed = if (options.ci_mode or effective_mode == .ci)
            (effect_result == .allow or effect_result == .observe)
        else
            (effect_result != .deny),
    };
}

fn evaluateServices(
    allocator: std.mem.Allocator,
    services: []const schema.ServicePolicy,
    mode: schema.NetworkMode,
    destination: Destination,
    method: ?[]const u8,
    enforcement_mode: EnforcementMode,
    findings: []ExfilFinding,
    redacted_target: []u8,
    ci_mode: bool,
) !?Decision {
    for (services) |service| {
        if (!serviceHostMatches(service, destination)) continue;
        const method_matches = methodMatches(service.methods, method);
        if (!method_matches and service.unmatched == null) {
            return try buildServiceUnmatchedDecision(allocator, destination, .deny, service, "method not allowed", enforcement_mode, findings, redacted_target, ci_mode);
        }
        if (method_matches) {
            if (findPathMatch(service.paths.deny, destination.path)) |matched| {
                return try buildServiceDecision(allocator, destination, coerceServiceDecision(.deny, mode, ci_mode), service, "paths.deny", matched, "service path deny", enforcement_mode, findings, redacted_target, ci_mode);
            }
            if (findPathMatch(service.paths.allow, destination.path)) |matched| {
                return try buildServiceDecision(allocator, destination, coerceServiceDecision(.allow, mode, ci_mode), service, "paths.allow", matched, "service path allow", enforcement_mode, findings, redacted_target, ci_mode);
            }
        }
        if (service.unmatched) |unmatched| {
            return try buildServiceUnmatchedDecision(allocator, destination, coerceServiceDecision(unmatched, mode, ci_mode), service, if (method_matches) "service unmatched" else "method not allowed", enforcement_mode, findings, redacted_target, ci_mode);
        }
        return null;
    }
    return null;
}

fn serviceHostMatches(service: schema.ServicePolicy, destination: Destination) bool {
    for (service.hosts) |host| {
        if (matchesNetworkRule(host, destination)) return true;
    }
    return false;
}

fn serviceHostMatchesAny(services: []const schema.ServicePolicy, destination: Destination) bool {
    for (services) |service| {
        if (serviceHostMatches(service, destination)) return true;
    }
    return false;
}

fn methodMatches(methods: []const []const u8, method: ?[]const u8) bool {
    if (methods.len == 0) return true;
    if (method == null) return false;
    for (methods) |allowed| {
        if (std.mem.eql(u8, allowed, "*") or std.ascii.eqlIgnoreCase(allowed, method.?)) return true;
    }
    return false;
}

fn coerceServiceDecision(value: schema.DecisionValue, mode: schema.NetworkMode, ci_mode: bool) schema.DecisionValue {
    if (mode == .off) return .deny;
    if (ci_mode and value == .ask) return .deny;
    return value;
}

fn buildServiceUnmatchedDecision(
    allocator: std.mem.Allocator,
    destination: Destination,
    value: schema.DecisionValue,
    service: schema.ServicePolicy,
    reason_base: []const u8,
    enforcement_mode: EnforcementMode,
    findings: []ExfilFinding,
    redacted_target: []u8,
    ci_mode: bool,
) !Decision {
    const rule_id = try std.fmt.allocPrint(allocator, "services.{s}.unmatched", .{service.name});
    const reason_label = try serviceReasonLabel(allocator, reason_base, service);
    defer allocator.free(reason_label);
    return try buildDecisionWithRuleId(allocator, destination, value, rule_id, "unmatched", reason_label, enforcement_mode, findings, redacted_target, true, ci_mode);
}

fn findPathMatch(patterns: []const []const u8, raw_path: []const u8) ?Match {
    const path = if (raw_path.len == 0) "/" else raw_path;
    for (patterns, 0..) |pattern, index| {
        if (matchers.matchesPattern(pattern, path)) return .{ .label = "", .index = index, .pattern = pattern };
    }
    return null;
}

fn buildServiceDecision(
    allocator: std.mem.Allocator,
    destination: Destination,
    value: schema.DecisionValue,
    service: schema.ServicePolicy,
    label_suffix: []const u8,
    matched: Match,
    reason_label: []const u8,
    enforcement_mode: EnforcementMode,
    findings: []ExfilFinding,
    redacted_target: []u8,
    ci_mode: bool,
) !Decision {
    const label = try std.fmt.allocPrint(allocator, "services.{s}.{s}", .{ service.name, label_suffix });
    defer allocator.free(label);
    const reason = try serviceReasonLabel(allocator, reason_label, service);
    defer allocator.free(reason);
    return buildDecision(allocator, destination, value, .{ .label = label, .index = matched.index, .pattern = matched.pattern }, reason, enforcement_mode, findings, redacted_target, true, ci_mode);
}

fn serviceReasonLabel(allocator: std.mem.Allocator, base: []const u8, service: schema.ServicePolicy) ![]u8 {
    if (service.credentials.use != null) {
        return std.fmt.allocPrint(allocator, "{s}; service={s}; credential_ref=configured", .{ base, service.name });
    }
    return std.fmt.allocPrint(allocator, "{s}; service={s}", .{ base, service.name });
}

pub fn detectExfiltration(allocator: std.mem.Allocator, destination: Destination, config: schema.ExfiltrationDetection) ![]ExfilFinding {
    var findings: std.ArrayList(ExfilFinding) = .empty;
    errdefer findings.deinit(allocator);

    if (config.long_query_strings and destination.query.len >= 120) try findings.append(allocator, .{ .signal = .long_query_string, .score = 70 });
    if (config.secret_patterns and urlContainsSecret(destination)) try findings.append(allocator, .{ .signal = .secret_like_url_value, .score = 95 });
    if (destination.host_class == .direct_ip) try findings.append(allocator, .{ .signal = .direct_ip_destination, .score = 70 });
    if (isPasteSite(destination.host)) try findings.append(allocator, .{ .signal = .paste_site_destination, .score = 85 });
    if (isWebhookOrRequestBin(destination.host)) try findings.append(allocator, .{ .signal = .webhook_request_bin_destination, .score = 90 });
    if (isTunnelingService(destination.host)) try findings.append(allocator, .{ .signal = .tunneling_service_destination, .score = 85 });
    if (config.dns and hasHighEntropyDnsLabel(destination.host)) try findings.append(allocator, .{ .signal = .high_entropy_dns_label, .score = 75 });
    if (config.dns and hasLongSubdomain(destination.host)) try findings.append(allocator, .{ .signal = .long_subdomain, .score = 65 });
    if (hasBase64LikeComponent(destination.path) or hasBase64LikeComponent(destination.query)) try findings.append(allocator, .{ .signal = .base64_like_url_component, .score = 70 });

    return try findings.toOwnedSlice(allocator);
}

pub fn redactedDestinationAlloc(allocator: std.mem.Allocator, destination: Destination) ![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    if (destination.scheme) |scheme| {
        try list.appendSlice(allocator, scheme);
        try list.appendSlice(allocator, "://");
    }
    try list.appendSlice(allocator, destination.host);
    if (destination.port) |port| {
        var list_aw: std.Io.Writer.Allocating = .init(allocator);
        errdefer list_aw.deinit();
        try list_aw.writer.print(":{d}", .{port});
        try list_aw.writer.flush();
        var port_suffix = list_aw.toArrayList();
        defer port_suffix.deinit(allocator);
        try list.appendSlice(allocator, port_suffix.items);
    }
    if (destination.path.len > 0) try appendRedactedUrlPart(allocator, &list, destination.path, false);
    if (destination.query.len > 0) {
        try list.append(allocator, '?');
        try appendRedactedUrlPart(allocator, &list, destination.query, true);
    }
    return try list.toOwnedSlice(allocator);
}

/// Inject ryk loopback proxy mediation into the child env map.
///
/// Sets **both** uppercase and lowercase of `HTTP_PROXY`, `HTTPS_PROXY`,
/// `ALL_PROXY`, and `NO_PROXY` so host lowercase proxies cannot bypass ryk
/// inject (M-3 / fn-security-1). `put` overwrites any pre-existing host values
/// for those keys. Callers should prefer this after host env filtering and
/// before attach allowlist so loopback wins.
pub fn appendProxyEnvironment(env_map: *std.process.Environ.Map, proxy_url: []const u8, no_proxy: []const u8) !void {
    try env_map.put("HTTP_PROXY", proxy_url);
    try env_map.put("http_proxy", proxy_url);
    try env_map.put("HTTPS_PROXY", proxy_url);
    try env_map.put("https_proxy", proxy_url);
    try env_map.put("ALL_PROXY", proxy_url);
    try env_map.put("all_proxy", proxy_url);
    try env_map.put("NO_PROXY", no_proxy);
    try env_map.put("no_proxy", no_proxy);
    try env_map.put("RYK_NETWORK_ENFORCEMENT", "proxy-mediated");
    try env_map.put("RYK_PROXY_ROUTE_FORCED", "false");
}

fn buildDecision(
    allocator: std.mem.Allocator,
    destination: Destination,
    value: schema.DecisionValue,
    matched: ?Match,
    reason_label: []const u8,
    enforcement_mode: EnforcementMode,
    findings: []ExfilFinding,
    redacted_target: []u8,
    owns_findings: bool,
    ci_mode: bool,
) !Decision {
    const result = value.toDecisionResult();
    var rule_id: ?[]u8 = null;
    var matched_rule: ?schema.RuleRef = null;
    if (matched) |item| {
        rule_id = try std.fmt.allocPrint(allocator, "{s}[{d}]", .{ item.label, item.index });
        matched_rule = .{ .id = rule_id.?, .pattern = item.pattern };
    }
    errdefer if (rule_id) |owned| allocator.free(owned);

    const reason = try formatReason(allocator, reason_label, destination, enforcement_mode, findings);
    errdefer allocator.free(reason);
    return .{
        .destination = destination,
        .decision = .{
            .result = result,
            .rule_id = rule_id,
            .reason = reason,
            .risk_score = maxRisk(findings),
            .requires_user = result == .ask,
            .ci_may_proceed = if (ci_mode) (result == .allow or result == .observe) else (result != .deny),
        },
        .matched_rule = matched_rule,
        .enforcement_mode = enforcement_mode,
        .exfil_findings = findings,
        .redacted_target = redacted_target,
        .owned_reason = reason,
        .owned_rule_id = rule_id,
        .owned_findings = owns_findings,
    };
}

fn buildDecisionWithRuleId(
    allocator: std.mem.Allocator,
    destination: Destination,
    value: schema.DecisionValue,
    owned_rule_id: []u8,
    pattern: []const u8,
    reason_label: []const u8,
    enforcement_mode: EnforcementMode,
    findings: []ExfilFinding,
    redacted_target: []u8,
    owns_findings: bool,
    ci_mode: bool,
) !Decision {
    errdefer allocator.free(owned_rule_id);
    const result = value.toDecisionResult();
    const reason = try formatReason(allocator, reason_label, destination, enforcement_mode, findings);
    errdefer allocator.free(reason);
    return .{
        .destination = destination,
        .decision = .{
            .result = result,
            .rule_id = owned_rule_id,
            .reason = reason,
            .risk_score = maxRisk(findings),
            .requires_user = result == .ask,
            .ci_may_proceed = if (ci_mode) (result == .allow or result == .observe) else (result != .deny),
        },
        .matched_rule = .{ .id = owned_rule_id, .pattern = pattern },
        .enforcement_mode = enforcement_mode,
        .exfil_findings = findings,
        .redacted_target = redacted_target,
        .owned_reason = reason,
        .owned_rule_id = owned_rule_id,
        .owned_findings = owns_findings,
    };
}

fn formatReason(allocator: std.mem.Allocator, reason_label: []const u8, destination: Destination, enforcement_mode: EnforcementMode, findings: []ExfilFinding) ![]u8 {
    if (findings.len == 0) {
        return std.fmt.allocPrint(allocator, "{s}; host={s}; enforcement={s}", .{ reason_label, destination.host, enforcement_mode.toString() });
    }
    return std.fmt.allocPrint(allocator, "{s}; host={s}; enforcement={s}; risk={s}", .{ reason_label, destination.host, enforcement_mode.toString(), findings[0].signal.reason() });
}

fn maxRisk(findings: []const ExfilFinding) ?u8 {
    if (findings.len == 0) return null;
    var max: u8 = 0;
    for (findings) |finding| max = @max(max, finding.score);
    return max;
}

fn findMatch(label: []const u8, destination: Destination, rules: []const []const u8) ?Match {
    for (rules, 0..) |pattern, index| {
        if (matchesNetworkRule(pattern, destination)) return .{ .label = label, .index = index, .pattern = pattern };
    }
    return null;
}

pub fn matchesNetworkRule(pattern: []const u8, destination: Destination) bool {
    if (std.mem.indexOfScalar(u8, pattern, ':')) |colon| {
        const maybe_port = std.fmt.parseInt(u16, pattern[colon + 1 ..], 10) catch null;
        if (maybe_port) |rule_port| {
            if (destination.port == null or destination.port.? != rule_port) return false;
            return matchesHostPattern(pattern[0..colon], destination);
        }
    }
    return matchesHostPattern(pattern, destination);
}

fn matchesHostPattern(pattern: []const u8, destination: Destination) bool {
    if (std.ascii.eqlIgnoreCase(pattern, "localhost")) return destination.host_class == .localhost;
    if (std.ascii.eqlIgnoreCase(pattern, "private") or std.ascii.eqlIgnoreCase(pattern, "private:*")) return destination.host_class == .private_network;
    if (std.ascii.eqlIgnoreCase(pattern, "metadata") or std.ascii.eqlIgnoreCase(pattern, "cloud-metadata")) return destination.host_class == .cloud_metadata;
    if (std.ascii.eqlIgnoreCase(pattern, "direct-ip")) return destination.host_class == .direct_ip;
    return matchers.matchesDomain(pattern, destination.host);
}

fn strictDefaultDenyReason(destination: Destination) ?[]const u8 {
    return switch (destination.host_class) {
        .direct_ip => "direct IP destinations deny by default",
        .localhost => "localhost destinations deny by default",
        .private_network => "private network destinations deny by default",
        .cloud_metadata => "cloud metadata endpoints deny by default",
        .invalid => "invalid destination denies by default",
        .domain => null,
    };
}

fn classifyHost(host: []const u8) HostClass {
    if (isLocalhost(host)) return .localhost;
    if (isCloudMetadataHost(host)) return .cloud_metadata;
    if (parseIpv4(host)) |ip| {
        if (isCloudMetadataIp(ip)) return .cloud_metadata;
        if (isLocalhostIp(ip)) return .localhost;
        if (isPrivateIpv4(ip)) return .private_network;
        return .direct_ip;
    }
    if (std.mem.indexOfScalar(u8, host, ':') != null) {
        if (std.ascii.eqlIgnoreCase(host, "::1")) return .localhost;
        if (std.ascii.startsWithIgnoreCase(host, "fe80:")) return .private_network;
        return .direct_ip;
    }
    if (!validDomain(host)) return .invalid;
    return .domain;
}

fn parsePort(value: []const u8) !u16 {
    if (value.len == 0) return error.InvalidNetworkDestination;
    return std.fmt.parseInt(u16, value, 10) catch return error.InvalidNetworkDestination;
}

fn trimTrailingDot(value: []const u8) []const u8 {
    if (value.len > 0 and value[value.len - 1] == '.') return value[0 .. value.len - 1];
    return value;
}

fn validDomain(host: []const u8) bool {
    if (host.len == 0) return false;
    var labels = std.mem.splitScalar(u8, host, '.');
    while (labels.next()) |label| {
        if (label.len == 0 or label.len > 63) return false;
        if (label[0] == '-' or label[label.len - 1] == '-') return false;
        for (label) |char| {
            if (!(std.ascii.isAlphanumeric(char) or char == '-')) return false;
        }
    }
    return true;
}

fn isLocalhost(host: []const u8) bool {
    return std.ascii.eqlIgnoreCase(host, "localhost") or std.ascii.endsWithIgnoreCase(host, ".localhost");
}

fn isCloudMetadataHost(host: []const u8) bool {
    return std.ascii.eqlIgnoreCase(host, "metadata.google.internal") or
        std.ascii.eqlIgnoreCase(host, "metadata") or
        std.ascii.eqlIgnoreCase(host, "169.254.169.254");
}

fn parseIpv4(host: []const u8) ?[4]u8 {
    var out: [4]u8 = undefined;
    var parts = std.mem.splitScalar(u8, host, '.');
    var index: usize = 0;
    while (parts.next()) |part| {
        if (index >= 4 or part.len == 0) return null;
        out[index] = std.fmt.parseInt(u8, part, 10) catch return null;
        index += 1;
    }
    if (index != 4) return null;
    return out;
}

fn isLocalhostIp(ip: [4]u8) bool {
    return ip[0] == 127;
}

fn isCloudMetadataIp(ip: [4]u8) bool {
    return ip[0] == 169 and ip[1] == 254 and ip[2] == 169 and ip[3] == 254;
}

fn isPrivateIpv4(ip: [4]u8) bool {
    return ip[0] == 10 or
        (ip[0] == 172 and ip[1] >= 16 and ip[1] <= 31) or
        (ip[0] == 192 and ip[1] == 168) or
        (ip[0] == 169 and ip[1] == 254);
}

fn isPasteSite(host: []const u8) bool {
    return hostMatchesAny(host, &.{ "pastebin.com", "*.pastebin.com", "gist.github.com", "hastebin.com", "*.hastebin.com" });
}

fn isWebhookOrRequestBin(host: []const u8) bool {
    return hostMatchesAny(host, &.{ "*.requestbin.net", "requestbin.net", "*.webhook.site", "webhook.site", "*.pipipedream.net", "*.pipedream.net" });
}

fn isTunnelingService(host: []const u8) bool {
    return hostMatchesAny(host, &.{ "*.ngrok.io", "*.ngrok-free.app", "*.trycloudflare.com", "*.loca.lt", "*.localtunnel.me", "*.serveo.net" });
}

/// Public: cloud metadata class hostnames (IMDS / GCE metadata).
/// Shared with discovery extract so allowlist cannot short-circuit class deny.
pub fn isCloudMetadataHostname(host: []const u8) bool {
    return isCloudMetadataHost(host);
}

/// Public: paste / webhook / tunnel exfil sinks. Shared with discovery soft-drop
/// so agent-writable auth cannot self-grant sinks that eval would flag.
pub fn isExfilSinkHostname(host: []const u8) bool {
    return isPasteSite(host) or isWebhookOrRequestBin(host) or isTunnelingService(host);
}

// ---------------------------------------------------------------------------
// Post-DNS-resolution fence (P1-6)
// ---------------------------------------------------------------------------

/// Classify a resolved IP into the same HostClass fences `classifyHost` applies
/// to destination text, plus IPv6 cases the text path only approximates
/// (v4-mapped ::ffff:a.b.c.d, fc00::/7 ULA). Byte-based so OS resolver output
/// needs no re-parse.
pub fn classifyResolvedIp(ip: std.Io.net.IpAddress) HostClass {
    return switch (ip) {
        .ip4 => |a| classifyIpv4Bytes(a.bytes),
        .ip6 => |a| classifyIpv6Bytes(a.bytes),
    };
}

fn classifyIpv4Bytes(ip: [4]u8) HostClass {
    if (isCloudMetadataIp(ip)) return .cloud_metadata;
    if (isLocalhostIp(ip)) return .localhost;
    // 0/8 is "this network" (RFC 1122): connect() to 0.0.0.0 routes to loopback
    // on Linux/macOS, so unspecified answers are loopback-class, not direct_ip.
    if (ip[0] == 0) return .localhost;
    if (isPrivateIpv4(ip)) return .private_network;
    return .direct_ip;
}

fn classifyIpv6Bytes(bytes: [16]u8) HostClass {
    // v4-mapped (::ffff:a.b.c.d) inherits the embedded IPv4 class.
    if (std.mem.allEqual(u8, bytes[0..10], 0) and bytes[10] == 0xff and bytes[11] == 0xff) {
        return classifyIpv4Bytes(bytes[12..16].*);
    }
    if (std.mem.allEqual(u8, bytes[0..15], 0) and bytes[15] == 1) return .localhost; // ::1
    // Deprecated v4-compatible (::a.b.c.d, RFC 4291) and the v6 unspecified
    // address (::) embed IPv4 in the low 32 bits — inherit that class so ::
    // fences as loopback (0.0.0.0) and ::127.0.0.1 cannot slip loopback through.
    if (std.mem.allEqual(u8, bytes[0..12], 0)) {
        return classifyIpv4Bytes(bytes[12..16].*);
    }
    if (bytes[0] == 0xfe and (bytes[1] & 0xc0) == 0x80) return .private_network; // fe80::/10 link-local
    if ((bytes[0] & 0xfe) == 0xfc) return .private_network; // fc00::/7 unique-local
    return .direct_ip;
}

pub const ResolvedAddressFence = struct {
    allowed: bool,
    host_class: HostClass,
    /// Static reason text when `allowed` is false.
    reason: []const u8 = "",
};

/// Post-resolution fence for the intercept proxy: a hostname allow covers
/// public-unicast DNS answers only. Loopback, private/link-local, and
/// cloud-metadata answers require an explicit class-token (`localhost`,
/// `private`, `metadata`) or exact-IP rule in `network.allow`; otherwise the
/// resolved address is denied (DNS-rebinding fence). `direct_ip` answers pass:
/// public unicast is the expected resolution of an allowlisted hostname.
pub fn resolvedAddressFence(policy: *const schema.Policy, ip: std.Io.net.IpAddress, port: ?u16) ResolvedAddressFence {
    const host_class = classifyResolvedIp(ip);
    switch (host_class) {
        .domain, .direct_ip => return .{ .allowed = true, .host_class = host_class },
        else => {},
    }
    var text_buf: [48]u8 = undefined;
    const ip_text = formatResolvedIpText(&text_buf, ip) catch return .{
        .allowed = false,
        .host_class = host_class,
        .reason = "resolved address could not be classified",
    };
    const destination: Destination = .{
        .raw = ip_text,
        .host = ip_text,
        .port = port,
        .host_class = host_class,
    };
    if (findMatch("network.allow", destination, policy.network.allow) != null) {
        return .{ .allowed = true, .host_class = host_class };
    }
    return .{
        .allowed = false,
        .host_class = host_class,
        .reason = strictDefaultDenyReason(destination) orelse "resolved address class denied by default",
    };
}

/// IP text without port for rule matching (exact-IP allow rules compare strings).
fn formatResolvedIpText(buf: []u8, ip: std.Io.net.IpAddress) ![]u8 {
    var writer: std.Io.Writer = .fixed(buf);
    switch (ip) {
        .ip4 => |a| try writer.print("{d}.{d}.{d}.{d}", .{ a.bytes[0], a.bytes[1], a.bytes[2], a.bytes[3] }),
        .ip6 => |a| {
            const unresolved: std.Io.net.Ip6Address.Unresolved = .{ .bytes = a.bytes, .interface_name = null };
            try writer.print("{f}", .{unresolved});
        },
    }
    return writer.buffered();
}

fn hostMatchesAny(host: []const u8, patterns: []const []const u8) bool {
    for (patterns) |pattern| {
        if (matchers.matchesDomain(pattern, host)) return true;
    }
    return false;
}

fn hasHighEntropyDnsLabel(host: []const u8) bool {
    var labels = std.mem.splitScalar(u8, host, '.');
    while (labels.next()) |label| {
        if (label.len >= 24 and entropyish(label)) return true;
    }
    return false;
}

fn hasLongSubdomain(host: []const u8) bool {
    var labels = std.mem.splitScalar(u8, host, '.');
    var index: usize = 0;
    while (labels.next()) |label| : (index += 1) {
        if (index == 0 and label.len >= 48) return true;
    }
    return false;
}

fn hasBase64LikeComponent(value: []const u8) bool {
    var tokens = std.mem.tokenizeAny(u8, value, "/?&=._-");
    while (tokens.next()) |token| {
        if (token.len >= 32 and base64ish(token)) return true;
    }
    return false;
}

fn entropyish(value: []const u8) bool {
    if (value.len < 24) return false;
    var classes: u8 = 0;
    var unique = [_]bool{false} ** 256;
    var unique_count: usize = 0;
    for (value) |char| {
        if (std.ascii.isUpper(char)) classes |= 1 else if (std.ascii.isLower(char)) classes |= 2 else if (std.ascii.isDigit(char)) classes |= 4 else if (char == '-' or char == '_') classes |= 8 else return false;
        if (!unique[char]) {
            unique[char] = true;
            unique_count += 1;
        }
    }
    return @popCount(classes) >= 2 and unique_count >= 14;
}

fn base64ish(value: []const u8) bool {
    var useful: usize = 0;
    for (value) |char| {
        if (std.ascii.isAlphanumeric(char) or char == '+' or char == '/' or char == '_' or char == '-' or char == '=') {
            useful += 1;
        } else return false;
    }
    return useful >= 32 and entropyish(value[0..@min(value.len, 64)]);
}

fn urlContainsSecret(destination: Destination) bool {
    return urlPartContainsSecret(destination.path) or urlPartContainsSecret(destination.query);
}

fn appendRedactedUrlPart(allocator: std.mem.Allocator, list: *std.ArrayList(u8), value: []const u8, query: bool) !void {
    const separators = if (query) "&;" else "/";
    var cursor: usize = 0;
    while (cursor < value.len) {
        const next = std.mem.indexOfAnyPos(u8, value, cursor, separators) orelse value.len;
        const part = value[cursor..next];
        var buf: [256]u8 = undefined;
        const redacted = redactUrlPartBounded(allocator, part, &buf);
        try list.appendSlice(allocator, redacted);
        if (next == value.len) break;
        try list.append(allocator, value[next]);
        cursor = next + 1;
    }
}

fn urlPartContainsSecret(part: []const u8) bool {
    if (audit_redact.classifyString(part) != null) return true;
    var buf: [1024]u8 = undefined;
    if (percentDecodeBounded(part, &buf)) |decoded| {
        return audit_redact.classifyString(decoded) != null;
    }
    return false;
}

fn redactUrlPartBounded(allocator: std.mem.Allocator, part: []const u8, buffer: []u8) []const u8 {
    const direct = audit_redact.redactStringBounded(part, buffer);
    if (direct.ptr != part.ptr or direct.len != part.len) return direct;
    const decoded = percentDecodeAlloc(allocator, part) catch return part;
    defer allocator.free(decoded);
    if (audit_redact.classifyString(decoded) != null) {
        return audit_redact.redactStringBounded(decoded, buffer);
    }
    return part;
}

fn percentDecodeBounded(value: []const u8, buffer: []u8) ?[]const u8 {
    if (value.len > buffer.len) return null;
    var out: usize = 0;
    var i: usize = 0;
    var changed = false;
    while (i < value.len) {
        if (value[i] == '%' and i + 2 < value.len) {
            const hi = hexValue(value[i + 1]);
            const lo = hexValue(value[i + 2]);
            if (hi != null and lo != null) {
                buffer[out] = (hi.? << 4) | lo.?;
                out += 1;
                i += 3;
                changed = true;
                continue;
            }
        }
        buffer[out] = value[i];
        out += 1;
        i += 1;
    }
    if (!changed) return null;
    return buffer[0..out];
}

fn percentDecodeAlloc(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, value.len);
    if (percentDecodeBounded(value, out)) |decoded| {
        const exact = try allocator.dupe(u8, decoded);
        allocator.free(out);
        return exact;
    }
    allocator.free(out);
    return error.NoPercentEncoding;
}

fn hexValue(char: u8) ?u8 {
    if (char >= '0' and char <= '9') return char - '0';
    if (char >= 'a' and char <= 'f') return 10 + char - 'a';
    if (char >= 'A' and char <= 'F') return 10 + char - 'A';
    return null;
}

test "network decision allows exact and wildcard domains" {
    const load = @import("load.zig");
    var policy = try load.parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\network:
        \\  mode: allowlist
        \\  allow:
        \\    - "api.github.com"
        \\    - "*.github.com"
    , "network.yaml");
    defer policy.deinit();

    var exact = try evaluate(std.testing.allocator, &policy, .strict, "https://api.github.com/repos", .{});
    defer exact.deinit(std.testing.allocator);
    try std.testing.expectEqual(core.decision.DecisionResult.allow, exact.decision.result);
    try std.testing.expectEqualStrings("network.allow[0]", exact.decision.rule_id.?);

    var wildcard = try evaluate(std.testing.allocator, &policy, .strict, "uploads.github.com", .{});
    defer wildcard.deinit(std.testing.allocator);
    try std.testing.expectEqual(core.decision.DecisionResult.allow, wildcard.decision.result);
    try std.testing.expectEqualStrings("network.allow[1]", wildcard.decision.rule_id.?);
}

test "deny beats allow and unknown ask denies in ci" {
    const load = @import("load.zig");
    var policy = try load.parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: ci
        \\network:
        \\  mode: ask
        \\  allow:
        \\    - "*.github.com"
        \\  ask:
        \\    - "*.githubusercontent.com"
        \\  deny:
        \\    - "api.github.com"
    , "network.yaml");
    defer policy.deinit();

    var denied = try evaluate(std.testing.allocator, &policy, .ci, "api.github.com", .{ .ci_mode = true });
    defer denied.deinit(std.testing.allocator);
    try std.testing.expectEqual(core.decision.DecisionResult.deny, denied.decision.result);
    try std.testing.expectEqualStrings("network.deny[0]", denied.decision.rule_id.?);

    var ask = try evaluate(std.testing.allocator, &policy, .ci, "raw.githubusercontent.com", .{ .ci_mode = true });
    defer ask.deinit(std.testing.allocator);
    try std.testing.expectEqual(core.decision.DecisionResult.deny, ask.decision.result);
}

test "strict defaults deny direct localhost private and metadata destinations" {
    const load = @import("load.zig");
    var policy = try load.parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\network:
        \\  mode: allowlist
    , "network.yaml");
    defer policy.deinit();

    const values = [_][]const u8{ "8.8.8.8", "localhost:3000", "192.168.1.2", "169.254.169.254" };
    for (values) |value| {
        var result = try evaluate(std.testing.allocator, &policy, .strict, value, .{});
        defer result.deinit(std.testing.allocator);
        try std.testing.expectEqual(core.decision.DecisionResult.deny, result.decision.result);
    }
}

test "resolved address fence denies loopback private and metadata answers by default" {
    const load = @import("load.zig");
    var policy = try load.parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\network:
        \\  mode: allowlist
        \\  allow:
        \\    - "api.example.com"
    , "network.yaml");
    defer policy.deinit();

    // DNS-rebinding shapes: an allowlisted hostname answering with fenced classes.
    const denied_cases = [_]struct { text: []const u8, class: HostClass }{
        .{ .text = "169.254.169.254", .class = .cloud_metadata },
        .{ .text = "127.0.0.1", .class = .localhost },
        .{ .text = "127.55.66.77", .class = .localhost },
        .{ .text = "10.0.0.9", .class = .private_network },
        .{ .text = "172.16.0.1", .class = .private_network },
        .{ .text = "192.168.1.7", .class = .private_network },
        .{ .text = "169.254.1.1", .class = .private_network }, // link-local
        .{ .text = "::1", .class = .localhost },
        .{ .text = "::ffff:127.0.0.1", .class = .localhost }, // v4-mapped
        .{ .text = "::ffff:169.254.169.254", .class = .cloud_metadata },
        .{ .text = "fc00::1", .class = .private_network }, // ULA
        .{ .text = "fe80::1", .class = .private_network }, // v6 link-local
        // Loopback aliases (review 2026-08-13): connect() to the unspecified
        // address routes to loopback on Linux/macOS, so 0/8 and :: must not
        // pass the fence as direct_ip.
        .{ .text = "0.0.0.0", .class = .localhost },
        .{ .text = "0.1.2.3", .class = .localhost }, // 0/8 "this network" (RFC 1122)
        .{ .text = "::", .class = .localhost }, // v6 unspecified
        .{ .text = "::ffff:0.0.0.0", .class = .localhost }, // v4-mapped unspecified
    };
    for (denied_cases) |case| {
        const ip = try std.Io.net.IpAddress.parse(case.text, 443);
        const fence = resolvedAddressFence(&policy, ip, 443);
        try std.testing.expect(!fence.allowed);
        try std.testing.expectEqual(case.class, fence.host_class);
        try std.testing.expect(fence.reason.len > 0);
    }

    // Deprecated v4-compatible form (::a.b.c.d, RFC 4291): Zig's parser rejects
    // the text, but a hostile AAAA answer can still carry these bytes — the
    // embedded IPv4 class must apply (here: loopback).
    const v4_compatible_loopback = std.Io.net.IpAddress{ .ip6 = .{
        .bytes = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 0, 0, 1 },
        .port = 443,
        .interface = .none,
    } };
    const v4_compat_fence = resolvedAddressFence(&policy, v4_compatible_loopback, 443);
    try std.testing.expect(!v4_compat_fence.allowed);
    try std.testing.expectEqual(HostClass.localhost, v4_compat_fence.host_class);

    // Public unicast answers pass: the expected resolution of an allowlisted host.
    const public_ip = try std.Io.net.IpAddress.parse("93.184.216.34", 443);
    const public_fence = resolvedAddressFence(&policy, public_ip, 443);
    try std.testing.expect(public_fence.allowed);
    try std.testing.expectEqual(HostClass.direct_ip, public_fence.host_class);
}

test "resolved address fence lifts only on explicit class or exact-IP allow" {
    const load = @import("load.zig");
    var class_policy = try load.parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\network:
        \\  mode: allowlist
        \\  allow:
        \\    - "localhost"
    , "network.yaml");
    defer class_policy.deinit();

    const loopback = try std.Io.net.IpAddress.parse("127.0.0.1", 443);
    try std.testing.expect(resolvedAddressFence(&class_policy, loopback, 443).allowed);
    // A class allow does not lift other fenced classes.
    const metadata = try std.Io.net.IpAddress.parse("169.254.169.254", 443);
    try std.testing.expect(!resolvedAddressFence(&class_policy, metadata, 443).allowed);
    const private_ip = try std.Io.net.IpAddress.parse("10.0.0.9", 443);
    try std.testing.expect(!resolvedAddressFence(&class_policy, private_ip, 443).allowed);

    var exact_policy = try load.parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\network:
        \\  mode: allowlist
        \\  allow:
        \\    - "10.0.0.9"
    , "network.yaml");
    defer exact_policy.deinit();
    try std.testing.expect(resolvedAddressFence(&exact_policy, private_ip, 443).allowed);
    try std.testing.expect(!resolvedAddressFence(&exact_policy, loopback, 443).allowed);
}

test "unknown domain denies in allowlist mode" {
    const load = @import("load.zig");
    var policy = try load.parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\network:
        \\  mode: allowlist
        \\  allow:
        \\    - "api.github.com"
    , "network.yaml");
    defer policy.deinit();

    var result = try evaluate(std.testing.allocator, &policy, .strict, "unknown.example.com", .{});
    defer result.deinit(std.testing.allocator);
    try std.testing.expectEqual(core.decision.DecisionResult.deny, result.decision.result);
}

test "service-aware network policy allows scoped github issue and pull requests" {
    const load = @import("load.zig");
    var policy = try load.parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\services:
        \\  github:
        \\    hosts:
        \\      - "api.github.com"
        \\    methods:
        \\      - "GET"
        \\      - "POST"
        \\    paths:
        \\      allow:
        \\        - "/repos/*/issues"
        \\        - "/repos/*/pulls"
        \\      deny:
        \\        - "/user/keys"
        \\        - "/orgs/*/secrets/*"
        \\    credentials:
        \\      use: github_pat
        \\    unmatched: deny
    , "network-services.yaml");
    defer policy.deinit();

    var allowed = try evaluate(std.testing.allocator, &policy, .strict, "https://api.github.com/repos/ryk/ryk/issues", .{ .method = "POST" });
    defer allowed.deinit(std.testing.allocator);
    try std.testing.expectEqual(core.decision.DecisionResult.allow, allowed.decision.result);
    try std.testing.expectEqualStrings("services.github.paths.allow[0]", allowed.decision.rule_id.?);
    try std.testing.expect(std.mem.indexOf(u8, allowed.decision.reason, "credential_ref=configured") != null);

    var denied = try evaluate(std.testing.allocator, &policy, .strict, "https://api.github.com/user/keys", .{ .method = "GET" });
    defer denied.deinit(std.testing.allocator);
    try std.testing.expectEqual(core.decision.DecisionResult.deny, denied.decision.result);
    try std.testing.expectEqualStrings("services.github.paths.deny[0]", denied.decision.rule_id.?);

    var unmatched = try evaluate(std.testing.allocator, &policy, .strict, "https://api.github.com/repos/ryk/ryk/actions/secrets", .{ .method = "GET" });
    defer unmatched.deinit(std.testing.allocator);
    try std.testing.expectEqual(core.decision.DecisionResult.deny, unmatched.decision.result);
    try std.testing.expectEqualStrings("services.github.unmatched", unmatched.decision.rule_id.?);
}

test "service-aware network policy honors network off ci ask conversion and method scope" {
    const load = @import("load.zig");
    var off_policy = try load.parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\network:
        \\  mode: off
        \\services:
        \\  github:
        \\    hosts:
        \\      - "api.github.com"
        \\    paths:
        \\      allow:
        \\        - "/repos/*/issues"
    , "network-off-services.yaml");
    defer off_policy.deinit();

    var off = try evaluate(std.testing.allocator, &off_policy, .strict, "https://api.github.com/repos/ryk/ryk/issues", .{});
    defer off.deinit(std.testing.allocator);
    try std.testing.expectEqual(core.decision.DecisionResult.deny, off.decision.result);

    var ci_policy = try load.parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: ci
        \\services:
        \\  github:
        \\    hosts:
        \\      - "*.known-service.example"
        \\    paths:
        \\      allow:
        \\        - "/repos/*/issues"
        \\    unmatched: ask
    , "network-ci-services.yaml");
    defer ci_policy.deinit();

    var ci_unmatched = try evaluate(std.testing.allocator, &ci_policy, .ci, "https://api.github.com/user/keys", .{ .ci_mode = true });
    defer ci_unmatched.deinit(std.testing.allocator);
    try std.testing.expectEqual(core.decision.DecisionResult.deny, ci_unmatched.decision.result);
    try std.testing.expect(!ci_unmatched.decision.requires_user);

    var method_policy = try load.parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\services:
        \\  github:
        \\    hosts:
        \\      - "api.github.com"
        \\    methods:
        \\      - "GET"
        \\    paths:
        \\      allow:
        \\        - "/repos/*/issues"
        \\    unmatched: deny
    , "network-method-services.yaml");
    defer method_policy.deinit();

    var missing_method = try evaluate(std.testing.allocator, &method_policy, .strict, "https://api.github.com/repos/ryk/ryk/issues", .{});
    defer missing_method.deinit(std.testing.allocator);
    try std.testing.expectEqual(core.decision.DecisionResult.deny, missing_method.decision.result);

    var post_method = try evaluate(std.testing.allocator, &method_policy, .strict, "https://api.github.com/repos/ryk/ryk/issues", .{ .method = "POST" });
    defer post_method.deinit(std.testing.allocator);
    try std.testing.expectEqual(core.decision.DecisionResult.deny, post_method.decision.result);
}

test "exfiltration heuristics flag required URL and host patterns" {
    const config: schema.ExfiltrationDetection = .{};
    var long_query_buf: [180]u8 = undefined;
    @memset(&long_query_buf, 'a');
    const long_url = try std.fmt.allocPrint(std.testing.allocator, "https://example.com/path?q={s}", .{&long_query_buf});
    defer std.testing.allocator.free(long_url);

    const cases = [_]struct {
        url: []const u8,
        signal: ExfilSignal,
    }{
        .{ .url = long_url, .signal = .long_query_string },
        .{ .url = "https://example.com/dGhpcy1sb29rcy1saWtlLWJhc2U2NC1leGZpbC1wYXlsb2FkMTIzNDU2", .signal = .base64_like_url_component },
        .{ .url = "https://a8F3kLm9PqR2sTu7VwXyZ012345.example.com", .signal = .high_entropy_dns_label },
        .{ .url = "https://pastebin.com/abc", .signal = .paste_site_destination },
        .{ .url = "https://demo.requestbin.net/abc", .signal = .webhook_request_bin_destination },
        .{ .url = "https://demo.ngrok.io/abc", .signal = .tunneling_service_destination },
        .{ .url = "https://example.com/?token=sk-fakeSyntheticOpenAIKey1234567890", .signal = .secret_like_url_value },
    };
    for (cases) |case| {
        const destination = try parseDestination(case.url);
        const findings = try detectExfiltration(std.testing.allocator, destination, config);
        defer std.testing.allocator.free(findings);
        var found = false;
        for (findings) |finding| {
            if (finding.signal == case.signal) found = true;
        }
        try std.testing.expect(found);
    }
}

test "redacted network targets do not include fake secrets" {
    const destination = try parseDestination("https://example.com/path?token=sk-fakeSyntheticOpenAIKey1234567890&ok=1");
    const redacted = try redactedDestinationAlloc(std.testing.allocator, destination);
    defer std.testing.allocator.free(redacted);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "sk-fakeSyntheticOpenAIKey") == null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "[REDACTED") != null);
}

test "percent-encoded secret URL values are detected and redacted" {
    const destination = try parseDestination("https://example.com/path?token=sk%2DfakeSyntheticOpenAIKey1234567890");
    const findings = try detectExfiltration(std.testing.allocator, destination, .{});
    defer std.testing.allocator.free(findings);
    var found = false;
    for (findings) |finding| {
        if (finding.signal == .secret_like_url_value) found = true;
    }
    try std.testing.expect(found);

    const redacted = try redactedDestinationAlloc(std.testing.allocator, destination);
    defer std.testing.allocator.free(redacted);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "sk%2DfakeSyntheticOpenAIKey") == null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "[REDACTED") != null);
}

test "many unknown domains signal only counts policy-unknown domains" {
    const load = @import("load.zig");
    var policy = try load.parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\network:
        \\  mode: allowlist
        \\  allow:
        \\    - "*.known.example"
    , "network.yaml");
    defer policy.deinit();

    var tracker = UnknownDomainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    for ([_][]const u8{ "a.known.example", "b.known.example", "c.known.example", "d.known.example", "e.known.example" }) |host| {
        var decision = try evaluate(std.testing.allocator, &policy, .strict, host, .{ .unknown_tracker = &tracker });
        defer decision.deinit(std.testing.allocator);
        for (decision.exfil_findings) |finding| try std.testing.expect(finding.signal != .many_unknown_domains);
    }

    for ([_][]const u8{ "one.unknown.example", "two.unknown.example", "three.unknown.example", "four.unknown.example", "five.unknown.example" }, 0..) |host, index| {
        var decision = try evaluate(std.testing.allocator, &policy, .strict, host, .{ .unknown_tracker = &tracker });
        defer decision.deinit(std.testing.allocator);
        if (index == 4) {
            var found = false;
            for (decision.exfil_findings) |finding| {
                if (finding.signal == .many_unknown_domains) found = true;
            }
            try std.testing.expect(found);
        }
    }
}

test "service hosts are not counted as policy-unknown domains" {
    const load = @import("load.zig");
    var policy = try load.parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\services:
        \\  github:
        \\    hosts:
        \\      - "*.known-service.example"
        \\    paths:
        \\      allow:
        \\        - "/repos/*/issues"
    , "network-service-known.yaml");
    defer policy.deinit();

    var tracker = UnknownDomainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    for ([_][]const u8{
        "https://one.known-service.example/repos/app/issues",
        "https://two.known-service.example/repos/app/issues",
        "https://three.known-service.example/repos/app/issues",
        "https://four.known-service.example/repos/app/issues",
        "https://five.known-service.example/repos/app/issues",
    }) |target| {
        var decision = try evaluate(std.testing.allocator, &policy, .strict, target, .{ .unknown_tracker = &tracker });
        defer decision.deinit(std.testing.allocator);
        for (decision.exfil_findings) |finding| try std.testing.expect(finding.signal != .many_unknown_domains);
    }
}

test "unknown domain tracker owns host keys" {
    var tracker = UnknownDomainTracker.init(std.testing.allocator);
    defer tracker.deinit();

    const transient = try std.testing.allocator.dupe(u8, "first.example.com");
    const transient_ptr = transient.ptr;
    _ = try tracker.record(transient);
    std.testing.allocator.free(transient);

    var it = tracker.hosts.keyIterator();
    const stored = it.next().?.*;
    try std.testing.expectEqualStrings("first.example.com", stored);
    try std.testing.expect(stored.ptr != transient_ptr);
    try std.testing.expect(!try tracker.record("first.example.com"));
}

test "network effect tags deny publish host under open network policy" {
    const load = @import("load.zig");
    var policy = try load.parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\network:
        \\  mode: open
        \\  default: allow
        \\effects:
        \\  deny:
        \\    - comms.publish
    , "net-effects-proxy.yaml");
    defer policy.deinit();

    // Same path the runtime proxy uses (network_eval.evaluate).
    var denied = try evaluate(std.testing.allocator, &policy, .strict, "https://api.twitter.com/2/tweets", .{
        .enforcement_mode = .proxy_mediated,
    });
    defer denied.deinit(std.testing.allocator);
    try std.testing.expectEqual(core.decision.DecisionResult.deny, denied.decision.result);
    try std.testing.expect(std.mem.indexOf(u8, denied.decision.reason, "comms.publish") != null or
        std.mem.indexOf(u8, denied.decision.reason, "network_tag.") != null);

    var untagged = try evaluate(std.testing.allocator, &policy, .strict, "https://example.com/", .{
        .enforcement_mode = .proxy_mediated,
    });
    defer untagged.deinit(std.testing.allocator);
    try std.testing.expectEqual(core.decision.DecisionResult.allow, untagged.decision.result);
}

test "network effect tags absent when effects section missing" {
    const load = @import("load.zig");
    var policy = try load.parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\network:
        \\  mode: open
        \\  default: allow
    , "net-open-proxy.yaml");
    defer policy.deinit();

    var allowed = try evaluate(std.testing.allocator, &policy, .strict, "https://api.twitter.com/2/tweets", .{
        .enforcement_mode = .proxy_mediated,
    });
    defer allowed.deinit(std.testing.allocator);
    try std.testing.expectEqual(core.decision.DecisionResult.allow, allowed.decision.result);
}

test "appendProxyEnvironment sets both cases and overwrites host proxies (M-3)" {
    var env_map = std.process.Environ.Map.init(std.testing.allocator);
    defer env_map.deinit();

    // Host proxies (including credentialed lowercase) must not survive inject.
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
    try appendProxyEnvironment(&env_map, proxy_url, proxy_no);

    // Both casings point at ryk loopback (ryk inject wins).
    try std.testing.expectEqualStrings(proxy_url, env_map.get("HTTP_PROXY").?);
    try std.testing.expectEqualStrings(proxy_url, env_map.get("http_proxy").?);
    try std.testing.expectEqualStrings(proxy_url, env_map.get("HTTPS_PROXY").?);
    try std.testing.expectEqualStrings(proxy_url, env_map.get("https_proxy").?);
    try std.testing.expectEqualStrings(proxy_url, env_map.get("ALL_PROXY").?);
    try std.testing.expectEqualStrings(proxy_url, env_map.get("all_proxy").?);
    try std.testing.expectEqualStrings(proxy_no, env_map.get("NO_PROXY").?);
    try std.testing.expectEqualStrings(proxy_no, env_map.get("no_proxy").?);
    try std.testing.expectEqualStrings("proxy-mediated", env_map.get("RYK_NETWORK_ENFORCEMENT").?);
    try std.testing.expectEqualStrings("false", env_map.get("RYK_PROXY_ROUTE_FORCED").?);

    // No host credential residue in any proxy value.
    inline for (.{ "HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy" }) |key| {
        const v = env_map.get(key).?;
        try std.testing.expect(std.mem.indexOf(u8, v, "user:") == null);
        try std.testing.expect(std.mem.indexOf(u8, v, "pass") == null);
        try std.testing.expect(std.mem.indexOf(u8, v, "host-proxy") == null);
        try std.testing.expect(std.mem.indexOf(u8, v, "tok:") == null);
    }
}

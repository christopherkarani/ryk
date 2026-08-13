const std = @import("std");
const builtin = @import("builtin");
const platform = @import("ryk_core").platform;
const linux_backend = @import("linux.zig");
const macos_backend = @import("macos.zig");
const windows_backend = @import("windows.zig");

pub const Feature = enum {
    policy_engine,
    audit,
    env_filtering,
    path_staging,
    shell_wrapping,
    path_shims,
    mcp_stdio_proxy,
    network_observe,
    network_proxy_enforce,
    network_enforce,
    process_supervision,
    user_namespaces,
    mount_namespaces,
    seccomp,
    landlock,
    cgroups,
    strong_sandbox,

    pub fn key(self: Feature) []const u8 {
        return @tagName(self);
    }

    pub fn label(self: Feature) []const u8 {
        return switch (self) {
            .policy_engine => "policy engine",
            .audit => "audit/replay",
            .env_filtering => "env filtering",
            .path_staging => "path staging",
            .shell_wrapping => "shell shims",
            .path_shims => "PATH shims",
            .mcp_stdio_proxy => "mcp stdio proxy",
            .network_observe => "network observation",
            .network_proxy_enforce => "proxy-mediated network enforcement",
            .network_enforce => "transparent network enforcement",
            .process_supervision => "process supervision",
            .user_namespaces => "user namespace",
            .mount_namespaces => "mount namespace",
            .seccomp => "seccomp",
            .landlock => "landlock",
            .cgroups => "cgroups",
            .strong_sandbox => "strong sandbox",
        };
    }

    pub fn parse(value: []const u8) ?Feature {
        inline for (@typeInfo(Feature).@"enum".fields) |field| {
            const feature: Feature = @enumFromInt(field.value);
            if (featureNameMatches(value, field.name) or featureNameMatches(value, feature.label()) or feature.aliasMatches(value)) return feature;
        }
        return null;
    }

    fn aliasMatches(self: Feature, value: []const u8) bool {
        return switch (self) {
            .network_proxy_enforce => featureNameMatches(value, "network proxy") or
                featureNameMatches(value, "network proxy enforce") or
                featureNameMatches(value, "network proxy enforcement") or
                featureNameMatches(value, "proxy mediated network enforcement"),
            .network_enforce => featureNameMatches(value, "network enforcement"),
            else => false,
        };
    }
};

fn featureNameMatches(value: []const u8, expected: []const u8) bool {
    if (value.len != expected.len) return false;
    for (value, expected) |actual, wanted| {
        const normalized_actual = if (actual == '-' or actual == ' ') '_' else std.ascii.toLower(actual);
        const normalized_wanted = if (wanted == '-' or wanted == ' ') '_' else std.ascii.toLower(wanted);
        if (normalized_actual != normalized_wanted) return false;
    }
    return true;
}

pub const Level = enum {
    active,
    partial,
    limited,
    observe_only,
    wrapper_only,
    unavailable,
    unsupported,
    failed,

    pub fn toString(self: Level) []const u8 {
        return switch (self) {
            .active => "active",
            .partial => "partial",
            .limited => "limited",
            .observe_only => "observe-only",
            .wrapper_only => "wrapper-only",
            .unavailable => "unavailable",
            .unsupported => "unsupported",
            .failed => "failed",
        };
    }

    pub fn isUsable(self: Level) bool {
        return switch (self) {
            .active, .partial, .limited, .observe_only, .wrapper_only => true,
            .unavailable, .unsupported, .failed => false,
        };
    }
};

pub const FeatureReport = struct {
    feature: Feature,
    level: Level,
    note: []const u8,
};

pub const feature_order = [_]Feature{
    .policy_engine,
    .audit,
    .env_filtering,
    .path_staging,
    .shell_wrapping,
    .path_shims,
    .mcp_stdio_proxy,
    .network_observe,
    .network_proxy_enforce,
    .network_enforce,
    .process_supervision,
    .user_namespaces,
    .mount_namespaces,
    .seccomp,
    .landlock,
    .cgroups,
    .strong_sandbox,
};

pub const ReportSet = struct {
    os: platform.Os,
    backend_name: []const u8,
    /// Highest probed Landlock ABI, when the Linux syscall probe succeeded.
    landlock_abi: ?u32 = null,
    fallback_level: Level,
    fallback_note: []const u8,
    reports: [feature_order.len]FeatureReport,

    pub fn get(self: ReportSet, feature: Feature) FeatureReport {
        for (self.reports) |report| {
            if (report.feature == feature) return report;
        }
        unreachable;
    }

    pub fn featureAvailable(self: ReportSet, feature: Feature) bool {
        return self.get(feature).level == .active;
    }

    pub fn featureSatisfiesRequirement(self: ReportSet, feature: Feature) bool {
        return self.featureAvailable(feature);
    }

    pub fn firstMissingRequired(self: ReportSet, required: []const Feature) ?FeatureReport {
        for (required) |feature| {
            if (!self.featureSatisfiesRequirement(feature)) return self.get(feature);
        }
        return null;
    }
};

/// Production agent launch is exclusively `apply.applyBeforeExec` +
/// `process.OsChildApply` / `apply_posix`. Capability detection lives
/// here; there is no scaffold spawn path that could be mistaken for attach.
pub fn detect(os: platform.Os) ReportSet {
    return switch (os) {
        .linux => linux_backend.detect(),
        .macos => macos_backend.detect(),
        .windows => windows_backend.detect(),
        else => fallbackReport(os),
    };
}

pub fn killProcessGroup(io: std.Io, pgid: std.posix.pid_t) void {
    switch (builtin.os.tag) {
        .windows, .wasi => return,
        else => {
            if (pgid <= 0) return;
            std.posix.kill(-pgid, std.posix.SIG.TERM) catch {};
            std.Io.sleep(io, std.Io.Duration.fromNanoseconds(50 * std.time.ns_per_ms), .awake) catch {};
            std.posix.kill(-pgid, std.posix.SIG.KILL) catch {};
        },
    }
}

pub fn fallbackReport(os: platform.Os) ReportSet {
    var reports = baseReports(os);
    setReport(&reports, .process_supervision, .unavailable, "direct child wait only; Linux process-group cleanup is not active on this platform");
    setReport(&reports, .user_namespaces, .unsupported, "Linux user namespaces are unsupported on this platform");
    setReport(&reports, .mount_namespaces, .unsupported, "Linux mount namespaces are unsupported on this platform");
    setReport(&reports, .seccomp, .unsupported, "Linux seccomp-bpf is unsupported on this platform");
    setReport(&reports, .landlock, .unsupported, "Linux Landlock is unsupported on this platform");
    setReport(&reports, .cgroups, .unsupported, "Linux cgroup cleanup is unsupported on this platform");
    setReport(&reports, .strong_sandbox, .unsupported, "no Linux OS-level sandbox backend is available on this platform");
    return .{
        .os = os,
        .backend_name = "fallback",
        .fallback_level = .wrapper_only,
        .fallback_note = "wrapper-level controls only; Linux OS-level sandbox features are unavailable",
        .reports = reports,
    };
}

pub fn baseReports(os: platform.Os) [feature_order.len]FeatureReport {
    _ = os;
    var reports: [feature_order.len]FeatureReport = undefined;
    for (feature_order, 0..) |feature, index| {
        reports[index] = .{
            .feature = feature,
            .level = .unavailable,
            .note = "not detected",
        };
    }
    setReport(&reports, .policy_engine, .active, "policy evaluation is implemented before launch");
    setReport(&reports, .audit, .active, "session audit writer records security events through redaction");
    setReport(&reports, .env_filtering, .active, "child environment is built through env filtering");
    setReport(&reports, .path_staging, .active, "ryk-mediated writes use staged review artifacts");
    setReport(&reports, .shell_wrapping, .wrapper_only, "session shell controls are wrapper-level");
    setReport(&reports, .path_shims, .wrapper_only, "session PATH shims are wrapper-level");
    setReport(&reports, .mcp_stdio_proxy, .active, "stdio MCP proxy enforcement is implemented for mediated MCP traffic");
    setReport(&reports, .network_observe, .observe_only, "network policy decisions and audit observations are implemented");
    setReport(&reports, .network_proxy_enforce, .limited, "explicit loopback proxy is available when requested; route forcing requires per-session OS sandbox attach");
    setReport(&reports, .network_enforce, .observe_only, "transparent network enforcement is not active; decisions are observed and audited");
    return reports;
}

pub fn setReport(reports: *[feature_order.len]FeatureReport, feature: Feature, level: Level, note: []const u8) void {
    for (reports) |*report| {
        if (report.feature == feature) {
            report.level = level;
            report.note = note;
            return;
        }
    }
    unreachable;
}

test "backend capability levels are explicit and parseable" {
    try std.testing.expectEqualStrings("observe-only", Level.observe_only.toString());
    try std.testing.expectEqualStrings("wrapper-only", Level.wrapper_only.toString());
    try std.testing.expectEqualStrings("limited", Level.limited.toString());
    try std.testing.expectEqual(Feature.user_namespaces, Feature.parse("user-namespaces").?);
    try std.testing.expectEqual(Feature.mount_namespaces, Feature.parse("mount namespace").?);
    try std.testing.expectEqual(Feature.network_enforce, Feature.parse("network enforcement").?);
    try std.testing.expectEqual(Feature.network_enforce, Feature.parse("network-enforcement").?);
    try std.testing.expectEqual(Feature.network_enforce, Feature.parse("transparent network enforcement").?);
    try std.testing.expectEqual(Feature.network_proxy_enforce, Feature.parse("network-proxy").?);
    try std.testing.expectEqual(Feature.network_proxy_enforce, Feature.parse("network proxy enforcement").?);
    try std.testing.expectEqual(Feature.network_proxy_enforce, Feature.parse("proxy-mediated network enforcement").?);
    try std.testing.expectEqual(Feature.strong_sandbox, Feature.parse("strong_sandbox").?);
}

test "fallback backend reports Linux-only features as unsupported without breaking baseline controls" {
    const report = fallbackReport(.freebsd);
    try std.testing.expectEqualStrings("fallback", report.backend_name);
    try std.testing.expectEqual(Level.active, report.get(.env_filtering).level);
    try std.testing.expectEqual(Level.wrapper_only, report.get(.path_shims).level);
    try std.testing.expectEqual(Level.unsupported, report.get(.user_namespaces).level);
    try std.testing.expectEqual(Level.unsupported, report.get(.strong_sandbox).level);
    try std.testing.expect(!report.featureAvailable(.strong_sandbox));
}

test "macOS backend is selected explicitly instead of generic fallback" {
    const report = detect(.macos);
    try std.testing.expectEqual(platform.Os.macos, report.os);
    try std.testing.expectEqualStrings("macos", report.backend_name);
    try std.testing.expectEqual(Level.active, report.get(.env_filtering).level);
    try std.testing.expectEqual(Level.wrapper_only, report.get(.path_shims).level);
    // Capability probe: partial on matrix hosts with sandbox_init; never live active.
    const strong = report.get(.strong_sandbox).level;
    try std.testing.expect(strong == .partial or strong == .unavailable);
    try std.testing.expect(strong != .active);
}

test "Windows backend is selected explicitly instead of generic fallback" {
    const report = detect(.windows);
    try std.testing.expectEqual(platform.Os.windows, report.os);
    try std.testing.expectEqualStrings("windows", report.backend_name);
    try std.testing.expectEqual(Level.active, report.get(.env_filtering).level);
    try std.testing.expectEqual(Level.wrapper_only, report.get(.path_shims).level);
    try std.testing.expectEqual(Level.unavailable, report.get(.strong_sandbox).level);
}

test "required backend features require active enforcement" {
    var reports = baseReports(.linux);
    setReport(&reports, .network_enforce, .observe_only, "observe-only is not enforcement");
    setReport(&reports, .seccomp, .partial, "API detected but no filter installed");
    setReport(&reports, .path_shims, .wrapper_only, "wrapper-only control");
    const report: ReportSet = .{
        .os = .linux,
        .backend_name = "test",
        .fallback_level = .partial,
        .fallback_note = "test",
        .reports = reports,
    };

    try std.testing.expect(report.firstMissingRequired(&.{.env_filtering}) == null);
    try std.testing.expectEqual(Feature.network_enforce, report.firstMissingRequired(&.{.network_enforce}).?.feature);
    try std.testing.expectEqual(Feature.network_proxy_enforce, report.firstMissingRequired(&.{.network_proxy_enforce}).?.feature);
    try std.testing.expectEqual(Feature.seccomp, report.firstMissingRequired(&.{.seccomp}).?.feature);
    try std.testing.expectEqual(Feature.path_shims, report.firstMissingRequired(&.{.path_shims}).?.feature);
}

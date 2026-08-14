const std = @import("std");
const builtin = @import("builtin");

pub const Os = enum {
    linux,
    macos,
    windows,
    freebsd,
    unknown,

    pub fn toString(self: Os) []const u8 {
        return @tagName(self);
    }
};

pub const Capability = enum {
    process_supervision,
    env_filtering,
    path_staging,
    shell_wrapping,
    path_shims,
    mcp_stdio_proxy,
    network_policy_engine,
    network_observe,
    network_proxy_enforce,
    network_enforce,
    strong_sandbox,

    pub fn toString(self: Capability) []const u8 {
        return @tagName(self);
    }
};

pub const CapabilityState = enum {
    active,
    partial,
    observe,
    limited,
    unavailable,
    unknown,

    pub fn toString(self: CapabilityState) []const u8 {
        return @tagName(self);
    }
};

pub const CapabilityReport = struct {
    capability: Capability,
    state: CapabilityState,
    note: []const u8,
};

pub fn detectOs() Os {
    return switch (builtin.os.tag) {
        .linux => .linux,
        .macos => .macos,
        .windows => .windows,
        .freebsd => .freebsd,
        else => .unknown,
    };
}

pub fn defaultCapabilityState(os: Os, capability: Capability) CapabilityState {
    return switch (capability) {
        .env_filtering,
        .path_staging,
        .mcp_stdio_proxy,
        .network_policy_engine,
        => .active,
        .process_supervision,
        .path_shims,
        .network_observe,
        => .partial,
        .shell_wrapping => .limited,
        .network_proxy_enforce => if (os == .windows) .unavailable else .limited,
        .network_enforce,
        .strong_sandbox,
        => .unavailable,
    };
}

pub fn reportCapability(os: Os, capability: Capability) CapabilityReport {
    const state: CapabilityState = switch (capability) {
        .process_supervision => if (os == .linux) .active else .partial,
        .env_filtering => .active,
        .path_staging => .active,
        .shell_wrapping => .limited,
        .path_shims => .limited,
        .mcp_stdio_proxy => .active,
        .network_policy_engine => .active,
        .network_observe => .partial,
        .network_proxy_enforce => if (os == .windows) .unavailable else .limited,
        .network_enforce => .unavailable,
        .strong_sandbox => .unavailable,
    };
    return .{
        .capability = capability,
        .state = state,
        .note = switch (state) {
            .active => switch (capability) {
                .process_supervision => "Linux backend uses process-group cleanup where available",
                .env_filtering => "child environment filtering is implemented and tested",
                .path_staging => "ryk-mediated write staging is implemented and tested",
                .mcp_stdio_proxy => "stdio MCP proxy enforcement is implemented and tested",
                .network_policy_engine => "pure policy decisions are implemented and tested",
                else => "backend reported active",
            },
            .partial => switch (capability) {
                .process_supervision => "direct-child supervision is implemented; Linux process-tree cleanup is backend-specific",
                .network_observe => "network audit events exist for ryk-mediated decisions; transparent observation is platform-dependent",
                else => "partial backend support",
            },
            .limited => switch (capability) {
                .shell_wrapping => "shell controls are wrapper-level",
                .path_shims => "PATH shims are wrapper-level",
                .network_proxy_enforce => "explicit loopback proxy backend is available when requested; HTTPS visibility is host/port only",
                else => "limited backend support",
            },
            .unknown => "backend state is unknown",
            .unavailable => switch (capability) {
                .network_enforce => "transparent OS-level network enforcement is not implemented in Phase 12",
                .network_proxy_enforce => "loopback HTTP proxy is unavailable on Windows (ProxyUnsupportedOnWindows)",
                .strong_sandbox => "OS filesystem sandbox is not active until apply-before-exec succeeds; capability probes alone never mean active",
                else => "not available on this platform",
            },
            else => "backend reported capability",
        },
    };
}

test "platform detection returns valid enum and capabilities are non-boolean" {
    const os = detectOs();
    try std.testing.expect(std.mem.eql(u8, os.toString(), @tagName(os)));

    const report = reportCapability(os, .strong_sandbox);
    try std.testing.expectEqual(Capability.strong_sandbox, report.capability);
    try std.testing.expect(report.state == .unavailable or report.state == .unknown);
}

test "strong_sandbox is never active from platform defaults (S-GLO-01)" {
    inline for (.{ Os.linux, Os.macos, Os.windows, Os.freebsd, Os.unknown }) |os| {
        const report = reportCapability(os, .strong_sandbox);
        try std.testing.expect(report.state != .active);
        try std.testing.expectEqual(CapabilityState.unavailable, defaultCapabilityState(os, .strong_sandbox));
    }
}

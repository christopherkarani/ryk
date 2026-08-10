//! Unified host integration status + install smoke helpers for ryk plugins.
//!
//! Product fields (human + JSON): host, wired, shell_gate, fail_stance,
//! smoke_allow, smoke_deny, fix. Smoke maps to each host's real veto path.

const std = @import("std");
const env_util = @import("../env_util.zig");
const child_process = @import("child_process.zig");
const pi_install = @import("pi_install.zig");

pub const managed_hosts = [_][]const u8{ "codex", "claude", "opencode", "openclaw", "hermes" };
pub const pi_process_command = "ryk run -- pi";

pub const PiStatus = struct {
    binary_detected: bool = false,
    extension_installed: bool = false,

    pub fn detected(self: PiStatus) bool {
        return self.binary_detected or self.extension_installed;
    }

    pub fn wiredLabel(self: PiStatus) []const u8 {
        if (self.extension_installed) return "yes";
        if (self.binary_detected) return "no";
        return "—";
    }

    pub fn detail(self: PiStatus) []const u8 {
        if (self.extension_installed) return "ryk extension installed; coverage unknown until live smoke";
        if (self.binary_detected) return "Pi detected; ryk extension not installed";
        return "Pi not detected";
    }
};

pub const SmokeOutcome = enum {
    pass,
    fail,
    not_run,

    pub fn toString(self: SmokeOutcome) []const u8 {
        return switch (self) {
            .pass => "pass",
            .fail => "fail",
            .not_run => "not-run",
        };
    }
};

pub const HostSmokePair = struct {
    allow: SmokeOutcome = .not_run,
    deny: SmokeOutcome = .not_run,

    pub fn bothPassed(self: HostSmokePair) bool {
        return self.allow == .pass and self.deny == .pass;
    }

    pub fn denyFailed(self: HostSmokePair) bool {
        return self.deny == .fail;
    }

    pub fn isDegraded(self: HostSmokePair) bool {
        return self.deny == .pass and self.allow == .fail;
    }
};

/// Evidence-based readiness from smoke (deny proves protection; allow proves usability).
pub const HostReadiness = enum {
    /// allow+deny both pass — usable and protected.
    protected,
    /// deny pass, allow fail — fail-closed/safe but not usable (daemon/policy).
    degraded,
    /// deny fail — not proven protected.
    not_protected,
    /// smoke not run (or incomplete) — do not claim ready.
    unknown,

    pub fn toString(self: HostReadiness) []const u8 {
        return switch (self) {
            .protected => "protected",
            .degraded => "degraded",
            .not_protected => "not-protected",
            .unknown => "unknown",
        };
    }

    /// User-facing label; never "ready/protected" unless fully green.
    pub fn label(self: HostReadiness) []const u8 {
        return switch (self) {
            .protected => "protected (ready)",
            .degraded => "degraded (deny ok, allow failed — not ready)",
            .not_protected => "not protected",
            .unknown => "unknown (smoke not run)",
        };
    }
};

pub fn classifyReadiness(smoke: HostSmokePair) HostReadiness {
    if (smoke.deny == .fail) return .not_protected;
    if (smoke.bothPassed()) return .protected;
    if (smoke.isDegraded()) return .degraded;
    if (smoke.deny == .pass and smoke.allow == .not_run) return .degraded;
    return .unknown;
}

pub const HostStatusRow = struct {
    host: []const u8,
    wired: []const u8,
    shell_gate: []const u8,
    fail_stance: []const u8,
    smoke_allow: SmokeOutcome = .not_run,
    smoke_deny: SmokeOutcome = .not_run,
    fix: []const u8,
};

/// Hook event name for shell veto per managed host.
pub fn shellGate(host: []const u8) []const u8 {
    if (std.mem.eql(u8, host, "codex") or
        std.mem.eql(u8, host, "claude") or
        std.mem.eql(u8, host, "grok"))
        return "PreToolUse";
    if (std.mem.eql(u8, host, "opencode")) return "tool.execute.before";
    if (std.mem.eql(u8, host, "openclaw")) return "tool.before";
    if (std.mem.eql(u8, host, "hermes")) return "pre_tool_call";
    if (std.mem.eql(u8, host, "pi")) return "extension-managed (smoke not run)";
    // Day-one membership includes cursor (D03); W3 owns the real beforeShellExecution
    // writer. Until then smoke stays not-run and rows must not claim wired/✓.
    if (std.mem.eql(u8, host, "cursor")) return "cursor-shell (W3 deferred)";
    return "unknown";
}

/// Effective fail stance label for doctor tables.
///
/// RT-06/H1: never claim `"fail-closed shell"` when the host hook is unwired.
/// Process-wrap / PATH shims (if any) do not close absolute-path mediation; only a
/// wired host hook that fires and honors veto can claim fail-closed shell.
/// `wired` is doctor wired label: `"yes"` / `"partial"` / `"no"` / `"—"`.
pub fn failStance(host: []const u8, hermes_fail_open: bool, wired: []const u8) []const u8 {
    // RT-06: never claim fail-closed (or explicit Hermes fail-open) when unwired.
    // when the host hook is unwired — process-wrap alone is not shell mediation.
    const hook_wired = std.mem.eql(u8, wired, "yes") or std.mem.eql(u8, wired, "partial");
    if (std.mem.eql(u8, host, "hermes")) {
        if (!hook_wired) return "unwired (no fail-closed shell)";
        return if (hermes_fail_open) "fail-open (explicit)" else "fail-closed";
    }
    if (std.mem.eql(u8, host, "pi")) return "mode-dependent";
    if (!hook_wired) return "unwired (no fail-closed shell)";
    return "fail-closed shell";
}

/// Runtime fix line for non-green host rows.
pub fn formatFix(
    allocator: std.mem.Allocator,
    host: []const u8,
    wired: []const u8,
    smoke: HostSmokePair,
    hermes_fail_open: bool,
) ![]const u8 {
    // Cursor: day-one membership (D03) without W3 writer — always fail+repair honesty.
    // Never teach a silent ✓ or marketplace wire; sole repair door is doctor --fix.
    if (std.mem.eql(u8, host, "cursor")) {
        if (std.mem.eql(u8, wired, "yes") or std.mem.eql(u8, wired, "partial")) {
            // Should not claim full wire until W3; still surface repair if mislabeled.
            return try allocator.dupe(u8, "ryk doctor --fix  # Cursor writer ships in W3");
        }
        return try allocator.dupe(u8, "ryk doctor --fix  # Cursor auto-wire deferred to W3");
    }
    if (std.mem.eql(u8, host, "pi")) {
        if (std.mem.eql(u8, wired, "yes")) {
            return try allocator.dupe(u8, "./scripts/host-live-e2e.sh pi  # verify extension coverage");
        }
        if (std.mem.eql(u8, wired, "no")) {
            return try allocator.dupe(u8, "ryk doctor --fix  # install the bundled Pi extension");
        }
        return try allocator.dupe(u8, "install Pi, then run: ryk doctor --fix");
    }
    if (std.mem.eql(u8, host, "grok")) {
        if (smoke.deny == .fail or smoke.allow == .fail) {
            return try allocator.dupe(u8, "ryk doctor  # grok PreToolUse smoke failed — check ryk hook grok PreToolUse");
        }
        if (std.mem.eql(u8, wired, "yes") or std.mem.eql(u8, wired, "partial")) {
            return try allocator.dupe(u8, "—");
        }
        // Sole repair door is doctor --fix (never teach ryk start as required primary).
        if (std.mem.eql(u8, wired, "no")) {
            return try allocator.dupe(u8, "ryk doctor --fix  # installs ~/.grok PreToolUse Command Guard");
        }
        return try allocator.dupe(u8, "install grok CLI, then run: ryk doctor --fix");
    }
    // Degraded first: deny works but allow failed → daemon/policy, not reinstall.
    if (smoke.isDegraded() or (smoke.deny == .pass and smoke.allow == .fail)) {
        return try allocator.dupe(u8, "ryk doctor  # fix daemon/policy (deny ok, allow failed — not ready)");
    }
    if (smoke.deny == .fail) {
        if (std.mem.eql(u8, host, "hermes")) {
            return try allocator.dupe(u8, "ryk plugin doctor hermes; set RYK_BIN; RYK_HERMES_FAIL_OPEN=0 for fail-closed");
        }
        return try std.fmt.allocPrint(allocator, "ryk plugin doctor {s}", .{host});
    }
    if (smoke.allow == .fail) {
        return try std.fmt.allocPrint(allocator, "ryk plugin doctor {s}", .{host});
    }
    if (std.mem.eql(u8, wired, "yes") or std.mem.eql(u8, wired, "partial")) {
        if (std.mem.eql(u8, host, "hermes") and hermes_fail_open) {
            return try allocator.dupe(u8, "unset RYK_HERMES_FAIL_OPEN  # or: ryk run -- hermes");
        }
        return try allocator.dupe(u8, "—");
    }
    if (std.mem.eql(u8, wired, "no")) {
        return try std.fmt.allocPrint(allocator, "ryk plugin install {s} --yes", .{host});
    }
    return try std.fmt.allocPrint(allocator, "install {s} CLI, then ryk plugin install {s} --yes", .{ host, host });
}

/// Pure smoke decision parser — unit-tested without spawning hooks.
/// `expected` is "allow" or "block".
pub fn interpretSmokeOutcome(
    host: []const u8,
    expected: []const u8,
    exit_code: u8,
    stdout: []const u8,
    stderr: []const u8,
) bool {
    if (std.mem.eql(u8, expected, "allow")) {
        if (exit_code != 0) return false;
        const decision = extractDecision(stdout) orelse return false;
        return std.mem.eql(u8, decision, "allow");
    }
    if (std.mem.eql(u8, expected, "block")) {
        // Codex and Grok deny with exit 2; stdout JSON may be intentionally empty.
        if (std.mem.eql(u8, host, "codex") or std.mem.eql(u8, host, "grok")) {
            if (exit_code == 2) return true;
            // Defensive: accept decision=block JSON if a host version emits it.
            if (exit_code == 0) {
                if (extractDecision(stdout)) |d| return std.mem.eql(u8, d, "block");
            }
            return false;
        }
        _ = stderr;
        if (exit_code != 0) return false;
        const decision = extractDecision(stdout) orelse return false;
        return std.mem.eql(u8, decision, "block");
    }
    return false;
}

fn extractDecision(stdout: []const u8) ?[]const u8 {
    const trimmed = std.mem.trim(u8, stdout, " \t\r\n");
    if (trimmed.len == 0) return null;
    // Lightweight scan avoids full JSON parse in the pure helper path.
    const key = "\"decision\"";
    const idx = std.mem.indexOf(u8, trimmed, key) orelse return null;
    var i = idx + key.len;
    while (i < trimmed.len and (trimmed[i] == ' ' or trimmed[i] == '\t' or trimmed[i] == ':' or trimmed[i] == '\n' or trimmed[i] == '\r')) : (i += 1) {}
    if (i >= trimmed.len or trimmed[i] != '"') return null;
    const start = i + 1;
    const end = std.mem.indexOfScalarPos(u8, trimmed, start, '"') orelse return null;
    return trimmed[start..end];
}

/// Minimal shell veto fixtures matching each host envelope (command in payload).
pub fn buildHookFixture(allocator: std.mem.Allocator, host: []const u8, event: []const u8, command: []const u8) ![]u8 {
    if (std.mem.eql(u8, host, "grok")) {
        // Official Grok Build envelope (camelCase + snake_case event value).
        // ryk also accepts Claude-compat snake_case; smoke uses the live wire shape.
        const grok_event = if (std.mem.eql(u8, event, "PreToolUse")) "pre_tool_use" else event;
        return try std.fmt.allocPrint(allocator,
            \\{{"hookEventName":"{s}","sessionId":"ryk-smoke","cwd":"/tmp","workspaceRoot":"/tmp","toolName":"run_terminal_cmd","toolUseId":"smoke-1","toolInput":{{"command":"{s}"}},"toolInputTruncated":false}}
        , .{ grok_event, command });
    }
    if (std.mem.eql(u8, host, "hermes")) {
        return try std.fmt.allocPrint(allocator,
            \\{{"version":1,"host":"hermes","event":"{s}","payload":{{"tool_name":"terminal","tool_input":{{"command":"{s}"}},"command":"{s}"}}}}
        , .{ event, command, command });
    }
    if (std.mem.eql(u8, host, "opencode")) {
        return try std.fmt.allocPrint(allocator,
            \\{{"version":1,"host":"opencode","event":"{s}","payload":{{"tool":"bash","sessionID":"smoke","callID":"1","command":"{s}","args":{{"command":"{s}"}}}}}}
        , .{ event, command, command });
    }
    if (std.mem.eql(u8, host, "openclaw")) {
        return try std.fmt.allocPrint(allocator,
            \\{{"version":1,"host":"openclaw","event":"{s}","payload":{{"tool":"bash","command":"{s}"}}}}
        , .{ event, command });
    }
    // codex / claude PreToolUse shape
    return try std.fmt.allocPrint(allocator,
        \\{{"version":1,"host":"{s}","event":"{s}","payload":{{"tool_name":"Bash","tool_input":{{"command":"{s}"}}}}}}
    , .{ host, event, command });
}

pub const safe_smoke_command = "git status";
pub const danger_smoke_command = "rm -rf /";

/// Resolve a ryk CLI binary for hook smoke. Null when only the unit-test harness is available.
fn resolveSmokeBinary(io: std.Io, allocator: std.mem.Allocator) !?[]u8 {
    var env_map = env_util.createProcessMap(allocator) catch null;
    defer if (env_map) |*m| m.deinit();
    if (env_map) |*m| {
        // RYK_BIN only (hard-cut).
        if (try env_util.getOwnedBrand(m, allocator, "BIN")) |configured| {
            if (std.Io.Dir.accessAbsolute(io, configured, .{})) |_| {
                return configured;
            } else |_| {
                allocator.free(configured);
            }
        }
    }

    const self_exe = try std.process.executablePathAlloc(io, allocator);
    const base = std.fs.path.basename(self_exe);
    // Real CLI binaries are named `ryk` (or `ryk.exe`). The zig test harness is not.
    const brand = @import("brand.zig");
    if (brand.isPrimaryInvocation(base)) {
        const owned = try allocator.dupe(u8, self_exe);
        allocator.free(self_exe);
        return owned;
    }
    allocator.free(self_exe);
    return null;
}

/// Spawn `ryk hook <host> <event>` with fixture JSON on stdin.
/// Returns error.SmokeBinaryUnavailable when no ryk CLI can be resolved (unit tests).
pub fn smokeTestHookPayload(
    allocator: std.mem.Allocator,
    host: []const u8,
    event: []const u8,
    fixture_json: []const u8,
    expected_decision: []const u8,
) !bool {
    var threaded = std.Io.Threaded.init(allocator, .{
        .environ = env_util.processEnviron(),
    });
    defer threaded.deinit();
    const io = threaded.io();
    const ryk_bin = try resolveSmokeBinary(io, allocator) orelse return error.SmokeBinaryUnavailable;
    defer allocator.free(ryk_bin);

    return smokeTestHookPayloadWithBinary(
        allocator,
        ryk_bin,
        host,
        event,
        fixture_json,
        expected_decision,
        5_000,
    );
}

fn smokeTestHookPayloadWithBinary(
    allocator: std.mem.Allocator,
    ryk_bin: []const u8,
    host: []const u8,
    event: []const u8,
    fixture_json: []const u8,
    expected_decision: []const u8,
    timeout_ms: u64,
) !bool {
    // Health-path smoke joins the parent process group so the agents-health
    // outer watchdog can reap nested hook probes (M-7). Windows has no join
    // API; use a private process group there.
    const result = if (comptime @import("builtin").os.tag == .windows)
        try child_process.runHostCommandInputCaptureTimed(
            allocator,
            &.{ ryk_bin, "hook", host, event },
            fixture_json,
            timeout_ms,
        )
    else
        try child_process.runHostCommandInputCaptureTimedInCurrentProcessGroup(
            allocator,
            &.{ ryk_bin, "hook", host, event },
            fixture_json,
            timeout_ms,
        );
    defer result.deinit(allocator);
    if (result.timed_out) return false;
    return interpretSmokeOutcome(host, expected_decision, result.exit_code, result.stdout, result.stderr);
}

/// Health-specific smoke using the running ryk executable and a caller-owned
/// deadline slice. This avoids trusting RYK_BIN and keeps the total health
/// command bounded across both allow and deny probes.
pub fn runHostSmokePairWithBinaryTimed(
    allocator: std.mem.Allocator,
    ryk_bin: []const u8,
    host: []const u8,
    timeout_each_ms: u64,
) !HostSmokePair {
    const event = shellGate(host);
    if (std.mem.eql(u8, event, "unknown") or
        std.mem.eql(u8, host, "pi") or
        std.mem.eql(u8, host, "cursor"))
    {
        return .{};
    }

    const allow_fixture = try buildHookFixture(allocator, host, event, safe_smoke_command);
    defer allocator.free(allow_fixture);
    const deny_fixture = try buildHookFixture(allocator, host, event, danger_smoke_command);
    defer allocator.free(deny_fixture);
    const allow_ok = smokeTestHookPayloadWithBinary(
        allocator,
        ryk_bin,
        host,
        event,
        allow_fixture,
        "allow",
        timeout_each_ms,
    ) catch false;
    const deny_ok = smokeTestHookPayloadWithBinary(
        allocator,
        ryk_bin,
        host,
        event,
        deny_fixture,
        "block",
        timeout_each_ms,
    ) catch false;
    return .{
        .allow = if (allow_ok) .pass else .fail,
        .deny = if (deny_ok) .pass else .fail,
    };
}

pub fn runHostSmokePair(allocator: std.mem.Allocator, host: []const u8) !HostSmokePair {
    const event = shellGate(host);
    // Pi is extension-managed (not a hook-event smoke target). Keep legacy "evaluate bash"
    // and expanded coverage labels out of the PreToolUse-style fixture path.
    // Cursor (W3 deferred): never run fixture smoke that could false-green wired/✓.
    if (std.mem.eql(u8, event, "unknown") or
        std.mem.eql(u8, host, "pi") or
        std.mem.eql(u8, host, "cursor") or
        std.mem.startsWith(u8, event, "cursor-shell") or
        std.mem.eql(u8, event, "evaluate bash") or
        std.mem.startsWith(u8, event, "bash+"))
    {
        return .{ .allow = .not_run, .deny = .not_run };
    }

    const allow_fixture = try buildHookFixture(allocator, host, event, safe_smoke_command);
    defer allocator.free(allow_fixture);
    const deny_fixture = try buildHookFixture(allocator, host, event, danger_smoke_command);
    defer allocator.free(deny_fixture);

    const allow_result = smokeTestHookPayload(allocator, host, event, allow_fixture, "allow");
    const deny_result = smokeTestHookPayload(allocator, host, event, deny_fixture, "block");

    // When only the unit-test harness is available, leave smoke as not-run.
    if (allow_result == error.SmokeBinaryUnavailable or deny_result == error.SmokeBinaryUnavailable) {
        return .{ .allow = .not_run, .deny = .not_run };
    }

    const allow_ok = allow_result catch false;
    const deny_ok = deny_result catch false;
    return .{
        .allow = if (allow_ok) .pass else .fail,
        .deny = if (deny_ok) .pass else .fail,
    };
}

pub fn writeHostSmokeReport(stdout: anytype, host: []const u8, smoke: HostSmokePair) !void {
    const readiness = classifyReadiness(smoke);
    try stdout.print("  smoke allow: {s}\n", .{smoke.allow.toString()});
    try stdout.print("  smoke deny:  {s}\n", .{smoke.deny.toString()});
    try stdout.print("  readiness:   {s}\n", .{readiness.label()});
    switch (readiness) {
        .protected => {
            try stdout.print("  smoke: PASSED (safe allow + dangerous deny on {s} veto path)\n", .{shellGate(host)});
        },
        .degraded => {
            try stdout.writeAll("  smoke: DEGRADED — deny works but safe allow failed (daemon down or policy?)\n");
            try stdout.writeAll("  status: NOT ready / NOT fully usable — fail-closed is active but everyday use may break\n");
            try stdout.writeAll("  fix: ryk doctor  # start/repair daemon first\n");
        },
        .not_protected => {
            try stdout.writeAll("  smoke: FAILED — deny did not fire; host is NOT protected\n");
            try stdout.print("  fix: ryk plugin doctor {s}\n", .{host});
        },
        .unknown => {
            try stdout.writeAll("  smoke: not run — do not treat host as protected or ready\n");
        },
    }
}

/// Inspect Pi host presence separately from the npm registration surface.
pub fn inspectPi(io: std.Io, allocator: std.mem.Allocator) PiStatus {
    const binary_detected = binaryInPath(io, allocator, "pi");
    var env_map = env_util.createProcessMap(allocator) catch return .{ .binary_detected = binary_detected };
    defer env_map.deinit();
    const home_owned = env_util.getOwnedHome(&env_map, allocator) catch return .{ .binary_detected = binary_detected };
    const home = home_owned orelse return .{ .binary_detected = binary_detected };
    defer allocator.free(home);
    return .{
        .binary_detected = binary_detected,
        .extension_installed = pi_install.isCompleteAtHome(io, allocator, home) or
            piExtensionInstalledAtHome(io, allocator, home),
    };
}

/// Compatibility helper for callers that only need to know whether any Pi surface exists.
pub fn detectPi(io: std.Io, allocator: std.mem.Allocator) bool {
    return inspectPi(io, allocator).detected();
}

const PiPackageManifest = struct {
    name: []const u8,
    version: []const u8,
};

const PiSettings = struct {
    packages: []const []const u8 = &.{},
};

fn piExtensionInstalledAtHome(io: std.Io, allocator: std.mem.Allocator, home: []const u8) bool {
    const package_root = std.fs.path.join(allocator, &.{ home, ".pi/agent/npm/node_modules/@rykan/pi-ryk" }) catch return false;
    defer allocator.free(package_root);
    const manifest_path = std.fs.path.join(allocator, &.{ package_root, "package.json" }) catch return false;
    defer allocator.free(manifest_path);
    const extension_path = std.fs.path.join(allocator, &.{ package_root, "extensions/ryk.ts" }) catch return false;
    defer allocator.free(extension_path);
    const settings_path = std.fs.path.join(allocator, &.{ home, ".pi/agent/settings.json" }) catch return false;
    defer allocator.free(settings_path);

    std.Io.Dir.accessAbsolute(io, extension_path, .{}) catch return false;
    const manifest_text = std.Io.Dir.cwd().readFileAlloc(io, manifest_path, allocator, .limited(64 * 1024)) catch return false;
    defer allocator.free(manifest_text);
    var parsed = std.json.parseFromSlice(PiPackageManifest, allocator, manifest_text, .{ .ignore_unknown_fields = true }) catch return false;
    defer parsed.deinit();
    if (!std.mem.eql(u8, parsed.value.name, "@rykan/pi-ryk") or parsed.value.version.len == 0) return false;

    const settings_text = std.Io.Dir.cwd().readFileAlloc(io, settings_path, allocator, .limited(1024 * 1024)) catch return false;
    defer allocator.free(settings_text);
    var settings = std.json.parseFromSlice(PiSettings, allocator, settings_text, .{ .ignore_unknown_fields = true }) catch return false;
    defer settings.deinit();
    for (settings.value.packages) |package| {
        if (std.mem.eql(u8, package, "npm:@rykan/pi-ryk")) return true;
    }
    return false;
}

fn binaryInPath(io: std.Io, allocator: std.mem.Allocator, name: []const u8) bool {
    var env_map = env_util.createProcessMap(allocator) catch return false;
    defer env_map.deinit();
    const path_owned = env_util.getOwned(&env_map, allocator, "PATH") catch return false;
    const path_val = path_owned orelse return false;
    defer allocator.free(path_val);
    var it = std.mem.splitScalar(u8, path_val, ':');
    while (it.next()) |dir| {
        if (dir.len == 0) continue;
        const candidate = std.fs.path.join(allocator, &.{ dir, name }) catch continue;
        defer allocator.free(candidate);
        std.Io.Dir.accessAbsolute(io, candidate, .{}) catch continue;
        return true;
    }
    return false;
}

/// Stance file written next to installed Hermes plugin for *new* installs (fail-closed).
pub const hermes_fail_stance_filename = ".ryk_fail_stance";

/// Effective Hermes fail-open from an env value only. Missing, empty, and
/// unrecognized values are fail-closed.
pub fn hermesFailOpenFromEnvValue(value: ?[]const u8) bool {
    const raw = value orelse return false;
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return false;
    if (std.ascii.eqlIgnoreCase(trimmed, "0") or
        std.ascii.eqlIgnoreCase(trimmed, "false") or
        std.ascii.eqlIgnoreCase(trimmed, "no") or
        std.ascii.eqlIgnoreCase(trimmed, "off") or
        std.ascii.eqlIgnoreCase(trimmed, "fail-closed") or
        std.ascii.eqlIgnoreCase(trimmed, "closed"))
        return false;
    if (std.ascii.eqlIgnoreCase(trimmed, "1") or
        std.ascii.eqlIgnoreCase(trimmed, "true") or
        std.ascii.eqlIgnoreCase(trimmed, "yes") or
        std.ascii.eqlIgnoreCase(trimmed, "on") or
        std.ascii.eqlIgnoreCase(trimmed, "fail-open") or
        std.ascii.eqlIgnoreCase(trimmed, "open"))
        return true;
    return false;
}

/// Parse install stance file content (`fail-closed` / `0` / `fail-open` / `1`).
pub fn hermesFailOpenFromStanceText(text: []const u8) ?bool {
    const trimmed = std.mem.trim(u8, text, " \t\r\n");
    if (trimmed.len == 0) return null;
    if (std.ascii.eqlIgnoreCase(trimmed, "0") or
        std.ascii.eqlIgnoreCase(trimmed, "false") or
        std.ascii.eqlIgnoreCase(trimmed, "no") or
        std.ascii.eqlIgnoreCase(trimmed, "off") or
        std.ascii.eqlIgnoreCase(trimmed, "fail-closed") or
        std.ascii.eqlIgnoreCase(trimmed, "closed"))
        return false;
    if (std.ascii.eqlIgnoreCase(trimmed, "1") or
        std.ascii.eqlIgnoreCase(trimmed, "true") or
        std.ascii.eqlIgnoreCase(trimmed, "yes") or
        std.ascii.eqlIgnoreCase(trimmed, "on") or
        std.ascii.eqlIgnoreCase(trimmed, "fail-open") or
        std.ascii.eqlIgnoreCase(trimmed, "open"))
        return true;
    return null;
}

/// Env wins when set; else install stance file under `plugin_dir`; else fail closed.
pub fn hermesFailOpenEffective(env_value: ?[]const u8, stance_file_text: ?[]const u8) bool {
    if (env_value) |v| {
        const trimmed = std.mem.trim(u8, v, " \t\r\n");
        return hermesFailOpenFromEnvValue(trimmed);
    }
    if (stance_file_text) |text| {
        if (hermesFailOpenFromStanceText(text)) |open| return open;
    }
    return false;
}

fn readHermesStanceFile(allocator: std.mem.Allocator) ?[]u8 {
    var env_map = env_util.createProcessMap(allocator) catch return null;
    defer env_map.deinit();
    const home_owned = env_util.getOwnedHome(&env_map, allocator) catch return null;
    const home = home_owned orelse return null;
    defer allocator.free(home);
    const path = std.fs.path.join(allocator, &.{ home, ".hermes", "plugins", "ryk", hermes_fail_stance_filename }) catch return null;
    defer allocator.free(path);
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    return std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(64)) catch null;
}

pub fn hermesFailOpenFromEnv() bool {
    var env_map = env_util.createProcessMap(std.heap.page_allocator) catch return false;
    defer env_map.deinit();
    const value = env_util.getOwnedBrand(&env_map, std.heap.page_allocator, "HERMES_FAIL_OPEN") catch null;
    defer if (value) |v| std.heap.page_allocator.free(v);

    // When env is present, including empty or invalid values, it wins and
    // remains fail-closed unless it contains an explicit recognized token.
    if (value) |v| {
        return hermesFailOpenFromEnvValue(v);
    }

    // New installs write .ryk_fail_stance under the user plugin dir.
    if (readHermesStanceFile(std.heap.page_allocator)) |stance| {
        defer std.heap.page_allocator.free(stance);
        if (hermesFailOpenFromStanceText(stance)) |open| return open;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test {
    _ = pi_install;
}

test "interpretSmokeOutcome allow requires exit 0 and decision allow" {
    try std.testing.expect(interpretSmokeOutcome("claude", "allow", 0, "{\"decision\":\"allow\"}\n", ""));
    try std.testing.expect(!interpretSmokeOutcome("claude", "allow", 0, "{\"decision\":\"block\"}\n", ""));
    try std.testing.expect(!interpretSmokeOutcome("claude", "allow", 1, "{\"decision\":\"allow\"}\n", ""));
}

test "interpretSmokeOutcome block for flexible hosts uses decision JSON" {
    try std.testing.expect(interpretSmokeOutcome("claude", "block", 0, "{\"decision\":\"block\"}\n", ""));
    try std.testing.expect(interpretSmokeOutcome("hermes", "block", 0, "{\n  \"decision\": \"block\"\n}\n", ""));
    try std.testing.expect(interpretSmokeOutcome("opencode", "block", 0, "{\"decision\":\"block\",\"reason\":\"x\"}", ""));
    try std.testing.expect(!interpretSmokeOutcome("openclaw", "block", 0, "{\"decision\":\"allow\"}", ""));
}

test "Grok host status uses raw PreToolUse fixtures and exit-two deny" {
    try std.testing.expectEqualStrings("PreToolUse", shellGate("grok"));
    try std.testing.expect(interpretSmokeOutcome("grok", "block", 2, "", ""));
    try std.testing.expect(!interpretSmokeOutcome("grok", "block", 0, "", ""));

    const fixture = try buildHookFixture(std.testing.allocator, "grok", "PreToolUse", "git status");
    defer std.testing.allocator.free(fixture);
    // Official Grok Build wire shape (camelCase + snake_case event value).
    try std.testing.expect(std.mem.startsWith(u8, fixture, "{\"hookEventName\":\"pre_tool_use\""));
    try std.testing.expect(std.mem.indexOf(u8, fixture, "\"cwd\":\"/tmp\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, fixture, "\"toolName\":\"run_terminal_cmd\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, fixture, "\"toolInput\":{\"command\":\"git status\"}") != null);
    try std.testing.expect(std.mem.indexOf(u8, fixture, "\"payload\"") == null);
}

test "interpretSmokeOutcome codex deny uses exit code 2" {
    try std.testing.expect(interpretSmokeOutcome("codex", "block", 2, "", "[[RYKAN-V-GUARD]] blocked."));
    try std.testing.expect(!interpretSmokeOutcome("codex", "block", 0, "", "error"));
    try std.testing.expect(interpretSmokeOutcome("codex", "block", 0, "{\"decision\":\"block\"}", ""));
}

test "buildHookFixture embeds host event and command" {
    const allocator = std.testing.allocator;
    const fixture = try buildHookFixture(allocator, "claude", "PreToolUse", "git status");
    defer allocator.free(fixture);
    try std.testing.expect(std.mem.indexOf(u8, fixture, "\"host\":\"claude\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, fixture, "\"event\":\"PreToolUse\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, fixture, "git status") != null);
    try std.testing.expect(std.mem.indexOf(u8, fixture, "tool_input") != null);
}

test "shellGate and failStance cover all P1 hosts" {
    try std.testing.expectEqualStrings("PreToolUse", shellGate("codex"));
    try std.testing.expectEqualStrings("PreToolUse", shellGate("claude"));
    try std.testing.expectEqualStrings("PreToolUse", shellGate("grok"));
    try std.testing.expectEqualStrings("tool.execute.before", shellGate("opencode"));
    try std.testing.expectEqualStrings("tool.before", shellGate("openclaw"));
    try std.testing.expectEqualStrings("pre_tool_call", shellGate("hermes"));
    try std.testing.expectEqualStrings("extension-managed (smoke not run)", shellGate("pi"));
    try std.testing.expectEqualStrings("fail-open (explicit)", failStance("hermes", true, "yes"));
    try std.testing.expectEqualStrings("fail-closed", failStance("hermes", false, "yes"));
    // RT-06/H1: Hermes unwired must not claim an active fail stance.
    try std.testing.expectEqualStrings("unwired (no fail-closed shell)", failStance("hermes", false, "no"));
    try std.testing.expectEqualStrings("unwired (no fail-closed shell)", failStance("hermes", true, "—"));
    try std.testing.expectEqualStrings("fail-open (explicit)", failStance("hermes", true, "partial"));
    try std.testing.expectEqualStrings("mode-dependent", failStance("pi", true, "yes"));
    try std.testing.expectEqualStrings("mode-dependent", failStance("pi", true, "no"));
    try std.testing.expectEqualStrings("fail-closed shell", failStance("codex", true, "yes"));
    // RT-06: unwired host must not claim fail-closed shell
    try std.testing.expectEqualStrings("unwired (no fail-closed shell)", failStance("codex", true, "no"));
    try std.testing.expectEqualStrings("unwired (no fail-closed shell)", failStance("opencode", true, "no"));
    try std.testing.expectEqualStrings("unwired (no fail-closed shell)", failStance("claude", true, "—"));
    try std.testing.expectEqualStrings("fail-closed shell", failStance("opencode", true, "partial"));
}

test "formatFix prefers smoke failure and hermes fail-open remediation" {
    const allocator = std.testing.allocator;
    const smoke_fail = try formatFix(allocator, "claude", "yes", .{ .allow = .pass, .deny = .fail }, true);
    defer allocator.free(smoke_fail);
    try std.testing.expect(std.mem.indexOf(u8, smoke_fail, "plugin doctor claude") != null);

    const hermes_open = try formatFix(allocator, "hermes", "yes", .{}, true);
    defer allocator.free(hermes_open);
    try std.testing.expect(std.mem.indexOf(u8, hermes_open, "unset RYK_HERMES_FAIL_OPEN") != null);

    const pi_fix = try formatFix(allocator, "pi", "—", .{}, true);
    defer allocator.free(pi_fix);
    try std.testing.expect(std.mem.indexOf(u8, pi_fix, "doctor --fix") != null);
    try std.testing.expect(std.mem.indexOf(u8, pi_fix, "ryk start") == null);
    try std.testing.expect(std.mem.indexOf(u8, pi_fix, "coverage") == null);

    // PR #97 residual: grok repair door is doctor --fix — never teach ryk start as primary.
    const grok_unwired = try formatFix(allocator, "grok", "no", .{}, true);
    defer allocator.free(grok_unwired);
    try std.testing.expect(std.mem.indexOf(u8, grok_unwired, "ryk doctor --fix") != null);
    try std.testing.expect(std.mem.indexOf(u8, grok_unwired, "ryk start") == null);
    try std.testing.expect(std.mem.indexOf(u8, grok_unwired, "plugin install grok") == null);

    const grok_missing = try formatFix(allocator, "grok", "—", .{}, true);
    defer allocator.free(grok_missing);
    try std.testing.expect(std.mem.indexOf(u8, grok_missing, "ryk doctor --fix") != null);
    try std.testing.expect(std.mem.indexOf(u8, grok_missing, "ryk start") == null);

    // Cursor / hermes already on doctor --fix or env remediation — no start teach.
    const cursor_fix = try formatFix(allocator, "cursor", "no", .{}, true);
    defer allocator.free(cursor_fix);
    try std.testing.expect(std.mem.indexOf(u8, cursor_fix, "ryk doctor --fix") != null);
    try std.testing.expect(std.mem.indexOf(u8, cursor_fix, "ryk start") == null);
}

test "Pi status distinguishes host detection from extension installation" {
    const binary_only = PiStatus{ .binary_detected = true };
    try std.testing.expectEqualStrings("no", binary_only.wiredLabel());
    try std.testing.expectEqualStrings("Pi detected; ryk extension not installed", binary_only.detail());

    const installed = PiStatus{ .binary_detected = true, .extension_installed = true };
    try std.testing.expectEqualStrings("yes", installed.wiredLabel());
    try std.testing.expectEqualStrings("ryk extension installed; coverage unknown until live smoke", installed.detail());

    const absent = PiStatus{};
    try std.testing.expectEqualStrings("—", absent.wiredLabel());
}

test "Pi extension installation requires registration and official package markers" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(home);

    try tmp.dir.createDirPath(std.testing.io, ".pi/agent/npm/node_modules/@rykan/pi-ryk/extensions");
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = ".pi/agent/npm/node_modules/@rykan/pi-ryk/package.json",
        .data = "{\"name\":\"@rykan/pi-ryk\",\"version\":\"1.2.9\"}",
    });
    try std.testing.expect(!piExtensionInstalledAtHome(std.testing.io, std.testing.allocator, home));

    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = ".pi/agent/npm/node_modules/@rykan/pi-ryk/extensions/ryk.ts",
        .data = "export default function ryk() {}",
    });
    try std.testing.expect(!piExtensionInstalledAtHome(std.testing.io, std.testing.allocator, home));

    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = ".pi/agent/settings.json",
        .data = "{\"packages\":[\"npm:@rykan/pi-ryk\"]}",
    });
    try std.testing.expect(piExtensionInstalledAtHome(std.testing.io, std.testing.allocator, home));
}

test "Pi process command is exact and copyable" {
    try std.testing.expectEqualStrings("ryk run -- pi", pi_process_command);
    try std.testing.expect(std.mem.indexOf(u8, pi_process_command, "…") == null);
}

test "HostSmokePair bothPassed requires allow and deny pass" {
    try std.testing.expect((HostSmokePair{ .allow = .pass, .deny = .pass }).bothPassed());
    try std.testing.expect(!(HostSmokePair{ .allow = .pass, .deny = .fail }).bothPassed());
    try std.testing.expect(!(HostSmokePair{ .allow = .not_run, .deny = .not_run }).bothPassed());
}

test "classifyReadiness maps smoke to protected degraded not-protected" {
    try std.testing.expectEqual(HostReadiness.protected, classifyReadiness(.{ .allow = .pass, .deny = .pass }));
    try std.testing.expectEqual(HostReadiness.degraded, classifyReadiness(.{ .allow = .fail, .deny = .pass }));
    try std.testing.expectEqual(HostReadiness.not_protected, classifyReadiness(.{ .allow = .pass, .deny = .fail }));
    try std.testing.expectEqual(HostReadiness.not_protected, classifyReadiness(.{ .allow = .fail, .deny = .fail }));
    try std.testing.expectEqual(HostReadiness.unknown, classifyReadiness(.{}));
    try std.testing.expect(std.mem.indexOf(u8, HostReadiness.degraded.label(), "not ready") != null);
    try std.testing.expect(std.mem.indexOf(u8, HostReadiness.not_protected.label(), "not protected") != null);
}

test "formatFix degraded prefers daemon doctor not reinstall" {
    const allocator = std.testing.allocator;
    const fix = try formatFix(allocator, "claude", "yes", .{ .allow = .fail, .deny = .pass }, true);
    defer allocator.free(fix);
    try std.testing.expect(std.mem.indexOf(u8, fix, "ryk doctor") != null);
    try std.testing.expect(std.mem.indexOf(u8, fix, "not ready") != null);
}

test "hermesFailOpenEffective prefers env then stance then default closed" {
    try std.testing.expect(!hermesFailOpenEffective(null, null));
    try std.testing.expect(!hermesFailOpenEffective(null, "fail-closed"));
    try std.testing.expect(hermesFailOpenEffective(null, "fail-open"));
    try std.testing.expect(!hermesFailOpenEffective("0", "fail-open"));
    try std.testing.expect(hermesFailOpenEffective("1", "fail-closed"));
    try std.testing.expect(!hermesFailOpenEffective("typo", "fail-open"));
    try std.testing.expect(!hermesFailOpenEffective("", "fail-open"));
    try std.testing.expect(!hermesFailOpenFromStanceText("fail-closed").?);
}

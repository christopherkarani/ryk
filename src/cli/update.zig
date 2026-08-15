//! `ryk update` — upgrade the installed ryk binary via the official installer.
//!
//! Reuses scripts/install.sh (Unix) / install.ps1 (Windows) so checksums,
//! atomic binary replace, and runtime layout stay one code path with first install.

const std = @import("std");
const builtin = @import("builtin");
const gpa_mod = @import("gpa.zig");
const build_options = @import("build_options");

const exit_codes = @import("exit_codes.zig");
const help = @import("help.zig");
const danger_confirmation = @import("danger_confirmation.zig");
const suggestions = @import("suggestions.zig");
const env_util = @import("../env_util.zig");
const telemetry = @import("../telemetry.zig");

pub const github_latest_url = "https://api.github.com/repos/christopherkarani/ryk/releases/latest";
/// Fallback when no target version is known (should be rare — prefer tag-pinned URLs).
pub const install_script_url_main = "https://raw.githubusercontent.com/christopherkarani/ryk/main/scripts/install.sh";
pub const install_ps1_url_main = "https://raw.githubusercontent.com/christopherkarani/ryk/main/scripts/install.ps1";
/// Back-compat alias used in user-facing manual recovery messages.
pub const install_script_url = install_script_url_main;
pub const install_ps1_url = install_ps1_url_main;
pub const docs_install_url = "https://github.com/christopherkarani/ryk/blob/main/docs/install.md";
pub const supported_install_command = "curl -fsSL https://rykanv.com/install | sh";

/// Pin installer script to the release tag that matches `target_version` (no leading `v`).
pub fn installScriptUrlForVersion(allocator: std.mem.Allocator, target_version: []const u8, windows: bool) ![]u8 {
    const tag = stripLeadingV(target_version);
    if (tag.len == 0) {
        return try allocator.dupe(u8, if (windows) install_ps1_url_main else install_script_url_main);
    }
    if (windows) {
        return try std.fmt.allocPrint(
            allocator,
            "https://raw.githubusercontent.com/christopherkarani/ryk/v{s}/scripts/install.ps1",
            .{tag},
        );
    }
    return try std.fmt.allocPrint(
        allocator,
        "https://raw.githubusercontent.com/christopherkarani/ryk/v{s}/scripts/install.sh",
        .{tag},
    );
}

pub const InstallChannel = enum {
    curl_installer,
    homebrew,
    npm,
    scoop,
    winget,
    unknown,
};

pub const Args = struct {
    check_only: bool = false,
    yes: bool = false,
    force: bool = false,
    json: bool = false,
    /// Pinned target version (no leading `v`). Null means resolve latest.
    version: ?[]const u8 = null,
};

pub const Semver = struct {
    major: u32,
    minor: u32,
    patch: u32,
};

pub const Order = enum { older, equal, newer };

const option_candidates = [_][]const u8{ "--check", "--yes", "--force", "--json", "--version", "--help" };

// ---------------------------------------------------------------------------
// Pure helpers (unit-tested without network)
// ---------------------------------------------------------------------------

pub fn parseArgs(argv: []const []const u8) !Args {
    var out: Args = .{};
    var index: usize = 0;
    while (index < argv.len) : (index += 1) {
        const arg = argv[index];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            return error.HelpRequested;
        }
        if (std.mem.eql(u8, arg, "--check")) {
            out.check_only = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--yes")) {
            out.yes = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--force")) {
            out.force = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--json")) {
            out.json = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--version")) {
            if (index + 1 >= argv.len) return error.MissingVersionValue;
            index += 1;
            const raw = argv[index];
            if (raw.len == 0 or std.mem.startsWith(u8, raw, "-")) return error.InvalidVersionValue;
            out.version = stripLeadingV(raw);
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--version=")) {
            const raw = arg["--version=".len..];
            if (raw.len == 0) return error.InvalidVersionValue;
            out.version = stripLeadingV(raw);
            continue;
        }
        return error.UnknownOption;
    }
    return out;
}

pub fn stripLeadingV(version: []const u8) []const u8 {
    if (version.len > 0 and (version[0] == 'v' or version[0] == 'V')) return version[1..];
    return version;
}

/// Parse major.minor.patch; ignores a trailing prerelease/build (`-rc.1`, `+meta`).
pub fn parseSemver(text: []const u8) !Semver {
    const core = stripLeadingV(text);
    const end = std.mem.indexOfAny(u8, core, "-+") orelse core.len;
    const base = core[0..end];
    var parts = std.mem.splitScalar(u8, base, '.');
    const major_s = parts.next() orelse return error.InvalidSemver;
    const minor_s = parts.next() orelse return error.InvalidSemver;
    const patch_s = parts.next() orelse return error.InvalidSemver;
    if (parts.next() != null) return error.InvalidSemver;
    if (major_s.len == 0 or minor_s.len == 0 or patch_s.len == 0) return error.InvalidSemver;
    return .{
        .major = try std.fmt.parseInt(u32, major_s, 10),
        .minor = try std.fmt.parseInt(u32, minor_s, 10),
        .patch = try std.fmt.parseInt(u32, patch_s, 10),
    };
}

/// True when version string carries a prerelease suffix (`-rc.1`, `-beta`, …).
pub fn hasPrereleaseSuffix(text: []const u8) bool {
    const core = stripLeadingV(text);
    return std.mem.indexOfScalar(u8, core, '-') != null;
}

/// Compare `a` to `b`: returns `.older` if a < b, `.equal` if equal, `.newer` if a > b.
pub fn compareSemver(a: Semver, b: Semver) Order {
    if (a.major != b.major) return if (a.major < b.major) .older else .newer;
    if (a.minor != b.minor) return if (a.minor < b.minor) .older else .newer;
    if (a.patch != b.patch) return if (a.patch < b.patch) .older else .newer;
    return .equal;
}

pub fn compareVersionStrings(current: []const u8, target: []const u8) !Order {
    const a = try parseSemver(current);
    const b = try parseSemver(target);
    const base = compareSemver(a, b);
    if (base != .equal) return base;
    // Same major.minor.patch: prerelease is older than a final release so
    // `1.2.9-rc.1` → `1.2.9` is an upgrade, not a skip.
    const cur_pre = hasPrereleaseSuffix(current);
    const tgt_pre = hasPrereleaseSuffix(target);
    if (cur_pre and !tgt_pre) return .older;
    if (!cur_pre and tgt_pre) return .newer;
    return .equal;
}

/// Heuristic install channel from the running binary path.
pub fn detectInstallChannel(exe_path: []const u8) InstallChannel {
    if (exe_path.len == 0) return .unknown;

    var lower_buf: [std.fs.max_path_bytes]u8 = undefined;
    if (exe_path.len > lower_buf.len) return .unknown;
    const lower = std.ascii.lowerString(lower_buf[0..exe_path.len], exe_path);

    if (std.mem.indexOf(u8, lower, "/cellar/") != null or
        std.mem.indexOf(u8, lower, "\\cellar\\") != null or
        std.mem.indexOf(u8, lower, "/homebrew/") != null or
        std.mem.indexOf(u8, lower, "\\homebrew\\") != null or
        std.mem.indexOf(u8, lower, "/linuxbrew/") != null)
    {
        return .homebrew;
    }
    if (std.mem.indexOf(u8, lower, "/node_modules/") != null or
        std.mem.indexOf(u8, lower, "\\node_modules\\") != null or
        std.mem.indexOf(u8, lower, "/.npm/") != null or
        std.mem.indexOf(u8, lower, "\\npm\\") != null)
    {
        return .npm;
    }
    if (std.mem.indexOf(u8, lower, "/scoop/") != null or
        std.mem.indexOf(u8, lower, "\\scoop\\") != null)
    {
        return .scoop;
    }
    if (std.mem.indexOf(u8, lower, "\\winget\\") != null or
        std.mem.indexOf(u8, lower, "/winget/") != null or
        std.mem.indexOf(u8, lower, "\\packages\\ryk") != null)
    {
        return .winget;
    }
    if (std.mem.indexOf(u8, lower, "/.local/bin/") != null or
        std.mem.indexOf(u8, lower, "\\.local\\bin\\") != null or
        std.mem.indexOf(u8, lower, "\\.ryk\\bin\\") != null)
    {
        return .curl_installer;
    }
    return .unknown;
}

pub fn channelAllowsInstaller(channel: InstallChannel, force: bool) bool {
    if (force) return true;
    return switch (channel) {
        .curl_installer, .unknown => true,
        .homebrew, .npm, .scoop, .winget => false,
    };
}

pub fn packageManagerHint(channel: InstallChannel) []const u8 {
    return switch (channel) {
        .homebrew, .npm, .scoop, .winget, .curl_installer, .unknown => supported_install_command,
    };
}

/// Extract tag_name from a GitHub releases/latest JSON body (minimal parser).
pub fn parseGitHubLatestTag(body: []const u8) ![]const u8 {
    const key = "\"tag_name\"";
    const key_pos = std.mem.indexOf(u8, body, key) orelse return error.MissingTagName;
    var i = key_pos + key.len;
    while (i < body.len and (body[i] == ' ' or body[i] == '\t' or body[i] == '\n' or body[i] == '\r' or body[i] == ':')) : (i += 1) {}
    if (i >= body.len or body[i] != '"') return error.MissingTagName;
    i += 1;
    const start = i;
    while (i < body.len and body[i] != '"') : (i += 1) {}
    if (i >= body.len) return error.MissingTagName;
    const tag = body[start..i];
    if (tag.len == 0) return error.MissingTagName;
    return stripLeadingV(tag);
}

pub fn shouldProceedWithInstall(order: Order, force: bool, version_pinned: bool) bool {
    return switch (order) {
        .older => true,
        .equal => false,
        .newer => force and version_pinned,
    };
}

// ---------------------------------------------------------------------------
// Command
// ---------------------------------------------------------------------------

pub fn command(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    var gpa_state: gpa_mod.State = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();

    const args = parseArgs(argv) catch |err| switch (err) {
        error.HelpRequested => {
            _ = try help.writeCommand(io, stdout, "update");
            return exit_codes.success;
        },
        error.MissingVersionValue => {
            try stderr.writeAll("ryk update: --version requires a value.\nRun 'ryk help update' for usage.\n");
            return exit_codes.usage;
        },
        error.InvalidVersionValue => {
            try stderr.writeAll("ryk update: invalid --version value.\nRun 'ryk help update' for usage.\n");
            return exit_codes.usage;
        },
        error.UnknownOption => {
            var unknown: []const u8 = "option";
            for (argv) |arg| {
                if (std.mem.startsWith(u8, arg, "-") and
                    !std.mem.eql(u8, arg, "--check") and
                    !std.mem.eql(u8, arg, "--yes") and
                    !std.mem.eql(u8, arg, "--force") and
                    !std.mem.eql(u8, arg, "--json") and
                    !std.mem.eql(u8, arg, "--help") and
                    !std.mem.eql(u8, arg, "-h") and
                    !std.mem.eql(u8, arg, "--version") and
                    !std.mem.startsWith(u8, arg, "--version="))
                {
                    unknown = arg;
                    break;
                }
            }
            try suggestions.writeUnknownOption(stderr, "ryk update", unknown, &option_candidates, "update");
            return exit_codes.usage;
        },
    };

    // Reject non-semver pins early so --json never embeds raw hostile argv.
    if (args.version) |pinned| {
        _ = parseSemver(pinned) catch {
            if (args.json) {
                try writeJsonResult(stdout, .{
                    .status = "error",
                    .current = build_options.version,
                    .target = null,
                    .channel = "unknown",
                    .action = "none",
                    .message = "invalid --version: expected major.minor.patch",
                });
            } else {
                try stderr.writeAll("ryk update: --version must be a semver like 1.2.9.\n");
            }
            return exit_codes.usage;
        };
    }

    const current = build_options.version;
    const exe_path = std.process.executablePathAlloc(io, allocator) catch null;
    defer if (exe_path) |p| allocator.free(p);
    const channel = detectInstallChannel(if (exe_path) |p| p else "");

    var target_owned: ?[]u8 = null;
    defer if (target_owned) |t| allocator.free(t);

    const target: []const u8 = blk: {
        if (args.version) |pinned| break :blk pinned;
        const body = fetchGitHubLatest(allocator, io) catch |err| {
            telemetry.recordUpdateFailed(@tagName(channel), "resolve");
            if (args.json) {
                try writeJsonResult(stdout, .{
                    .status = "error",
                    .current = current,
                    .target = null,
                    .channel = @tagName(channel),
                    .action = "none",
                    .message = "failed to resolve latest release",
                });
            } else {
                try stderr.print("ryk update: could not resolve latest release ({s}).\n", .{@errorName(err)});
                try stderr.writeAll("  Check network access, or pin a version: ryk update --version <semver>\n");
                try stderr.print("  Docs: {s}\n", .{docs_install_url});
            }
            return exit_codes.general;
        };
        defer allocator.free(body);
        const tag = parseGitHubLatestTag(body) catch {
            telemetry.recordUpdateFailed(@tagName(channel), "parse");
            if (args.json) {
                try writeJsonResult(stdout, .{
                    .status = "error",
                    .current = current,
                    .target = null,
                    .channel = @tagName(channel),
                    .action = "none",
                    .message = "could not parse GitHub latest tag",
                });
            } else {
                try stderr.writeAll("ryk update: could not parse GitHub latest release tag.\n");
            }
            return exit_codes.general;
        };
        // Validate remote tag is parseable semver before trusting it.
        _ = parseSemver(tag) catch {
            telemetry.recordUpdateFailed(@tagName(channel), "parse");
            if (args.json) {
                try writeJsonResult(stdout, .{
                    .status = "error",
                    .current = current,
                    .target = null,
                    .channel = @tagName(channel),
                    .action = "none",
                    .message = "latest release tag is not a valid semver",
                });
            } else {
                try stderr.writeAll("ryk update: latest release tag is not a valid semver.\n");
            }
            return exit_codes.general;
        };
        target_owned = try allocator.dupe(u8, tag);
        break :blk target_owned.?;
    };

    const order = compareVersionStrings(current, target) catch {
        telemetry.recordUpdateFailed(@tagName(channel), "compare");
        if (args.json) {
            try writeJsonResult(stdout, .{
                .status = "error",
                .current = current,
                .target = target,
                .channel = @tagName(channel),
                .action = "none",
                .message = "invalid version string",
            });
        } else {
            try stderr.print("ryk update: invalid version (current={s}, target={s}).\n", .{ current, target });
        }
        return exit_codes.general;
    };

    if (args.check_only) {
        return writeCheckResult(stdout, args.json, current, target, channel, order);
    }

    if (!shouldProceedWithInstall(order, args.force, args.version != null)) {
        if (args.json) {
            try writeJsonResult(stdout, .{
                .status = "up_to_date",
                .current = current,
                .target = target,
                .channel = @tagName(channel),
                .action = "none",
                .message = if (order == .newer)
                    "current version is newer than target; use --force --version to downgrade"
                else
                    "already at target version",
            });
        } else if (order == .newer) {
            try stdout.print("ryk {s} is newer than target {s}.\n", .{ current, target });
            try stdout.writeAll("To install the older version: ryk update --force --version <semver> --yes\n");
        } else {
            try stdout.print("ryk is up to date ({s}).\n", .{current});
        }
        return exit_codes.success;
    }

    if (!channelAllowsInstaller(channel, args.force)) {
        telemetry.recordUpdateFailed(@tagName(channel), "channel");
        const hint = packageManagerHint(channel);
        if (args.json) {
            try writeJsonResult(stdout, .{
                .status = "package_managed",
                .current = current,
                .target = target,
                .channel = @tagName(channel),
                .action = "none",
                .message = "package-managed install detected; migrate with the supported curl installer",
            });
        } else {
            try stderr.print("ryk update: this binary looks package-managed ({s}).\n", .{@tagName(channel)});
            try stderr.print("The supported install path is:\n  {s}\n", .{hint});
            try stderr.writeAll("Use it to migrate this install, or run: ryk update --force --yes\n");
        }
        return exit_codes.usage;
    }

    // JSON mode is non-interactive: require --yes (or treat as requires_yes).
    if (!args.yes) {
        if (args.json) {
            try writeJsonResult(stdout, .{
                .status = "error",
                .current = current,
                .target = target,
                .channel = @tagName(channel),
                .action = "none",
                .message = "confirmation required: pass --yes with --json",
            });
            return exit_codes.usage;
        }
        const stdin = std.Io.File.stdin();
        var prompt_buf: [128]u8 = undefined;
        const prompt = std.fmt.bufPrint(&prompt_buf, "Update ryk {s} → {s}?", .{ current, target }) catch "Update ryk?";
        const decision = danger_confirmation.decide(io, stdout, prompt, false, try stdin.isTty(io), null) catch |err| {
            telemetry.recordUpdateFailed(@tagName(channel), "confirmation");
            try stderr.print("ryk update: confirmation failed: {s}\n", .{@errorName(err)});
            return exit_codes.general;
        };
        switch (decision) {
            .proceed => {},
            .cancelled => {
                try stdout.writeAll("canceled\n");
                return exit_codes.success;
            },
            .requires_yes => {
                try stderr.writeAll("ryk update: requires --yes or an interactive terminal.\n");
                return exit_codes.usage;
            },
        }
    }

    if (!args.json) {
        try stdout.print("Updating ryk {s} → {s} via official installer…\n\n", .{ current, target });
    }

    const install_code = runOfficialInstaller(allocator, io, target, args.json, stderr) catch |err| {
        telemetry.recordUpdateFailed(@tagName(channel), "installer");
        if (args.json) {
            try writeJsonResult(stdout, .{
                .status = "error",
                .current = current,
                .target = target,
                .channel = @tagName(channel),
                .action = "install_failed",
                .message = @errorName(err),
            });
        } else {
            try stderr.print("ryk update: installer failed: {s}\n", .{@errorName(err)});
            try stderr.print("  Manual: RYK_VERSION={s} curl -fsSL {s} | sh\n", .{ target, install_script_url });
            try stderr.print("  Docs: {s}\n", .{docs_install_url});
        }
        return exit_codes.general;
    };

    if (install_code != 0) {
        telemetry.recordUpdateFailed(@tagName(channel), "installer");
        if (args.json) {
            try writeJsonResult(stdout, .{
                .status = "error",
                .current = current,
                .target = target,
                .channel = @tagName(channel),
                .action = "install_failed",
                .message = "installer exited non-zero",
            });
        } else {
            try stderr.print("ryk update: installer exited with code {d}.\n", .{install_code});
        }
        return exit_codes.general;
    }

    // Best-effort: re-read on-PATH version. Installer exit 0 alone is not enough
    // when PATH still points at a different binary.
    const post = resolveOnPathVersion(allocator, io);
    defer if (post) |p| allocator.free(p);
    const verified = if (post) |p| blk: {
        const post_order = compareVersionStrings(p, target) catch break :blk false;
        // Accept equal (exact) or newer (channel already past target).
        break :blk post_order == .equal or post_order == .newer;
    } else false;

    if (verified) {
        telemetry.recordUpdateCompleted(@tagName(channel), current, target, "verified");
    } else {
        telemetry.recordUpdateFailed(@tagName(channel), "verify");
    }

    if (args.json) {
        try writeJsonResult(stdout, .{
            .status = if (verified) "updated" else "installed_unverified",
            .current = if (post) |p| p else current,
            .target = target,
            .channel = @tagName(channel),
            .action = if (verified) "installed" else "installed_unverified",
            .message = if (verified)
                "installer completed; on-PATH version matches target"
            else
                "installer exited 0 but on-PATH version could not be confirmed; restart shells and re-check",
        });
    } else if (verified) {
        try stdout.print("\n✅ Update complete: ryk {s} → {s}\n", .{ current, target });
        try stdout.writeAll("If hosts need rewiring after a major change, run: ryk start\n");
    } else {
        try stdout.print("\n⚠ Installer finished, but could not confirm ryk {s} on PATH.\n", .{target});
        try stdout.writeAll("Open a new shell and run: ryk version\n");
        try stdout.writeAll("If hosts need rewiring after a major change, run: ryk start\n");
    }
    return exit_codes.success;
}

const JsonPayload = struct {
    status: []const u8,
    current: []const u8,
    target: ?[]const u8,
    channel: []const u8,
    action: []const u8,
    message: []const u8,
};

fn writeJsonResult(writer: anytype, payload: JsonPayload) !void {
    try writer.writeAll("{\n  \"status\": ");
    try writeJsonString(writer, payload.status);
    try writer.writeAll(",\n  \"current\": ");
    try writeJsonString(writer, payload.current);
    try writer.writeAll(",\n  \"target\": ");
    if (payload.target) |t| {
        try writeJsonString(writer, t);
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\n  \"channel\": ");
    try writeJsonString(writer, payload.channel);
    try writer.writeAll(",\n  \"action\": ");
    try writeJsonString(writer, payload.action);
    try writer.writeAll(",\n  \"message\": ");
    try writeJsonString(writer, payload.message);
    try writer.writeAll("\n}\n");
}

/// Same escaping contract as `version.zig` / core util (all string fields).
fn writeJsonString(writer: anytype, value: []const u8) !void {
    try writer.writeByte('"');
    for (value) |byte| {
        switch (byte) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            0...8, 11...12, 14...0x1f => try writer.print("\\u{x:0>4}", .{byte}),
            else => try writer.writeByte(byte),
        }
    }
    try writer.writeByte('"');
}

fn writeCheckResult(
    stdout: anytype,
    json: bool,
    current: []const u8,
    target: []const u8,
    channel: InstallChannel,
    order: Order,
) !u8 {
    const status: []const u8 = switch (order) {
        .equal => "up_to_date",
        .older => "update_available",
        .newer => "ahead_of_target",
    };
    if (json) {
        try writeJsonResult(stdout, .{
            .status = status,
            .current = current,
            .target = target,
            .channel = @tagName(channel),
            .action = "check",
            .message = switch (order) {
                .equal => "already at latest",
                .older => "a newer release is available",
                .newer => "current is newer than target",
            },
        });
    } else {
        try stdout.print("Current: {s}\n", .{current});
        try stdout.print("Latest:  {s}\n", .{target});
        try stdout.print("Channel: {s}\n", .{@tagName(channel)});
        switch (order) {
            .equal => try stdout.writeAll("Status:  up to date\n"),
            .older => try stdout.print("Status:  update available ({s} → {s})\n", .{ current, target }),
            .newer => try stdout.print("Status:  local is newer than target ({s} > {s})\n", .{ current, target }),
        }
    }
    return exit_codes.success;
}

const github_latest_html_url = "https://github.com/christopherkarani/ryk/releases/latest";

fn fetchGitHubLatest(allocator: std.mem.Allocator, io: std.Io) ![]u8 {
    var ua_header: [80]u8 = undefined;
    const header = std.fmt.bufPrint(&ua_header, "User-Agent: ryk-update/{s}", .{build_options.version}) catch "User-Agent: ryk-update";

    var ua_value: [64]u8 = undefined;
    const ua = std.fmt.bufPrint(&ua_value, "ryk-update/{s}", .{build_options.version}) catch "ryk-update";

    // 1) GitHub API (same as install.sh). May 403 under unauthenticated rate limits.
    if (runCapture(allocator, io, &.{
        "curl", "-fsSL", "--max-time", "8", "-H", header, github_latest_url,
    })) |body| {
        return body;
    } else |_| {}

    if (runCapture(allocator, io, &.{
        "wget", "-qO-", "--timeout=8", "--user-agent", ua, github_latest_url,
    })) |body| {
        return body;
    } else |_| {}

    // 2) Fallback: resolve the HTML release redirect final URL (no API quota).
    //    curl -w '%{url_effective}' -o /dev/null -L → …/releases/tag/vX.Y.Z
    if (runCapture(allocator, io, &.{
        "curl", "-fsSL", "--max-time", "8", "-H", header, "-o", "/dev/null", "-w", "%{url_effective}", github_latest_html_url,
    })) |final_url| {
        defer allocator.free(final_url);
        if (tagFromReleaseUrl(final_url)) |tag| {
            // synthesize a tiny JSON body so parseGitHubLatestTag works unchanged
            return try std.fmt.allocPrint(allocator, "{{\"tag_name\":\"{s}\"}}", .{tag});
        }
    } else |_| {}

    return error.FetchFailed;
}

/// From `https://github.com/.../releases/tag/v1.2.9` → `1.2.9`.
pub fn tagFromReleaseUrl(url: []const u8) ?[]const u8 {
    const marker = "/releases/tag/";
    const idx = std.mem.indexOf(u8, url, marker) orelse return null;
    var tag = url[idx + marker.len ..];
    // trim trailing whitespace / CR
    tag = std.mem.trim(u8, tag, " \t\r\n");
    if (tag.len == 0) return null;
    return stripLeadingV(tag);
}

/// Probe on-PATH `ryk version --json` after install (owned; null on failure).
fn resolveOnPathVersion(allocator: std.mem.Allocator, io: std.Io) ?[]u8 {
    const out = runCapture(allocator, io, &.{ "ryk", "version", "--json" }) catch return null;
    defer allocator.free(out);
    // Minimal extract: "version": "X.Y.Z"
    const key = "\"version\"";
    const idx = std.mem.indexOf(u8, out, key) orelse return null;
    var i = idx + key.len;
    while (i < out.len and (out[i] == ' ' or out[i] == ':' or out[i] == '\t')) : (i += 1) {}
    if (i >= out.len or out[i] != '"') return null;
    i += 1;
    const start = i;
    while (i < out.len and out[i] != '"') : (i += 1) {}
    if (i <= start) return null;
    const raw = out[start..i];
    _ = parseSemver(raw) catch return null;
    return allocator.dupe(u8, stripLeadingV(raw)) catch null;
}

fn runCapture(allocator: std.mem.Allocator, io: std.Io, argv: []const []const u8) ![]u8 {
    const run_result = std.process.run(allocator, io, .{
        .argv = argv,
        .stdout_limit = .limited(512 * 1024),
        .stderr_limit = .limited(16 * 1024),
        .timeout = .{ .duration = .{
            .raw = .fromNanoseconds(15 * std.time.ns_per_s),
            .clock = .awake,
        } },
    }) catch return error.FetchFailed;
    // Free stderr always; free stdout only on failure. Do not combine errdefer +
    // manual free on the same buffer (double-free on non-zero/non-exited terms).
    defer allocator.free(run_result.stderr);
    switch (run_result.term) {
        .exited => |code| if (code != 0) {
            allocator.free(run_result.stdout);
            return error.FetchFailed;
        },
        else => {
            allocator.free(run_result.stdout);
            return error.FetchFailed;
        },
    }
    return run_result.stdout;
}

fn runOfficialInstaller(
    allocator: std.mem.Allocator,
    io: std.Io,
    target_version: []const u8,
    quiet_json: bool,
    stderr: anytype,
) !u8 {
    if (builtin.os.tag == .windows) {
        return runWindowsInstaller(allocator, io, target_version, quiet_json, stderr);
    }
    return runUnixInstaller(allocator, io, target_version, quiet_json, stderr);
}

fn tempRoot() []const u8 {
    if (builtin.os.tag == .windows) {
        if (std.c.getenv("TEMP")) |t| return std.mem.span(t);
        if (std.c.getenv("TMP")) |t| return std.mem.span(t);
        return ".";
    }
    if (std.c.getenv("TMPDIR")) |t| return std.mem.span(t);
    return "/tmp";
}

/// Stage installer bytes into an exclusive temp file via an open fd (no path TOCTOU write).
fn stageInstallerFile(
    allocator: std.mem.Allocator,
    io: std.Io,
    url: []const u8,
    extension: []const u8,
) ![]u8 {
    // Random suffix so the path is not time-guessable; exclusive create fails if
    // a pre-planted path already exists (including a symlink).
    var rand_bytes: [8]u8 = undefined;
    io.randomSecure(&rand_bytes) catch {
        const nonce = std.Io.Clock.Timestamp.now(io, .awake).raw.nanoseconds;
        @memcpy(rand_bytes[0..@min(8, @sizeOf(@TypeOf(nonce)))], std.mem.asBytes(&nonce)[0..@min(8, @sizeOf(@TypeOf(nonce)))]);
    };
    var suffix: [16]u8 = undefined;
    const encoded = std.fmt.bytesToHex(rand_bytes, .lower);
    @memcpy(suffix[0..16], encoded[0..16]);

    // Retry a few times if exclusive create loses a rare race.
    var attempt: u8 = 0;
    while (attempt < 5) : (attempt += 1) {
        const path = try std.fmt.allocPrint(allocator, "{s}/ryk-update-{s}{d}.{s}", .{
            tempRoot(),
            suffix[0..],
            attempt,
            extension,
        });
        errdefer allocator.free(path);

        const file = std.Io.Dir.cwd().createFile(io, path, .{ .exclusive = true }) catch {
            allocator.free(path);
            continue;
        };

        const body = downloadBytes(allocator, io, url) catch {
            file.close(io);
            std.Io.Dir.cwd().deleteFile(io, path) catch {};
            allocator.free(path);
            return error.InstallerDownloadFailed;
        };
        defer allocator.free(body);

        file.writeStreamingAll(io, body) catch {
            file.close(io);
            std.Io.Dir.cwd().deleteFile(io, path) catch {};
            allocator.free(path);
            return error.InstallerStageFailed;
        };
        file.close(io);
        return path;
    }
    return error.InstallerStageFailed;
}

fn downloadBytes(allocator: std.mem.Allocator, io: std.Io, url: []const u8) ![]u8 {
    if (runCapture(allocator, io, &.{ "curl", "-fsSL", "--max-time", "60", url })) |body| {
        return body;
    } else |_| {}

    var ua_value: [64]u8 = undefined;
    const ua = std.fmt.bufPrint(&ua_value, "ryk-update/{s}", .{build_options.version}) catch "ryk-update";
    return try runCapture(allocator, io, &.{
        "wget", "-qO-", "--timeout=60", "--user-agent", ua, url,
    });
}

fn runUnixInstaller(
    allocator: std.mem.Allocator,
    io: std.Io,
    target_version: []const u8,
    quiet_json: bool,
    stderr: anytype,
) !u8 {
    // Prefer tag-pinned installer so floating `main` cannot diverge from the release.
    const url = try installScriptUrlForVersion(allocator, target_version, false);
    defer allocator.free(url);
    const script_path = stageInstallerFile(allocator, io, url, "sh") catch |err| {
        if (!quiet_json) {
            try stderr.writeAll("ryk update: failed to download install.sh (need curl or wget).\n");
        }
        return err;
    };
    defer {
        std.Io.Dir.cwd().deleteFile(io, script_path) catch {};
        allocator.free(script_path);
    }

    return try execInstaller(allocator, io, &.{ "sh", script_path }, target_version, quiet_json, true);
}

/// Installer child must not inherit operator overrides that redirect download roots.
const scrub_env_keys = [_][]const u8{
    "RYK_BASE_URL",
    "RYK_BASE_URL",
    "ARTIFACT_DIR",
    "RYK_ARTIFACT_DIR",
    "RYK_ARTIFACT_DIR",
    "RYK_INSTALL_ROOT",
    "RYK_INSTALL_ROOT",
};

fn scrubInstallerEnv(env_map: *std.process.Environ.Map) void {
    for (scrub_env_keys) |key| {
        _ = env_map.swapRemove(key);
    }
}

fn execInstaller(
    allocator: std.mem.Allocator,
    io: std.Io,
    argv: []const []const u8,
    target_version: []const u8,
    quiet_json: bool,
    skip_onboard: bool,
) !u8 {
    var env_map = try env_util.createProcessMap(allocator);
    defer env_map.deinit();
    scrubInstallerEnv(&env_map);
    try env_map.put("RYK_VERSION", target_version);
    try env_map.put("RYK_VERSION", target_version);
    if (skip_onboard) {
        try env_map.put("RYK_INSTALL_SKIP_ONBOARD", "1");
        try env_map.put("RYK_INSTALL_SKIP_ONBOARD", "1");
    }
    if (quiet_json) {
        try env_map.put("RYK_INSTALL_QUIET", "1");
        try env_map.put("RYK_INSTALL_QUIET", "1");
    }

    const stdio: std.process.SpawnOptions.StdIo = if (quiet_json) .ignore else .inherit;
    var child = try std.process.spawn(io, .{
        .argv = argv,
        .environ_map = &env_map,
        .stdin = .ignore,
        .stdout = stdio,
        .stderr = stdio,
    });
    const term = try child.wait(io);
    return switch (term) {
        .exited => |code| @intCast(@min(code, 255)),
        else => 1,
    };
}

fn runWindowsInstaller(
    allocator: std.mem.Allocator,
    io: std.Io,
    target_version: []const u8,
    quiet_json: bool,
    stderr: anytype,
) !u8 {
    const url = try installScriptUrlForVersion(allocator, target_version, true);
    defer allocator.free(url);
    const script_path = stageInstallerFile(allocator, io, url, "ps1") catch |err| {
        if (!quiet_json) {
            try stderr.writeAll("ryk update: failed to download Windows installer.\n");
        }
        return err;
    };
    defer {
        std.Io.Dir.cwd().deleteFile(io, script_path) catch {};
        allocator.free(script_path);
    }

    return try execInstaller(
        allocator,
        io,
        &.{ "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script_path },
        target_version,
        quiet_json,
        false,
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "parseArgs accepts flags and version pin" {
    const a = try parseArgs(&.{ "--check", "--yes", "--force", "--json", "--version", "1.3.0" });
    try std.testing.expect(a.check_only);
    try std.testing.expect(a.yes);
    try std.testing.expect(a.force);
    try std.testing.expect(a.json);
    try std.testing.expectEqualStrings("1.3.0", a.version.?);

    const b = try parseArgs(&.{"--version=v2.0.0"});
    try std.testing.expectEqualStrings("2.0.0", b.version.?);

    try std.testing.expectError(error.HelpRequested, parseArgs(&.{"--help"}));
    try std.testing.expectError(error.UnknownOption, parseArgs(&.{"--verbse"}));
    try std.testing.expectError(error.MissingVersionValue, parseArgs(&.{"--version"}));
}

test "compareSemver orders versions" {
    const a = try parseSemver("1.2.9");
    const b = try parseSemver("v1.3.0");
    try std.testing.expectEqual(Order.older, compareSemver(a, b));
    try std.testing.expectEqual(Order.newer, compareSemver(b, a));
    try std.testing.expectEqual(Order.equal, compareSemver(a, try parseSemver("1.2.9")));
    // Prerelease is older than the final release with the same core version.
    try std.testing.expectEqual(Order.older, try compareVersionStrings("1.2.9-rc.1", "1.2.9"));
    try std.testing.expectEqual(Order.newer, try compareVersionStrings("1.2.9", "1.2.9-rc.1"));
    try std.testing.expectEqual(Order.equal, try compareVersionStrings("1.2.9-rc.1", "1.2.9-rc.1"));
    try std.testing.expectError(error.InvalidSemver, parseSemver("nope"));
}

test "installScriptUrlForVersion pins release tag" {
    const sh = try installScriptUrlForVersion(std.testing.allocator, "1.3.0", false);
    defer std.testing.allocator.free(sh);
    try std.testing.expectEqualStrings(
        "https://raw.githubusercontent.com/christopherkarani/ryk/v1.3.0/scripts/install.sh",
        sh,
    );
    const ps1 = try installScriptUrlForVersion(std.testing.allocator, "v2.0.0", true);
    defer std.testing.allocator.free(ps1);
    try std.testing.expectEqualStrings(
        "https://raw.githubusercontent.com/christopherkarani/ryk/v2.0.0/scripts/install.ps1",
        ps1,
    );
}

test "detectInstallChannel classifies known layouts" {
    try std.testing.expectEqual(InstallChannel.homebrew, detectInstallChannel("/opt/homebrew/Cellar/ryk/1.2.9/bin/ryk"));
    try std.testing.expectEqual(InstallChannel.homebrew, detectInstallChannel("/home/linuxbrew/.linuxbrew/Cellar/ryk/1.0.0/bin/ryk"));
    try std.testing.expectEqual(InstallChannel.npm, detectInstallChannel("/usr/local/lib/node_modules/@rykan/ryk/vendor/ryk"));
    try std.testing.expectEqual(InstallChannel.scoop, detectInstallChannel("C:\\Users\\me\\scoop\\apps\\ryk\\current\\ryk.exe"));
    try std.testing.expectEqual(InstallChannel.curl_installer, detectInstallChannel("/Users/me/.local/bin/ryk"));
    try std.testing.expectEqual(InstallChannel.unknown, detectInstallChannel("/Users/me/src/rykan/zig-out/bin/ryk"));
}

test "channelAllowsInstaller respects force" {
    try std.testing.expect(channelAllowsInstaller(.curl_installer, false));
    try std.testing.expect(channelAllowsInstaller(.unknown, false));
    try std.testing.expect(!channelAllowsInstaller(.homebrew, false));
    try std.testing.expect(channelAllowsInstaller(.homebrew, true));
    try std.testing.expect(!channelAllowsInstaller(.npm, false));
}

test "parseGitHubLatestTag extracts version" {
    const body =
        \\{"url":"https://api.github.com/repos/christopherkarani/ryk/releases/123","tag_name":"v1.2.9","name":"1.2.9"}
    ;
    try std.testing.expectEqualStrings("1.2.9", try parseGitHubLatestTag(body));
    try std.testing.expectEqualStrings("2.0.0", try parseGitHubLatestTag("{\"tag_name\": \"2.0.0\"}"));
    try std.testing.expectError(error.MissingTagName, parseGitHubLatestTag("{}"));
}

test "shouldProceedWithInstall upgrade downgrade rules" {
    try std.testing.expect(shouldProceedWithInstall(.older, false, false));
    try std.testing.expect(!shouldProceedWithInstall(.equal, false, false));
    try std.testing.expect(!shouldProceedWithInstall(.newer, false, true));
    try std.testing.expect(shouldProceedWithInstall(.newer, true, true));
    try std.testing.expect(!shouldProceedWithInstall(.newer, true, false));
}

test "packageManagerHint is non-empty" {
    try std.testing.expect(packageManagerHint(.homebrew).len > 0);
    try std.testing.expectEqualStrings(supported_install_command, packageManagerHint(.homebrew));
    try std.testing.expectEqualStrings(supported_install_command, packageManagerHint(.npm));
    try std.testing.expectEqualStrings(supported_install_command, packageManagerHint(.scoop));
    try std.testing.expectEqualStrings(supported_install_command, packageManagerHint(.winget));
}

test "tagFromReleaseUrl strips path prefix and v" {
    try std.testing.expectEqualStrings(
        "1.2.9",
        tagFromReleaseUrl("https://github.com/christopherkarani/ryk/releases/tag/v1.2.9").?,
    );
    try std.testing.expectEqualStrings(
        "2.0.0",
        tagFromReleaseUrl("https://github.com/christopherkarani/ryk/releases/tag/2.0.0\n").?,
    );
    try std.testing.expect(tagFromReleaseUrl("https://github.com/christopherkarani/ryk/releases") == null);
}

test "writeJsonResult escapes hostile target strings" {
    var buf: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try writeJsonResult(&writer, .{
        .status = "error",
        .current = "1.0.0",
        .target = "1.0.0\",\"pwned\":\"",
        .channel = "unknown",
        .action = "none",
        .message = "line1\nline2",
    });
    const out = writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "\"pwned\"") == null or std.mem.indexOf(u8, out, "\\\"pwned\\\"") != null);
    // Escaped quote sequence must appear; raw field-break must not parse as extra key.
    try std.testing.expect(std.mem.indexOf(u8, out, "\\\"pwned\\\"") != null or std.mem.indexOf(u8, out, "\\\",\\\"pwned\\\":\\\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\\n") != null);
}

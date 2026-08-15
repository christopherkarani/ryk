const std = @import("std");
const gpa_mod = @import("gpa.zig");

const policy_mod = @import("ryk_core").policy;
const core = @import("ryk_core").core;
const exit_codes = @import("exit_codes.zig");
const help = @import("help.zig");
const style = @import("style.zig");
const suggestions = @import("suggestions.zig");
const pack_state = @import("pack_state.zig");

const InitOptions = struct {
    mode: ?[]const u8 = null,
    preset: policy_mod.presets.AgentPreset = .generic_agent,
    force: bool = false,
    quiet: bool = false,
};

pub fn command(io: std.Io, cwd: std.Io.Dir, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    const options = parseOptions(io, argv, stdout, stderr) catch |err| switch (err) {
        error.HelpShown => return exit_codes.success,
        error.Usage => return exit_codes.usage,
        else => return err,
    };

    cwd.createDirPath(io, ".ryk") catch |err| {
        try stderr.print("ryk init: failed to create .ryk: {s}\n", .{@errorName(err)});
        return exit_codes.general;
    };

    const flags: std.Io.Dir.CreateFileOptions = if (options.force) .{} else .{ .exclusive = true };
    const file = cwd.createFile(io, ".ryk/policy.yaml", flags) catch |err| switch (err) {
        error.PathAlreadyExists => {
            try stderr.writeAll("ryk init: .ryk/policy.yaml already exists; use --force to overwrite.\n");
            return exit_codes.general;
        },
        else => {
            try stderr.print("ryk init: failed to write .ryk/policy.yaml: {s}\n", .{@errorName(err)});
            return exit_codes.general;
        },
    };
    defer file.close(io);

    const preset_text = policy_mod.presets.agentPresetText(options.preset);
    try writePolicy(io, file, preset_text, options.mode);
    const info = policy_mod.presets.agentPresetInfo(options.preset);

    // Additive pack enablement for the daemon evaluator (project `.ryk.toml` when in a git
    // repo, else user config). Zig still owns policy.yaml; packs config is additive.
    var gpa_state: gpa_mod.State = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();

    // Resolve workspace from the init cwd (avoid importing onboarding — circular with init).
    const cwd_path = try cwd.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(cwd_path);
    const workspace_root = core.supervisor.resolveWorkspaceRoot(io, allocator, null, cwd_path) catch try allocator.dupe(u8, cwd_path);
    defer allocator.free(workspace_root);

    var packs_result = pack_state.ensurePresetPacks(io, allocator, workspace_root, options.preset) catch pack_state.EnsurePacksResult{
        .message = "Packs: baseline only (pack config write skipped)",
        .owned = false,
    };
    defer packs_result.deinit(allocator);

    if (!options.quiet) {
        // Warm success message: format into a buffer so it can route through
        // maybeColor, matching the style of setup.zig and run.zig warm paths.
        try stdout.writeAll("\n");
        var msg_buf: [256]u8 = undefined;
        const msg = std.fmt.bufPrint(&msg_buf, "{s} Created .ryk/policy.yaml from preset '{s}'.\n", .{ style.Glyph.check, info.name }) catch null;
        if (msg) |m| {
            try style.maybeColor(io, stdout, style.Style.green, m);
        } else {
            // Buffer too small (should never happen): fall back to manual gating.
            if (style.useColor(io, stdout)) {
                try stdout.writeAll(style.Style.green);
                try stdout.print("{s} Created .ryk/policy.yaml from preset '{s}'.\n", .{ style.Glyph.check, info.name });
                try stdout.writeAll(style.Style.reset);
            } else {
                try stdout.print("{s} Created .ryk/policy.yaml from preset '{s}'.\n", .{ style.Glyph.check, info.name });
            }
        }
        try stdout.print("{s}\n", .{packs_result.message});
        if (packs_result.config_path) |path| {
            try stdout.print("  Pack config ({s}): {s}\n", .{ packs_result.scope.?.label(), path });
        }
        if (info.experimental) try stdout.print("Warning: {s}\n", .{info.warning});
        try stdout.writeAll("\n" ++
            "Your policy is ready.\n" ++
            "\n" ++
            "Next steps:\n" ++
            "  ryk policy check .ryk/policy.yaml\n" ++
            "  ryk doctor\n" ++
            "  ryk run -- <command>\n" ++
            "\n");
    }

    // AINA P3 S5: soft-refresh managed discovery for known adapters (pi/opencode).
    // Never fails init; never touches policy.yaml (DIS-1 / DIS-7).
    // Prefer process Environ.Map over libc getenv (Zig 0.16 product path).
    softRefreshInitDiscovery(io, allocator, workspace_root, options.quiet, stderr) catch {};

    return exit_codes.success;
}

// ---------------------------------------------------------------------------
// AINA P3 S5 — managed discovery refresh lives in policy.network_discovered
// (CLI init/start are thin callers — no layering inversion).
// ---------------------------------------------------------------------------

/// Re-export for tests and start.zig composition (product API is network_discovered).
pub const refreshManagedDiscovery = policy_mod.network_discovered.refreshManagedDiscovery;

fn softRefreshInitDiscovery(
    io: std.Io,
    allocator: std.mem.Allocator,
    workspace_root: []const u8,
    quiet: bool,
    stderr: anytype,
) !void {
    const env_util = @import("../env_util.zig");
    var env_map = try env_util.createProcessMap(allocator);
    defer env_map.deinit();
    const home = (try env_util.getOwned(&env_map, allocator, "HOME")) orelse return;
    defer allocator.free(home);
    if (home.len == 0) return;

    refreshManagedDiscovery(io, allocator, workspace_root, home, &.{ "pi", "opencode" }) catch |err| {
        if (!quiet) {
            stderr.print(
                "ryk init: discovery refresh soft-skipped ({s})\n",
                .{@errorName(err)},
            ) catch {};
        }
    };
}

fn parseOptions(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !InitOptions {
    var options: InitOptions = .{};
    var index: usize = 0;
    while (index < argv.len) : (index += 1) {
        const arg = argv[index];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            _ = try help.writeCommand(io, stdout, "init");
            return error.HelpShown;
        } else if (std.mem.eql(u8, arg, "--force")) {
            options.force = true;
        } else if (std.mem.eql(u8, arg, "--ci")) {
            options.mode = "ci";
        } else if (std.mem.eql(u8, arg, "--quiet")) {
            options.quiet = true;
        } else if (std.mem.eql(u8, arg, "--preset")) {
            index += 1;
            if (index >= argv.len) {
                try stderr.writeAll("ryk init: --preset requires a preset name.\n");
                return error.Usage;
            }
            const preset = policy_mod.presets.AgentPreset.parse(argv[index]) orelse {
                try suggestions.writeInvalidValue(stderr, "ryk init", "--preset", argv[index], &.{ "generic-agent", "claude-code", "codex", "cursor-agent", "opencode", "cline-roo", "mcp-dev", "github-actions", "solo-dev", "strict-local", "team-ci", "openclaw-hermes", "unattended", "trusted-local" }, "init");
                return error.Usage;
            };
            options.preset = preset;
        } else if (std.mem.eql(u8, arg, "--mode")) {
            index += 1;
            if (index >= argv.len) {
                try stderr.writeAll("ryk init: --mode requires strict, ask, observe, ci, or trusted.\n");
                return error.Usage;
            }
            const mode = argv[index];
            if (!isValidMode(mode)) {
                try suggestions.writeInvalidValue(stderr, "ryk init", "--mode", mode, &.{ "strict", "ask", "observe", "ci", "trusted" }, "init");
                return error.Usage;
            }
            options.mode = mode;
        } else {
            try suggestions.writeUnknownOption(stderr, "ryk init", arg, &.{ "--force", "--ci", "--quiet", "--preset", "--mode", "--help", "-h" }, "init");
            return error.Usage;
        }
    }
    return options;
}

fn isValidMode(mode: []const u8) bool {
    return std.mem.eql(u8, mode, "strict") or
        std.mem.eql(u8, mode, "ask") or
        std.mem.eql(u8, mode, "observe") or
        std.mem.eql(u8, mode, "ci") or
        std.mem.eql(u8, mode, "trusted");
}

fn writePolicy(io: std.Io, file: std.Io.File, preset_text: []const u8, mode_override: ?[]const u8) !void {
    var buffer: [1024]u8 = undefined;
    var writer = file.writer(io, &buffer);
    if (mode_override) |mode| {
        var lines = std.mem.splitScalar(u8, preset_text, '\n');
        while (lines.next()) |line| {
            // Only the unindented top-level `mode:` key. Nested keys under
            // files.write / network stay as written in the preset.
            if (std.mem.startsWith(u8, line, "mode:")) {
                try writer.interface.print("mode: {s}\n", .{mode});
            } else {
                try writer.interface.writeAll(line);
                try writer.interface.writeByte('\n');
            }
        }
        try writer.interface.flush();
        return;
    }
    try writer.interface.writeAll(preset_text);
    try writer.interface.flush();
}

test "init creates policy and refuses overwrite without force" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var stdout_buf: [512]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, tmp.dir, &.{ "--mode", "strict" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);

    const policy = try tmp.dir.readFileAlloc(std.testing.io, ".ryk/policy.yaml", std.testing.allocator, .limited(16 * 1024));
    defer std.testing.allocator.free(policy);
    try std.testing.expect(std.mem.indexOf(u8, policy, "version: 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, policy, "mode: strict") != null);

    stdout_writer = .fixed(&stdout_buf);
    stderr_writer = .fixed(&stderr_buf);
    const second_code = try command(std.testing.io, tmp.dir, &.{}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.general, second_code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "already exists") != null);
}

test "init force overwrites existing policy" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(std.testing.io, ".ryk");
    {
        const existing = try tmp.dir.createFile(std.testing.io, ".ryk/policy.yaml", .{});
        defer existing.close(std.testing.io);
        try existing.writeStreamingAll(std.testing.io, "old\n");
    }

    var stdout_buf: [512]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, tmp.dir, &.{ "--mode", "observe", "--force" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());

    const policy = try tmp.dir.readFileAlloc(std.testing.io, ".ryk/policy.yaml", std.testing.allocator, .limited(16 * 1024));
    defer std.testing.allocator.free(policy);
    try std.testing.expect(std.mem.indexOf(u8, policy, "mode: observe") != null);
}

test "init accepts generic-agent preset alias" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var stdout_buf: [512]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, tmp.dir, &.{ "--preset", "generic-agent", "--force" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "generic-agent") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "Packs: baseline only") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());

    const policy = try tmp.dir.readFileAlloc(std.testing.io, ".ryk/policy.yaml", std.testing.allocator, .limited(16 * 1024));
    defer std.testing.allocator.free(policy);
    try std.testing.expect(std.mem.indexOf(u8, policy, "version: 1") != null);
}

test "init team-ci enables opt-in packs in project .ryk.toml" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, ".git");

    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, tmp.dir, &.{ "--preset", "team-ci", "--force" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    const out = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "Enabled packs:") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "containers.docker") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());

    const policy = try tmp.dir.readFileAlloc(std.testing.io, ".ryk/policy.yaml", std.testing.allocator, .limited(16 * 1024));
    defer std.testing.allocator.free(policy);
    try std.testing.expect(std.mem.indexOf(u8, policy, "version: 1") != null);

    const packs_cfg = try tmp.dir.readFileAlloc(std.testing.io, ".ryk.toml", std.testing.allocator, .limited(8192));
    defer std.testing.allocator.free(packs_cfg);
    try std.testing.expect(std.mem.indexOf(u8, packs_cfg, "containers.docker") != null);
    try std.testing.expect(std.mem.indexOf(u8, packs_cfg, "kubernetes.kubectl") != null);
    try std.testing.expect(std.mem.indexOf(u8, packs_cfg, "infrastructure.terraform") != null);

    // Idempotent re-run with force for policy only still merges packs without wiping.
    stdout_writer = .fixed(&stdout_buf);
    stderr_writer = .fixed(&stderr_buf);
    const second = try command(std.testing.io, tmp.dir, &.{ "--preset", "team-ci", "--force" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, second);
    const packs_cfg2 = try tmp.dir.readFileAlloc(std.testing.io, ".ryk.toml", std.testing.allocator, .limited(8192));
    defer std.testing.allocator.free(packs_cfg2);
    try std.testing.expect(std.mem.indexOf(u8, packs_cfg2, "containers.docker") != null);
}

test "init writes requested phase 18 presets as valid policies" {
    const sample_presets = [_][]const u8{ "generic-agent", "github-actions", "strict-local", "trusted-local" };
    for (sample_presets) |preset_name| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();

        var stdout_buf: [2048]u8 = undefined;
        var stderr_buf: [512]u8 = undefined;
        var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
        var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

        const code = try command(std.testing.io, tmp.dir, &.{ "--preset", preset_name, "--force" }, &stdout_writer, &stderr_writer);
        try std.testing.expectEqual(exit_codes.success, code);
        try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "Next steps:") != null);
        // Warm success path (checkmark + "Your policy is ready")
        try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), style.Glyph.check ++ " Created") != null);
        try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "Your policy is ready") != null);
        try std.testing.expectEqualStrings("", stderr_writer.buffered());

        const policy = try tmp.dir.readFileAlloc(std.testing.io, ".ryk/policy.yaml", std.testing.allocator, .limited(16 * 1024));
        defer std.testing.allocator.free(policy);
        var loaded = try policy_mod.load.parseFromSlice(std.testing.allocator, policy, ".ryk/policy.yaml");
        defer loaded.deinit();
        try policy_mod.validate.policy(&loaded);
    }
}

test "init --mode overrides only top-level policy mode and writes parseable YAML" {
    const modes = [_][]const u8{ "ask", "strict", "observe", "ci", "trusted" };
    for (modes) |mode| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();

        var stdout_buf: [512]u8 = undefined;
        var stderr_buf: [512]u8 = undefined;
        var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
        var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

        const code = try command(std.testing.io, tmp.dir, &.{ "--mode", mode, "--quiet" }, &stdout_writer, &stderr_writer);
        try std.testing.expectEqual(exit_codes.success, code);
        try std.testing.expectEqualStrings("", stdout_writer.buffered());
        try std.testing.expectEqualStrings("", stderr_writer.buffered());

        const policy = try tmp.dir.readFileAlloc(std.testing.io, ".ryk/policy.yaml", std.testing.allocator, .limited(16 * 1024));
        defer std.testing.allocator.free(policy);

        // Schema/load parse — substring search would pass on broken YAML with extra
        // unindented `mode:` keys rewritten from files.write / network.
        var loaded = try policy_mod.load.parseFromSlice(std.testing.allocator, policy, ".ryk/policy.yaml");
        defer loaded.deinit();
        try policy_mod.validate.policy(&loaded);
        try std.testing.expectEqual(policy_mod.schema.Mode.parse(mode).?, loaded.mode);
        try std.testing.expectEqual(policy_mod.schema.WriteMode.staged, loaded.files.write_mode);
        try std.testing.expectEqual(policy_mod.schema.NetworkMode.allowlist, loaded.network.mode.?);
    }
}

test "init without --mode writes default preset unchanged" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var stdout_buf: [512]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, tmp.dir, &.{ "--quiet" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);

    const policy = try tmp.dir.readFileAlloc(std.testing.io, ".ryk/policy.yaml", std.testing.allocator, .limited(16 * 1024));
    defer std.testing.allocator.free(policy);
    try std.testing.expectEqualStrings(policy_mod.presets.agentPresetText(.generic_agent), policy);

    var loaded = try policy_mod.load.parseFromSlice(std.testing.allocator, policy, ".ryk/policy.yaml");
    defer loaded.deinit();
    try policy_mod.validate.policy(&loaded);
    try std.testing.expectEqual(policy_mod.schema.Mode.strict, loaded.mode);
    try std.testing.expectEqual(policy_mod.schema.WriteMode.staged, loaded.files.write_mode);
    try std.testing.expectEqual(policy_mod.schema.NetworkMode.allowlist, loaded.network.mode.?);
}

test "init rejects invalid preset names clearly" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var stdout_buf: [512]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, tmp.dir, &.{ "--preset", "not-real" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "invalid --preset value 'not-real'") != null);
}

// ---------------------------------------------------------------------------
// AINA P3 S5 — init path discovery refresh (DIS-1 / DIS-7)
// Plan §3.6: `ryk init` runs adapters for detected hosts and refreshes managed file.
//
// Expected production API (implementer lands in init.zig; may share body with
// start.zig via `@import("init.zig")` from start — do NOT import start from init):
//
//   pub fn refreshManagedDiscovery(
//       io: std.Io,
//       allocator: std.mem.Allocator,
//       workspace_root: []const u8,
//       home: []const u8,
//       host_keys: []const []const u8,
//   ) !void
//
// Product wire: after policy write, call refresh for known adapter keys
// (pi/opencode minimum) using parent HOME + abs workspace_root. Soft-skip when
// no auth configs. Never wipe user policy allows on rediscovery.
// ---------------------------------------------------------------------------

const p3_init_pi_auth_json =
    \\{
    \\  "openrouter": {
    \\    "type": "api_key",
    \\    "key": "sk-fixture-init-pi-openrouter-NOT-REAL-i1"
    \\  },
    \\  "xai-oauth": {
    \\    "type": "oauth",
    \\    "access": "fixture-init-pi-xai-access-NOT-REAL-i2",
    \\    "refresh": "fixture-init-pi-xai-refresh-NOT-REAL-i3",
    \\    "tokenEndpoint": "https://auth.x.ai/oauth2/token",
    \\    "baseUrl": "https://api.x.ai/v1"
    \\  }
    \\}
;

const p3_init_pi_settings_json =
    \\{
    \\  "defaultProvider": "openrouter"
    \\}
;

const p3_init_opencode_auth_json =
    \\{
    \\  "xai": {
    \\    "type": "oauth",
    \\    "access": "fixture-init-oc-xai-access-NOT-REAL-i4",
    \\    "refresh": "fixture-init-oc-xai-refresh-NOT-REAL-i5"
    \\  }
    \\}
;

const p3_init_fixture_secret_needles = [_][]const u8{
    "sk-fixture-init-pi-openrouter-NOT-REAL-i1",
    "fixture-init-pi-xai-access-NOT-REAL-i2",
    "fixture-init-pi-xai-refresh-NOT-REAL-i3",
    "fixture-init-oc-xai-access-NOT-REAL-i4",
    "fixture-init-oc-xai-refresh-NOT-REAL-i5",
    "sk-fixture",
    "NOT-REAL",
};

fn p3InitAbsPath(tmp: anytype) ![]u8 {
    const z = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(z);
    return try std.testing.allocator.dupe(u8, z);
}

fn p3InitWriteRel(dir: anytype, rel: []const u8, content: []const u8) !void {
    if (std.fs.path.dirname(rel)) |parent| {
        if (parent.len > 0) try dir.createDirPath(std.testing.io, parent);
    }
    const file = try dir.createFile(std.testing.io, rel, .{});
    defer file.close(std.testing.io);
    try file.writeStreamingAll(std.testing.io, content);
}

fn p3InitPlantPiHome(home_dir: anytype) !void {
    try p3InitWriteRel(home_dir, ".pi/agent/auth.json", p3_init_pi_auth_json);
    try p3InitWriteRel(home_dir, ".pi/agent/settings.json", p3_init_pi_settings_json);
}

fn p3InitPlantOpencodeHome(home_dir: anytype) !void {
    try p3InitWriteRel(home_dir, ".local/share/opencode/auth.json", p3_init_opencode_auth_json);
}

fn p3InitStoreContainsHost(store: policy_mod.network_discovered.ManagedStore, needle: []const u8) bool {
    for (store.hosts) |entry| {
        if (std.mem.eql(u8, entry.host, needle)) return true;
    }
    return false;
}

fn p3InitAssertNoSecretsInBytes(bytes: []const u8) !void {
    for (p3_init_fixture_secret_needles) |needle| {
        try std.testing.expect(std.mem.indexOf(u8, bytes, needle) == null);
    }
    try std.testing.expect(std.mem.indexOf(u8, bytes, "://") == null);
}

test "init refreshManagedDiscovery pi/opencode writes managed yaml hostnames+sources only" {
    // Acceptance: Synthetic HOME+tmp workspace refresh for pi/opencode writes
    // <workspace>/.ryk/network-discovered.yaml with hostnames+sources only.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    const workspace_root = try p3InitAbsPath(&ws_tmp);
    defer allocator.free(workspace_root);

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    try p3InitPlantPiHome(home_tmp.dir);
    try p3InitPlantOpencodeHome(home_tmp.dir);
    const home = try p3InitAbsPath(&home_tmp);
    defer allocator.free(home);

    try refreshManagedDiscovery(io, allocator, workspace_root, home, &.{ "pi", "opencode" });

    var store = try policy_mod.network_discovered.loadManaged(io, allocator, workspace_root);
    defer store.deinit(allocator);

    try std.testing.expect(p3InitStoreContainsHost(store, "auth.x.ai"));
    try std.testing.expect(p3InitStoreContainsHost(store, "api.x.ai"));
    try std.testing.expect(store.hosts.len > 0);
    for (store.hosts) |entry| {
        try std.testing.expect(entry.sources.len > 0);
        try std.testing.expect(std.mem.indexOf(u8, entry.host, "://") == null);
    }

    const path = try policy_mod.network_discovered.managedPath(allocator, workspace_root);
    defer allocator.free(path);
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(64 * 1024));
    defer allocator.free(bytes);
    try p3InitAssertNoSecretsInBytes(bytes);
    try std.testing.expect(std.mem.indexOf(u8, bytes, "sources:") != null);
}

test "init refreshManagedDiscovery rediscovery leaves policy.yaml user allows untouched" {
    // Acceptance: Rediscovery replaces managed only; policy.yaml user allows untouched (DIS-7).
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    const workspace_root = try p3InitAbsPath(&ws_tmp);
    defer allocator.free(workspace_root);

    // Create policy via init first.
    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const init_code = try command(io, ws_tmp.dir, &.{ "--mode", "ask", "--force", "--quiet" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, init_code);

    // Append a user allow to policy.yaml (user-authored).
    const user_policy =
        \\version: 1
        \\mode: ask
        \\network:
        \\  allow:
        \\    - user-init-preserve.example
        \\    - registry.npmjs.org
        \\
    ;
    {
        const f = try ws_tmp.dir.createFile(io, ".ryk/policy.yaml", .{});
        defer f.close(io);
        try f.writeStreamingAll(io, user_policy);
    }
    const policy_before = try ws_tmp.dir.readFileAlloc(io, ".ryk/policy.yaml", allocator, .limited(4096));
    defer allocator.free(policy_before);

    try policy_mod.network_discovered.writeManaged(io, allocator, workspace_root, &.{
        .{ .host = "stale-init-managed.invalid", .sources = &.{"fixture:stale"} },
    });

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    try p3InitPlantPiHome(home_tmp.dir);
    const home = try p3InitAbsPath(&home_tmp);
    defer allocator.free(home);

    try refreshManagedDiscovery(io, allocator, workspace_root, home, &.{"pi"});
    try refreshManagedDiscovery(io, allocator, workspace_root, home, &.{"pi"});

    var store = try policy_mod.network_discovered.loadManaged(io, allocator, workspace_root);
    defer store.deinit(allocator);
    try std.testing.expect(p3InitStoreContainsHost(store, "auth.x.ai"));
    try std.testing.expect(!p3InitStoreContainsHost(store, "stale-init-managed.invalid"));

    const policy_after = try ws_tmp.dir.readFileAlloc(io, ".ryk/policy.yaml", allocator, .limited(4096));
    defer allocator.free(policy_after);
    try std.testing.expectEqualStrings(policy_before, policy_after);
    try std.testing.expect(std.mem.indexOf(u8, policy_after, "user-init-preserve.example") != null);
}

test "init refreshManagedDiscovery nested-cwd lands at workspace-root .ryk" {
    // Composition: nested-cwd refresh → managed at workspace-root (not under nested).
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    try ws_tmp.dir.createDirPath(io, "nested/cwd");
    const workspace_root = try p3InitAbsPath(&ws_tmp);
    defer allocator.free(workspace_root);

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    try p3InitPlantOpencodeHome(home_tmp.dir);
    const home = try p3InitAbsPath(&home_tmp);
    defer allocator.free(home);

    const nested_abs = try ws_tmp.dir.realPathFileAlloc(io, "nested/cwd", allocator);
    defer allocator.free(nested_abs);
    const original_cwd = try std.Io.Dir.cwd().realPathFileAlloc(io, ".", allocator);
    defer allocator.free(original_cwd);
    try std.Io.Threaded.chdir(nested_abs);
    defer std.Io.Threaded.chdir(original_cwd) catch {};

    try refreshManagedDiscovery(io, allocator, workspace_root, home, &.{"opencode"});

    var store = try policy_mod.network_discovered.loadManaged(io, allocator, workspace_root);
    defer store.deinit(allocator);
    try std.testing.expect(p3InitStoreContainsHost(store, "api.x.ai"));
    try std.testing.expect(p3InitStoreContainsHost(store, "auth.x.ai"));

    if (ws_tmp.dir.access(io, "nested/cwd/.ryk/network-discovered.yaml", .{})) |_| {
        try std.testing.expect(false);
    } else |_| {}
}

test "init command succeeds and refresh soft-succeeds when no hosts detected" {
    // Acceptance: ryk init succeeds; refresh soft-succeeds with no hosts detected.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();

    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const code = try command(io, ws_tmp.dir, &.{ "--mode", "observe", "--force", "--quiet" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);

    const workspace_root = try p3InitAbsPath(&ws_tmp);
    defer allocator.free(workspace_root);

    // Soft paths: empty keys, empty home, empty auth home.
    try refreshManagedDiscovery(io, allocator, workspace_root, "", &.{});
    try refreshManagedDiscovery(io, allocator, workspace_root, "", &.{"pi"});
    var empty_home = std.testing.tmpDir(.{});
    defer empty_home.cleanup();
    const home = try p3InitAbsPath(&empty_home);
    defer allocator.free(home);
    try refreshManagedDiscovery(io, allocator, workspace_root, home, &.{ "pi", "opencode" });

    // Policy created by init must still exist and be readable.
    const policy = try ws_tmp.dir.readFileAlloc(io, ".ryk/policy.yaml", allocator, .limited(16 * 1024));
    defer allocator.free(policy);
    try std.testing.expect(std.mem.indexOf(u8, policy, "mode: observe") != null);
}

test "init force still succeeds after refreshManagedDiscovery with fixtures" {
    // LIVE/composition: init + refresh with fixtures present → managed hosts + policy OK.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    const workspace_root = try p3InitAbsPath(&ws_tmp);
    defer allocator.free(workspace_root);

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    try p3InitPlantPiHome(home_tmp.dir);
    try p3InitPlantOpencodeHome(home_tmp.dir);
    const home = try p3InitAbsPath(&home_tmp);
    defer allocator.free(home);

    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const code = try command(io, ws_tmp.dir, &.{ "--mode", "ask", "--force", "--quiet" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);

    try refreshManagedDiscovery(io, allocator, workspace_root, home, &.{ "pi", "opencode" });

    var store = try policy_mod.network_discovered.loadManaged(io, allocator, workspace_root);
    defer store.deinit(allocator);
    try std.testing.expect(p3InitStoreContainsHost(store, "auth.x.ai"));
    try std.testing.expect(p3InitStoreContainsHost(store, "api.x.ai"));

    const policy = try ws_tmp.dir.readFileAlloc(io, ".ryk/policy.yaml", allocator, .limited(16 * 1024));
    defer allocator.free(policy);
    try std.testing.expect(std.mem.indexOf(u8, policy, "mode: ask") != null);
    // Managed secrets must not leak into policy.
    for (p3_init_fixture_secret_needles) |needle| {
        try std.testing.expect(std.mem.indexOf(u8, policy, needle) == null);
    }
}

//! Host-integration setup library used by onboarding flows.
//! Public CLI door is `ryk start` — top-level `ryk setup` is hard-removed from the dispatcher.

const std = @import("std");
const gpa_mod = @import("gpa.zig");

const exit_codes = @import("exit_codes.zig");
const help = @import("help.zig");
const style = @import("style.zig");
const plugin = @import("plugin.zig");
const onboarding = @import("onboarding.zig");
const ensure = @import("ensure.zig");
const pack_state = @import("pack_state.zig");
const spinner_pkg = @import("spinner.zig");
const build_options = @import("build_options");
const tui = @import("../tui/mod.zig");

/// Library entry for host wiring (policy ensure + plugin install + smoke).
/// Prefer `ryk start` for the public product path.
pub fn command(io: std.Io, cwd: std.Io.Dir, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    if (argv.len == 0) {
        if (onboarding.interactiveSetupDesired(io)) {
            return runGuidedSetup(io, cwd, onboarding.default_preset, stdout, stderr, null, .{});
        }
        _ = try help.writeCommand(io, stdout, "setup");
        return exit_codes.success;
    }

    for (argv) |arg| {
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            _ = try help.writeCommand(io, stdout, "setup");
            return exit_codes.success;
        }
    }

    const embedded = hasEmbeddedFlag(argv);
    const flags = parseSetupFlags(argv, stderr) catch |err| switch (err) {
        error.Usage => return exit_codes.usage,
        else => return err,
    };

    if (!flags.auto) {
        if (onboarding.interactiveSetupDesired(io)) {
            return runGuidedSetup(io, cwd, flags.preset, stdout, stderr, null, .{ .embedded = embedded });
        }
        _ = try help.writeCommand(io, stdout, "setup");
        return exit_codes.success;
    }

    return runAutoSetup(io, cwd, flags.preset, stdout, stderr, .{ .embedded = embedded });
}

fn hasEmbeddedFlag(argv: []const []const u8) bool {
    for (argv) |arg| {
        if (std.mem.eql(u8, arg, "--embedded")) return true;
    }
    return false;
}

fn parseSetupFlags(argv: []const []const u8, stderr: anytype) !onboarding.Flags {
    var filtered: [32][]const u8 = undefined;
    var count: usize = 0;
    for (argv) |arg| {
        if (std.mem.eql(u8, arg, "--embedded")) continue;
        if (count >= filtered.len) return error.Usage;
        filtered[count] = arg;
        count += 1;
    }
    return onboarding.parseFlags(filtered[0..count], stderr, "ryk setup", true);
}

const SetupRenderOpts = struct {
    embedded: bool = false,
};

fn runAutoSetup(io: std.Io, cwd: std.Io.Dir, preset: []const u8, stdout: anytype, stderr: anytype, render: SetupRenderOpts) !u8 {
    var gpa_state: gpa_mod.State = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();

    const self_exe = try std.process.executablePathAlloc(io, allocator);
    defer allocator.free(self_exe);

    if (!render.embedded) {
        try tui.render.banner(io, stdout, build_options.version, "setup");
    }

    const workspace_root = try onboarding.resolveWorkspaceRootFromCwd(io, allocator, cwd);
    defer allocator.free(workspace_root);

    // Shared ensure door (no parallel ensurePolicy create path). Policy-only: host wire is start/doctor.
    if (onboarding.policyExists(io, workspace_root)) {
        try stdout.writeAll("Policy already exists.\n");
    } else {
        try stdout.writeAll("Policy not found. Initializing...\n");
    }
    var ensure_outcome = try ensure.runEnsure(io, allocator, cwd, .{
        .preset = preset,
        .skip_host_wire = true,
        .workspace_root_override = workspace_root,
    }, stdout, stderr);
    defer ensure_outcome.deinit(allocator);
    const policy_code = ensure.processExitForOutcome(ensure_outcome);
    if (policy_code != exit_codes.success) return policy_code;

    // Additive pack enablement (idempotent). Init may have already written packs when policy
    // was created; re-run merges without wiping user customizations.
    var packs_result = pack_state.ensurePresetPacksByName(io, allocator, workspace_root, preset) catch pack_state.EnsurePacksResult{
        .message = "Packs: baseline only (pack config write skipped)",
        .owned = false,
    };
    defer packs_result.deinit(allocator);
    try stdout.print("{s}\n", .{packs_result.message});
    if (packs_result.config_path) |path| {
        try stdout.print("  Pack config ({s}): {s}\n", .{ packs_result.scope.?.label(), path });
    }

    var doctor_report = try plugin.collectPluginDoctorReport(io, allocator);
    defer plugin.deinitPluginDoctorReport(&doctor_report, allocator);

    var any_detected = false;
    var failure_count: usize = 0;
    var degraded_count: usize = 0;

    for (onboarding.supported_hosts) |host_name| {
        if (!plugin.binaryInPath(io, allocator, host_name)) continue;
        any_detected = true;
        try stdout.print("\nDetected host: {s}\n", .{host_name});

        const installed = plugin.hostPluginInstalledFromReport(host_name, doctor_report);

        if (installed) {
            try stdout.print("  ✓ {s}: already installed\n", .{host_name});
        } else {
            try stdout.print("  → {s}: Installing...", .{host_name});
            try flushIfSupported(stdout);

            var spinner = spinner_pkg.Spinner(@TypeOf(stdout)){
                .label = host_name,
                .io = io,
                .stdout = stdout,
            };
            try spinner.start();

            const install_argv = &[_][]const u8{ self_exe, "plugin", "install", host_name, "--yes" };
            const install_code = runChild(io, install_argv);
            if (install_code) |code| {
                const outcome = plugin.verifyHostInstallAfterChild(io, allocator, host_name, code);
                if (outcome == .failed) {
                    try spinner.stop(false);
                    try stdout.print(" verification failed (installer exit {d})\n", .{code});
                    failure_count += 1;
                    continue;
                }
                try spinner.stop(true);
                if (outcome == .installed_after_child_failure)
                    try stdout.print(" verified (installer exited {d})\n", .{code})
                else
                    try stdout.writeAll(" verified\n");
            } else |err| {
                try spinner.stop(false);
                try stdout.print(" ({s})\n", .{@errorName(err)});
                failure_count += 1;
                continue;
            }
        }

        {
            const host_status = @import("host_status.zig");
            const smoke = host_status.runHostSmokePair(allocator, host_name) catch host_status.HostSmokePair{ .allow = .fail, .deny = .fail };
            const readiness = host_status.classifyReadiness(smoke);
            try stdout.print("  {s}: smoke allow={s} deny={s} readiness={s}\n", .{
                host_name,
                smoke.allow.toString(),
                smoke.deny.toString(),
                readiness.toString(),
            });
            switch (readiness) {
                .protected => {},
                .degraded => {
                    try stdout.writeAll("    → DEGRADED (deny ok, allow failed) — not ready; fix: ryk doctor\n");
                    degraded_count += 1;
                },
                .not_protected => {
                    try stdout.writeAll("    → NOT protected — deny smoke failed\n");
                    failure_count += 1;
                },
                .unknown => {
                    try stdout.writeAll("    → smoke not run — do not treat as protected\n");
                },
            }
        }
    }

    try stdout.writeAll("\nPi: bundled setup is managed automatically by `ryk start` (no npm step).\n");
    try stdout.writeAll("  Verify: ryk doctor · process-level isolation: ryk run -- pi\n");

    if (!any_detected) {
        try stdout.writeAll("\nNo agent hosts detected in PATH.\n");
        try stdout.writeAll("Install a supported host and run `ryk start --auto` again.\n");
    }

    if (failure_count > 0) {
        try stdout.print("\nSetup finished with {d} failure(s).\n", .{failure_count});
        try stdout.writeAll("Review the messages above and re-run `ryk start --auto` after fixing blockers.\n");
        return exit_codes.general;
    }

    try stdout.writeAll("\n");
    if (degraded_count > 0) {
        try stdout.print("Setup finished with {d} degraded host(s) — deny ok but allow failed (not ready).\n", .{degraded_count});
        try stdout.writeAll("Monitoring/partial — not fully ready for protect.\n");
        try stdout.writeAll("Fix daemon first: ryk doctor --check\n");
        try stdout.writeAll("Live host E2E (optional): ./scripts/host-live-e2e.sh\n");
        // Nonzero: degraded hosts mean setup is not complete (honest exit contract).
        return exit_codes.general;
    }

    try style.maybeColor(io, stdout, style.Style.green, style.Glyph.party ++ " Setup complete!");
    try stdout.writeAll("\nNext: ryk claude  (or codex / pi / …) · ryk doctor · ryk replay\n");
    try stdout.writeAll("Re-run: ryk start --auto\n");
    return exit_codes.success;
}

fn flushIfSupported(writer: anytype) !void {
    const Writer = @TypeOf(writer);
    switch (@typeInfo(Writer)) {
        .pointer => |pointer| {
            if (@hasDecl(pointer.child, "flush")) try writer.flush();
        },
        else => {
            if (@hasDecl(Writer, "flush")) try writer.flush();
        },
    }
}

fn runChild(io: std.Io, argv: []const []const u8) !u8 {
    var child = try std.process.spawn(io, .{
        .argv = argv,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    const term = try child.wait(io);
    return switch (term) {
        .exited => |code| @as(u8, @intCast(@min(code, 255))),
        else => 255,
    };
}

fn runGuidedSetup(
    io: std.Io,
    cwd: std.Io.Dir,
    preset: []const u8,
    stdout: anytype,
    stderr: anytype,
    injected_reader: ?*std.Io.Reader,
    render: SetupRenderOpts,
) !u8 {
    var gpa_state: gpa_mod.State = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();

    const self_exe = try std.process.executablePathAlloc(io, allocator);
    defer allocator.free(self_exe);

    if (!render.embedded) {
        try tui.render.banner(io, stdout, build_options.version, "guided setup");
    }

    const workspace_root = try onboarding.resolveWorkspaceRootFromCwd(io, allocator, cwd);
    defer allocator.free(workspace_root);

    const policy_existed = onboarding.policyExists(io, workspace_root);
    if (!render.embedded) {
        try tui.render.stepLine(io, stdout, .active, "Policy", "Checking workspace policy...", 0);
    }
    if (!policy_existed and !render.embedded) {
        try stdout.writeAll("No policy found. Creating policy...\n");
    }
    var ensure_outcome = try ensure.runEnsure(io, allocator, cwd, .{
        .preset = preset,
        .skip_host_wire = true,
        .workspace_root_override = workspace_root,
    }, stdout, stderr);
    defer ensure_outcome.deinit(allocator);
    const policy_code = ensure.processExitForOutcome(ensure_outcome);
    if (policy_code != exit_codes.success) {
        if (!render.embedded) {
            try tui.render.stepLine(io, stdout, .failed, "Policy", "Policy setup failed.", 0);
        }
        try stderr.print("ryk setup: policy init returned non-success code {d}\n", .{policy_code});
        return policy_code;
    }
    if (!render.embedded) {
        try tui.render.stepLine(io, stdout, .done, "Policy", if (policy_existed) "Existing policy preserved." else "Policy created.", 0);
    }

    var packs_result = pack_state.ensurePresetPacksByName(io, allocator, workspace_root, preset) catch pack_state.EnsurePacksResult{
        .message = "Packs: baseline only (pack config write skipped)",
        .owned = false,
    };
    defer packs_result.deinit(allocator);
    try stdout.print("{s}\n", .{packs_result.message});
    if (packs_result.config_path) |path| {
        try stdout.print("  Pack config ({s}): {s}\n", .{ packs_result.scope.?.label(), path });
    }

    var doctor_report = try plugin.collectPluginDoctorReport(io, allocator);
    defer plugin.deinitPluginDoctorReport(&doctor_report, allocator);

    if (!render.embedded) {
        try tui.render.stepLine(io, stdout, .active, "Hosts", "Detecting agent hosts...", 0);
    }

    var host_statuses: std.ArrayList(onboarding.HostStatus) = .empty;
    defer host_statuses.deinit(allocator);

    for (onboarding.supported_hosts) |host_name| {
        const detected = plugin.binaryInPath(io, allocator, host_name);
        const installed = if (detected) plugin.hostPluginInstalledFromReport(host_name, doctor_report) else false;
        try host_statuses.append(allocator, .{
            .name = host_name,
            .detected = detected,
            .installed = installed,
        });
    }

    var detected_count: usize = 0;
    for (host_statuses.items) |status| {
        if (status.detected) detected_count += 1;
    }

    if (detected_count == 0) {
        if (!render.embedded) {
            try tui.render.stepLine(io, stdout, .done, "Hosts", "No supported hosts detected in PATH.", 0);
        }
        try stdout.writeAll("\nYou can still use `ryk run -- <your-command>` for protection.\n");
        return exit_codes.success;
    }

    var panel_lines: std.ArrayList([]const u8) = .empty;
    defer {
        for (panel_lines.items) |line| allocator.free(line);
        panel_lines.deinit(allocator);
    }

    for (host_statuses.items) |status| {
        if (!status.detected) continue;
        const line = try std.fmt.allocPrint(
            allocator,
            "{s}: {s}{s}",
            .{
                status.name,
                if (status.installed) "installed" else "detected",
                if (status.installed) "" else ", not integrated",
            },
        );
        try panel_lines.append(allocator, line);
    }
    try stdout.writeAll("\n");
    try tui.render.panel(io, stdout, "Detected hosts", panel_lines.items);
    try stdout.writeAll("\n");

    var options = try allocator.alloc(tui.prompt.SelectionOption, detected_count);
    defer {
        for (options) |opt| {
            allocator.free(opt.label);
            if (opt.id) |id| allocator.free(id);
        }
        allocator.free(options);
    }

    var visible_idx: usize = 0;
    for (host_statuses.items) |status| {
        if (!status.detected) continue;
        const marker = if (status.installed) " (installed)" else "";
        var label_buf: [64]u8 = undefined;
        const label = std.fmt.bufPrint(&label_buf, "{s}{s}", .{ status.name, marker }) catch status.name;
        options[visible_idx] = .{
            .label = try allocator.dupe(u8, label),
            .checked = true,
            .id = try allocator.dupe(u8, status.name),
        };
        visible_idx += 1;
    }

    const confirmed = try tui.prompt.multiSelect(io, allocator, stdout, options, "Select agent hosts to integrate", injected_reader);
    if (!confirmed) {
        try stdout.writeAll("\nHost selection cancelled.\n");
        return exit_codes.success;
    }

    if (!render.embedded) {
        try tui.render.stepLine(io, stdout, .active, "Hosts", "Installing integrations...", 0);
    }

    var installed_hosts: std.ArrayList([]const u8) = .empty;
    defer {
        for (installed_hosts.items) |host| allocator.free(host);
        installed_hosts.deinit(allocator);
    }
    var skipped_hosts: std.ArrayList([]const u8) = .empty;
    defer {
        for (skipped_hosts.items) |host| allocator.free(host);
        skipped_hosts.deinit(allocator);
    }
    var failure_count: usize = 0;

    for (options) |item| {
        const host_name = item.id orelse item.label;
        if (!item.checked) {
            try skipped_hosts.append(allocator, try allocator.dupe(u8, host_name));
            continue;
        }

        if (plugin.hostPluginInstalledFromReport(host_name, doctor_report)) {
            try installed_hosts.append(allocator, try allocator.dupe(u8, host_name));
            continue;
        }

        try stdout.print("  → {s}: ", .{host_name});
        try flushIfSupported(stdout);

        var spinner = spinner_pkg.Spinner(@TypeOf(stdout)){
            .label = host_name,
            .io = io,
            .stdout = stdout,
        };
        try spinner.start();

        const install_argv = &[_][]const u8{ self_exe, "plugin", "install", host_name, "--yes" };
        const code = runChild(io, install_argv) catch |err| {
            try spinner.stop(false);
            try stdout.print("failed ({s})\n", .{@errorName(err)});
            failure_count += 1;
            continue;
        };
        const outcome = plugin.verifyHostInstallAfterChild(io, allocator, host_name, code);
        if (outcome != .failed) {
            try spinner.stop(true);
            if (outcome == .installed_after_child_failure)
                try stdout.print("installed (verified; installer exited {d})\n", .{code})
            else
                try stdout.writeAll("installed (verified)\n");
            try installed_hosts.append(allocator, try allocator.dupe(u8, host_name));
        } else {
            try spinner.stop(false);
            try stdout.print("failed verification (installer exit {d})\n", .{code});
            failure_count += 1;
        }
    }

    if (!render.embedded) {
        if (failure_count == 0) {
            try tui.render.stepLine(io, stdout, .done, "Hosts", "Integrations configured.", 0);
        } else {
            try tui.render.stepLine(io, stdout, .failed, "Hosts", "Some integrations failed.", 0);
        }
    } else if (failure_count > 0) {
        try stdout.print("  {d} integration(s) failed.\n", .{failure_count});
    }

    var summary_lines: std.ArrayList([]const u8) = .empty;
    defer {
        for (summary_lines.items) |line| allocator.free(line);
        summary_lines.deinit(allocator);
    }

    for (installed_hosts.items) |host| {
        const line = try std.fmt.allocPrint(allocator, "✓ {s}: integrated", .{host});
        try summary_lines.append(allocator, line);
    }
    for (skipped_hosts.items) |host| {
        const line = try std.fmt.allocPrint(allocator, "○ {s}: skipped", .{host});
        try summary_lines.append(allocator, line);
    }
    if (failure_count > 0) {
        const line = try std.fmt.allocPrint(allocator, "✗ {d} integration(s) failed", .{failure_count});
        try summary_lines.append(allocator, line);
    }

    try stdout.writeAll("\n");
    try tui.render.panel(io, stdout, "Setup summary", summary_lines.items);
    try stdout.writeAll("\n");

    if (failure_count > 0) {
        try stdout.writeAll("Review the messages above and re-run `ryk start` after fixing blockers.\n");
        return exit_codes.general;
    }

    try style.maybeColor(io, stdout, style.Style.green, style.Glyph.party ++ " Guided setup complete!");
    try stdout.writeAll("\nRun 'ryk doctor' or 'ryk run -- <command>' to get started.\n");
    return exit_codes.success;
}

test "guided setup host panel formats detected hosts" {
    var gpa_state: gpa_mod.State = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();

    const statuses = [_]onboarding.HostStatus{
        .{ .name = "codex", .detected = true, .installed = false },
        .{ .name = "claude", .detected = true, .installed = true },
        .{ .name = "hermes", .detected = false, .installed = false },
    };

    var panel_lines: std.ArrayList([]const u8) = .empty;
    defer {
        for (panel_lines.items) |line| allocator.free(line);
        panel_lines.deinit(allocator);
    }

    for (statuses) |status| {
        if (!status.detected) continue;
        const line = try std.fmt.allocPrint(
            allocator,
            "{s}: {s}{s}",
            .{
                status.name,
                if (status.installed) "installed" else "detected",
                if (status.installed) "" else ", not integrated",
            },
        );
        try panel_lines.append(allocator, line);
    }

    try std.testing.expectEqual(@as(usize, 2), panel_lines.items.len);
    try std.testing.expect(std.mem.indexOf(u8, panel_lines.items[0], "codex") != null);
    try std.testing.expect(std.mem.indexOf(u8, panel_lines.items[1], "claude") != null);
}

test "guided setup multiSelect with injected reader accepts defaults" {
    tui.theme.resetCache();
    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var in = std.Io.Reader.fixed("enter\n");

    var options = [_]tui.prompt.SelectionOption{
        .{ .label = "codex", .checked = true, .id = "codex" },
        .{ .label = "claude", .checked = false, .id = "claude" },
    };

    const confirmed = try tui.prompt.multiSelect(std.testing.io, std.testing.allocator, &stdout_writer, &options, "Select hosts", &in);
    try std.testing.expect(confirmed);
    try std.testing.expect(options[0].checked);
    try std.testing.expect(!options[1].checked);
}

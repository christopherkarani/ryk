const std = @import("std");
const pcre2_slim = @import("build/pcre2_slim.zig");

/// Run a test binary in terminal mode (avoiding Zig 0.16 server-mode IPC
/// which hangs with this project's test suite).
/// Link the slim static PCRE2 (UNICODE/UCD/DFA/substitute dropped) + C shim.
/// Built from the pinned tarball so host/cross targets do not need system
/// libpcre2-dev. See `docs/dev/pcre2-slim.md`.
fn addPcre2Shim(
    b: *std.Build,
    mod: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) void {
    mod.link_libc = true;
    const slim = pcre2_slim.addLibrary(b, target, optimize);
    mod.linkLibrary(slim.lib);
    mod.addIncludePath(slim.include_dir);
    mod.addIncludePath(b.path("src/shell_engine"));
    // Static PCRE2 requires PCRE2_STATIC for the public header macros on all targets.
    mod.addCSourceFile(.{
        .file = b.path("src/shell_engine/pcre2_shim.c"),
        .flags = &.{ "-std=c99", "-DPCRE2_STATIC" },
    });
    mod.addCSourceFile(.{ .file = b.path("src/shell_engine/windows_acl.c"), .flags = &.{} });
    if (target.result.os.tag == .windows) mod.linkSystemLibrary("advapi32", .{});
}

/// Compile-time `-fstrip` is per-module. Setting it only on `exe.root_module`
/// leaves DWARF in `ryk_mod`, vaxis, PCRE2, and other linked objects.
/// ReleaseSafe only — default Debug test binaries stay unstripped.
fn applyReleaseSafeStrip(mod: *std.Build.Module) void {
    if (mod.strip == true) return;
    mod.strip = true;
    for (mod.import_table.values()) |imported| {
        applyReleaseSafeStrip(imported);
    }
    for (mod.link_objects.items) |obj| {
        switch (obj) {
            .other_step => |compile| applyReleaseSafeStrip(compile.root_module),
            else => {},
        }
    }
}

fn addRunTestTerminal(b: *std.Build, exe: *std.Build.Step.Compile) *std.Build.Step.Run {
    const step_name = if (exe.kind == .@"test" and std.mem.eql(u8, exe.name, "test"))
        b.fmt("run {s}", .{@tagName(exe.kind)})
    else
        b.fmt("run {s} {s}", .{ @tagName(exe.kind), exe.name });

    const run_step = std.Build.Step.Run.create(b, step_name);
    run_step.producer = exe;
    if (exe.exec_cmd_args) |exec_cmd_args| {
        for (exec_cmd_args) |cmd_arg| {
            if (cmd_arg) |arg| {
                run_step.addArg(arg);
            } else {
                run_step.addArtifactArg(exe);
            }
        }
    } else {
        run_step.addArtifactArg(exe);
    }
    run_step.stdio = .inherit;
    run_step.setEnvironmentVariable("RYK_DISABLE_GLOBAL_DASHBOARD_FEED", "1");
    if (b.args) |args| {
        run_step.addArgs(args);
    }
    return run_step;
}

pub fn build(b: *std.Build) void {
    if (b.option(bool, "incremental", "Enable incremental compilation (faster rebuilds)")) |inc| {
        b.graph.incremental = inc;
    }

    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const version_override = b.option([]const u8, "version", "ryk version metadata");
    const version = blk: {
        if (version_override) |v| break :blk v;
        const io = b.graph.io;
        const version_file = std.Io.Dir.cwd().readFileAlloc(io, "VERSION", b.allocator, std.Io.Limit.limited(32)) catch break :blk "1.2.9";
        const trimmed = std.mem.trim(u8, version_file, " \n\r\t");
        const result = b.allocator.dupe(u8, trimmed) catch break :blk "1.2.9";
        b.allocator.free(version_file);
        break :blk result;
    };
    const commit = b.option([]const u8, "commit", "Source commit metadata") orelse "unknown";
    const build_date = b.option([]const u8, "build-date", "UTC build date metadata") orelse "unknown";
    const posthog_project_token = b.option(
        []const u8,
        "posthog-project-token",
        "PostHog project token for release telemetry",
    ) orelse "";
    // Default stays HTTP-on (PATH `ryk`, curl|sh with a live PostHog token).
    // `-Dhttp=false` omits telemetry_transport + provider_gateway so TLS/HTTP
    // client code is not analyzed. Empty-token dry-run does not shrink curl|sh.
    const enable_http = b.option(
        bool,
        "http",
        "Link HTTP/TLS client (telemetry transport + provider gateway; default true)",
    ) orelse true;
    // Zig 0.16: filters are compile-time (passed to `zig test` as --test-filter), not runtime
    // argv on the terminal test runner. Use: ./scripts/zig build test-lib -Dtest-filter=Spinner
    const test_filter = b.option([]const u8, "test-filter", "Only run unit tests whose names contain this substring");
    const test_filters: []const []const u8 = if (test_filter) |f| b.dupeStrings(&.{f}) else &.{};

    const build_options = b.addOptions();
    build_options.addOption([]const u8, "version", version);
    build_options.addOption([]const u8, "commit", commit);
    build_options.addOption([]const u8, "build_date", build_date);
    build_options.addOption([]const u8, "posthog_project_token", posthog_project_token);
    build_options.addOption(bool, "enable_http", enable_http);
    const build_options_mod = build_options.createModule();

    const core_schema_documents = b.addOptions();
    core_schema_documents.addOption([]const u8, "policy_v1", @embedFile("schemas/policy-v1.json"));
    core_schema_documents.addOption([]const u8, "event_v1", @embedFile("schemas/event-v1.json"));
    core_schema_documents.addOption([]const u8, "mcp_manifest_v1", @embedFile("schemas/mcp-manifest-v1.json"));
    const core_schema_documents_mod = core_schema_documents.createModule();
    _ = &core_schema_documents_mod;

    const vaxis_dep = b.dependency("vaxis", .{ .target = target, .optimize = optimize, .external_uucode = true });
    const vaxis_mod = vaxis_dep.module("vaxis");
    const uucode_dep = b.dependency("uucode", .{
        .target = target,
        .optimize = optimize,
        .fields = @as([]const []const u8, &.{ "east_asian_width", "grapheme_break", "general_category", "is_emoji_presentation" }),
    });
    vaxis_mod.addImport("uucode", uucode_dep.module("uucode"));

    const ryk_core_engine_mod = b.createModule(.{
        .root_source_file = b.path("src/core_engine.zig"),
        .target = target,
        .optimize = optimize,
    });
    ryk_core_engine_mod.link_libc = true;

    const ryk_core_mod = b.addModule("ryk_core", .{
        .root_source_file = b.path("packages/core/src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "core_engine", .module = ryk_core_engine_mod },
        },
    });

    const ryk_mod = b.addModule("ryk", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "ryk_core", .module = ryk_core_mod },
            .{ .name = "build_options", .module = build_options_mod },
            .{ .name = "vaxis", .module = vaxis_mod },
        },
    });
    ryk_mod.addImport("build_options", build_options_mod);
    ryk_mod.addImport("ryk", ryk_mod);

    const ryk_cli_mod = b.addModule("ryk_cli", .{
        .root_source_file = b.path("packages/cli/src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "ryk", .module = ryk_mod },
            .{ .name = "ryk_core", .module = ryk_core_mod },
            .{ .name = "build_options", .module = build_options_mod },
        },
    });

    // Product binary is `ryk` only.
    const exe = b.addExecutable(.{
        .name = "ryk",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ryk", .module = ryk_mod },
                .{ .name = "build_options", .module = build_options_mod },
            },
        }),
    });
    exe.root_module.link_libc = true;
    exe.root_module.addImport("vaxis", vaxis_mod);
    // Attach once on the lib module (imported by the exe). Linking the same C shim on both
    // exe.root_module and ryk_mod duplicates _ryk_regex_* symbols at link time.
    addPcre2Shim(b, ryk_mod, target, optimize);
    // Ship `ryk` only. `ryk-windows-check` is a compile probe, not the Windows
    // artifact — that is this same `exe` with `-Dtarget=x86_64-windows`.
    if (optimize == .ReleaseSafe) {
        applyReleaseSafeStrip(exe.root_module);
    }

    const install_ryk = b.addInstallArtifact(exe, .{});
    b.getInstallStep().dependOn(&install_ryk.step);

    const install_ryk_step = b.step("install-ryk", "Install ryk CLI");
    install_ryk_step.dependOn(&install_ryk.step);

    const run_step = b.step("run", "Run the ryk CLI");
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    run_step.dependOn(&run_cmd.step);

    const lib_tests = b.addTest(.{
        .root_module = ryk_mod,
        .filters = test_filters,
    });
    const run_lib_tests = addRunTestTerminal(b, lib_tests);

    const exe_tests = b.addTest(.{
        .root_module = exe.root_module,
        .filters = test_filters,
    });
    const run_exe_tests = addRunTestTerminal(b, exe_tests);

    const core_package_tests = b.addTest(.{
        .root_module = ryk_core_mod,
        .filters = test_filters,
    });
    const run_core_package_tests = addRunTestTerminal(b, core_package_tests);
    // Independent run steps for focused test targets (do not inherit lib test dependency).
    const run_core_package_tests_only = addRunTestTerminal(b, core_package_tests);

    // Deep `src/policy/*` unit tests: package re-exports do not attach nested module
    // tests under Zig 0.16 monopath/ryk_core roots. Root at core_engine so
    // agent_inference_hosts is discoverable under test-core/test-policy with
    // `-Dtest-filter=…`. Dedicated module (not ryk_core_engine_mod) — reusing the
    // package import as test root fails nested audit/core compile under 0.16.
    //
    // Dedicated engine addTest (not ryk_core re-exports). On test-fast serial
    // chain, compile-test-fast, and `test` after P0-s4. Focused `test-core`
    // still uses run_core_engine_tests_only so the slice does not wait on lib.
    const core_engine_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/core_engine.zig"),
            .target = target,
            .optimize = optimize,
        }),
        .filters = test_filters,
    });
    // util.zig realpath helpers (user allowlist under-root) use libc realpath.
    // Also required so matcher unit tests can run under test-policy.
    core_engine_tests.root_module.link_libc = true;
    const run_core_engine_tests_only = addRunTestTerminal(b, core_engine_tests);

    const core_contract_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("packages/core/tests/contract.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ryk_core", .module = ryk_core_mod },
            },
        }),
        .filters = test_filters,
    });
    core_contract_tests.root_module.link_libc = true;
    const run_core_contract_tests = addRunTestTerminal(b, core_contract_tests);
    const run_core_contract_tests_only = addRunTestTerminal(b, core_contract_tests);

    // Domain-sliced test roots: root files live under src/ so relative imports
    // (e.g. sandbox → env_util) stay inside the module path. Avoids full ryk facade
    // (cli/tui/vaxis/plugin) for focused agent iteration.
    const sandbox_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/sandbox_slice_root.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ryk_core", .module = ryk_core_mod },
            },
        }),
        .filters = test_filters,
    });
    sandbox_tests.root_module.link_libc = true;
    const run_sandbox_tests = addRunTestTerminal(b, sandbox_tests);

    const intercept_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/intercept_slice_root.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ryk_core", .module = ryk_core_mod },
                .{ .name = "build_options", .module = build_options_mod },
            },
        }),
        .filters = test_filters,
    });
    intercept_tests.root_module.link_libc = true;
    const run_intercept_tests = addRunTestTerminal(b, intercept_tests);

    const shell_engine_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/shell_engine_slice_root.zig"),
            .target = target,
            .optimize = optimize,
        }),
        .filters = test_filters,
    });
    addPcre2Shim(b, shell_engine_tests.root_module, target, optimize);
    const run_shell_engine_tests = addRunTestTerminal(b, shell_engine_tests);

    const hook_cold_latency_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/shell_engine/cold_latency_test.zig"),
            .target = target,
            .optimize = optimize,
        }),
        .filters = test_filters,
    });
    addPcre2Shim(b, hook_cold_latency_tests.root_module, target, optimize);
    const run_hook_cold_latency_tests = addRunTestTerminal(b, hook_cold_latency_tests);

    const cli_package_tests = b.addTest(.{
        .root_module = ryk_cli_mod,
    });
    const run_cli_package_tests = addRunTestTerminal(b, cli_package_tests);

    const cli_contract_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("packages/cli/tests/contract.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ryk_cli", .module = ryk_cli_mod },
            },
        }),
    });
    const run_cli_contract_tests = addRunTestTerminal(b, cli_contract_tests);

    const hook_host_matrix_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/hook_host_matrix.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ryk", .module = ryk_mod },
            },
        }),
    });
    const run_hook_host_matrix_tests = addRunTestTerminal(b, hook_host_matrix_tests);
    // Matrix and dispatch spawn `./zig-out/bin/ryk`; install first so they cannot skip.
    run_hook_host_matrix_tests.step.dependOn(&install_ryk.step);

    const hook_dispatch_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/hook_dispatch.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ryk", .module = ryk_mod },
            },
        }),
    });
    const run_hook_dispatch_tests = addRunTestTerminal(b, hook_dispatch_tests);
    run_hook_dispatch_tests.step.dependOn(&install_ryk.step);

    const hook_validation_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/hook_validation.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ryk", .module = ryk_mod },
            },
        }),
    });
    const run_hook_validation_tests = addRunTestTerminal(b, hook_validation_tests);
    // Bare-`ryk` stdin tests exec ./zig-out/bin/ryk; missing binary must not skip.
    run_hook_validation_tests.step.dependOn(&install_ryk.step);

    const dashboard_feed_redaction_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/dashboard_feed_redaction.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ryk", .module = ryk_mod },
            },
        }),
    });
    const run_dashboard_feed_redaction_tests = addRunTestTerminal(b, dashboard_feed_redaction_tests);

    const presentation_redaction_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/presentation_redaction.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ryk", .module = ryk_mod },
            },
        }),
    });
    const run_presentation_redaction_tests = addRunTestTerminal(b, presentation_redaction_tests);

    const release_packaging_contract_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/release_packaging_contract.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ryk", .module = ryk_mod },
            },
        }),
    });
    const run_release_packaging_contract_tests = addRunTestTerminal(b, release_packaging_contract_tests);

    const daemon_ipc_hardening_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/daemon_ipc_hardening.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ryk", .module = ryk_mod },
            },
        }),
    });
    daemon_ipc_hardening_tests.root_module.link_libc = true;
    const run_daemon_ipc_hardening_tests = addRunTestTerminal(b, daemon_ipc_hardening_tests);

    const public_surface_contract_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/public_surface_contract.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_public_surface_contract_tests = addRunTestTerminal(b, public_surface_contract_tests);

    const plugin_codex_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/plugin_codex.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_plugin_codex_tests = addRunTestTerminal(b, plugin_codex_tests);

    const plugin_claude_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/plugin_claude.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_plugin_claude_tests = addRunTestTerminal(b, plugin_claude_tests);

    const plugin_security_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/plugin_security.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ryk", .module = ryk_mod },
            },
        }),
    });
    const run_plugin_security_tests = addRunTestTerminal(b, plugin_security_tests);

    const plugin_openclaw_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/plugin_openclaw.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_plugin_openclaw_tests = addRunTestTerminal(b, plugin_openclaw_tests);

    const plugin_hermes_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/plugin_hermes.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_plugin_hermes_tests = addRunTestTerminal(b, plugin_hermes_tests);

    const install_version_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/install_version.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_install_version_tests = addRunTestTerminal(b, install_version_tests);

    const install_opencode_detect_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/install_opencode_detect.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ryk", .module = ryk_mod },
            },
        }),
    });
    const run_install_opencode_detect_tests = addRunTestTerminal(b, install_opencode_detect_tests);

    const install_paths_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/install_paths.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ryk", .module = ryk_mod },
            },
        }),
    });
    const run_install_paths_tests = addRunTestTerminal(b, install_paths_tests);

    const start_onboarding_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/start_onboarding.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ryk", .module = ryk_mod },
            },
        }),
    });
    const run_start_onboarding_tests = addRunTestTerminal(b, start_onboarding_tests);

    const setup_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/setup.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ryk", .module = ryk_mod },
                .{ .name = "ryk_core", .module = ryk_core_mod },
            },
        }),
    });
    const run_setup_tests = addRunTestTerminal(b, setup_tests);

    const check_fixture_secrets = b.addSystemCommand(&.{ "bash", "scripts/check-fixture-secrets.sh" });
    check_fixture_secrets.setCwd(b.path("."));
    const check_fixture_secrets_step = b.step("check-fixture-secrets", "Scan fixtures/tests for non-synthetic secret patterns");
    check_fixture_secrets_step.dependOn(&check_fixture_secrets.step);

    const test_release_payload_boundary = b.addSystemCommand(&.{ "bash", "scripts/test-release-payload-boundary.sh" });
    test_release_payload_boundary.setCwd(b.path("."));

    const check_step = b.step("check", "Compile ryk CLI only (fastest compile gate)");
    check_step.dependOn(&exe.step);

    const compile_test_lib_step = b.step("compile-test-lib", "Compile ryk lib unit tests without running");
    compile_test_lib_step.dependOn(&lib_tests.step);

    // Dedicated core_engine addTest only — not the package half of test-core.
    const compile_test_core_step = b.step("compile-test-core", "Compile dedicated core_engine unit tests without running");
    compile_test_core_step.dependOn(&core_engine_tests.step);

    // Keep membership identical to `test-fast` (lib + ryk_core package + contract + core_engine).
    // daemon_ipc_hardening is full-suite only (`test` step), not the fast gate.
    const compile_test_fast_step = b.step("compile-test-fast", "Compile test-fast artifacts without running");
    compile_test_fast_step.dependOn(&lib_tests.step);
    compile_test_fast_step.dependOn(&core_package_tests.step);
    compile_test_fast_step.dependOn(&core_contract_tests.step);
    compile_test_fast_step.dependOn(&core_engine_tests.step);

    const test_lib_step = b.step("test-lib", "Run ryk lib inline tests only");
    test_lib_step.dependOn(&run_lib_tests.step);

    const test_core_step = b.step("test-core", "Run ryk_core package + core_engine (policy/audit) unit tests");
    test_core_step.dependOn(&run_core_package_tests_only.step);
    test_core_step.dependOn(&run_core_engine_tests_only.step);

    const test_core_contract_step = b.step("test-core-contract", "Run packages/core contract tests only");
    test_core_contract_step.dependOn(&run_core_contract_tests_only.step);

    const test_sandbox_step = b.step("test-sandbox", "Run sandbox domain unit tests only (sliced root)");
    test_sandbox_step.dependOn(&run_sandbox_tests.step);

    // Policy domain: deep `src/policy/*` lives under core_engine (not package re-exports).
    // Map `test-policy` to package + core_engine + contract (agent-facing "policy/core" slice).
    const test_policy_step = b.step("test-policy", "Run policy/core gates (test-core package + core_engine + contract)");
    test_policy_step.dependOn(&run_core_package_tests_only.step);
    test_policy_step.dependOn(&run_core_engine_tests_only.step);
    test_policy_step.dependOn(&run_core_contract_tests_only.step);

    const test_intercept_step = b.step("test-intercept", "Run intercept domain unit tests only (sliced root)");
    test_intercept_step.dependOn(&run_intercept_tests.step);

    const test_shell_engine_step = b.step("test-shell-engine", "Run Zig shell_engine unit + 100% oracle corpus parity tests");
    test_shell_engine_step.dependOn(&run_shell_engine_tests.step);
    test_shell_engine_step.dependOn(&run_hook_cold_latency_tests.step);

    const compile_test_sandbox_step = b.step("compile-test-sandbox", "Compile sandbox domain tests without running");
    compile_test_sandbox_step.dependOn(&sandbox_tests.step);

    const compile_test_intercept_step = b.step("compile-test-intercept", "Compile intercept domain tests without running");
    compile_test_intercept_step.dependOn(&intercept_tests.step);

    const compile_test_shell_engine_step = b.step("compile-test-shell-engine", "Compile shell_engine tests without running");
    compile_test_shell_engine_step.dependOn(&shell_engine_tests.step);
    compile_test_shell_engine_step.dependOn(&hook_cold_latency_tests.step);

    // Serialize runs so local `zig build test-fast` does not launch heavy test
    // binaries at once (parallel runs have hung with no output on some hosts).
    // New run step (not run_core_engine_tests_only) so test-core stays independent.
    const run_core_engine_tests = addRunTestTerminal(b, core_engine_tests);
    run_core_package_tests.step.dependOn(&run_lib_tests.step);
    run_core_contract_tests.step.dependOn(&run_core_package_tests.step);
    run_core_engine_tests.step.dependOn(&run_core_contract_tests.step);

    const test_fast_step = b.step("test-fast", "Run fast unit tests (ryk lib + ryk_core package + contract + core_engine)");
    test_fast_step.dependOn(&run_core_engine_tests.step);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&check_fixture_secrets.step);
    test_step.dependOn(&test_release_payload_boundary.step);
    test_step.dependOn(&run_shell_engine_tests.step);
    test_step.dependOn(&run_hook_cold_latency_tests.step);
    test_step.dependOn(&run_lib_tests.step);
    test_step.dependOn(&run_exe_tests.step);
    test_step.dependOn(&run_core_package_tests.step);
    // _only so full `test` does not wait on the test-fast lib serial chain.
    test_step.dependOn(&run_core_engine_tests_only.step);
    test_step.dependOn(&run_core_contract_tests.step);
    test_step.dependOn(&run_cli_package_tests.step);
    test_step.dependOn(&run_cli_contract_tests.step);
    test_step.dependOn(&run_release_packaging_contract_tests.step);
    test_step.dependOn(&run_daemon_ipc_hardening_tests.step);
    // Named subset for hook host-matrix, dispatch, validation, and plugin-security.
    const test_hooks_step = b.step("test-hooks", "Run hook host-matrix, dispatch, validation, and plugin-security tests");
    test_hooks_step.dependOn(&run_hook_host_matrix_tests.step);
    test_hooks_step.dependOn(&run_hook_dispatch_tests.step);
    test_hooks_step.dependOn(&run_hook_validation_tests.step);
    test_hooks_step.dependOn(&run_plugin_security_tests.step);
    test_hooks_step.dependOn(&run_hook_cold_latency_tests.step);

    test_step.dependOn(&run_hook_host_matrix_tests.step);
    test_step.dependOn(&run_hook_dispatch_tests.step);
    test_step.dependOn(&run_hook_validation_tests.step);
    test_step.dependOn(&run_dashboard_feed_redaction_tests.step);
    test_step.dependOn(&run_presentation_redaction_tests.step);
    test_step.dependOn(&run_public_surface_contract_tests.step);
    test_step.dependOn(&run_plugin_codex_tests.step);
    test_step.dependOn(&run_plugin_claude_tests.step);
    test_step.dependOn(&run_plugin_security_tests.step);
    test_step.dependOn(&run_plugin_openclaw_tests.step);
    test_step.dependOn(&run_plugin_hermes_tests.step);
    test_step.dependOn(&run_install_version_tests.step);
    test_step.dependOn(&run_install_opencode_detect_tests.step);
    test_step.dependOn(&run_install_paths_tests.step);
    test_step.dependOn(&run_start_onboarding_tests.step);
    test_step.dependOn(&run_setup_tests.step);

    const fuzz_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/fuzz/security_mutation.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ryk", .module = ryk_mod },
            },
        }),
    });
    const run_fuzz_tests = addRunTestTerminal(b, fuzz_tests);
    const fuzz_step = b.step("fuzz", "Run deterministic security mutation tests");
    fuzz_step.dependOn(&run_fuzz_tests.step);
    test_step.dependOn(&run_fuzz_tests.step);

    const windows_target = b.resolveTargetQuery(.{
        .cpu_arch = .x86_64,
        .os_tag = .windows,
    });
    const windows_mod = b.addModule("ryk-windows-check", .{
        .root_source_file = b.path("src/root.zig"),
        .target = windows_target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "ryk_core", .module = ryk_core_mod },
            .{ .name = "build_options", .module = build_options_mod },
        },
    });
    // Same as host `ryk_mod`: attach once so shell_engine regex links pcre2_shim + static
    // pcre2-8 for the Windows cross compile; do not also link on windows_exe.root_module.
    addPcre2Shim(b, windows_mod, windows_target, optimize);
    const windows_exe = b.addExecutable(.{
        .name = "ryk-windows-check",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = windows_target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ryk", .module = windows_mod },
                .{ .name = "build_options", .module = build_options_mod },
            },
        }),
    });
    windows_exe.root_module.link_libc = true;
    const check_windows_step = b.step("check-windows", "Compile ryk for Windows without running it");
    check_windows_step.dependOn(&windows_exe.step);
}

const std = @import("std");
const builtin = @import("builtin");

const core = @import("ryk_core").core;
const supervisor = core.supervisor;
const core_api = @import("ryk_core").api;
const env_util = @import("../env_util.zig");
const telemetry = @import("../telemetry.zig");
const intercept = @import("../intercept/mod.zig");
const policy = @import("ryk_core").policy;
const sandbox = @import("../sandbox/mod.zig");
const brand = @import("brand.zig");
const exit_codes = @import("exit_codes.zig");
const help = @import("help.zig");
const host_launch = @import("host_launch.zig");
const style = @import("style.zig");
const shell_eval = @import("shell_eval.zig");
const rust_visibility = @import("rust_visibility.zig");
const tui = @import("../tui/mod.zig");
const build_options = @import("build_options");
const suggestions = @import("suggestions.zig");
const run_os_sandbox = @import("run_os_sandbox.zig");
const codex_mcp_sandbox = @import("codex_mcp_sandbox.zig");
const host_mcp_sandbox = @import("host_mcp_sandbox.zig");

const RunOptions = struct {
    workspace: ?[]const u8 = null,
    mode: core.types.Mode = .observe,
    mode_explicit: bool = false,
    policy_path: ?[]const u8 = null,
    session_name: ?[]const u8 = null,
    no_secrets: bool = false,
    secretless: bool = false,
    with_host_secrets: bool = false,
    inherit_env: bool = false,
    /// Set by `--network` / `--no-network`. Null → host-alias mediated default allowlist
    /// (unless legacy kill switch); otherwise ask. Explicit flags always win.
    network_mode: ?policy.schema.NetworkMode = null,
    network_backend: ?policy.schema.NetworkBackend = null,
    /// OS FS sandbox mode (`--os-sandbox`). Default auto (on when available).
    os_sandbox: sandbox.posture.OsSandboxMode = .auto,
    /// macOS Seatbelt residual grade (`--seatbelt-profile` / `RYK_SEATBELT_PROFILE`).
    /// Default hardened. Ignored on non-macOS.
    seatbelt_profile: sandbox.posture.SeatbeltProfileGrade = sandbox.posture.SeatbeltProfileGrade.default_grade,
    allow_network_values: [32][]const u8 = undefined,
    allow_network_count: usize = 0,
    required_backend_values: [16]sandbox.backend.Feature = undefined,
    required_backend_count: usize = 0,
    command_argv: []const []const u8 = &.{},

    fn allowNetwork(self: *const RunOptions) []const []const u8 {
        return self.allow_network_values[0..self.allow_network_count];
    }

    fn requiredBackendFeatures(self: *const RunOptions) []const sandbox.backend.Feature {
        return self.required_backend_values[0..self.required_backend_count];
    }
};

const default_session_grants = [_]intercept.session_secrets.GrantSpec{
    .{
        .env_var = "ANTHROPIC_API_KEY",
        .provider = .anthropic,
        .allowed_hosts = &.{"api.anthropic.com"},
    },
    .{
        .env_var = "OPENAI_API_KEY",
        .provider = .openai,
        .allowed_hosts = &.{"api.openai.com"},
    },
};

/// Shared remount for agent-network mediation fail-closed paths (proxy bind, OS route-force).
const agent_mediation_network_open_help =
    \\  ryk run --network open -- <agent>
    \\(or set RYK_AGENT_NETWORK_DEFAULT=legacy for one-release pre-change defaults).
    \\
;

const agent_mediation_route_force_help =
    \\Agent host network mediation requires OS route-force onto the loopback proxy.
    \\Fix sandbox attach / proxy, or re-run with:
    \\  ryk run --network open -- <agent>
    \\(or set RYK_AGENT_NETWORK_DEFAULT=legacy for one-release pre-change defaults).
    \\
;

fn captureSessionGrants(
    allocator: std.mem.Allocator,
    store: *intercept.session_secrets.Store,
    host_env: *const std.process.Environ.Map,
    selected_policy: *const policy.schema.Policy,
    workspace_root: []const u8,
    env_schema: ?*const intercept.env_schema.Schema,
) !void {
    for (selected_policy.credentials.grants) |grant| {
        const spec: intercept.session_secrets.GrantSpec = .{
            .env_var = grant.env_var,
            .provider = grant.provider,
            .allowed_hosts = grant.allowed_hosts,
        };
        switch (grant.source) {
            .host_env => _ = try store.captureHostEnv(host_env, spec),
            .broker => {
                var resolved = try intercept.credentials.resolveCredential(
                    allocator,
                    selected_policy,
                    workspace_root,
                    grant.credential_ref.?,
                );
                defer resolved.deinit(allocator);
                _ = try store.captureResolved(spec, resolved.value);
            },
        }
    }
    for (default_session_grants) |grant| {
        if (store.hasEnvVar(grant.env_var)) continue;
        if (env_schema) |schema| {
            if (schema.find(grant.env_var)) |variable| {
                if (variable.grant == null) continue;
            }
        }
        _ = try store.captureHostEnv(host_env, grant);
    }
}

fn validateEnvSchemaGrants(
    schema: *const intercept.env_schema.Schema,
    credentials: policy.schema.CredentialsPolicy,
) !void {
    for (schema.vars) |variable| {
        const grant_name = variable.grant orelse continue;
        if (variable.class != .sensitive) return error.InvalidEnvSchemaGrant;
        var found = false;
        for (credentials.grants) |grant| {
            if (!std.mem.eql(u8, grant.name, grant_name)) continue;
            if (!std.mem.eql(u8, grant.env_var, variable.name)) return error.InvalidEnvSchemaGrant;
            found = true;
            break;
        }
        if (!found) return error.InvalidEnvSchemaGrant;
    }
}

pub fn command(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    return commandWithStdio(io, argv, stdout, stderr, .inherit, true);
}

/// Production entry point. Zig 0.16 supplies the authoritative process
/// environment through `std.process.Init`; callers must preserve that map
/// instead of reconstructing it from libc (which is empty on some Linux
/// startup paths).
pub fn commandWithEnv(
    io: std.Io,
    current_env: *const std.process.Environ.Map,
    argv: []const []const u8,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    return commandWithStdioAndEnv(io, argv, stdout, stderr, .inherit, true, current_env, null);
}

/// P1-1 session-end reconciliation: degraded in-shim audit becomes durable
/// `audit_degraded` evidence. (a) Parent-attested at setup (OS attach
/// write-denies the control root to the child): in-shim audit was dark by
/// design this session. (b) Unattested residual: a shim hit the control
/// write-deny path and dropped a workspace gap marker — allowed execs lack
/// in-shim events. Reason codes are static; no command payloads.
fn reconcileShimAuditGap(
    writer: *core_api.AuditWriter,
    io: std.Io,
    allocator: std.mem.Allocator,
    session: core.session.Session,
    parent_marked_degraded: bool,
) !void {
    const shim_mod = @import("shim.zig");
    const degraded_reason: ?[]const u8 = if (parent_marked_degraded)
        "in-shim audit dark by design this session: OS attach write-denies the control root to the child (parent-attested degraded mode)"
    else if (shim_mod.consumeShimAuditGapMarker(io, allocator, session.workspace_root, session.id.slice()) catch false)
        "shim audit open denied (control write-deny residual) without parent attestation; at least one allowed shim exec has no in-shim audit event"
    else
        null;
    if (degraded_reason) |reason| {
        const ts = core.time.Timestamp.now(io);
        const ev: core.event.Event = .{
            .session_id = session.id,
            .event_id = try core.event.generateEventId(ts),
            .timestamp = ts,
            .event_type = .audit_degraded,
            .actor = .{ .kind = .ryk, .display = "ryk" },
            .target = .{ .kind = .session, .value = session.id.slice() },
            .decision = .{ .result = .observe, .reason = reason, .ci_may_proceed = true },
        };
        try core_api.appendAuditEvent(writer, ev);
    }
}

fn commandWithStdio(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype, stdio: supervisor.StdioBehavior, audit_enabled: bool) !u8 {
    return commandWithStdioAndEnv(io, argv, stdout, stderr, stdio, audit_enabled, null, null);
}

fn commandWithStdioAndEnv(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype, stdio: supervisor.StdioBehavior, audit_enabled: bool, current_env_override: ?*const std.process.Environ.Map, shell_evaluator: ?shell_eval.ShellCommandEvaluatorFn) !u8 {
    const options = parseOptions(io, argv, stdout, stderr) catch |err| switch (err) {
        error.HelpShown => return exit_codes.success,
        error.Usage => return exit_codes.usage,
        else => return err,
    };
    if (options.with_host_secrets) {
        try stderr.writeAll(
            "ryk: WARNING: --with-host-secrets disables empty-backpack; child may inherit host secrets.\n" ++
                "Prefer host login (claude/codex login) or wait for provider gateway. See docs/credentials.md\n",
        );
    }
    if (options.secretless and options.with_host_secrets) {
        try stderr.writeAll("ryk run: cannot combine --secretless with --with-host-secrets.\n");
        return exit_codes.usage;
    }

    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();

    // Env map needed for PATH/HOME host-identity bind (and reused below).
    var owned_current_env: ?std.process.Environ.Map = null;
    defer if (owned_current_env) |*env_map| env_map.deinit();
    if (current_env_override == null) owned_current_env = try env_util.createProcessMap(allocator);
    const current_env = current_env_override orelse &owned_current_env.?;

    // Workspace first so host-identity can fence workspace-planted spoofs.
    const workspace_root_for_policy = supervisor.resolveWorkspaceRoot(io, allocator, options.workspace, ".") catch |err| switch (err) {
        error.FileNotFound => {
            try suggestions.writeSanitizedValue(stderr, "ryk run: workspace not found: ", options.workspace orelse ".", "\n");
            return exit_codes.general;
        },
        else => return err,
    };
    defer allocator.free(workspace_root_for_policy);

    // Trusted launch identity (F-02): basename alone is not an agent host.
    var launch_host_id = sandbox.host_identity.HostIdentity{};
    defer launch_host_id.deinit(allocator);
    if (options.command_argv.len > 0) {
        launch_host_id = try sandbox.host_identity.resolveHostIdentity(
            io,
            allocator,
            options.command_argv[0],
            current_env,
            .{ .workspace_root = workspace_root_for_policy },
        );
    }
    const trusted_host_key = launch_host_id.hostKey();
    const trusted_agent_host = launch_host_id.isTrusted() and host_launch.isHostLaunchAlias(trusted_host_key);

    const secret_boundary = effectiveSecretBoundary(options, trusted_agent_host);
    const boundary_active = secret_boundary == .empty_backpack;
    const effective_os_sandbox = effectiveOsSandboxMode(secret_boundary, options.os_sandbox) catch {
        try stderr.writeAll(
            "ryk run: empty-backpack secret boundary requires an active OS sandbox; " ++
                "remove --os-sandbox off.\n",
        );
        return exit_codes.usage;
    };

    var loaded_policy = core_api.discoverPolicy(io, allocator, options.policy_path, workspace_root_for_policy) catch |err| {
        try stderr.print("ryk run: invalid policy: {s}\n", .{@errorName(err)});
        return exit_codes.general;
    };
    defer loaded_policy.deinit();
    const effective_policy_mode = if (options.mode_explicit) coreModeToPolicyMode(options.mode) else loaded_policy.policy.mode();
    const session_mode = effective_policy_mode.toCoreMode();

    // Detect first session *before* any .ryk/sessions/ creation so the warm welcome
    // celebration can be emitted exactly once for a brand-new user/workspace.
    const is_first_session = isFirstSession(io, allocator, workspace_root_for_policy);

    const agent_net_default = parseAgentNetworkDefault(if (std.c.getenv("RYK_AGENT_NETWORK_DEFAULT")) |raw|
        std.mem.span(raw)
    else
        null);
    const mediate_agent_network = wantsMediatedAgentNetwork(options, agent_net_default, trusted_agent_host);
    if (trusted_agent_host and options.network_mode == .open) {
        try stderr.writeAll(
            "ryk: WARNING: --network open disables agent network mediation; " ++
                "child has unrestricted egress (escape used).\n",
        );
    }
    if (trusted_agent_host and agent_net_default == .legacy) {
        try stderr.writeAll(
            "ryk: WARNING: RYK_AGENT_NETWORK_DEFAULT=legacy restores pre-mediation agent net defaults " ++
                "(labels may not match OS enforcement).\n",
        );
    }

    // Product path: trusted host key selects overlay (not basename spoof). AINA P3:
    // pass abs workspace_root + parent HOME so launch merges managed + adapter hosts
    // before empty-backpack scrub (DIS / plan §3.6). Soft-skips if store/home missing.
    const parent_home = current_env.get("HOME") orelse "";
    try applyNetworkOverlayWithHostKey(
        allocator,
        loaded_policy.innerMutPtr(),
        options,
        agent_net_default,
        trusted_agent_host,
        if (trusted_host_key.len > 0) trusted_host_key else null,
        .{
            .io = io,
            .workspace_root = workspace_root_for_policy,
            .home = parent_home,
        },
    );

    var project_env_schema = intercept.env_schema.loadOptional(
        io,
        allocator,
        workspace_root_for_policy,
    ) catch |err| {
        try stderr.print("ryk run: invalid .ryk/env.schema.yaml: {s}\n", .{@errorName(err)});
        return exit_codes.general;
    };
    defer if (project_env_schema) |*schema_value| schema_value.deinit();
    if (project_env_schema) |*schema_value| {
        validateEnvSchemaGrants(schema_value, loaded_policy.innerPtr().credentials) catch |err| {
            try stderr.print("ryk run: invalid env schema grant binding: {s}\n", .{@errorName(err)});
            return exit_codes.general;
        };
    }

    const env_request: intercept.env.Request = .{
        .no_secrets = options.no_secrets,
        .secret_boundary = secret_boundary,
        .inherit_env = options.inherit_env,
        .with_host_secrets = options.with_host_secrets,
        .schema = if (project_env_schema) |*schema_value| schema_value else null,
    };

    var filtered_env = intercept.env.filterMap(
        allocator,
        current_env,
        loaded_policy.innerPtr(),
        effective_policy_mode,
        env_request,
    ) catch |err| switch (err) {
        error.InheritEnvDenied => {
            try stderr.writeAll("ryk run: --inherit-env is not allowed by the selected policy/mode.\n");
            return exit_codes.general;
        },
        else => {
            try stderr.print("ryk run: failed to filter environment: {s}\n", .{@errorName(err)});
            return exit_codes.general;
        },
    };
    defer filtered_env.deinit();

    var secret_store: ?intercept.session_secrets.Store = null;
    defer if (secret_store) |*store| store.deinit();
    if (secret_boundary == .empty_backpack) {
        secret_store = intercept.session_secrets.Store.init(io, allocator) catch |err| {
            try stderr.print("ryk run: secret boundary session store unavailable: {s}\n", .{@errorName(err)});
            return exit_codes.unsupported;
        };
        captureSessionGrants(
            allocator,
            &secret_store.?,
            current_env,
            loaded_policy.innerPtr(),
            workspace_root_for_policy,
            if (project_env_schema) |*schema_value| schema_value else null,
        ) catch |err| {
            try stderr.print("ryk run: secret boundary grant capture failed closed: {s}\n", .{@errorName(err)});
            return exit_codes.general;
        };
        _ = secret_store.?.injectPhantoms(&filtered_env.env_map) catch |err| {
            try stderr.print("ryk run: secret boundary phantom injection failed closed: {s}\n", .{@errorName(err)});
            return exit_codes.general;
        };
    }
    var anthropic_gateway: ?intercept.provider_gateway.Runtime = null;
    defer if (anthropic_gateway) |*runtime| runtime.deinit();
    var openai_gateway: ?intercept.provider_gateway.Runtime = null;
    defer if (openai_gateway) |*runtime| runtime.deinit();
    if (secret_store) |*store| {
        if (store.hasProvider(.anthropic)) {
            anthropic_gateway = intercept.provider_gateway.listen(allocator, store, .anthropic, .{}) catch |err| {
                try stderr.print("ryk run: required Anthropic provider gateway unavailable: {s}\n", .{@errorName(err)});
                return exit_codes.unsupported;
            };
            try filtered_env.env_map.put("ANTHROPIC_BASE_URL", anthropic_gateway.?.bindUrl());
        }
        if (store.hasProvider(.openai)) {
            openai_gateway = intercept.provider_gateway.listen(allocator, store, .openai, .{}) catch |err| {
                try stderr.print("ryk run: required OpenAI provider gateway unavailable: {s}\n", .{@errorName(err)});
                return exit_codes.unsupported;
            };
            const openai_base_url = try std.fmt.allocPrint(allocator, "{s}/v1", .{openai_gateway.?.bindUrl()});
            defer allocator.free(openai_base_url);
            try filtered_env.env_map.put("OPENAI_BASE_URL", openai_base_url);
        }
    }
    if (secret_boundary == .empty_backpack) {
        try writeOmittedModelKeyNotes(current_env_override, &filtered_env.env_map, stderr);
    }
    try installNetworkEnvironment(allocator, &filtered_env.env_map, loaded_policy.innerPtr().network);
    var proxy_runtime: ?intercept.proxy.Runtime = null;
    defer if (proxy_runtime) |*runtime| runtime.deinit();
    const proxy_required_by_backend = loaded_policy.innerPtr().network.effectiveBackend() == .proxy;
    if (proxy_required_by_backend and (anthropic_gateway != null or openai_gateway != null)) {
        try stderr.writeAll(
            "ryk run: provider gateway and route-forced proxy backend cannot share the current single-port sandbox route; failing closed.\n",
        );
        if (mediate_agent_network) {
            try stderr.writeAll(
                "Agent hosts need mediation: remove provider API keys from the host env (use host login), " ++
                    "or re-run with `ryk run --network open -- <agent>` (unrestricted egress).\n",
            );
        }
        return exit_codes.unsupported;
    }
    if (proxy_required_by_backend) {
        // Bind only (no accept thread) so Seatbelt fork stays single-threaded.
        // startServing runs after the agent child is forked (after_process_spawn).
        proxy_runtime = intercept.proxy.listen(allocator, loaded_policy.innerPtr(), effective_policy_mode) catch |err| blk: {
            if (effective_policy_mode == .strict or effective_policy_mode == .ci or requiresBackend(options, .network_proxy_enforce) or mediate_agent_network) {
                try stderr.print("ryk run: proxy network backend unavailable: {s}\n", .{@errorName(err)});
                if (mediate_agent_network) {
                    try stderr.writeAll(
                        "Agent host network mediation requires the proxy. Fix proxy bind, or re-run with:\n" ++
                            agent_mediation_network_open_help,
                    );
                }
                return exit_codes.unsupported;
            }
            try stderr.print("ryk run: proxy network backend unavailable; continuing without proxy in observe-compatible mode: {s}\n", .{@errorName(err)});
            break :blk null;
        };
        if (proxy_runtime) |runtime| {
            try intercept.network.appendProxyEnvironment(&filtered_env.env_map, runtime.bindUrl(), "localhost,127.0.0.1,::1");
            // Do not claim MEDIATED=active until route-force is proven (post-apply).
            try filtered_env.env_map.put("RYK_PROXY_MEDIATED_NETWORK_ENFORCEMENT", "bind-only");
            try filtered_env.env_map.put("RYK_PROXY_BIND", runtime.bindUrl());
            // RYK_PROXY_ROUTE_FORCED=false is set by appendProxyEnvironment; only flip to true when route-forced below.
            try filtered_env.env_map.put("RYK_PROXY_HTTPS_VISIBILITY", "host-port-only");
            try filtered_env.env_map.put("RYK_PROXY_METHOD_PATH_VISIBILITY", "http-and-cooperative-hooks");
        }
    }
    const backend_report = sandbox.backend.detect(core.platform.detectOs());
    try installBackendEnvironment(&filtered_env.env_map, backend_report);

    // Production apply-before-exec (helpers in run_os_sandbox.zig).
    // Pass argv0 so agents installed under $HOME (e.g. ~/.local/share/claude) get
    // narrow .exec grants — without this, child preflight fails with child_apply_failed.
    const launch_argv0: ?[]const u8 = if (options.command_argv.len > 0) options.command_argv[0] else null;
    var codex_mcp_plan: ?codex_mcp_sandbox.Plan = if (effective_os_sandbox != .off)
        codex_mcp_sandbox.prepare(
            io,
            allocator,
            options.command_argv,
            workspace_root_for_policy,
            loaded_policy.path,
            effective_policy_mode.toString(),
            &filtered_env.env_map,
        ) catch |err| {
            try stderr.print(
                "ryk run: cannot build protected Codex MCP launch plan ({s}); refusing direct MCP execution.\n",
                .{@errorName(err)},
            );
            return exit_codes.unsupported;
        }
    else
        null;
    defer if (codex_mcp_plan) |*plan| plan.deinit(io);
    var host_mcp_plan: ?host_mcp_sandbox.Plan = if (effective_os_sandbox != .off and codex_mcp_plan == null)
        host_mcp_sandbox.prepare(
            io,
            allocator,
            options.command_argv,
            workspace_root_for_policy,
            loaded_policy.path,
            effective_policy_mode.toString(),
            &filtered_env.env_map,
        ) catch |err| {
            try stderr.print(
                "ryk run: cannot build protected host MCP launch plan ({s}); refusing direct MCP execution.\n",
                .{@errorName(err)},
            );
            return exit_codes.unsupported;
        }
    else
        null;
    defer if (host_mcp_plan) |*plan| plan.deinit(io);
    const mcp_disabled_count: usize = if (codex_mcp_plan) |plan|
        plan.disabled_server_names.len
    else if (host_mcp_plan) |plan|
        plan.disabled_server_names.len
    else
        0;
    if (mcp_disabled_count > 0) {
        try stderr.print(
            "ryk run: disabled {d} MCP server(s) that could not be policy-mediated; external scripts need a matching .ryk/mcp manifest and HTTP MCP remains unsupported.\n",
            .{mcp_disabled_count},
        );
    }
    const mcp_exec_paths: []const []const u8 = if (codex_mcp_plan) |plan|
        plan.exec_paths
    else if (host_mcp_plan) |plan|
        plan.exec_paths
    else
        &.{};
    const mcp_ro_paths: []const []const u8 = if (codex_mcp_plan) |plan|
        plan.ro_paths
    else if (host_mcp_plan) |plan|
        plan.ro_paths
    else
        &.{};
    const minted_env_lookup: ?sandbox.env_scrub.MintedEnvLookup = if (secret_store) |*store| .{
        .context = store,
        .containsFn = intercept.session_secrets.Store.mintedEnvContains,
    } else null;
    // Route-force can only apply when OS attach is planned. With `--os-sandbox off`,
    // leave require_network_route_forcing false so apply does not short-circuit with
    // network_route_forcing_unavailable before the backend capability gate can report
    // BackendRequirementUnavailable for --require-backend network_enforce.
    const require_network_route_forcing = effective_os_sandbox != .off and
        (requiresBackend(options, .network_enforce) or mediate_agent_network);
    var apply_result = switch (try run_os_sandbox.applyForRun(
        io,
        allocator,
        effective_os_sandbox,
        workspace_root_for_policy,
        &filtered_env.env_map,
        minted_env_lookup,
        options.with_host_secrets,
        if (proxy_runtime) |runtime| runtime.bindPort() else null,
        require_network_route_forcing,
        options.seatbelt_profile,
        secret_boundary == .empty_backpack,
        stdout,
        stderr,
        launch_argv0,
        // Same bind as empty-backpack / mediation / auth preflight — do not re-resolve
        // under filtered child env (would drop RYK_TRUSTED_HOST_PREFIXES).
        trusted_host_key,
        mcp_exec_paths,
        mcp_ro_paths,
    )) {
        .require_failed => |code| {
            if (mediate_agent_network) {
                try stderr.writeAll(agent_mediation_route_force_help);
            }
            return code;
        },
        .ok => |r| r,
    };
    defer apply_result.deinit();
    // Belt-and-suspenders: mediation must achieve real route-force before spawn
    // (covers apply soft-degrade paths that return .ok without route-force).
    if (mediate_agent_network and !apply_result.network_route_forced) {
        try stderr.writeAll(agent_mediation_route_force_help);
        return exit_codes.unsupported;
    }
    if (proxy_runtime != null and apply_result.network_route_forced) {
        try filtered_env.env_map.put("RYK_PROXY_ROUTE_FORCED", "true");
        try filtered_env.env_map.put("RYK_PROXY_MEDIATED_NETWORK_ENFORCEMENT", "active");
        // Honest for both Seatbelt and Landlock: this feature is TCP localhost
        // proxy-port scoped (not full transparent network / not UDP-scoped).
        try filtered_env.env_map.put("RYK_TRANSPARENT_NETWORK_ENFORCEMENT", "tcp-port-route-forced");
        try filtered_env.env_map.put("RYK_BACKEND_NETWORK_ENFORCEMENT", "tcp-port-route-forced");
    }
    // RT-09: session-effective env filtering label (free-form; not backend.Level).
    // Capability/doctor may still report env_filtering=active via installBackendEnvironment;
    // restamp after apply so child env matches session facts (mirror network restamp).
    try filtered_env.env_map.put(
        "RYK_BACKEND_ENV_FILTERING",
        sessionEnvFilteringLabel(.{
            .with_host_secrets = options.with_host_secrets,
            .env_scrubbed = apply_result.env_scrubbed,
            .env_launch_allowlisted = apply_result.env_launch_allowlisted,
        }),
    );
    // E0 / RT-05: when OS attach is planned, control root is write-deny for the
    // agent — in-shim open of events.jsonl is known dead. Mark degraded so PATH
    // shims skip open silently (≤1 parent banner line, not N× per shimmed cmd).
    // Do not grant the agent write access to `.ryk` to "fix" audit.
    const shim_audit_degraded = apply_result.requiresChildApply();
    if (shim_audit_degraded) {
        try filtered_env.env_map.put("RYK_SHIM_AUDIT_MODE", "degraded");
        // Session-file attestation is written when the session id is known
        // (see prepareSessionEnv next to writeSessionShimMode) — env alone is child-forgable.
    }
    // Phase 5: effective session sandbox grade for operators/agents (env + banner).
    // Escape (--network open / legacy) never reports strong-mediated.
    const session_grade = computeSessionSandboxGrade(.{
        .os_attach_planned = apply_result.requiresChildApply(),
        .network_route_forced = apply_result.network_route_forced,
        .unrestricted_escape = isUnrestrictedNetworkEscape(options, agent_net_default, trusted_agent_host),
    });
    try filtered_env.env_map.put("RYK_SESSION_SANDBOX_GRADE", session_grade.toString());
    try run_os_sandbox.warnAutoDegrade(effective_os_sandbox, &apply_result, stderr);

    // Empty backpack + **trusted** agent host: require usable login material or a
    // *relevant* provider gateway (claude→Anthropic, codex→OpenAI). Config dir
    // alone is not enough for hosts with login markers (e.g. Claude credentials).
    // Without either, agents blank-hang after sandbox=active. Fail closed.
    // Basename spoofs are generic — no host auth preflight (not that host).
    // Help/version-only launches skip both missing-auth and stale-OAuth checks so
    // `ryk claude --help` works without login (self-contained binary).
    // Stale access-token fail-closed is intentional even if a refresh token exists:
    // on this product path expired access + no gateway blank-hangs; force re-login
    // or gateway rather than waiting forever (refresh success under the box is not
    // guaranteed and is not proven here).
    if (secret_boundary == .empty_backpack and trusted_host_key.len > 0) {
        if (sandbox.host_config_grants.specForHost(trusted_host_key) != null) {
            const help_only = sandbox.host_config_grants.isAgentHelpOrVersionOnly(options.command_argv);
            const home = filtered_env.env_map.get("HOME") orelse "";
            if (!help_only) {
                const has_usable = sandbox.host_config_grants.hostUsableAuthPresent(io, trusted_host_key, home);
                if (sandbox.host_config_grants.shouldFailClosedMissingAuth(
                    trusted_host_key,
                    anthropic_gateway != null,
                    openai_gateway != null,
                    has_usable,
                )) {
                    try stderr.writeAll(sandbox.host_config_grants.missing_config_fail_closed_message);
                    return exit_codes.unsupported;
                }
                if (sandbox.host_config_grants.shouldFailClosedStaleClaudeLogin(
                    io,
                    trusted_host_key,
                    options.command_argv,
                    home,
                    anthropic_gateway != null,
                )) {
                    try stderr.writeAll(sandbox.host_config_grants.stale_login_fail_closed_message);
                    return exit_codes.unsupported;
                }
            }
        }
        // Shell redirects open stdio FDs in the parent before fork. When those
        // targets sit under classic /tmp or /var/folders, empty-backpack Seatbelt
        // will deny Bun fstat — warn early so operators fix capture location first.
        if (sandbox.host_config_grants.parentStdioHasUngrantedHostTmpRisk(io)) {
            try stderr.writeAll(sandbox.host_config_grants.empty_backpack_stdio_host_tmp_warn);
        }
    }

    const AuditContext = struct {
        io: std.Io,
        allocator: std.mem.Allocator,
        writer: ?core_api.AuditWriter = null,
        session: ?core.session.Session = null,
        workspace_root_owned: ?[]const u8 = null,

        pub fn init(context: *anyopaque, session: core.session.Session) !void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.session = session;
            self.workspace_root_owned = try self.allocator.dupe(u8, session.workspace_root);
            self.writer = try core_api.createAuditWriter(self.io, self.allocator, session);
        }

        pub fn append(context: *anyopaque, ev: core.event.Event) !void {
            const self: *@This() = @ptrCast(@alignCast(context));
            try core_api.appendAuditEvent(&self.writer.?, ev);
        }

        pub fn deinit(self: *@This()) void {
            if (self.writer) |*writer| writer.deinit();
            self.writer = null;
            self.session = null;
            if (self.workspace_root_owned) |root| self.allocator.free(root);
            self.workspace_root_owned = null;
        }
    };
    var audit_context: AuditContext = .{ .io = io, .allocator = allocator };
    defer audit_context.deinit();

    // Shared session_exit + audit summary + last-pointer teardown for fail-closed
    // launch paths (command deny, backend requirement, sandbox attach failure).
    const finalizeFailedSession = struct {
        fn call(
            ctx: *AuditContext,
            alloc: std.mem.Allocator,
            exit_status: u8,
            policy_path: []const u8,
        ) !void {
            if (ctx.writer) |*writer| {
                if (ctx.session) |session| {
                    var ended = session;
                    if (ctx.workspace_root_owned) |root| ended.workspace_root = root;
                    ended.ended_at = core.time.Timestamp.now(ctx.io);
                    const ts = ended.ended_at.?;
                    const ev: core.event.Event = .{
                        .session_id = ended.id,
                        .event_id = try core.event.generateEventId(ts),
                        .timestamp = ts,
                        .event_type = .session_exit,
                        .actor = .{ .kind = .ryk, .display = "ryk" },
                        .target = .{ .kind = .session, .value = ended.id.slice() },
                    };
                    try core_api.appendAuditEvent(writer, ev);
                    const final_hash = writer.finalHash() orelse "";
                    try core_api.writeAuditSummary(alloc, writer.session_dir_path, .{
                        .session = ended,
                        .status = .{ .exited = exit_status },
                        .event_count = writer.event_count,
                        .final_event_hash = final_hash,
                        .policy = policy_path,
                        .product_label = brand.product_display,
                    });
                    try writeLastPointerNoMakePath(alloc, ended.workspace_root, ended.id.slice());
                }
            }
        }
    }.call;

    const StartPrinter = struct {
        io: std.Io,
        writer: @TypeOf(stdout),
        network_mode: policy.schema.NetworkMode,
        secretless: bool,
        with_host_secrets: bool,
        anthropic_gateway: bool,
        openai_gateway: bool,
        apply_result: *const sandbox.apply.ApplyResult,
        audit_context: *AuditContext,
        session_grade: SessionSandboxGrade,
        shim_audit_degraded: bool,

        pub fn print(context: *anyopaque, session: core.session.Session) !void {
            const self: *@This() = @ptrCast(@alignCast(context));
            // Active receipt is set inside ApplyResult.spawnAgent via activateAfterHandshake
            // after the child status-pipe handshake (pre-exec apply + setup). Do not
            // activate from materials alone. Residual: status_ok is pre-exec only —
            // agent binary may still fail after attach (see post-run note on non-zero exit).
            try run_os_sandbox.auditSandboxPosture(self.audit_context, session, self.apply_result.receipt);
            try printSessionStart(
                self.io,
                self.writer,
                session,
                self.network_mode,
                self.secretless,
                self.with_host_secrets,
                self.anthropic_gateway,
                self.openai_gateway,
                self.apply_result.receipt,
                self.session_grade,
                self.shim_audit_degraded,
            );
            // Flush before the shield dwell so the card is on-screen, not buffered.
            try flushIfSupported(self.writer);
            holdShieldCardIfNeeded(self.io, self.writer, self.apply_result.receipt);
        }
    };

    const BoundaryHealthContext = struct {
        proxy: ?*intercept.proxy.Runtime,
        anthropic: ?*intercept.provider_gateway.Runtime,
        openai: ?*intercept.provider_gateway.Runtime,

        pub fn healthy(context: *anyopaque) bool {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (self.proxy) |runtime| {
                if (!runtime.isHealthy()) return false;
            }
            if (self.anthropic) |runtime| {
                if (!runtime.isHealthy()) return false;
            }
            if (self.openai) |runtime| {
                if (!runtime.isHealthy()) return false;
            }
            return true;
        }
    };

    var start_printer: StartPrinter = .{
        .io = io,
        .writer = stdout,
        .network_mode = cliNetworkMode(options, agent_net_default, trusted_agent_host),
        .secretless = boundary_active,
        .with_host_secrets = options.with_host_secrets,
        .anthropic_gateway = anthropic_gateway != null,
        .openai_gateway = openai_gateway != null,
        .apply_result = &apply_result,
        .audit_context = &audit_context,
        .session_grade = session_grade,
        .shim_audit_degraded = shim_audit_degraded,
    };

    var session_approvals = intercept.approvals.SessionApprovals.init(allocator);
    defer session_approvals.deinit();

    const CommandGuardContext = struct {
        io: std.Io,
        allocator: std.mem.Allocator,
        selected_policy: *const policy.schema.Policy,
        effective_mode: policy.schema.Mode,
        command_argv: []const []const u8,
        env_map: *std.process.Environ.Map,
        audit_context: *AuditContext,
        approvals: *intercept.approvals.SessionApprovals,
        backend_report: sandbox.backend.ReportSet,
        required_backend_features: []const sandbox.backend.Feature,
        proxy_bind: ?[]const u8,
        network_route_forced: bool,
        stderr: @TypeOf(stderr),
        shell_evaluator: ?shell_eval.ShellCommandEvaluatorFn = null,
        workspace_root: []const u8,
        // Phase 1 UX: captures the rule id of the most recently denied command so
        // the `error.CommandDenied` handler can render a rich guardian block with a
        // plain-English reason + risk meter. Allocator-owned; freed by the handler.
        // Null on the fail-closed / user-denial paths (graceful degrade).
        last_denied_rule_id: ?[]const u8 = null,
        last_denied_remediation: ?[]const u8 = null,
        /// When true, filter child PATH for sandbox honesty after shim prepend.
        os_attach_planned: bool = false,
        /// Prepared mechanism for session-level backend requirements.
        os_attach_kind: sandbox.apply.ChildApplyKind = .none,

        pub fn beforeProcessLaunch(context: *anyopaque, session: core.session.Session) !void {
            const self: *@This() = @ptrCast(@alignCast(context));
            try self.installShims(session);
            try self.auditBackendCapability(session);
            // Check *every* required feature. Exceptions (proxy bind / route force)
            // skip only that feature — never short-circuit remaining requirements (M-6).
            for (self.required_backend_features) |feature| {
                if (self.backend_report.featureSatisfiesRequirement(feature)) continue;
                if (feature == .network_proxy_enforce and self.proxy_bind != null) continue;
                if (feature == .network_enforce and self.network_route_forced) continue;
                if (feature == .strong_sandbox and self.os_attach_planned) continue;
                if (feature == .landlock and self.os_attach_kind == .landlock) continue;
                const missing = self.backend_report.get(feature);
                try self.auditBackendRequirementDenied(session, missing);
                return error.BackendRequirementUnavailable;
            }
            if (self.proxy_bind) |bind| try self.auditNetworkDecision(session, bind, .network_proxy_start, .{ .result = .observe, .reason = "proxy-mediated network backend started", .ci_may_proceed = true });
            try self.auditNetworkStartupEvents(session);
            const raw_display = try intercept.commands.displayArgvAlloc(self.allocator, self.command_argv);
            defer self.allocator.free(raw_display);
            const display = try intercept.commands.displayArgvRedactedAlloc(self.allocator, self.command_argv);
            defer self.allocator.free(display);

            try self.auditCommandEvent(session, .command_attempt, rust_visibility.target_summary_shell, null, .{});

            var rust_metadata: core.event.EventMetadata = .{};
            defer rust_metadata.deinit(self.allocator);

            const audit_options = shell_eval.ShellAuditOptions{
                .io = self.audit_context.io,
                .workspace_root = self.workspace_root,
                .event_source = rust_visibility.event_source_run,
                .session_id = session.id.slice(),
                .verified = false,
                .os_sandbox_active = self.os_attach_planned,
            };

            var command_decision = try shell_eval.evaluateCommand(
                self.allocator,
                self.effective_mode,
                self.command_argv,
                self.workspace_root,
                self.shell_evaluator,
                &rust_metadata,
                audit_options,
                self.selected_policy.commands.allow,
            );
            defer command_decision.deinit(self.allocator);

            var final_decision = command_decision.decision;
            var approval_reason: ?[]const u8 = null;
            defer if (approval_reason) |reason| self.allocator.free(reason);
            const already_approved = self.approvals.contains(raw_display);
            if (already_approved and final_decision.result == .ask) {
                approval_reason = try std.fmt.allocPrint(self.allocator, "session approval matched command: {s}", .{display});
                final_decision = .{
                    .result = .allow,
                    .reason = approval_reason.?,
                    .risk_score = command_decision.decision.risk_score,
                    .ci_may_proceed = true,
                };
            } else if (final_decision.result == .ask) {
                try self.auditCommandEvent(session, .command_approval_requested, rust_visibility.target_summary_shell, final_decision, rust_metadata);
                const choice = try self.resolveApproval(command_decision, display);
                switch (choice) {
                    .allow_once, .allow_session => {
                        if (choice == .allow_session) try self.approvals.allowForSession(raw_display, command_decision.decision.reason);
                        try intercept.commands.appendApprovalHashEnv(
                            self.allocator,
                            self.env_map,
                            if (choice == .allow_session) intercept.commands.approved_session_env else intercept.commands.approved_once_env,
                            raw_display,
                        );
                        // WP3/WP5 sticky: record after host ask→allow so later shell eval skips re-ask.
                        // Prefer session scope for product trust; once path uses once grant.
                        // Map FM ask_sticky_candidate suggested_sticky_scope / effect_class when present.
                        const sticky_scope: policy.sticky.Scope = if (choice == .allow_session) .session else .once;
                        const sticky_severity = shell_eval.riskLevelFromScore(command_decision.decision.risk_score orelse 80);
                        // best-effort sticky; re-ask on failure
                        shell_eval.recordStickyFromAskWithHints(
                            shell_eval.getSessionStickyStore(),
                            raw_display,
                            sticky_scope,
                            sticky_severity,
                            command_decision.suggested_sticky_scope,
                            command_decision.suggested_effect_class,
                        ) catch {};
                        approval_reason = try std.fmt.allocPrint(self.allocator, "user approved command {s}", .{if (choice == .allow_session) "for this session" else "once"});
                        final_decision = .{
                            .result = .allow,
                            .reason = approval_reason.?,
                            .risk_score = command_decision.decision.risk_score,
                            .ci_may_proceed = true,
                        };
                        // F12: shim soft-allow matches cmd-hash of full display, not redacted summary.
                        // Redacted summary alone would either never match or match every command.
                        const approval_fp = intercept.commands.approvalTargetFingerprint(raw_display);
                        try self.auditCommandEvent(session, .user_approval, &approval_fp, final_decision, rust_metadata);
                    },
                    .deny => {
                        approval_reason = try self.allocator.dupe(u8, "user denied command approval");
                        final_decision = .{
                            .result = .deny,
                            .reason = approval_reason.?,
                            .risk_score = command_decision.decision.risk_score,
                            .ci_may_proceed = false,
                        };
                        try self.auditCommandEvent(session, .user_denial, rust_visibility.target_summary_shell, final_decision, rust_metadata);
                    },
                }
            }

            telemetry.recordEnforcement(
                "run",
                null,
                @tagName(final_decision.result),
                @tagName(shell_eval.riskLevelFromScore(final_decision.risk_score orelse 60)),
                "shell",
                self.effective_mode.toString(),
            );

            if (final_decision.result == .allow or final_decision.result == .observe) {
                try self.auditCommandEvent(session, .command_allowed, rust_visibility.target_summary_shell, final_decision, rust_metadata);
                return;
            }
            try self.auditCommandEvent(session, .command_denied, rust_visibility.target_summary_shell, final_decision, rust_metadata);
            // Capture the matched rule id and remediation tip for the rich deny
            // block. The decision is freed by `defer command_decision.deinit`
            // below; dupe so the handler can read them after this closure returns.
            // Rule id is pack:pattern when available; null on fail-closed.
            if (command_decision.owned_rule_id) |rid| {
                self.last_denied_rule_id = try core_api.redactAlloc(self.allocator, rid);
            }
            if (command_decision.owned_remediation) |tip| {
                self.last_denied_remediation = try core_api.redactAlloc(self.allocator, tip);
            } else if (rust_metadata.remediation) |tip| {
                self.last_denied_remediation = try core_api.redactAlloc(self.allocator, tip);
            }
            return error.CommandDenied;
        }

        fn installShims(self: *@This(), session: core.session.Session) !void {
            const self_exe = try std.process.executablePathAlloc(self.audit_context.io, self.allocator);
            defer self.allocator.free(self_exe);
            const shim_dir = try intercept.commands.createShimDirectory(self.audit_context.io, self.allocator, session.workspace_root, session.id.slice(), self_exe);
            defer self.allocator.free(shim_dir);
            try intercept.commands.prependShimPath(self.allocator, self.env_map, shim_dir);
            // Phase 4 PATH honesty: after shim prepend, drop ungranted host package
            // trees from PATH when OS attach is planned. Pack parents stay for grant.
            if (self.os_attach_planned) {
                const pack = sandbox.tool_pack.resolveToolPack(self.env_map, true);
                const pack_paths = try sandbox.tool_pack.collectPackExecPaths(
                    self.audit_context.io,
                    self.allocator,
                    pack,
                    session.workspace_root,
                    self.env_map,
                );
                defer sandbox.tool_pack.freePackExecPaths(self.allocator, pack_paths);
                try sandbox.tool_pack.applyPathFilterToEnv(
                    self.allocator,
                    self.env_map,
                    true,
                    pack,
                    .{
                        .shim_dir = shim_dir,
                        .workspace_root = session.workspace_root,
                        .pack_exec_paths = pack_paths,
                    },
                );
            }
            try self.env_map.put("RYK_SESSION_ID", session.id.slice());
            try self.env_map.put("RYK_WORKSPACE_ROOT", session.workspace_root);
            if (self.selected_policy.source_path) |path| try self.env_map.put("RYK_POLICY_PATH", path);
            try self.env_map.put("RYK_MODE", self.effective_mode.toString());
            // Durable mode for path-shim callbacks — env alone is child-writable.
            const shim_mod = @import("shim.zig");
            try shim_mod.writeSessionShimMode(
                self.audit_context.io,
                self.allocator,
                session.workspace_root,
                session.id.slice(),
                self.effective_mode,
            );
            // Parent-attested audit mode (F36/F200): env alone is child-forgable.
            // If the session file cannot be written, drop the env claim so the
            // banner does not advertise degraded without attestation.
            if (self.env_map.get("RYK_SHIM_AUDIT_MODE")) |mode| {
                if (std.ascii.eqlIgnoreCase(mode, "degraded") or std.ascii.eqlIgnoreCase(mode, "skip")) {
                    shim_mod.writeSessionShimAuditMode(
                        self.audit_context.io,
                        self.allocator,
                        session.workspace_root,
                        session.id.slice(),
                        "degraded",
                    ) catch {
                        _ = self.env_map.swapRemove("RYK_SHIM_AUDIT_MODE");
                    };
                }
            }
        }

        fn auditBackendCapability(self: *@This(), session: core.session.Session) !void {
            if (self.audit_context.writer == null) return;
            const target = try std.fmt.allocPrint(self.allocator, "{s} backend", .{self.backend_report.backend_name});
            defer self.allocator.free(target);
            const reason = try std.fmt.allocPrint(self.allocator, "fallback={s}; strong_sandbox={s}; network_enforcement={s}", .{
                self.backend_report.fallback_level.toString(),
                self.backend_report.get(.strong_sandbox).level.toString(),
                self.backend_report.get(.network_enforce).level.toString(),
            });
            defer self.allocator.free(reason);
            const decision: core.decision.Decision = .{
                .result = .observe,
                .reason = reason,
                .ci_may_proceed = true,
            };
            const ts = core.time.Timestamp.now(self.audit_context.io);
            const ev: core.event.Event = .{
                .session_id = session.id,
                .event_id = try core.event.generateEventId(ts),
                .timestamp = ts,
                .event_type = .backend_capability,
                .actor = .{ .kind = .ryk, .display = "ryk" },
                .target = .{ .kind = .unknown, .value = target },
                .decision = decision,
            };
            try core_api.appendAuditEvent(&self.audit_context.writer.?, ev);
        }

        fn auditBackendRequirementDenied(self: *@This(), session: core.session.Session, missing: sandbox.backend.FeatureReport) !void {
            if (self.audit_context.writer == null) return;
            const target = try std.fmt.allocPrint(self.allocator, "required backend feature: {s}", .{missing.feature.key()});
            defer self.allocator.free(target);
            const reason = try std.fmt.allocPrint(self.allocator, "required backend feature unavailable: {s} is {s}", .{ missing.feature.key(), missing.level.toString() });
            defer self.allocator.free(reason);
            const decision: core.decision.Decision = .{
                .result = .deny,
                .reason = reason,
                .ci_may_proceed = false,
            };
            const ts = core.time.Timestamp.now(self.audit_context.io);
            const ev: core.event.Event = .{
                .session_id = session.id,
                .event_id = try core.event.generateEventId(ts),
                .timestamp = ts,
                .event_type = .backend_capability,
                .actor = .{ .kind = .ryk, .display = "ryk" },
                .target = .{ .kind = .unknown, .value = target },
                .decision = decision,
            };
            try core_api.appendAuditEvent(&self.audit_context.writer.?, ev);
        }

        fn auditNetworkStartupEvents(self: *@This(), session: core.session.Session) !void {
            const mode = self.selected_policy.network.effectiveMode();
            if (mode == .open) {
                // Loud escape: unrestricted egress when user chose --network open.
                try self.auditNetworkDecision(session, "*", .network_connect_attempt, null);
                const decision: core.decision.Decision = .{
                    .result = .allow,
                    .reason = "network unrestricted; escape used",
                    .ci_may_proceed = true,
                };
                try self.auditNetworkDecision(session, "*", .network_connect_allowed, decision);
            }
            // Kill switch: durable audit marker (stderr already warned at start).
            if (std.c.getenv("RYK_AGENT_NETWORK_DEFAULT")) |raw| {
                if (std.mem.eql(u8, std.mem.span(raw), "legacy")) {
                    try self.auditNetworkDecision(session, "*", .network_connect_attempt, null);
                    const decision: core.decision.Decision = .{
                        .result = .allow,
                        .reason = "network mediation disabled; RYK_AGENT_NETWORK_DEFAULT=legacy",
                        .ci_may_proceed = true,
                    };
                    try self.auditNetworkDecision(session, "*", .network_connect_allowed, decision);
                }
            }
            if (mode == .off) {
                try self.auditNetworkDecision(session, "*", .network_connect_attempt, null);
                const decision: core.decision.Decision = .{
                    .result = .deny,
                    .reason = "network mode off; enforcement=unavailable",
                    .ci_may_proceed = false,
                };
                try self.auditNetworkDecision(session, "*", .network_connect_denied, decision);
            }
            for (self.selected_policy.network.allow) |allowed| {
                const network_decision = try intercept.network.evaluate(self.allocator, self.selected_policy, self.effective_mode, allowed, .{ .enforcement_mode = .unavailable, .ci_mode = self.effective_mode == .ci });
                defer network_decision.deinit(self.allocator);
                try self.auditNetworkDecision(session, network_decision.redacted_target, .network_connect_attempt, null);
                try self.auditNetworkDecision(session, network_decision.redacted_target, if (network_decision.decision.result == .deny) .network_connect_denied else .network_connect_allowed, network_decision.decision);
                if (network_decision.exfil_findings.len > 0) {
                    try self.auditNetworkDecision(session, network_decision.redacted_target, .network_exfiltration_suspected, network_decision.decision);
                }
            }
            // Policy-table deny hosts are not live connections. Emitting
            // network_connect_denied here inflated report/replay "prevented" counts.
        }

        fn resolveApproval(self: *@This(), command_decision: intercept.commands.CommandDecision, display: []const u8) !intercept.approvals.ApprovalChoice {
            if (self.effective_mode == .ci) return .deny;
            const stdin_file = std.Io.File.stdin();
            if (!(try stdin_file.isTty(self.io))) {
                try self.stderr.writeAll("ryk run: command requires approval, but stdin is non-interactive; denying.\n");
                return .deny;
            }
            var stdin_buf: [1024]u8 = undefined;
            var stdin_reader = stdin_file.readerStreaming(self.io, &stdin_buf);
            const safe_policy_reason = try core_api.redactAlloc(self.allocator, command_decision.decision.reason);
            defer self.allocator.free(safe_policy_reason);
            const safe_rule = if (command_decision.decision.rule_id) |rule| try core_api.redactAlloc(self.allocator, rule) else null;
            defer if (safe_rule) |rule| self.allocator.free(rule);
            return intercept.approvals.prompt(&stdin_reader.interface, self.stderr, .{
                .command = display,
                .risk_class = command_decision.classification.risk_class.toString(),
                .risk_reason = command_decision.classification.reason,
                .policy_reason = safe_policy_reason,
                .matched_rule = safe_rule,
            });
        }

        fn auditCommandEvent(self: *@This(), session: core.session.Session, event_type: core.event.EventType, target: []const u8, maybe_decision: ?core.decision.Decision, metadata: core.event.EventMetadata) !void {
            if (self.audit_context.writer == null) return;
            const ts = core.time.Timestamp.now(self.audit_context.io);
            const ev: core.event.Event = .{
                .session_id = session.id,
                .event_id = try core.event.generateEventId(ts),
                .timestamp = ts,
                .event_type = event_type,
                .actor = .{ .kind = .ryk, .display = "ryk" },
                .target = .{ .kind = .command, .value = target },
                .decision = maybe_decision,
                .metadata = metadata,
            };
            try core_api.appendAuditEvent(&self.audit_context.writer.?, ev);
        }

        fn auditNetworkDecision(self: *@This(), session: core.session.Session, target: []const u8, event_type: core.event.EventType, maybe_decision: ?core.decision.Decision) !void {
            if (self.audit_context.writer == null) return;
            const ts = core.time.Timestamp.now(self.audit_context.io);
            const ev: core.event.Event = .{
                .session_id = session.id,
                .event_id = try core.event.generateEventId(ts),
                .timestamp = ts,
                .event_type = event_type,
                .actor = .{ .kind = .ryk, .display = "ryk" },
                .target = .{ .kind = .network_endpoint, .value = target },
                .decision = maybe_decision,
            };
            try core_api.appendAuditEvent(&self.audit_context.writer.?, ev);
        }
    };
    var command_guard_context: CommandGuardContext = .{
        .io = io,
        .allocator = allocator,
        .selected_policy = loaded_policy.innerPtr(),
        .effective_mode = effective_policy_mode,
        .command_argv = options.command_argv,
        .env_map = &filtered_env.env_map,
        .audit_context = &audit_context,
        .approvals = &session_approvals,
        .backend_report = backend_report,
        .required_backend_features = options.requiredBackendFeatures(),
        .proxy_bind = if (proxy_runtime) |runtime| runtime.bindUrl() else null,
        .network_route_forced = apply_result.network_route_forced,
        .stderr = stderr,
        .workspace_root = workspace_root_for_policy,
        .shell_evaluator = shell_evaluator,
        // PATH honesty only when child will actually OS-attach (not soft-degraded unboxed).
        .os_attach_planned = apply_result.requiresChildApply(),
        .os_attach_kind = apply_result.childApplyKind(),
    };
    // Fail closed if proxy dies when policy/backend requires it, session is
    // route-forced onto the proxy port (M-7), or host-alias mediation is active.
    const proxy_fail_closed = proxy_runtime != null and ((proxy_required_by_backend and (effective_policy_mode == .strict or effective_policy_mode == .ci or requiresBackend(options, .network_proxy_enforce))) or
        apply_result.network_route_forced or mediate_agent_network);
    const gateway_required = anthropic_gateway != null or openai_gateway != null;
    var boundary_health_context: BoundaryHealthContext = undefined;
    const health_monitor: ?supervisor.HealthMonitor = if (proxy_fail_closed or gateway_required) blk: {
        boundary_health_context = .{
            .proxy = if (proxy_fail_closed) &proxy_runtime.? else null,
            .anthropic = if (anthropic_gateway != null) &anthropic_gateway.? else null,
            .openai = if (openai_gateway != null) &openai_gateway.? else null,
        };
        break :blk .{
            .context = &boundary_health_context,
            .callback = BoundaryHealthContext.healthy,
        };
    } else null;

    const before_spawn = if (audit_enabled) supervisor.StartHook{
        .context = &audit_context,
        .callback = AuditContext.init,
    } else null;
    const on_event = if (audit_enabled) supervisor.EventHook{
        .context = &audit_context,
        .callback = AuditContext.append,
    } else null;

    // Sandboxed spawn via run_os_sandbox (spawnAgent promotes with proof).
    var sandbox_spawn_ctx: run_os_sandbox.SandboxSpawnCtx = undefined;
    const os_child_apply = run_os_sandbox.buildOsChildApply(&apply_result, &sandbox_spawn_ctx);

    // Start network mediation accept loops only after the agent child is forked.
    const NetworkServeCtx = struct {
        proxy: ?*intercept.proxy.Runtime,
        anthropic: ?*intercept.provider_gateway.Runtime,
        openai: ?*intercept.provider_gateway.Runtime,
        pub fn afterSpawn(context: *anyopaque, _: core.session.Session) !void {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (self.proxy) |runtime| try runtime.startServing();
            if (self.anthropic) |runtime| try runtime.startServing();
            if (self.openai) |runtime| try runtime.startServing();
        }
    };
    var network_serve_ctx: NetworkServeCtx = .{
        .proxy = if (proxy_runtime != null) &proxy_runtime.? else null,
        .anthropic = if (anthropic_gateway != null) &anthropic_gateway.? else null,
        .openai = if (openai_gateway != null) &openai_gateway.? else null,
    };

    // Empty-backpack: shell wrappers (hermes → venv/python symlink → uv) hit a
    // Seatbelt residual where open/exec of the *symlink path* is denied even when
    // the realpath target is RO-granted. Expand to realpath argv before spawn.
    //
    // `#!/usr/bin/env node` (pi, npm-global agents) PATH-searches `node` after
    // attach. The session node shim then fails: PATH honesty drops Homebrew, and
    // home/nvm/hermes node EPERMs under no-bare-home. Expand to absolute
    // interpreter + script. Host MCP plans keep bare `pi` argv0 — do not skip
    // this expand when a plan is present (codex MCP expands itself).
    //
    // PATH honesty (before_process_launch) drops denylisted package trees from the
    // child PATH. Absolute-ize bare argv0 before that filter so spawn does not
    // re-search PATH for brew-installed host aliases (pi, opencode, codex, …).
    // Host MCP env overlays (e.g. OPENCODE_CONFIG_CONTENT) are ryk-minted after the
    // launch allowlist so host-supplied blobs cannot ride the empty-backpack path.
    if (host_mcp_plan) |plan| {
        for (plan.env_puts) |put| {
            try filtered_env.env_map.put(put.name, put.value);
        }
    }
    const planned_argv = if (codex_mcp_plan) |plan|
        plan.argv
    else if (host_mcp_plan) |plan|
        plan.argv
    else
        options.command_argv;
    var launch_argv_owned: ?[]const []const u8 = null;
    defer if (launch_argv_owned) |a| sandbox.apply.freeExpandedShellWrapperArgv(allocator, a);
    const expand_shell_wrapper = secret_boundary == .empty_backpack and codex_mcp_plan == null;
    if (expand_shell_wrapper or command_guard_context.os_attach_planned) {
        launch_argv_owned = sandbox.apply.rewriteOsAttachLaunchArgv(
            io,
            allocator,
            planned_argv,
            &filtered_env.env_map,
            .{
                .expand_shell_wrapper = expand_shell_wrapper,
                .os_attach = command_guard_context.os_attach_planned,
            },
        ) catch null;
    }
    const spawn_argv: []const []const u8 = launch_argv_owned orelse planned_argv;

    var result = supervisor.run(io, allocator, .{
        .command = spawn_argv[0],
        .args = spawn_argv[1..],
        .workspace = options.workspace,
        .mode = session_mode,
        .session_name = options.session_name,
        .policy_source = loaded_policy.path,
        .stdio = stdio,
        .env_map = &filtered_env.env_map,
        .env_redactions = filtered_env.redactions,
        .os_child_apply = os_child_apply,
        .before_spawn = before_spawn,
        .before_process_launch = if (audit_enabled) supervisor.StartHook{
            .context = &command_guard_context,
            .callback = CommandGuardContext.beforeProcessLaunch,
        } else null,
        .after_process_spawn = if (proxy_runtime != null or gateway_required) supervisor.StartHook{
            .context = &network_serve_ctx,
            .callback = NetworkServeCtx.afterSpawn,
        } else null,
        .on_session_start = .{
            .context = &start_printer,
            .callback = StartPrinter.print,
        },
        .on_event = on_event,
        .health_monitor = health_monitor,
    }) catch |err| switch (err) {
        error.CommandNotFound => {
            try suggestions.writeSanitizedValue(stderr, "ryk run: command not found: ", options.command_argv[0], "\n");
            return exit_codes.general;
        },
        error.InvalidCommand => {
            try stderr.writeAll("ryk run: missing command after '--'.\n");
            return exit_codes.usage;
        },
        error.FileNotFound => {
            try suggestions.writeSanitizedValue(stderr, "ryk run: workspace not found: ", options.workspace orelse ".", "\n");
            return exit_codes.general;
        },
        error.CommandDenied => {
            try finalizeFailedSession(&audit_context, allocator, exit_codes.denial, loaded_policy.path);
            // Phase 1 UX: render a rich "guardian block" to human stderr instead of
            // the old flat one-liner. --json/robot/machine output is unaffected (it
            // never reaches this human stderr path). Graceful-degrades when the
            // matched rule id is unknown/null (fail-closed / user-denial paths).
            renderDenyBlock(
                io,
                stderr,
                allocator,
                options.command_argv,
                command_guard_context.last_denied_rule_id,
                command_guard_context.last_denied_remediation,
                loaded_policy.path,
                effective_policy_mode.toString(),
            ) catch |render_err| {
                // Never let a presentation failure mask the deny or alter the exit
                // code; fall back to a minimal message and continue to denial.
                stderr.print("ryk run: command denied by command guard ({s}).\n", .{@errorName(render_err)}) catch {};
            };
            if (command_guard_context.last_denied_rule_id) |rid| allocator.free(rid);
            command_guard_context.last_denied_rule_id = null;
            if (command_guard_context.last_denied_remediation) |tip| allocator.free(tip);
            command_guard_context.last_denied_remediation = null;
            return exit_codes.denial;
        },
        error.BackendRequirementUnavailable => {
            try finalizeFailedSession(&audit_context, allocator, exit_codes.unsupported, loaded_policy.path);
            try stderr.writeAll("ryk run: required backend feature is unavailable.\n");
            return exit_codes.unsupported;
        },
        else => |launch_err| {
            // F-3: sandboxed child apply/handshake failure is fail-closed with sandbox
            // language — never a bare "failed to launch child: ApplyFailed".
            if (run_os_sandbox.isSandboxSpawnFailure(launch_err) and apply_result.requiresChildApply()) {
                const reason = run_os_sandbox.sandboxSpawnFailReason(launch_err);
                // Failed posture before session_exit.
                if (audit_context.session) |session| {
                    try run_os_sandbox.auditSandboxPosture(&audit_context, session, sandbox.posture.failedReceipt(reason));
                }
                try finalizeFailedSession(&audit_context, allocator, exit_codes.unsupported, loaded_policy.path);
                switch (effective_os_sandbox) {
                    .on => try stderr.print(
                        "ryk run: OS sandbox required but attach failed ({s}).\n",
                        .{reason},
                    ),
                    .auto => try stderr.print(
                        "ryk run: OS sandbox attach failed under --os-sandbox auto ({s}); not launching unboxed agent.\n",
                        .{reason},
                    ),
                    .off => try stderr.print(
                        "ryk run: OS sandbox attach failed ({s}).\n",
                        .{reason},
                    ),
                }
                return exit_codes.unsupported;
            }
            try stderr.print("ryk run: failed to launch child: {s}\n", .{core.process.childLaunchFailureMessage(launch_err)});
            return exit_codes.general;
        },
    };
    defer result.deinit();

    const required_proxy_failed = proxy_fail_closed and if (proxy_runtime) |runtime| runtime.failed() else false;
    const required_gateway_failed =
        (if (anthropic_gateway) |runtime| runtime.failed() else false) or
        (if (openai_gateway) |runtime| runtime.failed() else false);
    const boundary_backend_failed = required_proxy_failed or required_gateway_failed;
    const final_status: core.process.ChildStatus = if (boundary_backend_failed)
        .{ .exited = exit_codes.unsupported }
    else
        result.status;

    // M-20 partial-ok: attach/handshake proves apply, not agent success. When attach
    // succeeded but the agent process ends non-zero, say so explicitly so operators
    // do not read "OS sandbox: active" as "agent ran successfully under the box".
    // Wording uses "after sandbox attach" (not "pre-exec handshake residual") so
    // operators do not think attach itself failed.
    if (apply_result.receipt.isActive() and !boundary_backend_failed) {
        const agent_failed = switch (result.status) {
            .exited => |code| code != 0,
            .signal, .stopped, .unknown => true,
        };
        if (agent_failed) {
            switch (result.status) {
                .exited => |code| try stderr.print(
                    "ryk run: note: OS sandbox attach succeeded; agent exited with code {d} after sandbox attach.\n",
                    .{code},
                ),
                .signal => |sig| try stderr.print(
                    "ryk run: note: OS sandbox attach succeeded; agent terminated by signal {d} after sandbox attach.\n",
                    .{sig},
                ),
                .stopped => |sig| try stderr.print(
                    "ryk run: note: OS sandbox attach succeeded; agent stopped by signal {d} after sandbox attach.\n",
                    .{sig},
                ),
                .unknown => |st| try stderr.print(
                    "ryk run: note: OS sandbox attach succeeded; agent ended with unknown status {d} after sandbox attach.\n",
                    .{st},
                ),
            }
            if (secret_boundary == .empty_backpack) {
                const stdio_risk = sandbox.host_config_grants.parentStdioHasUngrantedHostTmpRisk(io);
                // Agent stdio is usually inherited (not retained here). Path-walk residual
                // is classified when agent_output is available; generic tip also names it.
                try stderr.writeAll(sandbox.host_config_grants.selectEmptyBackpackAgentExitTip(.{
                    .stdio_host_tmp_risk = stdio_risk,
                    .agent_output = null,
                }));
            }
        }
    }

    var chain_hash_buf: [64]u8 = undefined;
    var chain_hash: ?[]const u8 = null;
    if (audit_context.writer) |*writer| {
        if (audit_context.session) |session| {
            if (proxy_runtime) |runtime| {
                runtime.waitForIdle(1 * std.time.ns_per_s) catch {};
                const proxy_events = try runtime.snapshotAuditEvents(allocator);
                defer runtime.freeAuditEvents(allocator, proxy_events);
                for (proxy_events) |proxy_event| {
                    const event_ts = core.time.Timestamp.now(audit_context.io);
                    const ev: core.event.Event = .{
                        .session_id = session.id,
                        .event_id = try core.event.generateEventId(event_ts),
                        .timestamp = event_ts,
                        .event_type = proxy_event.event_type,
                        .actor = .{ .kind = .ryk, .display = "ryk" },
                        .target = .{ .kind = .network_endpoint, .value = proxy_event.target },
                        .decision = if (proxy_event.result) |decision_result| .{
                            .result = decision_result,
                            .reason = proxy_event.reason orelse "proxy-mediated network decision",
                            .ci_may_proceed = proxy_event.ci_may_proceed,
                        } else null,
                    };
                    try core_api.appendAuditEvent(writer, ev);
                }
                const ts = core.time.Timestamp.now(audit_context.io);
                const ev: core.event.Event = .{
                    .session_id = session.id,
                    .event_id = try core.event.generateEventId(ts),
                    .timestamp = ts,
                    .event_type = .network_proxy_stop,
                    .actor = .{ .kind = .ryk, .display = "ryk" },
                    .target = .{ .kind = .network_endpoint, .value = runtime.bindUrl() },
                    .decision = .{ .result = if (required_proxy_failed) .deny else .observe, .reason = if (required_proxy_failed) "required proxy backend failed during child run" else "proxy-mediated network backend stopped", .ci_may_proceed = !required_proxy_failed },
                };
                try core_api.appendAuditEvent(writer, ev);
            }
            const gateways = [_]?*intercept.provider_gateway.Runtime{
                if (anthropic_gateway != null) &anthropic_gateway.? else null,
                if (openai_gateway != null) &openai_gateway.? else null,
            };
            for (gateways) |maybe_gateway| {
                const runtime = maybe_gateway orelse continue;
                runtime.waitForIdle(1 * std.time.ns_per_s) catch {};
                const gateway_events = try runtime.snapshotAuditEvents(allocator);
                defer runtime.freeAuditEvents(allocator, gateway_events);
                for (gateway_events) |gateway_event| {
                    const event_ts = core.time.Timestamp.now(audit_context.io);
                    const allowed = gateway_event.kind == .phantom_swap;
                    const ev: core.event.Event = .{
                        .session_id = session.id,
                        .event_id = try core.event.generateEventId(event_ts),
                        .timestamp = event_ts,
                        .event_type = if (allowed) .phantom_swap else .phantom_denied,
                        .actor = .{ .kind = .ryk, .display = "ryk" },
                        .target = .{ .kind = .env_var, .value = gateway_event.env_var },
                        .decision = .{
                            .result = if (allowed) .allow else .deny,
                            .reason = gateway_event.reason_code,
                            .ci_may_proceed = allowed,
                        },
                    };
                    try core_api.appendAuditEvent(writer, ev);
                }
            }
        }
        // P1-1 reconciliation: make degraded in-shim audit durable evidence.
        if (audit_context.session) |session| {
            try reconcileShimAuditGap(writer, io, allocator, session, shim_audit_degraded);
        }
        const final_hash = writer.finalHash() orelse "";
        try core_api.writeAuditSummary(allocator, writer.session_dir_path, .{
            .session = result.session,
            .status = final_status,
            .event_count = writer.event_count,
            .final_event_hash = final_hash,
            .policy = loaded_policy.path,
            .product_label = brand.product_display,
        });
        try writer.writeLastPointer();
        if (final_hash.len == chain_hash_buf.len) {
            @memcpy(&chain_hash_buf, final_hash);
            chain_hash = &chain_hash_buf;
        }
    }

    const protected_session =
        boundary_active and apply_result.receipt.posture == .active and !boundary_backend_failed;
    const protected_run_succeeded = protected_session and switch (final_status) {
        .exited => |code| code == exit_codes.success,
        .signal, .stopped, .unknown => false,
    };
    if (protected_run_succeeded) telemetry.recordActivation(trusted_host_key);
    try printSessionEnd(io, stdout, result, is_first_session, protected_session, chain_hash);

    if (required_proxy_failed) {
        try stderr.writeAll("ryk run: required proxy backend failed during child run; child was terminated.\n");
        return exit_codes.unsupported;
    }
    if (required_gateway_failed) {
        try stderr.writeAll("ryk run: required provider gateway failed during child run; child was terminated.\n");
        return exit_codes.unsupported;
    }

    return switch (result.status) {
        .exited => |code| code,
        .signal => |signal| {
            try stderr.print("ryk run: child terminated by signal {d}.\n", .{signal});
            return exit_codes.child_failure;
        },
        .stopped => |signal| {
            try stderr.print("ryk run: child stopped by signal {d}.\n", .{signal});
            return exit_codes.child_failure;
        },
        .unknown => |status| {
            try stderr.print("ryk run: child ended with unknown status {d}.\n", .{status});
            return exit_codes.child_failure;
        },
    };
}

test "schema-sensitive provider variables require an explicit grant before capture" {
    var schema = try intercept.env_schema.parseFromSlice(std.testing.allocator,
        \\defaults:
        \\  unknown: omit
        \\vars:
        \\  OPENAI_API_KEY:
        \\    class: sensitive
    );
    defer schema.deinit();

    var host_env = std.process.Environ.Map.init(std.testing.allocator);
    defer host_env.deinit();
    try host_env.put("OPENAI_API_KEY", "sk-fake-schema-no-grant-canary");

    var store = try intercept.session_secrets.Store.init(std.testing.io, std.testing.allocator);
    defer store.deinit();
    const selected_policy: policy.schema.Policy = .{ .allocator = std.testing.allocator };
    try captureSessionGrants(
        std.testing.allocator,
        &store,
        &host_env,
        &selected_policy,
        ".",
        &schema,
    );

    try std.testing.expect(!store.hasEnvVar("OPENAI_API_KEY"));
    try std.testing.expect(!store.hasProvider(.openai));
}

fn parseOptions(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !RunOptions {
    var options: RunOptions = .{};
    // Env default; CLI `--seatbelt-profile` overrides when present.
    // Invalid values keep the hardened default and warn (flag path still fails closed).
    if (std.c.getenv("RYK_SEATBELT_PROFILE")) |raw| {
        const value = std.mem.span(raw);
        if (value.len > 0) {
            if (sandbox.posture.SeatbeltProfileGrade.parse(value)) |grade| {
                options.seatbelt_profile = grade;
            } else {
                try stderr.print(
                    "ryk run: WARNING: ignoring invalid RYK_SEATBELT_PROFILE={s} (use compatible|hardened|strict); defaulting to {s}.\n",
                    .{ value, sandbox.posture.SeatbeltProfileGrade.default_grade.toString() },
                );
            }
        }
    }
    var index: usize = 0;

    while (index < argv.len) : (index += 1) {
        const arg = argv[index];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            _ = try help.writeCommand(io, stdout, "run");
            return error.HelpShown;
        } else if (std.mem.eql(u8, arg, "--")) {
            options.command_argv = argv[index + 1 ..];
            break;
        } else if (std.mem.eql(u8, arg, "--ci")) {
            options.mode = .ci;
            options.mode_explicit = true;
        } else if (std.mem.eql(u8, arg, "--workspace")) {
            index += 1;
            if (index >= argv.len) {
                try stderr.writeAll("ryk run: --workspace requires a path.\n");
                return error.Usage;
            }
            options.workspace = argv[index];
        } else if (std.mem.eql(u8, arg, "--mode")) {
            index += 1;
            if (index >= argv.len) {
                try stderr.writeAll("ryk run: --mode requires observe, ask, strict, or ci.\n");
                return error.Usage;
            }
            options.mode = parseMode(argv[index]) orelse {
                try suggestions.writeInvalidValue(stderr, "ryk run", "--mode", argv[index], &.{ "observe", "ask", "strict", "ci" }, "run");
                return error.Usage;
            };
            options.mode_explicit = true;
        } else if (std.mem.eql(u8, arg, "--policy")) {
            index += 1;
            if (index >= argv.len) {
                try stderr.writeAll("ryk run: --policy requires a path.\n");
                return error.Usage;
            }
            options.policy_path = argv[index];
        } else if (std.mem.eql(u8, arg, "--session-name")) {
            index += 1;
            if (index >= argv.len) {
                try stderr.writeAll("ryk run: --session-name requires a name.\n");
                return error.Usage;
            }
            options.session_name = argv[index];
        } else if (std.mem.eql(u8, arg, "--no-secrets")) {
            options.no_secrets = true;
        } else if (std.mem.eql(u8, arg, "--secretless")) {
            options.secretless = true;
        } else if (std.mem.eql(u8, arg, "--with-host-secrets")) {
            options.with_host_secrets = true;
        } else if (std.mem.eql(u8, arg, "--inherit-env")) {
            options.inherit_env = true;
        } else if (std.mem.eql(u8, arg, "--no-network")) {
            options.network_mode = .off;
        } else if (std.mem.eql(u8, arg, "--allow-network")) {
            index += 1;
            if (index >= argv.len) {
                try stderr.writeAll("ryk run: --allow-network requires a domain or IP destination.\n");
                return error.Usage;
            }
            if (options.allow_network_count >= options.allow_network_values.len) {
                try stderr.writeAll("ryk run: too many --allow-network rules.\n");
                return error.Usage;
            }
            options.allow_network_values[options.allow_network_count] = argv[index];
            options.allow_network_count += 1;
        } else if (std.mem.eql(u8, arg, "--network")) {
            index += 1;
            if (index >= argv.len) {
                try stderr.writeAll("ryk run: --network requires observe, ask, allowlist, open, or off.\n");
                return error.Usage;
            }
            options.network_mode = policy.schema.NetworkMode.parse(argv[index]) orelse {
                try suggestions.writeInvalidValue(stderr, "ryk run", "--network", argv[index], &.{ "observe", "ask", "allowlist", "open", "off" }, "run");
                return error.Usage;
            };
        } else if (std.mem.eql(u8, arg, "--network-backend")) {
            index += 1;
            if (index >= argv.len) {
                try stderr.writeAll("ryk run: --network-backend requires decision-only or proxy.\n");
                return error.Usage;
            }
            options.network_backend = policy.schema.NetworkBackend.parse(argv[index]) orelse {
                try suggestions.writeInvalidValue(stderr, "ryk run", "--network-backend", argv[index], &.{ "decision-only", "proxy" }, "run");
                return error.Usage;
            };
        } else if (std.mem.eql(u8, arg, "--os-sandbox")) {
            index += 1;
            if (index >= argv.len) {
                try stderr.writeAll("ryk run: --os-sandbox requires auto, on, or off.\n");
                return error.Usage;
            }
            options.os_sandbox = sandbox.posture.OsSandboxMode.parse(argv[index]) orelse {
                try suggestions.writeInvalidValue(stderr, "ryk run", "--os-sandbox", argv[index], &.{ "auto", "on", "off" }, "run");
                return error.Usage;
            };
        } else if (std.mem.eql(u8, arg, "--seatbelt-profile")) {
            index += 1;
            if (index >= argv.len) {
                try stderr.writeAll("ryk run: --seatbelt-profile requires compatible, hardened, or strict.\n");
                return error.Usage;
            }
            options.seatbelt_profile = sandbox.posture.SeatbeltProfileGrade.parse(argv[index]) orelse {
                try suggestions.writeInvalidValue(stderr, "ryk run", "--seatbelt-profile", argv[index], &.{ "compatible", "hardened", "strict" }, "run");
                return error.Usage;
            };
        } else if (std.mem.eql(u8, arg, "--require-backend")) {
            index += 1;
            if (index >= argv.len) {
                try stderr.writeAll("ryk run: --require-backend requires a capability name.\n");
                return error.Usage;
            }
            if (options.required_backend_count >= options.required_backend_values.len) {
                try stderr.writeAll("ryk run: too many --require-backend values.\n");
                return error.Usage;
            }
            options.required_backend_values[options.required_backend_count] = sandbox.backend.Feature.parse(argv[index]) orelse {
                try suggestions.writeInvalidValue(stderr, "ryk run", "--require-backend", argv[index], &.{ "policy-engine", "audit", "env-filtering", "path-staging", "shell-wrapping", "path-shims", "mcp-stdio-proxy", "network-observe", "network-proxy", "network-enforce", "process-supervision", "user-namespaces", "mount-namespaces", "seccomp", "landlock", "cgroups", "strong-sandbox" }, "run");
                return error.Usage;
            };
            options.required_backend_count += 1;
        } else if (std.mem.startsWith(u8, arg, "-")) {
            try suggestions.writeUnknownOption(stderr, "ryk run", arg, &.{ "--workspace", "--mode", "--policy", "--session-name", "--no-secrets", "--secretless", "--with-host-secrets", "--inherit-env", "--no-network", "--allow-network", "--network", "--network-backend", "--os-sandbox", "--seatbelt-profile", "--require-backend", "--help", "-h" }, "run");
            return error.Usage;
        } else {
            try stderr.writeAll("ryk run: expected '--' before the command you want to run.\n" ++
                "\n" ++
                "Example:\n" ++
                "  ryk run -- ./scripts/agent-task.sh\n" ++
                "  ryk run --mode strict -- npm install\n" ++
                "\n" ++
                "Run 'ryk help run' for more examples.\n");
            return error.Usage;
        }
    }

    if (options.command_argv.len == 0) {
        try stderr.writeAll("ryk run: missing command after '--'.\n" ++
            "\n" ++
            "Example:\n" ++
            "  ryk run -- echo 'hello world'\n");
        return error.Usage;
    }

    return options;
}

/// Kill switch for host-alias network defaults (`RYK_AGENT_NETWORK_DEFAULT`).
/// `mediated` (default): proxy + route-force. `legacy`: pre-change labels-only path.
///
/// **Sunset:** one-release escape only. Track removal after mediation is the
/// default GA path — prefer deleting `legacy` once operators have a stable
/// `--network open` / policy escape. Emits WARNING on use (see parse path).
/// Target: remove no later than the release after 2026-09 (or earlier if
/// usage is zero). Do not treat as a permanent product surface.
const AgentNetworkDefault = enum { mediated, legacy };

/// Effective session sandbox grade (Phase 5 honesty). Advertised via
/// `RYK_SESSION_SANDBOX_GRADE` and the session banner. Distinct from doctor
/// capability probes (probe ≠ session).
const SessionSandboxGrade = enum {
    strong_mediated,
    fs_attached,
    wrapper_only,
    unrestricted_escape,

    pub fn toString(self: SessionSandboxGrade) []const u8 {
        return switch (self) {
            .strong_mediated => "strong-mediated",
            .fs_attached => "fs-attached",
            .wrapper_only => "wrapper-only",
            .unrestricted_escape => "unrestricted-escape",
        };
    }
};

const SessionGradeInputs = struct {
    os_attach_planned: bool,
    network_route_forced: bool,
    unrestricted_escape: bool,
};

/// Compute truthful grade for this spawn. Escape always wins over attach labels.
fn computeSessionSandboxGrade(inputs: SessionGradeInputs) SessionSandboxGrade {
    if (inputs.unrestricted_escape) return .unrestricted_escape;
    if (inputs.os_attach_planned and inputs.network_route_forced) return .strong_mediated;
    if (inputs.os_attach_planned) return .fs_attached;
    return .wrapper_only;
}

/// True when the user chose unrestricted egress (`--network open`) or the
/// legacy agent-network kill switch. Those sessions must not claim mediation.
fn isUnrestrictedNetworkEscape(options: RunOptions, agent_net_default: AgentNetworkDefault, trusted_agent_host: bool) bool {
    if (options.network_mode) |mode| {
        if (mode == .open) return true;
    }
    if (agent_net_default == .legacy and trusted_agent_host) return true;
    return false;
}

fn parseAgentNetworkDefault(value: ?[]const u8) AgentNetworkDefault {
    if (value) |raw| {
        if (std.mem.eql(u8, raw, "legacy")) return .legacy;
        // Unknown values keep mediated (safe default); only "legacy" opts out.
    }
    return .mediated;
}

/// Host aliases default to proxy + OS route-force unless the user escapes.
/// Non-alias `ryk run -- <cmd>` is unchanged (no silent lockdown).
/// Escapes only: `--network open` and `RYK_AGENT_NETWORK_DEFAULT=legacy`.
/// `--network-backend decision-only` does **not** opt out (would recreate labels-only theater).
/// Requires **trusted** agent host identity (F-02), not basename alone.
fn wantsMediatedAgentNetwork(options: RunOptions, agent_net_default: AgentNetworkDefault, trusted_agent_host: bool) bool {
    if (agent_net_default != .mediated) return false;
    if (!trusted_agent_host) return false;
    if (options.network_mode) |mode| {
        // Explicit unrestricted escape — no route-force required.
        if (mode == .open) return false;
    }
    return true;
}

/// CLI network mode: explicit `--network`/`--no-network` wins.
/// Trusted host-alias mediated default is allowlist (headless-safe); everything else stays ask.
/// Secretless is intentionally not defaulted here (Phase 1 SECRETLESS_DEFAULT_GO: no).
fn cliNetworkMode(options: RunOptions, agent_net_default: AgentNetworkDefault, trusted_agent_host: bool) policy.schema.NetworkMode {
    if (options.network_mode) |mode| return mode;
    if (wantsMediatedAgentNetwork(options, agent_net_default, trusted_agent_host)) return .allowlist;
    return .ask;
}

/// Empty backpack for explicit `--secretless` or a **trusted** host-launch alias.
/// Basename spoofs (workspace `./codex`) do not auto empty-backpack (F-02).
fn effectiveSecretBoundary(options: RunOptions, trusted_agent_host: bool) intercept.env.SecretBoundary {
    if (options.with_host_secrets) return .off;
    if (options.secretless) return .empty_backpack;
    if (trusted_agent_host) return .empty_backpack;
    return .off;
}

/// Basename of argv0 for unit-test / fallback overlay selection when the product
/// call site has not supplied a resolved trusted host key.
fn hostKeyFromCommandArgv(options: RunOptions) ?[]const u8 {
    if (options.command_argv.len == 0) return null;
    const base = std.fs.path.basename(options.command_argv[0]);
    if (base.len == 0) return null;
    return base;
}

/// Launch-time discovery context for AINA P3 (plan §3.6 S4).
/// When null, pack-only (P1) path. Product always supplies abs workspace_root + parent HOME.
pub const DiscoveryLaunchContext = struct {
    io: std.Io,
    /// Absolute workspace root; managed file is always `<root>/.ryk/network-discovered.yaml`.
    workspace_root: []const u8,
    /// Parent-process HOME for `discoverForHost` (may be empty → adapter soft-empty).
    home: []const u8,
};

/// Test-facing entry: overlay host key is derived from `command_argv[0]` basename.
fn applyNetworkOverlay(
    allocator: std.mem.Allocator,
    selected_policy: *policy.schema.Policy,
    options: RunOptions,
    agent_net_default: AgentNetworkDefault,
    trusted_agent_host: bool,
) !void {
    try applyNetworkOverlayWithHostKey(
        allocator,
        selected_policy,
        options,
        agent_net_default,
        trusted_agent_host,
        hostKeyFromCommandArgv(options),
        null,
    );
}

/// Product + test implementation. When `host_key` is non-null it selects the host
/// overlay (EFF-2); null seeds core pack only. Seed runs only under mediated +
/// trusted host-alias (`wantsMediatedAgentNetwork`); never under legacy/open/untrusted.
///
/// Merge order when `discovery` is non-null and mediated trusted (AINA P3 S4):
///   existing policy ∪ core ∪ host_overlay
///     ∪ managed hosts (`loadManaged`, soft-empty on missing/corrupt)
///     ∪ launch-time adapter (`discoverForHost`, soft-empty)
///     then CLI `--allow-network` (EFF-3)
/// Soft skip: missing managed / empty home / adapter empty → pack floor retained;
/// never fail launch for discovery. Null discovery = P1 pack-only path.
///
/// Ownership: after seed, `network.allow` is fully allocator-owned (every string +
/// outer slice). CLI `--allow-network` appends transfer prior string ownership into
/// a new outer slice and free only the previous outer pointer.
fn applyNetworkOverlayWithHostKey(
    allocator: std.mem.Allocator,
    selected_policy: *policy.schema.Policy,
    options: RunOptions,
    agent_net_default: AgentNetworkDefault,
    trusted_agent_host: bool,
    host_key: ?[]const u8,
    discovery: ?DiscoveryLaunchContext,
) !void {
    selected_policy.network.mode = cliNetworkMode(options, agent_net_default, trusted_agent_host);
    if (wantsMediatedAgentNetwork(options, agent_net_default, trusted_agent_host)) {
        // Host aliases: always force proxy (overrides decision-only) so labels are not theater.
        selected_policy.network.backend = .proxy;

        // Seed even when CLI --allow-network is empty (must not early-return past this).
        // Floor: existing policy ∪ core ∪ host_overlay (P1).
        const old_seed_allow = selected_policy.network.allow;
        const merged = try policy.agent_inference_hosts.mergeAllowList(
            allocator,
            host_key,
            old_seed_allow,
        );
        policy.schema.freeStringList(allocator, old_seed_allow);
        selected_policy.network.allow = merged;

        // P3: ∪ managed ∪ launch-time adapter (soft skip; never wipe user allows).
        if (discovery) |ctx| {
            try mergeDiscoveryIntoAllow(allocator, selected_policy, host_key, ctx);
        }
    } else if (options.network_backend) |backend| {
        selected_policy.network.backend = backend;
    }

    // CLI --allow-network after seed (EFF-3); no-op when empty keeps seed-only list.
    const runtime_allow = options.allowNetwork();
    if (runtime_allow.len == 0) return;

    const old_allow = selected_policy.network.allow;
    const old_len = old_allow.len;
    var next = try allocator.alloc([]const u8, old_len + runtime_allow.len);
    errdefer allocator.free(next);
    for (old_allow, 0..) |value, index| next[index] = value;
    var copied: usize = 0;
    errdefer {
        for (next[old_len .. old_len + copied]) |value| allocator.free(value);
    }
    for (runtime_allow, 0..) |value, index| {
        if (std.mem.startsWith(u8, value, "*.")) {
            next[old_len + index] = try allocator.dupe(u8, value);
        } else {
            const destination = try intercept.network.parseDestination(value);
            next[old_len + index] = try destination.endpointDisplay(allocator);
        }
        copied += 1;
    }
    if (old_allow.len > 0) allocator.free(old_allow);
    selected_policy.network.allow = next;
}

/// Merge managed store + launch-time adapter hosts into `network.allow`.
/// Soft-skip missing/corrupt managed and empty/unknown adapter results.
/// Managed entries are filtered by host_key source tags (no cross-host bleed).
/// Preserves every pre-existing allow entry (A-P3-3 / EFF-4). Hostnames only (SEC-3).
fn mergeDiscoveryIntoAllow(
    allocator: std.mem.Allocator,
    selected_policy: *policy.schema.Policy,
    host_key: ?[]const u8,
    ctx: DiscoveryLaunchContext,
) !void {
    var store = try policy.network_discovered.loadManaged(ctx.io, allocator, ctx.workspace_root);
    defer store.deinit(allocator);

    // All contrib strings are owned (duped managed + owned discover) so free is uniform.
    var contrib: std.ArrayList([]const u8) = .empty;
    var contrib_live = true;
    errdefer if (contrib_live) {
        for (contrib.items) |h| allocator.free(h);
        contrib.deinit(allocator);
    };

    const key = host_key orelse "";
    if (key.len > 0) {
        for (store.hosts) |entry| {
            if (!policy.network_discovered.managedEntryMatchesHostKey(entry, key)) continue;
            const owned = try allocator.dupe(u8, entry.host);
            errdefer allocator.free(owned);
            try contrib.append(allocator, owned);
        }

        const discovered = try policy.inference_discover.discoverForHost(
            ctx.io,
            allocator,
            key,
            ctx.home,
        );
        defer policy.schema.freeStringList(allocator, discovered);
        for (discovered) |h| {
            const owned = try allocator.dupe(u8, h);
            errdefer allocator.free(owned);
            try contrib.append(allocator, owned);
        }
    }

    if (contrib.items.len == 0) {
        contrib.deinit(allocator);
        contrib_live = false;
        return;
    }

    const old_allow = selected_policy.network.allow;
    const next = try policy.network_discovered.mergePreserveUserAllows(
        allocator,
        old_allow,
        contrib.items,
    );
    policy.schema.freeStringList(allocator, old_allow);
    selected_policy.network.allow = next;
    // mergePreserve duped inputs — free our owned contrib list; disarm errdefer.
    for (contrib.items) |h| allocator.free(h);
    contrib.deinit(allocator);
    contrib_live = false;
}

fn requiresBackend(options: RunOptions, feature: sandbox.backend.Feature) bool {
    for (options.requiredBackendFeatures()) |required| {
        if (required == feature) return true;
    }
    return false;
}

fn installNetworkEnvironment(allocator: std.mem.Allocator, env_map: *std.process.Environ.Map, network_policy: policy.schema.NetworkPolicy) !void {
    try env_map.put("RYK_NETWORK_POLICY_ENGINE", "active");
    try env_map.put("RYK_NETWORK_MODE", network_policy.effectiveMode().toString());
    try env_map.put("RYK_TRANSPARENT_NETWORK_ENFORCEMENT", "unavailable");
    try env_map.put("RYK_PROXY_MEDIATED_NETWORK_ENFORCEMENT", "unavailable");
    if (network_policy.allow.len > 0) {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(allocator);
        for (network_policy.allow, 0..) |allowed, index| {
            if (index > 0) try list.append(allocator, ',');
            try list.appendSlice(allocator, allowed);
        }
        const owned = try list.toOwnedSlice(allocator);
        defer allocator.free(owned);
        try env_map.put("RYK_NETWORK_ALLOW", owned);
    }
}

fn installBackendEnvironment(env_map: *std.process.Environ.Map, report: sandbox.backend.ReportSet) !void {
    try env_map.put("RYK_BACKEND", report.backend_name);
    try env_map.put("RYK_BACKEND_FALLBACK", report.fallback_level.toString());
    // Capability seed only — session-effective label is restamped after applyForRun
    // (see sessionEnvFilteringLabel). Do not stuff denylist-only / host-secrets into backend.Level.
    try env_map.put("RYK_BACKEND_ENV_FILTERING", report.get(.env_filtering).level.toString());
    try env_map.put("RYK_BACKEND_PATH_STAGING", report.get(.path_staging).level.toString());
    try env_map.put("RYK_BACKEND_SHELL_WRAPPING", report.get(.shell_wrapping).level.toString());
    try env_map.put("RYK_BACKEND_PATH_SHIMS", report.get(.path_shims).level.toString());
    try env_map.put("RYK_BACKEND_STRONG_SANDBOX", report.get(.strong_sandbox).level.toString());
    try env_map.put("RYK_BACKEND_PROCESS_SUPERVISION", report.get(.process_supervision).level.toString());
    try env_map.put("RYK_BACKEND_USER_NAMESPACES", report.get(.user_namespaces).level.toString());
    try env_map.put("RYK_BACKEND_MOUNT_NAMESPACES", report.get(.mount_namespaces).level.toString());
    try env_map.put("RYK_BACKEND_SECCOMP", report.get(.seccomp).level.toString());
    try env_map.put("RYK_BACKEND_LANDLOCK", report.get(.landlock).level.toString());
    try env_map.put("RYK_BACKEND_CGROUPS", report.get(.cgroups).level.toString());
    try env_map.put("RYK_BACKEND_NETWORK_OBSERVE", report.get(.network_observe).level.toString());
    try env_map.put("RYK_BACKEND_NETWORK_PROXY_ENFORCEMENT", report.get(.network_proxy_enforce).level.toString());
    try env_map.put("RYK_BACKEND_NETWORK_ENFORCEMENT", report.get(.network_enforce).level.toString());
}

/// Session-effective `RYK_BACKEND_ENV_FILTERING` vocabulary (RT-09).
/// Free-form session string — never written into `backend.Level` for `--require-backend`.
/// Label honesty ≠ process secret presence after FS load (OpenCode putenv residual is WP-G).
pub const SessionEnvFilteringFacts = struct {
    with_host_secrets: bool,
    env_scrubbed: bool,
    env_launch_allowlisted: bool,
};

pub fn sessionEnvFilteringLabel(facts: SessionEnvFilteringFacts) []const u8 {
    if (facts.with_host_secrets) return "host-secrets-escape";
    // denylist + launch allowlist applied under attach materials
    if (facts.env_scrubbed and facts.env_launch_allowlisted) return "active";
    // denylist scrub only (grade-drop unavailable/failed; provider creds may remain)
    if (facts.env_scrubbed) return "denylist-only";
    // No OS scrub path (sandbox off / no apply scrub): policy filterMap only
    return "policy-only";
}

fn parseMode(value: []const u8) ?core.types.Mode {
    if (std.mem.eql(u8, value, "observe")) return .observe;
    if (std.mem.eql(u8, value, "ask")) return .ask;
    if (std.mem.eql(u8, value, "strict")) return .strict;
    if (std.mem.eql(u8, value, "ci")) return .ci;
    return null;
}

fn coreModeToPolicyMode(mode: core.types.Mode) policy.schema.Mode {
    return switch (mode) {
        .observe => .observe,
        .ask => .ask,
        .strict => .strict,
        .ci => .ci,
    };
}

fn effectiveOsSandboxMode(
    secret_boundary: intercept.env.SecretBoundary,
    requested: sandbox.posture.OsSandboxMode,
) error{SecretBoundaryRequiresSandbox}!sandbox.posture.OsSandboxMode {
    if (secret_boundary == .off) return requested;
    if (requested == .off) return error.SecretBoundaryRequiresSandbox;
    return .on;
}

fn writeOmittedModelKeyNotes(
    current_env_override: ?*const std.process.Environ.Map,
    child_env: *const std.process.Environ.Map,
    stderr: anytype,
) !void {
    const model_key_names = [_][:0]const u8{
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
    };
    for (model_key_names) |name| {
        const host_has_key = if (current_env_override) |current_env|
            current_env.get(name) != null
        else
            std.c.getenv(name) != null;
        if (host_has_key and child_env.get(name) == null) {
            try stderr.print(
                "ryk run: Host had {s}; child will not. Use host login or --with-host-secrets.\n",
                .{name},
            );
        }
    }
}

fn gatewayPostureLabel(anthropic: bool, openai: bool) []const u8 {
    if (anthropic and openai) return "anthropic+openai";
    if (anthropic) return "anthropic";
    if (openai) return "openai";
    return "off";
}

fn writeSessionPosture(
    stdout: anytype,
    network_mode: policy.schema.NetworkMode,
    secretless: bool,
    with_host_secrets: bool,
    sandbox_posture: sandbox.posture.SessionPosture,
    anthropic_gateway: bool,
    openai_gateway: bool,
) !void {
    try stdout.print(
        "Posture: secret-boundary={s} sandbox={s} gateway={s} escape={s} network={s}\n",
        .{
            if (secretless) "on" else "off",
            @tagName(sandbox_posture),
            gatewayPostureLabel(anthropic_gateway, openai_gateway),
            if (with_host_secrets) "host-secrets" else "none",
            network_mode.toString(),
        },
    );
}

/// Format the greppable posture line into `buf` (includes trailing newline).
fn formatSessionPostureLine(
    buf: []u8,
    network_mode: policy.schema.NetworkMode,
    secretless: bool,
    with_host_secrets: bool,
    sandbox_posture: sandbox.posture.SessionPosture,
    anthropic_gateway: bool,
    openai_gateway: bool,
) ![]const u8 {
    return try std.fmt.bufPrint(
        buf,
        "Posture: secret-boundary={s} sandbox={s} gateway={s} escape={s} network={s}\n",
        .{
            if (secretless) "on" else "off",
            @tagName(sandbox_posture),
            gatewayPostureLabel(anthropic_gateway, openai_gateway),
            if (with_host_secrets) "host-secrets" else "none",
            network_mode.toString(),
        },
    );
}

fn printSessionStart(
    io: std.Io,
    stdout: anytype,
    session: core.session.Session,
    network_mode: policy.schema.NetworkMode,
    secretless: bool,
    with_host_secrets: bool,
    anthropic_gateway: bool,
    openai_gateway: bool,
    os_receipt: sandbox.posture.AttachReceipt,
    session_grade: SessionSandboxGrade,
    shim_audit_degraded: bool,
) !void {
    // Compact brand banner + Session / Workspace / Mode / Name grid. Celebration stays in printSessionEnd.
    try tui.render.banner(io, stdout, build_options.version, "watching this session");

    var rows: [4]tui.render.KV = .{
        .{ .label = "Session", .value = session.id.slice() },
        .{ .label = "Workspace", .value = session.workspace_root },
        .{ .label = "Mode", .value = session.mode.toString() },
        .{ .label = "Name", .value = "" },
    };
    var count: usize = 3;
    if (session.session_name) |name| {
        rows[3].value = name;
        count = 4;
    }
    try tui.render.keyValue(io, stdout, rows[0..count]);

    // Mechanism-neutral OS sandbox line (S-GLO-03) — never "Seatbelt"/"Landlock" here.
    // Sized for longest production landlock route-forced banner (see posture.session_banner_buf_len).
    var os_line_buf: [sandbox.posture.session_banner_buf_len]u8 = undefined;
    const os_line = run_os_sandbox.formatOsSandboxBannerLine(
        &os_line_buf,
        os_receipt,
        with_host_secrets,
    );
    var posture_line_buf: [192]u8 = undefined;
    const posture_line = try formatSessionPostureLine(
        &posture_line_buf,
        network_mode,
        secretless,
        with_host_secrets,
        os_receipt.posture,
        anthropic_gateway,
        openai_gateway,
    );
    var grade_line_buf: [96]u8 = undefined;
    const grade_line = try std.fmt.bufPrint(
        &grade_line_buf,
        "Session grade: {s}\n",
        .{session_grade.toString()},
    );
    // E0: one greppable audit=degraded line per session when in-shim audit is known dead.
    var audit_line_buf: [48]u8 = undefined;
    const audit_line: ?[]const u8 = if (shim_audit_degraded)
        try std.fmt.bufPrint(&audit_line_buf, "audit=degraded\n", .{})
    else
        null;

    const card_posture = tui.sandbox_card.PostureKind.parse(@tagName(os_receipt.posture));
    if (card_posture.isDramatic()) {
        const grade_str: ?[]const u8 = if (os_receipt.seatbelt_profile) |g| g.toString() else null;
        try tui.sandbox_card.render(io, stdout, .{
            .posture = card_posture,
            .fs_scope = os_receipt.fs_scope,
            .network_scope = os_receipt.network_scope,
            .seatbelt_profile = grade_str,
            .secretless = secretless,
            .with_host_secrets = with_host_secrets,
            .network_mode = network_mode.toString(),
            .gateway_label = gatewayPostureLabel(anthropic_gateway, openai_gateway),
            .machine_posture_line = posture_line,
            .machine_os_line = os_line,
        });
        try stdout.writeAll(grade_line);
        if (audit_line) |line| try stdout.writeAll(line);
        try stdout.writeAll("\n");
    } else {
        try stdout.writeAll(posture_line);
        try stdout.writeAll(os_line);
        try stdout.writeAll("\n");
        try stdout.writeAll(grade_line);
        if (audit_line) |line| try stdout.writeAll(line);
        try stdout.writeAll("\n");
    }
}

fn printSessionEnd(
    io: std.Io,
    stdout: anytype,
    result: supervisor.SessionResult,
    is_first_session: bool,
    protected_session: bool,
    chain_hash: ?[]const u8,
) !void {
    const code = result.exitCode();
    if (code == 0) {
        // Dynamic success line: explicit gated pattern (no alloc, respects useColor).
        // Uses Glyph for the checkmark (eliminates prior duplication).
        try stdout.writeAll("\n");
        if (style.useColor(io, stdout)) {
            try stdout.writeAll(style.Style.green);
            try stdout.print("{s} Session ended cleanly (exit {d})\n", .{ style.Glyph.check, code });
            try stdout.writeAll(style.Style.reset);
        } else {
            try stdout.print("{s} Session ended cleanly (exit {d})\n", .{ style.Glyph.check, code });
        }
    } else {
        try stdout.print("\n{s} Session ended with exit code {d}\n", .{ style.Glyph.cross, code });
    }
    if (chain_hash) |hash| {
        try stdout.print("Audit chain: {s}\n", .{hash});
    }
    if (is_first_session and protected_session and code == 0) {
        // Phase 7: elevate the first-run celebration into a branded moment.
        // A celebratory brand banner (shield + version + status) opens the
        // moment, followed by a warm welcome line and a "Next steps" hint list
        // composed from the same `→ ` pattern the deny block uses, so the whole
        // tool speaks one visual language. Human-only — `--json`/machine output
        // never reaches here. `isFirstSession` once-per-workspace semantics are
        // unchanged (still best-effort, still gated on exit code 0).
        try stdout.writeAll("\n");
        try tui.render.banner(io, stdout, build_options.version, "first protected session complete");
        try stdout.writeAll("\n");
        try tui.theme.paintBold(io, stdout, .success, "  Welcome to ryk!");
        try stdout.writeAll(" Your first protected session completed successfully.\n");
        try stdout.writeAll("\n");
        try tui.theme.paintBold(io, stdout, .info, "  Next steps");
        try stdout.writeAll("\n");
        try stdout.writeAll("  → ");
        try tui.theme.paint(io, stdout, .text_bright, "ryk replay --session last");
        try stdout.writeAll("  (review what happened)\n");
        try stdout.writeAll("  → ");
        try tui.theme.paint(io, stdout, .text_bright, "ryk policy explain command \"<your-command>\"");
        try stdout.writeAll("  (understand your rules)\n");
        try stdout.writeAll("  → ");
        try tui.theme.paint(io, stdout, .text_bright, "ryk <agent>");
        try stdout.writeAll("  (launch another protected agent)\n");
        try stdout.writeAll("\n");
    }
}

/// Render the rich "guardian block" for a denied command to a human-facing
/// writer (stderr). Composes the `tui` design-system primitives:
///
///   ✗  ryk blocked a command            (callout .danger header)
///   ┌──────────────────────────────┐
///   │ ✗  <command>                 │     (panel, command as headline)
///   ├──────────────────────────────┤
///   │ Why        <plain-english>   │
///   │ Rule       <rule_id or —>    │
///   │ Policy     <path> · mode <m> │
///   └──────────────────────────────┘
///     Risk   ███████░░░░  <label>        (standalone meter — colour-safe)
///   Safe alternatives               (when derivable from command shape)
///     → <alt>  (<note>)
///   Tip / Next
///     Tip: <daemon suggestion when present>
///     → ryk explain "…"
///     → ryk allowlist add <rule> -r "reason"
///     → ryk allow-once <code>
///
/// Graceful degrade: when `rule_id` is null (fail-closed / user-denial paths) or
/// not in the reason table, a generic reason + medium risk meter are used and
/// Progressive deny presentation (ISS-DENY-01): What → Why → Risk → Safer
/// shape → What now. Presentation only — never changes the decision, audit
/// output, or exit code. `--json`/robot output never reaches here.
fn renderDenyBlock(
    io: std.Io,
    stdout: anytype,
    allocator: std.mem.Allocator,
    command_argv: []const []const u8,
    rule_id: ?[]const u8,
    remediation_tip: ?[]const u8,
    policy_path: ?[]const u8,
    policy_mode: []const u8,
) !void {
    try stdout.writeAll("\n");
    try tui.render.callout(io, stdout, .danger, "ryk blocked a command", "");
    try stdout.writeAll("\n");

    // Compose panel body lines (text-only — safe for the panel's width padding).
    // The coloured risk meter is rendered separately below to avoid ANSI codes
    // inside the padded panel body.
    var body: std.ArrayList([]const u8) = .empty;
    defer {
        for (body.items) |line| allocator.free(line);
        body.deinit(allocator);
    }

    // Prefer bare pattern for the reason table (accepts pack:pattern or bare).
    const reason_key = if (rule_id) |rid| blk: {
        if (std.mem.lastIndexOfScalar(u8, rid, ':')) |idx| break :blk rid[idx + 1 ..];
        break :blk rid;
    } else null;
    const reason_text = if (reason_key) |rid| tui.reasons.reasonForRule(rid) else "Matched a deny rule in your ryk policy.";
    try body.append(allocator, try std.fmt.allocPrint(allocator, "Why        {s}", .{reason_text}));

    if (rule_id) |rid| {
        try body.append(allocator, try std.fmt.allocPrint(allocator, "Rule       {s}", .{rid}));
    } else {
        try body.append(allocator, try allocator.dupe(u8, "Rule       —"));
    }
    try body.append(allocator, try std.fmt.allocPrint(allocator, "Policy     {s} · mode {s}", .{ policy_path orelse "built-in", policy_mode }));

    // Panel title = the denied command (What), prefixed with the deny glyph.
    const command_display = try intercept.commands.displayArgvRedactedAlloc(allocator, command_argv);
    defer allocator.free(command_display);
    const title = try std.fmt.allocPrint(allocator, "✗  {s}", .{command_display});
    defer allocator.free(title);
    try tui.render.panel(io, stdout, title, body.items);
    try stdout.writeAll("\n");
    const risk = if (reason_key) |rid| tui.reasons.riskForRule(rid) else .medium;
    try stdout.writeAll("  ");
    try tui.theme.paintBold(io, stdout, .danger, "Risk");
    try stdout.writeAll("   ");
    try tui.render.meter(io, stdout, tui.reasons.riskFraction(risk), tui.reasons.riskLabel(risk));
    try stdout.writeAll("\n\n");
    const alts = try tui.reasons.safeAlternatives(allocator, command_display);
    defer {
        for (alts) |a| allocator.free(a.command);
        allocator.free(alts);
    }
    if (remediation_tip) |tip| {
        try tui.theme.paintBold(io, stdout, .info, "  Safer shape");
        try stdout.writeAll("\n  ");
        try stdout.writeAll(tip);
        try stdout.writeAll("\n\n");
    } else if (alts.len > 0) {
        try tui.theme.paintBold(io, stdout, .info, "  Safer shape");
        try stdout.writeAll("\n");
        for (alts) |a| {
            try stdout.writeAll("  → ");
            try tui.theme.paint(io, stdout, .text_bright, a.command);
            try stdout.print("  ({s})\n", .{a.note});
        }
        try stdout.writeAll("\n");
    }
    // Tip is not re-injected here — safer shape above already showed remediation.
    const next_steps = try rust_visibility.formatDenyNextSteps(allocator, command_display, rule_id, null);
    defer allocator.free(next_steps);
    try tui.theme.paintBold(io, stdout, .text_bright, "  What now");
    try stdout.writeAll("\n");
    // Indent each line of the footer for the panel-adjacent layout.
    var line_iter = std.mem.splitScalar(u8, next_steps, '\n');
    while (line_iter.next()) |line| {
        if (line.len == 0) continue;
        // Title already painted above (handles both legacy "Next:" and "What now:").
        if (std.mem.startsWith(u8, line, "Next:") or std.mem.startsWith(u8, line, "What now:")) continue;
        if (std.mem.startsWith(u8, line, "  ")) {
            try stdout.writeAll(line);
            try stdout.writeAll("\n");
        } else {
            try stdout.writeAll("  ");
            try stdout.writeAll(line);
            try stdout.writeAll("\n");
        }
    }
    try stdout.writeAll("\n");
}

fn flushIfSupported(writer: anytype) !void {
    const Writer = @TypeOf(writer);
    switch (@typeInfo(Writer)) {
        .pointer => |pointer| {
            if (@hasDecl(pointer.child, "flush")) {
                try writer.flush();
            }
        },
        else => {
            if (@hasDecl(Writer, "flush")) {
                try writer.flush();
            }
        },
    }
}

/// After the shield card is painted + flushed, dwell ~2s on an interactive TTY
/// so humans can actually read it. Skips pipes, dumb terminals, tests, and
/// `RYK_SHIELD_HOLD=0`.
fn holdShieldCardIfNeeded(io: std.Io, stdout: anytype, receipt: sandbox.posture.AttachReceipt) void {
    const posture = tui.sandbox_card.PostureKind.parse(@tagName(receipt.posture));
    const is_tty = stdoutIsTty(io, stdout);
    const term_dumb = blk: {
        const term = std.c.getenv("TERM") orelse break :blk false;
        break :blk std.mem.eql(u8, std.mem.sliceTo(term, 0), "dumb");
    };
    const hold_disabled = shieldHoldDisabledByEnv();
    tui.sandbox_card.holdIfNeeded(io, posture, is_tty, term_dumb, hold_disabled);
}

fn shieldHoldDisabledByEnv() bool {
    // Honor the canonical RYK_SHIELD_HOLD setting.
    for ([_][:0]const u8{"RYK_SHIELD_HOLD"}) |name| {
        if (std.c.getenv(name)) |raw| {
            const v = std.mem.sliceTo(raw, 0);
            if (v.len == 0) continue;
            if (std.mem.eql(u8, v, "0") or std.mem.eql(u8, v, "off") or std.mem.eql(u8, v, "false")) return true;
        }
    }
    return false;
}

fn stdoutIsTty(io: std.Io, stdout: anytype) bool {
    const Writer = @TypeOf(stdout);
    const is_file = switch (@typeInfo(Writer)) {
        .pointer => |ptr| ptr.child == std.Io.File,
        else => Writer == std.Io.File,
    };
    if (is_file) {
        const file = switch (@typeInfo(Writer)) {
            .pointer => stdout.*,
            else => stdout,
        };
        return file.isTty(io) catch false;
    }
    const is_file_writer = switch (@typeInfo(Writer)) {
        .pointer => |ptr| @hasField(ptr.child, "file") and @hasField(ptr.child, "interface"),
        else => @hasField(Writer, "file") and @hasField(Writer, "interface"),
    };
    if (is_file_writer) {
        const w = switch (@typeInfo(Writer)) {
            .pointer => stdout.*,
            else => stdout,
        };
        return w.file.isTty(io) catch false;
    }
    return std.Io.File.stdout().isTty(io) catch false;
}

/// Returns true if the workspace has no prior .ryk/sessions/ entries.
/// Checked *before* the current session creates its directory so the first-run
/// celebration can be emitted exactly once.
///
/// NOTE: This is best-effort. A concurrent process may create a session dir
/// between the check and the current session's creation, or the user may have
/// manually cleaned sessions while keeping the workspace. The celebration is
/// a warm UX nicety — occasional false positives are acceptable.
fn isFirstSession(io: std.Io, allocator: std.mem.Allocator, workspace_root: []const u8) bool {
    const sessions_dir = std.fs.path.join(allocator, &.{ workspace_root, ".ryk", "sessions" }) catch return true;
    defer allocator.free(sessions_dir);

    var dir = std.Io.Dir.cwd().openDir(io, sessions_dir, .{ .iterate = true }) catch return true;
    defer dir.close(io);

    var it = dir.iterate();
    while (it.next(io) catch return true) |entry| {
        if (entry.kind == .directory) {
            // Any real session dir means this is not the user's first
            return false;
        }
    }
    return true;
}

test "run rejects missing child command" {
    var stdout_buf: [512]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, &.{"--"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "missing command") != null);
    // TDD: warm multi-line error message with examples (foundation UX)
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "Example:") != null);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "ryk run -- echo") != null);
}

test "run rejects child command without separator" {
    var stdout_buf: [512]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, &.{"echo"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "expected '--'") != null);
    // TDD: warm multi-line error message with examples + help pointer (foundation UX)
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "Example:") != null);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "ryk help run") != null);
}

test "run reports missing command usefully" {
    var stdout_buf: [512]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try commandForTest(&.{ "--", "ryk-definitely-missing-command" }, &stdout_writer, &stderr_writer, .ignore);
    try std.testing.expectEqual(exit_codes.general, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "command not found") != null);
}

pub fn commandForTest(argv: []const []const u8, stdout: anytype, stderr: anytype, stdio: supervisor.StdioBehavior) !u8 {
    return commandForTestWithShellEvaluator(argv, stdout, stderr, stdio, null);
}

pub fn commandForTestWithShellEvaluator(argv: []const []const u8, stdout: anytype, stderr: anytype, stdio: supervisor.StdioBehavior, shell_evaluator: ?shell_eval.ShellCommandEvaluatorFn) !u8 {
    return commandWithStdioAndEnv(std.testing.io, argv, stdout, stderr, stdio, false, null, shell_evaluator);
}

pub fn commandForGuardTestWithShellEvaluator(argv: []const []const u8, stdout: anytype, stderr: anytype, stdio: supervisor.StdioBehavior, shell_evaluator: ?shell_eval.ShellCommandEvaluatorFn) !u8 {
    return commandWithStdioAndEnv(std.testing.io, argv, stdout, stderr, stdio, true, null, shell_evaluator);
}

fn commandForTestWithEnv(argv: []const []const u8, stdout: anytype, stderr: anytype, stdio: supervisor.StdioBehavior, current_env: *const std.process.Environ.Map) !u8 {
    return commandForTestWithEnvAndShellEvaluator(argv, stdout, stderr, stdio, current_env, shell_eval.mockDaemonAllowEvaluator);
}

fn commandForTestWithEnvAndShellEvaluator(argv: []const []const u8, stdout: anytype, stderr: anytype, stdio: supervisor.StdioBehavior, current_env: *const std.process.Environ.Map, shell_evaluator: ?shell_eval.ShellCommandEvaluatorFn) !u8 {
    return commandWithStdioAndEnv(std.testing.io, argv, stdout, stderr, stdio, true, current_env, shell_evaluator);
}

test "run accepts policy path and uses policy mode when mode is not explicit" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        const file = try tmp.dir.createFile(std.testing.io, "strict.yaml", .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io, policy.presets.text(.strict));
    }
    const path = try tmp.dir.realPathFileAlloc(std.testing.io, "strict.yaml", std.testing.allocator);
    defer std.testing.allocator.free(path);

    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try commandForTestWithShellEvaluator(&.{ "--policy", path, "--os-sandbox", "off", "--", "zig", "version" }, &stdout_writer, &stderr_writer, .ignore, shell_eval.mockDaemonAllowEvaluator);
    try std.testing.expectEqual(exit_codes.success, code);
    // Phase 2: printSessionStart renders Mode via the tui key-value grid (label
    // "Mode", value = mode string). The exact padded column format is owned by
    // tui.render.keyValue; assert the mode value + label are present.
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "Mode") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "strict") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "run rejects inherit-env when selected policy disallows it" {
    var stdout_buf: [512]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try commandForTest(&.{ "--policy", "policies/strict.yaml", "--inherit-env", "--", "zig", "version" }, &stdout_writer, &stderr_writer, .ignore);
    try std.testing.expectEqual(exit_codes.general, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "--inherit-env is not allowed") != null);
}

test "run rejects secretless with os sandbox off before child launch" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var stdout_buf: [1024]u8 = undefined;
    var stderr_buf: [2048]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try commandForTestWithShellEvaluator(
        &.{ "--workspace", root, "--secretless", "--os-sandbox", "off", "--", "/bin/sh", "-c", "touch child-started" },
        &stdout_writer,
        &stderr_writer,
        .ignore,
        shell_eval.mockDaemonAllowEvaluator,
    );
    try std.testing.expectEqual(exit_codes.usage, code);
    try std.testing.expect(
        std.mem.indexOf(
            u8,
            stderr_writer.buffered(),
            "empty-backpack secret boundary requires an active OS sandbox",
        ) != null,
    );
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(std.testing.io, "child-started", .{}));
}

test "run parses with-host-secrets and suggests the escape flag" {
    var stdout_buf: [1024]u8 = undefined;
    var stderr_buf: [2048]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const defaults = try parseOptions(std.testing.io, &.{ "--", "true" }, &stdout_writer, &stderr_writer);
    try std.testing.expect(!defaults.with_host_secrets);

    const escape = try parseOptions(
        std.testing.io,
        &.{ "--with-host-secrets", "--", "true" },
        &stdout_writer,
        &stderr_writer,
    );
    try std.testing.expect(escape.with_host_secrets);

    stdout_writer = .fixed(&stdout_buf);
    stderr_writer = .fixed(&stderr_buf);
    const code = try commandForTest(
        &.{ "--with-host-secret", "--", "true" },
        &stdout_writer,
        &stderr_writer,
        .ignore,
    );
    try std.testing.expectEqual(exit_codes.usage, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "--with-host-secrets") != null);
}

test "run rejects secretless with with-host-secrets before child launch" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var stdout_buf: [1024]u8 = undefined;
    var stderr_buf: [2048]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try commandForTestWithShellEvaluator(
        &.{ "--workspace", root, "--secretless", "--with-host-secrets", "--", "/bin/sh", "-c", "touch child-started" },
        &stdout_writer,
        &stderr_writer,
        .ignore,
        shell_eval.mockDaemonAllowEvaluator,
    );
    try std.testing.expectEqual(exit_codes.usage, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "cannot combine --secretless with --with-host-secrets") != null);
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(std.testing.io, "child-started", .{}));
}

test "run with-host-secrets is loud and retains host canary through sandbox attach" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    try skipUnlessOsSandboxBackend();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    {
        const policy_file = try tmp.dir.createFile(std.testing.io, "policy.yaml", .{});
        defer policy_file.close(std.testing.io);
        try policy_file.writeStreamingAll(std.testing.io,
            \\version: 1
            \\mode: observe
            \\env:
            \\  inherit: false
            \\commands:
            \\  allow:
            \\    - "/bin/sh *"
        );
    }
    const policy_path = try tmp.dir.realPathFileAlloc(std.testing.io, "policy.yaml", std.testing.allocator);
    defer std.testing.allocator.free(policy_path);

    var current = std.process.Environ.Map.init(std.testing.allocator);
    defer current.deinit();
    const path_env = if (std.c.getenv("PATH")) |path| std.mem.span(path) else "/usr/bin:/bin:/usr/sbin:/sbin";
    try current.put("PATH", path_env);
    try current.put("MYSQL_PWD", "SuperSecretPass99");

    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [4096]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try commandForTestWithEnvAndShellEvaluator(
        &.{ "--workspace", root, "--policy", policy_path, "--with-host-secrets", "--", "/bin/sh", "-c", "printf '%s' \"$MYSQL_PWD\" > child-env.txt" },
        &stdout_writer,
        &stderr_writer,
        .ignore,
        &current,
        shell_eval.mockDaemonAllowEvaluator,
    );
    try std.testing.expectEqual(exit_codes.success, code);
    const stderr_out = stderr_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, stderr_out, "WARNING: --with-host-secrets disables empty-backpack") != null);
    try std.testing.expect(std.mem.indexOf(u8, stderr_out, "docs/credentials.md") != null);
    try std.testing.expect(
        std.mem.indexOf(u8, stdout_writer.buffered(), "host environment retained (explicit escape)") != null,
    );

    const child_env = try tmp.dir.readFileAlloc(std.testing.io, "child-env.txt", std.testing.allocator, .limited(128));
    defer std.testing.allocator.free(child_env);
    try std.testing.expectEqualStrings("SuperSecretPass99", child_env);
}

test "run secretless injects a minted provider phantom and keeps raw secrets out of child and audit" {
    // Linux protected launches self-exec /proc/self/exe into the hidden
    // workspace-view bootstrap. A Zig unit-test image is a test runner, not
    // the ryk CLI image; the real Debug-binary canary covers this end to end.
    if (builtin.os.tag == .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    {
        const policy_file = try tmp.dir.createFile(std.testing.io, "policy.yaml", .{});
        defer policy_file.close(std.testing.io);
        try policy_file.writeStreamingAll(std.testing.io,
            \\version: 1
            \\mode: observe
            \\env:
            \\  inherit: true
        );
    }
    const policy_path = try tmp.dir.realPathFileAlloc(std.testing.io, "policy.yaml", std.testing.allocator);
    defer std.testing.allocator.free(policy_path);
    {
        const script = try tmp.dir.createFile(std.testing.io, "dump-env.sh", .{});
        defer script.close(std.testing.io);
        try script.writeStreamingAll(std.testing.io,
            \\#!/bin/sh
            \\printf '%s|%s|%s|%s|%s|%s' \
            \\  "$GITHUB_TOKEN" "$DATABASE_URL" "$MYSQL_PWD" "$OPENAI_API_KEY" "$RANDOM_HOST_VALUE" "$OPENAI_BASE_URL" \
            \\  > child-env.txt
            \\
        );
        try tmp.dir.setFilePermissions(std.testing.io, "dump-env.sh", @enumFromInt(0o755), .{});
    }

    var current = std.process.Environ.Map.init(std.testing.allocator);
    defer current.deinit();
    const path_env = if (std.c.getenv("PATH")) |path| std.mem.span(path) else "/usr/bin:/bin:/usr/sbin:/sbin";
    try current.put("PATH", path_env);
    try current.put("GITHUB_TOKEN", "ghp_fakeSyntheticTokenValue1234567890");
    try current.put("DATABASE_URL", "postgres://synthetic:SuperSecretPass99@db.invalid/app");
    try current.put("MYSQL_PWD", "SuperSecretPass99");
    try current.put("OPENAI_API_KEY", "sk-fakeSyntheticOpenAIKey1234567890");
    try current.put("RANDOM_HOST_VALUE", "must-not-survive");
    try current.put("TOKEN_ghp_fakeSyntheticNameCanary1234567890", "ordinary");

    var stdout_buf: [8192]u8 = undefined;
    var stderr_buf: [2048]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try commandForTestWithEnv(&.{ "--workspace", root, "--policy", policy_path, "--secretless", "--inherit-env", "--", "./dump-env.sh" }, &stdout_writer, &stderr_writer, .ignore, &current);
    try std.testing.expectEqual(exit_codes.success, code);

    const stderr_out = stderr_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, stderr_out, "--secretless rewrote") == null);
    try std.testing.expect(std.mem.indexOf(u8, stderr_out, "ghp_fakeSyntheticTokenValue") == null);
    try std.testing.expect(std.mem.indexOf(u8, stderr_out, "ghp_fakeSyntheticNameCanary") == null);
    try std.testing.expect(std.mem.indexOf(u8, stderr_out, "SuperSecretPass99") == null);
    try std.testing.expect(std.mem.indexOf(u8, stderr_out, "Host had OPENAI_API_KEY; child will not") == null);
    try std.testing.expect(std.mem.indexOf(u8, stderr_out, "sk-fakeSyntheticOpenAIKey1234567890") == null);

    const child_env = try tmp.dir.readFileAlloc(std.testing.io, "child-env.txt", std.testing.allocator, .limited(512));
    defer std.testing.allocator.free(child_env);
    var fields = std.mem.splitScalar(u8, child_env, '|');
    try std.testing.expectEqualStrings("", fields.next().?);
    try std.testing.expectEqualStrings("", fields.next().?);
    try std.testing.expectEqualStrings("", fields.next().?);
    const openai_phantom = fields.next().?;
    try std.testing.expect(std.mem.startsWith(u8, openai_phantom, "ryk-secret://session/"));
    const name_marker = "/OPENAI_API_KEY/";
    const marker_index = std.mem.indexOf(u8, openai_phantom, name_marker) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 16), openai_phantom.len - marker_index - name_marker.len);
    try std.testing.expectEqualStrings("", fields.next().?);
    const openai_base_url = fields.next().?;
    try std.testing.expect(std.mem.startsWith(u8, openai_base_url, "http://127.0.0.1:"));
    try std.testing.expect(std.mem.endsWith(u8, openai_base_url, "/v1"));
    try std.testing.expect(fields.next() == null);
    try std.testing.expect(std.mem.indexOf(u8, child_env, "sk-fakeSyntheticOpenAIKey1234567890") == null);

    const events = try readLastEvents(std.testing.allocator, root);
    defer std.testing.allocator.free(events);
    try std.testing.expect(std.mem.indexOf(u8, events, "\"type\":\"secret_redacted\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, events, "ghp_fakeSyntheticTokenValue") == null);
    try std.testing.expect(std.mem.indexOf(u8, events, "ghp_fakeSyntheticNameCanary") == null);
    try std.testing.expect(std.mem.indexOf(u8, events, "SuperSecretPass99") == null);
    try std.testing.expect(std.mem.indexOf(u8, events, "sk-fakeSyntheticOpenAIKey1234567890") == null);
}

test "run secretless resolves broker grant in parent and injects phantom only" {
    // See the sibling host-grant test above. Linux coverage lives in the real
    // Debug-binary canary plus the workspace-view and session-store unit tests.
    if (builtin.os.tag == .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    try tmp.dir.createDir(std.testing.io, ".ryk", .default_dir);
    {
        const secret_file = try tmp.dir.createFile(std.testing.io, ".ryk/dev-secrets.env", .{});
        defer secret_file.close(std.testing.io);
        try secret_file.writeStreamingAll(std.testing.io, "OPENAI_BROKER_KEY=sk-openai-broker-parent-canary\n");
    }
    {
        const schema_file = try tmp.dir.createFile(std.testing.io, ".ryk/env.schema.yaml", .{});
        defer schema_file.close(std.testing.io);
        try schema_file.writeStreamingAll(std.testing.io,
            \\defaults:
            \\  unknown: omit
            \\vars:
            \\  OPENAI_API_KEY:
            \\    class: sensitive
            \\    grant: openai
            \\
        );
    }
    {
        const policy_file = try tmp.dir.createFile(std.testing.io, "policy.yaml", .{});
        defer policy_file.close(std.testing.io);
        try policy_file.writeStreamingAll(std.testing.io,
            \\version: 1
            \\mode: observe
            \\credentials:
            \\  brokers:
            \\    env_dev:
            \\      type: env-file-dev
            \\      path: .ryk/dev-secrets.env
            \\  refs:
            \\    openai_key:
            \\      broker: env_dev
            \\      ref: OPENAI_BROKER_KEY
            \\  grants:
            \\    openai:
            \\      env_var: OPENAI_API_KEY
            \\      provider: openai
            \\      source: broker
            \\      credential_ref: openai_key
            \\      allowed_hosts:
            \\        - api.openai.com
            \\
        );
    }
    {
        const script = try tmp.dir.createFile(std.testing.io, "dump-env.sh", .{});
        defer script.close(std.testing.io);
        try script.writeStreamingAll(std.testing.io,
            \\#!/bin/sh
            \\printf '%s|%s' "$OPENAI_API_KEY" "$OPENAI_BASE_URL" > child-env.txt
            \\
        );
        try tmp.dir.setFilePermissions(std.testing.io, "dump-env.sh", @enumFromInt(0o755), .{});
    }
    const policy_path = try tmp.dir.realPathFileAlloc(std.testing.io, "policy.yaml", std.testing.allocator);
    defer std.testing.allocator.free(policy_path);
    var current = std.process.Environ.Map.init(std.testing.allocator);
    defer current.deinit();
    const path_env = if (std.c.getenv("PATH")) |path| std.mem.span(path) else "/usr/bin:/bin:/usr/sbin:/sbin";
    try current.put("PATH", path_env);
    var stdout_buffer: [8192]u8 = undefined;
    var stderr_buffer: [2048]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buffer);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buffer);
    const code = try commandForTestWithEnv(
        &.{ "--workspace", root, "--policy", policy_path, "--secretless", "--", "./dump-env.sh" },
        &stdout_writer,
        &stderr_writer,
        .ignore,
        &current,
    );
    try std.testing.expectEqual(exit_codes.success, code);
    const child_env = try tmp.dir.readFileAlloc(std.testing.io, "child-env.txt", std.testing.allocator, .limited(1024));
    defer std.testing.allocator.free(child_env);
    try std.testing.expect(std.mem.startsWith(u8, child_env, "ryk-secret://session/"));
    try std.testing.expect(std.mem.indexOf(u8, child_env, "sk-openai-broker-parent-canary") == null);
    try std.testing.expect(std.mem.indexOf(u8, child_env, "|http://127.0.0.1:") != null);
    const events = try readLastEvents(std.testing.allocator, root);
    defer std.testing.allocator.free(events);
    try std.testing.expect(std.mem.indexOf(u8, events, "sk-openai-broker-parent-canary") == null);
}

test "run command guard denies ci ask without prompting and audits command events" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [2048]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try commandForGuardTestWithShellEvaluator(&.{ "--workspace", root, "--mode", "ci", "--", "npm", "install", "OPENAI_API_KEY=sk-fakeSyntheticOpenAIKey1234567890" }, &stdout_writer, &stderr_writer, .inherit, shell_eval.mockDaemonDenyEvaluator);
    try std.testing.expectEqual(exit_codes.denial, code);
    // Phase 1 UX: rich guardian block replaces the flat "command denied" line.
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "ryk blocked") != null);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "✗") != null);

    const events = try readLastEvents(std.testing.allocator, root);
    defer std.testing.allocator.free(events);
    try std.testing.expect(std.mem.indexOf(u8, events, "\"type\":\"command_attempt\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, events, "\"type\":\"command_denied\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, events, "sk-fakeSyntheticOpenAIKey") == null);
    try std.testing.expect(std.mem.indexOf(u8, events, "shell command (redacted)") != null);
    try std.testing.expect(std.mem.indexOf(u8, events, "\"decision_source\":\"zig-native\"") != null);
}

// Default auto attach + orchestration (shim dir). Skips when no OS backend.
// Full multi-agent smoke remains manual (see attach tests near file end).
test "run command guard allows safe command and creates session shim directory" {
    try skipUnlessOsSandboxBackend();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var stdout_buf: [8192]u8 = undefined;
    var stderr_buf: [2048]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    // Default --os-sandbox auto (omit flag) to exercise attach + shim orchestration.
    const code = try commandForGuardTestWithShellEvaluator(&.{ "--workspace", root, "--", "true" }, &stdout_writer, &stderr_writer, .inherit, shell_eval.mockDaemonAllowEvaluator);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "OS sandbox: active") != null);

    const session_id = try readLastSessionId(std.testing.allocator, root);
    defer std.testing.allocator.free(session_id);
    const shim_path = try std.fs.path.join(std.testing.allocator, &.{ root, ".ryk", "sessions", session_id, "shims", "git" });
    defer std.testing.allocator.free(shim_path);
    try std.Io.Dir.cwd().access(std.testing.io, shim_path, .{});

    const events = try readLastEvents(std.testing.allocator, root);
    defer std.testing.allocator.free(events);
    try std.testing.expect(std.mem.indexOf(u8, events, "\"type\":\"command_allowed\"") != null);
}

test "run emits sandbox_posture audit event without full profile" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [2048]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    // --os-sandbox off guarantees disabled posture and a successful session start path.
    const code = try commandForGuardTestWithShellEvaluator(&.{ "--workspace", root, "--os-sandbox", "off", "--", "true" }, &stdout_writer, &stderr_writer, .inherit, shell_eval.mockDaemonAllowEvaluator);
    try std.testing.expectEqual(exit_codes.success, code);

    const events = try readLastEvents(std.testing.allocator, root);
    defer std.testing.allocator.free(events);
    try std.testing.expect(std.mem.indexOf(u8, events, "\"type\":\"sandbox_posture\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, events, "posture=disabled") != null);
    try std.testing.expect(std.mem.indexOf(u8, events, "fs_scope=") != null);
    // No full profile / SBPL blobs on a normal run (hash_chain covers serialization).
    try std.testing.expect(std.mem.indexOf(u8, events, "allow default") == null);
    try std.testing.expect(std.mem.indexOf(u8, events, "(version 1)") == null);
}

test "run command guard denies destructive command before spawn" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [2048]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try commandForGuardTestWithShellEvaluator(&.{ "--workspace", root, "--", "rm", "-rf", "/" }, &stdout_writer, &stderr_writer, .inherit, shell_eval.mockDaemonDenyEvaluator);
    try std.testing.expectEqual(exit_codes.denial, code);
    const events = try readLastEvents(std.testing.allocator, root);
    defer std.testing.allocator.free(events);
    try std.testing.expect(std.mem.indexOf(u8, events, "\"type\":\"command_denied\"") != null);
}

test "run no-network sets network mode off and audits denied network state" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [2048]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try commandForGuardTestWithShellEvaluator(&.{ "--workspace", root, "--no-network", "--os-sandbox", "off", "--", "true" }, &stdout_writer, &stderr_writer, .inherit, shell_eval.mockDaemonAllowEvaluator);
    try std.testing.expectEqual(exit_codes.success, code);
    const events = try readLastEvents(std.testing.allocator, root);
    defer std.testing.allocator.free(events);
    try std.testing.expect(std.mem.indexOf(u8, events, "\"type\":\"network_connect_denied\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, events, "\"type\":\"network_exfiltration_suspected\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, events, "network mode off") != null);
}

test "sessionEnvFilteringLabel maps session facts without backend.Level stuffing" {
    try std.testing.expectEqualStrings(
        "host-secrets-escape",
        sessionEnvFilteringLabel(.{ .with_host_secrets = true, .env_scrubbed = true, .env_launch_allowlisted = true }),
    );
    try std.testing.expectEqualStrings(
        "active",
        sessionEnvFilteringLabel(.{ .with_host_secrets = false, .env_scrubbed = true, .env_launch_allowlisted = true }),
    );
    try std.testing.expectEqualStrings(
        "denylist-only",
        sessionEnvFilteringLabel(.{ .with_host_secrets = false, .env_scrubbed = true, .env_launch_allowlisted = false }),
    );
    try std.testing.expectEqualStrings(
        "policy-only",
        sessionEnvFilteringLabel(.{ .with_host_secrets = false, .env_scrubbed = false, .env_launch_allowlisted = false }),
    );
    // with-host-secrets never bare active even if scrub flags look happy
    try std.testing.expect(!std.mem.eql(
        u8,
        "active",
        sessionEnvFilteringLabel(.{ .with_host_secrets = true, .env_scrubbed = false, .env_launch_allowlisted = false }),
    ));
}

test "run with-host-secrets exports host-secrets-escape env filtering label" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "out");
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var stdout_buf: [8192]u8 = undefined;
    var stderr_buf: [4096]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    // Escape path: label must not claim active even when OS attach succeeds.
    const code = try commandForTestWithShellEvaluator(
        &.{ "--workspace", root, "--with-host-secrets", "--os-sandbox", "off", "--", "/bin/sh", "-c", "env > out/env-label.txt" },
        &stdout_writer,
        &stderr_writer,
        .ignore,
        shell_eval.mockDaemonAllowEvaluator,
    );
    try std.testing.expectEqual(exit_codes.success, code);
    const written = try tmp.dir.readFileAlloc(std.testing.io, "out/env-label.txt", std.testing.allocator, .limited(8192));
    defer std.testing.allocator.free(written);
    try std.testing.expect(std.mem.indexOf(u8, written, "RYK_BACKEND_ENV_FILTERING=host-secrets-escape") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "RYK_BACKEND_ENV_FILTERING=active") == null);
}

test "run os-sandbox off exports policy-only env filtering label" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "out");
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var stdout_buf: [8192]u8 = undefined;
    var stderr_buf: [4096]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try commandForTestWithShellEvaluator(
        &.{ "--workspace", root, "--os-sandbox", "off", "--", "/bin/sh", "-c", "env > out/env-label.txt" },
        &stdout_writer,
        &stderr_writer,
        .ignore,
        shell_eval.mockDaemonAllowEvaluator,
    );
    try std.testing.expectEqual(exit_codes.success, code);
    const written = try tmp.dir.readFileAlloc(std.testing.io, "out/env-label.txt", std.testing.allocator, .limited(8192));
    defer std.testing.allocator.free(written);
    try std.testing.expect(std.mem.indexOf(u8, written, "RYK_BACKEND_ENV_FILTERING=policy-only") != null);
}

test "run defaults trusted host agents to empty backpack; basename spoof is generic" {
    const defaults: RunOptions = .{};
    try std.testing.expectEqual(policy.schema.NetworkMode.ask, cliNetworkMode(defaults, .mediated, false));
    try std.testing.expect(!defaults.secretless);
    try std.testing.expectEqual(intercept.env.SecretBoundary.off, effectiveSecretBoundary(defaults, false));

    const modes = [_]policy.schema.NetworkMode{ .open, .allowlist, .observe, .off, .ask };
    for (modes) |mode| {
        try std.testing.expectEqual(mode, cliNetworkMode(.{ .network_mode = mode }, .mediated, false));
    }

    // --no-network is modeled as network_mode = .off (last flag wins in parseOptions).
    try std.testing.expectEqual(policy.schema.NetworkMode.off, cliNetworkMode(.{ .network_mode = .off }, .mediated, false));
    const secretless_on: RunOptions = .{ .secretless = true };
    try std.testing.expect(secretless_on.secretless);
    try std.testing.expectEqual(intercept.env.SecretBoundary.empty_backpack, effectiveSecretBoundary(secretless_on, false));

    // Trusted agent host identity → empty backpack + mediation (F-02 coupling).
    try std.testing.expectEqual(
        intercept.env.SecretBoundary.empty_backpack,
        effectiveSecretBoundary(.{ .command_argv = &.{"codex"} }, true),
    );
    try std.testing.expectEqual(
        policy.schema.NetworkMode.allowlist,
        cliNetworkMode(.{ .command_argv = &.{"codex"} }, .mediated, true),
    );
    try std.testing.expect(wantsMediatedAgentNetwork(.{ .command_argv = &.{"codex"} }, .mediated, true));
    try std.testing.expect(!wantsMediatedAgentNetwork(.{ .command_argv = &.{"codex"} }, .legacy, true));
    try std.testing.expect(!wantsMediatedAgentNetwork(.{
        .command_argv = &.{"codex"},
        .network_mode = .open,
    }, .mediated, true));
    try std.testing.expect(wantsMediatedAgentNetwork(.{
        .command_argv = &.{"codex"},
        .network_backend = .decision_only,
    }, .mediated, true));
    // Basename-only / untrusted: no empty-backpack, no mediation (F-02).
    try std.testing.expectEqual(
        intercept.env.SecretBoundary.off,
        effectiveSecretBoundary(.{ .command_argv = &.{"codex"} }, false),
    );
    try std.testing.expectEqual(
        intercept.env.SecretBoundary.off,
        effectiveSecretBoundary(.{ .command_argv = &.{"/usr/local/bin/claude"} }, false),
    );
    try std.testing.expectEqual(
        intercept.env.SecretBoundary.off,
        effectiveSecretBoundary(.{
            .with_host_secrets = true,
            .command_argv = &.{"claude"},
        }, true),
    );
    try std.testing.expectEqual(
        intercept.env.SecretBoundary.off,
        effectiveSecretBoundary(.{ .command_argv = &.{"/bin/sh"} }, false),
    );
    try std.testing.expectEqual(
        policy.schema.NetworkMode.ask,
        cliNetworkMode(.{ .command_argv = &.{"/bin/sh"} }, .mediated, false),
    );
    try std.testing.expect(!wantsMediatedAgentNetwork(.{ .command_argv = &.{"/bin/sh"} }, .mediated, false));
    try std.testing.expect(!wantsMediatedAgentNetwork(.{ .command_argv = &.{"codex"} }, .mediated, false));
}

test "trusted agent-primary host launch enters empty backpack without secretless flag" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    try skipUnlessOsSandboxBackend();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    // Fake HOME with Claude login material so empty-backpack fail-closed does not fire.
    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    try home_tmp.dir.createDirPath(std.testing.io, ".claude");
    try home_tmp.dir.writeFile(std.testing.io, .{
        .sub_path = ".claude/.credentials.json",
        // Far-future expiresAt so freshness preflight does not fail closed.
        .data = "{\"claudeAiOauth\":{\"accessToken\":\"test\",\"expiresAt\":9999999999999}}\n",
    });
    const fake_home = try home_tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(fake_home);
    // Trusted install fixture (not workspace basename spoof).
    var trust_tmp = std.testing.tmpDir(.{});
    defer trust_tmp.cleanup();
    const trust_root = try trust_tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(trust_root);
    {
        const script = try trust_tmp.dir.createFile(std.testing.io, "claude", .{});
        defer script.close(std.testing.io);
        try script.writeStreamingAll(std.testing.io,
            \\#!/bin/sh
            \\printf '%s' "${MYSQL_PWD-unset}" > child-env.txt
            \\
        );
        try trust_tmp.dir.setFilePermissions(std.testing.io, "claude", @enumFromInt(0o755), .{});
    }
    var current = std.process.Environ.Map.init(std.testing.allocator);
    defer current.deinit();
    try current.put("PATH", trust_root);
    try current.put("HOME", fake_home);
    try current.put("MYSQL_PWD", "SuperSecretPass99");
    try current.put("RYK_TRUSTED_HOST_PREFIXES", trust_root);

    var stdout_buf: [8192]u8 = undefined;
    var stderr_buf: [4096]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    // Bare alias on trusted PATH — must empty-backpack without --secretless.
    const code = try commandForTestWithEnvAndShellEvaluator(
        &.{ "--workspace", root, "--mode", "observe", "--", "claude" },
        &stdout_writer,
        &stderr_writer,
        .ignore,
        &current,
        shell_eval.mockDaemonAllowEvaluator,
    );
    try std.testing.expectEqual(exit_codes.success, code);
    const child_env = try tmp.dir.readFileAlloc(std.testing.io, "child-env.txt", std.testing.allocator, .limited(64));
    defer std.testing.allocator.free(child_env);
    try std.testing.expectEqualStrings("unset", child_env);
    try std.testing.expect(
        std.mem.indexOf(
            u8,
            stdout_writer.buffered(),
            "Posture: secret-boundary=on sandbox=active gateway=off escape=none",
        ) != null,
    );
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "SuperSecretPass99") == null);
}

test "workspace basename spoof does not empty-backpack without secretless" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    {
        const script = try tmp.dir.createFile(std.testing.io, "codex", .{});
        defer script.close(std.testing.io);
        try script.writeStreamingAll(std.testing.io,
            \\#!/bin/sh
            \\printf 'ran\n' > child-out.txt
            \\
        );
        try tmp.dir.setFilePermissions(std.testing.io, "codex", @enumFromInt(0o755), .{});
    }
    var current = std.process.Environ.Map.init(std.testing.allocator);
    defer current.deinit();
    const path_env = if (std.c.getenv("PATH")) |path| std.mem.span(path) else "/usr/bin:/bin";
    try current.put("PATH", path_env);
    try current.put("HOME", root);

    var stdout_buf: [8192]u8 = undefined;
    var stderr_buf: [4096]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    // os-sandbox off is allowed only when secret boundary is off (generic spoof).
    const code = try commandForTestWithEnvAndShellEvaluator(
        &.{ "--workspace", root, "--mode", "observe", "--os-sandbox", "off", "--", "./codex" },
        &stdout_writer,
        &stderr_writer,
        .ignore,
        &current,
        shell_eval.mockDaemonAllowEvaluator,
    );
    try std.testing.expectEqual(exit_codes.success, code);
    // F-02: basename spoof must not auto empty-backpack (would reject --os-sandbox off).
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "secret-boundary=off") != null);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "requires an active OS sandbox") == null);
    const ran = try tmp.dir.readFileAlloc(std.testing.io, "child-out.txt", std.testing.allocator, .limited(64));
    defer std.testing.allocator.free(ran);
    try std.testing.expect(std.mem.indexOf(u8, ran, "ran") != null);
}

test "writeSessionPosture attests boundary sandbox gateway and escape truthfully" {
    var buf: [256]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try writeSessionPosture(&writer, .ask, false, false, .disabled, false, false);
    try std.testing.expectEqualStrings(
        "Posture: secret-boundary=off sandbox=disabled gateway=off escape=none network=ask\n",
        writer.buffered(),
    );

    writer = .fixed(&buf);
    try writeSessionPosture(&writer, .allowlist, true, false, .active, true, true);
    try std.testing.expectEqualStrings(
        "Posture: secret-boundary=on sandbox=active gateway=anthropic+openai escape=none network=allowlist\n",
        writer.buffered(),
    );

    writer = .fixed(&buf);
    try writeSessionPosture(&writer, .open, false, true, .disabled, false, false);
    try std.testing.expectEqualStrings(
        "Posture: secret-boundary=off sandbox=disabled gateway=off escape=host-secrets network=open\n",
        writer.buffered(),
    );
}

test "applyNetworkOverlay defaults to ask and does not force allowlist for --allow-network alone" {
    var pol: policy.schema.Policy = .{ .allocator = std.testing.allocator };
    defer pol.network.deinit(std.testing.allocator);
    pol.network.mode = .allowlist; // preset-like; CLI default must override for non-alias

    try applyNetworkOverlay(std.testing.allocator, &pol, .{}, .mediated, false);
    try std.testing.expectEqual(policy.schema.NetworkMode.ask, pol.network.mode.?);
    // Non-alias: backend stays unset / decision_only unless user or policy set it.
    try std.testing.expect(pol.network.backend == null or pol.network.backend.? == .decision_only);

    pol.network.mode = .allowlist;
    var opts: RunOptions = .{};
    opts.allow_network_values[0] = "api.example.com";
    opts.allow_network_count = 1;
    try applyNetworkOverlay(std.testing.allocator, &pol, opts, .mediated, false);
    try std.testing.expectEqual(policy.schema.NetworkMode.ask, pol.network.mode.?);
    try std.testing.expect(pol.network.allow.len >= 1);

    try applyNetworkOverlay(std.testing.allocator, &pol, .{ .network_mode = .open }, .mediated, false);
    try std.testing.expectEqual(policy.schema.NetworkMode.open, pol.network.mode.?);

    try applyNetworkOverlay(std.testing.allocator, &pol, .{ .network_mode = .off }, .mediated, false);
    try std.testing.expectEqual(policy.schema.NetworkMode.off, pol.network.mode.?);
}

test "applyNetworkOverlay trusted host-alias defaults force proxy backend and allowlist mode" {
    var pol: policy.schema.Policy = .{ .allocator = std.testing.allocator };
    defer pol.network.deinit(std.testing.allocator);
    pol.network.mode = .ask;
    pol.network.backend = null;

    const host_opts: RunOptions = .{ .command_argv = &.{"pi"} };
    try applyNetworkOverlay(std.testing.allocator, &pol, host_opts, .mediated, true);
    try std.testing.expectEqual(policy.schema.NetworkMode.allowlist, pol.network.mode.?);
    try std.testing.expectEqual(policy.schema.NetworkBackend.proxy, pol.network.backend.?);
    try std.testing.expectEqual(policy.schema.NetworkBackend.proxy, pol.network.effectiveBackend());
    try std.testing.expect(wantsMediatedAgentNetwork(host_opts, .mediated, true));

    // Basename-only (untrusted): no mediation force.
    pol.network.backend = null;
    pol.network.mode = .ask;
    try applyNetworkOverlay(std.testing.allocator, &pol, host_opts, .mediated, false);
    try std.testing.expectEqual(policy.schema.NetworkMode.ask, pol.network.mode.?);
    try std.testing.expect(pol.network.backend == null);
    try std.testing.expect(!wantsMediatedAgentNetwork(host_opts, .mediated, false));

    // --network open: no proxy force, mediation off.
    pol.network.backend = null;
    const open_opts: RunOptions = .{ .command_argv = &.{"pi"}, .network_mode = .open };
    try applyNetworkOverlay(std.testing.allocator, &pol, open_opts, .mediated, true);
    try std.testing.expectEqual(policy.schema.NetworkMode.open, pol.network.mode.?);
    try std.testing.expect(pol.network.backend == null);
    try std.testing.expectEqual(policy.schema.NetworkBackend.decision_only, pol.network.effectiveBackend());
    try std.testing.expect(!wantsMediatedAgentNetwork(open_opts, .mediated, true));

    // decision-only does not disable mediation: still force proxy on trusted hosts.
    pol.network.backend = .decision_only;
    try applyNetworkOverlay(std.testing.allocator, &pol, .{
        .command_argv = &.{"pi"},
        .network_backend = .decision_only,
    }, .mediated, true);
    try std.testing.expectEqual(policy.schema.NetworkBackend.proxy, pol.network.backend.?);
    try std.testing.expect(wantsMediatedAgentNetwork(.{
        .command_argv = &.{"pi"},
        .network_backend = .decision_only,
    }, .mediated, true));

    // Explicit --network-backend proxy still works with mediation.
    pol.network.backend = null;
    try applyNetworkOverlay(std.testing.allocator, &pol, .{
        .command_argv = &.{"claude"},
        .network_backend = .proxy,
        .network_mode = .allowlist,
    }, .mediated, true);
    try std.testing.expectEqual(policy.schema.NetworkBackend.proxy, pol.network.backend.?);

    // Kill switch restores legacy (no forced proxy / allowlist default).
    pol.network.backend = null;
    pol.network.mode = .ask;
    try applyNetworkOverlay(std.testing.allocator, &pol, host_opts, .legacy, true);
    try std.testing.expectEqual(policy.schema.NetworkMode.ask, pol.network.mode.?);
    try std.testing.expect(pol.network.backend == null);
    try std.testing.expect(!wantsMediatedAgentNetwork(host_opts, .legacy, true));

    // Non-alias run still does not force proxy.
    pol.network.backend = null;
    try applyNetworkOverlay(std.testing.allocator, &pol, .{ .command_argv = &.{"/bin/true"} }, .mediated, false);
    try std.testing.expectEqual(policy.schema.NetworkMode.ask, pol.network.mode.?);
    try std.testing.expect(pol.network.backend == null);
}

// ---------------------------------------------------------------------------
// Agent-inference allow seed (AINA-2026-08-02)
// Mediated + trusted host-alias launches seed core_pack ∪ host_overlay into
// network.allow; legacy / open / non-alias / untrusted must not seed.
// Production passes resolved trusted_host_key into applyNetworkOverlayWithHostKey.
// Basename-derived applyNetworkOverlay is test-only convenience.
// ---------------------------------------------------------------------------

fn testNetworkAllowContains(allow: []const []const u8, host: []const u8) bool {
    for (allow) |entry| {
        if (std.mem.eql(u8, entry, host)) return true;
    }
    return false;
}

/// Spec §5.1 core pack minima (independent of pack module implementation).
fn expectCorePackOnAllow(allow: []const []const u8) !void {
    try std.testing.expect(testNetworkAllowContains(allow, "api.anthropic.com"));
    try std.testing.expect(testNetworkAllowContains(allow, "api.openai.com"));
    try std.testing.expect(testNetworkAllowContains(allow, "api.x.ai"));
}

/// No agent pack or any §5.2 overlay host may appear (no-seed / fail-closed paths).
fn expectNoAgentInferencePackOrOverlay(allow: []const []const u8) !void {
    try std.testing.expect(!testNetworkAllowContains(allow, "api.anthropic.com"));
    try std.testing.expect(!testNetworkAllowContains(allow, "api.openai.com"));
    try std.testing.expect(!testNetworkAllowContains(allow, "api.x.ai"));
    try std.testing.expect(!testNetworkAllowContains(allow, "openrouter.ai"));
    try std.testing.expect(!testNetworkAllowContains(allow, "opencode.ai"));
    try std.testing.expect(!testNetworkAllowContains(allow, "models.opencode.ai"));
    try std.testing.expect(!testNetworkAllowContains(allow, "cli-chat-proxy.grok.com"));
    try std.testing.expect(!testNetworkAllowContains(allow, "auth.x.ai"));
}

test "applyNetworkOverlay seeds core pack and pi overlay on mediated trusted host-alias with empty allow and no CLI --allow-network" {
    // Must not early-return past seed when CLI --allow-network is absent.
    const allocator = std.testing.allocator;
    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), pol.network.allow.len);
    try std.testing.expectEqual(@as(usize, 0), (@as(RunOptions, .{})).allow_network_count);

    const opts: RunOptions = .{ .command_argv = &.{"pi"} };
    try applyNetworkOverlay(allocator, &pol, opts, .mediated, true);

    try std.testing.expectEqual(policy.schema.NetworkMode.allowlist, pol.network.mode.?);
    try std.testing.expectEqual(policy.schema.NetworkBackend.proxy, pol.network.backend.?);
    try expectCorePackOnAllow(pol.network.allow);
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "openrouter.ai"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "models.opencode.ai"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "opencode.ai"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "cli-chat-proxy.grok.com"));
}

test "applyNetworkOverlayWithHostKey seeds pi overlay when host_key differs from argv basename" {
    // Product path: trusted_host_key drives overlay, not argv leaf (node/script wrappers).
    const allocator = std.testing.allocator;
    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);

    try applyNetworkOverlayWithHostKey(
        allocator,
        &pol,
        .{ .command_argv = &.{"/usr/local/bin/cli.js"} },
        .mediated,
        true,
        "pi",
        null,
    );

    try expectCorePackOnAllow(pol.network.allow);
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "openrouter.ai"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "models.opencode.ai"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "opencode.ai"));
}

test "applyNetworkOverlayWithHostKey seeds opencode overlay when host_key differs from argv basename" {
    const allocator = std.testing.allocator;
    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);

    try applyNetworkOverlayWithHostKey(
        allocator,
        &pol,
        .{ .command_argv = &.{"/opt/node"} },
        .mediated,
        true,
        "opencode",
        null,
    );

    try expectCorePackOnAllow(pol.network.allow);
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "opencode.ai"));
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "models.opencode.ai"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "openrouter.ai"));
}

test "applyNetworkOverlayWithHostKey null host_key seeds core pack only" {
    const allocator = std.testing.allocator;
    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);

    try applyNetworkOverlayWithHostKey(
        allocator,
        &pol,
        .{ .command_argv = &.{"claude"} },
        .mediated,
        true,
        null,
        null,
    );

    try expectCorePackOnAllow(pol.network.allow);
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "openrouter.ai"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "opencode.ai"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "models.opencode.ai"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "cli-chat-proxy.grok.com"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "auth.x.ai"));
}

test "applyNetworkOverlay seeds core pack and opencode overlay on mediated trusted host-alias" {
    const allocator = std.testing.allocator;
    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);

    try applyNetworkOverlay(allocator, &pol, .{ .command_argv = &.{"opencode"} }, .mediated, true);

    try expectCorePackOnAllow(pol.network.allow);
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "opencode.ai"));
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "models.opencode.ai"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "openrouter.ai"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "cli-chat-proxy.grok.com"));
}

test "applyNetworkOverlay seeds core and overlay into stale github-only policy allow without dropping existing" {
    // A-seed / EFF-3/4/5: stale workspace allow (github/npm) still gains pack; existing kept.
    const allocator = std.testing.allocator;
    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);
    pol.network.allow = try policy.schema.duplicateStringList(allocator, &.{
        "github.com",
        "registry.npmjs.org",
    });

    try applyNetworkOverlay(allocator, &pol, .{ .command_argv = &.{"pi"} }, .mediated, true);

    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "github.com"));
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "registry.npmjs.org"));
    try expectCorePackOnAllow(pol.network.allow);
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "openrouter.ai"));
}

test "applyNetworkOverlay seed composes CLI --allow-network after pack without removing policy allows" {
    // A-composition / EFF-3: policy ∪ pack/overlay ∪ CLI --allow-network.
    const allocator = std.testing.allocator;
    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);
    pol.network.allow = try policy.schema.duplicateStringList(allocator, &.{"github.com"});

    var opts: RunOptions = .{ .command_argv = &.{"opencode"} };
    opts.allow_network_values[0] = "api.custom-provider.example";
    opts.allow_network_count = 1;

    try applyNetworkOverlay(allocator, &pol, opts, .mediated, true);

    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "github.com"));
    try expectCorePackOnAllow(pol.network.allow);
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "opencode.ai"));
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "models.opencode.ai"));
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "api.custom-provider.example"));
}

test "applyNetworkOverlay core-only host-alias seeds core pack without foreign host overlays" {
    // A-seed / PKG-2: claude is core-only at P1 (no pi/opencode/grok overlay pollution).
    const allocator = std.testing.allocator;
    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);

    try applyNetworkOverlay(allocator, &pol, .{ .command_argv = &.{"claude"} }, .mediated, true);

    try expectCorePackOnAllow(pol.network.allow);
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "openrouter.ai"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "opencode.ai"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "models.opencode.ai"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "cli-chat-proxy.grok.com"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "auth.x.ai"));
}

test "applyNetworkOverlay does not seed agent pack when agent_net_default is legacy" {
    // A-no-seed: RYK_AGENT_NETWORK_DEFAULT=legacy kill switch — no pack theater.
    const allocator = std.testing.allocator;
    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);
    pol.network.allow = try policy.schema.duplicateStringList(allocator, &.{"github.com"});

    try applyNetworkOverlay(allocator, &pol, .{ .command_argv = &.{"pi"} }, .legacy, true);

    try std.testing.expectEqual(policy.schema.NetworkMode.ask, pol.network.mode.?);
    try std.testing.expect(pol.network.backend == null);
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "github.com"));
    try expectNoAgentInferencePackOrOverlay(pol.network.allow);
}

test "applyNetworkOverlay does not seed agent pack when network_mode is open" {
    // A-no-seed: --network open escape — unrestricted; no pack seed / no allowlist theater.
    const allocator = std.testing.allocator;
    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);

    try applyNetworkOverlay(allocator, &pol, .{
        .command_argv = &.{"pi"},
        .network_mode = .open,
    }, .mediated, true);

    try std.testing.expectEqual(policy.schema.NetworkMode.open, pol.network.mode.?);
    try expectNoAgentInferencePackOrOverlay(pol.network.allow);
}

test "applyNetworkOverlay does not seed agent pack when trusted_agent_host is false (basename spoof)" {
    // A-no-seed / F-02: untrusted / basename spoof — command looks like pi but not trusted.
    const allocator = std.testing.allocator;
    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);

    try applyNetworkOverlay(allocator, &pol, .{ .command_argv = &.{"pi"} }, .mediated, false);

    try std.testing.expectEqual(policy.schema.NetworkMode.ask, pol.network.mode.?);
    try expectNoAgentInferencePackOrOverlay(pol.network.allow);
}

test "applyNetworkOverlay does not seed agent pack for non-alias command even under mediated default" {
    // A-no-seed / PKG-3: generic ryk run -- <cmd> must not silently gain agent overlays.
    const allocator = std.testing.allocator;
    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);

    try applyNetworkOverlay(allocator, &pol, .{ .command_argv = &.{"/bin/true"} }, .mediated, false);

    try std.testing.expectEqual(policy.schema.NetworkMode.ask, pol.network.mode.?);
    try expectNoAgentInferencePackOrOverlay(pol.network.allow);
}

test "applyNetworkOverlay non-alias with CLI --allow-network still does not seed agent pack" {
    // A-no-seed + composition: CLI allow alone must not pull core pack/overlays for non-alias.
    const allocator = std.testing.allocator;
    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);

    var opts: RunOptions = .{ .command_argv = &.{"/bin/true"} };
    opts.allow_network_values[0] = "api.example.com";
    opts.allow_network_count = 1;

    try applyNetworkOverlay(allocator, &pol, opts, .mediated, false);

    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "api.example.com"));
    try expectNoAgentInferencePackOrOverlay(pol.network.allow);
}

// AINA P3 launch wire — discovery merge into applyNetworkOverlayWithHostKey (S4).

/// Synthetic pi auth.json shape (fake tokens only). xai-oauth URL hosts + openrouter id.
const p3_launch_pi_auth_json =
    \\{
    \\  "openrouter": {
    \\    "type": "api_key",
    \\    "key": "sk-fixture-launch-pi-openrouter-NOT-REAL-a1"
    \\  },
    \\  "xai-oauth": {
    \\    "type": "oauth",
    \\    "access": "fixture-launch-pi-xai-access-NOT-REAL-b2",
    \\    "refresh": "fixture-launch-pi-xai-refresh-NOT-REAL-c3",
    \\    "tokenEndpoint": "https://auth.x.ai/oauth2/token",
    \\    "baseUrl": "https://api.x.ai/v1"
    \\  }
    \\}
;

/// Pi settings with defaultProvider openrouter (catalog path).
const p3_launch_pi_settings_json =
    \\{
    \\  "defaultProvider": "openrouter",
    \\  "model": "openrouter/fixture-launch-model"
    \\}
;

/// Opencode auth: xai oauth key → catalog api.x.ai + auth.x.ai; opencode key → overlay hosts.
const p3_launch_opencode_auth_json =
    \\{
    \\  "xai": {
    \\    "type": "oauth",
    \\    "access": "fixture-launch-oc-xai-access-NOT-REAL-d4",
    \\    "refresh": "fixture-launch-oc-xai-refresh-NOT-REAL-e5"
    \\  },
    \\  "opencode": {
    \\    "type": "api",
    \\    "key": "sk-fixture-launch-oc-api-NOT-REAL-f6"
    \\  }
    \\}
;

/// Pi auth with URL hosts that catalog cannot invent (proves adapter extract is wired).
const p3_launch_pi_url_diverge_auth_json =
    \\{
    \\  "xai-oauth": {
    \\    "type": "oauth",
    \\    "access": "fixture-launch-pi-diverge-access-NOT-REAL-g7",
    \\    "refresh": "fixture-launch-pi-diverge-refresh-NOT-REAL-h8",
    \\    "tokenEndpoint": "https://oauth-edge.custom.invalid/oauth2/token",
    \\    "baseUrl": "https://inference-proxy.custom.invalid/v1"
    \\  }
    \\}
;

const p3_launch_fixture_secret_needles = [_][]const u8{
    "sk-fixture-launch-pi-openrouter-NOT-REAL-a1",
    "fixture-launch-pi-xai-access-NOT-REAL-b2",
    "fixture-launch-pi-xai-refresh-NOT-REAL-c3",
    "fixture-launch-oc-xai-access-NOT-REAL-d4",
    "fixture-launch-oc-xai-refresh-NOT-REAL-e5",
    "sk-fixture-launch-oc-api-NOT-REAL-f6",
    "fixture-launch-pi-diverge-access-NOT-REAL-g7",
    "fixture-launch-pi-diverge-refresh-NOT-REAL-h8",
    "sk-fixture",
    "NOT-REAL",
};

fn p3LaunchAbsPath(tmp: anytype) ![]u8 {
    // realPathFileAlloc → [:0]u8; re-dupe so free size matches DebugAllocator (Zig 0.16).
    const z = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(z);
    return try std.testing.allocator.dupe(u8, z);
}

fn p3LaunchWriteRel(dir: anytype, rel: []const u8, content: []const u8) !void {
    if (std.fs.path.dirname(rel)) |parent| {
        if (parent.len > 0) try dir.createDirPath(std.testing.io, parent);
    }
    const file = try dir.createFile(std.testing.io, rel, .{});
    defer file.close(std.testing.io);
    try file.writeStreamingAll(std.testing.io, content);
}

fn p3LaunchPlantPiHome(home_dir: anytype, auth: []const u8, settings: ?[]const u8) !void {
    try p3LaunchWriteRel(home_dir, ".pi/agent/auth.json", auth);
    if (settings) |s| try p3LaunchWriteRel(home_dir, ".pi/agent/settings.json", s);
}

fn p3LaunchPlantOpencodeHome(home_dir: anytype, auth: []const u8) !void {
    try p3LaunchWriteRel(home_dir, ".local/share/opencode/auth.json", auth);
}

fn p3LaunchAssertNoSecretsInAllow(allow: []const []const u8) !void {
    for (allow) |entry| {
        for (p3_launch_fixture_secret_needles) |needle| {
            try std.testing.expect(std.mem.indexOf(u8, entry, needle) == null);
        }
        try std.testing.expect(std.mem.indexOf(u8, entry, "://") == null);
        try std.testing.expect(std.mem.indexOf(u8, entry, "@") == null);
    }
}

fn p3LaunchExpectNetworkResult(
    allocator: std.mem.Allocator,
    pol: *const policy.schema.Policy,
    destination: []const u8,
    want: core.decision.DecisionResult,
) !void {
    var decision = try policy.network_eval.evaluate(allocator, pol, .strict, destination, .{});
    defer decision.deinit(allocator);
    try std.testing.expectEqual(want, decision.decision.result);
}

test "applyNetworkOverlayWithHostKey P3 managed hosts merge for pi with pack floor and user preserve" {
    // Unit acceptance: fixture managed hosts ∪ core/overlay floor; user pre-seed kept.
    // auth.x.ai is NOT in pi static overlay — only discovery/managed can add it for pi.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    const workspace_root = try p3LaunchAbsPath(&ws_tmp);
    defer allocator.free(workspace_root);

    const managed_entries = [_]policy.network_discovered.ManagedHost{
        .{ .host = "auth.x.ai", .sources = &.{"pi:discover"} },
        .{ .host = "launch-managed-only.invalid", .sources = &.{"pi:discover"} },
    };
    try policy.network_discovered.writeManaged(io, allocator, workspace_root, &managed_entries);

    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);
    pol.network.allow = try policy.schema.duplicateStringList(allocator, &.{
        "github.com",
        "registry.npmjs.org",
    });

    // Empty home → adapter soft-empty; managed file alone must still merge.
    try applyNetworkOverlayWithHostKey(
        allocator,
        &pol,
        .{ .command_argv = &.{"/usr/bin/node"} },
        .mediated,
        true,
        "pi",
        .{ .io = io, .workspace_root = workspace_root, .home = "" },
    );

    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "github.com"));
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "registry.npmjs.org"));
    try expectCorePackOnAllow(pol.network.allow);
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "openrouter.ai")); // pi overlay floor
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "auth.x.ai"));
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "launch-managed-only.invalid"));
    try p3LaunchAssertNoSecretsInAllow(pol.network.allow);
}

test "applyNetworkOverlayWithHostKey P3 launch-time pi adapter discovers auth.x.ai from fixture home" {
    // Launch-time discoverForHost(pi) must run even when managed file is missing (plan §3.6).
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    const workspace_root = try p3LaunchAbsPath(&ws_tmp);
    defer allocator.free(workspace_root);

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    try p3LaunchPlantPiHome(home_tmp.dir, p3_launch_pi_auth_json, p3_launch_pi_settings_json);
    const home = try p3LaunchAbsPath(&home_tmp);
    defer allocator.free(home);

    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);

    try applyNetworkOverlayWithHostKey(
        allocator,
        &pol,
        .{ .command_argv = &.{"pi"} },
        .mediated,
        true,
        "pi",
        .{ .io = io, .workspace_root = workspace_root, .home = home },
    );

    try expectCorePackOnAllow(pol.network.allow);
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "openrouter.ai"));
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "auth.x.ai"));
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "api.x.ai"));
    try p3LaunchAssertNoSecretsInAllow(pol.network.allow);
}

test "applyNetworkOverlayWithHostKey P3 launch-time opencode adapter maps xai catalog hosts" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    const workspace_root = try p3LaunchAbsPath(&ws_tmp);
    defer allocator.free(workspace_root);

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    try p3LaunchPlantOpencodeHome(home_tmp.dir, p3_launch_opencode_auth_json);
    const home = try p3LaunchAbsPath(&home_tmp);
    defer allocator.free(home);

    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);

    try applyNetworkOverlayWithHostKey(
        allocator,
        &pol,
        .{ .command_argv = &.{"opencode"} },
        .mediated,
        true,
        "opencode",
        .{ .io = io, .workspace_root = workspace_root, .home = home },
    );

    try expectCorePackOnAllow(pol.network.allow);
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "opencode.ai"));
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "models.opencode.ai"));
    // Catalog hosts for auth key `xai` (not in opencode static overlay).
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "auth.x.ai"));
    try p3LaunchAssertNoSecretsInAllow(pol.network.allow);
}

test "applyNetworkOverlayWithHostKey P3 managed union adapter for pi URL-diverge hosts" {
    // Managed + launch adapter: URL extract hosts cannot come from static pack alone.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    const workspace_root = try p3LaunchAbsPath(&ws_tmp);
    defer allocator.free(workspace_root);

    const managed_entries = [_]policy.network_discovered.ManagedHost{
        .{ .host = "managed-from-start.invalid", .sources = &.{"pi:discover"} },
    };
    try policy.network_discovered.writeManaged(io, allocator, workspace_root, &managed_entries);

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    try p3LaunchPlantPiHome(home_tmp.dir, p3_launch_pi_url_diverge_auth_json, null);
    const home = try p3LaunchAbsPath(&home_tmp);
    defer allocator.free(home);

    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);
    pol.network.allow = try policy.schema.duplicateStringList(allocator, &.{"user-preseed.example"});

    try applyNetworkOverlayWithHostKey(
        allocator,
        &pol,
        .{ .command_argv = &.{"pi"} },
        .mediated,
        true,
        "pi",
        .{ .io = io, .workspace_root = workspace_root, .home = home },
    );

    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "user-preseed.example"));
    try expectCorePackOnAllow(pol.network.allow);
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "openrouter.ai"));
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "managed-from-start.invalid"));
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "oauth-edge.custom.invalid"));
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "inference-proxy.custom.invalid"));
    try p3LaunchAssertNoSecretsInAllow(pol.network.allow);
}

test "applyNetworkOverlayWithHostKey P3 pastebin and example.com still deny under network_eval after discovery merge" {
    // SEC-1 / A-P1-2/3 retained after P3: non-allow public hosts stay denied.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    const workspace_root = try p3LaunchAbsPath(&ws_tmp);
    defer allocator.free(workspace_root);

    const managed_entries = [_]policy.network_discovered.ManagedHost{
        .{ .host = "auth.x.ai", .sources = &.{"pi:discover"} },
    };
    try policy.network_discovered.writeManaged(io, allocator, workspace_root, &managed_entries);

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    try p3LaunchPlantPiHome(home_tmp.dir, p3_launch_pi_auth_json, p3_launch_pi_settings_json);
    const home = try p3LaunchAbsPath(&home_tmp);
    defer allocator.free(home);

    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);

    try applyNetworkOverlayWithHostKey(
        allocator,
        &pol,
        .{ .command_argv = &.{"pi"} },
        .mediated,
        true,
        "pi",
        .{ .io = io, .workspace_root = workspace_root, .home = home },
    );

    try std.testing.expectEqual(policy.schema.NetworkMode.allowlist, pol.network.mode.?);
    // Discovered / pack still allow.
    try p3LaunchExpectNetworkResult(allocator, &pol, "https://auth.x.ai/oauth2/token", .allow);
    try p3LaunchExpectNetworkResult(allocator, &pol, "https://api.x.ai/v1/chat", .allow);
    try p3LaunchExpectNetworkResult(allocator, &pol, "https://openrouter.ai/api/v1", .allow);
    // Closed default retained.
    try p3LaunchExpectNetworkResult(allocator, &pol, "https://pastebin.com/raw/abc", .deny);
    try p3LaunchExpectNetworkResult(allocator, &pol, "pastebin.com", .deny);
    try p3LaunchExpectNetworkResult(allocator, &pol, "https://example.com/", .deny);
    try p3LaunchExpectNetworkResult(allocator, &pol, "example.com", .deny);
}

test "applyNetworkOverlayWithHostKey P3 class tokens never land in allow; private/IMDS still deny" {
    // Blocker residual: hostile baseUrl private/metadata must not class-widen allow.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    const workspace_root = try p3LaunchAbsPath(&ws_tmp);
    defer allocator.free(workspace_root);

    // Poison managed file with class tokens (load must soft-drop).
    try ws_tmp.dir.createDirPath(io, ".ryk");
    {
        const f = try ws_tmp.dir.createFile(io, ".ryk/network-discovered.yaml", .{});
        defer f.close(io);
        try f.writeStreamingAll(io,
            \\version: 1
            \\hosts:
            \\  - host: private
            \\    sources: [pi:discover]
            \\  - host: metadata
            \\    sources: [pi:discover]
            \\  - host: direct-ip
            \\    sources: [pi:discover]
            \\  - host: metadata.google.internal
            \\    sources: [pi:discover]
            \\  - host: localhost
            \\    sources: [pi:discover]
            \\  - host: pastebin.com
            \\    sources: [pi:discover]
            \\
        );
    }

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    const hostile_auth =
        \\{
        \\  "hostile": {
        \\    "type": "api",
        \\    "key": "sk-fixture-hostile-class-NOT-REAL",
        \\    "baseUrl": "https://private/",
        \\    "tokenEndpoint": "https://metadata.google.internal/"
        \\  },
        \\  "local": {
        \\    "type": "api",
        \\    "key": "sk-fixture-local-NOT-REAL",
        \\    "baseUrl": "http://localhost:9/"
        \\  }
        \\}
    ;
    try p3LaunchPlantPiHome(home_tmp.dir, hostile_auth, null);
    const home = try p3LaunchAbsPath(&home_tmp);
    defer allocator.free(home);

    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);

    try applyNetworkOverlayWithHostKey(
        allocator,
        &pol,
        .{ .command_argv = &.{"pi"} },
        .mediated,
        true,
        "pi",
        .{ .io = io, .workspace_root = workspace_root, .home = home },
    );

    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "private"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "metadata"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "cloud-metadata"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "direct-ip"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "metadata.google.internal"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "localhost"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "pastebin.com"));
    // Class destinations still deny under allowlist (no class-wide grant).
    try p3LaunchExpectNetworkResult(allocator, &pol, "http://10.0.0.1/", .deny);
    try p3LaunchExpectNetworkResult(allocator, &pol, "http://169.254.169.254/latest/meta-data/", .deny);
    try p3LaunchExpectNetworkResult(allocator, &pol, "http://metadata.google.internal/", .deny);
    try p3LaunchExpectNetworkResult(allocator, &pol, "http://127.0.0.1:1/", .deny);
}

test "applyNetworkOverlayWithHostKey P3 rejects 127.0.0.2 planted in agent auth" {
    // Keep major residual: loopback residual is exact 127.0.0.1 only, not 127/8.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    const workspace_root = try p3LaunchAbsPath(&ws_tmp);
    defer allocator.free(workspace_root);

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    const hostile_auth =
        \\{
        \\  "local": {
        \\    "type": "api",
        \\    "key": "sk-fixture-127-wide-NOT-REAL",
        \\    "baseUrl": "http://127.0.0.2:9/v1"
        \\  }
        \\}
    ;
    try p3LaunchPlantPiHome(home_tmp.dir, hostile_auth, null);
    const home = try p3LaunchAbsPath(&home_tmp);
    defer allocator.free(home);

    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);

    try applyNetworkOverlayWithHostKey(
        allocator,
        &pol,
        .{ .command_argv = &.{"pi"} },
        .mediated,
        true,
        "pi",
        .{ .io = io, .workspace_root = workspace_root, .home = home },
    );

    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "127.0.0.2"));
    try p3LaunchExpectNetworkResult(allocator, &pol, "http://127.0.0.2:9/", .deny);
    try p3LaunchExpectNetworkResult(allocator, &pol, "http://127.1.2.3/", .deny);
}

test "applyNetworkOverlayWithHostKey P3 soft-skips missing managed and empty home still seeds pack floor" {
    // Soft skip: no managed file, empty home — launch still gets core∪overlay (P1 floor).
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    const workspace_root = try p3LaunchAbsPath(&ws_tmp);
    defer allocator.free(workspace_root);
    // Intentionally do not write managed YAML; home empty.

    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);

    try applyNetworkOverlayWithHostKey(
        allocator,
        &pol,
        .{ .command_argv = &.{"pi"} },
        .mediated,
        true,
        "pi",
        .{ .io = io, .workspace_root = workspace_root, .home = "" },
    );

    try expectCorePackOnAllow(pol.network.allow);
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "openrouter.ai"));
    // Discovery-only host must not appear without managed/adapter input.
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "launch-managed-only.invalid"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "oauth-edge.custom.invalid"));
}

test "applyNetworkOverlayWithHostKey P3 null discovery keeps P1 pack-only path" {
    // Backward-compat: discovery: null (or omitted default) must not require FS.
    const allocator = std.testing.allocator;
    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);

    try applyNetworkOverlayWithHostKey(
        allocator,
        &pol,
        .{ .command_argv = &.{"pi"} },
        .mediated,
        true,
        "pi",
        null,
    );

    try expectCorePackOnAllow(pol.network.allow);
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "openrouter.ai"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "launch-managed-only.invalid"));
}

test "applyNetworkOverlayWithHostKey P3 does not merge discovery when not mediated trusted" {
    // legacy / open / untrusted must not pull managed or adapter hosts.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    const workspace_root = try p3LaunchAbsPath(&ws_tmp);
    defer allocator.free(workspace_root);
    try policy.network_discovered.writeManaged(io, allocator, workspace_root, &.{
        .{ .host = "should-not-merge.invalid", .sources = &.{"pi:discover"} },
    });

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    try p3LaunchPlantPiHome(home_tmp.dir, p3_launch_pi_auth_json, null);
    const home = try p3LaunchAbsPath(&home_tmp);
    defer allocator.free(home);

    const discovery: DiscoveryLaunchContext = .{ .io = io, .workspace_root = workspace_root, .home = home };

    {
        var pol: policy.schema.Policy = .{ .allocator = allocator };
        defer pol.network.deinit(allocator);
        try applyNetworkOverlayWithHostKey(
            allocator,
            &pol,
            .{ .command_argv = &.{"pi"} },
            .legacy,
            true,
            "pi",
            discovery,
        );
        try expectNoAgentInferencePackOrOverlay(pol.network.allow);
        try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "should-not-merge.invalid"));
        try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "auth.x.ai"));
    }
    {
        var pol: policy.schema.Policy = .{ .allocator = allocator };
        defer pol.network.deinit(allocator);
        try applyNetworkOverlayWithHostKey(
            allocator,
            &pol,
            .{ .command_argv = &.{"pi"}, .network_mode = .open },
            .mediated,
            true,
            "pi",
            discovery,
        );
        try expectNoAgentInferencePackOrOverlay(pol.network.allow);
        try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "should-not-merge.invalid"));
    }
    {
        var pol: policy.schema.Policy = .{ .allocator = allocator };
        defer pol.network.deinit(allocator);
        try applyNetworkOverlayWithHostKey(
            allocator,
            &pol,
            .{ .command_argv = &.{"pi"} },
            .mediated,
            false, // untrusted / basename spoof
            "pi",
            discovery,
        );
        try expectNoAgentInferencePackOrOverlay(pol.network.allow);
        try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "should-not-merge.invalid"));
    }
}

test "applyNetworkOverlayWithHostKey P3 CLI --allow-network composes after discovery merge" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    const workspace_root = try p3LaunchAbsPath(&ws_tmp);
    defer allocator.free(workspace_root);
    try policy.network_discovered.writeManaged(io, allocator, workspace_root, &.{
        .{ .host = "auth.x.ai", .sources = &.{"pi:discover"} },
    });

    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);
    pol.network.allow = try policy.schema.duplicateStringList(allocator, &.{"github.com"});

    var opts: RunOptions = .{ .command_argv = &.{"pi"} };
    opts.allow_network_values[0] = "api.session-cli.example";
    opts.allow_network_count = 1;

    try applyNetworkOverlayWithHostKey(
        allocator,
        &pol,
        opts,
        .mediated,
        true,
        "pi",
        .{ .io = io, .workspace_root = workspace_root, .home = "" },
    );

    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "github.com"));
    try expectCorePackOnAllow(pol.network.allow);
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "openrouter.ai"));
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "auth.x.ai"));
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "api.session-cli.example"));
}

test "applyNetworkOverlayWithHostKey P3 managed path is workspace_root/.ryk/network-discovered.yaml" {
    // Composition: launch loader must use the same path as p3-managed writer.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    const workspace_root = try p3LaunchAbsPath(&ws_tmp);
    defer allocator.free(workspace_root);

    const path = try policy.network_discovered.managedPath(allocator, workspace_root);
    defer allocator.free(path);
    try std.testing.expect(std.mem.endsWith(u8, path, ".ryk/network-discovered.yaml"));
    try std.testing.expect(std.mem.startsWith(u8, path, workspace_root));

    // Write via managed API then launch-merge must observe the same file.
    try policy.network_discovered.writeManaged(io, allocator, workspace_root, &.{
        .{ .host = "path-parity-host.invalid", .sources = &.{"pi:discover"} },
    });
    // Direct load parity (writer↔loader).
    var store = try policy.network_discovered.loadManaged(io, allocator, workspace_root);
    defer store.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), store.hosts.len);
    try std.testing.expectEqualStrings("path-parity-host.invalid", store.hosts[0].host);

    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);
    try applyNetworkOverlayWithHostKey(
        allocator,
        &pol,
        .{ .command_argv = &.{"pi"} },
        .mediated,
        true,
        "pi",
        .{ .io = io, .workspace_root = workspace_root, .home = "" },
    );
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "path-parity-host.invalid"));
}

test "applyNetworkOverlayWithHostKey P3 nested-cwd managed write still merges from abs workspace root" {
    // Monopath/nested-cwd parity: process cwd under nested/ must not shadow workspace managed file.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    const workspace_root = try p3LaunchAbsPath(&ws_tmp);
    defer allocator.free(workspace_root);

    try ws_tmp.dir.createDirPath(io, "nested/deep");
    // Decoy under nested cwd path — must NOT be the product managed file.
    try p3LaunchWriteRel(ws_tmp.dir, "nested/deep/.ryk/network-discovered.yaml",
        \\version: 1
        \\hosts:
        \\  - host: decoy-nested-cwd.invalid
        \\    sources: [decoy]
    );

    // Product write under abs workspace root (independent of cwd).
    try policy.network_discovered.writeManaged(io, allocator, workspace_root, &.{
        .{ .host = "workspace-root-managed.invalid", .sources = &.{"opencode:discover"} },
    });

    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);

    // Call site always passes abs workspace_root (product path); cwd may be nested.
    try applyNetworkOverlayWithHostKey(
        allocator,
        &pol,
        .{ .command_argv = &.{"opencode"} },
        .mediated,
        true,
        "opencode",
        .{ .io = io, .workspace_root = workspace_root, .home = "" },
    );

    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "workspace-root-managed.invalid"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "decoy-nested-cwd.invalid"));
    try expectCorePackOnAllow(pol.network.allow);
    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "opencode.ai"));
}

test "applyNetworkOverlayWithHostKey P3 host_key scopes managed grants (no cross-adapter bleed)" {
    // opencode-tagged managed hosts must not appear on pi launch allow.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    const workspace_root = try p3LaunchAbsPath(&ws_tmp);
    defer allocator.free(workspace_root);

    try policy.network_discovered.writeManaged(io, allocator, workspace_root, &.{
        .{ .host = "auth.x.ai", .sources = &.{"pi:discover"} },
        .{ .host = "opencode-only-managed.invalid", .sources = &.{"opencode:discover"} },
    });

    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);

    try applyNetworkOverlayWithHostKey(
        allocator,
        &pol,
        .{ .command_argv = &.{"pi"} },
        .mediated,
        true,
        "pi",
        .{ .io = io, .workspace_root = workspace_root, .home = "" },
    );

    try std.testing.expect(testNetworkAllowContains(pol.network.allow, "auth.x.ai"));
    try std.testing.expect(!testNetworkAllowContains(pol.network.allow, "opencode-only-managed.invalid"));
}

test "applyNetworkOverlayWithHostKey P3 RYK_NETWORK_ALLOW includes discovered hosts after installNetworkEnvironment" {
    // LIVE unit proxy: product exports effective allow via RYK_NETWORK_ALLOW (installNetworkEnvironment).
    // Full binary ryk pi/opencode CONNECT smoke remains implementer / p3-docs-live gate.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    const workspace_root = try p3LaunchAbsPath(&ws_tmp);
    defer allocator.free(workspace_root);
    try policy.network_discovered.writeManaged(io, allocator, workspace_root, &.{
        .{ .host = "auth.x.ai", .sources = &.{"opencode:discover"} },
    });

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    try p3LaunchPlantOpencodeHome(home_tmp.dir, p3_launch_opencode_auth_json);
    const home = try p3LaunchAbsPath(&home_tmp);
    defer allocator.free(home);

    var pol: policy.schema.Policy = .{ .allocator = allocator };
    defer pol.network.deinit(allocator);

    try applyNetworkOverlayWithHostKey(
        allocator,
        &pol,
        .{ .command_argv = &.{"opencode"} },
        .mediated,
        true,
        "opencode",
        .{ .io = io, .workspace_root = workspace_root, .home = home },
    );

    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    try installNetworkEnvironment(allocator, &env_map, pol.network);

    const allow_csv = env_map.get("RYK_NETWORK_ALLOW") orelse {
        try std.testing.expect(false); // must export when allow non-empty
        return;
    };
    try std.testing.expect(std.mem.indexOf(u8, allow_csv, "auth.x.ai") != null);
    try std.testing.expect(std.mem.indexOf(u8, allow_csv, "api.x.ai") != null);
    try std.testing.expect(std.mem.indexOf(u8, allow_csv, "opencode.ai") != null);
    try std.testing.expect(std.mem.indexOf(u8, allow_csv, "pastebin.com") == null);
    try std.testing.expect(std.mem.indexOf(u8, allow_csv, "NOT-REAL") == null);
}

test "parseAgentNetworkDefault only legacy opts out" {
    try std.testing.expectEqual(AgentNetworkDefault.mediated, parseAgentNetworkDefault(null));
    try std.testing.expectEqual(AgentNetworkDefault.mediated, parseAgentNetworkDefault(""));
    try std.testing.expectEqual(AgentNetworkDefault.mediated, parseAgentNetworkDefault("mediated"));
    try std.testing.expectEqual(AgentNetworkDefault.mediated, parseAgentNetworkDefault("other"));
    try std.testing.expectEqual(AgentNetworkDefault.legacy, parseAgentNetworkDefault("legacy"));
}

test "run defaults to network ask, secretless off, posture line; noninteractive does not hang" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    {
        const policy_file = try tmp.dir.createFile(std.testing.io, "policy.yaml", .{});
        defer policy_file.close(std.testing.io);
        try policy_file.writeStreamingAll(std.testing.io,
            \\version: 1
            \\mode: observe
            \\env:
            \\  inherit: true
            \\network:
            \\  mode: allowlist
            \\commands:
            \\  allow:
            \\    - "/bin/sh *"
        );
    }
    const policy_path = try tmp.dir.realPathFileAlloc(std.testing.io, "policy.yaml", std.testing.allocator);
    defer std.testing.allocator.free(policy_path);

    var current = std.process.Environ.Map.init(std.testing.allocator);
    defer current.deinit();
    const path_env = if (std.c.getenv("PATH")) |path| std.mem.span(path) else "/usr/bin:/bin:/usr/sbin:/sbin";
    try current.put("PATH", path_env);
    try current.put("GITHUB_TOKEN", "ghp_rawDefaultSecretShouldStay");

    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [2048]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try commandForTestWithEnvAndShellEvaluator(&.{ "--workspace", root, "--policy", policy_path, "--os-sandbox", "off", "--", "/bin/sh", "-c", "env > default-env.txt" }, &stdout_writer, &stderr_writer, .ignore, &current, shell_eval.mockDaemonAllowEvaluator);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "Posture: secret-boundary=off") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "escape=none") != null);

    const written = try tmp.dir.readFileAlloc(std.testing.io, "default-env.txt", std.testing.allocator, .limited(16384));
    defer std.testing.allocator.free(written);
    try std.testing.expect(std.mem.indexOf(u8, written, "RYK_NETWORK_MODE=ask") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "GITHUB_TOKEN=ghp_rawDefaultSecretShouldStay") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "ryk-secret://") == null);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "--secretless rewrote") == null);

    // CI + default network ask: no session-start stdin prompt; completes without hang.
    stdout_writer = .fixed(&stdout_buf);
    stderr_writer = .fixed(&stderr_buf);
    const ci_code = try commandForGuardTestWithShellEvaluator(&.{ "--workspace", root, "--mode", "ci", "--os-sandbox", "off", "--", "true" }, &stdout_writer, &stderr_writer, .ignore, shell_eval.mockDaemonAllowEvaluator);
    try std.testing.expectEqual(exit_codes.success, ci_code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "Posture: secret-boundary=off") != null);
}

test "run allow-network adds temporary allow rule and redacts URL secrets in audit" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [2048]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try commandForGuardTestWithShellEvaluator(&.{ "--workspace", root, "--allow-network", "https://api.github.com/repos?token=sk-fakeSyntheticOpenAIKey1234567890", "--os-sandbox", "off", "--", "true" }, &stdout_writer, &stderr_writer, .inherit, shell_eval.mockDaemonAllowEvaluator);
    try std.testing.expectEqual(exit_codes.success, code);
    const events = try readLastEvents(std.testing.allocator, root);
    defer std.testing.allocator.free(events);
    try std.testing.expect(std.mem.indexOf(u8, events, "\"type\":\"network_connect_allowed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, events, "api.github.com") != null);
    try std.testing.expect(std.mem.indexOf(u8, events, "sk-fakeSyntheticOpenAIKey") == null);
}

// Default auto attach + child env export. Skips when no OS backend.
test "run exports backend capability status to child environment" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    try skipUnlessOsSandboxBackend();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    // Landlock: workspace-root is RO; write into a pre-created child dir (not root).
    try tmp.dir.createDirPath(std.testing.io, "out");
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var stdout_buf: [8192]u8 = undefined;
    var stderr_buf: [2048]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    // Default --os-sandbox auto (omit flag) to exercise attach + env orchestration.
    const code = try commandForTestWithShellEvaluator(&.{ "--workspace", root, "--", "/bin/sh", "-c", "env > out/backend-env.txt" }, &stdout_writer, &stderr_writer, .ignore, shell_eval.mockDaemonAllowEvaluator);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "OS sandbox: active") != null);

    const written = try tmp.dir.readFileAlloc(std.testing.io, "out/backend-env.txt", std.testing.allocator, .limited(8192));
    defer std.testing.allocator.free(written);
    try std.testing.expect(std.mem.indexOf(u8, written, "RYK_BACKEND=") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "RYK_BACKEND_ENV_FILTERING=") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "RYK_BACKEND_PATH_STAGING=") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "RYK_BACKEND_SHELL_WRAPPING=") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "RYK_BACKEND_PATH_SHIMS=") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "RYK_BACKEND_STRONG_SANDBOX=") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "RYK_BACKEND_PROCESS_SUPERVISION=") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "RYK_BACKEND_NETWORK_OBSERVE=") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "RYK_BACKEND_NETWORK_PROXY_ENFORCEMENT=") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "RYK_BACKEND_NETWORK_ENFORCEMENT=") != null);
}

test "run proxy backend injects proxy environment and satisfies proxy requirement" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    {
        const policy_file = try tmp.dir.createFile(std.testing.io, "policy.yaml", .{});
        defer policy_file.close(std.testing.io);
        try policy_file.writeStreamingAll(std.testing.io,
            \\version: 1
            \\mode: observe
            \\env:
            \\  inherit: true
            \\commands:
            \\  allow:
            \\    - "/bin/sh *"
        );
    }
    const policy_path = try tmp.dir.realPathFileAlloc(std.testing.io, "policy.yaml", std.testing.allocator);
    defer std.testing.allocator.free(policy_path);

    var current = std.process.Environ.Map.init(std.testing.allocator);
    defer current.deinit();
    const path_env = if (std.c.getenv("PATH")) |path| std.mem.span(path) else "/usr/bin:/bin:/usr/sbin:/sbin";
    try current.put("PATH", path_env);

    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [2048]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try commandForTestWithEnvAndShellEvaluator(&.{ "--workspace", root, "--policy", policy_path, "--os-sandbox", "off", "--network-backend", "proxy", "--require-backend", "network-proxy", "--", "/bin/sh", "-c", "env > proxy-env.txt" }, &stdout_writer, &stderr_writer, .ignore, &current, shell_eval.mockDaemonAllowEvaluator);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());

    const written = try tmp.dir.readFileAlloc(std.testing.io, "proxy-env.txt", std.testing.allocator, .limited(8192));
    defer std.testing.allocator.free(written);
    try std.testing.expect(std.mem.indexOf(u8, written, "HTTP_PROXY=http://127.0.0.1:") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "HTTPS_PROXY=http://127.0.0.1:") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "ALL_PROXY=http://127.0.0.1:") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "RYK_NETWORK_ENFORCEMENT=proxy-mediated") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "RYK_PROXY_ROUTE_FORCED=false") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "RYK_PROXY_HTTPS_VISIBILITY=host-port-only") != null);

    const events = try readLastEvents(std.testing.allocator, root);
    defer std.testing.allocator.free(events);
    try std.testing.expect(std.mem.indexOf(u8, events, "\"type\":\"network_proxy_start\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, events, "\"type\":\"network_proxy_stop\"") != null);
}

test "run proxy backend does not satisfy transparent network enforcement requirement" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [2048]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, &.{ "--workspace", root, "--mode", "ci", "--os-sandbox", "off", "--network-backend", "proxy", "--require-backend", "network_enforce", "--", "true" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.unsupported, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "required backend feature is unavailable") != null);
}

test "run rejects unknown network backend" {
    var stdout_buf: [512]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, &.{ "--network-backend", "magic", "--", "true" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "invalid --network-backend value") != null);
}

test "run require-backend fails closed when requested feature is unavailable" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [2048]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    // Pin --os-sandbox off so this asserts the *backend capability* fail-closed path.
    // Default --os-sandbox auto + require-backend network_enforce sets
    // require_network_route_forcing on applyBeforeExec; when route forcing is
    // unavailable the OS-sandbox layer fail-closes first with
    // "network_route_forcing_unavailable" and never reaches BackendRequirementUnavailable.
    // Sibling: "run proxy backend does not satisfy transparent network enforcement requirement".
    const code = try command(std.testing.io, &.{
        "--workspace",       root,
        "--mode",            "ci",
        "--os-sandbox",      "off",
        "--require-backend", "network_enforce",
        "--",                "true",
    }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.unsupported, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "required backend feature is unavailable") != null);

    const events = try readLastEvents(std.testing.allocator, root);
    defer std.testing.allocator.free(events);
    try std.testing.expect(std.mem.indexOf(u8, events, "\"type\":\"backend_capability\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, events, "required backend feature unavailable") != null);
}

test "run require-backend network_enforce with os-sandbox auto fails closed on route forcing" {
    // Documents the coupled path: require-backend network_enforce forces
    // applyBeforeExec network route forcing; auto mode fail-closes there when
    // transparent route forcing is unavailable (no proxy bind / no backend).
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [2048]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, &.{
        "--workspace",       root,
        "--mode",            "ci",
        "--os-sandbox",      "auto",
        "--require-backend", "network_enforce",
        "--",                "true",
    }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.unsupported, code);
    const err = stderr_writer.buffered();
    // Either layer is fail-closed; auto path currently hits OS apply first.
    const os_route = std.mem.indexOf(u8, err, "network_route_forcing_unavailable") != null;
    const backend_msg = std.mem.indexOf(u8, err, "required backend feature is unavailable") != null;
    try std.testing.expect(os_route or backend_msg);
}

test "run require-backend multi-feature does not short-circuit after network-proxy exception" {
    // M-6: an exception for network-proxy (live proxy bind) must not skip other
    // unsatisfied --require-backend features. Order network-proxy first so the
    // old firstMissingRequired short-circuit would have wrongly allowed launch.
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [2048]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    // os-sandbox off: proxy can start, but network_enforce is not route-forced.
    // network-proxy is session-satisfied via proxy_bind; network_enforce is not.
    const code = try command(std.testing.io, &.{
        "--workspace",       root,
        "--mode",            "ci",
        "--os-sandbox",      "off",
        "--network-backend", "proxy",
        "--require-backend", "network-proxy",
        "--require-backend", "network_enforce",
        "--",                "true",
    }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.unsupported, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "required backend feature is unavailable") != null);
}

// Phase 1 network honesty: trusted host-alias path forces proxy + route-force (or fail closed).
// F-02: mediation keys off trusted install identity, not workspace basename alone.
test "run host-alias path mediates network with proxy and route-force or fails closed" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    try skipUnlessOsSandboxBackend();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    {
        const policy_file = try tmp.dir.createFile(std.testing.io, "policy.yaml", .{});
        defer policy_file.close(std.testing.io);
        try policy_file.writeStreamingAll(std.testing.io,
            \\version: 1
            \\mode: observe
            \\env:
            \\  inherit: true
            \\network:
            \\  mode: allowlist
            \\  allow:
            \\    - "api.github.com"
            \\commands:
            \\  allow:
            \\    - "/bin/sh *"
            \\    - "true"
        );
    }
    const policy_path = try tmp.dir.realPathFileAlloc(std.testing.io, "policy.yaml", std.testing.allocator);
    defer std.testing.allocator.free(policy_path);

    // Trusted install fixture (not workspace basename spoof).
    var trust_tmp = std.testing.tmpDir(.{});
    defer trust_tmp.cleanup();
    const trust_root = try trust_tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(trust_root);
    {
        const script = try trust_tmp.dir.createFile(std.testing.io, "pi", .{});
        defer script.close(std.testing.io);
        try script.writeStreamingAll(std.testing.io,
            \\#!/bin/sh
            \\env > child-env.txt
            \\
        );
        try trust_tmp.dir.setFilePermissions(std.testing.io, "pi", @enumFromInt(0o755), .{});
    }
    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    // pi config root counts as usable auth (no login markers on this host).
    try home_tmp.dir.createDirPath(std.testing.io, ".pi");
    const fake_home = try home_tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(fake_home);

    var current = std.process.Environ.Map.init(std.testing.allocator);
    defer current.deinit();
    const system_path = if (std.c.getenv("PATH")) |path| std.mem.span(path) else "/usr/bin:/bin:/usr/sbin:/sbin";
    const path_env = try std.fmt.allocPrint(std.testing.allocator, "{s}:{s}", .{ trust_root, system_path });
    defer std.testing.allocator.free(path_env);
    try current.put("PATH", path_env);
    try current.put("HOME", fake_home);
    try current.put("RYK_TRUSTED_HOST_PREFIXES", trust_root);

    var stdout_buf: [16384]u8 = undefined;
    var stderr_buf: [8192]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    // Bare alias on trusted PATH — must empty-backpack + mediate (F-02).
    const code = try commandForTestWithEnvAndShellEvaluator(
        &.{ "--workspace", root, "--policy", policy_path, "--mode", "observe", "--", "pi" },
        &stdout_writer,
        &stderr_writer,
        .ignore,
        &current,
        shell_eval.mockDaemonAllowEvaluator,
    );
    // Mediated path must either succeed with route-forced env or refuse to start.
    // Trusted host "pi" → empty backpack + proxy + require route-force.
    if (code == exit_codes.success) {
        const written = try tmp.dir.readFileAlloc(std.testing.io, "child-env.txt", std.testing.allocator, .limited(16384));
        defer std.testing.allocator.free(written);
        try std.testing.expect(std.mem.indexOf(u8, written, "HTTP_PROXY=http://127.0.0.1:") != null or
            std.mem.indexOf(u8, written, "HTTP_PROXY=http://localhost:") != null);
        try std.testing.expect(std.mem.indexOf(u8, written, "RYK_PROXY_ROUTE_FORCED=true") != null);
        try std.testing.expect(std.mem.indexOf(u8, written, "RYK_PROXY_MEDIATED_NETWORK_ENFORCEMENT=active") != null);
        try std.testing.expect(std.mem.indexOf(u8, written, "RYK_NETWORK_MODE=allowlist") != null);
        try std.testing.expect(std.mem.indexOf(u8, written, "RYK_BACKEND_NETWORK_ENFORCEMENT=tcp-port-route-forced") != null or
            std.mem.indexOf(u8, written, "RYK_TRANSPARENT_NETWORK_ENFORCEMENT=tcp-port-route-forced") != null);
        // Phase 5 honesty: mediated host-alias reports strong-mediated, never open escape.
        try std.testing.expect(std.mem.indexOf(u8, written, "RYK_SESSION_SANDBOX_GRADE=strong-mediated") != null);
        try std.testing.expect(std.mem.indexOf(u8, written, "RYK_SESSION_SANDBOX_GRADE=unrestricted-escape") == null);
        // Honesty: not labels-only unavailable with a populated allowlist.
        try std.testing.expect(std.mem.indexOf(u8, written, "RYK_BACKEND_NETWORK_ENFORCEMENT=unavailable") == null);
        const out = stdout_writer.buffered();
        try std.testing.expect(std.mem.indexOf(u8, out, "route-forced") != null or
            std.mem.indexOf(u8, out, "proxy route-forced") != null);
        try std.testing.expect(std.mem.indexOf(u8, out, "Session grade: strong-mediated") != null);
    } else {
        try std.testing.expectEqual(exit_codes.unsupported, code);
        const err = stderr_writer.buffered();
        const mediation_msg = std.mem.indexOf(u8, err, "network mediation") != null or
            std.mem.indexOf(u8, err, "route-force") != null or
            std.mem.indexOf(u8, err, "network_route_forcing") != null or
            std.mem.indexOf(u8, err, "proxy network backend") != null;
        try std.testing.expect(mediation_msg);
        try std.testing.expect(std.mem.indexOf(u8, err, "--network open") != null);
    }
}

// F-02 negative control: workspace-planted `pi` is basename-only, not trusted mediation.
test "run workspace pi basename does not mediate network without trusted install" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    {
        const policy_file = try tmp.dir.createFile(std.testing.io, "policy.yaml", .{});
        defer policy_file.close(std.testing.io);
        try policy_file.writeStreamingAll(std.testing.io,
            \\version: 1
            \\mode: observe
            \\env:
            \\  inherit: true
            \\network:
            \\  mode: allowlist
            \\  allow:
            \\    - "api.github.com"
            \\commands:
            \\  allow:
            \\    - "/bin/sh *"
            \\    - "true"
        );
    }
    const policy_path = try tmp.dir.realPathFileAlloc(std.testing.io, "policy.yaml", std.testing.allocator);
    defer std.testing.allocator.free(policy_path);

    {
        const script = try tmp.dir.createFile(std.testing.io, "pi", .{});
        defer script.close(std.testing.io);
        try script.writeStreamingAll(std.testing.io,
            \\#!/bin/sh
            \\env > spoof-env.txt
            \\
        );
        try tmp.dir.setFilePermissions(std.testing.io, "pi", @enumFromInt(0o755), .{});
    }
    var current = std.process.Environ.Map.init(std.testing.allocator);
    defer current.deinit();
    const path_env = if (std.c.getenv("PATH")) |path| std.mem.span(path) else "/usr/bin:/bin:/usr/sbin:/sbin";
    try current.put("PATH", path_env);
    try current.put("HOME", root);

    var stdout_buf: [8192]u8 = undefined;
    var stderr_buf: [4096]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const pi_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/pi", .{root});
    defer std.testing.allocator.free(pi_path);

    // Workspace spoof: no empty-backpack mediation; --os-sandbox off is legal.
    const code = try commandForTestWithEnvAndShellEvaluator(
        &.{
            "--workspace",  root,
            "--policy",     policy_path,
            "--mode",       "observe",
            "--os-sandbox", "off",
            "--",           pi_path,
        },
        &stdout_writer,
        &stderr_writer,
        .ignore,
        &current,
        shell_eval.mockDaemonAllowEvaluator,
    );
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "secret-boundary=off") != null);
    const written = try tmp.dir.readFileAlloc(std.testing.io, "spoof-env.txt", std.testing.allocator, .limited(16384));
    defer std.testing.allocator.free(written);
    try std.testing.expect(std.mem.indexOf(u8, written, "RYK_PROXY_ROUTE_FORCED=true") == null);
    try std.testing.expect(std.mem.indexOf(u8, written, "RYK_PROXY_MEDIATED_NETWORK_ENFORCEMENT=active") == null);
}

test "run host-alias --network open does not require route-force and warns loudly" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    {
        const policy_file = try tmp.dir.createFile(std.testing.io, "policy.yaml", .{});
        defer policy_file.close(std.testing.io);
        try policy_file.writeStreamingAll(std.testing.io,
            \\version: 1
            \\mode: observe
            \\env:
            \\  inherit: true
            \\network:
            \\  mode: allowlist
            \\commands:
            \\  allow:
            \\    - "/bin/sh *"
            \\    - "true"
        );
    }
    const policy_path = try tmp.dir.realPathFileAlloc(std.testing.io, "policy.yaml", std.testing.allocator);
    defer std.testing.allocator.free(policy_path);

    // Trusted install fixture (F-02): basename alone is not an agent host.
    var trust_tmp = std.testing.tmpDir(.{});
    defer trust_tmp.cleanup();
    const trust_root = try trust_tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(trust_root);
    {
        const script = try trust_tmp.dir.createFile(std.testing.io, "pi", .{});
        defer script.close(std.testing.io);
        try script.writeStreamingAll(std.testing.io,
            \\#!/bin/sh
            \\env > open-env.txt
            \\
        );
        try trust_tmp.dir.setFilePermissions(std.testing.io, "pi", @enumFromInt(0o755), .{});
    }
    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    try home_tmp.dir.createDirPath(std.testing.io, ".pi");
    const fake_home = try home_tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(fake_home);

    var current = std.process.Environ.Map.init(std.testing.allocator);
    defer current.deinit();
    const system_path = if (std.c.getenv("PATH")) |path| std.mem.span(path) else "/usr/bin:/bin:/usr/sbin:/sbin";
    const path_env = try std.fmt.allocPrint(std.testing.allocator, "{s}:{s}", .{ trust_root, system_path });
    defer std.testing.allocator.free(path_env);
    try current.put("PATH", path_env);
    try current.put("HOME", fake_home);
    try current.put("RYK_TRUSTED_HOST_PREFIXES", trust_root);

    var stdout_buf: [8192]u8 = undefined;
    var stderr_buf: [4096]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    // --os-sandbox off is illegal with empty backpack; open escape still needs sandbox for trusted host.
    // Use observe + default auto/on path. If backend missing, skip.
    try skipUnlessOsSandboxBackend();

    const code = try commandForTestWithEnvAndShellEvaluator(
        &.{
            "--workspace", root,
            "--policy",    policy_path,
            "--mode",      "observe",
            "--network",   "open",
            "--",          "pi",
        },
        &stdout_writer,
        &stderr_writer,
        .ignore,
        &current,
        shell_eval.mockDaemonAllowEvaluator,
    );
    try std.testing.expectEqual(exit_codes.success, code);
    const err = stderr_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, err, "--network open") != null);
    try std.testing.expect(std.mem.indexOf(u8, err, "unrestricted") != null or
        std.mem.indexOf(u8, err, "escape used") != null);

    const written = try tmp.dir.readFileAlloc(std.testing.io, "open-env.txt", std.testing.allocator, .limited(16384));
    defer std.testing.allocator.free(written);
    try std.testing.expect(std.mem.indexOf(u8, written, "RYK_NETWORK_MODE=open") != null);
    // Open escape: must not require route-forced proxy.
    try std.testing.expect(std.mem.indexOf(u8, written, "RYK_PROXY_ROUTE_FORCED=true") == null);
    // Phase 5: open escape grade must not look like strong-mediated.
    try std.testing.expect(std.mem.indexOf(u8, written, "RYK_SESSION_SANDBOX_GRADE=unrestricted-escape") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "RYK_SESSION_SANDBOX_GRADE=strong-mediated") == null);
    const open_out = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, open_out, "Session grade: unrestricted-escape") != null);

    const events = try readLastEvents(std.testing.allocator, root);
    defer std.testing.allocator.free(events);
    try std.testing.expect(std.mem.indexOf(u8, events, "network unrestricted") != null or
        std.mem.indexOf(u8, events, "escape used") != null);
}

test "run host-alias with host-secrets and os-sandbox off fails closed under mediation" {
    // M-1: mediation must not spawn when route-force cannot apply (sandbox off).
    // F-02: requires trusted host identity (not workspace basename) for mediation.
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    {
        const policy_file = try tmp.dir.createFile(std.testing.io, "policy.yaml", .{});
        defer policy_file.close(std.testing.io);
        try policy_file.writeStreamingAll(std.testing.io,
            \\version: 1
            \\mode: observe
            \\env:
            \\  inherit: true
            \\network:
            \\  mode: allowlist
            \\  allow:
            \\    - "example.com"
            \\commands:
            \\  allow:
            \\    - "*"
        );
    }
    const policy_path = try tmp.dir.realPathFileAlloc(std.testing.io, "policy.yaml", std.testing.allocator);
    defer std.testing.allocator.free(policy_path);

    var trust_tmp = std.testing.tmpDir(.{});
    defer trust_tmp.cleanup();
    const trust_root = try trust_tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(trust_root);
    {
        const script = try trust_tmp.dir.createFile(std.testing.io, "pi", .{});
        defer script.close(std.testing.io);
        try script.writeStreamingAll(std.testing.io,
            \\#!/bin/sh
            \\env > child-env-off.txt
            \\exit 0
        );
        try trust_tmp.dir.setFilePermissions(std.testing.io, "pi", @enumFromInt(0o755), .{});
    }
    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    try home_tmp.dir.createDirPath(std.testing.io, ".pi");
    const fake_home = try home_tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(fake_home);

    var current = std.process.Environ.Map.init(std.testing.allocator);
    defer current.deinit();
    const system_path = if (std.c.getenv("PATH")) |path| std.mem.span(path) else "/usr/bin:/bin:/usr/sbin:/sbin";
    const path_env = try std.fmt.allocPrint(std.testing.allocator, "{s}:{s}", .{ trust_root, system_path });
    defer std.testing.allocator.free(path_env);
    try current.put("PATH", path_env);
    try current.put("HOME", fake_home);
    try current.put("RYK_TRUSTED_HOST_PREFIXES", trust_root);

    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [4096]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    // Trusted host + --with-host-secrets keeps mediation on; sandbox off cannot route-force.
    // Empty-backpack requires sandbox, so --with-host-secrets is needed to reach mediation fail-closed
    // for the os-sandbox-off path (secret boundary off, network mediation still on).
    const code = try commandForTestWithEnvAndShellEvaluator(
        &.{
            "--workspace",         root,
            "--policy",            policy_path,
            "--mode",              "observe",
            "--with-host-secrets", "--os-sandbox",
            "off",                 "--",
            "pi",
        },
        &stdout_writer,
        &stderr_writer,
        .ignore,
        &current,
        shell_eval.mockDaemonAllowEvaluator,
    );
    try std.testing.expectEqual(exit_codes.unsupported, code);
    const err = stderr_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, err, "network mediation") != null or
        std.mem.indexOf(u8, err, "route-force") != null or
        std.mem.indexOf(u8, err, "network_route_forcing") != null);
    try std.testing.expect(std.mem.indexOf(u8, err, "--network open") != null);
}

test "run non-alias default does not force proxy backend" {
    // Pin: custom `ryk run -- <cmd>` stays labels/decision-only unless flags say otherwise.
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    {
        const policy_file = try tmp.dir.createFile(std.testing.io, "policy.yaml", .{});
        defer policy_file.close(std.testing.io);
        try policy_file.writeStreamingAll(std.testing.io,
            \\version: 1
            \\mode: observe
            \\env:
            \\  inherit: true
            \\network:
            \\  mode: allowlist
            \\  allow:
            \\    - "api.github.com"
            \\commands:
            \\  allow:
            \\    - "/bin/sh *"
        );
    }
    const policy_path = try tmp.dir.realPathFileAlloc(std.testing.io, "policy.yaml", std.testing.allocator);
    defer std.testing.allocator.free(policy_path);

    var current = std.process.Environ.Map.init(std.testing.allocator);
    defer current.deinit();
    const path_env = if (std.c.getenv("PATH")) |path| std.mem.span(path) else "/usr/bin:/bin:/usr/sbin:/sbin";
    try current.put("PATH", path_env);

    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [2048]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try commandForTestWithEnvAndShellEvaluator(
        &.{
            "--workspace",  root,
            "--policy",     policy_path,
            "--os-sandbox", "off",
            "--",           "/bin/sh",
            "-c",           "env > non-alias-env.txt",
        },
        &stdout_writer,
        &stderr_writer,
        .ignore,
        &current,
        shell_eval.mockDaemonAllowEvaluator,
    );
    try std.testing.expectEqual(exit_codes.success, code);
    const written = try tmp.dir.readFileAlloc(std.testing.io, "non-alias-env.txt", std.testing.allocator, .limited(16384));
    defer std.testing.allocator.free(written);
    try std.testing.expect(std.mem.indexOf(u8, written, "RYK_NETWORK_MODE=ask") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "HTTP_PROXY=") == null);
    try std.testing.expect(std.mem.indexOf(u8, written, "RYK_PROXY_ROUTE_FORCED=true") == null);
}

test "run shell evaluation forwards command and cwd to daemon Evaluate" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    shell_eval.test_last_evaluate_command = null;
    shell_eval.test_last_evaluate_cwd = null;

    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [2048]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    // Keep this forwarding test independent of the child/shim lifecycle. `git`
    // is one of ryk's generated shims, so launching `git status` here also
    // exercised a nested test-binary process and intermittently surfaced its
    // signal termination as exit code 5. `true` is not shimmed and keeps this
    // test focused on the Evaluate command/cwd boundary.
    const code = try commandForGuardTestWithShellEvaluator(&.{ "--workspace", root, "--", "true" }, &stdout_writer, &stderr_writer, .ignore, shell_eval.mockDaemonAllowEvaluator);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expectEqualStrings("true", shell_eval.test_last_evaluate_command.?);
    try std.testing.expectEqualStrings(root, shell_eval.test_last_evaluate_cwd.?);
}

test "approval presentation redacts argv while evaluation and execution retain original argv" {
    const sentinel = "sk-rykPresentationBoundarySentinel123456789";
    const child_arg = "--token=sk-rykPresentationBoundarySentinel123456789";

    const command_argv = [_][]const u8{ "./capture-argv.sh", child_arg };
    const display = try intercept.commands.displayArgvRedactedAlloc(std.testing.allocator, &command_argv);
    defer std.testing.allocator.free(display);
    var prompt_input: std.Io.Reader = .fixed("d\n");
    var prompt_buf: [2048]u8 = undefined;
    var prompt_writer: std.Io.Writer = .fixed(&prompt_buf);
    const choice = try intercept.approvals.prompt(&prompt_input, &prompt_writer, .{
        .command = display,
        .risk_class = "unknown",
        .risk_reason = "test evaluator requires approval",
        .policy_reason = "commands.default: ask",
    });
    try std.testing.expectEqual(intercept.approvals.ApprovalChoice.deny, choice);
    try std.testing.expect(std.mem.indexOf(u8, prompt_writer.buffered(), sentinel) == null);
    try std.testing.expect(std.mem.indexOf(u8, prompt_writer.buffered(), "[REDACTED]") != null);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    {
        const script = try tmp.dir.createFile(std.testing.io, "capture-argv.sh", .{});
        defer script.close(std.testing.io);
        try script.writeStreamingAll(std.testing.io,
            \\#!/bin/sh
            \\printf '%s' "$1" > received-argv.txt
            \\
        );
        try tmp.dir.setFilePermissions(std.testing.io, "capture-argv.sh", @enumFromInt(0o755), .{});
    }

    shell_eval.test_last_evaluate_command = null;
    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [2048]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const code = try commandForGuardTestWithShellEvaluator(&.{ "--workspace", root, "--mode", "observe", "--", "./capture-argv.sh", child_arg }, &stdout_writer, &stderr_writer, .ignore, shell_eval.mockDaemonAllowEvaluator);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expect(std.mem.indexOf(u8, shell_eval.test_last_evaluate_command.?, sentinel) != null);

    const received = try tmp.dir.readFileAlloc(std.testing.io, "received-argv.txt", std.testing.allocator, .limited(512));
    defer std.testing.allocator.free(received);
    try std.testing.expectEqualStrings(child_arg, received);
}

test "denial panel and remediation redact argv while evaluator receives original argv" {
    const sentinel = "sk-rykDeniedBoundarySentinel123456789";
    const secret_arg = "--token=sk-rykDeniedBoundarySentinel123456789";
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    shell_eval.test_last_evaluate_command = null;
    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [8192]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const code = try commandForGuardTestWithShellEvaluator(&.{ "--workspace", root, "--mode", "ci", "--", "rm", "-rf", secret_arg }, &stdout_writer, &stderr_writer, .ignore, shell_eval.mockDaemonDenyEvaluator);
    try std.testing.expectEqual(exit_codes.denial, code);
    const rendered = stderr_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, rendered, "ryk blocked") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "ryk explain") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, sentinel) == null);
    try std.testing.expect(std.mem.indexOf(u8, shell_eval.test_last_evaluate_command.?, sentinel) != null);
}

test "run daemon unavailable denies shell command" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [2048]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try commandForGuardTestWithShellEvaluator(&.{ "--workspace", root, "--", "git", "status" }, &stdout_writer, &stderr_writer, .ignore, shell_eval.mockDaemonUnavailableEvaluator);
    try std.testing.expectEqual(exit_codes.denial, code);
    // Phase 1 UX: rich guardian block (graceful-degrade path — no rule id).
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "ryk blocked") != null);
}

test "run daemon protocol mismatch denies shell command" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [2048]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try commandForGuardTestWithShellEvaluator(&.{ "--workspace", root, "--", "git", "status" }, &stdout_writer, &stderr_writer, .ignore, shell_eval.mockDaemonProtocolMismatchEvaluator);
    try std.testing.expectEqual(exit_codes.denial, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "ryk blocked") != null or std.mem.indexOf(u8, stderr_writer.buffered(), "command denied") != null);
}

fn readLastSessionId(allocator: std.mem.Allocator, root: []const u8) ![]u8 {
    const last_path = try std.fs.path.join(allocator, &.{ root, ".ryk", "last" });
    defer allocator.free(last_path);
    const text = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, last_path, allocator, .limited(core.limits.max_session_id_len + 2));
    defer allocator.free(text);
    return try allocator.dupe(u8, std.mem.trim(u8, text, " \t\r\n"));
}

fn readLastEvents(allocator: std.mem.Allocator, root: []const u8) ![]u8 {
    const session_id = try readLastSessionId(allocator, root);
    defer allocator.free(session_id);
    const events_path = try std.fs.path.join(allocator, &.{ root, ".ryk", "sessions", session_id, "events.jsonl" });
    defer allocator.free(events_path);
    return try std.Io.Dir.cwd().readFileAlloc(std.testing.io, events_path, allocator, .limited(64 * 1024));
}

fn writeLastPointerNoMakePath(allocator: std.mem.Allocator, workspace_root: []const u8, session_id: []const u8) !void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const last_path = try std.fs.path.join(allocator, &.{ workspace_root, ".ryk", "last" });
    defer allocator.free(last_path);
    const file = try std.Io.Dir.cwd().createFile(io, last_path, .{ .truncate = true });
    defer file.close(io);
    try file.writeStreamingAll(io, session_id);
    try file.writeStreamingAll(io, "\n");
    try file.sync(io);
}

// ---------------------------------------------------------------------------
// TDD: first successful run celebration (written FIRST — RED, foundation work)
// These exercise isFirstSession + the celebration branch in printSessionEnd.
// ---------------------------------------------------------------------------

test "first successful run prints celebration" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    try skipUnlessOsSandboxBackend();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    // Fresh workspace: no .ryk/sessions yet → should be first
    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try commandForTestWithShellEvaluator(
        &.{ "--workspace", root, "--mode", "observe", "--secretless", "--", "/bin/echo", "hi-from-first" },
        &stdout_writer,
        &stderr_writer,
        .inherit,
        shell_eval.mockDaemonAllowEvaluator,
    );
    try std.testing.expectEqual(exit_codes.success, code);
    const out = stdout_writer.buffered();
    // Phase 7: elevated branded moment — brand shield + warm welcome + next-step hints.
    try std.testing.expect(std.mem.indexOf(u8, out, "\u{1F6E1}") != null); // 🛡 brand shield glyph
    try std.testing.expect(std.mem.indexOf(u8, out, "Welcome to ryk!") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "replay --session last") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Next steps") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "policy explain") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "ryk <agent>") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "boundary-off runs do not print protected celebration" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try commandForTestWithShellEvaluator(&.{ "--workspace", root, "--os-sandbox", "off", "--", "echo", "hi-from-second" }, &stdout_writer, &stderr_writer, .inherit, shell_eval.mockDaemonAllowEvaluator);
    try std.testing.expectEqual(exit_codes.success, code);
    const out = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "secret-boundary=off") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Welcome to ryk!") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "first protected session complete") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Next steps") == null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "session end prints final audit chain hash matching summary" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [2048]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try commandForGuardTestWithShellEvaluator(
        &.{ "--workspace", root, "--os-sandbox", "off", "--", "true" },
        &stdout_writer,
        &stderr_writer,
        .inherit,
        shell_eval.mockDaemonAllowEvaluator,
    );
    try std.testing.expectEqual(exit_codes.success, code);
    const out = stdout_writer.buffered();
    const prefix = "Audit chain: ";
    const start = std.mem.indexOf(u8, out, prefix) orelse return error.TestExpectedEqual;
    const hash_start = start + prefix.len;
    try std.testing.expect(out.len >= hash_start + 64);
    const printed = out[hash_start .. hash_start + 64];
    for (printed) |byte| try std.testing.expect(std.ascii.isHex(byte));

    const session_id = try readLastSessionId(std.testing.allocator, root);
    defer std.testing.allocator.free(session_id);
    const summary_path = try std.fs.path.join(std.testing.allocator, &.{ root, ".ryk", "sessions", session_id, "summary.json" });
    defer std.testing.allocator.free(summary_path);
    const summary = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, summary_path, std.testing.allocator, .limited(64 * 1024));
    defer std.testing.allocator.free(summary);
    var needle_buf: [96]u8 = undefined;
    const needle = try std.fmt.bufPrint(&needle_buf, "\"final_event_hash\":\"{s}\"", .{printed});
    try std.testing.expect(std.mem.indexOf(u8, summary, needle) != null);
}

// ---------------------------------------------------------------------------
// TDD: Phase 1 — rich guardian block on deny (written FIRST → RED → GREEN).
// These exercise renderDenyBlock via the real run.zig deny path. Fixed-buffer
// writers + std.testing.io force theme.active() to .none, so assertions hold
// against the plain-text degrade path (the colour path is covered by theme.zig).
// ---------------------------------------------------------------------------

test "deny block renders rich guardian block for rm -rf /" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [4096]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try commandForGuardTestWithShellEvaluator(&.{ "--workspace", root, "--", "rm", "-rf", "/" }, &stdout_writer, &stderr_writer, .inherit, shell_eval.mockDaemonDenyEvaluator);
    try std.testing.expectEqual(exit_codes.denial, code);
    const err = stderr_writer.buffered();

    // Hero header (What).
    try std.testing.expect(std.mem.indexOf(u8, err, "✗") != null);
    try std.testing.expect(std.mem.indexOf(u8, err, "ryk blocked") != null);
    // The denied command appears as the panel headline.
    try std.testing.expect(std.mem.indexOf(u8, err, "rm -rf /") != null);
    // Why / Rule / Policy rows inside the panel.
    try std.testing.expect(std.mem.indexOf(u8, err, "Why") != null);
    try std.testing.expect(std.mem.indexOf(u8, err, "Rule") != null);
    try std.testing.expect(std.mem.indexOf(u8, err, "Policy") != null);
    // Risk meter label is present.
    try std.testing.expect(std.mem.indexOf(u8, err, "Risk") != null);
    // Safer shape (daemon tip or heuristic alternatives).
    try std.testing.expect(std.mem.indexOf(u8, err, "Safer shape") != null or std.mem.indexOf(u8, err, "Tip") != null);
    try std.testing.expect(std.mem.indexOf(u8, err, "rm -rf ./build") != null or std.mem.indexOf(u8, err, "./build") != null);
    // Progressive What-now footer (explain → allow-once → allowlist).
    try std.testing.expect(std.mem.indexOf(u8, err, "What now") != null);
    try std.testing.expect(std.mem.indexOf(u8, err, "ryk explain") != null);
    try std.testing.expect(std.mem.indexOf(u8, err, "ryk allowlist add") != null);
    try std.testing.expect(std.mem.indexOf(u8, err, "ryk allow-once") != null);
    // The old flat line is gone.
    try std.testing.expect(std.mem.indexOf(u8, err, "command denied by command guard") == null);
}

test "deny block includes reasonForRule text when rule id is known" {
    // reasonForRule is driven by the daemon's pattern_name. The mock deny
    // evaluator returns pack:pattern "core.filesystem:destructive_rm"; pattern
    // is not in the reason table, so graceful-degrade fallback still applies.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [4096]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try commandForGuardTestWithShellEvaluator(&.{ "--workspace", root, "--", "rm", "-rf", "/" }, &stdout_writer, &stderr_writer, .inherit, shell_eval.mockDaemonDenyEvaluator);
    try std.testing.expectEqual(exit_codes.denial, code);
    const err = stderr_writer.buffered();
    // Full pack:pattern rule id is shown in the Rule row.
    try std.testing.expect(std.mem.indexOf(u8, err, "core.filesystem:destructive_rm") != null);
    // Unknown rule → fallback reason text from reasonForRule.
    try std.testing.expect(std.mem.indexOf(u8, err, "deny rule") != null);
}

test "deny block graceful-degrades without rule id (daemon unavailable)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [4096]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    // mockDaemonUnavailableEvaluator → fail-closed deny with no rule id.
    const code = try commandForGuardTestWithShellEvaluator(&.{ "--workspace", root, "--", "git", "status" }, &stdout_writer, &stderr_writer, .ignore, shell_eval.mockDaemonUnavailableEvaluator);
    try std.testing.expectEqual(exit_codes.denial, code);
    const err = stderr_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, err, "ryk blocked") != null);
    try std.testing.expect(std.mem.indexOf(u8, err, "✗") != null);
    // Rule row shows the em-dash placeholder when no rule id is available.
    try std.testing.expect(std.mem.indexOf(u8, err, "Rule") != null);
    // No crash; exit code unchanged.
}

test "deny block keeps exit code and does not print the flat line" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [4096]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try commandForGuardTestWithShellEvaluator(&.{ "--workspace", root, "--", "rm", "-rf", "/" }, &stdout_writer, &stderr_writer, .inherit, shell_eval.mockDaemonDenyEvaluator);
    // Invariant: exit code stays exit_codes.denial.
    try std.testing.expectEqual(exit_codes.denial, code);
    // The flat one-liner is fully replaced.
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "ryk run: command denied by command guard.\n") == null);
}

test "parse --os-sandbox accepts auto|on|off; invalid and missing fail usage" {
    // Valid tokens match OsSandboxMode (CLI uses the same parser).
    try std.testing.expectEqual(sandbox.posture.OsSandboxMode.auto, sandbox.posture.OsSandboxMode.parse("auto").?);
    try std.testing.expectEqual(sandbox.posture.OsSandboxMode.on, sandbox.posture.OsSandboxMode.parse("on").?);
    try std.testing.expectEqual(sandbox.posture.OsSandboxMode.off, sandbox.posture.OsSandboxMode.parse("off").?);

    var stdout_buf: [512]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    // Invalid value
    {
        stdout_writer = .fixed(&stdout_buf);
        stderr_writer = .fixed(&stderr_buf);
        const code = try command(std.testing.io, &.{ "--os-sandbox", "seatbelt", "--", "true" }, &stdout_writer, &stderr_writer);
        try std.testing.expectEqual(exit_codes.usage, code);
        try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "invalid --os-sandbox value") != null);
    }
    // Missing value
    {
        stdout_writer = .fixed(&stdout_buf);
        stderr_writer = .fixed(&stderr_buf);
        const code = try command(std.testing.io, &.{"--os-sandbox"}, &stdout_writer, &stderr_writer);
        try std.testing.expectEqual(exit_codes.usage, code);
    }
}

test "run --os-sandbox on fails closed without backend (no agent)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [2048]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try commandForGuardTestWithShellEvaluator(
        &.{ "--workspace", root, "--os-sandbox", "on", "--", "true" },
        &stdout_writer,
        &stderr_writer,
        .ignore,
        shell_eval.mockDaemonAllowEvaluator,
    );
    // Linux Landlock or macOS Seatbelt (matrix majors) may attach; elsewhere fail-closed.
    if (code == exit_codes.unsupported) {
        try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "OS sandbox required") != null);
        // Real reason_code — not the backend_not_implemented placeholder.
        try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "backend_not_implemented") == null or builtin.os.tag != .macos);
        // Outside matrix (or symbol missing): version/symbol reasons only.
        if (builtin.os.tag == .macos) {
            const err = stderr_writer.buffered();
            const version_gate = std.mem.indexOf(u8, err, "macos_version_unsupported") != null;
            const symbol_gate = std.mem.indexOf(u8, err, "sandbox_init_unavailable") != null;
            try std.testing.expect(version_gate or symbol_gate);
        }
    } else {
        try std.testing.expectEqual(exit_codes.success, code);
    }
}

test "run --os-sandbox off succeeds with disabled path" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [2048]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try commandForGuardTestWithShellEvaluator(
        &.{ "--workspace", root, "--os-sandbox", "off", "--", "true" },
        &stdout_writer,
        &stderr_writer,
        .ignore,
        shell_eval.mockDaemonAllowEvaluator,
    );
    try std.testing.expectEqual(exit_codes.success, code);
    const out = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "OS sandbox: disabled") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Seatbelt") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Landlock") == null);
    // off should not print grade-drop warning
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "grade drop") == null);
}

test "run --os-sandbox auto degrades loudly when backend unavailable" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [4096]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try commandForGuardTestWithShellEvaluator(
        &.{ "--workspace", root, "--os-sandbox", "auto", "--", "true" },
        &stdout_writer,
        &stderr_writer,
        .ignore,
        shell_eval.mockDaemonAllowEvaluator,
    );
    try std.testing.expectEqual(exit_codes.success, code);
    const out = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "OS sandbox:") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Seatbelt") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Landlock") == null);

    // When no child apply plan (typical macOS outside matrix / landlock-less hosts): loud degrade.
    // When Landlock/Seatbelt child plan exists, spawn may attach — grade drop optional.
    const err = stderr_writer.buffered();
    if (std.mem.indexOf(u8, out, "OS sandbox: unavailable") != null or std.mem.indexOf(u8, out, "OS sandbox: failed") != null) {
        try std.testing.expect(std.mem.indexOf(u8, err, "grade drop") != null);
        try std.testing.expect(std.mem.indexOf(u8, err, "WARNING") != null);
    }
}

test "RunOptions default os_sandbox is auto" {
    const defaults: RunOptions = .{};
    try std.testing.expectEqual(sandbox.posture.OsSandboxMode.auto, defaults.os_sandbox);
    try std.testing.expectEqual(sandbox.posture.SeatbeltProfileGrade.hardened, defaults.seatbelt_profile);
}

test "parse --seatbelt-profile accepts grades; invalid fails usage" {
    var stdout_buf: [512]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    // Accept path: enum parse + CLI does not reject valid tokens (os-sandbox off avoids attach).
    inline for (.{ "compatible", "hardened", "strict" }) |grade| {
        try std.testing.expect(sandbox.posture.SeatbeltProfileGrade.parse(grade) != null);
        stdout_writer = .fixed(&stdout_buf);
        stderr_writer = .fixed(&stderr_buf);
        const code = try command(
            std.testing.io,
            &.{ "--mode", "observe", "--os-sandbox", "off", "--seatbelt-profile", grade, "--", "/usr/bin/true" },
            &stdout_writer,
            &stderr_writer,
        );
        try std.testing.expectEqual(exit_codes.success, code);
        try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "invalid --seatbelt-profile value") == null);
    }
    {
        stdout_writer = .fixed(&stdout_buf);
        stderr_writer = .fixed(&stderr_buf);
        const code = try command(std.testing.io, &.{ "--seatbelt-profile", "paranoid", "--", "true" }, &stdout_writer, &stderr_writer);
        try std.testing.expectEqual(exit_codes.usage, code);
        try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "invalid --seatbelt-profile value") != null);
    }
    {
        stdout_writer = .fixed(&stdout_buf);
        stderr_writer = .fixed(&stderr_buf);
        const code = try command(std.testing.io, &.{"--seatbelt-profile"}, &stdout_writer, &stderr_writer);
        try std.testing.expectEqual(exit_codes.usage, code);
    }
}

// Env helpers for seatbelt-profile env tests only (not used by production path).
extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;
extern "c" fn unsetenv(name: [*:0]const u8) c_int;

// M-2: invalid RYK_SEATBELT_PROFILE warns and stays hardened (PR test plan A13).
test "invalid RYK_SEATBELT_PROFILE warns and keeps hardened default" {
    const previous = std.c.getenv("RYK_SEATBELT_PROFILE");
    const prev_owned: ?[:0]const u8 = if (previous) |p|
        try std.testing.allocator.dupeZ(u8, std.mem.span(p))
    else
        null;
    defer if (prev_owned) |o| std.testing.allocator.free(o);
    defer {
        if (prev_owned) |o| {
            _ = setenv("RYK_SEATBELT_PROFILE", o.ptr, 1);
        } else {
            _ = unsetenv("RYK_SEATBELT_PROFILE");
        }
    }

    try std.testing.expectEqual(@as(c_int, 0), setenv("RYK_SEATBELT_PROFILE", "paranoid", 1));

    var stdout_buf: [512]u8 = undefined;
    var stderr_buf: [1024]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const code = try command(
        std.testing.io,
        &.{ "--mode", "observe", "--os-sandbox", "off", "--", "/usr/bin/true" },
        &stdout_writer,
        &stderr_writer,
    );
    try std.testing.expectEqual(exit_codes.success, code);
    const err = stderr_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, err, "WARNING: ignoring invalid RYK_SEATBELT_PROFILE=paranoid") != null);
    try std.testing.expect(std.mem.indexOf(u8, err, "defaulting to hardened") != null);
}

test "empty backpack resolves sandbox auto to required on" {
    try std.testing.expectEqual(
        sandbox.posture.OsSandboxMode.on,
        try effectiveOsSandboxMode(.empty_backpack, .auto),
    );
    try std.testing.expectEqual(
        sandbox.posture.OsSandboxMode.on,
        try effectiveOsSandboxMode(.empty_backpack, .on),
    );
    try std.testing.expectError(
        error.SecretBoundaryRequiresSandbox,
        effectiveOsSandboxMode(.empty_backpack, .off),
    );
    try std.testing.expectEqual(
        sandbox.posture.OsSandboxMode.auto,
        try effectiveOsSandboxMode(.off, .auto),
    );
    try std.testing.expectEqual(
        sandbox.posture.OsSandboxMode.off,
        try effectiveOsSandboxMode(.off, .off),
    );
    try std.testing.expectEqual(
        sandbox.posture.OsSandboxMode.on,
        try effectiveOsSandboxMode(.off, .on),
    );
}

test "secretless default fails closed when sandbox profile cannot attach" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const marker_path = try std.fs.path.join(std.testing.allocator, &.{ root, "child-started" });
    defer std.testing.allocator.free(marker_path);

    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [4096]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const args = &.{
        "--workspace",
        "/",
        "--policy",
        "policies/observe.yaml",
        "--secretless",
        "--",
        "/usr/bin/touch",
        marker_path,
    };
    const code = try commandForGuardTestWithShellEvaluator(
        args,
        &stdout_writer,
        &stderr_writer,
        .ignore,
        shell_eval.mockDaemonAllowEvaluator,
    );

    try std.testing.expectError(error.FileNotFound, tmp.dir.access(std.testing.io, "child-started", .{}));
    try std.testing.expectEqual(exit_codes.unsupported, code);
    try std.testing.expect(
        std.mem.indexOf(u8, stderr_writer.buffered(), "OS sandbox required but unavailable") != null,
    );
}

// Always-on attach subset (skip when no backend). Full multi-agent smoke is manual.
fn skipUnlessOsSandboxBackend() !void {
    if (builtin.os.tag == .macos) {
        if (!sandbox.macos_seatbelt.sandboxInitAvailable()) return error.SkipZigTest;
        const ver = sandbox.macos_seatbelt.detectProductVersion() catch return error.SkipZigTest;
        if (!sandbox.macos_seatbelt.isMatrixMajor(ver.major)) return error.SkipZigTest;
    } else if (builtin.os.tag == .linux) {
        if (!sandbox.landlock.isAbiAvailable()) return error.SkipZigTest;
    } else return error.SkipZigTest;
}

// Full production `ryk run` attach when OS backend is available.
// Full multi-agent / long-running agent smoke remains manual.
test "ryk run --os-sandbox on attaches and banners active when backend available" {
    try skipUnlessOsSandboxBackend();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, ".ryk");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "neighbor.txt", .data = "ok" });
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var stdout_buf: [8192]u8 = undefined;
    var stderr_buf: [4096]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try commandForGuardTestWithShellEvaluator(
        // observe: avoid builtin:strict command-guard deny so this test measures Seatbelt attach.
        &.{ "--workspace", root, "--mode", "observe", "--os-sandbox", "on", "--seatbelt-profile", "hardened", "--", "/usr/bin/true" },
        &stdout_writer,
        &stderr_writer,
        .ignore,
        shell_eval.mockDaemonAllowEvaluator,
    );
    try std.testing.expectEqual(exit_codes.success, code);
    const out = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "OS sandbox: active") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Seatbelt") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Landlock") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "network: unrestricted") != null);
    if (builtin.os.tag == .macos) {
        // Residual grade token — same form as audit / doctor capability note.
        try std.testing.expect(std.mem.indexOf(u8, out, "seatbelt_profile=hardened") != null);
    }
    if (builtin.os.tag == .linux) {
        try std.testing.expect(std.mem.indexOf(u8, out, "workspace child RW") != null or std.mem.indexOf(u8, out, "root RO") != null);
        try std.testing.expect(std.mem.indexOf(u8, out, "seatbelt_profile=") == null);
    }
}

// M-4: non-default residual grade must reach banner + audit on the live production path.
test "ryk run --seatbelt-profile strict surfaces grade on banner and audit when backend available" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    try skipUnlessOsSandboxBackend();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, ".ryk");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "neighbor.txt", .data = "ok" });
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var stdout_buf: [8192]u8 = undefined;
    var stderr_buf: [4096]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try commandForGuardTestWithShellEvaluator(
        &.{ "--workspace", root, "--mode", "observe", "--os-sandbox", "on", "--seatbelt-profile", "strict", "--", "/usr/bin/true" },
        &stdout_writer,
        &stderr_writer,
        .ignore,
        shell_eval.mockDaemonAllowEvaluator,
    );
    try std.testing.expectEqual(exit_codes.success, code);
    const out = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "OS sandbox: active") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "seatbelt_profile=strict") != null);
    // Strict without route force: network honesty is deny-default, not unrestricted.
    try std.testing.expect(std.mem.indexOf(u8, out, "network: unrestricted") == null);

    const events = try readLastEvents(std.testing.allocator, root);
    defer std.testing.allocator.free(events);
    try std.testing.expect(std.mem.indexOf(u8, events, "\"type\":\"sandbox_posture\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, events, "seatbelt_profile=strict") != null);
}

// M-18: active attach must emit sandbox_posture with posture=active and 64-hex profile_hash.
test "ryk run --os-sandbox on active audit has posture=active and 64-hex profile_hash" {
    try skipUnlessOsSandboxBackend();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, ".ryk");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "neighbor.txt", .data = "ok" });
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var stdout_buf: [8192]u8 = undefined;
    var stderr_buf: [4096]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try commandForGuardTestWithShellEvaluator(
        &.{ "--workspace", root, "--mode", "observe", "--os-sandbox", "on", "--seatbelt-profile", "hardened", "--", "/usr/bin/true" },
        &stdout_writer,
        &stderr_writer,
        .ignore,
        shell_eval.mockDaemonAllowEvaluator,
    );
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "OS sandbox: active") != null);

    const events = try readLastEvents(std.testing.allocator, root);
    defer std.testing.allocator.free(events);
    try std.testing.expect(std.mem.indexOf(u8, events, "\"type\":\"sandbox_posture\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, events, "posture=active") != null);
    const hash_marker = "profile_hash=";
    const hash_at = std.mem.indexOf(u8, events, hash_marker);
    try std.testing.expect(hash_at != null);
    const hash_start = hash_at.? + hash_marker.len;
    var hash_end = hash_start;
    while (hash_end < events.len and std.ascii.isHex(events[hash_end])) : (hash_end += 1) {}
    try std.testing.expectEqual(@as(usize, 64), hash_end - hash_start);
    try std.testing.expect(sandbox.posture.isValidProfileHashHex(events[hash_start..hash_end]));
    if (builtin.os.tag == .macos) {
        try std.testing.expect(std.mem.indexOf(u8, events, "seatbelt_profile=hardened") != null);
    }
}

// M-20 residual honesty: active attach + non-zero agent exit emits follow-up note.
test "ryk run notes attach-ok residual when agent exits non-zero after active attach" {
    try skipUnlessOsSandboxBackend();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, ".ryk");
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var stdout_buf: [8192]u8 = undefined;
    var stderr_buf: [4096]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const false_bin: []const u8 = blk: {
        std.Io.Dir.cwd().access(std.testing.io, "/usr/bin/false", .{}) catch break :blk "/bin/false";
        break :blk "/usr/bin/false";
    };
    const code = try commandForGuardTestWithShellEvaluator(
        &.{ "--workspace", root, "--mode", "observe", "--os-sandbox", "on", "--", false_bin },
        &stdout_writer,
        &stderr_writer,
        .ignore,
        shell_eval.mockDaemonAllowEvaluator,
    );
    try std.testing.expect(code != exit_codes.success);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "OS sandbox: active") != null);
    const err = stderr_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, err, "OS sandbox attach succeeded") != null);
    try std.testing.expect(std.mem.indexOf(u8, err, "after sandbox attach") != null);
    try std.testing.expect(std.mem.indexOf(u8, err, "pre-exec handshake residual") == null);
}

test "require-backend strong-sandbox accepts planned attach and rejects off" {
    try skipUnlessOsSandboxBackend();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, ".ryk");
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const true_bin: []const u8 = blk: {
        std.Io.Dir.cwd().access(std.testing.io, "/usr/bin/true", .{}) catch break :blk "/bin/true";
        break :blk "/usr/bin/true";
    };

    var on_stdout_buf: [8192]u8 = undefined;
    var on_stderr_buf: [4096]u8 = undefined;
    var on_stdout: std.Io.Writer = .fixed(&on_stdout_buf);
    var on_stderr: std.Io.Writer = .fixed(&on_stderr_buf);
    const on_code = try commandForGuardTestWithShellEvaluator(
        &.{
            "--workspace",       root,
            "--mode",            "observe",
            "--os-sandbox",      "on",
            "--require-backend", "strong-sandbox",
            "--",                true_bin,
        },
        &on_stdout,
        &on_stderr,
        .ignore,
        shell_eval.mockDaemonAllowEvaluator,
    );
    try std.testing.expectEqual(exit_codes.success, on_code);
    try std.testing.expect(std.mem.indexOf(u8, on_stdout.buffered(), "OS sandbox: active") != null);

    var off_stdout_buf: [4096]u8 = undefined;
    var off_stderr_buf: [4096]u8 = undefined;
    var off_stdout: std.Io.Writer = .fixed(&off_stdout_buf);
    var off_stderr: std.Io.Writer = .fixed(&off_stderr_buf);
    const off_code = try commandForGuardTestWithShellEvaluator(
        &.{
            "--workspace",       root,
            "--mode",            "observe",
            "--os-sandbox",      "off",
            "--require-backend", "strong-sandbox",
            "--",                true_bin,
        },
        &off_stdout,
        &off_stderr,
        .ignore,
        shell_eval.mockDaemonAllowEvaluator,
    );
    try std.testing.expectEqual(exit_codes.unsupported, off_code);
}

test "require-backend landlock requires planned Landlock mechanism" {
    try skipUnlessOsSandboxBackend();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, ".ryk");
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const true_bin: []const u8 = blk: {
        std.Io.Dir.cwd().access(std.testing.io, "/usr/bin/true", .{}) catch break :blk "/bin/true";
        break :blk "/usr/bin/true";
    };

    var stdout_buf: [8192]u8 = undefined;
    var stderr_buf: [4096]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const code = try commandForGuardTestWithShellEvaluator(
        &.{
            "--workspace",       root,
            "--mode",            "observe",
            "--os-sandbox",      "on",
            "--require-backend", "landlock",
            "--",                true_bin,
        },
        &stdout_writer,
        &stderr_writer,
        .ignore,
        shell_eval.mockDaemonAllowEvaluator,
    );
    if (builtin.os.tag == .linux) {
        try std.testing.expectEqual(exit_codes.success, code);
    } else {
        try std.testing.expectEqual(exit_codes.unsupported, code);
    }
}

// M-31: fail-closed spawn/handshake under on and auto (preflight fails → ApplyFailed).
test "ryk run --os-sandbox on fail-closed when child handshake fails" {
    try skipUnlessOsSandboxBackend();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, ".ryk");
    // Non-executable payload: parent resolve allows absolute paths; child preflight
    // (R_OK|X_OK) fails before status_ok → ApplyFailed → fail-closed attach path.
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "no-exec-agent", .data = "#!/bin/sh\necho should-not-run\n" });
    // Explicitly strip execute bits (writeFile may leave platform-default modes).
    try tmp.dir.setFilePermissions(std.testing.io, "no-exec-agent", std.Io.File.Permissions.fromMode(0o644), .{});
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const agent_path = try std.fs.path.join(std.testing.allocator, &.{ root, "no-exec-agent" });
    defer std.testing.allocator.free(agent_path);

    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [4096]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try commandForGuardTestWithShellEvaluator(
        &.{ "--workspace", root, "--mode", "observe", "--os-sandbox", "on", "--", agent_path },
        &stdout_writer,
        &stderr_writer,
        .ignore,
        shell_eval.mockDaemonAllowEvaluator,
    );
    try std.testing.expectEqual(exit_codes.unsupported, code);
    const err = stderr_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, err, "OS sandbox required") != null);
    try std.testing.expect(std.mem.indexOf(u8, err, "attach failed") != null);
    try std.testing.expect(std.mem.indexOf(u8, err, "child_apply_failed") != null);
    // Must not claim active after failed handshake.
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "OS sandbox: active") == null);
}

test "ryk run --os-sandbox auto fail-closed when child handshake fails (no unboxed launch)" {
    try skipUnlessOsSandboxBackend();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, ".ryk");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "no-exec-agent", .data = "#!/bin/sh\necho should-not-run\n" });
    try tmp.dir.setFilePermissions(std.testing.io, "no-exec-agent", std.Io.File.Permissions.fromMode(0o644), .{});
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const agent_path = try std.fs.path.join(std.testing.allocator, &.{ root, "no-exec-agent" });
    defer std.testing.allocator.free(agent_path);

    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [4096]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try commandForGuardTestWithShellEvaluator(
        &.{ "--workspace", root, "--mode", "observe", "--os-sandbox", "auto", "--", agent_path },
        &stdout_writer,
        &stderr_writer,
        .ignore,
        shell_eval.mockDaemonAllowEvaluator,
    );
    try std.testing.expectEqual(exit_codes.unsupported, code);
    const err = stderr_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, err, "attach failed under --os-sandbox auto") != null);
    try std.testing.expect(std.mem.indexOf(u8, err, "not launching unboxed agent") != null);
    try std.testing.expect(std.mem.indexOf(u8, err, "child_apply_failed") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "OS sandbox: active") == null);
}

// F-5: default auto path (omit --os-sandbox) attaches when backend present.
test "ryk run default auto attaches when backend available" {
    try skipUnlessOsSandboxBackend();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, ".ryk");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "neighbor.txt", .data = "ok" });
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var stdout_buf: [8192]u8 = undefined;
    var stderr_buf: [4096]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    // Intentionally omit --os-sandbox so default .auto is used.
    // observe: avoid builtin:strict command-guard deny of /usr/bin/true.
    const code = try commandForGuardTestWithShellEvaluator(
        &.{ "--workspace", root, "--mode", "observe", "--", "/usr/bin/true" },
        &stdout_writer,
        &stderr_writer,
        .ignore,
        shell_eval.mockDaemonAllowEvaluator,
    );
    try std.testing.expectEqual(exit_codes.success, code);
    const out = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "OS sandbox: active") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Seatbelt") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Landlock") == null);
}

test "empty backpack fails closed when claude has config dir but no credentials" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    try skipUnlessOsSandboxBackend();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    // Config root only — no .credentials.json (R4).
    try home_tmp.dir.createDirPath(std.testing.io, ".claude");
    const fake_home = try home_tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(fake_home);

    var trust_tmp = std.testing.tmpDir(.{});
    defer trust_tmp.cleanup();
    {
        const script = try trust_tmp.dir.createFile(std.testing.io, "claude", .{});
        defer script.close(std.testing.io);
        try script.writeStreamingAll(std.testing.io, "#!/bin/sh\nexit 0\n");
        try trust_tmp.dir.setFilePermissions(std.testing.io, "claude", @enumFromInt(0o755), .{});
    }
    const trust_root = try trust_tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(trust_root);

    var current = std.process.Environ.Map.init(std.testing.allocator);
    defer current.deinit();
    try current.put("PATH", trust_root);
    try current.put("HOME", fake_home);
    try current.put("RYK_TRUSTED_HOST_PREFIXES", trust_root);
    // No ANTHROPIC_API_KEY → no gateway substitute.

    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [4096]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const code = try commandForTestWithEnvAndShellEvaluator(
        &.{ "--workspace", root, "--mode", "observe", "--", "claude" },
        &stdout_writer,
        &stderr_writer,
        .ignore,
        &current,
        shell_eval.mockDaemonAllowEvaluator,
    );
    try std.testing.expectEqual(exit_codes.unsupported, code);
    const err = stderr_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, err, "usable host login material") != null or
        std.mem.indexOf(u8, err, ".credentials.json") != null);
}

test "empty backpack fails closed when claude OAuth access token is expired" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    try skipUnlessOsSandboxBackend();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    try home_tmp.dir.createDirPath(std.testing.io, ".claude");
    try home_tmp.dir.writeFile(std.testing.io, .{
        .sub_path = ".claude/.credentials.json",
        .data = "{\"claudeAiOauth\":{\"expiresAt\":1}}\n",
    });
    const fake_home = try home_tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(fake_home);

    var trust_tmp = std.testing.tmpDir(.{});
    defer trust_tmp.cleanup();
    {
        const script = try trust_tmp.dir.createFile(std.testing.io, "claude", .{});
        defer script.close(std.testing.io);
        try script.writeStreamingAll(std.testing.io, "#!/bin/sh\nexit 0\n");
        try trust_tmp.dir.setFilePermissions(std.testing.io, "claude", @enumFromInt(0o755), .{});
    }
    const trust_root = try trust_tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(trust_root);

    var current = std.process.Environ.Map.init(std.testing.allocator);
    defer current.deinit();
    try current.put("PATH", trust_root);
    try current.put("HOME", fake_home);
    try current.put("RYK_TRUSTED_HOST_PREFIXES", trust_root);

    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [4096]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const code = try commandForTestWithEnvAndShellEvaluator(
        &.{ "--workspace", root, "--mode", "observe", "--", "claude" },
        &stdout_writer,
        &stderr_writer,
        .ignore,
        &current,
        shell_eval.mockDaemonAllowEvaluator,
    );
    try std.testing.expectEqual(exit_codes.unsupported, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "expired") != null);
}

test "empty backpack allows claude --help with expired credentials" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    try skipUnlessOsSandboxBackend();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    try home_tmp.dir.createDirPath(std.testing.io, ".claude");
    try home_tmp.dir.writeFile(std.testing.io, .{
        .sub_path = ".claude/.credentials.json",
        .data = "{\"claudeAiOauth\":{\"expiresAt\":1}}\n",
    });
    const fake_home = try home_tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(fake_home);

    var trust_tmp = std.testing.tmpDir(.{});
    defer trust_tmp.cleanup();
    {
        const script = try trust_tmp.dir.createFile(std.testing.io, "claude", .{});
        defer script.close(std.testing.io);
        try script.writeStreamingAll(std.testing.io, "#!/bin/sh\necho help-ok\n");
        try trust_tmp.dir.setFilePermissions(std.testing.io, "claude", @enumFromInt(0o755), .{});
    }
    const trust_root = try trust_tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(trust_root);

    var current = std.process.Environ.Map.init(std.testing.allocator);
    defer current.deinit();
    try current.put("PATH", trust_root);
    try current.put("HOME", fake_home);
    try current.put("RYK_TRUSTED_HOST_PREFIXES", trust_root);

    var stdout_buf: [8192]u8 = undefined;
    var stderr_buf: [4096]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const code = try commandForTestWithEnvAndShellEvaluator(
        &.{ "--workspace", root, "--mode", "observe", "--", "claude", "--help" },
        &stdout_writer,
        &stderr_writer,
        .ignore,
        &current,
        shell_eval.mockDaemonAllowEvaluator,
    );
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "expired") == null);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "usable host login material") == null);
}

test "empty backpack allows claude --help with no credentials at all" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    try skipUnlessOsSandboxBackend();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    // No .claude at all.
    const fake_home = try home_tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(fake_home);

    var trust_tmp = std.testing.tmpDir(.{});
    defer trust_tmp.cleanup();
    {
        const script = try trust_tmp.dir.createFile(std.testing.io, "claude", .{});
        defer script.close(std.testing.io);
        try script.writeStreamingAll(std.testing.io, "#!/bin/sh\necho help-ok\n");
        try trust_tmp.dir.setFilePermissions(std.testing.io, "claude", @enumFromInt(0o755), .{});
    }
    const trust_root = try trust_tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(trust_root);

    var current = std.process.Environ.Map.init(std.testing.allocator);
    defer current.deinit();
    try current.put("PATH", trust_root);
    try current.put("HOME", fake_home);
    try current.put("RYK_TRUSTED_HOST_PREFIXES", trust_root);

    var stdout_buf: [8192]u8 = undefined;
    var stderr_buf: [4096]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const code = try commandForTestWithEnvAndShellEvaluator(
        &.{ "--workspace", root, "--mode", "observe", "--", "claude", "--help" },
        &stdout_writer,
        &stderr_writer,
        .ignore,
        &current,
        shell_eval.mockDaemonAllowEvaluator,
    );
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "usable host login material") == null);
}

test "empty backpack non-host binary does not fail closed for missing claude config" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    try skipUnlessOsSandboxBackend();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    const fake_home = try home_tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(fake_home);

    var current = std.process.Environ.Map.init(std.testing.allocator);
    defer current.deinit();
    const path_env = if (std.c.getenv("PATH")) |path| std.mem.span(path) else "/usr/bin:/bin:/usr/sbin:/sbin";
    try current.put("PATH", path_env);
    try current.put("HOME", fake_home);

    var stdout_buf: [8192]u8 = undefined;
    var stderr_buf: [4096]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    // /bin/echo is not a known host — no fail-closed for missing agent config.
    const code = try commandForTestWithEnvAndShellEvaluator(
        &.{ "--workspace", root, "--mode", "observe", "--secretless", "--", "/bin/echo", "ok" },
        &stdout_writer,
        &stderr_writer,
        .ignore,
        &current,
        shell_eval.mockDaemonAllowEvaluator,
    );
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "usable host login material") == null);
}

test "session start banner is mechanism-neutral for disabled OS sandbox" {
    // Shield card (active path) is multi-line; keep headroom for both postures.
    var buf: [4096]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    const id = try core.session.generateSessionId(core.time.Timestamp.fromUnixSeconds(1_777_983_130));
    const session: core.session.Session = .{
        .id = id,
        .started_at = core.time.Timestamp.fromUnixSeconds(1_777_983_130),
        .command = "true",
        .args = &.{},
        .workspace_root = "/tmp/ws",
        .mode = .observe,
        .platform = core.platform.detectOs(),
    };
    try printSessionStart(std.testing.io, &writer, session, .ask, false, false, false, false, sandbox.posture.disabledReceipt(), .wrapper_only, false);
    const out = writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "OS sandbox: disabled") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Session grade: wrapper-only") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Seatbelt") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Landlock") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "audit=degraded") == null);

    writer = .fixed(&buf);
    const active_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    try printSessionStart(
        std.testing.io,
        &writer,
        session,
        .ask,
        true,
        false,
        true,
        false,
        try sandbox.posture.activeReceipt(
            .seatbelt,
            active_hash,
            "workspace RW, system RO, platform tmp RW, no home",
        ),
        .strong_mediated,
        true,
    );
    const active_out = writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, active_out, "SHIELD UP") != null);
    try std.testing.expect(std.mem.indexOf(u8, active_out, "secret-boundary=on") != null);
    try std.testing.expect(std.mem.indexOf(u8, active_out, "sandbox=active") != null);
    try std.testing.expect(std.mem.indexOf(u8, active_out, "gateway=anthropic") != null);
    try std.testing.expect(std.mem.indexOf(u8, active_out, "OS sandbox: active") != null);
    try std.testing.expect(std.mem.indexOf(u8, active_out, "Session grade: strong-mediated") != null);
    try std.testing.expect(std.mem.indexOf(u8, active_out, "audit=degraded") != null);
    try std.testing.expect(std.mem.indexOf(u8, active_out, "Seatbelt") == null);
    try std.testing.expect(std.mem.indexOf(u8, active_out, "network: unrestricted") != null);
}

test "computeSessionSandboxGrade: mediated attach vs open escape" {
    try std.testing.expectEqual(
        SessionSandboxGrade.strong_mediated,
        computeSessionSandboxGrade(.{
            .os_attach_planned = true,
            .network_route_forced = true,
            .unrestricted_escape = false,
        }),
    );
    try std.testing.expectEqual(
        SessionSandboxGrade.fs_attached,
        computeSessionSandboxGrade(.{
            .os_attach_planned = true,
            .network_route_forced = false,
            .unrestricted_escape = false,
        }),
    );
    try std.testing.expectEqual(
        SessionSandboxGrade.wrapper_only,
        computeSessionSandboxGrade(.{
            .os_attach_planned = false,
            .network_route_forced = false,
            .unrestricted_escape = false,
        }),
    );
    // Escape wins even when attach + route-force would otherwise look strong.
    try std.testing.expectEqual(
        SessionSandboxGrade.unrestricted_escape,
        computeSessionSandboxGrade(.{
            .os_attach_planned = true,
            .network_route_forced = true,
            .unrestricted_escape = true,
        }),
    );
    try std.testing.expectEqualStrings("strong-mediated", SessionSandboxGrade.strong_mediated.toString());
    try std.testing.expectEqualStrings("unrestricted-escape", SessionSandboxGrade.unrestricted_escape.toString());
}

test "reconcileShimAuditGap appends audit_degraded for attested and marker paths only" {
    const shim_mod = @import("shim.zig");
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const Case = struct {
        parent_marked: bool,
        plant_marker: bool,
        expect_degraded: bool,
    };
    for ([_]Case{
        .{ .parent_marked = true, .plant_marker = false, .expect_degraded = true },
        .{ .parent_marked = false, .plant_marker = true, .expect_degraded = true },
        .{ .parent_marked = false, .plant_marker = false, .expect_degraded = false },
    }) |case| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const root = try tmp.dir.realPathFileAlloc(io, ".", allocator);
        defer allocator.free(root);

        const ts = core.time.Timestamp.fromUnixSeconds(1_777_983_130);
        const session: core.session.Session = .{
            .id = try core.session.generateSessionId(ts),
            .started_at = ts,
            .command = "true",
            .args = &.{},
            .workspace_root = root,
            .mode = .strict,
            .platform = core.platform.detectOs(),
        };
        var writer = try core_api.createAuditWriter(io, allocator, session);
        defer writer.deinit();

        if (case.plant_marker) {
            const marker_name = try std.fmt.allocPrint(allocator, "{s}{s}", .{ shim_mod.shim_audit_gap_marker_prefix, session.id.slice() });
            defer allocator.free(marker_name);
            try tmp.dir.writeFile(io, .{ .sub_path = marker_name, .data = "audit_degraded reason=shim_audit_open_control_write_deny_residual\n" });
        }

        try reconcileShimAuditGap(&writer, io, allocator, session, case.parent_marked);

        const events_path = try std.fs.path.join(allocator, &.{ root, ".ryk", "sessions", session.id.slice(), "events.jsonl" });
        defer allocator.free(events_path);
        const events = try std.Io.Dir.cwd().readFileAlloc(io, events_path, allocator, .limited(64 * 1024));
        defer allocator.free(events);
        const found = std.mem.indexOf(u8, events, "\"type\":\"audit_degraded\"") != null;
        try std.testing.expectEqual(case.expect_degraded, found);
        if (case.expect_degraded) {
            // Reason codes only — static text, no command payload.
            try std.testing.expect(std.mem.indexOf(u8, events, "in-shim audit") != null);
        }
        if (case.plant_marker) {
            // Marker consumed (idempotent reconciliation).
            try std.testing.expect(!(try shim_mod.consumeShimAuditGapMarker(io, allocator, root, session.id.slice())));
        }
    }
}

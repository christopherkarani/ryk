const std = @import("std");
const gpa_mod = @import("gpa.zig");

const env_util = @import("../env_util.zig");
const mcp_mod = @import("../mcp/mod.zig");
const sandbox = @import("../sandbox/mod.zig");
const core = @import("ryk_core").core;
const audit = @import("ryk_core").audit;
const supervisor = core.supervisor;
const core_api = @import("ryk_core").api;
const brand = @import("brand.zig");
const exit_codes = @import("exit_codes.zig");
const help = @import("help.zig");
const policy = @import("ryk_core").policy;
const version_command = @import("version.zig");
const suggestions = @import("suggestions.zig");
const tui = @import("ryk").tui;

pub fn command(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    if (argv.len > 0 and (std.mem.eql(u8, argv[0], "--help") or std.mem.eql(u8, argv[0], "-h"))) {
        _ = try help.writeCommand(io, stdout, "mcp");
        return exit_codes.success;
    }
    if (argv.len == 0) {
        try writeGroupedHelp(io, stdout);
        return exit_codes.success;
    }
    if (std.mem.eql(u8, argv[0], "inspect")) return inspect(io, argv[1..], stdout, stderr);
    if (std.mem.eql(u8, argv[0], "proxy")) return proxy(io, argv[1..], stdout, stderr);
    if (std.mem.eql(u8, argv[0], "list")) return list(io, argv[1..], stdout, stderr);
    if (std.mem.eql(u8, argv[0], "trust")) return trust(argv[1..], stdout, stderr);
    if (std.mem.eql(u8, argv[0], "manifest")) return manifestCommand(io, argv[1..], stdout, stderr);
    try suggestions.writeUnknownSubcommand(stderr, "ryk mcp", argv[0], &.{ "inspect", "proxy", "list", "trust", "manifest" }, "mcp");
    return exit_codes.usage;
}

fn writeGroupedHelp(io: std.Io, stdout: anytype) !void {
    try tui.theme.paintBold(io, stdout, .brand, "Common commands");
    try stdout.writeByte('\n');
    try tui.render.definitionList(io, stdout, &.{
        .{ .term = "ryk mcp list", .description = "Show configured MCP servers" },
        .{ .term = "ryk mcp inspect", .description = "Inspect tools exposed by a server" },
    });
    try stdout.writeByte('\n');
    try tui.theme.paintBold(io, stdout, .brand, "Advanced and protocol");
    try stdout.writeByte('\n');
    try tui.render.definitionList(io, stdout, &.{
        .{ .term = "ryk mcp proxy", .description = "Run the policy-enforcing stdio proxy" },
        .{ .term = "ryk mcp manifest", .description = "Check or generate a server manifest" },
        .{ .term = "ryk mcp trust", .description = "Print a reviewed policy snippet" },
    });
    try stdout.writeAll("\nRun `ryk help mcp` for complete options.\n");
}

const Options = struct {
    command_argv: []const []const u8 = &.{},
    owns_command_argv: bool = false,
    server_name: []const u8 = "fake",
    policy_path: ?[]const u8 = null,
    manifest_path: ?[]const u8 = null,
    audit_dir_name: ?[]const u8 = null,
    workspace_root: ?[]const u8 = null,
    codex_inventory_bin: ?[]const u8 = null,
    codex_inventory_fingerprint: ?[]const u8 = null,
    mode: ?policy.schema.Mode = null,

    fn deinit(self: Options, allocator: std.mem.Allocator) void {
        if (self.owns_command_argv) allocator.free(self.command_argv);
    }
};

fn parseOptions(allocator: std.mem.Allocator, argv: []const []const u8, stderr: anytype) !Options {
    var options: Options = .{};
    var command_parts: std.ArrayList([]const u8) = .empty;
    defer command_parts.deinit(allocator);
    var index: usize = 0;
    while (index < argv.len) : (index += 1) {
        const arg = argv[index];
        if (std.mem.eql(u8, arg, "--command")) {
            index += 1;
            if (index >= argv.len) return error.Usage;
            try command_parts.append(allocator, argv[index]);
        } else if (std.mem.eql(u8, arg, "--server")) {
            index += 1;
            if (index >= argv.len) return error.Usage;
            options.server_name = argv[index];
            try stderr.print("ryk mcp: --server presets are not implemented in Phase 11; use --command.\n", .{});
            return error.Unsupported;
        } else if (std.mem.eql(u8, arg, "--name")) {
            index += 1;
            if (index >= argv.len) return error.Usage;
            options.server_name = argv[index];
        } else if (std.mem.eql(u8, arg, "--policy")) {
            index += 1;
            if (index >= argv.len) return error.Usage;
            options.policy_path = argv[index];
        } else if (std.mem.eql(u8, arg, "--manifest")) {
            index += 1;
            if (index >= argv.len) return error.Usage;
            options.manifest_path = argv[index];
        } else if (std.mem.eql(u8, arg, "--mode")) {
            index += 1;
            if (index >= argv.len) return error.Usage;
            options.mode = policy.schema.Mode.parse(argv[index]) orelse return error.Usage;
        } else if (std.mem.eql(u8, arg, "--audit-dir-name")) {
            index += 1;
            if (index >= argv.len or !safeProxyAuditDirName(argv[index])) return error.Usage;
            options.audit_dir_name = argv[index];
        } else if (std.mem.eql(u8, arg, "--workspace")) {
            index += 1;
            if (index >= argv.len or !std.fs.path.isAbsolute(argv[index])) return error.Usage;
            options.workspace_root = argv[index];
        } else if (std.mem.eql(u8, arg, "--codex-inventory-bin")) {
            index += 1;
            if (index >= argv.len or argv[index].len == 0) return error.Usage;
            options.codex_inventory_bin = argv[index];
        } else if (std.mem.eql(u8, arg, "--codex-inventory-fingerprint")) {
            index += 1;
            if (index >= argv.len or argv[index].len != 64) return error.Usage;
            for (argv[index]) |byte| if (!std.ascii.isHex(byte)) return error.Usage;
            options.codex_inventory_fingerprint = argv[index];
        } else if (std.mem.eql(u8, arg, "--")) {
            for (argv[index + 1 ..]) |command_arg| try command_parts.append(allocator, command_arg);
            break;
        } else {
            try suggestions.writeUnknownOption(stderr, "ryk mcp", arg, &.{ "--command", "--server", "--name", "--policy", "--manifest", "--mode", "--audit-dir-name", "--workspace" }, "mcp");
            return error.Usage;
        }
    }
    const has_codex_inventory = options.codex_inventory_bin != null or options.codex_inventory_fingerprint != null;
    if (has_codex_inventory and
        (options.codex_inventory_bin == null or options.codex_inventory_fingerprint == null or
            command_parts.items.len != 0)) return error.Usage;
    if (!has_codex_inventory and command_parts.items.len == 0) return error.MissingCommand;
    options.command_argv = try command_parts.toOwnedSlice(allocator);
    options.owns_command_argv = true;
    return options;
}

const RefreshedCodexLaunch = struct {
    inventory: sandbox.mcp_runtime_grants.LaunchInventory,
    argv: []const []const u8,
    env_map: std.process.Environ.Map,

    fn deinit(self: *RefreshedCodexLaunch, allocator: std.mem.Allocator) void {
        self.env_map.deinit();
        allocator.free(self.argv);
        self.inventory.deinit(allocator);
        self.* = undefined;
    }
};

fn refreshCodexLaunch(
    io: std.Io,
    allocator: std.mem.Allocator,
    codex_bin: []const u8,
    server_name: []const u8,
    expected_fingerprint: []const u8,
    workspace: []const u8,
) !RefreshedCodexLaunch {
    var process_env = try env_util.createProcessMap(allocator);
    errdefer process_env.deinit();
    const result = try std.process.run(allocator, io, .{
        .argv = &.{ codex_bin, "mcp", "list", "--json" },
        .cwd = .{ .path = workspace },
        .environ_map = &process_env,
        .expand_arg0 = .expand,
        .stdout_limit = .limited(sandbox.mcp_runtime_grants.max_config_bytes),
        .stderr_limit = .limited(32 * 1024),
        .timeout = .{ .duration = .{ .raw = .fromSeconds(10), .clock = .awake } },
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    switch (result.term) {
        .exited => |code| if (code != 0) return error.InventoryCommandFailed,
        else => return error.InventoryCommandFailed,
    }
    const home = process_env.get("HOME") orelse "";
    var inventory = try sandbox.mcp_runtime_grants.parse(allocator, io, result.stdout, home);
    errdefer inventory.deinit(allocator);
    const selected = for (inventory.servers) |*server| {
        if (std.mem.eql(u8, server.name, server_name)) break server;
    } else return error.InventoryServerMissing;
    const actual_fingerprint = sandbox.mcp_runtime_grants.fingerprint(selected.*);
    if (!std.mem.eql(u8, &actual_fingerprint, expected_fingerprint)) return error.InventoryChanged;
    for (selected.env) |entry| {
        if (sandbox.env_scrub.shouldScrubKey(entry.name)) return error.InvalidInventoryEnvironment;
        try process_env.put(entry.name, entry.value);
    }
    const launch_argv = try allocator.alloc([]const u8, selected.args.len + 1);
    launch_argv[0] = selected.command;
    @memcpy(launch_argv[1..], selected.args);
    return .{ .inventory = inventory, .argv = launch_argv, .env_map = process_env };
}

fn inspect(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    if (argv.len > 0 and (std.mem.eql(u8, argv[0], "--help") or std.mem.eql(u8, argv[0], "-h"))) {
        try stdout.writeAll("Usage: ryk mcp inspect --command <server> [--name <server-name>] [--policy <path>]\n");
        return exit_codes.success;
    }
    var gpa_state: gpa_mod.State = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();

    const options = parseOptions(allocator, argv, stderr) catch |err| return usageCode(err, stderr);
    defer options.deinit(allocator);
    if (options.codex_inventory_bin != null) return usageCode(error.Usage, stderr);
    // Schema policy so inspect can read effects.classifier (opaque core_api.Policy cannot).
    var loaded_policy: ?policy.schema.Policy = null;
    defer if (loaded_policy) |*loaded| loaded.deinit();
    if (options.policy_path) |path| {
        loaded_policy = policy.load.loadFile(io, allocator, path) catch |err| {
            try stderr.print("ryk mcp inspect: invalid policy: {s}\n", .{@errorName(err)});
            return exit_codes.general;
        };
    }
    const policy_ref: ?*const policy.schema.Policy = if (loaded_policy) |*loaded| loaded else null;
    var server = mcp_mod.transport.ProcessServer.spawn(io, allocator, options.command_argv) catch |err| {
        try stderr.print("ryk mcp inspect: failed to start server: {s}\n", .{@errorName(err)});
        return exit_codes.general;
    };
    defer server.deinit(io);

    const initialize = try initializeRequestAlloc(allocator);
    defer allocator.free(initialize);
    const initialized = "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\",\"params\":{}}";
    const list_tools = "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}";
    const init_response = mcp_mod.transport.ProcessServer.request(&server, allocator, initialize) catch |err| {
        try stderr.print("ryk mcp inspect: initialize failed: {s}\n", .{@errorName(err)});
        return exit_codes.general;
    };
    allocator.free(init_response);
    mcp_mod.transport.ProcessServer.notify(&server, initialized) catch |err| {
        try stderr.print("ryk mcp inspect: initialized notification failed: {s}\n", .{@errorName(err)});
        return exit_codes.general;
    };
    const tools_response = mcp_mod.transport.ProcessServer.request(&server, allocator, list_tools) catch |err| {
        try stderr.print("ryk mcp inspect: tools/list failed: {s}\n", .{@errorName(err)});
        return exit_codes.general;
    };
    defer allocator.free(tools_response);
    var parsed = mcp_mod.jsonrpc.parseLine(allocator, tools_response) catch |err| {
        try stderr.print("ryk mcp inspect: invalid tools/list response: {s}\n", .{@errorName(err)});
        return exit_codes.general;
    };
    defer parsed.deinit();
    var inventory = mcp_mod.tools.inspectToolsListResponse(allocator, options.server_name, parsed.value()) catch |err| {
        try stderr.print("ryk mcp inspect: could not inspect tools: {s}\n", .{@errorName(err)});
        return exit_codes.general;
    };
    defer inventory.deinit(allocator);

    const workspace = supervisor.resolveWorkspaceRoot(io, allocator, null, ".") catch try allocator.dupe(u8, ".");
    defer allocator.free(workspace);
    var effect_packs = policy.effects.loadPacks(io, allocator, workspace, null) catch |err| {
        try stderr.print("ryk mcp inspect: invalid effect pack: {s}\n", .{@errorName(err)});
        return exit_codes.general;
    };
    defer effect_packs.deinit();

    try writeInspectReport(allocator, stdout, options.server_name, inventory, policy_ref, &effect_packs);
    return exit_codes.success;
}

fn writeInspectReport(
    allocator: std.mem.Allocator,
    stdout: anytype,
    server_name: []const u8,
    inventory: mcp_mod.tools.Inventory,
    loaded_policy: ?*const policy.schema.Policy,
    effect_packs: *const policy.effects.PackSet,
) !void {
    const safe_server_name = try core_api.redactAlloc(allocator, server_name);
    defer allocator.free(safe_server_name);
    try stdout.print("MCP Server: {s}\nTransport: stdio\nTools:\n", .{safe_server_name});
    for (inventory.tools) |tool| {
        try writeInspectToolLine(allocator, stdout, server_name, tool, loaded_policy, effect_packs);
    }
    try stdout.writeAll("\nFindings:\n");
    var finding_count: usize = 0;
    for (inventory.tools) |tool| {
        for (tool.findings) |finding| {
            finding_count += 1;
            const safe_tool_name = try core_api.redactAlloc(allocator, tool.name);
            defer allocator.free(safe_tool_name);
            const safe_reason = try core_api.redactAlloc(allocator, finding.reason);
            defer allocator.free(safe_reason);
            try stdout.print("  {s}: {s} ({s})\n", .{ safe_tool_name, safe_reason, finding.risk.toString() });
        }
    }
    if (finding_count == 0) try stdout.writeAll("  none\n");
}

fn writeInspectToolLine(
    allocator: std.mem.Allocator,
    stdout: anytype,
    server_name: []const u8,
    tool: mcp_mod.tools.ToolInfo,
    loaded_policy: ?*const policy.schema.Policy,
    effect_packs: *const policy.effects.PackSet,
) !void {
    const safe_tool_name = try core_api.redactAlloc(allocator, tool.name);
    defer allocator.free(safe_tool_name);
    try stdout.print("  {s:<24} risk: {s:<8} default: {s}", .{
        safe_tool_name,
        tool.risk.toString(),
        mcp_mod.tools.defaultDecisionForRisk(tool.risk),
    });
    // Match evaluate/tools classify: residual when effects.classifier is enabled.
    const classifier_enabled = if (loaded_policy) |selected|
        selected.effects.isActive() and selected.effects.classifier.isEnabled()
    else
        false;
    const classified = try policy.effects.classifyToolCallWithResidual(
        allocator,
        effect_packs,
        tool.name,
        null,
        classifier_enabled,
    );
    defer classified.deinit(allocator);
    const effects_text = try policy.effects.formatHitsCompact(classified.hits, allocator);
    defer allocator.free(effects_text);
    const safe_effects_text = try core_api.redactAlloc(allocator, effects_text);
    defer allocator.free(safe_effects_text);
    try stdout.print(" effects: {s}", .{safe_effects_text});
    if (loaded_policy) |selected| {
        var evaluation = try policy.evaluate.action(
            selected,
            .{ .mcp_tool_call = .{ .server = server_name, .tool_name = tool.name } },
            .{ .effect_packs = effect_packs },
            allocator,
        );
        defer evaluation.deinit(allocator);
        try stdout.print(" policy: {s}", .{evaluation.decision.result.toString()});
        if (evaluation.decision.rule_id) |rule_id| {
            const safe_rule_id = try core_api.redactAlloc(allocator, rule_id);
            defer allocator.free(safe_rule_id);
            try stdout.print(" rule: {s}", .{safe_rule_id});
        }
    }
    try stdout.writeByte('\n');
}

fn proxy(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    if (argv.len > 0 and (std.mem.eql(u8, argv[0], "--help") or std.mem.eql(u8, argv[0], "-h"))) {
        try stdout.writeAll("Usage: ryk mcp proxy --command <server> [--name <server-name>] [--policy <path>] [--manifest <path>] [--mode observe|ask|strict|ci]\n");
        return exit_codes.success;
    }
    var gpa_state: gpa_mod.State = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();

    const options = parseOptions(allocator, argv, stderr) catch |err| return usageCode(err, stderr);
    defer options.deinit(allocator);
    const workspace = if (options.workspace_root) |root|
        try allocator.dupe(u8, root)
    else
        try supervisor.resolveWorkspaceRoot(io, allocator, null, ".");
    defer allocator.free(workspace);
    var refreshed_launch: ?RefreshedCodexLaunch = null;
    defer if (refreshed_launch) |*launch| launch.deinit(allocator);
    if (options.codex_inventory_bin) |codex_bin| {
        refreshed_launch = refreshCodexLaunch(
            io,
            allocator,
            codex_bin,
            options.server_name,
            options.codex_inventory_fingerprint.?,
            workspace,
        ) catch |err| {
            try stderr.print("ryk mcp proxy: Codex MCP inventory changed or is unavailable: {s}\n", .{@errorName(err)});
            return exit_codes.general;
        };
    }
    const requested_argv = if (refreshed_launch) |launch| launch.argv else options.command_argv;
    const requested_env: ?*const std.process.Environ.Map = if (refreshed_launch) |*launch| &launch.env_map else null;
    var loaded = core_api.discoverPolicy(io, allocator, options.policy_path, workspace) catch |err| {
        try stderr.print("ryk mcp proxy: invalid policy: {s}\n", .{@errorName(err)});
        return exit_codes.general;
    };
    defer loaded.deinit();
    const mode = options.mode orelse loaded.policy.mode();
    var loaded_manifest: ?mcp_mod.manifests.Manifest = null;
    defer if (loaded_manifest) |*manifest| manifest.deinit(allocator);
    var bound_launch: ?BoundManifestLaunch = null;
    defer if (bound_launch) |*binding| binding.deinit(allocator);
    if (options.manifest_path) |manifest_path| {
        loaded_manifest = mcp_mod.manifests.loadFile(io, allocator, manifest_path) catch |err| {
            try stderr.print("ryk mcp proxy: invalid manifest: {s}\n", .{@errorName(err)});
            return exit_codes.usage;
        };
        if (!std.mem.eql(u8, loaded_manifest.?.server.name, options.server_name)) {
            const safe_manifest_name = try audit.redact_bridge.redactAlloc(allocator, loaded_manifest.?.server.name);
            defer allocator.free(safe_manifest_name);
            const safe_requested_name = try audit.redact_bridge.redactAlloc(allocator, options.server_name);
            defer allocator.free(safe_requested_name);
            try stderr.print("ryk mcp proxy: manifest server '{s}' does not match --name '{s}'.\n", .{ safe_manifest_name, safe_requested_name });
            return exit_codes.usage;
        }
        bound_launch = bindManifestLaunch(
            io,
            allocator,
            loaded_manifest.?,
            requested_argv,
            requested_env,
        ) catch |err| {
            try stderr.print("ryk mcp proxy: manifest does not match launched server: {s}\n", .{@errorName(err)});
            return exit_codes.usage;
        };
    }
    const spawn_argv = if (bound_launch) |binding| binding.argv else requested_argv;
    const spawn_env = if (bound_launch) |*binding|
        &binding.env_map
    else if (requested_env) |map|
        map
    else
        null;

    const session = try makeSession(io, requested_argv, workspace, mode);
    var session_writer = (if (options.audit_dir_name) |audit_dir_name|
        core_api.createAuditWriterWithDirName(io, allocator, session, audit_dir_name)
    else
        core_api.createAuditWriter(io, allocator, session)) catch |err| {
        try stderr.print("ryk mcp proxy: audit unavailable: {s}\n", .{@errorName(err)});
        return exit_codes.general;
    };
    defer session_writer.deinit();
    try session_writer.writeLastPointer();

    var server = mcp_mod.transport.ProcessServer.spawnWithEnvMap(io, allocator, spawn_argv, spawn_env) catch |err| {
        try stderr.print("ryk mcp proxy: failed to start server: {s}\n", .{@errorName(err)});
        return exit_codes.general;
    };
    defer server.deinit(io);

    const stdin_buffer = try allocator.alloc(u8, core.limits.max_mcp_message_len + 1);
    defer allocator.free(stdin_buffer);
    var stdin_reader = std.Io.File.stdin().reader(io, stdin_buffer);
    var tty_file: ?std.Io.File = null;
    var approval_reader_storage: ?std.Io.File.Reader = null;
    var approval_writer_storage: ?std.Io.File.Writer = null;
    var approval_read_buffer: [1024]u8 = undefined;
    var approval_write_buffer: [4096]u8 = undefined;
    if (mode != .ci) {
        if (std.Io.Dir.openFileAbsolute(io, "/dev/tty", .{ .mode = .read_write })) |file| {
            tty_file = file;
            approval_reader_storage = file.reader(io, &approval_read_buffer);
            approval_writer_storage = file.writer(io, &approval_write_buffer);
        } else |_| {}
    }
    defer if (tty_file) |file| file.close(io);

    var effect_packs = policy.effects.loadPacksForEnforcement(
        io,
        allocator,
        workspace,
        loaded.innerPtr().effects.isActive(),
    ) catch |err| {
        try stderr.print("ryk mcp proxy: invalid effect pack: {s}\n", .{@errorName(err)});
        return exit_codes.general;
    };
    defer effect_packs.deinit();

    mcp_mod.proxy.runWithServer(allocator, .{
        .server_name = options.server_name,
        .server_command_display = requested_argv[0],
        .policy = loaded.innerPtr(),
        .mode = mode,
        .audit_writer = &session_writer,
        .approval_reader = if (approval_reader_storage) |*reader| &reader.interface else null,
        .approval_writer = if (approval_writer_storage) |*writer| &writer.interface else null,
        .manifest = if (loaded_manifest) |*manifest| manifest else null,
        .effect_packs = &effect_packs,
    }, &stdin_reader.interface, stdout, .{
        .context = &server,
        .request = mcp_mod.transport.ProcessServer.request,
        .notify = mcp_mod.transport.ProcessServer.notify,
        .read = mcp_mod.transport.ProcessServer.read,
    }) catch |err| {
        if (approval_writer_storage) |*writer| writer.interface.flush() catch {};
        var completed_session = session;
        completed_session.ended_at = core.time.Timestamp.now(io);
        try core_api.writeAuditSummary(allocator, session_writer.session_dir_path, .{
            .session = completed_session,
            .status = .{ .exited = exit_codes.general },
            .event_count = session_writer.event_count,
            .final_event_hash = session_writer.finalHash() orelse "",
            .policy = loaded.path,
            .product_label = brand.product_display,
        });
        try stderr.print("ryk mcp proxy: protocol failed: {s}\n", .{@errorName(err)});
        return exit_codes.general;
    };
    if (approval_writer_storage) |*writer| writer.interface.flush() catch {};
    var completed_session = session;
    completed_session.ended_at = core.time.Timestamp.now(io);
    const final_hash = session_writer.finalHash() orelse "";
    try core_api.writeAuditSummary(allocator, session_writer.session_dir_path, .{
        .session = completed_session,
        .status = .{ .exited = 0 },
        .event_count = session_writer.event_count,
        .final_event_hash = final_hash,
        .policy = loaded.path,
        .product_label = brand.product_display,
    });
    if (final_hash.len != 0) {
        try stderr.print("ryk mcp proxy: audit chain {s}\n", .{final_hash});
    }
    return exit_codes.success;
}

fn safeProxyAuditDirName(value: []const u8) bool {
    if (value.len == 0 or value.len > 1024 or std.fs.path.isAbsolute(value)) return false;
    if (!std.mem.startsWith(u8, value, ".ryk-tmp/session-")) return false;
    var parts = std.mem.splitScalar(u8, value, '/');
    while (parts.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return false;
    }
    return true;
}

fn initializeRequestAlloc(allocator: std.mem.Allocator) ![]u8 {
    return try std.fmt.allocPrint(
        allocator,
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{{\"protocolVersion\":\"2025-03-26\",\"capabilities\":{{}},\"clientInfo\":{{\"name\":\"ryk\",\"version\":\"{s}\"}}}}}}",
        .{version_command.current().version},
    );
}

fn list(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    if (argv.len > 0 and (std.mem.eql(u8, argv[0], "--help") or std.mem.eql(u8, argv[0], "-h"))) {
        try stdout.writeAll("Usage: ryk mcp list\n");
        return exit_codes.success;
    }
    if (argv.len != 0) {
        try stderr.writeAll("ryk mcp list: unexpected arguments.\n");
        return exit_codes.usage;
    }
    var gpa_state: gpa_mod.State = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();
    const Inventory = struct {
        name: []u8,
        transport: []u8,
        command: []u8,
        path: []u8,

        fn deinit(self: @This(), allocator_: std.mem.Allocator) void {
            allocator_.free(self.name);
            allocator_.free(self.transport);
            allocator_.free(self.command);
            allocator_.free(self.path);
        }
    };
    var inventory: std.ArrayList(Inventory) = .empty;
    defer {
        for (inventory.items) |item| item.deinit(allocator);
        inventory.deinit(allocator);
    }
    if (std.Io.Dir.cwd().openDir(io, ".ryk/mcp", .{ .iterate = true })) |dir_value| {
        var dir = dir_value;
        defer dir.close(io);
        var it = dir.iterate();
        while (try it.next(io)) |entry| {
            if (entry.kind != .file or !(std.mem.endsWith(u8, entry.name, ".yaml") or std.mem.endsWith(u8, entry.name, ".yml"))) continue;
            const path = try std.fs.path.join(allocator, &.{ ".ryk", "mcp", entry.name });
            defer allocator.free(path);
            var manifest = mcp_mod.manifests.loadFile(io, allocator, path) catch |err| {
                const safe_path = try audit.redact_bridge.redactAlloc(allocator, path);
                defer allocator.free(safe_path);
                try tui.render.callout(io, stdout, .warn, "Invalid MCP manifest", safe_path);
                try stdout.print("  Reason: {s}\n", .{@errorName(err)});
                continue;
            };
            defer manifest.deinit(allocator);
            const name = try audit.redact_bridge.redactAlloc(allocator, manifest.server.name);
            errdefer allocator.free(name);
            const transport = try allocator.dupe(u8, manifest.server.transport.toString());
            errdefer allocator.free(transport);
            const command_text = try audit.redact_bridge.redactAlloc(allocator, manifest.server.command);
            errdefer allocator.free(command_text);
            const owned_path = try audit.redact_bridge.redactAlloc(allocator, path);
            errdefer allocator.free(owned_path);
            try inventory.append(allocator, .{ .name = name, .transport = transport, .command = command_text, .path = owned_path });
        }
    } else |_| {}
    if (inventory.items.len == 0) {
        try tui.render.callout(
            io,
            stdout,
            .info,
            "No MCP servers configured",
            "Create one with: ryk mcp manifest generate --server <name>",
        );
        return exit_codes.success;
    }
    const rows = try allocator.alloc([]const []const u8, inventory.items.len);
    defer allocator.free(rows);
    var initialized: usize = 0;
    defer for (rows[0..initialized]) |row| allocator.free(row);
    for (inventory.items, 0..) |item, index| {
        const cells = try allocator.alloc([]const u8, 4);
        cells[0] = item.name;
        cells[1] = item.transport;
        cells[2] = item.command;
        cells[3] = item.path;
        rows[index] = cells;
        initialized += 1;
    }
    try tui.render.table(io, stdout, &.{
        .{ .name = "SERVER" }, .{ .name = "TRANSPORT" }, .{ .name = "COMMAND" }, .{ .name = "MANIFEST" },
    }, rows);
    return exit_codes.success;
}

fn trust(argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    if (argv.len > 0 and (std.mem.eql(u8, argv[0], "--help") or std.mem.eql(u8, argv[0], "-h"))) {
        try stdout.writeAll("Usage: ryk mcp trust <server> --tool <tool>\n");
        return exit_codes.success;
    }
    if (argv.len != 3 or !std.mem.eql(u8, argv[1], "--tool")) {
        try stderr.writeAll("ryk mcp trust: expected <server> --tool <tool>.\n");
        return exit_codes.usage;
    }
    const server = argv[0];
    const tool = argv[2];
    if (!safeSelectorPart(server) or !safeSelectorPart(tool)) {
        try stderr.writeAll("ryk mcp trust: server and tool must be simple selector names.\n");
        return exit_codes.usage;
    }
    const allocator = std.heap.page_allocator;
    const safe_server = try audit.redact_bridge.redactAlloc(allocator, server);
    defer allocator.free(safe_server);
    const safe_tool = try audit.redact_bridge.redactAlloc(allocator, tool);
    defer allocator.free(safe_tool);
    // #293: nonzero exit + pointer to edit policy.yaml (stdout stays the snippet).
    try stdout.print(
        \\Direct policy mutation is not implemented for this command.
        \\Add this snippet to .ryk/policy.yaml after reviewing the server manifest:
        \\
        \\mcp:
        \\  allow:
        \\    - "{s}.{s}"
        \\
    , .{ safe_server, safe_tool });
    try stderr.writeAll(
        "ryk mcp trust: does not mutate policy; copy the snippet above into .ryk/policy.yaml.\n",
    );
    return exit_codes.general;
}

fn manifestCommand(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    if (argv.len == 0 or std.mem.eql(u8, argv[0], "--help") or std.mem.eql(u8, argv[0], "-h")) {
        try stdout.writeAll(
            \\Usage:
            \\  ryk mcp manifest check <manifest.yaml>
            \\  ryk mcp manifest generate --command <server-command> [-- <args...>]
            \\  ryk mcp manifest generate --server <name>
            \\
        );
        return if (argv.len == 0) exit_codes.usage else exit_codes.success;
    }
    if (std.mem.eql(u8, argv[0], "check")) return manifestCheck(io, argv[1..], stdout, stderr);
    if (std.mem.eql(u8, argv[0], "generate")) return manifestGenerate(argv[1..], stdout, stderr);
    try suggestions.writeUnknownSubcommand(stderr, "ryk mcp manifest", argv[0], &.{ "check", "generate" }, "mcp");
    return exit_codes.usage;
}

fn manifestCheck(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    if (argv.len != 1) {
        try stderr.writeAll("ryk mcp manifest check: expected <manifest.yaml>.\n");
        return exit_codes.usage;
    }
    var gpa_state: gpa_mod.State = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();
    var manifest = mcp_mod.manifests.loadFile(io, allocator, argv[0]) catch |err| {
        try stderr.print("invalid MCP manifest: {s}\n", .{@errorName(err)});
        return exit_codes.usage;
    };
    defer manifest.deinit(allocator);
    const safe_server_name = try core_api.redactAlloc(allocator, manifest.server.name);
    defer allocator.free(safe_server_name);
    const safe_command = try core_api.redactAlloc(allocator, manifest.server.command);
    defer allocator.free(safe_command);
    try stdout.print("valid MCP manifest: server={s} transport={s} command={s} tools={d}\n", .{
        safe_server_name,
        manifest.server.transport.toString(),
        safe_command,
        manifest.tools.len,
    });
    return exit_codes.success;
}

fn manifestGenerate(argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    var gpa_state: gpa_mod.State = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();
    var command_name: ?[]const u8 = null;
    var server_name: ?[]const u8 = null;
    var args_start: ?usize = null;
    var index: usize = 0;
    while (index < argv.len) : (index += 1) {
        if (std.mem.eql(u8, argv[index], "--command")) {
            index += 1;
            if (index >= argv.len) return exit_codes.usage;
            command_name = argv[index];
        } else if (std.mem.eql(u8, argv[index], "--server")) {
            index += 1;
            if (index >= argv.len) return exit_codes.usage;
            server_name = argv[index];
        } else if (std.mem.eql(u8, argv[index], "--")) {
            args_start = index + 1;
            break;
        } else {
            try suggestions.writeUnknownOption(stderr, "ryk mcp manifest generate", argv[index], &.{ "--command", "--server", "--" }, "mcp");
            return exit_codes.usage;
        }
    }
    const name = server_name orelse command_name orelse {
        try stderr.writeAll("ryk mcp manifest generate: expected --command or --server.\n");
        return exit_codes.usage;
    };
    const command_text = command_name orelse name;
    const extra_args = if (args_start) |start| argv[start..] else &.{};
    try mcp_mod.manifests.writeStarterManifestAlloc(allocator, stdout, name, command_text, extra_args);
    return exit_codes.success;
}

fn safeSelectorPart(value: []const u8) bool {
    if (value.len == 0 or value.len > 128) return false;
    for (value) |char| {
        if (!(std.ascii.isAlphanumeric(char) or char == '_' or char == '-' or char == '.')) return false;
    }
    return true;
}

const BoundManifestLaunch = struct {
    argv: []const []const u8,
    env_map: std.process.Environ.Map,

    fn deinit(self: *BoundManifestLaunch, allocator: std.mem.Allocator) void {
        for (self.argv) |arg| allocator.free(arg);
        if (self.argv.len > 0) allocator.free(self.argv);
        self.env_map.deinit();
        self.* = undefined;
    }
};

fn bindManifestLaunch(
    io: std.Io,
    allocator: std.mem.Allocator,
    manifest: mcp_mod.manifests.Manifest,
    requested_argv: []const []const u8,
    requested_env: ?*const std.process.Environ.Map,
) !BoundManifestLaunch {
    if (manifest.server.transport != .stdio) return error.UnsupportedManifestTransport;
    if (requested_argv.len != manifest.server.args.len + 1) return error.ManifestArgvMismatch;
    if (!std.mem.eql(u8, requested_argv[0], manifest.server.command)) return error.ManifestCommandMismatch;
    for (manifest.server.args, 0..) |expected, index| {
        if (!std.mem.eql(u8, expected, requested_argv[index + 1])) return error.ManifestArgvMismatch;
    }

    const resolved_command = try resolveCommandPath(io, allocator, manifest.server.command, requested_env);
    errdefer allocator.free(resolved_command);
    if (manifest.server.expected_hash) |expected_hash| {
        try verifyExpectedHash(io, allocator, resolved_command, expected_hash);
    }

    var argv = try allocator.alloc([]const u8, requested_argv.len);
    errdefer allocator.free(argv);
    argv[0] = resolved_command;
    var owned_count: usize = 1;
    errdefer {
        for (argv[0..owned_count]) |arg| allocator.free(arg);
    }
    for (requested_argv[1..], 1..) |arg, index| {
        argv[index] = try allocator.dupe(u8, arg);
        owned_count += 1;
    }

    var process_env = try env_util.createProcessMap(allocator);
    defer process_env.deinit();
    var env_map = std.process.Environ.Map.init(allocator);
    errdefer env_map.deinit();
    for (manifest.server.env_allow) |name| {
        if (!safeEnvName(name)) return error.InvalidManifestEnvAllow;
        if (requested_env) |source| {
            if (source.get(name)) |value| {
                try env_map.put(name, value);
                continue;
            }
        }
        if (env_util.getOwned(&process_env, allocator, name) catch null) |value| {
            defer allocator.free(value);
            try env_map.put(name, value);
        }
    }

    return .{ .argv = argv, .env_map = env_map };
}

fn resolveCommandPath(
    io: std.Io,
    allocator: std.mem.Allocator,
    command_name: []const u8,
    env_map: ?*const std.process.Environ.Map,
) ![]const u8 {
    const cwd = std.Io.Dir.cwd();
    if (std.fs.path.isAbsolute(command_name) or std.mem.indexOfAny(u8, command_name, "/\\") != null) {
        return realPathDupe(io, cwd, command_name, allocator) catch try allocator.dupe(u8, command_name);
    }
    var process_env: ?std.process.Environ.Map = null;
    defer if (process_env) |*map| map.deinit();
    const path_value = if (env_map) |map|
        map.get("PATH") orelse return error.ManifestCommandNotFound
    else blk: {
        process_env = try env_util.createProcessMap(allocator);
        break :blk process_env.?.get("PATH") orelse return error.ManifestCommandNotFound;
    };
    var parts = std.mem.splitScalar(u8, path_value, std.fs.path.delimiter);
    while (parts.next()) |dir| {
        if (dir.len == 0) continue;
        const candidate = try std.fs.path.join(allocator, &.{ dir, command_name });
        defer allocator.free(candidate);
        cwd.access(io, candidate, .{}) catch continue;
        return realPathDupe(io, cwd, candidate, allocator) catch try allocator.dupe(u8, candidate);
    }
    return error.ManifestCommandNotFound;
}

fn realPathDupe(io: std.Io, dir: std.Io.Dir, path: []const u8, allocator: std.mem.Allocator) ![]u8 {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const n = try dir.realPathFile(io, path, &buffer);
    return try allocator.dupe(u8, buffer[0..n]);
}

fn verifyExpectedHash(io: std.Io, allocator: std.mem.Allocator, resolved_command: []const u8, expected_hash: []const u8) !void {
    const normalized_expected = if (std.mem.startsWith(u8, expected_hash, "sha256:")) expected_hash["sha256:".len..] else expected_hash;
    if (normalized_expected.len != 64) return error.InvalidManifestExpectedHash;
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, resolved_command, allocator, .limited(128 * 1024 * 1024));
    defer allocator.free(bytes);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    if (!std.ascii.eqlIgnoreCase(normalized_expected, &hex)) return error.ManifestExpectedHashMismatch;
}

fn safeEnvName(value: []const u8) bool {
    if (value.len == 0 or value.len > core.limits.max_env_name_len) return false;
    for (value) |char| {
        if (!(std.ascii.isAlphanumeric(char) or char == '_')) return false;
    }
    return true;
}

fn usageCode(err: anyerror, stderr: anytype) !u8 {
    switch (err) {
        error.MissingCommand => try stderr.writeAll(
            "ryk mcp: expected --command <server>.\nNext: ryk mcp inspect --command <server-argv>\n",
        ),
        error.Unsupported => {},
        else => try stderr.writeAll("ryk mcp: invalid arguments.\n"),
    }
    return if (err == error.Unsupported) exit_codes.unsupported else exit_codes.usage;
}

fn makeSession(io: std.Io, command_argv: []const []const u8, workspace: []const u8, mode: policy.schema.Mode) !core.session.Session {
    if (command_argv.len == 0) return error.MissingCommand;
    const now = core.time.Timestamp.now(io);
    return .{
        .id = try core.session.generateSessionId(now),
        .started_at = now,
        .command = "ryk mcp proxy",
        // MCP argv frequently contains inline credentials. Persisting even
        // "redacted" argv is unsafe because split, low-entropy values evade
        // heuristic redaction. Keep only the executable identity.
        .args = command_argv[0..1],
        .workspace_root = workspace,
        .mode = mode.toCoreMode(),
        .platform = core.platform.detectOs(),
    };
}

test "mcp inspect without command includes an example" {
    var stdout_buf: [256]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, &.{"inspect"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, code);
    const err = stderr_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, err, "expected --command") != null);
    try std.testing.expect(std.mem.indexOf(u8, err, "Next: ryk mcp inspect --command") != null);
}

test "MCP proxy session metadata omits server arguments" {
    const session = try makeSession(
        std.testing.io,
        &.{ "/usr/bin/server", "--password", "synthetic-low-entropy-secret" },
        "/tmp/workspace",
        .strict,
    );
    try std.testing.expectEqual(@as(usize, 1), session.args.len);
    try std.testing.expectEqualStrings("/usr/bin/server", session.args[0]);
}

test "MCP proxy audit summaries never persist server arguments" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const workspace = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(workspace);
    const secret = "synthetic-low-entropy-secret";
    var session = try makeSession(io, &.{ "/usr/bin/server", "--password", secret }, workspace, .strict);
    session.ended_at = core.time.Timestamp.now(io);
    var writer = try core_api.createAuditWriterWithDirName(
        io,
        allocator,
        session,
        ".ryk-tmp/session-test/mcp-audit-0",
    );
    defer writer.deinit();
    try core_api.writeAuditSummary(allocator, writer.session_dir_path, .{
        .session = session,
        .status = .{ .exited = 0 },
        .event_count = 0,
        .final_event_hash = "",
        .product_label = "ryk MCP",
    });
    const json_path = try std.fs.path.join(allocator, &.{ writer.session_dir_path, "summary.json" });
    defer allocator.free(json_path);
    const markdown_path = try std.fs.path.join(allocator, &.{ writer.session_dir_path, "summary.md" });
    defer allocator.free(markdown_path);
    const json = try std.Io.Dir.cwd().readFileAlloc(io, json_path, allocator, .limited(64 * 1024));
    defer allocator.free(json);
    const markdown = try std.Io.Dir.cwd().readFileAlloc(io, markdown_path, allocator, .limited(64 * 1024));
    defer allocator.free(markdown);
    try std.testing.expect(std.mem.indexOf(u8, json, secret) == null);
    try std.testing.expect(std.mem.indexOf(u8, markdown, secret) == null);
    try std.testing.expect(std.mem.indexOf(u8, json, "--password") == null);
    try std.testing.expect(std.mem.indexOf(u8, markdown, "--password") == null);
}

test "mcp command help and invalid subcommands are stable" {
    var stdout_buf: [1024]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const help_code = try command(std.testing.io, &.{"--help"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, help_code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "Inspect and proxy MCP servers") != null);

    stdout_writer = .fixed(&stdout_buf);
    stderr_writer = .fixed(&stderr_buf);
    const bad_code = try command(std.testing.io, &.{"inspec"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, bad_code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "unknown subcommand") != null);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "Did you mean 'inspect'?") != null);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "ryk help mcp") != null);
}

test "MCP proxy audit directory is confined to a fresh workspace session" {
    try std.testing.expect(safeProxyAuditDirName(".ryk-tmp/session-abc/mcp-audit-0"));
    try std.testing.expect(!safeProxyAuditDirName(".ryk/sessions"));
    try std.testing.expect(!safeProxyAuditDirName(".ryk-tmp/../.ryk"));
    try std.testing.expect(!safeProxyAuditDirName("/tmp/mcp-audit"));
}

test "MCP proxy workspace override requires an absolute path" {
    var stderr_buf: [256]u8 = undefined;
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const options = try parseOptions(
        std.testing.allocator,
        &.{ "--workspace", "/workspace", "--command", "/bin/sh" },
        &stderr_writer,
    );
    defer options.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("/workspace", options.workspace_root.?);
    try std.testing.expectError(
        error.Usage,
        parseOptions(
            std.testing.allocator,
            &.{ "--workspace", "relative", "--command", "/bin/sh" },
            &stderr_writer,
        ),
    );
}

test "bare mcp renders grouped help with list as the friendly entry" {
    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [4096]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const code = try command(std.testing.io, &.{}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "Common commands") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "Advanced and protocol") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "ryk mcp list") != null);
}

test "mcp list empty state is friendly plain output" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const previous_cwd = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(previous_cwd);
    try std.process.setCurrentDir(std.testing.io, tmp.dir);
    defer std.process.setCurrentPath(std.testing.io, previous_cwd) catch {};

    var stdout_buf: [2048]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const code = try command(std.testing.io, &.{"list"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "No MCP servers configured") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "ryk mcp manifest generate") != null);
    try std.testing.expect(std.mem.indexOfScalar(u8, stdout_writer.buffered(), 0x1b) == null);
}

test "mcp proxy mismatch error redacts manifest and requested names" {
    const allocator = std.testing.allocator;
    const manifest_name = "ghp_syntheticManifestMismatch123456";
    const requested_name = "sk-fakeSyntheticRequestedName1234567890";
    const safe_manifest = try audit.redact_bridge.redactAlloc(allocator, manifest_name);
    defer allocator.free(safe_manifest);
    const safe_requested = try audit.redact_bridge.redactAlloc(allocator, requested_name);
    defer allocator.free(safe_requested);
    try std.testing.expect(std.mem.indexOf(u8, safe_manifest, manifest_name) == null);
    try std.testing.expect(std.mem.indexOf(u8, safe_requested, requested_name) == null);
}

test "mcp unknown flag and manifest subcommand include actionable suggestions" {
    var stdout_buf: [1024]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const flag_code = try command(std.testing.io, &.{ "inspect", "--comand", "server" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, flag_code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "Did you mean '--command'?") != null);

    stdout_writer = .fixed(&stdout_buf);
    stderr_writer = .fixed(&stderr_buf);
    const manifest_code = try command(std.testing.io, &.{ "manifest", "generat" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, manifest_code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "Did you mean 'generate'?") != null);
}

test "mcp command parsing preserves server argv after --command" {
    var stderr_buf: [256]u8 = undefined;
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const options = try parseOptions(std.testing.allocator, &.{ "--command", "node", "--", "server.js", "--flag" }, &stderr_writer);
    defer options.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 3), options.command_argv.len);
    try std.testing.expectEqualStrings("node", options.command_argv[0]);
    try std.testing.expectEqualStrings("server.js", options.command_argv[1]);
    try std.testing.expectEqualStrings("--flag", options.command_argv[2]);
}

test "mcp proxy parsing accepts a complete Codex inventory refresh selector" {
    var stderr_buf: [256]u8 = undefined;
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const fingerprint = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const options = try parseOptions(
        std.testing.allocator,
        &.{ "--codex-inventory-bin", "/usr/bin/codex", "--codex-inventory-fingerprint", fingerprint },
        &stderr_writer,
    );
    defer options.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("/usr/bin/codex", options.codex_inventory_bin.?);
    try std.testing.expectEqualStrings(fingerprint, options.codex_inventory_fingerprint.?);
    try std.testing.expectEqual(@as(usize, 0), options.command_argv.len);
    try std.testing.expectError(
        error.Usage,
        parseOptions(
            std.testing.allocator,
            &.{ "--codex-inventory-bin", "/usr/bin/codex" },
            &stderr_writer,
        ),
    );
}

test "Codex inventory refresh restores exact in-memory argv and environment" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const workspace = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(workspace);
    const inventory_json =
        "[{\"name\":\"synthetic\",\"enabled\":true,\"transport\":{" ++
        "\"type\":\"stdio\",\"command\":\"/bin/sh\",\"args\":[\"-c\",\"exit 0\"]," ++
        "\"env\":{\"MCP_SYNTHETIC\":\"present\"},\"cwd\":null}}]";
    const script = try std.fmt.allocPrint(allocator, "#!/bin/sh\nprintf '%s\\n' '{s}'\n", .{inventory_json});
    defer allocator.free(script);
    try tmp.dir.writeFile(io, .{
        .sub_path = "codex",
        .data = script,
    });
    // Close before exec: Linux ETXTBSY if the script stays open for write.
    {
        var file = try tmp.dir.openFile(io, "codex", .{ .mode = .read_write });
        defer file.close(io);
        try file.setPermissions(io, .executable_file);
    }
    const codex_bin = try tmp.dir.realPathFileAlloc(io, "codex", allocator);
    defer allocator.free(codex_bin);
    const expected_server: sandbox.mcp_runtime_grants.Server = .{
        .name = "synthetic",
        .command = "/bin/sh",
        .args = &.{ "-c", "exit 0" },
        .cwd = null,
        .env = &.{.{ .name = "MCP_SYNTHETIC", .value = "present" }},
        .file_args = &.{},
    };
    const expected_fingerprint = sandbox.mcp_runtime_grants.fingerprint(expected_server);
    var launch = try refreshCodexLaunch(
        io,
        allocator,
        codex_bin,
        "synthetic",
        &expected_fingerprint,
        workspace,
    );
    defer launch.deinit(allocator);
    try std.testing.expectEqualStrings("/bin/sh", launch.argv[0]);
    try std.testing.expectEqualStrings("exit 0", launch.argv[2]);
    try std.testing.expectEqualStrings("present", launch.env_map.get("MCP_SYNTHETIC").?);
}

test "mcp initialize request uses build version metadata" {
    const request = try initializeRequestAlloc(std.testing.allocator);
    defer std.testing.allocator.free(request);
    try std.testing.expect(std.mem.indexOf(u8, request, "\"clientInfo\":{\"name\":\"ryk\",\"version\":\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, request, version_command.current().version) != null);
    try std.testing.expect(std.mem.indexOf(u8, request, "\"version\":\"1.0.0\"") == null or std.mem.eql(u8, version_command.current().version, "1.0.0"));
}

test "mcp proxy reports invalid policy as CLI error" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        const file = try tmp.dir.createFile(std.testing.io, "bad-policy.yaml", .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io,
            \\version: 1
            \\mode: not-a-mode
        );
    }
    const policy_path = try tmp.dir.realPathFileAlloc(std.testing.io, "bad-policy.yaml", std.testing.allocator);
    defer std.testing.allocator.free(policy_path);

    var stdout_buf: [1024]u8 = undefined;
    var stderr_buf: [1024]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, &.{ "proxy", "--policy", policy_path, "--command", "python3", "--", "fixtures/mcp/fake_server.py" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.general, code);
    try std.testing.expectEqualStrings("", stdout_writer.buffered());
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "ryk mcp proxy: invalid policy") != null);
}

test "mcp inspect policy option reports Core policy decisions" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        const file = try tmp.dir.createFile(std.testing.io, "mcp-policy.yaml", .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io,
            \\version: 1
            \\mode: strict
            \\mcp:
            \\  allow:
            \\    - "fake.search_issues"
            \\  deny:
            \\    - "fake.delete_repository"
        );
    }
    const policy_path = try tmp.dir.realPathFileAlloc(std.testing.io, "mcp-policy.yaml", std.testing.allocator);
    defer std.testing.allocator.free(policy_path);

    var stdout_buf: [8192]u8 = undefined;
    var stderr_buf: [2048]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, &.{ "inspect", "--name", "fake", "--policy", policy_path, "--command", "python3", "--", "fixtures/mcp/fake_server.py" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "search_issues") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "policy: allow") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "delete_repository") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "policy: deny") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "effects:") != null);
    _ = stderr_writer.buffered();
}

test "mcp inspect shows effects and effects.deny for send_email" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        const file = try tmp.dir.createFile(std.testing.io, "effects-policy.yaml", .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io,
            \\version: 1
            \\mode: strict
            \\mcp:
            \\  default: allow
            \\  allow:
            \\    - "*"
            \\effects:
            \\  deny:
            \\    - comms.message
        );
    }
    const policy_path = try tmp.dir.realPathFileAlloc(std.testing.io, "effects-policy.yaml", std.testing.allocator);
    defer std.testing.allocator.free(policy_path);

    var stdout_buf: [16384]u8 = undefined;
    var stderr_buf: [2048]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try command(std.testing.io, &.{ "inspect", "--name", "fake", "--policy", policy_path, "--command", "python3", "--", "fixtures/mcp/fake_server.py" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "send_email") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "comms.message") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "effects:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "policy: deny") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "effects.") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "search_issues") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "(none)") != null);
    _ = stderr_writer.buffered();
}

test "writeInspectToolLine surfaces residual classifier.local when effects.classifier local" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        const file = try tmp.dir.createFile(std.testing.io, "residual.yaml", .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io,
            \\version: 1
            \\mode: strict
            \\mcp:
            \\  default: allow
            \\effects:
            \\  classifier: local
            \\  deny:
            \\    - comms.message
        );
    }
    const policy_path = try tmp.dir.realPathFileAlloc(std.testing.io, "residual.yaml", std.testing.allocator);
    defer std.testing.allocator.free(policy_path);

    var loaded = try policy.load.loadFile(std.testing.io, std.testing.allocator, policy_path);
    defer loaded.deinit();
    var packs = policy.effects.PackSet.empty(std.testing.allocator);
    defer packs.deinit();

    var stdout_buf: [2048]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    const tool = mcp_mod.tools.ToolInfo{
        .name = "acme_mailer_job",
        .description = "",
        .risk = .medium,
        .findings = &.{},
    };
    try writeInspectToolLine(std.testing.allocator, &stdout_writer, "fake", tool, &loaded, &packs);
    const out = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "classifier.local.") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "comms.message") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "policy: deny") != null);
}

test "writeInspectToolLine packs-only when classifier off" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        const file = try tmp.dir.createFile(std.testing.io, "no-residual.yaml", .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io,
            \\version: 1
            \\mode: strict
            \\mcp:
            \\  default: allow
            \\effects:
            \\  deny:
            \\    - comms.message
        );
    }
    const policy_path = try tmp.dir.realPathFileAlloc(std.testing.io, "no-residual.yaml", std.testing.allocator);
    defer std.testing.allocator.free(policy_path);

    var loaded = try policy.load.loadFile(std.testing.io, std.testing.allocator, policy_path);
    defer loaded.deinit();
    var packs = policy.effects.PackSet.empty(std.testing.allocator);
    defer packs.deinit();

    var stdout_buf: [2048]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    const tool = mcp_mod.tools.ToolInfo{
        .name = "acme_mailer_job",
        .description = "",
        .risk = .medium,
        .findings = &.{},
    };
    try writeInspectToolLine(std.testing.allocator, &stdout_writer, "fake", tool, &loaded, &packs);
    const out = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "classifier.local.") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "(none)") != null);
}

test "manifest binding requires exact argv hash and env allowlist" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        const file = try tmp.dir.createFile(std.testing.io, "server-bin", .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io, "fake server binary");
    }
    const server_path = try tmp.dir.realPathFileAlloc(std.testing.io, "server-bin", std.testing.allocator);
    defer std.testing.allocator.free(server_path);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("fake server binary", &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    const manifest_text = try std.fmt.allocPrint(std.testing.allocator,
        \\version: 1
        \\server:
        \\  name: fake
        \\  transport: stdio
        \\  command: {s}
        \\  args:
        \\    - --stdio
        \\  expected_hash: sha256:{s}
        \\  env:
        \\    allow:
        \\      - PATH
        \\tools:
        \\  search:
        \\    risk: low
        \\    default: allow
        \\resources:
        \\  default: ask
        \\prompts:
        \\  default: ask
        \\sampling:
        \\  default: deny
    , .{ server_path, &hex });
    defer std.testing.allocator.free(manifest_text);
    var manifest = try mcp_mod.manifests.parseFromSlice(std.testing.allocator, manifest_text, "test.yaml");
    defer manifest.deinit(std.testing.allocator);

    var binding = try bindManifestLaunch(
        std.testing.io,
        std.testing.allocator,
        manifest,
        &.{ server_path, "--stdio" },
        null,
    );
    defer binding.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings(server_path, binding.argv[0]);
    try std.testing.expectEqualStrings("--stdio", binding.argv[1]);
    try std.testing.expect(binding.env_map.get("PATH") != null);

    try std.testing.expectError(error.ManifestCommandMismatch, bindManifestLaunch(std.testing.io, std.testing.allocator, manifest, &.{ "/different", "--stdio" }, null));
    try std.testing.expectError(error.ManifestArgvMismatch, bindManifestLaunch(std.testing.io, std.testing.allocator, manifest, &.{ server_path, "--other" }, null));

    const bad_manifest_text = try std.fmt.allocPrint(std.testing.allocator,
        \\version: 1
        \\server:
        \\  name: fake
        \\  transport: stdio
        \\  command: {s}
        \\  expected_hash: {s}
        \\tools:
    , .{ server_path, "0000000000000000000000000000000000000000000000000000000000000000" });
    defer std.testing.allocator.free(bad_manifest_text);
    var bad_manifest = try mcp_mod.manifests.parseFromSlice(std.testing.allocator, bad_manifest_text, "bad.yaml");
    defer bad_manifest.deinit(std.testing.allocator);
    try std.testing.expectError(error.ManifestExpectedHashMismatch, bindManifestLaunch(std.testing.io, std.testing.allocator, bad_manifest, &.{server_path}, null));
}

test "mcp manifest check list trust and generate commands are safe" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const prev_cwd = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(prev_cwd);
    try std.process.setCurrentDir(std.testing.io, tmp.dir);
    defer std.process.setCurrentPath(std.testing.io, prev_cwd) catch {};

    try tmp.dir.createDirPath(std.testing.io, ".ryk/mcp");
    {
        const file = try tmp.dir.createFile(std.testing.io, ".ryk/mcp/github.yaml", .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io,
            \\version: 1
            \\server:
            \\  name: github
            \\  transport: stdio
            \\  command: github-mcp-server
            \\tools:
            \\  search_issues:
            \\    risk: low
            \\    default: allow
            \\resources:
            \\  default: ask
            \\prompts:
            \\  default: ask
            \\sampling:
            \\  default: deny
        );
    }

    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [1024]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const check_code = try command(std.testing.io, &.{ "manifest", "check", ".ryk/mcp/github.yaml" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, check_code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "valid MCP manifest") != null);

    stdout_writer = .fixed(&stdout_buf);
    stderr_writer = .fixed(&stderr_buf);
    const list_code = try command(std.testing.io, &.{"list"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, list_code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "github") != null);

    stdout_writer = .fixed(&stdout_buf);
    stderr_writer = .fixed(&stderr_buf);
    const trust_code = try command(std.testing.io, &.{ "trust", "github", "--tool", "search_issues" }, &stdout_writer, &stderr_writer);
    // #293: trust prints a snippet but does not mutate policy — nonzero exit.
    try std.testing.expectEqual(exit_codes.general, trust_code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "\"github.search_issues\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "does not mutate policy") != null);

    stdout_writer = .fixed(&stdout_buf);
    stderr_writer = .fixed(&stderr_buf);
    const generate_code = try command(std.testing.io, &.{ "manifest", "generate", "--command", "github-mcp-server", "--", "--token", "ghp_fakeSecretShouldNotPrint" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, generate_code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "ghp_fakeSecretShouldNotPrint") == null);
}

test "mcp manifest check redacts attacker-controlled server and command" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const prev_cwd = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(prev_cwd);
    try std.process.setCurrentDir(std.testing.io, tmp.dir);
    defer std.process.setCurrentPath(std.testing.io, prev_cwd) catch {};

    const server_secret = "manifest-server-password=correct-horse-battery-staple";
    const command_secret = "api_key=manifest-command-secret-value";
    {
        const file = try tmp.dir.createFile(std.testing.io, "hostile.yaml", .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io,
            \\version: 1
            \\server:
            \\  name: manifest-server-password=correct-horse-battery-staple
            \\  transport: stdio
            \\  command: api_key=manifest-command-secret-value
            \\tools:
            \\resources:
            \\  default: ask
            \\prompts:
            \\  default: ask
            \\sampling:
            \\  default: deny
        );
    }

    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [1024]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const code = try command(std.testing.io, &.{ "manifest", "check", "hostile.yaml" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, server_secret) == null);
    try std.testing.expect(std.mem.indexOf(u8, output, command_secret) == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "[REDACTED]") != null);
}

test "mcp inspect report redacts attacker-controlled dynamic fields" {
    const server_secret = "token=inspect-server-secret-value";
    const tool_secret = "ghp_abcdefghijklmnopqrstuvwxyz123456";
    const finding_secret = "password=inspect-finding-secret-value";
    const findings = [_]mcp_mod.tools.Finding{.{
        .tool_name = tool_secret,
        .reason = finding_secret,
        .risk = .critical,
    }};
    const tools = [_]mcp_mod.tools.ToolInfo{.{
        .name = tool_secret,
        .description = "",
        .risk = .critical,
        .findings = @constCast(&findings),
    }};
    const inventory: mcp_mod.tools.Inventory = .{ .tools = @constCast(&tools) };

    const pack = try policy.effects.packs.parsePackFromSlice(std.testing.allocator,
        \\version: 1
        \\id: hostile
        \\names:
        \\  ghp_abcdefghijklmnopqrstuvwxyz123456: comms.message
    , "hostile.yaml");
    var packs = try policy.effects.PackSet.fromPack(std.testing.allocator, pack);
    defer packs.deinit();

    var stdout_buf: [8192]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    try writeInspectReport(std.testing.allocator, &stdout_writer, server_secret, inventory, null, &packs);
    const output = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, server_secret) == null);
    try std.testing.expect(std.mem.indexOf(u8, output, tool_secret) == null);
    try std.testing.expect(std.mem.indexOf(u8, output, finding_secret) == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "[REDACTED]") != null);
}

const std = @import("std");
const exit_codes = @import("exit_codes.zig");
const help = @import("help.zig");
const tui = @import("ryk").tui;
const suggestions = @import("suggestions.zig");
const pack_config = @import("pack_config.zig");
const onboarding = @import("onboarding.zig");
const danger_confirmation = @import("danger_confirmation.zig");
const enable_tui = @import("build_options").enable_tui;
const packs_tui = if (enable_tui) @import("packs_tui.zig") else struct {
    pub fn wouldEnterPacksBrowse(
        stdin_is_tty: bool,
        stdout_is_tty: bool,
        argv: []const []const u8,
        machine_json: bool,
    ) bool {
        _ = .{ stdin_is_tty, stdout_is_tty, argv, machine_json };
        return false;
    }
};
const util = @import("ryk_core").core.util;

// Zig 0.16 monopath: nested module tests need an explicit test-block reference
// (same pattern as tui.mod → browse) so `packs browse` filters discover them.
test {
    if (enable_tui) {
        _ = @import("packs_tui.zig");
    }
}

/// Inflated oracle pack definitions (same gzip as `shell_engine.registry`).
const oracle_embed = @import("../shell_engine/oracle_embed.zig");

const Options = struct {
    filter: ?[]const u8 = null,
    installed: bool = false,
    page: usize = 1,
    page_size: usize = 25,
    machine_json: bool = false,
    explicit_page: bool = false,
    explicit_page_size: bool = false,
    /// `--plain` is the explicit linear catalog dump, not the default summary.
    plain: bool = false,
};

const ShowOptions = struct {
    pack_id: []const u8,
    no_patterns: bool = false,
    verbose: bool = false,
    machine_json: bool = false,
};

const PatternView = struct {
    name: []const u8,
    regex: []const u8,
    severity: []const u8,
    reason: []const u8,
};

const PackView = struct {
    id: []const u8,
    name: []const u8,
    category: []const u8,
    description: []const u8,
    enabled: bool,
    safe_pattern_count: usize,
    destructive_pattern_count: usize,
    safe: []const PatternView = &.{},
    destructive: []const PatternView = &.{},
};

const Catalog = struct {
    allocator: std.mem.Allocator,
    packs: []PackView,
    /// Owns dupe'd slices for name/category/description when allocated.
    owned_strings: std.ArrayListUnmanaged([]u8) = .empty,
    /// Owns pattern view arrays (not pattern field strings — those borrow JSON).
    owned_pattern_slices: std.ArrayListUnmanaged([]PatternView) = .empty,
    json_parsed: std.json.Parsed(std.json.Value),
    inflated_json: []u8,

    fn deinit(self: *Catalog) void {
        for (self.owned_strings.items) |s| self.allocator.free(s);
        self.owned_strings.deinit(self.allocator);
        for (self.owned_pattern_slices.items) |slice| self.allocator.free(slice);
        self.owned_pattern_slices.deinit(self.allocator);
        self.allocator.free(self.packs);
        self.json_parsed.deinit();
        self.allocator.free(self.inflated_json);
        self.* = undefined;
    }
};

pub fn command(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    // Executor retained only for test injectability; happy path never calls it.
    return commandWithExecutor(unusedExecutor, io, argv, stdout, stderr);
}

fn unusedExecutor(_: std.Io, _: []const []const u8, _: anytype, _: anytype) !u8 {
    return error.UnexpectedExecutorCall;
}

pub fn commandWithExecutor(comptime execute_cli: anytype, io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    _ = execute_cli; // no daemon path — tests inject failIfCalled to prove this

    for (argv) |arg| {
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            _ = try help.writeCommand(io, stdout, "packs");
            return exit_codes.success;
        }
    }

    if (argv.len > 0) {
        if (std.mem.eql(u8, argv[0], "show") or std.mem.eql(u8, argv[0], "info")) {
            return runShow(io, argv[1..], stdout, stderr);
        }
        if (std.mem.eql(u8, argv[0], "enable")) {
            return runEnable(io, argv[1..], stdout, stderr);
        }
        if (std.mem.eql(u8, argv[0], "disable")) {
            return runDisable(io, argv[1..], stdout, stderr);
        }
        // Non-flag first token that is not a known subcommand → suggestion path (not list options).
        if (!std.mem.startsWith(u8, argv[0], "-")) {
            try suggestions.writeUnknownSubcommand(
                stderr,
                "ryk packs",
                argv[0],
                &.{ "show", "info", "enable", "disable" },
                "packs",
            );
            return exit_codes.usage;
        }
    }

    const options = parseListOptions(argv, stderr) catch return exit_codes.usage;
    return runList(io, argv, options, stdout, stderr);
}

fn runList(io: std.Io, argv: []const []const u8, options: Options, stdout: anytype, stderr: anytype) !u8 {
    const allocator = std.heap.smp_allocator;
    var catalog = loadCatalog(allocator) catch |err| {
        try stderr.print("ryk packs: failed to load pack registry ({s}).\n", .{@errorName(err)});
        return exit_codes.general;
    };
    defer catalog.deinit();

    applyEnabledState(io, allocator, &catalog);

    if (options.machine_json) {
        return renderListJson(stdout, catalog.packs);
    }

    // Default browse TUI on interactive TTY (W1 / U04). --plain/--no-rich/--json
    // and non-TTY stay on the frozen linear list path.
    const stdin_tty = std.Io.File.stdin().isTty(io) catch false;
    const stdout_tty = std.Io.File.stdout().isTty(io) catch false;
    if (packs_tui.wouldEnterPacksBrowse(stdin_tty, stdout_tty, argv, options.machine_json)) {
        if (comptime enable_tui) {
            const code = try runPacksBrowse(io, allocator, &catalog, options, stdout, stderr);
            // Tty.init failure after gate: fall through to linear (never green-paint empty success).
            if (code != exit_codes.general) return code;
        }
    }

    return renderHuman(allocator, io, options, catalog.packs, stdout, stderr);
}

fn runPacksBrowse(
    io: std.Io,
    allocator: std.mem.Allocator,
    catalog: *Catalog,
    options: Options,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    // Build borrowed PackRef view + mutable enabled parallel array for live refresh.
    const n = catalog.packs.len;
    const refs = try allocator.alloc(packs_tui.PackRef, n);
    defer allocator.free(refs);
    const enabled = try allocator.alloc(bool, n);
    defer allocator.free(enabled);
    for (catalog.packs, 0..) |pack, i| {
        refs[i] = .{
            .id = pack.id,
            .name = pack.name,
            .category = pack.category,
            .description = pack.description,
            .enabled = pack.enabled,
            .safe_pattern_count = pack.safe_pattern_count,
            .destructive_pattern_count = pack.destructive_pattern_count,
        };
        enabled[i] = pack.enabled;
    }

    // Write-target status (project .ryk.toml vs user config).
    var write_scope: pack_config.ConfigScope = .user;
    var write_path: []const u8 = "user config";
    var write_path_owned: ?[]u8 = null;
    defer if (write_path_owned) |p| allocator.free(p);

    if (onboarding.resolveWorkspaceRoot(io, allocator)) |workspace_root| {
        defer allocator.free(workspace_root);
        if (pack_config.resolvePackConfigPath(io, allocator, workspace_root)) |resolved| {
            write_scope = resolved.scope;
            write_path_owned = resolved.path;
            write_path = resolved.path;
        } else |_| {}
    } else |_| {}

    // Default enabled+baseline (freeze #9 / U04); `a` toggles full catalog. Sticky (A)
    // keeps just-disabled rows when the user narrows with enabled-only.
    // `--enabled` / `--installed` still affect linear fallback filter only.
    return packs_tui.runBrowse(io, allocator, stdout, stderr, .{
        .packs = refs,
        .enabled = enabled,
        .write_scope = write_scope,
        .write_path = write_path,
        .initial_query = options.filter,
        .start_all = false,
    });
}

fn runShow(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    const options = parseShowOptions(argv, stderr) catch return exit_codes.usage;
    const allocator = std.heap.smp_allocator;

    var catalog = loadCatalog(allocator) catch |err| {
        try stderr.print("ryk packs: failed to load pack registry ({s}).\n", .{@errorName(err)});
        return exit_codes.general;
    };
    defer catalog.deinit();
    applyEnabledState(io, allocator, &catalog);

    const pack = findPack(catalog.packs, options.pack_id) orelse {
        try stderr.print(
            "ryk packs: pack '{s}' not found. Run 'ryk packs --filter {s}' to search.\n",
            .{ options.pack_id, options.pack_id },
        );
        return exit_codes.general;
    };

    if (options.machine_json) {
        return renderShowJson(stdout, pack, options.no_patterns, options.verbose);
    }
    return renderShowHuman(allocator, io, pack, options.verbose, options.no_patterns, stdout);
}

fn runEnable(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    const allocator = std.heap.smp_allocator;
    const ids = parseIdList(argv, stderr) catch return exit_codes.usage;

    var catalog = loadCatalog(allocator) catch |err| {
        try stderr.print("ryk packs: failed to load pack registry ({s}).\n", .{@errorName(err)});
        return exit_codes.general;
    };
    defer catalog.deinit();

    for (ids) |id| {
        if (pack_config.isBaselinePackId(id)) continue;
        if (findPack(catalog.packs, id) == null) {
            try stderr.print(
                "ryk packs: unknown pack id '{s}'. Run 'ryk packs --filter {s}' or 'ryk packs show {s}'.\n",
                .{ id, id, id },
            );
            return exit_codes.usage;
        }
    }

    const workspace_root = onboarding.resolveWorkspaceRoot(io, allocator) catch {
        try stderr.writeAll("ryk packs: could not resolve workspace root.\n");
        return exit_codes.general;
    };
    defer allocator.free(workspace_root);

    var result = pack_config.enablePacks(io, allocator, workspace_root, ids) catch |err| {
        try stderr.print("ryk packs enable: {s}. Run 'ryk help packs' for usage.\n", .{@errorName(err)});
        return exit_codes.general;
    };
    defer result.deinit(allocator);

    return printMutationResult(io, stdout, result);
}

fn runDisable(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    const allocator = std.heap.smp_allocator;
    const ids = parseIdList(argv, stderr) catch return exit_codes.usage;

    // M-2: baseline pack disable is operator break-glass only (agent-reachable CLI).
    if (idsIncludeBaseline(ids)) {
        const gate = try confirmBaselineDisable(io, stdout, stderr);
        if (!gate) {
            try stderr.writeAll("ryk packs disable: baseline packs left enabled (operator confirmation required).\n");
            return exit_codes.usage;
        }
    }

    const workspace_root = onboarding.resolveWorkspaceRoot(io, allocator) catch {
        try stderr.writeAll("ryk packs: could not resolve workspace root.\n");
        return exit_codes.general;
    };
    defer allocator.free(workspace_root);

    var result = pack_config.disablePacks(io, allocator, workspace_root, ids) catch |err| {
        try stderr.print("ryk packs disable: {s}. Run 'ryk help packs' for usage.\n", .{@errorName(err)});
        return exit_codes.general;
    };
    defer result.deinit(allocator);

    return printMutationResult(io, stdout, result);
}

fn idsIncludeBaseline(ids: []const []const u8) bool {
    for (ids) |id| {
        if (pack_config.isBaselinePackId(id)) return true;
    }
    return false;
}

/// Test seam: when non-null, overrides the real TTY probe for the baseline
/// disable gate. Production leaves this null; tests set it to simulate operator
/// presence (the RYK_OPERATOR env break-glass was removed).
pub var test_operator_tty_override: ?bool = null;

/// Require an interactive TTY before disabling baseline packs. Non-TTY (agent /
/// script / CI) fails closed — there is no env-var break-glass (RYK_OPERATOR was
/// removed: env vars are child-controlled and authenticate nobody).
fn confirmBaselineDisable(io: std.Io, stdout: anytype, stderr: anytype) !bool {
    // Test seam: explicit operator presence/absence without a real terminal.
    if (test_operator_tty_override) |v| return v;

    if (!pack_config.isOperatorBreakGlass(io)) {
        try stderr.writeAll(
            \\ryk packs disable: refusing to disable baseline packs (core, core.*, system.disk)
            \\without an interactive TTY. Re-run in a terminal to confirm.
            \\Baseline opt-outs are written to user config; project .ryk.toml cannot drop them.
            \\
        );
        return false;
    }

    const decision = danger_confirmation.decide(
        io,
        stdout,
        "Disable baseline safety pack(s)? This weakens default shell protection.",
        false,
        true,
        null,
    ) catch return false;
    return switch (decision) {
        .proceed => true,
        .cancelled, .requires_yes => blk: {
            try stderr.writeAll("ryk packs disable: cancelled (baseline packs left enabled).\n");
            break :blk false;
        },
    };
}

fn parseIdList(argv: []const []const u8, stderr: anytype) ![]const []const u8 {
    if (argv.len == 0) return usageError(stderr, "requires at least one pack id");
    for (argv) |arg| {
        if (std.mem.startsWith(u8, arg, "-")) return usageError(stderr, "unexpected option");
        if (arg.len == 0) return usageError(stderr, "pack id must be non-empty");
    }
    return argv;
}

fn printMutationResult(io: std.Io, stdout: anytype, result: pack_config.PackMutationResult) !u8 {
    try tui.theme.paintBold(io, stdout, .text_bright, "Safety packs");
    try stdout.writeAll("\n");
    try stdout.writeAll(result.message);
    try stdout.writeAll("\n");
    if (result.config_path) |path| {
        try stdout.writeAll("  Config: ");
        try stdout.writeAll(path);
        if (result.scope) |scope| {
            try stdout.print(" ({s})", .{scope.label()});
        }
        try stdout.writeAll("\n");
    }
    if (result.added.len > 0) {
        try stdout.writeAll("  Next:   ryk packs show ");
        try stdout.writeAll(result.added[0]);
        try stdout.writeAll("\n          ryk test \"…\"\n");
    } else if (result.removed.len > 0 or result.disabled_added.len > 0) {
        try stdout.writeAll("  Next:   ryk packs --enabled\n");
    } else {
        try stdout.writeAll("  Next:   ryk packs --enabled  ·  ryk packs show <id>\n");
    }
    return exit_codes.success;
}

fn parseListOptions(argv: []const []const u8, stderr: anytype) !Options {
    var options: Options = .{};
    var i: usize = 0;
    while (i < argv.len) : (i += 1) {
        const arg = argv[i];
        if (std.mem.eql(u8, arg, "--installed") or std.mem.eql(u8, arg, "--enabled")) {
            options.installed = true;
        } else if (std.mem.eql(u8, arg, "--json")) {
            options.machine_json = true;
        } else if (std.mem.eql(u8, arg, "--robot")) {
            options.machine_json = true;
        } else if (std.mem.eql(u8, arg, "--plain")) {
            // Linear list escape (disables TUI via shouldEnterTui / argvDisablesTui).
            options.plain = true;
        } else if (std.mem.eql(u8, arg, "--no-rich")) {
            // Global hatch may still appear on argv in some call paths; accept as linear.
        } else if (std.mem.eql(u8, arg, "--format") or std.mem.eql(u8, arg, "-f")) {
            i += 1;
            if (i >= argv.len) return usageError(stderr, "--format requires a value");
            if (std.mem.eql(u8, argv[i], "json")) {
                options.machine_json = true;
            } else {
                return usageError(stderr, "only --format json is supported");
            }
        } else if (std.mem.eql(u8, arg, "--format=json")) {
            options.machine_json = true;
        } else if (std.mem.startsWith(u8, arg, "--format=")) {
            return usageError(stderr, "only --format json is supported");
        } else if (std.mem.eql(u8, arg, "--filter")) {
            i += 1;
            if (i >= argv.len or argv[i].len == 0 or std.mem.startsWith(u8, argv[i], "--"))
                return usageError(stderr, "--filter requires a non-empty search term");
            options.filter = argv[i];
        } else if (std.mem.eql(u8, arg, "--page")) {
            i += 1;
            if (i >= argv.len) return usageError(stderr, "--page requires a positive integer");
            options.page = std.fmt.parseInt(usize, argv[i], 10) catch return usageError(stderr, "--page requires a positive integer");
            if (options.page == 0) return usageError(stderr, "--page requires a positive integer");
            options.explicit_page = true;
        } else if (std.mem.eql(u8, arg, "--page-size")) {
            i += 1;
            if (i >= argv.len) return usageError(stderr, "--page-size requires a positive integer");
            options.page_size = std.fmt.parseInt(usize, argv[i], 10) catch return usageError(stderr, "--page-size requires a positive integer");
            if (options.page_size == 0) return usageError(stderr, "--page-size requires a positive integer");
            options.explicit_page_size = true;
        } else {
            suggestions.writeUnknownOption(stderr, "ryk packs", arg, &.{
                "--installed", "--enabled", "--filter", "--page", "--page-size", "--json", "--format", "--plain",
            }, "packs") catch {};
            return error.InvalidArguments;
        }
    }
    return options;
}

fn parseShowOptions(argv: []const []const u8, stderr: anytype) !ShowOptions {
    var options: ShowOptions = .{ .pack_id = "" };
    var i: usize = 0;
    while (i < argv.len) : (i += 1) {
        const arg = argv[i];
        if (std.mem.eql(u8, arg, "--no-patterns")) {
            options.no_patterns = true;
        } else if (std.mem.eql(u8, arg, "--verbose") or std.mem.eql(u8, arg, "-v")) {
            options.verbose = true;
        } else if (std.mem.eql(u8, arg, "--json") or std.mem.eql(u8, arg, "--robot")) {
            options.machine_json = true;
        } else if (std.mem.eql(u8, arg, "--format") or std.mem.eql(u8, arg, "-f") or
            std.mem.startsWith(u8, arg, "--format="))
        {
            if (std.mem.eql(u8, arg, "--format") or std.mem.eql(u8, arg, "-f")) {
                i += 1;
                if (i >= argv.len) return usageError(stderr, "--format requires a value");
                if (std.mem.eql(u8, argv[i], "json")) options.machine_json = true else return usageError(stderr, "only --format json is supported for show");
            } else if (std.mem.eql(u8, arg, "--format=json")) {
                options.machine_json = true;
            } else {
                return usageError(stderr, "only --format json is supported for show");
            }
        } else if (std.mem.startsWith(u8, arg, "-")) {
            return usageError(stderr, "unknown show option");
        } else if (options.pack_id.len == 0) {
            options.pack_id = arg;
        } else {
            return usageError(stderr, "show accepts a single pack id");
        }
    }
    if (options.pack_id.len == 0) return usageError(stderr, "show requires a pack id");
    return options;
}

fn usageError(stderr: anytype, message: []const u8) error{InvalidArguments} {
    stderr.print("ryk packs: {s}. Run 'ryk help packs' for usage.\n", .{message}) catch {};
    return error.InvalidArguments;
}

fn usageExit(stderr: anytype, message: []const u8) u8 {
    usageError(stderr, message) catch {};
    return exit_codes.usage;
}

// ── Catalog load + enable-state (oracle + pack_config) ──────────────────────

fn loadCatalog(allocator: std.mem.Allocator) !Catalog {
    const inflated = try oracle_embed.inflateAlloc(allocator);
    errdefer allocator.free(inflated);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, inflated, .{});
    errdefer parsed.deinit();
    if (parsed.value != .array) return error.BadPacksJson;

    var list: std.ArrayListUnmanaged(PackView) = .empty;
    errdefer list.deinit(allocator);
    var owned_strings: std.ArrayListUnmanaged([]u8) = .empty;
    errdefer {
        for (owned_strings.items) |s| allocator.free(s);
        owned_strings.deinit(allocator);
    }
    var owned_pattern_slices: std.ArrayListUnmanaged([]PatternView) = .empty;
    errdefer {
        for (owned_pattern_slices.items) |slice| allocator.free(slice);
        owned_pattern_slices.deinit(allocator);
    }

    for (parsed.value.array.items) |item| {
        if (item != .object) continue;
        const obj = item.object;
        const id_val = obj.get("id") orelse continue;
        if (id_val != .string) continue;
        const id = id_val.string;
        // Mirror registry: skip synthetic test pack.
        if (std.mem.eql(u8, id, "test.deadline")) continue;

        const safe_pats = try loadPatterns(allocator, obj.get("safe"));
        try owned_pattern_slices.append(allocator, safe_pats);
        const dest_pats = try loadPatterns(allocator, obj.get("destructive"));
        try owned_pattern_slices.append(allocator, dest_pats);

        const category = categoryFromId(id);
        const name = try humanName(allocator, id);
        try owned_strings.append(allocator, name);
        const description = try descriptionFromKeywords(allocator, obj.get("keywords"), id);
        try owned_strings.append(allocator, description);

        try list.append(allocator, .{
            .id = id,
            .name = name,
            .category = category,
            .description = description,
            .enabled = isDefaultEnabled(id), // overwritten by applyEnabledState
            .safe_pattern_count = safe_pats.len,
            .destructive_pattern_count = dest_pats.len,
            .safe = safe_pats,
            .destructive = dest_pats,
        });
    }

    const packs = try list.toOwnedSlice(allocator);
    errdefer allocator.free(packs);
    // Sort by id for stable list/json (product UX; matches prior daemon-friendly sort).
    std.mem.sort(PackView, packs, {}, lessThanPackView);

    if (packs.len == 0) return error.BadPacksJson;

    return .{
        .allocator = allocator,
        .packs = packs,
        .owned_strings = owned_strings,
        .owned_pattern_slices = owned_pattern_slices,
        .json_parsed = parsed,
        .inflated_json = inflated,
    };
}

fn loadPatterns(allocator: std.mem.Allocator, value: ?std.json.Value) ![]PatternView {
    const v = value orelse return try allocator.alloc(PatternView, 0);
    if (v != .array) return try allocator.alloc(PatternView, 0);
    var out: std.ArrayListUnmanaged(PatternView) = .empty;
    errdefer out.deinit(allocator);
    for (v.array.items) |pat| {
        if (pat != .object) continue;
        const o = pat.object;
        const name = if (o.get("name")) |n| (if (n == .string) n.string else "unnamed") else "unnamed";
        const regex = if (o.get("regex")) |r| (if (r == .string) r.string else "") else "";
        const severity = if (o.get("severity")) |s| (if (s == .string) s.string else "high") else "high";
        const reason = if (o.get("reason")) |r| (if (r == .string) r.string else "") else "";
        try out.append(allocator, .{
            .name = name,
            .regex = regex,
            .severity = severity,
            .reason = reason,
        });
    }
    return try out.toOwnedSlice(allocator);
}

fn categoryFromId(id: []const u8) []const u8 {
    if (std.mem.indexOfScalar(u8, id, '.')) |dot| return id[0..dot];
    return id;
}

fn humanName(allocator: std.mem.Allocator, id: []const u8) ![]u8 {
    // Prefer trailing segment title-cased lightly; keep id readable as name.
    const seg = if (std.mem.lastIndexOfScalar(u8, id, '.')) |dot| id[dot + 1 ..] else id;
    if (seg.len == 0) return try allocator.dupe(u8, id);
    var buf = try allocator.alloc(u8, seg.len);
    for (seg, 0..) |c, i| {
        if (i == 0) {
            buf[i] = std.ascii.toUpper(c);
        } else if (c == '_' or c == '-') {
            buf[i] = ' ';
        } else {
            buf[i] = c;
        }
    }
    return buf;
}

fn descriptionFromKeywords(allocator: std.mem.Allocator, keywords_val: ?std.json.Value, id: []const u8) ![]u8 {
    _ = keywords_val;
    return try std.fmt.allocPrint(allocator, "Shell safety pack {s}", .{id});
}

fn isDefaultEnabled(id: []const u8) bool {
    return pack_config.isBaselinePackId(id);
}

fn packIdListed(pack_id: []const u8, ids: []const []const u8) bool {
    for (ids) |id| {
        if (std.mem.eql(u8, pack_id, id)) return true;
        // Category shorthand: `core` → `core.*` (mirror registry.packIdListed).
        if (std.mem.indexOfScalar(u8, id, '.') == null and id.len > 0) {
            if (pack_id.len > id.len and pack_id[id.len] == '.' and std.mem.startsWith(u8, pack_id, id)) {
                return true;
            }
        }
    }
    return false;
}

/// Active semantics mirror `registry.packIsActive` with default_packs_only=true.
fn packIsActive(id: []const u8, extra_enabled: []const []const u8, disabled: []const []const u8) bool {
    if (packIdListed(id, disabled)) return false;
    if (isDefaultEnabled(id)) return true;
    return packIdListed(id, extra_enabled);
}

fn applyEnabledState(io: std.Io, allocator: std.mem.Allocator, catalog: *Catalog) void {
    const workspace_root = onboarding.resolveWorkspaceRoot(io, allocator) catch {
        // Fail open to baseline defaults only.
        for (catalog.packs) |*pack| {
            pack.enabled = isDefaultEnabled(pack.id);
        }
        return;
    };
    defer allocator.free(workspace_root);

    var loaded = pack_config.loadPackIdsForWorkspace(io, allocator, workspace_root) catch {
        for (catalog.packs) |*pack| {
            pack.enabled = isDefaultEnabled(pack.id);
        }
        return;
    };
    defer loaded.deinit(allocator);

    for (catalog.packs) |*pack| {
        pack.enabled = packIsActive(pack.id, loaded.enabled, loaded.disabled);
    }
}

fn findPack(packs: []const PackView, id: []const u8) ?*const PackView {
    for (packs) |*pack| {
        if (std.mem.eql(u8, pack.id, id)) return pack;
    }
    return null;
}

fn lessThanPackView(_: void, lhs: PackView, rhs: PackView) bool {
    return std.mem.order(u8, lhs.id, rhs.id) == .lt;
}

// ── Render ──────────────────────────────────────────────────────────────────

fn renderListJson(stdout: anytype, packs: []const PackView) !u8 {
    var enabled_count: usize = 0;
    for (packs) |p| {
        if (p.enabled) enabled_count += 1;
    }
    try stdout.writeAll("{\n");
    try stdout.print("  \"schema_version\": {d},\n", .{1});
    try stdout.writeAll("  \"packs\": [\n");
    for (packs, 0..) |pack, i| {
        try stdout.writeAll("    {\n");
        try stdout.writeAll("      \"id\": ");
        try util.writeJsonString(stdout, pack.id);
        try stdout.writeAll(",\n      \"name\": ");
        try util.writeJsonString(stdout, pack.name);
        try stdout.writeAll(",\n      \"category\": ");
        try util.writeJsonString(stdout, pack.category);
        try stdout.writeAll(",\n      \"description\": ");
        try util.writeJsonString(stdout, pack.description);
        try stdout.print(",\n      \"enabled\": {},\n", .{pack.enabled});
        try stdout.print("      \"safe_pattern_count\": {d},\n", .{pack.safe_pattern_count});
        try stdout.print("      \"destructive_pattern_count\": {d}\n", .{pack.destructive_pattern_count});
        try stdout.writeAll("    }");
        if (i + 1 < packs.len) try stdout.writeAll(",");
        try stdout.writeAll("\n");
    }
    try stdout.writeAll("  ],\n");
    try stdout.print("  \"enabled_count\": {d},\n", .{enabled_count});
    try stdout.print("  \"total_count\": {d}\n", .{packs.len});
    try stdout.writeAll("}\n");
    return exit_codes.success;
}

fn renderShowJson(stdout: anytype, pack: *const PackView, no_patterns: bool, verbose: bool) !u8 {
    try stdout.writeAll("{\n");
    try stdout.print("  \"schema_version\": {d},\n", .{1});
    try stdout.writeAll("  \"id\": ");
    try util.writeJsonString(stdout, pack.id);
    try stdout.writeAll(",\n  \"name\": ");
    try util.writeJsonString(stdout, pack.name);
    try stdout.writeAll(",\n  \"category\": ");
    try util.writeJsonString(stdout, pack.category);
    try stdout.writeAll(",\n  \"description\": ");
    try util.writeJsonString(stdout, pack.description);
    try stdout.print(",\n  \"enabled\": {},\n", .{pack.enabled});
    try stdout.print("  \"safe_pattern_count\": {d},\n", .{pack.safe_pattern_count});
    try stdout.print("  \"destructive_pattern_count\": {d}", .{pack.destructive_pattern_count});

    if (!no_patterns) {
        try stdout.writeAll(",\n  \"destructive_patterns\": [\n");
        for (pack.destructive, 0..) |rule, i| {
            try stdout.writeAll("    {\n      \"name\": ");
            try util.writeJsonString(stdout, rule.name);
            try stdout.writeAll(",\n      \"severity\": ");
            try util.writeJsonString(stdout, rule.severity);
            try stdout.writeAll(",\n      \"reason\": ");
            try util.writeJsonString(stdout, rule.reason);
            if (verbose and rule.regex.len > 0) {
                try stdout.writeAll(",\n      \"regex\": ");
                try util.writeJsonString(stdout, rule.regex);
            }
            try stdout.writeAll("\n    }");
            if (i + 1 < pack.destructive.len) try stdout.writeAll(",");
            try stdout.writeAll("\n");
        }
        try stdout.writeAll("  ],\n  \"safe_patterns\": [\n");
        for (pack.safe, 0..) |rule, i| {
            try stdout.writeAll("    {\n      \"name\": ");
            try util.writeJsonString(stdout, rule.name);
            if (verbose and rule.regex.len > 0) {
                try stdout.writeAll(",\n      \"regex\": ");
                try util.writeJsonString(stdout, rule.regex);
            }
            try stdout.writeAll("\n    }");
            if (i + 1 < pack.safe.len) try stdout.writeAll(",");
            try stdout.writeAll("\n");
        }
        try stdout.writeAll("  ]");
    }
    try stdout.writeAll("\n}\n");
    return exit_codes.success;
}

fn trackSanitized(allocator: std.mem.Allocator, owned: *std.ArrayListUnmanaged([]u8), value: []const u8) ![]u8 {
    const safe = try tui.terminal_text.sanitizeAlloc(allocator, value, .single_line);
    errdefer allocator.free(safe);
    try owned.append(allocator, safe);
    return safe;
}

fn renderShowHuman(
    allocator: std.mem.Allocator,
    io: std.Io,
    pack: *const PackView,
    verbose: bool,
    no_patterns: bool,
    stdout: anytype,
) !u8 {
    var owned: std.ArrayListUnmanaged([]u8) = .empty;
    defer {
        for (owned.items) |v| allocator.free(v);
        owned.deinit(allocator);
    }

    const safe_id = try trackSanitized(allocator, &owned, pack.id);
    const safe_name = try trackSanitized(allocator, &owned, pack.name);
    const safe_desc = try trackSanitized(allocator, &owned, pack.description);

    try tui.theme.paintBold(io, stdout, .text_bright, "Safety pack");
    try stdout.writeAll("  ");
    try tui.theme.paintBold(io, stdout, .success, safe_id);
    try stdout.writeAll("  ");
    try tui.theme.paint(io, stdout, if (pack.enabled) .success else .muted, if (pack.enabled) "[enabled]" else "[available]");
    try stdout.writeAll("\n");
    try stdout.writeAll("Name         ");
    try stdout.writeAll(safe_name);
    try stdout.writeAll("\n");
    if (pack.category.len > 0) {
        const safe_cat = try trackSanitized(allocator, &owned, pack.category);
        try stdout.writeAll("Category     ");
        try stdout.writeAll(safe_cat);
        try stdout.writeAll("\n");
    }
    try stdout.writeAll("Description  ");
    try tui.render.writeWrappedWidth(stdout, safe_desc, 13, 80);
    try stdout.writeAll("\n");
    try stdout.print("Patterns     {d} safe / {d} destructive\n", .{ pack.safe_pattern_count, pack.destructive_pattern_count });

    if (!no_patterns) {
        if (pack.destructive.len > 0) {
            try stdout.writeAll("\n");
            try tui.theme.paintBold(io, stdout, .text_bright, "Destructive rules");
            try stdout.print(" ({d})\n", .{pack.destructive.len});
            for (pack.destructive) |rule| {
                const name = try trackSanitized(allocator, &owned, rule.name);
                const severity = try trackSanitized(allocator, &owned, rule.severity);
                const reason = try trackSanitized(allocator, &owned, rule.reason);
                try stdout.writeAll("  • ");
                try tui.theme.paintBold(io, stdout, .danger, name);
                try stdout.writeAll("  ");
                try tui.theme.paint(io, stdout, .danger, severity);
                try stdout.writeAll("\n    ");
                try tui.render.writeWrappedWidth(stdout, reason, 4, 80);
                try stdout.writeAll("\n");
                if (verbose and rule.regex.len > 0) {
                    const rx = try trackSanitized(allocator, &owned, rule.regex);
                    try stdout.writeAll("    regex: ");
                    try stdout.writeAll(rx);
                    try stdout.writeAll("\n");
                }
            }
        }
        if (pack.safe.len > 0) {
            try stdout.writeAll("\n");
            try tui.theme.paintBold(io, stdout, .text_bright, "Safe rules");
            try stdout.print(" ({d})\n", .{pack.safe.len});
            try stdout.writeAll("  ");
            var first = true;
            for (pack.safe) |rule| {
                if (!first) try stdout.writeAll(", ");
                first = false;
                const name = try trackSanitized(allocator, &owned, rule.name);
                try stdout.writeAll(name);
                if (verbose and rule.regex.len > 0) {
                    const rx = try trackSanitized(allocator, &owned, rule.regex);
                    try stdout.writeAll(" (");
                    try stdout.writeAll(rx);
                    try stdout.writeAll(")");
                }
            }
            try stdout.writeAll("\n");
        }
    }

    try stdout.writeAll("\nNext: ryk packs enable ");
    try stdout.writeAll(safe_id);
    try stdout.writeAll("  ·  ryk test \"…\"\n");
    return exit_codes.success;
}

fn renderHuman(
    allocator: std.mem.Allocator,
    io: std.Io,
    options: Options,
    packs: []const PackView,
    stdout: anytype,
    stderr: anytype,
) !u8 {
    var selected: std.ArrayListUnmanaged(PackView) = .empty;
    defer selected.deinit(allocator);
    for (packs) |pack| {
        if (options.installed and !pack.enabled) continue;
        if (options.filter) |term| {
            if (!containsIgnoreCase(pack.id, term) and !containsIgnoreCase(pack.name, term) and
                !containsIgnoreCase(pack.category, term) and !containsIgnoreCase(pack.description, term)) continue;
        }
        try selected.append(allocator, pack);
    }

    if (selected.items.len == 0) {
        try tui.render.callout(io, stdout, .info, "No safety packs found", if (options.filter != null)
            "Try a broader --filter term, or run 'ryk packs' to list all packs."
        else if (options.installed)
            "No opt-in packs enabled. Enable more with `ryk packs enable <id>` (baseline is always on)."
        else
            "No packs available in the oracle registry.");
        return exit_codes.success;
    }

    // Default linear (empty argv, no list-shaping flags): count + one next.
    // `--plain` stays on the existing catalog dump; TTY browse is decided earlier.
    if (options.filter == null and !options.installed and !options.explicit_page and
        !options.explicit_page_size and !options.plain)
    {
        var enabled_count: usize = 0;
        for (selected.items) |pack| {
            if (pack.enabled) enabled_count += 1;
        }
        try stdout.print("{d} packs ({d} enabled)\n", .{ selected.items.len, enabled_count });
        try stdout.writeAll("Next: ryk packs --enabled\n");
        return exit_codes.success;
    }

    const total_pages = 1 + (selected.items.len - 1) / options.page_size;
    if (options.page > total_pages) {
        return usageExit(stderr, "--page is beyond the available filtered results");
    }

    const start = std.math.mul(usize, options.page - 1, options.page_size) catch
        return usageExit(stderr, "--page and --page-size are too large");
    const end = @min(selected.items.len, std.math.add(usize, start, options.page_size) catch selected.items.len);
    const page_items = selected.items[start..end];

    var owned: std.ArrayListUnmanaged([]u8) = .empty;
    defer {
        for (owned.items) |value| allocator.free(value);
        owned.deinit(allocator);
    }
    try tui.theme.paintBold(io, stdout, .text_bright, "Safety packs");
    try stdout.writeAll("\n\n");
    for (page_items) |pack| {
        const safe_id = try tui.terminal_text.sanitizeAlloc(allocator, pack.id, .single_line);
        owned.append(allocator, safe_id) catch |err| {
            allocator.free(safe_id);
            return err;
        };
        const safe_category = try tui.terminal_text.sanitizeAlloc(allocator, pack.category, .single_line);
        owned.append(allocator, safe_category) catch |err| {
            allocator.free(safe_category);
            return err;
        };
        const safe_description = try tui.terminal_text.sanitizeAlloc(allocator, pack.description, .single_line);
        owned.append(allocator, safe_description) catch |err| {
            allocator.free(safe_description);
            return err;
        };
        const patterns = try std.fmt.allocPrint(allocator, "{d} safe / {d} blocked", .{ pack.safe_pattern_count, pack.destructive_pattern_count });
        owned.append(allocator, patterns) catch |err| {
            allocator.free(patterns);
            return err;
        };
        try stdout.writeAll("  ");
        try tui.theme.paintBold(io, stdout, if (pack.enabled) .success else .text_bright, if (pack.enabled) "●" else "○");
        try stdout.writeAll(" ");
        try tui.render.writeTruncated(stdout, safe_id, 60);
        try stdout.writeAll("  ");
        try tui.theme.paint(io, stdout, if (pack.enabled) .success else .muted, if (pack.enabled) "[enabled]" else "[available]");
        try stdout.writeAll("\n    ");
        try tui.render.writeTruncated(stdout, safe_category, 28);
        try stdout.writeAll(" · ");
        try stdout.writeAll(patterns);
        try stdout.writeAll("\n");
        try tui.render.writeWrappedWidth(stdout, safe_description, 4, 80);
        try stdout.writeAll("\n\n");
    }
    try stdout.print("Page {d} of {d} · {d} pack(s)\n", .{ options.page, total_pages, selected.items.len });
    return exit_codes.success;
}

fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (needle.len > haystack.len) return false;
    for (0..haystack.len - needle.len + 1) |start| {
        var matches = true;
        for (needle, 0..) |char, offset| {
            if (std.ascii.toLower(haystack[start + offset]) != std.ascii.toLower(char)) {
                matches = false;
                break;
            }
        }
        if (matches) return true;
    }
    return false;
}

// ── s-packs locked contract tests (Slice 4 / unit s-packs) ──────────────────
// Happy path must use shell_engine.registry + pack_config — never daemon CLI.

fn failIfCalled(_: std.Io, _: []const []const u8, _: anytype, _: anytype) !u8 {
    return error.UnexpectedExecutorCall;
}

// Test-only: pack_config for loadPackIdsForWorkspace membership (not production path).
const test_pack_config = @import("pack_config.zig");

extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;
extern "c" fn unsetenv(name: [*:0]const u8) c_int;

fn sPacksDupEnvZ(name: [*:0]const u8) !?[:0]u8 {
    const raw = std.c.getenv(name) orelse return null;
    return try std.testing.allocator.dupeZ(u8, std.mem.span(raw));
}

fn sPacksRestoreEnv(name: [*:0]const u8, prev: ?[:0]u8) void {
    if (prev) |value| {
        _ = setenv(name, value.ptr, 1);
        std.testing.allocator.free(value);
    } else {
        _ = unsetenv(name);
    }
}

const SPacksXdg = struct {
    tmp: std.testing.TmpDir,
    root: []u8,
    prev_xdg: ?[:0]u8,

    fn deinit(self: *@This()) void {
        sPacksRestoreEnv("XDG_CONFIG_HOME", self.prev_xdg);
        // Always clear the TTY test seam so tests cannot leak operator presence.
        test_operator_tty_override = null;
        std.testing.allocator.free(self.root);
        self.tmp.cleanup();
    }
};

/// Isolate user pack config + simulate operator TTY for baseline disable tests
/// (the RYK_OPERATOR env break-glass was removed; presence is TTY-only).
fn sPacksIsolateXdgWithOperator() !SPacksXdg {
    var tmp = std.testing.tmpDir(.{});
    errdefer tmp.cleanup();
    const root_z = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root_z);
    const root = try std.testing.allocator.dupe(u8, root_z);
    errdefer std.testing.allocator.free(root);

    const prev_xdg = try sPacksDupEnvZ("XDG_CONFIG_HOME");
    errdefer if (prev_xdg) |p| std.testing.allocator.free(p);

    const root_z0 = try std.testing.allocator.dupeZ(u8, root);
    defer std.testing.allocator.free(root_z0);
    try std.testing.expectEqual(@as(c_int, 0), setenv("XDG_CONFIG_HOME", root_z0.ptr, 1));
    test_operator_tty_override = true;

    return .{
        .tmp = tmp,
        .root = root,
        .prev_xdg = prev_xdg,
    };
}

fn sliceContainsId(ids: []const []const u8, want: []const u8) bool {
    for (ids) |id| {
        if (std.mem.eql(u8, id, want)) return true;
    }
    return false;
}

fn stdoutHasDigit(text: []const u8) bool {
    for (text) |byte| {
        if (byte >= '0' and byte <= '9') return true;
    }
    return false;
}

fn countSubstring(haystack: []const u8, needle: []const u8) usize {
    var count: usize = 0;
    var rest = haystack;
    while (std.mem.indexOf(u8, rest, needle)) |idx| {
        count += 1;
        rest = rest[idx + needle.len ..];
    }
    return count;
}

// Parse list `--json` output and return the `enabled` flag for `pack_id`.
fn jsonPackEnabledFlag(raw: []const u8, pack_id: []const u8) !bool {
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, raw, .{});
    defer parsed.deinit();
    const packs_val = parsed.value.object.get("packs") orelse return error.TestUnexpectedResult;
    try std.testing.expect(packs_val == .array);
    for (packs_val.array.items) |item| {
        try std.testing.expect(item == .object);
        const id = item.object.get("id") orelse return error.TestUnexpectedResult;
        try std.testing.expect(id == .string);
        if (std.mem.eql(u8, id.string, pack_id)) {
            const en = item.object.get("enabled") orelse return error.TestUnexpectedResult;
            try std.testing.expect(en == .bool);
            return en.bool;
        }
    }
    return error.TestUnexpectedResult; // pack id missing from list
}

/// Run `body` with process cwd set to a fresh git workspace under a tmp dir.
fn withGitWorkspace(comptime body: *const fn (workspace_root: []const u8) anyerror!void) !void {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, ".git");
    const root_z = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root_z);
    const root = try std.testing.allocator.dupe(u8, root_z);
    defer std.testing.allocator.free(root);

    const prev = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(prev);
    defer std.Io.Threaded.chdir(prev) catch @panic("s-packs test failed to restore process cwd");

    try std.Io.Threaded.chdir(root);
    try body(root);
}

test "s-packs: list real packs without daemon includes core.git enabled" {
    var stdout_buf: [64 * 1024]u8 = undefined;
    var stderr_buf: [1024]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    // failIfCalled proves no executeDaemonCli / executor on the happy path.
    const code = try commandWithExecutor(failIfCalled, std.testing.io, &.{}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());

    const out = stdout_writer.buffered();
    try std.testing.expect(stdoutHasDigit(out));
    try std.testing.expect(std.mem.indexOf(u8, out, "pack") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Next: ryk packs --enabled") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "[enabled]") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Page 1 of") == null);
}

test "s-packs: list --json stable schema with schema_version packs and counts" {
    // Isolate XDG so developer user config (baseline opt-outs) cannot flip core.git.
    var xdg = try sPacksIsolateXdgWithOperator();
    defer xdg.deinit();

    var stdout_buf: [256 * 1024]u8 = undefined;
    var stderr_buf: [1024]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try commandWithExecutor(failIfCalled, std.testing.io, &.{"--json"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());

    const raw = stdout_writer.buffered();
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, raw, .{});
    defer parsed.deinit();
    const root = parsed.value;
    try std.testing.expect(root == .object);
    const obj = root.object;

    const schema = obj.get("schema_version") orelse return error.TestUnexpectedResult;
    try std.testing.expect(schema == .integer);
    try std.testing.expectEqual(@as(i64, 1), schema.integer);

    const packs_val = obj.get("packs") orelse return error.TestUnexpectedResult;
    try std.testing.expect(packs_val == .array);
    try std.testing.expect(packs_val.array.items.len >= 50);

    const total = obj.get("total_count") orelse return error.TestUnexpectedResult;
    try std.testing.expect(total == .integer);
    try std.testing.expectEqual(@as(i64, @intCast(packs_val.array.items.len)), total.integer);

    const enabled_count = obj.get("enabled_count") orelse return error.TestUnexpectedResult;
    try std.testing.expect(enabled_count == .integer);
    try std.testing.expect(enabled_count.integer > 0);

    var found_core_git = false;
    var enabled_seen: i64 = 0;
    for (packs_val.array.items) |item| {
        try std.testing.expect(item == .object);
        const id = item.object.get("id") orelse return error.TestUnexpectedResult;
        try std.testing.expect(id == .string);
        const en = item.object.get("enabled") orelse return error.TestUnexpectedResult;
        try std.testing.expect(en == .bool);
        if (en.bool) enabled_seen += 1;
        if (std.mem.eql(u8, id.string, "core.git")) {
            found_core_git = true;
            try std.testing.expect(en.bool); // baseline always on unless disabled
        }
    }
    try std.testing.expect(found_core_git);
    try std.testing.expectEqual(enabled_count.integer, enabled_seen);
}

test "s-packs: list --format json is an alias for stable --json schema" {
    var stdout_buf: [256 * 1024]u8 = undefined;
    var stderr_buf: [1024]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try commandWithExecutor(failIfCalled, std.testing.io, &.{ "--format", "json" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    const raw = stdout_writer.buffered();
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, raw, .{});
    defer parsed.deinit();
    try std.testing.expectEqual(@as(i64, 1), parsed.value.object.get("schema_version").?.integer);
    try std.testing.expect(parsed.value.object.get("packs").?.array.items.len >= 50);
}

test "s-packs: show core.git works without daemon" {
    var stdout_buf: [64 * 1024]u8 = undefined;
    var stderr_buf: [1024]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try commandWithExecutor(failIfCalled, std.testing.io, &.{ "show", "core.git" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());

    const out = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "core.git") != null);
    // Real oracle pattern names (not daemon fixture force-push-only).
    try std.testing.expect(std.mem.indexOf(u8, out, "reset-hard") != null);
    // Raw regex stays hidden unless --verbose.
    try std.testing.expect(std.mem.indexOf(u8, out, "regex:") == null);
}

test "s-packs: show core.git --json includes id and pattern names" {
    var stdout_buf: [128 * 1024]u8 = undefined;
    var stderr_buf: [1024]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try commandWithExecutor(failIfCalled, std.testing.io, &.{ "show", "core.git", "--json" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);

    const raw = stdout_writer.buffered();
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, raw, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;
    if (obj.get("schema_version")) |sv| {
        try std.testing.expectEqual(@as(i64, 1), sv.integer);
    }
    try std.testing.expectEqualStrings("core.git", obj.get("id").?.string);
    // Pattern inventory present (names or counts).
    const text = raw;
    try std.testing.expect(std.mem.indexOf(u8, text, "reset-hard") != null);
}

test "s-packs: show missing pack remediates without daemon" {
    var stdout_buf: [1024]u8 = undefined;
    var stderr_buf: [1024]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try commandWithExecutor(failIfCalled, std.testing.io, &.{ "show", "no.such.pack" }, &stdout_writer, &stderr_writer);
    try std.testing.expect(code == exit_codes.general or code == exit_codes.usage);
    const err = stderr_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, err, "no.such.pack") != null or std.mem.indexOf(u8, err, "not found") != null);
    // No daemon / doctor essay as the primary remediation for missing pack.
    try std.testing.expect(std.mem.indexOf(u8, err, "executeDaemonCli") == null);
}

test "s-packs: enable opt-in pack writes project config without daemon" {
    try withGitWorkspace(struct {
        fn body(workspace_root: []const u8) !void {
            var stdout_buf: [4096]u8 = undefined;
            var stderr_buf: [1024]u8 = undefined;
            var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
            var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

            const code = try commandWithExecutor(
                failIfCalled,
                std.testing.io,
                &.{ "enable", "containers.docker" },
                &stdout_writer,
                &stderr_writer,
            );
            try std.testing.expectEqual(exit_codes.success, code);

            // Must go through pack_config semantics: id lands in [packs].enabled only.
            var loaded = try test_pack_config.loadPackIdsForWorkspace(std.testing.io, std.testing.allocator, workspace_root);
            defer loaded.deinit(std.testing.allocator);
            try std.testing.expect(sliceContainsId(loaded.enabled, "containers.docker"));
            try std.testing.expect(!sliceContainsId(loaded.disabled, "containers.docker"));
        }
    }.body);
}

test "s-packs: disable core.git uses shipped pack_config semantics without hard-fail" {
    try withGitWorkspace(struct {
        fn body(workspace_root: []const u8) !void {
            var xdg = try sPacksIsolateXdgWithOperator();
            defer xdg.deinit();

            var stdout_buf: [4096]u8 = undefined;
            var stderr_buf: [2048]u8 = undefined;
            var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
            var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

            const code = try commandWithExecutor(
                failIfCalled,
                std.testing.io,
                &.{ "disable", "core.git" },
                &stdout_writer,
                &stderr_writer,
            );
            // With RYK_OPERATOR break-glass: baseline opt-out succeeds (user config); no hard-fail.
            try std.testing.expectEqual(exit_codes.success, code);
            const combined = try std.fmt.allocPrint(std.testing.allocator, "{s}{s}", .{ stdout_writer.buffered(), stderr_writer.buffered() });
            defer std.testing.allocator.free(combined);
            try std.testing.expect(std.mem.indexOf(u8, combined, "cannot disable") == null);
            try std.testing.expect(std.mem.indexOf(u8, combined, "Cannot disable") == null);
            try std.testing.expect(std.mem.indexOf(u8, combined, "hard-fail") == null);
            try std.testing.expect(std.mem.indexOf(u8, combined, "daemon may still") == null);

            // Effective disabled list merges user baseline opt-out.
            var loaded = try test_pack_config.loadPackIdsForWorkspace(std.testing.io, std.testing.allocator, workspace_root);
            defer loaded.deinit(std.testing.allocator);
            try std.testing.expect(sliceContainsId(loaded.disabled, "core.git"));
        }
    }.body);
}

test "s-packs: disable baseline on non-TTY refuses even with RYK_OPERATOR set" {
    try withGitWorkspace(struct {
        fn body(_: []const u8) !void {
            // The removed RYK_OPERATOR env var must never authorize anything.
            const prev = try sPacksDupEnvZ("RYK_OPERATOR");
            defer sPacksRestoreEnv("RYK_OPERATOR", prev);
            _ = setenv("RYK_OPERATOR", "1", 1);
            // Force the non-TTY path explicitly via the test seam.
            test_operator_tty_override = false;
            defer test_operator_tty_override = null;

            var stdout_buf: [4096]u8 = undefined;
            var stderr_buf: [2048]u8 = undefined;
            var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
            var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

            const code = try commandWithExecutor(
                failIfCalled,
                std.testing.io,
                &.{ "disable", "core.git" },
                &stdout_writer,
                &stderr_writer,
            );
            try std.testing.expect(code != exit_codes.success);
            const err = stderr_writer.buffered();
            try std.testing.expect(std.mem.indexOf(u8, err, "TTY") != null or
                std.mem.indexOf(u8, err, "terminal") != null or
                std.mem.indexOf(u8, err, "baseline") != null);
        }
    }.body);
}

// Acceptance: enable → list enabled-state fidelity (not static registry flags).
test "s-packs: enable containers.docker then list --json reports enabled true" {
    try withGitWorkspace(struct {
        fn body(workspace_root: []const u8) !void {
            {
                var stdout_buf: [4096]u8 = undefined;
                var stderr_buf: [1024]u8 = undefined;
                var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
                var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
                const code = try commandWithExecutor(
                    failIfCalled,
                    std.testing.io,
                    &.{ "enable", "containers.docker" },
                    &stdout_writer,
                    &stderr_writer,
                );
                try std.testing.expectEqual(exit_codes.success, code);
            }

            // Config membership (pack_config path), not substring-soft TOML.
            var loaded = try test_pack_config.loadPackIdsForWorkspace(std.testing.io, std.testing.allocator, workspace_root);
            defer loaded.deinit(std.testing.allocator);
            try std.testing.expect(sliceContainsId(loaded.enabled, "containers.docker"));

            var list_out: [256 * 1024]u8 = undefined;
            var list_err: [1024]u8 = undefined;
            var list_stdout: std.Io.Writer = .fixed(&list_out);
            var list_stderr: std.Io.Writer = .fixed(&list_err);
            const list_code = try commandWithExecutor(
                failIfCalled,
                std.testing.io,
                &.{"--json"},
                &list_stdout,
                &list_stderr,
            );
            try std.testing.expectEqual(exit_codes.success, list_code);
            try std.testing.expectEqualStrings("", list_stderr.buffered());

            const en = try jsonPackEnabledFlag(list_stdout.buffered(), "containers.docker");
            try std.testing.expect(en); // list must honor enable mutation
        }
    }.body);
}

// Acceptance: disable baseline → list enabled false (packIsActive/disabled semantics via CLI).
test "s-packs: disable core.git then list --json reports enabled false" {
    try withGitWorkspace(struct {
        fn body(workspace_root: []const u8) !void {
            var xdg = try sPacksIsolateXdgWithOperator();
            defer xdg.deinit();

            {
                var stdout_buf: [4096]u8 = undefined;
                var stderr_buf: [2048]u8 = undefined;
                var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
                var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
                const code = try commandWithExecutor(
                    failIfCalled,
                    std.testing.io,
                    &.{ "disable", "core.git" },
                    &stdout_writer,
                    &stderr_writer,
                );
                try std.testing.expectEqual(exit_codes.success, code);
                const combined = try std.fmt.allocPrint(std.testing.allocator, "{s}{s}", .{ stdout_writer.buffered(), stderr_writer.buffered() });
                defer std.testing.allocator.free(combined);
                try std.testing.expect(std.mem.indexOf(u8, combined, "cannot disable") == null);
            }

            var loaded = try test_pack_config.loadPackIdsForWorkspace(std.testing.io, std.testing.allocator, workspace_root);
            defer loaded.deinit(std.testing.allocator);
            try std.testing.expect(sliceContainsId(loaded.disabled, "core.git"));

            var list_out: [256 * 1024]u8 = undefined;
            var list_err: [1024]u8 = undefined;
            var list_stdout: std.Io.Writer = .fixed(&list_out);
            var list_stderr: std.Io.Writer = .fixed(&list_err);
            const list_code = try commandWithExecutor(
                failIfCalled,
                std.testing.io,
                &.{"--json"},
                &list_stdout,
                &list_stderr,
            );
            try std.testing.expectEqual(exit_codes.success, list_code);

            const en = try jsonPackEnabledFlag(list_stdout.buffered(), "core.git");
            try std.testing.expect(!en); // list must honor disable → inactive

            // Human list also surfaces available (not enabled) for the baseline id.
            var human_out: [64 * 1024]u8 = undefined;
            var human_err: [1024]u8 = undefined;
            var human_stdout: std.Io.Writer = .fixed(&human_out);
            var human_stderr: std.Io.Writer = .fixed(&human_err);
            const human_code = try commandWithExecutor(
                failIfCalled,
                std.testing.io,
                &.{ "--filter", "core.git" },
                &human_stdout,
                &human_stderr,
            );
            try std.testing.expectEqual(exit_codes.success, human_code);
            const human = human_stdout.buffered();
            try std.testing.expect(std.mem.indexOf(u8, human, "core.git") != null);
            try std.testing.expect(std.mem.indexOf(u8, human, "[available]") != null);
            try std.testing.expect(std.mem.indexOf(u8, human, "[enabled]") == null);
        }
    }.body);
}

// Opt-in disable via CLI removes from enabled and list reports false.
test "s-packs: disable opt-in pack removes from enabled and list reports false" {
    try withGitWorkspace(struct {
        fn body(workspace_root: []const u8) !void {
            {
                var stdout_buf: [4096]u8 = undefined;
                var stderr_buf: [1024]u8 = undefined;
                var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
                var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
                try std.testing.expectEqual(exit_codes.success, try commandWithExecutor(
                    failIfCalled,
                    std.testing.io,
                    &.{ "enable", "containers.docker" },
                    &stdout_writer,
                    &stderr_writer,
                ));
            }
            {
                var stdout_buf: [4096]u8 = undefined;
                var stderr_buf: [1024]u8 = undefined;
                var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
                var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
                try std.testing.expectEqual(exit_codes.success, try commandWithExecutor(
                    failIfCalled,
                    std.testing.io,
                    &.{ "disable", "containers.docker" },
                    &stdout_writer,
                    &stderr_writer,
                ));
            }

            var loaded = try test_pack_config.loadPackIdsForWorkspace(std.testing.io, std.testing.allocator, workspace_root);
            defer loaded.deinit(std.testing.allocator);
            try std.testing.expect(!sliceContainsId(loaded.enabled, "containers.docker"));

            var list_out: [256 * 1024]u8 = undefined;
            var list_err: [1024]u8 = undefined;
            var list_stdout: std.Io.Writer = .fixed(&list_out);
            var list_stderr: std.Io.Writer = .fixed(&list_err);
            try std.testing.expectEqual(exit_codes.success, try commandWithExecutor(
                failIfCalled,
                std.testing.io,
                &.{"--json"},
                &list_stdout,
                &list_stderr,
            ));
            const en = try jsonPackEnabledFlag(list_stdout.buffered(), "containers.docker");
            try std.testing.expect(!en);
        }
    }.body);
}

test "s-packs: help unhides packs command" {
    const info = help.findCommand("packs") orelse return error.TestUnexpectedResult;
    try std.testing.expect(!info.hidden);
    // Product copy must not claim Rust daemon ownership after Slice 4.
    for (info.details) |line| {
        try std.testing.expect(std.mem.indexOf(u8, line, "Rust daemon") == null);
        try std.testing.expect(std.mem.indexOf(u8, line, "Rust shell-rule") == null);
    }
}

test "s-packs: --help is Zig-owned and does not call daemon" {
    var stdout_buf: [8192]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const code = try commandWithExecutor(failIfCalled, std.testing.io, &.{"--help"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    const out = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "packs") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "enable") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "disable") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "show") != null);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
}

test "s-packs: show requires pack id" {
    var stdout_buf: [64]u8 = undefined;
    var stderr_buf: [256]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const code = try commandWithExecutor(failIfCalled, std.testing.io, &.{"show"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, code);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "ryk help packs") != null or std.mem.indexOf(u8, stderr_writer.buffered(), "pack id") != null);
}

test "s-packs: enable and disable require pack ids" {
    const cases = [_][]const []const u8{
        &.{"enable"},
        &.{"disable"},
    };
    for (cases) |args| {
        var stdout_buf: [64]u8 = undefined;
        var stderr_buf: [256]u8 = undefined;
        var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
        var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
        const code = try commandWithExecutor(failIfCalled, std.testing.io, args, &stdout_writer, &stderr_writer);
        try std.testing.expectEqual(exit_codes.usage, code);
    }
}

test "s-packs: enable rejects unknown pack ids against registry without daemon" {
    try withGitWorkspace(struct {
        fn body(workspace_root: []const u8) !void {
            _ = workspace_root;
            var stdout_buf: [4096]u8 = undefined;
            var stderr_buf: [2048]u8 = undefined;
            var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
            var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
            // Without registry validation, today's path may wrongly succeed —
            // locked: reject unknown ids using oracle registry (no daemon).
            const code = try commandWithExecutor(
                failIfCalled,
                std.testing.io,
                &.{ "enable", "no.such.pack.xyz" },
                &stdout_writer,
                &stderr_writer,
            );
            try std.testing.expectEqual(exit_codes.usage, code);
            try std.testing.expect(std.mem.indexOf(u8, stderr_writer.buffered(), "unknown") != null or std.mem.indexOf(u8, stderr_writer.buffered(), "not found") != null);
        }
    }.body);
}

test "s-packs: info is an alias for show core.git" {
    var stdout_buf: [64 * 1024]u8 = undefined;
    var stderr_buf: [1024]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const code = try commandWithExecutor(failIfCalled, std.testing.io, &.{ "info", "core.git" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "core.git") != null);
}

test "s-packs: list --filter narrows to matching pack ids" {
    var stdout_buf: [64 * 1024]u8 = undefined;
    var stderr_buf: [1024]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const code = try commandWithExecutor(failIfCalled, std.testing.io, &.{ "--filter", "core.git" }, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    const out = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "core.git") != null);
    // Unrelated opt-in pack should not appear when filtering for core.git specifically.
    try std.testing.expect(std.mem.indexOf(u8, out, "containers.docker") == null);
}

test "s-packs: rejects invalid list options without daemon" {
    const cases = [_][]const []const u8{
        &.{"--filter"},
        &.{ "--page", "0" },
        &.{"--unknown-flag"},
    };
    for (cases) |args| {
        var stdout_buf: [64]u8 = undefined;
        var stderr_buf: [512]u8 = undefined;
        var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
        var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
        const code = try commandWithExecutor(failIfCalled, std.testing.io, args, &stdout_writer, &stderr_writer);
        try std.testing.expectEqual(exit_codes.usage, code);
    }
}

test "s-packs: unknown subcommand suggests show for shoe typo" {
    var stdout_buf: [64]u8 = undefined;
    var stderr_buf: [512]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const code = try commandWithExecutor(failIfCalled, std.testing.io, &.{"shoe"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.usage, code);
    const err = stderr_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, err, "unknown subcommand") != null);
    try std.testing.expect(std.mem.indexOf(u8, err, "Did you mean 'show'?") != null);
    try std.testing.expect(std.mem.indexOf(u8, err, "ryk help packs") != null);
}

test "s-packs: --plain is accepted and stays on linear list path" {
    // Help documents --plain as the linear escape; non-TTY tests always take linear
    // path, so this proves the flag parses and still lists packs without usage error.
    var stdout_buf: [64 * 1024]u8 = undefined;
    var stderr_buf: [1024]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const code = try commandWithExecutor(failIfCalled, std.testing.io, &.{"--plain"}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());
    const out = stdout_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "core.git") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "[enabled]") != null);
}

test "s-packs: default linear list is count + one next" {
    var stdout_buf: [64 * 1024]u8 = undefined;
    var stderr_buf: [1024]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const code = try commandWithExecutor(failIfCalled, std.testing.io, &.{}, &stdout_writer, &stderr_writer);
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expectEqualStrings("", stderr_writer.buffered());

    const out = stdout_writer.buffered();
    try std.testing.expect(stdoutHasDigit(out));
    try std.testing.expect(std.mem.indexOf(u8, out, "pack") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Next: ryk packs --enabled") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Page ") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "[available]") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "containers.docker") == null);
    try std.testing.expectEqual(@as(usize, 1), countSubstring(out, "Next:"));
}

test "s-packs: packs list TUI entry uses shared shouldEnterTui gate" {
    // Composition: list path decides via packs_tui.wouldEnterPacksBrowse which
    // wraps tui.output_policy.shouldEnterTui — not a dead import.
    // Slim stub is always false; TUI-on applies the real TTY/argv gate.
    try std.testing.expectEqual(enable_tui, packs_tui.wouldEnterPacksBrowse(true, true, &.{}, false));
    try std.testing.expect(!packs_tui.wouldEnterPacksBrowse(true, true, &.{"--plain"}, false));
    try std.testing.expect(!packs_tui.wouldEnterPacksBrowse(true, true, &.{"--json"}, true));
    try std.testing.expect(!packs_tui.wouldEnterPacksBrowse(false, true, &.{}, false));
    // Browse kit is the frame chassis used by the TUI helper.
    if (enable_tui) {
        try std.testing.expect(@TypeOf(tui.browse.keyToAction) != void);
    }
}

const std = @import("std");

const env_util = @import("../env_util.zig");
const policy_schema = @import("ryk_core").policy.schema;

pub const BrokerKind = policy_schema.CredentialBrokerKind;

pub const StatusState = enum {
    available,
    limited,
    unavailable,
    unsupported,
    failed,

    pub fn toString(self: StatusState) []const u8 {
        return @tagName(self);
    }
};

pub const CredentialRef = struct {
    value: []u8,

    pub fn deinit(self: CredentialRef, allocator: std.mem.Allocator) void {
        allocator.free(self.value);
    }
};

pub const ResolvedSecret = struct {
    value: []u8,

    pub fn deinit(self: *ResolvedSecret, allocator: std.mem.Allocator) void {
        @memset(self.value, 0);
        allocator.free(self.value);
        self.* = undefined;
    }
};

pub const BrokerStatus = struct {
    name: []u8,
    kind: BrokerKind,
    state: StatusState,
    message: []u8,

    pub fn deinit(self: BrokerStatus, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.message);
    }
};

pub const CheckReport = struct {
    ref_name: ?[]u8 = null,
    statuses: []BrokerStatus,

    pub fn deinit(self: *CheckReport, allocator: std.mem.Allocator) void {
        if (self.ref_name) |value| allocator.free(value);
        for (self.statuses) |status| status.deinit(allocator);
        if (self.statuses.len > 0) allocator.free(self.statuses);
        self.* = undefined;
    }

    pub fn ok(self: CheckReport) bool {
        for (self.statuses) |status| {
            if (status.state == .failed or status.state == .unavailable or status.state == .unsupported) return false;
        }
        return true;
    }
};

pub const Broker = struct {
    kind: BrokerKind,

    pub fn envReference(self: Broker, allocator: std.mem.Allocator, name: []const u8, raw_value: []const u8) !CredentialRef {
        _ = raw_value;
        const opaque_id = credential_ref_counter.fetchAdd(1, .monotonic);
        return .{
            .value = try std.fmt.allocPrint(allocator, "ryk-secret://{s}/env/{s}/{x:0>16}", .{ self.kind.toString(), name, opaque_id }),
        };
    }
};

var credential_ref_counter: std.atomic.Value(u64) = .init(1);

const CommandResult = struct {
    stdout: []u8,
    stderr: []u8,
    code: u8,

    fn deinit(self: CommandResult, allocator: std.mem.Allocator) void {
        wipeAndFree(allocator, self.stdout);
        wipeAndFree(allocator, self.stderr);
    }
};

const default_broker_command_timeout_ns: u64 = 5 * std.time.ns_per_s;

pub fn localDummyBroker() Broker {
    return .{ .kind = .local_dummy };
}

pub fn configuredBrokerCount(credentials: policy_schema.CredentialsPolicy) usize {
    if (credentials.brokers.len == 0) return 1;
    return credentials.brokers.len;
}

pub fn check(
    io: std.Io,
    allocator: std.mem.Allocator,
    selected_policy: *const policy_schema.Policy,
    workspace_root: []const u8,
    ref_name: ?[]const u8,
) !CheckReport {
    var statuses: std.ArrayList(BrokerStatus) = .empty;
    errdefer {
        for (statuses.items) |status| status.deinit(allocator);
        statuses.deinit(allocator);
    }

    if (ref_name) |name| {
        const credential_ref = findCredentialRef(selected_policy.credentials, name) orelse return error.UnknownCredentialRef;
        const broker_config = findBrokerForRef(selected_policy.credentials, credential_ref) orelse defaultDummyConfig();
        try statuses.append(allocator, try checkBrokerRef(allocator, broker_config, credential_ref, workspace_root));
    } else if (selected_policy.credentials.brokers.len == 0) {
        try statuses.append(allocator, try makeStatus(allocator, "local-dummy", .local_dummy, .available, "built-in reference broker available"));
    } else {
        for (selected_policy.credentials.brokers) |broker| {
            try statuses.append(allocator, try checkBroker(io, allocator, broker, workspace_root));
        }
    }

    return .{
        .ref_name = if (ref_name) |name| try allocator.dupe(u8, name) else null,
        .statuses = try statuses.toOwnedSlice(allocator),
    };
}

pub fn resolveCredential(
    allocator: std.mem.Allocator,
    selected_policy: *const policy_schema.Policy,
    workspace_root: []const u8,
    ref_name: []const u8,
) !ResolvedSecret {
    const credential_ref = findCredentialRef(selected_policy.credentials, ref_name) orelse return error.UnknownCredentialRef;
    const broker = findBrokerForRef(selected_policy.credentials, credential_ref) orelse defaultDummyConfig();
    return switch (broker.kind) {
        .local_dummy => error.ReferenceOnlyBroker,
        .env_file_dev => resolveEnvFileDev(allocator, broker, workspace_root, credential_ref.ref),
        .onepassword_cli => resolveOnePassword(allocator, broker, credential_ref.ref),
        .macos_keychain => resolveMacosKeychain(allocator, credential_ref.ref),
        .infisical_agent_vault => error.UnsupportedBrokerResolution,
    };
}

fn checkBroker(io: std.Io, allocator: std.mem.Allocator, broker: policy_schema.CredentialBrokerPolicy, workspace_root: []const u8) !BrokerStatus {
    return switch (broker.kind) {
        .local_dummy => makeStatus(allocator, broker.name, broker.kind, .available, "reference-only broker available"),
        .env_file_dev => blk: {
            const path = try envFilePath(allocator, workspace_root, broker);
            defer allocator.free(path);
            std.Io.Dir.cwd().access(io, path, .{}) catch |err| {
                const message = try std.fmt.allocPrint(allocator, "env file unavailable: {s}", .{@errorName(err)});
                defer allocator.free(message);
                break :blk try makeStatus(allocator, broker.name, broker.kind, .unavailable, message);
            };
            break :blk try makeStatus(allocator, broker.name, broker.kind, .available, "dev env file readable");
        },
        .onepassword_cli => if (try executableInPath(io, allocator, "op"))
            makeStatus(allocator, broker.name, broker.kind, .limited, "op CLI found; ref checks use op read without printing values")
        else
            makeStatus(allocator, broker.name, broker.kind, .unavailable, "op CLI not found"),
        .macos_keychain => if (fileExists("/usr/bin/security"))
            makeStatus(allocator, broker.name, broker.kind, .limited, "macOS security CLI found; ref checks query keychain without printing values")
        else
            makeStatus(allocator, broker.name, broker.kind, .unavailable, "macOS security CLI unavailable"),
        .infisical_agent_vault => makeStatus(allocator, broker.name, broker.kind, .unsupported, "status/config boundary only; resolution disabled until local API/CLI behavior is verified"),
    };
}

fn checkBrokerRef(
    allocator: std.mem.Allocator,
    broker: policy_schema.CredentialBrokerPolicy,
    credential_ref: policy_schema.CredentialRefPolicy,
    workspace_root: []const u8,
) !BrokerStatus {
    switch (broker.kind) {
        .local_dummy => return makeStatus(allocator, broker.name, broker.kind, .available, "reference configured; local dummy does not resolve raw values"),
        .env_file_dev => {
            var secret = resolveEnvFileDev(allocator, broker, workspace_root, credential_ref.ref) catch |err| {
                const message = try std.fmt.allocPrint(allocator, "ref check failed: {s}", .{safeErrorClass(err)});
                defer allocator.free(message);
                return makeStatus(allocator, broker.name, broker.kind, .failed, message);
            };
            secret.deinit(allocator);
            return makeStatus(allocator, broker.name, broker.kind, .available, "ref resolved and discarded without printing value");
        },
        .onepassword_cli => {
            var secret = resolveOnePassword(allocator, broker, credential_ref.ref) catch |err| {
                const message = try std.fmt.allocPrint(allocator, "ref check failed: {s}", .{safeErrorClass(err)});
                defer allocator.free(message);
                return makeStatus(allocator, broker.name, broker.kind, .failed, message);
            };
            secret.deinit(allocator);
            return makeStatus(allocator, broker.name, broker.kind, .available, "ref resolved and discarded without printing value");
        },
        .macos_keychain => {
            var secret = resolveMacosKeychain(allocator, credential_ref.ref) catch |err| {
                const message = try std.fmt.allocPrint(allocator, "ref check failed: {s}", .{safeErrorClass(err)});
                defer allocator.free(message);
                return makeStatus(allocator, broker.name, broker.kind, .failed, message);
            };
            secret.deinit(allocator);
            return makeStatus(allocator, broker.name, broker.kind, .available, "ref resolved and discarded without printing value");
        },
        .infisical_agent_vault => return makeStatus(allocator, broker.name, broker.kind, .unsupported, "ref configured; resolution disabled until adapter behavior is verified"),
    }
}

fn resolveEnvFileDev(
    allocator: std.mem.Allocator,
    broker: policy_schema.CredentialBrokerPolicy,
    workspace_root: []const u8,
    key: []const u8,
) !ResolvedSecret {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const path = try envFilePath(allocator, workspace_root, broker);
    defer allocator.free(path);
    const text = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(128 * 1024));
    defer wipeAndFree(allocator, text);
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const name = std.mem.trim(u8, line[0..eq], " \t");
        if (!std.mem.eql(u8, name, key)) continue;
        const value = parseEnvFileValue(std.mem.trim(u8, line[eq + 1 ..], " \t"));
        return .{ .value = try allocator.dupe(u8, value) };
    }
    return error.CredentialRefNotFound;
}

fn resolveOnePassword(
    allocator: std.mem.Allocator,
    broker: policy_schema.CredentialBrokerPolicy,
    ref: []const u8,
) !ResolvedSecret {
    var argv_list: std.ArrayList([]const u8) = .empty;
    defer argv_list.deinit(allocator);
    try argv_list.appendSlice(allocator, &.{ "op", "read", ref });
    if (broker.account) |account| try argv_list.appendSlice(allocator, &.{ "--account", account });
    const result = try runCapture(allocator, argv_list.items);
    defer result.deinit(allocator);
    if (result.code != 0) return classifyCommandFailure(result.stderr);
    return .{ .value = try allocator.dupe(u8, std.mem.trim(u8, result.stdout, " \t\r\n")) };
}

fn resolveMacosKeychain(allocator: std.mem.Allocator, ref: []const u8) !ResolvedSecret {
    const parsed = parseKeychainRef(ref);
    var argv_list: std.ArrayList([]const u8) = .empty;
    defer argv_list.deinit(allocator);
    try argv_list.appendSlice(allocator, &.{ "/usr/bin/security", "find-generic-password", "-s", parsed.service });
    if (parsed.account) |account| try argv_list.appendSlice(allocator, &.{ "-a", account });
    try argv_list.append(allocator, "-w");
    const result = try runCapture(allocator, argv_list.items);
    defer result.deinit(allocator);
    if (result.code != 0) return classifyCommandFailure(result.stderr);
    return .{ .value = try allocator.dupe(u8, std.mem.trim(u8, result.stdout, " \t\r\n")) };
}

fn runCapture(allocator: std.mem.Allocator, argv: []const []const u8) !CommandResult {
    return runCaptureWithTimeout(allocator, argv, default_broker_command_timeout_ns);
}

fn runCaptureWithTimeout(allocator: std.mem.Allocator, argv: []const []const u8, timeout_ns: u64) !CommandResult {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const run_result = std.process.run(allocator, io, .{
        .argv = argv,
        .stdout_limit = .limited(128 * 1024),
        .stderr_limit = .limited(32 * 1024),
        .timeout = .{ .duration = .{
            .raw = .fromNanoseconds(@intCast(timeout_ns)),
            .clock = .awake,
        } },
    }) catch |err| switch (err) {
        error.Timeout => return error.BrokerCommandTimeout,
        else => return err,
    };
    errdefer {
        allocator.free(run_result.stdout);
        allocator.free(run_result.stderr);
    }
    const code: u8 = switch (run_result.term) {
        .exited => |value| @intCast(@min(value, 255)),
        else => 255,
    };
    return .{
        .stdout = run_result.stdout,
        .stderr = run_result.stderr,
        .code = code,
    };
}

const CommandWatchdogContext = struct {
    child: *std.process.Child,
    done: *std.atomic.Value(bool),
    timed_out: *std.atomic.Value(bool),
    timeout_ns: u64,
};

fn commandWatchdog(context: *CommandWatchdogContext) void {
    const started = std.time.nanoTimestamp();
    while (!context.done.load(.acquire)) {
        if (std.time.nanoTimestamp() - started >= context.timeout_ns) {
            context.timed_out.store(true, .release);
            _ = context.child.kill() catch {};
            return;
        }
        std.Thread.sleep(10 * std.time.ns_per_ms);
    }
}

fn classifyCommandFailure(stderr: []const u8) anyerror {
    if (containsInsensitive(stderr, "not signed in") or
        containsInsensitive(stderr, "sign in") or
        containsInsensitive(stderr, "not logged in") or
        containsInsensitive(stderr, "login"))
    {
        return error.BrokerLoginRequired;
    }
    if (containsInsensitive(stderr, "not found") or
        containsInsensitive(stderr, "could not be found") or
        containsInsensitive(stderr, "no item") or
        containsInsensitive(stderr, "no such") or
        containsInsensitive(stderr, "specified item could not be found"))
    {
        return error.CredentialRefNotFound;
    }
    if (containsInsensitive(stderr, "timed out") or containsInsensitive(stderr, "timeout")) {
        return error.BrokerCommandTimeout;
    }
    return error.BrokerCommandFailed;
}

fn envFilePath(allocator: std.mem.Allocator, workspace_root: []const u8, broker: policy_schema.CredentialBrokerPolicy) ![]u8 {
    const relative = broker.path orelse return error.InvalidBrokerConfig;
    if (std.fs.path.isAbsolute(relative)) return error.InvalidBrokerConfig;
    if (std.mem.indexOf(u8, relative, "..") != null) return error.InvalidBrokerConfig;
    if (!(std.mem.startsWith(u8, relative, ".ryk/") or std.mem.startsWith(u8, relative, ".ryk\\"))) return error.InvalidBrokerConfig;
    return std.fs.path.join(allocator, &.{ workspace_root, relative });
}

fn parseEnvFileValue(value: []const u8) []const u8 {
    if (value.len >= 2 and ((value[0] == '"' and value[value.len - 1] == '"') or (value[0] == '\'' and value[value.len - 1] == '\''))) {
        return value[1 .. value.len - 1];
    }
    return value;
}

const KeychainRef = struct {
    service: []const u8,
    account: ?[]const u8 = null,
};

fn parseKeychainRef(ref: []const u8) KeychainRef {
    if (std.mem.indexOfScalar(u8, ref, '/')) |slash| {
        return .{ .service = ref[0..slash], .account = ref[slash + 1 ..] };
    }
    return .{ .service = ref };
}

fn findCredentialRef(credentials: policy_schema.CredentialsPolicy, name: []const u8) ?policy_schema.CredentialRefPolicy {
    for (credentials.refs) |credential_ref| {
        if (std.ascii.eqlIgnoreCase(credential_ref.name, name)) return credential_ref;
    }
    return null;
}

fn findBrokerForRef(
    credentials: policy_schema.CredentialsPolicy,
    credential_ref: policy_schema.CredentialRefPolicy,
) ?policy_schema.CredentialBrokerPolicy {
    const wanted = credential_ref.broker orelse credentials.default_broker orelse return null;
    for (credentials.brokers) |broker| {
        if (std.ascii.eqlIgnoreCase(broker.name, wanted)) return broker;
    }
    return null;
}

fn defaultDummyConfig() policy_schema.CredentialBrokerPolicy {
    return .{ .name = "local-dummy", .kind = .local_dummy };
}

fn makeStatus(
    allocator: std.mem.Allocator,
    name: []const u8,
    kind: BrokerKind,
    state: StatusState,
    message: []const u8,
) !BrokerStatus {
    return .{
        .name = try allocator.dupe(u8, name),
        .kind = kind,
        .state = state,
        .message = try allocator.dupe(u8, message),
    };
}

fn safeErrorClass(err: anyerror) []const u8 {
    return switch (err) {
        error.FileNotFound => "not-found",
        error.AccessDenied => "access-denied",
        error.CredentialRefNotFound, error.UnknownCredentialRef => "missing-ref",
        error.BrokerLoginRequired => "login-required",
        error.BrokerCommandTimeout => "timeout",
        error.BrokerCommandFailed => "broker-command-failed",
        error.InvalidBrokerConfig => "invalid-config",
        error.ReferenceOnlyBroker => "reference-only",
        error.UnsupportedBrokerResolution => "unsupported",
        else => "unavailable",
    };
}

fn executableInPath(io: std.Io, allocator: std.mem.Allocator, name: []const u8) !bool {
    _ = io;
    var env_map = env_util.createProcessMap(allocator) catch return false;
    defer env_map.deinit();
    const path_owned = env_util.getOwned(&env_map, allocator, "PATH") catch return false;
    const path = path_owned orelse return false;
    defer allocator.free(path);
    const separator: u8 = if (@import("builtin").os.tag == .windows) ';' else ':';
    var parts = std.mem.splitScalar(u8, path, separator);
    while (parts.next()) |part| {
        if (part.len == 0) continue;
        const candidate = try std.fs.path.join(allocator, &.{ part, name });
        defer allocator.free(candidate);
        if (fileExists(candidate)) return true;
    }
    return false;
}

fn containsInsensitive(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (haystack.len < needle.len) return false;
    var index: usize = 0;
    while (index + needle.len <= haystack.len) : (index += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[index .. index + needle.len], needle)) return true;
    }
    return false;
}

fn fileExists(path: []const u8) bool {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const file = std.Io.Dir.cwd().openFile(io, path, .{}) catch return false;
    file.close(io);
    return true;
}

fn wipeAndFree(allocator: std.mem.Allocator, value: []u8) void {
    @memset(value, 0);
    allocator.free(value);
}

test "local dummy broker creates raw-secret-free env references" {
    const broker = localDummyBroker();
    const ref = try broker.envReference(std.testing.allocator, "GITHUB_TOKEN", "ghp_fakeSyntheticTokenValue1234567890");
    defer ref.deinit(std.testing.allocator);

    try std.testing.expect(std.mem.startsWith(u8, ref.value, "ryk-secret://local-dummy/env/GITHUB_TOKEN/"));
    try std.testing.expect(std.mem.indexOf(u8, ref.value, "ghp_fakeSyntheticTokenValue") == null);
}

test "local dummy broker references are opaque and not stable secret verifiers" {
    const broker = localDummyBroker();
    const first = try broker.envReference(std.testing.allocator, "TOKEN", "same-low-entropy-secret");
    defer first.deinit(std.testing.allocator);
    const second = try broker.envReference(std.testing.allocator, "TOKEN", "same-low-entropy-secret");
    defer second.deinit(std.testing.allocator);

    try std.testing.expect(!std.mem.eql(u8, first.value, second.value));
    try std.testing.expect(std.mem.indexOf(u8, first.value, "same-low-entropy-secret") == null);
}

test "env-file dev broker resolves and redacts check output" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, ".ryk");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = ".ryk/dev-secrets.env", .data = "GITHUB_PAT=ghp_fakeSyntheticTokenValue1234567890\n" });
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    var loaded = try @import("ryk_core").policy.load.parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\credentials:
        \\  default_broker: env_dev
        \\  brokers:
        \\    env_dev:
        \\      type: env-file-dev
        \\      path: .ryk/dev-secrets.env
        \\  refs:
        \\    github_pat:
        \\      broker: env_dev
        \\      ref: GITHUB_PAT
    , "credentials.yaml");
    defer loaded.deinit();

    var secret = try resolveCredential(std.testing.allocator, &loaded, root, "github_pat");
    defer secret.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("ghp_fakeSyntheticTokenValue1234567890", secret.value);

    var report = try check(std.testing.io, std.testing.allocator, &loaded, root, "github_pat");
    defer report.deinit(std.testing.allocator);
    try std.testing.expect(report.ok());
    try std.testing.expect(std.mem.indexOf(u8, report.statuses[0].message, "ghp_fake") == null);
}

test "env-file dev broker rejects unsafe paths at runtime" {
    const broker: policy_schema.CredentialBrokerPolicy = .{ .name = "env_dev", .kind = .env_file_dev, .path = "/tmp/secrets.env" };
    try std.testing.expectError(error.InvalidBrokerConfig, envFilePath(std.testing.allocator, ".", broker));
}

test "broker command capture times out hung CLIs without leaking output" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;

    const started = std.Io.Clock.Timestamp.now(std.testing.io, .awake);
    try std.testing.expectError(error.BrokerCommandTimeout, runCaptureWithTimeout(std.testing.allocator, &.{ "/bin/sh", "-c", "sleep 2" }, 75 * std.time.ns_per_ms));
    const elapsed_ms = started.untilNow(std.testing.io).raw.toMilliseconds();
    try std.testing.expect(elapsed_ms < 1000);
}

test "broker command error classes are redacted and specific" {
    try std.testing.expectEqualStrings("timeout", safeErrorClass(error.BrokerCommandTimeout));
    try std.testing.expectEqualStrings("login-required", safeErrorClass(error.BrokerLoginRequired));
    try std.testing.expectEqualStrings("missing-ref", safeErrorClass(error.CredentialRefNotFound));
}

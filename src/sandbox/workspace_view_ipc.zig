//! Versioned, bounded wire codec for the Linux workspace-view bootstrap.
//!
//! The parent sends one request over a private pipe after self-exec. The
//! bootstrap returns one fixed-size response after FUSE INIT and Landlock
//! attach, or a stable reason code on failure. This module performs no I/O and
//! never formats request bytes into diagnostics.

const std = @import("std");

pub const cookie_len = 32;
pub const profile_hash_len = 32;
/// v4 (2026-08-18): fixed payload grew 36 → 40 bytes with ro_file_path_count
/// and a file-only RO list so ancestor instruction keeps OS grant kind file
/// on protect-on rebuild. v3 bootstrap children reject v4 parents.
pub const protocol_version: u16 = 4;

const magic = [4]u8{ 'R', 'Y', 'K', 'W' };
const header_len = 12;
const request_fixed_payload_len = cookie_len + profile_hash_len + 40;
const request_variable_offset = header_len + request_fixed_payload_len;
const request_options_offset = header_len + cookie_len + profile_hash_len;
const request_stdio_offset = request_options_offset + 1;
const response_status_offset = header_len + cookie_len + profile_hash_len;
const response_proof_offset = response_status_offset + 1;
const response_reason_offset = response_proof_offset + 1;
pub const response_frame_len = header_len + cookie_len + profile_hash_len + 8;
/// Allocations in `decodeRequestAlloc`: 1 frame storage copy + 7 slice tables
/// (control_roots, exec_paths, ro_paths, ro_file_paths, host_rw_paths, argv, environ).
const decode_allocation_count = 8;

const option_include_tmp: u8 = 1 << 0;
const option_has_proxy: u8 = 1 << 1;
const option_require_route: u8 = 1 << 2;
const option_protect_secrets: u8 = 1 << 3;
const known_option_flags = option_include_tmp | option_has_proxy | option_require_route | option_protect_secrets;

const proof_fuse_initialized: u8 = 1 << 0;
const proof_landlock_attached: u8 = 1 << 1;
const known_proof_flags = proof_fuse_initialized | proof_landlock_attached;

pub const Limits = struct {
    max_frame_bytes: usize = 2 * 1024 * 1024,
    max_path_bytes: usize = 16 * 1024,
    max_item_bytes: usize = 128 * 1024,
    max_control_roots: usize = 256,
    max_exec_paths: usize = 64,
    max_ro_paths: usize = 256,
    max_ro_file_paths: usize = 256,
    max_host_rw_paths: usize = 256,
    max_arguments: usize = 4096,
    max_environment_entries: usize = 8192,
};

pub const FrameKind = enum(u8) {
    request = 1,
    response = 2,
};

pub const StdioBehavior = enum(u8) {
    inherit = 0,
    ignore = 1,
};

pub const ProfileOptions = struct {
    include_tmp: bool = false,
    control_roots: []const []const u8 = &.{},
    /// Narrow absolute launch-binary paths (parent `.exec` grants). Required for
    /// bootstrap profile hash parity with `compileProfile(..., .exec_paths)`.
    exec_paths: []const []const u8 = &.{},
    /// Original parent compile inputs required for profile-hash parity.
    ro_paths: []const []const u8 = &.{},
    /// File-only RO grants (ancestor instruction). Rebuild as extra_grants kind file.
    ro_file_paths: []const []const u8 = &.{},
    host_rw_paths: []const []const u8 = &.{},
    network_proxy_port: ?u16 = null,
    require_network_route_forcing: bool = false,
    protect_workspace_secrets: bool,
};

pub const BootstrapRequest = struct {
    cookie: [cookie_len]u8,
    expected_profile_hash: [profile_hash_len]u8,
    workspace_root: []const u8,
    agent_cwd: []const u8,
    argv: []const []const u8,
    environ: []const []const u8,
    profile: ProfileOptions,
    stdio: StdioBehavior,
};

pub const OwnedProfileOptions = struct {
    include_tmp: bool,
    control_roots: [][]const u8,
    exec_paths: [][]const u8,
    ro_paths: [][]const u8,
    ro_file_paths: [][]const u8,
    host_rw_paths: [][]const u8,
    network_proxy_port: ?u16,
    require_network_route_forcing: bool,
    protect_workspace_secrets: bool,
};

/// Owns `storage` plus the six outer slice tables. All string fields are
/// views into `storage` and become invalid after `deinit`.
pub const OwnedBootstrapRequest = struct {
    allocator: std.mem.Allocator,
    storage: []u8,
    cookie: [cookie_len]u8,
    expected_profile_hash: [profile_hash_len]u8,
    workspace_root: []const u8,
    agent_cwd: []const u8,
    argv: [][]const u8,
    environ: [][]const u8,
    profile: OwnedProfileOptions,
    stdio: StdioBehavior,

    /// Wipes the frame-backed strings and identity arrays. Idempotent so error
    /// cleanup can converge on one path without risking a double free.
    pub fn deinit(self: *OwnedBootstrapRequest) void {
        self.allocator.free(self.profile.control_roots);
        self.allocator.free(self.profile.exec_paths);
        self.allocator.free(self.profile.ro_paths);
        self.allocator.free(self.profile.ro_file_paths);
        self.allocator.free(self.profile.host_rw_paths);
        self.allocator.free(self.argv);
        self.allocator.free(self.environ);
        wipeAndFree(self.allocator, self.storage);
        std.crypto.secureZero(u8, &self.cookie);
        std.crypto.secureZero(u8, &self.expected_profile_hash);
        self.storage = &.{};
        self.workspace_root = "";
        self.agent_cwd = "";
        self.argv = &.{};
        self.environ = &.{};
        self.profile.control_roots = &.{};
        self.profile.exec_paths = &.{};
        self.profile.ro_paths = &.{};
        self.profile.ro_file_paths = &.{};
        self.profile.host_rw_paths = &.{};
    }

    pub fn borrowed(self: *const OwnedBootstrapRequest) BootstrapRequest {
        return .{
            .cookie = self.cookie,
            .expected_profile_hash = self.expected_profile_hash,
            .workspace_root = self.workspace_root,
            .agent_cwd = self.agent_cwd,
            .argv = self.argv,
            .environ = self.environ,
            .profile = .{
                .include_tmp = self.profile.include_tmp,
                .control_roots = self.profile.control_roots,
                .exec_paths = self.profile.exec_paths,
                .ro_paths = self.profile.ro_paths,
                .ro_file_paths = self.profile.ro_file_paths,
                .host_rw_paths = self.profile.host_rw_paths,
                .network_proxy_port = self.profile.network_proxy_port,
                .require_network_route_forcing = self.profile.require_network_route_forcing,
                .protect_workspace_secrets = self.profile.protect_workspace_secrets,
            },
            .stdio = self.stdio,
        };
    }
};

/// Owned encoded request bytes. Call `deinit` so environment material is wiped
/// before release even though the normal boundary carries only constructed,
/// secretless environment entries.
pub const EncodedFrame = struct {
    allocator: std.mem.Allocator,
    bytes: []u8,

    pub fn deinit(self: *EncodedFrame) void {
        wipeAndFree(self.allocator, self.bytes);
        self.bytes = &.{};
    }
};

pub const ResponseStatus = enum(u8) {
    failed = 0,
    ready = 1,
};

pub const BootstrapProof = struct {
    fuse_initialized: bool = false,
    landlock_attached: bool = false,
};

/// Stable on-wire values. Do not reorder or reuse numeric codes.
pub const ReasonCode = enum(u16) {
    none = 0,
    malformed_request = 1,
    unsupported_version = 2,
    protocol_violation = 3,
    namespace_setup_failed = 4,
    user_mapping_failed = 5,
    stdio_setup_failed = 6,
    backing_open_failed = 7,
    fuse_device_unavailable = 8,
    fuse_mount_failed = 9,
    fuse_daemon_start_failed = 10,
    fuse_init_failed = 11,
    profile_rebuild_failed = 12,
    profile_hash_mismatch = 13,
    landlock_unavailable = 14,
    landlock_attach_failed = 15,
    chdir_failed = 16,
    fd_scrub_failed = 17,
    exec_preflight_failed = 18,
    daemon_exited = 19,
    timeout = 20,
    internal_failure = 21,
    capability_lockdown_failed = 22,
    mount_verification_failed = 23,
};

pub const BootstrapFailure = error{
    MalformedRequest,
    UnsupportedVersion,
    ProtocolViolation,
    NamespaceSetupFailed,
    UserMappingFailed,
    StdioSetupFailed,
    FuseDeviceUnavailable,
    BackingOpenFailed,
    FuseMountFailed,
    FuseDaemonStartFailed,
    FuseInitFailed,
    ProfileRebuildFailed,
    LandlockUnavailable,
    LandlockAttachFailed,
    ProfileHashMismatch,
    ChdirFailed,
    FdScrubFailed,
    ExecPreflightFailed,
    DaemonExited,
    Timeout,
    InternalFailure,
    CapabilityLockdownFailed,
    MountVerificationFailed,
};

pub const BootstrapResponse = struct {
    cookie: [cookie_len]u8,
    profile_hash: [profile_hash_len]u8,
    status: ResponseStatus,
    reason: ReasonCode,
    daemon_pid: u32,
    proof: BootstrapProof,

    pub fn isReady(self: BootstrapResponse) bool {
        return self.status == .ready and
            self.reason == .none and
            self.daemon_pid != 0 and
            self.proof.fuse_initialized and
            self.proof.landlock_attached;
    }

    /// Constant-time identity comparison prevents the response pipe from
    /// becoming a cookie/profile-hash oracle.
    pub fn matchesIdentity(
        self: BootstrapResponse,
        cookie: [cookie_len]u8,
        profile_hash: [profile_hash_len]u8,
    ) bool {
        const cookie_matches = std.crypto.timing_safe.eql([cookie_len]u8, self.cookie, cookie);
        const hash_matches = std.crypto.timing_safe.eql([profile_hash_len]u8, self.profile_hash, profile_hash);
        return cookie_matches and hash_matches;
    }
};

pub const CodecError = error{
    OutOfMemory,
    BufferTooSmall,
    FrameTooLarge,
    TruncatedFrame,
    TrailingBytes,
    BadMagic,
    UnsupportedVersion,
    UnexpectedFrameKind,
    InvalidReservedBits,
    InvalidOptionFlags,
    InvalidProofFlags,
    InvalidStdioBehavior,
    InvalidResponseStatus,
    InvalidReasonCode,
    InvalidResponseState,
    IntegerOverflow,
    LengthOutOfRange,
    TooManyControlRoots,
    TooManyExecPaths,
    TooManyRoPaths,
    TooManyHostRwPaths,
    TooManyArguments,
    TooManyEnvironmentEntries,
    PathTooLong,
    ItemTooLong,
    EmptyPath,
    PathNotAbsolute,
    EmptyArguments,
    EmptyExecutable,
    InvalidEnvironmentEntry,
    EmbeddedNul,
    SecretProtectionRequired,
    RouteForcingNeedsProxy,
    InvalidProxyPort,
    InvalidCookie,
    InvalidProfileHash,
    ResponseIdentityMismatch,
};

pub fn encodedRequestSize(request: BootstrapRequest, limits: Limits) CodecError!usize {
    try validateBorrowedRequest(request, limits);

    var size: usize = request_variable_offset;
    size = try checkedAdd(size, request.workspace_root.len);
    size = try checkedAdd(size, request.agent_cwd.len);
    size = try addStringListSize(size, request.profile.control_roots);
    size = try addStringListSize(size, request.profile.exec_paths);
    size = try addStringListSize(size, request.profile.ro_paths);
    size = try addStringListSize(size, request.profile.ro_file_paths);
    size = try addStringListSize(size, request.profile.host_rw_paths);
    size = try addStringListSize(size, request.argv);
    size = try addStringListSize(size, request.environ);
    if (size > limits.max_frame_bytes) return error.FrameTooLarge;
    const payload_len = size - header_len;
    if (payload_len > std.math.maxInt(u32)) return error.LengthOutOfRange;
    return size;
}

pub fn encodeRequestAlloc(
    allocator: std.mem.Allocator,
    request: BootstrapRequest,
    limits: Limits,
) CodecError!EncodedFrame {
    const size = try encodedRequestSize(request, limits);
    const bytes = try allocator.alloc(u8, size);
    errdefer wipeAndFree(allocator, bytes);
    _ = try encodeRequest(bytes, request, limits);
    return .{ .allocator = allocator, .bytes = bytes };
}

pub fn encodeRequest(
    output: []u8,
    request: BootstrapRequest,
    limits: Limits,
) CodecError![]u8 {
    const size = try encodedRequestSize(request, limits);
    if (output.len < size) return error.BufferTooSmall;

    var writer: Writer = .{ .bytes = output[0..size] };
    try writeHeader(&writer, .request, size - header_len);
    try writer.putBytes(&request.cookie);
    try writer.putBytes(&request.expected_profile_hash);
    try writer.putU8(requestOptionFlags(request.profile));
    try writer.putU8(@intFromEnum(request.stdio));
    try writer.putU16(request.profile.network_proxy_port orelse 0);
    try writer.putU32(try usizeToU32(request.profile.control_roots.len));
    try writer.putU32(try usizeToU32(request.profile.exec_paths.len));
    try writer.putU32(try usizeToU32(request.profile.ro_paths.len));
    try writer.putU32(try usizeToU32(request.profile.ro_file_paths.len));
    try writer.putU32(try usizeToU32(request.profile.host_rw_paths.len));
    try writer.putU32(try usizeToU32(request.argv.len));
    try writer.putU32(try usizeToU32(request.environ.len));
    try writer.putU32(try usizeToU32(request.workspace_root.len));
    try writer.putU32(try usizeToU32(request.agent_cwd.len));
    try writer.putBytes(request.workspace_root);
    try writer.putBytes(request.agent_cwd);
    try writeStringList(&writer, request.profile.control_roots);
    try writeStringList(&writer, request.profile.exec_paths);
    try writeStringList(&writer, request.profile.ro_paths);
    try writeStringList(&writer, request.profile.ro_file_paths);
    try writeStringList(&writer, request.profile.host_rw_paths);
    try writeStringList(&writer, request.argv);
    try writeStringList(&writer, request.environ);
    if (writer.pos != size) return error.InvalidResponseState;
    return output[0..size];
}

pub fn decodeRequestAlloc(
    allocator: std.mem.Allocator,
    frame: []const u8,
    limits: Limits,
) CodecError!OwnedBootstrapRequest {
    const meta = try validateRequestFrame(frame, limits);

    const storage = try allocator.dupe(u8, frame);
    errdefer wipeAndFree(allocator, storage);
    const control_roots = try allocator.alloc([]const u8, meta.control_root_count);
    errdefer allocator.free(control_roots);
    const exec_paths = try allocator.alloc([]const u8, meta.exec_path_count);
    errdefer allocator.free(exec_paths);
    const ro_paths = try allocator.alloc([]const u8, meta.ro_path_count);
    errdefer allocator.free(ro_paths);
    const ro_file_paths = try allocator.alloc([]const u8, meta.ro_file_path_count);
    errdefer allocator.free(ro_file_paths);
    const host_rw_paths = try allocator.alloc([]const u8, meta.host_rw_path_count);
    errdefer allocator.free(host_rw_paths);
    const argv = try allocator.alloc([]const u8, meta.argument_count);
    errdefer allocator.free(argv);
    const environ = try allocator.alloc([]const u8, meta.environment_count);
    errdefer allocator.free(environ);

    var reader: Reader = .{ .bytes = storage };
    try skipHeader(&reader, .request, limits.max_frame_bytes);
    var cookie: [cookie_len]u8 = undefined;
    @memcpy(&cookie, try reader.take(cookie_len));
    var profile_hash: [profile_hash_len]u8 = undefined;
    @memcpy(&profile_hash, try reader.take(profile_hash_len));
    const option_flags = try reader.readU8();
    const stdio = std.enums.fromInt(StdioBehavior, try reader.readU8()) orelse
        return error.InvalidStdioBehavior;
    const proxy_port_raw = try reader.readU16();
    _ = try reader.readU32(); // control_root_count
    _ = try reader.readU32(); // exec_path_count
    _ = try reader.readU32(); // ro_path_count
    _ = try reader.readU32(); // ro_file_path_count
    _ = try reader.readU32(); // host_rw_path_count
    _ = try reader.readU32(); // argument_count
    _ = try reader.readU32(); // environment_count
    const workspace_len: usize = try reader.readU32();
    const cwd_len: usize = try reader.readU32();
    const workspace_root = try reader.take(workspace_len);
    const agent_cwd = try reader.take(cwd_len);
    try readStringListViews(&reader, control_roots);
    try readStringListViews(&reader, exec_paths);
    try readStringListViews(&reader, ro_paths);
    try readStringListViews(&reader, ro_file_paths);
    try readStringListViews(&reader, host_rw_paths);
    try readStringListViews(&reader, argv);
    try readStringListViews(&reader, environ);
    if (reader.pos != storage.len) return error.TrailingBytes;

    return .{
        .allocator = allocator,
        .storage = storage,
        .cookie = cookie,
        .expected_profile_hash = profile_hash,
        .workspace_root = workspace_root,
        .agent_cwd = agent_cwd,
        .argv = argv,
        .environ = environ,
        .profile = .{
            .include_tmp = option_flags & option_include_tmp != 0,
            .control_roots = control_roots,
            .exec_paths = exec_paths,
            .ro_paths = ro_paths,
            .ro_file_paths = ro_file_paths,
            .host_rw_paths = host_rw_paths,
            .network_proxy_port = if (option_flags & option_has_proxy != 0) proxy_port_raw else null,
            .require_network_route_forcing = option_flags & option_require_route != 0,
            .protect_workspace_secrets = option_flags & option_protect_secrets != 0,
        },
        .stdio = stdio,
    };
}

pub fn encodeResponse(output: []u8, response: BootstrapResponse) CodecError![]u8 {
    try validateResponse(response);
    if (output.len < response_frame_len) return error.BufferTooSmall;

    var writer: Writer = .{ .bytes = output[0..response_frame_len] };
    try writeHeader(&writer, .response, response_frame_len - header_len);
    try writer.putBytes(&response.cookie);
    try writer.putBytes(&response.profile_hash);
    try writer.putU8(@intFromEnum(response.status));
    try writer.putU8(proofFlags(response.proof));
    try writer.putU16(@intFromEnum(response.reason));
    try writer.putU32(response.daemon_pid);
    return output[0..response_frame_len];
}

pub fn decodeResponse(frame: []const u8) CodecError!BootstrapResponse {
    var reader: Reader = .{ .bytes = frame };
    try skipHeader(&reader, .response, std.math.maxInt(usize));
    if (frame.len != response_frame_len) {
        return if (frame.len < response_frame_len) error.TruncatedFrame else error.TrailingBytes;
    }

    var cookie: [cookie_len]u8 = undefined;
    @memcpy(&cookie, try reader.take(cookie_len));
    var profile_hash: [profile_hash_len]u8 = undefined;
    @memcpy(&profile_hash, try reader.take(profile_hash_len));
    const status = std.enums.fromInt(ResponseStatus, try reader.readU8()) orelse
        return error.InvalidResponseStatus;
    const proof_flags = try reader.readU8();
    if (proof_flags & ~known_proof_flags != 0) return error.InvalidProofFlags;
    const reason = std.enums.fromInt(ReasonCode, try reader.readU16()) orelse
        return error.InvalidReasonCode;
    const response: BootstrapResponse = .{
        .cookie = cookie,
        .profile_hash = profile_hash,
        .status = status,
        .reason = reason,
        .daemon_pid = try reader.readU32(),
        .proof = .{
            .fuse_initialized = proof_flags & proof_fuse_initialized != 0,
            .landlock_attached = proof_flags & proof_landlock_attached != 0,
        },
    };
    try validateResponse(response);
    return response;
}

pub fn decodeResponseForIdentity(
    frame: []const u8,
    cookie: [cookie_len]u8,
    profile_hash: [profile_hash_len]u8,
) CodecError!BootstrapResponse {
    const response = try decodeResponse(frame);
    if (!response.matchesIdentity(cookie, profile_hash)) return error.ResponseIdentityMismatch;
    return response;
}

pub fn reasonAsError(reason: ReasonCode) ?BootstrapFailure {
    return switch (reason) {
        .none => null,
        .malformed_request => error.MalformedRequest,
        .unsupported_version => error.UnsupportedVersion,
        .protocol_violation => error.ProtocolViolation,
        .namespace_setup_failed => error.NamespaceSetupFailed,
        .user_mapping_failed => error.UserMappingFailed,
        .stdio_setup_failed => error.StdioSetupFailed,
        .fuse_device_unavailable => error.FuseDeviceUnavailable,
        .backing_open_failed => error.BackingOpenFailed,
        .fuse_mount_failed => error.FuseMountFailed,
        .fuse_daemon_start_failed => error.FuseDaemonStartFailed,
        .fuse_init_failed => error.FuseInitFailed,
        .profile_rebuild_failed => error.ProfileRebuildFailed,
        .landlock_unavailable => error.LandlockUnavailable,
        .landlock_attach_failed => error.LandlockAttachFailed,
        .profile_hash_mismatch => error.ProfileHashMismatch,
        .chdir_failed => error.ChdirFailed,
        .fd_scrub_failed => error.FdScrubFailed,
        .exec_preflight_failed => error.ExecPreflightFailed,
        .daemon_exited => error.DaemonExited,
        .timeout => error.Timeout,
        .internal_failure => error.InternalFailure,
        .capability_lockdown_failed => error.CapabilityLockdownFailed,
        .mount_verification_failed => error.MountVerificationFailed,
    };
}

const RequestMeta = struct {
    control_root_count: usize,
    exec_path_count: usize,
    ro_path_count: usize,
    ro_file_path_count: usize,
    host_rw_path_count: usize,
    argument_count: usize,
    environment_count: usize,
};

fn validateBorrowedRequest(request: BootstrapRequest, limits: Limits) CodecError!void {
    if (allZero(&request.cookie)) return error.InvalidCookie;
    if (allZero(&request.expected_profile_hash)) return error.InvalidProfileHash;
    if (!request.profile.protect_workspace_secrets) return error.SecretProtectionRequired;
    if (request.profile.control_roots.len > limits.max_control_roots) return error.TooManyControlRoots;
    if (request.profile.exec_paths.len > limits.max_exec_paths) return error.TooManyExecPaths;
    if (request.profile.ro_paths.len > limits.max_ro_paths) return error.TooManyRoPaths;
    if (request.profile.ro_file_paths.len > limits.max_ro_file_paths) return error.TooManyRoPaths;
    if (request.profile.host_rw_paths.len > limits.max_host_rw_paths) return error.TooManyHostRwPaths;
    if (request.argv.len == 0) return error.EmptyArguments;
    if (request.argv.len > limits.max_arguments) return error.TooManyArguments;
    if (request.environ.len > limits.max_environment_entries) return error.TooManyEnvironmentEntries;
    try validatePath(request.workspace_root, limits.max_path_bytes, true);
    try validatePath(request.agent_cwd, limits.max_path_bytes, true);
    for (request.profile.control_roots) |root| try validatePath(root, limits.max_path_bytes, false);
    for (request.profile.exec_paths) |exec_path| try validatePath(exec_path, limits.max_path_bytes, true);
    for (request.profile.ro_paths) |ro_path| try validatePath(ro_path, limits.max_path_bytes, true);
    for (request.profile.ro_file_paths) |ro_file_path| try validatePath(ro_file_path, limits.max_path_bytes, true);
    for (request.profile.host_rw_paths) |host_rw_path| try validatePath(host_rw_path, limits.max_path_bytes, true);
    for (request.argv, 0..) |arg, index| {
        try validateItem(arg, limits.max_item_bytes);
        if (index == 0 and arg.len == 0) return error.EmptyExecutable;
    }
    for (request.environ) |entry| {
        try validateItem(entry, limits.max_item_bytes);
        try validateEnvironmentEntry(entry);
    }
    try validateProxyOptions(request.profile.network_proxy_port, request.profile.require_network_route_forcing);

    _ = try usizeToU32(request.profile.control_roots.len);
    _ = try usizeToU32(request.profile.exec_paths.len);
    _ = try usizeToU32(request.profile.ro_paths.len);
    _ = try usizeToU32(request.profile.ro_file_paths.len);
    _ = try usizeToU32(request.profile.host_rw_paths.len);
    _ = try usizeToU32(request.argv.len);
    _ = try usizeToU32(request.environ.len);
}

fn validateRequestFrame(frame: []const u8, limits: Limits) CodecError!RequestMeta {
    var reader: Reader = .{ .bytes = frame };
    try skipHeader(&reader, .request, limits.max_frame_bytes);
    if (allZero(try reader.take(cookie_len))) return error.InvalidCookie;
    if (allZero(try reader.take(profile_hash_len))) return error.InvalidProfileHash;

    const option_flags = try reader.readU8();
    if (option_flags & ~known_option_flags != 0) return error.InvalidOptionFlags;
    if (option_flags & option_protect_secrets == 0) return error.SecretProtectionRequired;
    _ = std.enums.fromInt(StdioBehavior, try reader.readU8()) orelse
        return error.InvalidStdioBehavior;
    const proxy_port_raw = try reader.readU16();
    const control_root_count: usize = try reader.readU32();
    const exec_path_count: usize = try reader.readU32();
    const ro_path_count: usize = try reader.readU32();
    const ro_file_path_count: usize = try reader.readU32();
    const host_rw_path_count: usize = try reader.readU32();
    const argument_count: usize = try reader.readU32();
    const environment_count: usize = try reader.readU32();
    const workspace_len: usize = try reader.readU32();
    const cwd_len: usize = try reader.readU32();

    if (control_root_count > limits.max_control_roots) return error.TooManyControlRoots;
    if (exec_path_count > limits.max_exec_paths) return error.TooManyExecPaths;
    if (ro_path_count > limits.max_ro_paths) return error.TooManyRoPaths;
    if (ro_file_path_count > limits.max_ro_file_paths) return error.TooManyRoPaths;
    if (host_rw_path_count > limits.max_host_rw_paths) return error.TooManyHostRwPaths;
    if (argument_count == 0) return error.EmptyArguments;
    if (argument_count > limits.max_arguments) return error.TooManyArguments;
    if (environment_count > limits.max_environment_entries) return error.TooManyEnvironmentEntries;

    const workspace_root = try reader.take(workspace_len);
    const agent_cwd = try reader.take(cwd_len);
    try validatePath(workspace_root, limits.max_path_bytes, true);
    try validatePath(agent_cwd, limits.max_path_bytes, true);

    try scanStringList(&reader, control_root_count, limits.max_path_bytes, .path);
    try scanStringList(&reader, exec_path_count, limits.max_path_bytes, .absolute_path);
    try scanStringList(&reader, ro_path_count, limits.max_path_bytes, .absolute_path);
    try scanStringList(&reader, ro_file_path_count, limits.max_path_bytes, .absolute_path);
    try scanStringList(&reader, host_rw_path_count, limits.max_path_bytes, .absolute_path);
    try scanStringList(&reader, argument_count, limits.max_item_bytes, .argument);
    try scanStringList(&reader, environment_count, limits.max_item_bytes, .environment);
    if (reader.pos != frame.len) return error.TrailingBytes;

    const proxy_port: ?u16 = if (option_flags & option_has_proxy != 0) proxy_port_raw else null;
    if (proxy_port == null and proxy_port_raw != 0) return error.InvalidProxyPort;
    try validateProxyOptions(proxy_port, option_flags & option_require_route != 0);

    return .{
        .control_root_count = control_root_count,
        .exec_path_count = exec_path_count,
        .ro_path_count = ro_path_count,
        .ro_file_path_count = ro_file_path_count,
        .host_rw_path_count = host_rw_path_count,
        .argument_count = argument_count,
        .environment_count = environment_count,
    };
}

const StringClass = enum {
    path,
    absolute_path,
    argument,
    environment,
};

fn scanStringList(reader: *Reader, count: usize, max_len: usize, class: StringClass) CodecError!void {
    var index: usize = 0;
    while (index < count) : (index += 1) {
        const len: usize = try reader.readU32();
        const item = try reader.take(len);
        switch (class) {
            .path => try validatePath(item, max_len, false),
            .absolute_path => try validatePath(item, max_len, true),
            .argument => {
                try validateItem(item, max_len);
                if (index == 0 and item.len == 0) return error.EmptyExecutable;
            },
            .environment => {
                try validateItem(item, max_len);
                try validateEnvironmentEntry(item);
            },
        }
    }
}

fn validatePath(path: []const u8, max_len: usize, require_absolute: bool) CodecError!void {
    if (path.len == 0) return error.EmptyPath;
    if (path.len > max_len) return error.PathTooLong;
    if (std.mem.indexOfScalar(u8, path, 0) != null) return error.EmbeddedNul;
    if (require_absolute and path[0] != '/') return error.PathNotAbsolute;
}

fn validateItem(item: []const u8, max_len: usize) CodecError!void {
    if (item.len > max_len) return error.ItemTooLong;
    if (std.mem.indexOfScalar(u8, item, 0) != null) return error.EmbeddedNul;
}

fn validateEnvironmentEntry(entry: []const u8) CodecError!void {
    const equals = std.mem.indexOfScalar(u8, entry, '=') orelse return error.InvalidEnvironmentEntry;
    if (equals == 0) return error.InvalidEnvironmentEntry;
}

fn allZero(bytes: []const u8) bool {
    var combined: u8 = 0;
    for (bytes) |byte| combined |= byte;
    return combined == 0;
}

fn validateProxyOptions(proxy_port: ?u16, require_route: bool) CodecError!void {
    if (proxy_port) |port| {
        if (port == 0) return error.InvalidProxyPort;
    } else if (require_route) {
        return error.RouteForcingNeedsProxy;
    }
}

fn validateResponse(response: BootstrapResponse) CodecError!void {
    if (response.proof.landlock_attached and !response.proof.fuse_initialized) {
        return error.InvalidResponseState;
    }
    switch (response.status) {
        .ready => {
            if (response.reason != .none or
                response.daemon_pid == 0 or
                !response.proof.fuse_initialized or
                !response.proof.landlock_attached)
            {
                return error.InvalidResponseState;
            }
        },
        .failed => {
            if (response.reason == .none) return error.InvalidResponseState;
        },
    }
}

fn requestOptionFlags(options: ProfileOptions) u8 {
    var flags: u8 = 0;
    if (options.include_tmp) flags |= option_include_tmp;
    if (options.network_proxy_port != null) flags |= option_has_proxy;
    if (options.require_network_route_forcing) flags |= option_require_route;
    if (options.protect_workspace_secrets) flags |= option_protect_secrets;
    return flags;
}

fn proofFlags(proof: BootstrapProof) u8 {
    var flags: u8 = 0;
    if (proof.fuse_initialized) flags |= proof_fuse_initialized;
    if (proof.landlock_attached) flags |= proof_landlock_attached;
    return flags;
}

fn addStringListSize(initial: usize, values: []const []const u8) CodecError!usize {
    var size = initial;
    for (values) |value| {
        size = try checkedAdd(size, @sizeOf(u32));
        size = try checkedAdd(size, value.len);
    }
    return size;
}

fn writeStringList(writer: *Writer, values: []const []const u8) CodecError!void {
    for (values) |value| {
        try writer.putU32(try usizeToU32(value.len));
        try writer.putBytes(value);
    }
}

fn readStringListViews(reader: *Reader, values: [][]const u8) CodecError!void {
    for (values) |*value| {
        const len: usize = try reader.readU32();
        value.* = try reader.take(len);
    }
}

fn writeHeader(writer: *Writer, kind: FrameKind, payload_len: usize) CodecError!void {
    try writer.putBytes(&magic);
    try writer.putU16(protocol_version);
    try writer.putU8(@intFromEnum(kind));
    try writer.putU8(0);
    try writer.putU32(try usizeToU32(payload_len));
}

fn skipHeader(reader: *Reader, expected_kind: FrameKind, max_frame_bytes: usize) CodecError!void {
    if (reader.bytes.len > max_frame_bytes) return error.FrameTooLarge;
    if (reader.bytes.len < header_len) return error.TruncatedFrame;
    if (!std.mem.eql(u8, try reader.take(magic.len), &magic)) return error.BadMagic;
    if (try reader.readU16() != protocol_version) return error.UnsupportedVersion;
    if (try reader.readU8() != @intFromEnum(expected_kind)) return error.UnexpectedFrameKind;
    if (try reader.readU8() != 0) return error.InvalidReservedBits;
    const payload_len: usize = try reader.readU32();
    const declared_len = try checkedAdd(header_len, payload_len);
    if (reader.bytes.len < declared_len) return error.TruncatedFrame;
    if (reader.bytes.len > declared_len) return error.TrailingBytes;
}

fn checkedAdd(a: usize, b: usize) CodecError!usize {
    return std.math.add(usize, a, b) catch error.IntegerOverflow;
}

fn usizeToU32(value: usize) CodecError!u32 {
    if (value > std.math.maxInt(u32)) return error.LengthOutOfRange;
    return @intCast(value);
}

/// `Allocator.free` poisons released bytes in safety builds after a wipe. Use
/// the matching raw free so the final store to sensitive request storage is
/// the explicit zeroization.
fn wipeAndFree(allocator: std.mem.Allocator, bytes: []u8) void {
    if (bytes.len == 0) return;
    std.crypto.secureZero(u8, bytes);
    allocator.rawFree(bytes, .of(u8), @returnAddress());
}

const Writer = struct {
    bytes: []u8,
    pos: usize = 0,

    fn putU8(self: *Writer, value: u8) CodecError!void {
        const dest = try self.take(1);
        dest[0] = value;
    }

    fn putU16(self: *Writer, value: u16) CodecError!void {
        const dest = try self.take(2);
        dest[0] = @truncate(value);
        dest[1] = @truncate(value >> 8);
    }

    fn putU32(self: *Writer, value: u32) CodecError!void {
        const dest = try self.take(4);
        dest[0] = @truncate(value);
        dest[1] = @truncate(value >> 8);
        dest[2] = @truncate(value >> 16);
        dest[3] = @truncate(value >> 24);
    }

    fn putBytes(self: *Writer, value: []const u8) CodecError!void {
        @memcpy(try self.take(value.len), value);
    }

    fn take(self: *Writer, len: usize) CodecError![]u8 {
        if (len > self.bytes.len - self.pos) return error.BufferTooSmall;
        const start = self.pos;
        self.pos += len;
        return self.bytes[start..self.pos];
    }
};

const Reader = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn readU8(self: *Reader) CodecError!u8 {
        return (try self.take(1))[0];
    }

    fn readU16(self: *Reader) CodecError!u16 {
        const source = try self.take(2);
        return @as(u16, source[0]) | (@as(u16, source[1]) << 8);
    }

    fn readU32(self: *Reader) CodecError!u32 {
        const source = try self.take(4);
        return @as(u32, source[0]) |
            (@as(u32, source[1]) << 8) |
            (@as(u32, source[2]) << 16) |
            (@as(u32, source[3]) << 24);
    }

    fn take(self: *Reader, len: usize) CodecError![]const u8 {
        if (len > self.bytes.len - self.pos) return error.TruncatedFrame;
        const start = self.pos;
        self.pos += len;
        return self.bytes[start..self.pos];
    }
};

test "request frame round trips every bootstrap field" {
    const control_roots = [_][]const u8{ "/work/.ryk", "/run/ryk-control" };
    const exec_paths = [_][]const u8{ "/home/user/.local/bin/agent", "/home/user/.local/bin/agent-real" };
    const ro_paths = [_][]const u8{ "/home/user/.local/share/agent", "/etc/agent/config" };
    const host_rw_paths = [_][]const u8{"/home/user/.config/agent"};
    const argv = [_][]const u8{ "/usr/bin/agent", "--mode", "safe" };
    const environ = [_][]const u8{ "PATH=/usr/bin:/bin", "RYK_SESSION_ID=session-test" };
    const request: BootstrapRequest = .{
        .cookie = [_]u8{0xA5} ** cookie_len,
        .expected_profile_hash = [_]u8{0x5A} ** profile_hash_len,
        .workspace_root = "/work",
        .agent_cwd = "/work/src",
        .argv = &argv,
        .environ = &environ,
        .profile = .{
            .include_tmp = true,
            .control_roots = &control_roots,
            .exec_paths = &exec_paths,
            .ro_paths = &ro_paths,
            .host_rw_paths = &host_rw_paths,
            .network_proxy_port = 43123,
            .require_network_route_forcing = true,
            .protect_workspace_secrets = true,
        },
        .stdio = .ignore,
    };

    var encoded = try encodeRequestAlloc(std.testing.allocator, request, .{});
    defer encoded.deinit();
    var decoded = try decodeRequestAlloc(std.testing.allocator, encoded.bytes, .{});
    defer decoded.deinit();

    try std.testing.expectEqualSlices(u8, &request.cookie, &decoded.cookie);
    try std.testing.expectEqualSlices(u8, &request.expected_profile_hash, &decoded.expected_profile_hash);
    try std.testing.expectEqualStrings(request.workspace_root, decoded.workspace_root);
    try std.testing.expectEqualStrings(request.agent_cwd, decoded.agent_cwd);
    try expectStringListsEqual(request.argv, decoded.argv);
    try expectStringListsEqual(request.environ, decoded.environ);
    try expectStringListsEqual(request.profile.control_roots, decoded.profile.control_roots);
    try expectStringListsEqual(request.profile.exec_paths, decoded.profile.exec_paths);
    try expectStringListsEqual(request.profile.ro_paths, decoded.profile.ro_paths);
    try expectStringListsEqual(request.profile.host_rw_paths, decoded.profile.host_rw_paths);
    try std.testing.expectEqual(request.profile.include_tmp, decoded.profile.include_tmp);
    try std.testing.expectEqual(request.profile.network_proxy_port, decoded.profile.network_proxy_port);
    try std.testing.expectEqual(
        request.profile.require_network_route_forcing,
        decoded.profile.require_network_route_forcing,
    );
    try std.testing.expect(decoded.profile.protect_workspace_secrets);
    try std.testing.expectEqual(request.stdio, decoded.stdio);
}

fn expectStringListsEqual(expected: []const []const u8, actual: []const []const u8) !void {
    try std.testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |want, got| {
        try std.testing.expectEqualStrings(want, got);
    }
}

test "decoded request owns bytes independently from input frame" {
    const argv = [_][]const u8{"/usr/bin/agent"};
    const environ = [_][]const u8{"PATH=/usr/bin"};
    const request: BootstrapRequest = .{
        .cookie = [_]u8{1} ** cookie_len,
        .expected_profile_hash = [_]u8{2} ** profile_hash_len,
        .workspace_root = "/work",
        .agent_cwd = "/work",
        .argv = &argv,
        .environ = &environ,
        .profile = .{ .protect_workspace_secrets = true },
        .stdio = .inherit,
    };
    var encoded = try encodeRequestAlloc(std.testing.allocator, request, .{});
    defer encoded.deinit();
    var decoded = try decodeRequestAlloc(std.testing.allocator, encoded.bytes, .{});
    defer decoded.deinit();

    @memset(encoded.bytes, 0);
    try std.testing.expectEqualStrings("/work", decoded.workspace_root);
    try std.testing.expectEqualStrings("/usr/bin/agent", decoded.argv[0]);
    try std.testing.expectEqualStrings("PATH=/usr/bin", decoded.environ[0]);
}

test "request codec rejects cap violations before allocation" {
    const roots = [_][]const u8{ "/one", "/two" };
    const argv = [_][]const u8{ "/usr/bin/agent", "--safe" };
    const environ = [_][]const u8{"PATH=/usr/bin"};
    const request: BootstrapRequest = .{
        .cookie = [_]u8{3} ** cookie_len,
        .expected_profile_hash = [_]u8{4} ** profile_hash_len,
        .workspace_root = "/work",
        .agent_cwd = "/work",
        .argv = &argv,
        .environ = &environ,
        .profile = .{
            .control_roots = &roots,
            .ro_paths = &roots,
            .host_rw_paths = &roots,
            .protect_workspace_secrets = true,
        },
        .stdio = .inherit,
    };

    try std.testing.expectError(
        error.TooManyControlRoots,
        encodedRequestSize(request, .{ .max_control_roots = 1 }),
    );
    try std.testing.expectError(error.TooManyRoPaths, encodedRequestSize(request, .{ .max_ro_paths = 1 }));
    try std.testing.expectError(
        error.TooManyHostRwPaths,
        encodedRequestSize(request, .{ .max_host_rw_paths = 1 }),
    );
    try std.testing.expectError(error.TooManyArguments, encodedRequestSize(request, .{ .max_arguments = 1 }));
    try std.testing.expectError(error.TooManyEnvironmentEntries, encodedRequestSize(
        request,
        .{ .max_environment_entries = 0 },
    ));
    try std.testing.expectError(error.PathTooLong, encodedRequestSize(request, .{ .max_path_bytes = 4 }));
    try std.testing.expectError(error.FrameTooLarge, encodedRequestSize(request, .{ .max_frame_bytes = 100 }));
}

test "request codec rejects unsafe semantic values" {
    const argv_empty = [_][]const u8{""};
    const argv = [_][]const u8{"/usr/bin/agent"};
    const bad_environ = [_][]const u8{"TOKEN_WITHOUT_EQUALS"};
    const good_environ = [_][]const u8{"PATH=/usr/bin"};
    const embedded_nul = [_][]const u8{"PATH=/usr/bin\x00/evil"};

    const base: BootstrapRequest = .{
        .cookie = [_]u8{5} ** cookie_len,
        .expected_profile_hash = [_]u8{6} ** profile_hash_len,
        .workspace_root = "/work",
        .agent_cwd = "/work",
        .argv = &argv,
        .environ = &good_environ,
        .profile = .{ .protect_workspace_secrets = true },
        .stdio = .inherit,
    };

    var request = base;
    request.argv = &.{};
    try std.testing.expectError(error.EmptyArguments, encodedRequestSize(request, .{}));
    request.argv = &argv_empty;
    try std.testing.expectError(error.EmptyExecutable, encodedRequestSize(request, .{}));
    request = base;
    request.workspace_root = "relative";
    try std.testing.expectError(error.PathNotAbsolute, encodedRequestSize(request, .{}));
    request = base;
    request.agent_cwd = "";
    try std.testing.expectError(error.EmptyPath, encodedRequestSize(request, .{}));
    request = base;
    request.environ = &bad_environ;
    try std.testing.expectError(error.InvalidEnvironmentEntry, encodedRequestSize(request, .{}));
    request.environ = &embedded_nul;
    try std.testing.expectError(error.EmbeddedNul, encodedRequestSize(request, .{}));
    request = base;
    request.profile.protect_workspace_secrets = false;
    try std.testing.expectError(error.SecretProtectionRequired, encodedRequestSize(request, .{}));
    request = base;
    request.profile.require_network_route_forcing = true;
    try std.testing.expectError(error.RouteForcingNeedsProxy, encodedRequestSize(request, .{}));
    request.profile.network_proxy_port = 0;
    try std.testing.expectError(error.InvalidProxyPort, encodedRequestSize(request, .{}));
    request = base;
    request.cookie = [_]u8{0} ** cookie_len;
    try std.testing.expectError(error.InvalidCookie, encodedRequestSize(request, .{}));
    request = base;
    request.expected_profile_hash = [_]u8{0} ** profile_hash_len;
    try std.testing.expectError(error.InvalidProfileHash, encodedRequestSize(request, .{}));
}

test "request decoder rejects malformed framing and wire fields" {
    const argv = [_][]const u8{"/usr/bin/agent"};
    const environ = [_][]const u8{"PATH=/usr/bin"};
    const request: BootstrapRequest = .{
        .cookie = [_]u8{7} ** cookie_len,
        .expected_profile_hash = [_]u8{8} ** profile_hash_len,
        .workspace_root = "/work",
        .agent_cwd = "/work",
        .argv = &argv,
        .environ = &environ,
        .profile = .{ .protect_workspace_secrets = true },
        .stdio = .inherit,
    };
    var encoded = try encodeRequestAlloc(std.testing.allocator, request, .{});
    defer encoded.deinit();

    try std.testing.expectError(
        error.TruncatedFrame,
        decodeRequestAlloc(std.testing.allocator, encoded.bytes[0 .. encoded.bytes.len - 1], .{}),
    );

    var copy = try std.testing.allocator.dupe(u8, encoded.bytes);
    defer std.testing.allocator.free(copy);
    copy[0] ^= 0xff;
    try std.testing.expectError(error.BadMagic, decodeRequestAlloc(std.testing.allocator, copy, .{}));
    @memcpy(copy, encoded.bytes);
    // protocol_version is little-endian u16 at offset 4; set to unsupported (not current v3).
    copy[4] = 2;
    copy[5] = 0;
    try std.testing.expectError(error.UnsupportedVersion, decodeRequestAlloc(std.testing.allocator, copy, .{}));
    @memcpy(copy, encoded.bytes);
    copy[6] = @intFromEnum(FrameKind.response);
    try std.testing.expectError(error.UnexpectedFrameKind, decodeRequestAlloc(std.testing.allocator, copy, .{}));
    @memcpy(copy, encoded.bytes);
    copy[7] = 1;
    try std.testing.expectError(error.InvalidReservedBits, decodeRequestAlloc(std.testing.allocator, copy, .{}));
    @memcpy(copy, encoded.bytes);
    copy[request_options_offset] |= 0x80;
    try std.testing.expectError(error.InvalidOptionFlags, decodeRequestAlloc(std.testing.allocator, copy, .{}));
    @memcpy(copy, encoded.bytes);
    copy[request_stdio_offset] = 0xff;
    try std.testing.expectError(error.InvalidStdioBehavior, decodeRequestAlloc(std.testing.allocator, copy, .{}));
    @memcpy(copy, encoded.bytes);
    @memset(copy[header_len .. header_len + cookie_len], 0);
    try std.testing.expectError(error.InvalidCookie, decodeRequestAlloc(std.testing.allocator, copy, .{}));
    @memcpy(copy, encoded.bytes);
    @memset(copy[header_len + cookie_len .. header_len + cookie_len + profile_hash_len], 0);
    try std.testing.expectError(error.InvalidProfileHash, decodeRequestAlloc(std.testing.allocator, copy, .{}));

    var with_trailing = try std.testing.allocator.alloc(u8, encoded.bytes.len + 1);
    defer std.testing.allocator.free(with_trailing);
    @memcpy(with_trailing[0..encoded.bytes.len], encoded.bytes);
    with_trailing[encoded.bytes.len] = 0;
    try std.testing.expectError(
        error.TrailingBytes,
        decodeRequestAlloc(std.testing.allocator, with_trailing, .{}),
    );
}

test "request decoder applies local limits to otherwise valid frame" {
    const argv = [_][]const u8{ "/usr/bin/agent", "--safe" };
    const environ = [_][]const u8{"PATH=/usr/bin"};
    const request: BootstrapRequest = .{
        .cookie = [_]u8{9} ** cookie_len,
        .expected_profile_hash = [_]u8{10} ** profile_hash_len,
        .workspace_root = "/work",
        .agent_cwd = "/work",
        .argv = &argv,
        .environ = &environ,
        .profile = .{ .protect_workspace_secrets = true },
        .stdio = .inherit,
    };
    var encoded = try encodeRequestAlloc(std.testing.allocator, request, .{});
    defer encoded.deinit();

    try std.testing.expectError(error.TooManyArguments, decodeRequestAlloc(
        std.testing.allocator,
        encoded.bytes,
        .{ .max_arguments = 1 },
    ));
    try std.testing.expectError(error.FrameTooLarge, decodeRequestAlloc(
        std.testing.allocator,
        encoded.bytes,
        .{ .max_frame_bytes = encoded.bytes.len - 1 },
    ));
}

test "request allocation failures propagate and clean up partial decode" {
    const roots = [_][]const u8{"/work/.ryk"};
    const exec_paths = [_][]const u8{"/usr/bin/agent"};
    const ro_paths = [_][]const u8{"/usr/share/agent"};
    const ro_file_paths = [_][]const u8{"/home/user/CodingProjects/AGENTS.md"};
    const host_rw_paths = [_][]const u8{"/home/user/.agent"};
    const argv = [_][]const u8{"/usr/bin/agent"};
    const environ = [_][]const u8{"PATH=/usr/bin"};
    const request: BootstrapRequest = .{
        .cookie = [_]u8{11} ** cookie_len,
        .expected_profile_hash = [_]u8{12} ** profile_hash_len,
        .workspace_root = "/work",
        .agent_cwd = "/work",
        .argv = &argv,
        .environ = &environ,
        .profile = .{
            .control_roots = &roots,
            .exec_paths = &exec_paths,
            .ro_paths = &ro_paths,
            .ro_file_paths = &ro_file_paths,
            .host_rw_paths = &host_rw_paths,
            .protect_workspace_secrets = true,
        },
        .stdio = .inherit,
    };
    var encoded = try encodeRequestAlloc(std.testing.allocator, request, .{});
    defer encoded.deinit();

    var encode_failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, encodeRequestAlloc(encode_failing.allocator(), request, .{}));
    try std.testing.expect(encode_failing.has_induced_failure);

    var fail_index: usize = 0;
    while (fail_index < decode_allocation_count) : (fail_index += 1) {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = fail_index });
        try std.testing.expectError(
            error.OutOfMemory,
            decodeRequestAlloc(failing.allocator(), encoded.bytes, .{}),
        );
        try std.testing.expect(failing.has_induced_failure);
    }
}

test "owned request and encoded frame wipe their byte storage on deinit" {
    const argv = [_][]const u8{"/usr/bin/agent"};
    const environ = [_][]const u8{"CANARY=ghp_fake_workspace_ipc_canary"};
    const request: BootstrapRequest = .{
        .cookie = [_]u8{0xCC} ** cookie_len,
        .expected_profile_hash = [_]u8{0xDD} ** profile_hash_len,
        .workspace_root = "/work",
        .agent_cwd = "/work",
        .argv = &argv,
        .environ = &environ,
        .profile = .{ .protect_workspace_secrets = true },
        .stdio = .inherit,
    };
    const encoded_size = try encodedRequestSize(request, .{});

    var encode_backing: [4096]u8 = [_]u8{0xEE} ** 4096;
    var encode_fba = std.heap.FixedBufferAllocator.init(&encode_backing);
    var encoded = try encodeRequestAlloc(encode_fba.allocator(), request, .{});
    encoded.deinit();
    for (encode_backing[0..encoded_size]) |byte| try std.testing.expectEqual(@as(u8, 0), byte);

    var source = try encodeRequestAlloc(std.testing.allocator, request, .{});
    defer source.deinit();
    var decode_backing: [8192]u8 = [_]u8{0xEE} ** 8192;
    var decode_fba = std.heap.FixedBufferAllocator.init(&decode_backing);
    var decoded = try decodeRequestAlloc(decode_fba.allocator(), source.bytes, .{});
    decoded.deinit();
    for (decode_backing[0..encoded_size]) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
    try std.testing.expect(allZero(&decoded.cookie));
    try std.testing.expect(allZero(&decoded.expected_profile_hash));
    decoded.deinit();
}

test "ready response round trips proof and matches request identity" {
    const cookie = [_]u8{13} ** cookie_len;
    const profile_hash = [_]u8{14} ** profile_hash_len;
    const response: BootstrapResponse = .{
        .cookie = cookie,
        .profile_hash = profile_hash,
        .status = .ready,
        .reason = .none,
        .daemon_pid = 4242,
        .proof = .{ .fuse_initialized = true, .landlock_attached = true },
    };

    var bytes: [response_frame_len]u8 = undefined;
    const frame = try encodeResponse(&bytes, response);
    const decoded = try decodeResponse(frame);
    try std.testing.expectEqual(response, decoded);
    try std.testing.expect(decoded.isReady());
    try std.testing.expect(decoded.matchesIdentity(cookie, profile_hash));
    try std.testing.expectEqual(
        decoded,
        try decodeResponseForIdentity(frame, cookie, profile_hash),
    );

    var wrong_cookie = cookie;
    wrong_cookie[0] ^= 1;
    try std.testing.expect(!decoded.matchesIdentity(wrong_cookie, profile_hash));
    try std.testing.expectError(
        error.ResponseIdentityMismatch,
        decodeResponseForIdentity(frame, wrong_cookie, profile_hash),
    );
    var wrong_hash = profile_hash;
    wrong_hash[0] ^= 1;
    try std.testing.expect(!decoded.matchesIdentity(cookie, wrong_hash));
}

test "error response carries only stable reason and partial proof" {
    const response: BootstrapResponse = .{
        .cookie = [_]u8{15} ** cookie_len,
        .profile_hash = [_]u8{16} ** profile_hash_len,
        .status = .failed,
        .reason = .landlock_attach_failed,
        .daemon_pid = 4243,
        .proof = .{ .fuse_initialized = true, .landlock_attached = false },
    };

    var bytes: [response_frame_len]u8 = undefined;
    const decoded = try decodeResponse(try encodeResponse(&bytes, response));
    try std.testing.expectEqual(response, decoded);
    try std.testing.expect(!decoded.isReady());
    try std.testing.expectEqualStrings("LandlockAttachFailed", @errorName(reasonAsError(decoded.reason).?));
}

test "response codec rejects contradictory and unknown states" {
    const ready: BootstrapResponse = .{
        .cookie = [_]u8{17} ** cookie_len,
        .profile_hash = [_]u8{18} ** profile_hash_len,
        .status = .ready,
        .reason = .none,
        .daemon_pid = 42,
        .proof = .{ .fuse_initialized = true, .landlock_attached = true },
    };
    var bytes: [response_frame_len + 1]u8 = undefined;

    var invalid = ready;
    invalid.proof.landlock_attached = false;
    try std.testing.expectError(error.InvalidResponseState, encodeResponse(&bytes, invalid));
    invalid = ready;
    invalid.reason = .internal_failure;
    try std.testing.expectError(error.InvalidResponseState, encodeResponse(&bytes, invalid));
    invalid = ready;
    invalid.daemon_pid = 0;
    try std.testing.expectError(error.InvalidResponseState, encodeResponse(&bytes, invalid));
    invalid = ready;
    invalid.status = .failed;
    invalid.reason = .fuse_init_failed;
    invalid.proof.fuse_initialized = false;
    try std.testing.expectError(error.InvalidResponseState, encodeResponse(&bytes, invalid));

    const frame = try encodeResponse(&bytes, ready);
    bytes[response_reason_offset] = 0xff;
    bytes[response_reason_offset + 1] = 0xff;
    try std.testing.expectError(error.InvalidReasonCode, decodeResponse(frame));
    _ = try encodeResponse(&bytes, ready);
    bytes[response_proof_offset] |= 0x80;
    try std.testing.expectError(error.InvalidProofFlags, decodeResponse(bytes[0..response_frame_len]));
    _ = try encodeResponse(&bytes, ready);
    bytes[response_status_offset] = 0xff;
    try std.testing.expectError(error.InvalidResponseStatus, decodeResponse(bytes[0..response_frame_len]));
    try std.testing.expectError(error.BufferTooSmall, encodeResponse(bytes[0 .. response_frame_len - 1], ready));

    _ = try encodeResponse(&bytes, ready);
    bytes[response_frame_len] = 0;
    try std.testing.expectError(error.TrailingBytes, decodeResponse(bytes[0 .. response_frame_len + 1]));
}

test "stable response reasons cover every bootstrap failure stage" {
    const reasons = [_]ReasonCode{
        .malformed_request,
        .unsupported_version,
        .protocol_violation,
        .namespace_setup_failed,
        .user_mapping_failed,
        .stdio_setup_failed,
        .backing_open_failed,
        .fuse_device_unavailable,
        .fuse_mount_failed,
        .fuse_daemon_start_failed,
        .fuse_init_failed,
        .profile_rebuild_failed,
        .profile_hash_mismatch,
        .landlock_unavailable,
        .landlock_attach_failed,
        .chdir_failed,
        .fd_scrub_failed,
        .exec_preflight_failed,
        .daemon_exited,
        .timeout,
        .internal_failure,
    };
    for (reasons) |reason| {
        const response: BootstrapResponse = .{
            .cookie = [_]u8{19} ** cookie_len,
            .profile_hash = [_]u8{20} ** profile_hash_len,
            .status = .failed,
            .reason = reason,
            .daemon_pid = 0,
            .proof = .{},
        };
        var bytes: [response_frame_len]u8 = undefined;
        const decoded = try decodeResponse(try encodeResponse(&bytes, response));
        try std.testing.expectEqual(reason, decoded.reason);
        try std.testing.expect(reasonAsError(reason).? != error.ProtocolViolation or reason == .protocol_violation);
    }
    try std.testing.expect(reasonAsError(.none) == null);
}

test "checked size arithmetic rejects overflow" {
    try std.testing.expectError(error.IntegerOverflow, checkedAdd(std.math.maxInt(usize), 1));
}

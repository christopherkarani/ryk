const std = @import("std");
const builtin = @import("builtin");
const session_secrets = @import("session_secrets.zig");
const protocol = @import("provider_gateway_protocol.zig");
const types = @import("provider_gateway_types.zig");

pub const Provider = types.Provider;
pub const Limits = types.Limits;
const ParsedInbound = protocol.ParsedInbound;
pub const AuditKind = types.AuditKind;
pub const AuditEvent = types.AuditEvent;

/// Cap in-memory provider-gateway audit trail (#371). Older events dropped FIFO.
/// Mirrors intercept proxy max_audit_events — not a durability store.
const max_audit_events: usize = 256;

const ProviderConfig = struct {
    logical_host: []const u8,
    env_var: []const u8,
    production_origin: []const u8,

    fn get(provider: Provider) ProviderConfig {
        return switch (provider) {
            .anthropic => .{
                .logical_host = "api.anthropic.com",
                .env_var = "ANTHROPIC_API_KEY",
                .production_origin = "https://api.anthropic.com",
            },
            .openai => .{
                .logical_host = "api.openai.com",
                .env_var = "OPENAI_API_KEY",
                .production_origin = "https://api.openai.com",
            },
        };
    }
};

pub const Runtime = struct {
    state: *State,

    pub fn bindUrl(self: Runtime) []const u8 {
        return self.state.bind_url;
    }
    pub fn bindPort(self: Runtime) u16 {
        return self.state.bind_port;
    }
    pub fn provider(self: Runtime) Provider {
        return self.state.provider;
    }
    pub fn isServing(self: Runtime) bool {
        return self.state.serving.load(.acquire);
    }
    pub fn isHealthy(self: Runtime) bool {
        return self.state.serving.load(.acquire) and
            !self.state.stop.load(.acquire) and
            !self.state.failed.load(.acquire);
    }
    pub fn failed(self: Runtime) bool {
        return self.state.failed.load(.acquire);
    }
    pub fn startServing(self: *Runtime) !void {
        if (comptime builtin.os.tag == .windows) return error.GatewayUnsupportedOnWindows;
        if (self.state.serving.swap(true, .acq_rel)) return;
        self.state.thread = std.Thread.spawn(.{}, serverLoop, .{self.state}) catch |err| {
            self.state.serving.store(false, .release);
            return err;
        };
        self.state.thread_started = true;
    }
    pub fn waitForIdle(self: Runtime, timeout_ns: u64) !void {
        var threaded: std.Io.Threaded = .init_single_threaded;
        const io = threaded.io();
        const started = std.Io.Clock.Timestamp.now(io, .awake);
        while (self.state.active_connections.load(.acquire) > 0) {
            if (started.durationFromNow(io).raw.nanoseconds > timeout_ns)
                return error.GatewayConnectionsActive;
            std.Io.sleep(io, std.Io.Duration.fromNanoseconds(10 * std.time.ns_per_ms), .awake) catch {};
        }
    }
    pub fn snapshotAuditEvents(self: Runtime, allocator: std.mem.Allocator) ![]AuditEvent {
        const io = self.state.threaded.io();
        try self.state.audit_mutex.lock(io);
        defer self.state.audit_mutex.unlock(io);
        return try allocator.dupe(AuditEvent, self.state.audit_events.items);
    }
    pub fn freeAuditEvents(_: Runtime, allocator: std.mem.Allocator, events: []AuditEvent) void {
        allocator.free(events);
    }
    pub fn deinit(self: *Runtime) void {
        const state = self.state;
        const io = state.threaded.io();
        state.stop.store(true, .release);
        wake(io, state.bind_port);
        if (state.thread_started) state.thread.join();
        state.server.deinit(io);
        state.shutdownConnections(io);
        while (state.active_connections.load(.acquire) > 0)
            std.Io.sleep(io, std.Io.Duration.fromNanoseconds(10 * std.time.ns_per_ms), .awake) catch {};
        state.http_client.deinit();
        state.active_streams.deinit(state.allocator);
        state.audit_events.deinit(state.allocator);
        state.allocator.free(state.bind_url);
        state.allocator.free(state.upstream_origin);
        state.allocator.destroy(state);
        self.* = undefined;
    }
};

/// Narrow test seam for loopback integration harnesses. Production callers use
/// `listen`/`start`; tests may substitute a synthetic upstream origin and
/// observe only the aggregate connection count.
pub const testing = if (builtin.is_test) struct {
    pub fn listenWithOrigin(
        allocator: std.mem.Allocator,
        store: *const session_secrets.Store,
        provider: Provider,
        limits: Limits,
        upstream_origin: []const u8,
    ) !Runtime {
        return providerGatewayListenWithOrigin(allocator, store, provider, limits, upstream_origin);
    }

    pub fn activeConnectionCount(runtime: Runtime) usize {
        return runtime.state.active_connections.load(.acquire);
    }
} else struct {};

const State = struct {
    allocator: std.mem.Allocator,
    server: std.Io.net.Server,
    bind_port: u16,
    bind_url: []u8,
    provider: Provider,
    store: *const session_secrets.Store,
    limits: Limits,
    upstream_origin: []u8,
    threaded: std.Io.Threaded,
    http_client: std.http.Client,
    stop: std.atomic.Value(bool) = .init(false),
    failed: std.atomic.Value(bool) = .init(false),
    serving: std.atomic.Value(bool) = .init(false),
    active_connections: std.atomic.Value(usize) = .init(0),
    connections_mutex: std.Io.Mutex = .init,
    active_streams: std.ArrayList(std.Io.net.Stream) = .empty,
    audit_mutex: std.Io.Mutex = .init,
    audit_events: std.ArrayList(AuditEvent) = .empty,
    thread: std.Thread = undefined,
    thread_started: bool = false,

    fn record(self: *State, kind: AuditKind, reason_code: []const u8) !void {
        const config = ProviderConfig.get(self.provider);
        const io = self.threaded.io();
        try self.audit_mutex.lock(io);
        defer self.audit_mutex.unlock(io);
        // #371: bound in-memory trail (FIFO), same pattern as intercept proxy max_audit_events.
        while (self.audit_events.items.len >= max_audit_events) {
            _ = self.audit_events.orderedRemove(0);
        }
        try self.audit_events.append(self.allocator, .{
            .kind = kind,
            .provider = self.provider,
            .env_var = config.env_var,
            .reason_code = reason_code,
        });
    }

    fn registerConnection(self: *State, io: std.Io, stream: std.Io.net.Stream) !void {
        try self.connections_mutex.lock(io);
        defer self.connections_mutex.unlock(io);
        try self.active_streams.append(self.allocator, stream);
    }

    fn unregisterConnection(self: *State, io: std.Io, handle: std.Io.net.Socket.Handle) void {
        self.connections_mutex.lock(io) catch return;
        defer self.connections_mutex.unlock(io);
        for (self.active_streams.items, 0..) |stream, index| {
            if (stream.socket.handle != handle) continue;
            _ = self.active_streams.swapRemove(index);
            return;
        }
    }

    fn shutdownConnections(self: *State, io: std.Io) void {
        self.connections_mutex.lock(io) catch return;
        defer self.connections_mutex.unlock(io);
        for (self.active_streams.items) |stream| {
            stream.shutdown(io, .both) catch {};
        }
    }
};

pub fn listen(
    allocator: std.mem.Allocator,
    store: *const session_secrets.Store,
    provider: Provider,
    limits: Limits,
) !Runtime {
    return providerGatewayListenWithOrigin(
        allocator,
        store,
        provider,
        limits,
        ProviderConfig.get(provider).production_origin,
    );
}

pub fn start(
    allocator: std.mem.Allocator,
    store: *const session_secrets.Store,
    provider: Provider,
    limits: Limits,
) !Runtime {
    var runtime = try listen(allocator, store, provider, limits);
    errdefer runtime.deinit();
    try runtime.startServing();
    return runtime;
}

fn providerGatewayListenWithOrigin(
    allocator: std.mem.Allocator,
    store: *const session_secrets.Store,
    provider: Provider,
    limits: Limits,
    upstream_origin: []const u8,
) !Runtime {
    if (!store.hasProvider(provider)) return error.ProviderGrantMissing;
    if (limits.request_head < 1024 or limits.response_head < 1024 or
        limits.io_timeout_ms == 0 or limits.io_timeout_ms > std.math.maxInt(i32) or
        limits.upstream_timeout_ms == 0)
        return error.InvalidLimits;
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try address.listen(io, .{ .reuse_address = false });
    errdefer server.deinit(io);
    try setServerSocketCloexec(server.socket.handle);
    const port = server.socket.address.getPort();
    const bind_url = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}", .{port});
    errdefer allocator.free(bind_url);
    const owned_origin = try allocator.dupe(u8, upstream_origin);
    errdefer allocator.free(owned_origin);
    const state = try allocator.create(State);
    errdefer allocator.destroy(state);
    state.* = .{
        .allocator = allocator,
        .server = server,
        .bind_port = port,
        .bind_url = bind_url,
        .provider = provider,
        .store = store,
        .limits = limits,
        .upstream_origin = owned_origin,
        .threaded = threaded,
        .http_client = undefined,
    };
    state.http_client = .{
        .allocator = allocator,
        .io = state.threaded.io(),
        .read_buffer_size = limits.response_head,
    };
    return .{ .state = state };
}

fn setServerSocketCloexec(handle: std.Io.net.Socket.Handle) !void {
    switch (builtin.os.tag) {
        .windows, .wasi => {},
        else => if (std.c.fcntl(handle, std.c.F.SETFD, @as(c_int, std.c.FD_CLOEXEC)) == -1)
            return error.Unexpected,
    }
}

fn serverLoop(state: *State) void {
    const io = state.threaded.io();
    while (!state.stop.load(.acquire)) {
        var stream = state.server.accept(io) catch {
            if (!state.stop.load(.acquire)) state.failed.store(true, .release);
            break;
        };
        if (state.stop.load(.acquire)) {
            stream.close(io);
            break;
        }
        const context = state.allocator.create(ConnectionContext) catch {
            stream.close(io);
            continue;
        };
        state.registerConnection(io, stream) catch {
            stream.close(io);
            state.allocator.destroy(context);
            continue;
        };
        context.* = .{ .state = state, .client = stream };
        _ = state.active_connections.fetchAdd(1, .acq_rel);
        const thread = std.Thread.spawn(.{}, connectionLoop, .{context}) catch {
            state.unregisterConnection(io, stream.socket.handle);
            _ = state.active_connections.fetchSub(1, .acq_rel);
            stream.close(io);
            state.allocator.destroy(context);
            continue;
        };
        thread.detach();
    }
}

const ConnectionContext = struct { state: *State, client: std.Io.net.Stream };
fn connectionLoop(context: *ConnectionContext) void {
    const state = context.state;
    const io = state.threaded.io();
    defer {
        const allocator = context.state.allocator;
        context.state.unregisterConnection(io, context.client.socket.handle);
        context.client.close(io);
        _ = context.state.active_connections.fetchSub(1, .acq_rel);
        allocator.destroy(context);
    }
    handleConnection(state, io, context.client) catch {};
}

fn handleConnection(state: *State, io: std.Io, client: std.Io.net.Stream) !void {
    const head_buffer = try state.allocator.alloc(u8, state.limits.request_head);
    defer state.allocator.free(head_buffer);
    const read_len = readHeaders(state, io, client, head_buffer) catch |err| {
        const status: u16 = if (err == error.RequestTooLarge) 431 else 400;
        writeError(io, client, status, if (status == 431) "Request Header Fields Too Large" else "Bad Request") catch {};
        return;
    };
    var parsed = protocol.parseInbound(
        state.allocator,
        state.provider,
        head_buffer[0..read_len],
        state.limits,
    ) catch |err| {
        state.record(.phantom_denied, protocol.denialReason(err)) catch {};
        const status: u16 = if (err == error.RequestBodyTooLarge) 413 else if (protocol.isAuthorizationError(err)) 403 else 400;
        writeError(io, client, status, if (status == 403) "Forbidden" else if (status == 413) "Payload Too Large" else "Bad Request") catch {};
        return;
    };
    defer parsed.deinit(state.allocator);
    const config = ProviderConfig.get(state.provider);
    const authorized = state.store.authorize(
        parsed.phantom,
        state.provider,
        config.env_var,
        config.logical_host,
    ) catch |err| {
        state.record(.phantom_denied, authorizationReason(err)) catch {};
        try writeError(io, client, 403, "Forbidden");
        return;
    };
    state.record(.phantom_swap, "authorized") catch {
        try writeError(io, client, 503, "Service Unavailable");
        return;
    };
    var downstream_started = false;
    forwardRequestWithTimeout(
        state,
        io,
        client,
        &parsed,
        head_buffer[parsed.headers_end..read_len],
        authorized.raw,
        &downstream_started,
    ) catch {
        if (!downstream_started) writeError(io, client, 502, "Bad Gateway") catch {};
    };
}

fn forwardRequestWithTimeout(
    state: *State,
    io: std.Io,
    downstream: std.Io.net.Stream,
    inbound: *const ParsedInbound,
    initial_body: []const u8,
    raw: []const u8,
    downstream_started: *bool,
) !void {
    const deadline_ns = @as(i128, std.Io.Clock.Timestamp.now(io, .awake).raw.nanoseconds) +
        @as(i128, state.limits.upstream_timeout_ms) * std.time.ns_per_ms;
    const Task = struct {
        fn run(
            task_state: *State,
            task_io: std.Io,
            task_downstream: std.Io.net.Stream,
            task_inbound: *const ParsedInbound,
            task_initial_body: []const u8,
            task_raw: []const u8,
            task_downstream_started: *bool,
            task_deadline_ns: i128,
            result: *?anyerror,
            done: *std.Io.Event,
        ) void {
            defer done.set(task_io);
            forwardRequest(
                task_state,
                task_io,
                task_downstream,
                task_inbound,
                task_initial_body,
                task_raw,
                task_downstream_started,
                task_deadline_ns,
            ) catch |err| {
                result.* = err;
            };
        }
    };

    var result: ?anyerror = null;
    var done: std.Io.Event = .unset;
    var future = io.async(Task.run, .{
        state,
        io,
        downstream,
        inbound,
        initial_body,
        raw,
        downstream_started,
        deadline_ns,
        &result,
        &done,
    });
    while (true) {
        done.waitTimeout(io, .{
            .duration = .{
                .raw = std.Io.Duration.fromMilliseconds(@min(state.limits.upstream_timeout_ms, 10)),
                .clock = .awake,
            },
        }) catch |err| switch (err) {
            error.Timeout => {
                if (state.stop.load(.acquire)) {
                    _ = future.cancel(io);
                    return error.Canceled;
                }
                if (std.Io.Clock.Timestamp.now(io, .awake).raw.nanoseconds >= deadline_ns) {
                    _ = future.cancel(io);
                    return error.UpstreamTimeout;
                }
                continue;
            },
            error.Canceled => {
                _ = future.cancel(io);
                return error.Canceled;
            },
        };
        break;
    }
    future.await(io);
    if (result) |err| return err;
}

fn readHeaders(state: *const State, io: std.Io, stream: std.Io.net.Stream, buffer: []u8) !usize {
    const deadline_ns = @as(i128, std.Io.Clock.Timestamp.now(io, .awake).raw.nanoseconds) +
        @as(i128, state.limits.io_timeout_ms) * std.time.ns_per_ms;
    var total: usize = 0;
    while (total < buffer.len) {
        if (state.stop.load(.acquire)) return error.Canceled;
        const now_ns = std.Io.Clock.Timestamp.now(io, .awake).raw.nanoseconds;
        if (now_ns >= deadline_ns) return error.RequestTimeout;
        const remaining_ns = deadline_ns - now_ns;
        const remaining_ms = @divTrunc(remaining_ns + std.time.ns_per_ms - 1, std.time.ns_per_ms);
        const n = try readSocketChunk(
            stream.socket.handle,
            buffer[total..],
            @intCast(@min(remaining_ms, state.limits.io_timeout_ms)),
        );
        if (n == 0) return error.InvalidRequest;
        total += n;
        if (std.mem.indexOf(u8, buffer[0..total], "\r\n\r\n") != null) return total;
    }
    return error.RequestTooLarge;
}

fn readSocketChunk(handle: std.Io.net.Socket.Handle, buffer: []u8, timeout_ms: u32) !usize {
    var descriptor = [_]std.posix.pollfd{.{
        .fd = handle,
        .events = std.posix.POLL.IN,
        .revents = 0,
    }};
    const ready = try std.posix.poll(&descriptor, @intCast(timeout_ms));
    if (ready == 0) return error.RequestTimeout;
    return std.posix.read(handle, buffer) catch |err| switch (err) {
        error.WouldBlock => error.RequestTimeout,
        else => |e| e,
    };
}

fn forwardRequest(
    state: *State,
    io: std.Io,
    downstream: std.Io.net.Stream,
    inbound: *const ParsedInbound,
    initial_body: []const u8,
    raw: []const u8,
    downstream_started: *bool,
    deadline_ns: i128,
) !void {
    if (initial_body.len > inbound.content_length) return error.UnexpectedExtraRequestBytes;
    const uri_text = try std.fmt.allocPrint(state.allocator, "{s}{s}", .{ state.upstream_origin, inbound.target });
    defer state.allocator.free(uri_text);
    const uri = try std.Uri.parse(uri_text);
    var auth_header: ?[]u8 = null;
    defer if (auth_header) |value| wipeAndFree(state.allocator, value);
    var extra_headers: std.ArrayList(std.http.Header) = .empty;
    defer extra_headers.deinit(state.allocator);
    try extra_headers.appendSlice(state.allocator, inbound.forwarded_headers.items);
    var request_headers: std.http.Client.Request.Headers = .{
        .authorization = .omit,
        .user_agent = .omit,
        .connection = .{ .override = "close" },
        .accept_encoding = .omit,
        .content_type = .omit,
    };
    switch (state.provider) {
        .anthropic => try extra_headers.append(state.allocator, .{ .name = "x-api-key", .value = raw }),
        .openai => {
            auth_header = try std.fmt.allocPrint(state.allocator, "Bearer {s}", .{raw});
            request_headers.authorization = .{ .override = auth_header.? };
        },
    }
    var request = try state.http_client.request(inbound.method, uri, .{
        .keep_alive = false,
        .redirect_behavior = .unhandled,
        .headers = request_headers,
        .extra_headers = extra_headers.items,
    });
    defer request.deinit();
    var watchdog: UpstreamWatchdog = .{
        .io = io,
        .stream = request.connection.?.stream_reader.stream,
        .deadline_ns = deadline_ns,
    };
    const watchdog_thread = try std.Thread.spawn(.{}, UpstreamWatchdog.run, .{&watchdog});
    defer {
        watchdog.done.store(true, .release);
        watchdog_thread.join();
    }
    if (inbound.method.requestHasBody()) {
        request.transfer_encoding = .{ .content_length = inbound.content_length };
        var write_buffer: [16 * 1024]u8 = undefined;
        var body_writer = try request.sendBody(&write_buffer);
        try copyRequestBody(
            downstream,
            initial_body,
            inbound.content_length,
            state.limits.io_timeout_ms,
            &body_writer,
        );
        try body_writer.end();
    } else {
        if (inbound.content_length != 0) return error.BodyNotAllowed;
        try request.sendBodiless();
    }
    var response = try request.receiveHead(&.{});
    const status = response.head.status;
    const reason = try state.allocator.dupe(u8, response.head.reason);
    defer state.allocator.free(reason);
    const response_headers = try protocol.copyResponseHeaders(state.allocator, response.head, state.limits.response_head);
    defer protocol.freeHeaders(state.allocator, response_headers);
    const response_content_length = try protocol.boundedResponseContentLength(
        response.head.content_length,
        state.limits.response_body,
    );
    var downstream_buffer: [16 * 1024]u8 = undefined;
    var downstream_writer = downstream.writer(io, &downstream_buffer);
    const chunked = response_content_length == null;
    try protocol.writeResponseHead(
        &downstream_writer.interface,
        @intFromEnum(status),
        reason,
        response_headers,
        response_content_length,
        chunked,
    );
    downstream_started.* = true;
    var transfer_buffer: [16 * 1024]u8 = undefined;
    const reader = response.reader(&transfer_buffer);
    var chunk: [16 * 1024]u8 = undefined;
    var total: usize = 0;
    while (true) {
        var chunk_writer = std.Io.Writer.fixed(&chunk);
        const n = reader.stream(&chunk_writer, .limited(chunk.len)) catch |err| switch (err) {
            error.EndOfStream => break,
            else => |e| return e,
        };
        if (n == 0) return error.IncompleteResponse;
        if (n > state.limits.response_body -| total) return error.ResponseBodyTooLarge;
        total += n;
        if (chunked) try downstream_writer.interface.print("{x}\r\n", .{n});
        try downstream_writer.interface.writeAll(chunk_writer.buffered());
        if (chunked) try downstream_writer.interface.writeAll("\r\n");
        try downstream_writer.interface.flush();
    }
    if (chunked) {
        try downstream_writer.interface.writeAll("0\r\n\r\n");
        try downstream_writer.interface.flush();
    }
}

const UpstreamWatchdog = struct {
    io: std.Io,
    stream: std.Io.net.Stream,
    deadline_ns: i128,
    done: std.atomic.Value(bool) = .init(false),

    fn run(self: *UpstreamWatchdog) void {
        while (!self.done.load(.acquire)) {
            const now_ns = std.Io.Clock.Timestamp.now(self.io, .awake).raw.nanoseconds;
            if (now_ns >= self.deadline_ns) {
                self.stream.shutdown(self.io, .both) catch {};
                return;
            }
            std.Io.sleep(self.io, std.Io.Duration.fromNanoseconds(std.time.ns_per_ms), .awake) catch return;
        }
    }
};

fn copyRequestBody(
    downstream: std.Io.net.Stream,
    initial: []const u8,
    content_length: usize,
    timeout_ms: u32,
    upstream: *std.http.BodyWriter,
) !void {
    if (initial.len > content_length) return error.UnexpectedExtraRequestBytes;
    try upstream.writer.writeAll(initial);
    try upstream.flush();
    var remaining = content_length - initial.len;
    var chunk: [16 * 1024]u8 = undefined;
    while (remaining > 0) {
        const n = try readSocketChunk(downstream.socket.handle, chunk[0..@min(chunk.len, remaining)], timeout_ms);
        if (n == 0) return error.IncompleteBody;
        try upstream.writer.writeAll(chunk[0..n]);
        try upstream.flush();
        remaining -= n;
    }
}

fn writeError(io: std.Io, stream: std.Io.net.Stream, status: u16, reason: []const u8) !void {
    var buffer: [512]u8 = undefined;
    var writer = stream.writer(io, &buffer);
    try writer.interface.print(
        "HTTP/1.1 {d} {s}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        .{ status, reason },
    );
    try writer.interface.flush();
}
fn authorizationReason(err: session_secrets.AuthorizationError) []const u8 {
    return switch (err) {
        error.UnmintedPhantom => "unminted",
        error.WrongProvider => "wrong_provider",
        error.WrongName => "wrong_name",
        error.WrongHost => "wrong_host",
    };
}
fn wipeAndFree(allocator: std.mem.Allocator, bytes: []u8) void {
    std.crypto.secureZero(u8, bytes);
    allocator.rawFree(bytes, .of(u8), @returnAddress());
}
fn wake(io: std.Io, port: u16) void {
    const address = std.Io.net.IpAddress.parse("127.0.0.1", port) catch return;
    var stream = address.connect(io, .{ .mode = .stream }) catch return;
    stream.close(io);
}

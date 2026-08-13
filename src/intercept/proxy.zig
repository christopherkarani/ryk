const std = @import("std");
const builtin = @import("builtin");

const network = @import("ryk_core").policy.network_eval;
const core = @import("ryk_core").core;
const schema = @import("ryk_core").policy.schema;

pub const AuditEvent = struct {
    event_type: core.event.EventType,
    target: []u8,
    result: ?core.decision.DecisionResult = null,
    reason: ?[]u8 = null,
    ci_may_proceed: bool = false,

    pub fn deinit(self: AuditEvent, allocator: std.mem.Allocator) void {
        allocator.free(self.target);
        if (self.reason) |reason| allocator.free(reason);
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

    /// True when the accept-loop thread has been started (M-5).
    pub fn isServing(self: Runtime) bool {
        return self.state.serving.load(.acquire);
    }

    pub fn isHealthy(self: Runtime) bool {
        if (!self.state.serving.load(.acquire)) return true;
        return !self.state.stop.load(.acquire) and !self.state.failed.load(.acquire);
    }

    pub fn failed(self: Runtime) bool {
        return self.state.failed.load(.acquire);
    }

    /// Start the accept-loop thread. Safe to call once after `listen`.
    /// Call after sandboxed agent fork so Seatbelt `sandbox_init` is not
    /// raced with a multi-threaded parent (M-5).
    pub fn startServing(self: *Runtime) !void {
        if (comptime builtin.os.tag == .windows) return error.ProxyUnsupportedOnWindows;
        if (self.state.serving.swap(true, .acq_rel)) return;
        self.state.thread = try std.Thread.spawn(.{}, serverLoop, .{self.state});
        self.state.thread_started = true;
    }

    pub fn waitForIdle(self: Runtime, timeout_ns: u64) !void {
        var threaded: std.Io.Threaded = .init_single_threaded;
        const io = threaded.io();
        const started = std.Io.Clock.Timestamp.now(io, .awake);
        while (self.state.active_connections.load(.acquire) > 0) {
            const elapsed = started.durationFromNow(io).raw.nanoseconds;
            if (elapsed > timeout_ns) return error.ProxyConnectionsActive;
            const duration = std.Io.Duration.fromNanoseconds(10 * std.time.ns_per_ms);
            std.Io.sleep(io, duration, .awake) catch {};
        }
    }

    pub fn snapshotAuditEvents(self: Runtime, allocator: std.mem.Allocator) ![]AuditEvent {
        const io = self.state.threaded.io();
        try self.state.audit_mutex.lock(io);
        defer self.state.audit_mutex.unlock(io);
        const out = try allocator.alloc(AuditEvent, self.state.audit_events.items.len);
        var copied: usize = 0;
        errdefer {
            for (out[0..copied]) |ev| ev.deinit(allocator);
            allocator.free(out);
        }
        for (self.state.audit_events.items, 0..) |ev, index| {
            const target = try allocator.dupe(u8, ev.target);
            errdefer allocator.free(target);
            const reason = if (ev.reason) |value| try allocator.dupe(u8, value) else null;
            errdefer if (reason) |value| allocator.free(value);
            out[index] = .{
                .event_type = ev.event_type,
                .target = target,
                .result = ev.result,
                .reason = reason,
                .ci_may_proceed = ev.ci_may_proceed,
            };
            copied += 1;
        }
        return out;
    }

    pub fn freeAuditEvents(_: Runtime, allocator: std.mem.Allocator, events: []AuditEvent) void {
        for (events) |ev| ev.deinit(allocator);
        allocator.free(events);
    }

    pub fn deinit(self: *Runtime) void {
        const io = self.state.threaded.io();
        self.state.stop.store(true, .release);
        wake(io, self.state.bind_port);
        if (self.state.thread_started) {
            self.state.thread.join();
        }
        // Force-shutdown active client FDs so tunnel/readHeaders workers observe
        // HUP/ERR and drain without waiting tunnel_idle_ms (agent-grade quiet
        // budget, not a deinit drain valve). Never free State while workers
        // still hold *State (M-6 free-before-join).
        self.state.shutdownConnections(io);
        const idle_budget_ns: u64 = 8 * std.time.ns_per_s;
        var server_closed = false;
        self.waitForIdle(idle_budget_ns) catch {
            // Force-close the accept socket, then wait once more so half-open
            // workers can observe peer close before reclaim.
            self.state.server.deinit(io);
            server_closed = true;
            self.state.shutdownConnections(io);
            self.waitForIdle(idle_budget_ns) catch {};
        };
        if (!server_closed) {
            self.state.server.deinit(io);
        }
        // Bound reclaim: force-shutdown client + upstream FDs, then wait a hard budget.
        // Mid-dial cannot use ConnectOptions.timeout on Zig 0.16 (TODO panic).
        const hard_reclaim_ns: u64 = 5 * std.time.ns_per_s;
        const reclaim_started = std.Io.Clock.Timestamp.now(io, .awake);
        while (self.state.active_connections.load(.acquire) > 0) {
            const elapsed: u64 = @intCast(@max(reclaim_started.durationFromNow(io).raw.nanoseconds, 0));
            if (elapsed > hard_reclaim_ns) break;
            self.state.shutdownConnections(io);
            const duration = std.Io.Duration.fromNanoseconds(10 * std.time.ns_per_ms);
            std.Io.sleep(io, duration, .awake) catch {};
        }
        // Prefer intentional State leak over free-while-workers-hold-*State (UAF).
        // Workers still mid-dial after the budget keep State alive until they exit.
        if (self.state.active_connections.load(.acquire) > 0) {
            self.* = undefined;
            return;
        }
        for (self.state.audit_events.items) |ev| ev.deinit(self.state.allocator);
        self.state.audit_events.deinit(self.state.allocator);
        self.state.active_streams.deinit(self.state.allocator);
        self.state.active_upstreams.deinit(self.state.allocator);
        self.state.allocator.free(self.state.bind_url);
        self.state.allocator.destroy(self.state);
        self.* = undefined;
    }
};

/// Quiet-gap idle before `fn tunnel` exits. Agent-grade (LLM think/stream pauses);
/// was historically 3s (deinit drain shaped) which killed quiet CONNECT streams.
/// On `Runtime.deinit` / stop, active client FDs are force-shutdown so reclaim does
/// not wait this full budget.
const tunnel_idle_ms: usize = 300_000;

const State = struct {
    allocator: std.mem.Allocator,
    server: std.Io.net.Server,
    bind_port: u16,
    bind_url: []u8,
    selected_policy: *const schema.Policy,
    effective_mode: schema.Mode,
    stop: std.atomic.Value(bool) = .init(false),
    failed: std.atomic.Value(bool) = .init(false),
    serving: std.atomic.Value(bool) = .init(false),
    active_connections: std.atomic.Value(usize) = .init(0),
    connections_mutex: std.Io.Mutex = .init,
    active_streams: std.ArrayList(std.Io.net.Stream) = .empty,
    /// Upstream ends (CONNECT/HTTP forward) so deinit force-close is not client-only.
    active_upstreams: std.ArrayList(std.Io.net.Stream) = .empty,
    audit_mutex: std.Io.Mutex = .init,
    audit_events: std.ArrayList(AuditEvent) = .empty,
    threaded: std.Io.Threaded = undefined,
    thread: std.Thread = undefined,
    thread_started: bool = false,
    /// DNS resolution seam (P1-6 tests inject fixed answers; production uses
    /// `defaultLookup`). Resolved answers are fenced before connect.
    lookup_fn: LookupFn = defaultLookup,
    lookup_context: ?*anyopaque = null,

    fn record(self: *State, event_type: core.event.EventType, target: []const u8, maybe_decision: ?core.decision.Decision) !void {
        const owned_target = try self.allocator.dupe(u8, target);
        errdefer self.allocator.free(owned_target);
        const owned_reason = if (maybe_decision) |decision| try self.allocator.dupe(u8, decision.reason) else null;
        errdefer if (owned_reason) |reason| self.allocator.free(reason);
        const io = self.threaded.io();
        try self.audit_mutex.lock(io);
        defer self.audit_mutex.unlock(io);
        try self.audit_events.append(self.allocator, .{
            .event_type = event_type,
            .target = owned_target,
            .result = if (maybe_decision) |decision| decision.result else null,
            .reason = owned_reason,
            .ci_may_proceed = if (maybe_decision) |decision| decision.ci_may_proceed else true,
        });
    }

    fn registerConnection(self: *State, io: std.Io, stream: std.Io.net.Stream) !void {
        self.connections_mutex.lockUncancelable(io);
        defer self.connections_mutex.unlock(io);
        try self.active_streams.append(self.allocator, stream);
    }

    fn unregisterConnection(self: *State, io: std.Io, handle: std.Io.net.Socket.Handle) void {
        // Uncancelable: silent cancel/skip leaves closed FDs in the force-shutdown list
        // (recycled-FD SHUT_RDWR risk after accept reuses the number).
        self.connections_mutex.lockUncancelable(io);
        defer self.connections_mutex.unlock(io);
        for (self.active_streams.items, 0..) |stream, index| {
            if (stream.socket.handle != handle) continue;
            _ = self.active_streams.swapRemove(index);
            return;
        }
    }

    fn registerUpstream(self: *State, io: std.Io, stream: std.Io.net.Stream) !void {
        self.connections_mutex.lockUncancelable(io);
        defer self.connections_mutex.unlock(io);
        try self.active_upstreams.append(self.allocator, stream);
    }

    fn unregisterUpstream(self: *State, io: std.Io, handle: std.Io.net.Socket.Handle) void {
        self.connections_mutex.lockUncancelable(io);
        defer self.connections_mutex.unlock(io);
        for (self.active_upstreams.items, 0..) |stream, index| {
            if (stream.socket.handle != handle) continue;
            _ = self.active_upstreams.swapRemove(index);
            return;
        }
    }

    fn shutdownConnections(self: *State, io: std.Io) void {
        self.connections_mutex.lockUncancelable(io);
        defer self.connections_mutex.unlock(io);
        for (self.active_streams.items) |stream| {
            stream.shutdown(io, .both) catch {};
        }
        for (self.active_upstreams.items) |stream| {
            stream.shutdown(io, .both) catch {};
        }
    }
};

const ParsedRequest = struct {
    method: []const u8,
    target: []const u8,
    version: []const u8,
    host: []const u8,
    port: ?u16,
    path: []const u8,
    destination: []const u8,
    https_connect: bool,
    headers_end: usize,
};

/// Bind the proxy listener without starting the accept-loop thread (M-5).
/// Returns a Runtime that can inject bind URL into the agent env while the
/// parent stays single-threaded for sandboxed fork. Call `startServing` after
/// the agent child has been forked (or use `start` for the legacy all-in-one path).
pub fn listen(
    allocator: std.mem.Allocator,
    selected_policy: *const schema.Policy,
    effective_mode: schema.Mode,
) !Runtime {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    // Production mediation listener: no SO_REUSEADDR/SO_REUSEPORT. Ephemeral
    // ports do not need rebind, and reuse would enable MitM rebind after proxy
    // death on a route-forced fixed port (M-7). Test-only upstream helpers may
    // still set reuse_address = true.
    var server = try address.listen(io, .{ .reuse_address = false });
    errdefer server.deinit(io);
    // Defense-in-depth: explicit FD_CLOEXEC before sandboxed agent fork (M-4).
    // Zig's netListenIp usually applies SOCK_CLOEXEC already; fail closed if we
    // cannot set the flag. Child fd scrub remains the keep-set close path.
    try setServerSocketCloexec(server.socket.handle);
    const port = server.socket.address.getPort();
    const bind_url = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}", .{port});
    errdefer allocator.free(bind_url);

    const state = try allocator.create(State);
    errdefer allocator.destroy(state);
    state.* = .{
        .allocator = allocator,
        .server = server,
        .bind_port = port,
        .bind_url = bind_url,
        .selected_policy = selected_policy,
        .effective_mode = effective_mode,
        .threaded = threaded,
    };
    return .{ .state = state };
}

/// Set FD_CLOEXEC on the proxy listen socket when the platform supports fcntl.
/// Fail closed on fcntl error so a non-CLOEXEC listen FD cannot leak into the
/// agent child if scrub misses a FD under pressure.
fn setServerSocketCloexec(handle: std.Io.net.Socket.Handle) !void {
    switch (@import("builtin").os.tag) {
        .windows, .wasi => {},
        else => {
            if (std.c.fcntl(handle, std.c.F.SETFD, @as(c_int, std.c.FD_CLOEXEC)) == -1)
                return error.Unexpected;
        },
    }
}

/// Bind and immediately start the accept-loop thread (legacy / tests).
pub fn start(
    allocator: std.mem.Allocator,
    selected_policy: *const schema.Policy,
    effective_mode: schema.Mode,
) !Runtime {
    var runtime = try listen(allocator, selected_policy, effective_mode);
    errdefer runtime.deinit();
    try runtime.startServing();
    return runtime;
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

const ConnectionContext = struct {
    state: *State,
    client: std.Io.net.Stream,
};

fn connectionLoop(context: *ConnectionContext) void {
    const state = context.state;
    const io = state.threaded.io();
    // M-1: cache allocator before fetchSub. Runtime.deinit reclaims State as
    // soon as active_connections hits 0; touching *State after the last
    // worker's fetchSub is free-before-join UAF.
    // Unregister + close client here (not in handleConnection) so deinit's
    // force-shutdown list stays accurate until the worker is done with the FD.
    defer {
        const allocator = context.state.allocator;
        context.state.unregisterConnection(io, context.client.socket.handle);
        context.client.close(io);
        _ = context.state.active_connections.fetchSub(1, .acq_rel);
        // Last *State touch was fetchSub; free ConnectionContext only.
        allocator.destroy(context);
    }
    handleConnection(state, io, context.client) catch {};
}

fn handleConnection(state: *State, io: std.Io, client: std.Io.net.Stream) !void {
    var buffer: [64 * 1024]u8 = undefined;
    const read_len = try readHeaders(io, client, &buffer);
    if (read_len == 0) return;
    const request = try parseRequest(buffer[0..read_len]);
    var decision = try network.evaluate(state.allocator, state.selected_policy, state.effective_mode, request.destination, .{
        .enforcement_mode = .proxy_mediated,
        .ci_mode = state.effective_mode == .ci,
        .method = if (request.https_connect) null else request.method,
    });
    defer decision.deinit(state.allocator);
    state.record(.network_connect_attempt, decision.redacted_target, null) catch {};

    // RT-03 F-audit: annotate-only — emit exfil findings even when allow.
    // Visible surfaces only: CONNECT is host:port; cleartext absolute-form may
    // include path/query. Not body, headers, or TLS payload. Flushed end-of-run
    // via Runtime.snapshotAuditEvents (not mid-CONNECT live stream).
    if (decision.exfil_findings.len > 0) {
        state.record(.network_exfiltration_suspected, decision.redacted_target, decision.decision) catch {};
    }

    if (!(decision.decision.result == .allow or decision.decision.result == .observe)) {
        state.record(.network_connect_denied, decision.redacted_target, decision.decision) catch {};
        try writeProxyError(io, client, 403, "Forbidden");
        return;
    }
    state.record(.network_connect_allowed, decision.redacted_target, decision.decision) catch {};

    if (request.https_connect) {
        try (tunnelConnect(state, io, client, request.host, request.port orelse 443) catch |err|
            writeForbiddenIfResolvedAddressDenied(err, io, client));
        return;
    }
    try (forwardHttp(state, io, client, request, buffer[0..read_len]) catch |err|
        writeForbiddenIfResolvedAddressDenied(err, io, client));
}

/// Post-resolution fence (P1-6): a rebinding deny answers 403 like a policy
/// deny instead of silently dropping the client connection.
fn writeForbiddenIfResolvedAddressDenied(err: anyerror, io: std.Io, client: std.Io.net.Stream) !void {
    if (err == error.ResolvedAddressDenied) return writeProxyError(io, client, 403, "Forbidden");
    return err;
}

fn readHeaders(io: std.Io, stream: std.Io.net.Stream, buffer: []u8) !usize {
    var total: usize = 0;
    const started = std.Io.Clock.Timestamp.now(io, .awake);
    const deadline_ns: i96 = 5 * std.time.ns_per_s;
    while (total < buffer.len and started.durationFromNow(io).raw.nanoseconds < deadline_ns) {
        var fds = [_]std.posix.pollfd{.{
            .fd = stream.socket.handle,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        const ready = std.posix.poll(&fds, 100) catch break;
        if (ready == 0) continue;
        const n = std.posix.read(stream.socket.handle, buffer[total..]) catch |err| switch (err) {
            error.WouldBlock => continue,
            else => return err,
        };
        if (n == 0) return if (total == 0) error.InvalidProxyRequest else total;
        total += n;
        if (std.mem.indexOf(u8, buffer[0..total], "\r\n\r\n") != null) return total;
    }
    return if (total == 0) error.InvalidProxyRequest else error.RequestTooLarge;
}

pub fn parseRequest(bytes: []const u8) !ParsedRequest {
    const headers_end = (std.mem.indexOf(u8, bytes, "\r\n\r\n") orelse return error.InvalidProxyRequest) + 4;
    const line_end = std.mem.indexOf(u8, bytes, "\r\n") orelse return error.InvalidProxyRequest;
    const line = bytes[0..line_end];
    var parts = std.mem.splitScalar(u8, line, ' ');
    const method = parts.next() orelse return error.InvalidProxyRequest;
    const target = parts.next() orelse return error.InvalidProxyRequest;
    const version = parts.next() orelse return error.InvalidProxyRequest;
    if (std.ascii.eqlIgnoreCase(method, "CONNECT")) {
        const parsed = try parseAuthority(target, 443);
        return .{
            .method = method,
            .target = target,
            .version = version,
            .host = parsed.host,
            .port = parsed.port,
            .path = "",
            .destination = target,
            .https_connect = true,
            .headers_end = headers_end,
        };
    }

    const host_header = headerValue(bytes[0 .. headers_end - 4], "host") orelse return error.InvalidProxyRequest;
    const parsed_host = try parseAuthority(host_header, 80);
    // Dial authority must match the authority used for network.evaluate (M-9/M-8).
    // Absolute-form (://) and scheme-less authority-in-target both embed a
    // destination host: TCP must use that host/port, not a diverging Host
    // header (SSRF via evaluate-target vs dial-Host mismatch).
    var dial_host = parsed_host.host;
    var dial_port = parsed_host.port;
    var path = target;
    // Origin-form starts with '/' (or is empty/*); anything else may embed a host.
    const target_embeds_authority = blk: {
        if (std.mem.indexOf(u8, target, "://") != null) break :blk true;
        if (target.len == 0 or target[0] == '/' or target[0] == '*') break :blk false;
        break :blk true;
    };
    if (target_embeds_authority) {
        const parsed_destination = try network.parseDestination(target);
        path = if (parsed_destination.path.len == 0) "/" else parsed_destination.path;
        const scheme = parsed_destination.scheme orelse "http";
        const default_port: u16 = if (std.ascii.eqlIgnoreCase(scheme, "https")) 443 else 80;
        dial_host = parsed_destination.host;
        dial_port = parsed_destination.port orelse default_port;
        // Reject dual-authority: Host host must equal request-target host.
        if (!std.ascii.eqlIgnoreCase(parsed_host.host, dial_host)) return error.InvalidProxyRequest;
    } else {
        path = if (target.len == 0) "/" else target;
    }
    return .{
        .method = method,
        .target = target,
        .version = version,
        .host = dial_host,
        .port = dial_port,
        .path = path,
        .destination = target,
        .https_connect = false,
        .headers_end = headers_end,
    };
}

/// DNS resolution seam: resolves `host` to up to `out.len` addresses and
/// returns the count. Tests inject fixed answers to exercise the rebind fence
/// hermetically; production resolves via `HostName.lookup`.
const LookupFn = *const fn (context: ?*anyopaque, io: std.Io, host: []const u8, port: u16, out: []std.Io.net.IpAddress) anyerror!usize;

fn defaultLookup(context: ?*anyopaque, io: std.Io, host: []const u8, port: u16, out: []std.Io.net.IpAddress) !usize {
    _ = context;
    const hostname = try std.Io.net.HostName.init(host);
    var lookup_buffer: [32]std.Io.net.HostName.LookupResult = undefined;
    var lookup_queue: std.Io.Queue(std.Io.net.HostName.LookupResult) = .init(&lookup_buffer);
    var lookup_future = io.async(std.Io.net.HostName.lookup, .{ hostname, io, &lookup_queue, .{ .port = port } });
    defer lookup_future.cancel(io) catch {};

    var count: usize = 0;
    while (lookup_queue.getOne(io)) |result| {
        switch (result) {
            .address => |address| {
                if (count < out.len) {
                    out[count] = address;
                    count += 1;
                }
            },
            .canonical_name => {},
        }
    } else |err| switch (err) {
        error.Canceled => return error.Canceled,
        // Queue closed: lookup finished. Propagate a lookup failure, else keep
        // the addresses collected so far.
        error.Closed => try lookup_future.await(io),
    }
    return count;
}

/// Dial upstream by IP literal or DNS hostname.
/// Zig 0.16 `IpAddress.resolve` only parses IP text (not DNS). Hostnames resolve
/// through `state.lookup_fn`, then every answer passes the post-resolution fence
/// (`network.resolvedAddressFence`, P1-6): loopback / private / link-local /
/// cloud-metadata answers are skipped unless policy explicitly allows the class,
/// and the connection pins the first validated address — no re-resolution
/// between check and connect (TOCTOU). When every answer is fenced, the attempt
/// is denied and audited (`network_connect_denied`) as a rebinding shape.
///
/// Honors Runtime stop before dial. Zig 0.16 Threaded `netConnectIp` panics if
/// `ConnectOptions.timeout != .none`, so dials are not OS-timeout bound here;
/// `Runtime.deinit` force-closes client+upstream FDs and uses a hard reclaim budget
/// so teardown cannot hang forever on blackhole mid-dial workers.
fn connectUpstream(state: *State, io: std.Io, host: []const u8, port: u16) !std.Io.net.Stream {
    if (state.stop.load(.acquire)) return error.ProxyStopped;
    // Never pass ConnectOptions.timeout — Threaded backend panics (Zig 0.16 TODO).
    if (std.Io.net.IpAddress.parse(host, port)) |address| {
        // IP literals were policy-evaluated as the destination itself.
        return address.connect(io, .{ .mode = .stream });
    } else |_| {}

    var addresses: [32]std.Io.net.IpAddress = undefined;
    const count = try state.lookup_fn(state.lookup_context, io, host, port, &addresses);
    if (count == 0) return error.UnknownHostName;

    var connect_err: ?anyerror = null;
    var fenced: ?network.ResolvedAddressFence = null;
    for (addresses[0..count]) |address| {
        const fence = network.resolvedAddressFence(state.selected_policy, address, port);
        if (!fence.allowed) {
            fenced = fence;
            continue;
        }
        return address.connect(io, .{ .mode = .stream }) catch |err| {
            connect_err = err;
            continue;
        };
    }
    if (connect_err == null and fenced != null) {
        var reason_buf: [192]u8 = undefined;
        const reason = std.fmt.bufPrint(
            &reason_buf,
            "resolved to {s} address denied by network policy (possible DNS rebinding)",
            .{@tagName(fenced.?.host_class)},
        ) catch "resolved address denied by network policy";
        state.record(.network_connect_denied, host, .{
            .result = .deny,
            .reason = reason,
            .ci_may_proceed = false,
        }) catch {};
        return error.ResolvedAddressDenied;
    }
    return connect_err orelse error.UnknownHostName;
}

fn forwardHttp(
    state: *State,
    io: std.Io,
    client: std.Io.net.Stream,
    request: ParsedRequest,
    first_read: []const u8,
) !void {
    if (state.stop.load(.acquire)) return error.ProxyStopped;
    var upstream = try connectUpstream(state, io, request.host, request.port orelse 80);
    // Register before tunnel so deinit force-closes blackholed upstream ends.
    state.registerUpstream(io, upstream) catch {
        upstream.close(io);
        return error.OutOfMemory;
    };
    defer {
        state.unregisterUpstream(io, upstream.socket.handle);
        upstream.close(io);
    }
    var upstream_buf: [64 * 1024]u8 = undefined;
    var upstream_writer = upstream.writer(io, &upstream_buf);
    if (std.mem.indexOf(u8, request.target, "://")) |_| {
        const rewritten = try rewriteAbsoluteRequest(state.allocator, request, first_read);
        defer state.allocator.free(rewritten);
        try upstream_writer.interface.writeAll(rewritten);
    } else {
        try upstream_writer.interface.writeAll(first_read);
    }
    try upstream_writer.interface.flush();
    try tunnel(io, client, upstream, &state.stop);
}

fn tunnelConnect(
    state: *State,
    io: std.Io,
    client: std.Io.net.Stream,
    host: []const u8,
    port: u16,
) !void {
    if (state.stop.load(.acquire)) return error.ProxyStopped;
    var upstream = try connectUpstream(state, io, host, port);
    state.registerUpstream(io, upstream) catch {
        upstream.close(io);
        return error.OutOfMemory;
    };
    defer {
        state.unregisterUpstream(io, upstream.socket.handle);
        upstream.close(io);
    }
    var client_buf: [256]u8 = undefined;
    var client_writer = client.writer(io, &client_buf);
    try client_writer.interface.writeAll("HTTP/1.1 200 Connection Established\r\nProxy-Agent: ryk\r\n\r\n");
    try client_writer.interface.flush();
    try tunnel(io, client, upstream, &state.stop);
}

/// Bidirectional byte relay for CONNECT and HTTP forward (shared path).
/// Exits on peer EOF/HUP/ERR, Runtime stop, or quiet idle ≥ tunnel_idle_ms.
fn tunnel(io: std.Io, a: std.Io.net.Stream, b: std.Io.net.Stream, stop: *const std.atomic.Value(bool)) !void {
    var fds = [_]std.posix.pollfd{
        .{ .fd = a.socket.handle, .events = std.posix.POLL.IN, .revents = 0 },
        .{ .fd = b.socket.handle, .events = std.posix.POLL.IN, .revents = 0 },
    };
    var buf: [16 * 1024]u8 = undefined;
    var b_buf: [16 * 1024]u8 = undefined;
    var a_buf: [16 * 1024]u8 = undefined;
    var b_writer = b.writer(io, &b_buf);
    var a_writer = a.writer(io, &a_buf);
    var idle_ms: usize = 0;
    while (true) {
        if (stop.load(.acquire)) return;
        const ready = try std.posix.poll(&fds, 200);
        if (ready == 0) {
            idle_ms += 200;
            if (idle_ms >= tunnel_idle_ms) return;
            continue;
        }
        idle_ms = 0;
        if ((fds[0].revents & std.posix.POLL.IN) != 0) {
            const n = std.posix.read(a.socket.handle, &buf) catch |err| switch (err) {
                error.WouldBlock => continue,
                else => return err,
            };
            if (n == 0) return;
            try b_writer.interface.writeAll(buf[0..n]);
            try b_writer.interface.flush();
        }
        if ((fds[1].revents & std.posix.POLL.IN) != 0) {
            const n = std.posix.read(b.socket.handle, &buf) catch |err| switch (err) {
                error.WouldBlock => continue,
                else => return err,
            };
            if (n == 0) return;
            try a_writer.interface.writeAll(buf[0..n]);
            try a_writer.interface.flush();
        }
        if ((fds[0].revents & (std.posix.POLL.HUP | std.posix.POLL.ERR)) != 0) return;
        if ((fds[1].revents & (std.posix.POLL.HUP | std.posix.POLL.ERR)) != 0) return;
        fds[0].revents = 0;
        fds[1].revents = 0;
    }
}

fn rewriteAbsoluteRequest(allocator: std.mem.Allocator, request: ParsedRequest, first_read: []const u8) ![]u8 {
    const line_end = std.mem.indexOf(u8, first_read, "\r\n") orelse return error.InvalidProxyRequest;
    var out_aw: std.Io.Writer.Allocating = .init(allocator);
    errdefer out_aw.deinit();
    try out_aw.writer.print("{s} {s} {s}\r\n", .{ request.method, request.path, request.version });
    try out_aw.writer.writeAll(first_read[line_end + 2 ..]);
    try out_aw.writer.flush();
    return try out_aw.toOwnedSlice();
}

fn writeProxyError(io: std.Io, stream: std.Io.net.Stream, code: u16, label: []const u8) !void {
    var body_buf: [128]u8 = undefined;
    const body = try std.fmt.bufPrint(&body_buf, "{s}\n", .{label});
    var header_buf: [256]u8 = undefined;
    const header = try std.fmt.bufPrint(&header_buf, "HTTP/1.1 {d} {s}\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{ code, label, body.len });
    var stream_buf: [512]u8 = undefined;
    var stream_writer = stream.writer(io, &stream_buf);
    try stream_writer.interface.writeAll(header);
    try stream_writer.interface.writeAll(body);
    try stream_writer.interface.flush();
}

fn headerValue(headers: []const u8, wanted: []const u8) ?[]const u8 {
    var lines = std.mem.splitSequence(u8, headers, "\r\n");
    _ = lines.next();
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = std.mem.trim(u8, line[0..colon], " \t");
        if (!std.ascii.eqlIgnoreCase(name, wanted)) continue;
        return std.mem.trim(u8, line[colon + 1 ..], " \t");
    }
    return null;
}

const Authority = struct {
    host: []const u8,
    port: ?u16,
};

fn parseAuthority(raw: []const u8, default_port: u16) !Authority {
    var value = std.mem.trim(u8, raw, " \t\r\n");
    if (value.len == 0) return error.InvalidProxyRequest;
    if (std.mem.indexOfScalar(u8, value, '@')) |at| value = value[at + 1 ..];
    if (value[0] == '[') {
        const close = std.mem.indexOfScalar(u8, value, ']') orelse return error.InvalidProxyRequest;
        const host = value[1..close];
        if (value.len > close + 1) {
            if (value[close + 1] != ':') return error.InvalidProxyRequest;
            return .{ .host = host, .port = try parsePort(value[close + 2 ..]) };
        }
        return .{ .host = host, .port = default_port };
    }
    if (std.mem.lastIndexOfScalar(u8, value, ':')) |colon| {
        if (std.mem.indexOfScalar(u8, value[0..colon], ':') == null) {
            return .{ .host = value[0..colon], .port = try parsePort(value[colon + 1 ..]) };
        }
    }
    return .{ .host = value, .port = default_port };
}

fn parsePort(value: []const u8) !u16 {
    if (value.len == 0) return error.InvalidProxyRequest;
    return std.fmt.parseInt(u16, value, 10) catch return error.InvalidProxyRequest;
}

fn wake(io: std.Io, port: u16) void {
    const address = std.Io.net.IpAddress.parse("127.0.0.1", port) catch return;
    var stream = address.connect(io, .{ .mode = .stream }) catch return;
    stream.close(io);
}

test "proxy parses HTTP requests with method and path visibility" {
    const request =
        "POST http://api.github.com/repos/acme/app/issues HTTP/1.1\r\nHost: api.github.com\r\n\r\n";
    const parsed = try parseRequest(request);
    try std.testing.expect(!parsed.https_connect);
    try std.testing.expectEqualStrings("POST", parsed.method);
    try std.testing.expectEqualStrings("api.github.com", parsed.host);
    try std.testing.expectEqual(@as(?u16, 80), parsed.port);
    try std.testing.expectEqualStrings("/repos/acme/app/issues", parsed.path);
    try std.testing.expectEqualStrings("http://api.github.com/repos/acme/app/issues", parsed.destination);
}

test "proxy parses HTTPS CONNECT as host-port only" {
    const request = "CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\n\r\n";
    const parsed = try parseRequest(request);
    try std.testing.expect(parsed.https_connect);
    try std.testing.expectEqualStrings("CONNECT", parsed.method);
    try std.testing.expectEqualStrings("api.github.com", parsed.host);
    try std.testing.expectEqual(@as(?u16, 443), parsed.port);
    try std.testing.expectEqualStrings("", parsed.path);
    try std.testing.expectEqualStrings("api.github.com:443", parsed.destination);
}

test "proxy absolute-form dial host comes from URL not Host header" {
    // Matching Host (default port) still dials absolute-form port when present.
    const matched =
        "GET http://api.github.com:8080/repos/acme/app HTTP/1.1\r\nHost: api.github.com\r\n\r\n";
    const parsed = try parseRequest(matched);
    try std.testing.expectEqualStrings("api.github.com", parsed.host);
    try std.testing.expectEqual(@as(?u16, 8080), parsed.port);
    try std.testing.expectEqualStrings("http://api.github.com:8080/repos/acme/app", parsed.destination);

    // Host pointing at metadata / evil host must not become the dial authority.
    const mismatched =
        "GET http://api.github.com/repos/acme/app HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n";
    try std.testing.expectError(error.InvalidProxyRequest, parseRequest(mismatched));
}

test "proxy scheme-less request-target Host pivot is rejected" {
    // M-8: without "://", evaluate would parse destination from the request-target
    // while dial used Host — reject dual-authority (metadata Host pivot).
    const mismatched =
        "GET api.github.com/repos/acme/app HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n";
    try std.testing.expectError(error.InvalidProxyRequest, parseRequest(mismatched));

    // Matching Host still dials the request-target authority and exposes path.
    const matched =
        "GET api.github.com:8080/repos/acme/app HTTP/1.1\r\nHost: api.github.com\r\n\r\n";
    const parsed = try parseRequest(matched);
    try std.testing.expectEqualStrings("api.github.com", parsed.host);
    try std.testing.expectEqual(@as(?u16, 8080), parsed.port);
    try std.testing.expectEqualStrings("/repos/acme/app", parsed.path);
    try std.testing.expectEqualStrings("api.github.com:8080/repos/acme/app", parsed.destination);

    // Origin-form path-only remains Host-dialed (no embedded authority).
    const origin =
        "GET /repos/acme/app HTTP/1.1\r\nHost: api.github.com\r\n\r\n";
    const origin_parsed = try parseRequest(origin);
    try std.testing.expectEqualStrings("api.github.com", origin_parsed.host);
    try std.testing.expectEqual(@as(?u16, 80), origin_parsed.port);
    try std.testing.expectEqualStrings("/repos/acme/app", origin_parsed.path);
    try std.testing.expectEqualStrings("/repos/acme/app", origin_parsed.destination);
}

test "proxy forwards delayed HTTP request bodies and records request audit events" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;

    var loaded = try @import("ryk_core").policy.load.parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: observe
        \\network:
        \\  mode: open
        \\  backend: proxy
    , "proxy-test.yaml");
    defer loaded.deinit();

    const io = std.testing.io;
    const upstream_address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var upstream = try upstream_address.listen(io, .{ .reuse_address = true });
    defer upstream.deinit(io);
    const upstream_port = upstream.socket.address.getPort();
    var upstream_state: TestHttpServerState = .{ .server = &upstream, .io = io, .expected_body = "delayed-body" };
    const upstream_thread = try std.Thread.spawn(.{}, testHttpServer, .{&upstream_state});
    defer upstream_thread.join();
    std.Io.sleep(io, std.Io.Duration.fromNanoseconds(50 * std.time.ns_per_ms), .awake) catch {};

    var runtime = try start(std.testing.allocator, &loaded, .observe);
    defer runtime.deinit();
    std.Io.sleep(io, std.Io.Duration.fromNanoseconds(50 * std.time.ns_per_ms), .awake) catch {};
    const proxy_port = try bindPort(runtime.bindUrl());
    const proxy_addr = try std.Io.net.IpAddress.parse("127.0.0.1", proxy_port);
    var client = try std.Io.net.IpAddress.connect(&proxy_addr, io, .{ .mode = .stream });
    defer client.close(io);
    var request_buf: [256]u8 = undefined;
    const head = try std.fmt.bufPrint(
        &request_buf,
        "POST http://127.0.0.1:{d}/echo HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nContent-Length: 12\r\nConnection: close\r\n\r\n",
        .{ upstream_port, upstream_port },
    );
    var client_write_buf: [512]u8 = undefined;
    var client_writer = client.writer(io, &client_write_buf);
    try client_writer.interface.writeAll(head);
    try client_writer.interface.flush();
    std.Io.sleep(io, std.Io.Duration.fromNanoseconds(250 * std.time.ns_per_ms), .awake) catch {};
    try client_writer.interface.writeAll("delayed-body");
    try client_writer.interface.flush();

    var response_buf: [512]u8 = undefined;
    const response_len = try readHttpResponse(io, client, &response_buf);
    try std.testing.expect(std.mem.indexOf(u8, response_buf[0..response_len], "200 OK") != null);
    try std.testing.expect(std.mem.indexOf(u8, response_buf[0..response_len], "proxied") != null);

    try runtime.waitForIdle(2 * std.time.ns_per_s);
    const events = try runtime.snapshotAuditEvents(std.testing.allocator);
    defer runtime.freeAuditEvents(std.testing.allocator, events);
    try std.testing.expect(events.len >= 2);
    try std.testing.expectEqual(@import("ryk_core").core.event.EventType.network_connect_attempt, events[0].event_type);
    try std.testing.expectEqual(@import("ryk_core").core.event.EventType.network_connect_allowed, events[1].event_type);
    try std.testing.expect(std.mem.indexOf(u8, events[0].target, "127.0.0.1") != null);
}

test "proxy denies controlled HTTP endpoint before upstream connect" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;

    const io = std.testing.io;
    const upstream_address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var upstream = try upstream_address.listen(io, .{ .reuse_address = true });
    defer upstream.deinit(io);
    const upstream_port = upstream.socket.address.getPort();

    const policy_text = try std.fmt.allocPrint(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\network:
        \\  mode: open
        \\  backend: proxy
        \\  deny:
        \\    - "127.0.0.1:{d}"
    , .{upstream_port});
    defer std.testing.allocator.free(policy_text);
    var loaded = try @import("ryk_core").policy.load.parseFromSlice(std.testing.allocator, policy_text, "proxy-http-deny.yaml");
    defer loaded.deinit();

    var upstream_state: TestDenyServerState = .{ .server = &upstream, .io = io };
    const upstream_thread = try std.Thread.spawn(.{}, testDenyServerNoConnect, .{&upstream_state});
    defer upstream_thread.join();

    var runtime = try start(std.testing.allocator, &loaded, .strict);
    defer runtime.deinit();
    std.Io.sleep(io, std.Io.Duration.fromNanoseconds(50 * std.time.ns_per_ms), .awake) catch {};

    const proxy_port = try bindPort(runtime.bindUrl());
    const proxy_addr = try std.Io.net.IpAddress.parse("127.0.0.1", proxy_port);
    var client = try std.Io.net.IpAddress.connect(&proxy_addr, io, .{ .mode = .stream });
    defer client.close(io);

    var request_buf: [256]u8 = undefined;
    const request = try std.fmt.bufPrint(
        &request_buf,
        "GET http://127.0.0.1:{d}/secret HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nConnection: close\r\n\r\n",
        .{ upstream_port, upstream_port },
    );
    var client_write_buf: [512]u8 = undefined;
    var client_writer = client.writer(io, &client_write_buf);
    try client_writer.interface.writeAll(request);
    try client_writer.interface.flush();

    var response_buf: [512]u8 = undefined;
    const response_len = try readHttpResponse(io, client, &response_buf);
    try std.testing.expect(std.mem.indexOf(u8, response_buf[0..response_len], "403 Forbidden") != null);

    try runtime.waitForIdle(2 * std.time.ns_per_s);
    const events = try runtime.snapshotAuditEvents(std.testing.allocator);
    defer runtime.freeAuditEvents(std.testing.allocator, events);
    try std.testing.expectEqual(@as(usize, 2), events.len);
    try std.testing.expectEqual(@import("ryk_core").core.event.EventType.network_connect_attempt, events[0].event_type);
    try std.testing.expectEqual(@import("ryk_core").core.event.EventType.network_connect_denied, events[1].event_type);
    try std.testing.expectEqual(@import("ryk_core").core.decision.DecisionResult.deny, events[1].result.?);
    try std.testing.expect(std.mem.indexOf(u8, events[1].reason.?, "explicit network deny") != null);
    try std.testing.expect(!upstream_state.accepted.load(.acquire));
}

test "proxy applies HTTP method and path policy while CONNECT remains host-port only" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;

    const io = std.testing.io;
    const upstream_address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var upstream = try upstream_address.listen(io, .{ .reuse_address = true });
    defer upstream.deinit(io);
    const upstream_port = upstream.socket.address.getPort();

    const policy_text = try std.fmt.allocPrint(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\network:
        \\  mode: open
        \\  backend: proxy
        \\services:
        \\  local_test:
        \\    hosts:
        \\      - "127.0.0.1:{d}"
        \\    methods:
        \\      - "GET"
        \\    paths:
        \\      deny:
        \\        - "/secret"
        \\    unmatched: allow
    , .{upstream_port});
    defer std.testing.allocator.free(policy_text);
    var loaded = try @import("ryk_core").policy.load.parseFromSlice(std.testing.allocator, policy_text, "proxy-service-deny.yaml");
    defer loaded.deinit();

    var runtime = try start(std.testing.allocator, &loaded, .strict);
    defer runtime.deinit();
    std.Io.sleep(io, std.Io.Duration.fromNanoseconds(50 * std.time.ns_per_ms), .awake) catch {};

    const proxy_port = try bindPort(runtime.bindUrl());
    const proxy_addr = try std.Io.net.IpAddress.parse("127.0.0.1", proxy_port);

    {
        var client = try std.Io.net.IpAddress.connect(&proxy_addr, io, .{ .mode = .stream });
        defer client.close(io);
        var request_buf: [256]u8 = undefined;
        const request = try std.fmt.bufPrint(
            &request_buf,
            "GET http://127.0.0.1:{d}/secret HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nConnection: close\r\n\r\n",
            .{ upstream_port, upstream_port },
        );
        var client_write_buf: [512]u8 = undefined;
        var client_writer = client.writer(io, &client_write_buf);
        try client_writer.interface.writeAll(request);
        try client_writer.interface.flush();
        var response_buf: [512]u8 = undefined;
        const response_len = try readHttpResponse(io, client, &response_buf);
        try std.testing.expect(std.mem.indexOf(u8, response_buf[0..response_len], "403 Forbidden") != null);
    }

    try runtime.waitForIdle(2 * std.time.ns_per_s);
    const events = try runtime.snapshotAuditEvents(std.testing.allocator);
    defer runtime.freeAuditEvents(std.testing.allocator, events);
    try std.testing.expect(events.len >= 2);
    try std.testing.expectEqual(@import("ryk_core").core.event.EventType.network_connect_denied, events[1].event_type);
    try std.testing.expect(std.mem.indexOf(u8, events[1].reason.?, "service path deny") != null);

    var connect_target_buf: [32]u8 = undefined;
    const connect_target = try std.fmt.bufPrint(&connect_target_buf, "127.0.0.1:{d}", .{upstream_port});
    var connect_decision = try network.evaluate(std.testing.allocator, &loaded, .strict, connect_target, .{
        .enforcement_mode = .proxy_mediated,
        .method = null,
    });
    defer connect_decision.deinit(std.testing.allocator);
    try std.testing.expectEqual(@import("ryk_core").core.decision.DecisionResult.allow, connect_decision.decision.result);
    try std.testing.expectEqualStrings("services.local_test.unmatched", connect_decision.decision.rule_id.?);
}

test "proxy allowed absolute URL does not connect to mismatched Host target" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;

    const io = std.testing.io;

    // "Evil" listener: Host will point here; must never accept a connection.
    const evil_address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var evil = try evil_address.listen(io, .{ .reuse_address = true });
    defer evil.deinit(io);
    const evil_port = evil.socket.address.getPort();
    var evil_state: TestDenyServerState = .{ .server = &evil, .io = io };
    const evil_thread = try std.Thread.spawn(.{}, testDenyServerNoConnectLong, .{&evil_state});
    defer evil_thread.join();

    // Allowed absolute-form authority (open network policy would permit either host:port;
    // the regression is that Host must not become the TCP peer).
    const allowed_address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var allowed = try allowed_address.listen(io, .{ .reuse_address = true });
    defer allowed.deinit(io);
    const allowed_port = allowed.socket.address.getPort();
    var allowed_state: TestHttpServerState = .{ .server = &allowed, .io = io, .expected_body = "" };
    const allowed_thread = try std.Thread.spawn(.{}, testHttpServer, .{&allowed_state});
    defer allowed_thread.join();

    var loaded = try @import("ryk_core").policy.load.parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: observe
        \\network:
        \\  mode: open
        \\  backend: proxy
    , "proxy-host-ssrf.yaml");
    defer loaded.deinit();

    var runtime = try start(std.testing.allocator, &loaded, .observe);
    defer runtime.deinit();
    std.Io.sleep(io, std.Io.Duration.fromNanoseconds(50 * std.time.ns_per_ms), .awake) catch {};

    const proxy_port = try bindPort(runtime.bindUrl());
    const proxy_addr = try std.Io.net.IpAddress.parse("127.0.0.1", proxy_port);
    var client = try std.Io.net.IpAddress.connect(&proxy_addr, io, .{ .mode = .stream });
    defer client.close(io);

    // Absolute URL → allowed listener; Host → evil listener (metadata-style pivot).
    var request_buf: [320]u8 = undefined;
    const request = try std.fmt.bufPrint(
        &request_buf,
        "GET http://127.0.0.1:{d}/ok HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nConnection: close\r\n\r\n",
        .{ allowed_port, evil_port },
    );
    var client_write_buf: [512]u8 = undefined;
    var client_writer = client.writer(io, &client_write_buf);
    try client_writer.interface.writeAll(request);
    try client_writer.interface.flush();

    var response_buf: [512]u8 = undefined;
    _ = readHttpResponse(io, client, &response_buf) catch {};
    try runtime.waitForIdle(2 * std.time.ns_per_s);

    // Policy would allow the absolute URL under open mode; Host pivot must not dial evil.
    try std.testing.expect(!evil_state.accepted.load(.acquire));
}

test "proxy deinit reclaims state only after connection workers drain" {
    // M-6: Runtime.deinit must not free State while active_connections > 0.
    // Hold a half-open client so a detached worker is live, then peer-close,
    // waitForIdle, and deinit under the testing allocator (leak check).
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;

    var loaded = try @import("ryk_core").policy.load.parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: observe
        \\network:
        \\  mode: open
        \\  backend: proxy
    , "proxy-deinit-drain.yaml");
    defer loaded.deinit();

    const io = std.testing.io;
    var runtime = try start(std.testing.allocator, &loaded, .observe);
    errdefer runtime.deinit();
    std.Io.sleep(io, std.Io.Duration.fromNanoseconds(50 * std.time.ns_per_ms), .awake) catch {};

    const proxy_port = try bindPort(runtime.bindUrl());
    const proxy_addr = try std.Io.net.IpAddress.parse("127.0.0.1", proxy_port);
    var client = try std.Io.net.IpAddress.connect(&proxy_addr, io, .{ .mode = .stream });
    var client_open = true;
    defer if (client_open) client.close(io);

    // Incomplete headers keep the worker in readHeaders until peer close / deadline.
    var write_buf: [64]u8 = undefined;
    var writer = client.writer(io, &write_buf);
    try writer.interface.writeAll("GET /partial HTTP/1.1\r\n");
    try writer.interface.flush();

    {
        var threaded: std.Io.Threaded = .init_single_threaded;
        const wait_io = threaded.io();
        const started = std.Io.Clock.Timestamp.now(wait_io, .awake);
        while (runtime.state.active_connections.load(.acquire) == 0) {
            const elapsed = started.durationFromNow(wait_io).raw.nanoseconds;
            try std.testing.expect(elapsed <= 2 * std.time.ns_per_s);
            std.Io.sleep(wait_io, std.Io.Duration.fromNanoseconds(10 * std.time.ns_per_ms), .awake) catch {};
        }
    }
    try std.testing.expect(runtime.state.active_connections.load(.acquire) > 0);

    client.close(io);
    client_open = false;
    try runtime.waitForIdle(2 * std.time.ns_per_s);
    try std.testing.expectEqual(@as(usize, 0), runtime.state.active_connections.load(.acquire));
    // Workers idle: deinit reclaims State (GPA / testing allocator must not report leak).
    runtime.deinit();
}

test "proxy deinit blocks until workers drain instead of abandoning state" {
    // M-2/M-3 + M-1: deinit must not return while active_connections > 0
    // (borrowed selected_policy / last-worker State lifetime). Force-shutdown of
    // active client FDs unblocks readHeaders/tunnel workers; deinit then reclaims
    // without requiring the test client to peer-close first.
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;

    var loaded = try @import("ryk_core").policy.load.parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: observe
        \\network:
        \\  mode: open
        \\  backend: proxy
    , "proxy-deinit-no-abandon.yaml");
    defer loaded.deinit();

    const io = std.testing.io;
    var runtime = try start(std.testing.allocator, &loaded, .observe);
    var needs_deinit = true;
    errdefer if (needs_deinit) runtime.deinit();
    std.Io.sleep(io, std.Io.Duration.fromNanoseconds(50 * std.time.ns_per_ms), .awake) catch {};

    const proxy_port = try bindPort(runtime.bindUrl());
    const proxy_addr = try std.Io.net.IpAddress.parse("127.0.0.1", proxy_port);
    var client = try std.Io.net.IpAddress.connect(&proxy_addr, io, .{ .mode = .stream });
    var client_open = true;
    defer if (client_open) client.close(io);

    var write_buf: [64]u8 = undefined;
    var writer = client.writer(io, &write_buf);
    try writer.interface.writeAll("GET /partial HTTP/1.1\r\n");
    try writer.interface.flush();

    {
        var threaded: std.Io.Threaded = .init_single_threaded;
        const wait_io = threaded.io();
        const started = std.Io.Clock.Timestamp.now(wait_io, .awake);
        while (runtime.state.active_connections.load(.acquire) == 0) {
            const elapsed = started.durationFromNow(wait_io).raw.nanoseconds;
            try std.testing.expect(elapsed <= 2 * std.time.ns_per_s);
            std.Io.sleep(wait_io, std.Io.Duration.fromNanoseconds(10 * std.time.ns_per_ms), .awake) catch {};
        }
    }
    try std.testing.expect(runtime.state.active_connections.load(.acquire) > 0);

    const DeinitCtx = struct {
        runtime: *Runtime,
        done: std.atomic.Value(bool) = .init(false),
        fn run(ctx: *@This()) void {
            ctx.runtime.deinit();
            ctx.done.store(true, .release);
        }
    };
    var deinit_ctx: DeinitCtx = .{ .runtime = &runtime };
    const deinit_thread = try std.Thread.spawn(.{}, DeinitCtx.run, .{&deinit_ctx});
    needs_deinit = false;

    // Force-shutdown path: deinit completes without the test peer-closing first.
    const bound_started = std.Io.Clock.Timestamp.now(io, .awake);
    const bound_ns: i96 = 5 * std.time.ns_per_s;
    while (!deinit_ctx.done.load(.acquire)) {
        if (bound_started.durationFromNow(io).raw.nanoseconds > bound_ns) {
            if (client_open) {
                client.close(io);
                client_open = false;
            }
            deinit_thread.join();
            try std.testing.expect(false); // deinit did not reclaim worker within bound
        }
        std.Io.sleep(io, std.Io.Duration.fromNanoseconds(10 * std.time.ns_per_ms), .awake) catch {};
    }
    deinit_thread.join();
    try std.testing.expect(deinit_ctx.done.load(.acquire));
    if (client_open) {
        client.close(io);
        client_open = false;
    }
}

test "proxy scheme-less allowed target does not connect to mismatched Host" {
    // M-8 integration: scheme-less request-target + metadata-style Host pivot
    // must not dial the Host peer (mirror absolute-form SSRF regression).
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;

    const io = std.testing.io;

    const evil_address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var evil = try evil_address.listen(io, .{ .reuse_address = true });
    defer evil.deinit(io);
    const evil_port = evil.socket.address.getPort();
    var evil_state: TestDenyServerState = .{ .server = &evil, .io = io };
    const evil_thread = try std.Thread.spawn(.{}, testDenyServerNoConnectLong, .{&evil_state});
    defer evil_thread.join();

    const allowed_address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var allowed = try allowed_address.listen(io, .{ .reuse_address = true });
    defer allowed.deinit(io);
    const allowed_port = allowed.socket.address.getPort();
    var allowed_state: TestHttpServerState = .{ .server = &allowed, .io = io, .expected_body = "" };
    const allowed_thread = try std.Thread.spawn(.{}, testHttpServer, .{&allowed_state});
    defer allowed_thread.join();

    var loaded = try @import("ryk_core").policy.load.parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: observe
        \\network:
        \\  mode: open
        \\  backend: proxy
    , "proxy-host-ssrf-schemeless.yaml");
    defer loaded.deinit();

    var runtime = try start(std.testing.allocator, &loaded, .observe);
    defer runtime.deinit();
    std.Io.sleep(io, std.Io.Duration.fromNanoseconds(50 * std.time.ns_per_ms), .awake) catch {};

    const proxy_port = try bindPort(runtime.bindUrl());
    const proxy_addr = try std.Io.net.IpAddress.parse("127.0.0.1", proxy_port);
    var client = try std.Io.net.IpAddress.connect(&proxy_addr, io, .{ .mode = .stream });
    defer client.close(io);

    // Scheme-less target → allowed listener; Host → evil listener.
    var request_buf: [320]u8 = undefined;
    const request = try std.fmt.bufPrint(
        &request_buf,
        "GET 127.0.0.1:{d}/ok HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nConnection: close\r\n\r\n",
        .{ allowed_port, evil_port },
    );
    var client_write_buf: [512]u8 = undefined;
    var client_writer = client.writer(io, &client_write_buf);
    try client_writer.interface.writeAll(request);
    try client_writer.interface.flush();

    var response_buf: [512]u8 = undefined;
    _ = readHttpResponse(io, client, &response_buf) catch {};
    try runtime.waitForIdle(2 * std.time.ns_per_s);

    try std.testing.expect(!evil_state.accepted.load(.acquire));
}

test "proxy does not tunnel a second HTTP request after an allowed first request" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;

    const io = std.testing.io;
    const upstream_address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var upstream = try upstream_address.listen(io, .{ .reuse_address = true });
    defer upstream.deinit(io);
    const upstream_port = upstream.socket.address.getPort();
    var upstream_state: TestPipelinedServerState = .{ .server = &upstream, .io = io };
    const upstream_thread = try std.Thread.spawn(.{}, testPipelinedServer, .{&upstream_state});
    // Join before asserts (flags publish at end of server read loop). Use a joined flag so
    // early `try` failures still join via defer (no double-join on the success path).
    var upstream_joined = false;
    defer if (!upstream_joined) upstream_thread.join();

    const policy_text = try std.fmt.allocPrint(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\network:
        \\  mode: open
        \\  backend: proxy
        \\services:
        \\  local_test:
        \\    hosts:
        \\      - "127.0.0.1:{d}"
        \\    methods:
        \\      - "GET"
        \\    paths:
        \\      deny:
        \\        - "/denied"
        \\    unmatched: allow
    , .{upstream_port});
    defer std.testing.allocator.free(policy_text);
    var loaded = try @import("ryk_core").policy.load.parseFromSlice(std.testing.allocator, policy_text, "proxy-pipelining.yaml");
    defer loaded.deinit();

    var runtime = try start(std.testing.allocator, &loaded, .strict);
    defer runtime.deinit();
    std.Io.sleep(io, std.Io.Duration.fromNanoseconds(50 * std.time.ns_per_ms), .awake) catch {};

    const proxy_port = try bindPort(runtime.bindUrl());
    const proxy_addr = try std.Io.net.IpAddress.parse("127.0.0.1", proxy_port);
    var client = try std.Io.net.IpAddress.connect(&proxy_addr, io, .{ .mode = .stream });
    defer client.close(io);
    var writer_buffer: [1024]u8 = undefined;
    var writer = client.writer(io, &writer_buffer);
    // Host host must match absolute-form host (M-9); port may appear on Host.
    try writer.interface.print(
        "GET http://127.0.0.1:{d}/allowed HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nConnection: keep-alive\r\n\r\n",
        .{ upstream_port, upstream_port },
    );
    try writer.interface.flush();
    std.Io.sleep(io, std.Io.Duration.fromNanoseconds(150 * std.time.ns_per_ms), .awake) catch {};
    try writer.interface.print(
        "GET http://127.0.0.1:{d}/denied HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nConnection: close\r\n\r\n",
        .{ upstream_port, upstream_port },
    );
    try writer.interface.flush();
    std.Io.sleep(io, std.Io.Duration.fromNanoseconds(700 * std.time.ns_per_ms), .awake) catch {};
    upstream_thread.join();
    upstream_joined = true;

    try std.testing.expect(upstream_state.saw_allowed.load(.acquire));
    try std.testing.expect(!upstream_state.saw_denied.load(.acquire));
}

const TestHttpServerState = struct {
    server: *std.Io.net.Server,
    io: std.Io,
    expected_body: []const u8,
};

fn testHttpServer(state: *TestHttpServerState) void {
    var listen_fd = [_]std.posix.pollfd{.{
        .fd = state.server.socket.handle,
        .events = std.posix.POLL.IN,
        .revents = 0,
    }};
    _ = std.posix.poll(&listen_fd, 5_000) catch return;
    var stream = state.server.accept(state.io) catch return;
    defer stream.close(state.io);
    var buffer: [1024]u8 = undefined;
    var total: usize = 0;
    const started = std.Io.Clock.Timestamp.now(state.io, .awake);
    const deadline_ns: i96 = 750 * std.time.ns_per_ms;
    while (total < buffer.len and started.durationFromNow(state.io).raw.nanoseconds < deadline_ns) {
        var fds = [_]std.posix.pollfd{.{
            .fd = stream.socket.handle,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        const ready = std.posix.poll(&fds, 50) catch break;
        if (ready == 0) continue;
        const n = std.posix.read(stream.socket.handle, buffer[total..]) catch |err| switch (err) {
            error.WouldBlock => continue,
            else => break,
        };
        if (n == 0) break;
        total += n;
        if (std.mem.indexOf(u8, buffer[0..total], state.expected_body) != null) break;
    }
    const ok = std.mem.indexOf(u8, buffer[0..total], state.expected_body) != null;
    const body = if (ok) "proxied" else "missing-body";
    var response: [128]u8 = undefined;
    const text = std.fmt.bufPrint(&response, "HTTP/1.1 {d} {s}\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{
        if (ok) @as(u16, 200) else @as(u16, 408),
        if (ok) "OK" else "Request Timeout",
        body.len,
        body,
    }) catch return;
    var write_buf: [256]u8 = undefined;
    var writer = stream.writer(state.io, &write_buf);
    writer.interface.writeAll(text) catch {};
    writer.interface.flush() catch {};
}

const TestDenyServerState = struct {
    server: *std.Io.net.Server,
    io: std.Io,
    accepted: std.atomic.Value(bool) = .init(false),
};

const TestPipelinedServerState = struct {
    server: *std.Io.net.Server,
    io: std.Io,
    saw_allowed: std.atomic.Value(bool) = .init(false),
    saw_denied: std.atomic.Value(bool) = .init(false),
};

fn testPipelinedServer(state: *TestPipelinedServerState) void {
    var stream = state.server.accept(state.io) catch return;
    defer stream.close(state.io);
    var buffer: [2048]u8 = undefined;
    var total: usize = 0;
    const started = std.Io.Clock.Timestamp.now(state.io, .awake);
    // Respond as soon as the first request headers are complete so Connection: close
    // tears down the tunnel before a later pipelined client request can be forwarded.
    // (A long drain window falsely marks /denied as "tunneled" when the client sends
    // a second request while this server is still reading.)
    while (total < buffer.len and started.durationFromNow(state.io).raw.nanoseconds < 600 * std.time.ns_per_ms) {
        var fds = [_]std.posix.pollfd{.{
            .fd = stream.socket.handle,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        const ready = std.posix.poll(&fds, 50) catch break;
        if (ready == 0) continue;
        const n = std.posix.read(stream.socket.handle, buffer[total..]) catch break;
        if (n == 0) break;
        total += n;
        if (std.mem.indexOf(u8, buffer[0..total], "\r\n\r\n") != null) break;
    }
    state.saw_allowed.store(std.mem.indexOf(u8, buffer[0..total], "/allowed") != null, .release);
    state.saw_denied.store(std.mem.indexOf(u8, buffer[0..total], "/denied") != null, .release);
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";
    var write_buffer: [128]u8 = undefined;
    var writer = stream.writer(state.io, &write_buffer);
    writer.interface.writeAll(response) catch return;
    writer.interface.flush() catch {};
}

fn testDenyServerNoConnect(state: *TestDenyServerState) void {
    testDenyServerAwait(state, 500);
}

/// Same as testDenyServerNoConnect but with a longer accept window (SSRF / race-sensitive tests).
fn testDenyServerNoConnectLong(state: *TestDenyServerState) void {
    testDenyServerAwait(state, 5_000);
}

fn testDenyServerAwait(state: *TestDenyServerState, timeout_ms: i32) void {
    var listen_fd = [_]std.posix.pollfd{.{
        .fd = state.server.socket.handle,
        .events = std.posix.POLL.IN,
        .revents = 0,
    }};
    const ready = std.posix.poll(&listen_fd, timeout_ms) catch return;
    if (ready == 0) return;
    var stream = state.server.accept(state.io) catch return;
    defer stream.close(state.io);
    state.accepted.store(true, .release);
}

fn readHttpResponse(io: std.Io, stream: std.Io.net.Stream, buffer: []u8) !usize {
    var total: usize = 0;
    const started = std.Io.Clock.Timestamp.now(io, .awake);
    const deadline_ns: i96 = 2 * std.time.ns_per_s;
    while (total < buffer.len and started.durationFromNow(io).raw.nanoseconds < deadline_ns) {
        var fds = [_]std.posix.pollfd{.{
            .fd = stream.socket.handle,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        const ready = std.posix.poll(&fds, 100) catch break;
        if (ready == 0) continue;
        const n = std.posix.read(stream.socket.handle, buffer[total..]) catch |err| switch (err) {
            error.WouldBlock => continue,
            else => return err,
        };
        if (n == 0) break;
        total += n;
        if (std.mem.indexOf(u8, buffer[0..total], "\r\n\r\n") != null) break;
    }
    return total;
}

fn bindPort(bind_url: []const u8) !u16 {
    const colon = std.mem.lastIndexOfScalar(u8, bind_url, ':') orelse return error.InvalidBindUrl;
    return std.fmt.parseInt(u16, bind_url[colon + 1 ..], 10);
}

test "connectUpstream dials IP literals and DNS hostnames" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();

    // localhost resolves to loopback; the post-resolution fence requires an
    // explicit class allow, so the test policy carries one.
    var loaded = try @import("ryk_core").policy.load.parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: observe
        \\network:
        \\  mode: allowlist
        \\  allow:
        \\    - "localhost"
    , "connect-upstream.yaml");
    defer loaded.deinit();
    var runtime = try listen(std.testing.allocator, &loaded, .observe);
    defer runtime.deinit();
    const state = runtime.state;

    // IP path (loopback listen + dial)
    const listen_addr = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try listen_addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    const port = server.socket.address.getPort();
    const accept_thread = try std.Thread.spawn(.{}, struct {
        fn run(s: *std.Io.net.Server, thread_io: std.Io) void {
            var stream = s.accept(thread_io) catch return;
            stream.close(thread_io);
        }
    }.run, .{ &server, io });
    defer accept_thread.join();
    var ip_stream = try connectUpstream(state, io, "127.0.0.1", port);
    ip_stream.close(io);

    // DNS path via localhost (hermetic: no external resolv / offline skip).
    // Proves HostName dial, not IP-literal-only path.
    var host_server = try listen_addr.listen(io, .{ .reuse_address = true });
    defer host_server.deinit(io);
    const host_port = host_server.socket.address.getPort();
    const host_accept = try std.Thread.spawn(.{}, struct {
        fn run(s: *std.Io.net.Server, thread_io: std.Io) void {
            var stream = s.accept(thread_io) catch return;
            stream.close(thread_io);
        }
    }.run, .{ &host_server, io });
    defer host_accept.join();
    var host_stream = try connectUpstream(state, io, "localhost", host_port);
    host_stream.close(io);
}

const FakeLookup = struct {
    answers: []const std.Io.net.IpAddress,
    calls: usize = 0,

    fn lookup(self: *FakeLookup, out: []std.Io.net.IpAddress) usize {
        self.calls += 1;
        const n = @min(self.answers.len, out.len);
        @memcpy(out[0..n], self.answers[0..n]);
        return n;
    }
};

fn fakeLookupThunk(context: ?*anyopaque, io: std.Io, host: []const u8, port: u16, out: []std.Io.net.IpAddress) anyerror!usize {
    _ = io;
    _ = host;
    _ = port;
    const fake: *FakeLookup = @ptrCast(@alignCast(context.?));
    return fake.lookup(out);
}

fn connectViaProxy(io: std.Io, proxy_port: u16, host: []const u8, port: u16) ![]u8 {
    const proxy_addr = try std.Io.net.IpAddress.parse("127.0.0.1", proxy_port);
    var client = try std.Io.net.IpAddress.connect(&proxy_addr, io, .{ .mode = .stream });
    defer client.close(io);
    var req_buf: [256]u8 = undefined;
    const req = try std.fmt.bufPrint(&req_buf, "CONNECT {s}:{d} HTTP/1.1\r\nHost: {s}:{d}\r\n\r\n", .{ host, port, host, port });
    var write_buf: [512]u8 = undefined;
    var writer = client.writer(io, &write_buf);
    try writer.interface.writeAll(req);
    try writer.interface.flush();
    var response_buf: [1024]u8 = undefined;
    const response_len = try readHttpResponse(io, client, &response_buf);
    return std.testing.allocator.dupe(u8, response_buf[0..response_len]);
}

test "proxy denies allowlisted hostname that resolves to fenced addresses (DNS rebinding)" {
    // P1-6: policy allows the hostname (domain class), but every resolved
    // answer is loopback / metadata / private — the connection must be refused
    // with a deny audit event on every connection, not just the first.
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;

    var loaded = try @import("ryk_core").policy.load.parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\network:
        \\  mode: allowlist
        \\  backend: proxy
        \\  allow:
        \\    - "allowed.example"
    , "proxy-rebind-deny.yaml");
    defer loaded.deinit();

    const answer_metadata = try std.Io.net.IpAddress.parse("169.254.169.254", 443);
    const answer_loopback = try std.Io.net.IpAddress.parse("127.0.0.1", 443);
    const answer_private = try std.Io.net.IpAddress.parse("10.0.0.9", 443);
    const rebind_answers = [_]std.Io.net.IpAddress{ answer_metadata, answer_loopback, answer_private };
    var fake = FakeLookup{ .answers = &rebind_answers };

    var runtime = try start(std.testing.allocator, &loaded, .strict);
    defer runtime.deinit();
    runtime.state.lookup_fn = fakeLookupThunk;
    runtime.state.lookup_context = &fake;

    const io = std.testing.io;
    std.Io.sleep(io, std.Io.Duration.fromNanoseconds(50 * std.time.ns_per_ms), .awake) catch {};
    const proxy_port = try bindPort(runtime.bindUrl());

    // Every connection re-fences: two attempts, both denied.
    for (0..2) |_| {
        const response = try connectViaProxy(io, proxy_port, "allowed.example", 443);
        defer std.testing.allocator.free(response);
        try std.testing.expect(std.mem.indexOf(u8, response, "403") != null);
    }
    try std.testing.expect(fake.calls >= 2);

    try runtime.waitForIdle(2 * std.time.ns_per_s);
    const events = try runtime.snapshotAuditEvents(std.testing.allocator);
    defer runtime.freeAuditEvents(std.testing.allocator, events);
    var saw_rebind_deny = false;
    for (events) |ev| {
        if (ev.event_type == .network_connect_denied and
            ev.reason != null and
            std.mem.indexOf(u8, ev.reason.?, "DNS rebinding") != null)
        {
            saw_rebind_deny = true;
        }
    }
    try std.testing.expect(saw_rebind_deny);
}

test "proxy connects when resolved loopback is covered by an explicit class allow" {
    // Explicit `localhost` class allow lifts the fence: the pinned resolved
    // address connects (proves allow path + no re-resolution between check
    // and connect — the fake answers once per lookup).
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;

    const io = std.testing.io;
    const upstream_addr = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var upstream = try upstream_addr.listen(io, .{ .reuse_address = true });
    defer upstream.deinit(io);
    const upstream_port = upstream.socket.address.getPort();
    const accept_thread = try std.Thread.spawn(.{}, struct {
        fn run(s: *std.Io.net.Server, thread_io: std.Io) void {
            var stream = s.accept(thread_io) catch return;
            stream.close(thread_io);
        }
    }.run, .{ &upstream, io });
    defer accept_thread.join();

    var loaded = try @import("ryk_core").policy.load.parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: strict
        \\network:
        \\  mode: allowlist
        \\  backend: proxy
        \\  allow:
        \\    - "allowed.example"
        \\    - "localhost"
    , "proxy-rebind-allow.yaml");
    defer loaded.deinit();

    const answer_loopback = try std.Io.net.IpAddress.parse("127.0.0.1", upstream_port);
    const loopback_answers = [_]std.Io.net.IpAddress{answer_loopback};
    var fake = FakeLookup{ .answers = &loopback_answers };

    var runtime = try start(std.testing.allocator, &loaded, .strict);
    defer runtime.deinit();
    runtime.state.lookup_fn = fakeLookupThunk;
    runtime.state.lookup_context = &fake;

    std.Io.sleep(io, std.Io.Duration.fromNanoseconds(50 * std.time.ns_per_ms), .awake) catch {};
    const proxy_port = try bindPort(runtime.bindUrl());
    const response = try connectViaProxy(io, proxy_port, "allowed.example", upstream_port);
    defer std.testing.allocator.free(response);
    try std.testing.expect(std.mem.indexOf(u8, response, "200 Connection Established") != null);
}

test "proxy CONNECT allowlisted hostname returns 200 Connection Established" {
    // Hermetic production path: allowlist `localhost`, CONNECT to a loopback
    // listener. Proves HostName DNS dial (not IP-literal-only) after allow
    // without external network / offline SkipZigTest.
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;

    var threaded: std.Io.Threaded = .init_single_threaded;
    const thread_io = threaded.io();
    const upstream_addr = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var upstream = try upstream_addr.listen(thread_io, .{ .reuse_address = true });
    defer upstream.deinit(thread_io);
    const upstream_port = upstream.socket.address.getPort();
    const accept_thread = try std.Thread.spawn(.{}, struct {
        fn run(s: *std.Io.net.Server, io: std.Io) void {
            var stream = s.accept(io) catch return;
            stream.close(io);
        }
    }.run, .{ &upstream, thread_io });
    defer accept_thread.join();

    var loaded = try @import("ryk_core").policy.load.parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: observe
        \\network:
        \\  mode: allowlist
        \\  backend: proxy
        \\  allow:
        \\    - "localhost"
    , "proxy-connect-hostname.yaml");
    defer loaded.deinit();

    var runtime = try start(std.testing.allocator, &loaded, .observe);
    defer runtime.deinit();

    const io = std.testing.io;
    std.Io.sleep(io, std.Io.Duration.fromNanoseconds(50 * std.time.ns_per_ms), .awake) catch {};
    const proxy_port = try bindPort(runtime.bindUrl());
    const proxy_addr = try std.Io.net.IpAddress.parse("127.0.0.1", proxy_port);
    var client = try std.Io.net.IpAddress.connect(&proxy_addr, io, .{ .mode = .stream });
    defer client.close(io);

    var req_buf: [128]u8 = undefined;
    const req = try std.fmt.bufPrint(
        &req_buf,
        "CONNECT localhost:{d} HTTP/1.1\r\nHost: localhost:{d}\r\n\r\n",
        .{ upstream_port, upstream_port },
    );
    var write_buf: [256]u8 = undefined;
    var writer = client.writer(io, &write_buf);
    try writer.interface.writeAll(req);
    try writer.interface.flush();

    var response_buf: [512]u8 = undefined;
    const response_len = try readHttpResponse(io, client, &response_buf);
    try std.testing.expect(std.mem.indexOf(u8, response_buf[0..response_len], "200 Connection Established") != null);
    try runtime.waitForIdle(2 * std.time.ns_per_s);
    const events = try runtime.snapshotAuditEvents(std.testing.allocator);
    defer runtime.freeAuditEvents(std.testing.allocator, events);
    try std.testing.expect(events.len >= 2);
    try std.testing.expectEqual(@import("ryk_core").core.event.EventType.network_connect_allowed, events[1].event_type);
}

test "proxy tunnel survives mid-stream quiet gap of 5s (CONNECT shares fn tunnel)" {
    // U1: product bug was idle_ms >= 3000 closing both tunnel ends during LLM
    // think/stream pauses. CONNECT and HTTP forward both call the same `fn tunnel`;
    // this exercises CONNECT with first body chunk → pause ≥5s → second chunk.
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;

    const io = std.testing.io;
    const upstream_addr = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var upstream = try upstream_addr.listen(io, .{ .reuse_address = true });
    defer upstream.deinit(io);
    const upstream_port = upstream.socket.address.getPort();

    const UpstreamState = struct {
        server: *std.Io.net.Server,
        io: std.Io,
        fn run(self: *@This()) void {
            var stream = self.server.accept(self.io) catch return;
            defer stream.close(self.io);
            var write_buf: [64]u8 = undefined;
            var writer = stream.writer(self.io, &write_buf);
            writer.interface.writeAll("chunk-a") catch return;
            writer.interface.flush() catch return;
            // Quiet gap longer than the old 3s tunnel idle kill.
            std.Io.sleep(self.io, std.Io.Duration.fromNanoseconds(5 * std.time.ns_per_s), .awake) catch {};
            writer.interface.writeAll("chunk-b") catch return;
            writer.interface.flush() catch {};
        }
    };
    var upstream_state: UpstreamState = .{ .server = &upstream, .io = io };
    const upstream_thread = try std.Thread.spawn(.{}, UpstreamState.run, .{&upstream_state});
    defer upstream_thread.join();

    var loaded = try @import("ryk_core").policy.load.parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: observe
        \\network:
        \\  mode: open
        \\  backend: proxy
    , "proxy-tunnel-quiet-gap.yaml");
    defer loaded.deinit();

    var runtime = try start(std.testing.allocator, &loaded, .observe);
    defer runtime.deinit();
    std.Io.sleep(io, std.Io.Duration.fromNanoseconds(50 * std.time.ns_per_ms), .awake) catch {};

    const proxy_port = try bindPort(runtime.bindUrl());
    const proxy_addr = try std.Io.net.IpAddress.parse("127.0.0.1", proxy_port);
    var client = try std.Io.net.IpAddress.connect(&proxy_addr, io, .{ .mode = .stream });
    defer client.close(io);

    var req_buf: [128]u8 = undefined;
    const req = try std.fmt.bufPrint(
        &req_buf,
        "CONNECT 127.0.0.1:{d} HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\n\r\n",
        .{ upstream_port, upstream_port },
    );
    var write_buf: [256]u8 = undefined;
    var writer = client.writer(io, &write_buf);
    try writer.interface.writeAll(req);
    try writer.interface.flush();

    var head_buf: [512]u8 = undefined;
    const head_len = try readHttpResponse(io, client, &head_buf);
    try std.testing.expect(std.mem.indexOf(u8, head_buf[0..head_len], "200 Connection Established") != null);

    // Read tunnel body until both chunks arrive (or 10s deadline).
    var body_buf: [64]u8 = undefined;
    var total: usize = 0;
    const started = std.Io.Clock.Timestamp.now(io, .awake);
    const deadline_ns: i96 = 10 * std.time.ns_per_s;
    while (total < body_buf.len and started.durationFromNow(io).raw.nanoseconds < deadline_ns) {
        if (std.mem.indexOf(u8, body_buf[0..total], "chunk-a") != null and
            std.mem.indexOf(u8, body_buf[0..total], "chunk-b") != null) break;
        var fds = [_]std.posix.pollfd{.{
            .fd = client.socket.handle,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        const ready = std.posix.poll(&fds, 200) catch break;
        if (ready == 0) continue;
        const n = std.posix.read(client.socket.handle, body_buf[total..]) catch |err| switch (err) {
            error.WouldBlock => continue,
            else => break,
        };
        if (n == 0) break;
        total += n;
    }
    try std.testing.expect(std.mem.indexOf(u8, body_buf[0..total], "chunk-a") != null);
    try std.testing.expect(std.mem.indexOf(u8, body_buf[0..total], "chunk-b") != null);
    try runtime.waitForIdle(2 * std.time.ns_per_s);
}

test "proxy deinit reclaims quiet open tunnel within bound" {
    // U1 / B1: after lengthening tunnel idle, deinit must force-close active
    // sockets so workers drain without waiting the full idle budget (or hanging).
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;

    const io = std.testing.io;
    const upstream_addr = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var upstream = try upstream_addr.listen(io, .{ .reuse_address = true });
    defer upstream.deinit(io);
    const upstream_port = upstream.socket.address.getPort();

    // Quiet upstream: accept and hold until peer close / error (no bytes).
    const QuietUpstream = struct {
        server: *std.Io.net.Server,
        io: std.Io,
        fn run(self: *@This()) void {
            var stream = self.server.accept(self.io) catch return;
            defer stream.close(self.io);
            var buf: [16]u8 = undefined;
            const hold_started = std.Io.Clock.Timestamp.now(self.io, .awake);
            while (hold_started.durationFromNow(self.io).raw.nanoseconds < 30 * std.time.ns_per_s) {
                var fds = [_]std.posix.pollfd{.{
                    .fd = stream.socket.handle,
                    .events = std.posix.POLL.IN,
                    .revents = 0,
                }};
                const ready = std.posix.poll(&fds, 200) catch break;
                if (ready == 0) continue;
                const n = std.posix.read(stream.socket.handle, &buf) catch break;
                if (n == 0) break;
            }
        }
    };
    var quiet: QuietUpstream = .{ .server = &upstream, .io = io };
    const upstream_thread = try std.Thread.spawn(.{}, QuietUpstream.run, .{&quiet});
    defer upstream_thread.join();

    var loaded = try @import("ryk_core").policy.load.parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: observe
        \\network:
        \\  mode: open
        \\  backend: proxy
    , "proxy-deinit-quiet-tunnel.yaml");
    defer loaded.deinit();

    var runtime = try start(std.testing.allocator, &loaded, .observe);
    var needs_deinit = true;
    errdefer if (needs_deinit) runtime.deinit();
    std.Io.sleep(io, std.Io.Duration.fromNanoseconds(50 * std.time.ns_per_ms), .awake) catch {};

    const proxy_port = try bindPort(runtime.bindUrl());
    const proxy_addr = try std.Io.net.IpAddress.parse("127.0.0.1", proxy_port);
    var client = try std.Io.net.IpAddress.connect(&proxy_addr, io, .{ .mode = .stream });
    var client_open = true;
    defer if (client_open) client.close(io);

    var req_buf: [128]u8 = undefined;
    const req = try std.fmt.bufPrint(
        &req_buf,
        "CONNECT 127.0.0.1:{d} HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\n\r\n",
        .{ upstream_port, upstream_port },
    );
    var write_buf: [256]u8 = undefined;
    var writer = client.writer(io, &write_buf);
    try writer.interface.writeAll(req);
    try writer.interface.flush();

    var head_buf: [512]u8 = undefined;
    const head_len = try readHttpResponse(io, client, &head_buf);
    try std.testing.expect(std.mem.indexOf(u8, head_buf[0..head_len], "200 Connection Established") != null);

    // Wait until worker is active in the quiet tunnel.
    {
        const wait_started = std.Io.Clock.Timestamp.now(io, .awake);
        while (runtime.state.active_connections.load(.acquire) == 0) {
            try std.testing.expect(wait_started.durationFromNow(io).raw.nanoseconds <= 2 * std.time.ns_per_s);
            std.Io.sleep(io, std.Io.Duration.fromNanoseconds(10 * std.time.ns_per_ms), .awake) catch {};
        }
    }
    try std.testing.expect(runtime.state.active_connections.load(.acquire) > 0);

    const DeinitCtx = struct {
        runtime: *Runtime,
        done: std.atomic.Value(bool) = .init(false),
        fn run(ctx: *@This()) void {
            ctx.runtime.deinit();
            ctx.done.store(true, .release);
        }
    };
    var deinit_ctx: DeinitCtx = .{ .runtime = &runtime };
    const deinit_thread = try std.Thread.spawn(.{}, DeinitCtx.run, .{&deinit_ctx});
    needs_deinit = false;

    // Bound: force-close path must finish well under tunnel_idle (300s) and under
    // a tight few-second product bound. Do not peer-close the client first.
    const bound_started = std.Io.Clock.Timestamp.now(io, .awake);
    const bound_ns: i96 = 5 * std.time.ns_per_s;
    while (!deinit_ctx.done.load(.acquire)) {
        if (bound_started.durationFromNow(io).raw.nanoseconds > bound_ns) {
            // Unblock any stuck worker so the suite can finish, then fail.
            if (client_open) {
                client.close(io);
                client_open = false;
            }
            deinit_thread.join();
            try std.testing.expect(false); // deinit exceeded bound with quiet tunnel
        }
        std.Io.sleep(io, std.Io.Duration.fromNanoseconds(10 * std.time.ns_per_ms), .awake) catch {};
    }
    deinit_thread.join();
    try std.testing.expect(deinit_ctx.done.load(.acquire));
    if (client_open) {
        client.close(io);
        client_open = false;
    }
}

test "proxy F-audit records exfil on allow for sink host and cleartext secret query" {
    // RT-03 F-audit: annotate-only even when allow. CONNECT host-class sinks fire;
    // cleartext absolute-form secret query fires; plain CONNECT non-sink does not.
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;

    var loaded = try @import("ryk_core").policy.load.parseFromSlice(std.testing.allocator,
        \\version: 1
        \\mode: observe
        \\network:
        \\  mode: open
        \\  backend: proxy
        \\  detect_exfiltration:
        \\    dns: true
        \\    long_query_strings: true
        \\    secret_patterns: true
    , "proxy-f-audit.yaml");
    defer loaded.deinit();

    const io = std.testing.io;
    var runtime = try start(std.testing.allocator, &loaded, .observe);
    defer runtime.deinit();
    std.Io.sleep(io, std.Io.Duration.fromNanoseconds(50 * std.time.ns_per_ms), .awake) catch {};
    const proxy_port = try bindPort(runtime.bindUrl());
    const proxy_addr = try std.Io.net.IpAddress.parse("127.0.0.1", proxy_port);

    // 1) CONNECT non-sink (api.github.com) — no exfil event expected for host-class.
    {
        var client = try std.Io.net.IpAddress.connect(&proxy_addr, io, .{ .mode = .stream });
        defer client.close(io);
        const req = "CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\n\r\n";
        var write_buf: [256]u8 = undefined;
        var writer = client.writer(io, &write_buf);
        try writer.interface.writeAll(req);
        try writer.interface.flush();
        var response_buf: [512]u8 = undefined;
        _ = readHttpResponse(io, client, &response_buf) catch {};
    }
    try runtime.waitForIdle(2 * std.time.ns_per_s);
    {
        const events = try runtime.snapshotAuditEvents(std.testing.allocator);
        defer runtime.freeAuditEvents(std.testing.allocator, events);
        var saw_exfil = false;
        for (events) |ev| {
            if (ev.event_type == .network_exfiltration_suspected) saw_exfil = true;
        }
        try std.testing.expect(!saw_exfil);
    }

    // 2) CONNECT paste sink — annotate + allow (open mode).
    {
        var client = try std.Io.net.IpAddress.connect(&proxy_addr, io, .{ .mode = .stream });
        defer client.close(io);
        const req = "CONNECT pastebin.com:443 HTTP/1.1\r\nHost: pastebin.com:443\r\n\r\n";
        var write_buf: [256]u8 = undefined;
        var writer = client.writer(io, &write_buf);
        try writer.interface.writeAll(req);
        try writer.interface.flush();
        var response_buf: [512]u8 = undefined;
        _ = readHttpResponse(io, client, &response_buf) catch {};
    }
    try runtime.waitForIdle(2 * std.time.ns_per_s);
    {
        const events = try runtime.snapshotAuditEvents(std.testing.allocator);
        defer runtime.freeAuditEvents(std.testing.allocator, events);
        var saw_exfil = false;
        var saw_allowed = false;
        for (events) |ev| {
            if (ev.event_type == .network_exfiltration_suspected and
                std.mem.indexOf(u8, ev.target, "pastebin.com") != null)
                saw_exfil = true;
            if (ev.event_type == .network_connect_allowed and
                std.mem.indexOf(u8, ev.target, "pastebin.com") != null)
                saw_allowed = true;
        }
        try std.testing.expect(saw_exfil);
        try std.testing.expect(saw_allowed);
    }

    // 3) Cleartext absolute-form HTTP with secret query — findings on visible path/query.
    {
        var client = try std.Io.net.IpAddress.connect(&proxy_addr, io, .{ .mode = .stream });
        defer client.close(io);
        const req =
            "GET http://example.com/path?token=sk-fakeSyntheticOpenAIKey1234567890 HTTP/1.1\r\n" ++
            "Host: example.com\r\nConnection: close\r\n\r\n";
        var write_buf: [512]u8 = undefined;
        var writer = client.writer(io, &write_buf);
        try writer.interface.writeAll(req);
        try writer.interface.flush();
        var response_buf: [512]u8 = undefined;
        _ = readHttpResponse(io, client, &response_buf) catch {};
    }
    try runtime.waitForIdle(2 * std.time.ns_per_s);
    {
        const events = try runtime.snapshotAuditEvents(std.testing.allocator);
        defer runtime.freeAuditEvents(std.testing.allocator, events);
        var saw_secret_exfil = false;
        for (events) |ev| {
            if (ev.event_type == .network_exfiltration_suspected and
                std.mem.indexOf(u8, ev.target, "example.com") != null)
            {
                // Redacted target must not contain the raw synthetic secret.
                try std.testing.expect(std.mem.indexOf(u8, ev.target, "sk-fakeSyntheticOpenAIKey") == null);
                saw_secret_exfil = true;
            }
        }
        try std.testing.expect(saw_secret_exfil);
    }
}

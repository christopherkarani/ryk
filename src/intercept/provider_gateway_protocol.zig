const std = @import("std");
const types = @import("provider_gateway_types.zig");

pub const Provider = types.Provider;
pub const Limits = types.Limits;

pub const ParsedInbound = struct {
    method: std.http.Method,
    target: []const u8,
    headers_end: usize,
    content_length: usize,
    forwarded_headers: std.ArrayList(std.http.Header),
    phantom: []const u8,

    pub fn deinit(self: *ParsedInbound, allocator: std.mem.Allocator) void {
        self.forwarded_headers.deinit(allocator);
    }
};

pub fn parseInbound(
    allocator: std.mem.Allocator,
    provider: Provider,
    bytes: []const u8,
    limits: Limits,
) !ParsedInbound {
    const headers_end = (std.mem.indexOf(u8, bytes, "\r\n\r\n") orelse return error.InvalidRequest) + 4;
    const line_end = std.mem.indexOf(u8, bytes[0..headers_end], "\r\n") orelse return error.InvalidRequest;
    var parts = std.mem.splitScalar(u8, bytes[0..line_end], ' ');
    const method_text = parts.next() orelse return error.InvalidRequest;
    const target = parts.next() orelse return error.InvalidRequest;
    const version = parts.next() orelse return error.InvalidRequest;
    if (parts.next() != null or !std.mem.eql(u8, version, "HTTP/1.1")) return error.InvalidRequest;
    const method = std.meta.stringToEnum(std.http.Method, method_text) orelse return error.UnsupportedMethod;
    if (method == .CONNECT or target.len == 0 or target[0] != '/' or
        std.mem.indexOf(u8, target, "://") != null or std.mem.indexOfScalar(u8, target, '#') != null)
        return error.InvalidTarget;

    var forwarded: std.ArrayList(std.http.Header) = .empty;
    errdefer forwarded.deinit(allocator);
    var content_length: ?usize = null;
    var phantom: ?[]const u8 = null;
    var saw_host = false;
    var lines = std.mem.splitSequence(u8, bytes[line_end + 2 .. headers_end - 2], "\r\n");
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.InvalidHeader;
        if (colon == 0) return error.InvalidHeader;
        const name = line[0..colon];
        const raw_value = line[colon + 1 ..];
        if (!isValidHeaderName(name) or !isValidHeaderValue(raw_value)) return error.InvalidHeader;
        const value = std.mem.trim(u8, raw_value, " ");
        if (std.ascii.eqlIgnoreCase(name, "host")) {
            if (saw_host) return error.DuplicateHeader;
            saw_host = true;
            continue;
        }
        if (std.ascii.eqlIgnoreCase(name, "content-length")) {
            if (content_length != null) return error.DuplicateHeader;
            content_length = std.fmt.parseInt(usize, value, 10) catch return error.InvalidHeader;
            if (content_length.? > limits.request_body) return error.RequestBodyTooLarge;
            continue;
        }
        if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) return error.UnsupportedTransferEncoding;
        if (isHopByHop(name) or std.ascii.eqlIgnoreCase(name, "accept-encoding")) continue;
        const anthropic_auth = std.ascii.eqlIgnoreCase(name, "x-api-key");
        const authorization = std.ascii.eqlIgnoreCase(name, "authorization");
        switch (provider) {
            .anthropic => {
                if (authorization) return error.UnexpectedAuthorizationHeader;
                if (anthropic_auth) {
                    if (phantom != null) return error.DuplicateAuthorizationHeader;
                    phantom = value;
                    continue;
                }
            },
            .openai => {
                if (anthropic_auth) return error.UnexpectedAuthorizationHeader;
                if (authorization) {
                    if (phantom != null) return error.DuplicateAuthorizationHeader;
                    if (!std.mem.startsWith(u8, value, "Bearer ")) return error.InvalidAuthorizationScheme;
                    phantom = value["Bearer ".len..];
                    if (phantom.?.len == 0) return error.InvalidAuthorizationScheme;
                    continue;
                }
            },
        }
        if (std.mem.indexOf(u8, value, "ryk-secret://") != null) return error.PhantomInUnexpectedHeader;
        try forwarded.append(allocator, .{ .name = name, .value = value });
    }
    if (!saw_host) return error.MissingHost;
    return .{
        .method = method,
        .target = target,
        .headers_end = headers_end,
        .content_length = content_length orelse 0,
        .forwarded_headers = forwarded,
        .phantom = phantom orelse return error.MissingAuthorization,
    };
}

pub fn boundedResponseContentLength(content_length: ?u64, limit: usize) !?usize {
    const value = content_length orelse return null;
    const length = std.math.cast(usize, value) orelse return error.ResponseBodyTooLarge;
    if (length > limit) return error.ResponseBodyTooLarge;
    return length;
}

pub fn copyResponseHeaders(
    allocator: std.mem.Allocator,
    head: std.http.Client.Response.Head,
    max_bytes: usize,
) ![]std.http.Header {
    var headers: std.ArrayList(std.http.Header) = .empty;
    errdefer freeHeaderList(allocator, &headers);
    var total: usize = 0;
    var iterator = head.iterateHeaders();
    while (iterator.next()) |header| {
        if (isHopByHop(header.name) or std.ascii.eqlIgnoreCase(header.name, "content-length") or
            std.ascii.eqlIgnoreCase(header.name, "transfer-encoding")) continue;
        total += header.name.len + header.value.len + 4;
        if (total > max_bytes) return error.ResponseHeadersTooLarge;
        const name = try allocator.dupe(u8, header.name);
        errdefer allocator.free(name);
        const value = try allocator.dupe(u8, header.value);
        errdefer allocator.free(value);
        try headers.append(allocator, .{ .name = name, .value = value });
    }
    return try headers.toOwnedSlice(allocator);
}

fn freeHeaderList(allocator: std.mem.Allocator, headers: *std.ArrayList(std.http.Header)) void {
    for (headers.items) |header| {
        allocator.free(header.name);
        allocator.free(header.value);
    }
    headers.deinit(allocator);
}

pub fn freeHeaders(allocator: std.mem.Allocator, headers: []std.http.Header) void {
    for (headers) |header| {
        allocator.free(header.name);
        allocator.free(header.value);
    }
    allocator.free(headers);
}

pub fn writeResponseHead(
    writer: *std.Io.Writer,
    status: u16,
    reason: []const u8,
    headers: []const std.http.Header,
    content_length: ?usize,
    chunked: bool,
) !void {
    try writer.print("HTTP/1.1 {d} {s}\r\n", .{ status, reason });
    for (headers) |header| try writer.print("{s}: {s}\r\n", .{ header.name, header.value });
    if (content_length) |length| {
        try writer.print("Content-Length: {d}\r\n", .{length});
    } else if (chunked) {
        try writer.writeAll("Transfer-Encoding: chunked\r\n");
    }
    try writer.writeAll("Connection: close\r\n\r\n");
    try writer.flush();
}

pub fn isAuthorizationError(err: anyerror) bool {
    return err == error.MissingAuthorization or err == error.DuplicateAuthorizationHeader or
        err == error.UnexpectedAuthorizationHeader or err == error.InvalidAuthorizationScheme or
        err == error.PhantomInUnexpectedHeader;
}

pub fn denialReason(err: anyerror) []const u8 {
    if (isAuthorizationError(err)) return "invalid_auth";
    return switch (err) {
        error.RequestBodyTooLarge => "request_body_too_large",
        error.InvalidTarget => "invalid_target",
        error.UnsupportedTransferEncoding => "unsupported_transfer_encoding",
        else => "invalid_request",
    };
}

fn isHopByHop(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "connection") or std.ascii.eqlIgnoreCase(name, "keep-alive") or
        std.ascii.eqlIgnoreCase(name, "proxy-authenticate") or
        std.ascii.eqlIgnoreCase(name, "proxy-authorization") or std.ascii.eqlIgnoreCase(name, "te") or
        std.ascii.eqlIgnoreCase(name, "trailer") or std.ascii.eqlIgnoreCase(name, "upgrade");
}

fn isValidHeaderName(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |byte| {
        if (std.ascii.isAlphanumeric(byte)) continue;
        switch (byte) {
            '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => continue,
            else => return false,
        }
    }
    return true;
}

fn isValidHeaderValue(value: []const u8) bool {
    for (value) |byte| {
        if (byte < 0x20 or byte == 0x7f) return false;
    }
    return true;
}

test "provider protocol accepts exact auth and rejects forwarding grammar smuggling" {
    const phantom = "ryk-secret://session/0123456789abcdef0123456789abcdef/ANTHROPIC_API_KEY/0123456789abcdef";
    const valid = try std.fmt.allocPrint(
        std.testing.allocator,
        "POST /v1/messages HTTP/1.1\r\nHost: localhost\r\nx-api-key: {s}\r\ncontent-length: 2\r\n\r\n{{}}",
        .{phantom},
    );
    defer std.testing.allocator.free(valid);
    var parsed = try parseInbound(std.testing.allocator, .anthropic, valid, .{});
    defer parsed.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings(phantom, parsed.phantom);
    try std.testing.expectEqual(@as(usize, 2), parsed.content_length);

    const malformed = try std.fmt.allocPrint(
        std.testing.allocator,
        "POST /v1/messages HTTP/1.1\r\nHost: localhost\r\nx-api-key: {s}\r\nContent-Length : 0\r\n\r\n",
        .{phantom},
    );
    defer std.testing.allocator.free(malformed);
    try std.testing.expectError(
        error.InvalidHeader,
        parseInbound(std.testing.allocator, .anthropic, malformed, .{}),
    );
}

test "provider response framing is bounded and emits one framing mode" {
    try std.testing.expectEqual(@as(?usize, 4), try boundedResponseContentLength(4, 4));
    try std.testing.expectError(error.ResponseBodyTooLarge, boundedResponseContentLength(5, 4));

    var output: [256]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&output);
    try writeResponseHead(&writer, 200, "OK", &.{}, 4, false);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\n",
        writer.buffered(),
    );
}

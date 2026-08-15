const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const brand = @import("brand.zig");
const daemon = @import("daemon.zig");
const tui = @import("ryk").tui;

pub const Metadata = struct {
    product: []const u8 = brand.versionProduct(),
    version: []const u8,
    commit: ?[]const u8,
    target: []const u8,
    target_triple: []const u8,
    build_date: ?[]const u8,
    release_channel: []const u8 = "stable",
    safety_boundary_version: []const u8 = "cli-local-dev-v1",
    safety_boundary: []const u8 = brand.safetyBoundary(),
};

pub const DaemonMetadata = struct {
    status: []const u8,
    version: ?[]const u8,
    detail: []const u8,
    binary_path: ?[]const u8,

    pub fn deinit(self: DaemonMetadata, allocator: std.mem.Allocator) void {
        if (self.version) |value| allocator.free(value);
        if (self.binary_path) |value| allocator.free(value);
    }
};

pub const Report = struct {
    cli: Metadata,
    daemon: DaemonMetadata,

    pub fn deinit(self: Report, allocator: std.mem.Allocator) void {
        self.daemon.deinit(allocator);
    }
};

pub fn current() Metadata {
    const target = targetName();
    return .{
        .version = build_options.version,
        .commit = optionalValue(build_options.commit),
        .target = target,
        .target_triple = target,
        .build_date = optionalValue(build_options.build_date),
    };
}

pub fn writePlain(writer: anytype, metadata: Metadata) !void {
    try writer.print("{s} {s} ({s}, {s})\n", .{ metadata.product, metadata.version, metadata.release_channel, metadata.target_triple });
}

pub fn writeJson(writer: anytype, metadata: Metadata) !void {
    try writer.writeAll("{\n");
    try writer.writeAll("  \"product\": ");
    try writeJsonString(writer, metadata.product);
    try writer.writeAll(",\n  \"version\": ");
    try writeJsonString(writer, metadata.version);
    try writer.writeAll(",\n  \"commit\": ");
    try writeJsonNullableString(writer, metadata.commit);
    try writer.writeAll(",\n  \"target\": ");
    try writeJsonString(writer, metadata.target);
    try writer.writeAll(",\n  \"target_triple\": ");
    try writeJsonString(writer, metadata.target_triple);
    try writer.writeAll(",\n  \"build_date\": ");
    try writeJsonNullableString(writer, metadata.build_date);
    try writer.writeAll(",\n  \"release_channel\": ");
    try writeJsonString(writer, metadata.release_channel);
    try writer.writeAll(",\n  \"safety_boundary_version\": ");
    try writeJsonString(writer, metadata.safety_boundary_version);
    try writer.writeAll(",\n  \"safety_boundary\": ");
    try writeJsonString(writer, metadata.safety_boundary);
    try writer.writeAll("\n}\n");
}

pub fn collectReport(allocator: std.mem.Allocator) !Report {
    const cli_metadata = current();
    const binary_path = binaryPathForReport(allocator);
    errdefer if (binary_path) |value| allocator.free(value);

    if (daemon.executeCli(allocator, &.{"version"})) |parsed| {
        defer parsed.deinit();
        const execution = try daemon.parseCliExecution(parsed.value.result);
        const daemon_version = try trimOwned(allocator, execution.stdout);
        errdefer allocator.free(daemon_version);
        return .{
            .cli = cli_metadata,
            .daemon = .{
                .status = "compatible",
                .version = daemon_version,
                .detail = "daemon responded to ExecuteCli version with a compatible protocol handshake.",
                .binary_path = binary_path,
            },
        };
    } else |err| {
        return .{
            .cli = cli_metadata,
            .daemon = .{
                .status = daemonStatusFromError(err),
                .version = null,
                .detail = daemonDetailFromError(err),
                .binary_path = binary_path,
            },
        };
    }
}

pub fn writePlainWithDaemon(allocator: std.mem.Allocator, writer: anytype) !void {
    var report = try collectReport(allocator);
    defer report.deinit(allocator);

    try writePlain(writer, report.cli);
    if (report.daemon.version) |daemon_version| {
        try writer.print("daemon {s} ({s})\n", .{ daemon_version, report.daemon.status });
    } else {
        try writer.print("daemon {s} ({s})\n", .{ report.daemon.status, report.daemon.detail });
    }
}

/// Human-facing version output for Phase 2: compact brand banner plus a
/// key-value grid (Version / Channel / Target / Daemon). The daemon row shows
/// `version (status)` when the daemon answered, else the status alone. The
/// `--json` machine path (`writeJsonWithDaemon`) is unchanged and byte-identical.
pub fn writeHumanBanner(allocator: std.mem.Allocator, io: std.Io, writer: anytype) !void {
    var report = try collectReport(allocator);
    defer report.deinit(allocator);

    try tui.render.banner(io, writer, report.cli.version, null);

    var daemon_buf: [160]u8 = undefined;
    const daemon_value = if (report.daemon.version) |daemon_version|
        std.fmt.bufPrint(&daemon_buf, "{s} ({s})", .{ daemon_version, report.daemon.status }) catch report.daemon.status
    else
        report.daemon.status;

    const rows = [_]tui.render.KV{
        .{ .label = "Version", .value = report.cli.version },
        .{ .label = "Channel", .value = report.cli.release_channel },
        .{ .label = "Target", .value = report.cli.target },
        .{ .label = "Daemon", .value = daemon_value },
    };
    try tui.render.keyValue(io, writer, &rows);
}

pub fn writeJsonWithDaemon(allocator: std.mem.Allocator, writer: anytype) !void {
    var report = try collectReport(allocator);
    defer report.deinit(allocator);

    try writer.writeAll("{\n");
    try writer.writeAll("  \"product\": ");
    try writeJsonString(writer, report.cli.product);
    try writer.writeAll(",\n  \"version\": ");
    try writeJsonString(writer, report.cli.version);
    try writer.writeAll(",\n  \"commit\": ");
    try writeJsonNullableString(writer, report.cli.commit);
    try writer.writeAll(",\n  \"target\": ");
    try writeJsonString(writer, report.cli.target);
    try writer.writeAll(",\n  \"target_triple\": ");
    try writeJsonString(writer, report.cli.target_triple);
    try writer.writeAll(",\n  \"build_date\": ");
    try writeJsonNullableString(writer, report.cli.build_date);
    try writer.writeAll(",\n  \"release_channel\": ");
    try writeJsonString(writer, report.cli.release_channel);
    try writer.writeAll(",\n  \"safety_boundary_version\": ");
    try writeJsonString(writer, report.cli.safety_boundary_version);
    try writer.writeAll(",\n  \"safety_boundary\": ");
    try writeJsonString(writer, report.cli.safety_boundary);
    try writer.writeAll(",\n  \"daemon\": {\n    \"status\": ");
    try writeJsonString(writer, report.daemon.status);
    try writer.writeAll(",\n    \"version\": ");
    try writeJsonNullableString(writer, report.daemon.version);
    try writer.writeAll(",\n    \"detail\": ");
    try writeJsonString(writer, report.daemon.detail);
    try writer.writeAll(",\n    \"binary_path\": ");
    try writeJsonNullableString(writer, report.daemon.binary_path);
    try writer.writeAll("\n  }\n}\n");
}

fn optionalValue(value: []const u8) ?[]const u8 {
    if (value.len == 0 or std.mem.eql(u8, value, "unknown")) return null;
    return value;
}

fn trimOwned(allocator: std.mem.Allocator, value: []const u8) ![]const u8 {
    const trimmed = std.mem.trim(u8, value, " \n\r\t");
    return try allocator.dupe(u8, trimmed);
}

fn daemonStatusFromError(err: anyerror) []const u8 {
    return switch (err) {
        error.ProtocolMismatch => "incompatible",
        error.MissingHandshake,
        error.HandshakeMalformed,
        error.DaemonProtocolError,
        error.ResponseParseFailed,
        => "degraded",
        else => "unavailable",
    };
}

fn daemonDetailFromError(err: anyerror) []const u8 {
    return daemon.errors.versionProbeDetail(err);
}

fn binaryPathForReport(allocator: std.mem.Allocator) ?[]const u8 {
    const inspection = daemon.inspectDaemonBinary(allocator) catch return null;
    if (inspection) |value| {
        defer value.deinit(allocator);
        return allocator.dupe(u8, value.path) catch null;
    }
    return null;
}

fn targetName() []const u8 {
    return @tagName(builtin.cpu.arch) ++ "-" ++ @tagName(builtin.os.tag);
}

fn writeJsonNullableString(writer: anytype, value: ?[]const u8) !void {
    if (value) |actual| {
        try writeJsonString(writer, actual);
    } else {
        try writer.writeAll("null");
    }
}

fn writeJsonString(writer: anytype, value: []const u8) !void {
    try writer.writeByte('"');
    for (value) |byte| {
        switch (byte) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            0...8, 11...12, 14...0x1f => try writer.print("\\u{x:0>4}", .{byte}),
            else => try writer.writeByte(byte),
        }
    }
    try writer.writeByte('"');
}

test "version json writer emits valid object shape with null metadata" {
    var buffer: [512]u8 = undefined;
    var stream_writer: std.Io.Writer = .fixed(&buffer);

    try writeJson(&stream_writer, .{
        .version = "1.0.0",
        .commit = null,
        .target = "x86_64-linux",
        .target_triple = "x86_64-linux",
        .build_date = null,
    });

    const json = stream_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, json, "\"product\": \"ryk\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"version\": \"1.0.0\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"commit\": null") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"target\": \"x86_64-linux\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"target_triple\": \"x86_64-linux\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"build_date\": null") != null);

    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json, .{});
    defer parsed.deinit();
    try std.testing.expect(parsed.value.object.get("version") != null);
}

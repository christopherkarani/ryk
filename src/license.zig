const std = @import("std");

const core = @import("ryk_core").core;
const Ed25519 = std.crypto.sign.Ed25519;

pub const Feature = enum {
    report_export,
    advanced_dashboard,
    policy_packs,
    team_ci_baseline,
};

pub const Tier = enum {
    free,
    pro,
    team,

    pub fn parse(value: []const u8) ?Tier {
        if (std.ascii.eqlIgnoreCase(value, "Free")) return .free;
        if (std.ascii.eqlIgnoreCase(value, "Pro")) return .pro;
        if (std.ascii.eqlIgnoreCase(value, "Team")) return .team;
        return null;
    }

    pub fn label(self: Tier) []const u8 {
        return switch (self) {
            .free => "Free",
            .pro => "Pro",
            .team => "Team",
        };
    }

    pub fn allows(self: Tier, feature: Feature) bool {
        return switch (feature) {
            // Report export is free for all tiers (local safety report, no license gate).
            .report_export => true,
            .advanced_dashboard, .policy_packs => self == .pro or self == .team,
            .team_ci_baseline => self == .team,
        };
    }
};

pub const License = struct {
    allocator: std.mem.Allocator,
    tier: Tier,
    license_id: []u8,
    subject: []u8,
    issued_at: []u8,
    expires_at: ?[]u8,
    source: []u8,
    verified: bool,

    pub fn deinit(self: *License) void {
        self.allocator.free(self.license_id);
        self.allocator.free(self.subject);
        self.allocator.free(self.issued_at);
        if (self.expires_at) |value| self.allocator.free(value);
        self.allocator.free(self.source);
        self.* = undefined;
    }

    pub fn free(allocator: std.mem.Allocator, source: []const u8) !License {
        // #379: sequential dupes need errdefer so a later OOM does not leak earlier strings.
        const license_id = try allocator.dupe(u8, "free");
        errdefer allocator.free(license_id);
        const subject = try allocator.dupe(u8, "local user");
        errdefer allocator.free(subject);
        const issued_at = try allocator.dupe(u8, "not activated");
        errdefer allocator.free(issued_at);
        const source_owned = try allocator.dupe(u8, source);
        return .{
            .allocator = allocator,
            .tier = .free,
            .license_id = license_id,
            .subject = subject,
            .issued_at = issued_at,
            .expires_at = null,
            .source = source_owned,
            .verified = false,
        };
    }
};

pub const ActivationResult = struct {
    license: License,
    path: []u8,

    pub fn deinit(self: *ActivationResult) void {
        const allocator = self.license.allocator;
        self.license.deinit();
        allocator.free(self.path);
        self.* = undefined;
    }
};

const dev_issuer = "ryk-local-dev-ed25519";
const dev_public_key_hex = "a9ab1957b0ef6d1403de507376dc5edfa2c6af06446117424e3410c35edfc087";

const dev_free_payload = "{\"version\":1,\"license_id\":\"dev-free\",\"tier\":\"Free\",\"subject\":\"local development\",\"issued_at\":\"2026-01-01\",\"expires_at\":null}";
const dev_free_signature = "53068aa9761570e9b1e6b50ad697bbd8a97a4001ff1d40eeae8638371382c5ce1fab8a4138c9ca663226443016123fd012fe6392623de02b30c277cfd9d3e606";
const dev_pro_payload = "{\"version\":1,\"license_id\":\"dev-pro\",\"tier\":\"Pro\",\"subject\":\"local development\",\"issued_at\":\"2026-01-01\",\"expires_at\":null}";
const dev_pro_signature = "fab43b7785c49e822b3f1de319c5011a797fbb283927689a78b745021ee95948b4d653c1c80fa86eff72e1613610d0bbc9d75a51ce62b6f03aeff138379bad05";
const dev_team_payload = "{\"version\":1,\"license_id\":\"dev-team\",\"tier\":\"Team\",\"subject\":\"local development\",\"issued_at\":\"2026-01-01\",\"expires_at\":null}";
const dev_team_signature = "f939c13580a836f1d4481dfd6790dba890c9242ed762565e715d07225c01e0aa18dc09d2aeedaae31a33bbe79ed6a314a6dbe6b23a628b32325befe2e3e0b701";

pub fn status(io: std.Io, allocator: std.mem.Allocator) !License {
    const path = try defaultLicensePath(allocator);
    defer allocator.free(path);
    return statusFromPath(io, allocator, path);
}

pub fn statusFromPath(io: std.Io, allocator: std.mem.Allocator, path: []const u8) !License {
    const text = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(core.limits.max_policy_file_len)) catch |err| switch (err) {
        error.FileNotFound => return License.free(allocator, "not found"),
        else => return err,
    };
    defer allocator.free(text);
    return parseSignedLicense(allocator, text, path);
}

pub fn activate(io: std.Io, allocator: std.mem.Allocator, key_or_file: []const u8) !ActivationResult {
    const path = try defaultLicensePath(allocator);
    errdefer allocator.free(path);
    const result = try activateToPath(io, allocator, key_or_file, path);
    allocator.free(path);
    return result;
}

pub fn activateToPath(io: std.Io, allocator: std.mem.Allocator, key_or_file: []const u8, destination_path: []const u8) !ActivationResult {
    const signed_text = try signedTextForActivationInput(io, allocator, key_or_file);
    defer allocator.free(signed_text);
    var parsed = try parseSignedLicense(allocator, signed_text, destination_path);
    errdefer parsed.deinit();

    if (std.fs.path.dirname(destination_path)) |parent| try std.Io.Dir.cwd().createDirPath(io, parent);
    const file = try std.Io.Dir.cwd().createFile(io, destination_path, .{});
    defer file.close(io);
    try file.writeStreamingAll(io, signed_text);
    try file.writeStreamingAll(io, "\n");
    try file.sync(io);

    return .{
        .license = parsed,
        .path = try allocator.dupe(u8, destination_path),
    };
}

pub fn defaultLicensePath(allocator: std.mem.Allocator) ![]u8 {
    if (std.c.getenv("XDG_CONFIG_HOME")) |xdg| {
        return std.fs.path.join(allocator, &.{ std.mem.sliceTo(xdg, 0), "ryk", "license.json" });
    }
    const home = std.c.getenv("HOME") orelse return error.EnvironmentVariableMissing;
    return licensePathFromHome(allocator, std.mem.sliceTo(home, 0));
}

pub fn licensePathFromHome(allocator: std.mem.Allocator, home: []const u8) ![]u8 {
    return std.fs.path.join(allocator, &.{ home, ".config", "ryk", "license.json" });
}

fn signedTextForActivationInput(io: std.Io, allocator: std.mem.Allocator, key_or_file: []const u8) ![]u8 {
    if (std.mem.eql(u8, key_or_file, "dev-free") or std.mem.eql(u8, key_or_file, "ryk-dev-free")) {
        return writeDevSignedText(allocator, dev_free_payload, dev_free_signature);
    }
    if (std.mem.eql(u8, key_or_file, "dev-pro") or std.mem.eql(u8, key_or_file, "ryk-dev-pro")) {
        return writeDevSignedText(allocator, dev_pro_payload, dev_pro_signature);
    }
    if (std.mem.eql(u8, key_or_file, "dev-team") or std.mem.eql(u8, key_or_file, "ryk-dev-team")) {
        return writeDevSignedText(allocator, dev_team_payload, dev_team_signature);
    }
    return try std.Io.Dir.cwd().readFileAlloc(io, key_or_file, allocator, .limited(core.limits.max_policy_file_len));
}

fn writeDevSignedText(allocator: std.mem.Allocator, payload: []const u8, signature: []const u8) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    const writer = &out.writer;
    try writer.writeAll("{\"version\":1,\"issuer\":");
    try core.util.writeJsonString(writer, dev_issuer);
    try writer.writeAll(",\"payload\":");
    try core.util.writeJsonString(writer, payload);
    try writer.writeAll(",\"signature\":");
    try core.util.writeJsonString(writer, signature);
    try writer.writeByte('}');
    return try out.toOwnedSlice();
}

pub fn parseSignedLicense(allocator: std.mem.Allocator, text: []const u8, source: []const u8) !License {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, text, .{});
    defer parsed.deinit();
    const object = if (parsed.value == .object) parsed.value.object else return error.InvalidLicense;
    try rejectUnknownKeys(object, &.{ "version", "issuer", "payload", "signature" });
    if (try expectInteger(try required(object, "version")) != 1) return error.InvalidLicense;
    const issuer = try expectString(try required(object, "issuer"));
    if (!std.mem.eql(u8, issuer, dev_issuer)) return error.UnsupportedLicenseIssuer;
    const payload_text = try expectString(try required(object, "payload"));
    const signature_hex = try expectString(try required(object, "signature"));
    try verifyPayloadSignature(payload_text, signature_hex);
    return parsePayload(allocator, payload_text, source, true);
}

fn parsePayload(allocator: std.mem.Allocator, payload_text: []const u8, source: []const u8, verified: bool) !License {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload_text, .{});
    defer parsed.deinit();
    const object = if (parsed.value == .object) parsed.value.object else return error.InvalidLicense;
    try rejectUnknownKeys(object, &.{ "version", "license_id", "tier", "subject", "issued_at", "expires_at" });
    if (try expectInteger(try required(object, "version")) != 1) return error.InvalidLicense;
    const tier_text = try expectString(try required(object, "tier"));
    const tier = Tier.parse(tier_text) orelse return error.UnsupportedLicenseTier;
    const expires_at: ?[]u8 = switch (try required(object, "expires_at")) {
        .null => null,
        .string => |value| try allocator.dupe(u8, value),
        else => return error.InvalidLicense,
    };
    errdefer if (expires_at) |value| allocator.free(value);
    return .{
        .allocator = allocator,
        .tier = tier,
        .license_id = try allocator.dupe(u8, try expectString(try required(object, "license_id"))),
        .subject = try allocator.dupe(u8, try expectString(try required(object, "subject"))),
        .issued_at = try allocator.dupe(u8, try expectString(try required(object, "issued_at"))),
        .expires_at = expires_at,
        .source = try allocator.dupe(u8, source),
        .verified = verified,
    };
}

fn verifyPayloadSignature(payload_text: []const u8, signature_hex: []const u8) !void {
    var public_key_bytes: [Ed25519.PublicKey.encoded_length]u8 = undefined;
    var signature_bytes: [Ed25519.Signature.encoded_length]u8 = undefined;
    try hexToBytes(&public_key_bytes, dev_public_key_hex);
    try hexToBytes(&signature_bytes, signature_hex);
    const public_key = try Ed25519.PublicKey.fromBytes(public_key_bytes);
    const signature = Ed25519.Signature.fromBytes(signature_bytes);
    signature.verify(payload_text, public_key) catch return error.InvalidLicenseSignature;
}

fn hexToBytes(out: []u8, hex: []const u8) !void {
    if (hex.len != out.len * 2) return error.InvalidHex;
    for (out, 0..) |*byte, index| {
        byte.* = try std.fmt.parseInt(u8, hex[index * 2 .. index * 2 + 2], 16);
    }
}

fn required(object: std.json.ObjectMap, name: []const u8) !std.json.Value {
    return object.get(name) orelse return error.InvalidLicense;
}

fn expectString(value: std.json.Value) ![]const u8 {
    return switch (value) {
        .string => |string| string,
        else => error.InvalidLicense,
    };
}

fn expectInteger(value: std.json.Value) !i64 {
    return switch (value) {
        .integer => |integer| integer,
        else => error.InvalidLicense,
    };
}

fn rejectUnknownKeys(object: std.json.ObjectMap, allowed: []const []const u8) !void {
    var iterator = object.iterator();
    while (iterator.next()) |entry| {
        var known = false;
        for (allowed) |name| {
            if (std.mem.eql(u8, entry.key_ptr.*, name)) {
                known = true;
                break;
            }
        }
        if (!known) return error.InvalidLicense;
    }
}

test "dev licenses verify and expose paid gates" {
    const text = try writeDevSignedText(std.testing.allocator, dev_pro_payload, dev_pro_signature);
    defer std.testing.allocator.free(text);
    var parsed = try parseSignedLicense(std.testing.allocator, text, "test");
    defer parsed.deinit();
    try std.testing.expectEqual(Tier.pro, parsed.tier);
    try std.testing.expect(parsed.verified);
    // report_export is free on every tier.
    try std.testing.expect(Tier.free.allows(.report_export));
    try std.testing.expect(parsed.tier.allows(.report_export));
    try std.testing.expect(!parsed.tier.allows(.team_ci_baseline));
}

test "tampered license signature fails closed" {
    const text = try writeDevSignedText(std.testing.allocator, dev_pro_payload, dev_team_signature);
    defer std.testing.allocator.free(text);
    try std.testing.expectError(error.InvalidLicenseSignature, parseSignedLicense(std.testing.allocator, text, "test"));
}

test "activation writes signed license to requested config path" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const path = try std.fs.path.join(std.testing.allocator, &.{ root, ".config", "ryk", "license.json" });
    defer std.testing.allocator.free(path);

    var activated = try activateToPath(std.testing.io, std.testing.allocator, "dev-team", path);
    defer activated.deinit();
    try std.testing.expectEqual(Tier.team, activated.license.tier);
    try tmp.dir.access(std.testing.io, ".config/ryk/license.json", .{});
    var current = try statusFromPath(std.testing.io, std.testing.allocator, path);
    defer current.deinit();
    try std.testing.expectEqual(Tier.team, current.tier);
}

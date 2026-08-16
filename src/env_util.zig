const std = @import("std");
const builtin = @import("builtin");

/// Duplicate an environment variable from a map, or null if unset.
pub fn getOwned(map: *const std.process.Environ.Map, allocator: std.mem.Allocator, key: []const u8) !?[]u8 {
    const value = map.get(key) orelse return null;
    return try allocator.dupe(u8, value);
}

/// Prefer the first present key among `keys`.
/// Returns an owned copy of the first non-null value, or null if none are set.
pub fn getOwnedFirst(map: *const std.process.Environ.Map, allocator: std.mem.Allocator, keys: []const []const u8) !?[]u8 {
    for (keys) |key| {
        if (try getOwned(map, allocator, key)) |value| return value;
    }
    return null;
}

/// Brand env read: `RYK_<suffix>` only.
/// `suffix` is the part after the underscore prefix (e.g. "BIN", "RESOURCE_ROOT").
pub fn getOwnedBrand(map: *const std.process.Environ.Map, allocator: std.mem.Allocator, suffix: []const u8) !?[]u8 {
    var ryk_buf: [128]u8 = undefined;
    // `RYK_` = 4 prefix chars
    if (suffix.len + 4 > ryk_buf.len) return error.NameTooLong;
    const ryk_key = try std.fmt.bufPrint(&ryk_buf, "RYK_{s}", .{suffix});
    return getOwned(map, allocator, ryk_key);
}

/// Return the user home directory for host-scoped state.
/// Windows commonly provides USERPROFILE instead of HOME; Unix keeps the
/// existing HOME-only contract so an unrelated USERPROFILE cannot redirect
/// local state.
pub fn getOwnedHome(map: *const std.process.Environ.Map, allocator: std.mem.Allocator) !?[]u8 {
    if (try getOwned(map, allocator, "HOME")) |home| return home;
    if (comptime builtin.os.tag == .windows) return getOwned(map, allocator, "USERPROFILE");
    return null;
}

/// Process-environ brand read: `RYK_<suffix>` only.
/// Returns the raw C string pointer (not owned). Null if unset.
pub fn getenvBrand(suffix: []const u8) ?[*:0]const u8 {
    var ryk_buf: [128]u8 = undefined;
    if (suffix.len + 4 >= ryk_buf.len) return null;
    const ryk_key = std.fmt.bufPrintZ(&ryk_buf, "RYK_{s}", .{suffix}) catch return null;
    return std.c.getenv(ryk_key.ptr);
}

/// True when RYK_<suffix> is a truthy flag (`1`/`true`/`yes`/`on`).
pub fn getenvBrandFlagTruthy(suffix: []const u8) bool {
    const raw_c = getenvBrand(suffix) orelse return false;
    const raw = std.mem.span(raw_c);
    return envTokenTruthy(raw);
}

fn envTokenTruthy(raw: []const u8) bool {
    const value = std.mem.trim(u8, raw, " \t\r\n");
    return std.mem.eql(u8, value, "1") or
        std.ascii.eqlIgnoreCase(value, "true") or
        std.ascii.eqlIgnoreCase(value, "yes") or
        std.ascii.eqlIgnoreCase(value, "on");
}

/// Residual `ask` hardens to deny when the operator asked for unattended/CI.
/// Coding hosts otherwise permit residual ask so agents can work; explicit deny
/// is unchanged. Signals: `RYK_UNATTENDED`, `RYK_CI`, `RYK_NONINTERACTIVE`, `CI`.
pub fn getenvUnattended() bool {
    if (getenvBrandFlagTruthy("UNATTENDED")) return true;
    if (getenvBrandFlagTruthy("CI")) return true;
    if (getenvBrandFlagTruthy("NONINTERACTIVE")) return true;
    const ci = std.c.getenv("CI") orelse return false;
    return envTokenTruthy(std.mem.span(ci));
}

/// Process home directory across Unix and Windows. Windows PowerShell commonly
/// exposes USERPROFILE without HOME; product cleanup must cover both.
pub fn getenvHome() ?[*:0]const u8 {
    if (std.c.getenv("HOME")) |home| return home;
    if (comptime builtin.os.tag == .windows) return std.c.getenv("USERPROFILE");
    return null;
}

test "envTokenTruthy accepts 1/true/yes/on and rejects empty or 0" {
    try std.testing.expect(envTokenTruthy("1"));
    try std.testing.expect(envTokenTruthy("true"));
    try std.testing.expect(envTokenTruthy("YES"));
    try std.testing.expect(envTokenTruthy("On"));
    try std.testing.expect(!envTokenTruthy(""));
    try std.testing.expect(!envTokenTruthy("0"));
    try std.testing.expect(!envTokenTruthy("false"));
    try std.testing.expect(envTokenTruthy(" 1 "));
    try std.testing.expect(envTokenTruthy("true\n"));
}

test "getOwnedFirst prefers first key" {
    var map = std.process.Environ.Map.init(std.testing.allocator);
    defer map.deinit();
    try map.put("RYK_BIN", "/new/ryk");
    try map.put("OTHER_BIN", "/other");
    const value = try getOwnedFirst(&map, std.testing.allocator, &.{ "RYK_BIN", "OTHER_BIN" });
    defer if (value) |v| std.testing.allocator.free(v);
    try std.testing.expectEqualStrings("/new/ryk", value.?);
}

test "getOwnedFirst falls back to second key" {
    var map = std.process.Environ.Map.init(std.testing.allocator);
    defer map.deinit();
    try map.put("OTHER_BIN", "/other");
    const value = try getOwnedFirst(&map, std.testing.allocator, &.{ "RYK_BIN", "OTHER_BIN" });
    defer if (value) |v| std.testing.allocator.free(v);
    try std.testing.expectEqualStrings("/other", value.?);
}

test "getOwnedFirst returns null when none set" {
    var map = std.process.Environ.Map.init(std.testing.allocator);
    defer map.deinit();
    const value = try getOwnedFirst(&map, std.testing.allocator, &.{ "RYK_BIN", "OTHER_BIN" });
    try std.testing.expect(value == null);
}

test "getOwnedBrand reads RYK_ only" {
    var map = std.process.Environ.Map.init(std.testing.allocator);
    defer map.deinit();
    try map.put("RYK_RESOURCE_ROOT", "/share/ryk");
    const value = try getOwnedBrand(&map, std.testing.allocator, "RESOURCE_ROOT");
    defer if (value) |v| std.testing.allocator.free(v);
    try std.testing.expectEqualStrings("/share/ryk", value.?);
}

test "getOwnedBrand NameTooLong" {
    // Buffer is 128; RYK_ (4) + suffix must fit.
    const too_long = "X" ** 125;
    var map = std.process.Environ.Map.init(std.testing.allocator);
    defer map.deinit();
    try std.testing.expectError(error.NameTooLong, getOwnedBrand(&map, std.testing.allocator, too_long));
}

/// Read the process environment block (POSIX libc `environ`).
pub fn processEnviron() std.process.Environ {
    if (comptime builtin.os.tag == .windows) return .{ .block = .global };
    return .{ .block = std.process.Environ.PosixBlock{
        .slice = @ptrCast(std.c.environ[0..countCEnviron() :null]),
    } };
}

fn countCEnviron() usize {
    var n: usize = 0;
    while (std.c.environ[n]) |entry| : (n += 1) {
        _ = entry;
    }
    return n;
}

/// Allocate a map of the current process environment.
pub fn createProcessMap(allocator: std.mem.Allocator) !std.process.Environ.Map {
    return try std.process.Environ.createMap(processEnviron(), allocator);
}

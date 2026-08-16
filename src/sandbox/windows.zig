const std = @import("std");
const builtin = @import("builtin");

const backend = @import("backend.zig");
const platform = @import("ryk_core").platform;

pub const implemented = true;

pub const EnvRoots = struct {
    user_profile: []const u8,
    app_data: []const u8,
    local_app_data: []const u8,
};

pub const ProtectedPathMatch = struct {
    id: []const u8,
    pattern: []const u8,
};

const protected_windows_path_rule: ProtectedPathMatch = .{
    .id = "builtin.files.read.deny[windows]",
    .pattern = "default Windows credential and browser profile paths",
};

pub fn detect() backend.ReportSet {
    var reports = backend.baseReports(.windows);
    backend.setReport(&reports, .process_supervision, .partial, "Windows direct-child cleanup is available; Job Object process-tree cleanup is not installed in this backend");
    backend.setReport(&reports, .shell_wrapping, .wrapper_only, "cmd.exe, powershell.exe, and pwsh.exe are guarded when resolved through ryk PATH shims");
    backend.setReport(&reports, .path_shims, .wrapper_only, "ryk prepends session .cmd shims to PATH for wrapper-mediated command checks");
    backend.setReport(&reports, .network_observe, .observe_only, "network policy decisions are audited for ryk-mediated actions");
    backend.setReport(&reports, .network_enforce, .unavailable, "transparent Windows network enforcement is not installed; only wrapper-mediated hooks are available");
    backend.setReport(&reports, .network_proxy_enforce, .unavailable, "loopback HTTP proxy is unavailable on Windows (ProxyUnsupportedOnWindows)");
    backend.setReport(&reports, .user_namespaces, .unsupported, "Linux user namespaces are not a Windows feature");
    backend.setReport(&reports, .mount_namespaces, .unsupported, "Linux mount namespaces are not a Windows feature");
    backend.setReport(&reports, .seccomp, .unsupported, "Linux seccomp-bpf is not a Windows feature");
    backend.setReport(&reports, .landlock, .unsupported, "Linux Landlock is not a Windows feature");
    backend.setReport(&reports, .cgroups, .unsupported, "Linux cgroup cleanup is not a Windows feature");
    backend.setReport(&reports, .strong_sandbox, .unavailable, "no Windows Filtering Platform driver, AppContainer profile, or admin-required OS sandbox is installed by default");

    return .{
        .os = .windows,
        .backend_name = "windows",
        .fallback_level = .partial,
        .fallback_note = "Windows backend uses practical local wrapper controls, staging, env filtering, MCP proxying, audit, and direct-child cleanup",
        .reports = reports,
    };
}

pub fn processEnvRoots(allocator: std.mem.Allocator) !?EnvRoots {
    const env_util = @import("../env_util.zig");
    var env_map = try env_util.createProcessMap(allocator);
    defer env_map.deinit();
    const user_profile = if (env_map.get("USERPROFILE")) |v| try allocator.dupe(u8, v) else return null;
    errdefer allocator.free(user_profile);
    const app_data = if (env_map.get("APPDATA")) |v| try allocator.dupe(u8, v) else {
        allocator.free(user_profile);
        return null;
    };
    errdefer allocator.free(app_data);
    const local_app_data = if (env_map.get("LOCALAPPDATA")) |v| try allocator.dupe(u8, v) else {
        allocator.free(user_profile);
        allocator.free(app_data);
        return null;
    };
    return .{
        .user_profile = user_profile,
        .app_data = app_data,
        .local_app_data = local_app_data,
    };
}

pub fn freeProcessEnvRoots(allocator: std.mem.Allocator, roots: EnvRoots) void {
    allocator.free(roots.user_profile);
    allocator.free(roots.app_data);
    allocator.free(roots.local_app_data);
}

pub fn protectedPathMatchProcessEnv(allocator: std.mem.Allocator, raw_path: []const u8) !?ProtectedPathMatch {
    const roots = try processEnvRoots(allocator) orelse return null;
    defer freeProcessEnvRoots(allocator, roots);
    return try protectedPathMatch(allocator, raw_path, roots);
}

pub fn protectedPathMatch(allocator: std.mem.Allocator, raw_path: []const u8, roots: EnvRoots) !?ProtectedPathMatch {
    const normalized = try normalizePathAlloc(allocator, raw_path, roots);
    defer allocator.free(normalized);

    const user_profile = try normalizePathAlloc(allocator, roots.user_profile, roots);
    defer allocator.free(user_profile);
    const app_data = try normalizePathAlloc(allocator, roots.app_data, roots);
    defer allocator.free(app_data);
    const local_app_data = try normalizePathAlloc(allocator, roots.local_app_data, roots);
    defer allocator.free(local_app_data);

    if (try isWithinRootSuffix(allocator, normalized, user_profile, ".ssh")) return protected_windows_path_rule;
    if (try isWithinRootSuffix(allocator, normalized, user_profile, ".aws")) return protected_windows_path_rule;
    if (try isWithinRootSuffix(allocator, normalized, user_profile, ".gcloud")) return protected_windows_path_rule;
    if (try isWithinRootSuffix(allocator, normalized, user_profile, ".azure")) return protected_windows_path_rule;
    if (try isWithinRootSuffix(allocator, normalized, app_data, "github cli")) return protected_windows_path_rule;
    if (try isWithinRootSuffix(allocator, normalized, app_data, "gh")) return protected_windows_path_rule;
    if (try isWithinRootSuffix(allocator, normalized, local_app_data, "google/chrome/user data")) return protected_windows_path_rule;
    if (try isWithinRootSuffix(allocator, normalized, local_app_data, "bravesoftware/brave-browser/user data")) return protected_windows_path_rule;
    if (try isWithinRootSuffix(allocator, normalized, app_data, "mozilla/firefox")) return protected_windows_path_rule;
    if (try isWithinRootSuffix(allocator, normalized, app_data, "microsoft/windows/powershell/psreadline")) return protected_windows_path_rule;

    if (hasCredentialFilename(normalized)) return protected_windows_path_rule;
    return null;
}

fn isWithinRootSuffix(allocator: std.mem.Allocator, path: []const u8, root: []const u8, suffix: []const u8) !bool {
    const joined = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ root, suffix });
    defer allocator.free(joined);
    return isWithinPath(path, joined);
}

pub fn normalizePathAlloc(allocator: std.mem.Allocator, raw_path: []const u8, roots: EnvRoots) ![]u8 {
    if (raw_path.len == 0 or std.mem.indexOfScalar(u8, raw_path, 0) != null) return error.InvalidPath;
    const trimmed = trimPowerShellPathSyntax(raw_path);
    const expanded = try expandEnvironmentVariables(allocator, trimmed, roots);
    defer allocator.free(expanded);

    var lowered = std.ArrayList(u8).empty;
    defer lowered.deinit(allocator);
    for (expanded) |char| {
        const next = if (char == '\\') '/' else std.ascii.toLower(char);
        try lowered.append(allocator, next);
    }

    const lowered_slice = lowered.items;
    var prefix: []const u8 = "";
    var rest: []const u8 = lowered_slice;
    if (lowered_slice.len >= 2 and std.ascii.isAlphabetic(lowered_slice[0]) and lowered_slice[1] == ':') {
        prefix = lowered_slice[0..2];
        rest = lowered_slice[2..];
        while (rest.len > 0 and rest[0] == '/') rest = rest[1..];
    } else if (std.mem.startsWith(u8, lowered_slice, "//")) {
        prefix = "//";
        rest = lowered_slice[2..];
    } else {
        while (rest.len > 0 and rest[0] == '/') rest = rest[1..];
    }

    var components: std.ArrayList([]u8) = .empty;
    defer {
        for (components.items) |component| allocator.free(component);
        components.deinit(allocator);
    }
    var it = std.mem.splitScalar(u8, rest, '/');
    while (it.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".")) continue;
        if (std.mem.eql(u8, component, "..")) {
            if (components.items.len > 0) allocator.free(components.pop().?);
            continue;
        }
        const owned = try allocator.dupe(u8, component);
        errdefer allocator.free(owned);
        try components.append(allocator, owned);
    }

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, prefix);
    if (prefix.len > 0 and !std.mem.eql(u8, prefix, "//") and components.items.len > 0) try out.append(allocator, '/');
    for (components.items, 0..) |component, index| {
        if (index > 0) try out.append(allocator, '/');
        try out.appendSlice(allocator, component);
    }
    return try out.toOwnedSlice(allocator);
}

fn expandEnvironmentVariables(allocator: std.mem.Allocator, value: []const u8, roots: EnvRoots) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var index: usize = 0;
    while (index < value.len) {
        if (value[index] != '%') {
            try out.append(allocator, value[index]);
            index += 1;
            continue;
        }
        const end_offset = std.mem.indexOfScalar(u8, value[index + 1 ..], '%') orelse {
            try out.append(allocator, value[index]);
            index += 1;
            continue;
        };
        const end = index + 1 + end_offset;
        const name = value[index + 1 .. end];
        if (envNameEquals(name, "USERPROFILE")) {
            try out.appendSlice(allocator, roots.user_profile);
        } else if (envNameEquals(name, "APPDATA")) {
            try out.appendSlice(allocator, roots.app_data);
        } else if (envNameEquals(name, "LOCALAPPDATA")) {
            try out.appendSlice(allocator, roots.local_app_data);
        } else {
            try out.appendSlice(allocator, value[index .. end + 1]);
        }
        index = end + 1;
    }
    return try out.toOwnedSlice(allocator);
}

fn trimPowerShellPathSyntax(value: []const u8) []const u8 {
    var trimmed = std.mem.trim(u8, value, " \t\r\n");
    if (std.mem.startsWith(u8, trimmed, "&")) trimmed = std.mem.trim(u8, trimmed[1..], " \t\r\n");
    if (trimmed.len >= 2 and ((trimmed[0] == '\'' and trimmed[trimmed.len - 1] == '\'') or (trimmed[0] == '"' and trimmed[trimmed.len - 1] == '"'))) {
        trimmed = trimmed[1 .. trimmed.len - 1];
    }
    return trimmed;
}

fn envNameEquals(actual: []const u8, expected: []const u8) bool {
    return std.ascii.eqlIgnoreCase(actual, expected);
}

fn isWithinPath(path: []const u8, root: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(path, root)) return true;
    if (path.len <= root.len) return false;
    return std.ascii.eqlIgnoreCase(path[0..root.len], root) and path[root.len] == '/';
}

fn hasCredentialFilename(normalized: []const u8) bool {
    const base = std.fs.path.basename(normalized);
    if (std.mem.eql(u8, base, ".env") or std.mem.startsWith(u8, base, ".env.")) return true;
    if (std.mem.eql(u8, base, ".npmrc") or std.mem.eql(u8, base, ".netrc")) return true;
    if (std.mem.eql(u8, base, "id_rsa") or std.mem.eql(u8, base, "id_ed25519")) return true;
    if (std.mem.endsWith(u8, base, "_rsa") or std.mem.endsWith(u8, base, "_ed25519")) return true;
    if (std.mem.indexOf(u8, base, "credential") != null) return true;
    if (std.mem.indexOf(u8, base, "credentials") != null) return true;
    if (std.mem.indexOf(u8, base, "secret") != null) return true;
    if (std.mem.indexOf(u8, base, "token") != null) return true;
    if (std.mem.endsWith(u8, base, "_history") or std.mem.endsWith(u8, base, "history.txt")) return true;
    return false;
}

test "Windows capability detector is honest about wrapper and unavailable protections" {
    const report = detect();
    try std.testing.expectEqual(platform.Os.windows, report.os);
    try std.testing.expectEqualStrings("windows", report.backend_name);
    try std.testing.expectEqual(backend.Level.active, report.get(.env_filtering).level);
    try std.testing.expectEqual(backend.Level.active, report.get(.path_staging).level);
    try std.testing.expectEqual(backend.Level.wrapper_only, report.get(.shell_wrapping).level);
    try std.testing.expectEqual(backend.Level.wrapper_only, report.get(.path_shims).level);
    try std.testing.expectEqual(backend.Level.partial, report.get(.process_supervision).level);
    try std.testing.expectEqual(backend.Level.unavailable, report.get(.network_enforce).level);
    try std.testing.expectEqual(backend.Level.unavailable, report.get(.network_proxy_enforce).level);
    try std.testing.expectEqual(backend.Level.unavailable, report.get(.strong_sandbox).level);
    try std.testing.expect(!report.featureAvailable(.strong_sandbox));
}

// No scaffold prepare path on Windows either.
test "Windows process cleanup status is partial until Job Objects are installed" {
    const report = detect();
    try std.testing.expectEqual(backend.Level.partial, report.get(.process_supervision).level);
    try std.testing.expect(std.mem.indexOf(u8, report.get(.process_supervision).note, "Job Object") != null);
}

test "Windows path normalization handles drives UNC separators traversal and case" {
    const roots: EnvRoots = .{
        .user_profile = "C:\\Users\\Dev User",
        .app_data = "C:\\Users\\Dev User\\AppData\\Roaming",
        .local_app_data = "C:\\Users\\Dev User\\AppData\\Local",
    };

    const drive = try normalizePathAlloc(std.testing.allocator, "C:\\Users\\Dev User\\PROJECT\\src\\..\\Src\\main.zig", roots);
    defer std.testing.allocator.free(drive);
    try std.testing.expectEqualStrings("c:/users/dev user/project/src/main.zig", drive);

    const unc = try normalizePathAlloc(std.testing.allocator, "\\\\Server\\Share\\Team\\..\\Repo\\file.txt", roots);
    defer std.testing.allocator.free(unc);
    try std.testing.expectEqualStrings("//server/share/repo/file.txt", unc);

    const expanded = try normalizePathAlloc(std.testing.allocator, "%USERPROFILE%\\.ssh\\id_ed25519", roots);
    defer std.testing.allocator.free(expanded);
    try std.testing.expectEqualStrings("c:/users/dev user/.ssh/id_ed25519", expanded);

    const escaped = try normalizePathAlloc(std.testing.allocator, "'%APPDATA%\\GitHub CLI\\hosts.yml'", roots);
    defer std.testing.allocator.free(escaped);
    try std.testing.expectEqualStrings("c:/users/dev user/appdata/roaming/github cli/hosts.yml", escaped);
}

test "Windows protected path matching uses simulated profile roots only" {
    const roots: EnvRoots = .{
        .user_profile = "C:\\Users\\Dev User",
        .app_data = "C:\\Users\\Dev User\\AppData\\Roaming",
        .local_app_data = "C:\\Users\\Dev User\\AppData\\Local",
    };

    const protected = [_][]const u8{
        "%USERPROFILE%\\.ssh\\id_ed25519",
        "c:/users/dev user/.AWS/credentials",
        "%APPDATA%\\GitHub CLI\\hosts.yml",
        "%APPDATA%\\gh\\hosts.yml",
        "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data",
        "%LOCALAPPDATA%\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Cookies",
        "%APPDATA%\\Mozilla\\Firefox\\Profiles\\fake.default\\cookies.sqlite",
        "%APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
        "repo\\.env",
        "repo\\private_token.txt",
    };
    for (protected) |path| {
        try std.testing.expect((try protectedPathMatch(std.testing.allocator, path, roots)) != null);
    }

    try std.testing.expect((try protectedPathMatch(std.testing.allocator, "C:\\Users\\Dev User\\project\\src\\main.zig", roots)) == null);
}

/// Same roots as the drive/UNC/USERPROFILE happy-path fixtures above.
const windows_normalize_oom_roots: EnvRoots = .{
    .user_profile = "C:\\Users\\Dev User",
    .app_data = "C:\\Users\\Dev User\\AppData\\Roaming",
    .local_app_data = "C:\\Users\\Dev User\\AppData\\Local",
};

fn windowsNormalizeOomDriveUncProbe(allocator: std.mem.Allocator) !void {
    const roots = windows_normalize_oom_roots;

    // Clone existing fixtures so the component loop actually dupes. Drive-only
    // "C:" never enters that loop.
    const drive = try normalizePathAlloc(allocator, "C:\\Users\\Dev User\\PROJECT\\src\\..\\Src\\main.zig", roots);
    defer allocator.free(drive);
    try std.testing.expectEqualStrings("c:/users/dev user/project/src/main.zig", drive);

    const unc = try normalizePathAlloc(allocator, "\\\\Server\\Share\\Team\\..\\Repo\\file.txt", roots);
    defer allocator.free(unc);
    try std.testing.expectEqualStrings("//server/share/repo/file.txt", unc);

    const expanded = try normalizePathAlloc(allocator, "%USERPROFILE%\\.ssh\\id_ed25519", roots);
    defer allocator.free(expanded);
    try std.testing.expectEqualStrings("c:/users/dev user/.ssh/id_ed25519", expanded);
}

fn windowsNormalizeOomProtectedMatchProbe(allocator: std.mem.Allocator) !void {
    const roots = windows_normalize_oom_roots;
    // OOM must stay error.OutOfMemory — never swallow as not-protected (null).
    const match = try protectedPathMatch(allocator, "%USERPROFILE%\\.ssh\\id_ed25519", roots);
    if (match == null) return error.TestUnexpectedResult;
}

test "WindowsNormalizeOom normalizePathAlloc OOM ownership" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        windowsNormalizeOomDriveUncProbe,
        .{},
    );
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        windowsNormalizeOomProtectedMatchProbe,
        .{},
    );
}

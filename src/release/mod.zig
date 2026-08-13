const std = @import("std");

pub const ArtifactTarget = struct {
    os: []const u8,
    arch: []const u8,
    extension: []const u8,
};

pub const targets = [_]ArtifactTarget{
    .{ .os = "darwin", .arch = "amd64", .extension = "tar.gz" },
    .{ .os = "darwin", .arch = "arm64", .extension = "tar.gz" },
    .{ .os = "linux", .arch = "amd64", .extension = "tar.gz" },
    .{ .os = "linux", .arch = "arm64", .extension = "tar.gz" },
    .{ .os = "windows", .arch = "amd64", .extension = "zip" },
};

pub fn artifactName(buffer: []u8, product: []const u8, version: []const u8, target: ArtifactTarget) ![]const u8 {
    return std.fmt.bufPrint(buffer, "{s}-v{s}-{s}-{s}.{s}", .{
        product,
        version,
        target.os,
        target.arch,
        target.extension,
    });
}

test "phase 19 artifact names match release contract" {
    var names: [targets.len][96]u8 = undefined;
    const expected = [_][]const u8{
        "ryk-v0.19.0-darwin-amd64.tar.gz",
        "ryk-v0.19.0-darwin-arm64.tar.gz",
        "ryk-v0.19.0-linux-amd64.tar.gz",
        "ryk-v0.19.0-linux-arm64.tar.gz",
        "ryk-v0.19.0-windows-amd64.zip",
    };

    for (targets, 0..) |target, index| {
        const actual = try artifactName(&names[index], "ryk", "0.19.0", target);
        try std.testing.expectEqualStrings(expected[index], actual);
    }
}

test "phase 19 package and workflow files are present" {
    const required_files = [_][]const u8{
        "scripts/install.sh",
        "scripts/install.ps1",
        "scripts/build-release.sh",
        "scripts/build-release.ps1",
        "scripts/generate-checksums.sh",
        "scripts/generate-sbom.sh",
        "scripts/stage-release-payload.sh",
        "scripts/check-release-payload-secrets.sh",
        "scripts/docker-install-layout-smoke-test.sh",
        "packaging/homebrew/Formula/ryk.rb",
        "packaging/scoop/ryk.json",
        "packaging/winget/ryk.yaml",
        "packaging/npm/package.json",
        "packaging/npm/bin/ryk.js",
        "packaging/docker/Dockerfile",
        ".github/workflows/build.yml",
        ".github/workflows/test.yml",
        ".github/workflows/release.yml",
    };

    for (required_files) |path| {
        var file = try std.Io.Dir.cwd().openFile(std.testing.io, path, .{});
        file.close(std.testing.io);
    }
}

test "release builder stages tracked files and scans every payload" {
    const text = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, "scripts/build-release.sh", std.testing.allocator, .limited(256 * 1024));
    defer std.testing.allocator.free(text);
    try std.testing.expect(std.mem.indexOf(u8, text, "stage-release-payload.sh") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "check-release-payload-secrets.sh") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "cp -R docs policies") == null);
}

test "phase 19 release files include integrity checks without obvious credentials" {
    const checked_files = [_][]const u8{
        "scripts/install.sh",
        "scripts/install.ps1",
        "packaging/homebrew/Formula/ryk.rb",
        "packaging/scoop/ryk.json",
        "packaging/winget/ryk.yaml",
        "packaging/npm/package.json",
        "packaging/npm/bin/ryk.js",
        "packaging/docker/Dockerfile",
        ".github/workflows/build.yml",
        ".github/workflows/test.yml",
        ".github/workflows/release.yml",
    };

    for (checked_files) |path| {
        const text = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, std.testing.allocator, .limited(256 * 1024));
        defer std.testing.allocator.free(text);
        try std.testing.expect(std.mem.indexOf(u8, text, "checksum") != null or std.mem.indexOf(u8, text, "Checksum") != null or std.mem.indexOf(u8, text, "sha256") != null);
        try std.testing.expect(std.mem.indexOf(u8, text, "BEGIN PRIVATE KEY") == null);
        try std.testing.expect(std.mem.indexOf(u8, text, "ghp_") == null);
        try std.testing.expect(std.mem.indexOf(u8, text, "sk-") == null);
        try std.testing.expect(std.mem.indexOf(u8, text, "AKIA") == null);
    }
}

test "phase 19 Dockerfile references installed ryk binary" {
    const text = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, "packaging/docker/Dockerfile", std.testing.allocator, .limited(64 * 1024));
    defer std.testing.allocator.free(text);
    try std.testing.expectEqual(@as(usize, 1), countOccurrences(text, "COPY ryk /opt/ryk"));
    try std.testing.expect(std.mem.indexOf(u8, text, "/opt/ryk/bin/ryk") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "RYK_RESOURCE_ROOT=\"/opt/ryk\"") != null);
    // Product packaging is CLI-only; daemon binary must not be required.
    try std.testing.expect(std.mem.indexOf(u8, text, "ryk-daemon") != null);
}

fn countOccurrences(haystack: []const u8, needle: []const u8) usize {
    var count: usize = 0;
    var index: usize = 0;
    while (std.mem.indexOf(u8, haystack[index..], needle)) |match| {
        count += 1;
        index += match + needle.len;
    }
    return count;
}

test "GitHub composite action does not shell-interpolate command input before ryk" {
    const text = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, ".github/actions/ryk-run/action.yml", std.testing.allocator, .limited(64 * 1024));
    defer std.testing.allocator.free(text);
    try std.testing.expect(std.mem.indexOf(u8, text, "ryk run --mode ci -- ${{ inputs.command }}") == null);
    try std.testing.expect(std.mem.indexOf(u8, text, "RYK_ACTION_COMMAND: ${{ inputs.command }}") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "ryk run --mode ci -- bash -c \"$RYK_ACTION_COMMAND\"") != null);
}

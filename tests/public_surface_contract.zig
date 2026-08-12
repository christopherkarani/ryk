const std = @import("std");

fn expectContains(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) == null) {
        std.debug.print("expected public text not found: {s}\n", .{needle});
        return error.ExpectedTextMissing;
    }
}

fn expectNotContains(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) != null) {
        std.debug.print("forbidden public text found: {s}\n", .{needle});
        return error.ForbiddenTextFound;
    }
}

fn expectMissing(path: []const u8) !void {
    try std.testing.expectError(error.FileNotFound, std.Io.Dir.cwd().access(std.testing.io, path, .{}));
}

test "private go-to-market material is excluded from the public repository" {
    const excluded = [_][]const u8{
        "go_to_market/README.md",
        "go_to_market/30-day-plan.md",
        "go_to_market/icp.md",
        "go_to_market/outreach/founder-email-1.md",
        "go_to_market/pilots/paid-pilot-offer.md",
        "go_to_market/safety/claims-to-avoid.md",
        "go_to_market/target-account-template.csv",
        "go_to_market/internal-output-summary.md",
    };
    for (excluded) |path| try expectMissing(path);
}

test "public docs contain no customer acquisition collateral" {
    const allocator = std.testing.allocator;
    const public_files = [_][]const u8{
        "README.md",
        "docs/README.md",
        "docs/quickstart.md",
        "docs/commands.md",
        "docs/ci.md",
        "docs/presets.md",
    };
    const forbidden = [_][]const u8{
        "paid pilot",
        "design partner",
        "target accounts",
        "founder-led outreach",
        "customer acquisition",
        "book 10 customer discovery/demo calls",
        "$10k-$25k",
        "warm intro",
        "automated sender",
        "scrape private",
    };

    for (public_files) |path| {
        const text = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, allocator, .limited(512 * 1024));
        defer allocator.free(text);
        for (forbidden) |phrase| try expectNotContains(text, phrase);
    }
}

test "agent handoff docs are excluded from the public repository" {
    const excluded = [_][]const u8{
        "docs/handoffs/coding-agent-pack-ux-2026-08-11.md",
        "docs/handoffs/coding-agent-pack-ux-prompt.md",
    };
    for (excluded) |path| try expectMissing(path);
}

test "gitignore blocks handoffs, releases, and orca husks" {
    const text = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, ".gitignore", std.testing.allocator, .limited(512 * 1024));
    defer std.testing.allocator.free(text);
    try expectContains(text, "docs/handoffs/");
    try expectContains(text, "docs/releases/");
    try expectContains(text, "orca-*/");
}

test "public README stays product-focused and safety-bounded" {
    const text = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, "README.md", std.testing.allocator, .limited(512 * 1024));
    defer std.testing.allocator.free(text);
    try expectContains(text, "ryk");
    try expectContains(text, "local");
    try expectContains(text, "policy");
    try expectNotContains(text, "certified safe");
    try expectNotContains(text, "FAA approved");
    try expectNotContains(text, "BVLOS-ready");
    try expectNotContains(text, "real-flight-ready");
    try expectNotContains(text, "BEGIN PRIVATE KEY");
    try expectNotContains(text, "ghp_");
    try expectNotContains(text, "sk-");
}

test "public README does not contain you would be surprised" {
    const text = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, "README.md", std.testing.allocator, .limited(512 * 1024));
    defer std.testing.allocator.free(text);
    try expectNotContains(text, "you would be surprised");
}

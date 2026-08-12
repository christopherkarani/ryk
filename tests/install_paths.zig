const std = @import("std");
const posix = std.posix;
const plugin = @import("ryk").cli.plugin;
const plugin_install = @import("ryk").cli.plugin_install;

test "phase 44 install from subdirectory writes plugins under workspace root" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(std.testing.io, ".ryk");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = ".ryk/policy.yaml", .data = "mode: generic-agent\n" });
    try tmp.dir.createDirPath(std.testing.io, "nested/work");

    const plugin_dir = try plugin.resolveBundledPath(std.testing.io, std.testing.allocator, "integrations/codex-plugin");
    defer std.testing.allocator.free(plugin_dir);
    const template_path = try plugin.resolveBundledPath(std.testing.io, std.testing.allocator, "integrations/codex-plugin/examples/marketplace.json");
    defer std.testing.allocator.free(template_path);
    const plugin_dir_abs = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, plugin_dir, std.testing.allocator);
    defer std.testing.allocator.free(plugin_dir_abs);
    const template_abs = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, template_path, std.testing.allocator);
    defer std.testing.allocator.free(template_abs);

    const nested_path = try tmp.dir.realPathFileAlloc(std.testing.io, "nested/work", std.testing.allocator);
    defer std.testing.allocator.free(nested_path);
    const original_cwd = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(original_cwd);
    try std.Io.Threaded.chdir(nested_path);
    defer std.Io.Threaded.chdir(original_cwd) catch {};

    const workspace_root = try plugin_install.resolveWorkspaceInstallRoot(std.testing.io, std.testing.allocator);
    defer std.testing.allocator.free(workspace_root);
    const workspace_canonical = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, workspace_root, std.testing.allocator);
    defer std.testing.allocator.free(workspace_canonical);
    const tmp_root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(tmp_root);
    try std.testing.expectEqualStrings(tmp_root, workspace_canonical);

    const marketplace_json = try plugin_install.loadMarketplaceTemplate(
        std.testing.io,
        std.testing.allocator,
        template_abs,
        "./integrations/codex-plugin",
        "./ryk",
    );
    defer std.testing.allocator.free(marketplace_json);

    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    try plugin_install.installCodexPlugin(std.testing.io, std.testing.allocator, plugin_dir_abs, workspace_root, marketplace_json, &stdout_writer);

    const user_plugin_path = try std.fs.path.join(
        std.testing.allocator,
        &.{ workspace_root, ".agents", "plugins", "ryk", ".codex-plugin", "plugin.json" },
    );
    defer std.testing.allocator.free(user_plugin_path);
    try std.testing.expect(plugin.fileExistsAbsolute(std.testing.io, user_plugin_path));

    var report = try plugin.collectPluginDoctorReport(std.testing.io, std.testing.allocator);
    defer plugin.deinitPluginDoctorReport(&report, std.testing.allocator);
    try std.testing.expect(report.marketplace.codex_user_plugin);
    try std.testing.expectEqualStrings(tmp_root, report.workspace_root);
}

test "phase 44 openClaw plugin list JSON ignores decoy ryk substring" {
    const decoy_json =
        \\[
        \\  {
        \\    "id": "other",
        \\    "name": "not-orca",
        \\    "description": "mentions ryk in prose only"
        \\  }
        \\]
    ;
    try std.testing.expect(!plugin.openClawPluginListedInJson(std.testing.allocator, decoy_json));

    const installed_json =
        \\[
        \\  {
        \\    "id": "ryk",
        \\    "name": "ryk"
        \\  }
        \\]
    ;
    try std.testing.expect(plugin.openClawPluginListedInJson(std.testing.allocator, installed_json));
}

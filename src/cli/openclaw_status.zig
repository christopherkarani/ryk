//! OpenClaw protection honesty for doctor/install surfaces.
//! Standing product claim until live-host E2E exists: the supported OpenClaw
//! deployment starts with the curl-installed ryk binary and `ryk unattended`.
//! Registry/npm paths are sunset and metadata/discovery passes are unprotected.

const std = @import("std");
const core = @import("ryk_core").core;

/// Shared enforcement note (plain + JSON). Single source of truth for doctor copy.
pub const enforcement_note =
    "supported install is curl-installed ryk + ryk unattended setup; npm/ClawHub paths are sunset; metadata/discovery passes are unprotected; prefer wrapper: ryk run -- openclaw";

/// Hook grade until real-host E2E proves veto. Not a boolean "enforcing" claim.
pub const hook_grade = "unverified";

/// Registry install paths are retained as an explicit sunset marker.
pub const npm_path_label = "sunset";

pub const supported_install_command = "curl -fsSL https://rykanv.com/install | sh";

/// Preferred protection path (grade wrapper).
pub const preferred_wrapper = "ryk run -- openclaw";

/// Plain-text honesty lines for `ryk plugin doctor openclaw`.
pub fn writeDoctorHonesty(stdout: anytype) !void {
    try stdout.print("  enforcement: {s}\n", .{enforcement_note});
    try stdout.writeAll("  hook grade: unverified (no live host E2E); installed != protected\n");
    try stdout.print("  supported install: {s}\n", .{supported_install_command});
    try stdout.writeAll("  next: ryk unattended setup --hosts openclaw\n");
    try stdout.writeAll("  note: npm/ClawHub distribution is sunset; CLI metadata/discovery passes are unprotected\n");
    try stdout.writeAll("  verify: openclaw plugins inspect ryk --runtime --json; openclaw gateway status --deep --require-rpc; openclaw gateway call ryk.unattended --json\n");
}

/// Append OpenClaw honesty fields inside an existing `openclaw_paths` JSON object
/// (caller has already written detection_note and a trailing comma is expected before this).
pub fn writePathsJsonHonesty(stdout: anytype) !void {
    try stdout.writeAll("    \"enforcement_note\": ");
    try core.util.writeJsonString(stdout, enforcement_note);
    try stdout.writeAll(",\n");
    try stdout.writeAll("    \"hook_grade\": ");
    try core.util.writeJsonString(stdout, hook_grade);
    try stdout.writeAll(",\n");
    try stdout.writeAll("    \"npm_path\": ");
    try core.util.writeJsonString(stdout, npm_path_label);
    try stdout.writeAll("\n");
}

/// Install-path guidance (dry-run / install openclaw).
pub fn writeInstallPaths(stdout: anytype) !void {
    try stdout.writeAll("  install paths for OpenClaw:\n");
    try stdout.print("    supported: {s}\n", .{supported_install_command});
    try stdout.writeAll("    configure: ryk unattended setup --hosts openclaw\n");
    try stdout.print("    fallback:  {s}  (wrapper)\n", .{preferred_wrapper});
    try stdout.writeAll("    npm/ClawHub: sunset; do not use for deployment\n");
}

test "openclaw honesty constants are stable tokens" {
    try std.testing.expect(std.mem.indexOf(u8, enforcement_note, "metadata") != null);
    try std.testing.expect(std.mem.indexOf(u8, enforcement_note, preferred_wrapper) != null);
    try std.testing.expectEqualStrings("unverified", hook_grade);
    try std.testing.expectEqualStrings("sunset", npm_path_label);
    try std.testing.expect(std.mem.indexOf(u8, supported_install_command, "curl") != null);
}

test "writeDoctorHonesty includes enforcement and wrapper" {
    var buf: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeDoctorHonesty(&w);
    const out = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "sunset") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, preferred_wrapper) != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "installed != protected") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "hook grade: unverified") != null);
}

test "writePathsJsonHonesty uses hook_grade not hook_enforcing" {
    var buf: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writePathsJsonHonesty(&w);
    const out = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "\"enforcement_note\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"hook_grade\": \"unverified\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"npm_path\": \"sunset\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "hook_enforcing") == null);
}

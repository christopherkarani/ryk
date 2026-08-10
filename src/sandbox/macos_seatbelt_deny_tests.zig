//! Seatbelt real-FS deny and canary integration tests.
//! Imported from macos_seatbelt.zig so production apply code stays scannable.
//! Mirrors landlock_deny_tests.zig.

const std = @import("std");
const builtin = @import("builtin");
const profile = @import("profile.zig");
const canary = @import("canary.zig");
const macos_seatbelt = @import("macos_seatbelt.zig");

const sandboxInitAvailable = macos_seatbelt.sandboxInitAvailable;
const detectProductVersion = macos_seatbelt.detectProductVersion;
const isMatrixMajor = macos_seatbelt.isMatrixMajor;
const evaluateSupport = macos_seatbelt.evaluateSupport;
const prepareForChildApply = macos_seatbelt.prepareForChildApply;
const prepareForChildApplyWithOptions = macos_seatbelt.prepareForChildApplyWithOptions;
const applyInChild = macos_seatbelt.applyInChild;
const SupportStatus = macos_seatbelt.SupportStatus;

fn waitExitCode(pid: std.c.pid_t) !u8 {
    var status: c_int = 0;
    // Retry waitpid on EINTR. On other failure return error — do not invent exit 0
    // from the zero-initialized status when waitpid never reaped the child.
    while (true) {
        const rc = std.c.waitpid(pid, &status, 0);
        if (rc >= 0) break;
        if (std.c.errno(rc) == .INTR) continue;
        return error.WaitpidFailed;
    }
    try std.testing.expect((status & 0x7f) == 0);
    return @intCast((status >> 8) & 0xff);
}

fn childExecNc(port_text: [*:0]const u8) noreturn {
    const argv = [_:null]?[*:0]const u8{
        "nc",
        "-z",
        "-G",
        "1",
        "127.0.0.1",
        port_text,
        null,
    };
    _ = std.c.execve("/usr/bin/nc", @ptrCast(&argv), @ptrCast(std.c.environ));
    std.c._exit(8);
}

// CTRL template: unsandboxed canary readable; sandboxed child denies outside grant,
// allows workspace neighbor read/write, and denies control-root write (.ryk + .git).
// Uses prepare SBPL + applyInChild.
// Exit codes from child: 0=ok, 2=apply fail, 3=outside readable (leak), 4=ws read fail,
// 5=ws write fail, 6=.ryk control writable (leak), 7=.git control writable (leak).
test "real FS deny: outside canary denied; workspace readable and writable" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    if (!sandboxInitAvailable()) return error.SkipZigTest;

    const ver = try detectProductVersion();
    // Only claim matrix enforcement when this host major is in the advertised range.
    try std.testing.expect(isMatrixMajor(ver.major));
    try std.testing.expectEqual(SupportStatus.supported, evaluateSupport());

    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    // Control roots must exist under the workspace before apply so write probes
    // target real paths (profile always carves {workspace}/.ryk and .git).
    try ws_tmp.dir.createDirPath(io, ".ryk");
    try ws_tmp.dir.createDirPath(io, ".git");
    // realPath so Seatbelt grants match kernel paths (/private/var vs /var).
    const ws_root = try ws_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(ws_root);

    var out_tmp = std.testing.tmpDir(.{});
    defer out_tmp.cleanup();
    const out_root = try out_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(out_root);

    var synth = try canary.generate(allocator);
    defer synth.deinit();

    // Outside canary (must NOT be under workspace grant).
    try out_tmp.dir.writeFile(io, .{ .sub_path = "canary.txt", .data = synth.body });
    const canary_path = try std.fs.path.join(allocator, &.{ out_root, "canary.txt" });
    defer allocator.free(canary_path);
    const canary_z = try allocator.dupeZ(u8, canary_path);
    defer allocator.free(canary_z);

    // Workspace neighbor (must remain readable/writable under grant).
    try ws_tmp.dir.writeFile(io, .{ .sub_path = "neighbor.txt", .data = "WORKSPACE_NEIGHBOR_OK" });
    const neighbor_path = try std.fs.path.join(allocator, &.{ ws_root, "neighbor.txt" });
    defer allocator.free(neighbor_path);
    const neighbor_z = try allocator.dupeZ(u8, neighbor_path);
    defer allocator.free(neighbor_z);

    const write_probe_path = try std.fs.path.join(allocator, &.{ ws_root, "write_probe.txt" });
    defer allocator.free(write_probe_path);
    const write_probe_z = try allocator.dupeZ(u8, write_probe_path);
    defer allocator.free(write_probe_z);

    const control_write_path = try std.fs.path.join(allocator, &.{ ws_root, ".ryk", "policy.yaml" });
    defer allocator.free(control_write_path);
    const control_write_z = try allocator.dupeZ(u8, control_write_path);
    defer allocator.free(control_write_z);

    const git_control_write_path = try std.fs.path.join(allocator, &.{ ws_root, ".git", "phase2-probe" });
    defer allocator.free(git_control_write_path);
    const git_control_write_z = try allocator.dupeZ(u8, git_control_write_path);
    defer allocator.free(git_control_write_z);

    // CTRL-BASELINE: unsandboxed parent can read the outside canary.
    {
        const baseline = try std.Io.Dir.cwd().readFileAlloc(io, canary_path, allocator, .limited(4096));
        defer allocator.free(baseline);
        try std.testing.expectEqualStrings(synth.body, baseline);
    }
    // Neighbor also readable without sandbox.
    {
        const baseline_ws = try std.Io.Dir.cwd().readFileAlloc(io, neighbor_path, allocator, .limited(4096));
        defer allocator.free(baseline_ws);
        try std.testing.expectEqualStrings("WORKSPACE_NEIGHBOR_OK", baseline_ws);
    }

    // Prepare real product SBPL from compiled profile (not a hand-rolled minimal string).
    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = ws_root,
        .include_tmp = false,
    });
    defer compiled.deinit();
    // Outside path must not sit under the workspace grant.
    try std.testing.expect(!compiled.isAgentWritable(canary_path));
    try std.testing.expect(compiled.isAgentWritable(neighbor_path));
    // Control paths under workspace must not be agent-writable (.ryk + .git).
    try std.testing.expect(!compiled.isAgentWritable(control_write_path));
    try std.testing.expect(!compiled.isAgentWritable(git_control_write_path));

    const prepared = prepareForChildApply(allocator, &compiled);
    defer if (prepared.sbpl_z) |p| allocator.free(p);
    try std.testing.expectEqual(.prepared, prepared.status);
    try std.testing.expect(prepared.sbpl_z != null);
    const sbpl_z = prepared.sbpl_z.?;

    const pid = std.c.fork();
    if (pid < 0) return error.SkipZigTest;
    if (pid == 0) {
        applyInChild(sbpl_z.ptr) catch std.c._exit(2);

        // TEST-DENY: outside canary must not be readable.
        const outside_fd = std.c.open(canary_z.ptr, .{ .ACCMODE = .RDONLY });
        if (outside_fd >= 0) {
            _ = std.c.close(outside_fd);
            std.c._exit(3); // leak — outside grant hole
        }

        // Workspace neighbor must still be readable.
        const ws_fd = std.c.open(neighbor_z.ptr, .{ .ACCMODE = .RDONLY });
        if (ws_fd < 0) std.c._exit(4);
        var buf: [64]u8 = undefined;
        const n = std.c.read(ws_fd, &buf, buf.len);
        _ = std.c.close(ws_fd);
        if (n < 0) std.c._exit(4);
        if (n != "WORKSPACE_NEIGHBOR_OK".len) std.c._exit(4);
        if (!std.mem.eql(u8, buf[0..@intCast(n)], "WORKSPACE_NEIGHBOR_OK")) std.c._exit(4);

        // Workspace write must succeed.
        const wfd = std.c.open(write_probe_z.ptr, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, @as(std.c.mode_t, 0o600));
        if (wfd < 0) std.c._exit(5);
        const wrote = std.c.write(wfd, "wrote", 5);
        _ = std.c.close(wfd);
        if (wrote != 5) std.c._exit(5);

        // F-3: control root write must fail under live Seatbelt (not SBPL string only).
        const cfd = std.c.open(
            control_write_z.ptr,
            .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true },
            @as(std.c.mode_t, 0o600),
        );
        if (cfd >= 0) {
            _ = std.c.close(cfd);
            std.c._exit(6); // .ryk control write leak
        }

        // Phase 2: workspace .git is a default control root — same write-deny class as .ryk.
        const gfd = std.c.open(
            git_control_write_z.ptr,
            .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true },
            @as(std.c.mode_t, 0o600),
        );
        if (gfd >= 0) {
            _ = std.c.close(gfd);
            std.c._exit(7); // .git control write leak
        }

        std.c._exit(0);
    }

    var status: c_int = 0;
    _ = std.c.waitpid(pid, &status, 0);
    const exited = (status & 0x7f) == 0;
    try std.testing.expect(exited);
    const exit_code: u8 = @intCast((status >> 8) & 0xff);
    // Surface distinct failures for the proof report (do not collapse to a single assert).
    switch (exit_code) {
        0 => {},
        2 => return error.SeatbeltApplyFailedOnHost,
        3 => return error.OutsideCanaryReadableUnderSandbox,
        4 => return error.WorkspaceNeighborUnreadableUnderSandbox,
        5 => return error.WorkspaceWriteFailedUnderSandbox,
        6 => return error.ControlRootWritableUnderSandbox,
        7 => return error.GitControlRootWritableUnderSandbox,
        else => return error.UnexpectedSandboxChildExit,
    }
    try std.testing.expectEqual(@as(u8, 0), exit_code);

    // Parent can still read the write probe produced by the sandboxed child.
    const probe = try std.Io.Dir.cwd().readFileAlloc(io, write_probe_path, allocator, .limited(64));
    defer allocator.free(probe);
    try std.testing.expectEqualStrings("wrote", probe);

    // Control files must not have been created by the sandboxed child.
    const ctrl_probe = std.Io.Dir.cwd().access(io, control_write_path, .{});
    try std.testing.expectError(error.FileNotFound, ctrl_probe);
    const git_ctrl_probe = std.Io.Dir.cwd().access(io, git_control_write_path, .{});
    try std.testing.expectError(error.FileNotFound, git_ctrl_probe);
}

test "real network route forcing: proxy port allowed and neighboring loopback port denied" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    if (!sandboxInitAvailable()) return error.SkipZigTest;
    const ver = try detectProductVersion();
    try std.testing.expect(isMatrixMajor(ver.major));

    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var allowed_server = try (try std.Io.net.IpAddress.parse("127.0.0.1", 0)).listen(io, .{ .reuse_address = true });
    defer allowed_server.deinit(io);
    const allowed_port = allowed_server.socket.address.getPort();

    var denied_server = try (try std.Io.net.IpAddress.parse("127.0.0.1", 0)).listen(io, .{ .reuse_address = true });
    defer denied_server.deinit(io);
    const denied_port = denied_server.socket.address.getPort();
    if (allowed_port == denied_port) return error.SkipZigTest;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    try ws_tmp.dir.createDirPath(io, ".ryk");
    const ws_root = try ws_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(ws_root);

    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = ws_root,
        .include_tmp = false,
    });
    defer compiled.deinit();

    const prepared = macos_seatbelt.prepareForChildApplyWithOptions(
        allocator,
        &compiled,
        .supported,
        .{ .network_route_forcing = .{ .proxy_port = allowed_port } },
    );
    defer if (prepared.sbpl_z) |p| allocator.free(p);
    try std.testing.expectEqual(.prepared, prepared.status);
    const sbpl_z = prepared.sbpl_z orelse return error.SeatbeltApplyFailedOnHost;

    const denied_pid = std.c.fork();
    if (denied_pid < 0) return error.SkipZigTest;
    if (denied_pid == 0) {
        applyInChild(sbpl_z.ptr) catch std.c._exit(2);
        var port_buf: [8]u8 = undefined;
        const port_text = std.fmt.bufPrintZ(&port_buf, "{d}", .{denied_port}) catch std.c._exit(7);
        childExecNc(port_text.ptr);
    }
    const denied_code = try waitExitCode(denied_pid);
    try std.testing.expect(denied_code != 0);
    try std.testing.expect(denied_code != 2);
    try std.testing.expect(denied_code != 8);

    const allowed_pid = std.c.fork();
    if (allowed_pid < 0) return error.SkipZigTest;
    if (allowed_pid == 0) {
        applyInChild(sbpl_z.ptr) catch std.c._exit(2);
        var port_buf: [8]u8 = undefined;
        const port_text = std.fmt.bufPrintZ(&port_buf, "{d}", .{allowed_port}) catch std.c._exit(7);
        childExecNc(port_text.ptr);
    }
    const allowed_code = try waitExitCode(allowed_pid);
    try std.testing.expectEqual(@as(u8, 0), allowed_code);
}

var data_scratch_seq: std.atomic.Value(u64) = .init(1);

/// Plant live R2-1 canaries on the home firmlink surface (content lives on the Data
/// volume). Prefer `$HOME/Library/Caches` — Seatbelt `subpath` filters match the
/// normalized `/Users/…` form, not `/System/Volumes/Data/…` path strings (live probe
/// on macOS 14–26: Data-form subpath grants never open; Users-form grants do).
/// Returns owned scratch path or null when no writable home surface exists.
fn tryHomeFirmlinkScratchBase(allocator: std.mem.Allocator, io: anytype) ?[]u8 {
    const home_z = std.c.getenv("HOME") orelse return null;
    const home = std.mem.span(home_z);
    if (home.len < 2 or home[0] != '/') return null;

    const caches = std.fmt.allocPrint(allocator, "{s}/Library/Caches", .{home}) catch return null;
    defer allocator.free(caches);
    std.Io.Dir.cwd().access(io, caches, .{}) catch return null;

    const seq = data_scratch_seq.fetchAdd(1, .monotonic);
    const scratch = std.fmt.allocPrint(allocator, "{s}/ryk-sb-data-{d}-{d}", .{
        caches,
        std.c.getpid(),
        seq,
    }) catch return null;
    std.Io.Dir.cwd().createDirPath(io, scratch) catch {
        allocator.free(scratch);
        return null;
    };
    return scratch;
}

/// When `users_path` is under `/Users/…`, return owned `/System/Volumes/Data` + path.
/// Null when not a Users-form path (caller skips Data-form dual open).
fn dataFormPath(allocator: std.mem.Allocator, users_path: []const u8) ?[]u8 {
    if (!profile.isPathWithin(users_path, "/Users") and !std.mem.eql(u8, users_path, "/Users")) {
        return null;
    }
    return std.fmt.allocPrint(allocator, "/System/Volumes/Data{s}", .{users_path}) catch null;
}

// R3-2: live-ish Seatbelt canary for R2-1 home/Data firmlink composition.
//
// Seatbelt path filters evaluate the *normalized* `/Users/…` form. Planting the
// workspace grant as a Data-form string (`/System/Volumes/Data/Users/…`) fails open
// even without a Data deny. Strongest feasible live proof on matrix hosts:
//   1. workspace + sibling on $HOME caches (Data firmlink content; Users-form paths)
//   2. product SBPL still emits Data deny (composition present)
//   3. sibling denied via Users-form open and via explicit Data-form open
//   4. workspace neighbor readable + writable
// Pure/SBPL last-match keepers above still prove Data-form string order for hosts
// whose realpath returns Data-form paths.
// Exit: 0=ok, 2=apply fail, 3=sibling readable, 4=ws read fail, 5=ws write fail,
//       7=Data-form sibling readable.
test "real FS deny: Data-volume sibling secret denied; workspace RW (R2-1)" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    if (!sandboxInitAvailable()) return error.SkipZigTest;

    const ver = try detectProductVersion();
    try std.testing.expect(isMatrixMajor(ver.major));
    try std.testing.expectEqual(SupportStatus.supported, evaluateSupport());

    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Prefer home firmlink surface. Skip when $HOME caches unavailable (rare CI).
    const scratch = tryHomeFirmlinkScratchBase(allocator, io) orelse return error.SkipZigTest;
    defer {
        std.Io.Dir.cwd().deleteTree(io, scratch) catch {};
        allocator.free(scratch);
    }

    const ws_rel = try std.fs.path.join(allocator, &.{ scratch, "workspace" });
    defer allocator.free(ws_rel);
    const sibling_rel = try std.fs.path.join(allocator, &.{ scratch, "sibling" });
    defer allocator.free(sibling_rel);

    try std.Io.Dir.cwd().createDirPath(io, ws_rel);
    try std.Io.Dir.cwd().createDirPath(io, sibling_rel);

    const ws_root = try std.Io.Dir.realPathFileAbsoluteAlloc(io, ws_rel, allocator);
    defer allocator.free(ws_root);

    var synth = try canary.generate(allocator);
    defer synth.deinit();

    const secret_path = try std.fs.path.join(allocator, &.{ sibling_rel, "secret.txt" });
    defer allocator.free(secret_path);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = secret_path, .data = synth.body });
    const secret_real = try std.Io.Dir.realPathFileAbsoluteAlloc(io, secret_path, allocator);
    defer allocator.free(secret_real);
    const secret_z = try allocator.dupeZ(u8, secret_real);
    defer allocator.free(secret_z);

    // Dual open: explicit Data-form path to the same vnode (when under /Users).
    const secret_data_owned = dataFormPath(allocator, secret_real);
    defer if (secret_data_owned) |p| allocator.free(p);
    const secret_data_z: ?[:0]u8 = if (secret_data_owned) |p| try allocator.dupeZ(u8, p) else null;
    defer if (secret_data_z) |p| allocator.free(p);

    const neighbor_path = try std.fs.path.join(allocator, &.{ ws_root, "neighbor.txt" });
    defer allocator.free(neighbor_path);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = neighbor_path, .data = "DATA_WS_NEIGHBOR_OK" });
    const neighbor_z = try allocator.dupeZ(u8, neighbor_path);
    defer allocator.free(neighbor_z);

    const write_probe_path = try std.fs.path.join(allocator, &.{ ws_root, "write_probe.txt" });
    defer allocator.free(write_probe_path);
    const write_probe_z = try allocator.dupeZ(u8, write_probe_path);
    defer allocator.free(write_probe_z);

    // CTRL-BASELINE: unsandboxed parent can read the sibling secret (both forms).
    {
        const baseline = try std.Io.Dir.cwd().readFileAlloc(io, secret_real, allocator, .limited(4096));
        defer allocator.free(baseline);
        try std.testing.expectEqualStrings(synth.body, baseline);
    }
    if (secret_data_owned) |dp| {
        const baseline_d = try std.Io.Dir.cwd().readFileAlloc(io, dp, allocator, .limited(4096));
        defer allocator.free(baseline_d);
        try std.testing.expectEqualStrings(synth.body, baseline_d);
    }

    // No production temp grants — sibling must not ride `/private/tmp` RW.
    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = ws_root,
        .system_ro_prefixes = profile.defaultSystemRoPrefixes(),
        .include_tmp = false,
    });
    defer compiled.deinit();
    try std.testing.expect(compiled.isAgentWritable(neighbor_path));
    try std.testing.expect(!compiled.isGrantedReadable(secret_real));
    try std.testing.expect(!compiled.isAgentWritable(secret_real));

    const prepared = prepareForChildApply(allocator, &compiled);
    defer if (prepared.sbpl_z) |p| allocator.free(p);
    try std.testing.expectEqual(.prepared, prepared.status);
    const sbpl = prepared.sbpl_z.?;
    // Product SBPL always emits Data deny (R2-1 composition), even when workspace
    // realpath is Users-form (re-allow only appears when a grant sits under Data).
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "(deny file-read* (subpath \"/System/Volumes/Data\"))") != null);

    const pid = std.c.fork();
    if (pid < 0) return error.SkipZigTest;
    if (pid == 0) {
        applyInChild(sbpl.ptr) catch std.c._exit(2);

        // Sibling outside workspace must not be readable (Users-form open).
        const sfd = std.c.open(secret_z.ptr, .{ .ACCMODE = .RDONLY });
        if (sfd >= 0) {
            _ = std.c.close(sfd);
            std.c._exit(3);
        }

        // Explicit Data-form open of the same secret must also fail.
        if (secret_data_z) |dz| {
            const dfd = std.c.open(dz.ptr, .{ .ACCMODE = .RDONLY });
            if (dfd >= 0) {
                _ = std.c.close(dfd);
                std.c._exit(7);
            }
        }

        const nfd = std.c.open(neighbor_z.ptr, .{ .ACCMODE = .RDONLY });
        if (nfd < 0) std.c._exit(4);
        var buf: [64]u8 = undefined;
        const n = std.c.read(nfd, &buf, buf.len);
        _ = std.c.close(nfd);
        if (n != "DATA_WS_NEIGHBOR_OK".len) std.c._exit(4);
        if (!std.mem.eql(u8, buf[0..@intCast(n)], "DATA_WS_NEIGHBOR_OK")) std.c._exit(4);

        const wfd = std.c.open(write_probe_z.ptr, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, @as(std.c.mode_t, 0o600));
        if (wfd < 0) std.c._exit(5);
        const wrote = std.c.write(wfd, "data-ok", 7);
        _ = std.c.close(wfd);
        if (wrote != 7) std.c._exit(5);

        std.c._exit(0);
    }

    var status: c_int = 0;
    _ = std.c.waitpid(pid, &status, 0);
    const exited = (status & 0x7f) == 0;
    try std.testing.expect(exited);
    const exit_code: u8 = @intCast((status >> 8) & 0xff);
    switch (exit_code) {
        0 => {},
        2 => return error.SeatbeltApplyFailedOnHost,
        3 => return error.DataVolumeSiblingReadableUnderSandbox,
        4 => return error.DataVolumeWorkspaceUnreadableUnderSandbox,
        5 => return error.DataVolumeWorkspaceWriteFailedUnderSandbox,
        7 => return error.DataFormSiblingReadableUnderSandbox,
        else => return error.UnexpectedSandboxChildExit,
    }

    const probe = try std.Io.Dir.cwd().readFileAlloc(io, write_probe_path, allocator, .limited(64));
    defer allocator.free(probe);
    try std.testing.expectEqualStrings("data-ok", probe);
}

// Planted workspace symlink to an outside path must not make outside content
// readable under real Seatbelt apply (path policy follows final target).
// Exit: 0=ok, 2=apply fail, 3=outside direct readable, 4=neighbor fail, 9=symlink escape.
test "real FS deny: workspace symlink to outside is not readable" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    if (!sandboxInitAvailable()) return error.SkipZigTest;

    const ver = try detectProductVersion();
    try std.testing.expect(isMatrixMajor(ver.major));
    try std.testing.expectEqual(SupportStatus.supported, evaluateSupport());

    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    try ws_tmp.dir.createDirPath(io, ".ryk");
    try ws_tmp.dir.writeFile(io, .{ .sub_path = "neighbor.txt", .data = "NEIGHBOR" });
    const ws_root = try ws_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(ws_root);

    var out_tmp = std.testing.tmpDir(.{});
    defer out_tmp.cleanup();
    var synth = try canary.generate(allocator);
    defer synth.deinit();
    try out_tmp.dir.writeFile(io, .{ .sub_path = "secret.txt", .data = synth.body });
    const out_root = try out_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(out_root);

    const secret_path = try std.fs.path.join(allocator, &.{ out_root, "secret.txt" });
    defer allocator.free(secret_path);
    const link_path = try std.fs.path.join(allocator, &.{ ws_root, "escape_link" });
    defer allocator.free(link_path);

    std.Io.Dir.cwd().symLink(io, secret_path, link_path, .{}) catch |err| switch (err) {
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };

    const neighbor_path = try std.fs.path.join(allocator, &.{ ws_root, "neighbor.txt" });
    defer allocator.free(neighbor_path);

    // CTRL-BASELINE: unsandboxed parent can read outside via the planted symlink.
    {
        const via_link = try std.Io.Dir.cwd().readFileAlloc(io, link_path, allocator, .limited(4096));
        defer allocator.free(via_link);
        try std.testing.expectEqualStrings(synth.body, via_link);
    }

    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = ws_root,
        .include_tmp = false,
    });
    defer compiled.deinit();
    try std.testing.expect(!compiled.isGrantedReadable(secret_path));
    try std.testing.expect(compiled.isGrantedReadable(neighbor_path));

    const prepared = prepareForChildApply(allocator, &compiled);
    defer if (prepared.sbpl_z) |p| allocator.free(p);
    try std.testing.expectEqual(.prepared, prepared.status);
    const sbpl_z = prepared.sbpl_z.?;

    const secret_z = try allocator.dupeZ(u8, secret_path);
    defer allocator.free(secret_z);
    const link_z = try allocator.dupeZ(u8, link_path);
    defer allocator.free(link_z);
    const neighbor_z = try allocator.dupeZ(u8, neighbor_path);
    defer allocator.free(neighbor_z);

    const pid = std.c.fork();
    if (pid < 0) return error.SkipZigTest;
    if (pid == 0) {
        applyInChild(sbpl_z.ptr) catch std.c._exit(2);

        // Outside real path must not be readable.
        const out_fd = std.c.open(secret_z.ptr, .{ .ACCMODE = .RDONLY });
        if (out_fd >= 0) {
            _ = std.c.close(out_fd);
            std.c._exit(3);
        }

        // Via workspace symlink: outside content must still be denied.
        const link_fd = std.c.open(link_z.ptr, .{ .ACCMODE = .RDONLY });
        if (link_fd >= 0) {
            _ = std.c.close(link_fd);
            std.c._exit(9);
        }

        const nfd = std.c.open(neighbor_z.ptr, .{ .ACCMODE = .RDONLY });
        if (nfd < 0) std.c._exit(4);
        var buf: [16]u8 = undefined;
        const n = std.c.read(nfd, &buf, buf.len);
        _ = std.c.close(nfd);
        if (n != "NEIGHBOR".len) std.c._exit(4);
        if (!std.mem.eql(u8, buf[0..@intCast(n)], "NEIGHBOR")) std.c._exit(4);

        std.c._exit(0);
    }

    var status: c_int = 0;
    _ = std.c.waitpid(pid, &status, 0);
    const exited = (status & 0x7f) == 0;
    try std.testing.expect(exited);
    const exit_code: u8 = @intCast((status >> 8) & 0xff);
    switch (exit_code) {
        0 => {},
        2 => return error.SeatbeltApplyFailedOnHost,
        3 => return error.OutsideCanaryReadableUnderSandbox,
        4 => return error.WorkspaceNeighborUnreadableUnderSandbox,
        9 => return error.SymlinkEscapeReadableUnderSandbox,
        else => return error.UnexpectedSandboxProbeExit,
    }
}

test "hardened profile: shell fork+exec works under attach" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    if (!sandboxInitAvailable()) return error.SkipZigTest;
    const ver = try detectProductVersion();
    try std.testing.expect(isMatrixMajor(ver.major));

    const allocator = std.testing.allocator;
    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    try ws_tmp.dir.createDirPath(std.testing.io, ".ryk");
    const ws_root = try ws_tmp.dir.realPathFileAlloc(std.testing.io, ".", allocator);
    defer allocator.free(ws_root);

    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = ws_root,
        .include_tmp = false,
    });
    defer compiled.deinit();

    const prepared = macos_seatbelt.prepareForChildApplyWithOptions(
        allocator,
        &compiled,
        .supported,
        .{ .profile_grade = .hardened },
    );
    defer if (prepared.sbpl_z) |p| allocator.free(p);
    try std.testing.expectEqual(.prepared, prepared.status);
    const sbpl_z = prepared.sbpl_z orelse return error.SeatbeltApplyFailedOnHost;
    try std.testing.expect(std.mem.indexOf(u8, sbpl_z, "(allow process*)") == null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl_z, "(allow process-fork)") != null);

    const pid = std.c.fork();
    if (pid < 0) return error.SkipZigTest;
    if (pid == 0) {
        applyInChild(sbpl_z.ptr) catch std.c._exit(2);
        const argv = [_:null]?[*:0]const u8{ "/bin/sh", "-c", "/bin/echo hardened_ok", null };
        _ = std.c.execve("/bin/sh", @ptrCast(&argv), @ptrCast(std.c.environ));
        std.c._exit(8);
    }
    const code = try waitExitCode(pid);
    try std.testing.expectEqual(@as(u8, 0), code);
}

test "strict route-force: outbound proxy allowed; bind/listen denied" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    if (!sandboxInitAvailable()) return error.SkipZigTest;
    const ver = try detectProductVersion();
    try std.testing.expect(isMatrixMajor(ver.major));

    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var allowed_server = try (try std.Io.net.IpAddress.parse("127.0.0.1", 0)).listen(io, .{ .reuse_address = true });
    defer allowed_server.deinit(io);
    const allowed_port = allowed_server.socket.address.getPort();

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    try ws_tmp.dir.createDirPath(io, ".ryk");
    const ws_root = try ws_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(ws_root);

    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = ws_root,
        .include_tmp = false,
    });
    defer compiled.deinit();

    const prepared = macos_seatbelt.prepareForChildApplyWithOptions(
        allocator,
        &compiled,
        .supported,
        .{
            .network_route_forcing = .{ .proxy_port = allowed_port },
            .profile_grade = .strict,
        },
    );
    defer if (prepared.sbpl_z) |p| allocator.free(p);
    try std.testing.expectEqual(.prepared, prepared.status);
    const sbpl_z = prepared.sbpl_z orelse return error.SeatbeltApplyFailedOnHost;
    try std.testing.expect(std.mem.indexOf(u8, sbpl_z, "(allow network-inbound)") == null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl_z, "(allow network-bind)") == null);

    // Outbound to proxy port still allowed.
    const allow_pid = std.c.fork();
    if (allow_pid < 0) return error.SkipZigTest;
    if (allow_pid == 0) {
        applyInChild(sbpl_z.ptr) catch std.c._exit(2);
        var port_buf: [8]u8 = undefined;
        const port_text = std.fmt.bufPrintZ(&port_buf, "{d}", .{allowed_port}) catch std.c._exit(7);
        childExecNc(port_text.ptr);
    }
    const allow_code = try waitExitCode(allow_pid);
    try std.testing.expectEqual(@as(u8, 0), allow_code);

    // Bind/listen denied under strict route-force.
    const bind_pid = std.c.fork();
    if (bind_pid < 0) return error.SkipZigTest;
    if (bind_pid == 0) {
        applyInChild(sbpl_z.ptr) catch std.c._exit(2);
        const fd = std.c.socket(std.c.AF.INET, std.c.SOCK.STREAM, 0);
        if (fd < 0) std.c._exit(3);
        var addr: std.c.sockaddr.in = .{
            .family = std.c.AF.INET,
            .port = 0,
            .addr = std.mem.nativeToBig(u32, 0x7f000001),
            .zero = [_]u8{0} ** 8,
        };
        const rc = std.c.bind(fd, @ptrCast(&addr), @sizeOf(std.c.sockaddr.in));
        if (rc == 0) std.c._exit(0); // bind succeeded = fail the canary
        std.c._exit(1); // expected: bind denied
    }
    const bind_code = try waitExitCode(bind_pid);
    try std.testing.expectEqual(@as(u8, 1), bind_code);
}

// M-5: hardened bootstrap FS residual — no literal `/private/var` grant; live open must deny.
// Compatible control proves the same path is readable under the historical residual.
test "hardened profile: open /private/var denied; compatible allows" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    if (!sandboxInitAvailable()) return error.SkipZigTest;
    const ver = try detectProductVersion();
    try std.testing.expect(isMatrixMajor(ver.major));

    const allocator = std.testing.allocator;
    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    try ws_tmp.dir.createDirPath(std.testing.io, ".ryk");
    const ws_root = try ws_tmp.dir.realPathFileAlloc(std.testing.io, ".", allocator);
    defer allocator.free(ws_root);

    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = ws_root,
        .include_tmp = false,
    });
    defer compiled.deinit();

    // Hardened: open of `/private/var` (literal residual removed) must fail after apply.
    {
        const prepared = macos_seatbelt.prepareForChildApplyWithOptions(
            allocator,
            &compiled,
            .supported,
            .{ .profile_grade = .hardened },
        );
        defer if (prepared.sbpl_z) |p| allocator.free(p);
        try std.testing.expectEqual(.prepared, prepared.status);
        const sbpl_z = prepared.sbpl_z orelse return error.SeatbeltApplyFailedOnHost;
        try std.testing.expect(std.mem.indexOf(u8, sbpl_z, "(allow file-read* (literal \"/private/var\"))") == null);

        const pid = std.c.fork();
        if (pid < 0) return error.SkipZigTest;
        if (pid == 0) {
            applyInChild(sbpl_z.ptr) catch std.c._exit(2);
            const fd = std.c.open("/private/var", .{ .ACCMODE = .RDONLY });
            if (fd >= 0) {
                _ = std.c.close(fd);
                std.c._exit(0); // open succeeded = residual still broad
            }
            std.c._exit(1); // expected deny
        }
        const code = try waitExitCode(pid);
        try std.testing.expectEqual(@as(u8, 1), code);
    }

    // Compatible control: same open succeeds under historical residual.
    {
        const prepared = macos_seatbelt.prepareForChildApplyWithOptions(
            allocator,
            &compiled,
            .supported,
            .{ .profile_grade = .compatible },
        );
        defer if (prepared.sbpl_z) |p| allocator.free(p);
        try std.testing.expectEqual(.prepared, prepared.status);
        const sbpl_z = prepared.sbpl_z orelse return error.SeatbeltApplyFailedOnHost;
        try std.testing.expect(std.mem.indexOf(u8, sbpl_z, "(allow file-read* (literal \"/private/var\"))") != null);

        const pid = std.c.fork();
        if (pid < 0) return error.SkipZigTest;
        if (pid == 0) {
            applyInChild(sbpl_z.ptr) catch std.c._exit(2);
            const fd = std.c.open("/private/var", .{ .ACCMODE = .RDONLY });
            if (fd >= 0) {
                _ = std.c.close(fd);
                std.c._exit(0);
            }
            std.c._exit(1);
        }
        const code = try waitExitCode(pid);
        try std.testing.expectEqual(@as(u8, 0), code);
    }
}

// Phase 1d / P1-5: workspace secret-form deny under protect_workspace_secrets.
// Edge cases exercised under live Seatbelt:
//   - `.env` canary content never returned (open fails; no partial read)
//   - nested `.env.local` denied
//   - `.env.example.local` denied (not an exact safe template)
//   - exact templates `.env.example` / `.env.sample` / `.env.template` readable
//   - ordinary workspace file remains RW
//   - write create of new `.env` denied
//   - protect-off control SBPL still allows `.env` read (negative control)
// Exit: 0=ok, 2=apply fail, 3=.env readable, 4=template fail, 5=ordinary fail,
//       6=.env.local readable, 7=.env.example.local readable, 8=write to .env ok (leak),
//       10=ordinary write fail, 11=canary body leaked via any open buffer.
test "real FS deny: workspace .env secret forms denied under protect; templates and ordinary remain" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    if (!sandboxInitAvailable()) return error.SkipZigTest;

    const ver = try detectProductVersion();
    try std.testing.expect(isMatrixMajor(ver.major));
    try std.testing.expectEqual(SupportStatus.supported, evaluateSupport());

    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    try ws_tmp.dir.createDirPath(io, ".ryk");
    try ws_tmp.dir.createDirPath(io, "nested");

    var synth = try canary.generate(allocator);
    defer synth.deinit();

    try ws_tmp.dir.writeFile(io, .{ .sub_path = ".env", .data = synth.body });
    try ws_tmp.dir.writeFile(io, .{ .sub_path = "nested/.env.local", .data = synth.body });
    try ws_tmp.dir.writeFile(io, .{ .sub_path = ".env.example.local", .data = synth.body });
    try ws_tmp.dir.writeFile(io, .{ .sub_path = ".env.example", .data = "template-ok" });
    try ws_tmp.dir.writeFile(io, .{ .sub_path = ".env.sample", .data = "sample-ok" });
    try ws_tmp.dir.writeFile(io, .{ .sub_path = ".env.template", .data = "template-file-ok" });
    try ws_tmp.dir.writeFile(io, .{ .sub_path = "readme.txt", .data = "ordinary-ok" });

    const ws_root = try ws_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(ws_root);

    const env_path = try std.fs.path.join(allocator, &.{ ws_root, ".env" });
    defer allocator.free(env_path);
    const env_local_path = try std.fs.path.join(allocator, &.{ ws_root, "nested", ".env.local" });
    defer allocator.free(env_local_path);
    const env_example_local_path = try std.fs.path.join(allocator, &.{ ws_root, ".env.example.local" });
    defer allocator.free(env_example_local_path);
    const env_example_path = try std.fs.path.join(allocator, &.{ ws_root, ".env.example" });
    defer allocator.free(env_example_path);
    const env_sample_path = try std.fs.path.join(allocator, &.{ ws_root, ".env.sample" });
    defer allocator.free(env_sample_path);
    const env_template_path = try std.fs.path.join(allocator, &.{ ws_root, ".env.template" });
    defer allocator.free(env_template_path);
    const readme_path = try std.fs.path.join(allocator, &.{ ws_root, "readme.txt" });
    defer allocator.free(readme_path);
    const write_env_path = try std.fs.path.join(allocator, &.{ ws_root, ".env.created_by_probe" });
    defer allocator.free(write_env_path);
    const write_ordinary_path = try std.fs.path.join(allocator, &.{ ws_root, "write_probe.txt" });
    defer allocator.free(write_ordinary_path);

    // CTRL-BASELINE: unsandboxed parent can still read the canary.
    {
        const baseline = try std.Io.Dir.cwd().readFileAlloc(io, env_path, allocator, .limited(4096));
        defer allocator.free(baseline);
        try std.testing.expectEqualStrings(synth.body, baseline);
        try std.testing.expect(canary.bodyLeaked(synth, baseline));
    }

    // Negative control: protect-off product SBPL must still allow workspace `.env` open.
    {
        var unprotected = try profile.compileProfile(allocator, .{
            .workspace_root = ws_root,
            .include_tmp = false,
            .protect_workspace_secrets = false,
        });
        defer unprotected.deinit();
        const prepared_off = prepareForChildApply(allocator, &unprotected);
        defer if (prepared_off.sbpl_z) |p| allocator.free(p);
        try std.testing.expectEqual(.prepared, prepared_off.status);
        const sbpl_off = prepared_off.sbpl_z.?;

        const env_z_off = try allocator.dupeZ(u8, env_path);
        defer allocator.free(env_z_off);

        const pid_off = std.c.fork();
        if (pid_off < 0) return error.SkipZigTest;
        if (pid_off == 0) {
            applyInChild(sbpl_off.ptr) catch std.c._exit(2);
            const fd = std.c.open(env_z_off.ptr, .{ .ACCMODE = .RDONLY });
            if (fd < 0) std.c._exit(3);
            var buf: [256]u8 = undefined;
            const n = std.c.read(fd, &buf, buf.len);
            _ = std.c.close(fd);
            if (n <= 0) std.c._exit(3);
            if (std.mem.indexOf(u8, buf[0..@intCast(n)], synth.body) == null) std.c._exit(3);
            std.c._exit(0);
        }
        const code_off = try waitExitCode(pid_off);
        switch (code_off) {
            0 => {},
            2 => return error.SeatbeltApplyFailedOnHost,
            3 => return error.ProtectOffControlCouldNotReadEnv,
            else => return error.UnexpectedSandboxChildExit,
        }
    }

    var protected = try profile.compileProfile(allocator, .{
        .workspace_root = ws_root,
        .include_tmp = false,
        .protect_workspace_secrets = true,
    });
    defer protected.deinit();
    try std.testing.expect(protected.protect_workspace_secrets);

    const prepared = prepareForChildApply(allocator, &protected);
    defer if (prepared.sbpl_z) |p| allocator.free(p);
    try std.testing.expectEqual(.prepared, prepared.status);
    const sbpl = prepared.sbpl_z.?;
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "workspace env secret carve-out") != null);

    const env_z = try allocator.dupeZ(u8, env_path);
    defer allocator.free(env_z);
    const env_local_z = try allocator.dupeZ(u8, env_local_path);
    defer allocator.free(env_local_z);
    const env_example_local_z = try allocator.dupeZ(u8, env_example_local_path);
    defer allocator.free(env_example_local_z);
    const env_example_z = try allocator.dupeZ(u8, env_example_path);
    defer allocator.free(env_example_z);
    const env_sample_z = try allocator.dupeZ(u8, env_sample_path);
    defer allocator.free(env_sample_z);
    const env_template_z = try allocator.dupeZ(u8, env_template_path);
    defer allocator.free(env_template_z);
    const readme_z = try allocator.dupeZ(u8, readme_path);
    defer allocator.free(readme_z);
    const write_env_z = try allocator.dupeZ(u8, write_env_path);
    defer allocator.free(write_env_z);
    const write_ordinary_z = try allocator.dupeZ(u8, write_ordinary_path);
    defer allocator.free(write_ordinary_z);

    const pid = std.c.fork();
    if (pid < 0) return error.SkipZigTest;
    if (pid == 0) {
        applyInChild(sbpl.ptr) catch std.c._exit(2);

        // Denied secret forms must not open (and must never return canary bytes).
        const env_fd = std.c.open(env_z.ptr, .{ .ACCMODE = .RDONLY });
        if (env_fd >= 0) {
            var leak_buf: [256]u8 = undefined;
            const n = std.c.read(env_fd, &leak_buf, leak_buf.len);
            _ = std.c.close(env_fd);
            if (n > 0 and std.mem.indexOf(u8, leak_buf[0..@intCast(n)], synth.body) != null) {
                std.c._exit(11);
            }
            std.c._exit(3);
        }

        const local_fd = std.c.open(env_local_z.ptr, .{ .ACCMODE = .RDONLY });
        if (local_fd >= 0) {
            var leak_buf: [256]u8 = undefined;
            const n = std.c.read(local_fd, &leak_buf, leak_buf.len);
            _ = std.c.close(local_fd);
            if (n > 0 and std.mem.indexOf(u8, leak_buf[0..@intCast(n)], synth.body) != null) {
                std.c._exit(11);
            }
            std.c._exit(6);
        }

        const ex_local_fd = std.c.open(env_example_local_z.ptr, .{ .ACCMODE = .RDONLY });
        if (ex_local_fd >= 0) {
            var leak_buf: [256]u8 = undefined;
            const n = std.c.read(ex_local_fd, &leak_buf, leak_buf.len);
            _ = std.c.close(ex_local_fd);
            if (n > 0 and std.mem.indexOf(u8, leak_buf[0..@intCast(n)], synth.body) != null) {
                std.c._exit(11);
            }
            std.c._exit(7);
        }

        // Exact safe templates remain readable.
        if (!childReadEquals(env_example_z.ptr, "template-ok")) std.c._exit(4);
        if (!childReadEquals(env_sample_z.ptr, "sample-ok")) std.c._exit(4);
        if (!childReadEquals(env_template_z.ptr, "template-file-ok")) std.c._exit(4);

        // Ordinary workspace file remains readable.
        if (!childReadEquals(readme_z.ptr, "ordinary-ok")) std.c._exit(5);

        // Ordinary write remains allowed.
        const wfd = std.c.open(
            write_ordinary_z.ptr,
            .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true },
            @as(std.c.mode_t, 0o600),
        );
        if (wfd < 0) std.c._exit(10);
        const wrote = std.c.write(wfd, "wrote-ok", 8);
        _ = std.c.close(wfd);
        if (wrote != 8) std.c._exit(10);

        // Creating a new secret-form file under the workspace must fail.
        const sfd = std.c.open(
            write_env_z.ptr,
            .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true },
            @as(std.c.mode_t, 0o600),
        );
        if (sfd >= 0) {
            _ = std.c.close(sfd);
            std.c._exit(8);
        }

        std.c._exit(0);
    }

    const exit_code = try waitExitCode(pid);
    switch (exit_code) {
        0 => {},
        2 => return error.SeatbeltApplyFailedOnHost,
        3 => return error.WorkspaceEnvReadableUnderProtect,
        4 => return error.WorkspaceEnvTemplateUnreadableUnderProtect,
        5 => return error.OrdinaryWorkspaceFileUnreadableUnderProtect,
        6 => return error.NestedEnvLocalReadableUnderProtect,
        7 => return error.EnvExampleLocalReadableUnderProtect,
        8 => return error.WorkspaceEnvWriteAllowedUnderProtect,
        10 => return error.OrdinaryWorkspaceWriteFailedUnderProtect,
        11 => return error.CanaryBodyLeakedUnderProtect,
        else => return error.UnexpectedSandboxChildExit,
    }

    const probe = try std.Io.Dir.cwd().readFileAlloc(io, write_ordinary_path, allocator, .limited(64));
    defer allocator.free(probe);
    try std.testing.expectEqualStrings("wrote-ok", probe);

    // Parent still holds the real canary; sandboxed child never returned it.
    const still = try std.Io.Dir.cwd().readFileAlloc(io, env_path, allocator, .limited(4096));
    defer allocator.free(still);
    try std.testing.expect(canary.bodyLeaked(synth, still));
}

fn childReadEquals(path_z: [*:0]const u8, expected: []const u8) bool {
    if (expected.len > 128) return false;
    const fd = std.c.open(path_z, .{ .ACCMODE = .RDONLY });
    if (fd < 0) return false;
    var buf: [128]u8 = undefined;
    const n = std.c.read(fd, &buf, buf.len);
    _ = std.c.close(fd);
    if (n < 0) return false;
    if (@as(usize, @intCast(n)) != expected.len) return false;
    return std.mem.eql(u8, buf[0..@intCast(n)], expected);
}

// Pre-planted hardlink to a secret-form inode must not return canary content under
// protect-on. Path-regex alone misses non-.env basenames; prepare-time scan emits
// last-match path denies for those aliases. Exit: 0=ok, 2=apply, 3=alias readable,
// 4=canary leak, 5=neighbor fail.
//
// When prepare fails closed (e.g. scan open error), this test fails at prepare —
// never observes canary body. Companion unit tests cover mode-000 ScanOpenFailed.

// Pre-planted hardlink to a secret-form inode must not return canary content under
// protect-on. Path-regex alone misses non-.env basenames; prepare-time scan emits
// last-match path denies for those aliases. Exit: 0=ok, 2=apply, 3=alias readable,
// 4=canary leak, 5=neighbor fail.
//
// When prepare fails closed (e.g. scan open error), this test fails at prepare —
// never observes canary body. Companion unit tests cover mode-000 ScanOpenFailed.
test "real FS deny: hardlink alias of workspace .env denied under protect" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    if (!sandboxInitAvailable()) return error.SkipZigTest;

    const ver = try detectProductVersion();
    try std.testing.expect(isMatrixMajor(ver.major));
    try std.testing.expectEqual(SupportStatus.supported, evaluateSupport());

    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    try ws_tmp.dir.createDirPath(io, ".ryk");

    var synth = try canary.generate(allocator);
    defer synth.deinit();
    try ws_tmp.dir.writeFile(io, .{ .sub_path = ".env", .data = synth.body });
    try ws_tmp.dir.writeFile(io, .{ .sub_path = "neighbor.txt", .data = "neighbor-ok" });

    // Pre-plant hardlink with a non-secret basename (path-regex alone would miss it).
    ws_tmp.dir.hardLink(".env", ws_tmp.dir, "notes.txt", io, .{}) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return error.SkipZigTest,
    };

    const ws_root = try ws_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(ws_root);

    const alias_path = try std.fs.path.join(allocator, &.{ ws_root, "notes.txt" });
    defer allocator.free(alias_path);
    const neighbor_path = try std.fs.path.join(allocator, &.{ ws_root, "neighbor.txt" });
    defer allocator.free(neighbor_path);

    // CTRL-BASELINE: unsandboxed parent can read the alias (same inode as .env).
    {
        const baseline = try std.Io.Dir.cwd().readFileAlloc(io, alias_path, allocator, .limited(4096));
        defer allocator.free(baseline);
        try std.testing.expectEqualStrings(synth.body, baseline);
    }

    var protected = try profile.compileProfile(allocator, .{
        .workspace_root = ws_root,
        .include_tmp = false,
        .protect_workspace_secrets = true,
    });
    defer protected.deinit();

    const prepared = prepareForChildApply(allocator, &protected);
    defer if (prepared.sbpl_z) |p| allocator.free(p);
    try std.testing.expectEqual(.prepared, prepared.status);
    const sbpl = prepared.sbpl_z.?;
    // Prepare scan must emit an explicit deny for the alias path.
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "multi-nlink non-secret basenames") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl, "notes.txt") != null);

    const alias_z = try allocator.dupeZ(u8, alias_path);
    defer allocator.free(alias_z);
    const neighbor_z = try allocator.dupeZ(u8, neighbor_path);
    defer allocator.free(neighbor_z);

    const pid = std.c.fork();
    if (pid < 0) return error.SkipZigTest;
    if (pid == 0) {
        applyInChild(sbpl.ptr) catch std.c._exit(2);

        const afd = std.c.open(alias_z.ptr, .{ .ACCMODE = .RDONLY });
        if (afd >= 0) {
            var buf: [256]u8 = undefined;
            const n = std.c.read(afd, &buf, buf.len);
            _ = std.c.close(afd);
            if (n > 0 and std.mem.indexOf(u8, buf[0..@intCast(n)], synth.body) != null) {
                std.c._exit(4);
            }
            std.c._exit(3);
        }

        if (!childReadEquals(neighbor_z.ptr, "neighbor-ok")) std.c._exit(5);
        std.c._exit(0);
    }

    const exit_code = try waitExitCode(pid);
    switch (exit_code) {
        0 => {},
        2 => return error.SeatbeltApplyFailedOnHost,
        3 => return error.HardlinkAliasReadableUnderProtect,
        4 => return error.CanaryBodyLeakedViaHardlinkAlias,
        5 => return error.OrdinaryNeighborUnreadableUnderProtect,
        else => return error.UnexpectedSandboxChildExit,
    }
}

// Host-agent config RW grant: ~/.claude canary readable+writable; sibling ~/.ssh
// denied; bare HOME still not granted. Exit: 0=ok, 2=apply fail, 3=claude unreadable,
// 4=ssh leak, 5=ws neighbor fail, 6=claude write fail.
test "real FS: host config RW grant allows .claude and still denies .ssh" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    if (!sandboxInitAvailable()) return error.SkipZigTest;
    const ver = try detectProductVersion();
    try std.testing.expect(isMatrixMajor(ver.major));
    try std.testing.expectEqual(SupportStatus.supported, evaluateSupport());

    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    const home_root = try home_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(home_root);

    try home_tmp.dir.createDirPath(io, ".claude");
    try home_tmp.dir.createDirPath(io, ".ssh");
    try home_tmp.dir.writeFile(io, .{ .sub_path = ".claude/settings.json", .data = "CLAUDE_CFG_OK" });
    try home_tmp.dir.writeFile(io, .{ .sub_path = ".ssh/id_canary", .data = "SSH_SECRET_LEAK" });

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    try ws_tmp.dir.createDirPath(io, ".ryk");
    try ws_tmp.dir.writeFile(io, .{ .sub_path = "neighbor.txt", .data = "WS_OK" });
    const ws_root = try ws_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(ws_root);

    const claude_cfg = try std.fs.path.join(allocator, &.{ home_root, ".claude" });
    defer allocator.free(claude_cfg);
    const claude_file = try std.fs.path.join(allocator, &.{ home_root, ".claude", "settings.json" });
    defer allocator.free(claude_file);
    const claude_write = try std.fs.path.join(allocator, &.{ home_root, ".claude", "write_probe.txt" });
    defer allocator.free(claude_write);
    const ssh_file = try std.fs.path.join(allocator, &.{ home_root, ".ssh", "id_canary" });
    defer allocator.free(ssh_file);
    const neighbor = try std.fs.path.join(allocator, &.{ ws_root, "neighbor.txt" });
    defer allocator.free(neighbor);

    const claude_z = try allocator.dupeZ(u8, claude_file);
    defer allocator.free(claude_z);
    const claude_write_z = try allocator.dupeZ(u8, claude_write);
    defer allocator.free(claude_write_z);
    const ssh_z = try allocator.dupeZ(u8, ssh_file);
    defer allocator.free(ssh_z);
    const neighbor_z = try allocator.dupeZ(u8, neighbor);
    defer allocator.free(neighbor_z);

    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = ws_root,
        .include_tmp = false,
        .host_rw_paths = &.{claude_cfg},
    });
    defer compiled.deinit();
    try std.testing.expect(compiled.hasGrant(claude_cfg, .rw));
    try std.testing.expect(compiled.isGrantedReadable(claude_file));
    try std.testing.expect(compiled.isAgentWritable(claude_write));
    try std.testing.expect(!compiled.isGrantedReadable(ssh_file));
    try std.testing.expect(!compiled.grantsHome(home_root));

    const prepared = prepareForChildApply(allocator, &compiled);
    defer if (prepared.sbpl_z) |p| allocator.free(p);
    try std.testing.expectEqual(.prepared, prepared.status);
    const sbpl_z = prepared.sbpl_z.?;

    const pid = std.c.fork();
    if (pid < 0) return error.SkipZigTest;
    if (pid == 0) {
        applyInChild(sbpl_z.ptr) catch std.c._exit(2);

        const cfd = std.c.open(claude_z.ptr, .{ .ACCMODE = .RDONLY });
        if (cfd < 0) std.c._exit(3);
        var buf: [64]u8 = undefined;
        const n = std.c.read(cfd, &buf, buf.len);
        _ = std.c.close(cfd);
        if (n != "CLAUDE_CFG_OK".len or !std.mem.eql(u8, buf[0..@intCast(n)], "CLAUDE_CFG_OK")) std.c._exit(3);

        const sfd = std.c.open(ssh_z.ptr, .{ .ACCMODE = .RDONLY });
        if (sfd >= 0) {
            _ = std.c.close(sfd);
            std.c._exit(4);
        }

        const nfd = std.c.open(neighbor_z.ptr, .{ .ACCMODE = .RDONLY });
        if (nfd < 0) std.c._exit(5);
        _ = std.c.close(nfd);

        const wfd = std.c.open(
            claude_write_z.ptr,
            .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true },
            @as(std.c.mode_t, 0o600),
        );
        if (wfd < 0) std.c._exit(6);
        const wrote = std.c.write(wfd, "ok", 2);
        _ = std.c.close(wfd);
        if (wrote != 2) std.c._exit(6);

        std.c._exit(0);
    }

    const exit_code = try waitExitCode(pid);
    switch (exit_code) {
        0 => {},
        2 => return error.SeatbeltApplyFailedOnHost,
        3 => return error.HostConfigClaudeUnreadable,
        4 => return error.SshReadableUnderHostConfigGrant,
        5 => return error.WorkspaceNeighborUnreadable,
        6 => return error.HostConfigClaudeWriteFailed,
        else => return error.UnexpectedSandboxChildExit,
    }
}

// m1: live attach proof for host-config authority write-deny (not SBPL-string only).
// Authority file (settings.json) must EPERM on open(O_WRONLY|O_TRUNC); sibling under
// the same host RW tree may still write; authority remains readable.
// Exit: 0=ok, 2=apply fail, 3=authority unreadable, 4=authority writable (leak),
// 5=sibling session write failed.
test "real FS: host config authority write denied; sibling session file still writable" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    if (!sandboxInitAvailable()) return error.SkipZigTest;
    const ver = try detectProductVersion();
    try std.testing.expect(isMatrixMajor(ver.major));
    try std.testing.expectEqual(SupportStatus.supported, evaluateSupport());

    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    const home_root = try home_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(home_root);

    try home_tmp.dir.createDirPath(io, ".claude");
    try home_tmp.dir.writeFile(io, .{ .sub_path = ".claude/settings.json", .data = "AUTHORITY_OK\n" });

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    try ws_tmp.dir.createDirPath(io, ".ryk");
    const ws_root = try ws_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(ws_root);

    const claude_cfg = try std.fs.path.join(allocator, &.{ home_root, ".claude" });
    defer allocator.free(claude_cfg);
    const authority = try std.fs.path.join(allocator, &.{ home_root, ".claude", "settings.json" });
    defer allocator.free(authority);
    const session_write = try std.fs.path.join(allocator, &.{ home_root, ".claude", "session_probe.txt" });
    defer allocator.free(session_write);

    const authority_z = try allocator.dupeZ(u8, authority);
    defer allocator.free(authority_z);
    const session_write_z = try allocator.dupeZ(u8, session_write);
    defer allocator.free(session_write_z);

    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = ws_root,
        .include_tmp = false,
        .host_rw_paths = &.{claude_cfg},
        .control_roots = &.{authority},
    });
    defer compiled.deinit();
    try std.testing.expect(compiled.isControlPath(authority));
    try std.testing.expect(!compiled.isAgentWritable(authority));

    const prepared = prepareForChildApplyWithOptions(allocator, &compiled, evaluateSupport(), .{
        .write_deny_literals = &.{authority},
    });
    defer if (prepared.sbpl_z) |p| allocator.free(p);
    try std.testing.expectEqual(.prepared, prepared.status);
    const sbpl_z = prepared.sbpl_z.?;

    const pid = std.c.fork();
    if (pid < 0) return error.SkipZigTest;
    if (pid == 0) {
        applyInChild(sbpl_z.ptr) catch std.c._exit(2);

        // Authority remains readable under host RW + write-deny.
        const rfd = std.c.open(authority_z.ptr, .{ .ACCMODE = .RDONLY });
        if (rfd < 0) std.c._exit(3);
        _ = std.c.close(rfd);

        // Authority write must fail (literal deny + control-root carve-out).
        const wfd = std.c.open(
            authority_z.ptr,
            .{ .ACCMODE = .WRONLY, .TRUNC = true },
            @as(std.c.mode_t, 0o600),
        );
        if (wfd >= 0) {
            _ = std.c.close(wfd);
            std.c._exit(4);
        }

        // Sibling session file under same RW tree may still write.
        const sfd = std.c.open(
            session_write_z.ptr,
            .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true },
            @as(std.c.mode_t, 0o600),
        );
        if (sfd < 0) std.c._exit(5);
        const wrote = std.c.write(sfd, "ok", 2);
        _ = std.c.close(sfd);
        if (wrote != 2) std.c._exit(5);

        std.c._exit(0);
    }

    const exit_code = try waitExitCode(pid);
    switch (exit_code) {
        0 => {},
        2 => return error.SeatbeltApplyFailedOnHost,
        3 => return error.HostConfigAuthorityUnreadable,
        4 => return error.HostConfigAuthorityWritableUnderDeny,
        5 => return error.HostConfigSiblingSessionWriteFailed,
        else => return error.UnexpectedSandboxChildExit,
    }
}

// F-03: host-config RW must not allow hardlink plant into workspace after attach.
// Synthetic host_rw (not basename spoof). Exit: 0=ok, 2=apply fail, 3=host→ws
// link succeeded (leak), 4=workspace-only link failed, 5=workspace write failed,
// 6=ws→host reverse plant succeeded (leak), 7=control-root (.git) hardlink plant leak.
test "real FS: F-03 host-config hardlink into workspace denied; workspace-only link ok" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    if (!sandboxInitAvailable()) return error.SkipZigTest;
    const ver = try detectProductVersion();
    try std.testing.expect(isMatrixMajor(ver.major));
    try std.testing.expectEqual(SupportStatus.supported, evaluateSupport());

    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var home_tmp = std.testing.tmpDir(.{});
    defer home_tmp.cleanup();
    const home_root = try home_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(home_root);
    try home_tmp.dir.createDirPath(io, ".codex");
    try home_tmp.dir.writeFile(io, .{ .sub_path = ".codex/auth.json", .data = "AUTH_CANARY\n" });

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    try ws_tmp.dir.createDirPath(io, ".ryk");
    try ws_tmp.dir.createDirPath(io, ".git");
    const ws_root = try ws_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(ws_root);

    const codex_cfg = try std.fs.path.join(allocator, &.{ home_root, ".codex" });
    defer allocator.free(codex_cfg);
    const auth = try std.fs.path.join(allocator, &.{ home_root, ".codex", "auth.json" });
    defer allocator.free(auth);
    const smuggle = try std.fs.path.join(allocator, &.{ ws_root, "smuggle.env" });
    defer allocator.free(smuggle);
    const reverse = try std.fs.path.join(allocator, &.{ home_root, ".codex", "ws_plant.txt" });
    defer allocator.free(reverse);
    const ws_a = try std.fs.path.join(allocator, &.{ ws_root, "a.txt" });
    defer allocator.free(ws_a);
    const ws_b = try std.fs.path.join(allocator, &.{ ws_root, "b.txt" });
    defer allocator.free(ws_b);
    const git_plant = try std.fs.path.join(allocator, &.{ ws_root, ".git", "hooks_plant" });
    defer allocator.free(git_plant);

    const auth_z = try allocator.dupeZ(u8, auth);
    defer allocator.free(auth_z);
    const smuggle_z = try allocator.dupeZ(u8, smuggle);
    defer allocator.free(smuggle_z);
    const reverse_z = try allocator.dupeZ(u8, reverse);
    defer allocator.free(reverse_z);
    const ws_a_z = try allocator.dupeZ(u8, ws_a);
    defer allocator.free(ws_a_z);
    const ws_b_z = try allocator.dupeZ(u8, ws_b);
    defer allocator.free(ws_b_z);
    const git_plant_z = try allocator.dupeZ(u8, git_plant);
    defer allocator.free(git_plant_z);

    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = ws_root,
        .include_tmp = false,
        .host_rw_paths = &.{codex_cfg},
    });
    defer compiled.deinit();
    try std.testing.expect(compiled.hasGrant(codex_cfg, .rw));

    const prepared = prepareForChildApply(allocator, &compiled);
    defer if (prepared.sbpl_z) |p| allocator.free(p);
    try std.testing.expectEqual(.prepared, prepared.status);
    const sbpl_z = prepared.sbpl_z.?;
    // SBPL must carry the fence tokens (regression if emit drops).
    try std.testing.expect(std.mem.indexOf(u8, sbpl_z, "(deny file-link)") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl_z, "(allow file-link (require-all (subpath \"") != null);

    const pid = std.c.fork();
    if (pid < 0) return error.SkipZigTest;
    if (pid == 0) {
        applyInChild(sbpl_z.ptr) catch std.c._exit(2);

        // Cross-root hardlink must fail (F-03).
        if (std.c.link(auth_z.ptr, smuggle_z.ptr) == 0) std.c._exit(3);

        // Workspace write + workspace-only hardlink must still work.
        const wfd = std.c.open(
            ws_a_z.ptr,
            .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true },
            @as(std.c.mode_t, 0o600),
        );
        if (wfd < 0) std.c._exit(5);
        const wrote = std.c.write(wfd, "x", 1);
        _ = std.c.close(wfd);
        if (wrote != 1) std.c._exit(5);
        if (std.c.link(ws_a_z.ptr, ws_b_z.ptr) != 0) std.c._exit(4);

        // Reverse plant (workspace → host-config name) denied by global file-link
        // fence (workspace-only re-allow; no host_rw file-link allow).
        if (std.c.link(ws_a_z.ptr, reverse_z.ptr) == 0) std.c._exit(6);

        // Control-root plant: workspace file-link re-allow must not cover .git
        // (require-not carve; same class as file-write* control isolation).
        if (std.c.link(ws_a_z.ptr, git_plant_z.ptr) == 0) std.c._exit(7);

        std.c._exit(0);
    }

    const exit_code = try waitExitCode(pid);
    switch (exit_code) {
        0 => {},
        2 => return error.SeatbeltApplyFailedOnHost,
        3 => return error.HostConfigHardlinkIntoWorkspaceSucceeded,
        4 => return error.WorkspaceOnlyHardlinkFailed,
        5 => return error.WorkspaceWriteFailed,
        6 => return error.WorkspaceHardlinkIntoHostConfigSucceeded,
        7 => return error.ControlRootHardlinkPlantSucceeded,
        else => return error.UnexpectedSandboxChildExit,
    }
}

// Path-walk residual canary: after Seatbelt attach, lstat each intermediate path
// component of the workspace grant must succeed (Node realpath / resolveMainPath).
// Sibling content outside the grant must still be denied (no over-grant).
// Exit: 0=ok, 2=apply fail, 3=ancestor lstat EPERM, 4=outside readable (leak),
// 5=workspace file unreadable.
test "real FS: path-walk lstat of grant ancestors succeeds; outside still denied" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    if (!sandboxInitAvailable()) return error.SkipZigTest;
    const ver = try detectProductVersion();
    try std.testing.expect(isMatrixMajor(ver.major));
    try std.testing.expectEqual(SupportStatus.supported, evaluateSupport());

    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    try ws_tmp.dir.createDirPath(io, ".ryk");
    try ws_tmp.dir.createDirPath(io, "nested/deep");
    try ws_tmp.dir.writeFile(io, .{ .sub_path = "nested/deep/file.txt", .data = "WS_OK" });
    const ws_root = try ws_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(ws_root);

    var out_tmp = std.testing.tmpDir(.{});
    defer out_tmp.cleanup();
    try out_tmp.dir.writeFile(io, .{ .sub_path = "secret.txt", .data = "OUTSIDE_LEAK" });
    const out_root = try out_tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(out_root);

    const ws_file = try std.fs.path.join(allocator, &.{ ws_root, "nested", "deep", "file.txt" });
    defer allocator.free(ws_file);
    const out_file = try std.fs.path.join(allocator, &.{ out_root, "secret.txt" });
    defer allocator.free(out_file);

    const ws_root_z = try allocator.dupeZ(u8, ws_root);
    defer allocator.free(ws_root_z);
    const ws_file_z = try allocator.dupeZ(u8, ws_file);
    defer allocator.free(ws_file_z);
    const out_file_z = try allocator.dupeZ(u8, out_file);
    defer allocator.free(out_file_z);

    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = ws_root,
        .include_tmp = false,
    });
    defer compiled.deinit();

    const prepared = prepareForChildApply(allocator, &compiled);
    defer if (prepared.sbpl_z) |p| allocator.free(p);
    try std.testing.expectEqual(.prepared, prepared.status);
    const sbpl_z = prepared.sbpl_z.?;

    // Pure model: SBPL must emit the path-walk ancestor section.
    try std.testing.expect(std.mem.indexOf(u8, sbpl_z, "path-walk ancestor metadata") != null);

    const pid = std.c.fork();
    if (pid < 0) return error.SkipZigTest;
    if (pid == 0) {
        applyInChild(sbpl_z.ptr) catch std.c._exit(2);

        // lstat every prefix component of workspace_root (and the root itself).
        // Match Node realpath: component-wise lstat, not open/read content.
        const lstat_fn = struct {
            extern "c" fn lstat(p: [*:0]const u8, buf: *std.c.Stat) c_int;
        }.lstat;
        const path = ws_root_z;
        var i: usize = 1;
        while (i <= path.len) : (i += 1) {
            const at_end = i == path.len;
            const at_slash = !at_end and path[i] == '/';
            if (!at_end and !at_slash) continue;
            if (i <= 1) continue; // skip bare "/"
            var component_buf: [std.fs.max_path_bytes + 1]u8 = undefined;
            if (i >= component_buf.len) std.c._exit(3);
            @memcpy(component_buf[0..i], path[0..i]);
            component_buf[i] = 0;
            var st: std.c.Stat = undefined;
            if (lstat_fn(@ptrCast(&component_buf), &st) != 0) std.c._exit(3);
            if (at_end) break;
        }

        const ofd = std.c.open(out_file_z.ptr, .{ .ACCMODE = .RDONLY });
        if (ofd >= 0) {
            _ = std.c.close(ofd);
            std.c._exit(4);
        }

        const wfd = std.c.open(ws_file_z.ptr, .{ .ACCMODE = .RDONLY });
        if (wfd < 0) std.c._exit(5);
        _ = std.c.close(wfd);

        std.c._exit(0);
    }

    const exit_code = try waitExitCode(pid);
    switch (exit_code) {
        0 => {},
        2 => return error.SeatbeltApplyFailedOnHost,
        3 => return error.PathWalkAncestorLstatDenied,
        4 => return error.OutsideReadableUnderPathWalkProfile,
        5 => return error.WorkspaceFileUnreadable,
        else => return error.UnexpectedSandboxChildExit,
    }
}

// Codex/Node residual: resolveMainPath realpathSync walks install path components
// under $HOME/.local/... (and lstats /Users first). Product must grant file-only
// .exec on the entry script and metadata on every ancestor so Seatbelt does not
// EPERM mid-walk. Also lstats Data-form `/System/Volumes/Data/Users` when present
// (firmlink residual after Data deny).
// Exit: 0=ok, 2=apply fail, 3=/Users lstat EPERM, 4=codex component lstat EPERM,
// 5=codex.js open fail (content/exec residual), 6=Data-form Users lstat EPERM.
test "real FS: Users path-walk + codex npm install realpath chain" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    if (!sandboxInitAvailable()) return error.SkipZigTest;
    const ver = try detectProductVersion();
    try std.testing.expect(isMatrixMajor(ver.major));
    try std.testing.expectEqual(SupportStatus.supported, evaluateSupport());

    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const home_z = std.c.getenv("HOME") orelse return error.SkipZigTest;
    const home = std.mem.span(home_z);
    if (!std.mem.startsWith(u8, home, "/Users/")) return error.SkipZigTest;

    const codex_js = try std.fs.path.join(allocator, &.{
        home,
        ".local/lib/node_modules/@openai/codex/bin/codex.js",
    });
    defer allocator.free(codex_js);
    std.Io.Dir.cwd().access(io, codex_js, .{}) catch return error.SkipZigTest;

    // Prefer real Users-form product workspace when present; else plant under $HOME.
    var planted_ws: ?[]u8 = null;
    defer if (planted_ws) |p| {
        std.Io.Dir.cwd().deleteTree(io, p) catch {};
        allocator.free(p);
    };

    const ws_root: []const u8 = blk: {
        const candidate = try std.fs.path.join(allocator, &.{ home, "CodingProjects/ryk" });
        if (std.Io.Dir.cwd().access(io, candidate, .{})) |_| {
            break :blk candidate;
        } else |_| {
            allocator.free(candidate);
        }
        const planted = try std.fs.path.join(allocator, &.{ home, ".ryk-tmp-pathwalk-probe" });
        std.Io.Dir.cwd().createDirPath(io, planted) catch {
            allocator.free(planted);
            return error.SkipZigTest;
        };
        planted_ws = planted;
        break :blk planted;
    };
    defer if (planted_ws == null) allocator.free(ws_root);

    const users_z = try allocator.dupeZ(u8, "/Users");
    defer allocator.free(users_z);
    const codex_z = try allocator.dupeZ(u8, codex_js);
    defer allocator.free(codex_z);

    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = ws_root,
        .include_tmp = false,
        .exec_paths = &.{codex_js},
    });
    defer compiled.deinit();

    const prepared = prepareForChildApply(allocator, &compiled);
    defer if (prepared.sbpl_z) |p| allocator.free(p);
    try std.testing.expectEqual(.prepared, prepared.status);
    const sbpl_z = prepared.sbpl_z.?;

    // Model: exec file + Users + Data-form Users ancestors must appear.
    try std.testing.expect(std.mem.indexOf(u8, sbpl_z, "(allow file-read-metadata (literal \"/Users\"))") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl_z, "(allow file-read-metadata (literal \"/System/Volumes/Data/Users\"))") != null);
    try std.testing.expect(std.mem.indexOf(u8, sbpl_z, "file-read*") != null);
    // No content grant on bare Data Users.
    try std.testing.expect(std.mem.indexOf(u8, sbpl_z, "(allow file-read* (subpath \"/System/Volumes/Data/Users\"))") == null);

    const data_users_z = try allocator.dupeZ(u8, "/System/Volumes/Data/Users");
    defer allocator.free(data_users_z);

    const pid = std.c.fork();
    if (pid < 0) return error.SkipZigTest;
    if (pid == 0) {
        applyInChild(sbpl_z.ptr) catch std.c._exit(2);

        const lstat_fn = struct {
            extern "c" fn lstat(p: [*:0]const u8, buf: *std.c.Stat) c_int;
        }.lstat;
        var st: std.c.Stat = undefined;
        if (lstat_fn(users_z.ptr, &st) != 0) std.c._exit(3);

        // Firmlink residual: Data-form vnode for /Users after Data deny.
        // Skip if the path is absent on this host (non-standard layout).
        if (lstat_fn(data_users_z.ptr, &st) != 0) {
            const e = std.c.errno(-1);
            // Only treat EPERM/EACCES as residual failure; ENOENT is skip-in-child.
            if (e == .PERM or e == .ACCES) std.c._exit(6);
        }

        // Component walk of codex install path (Node realpath shape).
        const path = codex_z;
        var i: usize = 1;
        while (i <= path.len) : (i += 1) {
            const at_end = i == path.len;
            const at_slash = !at_end and path[i] == '/';
            if (!at_end and !at_slash) continue;
            if (i <= 1) continue;
            var component_buf: [std.fs.max_path_bytes + 1]u8 = undefined;
            if (i >= component_buf.len) std.c._exit(4);
            @memcpy(component_buf[0..i], path[0..i]);
            component_buf[i] = 0;
            if (lstat_fn(@ptrCast(&component_buf), &st) != 0) std.c._exit(4);
            if (at_end) break;
        }

        const fd = std.c.open(codex_z.ptr, .{ .ACCMODE = .RDONLY });
        if (fd < 0) std.c._exit(5);
        _ = std.c.close(fd);
        std.c._exit(0);
    }

    const exit_code = try waitExitCode(pid);
    switch (exit_code) {
        0 => {},
        2 => return error.SeatbeltApplyFailedOnHost,
        3 => return error.UsersLstatDenied,
        4 => return error.CodexInstallPathWalkDenied,
        5 => return error.CodexJsUnreadable,
        6 => return error.DataFormUsersLstatDenied,
        else => return error.UnexpectedSandboxChildExit,
    }
}

// Live residual: hermes venv/python is a symlink → uv cpython outside `.hermes`.
// Seatbelt denies open/exec of the *symlink path* (cross-grant follow) even when
// the realpath target is RO-granted. Product rewrites argv to realpath
// (`expandShellWrapperLaunch`). Prove realpath exec works under production grants.
// Exit: 0=ok, 2=apply fail, 3=realpath exec fail, 5=realpath unreadable.
test "real FS: hermes nested uv python exec under launch grants" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    if (!sandboxInitAvailable()) return error.SkipZigTest;
    const ver = try detectProductVersion();
    try std.testing.expect(isMatrixMajor(ver.major));
    try std.testing.expectEqual(SupportStatus.supported, evaluateSupport());

    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const apply = @import("apply.zig");
    const host_config_grants = @import("host_config_grants.zig");

    const home_z = std.c.getenv("HOME") orelse return error.SkipZigTest;
    const home = std.mem.span(home_z);
    if (home.len == 0) return error.SkipZigTest;

    const wrapper = try std.fs.path.join(allocator, &.{ home, ".local/bin/hermes" });
    defer allocator.free(wrapper);
    const venv_py = try std.fs.path.join(allocator, &.{ home, ".hermes/hermes-agent/venv/bin/python" });
    defer allocator.free(venv_py);
    std.Io.Dir.cwd().access(io, wrapper, .{}) catch return error.SkipZigTest;
    std.Io.Dir.cwd().access(io, venv_py, .{}) catch return error.SkipZigTest;

    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    try env_map.put("HOME", home);
    try env_map.put("PATH", "/usr/bin:/bin");

    const execs = try apply.collectLaunchExecPaths(io, allocator, wrapper, &env_map);
    defer apply.freeLaunchExecPaths(allocator, execs);
    const ros = try apply.collectLaunchInstallRoPaths(io, allocator, wrapper, &env_map);
    defer apply.freeLaunchInstallRoPaths(allocator, ros);
    const host_rw = try host_config_grants.collectHostConfigPaths(io, allocator, "hermes", home);
    defer host_config_grants.freeHostConfigPaths(allocator, host_rw);
    try std.testing.expect(host_rw.len > 0);
    try std.testing.expect(ros.len > 0);

    var real_buf: [std.fs.max_path_bytes]u8 = undefined;
    const real_py: []const u8 = blk: {
        var in_buf: [std.fs.max_path_bytes]u8 = undefined;
        @memcpy(in_buf[0..venv_py.len], venv_py);
        in_buf[venv_py.len] = 0;
        const r = std.c.realpath(in_buf[0..venv_py.len :0].ptr, &real_buf) orelse break :blk venv_py;
        break :blk std.mem.span(r);
    };

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const ws = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(ws);

    var compiled = try profile.compileProfile(allocator, .{
        .workspace_root = ws,
        .include_tmp = false,
        .exec_paths = execs,
        .ro_paths = ros,
        .host_rw_paths = host_rw,
        .protect_workspace_secrets = false,
    });
    defer compiled.deinit();
    try std.testing.expect(compiled.isGrantedReadable(real_py));

    const prepared = prepareForChildApply(allocator, &compiled);
    defer if (prepared.sbpl_z) |p| allocator.free(p);
    try std.testing.expectEqual(.prepared, prepared.status);
    const sbpl_z = prepared.sbpl_z.?;
    // Classic uv layout or Hermes-managed runtime cpython (generation/cpython-…).
    const has_nested_python_grant = std.mem.indexOf(u8, sbpl_z, "/.local/share/uv/python/") != null or
        std.mem.indexOf(u8, sbpl_z, "/.hermes-runtime/python/") != null or
        std.mem.indexOf(u8, sbpl_z, "/cpython-") != null;
    try std.testing.expect(has_nested_python_grant);

    const real_z = try allocator.dupeZ(u8, real_py);
    defer allocator.free(real_z);

    const pid = std.c.fork();
    if (pid < 0) return error.SkipZigTest;
    if (pid == 0) {
        applyInChild(sbpl_z.ptr) catch std.c._exit(2);
        const rfd = std.c.open(real_z.ptr, .{ .ACCMODE = .RDONLY });
        if (rfd < 0) std.c._exit(5);
        _ = std.c.close(rfd);
        const argv = [_:null]?[*:0]const u8{ real_z.ptr, "--version", null };
        _ = std.c.execve(real_z.ptr, @ptrCast(&argv), @ptrCast(std.c.environ));
        std.c._exit(3);
    }

    const exit_code = try waitExitCode(pid);
    switch (exit_code) {
        0 => {},
        2 => return error.SeatbeltApplyFailedOnHost,
        3 => return error.HermesNestedPythonExecDenied,
        5 => return error.HermesUvPythonUnreadable,
        else => return error.UnexpectedSandboxChildExit,
    }
}

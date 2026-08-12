const std = @import("std");

const onboarding = @import("ryk").cli.onboarding;
const start = @import("ryk").cli.start;
const exit_codes = @import("ryk").cli.exit_codes;
const shell_eval = @import("ryk").cli.shell_eval;

test "phase45 start idempotent second run preserves policy" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var stdout_buf: [32768]u8 = undefined;
    var stderr_buf: [1024]u8 = undefined;

    const flags = onboarding.StartFlags{
        .auto = true,
        .protection = .firewall,
        .skip_verify = true,
    };

    const mock_checker = struct {
        fn check(_: std.mem.Allocator, _: bool) !void {}
    }.check;

    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);
    const first = try start.runStart(
        std.testing.io,
        tmp.dir,
        flags,
        &stdout_writer,
        &stderr_writer,
        mock_checker,
        onboarding.mockOnboardingEvaluator,
    );
    try std.testing.expectEqual(exit_codes.success, first);

    stdout_writer = .fixed(&stdout_buf);
    stderr_writer = .fixed(&stderr_buf);
    const second = try start.runStart(
        std.testing.io,
        tmp.dir,
        flags,
        &stdout_writer,
        &stderr_writer,
        mock_checker,
        onboarding.mockOnboardingEvaluator,
    );
    try std.testing.expectEqual(exit_codes.success, second);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "Policy already exists") != null);
}

test "phase45 maximum protection verifies shell path with mock evaluator" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(std.testing.io, ".ryk");
    {
        const file = try tmp.dir.createFile(std.testing.io, ".ryk/policy.yaml", .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io, "version: 1\nmode: strict\n");
    }

    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    const outcome = try onboarding.runVerification(
        std.testing.allocator,
        std.testing.io,
        root,
        .maximum_protection,
        &.{},
        onboarding.mockOnboardingEvaluator,
        null,
    );
    try std.testing.expect(outcome.passed());
}

test "phase45 command guard onboarding is in-process and does not require a daemon" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var stdout_buf: [16384]u8 = undefined;
    var stderr_buf: [1024]u8 = undefined;
    var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
    var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

    const flags = onboarding.StartFlags{
        .auto = true,
        .protection = .command_guard,
        .hosts_csv = "",
        .skip_verify = true,
    };

    const failing_checker = struct {
        fn check(_: std.mem.Allocator, _: bool) !void {
            return error.DaemonBinaryNotFound;
        }
    }.check;

    const code = try start.runStart(
        std.testing.io,
        tmp.dir,
        flags,
        &stdout_writer,
        &stderr_writer,
        failing_checker,
        null,
    );
    try std.testing.expectEqual(exit_codes.success, code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "Zig shell_engine ready (in-process)") != null);
}

test "phase45 allow-only mock fails verification gate" {
    const outcome = try onboarding.verifyShellEvaluation(
        std.testing.allocator,
        null,
        shell_eval.mockDaemonAllowEvaluator,
    );
    try std.testing.expect(!outcome.passed());
}

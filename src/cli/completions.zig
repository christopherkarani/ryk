const std = @import("std");

const exit_codes = @import("exit_codes.zig");
const help = @import("help.zig");

const global_flags = [_][]const u8{ "--help", "--no-rich" };

const max_command_flags = 64;

pub fn command(io: std.Io, argv: []const []const u8, stdout: anytype, stderr: anytype) !u8 {
    if (argv.len == 1 and (std.mem.eql(u8, argv[0], "--help") or std.mem.eql(u8, argv[0], "-h"))) {
        _ = try help.writeCommand(io, stdout, "completions");
        return exit_codes.success;
    }
    if (argv.len != 1) {
        try stderr.writeAll("ryk completions: expected one shell: bash, zsh, fish, or powershell.\n");
        return exit_codes.usage;
    }

    const shell = argv[0];
    if (std.mem.eql(u8, shell, "bash")) {
        try writeBash(stdout);
    } else if (std.mem.eql(u8, shell, "zsh")) {
        try writeZsh(stdout);
    } else if (std.mem.eql(u8, shell, "fish")) {
        try writeFish(stdout);
    } else if (std.mem.eql(u8, shell, "powershell")) {
        try writePowerShell(stdout);
    } else {
        try stderr.print("ryk completions: unsupported shell '{s}'. Expected bash, zsh, fish, or powershell.\n", .{shell});
        return exit_codes.usage;
    }
    return exit_codes.success;
}

fn writeWords(writer: anytype, words: []const []const u8) !void {
    for (words, 0..) |word, index| {
        if (index > 0) try writer.writeByte(' ');
        try writer.writeAll(word);
    }
}

fn writePublicCommands(writer: anytype) !void {
    var first = true;
    for (help.commands) |cmd| {
        if (cmd.hidden) continue;
        if (!first) try writer.writeByte(' ');
        try writer.writeAll(cmd.name);
        first = false;
    }
}

/// Extract long flags from help text. Soft-caps at `flags.len` — extras are dropped
/// rather than panicking or overflowing the fixed buffer.
fn appendLongFlags(text: []const u8, flags: *[max_command_flags][]const u8, len: *usize) void {
    var cursor: usize = 0;
    while (std.mem.indexOfPos(u8, text, cursor, "--")) |start| {
        var end = start + 2;
        while (end < text.len and (std.ascii.isAlphanumeric(text[end]) or text[end] == '-')) : (end += 1) {}
        cursor = end;
        if (end == start + 2) continue;

        const candidate = text[start..end];
        for (flags[0..len.*]) |existing| {
            if (std.mem.eql(u8, candidate, existing)) break;
        } else {
            if (len.* >= flags.len) return; // soft-cap: keep first N unique flags
            flags[len.*] = candidate;
            len.* += 1;
        }
    }
}

fn commandFlags(command_info: help.CommandInfo, buffer: *[max_command_flags][]const u8) []const []const u8 {
    var len: usize = 0;
    appendLongFlags(command_info.usage, buffer, &len);
    for (command_info.examples) |example| appendLongFlags(example, buffer, &len);
    for (command_info.additional_completion_flags) |flag| appendLongFlags(flag, buffer, &len);
    return buffer[0..len];
}

fn writeBashCases(writer: anytype) !void {
    for (help.commands) |cmd| {
        if (cmd.hidden) continue;
        var flag_buffer: [max_command_flags][]const u8 = undefined;
        const flags = commandFlags(cmd, &flag_buffer);
        if (flags.len == 0) continue;
        try writer.print("    {s}) has_command=true; flags=\"${{flags}}", .{cmd.name});
        if (flags.len > 0) {
            try writer.writeByte(' ');
            try writeWords(writer, flags);
        }
        try writer.writeAll("\" ;;\n");
    }
}

fn writeZshCases(writer: anytype) !void {
    for (help.commands) |cmd| {
        if (cmd.hidden) continue;
        var flag_buffer: [max_command_flags][]const u8 = undefined;
        const flags = commandFlags(cmd, &flag_buffer);
        if (flags.len == 0) continue;
        try writer.print("    {s}) has_command=true; flags+=(", .{cmd.name});
        for (flags) |flag| try writer.print(" '{s}'", .{flag});
        try writer.writeAll(" ) ;;\n");
    }
}

fn writeBash(writer: anytype) !void {
    try writer.writeAll(
        \\_ryk_completions() {
        \\  local cur commands command flags has_command word
        \\  COMPREPLY=()
        \\  cur="${COMP_WORDS[COMP_CWORD]}"
        \\  command=""
        \\  has_command=false
        \\  for word in "${COMP_WORDS[@]:1}"; do
        \\    [[ "${word}" == -* ]] && continue
        \\    command="${word}"
        \\    break
        \\  done
        \\  commands="
    );
    try writePublicCommands(writer);
    try writer.writeAll(
        \\"
        \\  flags="
    );
    try writeWords(writer, &global_flags);
    try writer.writeAll(
        \\"
        \\  case " ${commands} " in *" ${command} "*) has_command=true ;; esac
        \\  case "${command}" in
    );
    try writeBashCases(writer);
    try writer.writeAll(
        \\  esac
        \\  if [[ "${has_command}" != true ]]; then
        \\    COMPREPLY=( $(compgen -W "${commands} ${flags}" -- "${cur}") )
        \\  else
        \\    COMPREPLY=( $(compgen -W "${flags}" -- "${cur}") )
        \\  fi
        \\}
        \\complete -F _ryk_completions ryk
        \\
    );
}

fn writeZsh(writer: anytype) !void {
    try writer.writeAll(
        \\#compdef ryk
        \\_ryk() {
        \\  local -a commands flags
        \\  local command word
        \\  local has_command=false
        \\  commands=(
    );
    for (help.commands) |cmd| {
        if (!cmd.hidden) try writer.print("    '{s}'\n", .{cmd.name});
    }
    try writer.writeAll(
        \\  )
        \\  flags=(
    );
    for (global_flags) |flag| try writer.print("    '{s}'\n", .{flag});
    try writer.writeAll(
        \\  )
        \\  command=""
        \\  for word in "${words[@]:2}"; do
        \\    [[ "${word}" == -* ]] && continue
        \\    command="${word}"
        \\    break
        \\  done
        \\  (( ${commands[(Ie)$command]} )) && has_command=true
        \\  case "${command}" in
    );
    try writeZshCases(writer);
    try writer.writeAll(
        \\  esac
        \\  if [[ "${has_command}" != true ]]; then
        \\    _describe 'command' commands
        \\  else
        \\    _describe 'flag' flags
        \\  fi
        \\}
        \\_ryk "$@"
        \\
    );
}

fn writeFish(writer: anytype) !void {
    for (help.commands) |cmd| {
        if (!cmd.hidden) try writer.print("complete -c ryk -f -n '__fish_use_subcommand' -a '{s}'\n", .{cmd.name});
    }
    for (global_flags) |flag| {
        try writer.print("complete -c ryk -f -l {s}\n", .{flag[2..]});
    }
    for (help.commands) |cmd| {
        if (cmd.hidden) continue;
        var flag_buffer: [max_command_flags][]const u8 = undefined;
        for (commandFlags(cmd, &flag_buffer)) |flag| {
            try writer.print("complete -c ryk -f -n '__fish_seen_subcommand_from {s}' -l {s}\n", .{ cmd.name, flag[2..] });
        }
    }
}

fn writePowerShell(writer: anytype) !void {
    try writer.writeAll(
        \\Register-ArgumentCompleter -Native -CommandName ryk -ScriptBlock {
        \\  param($wordToComplete, $commandAst, $cursorPosition)
        \\  $commands = @(
    );
    for (help.commands) |cmd| {
        if (!cmd.hidden) try writer.print("    '{s}'\n", .{cmd.name});
    }
    try writer.writeAll(
        \\  )
        \\  $globalFlags = @(
    );
    for (global_flags) |flag| try writer.print("    '{s}'\n", .{flag});
    try writer.writeAll(
        \\  )
        \\  $elements = @($commandAst.CommandElements)
        \\  $flags = @($globalFlags)
        \\  $commandName = $null
        \\  $hasCommand = $false
        \\  foreach ($element in $elements | Select-Object -Skip 1) {
        \\    $text = $element.Extent.Text
        \\    if (-not $text.StartsWith('-')) {
        \\      $commandName = $text
        \\      break
        \\    }
        \\  }
        \\  $hasCommand = $commands -contains $commandName
        \\  switch ($commandName) {
    );
    for (help.commands) |cmd| {
        if (cmd.hidden) continue;
        var flag_buffer: [max_command_flags][]const u8 = undefined;
        const flags = commandFlags(cmd, &flag_buffer);
        if (flags.len == 0) continue;
        try writer.print("    '{s}' {{ $hasCommand = $true; $flags += @(", .{cmd.name});
        for (flags, 0..) |flag, index| {
            if (index > 0) try writer.writeAll(", ");
            try writer.print("'{s}'", .{flag});
        }
        try writer.writeAll(") }\n");
    }
    try writer.writeAll(
        \\  }
        \\  $candidates = if (-not $hasCommand) { $commands + $globalFlags } else { $flags }
        \\  $candidates | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
        \\    [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        \\  }
        \\}
        \\
    );
}

test "appendLongFlags soft-caps without panic or overflow" {
    var buffer: [max_command_flags][]const u8 = undefined;
    var len: usize = 0;

    // Build a synthetic help string with more unique flags than the fixed buffer.
    var text_aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer text_aw.deinit();
    var index: usize = 0;
    while (index < max_command_flags + 32) : (index += 1) {
        try text_aw.writer.print(" --flag{d}", .{index});
    }
    appendLongFlags(text_aw.writer.buffered(), &buffer, &len);
    try std.testing.expectEqual(@as(usize, max_command_flags), len);
    try std.testing.expectEqualStrings("--flag0", buffer[0]);
    try std.testing.expectEqualStrings("--flag63", buffer[max_command_flags - 1]);
}

test "completions output is non-empty for supported shells" {
    const shells = [_][]const u8{ "bash", "zsh", "fish", "powershell" };
    for (shells) |shell| {
        var stdout_buf: [32 * 1024]u8 = undefined;
        var stderr_buf: [512]u8 = undefined;
        var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
        var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

        const code = try command(std.testing.io, &.{shell}, &stdout_writer, &stderr_writer);
        try std.testing.expectEqual(exit_codes.success, code);
        try std.testing.expect(stdout_writer.buffered().len > 0);
        try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "run") != null);
        try std.testing.expectEqualStrings("", stderr_writer.buffered());
    }
}

test "completions hide internal commands and expose global no-rich flag" {
    const shells = [_][]const u8{ "bash", "zsh", "fish", "powershell" };
    for (shells) |shell| {
        var stdout_buf: [32 * 1024]u8 = undefined;
        var stderr_buf: [512]u8 = undefined;
        var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
        var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

        const code = try command(std.testing.io, &.{shell}, &stdout_writer, &stderr_writer);
        const output = stdout_writer.buffered();

        try std.testing.expectEqual(exit_codes.success, code);
        try std.testing.expect(std.mem.indexOf(u8, output, "shim") == null);
        const no_rich = if (std.mem.eql(u8, shell, "fish")) "-l no-rich" else "--no-rich";
        try std.testing.expect(std.mem.indexOf(u8, output, no_rich) != null);
        try std.testing.expectEqualStrings("", stderr_writer.buffered());
    }
}

test "completions include command-specific dashboard flags" {
    // packs is P0-hidden until Slice 4 lands; only assert live command flags here.
    const shells = [_][]const u8{ "bash", "zsh", "fish", "powershell" };
    const required_flags = [_][]const u8{
        "--machine", "--workspace", "--host", "--port", "--once", "--view", "--demo",
    };
    for (shells) |shell| {
        var stdout_buf: [32 * 1024]u8 = undefined;
        var stderr_buf: [512]u8 = undefined;
        var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
        var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

        const code = try command(std.testing.io, &.{shell}, &stdout_writer, &stderr_writer);
        const output = stdout_writer.buffered();

        try std.testing.expectEqual(exit_codes.success, code);
        for (required_flags) |flag| {
            if (std.mem.eql(u8, shell, "fish")) {
                var needle_buf: [64]u8 = undefined;
                const needle = try std.fmt.bufPrint(&needle_buf, "-l {s}", .{flag[2..]});
                try std.testing.expect(std.mem.indexOf(u8, output, needle) != null);
            } else {
                try std.testing.expect(std.mem.indexOf(u8, output, flag) != null);
            }
        }
        try std.testing.expectEqualStrings("", stderr_writer.buffered());
    }
}

test "completions scope flags to their owning command" {
    const cases = [_]struct {
        shell: []const u8,
        dashboard_scope: []const u8,
        init_scope: []const u8,
    }{
        .{ .shell = "bash", .dashboard_scope = "dashboard) has_command=true; flags=", .init_scope = "init) has_command=true; flags=" },
        .{ .shell = "zsh", .dashboard_scope = "dashboard) has_command=true; flags+=(", .init_scope = "init) has_command=true; flags+=(" },
        .{ .shell = "fish", .dashboard_scope = "__fish_seen_subcommand_from dashboard", .init_scope = "__fish_seen_subcommand_from init" },
        .{ .shell = "powershell", .dashboard_scope = "'dashboard' { $hasCommand = $true; $flags +=", .init_scope = "'init' { $hasCommand = $true; $flags +=" },
    };
    for (cases) |case| {
        var stdout_buf: [32 * 1024]u8 = undefined;
        var stderr_buf: [512]u8 = undefined;
        var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
        var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

        const code = try command(std.testing.io, &.{case.shell}, &stdout_writer, &stderr_writer);
        const output = stdout_writer.buffered();

        try std.testing.expectEqual(exit_codes.success, code);
        try std.testing.expect(std.mem.indexOf(u8, output, case.dashboard_scope) != null);
        try std.testing.expect(std.mem.indexOf(u8, output, case.init_scope) != null);
        try std.testing.expectEqualStrings("", stderr_writer.buffered());
    }
}

// ---------------------------------------------------------------------------
// Completions must stay in sync with help.commands.
// ---------------------------------------------------------------------------

test "completions include every public help command" {
    const shells = [_][]const u8{ "bash", "zsh", "fish", "powershell" };
    for (shells) |shell| {
        var stdout_buf: [32 * 1024]u8 = undefined;
        var stderr_buf: [512]u8 = undefined;
        var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
        var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

        const code = try command(std.testing.io, &.{shell}, &stdout_writer, &stderr_writer);
        try std.testing.expectEqual(exit_codes.success, code);

        for (help.commands) |cmd| {
            if (cmd.hidden) continue;
            try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), cmd.name) != null);
        }
    }
}

test "completions discover the first public command after global options" {
    const cases = [_]struct {
        shell: []const u8,
        marker: []const u8,
    }{
        .{ .shell = "bash", .marker = "for word in \"${COMP_WORDS[@]:1}\"" },
        .{ .shell = "zsh", .marker = "for word in \"${words[@]:2}\"" },
        .{ .shell = "powershell", .marker = "Select-Object -Skip 1" },
    };

    for (cases) |case| {
        var stdout_buf: [32 * 1024]u8 = undefined;
        var stderr_buf: [512]u8 = undefined;
        var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
        var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

        const code = try command(std.testing.io, &.{case.shell}, &stdout_writer, &stderr_writer);
        try std.testing.expectEqual(exit_codes.success, code);
        try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), case.marker) != null);
    }
}

test "completions expose canonical init and onboarding flags" {
    // history is on the Slice 1 hide-list; do not require its completion surface.
    const cases = [_]struct {
        shell: []const u8,
        required: []const []const u8,
    }{
        // Public onboarding door is `start` (setup/quickstart are hidden / hard-removed).
        .{ .shell = "bash", .required = &.{ "init) has_command=true; flags=\"${flags} --preset --mode --ci --force --quiet", "start) has_command=true; flags=\"${flags} --auto --yes --no-interact --hosts --preset --skip-verify" } },
        .{ .shell = "zsh", .required = &.{ "init) has_command=true; flags+=( '--preset' '--mode' '--ci' '--force' '--quiet'", "start) has_command=true; flags+=( '--auto' '--yes' '--no-interact' '--hosts' '--preset' '--skip-verify'" } },
        .{ .shell = "fish", .required = &.{ "__fish_seen_subcommand_from init' -l quiet", "__fish_seen_subcommand_from start' -l no-interact" } },
        .{ .shell = "powershell", .required = &.{ "'init' { $hasCommand = $true; $flags += @('--preset', '--mode', '--ci', '--force', '--quiet')", "'start' { $hasCommand = $true; $flags += @('--auto', '--yes', '--no-interact', '--hosts', '--preset', '--skip-verify')" } },
    };

    for (cases) |case| {
        var stdout_buf: [32 * 1024]u8 = undefined;
        var stderr_buf: [512]u8 = undefined;
        var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
        var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

        const code = try command(std.testing.io, &.{case.shell}, &stdout_writer, &stderr_writer);
        try std.testing.expectEqual(exit_codes.success, code);
        for (case.required) |needle| {
            try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), needle) != null);
        }
    }
}

/// True when shell completion script registers `name` as a top-level ryk subcommand.
/// Token-equal within the top-level commands list only — free `indexOf("'allow'")`
/// would false-hit `'allowlist'` on zsh/powershell.
fn completionRegistersCommand(output: []const u8, shell: []const u8, name: []const u8) bool {
    if (std.mem.eql(u8, shell, "bash")) {
        // `commands="…"` is a space-separated word list of public verbs.
        const marker = "commands=\"";
        const start = std.mem.indexOf(u8, output, marker) orelse return false;
        const after = output[start + marker.len ..];
        const end = std.mem.indexOfScalar(u8, after, '"') orelse return false;
        var it = std.mem.tokenizeAny(u8, after[0..end], " \n\t\r");
        while (it.next()) |word| {
            if (std.mem.eql(u8, word, name)) return true;
        }
        return false;
    }
    if (std.mem.eql(u8, shell, "fish")) {
        // `complete … -a 'name'` — closing quote makes `'allow'` not a prefix of `'allowlist'`.
        var needle_buf: [80]u8 = undefined;
        const needle = std.fmt.bufPrint(&needle_buf, "-a '{s}'", .{name}) catch return false;
        return std.mem.indexOf(u8, output, needle) != null;
    }
    // zsh: commands=( … 'name' … ) ; powershell: $commands = @( … 'name' … )
    const start_marker: []const u8 = if (std.mem.eql(u8, shell, "zsh"))
        "commands=("
    else if (std.mem.eql(u8, shell, "powershell"))
        "$commands = @("
    else
        return false;
    const start = std.mem.indexOf(u8, output, start_marker) orelse return false;
    const after = output[start + start_marker.len ..];
    const end = std.mem.indexOfScalar(u8, after, ')') orelse return false;
    const region = after[0..end];
    var needle_buf: [72]u8 = undefined;
    const needle = std.fmt.bufPrint(&needle_buf, "'{s}'", .{name}) catch return false;
    var lines = std.mem.splitScalar(u8, region, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (std.mem.eql(u8, trimmed, needle)) return true;
    }
    return false;
}

test "P0 honesty: completions omit hide-list ports but include live P0 + shutdown" {
    const hidden = [_][]const u8{
        "precommit", "simulate", "classify", "suggest-allowlist",
        "history",   "rebase-recover", "config",
    };
    const live_scan = [_][]const u8{"scan"};
    const live_p0 = [_][]const u8{
        "packs", "allowlist", "allow", "unallow", "allow-once", "shutdown",
    };
    const shells = [_][]const u8{ "bash", "zsh", "fish", "powershell" };
    for (shells) |shell| {
        var stdout_buf: [32 * 1024]u8 = undefined;
        var stderr_buf: [512]u8 = undefined;
        var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
        var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

        const code = try command(std.testing.io, &.{shell}, &stdout_writer, &stderr_writer);
        try std.testing.expectEqual(exit_codes.success, code);
        const output = stdout_writer.buffered();

        for (live_p0) |name| {
            try std.testing.expect(completionRegistersCommand(output, shell, name));
        }
        for (live_scan) |name| {
            try std.testing.expect(completionRegistersCommand(output, shell, name));
        }
        for (hidden) |name| {
            try std.testing.expect(!completionRegistersCommand(output, shell, name));
        }
        try std.testing.expectEqualStrings("", stderr_writer.buffered());
    }
}

test "GitHub Actions documentation includes ryk run and redteam commands" {
    const doc = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, "docs/ci/github-actions.md", std.testing.allocator, .limited(32 * 1024));
    defer std.testing.allocator.free(doc);
    try std.testing.expect(std.mem.indexOf(u8, doc, "ryk run --mode ci -- ./scripts/agent-task.sh") != null);
    try std.testing.expect(std.mem.indexOf(u8, doc, "ryk redteam --ci") != null);
    try std.testing.expect(std.mem.indexOf(u8, doc, "actions/upload-artifact@v4") != null);
}

test "generated completions expose only the ryk command brand" {
    const shells = [_][]const u8{ "bash", "zsh", "fish", "powershell" };
    for (shells) |shell| {
        var stdout_buf: [32 * 1024]u8 = undefined;
        var stderr_buf: [512]u8 = undefined;
        var stdout_writer: std.Io.Writer = .fixed(&stdout_buf);
        var stderr_writer: std.Io.Writer = .fixed(&stderr_buf);

        const code = try command(std.testing.io, &.{shell}, &stdout_writer, &stderr_writer);
        try std.testing.expectEqual(exit_codes.success, code);
        // Split retired brand so bulk renames cannot self-corrupt this assert.
        const retired = "orc" ++ "a";
        try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), retired) == null);
        try std.testing.expect(std.mem.indexOf(u8, stdout_writer.buffered(), "ryk") != null);
    }
}

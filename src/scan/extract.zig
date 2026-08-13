//! Shared extraction of command candidates and text blobs from session JSON values.
const std = @import("std");
const types = @import("types.zig");

pub const Candidate = struct {
    command: ?[]const u8 = null,
    text_blob: ?[]const u8 = null,
    timestamp_secs: ?i64 = null,
};

/// Collect string fields that look like shell commands from a JSON value (shallow recursive).
pub fn walkValueForCommands(
    allocator: std.mem.Allocator,
    value: std.json.Value,
    out: *std.ArrayList([]const u8),
    depth: u8,
) !void {
    if (depth > 8) return;
    switch (value) {
        .object => |obj| {
            // Prefer known command keys.
            if (obj.get("command")) |c| {
                if (c == .string and c.string.len > 0) {
                    try appendOwned(allocator, out, c.string);
                }
            }
            if (obj.get("cmd")) |c| {
                if (c == .string and c.string.len > 0) {
                    try appendOwned(allocator, out, c.string);
                }
            }
            // Claude: message.content[].input.command with name Bash
            if (obj.get("name")) |name_v| {
                if (name_v == .string) {
                    const n = name_v.string;
                    if (isShellToolName(n)) {
                        if (obj.get("input")) |input| {
                            if (input == .object) {
                                if (input.object.get("command")) |cmd| {
                                    if (cmd == .string) try appendOwned(allocator, out, cmd.string);
                                }
                            }
                        }
                        if (obj.get("arguments")) |args| {
                            try extractCommandFromArguments(allocator, args, out);
                        }
                    }
                }
            }
            // Grok tool_calls: {name: run_terminal_command, arguments: "{\"command\":\"...\"}"}
            if (obj.get("tool_calls")) |tc| {
                if (tc == .array) {
                    for (tc.array.items) |item| {
                        try walkValueForCommands(allocator, item, out, depth + 1);
                    }
                }
            }
            // OpenCode / generic tool state.input.command
            if (obj.get("tool")) |tool| {
                if (tool == .string and isShellToolName(tool.string)) {
                    if (obj.get("state")) |state| {
                        if (state == .object) {
                            if (state.object.get("input")) |input| {
                                if (input == .object) {
                                    if (input.object.get("command")) |cmd| {
                                        if (cmd == .string) try appendOwned(allocator, out, cmd.string);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            // Codex exec_command / custom_tool_call input string
            if (obj.get("input")) |input| {
                if (input == .string) {
                    try extractCmdFromCodexInput(allocator, input.string, out);
                }
            }
            // Pi toolCall
            if (obj.get("type")) |t| {
                if (t == .string and (std.mem.eql(u8, t.string, "toolCall") or std.mem.eql(u8, t.string, "tool_use"))) {
                    if (obj.get("name")) |name_v| {
                        if (name_v == .string and isShellToolName(name_v.string)) {
                            if (obj.get("arguments")) |args| {
                                try extractCommandFromArguments(allocator, args, out);
                            }
                            if (obj.get("input")) |input| {
                                if (input == .object) {
                                    if (input.object.get("command")) |cmd| {
                                        if (cmd == .string) try appendOwned(allocator, out, cmd.string);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            // Recurse limited children commonly carrying nested content.
            const recurse_keys = [_][]const u8{ "message", "content", "payload", "arguments", "input", "state", "tool_calls" };
            for (recurse_keys) |key| {
                if (obj.get(key)) |child| {
                    try walkValueForCommands(allocator, child, out, depth + 1);
                }
            }
        },
        .array => |arr| {
            for (arr.items) |item| {
                try walkValueForCommands(allocator, item, out, depth + 1);
            }
        },
        else => {},
    }
}

/// Collect text blobs for secret material scanning (assistant/user text, tool outputs).
pub fn walkValueForTextBlobs(
    allocator: std.mem.Allocator,
    value: std.json.Value,
    out: *std.ArrayList([]const u8),
    depth: u8,
) !void {
    if (depth > 6) return;
    switch (value) {
        .object => |obj| {
            const text_keys = [_][]const u8{ "text", "content", "output", "result" };
            for (text_keys) |key| {
                if (obj.get(key)) |v| {
                    if (v == .string and v.string.len >= 12) {
                        const take = @min(v.string.len, types.max_file_bytes);
                        try appendOwned(allocator, out, v.string[0..take]);
                    } else {
                        try walkValueForTextBlobs(allocator, v, out, depth + 1);
                    }
                }
            }
            if (obj.get("message")) |m| try walkValueForTextBlobs(allocator, m, out, depth + 1);
            if (obj.get("payload")) |p| try walkValueForTextBlobs(allocator, p, out, depth + 1);
        },
        .array => |arr| {
            for (arr.items) |item| try walkValueForTextBlobs(allocator, item, out, depth + 1);
        },
        .string => |s| {
            if (s.len >= 20 and s.len <= types.max_file_bytes) {
                // Only keep if it looks secret-ish to avoid memory blowup.
                if (std.mem.indexOf(u8, s, "ghp_") != null or
                    std.mem.indexOf(u8, s, "sk-") != null or
                    std.mem.indexOf(u8, s, "AKIA") != null or
                    std.mem.indexOf(u8, s, "BEGIN PRIVATE") != null or
                    std.mem.indexOf(u8, s, "api_key") != null or
                    std.mem.indexOf(u8, s, "API_KEY") != null or
                    std.mem.indexOf(u8, s, "SECRET") != null or
                    std.mem.indexOf(u8, s, "password") != null)
                {
                    try appendOwned(allocator, out, s);
                }
            }
        },
        else => {},
    }
}

fn isShellToolName(name: []const u8) bool {
    const names = [_][]const u8{
        "Bash",        "bash",        "Shell",                "shell",
        "exec",        "Exec",        "run_terminal_command", "run_terminal",
        "terminal",    "local_shell", "shell_command",        "BashTool",
        "run_command", "execute",
    };
    for (names) |n| {
        if (std.mem.eql(u8, name, n)) return true;
    }
    // Case-insensitive contains "bash" / "shell" for tool names.
    if (std.ascii.eqlIgnoreCase(name, "bash") or std.ascii.eqlIgnoreCase(name, "shell")) return true;
    return false;
}

fn extractCommandFromArguments(allocator: std.mem.Allocator, args: std.json.Value, out: *std.ArrayList([]const u8)) !void {
    switch (args) {
        .object => |obj| {
            if (obj.get("command")) |c| {
                if (c == .string) try appendOwned(allocator, out, c.string);
            }
            if (obj.get("cmd")) |c| {
                if (c == .string) try appendOwned(allocator, out, c.string);
            }
        },
        .string => |s| {
            // JSON-encoded arguments string (Grok style).
            if (s.len > 0 and s[0] == '{') {
                var parsed = std.json.parseFromSlice(std.json.Value, allocator, s, .{}) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => {
                        try extractCmdFromCodexInput(allocator, s, out);
                        return;
                    },
                };
                defer parsed.deinit();
                try extractCommandFromArguments(allocator, parsed.value, out);
            } else {
                try extractCmdFromCodexInput(allocator, s, out);
            }
        },
        else => {},
    }
}

fn extractCmdFromCodexInput(allocator: std.mem.Allocator, input: []const u8, out: *std.ArrayList([]const u8)) !void {
    // Pattern: tools.exec_command({"cmd":"..."})
    if (std.mem.indexOf(u8, input, "\"cmd\"")) |idx| {
        const after = input[idx + 5 ..];
        // find : "..."
        const colon = std.mem.indexOfScalar(u8, after, ':') orelse return;
        var i = colon + 1;
        while (i < after.len and (after[i] == ' ' or after[i] == '\t')) : (i += 1) {}
        if (i >= after.len or after[i] != '"') return;
        i += 1;
        var out_buf: std.ArrayList(u8) = .empty;
        defer out_buf.deinit(allocator);
        while (i < after.len) : (i += 1) {
            const c = after[i];
            if (c == '\\' and i + 1 < after.len) {
                const n = after[i + 1];
                switch (n) {
                    'n' => try out_buf.append(allocator, '\n'),
                    't' => try out_buf.append(allocator, '\t'),
                    'r' => try out_buf.append(allocator, '\r'),
                    '"', '\\', '/' => try out_buf.append(allocator, n),
                    else => try out_buf.append(allocator, n),
                }
                i += 1;
                continue;
            }
            if (c == '"') break;
            try out_buf.append(allocator, c);
        }
        if (out_buf.items.len > 0) {
            const owned = try out_buf.toOwnedSlice(allocator);
            errdefer allocator.free(owned);
            // Reuse appendOwned for cap + dedup (it re-dupes; free local owned after).
            try appendOwned(allocator, out, owned);
            allocator.free(owned);
        }
        return;
    }
    // Bare command string if short and shell-like.
    if (input.len < 400 and (std.mem.indexOfScalar(u8, input, ' ') != null or std.mem.startsWith(u8, input, "rm ") or std.mem.startsWith(u8, input, "git "))) {
        try appendOwned(allocator, out, input);
    }
}

fn appendOwned(allocator: std.mem.Allocator, out: *std.ArrayList([]const u8), s: []const u8) !void {
    if (out.items.len >= types.max_commands_per_session) return;
    const trimmed = std.mem.trim(u8, s, " \t\r\n");
    if (trimmed.len == 0) return;
    // Dedup exact command lines within a session parse.
    for (out.items) |existing| {
        if (std.mem.eql(u8, existing, trimmed)) return;
    }
    const owned = try allocator.dupe(u8, trimmed);
    errdefer allocator.free(owned);
    try out.append(allocator, owned);
}

pub fn freeStringList(allocator: std.mem.Allocator, list: *std.ArrayList([]const u8)) void {
    for (list.items) |s| allocator.free(s);
    list.deinit(allocator);
}

test "extract cmd from codex exec_command input" {
    var list: std.ArrayList([]const u8) = .empty;
    defer freeStringList(std.testing.allocator, &list);
    const input =
        \\const r = await tools.exec_command({"cmd":"rm -rf /tmp/x"});
    ;
    try extractCmdFromCodexInput(std.testing.allocator, input, &list);
    try std.testing.expect(list.items.len == 1);
    try std.testing.expectEqualStrings("rm -rf /tmp/x", list.items[0]);
}

test "extract Claude Bash tool_use" {
    const line =
        \\{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Bash","input":{"command":"git status"}}]}}
    ;
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, line, .{});
    defer parsed.deinit();
    var list: std.ArrayList([]const u8) = .empty;
    defer freeStringList(std.testing.allocator, &list);
    try walkValueForCommands(std.testing.allocator, parsed.value, &list, 0);
    try std.testing.expect(list.items.len >= 1);
    try std.testing.expectEqualStrings("git status", list.items[0]);
}

test "named content fields cap at max_file_bytes" {
    const huge = try std.testing.allocator.alloc(u8, types.max_file_bytes + 64);
    defer std.testing.allocator.free(huge);
    @memset(huge, 'a');

    var obj: std.json.ObjectMap = .empty;
    defer obj.deinit(std.testing.allocator);
    try obj.put(std.testing.allocator, "content", .{ .string = huge });

    var list: std.ArrayList([]const u8) = .empty;
    defer freeStringList(std.testing.allocator, &list);
    try walkValueForTextBlobs(std.testing.allocator, .{ .object = obj }, &list, 0);
    try std.testing.expectEqual(@as(usize, 1), list.items.len);
    try std.testing.expectEqual(types.max_file_bytes, list.items[0].len);
}

test "JSON-encoded arguments OutOfMemory is not swallowed" {
    const line =
        \\{"type":"tool_use","name":"Bash","arguments":"{\"command\":\"hello\"}"}
    ;
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, line, .{});
    defer parsed.deinit();
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var list: std.ArrayList([]const u8) = .empty;
    defer freeStringList(failing.allocator(), &list);
    try std.testing.expectError(error.OutOfMemory, walkValueForCommands(failing.allocator(), parsed.value, &list, 0));
}

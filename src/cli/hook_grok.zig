//! Grok hook stdin payload adapter. Validate the raw host object and return it
//! as the shared hook-evaluator payload. Deny emit (JSON / sentinel / exit 2)
//! stays in `hook.zig`.

const std = @import("std");
const shell_tools = @import("shell_tools.zig");

pub const GrokHookPayloadError = error{
    InvalidGrokHookPayload,
    GrokHookEventMismatch,
    UnsupportedGrokPreToolUse,
};

/// Validate Grok's raw hook object and return it as the host-adapter payload.
///
/// Official Grok Build (xai-org/grok-build) serializes the envelope in camelCase
/// (`hookEventName`, `toolName`, `toolInput`, `sessionId`) with snake_case event
/// values (`pre_tool_use`). Claude-compat snake_case keys and PascalCase event
/// names are also accepted so legacy fixtures and dual-format hosts keep working.
///
/// `event_name` is the caller's event tag (for example `@tagName(event)`), not
/// a `hook.Event` value — this file must not import `hook.zig`.
pub fn grokHookPayload(value: std.json.Value, event_name: []const u8) GrokHookPayloadError!std.json.Value {
    if (value != .object) return error.InvalidGrokHookPayload;

    const hook_event_name = extractGrokEventName(value) orelse return error.InvalidGrokHookPayload;
    if (!grokEventNameMatches(hook_event_name, event_name)) return error.GrokHookEventMismatch;

    if (std.mem.eql(u8, event_name, "PreToolUse")) {
        const cwd = extractString(value, "cwd") orelse return error.InvalidGrokHookPayload;
        const tool_name = extractGrokToolName(value) orelse return error.InvalidGrokHookPayload;
        const tool_input = extractGrokToolInput(value) orelse return error.InvalidGrokHookPayload;
        if (std.mem.trim(u8, cwd, " \t\r\n").len == 0 or
            std.mem.trim(u8, tool_name, " \t\r\n").len == 0 or
            tool_input != .object)
        {
            return error.InvalidGrokHookPayload;
        }
        // Phase 3: shell or file-read tools only. Unknown tools stay unsupported.
        if (!shell_tools.isShellTool(tool_name) and !isFileReadTool(tool_name)) return error.UnsupportedGrokPreToolUse;
    }

    return value;
}

pub fn extractGrokEventName(value: std.json.Value) ?[]const u8 {
    return extractString(value, "hook_event_name") orelse
        extractString(value, "hookEventName");
}

pub fn extractGrokToolName(value: std.json.Value) ?[]const u8 {
    return extractString(value, "tool_name") orelse
        extractString(value, "toolName");
}

pub fn extractGrokToolInput(value: std.json.Value) ?std.json.Value {
    if (value != .object) return null;
    if (value.object.get("tool_input")) |v| return v;
    if (value.object.get("toolInput")) |v| return v;
    return null;
}

/// Accept PascalCase (`PreToolUse`), snake_case (`pre_tool_use`), and camelCase
/// (`preToolUse`) spellings that official Grok Build and Claude-compat sources emit.
/// `event_name` is `@tagName(event)` from the caller (or the same PascalCase string).
pub fn grokEventNameMatches(name: []const u8, event_name: []const u8) bool {
    if (std.mem.eql(u8, name, event_name)) return true;
    if (std.mem.eql(u8, event_name, "SessionStart")) {
        return std.mem.eql(u8, name, "session_start") or std.mem.eql(u8, name, "sessionStart");
    }
    if (std.mem.eql(u8, event_name, "UserPromptSubmit")) {
        return std.mem.eql(u8, name, "user_prompt_submit") or std.mem.eql(u8, name, "userPromptSubmit") or std.mem.eql(u8, name, "beforeSubmitPrompt");
    }
    if (std.mem.eql(u8, event_name, "PreToolUse")) {
        return std.mem.eql(u8, name, "pre_tool_use") or std.mem.eql(u8, name, "preToolUse") or
            std.mem.eql(u8, name, "beforeShellExecution") or std.mem.eql(u8, name, "beforeMCPExecution") or std.mem.eql(u8, name, "beforeReadFile");
    }
    if (std.mem.eql(u8, event_name, "PermissionRequest")) {
        return std.mem.eql(u8, name, "permission_request") or std.mem.eql(u8, name, "permissionRequest");
    }
    if (std.mem.eql(u8, event_name, "PostToolUse")) {
        return std.mem.eql(u8, name, "post_tool_use") or std.mem.eql(u8, name, "postToolUse") or
            std.mem.eql(u8, name, "afterShellExecution") or std.mem.eql(u8, name, "afterMCPExecution") or std.mem.eql(u8, name, "afterFileEdit");
    }
    if (std.mem.eql(u8, event_name, "Stop")) {
        return std.mem.eql(u8, name, "stop");
    }
    if (std.mem.eql(u8, event_name, "SessionEnd")) {
        return std.mem.eql(u8, name, "session_end") or std.mem.eql(u8, name, "sessionEnd");
    }
    return false;
}

fn extractString(payload: std.json.Value, key: []const u8) ?[]const u8 {
    if (payload != .object) return null;
    const v = payload.object.get(key) orelse return null;
    return if (v == .string) v.string else null;
}

/// Grok / Claude read tools. Case-insensitive. Keep in sync with `hook.zig`.
fn isFileReadTool(tool_name: []const u8) bool {
    const read_tools = &[_][]const u8{ "read_file", "Read", "read" };
    for (read_tools) |rt| {
        if (std.ascii.eqlIgnoreCase(tool_name, rt)) return true;
    }
    return false;
}

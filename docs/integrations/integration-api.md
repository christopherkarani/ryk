# Integration API

> Version: 1.0.0

## Overview

ryk exposes two local integration commands for agent hosts and wrappers:

- `ryk decide`, a direct policy evaluation API
- `ryk hook`, a host hook adapter for Codex and Claude Code events

Both commands are local only. They read `.ryk/policy.yaml`, apply policy, and return structured JSON. They do not provide sandboxing by themselves. The strongest protection remains `ryk run -- <command>`.

## `ryk decide`

`ryk decide` evaluates a single request against policy and returns a JSON decision.

### Usage

```sh
ryk decide command --json '{"command":"<cmd>"}'
ryk decide file    --json '{"path":"<p>","operation":"read|write"}'
ryk decide prompt  --json '{"text":"<text>"}'
ryk decide tool    --json '{"name":"<name>"}'

ryk decide <kind> --stdin
ryk decide <kind> --json <payload> [--ci]
ryk decide <kind> --stdin [--ci]
```

Kinds:

- `command`
- `file`
- `prompt`
- `tool`

Options:

- `--json`, inline JSON payload
- `--stdin`, read JSON from stdin
- `--ci`, treat `ask` as deny

### Evaluation rules

- The command loads `.ryk/policy.yaml`.
- `command` checks against policy command allow and deny rules.
- `file` checks file access rules using the supplied `operation`.
- `prompt` checks text for policy relevant content and redaction triggers.
- `tool` checks tool names against policy tool rules.
- If the request is malformed, the command returns a usage or general error.

### Exit codes

Policy outcomes for successful evaluation (JSON on stdout):

| Code | Decision | Meaning |
|------|----------|---------|
| `0` | `allow`, `context_only` | Permitted |
| `3` | `block` | Policy denied |
| `7` | `ask` | Approval required (non-interactive callers should read JSON) |
| `8` | `warn` | Redact or warn |

Failures before a decision is emitted:

| Code | Meaning |
|------|---------|
| `1` | General error (evaluation, parse, or internal failure) |
| `2` | Usage error |

Other ryk CLI commands also use `4` (`unsupported`), `5` (`child_failure`), and `6` (`redteam_failure`). Those codes are not returned for policy decisions above.

In `--ci` mode, `ask` is converted to `block` and exits with `3`.

### Examples

Allow a command:

```sh
ryk decide command --json '{"command":"git status"}'
```

Check a file write:

```sh
ryk decide file --json '{"path":"src/main.zig","operation":"write"}'
```

Check a prompt:

```sh
ryk decide prompt --json '{"text":"Do not include secrets in the response."}'
```

Check a tool name from stdin:

```sh
printf '{"name":"edit"}' | ryk decide tool --stdin
```

CI mode example:

```sh
ryk decide command --json '{"command":"git push --force"}' --ci
```

In CI mode, any `ask` result becomes a deny path.

## `ryk hook`

`ryk hook` adapts host events to ryk policy decisions.

### Usage

```sh
ryk hook codex SessionStart
ryk hook codex UserPromptSubmit
ryk hook codex PreToolUse
ryk hook codex PermissionRequest
ryk hook codex PostToolUse
ryk hook codex Stop

ryk hook claude SessionStart
ryk hook claude UserPromptSubmit
ryk hook claude PreToolUse
ryk hook claude PermissionRequest
ryk hook claude PostToolUse
ryk hook claude SessionEnd
```

### Hosts

- `codex`
- `claude`

### Events

- `SessionStart`
- `UserPromptSubmit`
- `PreToolUse`
- `PermissionRequest`
- `PostToolUse`
- `Stop`
- `SessionEnd`

### Request schema

Hooks always read a JSON request from stdin.

```json
{
  "version": 1,
  "host": "codex|claude",
  "event": "SessionStart|UserPromptSubmit|PreToolUse|PermissionRequest|PostToolUse|Stop|SessionEnd",
  "payload": {},
  "session_id": "optional",
  "timestamp": "optional ISO 8601"
}
```

### Request handling

- `SessionStart`, `Stop`, `SessionEnd`, `PostToolUse` always return allow style responses.
- `UserPromptSubmit` scans prompt text for secrets and redacts if needed.
- `PreToolUse` and `PermissionRequest` route to command, file, or tool evaluation.
- File tools are matched case insensitively.
- Payloads larger than 256 KiB are rejected.

#### Decision routing

If the payload has `command`, ryk evaluates it as a command.

If the tool name matches a file tool and the payload has `path`, ryk evaluates it as a file write:

- `edit`
- `write`
- `file_write`
- `file_edit`
- `apply`
- `create_file`
- `write_file`

Otherwise, ryk treats the event as an MCP or tool request. In strict mode, that defaults to deny when policy does not allow it.

### Response schema

Responses are written to stdout.

```json
{
  "version": 1,
  "decision": "allow|block|warn|ask|context_only|error",
  "risk": "low|medium|high|critical|unknown",
  "category": "command|file|prompt|tool|network|mcp|unknown",
  "reason": "machine-readable reason",
  "rule": "matched rule id or null",
  "message": "human-readable message",
  "redactions": [{"field":"...","reason":"..."}],
  "host_limitations": ["Hook enforcement is additive; does not replace ryk run supervision."]
}
```

### Decision mapping

| ryk decision | Hook response |
|---|---|
| `allow` | `allow` |
| `deny` | `block` |
| leftover unused policy `ask` | `allow` when attended; `block` when unattended. Rewritten on the coding-host enforcement wire — never emitted as `decision: ask`. Stage / FM / SoftBlock are not leftover unused ask. |
| `observe` | `context_only` |
| `redact` | `warn` |
| `stage` | `stage`, or `block` in CI. Never `allow`. Claude `permissionDecision` holds as `ask`. |
| `broker` | `error` |

### Examples

Session start:

```sh
printf '{"version":1,"host":"codex","event":"SessionStart","payload":{}}' | ryk hook codex SessionStart
```

Prompt submit with a secret:

```sh
printf '{"version":1,"host":"claude","event":"UserPromptSubmit","payload":{"text":"my token is abc123"}}' | ryk hook claude UserPromptSubmit
```

Tool request:

```sh
printf '{"version":1,"host":"codex","event":"PreToolUse","payload":{"name":"edit","path":"README.md"}}' | ryk hook codex PreToolUse
```

CI mode:

```sh
printf '{"version":1,"host":"claude","event":"PermissionRequest","payload":{"command":"git push --force"}}' | ryk hook claude PermissionRequest --ci
```

## JSON Schemas Reference

The schemas below are the integration contract reference. They are intentionally small and versioned.

### `hook-request-v1`

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "hook-request-v1",
  "type": "object",
  "required": ["version", "host", "event", "payload"],
  "properties": {
    "version": {"const": 1},
    "host": {"enum": ["codex", "claude"]},
    "event": {
      "enum": [
        "SessionStart",
        "UserPromptSubmit",
        "PreToolUse",
        "PermissionRequest",
        "PostToolUse",
        "Stop",
        "SessionEnd"
      ]
    },
    "payload": {"type": "object"},
    "session_id": {"type": "string"},
    "timestamp": {"type": "string"}
  },
  "additionalProperties": true
}
```

### `hook-response-v1`

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "hook-response-v1",
  "type": "object",
  "required": ["version", "decision", "risk", "category", "reason", "message", "redactions", "host_limitations"],
  "properties": {
    "version": {"const": 1},
    "decision": {"enum": ["allow", "block", "warn", "ask", "context_only", "error"]},
    "risk": {"enum": ["low", "medium", "high", "critical", "unknown"]},
    "category": {"enum": ["command", "file", "prompt", "tool", "network", "mcp", "unknown"]},
    "reason": {"type": "string"},
    "rule": {"type": ["string", "null"]},
    "message": {"type": "string"},
    "redactions": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["field", "reason"],
        "properties": {
          "field": {"type": "string"},
          "reason": {"type": "string"}
        },
        "additionalProperties": true
      }
    },
    "host_limitations": {
      "type": "array",
      "items": {"type": "string"}
    }
  },
  "additionalProperties": true
}
```

### `host-capabilities-v1`

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "host-capabilities-v1",
  "type": "object",
  "required": ["version", "host", "events", "supports_stdin", "supports_ci"],
  "properties": {
    "version": {"const": 1},
    "host": {"enum": ["codex", "claude"]},
    "events": {
      "type": "array",
      "items": {
        "enum": [
          "SessionStart",
          "UserPromptSubmit",
          "PreToolUse",
          "PermissionRequest",
          "PostToolUse",
          "Stop",
          "SessionEnd"
        ]
      }
    },
    "supports_stdin": {"type": "boolean"},
    "supports_ci": {"type": "boolean"},
    "max_payload_bytes": {"type": "integer"},
    "file_tools": {"type": "array", "items": {"type": "string"}}
  },
  "additionalProperties": true
}
```

## CI Mode

CI mode is fail closed for asks.

- In `ryk decide`, `ask` becomes a non interactive deny path.
- In `ryk hook`, `ask` becomes `block`.
- `warn` still returns warning output, but it does not become allow.
- CI mode does not add new policy rules. It only changes the fallback behavior for undecided actions.

## Error Handling

Common failures include:

- bad or missing JSON payloads
- invalid `kind`, `host`, or `event`
- unsupported payload shapes
- payloads over 256 KiB
- missing `.ryk/policy.yaml`
- policy parse failures
- internal evaluation errors

`ryk decide` uses the exit codes above so shell scripts and CI can gate on `$?` without parsing JSON. `ryk hook` writes JSON to stdout and returns exit `0` for successful evaluation (including `block`, `ask`, and `warn`); hosts must read the JSON `decision` field. Hook returns non-zero only for usage, parse, or internal failures.

When possible, error responses should be explicit about the failed stage, but they should not print secrets or raw payloads.

## Limitations

- These commands are local policy adapters, not a sandbox.
- They only see the events and payloads the host provides.
- They cannot enforce actions the host never reports.
- File tool matching is based on known tool names and path presence.
- Network and MCP requests are only as visible as the host event stream makes them.
- Host hook enforcement is additive. It does not replace `ryk run` supervision.
- `observe`, `context_only`, and similar non blocking responses are informational. A host may still choose its own final behavior.

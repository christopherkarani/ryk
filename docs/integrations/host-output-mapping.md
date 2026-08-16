# Host Output Mapping

> Host hook responses for Codex and Claude Code
> Version: 1.3.0

## Overview

`ryk hook` receives host lifecycle events from Codex and Claude Code plugins, plus the Grok managed hook, normalizes the payload, evaluates the event against existing ryk policy and redaction logic, then returns a host-valid decision object.

The hook is additive only. It does not replace `ryk run`. Claude tool-gating events emit native `permissionDecision` JSON so the host can veto tools when it honors that contract; grade remains **hook**, not OS-enforced sandbox.

## Supported Hosts

| Host | Supported events |
|---|---|
| Codex | `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PermissionRequest`, `PostToolUse`, `Stop` |
| Claude | `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PermissionRequest`, `PostToolUse`, `SessionEnd` |
| Grok | `PreToolUse` (managed matchers: Bash / Read). Native deny is `{"decision":"deny","reason":…}` + exit 2. Ask is hardened to deny (no resume). Missing `ryk` is wrapped to the same deny. |

## Event to Decision Mapping

| Event | Codex | Claude | Logic | Decision |
|---|---|---|---|---|
| `SessionStart` | ✓ | ✓ | Informational | `allow` |
| `UserPromptSubmit` | ✓ | ✓ | Secret redaction check on prompt text | `allow` if clean, `warn` if secrets found |
| `PreToolUse` | ✓ | ✓ | Command eval if `command` field is present, file write eval if file tool + path, otherwise MCP or tool eval | Varies by policy |
| `PermissionRequest` | ✓ | ✓ | Same as `PreToolUse` | Varies by policy |
| `PostToolUse` | ✓ | ✓ | Informational | `allow` |
| `Stop` | ✓ | ✗ | Informational | `allow` |
| `SessionEnd` | ✗ | ✓ | Informational | `allow` |

### File tool names

File tool matching is case-insensitive.

`edit`, `write`, `file_write`, `file_edit`, `apply`, `create_file`, `write_file`

## Host Event Rules

### `SessionStart`

No policy decision is needed. ryk returns an informational allow.

### `UserPromptSubmit`

ryk scans the prompt text for secret-like material before any other policy check.

- Clean prompt, return `allow`
- Secrets detected, return `warn` and include redactions

### `PreToolUse` and `PermissionRequest`

ryk evaluates the request by the most specific available input.

1. If `command` is present, run command policy evaluation.
2. If the tool is a file write tool and a path is present, run file write policy evaluation.
3. Otherwise, run generic tool or MCP evaluation.

### `PostToolUse`

No new decision is needed. ryk returns an informational allow.

### `Stop`

Codex only. Informational allow.

### `SessionEnd`

Claude only. Informational allow.

## Decision Mapping Reference

| ryk internal | Hook output | When |
|---|---|---|
| `allow` | `allow` | Policy allows |
| `deny` | `block` | Policy denies |
| `ask` | `ask` | Needs user confirmation |
| `observe` | `context_only` | Log only |
| `redact` | `warn` | Secrets detected |
| `stage` | `ask` | Staged write pending review |
| `broker` | `error` | Evaluation failure |

## Risk Level Reference

| Score | Risk level |
|---|---|
| `≤25` | low |
| `26-50` | medium |
| `51-75` | high |
| `>75` | critical |
| `none` | unknown |

## Category Mapping Reference

| Source input | Category |
|---|---|
| `command` | `command` |
| `file.write` | `file.write` |
| `file.read` | `file` |
| `prompt` | `prompt` |
| `mcp/tool` | `tool` |
| `network` | `network` |
| unknown or default | `unknown` |

`mcp` may appear in host payloads, but ryk normalizes it to `tool` in the canonical hook response.

## Response Fields

### Canonical ryk hook response (most hosts / non-tool Claude events)

Most hosts and Claude informational events (`SessionStart`, `UserPromptSubmit`, `PostToolUse`, `SessionEnd`) use the same top-level shape.

| Field | Required | Notes |
|---|---|---|
| `version` | yes | Always `1` |
| `decision` | yes | `allow`, `block`, `warn`, `ask`, `context_only`, `error` |
| `risk` | yes | `low`, `medium`, `high`, `critical`, `unknown` |
| `category` | yes | `command`, `file`, `prompt`, `tool`, `network`, `mcp`, `unknown` before normalization |
| `reason` | yes | Machine-readable string |
| `rule` | yes | Matched policy rule identifier or `null` |
| `message` | yes | Short agent-facing reason (prefer one line). Operator Recourse/Next live on stderr and in `remediation_commands` / `suggestions` — not stuffed into `message`. |
| `redactions` | yes | Array of `{field, reason}` |
| `host_limitations` | yes | Always includes `Hook enforcement is additive; does not replace ryk run supervision.` |

### Claude Code tool-gating events (`PreToolUse`, `PermissionRequest`)

Claude Code expects native host JSON so blocks surface as real permission denials. For these events `ryk hook claude` emits:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "command blocked by ryk policy: …"
  },
  "systemMessage": "command blocked by ryk policy: …"
}
```

| Field | Notes |
|---|---|
| `hookSpecificOutput.hookEventName` | Matches the event (`PreToolUse` or `PermissionRequest`) |
| `hookSpecificOutput.permissionDecision` | `allow` \| `deny` \| `ask` |
| `hookSpecificOutput.permissionDecisionReason` | Short one-line reason; no Recourse/Next walls; no redeemable allow-once codes |
| `systemMessage` | Optional short notice on deny/ask (UX only; not a substitute for `permissionDecision`) |

#### ryk decision → Claude `permissionDecision`

| ryk hook decision | Claude `permissionDecision` | Notes |
|---|---|---|
| `block` / `error` | `deny` | Hard veto |
| `ask` | `ask` | Interactive; under `--ci` ryk hardens `ask`→`block` before emit → `deny` |
| `allow` / `context_only` | `allow` | Proceed |
| `warn` | `allow` | Warn is not a hard veto on this surface (documented proceed; not a silent silent-allow of blocked tools) |

Process exit remains `0` for structured Claude JSON (plugin-compatible). Operator-rich explain still goes to **stderr** on block.

This is still **hook-grade** enforcement: strongest boundary remains `ryk claude` / `ryk run` (wrapper). Do not treat host-shaped deny as OS-enforced sandbox.

## Example Responses

### allow

```json
{
  "version": 1,
  "decision": "allow",
  "risk": "low",
  "category": "prompt",
  "reason": "prompt.clean",
  "rule": null,
  "message": "Prompt accepted.",
  "redactions": [],
  "host_limitations": [
    "Hook enforcement is additive; does not replace ryk run supervision."
  ]
}
```

### block

```json
{
  "version": 1,
  "decision": "block",
  "risk": "critical",
  "category": "command",
  "reason": "command.dangerous",
  "rule": "commands.deny[1]",
  "message": "Blocked by ryk policy.",
  "redactions": [],
  "host_limitations": [
    "Hook enforcement is additive; does not replace ryk run supervision."
  ]
}
```

### warn

```json
{
  "version": 1,
  "decision": "warn",
  "risk": "high",
  "category": "prompt",
  "reason": "prompt.secret_detected",
  "rule": "redaction.prompt.secrets",
  "message": "Potential secret material detected in prompt text.",
  "redactions": [
    {
      "field": "prompt",
      "reason": "secret_like_pattern"
    }
  ],
  "host_limitations": [
    "Hook enforcement is additive; does not replace ryk run supervision."
  ]
}
```

### ask

```json
{
  "version": 1,
  "decision": "ask",
  "risk": "medium",
  "category": "file.write",
  "reason": "file.staged_review_required",
  "rule": "files.write.stage[2]",
  "message": "Write is staged for review.",
  "redactions": [],
  "host_limitations": [
    "Hook enforcement is additive; does not replace ryk run supervision."
  ]
}
```

### context_only

```json
{
  "version": 1,
  "decision": "context_only",
  "risk": "unknown",
  "category": "tool",
  "reason": "tool.observe_only",
  "rule": null,
  "message": "Observed tool use for context only.",
  "redactions": [],
  "host_limitations": [
    "Hook enforcement is additive; does not replace ryk run supervision."
  ]
}
```

### error

```json
{
  "version": 1,
  "decision": "error",
  "risk": "unknown",
  "category": "unknown",
  "reason": "hook.evaluation_failed",
  "rule": null,
  "message": "ryk could not evaluate the hook payload.",
  "redactions": [],
  "host_limitations": [
    "Hook enforcement is additive; does not replace ryk run supervision."
  ]
}
```

## CI Mode Differences

CI mode is noninteractive and fail closed.

- `ask` becomes `block`
- `stage` becomes `block`
- `warn` still warns, but the host should not rely on a prompt path
- invalid or oversized hook JSON fails safely
- debug output stays on stderr
- no hook path may assume human confirmation is available

For headless runs, ryk should report the CI limitation directly instead of pretending an approval flow exists.

## Cross-host decision mapping

The living multi-host matrix (Hermes native approve-and-resume, OpenClaw/OpenCode ask→block limitations, prompt-path honesty) lives in:

- `docs/integrations/host-decision-mapping.md`
- `integrations/common/schemas/host-decision-mapping-v1.json`
- `integrations/common/schemas/examples/hermes-decision-mapping-v1.json`

Adapters must not claim text context notes enforce approval.

## See Also

- `docs/integrations/host-decision-mapping.md`
- `docs/integrations/ryk-cli-plugin.md`
- `docs/integrations/plugin-security-model.md`
- `docs/integrations/integration-api.md`

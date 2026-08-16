# Host Decision Mapping

> Scope: ryk policy vocabulary → host enforcement surfaces
> Version: 1.0.0  
> Status: living contract (plugins remain thin bridges; policy stays in ryk)

## Purpose

ryk decisions are host-agnostic:

| ryk decision | Meaning |
|---|---|
| `allow` | Proceed |
| `block` | Hard deny |
| `ask` | Leftover unused policy ask only. Coding hosts permit that leftover so agents can work. Unattended/CI hardens to deny. Not a host approval UI. Not stage, FM steward ask, or SoftBlock. |
| `stage` | Hold-for-review or deny. Never allow. Default `write_mode: staged` file writes. Unattended/`--ci` hardens to block. |
| `warn` | Advisory; do not silently treat as hard deny unless documented |
| `context_only` | Observe / inject context only |
| `error` | Evaluation failure; fail closed on enforcement surfaces |

Adapters **must not** claim stronger enforcement than the host provides. Passive notes are not approval gates.

## CI / unattended rule

Coding hosts (Claude, Codex, OpenCode, Cursor, Pi, Hermes, Grok, OpenClaw)
permit leftover unused policy `ask` so agents can work. There is no host
ask UI for that leftover. Stage, FM steward soft→ask, SoftBlock, and
explicit deny never become allow. ryk still hard-stops explicit deny/block.

When unattended (`CI`, `RYK_CI`, `RYK_NONINTERACTIVE`, `RYK_UNATTENDED`, or
host `--ci`):

- `ask` → `block` / deny
- Explicit deny is unchanged

## Tool-path matrix (primary enforcement)

| Host | Event | `allow` | `block` | `ask` | `warn` | Resume? | Notes |
|---|---|---|---|---|---|---|---|
| **Hermes** | `pre_tool_call` | proceed | `action: block` | **allow** (unattended → block) | log + proceed | No | Residual ask is permit. No Hermes approve UI. CI / unattended hardens `ask`→`block`. |
| **OpenClaw** | `tool.before` | proceed | block | **allow** (unattended → block) | log + allow | **No** | Residual unused ask is permit. Unknown/legacy/metadata registration is unprotected; use the wrapper for the hard boundary. |
| **OpenCode** | `tool.execute.before` | proceed | throw/block | **allow** (unattended → block) | log + allow | No | Residual ask is permit so agents can work. |
| **OpenCode** | `command.execute.before` | proceed | throw/block | **allow** (unattended → block) | log + allow | No | Slash/custom commands; payload uses command name as tool. |
| **OpenCode** | `permission.ask` | allow | deny | **allow** (unattended → deny) | log | No | Residual ask is permit; only hard-deny on `block`. |
| **Claude Code** | `PreToolUse` / `PermissionRequest` | `permissionDecision: allow` | `permissionDecision: deny` | **allow** (unattended/`--ci` → deny) | proceed as allow | No | Host-shaped stdout JSON via `hookSpecificOutput` (hook grade; exit 0). Residual ask is permit so agents can work. |
| **Codex** | `PreToolUse` / `PermissionRequest` | allow | deny | **allow** (unattended/`--ci` → deny) | warn | No | Residual ask is permit; unattended wires ask to block. |
| **Pi** | tool hooks | allow | deny | **allow** (unattended → auto-deny) | warn | No | Residual ask is permit. `RYK_UNATTENDED` / `CI` auto-denies. |
| **Grok** | `PreToolUse` (Bash / Read) | exit 0 | `{"decision":"deny","reason":…}` + exit 2 | **allow** (unattended → deny JSON + exit 2) | exit 0 | **No** | Residual unused ask is permit. Stage / SoftBlock / FM / explicit deny stay deny JSON + exit 2. **hook** + `ryk grok` **wrapper**. Missing/non-executable `ryk` emits deny JSON + exit 2. See below. |
| **Cursor** | `beforeShellExecution` (bare `ryk` stdin hook) | `permission: allow` JSON, exit 0 | `permission: deny` JSON, exit 0 | **allow** (unattended → deny) | log + allow | No | Residual ask is permit. Malformed/oversized/unknown payloads: dual-contract deny JSON + exit 2. |

### Grok hook fail-closed contract

Official Grok Build treats hook stdout + exit as:

- allow / warn / leftover unused ask → exit 0 (generic hook JSON from `ryk hook grok`)
- block / stage / SoftBlock / FM ask / error → `{"decision":"deny","reason":…}` + exit 2 (no resume)

The managed hook command is `/bin/sh -c '…' -- <absolute ryk>`: if the pinned file is missing or not executable, the wrapper prints that deny JSON and exits 2. `ryk doctor --fix` and `ryk start` rewrite legacy direct `…/ryk hook grok PreToolUse` entries (those still fail-open on exit 127).

Residual (host-side, not ryk-fixable): timeouts, crashes, and non-0/2 exits are **fail-open** unless the host adds its own fail-closed setting. Grade remains **hook**, not OS-enforced. Prefer `ryk grok` / `ryk run -- grok` for the wrapper boundary.

### Cursor bare-hook fail-closed contract

Bare `ryk` with piped stdin is the Cursor `beforeShellExecution` / Claude-compatible
hook entry. Cursor honors two deny channels: `permission: "deny"` JSON on exit 0,
and exit code 2 (block regardless of JSON). ryk uses both for defense in depth:

- Evaluated denies (well-formed payloads): deny JSON on stdout, exit 0 — the rich
  reason text rides the JSON contract.
- Malformed JSON, oversized payloads, unknown formats, and shell payloads missing
  a command: dual-contract deny JSON (flat `permission` + nested
  `hookSpecificOutput`) on stdout **and** exit 2.

Residual (host-side, not ryk-fixable): Cursor's default for hook *crashes*,
timeouts, and non-0/2 exits is fail-open unless the hook entry sets
`failClosed: true` in `hooks.json`. ryk's own deny paths never rely on that
setting, but enabling it is recommended for defense in depth. Recognized
non-shell tool hooks (e.g. Read/Edit on the Claude-compatible shape) carry no
command and intentionally pass through with empty stdout + exit 0.

## Prompt / pre-LLM path matrix

Most hosts **cannot** veto or open approve-and-resume on prompt submission. ryk may still return `ask`/`block`/`warn` for honesty and telemetry.

| Host | Event | Enforcement of `ask`/`block` | Allowed surface |
|---|---|---|---|
| **Hermes** | `pre_llm_call` | **None** via plugin | Advisory `context` only; notes **must not** claim enforcement. Outer gate: `ryk hermes`. |
| **OpenClaw** | prompt hooks | Limited | Prefer honest limitations over fake notes. |
| **OpenCode** | prompt hooks | Limited | Same. |
| **Claude / Codex** | `UserPromptSubmit` | Advisory / redaction | `warn` for secrets; not a full deny boundary. |

**Never** implement “skill that tells the model to call `clarify` when it sees a policy note” as the control plane for security-critical `ask`.

## Hermes detail (reference implementation)

### `pre_tool_call`

```text
allow  → None
block  → {"action":"block","message":"..."}
ask    → None (proceed; CI / unattended → block)
warn   → log advisory; None (proceed)
other  → block fail-closed
```

### `pre_llm_call`

```text
warn / context_only → {"context":"ryk policy note (warn/observe, advisory only): ..."}
ask                 → {"context":"... not an approval gate ... Prefer ryk hermes"}
block               → {"context":"... host cannot veto pre_llm_call ... Prefer ryk hermes"}
```

## Capability schema

See `integrations/common/schemas/host-capabilities-v1.json` and
`integrations/common/schemas/host-decision-mapping-v1.json` for machine-readable
enforcement modes plugins can advertise or tests can assert.

## Feed / dashboard classification

Blocked-actions counters classify by **decision**, not host event-type strings:

| decision | Counts as blocked/attention? |
|---|---|
| `deny` / `block` / `error` | Yes (hard deny or failure) |
| `ask` | No on coding-host wire for leftover unused policy ask (permitted). Yes if unattended hardens it to deny. Stage / FM / SoftBlock are not this leftover. |
| `stage` | Yes (hold or deny; never a permitted leftover ask) |
| `warn` | **No** (advisory; tool may proceed) |
| `allow` / `context_only` | No |

## Adapter rules (non-negotiable)

1. Policy logic stays in ryk (`ryk hook` / `ryk decide`). Plugins only map outputs.
2. Do not map security-critical `ask` solely to `{"context":"..."}` and call it done.
3. Do not collapse `warn` to `block` without docs + tests.
4. Document host limitations in README + `host_limitations` response fields.
5. Strongest shell boundary remains `ryk run -- <host> ...`.
6. Hermes pure mapping lives in `integrations/hermes-plugin/mapping.py`; the example JSON under `integrations/common/schemas/examples/` is asserted by plugin unit tests.

## See also

- `docs/integrations/host-output-mapping.md` (Codex/Claude field-level mapping)
- `docs/integrations/integration-api.md`
- `integrations/hermes-plugin/README.md`

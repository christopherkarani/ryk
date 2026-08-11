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
| `ask` | Require human approval **with resume** when the host can provide it |
| `warn` | Advisory; do not silently treat as hard deny unless documented |
| `context_only` | Observe / inject context only |
| `error` | Evaluation failure; fail closed on enforcement surfaces |

Adapters **must not** claim stronger enforcement than the host provides. Passive notes are not approval gates.

## CI / noninteractive rule

Where a host already hardens interactive outcomes:

- `ask` → `block` (no approval prompt available)
- Prefer env signals: `CI`, `RYK_CI`, `RYK_NONINTERACTIVE`, `RYK_UNATTENDED`, or host `--ci`

## Tool-path matrix (primary enforcement)

| Host | Event | `allow` | `block` | `ask` | `warn` | Resume? | Notes |
|---|---|---|---|---|---|---|---|
| **Hermes** | `pre_tool_call` | proceed | `action: block` | `action: approve` + `rule_key` | log + proceed | **Yes** (Hermes human gate) | Requires Hermes with `pre_tool_call` approve escalation. CI hardens `ask`→`block`. |
| **OpenClaw** | `tool.before` | proceed | block | **block** until a live, versioned resumable-approval contract is validated | log + allow | **No** | Unknown/legacy/metadata registration is unprotected; use the wrapper for the hard boundary. |
| **OpenCode** | `tool.execute.before` | proceed | throw/block | **block** (no resume) | log + allow | No on tool path | Prefer routing high-risk tools through OpenCode permission UX. |
| **OpenCode** | `command.execute.before` | proceed | throw/block | **block** (no resume) | log + allow | No | Slash/custom commands; payload uses command name as tool. |
| **OpenCode** | `permission.ask` | allow | deny | **host ask** (resume) | log | **Yes** | Leave OpenCode permission UI for ryk `ask`; only hard-deny on `block`. |
| **Claude Code** | `PreToolUse` / `PermissionRequest` | `permissionDecision: allow` | `permissionDecision: deny` | `permissionDecision: ask` (CI→deny) | proceed as allow | Partial | Host-shaped stdout JSON via `hookSpecificOutput` (hook grade; exit 0). See `host-output-mapping.md`. |
| **Codex** | `PreToolUse` / `PermissionRequest` | allow | deny | host permission / ask shape | warn | Partial | Same pattern as Claude adapter. |
| **Pi** | tool hooks | allow | deny | host-dependent | warn | Host-dependent | See `ryk-pi` extension docs. |

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
ask    → {"action":"approve","message":"...","rule_key":"ryk:{rule}:{tool}:{args_fp}"}
         (CI → block)
warn   → log advisory; None (proceed)
other  → block fail-closed
```

`rule_key` grain prevents over-approval of Hermes `[a]lways` allowlist entries.

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
| `ask` | Yes (approval required) |
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

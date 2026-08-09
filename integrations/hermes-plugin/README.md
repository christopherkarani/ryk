# ryk Hermes Plugin

This plugin connects Hermes Agent hooks to the ryk CLI runtime guardrail.

The plugin is a thin bridge. It does not duplicate ryk policy logic, store credentials, run telemetry, or expose MCP/server behavior.

## Decision → Hermes action (tools)

On `pre_tool_call`, ryk decisions map to Hermes native directives:

| ryk decision | Hermes return | Effect |
|---|---|---|
| `allow` | `None` | Tool proceeds |
| `block` | `{"action":"block","message":...}` | Hard deny; tool does not run |
| `ask` | `{"action":"approve","message":...,"rule_key":...}` | Escalates to Hermes **human approval gate** (`[o]nce` / `[s]ession` / `[a]lways` / `[d]eny`) — approve-and-resume |
| `warn` | log + `None` | Advisory warning only; tool proceeds (not collapsed to block) |
| other / malformed | `{"action":"block",...}` | Fail-closed |

### Approve-and-resume (`ask`)

Hermes ≥ the version that shipped `pre_tool_call` `action: approve` (escalation to the same gate Tier-2 dangerous commands use) is required for the native path. When ryk returns `ask`:

1. The plugin returns `{"action":"approve","message":...,"rule_key":...}`.
2. Hermes prompts the user (CLI/TUI) or submits a pending approval (gateway).
3. On approve, the tool **resumes** and runs. On deny/timeout, Hermes fail-closes to a block.

This is **not** a passive model note, and it is **not** a request for the model to invoke `clarify`. Enforcement is host-native.

#### `rule_key` grain

Always-allow entries are keyed so they do not over-approve:

```text
ryk|{rule_id|policy}|{tool_name}|{sha256(args)[:12]}
```

Separators are `|` so rule ids that contain `:` stay unambiguous. Approving `curl http://a.example` under rule `core.shell:network` does **not** auto-approve a later `curl http://b.example` under the same rule.

### CI / noninteractive

When `CI`, `RYK_CI`, `RYK_NONINTERACTIVE`, `RYK_UNATTENDED`, or `RYK_HERMES_UNATTENDED` is set truthily, ryk `ask` is hardened to Hermes `block` (no approval prompt). These unattended signals also override `RYK_HERMES_FAIL_OPEN=1`; a missing ryk binary remains blocked. Hermes also fail-closes plugin-escalated approvals in non-interactive non-gateway contexts.

## Failure modes

- **`pre_tool_call`**: Uses the mapping above. When ryk is missing, too old for Hermes hooks, or returns a Hermes host mismatch, the default is fail-closed. Set `RYK_HERMES_FAIL_OPEN=1` only for an attended deployment that deliberately accepts unguarded tool execution; unattended/CI signals always remain fail-closed.
- **`pre_llm_call`**: **Context-only** — Hermes cannot veto the turn or open an approval dialog on this hook. ryk `warn` / `context_only` inject advisory notes. ryk `ask` and `block` inject **honest** notes that do **not** claim enforcement or auto-triggered approval; the strongest real gate for prompts remains `ryk run -- hermes ...`. Other ryk failures log a warning and continue without injecting policy context.
- **Informational hooks** (`post_tool_call`, session lifecycle, etc.): Log warnings on ryk failure and never block Hermes.

The strongest local protection remains running Hermes through `ryk run -- hermes ...`, because the wrapper can enforce command-level behavior outside the plugin lifecycle.

## Install

Supported deployment:

```sh
curl -fsSL https://rykanv.com/install | sh
ryk unattended setup --hosts hermes
ryk unattended health --json --hosts hermes
```

Source checkout development only:

```sh
ryk plugin install hermes --yes
hermes plugins enable ryk
ryk plugin doctor hermes
```

The installer copies this directory to `~/.hermes/plugins/ryk/` and enables it with `hermes plugins enable ryk` when the `hermes` binary is available.

## Hook Coverage

- `pre_tool_call` is the tool policy gate: hard `block`, native `approve` for `ask`, advisory log for `warn`.
- `pre_llm_call` is context-only and is **not** an enforcement or approval path (see above).
- `on_session_start`, `post_tool_call`, `on_session_end`, `on_session_finalize`, and `on_session_reset` are mapped to ryk lifecycle events.
- `post_llm_call` and `subagent_stop` are informational.
- `pre_gateway_dispatch` is intentionally deferred until the Hermes gateway payload contract is stable.

## Telegram and Discord (gateway)

Hermes versions that honor hook return values apply `pre_tool_call` directives in gateway sessions:

- **`block`**: Denied tools do not execute. Hermes reports the plugin block to the agent as a tool failure.
- **`ask` → `approve`**: Escalates through Hermes’ gateway approval path (pending approval / platform buttons where supported). Exact UX varies by Hermes version and platform adapter; ryk does not fake a dialog.
- **`warn`**: Advisory only (tool proceeds after a log line).

Limitations (honest):

- Gateway approval UX depends on Hermes (buttons, `/approve`, etc.). If the gateway path cannot present a prompt, Hermes fail-closes the plugin-escalated approval rather than silently running the tool.
- The exact ryk reason text is not guaranteed to appear verbatim in the Telegram or Discord message body.
- Prompt-level `ask`/`block` still cannot be gated by this plugin alone — use `ryk run -- hermes` for outer enforcement.

## ryk discovery

The plugin resolves ryk once per process (cached until `RYK_BIN` changes), probing candidates in this order:

1. `RYK_BIN`
2. `~/.local/bin/ryk` / `~/.ryk/bin`
3. `ryk` on `PATH`
4. `./zig-out/bin/ryk` (current repo and parents — only when `RYK_ALLOW_WORKSPACE_BIN=1`)

Only regular files that are executable, identify as `product: ryk` via `ryk version --json`, and pass a Hermes `pre_tool_call` smoke test are selected (exit 0 and hook decision is not `block`, matching `tests/fixtures/hook-safe.json`). Workspace candidates require the explicit `RYK_ALLOW_WORKSPACE_BIN=1` development opt-in. `ryk plugin doctor` uses a stricter allow-only check on the running ryk binary.

Environment:

- `RYK_BIN` — force a specific ryk executable (must be executable on disk).
- `RYK_ALLOW_WORKSPACE_BIN=1` — opt into repo-local `zig-out/bin/ryk` discovery for development/testing.
- `RYK_HERMES_FAIL_OPEN` — only recognized truthy tokens (`1`, `true`, `yes`, `on`, `fail-open`, `open`) enable degraded fail-open behavior in attended mode; unattended/CI signals override it.
- `CI` / `RYK_CI` / `RYK_NONINTERACTIVE` / `RYK_UNATTENDED` / `RYK_HERMES_UNATTENDED` — when truthy, harden ryk `ask` on tools to Hermes `block` and keep degraded execution fail-closed.

## Manual verification (CLI approve UI)

1. Install/enable the plugin and point `RYK_BIN` at a Hermes-capable ryk build.
2. Run Hermes interactively so a policy `ask` tool fires (or temporarily configure a policy that returns `ask` for a known tool).
3. Confirm Hermes shows the once/session/always/deny approval UI — not a permanent block error with no resume.
4. Approve once → tool runs. Deny → tool blocked. Always → subsequent identical args under the same `rule_key` skip the prompt.
5. Export `CI=1` and confirm the same `ask` becomes a hard block without a prompt.

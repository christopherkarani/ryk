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

Host-facing `message` on block/approve is a **short single line** (reason and/or rule id). Operator tips (`Recourse` / `Next` / `remediation_commands`) are **not** stuffed into the Hermes UI string — use `ryk explain` / stderr from the CLI for those.

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

When `CI`, `RYK_CI`, `RYK_NONINTERACTIVE`, `RYK_UNATTENDED`, or `RYK_HERMES_UNATTENDED` is set truthily, **or** the install-time `.ryk_unattended` marker is present, ryk `ask` is hardened to Hermes `block` (no approval prompt). The live hook also passes `ryk hook hermes … --ci` so residual CLI-side ask (FM soft / stage) hardens inside ryk, not only in the host mapping layer. These unattended signals also override `RYK_HERMES_FAIL_OPEN=1`; a missing ryk binary remains blocked. Hermes also fail-closes plugin-escalated approvals in non-interactive non-gateway contexts.

## Failure modes

- **`pre_tool_call`**: Uses the mapping above. When ryk is missing, too old for Hermes hooks, or returns a Hermes host mismatch, the default is fail-closed. Set `RYK_HERMES_FAIL_OPEN=1` only for an attended deployment that deliberately accepts unguarded tool execution; unattended/CI signals always remain fail-closed.
- **Boundary failures**: Cyclic, unsupported, deeply nested, or oversized hook payloads are rejected before Ryk is started. Empty, malformed, oversized, timed-out, or failed Ryk responses return Hermes' exact non-empty block shape: `{"action":"block","message":"..."}`. Policy responses and diagnostics are bounded, and child stderr is never copied into the tool result.
- **`pre_llm_call`**: **Context-only** — Hermes cannot veto the turn or open an approval dialog on this hook. ryk `warn` / `context_only` inject advisory notes. ryk `ask` and `block` inject **honest** notes that do **not** claim enforcement or auto-triggered approval; the strongest real gate for prompts remains `ryk run -- hermes ...`. Other ryk failures log a warning and continue without injecting policy context.
- **Informational hooks** (`post_tool_call`, session lifecycle, etc.): Log warnings on ryk failure and never block Hermes.

The strongest local protection remains running Hermes through `ryk run -- hermes ...`, because the wrapper can enforce command-level behavior outside the plugin lifecycle.

Hermes currently exposes no authoritative live callback-introspection probe. `ryk agents health hermes --json` can report the plugin installed and configured, but it intentionally keeps `ready=false` until Hermes provides live registration evidence. The unattended preset also denies native file-write tools; use the wrapper for Ryk-mediated staged changes and authoritative workspace binding.

## Install

Supported deployment:

```sh
curl -fsSL https://rykanv.com/install | sh
ryk agents setup hermes
ryk agents health hermes --json
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

- `RYK_BIN` — select an absolute Ryk executable under `~/.local/bin` or `~/.ryk/bin`; managed binaries also require the installer's adjacent path-bound `.ryk-provenance` SHA-256 receipt, which is re-attested before each policy call. This is integrity evidence rather than a cryptographic signature, so same-user binary-and-receipt replacement is outside the trust claim. Repository-local binaries additionally require the development override below.
- `RYK_ALLOW_WORKSPACE_BIN=1` — opt into repo-local `zig-out/bin/ryk` discovery for development/testing.
- `RYK_HERMES_FAIL_OPEN` — only recognized truthy tokens (`1`, `true`, `yes`, `on`, `fail-open`, `open`) enable degraded fail-open behavior in attended mode; unattended/CI signals override it.
- `CI` / `RYK_CI` / `RYK_NONINTERACTIVE` / `RYK_UNATTENDED` / `RYK_HERMES_UNATTENDED` — when truthy, harden ryk `ask` on tools to Hermes `block`, pass `--ci` to the hook CLI, and keep degraded execution fail-closed.
- `RYK_HERMES_WORKSPACE` — optional absolute policy workspace for `ryk hook` subprocess cwd (pins policy discovery when the Hermes daemon cwd is not the setup tree).

`ryk agents setup hermes` also writes a `.ryk_unattended` marker beside the installed plugin. That persistent marker forces fail-closed behavior and ask→block even if the host process clears CI env vars or inherits `RYK_HERMES_FAIL_OPEN=1`. Marker body may include `workspace=<abs path>` to pin the policy root for hook subprocesses; when absent, operators can set `RYK_HERMES_WORKSPACE`. Residual: current setup writes integrity `path=<plugin-dir>` (not the setup workspace), so without `workspace=` / env the hook still inherits the Hermes process cwd for policy walk — weaker than OpenClaw's `workspaceRoot` binding.

## Manual verification (CLI approve UI)

1. Install/enable the plugin and point `RYK_BIN` at a Hermes-capable ryk build.
2. Run Hermes interactively so a policy `ask` tool fires (or temporarily configure a policy that returns `ask` for a known tool).
3. Confirm Hermes shows the once/session/always/deny approval UI — not a permanent block error with no resume.
4. Approve once → tool runs. Deny → tool blocked. Always → subsequent identical args under the same `rule_key` skip the prompt.
5. Export `CI=1` and confirm the same `ask` becomes a hard block without a prompt.

# ryk OpenClaw Plugin

OpenClaw plugin wrapper for ryk runtime guardrails.

## Protection first (read this)

| Path | Grade | Blocks tools? |
|------|-------|---------------|
| `ryk run -- openclaw` | **`wrapper`** (supported) | Yes — process launched under ryk |
| curl-installed ryk + `ryk unattended setup` | **supported `hook` path** | Runtime hooks when OpenClaw full registration and live inspection are proven |
| CLI-metadata / discovery pass | **`unprotected`** | No — OpenClaw wires `api.on` to a no-op |
| Local / bundled plugin path | **unverified `hook`** | Only if the host actually registers and honors hooks (not proven by install alone) |

**Never treat “plugin installed” as protection.** For mediation you can rely on today, use:

```bash
ryk run -- openclaw
```

Grades: see the main README [protection grades](../../README.md#protection-grades) and `docs/compatibility.md`.

## What this plugin does

This plugin adds ryk-native lifecycle hooks to OpenClaw when the host exposes real `api.on` registration. It calls the ryk CLI for policy checks, audit logging, and runtime safety decisions without duplicating policy logic.

The ryk CLI remains the source of truth for all policy decisions. When hooks do not fire (metadata/discovery), this package cannot enforce anything.

## Prerequisites

- ryk CLI built and available in PATH (run `ryk doctor` to verify)
- OpenClaw host installed

The supported setup starts with the curl-installed ryk binary:

```bash
curl -fsSL https://rykanv.com/install | sh
ryk unattended setup --hosts openclaw
ryk unattended health --json --hosts openclaw
```

The health command is ready only when the plugin is loaded, runtime inspection proves `before_tool_call`, the Gateway RPC is healthy, and the active Gateway answers `ryk.unattended` with a deny canary. The canary invokes the ryk callback against a synthetic dangerous command without executing it; it proves the active plugin callback and policy path, not a real agent tool execution.

## Supported protection path

```bash
ryk run -- openclaw
```

This is the primary recommended path (grade **`wrapper`**). It does not depend on OpenClaw plugin hooks firing.

## Source checkout path (development only)

If you have OpenClaw installed locally:

```bash
openclaw plugins install ./integrations/openclaw-plugin
```

Or:

```bash
ryk plugin install openclaw
```

This path is for development and manual adapter work. It is not the supported Mac mini/VPS deployment path. Confirm runtime registration with `ryk unattended health --json --hosts openclaw`.

## Npm / ClawHub sunset

Npm and ClawHub distribution paths are sunset and must not be used for new deployments. Existing installations should migrate to the curl installer and `ryk unattended setup`.

Metadata/discovery passes remain **`unprotected`** because `api.on` is not live. Do not use a registry install as a security step.

## Verify install (honest doctor)

```bash
ryk plugin doctor openclaw
```

Doctor reports host binary, extension paths, and whether a host plugin appears installed. **Installed does not mean protected.** Use the bounded unattended health check and then verify the live OpenClaw runtime:

```bash
openclaw plugins inspect ryk --runtime --json
openclaw gateway status --deep --require-rpc
openclaw gateway call ryk.unattended --json
```

If runtime inspection or the live plugin probe is unavailable on an older OpenClaw build, health remains not ready. Use `ryk run -- openclaw` for enforced wrapper protection.

## Hooks included

When hooks actually register (not npm CLI-metadata), the plugin calls `ryk hook openclaw <event>`:

| Event | When it fires | Behavior |
|-------|---------------|----------|
| `session.start` | At the start of an OpenClaw session | Informational (readiness log) |
| `tool.before` | Before OpenClaw invokes a tool | **Blocking when hooks fire** — empty/malformed/`ask` fail closed; legacy and metadata passes are unprotected |
| `tool.after` | After OpenClaw finishes using a tool | Informational (audit only) |
| `session.end` | When the session ends | Informational (audit only) |

OpenClaw’s `before_tool_call` result can evolve across host versions. This adapter only relies on the stable blocking shape, and handles permission-like `ask` decisions as blocks until a live resumable-approval contract is validated. Blocking is effective **only if** `before_tool_call` runs.

**Do not claim `tool.before` is blocking for metadata/discovery passes** — those passes are **`unprotected`**.

## How hooks call ryk

Each hook sends a JSON payload to `ryk hook openclaw <event>` via stdin and reads a JSON decision from stdout. On the blocking path (`tool.before`):

- empty or whitespace-only stdout → **block**
- JSON parse failure or missing `decision` → **block**
- `decision: "ask"` → **block** until a live, versioned OpenClaw resumable-approval contract is validated; this prevents an unknown host from silently proceeding
- unrecognized → **block**
- `decision: "block"` → block
- `decision: "allow"` / `"warn"` → allow (warn logs only)

Human-readable logs go to stderr.

Example payload for `tool.before`:

```json
{
  "version": 1,
  "host": "openclaw",
  "event": "tool.before",
  "payload": {
    "tool": "shell",
    "command": "git status"
  },
  "session_id": "session-uuid",
  "timestamp": "2026-01-01T00:00:00Z"
}
```

Example response:

```json
{
  "version": 1,
  "decision": "allow",
  "risk": "low",
  "category": "command",
  "reason": "policy_allow",
  "message": "Allowed by policy"
}
```

If the decision is `block` (including fail-closed cases), the plugin returns a block result that prevents the tool from executing **when the host honors the hook**.

## Run redteam

```bash
ryk redteam --ci
```

## Replay sessions

```bash
ryk replay --session last --verify
```

## Uninstall

Remove the plugin from your OpenClaw configuration:

```bash
openclaw plugins uninstall ryk
```

This plugin does not mutate host configuration, so uninstalling is safe.

## Known limitations

- **Metadata/discovery passes are `unprotected`.** OpenClaw reports a non-full registration mode and `api.on` is a no-op. Hooks never fire; the plugin cannot block tools. Supported setup: curl installer + `ryk unattended setup`; fallback protection is `ryk run -- openclaw` (**`wrapper`**).
- Local/bundled install does not by itself prove **`hook`** grade without live-host E2E.
- Hooks are advisory for informational events; blocking depends on OpenClaw honoring hook return values.
- Plugin installation depends on OpenClaw version and plugin loading mechanism.
- The plugin does not collect telemetry itself. Hook, plugin, and machine-readable calls are excluded from release CLI telemetry; a user-invoked `ryk run -- openclaw` wrapper may record only the fixed anonymous CLI metadata described in [`../../docs/telemetry.md`](../../docs/telemetry.md).
- Npm/ClawHub distribution is sunset; the supported deployment path is the curl installer plus `ryk unattended setup`.

## Security model

- This plugin calls the ryk CLI; it does not reimplement policy logic.
- No raw secrets are persisted in plugin files.
- Secrets are redacted from payloads before sending to ryk (keys matching `password`, `token`, `secret`, `api_key`, etc. are replaced with `[REDACTED]`).
- Blocking hooks fail closed on empty/malformed/`ask` responses.
- Human logs go to stderr.
- Unattended mode never prompts.
- This plugin does not claim stronger enforcement than OpenClaw hooks actually provide.
- Non-enforcing metadata/discovery passes are labeled **`unprotected`**, not soft-warned “green” installs.

## No MCP server behavior

The OpenClaw plugin does not add MCP server behavior.

## OpenClaw Security Scan Notice

OpenClaw’s plugin security scanner may block packages that use `child_process`. The ryk plugin needs that only to call the local `ryk` binary.

Registry security-scanner bypasses are not part of the supported deployment path. Use the curl installer plus `ryk unattended setup`, or `ryk run -- openclaw` as the wrapper fallback.

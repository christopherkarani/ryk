# ryk OpenClaw Plugin

OpenClaw plugin wrapper for ryk runtime guardrails.

## Protection first (read this)

| Path | Grade | Blocks tools? |
|------|-------|---------------|
| `ryk run -- openclaw` | **`wrapper`** (supported) | Yes — process launched under ryk |
| curl-installed ryk + `ryk agents setup openclaw` | **supported `hook` path** | Runtime hooks when OpenClaw full registration and Gateway dispatch are proven |
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
ryk agents setup openclaw
ryk agents health openclaw --json
```

OpenClaw 2026.8.1 is the minimum verified host and plugin API version. Older OpenClaw builds do not provide the dispatcher contract used by Ryk health and must remain not ready.

Health is ready only when the installed plugin is the receipt-bound reviewed bundle, runtime inspection proves `before_tool_call`, the Gateway RPC is healthy, the running Gateway identity is bound to the screened OpenClaw executable, and Gateway `tools.invoke` routes the manifest-declared `ryk_openclaw_canary` tool through the real tool dispatcher. The canary tool executor is inert: it never passes its synthetic command to a shell or any other executor.

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

This path is for development and manual adapter work. It is not the supported Mac mini/VPS deployment path. Confirm runtime registration with `ryk agents health openclaw --json`.

## Npm / ClawHub sunset

Npm and ClawHub distribution paths are sunset and must not be used for new deployments. Existing installations should migrate to the curl installer and `ryk agents setup openclaw`.

Metadata/discovery passes remain **`unprotected`** because `api.on` is not live. Do not use a registry install as a security step.

## Verify install (honest doctor)

```bash
ryk plugin doctor openclaw
```

Doctor reports host binary, extension paths, and whether a host plugin appears installed. **Installed does not mean protected.** Use the bounded agents health check and then verify the live OpenClaw runtime:

```bash
openclaw plugins inspect ryk --runtime --json
openclaw gateway status --deep --require-rpc
openclaw gateway call tools.invoke --params '{"name":"ryk_openclaw_canary","args":{"command":"rm -rf /","nonce":"ryk-health","cwd":"/absolute/workspace"}}' --json
```

The last command sends a dangerous-looking string only to the inert canary tool. The normal Gateway dispatcher must run `before_tool_call` first. A genuine Ryk denial returns the upstream RPC envelope `{"ok":false,"toolName":"ryk_openclaw_canary","error":{"code":"forbidden","message":"RYK_CANARY_BLOCK:ryk-health"}}`. Health must match that exact nonce-bound marker; a generic host denial is not Ryk evidence. Even if a broken policy allows the call, the inert executor returns `executed: false` with evidence `inert-tool-executor` and never executes or reflects the string.

`ryk agents setup openclaw` stores the canonical workspace in the plugin's `workspaceRoot` config. The adapter starts Ryk only in that operator-controlled directory; a tool's `cwd` parameter cannot select another policy. Health supplies the same workspace in its canary and rejects a mismatch. The unattended policy denies host-native file writes; its staged-write setting only applies to Ryk-mediated operations. Use `ryk run -- openclaw` for sessions that need staged workspace changes.

If runtime inspection or either live probe is unavailable, health remains not ready. Use `ryk run -- openclaw` for enforced wrapper protection.

OpenClaw 2026.8.1 does not currently expose the authoritative running executable identity needed for Ryk to bind a healthy Gateway to the screened CLI. Ryk therefore keeps `ready=false` until that upstream contract is available; setup and installed-file presence never substitute for it.

## What each probe proves

| Evidence | Probe | What it proves | What it does not prove |
|----------|-------|----------------|------------------------|
| Callback | None | No callback-only proof is accepted; the legacy plugin callback was removed | Gateway tool dispatch or agent-tool execution |
| Gateway dispatch | `tools.invoke` with `ryk_openclaw_canary` | The upstream Gateway dispatcher finds the manifest tool and traverses the normal tool-policy and hook path | A model or agent chose and invoked a tool |
| Agent tool | A real agent turn selecting a tool | End-to-end agent-to-tool execution for that installed host | Not established by either health probe |

Health reports Gateway-dispatch evidence, not callback evidence. It must not report live agent-tool evidence unless a real agent turn was observed separately.

## Hooks included

When hooks actually register (not npm CLI-metadata), the plugin calls `ryk hook openclaw <event>`:

| Event | When it fires | Behavior |
|-------|---------------|----------|
| `session.start` | At the start of an OpenClaw session | Informational (readiness log) |
| `tool.before` | Before OpenClaw invokes a tool | **Blocking when hooks fire** — empty/malformed fail closed; attended leftover unused `ask` is permit; unattended leftover `ask` is block; legacy and metadata passes are unprotected |
| `tool.after` | After OpenClaw finishes using a tool | Informational (audit only) |
| `session.end` | When the session ends | Informational (audit only) |

OpenClaw’s `before_tool_call` result can evolve across host versions. This adapter only relies on the stable blocking shape. Attended leftover unused policy `ask` is permit; unattended leftover `ask` is block. Stage, SoftBlock, and FM steward ask never become allow. Blocking is effective **only if** `before_tool_call` runs.

**Do not claim `tool.before` is blocking for metadata/discovery passes** — those passes are **`unprotected`**.

## How hooks call ryk

Each hook sends a JSON payload to `ryk hook openclaw <event>` via stdin and reads a JSON decision from stdout. On the blocking path (`tool.before`):

- empty or whitespace-only stdout → **block**
- JSON parse failure or missing `decision` → **block**
- `decision: "ask"` → **allow** when attended (leftover unused policy ask is permit); **block** when unattended / `--ci`. There is no OpenClaw ask UI. Stage / SoftBlock / FM ask are remapped to block by `ryk hook` before emit.
- unrecognized → **block**
- `decision: "block"` → block
- `decision: "allow"` / `"warn"` → allow (warn logs only)
- cyclic or BigInt input → **block before spawning ryk**
- payload larger than 1 MiB → **block before spawning ryk**

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

- **Metadata/discovery passes are `unprotected`.** OpenClaw reports a non-full registration mode and `api.on` is a no-op. Hooks never fire; the plugin cannot block tools. Supported setup: curl installer + `ryk agents setup openclaw`; fallback protection is `ryk run -- openclaw` (**`wrapper`**).
- OpenClaw 2026.8.1 is the verified floor for manifest tool ownership plus Gateway `tools.invoke` dispatcher evidence.
- Managed Ryk executable discovery requires the installer's path-bound SHA-256 receipt; a self-reporting binary is not accepted. The cached path is re-attested before each hook. This checksum receipt is integrity evidence, not a cryptographic signature: a same-user actor able to rewrite both the binary and receipt remains outside the trust claim.
- The current OpenClaw status contract lacks the running-Gateway executable identity needed for readiness, so the wrapper remains the required fallback until upstream exposes it.
- Callback proof and Gateway-dispatch proof are not live agent-tool execution proof.
- Local/bundled install does not by itself prove **`hook`** grade without live-host E2E.
- Hooks are advisory for informational events; blocking depends on OpenClaw honoring hook return values.
- Plugin installation depends on OpenClaw version and plugin loading mechanism.
- The plugin does not collect telemetry itself. Hook, plugin, and machine-readable calls are excluded from release CLI telemetry; a user-invoked `ryk run -- openclaw` wrapper may record only the fixed anonymous CLI metadata described in [`../../docs/telemetry.md`](../../docs/telemetry.md).
- Npm/ClawHub distribution is sunset; the supported deployment path is the curl installer plus `ryk agents setup openclaw`.

## Security model

- This plugin calls the ryk CLI; it does not reimplement policy logic.
- No raw secrets are persisted in plugin files.
- Secrets are redacted from payloads before sending to ryk (keys matching `password`, `token`, `secret`, `api_key`, etc. are replaced with `[REDACTED]`).
- Blocking hooks fail closed on empty/malformed responses, unrecognized decisions, cyclic or BigInt input, and payloads larger than 1 MiB. Attended leftover unused `ask` is permit; unattended leftover `ask` is block.
- Child-process error details are withheld from logs so stderr cannot smuggle secrets into operator output.
- Human logs go to stderr.
- Unattended mode never prompts.
- This plugin does not claim stronger enforcement than OpenClaw hooks actually provide.
- Non-enforcing metadata/discovery passes are labeled **`unprotected`**, not soft-warned “green” installs.

## No MCP server behavior

The OpenClaw plugin does not add MCP server behavior.

## OpenClaw Security Scan Notice

OpenClaw’s plugin security scanner may block packages that use `child_process`. The ryk plugin needs that only to call the local `ryk` binary.

Registry security-scanner bypasses are not part of the supported deployment path. Use the curl installer plus `ryk agents setup openclaw`, or `ryk run -- openclaw` as the wrapper fallback.

# ryk OpenCode Plugin

OpenCode plugin wrapper for ryk runtime guardrails.

## What this plugin does

This plugin adds ryk-native lifecycle hooks to OpenCode. It lets OpenCode call the ryk CLI for policy checks, audit logging, and runtime safety decisions without duplicating policy logic.

The plugin is a thin integration layer. The ryk CLI remains the source of truth for all policy decisions.

## Prerequisites

- ryk CLI built and available in PATH (run `ryk doctor` to verify)
- OpenCode host installed

ryk is not bundled into this plugin package. Fast setup:

```bash
ryk plugin install opencode --yes
```

Windows:

```powershell
ryk plugin install opencode --yes
```

## Supported install

The supported ryk installation path is the curl installer. The npm registry
path for ryk plugins is sunset and must not be used for new deployments.

```bash
curl -fsSL https://rykanv.com/install | sh
ryk plugin install opencode --yes
```

The strongest local protection remains running OpenCode through `ryk run -- opencode`; the OpenCode plugin provides native hooks and guardrails inside OpenCode.

## Install from local path

If you prefer to use the plugin directly from the ryk repository:

### Project-local install

Copy or symlink this directory into your project:

```bash
# From the ryk repo root
mkdir -p .opencode/plugins
cp integrations/opencode-plugin/ryk.ts .opencode/plugins/ryk.ts
cp integrations/opencode-plugin/ryk-tui.ts .opencode/plugins/ryk-tui.ts
```

See `examples/project-plugin-path.md` for details.

### Global install

Copy or symlink to the OpenCode global plugins directory:

```bash
mkdir -p ~/.config/opencode/plugins
cp integrations/opencode-plugin/ryk.ts ~/.config/opencode/plugins/ryk.ts
cp integrations/opencode-plugin/ryk-tui.ts ~/.config/opencode/plugins/ryk-tui.ts
```

See `examples/global-plugin-path.md` for details.

### Verify the plugin is recognized

```bash
ryk plugin doctor opencode
```

## Verify install

Run the ryk plugin doctor:

```bash
ryk plugin doctor opencode
```

Expected output sections:
- ryk version
- Policy status (present/valid)
- Plugin directories (opencode: found)
- Host binaries (opencode: detected or not detected)

## Hooks included

The plugin registers lifecycle hooks that call `ryk hook opencode <event>`:

| Event | When it fires | Behavior |
|-------|---------------|----------|
| `session.created` | At the start of an OpenCode session | Informational (readiness log) |
| `tool.execute.before` | Before OpenCode invokes a tool | **Blocking** — ryk can prevent the tool call |
| `tool.execute.after` | After OpenCode finishes using a tool | Informational (audit only) |
| `permission.ask` → `permission.asked` | When OpenCode requests user permission | ryk `block`/`error` → deny; residual `ask` is permit unless unattended |
| `command.execute.before` | Before a slash/custom command runs | **Blocking** — evaluated as a tool name |
| `file.edited` | When a file is edited by OpenCode | Informational (audit only) |
| `command.executed` | When a shell command is executed | Informational (audit only) |
| `session.updated` | When the session state changes | Informational (audit only) |
| `session.idle` | When the session becomes idle | Informational (audit only) |
| `session.error` | When a session error occurs | Informational (audit only) |
| `shell.env` | When the shell environment is prepared | **Scrubs secret env vars** from what OpenCode passes to shell, then audits |

## How hooks call ryk

Each hook sends a JSON payload to `ryk hook opencode <event>` via stdin and reads a JSON decision from stdout. The plugin preserves OpenCode's expected return values. Human-readable logs go to stderr.

Example payload for `tool.execute.before`:

```json
{
  "version": 1,
  "host": "opencode",
  "event": "tool.execute.before",
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

If the decision is `block`, the server hook throws a **single-line** `Error` so the tool does not run. The companion `ryk-tui.ts` host (`id: "ryk"`) is what vanilla OpenCode lists as a plugin and is what shows the toast — a server-only file cannot also export `tui` on OpenCode 1.18. Set `RYK_OPENCODE_VERBOSE=1` to also log full operator detail (Next / remediation) to stderr. Do not `console.log` from the plugin: OpenCode dumps that into the prompt.

## Run redteam

```bash
ryk redteam --ci
```

## Replay sessions

```bash
ryk replay --session last --verify
```

## Uninstall

Remove the local plugin from your OpenCode configuration:

```bash
# Project-local files
rm .opencode/plugins/ryk.ts .opencode/plugins/ryk-tui.ts

# Global files
rm ~/.config/opencode/plugins/ryk.ts ~/.config/opencode/plugins/ryk-tui.ts
```

This plugin does not mutate host configuration, so uninstalling is safe.

## Known limitations

- Hooks are advisory for informational events; blocking hooks depend on OpenCode honoring thrown errors.
- The strongest protection remains `ryk run -- opencode`.
- Plugin installation depends on OpenCode version and plugin loading mechanism.
- The plugin does not collect telemetry itself. Hook, plugin, and machine-readable calls are excluded from release CLI telemetry; a user-invoked `ryk run -- opencode` wrapper may record only the fixed anonymous CLI metadata described in [`../../docs/telemetry.md`](../../docs/telemetry.md).
- Official npm publication is in progress; the package structure is ready for publication.

## Security model

- This plugin calls the ryk CLI; it does not reimplement policy logic.
- No raw secrets are persisted in plugin files.
- Secrets are redacted from payloads before sending to ryk (keys matching `password`, `token`, `secret`, `api_key`, etc. are replaced with `[REDACTED]`).
- Hook return values remain valid for OpenCode parsing.
- Human logs go to stderr.
- CI mode never prompts.
- This plugin does not claim stronger enforcement than OpenCode hooks support.

## No MCP server behavior

The OpenCode plugin does not add MCP server behavior.

## Strongest protection warning

> The ryk OpenCode plugin adds lifecycle hooks for OpenCode. For the strongest local protection, run the OpenCode process itself through ryk with `ryk run -- opencode`.

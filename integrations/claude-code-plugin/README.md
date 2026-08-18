# ryk Claude Code Plugin

ryk safety hooks and skills for Claude Code.

## What this plugin does

This plugin adds ryk-native skills and lifecycle hooks to Claude Code. It lets Claude Code call the ryk CLI for policy checks, red-team fixtures, session replay, and runtime safety decisions without duplicating policy logic.

The plugin is a thin integration layer. The ryk CLI remains the source of truth for all policy decisions.

## Prerequisites

- ryk CLI built and available in PATH (or use `./zig-out/bin/ryk` from the repo)
- Zig 0.16.0 to build ryk from source
- Claude Code host binary installed

## Install from local path

1. Build ryk:
   ```bash
   ./scripts/zig build
   ```

2. Install the plugin locally in Claude Code (method depends on Claude Code version; consult Claude Code docs for the latest plugin loading mechanism).

3. Verify the plugin is recognized:
   ```bash
   ryk plugin doctor claude
   ```

## Install through local marketplace

If your Claude Code version supports repo-local marketplace files, see `integrations/claude-marketplace/` for a documented example catalog. The exact marketplace schema depends on the Claude Code version you are using.

## Verify install

Run the ryk plugin doctor:

```bash
ryk plugin doctor claude
```

Expected output sections:
- ryk version
- Policy status (present/valid)
- Plugin directories (claude: found)
- Host binaries (claude: detected or not detected)

## Available skills

| Skill | Purpose |
|-------|---------|
| `doctor` | Check ryk installation, policy, and plugin readiness |
| `init` | Create or repair an ryk policy for the current repo |
| `protect` | Explain how to run Claude Code under ryk protection |
| `redteam` | Run deterministic red-team fixtures |
| `replay` | Show and explain the latest ryk session replay |

Skills are invoked as `/ryk:doctor`, `/ryk:init`, `/ryk:protect`, `/ryk:redteam`, `/ryk:replay` depending on the Claude Code plugin namespace configuration.

## Hooks included

The plugin registers lifecycle hooks that call `ryk hook claude <event>`:

| Event | When it fires |
|-------|---------------|
| `SessionStart` | At the start of a Claude Code session |
| `UserPromptSubmit` | When a user submits a prompt |
| `PreToolUse` | Before Claude Code invokes a tool |
| `PermissionRequest` | When Claude Code requests user permission |
| `PostToolUse` | After Claude Code finishes using a tool |
| `SessionEnd` | When the session ends |

## How hooks call ryk

Each hook sends a JSON payload to `ryk hook claude <event>` via stdin and reads a JSON decision from stdout. The hook stdout remains valid for Claude Code parsing. Human-readable logs go to stderr.

Example:

```bash
echo '{"version":1,"host":"claude","event":"PreToolUse","payload":{"tool":"shell","command":"git status"}}' \
  | ryk hook claude PreToolUse
```

## Run redteam

```bash
ryk redteam --ci
```

## Replay sessions

```bash
ryk replay --session last --verify
```

## Uninstall

Remove the plugin from Claude Code using your Claude Code plugin management commands. This plugin does not mutate host configuration, so uninstalling is safe.

## Known limitations

- Hooks are advisory; they do not enforce policy independently of the host.
- The strongest protection remains `ryk run -- <claude-code-command>`.
- Plugin installation preview only; actual host plugin loading depends on Claude Code version.
- The plugin does not collect telemetry itself. Hook, plugin, and machine-readable calls are excluded from release CLI telemetry; a user-invoked `ryk run -- <claude-code-command>` wrapper may record only the fixed anonymous CLI metadata described in [`../../docs/telemetry.md`](../../docs/telemetry.md).
- Official marketplace availability is not yet implemented.

## Security model

- This plugin calls the ryk CLI; it does not reimplement policy logic.
- No raw secrets are persisted in plugin files.
- Hook stdout is host-valid JSON.
- Human logs go to stderr.
- CI mode never prompts.
- This plugin does not claim stronger enforcement than Claude Code hooks support.

## No MCP server behavior

This plugin does not add MCP server behavior.

## Decision mapping (honest)

ryk returns host-actionable decisions on hook stdout. Claude Code interprets them:

| ryk | Expected host behavior |
|---|---|
| `allow` | Proceed |
| `block` | Deny the tool / permission |
| leftover unused policy `ask` | **allow** from `ryk hook` when attended; deny when unattended / `--ci`. A leaked `ask` after rewrite is fail-closed deny. Explicit `block` stays deny. |
| `warn` | Advisory; do not silently equate to hard deny unless policy/CI requires it |

Unattended (`ryk hook ... --ci`, `RYK_UNATTENDED`, `CI`) hardens leftover unused policy ask → `block`. Attended leftover is rewritten to allow by `ryk hook`.

## Strongest protection warning

> The ryk Claude Code plugin adds native skills and lifecycle hooks for Claude Code. For the strongest local protection, run the Claude Code process itself through ryk with `ryk run -- <claude-code-command>`.

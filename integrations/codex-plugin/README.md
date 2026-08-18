# ryk Codex Plugin

ryk safety hooks and skills for Codex.

## What this plugin does

This plugin adds ryk-native skills and lifecycle hooks to Codex. It lets Codex call the ryk CLI for policy checks, red-team fixtures, session replay, and runtime safety decisions without duplicating policy logic.

The plugin is a thin integration layer. The ryk CLI remains the source of truth for all policy decisions.

## Prerequisites

- ryk CLI built and available in PATH (or use `./zig-out/bin/ryk` from the repo)
- Zig 0.16.0 to build ryk from source
- Codex host binary installed

## Install from local path

1. Build ryk:
   ```bash
   ./scripts/zig build
   ```

2. Install the plugin locally in Codex (method depends on Codex version; consult Codex docs for the latest plugin loading mechanism).

3. Verify the plugin is recognized:
   ```bash
   ryk plugin doctor codex
   ```

## Install through repo marketplace

If your Codex version supports repo-local marketplace files, see `integrations/codex-plugin/examples/marketplace.json` for a documented example. The exact marketplace schema depends on the Codex version you are using.

## Verify install

Run the ryk plugin doctor:

```bash
ryk plugin doctor codex
```

Expected output sections:
- ryk version
- Policy status (present/valid)
- Plugin directories (codex: found)
- Host binaries (codex: detected or not detected)

## Available skills

| Skill | Purpose |
|-------|---------|
| `ryk-doctor` | Check ryk installation, policy, and plugin readiness |
| `ryk-init` | Create or repair an ryk policy for the current repo |
| `ryk-protect` | Explain how to run Codex under ryk protection |
| `ryk-redteam` | Run deterministic red-team fixtures |
| `ryk-replay` | Show and explain the latest ryk session replay |

## Hooks included

The plugin registers lifecycle hooks that call `ryk hook codex <event>`:

| Event | When it fires |
|-------|---------------|
| `SessionStart` | At the start of a Codex session |
| `UserPromptSubmit` | When a user submits a prompt |
| `PreToolUse` | Before Codex invokes a tool |
| `PermissionRequest` | When Codex requests user permission |
| `PostToolUse` | After Codex finishes using a tool |
| `Stop` | When the session stops |

## How hooks call ryk

Each hook sends a JSON payload to `ryk hook codex <event>` via stdin and reads a JSON decision from stdout. The hook stdout remains valid for Codex parsing. Human-readable logs go to stderr.

Example:

```bash
echo '{"version":1,"host":"codex","event":"PreToolUse","payload":{"tool":"shell","command":"git status"}}' \
  | ryk hook codex PreToolUse
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

Remove the plugin from Codex using your Codex plugin management commands. This plugin does not mutate host configuration, so uninstalling is safe.

## Known limitations

- Hooks are advisory; they do not enforce policy independently of the host.
- The strongest protection remains `ryk run -- <codex-command>`.
- Plugin installation preview only; actual host plugin loading depends on Codex version.
- The plugin does not collect telemetry itself. Hook, plugin, and machine-readable calls are excluded from release CLI telemetry; a user-invoked `ryk run -- <codex-command>` wrapper may record only the fixed anonymous CLI metadata described in [`../../docs/telemetry.md`](../../docs/telemetry.md).

## Security model

- This plugin calls the ryk CLI; it does not reimplement policy logic.
- No raw secrets are persisted in plugin files.
- Hook stdout is host-valid JSON.
- Human logs go to stderr.
- CI mode never prompts.
- This plugin does not claim stronger enforcement than Codex hooks support.

## No MCP server behavior

This plugin does not add MCP server behavior.

## Decision mapping (honest)

ryk returns host-actionable decisions on hook stdout. Codex interprets them:

| ryk | Expected host behavior |
|---|---|
| `allow` | Proceed |
| `block` | Deny the tool / permission |
| leftover unused policy `ask` | **allow** from `ryk hook` when attended; deny when unattended / `--ci`. A leaked `ask` after rewrite is fail-closed deny. Explicit `block` stays deny. |
| `warn` | Advisory; do not silently equate to hard deny unless policy/CI requires it |

Unattended (`ryk hook ... --ci`, `RYK_UNATTENDED`, `CI`) hardens leftover unused policy ask → `block`. Attended leftover is rewritten to allow by `ryk hook`.

## Strongest protection warning

> The ryk Codex plugin adds native skills and lifecycle hooks for Codex. For the strongest local protection, run the Codex process itself through ryk with `ryk run -- <codex-command>`.

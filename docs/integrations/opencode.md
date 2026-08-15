# ryk OpenCode Plugin Integration

This document describes the ryk OpenCode plugin, how to install it, and how to use it.

## Overview

The ryk OpenCode plugin is a local integration package that adds ryk skills and lifecycle hooks to OpenCode. It lives under `integrations/opencode-plugin/` in the ryk repository.

The plugin is a thin layer. All policy decisions are made by the ryk CLI. The plugin does not duplicate policy logic.

The plugin provides native hooks and guardrails inside OpenCode, routing lifecycle events through ryk policy for evaluation and logging.

## Strongest protection

The strongest protection for OpenCode sessions is running the host through ryk:

```bash
ryk opencode
```

The plugin adds native hooks and guardrails inside OpenCode, but `ryk opencode` is the strongest protection because the agent session itself is launched as a ryk-managed child process with filtered environment variables and full policy enforcement.

The strongest local protection remains running OpenCode through `ryk opencode`; the OpenCode plugin provides native hooks and guardrails inside OpenCode.

## Prerequisites

- ryk CLI built and available in PATH (run `ryk doctor` to verify)
- OpenCode host installed

ryk must be installed separately. The plugin does not bundle the ryk CLI.

## Install instructions

### Supported install

The supported ryk installation path is the curl installer. The npm registry
path for ryk plugins is sunset and must not be used for new deployments.

```bash
curl -fsSL https://rykanv.com/install | sh
ryk plugin install opencode --yes
```

For the strongest protection, launch the host through ryk:

```bash
ryk opencode
```

### Build ryk

If you are installing from the ryk repository:

```bash
./scripts/zig build
```

### Local project install

Install the plugin into the current project:

```text
.opencode/plugins/ryk.ts
.opencode/plugins/ryk-tui.ts
```

OpenCode loads plugins from `.opencode/plugins/` relative to the workspace root when running inside a project directory. `ryk.ts` is the server hook module; `ryk-tui.ts` is the TUI host (`id: "ryk"`). OpenCode 1.18 cannot put both in one file.

### Global install

Install the plugin for all OpenCode sessions:

```text
~/.config/opencode/plugins/ryk.ts
~/.config/opencode/plugins/ryk-tui.ts
```

OpenCode loads global plugins from `~/.config/opencode/plugins/` when no project-local plugin is present.

### Local fallback install

```bash
mkdir -p ~/.config/opencode/plugins
cp integrations/opencode-plugin/ryk.ts ~/.config/opencode/plugins/ryk.ts
cp integrations/opencode-plugin/ryk-tui.ts ~/.config/opencode/plugins/ryk-tui.ts
```

### Manual fallback install

If automatic loading fails:

1. Copy `integrations/opencode-plugin/ryk.ts` and `ryk-tui.ts` to `.opencode/plugins/` (project) or `~/.config/opencode/plugins/` (global).
2. Ensure `ryk` is on PATH (or set absolute `RYK_BIN`).
3. Restart OpenCode and run `ryk plugin doctor opencode`.

## Verify install

### Plugin doctor

```bash
ryk plugin doctor opencode
```

With JSON output:

```bash
ryk plugin doctor opencode --json
```

Expected output sections:
- ryk version
- Policy status (present/valid)
- Plugin directories (opencode: found)
- Host binaries (opencode: detected or not detected)

### Plugin manifest

```bash
ryk plugin manifest opencode
```

This reports the expected manifest path and existence status.

### Dry-run install

```bash
ryk plugin install opencode --dry-run

Day-one / `ryk doctor --fix` installs to the **global** path (`~/.config/opencode/plugins/ryk.ts` and `ryk-tui.ts`) by default. Use `--scope project` for a repo-local plugin only.
```

### Hook smoke test

```bash
cat tests/plugin-fixtures/opencode/tool_execute_before_command_safe.json \
  | ryk hook opencode tool.execute.before
```

Expected: `allow` decision in valid JSON.

When a blocking hook vetoes a tool, the OpenCode TUI shows a toast with the command, matched rule, and reason. See the live clip in [`integrations/opencode-plugin/README.md`](../integrations/opencode-plugin/README.md#block-toast).

### Example decision command

```bash
ryk decide command --json '{"version":1,"host":"opencode","command":"git status","mode":"strict"}'
```

### Run redteam

```bash
ryk redteam --ci
```

### Replay last session

```bash
ryk replay --session last --verify
```

## Skills

This package is hooks-only. It does not ship OpenCode skill folders. Use `ryk doctor`, `ryk init`, and `ryk redteam` from the CLI (or your agent’s own skill system).

## Hooks supported

Hooks call `ryk hook opencode <event>` with a JSON payload on stdin. The following OpenCode events are supported:

| Event | Description | Timeout |
|-------|-------------|---------|
| `session.created` | Session initialization check | 10s |
| `tool.execute.before` | Tool use policy evaluation before execution | 15s |
| `tool.execute.after` | Post-tool acknowledgment and logging | 10s |
| `command.execute.before` | Slash/custom command policy evaluation | 15s |
| `permission.asked` | Permission request policy evaluation (`permission.ask` host hook) | 15s |
| `permission.replied` | Permission response logging | 10s |
| `file.edited` | File edit policy evaluation and logging | 10s |
| `command.executed` | Shell command execution logging | 10s |
| `session.updated` | Session state update logging | 10s |
| `session.idle` | Session idle event handling | 10s |
| `session.error` | Session error logging | 10s |
| `shell.env` | Environment variable inspection and redaction | 10s |

### How hooks call ryk

Each hook sends a JSON payload to stdin and expects a JSON decision on stdout:

```bash
echo '{"version":1,"host":"opencode","event":"tool.execute.before","payload":{"tool":"shell","command":"git status","cwd":"/path/to/project"}}' \
  | ryk hook opencode tool.execute.before
```

Example with a fixture file:

```bash
cat tests/plugin-fixtures/opencode/tool_execute_before_command_safe.json \
  | ryk hook opencode tool.execute.before
```

## Uninstall

Remove the plugin from your OpenCode configuration:

1. Delete the local project plugin:
   ```bash
   rm .opencode/plugins/ryk.ts .opencode/plugins/ryk-tui.ts
   ```

2. Or delete the global plugin:
   ```bash
   rm ~/.config/opencode/plugins/ryk.ts ~/.config/opencode/plugins/ryk-tui.ts
   ```

This plugin does not mutate host configuration beyond the plugin file itself, so uninstalling is safe.

## Troubleshooting

### Plugin directory not found

Ensure you run `ryk plugin doctor opencode` from the repository root or a project directory that contains the plugin. The doctor treats a scope as installed only when both `.opencode/plugins/ryk.ts` and `ryk-tui.ts` (local) or both `~/.config/opencode/plugins/ryk.ts` and `ryk-tui.ts` (global) exist.

### Hooks timeout

If hooks exceed their timeout, OpenCode may skip them. Check that `ryk` is in PATH and that `.ryk/policy.yaml` loads quickly.

### Policy not found

Run `ryk init --preset generic-agent` to create a default policy, then validate with `ryk policy check .ryk/policy.yaml`.

### ryk binary not found

Build ryk with `./scripts/zig build` or ensure `./zig-out/bin/ryk` is in your PATH.

### Fake secret redaction questions

The plugin uses synthetic test secrets (e.g., `fake_p05_secret_value`) in fixtures only. If you see redaction warnings about these values in test output, that is expected behavior.

## Limitations

- Hooks are advisory; enforcement depends on OpenCode host support.
- The strongest protection is `ryk opencode`.
- Plugin installation is a preview/dry-run by default.
- No telemetry is collected.
- The OpenCode plugin does not add MCP server behavior.

## Security model

- The ryk CLI is the source of truth.
- The plugin does not reimplement policy logic.
- No secrets are stored in plugin files.
- Hook stdout is host-valid JSON.
- Human logs go to stderr.
- CI mode never prompts.

## No telemetry

This plugin does not collect telemetry. No usage data, session content, or metadata is transmitted to any external service.

## No MCP behavior

This plugin does not add MCP server behavior.

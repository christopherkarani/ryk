# ryk Claude Code Plugin Integration

This document describes the ryk Claude Code plugin, how to install it, and how to use it.

## Overview

The ryk Claude Code plugin is a local integration package that adds ryk skills and lifecycle hooks to Claude Code. It lives under `integrations/claude-code-plugin/` in the ryk repository.

The plugin is a thin layer. All policy decisions are made by the ryk CLI. The plugin does not duplicate policy logic.

## Prerequisites

- Zig 0.16.0 (to build ryk from source)
- ryk CLI built and available in PATH
- Claude Code host binary installed

## Install instructions

### Build ryk

```bash
./scripts/zig build
```

### Install from release artifact

1. Download the latest plugin zip from the release page:
   ```text
   ryk-claude-code-plugin-vX.Y.Z.zip
   ```

2. Verify the checksum:
   ```bash
   sha256sum -c ryk-plugin-checksums.txt
   ```

3. Extract the plugin to your preferred location:
   ```bash
   unzip ryk-claude-code-plugin-vX.Y.Z.zip -d ~/ryk-plugins/claude
   ```

4. Point Claude Code to the extracted plugin directory.

### Install from local path (repo)

1. Build ryk:
   ```bash
   ./scripts/zig build
   ```

2. Point Claude Code to the plugin directory:
   ```text
   integrations/claude-code-plugin/
   ```

3. Verify the plugin is recognized:
   ```bash
   ./zig-out/bin/ryk plugin doctor claude
   ```

### Repo marketplace install

If your Claude Code version supports repo marketplace sources, add this repository:

```bash
claude plugin marketplace add christopherkarani/ryk
claude plugin install ryk@ryk-local-plugins --scope user
```

Or inside Claude Code:
```text
/plugin marketplace add christopherkarani/ryk
/plugin install ryk@ryk-local-plugins
/reload-plugins
```

These commands add the ryk repository as a plugin marketplace source. This is not the same as being listed in the official Claude marketplace.

### Local marketplace example

For reference, a local marketplace catalog example is available at:

```text
integrations/claude-marketplace/.claude-plugin/marketplace.json
```

This is a documented example only. The catalog references the plugin source at `../claude-code-plugin` (relative to that directory).

The root-level marketplace file for repo marketplace install is:

```text
.claude-plugin/marketplace.json
```

### Manual fallback install

If your Claude Code version does not support automatic plugin loading:

1. Copy the skills from `integrations/claude-code-plugin/skills/` into your Claude Code skills directory.
2. Copy the hooks from `integrations/claude-code-plugin/hooks/hooks.json` into your Claude Code hooks configuration.
3. Ensure `ryk` is in PATH or use the full path to the binary.

## Verify install

### Plugin doctor

```bash
./zig-out/bin/ryk plugin doctor claude
```

Expected output sections:
- ryk version
- Policy status (present/valid)
- Plugin directories (claude: found)
- Host binaries (claude: detected or not detected)

### Plugin manifest

```bash
./zig-out/bin/ryk plugin manifest claude
```

This reports the expected manifest path and existence status.

### Hook smoke test

```bash
cat tests/plugin-fixtures/claude/pre_tool_use_command_safe.json \
  | ./zig-out/bin/ryk hook claude PreToolUse
```

Expected: `allow` decision in valid JSON.

### Run redteam

```bash
./zig-out/bin/ryk redteam --ci
```

### Replay last session

```bash
./zig-out/bin/ryk replay --session last --verify
```

## Skill list

| Skill | File | Purpose |
|-------|------|---------|
| `doctor` | `skills/doctor/SKILL.md` | Check installation and readiness |
| `init` | `skills/init/SKILL.md` | Create or repair a policy |
| `protect` | `skills/protect/SKILL.md` | Explain strongest protection |
| `redteam` | `skills/redteam/SKILL.md` | Run red-team fixtures |
| `replay` | `skills/replay/SKILL.md` | Replay latest session |

Skills are invoked as `/ryk:doctor`, `/ryk:init`, `/ryk:protect`, `/ryk:redteam`, `/ryk:replay` depending on the Claude Code plugin namespace configuration.

## Hook list

Hooks call `ryk hook claude <event>` with a JSON payload on stdin:

| Event | Description | Timeout |
|-------|-------------|---------|
| `SessionStart` | Session initialization check | 10s |
| `UserPromptSubmit` | Prompt secret/redaction check | 10s |
| `PreToolUse` | Tool use policy evaluation | 15s |
| `PermissionRequest` | Permission policy evaluation | 15s |
| `PostToolUse` | Post-tool acknowledgment | 10s |
| `SessionEnd` | Session end notification | 10s |

## Uninstall

Remove the plugin from Claude Code using your Claude Code plugin management commands. This plugin does not mutate host configuration, so uninstalling is safe.

If you installed from a release artifact, simply delete the extracted directory.

## Troubleshooting

### Plugin directory not found

Ensure you run `ryk plugin doctor claude` from the repository root. The doctor looks for `integrations/claude-code-plugin/` relative to the workspace root.

### Hooks timeout

If hooks exceed their timeout, Claude Code may skip them. Check that `ryk` is in PATH and that `.ryk/policy.yaml` loads quickly.

### Policy not found

Run `ryk init --preset generic-agent` to create a default policy, then validate with `ryk policy check .ryk/policy.yaml`.

### ryk binary not found

Build ryk with `./scripts/zig build` or ensure `./zig-out/bin/ryk` is in your PATH.

### Fake secret redaction questions

The plugin uses synthetic test secrets (e.g., `fake_p05_secret_value`) in fixtures only. If you see redaction warnings about these values in test output, that is expected behavior.

### Marketplace path issues

The marketplace catalog uses a relative path (`../claude-code-plugin`). If your Claude Code version requires absolute paths, adjust the `source` field in `integrations/claude-marketplace/.claude-plugin/marketplace.json`.

## Hook stdout contract (tool gates)

For `PreToolUse` and `PermissionRequest`, `ryk hook claude` emits Claude-native JSON so the host can hard-stop the tool:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "command blocked by ryk policy: …"
  }
}
```

- `permissionDecision`: `allow` | `deny` (residual `ask` is permit; unattended / `--ci` hardens to `deny`)
- `permissionDecisionReason`: short one-line reason (no Recourse/Next walls)
- Process exit is `0` with structured JSON (Claude plugin-compatible)
- Operator Recourse/Next remain on **stderr**, not in the reason string
- Informational events (`SessionStart`, `UserPromptSubmit`, …) still use ryk-generic hook JSON

Grade: **hook**. Host-shaped deny works when Claude Code honors `permissionDecision`. It does not replace process wrapping.

## Limitations

- Tool-gate deny/ask is host-shaped hook output; enforcement still depends on Claude Code honoring `permissionDecision` (hook grade, not OS sandbox).
- The strongest protection is the process-level wrapper `ryk run -- <claude-code-command>` (the `ryk claude` launcher uses the same protected path).
- Plugin installation is a preview/dry-run by default.
- The plugin does not collect telemetry itself. Hook and machine-readable calls are excluded from release CLI telemetry; user-invoked CLI wrappers may record only the fixed pseudonymous metadata described in [`../telemetry.md`](../telemetry.md).
- Official marketplace availability is not yet implemented.

## Security model

- The ryk CLI is the source of truth.
- The plugin does not reimplement policy logic.
- No secrets are stored in plugin files.
- Hook stdout is host-valid JSON.
- Human logs go to stderr.
- CI mode never prompts.

## No MCP support

This plugin does not add MCP server behavior.

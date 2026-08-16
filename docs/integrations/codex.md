# ryk Codex Plugin Integration

The Codex plugin adds ryk skills and lifecycle hooks. It lives in `integrations/codex-plugin/`. The ryk CLI makes every policy decision; the plugin does not copy that logic.

## Prerequisites

- Zig 0.16.0 (to build ryk from source)
- ryk CLI built and available in PATH
- Codex host binary installed

## Install instructions

### Build ryk

```bash
./scripts/zig build
```

### Install from release artifact

1. Download the latest plugin zip from the release page:
   ```text
   ryk-codex-plugin-vX.Y.Z.zip
   ```

2. Verify the checksum:
   ```bash
   sha256sum -c ryk-plugin-checksums.txt
   ```

3. Extract the plugin to your preferred location:
   ```bash
   unzip ryk-codex-plugin-vX.Y.Z.zip -d ~/ryk-plugins/codex
   ```

4. Point Codex to the extracted plugin directory.

### Install from local path (repo)

1. Build ryk:
   ```bash
   ./scripts/zig build
   ```

2. Point Codex to the plugin directory:
   ```text
   integrations/codex-plugin/
   ```

3. Verify the plugin is recognized:
   ```bash
   ./zig-out/bin/ryk plugin doctor codex
   ```

### Repo marketplace install

If your Codex version supports repo marketplace sources, add this repository:

```bash
codex plugin marketplace add christopherkarani/ryk
```

Then install ryk from Codex's plugin UI/directory after adding the marketplace.

This command adds the ryk repository as a plugin marketplace source. This is not the same as being listed in the official Codex marketplace.

### Local marketplace example

For reference, a local marketplace example is available at:

```text
integrations/codex-plugin/examples/marketplace.json
```

This is a documented example only. The exact schema depends on your Codex version.

The tracked repository marketplace file for repo marketplace install is:

```text
.agents/plugins/marketplace.json (plugin source: integrations/codex-plugin/)
```

### Manual fallback install

If your Codex version does not support automatic plugin loading:

1. Copy the skills from `integrations/codex-plugin/skills/` into your Codex skills directory.
2. Copy the hooks from `integrations/codex-plugin/hooks/hooks.json` into your Codex hooks configuration.
3. Ensure `ryk` is in PATH or use the full path to the binary.

## Verify install

### Plugin doctor

```bash
./zig-out/bin/ryk plugin doctor codex
```

Expected output sections:
- ryk version
- Policy status (present/valid)
- Plugin directories (codex: found)
- Host binaries (codex: detected or not detected)

### Plugin manifest

```bash
./zig-out/bin/ryk plugin manifest codex
```

This reports the expected manifest path and existence status.

### Hook smoke test

```bash
cat tests/plugin-fixtures/codex/pre_tool_use_command_safe.json \
  | ./zig-out/bin/ryk hook codex PreToolUse
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
| `ryk-doctor` | `skills/ryk-doctor/SKILL.md` | Check installation and readiness |
| `ryk-init` | `skills/ryk-init/SKILL.md` | Create or repair a policy |
| `ryk-protect` | `skills/ryk-protect/SKILL.md` | Explain strongest protection |
| `ryk-redteam` | `skills/ryk-redteam/SKILL.md` | Run red-team fixtures |
| `ryk-replay` | `skills/ryk-replay/SKILL.md` | Replay latest session |

## Hook list

Hooks call `ryk hook codex <event>` with a JSON payload on stdin:

| Event | Description | Timeout |
|-------|-------------|---------|
| `SessionStart` | Session initialization check | 10s |
| `UserPromptSubmit` | Prompt secret/redaction check | 10s |
| `PreToolUse` | Tool use policy evaluation | 15s |
| `PermissionRequest` | Permission policy evaluation | 15s |
| `PostToolUse` | Post-tool acknowledgment | 10s |
| `Stop` | Session stop notification | 10s |

## Uninstall

Remove the plugin from Codex using your Codex plugin management commands. This plugin does not mutate host configuration, so uninstalling is safe.

If you installed from a release artifact, simply delete the extracted directory.

## Troubleshooting

### Plugin directory not found

Ensure you run `ryk plugin doctor codex` from the repository root. The doctor looks for `integrations/codex-plugin/` relative to the workspace root.

### Hooks timeout

If hooks exceed their timeout, Codex may skip them. Check that `ryk` is in PATH and that `.ryk/policy.yaml` loads quickly.

### Policy not found

Run `ryk init --preset codex` to create a default policy, then validate with `ryk policy check .ryk/policy.yaml`.

### ryk binary not found

Build ryk with `./scripts/zig build` or ensure `./zig-out/bin/ryk` is in your PATH.

### Fake secret redaction questions

The plugin uses synthetic test secrets (e.g., `fake_p05_secret_value`) in fixtures only. If you see redaction warnings about these values in test output, that is expected behavior.

## Limitations

- Hooks are advisory; enforcement depends on Codex host support.
- The strongest protection is the process-level wrapper `ryk run -- <codex-command>` (the `ryk codex` launcher uses the same protected path).
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

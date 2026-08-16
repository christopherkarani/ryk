# ryk OpenClaw Plugin Integration

This document describes the ryk OpenClaw plugin, how to install it, and how to use it.

## Overview

The ryk OpenClaw plugin is a local integration package that adds ryk runtime guardrails to OpenClaw. It lives under `integrations/openclaw-plugin/` in the ryk repository.

The plugin is a thin layer. All policy decisions are made by the ryk CLI. The plugin does not duplicate policy logic.

The plugin provides native hooks and guardrails inside OpenClaw, routing lifecycle events through ryk policy for evaluation and logging.

## Strongest protection

The strongest protection for OpenClaw sessions is running the host through ryk:

```bash
ryk openclaw
```

The plugin adds native hooks and guardrails inside OpenClaw, but `ryk openclaw` is the strongest protection because the agent session itself is launched as a ryk-managed child process with filtered environment variables and full policy enforcement.

The strongest local protection remains running OpenClaw through `ryk openclaw`; the OpenClaw plugin provides native guardrails where OpenClaw plugin hooks support them.

## Prerequisites

- ryk CLI built and available in PATH (run `ryk doctor` to verify)
- OpenClaw host installed

ryk must be installed separately. The plugin does not bundle the ryk CLI.

## Install instructions

### Supported install: curl + unattended setup

The supported deployment path is the checksum-verified curl installer followed by the first-class unattended workflow:

```bash
curl -fsSL https://rykanv.com/install | sh
ryk agents setup openclaw
ryk agents health openclaw --json
```

This path installs the ryk binary and its native OpenClaw integration assets. Do not treat a copied plugin directory or a registry package as a supported deployment.

Native health readiness is gated in order: the installed plugin must be the receipt-bound reviewed bundle, runtime inspection must prove `before_tool_call`, Gateway RPC must be healthy, and the running Gateway identity must be bound to the screened OpenClaw executable. **Identity is the permanent gate today:** OpenClaw does not expose a comparable process identity, so `ready` stays false and the wrapper is required. A nonce-bound deny canary through Gateway `tools.invoke` is implemented for the future path after identity binds; it is not a current readiness requirement while identity remains unavailable. The manifest-declared canary tool is inert and never executes its command argument.

Setup writes the canonical workspace to `plugins.entries.ryk.config.workspaceRoot`. The adapter always discovers policy from that operator-controlled root and treats tool-supplied `cwd` only as action data. When identity binding becomes available, health will also require the canary to name the same configured workspace and return the exact Ryk denial marker (generic host denials and the inert executor sentinel fail). That proves the Gateway dispatcher and Ryk policy path for that workspace. It does not prove a model-selected agent turn. Native file-write tools remain denied by the unattended preset; use `ryk run -- openclaw` when the session needs Ryk-mediated staged changes.

The installer's adjacent SHA-256 receipt and the managed bundle receipt are integrity checks, not cryptographic signatures. They reject ordinary path, mode, symlink, and content substitutions and are revalidated at use or health time, but a same-user actor able to rewrite both an executable or adapter tree and its receipt is outside the trust claim.

### Sunset registry paths

Npm and ClawHub distribution paths are sunset and must not be used for new Mac mini/VPS deployments. Metadata/discovery passes are unprotected because OpenClaw does not provide live hook registration there. Existing installations should migrate to the curl installer plus `ryk agents setup openclaw`.

For historical packaging notes only, see [openclaw-clawhub.md](openclaw-clawhub.md).

### Build ryk

If you are installing from the ryk repository:

```bash
./scripts/zig build
```

## Verify install

### Plugin doctor

```bash
ryk plugin doctor openclaw
```

With JSON output:

```bash
ryk plugin doctor openclaw --json
```

Expected output sections:
- ryk version
- Policy status (present/valid)
- Plugin directories (openclaw: found)
- Host binaries (openclaw: detected or not detected)

For live runtime proof, also run:

```bash
openclaw plugins inspect ryk --runtime --json
openclaw gateway status --deep --require-rpc
ryk agents health openclaw --json
```

Older OpenClaw builds may not provide runtime inspection or the live plugin probe. In that case health remains not ready and the wrapper is the enforced fallback:

```bash
ryk run -- openclaw
```

OpenClaw 2026.8.1's status contract does not currently expose an authoritative running executable identity that Ryk can compare with the screened CLI. Until that upstream contract exists, Ryk deliberately keeps OpenClaw `ready=false` and requires the wrapper fallback; setup, plugin file presence, and the deferred dispatcher canary are not substitutes for identity binding.

### Plugin manifest

```bash
ryk plugin manifest openclaw
```

This reports the expected manifest path and existence status.

### Dry-run install

```bash
ryk plugin install openclaw --dry-run
```

### Hook smoke test

```bash
cat tests/plugin-fixtures/openclaw/tool_command_safe.json \
  | ryk hook openclaw tool.before
```

Expected: `allow` decision in valid JSON.

### Example decision command

```bash
ryk decide command --json '{"version":1,"host":"openclaw","command":"git status","mode":"strict"}'
```

### Run redteam

```bash
ryk redteam --ci
```

### Replay last session

```bash
ryk replay --session last --verify
```

## Hooks supported

Hooks call `ryk hook openclaw <event>` with a JSON payload on stdin. The following OpenClaw events are supported:

| OpenClaw Hook | ryk CLI Event | Description | Timeout |
|---------------|----------------|-------------|---------|
| `session_start` | `session.start` | Session initialization check | 10s |
| `before_tool_call` | `tool.before` | Tool use policy evaluation before execution | 15s |
| `after_tool_call` | `tool.after` | Post-tool acknowledgment and logging | 10s |
| `session_end` | `session.end` | Session end handling | 10s |

`before_tool_call` is the enforcement hook. Leftover unused policy `ask` is permit (allow) on the attended path — same coding-host wire as Grok. Unattended mode still maps leftover `ask` to a hard block. Explicit deny, stage, SoftBlock, and FM steward ask never become allow. Metadata/discovery and legacy passes do not enforce because their `api.on` is not proven live; use `ryk run -- openclaw` until the host reports an explicit full runtime.

### How hooks call ryk

Each hook sends a JSON payload to stdin and expects a JSON decision on stdout:

```bash
echo '{"version":1,"host":"openclaw","event":"tool.before","payload":{"tool":"shell","command":"git status","cwd":"/path/to/project"}}' \
  | ryk hook openclaw tool.before
```

Example with a fixture file:

```bash
cat tests/plugin-fixtures/openclaw/tool_command_safe.json \
  | ryk hook openclaw tool.before
```

## Uninstall

Remove the plugin from your OpenClaw configuration:

```bash
openclaw plugins uninstall ryk
```

This plugin does not mutate host configuration beyond the plugin file itself, so uninstalling is safe.

## Troubleshooting

### Plugin directory not found

Ensure you run `ryk plugin doctor openclaw` from the repository root or a project directory that contains the plugin. The doctor looks for `integrations/openclaw-plugin/`.

### Hooks timeout

If hooks exceed their timeout, OpenClaw may skip them. Check that `ryk` is in PATH and that `.ryk/policy.yaml` loads quickly.

### Policy not found

Run `ryk init --preset generic-agent` to create a default policy, then validate with `ryk policy check .ryk/policy.yaml`.

### ryk binary not found

Build ryk with `./scripts/zig build` or ensure `./zig-out/bin/ryk` is in your PATH.

### Fake secret redaction questions

The plugin uses synthetic test secrets in fixtures only. If you see redaction warnings about these values in test output, that is expected behavior.

## Limitations

- Hooks are advisory; enforcement depends on OpenClaw host support.
- The strongest protection is `ryk openclaw`.
- Plugin installation is a preview/dry-run by default.
- The plugin does not collect telemetry itself. Hook and machine-readable calls are excluded from release CLI telemetry; user-invoked CLI wrappers may record only the fixed pseudonymous metadata described in [`../telemetry.md`](../telemetry.md).
- Npm/ClawHub distribution is sunset; do not use registry packages for deployment.
- The OpenClaw plugin does not add MCP server behavior.
- OpenClaw uses the manifest id `ryk` for the native integration installed by the curl-based ryk workflow.

## Security model

- The ryk CLI is the source of truth.
- The plugin does not reimplement policy logic.
- No secrets are stored in plugin files.
- Hook stdout is host-valid JSON.
- Human logs go to stderr.
- CI mode never prompts.

## Plugin telemetry boundary

This plugin does not collect telemetry itself. Hook and machine-readable calls are excluded from release CLI telemetry. A user-invoked release CLI wrapper may record only the fixed pseudonymous metadata described in [`../telemetry.md`](../telemetry.md); it never transmits usage content, session content, command text, or tool payloads.

## No MCP behavior

This plugin does not add MCP server behavior.

# Local Dashboard

ryk includes a local-first web dashboard for machine-wide activity and workspace drill-down.

```sh
ryk dashboard
```

`ryk dashboard` now opens the machine-wide view by default. It is no longer tied to the shell's current working directory, so it can be started from `~` or any other directory.

Use an explicit workspace for policy, Secretless, integrations, and workspace-scoped actions:

```sh
ryk dashboard --workspace /path/to/project
```

`--machine` is an explicit alias for the default:

```sh
ryk dashboard --machine
```

Set `RYK_DASHBOARD_WORKSPACE` to make workspace mode the default for a shell or launcher:

```sh
export RYK_DASHBOARD_WORKSPACE=/path/to/project
ryk dashboard
```

An explicit `--workspace` or `--machine` flag takes precedence over the environment variable. `--workspace` and `--machine` cannot be combined.

By default it listens only on:

```text
http://127.0.0.1:7742
```

The dashboard is a local control surface over existing ryk behavior. It does not replace the CLI, does not evaluate policy in frontend code, and does not add dashboard-specific accounts, cloud sync, or external services. Release builds may send the fixed pseudonymous CLI telemetry described in [the telemetry contract](telemetry.md); the dashboard has no separate telemetry surface.

## Machine-Wide View

Machine-wide mode reads ryk's local workspace registry and global decision feed. It does not recursively scan `$HOME`.

- Registered workspaces and their most recently observed agent host
- Recent shell / policy decisions across Pi, Codex, Claude, OpenCode, `ryk run`, and other hook paths
- Sessions merged from registered workspace `.ryk/sessions` directories and feed-backed agent sessions such as Pi
- Denied shell decisions with `workspace_root`, `host`, and recording source
- Cloud Terminal stream (`ryk cloud` or `ryk dashboard --view terminal`) for blocked commands from ryk agent, Cursor Cloud, and host plugins
- Machine-wide daemon health

Decision writers continue to store the existing per-workspace feed and also append a redacted record to `$HOME/.ryk/dashboard/events.jsonl`. `$HOME/.ryk/dashboard/workspaces.json` indexes recently active workspaces for session aggregation. Feed writes are best-effort and do not change hook, run, or evaluate exit behavior. Crafted feed `session_id` or `workspace_root` values (`..`, extra separators) are skipped before any filesystem join; that is a loader skip, not a fail-closed policy deny.

Machine-wide mode exposes only the global action `ryk doctor`. Policy, replay, report, CI, credential, proxy, and integration actions stay hidden and are rejected server-side until the dashboard is started with an explicit workspace. This prevents ambiguous uses of `last` from `~`.

## Workspace View

- ryk version and workspace root
- CI readiness from the same checks as `ryk ci check`
- `.ryk/policy.yaml` presence, mode, and validation status
- Secretless runtime availability, broker-reference mode, service-policy templates, verification commands, guarantees, and limitations
- Productized policy packs that initialize through ryk policy code
- OpenClaw and Hermes setup cards with exact local commands
- Recent `.ryk/sessions` entries
- Denied actions from replay artifacts
- Event type, target, decision, policy context, rule/reason when recorded, and hash-chain verification status

## Local Actions

In workspace mode, the browser can run only fixed ryk actions:

```sh
ryk doctor
ryk policy check .ryk/policy.yaml
ryk plugin doctor openclaw
ryk plugin doctor hermes
ryk replay --session last --only denied --verify
ryk report --session last --format markdown
ryk ci check --format markdown
ryk explain "rm -rf /"
```

Policy edits are saved only after ryk parses and validates the submitted YAML. Preset initialization writes `.ryk/policy.yaml` from the same preset text used by the CLI. Policy routes return `workspace_required` in machine-wide mode.

## Secretless View

The Secretless tab is the operator surface for the Secret Boundary runtime.

It includes:

- Active broker status and whether raw secrets are stored or injected
- Credential reference rows derived from policy without raw values
- Broker check cards for configured brokers
- Proxy backend status, bind behavior, and HTTPS host/port-only limitation
- A generated `ryk run --secretless --network-backend proxy -- <custom-command>` command
- A GitHub service-policy template covering hosts, methods, allowed paths, denied paths, credential references, and `unmatched: deny`
- Fixed verification actions for credential checks, proxy smoke, policy check/explain, and replay verification
- A capability matrix for env replacement, broker checks, service policy, proxy backend, and transparent-interception status
- Broker extension-point cards for local dummy, Infisical / Agent Vault, 1Password CLI, macOS Keychain, and env-file development brokers
- Recent secret redaction and proxy request-level audit events from `.ryk/sessions`
- Guarantees and limitations so the UI does not imply vault behavior or transparent network interception

The generated command is copied or shown for terminal use. The dashboard does not execute arbitrary agent commands from the browser. The service-policy template can be inserted into the policy editor, but it is not persisted until the user clicks **Validate and save** and ryk accepts the YAML.

The dashboard’s fixed actions are allowlisted server-side: `credentials-check`, `credentials-check-github`, `proxy-smoke`, `policy-check`, `policy-explain-github`, `replay-last`, and the existing operational checks. `proxy-smoke` starts a local ryk proxy instance and forwards a fixed localhost request through it to verify forwarding plus request-level decision capture. Unsupported action IDs are rejected.

Mutation routes require a per-run browser token embedded in the dashboard page and the server rejects non-localhost bindings by default.

## Security Notes

Binding to non-loopback addresses (LAN or `0.0.0.0`) is not supported. The dashboard is intentionally localhost-only so a browser on the local machine cannot be turned into a remote command or open-proxy surface.

Use `ryk doctor` as the source of truth for platform capability claims. The dashboard should describe controls as active, limited, wrapper-only, observe-only, or unavailable based on ryk state; it must not imply transparent sandboxing or enforcement that ryk does not provide.

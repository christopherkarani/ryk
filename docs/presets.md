# Policy Presets

Presets live under `policies/presets/` and are plain YAML with comments. They are designed as editable starting points, not immutable security profiles.

Create a policy:

```bash
ryk init --preset generic-agent
ryk policy check .ryk/policy.yaml
```

Available presets:

- `generic-agent`: coding-agent day-to-day baseline (the default for `ryk init --preset` and `ryk start` / `start --auto`). **DCG-style:** `mode: strict` with an **empty** `commands.allow` (matrix-only — no `strict: not on allowlist` refuse) and `commands.default: allow` so normal shell work is not approval-gated. Packs + hard fence **block** high/critical danger; catastrophe deny patterns stay on. Network defaults to deny with a narrow allowlist; secret read denys remain expanded. Not ask-on-risk.
- `claude-code`, `codex`, `cursor-agent`, `opencode`, `cline-roo`, `solo-dev`, `mcp-dev`: same coding DCG body as `generic-agent` (host/product labels differ; mcp-dev notes stdio MCP manifest binding still required).
- `no-external-comms`: strict-local baseline plus effect-class denials for messaging, social publish, and payments (`comms.message`, `comms.publish`, `money.transfer`).
- `github-actions`: non-interactive CI baseline.
- `strict-local`: strict local baseline with a **sample** `commands.allow` permit list (off-list refuse when the host wires that list).
- `team-ci`: product policy pack for team CI baselines.
- `openclaw-hermes`: product policy pack for OpenClaw and Hermes hook workflows (**ask-mode** body — approval-capable; not the coding DCG path).
- `unattended`: strict permit-list fail-closed baseline for agents running without an operator. Commands outside the reviewed local-safe set are denied rather than waiting for approval.
- `trusted-local`: more permissive local baseline for trusted repositories; secret redaction and deny rules remain active.

For a dedicated Hermes/OpenClaw unattended setup, use:

```bash
ryk agents setup
ryk agents health --json
```

The preset is safe for a Mac mini, VPS, or other non-interactive host: commands outside the reviewed permit list are denied, and both adapters deny approval-class requests when `RYK_UNATTENDED=1` (or a host-specific unattended signal) is present. A successful file install is not proof that a long-running host has loaded the hook; restart the host and run `ryk agents health --json`.

Native host hooks deliberately deny file-write tools under this preset. `write_mode: staged` applies only when an operation runs through Ryk's mediated file path; a host-native write cannot be redirected into Ryk's staging area by policy alone. Run the agent through `ryk run -- ...` when it must make staged workspace changes.

Ryk does not currently generate launchd or systemd units. Use `ryk agents health --json` from an existing supervisor, cron, or monitoring service. Native service-unit generation remains a release gap rather than an implied setup side effect.

Productized policy packs can also be inspected and applied through the policy command:

```bash
ryk policy packs
ryk policy apply-pack solo-dev
ryk policy apply-pack team-ci --force
ryk policy apply-pack openclaw-hermes --force
```

All presets preserve:

- deny-priority semantics;
- secret redaction before persistence;
- staged writes for ryk-mediated writes;
- no real secrets in policy text;
- no external service dependency for policy validation.

Agent-specific presets are marked generic/experimental when ryk cannot verify proprietary agent internals. Binary detection in `ryk doctor` only reports presence in PATH; it does not prove an agent is configured safely.

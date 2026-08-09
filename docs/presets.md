# Policy Presets

Presets live under `policies/presets/` and are plain YAML with comments. They are designed as editable starting points, not immutable security profiles.

Create a policy:

```bash
ryk init --preset generic-agent
ryk policy check .ryk/policy.yaml
```

Available presets:

- `generic-agent`: conservative local coding-agent baseline (the default for `ryk init --preset` and `ryk start` / `start --auto`). The on-disk YAML documents the structure; the generated policy uses the stricter embedded variant (network default deny + expanded secret protections + **agents default command permit** — see the file header and `src/policy/presets.zig`). The permit is usable for agent shell work under strict refuse without blanket `python3 *` / `bash *` / `git *`; recovery commands (`ryk explain`, `ryk allow-once`) are included so agents cannot deadlock on the escape hatch.
- `claude-code`: generic/experimental local coding-agent assumptions for Claude Code-style use.
- `codex`: generic/experimental local coding-agent assumptions for Codex-style use.
- `cursor-agent`: generic/experimental local editor-agent assumptions.
- `opencode`: generic/experimental local coding-agent assumptions.
- `cline-roo`: generic/experimental local editor/MCP-agent assumptions.
- `mcp-dev`: stdio MCP development baseline with conservative tool defaults.
- `no-external-comms`: strict-local baseline plus effect-class denials for messaging, social publish, and payments (`comms.message`, `comms.publish`, `money.transfer`).
- `github-actions`: non-interactive CI baseline.
- `solo-dev`: product policy pack for local solo development with ask-mode defaults.
- `strict-local`: strict local baseline with denied unknown commands/network.
- `team-ci`: product policy pack for team CI baselines.
- `openclaw-hermes`: product policy pack for OpenClaw and Hermes hook workflows.
- `unattended`: strict permit-list fail-closed baseline for agents running without an operator. Commands outside the reviewed local-safe set are denied rather than waiting for approval.
- `trusted-local`: more permissive local baseline for trusted repositories; secret redaction and deny rules remain active.

For a dedicated Hermes/OpenClaw unattended setup, use:

```bash
ryk unattended setup --hosts hermes,openclaw
ryk unattended health --json
```

The preset is safe for a Mac mini, VPS, or other non-interactive host: commands outside the reviewed permit list are denied, and both adapters deny approval-class requests when `RYK_UNATTENDED=1` (or `RYK_OPENCLAW_UNATTENDED=1`) is present. A successful file install is not proof that a long-running host has loaded the hook; restart the host and run `ryk unattended health --json`.

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

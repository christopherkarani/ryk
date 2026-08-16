# ryk documentation

The docs describe the current CLI and its limits. When a platform detail matters, run `ryk doctor` on the machine that will run the agent.

## Start here

- [Install](install.md): source builds, checksum-verified curl installs, release archives, and platform notes.
- [Quickstart](quickstart.md): create a policy, launch an agent, inspect a session, and stop protection.
- [CLI reference](cli-reference.md): verified commands, output contracts, exit statuses, and integration boundaries.
- [Commands](commands.md): command guard, shims, session grades, and known bypasses.
- [Compatibility](compatibility.md): protection grades and the Linux, macOS, and Windows matrix.
- [Threat model](threat-model.md): assets, trust boundaries, and non-goals.

## Policy and runtime behavior

- [Policy reference](policy.md): modes, rules, priorities, effects, and examples.
- [Presets](presets.md): built-in policy presets and their assumptions.
- [Credentials](credentials.md): environment filtering, redaction, secret boundaries, and brokers.
- [Network](network.md): host decisions, proxies, and route-enforcement limits.
- [Filesystem staging](filesystem-staging.md): staged writes and review commands.
- [MCP](mcp.md): stdio proxying, manifests, and mediated methods.
- [Replay](replay.md): local audit records, redaction, and hash-chain verification.
- [Dashboard](dashboard.md): the localhost operator view.
- [Red-team fixtures](redteam.md): deterministic local security checks.

## Host integrations

- [Codex](integrations/codex.md)
- [Claude Code](integrations/claude-code.md)
- [OpenCode](integrations/opencode.md)
- [OpenClaw](integrations/openclaw.md)
- [Plugin compatibility](integrations/plugin-compatibility.md)
- [Plugin security model](integrations/plugin-security-model.md)
- [Plugin troubleshooting](integrations/plugin-troubleshooting.md)
- [Integration API](integrations/integration-api.md)
- [OpenClaw distribution notes](integrations/openclaw-clawhub.md)

## Examples and contribution

- [Launch path](quickstart.md)
- [Fixture layout](../fixtures/README.md)
- [Example projects](../examples/README.md)
- [Script reference](../scripts/README.md)
- [Release process](dev/release.md)
- [Dependency notes](dev/dependencies.md)
- [Binary size P4 (flags-only vs `ryk-dev`)](dev/binary-size-p4.md)

For security reports, read [SECURITY.md](../SECURITY.md). For code and documentation changes, read [CONTRIBUTING.md](../CONTRIBUTING.md).

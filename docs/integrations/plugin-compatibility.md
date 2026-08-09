# Plugin compatibility

The ryk CLI owns policy decisions. Host packages call the CLI and adapt its results to the host's hook or plugin API.

## Current surface

| Surface | CLI | Codex | Claude Code | OpenCode | OpenClaw |
|---|---|---|---|---|---|
| `plugin doctor` | native | calls CLI | calls CLI | calls CLI | calls CLI |
| `plugin manifest` | native | calls CLI | calls CLI | calls CLI | calls CLI |
| `plugin install --dry-run` | native | calls CLI | calls CLI | calls CLI | calls CLI |
| `decide` | native | calls CLI | calls CLI | calls CLI | calls CLI |
| `hook` | native | calls CLI | calls CLI | calls CLI | calls CLI |
| `redteam --ci` | native | calls CLI | calls CLI | calls CLI | calls CLI |
| `replay` | native | calls CLI | calls CLI | calls CLI | calls CLI |

None of the host packages adds MCP server behavior or telemetry.

## Host support

| Host | Integration in this repository | Important limitation |
|---|---|---|
| Codex | Plugin and hook configuration | Enforcement depends on the Codex hook surface and version. |
| Claude Code | Plugin and hook configuration | Enforcement depends on the Claude Code hook surface and version. |
| OpenCode | Plugin and hook configuration | OpenCode hooks must fire for a decision to affect a tool call. |
| OpenClaw | Plugin and hook configuration | Registry installs are sunset; use the curl-installed ryk binary plus `ryk unattended setup`. Metadata/discovery passes remain unprotected. |
| Cursor | Host discovery and preset support | Use the process wrapper when the host does not expose a blocking hook. |
| Pi, Hermes | Native ryk launchers | The launcher starts the host as a ryk-managed child process. |

The strongest protection for every host is the supervised process path:

```sh
ryk run -- <agent-command>
```

Hooks are useful integration points, but they cannot protect actions the host never sends to the hook.

## Versioning

The repository release version is `1.2.11`. Versioned plugin manifests in the tree are checked against `VERSION` during release verification. Keep the CLI and plugin packages aligned when preparing a release.

Official marketplace or registry availability is not recorded here. Check the relevant registry at release time instead of relying on a stale repository claim.

## Local package locations

- Codex: `integrations/codex-plugin/`
- Claude Code: `integrations/claude-code-plugin/`
- OpenCode: `integrations/opencode-plugin/`
- OpenClaw: `integrations/openclaw-plugin/`
- Hermes: `integrations/hermes-plugin/`

Start with the host-specific guides:

- [Codex](codex.md)
- [Claude Code](claude-code.md)
- [OpenCode](opencode.md)
- [OpenClaw](openclaw.md)
- [Plugin security model](plugin-security-model.md)

# OpenClaw plugin distribution (sunset)

Npm and ClawHub distribution for the OpenClaw integration is sunset. Do not use a registry package for a new deployment. The supported path is the checksum-verified curl installer followed by `ryk agents setup openclaw`; use `ryk run -- openclaw` when native runtime proof is unavailable.

## Validate the local package

The package lives at `integrations/openclaw-plugin/` and requires a separately installed `ryk` binary.

```sh
ryk doctor
npm run build --prefix integrations/openclaw-plugin
npm pack --dry-run ./integrations/openclaw-plugin
node -e "JSON.parse(require('fs').readFileSync('integrations/openclaw-plugin/openclaw.plugin.json'))"
```

Check the package contents before publishing. It should contain the compiled plugin, manifest, README, and package metadata. It should not contain install scripts, secrets, telemetry code, or MCP server configuration.

## Historical registry notes

Registry commands and publication status are intentionally out of the supported deployment contract. Keep this page only for historical package validation context; do not publish or recommend registry installs.

Keep the package version aligned with `VERSION`. Do not put credentials or registry tokens in this repository.

## Verify an installed package

```sh
ryk plugin doctor openclaw
ryk plugin manifest openclaw
ryk plugin install openclaw --dry-run
openclaw plugins list --json
```

For a hook smoke test from this repository:

```sh
cat tests/plugin-fixtures/openclaw/tool_command_safe.json \
  | ./zig-out/bin/ryk hook openclaw tool.before
```

For the enforcement boundary and known host limitations, read [the OpenClaw integration guide](openclaw.md) and [the plugin security model](plugin-security-model.md).

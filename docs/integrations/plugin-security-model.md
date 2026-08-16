# Plugin security model

Plugins are integration layers. They call the local ryk CLI; they do not reimplement policy decisions.

The strongest local protection is still the supervised process path:

```sh
ryk run -- <agent-command>
```

## Principles

1. The ryk CLI is the policy source of truth.
2. A hook must fail closed when it cannot produce a safe decision.
3. Installation previews changes before writing them.
4. Plugin commands do not print or persist raw secrets.
5. The plugin surface has no telemetry or hosted dependency.

## Trust boundaries

```text
Host agent or IDE
  -> host hook or plugin package
  -> ryk CLI
  -> local policy, audit, and decision engine
```

Host input, prompts, tool calls, and hook payloads are untrusted. The host can enforce only the events it exposes and actually delivers. A plugin is not a substitute for process supervision or an operating-system sandbox.

## Permission levels

| Level | Operation | Example |
|---|---|---|
| Read-only | Inspect local state | `ryk plugin doctor`, `ryk plugin manifest` |
| Preview | Show a proposed change | `ryk plugin install <host> --dry-run` |
| Mutate | Change host configuration | Requires `--yes` and explicit user approval |
| Actuate | Trigger an external effect | Not exposed by default |

The CLI does not silently overwrite host configuration. CI / unattended never prompts: residual `ask` hardens to deny. Attended coding hosts permit residual `ask` so agents can work. Explicit deny never becomes allow.

## Secret handling

- Do not print API keys, credentials, connection strings, or raw environment values.
- Do not store credentials in plugin-specific configuration.
- Do not forward secrets to a remote service.
- Use synthetic values in fixtures and rotate any real credential exposed during development.

## What this model does not promise

- Host hooks do not protect actions that bypass the host hook.
- Plugins do not protect against a user approving an unsafe action.
- Plugins do not protect against root, administrator, kernel, or host compromise.
- A package install is not evidence that enforcement is active. Run `ryk plugin doctor <host>` and use `ryk run -- ...` when process supervision is required.

See [the CLI plugin surface](ryk-cli-plugin.md), [compatibility](plugin-compatibility.md), and [troubleshooting](plugin-troubleshooting.md).

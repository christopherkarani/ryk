<p align="center">
  <img src="docs/images/ryk-banner.svg" alt="ryk, guardrails for coding agents" width="100%">
</p>

<p align="center">
  <a href="https://rykanv.com/">Website</a> ·
  <a href="https://discord.gg/uZn9MDUYKx">Discord</a> ·
  <a href="CONTRIBUTING.md">Contributing</a> ·
  <a href="SECURITY.md">Security</a>
</p>

<p align="center">
  <a href="README.zh-CN.md">简体中文</a> ·
  <a href="README.ur-pk.md">اردو</a> ·
  <a href="README.es.md">Español</a>
</p>

<p align="center">
  <a href="https://github.com/christopherkarani/ryk/actions/workflows/build.yml"><img src="https://img.shields.io/github/actions/workflow/status/christopherkarani/ryk/build.yml?label=build" alt="Build status"></a>
  <a href="https://github.com/christopherkarani/ryk/blob/main/LICENSE"><img src="https://img.shields.io/github/license/christopherkarani/ryk" alt="Apache 2.0 license"></a>
  <a href="https://github.com/christopherkarani/ryk"><img src="https://img.shields.io/github/stars/christopherkarani/ryk?style=flat" alt="GitHub stars"></a>
</p>

# ryk

Local guardrails for coding agents.

ryk runs the agents you already use with local checks for commands, files, secrets, network requests, MCP actions, and other effects. It returns an explicit `allow`, `ask`, `deny`, or `observe` decision and keeps session evidence on your machine.

If ryk is useful in your workflow, [star the repository](https://github.com/christopherkarani/ryk). It helps other engineers find the project.

## Install

```sh
curl -fsSL https://rykanv.com/install | sh
```

## Start an agent

`ryk <agent>` launches the host through a protected child session. ryk is macOS/Linux-first: it attaches the OS filesystem sandbox by default on those platforms (Seatbelt on macOS, Landlock on Linux). Windows sessions have no OS sandbox and run at wrapper/hook grade only. See the [compatibility matrix](docs/compatibility.md).

```sh
ryk <agent>
```


Scan past agent sessions for risky commands and secret-like exposure:

```sh
ryk scan
```

The installer prints the shell activation line for your platform. After `ryk` is on your `PATH`, check the local posture:

```sh
ryk doctor
```

## What you get

| | |
| --- | --- |
| Host integrations | Launch aliases for Pi, Hermes, OpenCode, Codex, Claude Code, OpenClaw, and Grok. Cursor is supported through host discovery and its shell hook. |
| OS sandboxing | Automatic OS filesystem sandboxing with Seatbelt on macOS and Landlock on Linux when available. Windows has no OS sandbox (wrapper/hook grade only). |
| Secret redaction | Secret-like values are redacted before audit and replay data is written. |
| MCP protection | MCP tool calls are classified locally, and supported stdio servers run through ryk's protected proxy. |
| 86 safety packs | Built-in command patterns for destructive and sensitive operations, with project-level opt-in packs. |
| Policy decisions | `allow`, `ask`, `deny`, and `observe` decisions for local actions. |
| Local evidence | A dashboard and replay commands for sessions, decisions, and audit records. |
| One local binary | The Zig CLI owns launch, evaluation, policy checks, host adapters, and diagnostics. |



### Supported hosts

| Host | Entry point | Integration point |
| --- | --- | --- |
| Pi | `ryk pi` | Bundled extension |
| Hermes | `ryk hermes` | `pre_tool_call` |
| OpenCode | `ryk opencode` | `tool.execute.before` |
| Codex | `ryk codex` | `PreToolUse` |
| Claude Code | `ryk claude` | `PreToolUse` |
| OpenClaw | `ryk openclaw` | `tool.before` |
| Grok | `ryk grok` | `PreToolUse` |
| Cursor | Host discovery and `cursor-agent` preset | `beforeShellExecution` |



## How policy works

ryk evaluates each guarded action locally. The main policy surfaces are:

| Surface | Examples |
| --- | --- |
| Commands | Shell commands, pipelines, redirects, and interpreters |
| Files | Workspace files, project control files, and sensitive paths |
| Environment | Inherited variables and secret access |
| Network | Host allowlists and mediated outbound connections |
| Tools | MCP and host tool calls mapped to effects |

The policy mode controls the response:

| Mode | Behavior |
| --- | --- |
| `observe` | Record decisions without blocking supported actions |
| `ask` | Prompt for risky actions when the host can resume them |
| `strict` | Deny unknown or risky actions unless a rule allows them |
| `ci` | Run strict behavior without prompts; `ask` becomes deny |

Explicit deny rules take priority. Safety packs classify commands and effects, but they do not grant permission past a deny rule.

Validate a built-in preset:

```sh
ryk policy check --preset ask
```

See the [policy reference](docs/policy.md) for policy files, priorities, and examples.

## Safety packs

Safety packs extend the shell evaluator with focused command coverage. Baseline packs such as `core.*` and `system.disk` are enabled by default.

```sh
ryk packs
ryk packs show core.git
ryk packs enable containers.docker database.postgresql
ryk packs disable containers.docker
```

In a Git workspace, project pack choices are stored in `.ryk.toml`. Use `ryk packs` for scripts and diagnostics.

Test or explain a command without running it:

```sh
ryk test "git status"
ryk test "rm -rf /" --format json
ryk explain "rm -rf /"
```

## Architecture

The launch aliases, host adapters, shell evaluator, and policy engine share one local decision path.

<p align="center">
  <img src="docs/images/ryk-architecture.svg" alt="ryk architecture from agent hosts through local policy to guarded effects and evidence" width="100%">
</p>

1. A launch alias starts the agent with ryk's session defaults.
2. Host adapters send shell and tool events to the evaluator.
3. The evaluator combines policy rules, safety-pack matches, and the active mode.
4. ryk allows, asks, observes, or denies the action.
5. The session records local evidence for the dashboard and replay commands.

## Dashboard

Start the localhost dashboard:

```sh
ryk dashboard
ryk cloud --demo
```

Open [http://127.0.0.1:7742](http://127.0.0.1:7742) for the dashboard, or [http://127.0.0.1:7742/#terminal](http://127.0.0.1:7742/#terminal) for the Cloud Terminal. Blocked commands from `ryk agent`, Cursor Cloud, and host plugins appear in that stream. The server is localhost-only by default and uses the existing ryk policy and CLI paths.

For smoke tests and automation, `--once` serves one request and then exits:

```sh
ryk dashboard --once
```

## Limits

ryk is graded mediation, not a universal OS sandbox. It is macOS/Linux-first. Windows sessions run at wrapper/hook grade with no OS sandbox. Absolute-path binaries, non-shimmed tools, non-proxy traffic, and host hooks that do not fire can sit outside a particular enforcement surface. `ryk doctor` reports platform capability; it does not prove that a child session attached to an OS sandbox, and it cannot promote Windows to `OS-enforced`. Read the [compatibility matrix](docs/compatibility.md) and [threat model](docs/threat-model.md) before making a stronger claim.

Release builds include opt-in product telemetry: nothing is collected or sent unless you run `ryk telemetry enable`. See [docs/telemetry.md](docs/telemetry.md) for the exact payload contract.

## Documentation

Start with the [documentation index](docs/README.md). The most useful guides are:

- [Install and release artifacts](docs/install.md)
- [Quickstart](docs/quickstart.md)
- [Commands](docs/commands.md)
- [Policy](docs/policy.md)
- [Credentials and secret handling](docs/credentials.md)
- [MCP](docs/mcp.md)
- [Platform notes](docs/platform-linux.md)
- [Windows platform](docs/platform-windows.md)

## Contributing

ryk is built with Zig 0.16.0. From a checkout:

```sh
./scripts/zig version
./scripts/compile-fast.sh check
./scripts/zig build test-shell-engine
```

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. For security issues, use [SECURITY.md](SECURITY.md).

## Community

- [Website](https://rykanv.com/)
- [Discord](https://discord.gg/uZn9MDUYKx)
- [GitHub issues](https://github.com/christopherkarani/ryk/issues)

## License

Apache 2.0. See [LICENSE](LICENSE).

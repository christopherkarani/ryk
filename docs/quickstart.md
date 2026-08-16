# Quickstart

Use the installed `ryk` command. For install methods, see [install.md](install.md).

## 1. Start protection

From the workspace you want protected:

```sh
ryk start
```

`ryk start` creates `.ryk/policy.yaml` when missing, wires detected hosts, and checks readiness. On an interactive terminal it asks which detected hosts to enable. It then prints next steps.

Non-interactive:

```sh
ryk start --auto
ryk start --auto --hosts claude,codex
```

## 2. Launch an agent

```sh
ryk claude
# or: codex | pi | opencode | openclaw | hermes | grok
```

Host aliases use the run engine with `--os-sandbox auto`; no `--os-sandbox` flag is required. The OS filesystem sandbox attaches when Seatbelt (macOS majors 14–26) or Landlock (ABI ≥ 3) can complete child apply-before-exec. `auto` degrades if no backend plan exists. Doctor probes are capability only.

Leftover unused policy ask is allow on coding hosts, including Claude, Codex, OpenCode, Pi, Hermes, Grok, and OpenClaw. There is no host ask UI. Unattended or CI hardens leftover ask to deny. Once / Session / Never is the `ryk run -- <command>` TTY prompt.

Session artifacts land under `.ryk/sessions/<session-id>/`. On a successful macOS Seatbelt attach the session banner includes `seatbelt_profile=hardened` (or the grade you chose).

Custom commands and CI automation still use the run engine:

```sh
ryk run -- echo hello
ryk run --ci -- ./scripts/agent-task.sh
```

Absolute paths, non-shimmed binaries, non-proxy traffic, and hooks that do not fire can sit outside a given enforcement surface. Grades: [compatibility.md](compatibility.md#protection-grades-canonical).

## 3. Check readiness

```sh
ryk doctor
```

`ryk doctor` reports policy, host integrations, capabilities, packs, and a recommended next step. Use `ryk doctor --check` in automation (non-zero when core readiness fails).

## 4. Replay the last session

```sh
ryk replay
```

Bare `ryk replay` loads the last session and highlights denied actions.

```sh
ryk replay --only denied
ryk replay --verify
ryk replay --list
```

`--verify` checks the tamper-evident hash chain. If there are no sessions yet, replay points you back to `ryk start` then `ryk <agent>`.

## 5. Stop protection

```sh
ryk stop
```

Removes host plugin registrations. Binary and policy stay. Restart later with `ryk start`.

## 6. Optional: explain and dashboard

Explain a destructive command without executing it:

```sh
ryk explain "rm -rf /"
```

Local dashboard:

```sh
ryk dashboard
```

Open `http://127.0.0.1:7742` for health, policy, sessions, and denials. Install does not start this UI.

See `ryk help --all` for CI, packs, and red-team.

## Next steps

- Full CLI surface: `ryk help --all`
- Policies: [policy.md](policy.md)
- Dashboard: [dashboard.md](dashboard.md)
- [Leaky-agent demo](../examples/leaky-agent-demo/README.md)
- MCP proxy: [mcp.md](mcp.md)
- Staged writes: [filesystem-staging.md](filesystem-staging.md)

# Quickstart (Safe Launch)

Protected agent in a few minutes. Taught path only — no parallel setup/quickstart doors.

## 1. Build Or Install

From a clean checkout:

```sh
./scripts/zig version   # must show 0.16.0
./scripts/zig build
./zig-out/bin/ryk version --json
```

The repository is pinned to Zig `0.16.0` (use `./scripts/zig` or `direnv allow` if system `zig` differs). After policy or CLI changes, run `./scripts/test-fast.sh`; run `./scripts/zig build test` before opening a PR. Release installs are covered in [install.md](install.md).

For a release install, use the checksum-verified curl installer in [install.md](install.md), then continue from step 2 with `ryk` (or `ryk` alias) on your `PATH`.

## 2. Get Protected

```sh
./zig-out/bin/ryk start
```

`ryk start` is the **only** onboarding door:

- creates `.ryk/policy.yaml` when missing (Ask on risk / `generic-agent` preset)
- wires host integrations
- verifies core readiness (daemon + policy)
- prints next steps: run an agent, then `doctor` / `scan` / `replay`

Non-interactive / CI-friendly:

```sh
./zig-out/bin/ryk start --auto
./zig-out/bin/ryk start --auto --hosts claude,codex
```

Public peers `ryk setup` / `ryk setup` and quickstart are removed — use `ryk start`. Power/CI scaffolding may still use advanced commands via `ryk help --all`.

## 3. Diagnose readiness

```sh
./zig-out/bin/ryk doctor
```

`ryk doctor` reports policy, host integrations, capabilities, packs, and a recommended next step. Use `ryk doctor --check` in automation (non-zero when core readiness fails).

## 4. Run A Protected Agent

Host aliases are the taught launch path (OS filesystem sandbox attaches automatically when the host supports it — no `--os-sandbox` flag required):

```sh
./zig-out/bin/ryk claude
# or: codex | pi | opencode | openclaw | hermes
```

When a risky action needs approval, interactive sessions offer **Once** / **Always** / **Never** (no rule ids required). Session artifacts land under `.ryk/sessions/<session-id>/`. On a successful macOS Seatbelt attach the session banner includes `seatbelt_profile=hardened` (or the grade you chose). Verify host capability with `ryk doctor` (capability ≠ live session).

Custom commands and CI automation still use the advanced run engine (not the day-1 agent launch path):

```sh
./zig-out/bin/ryk run -- echo hello
./zig-out/bin/ryk run --ci -- ./scripts/agent-task.sh
```

ryk is graded mediation, not a universal sandbox. Absolute paths, non-shimmed binaries, non-proxy traffic, and non-firing host hooks can still bypass. Canonical grades: [compatibility.md](compatibility.md#protection-grades-canonical).

## 5. Replay The Last Session

```sh
./zig-out/bin/ryk replay
```

Bare `ryk replay` loads the **last** session and highlights denied actions. Useful flags:

```sh
./zig-out/bin/ryk replay --only denied
./zig-out/bin/ryk replay --verify
./zig-out/bin/ryk replay --list
```

`--verify` checks the tamper-evident hash chain. If there are no sessions yet, replay points you back to `ryk start` then `ryk <agent>`.

## 6. Stop Protection

```sh
./zig-out/bin/ryk stop
```

Removes host plugin registrations; binary and policy stay. Restart later with `ryk start`.

## 7. Optional: Explain, Dashboard, CI, Red-team

Explain a destructive command without executing it (same shell engine hooks use):

```sh
./zig-out/bin/ryk explain "rm -rf /"
```

Local dashboard:

```sh
./zig-out/bin/ryk dashboard
```

Open `http://127.0.0.1:7742` for health, policy, sessions, and denials. Optional; uses existing CLI/Core paths.

CI readiness and packs (advanced):

```sh
./zig-out/bin/ryk policy packs
./zig-out/bin/ryk policy apply-pack team-ci --force
./zig-out/bin/ryk ci check --format markdown
```

Engine self-test fixtures (not your workspace policy):

```sh
./zig-out/bin/ryk redteam --ci
```

Safety reports are free (`ryk report`; export with `--format markdown|json`). See `ryk help --all` for the full command surface.

## Next Steps

- Full CLI surface: `ryk help --all`
- Policies: [policy.md](policy.md)
- Dashboard: [dashboard.md](dashboard.md)
- [Leaky-agent demo](../examples/leaky-agent-demo/README.md)
- MCP proxy: [mcp.md](mcp.md)
- Staged writes: [filesystem-staging.md](filesystem-staging.md)

# Troubleshooting

## Build Issues

Confirm Zig **0.16.0** (this repo pins that version):

```sh
./scripts/zig version   # must show 0.16.0
./scripts/zig build
```

If `./scripts/zig version` is not `0.16.0`, the failure is usually a **toolchain mismatch**, not a source bug.

```sh
./scripts/ensure-zig-toolchain.sh --install
eval "$(./scripts/ensure-zig-toolchain.sh --export)"   # or: direnv allow
./scripts/zig version
./scripts/zig build
```

Day-to-day verification after policy/CLI changes:

```sh
./scripts/compile-fast.sh       # fastest compile check (iteration)
./scripts/test-fast.sh          # full local gate (build + units + quick-install)
./scripts/test-fast.sh units    # units only (no quick-install)
./scripts/zig build test        # full suite before merge/CI
```

For repo builds, use the toolchain notes in `AGENTS.md`.

## Command Not Found

Install ryk or put the binary on `PATH`, then check it:

```sh
ryk version --json
```

## Policy Validation Errors

```sh
./zig-out/bin/ryk policy check .ryk/policy.yaml
```

Unknown keys, missing `version: 1`, invalid modes, and malformed rule lists fail validation.

## Denied Commands

Use:

```sh
./zig-out/bin/ryk policy explain command <command> [args...]
./zig-out/bin/ryk replay --session last --only denied
```

## Missing Backend Features

Run `ryk doctor`. If a feature is `limited`, `wrapper-only`, `observe-only`, or `unavailable`, docs and policies must treat it as weaker than active enforcement.

## Doctor vs session sandbox grade

`ryk doctor` reports host capability. It does not mean a live session is attached. Doctor will not show strong sandbox as `active` from a probe alone.

This session's enforcement class is `RYK_SESSION_SANDBOX_GRADE` and the banner `Session grade:` line (`strong-mediated`, `fs-attached`, `wrapper-only`, `unrestricted-escape`). See `docs/platform-macos.md` and `docs/commands.md`.

## Every Pi or Grok tool fail-closes with malformed JSON

If `echo`, `pwd`, `read`, and the deny-set all fail closed at once, the hook is probably calling a Zig **test** binary (or the Zig compiler) instead of product `ryk`. Doctor will show that host as `wired: broken` and say the hook is a test program.

**Fix** from a normal terminal, using the installed `ryk` (not `./scripts/zig` and not a zig-cache `test` binary):

```sh
ryk doctor --fix
```

Then restart Pi or Grok. If `ryk doctor --fix` itself says this process is a Zig test program, you are still running the wrong binary — use the path `ryk version` prints, typically `~/.local/bin/ryk`.

This is hook-grade repair. It is not OS-enforced.

## Pi tools fail with malformed JSON / evaluation errors

Protocol failures (timeout, malformed JSON, spawn failure, inconsistent exit) **fail closed for that tool call only**. Pi retries decide/evaluate **once** only for *transient* classes (`timeout`, `malformed_json`, `spawn_failed`, `output_too_large`, `inconsistent_exit`); schema-valid `decision: "error"` is not retried. Messages include a failure **class** token (e.g. `[malformed_json]`). After several consecutive protocol failures, Pi notifies **protocol degraded** once — still fail-closed per call, never silent allow. `allow-with-warning` soft-allows only `spawn_failed` (binary missing); other protocol classes still block. Retry the tool; if it persists, `/ryk-setup` then `/ryk-doctor`. Do not pass blanket `--ci` to interactive decide.

## Pi exits with `child.render is not a function`

A ryk block/ask card was sent and the installed Pi extension returned a colored **string** from `registerMessageRenderer`. Pi's TUI requires a component with `.render(width)`. The session then throws `TypeError: child.render is not a function` and exits.

**Fix:** update ryk-pi so the decision renderer returns `{ render(width) => string[] }`, then replace the installed copy:

```sh
ryk doctor --fix
# confirm ~/.pi/agent/extensions/ryk/runtime.ts is newer than the crash
```

Restart `ryk pi`. A stale `runtime.ts` from a previous install will keep crashing until it is replaced.

## Pi exits with `EPERM` mkdir `~/.local/state/ryk/pi-ask`

Under an attached OS sandbox (empty backpack), writes to `$HOME/.local/state` are denied. The ryk Pi extension used to `mkdirSync` that tree on `session_start` for parent-ask IPC. An uncaught `EPERM` exits Pi with code 1 after sandbox attach.

**Fix:** update ryk-pi so parent-ask mkdir is best-effort (no throw). Policy ask/block on the main TUI still works. Subagent parent-forward stays fail-closed if the IPC dir cannot be created. Replace `~/.pi/agent/extensions/ryk/parent_ask.ts` and `runtime.ts`, then restart `ryk pi`.

## Sandbox stress regression (P1–4)

After OS sandbox or network changes on a matrix host:

```sh
./scripts/zig build
./scripts/sandbox-stress-regression.sh
# or: ./scripts/sandbox-stress-regression.sh --binary ./zig-out/bin/ryk
```

Clean **SKIP** (exit 0) when Seatbelt/Landlock attach is unavailable. Exit 1 only on unexpected allows. Safe probes only (no exploit payloads). Distinct from fixture `ryk redteam --ci`.

## Tool not found vs EPERM under OS sandbox

Under attached sessions (`ryk pi`, `ryk claude`, `ryk run --os-sandbox on`, …):

| Symptom | Likely cause | What to do |
|---|---|---|
| `command not found` for `rg` / `fd` / `jq` | Tool not on host, or PATH honesty dropped an ungranted package dir | Install the tool, or use a system path; pack only grants files that exist. Set `RYK_TOOL_PACK=essentials` (default under attach). |
| `command not found` but tool lives under Homebrew | PATH denylist removed `/opt/homebrew/bin` so the agent does not see a lie | Either install into a kept prefix, rely on essentials pack file grant (pack re-adds the parent of a granted file), or accept absence |
| EPERM on absolute `/opt/homebrew/bin/...` | Absolute path bypasses shims; OS did not grant that file | Expected — no broad brew tree grants. Use essentials pack or do not invoke absolute brew paths |
| EPERM on `~/.ssh` / bare `$HOME` | Empty-backpack FS fence | Expected; do not request bare home grants |
| Shim name works but absolute path differs | Shims are **wrapper-only** | Absolute paths skip PATH shims; OS still enforces FS/network |

Inspect child labels when debugging: `RYK_PATH_FILTER=denylist`, `RYK_TOOL_PACK=essentials|none`.

## MCP Protocol Issues

Ensure server stdout is only newline-delimited JSON-RPC. Send human logs to stderr.

## Redaction Questions

ryk redacts before persistence. If you find a raw secret in `events.jsonl`, `summary.json`, `summary.md`, replay output, or red-team output, treat it as a security issue.

## Red-team Failures

Run a focused fixture:

```sh
./zig-out/bin/ryk redteam fixtures --fixture prompt-injection/readme-env-read --ci
```

Unsupported means the host lacks the required backend; it is not proof that the feature works.

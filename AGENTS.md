# AGENTS.md

## Cursor Cloud specific instructions

### What this repo is
`ryk` is a local-first guardrails runtime for AI coding agents. The product is a
single Zig binary (`./zig-out/bin/ryk`) that evaluates shell commands, file/network
access, and MCP tool calls locally and returns `allow` / `ask` / `deny` / `observe`
decisions. A bundled Next.js dashboard (`ryk-dashboard-ui/`) is served by the Zig
binary. There is **no database, no docker-compose stack, and no cloud service** — it
is entirely local.

### Toolchain (already installed by the startup update script)
- Zig `0.16.0` is pinned by `.zigversion`. Always invoke Zig through `./scripts/zig`
  (it exports the pinned toolchain from `~/.local/zig`). Do **not** use a system `zig`.
- Node `>= 22.6` is required for the dashboard UI (present on the VM).

### Build & run (not part of the update script)
- Build the CLI: `./scripts/zig build` → produces `./zig-out/bin/ryk` (Debug build by
  default; pass `-Doptimize=ReleaseSafe` for a release-style binary). First build is a
  few minutes because PCRE2 is compiled from source.
- Core "does it work" checks: `./zig-out/bin/ryk doctor`,
  `./zig-out/bin/ryk test "git status"` (→ allow),
  `./zig-out/bin/ryk test "rm -rf /"` (→ deny), `./zig-out/bin/ryk explain "<cmd>"`.
- First-run onboarding: `./zig-out/bin/ryk start --auto` (writes `.ryk/policy.yaml`).
- Dashboard: `./zig-out/bin/ryk dashboard` serves http://127.0.0.1:7742 (loopback only).
  `ryk dashboard --once` serves a single request and exits (good for smoke tests).

### Lint / static gate
- The canonical fast compile/lint gate is `./scripts/compile-fast.sh check`.
- Note: `npm run lint` (`next lint`) is **not configured** in `ryk-dashboard-ui` and
  will drop into an interactive ESLint setup prompt — do not rely on it in automation.
  The dashboard's real check is `npm test` (see below).

### Tests
- Shell engine (canonical): `./scripts/zig build test-shell-engine` — passes green.
- Dashboard contract tests: `cd ryk-dashboard-ui && npm test` — passes green.
- Full/fast Zig suites: `./scripts/zig build test-fast` and `./scripts/zig build test`.
  Also `./scripts/test-fast.sh`, `./scripts/verify-pre-merge.sh` (multi-minute).

### Known environment caveat (Zig 0.16 + Linux)
`./scripts/zig build test-fast` currently **aborts** on one unit test:
`Hermes bundle install rewrites stale name: orca source to name: ryk`
(`src/cli/plugin.zig`). Root cause: `syncDirectory` in `src/cli/plugin_install.zig`
calls `fsync()` on a directory handle that Zig 0.16 opens with `O_PATH`; `fsync` on an
`O_PATH` fd returns `EBADF` on Linux, and Zig's Debug IO backend turns that errno into a
`programmer bug ... EBADF` panic (SIGABRT), which stops the rest of that test binary.
This is a pre-existing repo/Zig-migration issue (it only panics in Debug builds and only
on the plugin-bundle install path), **not** an environment-setup problem. Core flows
(policy engine, `ryk start --auto`, dashboard) do not hit this path and work correctly.
Do not try to "fix the environment" for this — if you touch it, it's a product code
change. Note: the project's GitHub Actions have not run recently because the account is
locked for a billing issue, so CI cannot be used to confirm suite status.

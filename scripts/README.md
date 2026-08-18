# Scripts

The scripts assume you are at the repository root and use the pinned Zig wrapper at `./scripts/zig`.

## Build and test

| Goal | Command |
| --- | --- |
| Check the CLI compiles | `./scripts/compile-fast.sh check` |
| Pick a gate from changed paths | `./scripts/agent-gate.sh --dry-run` |
| Run a domain slice | `./scripts/test-slice.sh sandbox`, `policy`, or `intercept` |
| Run the shell evaluator and corpus | `./scripts/zig build test-shell-engine` |
| Run the default local product gate | `./scripts/test-fast.sh` |
| Run the full pre-merge gate | `./scripts/verify-pre-merge.sh` |

Use `./scripts/agent-gate.sh` when you are unsure which check fits the change. It selects a gate from staged and unstaged paths; `--dry-run` prints the selection without running it.

## Installation and release

- `install.sh` and `install.ps1` install the CLI and runtime assets.
- `build-release.sh` creates checksum-covered archives for the supported targets.
- `verify-release.sh` checks archives, manifests, checksums, and version alignment.
- `release-dry-run.sh` builds and verifies a host archive without publishing it.
- `cut-release.sh` is the maintainer release orchestrator. Read [the release guide](../docs/dev/release.md) before using its live mode.
- `test-release-signing.sh` always asserts `cut-release.sh` dispatches `sign)`. When a verifier is present it also proves the provisioned-key installer path refuses a release it cannot authenticate (tampered, forged, wrong-key, or missing signature). Uses a throwaway keypair, never the release key. Current shipping is sentinel / checksum-only. Runs inside `verify-pre-merge.sh`; see [release signing](../docs/release-signing.md).
- `update-homebrew-tap.sh` regenerates the Homebrew formula from a release's `checksums.txt` and, with `--live`, pushes the tap once it exists. `cut-release.sh` calls it in the `publish-brew` phase; run it by hand only to repair a stale channel. The public tap is not published yet.

The release scripts write archives and generated metadata under ignored `dist/` or `dist-dry-run/` directories. Do not commit those outputs.

## Other useful checks

- `check-fixture-secrets.sh` rejects non-synthetic secret patterns.
- `validate-docs.sh` checks documentation links, example policies, and the deterministic demo.
- `os-sandbox-adversarial-e2e.sh` runs the OS sandbox fixture probes when the platform can attach the backend.
- `host-live-e2e.sh` exercises every supported ryk veto envelope (`ryk hook` / `evaluate` / bare stdin). Host CLIs are optional. Cursor uses bare stdin; there is no first-class launch alias.
- `harness-stress.sh` prints allow/deny wire shapes for every ryk host envelope, including the blocked command.
- `quick-install-dx-verify.sh` exercises the first-run CLI setup matrix.
- `test-openclaw-release-assets.sh` proves committed OpenClaw `dist/` is present, then compares it to TypeScript when plugin `tsc` is installed. Without `tsc` it skip-passes freshness unless `RYK_RELEASE_LIVE=1` (then missing `tsc` or stale `dist/` fail-closes). `agent-gate` invokes the script when `integrations/openclaw-plugin/**` is dirty. Backup `release.yml` runs plugin `npm ci` then the script so live CI can compare; Mac `cut-release.sh` does not install plugin deps. `test.yml` has no dedicated job; `zig-full` dry-run may still reach the script and skip freshness without `tsc`.
- `test-homebrew-formula.sh` checks the Homebrew formula offline (pins `VERSION`, digest markers intact, automation fails closed without mutating the formula). Runs inside `verify-pre-merge.sh`.

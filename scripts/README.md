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
- `test-release-signing.sh` proves the installer refuses a release it cannot authenticate (tampered, forged, wrong-key, or missing signature). Uses a throwaway keypair, never the release key. Runs inside `verify-pre-merge.sh`; see [release signing](../docs/release-signing.md).

The release scripts write archives and generated metadata under ignored `dist/` or `dist-dry-run/` directories. Do not commit those outputs.

## Other useful checks

- `check-fixture-secrets.sh` rejects non-synthetic secret patterns.
- `validate-docs.sh` checks documentation links, example policies, and the deterministic demo.
- `os-sandbox-adversarial-e2e.sh` runs the OS sandbox fixture probes when the platform can attach the backend.
- `quick-install-dx-verify.sh` exercises the first-run CLI setup matrix.
- `test-openclaw-release-assets.sh` proves committed OpenClaw `dist/` matches TypeScript. `agent-gate` runs it when `integrations/openclaw-plugin/**` is dirty (plugin gate); release packaging also runs it.

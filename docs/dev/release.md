# Release

## Primary path: curl installer

Ship from a clean `main` on a Mac using **`scripts/cut-release.sh`**. The only
published channel is the GitHub Release consumed by the curl installer.

Full guide: [`cut-release-shortcut.md`](cut-release-shortcut.md).

```sh
./scripts/cut-release.sh --version 1.2.10 --plan-only   # preview
RYK_POSTHOG_PROJECT_TOKEN="<release-project-token>" ./scripts/cut-release.sh --version 1.2.10 --live
```

Release builds require the public PostHog project token in
`RYK_POSTHOG_PROJECT_TOKEN`. A live build also needs Docker for the Linux
artifacts and `gh` access to publish the GitHub Release. npm is used only to
build the dashboard when its local `dist/` directory is absent; no npm package
is published. Homebrew and other package-manager channels are not part of the
release.

What it does:

1. Checks clean `main`, Docker, `gh`, the Zig pin, and the telemetry token.
2. Bumps the version and writes release notes.
3. Runs `./scripts/verify-pre-merge.sh`.
4. Builds the macOS, Linux, and Windows CLI archives.
5. Verifies checksums, SBOM, telemetry contract, and release manifest.
6. Creates the GitHub Release with the assets required by `curl | sh`.

CI `release.yml` is a backup path. It skips when the complete curl installer
asset set is already attached to the tag's GitHub Release.

## Lower-level scripts

| Script | Role |
|--------|------|
| `scripts/build-release.sh` | Build CLI archives, checksums, SBOM, and release manifest |
| `scripts/build-linux-release-docker.sh` | Stage Linux `ryk` bins for Mac hosts |
| `scripts/verify-release.sh` | Verify the curl installer artifact contract |
| `scripts/stage-release-payload.sh` | Stage only Git-tracked runtime files |
| `scripts/check-release-payload-secrets.sh` | Reject credential-shaped content from staged and archived payloads |
| `scripts/release-dry-run.sh` | Host-only dry-run build and verify |

## Product notes

Keep the Zig version pinned (`.zigversion`). Generated release archives, SBOMs,
and checksums under `dist/` are not committed.

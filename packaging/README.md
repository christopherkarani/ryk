# Packaging inputs

The canonical binary is `ryk`. Release artifacts use the form
`ryk-v{version}-{os}-{arch}` and are published on GitHub for the checksum-
verified curl installer.

The `packaging/` tree contains build and container inputs used by the release
build.

## Channel decisions (2026-08-13)

**WinGet and Scoop stay deferred pending a Windows story.** Windows has no
OS-enforced session-attach (`src/sandbox/windows.zig`), so Windows sessions run at
wrapper/hook grade only — see [`docs/platform-windows.md`](../docs/platform-windows.md)
and [`docs/compatibility.md`](../docs/compatibility.md). Shipping a Windows
package manager entry would market protection the platform cannot enforce.
`packaging/winget/` and `packaging/scoop/` remain legacy templates and are not
wired into `cut-release.sh` publishing.

Use `scripts/cut-release.sh` for the supported release path. Read
[`docs/dev/release.md`](../docs/dev/release.md) first.

```sh
./scripts/cut-release.sh --version X.Y.Z --plan-only
```

# Packaging inputs

The canonical binary is `ryk`. Release artifacts use the form
`ryk-v{version}-{os}-{arch}` and are published on GitHub for the checksum-
verified curl installer.

Use `scripts/cut-release.sh` for the supported release path. Read
[`docs/dev/release.md`](../docs/dev/release.md) first.

```sh
./scripts/cut-release.sh --version X.Y.Z --plan-only
```

## Channel decisions (2026-08-13)

| Channel | Status | Notes |
| --- | --- | --- |
| curl installer | **live** | `scripts/install.sh`; checksum-verified. Working public path on macOS and Linux. |
| Homebrew (tap) | **ready, tap not published yet** | Formula is real (`packaging/homebrew/`). `christopherkarani/homebrew-ryk` is 404. Blocked until the tap exists. |
| Docker | build input | `packaging/docker/` is used by the release build, not a user channel. |
| npm | **deferred** | Not published. |
| WinGet | **deferred** | Legacy template; blocked on the Windows story. |
| Scoop | **deferred** | Legacy template; blocked on the Windows story. |

**Homebrew is ready but blocked** on publishing the tap. Do not `brew tap
christopherkarani/ryk` until `christopherkarani/homebrew-ryk` exists. Until
then, install with the curl installer. The formula ships the binary only;
`ryk doctor --fix` wires host plugins. Unlike the curl installer, `brew install`
does not wire host hooks — Homebrew's post-install step runs with a temporary
`HOME`, so onboarding there would configure nothing. The formula is regenerated
by release automation — see [`homebrew/README.md`](homebrew/README.md).

**npm is deferred** until a demand trigger fires: users ask for it, a corporate
environment blocks `curl | sh`, or post-deadlock retention justifies the second
channel. `packaging/npm/` stays as a template. Do not publish it without a
product decision.

**WinGet and Scoop stay deferred pending a Windows story.** Windows has no
OS-enforced session-attach (`src/sandbox/windows.zig`), so Windows sessions run at
wrapper/hook grade only — see [`docs/platform-windows.md`](../docs/platform-windows.md)
and [`docs/compatibility.md`](../docs/compatibility.md). Shipping a Windows
package manager entry would market protection the platform cannot enforce.
`packaging/winget/` and `packaging/scoop/` remain legacy templates and are not
wired into `cut-release.sh` publishing.

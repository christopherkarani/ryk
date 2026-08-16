# Install

## Recommended: curl installer

```sh
curl -fsSL https://rykanv.com/install | sh
```

This is the working public install path on macOS and Linux. ryk is
macOS/Linux-first. Windows can run the CLI, but sessions there have no OS
sandbox and stay at wrapper/hook grade — see [Windows Notes](#windows-notes)
and the [compatibility matrix](compatibility.md).

npm, WinGet, and Scoop are not published — see
[`packaging/README.md`](../packaging/README.md).

## Homebrew (ready, tap not published yet)

The formula in [`packaging/homebrew/`](../packaging/homebrew/) is real and
release-ready, but the public tap (`christopherkarani/homebrew-ryk`) is **not
published yet**. `brew tap christopherkarani/ryk` will 404 until that repo
exists. Until then, use the curl installer above.

When the tap is published:

```sh
brew tap christopherkarani/ryk
brew install ryk
ryk doctor --fix    # wire host hooks; nothing is gated until you run this
ryk doctor
```

`brew upgrade ryk` replaces the binary only. Run `ryk doctor --fix` afterwards
to refresh managed host plugins. Unlike the curl installer, `brew install` does
**not** wire host hooks — Homebrew's post-install `HOME` is temporary.

## Build From Source

```sh
./scripts/zig version   # must print 0.16.0
./scripts/build-all.sh  # or: ./scripts/zig build
./zig-out/bin/ryk version --json
```

Use Zig `0.16.0` (see `.zigversion`; prefer `./scripts/zig`). The product CLI is Zig-only: shell evaluation runs in-process via `shell_engine` (no Rust toolchain or `ryk-daemon` companion). `./scripts/build-all.sh` and `./scripts/zig build` both produce `./zig-out/bin/ryk`.

## Release Artifacts

Release helpers build checksum-covered **ryk** archives into `dist/`:

```sh
RYK_POSTHOG_PROJECT_TOKEN="<release-project-token>" ./scripts/build-release.sh
(cd dist && shasum -a 256 -c checksums.txt)
```

The release token is embedded as a public project identifier, not a user credential. For local archive and layout checks where telemetry transport must remain disabled, set `RYK_TELEMETRY_BUILD_DISABLED=1` instead.

Windows archive smoke-test helper:

```powershell
$env:RYK_TELEMETRY_BUILD_DISABLED = "1"
.\scripts\build-release.ps1 -ArchiveOnly
.\scripts\install.ps1 -Version 1.2.9 -ArtifactDir .\dist -InstallDir "$env:USERPROFILE\bin"
```

`scripts/build-release.ps1` does not produce `release-manifest.json`. Use `scripts/build-release.sh` plus `scripts/verify-release.sh` for production release verification.

Do not use an install-only path without verification. Download the archive, verify `dist/checksums.txt`, inspect the install script if using it, then install.

## Manual Artifact Install

1. Download or build the archive for your OS and CPU.
2. Verify its SHA-256 digest against `dist/checksums.txt`.
3. Extract the archive, or run `scripts/install.sh` / `scripts/install.ps1` to install the binary and runtime assets together.
4. Open a new shell so `PATH` includes the install dir, then run `ryk claude` (or the host you use). The installer writes the profile `PATH` entry and runs `ryk doctor --fix --from-install` to configure protection.

### Updating

If you installed with Homebrew:

```sh
brew update && brew upgrade ryk
ryk doctor --fix    # refresh managed host plugins after the upgrade
```

If you installed via the curl installer (`~/.local/bin/ryk`):

```sh
ryk update          # confirm + upgrade to latest
ryk update --check  # report only
ryk update --yes    # non-interactive
```

`ryk update` reuses the official curl installer (checksums + atomic replace). Use `ryk update --force` only when you intentionally want to override the normal release check. After the binary is replaced, the installer runs `ryk doctor --fix --from-install`, which refreshes managed host plugins (for example OpenCode `ryk.ts`, Codex/Claude marketplace plugins, and ryk-owned Hermes trees) so stale plugin files are upgraded in place without a manual delete.

The installers print a step-based receipt (brand header, phases, optional one-line host hint). They honor `NO_COLOR` and `RYK_INSTALL_QUIET=1` (non-error silence) and run the canonical `doctor --fix --from-install` setup door.

Windows (`scripts/install.ps1`) is **checksum-only (unsigned)**: it verifies
SHA-256 against `checksums.txt` and does not consume `checksums.txt.minisig`.
It shares the other core contracts (binary + runtime install, structured
failures, quiet mode, optional host hint) with a smaller surface: it does not
manage `PATH` (use your profile / user PATH) and does not soft-warn on a missing
dashboard UI bundle.

## Verifying a release

Signing is not yet active. `keys/ryk-release-minisign.pub` ships the sentinel
`RYK_RELEASE_PUBKEY_UNPROVISIONED`. Until a real key is provisioned,
`scripts/install.sh` reports `not yet active for this release` and continues on
SHA-256 only. `scripts/install.ps1` is checksum-only (Windows unsigned).

After provisioning, every release will publish `checksums.txt` (SHA-256 for each
artifact) and `checksums.txt.minisig`, an Ed25519 signature over that file in
[minisign](https://jedisct1.github.io/minisign/) format. One signature over the
checksums authenticates every artifact. Manual verification:

```sh
V=X.Y.Z
B="https://github.com/christopherkarani/ryk/releases/download/v$V"
curl -fsSLO "$B/checksums.txt" -O "$B/checksums.txt.minisig"
minisign -V -p keys/ryk-release-minisign.pub -x checksums.txt.minisig -m checksums.txt
shasum -a 256 -c checksums.txt --ignore-missing
```

Once the key is provisioned, `scripts/install.sh` will refuse a release whose
signature is missing or does not verify. If neither `minisign` nor `rsign` is
installed it will stop with instructions rather than skipping the check; you can
explicitly accept checksum-only trust with `RYK_INSTALL_ALLOW_UNSIGNED=1`, which
prints a visible `SKIPPED` line. That fail-closed path is **not** current
shipping behavior.

What signing does and does not protect — in particular that `curl … | sh` still
trusts whoever served the script — is spelled out in
[`release-signing.md`](release-signing.md).

## Release channel

The working public path is the checksum-verified curl installer. Homebrew is
ready but the tap is not published yet — see
[Homebrew](#homebrew-ready-tap-not-published-yet). The curl installer:

```sh
curl -fsSL https://rykanv.com/install | sh
```

It downloads the matching GitHub Release archive, verifies `checksums.txt`,
and installs the CLI and runtime assets. The installer runs
`ryk doctor --fix --from-install`, which creates a coding default policy
under `$HOME/.ryk/policy.yaml` and seeds the runtime user fallback at
`~/.config/ryk/policy.yaml` (create-only; never overwrites). `ryk <agent>`
loads that user path when a project has no local `.ryk/policy.yaml`. The
`packaging/` directory contains build and container inputs. It is not a
user installation channel.

## macOS Notes

macOS sessions can attach Seatbelt OS filesystem isolation through `ryk <agent>` (advanced flag: `ryk run --os-sandbox auto|on|off`) on macOS 14–26. macOS builds also provide process supervision, environment filtering, staged writes, PATH/shell shims, MCP stdio proxying, audit/replay, and network policy decisions. Proxy route forcing is available per session when the proxy backend and OS sandbox attach are both active. Proxy startup alone is not route forcing. CI attach evidence is linux amd64 (Landlock). Seatbelt attach is local. `ryk doctor` capability probes are not a live session claim. Session attach is proven only after the child sandbox applies before exec succeeds.

## Linux Notes

Linux builds detect namespace, seccomp, Landlock, cgroup, and process supervision capability. OS filesystem isolation for protected agent children is available through the run engine (`ryk <agent>`; advanced flag: `ryk run --os-sandbox auto|on|off`) using Landlock when the host supports **ABI ≥ 3** (kernel **6.2+**). ABI 1/2 lack truncation mediation, so they do not attach; `--os-sandbox on` fails closed below that floor. CI attach evidence is linux amd64. Other cells are local until freeze jobs exist. Doctor Landlock probes are capability evidence only. They do not authorize a session `active` claim.

## Windows Notes

ryk is macOS/Linux-first. Windows sessions run at **wrapper/hook grade** with **no OS sandbox**. There is no Seatbelt, Landlock, AppContainer, or Windows Filtering Platform session-attach backend; `src/sandbox/windows.zig` reports `strong_sandbox` unavailable. Doctor cannot promote a Windows session to `OS-enforced`. MCP stdio is **proxy** grade.

Windows builds use `ryk.exe`, PowerShell scripts, path normalization, command wrappers, staged writes, and process cleanup support where implemented. Transparent filesystem enforcement is unavailable (ryk-mediated staging and protected-path matching still run). Transparent network enforcement and proxy-mediated HTTP are unavailable (no loopback proxy).

`scripts/install.ps1` is checksum-only (Windows unsigned): it verifies SHA-256
against `checksums.txt` and does not read `checksums.txt.minisig`.

See the [compatibility matrix](compatibility.md) and [Windows platform notes](platform-windows.md). WinGet and Scoop are not published; they stay deferred pending a Windows story ([packaging/README.md](../packaging/README.md)).

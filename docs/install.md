# Install

ryk is macOS/Linux-first. The supported install path is the checksum-verified
curl installer on those platforms. Windows can run the CLI, but sessions there
have no OS sandbox and stay at wrapper/hook grade — see [Windows Notes](#windows-notes)
and the [compatibility matrix](compatibility.md).

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
4. Paste the activation command printed by the installer (the highlighted `eval "$(… env …)"` block on Unix). It invokes the absolute installed binary, so it also works in the shell that launched a first-time install before `ryk` is on `PATH`. The installer runs `ryk doctor --fix --from-install` to configure protection.

### Updating

If you installed via the curl installer (`~/.local/bin/ryk`):

```sh
ryk update          # confirm + upgrade to latest
ryk update --check  # report only
ryk update --yes    # non-interactive
```

`ryk update` reuses the official curl installer (checksums + atomic replace). Use `ryk update --force` only when you intentionally want to override the normal release check. After the binary is replaced, the installer runs `ryk doctor --fix --from-install`, which refreshes managed host plugins (for example OpenCode `ryk.ts`, Codex/Claude marketplace plugins, and ryk-owned Hermes trees) so stale plugin files are upgraded in place without a manual delete.

The installers print a step-based receipt (brand header, phases, activation hero). They honor `NO_COLOR` and `RYK_INSTALL_QUIET=1` (non-error silence; activation line still printed) and run the canonical `doctor --fix --from-install` setup door.

Windows (`scripts/install.ps1`) shares the same core contracts (checksum verify, binary + runtime install, structured failures, quiet mode, activation handoff) with a smaller surface: it does not manage `PATH` (use your profile / user PATH) and does not soft-warn on a missing dashboard UI bundle.

## Verifying a release

Every release publishes `checksums.txt` (SHA-256 for each artifact) and
`checksums.txt.minisig`, an Ed25519 signature over that file in
[minisign](https://jedisct1.github.io/minisign/) format. One signature over the
checksums authenticates every artifact.

```sh
V=X.Y.Z
B="https://github.com/christopherkarani/ryk/releases/download/v$V"
curl -fsSLO "$B/checksums.txt" -O "$B/checksums.txt.minisig"
minisign -V -p keys/ryk-release-minisign.pub -x checksums.txt.minisig -m checksums.txt
shasum -a 256 -c checksums.txt --ignore-missing
```

The installer does this for you and **refuses to install** a release whose
signature is missing or does not verify. If neither `minisign` nor `rsign` is
installed it stops with instructions rather than skipping the check; you can
explicitly accept checksum-only trust with `RYK_INSTALL_ALLOW_UNSIGNED=1`, which
prints a visible `SKIPPED` line.

Signature enforcement activates once the release signing key is provisioned;
until then the installer reports `not yet active for this release` and verifies
SHA-256 as before. What signing does and does not protect — in particular that
`curl … | sh` still trusts whoever served the script — is spelled out in
[`release-signing.md`](release-signing.md).

## Release channel

The supported install path is the checksum-verified curl installer:

```sh
curl -fsSL https://rykanv.com/install | sh
```

It downloads the matching GitHub Release archive, verifies `checksums.txt`,
installs the CLI and runtime assets, and prints the activation command. The
installer runs `ryk doctor --fix --from-install`, which creates a coding
default policy under `$HOME/.ryk/policy.yaml` and seeds the runtime user
fallback at `~/.config/ryk/policy.yaml` (create-only; never overwrites). That
user path is what `ryk <agent>` loads when a project has no local
`.ryk/policy.yaml` — without it, uninited directories fell back to
`builtin:strict` and could block host launches. The `packaging/` directory
contains build and container inputs; it is not a user installation channel.

## macOS Notes

macOS builds provide process supervision, environment filtering, staged writes, PATH/shell shims, MCP stdio proxying, audit/replay, and network policy decisions. Proxy route forcing is available per session when the proxy backend and OS sandbox attach are both active; proxy startup alone is not route forcing. OS filesystem isolation for protected agent children is available through the run engine (`ryk <agent>`; advanced flag: `ryk run --os-sandbox auto|on|off`) using Seatbelt on product majors **14–26** (capability/version gate). **CI attach evidence** is currently **macos-14** (plus Linux amd64 for Landlock); other majors are local until freeze CI covers them. Doctor capability probes are not a live session claim; session-attach is proven only after child apply-before-exec succeeds.

## Linux Notes

Linux builds use backend detection for namespace, seccomp, Landlock, cgroup, and process supervision capability. OS filesystem isolation for protected agent children is available through the run engine (`ryk <agent>`; advanced flag: `ryk run --os-sandbox auto|on|off`) using Landlock when the host supports **ABI ≥ 1** (kernel **5.13+**). **CI attach evidence** is currently **linux amd64**; other cells are local until freeze jobs exist. Doctor Landlock probes are capability evidence only and never alone authorize a session `active` claim. `--os-sandbox on` fails closed when attach cannot complete.

## Windows Notes

ryk is macOS/Linux-first. Windows sessions run at **wrapper/hook grade** with **no OS sandbox**. There is no Seatbelt, Landlock, AppContainer, or Windows Filtering Platform session-attach backend; `src/sandbox/windows.zig` reports `strong_sandbox` unavailable. Doctor cannot promote a Windows session to `OS-enforced`. MCP stdio is **proxy** grade.

Windows builds use `ryk.exe`, PowerShell scripts, path normalization, command wrappers, staged writes, and process cleanup support where implemented. Transparent filesystem enforcement is unavailable (ryk-mediated staging and protected-path matching still run). Transparent network enforcement and proxy-mediated HTTP are unavailable (no loopback proxy).

See the [compatibility matrix](compatibility.md) and [Windows platform notes](platform-windows.md). WinGet and Scoop are not published; they stay deferred pending a Windows story ([packaging/README.md](../packaging/README.md)).

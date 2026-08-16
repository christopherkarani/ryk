# Dependency notes

Dependency changes should be reviewed for provenance, license, input handling, and release impact. Pin exact sources and hashes in `build.zig.zon` or the package lockfile.

## Zig packages

- [libvaxis](https://github.com/rockorager/libvaxis) is pinned to commit `ca781b3c01f44a92e5331652823b5a9ce445be96` for terminal capability detection and interactive widgets. Default `zig build` / PATH `ryk` keeps TUI (`-Dtui` defaults true). `-Dtui=false` is a slim profile that must not fetch or link vaxis/uucode. Prove a ReleaseSafe slim `ryk` with `./scripts/check-slim-tui-symbols.sh` (wired from `verify-pre-merge.sh`, not test-fast).
- [uucode](https://github.com/jacobsandlund/uucode) is pinned in `build.zig.zon` as a lazy root dep so a TUI-on checkout resolves Unicode without a vendored cache. Both vaxis and uucode are `.lazy = true`.
- [PCRE2](https://github.com/PCRE2Project/pcre2) 10.48 is pinned at `5a632d3` and statically linked for the in-process Zig shell evaluator. ryk does **not** link upstream's `pcre2/build.zig` artifact (no flag to drop UNICODE/UCD/DFA/substitute). `build/pcre2_slim.zig` is the documented fork of that build: `SUPPORT_UNICODE=false`, JIT off, DFA/substitute/convert/serialize/UTF helpers omitted. See [`pcre2-slim.md`](pcre2-slim.md).
- HTTP/TLS (`std.http.Client`) lives in `telemetry_transport.zig` and `intercept/provider_gateway.zig`. Default `zig build` / PATH / curl|sh keeps both (`-Dhttp` defaults true; live releases set a PostHog token). `-Dhttp=false` omits those modules so TLS is not linked. Shared types live in `provider_gateway_types.zig` (no `std.http`) so the slim stub cannot copy `Limits` / audit shapes. `./scripts/zig build check-http-slim` runs the stub fail-closed tests; `./scripts/zig build -Dhttp=false check` compiles the full CLI against those stubs. Empty-token dry-run does not shrink the token-present release binary. Isolation of the two constructors alone is a size no-op. Post-P0–P3 size vs the 1.8–2.5 MiB floor, unwind/panic notes, and the flags-only vs optional `ryk-dev` recommendation are in [`binary-size-p4.md`](binary-size-p4.md). P4 did not land a second shipped binary.

The package hashes in `build.zig.zon` are part of the build contract. Do not replace them with floating versions or a system library search path.

## Dashboard build dependencies

`ryk-dashboard-ui/` uses Next.js, React, TypeScript, Tailwind CSS, and presentation libraries at build time. The generated static bundle is served by the local Zig dashboard; these Node packages are not linked into the CLI.

Run `npm ci` and `npm test` in `ryk-dashboard-ui/` when changing the dashboard. Do not commit `node_modules/`, `.next/`, or generated release output.

## Release signing (maintainer tooling)

[minisign](https://jedisct1.github.io/minisign/) signs release artifacts. It is a
maintainer-side tool invoked by `scripts/cut-release.sh`, not a build or runtime
dependency, and nothing links against it. Chosen over sigstore/cosign because the
verification side runs inside a POSIX `sh` installer on the user's machine, where a
single small Ed25519 signature check is the whole requirement — cosign would pull
an OIDC/transparency-log stack into that path for no gain at this scale.

Signing is not yet active (sentinel `RYK_RELEASE_PUBKEY_UNPROVISIONED`). After
provisioning, `scripts/install.sh` will verify with `minisign`, or `rsign` (Rust
implementation of the same format) if minisign is absent, and fail closed when
neither exists. `scripts/install.ps1` remains checksum-only (Windows unsigned).
The public key lives in `keys/ryk-release-minisign.pub`; the secret key must never
be in this repo or in CI. See [`../release-signing.md`](../release-signing.md).

## macOS FM steward

Swift source and the Wax SPM pin live in [ryk-fm-steward](https://github.com/christopherkarani/ryk-fm-steward) (`Package.swift`, Wax 0.1.25, `traits: []`). This repo keeps the wire contract under `macos/fm-steward/Schemas` and `macos/fm-steward/Fixtures`. The steward is an assistive classifier, not a policy authority. Policy and shell decisions remain on the Zig path (`src/cli/fm_steward_client.zig`).

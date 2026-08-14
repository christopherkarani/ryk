# Dependency notes

Dependency changes should be reviewed for provenance, license, input handling, and release impact. Pin exact sources and hashes in `build.zig.zon` or the package lockfile.

## Zig packages

- [libvaxis](https://github.com/rockorager/libvaxis) is pinned to commit `ca781b3c01f44a92e5331652823b5a9ce445be96` for terminal capability detection and interactive widgets.
- [uucode](https://github.com/jacobsandlund/uucode) is pinned in `build.zig.zon` because libvaxis declares it as a lazy dependency.
- [PCRE2](https://github.com/PCRE2Project/pcre2) is built and statically linked for the in-process Zig shell evaluator.

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

`scripts/install.sh` verifies with `minisign`, or `rsign` (Rust implementation of
the same format) if minisign is absent, and fails closed when neither exists. The
public key lives in `keys/ryk-release-minisign.pub`; the secret key must never be
in this repo or in CI. See [`../release-signing.md`](../release-signing.md).

## macOS FM steward

The macOS FM steward uses the pinned Wax package in `macos/fm-steward/Package.swift` for local few-shot retrieval. It is an assistive classifier, not a policy authority. Policy and shell decisions remain on the Zig path.

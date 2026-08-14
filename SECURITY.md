# Security policy

## Supported versions

Security fixes target the current release line identified by [`VERSION`](VERSION). Older snapshots may not receive fixes, so reproduce issues against the current checkout before reporting them.

## Reporting a vulnerability

Please use [GitHub's private security advisory form](https://github.com/christopherkarani/ryk/security/advisories/new). Include the affected version or commit, operating system, reproduction steps, and any generated ryk audit directory if it contains only synthetic data.

Do not include real credentials, API keys, access tokens, private keys, customer data, or proprietary logs. Replace them with synthetic values.

## Safe handling

Keep exploit details private until a fix or documented limitation is available. A design limitation may require a documentation change or a regression fixture rather than a code change.

## Security scope

ryk protects local agent runs that go through ryk-managed wrappers, shims, staging, policy checks, audit logging, and the stdio MCP proxy. It reduces blast radius and improves reviewability.

ryk does not make arbitrary malicious code safe, and it does not provide universal transparent filesystem or network enforcement on every operating system. Use `ryk doctor` for local capability status and read the [compatibility matrix](docs/compatibility.md) before making an enforcement claim.

## Release integrity

Signing is not yet active. The published public key is the sentinel
`RYK_RELEASE_PUBKEY_UNPROVISIONED`, so installers are checksum-only
(fail-open on signatures) until a real key is provisioned.

`scripts/install.sh` reports `not yet active for this release` and verifies
SHA-256. `scripts/install.ps1` is checksum-only (Windows unsigned) and does
not consume `checksums.txt.minisig`.

After provisioning, releases will publish `checksums.txt.minisig` and the
POSIX installer will verify it before trusting any digest.

Verifying by hand is the strongest path, because `curl … | sh` trusts whoever
served the script. [Release signing](docs/release-signing.md) documents the key,
the verification commands, and precisely which attacks signing does and does not
stop. Report a suspected key compromise through the process above; rotation
happens before anything else signed by that key is published.

## Regression checks

```sh
./scripts/zig build
./scripts/zig build test
./zig-out/bin/ryk redteam --ci
./zig-out/bin/ryk doctor
```

Raw secrets must not appear in `events.jsonl`, `summary.json`, `summary.md`, replay output, red-team output, doctor output, generated policies, or release files.

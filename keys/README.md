# Release signing keys

`ryk-release-minisign.pub` is the Ed25519 (minisign) public key that
authenticates release artifacts. `checksums.txt` covers every artifact, so the
single detached signature `checksums.txt.minisig` authenticates the whole
release.

Verify a downloaded release by hand:

```sh
minisign -V -p keys/ryk-release-minisign.pub -x checksums.txt.minisig -m checksums.txt
shasum -a 256 -c checksums.txt --ignore-missing
```

## Provisioning state

The key ships as the sentinel `RYK_RELEASE_PUBKEY_UNPROVISIONED`, which means
signature enforcement is **not active yet**: `scripts/install.sh` says signing is
not yet active for the release instead of pretending a missing signature is fine,
and a dry-run release cut warns rather than signing.

Provisioning is a maintainer action because the secret key must never exist in
this repo or in CI. See [`docs/release-signing.md`](../docs/release-signing.md).
Once the real key replaces the sentinel here and in `scripts/install.sh`,
enforcement turns on for every subsequent release: the installer then refuses any
release whose signature is missing or does not verify.

## What signing does and does not protect

It splits trust between two hosts. Archives and `checksums.txt` come from GitHub
Releases; `scripts/install.sh` and the key come from rykanv.com. Compromising the
release host alone no longer ships attacker code.

It does **not** protect `curl … | sh` against a compromised copy of the installer
itself — that path trusts whoever served the script, and an attacker who can
replace the script can also replace the key inside it. Manual verification
against this file (fetched from the repo, a third origin) is what closes that gap.

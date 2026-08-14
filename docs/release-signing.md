# Release signing

**Signing is not yet active.** `keys/ryk-release-minisign.pub` holds the sentinel
`RYK_RELEASE_PUBKEY_UNPROVISIONED`. Until a real key is provisioned, installers
are checksum-only (fail-open on signatures): `scripts/install.sh` prints
`not yet active for this release` and continues on SHA-256; `scripts/install.ps1`
is checksum-only (Windows unsigned) and never reads `checksums.txt.minisig`.
CI backup (`release.yml`) still does not attach a minisig.

The machinery below is wired for the day a key is provisioned. It is not current
shipping enforcement.

Release artifacts will then be authenticated with an Ed25519 signature in
[minisign](https://jedisct1.github.io/minisign/) format. `checksums.txt` already
covers the contents of every artifact, so one detached signature over it —
`checksums.txt.minisig` — authenticates the whole release.

SHA-256 verification stays exactly where it was. Signing is the layer that says
*who* produced those digests; the digests still say *what* the archive contains.

## What this protects, and what it does not

| Attack | Before | After |
| --- | --- | --- |
| Corrupt download | caught (SHA-256) | caught |
| Attacker replaces the archive on the release host | **not caught** — they rewrite `checksums.txt` too | caught: the signature no longer verifies |
| Attacker replaces `scripts/install.sh` on rykanv.com | not caught | **still not caught** |

The gain is a trust split. Archives and `checksums.txt` come from GitHub
Releases; the installer and the key it carries come from rykanv.com. Compromising
the release host alone no longer ships attacker code.

`curl … | sh` inherently trusts whoever served the script: an attacker who can
replace the installer can also replace the key inside it. That gap closes only by
verifying by hand against the key published in the repo — a third origin.

```sh
curl -fsSLO https://github.com/christopherkarani/ryk/releases/download/vX.Y.Z/checksums.txt
curl -fsSLO https://github.com/christopherkarani/ryk/releases/download/vX.Y.Z/checksums.txt.minisig
minisign -V -p keys/ryk-release-minisign.pub -x checksums.txt.minisig -m checksums.txt
shasum -a 256 -c checksums.txt --ignore-missing
```

## Current state: enforcement is not active

`keys/ryk-release-minisign.pub` holds the sentinel
`RYK_RELEASE_PUBKEY_UNPROVISIONED`, and `scripts/install.sh` carries the same
value. While that is true:

- the installer prints `Verify signature  not yet active for this release` and
  continues on SHA-256 alone (the behavior users already have today);
- a dry-run release cut warns that signing was skipped;
- a **live** release cut still fails in the `sign` phase, before pushing
  anything, because a live cut requires a key.

The secret key must never exist in this repo or in CI, so provisioning is a
maintainer action.

## Provisioning (maintainer, one time)

Generate the keypair on a trusted machine and keep the secret key offline —
ideally on removable media or in a password manager, never in the repo, never in
a CI secret, since a CI secret would let anyone with push access to a workflow
sign a release.

```sh
minisign -G -p ryk-release-minisign.pub -s ryk-release-minisign.key
```

Use a passphrase. The signing path is interactive and maintainer-only, so a
prompt costs nothing and a stolen key file is then useless on its own.

Publish the public half in two places, which `scripts/test-release-signing.sh`
asserts agree:

1. `keys/ryk-release-minisign.pub` — replace the whole file with the generated
   public key file.
2. `scripts/install.sh` — replace the sentinel in the `RELEASE_PUBKEY` line with
   the base64 key (the second line of the `.pub` file).

Then announce the key in the release notes for the first signed release, so
existing users can see where it came from, and record its fingerprint somewhere
outside this repo.

### Cutting a signed release

```sh
export RYK_MINISIGN_SECRET_KEY="$HOME/offline/ryk-release-minisign.key"
./scripts/cut-release.sh --version X.Y.Z --live
```

The `sign` phase runs after `verify` and before `publish-git`. A live cut with
no key stops in `sign` before `git push`. While the sentinel is shipped, do not
read that as "unsigned never reaches users": installers are still checksum-only,
and CI backup does not attach a minisig. After provisioning, `sign` verifies the
result against `keys/ryk-release-minisign.pub` — not against the secret key's own
copy — because the assertion that matters is that *users* can verify it. If the
two disagree it fails with nothing pushed.

`publish-git` checks `checksums.txt.minisig` before `git push`. After
provisioning it requires a signature that actually verifies, not merely a
non-empty file, and uploads it alongside `checksums.txt`.

To resume after fixing a signing problem:

```sh
./scripts/cut-release.sh --version X.Y.Z --live --resume-from sign
```

## Key rotation

Publish the new public key in both locations in one commit, then cut a release
signed with the new key. Installers fetch the key with the script, so a rotation
takes effect immediately for `curl | sh` users; anyone verifying by hand should be
told in the release notes. Keep the old public key in the release notes of the
last release it signed, so old artifacts stay verifiable.

If a key is suspected compromised, rotate first and say so in `SECURITY.md`
before publishing anything else signed by the old key.

## Verifier availability

After provisioning, the POSIX installer verifies with `minisign` if present, or
`rsign` (the Rust implementation of the same format) otherwise. If neither is
installed it will fail closed with install instructions, because an unverifiable
release is ambiguous state, not an implicit pass. That fail-closed path is not
current shipping behavior: today the sentinel key keeps installers on
checksum-only trust.

A user who cannot install a verifier can explicitly accept checksum-only trust:

```sh
RYK_INSTALL_ALLOW_UNSIGNED=1 curl -fsSL https://rykanv.com/install | sh
```

That prints `Verify signature  SKIPPED` so it is never silent. A compromised
release host cannot set it — only the person running the installer can.

## Tests

`scripts/test-release-signing.sh` (in `verify-pre-merge.sh`) always asserts
`cut-release.sh` dispatches `sign)` and does not document `--resume-from
publish-git`. When a verifier is installed it also generates a throwaway
keypair, never touching the production key, and drives the real installer
offline. Those cases assert a valid signature verifies; a tampered
`checksums.txt`, a forged signature, a signature from an unrelated key, and a
missing signature are each refused; the tampered case fails at the signature
*before* any digest is trusted; the opt-out announces itself; and, under the
sentinel key, SHA-256 verification still catches a bad digest. It also asserts
the key in `scripts/install.sh` matches `keys/ryk-release-minisign.pub`.

Crypto installer cases skip with a clear message when no verifier is installed.
The dispatcher contract still runs, so a missing `sign)` arm cannot hide behind
that skip.

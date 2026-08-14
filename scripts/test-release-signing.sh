#!/usr/bin/env bash
# Release signing contract, offline and hermetic.
#
# Drives the real scripts/install.sh signature path with a throwaway keypair —
# the production key is never needed and never touched. The point is the
# fail-closed boundary: a release that cannot be authenticated must not install,
# and "cannot be authenticated" includes a tampered checksums file, a tampered
# signature, a signature from the wrong key, and a missing signature.
set -euo pipefail

cd "$(dirname "$0")/.."
REPO="$PWD"
INSTALLER="$REPO/scripts/install.sh"

pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1" >&2; exit 1; }
note() { printf '%s\n' "$1"; }

SIGNER=""
if command -v minisign >/dev/null 2>&1; then
  SIGNER=minisign
elif command -v rsign >/dev/null 2>&1; then
  SIGNER=rsign
fi
if [[ -z "$SIGNER" ]]; then
  note "test-release-signing: SKIPPED (no minisign or rsign available)"
  note "  install one: brew install minisign | cargo install rsign2"
  exit 0
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

note "test-release-signing: using $SIGNER"

# ── throwaway keypair (never the production key) ──────────────────────────────
case "$SIGNER" in
  minisign)
    minisign -G -f -W -p "$TMP/test.pub" -s "$TMP/test.key" >/dev/null 2>&1 \
      || fail "could not generate a test keypair"
    ;;
  rsign)
    rsign generate -f -W -p "$TMP/test.pub" -s "$TMP/test.key" >/dev/null 2>&1 \
      || fail "could not generate a test keypair"
    ;;
esac
PUBKEY="$(grep -v '^untrusted comment:' "$TMP/test.pub" | head -n1)"
[[ -n "$PUBKEY" ]] || fail "test public key is empty"

# A second key, to prove a valid signature from the wrong signer is rejected.
case "$SIGNER" in
  minisign) minisign -G -f -W -p "$TMP/other.pub" -s "$TMP/other.key" >/dev/null 2>&1 ;;
  rsign) rsign generate -f -W -p "$TMP/other.pub" -s "$TMP/other.key" >/dev/null 2>&1 ;;
esac

# -W because the throwaway keys above are passwordless; without it the signer
# tries to read a passphrase from a terminal that is not there.
sign_file() {
  local key="$1" file="$2" out="$3"
  case "$SIGNER" in
    minisign) minisign -S -W -s "$key" -m "$file" -x "$out" >/dev/null 2>&1 ;;
    rsign) rsign sign -W -s "$key" -x "$out" "$file" >/dev/null 2>&1 ;;
  esac
}

# ── synthetic release dir: an artifact, its checksums, and a signature ────────
# The archive is deliberately not a real ryk release, so a run that gets past
# signature and checksum verification fails later on extraction. That is what
# distinguishes "signature accepted" from "signature rejected" below.
VERSION="9.9.9"
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$(uname -m)" in
  arm64 | aarch64) ARCH=arm64 ;;
  *) ARCH=amd64 ;;
esac
ARTIFACT="ryk-v${VERSION}-${OS}-${ARCH}.tar.gz"

new_release_dir() {
  local dir="$1"
  mkdir -p "$dir"
  printf 'not a real release archive\n' > "$dir/$ARTIFACT"
  ( cd "$dir" && { shasum -a 256 "$ARTIFACT" 2>/dev/null || sha256sum "$ARTIFACT"; } > checksums.txt )
  sign_file "$TMP/test.key" "$dir/checksums.txt" "$dir/checksums.txt.minisig"
}

# Run the installer offline against a synthetic release dir. Prints its exit code;
# never installs, because HOME and the install dirs are inside $TMP.
#
# stdin comes from /dev/null and every RYK_* knob is set explicitly, so an
# ambient value cannot change the outcome and nothing can block on a prompt. A
# scrubbed environment (env -i) is deliberately avoided: it breaks the terminal
# the installer inherits.
run_installer() {
  local dir="$1" out="$2"
  shift 2
  local rc=0
  env \
    HOME="$TMP/home" \
    RYK_VERSION="$VERSION" \
    RYK_ARTIFACT_DIR="$dir" \
    RYK_INSTALL_DIR="$TMP/home/bin" \
    RYK_SHARE_DIR="$TMP/home/share" \
    RYK_INSTALL_SKIP_ONBOARD=1 \
    RYK_INSTALL_QUIET=0 \
    RYK_INSTALL_ALLOW_UNSIGNED=0 \
    RYK_RELEASE_PUBKEY="RYK_RELEASE_PUBKEY_UNPROVISIONED" \
    NO_COLOR=1 \
    "$@" \
    sh "$INSTALLER" </dev/null >"$out" 2>&1 || rc=$?
  printf '%s' "$rc"
}

mkdir -p "$TMP/home"

note "test-release-signing: enforcement on (provisioned key)"

# 1. Valid signature → the signature step passes and the run proceeds past it.
new_release_dir "$TMP/good"
rc="$(run_installer "$TMP/good" "$TMP/good.log" RYK_RELEASE_PUBKEY="$PUBKEY")"
grep -q 'Verify signature' "$TMP/good.log" || fail "no signature step in output"
grep -q 'ok · minisign over checksums.txt' "$TMP/good.log" \
  || { cat "$TMP/good.log"; fail "valid signature was not reported as verified"; }
grep -qi 'signature verification FAILED' "$TMP/good.log" \
  && fail "valid signature reported as failed"
pass "valid signature verifies and the install proceeds"

# 2. Tampered checksums.txt → refuse. This is the attack the audit named: a
#    release host that swaps the archive and rewrites its digest.
new_release_dir "$TMP/tampered"
printf '0000000000000000000000000000000000000000000000000000000000000000  %s\n' "$ARTIFACT" \
  > "$TMP/tampered/checksums.txt"
rc="$(run_installer "$TMP/tampered" "$TMP/tampered.log" RYK_RELEASE_PUBKEY="$PUBKEY")"
[[ "$rc" != "0" ]] || fail "tampered checksums.txt installed anyway"
grep -qi 'signature verification FAILED' "$TMP/tampered.log" \
  || { cat "$TMP/tampered.log"; fail "tampered checksums.txt did not fail on the signature"; }
grep -qi 'checksum mismatch' "$TMP/tampered.log" \
  && fail "reached the checksum step; signature must fail first"
pass "tampered checksums.txt is refused at the signature, before any digest is trusted"

# 3. Tampered signature → refuse.
new_release_dir "$TMP/badsig"
printf 'untrusted comment: forged\nRWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7Gw==\n' \
  > "$TMP/badsig/checksums.txt.minisig"
rc="$(run_installer "$TMP/badsig" "$TMP/badsig.log" RYK_RELEASE_PUBKEY="$PUBKEY")"
[[ "$rc" != "0" ]] || fail "forged signature installed anyway"
grep -qi 'signature verification FAILED' "$TMP/badsig.log" \
  || fail "forged signature was not rejected"
pass "forged signature is refused"

# 4. Valid signature from the wrong key → refuse.
new_release_dir "$TMP/wrongkey"
sign_file "$TMP/other.key" "$TMP/wrongkey/checksums.txt" "$TMP/wrongkey/checksums.txt.minisig"
rc="$(run_installer "$TMP/wrongkey" "$TMP/wrongkey.log" RYK_RELEASE_PUBKEY="$PUBKEY")"
[[ "$rc" != "0" ]] || fail "signature from an unrelated key installed anyway"
grep -qi 'signature verification FAILED' "$TMP/wrongkey.log" \
  || fail "signature from an unrelated key was not rejected"
pass "valid signature from the wrong key is refused"

# 5. Missing signature → refuse. A downgrade attack must not look like an
#    unsigned release that is fine to install.
new_release_dir "$TMP/nosig"
rm -f "$TMP/nosig/checksums.txt.minisig"
rc="$(run_installer "$TMP/nosig" "$TMP/nosig.log" RYK_RELEASE_PUBKEY="$PUBKEY")"
[[ "$rc" != "0" ]] || fail "release with no signature installed anyway"
grep -qi 'release signature not found' "$TMP/nosig.log" \
  || { cat "$TMP/nosig.log"; fail "missing signature was not refused"; }
pass "missing signature is refused (no silent downgrade)"

# 6. Explicit user opt-out → proceeds, and says so out loud.
rc="$(run_installer "$TMP/nosig" "$TMP/optout.log" \
  RYK_RELEASE_PUBKEY="$PUBKEY" RYK_INSTALL_ALLOW_UNSIGNED=1)"
grep -q 'SKIPPED (RYK_INSTALL_ALLOW_UNSIGNED=1)' "$TMP/optout.log" \
  || { cat "$TMP/optout.log"; fail "opt-out did not announce itself"; }
pass "RYK_INSTALL_ALLOW_UNSIGNED=1 proceeds and announces the downgrade"

note "test-release-signing: enforcement off (sentinel key, current shipping state)"

# 7. Unprovisioned key → honest status line, and checksums still enforced.
new_release_dir "$TMP/sentinel"
rm -f "$TMP/sentinel/checksums.txt.minisig"
rc="$(run_installer "$TMP/sentinel" "$TMP/sentinel.log")"
grep -q 'not yet active for this release' "$TMP/sentinel.log" \
  || { cat "$TMP/sentinel.log"; fail "sentinel key did not report signing as inactive"; }
grep -q 'Verify SHA-256' "$TMP/sentinel.log" \
  || fail "checksum verification did not run under the sentinel key"
pass "sentinel key reports signing inactive and still verifies SHA-256"

# 8. With the sentinel, a tampered digest is still caught by the checksum step.
new_release_dir "$TMP/sentinel_bad"
printf '0000000000000000000000000000000000000000000000000000000000000000  %s\n' "$ARTIFACT" \
  > "$TMP/sentinel_bad/checksums.txt"
rc="$(run_installer "$TMP/sentinel_bad" "$TMP/sentinel_bad.log")"
[[ "$rc" != "0" ]] || fail "sentinel key let a bad digest install"
grep -qi 'checksum mismatch' "$TMP/sentinel_bad.log" \
  || fail "checksum mismatch was not reported under the sentinel key"
pass "SHA-256 remains defense in depth while signing is inactive"

note "test-release-signing: repo state"

# 9. The shipped installer and the shipped public key must agree, or the release
#    would be signed by a key users cannot verify against.
key_line="$(grep -v '^untrusted comment:' keys/ryk-release-minisign.pub | head -n1)"
installer_key="$(sed -n 's/^RELEASE_PUBKEY="\${RYK_RELEASE_PUBKEY:-\(.*\)}"$/\1/p' scripts/install.sh)"
[[ -n "$installer_key" ]] || fail "could not read RELEASE_PUBKEY from scripts/install.sh"
[[ "$key_line" == "$installer_key" ]] \
  || fail "keys/ryk-release-minisign.pub ($key_line) and scripts/install.sh ($installer_key) disagree"
pass "installer key matches keys/ryk-release-minisign.pub"

note "test-release-signing: passed"

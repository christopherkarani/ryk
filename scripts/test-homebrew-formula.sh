#!/usr/bin/env bash
# Offline contract test for the Homebrew formula and its release automation.
#
# The Homebrew channel is also ryk's update mechanism, so a formula that drifts
# from VERSION — or automation that silently skips a digest — ships stale
# protection to everyone who installed with brew. These checks run without
# network so they can gate every merge.
#
# Usage:
#   ./scripts/test-homebrew-formula.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$REPO_ROOT"

FORMULA="packaging/homebrew/Formula/ryk.rb"
UPDATER="scripts/update-homebrew-tap.sh"
PLATFORMS=(darwin-arm64 darwin-amd64 linux-arm64 linux-amd64)

WORK="$(mktemp -d "${TMPDIR:-/tmp}/ryk-brew-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

pass() { printf '  ok   %s\n' "$*"; }
fail() {
  printf 'test-homebrew-formula: FAIL: %s\n' "$*" >&2
  exit 1
}

printf 'test-homebrew-formula: formula shape\n'

[[ -f "$FORMULA" ]] || fail "missing ${FORMULA}"
[[ -x "$UPDATER" ]] || fail "${UPDATER} is not executable"

if command -v ruby >/dev/null 2>&1; then
  ruby -c "$FORMULA" >/dev/null || fail "${FORMULA} is not valid Ruby"
  pass "valid Ruby"
else
  printf '  skip valid Ruby (no ruby on PATH)\n'
fi

# The formula must pin the version this tree ships, or `brew upgrade` lands on a
# release whose assets do not match the digests below.
version="$(tr -d '[:space:]' <VERSION)"
grep -q "^  version \"${version}\"\$" "$FORMULA" \
  || fail "${FORMULA} does not pin VERSION ${version}"
pass "pins VERSION ${version}"

grep -q "https://github.com/christopherkarani/ryk/releases/download/v#{version}/ryk-v#{version}-darwin-arm64.tar.gz" "$FORMULA" \
  || fail "formula does not point at the real release asset URL"
pass "real release asset URLs"

# Every platform needs exactly one marker, each followed by a 64-hex digest.
for platform in "${PLATFORMS[@]}"; do
  count="$(grep -c "ryk:sha256:${platform}\$" "$FORMULA" || true)"
  [[ "$count" == "1" ]] || fail "marker ryk:sha256:${platform} appears ${count} times (want 1)"
  digest="$(grep -A1 "ryk:sha256:${platform}\$" "$FORMULA" | tail -1 | sed -n 's/.*sha256 "\([0-9a-f]*\)".*/\1/p')"
  [[ "${#digest}" == "64" ]] || fail "digest after ryk:sha256:${platform} is not 64 hex chars: '${digest}'"
done
pass "4 platform markers with 64-hex digests"

# No template placeholders may survive: an unrendered {{...}} would make brew
# refuse the formula at install time instead of at merge time.
grep -q '{{' "$FORMULA" && fail "formula still contains a {{PLACEHOLDER}}"
pass "no unrendered placeholders"

grep -q 'ryk doctor' "$FORMULA" || fail "caveats must point at ryk doctor"
grep -q 'ryk --version' "$FORMULA" || fail "test block must run ryk --version"
pass "caveats point at ryk doctor; test block runs ryk --version"

# Regression guard: Homebrew's Formula#system is (cmd, *args). An env hash passed
# as the first argument is executed as the command, so onboarding silently never
# runs and `brew install` fails in post_install. Env must go through with_env.
grep -nE '^\s*system\s+[A-Za-z_][A-Za-z0-9_]*,' "$FORMULA" \
  && fail "system() called with an env hash as its first argument; use with_env"
grep -q 'with_env(' "$FORMULA" || fail "expected with_env for onboarding/test env"
pass "system() never takes an env hash (with_env is used)"

printf 'test-homebrew-formula: automation round-trip\n'

cat >"${WORK}/checksums.txt" <<'EOF'
1111111111111111111111111111111111111111111111111111111111111111  ryk-v9.9.9-darwin-amd64.tar.gz
2222222222222222222222222222222222222222222222222222222222222222  ryk-v9.9.9-darwin-arm64.tar.gz
3333333333333333333333333333333333333333333333333333333333333333  ryk-v9.9.9-linux-amd64.tar.gz
4444444444444444444444444444444444444444444444444444444444444444  ryk-v9.9.9-linux-arm64.tar.gz
EOF

cp "$FORMULA" "${WORK}/probe.rb"
"$UPDATER" --version 9.9.9 --checksums "${WORK}/checksums.txt" --formula "${WORK}/probe.rb" >/dev/null \
  || fail "updater refused a well-formed release"
grep -q '^  version "9.9.9"$' "${WORK}/probe.rb" || fail "updater did not rewrite the version"

# Each digest must land in its own platform slot, not merely appear somewhere.
assert_slot() {
  local platform="$1" want="$2" got
  got="$(grep -A1 "ryk:sha256:${platform}\$" "${WORK}/probe.rb" | tail -1 | sed -n 's/.*sha256 "\([0-9a-f]*\)".*/\1/p')"
  [[ "$got" == "$want" ]] || fail "${platform} slot holds ${got}, want ${want}"
}
assert_slot darwin-arm64 2222222222222222222222222222222222222222222222222222222222222222
assert_slot darwin-amd64 1111111111111111111111111111111111111111111111111111111111111111
assert_slot linux-arm64 4444444444444444444444444444444444444444444444444444444444444444
assert_slot linux-amd64 3333333333333333333333333333333333333333333333333333333333333333
pass "digests land in the correct per-platform slots"

if command -v ruby >/dev/null 2>&1; then
  ruby -c "${WORK}/probe.rb" >/dev/null || fail "rendered formula is not valid Ruby"
  pass "rendered formula is valid Ruby"
fi

printf 'test-homebrew-formula: fail-closed negatives\n'

# Each negative must exit non-zero AND leave the target formula byte-identical:
# a half-rendered formula in the tap is worse than no update.
refuses() {
  local label="$1"
  shift
  local target="$1"
  shift
  local before after
  before="$(shasum -a 256 <"$target")"
  if "$UPDATER" "$@" >/dev/null 2>&1; then
    fail "${label}: updater accepted it"
  fi
  after="$(shasum -a 256 <"$target")"
  [[ "$before" == "$after" ]] || fail "${label}: target formula was mutated on failure"
  pass "${label}"
}

cp "$FORMULA" "${WORK}/n1.rb"
grep -v 'linux-arm64' "${WORK}/checksums.txt" >"${WORK}/partial.txt"
refuses "incomplete release checksums" "${WORK}/n1.rb" \
  --version 9.9.9 --checksums "${WORK}/partial.txt" --formula "${WORK}/n1.rb"

cp "$FORMULA" "${WORK}/n2.rb"
sed 's/^1111111111111111111111111111111111111111111111111111111111111111/deadbeef/' \
  "${WORK}/checksums.txt" >"${WORK}/short.txt"
refuses "digest that is not 64 hex chars" "${WORK}/n2.rb" \
  --version 9.9.9 --checksums "${WORK}/short.txt" --formula "${WORK}/n2.rb"

cp "$FORMULA" "${WORK}/n3.rb"
refuses "malformed --version" "${WORK}/n3.rb" \
  --version 1.2 --checksums "${WORK}/checksums.txt" --formula "${WORK}/n3.rb"

cp "$FORMULA" "${WORK}/n4.rb"
: >"${WORK}/empty.txt"
refuses "empty checksums file" "${WORK}/n4.rb" \
  --version 9.9.9 --checksums "${WORK}/empty.txt" --formula "${WORK}/n4.rb"

# A hand-edited formula that lost a marker must abort rather than push a formula
# with one stale digest.
grep -v 'ryk:sha256:linux-amd64' "$FORMULA" >"${WORK}/n5.rb"
refuses "formula missing a platform marker" "${WORK}/n5.rb" \
  --version 9.9.9 --checksums "${WORK}/checksums.txt" --formula "${WORK}/n5.rb"

printf 'test-homebrew-formula: passed\n'

#!/usr/bin/env bash
# Rewrite the Homebrew formula for a release and (optionally) publish it to the tap.
#
# The Homebrew channel doubles as ryk's update mechanism: `brew upgrade ryk` is what
# refreshes managed host plugins on an existing install. A formula that lags the
# latest release therefore ships stale protection, so cut-release calls this script
# instead of leaving the bump to a human.
#
# Usage:
#   ./scripts/update-homebrew-tap.sh --version X.Y.Z [options]
#
# Options:
#   --version X.Y.Z     Release version to pin (required)
#   --checksums FILE    checksums.txt to read digests from
#                       (default: dist/checksums.txt, else download from the release)
#   --formula PATH      Formula to rewrite in place
#                       (default: packaging/homebrew/Formula/ryk.rb)
#   --tap-dir DIR       Existing tap checkout to also write + commit into
#   --tap-repo SLUG     Tap repo to clone when --tap-dir is absent
#                       (default: christopherkarani/homebrew-ryk)
#   --live              Commit and push the tap (default: render + verify only)
#   --print             Write the rendered formula to stdout instead of any file
#   -h, --help          Show this help
#
# Fails closed: a missing digest for any published platform, a digest that is not
# 64 hex characters, or a formula whose markers do not match aborts without writing.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$REPO_ROOT"

VERSION=""
CHECKSUMS=""
FORMULA="packaging/homebrew/Formula/ryk.rb"
TAP_DIR=""
TAP_REPO="${RYK_HOMEBREW_TAP_REPO:-christopherkarani/homebrew-ryk}"
LIVE=0
PRINT_ONLY=0

# Platform key → release asset suffix. Keys match the `ryk:sha256:<key>` markers.
PLATFORMS=(darwin-arm64 darwin-amd64 linux-arm64 linux-amd64)

log() { printf 'update-homebrew-tap: %s\n' "$*"; }
fail() {
  printf 'update-homebrew-tap: error: %s\n' "$*" >&2
  exit 1
}

usage() { sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      VERSION="${2:-}"
      shift 2
      ;;
    --checksums)
      CHECKSUMS="${2:-}"
      shift 2
      ;;
    --formula)
      FORMULA="${2:-}"
      shift 2
      ;;
    --tap-dir)
      TAP_DIR="${2:-}"
      shift 2
      ;;
    --tap-repo)
      TAP_REPO="${2:-}"
      shift 2
      ;;
    --live)
      LIVE=1
      shift
      ;;
    --print)
      PRINT_ONLY=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *) fail "unknown argument: $1" ;;
  esac
done

[[ -n "$VERSION" ]] || fail "pass --version X.Y.Z"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "--version must be X.Y.Z, got: ${VERSION}"
[[ -f "$FORMULA" ]] || fail "formula not found: ${FORMULA}"

# ---------------------------------------------------------------------------
# Digests
# ---------------------------------------------------------------------------
if [[ -z "$CHECKSUMS" ]]; then
  if [[ -s "dist/checksums.txt" ]]; then
    CHECKSUMS="dist/checksums.txt"
    log "using local dist/checksums.txt"
  else
    command -v gh >/dev/null 2>&1 || fail "no --checksums and no dist/checksums.txt; gh is required to download from the release"
    CHECKSUMS="$(mktemp -t ryk-brew-checksums)"
    log "downloading checksums.txt from release v${VERSION}…"
    gh release download "v${VERSION}" --pattern checksums.txt --output "$CHECKSUMS" --clobber \
      || fail "could not download checksums.txt for v${VERSION}; publish release assets first"
  fi
fi
[[ -s "$CHECKSUMS" ]] || fail "checksums file is empty: ${CHECKSUMS}"

digest_for() {
  local platform="$1" asset digest
  asset="ryk-v${VERSION}-${platform}.tar.gz"
  # checksums.txt is "<digest>  <asset>"; match the asset name exactly.
  digest="$(awk -v want="$asset" '$2 == want { print $1; exit }' "$CHECKSUMS")"
  [[ -n "$digest" ]] || fail "no digest for ${asset} in ${CHECKSUMS} (release incomplete?)"
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || fail "digest for ${asset} is not 64 lowercase hex chars: ${digest}"
  printf '%s' "$digest"
}

declare -a DIGESTS=()
for platform in "${PLATFORMS[@]}"; do
  DIGESTS+=("$(digest_for "$platform")")
done

# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------
# Rewrites the `version "X.Y.Z"` line and each sha256 line that follows a
# `ryk:sha256:<platform>` marker. Every marker must be present exactly once and
# be followed by a sha256 line, or nothing is written.
render() {
  local src="$1"
  VERSION="$VERSION" PLATFORM_LIST="${PLATFORMS[*]}" DIGEST_LIST="${DIGESTS[*]}" \
    awk '
    BEGIN {
      version = ENVIRON["VERSION"]
      n = split(ENVIRON["PLATFORM_LIST"], platforms, " ")
      split(ENVIRON["DIGEST_LIST"], digests, " ")
      for (i = 1; i <= n; i++) want[platforms[i]] = digests[i]
      pending = ""
      version_hits = 0
    }
    {
      if (pending != "") {
        if ($0 !~ /^[[:space:]]*sha256 "[0-9a-f]*"$/) {
          printf("update-homebrew-tap: error: marker ryk:sha256:%s is not followed by a sha256 line\n", pending) > "/dev/stderr"
          exit 3
        }
        match($0, /^[[:space:]]*/)
        printf("%ssha256 \"%s\"\n", substr($0, 1, RLENGTH), want[pending])
        seen[pending]++
        pending = ""
        next
      }
      if (match($0, /ryk:sha256:[a-z0-9-]+/)) {
        key = substr($0, RSTART + 11, RLENGTH - 11)
        if (!(key in want)) {
          printf("update-homebrew-tap: error: unknown platform marker: %s\n", key) > "/dev/stderr"
          exit 3
        }
        pending = key
        print
        next
      }
      if (match($0, /^([[:space:]]*)version "[0-9]+\.[0-9]+\.[0-9]+"$/)) {
        match($0, /^[[:space:]]*/)
        printf("%sversion \"%s\"\n", substr($0, 1, RLENGTH), version)
        version_hits++
        next
      }
      print
    }
    END {
      if (pending != "") {
        printf("update-homebrew-tap: error: trailing marker with no sha256 line: %s\n", pending) > "/dev/stderr"
        exit 3
      }
      if (version_hits != 1) {
        printf("update-homebrew-tap: error: expected exactly one version line, found %d\n", version_hits) > "/dev/stderr"
        exit 3
      }
      for (i = 1; i <= n; i++) {
        if (seen[platforms[i]] != 1) {
          printf("update-homebrew-tap: error: marker ryk:sha256:%s appeared %d times (want 1)\n", platforms[i], seen[platforms[i]] + 0) > "/dev/stderr"
          exit 3
        }
      }
    }
  ' "$src"
}

RENDERED="$(mktemp -t ryk-brew-formula)"
trap 'rm -f "$RENDERED"' EXIT
render "$FORMULA" >"$RENDERED" || fail "formula render failed (markers out of shape); ${FORMULA} left untouched"

# Post-render self-check: the rendered formula must pin this version and carry
# every digest, so a silently-skipped substitution cannot reach the tap.
grep -q "version \"${VERSION}\"" "$RENDERED" || fail "rendered formula does not pin ${VERSION}"
for i in "${!PLATFORMS[@]}"; do
  grep -q "sha256 \"${DIGESTS[$i]}\"" "$RENDERED" \
    || fail "rendered formula missing digest for ${PLATFORMS[$i]}"
done
if command -v ruby >/dev/null 2>&1; then
  ruby -c "$RENDERED" >/dev/null || fail "rendered formula is not valid Ruby"
fi

if [[ "$PRINT_ONLY" -eq 1 ]]; then
  cat "$RENDERED"
  exit 0
fi

if cmp -s "$RENDERED" "$FORMULA"; then
  log "formula already at v${VERSION} with matching digests: ${FORMULA}"
else
  cp "$RENDERED" "$FORMULA"
  log "rewrote ${FORMULA} → v${VERSION}"
fi

# ---------------------------------------------------------------------------
# Tap
# ---------------------------------------------------------------------------
if [[ "$LIVE" -eq 0 ]]; then
  log "dry-run: tap not touched (pass --live to commit and push ${TAP_REPO})"
  exit 0
fi

cleanup_clone=""
if [[ -z "$TAP_DIR" ]]; then
  command -v gh >/dev/null 2>&1 || fail "gh is required to clone the tap"
  TAP_DIR="$(mktemp -d -t ryk-tap)"
  cleanup_clone="$TAP_DIR"
  log "cloning tap ${TAP_REPO}…"
  gh repo clone "$TAP_REPO" "$TAP_DIR" -- --depth 1 >/dev/null 2>&1 || fail "could not clone ${TAP_REPO}. Bootstrap the tap once (see packaging/homebrew/README.md), then re-run."
fi
[[ -d "$TAP_DIR" ]] || fail "tap dir not found: ${TAP_DIR}"

mkdir -p "${TAP_DIR}/Formula"
cp "$RENDERED" "${TAP_DIR}/Formula/ryk.rb"

if git -C "$TAP_DIR" diff --quiet -- Formula/ryk.rb; then
  log "tap already at v${VERSION}; nothing to push"
else
  git -C "$TAP_DIR" add Formula/ryk.rb
  git -C "$TAP_DIR" commit -q -m "ryk ${VERSION}"
  git -C "$TAP_DIR" push -q origin HEAD
  log "pushed ryk ${VERSION} to ${TAP_REPO}"
fi

[[ -z "$cleanup_clone" ]] || rm -rf "$cleanup_clone"

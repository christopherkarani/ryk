#!/usr/bin/env bash
# Focused installer/release contract smoke. Uses a staged fake CLI so it does
# not require a Zig build, network access, or writes outside a temporary tree.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VERSION="$(tr -d '[:space:]' < "${REPO_ROOT}/VERSION")"

fail() {
  printf 'test-installer-release-contract: FAIL: %s\n' "$1" >&2
  exit 1
}

assert_absent() {
  local file="$1"
  local pattern="$2"
  if grep -Eiq -- "$pattern" "$REPO_ROOT/$file"; then
    fail "${file} still contains forbidden contract: ${pattern}"
  fi
}

tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/ryk-installer-release-contract.XXXXXX")"
dashboard_dist="${REPO_ROOT}/ryk-dashboard-ui/dist"
dashboard_dist_created=0
cleanup() {
  rm -rf "$tmp_root"
  if [[ "$dashboard_dist_created" -eq 1 ]]; then
    rm -rf "$dashboard_dist"
  fi
}
trap cleanup EXIT INT TERM

if RYK_RELEASE_LIVE=1 RYK_TELEMETRY_BUILD_DISABLED=1 RYK_VERSION="$VERSION" \
  "$REPO_ROOT/scripts/build-release.sh" >/dev/null 2>&1; then
  fail "live release builder accepted disabled telemetry transport"
fi

# build-release intentionally refuses to fall back to the removed legacy
# dashboard assets. Supply a disposable bundle so this contract remains a
# release-layout test and does not require a UI dependency install.
if [[ ! -d "$dashboard_dist" ]]; then
  mkdir -p "$dashboard_dist"
  printf '%s\n' '<!doctype html><title>ryk contract fixture</title>' > "$dashboard_dist/index.html"
  dashboard_dist_created=1
fi

for target in darwin-amd64 darwin-arm64 linux-amd64 linux-arm64 windows-amd64; do
  target_os="${target%%-*}"
  target_arch="${target#*-}"
  bin_name=ryk
  if [[ "$target_os" == windows ]]; then
    bin_name=ryk.exe
  fi
  mkdir -p "$tmp_root/cli/${target_os}-${target_arch}"
  cat > "$tmp_root/cli/${target_os}-${target_arch}/${bin_name}" <<'EOF'
#!/usr/bin/env sh
# ryk-telemetry-transport-disabled-v1
printf 'ryk 0.0.0\n'
EOF
  chmod 0755 "$tmp_root/cli/${target_os}-${target_arch}/${bin_name}"
done

RYK_CLI_ARTIFACT_DIR="$tmp_root/cli" \
RYK_RELEASE_PRODUCT=curl \
RYK_DIST_DIR="$tmp_root/dist" \
RYK_VERSION="$VERSION" \
RYK_BUILD_DATE=2026-01-01T00:00:00Z \
RYK_TELEMETRY_BUILD_DISABLED=1 \
  "$REPO_ROOT/scripts/build-release.sh" >/dev/null

for artifact in \
  "$tmp_root/dist/ryk-v${VERSION}-darwin-amd64.tar.gz" \
  "$tmp_root/dist/ryk-v${VERSION}-darwin-arm64.tar.gz" \
  "$tmp_root/dist/ryk-v${VERSION}-linux-amd64.tar.gz" \
  "$tmp_root/dist/ryk-v${VERSION}-linux-arm64.tar.gz" \
  "$tmp_root/dist/ryk-v${VERSION}-windows-amd64.zip"; do
  [[ -s "$artifact" ]] || fail "release builder did not create $(basename "$artifact")"
done
tar_listing="$(tar -tzf "$tmp_root/dist/ryk-v${VERSION}-darwin-amd64.tar.gz")"
printf '%s\n' "$tar_listing" | grep "/bin/ryk$" >/dev/null || fail "archive is missing bin/ryk"
if printf '%s\n' "$tar_listing" | grep -Ei '/bin/(orca|aegis)$|orca-pi/' >/dev/null; then
  fail "archive contains a removed product path or binary alias"
fi
printf '%s\n' "$tar_listing" | grep "/ryk-pi/extensions/parent_ask.ts$" >/dev/null ||
  fail "archive is missing the bundled ryk-pi parent-ask extension"
zip_listing="$(unzip -Z1 "$tmp_root/dist/ryk-v${VERSION}-windows-amd64.zip")"
printf '%s\n' "$zip_listing" | grep "/bin/ryk.exe$" >/dev/null || fail "Windows archive is missing bin/ryk.exe"

[[ ! -d "$tmp_root/dist/package-manifests" ]] ||
  fail "curl release unexpectedly rendered package-manager manifests"

RYK_RELEASE_PRODUCT=curl "$REPO_ROOT/scripts/verify-release.sh" "$tmp_root/dist" >/dev/null

grep -q 'RYK_TELEMETRY_BUILD_DISABLED' "$REPO_ROOT/scripts/release-dry-run.sh" ||
  fail "release dry-run does not default telemetry transport disabled without a token"
assert_absent scripts/build-release.sh 'orca-pi|DUAL_PUBLISH|legacy_cli_alias|install_primary_and_alias'
assert_absent scripts/cut-release.sh 'publish-npm|publish-homebrew|skip-npm|homebrew-ryk|npm publish|npm whoami'
assert_absent scripts/install.sh 'LEGACY_|/orca|probe_existing_orca|dual-publish|compatibility alias'
assert_absent scripts/install.ps1 'legacyDestination|ryk/orca|legacyArtifact|dual-name'
assert_absent scripts/install.ps1 'ryk start'
assert_absent scripts/install.ps1 '"1\.2\.9"'
assert_absent scripts/build-release.ps1 '"1\.2\.9"|"1\.1\.0"'
assert_absent packaging/npm/bin/ryk.js 'aliasName|installedAlias|sourceAlias|legacyUrl|compat alias|dual-publish'
grep -qF 'doctor --fix --from-install' scripts/install.ps1 ||
  fail 'PowerShell installer is missing the canonical doctor --fix --from-install door'

node --check "$REPO_ROOT/packaging/npm/bin/ryk.js" >/dev/null

printf 'test-installer-release-contract: passed\n'

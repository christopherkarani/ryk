#!/usr/bin/env sh
set -eu

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST_DIR="${1:-${RYK_DIST_DIR:-dist}}"
RELEASE_PRODUCT="${RYK_RELEASE_PRODUCT:-curl}"

fail() {
  printf 'release verify: %s\n' "$1" >&2
  exit 1
}

checksum_for_name() {
  name="$1"
  awk -v name="$name" '$2 == name {print $1}' "$DIST_DIR/checksums.txt"
}

require_artifact() {
  pattern="$1"
  found=0
  for artifact in $pattern; do
    [ -f "$artifact" ] || continue
    found=1
    name="$(basename "$artifact")"
    [ -n "$(checksum_for_name "$name")" ] || fail "missing checksum entry for $name"
    grep -q "\"name\":\"$name\"" "$DIST_DIR/release-manifest.json" ||
      fail "missing release-manifest.json artifact entry for $name"
  done
  [ "$found" = "1" ] || fail "missing artifact pattern $pattern"
}

require_archive_binary() {
  pattern="$1"
  binary="$2"
  found=0
  for artifact in $pattern; do
    [ -f "$artifact" ] || continue
    found=1
    name="$(basename "$artifact")"
    case "$name" in
      *.tar.gz)
        tar -tzf "$artifact" | grep -q "^[^/]*/bin/$binary$" ||
          fail "artifact $name missing bin/$binary"
        ;;
      *.zip)
        command -v unzip >/dev/null 2>&1 || fail "unzip is required to inspect $name"
        unzip -Z1 "$artifact" | grep -q "^[^/]*/bin/$binary$" ||
          fail "artifact $name missing bin/$binary"
        ;;
      *)
        fail "unsupported archive format: $name"
        ;;
    esac
  done
  [ "$found" = "1" ] || fail "missing artifact pattern $pattern"
}

disallowed_archive_path() {
  case "$1" in
    */customer_pilot/*)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

require_archive_excludes() {
  pattern="$1"
  found=0
  for artifact in $pattern; do
    [ -f "$artifact" ] || continue
    found=1
    name="$(basename "$artifact")"
    case "$name" in
      *.tar.gz)
        listing="$(tar -tzf "$artifact")"
        ;;
      *.zip)
        command -v unzip >/dev/null 2>&1 || fail "unzip is required to inspect $name"
        listing="$(unzip -Z1 "$artifact")"
        ;;
      *)
        fail "unsupported archive format: $name"
        ;;
    esac

    for path in $listing; do
      if disallowed_archive_path "$path"; then
        fail "artifact $name contains a private path: $path"
      fi
    done
    bash "$REPO_ROOT/scripts/check-release-payload-secrets.sh" "$artifact" >/dev/null
  done
  [ "$found" = "1" ] || fail "missing artifact pattern $pattern"
}

artifact_package_key() {
  case "$1" in
    ryk-v*-darwin-amd64.tar.gz) printf 'darwin-amd64' ;;
    ryk-v*-darwin-arm64.tar.gz) printf 'darwin-arm64' ;;
    ryk-v*-linux-amd64.tar.gz) printf 'linux-amd64' ;;
    ryk-v*-linux-arm64.tar.gz) printf 'linux-arm64' ;;
    ryk-v*-windows-amd64.zip) printf 'windows-amd64' ;;
    *) fail "unsupported package artifact name: $1" ;;
  esac
}

detect_host_target() {
  host_os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  host_arch="$(uname -m)"
  case "$host_arch" in
    x86_64|amd64) host_arch="amd64" ;;
    arm64|aarch64) host_arch="arm64" ;;
  esac
  printf '%s-%s' "$host_os" "$host_arch"
}

artifact_manifest_name() {
  case "$1" in
    ryk-v*-darwin-amd64.tar.gz) printf 'ryk-v#{version}-darwin-amd64.tar.gz' ;;
    ryk-v*-darwin-arm64.tar.gz) printf 'ryk-v#{version}-darwin-arm64.tar.gz' ;;
    ryk-v*-linux-amd64.tar.gz) printf 'ryk-v#{version}-linux-amd64.tar.gz' ;;
    ryk-v*-linux-arm64.tar.gz) printf 'ryk-v#{version}-linux-arm64.tar.gz' ;;
    *) printf '%s' "$1" ;;
  esac
}

require_manifest_hash_for_artifact() {
  manifest="$1"
  artifact_name="$2"
  hash="$(checksum_for_name "$artifact_name")"
  [ -n "$hash" ] || fail "missing checksum entry for $artifact_name"

  case "$manifest" in
    */homebrew/Formula/ryk.rb)
      manifest_name="$(artifact_manifest_name "$artifact_name")"
      awk -v name="$manifest_name" -v hash="$hash" -v raw="$artifact_name" '
        index($0, name) || index($0, raw) { seen = 1; window = 8 }
        seen && index($0, hash) { ok = 1 }
        seen { window -= 1; if (window <= 0) seen = 0 }
        END { exit ok ? 0 : 1 }
      ' "$manifest" || fail "rendered Homebrew formula checksum is not bound to $artifact_name"
      ;;
    */npm/package.json)
      key="$(artifact_package_key "$artifact_name")"
      grep -Eq "\"$key\"[[:space:]]*:[[:space:]]*\"$hash\"" "$manifest" ||
        fail "rendered npm package checksum is not bound to $artifact_name"
      ;;
    */scoop/ryk.json|*/winget/ryk.yaml)
      grep -q "$artifact_name" "$manifest" ||
        fail "rendered manifest $(basename "$manifest") missing artifact URL for $artifact_name"
      grep -q "$hash" "$manifest" ||
        fail "rendered manifest $(basename "$manifest") missing checksum for $artifact_name"
      ;;
    *)
      fail "unsupported rendered package manifest: $manifest"
      ;;
  esac
}

require_package_hashes() {
  homebrew_ryk="$DIST_DIR/package-manifests/homebrew/Formula/ryk.rb"
  npm="$DIST_DIR/package-manifests/npm/package.json"

  for artifact in \
    "$DIST_DIR"/ryk-v*-darwin-amd64.tar.gz \
    "$DIST_DIR"/ryk-v*-darwin-arm64.tar.gz \
    "$DIST_DIR"/ryk-v*-linux-amd64.tar.gz \
    "$DIST_DIR"/ryk-v*-linux-arm64.tar.gz
  do
    [ -f "$artifact" ] || continue
    name="$(basename "$artifact")"
    require_manifest_hash_for_artifact "$homebrew_ryk" "$name"
    require_manifest_hash_for_artifact "$npm" "$name"
  done

  scoop="$DIST_DIR/package-manifests/scoop/ryk.json"
  winget="$DIST_DIR/package-manifests/winget/ryk.yaml"
  for artifact in "$DIST_DIR"/ryk-v*-windows-amd64.zip; do
    [ -f "$artifact" ] || continue
    name="$(basename "$artifact")"
    require_manifest_hash_for_artifact "$npm" "$name"
    require_manifest_hash_for_artifact "$scoop" "$name"
    require_manifest_hash_for_artifact "$winget" "$name"
  done
}

# Product archives ship the Zig CLI only (shell evaluation is in-process shell_engine).
forbid_archive_binary() {
  pattern="$1"
  binary="$2"
  found=0
  for artifact in $pattern; do
    [ -f "$artifact" ] || continue
    found=1
    name="$(basename "$artifact")"
    case "$name" in
      *.tar.gz)
        if tar -tzf "$artifact" | grep -q "^[^/]*/bin/$binary$"; then
          fail "artifact $name unexpectedly contains bin/$binary (daemon removed from product packaging)"
        fi
        ;;
      *.zip)
        command -v unzip >/dev/null 2>&1 || fail "unzip is required to inspect $name"
        if unzip -Z1 "$artifact" | grep -q "^[^/]*/bin/$binary$"; then
          fail "artifact $name unexpectedly contains bin/$binary (daemon removed from product packaging)"
        fi
        ;;
      *)
        fail "unsupported archive format: $name"
        ;;
    esac
  done
  [ "$found" = "1" ] || fail "missing artifact pattern $pattern"
}

require_cli_archive() {
  pattern="$1"
  require_archive_binary "$pattern" "ryk"
  forbid_archive_binary "$pattern" "ryk-daemon"
  require_archive_excludes "$pattern"
}

require_release_artifacts() {
  case "$RELEASE_PRODUCT" in
    all | cli | curl)
      require_artifact "$DIST_DIR/ryk-v*-darwin-amd64.tar.gz"
      require_artifact "$DIST_DIR/ryk-v*-darwin-arm64.tar.gz"
      require_artifact "$DIST_DIR/ryk-v*-linux-amd64.tar.gz"
      require_artifact "$DIST_DIR/ryk-v*-linux-arm64.tar.gz"
      require_artifact "$DIST_DIR/ryk-v*-windows-amd64.zip"
      require_cli_archive "$DIST_DIR/ryk-v*-darwin-amd64.tar.gz"
      require_cli_archive "$DIST_DIR/ryk-v*-darwin-arm64.tar.gz"
      require_cli_archive "$DIST_DIR/ryk-v*-linux-amd64.tar.gz"
      require_cli_archive "$DIST_DIR/ryk-v*-linux-arm64.tar.gz"
      require_archive_binary "$DIST_DIR/ryk-v*-windows-amd64.zip" "ryk.exe"
      forbid_archive_binary "$DIST_DIR/ryk-v*-windows-amd64.zip" "ryk-daemon.exe"
      require_archive_excludes "$DIST_DIR/ryk-v*-windows-amd64.zip"
      ;;
    host)
      case "$(detect_host_target)" in
        darwin-amd64)
          require_artifact "$DIST_DIR/ryk-v*-darwin-amd64.tar.gz"
          require_cli_archive "$DIST_DIR/ryk-v*-darwin-amd64.tar.gz"
          ;;
        darwin-arm64)
          require_artifact "$DIST_DIR/ryk-v*-darwin-arm64.tar.gz"
          require_cli_archive "$DIST_DIR/ryk-v*-darwin-arm64.tar.gz"
          ;;
        linux-amd64)
          require_artifact "$DIST_DIR/ryk-v*-linux-amd64.tar.gz"
          require_cli_archive "$DIST_DIR/ryk-v*-linux-amd64.tar.gz"
          ;;
        linux-arm64)
          require_artifact "$DIST_DIR/ryk-v*-linux-arm64.tar.gz"
          require_cli_archive "$DIST_DIR/ryk-v*-linux-arm64.tar.gz"
          ;;
        windows-amd64)
          require_artifact "$DIST_DIR/ryk-v*-windows-amd64.zip"
          require_archive_binary "$DIST_DIR/ryk-v*-windows-amd64.zip" "ryk.exe"
          forbid_archive_binary "$DIST_DIR/ryk-v*-windows-amd64.zip" "ryk-daemon.exe"
          require_archive_excludes "$DIST_DIR/ryk-v*-windows-amd64.zip"
          ;;
        *)
          fail "unsupported host target for host-only release verification"
          ;;
      esac
      ;;
    *)
      fail "unsupported RELEASE_PRODUCT=${RELEASE_PRODUCT}"
      ;;
  esac
}

[ -d "$DIST_DIR" ] || fail "missing dist dir: $DIST_DIR"
[ -s "$DIST_DIR/checksums.txt" ] || fail "missing checksums.txt"
[ -s "$DIST_DIR/release-manifest.json" ] || fail "missing release-manifest.json"
[ -s "$DIST_DIR/telemetry-contract.txt" ] || fail "missing telemetry-contract.txt"
[ -s "$DIST_DIR/sbom.json" ] || fail "missing sbom.json"
if [ "$RELEASE_PRODUCT" = "all" ]; then
  [ -s "$DIST_DIR/package-manifests/homebrew/Formula/ryk.rb" ] || fail "missing rendered Homebrew formula"
  [ -s "$DIST_DIR/package-manifests/npm/package.json" ] || fail "missing rendered npm package manifest"
  [ -s "$DIST_DIR/package-manifests/npm/bin/ryk.js" ] || fail "missing rendered npm launcher"
  [ -s "$DIST_DIR/package-manifests/scoop/ryk.json" ] || fail "missing rendered Scoop manifest"
  [ -s "$DIST_DIR/package-manifests/winget/ryk.yaml" ] || fail "missing rendered WinGet manifest"
fi
grep -q '"products_included"' "$DIST_DIR/release-manifest.json" || fail "release-manifest.json missing products_included"
grep -q '"ryk"' "$DIST_DIR/release-manifest.json" || fail "release-manifest.json missing ryk product"
sed -n '1p' "$DIST_DIR/telemetry-contract.txt" | grep -qx 'telemetry_schema_version=1' || fail "invalid telemetry contract schema"
grep -Eq '^transport=(enabled|disabled)$' "$DIST_DIR/telemetry-contract.txt" || fail "invalid telemetry contract transport"
sed -n '3p' "$DIST_DIR/telemetry-contract.txt" | grep -qx 'endpoint=https://us.i.posthog.com/batch/' || fail "invalid telemetry contract endpoint"
if [ "${RYK_RELEASE_LIVE:-0}" = "1" ]; then
  sed -n '2p' "$DIST_DIR/telemetry-contract.txt" | grep -qx 'transport=enabled' || fail "live release telemetry transport is disabled"
fi
# Daemon product was removed; packaging is CLI + core only (Zig shell_engine in-process).
if grep -q '"ryk-daemon"' "$DIST_DIR/release-manifest.json"; then
  fail "release-manifest.json still lists ryk-daemon product (removed from packaging)"
fi
if grep -q '"ryk-daemon"' "$DIST_DIR/sbom.json"; then
  fail "sbom.json still lists ryk-daemon component (removed from packaging)"
fi
if ! grep -q '"ryk"' "$DIST_DIR/sbom.json"; then
  fail "sbom.json missing ryk component"
fi
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$DIST_DIR" && sha256sum -c checksums.txt)
else
  (cd "$DIST_DIR" && shasum -a 256 -c checksums.txt)
fi

require_release_artifacts
grep -q '"signing_status"' "$DIST_DIR/release-manifest.json"
grep -q '"sbom_status"' "$DIST_DIR/release-manifest.json"
if [ "$RELEASE_PRODUCT" = "all" ]; then
  for rendered in \
    "$DIST_DIR/package-manifests/homebrew/Formula/ryk.rb" \
    "$DIST_DIR/package-manifests/npm/package.json" \
    "$DIST_DIR/package-manifests/scoop/ryk.json" \
    "$DIST_DIR/package-manifests/winget/ryk.yaml"
  do
    [ -f "$rendered" ] || continue
    ! grep -q 'PLACEHOLDER' "$rendered" || { printf 'release verify: placeholder left in %s\n' "$rendered" >&2; exit 1; }
  done
  require_package_hashes
fi

# Plugin version alignment check
CLI_VERSION="$(tr -d '[:space:]' < "${REPO_ROOT}/VERSION")"
HERMES_VERSION=$(grep "^version:" "${REPO_ROOT}/integrations/hermes-plugin/plugin.yaml" | sed 's/version: *//')
OPENCLAW_VERSION=$(grep '"version"' "${REPO_ROOT}/integrations/openclaw-plugin/package.json" | head -1 | sed 's/.*"version": *"\([^"]*\)".*/\1/')
CODEX_VERSION=$(grep '"version"' "${REPO_ROOT}/integrations/codex-plugin/.codex-plugin/plugin.json" | head -1 | sed 's/.*"version": *"\([^"]*\)".*/\1/')
CLAUDE_VERSION=$(grep '"version"' "${REPO_ROOT}/integrations/claude-code-plugin/.claude-plugin/plugin.json" | head -1 | sed 's/.*"version": *"\([^"]*\)".*/\1/')
OPENCODE_VERSION=$(grep '"version"' "${REPO_ROOT}/integrations/opencode-plugin/package.json" | head -1 | sed 's/.*"version": *"\([^"]*\)".*/\1/')
# Pi runtime dependency is the canonical @rykan/ryk package.
PI_RUNTIME_VERSION=$(grep '"@rykan/ryk"' "${REPO_ROOT}/ryk-pi/package.json" | head -1 | sed 's/.*"@rykan\/ryk": *"\([^"]*\)".*/\1/')
for plugin_version in "${HERMES_VERSION}" "${OPENCLAW_VERSION}" "${CODEX_VERSION}" "${CLAUDE_VERSION}" "${OPENCODE_VERSION}" "${PI_RUNTIME_VERSION}"; do
  if [ "${plugin_version}" != "${CLI_VERSION}" ]; then
    echo "ERROR: plugin version mismatch (expected ${CLI_VERSION}, got ${plugin_version})" >&2
    exit 1
  fi
done

printf 'release verify: passed\n'
printf 'Limitations: ryk release assets cover local CLI/runtime guardrails and fixed pseudonymous CLI telemetry; no hosted policy sync or cloud enforcement is included.\n'

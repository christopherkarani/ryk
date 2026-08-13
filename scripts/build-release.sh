#!/usr/bin/env sh
set -eu

# Canonical product brand is ryk (Rykan V).
if [ -n "${RYK_VERSION:-}" ]; then
  VERSION="$RYK_VERSION"
else
  VERSION="$(tr -d '[:space:]' <"$(dirname "$0")/../VERSION" 2>/dev/null)" || {
    printf 'build-release: VERSION is required (set RYK_VERSION or provide VERSION)\n' >&2
    exit 1
  }
fi
[ -f "$(dirname "$0")/../VERSION" ] && SOURCE_VERSION="$(tr -d '[:space:]' <"$(dirname "$0")/../VERSION")"
if [ -n "${SOURCE_VERSION:-}" ] && [ "$VERSION" != "$SOURCE_VERSION" ]; then
  printf 'build-release: RYK_VERSION (%s) must match VERSION (%s)\n' "$VERSION" "$SOURCE_VERSION" >&2
  exit 1
fi
[ -n "$VERSION" ] || {
  printf 'build-release: VERSION is empty\n' >&2
  exit 1
}
COMMIT="${RYK_COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || printf unknown)}"
BUILD_DATE="${RYK_BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
DIST_DIR="${RYK_DIST_DIR:-dist}"
ZIG_OPTIMIZE="${RYK_ZIG_OPTIMIZE:-ReleaseSafe}"
RELEASE_PRODUCT="${RYK_RELEASE_PRODUCT:-curl}"
CLI_ARTIFACT_DIR="${RYK_CLI_ARTIFACT_DIR:-}"
SIGNING_STATUS="not_configured"
TELEMETRY_BUILD_DISABLED="${RYK_TELEMETRY_BUILD_DISABLED:-0}"
POSTHOG_PROJECT_TOKEN="${RYK_POSTHOG_PROJECT_TOKEN:-}"
RELEASE_LIVE="${RYK_RELEASE_LIVE:-0}"

if [ "$RELEASE_LIVE" = "1" ] && [ "$TELEMETRY_BUILD_DISABLED" = "1" ]; then
  printf 'build-release: live releases cannot disable telemetry transport\n' >&2
  exit 1
fi
if [ "$TELEMETRY_BUILD_DISABLED" != "1" ] && [ -z "$POSTHOG_PROJECT_TOKEN" ]; then
  printf 'build-release: RYK_POSTHOG_PROJECT_TOKEN is required for a release build (or set RYK_TELEMETRY_BUILD_DISABLED=1 for a local dry-run)\n' >&2
  exit 1
fi
if [ "$TELEMETRY_BUILD_DISABLED" = "1" ]; then
  POSTHOG_PROJECT_TOKEN=""
fi

HOST_OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
HOST_ARCH="$(uname -m)"
case "$HOST_ARCH" in
x86_64) HOST_ARCH="amd64" ;;
aarch64 | arm64) HOST_ARCH="arm64" ;;
esac

# Artifact contract:
# - ryk-v{version}-darwin-amd64.tar.gz
# - ryk-v{version}-darwin-arm64.tar.gz
# - ryk-v{version}-linux-amd64.tar.gz
# - ryk-v{version}-linux-arm64.tar.gz
# - ryk-v{version}-windows-amd64.zip
# Archive roots contain one canonical CLI at bin/ryk (or bin/ryk.exe on Windows).

CLI_TARGETS="
darwin amd64 x86_64-macos tar.gz ryk
darwin arm64 aarch64-macos tar.gz ryk
linux amd64 x86_64-linux tar.gz ryk
linux arm64 aarch64-linux tar.gz ryk
windows amd64 x86_64-windows zip ryk.exe
"

selected_targets() {
  case "$RELEASE_PRODUCT" in
    all | cli | curl)
      printf '%s\n' "$CLI_TARGETS"
      ;;
    host)
      case "$HOST_OS-$HOST_ARCH" in
        darwin-amd64) printf 'darwin amd64 x86_64-macos tar.gz ryk\n' ;;
        darwin-arm64) printf 'darwin arm64 aarch64-macos tar.gz ryk\n' ;;
        linux-amd64) printf 'linux amd64 x86_64-linux tar.gz ryk\n' ;;
        linux-arm64) printf 'linux arm64 aarch64-linux tar.gz ryk\n' ;;
        windows-amd64) printf 'windows amd64 x86_64-windows zip ryk.exe\n' ;;
        *) printf 'build-release: unsupported host target for release dry-run: %s-%s\n' "$HOST_OS" "$HOST_ARCH" >&2; exit 1 ;;
      esac
      ;;
    *)
      printf 'build-release: unsupported RELEASE_PRODUCT=%s (expected curl, cli, all, or host)\n' "$RELEASE_PRODUCT" >&2
      exit 1
      ;;
  esac
}

target_platforms_json() {
  case "$RELEASE_PRODUCT" in
    all | cli | curl) printf '["darwin-amd64", "darwin-arm64", "linux-amd64", "linux-arm64", "windows-amd64"]' ;;
    host) printf '["%s-%s"]' "$HOST_OS" "$HOST_ARCH" ;;
    *) printf '[]' ;;
  esac
}

copy_cli_payload() {
  root="$1"
  ./scripts/test-openclaw-release-assets.sh
  [ -f "ryk-pi/extensions/ryk.ts" ] || {
    printf 'error: bundled Pi extension is missing ryk-pi/extensions/ryk.ts\n' >&2
    exit 1
  }
  [ -f "ryk-pi/extensions/secret_capture.ts" ] || {
    printf 'error: bundled Pi extension is missing ryk-pi/extensions/secret_capture.ts\n' >&2
    exit 1
  }
  [ -f "ryk-pi/extensions/parent_ask.ts" ] || {
    printf 'error: bundled Pi extension is missing ryk-pi/extensions/parent_ask.ts\n' >&2
    exit 1
  }
  mkdir -p "$root"
  bash ./scripts/stage-release-payload.sh "$(pwd)" "$root"
  if [ -d "ryk-dashboard-ui/dist" ]; then
    mkdir -p "$root/ryk-dashboard-ui"
    cp -R ryk-dashboard-ui/dist "$root/ryk-dashboard-ui/dist"
  elif [ -f "src/dashboard/assets/index.html" ]; then
    printf 'error: ryk-dashboard-ui/dist/ missing but legacy src/dashboard/assets/ exists.\n' >&2
    printf 'error: Run "npm ci && npm run build" in ryk-dashboard-ui/ before creating a release.\n' >&2
    printf 'error: The legacy fallback has been intentionally removed to prevent shipping the wrong dashboard.\n' >&2
    exit 1
  else
    printf 'warning: dashboard UI assets not found; ryk dashboard will be unavailable in this artifact.\n' >&2
  fi
  find "$root" -type d \( \
    -name node_modules -o \
    -name __pycache__ -o \
    -name .pytest_cache -o \
    -name .pnpm-store -o \
    -name .yarn -o \
    -name .turbo -o \
    -name .cache \
    \) -prune -exec rm -rf {} +
  find "$root" -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete
  rm -rf \
    "$root/.DS_Store" \
    "$root/docs/.DS_Store" \
    "$root/packages/.DS_Store" \
    "$root/examples/.DS_Store" \
    "$root/ryk-dashboard-ui/node_modules" 2>/dev/null || true
}

write_release_readme() {
  root="$1"
  title="ryk ${VERSION} Release Artifact"
  boundary="This archive contains the canonical ryk CLI, the bundled Pi extension, and the local policy, audit, replay, redaction, schema, integration, and packaging resources required by the product."
  cat >"$root/README-release.md" <<EOF
# ${title}

This artifact is built from commit ${COMMIT} at ${BUILD_DATE}.

Canonical CLI: \`bin/ryk\`.

Verify the archive against the top-level checksums.txt before installing:

\`\`\`sh
sha256sum -c checksums.txt
\`\`\`

${boundary}
EOF
}

write_telemetry_contract() {
  output="${DIST_DIR}/telemetry-contract.txt"
  {
    printf 'telemetry_schema_version=1\n'
    if [ "$TELEMETRY_BUILD_DISABLED" = "1" ]; then
      printf 'transport=disabled\n'
    else
      printf 'transport=enabled\n'
    fi
    printf 'endpoint=%s\n' 'https://us.i.posthog.com/batch/'
    printf 'lifecycle_events=%s\n' 'ryk_activation,ryk_setup_completed,ryk_setup_failed,ryk_feedback_submitted,ryk_update_completed,ryk_update_failed'
  } >"$output"
  printf 'Wrote %s\n' "$output"
}

# CLI-only archives: Zig shell_engine evaluates in-process (no ryk-daemon product binary).

install_cli() {
  # Copy the one canonical ryk binary into root/bin.
  os="$1"
  prefix="$2"
  root="$3"
  bin_name="$4"

  source="$prefix/bin/$bin_name"
  [ -f "$source" ] || {
    printf 'missing ryk binary: %s\n' "$source" >&2
    exit 1
  }
  cp "$source" "$root/bin/$bin_name"
  if [ "$os" != "windows" ]; then
    chmod 0755 "$root/bin/$bin_name"
  fi
}

verify_staged_cli_telemetry() {
  staged_path="$1"
  if [ "$TELEMETRY_BUILD_DISABLED" = "1" ]; then
    grep -aFq 'ryk-telemetry-transport-disabled-v1' "$staged_path" || {
      printf 'staged ryk binary is not transport-disabled: %s\n' "$staged_path" >&2
      exit 1
    }
    return 0
  fi
  grep -aFq 'ryk-telemetry-transport-enabled-v1' "$staged_path" || {
    printf 'staged ryk binary is not transport-enabled: %s\n' "$staged_path" >&2
    exit 1
  }
  grep -aFq "$POSTHOG_PROJECT_TOKEN" "$staged_path" || {
    printf 'staged ryk binary does not contain the configured PostHog transport token: %s\n' "$staged_path" >&2
    exit 1
  }
}

build_cli_target() {
  os="$1"
  arch="$2"
  zig_target="$3"
  ext="$4"
  bin_name="$5"

  artifact="ryk-v${VERSION}-${os}-${arch}.${ext}"
  work="${DIST_DIR}/work/cli-${os}-${arch}"
  prefix="${work}/prefix"
  root="${work}/ryk-v${VERSION}-${os}-${arch}"

  rm -rf "$work"
  mkdir -p "$prefix" "$root/bin"

  staged_cli="${CLI_ARTIFACT_DIR}/${os}-${arch}/${bin_name}"
  if [ -n "$CLI_ARTIFACT_DIR" ] && [ -f "$staged_cli" ]; then
    mkdir -p "$prefix/bin"
    cp -p "$staged_cli" "$prefix/bin/$bin_name"
    verify_staged_cli_telemetry "$staged_cli"
  else
    "$(dirname "$0")/zig" build install-ryk \
      -Dtarget="$zig_target" \
      -Doptimize="$ZIG_OPTIMIZE" \
      -Dversion="$VERSION" \
      -Dcommit="$COMMIT" \
      -Dbuild-date="$BUILD_DATE" \
      -Dposthog-project-token="$POSTHOG_PROJECT_TOKEN" \
      --prefix "$prefix"
  fi
  verify_staged_cli_telemetry "$prefix/bin/$bin_name"

  copy_cli_payload "$root"
  write_release_readme "$root"
  install_cli "$os" "$prefix" "$root" "$bin_name"
  # ryk-daemon removed: Zig shell_engine evaluates in-process.
  find "$root" -name .DS_Store -delete
  bash ./scripts/check-release-payload-secrets.sh "$root"

  if [ "$ext" = "zip" ]; then
    (cd "$work" && zip -qr "../../$artifact" "ryk-v${VERSION}-${os}-${arch}")
  else
    # COPYFILE_DISABLE=1 prevents macOS bsdtar from embedding extended attributes
    # (LIBARCHIVE.xattr.com.apple.provenance etc.) as PAX headers. This eliminates
    # the 80–120+ "Ignoring unknown extended header keyword" lines on Linux extracts
    # of mac-built release tarballs (Ubuntu 24.04 + Alpine curl|sh flow).
    COPYFILE_DISABLE=1 tar -C "$work" -czf "${DIST_DIR}/$artifact" "ryk-v${VERSION}-${os}-${arch}"
  fi
  printf 'Built %s\n' "${DIST_DIR}/$artifact"

}

write_release_manifest() {
  output="${DIST_DIR}/release-manifest.json"
  artifact_entries=""
  first=1
  for file in "${DIST_DIR}"/ryk-v*; do
    [ -f "$file" ] || continue
    name="$(basename "$file")"
    hash="$(awk -v name="$name" '$2 == name {print $1}' "${DIST_DIR}/checksums.txt")"
    [ -n "$hash" ] || {
      printf 'missing checksum for %s\n' "$name" >&2
      exit 1
    }
    if [ "$first" = "1" ]; then
      first=0
    else
      artifact_entries="${artifact_entries},"
    fi
    artifact_entries="${artifact_entries}
    {\"name\":\"${name}\",\"sha256\":\"${hash}\"}"
  done

  products_json="[\"ryk\", \"core\"]"
  runtime_assets_json="[\"schemas\", \"policies\", \"fixtures\", \"examples\", \"integrations\", \"packaging\", \"ryk-pi/extensions\"]"
  schemas_json="[\"schemas/policy-v1.json\", \"schemas/event-v1.json\", \"schemas/mcp-manifest-v1.json\"]"
  fixtures_json="[\"fixtures/shell-abuse/curl-pipe-sh\", \"examples/mcp\", \"examples/network\", \"examples/policies\"]"
  docs_json="[\"README.md\", \"docs/install.md\", \"README-release.md\"]"
  target_platforms="$(target_platforms_json)"
  safety_summary="ryk provides local CLI/runtime guardrails; release archives do not include hosted enforcement or telemetry."

  cat >"$output" <<EOF
{
  "release_version": "${VERSION}",
  "commit": "${COMMIT}",
  "build_date": "${BUILD_DATE}",
  "release_channel": "stable",
  "products_included": ${products_json},
  "artifacts": [${artifact_entries}
  ],
  "checksums": "checksums.txt",
  "telemetry_contract": "telemetry-contract.txt",
  "target_platforms": ${target_platforms},
  "required_runtime_assets": ${runtime_assets_json},
  "schemas_included": ${schemas_json},
  "fixtures_included": ${fixtures_json},
  "docs_included": ${docs_json},
  "safety_boundary_summary": "${safety_summary}",
  "known_limitations_path": null,
  "generated_by": "scripts/build-release.sh",
  "signing_status": "${SIGNING_STATUS}",
  "sbom_status": "hook-only inventory generated at sbom.json",
  "primary_cli": "ryk"
}
EOF
  printf 'Wrote %s\n' "$output"
}

cleanup_attempts=0
while [ -d "$DIST_DIR" ] && [ "$cleanup_attempts" -lt 5 ]; do
  find "$DIST_DIR" -name .DS_Store -type f -delete 2>/dev/null || true
  rm -rf "$DIST_DIR" 2>/dev/null || true
  cleanup_attempts=$((cleanup_attempts + 1))
  [ ! -d "$DIST_DIR" ] || sleep 1
done
[ ! -d "$DIST_DIR" ] || {
  printf 'could not clean release directory: %s\n' "$DIST_DIR" >&2
  exit 1
}
mkdir -p "$DIST_DIR"

printf '%s\n' "$(selected_targets)" | while read -r os arch zig_target ext bin_name; do
  [ -n "${os:-}" ] || continue
  build_cli_target "$os" "$arch" "$zig_target" "$ext" "$bin_name"
done

write_telemetry_contract

if [ "${RYK_SIGNING_ENABLED:-0}" = "1" ]; then
  if [ -n "${RYK_SIGNING_COMMAND:-}" ]; then
    SIGNING_STATUS="signed"
    sh -c "$RYK_SIGNING_COMMAND" sh "$DIST_DIR"
  else
    printf 'Signing requested but RYK_SIGNING_COMMAND is not set.\n' >&2
    exit 1
  fi
else
  SIGNING_STATUS="signing hook available; not configured"
  printf 'Signing skipped; set RYK_SIGNING_ENABLED=1 (or RYK_SIGNING_ENABLED) and signing command in release environments.\n'
fi

./scripts/generate-checksums.sh "$DIST_DIR"
if [ "$RELEASE_PRODUCT" = "all" ]; then
  RYK_DIST_DIR="$DIST_DIR" ./scripts/render-package-manifests.sh
fi
RYK_RELEASE_PRODUCT="$RELEASE_PRODUCT" ./scripts/generate-sbom.sh "$DIST_DIR"

write_release_manifest
rm -rf "$DIST_DIR/work"
rm -rf "$DIST_DIR/daemon-artifacts"

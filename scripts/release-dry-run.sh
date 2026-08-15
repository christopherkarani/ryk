#!/usr/bin/env sh
set -eu

DIST_DIR="${RYK_DIST_DIR:-dist-dry-run}"
SIZE_BASELINE_FILE="${RYK_BINARY_SIZE_BASELINE:-docs/dev/binary-size-baseline.tsv}"

file_size_bytes() {
  if stat -f%z "$1" >/dev/null 2>&1; then
    stat -f%z "$1"
  else
    stat -c%s "$1"
  fi
}

# Archive names are ryk-vVERSION-os-arch.ext. Lookup is by os-arch + binary
# so a VERSION bump still matches. Missing row still passes (establishing).
# P0 does not fail on growth.
os_arch_from_archive() {
  printf '%s\n' "$1" | sed -E 's/^ryk-v[0-9][0-9.]*-//; s/\.tar\.gz$//; s/\.zip$//'
}

baseline_size_for() {
  [ -f "$SIZE_BASELINE_FILE" ] || return 1
  os_arch="$(os_arch_from_archive "$1")"
  awk -F '\t' -v os_arch="$os_arch" -v binary="$2" '$1 == os_arch && $2 == binary {print $3; found=1} END {exit found ? 0 : 1}' "$SIZE_BASELINE_FILE"
}

report_binary_sizes() {
  tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/ryk-size.XXXXXX")"
  trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM
  current_baseline="${DIST_DIR}/binary-size-baseline.tsv"
  : >"$current_baseline"

  printf 'release dry-run: binary size report\n'
  found=0
  for artifact in "$DIST_DIR"/ryk-v*.tar.gz "$DIST_DIR"/ryk-v*.zip; do
    [ -f "$artifact" ] || continue
    found=1
    artifact_name="$(basename "$artifact")"
    extract_dir="${tmp_dir}/${artifact_name}"
    mkdir -p "$extract_dir"
    case "$artifact" in
    *.tar.gz) tar -xzf "$artifact" -C "$extract_dir" ;;
    *.zip) unzip -q "$artifact" -d "$extract_dir" ;;
    esac
    for binary in ryk ryk.exe; do
      path="$(find "$extract_dir" -path "*/bin/$binary" -type f | head -n 1)"
      [ -n "$path" ] || continue
      size="$(file_size_bytes "$path")"
      printf '%s\t%s\t%s\n' "$artifact_name" "$binary" "$size" >>"$current_baseline"
      if baseline="$(baseline_size_for "$artifact_name" "$binary" 2>/dev/null)"; then
        delta=$((size - baseline))
        printf '  %s %s: %s bytes (baseline %s, delta %+d)\n' "$artifact_name" "$binary" "$size" "$baseline" "$delta"
      else
        printf '  %s %s: %s bytes (no prior baseline; establishing)\n' "$artifact_name" "$binary" "$size"
      fi
    done
  done
  [ "$found" = "1" ] || {
    printf 'release dry-run: no release archives found for binary-size report\n' >&2
    exit 1
  }
  printf 'release dry-run: wrote current binary-size baseline to %s\n' "$current_baseline"
}

# Verifies release archive checksums through scripts/verify-release.sh.
# Local/CI dry-run is packaging + layout only. Do not require a live PostHog
# token; live cut-release still refuses RYK_TELEMETRY_BUILD_DISABLED=1.
if [ -z "${RYK_POSTHOG_PROJECT_TOKEN:-}" ]; then
  export RYK_TELEMETRY_BUILD_DISABLED="${RYK_TELEMETRY_BUILD_DISABLED:-1}"
fi
printf 'release dry-run: building artifacts into %s\n' "$DIST_DIR"
RYK_RELEASE_PRODUCT=host RYK_DIST_DIR="$DIST_DIR" ./scripts/build-release.sh
RYK_RELEASE_PRODUCT=host ./scripts/verify-release.sh "$DIST_DIR"
RYK_DIST_DIR="$DIST_DIR" ./scripts/install-layout-smoke-test.sh
report_binary_sizes
if [ "$(uname -s)" = "Linux" ] && command -v docker >/dev/null 2>&1; then
  RYK_DIST_DIR="$DIST_DIR" ./scripts/docker-install-layout-smoke-test.sh
fi

printf 'release dry-run: passed\n'
printf 'Limitations: this checks local packaging and install layout only; it does not publish artifacts or exercise host-specific runtime enforcement.\n'

#!/usr/bin/env bash
# Build Linux ryk CLI binaries (amd64 + arm64) and stage them for
# scripts/build-release.sh (RYK_CLI_ARTIFACT_DIR).
#
# Layout written:
#   $OUT_DIR/linux-amd64/ryk
#   $OUT_DIR/linux-arm64/ryk
#
# OUT_DIR must NOT live under dist/ if you then run build-release.sh — that script
# wipes dist/. Prefer .release-cli-bins/ (cut-release default).
#
# Paths:
#   Default: Docker buildx (linux/amd64 + linux/arm64).
#   RYK_LINUX_HOST_CROSS=1: host Zig cross-compile (preferred on Apple Silicon —
#     Docker+Rosetta often dies with "bss_size overflow" on x86_64 Zig).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUT_DIR="${1:-${RYK_LINUX_ARTIFACT_DIR:-${REPO_ROOT}/.release-cli-bins}}"
VERSION="${RYK_VERSION:-$(tr -d '[:space:]' <"${REPO_ROOT}/VERSION")}"
COMMIT="${RYK_COMMIT:-$(git -C "${REPO_ROOT}" rev-parse --short=12 HEAD)}"
BUILD_DATE="${RYK_BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
TELEMETRY_BUILD_DISABLED="${RYK_TELEMETRY_BUILD_DISABLED:-0}"
POSTHOG_PROJECT_TOKEN="${RYK_POSTHOG_PROJECT_TOKEN:-}"
RELEASE_LIVE="${RYK_RELEASE_LIVE:-0}"
HOST_CROSS="${RYK_LINUX_HOST_CROSS:-0}"

if [[ "$RELEASE_LIVE" == "1" && "$TELEMETRY_BUILD_DISABLED" == "1" ]]; then
  echo "build-linux-release-docker: live releases cannot disable telemetry transport" >&2
  exit 1
fi
if [[ "$TELEMETRY_BUILD_DISABLED" != "1" && -z "$POSTHOG_PROJECT_TOKEN" ]]; then
  echo "build-linux-release-docker: RYK_POSTHOG_PROJECT_TOKEN is required for release binaries (or set RYK_TELEMETRY_BUILD_DISABLED=1 for a local dry-run)" >&2
  exit 1
fi
if [[ "$TELEMETRY_BUILD_DISABLED" == "1" ]]; then
  POSTHOG_PROJECT_TOKEN=""
fi

# Auto host-cross on Apple Silicon: Docker linux/amd64 under Rosetta is unreliable
# with Zig 0.16 (bss_size overflow). Override with RYK_LINUX_HOST_CROSS=0 to force Docker.
if [[ "$HOST_CROSS" != "1" && "$HOST_CROSS" != "0" ]]; then
  HOST_CROSS=0
fi
if [[ "$HOST_CROSS" != "1" && "$(uname -s)" == "Darwin" && "$(uname -m)" == "arm64" && "${RYK_LINUX_HOST_CROSS:-}" != "0" ]]; then
  HOST_CROSS=1
  echo "build-linux-release-docker: Darwin arm64 → host Zig cross-compile (set RYK_LINUX_HOST_CROSS=0 to force Docker)"
fi

stage_bin() {
  local arch="$1"
  local src="$2"
  mkdir -p "${OUT_DIR}/linux-${arch}"
  if [[ ! -x "$src" ]]; then
    echo "build-linux-release-docker: missing binary at ${src}" >&2
    exit 1
  fi
  cp -p "$src" "${OUT_DIR}/linux-${arch}/ryk"
  chmod 0755 "${OUT_DIR}/linux-${arch}/ryk"
  if [[ -e "${OUT_DIR}/linux-${arch}/ryk-daemon" ]]; then
    echo "build-linux-release-docker: unexpected ryk-daemon under ${OUT_DIR}/linux-${arch}" >&2
    exit 1
  fi
  file "${OUT_DIR}/linux-${arch}/ryk"
}

if [[ "$HOST_CROSS" == "1" ]]; then
  rm -rf "${OUT_DIR}"
  mkdir -p "${OUT_DIR}"
  TMP_PREFIX="$(mktemp -d "${TMPDIR:-/tmp}/ryk-linux-host-cross.XXXXXX")"
  cleanup() {
    rm -rf "${TMP_PREFIX}"
  }
  trap cleanup EXIT INT TERM

  for arch in amd64 arm64; do
    case "$arch" in
      amd64) zig_target=x86_64-linux ;;
      arm64) zig_target=aarch64-linux ;;
      *) echo "build-linux-release-docker: unsupported arch ${arch}" >&2; exit 1 ;;
    esac
    prefix="${TMP_PREFIX}/${arch}"
    echo "Building linux-${arch} ryk via host Zig cross (${zig_target})"
    (
      cd "${REPO_ROOT}"
      ./scripts/zig build install-ryk \
        -Dtarget="${zig_target}" \
        -Doptimize=ReleaseSafe \
        -Dversion="${VERSION}" \
        -Dcommit="${COMMIT}" \
        -Dbuild-date="${BUILD_DATE}" \
        -Dposthog-project-token="${POSTHOG_PROJECT_TOKEN}" \
        --prefix "${prefix}"
    )
    stage_bin "$arch" "${prefix}/bin/ryk"
  done
  echo "Host-cross Linux release binaries staged in ${OUT_DIR}"
  exit 0
fi

command -v docker >/dev/null 2>&1 || {
  echo "build-linux-release-docker: docker is required" >&2
  exit 1
}
docker info >/dev/null 2>&1 || {
  echo "build-linux-release-docker: docker daemon is unavailable" >&2
  exit 1
}

# Each buildx local export replaces the dest tree; merge per-arch into OUT_DIR.
rm -rf "${OUT_DIR}"
mkdir -p "${OUT_DIR}"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/ryk-linux-docker.XXXXXX")"
cleanup() {
  rm -rf "${TMP_ROOT}"
}
trap cleanup EXIT INT TERM

for arch in amd64 arm64; do
  echo "Building linux-${arch} ryk binaries with Docker"
  arch_out="${TMP_ROOT}/linux-${arch}"
  mkdir -p "${arch_out}"
  docker buildx build \
    --platform "linux/${arch}" \
    --build-arg "RYK_VERSION=${VERSION}" \
    --build-arg "RYK_COMMIT=${COMMIT}" \
    --build-arg "RYK_BUILD_DATE=${BUILD_DATE}" \
    --build-arg "RYK_POSTHOG_PROJECT_TOKEN=${POSTHOG_PROJECT_TOKEN}" \
    --file "${REPO_ROOT}/packaging/docker/Dockerfile.release" \
    --output "type=local,dest=${arch_out}" \
    "${REPO_ROOT}"

  # Image root is /out/linux-$TARGETARCH → local export may nest as linux-$arch/...
  staged=""
  if [[ -x "${arch_out}/linux-${arch}/ryk" ]]; then
    staged="${arch_out}/linux-${arch}"
  elif [[ -x "${arch_out}/ryk" ]]; then
    staged="${arch_out}"
  else
    echo "build-linux-release-docker: could not find ryk under ${arch_out}" >&2
    find "${arch_out}" -type f 2>/dev/null | head -40 >&2 || true
    exit 1
  fi

  stage_bin "$arch" "${staged}/ryk"
done

echo "Docker-built Linux release binaries staged in ${OUT_DIR}"

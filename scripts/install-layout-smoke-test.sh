#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DIST_DIR="${RYK_DIST_DIR:-dist}"
VERSION="$(tr -d '[:space:]' <"${REPO_ROOT}/VERSION")"

detect_os() {
  case "$(uname -s)" in
  Darwin) printf 'darwin' ;;
  Linux) printf 'linux' ;;
  *) printf 'unsupported' ;;
  esac
}

detect_arch() {
  case "$(uname -m)" in
  x86_64 | amd64) printf 'amd64' ;;
  arm64 | aarch64) printf 'arm64' ;;
  *) printf 'unsupported' ;;
  esac
}

fail() {
  printf 'install-layout-smoke: %s\n' "$1" >&2
  exit 1
}

assert_contains() {
  local haystack="$1"
  local needle="$2"
  if [[ "${haystack}" != *"${needle}"* ]]; then
    fail "expected output to contain: ${needle}"
  fi
}

OS="$(detect_os)"
ARCH="$(detect_arch)"
[[ "${OS}" != "unsupported" ]] || fail "unsupported host OS for smoke test"
[[ "${ARCH}" != "unsupported" ]] || fail "unsupported host architecture for smoke test"

ARTIFACT="${DIST_DIR}/ryk-v${VERSION}-${OS}-${ARCH}.tar.gz"
[[ -f "${ARTIFACT}" ]] || fail "missing host artifact: ${ARTIFACT}"

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/ryk-install-layout.XXXXXX")"
cleanup() {
  rm -rf "${TMP_ROOT}"
}
trap cleanup EXIT INT TERM

tar -xzf "${ARTIFACT}" -C "${TMP_ROOT}"
STAGE_ROOT="${TMP_ROOT}/ryk-v${VERSION}-${OS}-${ARCH}"
[[ -d "${STAGE_ROOT}" ]] || fail "staged archive root not found under ${TMP_ROOT}"

RYK_BIN="${STAGE_ROOT}/bin/ryk"
# Product packaging is CLI-only; Zig shell_engine evaluates shell in-process.
[[ -x "${RYK_BIN}" ]] || fail "staged ryk binary is missing or not executable"
[[ ! -e "${STAGE_ROOT}/bin/orca" ]] || fail "staged release contains a removed orca binary alias"
if [[ -e "${STAGE_ROOT}/bin/ryk-daemon" ]]; then
  fail "staged release unexpectedly contains ryk-daemon (daemon removed from product packaging)"
fi

TMP_HOME="${TMP_ROOT}/home"
mkdir -p "${TMP_HOME}/workspace"

export HOME="${TMP_HOME}"
export PATH="${STAGE_ROOT}/bin:${PATH}"
export RYK_RESOURCE_ROOT="${STAGE_ROOT}"

version_output="$("${RYK_BIN}" version)"
assert_contains "${version_output}" "Version"
assert_contains "${version_output}" "${VERSION}"

# Doctor should run without a companion daemon binary in the archive.
doctor_output="$("${RYK_BIN}" doctor --verbose)"
assert_contains "${doctor_output}" "ryk Doctor"
assert_contains "${doctor_output}" "Version: ${VERSION}"

"${RYK_BIN}" packs --help >/dev/null

dangerous_fixture="${REPO_ROOT}/tests/plugin-fixtures/claude/pre_tool_use_command_dangerous.json"
safe_fixture="${REPO_ROOT}/tests/plugin-fixtures/claude/pre_tool_use_command_safe.json"
[[ -f "${dangerous_fixture}" ]] || fail "missing dangerous hook fixture"
[[ -f "${safe_fixture}" ]] || fail "missing safe hook fixture"

# Shell PreToolUse is owned by in-process Zig shell_engine (not a daemon IPC path).
# Claude tool-gating stdout is host-shaped hookSpecificOutput.permissionDecision
# (deny/allow), not generic ryk {"decision":"block"}. See
# docs/integrations/host-decision-mapping.md.
dangerous_output="$("${RYK_BIN}" hook claude PreToolUse <"${dangerous_fixture}")"
if ! grep -Eq '"permissionDecision"[[:space:]]*:[[:space:]]*"deny"' <<<"${dangerous_output}"; then
  fail "dangerous Claude PreToolUse did not emit permissionDecision=deny"
fi

safe_output="$("${RYK_BIN}" hook claude PreToolUse <"${safe_fixture}")"
if ! grep -Eq '"permissionDecision"[[:space:]]*:[[:space:]]*"allow"' <<<"${safe_output}"; then
  fail "safe Claude PreToolUse did not emit permissionDecision=allow"
fi
# Daemon-unavailable fail-closed narrative is obsolete for shell hooks.
if [[ "${safe_output}" == *"daemon unavailable"* ]]; then
  fail "safe hook decision unexpectedly cited daemon unavailable (shell_engine path)"
fi

[[ -d "${STAGE_ROOT}/ryk-dashboard-ui/dist" ]] || fail "staged release missing ryk-dashboard-ui/dist"
[[ -f "${STAGE_ROOT}/ryk-dashboard-ui/dist/index.html" ]] || fail "staged dashboard bundle missing index.html"

assert_dashboard_bundle_contains() {
  local marker="$1"
  if ! grep -R -F -q -- "${marker}" "${STAGE_ROOT}/ryk-dashboard-ui/dist"; then
    fail "staged dashboard bundle missing machine-wide marker: ${marker}"
  fi
}

assert_dashboard_bundle_contains "machine-wide-capable"
assert_dashboard_bundle_contains "workspace-root-and-id"
assert_dashboard_bundle_contains "Activity feed is degraded"

printf '[install-layout-smoke] passed for %s-%s\n' "${OS}" "${ARCH}"

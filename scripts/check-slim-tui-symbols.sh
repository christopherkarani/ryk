#!/usr/bin/env bash
# Prove `-Dtui=false` ReleaseSafe `ryk` does not link vaxis/uucode.
#
# ReleaseSafe applies `-fstrip`, so `nm` may be empty; `strings` is the
# surviving proof. Distinctive linker / log-scope / package names only —
# help still says "libvaxis" and "TUI" on the slim profile.
#
# Usage:
#   ./scripts/check-slim-tui-symbols.sh
#
# Wired from verify-pre-merge.sh, not test-fast (slim ReleaseSafe is heavy).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

fail() {
  printf 'check-slim-tui-symbols: FAIL: %s\n' "$*" >&2
  exit 1
}

command -v nm >/dev/null 2>&1 || fail "nm is required"
command -v strings >/dev/null 2>&1 || fail "strings is required"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/ryk-slim-tui-symbols.XXXXXX")"
cleanup() {
  rm -rf "${WORK}"
}
trap cleanup EXIT INT TERM

# Isolated prefix so this check does not replace zig-out/bin/ryk (TUI-on Debug
# from test-fast / local iteration) with a slim ReleaseSafe binary.
printf '[check-slim-tui-symbols] ./scripts/zig build install-ryk -Dtui=false -Doptimize=ReleaseSafe\n'
./scripts/zig build install-ryk -Dtui=false -Doptimize=ReleaseSafe --prefix "${WORK}"

BIN="${WORK}/bin/ryk"
if [[ ! -f "${BIN}" ]]; then
  # Fallback when a host install layout uses zig-out instead of --prefix.
  BIN="${REPO_ROOT}/zig-out/bin/ryk"
fi
[[ -f "${BIN}" && -x "${BIN}" ]] || fail "missing executable (tried ${WORK}/bin/ryk and ${REPO_ROOT}/zig-out/bin/ryk)"

# Do not match bare "vaxis" (help: "libvaxis") or "TUI".
# TUI-on bins actually emit vaxis_parser / log.scoped(.vaxis*) / zig-pkg/vaxis-*.
PATTERN='vaxis\.|\.vaxis|vaxis_|vaxis-|uucode\.|uucode_|uucode-'

report_matches() {
  local label="$1"
  local file="$2"
  local matches
  matches="$(LC_ALL=C grep -E -- "${PATTERN}" "${file}" || true)"
  if [[ -n "${matches}" ]]; then
    printf '%s\n' "${matches}" | head -n 20 >&2
    fail "${label} contains vaxis/uucode markers"
  fi
}

# llvm-nm / BSD nm may exit non-zero on a fully stripped image ("no name list").
# That is not a pass by itself — strings must still be clean.
if ! nm -a "${BIN}" >"${WORK}/nm.txt" 2>"${WORK}/nm.err"; then
  err="$(tr -d '\r' <"${WORK}/nm.err" || true)"
  case "${err}" in
    *"no symbols"*|*"no name list"*|*"no symbols in"*|'')
      : # stripped or empty table; strings is the remaining proof
      ;;
    *)
      fail "nm could not read ${BIN}: ${err}"
      ;;
  esac
fi
report_matches "nm ${BIN}" "${WORK}/nm.txt"

strings -a "${BIN}" >"${WORK}/strings.txt" || fail "strings failed on ${BIN}"
report_matches "strings ${BIN}" "${WORK}/strings.txt"

printf '[check-slim-tui-symbols] ok (no vaxis/uucode symbols in %s)\n' "${BIN}"

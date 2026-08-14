#!/usr/bin/env bash
# Run a domain-sliced Zig unit gate (or filtered monopath) for coding agents.
#
# Zig 0.16 applies filters at *compile* time via -Dtest-filter=… (not runtime
# `-- --test-filter` on the terminal test runner — that ABRTs).
#
# Usage:
#   ./scripts/test-slice.sh sandbox
#   ./scripts/test-slice.sh policy
#   ./scripts/test-slice.sh intercept
#   ./scripts/test-slice.sh lib
#   ./scripts/test-slice.sh core
#   ./scripts/test-slice.sh sandbox --filter Seatbelt
#   ./scripts/test-slice.sh lib --filter Spinner
#   ./scripts/test-slice.sh sandbox --compile-only
#
# See CONTRIBUTING.md for the repository verification gates.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

slice=""
filter=""
compile_only=0

usage() {
  cat >&2 <<'EOF'
usage: ./scripts/test-slice.sh SLICE [--filter SUBSTR] [--compile-only]

Slices:
  sandbox     ./scripts/zig build test-sandbox      (src/sandbox only)
  policy      ./scripts/zig build test-policy       (ryk_core policy)
  intercept   ./scripts/zig build test-intercept    (src/intercept only)
  lib         ./scripts/zig build test-lib          (full monopath, slow)
  core        ./scripts/zig build test-core
              --compile-only → compile-test-core (engine addTest only)
  core-contract  ./scripts/zig build test-core-contract
  fast        ./scripts/zig build test-fast         (lib + core chain, slow)

Options:
  --filter SUBSTR   -Dtest-filter=SUBSTR (compile-time name substring)
  --compile-only    compile the slice test binary without running
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --filter)
      shift
      [[ $# -gt 0 ]] || { echo "error: --filter needs a value" >&2; exit 2; }
      filter="$1"
      shift
      ;;
    --compile-only) compile_only=1; shift ;;
    sandbox|policy|intercept|lib|core|core-contract|fast)
      slice="$1"
      shift
      ;;
    *)
      echo "error: unknown arg: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ -z "${slice}" ]]; then
  usage
  exit 2
fi

step=""
case "${slice}" in
  sandbox) step=$([[ "${compile_only}" -eq 1 ]] && echo compile-test-sandbox || echo test-sandbox) ;;
  policy) step=test-policy; [[ "${compile_only}" -eq 1 ]] && { echo "error: policy maps to test-core gates (no separate compile-only)" >&2; exit 2; } ;;
  intercept) step=$([[ "${compile_only}" -eq 1 ]] && echo compile-test-intercept || echo test-intercept) ;;
  lib) step=$([[ "${compile_only}" -eq 1 ]] && echo compile-test-lib || echo test-lib) ;;
  core) step=$([[ "${compile_only}" -eq 1 ]] && echo compile-test-core || echo test-core) ;;
  core-contract) step=test-core-contract; [[ "${compile_only}" -eq 1 ]] && { echo "error: core-contract has no compile-only step" >&2; exit 2; } ;;
  fast) step=$([[ "${compile_only}" -eq 1 ]] && echo compile-test-fast || echo test-fast) ;;
esac

# Run modes serial; compile-only can use default -j via no -j1 when compile_only.
if [[ "${compile_only}" -eq 1 ]]; then
  ZIG_BUILD=(./scripts/zig build -fincremental -Dincremental=true)
else
  ZIG_BUILD=(./scripts/zig build -fincremental -j1 -Dincremental=true)
fi

if [[ -n "${filter}" ]]; then
  ZIG_BUILD+=(-Dtest-filter="${filter}")
fi

echo "[test-slice] slice=${slice} step=${step} filter=${filter:-<none>} compile_only=${compile_only}"
start_ts=$(date +%s)
"${ZIG_BUILD[@]}" "${step}"
elapsed=$(( $(date +%s) - start_ts ))
echo "[test-slice] OK (${slice}) in ${elapsed}s"

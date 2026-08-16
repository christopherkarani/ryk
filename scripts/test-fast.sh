#!/usr/bin/env bash
# Fast local verification for policy/CLI/core changes (Zig 0.16.0).
#
# Modes (narrowest first):
#   compile  — toolchain check + build CLI + compile test-fast artifacts (no run)
#   units    — compile mode + run test-fast unit binaries (lib + ryk_core)
#   full     — units + quick-install / generic-agent policy matrix (default)
#
# Usage:
#   ./scripts/test-fast.sh              # full (default)
#   ./scripts/test-fast.sh full
#   ./scripts/test-fast.sh units
#   ./scripts/test-fast.sh compile
#   RYK_TEST_FAST=units ./scripts/test-fast.sh
#
# Prefer ./scripts/compile-fast.sh check for pure compile iteration.
# Prefer ./scripts/agent-gate.sh to pick a gate from dirty paths.
# Use ./scripts/zig build test or ./scripts/verify-pre-merge.sh before merge/CI.
# See Agents.md → "Verification gates".
#
# Note: L1 units are often multi-minute (large monopath lib test binary). Long
# silent stretches used to mean a pathological OOM-fail test — if silence lasts
# many minutes with high CPU, sample the test PID (see Agents.md pitfalls).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

# Incremental compile; -j1 keeps test binary runs serial (parallel hangs on some hosts).
# One `zig build` evaluates the graph once: default `install` (CLI) plus the
# requested test-fast step. Do not split into a second process entry.
ZIG_BUILD=(./scripts/zig build -fincremental -j1 -Dincremental=true)

mode="${1:-${RYK_TEST_FAST:-full}}"
case "${mode}" in
  full|units|compile) ;;
  *)
    echo "usage: $0 [compile|units|full]" >&2
    echo "  or: RYK_TEST_FAST=compile|units|full $0" >&2
    exit 2
    ;;
esac

step_start=0
step_begin() {
  step_start=$(date +%s)
  echo "[test-fast] $*"
}
step_end() {
  local label="$1"
  local elapsed=$(( $(date +%s) - step_start ))
  echo "[test-fast] ${label} done in ${elapsed}s"
}

gate_start=$(date +%s)
echo "[test-fast] mode=${mode}"

step_begin "Toolchain check (want 0.16.0 from .zigversion)"
./scripts/ensure-zig-toolchain.sh --check
step_end "toolchain"

if [[ "${mode}" == "compile" ]]; then
  step_begin "Build ryk CLI + compile test-fast artifacts (no run)"
  "${ZIG_BUILD[@]}" install compile-test-fast
  step_end "build+compile-test-fast"
  total=$(( $(date +%s) - gate_start ))
  echo "[test-fast] Compile-only gate passed in ${total}s."
  exit 0
fi

step_begin "Build ryk CLI + unit tests (lib + ryk_core via test-fast)"
"${ZIG_BUILD[@]}" install test-fast
step_end "build+units"

if [[ "${mode}" == "units" ]]; then
  total=$(( $(date +%s) - gate_start ))
  echo "[test-fast] Units gate passed in ${total}s."
  exit 0
fi

step_begin "Quick-install / generic-agent policy matrix"
./scripts/quick-install-dx-verify.sh
step_end "quick-install"

step_begin "Token-enabled telemetry release contract"
./scripts/test-telemetry-release-contract.sh
step_end "telemetry-release-contract"

total=$(( $(date +%s) - gate_start ))
echo "[test-fast] All full fast checks passed in ${total}s."

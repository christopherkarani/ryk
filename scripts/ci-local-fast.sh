#!/usr/bin/env bash
# Local mirror of the *fast* PR signal (not full matrix / full zig test).
#
#   - Zig: install + test-fast units (lib+core chain) + test-shell-engine
#     in one `zig build` (toolchain check is not a zig build)
#
# Usage:
#   ./scripts/ci-local-fast.sh
#   ./scripts/ci-local-fast.sh --zig-only
#
# Full suite remains: ./scripts/zig build test / ./scripts/verify-pre-merge.sh
# See Agents.md → Verification gates.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-rust|--rust-only)
      echo "warning: Rust daemon removed; ignoring $1" >&2
      shift
      ;;
    --zig-only) shift ;;
    -h|--help)
      echo "usage: $0 [--zig-only]" >&2
      exit 0
      ;;
    *)
      echo "error: unknown arg: $1" >&2
      exit 2
      ;;
  esac
done

# Incremental compile; -j1 keeps test binary runs serial (parallel hangs on some hosts).
ZIG_BUILD=(./scripts/zig build -fincremental -j1 -Dincremental=true)

gate_start=$(date +%s)

echo "[ci-local-fast] Toolchain check"
./scripts/ensure-zig-toolchain.sh --check

echo "[ci-local-fast] Zig units + shell_engine (install test-fast test-shell-engine)"
"${ZIG_BUILD[@]}" install test-fast test-shell-engine

total=$(( $(date +%s) - gate_start ))
echo "[ci-local-fast] OK in ${total}s"

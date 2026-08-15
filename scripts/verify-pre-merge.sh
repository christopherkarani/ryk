#!/usr/bin/env bash
# Pre-merge verification: fast gate + full test suite (Zig 0.16.0).
#
# Usage:
#   ./scripts/verify-pre-merge.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${REPO_ROOT}"

echo "[verify-pre-merge] Fast gate"
./scripts/test-fast.sh

echo "[verify-pre-merge] Full test suite (plugins/setup/fuzz)"
./scripts/zig build test

# OpenClaw ships committed dist/; require freshness when plugin deps are present.
if [[ -x integrations/openclaw-plugin/node_modules/.bin/tsc ]]; then
  echo "[verify-pre-merge] OpenClaw release assets"
  ./scripts/test-openclaw-release-assets.sh
else
  echo "[verify-pre-merge] skip openclaw release assets (plugin node_modules/.bin/tsc missing)"
fi

# Dispatcher contract always runs (sign) arm). Crypto installer tests skip only
# when no minisign/rsign is installed; a skip must not bypass the dispatcher check.
echo "[verify-pre-merge] Release signing contract"
./scripts/test-release-signing.sh
grep -qE '^[[:space:]]*sign\)[[:space:]]+phase_sign' scripts/cut-release.sh \
  || { echo "cut-release.sh run_phase is missing sign) phase_sign" >&2; exit 1; }

# Homebrew formula contract (offline). The public tap is not published yet.
echo "[verify-pre-merge] Homebrew formula contract"
./scripts/test-homebrew-formula.sh

echo "[verify-pre-merge] First-user install and uninstall regressions"
./scripts/install-first-user-regression-test.sh
./scripts/uninstall-first-user-regression-test.sh

# Slim ReleaseSafe rebuild is too heavy for test-fast units. Isolates to a
# prefix so it does not replace zig-out/bin/ryk from the gates above.
echo "[verify-pre-merge] Slim -Dtui=false ReleaseSafe has no vaxis/uucode symbols"
./scripts/check-slim-tui-symbols.sh

echo "[verify-pre-merge] All checks passed."

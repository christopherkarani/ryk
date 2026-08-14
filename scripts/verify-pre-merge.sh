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

# The installer must refuse a release it cannot authenticate. Skips loudly when no
# minisign/rsign is installed rather than passing silently.
echo "[verify-pre-merge] Release signing contract"
./scripts/test-release-signing.sh

echo "[verify-pre-merge] First-user install and uninstall regressions"
./scripts/install-first-user-regression-test.sh
./scripts/uninstall-first-user-regression-test.sh

echo "[verify-pre-merge] All checks passed."

#!/usr/bin/env sh
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PLUGIN_DIR="${REPO_ROOT}/integrations/openclaw-plugin"
TSC="${PLUGIN_DIR}/node_modules/.bin/tsc"

for runtime_asset in dist/index.js dist/index.d.ts dist/index.d.ts.map; do
  asset_path="integrations/openclaw-plugin/${runtime_asset}"
  if ! git -C "${REPO_ROOT}" ls-files --error-unmatch "${asset_path}" >/dev/null 2>&1; then
    git -C "${REPO_ROOT}" ls-files --others --exclude-standard -- "${asset_path}" | grep -qx "${asset_path}" || {
      echo "openclaw release assets: ${runtime_asset} is ignored or missing from the deliverable" >&2
      exit 1
    }
  fi
  [ -s "${PLUGIN_DIR}/${runtime_asset}" ] || {
    echo "openclaw release assets: ${runtime_asset} is missing or empty" >&2
    exit 1
  }
done

[ -x "${TSC}" ] || {
  echo "openclaw release assets: install plugin dev dependencies before checking dist freshness" >&2
  exit 1
}

CHECK_DIR="$(mktemp -d "${PLUGIN_DIR}/.dist-check.XXXXXX")"
trap 'rm -rf "${CHECK_DIR}"' EXIT HUP INT TERM
"${TSC}" -p "${PLUGIN_DIR}/tsconfig.json" --outDir "${CHECK_DIR}"
for runtime_asset in index.js index.d.ts index.d.ts.map; do
  cmp -s "${PLUGIN_DIR}/dist/${runtime_asset}" "${CHECK_DIR}/${runtime_asset}" || {
    echo "openclaw release assets: dist/${runtime_asset} is stale; run npm run build in the plugin directory" >&2
    exit 1
  }
done

echo "openclaw release assets: passed"

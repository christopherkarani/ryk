#!/usr/bin/env bash
# Rebuild src/shell_engine/oracle_packs.default.json.gz from oracle_packs.json.
# Default packs: core.* + system.disk (hook / load_all=false init).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
python3 - "$root/src/shell_engine/oracle_packs.json" "$root/src/shell_engine/oracle_packs.default.json.gz" <<'PY'
import gzip, json, sys
src, dst = sys.argv[1], sys.argv[2]
data = json.load(open(src))
chosen = [p for p in data if p["id"].startswith("core.") or p["id"] == "system.disk"]
raw = json.dumps(chosen, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
with gzip.GzipFile(filename="", mode="wb", fileobj=open(dst, "wb"), mtime=0, compresslevel=9) as gz:
    gz.write(raw)
print(f"wrote {dst} ({len(raw)} inflated bytes, {len(chosen)} packs)")
PY

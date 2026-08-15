#!/usr/bin/env bash
# validate.sh — lightweight contract check for fm-steward schemas + fixture cards.
#
# Usage (from repo root or this directory):
#   ./macos/fm-steward/Fixtures/validate.sh
#   bash macos/fm-steward/Fixtures/validate.sh
# This is the ryk contract pin. Swift source lives in ryk-fm-steward.
#
# Exit 0 when:
#   - risk-card-v1 + classify-response-v1 schemas exist and are valid JSON
#   - classify-response-v1 verdict enum contains continue | ask | ask_sticky_candidate
#   - v1 shell fixture cards exist with schema_version=1 and required core fields
#   - fixture-specific feature constraints match shell demo bar
#
# Dependencies: bash, python3 (stdlib only).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SCHEMAS="${ROOT}/Schemas"
FIXTURES="${SCRIPT_DIR}"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

pass() {
    echo "OK: $*"
}

# --- existence ---
for f in \
    "${SCHEMAS}/risk-card-v1.json" \
    "${SCHEMAS}/classify-response-v1.json" \
    "${FIXTURES}/grep_rm_rf.json" \
    "${FIXTURES}/npm_test_loop.json" \
    "${FIXTURES}/curl_pipe_sh.json" \
    "${FIXTURES}/rm_rf_workdir.json"
do
    [[ -f "$f" ]] || fail "missing required file: $f"
done
pass "required schema + fixture files present"

# --- structural + semantic checks (python3 stdlib) ---
export SCHEMAS FIXTURES
python3 <<'PY'
import json
import os
import sys

schemas_dir = os.environ["SCHEMAS"]
fixtures_dir = os.environ["FIXTURES"]
errors = []

def load(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        errors.append(f"invalid JSON {path}: {e}")
        return None

def require(cond, msg):
    if not cond:
        errors.append(msg)

# Schemas
risk_schema = load(os.path.join(schemas_dir, "risk-card-v1.json"))
cls_schema = load(os.path.join(schemas_dir, "classify-response-v1.json"))

if risk_schema is not None:
    require(isinstance(risk_schema, dict), "risk-card-v1.json must be an object")
    props = risk_schema.get("properties") or {}
    for key in ("schema_version", "session_id", "tool", "command", "features", "thresholds", "meta"):
        require(key in props, f"risk-card-v1 schema missing properties.{key}")
    required = set(risk_schema.get("required") or [])
    for key in ("schema_version", "session_id", "tool", "features"):
        require(key in required, f"risk-card-v1 schema must require {key}")
    features_schema = (props.get("features") or {})
    # Forward-compat: additionalProperties true, or an object schema (not false / missing).
    ap = features_schema.get("additionalProperties", None)
    require(ap is True or isinstance(ap, dict),
            "risk-card-v1 features must allow additionalProperties for forward-compat")

if cls_schema is not None:
    require(isinstance(cls_schema, dict), "classify-response-v1.json must be an object")
    props = cls_schema.get("properties") or {}
    for key in (
        "schema_version", "verdict", "why", "explain",
        "suggested_sticky_scope", "suggested_effect_class",
        "timed_out", "fallback", "model_available", "latency_ms",
    ):
        require(key in props, f"classify-response-v1 schema missing properties.{key}")
    verdict = props.get("verdict") or {}
    enum = set(verdict.get("enum") or [])
    for v in ("continue", "ask", "ask_sticky_candidate"):
        require(v in enum, f"classify-response-v1 verdict enum missing {v!r}")
    require(enum == {"continue", "ask", "ask_sticky_candidate"},
            f"classify-response-v1 verdict enum must be exactly continue|ask|ask_sticky_candidate, got {sorted(enum)}")

# Fixtures — required core fields + schema_version == 1
CORE_REQUIRED = ("schema_version", "session_id", "tool", "features")
# v1 shell-focused fixture table (email bulk/VIP demos removed)
FIXTURE_IDS = ("grep_rm_rf", "npm_test_loop", "curl_pipe_sh", "rm_rf_workdir")

cards = {}
for fid in FIXTURE_IDS:
    path = os.path.join(fixtures_dir, f"{fid}.json")
    card = load(path)
    if card is None:
        continue
    cards[fid] = card
    for key in CORE_REQUIRED:
        require(key in card, f"{fid}: missing required field {key}")
    require(card.get("schema_version") == 1, f"{fid}: schema_version must be 1, got {card.get('schema_version')!r}")
    features = card.get("features")
    require(isinstance(features, dict), f"{fid}: features must be object")

# Shell fixture constraints
if "grep_rm_rf" in cards:
    c = cards["grep_rm_rf"]
    require(c.get("tool") == "bash", "grep_rm_rf: tool must be bash")
    require(c["features"].get("executed") is False, "grep_rm_rf: features.executed must be false")
    cmd = c.get("command") or ""
    require(isinstance(cmd, str) and "rm" in cmd, "grep_rm_rf: command must mention rm")

if "npm_test_loop" in cards:
    c = cards["npm_test_loop"]
    require(c["features"].get("same_intent") == "test_loop",
            "npm_test_loop: features.same_intent must be test_loop")

if "curl_pipe_sh" in cards:
    c = cards["curl_pipe_sh"]
    require(c.get("tool") == "bash", "curl_pipe_sh: tool must be bash")
    require(c["features"].get("executed") is True, "curl_pipe_sh: executed must be true")
    cmd = (c.get("command") or "").lower()
    require("curl" in cmd and "bash" in cmd, "curl_pipe_sh: command must be curl|bash style")

if "rm_rf_workdir" in cards:
    c = cards["rm_rf_workdir"]
    require(c.get("tool") == "bash", "rm_rf_workdir: tool must be bash")
    require(c["features"].get("executed") is True, "rm_rf_workdir: executed must be true")
    cmd = c.get("command") or ""
    require("rm" in cmd and "-rf" in cmd, "rm_rf_workdir: command must be rm -rf style")

if errors:
    for e in errors:
        print(f"FAIL: {e}", file=sys.stderr)
    sys.exit(1)

print("OK: schemas structural contract")
print("OK: classify-response verdict enum exact")
print("OK: fixtures schema_version=1 + required fields")
print("OK: v1 shell fixture constraints")
PY

# Residual knowledge packs → seed (YAML source of truth)
if [[ -f "${ROOT}/scripts/compile-residual-knowledge.py" ]]; then
    python3 "${ROOT}/scripts/compile-residual-knowledge.py" --self-test \
        || fail "compile-residual-knowledge.py --self-test"
    pass "residual-knowledge compiler self-test"
    if [[ -d "${ROOT}/residual-knowledge" ]]; then
        python3 "${ROOT}/scripts/compile-residual-knowledge.py" --check \
            || fail "compile-residual-knowledge.py --check (seed stale vs YAML packs)"
        pass "residual-knowledge seed matches packs"
    fi
fi

echo "PASS: fm-steward Schemas + Fixtures contract validation"
exit 0

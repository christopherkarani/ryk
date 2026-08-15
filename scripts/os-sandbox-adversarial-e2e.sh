#!/usr/bin/env bash
# Adversarial OS FS sandbox e2e + evidence generator (P0-I-06 / M-11 / M-12 / F-1 / F-5).
#
# Primary proofs use the production apply path unit tests (real FS deny canaries,
# neighbor RW, control-root non-writable). Full `ryk run` shell evaluation uses
# in-process Zig shell_engine; when packaged attach is unavailable this script still
# records proofs from the Zig test surface.
#
# Honesty (S-GLO-09 / dual-proof) — CTRL-ATTACH claim rules:
#   Unit dual-proof (local, non --require-attach): production-defaults real FS deny
#   canary + production forkApply* handshake →
#   attach_detail=zig_real_fs_deny_canary_and_handshake (allowlisted local token).
#   Isolated include_tmp=false canaries are support-only — never alone paint TEST-DENY
#   on Linux or authorize unit dual-proof attach (Linux requires production-defaults
#   title; macOS keeps isolated until a production-defaults canary exists).
#   Packaged primary (CI --require-attach on linux/darwin): `ryk run --os-sandbox on`
#   banner active + recoverable 64-hex profile_hash from audit .decision.reason →
#   attach_detail=ryk_run_os_sandbox_on_active. Unit greps never primary under
#   --require-attach (require packaged detail + 64-hex hash).
#   FS-deny-only (no handshake) → TEST-DENY + neighbor only (not attach).
#   Banner alone never sets TEST-DENY. Handshake/prepare greps → CTRL-PREPARE only.
#   Platform SKIP of host real FS deny is honest non-attach (Z-1 host-OS only).
#   Evidence emission requires jq; control fields validated like evidence.zig.
#
# Usage:
#   ./scripts/os-sandbox-adversarial-e2e.sh [--case CASE_ID] [--binary PATH] [--out DIR] [--require-attach]
#   RYK_E2E_SELFTEST=1 ./scripts/os-sandbox-adversarial-e2e.sh
#     Fixture-driven classify / profile_hash / require-attach checks (no test-fast).
#
# Exit 0 when full attach is proven, or partial when platform-skip / no backend
# expected. Exit 1 on suite failure, contradictory attach claims, (on
# linux/darwin) green suite without dual attach proof when deny did not SKIP,
# or when --require-attach is set without packaged ryk_run + 64-hex profile_hash.

set -euo pipefail

CASE_ID="os-fs-adversarial"
BINARY=""
OUT_DIR=""
REQUIRE_ATTACH=false
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"
FIXTURE_DIR="$REPO_ROOT/scripts/fixtures/os-sandbox-e2e"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --case) CASE_ID="$2"; shift 2 ;;
    --binary) BINARY="$2"; shift 2 ;;
    --out) OUT_DIR="$2"; shift 2 ;;
    --require-attach) REQUIRE_ATTACH=true; shift ;;
    -h|--help)
      sed -n '2,35p' "$0"
      exit 0
      ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

bool_json() { if [[ "$1" == true ]]; then echo true; else echo false; fi; }

# Reset classify outputs (globals used by classify_from_test_log).
reset_classify_state() {
  ctrl_prepare_ok=false
  ctrl_attach_ok=false
  test_deny_ok=false
  ctrl_neighbor_ok=false
  prepare_detail="not_proven"
  attach_detail="not_proven"
  deny_detail="not_proven"
  neighbor_detail="not_proven"
  backend_id="none"
  handshake_ok=false
  linux_deny_required=false
}

# Classify attach gates from a test-fast log for a host OS.
# Args: <test_log_path> <os_name>
# Sets globals: handshake_ok, ctrl_prepare_ok, prepare_detail, test_deny_ok,
# deny_detail, ctrl_neighbor_ok, neighbor_detail, ctrl_attach_ok, attach_detail,
# backend_id, linux_deny_required.
#
# Residual honesty (dual-proof path):
# Production-defaults real FS deny canary (Linux title below; macOS when present)
# is authoritative for TEST-DENY + unit dual-proof attach. Isolated
# include_tmp=false canaries are support-only (neighbor/backend hints). Packaged
# `ryk run --os-sandbox on` + profile_hash is primary CTRL-ATTACH under
# --require-attach (ryk_run_os_sandbox_on_active). Unit dual-proof greps stitch
# separate children (deny canary vs forkApply handshake) — stronger than isolated
# alone but not a single-child integrated proof (other agents may add that test).
classify_from_test_log() {
  local test_log="$1"
  local os_name="$2"
  local isolated_deny_ok=false
  local prod_defaults_deny_ok=false

  reset_classify_state

  # CTRL-PREPARE only — probe/prepare greps never authorize CTRL-ATTACH.
  if grep -qE 'Linux Landlock prepares child plan without claiming active\.\.\.OK' "$test_log" \
    || grep -qE 'verifyApplyInChild and applySelf skip or run on Linux only\.\.\.OK' "$test_log" \
    || grep -qE 'parent apply seam never claims active \(probe/prepare only\)\.\.\.OK' "$test_log"; then
    ctrl_prepare_ok=true
    prepare_detail="zig_prepare_or_probe_only"
  fi

  # Production forkApply + status-pipe handshake (Seatbelt on macOS, Landlock on Linux).
  # Handshake alone is prepare-strength only — never paints CTRL-ATTACH green without FS deny.
  if grep -qE 'forkApplySeatbeltAndExec applies then execs on macOS with handshake\.\.\.OK' "$test_log" \
    || grep -qE 'forkApplyLandlockAndExec applies then execs on Linux with handshake\.\.\.OK' "$test_log"; then
    handshake_ok=true
    ctrl_prepare_ok=true
    prepare_detail="zig_fork_apply_handshake"
    if [[ "$os_name" == "darwin" ]]; then backend_id="seatbelt"; fi
    if [[ "$os_name" == "linux" ]]; then backend_id="landlock"; fi
  fi

  # Isolated include_tmp=false canaries — support only (never sole Linux TEST-DENY /
  # dual-proof). Titles: macOS outside canary; Linux control-root isolated.
  if grep -qE 'real FS deny: outside canary denied; workspace readable and writable\.\.\.OK' "$test_log" \
    || grep -qE 'real FS deny: outside denied; neighbor RW; control root not writable\.\.\.OK' "$test_log"; then
    isolated_deny_ok=true
    if [[ "$os_name" == "darwin" ]]; then backend_id="seatbelt"; fi
    if [[ "$os_name" == "linux" ]]; then backend_id="landlock"; fi
  fi

  # Production-defaults deny canary (authoritative for TEST-DENY + unit dual-proof).
  # Linux: landlock_deny_tests "real FS deny under production defaults…".
  # macOS: same title if/when a production-defaults real FS canary lands.
  if grep -qE 'real FS deny under production defaults: outside denied; neighbor RW; control not writable\.\.\.OK' "$test_log"; then
    prod_defaults_deny_ok=true
    if [[ "$os_name" == "darwin" ]]; then backend_id="seatbelt"; fi
    if [[ "$os_name" == "linux" ]]; then backend_id="landlock"; fi
  fi

  # TEST-DENY + neighbor: production-defaults preferred; on darwin without that
  # title yet, isolated canary still paints TEST-DENY. Linux isolated alone is
  # support-only (neighbor hint, not TEST-DENY).
  if [[ "$prod_defaults_deny_ok" == true ]]; then
    test_deny_ok=true
    deny_detail="outside_unreadable_under_production_defaults"
    ctrl_neighbor_ok=true
    neighbor_detail="workspace_neighbor_rw"
  elif [[ "$os_name" == "darwin" && "$isolated_deny_ok" == true ]]; then
    test_deny_ok=true
    deny_detail="outside_unreadable_under_sandbox"
    ctrl_neighbor_ok=true
    neighbor_detail="workspace_neighbor_rw"
  elif [[ "$isolated_deny_ok" == true ]]; then
    # Linux isolated support — neighbor only; not TEST-DENY / not dual-proof deny.
    ctrl_neighbor_ok=true
    neighbor_detail="workspace_neighbor_rw_isolated_support_only"
    deny_detail="isolated_canary_support_only"
  fi

  # Unit dual-proof CTRL-ATTACH (local only; --require-attach still needs packaged):
  # Require production-defaults deny + handshake when available. Isolated + handshake
  # alone must not authorize attach on Linux. Darwin falls back to isolated + handshake
  # until a production-defaults real FS canary exists.
  if [[ "$prod_defaults_deny_ok" == true && "$handshake_ok" == true ]]; then
    ctrl_attach_ok=true
    attach_detail="zig_real_fs_deny_canary_and_handshake"
  elif [[ "$os_name" == "darwin" && "$test_deny_ok" == true && "$handshake_ok" == true ]]; then
    ctrl_attach_ok=true
    attach_detail="zig_real_fs_deny_canary_and_handshake"
  elif [[ "$prod_defaults_deny_ok" == true || ( "$os_name" == "darwin" && "$test_deny_ok" == true ) ]]; then
    # Deny without handshake — not attach.
    attach_detail="zig_unit_fs_deny_without_production_handshake"
  elif [[ "$isolated_deny_ok" == true && "$handshake_ok" == true ]]; then
    # Stitched isolated canary + handshake is support-only (not dual-proof attach).
    attach_detail="zig_isolated_canary_and_handshake_support_only"
  elif [[ "$isolated_deny_ok" == true ]]; then
    attach_detail="zig_isolated_canary_support_only"
  fi

  # SKIP on wrong OS / missing ABI is honest non-attach, not failure.
  # Z-1: only the HOST OS's real FS deny test may set platform_skip. Never let the
  # other OS's always-SKIP line overwrite a more specific attach_detail.
  if [[ "$ctrl_attach_ok" != true ]]; then
    local host_deny_skip=false
    case "$os_name" in
      linux)
        # Prefer production-defaults skip; fall back to isolated host title.
        if grep -qE 'real FS deny under production defaults: outside denied; neighbor RW; control not writable\.\.\.SKIP' "$test_log" \
          && ! grep -qE 'real FS deny under production defaults: outside denied; neighbor RW; control not writable\.\.\.OK' "$test_log"; then
          host_deny_skip=true
        elif grep -qE 'real FS deny: outside denied; neighbor RW; control root not writable\.\.\.SKIP' "$test_log" \
          && ! grep -qE 'real FS deny: outside denied; neighbor RW; control root not writable\.\.\.OK' "$test_log" \
          && ! grep -qE 'real FS deny under production defaults: outside denied; neighbor RW; control not writable\.\.\.OK' "$test_log"; then
          host_deny_skip=true
        fi
        ;;
      darwin)
        if grep -qE 'real FS deny under production defaults: outside denied; neighbor RW; control not writable\.\.\.SKIP' "$test_log" \
          && ! grep -qE 'real FS deny under production defaults: outside denied; neighbor RW; control not writable\.\.\.OK' "$test_log"; then
          host_deny_skip=true
        elif grep -qE 'real FS deny: outside canary denied; workspace readable and writable\.\.\.SKIP' "$test_log" \
          && ! grep -qE 'real FS deny: outside canary denied; workspace readable and writable\.\.\.OK' "$test_log" \
          && ! grep -qE 'real FS deny under production defaults: outside denied; neighbor RW; control not writable\.\.\.OK' "$test_log"; then
          host_deny_skip=true
        fi
        ;;
    esac
    if [[ "$host_deny_skip" == true && "$attach_detail" == "not_proven" ]]; then
      attach_detail="platform_skip_no_backend_on_host"
      deny_detail="platform_skip"
    fi
  fi

  # F-5: On Linux, if prepare/ABI path ran and production-defaults (or isolated
  # host) real FS deny was neither OK nor SKIP, fail closed.
  if [[ "$os_name" == "linux" ]]; then
    if grep -qE 'Linux Landlock prepares child plan without claiming active\.\.\.OK' "$test_log" \
      || grep -qE 'verifyApplyInChild and applySelf skip or run on Linux only\.\.\.OK' "$test_log"; then
      linux_deny_required=true
    fi
    if grep -qE 'real FS deny under production defaults: outside denied; neighbor RW; control not writable\.\.\.OK' "$test_log" \
      || grep -qE 'real FS deny: outside denied; neighbor RW; control root not writable\.\.\.OK' "$test_log"; then
      linux_deny_required=false # satisfied
    elif grep -qE 'real FS deny under production defaults: outside denied; neighbor RW; control not writable\.\.\.SKIP' "$test_log" \
      || grep -qE 'real FS deny: outside denied; neighbor RW; control root not writable\.\.\.SKIP' "$test_log"; then
      # Explicit host landlock skip (no ABI) — allow partial pass without attach.
      linux_deny_required=false
    fi
  fi
}

# Extract 64-hex profile_hash from sandbox_posture events.jsonl.
# Audit stores reason under .decision.reason (not top-level .reason).
extract_profile_hash_from_events() {
  local ev="$1"
  local hash=""
  if command -v jq >/dev/null 2>&1; then
    hash="$(jq -r 'select(.type=="sandbox_posture") | .decision.reason // empty' "$ev" 2>/dev/null \
      | sed -n 's/.*profile_hash=\([0-9a-fA-F]\{64\}\).*/\1/p' | head -1 || true)"
  else
    # Fallback when jq absent (evidence emission still requires jq).
    hash="$(grep -o 'profile_hash=[0-9a-fA-F]\{64\}' "$ev" 2>/dev/null | head -1 | cut -d= -f2 || true)"
  fi
  printf '%s' "$hash"
}

# Mirror src/sandbox/evidence.zig Manifest.validate for shell-built control fields.
# Returns 0 if rules pass, 1 if evidence must not claim enforcement.
validate_evidence_control_rules() {
  local attach_ok="$1"
  local attach_detail="$2"
  local deny_ok="$3"
  local phash="$4"

  if [[ "$attach_detail" == "capability_probe" ]]; then
    echo "FAIL: probe-only CTRL-ATTACH detail forbidden (evidence.zig)" >&2
    return 1
  fi
  if [[ "$attach_detail" == "zig_status_pipe_or_prepare_handshake" ]]; then
    echo "FAIL: prepare-only CTRL-ATTACH detail forbidden (evidence.zig)" >&2
    return 1
  fi
  if [[ "$attach_detail" == *"prepare"* && "$attach_detail" == *"without"* ]]; then
    echo "FAIL: prepare-without attach detail forbidden (evidence.zig)" >&2
    return 1
  fi
  if [[ "$attach_detail" == "zig_real_fs_deny_canary" ]]; then
    echo "FAIL: unit-canary-only CTRL-ATTACH detail forbidden (evidence.zig)" >&2
    return 1
  fi
  if [[ "$attach_ok" == true && "$deny_ok" != true ]]; then
    echo "FAIL: CTRL-ATTACH without TEST-DENY (evidence.zig AttachWithoutDeny)" >&2
    return 1
  fi
  if [[ "$attach_ok" == true ]]; then
    case "$attach_detail" in
      zig_real_fs_deny_canary_and_handshake|ryk_run_os_sandbox_on_active) ;;
      *)
        echo "FAIL: CTRL-ATTACH detail not allowlisted: ${attach_detail}" >&2
        return 1
        ;;
    esac
  fi
  if [[ "$attach_ok" == true && "$attach_detail" == "ryk_run_os_sandbox_on_active" && ${#phash} -ne 64 ]]; then
    echo "FAIL: ryk_run attach requires 64-hex profile_hash (evidence.zig MissingProfileHash)" >&2
    return 1
  fi
  return 0
}

# --require-attach gate (CI matrix).
# Args: <require> <ctrl_attach_ok> <attach_detail> [profile_hash] [os_name]
# On linux/darwin: primary attach must be packaged ryk_run + 64-hex profile_hash.
# Unit dual-proof greps are support evidence only under --require-attach.
require_attach_gate() {
  local require="$1"
  local attach_ok="$2"
  local detail="$3"
  local phash="${4:-}"
  local os_name="${5:-}"
  if [[ "$require" != true ]]; then
    return 0
  fi
  if [[ "$attach_ok" != true ]]; then
    echo "FAIL: --require-attach set but CTRL-ATTACH not proven (detail=${detail})" >&2
    return 1
  fi
  if [[ "$os_name" == "linux" || "$os_name" == "darwin" ]]; then
    if [[ "$detail" != "ryk_run_os_sandbox_on_active" ]]; then
      echo "FAIL: --require-attach on ${os_name} requires packaged ryk_run attach + profile_hash (detail=${detail}); unit dual-proof is support only" >&2
      return 1
    fi
    if [[ ${#phash} -ne 64 ]]; then
      echo "FAIL: --require-attach packaged attach missing recoverable 64-hex profile_hash" >&2
      return 1
    fi
  fi
  return 0
}

# RYK_E2E_SELFTEST=1: fixture-driven Z-1 / require-attach checks (no test-fast).
run_e2e_selftest() {
  local fails=0
  local f

  echo "RYK_E2E_SELFTEST: classifying fixtures under $FIXTURE_DIR"

  f="$FIXTURE_DIR/linux-macos-skip-only.log"
  if [[ ! -f "$f" ]]; then
    echo "FAIL: missing fixture $f" >&2
    return 1
  fi
  classify_from_test_log "$f" "linux"
  if [[ "$attach_detail" == "platform_skip_no_backend_on_host" ]]; then
    echo "FAIL fixture linux-macos-skip-only: false platform_skip from opposite-OS SKIP (got $attach_detail)" >&2
    fails=$((fails + 1))
  elif [[ "$ctrl_attach_ok" == true ]]; then
    echo "FAIL fixture linux-macos-skip-only: attach must not be proven" >&2
    fails=$((fails + 1))
  else
    echo "OK fixture linux-macos-skip-only: no false platform_skip (attach_detail=$attach_detail)"
  fi
  if require_attach_gate true "$ctrl_attach_ok" "$attach_detail" 2>/dev/null; then
    echo "FAIL fixture linux-macos-skip-only: --require-attach should fail without attach" >&2
    fails=$((fails + 1))
  else
    echo "OK fixture linux-macos-skip-only: --require-attach fails closed"
  fi

  f="$FIXTURE_DIR/linux-deny-ok-no-handshake.log"
  if [[ ! -f "$f" ]]; then
    echo "FAIL: missing fixture $f" >&2
    return 1
  fi
  classify_from_test_log "$f" "linux"
  if [[ "$attach_detail" != "zig_unit_fs_deny_without_production_handshake" ]]; then
    echo "FAIL fixture linux-deny-ok-no-handshake: expected zig_unit_fs_deny_without_production_handshake got $attach_detail" >&2
    fails=$((fails + 1))
  elif [[ "$ctrl_attach_ok" == true ]]; then
    echo "FAIL fixture linux-deny-ok-no-handshake: attach must not be proven without handshake" >&2
    fails=$((fails + 1))
  elif [[ "$test_deny_ok" != true ]]; then
    echo "FAIL fixture linux-deny-ok-no-handshake: TEST-DENY should be ok" >&2
    fails=$((fails + 1))
  else
    echo "OK fixture linux-deny-ok-no-handshake: unit deny without handshake (no platform_skip overwrite)"
  fi
  if require_attach_gate true "$ctrl_attach_ok" "$attach_detail" 2>/dev/null; then
    echo "FAIL fixture linux-deny-ok-no-handshake: --require-attach should fail" >&2
    fails=$((fails + 1))
  else
    echo "OK fixture linux-deny-ok-no-handshake: --require-attach fails closed"
  fi

  f="$FIXTURE_DIR/linux-host-deny-skip.log"
  if [[ ! -f "$f" ]]; then
    echo "FAIL: missing fixture $f" >&2
    return 1
  fi
  classify_from_test_log "$f" "linux"
  if [[ "$attach_detail" != "platform_skip_no_backend_on_host" ]]; then
    echo "FAIL fixture linux-host-deny-skip: expected platform_skip_no_backend_on_host got $attach_detail" >&2
    fails=$((fails + 1))
  else
    echo "OK fixture linux-host-deny-skip: host deny SKIP → platform_skip"
  fi
  if require_attach_gate true "$ctrl_attach_ok" "$attach_detail" 2>/dev/null; then
    echo "FAIL fixture linux-host-deny-skip: --require-attach should fail on platform_skip" >&2
    fails=$((fails + 1))
  else
    echo "OK fixture linux-host-deny-skip: --require-attach fails closed on platform_skip"
  fi

  f="$FIXTURE_DIR/linux-deny-ok-and-handshake.log"
  if [[ ! -f "$f" ]]; then
    echo "FAIL: missing fixture $f" >&2
    return 1
  fi
  classify_from_test_log "$f" "linux"
  if [[ "$ctrl_attach_ok" != true || "$attach_detail" != "zig_real_fs_deny_canary_and_handshake" ]]; then
    echo "FAIL fixture linux-deny-ok-and-handshake: expected attach ok+handshake detail (attach_ok=$ctrl_attach_ok detail=$attach_detail)" >&2
    fails=$((fails + 1))
  elif [[ "$test_deny_ok" != true || "$deny_detail" != "outside_unreadable_under_production_defaults" ]]; then
    echo "FAIL fixture linux-deny-ok-and-handshake: expected production-defaults TEST-DENY (deny_ok=$test_deny_ok detail=$deny_detail)" >&2
    fails=$((fails + 1))
  else
    echo "OK fixture linux-deny-ok-and-handshake: unit dual-proof (prod-defaults deny + handshake)"
  fi
  # Unit dual-proof alone must not satisfy --require-attach on linux.
  if require_attach_gate true "$ctrl_attach_ok" "$attach_detail" "" "linux" 2>/dev/null; then
    echo "FAIL fixture linux-deny-ok-and-handshake: --require-attach must reject unit-only dual-proof" >&2
    fails=$((fails + 1))
  else
    echo "OK fixture linux-deny-ok-and-handshake: --require-attach rejects unit-only dual-proof"
  fi

  # M-1: isolated include_tmp=false + handshake must not alone authorize TEST-DENY / dual-proof.
  f="$FIXTURE_DIR/linux-isolated-only-and-handshake.log"
  if [[ ! -f "$f" ]]; then
    echo "FAIL: missing fixture $f" >&2
    return 1
  fi
  classify_from_test_log "$f" "linux"
  if [[ "$ctrl_attach_ok" == true ]]; then
    echo "FAIL fixture linux-isolated-only-and-handshake: isolated must not authorize CTRL-ATTACH" >&2
    fails=$((fails + 1))
  elif [[ "$test_deny_ok" == true ]]; then
    echo "FAIL fixture linux-isolated-only-and-handshake: isolated must not alone paint TEST-DENY" >&2
    fails=$((fails + 1))
  elif [[ "$attach_detail" != "zig_isolated_canary_and_handshake_support_only" ]]; then
    echo "FAIL fixture linux-isolated-only-and-handshake: expected support-only detail got $attach_detail" >&2
    fails=$((fails + 1))
  else
    echo "OK fixture linux-isolated-only-and-handshake: isolated+handshake support-only (no TEST-DENY/attach)"
  fi
  if require_attach_gate true "$ctrl_attach_ok" "$attach_detail" "" "linux" 2>/dev/null; then
    echo "FAIL fixture linux-isolated-only-and-handshake: --require-attach should fail" >&2
    fails=$((fails + 1))
  else
    echo "OK fixture linux-isolated-only-and-handshake: --require-attach fails closed"
  fi

  # profile_hash jq path must read .decision.reason (not top-level .reason).
  f="$FIXTURE_DIR/sandbox_posture_events.jsonl"
  if [[ ! -f "$f" ]]; then
    echo "FAIL: missing fixture $f" >&2
    return 1
  fi
  if ! command -v jq >/dev/null 2>&1; then
    echo "FAIL fixture sandbox_posture_events: jq required for profile_hash selftest" >&2
    fails=$((fails + 1))
  else
    local extracted wrong_field
    extracted="$(extract_profile_hash_from_events "$f")"
    if [[ ${#extracted} -ne 64 || ! "$extracted" =~ ^[0-9a-fA-F]{64}$ ]]; then
      echo "FAIL fixture sandbox_posture_events: expected 64-hex profile_hash via .decision.reason (got '${extracted}')" >&2
      fails=$((fails + 1))
    else
      echo "OK fixture sandbox_posture_events: jq .decision.reason yields 64-hex profile_hash"
    fi
    # Prove the old wrong field path is empty (regression guard for M-1).
    wrong_field="$(jq -r 'select(.type=="sandbox_posture") | .reason // empty' "$f" 2>/dev/null \
      | sed -n 's/.*profile_hash=\([0-9a-fA-F]\{64\}\).*/\1/p' | head -1 || true)"
    if [[ -n "$wrong_field" ]]; then
      echo "FAIL fixture sandbox_posture_events: top-level .reason unexpectedly non-empty (fixture shape wrong)" >&2
      fails=$((fails + 1))
    else
      echo "OK fixture sandbox_posture_events: top-level .reason empty (jq branch must use .decision.reason)"
    fi
  fi

  # M-4: packaged attach detail + 64-hex hash passes --require-attach on linux.
  local pack_hash="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  if ! require_attach_gate true true "ryk_run_os_sandbox_on_active" "$pack_hash" "linux"; then
    echo "FAIL fixture packaged-attach: --require-attach should pass for ryk_run + hash" >&2
    fails=$((fails + 1))
  else
    echo "OK fixture packaged-attach: --require-attach passes for ryk_run + 64-hex hash"
  fi
  if require_attach_gate true true "ryk_run_os_sandbox_on_active" "" "linux" 2>/dev/null; then
    echo "FAIL fixture packaged-attach-no-hash: --require-attach must fail without hash" >&2
    fails=$((fails + 1))
  else
    echo "OK fixture packaged-attach-no-hash: --require-attach fails closed without hash"
  fi

  # M-2: shell validation mirrors evidence.zig allowlist + profile_hash rules.
  if ! validate_evidence_control_rules true "zig_real_fs_deny_canary_and_handshake" true ""; then
    echo "FAIL validate: unit dual-proof should pass control rules" >&2
    fails=$((fails + 1))
  else
    echo "OK validate: unit dual-proof passes evidence control rules"
  fi
  if validate_evidence_control_rules true "ryk_run_os_sandbox_on_active" true "" 2>/dev/null; then
    echo "FAIL validate: ryk_run without hash must fail" >&2
    fails=$((fails + 1))
  else
    echo "OK validate: ryk_run without hash fails (MissingProfileHash)"
  fi
  if ! validate_evidence_control_rules true "ryk_run_os_sandbox_on_active" true "$pack_hash"; then
    echo "FAIL validate: ryk_run + hash should pass" >&2
    fails=$((fails + 1))
  else
    echo "OK validate: ryk_run + 64-hex hash passes"
  fi
  if validate_evidence_control_rules true "zig_real_fs_deny_canary_and_handshake" false "" 2>/dev/null; then
    echo "FAIL validate: attach without TEST-DENY must fail" >&2
    fails=$((fails + 1))
  else
    echo "OK validate: attach without TEST-DENY fails"
  fi

  # Darwin classify fixtures (M-30 parity with Linux).
  f="$FIXTURE_DIR/darwin-linux-skip-only.log"
  if [[ ! -f "$f" ]]; then
    echo "FAIL: missing fixture $f" >&2
    return 1
  fi
  classify_from_test_log "$f" "darwin"
  if [[ "$attach_detail" == "platform_skip_no_backend_on_host" ]]; then
    echo "FAIL fixture darwin-linux-skip-only: false platform_skip from opposite-OS SKIP" >&2
    fails=$((fails + 1))
  else
    echo "OK fixture darwin-linux-skip-only: no false platform_skip (attach_detail=$attach_detail)"
  fi

  f="$FIXTURE_DIR/darwin-deny-ok-no-handshake.log"
  if [[ ! -f "$f" ]]; then
    echo "FAIL: missing fixture $f" >&2
    return 1
  fi
  classify_from_test_log "$f" "darwin"
  if [[ "$ctrl_attach_ok" == true ]]; then
    echo "FAIL fixture darwin-deny-ok-no-handshake: attach must not be proven without handshake" >&2
    fails=$((fails + 1))
  elif [[ "$test_deny_ok" != true ]]; then
    echo "FAIL fixture darwin-deny-ok-no-handshake: TEST-DENY should be ok" >&2
    fails=$((fails + 1))
  elif [[ "$attach_detail" != "zig_unit_fs_deny_without_production_handshake" ]]; then
    echo "FAIL fixture darwin-deny-ok-no-handshake: expected zig_unit_fs_deny_without_production_handshake got $attach_detail" >&2
    fails=$((fails + 1))
  else
    echo "OK fixture darwin-deny-ok-no-handshake: isolated deny without handshake"
  fi
  if require_attach_gate true "$ctrl_attach_ok" "$attach_detail" "" "darwin" 2>/dev/null; then
    echo "FAIL fixture darwin-deny-ok-no-handshake: --require-attach should fail" >&2
    fails=$((fails + 1))
  else
    echo "OK fixture darwin-deny-ok-no-handshake: --require-attach fails closed"
  fi

  f="$FIXTURE_DIR/darwin-deny-ok-and-handshake.log"
  if [[ ! -f "$f" ]]; then
    echo "FAIL: missing fixture $f" >&2
    return 1
  fi
  classify_from_test_log "$f" "darwin"
  if [[ "$ctrl_attach_ok" != true || "$attach_detail" != "zig_real_fs_deny_canary_and_handshake" ]]; then
    echo "FAIL fixture darwin-deny-ok-and-handshake: expected attach ok+handshake (attach_ok=$ctrl_attach_ok detail=$attach_detail)" >&2
    fails=$((fails + 1))
  else
    echo "OK fixture darwin-deny-ok-and-handshake: unit dual-proof attach classified"
  fi
  if require_attach_gate true "$ctrl_attach_ok" "$attach_detail" "" "darwin" 2>/dev/null; then
    echo "FAIL fixture darwin-deny-ok-and-handshake: --require-attach must reject unit-only dual-proof" >&2
    fails=$((fails + 1))
  else
    echo "OK fixture darwin-deny-ok-and-handshake: --require-attach rejects unit-only dual-proof"
  fi

  f="$FIXTURE_DIR/darwin-host-deny-skip.log"
  if [[ ! -f "$f" ]]; then
    echo "FAIL: missing fixture $f" >&2
    return 1
  fi
  classify_from_test_log "$f" "darwin"
  if [[ "$attach_detail" != "platform_skip_no_backend_on_host" ]]; then
    echo "FAIL fixture darwin-host-deny-skip: expected platform_skip_no_backend_on_host got $attach_detail" >&2
    fails=$((fails + 1))
  else
    echo "OK fixture darwin-host-deny-skip: host deny SKIP → platform_skip"
  fi
  if require_attach_gate true "$ctrl_attach_ok" "$attach_detail" "" "darwin" 2>/dev/null; then
    echo "FAIL fixture darwin-host-deny-skip: --require-attach should fail on platform_skip" >&2
    fails=$((fails + 1))
  else
    echo "OK fixture darwin-host-deny-skip: --require-attach fails closed on platform_skip"
  fi

  if [[ $fails -ne 0 ]]; then
    echo "RYK_E2E_SELFTEST: FAILED ($fails assertion(s))" >&2
    return 1
  fi
  echo "RYK_E2E_SELFTEST: PASS"
  return 0
}

if [[ "${RYK_E2E_SELFTEST:-}" == "1" ]]; then
  run_e2e_selftest
  exit $?
fi

if [[ -z "$BINARY" ]]; then
  if [[ -x ./zig-out/bin/ryk ]]; then
    BINARY=./zig-out/bin/ryk
  else
    echo "building ryk..."
    ./scripts/zig build
    BINARY=./zig-out/bin/ryk
  fi
fi

if [[ -z "$OUT_DIR" ]]; then
  OUT_DIR="$REPO_ROOT/planning/security/evidence"
fi
mkdir -p "$OUT_DIR"

OS_NAME="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH_NAME="$(uname -m)"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
BINARY_SHA="unknown"
if command -v shasum >/dev/null 2>&1; then
  BINARY_SHA="$(shasum -a 256 "$BINARY" | awk '{print $1}')"
elif command -v sha256sum >/dev/null 2>&1; then
  BINARY_SHA="$(sha256sum "$BINARY" | awk '{print $1}')"
fi

# M-12: baseline starts false; set true only after BINARY --version succeeds.
ctrl_baseline_ok=false
ctrl_off_ok=false
off_detail="not_run"
exit_code=0
reset_classify_state

# --- Zig production-path proofs (apply_posix / landlock / seatbelt) ----------
# Single test-fast run produces both unit results and evidence greps (CI must not
# double-run test-fast before calling this script).
echo "Running sandbox apply/landlock/seatbelt proofs via test-fast..."
set +e
TEST_LOG="$(mktemp)"
# M-23: always remove temp log on EXIT (early fail must not leak mktemp files).
trap 'rm -f "$TEST_LOG"' EXIT
./scripts/zig build test-fast >"$TEST_LOG" 2>&1
TEST_RC=$?
set -e

if [[ ! -s "$TEST_LOG" ]]; then
  echo "FAIL: test-fast produced empty log; cannot prove sandbox evidence" >&2
  exit 1
fi

classify_from_test_log "$TEST_LOG" "$OS_NAME"

# Mode-off unit proof
if grep -qE 'mode off returns disabled receipt without scrub or active claim\.\.\.OK' "$TEST_LOG"; then
  ctrl_off_ok=true
  off_detail="apply_mode_off_disabled_receipt"
fi

# Parent seam never claims active without child
if ! grep -qE 'parent apply seam never claims active \(probe/prepare only\)\.\.\.OK' "$TEST_LOG" \
  && ! grep -qE 'parent apply seam never claims active.*SKIP' "$TEST_LOG"; then
  if [[ $TEST_RC -ne 0 ]]; then
    echo "WARN: parent-seam honesty test missing or suite failed (rc=$TEST_RC)" >&2
  fi
fi

# --- Optional: ryk binary smoke (does not require daemon allow) ----
set +e
"$BINARY" --version >/dev/null 2>&1
BIN_RC=$?
set -e
if [[ $BIN_RC -eq 0 ]]; then
  ctrl_baseline_ok=true
fi

# --- Packaged `ryk run --os-sandbox on` attach (primary under --require-attach) ---
# Prefer production binary attach for CTRL-ATTACH when banner active + profile_hash.
# Unit greps remain TEST-DENY / neighbor / handshake support only (never set TEST-DENY
# from the banner alone — M-12). Under --require-attach, packaged active without a
# recoverable hash FAILS closed (M-1); do not demote primary attach to unit dual-proof.
profile_hash=""
packaged_banner_active=false
packaged_hash_missing=false
if [[ $BIN_RC -eq 0 ]]; then
  PACK_WS="$(mktemp -d "${TMPDIR:-/tmp}/ryk-e2e-attach.XXXXXX")"
  mkdir -p "$PACK_WS/.ryk"
  set +e
  PACK_OUT="$(mktemp)"
  # Use /usr/bin/true (or /bin/true) — a non-shell absolute path — so this
  # probes OS sandbox attach/apply only, not Zig shell_engine evaluation.
  TRUE_BIN="/usr/bin/true"
  [[ -x "$TRUE_BIN" ]] || TRUE_BIN="/bin/true"
  if [[ -x "$TRUE_BIN" ]]; then
    PACK_POLICY="$REPO_ROOT/policies/observe.yaml"
    # Same packaged attach surface the secret-boundary canary just proved:
    # explicit policy + OS sandbox on. An empty workspace has no policy file.
    "$BINARY" run \
      --workspace "$PACK_WS" \
      --policy "$PACK_POLICY" \
      --os-sandbox on \
      --network off \
      -- "$TRUE_BIN" >"$PACK_OUT" 2>&1
    PACK_RC=$?
    if [[ $PACK_RC -eq 0 ]] && grep -q 'OS sandbox: active' "$PACK_OUT"; then
      packaged_banner_active=true
      # Prefer audit events for profile_hash (.decision.reason — M-1).
      if [[ -f "$PACK_WS/.ryk/last" ]]; then
        SID="$(tr -d '[:space:]' <"$PACK_WS/.ryk/last" || true)"
        EV="$PACK_WS/.ryk/sessions/${SID}/events.jsonl"
        if [[ -f "$EV" ]]; then
          profile_hash="$(extract_profile_hash_from_events "$EV")"
        fi
      fi
      if [[ ${#profile_hash} -eq 64 ]]; then
        ctrl_attach_ok=true
        attach_detail="ryk_run_os_sandbox_on_active"
        # M-12: never invent TEST-DENY from banner; unit greps must have set it.
      else
        packaged_hash_missing=true
        if [[ "$REQUIRE_ATTACH" == true ]]; then
          echo "FAIL: packaged OS sandbox banner active but profile_hash not recoverable from audit; --require-attach fails closed (M-1)" >&2
        else
          echo "WARN: packaged attach active but profile_hash not found in audit; keeping unit dual-proof attach if any" >&2
        fi
      fi
    elif [[ "$REQUIRE_ATTACH" == true ]]; then
      echo "WARN: packaged ryk run attach did not report active (rc=$PACK_RC)" >&2
      tail -20 "$PACK_OUT" >&2 || true
    fi
  fi
  set -e
  rm -rf "$PACK_WS" "$PACK_OUT" 2>/dev/null || true
fi

if [[ $TEST_RC -ne 0 ]]; then
  exit_code=$TEST_RC
  echo "test-fast failed (rc=$TEST_RC); see evidence for details" >&2
  tail -40 "$TEST_LOG" >&2 || true
fi

# Never claim attach without deny (F-1 invariant).
if [[ "$ctrl_attach_ok" == true && "$test_deny_ok" != true ]]; then
  echo "FAIL: CTRL-ATTACH set without TEST-DENY" >&2
  ctrl_attach_ok=false
  attach_detail="invalid_attach_without_deny"
  exit_code=1
fi

MANIFEST="$OUT_DIR/${CASE_ID}-${OS_NAME}-${ARCH_NAME}.json"
# profile_hash: set when packaged ryk run attach greened with audit hash.
# Unit dual-proof path may leave it empty (allowlisted for zig_real_fs_deny_canary_and_handshake only).
if [[ "$attach_detail" == "ryk_run_os_sandbox_on_active" ]]; then
  evidence_command='ryk run --os-sandbox on -- /usr/bin/true (+ test-fast dual-proof support)'
  canary_fingerprint="packaged:ryk_run_os_sandbox_on_active"
else
  evidence_command='./scripts/zig build test-fast (sandbox apply real-FS-deny proofs only for CTRL-ATTACH)'
  canary_fingerprint="zig-unit:real-fs-deny"
fi

# M-24: jq required for evidence emission (no unescaped heredoc path).
if ! command -v jq >/dev/null 2>&1; then
  echo "FAIL: jq is required to emit evidence manifests (install jq; no heredoc fallback)" >&2
  exit 1
fi

# M-2: shell control booleans must satisfy the same rules as evidence.zig before write.
if ! validate_evidence_control_rules "$ctrl_attach_ok" "$attach_detail" "$test_deny_ok" "$profile_hash"; then
  exit_code=1
fi

jq -n \
  --argjson schema_version 1 \
  --argjson gate_ids '["P1-I-01", "P0-I-06", "M-11", "M-12", "F-1", "F-5"]' \
  --arg case_id "$CASE_ID" \
  --arg source_commit "$COMMIT" \
  --arg binary_sha256 "$BINARY_SHA" \
  --arg os "$OS_NAME" \
  --arg arch "$ARCH_NAME" \
  --arg backend_id "$backend_id" \
  --arg profile_hash "$profile_hash" \
  --arg command "$evidence_command" \
  --argjson exit_code "$exit_code" \
  --argjson ctrl_baseline_ok "$(bool_json "$ctrl_baseline_ok")" \
  --argjson ctrl_prepare_ok "$(bool_json "$ctrl_prepare_ok")" \
  --arg prepare_detail "$prepare_detail" \
  --argjson ctrl_attach_ok "$(bool_json "$ctrl_attach_ok")" \
  --arg attach_detail "$attach_detail" \
  --argjson test_deny_ok "$(bool_json "$test_deny_ok")" \
  --arg deny_detail "$deny_detail" \
  --argjson ctrl_neighbor_ok "$(bool_json "$ctrl_neighbor_ok")" \
  --arg neighbor_detail "$neighbor_detail" \
  --argjson ctrl_off_ok "$(bool_json "$ctrl_off_ok")" \
  --arg off_detail "$off_detail" \
  --arg canary_fingerprint "$canary_fingerprint" \
  --arg rerun "./scripts/os-sandbox-adversarial-e2e.sh --case ${CASE_ID}" \
  '{
    schema_version: $schema_version,
    gate_ids: $gate_ids,
    case_id: $case_id,
    source_commit: $source_commit,
    binary_sha256: $binary_sha256,
    platform: {os: $os, arch: $arch},
    backend_id: $backend_id,
    profile_hash: $profile_hash,
    command: $command,
    exit_code: $exit_code,
    controls: {
      "CTRL-BASELINE": {ok: $ctrl_baseline_ok, detail: "binary_present"},
      "CTRL-PREPARE": {ok: $ctrl_prepare_ok, detail: $prepare_detail},
      "CTRL-ATTACH": {ok: $ctrl_attach_ok, detail: $attach_detail},
      "TEST-DENY": {ok: $test_deny_ok, detail: $deny_detail},
      "CTRL-NEIGHBOR": {ok: $ctrl_neighbor_ok, detail: $neighbor_detail},
      "CTRL-OFF": {ok: $ctrl_off_ok, detail: $off_detail}
    },
    canary_fingerprint: $canary_fingerprint,
    rerun: $rerun
  }' >"$MANIFEST"

# Fail closed if evidence artifact is missing or empty (M-11).
if [[ ! -s "$MANIFEST" ]]; then
  echo "FAIL: evidence manifest missing or empty: $MANIFEST" >&2
  exit 1
fi

echo "Wrote evidence: $MANIFEST"
echo "CTRL-BASELINE=$(bool_json $ctrl_baseline_ok) CTRL-PREPARE=$(bool_json $ctrl_prepare_ok) CTRL-ATTACH=$(bool_json $ctrl_attach_ok) TEST-DENY=$(bool_json $test_deny_ok) CTRL-NEIGHBOR=$(bool_json $ctrl_neighbor_ok) CTRL-OFF=$(bool_json $ctrl_off_ok) fingerprint=${canary_fingerprint}"

if [[ $TEST_RC -ne 0 ]]; then
  exit 1
fi

# M-1: packaged banner active without hash under --require-attach is fail closed.
if [[ "$REQUIRE_ATTACH" == true && "$packaged_hash_missing" == true ]]; then
  echo "FAIL: --require-attach with packaged banner active but no recoverable profile_hash" >&2
  exit 1
fi

# Re-validate control rules (may have been marked exit_code=1 above).
if ! validate_evidence_control_rules "$ctrl_attach_ok" "$attach_detail" "$test_deny_ok" "$profile_hash"; then
  exit 1
fi

# F-5: Linux ABI/prepare present but real FS deny not green is fail.
if [[ "$linux_deny_required" == true && "$test_deny_ok" != true ]]; then
  echo "FAIL: Linux Landlock ABI/prepare path ran but real FS deny was not OK (F-5)" >&2
  exit 1
fi

# Mode-off receipt is always expected from the Zig suite (not platform-gated).
if [[ "$ctrl_off_ok" != true ]]; then
  echo "FAIL: expected CTRL-OFF (mode off receipt) evidence missing from test-fast log" >&2
  exit 1
fi

# Any CTRL-ATTACH claim requires TEST-DENY + CTRL-NEIGHBOR + production handshake
# (unit greps as dual-proof support; packaged path still needs those support bits).
if [[ "$ctrl_attach_ok" == true ]]; then
  if [[ "$test_deny_ok" != true || "$ctrl_neighbor_ok" != true || "$handshake_ok" != true ]]; then
    echo "FAIL: CTRL-ATTACH claimed (${attach_detail}) but dual proof incomplete (deny=${test_deny_ok} neighbor=${ctrl_neighbor_ok} handshake=${handshake_ok})" >&2
    exit 1
  fi
  # M-4 / CI: --require-attach needs packaged ryk_run + hash on linux/darwin.
  require_attach_gate "$REQUIRE_ATTACH" "$ctrl_attach_ok" "$attach_detail" "$profile_hash" "$OS_NAME" || exit 1
  echo "PASS: sandbox proofs green (attach=${attach_detail})"
  exit 0
fi

# Z-2: CI matrix jobs pass --require-attach so platform_skip / partial is not green.
if ! require_attach_gate "$REQUIRE_ATTACH" "$ctrl_attach_ok" "$attach_detail" "$profile_hash" "$OS_NAME"; then
  exit 1
fi

# M-15: on linux/darwin, green suite without dual attach proof is FAIL unless
# real FS deny platform-skipped (no backend ABI) — prepare-only is not enough.
if [[ "$OS_NAME" == "linux" || "$OS_NAME" == "darwin" ]]; then
  if [[ "$attach_detail" != "platform_skip_no_backend_on_host" ]]; then
    echo "FAIL: CTRL-ATTACH not proven on ${OS_NAME}; require production forkApply handshake + real FS deny (detail=${attach_detail})" >&2
    exit 1
  fi
fi

if [[ "$ctrl_prepare_ok" == true ]]; then
  echo "PASS (partial): prepare/probe only (detail=${prepare_detail}); no CTRL-ATTACH claimed (attach=${attach_detail})"
  exit 0
fi

echo "PASS (partial): no full attach on this host; suite green without false active claim (attach=${attach_detail})"
exit 0

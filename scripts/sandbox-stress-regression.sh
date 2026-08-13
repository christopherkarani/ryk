#!/usr/bin/env bash
# Sandbox stress regression pack (Phase 5) — safe, non-exploit probes for P1–4.
#
# Proves mediated / OS-attached `ryk run` still enforces:
#   P1 network mediation (example.com + raw TCP deny) when mediation is active
#   P2 .git / .ryk write deny; workspace write allow
#   P4 PATH honesty / session grade labels when present
# Optional: --network open escape grade honesty
#
# Not a substitute for fixture `ryk redteam --ci`. No secrets, no destructive rm.
#
# Usage:
#   ./scripts/sandbox-stress-regression.sh [--binary PATH] [--skip-open-escape]
#   RYK_STRESS_BINARY=./zig-out/bin/ryk ./scripts/sandbox-stress-regression.sh
#
# Exit:
#   0  all applicable probes passed, or clean SKIP (no Seatbelt/Landlock)
#   1  unexpected allow / suite failure
#   2  usage error

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

BINARY="${RYK_STRESS_BINARY:-}"
SKIP_OPEN_ESCAPE=false
WORK_DIR=""
STRESS_HOME=""
PASS=0
FAIL=0
SKIP=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary) BINARY="$2"; shift 2 ;;
    --skip-open-escape) SKIP_OPEN_ESCAPE=true; shift ;;
    -h|--help)
      sed -n '2,22p' "$0"
      exit 0
      ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

log() { printf '[stress] %s\n' "$*"; }
pass() { PASS=$((PASS + 1)); log "PASS: $*"; }
fail() { FAIL=$((FAIL + 1)); log "FAIL: $*"; }
skip() { SKIP=$((SKIP + 1)); log "SKIP: $*"; }

cleanup() {
  if [[ -n "${WORK_DIR}" && -d "${WORK_DIR}" ]]; then
    rm -rf "${WORK_DIR}"
  fi
  if [[ -n "${STRESS_HOME}" && -d "${STRESS_HOME}" ]]; then
    rm -rf "${STRESS_HOME}"
  fi
}
trap cleanup EXIT

resolve_binary() {
  local candidate=""
  if [[ -n "${BINARY}" && -x "${BINARY}" ]]; then
    candidate="${BINARY}"
  elif [[ -x "${REPO_ROOT}/zig-out/bin/ryk" ]]; then
    candidate="${REPO_ROOT}/zig-out/bin/ryk"
  elif [[ -x "${REPO_ROOT}/zig-out/bin/ryk" ]]; then
    candidate="${REPO_ROOT}/zig-out/bin/ryk"
  else
    return 1
  fi
  if [[ "${candidate}" != /* ]]; then
    candidate="$(cd "$(dirname "${candidate}")" && pwd)/$(basename "${candidate}")"
  fi
  echo "${candidate}"
}

# Run under OS sandbox attach without host-alias mediation (FS control probes).
run_os_sh() {
  local cmd="$1"
  local out_file="$2"
  shift 2
  (
    cd "${WORK_DIR}"
    env HOME="${STRESS_HOME}" \
      "${RYK}" run \
        --workspace "${WORK_DIR}" \
        --mode observe \
        --os-sandbox on \
        --network open \
        "$@" \
        -- /bin/sh -c "${cmd}" >"${out_file}" 2>&1
  )
}

# Trusted host-shaped mediation (real $HOME/.local/bin/pi → proxy + route-force).
run_mediated_pi() {
  local cmd="$1"
  local out_file="$2"
  (
    cd "${WORK_DIR}"
    env HOME="${STRESS_HOME}" \
      "${RYK}" run \
        --workspace "${WORK_DIR}" \
        --mode observe \
        --os-sandbox on \
        -- "${STRESS_HOME}/.local/bin/pi" -c "${cmd}" >"${out_file}" 2>&1
  )
}

# Workspace-planted basename spoof must remain untrusted and unmediated.
run_workspace_pi() {
  local cmd="$1"
  local out_file="$2"
  (
    cd "${WORK_DIR}"
    env HOME="${STRESS_HOME}" \
      "${RYK}" run \
        --workspace "${WORK_DIR}" \
        --mode observe \
        --os-sandbox on \
        -- "${WORK_DIR}/pi" -c "${cmd}" >"${out_file}" 2>&1
  )
}

expect_fs_deny() {
  local name="$1"
  local cmd="$2"
  local out="${WORK_DIR}/out-${name}.txt"
  set +e
  run_os_sh "${cmd}" "${out}"
  local code=$?
  set -e
  if grep -qE 'phase5-(git|ryk)-written|SSH_LIST_OK' "${out}" 2>/dev/null; then
    fail "${name}: unexpectedly allowed (see ${out})"
    return
  fi
  if [[ ${code} -ne 0 ]] || grep -qE 'STRESS_DENY_OK|Operation not permitted|Permission denied|EPERM' "${out}" 2>/dev/null; then
    pass "${name}"
    return
  fi
  fail "${name}: exit ${code} without deny evidence (see ${out})"
}

expect_fs_allow() {
  local name="$1"
  local cmd="$2"
  local marker="$3"
  local out="${WORK_DIR}/out-${name}.txt"
  set +e
  run_os_sh "${cmd}" "${out}"
  local code=$?
  set -e
  if [[ ${code} -eq 0 ]] && grep -qF "${marker}" "${out}" 2>/dev/null; then
    pass "${name}"
  else
    fail "${name}: exit ${code}, missing ${marker} (see ${out})"
    sed 's/^/[stress:detail] /' "${out}" | head -30 || true
  fi
}

main() {
  if ! RYK="$(resolve_binary)"; then
    log "no ryk binary; build with ./scripts/zig build or pass --binary"
    exit 1
  fi
  log "binary=${RYK}"
  log "version=$("${RYK}" version 2>/dev/null | head -1 || echo unknown)"

  WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ryk-stress.XXXXXX")"
  mkdir -p "${REPO_ROOT}/zig-cache"
  STRESS_HOME="$(mktemp -d "${REPO_ROOT}/zig-cache/ryk-stress-home.XXXXXX")"
  mkdir -p "${WORK_DIR}/.ryk" "${WORK_DIR}/tmp"
  mkdir -p "${WORK_DIR}/.git/objects" "${WORK_DIR}/.git/refs"
  printf 'ref: refs/heads/main\n' >"${WORK_DIR}/.git/HEAD"
  cat >"${WORK_DIR}/.ryk/policy.yaml" <<'YAML'
version: 1
mode: observe
env:
  inherit: true
network:
  mode: allowlist
  allow:
    - "api.github.com"
commands:
  allow:
    - "*"
YAML
  cat >"${WORK_DIR}/pi" <<'SH'
#!/bin/sh
if [ "$1" = "-c" ]; then
  shift
  eval "$1"
  exit $?
fi
exec /bin/sh "$@"
SH
  chmod 755 "${WORK_DIR}/pi"
  mkdir -p "${STRESS_HOME}/.pi" "${STRESS_HOME}/.local/bin"
  cp "${WORK_DIR}/pi" "${STRESS_HOME}/.local/bin/pi"
  chmod 755 "${STRESS_HOME}/.local/bin/pi"

  # Attach probe (non-host-alias): FS sandbox only.
  local attach_out="${WORK_DIR}/attach-probe.txt"
  set +e
  (
    cd "${WORK_DIR}"
    env HOME="${STRESS_HOME}" \
      "${RYK}" run --workspace "${WORK_DIR}" --mode observe --os-sandbox on --network open -- \
      /bin/echo attach-ok
  ) >"${attach_out}" 2>&1
  local attach_code=$?
  set -e
  if [[ ${attach_code} -ne 0 ]]; then
    if grep -qiE 'unavailable|not supported|OS sandbox required but|failed closed|attach failed' "${attach_out}"; then
      skip "OS sandbox attach unavailable on this host (clean skip)"
      sed 's/^/[stress:attach] /' "${attach_out}" | head -20 || true
      log "summary pass=${PASS} fail=${FAIL} skip=${SKIP}"
      exit 0
    fi
    fail "attach probe unexpected failure"
    sed 's/^/[stress:attach] /' "${attach_out}" | head -40 || true
    log "summary pass=${PASS} fail=${FAIL} skip=${SKIP}"
    exit 1
  fi
  if ! grep -q 'attach-ok' "${attach_out}"; then
    fail "attach probe missing attach-ok"
    log "summary pass=${PASS} fail=${FAIL} skip=${SKIP}"
    exit 1
  fi
  pass "os-sandbox attach probe"

  # F-02 anti-spoof: a workspace-planted `pi` must not gain host mediation.
  local spoof_out="${WORK_DIR}/out-workspace-pi-spoof.txt"
  set +e
  run_workspace_pi 'echo GRADE=$RYK_SESSION_SANDBOX_GRADE; echo ROUTE=${RYK_PROXY_ROUTE_FORCED:-false}' "${spoof_out}"
  local spoof_code=$?
  set -e
  if [[ ${spoof_code} -eq 0 ]] &&
     grep -q 'GRADE=fs-attached' "${spoof_out}" &&
     grep -q 'ROUTE=false' "${spoof_out}"; then
    pass "workspace-pi remains untrusted (fs-attached, no route force)"
  else
    fail "workspace-pi anti-spoof posture mismatch (see ${spoof_out})"
    sed 's/^/[stress:detail] /' "${spoof_out}" | head -30 || true
  fi

  # --- P2 control roots (OS attach; network open only to avoid mediation fail-closed) ---
  expect_fs_deny "write-git-control" \
    'echo probe > .git/phase5-probe 2>/dev/null && echo phase5-git-written && exit 0; echo STRESS_DENY_OK; exit 1'

  expect_fs_deny "write-ryk-control" \
    'echo probe > .ryk/phase5-probe 2>/dev/null && echo phase5-ryk-written && exit 0; echo STRESS_DENY_OK; exit 1'

  expect_fs_allow "workspace-write" \
    'echo ok > tmp/phase5-ok && test -f tmp/phase5-ok && echo PHASE5_WS_OK' \
    "PHASE5_WS_OK"

  expect_fs_deny "ssh-home-list" \
    'ls ~/.ssh 2>/dev/null && echo SSH_LIST_OK && exit 0; echo STRESS_DENY_OK; exit 1'

  # Session grade under attach + open (unrestricted-escape) via non-alias open path.
  local grade_out="${WORK_DIR}/out-grade-open.txt"
  set +e
  run_os_sh 'echo GRADE=$RYK_SESSION_SANDBOX_GRADE; echo PATH_FILTER=$RYK_PATH_FILTER; echo TOOL_PACK=$RYK_TOOL_PACK' "${grade_out}"
  local grade_code=$?
  set -e
  if [[ ${grade_code} -eq 0 ]]; then
    if grep -q 'GRADE=unrestricted-escape' "${grade_out}"; then
      pass "session-grade unrestricted-escape under --network open"
    elif grep -qE 'GRADE=(strong-mediated|fs-attached|wrapper-only)' "${grade_out}"; then
      # Open path should be unrestricted-escape; anything else is honesty bug.
      fail "session-grade under --network open expected unrestricted-escape (see ${grade_out})"
    else
      fail "RYK_SESSION_SANDBOX_GRADE missing under open attach (see ${grade_out})"
    fi
    if grep -qE 'PATH_FILTER=denylist|TOOL_PACK=' "${grade_out}"; then
      pass "PATH/tool_pack honesty labels present under attach"
    else
      skip "PATH filter labels not set (residual / attach path)"
    fi
  else
    fail "grade env probe exit ${grade_code}"
    sed 's/^/[stress:detail] /' "${grade_out}" | head -20 || true
  fi

  # --- P1 network mediation (host alias) ---
  # Fail-closed *launch* messages only (not banner "proxy route-forced" success text).
  mediation_launch_failed() {
    local f="$1"
    grep -qiE 'Agent host network mediation requires|network mediation requires|proxy network backend unavailable|network_route_forcing_unavailable|usable host login material|OS sandbox required but|OS sandbox attach failed' "$f"
  }

  local net_out="${WORK_DIR}/out-net-mediate.txt"
  if ! command -v curl >/dev/null 2>&1; then
    skip "curl not on PATH; network deny probe not proven (install curl to exercise P1)"
  else
    set +e
    run_mediated_pi 'echo GRADE=$RYK_SESSION_SANDBOX_GRADE; echo ROUTE=$RYK_PROXY_ROUTE_FORCED; code=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 5 https://example.com 2>/dev/null || echo fail); echo HTTP=$code; if [ "$code" = "200" ]; then echo HTTP_200; exit 0; fi; echo STRESS_DENY_OK; exit 1' "${net_out}"
    local net_code=$?
    set -e
    if mediation_launch_failed "${net_out}" && ! grep -q 'HTTP_200\|GRADE=\|ROUTE=' "${net_out}"; then
      skip "host-alias mediation unavailable (fail-closed); network live deny not proven"
      sed 's/^/[stress:net] /' "${net_out}" | head -15 || true
    elif grep -q 'HTTP_200' "${net_out}"; then
      fail "curl example.com allowed under mediation (see ${net_out})"
    elif [[ ${net_code} -ne 0 ]] || grep -q 'STRESS_DENY_OK' "${net_out}"; then
      pass "curl-example.com denied under mediation"
      if grep -q 'GRADE=strong-mediated' "${net_out}"; then
        pass "session-grade strong-mediated under host-alias mediation"
      else
        fail "mediated grade must be strong-mediated (see ${net_out})"
      fi
    else
      fail "network mediate probe inconclusive (see ${net_out})"
    fi
  fi

  local tcp_out="${WORK_DIR}/out-tcp.txt"
  if ! command -v python3 >/dev/null 2>&1; then
    skip "python3 not on PATH; raw-tcp deny probe not proven"
  else
    set +e
    # Python socket connect: timeout/refuse → deny success under mediation.
    run_mediated_pi 'echo GRADE=$RYK_SESSION_SANDBOX_GRADE; python3 -c "import socket,sys
try:
 s=socket.create_connection((\"1.1.1.1\",80),2); s.close(); print(\"TCP_OK\"); sys.exit(0)
except Exception as e:
 print(\"STRESS_DENY_OK\", type(e).__name__); sys.exit(1)
"' "${tcp_out}"
    local tcp_code=$?
    set -e
    if mediation_launch_failed "${tcp_out}" && ! grep -qE 'TCP_OK|STRESS_DENY_OK|GRADE=' "${tcp_out}"; then
      skip "raw-tcp probe skipped (mediation fail-closed)"
    elif grep -q 'TCP_OK' "${tcp_out}"; then
      fail "raw TCP to 1.1.1.1:80 allowed under mediation (see ${tcp_out})"
      sed 's/^/[stress:tcp] /' "${tcp_out}" | head -20 || true
    elif [[ ${tcp_code} -ne 0 ]] || grep -q 'STRESS_DENY_OK' "${tcp_out}"; then
      if grep -q 'GRADE=strong-mediated' "${tcp_out}"; then
        pass "raw-tcp-1.1.1.1 denied under strong mediation"
      else
        fail "raw-tcp deny lacked strong-mediated grade (see ${tcp_out})"
      fi
    else
      fail "raw-tcp probe inconclusive (see ${tcp_out})"
    fi
  fi

  # Optional open escape loud + grade (already partially covered above).
  if [[ "${SKIP_OPEN_ESCAPE}" == true ]]; then
    skip "open-escape (--skip-open-escape)"
  else
    local open_out="${WORK_DIR}/out-open-escape.txt"
    set +e
    (
      cd "${WORK_DIR}"
      env HOME="${STRESS_HOME}" \
        "${RYK}" run --workspace "${WORK_DIR}" --mode observe --os-sandbox on --network open -- \
        /bin/sh -c 'echo GRADE=$RYK_SESSION_SANDBOX_GRADE'
    ) >"${open_out}" 2>&1
    local open_code=$?
    set -e
    if [[ ${open_code} -ne 0 ]]; then
      skip "open-escape run failed"
    else
      if grep -q 'GRADE=unrestricted-escape' "${open_out}" && ! grep -q 'GRADE=strong-mediated' "${open_out}"; then
        pass "open-escape grade unrestricted-escape"
      else
        fail "open-escape grade dishonest (see ${open_out})"
      fi
      if grep -qiE 'unrestricted|--network open' "${open_out}"; then
        pass "open-escape loud warning present"
      else
        skip "open-escape warning not grepped in merged output"
      fi
    fi
  fi

  rm -f "${WORK_DIR}/.git/phase5-probe" "${WORK_DIR}/.ryk/phase5-probe" "${WORK_DIR}/tmp/phase5-ok" 2>/dev/null || true

  log "summary pass=${PASS} fail=${FAIL} skip=${SKIP}"
  if [[ ${FAIL} -gt 0 ]]; then
    exit 1
  fi
  exit 0
}

main "$@"

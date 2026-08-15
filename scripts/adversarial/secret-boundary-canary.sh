#!/usr/bin/env bash
# Secret Boundary Phase 1 adversarial process canary.
#
# Synthetic-only inputs. Never replace these with real credentials.
# Forbidden substrings:
#   SuperSecretPass99
#   ghp_fake
#   proxypass
#   sk-fakeProviderCanary99
#   CANARY_ENVFILE_BODY_99
#
# Cases:
#   A - empty-backpack child environment omits all host canaries
#   B - empty-backpack child cannot print the planted workspace .env body
#   C - empty backpack rejects --os-sandbox off with exit 2
#   D - an unminted ryk-secret:// reference is absent from the child
#   E - escape warns and exposes a synthetic canary with sandbox off
#   F - --secretless and --with-host-secrets conflict before child launch
#
# Usage:
#   ./scripts/adversarial/secret-boundary-canary.sh \
#     [--binary ./zig-out/bin/ryk] [--policy policies/observe.yaml] [--skip-escape]
#
# Build the Debug binary first:
#   ./scripts/zig build -Doptimize=Debug
#
# Attach-dependent cases print SKIP only when ryk explicitly reports that the
# required OS sandbox/protection backend is unavailable. Cases A and D use a
# successful child under explicit `--os-sandbox on` as their attach proof:
# empty backpack fails before spawn when attach does not succeed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BINARY="$REPO_ROOT/zig-out/bin/ryk"
POLICY="$REPO_ROOT/policies/observe.yaml"
SKIP_ESCAPE=false

usage() {
  printf '%s\n' \
    'Usage: scripts/adversarial/secret-boundary-canary.sh [options]' \
    '' \
    'Options:' \
    '  --binary PATH   Debug ryk binary (default: ./zig-out/bin/ryk)' \
    '  --policy PATH   Policy used by process probes (default: policies/observe.yaml)' \
    '  --skip-escape   Skip Phase 1e escape/dual-flag cases E and F' \
    '  -h, --help      Show this help'
}

require_value() {
  if [[ $# -lt 2 || -z "$2" ]]; then
    printf 'secret-boundary-canary: %s requires a value\n' "$1" >&2
    exit 2
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary)
      require_value "$@"
      BINARY="$2"
      shift 2
      ;;
    --policy)
      require_value "$@"
      POLICY="$2"
      shift 2
      ;;
    --skip-escape)
      SKIP_ESCAPE=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'secret-boundary-canary: unknown argument: %s\n' "$1" >&2
      exit 2
      ;;
  esac
done

cd "$REPO_ROOT"

if [[ ! -x "$BINARY" ]]; then
  printf 'secret-boundary-canary: Debug binary is missing or not executable: %s\n' "$BINARY" >&2
  printf 'Build it with: ./scripts/zig build -Doptimize=Debug\n' >&2
  exit 2
fi
if [[ ! -f "$POLICY" ]]; then
  printf 'secret-boundary-canary: policy file not found: %s\n' "$POLICY" >&2
  exit 2
fi

TMP_BASE="${TMPDIR:-/tmp}"
TMP_BASE="${TMP_BASE%/}"
TMP_ROOT="$(mktemp -d "$TMP_BASE/ryk-secret-boundary.XXXXXX")"
WORKSPACE="$TMP_ROOT/workspace"
HOME_DIR="$TMP_ROOT/home"
OUTPUT_DIR="$TMP_ROOT/output"
mkdir -p "$WORKSPACE" "$HOME_DIR" "$OUTPUT_DIR"

cleanup() {
  local expected_prefix="$TMP_BASE/ryk-secret-boundary."
  if [[ -n "${TMP_ROOT:-}" && -d "$TMP_ROOT" && "$TMP_ROOT" == "$expected_prefix"* ]]; then
    chmod -R u+w "$TMP_ROOT" 2>/dev/null || true
    rm -rf -- "$TMP_ROOT"
  else
    printf 'secret-boundary-canary: refusing unsafe temp cleanup: %s\n' "${TMP_ROOT:-unset}" >&2
  fi
}
trap cleanup EXIT

FAILURES=0
PASSES=0
SKIPS=0
ATTACH_STATE=unknown
PHASE_1E_PRESENT=false
INCOMPLETE=false
SAFE_PATH="/usr/bin:/bin:/usr/sbin:/sbin"
UNMINTED_REF="ryk-secret://evil/session/not-minted"
FORBIDDEN_SUBSTRINGS=(
  "SuperSecretPass99"
  "ghp_fake"
  "proxypass"
  "sk-fakeProviderCanary99"
  "CANARY_ENVFILE_BODY_99"
)

pass_case() {
  PASSES=$((PASSES + 1))
  printf 'PASS: %s\n' "$1"
}

fail_case() {
  FAILURES=$((FAILURES + 1))
  printf 'FAIL: %s\n' "$1" >&2
}

skip_case() {
  SKIPS=$((SKIPS + 1))
  printf 'SKIP: %s\n' "$1"
}

contains_forbidden() {
  local file="$1"
  local needle
  for needle in "${FORBIDDEN_SUBSTRINGS[@]}"; do
    if grep -Fq -- "$needle" "$file"; then
      return 0
    fi
  done
  return 1
}

scan_audit_forbidden() {
  local audit_root="$WORKSPACE/.ryk"
  local needle
  local grep_status
  [[ -d "$audit_root" ]] || return 1
  for needle in "${FORBIDDEN_SUBSTRINGS[@]}"; do
    if grep -r -Fq -- "$needle" "$audit_root"; then
      return 0
    else
      grep_status=$?
      if [[ "$grep_status" -gt 1 ]]; then
        return 2
      fi
    fi
  done
  return 1
}

reports_attach_unavailable() {
  local child_status="$1"
  local stdout_file="$2"
  local stderr_file="$3"
  [[ "$child_status" -eq 4 ]] || return 1
  grep -Eiq \
    'OS sandbox required but unavailable|workspace secret protection unavailable|sandbox backend unavailable|sandbox unavailable on this platform' \
    "$stdout_file" "$stderr_file"
}

attests_active_sandbox() {
  local stdout_file="$1"
  grep -Fq 'OS sandbox: active' "$stdout_file"
}

attests_latest_session_active() {
  local last_file="$WORKSPACE/.ryk/last"
  local session_id
  local events_file
  [[ -f "$last_file" && ! -L "$last_file" ]] || return 1
  IFS= read -r session_id <"$last_file" || return 1
  case "$session_id" in
    ''|*[!A-Za-z0-9_-]*) return 1 ;;
  esac
  events_file="$WORKSPACE/.ryk/sessions/$session_id/events.jsonl"
  [[ -f "$events_file" && ! -L "$events_file" ]] || return 1
  grep -Eq \
    '"type":"sandbox_posture".*"reason":"posture=active; profile_hash=[0-9A-Fa-f]{64};' \
    "$events_file"
}

run_with_canaries() {
  env -i \
    PATH="$SAFE_PATH" \
    HOME="$HOME_DIR" \
    MYSQL_PWD='SuperSecretPass99' \
    DATABASE_URL='postgres://synthetic:SuperSecretPass99@db.invalid/app' \
    GITHUB_TOKEN='ghp_fakeSyntheticTokenValue1234567890' \
    OPENAI_API_KEY='sk-fakeProviderCanary99' \
    HTTP_PROXY='http://synthetic:proxypass@proxy.invalid:8080' \
    RANDOM_HOST_CANARY='SuperSecretPass99-random-host' \
    UNMINTED_SECRET_REF="$UNMINTED_REF" \
    "$@"
}

run_without_canaries() {
  env -i PATH="$SAFE_PATH" HOME="$HOME_DIR" "$@"
}

COMMON_SECRETLESS=(
  "$BINARY" run
  --workspace "$WORKSPACE"
  --policy "$POLICY"
  --secretless
  --inherit-env
  --os-sandbox on
  --network off
  --
)

BINARY_HELP_STDOUT="$OUTPUT_DIR/binary-help.stdout"
BINARY_HELP_STDERR="$OUTPUT_DIR/binary-help.stderr"
if run_without_canaries "$BINARY" help run >"$BINARY_HELP_STDOUT" 2>"$BINARY_HELP_STDERR"; then
  BINARY_HELP_STATUS=0
else
  BINARY_HELP_STATUS=$?
fi
if [[ "$BINARY_HELP_STATUS" -ne 0 ]]; then
  fail_case "selected binary help probe exited $BINARY_HELP_STATUS"
elif grep -Fq -- '--with-host-secrets' "$BINARY_HELP_STDOUT"; then
  PHASE_1E_PRESENT=true
else
  BINARY_HELP_GREP_STATUS=$?
  if [[ "$BINARY_HELP_GREP_STATUS" -gt 1 ]]; then
    fail_case "selected binary help probe scan failed with status $BINARY_HELP_GREP_STATUS"
  fi
fi

printf 'secret-boundary-canary: mode=%s\n' "$([[ "$PHASE_1E_PRESENT" == true ]] && printf full || printf partial)"
if [[ "$PHASE_1E_PRESENT" == true && "$SKIP_ESCAPE" == true ]]; then
  INCOMPLETE=true
fi

# Case A: P1-4 / process-level empty-backpack environment proof.
A_STDOUT="$OUTPUT_DIR/case-a.stdout"
A_STDERR="$OUTPUT_DIR/case-a.stderr"
if run_with_canaries "${COMMON_SECRETLESS[@]}" /usr/bin/env >"$A_STDOUT" 2>"$A_STDERR"; then
  A_STATUS=0
else
  A_STATUS=$?
fi
if [[ "$A_STATUS" -ne 0 ]]; then
  if reports_attach_unavailable "$A_STATUS" "$A_STDOUT" "$A_STDERR"; then
    ATTACH_STATE=unavailable
    skip_case 'A env canary dump (required OS sandbox unavailable)'
  else
    fail_case "A env canary dump exited $A_STATUS"
    printf 'A stdout:\n%s\nA stderr:\n%s\n' "$(cat "$A_STDOUT")" "$(cat "$A_STDERR")" >&2
  fi
elif ! attests_latest_session_active; then
  fail_case 'A env canary dump lacked active sandbox_posture audit with profile hash'
elif contains_forbidden "$A_STDOUT" || contains_forbidden "$A_STDERR"; then
  fail_case 'A env canary dump exposed a forbidden synthetic substring'
elif ! grep -Eq '^OPENAI_API_KEY=ryk-secret://session/[^/]+/OPENAI_API_KEY/[0-9a-f]{16}$' "$A_STDOUT"; then
  fail_case 'A provider key was not replaced with an exact session-minted phantom'
elif ! grep -Eq '^OPENAI_BASE_URL=http://127[.]0[.]0[.]1:[0-9]+/v1$' "$A_STDOUT"; then
  fail_case 'A provider gateway loopback base URL was not injected'
else
  ATTACH_STATE=active
  pass_case 'A env canary dump omitted host canaries under active sandbox'
fi

# Case B: P1-5 / workspace .env is unreadable (or otherwise cannot print body).
printf '%s\n' 'SECRET_BOUNDARY_CANARY=CANARY_ENVFILE_BODY_99' >"$WORKSPACE/.env"
B_STDOUT="$OUTPUT_DIR/case-b.stdout"
B_STDERR="$OUTPUT_DIR/case-b.stderr"
B_CHILD_STDOUT="$WORKSPACE/.ryk-canary-cat.out"
B_CHILD_STDERR="$WORKSPACE/.ryk-canary-cat.err"
if [[ "$ATTACH_STATE" == unavailable ]]; then
  skip_case 'B workspace .env denial (required OS sandbox unavailable)'
elif [[ ! -f "$WORKSPACE/.env" || ! -r "$WORKSPACE/.env" ]]; then
  fail_case 'B host fixture is missing or unreadable before child launch'
elif ! grep -Fq 'CANARY_ENVFILE_BODY_99' "$WORKSPACE/.env"; then
  fail_case 'B host fixture does not contain the expected synthetic body'
elif [[ -e "$B_CHILD_STDOUT" || -e "$B_CHILD_STDERR" ]]; then
  fail_case 'B child diagnostic fixtures unexpectedly exist before launch'
else
  # The supervisor does not preserve direct child stderr separately from its
  # post-run note. Capture cat's streams inside the sandboxed child so exit 1
  # can be causally bound to the OS permission diagnostic.
  if run_with_canaries "${COMMON_SECRETLESS[@]}" \
    /bin/sh -c '/bin/cat .env > .ryk-canary-cat.out 2> .ryk-canary-cat.err' \
    >"$B_STDOUT" 2>"$B_STDERR"; then
    B_STATUS=0
  else
    B_STATUS=$?
  fi
  if reports_attach_unavailable "$B_STATUS" "$B_STDOUT" "$B_STDERR"; then
    ATTACH_STATE=unavailable
    skip_case 'B workspace .env denial (required OS protection unavailable)'
  elif [[ "$B_STATUS" -ne 1 ]]; then
    fail_case "B workspace .env probe expected child denial exit 1, got $B_STATUS"
  elif ! attests_active_sandbox "$B_STDOUT"; then
    fail_case 'B workspace .env probe lacked active-sandbox attestation'
  elif ! attests_latest_session_active; then
    fail_case 'B workspace .env probe lacked active sandbox_posture audit with profile hash'
  elif [[ ! -f "$B_CHILD_STDOUT" || -L "$B_CHILD_STDOUT" || ! -f "$B_CHILD_STDERR" || -L "$B_CHILD_STDERR" ]]; then
    fail_case 'B child did not create regular output and diagnostic fixtures'
  elif contains_forbidden "$B_CHILD_STDOUT" || contains_forbidden "$B_STDOUT"; then
    fail_case 'B workspace .env body reached child output'
  elif ! grep -Eiq 'Operation not permitted|Permission denied' "$B_CHILD_STDERR"; then
    fail_case 'B workspace .env exit 1 was not an OS permission denial'
  elif contains_forbidden "$B_CHILD_STDERR" || contains_forbidden "$B_STDERR"; then
    fail_case 'B workspace .env probe leaked a forbidden synthetic substring'
  else
    pass_case 'B workspace .env denied by OS with exit 1 and body absent from child output'
  fi
fi

# Case C: P1-3 / empty backpack cannot run with sandbox off.
C_STDOUT="$OUTPUT_DIR/case-c.stdout"
C_STDERR="$OUTPUT_DIR/case-c.stderr"
C_MARKER="$TMP_ROOT/case-c-child-started"
if run_without_canaries \
  "$BINARY" run --workspace "$WORKSPACE" --policy "$POLICY" \
  --secretless --os-sandbox off --network off -- /usr/bin/touch "$C_MARKER" \
  >"$C_STDOUT" 2>"$C_STDERR"; then
  C_STATUS=0
else
  C_STATUS=$?
fi
if [[ "$C_STATUS" -eq 2 ]] \
  && grep -Fq 'empty-backpack secret boundary requires an active OS sandbox' "$C_STDERR" \
  && [[ ! -e "$C_MARKER" ]]; then
  pass_case 'C sandbox-off conflict exited 2 before child launch'
else
  fail_case "C sandbox-off conflict status=$C_STATUS marker=$([[ -e "$C_MARKER" ]] && printf present || printf absent)"
fi

# Case D: P1-2 / free-form secret references never survive empty backpack.
D_STDOUT="$OUTPUT_DIR/case-d.stdout"
D_STDERR="$OUTPUT_DIR/case-d.stderr"
if [[ "$ATTACH_STATE" == unavailable ]]; then
  skip_case 'D unminted reference rejection (required OS sandbox unavailable)'
else
  if run_with_canaries "${COMMON_SECRETLESS[@]}" /usr/bin/env >"$D_STDOUT" 2>"$D_STDERR"; then
    D_STATUS=0
  else
    D_STATUS=$?
  fi
  if reports_attach_unavailable "$D_STATUS" "$D_STDOUT" "$D_STDERR"; then
    ATTACH_STATE=unavailable
    skip_case 'D unminted reference rejection (required OS sandbox unavailable)'
  elif [[ "$D_STATUS" -ne 0 ]]; then
    fail_case "D unminted reference probe exited $D_STATUS"
    printf 'D stdout:\n%s\nD stderr:\n%s\n' "$(cat "$D_STDOUT")" "$(cat "$D_STDERR")" >&2
  elif ! attests_latest_session_active; then
    fail_case 'D unminted reference probe lacked active sandbox_posture audit with profile hash'
  elif grep -Fq -- "$UNMINTED_REF" "$D_STDOUT" "$D_STDERR"; then
    fail_case 'D unminted ryk-secret reference reached child output'
  else
    pass_case 'D unminted ryk-secret reference absent from child'
  fi
fi

# Case E: P1-6 / explicit escape is loud and self-sufficient.
E_STDOUT="$OUTPUT_DIR/case-e.stdout"
E_STDERR="$OUTPUT_DIR/case-e.stderr"
if [[ "$PHASE_1E_PRESENT" != true ]]; then
  skip_case 'E escape proof (Phase 1e not present)'
elif [[ "$SKIP_ESCAPE" == true ]]; then
  skip_case 'E escape proof requested by --skip-escape'
else
  if run_with_canaries \
    "$BINARY" run --workspace "$WORKSPACE" --policy "$POLICY" \
    --with-host-secrets --os-sandbox off --network off -- /usr/bin/env \
    >"$E_STDOUT" 2>"$E_STDERR"; then
    E_STATUS=0
  else
    E_STATUS=$?
  fi
  if [[ "$E_STATUS" -eq 0 ]] \
    && grep -Fq 'WARNING: --with-host-secrets disables empty-backpack' "$E_STDERR" \
    && grep -Fq 'MYSQL_PWD=SuperSecretPass99' "$E_STDOUT"; then
    if contains_forbidden "$E_STDERR"; then
      fail_case 'E escape stderr exposed a forbidden synthetic substring'
    else
      pass_case 'E escape warning emitted and synthetic canary inherited without extra env flags'
    fi
  else
    fail_case "E escape warning/canary proof failed with status $E_STATUS"
  fi
fi

# Case F: dual posture is a usage error and never launches the child.
F_STDOUT="$OUTPUT_DIR/case-f.stdout"
F_STDERR="$OUTPUT_DIR/case-f.stderr"
F_MARKER="$TMP_ROOT/case-f-child-started"
if [[ "$PHASE_1E_PRESENT" != true ]]; then
  skip_case 'F dual-flag conflict (Phase 1e not present)'
elif [[ "$SKIP_ESCAPE" == true ]]; then
  skip_case 'F dual-flag conflict requested by --skip-escape'
else
  if run_without_canaries \
    "$BINARY" run --workspace "$WORKSPACE" --policy "$POLICY" \
    --secretless --with-host-secrets --os-sandbox off --network off -- /usr/bin/touch "$F_MARKER" \
    >"$F_STDOUT" 2>"$F_STDERR"; then
    F_STATUS=0
  else
    F_STATUS=$?
  fi
  if [[ "$F_STATUS" -eq 2 ]] \
    && grep -Fq 'cannot combine --secretless with --with-host-secrets' "$F_STDERR" \
    && [[ ! -e "$F_MARKER" ]]; then
    pass_case 'F dual-flag conflict exited 2 before child launch'
  else
    fail_case "F dual-flag conflict status=$F_STATUS marker=$([[ -e "$F_MARKER" ]] && printf present || printf absent)"
  fi
fi

if scan_audit_forbidden; then
  fail_case 'audit artifacts persisted a forbidden synthetic substring'
else
  AUDIT_SCAN_STATUS=$?
  case "$AUDIT_SCAN_STATUS" in
    1) printf 'PASS: audit artifacts contain no forbidden synthetic substrings\n' ;;
    *) fail_case "audit artifact scan failed closed with status $AUDIT_SCAN_STATUS" ;;
  esac
fi

printf 'secret-boundary-canary: summary pass=%d skip=%d fail=%d\n' "$PASSES" "$SKIPS" "$FAILURES"
if [[ "$FAILURES" -ne 0 ]]; then
  exit 1
fi
if [[ "$INCOMPLETE" == true ]]; then
  printf 'INCOMPLETE: Phase 1e escape cases were skipped; full certification was not run\n' >&2
  exit 3
fi

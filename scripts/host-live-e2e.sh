#!/usr/bin/env bash
# ryk envelope E2E: exercise each supported host's ryk veto path
# (`hook` / `evaluate` / bare stdin). This is not a live host-CLI test.
#
# Host binaries are noted when present but do not gate the fixture run —
# `ryk hook claude` does not need `claude` on PATH. Cursor uses bare stdin;
# there is no first-class launch alias.
#
# Usage:
#   ./scripts/host-live-e2e.sh              # all hosts
#   ./scripts/host-live-e2e.sh codex hermes # subset
#   RYK_BIN=/path/to/ryk ./scripts/host-live-e2e.sh
#
# Exit: 0 if no hard failures; 1 if any host envelope failed allow or deny.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RYK_BIN="${RYK_BIN:-}"
if [[ -z "$RYK_BIN" ]]; then
  if [[ -x "$ROOT/zig-out/bin/ryk" ]]; then
    RYK_BIN="$ROOT/zig-out/bin/ryk"
  elif command -v ryk >/dev/null 2>&1; then
    RYK_BIN="$(command -v ryk)"
  fi
fi

SAFE_CMD='git status'
DANGER_CMD='rm -rf /'

ALL_HOSTS=(codex claude opencode openclaw hermes grok pi cursor)
REQUESTED=("$@")
if [[ ${#REQUESTED[@]} -eq 0 ]]; then
  HOSTS=("${ALL_HOSTS[@]}")
else
  HOSTS=("${REQUESTED[@]}")
fi

pass=0
fail=0
skip=0

log() { printf '%s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

resolve_event() {
  case "$1" in
    codex|claude|grok) echo PreToolUse ;;
    opencode) echo tool.execute.before ;;
    openclaw) echo tool.before ;;
    hermes) echo pre_tool_call ;;
    pi) echo evaluate ;;
    cursor) echo beforeShellExecution ;;
    *) echo unknown ;;
  esac
}

fixture_for() {
  local host="$1" event="$2" cmd="$3"
  case "$host" in
    hermes)
      printf '{"version":1,"host":"hermes","event":"%s","payload":{"tool_name":"terminal","tool_input":{"command":"%s"},"command":"%s"}}' \
        "$event" "$cmd" "$cmd"
      ;;
    opencode)
      printf '{"version":1,"host":"opencode","event":"%s","payload":{"tool":"bash","sessionID":"live-e2e","callID":"1","command":"%s","args":{"command":"%s"}}}' \
        "$event" "$cmd" "$cmd"
      ;;
    openclaw)
      printf '{"version":1,"host":"openclaw","event":"%s","payload":{"tool":"bash","command":"%s"}}' \
        "$event" "$cmd"
      ;;
    grok)
      printf '{"hookEventName":"pre_tool_use","sessionId":"live-e2e","cwd":"/tmp","workspaceRoot":"/tmp","toolName":"run_terminal_cmd","toolUseId":"1","toolInput":{"command":"%s"},"toolInputTruncated":false}' \
        "$cmd"
      ;;
    cursor)
      printf '{"command":"%s","cwd":"/tmp"}' "$cmd"
      ;;
    codex|claude)
      printf '{"version":1,"host":"%s","event":"%s","payload":{"tool_name":"Bash","tool_input":{"command":"%s"}}}' \
        "$host" "$event" "$cmd"
      ;;
    *)
      return 1
      ;;
  esac
}

# True when stdout carries an allow on any supported host wire.
stdout_is_allow() {
  local stdout="$1"
  printf '%s' "$stdout" | grep -q '"decision"[[:space:]]*:[[:space:]]*"allow"' && return 0
  printf '%s' "$stdout" | grep -q '"permissionDecision"[[:space:]]*:[[:space:]]*"allow"' && return 0
  printf '%s' "$stdout" | grep -q '"permission"[[:space:]]*:[[:space:]]*"allow"' && return 0
  return 1
}

# True when stdout carries a deny/block on any supported host wire.
# ask/warn are not a successful deny.
stdout_is_block() {
  local stdout="$1"
  printf '%s' "$stdout" | grep -q '"decision"[[:space:]]*:[[:space:]]*"block"' && return 0
  printf '%s' "$stdout" | grep -q '"decision"[[:space:]]*:[[:space:]]*"deny"' && return 0
  printf '%s' "$stdout" | grep -q '"permissionDecision"[[:space:]]*:[[:space:]]*"deny"' && return 0
  printf '%s' "$stdout" | grep -q '"permission"[[:space:]]*:[[:space:]]*"deny"' && return 0
  return 1
}

interpret_allow() {
  local host="$1" code="$2" stdout="$3"
  [[ "$code" == "0" ]] || return 1
  stdout_is_allow "$stdout"
}

interpret_deny() {
  local host="$1" code="$2" stdout="$3"
  case "$host" in
    codex)
      # Codex deny: exit 2 + stderr sentinel (stdout JSON intentionally empty).
      [[ "$code" == "2" ]] && return 0
      stdout_is_block "$stdout"
      ;;
    grok)
      # Official Grok contract is exit 2 + decision deny JSON. Empty stdout is not enough.
      [[ "$code" == "2" ]] || return 1
      stdout_is_block "$stdout"
      ;;
    pi)
      # Pi evaluate deny requires decision deny/block JSON. Exit 2 with empty stdout is not a pass.
      stdout_is_block "$stdout" || return 1
      ;;
    *)
      [[ "$code" == "0" ]] || return 1
      stdout_is_block "$stdout"
      ;;
  esac
}

run_hook_case() {
  local host="$1" expected="$2" cmd="$3"
  local event out code
  event="$(resolve_event "$host")"
  out="$(mktemp)"
  set +e
  fixture_for "$host" "$event" "$cmd" | "$RYK_BIN" hook "$host" "$event" >"$out" 2>/dev/null
  code=$?
  set -e
  local body
  body="$(cat "$out")"
  rm -f "$out"
  if [[ "$expected" == "allow" ]]; then
    interpret_allow "$host" "$code" "$body"
  else
    interpret_deny "$host" "$code" "$body"
  fi
}

run_pi_case() {
  local expected="$1" cmd="$2"
  local cwd out code payload
  cwd="$(pwd)"
  payload="$(printf '{"schema_version":1,"request_id":"live-e2e","kind":"shell_command","command":"%s","cwd":"%s","source":{"host":"pi","tool_name":"bash","mode":"tui","session_id":"live-e2e"}}' \
    "$cmd" "$cwd")"
  out="$(mktemp)"
  set +e
  printf '%s' "$payload" | "$RYK_BIN" evaluate --json --stdin >"$out" 2>/dev/null
  code=$?
  set -e
  local body
  body="$(cat "$out")"
  rm -f "$out"
  if [[ "$expected" == "allow" ]]; then
    interpret_allow "pi" "$code" "$body"
  else
    interpret_deny "pi" "$code" "$body"
  fi
}

run_cursor_case() {
  local expected="$1" cmd="$2"
  local out code
  out="$(mktemp)"
  set +e
  fixture_for cursor beforeShellExecution "$cmd" | "$RYK_BIN" >"$out" 2>/dev/null
  code=$?
  set -e
  local body
  body="$(cat "$out")"
  rm -f "$out"
  if [[ "$expected" == "allow" ]]; then
    interpret_allow cursor "$code" "$body"
  else
    interpret_deny cursor "$code" "$body"
  fi
}

envelope_note() {
  case "$1" in
    codex) echo "ryk hook codex PreToolUse (deny=exit 2)" ;;
    claude) echo "ryk hook claude PreToolUse (permissionDecision)" ;;
    opencode) echo "ryk hook opencode tool.execute.before" ;;
    openclaw) echo "ryk hook openclaw tool.before" ;;
    hermes) echo "ryk hook hermes pre_tool_call" ;;
    grok) echo "ryk hook grok PreToolUse (deny=exit 2 + decision JSON)" ;;
    pi) echo "ryk evaluate --json --stdin (Pi extension path)" ;;
    cursor) echo "bare ryk stdin → beforeShellExecution permission (no first-class launch alias)" ;;
  esac
}

if [[ -z "$RYK_BIN" || ! -x "$RYK_BIN" ]]; then
  log "RYK_BIN missing — cannot run envelope E2E. Build with ./scripts/zig build or set RYK_BIN."
  log "status: skipped (no ryk binary)"
  exit 0
fi

log "ryk host envelope E2E"
log "  ryk: $RYK_BIN"
log "  note: proves ryk hook/evaluate/bare stdin envelopes; host CLI is informational"
log ""

for host in "${HOSTS[@]}"; do
  event="$(resolve_event "$host")"
  if [[ "$event" == "unknown" ]]; then
    log "[$host] skip — unknown host"
    skip=$((skip + 1))
    continue
  fi

  if have "$host" || { [[ "$host" == "cursor" ]] && have cursor-agent; }; then
    log "[$host] run — gate=$event; $(envelope_note "$host") (host CLI present)"
  else
    log "[$host] run — gate=$event; $(envelope_note "$host") (host CLI not installed; ryk envelope path)"
  fi

  allow_ok=0
  deny_ok=0
  if [[ "$host" == "pi" ]]; then
    if run_pi_case allow "$SAFE_CMD"; then allow_ok=1; fi
    if run_pi_case deny "$DANGER_CMD"; then deny_ok=1; fi
  elif [[ "$host" == "cursor" ]]; then
    if run_cursor_case allow "$SAFE_CMD"; then allow_ok=1; fi
    if run_cursor_case deny "$DANGER_CMD"; then deny_ok=1; fi
  else
    if run_hook_case "$host" allow "$SAFE_CMD"; then allow_ok=1; fi
    if run_hook_case "$host" deny "$DANGER_CMD"; then deny_ok=1; fi
  fi

  if [[ "$allow_ok" -eq 1 && "$deny_ok" -eq 1 ]]; then
    log "  readiness: protected (allow+deny pass)"
    pass=$((pass + 1))
  elif [[ "$deny_ok" -eq 1 && "$allow_ok" -eq 0 ]]; then
    log "  readiness: degraded (deny ok, allow failed — policy/eval? fix: ryk doctor)"
    fail=$((fail + 1))
  elif [[ "$deny_ok" -eq 0 ]]; then
    log "  readiness: not-protected (deny failed)"
    fail=$((fail + 1))
  else
    log "  readiness: unknown"
    fail=$((fail + 1))
  fi
  log "  smoke allow=$([[ $allow_ok -eq 1 ]] && echo pass || echo fail) deny=$([[ $deny_ok -eq 1 ]] && echo pass || echo fail)"
done

log ""
log "summary: pass=$pass fail=$fail skip=$skip"
if [[ "$fail" -gt 0 ]]; then
  exit 1
fi
exit 0

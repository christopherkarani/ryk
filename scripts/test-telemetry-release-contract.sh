#!/usr/bin/env bash
# Token-enabled native telemetry smoke. Uses a disposable public PostHog token
# and loopback proxies, so it exercises the shipped worker without network I/O.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/ryk-telemetry-release-contract.XXXXXX")"
cleanup() {
  rm -rf "$TMP_ROOT"
}
trap cleanup EXIT INT TERM

fail() {
  printf 'test-telemetry-release-contract: FAIL: %s\n' "$1" >&2
  exit 1
}

PREFIX="$TMP_ROOT/prefix"
CONFIG="$TMP_ROOT/config"
TOKEN="phc_test_public_token"
PROXY_ENV=(
  "HTTP_PROXY=http://127.0.0.1:1"
  "HTTPS_PROXY=http://127.0.0.1:1"
  "http_proxy=http://127.0.0.1:1"
  "https_proxy=http://127.0.0.1:1"
  "ALL_PROXY=http://127.0.0.1:1"
  "all_proxy=http://127.0.0.1:1"
  "NO_PROXY="
  "no_proxy="
)

./scripts/zig build install-ryk \
  -Doptimize=Debug \
  -Dposthog-project-token="$TOKEN" \
  --prefix "$PREFIX" >/dev/null

ryk() {
  env "XDG_CONFIG_HOME=$CONFIG" "${PROXY_ENV[@]}" "$PREFIX/bin/ryk" "$@"
}

wait_for_queue() {
  local queue="$CONFIG/ryk/telemetry.queue.jsonl"
  for _ in $(seq 1 20); do
    if [[ -s "$queue" ]]; then return 0; fi
    sleep 0.1
  done
  return 1
}

wait_for_event() {
  local event="$1"
  local queue="$CONFIG/ryk/telemetry.queue.jsonl"
  for _ in $(seq 1 30); do
    if [[ -s "$queue" ]] && grep -F -q "\"event\":\"${event}\"" "$queue"; then return 0; fi
    sleep 0.1
  done
  return 1
}

count_event() {
  local event="$1"
  local queue="$CONFIG/ryk/telemetry.queue.jsonl"
  if [[ ! -f "$queue" ]]; then
    printf '0\n'
    return 0
  fi
  grep -F -c "\"event\":\"${event}\"" "$queue" || true
}

has_hook_attribution() {
  local queue="$CONFIG/ryk/telemetry.queue.jsonl"
  [[ -f "$queue" ]] || return 1
  local line
  while IFS= read -r line; do
    [[ "$line" == *'"event":"ryk_enforcement_summary"'* ]] || continue
    [[ "$line" == *'"host":"other"'* ]] || continue
    [[ "$line" == *'"source":"hook"'* ]] || continue
    return 0
  done < "$queue"
  return 1
}

assert_queue_payloads() {
  local queue="$CONFIG/ryk/telemetry.queue.jsonl"
  while IFS= read -r line; do
    [[ "$line" == *'"$ip":0'* ]] || fail "queued event does not disable PostHog IP enrichment"
    [[ "$line" != *'"feature":"telemetry"'* ]] || fail "telemetry control recorded as a feature"
  done < "$queue"
}

# P1-5 opt-in default: fresh state is disabled and nothing is queued or sent
# until an explicit `ryk telemetry enable`.
fresh_status="$(ryk telemetry status --json)"
printf '%s\n' "$fresh_status" | grep -q '"enabled":false' || fail "fresh release did not default to telemetry disabled"
ryk doctor --help >/dev/null 2>/dev/null || true
if [[ -e "$CONFIG/ryk/telemetry.queue.jsonl" ]]; then
  fail "command queued telemetry before explicit opt-in"
fi

ryk telemetry enable >/dev/null || fail "telemetry enable failed"
enabled_status="$(ryk telemetry status --json)"
printf '%s\n' "$enabled_status" | grep -q '"enabled":true' || fail "explicit opt-in did not enable telemetry"

ryk doctor --help >/dev/null 2>/dev/null || true
wait_for_queue || fail "human command did not create a queued telemetry event"
wait_for_event "ryk_feature_summary" || fail "feature summary was not queued"
assert_queue_payloads

ryk feedback bug >/dev/null
wait_for_event "ryk_feedback_submitted" || fail "fixed-category feedback event was not queued"
assert_queue_payloads

integration_before="$(count_event "ryk_integration_summary")"
ryk plugin doctor >/dev/null 2>/dev/null || true
wait_for_event "ryk_integration_summary" || fail "integration summary was not queued"
integration_after="$(count_event "ryk_integration_summary")"
[[ "$integration_after" -eq $((integration_before + 1)) ]] || fail "plugin doctor emitted duplicate integration summaries"
assert_queue_payloads

evaluate_payload="{\"schema_version\":1,\"request_id\":\"telemetry-release-contract\",\"kind\":\"shell_command\",\"command\":\"echo telemetry-safe\",\"cwd\":\"$REPO_ROOT\",\"source\":{\"host\":\"pi\",\"tool_name\":\"bash\",\"mode\":\"tui\",\"session_id\":\"telemetry-release-contract\"}}"
printf '%s\n' "$evaluate_payload" | ryk evaluate --json --stdin >/dev/null 2>/dev/null || true
wait_for_event "ryk_fm_steward_summary" || fail "FM Steward summary was not queued"
wait_for_event "ryk_enforcement_summary" || fail "enforcement summary was not queued"

printf '{}' | ryk evaluate --json --stdin >/dev/null 2>/dev/null || true
wait_for_event "ryk_reliability_summary" || fail "reliability summary was not queued"
assert_queue_payloads

printf '%s' '{"tool_name":"Bash","tool_input":{"command":"echo telemetry-safe"}}' |
  ryk >/dev/null 2>/dev/null || true
for _ in $(seq 1 30); do
  if has_hook_attribution; then
    break
  fi
  sleep 0.1
done
has_hook_attribution || fail "bare agent-hook enforcement was not attributed"
assert_queue_payloads

ryk hook hermes pre_tool_call < "$REPO_ROOT/tests/fixtures/hook-safe.json" >/dev/null 2>/dev/null || true
wait_for_event "ryk_session_summary" || fail "session summary was not queued"
assert_queue_payloads

controls_before="$(wc -l < "$CONFIG/ryk/telemetry.queue.jsonl")"
ryk telemetry status >/dev/null
sleep 0.3
controls_after="$(wc -l < "$CONFIG/ryk/telemetry.queue.jsonl")"
[[ "$controls_before" == "$controls_after" ]] || fail "telemetry status recorded a feature summary"

status_json="$(ryk telemetry status --json)"
printf '%s\n' "$status_json" | grep -q '"enabled":true' || fail "enabled release reports telemetry disabled"
printf '%s\n' "$status_json" | grep -q '"configured":true' || fail "token-enabled release reports transport disabled"
printf '%s\n' "$status_json" | grep -q '"installation_id_present":true' || fail "enabled release did not persist an installation id"

before_machine="$(wc -l < "$CONFIG/ryk/telemetry.queue.jsonl")"
ryk doctor --json >/dev/null 2>/dev/null || true
sleep 0.3
after_machine="$(wc -l < "$CONFIG/ryk/telemetry.queue.jsonl")"
[[ "$before_machine" == "$after_machine" ]] || fail "machine-readable command changed the telemetry queue"

ryk telemetry disable >/dev/null
disabled_json="$(ryk telemetry status --json)"
printf '%s\n' "$disabled_json" | grep -q '"enabled":false' || fail "disable did not persist"
printf '%s\n' "$disabled_json" | grep -q '"queued_events":0' || fail "disable did not clear queued events"
printf '%s\n' "$disabled_json" | grep -q '"installation_id_present":false' || fail "disable did not clear installation id"
if ryk feedback bug >/dev/null 2>/dev/null; then
  fail "feedback claimed delivery while telemetry was disabled"
fi

hard_disabled_json="$(env "XDG_CONFIG_HOME=$CONFIG" RYK_NO_TELEMETRY=1 "$PREFIX/bin/ryk" telemetry status --json)"
printf '%s\n' "$hard_disabled_json" | grep -q '"enabled":false' || fail "hard disable did not override persisted state"
if env "XDG_CONFIG_HOME=$CONFIG" RYK_NO_TELEMETRY=1 "$PREFIX/bin/ryk" feedback bug >/dev/null 2>/dev/null; then
  fail "feedback claimed delivery under hard disable"
fi

printf 'test-telemetry-release-contract: passed\n'

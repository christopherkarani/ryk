#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMUX_SOCKET="ryk-tui-smoke-$$"
SMOKE_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/ryk-tui-smoke.XXXXXX")"

cleanup() {
    tmux -L "$TMUX_SOCKET" kill-server 2>/dev/null || true
    rm -rf "$SMOKE_ROOT"
}
trap cleanup EXIT

fail() {
    echo "tui onboarding PTY smoke: $*" >&2
    exit 1
}

command -v tmux >/dev/null 2>&1 || fail "tmux is required"

RYK_BIN="$ROOT/zig-out/bin/ryk"
[[ -x "$RYK_BIN" ]] || fail "build ryk first with ./scripts/zig build"

capture_pane() {
    tmux -L "$TMUX_SOCKET" capture-pane -p -S -200 2>/dev/null
}

wait_for() {
    local needle="$1"
    local attempts=0
    while ((attempts < 80)); do
        if capture_pane | grep -Fq "$needle"; then
            return 0
        fi
        sleep 0.05
        attempts=$((attempts + 1))
    done
    capture_pane >&2
    fail "timed out waiting for: $needle"
}

mkdir -p "$SMOKE_ROOT/start-workspace" "$SMOKE_ROOT/home"
tmux -L "$TMUX_SOCKET" new-session -d -x 100 -y 30 \
    -c "$SMOKE_ROOT/start-workspace" \
    "before=\$(stty -g); env HOME='$SMOKE_ROOT/home' PATH='/usr/bin:/bin' RYK_RESOURCE_ROOT='$ROOT' '$RYK_BIN' start --skip-verify; code=\$?; after=\$(stty -g); if [ \"\$before\" = \"\$after\" ]; then echo __RYK_TERMIOS_RESTORED__; else echo __RYK_TERMIOS_CHANGED__; fi; exit \$code"
tmux -L "$TMUX_SOCKET" set-option remain-on-exit on

# Scenario 1 (no hosts on PATH): start skips the multi-select and reports skipped verification.
wait_for "No supported agent hosts detected in PATH."
sleep 0.3

start_screen="$(capture_pane)"
notice_count="$(grep -Fc "No supported agent hosts detected in PATH." <<<"$start_screen")"
[[ "$notice_count" == "1" ]] || fail "expected one no-hosts notice, found $notice_count"

if grep -Eq '^ {12,}(🛡  )?ryk' <<<"$start_screen"; then
    fail "banner drifted horizontally after buffered output flushed in raw mode"
fi

wait_for "Setup complete — verification skipped"
wait_for "__RYK_TERMIOS_RESTORED__"

echo "ryk start (no hosts) PTY smoke passed"

tmux -L "$TMUX_SOCKET" kill-server 2>/dev/null || true
mkdir -p "$SMOKE_ROOT/hosts-workspace" "$SMOKE_ROOT/hosts-home" "$SMOKE_ROOT/bin"
printf '#!/usr/bin/env bash\nexit 0\n' >"$SMOKE_ROOT/bin/codex"
chmod +x "$SMOKE_ROOT/bin/codex"

# Scenario 2 (fake codex on PATH): multi-select shows once and reports skipped verification.
tmux -L "$TMUX_SOCKET" new-session -d -x 100 -y 40 \
    -c "$SMOKE_ROOT/hosts-workspace" \
    "before=\$(stty -g); env HOME='$SMOKE_ROOT/hosts-home' PATH='$SMOKE_ROOT/bin:/usr/bin:/bin' RYK_RESOURCE_ROOT='$ROOT' '$RYK_BIN' start --skip-verify; code=\$?; after=\$(stty -g); if [ \"\$before\" = \"\$after\" ]; then echo __RYK_TERMIOS_RESTORED__; else echo __RYK_TERMIOS_CHANGED__; fi; exit \$code"
tmux -L "$TMUX_SOCKET" set-option remain-on-exit on

wait_for "Select agent hosts to integrate"
sleep 0.3

hosts_screen="$(capture_pane)"
host_prompt_count="$(grep -Fc "Select agent hosts to integrate" <<<"$hosts_screen")"
[[ "$host_prompt_count" == "1" ]] || fail "expected one host prompt, found $host_prompt_count"

if grep -Eq '^ {12,}(🛡  )?(ryk|Select agent hosts)' <<<"$hosts_screen"; then
    fail "start output drifted horizontally at the raw prompt boundary"
fi

tmux -L "$TMUX_SOCKET" send-keys Enter
wait_for "Setup complete — verification skipped"
wait_for "__RYK_TERMIOS_RESTORED__"

echo "ryk start (host multi-select) PTY smoke passed"

# Scenario 3: exercise the real verified auto path rather than a fixture binary.
mkdir -p "$SMOKE_ROOT/verified-workspace" "$SMOKE_ROOT/verified-home"
verified_output="$SMOKE_ROOT/verified.out"
(
    cd "$SMOKE_ROOT/verified-workspace"
    env HOME="$SMOKE_ROOT/verified-home" \
        PATH="$SMOKE_ROOT/bin:/usr/bin:/bin" \
        RYK_RESOURCE_ROOT="$ROOT" \
        "$RYK_BIN" start --auto
) >"$verified_output"

[[ "$(grep -Fc "🛡  ryk" "$verified_output")" == "1" ]] ||
    fail "verified auto onboarding did not render exactly one banner"
grep -Fq "codex  ✓ fail-closed chain verified" "$verified_output" ||
    fail "verified auto onboarding did not verify the Codex integration chain"
[[ "$(grep -Fc "Setup complete — hooks verified for codex" "$verified_output")" == "1" ]] ||
    fail "verified auto onboarding did not render exactly one verified-hooks end card"
grep -Fq "protection grade: hook" "$verified_output" ||
    fail "verified auto onboarding did not state the hook protection grade"
if grep -Fq "You're now protected by ryk" "$verified_output"; then
    fail "verified auto onboarding claimed unqualified protection"
fi
[[ -f "$SMOKE_ROOT/verified-workspace/.agents/plugins/ryk/.codex-plugin/plugin.json" ]] ||
    fail "verified auto onboarding did not install the managed Codex plugin"

echo "ryk start --auto (verified Codex chain) smoke passed"

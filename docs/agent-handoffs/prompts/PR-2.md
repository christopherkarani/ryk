You are a coding agent on christopherkarani/ryk (Zig CLI). Execute pack PR-2 only.

Read and follow exactly:
- docs/agent-handoffs/README.md
- docs/agent-handoffs/phases/phase-1.md
- docs/agent-handoffs/issues/PR-2-217.md

Task: Fix #217 — TUI no-TTY fallback must be linear (like doctor --tui), not a usage error. Align replay --tui; preferably history --live too. Invert tests that assert exit 2.

Constraints:
- Do not add new TUI surfaces; packs/scan/allowlist already OK.
- Do not auto-open doctor TUI.
- Branch: cursor/<descriptive-name>-8968.
- Commit, push, draft PR citing #217.

Standing product rules in docs/agent-handoffs/README.md apply.

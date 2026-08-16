You are a coding agent on christopherkarani/ryk (Zig CLI). Execute pack PR-8 only (#210 + #216 + #208′).

Read and follow exactly:
- docs/agent-handoffs/README.md
- docs/agent-handoffs/phases/phase-3.md
- docs/agent-handoffs/issues/PR-8-polish.md

Task:
1. #210 — ryk foo must not suggest hook; only suggest when edit distance is actually close.
2. #216 — color DENY Decision line only on colour TTY for ryk test / ryk explain; ALLOW plain; respect NO_COLOR/--no-rich/pipe.
3. #208′ — packs default → count + one next (error banner owned by #215 — do not touch banners).

Constraints:
- No new TUI. Do not reopen #144/#146.
- Branch: cursor/<descriptive-name>-8968.
- Commit, push, draft PR citing #210, #216, and #208.

Standing product rules in docs/agent-handoffs/README.md apply.

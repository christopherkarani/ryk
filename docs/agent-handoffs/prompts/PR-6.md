You are a coding agent on christopherkarani/ryk (Zig CLI). Execute pack PR-6 only (#211 + #214). Safe to run in parallel with PR-0/1/2.

Read and follow exactly:
- docs/agent-handoffs/README.md
- docs/agent-handoffs/phases/phase-2.md
- docs/agent-handoffs/issues/PR-6-211-214.md

Task:
1. #211 — ryk env --help must print real env help and exit 0 (today routes to env schema usage exit 2).
2. #214 — bare ryk policy explain must print usage (like ryk test), not only “expected a type and target.”

Skip #204 — already fixed on main.

Constraints:
- Branch: cursor/<descriptive-name>-8968.
- Commit, push, draft PR citing #211 and #214.

Standing product rules in docs/agent-handoffs/README.md apply.

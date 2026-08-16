You are a coding agent on christopherkarani/ryk (Zig CLI). Execute pack PR-5 only (#206 + #212).

Read and follow exactly:
- docs/agent-handoffs/README.md
- docs/agent-handoffs/phases/phase-2.md
- docs/agent-handoffs/issues/PR-5-206-212.md

Task:
1. #206 — remove cursor advertising from stop help/examples and uninstall dry-run; launch forbids ryk cursor.
2. #212 — plugin --help host list honesty for grok/pi (copy only; no fake plugin-pi).

Constraints:
- Update tests that currently lock the dishonest lists.
- Watch help.zig conflicts if PR-4 is in flight.
- Branch: cursor/<descriptive-name>-8968.
- Commit, push, draft PR citing #206 and #212.

Standing product rules in docs/agent-handoffs/README.md apply.

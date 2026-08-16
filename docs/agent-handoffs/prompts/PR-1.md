You are a coding agent on christopherkarani/ryk (Zig CLI). Execute pack PR-1 only.

Read and follow exactly:
- docs/agent-handoffs/README.md
- docs/agent-handoffs/phases/phase-1.md
- docs/agent-handoffs/issues/PR-1-215.md

Task: Fix #215 — drop the shield banner from almost every command. Quiet success; no banner on success/--quiet/--no-rich/pipe/errors. Brand may stay on --version and maybe first-run help only. After merge, close #213 as duplicate with a comment pointing at this PR.

Constraints:
- Rewrite banner tests in src/cli/mod.zig (do not quiet-only-on-init).
- Do not fold packs dump (#208) or session SHIELD UP (#145).
- Branch: cursor/<descriptive-name>-8968.
- Commit, push, draft PR citing #215 (and note closes #213).

Standing product rules in docs/agent-handoffs/README.md apply.

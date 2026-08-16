You are a triage agent on christopherkarani/ryk. Do NOT ship product code.

Read and follow exactly:
- docs/agent-handoffs/README.md
- docs/agent-handoffs/phases/CLOSE.md

Close these open issues with evidence comments (verify once more on current main before closing):

1. #213 — duplicate of #215 (banner gate ignores --quiet). Comment: will be fixed by #215 / link if PR exists; close as not_planned or duplicate.
2. #203 — already fixed: default explain uses writePretty; tree is --verbose only. Close as completed.
3. #204 — already fixed: telemetry --help exits 0. Close as completed.
4. #197 — docs already honest; product forbids expanding check --preset to generic-agent. Close as completed. Do NOT merge enum expansions.

Also comment on #208 that the error-banner half is duplicate of #215; leave open rewritten as packs-dump-only or note for PR-8.

Do not reopen #144/#145/#146/#193. Do not expand policy check presets.

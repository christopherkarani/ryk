# Agent hand-offs — ryk open-issue triage

**Repo:** `christopherkarani/ryk` · **Pin:** `0.2.19` / `main`  
**Triage date:** 2026-08-16  
**Method:** three adversarial explore agents + dependency analyst against current source (not issue text).

**Wave 2 (2026-08-16):** PERF/MEM/security `needs-triage` review — 20 confirmed → ready-for-eng, 7 rejected. See [wave-2-ready-for-eng.md](wave-2-ready-for-eng.md).

## Verdict summary

| Issue | Verdict | Action |
|------:|---------|--------|
| 221 | REAL (P1) | Fix — Phase 0 |
| 215 | REAL | Fix — Phase 1 (closes #213) |
| 217 | REAL | Fix — Phase 1 |
| 205 | REAL | Fix — Phase 1 (with #218) |
| 218 | REAL | Fix — Phase 1 (with #205) |
| 219 | REAL | Fix — Phase 2 (with #207) |
| 207 | PARTIALLY_REAL | Fix remaining — Phase 2 (with #219) |
| 206 | REAL | Fix — Phase 2 (with #212) |
| 212 | REAL | Fix — Phase 2 (with #206) |
| 211 | REAL | Fix — Phase 2 (with #214) |
| 214 | REAL | Fix — Phase 2 (with #211) |
| 209 | REAL | Fix — Phase 3 (with #220) |
| 220 | PARTIALLY_REAL | Fix remaining — Phase 3 (with #209) |
| 210 | REAL | Fix — Phase 3 |
| 216 | REAL | Fix — Phase 3 |
| 208 | PARTIALLY_REAL | Rewrite → packs dump only; Phase 3 |
| 213 | REAL but subsumed | **CLOSE** as duplicate of #215 |
| 203 | ALREADY_FIXED | **CLOSE** after one repro |
| 204 | ALREADY_FIXED | **CLOSE** |
| 197 | ALREADY_FIXED | **CLOSE** (do not expand check enum) |

## Parallel vs sequential

### Launch in parallel (max concurrency)

These four packs do not share choke-point files and can start together:

1. **PR-0** `#221` — `run.zig` / sandbox card / grok grants
2. **PR-1** `#215` — `mod.zig` banner gate
3. **PR-2** `#217` — `replay.zig` (+ `history.zig`)
4. **PR-6** `#211` + `#214` — env / policy-explain help

### Must be sequential

| Order | Why |
|-------|-----|
| PR-1 (`#215`) before any “banner on errors” polish | Shared `shouldShowBanner` / presentation tests |
| PR-3 (`#205`+`#218`) as **one** agent | Shared `doctor.zig` remediation voice |
| PR-3 before PR-4 (`#207`+`#219`) preferred | First-run “one next” must match start/doctor honesty |
| PR-0 alone for `run.zig` / `sandbox_card.zig` | Do not fold banner work into launch fix |

### Fill gaps after Phase 0–1 land

- **PR-5** `#206`+`#212` — host-list honesty (`help.zig` / plugin / stop)
- **PR-7** `#209`+`#220` — installer / update
- **PR-8** `#210`+`#216`+`#208′` — micro polish

## Pack index

| Pack | Issues | Handoff | Prompt |
|------|--------|---------|--------|
| PR-0 | #221 | [issues/PR-0-221.md](issues/PR-0-221.md) | [prompts/PR-0.md](prompts/PR-0.md) |
| PR-1 | #215 (−#213) | [issues/PR-1-215.md](issues/PR-1-215.md) | [prompts/PR-1.md](prompts/PR-1.md) |
| PR-2 | #217 | [issues/PR-2-217.md](issues/PR-2-217.md) | [prompts/PR-2.md](prompts/PR-2.md) |
| PR-3 | #205+#218 | [issues/PR-3-205-218.md](issues/PR-3-205-218.md) | [prompts/PR-3.md](prompts/PR-3.md) |
| PR-4 | #207+#219 | [issues/PR-4-207-219.md](issues/PR-4-207-219.md) | [prompts/PR-4.md](prompts/PR-4.md) |
| PR-5 | #206+#212 | [issues/PR-5-206-212.md](issues/PR-5-206-212.md) | [prompts/PR-5.md](prompts/PR-5.md) |
| PR-6 | #211+#214 | [issues/PR-6-211-214.md](issues/PR-6-211-214.md) | [prompts/PR-6.md](prompts/PR-6.md) |
| PR-7 | #209+#220 | [issues/PR-7-209-220.md](issues/PR-7-209-220.md) | [prompts/PR-7.md](prompts/PR-7.md) |
| PR-8 | #210+#216+#208′ | [issues/PR-8-polish.md](issues/PR-8-polish.md) | [prompts/PR-8.md](prompts/PR-8.md) |
| CLOSE | #213,#203,#204,#197 | [phases/CLOSE.md](phases/CLOSE.md) | [prompts/CLOSE.md](prompts/CLOSE.md) |

## Phase briefs

- [phases/phase-0.md](phases/phase-0.md) — P1 launch blocker
- [phases/phase-1.md](phases/phase-1.md) — UX chrome contracts
- [phases/phase-2.md](phases/phase-2.md) — help / copy
- [phases/phase-3.md](phases/phase-3.md) — polish

## Kickoff Canvas

Interactive one-button launcher: [`ryk-issue-kickoff.canvas.tsx`](ryk-issue-kickoff.canvas.tsx) (also written to the Cursor canvases directory for live Kick off agent buttons). Each button opens a Composer chat with the pack prompt preloaded and @mentions the canvas.

**Kick now (parallel):** PR-0 · PR-1 · PR-2 · PR-6  
**Then:** PR-3 (one agent) → PR-4 · PR-5 · PR-7 · PR-8 · CLOSE

## Standing product rules (every agent)

- Do **not** reopen #144, #145, #146, #193, #195, #196, #203–#212 as “reopens.”
- Do **not** expand `policy check --preset` to accept `generic-agent` (CPO #197).
- One PR per pack. Do not fold unrelated feel tickets.
- Prefer quiet success, one next step, no SHIELD walls on success/error paths unless the ticket says otherwise.

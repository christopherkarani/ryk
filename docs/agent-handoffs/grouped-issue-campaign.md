# Grouped-issue campaign (2026-08-16)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. One pack = one PR. Do not start a pack whose files collide with an unfinished earlier pack. Steps use checkbox syntax for Wave 0/1 kickoff only — this is a campaign plan, not 176 TDD tasks.

**Goal:** Every currently-open GitHub issue has exactly one primary pack, a disposition, and a Wave 0/1/2/3 slot so the board can be walked without duplicate work or silent drops.

**Architecture:** Group by shared root cause and shared files, not by title prefix. One pack owns one file set. Closed parent tickets are never reopened; leftover children get their own pack. Wave 3 is triage-first. Mega-packs are **never** one PR.

**Tech stack:** Zig 0.15.2. Default gate `zig build test-fast`. Use `zig build test` when a pack touches daemon, plugin install, or seatbelt.

**Pin:** this branch’s merge-base `430c13e6`. `origin/main` has moved (seen at `50a78fe`); fetch and re-pin before a pack starts.

**Canonical path:** `docs/agent-handoffs/grouped-issue-campaign.md` (tracked). A copy may exist under gitignored `docs/superpowers/plans/`.

---

## What "done today" means

This is a **campaign plan**, not a promise that 176 PRs merge in one sitting.

The campaign is done when all four are true:

1. Every open issue number appears **exactly once** in the `ISSUE-INVENTORY` block.
2. Wave 0 closes are applied on GitHub, or the apply script is the documented blocker (`403` / missing `issues:write`).
3. Wave 1 packs are launched (or explicitly blocked by a merge gate).
4. Wave 2 and Wave 3 have an owner, a file set, and a start condition. They are **not** "in parallel today."

A pack is launched when its branch exists, its first failing test is written, and its issue numbers are labeled `in-eng` (or the apply script is the documented blocker).

---

## Standing product rules (do not violate)

Copied from `docs/agent-handoffs/README.md`. These override any ticket text.

- Do **not** reopen #144, #145, #146, #193, #195, #196, **#203–#212** as "reopens."
- Close-as-completed for #203 / #204 is allowed (CPO already decided). That is not a reopen.
- Open members of #203–#212 (#205, #206, #207, #208) may be **fixed** in their packs. Do not file them again.
- Do **not** expand `policy check --preset` to accept `generic-agent` (CPO #197).
- One PR per pack. Quiet success, one next step. No SHIELD walls unless the ticket requires it.
- Do not weaken fail-closed / lock / fsync / ask≠allow / CI ask→deny.

---

## Closed-parent audit (do not plan work on these IDs)

These parents are **closed**. Do not reopen them. Do not put them in the inventory.

| Closed parent | Why it stays closed | Open leftover (own pack) |
|---|---|---|
| #391–#398, #402, #404 | Hook cluster closed after first review | #399 HOOK-PERF; #405 EVAL-PERF; #406 HOOK-PERF; #418 POLICY-PERF (Wave 3); #430 ENGINE-PERF (Wave 3); #433 POLICY-PERF (Wave 3); #436 EVAL-PERF; #438 HOOK-PERF |
| #209–#214, #217, #219–#221 | UX Wave 1 already shipped | #205/#218 DOCTOR-PR3; #206 HOSTHELP; #207/#216/#238 COPY; #215/#234 BANNER; #208/#235 PACKS |
| #219 | First-run copy **closed** | Do not reopen #219. #238 is a **new** ticket for leftover first-run strings — allowed. |
| #346–#349, #201, #202, #222, #223, #260 | Not in the live open set | Do not invent P1-ATTEST-CLI / P1-FEED / CLOSE-#202 packs for them |

If a leftover child's remaining work is already on the pin, Wave 0/3 closes it as `ALREADY_FIXED`. Do not reopen the parent.

---

## Dual-ownership resolution (binding)

| Issue | Loser | Winner | Why |
|---|---|---|---|
| #208 | BANNER | PACKS | Unique remaining work is the default dump. Banner half is #215 + #234. |
| #235 | — | PACKS | Sole owner of default `ryk packs` dump / `src/cli/packs.zig`. |
| #219 | COPY | closed | Do not reopen. Leftover first-run strings are #238. |
| #234 | HELP | BANNER | Same shield-banner root as #215. |
| #236 | CMD-UX | DOCTOR-PR3 | Same companion-reinstall next-step as #205. |
| #237 | HOST | DOCTOR-PR3 | Doctor table honesty. Actual hermes/opencode install is P1-HOST-WIRE. |
| #243 | DOCTOR-PR3 | DOCTOR-UX | Network-grade honesty at launch; includes `src/cli/run.zig`. After PR #359. |
| #270 | HOSTLIST | DOCS-QA | Windows `ryk.pdb` hygiene, not host-list drift. |
| #271 | DOCS-QA / HOSTLIST | P1-PLUGIN-LIST | Same grok/pi surface as #228 / #229. |
| #401 / #421 | PERF-REST | MATCH | Same file as #400: `src/policy/matchers.zig`. Sequence #401 first. |
| #440 / #446 | BUILD today | ZIG-ARCH | Today BUILD is #342 + #441 + #447 only. |
| #411 / #448 | DOCTOR-UX | PERF-REST | Doctor PERF after G1 and DOCTOR-PR3. |
| #224 / #225 / #226 / #242 | Wave 1 code | CLOSE-D | Pin already returns nonzero; confirm tests then close. |

---

## Merge gates (file collisions)

Do **not** start the later pack until the earlier pack is merged to `main` (or explicitly rebased onto the earlier pack and the earlier pack is abandoned).

| Gate | Earlier pack | Later pack | Shared files |
|---|---|---|---|
| G1 | MEM-ERRDEFER | DOCTOR-PR3, then DOCTOR-UX, then PERF-REST #411/#448 | `src/cli/doctor.zig` |
| G2 | MEM-ERRDEFER | HOOK-PERF | `src/cli/hook.zig` |
| G3 | P1-PLUGIN-LIST | P1-HOST-WIRE | `src/cli/plugin.zig` |
| G4 | P1-STOP | HOST (Wave 3 uninstall/list) | `src/cli/disable.zig` / plugin uninstall paths |
| G5 | HOOK-PERF issues | serialize #399 → #406 → #438 on one branch | `src/cli/hook.zig` |
| G6 | MATCH #401 | MATCH #400 / #421 | `src/policy/matchers.zig` — semantics before stack-copy / path-variant edits |
| G7 | BANNER | PACKS error-path chrome | presentation / `shouldShowBanner` in `src/cli/mod.zig` |
| G8 | DOCTOR-PR3 (PR #359) | DOCTOR-UX | `src/cli/doctor.zig`, `src/cli/start.zig` |

**Not a G3 member:** P1-ATTEST-HOT (#442) lives in `integrations/*-plugin`, not `src/cli/plugin.zig`. It may run in parallel with G3.

Wave 2 launch order after G1/G2 clear:

`DOCTOR-PR3 (rebase PR #359) → BANNER → HOSTHELP → HELP → PACKS → COPY → EXIT → CMD-UX (split) → DOCS-FAST → HOOK-PERF → EVAL-PERF → DOCTOR-UX`

HOOK-PERF is three sequential commits on `cursor/hook-perf-a58c` (#399, then #406, then #438).

---

## factory:auto rule (binding)

`factory:auto: yes` means a factory agent may pick the pack up. It does **not** mean the change is non-semantic.

**Honor labels already on GitHub** even when the work is security-adjacent: #215, #216, #218, #315, #317, #345, #411, #412, #430, #441, #445, #448.

**Do not honor a label that is not on GitHub.** #400 is `ready-for-eng` only — **no** `factory:auto`. Do not add it without human review.

Allowed new yes: mechanical errdefer, string-only help/copy, markdown-only docs.

Forbidden new yes: caps, eviction, matcher semantics, fail-closed, lock, fsync, ask≠allow, sandbox, attestation, plugin uninstall/install.

---

## Wave 0 — close / reject / confirm-fixed (no new feature code)

**Goal:** Remove work that is already done, overstated, or CPO-wontfix so engineering does not pick it up.

**Apply first, before any factory agent reads MEM tickets.**

Do **not** run `docs/agent-handoffs/apply-wave-2-triage.sh`. That script still lists closed parents (#391–#398, #402, #404) and would add `factory:auto` to cap tickets #371 / #373.

**Executable spec:** `docs/agent-handoffs/wave-0-campaign-apply.json`  
**Runner:** `docs/agent-handoffs/apply-wave-0-campaign.sh` (skips IDs that are already closed).

Promote labels (binding):

| IDs | Labels | Why |
|---|---|---|
| #362, #364, #365, #366, #367, #368 | `triage:confirmed` + `ready-for-eng` + `factory:auto` | Mechanical errdefer |
| #371, #373 | `triage:confirmed` + `ready-for-eng` only | Caps. **No `factory:auto`.** |

If GitHub returns `403`, stop and treat the JSON/script as the Wave 0 artifact. Do not assume labels flipped. Do not fall back to `wave-2-apply-plan.json`.

- [ ] **Step 0a:** Confirm CLOSE-A / CLOSE-D evidence on the current pin.
- [ ] **Step 0b:** Apply closes + remaining promotes with an `issues:write` token.
- [ ] **Step 0c:** Re-run Appendix B. When closes land, delete those IDs from the inventory.

### Pack CLOSE-A — CPO already decided

**Issues:** #197, #203, #204  
**Disposition:** close as completed after pin confirm.  
**factory:auto:** no

| Issue | Close as | Pin check |
|---|---|---|
| #197 | completed | Do not expand `policy check --preset`. Docs already use path form. |
| #203 | completed | Default `ryk explain` is `writePretty`; box tree only behind `--verbose`. |
| #204 | completed | `src/telemetry.zig` handles `--help` / `-h`. |

### Pack CLOSE-B — Wave 2 adversarial rejects

**Issues:** #280, #287, #294, #298, #299, #302, #311  
**Disposition:** close per `docs/agent-handoffs/wave-2-ready-for-eng.md`.  
**factory:auto:** no

| Issue | Close as | One-line reason (must stay true on pin) |
|---|---|---|
| #280 | completed | `init` already exits 1 on exists (`src/cli/init.zig`) |
| #287 | not_planned | `--json` exit 0 is by design; gate is `doctor --check` |
| #294 | not_planned | FM never softens `.block` (`src/cli/shell_eval_fm.zig`) |
| #298 | completed | feed uses `redact_bridge` |
| #299 | not_planned | No current secret-print path (`intercept/credentials.zig` redacts). Remaining ask is test-hardening, not a leak fix. |
| #302 | completed | seatbelt / `--os-sandbox on` fail closed |
| #311 | not_planned | documented host matrix + deadlock-check, not a missing gate |

**#311 does not close the HOST pack.** #258–#259 (Wave 1) and #261–#263 / #306–#310 (Wave 3) stay open. They are about wiring hosts, not about adding the gate #311 asked for.

### Pack CLOSE-C — temp probe

**Issues:** #324  
**Disposition:** close as not_planned. Title is `[TEMP] permission probe — close me`.  
**factory:auto:** no

### Pack CLOSE-D — evaluate / unknown-command already nonzero

**Issues:** #224, #225, #226, #242  
**Disposition:** close as completed after pin confirm. **Do not open a Wave 1 fix PR unless a named repro still exits 0.**  
**factory:auto:** no

| Issue | Pin check |
|---|---|
| #224 | `src/cli/mod.zig` unknown command returns `exit_codes.usage`; test `unknown command returns non-zero with useful message` (~L1243). |
| #225 / #242 | `evaluatePayload` parse failure returns `exit_invalid_input` (64) (`src/cli/evaluate.zig` ~L199–202). |
| #226 | Bare `ryk evaluate` without `--json --stdin` returns `exit_codes.usage` (`src/cli/evaluate.zig` ~L163–164). |

If a ticket names a **registered** command that still exits 0, move that ID to EXIT and keep it open. `audit` / `sandbox` are not registered commands; they hit the unknown-command path (already nonzero).

---

## Wave 1 — P0/P1 + confirmed mechanical (launch today)

Each pack: one branch, tests first, default gate, then `in-eng`.

### Pack P1-STOP — stop does not remove plugin dirs

**Issues:** #345  
**Files:** `src/cli/disable.zig` (`commandAs(..., "stop")` → `removeKnownPluginPaths`). There is **no** `src/cli/stop.zig`.  
**Bug (still real on pin):** `plugin.fileExistsAbsolute` is `access()` — true for directories. `deleteFile` fails `IsDir`, `catch` **`continue`s**, so `dirExists` / `deleteTree` never run (~L448–456). Hermes disable already uses `deleteTree` (~L274).  
**Test:** install a host whose plugin path is a directory; `ryk stop`; assert the directory is gone.  
**factory:auto:** yes (already on GitHub). Reviewer still checks uninstall fail-closed.  
**Gate:** G4.

- [ ] Write the failing stop-dir test.
- [ ] Run it; expect FAIL (`IsDir` / dir still present).
- [ ] Stop `continue`ing past `IsDir`; `deleteTree` directories.
- [ ] Re-run test; expect PASS. Then `zig build test-fast`.
- [ ] Commit on `cursor/p1-stop-a58c`.

### Pack P1-PLUGIN-LIST — grok / pi missing from plugin surface

**Issues:** #228, #229, #271  
**Files:** `src/cli/plugin.zig` list + help enum; public surface contract tests  
**Test:** `plugin list` and `plugin --help` include grok and pi; contract test covers those rows.  
**factory:auto:** no  
**Gate:** G3 — first on `plugin.zig`.

### Pack P1-HOST-WIRE — hermes / opencode advertised but unwired

**Issues:** #258, #259  
**Files:** plugin install / host alias wiring (not doctor copy — that is #237 / DOCTOR-PR3)  
**Test:** `ryk hermes` / `ryk opencode` install or fail closed with an honest next step. Do not weaken interactive defaults.  
**factory:auto:** no  
**Gate:** G3 — after P1-PLUGIN-LIST.

### Pack P1-ATTEST-HOT — plugin re-attest hashes the binary every block

**Issues:** #442  
**Files:** `integrations/openclaw-plugin/src/index.ts` (`callRyk` → `attestRykCandidate`), `integrations/opencode-plugin/src/index.ts`, `integrations/hermes-plugin/` as named by the ticket. **Not** `src/cli/plugin.zig`.  
**Test:** second blocking eval in one process does not re-hash ~16MB / respawn `version --json` unless the binary mtime changed. Fail-closed if attestation is missing.  
**factory:auto:** no  
**Gate:** none with G3. May run in parallel with P1-PLUGIN-LIST.

### Pack MATCH — 16KB glob / multi-star / path variants

**Issues:** #400, #401, #421  
**Files:** `src/policy/matchers.zig` (not `matcher.zig`)  
**Facts:** buffers are `max_command_glob_bytes` = **16KB**. #401 common-case trailing `*` is O(n+m); remaining work is multi-internal-`*`. Overflow stays match-fail-closed.  
**Sequence (G6):** (1) #401 failing glob tests only; review before other edits. (2) #400 stack-copy fast-path. (3) #421 path variants. One branch, three commits — or split #401 to `cursor/match-glob-a58c` if review wants isolation.  
**factory:auto:** no (GitHub has no `factory:auto` on #400; #401 is semantics).  
**Gate:** G6.

### Pack MEM-ERRDEFER — dual-dupe / missing errdefer

**Issues:** #362, #364, #365, #366, #367, #368  
**Files:** `src/cli/interactive.zig` (`getSelectedLabels`); `src/cli/hook.zig` (prompt-secret + `recordDaemonMetadataRedaction`); `src/cli/decide.zig` (#366); `src/cli/doctor.zig` host-row dupes (#367, #368)  
**Not in this pack:** #371 / #373 (caps, Wave 3 MEM-REST).  
**Test:** allocator-fail inject on the second dupe; no leak / no lost first dupe.  
**factory:auto:** yes **after** Wave 0 promote. Live labels today are still `needs-triage` — do not start factory pickup until promote lands or is 403-blocked.  
**Gate:** G1, G2 — merge before DOCTOR-PR3 / HOOK-PERF.

### Pack BUILD — today slice only

**Issues:** #342, #441, #447  
**Deferred:** #440, #446 → ZIG-ARCH  
**Files:** only the files those three tickets name. Do **not** list `hook.zig` / `plugin.zig` / `shell_eval.zig`.  
**#441:** honor existing `factory:auto`.  
**#342 / #447:** no new `factory:auto` unless the diff is mechanical build-graph with no runtime change.  
**Test:** `zig build test-fast` plus the ticket's named target.

---

## Wave 2 — leftover UX / hook-eval (after merge gates)

Start only after the listed gates. Launch order is the chain in Merge gates.

### Pack DOCTOR-PR3 — finish the in-review doctor PR

**Issues:** #205, #218, #236, #237  
**Files:** `src/cli/doctor.zig`, `src/cli/start.zig`, `src/cli/onboarding.zig`, `src/cli/daemon_errors.zig`, `src/tui/render.zig`  
**#218 is `in-review` on PR #359** (`factory/issue-218`). There is **no** `cursor/fix-205-218-daemon-honesty-8968` on origin.  
**Do not open a second doctor PR.** Rebase/finish [PR #359](https://github.com/christopherkarani/ryk/pull/359). Handoff notes: `docs/agent-handoffs/issues/PR-3-205-218.md` (branch field updated to `factory/issue-218`).  
**#236** is the same companion-reinstall next step as #205.  
**#237** is table honesty; do not implement hermes/opencode install here (P1-HOST-WIRE).  
**factory:auto:** no new yes (#218 already labeled).  
**Gate:** G1, then G8 before DOCTOR-UX.

### Pack DOCTOR-UX — remaining doctor/launch honesty

**Issues:** #243, #278, #288  
**Files:** `src/cli/doctor.zig`, `src/cli/run.zig` (#243 grade receipts), `--no-rich` table chrome (#278), `src/cli/readiness.zig` + docs (#288)  
**#288 vs #287:** #287 closes in Wave 0. #288 is docs/behavior of `doctor --check` vs default diagnose.  
**#411 / #448** stay in PERF-REST.  
**factory:auto:** no  
**Gate:** G8 — after PR #359 merges.

### Pack BANNER — SHIELD / quiet success

**Issues:** #215, #234  
**Files:** banner / `shouldShowBanner` / presentation in `src/cli/mod.zig` only. **Not** `src/cli/packs.zig`.  
**factory:auto:** #215 already yes.  
**Gate:** G7.

### Pack HOSTHELP — stop/start host-list copy

**Issues:** #206, #233  
**Files:** stop/start help strings. Not plugin uninstall (`disable.zig` body is P1-STOP).  
**factory:auto:** no

### Pack HELP — help / usage listing

**Issues:** #227, #230, #231, #232, #279, #282, #285, #290  
**Files:** root help; `src/cli/help.zig` or equivalent; **`src/cli/tools.zig` for #282 / #290**  
**Split:** if the tools-command diff is more than strings, land #282/#290 as a second commit or `cursor/tools-help-a58c`.  
**factory:auto:** yes if the diff is strings-only

### Pack PACKS — default `ryk packs` dump

**Issues:** #208, #235  
**Files:** `src/cli/packs.zig`  
**#208:** dump only. Banner half is BANNER. After #215 lands, rewrite #208 body to dump-only or close it as duplicate of #235.  
**factory:auto:** no  
**Gate:** G7.

### Pack COPY — remaining copy (including leftover first-run strings)

**Issues:** #207, #216, #238  
**Files:** the copy sites those tickets name.  
**#238 is not a reopen of #219.** Track concrete leftover first-run strings only.  
**factory:auto:** #216 already yes; #207/#238 yes if strings-only.

### Pack EXIT — remaining exit-code consistency

**Issues:** #277, #281  
**Files:** `src/cli/exit_codes.zig` and the command files those tickets name  
**Do not** change `--json` success-on-print (#287 closed). Evaluate/unknown-command exits are CLOSE-D unless a CLOSE-D pin check fails.  
**factory:auto:** no

### Pack CMD-UX — command UX leftovers

**Issues:** #239, #240, #241, #275, #276, #283, #284, #286, #291, #292  
**NEVER one PR.** One command file (or one shared help string) per PR / sequential commit.  
**Files:** per-ticket CLI command files under `src/cli/`  
**factory:auto:** no by default

### Pack DOCS-FAST — already `ready-for-eng` docs

**Issues:** #315, #317  
**Files:** `docs/redteam.md`, `docs/mcp.md`  
**factory:auto:** yes (already on GitHub)

### Pack HOOK-PERF — leftover hook.zig PERF

**Issues:** #399, #406, #438  
**Files:** `src/cli/hook.zig` only for this pack  
**#399:** remaining null site ~L547–548 `resolveWorkspaceRoot(io, allocator, null, ".")`. PreToolUse already passes bound workspace (~L1460). `src/cli/shell_eval.zig` already prefers bound `workspace_root` (M-9). **Do not** remove null walk-up in `shell_eval`.  
**#406 / #438:** response / fail-closed construction. Keep hook field contract.  
**factory:auto:** no  
**Gate:** G2, G5

### Pack EVAL-PERF — shell_eval leftover PERF

**Issues:** #405, #436  
**Files:** `src/cli/shell_eval.zig`, `src/cli/shell_eval_synth.zig`  
**#405:** `synthesizeDaemonResponseFromZig` still JSON stringify + parse. Keep hook field contract.  
**#436:** effective cwd `realpath` every eval.  
**factory:auto:** no

---

## Wave 3 — triage then pack (do not code first)

Every Wave 3 issue gets a written verdict before a PR:

| Verdict | Meaning | Next action |
|---|---|---|
| ALREADY_FIXED | Behavior exists on pin | Close as completed; cite file:line |
| OVERSTATED | Ticket asks more than the product rule allows | Close as not_planned; cite standing rule |
| REAL in-scope | Remaining work is local and named | Stay in this pack; **one root-cause PR** |
| REAL deferred | Remaining work is real but crosses god-module / new subsystem | Leave open; do not start today |
| UNCLEAR | Cannot confirm on pin | Leave `needs-triage`; do not guess a fix |

**Minimum steps per REAL in-scope ID:** (1) name the function, (2) cite current file:line, (3) write one failing test, (4) change only that path.

**NEVER one PR** for HOST, SEC-FENCE, MCP, MEM-REST, PERF-REST, ZIG-ARCH, DOCS-QA, ROADMAP, or CMD-UX. Inventory membership is a bucket, not a license to merge ten files.

### Pack HOST — host plugins / matrix (not #311)

**Issues:** #261, #262, #263, #306, #307, #308, #309, #310  
**Files:** host plugin modules / install. #258/#259 already Wave 1.  
**#311 is Wave 0 and does not belong here.**  
**factory:auto:** no  
**Gate:** G4 if uninstall paths are touched.

### Pack SEC-FENCE — sandbox / OS / network leftovers

**Issues:** #244, #245, #247, #248, #300, #301, #407  
**#407 is a `[PERF]` ticket** (`compileProfile`); keep it in this file bucket but land it as its own PR (`cursor/sandbox-perf-407-a58c`) after triage. Do not mix with landmine/feature work.  
**Files:** per ticket — `src/policy/network_eval.zig` (not `src/cli/network_eval.zig`), `src/sandbox/apply.zig`, seatbelt / `platform.zig` / `tool_pack.zig` as named.  
**factory:auto:** no

### Pack MCP — CLI mcp command + proxy/tools PERF

**Issues:** #249, #293, #408, #409  
**Two roots — two PRs after triage:**  
- #249 / #293: `src/cli/mcp.zig` (presets / mutation message). There is no `src/cli/mcp/` **directory**; the CLI entry is the file `src/cli/mcp.zig`.  
- #408 / #409: `src/mcp/proxy.zig`, `src/mcp/tools.zig` (`[PERF]`).  
**factory:auto:** no

### Pack MEM-REST — leftover MEM after MEM-ERRDEFER

**Issues:** #256, #257, #369, #371, #373, #374, #375, #376, #378, #379, #380, #381, #383, #384, #386  
**Triage first.** Caps (#371, #373, #381) are not errdefer. Files staging (#375, #376, #384) is one sub-PR.  
**#371 and #373 are still `needs-triage`.** Promote them in Wave 0. Only #386 is already `ready-for-eng` in this pack.  
**factory:auto:** yes only after verdict REAL in-scope and the fix is errdefer/dupe mechanical.

### Pack PERF-REST — leftover PERF after MATCH / HOOK-PERF / EVAL-PERF

**Issues:** #403, #411, #412, #414, #415, #416, #417, #418, #420, #423, #424, #425, #426, #430, #433, #434, #444, #445, #448  
**Triage first.** If a closed hook parent already landed the work, close as ALREADY_FIXED.  
**#411 / #448:** `src/cli/doctor.zig` — after G1 and DOCTOR-PR3.  
**#417 / #425:** allowlist match vs strip — distinct; do not merge blindly.  
**#444:** dashboard UI (`ryk-dashboard-ui`), not Zig CLI.  
**factory:auto:** honor existing (#411, #412, #430, #445, #448). No new yes on matcher/allowlist semantics.

### Pack ZIG-ARCH — zig incompletes, god-modules, deferred build

**Issues:** #246, #250, #255, #289, #296, #297, #304, #305, #335, #336, #337, #338, #339, #410, #429, #440, #446  
**Most will be REAL deferred** (god-module split, package boundary, monopath test graph).  
**#250 + #289:** legacy `history` stub — one sub-PR if REAL in-scope.  
**factory:auto:** no

### Pack DOCS-QA — docs, QA, orca/aegis leftovers

**Issues:** #251, #252, #253, #254, #264, #265, #266, #267, #268, #269, #270, #272, #273, #274, #295, #303  
**Not docs-only.** #251–#254 / #268 / #269 are stale orca/aegis strings and ship names in code/bin. Split: markdown (#264–#267, #315 is Wave 2) vs code-string PRs.  
**#265:** remove `generic-agent` from help/init preset lists. Do **not** expand the check enum.  
**#270:** Windows pdb hygiene.  
**factory:auto:** yes if markdown-only

### Pack ROADMAP — unlabeled / product roadmap

**Issues:** #325, #326, #327, #328, #329, #330, #331, #332, #333, #334, #340, #341, #343  
**Triage first.** Default verdict is REAL deferred unless a ticket is a one-file docs/CI change.  
**factory:auto:** no

---

## Kickoff canvas (current)

Do not use PR-0..PR-8 as the live queue. Those handoffs describe work that is largely closed (#209–#214, #217, #219–#221).

Live kickoff, in order:

0. Wave 0 filtered apply (CLOSE-A/B/C/D + MEM promote)
1. P1-STOP (`cursor/p1-stop-a58c`)
2. P1-ATTEST-HOT (`cursor/p1-attest-hot-a58c`) — parallel; integrations only
3. P1-PLUGIN-LIST → P1-HOST-WIRE (G3)
4. MATCH (`cursor/match-16kb-a58c`) — #401 first (G6); parallel with P1-STOP
5. MEM-ERRDEFER (`cursor/mem-errdefer-a58c`) — after Wave 0 promote; parallel with P1-STOP
6. BUILD today-slice (`cursor/build-today-a58c`)
7. After G1: DOCTOR-PR3 rebase [PR #359](https://github.com/christopherkarani/ryk/pull/359) (`factory/issue-218`)
8. Rest of Wave 2 chain

---

## Appendix A — every open issue, one primary pack

Inventory taken from GitHub `state:open` at plan write (176 issues). Re-run Appendix B before a pack starts. When Wave 0 closes land, delete those IDs from the block.

<!-- ISSUE-INVENTORY-START -->
CLOSE-A: 197 203 204
CLOSE-B: 280 287 294 298 299 302 311
CLOSE-C: 324
CLOSE-D: 224 225 226 242
P1-STOP: 345
P1-PLUGIN-LIST: 228 229 271
P1-HOST-WIRE: 258 259
P1-ATTEST-HOT: 442
MATCH: 400 401 421
MEM-ERRDEFER: 362 364 365 366 367 368
BUILD: 342 441 447
DOCTOR-PR3: 205 218 236 237
DOCTOR-UX: 243 278 288
BANNER: 215 234
HOSTHELP: 206 233
HELP: 227 230 231 232 279 282 285 290
PACKS: 208 235
COPY: 207 216 238
EXIT: 277 281
CMD-UX: 239 240 241 275 276 283 284 286 291 292
DOCS-FAST: 315 317
HOOK-PERF: 399 406 438
EVAL-PERF: 405 436
HOST: 261 262 263 306 307 308 309 310
SEC-FENCE: 244 245 247 248 300 301 407
MCP: 249 293 408 409
MEM-REST: 256 257 369 371 373 374 375 376 378 379 380 381 383 384 386
PERF-REST: 403 411 412 414 415 416 417 418 420 423 424 425 426 430 433 434 444 445 448
ZIG-ARCH: 246 250 255 289 296 297 304 305 335 336 337 338 339 410 429 440 446
DOCS-QA: 251 252 253 254 264 265 266 267 268 269 270 272 273 274 295 303
ROADMAP: 325 326 327 328 329 330 331 332 333 334 340 341 343
<!-- ISSUE-INVENTORY-END -->

---

## Appendix B — coverage check (run before every pack)

```bash
python3 - <<'PY'
import json, subprocess, re, pathlib
text = pathlib.Path("docs/agent-handoffs/grouped-issue-campaign.md").read_text()
start = text.index("<!-- ISSUE-INVENTORY-START -->")
end = text.index("<!-- ISSUE-INVENTORY-END -->")
block = text[start:end]
assigned = [int(x) for x in re.findall(r"\b(\d{3,4})\b", block)]
from collections import Counter
c = Counter(assigned)
dupes = sorted(n for n,k in c.items() if k>1)
raw = subprocess.check_output(
    ["gh","issue","list","--state","open","--limit","500","--json","number"],
    text=True,
)
live = sorted(x["number"] for x in json.loads(raw))
assigned_set = set(assigned)
missing = sorted(set(live) - assigned_set)
extra = sorted(assigned_set - set(live))
print(f"assigned={len(assigned)} unique={len(assigned_set)} live={len(live)}")
print(f"dupes={dupes}")
print(f"missing={missing}")
print(f"extra={extra}")
if dupes or missing or extra or len(assigned)!=len(assigned_set):
    raise SystemExit(1)
print("OK")
PY
```

Expected on the inventory this plan was written against: `assigned=176 unique=176 live=176`, empty dupes/missing/extra.

If `live` has changed, update the inventory before starting a pack. Do not "mostly" match.

---

## Appendix C — Wave 3 decision comment template

```
**Triage: <VERDICT>.**
Pin: main @ <sha>.
Static confirm: <file:line + what the code does>.
Next: <close as completed | close as not_planned | pack <NAME> | deferred>.
```

---

## Appendix D — branch names, prompts, default gate

Cloud **new** branches: `cursor/<descriptive-name>-a58c`.

Existing in-review work keeps its current branch (do not rename PR #359).

| Pack | Branch | First prompt | Default gate |
|---|---|---|---|
| P1-STOP | `cursor/p1-stop-a58c` | Failing stop-dir test in `disable.zig`; then `deleteTree` on `IsDir`. | `zig build test-fast` then the host-plugin test |
| P1-PLUGIN-LIST | `cursor/p1-plugin-list-a58c` | Contract test for grok/pi rows first. | `zig build test-fast` |
| P1-HOST-WIRE | `cursor/p1-host-wire-a58c` | After plugin-list is green. | `zig build test` |
| P1-ATTEST-HOT | `cursor/p1-attest-hot-a58c` | Cache attest in `integrations/*-plugin`; fail closed if missing. | plugin/integration tests |
| MATCH | `cursor/match-16kb-a58c` | #401 glob tests first in `matchers.zig`; then #400 / #421. | `zig build test-fast` |
| MEM-ERRDEFER | `cursor/mem-errdefer-a58c` | Allocator-fail tests on the listed dupes. | `zig build test-fast` |
| BUILD | `cursor/build-today-a58c` | Only #342, #441, #447. | `zig build test-fast` |
| DOCTOR-PR3 | `factory/issue-218` (PR #359) | Do not fork. Rebase/finish PR #359. | `zig build test-fast` |
| DOCTOR-UX | `cursor/doctor-ux-a58c` | After PR #359. #243 includes `run.zig`. | `zig build test-fast` |
| BANNER | `cursor/banner-a58c` | #215 + #234 only. | `zig build test-fast` |
| HOSTHELP | `cursor/hosthelp-a58c` | #206 + #233 help strings. | `zig build test-fast` |
| HELP | `cursor/help-a58c` | Strings only; `tools.zig` for #282/#290. | `zig build test-fast` |
| PACKS | `cursor/packs-dump-a58c` | Default dump in `src/cli/packs.zig`. | `zig build test-fast` |
| COPY | `cursor/copy-a58c` | #207 + #216 + #238. | `zig build test-fast` |
| EXIT | `cursor/exit-codes-a58c` | Do not touch #287 behavior. | `zig build test-fast` |
| CMD-UX | `cursor/cmd-ux-<cmd>-a58c` | One command per branch. | `zig build test-fast` |
| DOCS-FAST | `cursor/docs-fast-a58c` | #315 + #317. | docs diff + link check |
| HOOK-PERF | `cursor/hook-perf-a58c` | After MEM-ERRDEFER; one issue per commit. | `zig build test-fast` |
| EVAL-PERF | `cursor/eval-perf-a58c` | #405 synth + #436 cwd. | `zig build test-fast` |

Wave 3 packs use `cursor/<pack-slug>-<id>-a58c` after a REAL in-scope verdict (one root cause per branch).

---

## Appendix E — review log

**Pass 1 (hostile, two reviewers + pin checks).** Blockers: MEM-ERRDEFER vs DOCTOR/HOOK file collision; incomplete Wave 2 launch matrix. Majors: Wave numbering, #208/#235 dump ownership, #219 closed, #271 dual-own, standing rule #203–#212, #440 vs #441 factory:auto, wrong paths (`stop.zig`, `network_eval.zig`, `src/cli/mcp/`), HOOK-A over-scope on `shell_eval`, #311 vs HOST, missing Appendix D, BUILD file over-scope, MATCH 32KB, stub inventory script, stale PR-0..PR-8 canvas.

**Pass 1 rewrite was then invalidated** by a live-board refresh: Appendix A listed closed IDs and missed #315, #317, #442, #444, #445, #446, #448. Coverage script used `rfind("## Appendix A")` and matched its own source.

**Pass 2 (hostile, two reviewers + pin checks).** Blockers: MCP omitted `src/cli/mcp.zig`; #442 wrongly gated on `plugin.zig`; #400 `factory:auto` claimed but not on GitHub; DOCTOR pointed at a phantom branch instead of PR #359 / `factory/issue-218`. Majors: P1-EVAL-EXIT already nonzero on pin; MEM promote missed #366–#368; #371/#373 not `ready-for-eng`; DOCTOR mega-scope vs PR-3; Wave 3 mega-PR risk; HELP omitted `tools.zig`; #401 semantics mixed with #400.

**Pass 2 fixes (this file):** inventory live-176; CLOSE-D for #224/#225/#226/#242; #442 → integrations; MCP two roots; factory:auto honor list without #400; DOCTOR-PR3 vs DOCTOR-UX; PR #359; Wave 0 promote includes #366–#368/#371/#373; NEVER-one-PR on mega-packs; G6 #401 first; tracked path `docs/agent-handoffs/grouped-issue-campaign.md`.

**Pass 3 (hostile).** No blockers. Majors: Wave 0 promote for #366–#368 had no machine-readable spec; #371/#373 promote did not forbid `factory:auto` vs `wave-2-apply-plan.json`. Residual: Appendix E stub; pin vs HEAD; PR #359 may still need `tui/render.zig` for #205.

**Pass 3 fixes:** `wave-0-campaign-apply.json` + `apply-wave-0-campaign.sh` with explicit labels (errdefer +auto; caps no auto). Plan Wave 0 now points at that JSON only.

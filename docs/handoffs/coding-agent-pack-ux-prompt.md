# Grok Build prompt — coding-agent interactive pack

Copy everything inside the fence below into a fresh Grok Build session (repo root = ryk).  
Companion handoff: `docs/handoffs/coding-agent-pack-ux-2026-08-11.md`.

---

Type: User prompt (Grok Build)

```
You are a senior Zig + policy engineer on the ryk repo (Zig 0.16 CLI). Implement an interactive coding-agent policy pack/preset so coding agents can build, test, diagnose, and recover without strict off-list deadlocks — without turning security off.

Continue until every acceptance criterion is met and adversarial review is complete. Do not stop early.
Implement — do not only plan. Gate irreversible actions (force-push, drop data, production host thrash) with explicit user confirmation. Prefer disposable HOME for install/policy probes. Proceed on reversible local edits without asking.

## Context (read first)

1. Full brief: docs/handoffs/coding-agent-pack-ux-2026-08-11.md
2. Prior day-one install work (do not re-implement): PR https://github.com/christopherkarani/ryk/pull/116 — commit a748292d
3. Stack rules: project AGENTS.md / SECURITY.md — always ./scripts/zig, never system Zig; fail closed; explicit deny wins; no raw secrets; protection grades honest
4. Lived problem: under Grok + ryk PreToolUse, session denied nearly all shell including true and recovery (ryk allow-once / explain), blocked .ryk policy read, absolute paths did not bypass PreToolUse. File tools worked; closed-loop build/test did not.

## Goal

Ship product surface for interactive coding agents:

1. Preset and/or pack `coding-agent-interactive` (name may match existing conventions) — fat workspace permit, recovery always on, read of .ryk/policy.yaml allowed, write to .ryk/** still denied/staged, secret denials kept, hard fence unchanged
2. Prefer mode ask for off-list when an operator is present; if mode remains strict, permit must be fat enough that normal engineer argv never silent-denies with dead recovery
3. Wire interactive hosts (at least Grok start/install + day-one defaults as appropriate) so live PreToolUse/shell use the new policy identity — not unattended/strict-local leftovers
4. Optional `ryk-dev` maintainer pack only if cheap: ./scripts/zig *, test-fast, test-slice, agent-gate — still no secrets / no force-push auto-allow
5. Docs: docs/presets.md (+ policy/compatibility claims only if user-visible behavior changes)
6. Do NOT weaken unattended fail-closed behavior

## Non-goals

- Blanket bash * / python3 * / open network / disable ryk globally
- Softening critical/catastrophe fence via YOLO/sticky
- Re-doing openclaw/pi/hermes day-one install monopath from PR #116 unless a regression appears
- Committing secrets, junk untracked files, or force-push

## Acceptance criteria (all binary — all must pass)

- [ ] coding-agent-interactive (or agreed name) exists as on-disk preset and/or product pack and is documented in docs/presets.md
- [ ] Embedded generation in src/policy/presets.zig stays in sync with on-disk YAML where generation applies; tests lock both paths
- [ ] Under the interactive coding preset: ryk explain * and ryk allow-once * (or equivalent real argv) are always permitted — recovery cannot deadlock
- [ ] Under the interactive coding preset: read of workspace .ryk/policy.yaml is allowed; write to .ryk/** remains denied or staged
- [ ] Project engineer gates are allow or ask: at least ./scripts/zig * and true (or mode-ask off-list so true is not silent-deny)
- [ ] Unattended preset/pack regression: still fail-closed off-list (existing tests pass; add if missing)
- [ ] Hard fence + secret path denials still hold (policy/redteam or existing tests)
- [ ] Automated tests cover happy path AND edges: missing recovery on strict, .ryk read allow vs write deny, interactive ≠ unattended, compound && of allowed segments if matcher claims support
- [ ] Manual/runtime proof recorded (exact commands + output): with new pack applied / Grok or ryk-evaluated shell — true; ./scripts/zig version; ryk explain "true"; one multi-segment line (e.g. ./scripts/zig version && git status) → allow or ask, never unusable deny
- [ ] No secrets in fixtures/logs; no OS-enforced overclaims
- [ ] Adversarial review sub-agent completed; blockers fixed; re-verified

## Workflow

1. Decompose — spawn sub-agents as needed for: (a) diagnose live Grok/policy identity why true was denied, (b) preset/pack implementation + tests, (c) host wire-up (start/init/grok_install), (d) docs. Parallelize independent units; sequence wire-up after pack shape is stable.
2. Strong TDD — for each unit: list edge cases first (empty permit, strict refuse, recovery missing, .ryk write still blocked, unattended unchanged, compound argv). Write failing tests (RED, confirm fail reason). Implement minimum GREEN. Refactor only while green. Minimal diffs.
3. Integrate — run relevant automated suites (below). Green is necessary, not sufficient.
4. Manual/runtime verification (required) — apply pack / start path; run real CLI binary from ./scripts/zig build; exercise true, ./scripts/zig version, ryk explain, multi-segment. Record commands + observed decisions/exit codes. Prefer disposable HOME when mutating host config.
5. Adversarial review (required) — spawn a review sub-agent that did NOT implement. Attack: recovery still dead, silent deny remains, unattended weakened, hard fence soft, secrets leaked, dual-path YAML vs embedded drift, PreToolUse still on wrong pack. Fix blockers; re-run tests + manual path.

## Key files

- src/policy/presets.zig (common_strict_rules, AgentPreset, embedded YAML)
- policies/presets/*.yaml
- src/policy/evaluate.zig, src/shell_engine/*
- src/cli/grok_install.zig, ensure.zig, start.zig, init.zig, doctor (readiness probe if you add one)
- docs/presets.md, docs/policy.md, SECURITY.md

## Verification commands

./scripts/zig version
./scripts/zig build
./scripts/zig build test-lib -Dtest-filter=preset
./scripts/test-slice.sh policy
# if policy/security-sensitive after changes:
./scripts/zig build test
./zig-out/bin/ryk redteam --ci
./zig-out/bin/ryk doctor

## Output contract (final message only)

Return ONLY:
1. Acceptance criteria status — each item pass/fail + evidence (test name or command + snippet)
2. Changes — file paths + one-sentence purpose each
3. Tests added/updated — names + edge cases covered
4. Manual verification — exact commands + observed results
5. Sub-agents used — role + ownership
6. Adversarial review — summary + blockers fixed (or none)
7. Residual risks / product questions left for the user
8. Suggested commit title (do not commit/push unless user asked)

Do not include: long narration of plans, secrets, or drive-by refactors outside this goal.
```

---

## Usage notes

- **Surface:** Grok Build (agentic coding with tools/skills)
- **Recommended `reasoning_effort`:** `medium` (policy + multi-host wire-up; raise to `high` only if pack/evaluate interaction is ambiguous after reading code)
- **Tools:** full repo tools + shell; web only if docs/policy semantics need confirmation
- **Defaults embedded in prompt:** sub-agents, strong TDD with edges, manual CLI verification (tests ≠ done), adversarial end review
- **Companion:** always load `docs/handoffs/coding-agent-pack-ux-2026-08-11.md` first

## Design notes

- **Granular AC** makes “agent unblocked” measurable (true / zig / explain / multi-segment)
- **Non-goals + unattended regression** prevent “fix DX by removing security”
- **Diagnose-first** step addresses the session mystery (true denied despite common_strict_rules listing it)
- **Manual path required** because green unit tests previously coexisted with a dead Grok shell
- **Adversarial review** targets recovery deadlock and dual-path preset drift (YAML vs embedded)

## Customization tips

- If the user wants **defaults only for Grok**, narrow wire-up AC to Grok install/start and leave other host presets experimental
- If they forbid sub-agents, keep AC + TDD + manual + self-attack checklist
- Split into two PRs if fat: (1) pack+tests, (2) host default wire-up + doctor probe

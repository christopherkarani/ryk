# Handoff: coding-agent interactive pack + agent shell UX

**Date:** 2026-08-11  
**Repo:** `/Users/chriskarani/CodingProjects/ryk`  
**Branch (prior work landed):** `bug-tunes` → PR https://github.com/christopherkarani/ryk/pull/116  
**Prior commit (day-one install):** `a748292d` — `fix(cli): day-one host install reliability and actionable fix hints`  
**Investigation surface:** Grok Build + ryk PreToolUse (`RYKAN-V-GUARD`) under strict permit refuse  
**Remote:** do not force-push; do not commit secrets; prefer disposable HOME for policy/install probes  

**Related prior handoffs:**

- `docs/handoffs/ryk-start-host-install-failures-2026-08-10.md` — day-one openclaw/pi/hermes install (mostly done in PR #116)
- `docs/handoffs/ryk-agents-unattended-handoff-2026-08-09.md` — unattended path (**not** this work; keep fail-closed)

**Implementor prompt (copy-paste):** `docs/handoffs/coding-agent-pack-ux-prompt.md`

---

## Goal for the next agent

Ship product policy + wire-up so **interactive coding agents** (Grok Build, Claude, Codex, etc.) can run a normal engineer loop — build, test, diagnose, recover — without being deadlocked by strict off-list refuse, while **preserving**:

- fail-closed on invalid policy / eval errors  
- explicit deny wins (critical/catastrophe hard fence)  
- no blanket `bash *` / `python3 *` / bare `git *` unless deliberately chosen and documented  
- no secrets in audit, fixtures, docs  
- honest protection grades (`hook` / `wrapper` / …)  

**Success is UX + policy, not “turn ryk off.”**

---

## Why this exists (lived session evidence)

While implementing day-one host install fixes under Grok + ryk:

| Friction | What happened |
| --- | --- |
| Strict off-list refuse | Nearly all shell tools denied: `strict: not on allowlist` — including compounds and even `true` in the live session |
| Build/test loop dead | `./scripts/zig …`, project gates could not run from agent shell |
| Recovery deadlock | Recourse text said `ryk allow-once` / `ryk explain`, but those commands were themselves denied |
| Policy self-read blocked | `files.read.deny` on `./.ryk/**` prevented diagnosing the live policy |
| PreToolUse vs PATH | Absolute paths did not bypass Grok PreToolUse — same policy still applied |
| Incomplete stop (fixed in #116) | Legacy `~/.grok/user-settings.json` PreToolUse survived managed-hook-only uninstall |

**Workaround used:** Ghostty + open-computer-use (slow; not a product answer).

**File tools (read/write/grep) were fine** — only closed-loop shell verification died.

---

## Suggested product shape

### 1. Preset / pack: `coding-agent-interactive` (primary)

Role: **operator present**, interactive coding session.

| Axis | Recommendation |
| --- | --- |
| Mode | Prefer **`ask`** for off-list (not strict refuse). If mode stays `strict`, permit list must be **fat enough** that normal engineer argv never silent-denies. |
| Commands | Fat workspace permit: inspect, git local R/W, project `./scripts/*` gates, language toolchains used by this repo’s CI, **always-on recovery** |
| Files read | Allow **read** of `.ryk/policy.yaml` and session receipts; keep secret path denials |
| Files write | Keep deny/stage on `.git/**`, `.ryk/**` control surfaces |
| Network | Conservative default (deny or ask); no silent open internet |
| Hard fence | Unchanged — packs cannot unlock critical/catastrophe |

### 2. Optional pack: `ryk-dev` / maintainer

For agents developing **ryk itself**: `./scripts/zig *`, `./scripts/test-fast.sh`, `./scripts/test-slice.sh *`, `./scripts/agent-gate.sh *`, disposable-HOME install/doctor probes. Still no secrets, no force-push, no production destructive ops without ask.

### 3. Do **not** merge with `unattended`

`unattended` stays fail-closed, no ask. Wrong default for Grok/Claude interactive coding.

### 4. Host wire-up

- Day-one / `ryk start` / Grok install must attach **interactive coding pack** (or equivalent permit), not leftover strict-local / empty permit / unattended.
- Grok PreToolUse and shell shims must evaluate the **same** policy identity.
- After pack apply: doctor or session probe: agent can run `true`, `./scripts/zig version` (or project equivalent), and `ryk explain true` without deny.

### 5. Recovery + deny UX

- Recovery commands **unconditionally on permit** under every interactive coding preset (match real argv shapes agents emit).
- Deny message: rule/preset identity + **one working next step** (not only text that the agent cannot execute).

### 6. Command-shape realism

Agents emit `a && b && c`, pipes, `2>&1 | head`. Either:

- permit multi-segment when every segment is allowed, **and** test real agent argv strings, or  
- document + implement segment-aware matching improvements with TDD.

---

## Code map (start here)

| Area | Paths |
| --- | --- |
| Embedded presets / permit | `src/policy/presets.zig` (`common_strict_rules`, `AgentPreset`, pack YAML strings) |
| On-disk presets | `policies/presets/*.yaml` (`generic-agent`, `trusted-local`, `unattended`, host-named) |
| Pack apply surface | `ryk policy packs` / apply-pack — search `solo-dev`, `apply-pack` under `src/cli/` + `src/policy/` |
| Shell evaluate / strict refuse | `src/shell_engine/`, `src/policy/evaluate.zig` |
| Grok hooks | `src/cli/grok_install.zig`, disable path already strips legacy user-settings (PR #116) |
| Day-one monopath | `src/cli/ensure.zig` `installOneHost`, `src/cli/start.zig` |
| Docs claims | `docs/presets.md`, `docs/policy.md`, `docs/compatibility.md`, `SECURITY.md` before tightening claims |
| Tests | preset sync tests in `presets.zig`; policy/evaluate tests; shell_engine permit matching |

**Authoritative runtime preset** for quick-install is often **embedded** in `presets.zig`, not only on-disk YAML — keep them in sync or document divergence.

Existing invariants (do not silently reverse without product decision):

```text
# tests assert generic-agent embedded body does NOT include:
python3 *
bash *
```

---

## Acceptance criteria (binary)

- [ ] New preset and/or pack exists and is listed in `docs/presets.md` with honest scope (interactive coding ≠ unattended).
- [ ] Embedded generation path (if any) matches on-disk YAML structure; tests lock both.
- [ ] Recovery always permitted: `ryk explain *`, `ryk allow-once *` (or project-equivalent patterns) cannot be off-list under the interactive coding preset.
- [ ] Read of workspace `.ryk/policy.yaml` allowed for coding-agent interactive; write to `.ryk/**` still denied/staged.
- [ ] Project gates used by ryk agents are on permit or ask: at least `./scripts/zig *` (already in common_strict_rules — verify **live** Grok path actually loads it).
- [ ] Manual proof: under Grok (or ryk-wrapped shell) with the new pack, `true`, `./scripts/zig version`, and a multi-segment diagnostic either allow or **ask** — never silent deny with unusable recovery.
- [ ] Unattended preset behavior unchanged (regression tests).
- [ ] Hard fence / secret denials still fail closed (existing redteam or policy tests).
- [ ] No secrets in fixtures/logs; no overstated OS-enforced claims.
- [ ] Adversarial review completed; blockers fixed.

---

## Suggested implementation order

1. **Diagnose live Grok policy identity** — why session denied `true` despite `common_strict_rules` listing it (wrong preset? empty permit? strict refuse path? hook argv wrap?).
2. **TDD:** failing tests for recovery-on-permit, `.ryk` policy read, compound `&&` of allowed tools, and “coding pack does not equal unattended.”
3. **Implement** preset/pack + wire into init/start/Grok install defaults for interactive hosts.
4. **Doctor readiness probe** (optional but high ROI): “agent shell can run true + zig version + ryk explain.”
5. **Docs** + manual CLI proof with evidence in the PR.
6. **Adversarial review** sub-agent (security + DX).

---

## Out of scope (unless product asks)

- Turning off ryk system-wide or removing PreToolUse entirely  
- Blanket allow all shell / all network  
- Softening critical hard fence via YOLO/sticky  
- Nested OpenClaw install timeout UX (track A residual from day-one work)  
- Full Grok host rewrite beyond policy pack binding  

---

## Verification commands

```sh
./scripts/zig version
./scripts/zig build
# policy / preset unit coverage (adjust filter to new tests)
./scripts/zig build test-lib -Dtest-filter=preset
./scripts/zig build test-lib -Dtest-filter=day-one
./scripts/test-slice.sh policy
# when policy/security-sensitive:
./scripts/zig build && ./scripts/zig build test
./zig-out/bin/ryk redteam --ci
./zig-out/bin/ryk doctor
```

Manual (after pack apply / start):

```sh
# Expect allow or ask — not silent deny with dead recovery
true
./scripts/zig version
ryk explain "true"
# Multi-segment shape agents actually emit
./scripts/zig version && pwd && git status
```

---

## Suggested skills

- `zig` / `zig-best-practices` — Zig 0.16, `./scripts/zig` only  
- `tdd` — red → green → refactor; edge cases on permit matching  
- `check-work` / review — before PR claim  
- Project `AGENTS.md` / `SECURITY.md` — fail-closed, grades, no secrets  

---

## What not to redo

- Day-one openclaw/pi/hermes install timeout/classify/hints — **done in PR #116** (`a748292d`). Re-read that PR if host install breaks; do not re-implement monopath without cause.  
- Grok legacy user-settings strip on stop — **done in #116**.  

---

## Open product questions (resolve in PR or ask user)

1. Should **default** `ryk start` / `ryk init` switch from `generic-agent` strict-ish embedded body to `coding-agent-interactive` ask-default?  
2. Host-named presets (`claude-code`, `codex`, …) — inherit new interactive body or stay thin experimental?  
3. Is segment-aware `&&`/pipe matching in-scope for v1 of the pack, or pack-only permit growth first?  

Default if user is silent: **pack + defaults for interactive hosts + recovery + .ryk read**; segment matching only if tests prove current matcher already fails on allowed segments.

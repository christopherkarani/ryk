# Phase 0 — P1 launch blocker

**Parallel with:** PR-1, PR-2, PR-6  
**Blocks:** nothing else for file ownership of `run.zig` / `sandbox_card.zig`

## Goal

One-click `ryk grok` reaches Grok (protected), or fails with **one short error + one next**. No SHIELD UP walls, no `audit=degraded` on the success path, no tip novel.

## Pack

- **PR-0** → [#221](https://github.com/christopherkarani/ryk/issues/221)

## Success criteria

1. Clean dir, grok binary + `~/.grok/auth.json` present, **no** `ryk start`: `ryk grok` enters the agent.
2. If sandbox still blocks host config: one line naming the deny + one real next (only if that next is verified).
3. No box-drawing SHIELD UP card on this path.

## Out of scope

- Global banner kill (#215)
- Installer homework (#220)
- Reopening #145 / #195 / #196

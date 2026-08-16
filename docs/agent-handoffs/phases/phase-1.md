# Phase 1 — UX chrome contracts

**Start after or parallel with Phase 0** (disjoint files).  
**Internal order:** PR-1 ∥ PR-2 ∥ PR-3 (PR-3 is one agent for #205+#218).

## Packs

| Pack | Issues | Parallel? |
|------|--------|-----------|
| PR-1 | #215 (close #213) | Yes — with PR-0/2/6 |
| PR-2 | #217 | Yes |
| PR-3 | #205 + #218 | Yes vs banner/TUI; **internal serialize** on doctor |

## Contracts to land

1. **Banner:** quiet success. No shield banner on success, `--quiet`, `--no-rich`, pipe, or errors. Brand may stay on `ryk --version` and maybe first-run `ryk help` only.
2. **TUI fallback:** every `--tui` / live TUI: no TTY / `--plain` / `--json` / `NO_COLOR` / `--no-rich` → linear output, exit as linear would.
3. **Daemon honesty:** start and doctor share one truthful daemon/capability line; never “reinstall companion” when in-process Zig is enough.

## Do not

- Fold packs dump (#208) into banner PR
- Auto-open doctor TUI
- Reopen #145

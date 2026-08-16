# PR-8 handoff — polish #210 + #216 + #208′

**Priority:** P2  
**Parallel:** yes among micro-fixes; keep as one PR or three tiny PRs — prefer **one** polish PR if small

## Problems (verified)

**#210:** `suggestCommand` threshold edit distance ≤ 2 → `foo` uniquely matches `hook`. Tighten so only truly close typos suggest; else `unknown command` + `ryk help`.

**#216:** Default `ryk test` / `ryk explain` emit zero CSI. Feel: color **DENY Decision line only** on colour TTY; ALLOW plain; ask = quiet warning optional. Respect `NO_COLOR` / `--no-rich` / pipe. Surfaces: test + explain first. No new TUI.

**#208′:** After #215 owns error banners — packs default still dumps a detailed page (25 rows), not “count + one next”. Registry has 86 packs; pagination exists but feel unmet. Do not touch error banners here.

## Acceptance

1. `ryk foo` → no hook suggestion.
2. DENY Decision colored only under colour TTY gates; ALLOW plain.
3. `ryk packs` default human: count + one next (not row dump).
4. Do not invent a new TUI; do not reopen #144/#146.

## Primary files

`src/cli/suggestions.zig`, `src/cli/shell_test.zig`, `src/cli/explain_render.zig`, `src/tui/theme.zig`, `src/cli/packs.zig`

## Branch

`cursor/fix-210-216-208-polish-8968`

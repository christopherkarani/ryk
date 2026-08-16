# Phase 3 — polish

**After Phase 0–1.** Can parallelize packs freely if file ownership respected.

## Packs

| Pack | Issues |
|------|--------|
| PR-7 | #209 + #220 |
| PR-8 | #210 + #216 + #208′ (packs dump only) |

## Contracts

1. `ryk update` replaces a real ryk binary without false “non-ryk” refuse; `--force` / env named honestly if still needed.
2. Installer: curl-and-done — no leftover `eval` + `doctor --fix --from-install` homework on success path.
3. Suggestions: only when edit distance is actually close (`foo` must not suggest `hook`).
4. Color: DENY Decision line only on colour TTY; ALLOW plain; respect `NO_COLOR` / `--no-rich` / pipe.
5. Packs default: count + one next (not a detailed page dump). Error banner already owned by #215.

## Close without code

See [CLOSE.md](CLOSE.md).

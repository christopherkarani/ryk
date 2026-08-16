# CLOSE without a fix PR

Adversarial triage 2026-08-16 on `0.2.19` / current `main`.

## Close now

| Issue | Reason | Evidence |
|------:|--------|----------|
| **#213** | Duplicate of #215 | Banner printed before command dispatch via `shouldShowBanner` / `writeInvocationPresentation` in `src/cli/mod.zig`; `--quiet` never consulted. Fixing #215 retires the claim. Init “one next” remainder → #207/#219. |
| **#203** | Already fixed | Default `ryk explain` uses `writePretty` (Decision/Why/Rule/Safer/Next). Box tree only behind `--verbose` (`src/cli/shell_explain.zig`, `src/cli/explain_render.zig`). |
| **#204** | Already fixed | `src/telemetry.zig` handles `--help`/`-h`, writes help, returns success. Unit test in `src/cli/mod.zig`. |
| **#197** | Docs already honest; product forbids enum expansion | Zero in-repo `policy check --preset generic-agent`. Docs use path form. Closed unmerged PR #201 was the **wrong** fix. |

## Partial rewrite (do not close whole issue)

| Issue | Action |
|------:|--------|
| **#208** | After #215 lands: rewrite body to **packs default dump only** (page of rows → count + one next). Error-banner half is duplicate of #215. |

## Close agent

Use prompt [../prompts/CLOSE.md](../prompts/CLOSE.md): comment with evidence, close with `not_planned` or `completed` as appropriate, do not ship code.

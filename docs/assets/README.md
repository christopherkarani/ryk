# docs/assets

Marketing and README media for ryk.

| File | Notes |
| --- | --- |
| `ryk-deny-demo.gif` | Real 12s silent loop (720px). Recorded from a built `ryk` 0.2.18 binary: `ryk opencode` session start, `ryk hook opencode tool.execute.before` on `rm -rf /` (`core.filesystem:rm-rf-root-home`), the guardian deny block, then `ryk replay --only denied`. No mocked ryk UI. No real secrets. |

The banner SVG remains at `docs/images/ryk-banner.svg` for other surfaces. The README hero uses this GIF as the first visual.

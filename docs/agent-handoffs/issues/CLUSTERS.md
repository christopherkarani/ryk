# Related-issue clusters

Factory and coding agents: issues that share a `cluster:*` GitHub label are one workstream. Read the siblings before opening a PR.

Canonical data: [`.github/issue-clusters.json`](../../../.github/issue-clusters.json)  
Stamp labels (needs `issues:write`): `./scripts/apply-issue-clusters.sh`

| Label | Issues | Coordinate | Do not collide with |
| --- | --- | --- | --- |
| `cluster:mcp-memory` | #451 #347 #363 #385 | Proxy sequential (#451 in flight). tools.zig pair can run in parallel. | — |
| `cluster:redaction` | #366 #364 #365 | One PR | — |
| `cluster:files-index` | #376 #375 #384 | One PR | — |
| `cluster:doctor-start` | #205 #218 | One PR (PR-3). #218 in review. | `cluster:cli-chrome` |
| `cluster:cli-chrome` | #215 #207 #208 #216 #239 | Banner (#215) first | `cluster:doctor-start` |
| `cluster:stop-plugins` | #345 #206 | Bug #345 then copy #206 | `cluster:cli-chrome` |
| `cluster:errdefer` | #367 #374 #378 #379 #383 | Parallel, one locus per PR | `cluster:doctor-start` (#367 is doctor.zig) |
| `cluster:gateway-audit` | #371 | Solo | — |
| `cluster:release-signing` | #326 | Solo. Not factory:auto. | — |
| `cluster:mcp-docs` | #317 | Solo docs | `cluster:mcp-memory` |

## How to use the tag

1. If you pick an issue, search open issues for the same `cluster:*` label.
2. Treat members as related even when titles differ.
3. One PR per cluster unless `coordinate` says parallel-loci or sequential-proxy.
4. Do not start a second PR on a cluster that already has `in-eng` / `in-review`.

## Existing UX packs (same groups, older names)

These handoffs already pair related tickets. They keep their `cluster:*` tag as well:

- PR-1 `#215` → `cluster:cli-chrome`
- PR-3 `#205`+`#218` → `cluster:doctor-start`
- PR-4 `#207` → `cluster:cli-chrome`
- PR-5 `#206` → `cluster:stop-plugins`
- PR-8 `#216`+`#208` → `cluster:cli-chrome`

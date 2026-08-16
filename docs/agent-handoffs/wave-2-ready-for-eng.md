# Wave 2 — adversarial triage → ready-for-eng

**Repo:** `christopherkarani/ryk` · **Pin:** `main` @ `430c13e6`  
**Triage date:** 2026-08-16  
**Method:** verify against current source (not issue text). Line citations in tickets were filed vs 0.2.18 and are often stale.

**GitHub write:** this agent’s token can read issues but cannot comment or change labels (`403 Resource not accessible by personal access token`). Apply the transitions below with an `issues:write` token. Machine plan: [`wave-2-apply-plan.json`](wave-2-apply-plan.json).

## Selection

Started from open `needs-triage`. Preferred P0/P1, then filled with independently verifiable P2 PERF/MEM tickets after seven hunter tickets failed review.

## Promote — `needs-triage` → `triage:confirmed` + `ready-for-eng`

| Issue | Verdict | Pri | factory:auto | Remaining scope |
|------:|---------|:---:|:------------:|-----------------|
| [398](https://github.com/christopherkarani/ryk/issues/398) | PARTIALLY_REAL | P0 | no | Long-lived evaluator / reorder cheap rejects. Superset of #391/#392/#397/#399. Policy cache + lazy compile already landed; hook is still one-shot. |
| [397](https://github.com/christopherkarani/ryk/issues/397) | PARTIALLY_REAL | P0 | yes | Default-pack-only embed so hook cold start skips full-oracle inflate/scan. 1624-pattern upfront compile already lazy. Counts 86/830/794 still correct. |
| [394](https://github.com/christopherkarani/ryk/issues/394) | PARTIALLY_REAL | P0 | no | Product durability decision: batch/async fsync vs P0-5 hash-chain. Per-event `sync` is real; full-chain resync only on size divergence. |
| [396](https://github.com/christopherkarani/ryk/issues/396) | REAL | P1 | yes | Share pack-match state across candidates; do not skip hidden segments. |
| [392](https://github.com/christopherkarani/ryk/issues/392) | REAL | P1 | yes | mtime cache for `loadPackIdsForWorkspace`. Keep fail-closed on bad config. |
| [391](https://github.com/christopherkarani/ryk/issues/391) | REAL | P1 | yes | mtime cache for `loadMerged` allowlists. Distinct from #425 / #417. |
| [404](https://github.com/christopherkarani/ryk/issues/404) | PARTIALLY_REAL | P1 | no | Double lock already fixed (P001). Remaining: full JSONL rewrite + `sync` on consume. |
| [402](https://github.com/christopherkarani/ryk/issues/402) | REAL | P1 | yes | Parse/dupe cost in `loadRecentFromPath`. Distinct from #437 enrich O(S×F). |
| [395](https://github.com/christopherkarani/ryk/issues/395) | REAL | P1 | no | Hook-path exclusive lock + fsync on workspace and global feed. |
| [417](https://github.com/christopherkarani/ryk/issues/417) | REAL | P2 | yes | Hash maps for command/rule allowlist match. |
| [401](https://github.com/christopherkarani/ryk/issues/401) | PARTIALLY_REAL | P2 | no | Multi-star glob is O(n^k), not generic exponential. Typical trailing `*` is O(n+m). |
| [400](https://github.com/christopherkarani/ryk/issues/400) | PARTIALLY_REAL | P2 | yes | 32KB stack reserved every `matchesCommand`; memcpy only on normalize. Fast-path without large locals. |
| [362](https://github.com/christopherkarani/ryk/issues/362) | REAL | P2 | yes | `getSelectedLabels` leak on append OOM. Test-only caller; ownership still broken. |
| [373](https://github.com/christopherkarani/ryk/issues/373) | REAL | P2 | yes | `SessionApprovals` uncapped. M001 dual-dupe already errdefer-fixed. |
| [371](https://github.com/christopherkarani/ryk/issues/371) | REAL | P2 | yes | `provider_gateway` `audit_events` uncapped list. |
| [364](https://github.com/christopherkarani/ryk/issues/364) | REAL | P2 | yes | Prompt-secret redaction dual-dupe, no errdefer. Pair with #365. |
| [365](https://github.com/christopherkarani/ryk/issues/365) | REAL | P2 | yes | `recordDaemonMetadataRedaction` dual-dupe, no errdefer. |
| [405](https://github.com/christopherkarani/ryk/issues/405) | REAL | P2 | no | `synthesizeDaemonResponseFromZig` still JSON stringify + parse. Keep hook field contract. |
| [406](https://github.com/christopherkarani/ryk/issues/406) | REAL | P2 | no | Hook response still dupes limitation strings + stringify every call. |
| [399](https://github.com/christopherkarani/ryk/issues/399) | REAL | P2 | no | `resolveWorkspaceRoot` ancestor walk. Pass bound workspace; do not weaken M-9. |

## Do not send to engineering

| Issue | Verdict | Action | Why |
|------:|---------|--------|-----|
| [280](https://github.com/christopherkarani/ryk/issues/280) | NOT_REAL | close completed | `init` already exits 1 on `PathAlreadyExists`; test asserts it. |
| [287](https://github.com/christopherkarani/ryk/issues/287) | OVERSTATED | close not_planned | `--json` exit 0 is by design. CI gate is `doctor --check`. |
| [294](https://github.com/christopherkarani/ryk/issues/294) | NOT_REAL | close not_planned | macOS uses production client; FM never sees `.block`. Stub cannot soften deny. |
| [298](https://github.com/christopherkarani/ryk/issues/298) | ALREADY_FIXED | close completed | Feed uses `redact_bridge` via `core_api`; dashboard redaction tests exist. |
| [299](https://github.com/christopherkarani/ryk/issues/299) | NOT_REAL | close not_planned | Secrets discarded after resolve; plugin/doctor tests assert no raw prefixes. |
| [302](https://github.com/christopherkarani/ryk/issues/302) | ALREADY_FIXED | close completed | Seatbelt/profile/`--os-sandbox on` fail closed. `auto` degrade is a loud WARNING. |
| [311](https://github.com/christopherkarani/ryk/issues/311) | OVERSTATED | close not_planned | Ask/no-resume is the documented host matrix + `doctor --deadlock-check`, not a missing gate. |

## Overlaps (do not double-fix)

- #398 contains #391, #392, #397, #399.
- #402 parse/dupe is adjacent to already-confirmed #437 enrich.
- #417 match scan is distinct from already-confirmed #425 strip rebuild.
- #397 remaining inflate is distinct from already-confirmed #430 spin-wait.
- #364 and #365 are the same dual-dupe pattern in `hook.zig`.

## Standing rules for any follow-up fix

- Do not weaken fail-closed / lock / fsync without an explicit durability tradeoff.
- Do not change ask≠allow or CI ask→deny.
- Do not expand `policy check --preset` to accept `generic-agent`.
- Campaign plan supersedes this table's `factory:auto` on #400 (GitHub has no such label; do not add it). Wave 0 apply is `wave-0-campaign-apply.json`, not this file's promote list.

# fm-steward

Mac-only **on-device Apple Foundation Models steward** for ryk (`SystemLanguageModel`).

**v1 focus: dangerous shell / agent commands** (soft-interrupt nuance after policy + hard fence).  
Email bulk/VIP / pay adapters are **out of v1 product corpus** — architecture stubs only under `residual-knowledge/`.

Classifies **risk-card-v1** JSON into:

| Verdict | Meaning |
|---------|---------|
| `continue` | Proceed under existing policy + hard fence |
| `ask` | Soft interrupt; human-readable `explain` required |
| `ask_sticky_candidate` | Ask and suggest a sticky allow scope |

This package ships:

- Normative schemas under `Schemas/`
- Shell fixture corpus under `Fixtures/`
- Deterministic **rules pre-pass** (safe shapes + hard-danger ask + residual FM)
- **Live `LiveBackend`** using `import FoundationModels` + guided generation (`@Generable`)
- Warm `StewardSession` with timeout race for residual FM work
- **Residual Wax few-shot assist** (text mode): YAML packs → compiled seed → `.wax` → k≤3 neighbors
- Demo CLI: `fm-steward classify --card <path.json> [--live] [--few-shot auto|off|wax]`
- Zig product hooks call this binary (see [Product Zig wiring](#product-zig-wiring))

## Platform

| Platform | Support |
|----------|---------|
| **macOS 26+** | Supported — requires Apple Intelligence / Foundation Models assets |
| **Linux** | **Skipped** — product path does not use FM |

On macOS, product shell paths (`ryk hook`, `ryk evaluate`, `ryk run` / shim) call this steward after the Zig hard fence and policy matrix. Linux / non-macOS skip the call (continue stub; no steward binary required).

## Security honesty

**FM + Wax are residual assist only — not sole security.**

| Layer | Role |
|-------|------|
| Zig hard fence | Catastrophe **deny** |
| Policy / YOLO / sticky | Host product |
| Rules pre-pass | Clear continue / hard-ask |
| Wax few-shots | Gray **examples** for residual FM (never deny/allow) |
| On-device FM | Soft `continue` \| `ask` \| `ask_sticky_candidate` |

Wax never unlocks hard deny. Fail-open: store/search errors → empty few-shots → normal FM/unavailable path.

## Build

```bash
cd macos/fm-steward
swift build
```

## Test

```bash
cd macos/fm-steward
python3 scripts/compile-residual-knowledge.py --check
swift test
bash Fixtures/validate.sh
```

## Residual knowledge packs

Human-authored **ambiguous coding-agent** examples live under `residual-knowledge/`:

```text
residual-knowledge/shell/*.yaml
residual-knowledge/containers/*.yaml
residual-knowledge/email|pay|social/   # stubs only (not implemented)
```

Compile to the checked-in seed artifact:

```bash
python3 scripts/compile-residual-knowledge.py          # write Fixtures/ambig-fewshot/seed.json
python3 scripts/compile-residual-knowledge.py --check  # CI / pre-commit gate
python3 scripts/compile-residual-knowledge.py --self-test
```

**Pipeline:** YAML packs → `seed.json` → text-mode `.wax` (seeded on first use, seed-hash change, or store format version bump) → residual classify retrieves k≤3 under the session timeout budget → `LiveBackend.prompt` injects neighbors → FM decides.

See [`residual-knowledge/README.md`](residual-knowledge/README.md) for authoring rules and multi-domain employee architecture (docs/stubs only).

## CLI

```bash
cd macos/fm-steward

# Safe / rules short-circuit
swift run fm-steward classify --card Fixtures/grep_rm_rf.json --human
swift run fm-steward classify --card Fixtures/npm_test_loop.json --human

# Clear danger (deterministic hard-ask; no FM / no Wax)
swift run fm-steward classify --card Fixtures/curl_pipe_sh.json --human
swift run fm-steward classify --card Fixtures/rm_rf_workdir.json --human

# Residual gray (default --few-shot auto; live FM when available)
swift run fm-steward classify --card Fixtures/npm_test_loop.json --live --human
# pure FM residual (no few-shot):
swift run fm-steward classify --card Fixtures/npm_test_loop.json --few-shot off --live --human

# Full live prompt/output matrix
swift run fm-steward probe-matrix

# Pure-FM viability (always no few-shot)
swift run fm-steward eval-danger
```

### Behavior notes

- **v1 scope:** shell/command danger nuance only. Do not use email bulk/VIP demos as the product bar.
- **On-device model:** `SystemLanguageModel.default` + guided generation. Check `LiveBackend.isOnDeviceModelAvailable`.
- **Rules first (order):**
  1. `executed=false` → continue  
  2. `same_intent=test_loop` → continue  
  3. `CommandShape` safe shapes (echo/search/comment/print/var+echo/allowlisted dev clean) → continue  
  4. `HardDangerRules` clear catastrophe / exfil / RCE → **ask**  
  5. else residual: **Wax text few-shots (k≤3)** + **LiveBackend** FM  
- **Few-shot default:** `--few-shot auto` when seed is present; reseed if store missing, seed/store content hash ≠ sidecar, or store format version bumps (`*.wax.seedsha` payload `v{N}:<seed-sha256>:<store-sha256>`). Fail-open on auto. Use `off` for pure-FM comparisons. `eval-danger` is always pure-FM.
- **First-run seed:** when Application Support `seed.json` is missing but package `Fixtures/ambig-fewshot/seed.json` exists, CLI/library bootstrap copies package → App Support (`FewShotSeedBootstrap.bootstrapAppSupportSeedIfNeeded`). Hosts should call the same helper before resolve for installed products.
- **Hard fence** remains Zig (catastrophe deny). FM never unlocks hard deny; offline/timeout → continue.
- **Default timeout:** `3000ms` bounds residual **retrieve + backend** (raise with `--timeout-ms` for cold first token). Prefer **`StewardSession`** as host API.
- **Fresh LanguageModelSession per classify** so multi-card runs do not exceed the 4K context window.
- **Wax:** SPM pin exact **0.1.25**, `traits: []` (text mode; no MiniLM). See `docs/dev/dependencies.md`.

## Demo (v1 shell fixtures)

| Fixture | Expected (product path) |
|---------|-------------------------|
| `Fixtures/grep_rm_rf.json` | `continue` (rules: not executed) |
| `Fixtures/npm_test_loop.json` | `continue` (rules: test_loop) |
| `Fixtures/curl_pipe_sh.json` | `ask` (HardDangerRules: curl\|sh) |
| `Fixtures/rm_rf_workdir.json` | `ask` (HardDangerRules: home path wipe) |
| `Fixtures/timeout_forced.json` | Neutral card metadata; timeout proven via `SlowBackend` tests |

```bash
./scripts/demo.sh
```

## Product Zig wiring

`ryk evaluate` and `ryk run` / shim call this steward. **`ryk hook` and bare agent-hook do not** (they set `disable_fm` so host PreToolUse never waits on classify). The choke is `applyFmSoftSeatbelt` in `src/cli/shell_eval.zig`. Live callers (do not treat as unattached):

| Surface | Role |
|---------|------|
| `src/cli/fm_steward_client.zig` | Subprocess client: `fm-steward classify --card <temp> --timeout-ms N --json`. Fail-open. |
| `src/cli/shell_eval.zig` | Soft-seatbelt choke after hard fence + policy matrix |
| `src/cli/evaluate.zig` / run / shim | Product shell → that choke |
| `src/cli/hook.zig` | PreToolUse / PermissionRequest shell: `disable_fm` on the live route; tests may inject a client |

**Order (see `docs/policy.md`):** critical hard fence deny → sticky match → strict refuse → mode × severity matrix → **then** FM on remaining soft outcomes (`allow` \| `warn` \| `ask`).

**Assist only — never unlocks hard deny.**

- `.block` / critical deny never reach the client
- Sticky session trust is a terminal soft allow (no FM re-ask)
- FM may **upgrade** soft continue → `ask` only (`ask_sticky_candidate` → ask + optional sticky hints)
- Timeout / missing binary / parse error / `RYK_FM_STEWARD=0` / non-macOS → **continue** (keep the soft matrix outcome; never invent ask)

Binary resolve: `RYK_FM_STEWARD_BIN` if set, else `fm-steward` on PATH. Transport is subprocess only (no UDS). Zig does not call Swift `Classifier` for residual RAG.

```bash
# Live callers (expect hits; this is not a negative-scope check)
rg -n 'fm_steward_client|applyFmSoftSeatbelt' src/cli/hook.zig src/cli/shell_eval.zig src/cli/fm_steward_client.zig
```

### Remaining scope (not product)

- Host sticky UI / always-allow storage for hosts that approve **outside** ryk (Claude, Codex, Pi) — `docs/policy.md` A5
- Employee **email / pay / social** seed bodies — architecture **stubs** only under `residual-knowledge/`

## Library surface

```text
StewardSession     ← preferred host API (warm + timeout race; residual few-shot; default 3000ms)
Classifier         ← pure rules + backend only (NO residual few-shot / RAG)
RulesPrePass       ← executed=false → test_loop → CommandShape → HardDanger → residual FM
CommandShape       ← safe skip shapes (no pipe exfil on search/echo)
HardDangerRules    ← deterministic soft-ask for clear danger
FewShotRuntime     ← product factory: makeRetriever (off / auto / wax)
FewShotStorePaths  ← App Support ambig.wax (+ ensureParentDirectory)
SeedPathResolver   ← explicit → (AS↔package content pin) → package on diverge → nil
FewShotRetriever   ← protocol + Null / Static / WaxFewShotStore (text)
FewShotSeedBootstrap ← seed reseed helpers (vN:seed:store sidecar, reseed flock, App Support seed bootstrap)
LiveBackend        ← real SystemLanguageModel, shell-focused prompt + few-shot block
UnavailableBackend / SlowBackend
RiskCard / ClassifyResponse / StewardModelOutput
```

## Host attach

**Product residual path for hosts:** `StewardSession` + `FewShotRuntime.makeRetriever` only.

Do **not** use `Classifier` for residual RAG / few-shot. `Classifier` is the pure
rules + backend pipeline (tests and composition). It has no retriever, no Wax store,
and never injects neighbor examples. Residual few-shot assist is composed only on
`StewardSession` after the host builds a retriever from the library factory.

### Before you attach

Run the residual attach gate (offline hard gate; optional live soft SKIP):

```bash
# from package root (macos/fm-steward)
bash scripts/residual-stress-matrix.sh              # offline only (default)
bash scripts/residual-stress-matrix.sh --live       # offline + live residual dump

# from repo root
bash macos/fm-steward/scripts/residual-stress-matrix.sh
```

The residual-stress-matrix **offline** path is the **rules isolation hard gate**
(`few_shot_hits` / spy callCount == 0). Live residual dump soft-SKIPs when on-device
FM is unavailable (exit 0) and does **not** claim attach residual is proven after a
live SKIP — only “rules isolation hard gate PASS.” When live runs, it uses a **temp
`--wax-store` + package `--seed`** (never product App Support), dumps residual grays
with few-shot **off vs auto**, and asserts rules short-circuit **expected verdict**
(e.g. `ask` for hard-danger `curl|bash`) plus hits==0. **Run residual-stress-matrix
before host attach.** Do not enable few-shot on `eval-danger` (pure-FM only).

### Store layout (product default)

| Artifact | Path |
|----------|------|
| Wax store | `~/Library/Application Support/ryk/fm-steward/ambig.wax` |
| Seed-hash sidecar | `~/Library/Application Support/ryk/fm-steward/ambig.wax.seedsha` (`v{N}:<seed-sha256>:<store-sha256>`) |
| Reseed lock | `~/Library/Application Support/ryk/fm-steward/ambig.wax.reseed.lock` |
| Optional seed copy | `~/Library/Application Support/ryk/fm-steward/seed.json` |

Resolved via `FewShotStorePaths.productStoreURL()` / `storeURL(override:)`. Hosts may
override the store URL for tests or ops; product default is **not** a temp directory.

### Seed resolution order

Existence-checked (regular file only) — `SeedPathResolver.resolve`:

1. **Explicit** seed URL (host / CLI `--seed` override) if the file exists
2. When **both** App Support and package seeds exist: prefer **package** unless
   content SHA-256 is equal (true copy) — then App Support may be returned
3. Else first existing of: **App Support** → **package** → **`nil`**

**Trust model (assist only):** App Support `seed.json` is operator-trusted (same-user
FS). Divergent App Support content does not shadow the package curated seed without
an explicit `--seed` override. This is **not** a multi-user security fence.

**First-run bootstrap (P2):** before resolve, call
`FewShotSeedBootstrap.bootstrapAppSupportSeedIfNeeded(from: packageSeed, to: appSupportSeed)`
so a missing App Support copy is materialized from the package fixture. CLI does this
for product `auto`/`wax`. Idempotent when App Support already has `seed.json`.

| Mode (`FewShotMode`) | Missing seed / load failure |
|----------------------|-----------------------------|
| `.auto` (product default) | Fail-open → `NullFewShotRetriever` (pure residual FM) |
| `.wax` | Throws (`seedNotFound` / `seedFailed`) |
| `.off` | Always null retriever |

Reseed when the store is missing **or** sidecar is missing / unparseable **or**
format version ≠ `FewShotSeedBootstrap.storeFormatVersion` **or** seed content hash
≠ sidecar **or** store content hash ≠ sidecar (`v{N}:<seed-sha256>:<store-sha256>`
on `*.wax.seedsha`; legacy `vN:seed` without store field forces reseed). **Assist
integrity only** — not multi-user security. Runtime opens without the reseed lock
when the fingerprint already matches; otherwise holds exclusive `flock` (+ process-local
process-local gate) on `*.wax.reseed.lock` around needsReseed → seed → recordSeedHash;
`.auto` fail-opens Null on lock contention.

### Host wiring sketch

```swift
import FMSteward

let appSupportSeed = SeedPathResolver.productAppSupportSeedURL()
let packageSeed = packageFixtureSeedURL  // or nil in installed hosts without package tree

// 0) First-run: materialize App Support seed from package when missing
if let packageSeed {
    _ = try? FewShotSeedBootstrap.bootstrapAppSupportSeedIfNeeded(
        from: packageSeed,
        to: appSupportSeed
    )
}

// 1) Resolve seed (explicit → App Support → package fixture → nil)
let seedURL = SeedPathResolver.resolve(
    explicit: hostSeedOverride,                         // or nil
    appSupportSeed: appSupportSeed,
    packageSeed: packageSeed
)

// 2) Product store under Application Support
let storeURL = FewShotStorePaths.productStoreURL()
try? FewShotStorePaths.ensureParentDirectory(for: storeURL)

// 3) Residual retriever — ONLY via FewShotRuntime (not Classifier)
let mode: FewShotMode = .auto
let retriever: any FewShotRetriever
if let seedURL {
    retriever = try await FewShotRuntime.makeRetriever(
        mode: mode,
        seedURL: seedURL,
        storeURL: storeURL
        // searchMode defaults to .text (product path)
    )
} else if mode == .wax {
    // no seed → wax must error; auto would use Null
    throw … // host maps to fail-closed or operator message
} else {
    retriever = NullFewShotRetriever()  // auto / off without seed
}

// 4) Preferred host API — residual few-shot + timeout race (retrieve+backend)
let session = StewardSession(
    backend: LiveBackend.preferredDefault(),
    fewShotRetriever: retriever
)
await session.warm()
let response = await session.classify(card)
// Hosts that open Wax should close when done: await (retriever as? WaxFewShotStore)?.close()
```

### Honesty (Zig + Swift attach)

- **Zig product hooks call this steward.** `hook.zig` / `shell_eval.zig` (and
  evaluate / run through that choke) invoke `fm_steward_client` as a subprocess.
  The Swift sketch above is for Mac demo / in-process embed of `StewardSession`.
  Both paths are residual assist — not a second policy engine.
- **Assist only.** Wax neighbors + on-device FM are residual soft-seatbelt assist —
  not sole security. Zig hard fence still owns catastrophe deny. FM never unlocks
  hard deny. Fail-open on store/search errors → empty few-shots → normal FM /
  unavailable path.
- Prefer sequential `StewardSession.classify` from one owner (actor single-flight).

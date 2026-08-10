# Changelog

## [1.2.12] - 2026-08-08

**Full Changelog**: https://github.com/christopherkarani/ryk/compare/v1.2.11...v1.2.12

## [1.2.11] - 2026-08-08

## What's Changed
* Fix release resume state quoting by @christopherkarani in https://github.com/christopherkarani/ryk/pull/114


**Full Changelog**: https://github.com/christopherkarani/ryk/compare/v1.2.10...v1.2.11

## [1.2.10] - 2026-08-08

## What's Changed
* harden sandbox and secret-boundary enforcement across macOS and Linux
* add agent-inference policy discovery and CLI onboarding improvements
* add verified CLI documentation and PostHog product telemetry
* make the checksum-verified curl installer the only active release channel

**Full Changelog**: https://github.com/christopherkarani/ryk/compare/v1.2.9...v1.2.10

## [1.2.9] - 2026-07-25

## What's Changed
* feat: proxy daemon CLI and surface shell deny remediation by @christopherkarani in https://github.com/christopherkarani/ryk/pull/48
* feat(cli): P0 one-product UX (start, deny, doctor, help) by @christopherkarani in https://github.com/christopherkarani/ryk/pull/49
* feat(cli): P2a power baseline — packs productized + orca status by @christopherkarani in https://github.com/christopherkarani/ryk/pull/50
* feat(cli): mode×severity shell matrix and day-2 policy loop (P2b) by @christopherkarani in https://github.com/christopherkarani/ryk/pull/51
* fix: harden dashboard, redaction, and host integrations by @christopherkarani in https://github.com/christopherkarani/ryk/pull/52
* feat(cli): readiness contracts, daemon hardening, and OpenClaw honesty by @christopherkarani in https://github.com/christopherkarani/ryk/pull/53
* fix: close residual PR #53 security risks by @christopherkarani in https://github.com/christopherkarani/ryk/pull/54
* feat(install): polish curl|sh installer UX with step receipt by @christopherkarani in https://github.com/christopherkarani/ryk/pull/55
* feat(policy): effect-class semantic intent for host and MCP tools by @christopherkarani in https://github.com/christopherkarani/ryk/pull/56
* feat(policy): Phase B structural args, network tags, and shell effect merge by @christopherkarani in https://github.com/christopherkarani/ryk/pull/57
* feat(policy): Phase C user effect packs and tools discovery by @christopherkarani in https://github.com/christopherkarani/ryk/pull/58
* fix(policy): address PR #57 review gaps on proxy and shell classifiers by @christopherkarani in https://github.com/christopherkarani/ryk/pull/59
* feat(policy): Phase D local residual effect classifier by @christopherkarani in https://github.com/christopherkarani/ryk/pull/61
* feat(security): OS filesystem sandbox for orca run (Landlock + Seatbelt) by @christopherkarani in https://github.com/christopherkarani/ryk/pull/63
* feat(cli): viral Safe Launch surface for agent operators by @christopherkarani in https://github.com/christopherkarani/ryk/pull/64
* feat: add Phase 2 network route forcing by @christopherkarani in https://github.com/christopherkarani/ryk/pull/65
* refactor(orca-rs): remove orphan CLI surface and dead guard APIs by @christopherkarani in https://github.com/christopherkarani/ryk/pull/66
* feat: Zig shell_engine sole Evaluate authority; static PCRE2 by @christopherkarani in https://github.com/christopherkarani/ryk/pull/67
* chore(scripts): drop dead daemon stubs and orca-rs gate paths by @christopherkarani in https://github.com/christopherkarani/ryk/pull/68
* feat(shell_engine): Phase 1 hard fence — pack order + structure smart checks by @christopherkarani in https://github.com/christopherkarani/ryk/pull/69
* feat(policy): Phase 2 YOLO/Strict modes and session sticky trust by @christopherkarani in https://github.com/christopherkarani/ryk/pull/70
* feat(fm-steward): Phase 3 Mac risk-card steward with timeout fallback by @christopherkarani in https://github.com/christopherkarani/ryk/pull/71
* feat(fm-steward): wire real on-device SystemLanguageModel by @christopherkarani in https://github.com/christopherkarani/ryk/pull/72
* feat(fm-steward): residual attach surface + soft-edge integrity by @christopherkarani in https://github.com/christopherkarani/ryk/pull/73
* feat(hooks): Phase 4 wire FM steward into product shell paths by @christopherkarani in https://github.com/christopherkarani/ryk/pull/74
* feat(brand): Phase 5a product identity cut Orca → ryk by @christopherkarani in https://github.com/christopherkarani/ryk/pull/75
* feat(cli): P0 permanent allowlist, allow-once, and packs CLI by @christopherkarani in https://github.com/christopherkarani/ryk/pull/77
* feat(cli): DCG-parity ryk explain + remove demo by @christopherkarani in https://github.com/christopherkarani/ryk/pull/76


**Full Changelog**: https://github.com/christopherkarani/ryk/compare/v1.2.8...v1.2.9

## Unreleased

### Breaking
- **Brand hard cut — Rykan V / `ryk` only (no legacy-brand compatibility).**
  - **Product:** full name **Rykan V**; CLI **`ryk`** only (no retired binary aliases).
  - **Environment:** `RYK_*` only (no legacy-brand dual-read/write).
  - **Paths:** workspace `.ryk/`, config `~/.config/ryk/`, resources `share/ryk/`.
  - **Zig modules:** `ryk`, `ryk_core`, `ryk_cli`.
  - **npm scope:** `@rykan/ryk`, `@rykan/pi-ryk`.
  - **Audit actor kind:** `"ryk"`.
  - **Dirs:** `ryk-pi/`, `ryk-dashboard-ui/`.
  - Historical changelog and denylist tokens remain only where they document past brands or attack surface.
  - **Codex guard emit:** `[[RYKAN-V-GUARD]]` only.
  - **Share install path:** `~/.local/share/ryk`.
  - **Git remote / Zig package graph:** unchanged (`build.zig.zon` `.name = .ryk` stays).

### Changed
- **Full Zig shell evaluator (MVP)** — `ryk hook` / `ryk run` / shims evaluate shell commands in-process via `src/shell_engine` by default (`RYK_SHELL_EVAL=zig`). Daemon-down no longer gates shell PreToolUse. `ryk test` / `ryk explain` are Zig-native. Former Rust ExecuteCli surfaces (`scan`, `simulate`, `packs`, `history`, allowlist mutators, …) stub until ported. The Rust daemon crate is removed from the tree.
- **Product language cut (Safe Launch)** — public day-1 path is now:
  - `ryk start` → `ryk <agent>` → `ryk status` → `ryk replay` (+ `ryk stop` off-ramp)
  - Default help shows only public verbs; full surface via `ryk help --all`
  - Public onboarding peers **`ryk quickstart`** and **`ryk setup`** are hard-removed (use `ryk start`; logic retained as library for internal composition)
  - `ryk start` auto-selects **Ask on risk** (no public `--protection` grade menu)
  - Human `ryk status` is traffic light **Protected | Limited | Off** plus one mediation caveat
  - Bare `ryk replay` loads the last session; denials visually dominant; empty state teaches Safe Launch
  - Interactive deny offers **Once / Always / Never** (prompt-native; CLI allow/allow-once remain advanced fallback)
  - Host aliases (`ryk claude`, `ryk codex`, …) are the taught launch path; `ryk run` is the engine / advanced escape hatch
  - Docs/README/quickstart/CLI reference rewritten for the cut; stop next-step points to `orca start`

### Added
- **Phase D residual classifier** — optional `effects.classifier: local` (alias `local-embed`) runs pure-Zig prototype/token similarity on tools that catalog/structural/packs leave under-classified. Default **off**. Raise-only; matchers `classifier.local.*`; fail-closed in strict/ci/redteam when enabled but unavailable. No cloud classification; no new deps.
- **Effect-class policy** (`effects:`) classifies host/MCP tool names into semantic effects (`comms.message`, `comms.publish`, `money.transfer`, …) so users can deny messaging/social tools without listing every name.
- Built-in tool-name catalog and `ryk policy explain tool <name>`.
- Preset `no-external-comms` for strict-local plus external-comms effect denials.
- Host `PreToolUse` generic tools, `ryk decide tool`, and MCP `tools/call` enforce effect rules when `effects:` is configured (deny beats MCP allow).
- `effects.default` applies to unclassified tool names (catalog misses), matching surface-default semantics.
- **Phase B structural classification** — tools renamed as `notify`/`helper` still match effects from argument key sets (e.g. `{to, body}`) and bounded value shapes; reasons use `structural.*` matcher ids (no secret values).
- **Network effect tags** — when `effects:` is active, curated hosts (e.g. `api.twitter.com` → `comms.publish`) merge into network evaluation (`network_tag.*` matchers).
- **Shell bypass (Zig command path)** — `open mailto:…` (and optional curl-to-tagged-host) merges effects on Zig command evaluation (`shell_bypass.*`); host shell PreToolUse uses Zig `shell_engine` MVP packs (documented residual gap vs full effect-class parity).
- `ryk policy explain tool <name> --args '<json-object>'` for structural demos (size-bounded).
- **Phase C discovery** — `ryk mcp inspect` prints inferred effects per tool; `ryk tools classify <name> [--args] [--policy]` for interactive classification (no secret values in output).
- **User effect packs** — YAML in `.ryk/effect-packs/` and `~/.config/ryk/effect-packs/` add names/tokens/structural key-sets (`pack.<id>.*` matchers). Classification-only; decisions still require policy `effects:`. Invalid packs fail closed. Example: `examples/effect-packs/demo.yaml`.

### Fixed
- Network effect tags now apply on the **runtime proxy** path (`network_eval.evaluate` / `ryk run`), not only `policy explain network`.
- Shell bypass: `open -a`/`-b` option values are skipped; multi-URL `curl` scans every operand; `open`/`curl` require command position (avoids `printf … open mailto:` false positives).
- Shell bypass: wrappers with options (`sudo -u root curl …`, `env -i open …`, `xargs curl …`), escaped operators (`foo\;`), non-transfer curl values (`--referer`), and lookup-only `command -v`/`-V` are handled correctly.
- Structural arg scan prefers interesting keys/values against decoy padding (including large objects and string-value slot exhaustion); `href`/`uri` share interesting priority with other URL keys; eviction allocates before free (OOM-safe).
- Shell bypass residual note updated: host shell PreToolUse uses Zig `shell_engine` (MVP); full effect-class parity on compound shell forms remains deferred.

## v1.2.8 - 2026-07-04

### Changed
- Version bump to 1.2.8 across all manifests and plugins.

## v1.2.7 - 2026-07-03

### Added
- Dashboard activity feeds now surface Pi session identifiers for clearer multi-session diagnostics.

### Fixed
- Local release publishing now attaches the complete verified artifact contract, including installer checksums.

## v1.2.6 - 2026-07-01

### Changed
- All plugins and core unified to version **1.2.6**.

### Fixed
- Minor stability improvements across CLI, daemon, and plugin integrations.

## v1.2.5 - 2026-07-01

### Changed
- Pi block and ask states now use compact, branded Orca decision cards with clearer reason hierarchy and bounded long-text wrapping.
- Rust hook output and OpenCode/OpenClaw fallback copy now identify Orca explicitly across block and ask states.

### Fixed
- Pi decision cards use the stable above-editor widget surface and remain aligned for long or unbroken reasons.

## v1.2.4 - 2026-06-30

### Added
- **`--live` / `--tui` alt-screen views** for `history` and `replay`.
- **Reduced-motion support** across TUI spinners and animations.
- **OSC 11 background detection** for automatic light/dark theme wiring.
- **Branded first-run celebration** and improved onboarding moments.
- **Pi slash commands** `/orca-start` and `/orca-stop` for session-level protection control.

### Changed
- **`--no-rich`** and `RYK_NO_RICH=1` now gate color without changing machine-readable output.
- `--tui` + `--json` is rejected at preflight to prevent mixed output modes.

### Fixed
- CLI self-import support in the build.
- Replay/history live help and banner rejection edge cases.
- Phase 6 public contract freeze: exact bytes preserved for JSON, robot, export, and MCP proxy paths.

## v1.2.3 - 2026-06-24

### Fixed
- **OpenCode plugin** — Update for OpenCode 1.16 plugin API so `tool.execute.before` blocking works again.

## v1.2.0 - 2026-06-19

### Added
- **Rust daemon (`orca-daemon`)** — UDS IPC between Zig CLI and Rust evaluator; shell hook evaluation routed through daemon with fail-closed behavior when unavailable.
- **`orca evaluate`** — Stable machine JSON API for shell command evaluation (`--json --stdin`).
- **`orca start`** — Guided onboarding flow with host detection and plugin install.
- **Pi extension (`@orca-guard/pi-orca`)** — Official Pi package for bash tool-call protection via `orca evaluate`.
- **Bundled `orca-daemon`** in all platform release archives and install layouts.

### Changed
- **Zig 0.16.0** toolchain migration.
- **Guided onboarding** — Interactive `orca setup` with multi-host selection.
- **Unified versioning** — Core and all agent plugins aligned to 1.2.0.
- Shell `PreToolUse` / tool evaluation defaults route through Rust daemon when available.

### Fixed
- **Hermes Agent** — Orca discovery, degraded-mode handling, and version mismatch fixes.
- **Pi integration** — Honor deny decisions, timeouts, cwd, and auto unavailable mode.
- Install/DX hardening — quick-install presets, `orca doctor` activation exports, piped install robustness.

## v1.1.5 - 2026-05-24

### Added
- **`orca disable`** — Remove Orca plugin registrations from host agents without touching binary or policy.
- **`orca uninstall`** — Full removal of plugins, binary, and user config (preserves workspace `.ryk/`).

## v1.1.4 - 2026-05-21

### Fixed
- **OpenClaw plugin:** Detect and warn when `api.on` is a no-op for npm installs, preventing silent hook bypass.
- **Core stability:** Fix invalid free in redteam fixture root handling; prevent waitpid panic after watchdog kill in credentials broker.
- **CLI:** Add `--ci` shorthand for `orca run --ci`; auto-resolve fixture root via `resource_root` in `orca redteam`.

### Changed
- **Unified versioning:** All components — core, OpenClaw, OpenCode, Hermes, Codex, and Claude Code plugins — now share version 1.1.4.

## v1.1.0 - 2026-05-12

- Prepared Orca production release metadata and artifact contract.
- Added checksum, release-manifest, SBOM inventory hook, optional signing hook status, install guidance, GitHub release draft, tagging instructions, release checklist, and production-readiness report.

## Previous Phases

Earlier releases established the current policy engine, shell evaluator, host integrations, audit and replay tooling, red-team checks, and release process.

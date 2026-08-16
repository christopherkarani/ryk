# Compatibility Matrix

Use `ryk doctor` for the authoritative report on a specific machine. This matrix uses ryk capability vocabulary: `active`, `partial`, `wrapper-only`, `observe-only`, `limited`, `unavailable`, and `unsupported`.

## Protection grades (canonical)

ryk is **graded mediation**, not a universal OS sandbox. Public product language uses these grades:

| Grade | Meaning | Typical ryk surface |
| --- | --- | --- |
| `hook` | Host invokes ryk and honors veto | Native plugin / host hook that actually fires |
| `wrapper` | Public host launch aliases (`ryk <agent>`) / PATH shims / advanced run engine mediation | Finite executable list; absolute paths may bypass |
| `proxy` | Traffic must traverse a ryk proxy | MCP / optional network proxies |
| `OS-enforced` | Kernel/sandbox backend actually enforcing for that session | Only after child session-attach succeeds; doctor probes alone are not enough |

**Default public launch posture (`ryk <agent>`):** typically **`wrapper`**, plus optional OS filesystem session-attach through the run engine. Host **`hook`** applies only when hooks fire and honor veto. **`proxy`** applies only to traffic that traverses a ryk proxy. **`OS-enforced`** FS isolation requires a successful Landlock (Linux) or Seatbelt (macOS) attach for that child — not a doctor capability probe.

**What can still bypass `wrapper` mediation:** absolute-path binaries outside the shim list (including `/bin/rm`), `command -p`, shell aliases/functions, nested absolute `node`/`python` exec, outer allowed `bash ./script` until a child hits a shimmed name, non-shimmed tools, agents started outside `ryk <agent>` / advanced run / hooks, non-proxy HTTP clients, non-firing host hooks, and direct syscalls. High-risk bare PATH names (`rm`, `mv`, `cp`, `chmod`, `dd`) are shimmed when the session installs PATH shims; that does **not** close absolute-path residual without process-exec policy (product Q3).

### Vocabulary map

Doctor / platform reports are **not** a second taxonomy. Map them to grades:

| Other surface | Maps to grade(s) | Notes |
| --- | --- | --- |
| doctor `wrapper-only` (command guard / PATH shims) | `wrapper` | Not transparent OS enforcement |
| doctor sandbox / strong sandbox `partial` (API present) | probe only | Capability evidence; **not** a live session claim |
| doctor sandbox / transparent FS or network `active` | `OS-enforced` | Rare; doctor never marks session active from probe alone |
| Protected agent launch + successful child attach | `OS-enforced` (FS, that session) | `ryk <agent>` uses the run engine; advanced `ryk run --os-sandbox` exposes explicit attach flags. Landlock ABI ≥ 3 (kernel 6.2+; ABI 1/2 lack truncation mediation) or Seatbelt majors 14–26 (capability gate; CI attach evidence: linux amd64. Seatbelt attach is local.) |
| doctor `observe-only` / `limited` / `unavailable` | no enforcement claim | Decision or partial path only |
| MCP stdio proxy `active` | `proxy` (MCP path) | Only for mediated MCP traffic |
| `ryk start` default (**generic-agent / DCG strict**) | multi-grade aspirational (`hook` + `wrapper` when available) | Public path has no `--protection` flag; wires host hooks + policy; not `OS-enforced` from doctor probes alone |
| Host hooks that fire and honor veto | primarily `hook` (+ daemon for shell eval) | Depends on host install path; hooks alone are not process wrap |
| Host aliases / advanced run engine / PATH shims | primarily `wrapper` | Not kernel firewall; absolute paths may bypass |

Reserve marketing “firewall” / “maximum protection” for a **verified** multi-grade or **`OS-enforced`** posture. See also [threat-model.md](threat-model.md).

---

## Platform feature matrix

| Feature | Linux | macOS | Windows |
|---|---|---|---|
| Launch arbitrary command | active | active | active |
| Env filtering | active | active | active |
| Secret redaction | active | active | active |
| Audit/replay | active | active | active |
| Staged writes | active | active | active |
| Command guard | wrapper-only | wrapper-only | wrapper-only |
| Shell/PATH shims | wrapper-only | wrapper-only | wrapper-only |
| MCP stdio proxy | active | active | active |
| MCP manifests | active | active | active |
| MCP sampling controls | active | active | active |
| Network decision engine | active | active | active |
| Proxy-mediated network enforcement | limited; explicit loopback proxy when requested; route forcing when OS sandbox supports it | limited; explicit loopback proxy when requested; route forcing when OS sandbox supports it | unavailable (no loopback proxy) |
| Transparent network enforcement | per-session Landlock TCP route forcing with ABI >= 4; otherwise observe-only | per-session Seatbelt TCP route forcing with proxy backend + OS sandbox; otherwise unavailable | unavailable; wrapper-mediated only, routes not forced |
| Transparent filesystem enforcement | staged writes; Landlock attach when available | limited; Seatbelt attach when available | unavailable; no OS attach. Staged writes and protected-path matching only (wrapper/hook) |
| Strong sandbox (session-attach) | Landlock when ABI ≥ 3 (kernel 6.2+); else unavailable | Seatbelt capability majors 14–26; else unavailable | unavailable |
| Advanced `--os-sandbox` flag | auto \| on \| off (default auto) | auto \| on \| off (default auto) | off / unavailable |
| Advanced `--seatbelt-profile` / `RYK_SEATBELT_PROFILE` | n/a (Landlock) | compatible \| hardened \| strict (default **hardened**) | n/a |
| Process cleanup | active or partial | active | partial |
| Red-team suite | active | active | active |

`wrapper-only` means ryk-mediated command paths are protected by shims or wrappers (grade **`wrapper`**). It is not transparent OS enforcement. Absolute paths can skip PATH shims. On macOS and Linux, OS filesystem attach and network route-force (when active) still apply to the child process. PATH honesty under attach uses a **denylist** of known package trees plus an optional essentials file-only `.exec` pack (`RYK_TOOL_PACK`) — see `docs/commands.md`.

**Windows:** ryk is macOS/Linux-first. There is no OS-enforced session-attach (`src/sandbox/windows.zig` reports `strong_sandbox` unavailable). Sessions are `wrapper` / `hook` grade; MCP stdio is `proxy` grade. Doctor probes cannot promote Windows to `OS-enforced`. See [platform-windows.md](platform-windows.md).

**Probe vs session-attach:** Doctor and platform matrices may report sandbox **capability** (`partial` / API present). That is not a live session `active` claim. Trust **`OS-enforced`** filesystem isolation only for a protected agent session that completed child apply-before-exec attach (profile hash present). Use advanced `ryk run --os-sandbox on` to fail closed when attach cannot complete.

**DNS rebinding fence (proxy grade):** after a hostname passes policy, the intercept proxy re-checks every resolved address before connecting and pins the validated address (no re-resolution). Answers in loopback, RFC1918/private, link-local, or cloud-metadata classes are refused unless `network.allow` explicitly lists the class token (`localhost`, `private`, `metadata`) or the exact IP; the attempt is denied with a `network_connect_denied` audit event. A hostname allow therefore covers public-unicast answers only.

**In-shim audit under OS attach (evidence honesty):** when a session attaches Seatbelt/Landlock, the control root (`.ryk`) is write-denied to the child *by design*, so PATH shims cannot append to the session audit log. The parent records this as an `audit_degraded` event at session end, and `ryk replay` / `ryk doctor` surface degraded sessions. If a shim instead finds the audit file unwritable while the control root is writable (tamper-shaped, e.g. `chmod 000 events.jsonl`), the shim **fails closed**: the allowed exec is denied rather than run unaudited.

**Capability matrix vs CI attach evidence:** Landlock/Seatbelt version gates (Linux ABI ≥ 1; macOS product majors 14–26) describe **where attach may run**. Continuous **CI attach evidence** today is **linux amd64** only; Seatbelt and other OS/arch/major cells are local — do not treat every gated major as CI-proven.

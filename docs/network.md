# Network

ryk includes a network decision engine and wrapper/proxy-mediated hooks.

`file://` URLs are a filesystem/sandbox concern, not network policy. Treat them under FS grants and workspace mediation, not as network allowlist/exfil signals.

## Modes

- `off`: deny network decisions.
- `allowlist`: allow only configured destinations.
- `ask`: ask interactively where supported.
- `observe`: log decisions.
- `open`: allow decisions (and, for host aliases, **unrestricted OS egress**).

```sh
./zig-out/bin/ryk claude
./zig-out/bin/ryk codex
./zig-out/bin/ryk run --network allowlist --allow-network api.github.com -- <custom-command>
```

## Agent host defaults

Host aliases (`ryk pi`, `ryk claude`, `ryk codex`, `ryk opencode`, `ryk openclaw`, `ryk hermes`, `ryk grok`) default to **mediated** network:

1. Policy mode **allowlist** (when `--network` is omitted)
2. Network **backend = proxy**
3. OS sandbox **route-force** (child outbound TCP only to the loopback proxy port)
4. If proxy bind or route-force cannot start → **fail closed** (session does not start)

Escape hatch (loud stderr + audit `network unrestricted; escape used`):

```sh
# Pass run flags before the host — aliases do not peel flags after the host name.
ryk run --network open -- pi
# or: ryk run --network open -- claude
```

One-release kill switch to restore pre-change agent net defaults (labels without forced mediation):

```sh
RYK_AGENT_NETWORK_DEFAULT=legacy ryk pi
```

Custom `ryk run -- <command>` is **unchanged**: network mode still defaults to `ask`, backend stays policy/`decision_only` unless you pass `--network-backend proxy`. No silent lockdown on non-alias run.

**Honesty rule:** host aliases must not advertise `RYK_NETWORK_MODE=ask|allowlist` plus a populated allowlist while `RYK_BACKEND_NETWORK_ENFORCEMENT=unavailable` without either mediation (route-forced) or an explicit open/legacy escape.

## Policy

```yaml
network:
  mode: allowlist
  backend: proxy
  default: deny
  allow:
    - "api.github.com"
  ask:
    - "*.githubusercontent.com"
  deny:
    - "pastebin.com"
    - "*.ngrok.io"
    - "*.requestbin.net"
  detect_exfiltration:
    dns: true
    long_query_strings: true
    secret_patterns: true
```

Service-aware policy is additive to the flat host lists. Use it when a service needs method and path scope plus a credential reference name:

```yaml
services:
  github:
    hosts:
      - "api.github.com"
    methods:
      - "GET"
      - "POST"
    paths:
      allow:
        - "/repos/*/issues"
        - "/repos/*/pulls"
      deny:
        - "/user/keys"
        - "/orgs/*/secrets/*"
    credentials:
      use: github_pat
    unmatched: deny
```

The `credentials.use` value is a reference name for policy, audit, and external broker adapters. ryk does not store or inject the raw secret.

## Proxy Backend

`network.backend: proxy` starts an explicit loopback proxy for protected agent launches (`ryk <agent>` — default) and the advanced run engine. `ryk run --network-backend proxy` is still available for custom commands. The proxy path injects `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`, `RYK_NETWORK_ENFORCEMENT=proxy-mediated`, and `RYK_PROXY_ROUTE_FORCED`.

- HTTP requests are evaluated with host, port, method, and path visibility.
- HTTPS `CONNECT` requests are evaluated by host and port only.
- Proxy request attempts and allow/deny decisions are persisted as `network_connect_*` audit/replay events.
- The proxy accepts concurrent client connections and uses full-duplex forwarding after the first request bytes, which supports delayed request bodies, streaming bodies, and chunked-style uploads at the proxy layer.
- If proxy enforcement is required and the proxy fails while the child is running, ryk terminates the child and records a fail-closed proxy stop event.
- ryk does not perform HTTPS MITM.
- Proxy startup alone is not route forcing. `RYK_PROXY_ROUTE_FORCED=false` means the child received proxy env only.
- With `network.backend: proxy` plus OS sandbox attach, ryk installs child OS network rules where supported and exports `RYK_PROXY_ROUTE_FORCED=true`. Scope differs by mechanism:
  - **macOS Seatbelt:** outbound TCP only to the ryk **loopback** proxy port (`localhost:port` SBPL). Under default `--seatbelt-profile hardened` (and `compatible`), inbound/bind remain open (Landlock connect-only parity). Under `strict`, inbound/bind are denied. Residual mach-lookup / XPC isolation is still out of scope (see `docs/platform-macos.md` Seatbelt residual).
  - **Linux Landlock (ABI >= 4):** TCP **port-scoped only** (any remote IP on the proxy port; not address-scoped). **UDP/QUIC unrestricted.** Do **not** describe Landlock route force as loopback-only.
- Host aliases **require** route-force when mediation is on: `apply` fails closed if route-force cannot start (including sandbox `off` / soft-degrade), and `ryk run` refuses spawn when mediation is requested but `network_route_forced` is still false.
- `--require-backend network-proxy` is satisfied only when the explicit proxy backend starts successfully. `--require-backend network_enforce` is satisfied only by a route-forced OS sandbox session, not by proxy startup alone.

### Residuals (not claimed locked)

- **UDP / QUIC / WebRTC** are not day-one route-forced on either platform (Landlock leaves UDP unrestricted; Seatbelt proxy-port rules are TCP-oriented).
- Pre-existing connections outside the child process are out of scope.
- Tools that ignore `HTTP(S)_PROXY` still cannot dial arbitrary TCP hosts when route-force is active; absolute `/usr/bin/curl` is covered by OS rules, not shim theater. The `curl` PATH shim mediates the command through `shell_eval` (engine + destination allowlist); it is **not** itself the network allowlist.

## Exfiltration Heuristics

ryk flags long query strings, base64-like URL parts, high-entropy DNS labels, paste sites, request bins, tunneling services, direct IP destinations, secret-like values, and repeated unknown domains.

These findings are **annotate/audit by default**: they are recorded for operators and do not deny allowlisted HTTPS destinations. There is no separate “enforce secrets in URL” config switch on the proxy path (see also `docs/credentials.md`).

## Enforcement Levels

Policy decision is not the same as transparent network enforcement. `ryk doctor` distinguishes decision engine, observation, proxy-mediated enforcement, and transparent enforcement.

## Redaction

URLs are redacted before audit persistence when they contain secret-like material.

## Inference host discovery (AINA P3)

Fail closed to the open web; **fail open to the user’s already-configured model providers.**

Mediated agent launches (`ryk pi`, `ryk opencode`, other trusted host aliases) **discover** inference hostnames from the agent’s real config files (read-only under parent `HOME`) and **add** them to the effective network allow list. Discovery never replaces the static core/overlay floor and never removes user-authored `policy.yaml` allows.

### Effective allow merge order

Deterministic union (exact-host dedupe; first wins):

1. User policy allow (`policy.yaml`)
2. Core pack + host overlay (static floor)
3. Managed file (workspace-scoped, **host_key-filtered** by source tags) ∪ launch-time adapter for that host key
4. CLI `--allow-network`

**effective allow = user policy ∪ core ∪ overlay ∪ discovered(managed∩host_key + live adapter) ∪ CLI**

Managed store path: `<workspace>/.ryk/network-discovered.yaml` (optional; soft-skip when missing/corrupt). Contents are hostnames + source tags only — never tokens, keys, or credential-bearing URLs. Load re-validates every host (rejects wildcards, `network_eval` class tokens such as `private` / `metadata` / `direct-ip`, non-loopback IPs). Writes are atomic (temp+rename) and refuse symlink product paths.

### What discovery reads (and does not)

Adapters emit **hostnames only**. They prefer literal hosts from approved URL fields (`baseUrl`, `tokenEndpoint`, discovery endpoints), else map provider **ids** through a static catalog (unknown ids skipped). They **never** harvest MCP, marketplace, plugins, or full-tree URL regexes.

**Hard rejects on extract/load:** reserved policy class tokens (`private`, `metadata`, `direct-ip`, bare `localhost`), cloud-metadata hostnames, bare wildcards, credential-bearing URLs, **all IP literals** (incl. `127.0.0.1` / `::1`), and OS-ambiguous IP-like spellings (`127.1`, `10.1`, `0x7f000001`, decimal dwords, leading-zero octets). Local Ollama must be listed in user `policy.yaml` (avoids allow-before-class-deny SSRF via agent-writable auth).

**Soft-drop sinks:** paste/webhook/tunnel hosts from the shared `network_eval` table never auto-grant (live adapter and managed load).

**Residual (auth trust / DNS):** pi/opencode config dirs remain agent-writable for OAuth refresh. Novel multi-label non-sink hosts from custom `baseUrl` still auto-merge (URL-divergence support). Hostname-class deny does not re-check post-DNS peer address — a discovered name that later resolves to private/IMDS is a known residual; mitigate with catalog-only auto-merge or proxy post-resolve deny (follow-up). Operators can authority write-deny auth paths or pin allows only via `policy.yaml`.

**Deferred residuals:** interactive post-refresh host summary on `ryk start` (DIS-6 optional P1); pi `models.json` / models-store URL harvest (follow-up unit).

### Soft skip on errors

Missing/corrupt managed file, empty `HOME`, unknown host key, or adapter IO/parse failure does **not** fail launch — those sources soft-skip; the static floor and user allows remain. OOM hard-fails. Launch-time discovery is size-bounded.

### Start / init refresh

`ryk start` and `ryk init` refresh managed discovery for **pi ∪ opencode** (start always unions selected + detected + floor so partial selection does not clobber the other adapter):

- Read agent configs under parent `HOME` (process environ map, not libc-only getenv).
- Regenerate managed YAML (hostnames + source tags); never edit `policy.yaml`.
- Empty rediscovery leaves the existing managed file untouched.
- Refresh errors soft-warn and do not fail init/start.

Mediated `ryk <host>` also runs the launch-time adapter for that host key, so OAuth/API hosts work even if start/init was never re-run after a config change.

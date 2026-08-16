# Zig hook server — fast hooks for every host

One per-user Zig process, living inside `bin/ryk`, serving Claude, Codex, Grok, Cursor, Pi, OpenCode, OpenClaw, and Hermes at the same time.

This is not the removed Rust `ryk-daemon`. No second binary. Release archives must still forbid a file named `ryk-daemon`.

**Goal:** host PreToolUse / `evaluate` p50 under 5ms on a warm Mac, without changing allow / ask / deny.

---

## Why a server

Every host today starts a new 5.4MB `ryk` for each event:

| Host | Invocation | Events that pay the tax |
| --- | --- | --- |
| Grok | `ryk hook grok PreToolUse` | Every Bash and Read |
| Claude | `sh -c` → `exec ryk hook claude <event>` | SessionStart, prompt, PreToolUse, PermissionRequest, PostToolUse, SessionEnd |
| Codex | same `sh -c` pattern | Same as Claude, plus Stop |
| Cursor | bare `ryk` stdin, or Python then ryk | `beforeShellExecution` |
| Pi | `ryk evaluate --json --stdin` | Every bash tool from the extension |
| OpenCode / OpenClaw / Hermes | plugin `spawn` / `execFile` of `ryk hook` | Each registered event |

On Linux, a warm shell hook is already ~5ms. On Mac, spawn + dyld + dual feed `fsync` + a production telemetry spawn is 30–100ms. Pack matching is not the bulk.

A long-lived process loads packs and policy once. The host still spawns `ryk hook` (hosts only know how to run a command). That process becomes a thin client: connect, forward stdin, print the host JSON, exit.

---

## Decision: one server per user + binary, many hosts

**Yes — one server, many hosts, many agents, many workspaces.**

Not one server per Grok session. Not one server per host. Not one server for the whole machine if two UNIX users are logged in.

| Scope | What we run | Why |
| --- | --- | --- |
| One UNIX user + one `ryk` binary | One hook server | Packs and code stay warm. Claude + Grok + Codex on one laptop share it. |
| Two UNIX users | Two servers | Socket is `0600` / dir `0700`. No cross-user evaluate. |
| `/usr/local/bin/ryk` and `./zig-out/bin/ryk` | Two servers | Different bytes can decide differently. Socket path includes a short hash of the client realpath. |
| Two workspaces | Still one server | Cache policy by workspace realpath + mtime. Never mix `~/work` strict with `~/play` ask. |
| Two hosts in one repo | Still one server | Request carries `host` + `event`. Wire JSON is per host; the engine is shared. |

Same-UID isolation is already the product threat model. A same-user agent can already plant `policy.yaml`. The server does not make that worse.

### Alternatives we are not taking

1. **One server per `ryk <host>` session.** Four agents means four copies of the oracle and four idle processes. Sticky state is easier, speed is the same, RAM and wake-ups are worse.
2. **One server for the whole machine (root / launchd).** Cross-user evaluate is a non-starter. Extra privilege with no speed win.
3. **A second `ryk-hook` binary.** Fights the one-`bin/ryk` release contract. Hosts already call `ryk hook` / `ryk evaluate`.

---

## How a request looks

```
Claude / Codex / Grok / plugin
        │  spawn (unavoidable)
        ▼
ryk hook <host> <event>     ← thin client, ~1ms
        │  UDS / named pipe
        ▼
ryk hook-serve              ← one process, warm
        │
        ├─ cache[workspace] → policy, pack ids, allowlist (mtime)
        ├─ session[session_id] → sticky map
        ├─ evaluate (existing shell_engine + hook.zig)
        ├─ write host-shaped stdout/stderr/exit back
        └─ then append feed / telemetry (not on the return path)
```

Pi uses the same socket via `ryk evaluate`. Cursor uses it via bare `ryk` stdin. The client is whichever entry point the host already has.

### Protocol (v1)

NDJSON, one request line, one response line. Max line 1 MiB (same as today’s hook payload cap).

Request:

```json
{
  "v": 1,
  "id": 1,
  "method": "hook",
  "bin": "<realpath of client ryk>",
  "version": "<ryk version>",
  "host": "grok",
  "event": "PreToolUse",
  "ci": false,
  "probe": false,
  "workspace": "/Users/you/proj",
  "cwd": "/Users/you/proj",
  "session_id": "optional",
  "payload": { }
}
```

`method` is `hook`, `evaluate`, or `ping`. `evaluate` is the Pi / machine API. `ping` is version + ready.

Response:

```json
{
  "v": 1,
  "id": 1,
  "exit": 0,
  "stdout": "{\"decision\":\"allow\",...}",
  "stderr": ""
}
```

The server formats the host wire (Claude `permissionDecision`, Grok deny JSON, Codex exit 2 + sentinel, Cursor bare JSON, Pi evaluate JSON). The client only copies bytes and exits. That keeps `hook.zig` as the single formatter.

Handshake failures (version mismatch, `bin` realpath mismatch, protocol `v` ≠ 1): client does **not** use the server. It evaluates in-process and may ask that server to exit so the next spawn is the matching binary.

---

## Lifecycle

**Start (lazy, no `ryk start` required).** First `ryk hook` / `ryk evaluate` / bare Cursor entry:

1. Connect to `$XDG_RUNTIME_DIR/ryk/hook-<binhash>.sock` (macOS: `$TMPDIR/ryk-<uid>/hook-<binhash>.sock` if runtime dir is missing).
2. On connect failure: spawn `ryk hook-serve --socket <path>` detached, wait up to 200ms for the socket, ping.
3. Still down: in-process evaluate (today’s path). Fail closed. Never fail open.

Launch aliases (`ryk grok`, `ryk claude`, …) and `ryk start` may prewarm the same server so the first tool is already warm. Prewarm is an optimization, not a requirement.

**Stop.** Idle 30 minutes after the last request → process exits. Next hook respawns once (~30ms) then is warm again. `ryk shutdown` / `ryk stop` sends `method: "shutdown"` if a server is up. Do not keep a machine-wide launchd/systemd unit in v1.

**Crash / stale socket.** Client connect timeout or broken pipe → unlink stale sock if the peer pid is gone → in-process or respawn. Evaluate timeout (2s) → fail-closed host deny, not allow.

**Env escape.** `RYK_HOOK_SERVER=0` forces in-process (CI, tests, debugging).

---

## Cases the design must survive

### Several agents at once

Claude in one repo, Grok in another, Codex in the first. One server. Concurrent accepts. Evaluate under a mutex in v1 (warm evaluate is well under 1ms; lock wait is cheaper than a process). Later: per-workspace locks if a profile shows contention.

### Several workspaces

`cache` key = realpath(workspace) + policy file mtime + pack-config mtime. A write to `.ryk/policy.yaml` is visible on the next request. Cap at 16 workspace entries, evict LRU, so a long-lived server cannot grow without bound.

### Session sticky

Today sticky is “this process,” so Grok never keeps session sticky (new process per tool). The server keys sticky by `session_id` (host payload or launch session). That is a behavior improvement, not a silent policy weaken: YOLO / sticky still cannot unlock a critical deny. Document it. Cap the session map.

`--probe` and install smokes must not mint allow-once codes (already true; the server must pass `probe` through).

### Allow-once and allowlists

Stay file-backed with the existing locks. The server is another reader/writer, not a new store. Consume still requires an OS-sandbox-active session (`ryk run`); hook-only stays `allow_once_path = null`.

### OS sandbox

Host hooks are spawned by Claude/Codex/Grok **outside** the agent Seatbelt/Landlock. They can reach a user runtime socket. In-sandbox **shims** do not use this server in v1 — they keep in-process evaluate. If a future hook runs inside the sandbox, grant the socket path or fall back in-process.

### Windows

v1: named pipe `\\.\pipe\ryk-hook-<uid>-<binhash>` **or** in-process fallback if the pipe work slips. Do not block Mac/Linux on Windows. Doctor tells the truth.

### CI and tests

`test-hooks` / host matrix stay in-process unless a test sets a private socket. `--ci` is a request flag; the server applies it. No `elapsed <= 5ms` CI assertion (that lie was dropped in #164).

### Binary upgrade

Homebrew upgrades `ryk` while a server from the old inode is still up. Client realpath/version mismatch → in-process + shutdown of the old server. Next hook starts the new one.

### Telemetry and feeds

Production `spawnBatch` of a second `ryk` on every hook is on the critical path today. The server appends feed lines and queues telemetry **after** the response. Hook-path `fsync` goes away; `ryk run` audit `fsync` stays.

### Failure modes (never allow)

| Failure | Outcome |
| --- | --- |
| No socket, spawn failed | In-process evaluate |
| Socket up, version/bin mismatch | In-process; ask old server to exit |
| Server dies mid-request | Fail-closed deny for that event |
| Payload too large / bad JSON | Same fail-closed JSON as today |
| Policy load error | Fail-closed (Codex informational still discovers policy) |

---

## Command surface

Invisible on the default `ryk` help. Named, honest, machine-friendly:

| Command | Who calls it |
| --- | --- |
| `ryk hook …` / `ryk evaluate` / bare `ryk` | Hosts (unchanged argv). Try server, else in-process. |
| `ryk hook-serve` | Spawned by the client or a launch alias. Not a second binary. |
| `ryk doctor` | `hook server: running` / `not running` + socket path. |
| `ryk shutdown` | Stops this server if present. Keep existing copy; do not revive Rust daemon ads. |

`verify-release.sh` continues to forbid an archive member named `ryk-daemon`.

---

Task-level implementation steps live in [`zig-hook-daemon-plan.md`](zig-hook-daemon-plan.md).

## Implementation order

Do not land a 5ms SLA. Land a server that is correct, then fast.

### Phase A — I/O off the in-process return path

Still needed as the fallback, and it makes the first cold spawn less ugly.

- Hook feed: write + flush, no `file.sync`. Keep fsync on `ryk run` audit.
- Do not rewrite `workspaces.json` on every allow.
- Named `ryk hook`: do not `spawnBatch` a second ryk.
- `RYK_HOOK_PROFILE=1` prints stage timings on stderr.

Files: `src/cli/feed_writer.zig`, `src/cli/hook.zig`, `src/telemetry.zig`, `src/main.zig`.

### Phase B — Server + thin client (the speed win)

- New `src/cli/hook_serve.zig`: accept loop, ping, hook, evaluate, shutdown, idle exit.
- Reuse `src/cli/daemon_uds.zig` (raise listen backlog; today’s `listen(1)` cannot fan in).
- Do not reuse Rust `ryk-uds-v1` methods (`Ping` / `Evaluate` / `ExecuteCli`). New protocol label: `ryk-hook-v1`.
- `hook.command` / `evaluate` / `agent_hook.command`: try client, else current code.
- Workspace cache + session sticky map with caps.
- Respond, then feed.

Files: `src/cli/hook_serve.zig`, `src/cli/hook_client.zig`, `src/cli/hook.zig`, `src/cli/evaluate.zig`, `src/cli/agent_hook.zig`, `src/cli/mod.zig`, `src/cli/host_launch.zig`, `src/cli/doctor.zig`.

### Phase C — Hosts + doctor + docs

- Claude / Codex / Grok / plugin argv stay the same (already `ryk hook …`).
- Pi `evaluate` and Cursor bare stdin use the same client.
- Doctor line for server state.
- Docs: this file + a short note on `docs/cli-reference.md` and `docs/compatibility.md`.

### Phase D — Optional later

- Per-workspace evaluate locks.
- Precompiled default-pack blob (skip gzip scan on server start).
- Honor Grok `workspaceRoot` instead of walking from `"."`.
- Windows named pipe if v1 shipped in-process there.
- Drop the daemon JSON round-trip inside `shell_eval` (`synthesizeDaemonResponseFromZig`).

---

## Tests (must exist before calling it done)

- In-process fallback: socket missing → same Claude / Codex / Grok / Cursor / Pi fixtures as `tests/hook_host_matrix.zig`.
- Server path: private socket, two hosts (e.g. grok allow + claude deny) against one server process; decisions match in-process.
- Two workspaces: strict vs ask, no cross-talk.
- Version / bin mismatch → in-process, not the other binary’s decision.
- Server kill mid-request → deny / exit 2, not allow.
- `--probe` does not write allow-once.
- `RYK_HOOK_SERVER=0` never connects.
- Release / install contracts still reject a `ryk-daemon` artifact.
- No `elapsed <= 5ms` assertion.

Manual Mac check: `RYK_HOOK_PROFILE=1 ryk hook grok PreToolUse` before and after the server is up. Warm server p50 under 5ms is the product bar; CI does not encode that number.

---

## Non-goals

- Bringing back Rust `ryk-daemon`, `RYK_DAEMON`, or `ExecuteCli`.
- Shipping a second PATH binary.
- FM steward on the hook path (classify budget is seconds).
- Making hook enforcement replace `ryk run` / OS sandbox.
- A machine-wide privileged service.

---

## Naming

Call it the **hook server** in user copy (`ryk doctor`, this doc). Internal command: `hook-serve`. Never `ryk-daemon` on disk.

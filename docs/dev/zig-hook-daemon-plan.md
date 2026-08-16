# Zig Hook Server Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a per-user Zig hook server inside `bin/ryk` so Claude, Codex, Grok, Cursor, Pi, and the other hook hosts share one warm process and return host decisions in a few milliseconds.

**Architecture:** Hosts keep spawning `ryk hook` / `ryk evaluate` / bare `ryk`. Those commands become a thin UDS client. `ryk hook-serve` accepts many hosts and workspaces, caches policy by workspace mtime, formats the existing host wire in `hook.zig`, and writes feeds after the response. Socket missing or version mismatch falls back to today’s in-process path and fail-closes. Full design: [`zig-hook-daemon.md`](zig-hook-daemon.md).

**Tech Stack:** Zig 0.16.0 (`./scripts/zig`), existing `src/cli/daemon_uds.zig`, `src/cli/hook.zig`, `src/shell_engine`, NDJSON over a user-only Unix socket (Windows named pipe or in-process in v1).

## Global Constraints

- One `bin/ryk`. Never ship or name an archive member `ryk-daemon`.
- Not the removed Rust daemon. New protocol label `ryk-hook-v1` (do not reuse `Ping` / `Evaluate` / `ExecuteCli`).
- One server per UNIX user + ryk binary realpath. Many hosts and workspaces on that server.
- Fail closed. Socket down, timeout, or crash must not become allow.
- `RYK_HOOK_SERVER=0` forces in-process.
- No `elapsed <= 5ms` CI assertion.
- Hook-only sessions still do not consume `allow_once.jsonl` unless OS sandbox is active.
- `--probe` must not mint allow-once codes.
- FM steward stays off on the hook path.
- Listen backlog must be > 1 (today `bindListenUnixSocket` uses `listen(1)`).

---

### Task 1: Protocol types and socket path

**Files:**
- Create: `src/cli/hook_ipc.zig`
- Modify: `src/cli/mod.zig` (pull tests)
- Test: `src/cli/hook_ipc.zig` (inline tests)

**Interfaces:**
- Produces: `pub const protocol_label = "ryk-hook-v1"`
- Produces: `pub const Request` / `pub const Response` matching `docs/dev/zig-hook-daemon.md`
- Produces: `pub fn socketPathAlloc(allocator, uid, bin_realpath) ![]u8`
- Produces: `pub fn binHash(realpath: []const u8) [8]u8` (first 8 hex of sha256)

- [ ] **Step 1: Write failing tests** for empty realpath, overlong path, and hash stability.

```zig
test "socketPathAlloc includes uid and bin hash" {
    const path = try socketPathAlloc(std.testing.allocator, 501, "/usr/local/bin/ryk");
    defer std.testing.allocator.free(path);
    try std.testing.expect(std.mem.indexOf(u8, path, "hook-") != null);
    try std.testing.expect(std.mem.indexOf(u8, path, "ryk-daemon") == null);
}

test "binHash is stable for the same realpath" {
    const a = binHash("/usr/local/bin/ryk");
    const b = binHash("/usr/local/bin/ryk");
    try std.testing.expectEqualSlices(u8, &a, &b);
}
```

- [ ] **Step 2: Run** `./scripts/zig build test-lib -Dtest-filter=socketPathAlloc` — expect fail (type missing).
- [ ] **Step 3: Implement** path = `$XDG_RUNTIME_DIR/ryk/hook-<hex>.sock` or `$TMPDIR/ryk-<uid>/hook-<hex>.sock`. Reject empty realpath.
- [ ] **Step 4: Re-run the filter** — expect pass.
- [ ] **Step 5: Commit** `feat(hook): add ryk-hook-v1 ipc types and socket path`

---

### Task 2: Raise UDS listen backlog

**Files:**
- Modify: `src/cli/daemon_uds.zig` (`bindListenUnixSocket`)
- Test: existing `src/cli/daemon_uds.zig` tests plus a backlog argument

**Interfaces:**
- Produces: `pub fn bindListenUnixSocket(path: []const u8, backlog: u31) !std.posix.fd_t`
- Default backlog for hook-serve: `128`

- [ ] **Step 1: Add a test** that `bindListenUnixSocket` accepts a backlog and still rejects empty paths.
- [ ] **Step 2: Change the listen call** from `listen(fd, 1)` to the argument. Update current callers to pass `1` or `128` as appropriate so Rust-legacy tests keep compiling.
- [ ] **Step 3: Run** `./scripts/zig build test-lib -Dtest-filter=sockaddrUnFromPath`
- [ ] **Step 4: Commit** `fix(uds): allow listen backlog above 1 for hook-serve`

---

### Task 3: In-process fallback I/O (Phase A)

**Files:**
- Modify: `src/cli/feed_writer.zig` (`appendRecordAtPath`)
- Modify: `src/cli/feed_writer.zig` (`appendGlobalRecord` / `updateWorkspaceRegistry`)
- Modify: `src/telemetry.zig` (`recordInvocationInner` / `spawnBatch`)
- Test: `src/cli/feed_writer.zig` tests; `src/telemetry.zig` `isHookHotPath` tests

**Interfaces:**
- Produces: `appendRecordAtPath(..., sync: bool)` or `appendRecordBestEffort` skips `file.sync` when caller is hook
- Produces: hook path does not call `spawnBatch`

- [ ] **Step 1: Test** that a hook-originated feed append does not require a successful `sync` (inject a writer flag or count).
- [ ] **Step 2: Skip `file.sync`** on hook/evaluate feed appends only. Keep sync for `ryk run` audit writers.
- [ ] **Step 3: Skip `updateWorkspaceRegistry`** on hook allow.
- [ ] **Step 4: In `recordInvocationInner`**, if `isHookHotPath(argv)` return before `spawnBatch` (summaries may still be dropped or written to a queue file without a child).
- [ ] **Step 5: Run** `./scripts/zig build test-hooks` (or the narrowest slice that covers feed + hook).
- [ ] **Step 6: Commit** `perf(hook): keep feed and telemetry off the hook return path`

---

### Task 4: hook-serve accept loop

**Files:**
- Create: `src/cli/hook_serve.zig`
- Modify: `src/cli/mod.zig` (dispatch `hook-serve`, skip banner)
- Modify: `src/cli/help.zig` (hidden or `--help` only, not default help)
- Test: `src/cli/hook_serve.zig`

**Interfaces:**
- Produces: `pub fn command(io, argv, stdout, stderr) !u8`
- Produces: `ryk hook-serve --socket <path>` binds, pings, idle-exits after 30 minutes
- Consumes: `hook_ipc.Request` / `Response`, `daemon_uds.bindListenUnixSocket(path, 128)`

- [ ] **Step 1: Test** ping: start serve on a temp socket in a thread, client sends `{"v":1,"id":1,"method":"ping"}`, reads `exit:0`.
- [ ] **Step 2: Implement** bind, accept, one-line NDJSON, ping, shutdown, idle timer.
- [ ] **Step 3: Test** stale socket: bind after an orphan sock file (unlink + listen).
- [ ] **Step 4: Test** `method: shutdown` exits 0 and unlinks the socket.
- [ ] **Step 5: Run** `./scripts/zig build test-lib -Dtest-filter=hook-serve`
- [ ] **Step 6: Commit** `feat(hook): add ryk hook-serve ping and idle exit`

---

### Task 5: Server evaluates through existing hook.zig

**Files:**
- Modify: `src/cli/hook_serve.zig`
- Modify: `src/cli/hook.zig` (extract a function the server can call with a parsed payload, not stdin)
- Test: `tests/hook_host_matrix.zig` fixtures reused against the server

**Interfaces:**
- Consumes: `hook.evaluateForServer(io, allocator, host, event, payload, ci, probe) !HostEmit`
- Produces: `HostEmit { exit: u8, stdout: []u8, stderr: []u8 }`

- [ ] **Step 1: Extract** stdin-free evaluate from `hookCommand` so tests and the server share it. Do not duplicate Grok/Claude formatters.
- [ ] **Step 2: Failing test:** server + grok safe fixture → exit 0 and allow-shaped stdout; danger → exit 2.
- [ ] **Step 3: Failing test:** one server, grok allow then claude deny, no restart.
- [ ] **Step 4: Implement** `method: "hook"` and `method: "evaluate"` on the server.
- [ ] **Step 5: Workspace cache** keyed by realpath + mtime; cap 16.
- [ ] **Step 6: Run** a new `tests/hook_server.zig` plus existing matrix in-process (must still pass).
- [ ] **Step 7: Commit** `feat(hook): serve grok and claude decisions from one process`

---

### Task 6: Thin client on hook / evaluate / bare ryk

**Files:**
- Create: `src/cli/hook_client.zig`
- Modify: `src/cli/hook.zig` (`command`)
- Modify: `src/cli/evaluate.zig`
- Modify: `src/cli/agent_hook.zig`
- Modify: `src/main.zig` (keep hook hot-path allocator)
- Test: `src/cli/hook_client.zig`; `tests/hook_host_matrix.zig`

**Interfaces:**
- Produces: `pub fn tryServe(io, allocator, request) error{Unavailable}!Response`
- Produces: connect timeout ~50ms, request timeout 2s
- On `Unavailable` or mismatch: in-process, never allow-on-error

- [ ] **Step 1: Test** `RYK_HOOK_SERVER=0` never opens a socket (env in the test).
- [ ] **Step 2: Test** missing socket → `error.Unavailable` (no hang).
- [ ] **Step 3: Test** version/bin mismatch → `Unavailable` and client may send shutdown.
- [ ] **Step 4: Wire** `hook.command` / `evaluate` / `agent_hook.command` to tryServe then existing code.
- [ ] **Step 5: Lazy spawn** `ryk hook-serve --socket …` once, wait ≤200ms, ping, else in-process.
- [ ] **Step 6: Run** `./scripts/zig build test-hooks`
- [ ] **Step 7: Commit** `feat(hook): thin client with in-process fallback`

---

### Task 7: Isolation and fail-closed cases

**Files:**
- Test: `tests/hook_server.zig`
- Modify: `src/cli/hook_serve.zig` (session sticky map cap, probe flag)

- [ ] **Step 1: Test** two temp workspaces, different `policy.yaml` modes; requests must not share a cached policy.
- [ ] **Step 2: Test** kill server after accept, before response → client fail-closed deny.
- [ ] **Step 3: Test** `--probe` / `"probe": true` does not create allow-once files.
- [ ] **Step 4: Test** extra-pack workspace still fail-closes on bad pack config.
- [ ] **Step 5: Commit** `test(hook): server isolation and fail-closed cases`

---

### Task 8: Doctor, shutdown, launch prewarm, docs

**Files:**
- Modify: `src/cli/doctor.zig`
- Modify: `src/cli/shutdown.zig` (stop hook-serve if the Rust path is a stub)
- Modify: `src/cli/host_launch.zig` (best-effort prewarm, do not block launch)
- Modify: `docs/cli-reference.md`
- Modify: `docs/compatibility.md` (one line: hook server is best-effort speed, not a new enforcement grade)
- Keep: `docs/dev/zig-hook-daemon.md` as the design

- [ ] **Step 1: Doctor** prints `hook server: running` or `not running` and the socket path. No SHIELD wall.
- [ ] **Step 2: `ryk shutdown`** sends hook-serve shutdown when the socket exists.
- [ ] **Step 3: Launch aliases** spawn hook-serve in the background if the socket is down. Launch must still reach the agent if prewarm fails.
- [ ] **Step 4: Lock tests** still forbid `ryk-daemon` in release archives (`scripts/verify-release.sh` unchanged).
- [ ] **Step 5: Run** `./scripts/test-fast.sh` (or the docs + doctor slices plus `test-hooks`).
- [ ] **Step 6: Commit** `feat(hook): doctor and launch prewarm for hook-serve`

---

## Manual Mac bar (not CI)

```sh
# cold / fallback
RYK_HOOK_SERVER=0 RYK_HOOK_PROFILE=1 ./zig-out/bin/ryk hook grok PreToolUse < tests/plugin-fixtures/grok/pre_tool_use_command_safe.json

# warm server
./zig-out/bin/ryk hook-serve --socket /tmp/ryk-hook-test.sock &
RYK_HOOK_SOCKET=/tmp/ryk-hook-test.sock RYK_HOOK_PROFILE=1 ./zig-out/bin/ryk hook grok PreToolUse < tests/plugin-fixtures/grok/pre_tool_use_command_safe.json
```

Warm p50 under 5ms on Mac is the product bar. Repeat with Claude and Codex fixtures and a second workspace in parallel.

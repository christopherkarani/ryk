# ryk for Pi

The official Pi integration for ryk protects Pi tool calls before they run.
It is installed automatically by `ryk` onboarding; no npm command or additional
Pi setup is required.

## Protection coverage

| Tool | Enforcement |
|------|-------------|
| `bash` | `ryk evaluate --json --stdin`; failures block by default |
| `write` / `edit` | `ryk decide file` with `operation: write` |
| `read` | `ryk decide file` with `operation: read` |
| `grep` / `find` / `ls` | Root preflight via `ryk decide file` (same as read). Residual ask is permit. |
| `contact_supervisor` / `intercom` / `subagent` | Passthrough (no name-gate) |
| Other custom tool names | `ryk decide tool` name gate |

The extension also detects secret-like values in interactive prompts. With user
consent it stores them in the compatibility credential broker path
`.ryk/dev-secrets.env` using mode `0600`, then replaces the raw value with an
environment-variable reference before the model sees the message.

## Runtime behavior

- The generated Pi wrapper contains the absolute path of the installed `ryk`
  executable. Pi protection does not depend on PATH or shell profile activation.
- The bundled runtime fails closed when `ryk` is unavailable, returns malformed
  output, or times out.
- `/ryk-setup`, `/ryk-start`, `/ryk-stop`, `/ryk-doctor`, and `/ryk-mode`
  manage the current Pi integration.
- Residual policy `ask` is permit so coding agents can work. ryk only
  hard-stops explicit deny. Set `RYK_UNATTENDED=1` (or `CI` / `RYK_CI` /
  `RYK_NONINTERACTIVE`) to auto-deny residual ask. `RYK_PI_MODE=strict`
  fail-closes protocol/eval failures; it does not turn residual ask into deny.
- Process-level environment, network, and secretless controls require launching
  Pi through `ryk run -- pi`.

### Policy `ask` session matrix

When `ryk evaluate` / `ryk decide` returns policy **`ask`**, residual ask is
permit unless the operator set an unattended flag:

| Session class | Detection | Policy `ask` outcome |
|---------------|-----------|----------------------|
| Attended (interactive, print, subagent) | no `RYK_UNATTENDED` / `CI` / `RYK_CI` | **Permit** — ryk only hard-stops explicit deny |
| Unattended | `RYK_UNATTENDED`, `CI`, `RYK_CI`, or `RYK_NONINTERACTIVE` | **Auto-deny** with explicit reason |
| Strict | `RYK_PI_MODE=strict` | Protocol/eval failure fail-closes. Residual policy ask still permits unless unattended. |

### Protocol failure recovery

When `ryk evaluate` / `ryk decide` fails (timeout, malformed JSON, spawn error):

| Session | Outcome |
|---------|---------|
| Any session (including interactive / subagent) | Fail-closed **block** (short reason + `/ryk-doctor`). No recovery ask. |
| After sticky block | Further protocol errors auto-block without another prompt |

Card copy stays short (`Fail-closed. /ryk-doctor`).

Decision cards use a borderless layout (`RYKAN V · Blocked`) with Why / Cmd /
Meta / Next rows. They must return a TUI component from
`registerMessageRenderer` (`{ render(width) }`), not a colored string — a
string crashes Pi with `child.render is not a function`. After updating
ryk-pi, run `ryk doctor --fix` so `~/.pi/agent/extensions/ryk/runtime.ts` is
replaced.

Parent-ask IPC mkdir is best-effort. Under an attached OS sandbox, creating
`~/.local/state/ryk/pi-ask/<session>` can EPERM; the extension must not throw.

Auto-deny records a transcript audit event (`ryk_ask_auto_deny`) when the host
supports `sendMessage`, and still blocks if audit is unavailable. Protocol
recovery does not prompt. There is no host ask UI for residual policy ask.

## Security properties

- Child processes use argv arrays with `shell: false`.
- Evaluation requests are sent through stdin.
- Child output is bounded before parsing.
- Malformed tool payloads block.
- Credential files are written atomically and symlinked paths are rejected.
- Session bypass is not persisted and requires an explicit user choice.
- Tool hooks do not claim process-level network or environment isolation.

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
| `grep` / `find` / `ls` | Root preflight plus explicit approval |
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
- `RYK_PI_MODE=auto` is the default: interactive sessions ask; noninteractive
  sessions block. Use `RYK_PI_MODE=strict` for the strongest fail-closed posture.
- Process-level environment, network, and secretless controls require launching
  Pi through `ryk run -- pi`.

### Policy `ask` session matrix

When `ryk evaluate` / `ryk decide` returns policy **`ask`**, the extension
never silently allows the tool call:

| Session class | Detection | Policy `ask` outcome |
|---------------|-----------|----------------------|
| Interactive parent TUI | `hasUI === true` and mode not `print` / `json` / `noninteractive` | Human prompt (`select`) — once / Block / session disable / show reason |
| Noninteractive Pi (`-p`, print, json, headless) | `hasUI !== true` or mode is `print` / `json` / `noninteractive` | **Auto-deny** with explicit reason; no UI hang |
| Subagent / child agent | `PI_SUBAGENT_PARENT_SESSION` set (non-empty) | **Parent-forward ask** (file IPC); timeout / missing parent → **deny** |
| Strict / noninteractive-block | `RYK_PI_MODE=strict` (or once-bypass disabled) | Block; no once-bypass option on interactive ask |

### Protocol failure recovery

When `ryk evaluate` / `ryk decide` fails (timeout, malformed JSON, spawn error):

| Session | Outcome |
|---------|---------|
| Interactive parent | One recovery prompt: **Allow for this session**, allow once, **Block** (sticky for session) |
| After sticky block | Further protocol errors auto-block without another prompt |
| Subagent | Parent-forward recovery (same IPC as policy ask); parent block sticks on that child |
| Noninteractive / strict | Fail-closed block (short reason + `/ryk-doctor`) |

Card copy stays short (`Fail-closed. /ryk-doctor`).

Decision cards use a borderless Vercel-style layout (`RYKAN V · Blocked`) and
render through Pi theme tokens plus optional `pi-tui` `Box`/`Text` (padding only,
no filled panel). They must return a TUI component from `registerMessageRenderer`
(`{ render(width) }`), not a colored string — a string crashes Pi with
`child.render is not a function`. After updating ryk-pi, run `ryk doctor --fix`
so `~/.pi/agent/extensions/ryk/runtime.ts` is replaced.

Parent-ask IPC mkdir is best-effort. Under an attached OS sandbox, creating
`~/.local/state/ryk/pi-ask/<session>` can EPERM; the extension must not throw.
Main-TUI ask/block still works. Subagent parent-forward stays fail-closed if
the IPC dir cannot be created.

Auto-deny records a transcript audit event (`ryk_ask_auto_deny`) when the host
supports `sendMessage`, and still blocks if audit is unavailable. Subagent policy
`ask` and protocol recovery are forwarded to the parent via file IPC
(`RYK_PI_ASK_ROOT` / XDG runtime); the parent ryk extension must be loaded.
Timeout or missing parent fails closed. Session tool grants
(`Allow this tool for this Pi session`) inherit to children via `grants.json`
under the parent session id.

## Security properties

- Child processes use argv arrays with `shell: false`.
- Evaluation requests are sent through stdin.
- Child output is bounded before parsing.
- Malformed tool payloads block.
- Credential files are written atomically and symlinked paths are rejected.
- Session bypass is not persisted and requires an explicit user choice.
- Tool hooks do not claim process-level network or environment isolation.

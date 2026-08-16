# Threat model

Guarantees depend on how the agent was launched and which enforcement surfaces are active on that host.

## Assets

- Environment variables passed to agent processes.
- Secret-like values before they reach persistent logs.
- Protected paths such as `.env`, SSH keys, cloud credentials, and browser credential stores.
- Writes, commands, network requests, and MCP messages that pass through ryk.
- Audit records produced by ryk-managed sessions.

## Threat actors

- Prompt-injected agents.
- Malicious repository content that asks an agent to expose secrets or weaken policy.
- Untrusted MCP servers and tool metadata.
- Local automation launched through a protected session.

## Trust boundaries

- The user and local operating system launch ryk intentionally.
- Child processes, prompts, tool calls, and MCP payloads are untrusted.
- Policy files are trusted only after validation.
- Audit files are treated as untrusted input during replay and verification.

## Assumptions

- The agent is launched through ryk when process-level protection is required.
- The user does not approve an unsafe action deliberately.
- The host can write ryk audit data in the selected workspace.
- Platform capability reports are checked with `ryk doctor`.

## Non-goals

ryk does not promise perfect sandboxing, protection outside ryk-launched sessions, or defense against root, administrator, kernel, or host compromise. It cannot guarantee transparent network enforcement or transparent filesystem enforcement on a platform where the active backend does not provide those controls.

## Protection grades

Wrapper, hook, proxy, and OS controls are different surfaces. `ryk doctor` reports capability and readiness; it does not prove that a particular child session attached to an OS sandbox.

The public grades are:

- `hook`: host hook evaluation only.
- `wrapper`: the host runs as a ryk-managed child process.
- `proxy`: traffic through a ryk proxy is evaluated.
- `OS-enforced`: the host-specific operating-system backend attached successfully.

Use the [compatibility matrix](compatibility.md) for platform details and residuals.

## Fail-closed behavior

Strict and CI modes reject invalid policies, malformed untrusted input, unsupported approval paths, and missing backend features when the selected surface requires them. A hook cannot protect an event that the host never sends.

## Known bypasses

- An agent launched outside ryk is outside ryk's process boundary.
- A command or network request that bypasses the active hook, wrapper, or proxy is outside that surface.
- Privileged users can bypass user-space controls.
- A user can approve an unsafe action.
- A host can treat hook output as advisory rather than blocking.
- A local actor who rewrites both the audit event log and the session summary can produce a new internally consistent hash chain. Detecting that rewrite is out of scope; copy the printed session-end chain hash out of band if you need an external check.
- Product evaluate realpaths `XDG_CONFIG_HOME` / `HOME` before loading user `allowlist.toml` and skips a candidate under the workspace (unresolved paths are treated as inside). An existing joined `allowlist.toml` or its parent is also realpath'd so `$XDG/ryk` cannot symlink into the workspace. Poisoned XDG falls back to HOME only if HOME is outside the workspace; if both are poisoned there is no user store. Allow-once remains gated by the caller OS-sandbox flag (no HOME write-probe).

For implementation-specific residuals, read the platform notes and run `ryk doctor` on the machine that will run the agent.

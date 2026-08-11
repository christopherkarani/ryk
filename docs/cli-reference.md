# ryk CLI reference

This is the command reference for the current Zig CLI. It covers commands that a user or an integration can invoke, the boundaries between those commands, and the behavior verified in the working tree.

The page was checked on 2026-08-08 against Zig 0.16.0 and a locally built `./zig-out/bin/ryk` binary. Outputs that depend on local policy, installed hosts, sessions, or daemon state are described without copying local identifiers. Run `ryk version` to confirm the installed release version.

The primary sources are the [CLI dispatcher](../src/cli/mod.zig), [help declarations](../src/cli/help.zig), [run path](../src/cli/run.zig), [exit-code registry](../src/cli/exit_codes.zig), and the command implementations under src/cli/. The commands and examples below were cross-checked against those sources and manual probes. This page does not turn a capability report into a protection guarantee.

## Read the live contract first

Use the binary that matches the installation you are documenting:

~~~sh
# From a source checkout
./scripts/zig version
./scripts/zig build
./zig-out/bin/ryk help

# From an installed release
ryk version
ryk help
~~~

The CLI itself is the final authority for flags and host-specific events:

~~~sh
ryk help
ryk help --all
ryk help <command>
~~~

ryk help shows the Safe Launch surface. ryk help --all includes advanced commands. Hidden entries in the source are not a promise that the corresponding implementation is available.

## The first-run path

For a new workspace, use the single onboarding command:

~~~sh
ryk start
~~~

start creates a policy when one is missing, uses Ask posture by default, selects detected hosts, and verifies available integration paths. It can change local policy and host configuration. The non-interactive forms are:

~~~sh
ryk start --auto
ryk start --auto --hosts codex,claude
ryk start --auto --preset <name>
~~~

Use --yes or --no-interact when a caller needs the compatibility spelling for non-interactive mode. --skip-verify skips the verification phase and should be reserved for a caller that performs an equivalent check itself.

After setup:

~~~sh
ryk doctor
ryk doctor --check
ryk replay --session last --verify
~~~

doctor reports readiness and host capabilities. doctor --check is the automation gate and returns nonzero when core readiness fails. doctor --json is a small readiness document, but a JSON result with ready: false can still exit zero. Use --check when the process exit status is the gate. doctor --fix is a mutating repair path and cannot be combined with --check or --json.

Use init when you need to create a policy without the guided host setup:

~~~sh
ryk init --preset generic-agent
ryk policy check
~~~

init writes .ryk/policy.yaml and may update the mapped pack configuration. It refuses to overwrite an existing policy unless --force is supplied. policy check without a path checks the workspace policy, not a built-in preset. Use ryk policy check --preset strict or ryk policy check builtin:strict for a built-in preset.

env prints shell exports for the active CLI layout:

~~~sh
eval "$(ryk env)"
~~~

The output contains PATH and RYK_RESOURCE_ROOT exports. Review generated shell text before evaluating it in a different environment.

The top-level --print-install-env route emits the same activation exports for installer and wrapper callers. The source also contains an env schema route, but env schema --agent requires a workspace .ryk/env.schema.yaml; the checked workspace returned not found.

## Command inventory

| Area | Commands | Purpose |
| --- | --- | --- |
| Help and setup | help, version, env, start, init, doctor, completions, update | Discover, configure, inspect, and update the CLI |
| Session enforcement | run, claude, codex, pi, opencode, openclaw, hermes, grok | Run a child process or a supported host under ryk |
| Shell decisions | test, explain, packs, allowlist, allow, unallow, allow-once, policy | Inspect or change shell and policy decisions |
| Evidence | replay, report, scan, diff, apply, discard | Inspect sessions, findings, and staged file changes |
| Integrations | plugin, hook, evaluate, decide, mcp, tools, credentials | Connect host events and machine callers to ryk |
| Operations | dashboard, ci, redteam, telemetry, stop, disable, shutdown, uninstall | Operate, verify, disable, or remove local integrations |

The inventory describes the public working surface. ryk help <command> remains the authoritative usage string for each entry.

## Output and exit status

Use --no-rich or RYK_NO_RICH=1 when a command is being consumed by a script or a terminal cannot render the rich presentation. --json is a per-command option, not a universal output switch. Check the subcommand help before parsing JSON. The -- separator ends ryk option parsing and passes the remaining arguments to the child.

The useful decision statuses are not uniform across commands:

| Command or path | Allow or success | Deny or non-success |
| --- | --- | --- |
| explain | 0 | The command is informational, so an explained deny also returns 0 |
| test | 0 | 2 for a denied command |
| run | The child exit code when the child exits normally | 3 for a ryk denial; signal and supervision failures use the CLI failure paths |
| decide | 0 for allow | 3 block, 7 ask, 8 warn |
| evaluate | 0 allow | 2 deny, 3 evaluator failure, 64 invalid input, 1 unexpected internal error |
| doctor --check | 0 when the readiness check passes | 1 when core readiness fails |

Usage errors normally return 2. Do not write an integration that treats every nonzero result as a policy deny. Read the JSON decision or the command-specific contract.

## Running commands and hosts

The general form is:

~~~sh
ryk run [options] -- <command> [args...]
~~~

The parser accepts these session modes for run: observe, ask, strict, and ci. It also accepts --ci as a shorthand for CI mode. Policy files support a larger set of preset and mode names, but those names are not all valid values for run --mode.

The important run options are:

~~~text
--workspace <path>
--mode observe|ask|strict|ci
--policy <path>
--session-name <name>
--no-secrets
--secretless
--with-host-secrets
--inherit-env
--no-network
--allow-network <domain-or-IP>
--network observe|ask|allowlist|open|off
--network-backend decision-only|proxy
--os-sandbox auto|on|off
--seatbelt-profile compatible|hardened|strict
--require-backend <capability>
~~~

The security-sensitive choices are explicit:

- --secretless selects an empty-backpack boundary and requires the OS sandbox path. It cannot be combined with --with-host-secrets.
- --with-host-secrets is an explicit escape. It warns and may expose host credentials to the child.
- --inherit-env is accepted only when the selected policy allows environment inheritance.
- --os-sandbox on fails closed when the platform backend cannot attach. --os-sandbox off disables the OS apply step and should be treated as a lower protection posture.
- --network open is an unrestricted-egress escape. --network-backend proxy adds a local proxy path; it does not mean that every network protocol is transparently intercepted.
- --require-backend turns a named capability into a launch requirement. Use it when a degraded session is not acceptable.

Host aliases are exact, case-sensitive rewrites to ryk run -- <host> ...:

| Alias | Child host |
| --- | --- |
| ryk claude | claude |
| ryk codex | codex |
| ryk pi | pi |
| ryk opencode | opencode |
| ryk openclaw | openclaw |
| ryk hermes | hermes |
| ryk grok | grok |

Arguments after an alias belong to the host process. Put ryk options before the command separator on run:

~~~sh
ryk run --network allowlist -- pi
~~~

The current launch-alias list does not contain cursor. Cursor integration is a hook/configuration path, not a ryk cursor launch command. stop has a separate cursor integration target.

The source-defined agent-primary defaults for these aliases are stricter than the generic ryk run -- <command> defaults: allowlisted network mode, proxy and route-forcing requirements where supported, and an empty-backpack boundary for trusted host binaries. The session banner and doctor report the posture actually selected. A host alias is not proof that the host hook or an OS sandbox attached.

## Shell decisions and safety packs

test evaluates a command without running it:

~~~sh
ryk test "git status"
ryk test --format json "rm -rf /"
~~~

explain provides the richer trace. It reports the decision, matching rule, pack, pattern, span, pipeline, and suggestions. It never executes the command:

~~~sh
ryk explain "git status"
ryk explain "rm -rf /"
ryk explain --format json "rm -rf /tmp/example"
~~~

explain and test use the in-process Zig shell_engine. The old Rust evaluator selection is not a supported path. Setting RYK_SHELL_EVAL=rust is rejected as an unsupported legacy evaluator selection. Some machine responses label that unavailable backend as daemon_unavailable; the setting does not switch authority away from Zig.

Safety packs are embedded Zig shell-engine rule sets. They are not the same thing as policy presets:

~~~sh
ryk packs --plain
ryk packs --json
ryk packs show core.git
ryk packs show core.git --verbose
ryk packs enable containers.docker
ryk packs disable containers.docker
~~~

List and show are read-only. Enable and disable write pack configuration. In a git workspace the project configuration is used; otherwise the user configuration is used. The inventory and enabled count are local state, so documentation and tests should not hard-code the count returned by packs.

Permanent exceptions are managed separately:

~~~sh
ryk allowlist list --plain
ryk allowlist validate --project
ryk allowlist add core.git:branch-force-delete -r "reason"
ryk allowlist remove core.git:branch-force-delete
~~~

Every permanent entry needs a reason. Project entries live under the workspace .ryk directory; user entries live under the user ryk configuration directory. Critical pack hits cannot be permanently unlocked. Use allow-once for a single approved action:

~~~sh
ryk allow-once list
ryk allow-once <short-code>
ryk allow-once clear
~~~

The add, remove, enable, disable, and redeem paths are state-changing operations. Non-interactive callers may need the explicit operator setting required by the local command contract.

## Policy commands

Policy rules and shell packs answer different questions. Use these commands for policy.yaml rules:

~~~sh
ryk policy check
ryk policy check --preset strict
ryk policy explain file.read /etc/passwd
ryk policy explain network https://example.invalid/path
ryk policy packs
ryk policy apply-pack strict-local --force
~~~

policy explain covers file, environment, network, MCP, tool, and command policy rules. explain covers shell-engine pack traces. tools classify covers effect-class tool matching.

## Session evidence and staged changes

replay reads stored audit artifacts. It does not re-run the child command:

~~~sh
ryk replay --list
ryk replay --session last
ryk replay --session last --verify
ryk replay --session last --only denied
~~~

--verify checks the session hash chain. report produces a summary and export:

~~~sh
ryk report --session last --format json
ryk report --session last --format markdown
~~~

The report includes denied actions, redactions, readiness information, and a prevention summary. Redaction is part of the report contract, but it does not make an unsafe session safe.

scan is bounded offline forensics over known host stores. It does not crawl the whole home directory. It reports risky command and secret-like patterns without printing raw secret values. A finding is a pattern match that needs review, not proof that a secret was exfiltrated:

~~~sh
ryk scan --days 7
ryk scan --plain --days 7
ryk scan --json --days 7
ryk scan --host claude --all
~~~

Successful scanning returns zero even when findings exist. Parse the findings instead of using the process status as a clean-session claim.

File changes that ryk staged for review use this sequence:

~~~sh
ryk diff --session last
ryk apply --session last --dry-run
ryk apply --session last --yes
ryk discard --session last --dry-run
ryk discard --session last --yes
~~~

Review with diff first. apply mutates the workspace after its checks. discard removes proposed staged changes and does not edit workspace files. In non-interactive use, --yes is required for the mutating paths.

## Machine integrations

### evaluate

evaluate is the stable stdin API for shell-command events. It requires a versioned request, a shell-command kind, a command string, and an absolute existing cwd:

~~~sh
ryk_cwd="$(pwd)"
printf '%s\n' "{\"schema_version\":1,\"kind\":\"shell_command\",\"command\":\"git status\",\"cwd\":\"$ryk_cwd\"}" |
  ryk evaluate --json --stdin
~~~

It writes its response to stdout for valid decisions and typed input errors. The tested exit contract is 0 allow, 2 deny, 3 evaluator failure, 64 invalid input, and 1 unexpected internal error. Non-shell evaluation is not supported by this API.

### decide

decide evaluates a host-plugin action. The verified inline form is safer for scripts than the current stdin path:

~~~sh
ryk decide command --json '{"command":"git status"}'
ryk decide file --json '{"path":"README.md","operation":"read"}'
ryk decide prompt --json '{"text":"Summarize this change"}'
ryk decide tool --json '{"name":"send_email"}'
~~~

The default output is stable JSON. --human adds a presentation layer. A command block returns 3; an ask returns 7; a warn returns 8. Permanent allowlist and allow-once stores are not loaded on this host-plugin path.

### hook

hook reads a host-specific event from stdin and emits the host-valid response on stdout. Supported host names are codex, claude, opencode, openclaw, hermes, and grok in the current implementation:

~~~sh
ryk hook claude PreToolUse < host-payload.json
ryk hook codex SessionStart < host-payload.json
ryk hook opencode tool.execute.before < host-payload.json
~~~

The payload schema belongs to the host. Use the host integration documentation to construct it. Hook responses include host_limitations; hook enforcement is additive and does not replace supervision through ryk run. Shell tool-before events use the Zig shell engine, and the rejected Rust evaluator setting applies here too. The public help registry currently omits the grok hook route, so validate that host path before relying on it.

### Plugins and MCP

Inspect integrations before changing them:

~~~sh
ryk plugin list
ryk plugin doctor --json
ryk plugin manifest all --json
ryk plugin install
~~~

Bare plugin install is a dry-run preview. An explicit host or all plus --yes is required for mutation. Managed host plugins are part of the release: `ryk plugin install`, `ryk doctor --fix`, and post-install/`ryk update` setup upgrade ryk-owned plugin files in place when bundled content differs (unsafe destinations still refuse). Plugin diagnostics do not print secrets.

MCP commands cover local stdio servers and manifests:

~~~sh
ryk mcp list
ryk mcp inspect --command <server-command>
ryk mcp proxy --command <server-command> --mode ask
ryk mcp trust <server> --tool <tool>
ryk mcp manifest check <manifest.yaml>
ryk mcp manifest generate --command <server-command>
~~~

Remote HTTP MCP, OAuth, and hosted gateway behavior is limited or deferred in the current CLI. Do not describe the stdio proxy as universal network interception.

tools and credentials are inspection commands:

~~~sh
ryk tools classify send_email
ryk tools classify notify --args '{"to":"a@b.com","body":"hi"}'
ryk tools packs
ryk credentials check
~~~

Tool classification reports effect IDs and matcher labels, not raw argument values. Credential checks report broker status without printing raw credentials.

## Operations and verification

The dashboard is local and loopback-only:

~~~sh
ryk dashboard --workspace .
ryk dashboard --workspace . --port 7742
ryk dashboard --workspace . --once
~~~

The default bind is 127.0.0.1:7742. Non-loopback binds are rejected. Mutation routes use a per-run browser token and fixed ryk actions. The dashboard calls existing CLI and core paths; it is not a separate policy evaluator.

ci runs local readiness checks:

~~~sh
ryk ci check
ryk ci check --format json
~~~

The check validates the local policy, rejects dangerous obvious defaults, and runs a focused CI-safe red-team fixture. redteam is narrower:

~~~sh
ryk redteam --ci
ryk redteam --ci --json
~~~

The red-team command runs deterministic built-in fixtures against builtin:redteam with in-process Zig evaluation. It does not load .ryk/policy.yaml, install hooks, execute real actions, or prove wrapper, host, proxy, or OS enforcement. A 100 percent fixture score is an engine result, not workspace assurance.

Telemetry is controlled locally:

~~~sh
ryk telemetry status --json
ryk telemetry disable
ryk telemetry enable
~~~

Read [telemetry.md](telemetry.md) for the current release-build privacy contract. RYK_NO_TELEMETRY=1 is the environment-level opt-out. Development builds may have transport disabled even when the local setting reports enabled.

Use these commands for lifecycle changes:

~~~sh
ryk stop
ryk stop codex
ryk shutdown
ryk uninstall --dry-run
ryk uninstall --plugins-only --yes
ryk update --check
~~~

stop removes host protection registrations without removing the ryk binary or policy. shutdown is an advanced background-service command. uninstall can remove the installation and user configuration; use --dry-run first. update --check performs a read-only release check, while an update can contact the release service and replace the installed binary; the official installer then refreshes managed host plugins via doctor --fix.

disable dispatches to the same implementation as stop and is retained as an accepted compatibility route. New integrations should use stop, which is the documented command.

## Removed and internal commands

The current dispatcher returns a usage error and points to the replacement for these removed onboarding commands:

~~~text
ryk quickstart  -> ryk start
ryk setup       -> ryk start
ryk status      -> ryk doctor
~~~

The source help metadata still contains historical entries for history, precommit, classify, suggest-allowlist, simulate, rebase-recover, and config, but the current dispatcher routes them to unavailable stubs. Do not build new automation around them. shim is an internal callback for session-local PATH shims and is not a user entry point.

## Security boundaries to keep in every explanation

Ryk mediates the paths that actually enter its policy, shell, hook, proxy, or OS-sandbox boundary. It cannot claim control over an agent launched outside ryk, a host hook that is not installed or does not fire, a command that escapes the wrapper path, or a capability that doctor reports as unavailable or limited.

doctor describes host capability and configuration. It is not proof that a live session attached every listed backend. The session banner and audit artifacts describe the posture selected for that run. An explicit --os-sandbox off run is wrapper-level evidence only. A successful redteam --ci run is engine self-test evidence only.

The CLI is local. The version contract states that it does not provide hosted policy synchronization or cloud enforcement. Release builds may send fixed anonymous CLI telemetry under the separate telemetry contract. Neither statement changes the local enforcement boundary.

## Known behavior mismatches

These are recorded because they affect documentation and automation:

1. ryk help run mentions yolo in the displayed mode list, but the current run parser rejects --mode yolo and accepts only observe, ask, strict, and ci. Use the accepted list until the help and parser converge.
2. ryk help decide and the parser accept --stdin. A direct pipe probe against this build failed with EndOfStream in the stdin reader, so do not treat the route as reliable in this build. Use the verified inline --json form for now. The source location is [decide.zig](../src/cli/decide.zig#L696).
3. --json is scoped to a command implementation. In the checked build, replay --json --list rendered the list form rather than a JSON document. Treat each subcommand's help as its output contract.
4. doctor --json can return exit 0 with ready: false; use doctor --check when readiness must control a job.

## Verification record

The following probes were run against the source-built binary, with state-changing probes restricted to temporary workspaces or dry-run forms:

~~~sh
./scripts/zig version
./scripts/zig build
./zig-out/bin/ryk help --all
./zig-out/bin/ryk version --json
./zig-out/bin/ryk explain "git status"
./zig-out/bin/ryk explain --format json "rm -rf /"
./zig-out/bin/ryk test "git status"
./zig-out/bin/ryk test --format json "rm -rf /"
./zig-out/bin/ryk policy check --preset strict
./zig-out/bin/ryk packs --json
./zig-out/bin/ryk replay --session last --verify
./zig-out/bin/ryk report --session last --format json
./zig-out/bin/ryk ci check --format json
./zig-out/bin/ryk redteam --ci --json
~~~

Additional manual checks covered a temporary run workspace, child exit propagation, a denied strict-mode command, policy initialization, hook and evaluate fixtures, a loopback dashboard request, plugin diagnostics, and dry-run staged-change operations. No real host agent was launched during this documentation pass, so host alias behavior is source-verified rather than presented as a live host-session result.

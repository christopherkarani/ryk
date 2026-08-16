const std = @import("std");
const style = @import("style.zig");
const build_options = @import("build_options");
const tui = @import("../tui/mod.zig");
const host_launch = @import("host_launch.zig");

pub const Category = enum {
    getting_started,
    core_workflow,
    staged_changes,
    diagnostics,
    integrations,
    advanced,
    internal,
};

pub const CommandInfo = struct {
    name: []const u8,
    summary: []const u8,
    usage: []const u8,
    details: []const []const u8,
    examples: []const []const u8 = &.{},
    additional_completion_flags: []const []const u8 = &.{},
    category: Category = .advanced,
    /// When true, listed on default root help (Safe Launch progressive disclosure).
    public: bool = false,
    hidden: bool = false,
};

/// One help entry per allowlisted host — driven by `host_launch.host_launch_aliases`.
fn hostAliasCommand(comptime host: []const u8) CommandInfo {
    return .{
        .name = host,
        .summary = "Launch " ++ host ++ " under ryk protection",
        .usage = "ryk " ++ host ++ " [agent-args...]",
        .category = .core_workflow,
        .public = true,
        .examples = &.{"ryk " ++ host},
        .details = &.{
            "Public protected launch path for " ++ host ++ "; internally uses the run engine for session setup.",
            "Inherits agent-primary defaults: network allowlist + proxy mediation + empty-backpack secret boundary (trusted host binaries only; basename spoofs do not). Non-alias `ryk run` secretless stays off unless --secretless. ryk run flags stay on `ryk run` only — everything after the host name is agent argv.",
        },
    };
}

fn hostAliasCommands() [host_launch.host_launch_aliases.len]CommandInfo {
    var out: [host_launch.host_launch_aliases.len]CommandInfo = undefined;
    inline for (host_launch.host_launch_aliases, 0..) |host, i| {
        out[i] = hostAliasCommand(host);
    }
    return out;
}

pub const commands =
    [_]CommandInfo{
        .{
            .name = "run",
            .summary = "Run a command under ryk (agent-primary defaults)",
            .usage = "ryk run [options] -- <command> [args...]",
            .category = .core_workflow,
            .examples = &.{
                "ryk claude",
                "ryk pi",
                "ryk run -- <custom-command>",
                "ryk run --network allowlist -- ./scripts/agent-task.sh",
                "ryk run --no-network --no-secrets -- echo 'offline'",
                "ryk run --secretless --network-backend proxy -- <command>",
                // Advanced: force attach fail-closed (default is auto + hardened; not the day-1 path).
                "ryk run --os-sandbox on -- <command>",
            },
            .additional_completion_flags = &.{ "--workspace", "--policy", "--session-name", "--secretless", "--with-host-secrets", "--inherit-env", "--allow-network", "--network", "--network-backend", "--os-sandbox", "--seatbelt-profile", "--require-backend" },
            .details = &.{
                "Starts a protected session, filters the child environment through policy, checks the command through a command safety check, writes audit artifacts, and mirrors the child exit code.",
                "Agent-primary defaults for host aliases (ryk pi, ryk claude, …): network mode allowlist + proxy backend + OS route-force (fail closed if mediation cannot start) + empty-backpack secret boundary for trusted host binaries. Non-alias `ryk run -- <cmd>` still defaults network mode to ask without forcing proxy, and secretless stays off unless --secretless. Mode overrides: --network allowlist|observe|off|ask, --no-network (still mediate on host aliases). Mediation escapes: --network open (loud unrestricted egress), RYK_AGENT_NETWORK_DEFAULT=legacy (loud, one-release).",
                "Host launch aliases rewrite to this command with no extra flags — security defaults live here. Pass ryk run flags only on `ryk run`, not after a host alias name (e.g. `ryk run --network open -- pi`). One-release kill switch: RYK_AGENT_NETWORK_DEFAULT=legacy restores pre-mediation agent net defaults.",
                "Options: --workspace <path>, --mode observe|ask|yolo|strict|ci, --policy <path>, --session-name <name>, --no-secrets, --secretless, --with-host-secrets, --inherit-env, --no-network, --allow-network <domain>, --network observe|ask|allowlist|open|off, --network-backend decision-only|proxy, --os-sandbox auto|on|off, --seatbelt-profile compatible|hardened|strict, --require-backend <capability>, --help",
                "Strict and CI modes default to environments without secret access. --secretless is empty-backpack: public host env only (no raw secrets, no ryk-secret:// rewrite), OS sandbox required, and workspace .env forms denied at the OS layer when attach succeeds. --with-host-secrets is an explicit escape that may expose host secrets and always emits a warning. --inherit-env is allowed only when the selected policy permits inheritance.",
                "Network flags update the run-time policy and audit network decisions. --network-backend proxy starts an explicit localhost proxy and injects HTTP_PROXY/HTTPS_PROXY/ALL_PROXY; HTTPS CONNECT is host/port only without interception. Host aliases require route-forced proxy by default; --network open is a loud unrestricted-egress escape.",
                "Protected launch defaults attach the OS filesystem sandbox automatically when the host supports it (no flags required for ryk <agent> or ryk run -- <command>). Advanced: --os-sandbox auto|on|off (default auto). on fails closed when the platform backend cannot attach. auto: degrades loudly when no backend plan exists; fails closed on incomplete env scrub/allowlist; fails closed if attach fails after materials are prepared. off disables OS apply. --require-backend strong-sandbox accepts a planned OS attach; landlock additionally requires a Landlock plan. A later attach failure still aborts launch.",
                "Advanced (macOS residual grade only): --seatbelt-profile compatible|hardened|strict (default hardened; also RYK_SEATBELT_PROFILE). compatible is the historical broad process*/private/var residual; hardened narrows process ops and bootstrap FS; strict also drops inbound/bind under route-force and omits broad network* without route force. Still not process/XPC isolation. Use compatible if a tool breaks under hardened. Not required for the happy path.",
                "Linux (Landlock): when active, the session banner reports workspace child RW with workspace-root RO — create/write at the workspace root is denied; write works under pre-existing non-control children. macOS (Seatbelt): full workspace subpath RW minus control-root carve-outs (create-at-root allowed). With the proxy backend, supported OS sandbox sessions can route-force child outbound TCP to the ryk loopback proxy.",
                "Linux uses platform feature detection where available. Optional kernel features are reported honestly and are not claimed active unless actually active.",
            },
        },
    } ++ hostAliasCommands() ++ [_]CommandInfo{
        .{
            .name = "init",
            .summary = "Create an ryk policy",
            .usage = "ryk init [--preset <name>] [--mode strict|ask|observe|ci|trusted] [--ci] [--force] [--quiet]",
            .category = .getting_started,
            .examples = &.{
                "ryk init --preset generic-agent",
                "ryk init --mode strict --force",
                "ryk init --preset claude-code",
            },
            .details = &.{
                "Creates .ryk/policy.yaml from a practical editable preset.",
                "Also enables preset-mapped safety packs in project `.ryk.toml` (git repo) or user config (additive; never wipes customizations).",
                "Presets: generic-agent, claude-code, codex, cursor-agent, opencode, cline-roo, mcp-dev, github-actions, solo-dev, strict-local, team-ci, openclaw-hermes, unattended, trusted-local.",
                "Pack map: generic-agent/solo-dev/trusted-local/mcp-dev/unattended = baseline only; claude-code/codex/… = package_managers; team-ci/github-actions/openclaw-hermes = containers + k8s + terraform (+ GHA for CI); strict-local = strict_git.",
                "Refuses to overwrite an existing policy unless --force is provided.",
                "Use --quiet to suppress informational output in scripts.",
            },
        },
        .{
            .name = "start",
            .summary = "Guided setup: multi-select hosts, policy, and Ask posture",
            .usage = "ryk start [--auto|--yes|--no-interact] [--hosts <list>] [--preset <name>] [--skip-verify]",
            .category = .getting_started,
            .public = true,
            .examples = &.{
                "ryk start",
                "ryk start --auto",
                "ryk start --auto --hosts codex,claude",
            },
            .details = &.{
                "Primary first-run onboarding — the only Safe Launch door.",
                "Creates a policy if missing (coding DCG defaults via generic-agent: matrix-only strict, no ask main loop).",
                "Wires detected host integrations and verifies daemon/hook paths when available.",
                "Auto-selects the best available Ask posture — no protection-grade menu.",
                "On interactive terminals, prompts only for host selection when hosts are detected.",
                "On non-TTY terminals, auto-selects safe defaults (no --auto required).",
                "Use --auto to force non-interactive mode on a TTY; optional --hosts and --preset.",
                "Compatibility flags --yes and --no-interact also select non-interactive mode.",
                "Next steps after start: ryk <agent> · ryk doctor · ryk replay.",
                "Re-run safely to repair or update an existing setup.",
            },
        },
        .{
            .name = "agents",
            .summary = "Install and health-check Hermes/OpenClaw unattended agents",
            .usage = "ryk agents <setup|health> [hermes|openclaw] [--json]",
            .category = .getting_started,
            .public = true,
            .examples = &.{
                "ryk agents setup",
                "ryk agents setup hermes",
                "ryk agents setup openclaw",
                "ryk agents health --json",
            },
            .details = &.{
                "First-class setup for always-on Hermes and OpenClaw agents on Mac minis, VPSs, and other non-interactive hosts.",
                "Setup creates or preserves the fail-closed `unattended` strict policy, installs the selected host adapters, and runs the existing setup verification path.",
                "Health uses bounded host CLI probes and never waits for an operator. A missing, stale, or unresponsive host is reported as not ready.",
                "Risk decisions that would normally ask are denied when RYK_UNATTENDED, RYK_NONINTERACTIVE, RYK_CI, or CI is truthy.",
                "OpenClaw readiness requires the receipt-bound reviewed bundle, full runtime registration, runtime hook inspection, a healthy Gateway RPC, a bound running Gateway identity, and a nonce-bound denial through Gateway `tools.invoke`. Metadata/discovery passes are explicitly unprotected; when upstream identity or live dispatch proof is unavailable, use `ryk run -- openclaw`.",
                "Use `ryk agents health --json` from launchd, systemd, cron, or a VPS supervisor.",
            },
        },
        .{
            .name = "quickstart",
            .summary = "Removed — use ryk start",
            .usage = "ryk start",
            .category = .getting_started,
            .hidden = true,
            .examples = &.{},
            .details = &.{
                "`ryk quickstart` was removed. Use `ryk start` instead.",
            },
        },
        .{
            .name = "setup",
            .summary = "Removed — use ryk start",
            .usage = "ryk start",
            .category = .getting_started,
            .hidden = true,
            .examples = &.{},
            .details = &.{
                "`ryk setup` was removed. Use `ryk start` instead.",
            },
        },
        .{
            .name = "status",
            .summary = "Removed — use ryk doctor",
            .usage = "ryk doctor",
            .category = .getting_started,
            .hidden = true,
            .examples = &.{},
            .details = &.{
                "`ryk status` was removed. Use `ryk doctor` for diagnostics and readiness checks.",
            },
        },
        .{
            .name = "env",
            .summary = "Print shell environment for ryk",
            .usage = "ryk env",
            .category = .getting_started,
            .details = &.{
                "Prints export statements for PATH and RYK_RESOURCE_ROOT.",
                "Use with eval: eval \"$(ryk env)\"",
            },
        },
        .{
            .name = "doctor",
            .summary = "Diagnose protection readiness and platform capabilities",
            .usage = "ryk doctor [-v|--verbose] [--check] [--json] [--tui] [--fix] [--from-install] [--preset <name>] [--deadlock-check]",
            .category = .getting_started,
            .public = true,
            .examples = &.{
                "ryk doctor",
                "ryk doctor --verbose",
                "ryk doctor --check",
                "ryk doctor --json",
                "ryk doctor --tui",
                "ryk doctor --fix",
                "ryk doctor --deadlock-check",
            },
            .additional_completion_flags = &.{ "--verbose", "-v", "--check", "--json", "--tui", "--fix", "--from-install", "--preset", "--deadlock-check" },
            .details = &.{
                "Default output is a one-line summary plus recommended next steps (linear; fast glance).",
                "Includes a Packs section (baseline always-on + opt-in enabled) when the daemon is reachable.",
                "Use --verbose for the full platform, integration, and capability report.",
                "Use --check for automation: exit non-zero when core readiness fails (daemon not compatible, or policy missing/invalid).",
                "Use --json for a minimal readiness report (ready, state, policy.valid).",
                "Use --tui for a four-pane deep-dive (Summary · Hosts · Capabilities · Next steps) on an interactive TTY; non-TTY / --json / --plain falls back to linear.",
                "Next steps in --tui deep-link `ryk packs` and `ryk allowlist`.",
                "Use --fix to repair protection (create policy if missing, auto-wire day-one hosts). Exit 0 when core policy is ok; host soft-fails stay partial.",
                "--fix is exclusive with --check and --json (cannot combine; probe contracts stay pure).",
                "Optional --from-install scopes ensure to install HOME/resource-root; --preset selects create-if-missing policy preset. Both require --fix.",
                "Use --deadlock-check to replay a standard coding workflow against your active policy: exit non-zero when a normal step would ask/deny (an agent would stall) or a dangerous step would be allowed.",
                "--deadlock-check is read-only and exclusive with --fix/--check/--json.",
            },
        },
        .{
            .name = "test",
            .summary = "Test a shell command with Zig shell_engine packs",
            .usage = "ryk test <command> [options]",
            .category = .core_workflow,
            .examples = &.{
                "ryk test \"git status\"",
                "ryk test \"rm -rf /\" --format json",
            },
            .details = &.{
                "Evaluates the command with the in-process Zig shell_engine (oracle pack parity).",
                "Exit 0 = allow, 2 = deny. Use --format json for structured decision fields.",
            },
        },
        .{
            .name = "scan",
            .summary = "Scan past agent sessions for risky commands and secret exposure",
            .usage = "ryk scan [--days N|--all-time] [--all] [--json] [--plain] [--host <name>]",
            .category = .getting_started,
            .public = true,
            .hidden = false,
            .additional_completion_flags = &.{ "--days", "--all-time", "--all", "--json", "--plain", "--host" },
            .examples = &.{
                "ryk scan",
                "ryk scan --days 7",
                "ryk scan --json",
                "ryk scan --plain",
                "ryk scan --host claude --all",
            },
            .details = &.{
                "Free offline session forensics for new ryk users. Scans known host session stores only",
                "(Claude Code, Codex, Pi, OpenCode, Grok Build) plus a thin ryk bridge — no $HOME crawl.",
                "Reports dangerous shell/tool commands (high+medium via shell_engine) and secret material/access.",
                "Never prints raw secrets. Default window is 30 days; default list cap is ~20 (use --all).",
                "On an interactive colour TTY, opens a scorecard + list/detail viewer (libvaxis alt-screen).",
                "TUI keys: c copies the full evidence path · o reveals/opens it · q quits.",
                "Use --plain for linear rich text; --json for machine output (no TUI).",
                "Exit 0 on successful scan even when findings exist. Existing users: prefer `ryk replay`.",
                "Hosts: claude | codex | pi | opencode | grok | ryk. OpenCode uses opencode.db (read-only; requires sqlite3 CLI).",
            },
        },
        .{
            .name = "history",
            .summary = "Review protected command history",
            .usage = "ryk history [stats|check|analyze|interactive|export|prune|backup] [options] [--days N] [--strict] [--live] [--json|--robot|--format <value>]",
            .category = .diagnostics,
            .hidden = true, // use `replay` for history-like review
            .examples = &.{
                "ryk history stats --days 7",
                "ryk history check --strict",
                "ryk history --live",
            },
            .details = &.{
                "Human stats are rendered by ryk from structured history data.",
                "Use 'ryk history --help' for actions and examples.",
                "--live opens a scrollable alt-screen view of the current stats snapshot (TTY only; not with --json).",
                "Use --json, --robot, or --format for machine-readable daemon output.",
            },
        },
        .{
            .name = "precommit",
            .summary = "Run the Rust pre-commit safety scan",
            .usage = "ryk precommit [options]",
            .category = .core_workflow,
            .hidden = true,
            .examples = &.{
                "ryk precommit",
                "ryk precommit --format json",
            },
            .details = &.{
                "Proxies to the Rust daemon and runs the staged-file pre-commit scan path.",
                "This is the Phase 1 user-facing alias for the Rust scan pre-commit workflow.",
            },
        },
        .{
            .name = "explain",
            .summary = "Explain why a shell command is blocked or allowed",
            .usage = "ryk explain [--verbose|--format json] [--] <command>",
            .category = .getting_started,
            .public = true,
            .examples = &.{
                "ryk explain \"rm -rf /\"",
                "ryk explain \"git reset --hard\"",
                "ryk explain --verbose \"rm -rf /\"",
                "ryk explain --format json \"rm -rf /tmp/x\"",
            },
            .additional_completion_flags = &.{ "--verbose", "-v", "--format" },
            .details = &.{
                "Runs the in-process Zig shell_engine. Default output is decision, why, and one next command. Nothing is executed.",
                "Use --verbose for the match tree, pipeline steps, and safer-workflow suggestions.",
                "Use --format json for machine-readable output (regex, span, latency, tips).",
                "Different from 'ryk policy explain', which explains .ryk/policy.yaml file/network/tool rules.",
            },
        },
        .{
            .name = "classify",
            .summary = "Classify a shell command's risk without blocking",
            .usage = "ryk classify <command> [options]",
            .category = .diagnostics,
            .hidden = true,
            .examples = &.{
                "ryk classify \"git status\"",
                "ryk classify \"rm -rf /\" --format json",
            },
            .details = &.{
                "Proxies to the Rust daemon risk classifier (read-only; does not block).",
                "Use 'ryk classify --help' for the full Rust-backed option set.",
            },
        },
        .{
            .name = "allowlist",
            .summary = "Manage permanent pack-exception allowlist entries",
            .usage = "ryk allowlist <add|add-command|list|remove|validate|prune> [options]",
            .category = .core_workflow,
            // s-allowlist-cli: live Zig permanent TOML store (no daemon).
            .public = true,
            .hidden = false,
            .examples = &.{
                "ryk allowlist list",
                "ryk allowlist list --plain",
                "ryk allowlist add core.git:branch-force-delete -r \"cleanup stale local branches\"",
                "ryk allowlist add-command \"git status\" -r \"CI bootstrap\"",
                "ryk allow \"core.git:branch-force-delete\" -r \"cleanup stale local branches\"",
            },
            .details = &.{
                "Permanent pack exceptions (rule id or exact command) with required reason.",
                "Project file: .ryk/allowlist.toml · user: $XDG_CONFIG_HOME/ryk/allowlist.toml.",
                "kind=command short-circuits before packs; kind=rule skips that rule only (E8).",
                "Critical pack hits (e.g. core.git:reset-hard / git reset --hard) cannot be permanently unlocked — use allow-once or a safer workflow.",
                "Examples use medium rules (e.g. core.git:branch-force-delete / git branch -D).",
                "On a colour TTY, bare `ryk allowlist` / `allowlist list` opens a dual-layer browse (project then user).",
                "Use --plain for a linear list; --json for machine output (no TUI).",
                "Shortcuts: 'ryk allow <rule>' and 'ryk unallow <key>' (advanced; not on default help).",
                "Use 'ryk allowlist --help' for actions and options.",
            },
        },
        .{
            .name = "allow",
            .summary = "Add a rule to the permanent allowlist (shortcut)",
            .usage = "ryk allow <rule-id> -r <reason> [options]",
            .category = .core_workflow,
            // s-allowlist-cli: live Zig permanent TOML store (no daemon).
            .hidden = false,
            .examples = &.{
                "ryk allow core.git:branch-force-delete -r \"cleanup stale local branches\"",
            },
            .details = &.{
                "Shortcut for 'ryk allowlist add'. Writes project or user allowlist.toml.",
                "Critical pack hits cannot be permanently unlocked (hard fence).",
            },
        },
        .{
            .name = "unallow",
            .summary = "Remove a permanent allowlist entry (shortcut)",
            .usage = "ryk unallow <rule-id|exact-command> [options]",
            .category = .core_workflow,
            // s-allowlist-cli: live Zig permanent TOML store (no daemon).
            .hidden = false,
            .examples = &.{
                "ryk unallow core.git:branch-force-delete",
            },
            .details = &.{
                "Shortcut for 'ryk allowlist remove'. Key is rule id or exact command string.",
            },
        },
        .{
            .name = "allow-once",
            .summary = "Allow a blocked command once via short code",
            .usage = "ryk allow-once <code|list|clear|revoke> [options]",
            .category = .core_workflow,
            // s-once-cli: live Zig pending/allow-once JSONL store (no daemon).
            .hidden = false,
            .examples = &.{
                "ryk allow-once list",
                "ryk allow-once 510755",
                "ryk allow-once clear",
            },
            .details = &.{
                "Redeems a pending short code from a deny panel into a single-use grant.",
                "Subcommands: list, clear, revoke. Use 'ryk allow-once --help' for options.",
            },
        },
        .{
            .name = "suggest-allowlist",
            .summary = "Suggest allowlist entries from protected history",
            .usage = "ryk suggest-allowlist [options]",
            .category = .diagnostics,
            .hidden = true,
            .examples = &.{
                "ryk suggest-allowlist",
                "ryk suggest-allowlist --confidence high",
                "ryk suggest-allowlist --format json",
                "ryk history suggest",
            },
            .additional_completion_flags = &.{"--apply"},
            .details = &.{
                "Day-2 policy loop: denials → suggestions → allowlist.",
                "Proxies to the Rust daemon; requires history to be enabled.",
                "Human output includes copy-pasteable next commands (`suggest-allowlist --apply N` / `allowlist add-command`) for high-confidence items.",
                "Alias: `ryk history suggest` (same as suggest-allowlist).",
                "Use 'ryk suggest-allowlist --help' for filters and confidence options.",
            },
        },
        .{
            .name = "simulate",
            .summary = "Dry-run policy / packs against a command file or history dump",
            .usage = "ryk simulate [--file <path>] [options]",
            .category = .diagnostics,
            .hidden = true,
            .examples = &.{
                "ryk simulate --file commands.txt",
                "ryk simulate -f denials.jsonl --format pretty",
                "ryk simulate --help",
            },
            .details = &.{
                "What-if dry-run for pack rollout and false-positive review before tightening modes.",
                "Proxies to the Rust daemon simulate engine (does not execute shell commands).",
                "Input is a file of commands or hook JSONL (use -f / --file; default stdin).",
                "Prints allow/deny counts and top denials. Use before enabling packs or switching to strict/ci.",
            },
        },
        .{
            .name = "rebase-recover",
            .summary = "Issue a short-lived permit for git rebase recovery",
            .usage = "ryk rebase-recover [--ttl <seconds>]",
            .category = .core_workflow,
            .hidden = true,
            .examples = &.{
                "ryk rebase-recover",
                "ryk rebase-recover --ttl 120",
            },
            .details = &.{
                "Proxies to the Rust daemon. Unblocks the next git checkout -- / restore",
                "step after a messy rebase recovery within a short TTL.",
            },
        },
        .{
            .name = "config",
            .summary = "Show ryk daemon configuration",
            .usage = "ryk config",
            .category = .diagnostics,
            .hidden = true,
            .examples = &.{
                "ryk config",
            },
            .details = &.{
                "Proxies to the Rust daemon config show path (read-only).",
                "Use 'ryk config --help' for daemon-backed details.",
            },
        },
        .{
            .name = "packs",
            .summary = "Browse, inspect, and enable safety packs",
            .usage =
            \\ryk packs [--filter <term>] [--enabled|--installed] [--page N] [--page-size N] [--json] [--plain]
            \\  ryk packs show <id> [--no-patterns] [--verbose] [--json]
            \\  ryk packs enable <id> [id…]
            \\  ryk packs disable <id> [id…]
            ,
            .category = .diagnostics,
            // Slice 4 / s-packs: live oracle registry + pack_config (no daemon).
            .public = true,
            .hidden = false,
            .examples = &.{
                "ryk packs",
                "ryk packs --plain",
                "ryk packs --enabled",
                "ryk packs show core.git",
                "ryk packs enable containers.docker database.postgresql",
                "ryk packs disable containers.docker",
                "ryk packs --filter database --page-size 10",
                "ryk packs --json",
            },
            .additional_completion_flags = &.{ "--json", "--plain", "--no-patterns", "--verbose", "--enabled", "--filter" },
            .details = &.{
                "Safety packs are Zig shell_engine oracle rule sets (embedded registry; not policy presets).",
                "Policy presets use `ryk policy packs` / `ryk policy apply-pack` instead.",
                "On a colour TTY, bare `ryk packs` opens a browse view (enabled + baseline first; search and toggle all).",
                "Use --plain for the linear paginated list; --json / --format json for machine output (no TUI).",
                "List is sorted and paginated locally; --installed is an alias for --enabled.",
                "Baseline packs (core.*, system.disk) are on by default; list them in `disabled` to opt out (engine honors pack_config).",
                "Enable/disable writes project `.ryk.toml` in a git repo, otherwise user config (`$XDG_CONFIG_HOME/ryk/config.toml` or `~/.config/ryk/config.toml`).",
                "`ryk packs show <id>` reads the oracle registry (human view hides raw regex unless --verbose).",
                "Use --json or --format json for a stable machine schema (schema_version, packs, counts).",
            },
        },
        .{ .name = "policy", .summary = "Validate, explain, and apply policies", .usage = "ryk policy <check|explain|packs|apply-pack> [...]", .category = .core_workflow, .additional_completion_flags = &.{ "--policy", "--method", "--force", "--preset" }, .examples = &.{
            "ryk policy check",
            "ryk policy check .ryk/policy.yaml",
            "ryk policy check --preset strict",
            "ryk policy explain file.read /etc/passwd",
        }, .details = &.{
            "Subcommands:",
            "  ryk policy check [policy-path]   # default: workspace .ryk/policy.yaml (not builtin)",
            "  ryk policy check --preset <observe|ask|yolo|strict|ci|redteam|trusted>",
            "  ryk policy check builtin:<preset>",
            "  ryk policy explain [--policy <path>] <file.read|file.write|env|command|network|mcp|tool> <target> [--method <HTTP_METHOD>]",
            "  ryk policy packs",
            "  ryk policy apply-pack <solo-dev|strict-local|team-ci|openclaw-hermes> [--force]",
            "policy check with no path validates the workspace policy only; missing policy fails (run ryk init).",
            "Built-in presets require --preset or an explicit builtin:<name> path.",
            "policy explain covers Zig policy.yaml rules (file/env/network/mcp).",
            "For shell pack traces use 'ryk explain \"<command>\"' instead.",
            "For effect-class tool classification use 'ryk tools classify <name>'.",
        } },
        .{
            .name = "tools",
            .summary = "Classify tools into effect hits and list effect packs",
            .usage = "ryk tools <classify|packs> [...]",
            .category = .diagnostics,
            .additional_completion_flags = &.{ "--args", "--policy" },
            .examples = &.{
                "ryk tools classify send_email",
                "ryk tools classify notify --args '{\"to\":\"a@b.com\",\"body\":\"hi\"}'",
                "ryk tools classify send_email --policy .ryk/policy.yaml",
                "ryk tools packs",
            },
            .details = &.{
                "Discovery helpers for effect-class policy (not shell `ryk classify`).",
                "  ryk tools classify <name> [--args '<json-object>'] [--policy <path>]",
                "  ryk tools packs",
                "Prints effect ids, confidence, and matcher labels only (never raw arg values).",
                "User effect packs load from ~/.config/ryk/effect-packs and .ryk/effect-packs.",
                "Packs extend classification only; allow/deny still requires policy effects:.",
            },
        },
        .{ .name = "credentials", .summary = "Verify credential brokers without exposing secrets", .usage = "ryk credentials check [credential-ref]", .category = .advanced, .details = &.{
            "Checks configured credential brokers and optional credential refs without printing raw secret values.",
            "Supported broker kinds: local-dummy, env-file-dev, 1password-cli, macos-keychain, infisical-agent-vault.",
            "Infisical/Agent Vault is currently a status/config boundary until exact local API or CLI behavior is verified.",
        } },
        .{ .name = "report", .summary = "Show a safety report for a session", .usage = "ryk report --session <id|last> [--format human|markdown|json]", .category = .diagnostics, .details = &.{
            "Loads a local session, verifies session integrity, and shows denied actions, redactions, plugin readiness, and a plain-language prevention summary.",
            "Default output is a colour terminal report. Use --format markdown or --format json for export.",
            "Report export is free — no license required.",
        } },
        .{ .name = "ci", .summary = "Run local CI readiness checks", .usage = "ryk ci check [--format markdown|json] [--github-summary <path>]", .category = .advanced, .details = &.{
            "Validates .ryk/policy.yaml, rejects dangerous obvious defaults, runs a focused CI-safe redteam fixture, and emits GitHub Actions-friendly output.",
        } },
        .{ .name = "shutdown", .summary = "Stop the background ryk daemon", .usage = "ryk shutdown [--daemon]", .category = .advanced, .examples = &.{
            "ryk shutdown",
            "ryk shutdown --daemon",
        }, .details = &.{
            "Sends a graceful Shutdown request to the Rust daemon over UDS.",
            "Removes $HOME/.ryk/daemon.sock and daemon.pid when shutdown succeeds.",
            "When the daemon is not running, stale artifacts are cleaned when safe.",
        } },
        .{ .name = "stop", .summary = "Stop ryk protection for host agents", .usage = "ryk stop [codex|claude|cursor|opencode|openclaw|hermes|all] [--yes|--no]", .category = .integrations, .public = true, .examples = &.{
            "ryk stop",
            "ryk stop codex",
            "ryk stop cursor",
        }, .details = &.{
            "Removes ryk plugin registrations from host agents without removing the ryk binary or policy files.",
            "Non-interactive cancel: --no. Mutation requires --yes or an interactive confirm.",
            "Hosts: codex, claude, cursor, opencode, openclaw, hermes, grok. Defaults to all if no host is specified.",
            "Cursor: removes the ryk shell hook wrapper and disables simple ryk-only hooks.json files.",
            "OpenCode: removes .opencode/plugins/ryk.ts, ryk-tui.ts and ~/.config/opencode/plugins/ryk.ts, ryk-tui.ts",
            "OpenClaw: runs 'openclaw plugins uninstall ryk'",
            "Hermes: runs 'hermes plugins disable ryk' and removes ~/.hermes/plugins/ryk/",
            "Grok: removes ~/.grok/hooks/ryk.json and strips ryk PreToolUse from ~/.grok/user-settings.json (restart Grok to reload).",
            "Codex / Claude: removes known plugin paths (host-managed install locations).",
            "Restart protection later with: ryk start",
        } },
        .{ .name = "disable", .summary = "Stop ryk protection for host agents", .usage = "ryk disable [codex|claude|cursor|opencode|openclaw|hermes|all] [--yes|--no]", .category = .integrations, .hidden = true, .examples = &.{
            "ryk disable",
            "ryk disable codex",
        }, .details = &.{
            "Alias of `ryk stop`. Removes ryk plugin registrations from host agents without removing the ryk binary or policy files.",
            "Non-interactive cancel: --no. Mutation requires --yes or an interactive confirm.",
            "Hosts: codex, claude, cursor, opencode, openclaw, hermes, grok. Defaults to all if no host is specified.",
            "Restart protection later with: ryk start",
        } },
        .{ .name = "uninstall", .summary = "Uninstall ryk from this machine", .usage = "ryk uninstall [--plugins-only] [--keep-config] [--dry-run] [--yes]", .category = .integrations, .details = &.{
            "Completely removes ryk and its integrations from the machine.",
            "Steps:",
            "  1. Removes all plugins from host agents (same as 'ryk stop').",
            "  2. Removes the ryk binary from user install dirs, runtime assets,",
            "     shell activation markers, and share data.",
            "  3. Removes user config (~/.config/ryk/, ~/.ryk) unless --keep-config.",
            "Options:",
            "  --plugins-only   Only remove plugins; keep binary and config.",
            "  --keep-config    Keep ~/.config/ryk/ and allow-once data; still remove runtime + binary.",
            "  --dry-run        Print what would be removed without changing anything.",
            "  --yes            Skip confirmation prompt.",
            "Local workspace .ryk/ directories are never removed automatically;",
            "run 'find . -type d -name .ryk' to locate them manually.",
            "Package-manager binaries (Homebrew/Scoop/WinGet) are left in place; uninstall there separately.",
        } },
        .{ .name = "replay", .summary = "Replay an audit session", .usage = "ryk replay [--list] [--session <id|last>] [--json] [--only denied] [--verify] [--tui]", .category = .core_workflow, .public = true, .examples = &.{
            "ryk replay",
            "ryk replay --list",
            "ryk replay --session last",
            "ryk replay --session 2026-05-29-abc123",
            "ryk replay --session last --tui",
        }, .details = &.{
            "Reads .ryk session artifacts, renders a timeline, and can verify session integrity.",
            "With no args and no sessions, lists available sessions instead of erroring.",
            "Use --list to print all session IDs under .ryk/sessions/.",
            "--tui opens a scrollable alt-screen timeline view (TTY only; not with --json).",
        } },
        .{
            .name = "diff",
            .summary = "Show pending file changes",
            .usage = "ryk diff [--session <id|last>] [--file <path>]",
            .category = .staged_changes,
            .details = &.{
                "Shows unified diffs for ryk-mediated pending file changes.",
                "Use 'ryk apply' to commit changes or 'ryk discard' to cancel them.",
            },
        },
        .{
            .name = "apply",
            .summary = "Commit pending file changes",
            .usage = "ryk apply [--session <id|last>] [--file <path>] [--dry-run] [--yes]",
            .category = .staged_changes,
            .additional_completion_flags = &.{ "--dry-run", "--yes" },
            .details = &.{
                "Applies reviewed pending file changes after original-state checks where feasible.",
                "--dry-run prints a summary without mutating; non-interactive mutation requires --yes.",
                "Interactive confirm defaults to No (empty Enter cancels).",
                "See 'ryk diff' to review changes and 'ryk discard' to cancel them.",
            },
        },
        .{
            .name = "discard",
            .summary = "Reject pending file changes",
            .usage = "ryk discard [--session <id|last>] [--file <path>] [--dry-run] [--yes]",
            .category = .staged_changes,
            .additional_completion_flags = &.{ "--dry-run", "--yes" },
            .details = &.{
                "Destroys proposed staged changes without changing workspace files.",
                "--dry-run prints a summary without mutating; non-interactive mutation requires --yes.",
                "Interactive confirm defaults to No and warns that discard destroys proposed staged changes.",
                "See 'ryk diff' to review changes and 'ryk apply' to commit them.",
            },
        },
        .{ .name = "mcp", .summary = "Inspect and proxy MCP servers", .usage = "ryk mcp <inspect|proxy|list|trust|manifest> [options]", .category = .advanced, .additional_completion_flags = &.{ "--command", "--name", "--policy", "--manifest", "--mode", "--tool", "--server" }, .details = &.{
            "Subcommands:",
            "  ryk mcp inspect --command <server> [--name <server-name>] [--policy <path>]",
            "  ryk mcp proxy --command <server> [--name <server-name>] [--policy <path>] [--manifest <path>] [--mode observe|ask|yolo|strict|ci]",
            "  ryk mcp list",
            "  ryk mcp trust <server> --tool <tool>",
            "  ryk mcp manifest check <manifest.yaml>",
            "  ryk mcp manifest generate --command <server-command> | --server <name>",
            "The proxy handles MCP server communication over stdio and forwards messages transparently.",
            "Remote HTTP MCP, OAuth, and hosted gateway behavior are limited/deferred in Phase 17.",
        } },
        .{ .name = "redteam", .summary = "Run built-in fixture engine self-tests (not your workspace policy)", .usage = "ryk redteam [path] [--json] [--ci] [--fixture <id>]", .category = .advanced, .details = &.{
            "Runs deterministic local fixtures against the internal builtin:redteam preset with synthetic in-process (Zig) evaluation.",
            "This is an engine self-test: it does not load .ryk/policy.yaml, does not exercise host hook install, and does not prove wrapper/host/proxy/OS enforcement.",
            "Reports include provenance (suite_kind, policy, evaluator, real_action_attempted=false). A 100% score is not workspace-policy assurance.",
            "When no path is provided, fixtures are discovered under ./fixtures (or installed resource fixtures).",
            "--json emits a machine-readable report with a provenance object. --ci never prompts and exits non-zero if any required fixture fails or is unsupported.",
        } },
        .{ .name = "completions", .summary = "Generate shell completions", .usage = "ryk completions <bash|zsh|fish|powershell>", .category = .getting_started, .details = &.{
            "Prints a completion script to stdout for the requested shell.",
            "The generated completions include top-level commands and common flags.",
        } },
        .{ .name = "shim", .summary = "Internal callback for session-local PATH shims", .usage = "ryk shim exec -- <command> [args...]", .category = .internal, .hidden = true, .details = &.{
            "Internal callback used by session-local PATH shims under .ryk/sessions/<id>/shims/.",
            "The shim removes the session shim directory from PATH before resolving the real binary to avoid recursive invocation.",
            "This is wrapper-level coverage only and does not claim transparent OS-level interception.",
        } },
        .{ .name = "version", .summary = "Print version", .usage = "ryk version [--json] [--help]", .category = .diagnostics, .details = &.{
            "Prints the current ryk version.",
            "--json emits version, commit, target, and build_date fields for release automation.",
        } },
        .{
            .name = "update",
            .summary = "Update ryk to the latest release",
            .usage = "ryk update [--check] [--yes] [--version <semver>] [--json] [--force]",
            .category = .getting_started,
            .public = true,
            .examples = &.{
                "ryk update",
                "ryk update --check",
                "ryk update --yes",
                "ryk update --version 1.2.9 --yes",
            },
            .details = &.{
                "Checks GitHub for the latest release and upgrades this install via the official installer",
                "(scripts/install.sh on macOS/Linux, install.ps1 on Windows). Checksums and atomic install",
                "stay on the same path as a first-time curl install.",
                "Options:",
                "  --check            Report current vs latest only (no install).",
                "  --yes              Skip the confirmation prompt.",
                "  --version <semver> Install a specific release instead of latest.",
                "  --json             Machine-readable status.",
                "  --force            Allow curl installer on package-managed installs, or downgrade with --version.",
                "Legacy Homebrew/npm/scoop/winget installs are not upgraded through their package manager.",
                "Migrate them to the supported curl installer (use --force to overwrite in place).",
                "See also: docs/install.md",
            },
        },
        .{
            .name = "feedback",
            .summary = "Send fixed-category product feedback",
            .usage = "ryk feedback <bug|false_positive|false_negative|missing_integration|confusing>",
            .category = .advanced,
            .details = &.{
                "Records only the selected category; free-form feedback text is not accepted or transmitted.",
                "Categories: bug, false_positive, false_negative, missing_integration, confusing.",
            },
        },
        .{
            .name = "telemetry",
            .summary = "View or change pseudonymous usage telemetry",
            .usage = "ryk telemetry [status|enable|disable] [--json]",
            .category = .advanced,
            .public = true,
            .additional_completion_flags = &.{"--json"},
            .details = &.{
                "Telemetry is enabled by default in release builds and sends only a fixed allowlist of pseudonymous product metadata to PostHog, including FM, enforcement, integration, session, feature, and reliability summaries.",
                "Use `ryk telemetry disable` to opt out, `ryk telemetry enable` to resume, and `ryk telemetry status` to inspect the local state.",
                "Telemetry never records command text, arguments, prompts, paths, policy contents, environment values, secrets, or host payloads.",
                "RYK_NO_TELEMETRY=1 is an environment-level hard disable. Local development builds have transport disabled until built with a release PostHog token.",
            },
        },
        .{ .name = "plugin", .summary = "Plugin management and diagnostics", .usage = "ryk plugin <list|host|doctor|manifest|install> [options]", .category = .integrations, .additional_completion_flags = &.{ "--dry-run", "--yes", "--json", "--path" }, .details = &.{
            "Subcommands:",
            "  ryk plugin list",
            "  ryk plugin <codex|claude|opencode|openclaw|hermes> [--dry-run|--yes]",
            "  ryk plugin doctor [codex|claude|opencode|openclaw|hermes] [--json]",
            "  ryk plugin manifest [codex|claude|opencode|openclaw|hermes|all] [--json]",
            "  ryk plugin install                                 # dry-run preview of all hosts (no mutation)",
            "  ryk plugin install <codex|claude|opencode|openclaw|hermes|all> [--dry-run|--yes] [--path <path>]",
            "One-click repair: `ryk doctor --fix`. Guided multi-select setup: `ryk start`.",
            "Bare install never mutates; mutation requires an explicit host or `all` plus --yes (confirm default No on TTY).",
            "Plugin doctor does not print secrets.",
        } },
        .{ .name = "decide", .summary = "Ask ryk whether an action is allowed by policy", .usage = "ryk decide <command|file|prompt|tool> (--json <payload>|--stdin) [--ci] [--human]", .category = .advanced, .details = &.{
            "Evaluates a policy decision for host plugins (Codex, Claude Code, OpenCode, etc.).",
            "Subcommands:",
            "  ryk decide command --json '{\"command\":\"<cmd>\"}'",
            "  ryk decide file    --json '{\"path\":\"<p>\",\"operation\":\"read|write\"}'",
            "  ryk decide prompt  --json '{\"text\":\"<text>\"}'",
            "  ryk decide tool    --json '{\"name\":\"<name>\"}'",
            "  ryk decide <kind> --stdin",
            "  ryk decide <kind> --json <payload> [--ci]",
            "Command kind: default shell packs also fence medium+ denials over pure commands.allow (medium→ask, CI→block; high/critical→block). Permanent/allow-once product stores are not loaded on this path.",
            "Default output is stable JSON; add --human for a decision badge, details, and risk meter.",
            "Debug logs go to stderr only.",
        } },
        .{ .name = "evaluate", .summary = "Stable machine API for shell-command evaluation", .usage = "ryk evaluate --json --stdin", .category = .integrations, .details = &.{
            "Reads a versioned JSON request from stdin and evaluates shell_command events via the Zig shell_engine; legacy Rust evaluator selection is rejected.",
            "Requires schema_version=1, kind=shell_command, command string, and an absolute existing cwd.",
            "Always writes the stable integration JSON response to stdout for invalid input and expected evaluator outcomes.",
            "Exit codes: 0 allow, 2 deny, 3 evaluator failure, 64 invalid input, 1 unexpected internal error.",
            "Designed for external integrations such as Pi bash tool-call evaluation; non-shell evaluation is intentionally unsupported.",
        } },
        .{ .name = "hook", .summary = "Receive events from AI agent hosts", .usage = "ryk hook <codex|claude|grok|opencode|openclaw|hermes> <event> [--ci]", .category = .advanced, .details = &.{
            "Reads a JSON payload from stdin, normalizes host-specific events to ryk decisions,",
            "and emits a host-valid JSON response to stdout. Debug logs go to stderr only.",
            "Shell PreToolUse / PermissionRequest (and equivalent host tool-before events) evaluate commands via the in-process Zig shell_engine; legacy Rust evaluator selection is rejected.",
            "Events:",
            "  ryk hook codex SessionStart",
            "  ryk hook codex UserPromptSubmit",
            "  ryk hook codex PreToolUse",
            "  ryk hook codex PermissionRequest",
            "  ryk hook codex PostToolUse",
            "  ryk hook codex Stop",
            "  ryk hook claude SessionStart",
            "  ryk hook claude UserPromptSubmit",
            "  ryk hook claude PreToolUse",
            "  ryk hook claude PermissionRequest",
            "  ryk hook claude PostToolUse",
            "  ryk hook claude SessionEnd",
            "  ryk hook grok PreToolUse",
            "  ryk hook opencode session.created",
            "  ryk hook opencode tool.execute.before",
            "  ryk hook opencode tool.execute.after",
            "  ryk hook opencode permission.asked",
            "  ryk hook opencode permission.replied",
            "  ryk hook opencode file.edited",
            "  ryk hook opencode command.executed",
            "  ryk hook opencode session.updated",
            "  ryk hook opencode session.idle",
            "  ryk hook opencode session.error",
            "  ryk hook opencode shell.env",
            "  ryk hook openclaw session.start",
            "  ryk hook openclaw tool.before",
            "  ryk hook openclaw tool.after",
            "  ryk hook openclaw permission.before",
            "  ryk hook openclaw permission.after",
            "  ryk hook openclaw session.end",
            "  ryk hook hermes on_session_start",
            "  ryk hook hermes pre_tool_call",
            "  ryk hook hermes post_tool_call",
            "  ryk hook hermes pre_llm_call",
            "  ryk hook hermes post_llm_call",
            "  ryk hook hermes subagent_stop",
            "  ryk hook hermes on_session_end",
            "Hook responses include host_limitations to honestly report enforcement limits.",
        } },
        .{ .name = "dashboard", .summary = "Start the local ryk dashboard", .usage = "ryk dashboard [--machine | --workspace PATH] [--host 127.0.0.1] [--port 7742] [--once]", .category = .diagnostics, .details = &.{
            "Starts a localhost-only machine-wide dashboard by default; the view is not tied to shell cwd.",
            "Use --workspace PATH or RYK_DASHBOARD_WORKSPACE for policy, integrations, and workspace-scoped actions.",
            "The dashboard calls existing ryk CLI/Core paths and does not replace policy evaluation.",
            "Mutation routes use a per-run browser token and only expose fixed ryk actions; arbitrary shell commands are not accepted.",
            "Defaults to http://127.0.0.1:7742.",
            "LAN and non-loopback binds (for example 0.0.0.0) are rejected; the dashboard is intentionally localhost-only.",
            "Use --once to serve one request for smoke tests and automation.",
        } },
        .{ .name = "help", .summary = "Show help", .usage = "ryk help [command|--all]", .category = .getting_started, .details = &.{
            "Shows Safe Launch help by default (public verbs only).",
            "Use `ryk help --all` for the full command surface.",
            "Use `ryk help <command>` for command-specific help.",
        } },
    };

/// Prefix of Safe Launch teaching order (host aliases inserted after stop).
const public_help_prefix = [_][]const u8{ "start", "agents", "stop" };
/// Suffix of Safe Launch teaching order (after host aliases).
/// Day-2 loop: doctor → packs → allowlist, then review/forensics/explain/update.
const public_help_suffix = [_][]const u8{ "doctor", "packs", "allowlist", "replay", "scan", "explain", "update", "telemetry" };

pub const WriteMode = enum {
    /// Safe Launch surface only (default `ryk` / `ryk help`).
    public,
    /// Full command surface (`ryk help --all`).
    all,
};

/// Default root help: public Safe Launch verbs only.
pub fn write(io: std.Io, writer: anytype) !void {
    try writeWithMode(io, writer, .public);
}

/// Full root help including advanced / power commands.
pub fn writeAll(io: std.Io, writer: anytype) !void {
    try writeWithMode(io, writer, .all);
}

pub fn writeWithMode(io: std.Io, writer: anytype, mode: WriteMode) !void {
    // Compact brand header (Phase 2 brand cohesion).
    try tui.render.banner(io, writer, build_options.version, null);
    try tui.theme.paint(io, writer, .muted, "Graded policy mediation for AI agent actions");
    try writer.writeAll("\n\n");
    try writer.writeAll("Usage:\n  ryk <command> [options]\n\n");

    // Task-oriented primary paths — Safe Launch loop on default; richer on --all.
    try writer.writeAll("  ");
    try tui.theme.paintBold(io, writer, .brand, "Common tasks");
    try writer.writeAll("\n");
    const Task = struct { label: []const u8, cmd: []const u8 };
    const public_tasks = [_]Task{
        .{ .label = "Get protected", .cmd = "ryk doctor --fix" },
        .{ .label = "Guided setup", .cmd = "ryk start" },
        .{ .label = "Always-on setup", .cmd = "ryk agents setup" },
        .{ .label = "Run an agent", .cmd = "ryk claude  (or: codex | pi | opencode | openclaw | hermes | grok)" },
        .{ .label = "Diagnose", .cmd = "ryk doctor" },
        .{ .label = "Review session", .cmd = "ryk replay" },
        .{ .label = "Why blocked?", .cmd = "ryk explain \"…\"" },
        .{ .label = "Update ryk", .cmd = "ryk update" },
        .{ .label = "Stop protection", .cmd = "ryk stop" },
    };
    const all_tasks = [_]Task{
        .{ .label = "Get protected", .cmd = "ryk doctor --fix" },
        .{ .label = "Guided setup", .cmd = "ryk start" },
        .{ .label = "Always-on setup", .cmd = "ryk agents setup" },
        .{ .label = "Diagnose", .cmd = "ryk doctor" },
        .{ .label = "Why blocked?", .cmd = "ryk explain \"…\"" },
        .{ .label = "Run an agent", .cmd = "ryk claude  (or: codex | pi | opencode | openclaw | hermes | grok)" },
        .{ .label = "Wire a host", .cmd = "ryk plugin install" },
        .{ .label = "Review session", .cmd = "ryk replay" },
        .{ .label = "Stop protection", .cmd = "ryk stop" },
    };
    const tasks: []const Task = switch (mode) {
        .public => &public_tasks,
        .all => &all_tasks,
    };
    var task_label_width: usize = 0;
    for (tasks) |task| {
        const w = tui.render.displayWidth(task.label);
        if (w > task_label_width) task_label_width = w;
    }
    for (tasks) |task| {
        try writer.writeAll("    ");
        try tui.theme.paint(io, writer, .text_bright, task.label);
        try tui.render.writePadded(writer, "", task_label_width - tui.render.displayWidth(task.label) + 2);
        try writer.writeAll(task.cmd);
        try writer.writeAll("\n");
    }
    try writer.writeAll("\n");
    if (mode == .all) {
        // Shell deny remediation via explain; permanent allowlist / allow-once are live CLI verbs.
        try writer.writeAll("  ");
        try tui.theme.paint(io, writer, .muted, "Shell deny remediation: ryk explain \"…\". Policy files: ryk policy explain.");
        try writer.writeAll("\n\n");
    }

    // Compute a uniform command-name column width across listed commands.
    var name_width: usize = 0;
    for (commands) |cmd| {
        if (cmd.hidden) continue;
        if (mode == .public and !cmd.public) continue;
        const w = tui.render.displayWidth(cmd.name);
        if (w > name_width) name_width = w;
    }

    switch (mode) {
        .public => {
            try writer.writeAll("  ");
            try tui.theme.paintBold(io, writer, .brand, "Commands");
            try writer.writeAll("\n");
            // Teaching order: start → stop → host aliases → doctor → replay → explain
            for (public_help_prefix) |name| {
                try writeCommandRow(io, writer, name, name_width);
            }
            for (host_launch.host_launch_aliases) |host| {
                try writeCommandRow(io, writer, host, name_width);
            }
            for (public_help_suffix) |name| {
                try writeCommandRow(io, writer, name, name_width);
            }
            try writer.writeAll("\n");
            try writer.writeAll("  ");
            try tui.theme.paint(io, writer, .muted, "Power features:");
            try writer.writeAll(" ");
            try tui.theme.paint(io, writer, .text_bright, "ryk help --all");
            try writer.writeAll("\n\n");
        },
        .all => {
            const categories = comptime std.enums.values(Category);
            for (categories) |cat| {
                if (cat == .internal) continue; // hide internal group entirely
                var any = false;
                for (commands) |cmd| {
                    if (cmd.hidden or cmd.category != cat) continue;
                    if (!any) {
                        try writer.writeAll("  ");
                        try tui.theme.paintBold(io, writer, .brand, categoryTitle(cat));
                        try writer.writeAll("\n");
                        any = true;
                    }
                    try writer.writeAll("    ");
                    try tui.theme.paint(io, writer, .text_bright, cmd.name);
                    try tui.render.writePadded(writer, "", name_width - tui.render.displayWidth(cmd.name) + 2);
                    try writer.writeAll(cmd.summary);
                    try writer.writeAll("\n");
                }
                if (any) try writer.writeAll("\n");
            }
            // `ryk help --all` holds the long run contract that brief help used to
            // promise (os-sandbox auto degrade / fail-closed / empty-backpack).
            if (findCommand("run")) |run_cmd| {
                try writer.writeAll("  ");
                try tui.theme.paintBold(io, writer, .brand, "run");
                try writer.writeAll("\n");
                for (run_cmd.details) |line| {
                    try writer.print("    {s}\n", .{line});
                }
                try writer.writeAll("\n");
            }
        },
    }

    // Global options (Phase 7 discoverability): surface the --no-rich /
    // RYK_NO_RICH escape hatch at the top level so users can find it without
    // reading the source. --json/--robot are per-command machine flags.
    try writer.writeAll("  ");
    try tui.theme.paintBold(io, writer, .brand, "Global options");
    try writer.writeAll("\n");
    try writer.writeAll("    --no-rich   Plain text output (no colour, no animation). ");
    try tui.theme.paint(io, writer, .muted, "Also RYK_NO_RICH=1.");
    try writer.writeAll("\n");
    try writer.writeAll("                 Use this for piping, scripting, or terminals that mis-render colour.\n");
    try writer.writeAll("    --json      Per-command machine output (byte-stable). See `ryk help <command>`.\n");
    try writer.writeAll("\n");

    // Try-next hint.
    try writer.writeAll("  ");
    try tui.theme.paint(io, writer, .muted, "Next:");
    try writer.writeAll(" run ");
    try tui.theme.paint(io, writer, .text_bright, "ryk start");
    try writer.writeAll(" to get protected, or ");
    if (mode == .public) {
        try tui.theme.paint(io, writer, .text_bright, "ryk help --all");
        try writer.writeAll(" for the full surface.\n");
    } else {
        try tui.theme.paint(io, writer, .text_bright, "ryk help <command>");
        try writer.writeAll(" for details.\n");
    }
}

fn categoryTitle(cat: Category) []const u8 {
    return switch (cat) {
        .getting_started => "Getting Started",
        .core_workflow => "Core Workflow",
        .staged_changes => "Staged Changes",
        .diagnostics => "Diagnostics & Reporting",
        .integrations => "Integrations",
        .advanced => "Advanced",
        .internal => "Internal",
    };
}

fn writeCommandRow(io: std.Io, writer: anytype, name: []const u8, name_width: usize) !void {
    const cmd = findCommand(name) orelse return;
    if (cmd.hidden or !cmd.public) return;
    try writer.writeAll("    ");
    try tui.theme.paint(io, writer, .text_bright, cmd.name);
    try tui.render.writePadded(writer, "", name_width - tui.render.displayWidth(cmd.name) + 2);
    try writer.writeAll(cmd.summary);
    try writer.writeAll("\n");
}

/// Single notice for hard-removed onboarding peers (`setup` / `quickstart`).
/// Used by top-level dispatch and `writeCommand` so wording cannot drift.
pub fn writeRemovedOnboardingPeer(writer: anytype, name: []const u8) !void {
    try writer.print(
        "ryk: `{s}` was removed. Use `ryk start` instead.\nRun 'ryk help start' for usage.\n",
        .{name},
    );
}

pub fn writeRemovedStatus(writer: anytype) !void {
    try writer.writeAll(
        "ryk: `status` was removed. Use `ryk doctor` for diagnostics.\nRun 'ryk help doctor' for usage.\n",
    );
}

pub fn writeCommand(io: std.Io, writer: anytype, name: []const u8) !bool {
    // Progressive disclosure: `ryk help --all` reuses the existing single-arg
    // help dispatch path without changing top-level argv parsing.
    if (std.mem.eql(u8, name, "--all") or std.mem.eql(u8, name, "all")) {
        try writeAll(io, writer);
        return true;
    }
    // Hard-removed onboarding peers: do not re-teach live usage; point at `ryk start`.
    if (std.mem.eql(u8, name, "setup") or std.mem.eql(u8, name, "quickstart")) {
        try writeRemovedOnboardingPeer(writer, name);
        return true;
    }
    if (std.mem.eql(u8, name, "status")) {
        try writeRemovedStatus(writer);
        return true;
    }
    const command = findCommand(name) orelse return false;
    try writer.print("{s}\n\nUsage:\n  {s}\n\n", .{ command.summary, command.usage });

    if (command.examples.len > 0) {
        try writer.writeAll("Examples:\n");
        for (command.examples) |example| {
            try writer.print("  {s}\n", .{example});
        }
        try writer.writeAll("\n");
    }

    for (command.details) |line| {
        try writer.print("{s}\n", .{line});
    }
    return true;
}

pub fn findCommand(name: []const u8) ?CommandInfo {
    for (commands) |command| {
        if (std.mem.eql(u8, command.name, name)) return command;
    }
    return null;
}

test "run help documents --os-sandbox auto degrade and fail-closed paths" {
    const info = findCommand("run") orelse return error.TestUnexpectedResult;
    var joined: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&joined);
    for (info.details) |line| {
        try w.writeAll(line);
        try w.writeAll("\n");
    }
    const text = w.buffered();
    var printed_buf: [8192]u8 = undefined;
    var printed_w: std.Io.Writer = .fixed(&printed_buf);
    try std.testing.expect(try writeCommand(std.testing.io, &printed_w, "run"));
    const printed = printed_w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, text, "--os-sandbox auto|on|off") != null);
    // Happy path: no required sandbox flags for protected launch.
    try std.testing.expect(std.mem.indexOf(u8, text, "no flags required") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "ryk <agent>") != null);
    // Three auto outcomes (Z-6): degrade when no backend plan; scrub fail-closed; attach fail-closed.
    try std.testing.expect(std.mem.indexOf(u8, text, "degrades loudly when no backend plan exists") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "fails closed on incomplete env scrub/allowlist") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "fails closed if attach fails after materials are prepared") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "--seatbelt-profile compatible|hardened|strict") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "default hardened") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "--with-host-secrets") != null);
    try std.testing.expect(std.mem.indexOf(u8, printed, "--os-sandbox auto|on|off") != null);
    try std.testing.expect(std.mem.indexOf(u8, printed, "degrades loudly when no backend plan exists") != null);
    try std.testing.expect(std.mem.indexOf(u8, printed, "fails closed on incomplete env scrub/allowlist") != null);
    try std.testing.expect(std.mem.indexOf(u8, printed, "fails closed if attach fails after materials are prepared") != null);
    try std.testing.expect(std.mem.indexOf(u8, printed, "empty-backpack") != null);
    var lists_escape = false;
    for (info.additional_completion_flags) |flag| {
        if (std.mem.eql(u8, flag, "--with-host-secrets")) lists_escape = true;
    }
    try std.testing.expect(lists_escape);
    // Primary examples are host aliases / bare run — not multi-flag probe recipes.
    try std.testing.expectEqualStrings("ryk claude", info.examples[0]);
    try std.testing.expectEqualStrings("ryk run -- <custom-command>", info.examples[2]);
}

test "mode option lists include yolo" {
    const run_info = findCommand("run") orelse return error.TestUnexpectedResult;
    var run_joined: [4096]u8 = undefined;
    var run_w: std.Io.Writer = .fixed(&run_joined);
    for (run_info.details) |line| {
        try run_w.writeAll(line);
        try run_w.writeAll("\n");
    }
    try std.testing.expect(std.mem.indexOf(u8, run_w.buffered(), "observe|ask|yolo|strict|ci") != null);

    // init parser rejects yolo — usage must match the live option set (not advertise it).
    const init_info = findCommand("init") orelse return error.TestUnexpectedResult;
    try std.testing.expect(std.mem.indexOf(u8, init_info.usage, "yolo") == null);
    try std.testing.expect(std.mem.indexOf(u8, init_info.usage, "strict|ask|observe|ci|trusted") != null);

    const policy_info = findCommand("policy") orelse return error.TestUnexpectedResult;
    var policy_joined: [4096]u8 = undefined;
    var policy_w: std.Io.Writer = .fixed(&policy_joined);
    for (policy_info.details) |line| {
        try policy_w.writeAll(line);
        try policy_w.writeAll("\n");
    }
    try std.testing.expect(std.mem.indexOf(u8, policy_w.buffered(), "observe|ask|yolo|strict|ci|redteam|trusted") != null);

    const mcp_info = findCommand("mcp") orelse return error.TestUnexpectedResult;
    var mcp_joined: [4096]u8 = undefined;
    var mcp_w: std.Io.Writer = .fixed(&mcp_joined);
    for (mcp_info.details) |line| {
        try mcp_w.writeAll(line);
        try mcp_w.writeAll("\n");
    }
    try std.testing.expect(std.mem.indexOf(u8, mcp_w.buffered(), "observe|ask|yolo|strict|ci") != null);
}

test "host launch allowlist is the single source for help alias entries" {
    for (host_launch.host_launch_aliases) |host| {
        const info = findCommand(host) orelse {
            std.debug.print("missing help entry for host launch alias: {s}\n", .{host});
            try std.testing.expect(false);
            return;
        };
        try std.testing.expectEqualStrings(host, info.name);
        try std.testing.expect(std.mem.indexOf(u8, info.summary, host) != null);
        try std.testing.expect(std.mem.indexOf(u8, info.usage, host) != null);
        try std.testing.expect(std.mem.indexOf(u8, info.details[0], "Public protected launch path") != null);
        try std.testing.expect(std.mem.indexOf(u8, info.details[1], "network allowlist") != null);
        try std.testing.expect(std.mem.indexOf(u8, info.details[1], "empty-backpack") != null);
        try std.testing.expect(std.mem.indexOf(u8, info.details[1], "secretless stays off unless") != null);
        try std.testing.expect(std.mem.indexOf(u8, info.details[1], "network ask") == null);
    }
    try std.testing.expect(findCommand("notanagent") == null);
    try std.testing.expect(!host_launch.isHostLaunchAlias("notanagent"));
}

test "top help and per-host help surface claude and pi aliases" {
    var buf: [24576]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try write(std.testing.io, &writer);
    const top = writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, top, "claude") != null);
    try std.testing.expect(std.mem.indexOf(u8, top, "pi") != null);
    try std.testing.expect(std.mem.indexOf(u8, top, "ryk claude") != null);

    writer = .fixed(&buf);
    try std.testing.expect(try writeCommand(std.testing.io, &writer, "claude"));
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "ryk claude") != null);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "Public protected launch path") != null);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "network allowlist") != null);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "empty-backpack") != null);

    writer = .fixed(&buf);
    try std.testing.expect(try writeCommand(std.testing.io, &writer, "pi"));
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "ryk pi") != null);
}

/// True when root help lists `name` as a left-column peer command (not Common tasks / prose).
fn helpListsPeerCommand(text: []const u8, name: []const u8) bool {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "    ")) continue;
        if (std.mem.startsWith(u8, line, "    --")) continue;
        const rest = line[4..];
        if (rest.len <= name.len) continue;
        if (std.mem.startsWith(u8, rest, name) and rest[name.len] == ' ') return true;
    }
    return false;
}

test "default root help shows only public Safe Launch verbs" {
    var buf: [24576]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try write(std.testing.io, &writer);
    const top = writer.buffered();

    // Public Safe Launch verbs as command peers
    try std.testing.expect(helpListsPeerCommand(top, "start"));
    try std.testing.expect(helpListsPeerCommand(top, "stop"));
    try std.testing.expect(helpListsPeerCommand(top, "doctor"));
    try std.testing.expect(helpListsPeerCommand(top, "packs"));
    try std.testing.expect(helpListsPeerCommand(top, "allowlist"));
    try std.testing.expect(helpListsPeerCommand(top, "replay"));
    try std.testing.expect(helpListsPeerCommand(top, "scan"));
    try std.testing.expect(helpListsPeerCommand(top, "explain"));
    try std.testing.expect(helpListsPeerCommand(top, "update"));
    for (host_launch.host_launch_aliases) |host| {
        try std.testing.expect(helpListsPeerCommand(top, host));
    }

    // Teaching suffix order: doctor → packs → allowlist → replay → …
    const doctor_i = std.mem.indexOf(u8, top, "\n    doctor ").?;
    const packs_i = std.mem.indexOf(u8, top, "\n    packs ").?;
    const allowlist_i = std.mem.indexOf(u8, top, "\n    allowlist ").?;
    const replay_i = std.mem.indexOf(u8, top, "\n    replay ").?;
    try std.testing.expect(doctor_i < packs_i);
    try std.testing.expect(packs_i < allowlist_i);
    try std.testing.expect(allowlist_i < replay_i);

    // Common tasks teach start → agent → doctor → replay → update
    try std.testing.expect(std.mem.indexOf(u8, top, "ryk start") != null);
    try std.testing.expect(std.mem.indexOf(u8, top, "ryk doctor") != null);
    try std.testing.expect(std.mem.indexOf(u8, top, "ryk replay") != null);
    try std.testing.expect(std.mem.indexOf(u8, top, "ryk update") != null);
    try std.testing.expect(std.mem.indexOf(u8, top, "ryk claude") != null);
    try std.testing.expect(std.mem.indexOf(u8, top, "ryk status") == null);

    // Progressive disclosure escape hatch
    try std.testing.expect(std.mem.indexOf(u8, top, "help --all") != null);

    // Not Getting Started / public peers — allow/unallow stay advanced
    try std.testing.expect(!helpListsPeerCommand(top, "quickstart"));
    try std.testing.expect(!helpListsPeerCommand(top, "setup"));
    try std.testing.expect(!helpListsPeerCommand(top, "status"));
    try std.testing.expect(!helpListsPeerCommand(top, "init"));
    try std.testing.expect(!helpListsPeerCommand(top, "run"));
    try std.testing.expect(!helpListsPeerCommand(top, "history"));
    try std.testing.expect(!helpListsPeerCommand(top, "policy"));
    try std.testing.expect(!helpListsPeerCommand(top, "mcp"));
    try std.testing.expect(!helpListsPeerCommand(top, "allow"));
    try std.testing.expect(!helpListsPeerCommand(top, "unallow"));
    try std.testing.expect(!helpListsPeerCommand(top, "allow-once"));
}

test "help --all lists full advanced command surface" {
    var buf: [32768]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try std.testing.expect(try writeCommand(std.testing.io, &writer, "--all"));
    const all = writer.buffered();

    try std.testing.expect(helpListsPeerCommand(all, "start"));
    try std.testing.expect(helpListsPeerCommand(all, "run"));
    try std.testing.expect(helpListsPeerCommand(all, "doctor"));
    try std.testing.expect(helpListsPeerCommand(all, "policy"));
    try std.testing.expect(helpListsPeerCommand(all, "init"));
    try std.testing.expect(helpListsPeerCommand(all, "mcp"));
    try std.testing.expect(helpListsPeerCommand(all, "env"));
    // Live Zig daemon-stop remains on the advanced surface.
    try std.testing.expect(helpListsPeerCommand(all, "shutdown"));
    // Hard-removed peers: not listed as live usage on help --all
    try std.testing.expect(!helpListsPeerCommand(all, "quickstart"));
    try std.testing.expect(!helpListsPeerCommand(all, "setup"));
    // Unavailable ports are not product surface.
    try std.testing.expect(!helpListsPeerCommand(all, "history"));
    // scan is public Zig session forensics (not the old daemon file scan).
    try std.testing.expect(helpListsPeerCommand(all, "scan"));
    // Live P0: packs, allow-once, permanent allowlist writers.
    try std.testing.expect(helpListsPeerCommand(all, "packs"));
    try std.testing.expect(helpListsPeerCommand(all, "allow-once"));
    try std.testing.expect(helpListsPeerCommand(all, "allowlist"));
    try std.testing.expect(helpListsPeerCommand(all, "allow"));
    try std.testing.expect(helpListsPeerCommand(all, "unallow"));
    try std.testing.expect(std.mem.indexOf(u8, all, "degrades loudly when no backend plan exists") != null);
    try std.testing.expect(std.mem.indexOf(u8, all, "fails closed on incomplete env scrub/allowlist") != null);
    try std.testing.expect(std.mem.indexOf(u8, all, "empty-backpack") != null);
}

test "help setup and quickstart print removal notice pointing at start" {
    var buf: [1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try std.testing.expect(try writeCommand(std.testing.io, &writer, "setup"));
    const setup_out = writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, setup_out, "removed") != null);
    try std.testing.expect(std.mem.indexOf(u8, setup_out, "ryk start") != null);
    try std.testing.expect(std.mem.indexOf(u8, setup_out, "ryk setup --") == null);

    writer = .fixed(&buf);
    try std.testing.expect(try writeCommand(std.testing.io, &writer, "quickstart"));
    const qs_out = writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, qs_out, "removed") != null);
    try std.testing.expect(std.mem.indexOf(u8, qs_out, "ryk start") != null);
    try std.testing.expect(std.mem.indexOf(u8, qs_out, "ryk quickstart --") == null);
}

test "help status print removal notice pointing at doctor" {
    var buf: [1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try std.testing.expect(try writeCommand(std.testing.io, &writer, "status"));
    const out = writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "removed") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "ryk doctor") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "ryk status --") == null);
}

// ---------------------------------------------------------------------------
// Slice 1 (P0 honesty) — public help set tells the truth about live verbs.
// Hide-list = unavailable daemon ports. Live P0: packs, allow-once, allowlist/
// allow/unallow, shutdown.
// ---------------------------------------------------------------------------

/// Unavailable daemon-stub ports (plan hide-list). Not product surface.
/// `scan` was removed — it is now live Zig session forensics.
const p0_honesty_hide_list = [_][]const u8{
    "precommit",
    "simulate",
    "classify",
    "suggest-allowlist",
    "history",
    "rebase-recover",
    "config",
};

/// Formerly unfinished P0 verbs — now all live (empty sentinel for omit tests).
const p0_honesty_unfinished = [_][]const u8{};

test "P0 honesty: hide-list verbs are marked hidden; live P0 + shutdown are not" {
    for (p0_honesty_hide_list) |name| {
        const info = findCommand(name) orelse {
            std.debug.print("missing help entry for hide-list command: {s}\n", .{name});
            try std.testing.expect(false);
            return;
        };
        try std.testing.expect(info.hidden);
    }

    const shutdown_info = findCommand("shutdown") orelse return error.TestUnexpectedResult;
    try std.testing.expect(!shutdown_info.hidden);
    const packs_info = findCommand("packs") orelse return error.TestUnexpectedResult;
    try std.testing.expect(!packs_info.hidden);
    const allow_once_info = findCommand("allow-once") orelse return error.TestUnexpectedResult;
    try std.testing.expect(!allow_once_info.hidden);
    const allowlist_info = findCommand("allowlist") orelse return error.TestUnexpectedResult;
    try std.testing.expect(!allowlist_info.hidden);
    const allow_info = findCommand("allow") orelse return error.TestUnexpectedResult;
    try std.testing.expect(!allow_info.hidden);
    const unallow_info = findCommand("unallow") orelse return error.TestUnexpectedResult;
    try std.testing.expect(!unallow_info.hidden);
}

/// True when root help text teaches unfinished/hide-list verbs outside peer rows
/// (e.g. Common-tasks remediation). Peer-column omit alone is not enough: production
/// `writeWithMode(.all)` historically hardcoded `allow-once` / `allowlist (daemon)`.
/// Do **not** ban bare substring `allowlist` — live copy may say `--network allowlist`.
fn helpAdvertisesUnavailableVerb(text: []const u8, name: []const u8) bool {
    // Exact unfinished verb that must never appear once hidden.
    if (std.mem.eql(u8, name, "allow-once")) {
        return std.mem.indexOf(u8, text, "allow-once") != null;
    }
    if (std.mem.eql(u8, name, "allowlist")) {
        // Command teaching / remediation only — not `--network allowlist`.
        if (std.mem.indexOf(u8, text, "ryk allowlist") != null) return true;
        if (std.mem.indexOf(u8, text, "allowlist (daemon)") != null) return true;
        return false;
    }
    if (std.mem.eql(u8, name, "allow")) {
        // Token boundary: "ryk allow" must not match "ryk allowlist" / "ryk allow-once".
        var search: usize = 0;
        while (std.mem.indexOfPos(u8, text, search, "ryk allow")) |idx| {
            const after = idx + "ryk allow".len;
            if (after >= text.len or (!std.ascii.isAlphanumeric(text[after]) and text[after] != '-' and text[after] != '_')) {
                return true;
            }
            search = idx + 1;
        }
        return false;
    }
    // Other hide-list / unfinished: "ryk <verb>" teaching form.
    var needle_buf: [80]u8 = undefined;
    const ryk_cmd = std.fmt.bufPrint(&needle_buf, "ryk {s}", .{name}) catch return true;
    return std.mem.indexOf(u8, text, ryk_cmd) != null;
}

test "P0 honesty: default help and help --all omit hide-list and unfinished P0; still list shutdown" {
    var buf: [32768]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try write(std.testing.io, &writer);
    const top = writer.buffered();

    for (p0_honesty_hide_list) |name| {
        try std.testing.expect(!helpListsPeerCommand(top, name));
        try std.testing.expect(!helpAdvertisesUnavailableVerb(top, name));
    }
    for (p0_honesty_unfinished) |name| {
        try std.testing.expect(!helpListsPeerCommand(top, name));
        try std.testing.expect(!helpAdvertisesUnavailableVerb(top, name));
    }
    // Default Safe Launch help never listed shutdown / allow-once / allow shortcuts.
    // packs + allowlist are public Safe Launch (day-2 protection loop).
    try std.testing.expect(!helpListsPeerCommand(top, "shutdown"));
    try std.testing.expect(helpListsPeerCommand(top, "packs"));
    try std.testing.expect(helpListsPeerCommand(top, "allowlist"));
    try std.testing.expect(!helpListsPeerCommand(top, "allow-once"));
    try std.testing.expect(!helpListsPeerCommand(top, "allow"));
    try std.testing.expect(!helpListsPeerCommand(top, "unallow"));

    writer = .fixed(&buf);
    try writeAll(std.testing.io, &writer);
    const all = writer.buffered();

    for (p0_honesty_hide_list) |name| {
        try std.testing.expect(!helpListsPeerCommand(all, name));
        try std.testing.expect(!helpAdvertisesUnavailableVerb(all, name));
    }
    for (p0_honesty_unfinished) |name| {
        try std.testing.expect(!helpListsPeerCommand(all, name));
        try std.testing.expect(!helpAdvertisesUnavailableVerb(all, name));
    }
    try std.testing.expect(helpListsPeerCommand(all, "shutdown"));
    try std.testing.expect(helpListsPeerCommand(all, "packs"));
    try std.testing.expect(helpListsPeerCommand(all, "allowlist"));
    try std.testing.expect(helpListsPeerCommand(all, "allow-once"));

    // Explicit full-text: root --all must not teach daemon allowlist wording or
    // promote allow/unallow shortcuts in Common-tasks / remediation copy.
    try std.testing.expect(std.mem.indexOf(u8, all, "allowlist (daemon)") == null);
    try std.testing.expect(std.mem.indexOf(u8, all, "ryk unallow") == null);
    // "ryk allow " teaches the allow shortcut; does not match allowlist / allow-once.
    try std.testing.expect(std.mem.indexOf(u8, all, "ryk allow ") == null);
    // Live advanced verbs appear as peer columns on --all (name only; usage is per-command).
    // helpListsPeerCommand already asserted packs / allowlist / allow-once above.

    // Live product verbs remain discoverable on the full surface.
    try std.testing.expect(helpListsPeerCommand(all, "test"));
    try std.testing.expect(helpListsPeerCommand(all, "explain"));
    try std.testing.expect(helpListsPeerCommand(all, "start"));
}

test "public Safe Launch: packs and allowlist help details mention TTY browse and --plain" {
    const packs_info = findCommand("packs") orelse return error.TestUnexpectedResult;
    try std.testing.expect(packs_info.public);
    try std.testing.expect(!packs_info.hidden);
    var packs_blob: [4096]u8 = undefined;
    var packs_w: std.Io.Writer = .fixed(&packs_blob);
    for (packs_info.details) |line| {
        try packs_w.writeAll(line);
        try packs_w.writeAll("\n");
    }
    const packs_text = packs_w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, packs_text, "TTY") != null or std.mem.indexOf(u8, packs_text, "browse") != null);
    try std.testing.expect(std.mem.indexOf(u8, packs_text, "--plain") != null);

    const allowlist_info = findCommand("allowlist") orelse return error.TestUnexpectedResult;
    try std.testing.expect(allowlist_info.public);
    try std.testing.expect(!allowlist_info.hidden);
    var allow_blob: [4096]u8 = undefined;
    var allow_w: std.Io.Writer = .fixed(&allow_blob);
    for (allowlist_info.details) |line| {
        try allow_w.writeAll(line);
        try allow_w.writeAll("\n");
    }
    const allow_text = allow_w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, allow_text, "TTY") != null or std.mem.indexOf(u8, allow_text, "browse") != null);
    try std.testing.expect(std.mem.indexOf(u8, allow_text, "--plain") != null);

    // Shortcuts stay non-public
    const allow_info = findCommand("allow") orelse return error.TestUnexpectedResult;
    try std.testing.expect(!allow_info.public);
    const unallow_info = findCommand("unallow") orelse return error.TestUnexpectedResult;
    try std.testing.expect(!unallow_info.public);
}

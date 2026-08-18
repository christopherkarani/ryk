const std = @import("std");
const schema = @import("schema.zig");

pub const Preset = enum {
    observe,
    ask,
    /// YOLO + seatbelt: `mode: yolo` with the same conservative rule body as ask/strict.
    yolo,
    strict,
    ci,
    redteam,
    trusted,

    pub fn parse(value: []const u8) ?Preset {
        inline for (@typeInfo(Preset).@"enum".fields) |field| {
            if (std.mem.eql(u8, value, field.name)) return @enumFromInt(field.value);
        }
        return null;
    }
};

pub const AgentPreset = enum {
    generic_agent,
    claude_code,
    codex,
    cursor_agent,
    opencode,
    cline_roo,
    mcp_dev,
    github_actions,
    solo_dev,
    strict_local,
    team_ci,
    openclaw_hermes,
    unattended,
    trusted_local,
    no_external_comms,

    pub fn parse(value: []const u8) ?AgentPreset {
        for (agent_preset_infos) |info| {
            if (std.mem.eql(u8, value, info.name)) return info.preset;
        }
        return null;
    }
};

pub const AgentPresetInfo = struct {
    preset: AgentPreset,
    name: []const u8,
    experimental: bool,
    warning: []const u8,
};

pub const agent_preset_infos = [_]AgentPresetInfo{
    .{ .preset = .generic_agent, .name = "generic-agent", .experimental = false, .warning = "" },
    .{ .preset = .claude_code, .name = "claude-code", .experimental = true, .warning = "claude-code is a generic/experimental preset; review assumptions before trusting it." },
    .{ .preset = .codex, .name = "codex", .experimental = true, .warning = "codex is a generic/experimental preset; review assumptions before trusting it." },
    .{ .preset = .cursor_agent, .name = "cursor-agent", .experimental = true, .warning = "cursor-agent is a generic/experimental preset; review assumptions before trusting it." },
    .{ .preset = .opencode, .name = "opencode", .experimental = true, .warning = "opencode is a generic/experimental preset; review assumptions before trusting it." },
    .{ .preset = .cline_roo, .name = "cline-roo", .experimental = true, .warning = "cline-roo is a generic/experimental preset; review assumptions before trusting it." },
    .{ .preset = .mcp_dev, .name = "mcp-dev", .experimental = false, .warning = "" },
    .{ .preset = .github_actions, .name = "github-actions", .experimental = false, .warning = "" },
    .{ .preset = .solo_dev, .name = "solo-dev", .experimental = false, .warning = "" },
    .{ .preset = .strict_local, .name = "strict-local", .experimental = false, .warning = "" },
    .{ .preset = .team_ci, .name = "team-ci", .experimental = false, .warning = "" },
    .{ .preset = .openclaw_hermes, .name = "openclaw-hermes", .experimental = false, .warning = "" },
    .{ .preset = .unattended, .name = "unattended", .experimental = false, .warning = "" },
    .{ .preset = .trusted_local, .name = "trusted-local", .experimental = false, .warning = "" },
    .{ .preset = .no_external_comms, .name = "no-external-comms", .experimental = false, .warning = "" },
};

pub fn agentPresetName(preset: AgentPreset) []const u8 {
    return agentPresetInfo(preset).name;
}

pub fn agentPresetInfo(preset: AgentPreset) AgentPresetInfo {
    for (agent_preset_infos) |info| {
        if (info.preset == preset) return info;
    }
    unreachable;
}

pub fn agentPresetText(preset: AgentPreset) []const u8 {
    return switch (preset) {
        .generic_agent => generic_agent_policy,
        .claude_code => claude_code_policy,
        .codex => codex_policy,
        .cursor_agent => cursor_agent_policy,
        .opencode => opencode_policy,
        .cline_roo => cline_roo_policy,
        .mcp_dev => mcp_dev_policy,
        .github_actions => github_actions_policy,
        .solo_dev => solo_dev_policy,
        .strict_local => strict_local_policy,
        .team_ci => team_ci_policy,
        .openclaw_hermes => openclaw_hermes_policy,
        .unattended => unattended_policy,
        .trusted_local => trusted_local_policy,
        .no_external_comms => no_external_comms_policy,
    };
}

fn stringListEqual(left: []const []const u8, right: []const []const u8) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| {
        if (!std.mem.eql(u8, a, b)) return false;
    }
    return true;
}

fn ruleSetEqual(left: schema.RuleSet, right: schema.RuleSet) bool {
    return left.default == right.default and
        stringListEqual(left.allow, right.allow) and
        stringListEqual(left.deny, right.deny) and
        stringListEqual(left.ask, right.ask);
}

/// Equality for the security-reviewed unattended contract. Source paths,
/// allocators, and YAML formatting are intentionally ignored; every policy
/// decision surface is compared against the canonical preset semantics.
pub fn unattendedSemanticsEqual(left: *const schema.Policy, right: *const schema.Policy) bool {
    if (left.version_value != right.version_value or left.mode != right.mode) return false;
    if (!std.mem.eql(u8, left.workspace.root, right.workspace.root) or
        left.workspace.write_mode != right.workspace.write_mode) return false;
    if (left.env.inherit != right.env.inherit or left.env.default != right.env.default or
        !stringListEqual(left.env.allow, right.env.allow) or
        !stringListEqual(left.env.deny_patterns, right.env.deny_patterns) or
        !stringListEqual(left.env.ask, right.env.ask)) return false;
    if (left.files.write_mode != right.files.write_mode or
        !ruleSetEqual(left.files.read, right.files.read) or
        !ruleSetEqual(left.files.write, right.files.write) or
        !ruleSetEqual(left.commands, right.commands)) return false;
    if (left.network.effectiveMode() != right.network.effectiveMode() or
        left.network.effectiveBackend() != right.network.effectiveBackend() or
        left.network.default != right.network.default or
        !stringListEqual(left.network.allow, right.network.allow) or
        !stringListEqual(left.network.deny, right.network.deny) or
        !stringListEqual(left.network.ask, right.network.ask) or
        left.network.detect_exfiltration.dns != right.network.detect_exfiltration.dns or
        left.network.detect_exfiltration.long_query_strings != right.network.detect_exfiltration.long_query_strings or
        left.network.detect_exfiltration.secret_patterns != right.network.detect_exfiltration.secret_patterns) return false;
    if (left.credentials.default_broker != null or right.credentials.default_broker != null or
        left.credentials.brokers.len != 0 or right.credentials.brokers.len != 0 or
        left.credentials.refs.len != 0 or right.credentials.refs.len != 0 or
        left.credentials.grants.len != 0 or right.credentials.grants.len != 0 or
        left.services.len != 0 or right.services.len != 0) return false;
    if (!ruleSetEqual(left.mcp, right.mcp)) return false;
    if (left.effects.configured != right.effects.configured or
        left.effects.default != right.effects.default or
        left.effects.classifier != right.effects.classifier or
        !stringListEqual(left.effects.allow, right.effects.allow) or
        !stringListEqual(left.effects.deny, right.effects.deny) or
        !stringListEqual(left.effects.ask, right.effects.ask)) return false;
    return left.audit.level == right.audit.level and
        left.audit.redact_secrets == right.audit.redact_secrets and
        left.audit.tamper_evident == right.audit.tamper_evident;
}

pub fn text(preset: Preset) []const u8 {
    return switch (preset) {
        .observe => observe_policy,
        .ask => ask_policy,
        .yolo => yolo_policy,
        .strict => strict_policy,
        .ci => ci_policy,
        .redteam => redteam_policy,
        .trusted => trusted_policy,
    };
}

pub fn defaultPreset() Preset {
    return .strict;
}

const generic_agent_policy =
    \\# ryk preset: generic-agent
    \\# Coding DCG defaults: normal work allows; packs/hard fence block danger; no ask main loop.
    \\# mode strict + empty commands.allow (matrix-only) + commands.default allow.
    \\
++ coding_dcg_policy;

const claude_code_policy =
    \\# ryk preset: claude-code
    \\# Generic/experimental coding DCG defaults (not private Claude Code internals).
    \\
++ coding_dcg_policy;

const codex_policy =
    \\# ryk preset: codex
    \\# Generic/experimental coding DCG defaults for local Codex-style work.
    \\
++ coding_dcg_policy;

const cursor_agent_policy =
    \\# ryk preset: cursor-agent
    \\# Generic/experimental coding DCG defaults for local editor-agent work.
    \\
++ coding_dcg_policy;

const opencode_policy =
    \\# ryk preset: opencode
    \\# Generic/experimental coding DCG defaults for local coding-agent work.
    \\
++ coding_dcg_policy;

const cline_roo_policy =
    \\# ryk preset: cline-roo
    \\# Generic/experimental coding DCG defaults for local editor agents with MCP-style extensions.
    \\
++ coding_dcg_policy;

const mcp_dev_policy =
    \\# ryk preset: mcp-dev
    \\# Coding DCG defaults for developing stdio MCP servers through ryk.
    \\# Manifests still need explicit command/hash binding; this policy does not trust servers by name alone.
    \\
++ coding_dcg_policy;

const github_actions_policy =
    \\# ryk preset: github-actions
    \\# CI-safe preset. CI mode never prompts; ask-class decisions are denied unless explicitly allowed.
    \\# Do not put workflow tokens or repository secrets in this policy.
    \\
++ ci_policy;

const solo_dev_policy =
    \\# ryk policy pack: solo-dev
    \\# Coding DCG local development pack for one developer. Secret and destructive-action denies stay active.
    \\
++ coding_dcg_policy;

const strict_local_policy =
    \\# ryk preset: strict-local
    \\# Local strict mode. Unknown actions are denied or staged; add narrow allow rules as needed.
    \\
++ strict_policy;

const no_external_comms_policy =
    \\# ryk preset: no-external-comms
    \\# Strict local baseline plus effect-class denials for messaging, social publish, and payments.
    \\# Blocks tools like send_email / send_imessage / post_twitter by semantic effect, not exact tool names.
    \\
++ strict_policy ++
    \\
    \\effects:
    \\  default: allow
    \\  deny:
    \\    - comms.message
    \\    - comms.publish
    \\    - money.transfer
    \\  ask:
    \\    - unknown.external
    \\    - identity.auth
    \\    - device.control
    \\
;

const team_ci_policy =
    \\# ryk policy pack: team-ci
    \\# CI-safe team baseline. Ask-class decisions deny in CI; core safety and redteam commands are allowed.
    \\
++ ci_policy;

const openclaw_hermes_policy =
    \\# ryk policy pack: openclaw-hermes
    \\# Local plugin workflow pack for OpenClaw and Hermes hook development.
    \\
++ ask_policy;

const unattended_policy =
    \\# ryk preset: unattended
    \\# Fail-closed baseline for Hermes/OpenClaw and other agents running without an operator.
    \\# Every unmatched or approval-class action is denied; this preset never waits for an operator.
    \\
    \\version: 1
    \\mode: strict
    \\
    \\workspace:
    \\  root: "."
    \\  write_mode: staged
    \\
    \\env:
    \\  inherit: false
    \\  default: deny
    \\  allow:
    \\    - PATH
    \\    - HOME
    \\    - LANG
    \\    - TERM
    \\    - RYK_UNATTENDED
    \\    - RYK_NONINTERACTIVE
    \\    - RYK_CI
    \\    - CI
    \\    - RYK_HERMES_UNATTENDED
    \\    - RYK_OPENCLAW_UNATTENDED
    \\  deny_patterns:
    \\    - "*TOKEN*"
    \\    - "*SECRET*"
    \\    - "*PASSWORD*"
    \\    - "*PASSWD*"
    \\    - "*PRIVATE*"
    \\    - "*KEY*"
    \\    - "AWS_*"
    \\    - "AZURE_*"
    \\    - "GITHUB_TOKEN"
    \\    - "GH_TOKEN"
    \\    - "OPENAI_API_KEY"
    \\    - "ANTHROPIC_API_KEY"
    \\    - "NPM_TOKEN"
    \\    - "PYPI_TOKEN"
    \\    - "SSH_AUTH_SOCK"
    \\
    \\files:
    \\  read:
    \\    default: deny
    \\    allow:
    \\      - "./**"
    \\    deny:
    \\      - "./.env"
    \\      - "./.env.*"
    \\      - "**/.env"
    \\      - "**/.env.*"
    \\      - "./.git/**"
    \\      - ".git/**"
    \\      - "**/.git/**"
    \\      - "./.ryk/**"
    \\      - ".ryk/**"
    \\      - "**/.ryk/**"
    \\      - "**/.npmrc"
    \\      - "**/.pypirc"
    \\      - "**/.netrc"
    \\      - "~/.ssh/**"
    \\      - "~/.aws/**"
    \\      - "~/.config/gh/**"
    \\      - "**/*credentials*"
    \\      - "**/*credential*"
    \\      - "**/*secret*"
    \\      - "**/*token*"
    \\  write:
    \\    default: deny
    \\    deny:
    \\      - "./.git/**"
    \\      - ".git/**"
    \\      - "**/.git/**"
    \\      - "./.ryk/**"
    \\      - ".ryk/**"
    \\      - "**/.ryk/**"
    \\      - "./.env"
    \\      - "./.env.*"
    \\      - "**/.env"
    \\      - "**/.env.*"
    \\      - "**/.npmrc"
    \\      - "**/.pypirc"
    \\      - "**/.netrc"
    \\      - "**/*credentials*"
    \\      - "**/*credential*"
    \\      - "**/*secret*"
    \\      - "**/*token*"
    \\    mode: staged
    \\
    \\commands:
    \\  default: deny
    \\  allow:
    \\    - "git status"
    \\    - "ls *"
    \\    - "pwd"
    \\    - "which *"
    \\    - "node --version"
    \\    - "python3 --version"
    \\    - "zig version"
    \\    - "ryk version"
    \\    - "ryk doctor"
    \\    - "ryk doctor --json"
    \\    - "ryk explain *"
    \\  deny:
    \\    - "rm -rf *"
    \\    - "find * -delete"
    \\    - "shred *"
    \\    - "curl * | sh"
    \\    - "wget * | bash"
    \\    - "sudo *"
    \\    - "su *"
    \\    - "doas *"
    \\    - "cat .env"
    \\    - "cat ~/.ssh/*"
    \\
    \\network:
    \\  mode: allowlist
    \\  default: deny
    \\  allow:
    \\    - "api.github.com"
    \\    - "*.github.com"
    \\    - "registry.npmjs.org"
    \\    - "pypi.org"
    \\  deny:
    \\    - "pastebin.com"
    \\    - "*.ngrok.io"
    \\    - "*.requestbin.net"
    \\  detect_exfiltration:
    \\    dns: true
    \\    long_query_strings: true
    \\    secret_patterns: true
    \\
    \\mcp:
    \\  default: deny
    \\  allow:
    \\    - "*.search_*"
    \\    - "*.list_*"
    \\    - "*.get_*"
    \\    - "glob"
    \\    - "grep"
    \\    - "list"
    \\    - "read"
    \\    - "todowrite"
    \\    - "todoread"
    \\  deny:
    \\    - "*.delete_*"
    \\    - "*.shell"
    \\    - "*.run_command"
    \\
    \\effects:
    \\  default: deny
    \\  allow:
    \\    - fs.read
    \\    - shell.exec
    \\
    \\audit:
    \\  level: full
    \\  redact_secrets: true
    \\  tamper_evident: true
    \\
;

const trusted_local_policy =
    \\# ryk preset: trusted-local
    \\# Less restrictive local preset for trusted repositories. Secret redaction and deny rules remain enabled.
    \\
++ trusted_policy;

const common_strict_rules =
    \\workspace:
    \\  root: "."
    \\  write_mode: staged
    \\
    \\env:
    \\  inherit: false
    \\  allow:
    \\    - PATH
    \\    - HOME
    \\    - LANG
    \\    - TERM
    \\    - RYK_UNATTENDED
    \\    - RYK_OPENCLAW_UNATTENDED
    \\  deny_patterns:
    \\    - "*TOKEN*"
    \\    - "*SECRET*"
    \\    - "*PASSWORD*"
    \\    - "*PASSWD*"
    \\    - "*PRIVATE*"
    \\    - "*KEY*"
    \\    - "AWS_*"
    \\    - "AZURE_*"
    \\    - "GITHUB_TOKEN"
    \\    - "GH_TOKEN"
    \\    - "OPENAI_API_KEY"
    \\    - "ANTHROPIC_API_KEY"
    \\    - "GOOGLE_API_KEY"
    \\    - "GOOGLE_APPLICATION_CREDENTIALS"
    \\    - "NPM_TOKEN"
    \\    - "PYPI_TOKEN"
    \\    - "SSH_AUTH_SOCK"
    \\
    \\files:
    \\  read:
    \\    allow:
    \\      - "./**"
    \\    deny:
    \\      - "./.env"
    \\      - "./.env.*"
    \\      - "~/.ssh/**"
    \\      - "~/.aws/**"
    \\      - "~/.gcloud/**"
    \\      - "~/.azure/**"
    \\      - "~/.config/gh/**"
    \\      - "~/Library/Keychains/**"
    \\      - "./Library/Keychains/**"
    \\      - "~/Library/Application Support/**/Cookies*"
    \\      - "./Library/Application Support/**/Cookies*"
    \\      - "~/Library/Application Support/**/Login Data*"
    \\      - "./Library/Application Support/**/Login Data*"
    \\      - "~/Library/Application Support/Google/Chrome/**"
    \\      - "./Library/Application Support/Google/Chrome/**"
    \\      - "~/Library/Application Support/BraveSoftware/**"
    \\      - "./Library/Application Support/BraveSoftware/**"
    \\      - "~/Library/Application Support/Firefox/**"
    \\      - "./Library/Application Support/Firefox/**"
    \\      - "~/Library/Mobile Documents/**"
    \\      - "./Library/Mobile Documents/**"
    \\      - "~/.zsh_history"
    \\      - "~/.bash_history"
    \\      - "~/.zshrc"
    \\      - "~/.bashrc"
    \\      - "~/.profile"
    \\      - "**/id_rsa"
    \\      - "**/id_ed25519"
    \\      - "**/*credentials*"
    \\      - "**/*credential*"
    \\      - "**/*secret*"
    \\      - "**/*token*"
    \\  write:
    \\    allow:
    \\      - "./**"
    \\    deny:
    \\      # Dual patterns for robustness across hook/plugin path normalizations.
    \\      - "./.git/**"
    \\      - ".git/**"
    \\      - "./.ryk/**"
    \\      - ".ryk/**"
    \\    mode: staged
    \\
    \\commands:
    \\  default: ask
    \\  # Agents default permit (strict list; packs + hard fence still apply).
    \\  # Unquoted && chains are on-list only when every segment matches.
    \\  # Not a free pass: high/medium pack hits still matrix-block under strict.
    \\  allow:
    \\    # Workspace / inspect
    \\    - "cd *"
    \\    - "mkdir *"
    \\    - "touch *"
    \\    - "cp *"
    \\    - "mv *"
    \\    - "rmdir *"
    \\    - "cat *"
    \\    - "head *"
    \\    - "tail *"
    \\    - "file *"
    \\    - "stat *"
    \\    - "which *"
    \\    - "whoami"
    \\    - "id"
    \\    - "uname *"
    \\    - "date"
    \\    - "umask"
    \\    - "umask *"
    \\    - "ls"
    \\    - "ls *"
    \\    - "pwd"
    \\    - "echo *"
    \\    - "/usr/bin/env"
    \\    - "true"
    \\    - "false"
    \\    - "rg *"
    \\    - "grep *"
    \\    - "find *"
    \\    - "wc *"
    \\    - "sort *"
    \\    - "uniq *"
    \\    - "sed -n *"
    \\    - "curl *"
    \\    - "wget *"
    \\    # Git (local read/write; no bare git *; push stays ask)
    \\    - "git status"
    \\    - "git status*"
    \\    - "git diff"
    \\    - "git diff *"
    \\    - "git log"
    \\    - "git log *"
    \\    - "git branch"
    \\    - "git branch *"
    \\    - "git ls-files"
    \\    - "git ls-files *"
    \\    - "git add *"
    \\    - "git commit *"
    \\    - "git show *"
    \\    - "git stash *"
    \\    - "git fetch *"
    \\    - "git pull *"
    \\    - "git merge *"
    \\    - "git remote *"
    \\    - "git tag *"
    \\    - "git cherry-pick *"
    \\    - "git init"
    \\    - "git clone *"
    \\    - "git rev-parse *"
    \\    - "git merge-base *"
    \\    - "git checkout *"
    \\    - "git switch *"
    \\    - "git restore *"
    \\    # GitHub CLI (narrow; no blanket gh api *)
    \\    - "gh auth status"
    \\    - "gh pr *"
    \\    - "gh issue *"
    \\    # Language / test / build
    \\    - "zig version"
    \\    - "zig build"
    \\    - "zig build *"
    \\    - "zig fmt"
    \\    - "zig fmt *"
    \\    - "npm test*"
    \\    - "npm run *"
    \\    - "pnpm test*"
    \\    - "pnpm run *"
    \\    - "yarn test*"
    \\    - "yarn run *"
    \\    - "go test"
    \\    - "go test *"
    \\    - "go build"
    \\    - "go build *"
    \\    - "go run"
    \\    - "go run *"
    \\    - "go fmt"
    \\    - "go fmt *"
    \\    - "cargo test"
    \\    - "cargo test *"
    \\    - "cargo build"
    \\    - "cargo build *"
    \\    - "cargo run"
    \\    - "cargo run *"
    \\    - "cargo fmt"
    \\    - "cargo check"
    \\    - "cargo clippy"
    \\    - "swift test*"
    \\    - "swift build"
    \\    - "swift build *"
    \\    - "tsc"
    \\    - "tsc *"
    \\    - "python --version"
    \\    - "python3 --version"
    \\    - "python -m pytest*"
    \\    - "python3 -m pytest*"
    \\    - "pytest"
    \\    - "pytest *"
    \\    - "node --version"
    \\    - "make test*"
    \\    - "make build*"
    \\    - "make check*"
    \\    - "./scripts/zig *"
    \\    # Ryk recovery / inspect. `ryk allow-once` is intentionally NOT
    \\    # auto-allowed: redemption is operator-only (TTY-gated) and runs
    \\    # outside the managed session, so it falls through to `ask`.
    \\    - "ryk version"
    \\    - "ryk help *"
    \\    - "ryk doctor *"
    \\    - "ryk explain *"
    \\    - "ryk allowlist *"
    \\    - "ryk packs *"
    \\  deny:
    \\    - "rm -rf *"
    \\    - "find * -delete"
    \\    - "shred *"
    \\    - "curl * | sh"
    \\    - "wget * | bash"
    \\    - "sudo *"
    \\    - "su *"
    \\    - "doas *"
    \\    - "powershell *EncodedCommand*"
    \\    - "powershell *-enc*"
    \\    - "cat .env"
    \\    - "cat ~/.ssh/*"
    \\  ask:
    \\    - "npm install*"
    \\    - "pnpm install*"
    \\    - "yarn install*"
    \\    - "pip install*"
    \\    - "git push*"
    \\
    \\network:
    \\  mode: allowlist
    \\  default: deny
    \\  allow:
    \\    - "api.github.com"
    \\    - "*.github.com"
    \\    - "registry.npmjs.org"
    \\    - "pypi.org"
    \\  ask:
    \\    - "*.githubusercontent.com"
    \\  deny:
    \\    - "pastebin.com"
    \\    - "*.ngrok.io"
    \\    - "*.requestbin.net"
    \\  detect_exfiltration:
    \\    dns: true
    \\    long_query_strings: true
    \\    secret_patterns: true
    \\
    \\mcp:
    \\  default: ask
    \\  allow:
    \\    - "*.search_*"
    \\    - "*.list_*"
    \\    - "*.get_*"
    \\    - "glob"
    \\    - "grep"
    \\    - "list"
    \\    - "read"
    \\    - "todowrite"
    \\    - "todoread"
    \\    - "skill"
    \\    - "task"
    \\    - "question"
    \\    - "lsp"
    \\  deny:
    \\    - "*.delete_*"
    \\    - "*.shell"
    \\    - "*.run_command"
    \\
    \\audit:
    \\  level: full
    \\  redact_secrets: true
    \\  tamper_evident: true
    \\
;

/// Coding-agent DCG body (fork of common_strict_rules, not a shared empty-allow edit).
/// mode strict + empty commands.allow → matrix-only (no strict off-list refuse).
/// commands.default allow → unmatched shell is not approval-gated.
/// Packs + hard fence block high/critical; deny patterns keep catastrophes out.
/// yolo/strict-local/ask keep common_strict_rules (sample allow lists intact).
const coding_dcg_rules =
    \\workspace:
    \\  root: "."
    \\  write_mode: staged
    \\
    \\env:
    \\  inherit: false
    \\  allow:
    \\    - PATH
    \\    - HOME
    \\    - LANG
    \\    - TERM
    \\    - RYK_UNATTENDED
    \\    - RYK_OPENCLAW_UNATTENDED
    \\  deny_patterns:
    \\    - "*TOKEN*"
    \\    - "*SECRET*"
    \\    - "*PASSWORD*"
    \\    - "*PASSWD*"
    \\    - "*PRIVATE*"
    \\    - "*KEY*"
    \\    - "AWS_*"
    \\    - "AZURE_*"
    \\    - "GITHUB_TOKEN"
    \\    - "GH_TOKEN"
    \\    - "OPENAI_API_KEY"
    \\    - "ANTHROPIC_API_KEY"
    \\    - "GOOGLE_API_KEY"
    \\    - "GOOGLE_APPLICATION_CREDENTIALS"
    \\    - "NPM_TOKEN"
    \\    - "PYPI_TOKEN"
    \\    - "SSH_AUTH_SOCK"
    \\
    \\files:
    \\  read:
    \\    allow:
    \\      - "./**"
    \\    deny:
    \\      - "./.env"
    \\      - "./.env.*"
    \\      - "~/.ssh/**"
    \\      - "~/.aws/**"
    \\      - "~/.gcloud/**"
    \\      - "~/.azure/**"
    \\      - "~/.config/gh/**"
    \\      - "~/Library/Keychains/**"
    \\      - "./Library/Keychains/**"
    \\      - "~/Library/Application Support/**/Cookies*"
    \\      - "./Library/Application Support/**/Cookies*"
    \\      - "~/Library/Application Support/**/Login Data*"
    \\      - "./Library/Application Support/**/Login Data*"
    \\      - "~/Library/Application Support/Google/Chrome/**"
    \\      - "./Library/Application Support/Google/Chrome/**"
    \\      - "~/Library/Application Support/BraveSoftware/**"
    \\      - "./Library/Application Support/BraveSoftware/**"
    \\      - "~/Library/Application Support/Firefox/**"
    \\      - "./Library/Application Support/Firefox/**"
    \\      - "~/Library/Mobile Documents/**"
    \\      - "./Library/Mobile Documents/**"
    \\      - "~/.zsh_history"
    \\      - "~/.bash_history"
    \\      - "~/.zshrc"
    \\      - "~/.bashrc"
    \\      - "~/.profile"
    \\      - "**/id_rsa"
    \\      - "**/id_ed25519"
    \\      - "**/*credentials*"
    \\      - "**/*credential*"
    \\      - "**/*secret*"
    \\      - "**/*token*"
    \\  write:
    \\    allow:
    \\      - "./**"
    \\    deny:
    \\      # Dual patterns for robustness across hook/plugin path normalizations.
    \\      - "./.git/**"
    \\      - ".git/**"
    \\      - "./.ryk/**"
    \\      - ".ryk/**"
    \\      - "./.env"
    \\      - "./.env.*"
    \\      - "**/.env"
    \\      - "**/.env.*"
    \\    mode: staged
    \\
    \\commands:
    \\  default: allow
    \\  # Matrix-only Strict: empty commands.allow disables off-list refuse.
    \\  # Packs + hard fence block high/critical; deny patterns for catastrophes.
    \\  # Unmatched shell allows — normal coding work is not approval-gated.
    \\  deny:
    \\    - "rm -rf *"
    \\    - "find * -delete"
    \\    - "shred *"
    \\    - "curl * | sh"
    \\    - "wget * | bash"
    \\    - "sudo *"
    \\    - "su *"
    \\    - "doas *"
    \\    - "powershell *EncodedCommand*"
    \\    - "powershell *-enc*"
    \\    - "cat .env"
    \\    - "cat ~/.ssh/*"
    \\
    \\network:
    \\  mode: allowlist
    \\  default: deny
    \\  allow:
    \\    - "api.github.com"
    \\    - "*.github.com"
    \\    - "registry.npmjs.org"
    \\    - "pypi.org"
    \\  ask:
    \\    - "*.githubusercontent.com"
    \\  deny:
    \\    - "pastebin.com"
    \\    - "*.ngrok.io"
    \\    - "*.requestbin.net"
    \\  detect_exfiltration:
    \\    dns: true
    \\    long_query_strings: true
    \\    secret_patterns: true
    \\
    \\mcp:
    \\  default: ask
    \\  allow:
    \\    - "*.search_*"
    \\    - "*.list_*"
    \\    - "*.get_*"
    \\    - "glob"
    \\    - "grep"
    \\    - "list"
    \\    - "read"
    \\    - "todowrite"
    \\    - "todoread"
    \\    - "skill"
    \\    - "task"
    \\    - "question"
    \\    - "lsp"
    \\  deny:
    \\    - "*.delete_*"
    \\    - "*.shell"
    \\    - "*.run_command"
    \\
    \\audit:
    \\  level: full
    \\  redact_secrets: true
    \\  tamper_evident: true
    \\
;

/// Coding create-path product body: strict matrix-only + allow default (DCG-like).
pub const coding_dcg_policy =
    \\version: 1
    \\mode: strict
    \\
++ coding_dcg_rules;

pub const strict_policy =
    \\version: 1
    \\mode: strict
    \\
++ common_strict_rules;

pub const ci_policy =
    \\version: 1
    \\mode: ci
    \\
++ common_strict_rules;

pub const ask_policy =
    \\version: 1
    \\mode: ask
    \\
++ common_strict_rules;

/// YOLO + seatbelt hero preset: same conservative rule body as ask/strict, `mode: yolo`.
/// Shares the ask severity matrix under sandbox + hard fence; not refuse-all.
pub const yolo_policy =
    \\# ryk preset: yolo
    \\# YOLO + seatbelt: autonomous local agent under sandbox and hard fence.
    \\# Severity matrix matches ask (not refuse-all). Critical/catastrophe always denied.
    \\# Sticky trust (once/session/effect-class) may skip re-ask after user allow — never for hard fence.
    \\
    \\version: 1
    \\mode: yolo
    \\
++ common_strict_rules;

pub const observe_policy =
    \\version: 1
    \\mode: observe
    \\
    \\workspace:
    \\  root: "."
    \\  write_mode: staged
    \\
    \\env:
    \\  inherit: true
    \\  deny_patterns:
    \\    - "*TOKEN*"
    \\    - "*SECRET*"
    \\    - "*PASSWORD*"
    \\    - "*PASSWD*"
    \\    - "*PRIVATE*"
    \\    - "*KEY*"
    \\    - "AWS_*"
    \\    - "AZURE_*"
    \\    - "GITHUB_TOKEN"
    \\    - "GH_TOKEN"
    \\    - "OPENAI_API_KEY"
    \\    - "ANTHROPIC_API_KEY"
    \\    - "GOOGLE_API_KEY"
    \\    - "GOOGLE_APPLICATION_CREDENTIALS"
    \\    - "NPM_TOKEN"
    \\    - "PYPI_TOKEN"
    \\    - "SSH_AUTH_SOCK"
    \\
    \\files:
    \\  read:
    \\    default: observe
    \\    deny:
    \\      - "~/.ssh/**"
    \\      - "~/.aws/**"
    \\      - "~/.gcloud/**"
    \\      - "~/.azure/**"
    \\      - "~/.config/gh/**"
    \\      - "./.env"
    \\      - "./.env.*"
    \\  write:
    \\    default: observe
    \\    mode: staged
    \\
    \\commands:
    \\  default: observe
    \\  deny:
    \\    - "rm -rf *"
    \\
    \\network:
    \\  mode: observe
    \\  default: observe
    \\  deny:
    \\    - "pastebin.com"
    \\    - "*.ngrok.io"
    \\    - "*.requestbin.net"
    \\  detect_exfiltration:
    \\    dns: true
    \\    long_query_strings: true
    \\    secret_patterns: true
    \\
    \\mcp:
    \\  default: observe
    \\
    \\audit:
    \\  level: full
    \\  redact_secrets: true
    \\  tamper_evident: true
    \\
;

pub const redteam_policy =
    \\version: 1
    \\mode: redteam
    \\
++ common_strict_rules;

pub const trusted_policy =
    \\version: 1
    \\mode: trusted
    \\
    \\workspace:
    \\  root: "."
    \\  write_mode: staged
    \\
    \\env:
    \\  inherit: true
    \\  deny_patterns:
    \\    - "*TOKEN*"
    \\    - "*SECRET*"
    \\    - "*PASSWORD*"
    \\    - "*PASSWD*"
    \\    - "*PRIVATE*"
    \\    - "*KEY*"
    \\    - "AWS_*"
    \\    - "AZURE_*"
    \\    - "GITHUB_TOKEN"
    \\    - "GH_TOKEN"
    \\    - "OPENAI_API_KEY"
    \\    - "ANTHROPIC_API_KEY"
    \\    - "GOOGLE_API_KEY"
    \\    - "GOOGLE_APPLICATION_CREDENTIALS"
    \\    - "NPM_TOKEN"
    \\    - "PYPI_TOKEN"
    \\    - "SSH_AUTH_SOCK"
    \\
    \\files:
    \\  read:
    \\    allow:
    \\      - "./**"
    \\    deny:
    \\      - "~/.ssh/**"
    \\      - "~/.aws/**"
    \\      - "~/.gcloud/**"
    \\      - "~/.azure/**"
    \\      - "~/.config/gh/**"
    \\      - "./.env"
    \\      - "./.env.*"
    \\  write:
    \\    allow:
    \\      - "./**"
    \\    deny:
    \\      # Dual patterns for robustness across hook/plugin path normalizations.
    \\      - "./.git/**"
    \\      - ".git/**"
    \\      - "./.ryk/**"
    \\      - ".ryk/**"
    \\    mode: staged
    \\
    \\commands:
    \\  default: allow
    \\  deny:
    \\    - "rm -rf *"
    \\    - "curl * | sh"
    \\    - "sudo *"
    \\
    \\network:
    \\  default: ask
    \\  allow:
    \\    - "api.github.com"
    \\    - "registry.npmjs.org"
    \\
    \\mcp:
    \\  default: ask
    \\
    \\audit:
    \\  level: full
    \\  redact_secrets: true
    \\  tamper_evident: true
    \\
;

test "built-in presets expose required phase 07 policies" {
    try std.testing.expect(std.mem.indexOf(u8, text(.observe), "mode: observe") != null);
    try std.testing.expect(std.mem.indexOf(u8, text(.ask), "mode: ask") != null);
    try std.testing.expect(std.mem.indexOf(u8, text(.yolo), "mode: yolo") != null);
    try std.testing.expect(std.mem.indexOf(u8, text(.strict), "mode: strict") != null);
    try std.testing.expect(std.mem.indexOf(u8, text(.ci), "mode: ci") != null);
}

test "yolo preset is YOLO seatbelt with mode yolo and sample allowlist body" {
    try std.testing.expectEqual(Preset.yolo, Preset.parse("yolo").?);
    const source = text(.yolo);
    try std.testing.expect(std.mem.indexOf(u8, source, "mode: yolo") != null);
    try std.testing.expect(std.mem.indexOf(u8, source, "YOLO") != null);
    // Inherits common_strict_rules permit sample (same body as strict/ask).
    try std.testing.expect(std.mem.indexOf(u8, source, "commands:") != null);
    try std.testing.expect(std.mem.indexOf(u8, source, "git status") != null);

    const load = @import("load.zig");
    var policy = try load.parseFromSlice(std.testing.allocator, source, "builtin:yolo");
    defer policy.deinit();
    try std.testing.expectEqual(schema.Mode.yolo, policy.mode);
}

test "strict preset documents mode strict and commands.allow sample" {
    const source = text(.strict);
    try std.testing.expect(std.mem.indexOf(u8, source, "mode: strict") != null);
    try std.testing.expect(std.mem.indexOf(u8, source, "commands:") != null);
    try std.testing.expect(std.mem.indexOf(u8, source, "  allow:") != null);
    try std.testing.expect(std.mem.indexOf(u8, source, "git status") != null);
}

test "phase 18 agent presets are exposed with stable names" {
    try std.testing.expectEqual(@as(usize, 15), agent_preset_infos.len);
    try std.testing.expectEqual(AgentPreset.generic_agent, AgentPreset.parse("generic-agent").?);
    try std.testing.expectEqual(AgentPreset.github_actions, AgentPreset.parse("github-actions").?);
    try std.testing.expectEqual(AgentPreset.solo_dev, AgentPreset.parse("solo-dev").?);
    try std.testing.expectEqual(AgentPreset.strict_local, AgentPreset.parse("strict-local").?);
    try std.testing.expectEqual(AgentPreset.team_ci, AgentPreset.parse("team-ci").?);
    try std.testing.expectEqual(AgentPreset.openclaw_hermes, AgentPreset.parse("openclaw-hermes").?);
    try std.testing.expectEqual(AgentPreset.unattended, AgentPreset.parse("unattended").?);
    try std.testing.expectEqual(AgentPreset.no_external_comms, AgentPreset.parse("no-external-comms").?);
    try std.testing.expect(AgentPreset.parse("not-a-preset") == null);
    for (agent_preset_infos) |info| {
        const source = agentPresetText(info.preset);
        try std.testing.expect(std.mem.indexOf(u8, source, "version: 1") != null);
        try std.testing.expect(std.mem.indexOf(u8, source, "redact_secrets: true") != null);
    }
}

test "unattended preset is strict and never prompts" {
    const source = agentPresetText(.unattended);
    try std.testing.expect(std.mem.indexOf(u8, source, "# ryk preset: unattended") != null);
    try std.testing.expect(std.mem.indexOf(u8, source, "mode: strict") != null);
    try std.testing.expect(std.mem.indexOf(u8, source, "default: ask") == null);

    const load = @import("load.zig");
    var policy = try load.parseFromSlice(std.testing.allocator, source, "preset:unattended");
    defer policy.deinit();
    try std.testing.expectEqual(@import("schema.zig").Mode.strict, policy.mode);
    try std.testing.expectEqual(@import("schema.zig").DecisionValue.deny, policy.env.default.?);
    try std.testing.expectEqual(@import("schema.zig").DecisionValue.deny, policy.files.read.default.?);
    try std.testing.expectEqual(@import("schema.zig").DecisionValue.deny, policy.files.write.default.?);
    try std.testing.expectEqual(@import("schema.zig").DecisionValue.deny, policy.commands.default.?);
    try std.testing.expectEqual(@import("schema.zig").DecisionValue.deny, policy.network.default.?);
    try std.testing.expectEqual(@import("schema.zig").DecisionValue.deny, policy.mcp.default.?);
    try std.testing.expect(policy.effects.configured);
    try std.testing.expectEqual(@import("schema.zig").DecisionValue.deny, policy.effects.default.?);
    try std.testing.expectEqual(@as(usize, 0), policy.commands.ask.len);
    try std.testing.expectEqual(@as(usize, 0), policy.network.ask.len);
    try std.testing.expectEqual(@as(usize, 0), policy.mcp.ask.len);
    try std.testing.expectEqual(@as(usize, 0), policy.effects.ask.len);
    try std.testing.expectEqual(@as(usize, 0), policy.files.write.allow.len);
    try std.testing.expect(std.mem.indexOf(u8, source, "**/.git/**") != null);
    try std.testing.expect(std.mem.indexOf(u8, source, "**/.npmrc") != null);
    try std.testing.expect(std.mem.indexOf(u8, source, "npm test") == null);
    try std.testing.expect(std.mem.indexOf(u8, source, "zig build test") == null);
    try std.testing.expect(std.mem.indexOf(u8, source, "git diff *") == null);
}

test "unattended embedded and on-disk presets have the same reviewed semantics" {
    const load = @import("load.zig");
    var embedded = try load.loadAgentPreset(std.testing.allocator, .unattended);
    defer embedded.deinit();
    var disk = try load.loadFile(
        std.testing.io,
        std.testing.allocator,
        "policies/presets/unattended.yaml",
    );
    defer disk.deinit();
    try std.testing.expect(unattendedSemanticsEqual(&embedded, &disk));
}

test "no-external-comms preset includes effect denials" {
    const source = agentPresetText(.no_external_comms);
    try std.testing.expect(std.mem.indexOf(u8, source, "effects:") != null);
    try std.testing.expect(std.mem.indexOf(u8, source, "comms.message") != null);
    try std.testing.expect(std.mem.indexOf(u8, source, "comms.publish") != null);
    try std.testing.expect(std.mem.indexOf(u8, source, "money.transfer") != null);

    const load = @import("load.zig");
    var policy = try load.parseFromSlice(std.testing.allocator, source, "no-external-comms.yaml");
    defer policy.deinit();
    try std.testing.expect(policy.effects.isActive());

    const evaluate = @import("evaluate.zig");
    const core = @import("../core/public.zig");
    var denied = try evaluate.tool(&policy, "send_email", std.testing.allocator);
    defer denied.deinit(std.testing.allocator);
    try std.testing.expectEqual(core.decision.DecisionResult.deny, denied.decision.result);
}

test "no-external-comms on-disk YAML matches embedded effect rules" {
    const load = @import("load.zig");
    const evaluate = @import("evaluate.zig");
    const core = @import("../core/public.zig");

    var embedded = try load.parseFromSlice(
        std.testing.allocator,
        agentPresetText(.no_external_comms),
        "embedded-no-external-comms.yaml",
    );
    defer embedded.deinit();

    const on_disk_paths = [_][]const u8{
        "policies/presets/no-external-comms.yaml",
        "examples/policies/no-external-comms.yaml",
    };
    for (on_disk_paths) |path| {
        const text_bytes = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, std.testing.allocator, .limited(1024 * 1024));
        defer std.testing.allocator.free(text_bytes);
        var disk = try load.parseFromSlice(std.testing.allocator, text_bytes, path);
        defer disk.deinit();

        try std.testing.expect(disk.effects.isActive());
        try std.testing.expectEqual(embedded.effects.default, disk.effects.default);
        try std.testing.expectEqual(embedded.effects.deny.len, disk.effects.deny.len);
        try std.testing.expectEqual(embedded.effects.ask.len, disk.effects.ask.len);
        for (embedded.effects.deny, disk.effects.deny) |a, b| {
            try std.testing.expectEqualStrings(a, b);
        }
        for (embedded.effects.ask, disk.effects.ask) |a, b| {
            try std.testing.expectEqualStrings(a, b);
        }

        var denied = try evaluate.tool(&disk, "send_email", std.testing.allocator);
        defer denied.deinit(std.testing.allocator);
        try std.testing.expectEqual(core.decision.DecisionResult.deny, denied.decision.result);
    }
}

// Quick-install DX invariants: coding create-path presets (generic-agent via coding_dcg_rules)
// stay conservative on network + secrets while using DCG matrix-only command defaults.
// openclaw_hermes still inherits common_strict_rules (ask body).
test "quick install agent presets have conservative defaults (network deny + broad secret protection)" {
    const generic = agentPresetText(.generic_agent);
    const codex = agentPresetText(.codex);
    const openclaw = agentPresetText(.openclaw_hermes);

    // Network: default deny is the deliberate quick-install conservative choice (not ask).
    try std.testing.expect(std.mem.indexOf(u8, generic, "default: deny") != null);
    try std.testing.expect(std.mem.indexOf(u8, codex, "default: deny") != null);

    // Broad secret read protections that distinguish the embedded quick-install variant
    // (histories + macOS Library paths + expanded credential patterns).
    try std.testing.expect(std.mem.indexOf(u8, generic, "~/.zsh_history") != null);
    try std.testing.expect(std.mem.indexOf(u8, generic, "~/Library/Application Support/**/Login Data*") != null);
    try std.testing.expect(std.mem.indexOf(u8, generic, "**/*credential*") != null);

    // Protected write directories present (the DX fix will make these robust to bare paths too).
    try std.testing.expect(std.mem.indexOf(u8, generic, "./.git/**") != null);
    try std.testing.expect(std.mem.indexOf(u8, generic, "./.ryk/**") != null);

    // Same invariants for other quick-install used presets that inherit common_strict_rules.
    try std.testing.expect(std.mem.indexOf(u8, openclaw, "default: deny") != null);
    try std.testing.expect(std.mem.indexOf(u8, openclaw, "~/.zsh_history") != null);

    // Dual bare paths for control dirs (hook/plugin path normalizations).
    try std.testing.expect(std.mem.indexOf(u8, generic, ".git/**") != null);
    try std.testing.expect(std.mem.indexOf(u8, generic, ".ryk/**") != null);
    // Coding DCG: catastrophe deny patterns retained; no fat commands.allow sample.
    try std.testing.expect(std.mem.indexOf(u8, generic, "rm -rf *") != null);
    try std.testing.expect(std.mem.indexOf(u8, generic, "mode: strict") != null);
    // Must not ship unrestricted interpreter / blanket git shells.
    try std.testing.expect(std.mem.indexOf(u8, generic, "    - \"python3 *\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, generic, "    - \"bash *\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, generic, "    - \"git *\"") == null);
}

/// Coding create-path DCG contract: mode strict, empty commands.allow (matrix-only),
/// commands.default = allow (never ask). High/critical → block/deny, not ask.
const coding_dcg_agent_presets = [_]AgentPreset{
    .generic_agent,
    .claude_code,
    .codex,
    .cursor_agent,
    .opencode,
    .cline_roo,
    .solo_dev,
    .mcp_dev,
};

test "coding agent presets are DCG matrix-only strict (no ask default, empty allow)" {
    const load = @import("load.zig");
    const evaluate = @import("evaluate.zig");
    const core = @import("../core/public.zig");

    for (coding_dcg_agent_presets) |preset| {
        const source = agentPresetText(preset);
        try std.testing.expect(std.mem.indexOf(u8, source, "mode: strict") != null);

        var policy = try load.parseFromSlice(std.testing.allocator, source, "coding-dcg-test");
        defer policy.deinit();

        try std.testing.expectEqual(schema.Mode.strict, policy.mode);
        try std.testing.expectEqual(@as(usize, 0), policy.commands.allow.len);
        try std.testing.expectEqual(schema.DecisionValue.allow, policy.commands.default.?);
        // No ask spam lists required for default experience.
        try std.testing.expectEqual(@as(usize, 0), policy.commands.ask.len);

        // Unmatched / normal shell is not approval-gated.
        var normal = try evaluate.command(&policy, "chmod -R 777 .", std.testing.allocator);
        defer normal.deinit(std.testing.allocator);
        try std.testing.expectEqual(core.decision.DecisionResult.allow, normal.decision.result);
        try std.testing.expect(!normal.decision.requires_user);

        // Catastrophe / high-risk → block (deny), never ask.
        var wiped = try evaluate.command(&policy, "rm -rf /", std.testing.allocator);
        defer wiped.deinit(std.testing.allocator);
        try std.testing.expectEqual(core.decision.DecisionResult.deny, wiped.decision.result);
        try std.testing.expect(!wiped.decision.requires_user);

        var hard_reset = try evaluate.command(&policy, "git reset --hard", std.testing.allocator);
        defer hard_reset.deinit(std.testing.allocator);
        // Pack/matrix path may differ; rule-surface must not ask.
        try std.testing.expect(hard_reset.decision.result != .ask);
        try std.testing.expect(!hard_reset.decision.requires_user);
    }
}

test "openclaw_hermes remains ask_policy (not coding DCG)" {
    const load = @import("load.zig");
    const source = agentPresetText(.openclaw_hermes);
    try std.testing.expect(std.mem.indexOf(u8, source, "mode: ask") != null);

    var policy = try load.parseFromSlice(std.testing.allocator, source, "openclaw-hermes-ask");
    defer policy.deinit();
    try std.testing.expectEqual(schema.Mode.ask, policy.mode);
    // Still has sample allow list / ask-oriented defaults (not empty matrix-only).
    try std.testing.expect(policy.commands.allow.len > 0);
    try std.testing.expectEqual(schema.DecisionValue.ask, policy.commands.default.?);
}

test "generic-agent on-disk YAML matches coding DCG embedded contract" {
    const load = @import("load.zig");
    var embedded = try load.loadAgentPreset(std.testing.allocator, .generic_agent);
    defer embedded.deinit();
    var disk = try load.loadFile(
        std.testing.io,
        std.testing.allocator,
        "policies/presets/generic-agent.yaml",
    );
    defer disk.deinit();

    try std.testing.expectEqual(schema.Mode.strict, embedded.mode);
    try std.testing.expectEqual(schema.Mode.strict, disk.mode);
    try std.testing.expectEqual(@as(usize, 0), embedded.commands.allow.len);
    try std.testing.expectEqual(@as(usize, 0), disk.commands.allow.len);
    try std.testing.expectEqual(schema.DecisionValue.allow, embedded.commands.default.?);
    try std.testing.expectEqual(schema.DecisionValue.allow, disk.commands.default.?);
}

fn writeDenyHas(policy: *const schema.Policy, want: []const u8) bool {
    for (policy.files.write.deny) |pattern| {
        if (std.mem.eql(u8, pattern, want)) return true;
    }
    return false;
}

test "coding DCG files.write deny covers .env patterns on embedded and generic-agent.yaml" {
    const load = @import("load.zig");
    const evaluate = @import("evaluate.zig");
    const core = @import("../core/public.zig");

    var embedded = try load.loadAgentPreset(std.testing.allocator, .generic_agent);
    defer embedded.deinit();
    var disk = try load.loadFile(
        std.testing.io,
        std.testing.allocator,
        "policies/presets/generic-agent.yaml",
    );
    defer disk.deinit();

    const expected = [_][]const u8{ "./.env", "./.env.*", "**/.env", "**/.env.*" };
    for (expected) |pattern| {
        try std.testing.expect(writeDenyHas(&embedded, pattern));
        try std.testing.expect(writeDenyHas(&disk, pattern));
    }

    var env_write = try evaluate.fileWrite(&embedded, "./.env", std.testing.allocator);
    defer env_write.deinit(std.testing.allocator);
    try std.testing.expectEqual(core.decision.DecisionResult.deny, env_write.decision.result);
    try std.testing.expect(env_write.decision.rule_id != null);
    try std.testing.expect(std.mem.startsWith(u8, env_write.decision.rule_id.?, "files.write.deny"));

    var env_local = try evaluate.fileWrite(&embedded, "./.env.local", std.testing.allocator);
    defer env_local.deinit(std.testing.allocator);
    try std.testing.expectEqual(core.decision.DecisionResult.deny, env_local.decision.result);

    var nested_env = try evaluate.fileWrite(&embedded, "./src/.env", std.testing.allocator);
    defer nested_env.deinit(std.testing.allocator);
    try std.testing.expectEqual(core.decision.DecisionResult.deny, nested_env.decision.result);

    var ok_write = try evaluate.fileWrite(&embedded, "./src/ok.zig", std.testing.allocator);
    defer ok_write.deinit(std.testing.allocator);
    try std.testing.expect(ok_write.decision.result != .deny);
}

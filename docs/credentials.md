# Credential Guardrails

ryk implements defense-in-depth credential protection across eight layers. This document describes how each layer works, what patterns are detected, and how to configure credential management.

## Overview

When you run an AI agent through ryk, your environment variables, files, and network requests may contain sensitive credentials. ryk detects and protects these automatically—before they reach the agent process, before they are written to disk, and (for non-allowlisted destinations) before they leave your machine. **Allowlisted HTTPS** still completes by default: network exfiltration detection is **annotate/audit only** (findings are recorded; there is no config switch that denies allowlisted hosts for secret-like URL surfaces).

The protection layers are:

1. [Secret Detection Engine](#1-secret-detection-engine) — Pattern matching for API keys, tokens, and passwords
2. [Environment Variable Filtering](#2-environment-variable-filtering) — Strips secrets before child process spawn
3. [Credential Broker System](#3-credential-broker-system) — Secure resolution without exposing raw values
4. [Policy Validation](#4-policy-validation) — Rejects unsafe credential configurations
5. [Network Exfiltration Detection](#5-network-exfiltration-detection) — Flags secret-like values in visible URL surfaces (annotate/audit by default; does not deny allowlisted hosts by default)
6. [Command Classification](#6-command-classification) — Denies credential inspection commands
7. [File System Guards](#7-file-system-guards) — Blocks access to credential files
8. [Audit Trail Protection](#8-audit-trail-protection) — Redacts secrets before persistence

---

## 1. Secret Detection Engine

**File**: `src/audit/redact_bridge.zig`

The core engine detects and classifies sensitive values using pattern matching and entropy analysis.

### Environment Variable Name Patterns

Names are matched as **underscore-anchored tokens** or **exact aliases**, not as
substring globs (`*PASSWORD*` / `*KEY*`). `AWS_REGION`, `KEYBOARD_LAYOUT`, and
`MONKEY_MODE` are not secret names.

| Pattern | Examples |
|---------|----------|
| `TOKEN`, `*_TOKEN`, `*_TOKEN_*` | `TOKEN`, `GITHUB_TOKEN`, `API_TOKEN`, `NPM_TOKEN` |
| `SECRET`, `*_SECRET`, `*_SECRET_*` | `SECRET`, `AWS_SECRET`, `APP_SECRET`, `AZURE_CLIENT_SECRET` |
| `PASSWORD`, `*_PASSWORD`, `*_PASSWORD_*` | `PASSWORD`, `DB_PASSWORD`, `ADMIN_PASSWORD` |
| Exact `PGPASSWORD` | `PGPASSWORD` |
| `PASSWD`, `*_PASSWD`, `*_PASSWD_*` | `PASSWD`, `ROOT_PASSWD` |
| Exact `MYSQL_PWD` | `MYSQL_PWD` |
| `SECRET_KEY`, `*_SECRET_KEY` | `SECRET_KEY`, `DJANGO_SECRET_KEY` |
| `PRIVATE_KEY`, `*_PRIVATE_KEY` | `PRIVATE_KEY` |
| `API_KEY`, `*_API_KEY` | `API_KEY`, `OPENAI_API_KEY` |
| `*_ACCESS_KEY`, `*_ACCESS_KEY_*` | `AWS_ACCESS_KEY_ID` |
| `*_SIGNING_KEY` | `CUSTOM_SIGNING_KEY` |
| `*_ENCRYPTION_KEY` | `APP_ENCRYPTION_KEY` |
| `*_CLIENT_KEY` | `APP_CLIENT_KEY` |
| Exact `KEY` | `KEY` (not `KEYBOARD_LAYOUT`) |
| `*_CREDENTIALS` | `GOOGLE_APPLICATION_CREDENTIALS` |
| Exact `SSH_AUTH_SOCK` | `SSH_AUTH_SOCK` |

### Value Classification

ryk inspects values and classifies them into specific secret types:

| Secret Type | Pattern | Example |
|-------------|---------|---------|
| **AWS Access Key** | `AKIA` or `ASIA` prefix, 20 chars | `AKIAIOSFODNN7EXAMPLE` |
| **GitHub Token** | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` prefix (12+ chars) or `github_pat_` (20+ chars) | `ghp_xxxxxxxxxxxxxxxxxxxx` |
| **OpenAI API Key** | `sk-` prefix, 12+ chars | `sk-xxxxxxxxxxxxxxxxxxxx` |
| **Anthropic API Key** | `sk-ant-` prefix, 16+ chars | `sk-ant-xxxxxxxxxxxxxxxx` |
| **Slack Token** | `xoxb-`, `xoxp-`, `xoxa-`, `xoxs-`, `xoxe-` prefix + 12 token chars | `xoxb-fakeSynthetic` |
| **Stripe API Key** | `sk_live_` / `sk_test_` prefix (underscore, not `sk-`) + 8 token chars | `sk_live_fakeSynth` |
| **Hugging Face Token** | `hf_` prefix + 20 token chars (23+ total); excludes `HF_HUB_OFFLINE` / `hf_home_directory` | `hf_fakeSyntheticHuggingFaceTok` |
| **GitLab Token** | `glpat-` prefix + 12 token chars | `glpat-fakeSynthetic` |
| **Azure SAS** | query contains both `sv=` and `sig=`; signature ≥ 16 chars and ≥ 8 distinct (restricted alphabet) | `https://example.invalid/blob?sv=2021-06-08&sig=fakeSyntheticAzureSasSigValue` |
| **JWT** | Three base64url parts separated by dots (each part 4+ chars); first part starts with `eyJ` so dotted rule ids are not classified | `eyJhbG...eyJzdWI...c2lnbmF0dXJl` |
| **PEM Private Key** | `-----BEGIN PRIVATE KEY-----` | RSA/EC private keys |
| **SSH Private Key** | `-----BEGIN OPENSSH PRIVATE KEY-----` | Ed25519/RSA keys |
| **Cloud Credentials JSON** | Contains `"type"` + `"service_account"` or `"private_key"` | Google service account |
| **High-Entropy String** | 32-512 chars, 3+ character classes, 16+ unique chars; `/` allowed (standard base64). Absolute/home/relative path prefixes, `\`, and `:` still skip. | Generic API keys |

### Redaction Format

When a secret is detected, it is replaced with a classification label:

```
[REDACTED:env:GITHUB_TOKEN]
[REDACTED:secret:github_token]
```

Redaction output intentionally omits stable fingerprints. Even a truncated unsalted digest can act as an offline verifier for low-entropy passwords and can correlate the same credential across otherwise unrelated sessions.

### Embedded Secret Detection

The engine also finds secrets embedded in:
- Shell command text (e.g., `echo OPENAI_API_KEY=sk-...`)
- URL query parameters (e.g., `?token=ghp_...`)
- JSON payloads (e.g., `{"api_key":"sk-..."}`)
- Environment variable assignments in strings

---

## 2. Environment Variable Filtering

**File**: `src/intercept/env.zig`

Before launching the agent process, ryk filters the environment variables based on policy mode and detected secrets.

### Filtering Behavior by Mode

| Mode | Behavior |
|------|----------|
| `strict` / `ci` / `redteam` | Removes all secret-like env vars. Only explicitly allowed vars pass through. |
| `ask` | Removes secret-like vars unless explicitly allowed. Prompts for risky ones. |
| `observe` | Passes all vars through but records redactions for audit. |

### Secret Boundary (empty backpack)

**Trusted** agent-primary host launches enter the **empty-backpack** secret boundary by default when the resolved launch binary is a trusted install of a host-launch alias (`claude`, `codex`, `pi`, `opencode`, `openclaw`, `hermes`):

```bash
ryk claude
ryk codex
```

A workspace file named like an agent (`./codex`) is **not** treated as that host: no auto empty-backpack, no host-config RW, no agent network mediation defaults. Use `ryk run --secretless -- <command>` to apply the empty-backpack boundary to a custom/generic command.

In this mode:
- The child env is **public host keys only** from the launch exact allowlist (PATH, HOME, TERM, display, selected proxy/TLS trust keys, etc.) — secret-like names and values are not passed through. Prefix families such as `LC_*` / `XDG_*` are **not** automatically retained unless listed exactly
- Granted `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` values are replaced with session-minted `ryk-secret://session/...` phantoms; free-form references are rejected
- A ryk-owned loopback provider gateway sets `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` and swaps an exact phantom for raw bytes only on the fixed provider upstream
- There is **no** `ryk-secret://local-dummy/...` substitution into the child env
- Raw secret values are never written to policy, audit, or replay artifacts
- An **active OS sandbox is required** (`--os-sandbox off` is rejected; `auto` promotes to required on)
- When OS attach succeeds, workspace `.env` / `.env.*` secret forms are denied at the OS layer (exact safe templates `.env.example` / `.env.sample` / `.env.template` remain readable)
  - **macOS:** basename path-regex deny plus a prepare-time multi-nlink path deny for non-secret names under the workspace (covers outside secret-form inodes hardlinked in under ordinary names). No runtime inode taint after `sandbox_init` (single-writer residual)
  - **Linux protect-on:** FUSE workspace view hides secret basenames and multi-nlink regulars lazily on lookup/open/readdir

**Day-1 agent readiness (read carefully):**

| Fact | Detail |
|------|--------|
| Env contract | Public-only constructed child env plus exact session phantoms for granted model keys |
| Claude / Pi / Codex / OpenCode | Host login remains preferred; empty-backpack Seatbelt grants **narrow RW** to known agent config roots only for a **trusted resolved launch binary** (install-prefix allowlist + table host basename — not `basename(argv0)` alone). Trees include e.g. `~/.claude`, Claude Application Support trees, `~/.codex` — never bare `$HOME`, bare `~/Library`, `Library/Keychains`, or `~/.ssh`. Anthropic/OpenAI env-key clients that honor their base-URL variables use the loopback gateway. For trusted Claude/Codex non-help launches: **usable login material** (non-empty `~/.claude/.credentials.json` / Codex auth markers) **or** a **host-matched** gateway is required; config dir alone fails closed. Basename spoofs do not trigger host auth preflight. **Claude OAuth:** if `claudeAiOauth.expiresAt` is in the past and there is no Anthropic gateway, ryk **fails closed** (clear stderr) instead of blank-hanging after `sandbox=active`. Help/version-only (`--help` / `-h` / `--version`) skips both missing-auth and stale-OAuth preflights so self-contained `--help` still works. Residual hang risk remains when expiry is missing/unparseable, refresh might work but is not relied on, Keychain-only auth is needed, or the host agent hangs for network reasons. **Identity residuals:** `$HOME/.local/bin` over-trust (FP); installs outside allowlist get no host-config (FN — extend allowlist / `RYK_TRUSTED_HOST_PREFIXES`). **Hardlink fence (F-03):** macOS attach denies hardlinking host-config files into the workspace; **`cp` of readable auth still works** (S1C/gateway for stronger secretless) |
| FS scope honesty | When host-config grants are active, receipts say `narrow host-config RW, no bare home` (not bare `no home`) |
| Redirected stdio residual | Seatbelt does **not** grant host `/var/folders` or classic `/tmp` content under production defaults. Redirecting agent stdout/stderr into those paths can trigger Bun `EPERM fstat` / `process.stderr.fd` crashes (exit **1** after attach). Prefer TTY, pipes, or capture files under the workspace (session tmp is `{workspace}/.ryk-tmp`). Ryk detects parent stdio paths under classic tmp and prints a **stdio/fstat** tip (not a re-login lead). |

Inherited stdin/stdout/stderr (FDs 0/1/2) are user-directed, pre-opened capabilities. A redirect such as `ryk claude < ~/.aws/credentials` or `ryk claude > ~/out.log` gives the child access through that already-open descriptor even when the redirect target is outside the filesystem grant boundary; path mediation does not revoke existing FDs. Choose redirects with the same care as explicit file grants.

**Empty-backpack help redirect matrix (macOS, production Seatbelt):**

| Capture | Example | Expected exit | Notes |
|---------|---------|---------------|-------|
| Workspace file | `ryk claude --help > .ryk-tmp/out.txt 2> .ryk-tmp/err.txt` | **0** | Paths under workspace are granted |
| Pipe / TTY | `ryk claude --help 2>&1 \| cat` | **0** | No ungranted file path on stdio |
| Classic `/tmp` | `ryk claude --help > /tmp/out.txt 2> /tmp/err.txt` | **1** (residual) | Child Bun fstat denied; ryk note + stdio tip after attach |
| Stale OAuth non-help | `ryk claude -p '…' --print` with expired `expiresAt` | **4** (preflight) | Stale-login message **before** spawn; no “agent exited with code” note |
| Keychain residual | Empty backpack does **not** grant `~/Library/Keychains`. Claude OAuth is expected via `~/.claude` + Application Support trees (+ optional gateway). If a build requires Keychain FS access, that remains an intentional residual — use host login outside the box or `--with-host-secrets` (loud) |
| Broker resolve APIs | `source: broker` grants resolve in the parent session store; only the minted phantom reaches the child |
| Provider gateway | Fixed upstream hosts only; absolute-form/caller-selected destinations and unminted phantoms are denied |
| Network proxy | CONNECT policy proxy is separate; current route-forced proxy + provider gateway combination fails closed |
| OS sandbox | Required for empty backpack; Linux protect-on uses a FUSE workspace view + Landlock |

The default applies only to the agent-primary aliases (`claude`, `codex`, `pi`, `opencode`, `openclaw`, and `hermes`). Generic `ryk run` commands remain unchanged unless `--secretless` is explicit. Unrelated raw credentials such as `GITHUB_TOKEN` remain absent inside the boundary.

**Recommended day-1 agent path (usable credentials):**

```bash
# Prefer host login / non-env credential stores when available.
# Agent-primary aliases enter the empty backpack automatically.
ryk claude

# Loud, self-contained escape: disables empty-backpack and may expose host secrets.
ryk run --with-host-secrets -- claude
```

Clients using env keys must honor the injected Anthropic/OpenAI base URL. Otherwise use host login; use `--with-host-secrets` only as a visible escape.

### Redaction Records

When env vars are filtered, ryk creates redaction records for the audit trail:

```
Name: GITHUB_TOKEN
Label: [REDACTED:env:GITHUB_TOKEN]
Reason: environment variable name matches secret pattern
```

---

## 3. Credential Broker System

**File**: `src/intercept/credentials.zig`

ryk supports multiple credential brokers for secure secret resolution. The broker system ensures raw secrets are never stored in policy files or exposed in logs.

### Supported Brokers

| Broker | Type | Description |
|--------|------|-------------|
| `local-dummy` | Reference-only | Creates non-authoritative references for legacy testing; not used by the empty-backpack provider path. |
| `env-file-dev` | File-based | Reads from `.ryk/*.env` files. Local development only. |
| `1password-cli` | CLI integration | Resolves via `op read` command. Requires 1Password CLI. |
| `macos-keychain` | OS integration | Resolves via `/usr/bin/security` command. macOS only. |
| `infisical-agent-vault` | Config boundary | Status/config check only. Resolution disabled pending verification. |

### Configuration

```yaml
credentials:
  default_broker: onepassword
  brokers:
    onepassword:
      type: 1password-cli
      account: my-team
    env_dev:
      type: env-file-dev
      path: .ryk/dev-secrets.env
    macos:
      type: macos-keychain
  refs:
    github_pat:
      broker: onepassword
      ref: "op://Engineering/GitHub PAT/token"
    aws_key:
      broker: env_dev
      ref: "AWS_ACCESS_KEY_ID"
```

### Security Features

- **Secure memory wiping**: Resolved secrets are zeroed in memory before deallocation (`@memset(value, 0)`)
- **Timeout protection**: Broker CLI commands time out after 5 seconds with automatic kill
- **Redacted errors**: Errors are classified as `login-required`, `missing-ref`, `timeout` without leaking details
- **Path validation**: `env-file-dev` paths must be under `.ryk/` and contain `dev`
- **Reference checking**: `ryk credentials check` validates broker availability without printing values

### Checking Broker Status

```bash
# Check all brokers
ryk credentials check

# Check a specific credential reference
ryk credentials check github_pat
```

Output:
```
Credential brokers:
- onepassword (1password-cli): available - op CLI found; ref checks use op read without printing values
- env_dev (env-file-dev): available - dev env file readable
- macos (macos-keychain): limited - macOS security CLI found; ref checks query keychain without printing values
```

---

## 4. Policy Validation

**File**: `src/policy/validate.zig`

ryk validates credential configurations when loading policies and rejects unsafe setups.

### Validation Rules

- **Broker names** must be unique (case-insensitive)
- **Credential refs** must be unique (case-insensitive)
- **Credential refs** cannot contain raw secret values (rejected if `classifyString()` detects a secret)
- **Env-file paths** must be relative, under `.ryk/`, and contain `dev`
- **Service credential references** must point to defined refs
- **Default broker** must exist if brokers are configured

### Example: Rejected Configurations

```yaml
# REJECTED: Raw secret in credential ref
credentials:
  refs:
    github_pat:
      ref: "ghp_fakeSyntheticTokenValue1234567890"  # Error: InvalidPolicy

# REJECTED: Unsafe env-file path
credentials:
  brokers:
    env_dev:
      type: env-file-dev
      path: /tmp/secrets.env  # Error: InvalidPolicy

# REJECTED: Missing broker for ref
credentials:
  refs:
    github_pat:
      ref: "GITHUB_PAT"
      broker: missing_broker  # Error: InvalidPolicy
```

---

## 5. Network Exfiltration Detection

**File**: `src/intercept/network.zig`

ryk scans **visible** network surfaces for secret-like values and flags potential exfiltration. Default policy is **annotate/audit only**: findings do not flip allowlisted destinations to deny. There is no body/query DLP on TLS without a MITM architecture (explicit non-goal).

**What is visible:**

| Path | Visible surface | Not visible |
|------|-----------------|-------------|
| HTTPS CONNECT | destination **host:port** only | path, query, headers, TLS body |
| Cleartext HTTP absolute-form | path and query (when present on the wire to the proxy) | N/A for TLS payloads |

### Detected Patterns

| Signal | Score | Description |
|--------|-------|-------------|
| `secret_like_url_value` | 95 | API key or token detected in URL path or query |
| `long_query_string` | 70 | Query string exceeds 120 characters |
| `base64_like_url_component` | 70 | Base64-like string in URL path or query |
| `high_entropy_dns_label` | 75 | High-entropy subdomain (possible DNS exfiltration) |
| `paste_site_destination` | 85 | Destination is a paste site (pastebin, gist, etc.) |
| `webhook_request_bin_destination` | 90 | Destination is a webhook/request bin |
| `tunneling_service_destination` | 85 | Destination is a tunneling service (ngrok, etc.) |
| `direct_ip_destination` | 70 | Direct IP address instead of domain |
| `long_subdomain` | 65 | Subdomain exceeds 48 characters |
| `many_unknown_domains` | 75 | Repeated attempts to unknown domains |

### URL Redaction

When secrets are detected in URLs, they are redacted before audit persistence:

```
https://example.com/path?token=[REDACTED:secret:openai_api_key]&ok=1
```

ryk also handles percent-encoded secrets:

```
https://example.com/path?token=sk%2DfakeSyntheticOpenAIKey1234567890
# Detected and redacted despite URL encoding
```

### Policy Configuration

```yaml
network:
  detect_exfiltration:
    dns: true
    long_query_strings: true
    secret_patterns: true
```

---

## 6. Command Classification

**File**: `src/intercept/commands.zig`

ryk classifies commands by risk and denies credential inspection attempts automatically.

### Credential Inspection Risk Class

Commands that attempt to read credential files are classified as `credential_inspection` (risk score: 96, mandatory deny):

| Command | Reason |
|---------|--------|
| `cat .env` | Credential file inspection |
| `cat ~/.ssh/id_ed25519` | SSH private key inspection |
| `type %USERPROFILE%\.ssh\id_ed25519` | Windows credential inspection |
| `cat ~/.aws/credentials` | AWS credential inspection |

### Detected Credential Paths

The classifier checks for access to:
- `.env` and `.env.*` files
- `~/.ssh/` directory
- `~/.aws/` directory
- `~/.gcloud/` directory
- `~/.azure/` directory
- `~/.config/gh/` directory
- `id_rsa` and `id_ed25519` keys
- Windows credential stores (`%USERPROFILE%\.ssh\`, `%APPDATA%\gh\`)
- Browser login data and cookies

---

## 7. File System Guards

**File**: `src/intercept/files.zig`

ryk denies file read/write access to credential paths through built-in rules.

### Built-in Read Deny Patterns

The following patterns are denied by default for file reads:

```
./.env
./.env.*
~/.ssh/**
~/.aws/**
~/.gcloud/**
~/.azure/**
~/.config/gh/**
**/id_rsa
**/id_ed25519
**/*_rsa
**/*_ed25519
**/*credentials*
**/*credential*
**/*secret*
**/*token*
~/Library/Keychains/**
./Library/Keychains/**
~/Library/Application Support/**/Cookies*
~/Library/Application Support/Google/Chrome/**
~/Library/Application Support/BraveSoftware/**
~/Library/Application Support/Firefox/**
~/.zsh_history
~/.bash_history
```

### Built-in Write Deny Patterns

```
./.git/**
./.ryk/**
```

### Symlink Protection

ryk resolves symlinks and denies access if they escape the workspace or point to protected paths.

---

## 8. Audit Trail Protection

**Files**: `src/audit/writer.zig`, `src/audit/summary.zig`

All audit events are redacted before persistence to ensure secrets never reach the logs.

### Pre-Write Redaction

Before writing to `events.jsonl`:
- Event targets are scanned for secrets
- Secret values are replaced with redaction labels
- Command arguments are redacted
- Network destinations are redacted

### Tamper Detection

The audit log uses hash-chain verification:
- Each event includes a hash of the previous event
- Modifying the log breaks the chain
- Replay verification detects tampering
- A complete local rewrite of `events.jsonl` and `summary.json` together is out of scope (no signing). Session end prints the final chain hash so it can be checked out of band.

### Summary Redaction

Session summaries (`summary.json`, `summary.md`) also redact:
- Policy content
- Command arguments
- Any secret-like values

---

## Integration Points

The guardrails integrate at multiple stages:

```
Policy Load → Validation → Runtime → Audit
     ↓           ↓           ↓         ↓
  validate   reject raw   filter/    redact
  config     secrets      block      before
                          secrets    write
```

1. **Policy Load**: Credential configurations are validated
2. **Pre-Execution**: Environment is filtered, secrets replaced
3. **Runtime**: Commands, files, and network are evaluated
4. **Audit**: All events are redacted before persistence

---

## Testing

ryk includes comprehensive tests for credential guardrails:

```bash
# Run all tests
./scripts/zig build test

# For focused iteration, use the domain slice and a test-name filter.
./scripts/test-slice.sh intercept --filter credentials
```

### Synthetic Test Values

Tests use synthetic secrets that are still treated as sensitive:

```
ghp_fakeSyntheticTokenValue1234567890
sk-fakeSyntheticOpenAIKey1234567890
sk-ant-fakeSyntheticAnthropicKey1234567890
```

These are detected and redacted exactly like real secrets.

---

## See Also

- [Policy Reference](policy.md) — Full policy schema including credentials section
- [Network](network.md) — Network exfiltration detection and proxy configuration
- [Commands](commands.md) — Command risk classification and approvals
- [Threat Model](threat-model.md) — Security assumptions and trust boundaries

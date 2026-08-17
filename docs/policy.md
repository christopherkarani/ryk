# Policy

Policies are YAML files with `version: 1`.

## Locations And Load Order

Commands accept `--policy <path>`. Without it, ryk discovers policy in this order:

1. workspace `.ryk/policy.yaml`
2. `$HOME/.config/ryk/policy.yaml` (user fallback; install/ensure create-only seeds this)
3. `$HOME/.ryk/policy.yaml` (legacy home-workspace install layout, treated as user fallback when the workspace root is not already `$HOME`)
4. built-in defaults (`builtin:strict`)

If a discovered policy file exists but is invalid or unreadable, ryk fails closed instead of silently falling through to the next location.

```sh
./zig-out/bin/ryk init --preset generic-agent
./zig-out/bin/ryk policy check .ryk/policy.yaml

> **Quick-install note**: Coding defaults (`generic-agent` and coding host presets) use **DCG-style** gating: `mode: strict`, empty `commands.allow` (matrix-only), `commands.default: allow`, network `default: deny`, broad secret read denys, dual-path .git/.ryk protection. Normal work is not ask-gated; packs/hard fence block danger. Designed to be edited after init. See the "What to expect" guidance in quickstart.md.
```

## Modes

- `observe`: log decisions without blocking supported actions.
- `ask`: prompt for risky actions when interactive.
- `yolo`: **YOLO + seatbelt** — first-class mode for autonomous agent work. Uses the same severity matrix as `ask` (low continues; medium/high may prompt; not refuse-all). The agent continues under sandbox (Seatbelt/Landlock when session-attached) plus the hard fence. Prefer `yolo` over treating “ask on everything” as the hero path. Built-in preset: `ryk policy check --preset yolo` / `mode: yolo` in YAML.
- `strict`: deny unknown or risky actions unless allowed. When a shell **permit-list is configured** for Strict evaluation (`commands.allow` / host permit), commands **off** that list are **refused** (deny, never ask-spam); reason includes `strict: not on allowlist`. On-list does **not** auto-allow high/medium pack hits — the severity matrix still applies after the refuse gate. With an **empty / unconfigured** permit list, Strict keeps the severity matrix only (not refuse-all-off-list).
  - **Coding create-path (DCG):** `generic-agent` and coding host presets ship **empty** `commands.allow` + `commands.default: allow` under `mode: strict`. Unmatched shell is not approval-gated; high/medium pack hits **block** (never ask); critical stays hard-fenced. Catastrophe `commands.deny` patterns remain. This is intentional — not the sample permit list used by `strict-local` / `yolo` / `ask` built-ins.
  - **Host-runtime reads:** file-read policy allow is workspace `./**`. Absolute reads of first-class host skill trees (`~/.grok/skills/**`, `~/.grok/bundled/skills/**`, `~/.grok/installed-plugins/**/skills/**`, `~/.grok/third-party/**`, `~/.agents/skills/**`, `~/.claude/skills/**`, `~/.claude/plugins/**/skills/**`, `~/.codex/skills/**`, `~/.cursor/skills-cursor/**`, `~/.cursor/skills/**`, `~/.pi/agent/skills/**`, `~/.hermes/skills/**`, `~/.openclaw/skills/**`) are a built-in allow (`builtin.files.read.allow[host_skill]`). `~/.grok/third-party/**` is the whole pack checkout (broader than `…/skills/**`); secret basenames and resolved targets still apply. Env-rooted homes accumulate with those defaults: `CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `HERMES_HOME`, `PI_CODING_AGENT_DIR`. Outside-workspace `AGENTS.md` / `CLAUDE.md` (and the `AGENTS.MD` / `CLAUDE.MD` spellings) under `$HOME` are a sibling allow (`builtin.files.read.allow[host_instruction]`) so hosts can walk parent/home instruction files. Policy may allow a non-ancestor `~/other-project/AGENTS.md`; OS sandbox (when attached) still only grants ancestor files. Workspace or catalog-internal symlink reads are allowed only if the **resolved** target is still in this catalog; a workspace symlink to an outside non-catalog path is denied even when the target is missing (readlink, never the `./alias`), and an unresolved catalog symlink is not an allow. The catalog itself rejects `.env` / `.env.*` / `auth.json` / `.credentials.json` / `credentials.json` basenames and `..` segments; `~/.ssh/**` remains an explicit deny. Paths outside the catalog (including `~/.grok/auth.json` and host config) stay unmatched deny under coding DCG. Not leftover unused `ask`. Not whole `~/.grok` / `~/.claude` / `~/.codex`. Writes stay gated.
  - **Sample permit lists:** built-in `strict` / `yolo` / `ask` / `strict-local` still carry a curated `commands.allow` sample. Unquoted `&&` chains are on-list only when **every** segment matches; pipelines, sequencing, redirects, newlines, background, and `$()` / backticks stay off-list.
- `ci`: non-interactive strict behavior; ask becomes deny.
- `redteam`: strict fixture mode for deterministic tests (strict-like permit refuse when a list is configured).
- `trusted`: observe-like mode for local trusted workflows.

### Hard fence (unsoftenable)

Critical severity and always-on catastrophe classes (for example `rm -rf /`) are always **denied**. **YOLO**, sticky trust, and Strict permit lists **cannot** unlock the hard fence. Force-equivalent `git push` (`-f`, `+refspec`, `--delete`, `--mirror`, `:ref`) stays denied on the YAML heuristic and the command + shell-engine fence. Network or opaque-decode piped to an executor (`curl | sh`, `curl | sudo sh`, `base64 -d | sh`) is denied by the shell engine (wrappers unwrapped on both sides of `|`). These are command + shell-engine + pipe-to-executor fences, not a claim of critical deny on every host. After `ryk doctor --fix`, a pristine old default is seeded to generic-agent.

### Sticky trust

After an interactive **ask** that the user allows, ryk can record sticky trust so a later identical command (or effect class) skips re-ask:

| Scope | Behavior |
|-------|----------|
| **once** | One subsequent allow for that command fingerprint, then consumed |
| **session** | Allow that fingerprint until process/session end |
| **effect-class** | Allow a semantic effect-class id for the session |

Sticky state is **in-memory for the session** only. Critical and hard-fence denies are **never** recorded as sticky allows.

**Host-owned sticky limitation (A5):** FM sticky scope hints (`ask_sticky_candidate` → suggested once/session/effect-class) apply only when ryk itself observes the ask→allow transition in-process — notably `ryk run` / shim paths that call `recordStickyFromAskWithHints` after the user approves. Claude, Codex, Pi, and similar host UIs that approve **outside** ryk do **not** automatically feed that allow back into the ryk sticky store unless the host integration explicitly records it (e.g. by calling the same sticky record path). Sticky session trust remains **in-memory for the process session only** — a new ryk process starts with an empty sticky store.

### Shell evaluation order

For shell mediation (hook / run / shim / `ryk evaluate`), decisions follow this order:

1. empty command / evaluator error → deny (fail closed)
2. engine allow → allow candidate (still subject to later steps)
3. **critical hard fence** → deny (ignore sticky, mode, permit, and FM)
4. sticky match (once / session / effect-class) → allow
5. **strict refuse** off permit-list when mode is strict-like and a list is configured → deny
6. mode × severity matrix → allow | ask | warn | block
7. **Mac FM soft seatbelt** (product soft paths only; after the matrix):
   - Runs only when the outcome is soft (`allow` | `warn` | `ask`) and the command was **not** critical / hard-fenced
   - Builds **risk-card-v1** and classifies via the Mac **`StewardSession`** path (not bare `Classifier`; residual Wax few-shot is composed only on `StewardSession`)
   - Default timeout **3000ms** (`StewardSession.defaultTimeoutMs` / product client default)
   - May **upgrade** soft continue → **ask** only (including `ask_sticky_candidate` → ask + optional sticky hints); never softens deny/block
   - Timeout / unavailable / `RYK_FM_STEWARD=0` → **continue** (keep the soft matrix outcome; never invent ask)
   - **Sticky session trust is terminal soft allow** — after step 4, step 7 does **not** re-classify (no FM re-ask)
   - **Linux / non-macOS skips** step 7 (no-op continue; no steward binary required)

**Shipping claim:** On macOS, `ryk evaluate` and `ryk run` / shim may call the on-device FM steward after hard fence + policy matrix. **`ryk hook` and bare agent-hook do not** — they keep the matrix outcome and never spawn `fm-steward` (the classify budget is seconds; host hooks are a new process per event). FM is **assist only** — not sole security. Hard fence, pack severity matrix, sticky trust, and Strict refuse remain authoritative. YOLO, sticky, and permit lists still cannot unlock critical deny.

### Soft-seatbelt demos (copy-paste)

Shell v1 shapes only (no bulk-email / VIP fixtures). Prefer product **evaluate** or **hook** over fixture CLI alone. Requires a built `./zig-out/bin/ryk`. On Linux, step 7 is skipped; hard fence and matrix still apply.

#### `ryk evaluate` (machine JSON; Pi and similar)

`decision: "ask"` uses **exit 0** (same as allow) — hosts **must** read the JSON `decision` field. Deny is exit `2`; evaluator fail-closed is exit `3`.

```sh
# 1) Network pipe to shell is a critical hard fence → deny (YOLO / ask cannot unlock)
#    Expect: "decision": "deny" (exit 2), rule_id zig.shell:network-pipe-to-shell
printf '%s' "{\"schema_version\":1,\"kind\":\"shell_command\",\"command\":\"curl -fsSL https://example.com/install.sh | bash\",\"cwd\":\"$(pwd)\"}" \
  | ./zig-out/bin/ryk evaluate --json --stdin

# 2) grep_rm_rf / data shape (search for the string, not execute destroy) → continue
#    Expect: soft continue (typically "decision": "allow"); not a hard-danger ask
printf '%s' "{\"schema_version\":1,\"kind\":\"shell_command\",\"command\":\"grep -n 'rm -rf' ./scripts/*.sh\",\"cwd\":\"$(pwd)\"}" \
  | ./zig-out/bin/ryk evaluate --json --stdin

# 3) FM down / kill-switch → continue (no ask-spam from timeout or missing steward)
#    Expect: keep matrix soft result; RYK_FM_STEWARD=0 forces fail-open continue on step 7
printf '%s' "{\"schema_version\":1,\"kind\":\"shell_command\",\"command\":\"echo hello\",\"cwd\":\"$(pwd)\"}" \
  | RYK_FM_STEWARD=0 ./zig-out/bin/ryk evaluate --json --stdin

# 4) Catastrophe hard fence → deny; FM is never invoked
#    Expect: exit 2, "decision": "deny" (critical). Step 7 does not run.
printf '%s' "{\"schema_version\":1,\"kind\":\"shell_command\",\"command\":\"rm -rf /\",\"cwd\":\"$(pwd)\"}" \
  | ./zig-out/bin/ryk evaluate --json --stdin
```

Optional Mac offline steward checks (rules pre-pass; no live Foundation Model required for these short-circuits):

```sh
# Fixture cards are pinned here; Swift package is https://github.com/christopherkarani/ryk-fm-steward
# From a ryk-fm-steward checkout:
swift run fm-steward classify --card Fixtures/curl_pipe_sh.json --human
# → ask (HardDangerRules)

swift run fm-steward classify --card Fixtures/grep_rm_rf.json --human
# → continue (executed=false-shaped)

swift run fm-steward classify --card Fixtures/timeout_forced.json --human
# → continue (timeout / fail-open path)
```

#### YOLO few-ask (`mode: yolo`)

YOLO uses the **same severity matrix as `ask`** (low continues; medium/high may prompt) plus sandbox when session-attached — it is **not** refuse-all and **not** allow-all. Hard fence still denies catastrophe. On Mac, FM soft seatbelt may still upgrade soft continue → **ask** for hard-danger residuals (assist only).

`ryk evaluate` takes no `--mode` flag: mode comes from the **discovered** policy (`.ryk/policy.yaml` → user config → built-ins), and `RYK_MODE` may only **raise** strictness (never ambient-soften). Put `mode: yolo` in the workspace policy first (or use a policy that already has it), then run shell v1 evaluate shapes. Hosts must read the JSON `decision` field (`ask` is exit 0).

```sh
# Prerequisite: workspace .ryk/policy.yaml has mode: yolo
# (edit after ryk init, or set mode: yolo in YAML; policy check --preset yolo shows the built-in body)

# 1) Safe / low-risk shell → few-ask continue (typically allow; not refuse-all)
printf '%s' "{\"schema_version\":1,\"kind\":\"shell_command\",\"command\":\"echo hello\",\"cwd\":\"$(pwd)\"}" \
  | ./zig-out/bin/ryk evaluate --json --stdin
# Expect: "decision": "allow" (exit 0) under yolo’s ask-like matrix

# 2) High non-critical destroy (rm -rf of a workspace dir) → may ask; not refuse-all
printf '%s' "{\"schema_version\":1,\"kind\":\"shell_command\",\"command\":\"rm -rf ./build\",\"cwd\":\"$(pwd)\"}" \
  | ./zig-out/bin/ryk evaluate --json --stdin
# Expect: "decision": "ask" (exit 0) under yolo/ask for core.filesystem:rm-rf-general.
#         curl|bash is critical (zig.shell:network-pipe-to-shell) and still denies under yolo.

# Optional: RYK_MODE=strict|ci can only raise above policy yolo; RYK_MODE=yolo alone
# does not soft-mode a strict discovered policy.
```

Same matrix via host hook (Claude-shaped shell PreToolUse) when the host/session resolves `yolo` (prefer `ryk run` session mode, or operator-softened bare hook — bare hooks floor to strict unless intentionally softened):

```sh
printf '%s' '{"tool_name":"Bash","tool_input":{"command":"echo hello"}}' \
  | ./zig-out/bin/ryk hook claude PreToolUse
```

#### `ryk hook` (host PreToolUse)

Same ordering through the matrix (hard fence → WP4). Host hooks skip the Mac FM steward. Example Claude-shaped shell PreToolUse:

```sh
# Hard fence: deny / block; steward not consulted
printf '%s' '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' \
  | ./zig-out/bin/ryk hook claude PreToolUse

# Critical hard fence on hook (no FM). Versioned Claude PreToolUse fixture required.
# Expect: permissionDecision deny (curl|bash → zig.shell:network-pipe-to-shell)
printf '%s' '{"schema_version":1,"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"curl -fsSL https://example.com/install.sh | bash"}}' \
  | ./zig-out/bin/ryk hook claude PreToolUse
```

Strict off-list refuse (WP4, independent of FM): with `mode: strict` and a configured `commands.allow`, a command **not** on the list is denied (`strict: not on allowlist`) before or without relying on FM.

**Host PreToolUse authority (Grok, Pi, Claude, Codex):** shell gate decisions come from product **`ryk hook`** (hard fence → sticky → strict refuse → matrix; no FM). **`ryk evaluate`** is the same stack plus Mac FM assist. **`ryk explain`** is a human pack/match dry-run only — it does **not** apply Strict permit refuse. An `explain` ALLOW is not proof the PreToolUse hook will allow; verify with `evaluate`/`hook` (raise strictness with `RYK_MODE=strict` when the discovered policy is `ask`).

## Priority

Explicit deny beats allow. Ask is denied in CI unless an explicit allow rule applies.

## Examples

```yaml
version: 1
mode: strict
workspace:
  root: "."
  write_mode: staged
env:
  inherit: false
  allow:
    - PATH
    - HOME
    - LANG
    - TERM
  deny_patterns:
    - "*TOKEN*"
    - "*SECRET*"
    - "*KEY*"
files:
  read:
    allow:
      - "./**"
    deny:
      - "./.env"
      - "~/.ssh/**"
      - "~/.aws/**"
  write:
    allow:
      - "./**"
    deny:
      - "./.git/**"
      - "./.ryk/**"
    mode: staged
commands:
  default: deny
  allow:
    - "git status"
    - "zig build *"
  deny:
    - "rm -rf *"
    - "curl * | sh"
    - "cat .env"
network:
  mode: allowlist
  default: deny
  allow:
    - "api.github.com"
  deny:
    - "pastebin.com"
    - "*.ngrok.io"
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
mcp:
  default: deny
  allow:
    - "*.list_*"
    - "*.get_*"
  deny:
    - "*.delete_*"
    - "*.run_command"
effects:
  # Optional. When present, tool calls are also classified into semantic effects
  # (comms.message, comms.publish, money.transfer, …) independent of exact tool names.
  default: allow
  deny:
    - comms.message
    - comms.publish
    - money.transfer
  ask:
    - unknown.external
audit:
  level: full
  redact_secrets: true
  tamper_evident: true
```

**Command glob matching:** `commands.allow` / `commands.deny` globs collapse
runs of space, tab, and newline to a single space and strip a leading `./`
or `.//` (or `.\\`) from each word before matching. This is matcher-local
(whitespace + leading `./`); it is not shell-engine normalization. `cat  .env`,
`cat<TAB>.env`, and `cat ./.env` therefore still hit a `cat .env` deny.
Neighbor paths (`cat .env.example`, `cat secrets/.env`) do not. If normalize
cannot fit the 16KiB bound, evaluation fails closed (deny).

**`.git` / `.ryk` write deny and OS attach:** policy and builtins deny
`files.write` under `./.git/**` and `./.ryk/**`. When OS sandbox session-attach
succeeds, those paths are also default **control roots** (write-deny on disk,
still readable). Policy alone does not stop raw bash when attach is off. With
attach, `git commit` / `git add` and other writers into `.git` hit EPERM as well
(same class as planting under `.ryk`).

`audit.redact_secrets` may be omitted (it defaults to `true`) or explicitly set
to `true`. Setting it to `false` is rejected: persisted audit records and
exported replay data never permit raw secrets.

## Effects (semantic tool intent)

When the `effects:` section is present, ryk classifies mediated actions into
coarse **effect IDs** and evaluates them in addition to surface rules (`mcp`,
`commands`, `files`, `network`). Missing `effects:` keeps legacy behavior (no
effect evaluation). Classification is **deterministic** (catalog + structural
tables + host tags + optional local residual). No cloud LLM classification.

| Effect ID | Meaning |
|-----------|---------|
| `comms.message` | Email, SMS, iMessage, Slack/Discord/Telegram-style messaging |
| `comms.publish` | Public social posts (Twitter/X, LinkedIn, …) |
| `comms.calendar` | Calendar / invite side effects (reserved; limited catalog coverage) |
| `money.transfer` | Payments and transfers |
| `identity.auth` | Token/PAT/OAuth minting |
| `device.control` | Physical / IoT actuation |
| `code.mutate_remote` / `secrets.read` | Reserved for later phases (valid in YAML; limited emitters today) |
| `shell.exec` / `fs.read` / `fs.write` / `net.connect` | Tool-name surface IDs for shell/fs/net-shaped **tool names** |
| `unknown.external` | Unclassified outbound-looking tool names or arg shapes |

Patterns may be exact IDs or family wildcards (`comms.*`). **Any denied effect
denies**; deny beats allow. Equal severity keeps the **surface** result.
Structural hits only **raise** restriction — they never alone flip a surface
deny into allow. Explicit MCP allow does not override an effect deny.

### How classification works

1. **Tool name catalog (high confidence)** — exact names and domain tokens
   (`send_email` → `comms.message`, `post_twitter` → `comms.publish`).
2. **Structural args (medium)** — renamed tools such as `notify` / `helper`
   still match when argument **keys** form known sets (e.g. `{to, body}`) or
   string **values** look like email/phone/known messaging-API URLs. Reasons
   include matcher ids such as `structural.comms.message.keys:to+body` (keys
   only — never raw secret values).
3. **User effect packs (high/medium)** — workspace and user-config YAML packs
   add exact names, tokens, and structural key-sets. Matchers use
   `pack.<id>.*`. Packs are **classification-only**; they never grant allow
   past `effects.deny`.
4. **Local residual classifier (low, opt-in)** — when `effects.classifier` is
   `local` (or `local-embed`, same engine in v1), tools that A–C leave
   under-classified may pick up low-confidence hits via pure-Zig
   prototype/token similarity on the tool **name**, argument **keys**, and
   bounded short alphanumeric string **value tokens** (secrets filtered;
   not chat history, not a cloud model). Matchers use `classifier.local.*`.
   **Off by default.** Raise-only: residual hits may increase restriction
   (ask/deny) but never alone flip a surface deny into allow. In `strict` /
   `ci` / `redteam`, if the classifier is enabled but unavailable, residual
   tools **fail closed** (`effects.classifier unavailable`).
5. **Network host tags** — when `effects:` is active, destinations such as
   `api.twitter.com` map to `comms.publish` (matcher `network_tag.…`) and
   merge with network surface rules on **both** `policy explain network` and
   the runtime proxy (`ryk run` / `network_eval.evaluate`).
6. **Shell bypass (Zig command path)** — patterns such as `open mailto:…`
   (including `open -a Mail mailto:…`), multi-URL `curl` to tagged hosts, and
   command-position matching (including wrappers such as `sudo`/`env`/`xargs`)
   map to `comms.message` / `comms.publish` (matcher `shell_bypass.…`) on Zig
   `command` / `ryk policy explain command` evaluation. Tokenization is
   exhaustive (no 48-token cap): a long `curl -H …` list cannot hide a
   tagged publish URL past the classifier.

Example residual opt-in (block-style lists):

```yaml
version: 1
mode: strict
effects:
  default: ask
  deny:
    - comms.message
    - comms.publish
  classifier: local
```

Surfaces covered:

- Host generic tools (PreToolUse non-shell/file) **with tool_input/args** for
  structural matches (and user effect packs when present)
- `ryk decide tool --json '{"name":"…","tool_input":{…}}'` (same arg shapes)
- `ryk policy explain tool <name> --args '{…}'` for demos
- `ryk tools classify <name> [--args '{…}'] [--policy <path>]` for discovery
- MCP `tools/call` via the proxy (name + `arguments` object)
- `ryk mcp inspect` shows inferred effects per listed tool
- Network connect evaluation when effects are configured (explain **and**
  proxy-mediated runtime)
- Zig command evaluation (`ryk policy explain command`, `command_exec`)

### User effect packs

Extend the built-in catalog without listing every tool name in policy YAML:

| Priority | Path |
|----------|------|
| Lowest | Built-in Zig catalog / structural / network / shell |
| Mid | `$XDG_CONFIG_HOME/ryk/effect-packs/*.yaml` or `~/.config/ryk/effect-packs/` |
| Highest | Workspace `.ryk/effect-packs/*.yaml` |

Example (see also `examples/effect-packs/demo.yaml`):

```yaml
version: 1
id: acme-comms
description: optional
names:
  send_acme_ping: comms.message
tokens:
  acmechat: comms.message
structural:
  - effect: comms.message
    keys: [acme_to, acme_body]
```

Rules:

- `version: 1` only; `id` must match `[a-z0-9_-]{1,64}`
- Effect ids must be known (`comms.message`, …)
- Unknown keys, bad ids, or oversized files **fail closed** (clear error; no silent ignore of that file)
- Missing pack directories are fine
- Within a directory, packs load in **lexicographic filename order**; later files win on exact-name conflicts (workspace still outranks user config)
- Exact names match full normalized tool names and the last `__`/`/` segment (e.g. pack `send_acme_ping` matches `mcp__acme__send_acme_ping`)
- Tokens reuse catalog matching: short tokens (≤3 chars) require a whole `_`-separated segment
- Structural `keys` lists are capped (max 16 keys per rule)
- **Decisions still require policy `effects:`** — e.g. `effects.deny: [comms.message]` blocks pack-mapped tools

List loaded packs: `ryk tools packs`.

### Discovery

```sh
./zig-out/bin/ryk tools classify send_email
./zig-out/bin/ryk tools classify notify --args '{"to":"a@b.com","body":"hi"}'
./zig-out/bin/ryk tools classify send_acme_ping --policy .ryk/policy.yaml
./zig-out/bin/ryk mcp inspect --name demo --policy .ryk/policy.yaml --command python3 -- fixtures/mcp/fake_server.py
```

Inspect and classify print effect ids, confidence, and matcher labels only —
never raw email/body/token values.

### Residual gaps

- **Host shell PreToolUse** is owned by the in-process Zig **`shell_engine`**
  (oracle pack parity; default enablement matches Rust `core.*` + `system.disk`).
  `RYK_SHELL_EVAL=rust` is rejected — there is no supported dual-stack Evaluate
  backend. Network effect tags still catch many
  `curl`-style bypasses when the network path is evaluated (including the proxy).
- Structural classification is top-level + one nested object level of keys
  (interesting keys preferred against padding); deeper nesting or stringified
  JSON args are not fully covered.
- Host file PreToolUse uses `files.write` / `files.read` (not effect IDs on
  that specialized route). Denying `shell.exec` / `fs.write` as effects only
  applies when the call is evaluated as a **tool name**.
- Browser/computer-use UI actions remain out of scope.
- Residual classifier v1 is **local prototype/token similarity**, not neural
  embeddings or a remote LLM. `local-embed` is an alias for `local`. Features
  are tool name tokens, arg keys, and bounded short alphanumeric string value
  tokens (secret-looking values filtered). It only runs on under-classified
  tools and only raises restriction.

When `effects:` is present, `effects.default` applies to **tool**
classification hits that match no allow/deny/ask pattern and to **tools with
zero hits** (unclassified names). Network/shell effect merge only runs when a
tag or bypass pattern hits — untagged hosts are not denied solely by
`effects.default`.

Preset: `no-external-comms` (`ryk init --preset no-external-comms`).

Explain decisions:

```sh
./zig-out/bin/ryk policy explain file.read ./.env
./zig-out/bin/ryk policy explain command "open 'mailto:x@y.com'"
./zig-out/bin/ryk policy explain network https://example.invalid/path
./zig-out/bin/ryk policy explain network https://api.twitter.com/2/tweets
./zig-out/bin/ryk policy explain network https://api.github.com/repos/acme/app/issues --method POST
./zig-out/bin/ryk policy explain mcp demo.list_files
./zig-out/bin/ryk policy explain tool send_email
./zig-out/bin/ryk policy explain tool notify --args '{"to":"a@b.com","body":"hi"}'
```

## Invalid Policy Behavior

Missing versions, unknown keys, invalid modes, malformed rule shapes, oversized files, and unsafe patterns fail validation. Enforcing modes fail closed.

## CI Behavior

CI never prompts. `ask` decisions become `deny`.

## Common Workflows

- Start coding: `ryk init --preset generic-agent` (DCG-style: matrix-only strict + allow default; packs/hard fence block danger; not ask-on-risk).
- YOLO + seatbelt local autonomy: set `mode: yolo` (or `ryk policy check --preset yolo`) so the agent continues under sandbox + hard fence with the ask severity matrix + sample permit body.
- Strict local work with off-list refuse: `--preset strict-local` (`mode: strict` with a sample `commands.allow` permit list — off-list refuse when the host wires that list into shell evaluation).
- MCP development: `--preset mcp-dev` (same coding DCG body as generic-agent).
- CI: `--preset github-actions` and `ryk redteam --ci`.

## Secretless Runtime

Agent-primary aliases such as `ryk claude` and `ryk codex` enable the **empty backpack** secret boundary by default. Generic commands use `ryk run --secretless -- <command>` explicitly. The boundary provides public host env plus exact session phantoms for granted Anthropic/OpenAI keys, requires an OS sandbox, and denies workspace `.env` / `.env.*` forms at the OS layer. Raw values remain in the parent store; a provider-specific loopback gateway swaps exact mints only for fixed upstream hosts. Use `ryk run --with-host-secrets -- <agent-command>` as the loud escape. See [credentials.md](credentials.md) and [quickstart.md](quickstart.md).

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
```

Supported broker kinds are `local-dummy`, `env-file-dev`, `1password-cli`, `macos-keychain`, and `infisical-agent-vault`. `env-file-dev` is local-development only. `1password-cli` and `macos-keychain` resolve through their CLIs at check/runtime boundaries with bounded execution time and redacted timeout/login/missing-ref error classes. Infisical / Agent Vault is currently a status/config boundary only.

Use:

```bash
ryk credentials check
ryk credentials check github_pat
```

When `credentials.refs` are declared, `services.*.credentials.use` must point to one of those refs.

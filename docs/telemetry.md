# Telemetry

Rykan V release builds include lightweight pseudonymous product telemetry so the project can measure product usage and enforcement reliability. Telemetry is **opt-in**: it is disabled until you explicitly enable it, and you can opt back out at any time. It does not use an account, email address, host identity, or machine identifier, but its random installation identifier is retained locally so repeat usage can be measured:

```sh
ryk telemetry status
ryk telemetry enable
ryk telemetry disable
ryk feedback bug
```

There is no first-run prompt. Missing consent state means disabled; malformed or inaccessible state also fails closed to disabled. `RYK_NO_TELEMETRY=1` disables telemetry for the process and prevents queued events from being sent, overriding even an explicit opt-in. Disabling telemetry also clears the local queue and installation identifier.

Disabling affects future collection and removes locally queued data. It cannot recall events already delivered to PostHog; retention or deletion of received events is governed by the PostHog project settings.

Only release builds compiled with the project’s PostHog token have transport enabled. Ordinary local and test builds have no transport token. Release telemetry uses PostHog US Cloud through the batch endpoint and is isolated in one bounded background batch helper per CLI process. The helper appends the command and all fixed summaries, then delegates the HTTP attempt to a bounded send child; a failed request never changes the visible command output or exit code.

## Events and allowed telemetry fields

Every event is constructed from an explicit allowlist. The original command event is `ryk_cli_command`. The product summaries are `ryk_fm_steward_summary`, `ryk_enforcement_summary`, `ryk_integration_summary`, `ryk_session_summary`, `ryk_feature_summary`, and `ryk_reliability_summary`. Lifecycle events are `ryk_activation`, `ryk_setup_completed`, `ryk_setup_failed`, `ryk_feedback_submitted`, `ryk_update_completed`, and `ryk_update_failed`. Repeated fixed dimensions within one CLI process are represented by one event with a bounded `count`; no raw per-hook or per-command payload is buffered.

| Field | Source and type | Transformation | Purpose |
| --- | --- | --- | --- |
| `distinct_id` | Locally generated installation identifier, string | Random `ryk_` plus 32 hexadecimal characters | Measure repeat usage without an account or host identity |
| `$process_person_profile` | Compile-time constant, boolean | Fixed value `false` | Prevent an analytics person profile from being created |
| `$ip` | Compile-time constant, integer | Fixed value `0` on every event | Explicitly request that PostHog discard client-IP enrichment; the PostHog project must also keep IP capture disabled |
| `telemetry_schema_version` | Compile-time constant, integer | Fixed value `1` | Version the event contract |
| `command` | Fixed top-level command enum, string | Unknown commands are omitted; no arguments are included | Measure product-path usage |
| `host` | Fixed host-alias enum, string | Host aliases map to `host_launch`; non-alias commands use `none` | Compare direct host launches with other CLI paths |
| `outcome` | CLI exit code, fixed enum, string | Maps to `success`, `denied`, `ask`, `warning`, `usage_error`, or `failure` | Measure broad command outcomes |
| `product_version` | Build metadata, string | Release version only | Compare behavior across releases |
| `os` | Zig target metadata, fixed enum, string | Coarse `macos`, `linux`, `windows`, or `other` | Identify supported-platform usage |
| `arch` | Zig target metadata, fixed enum, string | Coarse architecture enum | Identify supported-architecture usage |
| `occurred_at` | Local clock, ISO-8601 string | Timestamp only | Place events in time |

Summary-specific fields are limited to these fixed dimensions:

| Event | Fields | Purpose |
| --- | --- | --- |
| `ryk_fm_steward_summary` | `host`, `source`, `verdict`, `status`, `model_available`, `timed_out`, `upgraded`, `latency_bucket`, `count` | Measure FM Steward availability, fallback/timeout behavior, latency buckets, and how often it upgrades a soft policy decision |
| `ryk_enforcement_summary` | `host`, `source`, `decision`, `risk`, `effect`, `mode`, `count` | Measure final allow/observe/ask/deny/error outcomes by coarse policy dimension |
| `ryk_integration_summary` | `host`, `operation`, `result`, `count` | Measure installation, verification, repair, onboarding, and inspection health |
| `ryk_session_summary` | `host`, `event_type`, `result`, `count` | Measure hook session and tool lifecycle coverage without session identifiers |
| `ryk_feature_summary` | `feature`, `operation`, `result`, `count` | Measure adoption of fixed CLI features and subcommands |
| `ryk_reliability_summary` | `operation`, `failure`, `source`, `count` | Measure fixed failure classes such as evaluator, protocol, timeout, policy-load, hook, usage, and command failures |

Lifecycle-specific fields are also fixed and allowlisted:

| Event | Fields | Source and purpose |
| --- | --- | --- |
| `ryk_activation` | `host` | First successful protected `ryk run` after the local telemetry installation state is created; host is a fixed enum |
| `ryk_setup_completed` | `mode` | Successful public `ryk start`, split into `auto` or `interactive` |
| `ryk_setup_failed` | `mode` | Failed public `ryk start`, split into `auto` or `interactive` |
| `ryk_feedback_submitted` | `category` | User-selected fixed category: `bug`, `false_positive`, `false_negative`, `missing_integration`, or `confusing`; `ryk feedback` reports when local telemetry is unavailable or disabled |
| `ryk_update_completed` | `channel`, `from_version`, `to_version`, `verification` | Official installer completed and the on-PATH version was verified |
| `ryk_update_failed` | `channel`, `stage` | Update failure at `resolve`, `parse`, `compare`, `channel`, `confirmation`, `installer`, or `verify`, including unverified installs |

The source boundaries are authoritative: activation comes from the protected-run result; setup comes from public `ryk start`; update events come from `ryk update`; feedback comes from the fixed-category `ryk feedback` command; FM fields come from the FM classify result; enforcement fields come from the final run, hook, or evaluate decision; integration fields come from install/verification boundaries; session fields come from fixed hook host/event arguments; and feature fields come from top-level dispatch. Collection is process-local and is emitted by the existing background telemetry worker after the command returns. Activation state is stored locally and marked under the telemetry store lock so concurrent processes emit it at most once per local telemetry identity.

## Forbidden telemetry fields

The payload never serializes runtime command or host objects. It does not include:

- command text, command arguments, prompts, tool inputs, or tool outputs;
- file paths, repository names, repository metadata, working directories, or environment values;
- policy contents, history, audit, session, replay, or dashboard records;
- secrets, credentials, tokens, proxy credentials, or host payloads;
- error strings, logs, stack traces, network destinations, or response bodies;
- free-form feedback text; feedback is accepted only as one of the five fixed categories above;
- user names, email addresses, account identifiers, or machine identifiers.

The top-level command and feature classifiers exclude hook/evaluate/decide/shim, CI, machine-readable, JSON/raw, and dry-run invocation metadata so scripts do not create command-usage events. Final enforcement summaries still cover hook and evaluate decisions because those summaries contain only fixed buckets. Bare agent-hook decisions are attributed as `source=hook`, `host=other`. The telemetry command itself never records an event, including its internal workers. A user-invoked release CLI wrapper such as `ryk run -- <agent>` records only fixed command and enforcement metadata; plugin code does not add payload fields.

The local state is stored under the existing user configuration convention: `$XDG_CONFIG_HOME/ryk` when set, otherwise `$HOME/.config/ryk`. State and queue files use owner-only permissions and atomic replacement. The queue is bounded to 64 events.

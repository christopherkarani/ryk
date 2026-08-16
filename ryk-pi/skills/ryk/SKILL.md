---
name: ryk
description: Use when Pi tool calls are protected by ryk runtime guardrails or when a secret was captured from a Pi prompt.
---

# ryk Guardrails for Pi

ryk evaluates Pi actions before they run:

| Tool | Enforcement |
|------|-------------|
| `bash` | `ryk evaluate --json --stdin` |
| `write` / `edit` | `ryk decide file` with `operation: write` |
| `read` | `ryk decide file` with `operation: read` |
| `grep` / `find` / `ls` | Root preflight via `ryk decide file` |
| Other tool names | `ryk decide tool` name gate |

A block is a security decision. Explain its redacted reason and rule id when
available; never bypass it by rewriting, splitting, encoding, or indirectly
executing the same action.

Use `/ryk-doctor` for integration health. Prefer repair over session bypass.
For process-level environment, network, and secretless controls, launch Pi with:

```bash
ryk run -- pi
ryk run --secretless --network ask -- pi
```

## Secret capture

Interactive Pi may ask for consent to store a pasted credential in the
compatibility broker path `.ryk/dev-secrets.env` and replace the raw value with
`$ENV_NAME` before the model sees it. Never ask the user to paste the raw secret
again, and never print or log the value. Noninteractive capture fails closed.

Primary settings use the `RYK_PI_` prefix. The hard-cut release accepts only
the canonical `RYK_*` environment variables and `ryk-*` slash commands.

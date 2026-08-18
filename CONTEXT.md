# ryk

Local policy and host-wire decisions for ryk-managed agent sessions.

## Language

**Policy decision**:
The host-agnostic result of policy evaluation: `allow`, `ask`, `deny`, `observe`, or `stage`.
_Avoid_: host-wire outcome, leftover unused policy ask

**Leftover unused policy ask**:
A policy decision of `ask` that is not stage, SoftBlock, FM steward ask, or explicit deny. On an attended coding-host enforcement wire this leftover is permit.
_Avoid_: residual ask, leftover ask, host approval

**Ask origin**:
Why this `ask` exists: leftover unused policy ask, SoftBlock, or FM steward ask. Required on a coding-host enforcement wire. Missing origin is never-permit.
_Avoid_: default leftover, residual

**Coding-host enforcement wire**:
The machine contract a coding host reads to allow or stop an action: `ryk hook`, Cursor agent_hook, `ryk evaluate`, and machine-JSON `ryk decide`.
_Avoid_: operator TTY decide, doctor probe

**Host-wire outcome**:
The `decision` value a coding-host enforcement wire emits: `allow` or deny (`stage` where that contract already exists). Leftover unused policy ask is not a host-wire `decision`.
_Avoid_: policy decision, decision: ask

**Host-wire rewrite**:
The coding-host enforcement wire rewrite: leftover unused policy ask becomes permit or deny; missing ask origin and never-permit ask become deny; unattended stage becomes deny. Not policy evaluate. Not host JSON formatting.
_Avoid_: leftover unused policy ask alone, WP4

**Unexpected ask**:
`decision: ask` on a coding-host enforcement wire after leftover unused policy ask has already been rewritten. Fail-closed deny. Plugins do not implement leftover unused policy ask.
_Avoid_: leftover unused policy ask, residual ask

**Never-permit ask**:
Stage, SoftBlock, FM steward ask, or explicit deny. These never become allow via leftover unused policy ask.
_Avoid_: leftover unused policy ask

**Unattended**:
No approval UI: `RYK_UNATTENDED`, `RYK_CI`, `RYK_NONINTERACTIVE`, `CI`, or `--ci`. Leftover unused policy ask becomes deny. Host-specific extras only flip this same bit in their adapter.
_Avoid_: Hermes marker files inside leftover unused policy ask

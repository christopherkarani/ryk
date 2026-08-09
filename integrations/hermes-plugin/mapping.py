"""Pure ryk decision → Hermes host action mapping.

Policy stays in ryk; this module only translates decisions into Hermes
pre_tool_call / pre_llm_call return shapes. No I/O, no subprocess.
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any, Callable

# Truthy env tokens for CI / unattended hardening of ask → block.
_CI_ENV_KEYS = (
    "CI",
    "RYK_CI",
    "RYK_NONINTERACTIVE",
    "RYK_UNATTENDED",
    "RYK_HERMES_UNATTENDED",
)
_FALSY_ENV = frozenset({"0", "false", "no", "off", ""})

# rule_key uses '|' so ryk rule_ids that contain ':' stay unambiguous.
_RULE_KEY_SEP = "|"


def ci_mode(environ: dict[str, str] | None = None) -> bool:
    """True when interactive approval cannot be answered (CI / unattended)."""
    env = os.environ if environ is None else environ
    for key in _CI_ENV_KEYS:
        value = env.get(key, "").strip().lower()
        if value and value not in _FALSY_ENV:
            return True
    return False


def stable_rule_key(response: dict[str, Any], tool_name: str, tool_input: Any) -> str:
    """Stable Hermes [a]lways allowlist grain for ryk ask decisions.

    Format: ``ryk|{rule}|{tool}|{args_fp}``
    """
    rule = response.get("rule_id") or response.get("rule") or "policy"
    rule_s = str(rule).strip() or "policy"
    tool_s = (tool_name or "tool").strip() or "tool"
    try:
        canonical = json.dumps(tool_input, sort_keys=True, default=str, separators=(",", ":"))
    except (TypeError, ValueError):
        canonical = str(tool_input)
    fingerprint = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]
    return f"ryk{_RULE_KEY_SEP}{rule_s}{_RULE_KEY_SEP}{tool_s}{_RULE_KEY_SEP}{fingerprint}"


def format_tool_message(response: dict[str, Any], *, default: str = "blocked by ryk") -> str:
    message = response.get("message") or response.get("reason") or default
    if not isinstance(message, str):
        message = default
    remediation = response.get("remediation_commands")
    if isinstance(remediation, list) and remediation:
        tips = "; ".join(str(item) for item in remediation if item)
        if tips:
            message = f"{message} Next: {tips}"
    rule_id = response.get("rule_id") or response.get("rule")
    if rule_id:
        message = f"{message} (rule: {rule_id})"
    return message


def _base_message(response: dict[str, Any], default: str) -> str:
    message = response.get("message") or response.get("reason") or default
    return message if isinstance(message, str) else default


# Prompt templates: Hermes pre_llm_call is context-only — never an approval gate.
_PROMPT_TEMPLATES: dict[str, str] = {
    "warn": "ryk policy note (warn/observe, advisory only): {message}",
    "context_only": "ryk policy note (warn/observe, advisory only): {message}",
    "ask": (
        "ryk policy note (ask — not an approval gate): {message} "
        "Hermes pre_llm_call cannot gate prompts or open approve-and-resume. "
        "This note does not enforce approval. Prefer `ryk run -- hermes` for outer enforcement."
    ),
    "block": (
        "ryk policy note (block — host cannot veto pre_llm_call): {message} "
        "Hermes pre_llm_call cannot block the turn; this note does not enforce a deny. "
        "Prefer `ryk run -- hermes` for outer enforcement."
    ),
}


def map_pre_llm_call(response: dict[str, Any]) -> dict[str, str] | None:
    """Map ryk decision → Hermes pre_llm_call context (advisory only)."""
    decision = response.get("decision")
    template = _PROMPT_TEMPLATES.get(decision) if isinstance(decision, str) else None
    if template is None:
        return None
    message = _base_message(response, "Review this prompt under ryk policy.")
    return {"context": template.format(message=message)}


def map_pre_tool_call(
    response: dict[str, Any],
    tool_name: str,
    tool_input: Any,
    *,
    log_warn: Callable[[str], None] | None = None,
    environ: dict[str, str] | None = None,
) -> dict[str, Any] | None:
    """Map ryk decision → Hermes pre_tool_call directive.

    - allow → None (proceed)
    - block → {"action": "block", ...}
    - ask → {"action": "approve", ...} or block under CI
    - warn → log advisory + None (not collapsed to block)
    - other → fail-closed block
    """
    decision = response.get("decision")
    if decision == "allow":
        return None
    if decision == "warn":
        message = format_tool_message(response, default="policy warning from ryk")
        if log_warn is not None:
            log_warn(f"WARN (advisory, not blocked): {message}")
        return None
    if decision == "block":
        return {
            "action": "block",
            "message": format_tool_message(response, default="blocked by ryk"),
        }
    if decision == "ask":
        message = format_tool_message(response, default="approval required by ryk")
        if ci_mode(environ):
            return {
                "action": "block",
                "message": (
                    f"{message} "
                    "(CI/noninteractive: ryk ask hardened to block; no approval prompt available)"
                ),
            }
        return {
            "action": "approve",
            "message": message,
            "rule_key": stable_rule_key(response, tool_name, tool_input),
        }
    return {
        "action": "block",
        "message": "ryk returned an invalid tool decision; blocked fail-closed.",
    }


def tool_action_mode(decision: str) -> str:
    """Machine-readable mode for host-decision-mapping contract tests."""
    return {
        "allow": "proceed",
        "block": "hard_block",
        "ask": "native_approve_and_resume",
        "warn": "advisory_log",
        "error": "fail_closed_block",
    }.get(decision, "fail_closed_block")

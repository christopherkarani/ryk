"""Pure ryk decision → Hermes host action mapping.

Policy stays in ryk; this module only translates decisions into Hermes
pre_tool_call / pre_llm_call return shapes. No I/O, no subprocess.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
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
_MAX_MESSAGE_CHARS = 2048
_MAX_RULE_COMPONENT_CHARS = 256
_MAX_RULE_INPUT_CHARS = 65536
_MAX_REMEDIATION_COMMANDS = 4
_SECRET_TEXT_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|token|api[_-]?key|apikey|api[_-]?secret|secret|"
    r"authorization|credential|access[_-]?token|refresh[_-]?token)\b"
    r"\s*[:=]\s*(?:bearer\s+)?[^\s,;]+|\bbearer\s+[^\s,;]+"
)


def _bounded_text(value: Any, default: str, limit: int = _MAX_MESSAGE_CHARS) -> str:
    if not isinstance(value, str) or not value.strip():
        value = default
    redacted = _SECRET_TEXT_RE.sub(lambda match: f"{match.group(1) or 'bearer'}=[REDACTED]", value)
    if len(redacted) <= limit:
        return redacted
    suffix = "...[truncated]"
    return redacted[: limit - len(suffix)] + suffix


def ci_mode(
    environ: dict[str, str] | None = None,
    *,
    unattended_marker: bool = False,
) -> bool:
    """True when interactive approval cannot be answered (CI / unattended).

    ``unattended_marker`` is the persistent install-time `.ryk_unattended` flag
    (I/O lives in the adapter). When set, ask hardens to block even if CI env
    vars were cleared by a long-lived Hermes daemon.
    """
    if unattended_marker:
        return True
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
    rule_s = _bounded_text(rule, "policy", _MAX_RULE_COMPONENT_CHARS).strip() or "policy"
    tool_s = _bounded_text(tool_name, "tool", _MAX_RULE_COMPONENT_CHARS).strip() or "tool"
    try:
        canonical = json.dumps(
            tool_input,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("Hermes tool input cannot be safely fingerprinted") from exc
    if len(canonical) > _MAX_RULE_INPUT_CHARS:
        raise ValueError("Hermes tool input exceeds the rule-key limit")
    fingerprint = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]
    return f"ryk{_RULE_KEY_SEP}{rule_s}{_RULE_KEY_SEP}{tool_s}{_RULE_KEY_SEP}{fingerprint}"


def format_tool_message(response: dict[str, Any], *, default: str = "blocked by ryk") -> str:
    message = response.get("message") or response.get("reason") or default
    message = _bounded_text(message, default)
    remediation = response.get("remediation_commands")
    if isinstance(remediation, list) and remediation:
        tips = "; ".join(
            _bounded_text(item, "", _MAX_RULE_COMPONENT_CHARS)
            for item in remediation[:_MAX_REMEDIATION_COMMANDS]
            if isinstance(item, str) and item
        )
        if tips:
            message = f"{message} Next: {tips}"
    rule_id = response.get("rule_id") or response.get("rule")
    if rule_id:
        message = f"{message} (rule: {_bounded_text(rule_id, 'policy', _MAX_RULE_COMPONENT_CHARS)})"
    return _bounded_text(message, default)


def _base_message(response: dict[str, Any], default: str) -> str:
    message = response.get("message") or response.get("reason") or default
    return _bounded_text(message, default)


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
    unattended_marker: bool = False,
) -> dict[str, Any] | None:
    """Map ryk decision → Hermes pre_tool_call directive.

    - allow → None (proceed)
    - block → {"action": "block", ...}
    - ask → {"action": "approve", ...} or block under CI / unattended marker
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
        if ci_mode(environ, unattended_marker=unattended_marker):
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

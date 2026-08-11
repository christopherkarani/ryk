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
# Host UI line for block/approve/warn — short, scannable (not operator walls).
_MAX_HOST_MESSAGE_CHARS = 200
_MAX_RULE_COMPONENT_CHARS = 256
_MAX_RULE_INPUT_CHARS = 65536
_SECRET_TEXT_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|token|api[_-]?key|apikey|api[_-]?secret|secret|"
    r"authorization|credential|access[_-]?token|refresh[_-]?token)\b"
    r"\s*[:=]\s*(?:bearer\s+)?[^\s,;]+|\bbearer\s+[^\s,;]+"
)
# Operator-only lines that must never re-inflate Hermes host message.
_OPERATOR_LINE_PREFIXES = ("recourse:", "next:")
# Same-line operator tails (e.g. "blocked. Recourse: … Next: …").
_INLINE_OPERATOR_RE = re.compile(r"(?i)\b(?:recourse|next)\s*:")


def _bounded_text(value: Any, default: str, limit: int = _MAX_MESSAGE_CHARS) -> str:
    if not isinstance(value, str) or not value.strip():
        value = default
    redacted = _SECRET_TEXT_RE.sub(lambda match: f"{match.group(1) or 'bearer'}=[REDACTED]", value)
    if len(redacted) <= limit:
        return redacted
    suffix = "...[truncated]"
    return redacted[: limit - len(suffix)] + suffix


def _first_host_line(value: Any) -> str:
    """First non-empty non-operator line; collapses internal whitespace."""
    if not isinstance(value, str):
        return ""
    for raw in value.splitlines():
        line = " ".join(raw.split())
        if not line:
            continue
        lowered = line.lower()
        if any(lowered.startswith(prefix) for prefix in _OPERATOR_LINE_PREFIXES):
            continue
        # Strip trailing operator walls glued onto the same line.
        cut = _INLINE_OPERATOR_RE.search(line)
        if cut is not None:
            line = line[: cut.start()].rstrip(" -–—|;")
        if not line:
            continue
        return line
    return ""


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
    """Short one-line host message for block/approve/warn.

    Prefer short reason, then first useful line of message, then default.
    Include rule once when present. Never append remediation_commands or
    Recourse/Next operator walls into the host string.
    """
    default_s = default if isinstance(default, str) and default.strip() else "blocked by ryk"
    # Prefer reason → message first line → default (remediation list ignored).
    body = _first_host_line(response.get("reason")) or _first_host_line(response.get("message"))
    if not body:
        body = default_s

    rule_s = ""
    rule_id = response.get("rule_id") or response.get("rule")
    if isinstance(rule_id, str) and rule_id.strip():
        rule_s = _bounded_text(rule_id.strip(), "policy", _MAX_RULE_COMPONENT_CHARS).strip()

    # Reserve room for " (rule: …)" so truncation keeps policy identity.
    rule_suffix = f" (rule: {rule_s})" if rule_s and rule_s not in body else ""
    body_limit = max(32, _MAX_HOST_MESSAGE_CHARS - len(rule_suffix))
    body = _bounded_text(body, default_s, body_limit)
    if rule_suffix and rule_s not in body:
        body = f"{body}{rule_suffix}"
    # Single line + tight UI cap (never multi-line walls).
    body = " ".join(body.split())
    return _bounded_text(body, default_s, _MAX_HOST_MESSAGE_CHARS)


def _base_message(response: dict[str, Any], default: str) -> str:
    """Advisory context base: short first line only (no Recourse walls)."""
    line = _first_host_line(response.get("message")) or _first_host_line(response.get("reason"))
    return _bounded_text(line or default, default, _MAX_HOST_MESSAGE_CHARS)


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
            # Keep one line; brief CI clause is OK for unattended harden.
            ci_message = (
                f"{message} "
                "(CI/noninteractive: ryk ask hardened to block; no approval prompt available)"
            )
            return {
                "action": "block",
                "message": _bounded_text(
                    " ".join(ci_message.split()),
                    "blocked by ryk",
                    _MAX_MESSAGE_CHARS,
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

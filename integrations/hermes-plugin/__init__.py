"""Hermes Agent plugin bridge for ryk runtime guardrails."""

from __future__ import annotations

import json
import hashlib
import os
import re
import select
import signal
import shutil
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _load_mapping() -> Any:
    """Load pure mapping helpers as package submodule or sibling file."""
    try:
        from . import mapping as mapping_mod  # type: ignore[attr-defined]

        return mapping_mod
    except ImportError:
        import importlib.util

        path = Path(__file__).resolve().with_name("mapping.py")
        spec = importlib.util.spec_from_file_location("ryk_hermes_mapping", path)
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod


_mapping = _load_mapping()


SECRET_KEYS = (
    "password",
    "token",
    "secret",
    "api_key",
    "apikey",
    "api_secret",
    "auth",
    "authorization",
    "bearer",
    "private_key",
    "access_token",
    "refresh_token",
    "credential",
    "passwd",
    "pwd",
)

POLICY_EVENTS = {"pre_tool_call", "pre_llm_call"}
EVENTS = (
    "on_session_start",
    "pre_tool_call",
    "post_tool_call",
    "pre_llm_call",
    "post_llm_call",
    "on_session_end",
    "on_session_finalize",
    "on_session_reset",
    "subagent_stop",
)

_HERMES_HOST_MISMATCH_MARKERS = (
    "unknown host 'hermes'",
    "Expected codex or claude.",
)
_PRE_TOOL_CALL_DEGRADED_MARKERS = _HERMES_HOST_MISMATCH_MARKERS + (
    "too old for Hermes hooks",
    "does not support Hermes hooks",
    "not found or too old for Hermes hooks",
)
_HERMES_SMOKE_PAYLOAD = json.dumps(
    {
        "version": 1,
        "host": "hermes",
        "event": "pre_tool_call",
        "payload": {"command": "git status"},
        "timestamp": "1970-01-01T00:00:00Z",
    },
    separators=(",", ":"),
)

_ryk_cache_env: str | None = None
_ryk_cache_path: str | None = None


_FAIL_STANCE_FILENAMES = (".ryk_fail_stance",)
_UNATTENDED_MARKER_FILENAMES = (".ryk_unattended",)
_FAIL_CLOSED_TOKENS = frozenset({"0", "false", "no", "off", "fail-closed", "closed"})
_FAIL_OPEN_TOKENS = frozenset({"1", "true", "yes", "on", "fail-open", "open"})
_RYK_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
_MAX_PAYLOAD_BYTES = 64 * 1024
_MAX_POLICY_OUTPUT_BYTES = 64 * 1024
_MAX_PAYLOAD_DEPTH = 32
_MAX_PAYLOAD_NODES = 4096
_MAX_PAYLOAD_STRING_CHARS = 16 * 1024
_MAX_LOG_MESSAGE_CHARS = 2048
_PROCESS_CLEANUP_GRACE_SECONDS = 0.25
_PRE_TOOL_CALL_FAILURE_MESSAGE = "ryk could not verify this Hermes tool call; blocked fail-closed."
_SECRET_TEXT_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|token|api[_-]?key|apikey|api[_-]?secret|secret|"
    r"authorization|credential|access[_-]?token|refresh[_-]?token)\b"
    r"\s*[:=]\s*(?:bearer\s+)?[^\s,;]+|\bbearer\s+[^\s,;]+"
)


class _ProcessOutputLimitError(subprocess.SubprocessError):
    pass


def _cancel_process_io(process: subprocess.Popen[bytes], cancel: threading.Event | None = None) -> None:
    if cancel is not None:
        cancel.set()
    if os.name == "nt":
        return
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream is None:
            continue
        try:
            os.close(stream.fileno())
        except (OSError, ValueError):
            pass


def _terminate_process_group(
    process: subprocess.Popen[bytes],
    cancel: threading.Event | None = None,
) -> None:
    """Kill the hook process/session and cancel any inherited pipe readers."""
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        try:
            process.kill()
        except OSError:
            pass
    _cancel_process_io(process, cancel)
    try:
        process.wait(timeout=1)
    except (OSError, subprocess.TimeoutExpired):
        pass


def _run_process_bounded(
    argv: list[str],
    *,
    input_text: str,
    timeout: float,
    output_limit: int = _MAX_POLICY_OUTPUT_BYTES,
) -> subprocess.CompletedProcess[str]:
    """Run a hook with bounded pipes and whole-process-group timeout cleanup."""
    process = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    assert process.stdin is not None
    assert process.stdout is not None
    assert process.stderr is not None

    overflow = threading.Event()
    cancel = threading.Event()
    stdout_buffer = bytearray()
    stderr_buffer = bytearray()

    def read_stream(stream: Any, destination: bytearray) -> None:
        try:
            if os.name != "nt":
                descriptor = stream.fileno()
                os.set_blocking(descriptor, False)
                while not cancel.is_set():
                    ready, _, _ = select.select([descriptor], [], [], 0.05)
                    if not ready:
                        continue
                    try:
                        chunk = os.read(descriptor, 8192)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        return
                    if len(destination) + len(chunk) > output_limit:
                        overflow.set()
                        return
                    destination.extend(chunk)
                return
            while True:
                chunk = stream.read(8192)
                if not chunk:
                    return
                if len(destination) + len(chunk) > output_limit:
                    overflow.set()
                    return
                destination.extend(chunk)
        except (OSError, ValueError):
            return
        finally:
            try:
                stream.close()
            except OSError:
                pass

    def write_input() -> None:
        try:
            process.stdin.write(input_text.encode("utf-8"))
            process.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
        finally:
            try:
                process.stdin.close()
            except OSError:
                pass

    readers = (
        threading.Thread(target=read_stream, args=(process.stdout, stdout_buffer), daemon=True),
        threading.Thread(target=read_stream, args=(process.stderr, stderr_buffer), daemon=True),
    )
    writer = threading.Thread(target=write_input, daemon=True)
    for thread in readers:
        thread.start()
    writer.start()

    deadline = time.monotonic() + timeout
    while process.poll() is None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _terminate_process_group(process, cancel)
            writer.join(timeout=_PROCESS_CLEANUP_GRACE_SECONDS)
            for thread in readers:
                thread.join(timeout=_PROCESS_CLEANUP_GRACE_SECONDS)
            raise subprocess.TimeoutExpired(argv, timeout)
        if overflow.wait(timeout=min(0.02, remaining)):
            _terminate_process_group(process, cancel)
            writer.join(timeout=_PROCESS_CLEANUP_GRACE_SECONDS)
            for thread in readers:
                thread.join(timeout=_PROCESS_CLEANUP_GRACE_SECONDS)
            raise _ProcessOutputLimitError("ryk subprocess output limit exceeded")

    # Once the parent has exited, pipe holders are no longer part of the
    # command's useful work. Give inherited descriptors their own short,
    # bounded drain window instead of spending the remaining command deadline
    # waiting for a detached descendant.
    writer.join(timeout=_PROCESS_CLEANUP_GRACE_SECONDS)
    for thread in readers:
        thread.join(timeout=_PROCESS_CLEANUP_GRACE_SECONDS)
    if overflow.is_set():
        _terminate_process_group(process, cancel)
        raise _ProcessOutputLimitError("ryk subprocess output limit exceeded")
    if writer.is_alive() or any(thread.is_alive() for thread in readers):
        _terminate_process_group(process, cancel)
        writer.join(timeout=_PROCESS_CLEANUP_GRACE_SECONDS)
        for thread in readers:
            thread.join(timeout=_PROCESS_CLEANUP_GRACE_SECONDS)
        raise subprocess.TimeoutExpired(argv, timeout)

    return subprocess.CompletedProcess(
        argv,
        process.returncode,
        stdout_buffer.decode("utf-8"),
        stderr_buffer.decode("utf-8"),
    )


def _parse_fail_open_token(raw: str) -> bool | None:
    token = raw.strip().lower()
    if not token:
        return None
    if token in _FAIL_CLOSED_TOKENS:
        return False
    if token in _FAIL_OPEN_TOKENS:
        return True
    return None


def _stance_file_fail_open() -> bool | None:
    """Read install-time stance next to this plugin (written for *new* ryk plugin install hermes)."""
    base = Path(__file__).resolve().parent
    for name in _FAIL_STANCE_FILENAMES:
        path = base / name
        try:
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parsed = _parse_fail_open_token(stripped)
            if parsed is not None:
                return parsed
    return None


def _unattended_install_marker_present() -> bool:
    base = Path(__file__).resolve().parent
    for name in _UNATTENDED_MARKER_FILENAMES:
        try:
            if (base / name).is_file():
                return True
        except OSError:
            continue
    return False


def _fail_open_enabled() -> bool:
    """Allow Hermes to proceed without ryk only when explicitly configured.

    Precedence: active CI/unattended environment or `.ryk_unattended` marker →
    RYK_HERMES_FAIL_OPEN env → install stance file → fail-closed default.
    `ryk agents setup hermes` writes the persistent unattended marker.
    """
    # An unattended/CI process must never inherit a fail-open override. The
    # no-human safety boundary dominates install stance and environment escape
    # hatches so a stale supervisor setting cannot turn a missing guard into
    # an allowed tool call.
    if _mapping.ci_mode():
        return False
    if _unattended_install_marker_present():
        return False
    if "RYK_HERMES_FAIL_OPEN" in os.environ:
        parsed = _parse_fail_open_token(os.environ.get("RYK_HERMES_FAIL_OPEN", ""))
        if parsed is not None:
            return parsed
        # Unknown or empty overrides must not silently opt into fail-open.
        return False
    stance = _stance_file_fail_open()
    if stance is not None:
        return stance
    return False


def _redact(
    value: Any,
    *,
    _depth: int = 0,
    _active: set[int] | None = None,
    _budget: list[int] | None = None,
) -> Any:
    """Return a bounded JSON-safe value with secret-key values removed.

    Rejecting unsafe payloads is intentional: pre_tool_call must block rather
    than send a partial policy request that could change the decision.
    """
    if _depth > _MAX_PAYLOAD_DEPTH:
        raise ValueError("Hermes hook payload exceeds maximum depth")
    if _active is None:
        _active = set()
    if _budget is None:
        _budget = [0, 0]
    _budget[0] += 1
    if _budget[0] > _MAX_PAYLOAD_NODES:
        raise ValueError("Hermes hook payload contains too many values")

    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("Hermes hook payload contains a non-finite number")
        return value
    if isinstance(value, str):
        if len(value) > _MAX_PAYLOAD_STRING_CHARS:
            raise ValueError("Hermes hook payload contains an oversized string")
        _budget[1] += len(value)
        if _budget[1] > _MAX_PAYLOAD_BYTES:
            raise ValueError("Hermes hook payload exceeds maximum size")
        return value

    if not isinstance(value, (dict, list, tuple)):
        raise TypeError(f"unsupported Hermes hook payload type: {type(value).__name__}")
    identity = id(value)
    if identity in _active:
        raise ValueError("Hermes hook payload contains a cycle")
    _active.add(identity)
    try:
        if isinstance(value, dict):
            result: dict[str, Any] = {}
            for key, item in value.items():
                if not isinstance(key, str):
                    raise TypeError("Hermes hook payload keys must be strings")
                if any(secret in key.lower() for secret in SECRET_KEYS):
                    result[key] = "[REDACTED]"
                else:
                    result[key] = _redact(
                        item,
                        _depth=_depth + 1,
                        _active=_active,
                        _budget=_budget,
                    )
            return result
        return [
            _redact(
                item,
                _depth=_depth + 1,
                _active=_active,
                _budget=_budget,
            )
            for item in value
        ]
    finally:
        _active.remove(identity)


def _bounded_log_text(value: Any, default: str = "ryk Hermes hook failed") -> str:
    if not isinstance(value, str) or not value.strip():
        value = default
    redacted = _SECRET_TEXT_RE.sub(lambda match: f"{match.group(1) or 'bearer'}=[REDACTED]", value)
    if len(redacted) <= _MAX_LOG_MESSAGE_CHARS:
        return redacted
    suffix = "...[truncated]"
    return redacted[: _MAX_LOG_MESSAGE_CHARS - len(suffix)] + suffix


def _pre_tool_call_failure() -> dict[str, str]:
    return {"action": "block", "message": _PRE_TOOL_CALL_FAILURE_MESSAGE}


def _error_has_marker(error: BaseException, markers: tuple[str, ...]) -> bool:
    try:
        message = str(error)
    except Exception:
        return False
    return any(marker in message for marker in markers)


def _is_degraded_ryk_error(error: BaseException) -> bool:
    if isinstance(error, OSError):
        return True
    return _error_has_marker(error, _PRE_TOOL_CALL_DEGRADED_MARKERS)


def _hook_smoke_passes(stdout: str) -> bool:
    """Probe: exit 0 and non-empty JSON with an explicit usable decision.

    Empty stdout is *not* a pass — planted binaries that print nothing must not
    become the policy oracle (F4/F21).
    """
    trimmed = stdout.strip()
    if not trimmed:
        return False
    try:
        parsed = json.loads(trimmed)
    except json.JSONDecodeError:
        return False
    if not isinstance(parsed, dict):
        return False
    decision = parsed.get("decision")
    if not isinstance(decision, str) or decision not in {"allow", "warn", "ask", "block"}:
        return False
    return decision != "block"


def _ryk_executable(candidate: str) -> str | None:
    if not Path(candidate).is_absolute():
        return None
    try:
        path = Path(candidate).resolve()
    except OSError:
        return None
    if not path.is_file() or not os.access(path, os.X_OK):
        return None
    if not _candidate_is_trusted(path):
        return None
    return str(path)


def _path_is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _candidate_is_trusted(path: Path) -> bool:
    try:
        canonical = path.resolve(strict=True)
        stat = canonical.stat()
        workspace = Path.cwd().resolve()
        temp_roots = {
            Path(tempfile.gettempdir()).resolve(),
            Path("/tmp").resolve(),
            Path("/private/tmp").resolve(),
        }
    except OSError:
        return False
    if "node_modules/.bin" in canonical.as_posix():
        return False
    if any(_path_is_within(canonical, root) for root in temp_roots):
        return False
    if _path_is_within(canonical, workspace) and os.environ.get("RYK_ALLOW_WORKSPACE_BIN") != "1":
        return False
    managed_roots = {
        (Path.home() / ".local" / "bin").resolve(),
        (Path.home() / ".ryk" / "bin").resolve(),
    }
    workspace_override = (
        os.environ.get("RYK_ALLOW_WORKSPACE_BIN") == "1"
        and _path_is_within(canonical, workspace)
    )
    if not any(_path_is_within(canonical, root) for root in managed_roots) and not workspace_override:
        return False
    if os.name != "nt":
        if stat.st_mode & 0o111 == 0 or stat.st_mode & 0o022 != 0:
            return False
        getuid = getattr(os, "getuid", None)
        if callable(getuid) and stat.st_uid != getuid():
            return False
    # Explicit workspace fixtures are intentionally allowed for development
    # and tests. Every installer-managed executable must carry a path-bound
    # checksum receipt generated by scripts/install.sh or install.ps1.
    if not workspace_override and not _installer_provenance_valid(canonical):
        return False
    return True


def _installer_provenance_valid(binary: Path, receipt: Path | None = None) -> bool:
    """Validate the installer's path-bound checksum receipt for ``binary``."""
    try:
        canonical = binary.resolve(strict=True)
        receipt_path = receipt or canonical.with_name(".ryk-provenance")
        if receipt_path.is_symlink():
            return False
        if receipt_path.stat().st_size > 4096:
            return False
        lines = receipt_path.read_text(encoding="utf-8").splitlines()
        fields: dict[str, str] = {}
        for line in lines:
            if not line:
                continue
            if "=" not in line:
                if line != "ryk-provenance-v1" or fields:
                    return False
                continue
            key, value = line.split("=", 1)
            if key in fields or key not in {"path", "sha256"} or not value:
                return False
            fields[key] = value
        if set(fields) != {"path", "sha256"} or fields["path"] != str(canonical):
            return False
        if len(fields["sha256"]) != 64 or any(c not in "0123456789abcdef" for c in fields["sha256"].lower()):
            return False
        actual = hashlib.sha256(canonical.read_bytes()).hexdigest()
        return actual == fields["sha256"].lower()
    except (OSError, ValueError, UnicodeError):
        return False


def _is_workspace_candidate(candidate: str) -> bool:
    if os.environ.get("RYK_ALLOW_WORKSPACE_BIN") == "1":
        return False
    try:
        path = Path(candidate).resolve()
        workspace = Path.cwd().resolve()
        path.relative_to(workspace)
        return True
    except (OSError, ValueError):
        pass
    return "node_modules/.bin" in Path(candidate).as_posix()


def _has_ryk_identity(ryk: str) -> bool:
    try:
        completed = _run_process_bounded(
            [ryk, "version", "--json"],
            input_text="",
            timeout=3,
        )
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return False
    if completed.returncode != 0:
        return False
    try:
        identity = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return False
    version = identity.get("version") if isinstance(identity, dict) else None
    return (
        isinstance(identity, dict)
        and identity.get("product") == "ryk"
        and isinstance(version, str)
        and bool(_RYK_VERSION_RE.fullmatch(version))
    )


def _supports_hermes_host(ryk: str) -> bool:
    if not _has_ryk_identity(ryk):
        return False
    try:
        completed = _run_process_bounded(
            [ryk, "hook", "hermes", "pre_tool_call"],
            input_text=_HERMES_SMOKE_PAYLOAD,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return False
    if completed.returncode != 0:
        return False
    return _hook_smoke_passes(completed.stdout)


def _ryk_candidates() -> list[str]:
    trusted: list[str] = []
    configured = os.environ.get("RYK_BIN")
    if configured:
        resolved = _ryk_executable(configured)
        if resolved:
            trusted.append(resolved)

    # Trusted installs and PATH before cwd zig-out (F10): a planted
    # ./zig-out/bin/ryk must not beat ~/.local/bin or PATH when both exist.
    home = Path.home()
    for path in (home / ".local" / "bin" / "ryk", home / ".ryk" / "bin" / "ryk"):
        resolved = _ryk_executable(str(path))
        if resolved:
            trusted.append(resolved)

    found = shutil.which("ryk")
    if found:
        resolved = _ryk_executable(found)
        if resolved:
            trusted.append(resolved)

    # F4: when any trusted candidate exists, never fall through to cwd zig-out
    # (planted binary must not become oracle after trusted smoke fails).
    candidates: list[str] = list(trusted)
    if not trusted and os.environ.get("RYK_ALLOW_WORKSPACE_BIN") == "1":
        directory = Path.cwd()
        for _ in range(3):
            zig_out = directory / "zig-out" / "bin" / "ryk"
            resolved = _ryk_executable(str(zig_out))
            if resolved:
                candidates.append(resolved)
            if directory.parent == directory:
                break
            directory = directory.parent

    deduped: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        if candidate not in seen:
            seen.add(candidate)
            deduped.append(candidate)
    return deduped


def _find_ryk() -> str | None:
    global _ryk_cache_env, _ryk_cache_path
    env_bin = os.environ.get("RYK_BIN")
    if _ryk_cache_path is not None and _ryk_cache_env == env_bin:
        return _ryk_cache_path

    for candidate in _ryk_candidates():
        if _is_workspace_candidate(candidate):
            continue
        try:
            if _supports_hermes_host(candidate):
                _ryk_cache_env = env_bin
                _ryk_cache_path = candidate
                return candidate
        except OSError:
            continue
    return None


def _warn_degraded(ctx: Any, event: str, message: str) -> None:
    """Always surface degraded-path warnings — never silent fail-open."""
    full = f"[ryk-hermes] {_bounded_log_text(message)}"
    logger = getattr(ctx, "logger", None)
    if logger and hasattr(logger, "warning"):
        logger.warning(full)
    # Also print so non-logger hosts and CI logs always see the stance.
    print(f"warning: {full}", flush=True)


def _handle_hook_error(ctx: Any, event: str, exc: BaseException) -> Any:
    if event == "pre_tool_call" and _is_degraded_ryk_error(exc):
        if not _fail_open_enabled():
            return _pre_tool_call_failure()
        _warn_degraded(
            ctx,
            event,
            "FAIL-OPEN: ryk is missing or too old for Hermes hooks; upgrade ryk or set RYK_BIN. "
            "Allowing tool call WITHOUT ryk guardrails. "
            "Set RYK_HERMES_FAIL_OPEN=0 to block, or use `ryk run -- hermes`.",
        )
        return None
    if event == "pre_tool_call":
        return _pre_tool_call_failure()
    if _error_has_marker(exc, _HERMES_HOST_MISMATCH_MARKERS):
        _warn_degraded(
            ctx,
            event,
            "FAIL-OPEN: ryk is too old for Hermes hooks; upgrade ryk or set RYK_BIN. "
            "Continuing without ryk guardrails for this event.",
        )
        return None
    logger = getattr(ctx, "logger", None)
    try:
        raw_error = str(exc)
    except Exception:
        raw_error = "hook failed"
    error_message = _bounded_log_text(raw_error)
    if logger and hasattr(logger, "warning"):
        logger.warning("ryk Hermes hook failed for %s: %s", event, error_message)
    else:
        print(f"warning: [ryk-hermes] hook failed for {event}: {error_message}", flush=True)
    return None


def _event_payload(event: str, hook_args: tuple[Any, ...], hook_kwargs: dict[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "hook_event_name": event,
        "args": hook_args,
        "kwargs": hook_kwargs,
        "extra": dict(hook_kwargs),
    }

    if event in {"pre_tool_call", "post_tool_call"}:
        if "tool_name" in hook_kwargs:
            payload["tool_name"] = hook_kwargs["tool_name"]
        elif len(hook_args) > 0:
            payload["tool_name"] = hook_args[0]

        if "args" in hook_kwargs:
            payload["tool_input"] = hook_kwargs["args"]
        elif "params" in hook_kwargs:
            payload["tool_input"] = hook_kwargs["params"]
        elif len(hook_args) > 1:
            payload["tool_input"] = hook_args[1]

    if event in {"pre_llm_call", "post_llm_call"}:
        for key in ("session_id", "user_message", "conversation_history", "model", "platform"):
            if key in hook_kwargs:
                payload[key] = hook_kwargs[key]
        if "user_message" not in payload and len(hook_args) > 1:
            payload["user_message"] = hook_args[1]

    return payload


def _payload(event: str, data: Any) -> str:
    payload = json.dumps(
        {
            "version": 1,
            "host": "hermes",
            "event": event,
            "payload": _redact(data),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
        separators=(",", ":"),
        allow_nan=False,
    )
    if len(payload.encode("utf-8")) > _MAX_PAYLOAD_BYTES:
        raise ValueError("Hermes hook payload exceeds maximum size")
    return payload


def _call_ryk(event: str, data: Any) -> dict[str, Any]:
    ryk = _find_ryk()
    if not ryk:
        raise RuntimeError(
            "ryk binary not found or too old for Hermes hooks. "
            "Install ryk or set RYK_BIN to an absolute executable path."
        )

    # The discovery result is cached for the plugin lifetime, so re-attest the
    # path immediately before every policy call. This narrows the replacement
    # window between discovery and use; it does not claim cryptographic
    # authenticity when a same-user actor can rewrite both binary and receipt.
    revalidated = _ryk_executable(ryk)
    if revalidated != ryk:
        raise RuntimeError(
            "ryk executable provenance or identity could not be re-attested; "
            "refusing the Hermes policy call"
        )

    try:
        completed = _run_process_bounded(
            [ryk, "hook", "hermes", event],
            input_text=_payload(event, data),
            timeout=15 if event in POLICY_EVENTS else 10,
        )
    except OSError as exc:
        raise RuntimeError(f"failed to run ryk at {ryk}: {exc}") from exc
    if not isinstance(completed.stdout, str) or not isinstance(completed.stderr, str):
        raise RuntimeError("ryk returned invalid process output")
    if len(completed.stdout.encode("utf-8")) > _MAX_POLICY_OUTPUT_BYTES:
        raise RuntimeError("ryk policy output exceeded the response limit")
    if len(completed.stderr.encode("utf-8")) > _MAX_POLICY_OUTPUT_BYTES:
        raise RuntimeError("ryk diagnostic output exceeded the response limit")
    if completed.returncode != 0:
        # Child diagnostics may contain command arguments or provider secrets.
        # The policy boundary needs the exit status, never verbatim stderr.
        raise RuntimeError(f"ryk exited {completed.returncode}")
    # F21: empty successful stdout is not an allow — fail closed so fail-open stance applies.
    if not completed.stdout.strip():
        raise RuntimeError(
            f"ryk at {ryk} returned empty stdout for hermes {event}; "
            "refusing hard-allow on empty policy response"
        )
    response = json.loads(completed.stdout)
    if not isinstance(response, dict):
        raise RuntimeError(
            f"ryk at {ryk} returned a non-object response for hermes {event}; "
            "refusing to map an ambiguous policy result"
        )
    return response


def _log_policy_warn(ctx: Any, message: str) -> None:
    """Surface an advisory policy warn — not a degraded/fail-open path."""
    full = f"[ryk-hermes] {_bounded_log_text(message)}"
    logger = getattr(ctx, "logger", None)
    if logger and hasattr(logger, "warning"):
        logger.warning(full)
    print(f"warning: {full}", flush=True)


# Re-export pure mapping helpers for tests and external callers.
_ci_mode = _mapping.ci_mode
_stable_rule_key = _mapping.stable_rule_key
_format_tool_message = _mapping.format_tool_message
_map_pre_llm_call = _mapping.map_pre_llm_call


def _map_pre_tool_call(
    ctx: Any,
    response: dict[str, Any],
    tool_name: str,
    tool_input: Any,
) -> Any:
    return _mapping.map_pre_tool_call(
        response,
        tool_name,
        tool_input,
        log_warn=lambda msg: _log_policy_warn(ctx, msg),
    )


def _register(ctx: Any, event: str) -> None:
    def handler(*args: Any, **kwargs: Any) -> Any:
        try:
            payload = _event_payload(event, args, kwargs)
            response = _call_ryk(event, payload)
            if event == "pre_tool_call":
                tool_name = str(payload.get("tool_name") or kwargs.get("tool_name") or "")
                tool_input = payload.get("tool_input")
                if tool_input is None:
                    tool_input = kwargs.get("args") or kwargs.get("params") or {}
                return _map_pre_tool_call(ctx, response, tool_name, tool_input)
            if event == "pre_llm_call":
                return _map_pre_llm_call(response)
            return None
        except Exception as exc:
            try:
                return _handle_hook_error(ctx, event, exc)
            except Exception:
                # The host hook contract is more important than diagnostics:
                # no logger, formatter, or exception object may escape a tool gate.
                return _pre_tool_call_failure() if event == "pre_tool_call" else None

    ctx.register_hook(event, handler)


def register(ctx: Any) -> None:
    for event in EVENTS:
        _register(ctx, event)

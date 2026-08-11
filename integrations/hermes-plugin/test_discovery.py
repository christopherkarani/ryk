"""Unit tests for Hermes plugin ryk discovery and degraded-mode handling."""

from __future__ import annotations

import importlib.util
from concurrent.futures import ThreadPoolExecutor
import contextlib
import hashlib
import io
import json
import os
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

_PLUGIN_PATH = Path(__file__).with_name("__init__.py")
_SPEC = importlib.util.spec_from_file_location("hermes_plugin", _PLUGIN_PATH)
assert _SPEC and _SPEC.loader
_PLUGIN = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _PLUGIN
_SPEC.loader.exec_module(_PLUGIN)


@contextlib.contextmanager
def _chdir(path: str):
    previous = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


class HermesPluginDiscoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        _PLUGIN._ryk_cache_env = None
        _PLUGIN._ryk_cache_path = None

    def test_fail_open_requires_explicit_configuration(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("RYK_HERMES_FAIL_OPEN", None)
            with mock.patch.object(_PLUGIN, "_stance_file_fail_open", return_value=None):
                self.assertFalse(_PLUGIN._fail_open_enabled())
        with mock.patch.dict(os.environ, {"RYK_HERMES_FAIL_OPEN": "0"}):
            self.assertFalse(_PLUGIN._fail_open_enabled())
        with mock.patch.dict(os.environ, {"RYK_HERMES_FAIL_OPEN": "typo"}):
            self.assertFalse(_PLUGIN._fail_open_enabled())

    def test_unattended_install_marker_dominates_fail_open_environment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            plugin_file = Path(directory) / "__init__.py"
            (Path(directory) / ".ryk_unattended").write_text("1\n", encoding="utf-8")
            with mock.patch.object(_PLUGIN, "__file__", str(plugin_file)), mock.patch.dict(
                os.environ,
                {"RYK_HERMES_FAIL_OPEN": "1"},
                clear=True,
            ):
                self.assertFalse(_PLUGIN._fail_open_enabled())

    def test_registered_pre_tool_call_fail_closes_without_mocked_policy_call(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with _chdir(directory), mock.patch.dict(
                os.environ,
                {"RYK_BIN": str(Path(directory) / "missing-ryk"), "HOME": directory, "PATH": directory},
                clear=True,
            ):
                ctx = mock.Mock()
                _PLUGIN._register(ctx, "pre_tool_call")
                handler = ctx.register_hook.call_args.args[1]
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    result = handler(tool_name="terminal", args={"command": "git status"})

        self.assertEqual(result.get("action"), "block")
        self.assertNotIn("FAIL-OPEN", output.getvalue())

    def test_registered_pre_tool_call_invokes_actual_ryk_binary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "ryk"
            log = Path(directory) / "invocations.log"
            binary.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = version ]; then printf '%s\\n' '{\"product\":\"ryk\",\"version\":\"1.2.9\"}'; exit 0; fi\n"
                "payload=$(/bin/cat)\n"
                "printf '%s\\n' \"$*\" >> \"$RYK_HERMES_TEST_LOG\"\n"
                "printf '%s\\n' \"$payload\" >> \"$RYK_HERMES_TEST_LOG\"\n"
                "printf '%s\\n' '{\"decision\":\"allow\"}'\n",
                encoding="utf-8",
            )
            binary.chmod(0o700)
            with mock.patch.object(_PLUGIN, "_candidate_is_trusted", return_value=True), mock.patch.dict(
                os.environ,
                {
                    "RYK_BIN": str(binary),
                    "RYK_HERMES_TEST_LOG": str(log),
                    "HOME": directory,
                    "PATH": directory,
                    "RYK_ALLOW_WORKSPACE_BIN": "1",
                },
                clear=True,
            ):
                ctx = mock.Mock()
                _PLUGIN._register(ctx, "pre_tool_call")
                handler = ctx.register_hook.call_args.args[1]
                result = handler(tool_name="terminal", args={"command": "git status"})

            invocations = log.read_text(encoding="utf-8").splitlines()

        self.assertIsNone(result)
        self.assertEqual(invocations[0], "hook hermes pre_tool_call")
        self.assertEqual(invocations[2], "hook hermes pre_tool_call")
        self.assertTrue(all('"host":"hermes"' in payload for payload in (invocations[1], invocations[3])))
        self.assertTrue(all('"event":"pre_tool_call"' in payload for payload in (invocations[1], invocations[3])))

    def test_identity_probe_rejects_non_ryk_binary(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["binary", "version", "--json"],
            returncode=0,
            stdout='{"product":"not-ryk","version":"1.2.9"}\n',
            stderr="",
        )
        with mock.patch.object(_PLUGIN, "_run_process_bounded", return_value=completed):
            self.assertFalse(_PLUGIN._has_ryk_identity("/tmp/binary"))

    def test_installer_provenance_requires_canonical_path_and_matching_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "ryk"
            receipt = Path(directory) / ".ryk-provenance"
            binary.write_bytes(b"ryk binary")
            digest = __import__("hashlib").sha256(binary.read_bytes()).hexdigest()
            receipt.write_text(
                "ryk-provenance-v1\n"
                f"path={binary.resolve()}\n"
                f"sha256={digest}\n",
                encoding="utf-8",
            )
            self.assertTrue(_PLUGIN._installer_provenance_valid(binary))
            receipt.write_text(receipt.read_text(encoding="utf-8").replace(digest, "0" * 64), encoding="utf-8")
            self.assertFalse(_PLUGIN._installer_provenance_valid(binary))

    def test_ryk_executable_rejects_temp_and_group_writable_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "ryk"
            candidate.write_text("#!/bin/sh\n", encoding="utf-8")
            candidate.chmod(0o755)
            self.assertIsNone(_PLUGIN._ryk_executable(str(candidate)))

        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory, mock.patch.dict(
            os.environ, {"RYK_ALLOW_WORKSPACE_BIN": "1"}
        ):
            candidate = Path(directory) / "ryk"
            candidate.write_text("#!/bin/sh\n", encoding="utf-8")
            candidate.chmod(0o775)
            self.assertIsNone(_PLUGIN._ryk_executable(str(candidate)))

    def test_workspace_fallback_requires_explicit_opt_in(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "zig-out" / "bin" / "ryk"
            candidate.parent.mkdir(parents=True)
            candidate.write_text("#!/bin/sh\n", encoding="utf-8")
            candidate.chmod(0o700)
            with _chdir(directory), mock.patch.dict(
                os.environ, {"HOME": directory, "PATH": ""}, clear=True
            ):
                self.assertEqual(_PLUGIN._ryk_candidates(), [])

    def test_managed_local_bin_trusted_when_cwd_is_home(self) -> None:
        """~/.local/bin/ryk must attest even when process cwd is $HOME."""
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            managed = home / ".local" / "bin"
            managed.mkdir(parents=True)
            binary = managed / "ryk"
            binary.write_bytes(b"#!/bin/sh\n# ryk fixture\n")
            binary.chmod(0o700)
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            receipt = managed / ".ryk-provenance"
            receipt.write_text(
                "ryk-provenance-v1\n"
                f"path={binary.resolve()}\n"
                f"sha256={digest}\n",
                encoding="utf-8",
            )
            with _chdir(str(home)), mock.patch.dict(
                os.environ,
                {"HOME": str(home), "PATH": "", "RYK_ALLOW_WORKSPACE_BIN": "0"},
                clear=False,
            ):
                os.environ.pop("RYK_ALLOW_WORKSPACE_BIN", None)
                self.assertTrue(_PLUGIN._candidate_is_trusted(binary))
                self.assertEqual(_PLUGIN._ryk_executable(str(binary)), str(binary.resolve()))

    def test_policy_workspace_cwd_prefers_marker_workspace_over_plugin_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            plugin_dir = Path(directory) / "plugin"
            workspace = Path(directory) / "workspace"
            plugin_dir.mkdir()
            workspace.mkdir()
            plugin_file = plugin_dir / "__init__.py"
            plugin_file.write_text("# fixture\n", encoding="utf-8")
            (plugin_dir / ".ryk_unattended").write_text(
                "ryk-hermes-unattended-v1\n"
                f"path={plugin_dir.resolve()}\n"
                f"workspace={workspace.resolve()}\n",
                encoding="utf-8",
            )
            with mock.patch.object(_PLUGIN, "__file__", str(plugin_file)), mock.patch.dict(
                os.environ, {}, clear=False
            ):
                os.environ.pop("RYK_HERMES_WORKSPACE", None)
                pinned = _PLUGIN._policy_workspace_cwd()
            self.assertEqual(pinned, str(workspace.resolve()))

    def test_policy_workspace_skips_integrity_only_plugin_path(self) -> None:
        """Zig integrity path=<plugin-dir> is not a policy workspace pin."""
        with tempfile.TemporaryDirectory() as directory:
            plugin_dir = Path(directory) / "plugin"
            plugin_dir.mkdir()
            plugin_file = plugin_dir / "__init__.py"
            plugin_file.write_text("# fixture\n", encoding="utf-8")
            (plugin_dir / ".ryk_unattended").write_text(
                "ryk-hermes-unattended-v1\n"
                f"path={plugin_dir.resolve()}\n",
                encoding="utf-8",
            )
            with mock.patch.object(_PLUGIN, "__file__", str(plugin_file)), mock.patch.dict(
                os.environ, {}, clear=False
            ):
                os.environ.pop("RYK_HERMES_WORKSPACE", None)
                self.assertIsNone(_PLUGIN._policy_workspace_cwd())

    def test_call_ryk_passes_policy_workspace_as_cwd(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["ryk", "hook", "hermes", "pre_tool_call", "--ci"],
            returncode=0,
            stdout='{"decision":"allow"}\n',
            stderr="",
        )
        captured: dict[str, Any] = {}

        def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            captured["argv"] = list(argv)
            captured["cwd"] = kwargs.get("cwd")
            return completed

        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(_PLUGIN, "_find_ryk", return_value="/usr/local/bin/ryk"), mock.patch.object(
                _PLUGIN, "_ryk_executable", return_value="/usr/local/bin/ryk"
            ), mock.patch.object(_PLUGIN, "_is_unattended", return_value=True), mock.patch.object(
                _PLUGIN, "_policy_workspace_cwd", return_value=directory
            ), mock.patch.object(_PLUGIN, "_run_process_bounded", side_effect=fake_run):
                _PLUGIN._call_ryk("pre_tool_call", {"tool_name": "terminal"})
        self.assertEqual(captured["cwd"], directory)
        self.assertIn("--ci", captured["argv"])

    def test_cancel_process_io_closes_streams_not_raw_fileno(self) -> None:
        process = mock.Mock()
        stdout = mock.Mock()
        stdout.fileno.return_value = 3
        process.stdin = None
        process.stdout = stdout
        process.stderr = None
        cancel = __import__("threading").Event()
        with mock.patch.object(_PLUGIN.os, "close") as raw_close:
            _PLUGIN._cancel_process_io(process, cancel)
        self.assertTrue(cancel.is_set())
        stdout.close.assert_called_once()
        raw_close.assert_not_called()

    def test_terminate_process_group_retries_wait_after_kill(self) -> None:
        process = mock.Mock()
        process.pid = 4242
        process.stdin = process.stdout = process.stderr = None
        waits = {"n": 0}

        def fake_wait(timeout: float = None) -> int:  # type: ignore[assignment]
            waits["n"] += 1
            if waits["n"] < 3:
                raise subprocess.TimeoutExpired(cmd=["ryk"], timeout=timeout or 0)
            return 0

        process.wait.side_effect = fake_wait
        with mock.patch.object(_PLUGIN, "_kill_process_tree") as kill_tree:
            _PLUGIN._terminate_process_group(process, None)
        kill_tree.assert_called_once_with(process)
        self.assertGreaterEqual(process.wait.call_count, 3)

    def test_kill_process_tree_windows_uses_taskkill_and_process_kill(self) -> None:
        process = mock.Mock()
        process.pid = 99
        with mock.patch.object(_PLUGIN.os, "name", "nt"), mock.patch.object(
            _PLUGIN.subprocess, "run"
        ) as run:
            _PLUGIN._kill_process_tree(process)
        run.assert_called_once()
        args = run.call_args.args[0]
        self.assertEqual(args[:2], ["taskkill", "/PID"])
        self.assertIn("99", args)
        self.assertIn("/T", args)
        process.kill.assert_called()

    def test_call_ryk_rejects_non_object_success_response(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["ryk", "hook", "hermes", "pre_tool_call"],
            returncode=0,
            stdout="[]\n",
            stderr="",
        )
        with mock.patch.object(_PLUGIN, "_find_ryk", return_value="/tmp/ryk"), mock.patch.object(
            _PLUGIN, "_ryk_executable", return_value="/tmp/ryk"
        ), mock.patch.object(_PLUGIN, "_run_process_bounded", return_value=completed):
            with self.assertRaisesRegex(RuntimeError, "non-object response"):
                _PLUGIN._call_ryk("pre_tool_call", {"tool_name": "terminal"})

    def test_call_ryk_rejects_a_replaced_cached_binary(self) -> None:
        with mock.patch.object(_PLUGIN, "_find_ryk", return_value="/tmp/ryk"), mock.patch.object(
            _PLUGIN, "_ryk_executable", return_value=None
        ):
            with self.assertRaisesRegex(RuntimeError, "provenance|identity|trusted"):
                _PLUGIN._call_ryk("pre_tool_call", {"tool_name": "terminal"})

    def test_fail_open_stance_file_fail_closed_for_new_installs(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("RYK_HERMES_FAIL_OPEN", None)
            with mock.patch.object(_PLUGIN, "_stance_file_fail_open", return_value=False):
                self.assertFalse(_PLUGIN._fail_open_enabled())
            # Env wins over stance file.
            with mock.patch.dict(os.environ, {"RYK_HERMES_FAIL_OPEN": "1"}):
                with mock.patch.object(_PLUGIN, "_stance_file_fail_open", return_value=False):
                    self.assertTrue(_PLUGIN._fail_open_enabled())

    def test_parse_fail_open_token(self) -> None:
        self.assertIs(_PLUGIN._parse_fail_open_token("fail-closed"), False)
        self.assertIs(_PLUGIN._parse_fail_open_token("0"), False)
        self.assertIs(_PLUGIN._parse_fail_open_token("fail-open"), True)
        self.assertIsNone(_PLUGIN._parse_fail_open_token(""))

    def test_ryk_executable_rejects_missing_file(self) -> None:
        self.assertIsNone(_PLUGIN._ryk_executable("/nonexistent/ryk-binary"))

    def test_hook_smoke_passes_blocks_only(self) -> None:
        self.assertTrue(_PLUGIN._hook_smoke_passes('{"decision":"allow"}'))
        self.assertFalse(_PLUGIN._hook_smoke_passes('{"decision":"block"}'))
        self.assertFalse(_PLUGIN._hook_smoke_passes("{}"))
        self.assertFalse(_PLUGIN._hook_smoke_passes('{"decision":"unknown"}'))
        # F21: empty stdout must not pass smoke (planted binary oracle).
        self.assertFalse(_PLUGIN._hook_smoke_passes(""))
        self.assertFalse(_PLUGIN._hook_smoke_passes("   "))

    def test_find_ryk_skips_oserror_from_smoke_probe(self) -> None:
        with mock.patch.object(_PLUGIN, "_ryk_candidates", return_value=["/tmp/ryk"]):
            with mock.patch.object(_PLUGIN, "_supports_hermes_host", side_effect=OSError("spawn failed")):
                self.assertIsNone(_PLUGIN._find_ryk())

    def test_pre_tool_call_fail_closed_when_disabled(self) -> None:
        ctx = mock.Mock()
        exc = RuntimeError("ryk binary not found or too old for Hermes hooks")
        with mock.patch.dict(os.environ, {"RYK_HERMES_FAIL_OPEN": "0"}):
            result = _PLUGIN._handle_hook_error(ctx, "pre_tool_call", exc)
        self.assertIsInstance(result, dict)
        assert result is not None
        self.assertEqual(result.get("action"), "block")

    def test_pre_tool_call_fail_open_when_enabled(self) -> None:
        ctx = mock.Mock()
        exc = RuntimeError("ryk binary not found or too old for Hermes hooks")
        with mock.patch.dict(os.environ, {"RYK_HERMES_FAIL_OPEN": "1"}):
            with mock.patch("builtins.print") as printed:
                result = _PLUGIN._handle_hook_error(ctx, "pre_tool_call", exc)
        self.assertIsNone(result)
        # Degraded allow must not be silent.
        printed.assert_called()
        warn_text = " ".join(str(c) for c in printed.call_args_list)
        self.assertIn("FAIL-OPEN", warn_text)
        self.assertIn("RYK_HERMES_FAIL_OPEN=0", warn_text)

    def test_unattended_overrides_fail_open(self) -> None:
        ctx = mock.Mock()
        exc = RuntimeError("ryk binary not found or too old for Hermes hooks")
        with mock.patch.dict(
            os.environ,
            {"RYK_HERMES_FAIL_OPEN": "1", "RYK_UNATTENDED": "1"},
            clear=False,
        ):
            with mock.patch("builtins.print") as printed:
                result = _PLUGIN._handle_hook_error(ctx, "pre_tool_call", exc)
        self.assertIsInstance(result, dict)
        assert result is not None
        self.assertEqual(result.get("action"), "block")
        printed.assert_not_called()

    def test_pre_tool_call_blocks_hard_deny(self) -> None:
        ctx = mock.Mock()
        _PLUGIN._register(ctx, "pre_tool_call")
        handler = ctx.register_hook.call_args.args[1]
        with mock.patch.object(
            _PLUGIN,
            "_call_ryk",
            return_value={"decision": "block", "message": "block by ryk"},
        ):
            result = handler(tool_name="terminal", args={"command": "rm -rf /"})
        self.assertEqual(result, {"action": "block", "message": "block by ryk"})

    def test_pre_tool_call_block_always_has_meaningful_message(self) -> None:
        ctx = mock.Mock()
        _PLUGIN._register(ctx, "pre_tool_call")
        handler = ctx.register_hook.call_args.args[1]
        for empty in ("", "   ", None, 123):
            with self.subTest(message=empty), mock.patch.object(
                _PLUGIN,
                "_call_ryk",
                return_value={"decision": "block", "message": empty},
            ):
                result = handler(tool_name="terminal", args={"command": "git status"})
            self.assertEqual(result, {"action": "block", "message": "blocked by ryk"})

    def test_pre_tool_call_ask_uses_native_approve_path(self) -> None:
        """ryk ask must escalate to Hermes human gate, not permanent block-without-resume."""
        ctx = mock.Mock()
        _PLUGIN._register(ctx, "pre_tool_call")
        handler = ctx.register_hook.call_args.args[1]
        with mock.patch.dict(os.environ, {}, clear=False):
            for key in (
                "CI",
                "RYK_CI",
                "RYK_NONINTERACTIVE",
                "RYK_UNATTENDED",
                "RYK_HERMES_UNATTENDED",
            ):
                os.environ.pop(key, None)
            with mock.patch.object(
                _PLUGIN,
                "_call_ryk",
                return_value={
                    "decision": "ask",
                    "message": "approval required by ryk",
                    "rule_id": "core.filesystem:destructive_rm",
                },
            ):
                result = handler(tool_name="terminal", args={"command": "rm -rf /tmp/x"})
        self.assertIsInstance(result, dict)
        assert result is not None
        self.assertEqual(result.get("action"), "approve")
        self.assertIn("approval required by ryk", result.get("message", ""))
        rule_key = result.get("rule_key", "")
        self.assertTrue(rule_key.startswith("ryk|"), rule_key)
        self.assertIn("core.filesystem:destructive_rm", rule_key)
        self.assertIn("|terminal|", f"|{rule_key}|")

    def test_pre_tool_call_ask_hardens_to_block_in_ci(self) -> None:
        ctx = mock.Mock()
        _PLUGIN._register(ctx, "pre_tool_call")
        handler = ctx.register_hook.call_args.args[1]
        with mock.patch.dict(os.environ, {"CI": "true"}):
            with mock.patch.object(
                _PLUGIN,
                "_call_ryk",
                return_value={"decision": "ask", "message": "approval required by ryk"},
            ):
                result = handler(tool_name="terminal", args={"command": "rm -rf /tmp/x"})
        self.assertEqual(result.get("action"), "block")
        self.assertIn("approval required", result.get("message", "").lower())

    def test_pre_tool_call_ask_hardens_to_block_when_unattended(self) -> None:
        ctx = mock.Mock()
        _PLUGIN._register(ctx, "pre_tool_call")
        handler = ctx.register_hook.call_args.args[1]
        with mock.patch.dict(os.environ, {"RYK_UNATTENDED": "1"}, clear=False):
            for key in ("CI", "RYK_CI", "RYK_NONINTERACTIVE", "RYK_HERMES_UNATTENDED"):
                os.environ.pop(key, None)
            with mock.patch.object(
                _PLUGIN,
                "_call_ryk",
                return_value={"decision": "ask", "message": "approval required by ryk"},
            ):
                result = handler(tool_name="terminal", args={"command": "git push"})
        self.assertEqual(result.get("action"), "block")
        self.assertIn("noninteractive", result.get("message", "").lower())

    def test_unattended_marker_hardens_ask_to_block_with_env_cleared(self) -> None:
        """`.ryk_unattended` alone must drive ask→block even when CI env is absent."""
        with tempfile.TemporaryDirectory() as directory:
            plugin_file = Path(directory) / "__init__.py"
            (Path(directory) / ".ryk_unattended").write_text(
                "ryk-hermes-unattended-v1\npath=" + directory + "\n",
                encoding="utf-8",
            )
            ctx = mock.Mock()
            _PLUGIN._register(ctx, "pre_tool_call")
            handler = ctx.register_hook.call_args.args[1]
            cleared = {
                key: ""
                for key in (
                    "CI",
                    "RYK_CI",
                    "RYK_NONINTERACTIVE",
                    "RYK_UNATTENDED",
                    "RYK_HERMES_UNATTENDED",
                )
            }
            with mock.patch.object(_PLUGIN, "__file__", str(plugin_file)), mock.patch.dict(
                os.environ, cleared, clear=False
            ):
                for key in cleared:
                    os.environ.pop(key, None)
                self.assertTrue(_PLUGIN._is_unattended())
                with mock.patch.object(
                    _PLUGIN,
                    "_call_ryk",
                    return_value={"decision": "ask", "message": "approval required by ryk"},
                ):
                    result = handler(tool_name="terminal", args={"command": "git push"})
            self.assertEqual(result.get("action"), "block")
            self.assertIn("noninteractive", result.get("message", "").lower())

    def test_call_ryk_passes_ci_flag_when_unattended(self) -> None:
        """Unattended hooks must invoke `ryk hook hermes … --ci`."""
        completed = subprocess.CompletedProcess(
            args=["ryk", "hook", "hermes", "pre_tool_call", "--ci"],
            returncode=0,
            stdout='{"decision":"allow"}\n',
            stderr="",
        )
        captured: dict[str, Any] = {}

        def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            captured["argv"] = list(argv)
            captured["cwd"] = kwargs.get("cwd")
            return completed

        with mock.patch.object(_PLUGIN, "_find_ryk", return_value="/usr/local/bin/ryk"), mock.patch.object(
            _PLUGIN, "_ryk_executable", return_value="/usr/local/bin/ryk"
        ), mock.patch.object(_PLUGIN, "_is_unattended", return_value=True), mock.patch.object(
            _PLUGIN, "_policy_workspace_cwd", return_value=None
        ), mock.patch.object(_PLUGIN, "_run_process_bounded", side_effect=fake_run):
            response = _PLUGIN._call_ryk("pre_tool_call", {"tool_name": "terminal"})
        self.assertEqual(response.get("decision"), "allow")
        self.assertEqual(
            captured["argv"],
            ["/usr/local/bin/ryk", "hook", "hermes", "pre_tool_call", "--ci"],
        )

    def test_pre_tool_call_warn_is_not_silent_block(self) -> None:
        """warn must not be collapsed to permanent block; log and allow with semantic fidelity."""
        ctx = mock.Mock()
        _PLUGIN._register(ctx, "pre_tool_call")
        handler = ctx.register_hook.call_args.args[1]
        with mock.patch.object(
            _PLUGIN,
            "_call_ryk",
            return_value={"decision": "warn", "message": "warn by ryk"},
        ):
            with mock.patch("builtins.print") as printed:
                result = handler(tool_name="terminal", args={"command": "curl example.com"})
        self.assertIsNone(result)
        warn_text = " ".join(str(c) for c in printed.call_args_list)
        self.assertIn("warn by ryk", warn_text)

    def test_pre_tool_call_rule_key_does_not_over_approve(self) -> None:
        """Distinct tool args under the same rule get distinct rule_keys for [a]lways grain."""
        key_a = _PLUGIN._stable_rule_key(
            {"rule_id": "core.shell:network"},
            "terminal",
            {"command": "curl http://a.example"},
        )
        key_b = _PLUGIN._stable_rule_key(
            {"rule_id": "core.shell:network"},
            "terminal",
            {"command": "curl http://b.example"},
        )
        self.assertNotEqual(key_a, key_b)
        self.assertTrue(key_a.startswith("ryk|core.shell:network|terminal|"), key_a)
        self.assertTrue(key_b.startswith("ryk|core.shell:network|terminal|"), key_b)

        # Same args → same key (stable).
        key_a2 = _PLUGIN._stable_rule_key(
            {"rule_id": "core.shell:network"},
            "terminal",
            {"command": "curl http://a.example"},
        )
        self.assertEqual(key_a, key_a2)

    def test_policy_warn_does_not_use_degraded_framing(self) -> None:
        ctx = mock.Mock()
        _PLUGIN._register(ctx, "pre_tool_call")
        handler = ctx.register_hook.call_args.args[1]
        with mock.patch.object(
            _PLUGIN,
            "_call_ryk",
            return_value={"decision": "warn", "message": "warn by ryk"},
        ):
            with mock.patch("builtins.print") as printed:
                result = handler(tool_name="terminal", args={"command": "curl example.com"})
        self.assertIsNone(result)
        warn_text = " ".join(str(c) for c in printed.call_args_list)
        self.assertIn("warn by ryk", warn_text)
        self.assertNotIn("FAIL-OPEN", warn_text)

    def test_host_decision_mapping_example_matches_tool_modes(self) -> None:
        """Schema example is enforced against pure mapping modes (no silent drift)."""
        example_path = (
            Path(__file__).resolve().parents[1]
            / "common"
            / "schemas"
            / "examples"
            / "hermes-decision-mapping-v1.json"
        )
        example = json.loads(example_path.read_text(encoding="utf-8"))
        mapping_table = example["tool_path"]["mapping"]
        for decision, expected in (
            ("allow", "proceed"),
            ("block", "hard_block"),
            ("ask", "native_approve_and_resume"),
            ("warn", "advisory_log"),
        ):
            with self.subTest(decision=decision):
                self.assertEqual(mapping_table[decision]["mode"], expected)
                self.assertEqual(_PLUGIN._mapping.tool_action_mode(decision), expected)

        # Runtime shapes for key decisions.
        self.assertIsNone(
            _PLUGIN._mapping.map_pre_tool_call({"decision": "allow"}, "terminal", {})
        )
        blocked = _PLUGIN._mapping.map_pre_tool_call(
            {"decision": "block", "message": "no"}, "terminal", {}
        )
        self.assertEqual(blocked["action"], "block")
        approved = _PLUGIN._mapping.map_pre_tool_call(
            {"decision": "ask", "message": "need"},
            "terminal",
            {"command": "x"},
            environ={},
        )
        self.assertEqual(approved["action"], "approve")
        self.assertTrue(approved["rule_key"].startswith("ryk|"))

    def test_pre_tool_call_block_message_is_short_without_remediation(self) -> None:
        """Host block message is one short line: no Next/remediation wall, rule once."""
        ctx = mock.Mock()
        _PLUGIN._register(ctx, "pre_tool_call")
        handler = ctx.register_hook.call_args.args[1]
        with mock.patch.object(
            _PLUGIN,
            "_call_ryk",
            return_value={
                "decision": "block",
                "message": "blocked by ryk",
                "rule_id": "core.filesystem:destructive_rm",
                "remediation_commands": ["ryk explain \"rm -rf /\"", "ryk allowlist list"],
            },
        ):
            result = handler(tool_name="terminal", args={"command": "rm -rf /"})
        self.assertEqual(result.get("action"), "block")
        message = result.get("message", "")
        self.assertTrue(message.strip())
        self.assertNotIn("Next:", message)
        self.assertNotIn("ryk explain", message)
        self.assertNotIn("allowlist", message)
        self.assertNotIn("\n", message)
        self.assertIn("core.filesystem:destructive_rm", message)
        self.assertLessEqual(len(message), 200)

    def test_format_tool_message_collapses_recourse_and_skips_remediation(self) -> None:
        """Multi-line CLI Recourse walls never reach Hermes host message."""
        mapping = _PLUGIN._mapping
        resp = {
            "message": (
                "command blocked by ryk policy: destructive\n"
                "Recourse: operator can run ryk allow-once <code>\n"
                "Next: ryk explain \"rm -rf /\""
            ),
            "reason": "blocked by ryk policy",
            "rule": "core.filesystem:rm-rf-root-home",
            "remediation_commands": [
                "ryk explain \"rm -rf /\"",
                "ryk allow-once <code>",
            ],
        }
        message = mapping.format_tool_message(resp, default="blocked by ryk")
        self.assertNotIn("Recourse", message)
        self.assertNotIn("Next:", message)
        self.assertNotIn("allow-once", message)
        self.assertNotIn("\n", message)
        self.assertTrue(message.strip())
        self.assertIn("core.filesystem:rm-rf-root-home", message)
        # Prefer short reason when present.
        self.assertIn("blocked by ryk policy", message)
        self.assertLessEqual(len(message), 200)

        out = mapping.map_pre_tool_call(
            {**resp, "decision": "block"},
            "terminal",
            {"command": "rm -rf /"},
        )
        assert out is not None
        self.assertEqual(out["action"], "block")
        host_msg = out["message"]
        self.assertNotIn("Recourse", host_msg)
        self.assertNotIn("Next:", host_msg)
        self.assertNotIn("\n", host_msg)
        self.assertLessEqual(len(host_msg), 200)

    def test_format_tool_message_empty_inputs_default_and_rule_only(self) -> None:
        mapping = _PLUGIN._mapping
        empty = mapping.format_tool_message({}, default="blocked by ryk")
        self.assertEqual(empty, "blocked by ryk")

        rule_only = mapping.format_tool_message(
            {"rule_id": "core.shell:network", "message": "", "reason": "   "},
            default="blocked by ryk",
        )
        self.assertIn("blocked by ryk", rule_only)
        self.assertIn("core.shell:network", rule_only)
        self.assertNotIn("\n", rule_only)

    def test_ask_approve_message_is_short_with_stable_rule_key(self) -> None:
        mapping = _PLUGIN._mapping
        out = mapping.map_pre_tool_call(
            {
                "decision": "ask",
                "message": (
                    "approval required by ryk\n"
                    "Recourse: run ryk allow-once <code>"
                ),
                "rule_id": "core.filesystem:destructive_rm",
                "remediation_commands": ["ryk allow-once <code>"],
            },
            "terminal",
            {"command": "rm -rf /tmp/x"},
            environ={},
        )
        assert out is not None
        self.assertEqual(out["action"], "approve")
        self.assertTrue(out["rule_key"].startswith("ryk|core.filesystem:destructive_rm|terminal|"))
        message = out["message"]
        self.assertIn("approval required", message.lower())
        self.assertNotIn("Recourse", message)
        self.assertNotIn("Next:", message)
        self.assertNotIn("\n", message)
        self.assertLessEqual(len(message), 200)

    def test_ci_ask_block_message_is_short_single_line(self) -> None:
        mapping = _PLUGIN._mapping
        out = mapping.map_pre_tool_call(
            {
                "decision": "ask",
                "message": "approval required by ryk\nRecourse: tip",
                "rule": "core.shell:push",
                "remediation_commands": ["ryk explain push"],
            },
            "terminal",
            {"command": "git push"},
            environ={"CI": "true"},
        )
        assert out is not None
        self.assertEqual(out["action"], "block")
        message = out["message"]
        self.assertIn("approval required", message.lower())
        self.assertIn("noninteractive", message.lower())
        self.assertNotIn("Recourse", message)
        self.assertNotIn("Next:", message)
        self.assertNotIn("\n", message)
        self.assertNotIn("ryk explain", message)

    def test_warn_stays_advisory_with_short_log_text(self) -> None:
        mapping = _PLUGIN._mapping
        logs: list[str] = []
        out = mapping.map_pre_tool_call(
            {
                "decision": "warn",
                "message": "warn by ryk\nRecourse: ignore me",
                "remediation_commands": ["ryk explain x"],
            },
            "terminal",
            {"command": "curl example.com"},
            log_warn=logs.append,
        )
        self.assertIsNone(out)
        self.assertEqual(len(logs), 1)
        self.assertIn("WARN (advisory, not blocked)", logs[0])
        self.assertIn("warn by ryk", logs[0])
        self.assertNotIn("Recourse", logs[0])
        self.assertNotIn("Next:", logs[0])

    def test_invalid_decision_fail_closed_meaningful_message(self) -> None:
        mapping = _PLUGIN._mapping
        out = mapping.map_pre_tool_call(
            {"decision": "future-decision", "message": "should not surface"},
            "terminal",
            {},
        )
        assert out is not None
        self.assertEqual(out["action"], "block")
        self.assertIn("fail-closed", out["message"].lower())
        self.assertTrue(out["message"].strip())

    def test_format_tool_message_redacts_secret_like_patterns(self) -> None:
        mapping = _PLUGIN._mapping
        message = mapping.format_tool_message(
            {
                "message": "token=super-secret-value blocked",
                "rule_id": "core.shell:env",
            },
            default="blocked by ryk",
        )
        self.assertNotIn("super-secret-value", message)
        self.assertIn("[REDACTED]", message)
        self.assertNotIn("\n", message)

    def test_format_tool_message_strips_inline_recourse_next(self) -> None:
        """Same-line operator tails must not re-inflate the host string."""
        mapping = _PLUGIN._mapping
        message = mapping.format_tool_message(
            {
                "message": (
                    "blocked by ryk policy. Recourse: run ryk allow-once <code> "
                    "Next: ryk explain \"rm -rf /\""
                ),
                "remediation_commands": ["ryk explain \"rm -rf /\""],
            },
            default="blocked by ryk",
        )
        self.assertEqual(message, "blocked by ryk policy.")
        self.assertNotIn("Recourse", message)
        self.assertNotIn("Next:", message)
        self.assertNotIn("allow-once", message)

    def test_pre_tool_call_allows_only_explicit_allow(self) -> None:
        ctx = mock.Mock()
        _PLUGIN._register(ctx, "pre_tool_call")
        handler = ctx.register_hook.call_args.args[1]
        with mock.patch.object(_PLUGIN, "_call_ryk", return_value={"decision": "allow"}):
            self.assertIsNone(handler(tool_name="terminal", args={"command": "git status"}))

        for malformed in (None, [], "error", "unexpected"):
            with self.subTest(decision=malformed):
                response = {} if malformed is None else {"decision": malformed}
                with mock.patch.object(_PLUGIN, "_call_ryk", return_value=response):
                    result = handler(tool_name="terminal", args={"command": "git status"})
                self.assertEqual(result.get("action"), "block")

    def test_pre_tool_call_stress_100_safe_100_risky_with_concurrency(self) -> None:
        ctx = mock.Mock()
        _PLUGIN._register(ctx, "pre_tool_call")
        handler = ctx.register_hook.call_args.args[1]

        def policy(_event: str, payload: dict[str, object]) -> dict[str, str]:
            tool_input = payload.get("tool_input")
            command = tool_input.get("command") if isinstance(tool_input, dict) else None
            return {"decision": "block" if command == "rm -rf /" else "allow"}

        requests = ["git status"] * 100 + ["rm -rf /"] * 100
        with mock.patch.object(_PLUGIN, "_call_ryk", side_effect=policy):
            with ThreadPoolExecutor(max_workers=16) as executor:
                results = list(
                    executor.map(
                        lambda command: handler(tool_name="terminal", args={"command": command}),
                        requests,
                    )
                )

        self.assertTrue(all(result is None for result in results[:100]))
        self.assertTrue(
            all(
                isinstance(result, dict) and result.get("action") == "block"
                for result in results[100:]
            )
        )

    def test_pre_tool_call_payload_failures_return_exact_block_directive(self) -> None:
        ctx = mock.Mock()
        _PLUGIN._register(ctx, "pre_tool_call")
        handler = ctx.register_hook.call_args.args[1]
        cyclic: list[object] = []
        cyclic.append(cyclic)
        deep: object = "leaf"
        for _ in range(80):
            deep = [deep]
        cases = (
            cyclic,
            {"value": object()},
            {"value": deep},
            {"value": "x" * (1024 * 1024)},
        )
        completed = subprocess.CompletedProcess(
            args=["ryk", "hook", "hermes", "pre_tool_call"],
            returncode=0,
            stdout='{"decision":"allow"}',
            stderr="",
        )
        with mock.patch.object(_PLUGIN, "_find_ryk", return_value="/tmp/ryk"), mock.patch.object(
            _PLUGIN, "_run_process_bounded", return_value=completed
        ) as run:
            for payload in cases:
                with self.subTest(payload_type=type(payload).__name__):
                    result = handler(tool_name="terminal", args=payload)
                    self.assertEqual(
                        result,
                        {
                            "action": "block",
                            "message": "ryk could not verify this Hermes tool call; blocked fail-closed.",
                        },
                    )
        run.assert_not_called()

    def test_pre_tool_call_subprocess_failures_return_exact_block_directive(self) -> None:
        ctx = mock.Mock()
        _PLUGIN._register(ctx, "pre_tool_call")
        handler = ctx.register_hook.call_args.args[1]
        failures = (
            subprocess.CompletedProcess(
                args=["ryk"], returncode=0, stdout="", stderr=""
            ),
            subprocess.CompletedProcess(
                args=["ryk"], returncode=0, stdout="not-json", stderr=""
            ),
            subprocess.CompletedProcess(
                args=["ryk"], returncode=9, stdout="", stderr="token=stderr-canary"
            ),
            subprocess.CompletedProcess(
                args=["ryk"], returncode=0, stdout="x" * (1024 * 1024), stderr=""
            ),
        )
        expected = {
            "action": "block",
            "message": "ryk could not verify this Hermes tool call; blocked fail-closed.",
        }
        with mock.patch.object(_PLUGIN, "_find_ryk", return_value="/tmp/ryk"):
            for completed in failures:
                with self.subTest(returncode=completed.returncode, stdout_len=len(completed.stdout)):
                    with mock.patch.object(_PLUGIN, "_run_process_bounded", return_value=completed):
                        output = io.StringIO()
                        with contextlib.redirect_stdout(output):
                            result = handler(tool_name="terminal", args={"command": "git status"})
                    self.assertEqual(result, expected)
                    self.assertNotIn("stderr-canary", json.dumps(result))
                    self.assertNotIn("stderr-canary", output.getvalue())

            with mock.patch.object(
                _PLUGIN,
                "_run_process_bounded",
                side_effect=subprocess.TimeoutExpired(["ryk"], timeout=15),
            ):
                self.assertEqual(
                    handler(tool_name="terminal", args={"command": "git status"}), expected
                )

    def test_subprocess_capture_is_bounded_while_child_is_running(self) -> None:
        with self.assertRaisesRegex(subprocess.SubprocessError, "output limit"):
            _PLUGIN._run_process_bounded(
                [sys.executable, "-c", "import sys; sys.stdout.write('x' * 1048576)"],
                input_text="",
                timeout=5,
                output_limit=4096,
            )

    @unittest.skipUnless(os.name == "posix", "process-group cleanup requires POSIX")
    def test_subprocess_timeout_kills_descendants(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "descendant-survived"
            command = f"(sleep 0.4; touch '{marker}') & sleep 10"
            started = time.monotonic()
            with self.assertRaises(subprocess.TimeoutExpired):
                _PLUGIN._run_process_bounded(
                    ["/bin/sh", "-c", command],
                    input_text="",
                    timeout=0.1,
                    output_limit=4096,
                )
            self.assertLess(time.monotonic() - started, 1.0)
            time.sleep(0.6)
            self.assertFalse(marker.exists(), "timed-out descendant was left running")

    @unittest.skipUnless(os.name == "posix", "process-group cleanup requires POSIX")
    def test_subprocess_pipe_drain_is_bounded_after_setsid_descendant(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "setsid-descendant.pid"
            child_code = (
                "import os, signal, time\n"
                "pid = os.fork()\n"
                "if pid == 0:\n"
                "    os.setsid()\n"
                f"    open({str(marker)!r}, 'w', encoding='utf-8').write(str(os.getpid()))\n"
                "    signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                "    time.sleep(30)\n"
                "else:\n"
                "    for _ in range(100):\n"
                f"        if os.path.exists({str(marker)!r}): break\n"
                "        time.sleep(0.01)\n"
            )
            command = shlex.join([sys.executable, "-c", child_code])
            started = time.monotonic()
            try:
                with self.assertRaises(subprocess.TimeoutExpired):
                    _PLUGIN._run_process_bounded(
                        ["/bin/sh", "-c", command],
                        input_text="",
                        timeout=5.0,
                        output_limit=4096,
                    )
                self.assertLess(time.monotonic() - started, 1.0)
            finally:
                if marker.exists():
                    descendant_pid = int(marker.read_text(encoding="utf-8"))
                    try:
                        os.kill(descendant_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_pre_tool_call_missing_binary_blocks_without_leaking_details(self) -> None:
        ctx = mock.Mock()
        _PLUGIN._register(ctx, "pre_tool_call")
        handler = ctx.register_hook.call_args.args[1]
        with mock.patch.dict(
            os.environ,
            {"RYK_HERMES_FAIL_OPEN": "1", "RYK_NONINTERACTIVE": "1"},
            clear=True,
        ), mock.patch.object(_PLUGIN, "_find_ryk", return_value=None):
            result = handler(tool_name="terminal", args={"command": "git status"})
        self.assertEqual(
            result,
            {
                "action": "block",
                "message": "ryk could not verify this Hermes tool call; blocked fail-closed.",
            },
        )

    def test_every_unattended_signal_dominates_conflicting_fail_open(self) -> None:
        ctx = mock.Mock()
        exc = RuntimeError("ryk binary not found or too old for Hermes hooks")
        for signal in (
            "CI",
            "RYK_CI",
            "RYK_NONINTERACTIVE",
            "RYK_UNATTENDED",
            "RYK_HERMES_UNATTENDED",
        ):
            with self.subTest(signal=signal), mock.patch.dict(
                os.environ,
                {"RYK_HERMES_FAIL_OPEN": "1", signal: "true"},
                clear=True,
            ):
                result = _PLUGIN._handle_hook_error(ctx, "pre_tool_call", exc)
                self.assertEqual(result.get("action"), "block")
                self.assertTrue(result.get("message"))

    def test_pre_tool_call_unknown_and_unattended_ask_are_nonempty_blocks(self) -> None:
        ctx = mock.Mock()
        _PLUGIN._register(ctx, "pre_tool_call")
        handler = ctx.register_hook.call_args.args[1]
        with mock.patch.object(
            _PLUGIN, "_call_ryk", return_value={"decision": "future-decision"}
        ):
            unknown = handler(tool_name="terminal", args={"command": "git status"})
        with mock.patch.dict(
            os.environ,
            {"RYK_HERMES_FAIL_OPEN": "1", "RYK_UNATTENDED": "1"},
            clear=True,
        ), mock.patch.object(
            _PLUGIN,
            "_call_ryk",
            return_value={"decision": "ask", "message": "approval required"},
        ):
            ask = handler(tool_name="terminal", args={"command": "git push"})
        for result in (unknown, ask):
            self.assertEqual(result.get("action"), "block")
            self.assertIsInstance(result.get("message"), str)
            self.assertTrue(result["message"].strip())

    def test_policy_output_and_logs_are_bounded_and_redacted(self) -> None:
        ctx = mock.Mock()
        _PLUGIN._register(ctx, "pre_tool_call")
        handler = ctx.register_hook.call_args.args[1]
        canary = "message-secret-canary"
        huge = "x" * (1024 * 1024)
        with mock.patch.object(
            _PLUGIN,
            "_call_ryk",
            return_value={
                "decision": "block",
                "message": f"token={canary} {huge}",
                "rule_id": huge,
                "remediation_commands": [f"authorization: Bearer {canary}", huge],
            },
        ):
            result = handler(tool_name="terminal", args={"command": "git status"})
        rendered = json.dumps(result)
        self.assertEqual(result.get("action"), "block")
        self.assertNotIn(canary, rendered)
        self.assertLessEqual(len(result.get("message", "")), 2048)

        with mock.patch.object(
            _PLUGIN,
            "_call_ryk",
            return_value={"decision": "warn", "message": f"password={canary} {huge}"},
        ):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertIsNone(handler(tool_name="terminal", args={"command": "git status"}))
        self.assertNotIn(canary, output.getvalue())
        self.assertLessEqual(len(output.getvalue()), 4096)

    def test_pre_llm_call_warn_is_advisory_context(self) -> None:
        ctx = mock.Mock()
        _PLUGIN._register(ctx, "pre_llm_call")
        handler = ctx.register_hook.call_args.args[1]
        with mock.patch.object(
            _PLUGIN,
            "_call_ryk",
            return_value={"decision": "warn", "message": "warn by ryk"},
        ):
            result = handler(session_id="session-1", user_message="review me")
        self.assertIsInstance(result, dict)
        assert result is not None
        self.assertIn("context", result)
        self.assertIn("warn by ryk", result["context"])
        self.assertIn("advisory", result["context"].lower())

    def test_pre_llm_call_ask_does_not_claim_enforcement(self) -> None:
        """Prompt-level ask cannot use Hermes native approve; notes must not pretend they enforce."""
        ctx = mock.Mock()
        _PLUGIN._register(ctx, "pre_llm_call")
        handler = ctx.register_hook.call_args.args[1]
        with mock.patch.object(
            _PLUGIN,
            "_call_ryk",
            return_value={"decision": "ask", "message": "ask by ryk"},
        ):
            result = handler(session_id="session-1", user_message="review me")
        self.assertIsInstance(result, dict)
        assert result is not None
        context = result.get("context", "")
        self.assertIn("ask by ryk", context)
        self.assertNotIn("requires user approval", context.lower())
        # Must be honest that this is not an approval gate.
        self.assertTrue(
            "does not enforce" in context.lower() or "cannot gate" in context.lower(),
            context,
        )
        self.assertIn("ryk run", context.lower())

    def test_pre_llm_call_block_is_honest_about_host_limit(self) -> None:
        ctx = mock.Mock()
        _PLUGIN._register(ctx, "pre_llm_call")
        handler = ctx.register_hook.call_args.args[1]
        with mock.patch.object(
            _PLUGIN,
            "_call_ryk",
            return_value={"decision": "block", "message": "block by ryk"},
        ):
            result = handler(session_id="session-1", user_message="review me")
        self.assertIsInstance(result, dict)
        assert result is not None
        context = result.get("context", "")
        self.assertIn("block by ryk", context)
        self.assertTrue(
            "does not enforce" in context.lower() or "cannot" in context.lower(),
            context,
        )


if __name__ == "__main__":
    unittest.main()

"""Unit tests for Hermes plugin ryk discovery and degraded-mode handling."""

from __future__ import annotations

import importlib.util
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_PLUGIN_PATH = Path(__file__).with_name("__init__.py")
_SPEC = importlib.util.spec_from_file_location("hermes_plugin", _PLUGIN_PATH)
assert _SPEC and _SPEC.loader
_PLUGIN = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _PLUGIN
_SPEC.loader.exec_module(_PLUGIN)


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

    def test_registered_pre_tool_call_fail_closes_without_mocked_policy_call(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with contextlib.chdir(directory), mock.patch.dict(
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
            with mock.patch.dict(
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
        with mock.patch.object(_PLUGIN.subprocess, "run", return_value=completed):
            self.assertFalse(_PLUGIN._has_ryk_identity("/tmp/binary"))

    def test_workspace_fallback_requires_explicit_opt_in(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "zig-out" / "bin" / "ryk"
            candidate.parent.mkdir(parents=True)
            candidate.write_text("#!/bin/sh\n", encoding="utf-8")
            candidate.chmod(0o700)
            with contextlib.chdir(directory), mock.patch.dict(
                os.environ, {"HOME": directory, "PATH": ""}, clear=True
            ):
                self.assertEqual(_PLUGIN._ryk_candidates(), [])

    def test_call_ryk_rejects_non_object_success_response(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["ryk", "hook", "hermes", "pre_tool_call"],
            returncode=0,
            stdout="[]\n",
            stderr="",
        )
        with mock.patch.object(_PLUGIN, "_find_ryk", return_value="/tmp/ryk"), mock.patch.object(
            _PLUGIN.subprocess, "run", return_value=completed
        ):
            with self.assertRaisesRegex(RuntimeError, "non-object response"):
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

    def test_pre_tool_call_surfaces_remediation_commands(self) -> None:
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
        self.assertIn("ryk explain", message)
        self.assertIn("rule: core.filesystem:destructive_rm", message)

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

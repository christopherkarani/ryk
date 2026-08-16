"""Sticky managed-provenance attest for the Hermes plugin.

Seam: `_attest_ryk_candidate` (and the `_ryk_executable` re-check used by
`_call_ryk`). First successful managed attest is full-file sha256 +
`version --json`. A later call with the same `(dev,ino,size,mtime)` skips
those two. Path / untrusted / mode / uid are re-checked every call.
Failures, `RYK_BIN` pins, and workspace-override candidates are never sticky.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Iterator
from unittest import mock


_PLUGIN_PATH = Path(__file__).with_name("__init__.py")
if "hermes_plugin" in sys.modules:
    _PLUGIN = sys.modules["hermes_plugin"]
else:
    _SPEC = importlib.util.spec_from_file_location("hermes_plugin", _PLUGIN_PATH)
    assert _SPEC and _SPEC.loader
    _PLUGIN = importlib.util.module_from_spec(_SPEC)
    sys.modules[_SPEC.name] = _PLUGIN
    _SPEC.loader.exec_module(_PLUGIN)


@contextlib.contextmanager
def _chdir(path: str | Path) -> Iterator[None]:
    previous = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


def _non_tmp_parent() -> Path:
    """Writable directory outside ryk tmp-plant roots (worktrees may live under /var/folders)."""
    tmp_roots: list[Path] = []
    for raw in (tempfile.gettempdir(), "/tmp", "/private/tmp"):
        try:
            tmp_roots.append(Path(raw).resolve())
        except OSError:
            continue

    def under_tmp(path: Path) -> bool:
        try:
            resolved = path.resolve()
        except OSError:
            return True
        for root in tmp_roots:
            try:
                resolved.relative_to(root)
                return True
            except ValueError:
                continue
        return False

    for candidate in (
        Path(__file__).resolve().parent,
        Path.home() / ".cache" / "ryk-hermes-plugin-tests",
        Path("/var/tmp") / "ryk-hermes-plugin-tests",
    ):
        if under_tmp(candidate):
            continue
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            probe = candidate / ".write-probe"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink()
            return candidate
        except OSError:
            continue
    raise RuntimeError("no writable non-tmp directory for source-build attest tests")


@contextlib.contextmanager
def _non_tmp_dir() -> Iterator[Path]:
    with tempfile.TemporaryDirectory(prefix="ryk-attest-", dir=_non_tmp_parent()) as directory:
        yield Path(directory)


@contextlib.contextmanager
def _count_binary_reads(target: Path) -> Iterator[dict[str, int]]:
    """Count `Path.read_bytes` of the attested binary (the sha256 input)."""
    expected = target.resolve()
    original = Path.read_bytes
    counts = {"n": 0}

    def wrapped(self: Path) -> bytes:
        try:
            if self.resolve() == expected:
                counts["n"] += 1
        except OSError:
            pass
        return original(self)

    Path.read_bytes = wrapped  # type: ignore[method-assign]
    try:
        yield counts
    finally:
        Path.read_bytes = original  # type: ignore[method-assign]


def _write_identity_ryk(path: Path, log: Path | None = None, mode: int = 0o700) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if log is None:
        body = (
            "#!/bin/sh\n"
            "if [ \"$1\" = version ]; then "
            "printf '%s\\n' '{\"product\":\"ryk\",\"version\":\"0.2.18\"}'; exit 0; fi\n"
            "printf '%s\\n' '{\"decision\":\"allow\"}'\n"
        )
    else:
        body = (
            "#!/bin/sh\n"
            f'printf "%s\\n" "$*" >> "{log}"\n'
            "if [ \"$1\" = version ]; then "
            "printf '%s\\n' '{\"product\":\"ryk\",\"version\":\"0.2.18\"}'; exit 0; fi\n"
            "printf '%s\\n' '{\"decision\":\"allow\"}'\n"
        )
    path.write_text(body, encoding="utf-8")
    path.chmod(mode)
    return path


def _write_provenance(binary: Path) -> Path:
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    receipt = binary.parent / ".ryk-provenance"
    receipt.write_text(
        "ryk-provenance-v1\n"
        f"path={binary.resolve()}\n"
        f"sha256={digest}\n",
        encoding="utf-8",
    )
    return receipt


def _version_invocations(log: Path) -> int:
    if not log.is_file():
        return 0
    return sum(1 for line in log.read_text(encoding="utf-8").splitlines() if line.startswith("version"))


class HermesPluginAttestTests(unittest.TestCase):
    def setUp(self) -> None:
        _PLUGIN._ryk_cache_env = None
        _PLUGIN._ryk_cache_path = None
        _PLUGIN._clear_sticky_attest()

    def tearDown(self) -> None:
        _PLUGIN._ryk_cache_env = None
        _PLUGIN._ryk_cache_path = None
        _PLUGIN._clear_sticky_attest()

    def test_first_managed_attest_hashes_and_runs_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            log = home / "invocations.log"
            binary = _write_identity_ryk(home / ".local" / "bin" / "ryk", log)
            _write_provenance(binary)
            cwd = home / "project"
            cwd.mkdir()
            with _chdir(cwd), mock.patch.dict(
                os.environ,
                {"HOME": str(home), "PATH": "", "RYK_ALLOW_WORKSPACE_BIN": "0"},
                clear=False,
            ):
                os.environ.pop("RYK_BIN", None)
                os.environ.pop("RYK_ALLOW_WORKSPACE_BIN", None)
                with _count_binary_reads(binary) as reads:
                    self.assertTrue(_PLUGIN._attest_ryk_candidate(str(binary)))
            self.assertGreater(reads["n"], 0)
            self.assertGreater(_version_invocations(log), 0)

    def test_second_managed_attest_same_tuple_skips_hash_and_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            log = home / "invocations.log"
            binary = _write_identity_ryk(home / ".local" / "bin" / "ryk", log)
            _write_provenance(binary)
            cwd = home / "project"
            cwd.mkdir()
            with _chdir(cwd), mock.patch.dict(
                os.environ,
                {"HOME": str(home), "PATH": ""},
                clear=False,
            ):
                os.environ.pop("RYK_BIN", None)
                os.environ.pop("RYK_ALLOW_WORKSPACE_BIN", None)
                with _count_binary_reads(binary) as reads:
                    self.assertTrue(_PLUGIN._attest_ryk_candidate(str(binary)))
                    first_reads = reads["n"]
                    first_versions = _version_invocations(log)
                    self.assertGreater(first_reads, 0)
                    self.assertGreater(first_versions, 0)
                    self.assertTrue(_PLUGIN._attest_ryk_candidate(str(binary)))
                    self.assertEqual(reads["n"], first_reads)
                    self.assertEqual(_version_invocations(log), first_versions)

    def test_size_or_mtime_change_forces_full_re_attest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            log = home / "invocations.log"
            binary = _write_identity_ryk(home / ".ryk" / "bin" / "ryk", log)
            _write_provenance(binary)
            cwd = home / "project"
            cwd.mkdir()
            with _chdir(cwd), mock.patch.dict(
                os.environ,
                {"HOME": str(home), "PATH": ""},
                clear=False,
            ):
                os.environ.pop("RYK_BIN", None)
                os.environ.pop("RYK_ALLOW_WORKSPACE_BIN", None)
                self.assertTrue(_PLUGIN._attest_ryk_candidate(str(binary)))
                after_first_versions = _version_invocations(log)
                self.assertGreater(after_first_versions, 0)

                binary.write_bytes(binary.read_bytes() + b"#resized\n")
                binary.chmod(0o700)
                _write_provenance(binary)
                with _count_binary_reads(binary) as reads:
                    self.assertTrue(_PLUGIN._attest_ryk_candidate(str(binary)))
                    self.assertGreater(reads["n"], 0)
                after_size_versions = _version_invocations(log)
                self.assertGreater(after_size_versions, after_first_versions)

                later = time.time() + 5
                os.utime(binary, (later, later))
                with _count_binary_reads(binary) as reads:
                    self.assertTrue(_PLUGIN._attest_ryk_candidate(str(binary)))
                    self.assertGreater(reads["n"], 0)
                self.assertGreater(_version_invocations(log), after_size_versions)

    def test_failed_attest_is_not_sticky(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            log = home / "invocations.log"
            binary = _write_identity_ryk(home / ".local" / "bin" / "ryk", log)
            _write_provenance(binary)
            cwd = home / "project"
            cwd.mkdir()
            outcomes = iter([False, True])
            with _chdir(cwd), mock.patch.dict(
                os.environ,
                {"HOME": str(home), "PATH": ""},
                clear=False,
            ):
                os.environ.pop("RYK_BIN", None)
                os.environ.pop("RYK_ALLOW_WORKSPACE_BIN", None)
                with mock.patch.object(
                    _PLUGIN,
                    "_has_ryk_identity",
                    side_effect=lambda _path: next(outcomes),
                ):
                    with _count_binary_reads(binary) as reads:
                        self.assertFalse(_PLUGIN._attest_ryk_candidate(str(binary)))
                        after_fail = reads["n"]
                        self.assertGreater(after_fail, 0)
                        self.assertTrue(_PLUGIN._attest_ryk_candidate(str(binary)))
                        self.assertGreater(reads["n"], after_fail)

    def test_workspace_override_always_full_probes_version(self) -> None:
        with _non_tmp_dir() as source:
            log = source / "invocations.log"
            binary = _write_identity_ryk(source / "zig-out" / "bin" / "ryk", log)
            with _chdir(source), mock.patch.dict(
                os.environ,
                {"HOME": str(source), "PATH": "", "RYK_ALLOW_WORKSPACE_BIN": "1"},
                clear=False,
            ):
                os.environ.pop("RYK_BIN", None)
                self.assertTrue(_PLUGIN._attest_ryk_candidate(str(binary)))
                first_versions = _version_invocations(log)
                self.assertGreater(first_versions, 0)
                self.assertTrue(_PLUGIN._attest_ryk_candidate(str(binary)))
                self.assertGreater(_version_invocations(log), first_versions)

    def test_ryk_bin_pin_always_full_probes_version(self) -> None:
        with _non_tmp_dir() as home, tempfile.TemporaryDirectory() as qa_cwd:
            log = home / "invocations.log"
            binary = _write_identity_ryk(home / ".local" / "bin" / "ryk", log)
            # Pin: no receipt required, and must not become sticky.
            self.assertFalse((binary.parent / ".ryk-provenance").exists())
            with _chdir(qa_cwd), mock.patch.dict(
                os.environ,
                {"HOME": str(home), "PATH": "", "RYK_BIN": str(binary)},
                clear=False,
            ):
                os.environ.pop("RYK_ALLOW_WORKSPACE_BIN", None)
                self.assertTrue(_PLUGIN._attest_ryk_candidate(str(binary)))
                first_versions = _version_invocations(log)
                self.assertGreater(first_versions, 0)
                self.assertTrue(_PLUGIN._attest_ryk_candidate(str(binary)))
                self.assertGreater(_version_invocations(log), first_versions)

    def test_mode_and_uid_are_rechecked_after_sticky_success(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            log = home / "invocations.log"
            binary = _write_identity_ryk(home / ".local" / "bin" / "ryk", log)
            _write_provenance(binary)
            cwd = home / "project"
            cwd.mkdir()
            with _chdir(cwd), mock.patch.dict(
                os.environ,
                {"HOME": str(home), "PATH": ""},
                clear=False,
            ):
                os.environ.pop("RYK_BIN", None)
                os.environ.pop("RYK_ALLOW_WORKSPACE_BIN", None)
                self.assertTrue(_PLUGIN._attest_ryk_candidate(str(binary)))
                versions_after_success = _version_invocations(log)

                binary.chmod(0o777)
                self.assertFalse(_PLUGIN._attest_ryk_candidate(str(binary)))
                binary.chmod(0o700)
                with mock.patch.object(_PLUGIN.os, "getuid", return_value=os.getuid() + 1):
                    self.assertFalse(_PLUGIN._attest_ryk_candidate(str(binary)))
                missing = home / ".local" / "bin" / "missing-ryk"
                self.assertFalse(_PLUGIN._attest_ryk_candidate(str(missing)))
                # Failed re-checks must not spawn version --json.
                self.assertEqual(_version_invocations(log), versions_after_success)

    def test_find_ryk_then_re_executable_skips_hash(self) -> None:
        """Product re-attest path (`_call_ryk` → `_ryk_executable`) skips hash."""
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            log = home / "invocations.log"
            binary = _write_identity_ryk(home / ".local" / "bin" / "ryk", log)
            _write_provenance(binary)
            cwd = home / "project"
            cwd.mkdir()
            with _chdir(cwd), mock.patch.dict(
                os.environ,
                {"HOME": str(home), "PATH": ""},
                clear=False,
            ):
                os.environ.pop("RYK_BIN", None)
                os.environ.pop("RYK_ALLOW_WORKSPACE_BIN", None)
                found = _PLUGIN._find_ryk()
                self.assertEqual(found, str(binary.resolve()))
                with _count_binary_reads(binary) as reads:
                    self.assertEqual(_PLUGIN._ryk_executable(found), found)
                    self.assertEqual(reads["n"], 0)
                # Identity probe is also sticky after managed discovery.
                versions_after_find = _version_invocations(log)
                self.assertTrue(_PLUGIN._has_ryk_identity(found))
                self.assertEqual(_version_invocations(log), versions_after_find)


if __name__ == "__main__":
    unittest.main()

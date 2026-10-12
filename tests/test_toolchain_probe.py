#!/usr/bin/env python3
"""tests/test_toolchain_probe.py — contract suite for the candidate-nightly
probe and promotion report (FSS-184, bead fss-x4a.26.4).

rustup is consulted through a stub on PATH in a tempdir so the states are
proven deterministically: current, candidate-available (with the
never-auto-promotes guarantee), unavailable, and pin-file errors.
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

import toolchain_probe  # noqa: E402

PIN = 'channel = "nightly-2026-08-31"\nprofile = "minimal"\n'


def _pin_root(td: Path, pin: str = PIN) -> Path:
    (td / "rust-toolchain.toml").write_text(pin, encoding="utf-8")
    return td


class _Proc:
    def __init__(self, returncode: int, stdout: str):
        self.returncode = returncode
        self.stdout = stdout


class TestStates(unittest.TestCase):
    def test_current_when_no_newer_nightly_installed(self):
        with tempfile.TemporaryDirectory() as t:
            root = _pin_root(Path(t))
            with mock.patch(
                "subprocess.run",
                return_value=_Proc(0, "nightly-2026-08-31\nstable-aarch64-apple-darwin\n"),
            ):
                report = toolchain_probe.probe(root)
        self.assertEqual(report["state"], "current")
        self.assertEqual(report["acceptedPin"], "nightly-2026-08-31")

    def test_candidate_available_names_candidate_and_gate(self):
        with tempfile.TemporaryDirectory() as t:
            root = _pin_root(Path(t))
            with mock.patch(
                "subprocess.run",
                return_value=_Proc(0, "nightly-2026-08-31\nnightly-2026-10-05\n"),
            ):
                report = toolchain_probe.probe(root)
        self.assertEqual(report["state"], "candidate-available")
        self.assertEqual(report["candidate"], "nightly-2026-10-05")
        self.assertIn("NOT promoted", report["evidence"])
        self.assertIn("full qualification", report["evidence"])

    def test_rustup_unavailable_is_unproven_not_current(self):
        with tempfile.TemporaryDirectory() as t:
            root = _pin_root(Path(t))
            with mock.patch("subprocess.run", side_effect=OSError("no rustup")):
                report = toolchain_probe.probe(root)
        self.assertEqual(report["state"], "unavailable")
        self.assertIn("unproven", report["evidence"])

    def test_missing_pin_is_error(self):
        with tempfile.TemporaryDirectory() as t:
            report = toolchain_probe.probe(Path(t))
        self.assertEqual(report["state"], "error")

    def test_stable_only_installations_are_current(self):
        with tempfile.TemporaryDirectory() as t:
            root = _pin_root(Path(t))
            with mock.patch(
                "subprocess.run",
                return_value=_Proc(0, "stable-aarch64-apple-darwin\n1.85.0-aarch64-apple-darwin\n"),
            ):
                report = toolchain_probe.probe(root)
        self.assertEqual(report["state"], "current")


class TestCli(unittest.TestCase):
    def test_cli_emits_schema_and_stable_exit(self):
        with tempfile.TemporaryDirectory() as t:
            root = _pin_root(Path(t))
            proc = subprocess.run(
                [sys.executable, str(REPO / "scripts" / "toolchain_probe.py"), "--root", str(root)],
                capture_output=True,
                text=True,
                timeout=30,
            )
        self.assertIn(proc.returncode, (0, 1, 2, 3))
        report = json.loads(proc.stdout)
        self.assertEqual(report["schema"], "fss.toolchain_promotion.v1")
        self.assertIn(report["state"], ("current", "candidate-available", "unavailable", "error"))


if __name__ == "__main__":
    unittest.main()

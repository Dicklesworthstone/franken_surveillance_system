#!/usr/bin/env python3
"""tests/test_capacity_check.py — contract suite for the qualification host
capacity/quarantine preflight (FSS-186, bead fss-x4a.26.6).

The typed state machine is pinned: sufficient / insufficient / unavailable /
error, with stable exit codes (0/1/2/3), one JSON object of evidence, and no
silent upgrade of an unproven capacity claim.
"""

import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

import capacity_check  # noqa: E402


def _run_cli(args: list[str]) -> tuple[int, dict]:
    proc = subprocess.run(
        [sys.executable, str(REPO / "scripts" / "capacity_check.py"), *args],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return proc.returncode, json.loads(proc.stdout)


class _Completed:
    def __init__(self, returncode: int, stdout: str):
        self.returncode = returncode
        self.stdout = stdout


class TestTypedStates(unittest.TestCase):
    def test_sufficient(self):
        report = {"container_available_bytes": 40 * 1024**3}
        with mock.patch("shutil.which", return_value="/usr/local/bin/sb h".replace(" ", "")), mock.patch(
            "subprocess.run",
            return_value=_Completed(0, json.dumps(report)),
        ):
            result = capacity_check.probe_sbh(10 * 1024**3)
        self.assertEqual(result["state"], "sufficient")
        self.assertEqual(result["availableBytes"], 40 * 1024**3)

    def test_insufficient(self):
        report = {"container_available_bytes": 1024**3}
        with mock.patch("shutil.which", return_value="/bin/sbh"), mock.patch(
            "subprocess.run", return_value=_Completed(1, json.dumps(report))
        ):
            result = capacity_check.probe_sbh(20 * 1024**3)
        self.assertEqual(result["state"], "insufficient")
        self.assertIn("reclaim", result["evidence"])

    def test_missing_sbh_is_unavailable_not_silent(self):
        with mock.patch("shutil.which", return_value=None):
            result = capacity_check.probe_sbh(1024)
        self.assertEqual(result["state"], "unavailable")
        self.assertIn("unproven", result["evidence"])

    def test_probe_failure_is_error(self):
        with mock.patch("shutil.which", return_value="/bin/sbh"), mock.patch(
            "subprocess.run", side_effect=subprocess.TimeoutExpired("sbh", 30)
        ):
            result = capacity_check.probe_sbh(1024)
        self.assertEqual(result["state"], "error")


class TestCliContract(unittest.TestCase):
    def test_cli_emits_one_json_object_with_stable_exit(self):
        rc, payload = _run_cli(["1073741824"])
        self.assertIn(rc, (0, 1, 2, 3))
        self.assertEqual(payload["schema"], "fss.capacity_check.v1")
        self.assertEqual(payload["needBytes"], 1073741824)
        self.assertIn(payload["state"], ("sufficient", "insufficient", "unavailable", "error"))

    def test_cli_default_need(self):
        rc, payload = _run_cli([])
        self.assertIn(rc, (0, 1, 2, 3))
        self.assertEqual(payload["needBytes"], 10 * 1024**3)


class TestQualifyWiring(unittest.TestCase):
    """The lane must actually run the preflight (not merely exist)."""

    def test_qualify_sh_runs_capacity_preflight(self):
        qualify = (REPO / "scripts" / "qualify.sh").read_text(encoding="utf-8")
        self.assertIn("capacity_check.py", qualify, "qualify.sh must run the capacity preflight")
        self.assertIn("capacity-preflight", qualify, "the step must be a named lane record")


if __name__ == "__main__":
    unittest.main()

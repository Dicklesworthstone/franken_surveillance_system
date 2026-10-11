#!/usr/bin/env python3
"""tests/test_netseal_selftest.py — fault-matrix contract for the qualification
network seal self-test (FSS-183, bead fss-x4a.26.3).

The seal self-test is the proof that qualification lanes run network-sealed
rather than merely claiming it. These tests drive both seal modes against both
probe outcomes by patching the socket layer, plus the qualify.sh wiring facts:
the seal mode is exported, and Cargo runs offline with the env seal in force.
"""

import io
import os
import sys
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

import netseal_selftest  # noqa: E402


class _FakeSock:
    def close(self) -> None:  # pragma: no cover - trivial
        pass


def _run(mode: str, connect_succeeds: bool) -> tuple[int, str, str]:
    env = {"QUALIFY_SEAL_MODE": mode}
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.dict(os.environ, env, clear=False):
        if connect_succeeds:
            patcher = mock.patch("socket.create_connection", return_value=_FakeSock())
        else:
            patcher = mock.patch(
                "socket.create_connection",
                side_effect=OSError("no route to host"),
            )
        with patcher, redirect_stdout(out), redirect_stderr(err):
            rc = netseal_selftest.main()
    return rc, out.getvalue(), err.getvalue()


class TestSealSemantics(unittest.TestCase):
    def test_namespace_mode_with_refused_probe_passes(self):
        rc, out, _ = _run("namespace", connect_succeeds=False)
        self.assertEqual(rc, 0)
        self.assertIn("namespace-sealed", out)

    def test_namespace_mode_with_successful_probe_fails_closed(self):
        rc, _out, err = _run("namespace", connect_succeeds=True)
        self.assertEqual(rc, 1)
        self.assertIn("seal is broken", err)

    def test_unavailable_mode_with_refused_probe_passes_degraded(self):
        rc, out, _ = _run("unavailable", connect_succeeds=False)
        self.assertEqual(rc, 0)
        self.assertIn("degraded", out)

    def test_unavailable_mode_with_successful_probe_fails(self):
        # Env-only seal on a host that CAN reach the network must not be
        # presented as a proven seal.
        rc, _out, err = _run("unavailable", connect_succeeds=True)
        self.assertEqual(rc, 1)
        self.assertIn("network-capable", err)

    def test_missing_mode_defaults_to_unavailable(self):
        rc, out, _ = _run("", connect_succeeds=False)
        # Empty env value behaves as unset (default unavailable).
        self.assertEqual(rc, 0)
        self.assertIn("degraded", out)


class TestQualifyWiring(unittest.TestCase):
    """The lane actually applies the seal: mode export + Cargo offline."""

    def test_qualify_sh_exports_seal_mode_and_offline_cargo(self):
        qualify = (REPO / "scripts" / "qualify.sh").read_text(encoding="utf-8")
        self.assertIn('export QUALIFY_SEAL_MODE="$SEAL_MODE"', qualify)
        self.assertIn("export CARGO_NET_OFFLINE=true", qualify)
        self.assertIn("--offline", qualify, "cargo invocations must pass --offline")

    def test_selftest_runs_inside_every_lane(self):
        qualify = (REPO / "scripts" / "qualify.sh").read_text(encoding="utf-8")
        self.assertIn('run netseal python3 "$ROOT/scripts/netseal_selftest.py"', qualify)


if __name__ == "__main__":
    unittest.main()

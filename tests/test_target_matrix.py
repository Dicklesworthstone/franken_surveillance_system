#!/usr/bin/env python3
"""tests/test_target_matrix.py — contract suite for interrupted target-matrix
resume without partial blessing (FSS-188, bead fss-x4a.26.8).

The no-partial-blessing contract is pinned from every angle: interrupted
matrices never complete, resume returns exactly the missing targets,
completed-then-extended matrices honestly reopen, digest conflicts refuse,
and corrupt state files fail closed.
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "target_matrix.py"

TARGETS = ["aarch64-apple-darwin", "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"]


def _run(*args: str) -> tuple[int, dict]:
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return proc.returncode, json.loads(proc.stdout)


class TestNoPartialBlessing(unittest.TestCase):
    def _init(self, td: Path) -> Path:
        state = td / "matrix.json"
        _run("init", "--state", str(state), "--targets", *TARGETS)
        return state

    def test_full_matrix_completes(self):
        with tempfile.TemporaryDirectory() as t:
            state = self._init(Path(t))
            for i, target in enumerate(TARGETS):
                rc, out = _run("record", "--state", str(state), "--target", target, "--digest", f"sha256:{i}")
                self.assertEqual(rc, 0)
            rc, out = _run("complete", "--state", str(state))
            self.assertEqual(rc, 0)
            self.assertTrue(out["complete"])

    def test_interrupted_matrix_never_blesses(self):
        with tempfile.TemporaryDirectory() as t:
            state = self._init(Path(t))
            _run("record", "--state", str(state), "--target", TARGETS[0], "--digest", "sha256:a")
            rc, out = _run("complete", "--state", str(state))
            self.assertEqual(rc, 0)
            self.assertFalse(out["complete"])
            self.assertEqual(out["missing"], sorted(TARGETS[1:]))

    def test_resume_returns_exactly_the_missing_targets(self):
        with tempfile.TemporaryDirectory() as t:
            state = self._init(Path(t))
            _run("record", "--state", str(state), "--target", TARGETS[0], "--digest", "sha256:a")
            _run("record", "--state", str(state), "--target", TARGETS[2], "--digest", "sha256:c")
            rc, out = _run("resume", "--state", str(state))
            self.assertEqual(rc, 0)
            self.assertEqual(out["pending"], [TARGETS[1]])
            # Resume the missing one; the matrix now completes.
            _run("record", "--state", str(state), "--target", TARGETS[1], "--digest", "sha256:b")
            rc, out = _run("complete", "--state", str(state))
            self.assertTrue(out["complete"])

    def test_extended_matrix_honestly_reopens(self):
        with tempfile.TemporaryDirectory() as t:
            state = self._init(Path(t))
            for i, target in enumerate(TARGETS):
                _run("record", "--state", str(state), "--target", target, "--digest", f"sha256:{i}")
            rc, out = _run("complete", "--state", str(state))
            self.assertTrue(out["complete"])
            # A crash-consistent re-init with an extra target must not bless.
            _run("init", "--state", str(state), "--targets", *TARGETS, "riscv64gc-unknown-linux-gnu")
            rc, out = _run("complete", "--state", str(state))
            self.assertFalse(out["complete"])

    def test_digest_conflict_refuses(self):
        with tempfile.TemporaryDirectory() as t:
            state = self._init(Path(t))
            _run("record", "--state", str(state), "--target", TARGETS[0], "--digest", "sha256:first")
            rc, out = _run("record", "--state", str(state), "--target", TARGETS[0], "--digest", "sha256:other")
            self.assertEqual(rc, 1)
            self.assertEqual(out["state"], "digest-conflict")
            # Idempotent same-digest record is fine.
            rc, out = _run("record", "--state", str(state), "--target", TARGETS[0], "--digest", "sha256:first")
            self.assertEqual(rc, 0)

    def test_undeclared_target_refused(self):
        with tempfile.TemporaryDirectory() as t:
            state = self._init(Path(t))
            rc, out = _run("record", "--state", str(state), "--target", "mips-unknown-none", "--digest", "sha256:x")
            self.assertEqual(rc, 1)
            self.assertEqual(out["state"], "undeclared-target")

    def test_corrupt_state_fails_closed(self):
        with tempfile.TemporaryDirectory() as t:
            state = self._init(Path(t))
            state.write_text("{ not json", encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, str(SCRIPT), "complete", "--state", str(state)],
                capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 2)

    def test_missing_state_fails_closed(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "complete", "--state", "/nonexistent/matrix.json"],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 2)


if __name__ == "__main__":
    unittest.main()

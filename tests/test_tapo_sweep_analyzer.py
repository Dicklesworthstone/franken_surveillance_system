#!/usr/bin/env python3
"""Tests for deliverables/scripts/tapo_sweep_analyzer.py.

The analyzer turns a sweep log into a buffer prediction, so the tests pin the oracle's arithmetic
and — more importantly — the cases where the log does *not* support a prediction. A confident
answer from an unbounded run is the failure mode that costs a 17 h walk.
"""
from __future__ import annotations

import importlib.util
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "tapo_sweep_analyzer", ROOT / "deliverables" / "scripts" / "tapo_sweep_analyzer.py")
assert SPEC is not None and SPEC.loader is not None
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)

HANG = '{"raw": ""} no shell; DECODE-BUFFER zone likely (stop here, do not retry)'
CRASH = '{"raw": ""} connection dropped; crash'
SHELL = '{"raw": "uid=0"} SHELL on 192.168.4.33:4444'


def line(addr: int, verdict: str, dur: float = 8.03) -> str:
    return f"19:00:00 addr=0x{addr:x} :: {dur:.2f}s {verdict}\n"


def write(steps: list[tuple[int, str]]) -> str:
    fh = tempfile.NamedTemporaryFile("w", suffix=".log", delete=False)
    for addr, v in steps:
        fh.write(line(addr, v))
    fh.close()
    return fh.name


class ClassifyTest(unittest.TestCase):
    def test_kinds(self) -> None:
        self.assertEqual(MOD.classify(HANG), "HANG")
        self.assertEqual(MOD.classify(CRASH), "CRASH")
        self.assertEqual(MOD.classify(SHELL), "SHELL")
        self.assertEqual(MOD.classify("something else"), "UNKNOWN")

    def test_no_shell_is_not_a_shell(self) -> None:
        self.assertNotEqual(MOD.classify(HANG), "SHELL")


class AnalyseTest(unittest.TestCase):
    def test_bounded_run_predicts_one_frame_below_the_top(self) -> None:
        top = 0xB6FF8000
        steps = [(top + 0x800, CRASH)]
        steps += [(top - i * 0x400, HANG) for i in range(6)]
        steps += [(top - 6 * 0x400, CRASH)]
        res = MOD.analyse(MOD.parse(write(steps)))
        self.assertEqual(res["verdict"], "predicted")
        self.assertEqual(res["top_edge"], top)
        self.assertEqual(res["edges_bounded"], 2)
        self.assertEqual(res["confidence"], "high")
        self.assertEqual(res["addr"], top - MOD.FRAME_DEPTH)
        self.assertLess(res["next_step"], res["step"])

    def test_one_edge_is_medium(self) -> None:
        top = 0xB6FF8000
        steps = [(top + 0x400, CRASH)] + [(top - i * 0x400, HANG) for i in range(4)]
        res = MOD.analyse(MOD.parse(write(steps)))
        self.assertEqual(res["edges_bounded"], 1)
        self.assertEqual(res["confidence"], "medium")

    def test_all_hang_is_low_and_says_walk_up(self) -> None:
        steps = [(0xB7000000 - i * 0x400, HANG) for i in range(16)]
        res = MOD.analyse(MOD.parse(write(steps)))
        self.assertEqual(res["verdict"], "predicted")
        self.assertEqual(res["confidence"], "low")
        self.assertEqual(res["edges_bounded"], 0)
        self.assertIn("walk UP", res["note"])

    def test_prediction_lands_inside_the_run(self) -> None:
        top, bottom = 0xB6FF8000, 0xB6FF7000
        steps = [(top, HANG), (bottom, HANG), (top + 0x400, CRASH), (bottom - 0x400, CRASH)]
        res = MOD.analyse(MOD.parse(write(steps)))
        self.assertLessEqual(res["addr"], top)
        self.assertGreaterEqual(res["addr"], bottom)

    def test_shell_wins(self) -> None:
        steps = [(0xB6FF8000, HANG), (0xB6FF7C00, SHELL)]
        res = MOD.analyse(MOD.parse(write(steps)))
        self.assertEqual(res["verdict"], "shell")
        self.assertEqual(res["addr"], 0xB6FF7C00)

    def test_no_hang_is_reported_not_guessed(self) -> None:
        steps = [(0xB7000000 - i * 0x400, CRASH) for i in range(5)]
        res = MOD.analyse(MOD.parse(write(steps)))
        self.assertEqual(res["verdict"], "no-hang")
        self.assertIn("wrong region", res["note"])

    def test_empty(self) -> None:
        self.assertEqual(MOD.analyse([])["verdict"], "no-steps")


class CliTest(unittest.TestCase):
    def test_exit_codes(self) -> None:
        good = write([(0xB6FF8000, HANG), (0xB6FF8400, CRASH)])
        import subprocess
        import sys
        script = ROOT / "deliverables" / "scripts" / "tapo_sweep_analyzer.py"
        self.assertEqual(subprocess.run([sys.executable, str(script), good],
                                        capture_output=True).returncode, 0)
        empty = write([(0xB6FF8000, CRASH)])
        self.assertEqual(subprocess.run([sys.executable, str(script), empty],
                                        capture_output=True).returncode, 1)
        blank = tempfile.NamedTemporaryFile("w", suffix=".log", delete=False)
        blank.write("nothing here\n")
        blank.close()
        self.assertEqual(subprocess.run([sys.executable, str(script), blank.name],
                                        capture_output=True).returncode, 2)

    def test_json_shape(self) -> None:
        import json
        import subprocess
        import sys
        log = write([(0xB6FF8000, HANG), (0xB6FF8400, CRASH)])
        out = subprocess.run([sys.executable, str(ROOT / "deliverables" / "scripts" /
                                                  "tapo_sweep_analyzer.py"), "--json", log],
                             capture_output=True, text=True)
        doc = json.loads(out.stdout)
        self.assertEqual(doc["verdict"], "predicted")
        self.assertEqual(doc["offset"], 1060)
        self.assertEqual(doc["mmap_base"], hex(MOD.MMAP_BASE))


if __name__ == "__main__":
    unittest.main(verbosity=2)

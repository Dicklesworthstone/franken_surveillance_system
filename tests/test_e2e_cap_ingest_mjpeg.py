#!/usr/bin/env python3
"""Tests for scripts/e2e/cap_ingest_mjpeg.sh with stubbed rch."""
from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/e2e/cap_ingest_mjpeg.sh"
# Every scratch path this suite creates lives under the repo's (git-ignored) target/ dir, never
# under the ambient TMPDIR or /tmp.
SCRATCH_BASE = ROOT / "target" / "test-e2e-cap-ingest-mjpeg"


def cap(payload: dict) -> str:
    """One shell-quoted CAPLOG JSON payload (compact, no single quotes inside)."""
    return "'" + json.dumps(payload, separators=(",", ":")) + "'"


class TestE2eCapIngestMjpeg(unittest.TestCase):
    def setUp(self) -> None:
        SCRATCH_BASE.mkdir(parents=True, exist_ok=True)
        self.tmp_dir = tempfile.TemporaryDirectory(dir=SCRATCH_BASE, prefix="run-")
        self.tmp_path = Path(self.tmp_dir.name)
        self.bin_dir = self.tmp_path / "bin"
        self.bin_dir.mkdir()
        self.log_dir = self.tmp_path / "logs"
        self.log_dir.mkdir()
        # TMPDIR handed to the harness: a sentinel that must stay empty.
        self.tmpdir_env = self.tmp_path / "tmpdir"
        self.tmpdir_env.mkdir()
        self.calls_file = self.tmp_path / "stub_calls.txt"
        self.fd_file = self.tmp_path / "stub_stdout_path.txt"

        stub_rch = self.bin_dir / "rch"
        cap_a = cap({"step": "a", "verdict": "pass", "exit": 0, "duration_ms": 1, "expected": {}, "observed": {}})
        cap_b = cap({"step": "b", "verdict": "pass", "exit": 0, "duration_ms": 2, "expected": {}, "observed": {}})
        cap_skip = cap({"step": "b", "verdict": "skip", "exit": 0, "duration_ms": 1, "expected": {"m": 1}, "observed": {"r": "skip"}})
        cap_skip_c = cap({"step": "c", "verdict": "skip", "exit": 0, "duration_ms": 1, "expected": {"m": 1}, "observed": {"r": "skip"}})
        cap_fail = cap({"step": "a", "verdict": "fail"})
        cap_bad = "'" + '{"step":"a", broken json' + "'"
        cap_noverdict = cap({"step": "a"})
        cap_nostep = cap({"verdict": "pass"})
        stub_content = f"""#!/usr/bin/env bash
echo \"$@\" >> \"{self.calls_file}\"
echo \"$(readlink /proc/$$/fd/1)\" >> \"{self.fd_file}\"
case \"${{STUB_MODE:-pass}}\" in
  pass)
    printf \"\\033[32mrunning 2 tests\\033[0m\\n\"
    echo CAPLOG {cap_a}
    echo CAPLOG {cap_b}
    printf \"test result: ok. 2 passed\\n\"
    exit 0
    ;;
  pass_with_skip)
    printf \"\\033[32mrunning 2 tests\\033[0m\\n\"
    echo CAPLOG {cap_a}
    echo CAPLOG {cap_skip}
    printf \"test result: ok. 2 passed\\n\"
    exit 0
    ;;
  all_skip)
    printf \"\\033[32mrunning 1 tests\\033[0m\\n\"
    echo CAPLOG {cap_skip}
    printf \"test result: ok. 1 passed\\n\"
    exit 0
    ;;
  all_skip2)
    echo CAPLOG {cap_skip}
    echo CAPLOG {cap_skip_c}
    exit 0
    ;;
  nocaplog)
    echo \"test result: ok. 0 passed\"
    exit 0
    ;;
  failverdict)
    echo CAPLOG {cap_fail}
    exit 0
    ;;
  noverdict)
    echo CAPLOG {cap_noverdict}
    exit 0
    ;;
  nostep)
    echo CAPLOG {cap_nostep}
    exit 0
    ;;
  duplicate_step)
    echo CAPLOG {cap_a}
    echo CAPLOG {cap_a}
    exit 0
    ;;
  badjson)
    echo CAPLOG {cap_bad}
    echo CAPLOG {cap_b}
    exit 0
    ;;
  e101)
    echo CAPLOG {cap_a}
    exit 101
    ;;
  e101_fail)
    echo CAPLOG {cap_fail}
    exit 101
    ;;
  e103)
    exit 103
    ;;
esac
"""
        stub_rch.write_text(stub_content, encoding="utf-8")
        stub_rch.chmod(stub_rch.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def run_harness(self, args: list[str] | None = None, extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
        env = dict(os.environ)
        env["PATH"] = f"{self.bin_dir}:{env.get('PATH', '')}"
        env["FSS_E2E_LOG_DIR"] = str(self.log_dir)
        env["RCH_REQUIRE_REMOTE"] = "1"
        env["TMPDIR"] = str(self.tmpdir_env)
        if extra_env:
            env.update(extra_env)

        cmd = ["bash", str(SCRIPT)]
        if args:
            cmd.extend(args)
        return subprocess.run(cmd, cwd=str(ROOT), env=env, capture_output=True, text=True)

    def read_latest_log_records(self) -> list[dict]:
        suite_dir = self.log_dir / "ingest_mjpeg"
        self.assertTrue(suite_dir.is_dir(), f"Suite log directory {suite_dir} does not exist")
        log_files = sorted(suite_dir.glob("run_*.log"))
        self.assertTrue(len(log_files) > 0, "No log files found")
        latest = log_files[-1]
        records = []
        with open(latest, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        return records

    def summary_line(self, proc: subprocess.CompletedProcess) -> str:
        lines = [line for line in proc.stdout.splitlines() if line.strip()]
        self.assertTrue(lines, f"harness printed nothing: {proc.stderr}")
        return lines[-1]

    def assert_summary(self, summary: dict, *, verdict: str, steps: int, passed: int,
                       step_failures: int, failures: list[str], skipped: list[str],
                       run_failures: tuple[str, ...] = ()) -> None:
        self.assertEqual(summary["step"], "summary")
        self.assertEqual(summary["verdict"], verdict)
        self.assertEqual(summary["steps"], steps)
        self.assertEqual(summary["passed"], passed)
        self.assertEqual(summary["step_failures"], step_failures)
        self.assertEqual(summary["failures"], failures)
        self.assertEqual(summary["run_failures"], list(run_failures))
        self.assertEqual([item["step"] for item in summary["skipped"]], skipped)
        self.assertEqual(summary["fail_count"], len(failures) + len(run_failures))

    def test_pass_summary_and_locked_offline(self) -> None:
        proc = self.run_harness(extra_env={"STUB_MODE": "pass"})
        self.assertEqual(proc.returncode, 0, f"Expected exit 0, got {proc.returncode}: {proc.stderr}")
        
        

        records = self.read_latest_log_records()
        self.assertEqual(len(records), 4)
        self.assertEqual(records[0]["step"], "env")
        self.assertEqual(records[1]["step"], "a")
        self.assertEqual(records[1]["verdict"], "pass")
        self.assertEqual(records[2]["step"], "b")
        self.assertEqual(records[2]["verdict"], "pass")

        summary = records[3]
        self.assertEqual(summary["step"], "summary")
        self.assertEqual(summary["verdict"], "pass")
        self.assertEqual(summary["steps"], 2)
        self.assertEqual(summary["failures"], [])
        self.assertEqual(summary["skipped"], [])
        self.assert_summary(summary, verdict="pass", steps=2, passed=2, step_failures=0, failures=[], skipped=[])

        calls = self.calls_file.read_text(encoding="utf-8")
        self.assertIn("--locked", calls)
        self.assertIn("--offline", calls)

    def test_pass_with_skip(self) -> None:
        proc = self.run_harness(extra_env={"STUB_MODE": "pass_with_skip"})
        self.assertEqual(proc.returncode, 0, f"Expected exit 0: {proc.stderr}")
        
        

        records = self.read_latest_log_records()
        summary = records[-1]
        self.assertEqual(summary["verdict"], "pass")
        self.assertEqual(summary["steps"], 2)
        self.assertEqual(summary["failures"], [])
        self.assertEqual([item["step"] for item in summary["skipped"]], ["b"])
        self.assertEqual(json.loads(summary["skipped"][0]["reason"]), {"r": "skip"})
        self.assert_summary(summary, verdict="pass", steps=2, passed=1, step_failures=0, failures=[], skipped=["b"])

    def test_only_filter_args(self) -> None:
        proc = self.run_harness(args=["--only", "step_custom"], extra_env={"STUB_MODE": "pass"})
        self.assertEqual(proc.returncode, 0, f"Expected exit 0: {proc.stderr}")

        calls = self.calls_file.read_text(encoding="utf-8")
        self.assertIn("step_custom", calls)

        records = self.read_latest_log_records()
        summary = records[-1]
        self.assertEqual(summary["repro"], "scripts/e2e/cap_ingest_mjpeg.sh --only step_custom")

    def test_only_equals_syntax(self) -> None:
        proc = self.run_harness(args=["--only=step_custom_eq"], extra_env={"STUB_MODE": "pass"})
        self.assertEqual(proc.returncode, 0, f"Expected exit 0: {proc.stderr}")

        calls = self.calls_file.read_text(encoding="utf-8")
        self.assertIn("step_custom_eq", calls)

        records = self.read_latest_log_records()
        summary = records[-1]
        self.assertEqual(summary["repro"], "scripts/e2e/cap_ingest_mjpeg.sh --only step_custom_eq")

    def test_badjson_fails_and_populates_failures(self) -> None:
        proc = self.run_harness(extra_env={"STUB_MODE": "badjson"})
        self.assertEqual(proc.returncode, 1, "Expected exit 1 on malformed JSON")
        
        

        records = self.read_latest_log_records()
        summary = records[-1]
        self.assertEqual(summary["verdict"], "fail")
        self.assertIn("malformed_caplog", summary["failures"])
        self.assert_summary(summary, verdict="fail", steps=2, passed=1, step_failures=1,
                            failures=["malformed_caplog"], skipped=[])

    def test_failverdict_populates_failures(self) -> None:
        proc = self.run_harness(extra_env={"STUB_MODE": "failverdict"})
        self.assertEqual(proc.returncode, 1, "Expected exit 1 on failed step")
        

        records = self.read_latest_log_records()
        summary = records[-1]
        self.assertEqual(summary["verdict"], "fail")
        self.assertIn("a", summary["failures"])
        self.assert_summary(summary, verdict="fail", steps=1, passed=0, step_failures=1,
                            failures=["a"], skipped=[])

    def test_missing_verdict_fails(self) -> None:
        proc = self.run_harness(extra_env={"STUB_MODE": "noverdict"})
        self.assertEqual(proc.returncode, 1, "Expected exit 1 on missing verdict key")
        
        

        records = self.read_latest_log_records()
        summary = records[-1]
        self.assertEqual(summary["verdict"], "fail")
        self.assertIn("a:missing_verdict", summary["failures"])
        self.assert_summary(summary, verdict="fail", steps=1, passed=0, step_failures=1,
                            failures=["a:missing_verdict"], skipped=[])

    def test_missing_step_fails(self) -> None:
        proc = self.run_harness(extra_env={"STUB_MODE": "nostep"})
        self.assertEqual(proc.returncode, 1, "Expected exit 1 on missing step key")
        
        

        records = self.read_latest_log_records()
        summary = records[-1]
        self.assertEqual(summary["verdict"], "fail")
        self.assertIn("missing_step", summary["failures"])
        self.assert_summary(summary, verdict="fail", steps=1, passed=0, step_failures=1,
                            failures=["missing_step"], skipped=[])

    def test_all_steps_skipped_fails(self) -> None:
        proc = self.run_harness(extra_env={"STUB_MODE": "all_skip"})
        self.assertEqual(proc.returncode, 1, "Expected exit 1 when all steps are skipped")
        
        

        records = self.read_latest_log_records()
        summary = records[-1]
        self.assertEqual(summary["verdict"], "fail")
        self.assertIn("all_steps_skipped", summary["run_failures"])
        self.assert_summary(summary, verdict="fail", steps=1, passed=0, step_failures=0,
                            failures=[], run_failures=("all_steps_skipped",), skipped=["b"])

    def test_all_two_steps_skipped_fails(self) -> None:
        proc = self.run_harness(extra_env={"STUB_MODE": "all_skip2"})
        self.assertEqual(proc.returncode, 1, "Expected exit 1 when all steps are skipped")
        

        summary = self.read_latest_log_records()[-1]
        self.assert_summary(summary, verdict="fail", steps=2, passed=0, step_failures=0,
                            failures=[], run_failures=("all_steps_skipped",), skipped=["b", "c"])

    def test_duplicate_step_fails(self) -> None:
        proc = self.run_harness(extra_env={"STUB_MODE": "duplicate_step"})
        self.assertEqual(proc.returncode, 1, "Expected exit 1 on duplicate step names")
        
        

        records = self.read_latest_log_records()
        summary = records[-1]
        self.assertEqual(summary["verdict"], "fail")
        self.assertIn("a:duplicate_step", summary["failures"])
        self.assert_summary(summary, verdict="fail", steps=2, passed=1, step_failures=1,
                            failures=["a:duplicate_step"], skipped=[])

    def test_nocaplog_fails(self) -> None:
        proc = self.run_harness(extra_env={"STUB_MODE": "nocaplog"})
        self.assertEqual(proc.returncode, 1, "Expected exit 1 when 0 CAPLOG records emitted")
        

        records = self.read_latest_log_records()
        summary = records[-1]
        self.assertEqual(summary["verdict"], "fail")
        self.assertIn("no_caplog_emitted", summary["run_failures"])
        self.assert_summary(summary, verdict="fail", steps=0, passed=0, step_failures=0,
                            failures=[], run_failures=("no_caplog_emitted",), skipped=[])

    def test_cargo_exit_nonzero_fails(self) -> None:
        proc = self.run_harness(extra_env={"STUB_MODE": "e101"})
        self.assertEqual(proc.returncode, 1, "Expected exit 1 when cargo fails")
        

        records = self.read_latest_log_records()
        summary = records[-1]
        self.assertEqual(summary["verdict"], "fail")
        self.assertIn("cargo_test_failed", summary["run_failures"])
        self.assert_summary(summary, verdict="fail", steps=1, passed=1, step_failures=0,
                            failures=[], run_failures=("cargo_test_failed",), skipped=[])

    def test_cargo_exit_nonzero_with_failed_step(self) -> None:
        proc = self.run_harness(extra_env={"STUB_MODE": "e101_fail"})
        self.assertEqual(proc.returncode, 1)
        

        summary = self.read_latest_log_records()[-1]
        self.assert_summary(summary, verdict="fail", steps=1, passed=0, step_failures=1,
                            failures=["a"], run_failures=("cargo_test_failed",), skipped=[])

    def test_e103_retries(self) -> None:
        proc = self.run_harness(extra_env={"STUB_MODE": "e103"})
        self.assertEqual(proc.returncode, 1, "Expected exit 1 when rch retries exhaust")
        

        calls = [c for c in self.calls_file.read_text(encoding="utf-8").splitlines() if c.strip()]
        self.assertEqual(len(calls), 4, f"Expected 4 attempts (1 initial + 3 retries), got {len(calls)}")

        summary = self.read_latest_log_records()[-1]
        self.assert_summary(summary, verdict="fail", steps=0, passed=0, step_failures=0,
                            failures=[], run_failures=("cargo_test_failed", "no_caplog_emitted"), skipped=[])

    def test_stdout_capture_lives_under_log_dir(self) -> None:
        proc = self.run_harness(extra_env={"STUB_MODE": "pass"})
        self.assertEqual(proc.returncode, 0, proc.stderr)

        suite_dir = (self.log_dir / "ingest_mjpeg").resolve()
        paths = [p for p in self.fd_file.read_text(encoding="utf-8").splitlines() if p.strip()]
        self.assertEqual(len(paths), 1, paths)
        capture = Path(paths[0])
        self.assertEqual(capture.parent, suite_dir, f"capture file {capture} not under {suite_dir}")
        self.assertTrue(capture.name.startswith("cargo_stdout."), capture.name)
        # The capture file is removed; only the run log remains. TMPDIR is never touched.
        self.assertFalse(capture.exists(), f"capture file {capture} left behind")
        self.assertEqual(sorted(p.name for p in suite_dir.iterdir()), ["run_0001.log"])
        self.assertEqual(list(self.tmpdir_env.iterdir()), [])

    def test_env_dynamic_dirty_and_bins(self) -> None:
        custom_bin_dir = self.tmp_path / "custom_bins"
        custom_bin_dir.mkdir()
        dummy_bin = custom_bin_dir / "fss-dummy"
        dummy_bin.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        dummy_bin.chmod(dummy_bin.stat().st_mode | stat.S_IXUSR)

        proc = self.run_harness(extra_env={"STUB_MODE": "pass", "FSS_BIN_DIR": str(custom_bin_dir)})
        self.assertEqual(proc.returncode, 0)

        records = self.read_latest_log_records()
        env_rec = records[0]
        self.assertIsInstance(env_rec["dirty"], bool)
        self.assertEqual([item["name"] for item in env_rec["bins"]], ["fss-dummy"])

    def test_per_step_ts(self) -> None:
        proc = self.run_harness(extra_env={"STUB_MODE": "pass"})
        self.assertEqual(proc.returncode, 0)

        records = self.read_latest_log_records()
        iso_pattern = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        for rec in records[1:-1]:
            self.assertIn("ts", rec)
            self.assertTrue(iso_pattern.match(rec["ts"]), f"Invalid ts format: {rec.get('ts')}")


if __name__ == "__main__":
    unittest.main()

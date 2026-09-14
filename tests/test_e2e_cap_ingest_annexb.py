#!/usr/bin/env python3
"""Tests for scripts/e2e/cap_ingest_annexb.sh with stubbed rch."""
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
SCRIPT = ROOT / "scripts/e2e/cap_ingest_annexb.sh"


class TestE2eCapIngestAnnexB(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp_dir.name)
        self.bin_dir = self.tmp_path / "bin"
        self.bin_dir.mkdir()
        self.log_dir = self.tmp_path / "logs"
        self.log_dir.mkdir()
        self.calls_file = self.tmp_path / "stub_calls.txt"

        stub_rch = self.bin_dir / "rch"
        cap_a = chr(39) + chr(123) + chr(34) + "step" + chr(34) + ":" + chr(34) + "a" + chr(34) + "," + chr(34) + "verdict" + chr(34) + ":" + chr(34) + "pass" + chr(34) + "," + chr(34) + "exit" + chr(34) + ":0," + chr(34) + "duration_ms" + chr(34) + ":1," + chr(34) + "expected" + chr(34) + ":{}," + chr(34) + "observed" + chr(34) + ":{}" + chr(125) + chr(39)
        cap_b = chr(39) + chr(123) + chr(34) + "step" + chr(34) + ":" + chr(34) + "b" + chr(34) + "," + chr(34) + "verdict" + chr(34) + ":" + chr(34) + "pass" + chr(34) + "," + chr(34) + "exit" + chr(34) + ":0," + chr(34) + "duration_ms" + chr(34) + ":2," + chr(34) + "expected" + chr(34) + ":{}," + chr(34) + "observed" + chr(34) + ":{}" + chr(125) + chr(39)
        cap_skip = chr(39) + chr(123) + chr(34) + "step" + chr(34) + ":" + chr(34) + "b" + chr(34) + "," + chr(34) + "verdict" + chr(34) + ":" + chr(34) + "skip" + chr(34) + "," + chr(34) + "exit" + chr(34) + ":0," + chr(34) + "duration_ms" + chr(34) + ":1," + chr(34) + "expected" + chr(34) + ":{" + chr(34) + "m" + chr(34) + ":1}," + chr(34) + "observed" + chr(34) + ":{" + chr(34) + "r" + chr(34) + ":" + chr(34) + "skip" + chr(34) + "}" + chr(125) + chr(39)
        cap_fail = chr(39) + chr(123) + chr(34) + "step" + chr(34) + ":" + chr(34) + "a" + chr(34) + "," + chr(34) + "verdict" + chr(34) + ":" + chr(34) + "fail" + chr(34) + chr(125) + chr(39)
        cap_bad = chr(39) + chr(123) + chr(34) + "step" + chr(34) + ":" + chr(34) + "a" + chr(34) + ", broken json" + chr(39)
        cap_noverdict = chr(39) + chr(123) + chr(34) + "step" + chr(34) + ":" + chr(34) + "a" + chr(34) + chr(125) + chr(39)
        cap_nostep = chr(39) + chr(123) + chr(34) + "verdict" + chr(34) + ":" + chr(34) + "pass" + chr(34) + chr(125) + chr(39)
        stub_content = f"""#!/usr/bin/env bash
echo "$@" >> "{self.calls_file}"
case "${{STUB_MODE:-pass}}" in
  pass)
    printf "\\033[32mrunning 2 tests\\033[0m\\n"
    echo CAPLOG {cap_a}
    echo CAPLOG {cap_b}
    printf "test result: ok. 2 passed\\n"
    exit 0
    ;;
  pass_with_skip)
    printf "\\033[32mrunning 2 tests\\033[0m\\n"
    echo CAPLOG {cap_a}
    echo CAPLOG {cap_skip}
    printf "test result: ok. 2 passed\\n"
    exit 0
    ;;
  all_skip)
    printf "\\033[32mrunning 1 tests\\033[0m\\n"
    echo CAPLOG {cap_skip}
    printf "test result: ok. 1 passed\\n"
    exit 0
    ;;
  nocaplog)
    echo "test result: ok. 0 passed"
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
  e103)
    exit 103
    ;;
esac
"""
        stub_rch.write_text(stub_content, encoding="utf-8")
        stub_rch.chmod(stub_rch.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def run_harness(
        self,
        args: list[str] | None = None,
        extra_env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["PATH"] = f"{self.bin_dir}:{env.get('PATH', '')}"
        env["FSS_E2E_LOG_DIR"] = str(self.log_dir)
        env["RCH_REQUIRE_REMOTE"] = "1"
        if extra_env:
            env.update(extra_env)

        cmd = [str(SCRIPT)]
        if args:
            cmd.extend(args)

        return subprocess.run(
            cmd,
            cwd=str(ROOT),
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def read_latest_log_records(self) -> list[dict]:
        log_files = sorted(self.log_dir.glob("ingest_annexb/run_*.log"))
        self.assertTrue(log_files, "No run logs found in log dir")
        latest = log_files[-1]
        records = []
        with open(latest, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        return records

    def test_pass_summary_and_locked_offline(self) -> None:
        proc = self.run_harness(extra_env={"STUB_MODE": "pass"})
        self.assertEqual(proc.returncode, 0, f"Expected exit 0, got {proc.returncode}: {proc.stderr}")
        self.assertIn("pass summary: 2 steps passed, 0 failures", proc.stdout)

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

        calls = self.calls_file.read_text(encoding="utf-8")
        self.assertIn("--locked", calls)
        self.assertIn("--offline", calls)

    def test_pass_with_skip(self) -> None:
        proc = self.run_harness(extra_env={"STUB_MODE": "pass_with_skip"})
        self.assertEqual(proc.returncode, 0, f"Expected exit 0: {proc.stderr}")
        self.assertIn("pass summary: 1 steps passed, 1 skipped, 0 failures", proc.stdout)

        records = self.read_latest_log_records()
        summary = records[-1]
        self.assertEqual(summary["verdict"], "pass")
        self.assertEqual(summary["steps"], 2)
        self.assertEqual(summary["failures"], [])
        self.assertEqual(summary["skipped"], ["b"])

    def test_only_filter_args(self) -> None:
        proc = self.run_harness(args=["--only", "step_custom"], extra_env={"STUB_MODE": "pass"})
        self.assertEqual(proc.returncode, 0, f"Expected exit 0: {proc.stderr}")

        calls = self.calls_file.read_text(encoding="utf-8")
        self.assertIn("step_custom", calls)

        records = self.read_latest_log_records()
        summary = records[-1]
        self.assertEqual(summary["repro"], "scripts/e2e/cap_ingest_annexb.sh --only step_custom")

    def test_only_equals_syntax(self) -> None:
        proc = self.run_harness(args=["--only=step_custom_eq"], extra_env={"STUB_MODE": "pass"})
        self.assertEqual(proc.returncode, 0, f"Expected exit 0: {proc.stderr}")

        calls = self.calls_file.read_text(encoding="utf-8")
        self.assertIn("step_custom_eq", calls)

        records = self.read_latest_log_records()
        summary = records[-1]
        self.assertEqual(summary["repro"], "scripts/e2e/cap_ingest_annexb.sh --only step_custom_eq")

    def test_badjson_fails_and_populates_failures(self) -> None:
        proc = self.run_harness(extra_env={"STUB_MODE": "badjson"})
        self.assertEqual(proc.returncode, 1, "Expected exit 1 on malformed JSON")
        self.assertIn("fail summary", proc.stdout)

        records = self.read_latest_log_records()
        summary = records[-1]
        self.assertEqual(summary["verdict"], "fail")
        self.assertIn("malformed_caplog", summary["failures"])

    def test_failverdict_populates_failures(self) -> None:
        proc = self.run_harness(extra_env={"STUB_MODE": "failverdict"})
        self.assertEqual(proc.returncode, 1, "Expected exit 1 on failed step")

        records = self.read_latest_log_records()
        summary = records[-1]
        self.assertEqual(summary["verdict"], "fail")
        self.assertIn("a", summary["failures"])

    def test_missing_verdict_fails(self) -> None:
        proc = self.run_harness(extra_env={"STUB_MODE": "noverdict"})
        self.assertEqual(proc.returncode, 1, "Expected exit 1 on missing verdict key")
        self.assertIn("fail summary", proc.stdout)

        records = self.read_latest_log_records()
        summary = records[-1]
        self.assertEqual(summary["verdict"], "fail")
        self.assertIn("a:missing_verdict", summary["failures"])

    def test_missing_step_fails(self) -> None:
        proc = self.run_harness(extra_env={"STUB_MODE": "nostep"})
        self.assertEqual(proc.returncode, 1, "Expected exit 1 on missing step key")
        self.assertIn("fail summary", proc.stdout)

        records = self.read_latest_log_records()
        summary = records[-1]
        self.assertEqual(summary["verdict"], "fail")
        self.assertIn("missing_step", summary["failures"])

    def test_all_steps_skipped_fails(self) -> None:
        proc = self.run_harness(extra_env={"STUB_MODE": "all_skip"})
        self.assertEqual(proc.returncode, 1, "Expected exit 1 when all steps are skipped")
        self.assertIn("fail summary", proc.stdout)

        records = self.read_latest_log_records()
        summary = records[-1]
        self.assertEqual(summary["verdict"], "fail")
        self.assertIn("all_steps_skipped", summary["failures"])

    def test_duplicate_step_fails(self) -> None:
        proc = self.run_harness(extra_env={"STUB_MODE": "duplicate_step"})
        self.assertEqual(proc.returncode, 1, "Expected exit 1 on duplicate step names")
        self.assertIn("fail summary", proc.stdout)

        records = self.read_latest_log_records()
        summary = records[-1]
        self.assertEqual(summary["verdict"], "fail")
        self.assertIn("a:duplicate_step", summary["failures"])

    def test_nocaplog_fails(self) -> None:
        proc = self.run_harness(extra_env={"STUB_MODE": "nocaplog"})
        self.assertEqual(proc.returncode, 1, "Expected exit 1 when 0 CAPLOG records emitted")

        records = self.read_latest_log_records()
        summary = records[-1]
        self.assertEqual(summary["verdict"], "fail")
        self.assertIn("no_caplog_emitted", summary["failures"])

    def test_cargo_exit_nonzero_fails(self) -> None:
        proc = self.run_harness(extra_env={"STUB_MODE": "e101"})
        self.assertEqual(proc.returncode, 1, "Expected exit 1 when cargo fails")

        records = self.read_latest_log_records()
        summary = records[-1]
        self.assertEqual(summary["verdict"], "fail")
        self.assertIn("cargo_test_failed", summary["failures"])

    def test_e103_retries(self) -> None:
        proc = self.run_harness(extra_env={"STUB_MODE": "e103"})
        self.assertEqual(proc.returncode, 1, "Expected exit 1 when rch retries exhaust")

        calls = [c for c in self.calls_file.read_text(encoding="utf-8").splitlines() if c.strip()]
        self.assertEqual(len(calls), 4, f"Expected 4 attempts (1 initial + 3 retries), got {len(calls)}")

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
        self.assertEqual(env_rec["bins"], ["fss-dummy"])

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

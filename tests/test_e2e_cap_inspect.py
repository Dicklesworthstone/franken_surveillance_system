#!/usr/bin/env python3
"""Tests for scripts/e2e/cap_inspect.sh with stubbed rch."""
from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/e2e/cap_inspect.sh"


class TestE2eCapInspect(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp_dir.name)
        self.bin_dir = self.tmp_path / "bin"
        self.bin_dir.mkdir()
        self.log_dir = self.tmp_path / "logs"
        self.log_dir.mkdir()
        self.calls_file = self.tmp_path / "stub_calls.txt"
        self.counter_file = self.tmp_path / "stub_counter.txt"

        stub_rch = self.bin_dir / "rch"
        cap_a = chr(39) + chr(123) + chr(34) + "step" + chr(34) + ":" + chr(34) + "step_a" + chr(34) + "," + chr(34) + "verdict" + chr(34) + ":" + chr(34) + "pass" + chr(34) + "," + chr(34) + "exit" + chr(34) + ":0," + chr(34) + "duration_ms" + chr(34) + ":1," + chr(34) + "expected" + chr(34) + ":{}," + chr(34) + "observed" + chr(34) + ":{}" + chr(125) + chr(39)
        cap_b = chr(39) + chr(123) + chr(34) + "step" + chr(34) + ":" + chr(34) + "step_b" + chr(34) + "," + chr(34) + "verdict" + chr(34) + ":" + chr(34) + "pass" + chr(34) + "," + chr(34) + "exit" + chr(34) + ":0," + chr(34) + "duration_ms" + chr(34) + ":2," + chr(34) + "expected" + chr(34) + ":{}," + chr(34) + "observed" + chr(34) + ":{}" + chr(125) + chr(39)
        cap_skip = chr(39) + chr(123) + chr(34) + "step" + chr(34) + ":" + chr(34) + "step_skip" + chr(34) + "," + chr(34) + "verdict" + chr(34) + ":" + chr(34) + "skip" + chr(34) + "," + chr(34) + "exit" + chr(34) + ":0," + chr(34) + "duration_ms" + chr(34) + ":1," + chr(34) + "expected" + chr(34) + ":{}," + chr(34) + "observed" + chr(34) + ":{}" + chr(125) + chr(39)
        cap_fail = chr(39) + chr(123) + chr(34) + "step" + chr(34) + ":" + chr(34) + "step_fail" + chr(34) + "," + chr(34) + "verdict" + chr(34) + ":" + chr(34) + "fail" + chr(34) + chr(125) + chr(39)

        stub_content = f"""#!/usr/bin/env bash
echo "$@" >> "{self.calls_file}"
TARGET="test"
prev=""
for arg in "$@"; do
  if [[ "$prev" == "--test" ]]; then
    TARGET="$arg"
  fi
  prev="$arg"
done

cap_a='{{"step":"'${{TARGET}}'_a","verdict":"pass","exit":0,"duration_ms":1,"expected":{{}},"observed":{{}}}}'
cap_b='{{"step":"'${{TARGET}}'_b","verdict":"pass","exit":0,"duration_ms":2,"expected":{{}},"observed":{{}}}}'
cap_skip='{{"step":"'${{TARGET}}'_skip","verdict":"skip","exit":0,"duration_ms":1,"expected":{{}},"observed":{{}}}}'
cap_fail='{{"step":"'${{TARGET}}'_fail","verdict":"fail","exit":1,"duration_ms":1,"expected":{{}},"observed":{{}}}}'

case "${{STUB_MODE:-pass}}" in
  pass)
    printf "\\033[32mrunning 2 tests\\033[0m\\n"
    echo CAPLOG $cap_a
    echo CAPLOG $cap_b
    printf "test result: ok. 2 passed\\n"
    exit 0
    ;;
  pass_with_skip)
    printf "\\033[32mrunning 2 tests\\033[0m\\n"
    echo CAPLOG $cap_a
    echo CAPLOG $cap_skip
    printf "test result: ok. 2 passed\\n"
    exit 0
    ;;
  all_skip)
    printf "\\033[32mrunning 1 tests\\033[0m\\n"
    echo CAPLOG $cap_skip
    printf "test result: ok. 1 passed\\n"
    exit 0
    ;;
  failverdict)
    echo CAPLOG $cap_fail
    exit 0
    ;;
  nocaplog)
    echo "test result: ok. 0 passed"
    exit 0
    ;;
  retry103)
    CNT=0
    if [[ -f "{self.counter_file}" ]]; then
      CNT=$(cat "{self.counter_file}")
    fi
    CNT=$((CNT + 1))
    echo "$CNT" > "{self.counter_file}"
    if (( CNT == 1 )); then
      exit 103
    fi
    echo CAPLOG $cap_a
    exit 0
    ;;
  e101)
    exit 101
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
    ) -> subprocess.CompletedProcess:
        env = dict(os.environ)
        env["PATH"] = f"{self.bin_dir}:{env.get('PATH', '')}"
        env["FSS_E2E_LOG_DIR"] = str(self.log_dir)
        env["RCH_REQUIRE_REMOTE"] = "1"
        if extra_env:
            env.update(extra_env)

        cmd = ["bash", str(SCRIPT)]
        if args:
            cmd.extend(args)
        return subprocess.run(cmd, cwd=str(ROOT), env=env, capture_output=True, text=True)

    def read_latest_log_records(self) -> list[dict]:
        suite_dir = self.log_dir / "cap_inspect"
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

    def test_pass_summary(self) -> None:
        proc = self.run_harness(extra_env={"STUB_MODE": "pass"})
        self.assertEqual(proc.returncode, 0, f"Expected exit 0, got {proc.returncode}: {proc.stderr}")
        self.assertIn("pass summary:", proc.stdout)

        records = self.read_latest_log_records()
        self.assertTrue(len(records) >= 3)
        self.assertEqual(records[0]["step"], "env")
        summary = records[-1]
        self.assertEqual(summary["step"], "summary")
        self.assertEqual(summary["verdict"], "pass")
        self.assertEqual(len(summary["failures"]), 0)

        # Validate with validate_log.py if available
        validator_path = ROOT / "scripts/e2e/validate_log.py"
        if not validator_path.is_file():
            validator_path = Path("/tmp/validate_log.py")
        if validator_path.is_file():
            suite_dir = self.log_dir / "cap_inspect"
            log_files = sorted(suite_dir.glob("run_*.log"))
            vp = subprocess.run(
                ["python3", str(validator_path), str(log_files[-1])],
                capture_output=True,
                text=True,
            )
            self.assertEqual(vp.returncode, 0, f"validate_log.py failed: {vp.stderr}")

    def test_pass_with_skip(self) -> None:
        proc = self.run_harness(extra_env={"STUB_MODE": "pass_with_skip"})
        self.assertEqual(proc.returncode, 0, f"Expected exit 0, got {proc.returncode}: {proc.stderr}")
        self.assertIn("pass summary:", proc.stdout)

        records = self.read_latest_log_records()
        summary = records[-1]
        self.assertEqual(summary["verdict"], "pass")

    def test_all_skip_fails_closed(self) -> None:
        proc = self.run_harness(extra_env={"STUB_MODE": "all_skip"})
        self.assertNotEqual(proc.returncode, 0, "Expected non-zero exit for all-skip")
        records = self.read_latest_log_records()
        summary = records[-1]
        self.assertEqual(summary["verdict"], "fail")
        self.assertIn("all_steps_skipped", summary["failures"])

    def test_failverdict(self) -> None:
        proc = self.run_harness(extra_env={"STUB_MODE": "failverdict"})
        self.assertNotEqual(proc.returncode, 0)
        records = self.read_latest_log_records()
        summary = records[-1]
        self.assertEqual(summary["verdict"], "fail")

    def test_nocaplog_fails_closed(self) -> None:
        proc = self.run_harness(extra_env={"STUB_MODE": "nocaplog"})
        self.assertNotEqual(proc.returncode, 0)
        records = self.read_latest_log_records()
        summary = records[-1]
        self.assertEqual(summary["verdict"], "fail")

    def test_e103_retry_success(self) -> None:
        proc = self.run_harness(extra_env={"STUB_MODE": "retry103"})
        self.assertEqual(proc.returncode, 0, f"Expected retry success, got {proc.returncode}: {proc.stderr}")
        records = self.read_latest_log_records()
        summary = records[-1]
        self.assertEqual(summary["verdict"], "pass")

    def test_list_flag(self) -> None:
        proc = self.run_harness(args=["--list"])
        self.assertEqual(proc.returncode, 0)
        lines = [line.strip() for line in proc.stdout.strip().splitlines() if line.strip()]
        self.assertIn("spool_inspect_contract", lines)
        self.assertIn("local_inspect_contract", lines)
        self.assertIn("durable_inspect_contract", lines)
        self.assertIn("effect_journal_inspect_contract", lines)

    def test_only_flag(self) -> None:
        proc = self.run_harness(
            args=["--only", "spool_inspect_contract"],
            extra_env={"STUB_MODE": "pass"},
        )
        self.assertEqual(proc.returncode, 0)
        records = self.read_latest_log_records()
        summary = records[-1]
        self.assertEqual(summary["steps"], 2)


if __name__ == "__main__":
    unittest.main()

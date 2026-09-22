#!/usr/bin/env python3
"""Unit test suite for CAP- fixtures JPEG E2E harness (scripts/e2e/cap_fixtures_jpeg.sh).

Verifies:
- Execution and exit code propagation.
- Output log schema, step recording, and summary verdict.
- Filtering via --only and --only= syntax.
- Fail-closed behavior on malformed JSON, missing step, missing verdict, duplicate steps,
  all-skipped runs, and missing CAPLOG.
- Exit code 103 retries.
- Strictly isolated stub execution without running real rch or cargo.
"""

import json
import os
import pathlib
import re
import stat
import subprocess
import tempfile
import unittest
from typing import Any, Dict, List, Optional


class TestE2eCapFixturesJpeg(unittest.TestCase):
    def setUp(self) -> None:
        repo_root = pathlib.Path(__file__).resolve().parent.parent
        target_tmp = repo_root / "target" / "tmp"
        target_tmp.mkdir(parents=True, exist_ok=True)
        self.tmp_dir = tempfile.TemporaryDirectory(dir=target_tmp)
        self.tmp_path = pathlib.Path(self.tmp_dir.name)
        self.log_dir = self.tmp_path / "logs"
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.bin_dir = self.tmp_path / "bin"
        self.bin_dir.mkdir(parents=True, exist_ok=True)
        self.calls_file = self.tmp_path / "cargo_calls.log"

        # Create stub cargo binary
        stub_cargo = self.bin_dir / "cargo"
        stub_script = f"""#!/usr/bin/env python3
import os, sys, pathlib

calls_path = pathlib.Path({repr(str(self.calls_file))})
with open(calls_path, "a", encoding="utf-8") as f:
    f.write(" ".join(sys.argv[1:]) + "\\n")

mode = os.environ.get("STUB_MODE", "pass")

if mode == "pass":
    print('CAPLOG {{"step":"a","verdict":"pass","exit":0,"duration_ms":12,"expected":{{"x":1}},"observed":{{"x":1}}}}')
    print('CAPLOG {{"step":"b","verdict":"pass","exit":0,"duration_ms":15,"expected":{{"y":2}},"observed":{{"y":2}}}}')
    sys.exit(0)
elif mode == "pass_with_skip":
    print('CAPLOG {{"step":"a","verdict":"pass","exit":0,"duration_ms":12,"expected":{{"x":1}},"observed":{{"x":1}}}}')
    print('CAPLOG {{"step":"b","verdict":"skip","exit":0,"duration_ms":0,"expected":{{"y":2}},"observed":{{"y":null}}}}')
    sys.exit(0)
elif mode == "badjson":
    print("CAPLOG {{bad json")
    sys.exit(0)
elif mode == "failverdict":
    print('CAPLOG {{"step":"a","verdict":"fail","exit":1,"duration_ms":10,"expected":1,"observed":0}}')
    sys.exit(0)
elif mode == "noverdict":
    print('CAPLOG {{"step":"a","exit":0,"duration_ms":10,"expected":1,"observed":1}}')
    sys.exit(0)
elif mode == "nostep":
    print('CAPLOG {{"verdict":"pass","exit":0,"duration_ms":10,"expected":1,"observed":1}}')
    sys.exit(0)
elif mode == "all_skip":
    print('CAPLOG {{"step":"a","verdict":"skip","exit":0,"duration_ms":0,"expected":1,"observed":1}}')
    sys.exit(0)
elif mode == "duplicate_step":
    print('CAPLOG {{"step":"a","verdict":"pass","exit":0,"duration_ms":10,"expected":1,"observed":1}}')
    print('CAPLOG {{"step":"a","verdict":"pass","exit":0,"duration_ms":10,"expected":1,"observed":1}}')
    sys.exit(0)
elif mode == "nocaplog":
    print("Normal test output without any caplog records")
    sys.exit(0)
elif mode == "e101":
    print("Compiling error...")
    sys.exit(101)
elif mode == "e103":
    sys.exit(103)
else:
    sys.exit(0)
"""
        stub_cargo.write_text(stub_script, encoding="utf-8")
        stub_cargo.chmod(stub_cargo.stat().st_mode | stat.S_IXUSR)

        self.repo_root = pathlib.Path(__file__).resolve().parent.parent
        self.script_path = self.repo_root / "scripts" / "e2e" / "cap_fixtures_jpeg.sh"

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def run_harness(
        self,
        args: Optional[List[str]] = None,
        extra_env: Optional[Dict[str, str]] = None,
    ) -> subprocess.CompletedProcess:
        env = os.environ.copy()
        env["PATH"] = f"{self.bin_dir}:{env['PATH']}"
        env["FSS_E2E_LOG_DIR"] = str(self.log_dir)
        env["RCH_STUB_LOG"] = "1"
        env["RCH_REQUIRE_REMOTE"] = "0"
        if extra_env:
            env.update(extra_env)

        cmd = ["bash", str(self.script_path)]
        if args:
            cmd.extend(args)

        return subprocess.run(
            cmd,
            cwd=str(self.repo_root),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

    def read_latest_log_records(self) -> List[Dict[str, Any]]:
        suite_dir = self.log_dir / "fixtures_jpeg"
        log_files = sorted(suite_dir.glob("run_*.log"))
        self.assertTrue(log_files, "No run logs produced in suite dir")
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
        self.assertEqual(proc.returncode, 0, f"Expected exit 0: {proc.stderr}")
        self.assertIn("pass summary", proc.stdout)

        records = self.read_latest_log_records()
        self.assertGreaterEqual(len(records), 3)
        self.assertEqual(records[0]["step"], "env")
        self.assertEqual(records[1]["step"], "a")
        self.assertEqual(records[1]["verdict"], "pass")
        self.assertEqual(records[2]["step"], "b")
        self.assertEqual(records[2]["verdict"], "pass")

        summary = records[-1]
        self.assertEqual(summary["step"], "summary")
        self.assertEqual(summary["verdict"], "pass")
        self.assertEqual(summary["failures"], [])

        calls = self.calls_file.read_text(encoding="utf-8")
        self.assertIn("--locked", calls)
        self.assertIn("--offline", calls)

    def test_pass_with_skip(self) -> None:
        proc = self.run_harness(extra_env={"STUB_MODE": "pass_with_skip"})
        self.assertEqual(proc.returncode, 0, f"Expected exit 0: {proc.stderr}")
        self.assertIn("pass summary", proc.stdout)

        records = self.read_latest_log_records()
        summary = records[-1]
        self.assertEqual(summary["verdict"], "pass")
        self.assertEqual(summary["failures"], [])
        self.assertIn("b", summary["skipped"])

    def test_only_filter_args(self) -> None:
        proc = self.run_harness(args=["--only", "step_custom"], extra_env={"STUB_MODE": "pass"})
        self.assertEqual(proc.returncode, 0, f"Expected exit 0: {proc.stderr}")

        records = self.read_latest_log_records()
        summary = records[-1]
        self.assertEqual(summary["repro"], "scripts/e2e/cap_fixtures_jpeg.sh --only step_custom")

    def test_only_equals_syntax(self) -> None:
        proc = self.run_harness(args=["--only=step_custom_eq"], extra_env={"STUB_MODE": "pass"})
        self.assertEqual(proc.returncode, 0, f"Expected exit 0: {proc.stderr}")

        records = self.read_latest_log_records()
        summary = records[-1]
        self.assertEqual(summary["repro"], "scripts/e2e/cap_fixtures_jpeg.sh --only step_custom_eq")

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
        self.assertEqual(proc.returncode, 1, "Expected exit 1 on missing verdict")
        self.assertIn("fail summary", proc.stdout)

        records = self.read_latest_log_records()
        summary = records[-1]
        self.assertEqual(summary["verdict"], "fail")
        self.assertIn("a:missing_verdict", summary["failures"])

    def test_missing_step_fails(self) -> None:
        proc = self.run_harness(extra_env={"STUB_MODE": "nostep"})
        self.assertEqual(proc.returncode, 1, "Expected exit 1 on missing step")
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

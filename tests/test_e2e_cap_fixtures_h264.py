#!/usr/bin/env python3
"""Tests for scripts/e2e/cap_fixtures_h264.sh with stubbed rch [fss-9gj41].

Covers: exactly one summary per run, the validator passing on the committed
fixtures, and fail-closed cases — a tampered fixture, a red cargo step, and a
missing CAPLOG from the cargo step. The standalone fallback is gone: lib.sh is
required.
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/e2e/cap_fixtures_h264.sh"
SCRATCH_BASE = ROOT / "target" / "test-e2e-cap-fixtures-h264"

FIXTURE_STEPS = [
    "clean_264",
    "clean_rtp",
    "loss_rtp",
    "reorder_rtp",
    "duplicate_rtp",
    "ssrc_reset_rtp",
    "truncated_last_record_rtp",
    "large_gap_rtp",
]


def cap(payload: dict) -> str:
    return "'" + json.dumps(payload, separators=(",", ":")) + "'"


class TestE2eCapFixturesH264(unittest.TestCase):
    def setUp(self) -> None:
        SCRATCH_BASE.mkdir(parents=True, exist_ok=True)
        self.tmp_dir = tempfile.TemporaryDirectory(dir=SCRATCH_BASE, prefix="run-")
        self.tmp_path = Path(self.tmp_dir.name)
        self.bin_dir = self.tmp_path / "bin"
        self.bin_dir.mkdir()
        self.log_dir = self.tmp_path / "logs"
        self.log_dir.mkdir()

        cap_pass = cap(
            {
                "step": "media_fixture_h264_contract",
                "verdict": "pass",
                "exit": 0,
                "duration_ms": 1,
                "expected": {},
                "observed": {},
            }
        )
        cap_fail = cap(
            {
                "step": "media_fixture_h264_contract",
                "verdict": "fail",
                "exit": 1,
                "duration_ms": 1,
                "expected": {},
                "observed": {},
            }
        )
        self.calls_file = self.tmp_path / "stub_calls.txt"
        stub_rch = self.bin_dir / "rch"
        stub_rch.write_text(
            f"""#!/usr/bin/env bash
echo "$@" >> "{self.calls_file}"
case "${{STUB_MODE:-pass}}" in
  pass)
    echo CAPLOG {cap_pass}
    printf "test result: ok. 6 passed\\n"
    exit 0
    ;;
  failverdict)
    echo CAPLOG {cap_fail}
    exit 0
    ;;
  nocaplog)
    printf "test result: ok. 6 passed\\n"
    exit 0
    ;;
esac
""",
            encoding="utf-8",
        )
        stub_rch.chmod(stub_rch.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def run_harness(
        self, args: list[str] | None = None, extra_env: dict[str, str] | None = None
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
        suite_dir = self.log_dir / "cap_fixtures_h264"
        self.assertTrue(suite_dir.is_dir(), f"Suite log directory {suite_dir} missing")
        log_files = sorted(suite_dir.glob("run_*.log"))
        self.assertTrue(log_files, "No log files found")
        records = []
        with open(log_files[-1], "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        return records

    def summaries(self, records: list[dict]) -> list[dict]:
        return [r for r in records if r.get("step") == "summary"]

    def test_validator_passes_on_committed_fixtures(self) -> None:
        proc = self.run_harness(extra_env={"STUB_MODE": "pass"})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        records = self.read_latest_log_records()
        summaries = self.summaries(records)
        self.assertEqual(len(summaries), 1, "exactly one summary")
        summary = summaries[0]
        self.assertEqual(summary["verdict"], "pass")
        self.assertEqual(summary["failures"], [])
        self.assertEqual(summary["run_failures"], [])
        # All eight fixture steps ran and passed (ffprobe steps may skip).
        step_names = [r["step"] for r in records if r.get("step") in FIXTURE_STEPS]
        self.assertEqual(step_names, FIXTURE_STEPS)
        for name in FIXTURE_STEPS:
            record = next(r for r in records if r.get("step") == f"{name}_exit")
            self.assertEqual(record["verdict"], "pass", name)
        # The cargo step went through the stubbed fleet with the locked/offline pins.
        calls = self.calls_file.read_text(encoding="utf-8")
        self.assertIn("--locked", calls)
        self.assertIn("--offline", calls)

    def test_tampered_fixture_fails_closed(self) -> None:
        fixture = ROOT / "tests/fixtures/media/h264/clean.264"
        original = fixture.read_bytes()
        tampered = bytearray(original)
        tampered[10] ^= 0xFF
        try:
            fixture.write_bytes(bytes(tampered))
            proc = self.run_harness(extra_env={"STUB_MODE": "pass"})
            self.assertNotEqual(proc.returncode, 0, "tampered fixture must fail the run")
            records = self.read_latest_log_records()
            summaries = self.summaries(records)
            self.assertEqual(len(summaries), 1)
            self.assertEqual(summaries[0]["verdict"], "fail")
            self.assertIn("clean_264_exit", summaries[0]["failures"])
        finally:
            fixture.write_bytes(original)

    def test_red_cargo_step_fails_closed(self) -> None:
        proc = self.run_harness(extra_env={"STUB_MODE": "failverdict"})
        self.assertNotEqual(proc.returncode, 0)
        records = self.read_latest_log_records()
        summaries = self.summaries(records)
        self.assertEqual(len(summaries), 1)
        self.assertEqual(summaries[0]["verdict"], "fail")
        self.assertTrue(any("media_fixture_h264_contract" in f for f in summaries[0]["failures"]))

    def test_missing_caplog_fails_closed(self) -> None:
        proc = self.run_harness(extra_env={"STUB_MODE": "nocaplog"})
        self.assertNotEqual(proc.returncode, 0)
        records = self.read_latest_log_records()
        summaries = self.summaries(records)
        self.assertEqual(len(summaries), 1)
        self.assertEqual(summaries[0]["verdict"], "fail")
        self.assertIn("no_caplog_emitted", summaries[0]["run_failures"])


if __name__ == "__main__":
    unittest.main()

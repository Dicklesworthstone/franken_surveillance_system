#!/usr/bin/env python3
"""Tests for scripts/e2e/cap_ingest_mjpeg.sh on the real scripts/e2e/lib.sh, with a stubbed rch.

The only rch on PATH is the stub below, and a cargo tripwire fails any test that reaches local
cargo. Every scratch path lives under the repo's (git-ignored) target/ dir, and the TMPDIR handed to
the harness must stay empty.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/e2e/cap_ingest_mjpeg.sh"
VALIDATOR = ROOT / "scripts/e2e/validate_log.py"
SCRATCH_BASE = ROOT / "target" / "test-e2e-cap-ingest-mjpeg"
TARGET = "mjpeg_split_contract"
REPRO = "scripts/e2e/cap_ingest_mjpeg.sh"
RCH_ARGV = f"RCH_REQUIRE_REMOTE=1 ARGS=exec -- cargo test -p fss-reference --test {TARGET} --locked --offline -- --nocapture"


def cap(payload: dict) -> str:
    """One shell-quoted CAPLOG JSON payload (compact, no single quotes inside)."""
    return "'" + json.dumps(payload, separators=(",", ":")) + "'"


def make_executable(path: Path) -> None:
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


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
        self.tripwire = self.tmp_path / "cargo_tripwire.txt"

        cap_a = cap({"step": "a", "verdict": "pass", "exit": 0, "duration_ms": 1, "expected": {}, "observed": {}})
        cap_b = cap({"step": "b", "verdict": "pass", "exit": 0, "duration_ms": 2, "expected": {}, "observed": {}})
        cap_skip = cap({"step": "b", "verdict": "skip", "exit": 0, "duration_ms": 1, "expected": {"m": 1}, "observed": {"r": "skip"}})
        cap_skip_c = cap({"step": "c", "verdict": "skip", "exit": 0, "duration_ms": 1, "expected": {"m": 1}, "observed": {"r": "skip"}})
        cap_fail = cap({"step": "a", "verdict": "fail"})
        cap_bad = "'" + '{"step":"a", broken json' + "'"
        cap_noverdict = cap({"step": "a"})
        cap_nostep = cap({"verdict": "pass"})
        stub_content = f"""#!/usr/bin/env bash
# STUB rch: never runs real rch, cargo or the network.
echo "RCH_REQUIRE_REMOTE=${{RCH_REQUIRE_REMOTE:-unset}} ARGS=$*" >> \"{self.calls_file}\"
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
        stub_rch = self.bin_dir / "rch"
        stub_rch.write_text(stub_content, encoding="utf-8")
        make_executable(stub_rch)
        tripwire = self.bin_dir / "cargo"
        tripwire.write_text(f"#!/usr/bin/env bash\necho \"$*\" >> \"{self.tripwire}\"\nexit 99\n", encoding="utf-8")
        make_executable(tripwire)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def run_harness(self, args: list[str] | None = None, mode: str = "pass",
                    extra_env: dict[str, str] | None = None, script: Path = SCRIPT) -> subprocess.CompletedProcess:
        # A minimal environment: secret-named host variables would otherwise be redacted from records.
        env = {
            "PATH": f"{self.bin_dir}:{os.environ.get('PATH', '')}",
            "HOME": os.environ.get("HOME", "/nonexistent"),
            "LANG": "C.UTF-8",
            "FSS_E2E_LOG_DIR": str(self.log_dir),
            "TMPDIR": str(self.tmpdir_env),
            "STUB_MODE": mode,
        }
        if extra_env:
            env.update(extra_env)
        # Stub-rch-only rule: the rch the harness will resolve is the stub, and cargo is the tripwire.
        self.assertEqual(shutil.which("rch", path=env["PATH"]), str(self.bin_dir / "rch"))
        self.assertEqual(shutil.which("cargo", path=env["PATH"]), str(self.bin_dir / "cargo"))
        proc = subprocess.run(["bash", str(script), *(args or [])], cwd=str(ROOT), env=env,
                              capture_output=True, text=True, timeout=300)
        self.assertEqual(list(self.tmpdir_env.iterdir()), [], "the harness wrote into TMPDIR")
        self.assertFalse(self.tripwire.exists(), "local cargo was called")
        return proc

    def calls(self) -> list[str]:
        if not self.calls_file.exists():
            return []
        return [c for c in self.calls_file.read_text(encoding="utf-8").splitlines() if c.strip()]

    def latest_log(self) -> Path:
        suite_dir = self.log_dir / "ingest_mjpeg"
        self.assertTrue(suite_dir.is_dir(), f"Suite log directory {suite_dir} does not exist")
        log_files = sorted(suite_dir.glob("run_*.log"))
        self.assertTrue(len(log_files) > 0, "No log files found")
        return log_files[-1]

    def read_latest_log_records(self) -> list[dict]:
        with open(self.latest_log(), "r", encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]

    def validator_rc(self) -> subprocess.CompletedProcess:
        return subprocess.run(["python3", str(VALIDATOR), str(self.latest_log())], capture_output=True, text=True)

    def assert_valid_log(self) -> None:
        v = self.validator_rc()
        self.assertEqual(v.returncode, 0, v.stderr)

    def step_ids(self, records: list[dict]) -> list[str]:
        return [r["step"] for r in records[1:-1]]

    def record(self, records: list[dict], step: str) -> dict:
        found = [r for r in records if r.get("step") == step]
        self.assertEqual(len(found), 1, f"expected one record for {step!r}")
        return found[0]

    def assert_fail_closed(self, proc: subprocess.CompletedProcess, failures: list[str]) -> list[dict]:
        """Exit 1, one summary with verdict fail and exactly these failures, and a valid log."""
        self.assertEqual(proc.returncode, 1, f"expected exit 1: {proc.stderr}")
        records = self.read_latest_log_records()
        summaries = [r for r in records if r.get("step") == "summary"]
        self.assertEqual(len(summaries), 1)
        self.assertEqual(records[-1]["verdict"], "fail")
        self.assertEqual(records[-1]["failures"], failures)
        self.assertEqual(records[-1]["repro"], f"{REPRO} --only {TARGET}")
        self.assertIn(f"E2E Repro (from {ROOT}): {REPRO} --only {TARGET}", proc.stdout)
        self.assert_valid_log()
        return records

    def test_pass_summary_and_locked_offline(self) -> None:
        proc = self.run_harness(mode="pass")
        self.assertEqual(proc.returncode, 0, f"Expected exit 0, got {proc.returncode}: {proc.stderr}")
        self.assertIn(f"E2E Log: {self.latest_log()}", proc.stdout)

        records = self.read_latest_log_records()
        self.assertEqual(len(records), 4)
        self.assertEqual(records[0]["step"], "env")
        self.assertEqual(records[0]["bead"], "fss-2h5zq.22")
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
        self.assertEqual(summary["repro"], REPRO)
        self.assert_valid_log()

        # Exactly one remote cargo invocation, with --locked --offline and RCH_REQUIRE_REMOTE=1.
        self.assertEqual(self.calls(), [RCH_ARGV])

    def test_pass_with_skip(self) -> None:
        proc = self.run_harness(mode="pass_with_skip")
        self.assertEqual(proc.returncode, 0, f"Expected exit 0: {proc.stderr}")
        records = self.read_latest_log_records()
        self.assertEqual(self.record(records, "b")["verdict"], "skip")
        summary = records[-1]
        self.assertEqual(summary["verdict"], "pass")
        self.assertEqual(summary["steps"], 2)
        self.assertEqual(summary["failures"], [])
        self.assertEqual(summary["skipped"], [{"step": "b", "reason": json.dumps({"r": "skip"})}])
        self.assert_valid_log()

    def test_only_selects_caplog_steps_by_cargo_target(self) -> None:
        proc = self.run_harness(args=["--only", TARGET], mode="pass")
        self.assertEqual(proc.returncode, 0, f"Expected exit 0: {proc.stderr}")
        self.assertEqual(self.calls(), [RCH_ARGV])
        records = self.read_latest_log_records()
        self.assertEqual(self.step_ids(records), ["a", "b"])
        self.assertEqual(records[-1]["repro"], f"{REPRO} --only {TARGET}")

    def test_only_equals_syntax(self) -> None:
        proc = self.run_harness(args=[f"--only={TARGET}"], mode="pass")
        self.assertEqual(proc.returncode, 0, f"Expected exit 0: {proc.stderr}")
        self.assertEqual(self.calls(), [RCH_ARGV])
        self.assertEqual(self.read_latest_log_records()[-1]["repro"], f"{REPRO} --only {TARGET}")

    def test_only_unknown_step_fails_closed(self) -> None:
        # A CAPLOG step name is not a selector: nothing runs, and an empty run is a failure.
        proc = self.run_harness(args=["--only", "step_custom"], mode="pass")
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertEqual(self.calls(), [])
        self.assertIn("no step matched --only 'step_custom'", proc.stderr)
        records = self.read_latest_log_records()
        self.assertEqual(records[-1]["verdict"], "fail")
        self.assertEqual(records[-1]["steps"], 0)
        self.assertEqual([r for r in records if r.get("verdict") == "pass"], [])

    def test_list_names_the_cargo_target(self) -> None:
        proc = self.run_harness(args=["--list"], mode="pass")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.split(), [TARGET])
        self.assertEqual(self.calls(), [])
        self.assertFalse((self.log_dir / "ingest_mjpeg").exists())

    def test_badjson_fails_and_populates_failures(self) -> None:
        proc = self.run_harness(mode="badjson")
        records = self.assert_fail_closed(proc, [TARGET])
        # A malformed CAPLOG stream is not trusted: no record of it survives, only the target's failure.
        self.assertEqual(self.step_ids(records), [TARGET])
        self.assertEqual(self.record(records, TARGET)["observed"], "malformed CAPLOG line observed: invalid JSON")

    def test_failverdict_populates_failures(self) -> None:
        proc = self.run_harness(mode="failverdict")
        records = self.assert_fail_closed(proc, ["a"])
        self.assertEqual(self.record(records, "a")["verdict"], "fail")
        self.assertEqual(self.record(records, "a")["exit"], 1)

    def test_missing_verdict_fails(self) -> None:
        proc = self.run_harness(mode="noverdict")
        records = self.assert_fail_closed(proc, [TARGET])
        self.assertEqual(self.record(records, TARGET)["observed"],
                         "malformed CAPLOG line observed: not an object with step and verdict")

    def test_missing_step_fails(self) -> None:
        proc = self.run_harness(mode="nostep")
        records = self.assert_fail_closed(proc, [TARGET])
        self.assertEqual(self.record(records, TARGET)["observed"],
                         "malformed CAPLOG line observed: not an object with step and verdict")

    def assert_all_skipped_fails(self, proc: subprocess.CompletedProcess, skipped: list[str]) -> None:
        # Skips never count as passes: an all-skipped run gets a FAIL summary and exit 1, and its
        # log is rejected by the validator (ERR_ALL_STEPS_SKIPPED).
        self.assertEqual(proc.returncode, 1, "Expected exit 1 when all steps are skipped")
        records = self.read_latest_log_records()
        self.assertEqual(records[-1]["step"], "summary")
        self.assertEqual(records[-1]["verdict"], "fail")
        self.assertEqual([r for r in records if r.get("step") == "summary" and r.get("verdict") == "pass"], [])
        self.assertEqual([s["step"] for s in records[-1]["skipped"]], skipped)
        self.assertIn("ERR_ALL_STEPS_SKIPPED", proc.stderr)
        v = self.validator_rc()
        self.assertNotEqual(v.returncode, 0)
        self.assertIn("ERR_ALL_STEPS_SKIPPED", v.stderr)

    def test_all_steps_skipped_fails(self) -> None:
        self.assert_all_skipped_fails(self.run_harness(mode="all_skip"), ["b"])

    def test_all_two_steps_skipped_fails(self) -> None:
        self.assert_all_skipped_fails(self.run_harness(mode="all_skip2"), ["b", "c"])

    def test_duplicate_step_fails(self) -> None:
        proc = self.run_harness(mode="duplicate_step")
        records = self.assert_fail_closed(proc, [TARGET])
        self.assertEqual(self.record(records, TARGET)["observed"],
                         "malformed CAPLOG line observed: missing, duplicate or reserved step")

    def test_nocaplog_fails(self) -> None:
        proc = self.run_harness(mode="nocaplog")
        records = self.assert_fail_closed(proc, [TARGET])
        self.assertEqual(self.step_ids(records), [TARGET])
        self.assertEqual(self.record(records, TARGET)["observed"], "no CAPLOG line observed")

    def test_cargo_exit_nonzero_fails(self) -> None:
        proc = self.run_harness(mode="e101")
        records = self.assert_fail_closed(proc, [TARGET])
        self.assertEqual(self.step_ids(records), ["a", TARGET])
        self.assertEqual(self.record(records, "a")["verdict"], "pass")
        self.assertEqual(self.record(records, TARGET)["exit"], 101)
        self.assertEqual(self.record(records, TARGET)["observed"], "cargo test failed (exit 101)")

    def test_cargo_exit_nonzero_with_failed_step(self) -> None:
        proc = self.run_harness(mode="e101_fail")
        records = self.assert_fail_closed(proc, ["a", TARGET])
        self.assertEqual(self.record(records, TARGET)["exit"], 101)

    def test_e103_retries(self) -> None:
        proc = self.run_harness(mode="e103")
        records = self.assert_fail_closed(proc, [TARGET])
        self.assertEqual(len(self.calls()), 4, f"Expected 4 attempts (1 initial + 3 retries), got {len(self.calls())}")
        self.assertEqual(self.record(records, TARGET)["exit"], 103)
        self.assertEqual(self.record(records, TARGET)["observed"],
                         "cargo test failed (exit 103); no CAPLOG line observed")

    def test_stdout_capture_lives_under_log_dir(self) -> None:
        proc = self.run_harness(mode="pass")
        self.assertEqual(proc.returncode, 0, proc.stderr)

        suite_dir = (self.log_dir / "ingest_mjpeg").resolve()
        paths = [p for p in self.fd_file.read_text(encoding="utf-8").splitlines() if p.strip()]
        self.assertEqual(len(paths), 1, paths)
        capture = Path(paths[0])
        self.assertEqual(capture.parent, suite_dir, f"capture file {capture} not under {suite_dir}")
        self.assertTrue(capture.name.startswith("cargo_test_stdout_"), capture.name)
        # The capture file is removed; only the run log remains. TMPDIR is never touched.
        self.assertFalse(capture.exists(), f"capture file {capture} left behind")
        self.assertEqual(sorted(p.name for p in suite_dir.iterdir()), ["run_0001.log"])
        self.assertEqual(list(self.tmpdir_env.iterdir()), [])

    def test_env_dynamic_dirty_and_bins(self) -> None:
        custom_bin_dir = self.tmp_path / "custom_bins"
        custom_bin_dir.mkdir()
        dummy_bin = custom_bin_dir / "fss-dummy"
        dummy_bin.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        make_executable(dummy_bin)

        proc = self.run_harness(mode="pass", extra_env={"FSS_BIN_DIR": str(custom_bin_dir)})
        self.assertEqual(proc.returncode, 0, proc.stderr)

        env_rec = self.read_latest_log_records()[0]
        self.assertIsInstance(env_rec["dirty"], bool)
        self.assertEqual(env_rec["bins"], [{
            "name": "fss-dummy",
            "path": str(dummy_bin),
            "sha256": hashlib.sha256(dummy_bin.read_bytes()).hexdigest(),
        }])

    def test_per_step_ts(self) -> None:
        proc = self.run_harness(mode="pass")
        self.assertEqual(proc.returncode, 0, proc.stderr)

        records = self.read_latest_log_records()
        iso_pattern = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        for rec in records[1:-1]:
            self.assertIn("ts", rec)
            self.assertTrue(iso_pattern.match(rec["ts"]), f"Invalid ts format: {rec.get('ts')}")

    def test_fails_closed_without_lib(self) -> None:
        tree = self.tmp_path / "nolib"
        (tree / "scripts/e2e").mkdir(parents=True)
        lone = tree / "scripts/e2e/cap_ingest_mjpeg.sh"
        shutil.copy2(SCRIPT, lone)
        proc = self.run_harness(mode="pass", script=lone)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("lib.sh (the fss-2h5zq.1 harness) is required", proc.stderr)
        self.assertEqual(self.calls(), [])
        self.assertEqual(list(self.log_dir.iterdir()), [])


if __name__ == "__main__":
    unittest.main()

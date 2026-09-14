#!/usr/bin/env python3
"""Tests for scripts/e2e/cap_ingest_annexb.sh on the real scripts/e2e/lib.sh, with a stubbed rch.

The Annex-B harness (fss-qwp8y) runs one cargo target through lib.sh and then a roster/comparison
gate: a run fails closed if any of the 19 required roster steps is missing or a pass record's
expected != observed. The only rch on PATH is the stub below; a cargo tripwire fails any test that
reaches local cargo. Every scratch path lives under the repo's (git-ignored) target/ dir, and the
TMPDIR handed to the harness must stay empty.
"""
from __future__ import annotations

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
SCRIPT = ROOT / "scripts/e2e/cap_ingest_annexb.sh"
VALIDATOR = ROOT / "scripts/e2e/validate_log.py"
SCRATCH_BASE = ROOT / "target" / "test-e2e-cap-ingest-annexb"
TARGET = "annexb_split_contract"
REPRO = "scripts/e2e/cap_ingest_annexb.sh"
GATE = "annexb_roster_gate"
ROSTER = [
    "manifest_clean_h264", "synthetic_standard", "synthetic_multi_slice", "padding_and_leading_zeros",
    "no_aud_grouping", "empty_and_no_start_code", "zero_length_and_truncated", "forbidden_zero_bit",
    "leading_garbage_limits", "emulation_prevention", "slice_header_syntax", "undecodable_flag",
    "unsupported_extensions", "limits_boundaries", "cooperative_cancellation", "mutant_kill_table",
    "mutation_gauntlet_10k", "loop_and_mid_push_limits", "validation_ceiling_bypass",
]


def make_executable(path: Path) -> None:
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


class TestE2eCapIngestAnnexb(unittest.TestCase):
    def setUp(self) -> None:
        SCRATCH_BASE.mkdir(parents=True, exist_ok=True)
        self.tmp_dir = tempfile.TemporaryDirectory(dir=SCRATCH_BASE, prefix="run-")
        self.tmp_path = Path(self.tmp_dir.name)
        self.bin_dir = self.tmp_path / "bin"
        self.bin_dir.mkdir()
        self.log_dir = self.tmp_path / "logs"
        self.log_dir.mkdir()
        self.tmpdir_env = self.tmp_path / "tmpdir"
        self.tmpdir_env.mkdir()
        self.calls_file = self.tmp_path / "stub_calls.txt"
        self.tripwire = self.tmp_path / "cargo_tripwire.txt"

        roster_bash = " ".join(ROSTER)
        stub_content = f"""#!/usr/bin/env bash
# STUB rch: never runs real rch, cargo or the network.
echo "RCH_REQUIRE_REMOTE=${{RCH_REQUIRE_REMOTE:-unset}} ARGS=$*" >> "{self.calls_file}"
ROSTER=({roster_bash})
emit_pass() {{ echo "CAPLOG {{\\"step\\":\\"$1\\",\\"verdict\\":\\"pass\\",\\"exit\\":0,\\"duration_ms\\":1,\\"expected\\":{{}},\\"observed\\":{{}}}}"; }}
case "${{STUB_MODE:-pass}}" in
  pass)
    printf "\\033[32mrunning ${{#ROSTER[@]}} tests\\033[0m\\n"
    for s in "${{ROSTER[@]}}"; do emit_pass "$s"; done
    printf "test result: ok\\n"
    exit 0
    ;;
  roster_missing)
    for s in "${{ROSTER[@]:0:18}}"; do emit_pass "$s"; done
    exit 0
    ;;
  mismatch)
    for s in "${{ROSTER[@]:0:18}}"; do emit_pass "$s"; done
    echo "CAPLOG {{\\"step\\":\\"validation_ceiling_bypass\\",\\"verdict\\":\\"pass\\",\\"exit\\":0,\\"duration_ms\\":1,\\"expected\\":{{\\"n\\":1}},\\"observed\\":{{\\"n\\":2}}}}"
    exit 0
    ;;
  malformed)
    echo 'CAPLOG {{"step":"synthetic_standard", broken json'
    exit 0
    ;;
  duplicate)
    emit_pass "synthetic_standard"
    emit_pass "synthetic_standard"
    exit 0
    ;;
  nocaplog)
    echo "test result: ok. 0 passed"
    exit 0
    ;;
  e101)
    emit_pass "synthetic_standard"
    exit 101
    ;;
  e103)
    echo "fleet saturated" >&2
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

    def run_harness(self, args=None, mode="pass", extra_env=None):
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
        self.assertEqual(shutil.which("rch", path=env["PATH"]), str(self.bin_dir / "rch"))
        self.assertEqual(shutil.which("cargo", path=env["PATH"]), str(self.bin_dir / "cargo"))
        proc = subprocess.run(["bash", str(SCRIPT), *(args or [])], cwd=str(ROOT), env=env,
                              capture_output=True, text=True, timeout=300)
        self.assertEqual(list(self.tmpdir_env.iterdir()), [], "the harness wrote into TMPDIR")
        self.assertFalse(self.tripwire.exists(), "local cargo was called")
        return proc

    def calls(self):
        if not self.calls_file.exists():
            return []
        return [c for c in self.calls_file.read_text(encoding="utf-8").splitlines() if c.strip()]

    def latest_log(self):
        suite_dir = self.log_dir / "ingest_annexb"
        self.assertTrue(suite_dir.is_dir(), f"Suite log directory {suite_dir} does not exist")
        log_files = sorted(suite_dir.glob("run_*.log"))
        self.assertTrue(len(log_files) > 0, "No log files found")
        return log_files[-1]

    def records(self):
        with open(self.latest_log(), "r", encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]

    def summary(self):
        return self.records()[-1]

    def step_ids(self):
        return [r["step"] for r in self.records()[1:-1]]

    def gate_stderr(self):
        for r in self.records():
            if r.get("step") == GATE:
                return r.get("stderr_excerpt", "")
        return ""

    def assert_valid_log(self):
        v = subprocess.run(["python3", str(VALIDATOR), str(self.latest_log())], capture_output=True, text=True)
        self.assertEqual(v.returncode, 0, v.stderr)

    def test_pass_full_roster(self):
        proc = self.run_harness(mode="pass")
        self.assertEqual(proc.returncode, 0, f"expected exit 0: {proc.stderr}")
        self.assert_valid_log()
        summary = self.summary()
        self.assertEqual(summary["verdict"], "pass")
        self.assertEqual(summary["failures"], [])
        # 19 roster steps plus the gate step.
        self.assertEqual(summary["steps"], len(ROSTER) + 1)
        for s in ROSTER:
            self.assertIn(s, self.step_ids())
        self.assertIn(GATE, self.step_ids())
        self.assertIn("pass summary:", proc.stdout)
        self.assertEqual(self.calls(), [f"RCH_REQUIRE_REMOTE=1 ARGS=exec -- cargo test -p fss-reference --test {TARGET} --locked --offline -- --nocapture"])

    def test_only_target_passes(self):
        # --only annexb_split_contract selects the cargo target; the gate step is not selected, so
        # the roster is not re-enforced on a scoped rerun, but the target's own records still land.
        proc = self.run_harness(args=["--only", TARGET], mode="pass")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assert_valid_log()
        self.assertEqual(self.summary()["repro"], f"{REPRO} --only {TARGET}")
        self.assertNotIn(GATE, self.step_ids())

    def _assert_target_fail(self, mode):
        # Target-failure modes run scoped to the cargo target; the summary blames only the target.
        proc = self.run_harness(args=["--only", TARGET], mode=mode)
        self.assertEqual(proc.returncode, 1, f"{mode}: expected exit 1: {proc.stdout}\n{proc.stderr}")
        self.assert_valid_log()
        summary = self.summary()
        self.assertEqual(summary["verdict"], "fail")
        self.assertEqual(summary["failures"], [TARGET], f"{mode}: {summary['failures']}")
        return proc

    def test_malformed_caplog_fails(self):
        self._assert_target_fail("malformed")

    def test_duplicate_step_fails(self):
        self._assert_target_fail("duplicate")

    def test_cargo_exit_nonzero_fails(self):
        self._assert_target_fail("e101")

    def test_no_caplog_fails(self):
        self._assert_target_fail("nocaplog")

    def test_e103_retry_bounded(self):
        proc = self.run_harness(args=["--only", TARGET], mode="e103")
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertEqual(len(self.calls()), 4, f"expected 4 attempts, got {len(self.calls())}")
        self.assert_valid_log()
        self.assertEqual(self.summary()["failures"], [TARGET])

    def test_missing_roster_step_fails(self):
        # A full run whose target skips a roster step is caught by the gate (not silently passed).
        proc = self.run_harness(mode="roster_missing")
        self.assertEqual(proc.returncode, 1, f"expected exit 1: {proc.stdout}\n{proc.stderr}")
        self.assert_valid_log()
        summary = self.summary()
        self.assertEqual(summary["verdict"], "fail")
        self.assertIn(GATE, summary["failures"])
        gate_err = self.gate_stderr()
        self.assertIn("missing roster steps", gate_err)
        self.assertIn("validation_ceiling_bypass", gate_err)

    def test_expected_observed_mismatch_fails(self):
        # A pass record whose expected != observed is caught by the gate (the B8 check never vanishes).
        proc = self.run_harness(mode="mismatch")
        self.assertEqual(proc.returncode, 1, f"expected exit 1: {proc.stdout}\n{proc.stderr}")
        self.assert_valid_log()
        summary = self.summary()
        self.assertEqual(summary["verdict"], "fail")
        self.assertIn(GATE, summary["failures"])
        self.assertIn("expected != observed", self.gate_stderr())

    def test_fails_closed_without_lib(self):
        tree = self.tmp_path / "nolib"
        (tree / "scripts/e2e").mkdir(parents=True)
        lone = tree / "scripts/e2e/cap_ingest_annexb.sh"
        shutil.copy2(SCRIPT, lone)
        env = {
            "PATH": f"{self.bin_dir}:{os.environ.get('PATH', '')}",
            "HOME": os.environ.get("HOME", "/nonexistent"),
            "FSS_E2E_LOG_DIR": str(self.log_dir),
            "TMPDIR": str(self.tmpdir_env),
            "STUB_MODE": "pass",
        }
        proc = subprocess.run(["bash", str(lone)], cwd=str(ROOT), env=env, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("lib.sh (the fss-2h5zq.1 harness) is required", proc.stderr)
        self.assertEqual(self.calls(), [])

    def test_per_step_ts(self):
        proc = self.run_harness(mode="pass")
        self.assertEqual(proc.returncode, 0)
        iso_pattern = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        for rec in self.records()[1:-1]:
            self.assertTrue(iso_pattern.match(rec["ts"]), rec.get("ts"))


if __name__ == "__main__":
    unittest.main()

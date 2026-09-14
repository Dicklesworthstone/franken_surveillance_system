#!/usr/bin/env python3
"""Tests for scripts/e2e/cap_inspect.sh on the shared scripts/e2e/lib.sh harness, with a stub rch.

Every scratch path lives under the repo's git-ignored target/ directory; nothing is written to the
system temp directory or the ambient TMPDIR (the harness gets a sentinel TMPDIR that must stay
empty).
"""
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
SCRIPT = ROOT / "scripts/e2e/cap_inspect.sh"
SCRATCH_BASE = ROOT / "target" / "test-e2e-cap-inspect"

# (crate, target) in the order the script runs them.
TARGETS = [
    ("fss-object", "spool_inspect_contract"),
    ("fss-publication", "local_inspect_contract"),
    ("fss-ledger", "durable_inspect_contract"),
    ("fss-reference", "effect_journal_inspect_contract"),
]
TARGET_NAMES = [target for _, target in TARGETS]

# The stub prints CAPLOG records named after the --test target it was asked to run.
STUB = r"""#!/usr/bin/env bash
echo "$@" >> "@CALLS@"
T=unknown; prev=""
for arg in "$@"; do
  if [[ "$prev" == "--test" ]]; then T="$arg"; fi
  prev="$arg"
done
pass_line() {
  printf 'CAPLOG {"step":"%s_%s","verdict":"pass","exit":0,"duration_ms":1,"expected":{"count":%s},"observed":{"count":%s}}\n' "$T" "$1" "$2" "$2"
}
skip_line() {
  printf 'CAPLOG {"step":"%s_%s","verdict":"skip","exit":1,"duration_ms":1,"expected":{},"observed":{"skip_reason":"privileged: create_new succeeded"}}\n' "$T" "$1"
}
case "${STUB_MODE:-pass}" in
  pass)
    pass_line a 1; pass_line b 2
    echo "test result: ok. 2 passed; 0 failed"
    exit 0 ;;
  pass_with_skip)
    pass_line a 1; skip_line s
    echo "test result: ok. 2 passed; 0 failed"
    exit 0 ;;
  all_skip)
    skip_line s
    exit 0 ;;
  failverdict)
    printf 'CAPLOG {"step":"%s_f","verdict":"fail","exit":1,"duration_ms":1,"expected":{"count":1},"observed":{"count":2}}\n' "$T"
    exit 0 ;;
  e101)
    pass_line a 1
    exit 101 ;;
  nocaplog)
    echo "test result: ok. 0 passed; 0 failed"
    exit 0 ;;
  retry103)
    count=0
    if [[ -f "@COUNTER@" ]]; then count=$(cat "@COUNTER@"); fi
    count=$((count + 1))
    echo "$count" > "@COUNTER@"
    if (( count == 1 )); then exit 103; fi
    pass_line a 1
    exit 0 ;;
esac
"""


class TestE2eCapInspect(unittest.TestCase):
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
        counter_file = self.tmp_path / "stub_counter.txt"
        stub = self.bin_dir / "rch"
        stub.write_text(
            STUB.replace("@CALLS@", str(self.calls_file)).replace("@COUNTER@", str(counter_file)),
            encoding="utf-8",
        )
        stub.chmod(stub.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def run_harness(self, args: list[str] | None = None, mode: str | None = None) -> subprocess.CompletedProcess:
        env = dict(os.environ)
        env["PATH"] = f"{self.bin_dir}:{env.get('PATH', '')}"
        env["FSS_E2E_LOG_DIR"] = str(self.log_dir)
        env["RCH_REQUIRE_REMOTE"] = "1"
        env["TMPDIR"] = str(self.tmpdir_env)
        if mode is not None:
            env["STUB_MODE"] = mode
        proc = subprocess.run(
            ["bash", str(SCRIPT), *(args or [])],
            cwd=str(ROOT),
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(sorted(os.listdir(self.tmpdir_env)), [], "harness wrote into TMPDIR")
        return proc

    def records(self) -> list[dict]:
        suite_dir = self.log_dir / "cap_inspect"
        log_files = sorted(suite_dir.glob("run_*.log"))
        self.assertEqual(len(log_files), 1, f"expected exactly one run log in {suite_dir}")
        return [json.loads(line) for line in log_files[0].read_text(encoding="utf-8").splitlines() if line.strip()]

    def calls(self) -> list[str]:
        if not self.calls_file.exists():
            return []
        return [line for line in self.calls_file.read_text(encoding="utf-8").splitlines() if line.strip()]

    def expected_calls(self) -> list[str]:
        return [
            f"exec -- cargo test -p {crate} --test {target} --locked --offline -- --nocapture"
            for crate, target in TARGETS
        ]

    def step_records(self, records: list[dict]) -> list[tuple[str, str]]:
        return [(r["step"], r["verdict"]) for r in records[1:-1]]

    def test_script_relies_on_lib_without_overrides(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        code = [line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
        self.assertIn('source "${SCRIPT_DIR}/lib.sh"', code)
        for forbidden in (r"\beval\b", r"\bsed\b", r"^\s*(function\s+)?_?e2e_[a-z_]*\s*\(\)", r"/tmp\b"):
            offenders = [line for line in code if re.search(forbidden, line)]
            self.assertEqual(offenders, [], f"{forbidden!r} in cap_inspect.sh")
        self.assertEqual(
            [line.strip() for line in code if line.strip().startswith("e2e_cargo_test")],
            [f'e2e_cargo_test "{crate}" "{target}"' for crate, target in TARGETS],
        )

    def test_list_flag(self) -> None:
        proc = self.run_harness(args=["--list"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.split(), TARGET_NAMES)
        self.assertEqual(self.calls(), [])

    def test_pass_summary(self) -> None:
        proc = self.run_harness(mode="pass")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.calls(), self.expected_calls())

        records = self.records()
        self.assertEqual(len(records), 1 + 2 * len(TARGETS) + 1)
        self.assertEqual(records[0]["step"], "env")
        self.assertEqual(
            self.step_records(records),
            [(f"{target}_{suffix}", "pass") for target in TARGET_NAMES for suffix in ("a", "b")],
        )
        # Expected and observed are carried through from the CAPLOG record, not rewritten.
        self.assertEqual(records[1]["expected"], {"count": 1})
        self.assertEqual(records[2]["observed"], {"count": 2})
        summary = records[-1]
        self.assertEqual(summary["step"], "summary")
        self.assertEqual(summary["verdict"], "pass")
        # lib.sh counts one step per CAPLOG record.
        self.assertEqual(summary["steps"], 2 * len(TARGETS))
        self.assertEqual(summary["failures"], [])
        # lib.sh records the script path exactly as it was invoked.
        self.assertEqual(summary["repro"], str(SCRIPT))
        self.assertIn(f"E2E Log: {self.log_dir / 'cap_inspect' / 'run_0001.log'}", proc.stdout)

    def test_skip_never_passes_and_keeps_its_reason(self) -> None:
        # A skip record is never relabelled a pass: the step keeps verdict "skip" with the reason
        # the test observed, and the run fails log validation even when every other step passed.
        proc = self.run_harness(mode="pass_with_skip")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("ERR_SUMMARY_INCONSISTENCY", proc.stdout + proc.stderr)
        records = self.records()
        self.assertEqual(len(records), 1 + 2 * len(TARGETS) + 1)
        self.assertEqual(
            self.step_records(records),
            [(f"{target}_{suffix}", verdict) for target in TARGET_NAMES for suffix, verdict in (("a", "pass"), ("s", "skip"))],
        )
        for record in records[1:-1]:
            if record["verdict"] == "skip":
                self.assertEqual(record["observed"], {"skip_reason": "privileged: create_new succeeded"})
        self.assertEqual(records[-1]["verdict"], "pass")

    def test_all_skip_fails_closed(self) -> None:
        proc = self.run_harness(mode="all_skip")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("ERR_ALL_STEPS_SKIPPED", proc.stdout + proc.stderr)
        records = self.records()
        self.assertEqual(len(records), 1 + len(TARGETS) + 1)
        self.assertEqual(self.step_records(records), [(f"{target}_s", "skip") for target in TARGET_NAMES])

    def test_fail_verdict_fails(self) -> None:
        proc = self.run_harness(mode="failverdict")
        self.assertEqual(proc.returncode, 1)
        records = self.records()
        self.assertEqual(len(records), 1 + len(TARGETS) + 1)
        self.assertEqual(self.step_records(records), [(f"{target}_f", "fail") for target in TARGET_NAMES])
        summary = records[-1]
        self.assertEqual(summary["verdict"], "fail")
        self.assertEqual(summary["failures"], [f"{target}_f" for target in TARGET_NAMES])

    def test_cargo_exit_nonzero_fails(self) -> None:
        proc = self.run_harness(mode="e101")
        self.assertEqual(proc.returncode, 1)
        records = self.records()
        self.assertEqual(len(records), 1 + len(TARGETS) + 1)
        self.assertEqual(self.step_records(records), [(target, "fail") for target in TARGET_NAMES])
        for record in records[1:-1]:
            self.assertEqual(record["exit"], 101)
            self.assertEqual(record["observed"], "cargo test failed (exit 101)")
        self.assertEqual(records[-1]["failures"], TARGET_NAMES)

    def test_no_caplog_fails_closed(self) -> None:
        proc = self.run_harness(mode="nocaplog")
        self.assertEqual(proc.returncode, 1)
        records = self.records()
        self.assertEqual(len(records), 1 + len(TARGETS) + 1)
        self.assertEqual(self.step_records(records), [(target, "fail") for target in TARGET_NAMES])
        for record in records[1:-1]:
            self.assertEqual(record["observed"], "no CAPLOG line observed")
        self.assertEqual(records[-1]["verdict"], "fail")

    def test_e103_retry_success(self) -> None:
        proc = self.run_harness(mode="retry103")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        expected = self.expected_calls()
        self.assertEqual(self.calls(), [expected[0], *expected])
        records = self.records()
        self.assertEqual(len(records), 1 + len(TARGETS) + 1)
        self.assertEqual(self.step_records(records), [(f"{target}_a", "pass") for target in TARGET_NAMES])

    def test_only_flag_runs_the_named_target(self) -> None:
        proc = self.run_harness(args=["--only", "local_inspect_contract"], mode="pass")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        calls = self.calls()
        self.assertIn(self.expected_calls()[1], calls)
        records = self.records()
        # lib.sh decides which targets an --only pattern selects; the summary counts exactly the
        # CAPLOG records (two per stubbed target) of those targets.
        self.assertEqual(records[-1]["steps"], 2 * len(calls))
        self.assertEqual(len(records), 1 + 2 * len(calls) + 1)
        self.assertIn(("local_inspect_contract_a", "pass"), self.step_records(records))


if __name__ == "__main__":
    unittest.main()

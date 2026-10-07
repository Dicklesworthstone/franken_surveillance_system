#!/usr/bin/env python3
"""tests/test_e2e_lib_fail_closed.py

Planted negatives for the review findings on scripts/e2e/lib.sh (fss-2h5zq.1, rounds r1e/r1f):

* CAPLOG records arrive on stderr under real rch, so a FAIL record on stderr only, or a stdout
  pass beside a stderr fail, must fail the run, and a stderr-only pass (the real rch shape) must
  pass it.
* A FAIL record hidden behind a libtest prefix ("running N tests", "... ok", a tab, an escape
  sequence, a repeated marker, two records on one line) must fail the run.
* EXIT traps and e2e_on_exit hooks must not be able to force exit status 0, and a script that
  ends before e2e_summary fails.
* A subshell or background job calling e2e_summary must not write a second summary (C3).
* The value after a dangling "Password:" prompt on the next line is redacted (I5e2).

Every case drives a generated suite script through a stub rch on PATH; nothing here runs real rch,
cargo or the network, and nothing is written outside target/test_sandboxes/.

FSS_E2E_LIB_UNDER_TEST may point at another copy of lib.sh (with validate_log.py beside it) to
show which of these cases an older harness let through.
"""

import json
import os
import re
import shutil
import stat
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts" / "e2e"))
from validate_log import validate_file  # noqa: E402

LIB = Path(os.environ.get("FSS_E2E_LIB_UNDER_TEST", REPO_ROOT / "scripts" / "e2e" / "lib.sh"))

PASS_A = '{"step": "alpha", "verdict": "pass", "expected": 1, "observed": 1}'
PASS_B = '{"step": "beta", "verdict": "pass"}'
FAIL_H = '{"step": "hidden_fail", "verdict": "fail", "expected": 1, "observed": 2}'

STUB_RCH = r"""#!/usr/bin/env bash
# Stub rch: replays canned stdout/stderr transcripts and exits with STUB_EXIT.
set -euo pipefail
if [[ -n "${STUB_RCH_LOG:-}" ]]; then
    echo "rch $*" >> "$STUB_RCH_LOG"
fi
if [[ -n "${STUB_STDOUT_FILE:-}" ]]; then cat "$STUB_STDOUT_FILE"; fi
if [[ -n "${STUB_STDERR_FILE:-}" ]]; then cat "$STUB_STDERR_FILE" >&2; fi
exit "${STUB_EXIT:-0}"
"""

# Shape of a real `RCH_REQUIRE_REMOTE=1 rch exec -- cargo test ... -- --nocapture` run: stdout is
# empty and everything, compiler progress (ANSI coloured), libtest lines and CAPLOG records, is
# forwarded on stderr.
REAL_RCH_STDERR = (
    "\x1b[1m\x1b[92m   Compiling\x1b[0m fss-reference v0.1.0 (/remote/fss/crates/fss-reference)\n"
    "\x1b[1m\x1b[92m    Finished\x1b[0m `test` profile [unoptimized + debuginfo] target(s) in 1m 40s\n"
    "\x1b[1m\x1b[92m     Running\x1b[0m tests/scalar_executor_contract.rs (target/debug/deps/x-1)\n"
    "\n"
    "running 2 tests\n"
    f"CAPLOG {PASS_A}\n"
    "test test_alpha ... ok\n"
    f"CAPLOG {PASS_B}\n"
    "test test_beta ... ok\n"
    "\n"
    "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.19s\n"
)


class E2eLibFailClosed(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = REPO_ROOT / "target" / "test_sandboxes" / f"e2e_lib_fail_closed_{os.getpid()}"
        cls.root.mkdir(parents=True, exist_ok=True)
        bin_dir = cls.root / "bin"
        bin_dir.mkdir(exist_ok=True)
        stub = bin_dir / "rch"
        stub.write_text(STUB_RCH, encoding="utf-8")
        stub.chmod(stub.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        cls.env = os.environ.copy()
        cls.env["PATH"] = f"{bin_dir}:{cls.env.get('PATH', '')}"
        for key in ("FSS_EXPECTED_ROSTER", "STUB_STDOUT_FILE", "STUB_STDERR_FILE", "STUB_EXIT"):
            cls.env.pop(key, None)
        if shutil.which("rch", path=cls.env["PATH"]) != str(stub):
            raise RuntimeError("HARD GUARD: rch does not resolve to the stub")
        cls.counter = 0

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root, ignore_errors=True)

    # ------------------------------------------------------------------ helpers

    def run_suite(self, body, stdout="", stderr="", stub_exit=0, extra_env=None):
        """Write and run a suite script; return (returncode, records, log_path, completed)."""
        type(self).counter += 1
        name = f"fc{type(self).counter:03d}"
        case_dir = self.root / name
        case_dir.mkdir(parents=True, exist_ok=True)
        out_file = case_dir / "stub_stdout.txt"
        err_file = case_dir / "stub_stderr.txt"
        out_file.write_text(stdout, encoding="utf-8")
        err_file.write_text(stderr, encoding="utf-8")
        script = case_dir / "run.sh"
        script.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            f'source "{LIB}"\n'
            f'e2e_init "{name}" "fss-2h5zq.1"\n'
            f"{body}\n",
            encoding="utf-8",
        )
        script.chmod(0o755)
        env = self.env.copy()
        env.update({
            "FSS_E2E_LOG_DIR": str(case_dir / "logs"),
            "STUB_STDOUT_FILE": str(out_file),
            "STUB_STDERR_FILE": str(err_file),
            "STUB_EXIT": str(stub_exit),
        })
        if extra_env:
            env.update(extra_env)
        res = subprocess.run(["bash", str(script)], cwd=str(case_dir), env=env,
                             capture_output=True, text=True, timeout=300)
        logs = sorted((case_dir / "logs" / name).glob("run_*.log"))
        self.assertTrue(logs, f"no run log written: {res.stdout}\n{res.stderr}")
        records = [json.loads(line) for line in logs[-1].read_text(encoding="utf-8").splitlines()]
        return res.returncode, records, logs[-1], res

    def summaries(self, records):
        return [r for r in records if r.get("step") == "summary"]

    def assert_fail_closed(self, rc, records, log, res, failed_step=None, run_failure=None):
        self.assertNotEqual(rc, 0, f"fail-open: exit 0\nstdout={res.stdout}\nstderr={res.stderr}")
        sums = self.summaries(records)
        self.assertEqual(len(sums), 1, f"expected exactly one summary, got {sums}")
        self.assertEqual(records[-1]["step"], "summary")
        self.assertEqual(sums[0]["verdict"], "fail", sums[0])
        if failed_step is not None:
            self.assertIn(failed_step, sums[0]["failures"], sums[0])
        if run_failure is not None:
            self.assertIn(run_failure, sums[0]["run_failures"], sums[0])
        validate_file(log)

    def assert_pass(self, rc, records, log, res, steps):
        self.assertEqual(rc, 0, f"stdout={res.stdout}\nstderr={res.stderr}")
        sums = self.summaries(records)
        self.assertEqual(len(sums), 1)
        self.assertEqual(sums[0]["verdict"], "pass", sums[0])
        passed = [r["step"] for r in records
                  if r.get("verdict") == "pass" and r.get("step") not in ("env", "summary")]
        self.assertEqual(passed, steps)
        validate_file(log)

    # ------------------------------------------------------------------ CAPLOG streams

    def test_real_rch_shape_stderr_only_pass_is_green(self):
        """Positive control: the real rch transcript (records on stderr only) passes."""
        rc, recs, log, res = self.run_suite('e2e_cargo_test "fss-reference" "contract"\ne2e_summary',
                                            stderr=REAL_RCH_STDERR)
        self.assert_pass(rc, recs, log, res, ["alpha", "beta"])

    def test_fail_on_stderr_only_fails_closed(self):
        rc, recs, log, res = self.run_suite('e2e_cargo_test "fss-reference" "contract"\ne2e_summary',
                                            stderr=f"running 1 test\nCAPLOG {FAIL_H}\n")
        self.assert_fail_closed(rc, recs, log, res, failed_step="hidden_fail")

    def test_stdout_pass_plus_stderr_fail_fails_closed(self):
        rc, recs, log, res = self.run_suite('e2e_cargo_test "fss-reference" "contract"\ne2e_summary',
                                            stdout=f"running 1 test\nCAPLOG {PASS_A}\n",
                                            stderr=f"CAPLOG {FAIL_H}\n")
        self.assert_fail_closed(rc, recs, log, res, failed_step="hidden_fail")

    def test_malformed_caplog_on_stderr_fails_closed(self):
        rc, recs, log, res = self.run_suite('e2e_cargo_test "fss-reference" "contract"\ne2e_summary',
                                            stdout=f"CAPLOG {PASS_A}\n",
                                            stderr='CAPLOG {"step": "cut", "verdict": "fa\n')
        self.assert_fail_closed(rc, recs, log, res, failed_step="malformed_caplog")

    def test_fail_hidden_behind_prefixes_fails_closed(self):
        """Each prefix shape hides a FAIL record next to a genuine stdout pass."""
        hidden = {
            "running_n_tests_glued": f"running 2 testsCAPLOG {FAIL_H}\n",
            "libtest_ok_glued": f"test t_hidden ... okCAPLOG {FAIL_H}\n",
            "tab_after_running": f"running 2 tests\tCAPLOG {FAIL_H}\n",
            "word_glued": f"xCAPLOG {FAIL_H}\n",
            "escape_split_marker": f"CAP\x1b(BLOG {FAIL_H}\n",
            "osc_title_prefix": f"\x1b]0;cargo\x07CAPLOG {FAIL_H}\n",
            "carriage_return_progress": f"Compiling 3/9\rCAPLOG {FAIL_H}\n",
            "nul_split_marker": f"CAP\x00LOG {FAIL_H}\n",
        }
        for label, line in hidden.items():
            for stream in ("stdout", "stderr"):
                with self.subTest(prefix=label, stream=stream):
                    kwargs = {"stdout": f"CAPLOG {PASS_A}\n", "stderr": ""}
                    kwargs[stream] = kwargs[stream] + line
                    rc, recs, log, res = self.run_suite(
                        'e2e_cargo_test "fss-reference" "contract"\ne2e_summary', **kwargs)
                    self.assert_fail_closed(rc, recs, log, res, failed_step="hidden_fail")

    def test_double_marker_and_two_records_per_line_fail_closed(self):
        cases = {
            "double_marker": (f"running 1 test CAPLOG CAPLOG {FAIL_H}\n", "hidden_fail"),
            "two_records_one_line": (f"CAPLOG {PASS_B}CAPLOG {FAIL_H}\n", "hidden_fail"),
            "marker_without_object": ("test t ... CAPLOG pending\n", "malformed_caplog"),
        }
        for label, (line, failed) in cases.items():
            with self.subTest(case=label):
                rc, recs, log, res = self.run_suite(
                    'e2e_cargo_test "fss-reference" "contract"\ne2e_summary',
                    stdout=f"CAPLOG {PASS_A}\n", stderr=line)
                self.assert_fail_closed(rc, recs, log, res, failed_step=failed)

    def test_two_records_on_one_line_both_count_when_passing(self):
        rc, recs, log, res = self.run_suite('e2e_cargo_test "fss-reference" "contract"\ne2e_summary',
                                            stderr=f"running 2 tests\tCAPLOG {PASS_A} CAPLOG {PASS_B}\n")
        self.assert_pass(rc, recs, log, res, ["alpha", "beta"])

    # ------------------------------------------------------------------ exit status hooks

    def test_trap_exit0_over_fail_summary(self):
        body = ("trap 'exit 0' EXIT\n"
                'e2e_expect_eq "mismatch" "a" "b"\n'
                "e2e_summary")
        rc, recs, log, res = self.run_suite(body)
        self.assert_fail_closed(rc, recs, log, res, failed_step="mismatch")

    def test_trap_exit0_on_dying_script(self):
        body = ("cleanup() { :; exit 0; }\n"
                "trap cleanup EXIT\n"
                'e2e_step "ok_step" echo fine\n'
                "false\n"
                "e2e_summary")
        rc, recs, log, res = self.run_suite(body)
        self.assert_fail_closed(rc, recs, log, res, run_failure="script_exit")

    def test_trap_exit0_then_early_exit0(self):
        body = ("trap 'exit 0' EXIT\n"
                'e2e_step "first" echo one\n'
                "exit 0\n"
                'e2e_expect_eq "never_reached" "a" "b"\n'
                "e2e_summary")
        rc, recs, log, res = self.run_suite(body)
        self.assert_fail_closed(rc, recs, log, res, run_failure="script_exit")

    def test_early_exit0_without_summary_fails(self):
        body = ('e2e_step "first" echo one\n'
                "exit 0\n"
                'e2e_expect_eq "never_reached" "a" "b"\n'
                "e2e_summary")
        rc, recs, log, res = self.run_suite(body)
        self.assert_fail_closed(rc, recs, log, res, run_failure="script_exit")

    def test_err_trap_exit0_fails(self):
        body = ("trap 'exit 0' ERR\n"
                'e2e_step "first" echo one\n'
                "false\n"
                "e2e_summary")
        rc, recs, log, res = self.run_suite(body)
        self.assert_fail_closed(rc, recs, log, res, run_failure="script_exit")

    def test_on_exit_hook_exit0_over_fail(self):
        body = ("e2e_on_exit 'exit 0'\n"
                'e2e_expect_eq "mismatch" "a" "b"\n'
                "e2e_summary")
        rc, recs, log, res = self.run_suite(body)
        self.assert_fail_closed(rc, recs, log, res, failed_step="mismatch")

    def test_on_exit_hook_exit0_on_dying_script(self):
        body = ("e2e_on_exit 'exit 0'\n"
                'e2e_step "ok_step" echo fine\n'
                "false\n"
                "e2e_summary")
        rc, recs, log, res = self.run_suite(body)
        self.assert_fail_closed(rc, recs, log, res, run_failure="script_exit")

    def test_builtin_trap_exit0_cannot_rewrite_summary_status(self):
        body = ("builtin trap 'exit 0' EXIT\n"
                'e2e_expect_eq "mismatch" "a" "b"\n'
                "e2e_summary")
        rc, recs, log, res = self.run_suite(body)
        self.assert_fail_closed(rc, recs, log, res, failed_step="mismatch")

    def test_failing_hook_fails_a_passing_run(self):
        body = ('e2e_on_exit "false"\n'
                'e2e_step "ok_step" echo fine\n'
                "e2e_summary")
        rc, recs, log, res = self.run_suite(body)
        self.assert_fail_closed(rc, recs, log, res, failed_step="harness_exit_hook")

    def test_hooks_still_run_and_other_signals_pass_through(self):
        marker_dir = self.root / "hook_marker"
        marker_dir.mkdir(exist_ok=True)
        marker = marker_dir / "ran.txt"
        body = (f"trap 'echo trap_hook >> \"{marker}\"' EXIT INT\n"
                f"e2e_on_exit 'echo on_exit_hook >> \"{marker}\"'\n"
                "trap -p INT | grep -q trap_hook\n"
                'e2e_step "ok_step" echo fine\n'
                "e2e_summary")
        rc, recs, log, res = self.run_suite(body)
        self.assert_pass(rc, recs, log, res, [])
        self.assertEqual(marker.read_text(encoding="utf-8").split(), ["trap_hook", "on_exit_hook"])

    # ------------------------------------------------------------------ C3: one summary

    def test_subshell_summary_is_refused(self):
        body = ('e2e_step "ok_step" echo fine\n'
                "( e2e_summary ) || true\n"
                "e2e_summary")
        rc, recs, log, res = self.run_suite(body)
        self.assert_fail_closed(rc, recs, log, res, failed_step="harness_subshell_summary")

    def test_background_job_summary_is_refused(self):
        body = ('e2e_step "ok_step" echo fine\n'
                "e2e_summary &\n"
                "wait $! || true\n"
                "e2e_summary")
        rc, recs, log, res = self.run_suite(body)
        self.assert_fail_closed(rc, recs, log, res, failed_step="harness_subshell_summary")

    # ------------------------------------------------------------------ I5e2: next-line value

    def test_dangling_prompt_value_on_next_line_is_redacted(self):
        needles = ["NEXTLINE_STEP_9f3", "NEXTLINE_SKIP_7c1", "NEXTLINE_STREAM_4b8", "NEXTLINE_EQ_2d6"]
        body = (
            f"e2e_step \"prompt_step\" printf 'Password:\\n{needles[0]}\\nafter\\n'\n"
            f"e2e_skip \"prompt_skip\" $'Password:\\n{needles[1]}'\n"
            f"e2e_expect_eq \"prompt_eq\" $'api_key =\\n{needles[3]}' $'api_key =\\n{needles[3]}'\n"
            'e2e_cargo_test "fss-reference" "contract"\n'
            "e2e_summary"
        )
        rc, recs, log, res = self.run_suite(
            body, stderr=f"running 1 test\nEnter password:\n{needles[2]}\nCAPLOG {PASS_A}\n")
        self.assertEqual(rc, 0, f"{res.stdout}\n{res.stderr}")
        text = log.read_text(encoding="utf-8")
        for needle in needles:
            self.assertNotIn(needle, text, f"{needle} leaked into {log}")
        self.assertIn("after", text)
        validate_file(log)

    # ------------------------------------------------------------------ lint

    def test_cap_scripts_do_not_bypass_the_harness_trap(self):
        """cap_*.sh may not reach the builtin trap, unset the wrapper, or exec away the shell."""
        forbidden = re.compile(
            r"^\s*(?:builtin\s+trap|command\s+trap|unset\s+-f\s+trap|enable\s+-n\s+trap|exec\s)",
            re.MULTILINE)
        scripts = sorted((REPO_ROOT / "scripts" / "e2e").glob("cap_*.sh"))
        self.assertTrue(scripts)
        offenders = [f"{p.name}: {m.group(0).strip()}" for p in scripts
                     for m in forbidden.finditer(p.read_text(encoding="utf-8"))]
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()

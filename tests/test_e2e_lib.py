#!/usr/bin/env python3
"""tests/test_e2e_lib.py

Comprehensive test companion for the FSS end-to-end logging harness (scripts/e2e/lib.sh).
Proves logging, expectations, secret redaction, output caps, fail-open behavior,
forensics tmpdir lifecycle, and mutant kills.
Uses a stub rch on PATH; never invokes real rch, network, or local cargo.
Never writes to /tmp; all sandbox artifacts reside under target/test_sandboxes/.
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

# Add scripts/e2e to sys.path for direct import of validate_log
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts" / "e2e"))
from validate_log import validate_file, validate_summary_record, ValidationError, find_log_files


class TestE2eLibHarness(unittest.TestCase):
    """Exhaustive tests for scripts/e2e/lib.sh and scripts/e2e/selftest.sh."""

    @classmethod
    def setUpClass(cls):
        cls.sandbox_root = REPO_ROOT / "target" / "test_sandboxes" / f"test_e2e_lib_py_{os.getpid()}"
        cls.sandbox_root.mkdir(parents=True, exist_ok=True)

        cls.stub_bin_dir = cls.sandbox_root / "bin"
        cls.stub_bin_dir.mkdir(parents=True, exist_ok=True)

        # Create stub rch script
        cls.stub_rch = cls.stub_bin_dir / "rch"
        cls.stub_rch.write_text(r"""#!/usr/bin/env bash
set -euo pipefail

mode="${STUB_RCH_MODE:-pass}"
target="${STUB_RCH_TARGET:-test_target}"

# Record invocation
if [[ -n "${STUB_RCH_LOG:-}" ]]; then
    echo "rch $*" >> "$STUB_RCH_LOG"
fi

case "$mode" in
    pass)
        echo "running 1 test"
        echo "CAPLOG {\"step\": \"${target}\", \"verdict\": \"pass\", \"exit\": 0, \"duration_ms\": 10, \"expected\": 1, \"observed\": 1}"
        echo "test result: ok. 1 passed; 0 failed"
        exit 0
        ;;
    fail)
        echo "running 1 test"
        echo "CAPLOG {\"step\": \"${target}_fail\", \"verdict\": \"fail\", \"exit\": 1, \"duration_ms\": 12, \"expected\": 1, \"observed\": 2}"
        echo "test result: FAILED. 0 passed; 1 failed"
        exit 0
        ;;
    zero_caplog)
        echo "running 1 test"
        echo "test result: ok. 1 passed; 0 failed"
        exit 0
        ;;
    bad_verdict)
        echo "CAPLOG {\"step\": \"${target}\", \"verdict\": \"bogus\", \"exit\": 0, \"duration_ms\": 5}"
        echo "test result: ok. 1 passed; 0 failed"
        exit 0
        ;;
    exit_103)
        echo "fleet saturated" >&2
        exit 103
        ;;
    crash_partial)
        echo "CAPLOG {\"step\": \"${target}\", \"verdict\": \"pass\", \"exit\": null}"
        exit 0
        ;;
    secret_caplog)
        echo "CAPLOG {\"step\": \"${target}\", \"verdict\": \"pass\", \"exit\": 0, \"duration_ms\": 10, \"expected\": \"ghp_EXPECTEDSECRET12345\", \"observed\": \"ghp_OBSERVEDSECRET67890\"}"
        exit 0
        ;;
    *)
        echo "Unknown stub mode: $mode" >&2
        exit 1
        ;;
esac
""")
        cls.stub_rch.chmod(cls.stub_rch.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

        # Set up isolated PATH with stub_bin_dir at the front
        cls.orig_path = os.environ.get("PATH", "")
        cls.env = os.environ.copy()
        cls.env["PATH"] = f"{cls.stub_bin_dir}:{cls.orig_path}"
        cls.env["REPO_ROOT"] = str(REPO_ROOT)

        # Guard: verify rch resolves to the stub binary
        resolved_rch = shutil.which("rch", path=cls.env["PATH"])
        if resolved_rch != str(cls.stub_rch):
            raise RuntimeError(f"HARD GUARD FAILED: rch resolves to {resolved_rch} instead of {cls.stub_rch}")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.sandbox_root, ignore_errors=True)

    def _run_script(self, script_path, args=None, extra_env=None):
        env = self.env.copy()
        if extra_env:
            env.update(extra_env)
        cmd = ["bash", str(script_path)] + (args or [])
        res = subprocess.run(cmd, cwd=str(REPO_ROOT), env=env, capture_output=True, text=True)
        return res

    def test_stub_rch_guard_active(self):
        """Proves that rch on PATH is strictly the isolated stub and never touches real rch."""
        resolved = shutil.which("rch", path=self.env["PATH"])
        self.assertEqual(resolved, str(self.stub_rch))

    def test_selftest_executes_cleanly_and_passes(self):
        """bash scripts/e2e/selftest.sh exits 0, every record validates, and final line has verdict pass."""
        run_sandbox = self.sandbox_root / "selftest_run"
        run_sandbox.mkdir(parents=True, exist_ok=True)
        log_dir = run_sandbox / "logs"

        res = self._run_script(
            REPO_ROOT / "scripts" / "e2e" / "selftest.sh",
            extra_env={"FSS_E2E_LOG_DIR": str(log_dir)}
        )
        self.assertEqual(res.returncode, 0, f"selftest.sh failed: stdout={res.stdout}, stderr={res.stderr}")

        logs = sorted((log_dir / "selftest").glob("run_*.log"))
        self.assertTrue(logs, "No log file created by selftest.sh")
        log_file = logs[-1]

        # Validate with python validator
        validate_file(log_file)

        # Read records
        lines = [line.strip() for line in log_file.read_text(encoding="utf-8").splitlines() if line.strip()]
        records = [json.loads(line) for line in lines]
        self.assertGreaterEqual(len(records), 3)

        # First record is env
        self.assertEqual(records[0]["step"], "env")
        self.assertEqual(records[0]["script"], "selftest.sh")
        self.assertEqual(records[0]["bead"], "fss-2h5zq.2")

        # Last record is summary with pass verdict
        summary = records[-1]
        self.assertEqual(summary["step"], "summary")
        self.assertEqual(summary["verdict"], "pass")
        self.assertEqual(summary["failures"], [])
        self.assertEqual(summary["steps"], len(records) - 2)

    def test_selftest_no_authorization_in_log(self):
        """The log contains no 'Authorization' text anywhere in any record."""
        run_sandbox = self.sandbox_root / "selftest_auth_check"
        run_sandbox.mkdir(parents=True, exist_ok=True)
        log_dir = run_sandbox / "logs"

        res = self._run_script(
            REPO_ROOT / "scripts" / "e2e" / "selftest.sh",
            extra_env={"FSS_E2E_LOG_DIR": str(log_dir)}
        )
        self.assertEqual(res.returncode, 0)
        log_file = sorted((log_dir / "selftest").glob("run_*.log"))[-1]
        log_text = log_file.read_text(encoding="utf-8")

        self.assertNotIn("authorization", log_text.lower(), "Found 'authorization' text in log file!")

    def test_selftest_excerpt_capped_for_1mib_output(self):
        """The excerpt is 4 KiB (4096 bytes) or less for 1 MiB of output."""
        run_sandbox = self.sandbox_root / "selftest_excerpt_check"
        run_sandbox.mkdir(parents=True, exist_ok=True)
        log_dir = run_sandbox / "logs"

        res = self._run_script(
            REPO_ROOT / "scripts" / "e2e" / "selftest.sh",
            extra_env={"FSS_E2E_LOG_DIR": str(log_dir)}
        )
        self.assertEqual(res.returncode, 0)
        log_file = sorted((log_dir / "selftest").glob("run_*.log"))[-1]

        found_large_step = False
        with open(log_file, "r", encoding="utf-8") as f:
            for line in f:
                rec = json.loads(line)
                if rec.get("step") == "step_large_output":
                    found_large_step = True
                    excerpt_bytes = rec.get("stdout_excerpt", "").encode("utf-8")
                    self.assertLessEqual(len(excerpt_bytes), 4096)
                    self.assertEqual(len(excerpt_bytes), 4096, "Expected exactly 4096 bytes for capped 1 MiB excerpt")
        self.assertTrue(found_large_step, "step_large_output record was not found in log")

    def test_selftest_two_runs_identical_after_stripping_ts(self):
        """Two runs give identical logs after stripping ts (and deterministic time/path normalization)."""
        run1_dir = self.sandbox_root / "det_run1"
        run2_dir = self.sandbox_root / "det_run2"
        run1_dir.mkdir(parents=True, exist_ok=True)
        run2_dir.mkdir(parents=True, exist_ok=True)

        fixed_env = {
            "FSS_E2E_FIXED_TIME": "100",
            "FSS_E2E_FIXED_TS": "2026-01-01T00:00:00Z",
        }

        res1 = self._run_script(
            REPO_ROOT / "scripts" / "e2e" / "selftest.sh",
            extra_env={**fixed_env, "FSS_E2E_LOG_DIR": str(run1_dir / "logs")}
        )
        res2 = self._run_script(
            REPO_ROOT / "scripts" / "e2e" / "selftest.sh",
            extra_env={**fixed_env, "FSS_E2E_LOG_DIR": str(run2_dir / "logs")}
        )

        self.assertEqual(res1.returncode, 0)
        self.assertEqual(res2.returncode, 0)

        log1 = (run1_dir / "logs" / "selftest" / "run_0001.log").read_text(encoding="utf-8").splitlines()
        log2 = (run2_dir / "logs" / "selftest" / "run_0001.log").read_text(encoding="utf-8").splitlines()

        self.assertEqual(len(log1), len(log2))
        for line1, line2 in zip(log1, log2):
            if not line1.strip():
                continue
            r1 = json.loads(line1)
            r2 = json.loads(line2)
            # Remove log path and log dir differences
            r1.pop("log_path", None)
            r2.pop("log_path", None)
            if "fss_env" in r1:
                r1["fss_env"].pop("FSS_E2E_LOG_DIR", None)
            if "fss_env" in r2:
                r2["fss_env"].pop("FSS_E2E_LOG_DIR", None)
            self.assertEqual(r1, r2, f"Records differ: {r1} vs {r2}")

    def test_negative_cases_fail_closed(self):
        """Negative cases (failing expectation, missing command, exit code) fail closed."""
        suite_dir = self.sandbox_root / "neg_suite"
        suite_dir.mkdir(parents=True, exist_ok=True)
        log_dir = suite_dir / "logs"

        test_script = suite_dir / "run_neg.sh"
        test_script.write_text("""#!/usr/bin/env bash
source "@REPO_ROOT@/scripts/e2e/lib.sh"
e2e_init "neg_suite" "fss-2h5zq.2"
case "${1:-}" in
    expect_mismatch)
        e2e_expect_eq "mismatch_step" "expected_val" "actual_val"
        ;;
    cmd_failure)
        e2e_step "failing_cmd" bash -c 'exit 19'
        ;;
    exit_mismatch)
        e2e_step "cmd_ok" echo "ok"
        e2e_expect_exit "cmd_ok" 42
        ;;
esac
e2e_summary
""".replace("@REPO_ROOT@", str(REPO_ROOT)))
        test_script.chmod(0o755)

        for case_name, failed_step in [
            ("expect_mismatch", "mismatch_step"),
            ("cmd_failure", "failing_cmd"),
            ("exit_mismatch", "cmd_ok_exit"),
        ]:
            res = self._run_script(test_script, args=[case_name], extra_env={"FSS_E2E_LOG_DIR": str(log_dir)})
            self.assertNotEqual(res.returncode, 0, f"Case {case_name} should have failed closed!")

            logs = sorted((log_dir / "neg_suite").glob("run_*.log"))
            self.assertTrue(logs)
            log_file = logs[-1]

            validate_file(log_file)
            summary = json.loads(log_file.read_text(encoding="utf-8").splitlines()[-1])
            self.assertEqual(summary["verdict"], "fail")
            self.assertIn(failed_step, summary["failures"])

    def test_uninitialized_exit_trap_fails_closed(self):
        """Sourcing lib.sh and exiting before e2e_init fails closed with exit 1."""
        cmd = ["bash", "-c", f'source "{REPO_ROOT}/scripts/e2e/lib.sh"; exit 42']
        res = subprocess.run(cmd, cwd=str(REPO_ROOT), env=self.env, capture_output=True, text=True)
        self.assertEqual(res.returncode, 1, f"Expected exit 1, got {res.returncode}")
        self.assertIn("failing closed", res.stderr)

    def test_exact_log_cap_boundary_n_and_n_plus_1(self):
        """The log cap boundary is exact: records under limit write; record pushing past limit is refused."""
        suite_dir = self.sandbox_root / "cap_suite"
        suite_dir.mkdir(parents=True, exist_ok=True)
        log_dir = suite_dir / "logs"

        test_script = suite_dir / "run_cap.sh"
        test_script.write_text(r"""#!/usr/bin/env bash
source "@REPO_ROOT@/scripts/e2e/lib.sh"
e2e_init "cap_suite" "fss-2h5zq.2"

# File capacity is 10 MiB (10485760 bytes), buffer is 4096 bytes: limit is 10481664 bytes.
# Create initial record to know base size
e2e_step "s_base" echo "base"

# Bloat log file up to exactly near the boundary
cur_size=$(wc -c < "$_E2E_LOG_FILE")
needed=$(( 10485760 - 4096 - cur_size - 300 ))

# Append a dummy line directly to bring it to exact boundary N
python3 -c 'import sys; open(sys.argv[1], "a").write("{\"pad\": \"" + "P" * (int(sys.argv[2]) - 13) + "\"}\n")' "$_E2E_LOG_FILE" "$needed"

# Step N: should succeed
e2e_step "step_under_limit" echo "within cap"

# Step N+1: pushing past limit should fail
set +e
e2e_step "step_over_limit" python3 -c 'print("B" * 5000)'
RC_OVER=$?
set -e

e2e_summary
""".replace("@REPO_ROOT@", str(REPO_ROOT)))
        test_script.chmod(0o755)

        res = self._run_script(test_script, extra_env={"FSS_E2E_LOG_DIR": str(log_dir)})
        self.assertNotEqual(res.returncode, 0, "Log cap exceeded must fail the run!")
        self.assertIn("10 MiB log cap exceeded", res.stderr)

        logs = sorted((log_dir / "cap_suite").glob("run_*.log"))
        self.assertTrue(logs)
        log_file = logs[-1]
        lines = [l.strip() for l in log_file.read_text(encoding="utf-8").splitlines() if l.strip()]
        steps = [json.loads(l).get("step") for l in lines]

        self.assertIn("step_under_limit", steps, "Step within cap boundary should have been written")
        self.assertNotIn("step_over_limit", steps, "Step exceeding cap boundary must NOT have been written")

    def test_secret_redaction_needles_never_appear(self):
        """All planted secret needles (env tokens, shapes, flags, URLs) are redacted from the log."""
        suite_dir = self.sandbox_root / "secrets_suite"
        suite_dir.mkdir(parents=True, exist_ok=True)
        log_dir = suite_dir / "logs"

        needles = [
            "ghpfakeENVVALUE0001",
            "wJalrFAKEENVVALUE0002",
            "hunterFAKEENVVALUE0003",
            "ghp_PLANTEDSECRETTOKEN12345",
            "github_pat_11AAAAAA_BBBBBBCCCCCC12345",
            "AKIA1234567890ABCDEF",
            "ASIA1234567890ABCDEF",
            "sk-1234567890abcdefghijklmnop",
            "xoxb-123456-abcdef",
            "glpat-1234567890abcdefghij",
            "my_super_secret_password_val",
            "mysql_secret_pwd",
            "http_secret_cred",
        ]

        test_script = suite_dir / "run_sec.sh"
        test_script.write_text(f"""#!/usr/bin/env bash
source "{REPO_ROOT}/scripts/e2e/lib.sh"
e2e_init "secrets_suite" "fss-2h5zq.2"

export GITHUB_TOKEN="ghpfakeENVVALUE0001"
export AWS_SECRET_ACCESS_KEY="wJalrFAKEENVVALUE0002"
export MYPASS="hunterFAKEENVVALUE0003"

e2e_step "step_needles" bash -c '
echo "ghp_PLANTEDSECRETTOKEN12345"
echo "github_pat_11AAAAAA_BBBBBBCCCCCC12345"
echo "AKIA1234567890ABCDEF"
echo "ASIA1234567890ABCDEF"
echo "sk-1234567890abcdefghijklmnop"
echo "xoxb-123456-abcdef"
echo "glpat-1234567890abcdefghij"
echo "--password my_super_secret_password_val"
echo "mysql -pmysql_secret_pwd"
echo "http://admin:http_secret_cred@example.com"
'

e2e_expect_eq "sec_eq" "ghp_PLANTEDSECRETTOKEN12345" "ghp_PLANTEDSECRETTOKEN12345"
e2e_skip "sec_skip" "sk-1234567890abcdefghijklmnop"

e2e_summary
""")
        test_script.chmod(0o755)

        res = self._run_script(test_script, extra_env={"FSS_E2E_LOG_DIR": str(log_dir)})
        log_file = sorted((log_dir / "secrets_suite").glob("run_*.log"))[-1]
        log_text = log_file.read_text(encoding="utf-8")

        for needle in needles:
            self.assertNotIn(needle, log_text, f"Secret needle '{needle}' leaked in log file!")

    def test_fail_open_exit_103_bounded_retry(self):
        """RCH exit 103 retries at most 3 times (4 calls total) and fails closed."""
        suite_dir = self.sandbox_root / "r103_suite"
        suite_dir.mkdir(parents=True, exist_ok=True)
        log_dir = suite_dir / "logs"
        rch_log = suite_dir / "rch.log"

        test_script = suite_dir / "run_r103.sh"
        test_script.write_text(f"""#!/usr/bin/env bash
source "{REPO_ROOT}/scripts/e2e/lib.sh"
e2e_init "r103_suite" "fss-2h5zq.2"
e2e_cargo_test "fss-cli" "test_r103"
e2e_summary
""")
        test_script.chmod(0o755)

        res = self._run_script(
            test_script,
            extra_env={
                "FSS_E2E_LOG_DIR": str(log_dir),
                "STUB_RCH_MODE": "exit_103",
                "STUB_RCH_LOG": str(rch_log),
            }
        )
        self.assertNotEqual(res.returncode, 0, "Exit 103 must fail the run")

        rch_invocations = rch_log.read_text().strip().splitlines()
        self.assertEqual(len(rch_invocations), 4, f"Expected 4 invocations (1 initial + 3 retries), got {len(rch_invocations)}")

        log_file = sorted((log_dir / "r103_suite").glob("run_*.log"))[-1]
        validate_file(log_file)
        summary = json.loads(log_file.read_text().splitlines()[-1])
        self.assertEqual(summary["verdict"], "fail")

    def test_forensics_tmpdir_preserved_on_failure_cleaned_on_pass(self):
        """Tmpdir is preserved on failure and emitted on stderr; cleaned up on pass."""
        suite_dir = self.sandbox_root / "tmpdir_suite"
        suite_dir.mkdir(parents=True, exist_ok=True)
        log_dir = suite_dir / "logs"

        # Failing run
        fail_script = suite_dir / "run_fail.sh"
        fail_script.write_text("""#!/usr/bin/env bash
source "@REPO_ROOT@/scripts/e2e/lib.sh"
e2e_init "tmp_suite" "fss-2h5zq.2"
TMP=$(e2e_tmpdir)
echo "fail_data" > "${TMP}/fail.txt"
echo "$TMP" > "@SUITE_DIR@/fail_tmp.txt"
e2e_expect_eq "must_fail" "a" "b"
e2e_summary
""".replace("@REPO_ROOT@", str(REPO_ROOT)).replace("@SUITE_DIR@", str(suite_dir)))
        fail_script.chmod(0o755)

        res1 = self._run_script(fail_script, extra_env={"FSS_E2E_LOG_DIR": str(log_dir)})
        self.assertNotEqual(res1.returncode, 0)
        self.assertIn("forensics_preserved", res1.stderr)

        fail_tmp = Path(suite_dir / "fail_tmp.txt").read_text().strip()
        self.assertTrue(Path(fail_tmp).is_dir(), "Failing tmpdir was not preserved on disk")

        # Passing run in same suite
        pass_script = suite_dir / "run_pass.sh"
        pass_script.write_text("""#!/usr/bin/env bash
source "@REPO_ROOT@/scripts/e2e/lib.sh"
e2e_init "tmp_suite" "fss-2h5zq.2"
TMP=$(e2e_tmpdir)
echo "pass_data" > "${TMP}/pass.txt"
echo "$TMP" > "@SUITE_DIR@/pass_tmp.txt"
e2e_step "pass_step" echo "ok"
e2e_summary
""".replace("@REPO_ROOT@", str(REPO_ROOT)).replace("@SUITE_DIR@", str(suite_dir)))
        pass_script.chmod(0o755)

        res2 = self._run_script(pass_script, extra_env={"FSS_E2E_LOG_DIR": str(log_dir)})
        self.assertEqual(res2.returncode, 0)

        pass_tmp = Path(suite_dir / "pass_tmp.txt").read_text().strip()
        self.assertFalse(Path(pass_tmp).exists(), "Passing tmpdir should have been cleaned up")
        self.assertTrue(Path(fail_tmp).is_dir(), "Run 1 failing tmpdir must still be preserved after Run 2 passes")

    def test_repro_command_reruns_target_step(self):
        """Summary repro command contains --only <step>, and executing it reruns the target."""
        suite_dir = self.sandbox_root / "repro_suite"
        suite_dir.mkdir(parents=True, exist_ok=True)
        log_dir = suite_dir / "logs"

        test_script = suite_dir / "run_multi.sh"
        test_script.write_text(f"""#!/usr/bin/env bash
source "{REPO_ROOT}/scripts/e2e/lib.sh"
e2e_init "repro_suite" "fss-2h5zq.2" "$@"
e2e_step "step_a" echo "step A"
e2e_step "step_b" bash -c 'exit 13'
e2e_step "step_c" echo "step C"
e2e_summary
""")
        test_script.chmod(0o755)

        res1 = self._run_script(test_script, extra_env={"FSS_E2E_LOG_DIR": str(log_dir)})
        self.assertNotEqual(res1.returncode, 0)

        log1 = sorted((log_dir / "repro_suite").glob("run_*.log"))[-1]
        summary = json.loads(log1.read_text().splitlines()[-1])
        self.assertIn("--only step_b", summary["repro"])

        # Execute repro command with --only step_b
        res2 = self._run_script(test_script, args=["--only", "step_b"], extra_env={"FSS_E2E_LOG_DIR": str(log_dir)})
        self.assertNotEqual(res2.returncode, 0)

        log2 = sorted((log_dir / "repro_suite").glob("run_*.log"))[-1]
        steps = [json.loads(line).get("step") for line in log2.read_text().splitlines() if line.strip()]
        self.assertEqual(steps, ["env", "step_b", "summary"])

    def test_mutant_kills(self):
        """Directly verifies that mutants M4b, M8, M9, M11, M12, M14, M15, and M16 are killed."""
        mutants = {
            "M4b": ("scripts/e2e/lib.sh", [("if len(res_bytes) > max_bytes:", "if False:"), ("    if len(b) > 4096:", "    if False:")]),
            "M8": ("scripts/e2e/lib.sh", [('        if data["verdict"] not in VALID_STEP_VERDICTS:\n            has_malformed = True', '        if False:\n            has_malformed = True')]),
            "M9": ("scripts/e2e/lib.sh", [('        echo "Error: E2E uninitialized or log file not set (failing closed)" >&2\n        exit 1', '        echo "Error: E2E uninitialized or log file not set (failing closed)" >&2\n        return')]),
            "M11": ("scripts/e2e/lib.sh", [('            "expected": sanitize_data(item.get("expected", None)),', '            "expected": item.get("expected", None),'),
                                           ('            "observed": sanitize_data(item.get("observed", None)),', '            "observed": item.get("observed", None),')]),
            "M12": ("scripts/e2e/lib.sh", [('if [[ ! "$_E2E_NAME" =~ ^[A-Za-z0-9_.-]+$ ]] || [[ "$_E2E_NAME" == *".."* ]]; then', 'if false; then')]),
            "M14": ("scripts/e2e/lib.sh", [('echo "$tmp" >> "${_E2E_LOG_FILE}.tmpdirs"', 'echo "$tmp" >> "${_E2E_RUN_DIR}/.tmpdirs"'),
                                           ('local tmpdirs_file="${_E2E_LOG_FILE:-}.tmpdirs"', 'local tmpdirs_file="${_E2E_RUN_DIR:-}/.tmpdirs"')]),
            "M15": ("scripts/e2e/lib.sh", [("matched = (cur == expected_val and type(cur) is type(expected_val))", "matched = (cur == expected_val)")]),
            "M16": ("scripts/e2e/lib.sh", [('            *)\n                echo "Error: unrecognized argument: $1" >&2\n                exit 1',
                                           '            *)\n                shift; continue\n                exit 1')]),
        }

        for mid, (rel_path, subs) in mutants.items():
            target_path = REPO_ROOT / rel_path
            orig_content = target_path.read_text(encoding="utf-8")
            mutated_content = orig_content

            for old, new in subs:
                self.assertIn(old, mutated_content, f"Mutant pattern {old[:40]} not found for {mid}")
                mutated_content = mutated_content.replace(old, new, 1)

            try:
                target_path.write_text(mutated_content, encoding="utf-8")
                # Run self-test shell suite to verify mutant is killed
                res = subprocess.run(
                    ["bash", str(REPO_ROOT / "tests" / "test_e2e_lib.sh")],
                    cwd=str(REPO_ROOT),
                    capture_output=True,
                    text=True
                )
                self.assertNotEqual(res.returncode, 0, f"Mutant {mid} survived tests!")
            finally:
                target_path.write_text(orig_content, encoding="utf-8")


if __name__ == "__main__":
    unittest.main()

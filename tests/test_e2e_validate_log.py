#!/usr/bin/env python3
"""Unit tests for scripts/e2e/validate_log.py.

Kills mutants for:
- Required field checks (env, step, summary)
- Non-JSON acceptance
- Env-first and summary-last enforcement
- Excerpt cap enforcement (> 4096 bytes)
- Duplicate JSON keys and duplicate step IDs
- Type mismatch (bool-as-int, negative duration, NaN duration)
- CRLF and invalid UTF-8 detection
- Summary consistency (verdict vs failures list vs step count)
"""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

# Add repo root to import path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys_path_e2e = REPO_ROOT / "scripts" / "e2e"
import sys

if str(sys_path_e2e) not in sys.path:
    sys.path.insert(0, str(sys_path_e2e))

import validate_log
from validate_log import ValidationError, validate_file, find_log_files

_TEST_SANDBOX = REPO_ROOT / "target" / "test_sandboxes"
_TEST_SANDBOX.mkdir(parents=True, exist_ok=True)
tempfile.tempdir = str(_TEST_SANDBOX)


class TestValidateLog(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="test_val_log_", dir=str(_TEST_SANDBOX))
        self.log_path = Path(self.tmp_dir) / "run_0001.log"

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _valid_env_record(self):
        return {
            "step": "env",
            "script": "test.sh",
            "bead": "fss-2h5zq.1",
            "git_sha": "7168075208f6a8a9c6b2015c20c0ea5bdf87d934",
            "dirty": False,
            "host": "x86_64-unknown-linux-gnu",
            "bins": [
                {
                    "name": "fss",
                    "path": "/bin/fss",
                    "sha256": "a" * 64
                }
            ],
            "fss_env": {
                "FSS_BIN_DIR": "",
                "FSS_E2E_LOG_DIR": ""
            }
        }

    def _valid_step_record(self, step="step1", verdict="pass", exit_code=0):
        return {
            "ts": "2026-09-13T20:00:00Z",
            "script": "test.sh",
            "bead": "fss-2h5zq.1",
            "step": step,
            "cmd": ["echo", "hello"],
            "exit": exit_code,
            "duration_ms": 10,
            "expected": None,
            "observed": None,
            "digest": None,
            "stdout_sha256": "b" * 64,
            "stdout_excerpt": "hello\n",
            "stderr_excerpt": "",
            "verdict": verdict,
            "repro": "test.sh --only " + step
        }

    def _valid_summary_record(self, verdict="pass", steps=1, failures=None, skipped=None):
        return {
            "step": "summary",
            "verdict": verdict,
            "steps": steps,
            "failures": failures if failures is not None else [],
            "skipped": skipped if skipped is not None else [],
            "duration_ms": 25,
            "log_path": str(self.log_path),
            "repro": "test.sh"
        }

    def _write_records(self, records, raw_override=None):
        if raw_override is not None:
            with open(self.log_path, "wb") as f:
                f.write(raw_override)
            return

        lines = [json.dumps(r) for r in records]
        content = "\n".join(lines) + "\n"
        with open(self.log_path, "w", encoding="utf-8") as f:
            f.write(content)

    def test_valid_log_passes(self):
        records = [
            self._valid_env_record(),
            self._valid_step_record("s1", "pass"),
            self._valid_summary_record("pass", steps=1)
        ]
        self._write_records(records)
        # Should not raise
        validate_file(self.log_path)

    def test_missing_env_field_rejected(self):
        rec = self._valid_env_record()
        del rec["git_sha"]
        records = [
            rec,
            self._valid_step_record("s1", "pass"),
            self._valid_summary_record("pass", steps=1)
        ]
        self._write_records(records)
        with self.assertRaises(ValidationError) as ctx:
            validate_file(self.log_path)
        self.assertEqual(ctx.exception.code, "ERR_MISSING_REQUIRED_FIELD")

    def test_missing_step_field_rejected(self):
        step = self._valid_step_record("s1", "pass")
        del step["repro"]
        records = [
            self._valid_env_record(),
            step,
            self._valid_summary_record("pass", steps=1)
        ]
        self._write_records(records)
        with self.assertRaises(ValidationError) as ctx:
            validate_file(self.log_path)
        self.assertEqual(ctx.exception.code, "ERR_MISSING_REQUIRED_FIELD")

    def test_missing_summary_field_rejected(self):
        summ = self._valid_summary_record("pass", steps=1)
        del summ["log_path"]
        records = [
            self._valid_env_record(),
            self._valid_step_record("s1", "pass"),
            summ
        ]
        self._write_records(records)
        with self.assertRaises(ValidationError) as ctx:
            validate_file(self.log_path)
        self.assertEqual(ctx.exception.code, "ERR_MISSING_REQUIRED_FIELD")

    def test_non_json_rejected(self):
        raw = (
            json.dumps(self._valid_env_record()) + "\n"
            + "not a json line\n"
            + json.dumps(self._valid_summary_record("pass", steps=1)) + "\n"
        ).encode("utf-8")
        self._write_records(None, raw_override=raw)
        with self.assertRaises(ValidationError) as ctx:
            validate_file(self.log_path)
        self.assertEqual(ctx.exception.code, "ERR_INVALID_JSON")

    def test_env_first_enforced(self):
        records = [
            self._valid_step_record("s1", "pass"),
            self._valid_summary_record("pass", steps=1)
        ]
        self._write_records(records)
        with self.assertRaises(ValidationError) as ctx:
            validate_file(self.log_path)
        self.assertEqual(ctx.exception.code, "ERR_ENV_NOT_FIRST")

    def test_summary_last_enforced(self):
        records = [
            self._valid_env_record(),
            self._valid_step_record("s1", "pass")
        ]
        self._write_records(records)
        with self.assertRaises(ValidationError) as ctx:
            validate_file(self.log_path)
        self.assertEqual(ctx.exception.code, "ERR_MISSING_SUMMARY")

    def test_multiple_summaries_rejected(self):
        records = [
            self._valid_env_record(),
            self._valid_summary_record("pass", steps=1),
            self._valid_step_record("s1", "pass"),
            self._valid_summary_record("pass", steps=1)
        ]
        self._write_records(records)
        with self.assertRaises(ValidationError) as ctx:
            validate_file(self.log_path)
        self.assertEqual(ctx.exception.code, "ERR_MULTIPLE_SUMMARIES")

    def test_duplicate_step_id_rejected(self):
        records = [
            self._valid_env_record(),
            self._valid_step_record("step_same", "pass"),
            self._valid_step_record("step_same", "pass"),
            self._valid_summary_record("pass", steps=2)
        ]
        self._write_records(records)
        with self.assertRaises(ValidationError) as ctx:
            validate_file(self.log_path)
        self.assertEqual(ctx.exception.code, "ERR_DUPLICATE_STEP_ID")

    def test_duplicate_json_key_rejected(self):
        raw = b'{"step": "env", "step": "env"}\n'
        self._write_records(None, raw_override=raw)
        with self.assertRaises(ValidationError) as ctx:
            validate_file(self.log_path)
        self.assertEqual(ctx.exception.code, "ERR_DUPLICATE_KEY")

    def test_crlf_rejected(self):
        records = [
            self._valid_env_record(),
            self._valid_step_record("s1", "pass"),
            self._valid_summary_record("pass", steps=1)
        ]
        raw = ("\r\n".join(json.dumps(r) for r in records) + "\r\n").encode("utf-8")
        self._write_records(None, raw_override=raw)
        with self.assertRaises(ValidationError) as ctx:
            validate_file(self.log_path)
        self.assertEqual(ctx.exception.code, "ERR_CRLF_LINE_ENDING")

    def test_invalid_utf8_rejected(self):
        raw = b'{"step": "env"}\n\xff\xfe\n{"step": "summary"}\n'
        self._write_records(None, raw_override=raw)
        with self.assertRaises(ValidationError) as ctx:
            validate_file(self.log_path)
        self.assertEqual(ctx.exception.code, "ERR_INVALID_UTF8")

    def test_line_too_long_rejected(self):
        long_str = "x" * 70000
        raw = f'{{"step": "env", "note": "{long_str}"}}\n'.encode("utf-8")
        self._write_records(None, raw_override=raw)
        with self.assertRaises(ValidationError) as ctx:
            validate_file(self.log_path)
        self.assertEqual(ctx.exception.code, "ERR_LINE_TOO_LONG")

    def test_bool_as_int_rejected(self):
        step = self._valid_step_record("s1", "pass")
        step["exit"] = True  # bool instead of int
        records = [
            self._valid_env_record(),
            step,
            self._valid_summary_record("pass", steps=1)
        ]
        self._write_records(records)
        with self.assertRaises(ValidationError) as ctx:
            validate_file(self.log_path)
        self.assertEqual(ctx.exception.code, "ERR_TYPE_MISMATCH")

    def test_negative_duration_rejected(self):
        step = self._valid_step_record("s1", "pass")
        step["duration_ms"] = -5
        records = [
            self._valid_env_record(),
            step,
            self._valid_summary_record("pass", steps=1)
        ]
        self._write_records(records)
        with self.assertRaises(ValidationError) as ctx:
            validate_file(self.log_path)
        self.assertEqual(ctx.exception.code, "ERR_INVALID_DURATION")

    def test_nan_duration_rejected(self):
        raw = (
            json.dumps(self._valid_env_record()) + "\n"
            + '{"ts":"2026-09-13T20:00:00Z","script":"t.sh","bead":"fss-2h5zq.1","step":"s1","cmd":"c","exit":0,"duration_ms":NaN,"expected":null,"observed":null,"digest":null,"stdout_sha256":"","stdout_excerpt":"","stderr_excerpt":"","verdict":"pass","repro":"r"}\n'
            + json.dumps(self._valid_summary_record("pass", steps=1)) + "\n"
        ).encode("utf-8")
        self._write_records(None, raw_override=raw)
        with self.assertRaises(ValidationError) as ctx:
            validate_file(self.log_path)
        self.assertIn(ctx.exception.code, ["ERR_INVALID_DURATION", "ERR_INVALID_JSON"])

    def test_excerpt_cap_rejected(self):
        step = self._valid_step_record("s1", "pass")
        step["stdout_excerpt"] = "x" * 4097
        records = [
            self._valid_env_record(),
            step,
            self._valid_summary_record("pass", steps=1)
        ]
        self._write_records(records)
        with self.assertRaises(ValidationError) as ctx:
            validate_file(self.log_path)
        self.assertEqual(ctx.exception.code, "ERR_EXCERPT_CAP_EXCEEDED")

    def test_secret_key_rejected(self):
        step = self._valid_step_record("s1", "pass")
        step["observed"] = {"user_password": "bar"}
        records = [
            self._valid_env_record(),
            step,
            self._valid_summary_record("pass", steps=1)
        ]
        self._write_records(records)
        with self.assertRaises(ValidationError) as ctx:
            validate_file(self.log_path)
        self.assertEqual(ctx.exception.code, "ERR_SECRET_KEY_FOUND")

    def test_summary_consistency_pass_with_failures(self):
        records = [
            self._valid_env_record(),
            self._valid_step_record("s1", "fail", exit_code=1),
            self._valid_summary_record("pass", steps=1, failures=[])
        ]
        self._write_records(records)
        with self.assertRaises(ValidationError) as ctx:
            validate_file(self.log_path)
        self.assertEqual(ctx.exception.code, "ERR_SUMMARY_INCONSISTENCY")

    def test_summary_consistency_fail_with_empty_failures(self):
        records = [
            self._valid_env_record(),
            self._valid_step_record("s1", "fail", exit_code=1),
            self._valid_summary_record("fail", steps=1, failures=[])
        ]
        self._write_records(records)
        with self.assertRaises(ValidationError) as ctx:
            validate_file(self.log_path)
        self.assertEqual(ctx.exception.code, "ERR_SUMMARY_INCONSISTENCY")

    def test_summary_consistency_steps_count_mismatch(self):
        records = [
            self._valid_env_record(),
            self._valid_step_record("s1", "pass"),
            self._valid_step_record("s2", "pass"),
            self._valid_summary_record("pass", steps=1)  # says 1, but 2 records
        ]
        self._write_records(records)
        with self.assertRaises(ValidationError) as ctx:
            validate_file(self.log_path)
        self.assertEqual(ctx.exception.code, "ERR_SUMMARY_INCONSISTENCY")

    def test_all_steps_skipped_rejected(self):
        step = self._valid_step_record("s1", "skip")
        records = [
            self._valid_env_record(),
            step,
            self._valid_summary_record("pass", steps=1, skipped=[{"step": "s1", "reason": "test"}])
        ]
        self._write_records(records)
        with self.assertRaises(ValidationError) as ctx:
            validate_file(self.log_path)
        self.assertEqual(ctx.exception.code, "ERR_ALL_STEPS_SKIPPED")

    def test_invalid_sha256_rejected(self):
        step = self._valid_step_record("s1", "pass")
        step["stdout_sha256"] = "not_64_hex_chars"
        records = [
            self._valid_env_record(),
            step,
            self._valid_summary_record("pass", steps=1)
        ]
        self._write_records(records)
        with self.assertRaises(ValidationError) as ctx:
            validate_file(self.log_path)
        self.assertEqual(ctx.exception.code, "ERR_INVALID_HEX_DIGEST")


    def test_invalid_bins_entry_rejected(self):
        env = self._valid_env_record()
        env["bins"] = [{"name": "bad_bin", "path": "/bin/bad", "sha256": "not_64_hex"}]
        records = [
            env,
            self._valid_step_record("s1", "pass"),
            self._valid_summary_record("pass", steps=1)
        ]
        self._write_records(records)
        with self.assertRaises(ValidationError) as ctx:
            validate_file(self.log_path)
        self.assertEqual(ctx.exception.code, "ERR_INVALID_HEX_DIGEST")

    def test_bins_missing_field_rejected(self):
        env = self._valid_env_record()
        env["bins"] = [{"name": "bad_bin"}]
        records = [
            env,
            self._valid_step_record("s1", "pass"),
            self._valid_summary_record("pass", steps=1)
        ]
        self._write_records(records)
        with self.assertRaises(ValidationError) as ctx:
            validate_file(self.log_path)
        self.assertEqual(ctx.exception.code, "ERR_INVALID_BINS")

    def test_empty_file_rejected(self):
        self._write_records(None, raw_override=b"")
        with self.assertRaises(ValidationError) as ctx:
            validate_file(self.log_path)
        self.assertEqual(ctx.exception.code, "ERR_EMPTY_FILE")

    def test_whitespace_line_rejected(self):
        raw = (
            json.dumps(self._valid_env_record()) + "\n\n"
            + json.dumps(self._valid_step_record("s1", "pass")) + "\n"
            + json.dumps(self._valid_summary_record("pass", steps=1)) + "\n"
        ).encode("utf-8")
        self._write_records(None, raw_override=raw)
        with self.assertRaises(ValidationError) as ctx:
            validate_file(self.log_path)
        self.assertEqual(ctx.exception.code, "ERR_EMPTY_LINE")

    def test_find_log_files_skips_tmp_dirs_relative_to_target(self):
        target_dir = Path(self.tmp_dir) / "suite_target"
        target_dir.mkdir(parents=True)
        good_log = target_dir / "run_0001.log"
        good_log.write_text("dummy")

        tmp_subdir = target_dir / "tmp_forensics"
        tmp_subdir.mkdir()
        ignored_log = tmp_subdir / "run_ignored.log"
        ignored_log.write_text("dummy")

        found = find_log_files(target_dir)
        self.assertIn(good_log, found)
        self.assertNotIn(ignored_log, found)

    def test_find_log_files_when_parent_has_tmp_prefix(self):
        parent_dir = Path(self.tmp_dir) / "tmp_container" / "suite_target"
        parent_dir.mkdir(parents=True)
        good_log = parent_dir / "run_0001.log"
        good_log.write_text("dummy")
        found = find_log_files(parent_dir)
        self.assertIn(good_log, found)

    def test_summary_consistency_pass_with_nonempty_failures(self):
        records = [
            self._valid_env_record(),
            self._valid_step_record("s1", "pass"),
            self._valid_summary_record("pass", steps=1, failures=["s1"])
        ]
        self._write_records(records)
        with self.assertRaises(ValidationError) as ctx:
            validate_file(self.log_path)
        self.assertEqual(ctx.exception.code, "ERR_SUMMARY_INCONSISTENCY")

    def test_n25_summary_failures_contains_unknown_step_rejected(self):
        records = [
            self._valid_env_record(),
            self._valid_step_record("s1", "pass"),
            self._valid_summary_record("fail", steps=1, failures=["unknown_ghost_step"])
        ]
        self._write_records(records)
        with self.assertRaises(ValidationError) as ctx:
            validate_file(self.log_path)
        self.assertEqual(ctx.exception.code, "ERR_SUMMARY_INCONSISTENCY")

    def test_n26_failed_step_not_reported_in_summary_failures_rejected(self):
        records = [
            self._valid_env_record(),
            self._valid_step_record("s1", "fail", exit_code=1),
            self._valid_step_record("s2", "fail", exit_code=1),
            self._valid_summary_record("fail", steps=2, failures=["s1"])
        ]
        self._write_records(records)
        with self.assertRaises(ValidationError) as ctx:
            validate_file(self.log_path)
        self.assertEqual(ctx.exception.code, "ERR_SUMMARY_INCONSISTENCY")

    def test_n27_summary_skipped_contains_unknown_step_rejected(self):
        records = [
            self._valid_env_record(),
            self._valid_step_record("s1", "pass"),
            self._valid_summary_record("pass", steps=1, failures=[], skipped=[{"step": "ghost_skip", "reason": "unseen"}])
        ]
        self._write_records(records)
        with self.assertRaises(ValidationError) as ctx:
            validate_file(self.log_path)
        self.assertEqual(ctx.exception.code, "ERR_SUMMARY_INCONSISTENCY")

    def test_n28_secret_value_scan_catches_short_ghp_token(self):
        step = self._valid_step_record("s1", "pass")
        step["stdout_excerpt"] = "leak: ghp_123456789012\n"
        records = [
            self._valid_env_record(),
            step,
            self._valid_summary_record("pass", steps=1)
        ]
        self._write_records(records)
        with self.assertRaises(ValidationError) as ctx:
            validate_file(self.log_path)
        self.assertEqual(ctx.exception.code, "ERR_SECRET_VALUE_FOUND")

    def test_n29_find_log_files_ignores_tmpdirs_extension(self):
        target_dir = Path(self.tmp_dir) / "suite_tmpdirs"
        target_dir.mkdir(parents=True)
        good_log = target_dir / "run_0001.log"
        good_log.write_text(json.dumps(self._valid_env_record()) + "\n")
        tmpdirs_file = target_dir / "run_0001.log.tmpdirs"
        tmpdirs_file.write_text("/path/to/some/tmpdir\n")

        found = find_log_files(target_dir)
        self.assertIn(good_log, found)
        self.assertNotIn(tmpdirs_file, found)
        self.assertEqual(found, [good_log])


if __name__ == "__main__":
    unittest.main()

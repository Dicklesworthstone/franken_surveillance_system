#!/usr/bin/env python3
"""E2E log validator for CAP- structured JSON-lines logs.

Validates that every record in an E2E log file adheres to the unified record schema,
enforces 4 KiB excerpt caps, 10 MiB total file cap, verdict enums, strict typing,
summary consistency, and ensures no keys resemble secrets.
"""

import json
import math
import os
import re
import sys
from pathlib import Path

MAX_EXCERPT_BYTES = 4096
MAX_FILE_BYTES = 10 * 1024 * 1024  # 10 MiB
MAX_LINE_BYTES = 65536  # 64 KiB line cap

SECRET_KEY_PATTERN = re.compile(
    r"authorization|password|token|secret|cookie|api_key|apikey", re.IGNORECASE
)
HEX_64_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")
STEP_VERDICTS = {"ran", "pass", "fail", "skip"}
SUMMARY_VERDICTS = {"pass", "fail"}


class ValidationError(Exception):
    def __init__(self, code: str, message: str, line_no=None, line=None):
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message
        self.line_no = line_no
        self.line = line


def check_no_secret_keys(data, path=""):
    """Recursively checks that no key name in data looks like a secret."""
    if isinstance(data, dict):
        for k, v in data.items():
            k_str = str(k)
            if SECRET_KEY_PATTERN.search(k_str):
                loc = f"{path}.{k_str}" if path else k_str
                raise ValidationError(
                    "ERR_SECRET_KEY_FOUND",
                    f"Forbidden secret-like key '{loc}' found in record",
                )
            check_no_secret_keys(v, f"{path}.{k_str}" if path else k_str)
    elif isinstance(data, list):
        for idx, item in enumerate(data):
            check_no_secret_keys(item, f"{path}[{idx}]")


def _strict_int(val, field_name, line_no):
    """Checks that val is an int and NOT a bool."""
    if isinstance(val, bool) or not isinstance(val, int):
        raise ValidationError(
            "ERR_TYPE_MISMATCH",
            f"Field '{field_name}' (line {line_no}) must be int, got {type(val).__name__}",
            line_no=line_no,
        )


def _check_duration(val, field_name, line_no, allow_float=False):
    if isinstance(val, bool):
        raise ValidationError(
            "ERR_TYPE_MISMATCH",
            f"Field '{field_name}' (line {line_no}) cannot be bool",
            line_no=line_no,
        )
    if allow_float:
        if not isinstance(val, (int, float)):
            raise ValidationError(
                "ERR_TYPE_MISMATCH",
                f"Field '{field_name}' (line {line_no}) must be number, got {type(val).__name__}",
                line_no=line_no,
            )
    else:
        if not isinstance(val, int):
            raise ValidationError(
                "ERR_TYPE_MISMATCH",
                f"Field '{field_name}' (line {line_no}) must be int, got {type(val).__name__}",
                line_no=line_no,
            )
    if math.isnan(val) or math.isinf(val) or val < 0:
        raise ValidationError(
            "ERR_INVALID_DURATION",
            f"Field '{field_name}' (line {line_no}) must be non-negative finite number, got {val}",
            line_no=line_no,
        )


def validate_env_record(rec, line_no):
    required = ["step", "script", "bead", "git_sha", "dirty", "host", "bins", "fss_env"]
    for req in required:
        if req not in rec:
            raise ValidationError(
                "ERR_MISSING_REQUIRED_FIELD",
                f"Env record (line {line_no}) missing required field '{req}'",
                line_no=line_no,
            )

    if rec["step"] != "env":
        raise ValidationError(
            "ERR_SCHEMA_VIOLATION",
            f"Env record (line {line_no}) has step != 'env'",
            line_no=line_no,
        )
    if not isinstance(rec["script"], str):
        raise ValidationError(
            "ERR_TYPE_MISMATCH",
            f"Env record (line {line_no}) field 'script' must be str",
            line_no=line_no,
        )
    if not isinstance(rec["bead"], str):
        raise ValidationError(
            "ERR_TYPE_MISMATCH",
            f"Env record (line {line_no}) field 'bead' must be str",
            line_no=line_no,
        )
    if not isinstance(rec["git_sha"], str):
        raise ValidationError(
            "ERR_TYPE_MISMATCH",
            f"Env record (line {line_no}) field 'git_sha' must be str",
            line_no=line_no,
        )
    if not isinstance(rec["dirty"], bool):
        raise ValidationError(
            "ERR_TYPE_MISMATCH",
            f"Env record (line {line_no}) field 'dirty' must be bool",
            line_no=line_no,
        )
    if not isinstance(rec["host"], str):
        raise ValidationError(
            "ERR_TYPE_MISMATCH",
            f"Env record (line {line_no}) field 'host' must be str",
            line_no=line_no,
        )
    if not isinstance(rec["bins"], list):
        raise ValidationError(
            "ERR_TYPE_MISMATCH",
            f"Env record (line {line_no}) field 'bins' must be list",
            line_no=line_no,
        )
    for b_idx, bin_entry in enumerate(rec["bins"]):
        if not isinstance(bin_entry, dict):
            raise ValidationError(
                "ERR_INVALID_BINS",
                f"Env record (line {line_no}) bins[{b_idx}] must be a dict",
                line_no=line_no,
            )
        for b_req in ["name", "path", "sha256"]:
            if b_req not in bin_entry:
                raise ValidationError(
                    "ERR_INVALID_BINS",
                    f"Env record (line {line_no}) bins[{b_idx}] missing required field '{b_req}'",
                    line_no=line_no,
                )
        if not isinstance(bin_entry["name"], str) or not isinstance(bin_entry["path"], str):
            raise ValidationError(
                "ERR_INVALID_BINS",
                f"Env record (line {line_no}) bins[{b_idx}] name and path must be str",
                line_no=line_no,
            )
        if not isinstance(bin_entry["sha256"], str) or not HEX_64_PATTERN.match(bin_entry["sha256"]):
            raise ValidationError(
                "ERR_INVALID_HEX_DIGEST",
                f"Env record (line {line_no}) bins[{b_idx}] sha256 must be 64 hex characters, got '{bin_entry.get('sha256')}'",
                line_no=line_no,
            )
    if not isinstance(rec["fss_env"], dict):
        raise ValidationError(
            "ERR_TYPE_MISMATCH",
            f"Env record (line {line_no}) field 'fss_env' must be dict",
            line_no=line_no,
        )


def validate_summary_record(rec, line_no):
    required = ["step", "verdict", "steps", "failures", "skipped", "duration_ms", "log_path", "repro"]
    for req in required:
        if req not in rec:
            raise ValidationError(
                "ERR_MISSING_REQUIRED_FIELD",
                f"Summary record (line {line_no}) missing required field '{req}'",
                line_no=line_no,
            )

    if rec["step"] != "summary":
        raise ValidationError(
            "ERR_SCHEMA_VIOLATION",
            f"Summary record (line {line_no}) has step != 'summary'",
            line_no=line_no,
        )
    if rec["verdict"] not in SUMMARY_VERDICTS:
        raise ValidationError(
            "ERR_INVALID_VERDICT",
            f"Summary record (line {line_no}) invalid verdict '{rec.get('verdict')}', must be one of {sorted(SUMMARY_VERDICTS)}",
            line_no=line_no,
        )
    _strict_int(rec["steps"], "steps", line_no)
    if rec["steps"] < 0:
        raise ValidationError(
            "ERR_TYPE_MISMATCH",
            f"Summary record (line {line_no}) field 'steps' cannot be negative",
            line_no=line_no,
        )
    if not isinstance(rec["failures"], list):
        raise ValidationError(
            "ERR_TYPE_MISMATCH",
            f"Summary record (line {line_no}) field 'failures' must be list",
            line_no=line_no,
        )
    if not isinstance(rec["skipped"], list):
        raise ValidationError(
            "ERR_TYPE_MISMATCH",
            f"Summary record (line {line_no}) field 'skipped' must be list",
            line_no=line_no,
        )
    _check_duration(rec["duration_ms"], "duration_ms", line_no, allow_float=False)
    if not isinstance(rec["log_path"], str):
        raise ValidationError(
            "ERR_TYPE_MISMATCH",
            f"Summary record (line {line_no}) field 'log_path' must be str",
            line_no=line_no,
        )
    if not isinstance(rec["repro"], str):
        raise ValidationError(
            "ERR_TYPE_MISMATCH",
            f"Summary record (line {line_no}) field 'repro' must be str",
            line_no=line_no,
        )


def validate_step_record(rec, line_no):
    required = [
        "ts",
        "script",
        "bead",
        "step",
        "cmd",
        "exit",
        "duration_ms",
        "expected",
        "observed",
        "digest",
        "stdout_sha256",
        "stdout_excerpt",
        "stderr_excerpt",
        "verdict",
        "repro",
    ]
    for req in required:
        if req not in rec:
            raise ValidationError(
                "ERR_MISSING_REQUIRED_FIELD",
                f"Step record (line {line_no}) missing required field '{req}'",
                line_no=line_no,
            )

    if not isinstance(rec["ts"], str):
        raise ValidationError(
            "ERR_TYPE_MISMATCH",
            f"Step record (line {line_no}) field 'ts' must be str",
            line_no=line_no,
        )
    if not isinstance(rec["script"], str):
        raise ValidationError(
            "ERR_TYPE_MISMATCH",
            f"Step record (line {line_no}) field 'script' must be str",
            line_no=line_no,
        )
    if not isinstance(rec["bead"], str):
        raise ValidationError(
            "ERR_TYPE_MISMATCH",
            f"Step record (line {line_no}) field 'bead' must be str",
            line_no=line_no,
        )
    if not isinstance(rec["step"], str):
        raise ValidationError(
            "ERR_TYPE_MISMATCH",
            f"Step record (line {line_no}) field 'step' must be str",
            line_no=line_no,
        )
    if not isinstance(rec["cmd"], (str, list)):
        raise ValidationError(
            "ERR_TYPE_MISMATCH",
            f"Step record (line {line_no}) field 'cmd' must be str or list",
            line_no=line_no,
        )
    _strict_int(rec["exit"], "exit", line_no)
    _check_duration(rec["duration_ms"], "duration_ms", line_no, allow_float=True)

    verdict = rec["verdict"]
    if verdict not in STEP_VERDICTS:
        raise ValidationError(
            "ERR_INVALID_VERDICT",
            f"Step record (line {line_no}) invalid verdict '{verdict}', must be one of {sorted(STEP_VERDICTS)}",
            line_no=line_no,
        )

    stdout_sha256 = rec.get("stdout_sha256")
    if stdout_sha256 and (not isinstance(stdout_sha256, str) or not HEX_64_PATTERN.match(stdout_sha256)):
        raise ValidationError(
            "ERR_INVALID_HEX_DIGEST",
            f"Step record (line {line_no}) field 'stdout_sha256' must be 64 hex characters",
            line_no=line_no,
        )

    digest = rec.get("digest")
    if digest and (not isinstance(digest, str) or not HEX_64_PATTERN.match(digest)):
        raise ValidationError(
            "ERR_INVALID_HEX_DIGEST",
            f"Step record (line {line_no}) field 'digest' must be 64 hex characters",
            line_no=line_no,
        )

    stdout_excerpt = rec.get("stdout_excerpt", "")
    if not isinstance(stdout_excerpt, str):
        raise ValidationError(
            "ERR_TYPE_MISMATCH",
            f"Step record (line {line_no}) field 'stdout_excerpt' must be str",
            line_no=line_no,
        )
    stdout_bytes = len(stdout_excerpt.encode("utf-8"))
    if stdout_bytes > MAX_EXCERPT_BYTES:
        raise ValidationError(
            "ERR_EXCERPT_CAP_EXCEEDED",
            f"Step record (line {line_no}) stdout_excerpt exceeds 4 KiB cap ({stdout_bytes} bytes > {MAX_EXCERPT_BYTES})",
            line_no=line_no,
        )

    stderr_excerpt = rec.get("stderr_excerpt", "")
    if not isinstance(stderr_excerpt, str):
        raise ValidationError(
            "ERR_TYPE_MISMATCH",
            f"Step record (line {line_no}) field 'stderr_excerpt' must be str",
            line_no=line_no,
        )
    stderr_bytes = len(stderr_excerpt.encode("utf-8"))
    if stderr_bytes > MAX_EXCERPT_BYTES:
        raise ValidationError(
            "ERR_EXCERPT_CAP_EXCEEDED",
            f"Step record (line {line_no}) stderr_excerpt exceeds 4 KiB cap ({stderr_bytes} bytes > {MAX_EXCERPT_BYTES})",
            line_no=line_no,
        )

    if not isinstance(rec["repro"], str):
        raise ValidationError(
            "ERR_TYPE_MISMATCH",
            f"Step record (line {line_no}) field 'repro' must be str",
            line_no=line_no,
        )


def _json_object_pairs_hook(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValidationError("ERR_DUPLICATE_KEY", f"Duplicate JSON key '{k}' found in record")
        d[k] = v
    return d


def validate_file(file_path: Path):
    """Validates a single log file."""
    try:
        size = file_path.stat().st_size
    except Exception as e:
        raise ValidationError("ERR_FILE_ACCESS", f"Cannot stat '{file_path}': {e}") from e

    if size > MAX_FILE_BYTES:
        raise ValidationError(
            "ERR_FILE_CAP_EXCEEDED",
            f"Log file '{file_path}' exceeds 10 MiB cap ({size} bytes > {MAX_FILE_BYTES})",
        )

    try:
        with open(file_path, "rb") as f:
            raw_bytes = f.read()
    except Exception as e:
        raise ValidationError("ERR_FILE_ACCESS", f"Cannot read '{file_path}': {e}") from e

    if not raw_bytes:
        raise ValidationError("ERR_EMPTY_FILE", f"Log file '{file_path}' is empty")

    if b"\r" in raw_bytes:
        raise ValidationError(
            "ERR_CRLF_LINE_ENDING",
            f"Log file '{file_path}' contains carriage return (CR/CRLF) line endings",
        )

    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ValidationError(
            "ERR_INVALID_UTF8",
            f"Log file '{file_path}' contains invalid UTF-8 bytes: {e}",
        ) from e

    # Check line lengths
    for l_idx, raw_line in enumerate(raw_bytes.split(b"\n"), start=1):
        if len(raw_line) > MAX_LINE_BYTES:
            raise ValidationError(
                "ERR_LINE_TOO_LONG",
                f"Line {l_idx} in '{file_path}' exceeds per-line cap ({len(raw_line)} bytes > {MAX_LINE_BYTES})",
                line_no=l_idx,
            )

    # Split lines, allowing trailing newline
    if text.endswith("\n"):
        text = text[:-1]

    raw_lines = text.split("\n")
    if not raw_lines or (len(raw_lines) == 1 and not raw_lines[0].strip()):
        raise ValidationError("ERR_EMPTY_FILE", f"Log file '{file_path}' is empty")

    step_records = []
    seen_step_ids = set()
    summary_record = None
    summary_line_no = None

    for idx, raw_line in enumerate(raw_lines, start=1):
        if not raw_line or not raw_line.strip():
            raise ValidationError(
                "ERR_EMPTY_LINE",
                f"Empty or whitespace-only line encountered at line {idx}",
                line_no=idx,
                line=raw_line,
            )

        try:
            rec = json.loads(raw_line, object_pairs_hook=_json_object_pairs_hook)
        except ValidationError as ve:
            ve.line_no = idx
            ve.line = raw_line
            raise ve
        except Exception as e:
            raise ValidationError(
                "ERR_INVALID_JSON",
                f"Invalid JSON at line {idx}: {e}",
                line_no=idx,
                line=raw_line,
            ) from e

        if not isinstance(rec, dict):
            raise ValidationError(
                "ERR_NOT_JSON_OBJECT",
                f"Record at line {idx} is not a JSON object",
                line_no=idx,
                line=raw_line,
            )

        try:
            check_no_secret_keys(rec)

            step = rec.get("step")
            if not step or not isinstance(step, str):
                raise ValidationError(
                    "ERR_SCHEMA_VIOLATION",
                    f"Record at line {idx} missing valid 'step' string",
                    line_no=idx,
                    line=raw_line,
                )

            if idx == 1:
                if step != "env":
                    raise ValidationError(
                        "ERR_ENV_NOT_FIRST",
                        f"First record must be an 'env' record, got '{step}'",
                        line_no=idx,
                        line=raw_line,
                    )
                validate_env_record(rec, idx)
            elif idx == len(raw_lines):
                if step != "summary":
                    raise ValidationError(
                        "ERR_MISSING_SUMMARY",
                        f"Last record must be a 'summary' record, got '{step}'",
                        line_no=idx,
                        line=raw_line,
                    )
                validate_summary_record(rec, idx)
                summary_record = rec
                summary_line_no = idx
            else:
                if step == "summary":
                    raise ValidationError(
                        "ERR_MULTIPLE_SUMMARIES",
                        f"Summary record found at line {idx} before the last record",
                        line_no=idx,
                        line=raw_line,
                    )
                if step == "env":
                    raise ValidationError(
                        "ERR_ENV_NOT_FIRST",
                        f"Env record found at line {idx} (only allowed at line 1)",
                        line_no=idx,
                        line=raw_line,
                    )
                if step in seen_step_ids:
                    raise ValidationError(
                        "ERR_DUPLICATE_STEP_ID",
                        f"Duplicate step id '{step}' found at line {idx}",
                        line_no=idx,
                        line=raw_line,
                    )
                seen_step_ids.add(step)
                validate_step_record(rec, idx)
                step_records.append(rec)
        except ValidationError as ve:
            if ve.line is None:
                ve.line = raw_line
            if ve.line_no is None:
                ve.line_no = idx
            raise ve

    if summary_record is None:
        raise ValidationError(
            "ERR_MISSING_SUMMARY",
            f"Log file '{file_path}' does not end with a 'summary' record",
        )

    # Consistency checks between step records and summary record
    summary_verdict = summary_record["verdict"]
    summary_steps = summary_record["steps"]
    summary_failures = summary_record["failures"]

    # 1. steps equals the number of step records
    if summary_steps != len(step_records):
        raise ValidationError(
            "ERR_SUMMARY_INCONSISTENCY",
            f"Summary steps count {summary_steps} does not equal number of step records {len(step_records)}",
            line_no=summary_line_no,
        )

    # 2. at least one non-skip record
    non_skip_count = sum(1 for r in step_records if r["verdict"] != "skip")
    if non_skip_count == 0:
        raise ValidationError(
            "ERR_ALL_STEPS_SKIPPED",
            "At least one non-skip step record is required; all steps are skipped",
            line_no=summary_line_no,
        )

    # 3. pass implies no fail verdicts and an empty failures list
    failed_steps = [r["step"] for r in step_records if r["verdict"] == "fail"]
    if summary_verdict == "pass":
        if failed_steps:
            raise ValidationError(
                "ERR_SUMMARY_INCONSISTENCY",
                f"Summary verdict is 'pass' but step records contain failed steps: {failed_steps}",
                line_no=summary_line_no,
            )
        if summary_failures:
            raise ValidationError(
                "ERR_SUMMARY_INCONSISTENCY",
                f"Summary verdict is 'pass' but failures list is non-empty: {summary_failures}",
                line_no=summary_line_no,
            )
    elif summary_verdict == "fail":
        if not summary_failures:
            raise ValidationError(
                "ERR_SUMMARY_INCONSISTENCY",
                "Summary verdict is 'fail' but summary failures list is empty",
                line_no=summary_line_no,
            )


def find_log_files(target: Path):
    if target.is_file():
        return [target]
    if target.is_dir():
        files = []
        for p in sorted(target.rglob("*")):
            # Skip temp directories created by e2e_tmpdir (tmp_* relative to target)
            try:
                rel_parts = p.relative_to(target).parts
                if any(part.startswith("tmp_") for part in rel_parts):
                    continue
            except Exception:
                pass
            if p.is_file() and (p.suffix in {".log", ".jsonl"} or p.name.startswith("run_")):
                files.append(p)
        return files
    raise ValidationError("ERR_TARGET_NOT_FOUND", f"Target path does not exist: {target}")


def main():
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: validate_log.py <log-dir-or-file> [more-paths...]\n")
        sys.exit(2)

    all_files = []
    for arg in sys.argv[1:]:
        target = Path(arg)
        try:
            files = find_log_files(target)
            if not files and target.is_dir():
                sys.stderr.write(f"Error: No log files found in directory '{target}'\n")
                sys.exit(1)
            all_files.extend(files)
        except ValidationError as exc:
            sys.stderr.write(f"VALIDATION_ERROR [{exc.code}]: {exc.message}\n")
            sys.exit(1)

    if not all_files:
        sys.stderr.write("Error: No log files found to validate\n")
        sys.exit(1)

    for file_path in all_files:
        try:
            validate_file(file_path)
            print(f"PASS: {file_path}")
        except ValidationError as exc:
            sys.stderr.write(f"VALIDATION_ERROR [{exc.code}]: {exc.message}\n")
            if exc.line:
                sys.stderr.write(f"Offending line: {exc.line.strip()}\n")
            sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()

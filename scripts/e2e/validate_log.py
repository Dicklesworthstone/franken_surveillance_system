#!/usr/bin/env python3
"""E2E log validator for CAP- structured JSON-lines logs.

Validates that every record in an E2E log file adheres to the unified record schema,
enforces 4 KiB excerpt caps, 10 MiB total file cap, verdict enums, and ensures no
keys resemble secrets.
"""

import json
import os
import re
import sys
from pathlib import Path

MAX_EXCERPT_BYTES = 4096
MAX_FILE_BYTES = 10 * 1024 * 1024  # 10 MiB

SECRET_KEY_PATTERN = re.compile(r"authorization|password|token|secret|cookie", re.IGNORECASE)
STEP_VERDICTS = {"ran", "pass", "fail", "skip"}
SUMMARY_VERDICTS = {"pass", "fail"}


class ValidationError(Exception):
    def __init__(self, message, line=None):
        super().__init__(message)
        self.line = line


def check_no_secret_keys(data, path=""):
    """Recursively checks that no key name in data looks like a secret."""
    if isinstance(data, dict):
        for k, v in data.items():
            k_str = str(k)
            if SECRET_KEY_PATTERN.search(k_str):
                loc = f"{path}.{k_str}" if path else k_str
                raise ValidationError(f"Forbidden secret-like key '{loc}' found in record")
            check_no_secret_keys(v, f"{path}.{k_str}" if path else k_str)
    elif isinstance(data, list):
        for idx, item in enumerate(data):
            check_no_secret_keys(item, f"{path}[{idx}]")


def validate_env_record(rec, line_no):
    required = ["step", "script", "bead", "git_sha", "dirty", "host", "bins", "fss_env"]
    for req in required:
        if req not in rec:
            raise ValidationError(f"Env record (line {line_no}) missing required field '{req}'")

    if rec["step"] != "env":
        raise ValidationError(f"Env record (line {line_no}) has step != 'env'")
    if not isinstance(rec["script"], str):
        raise ValidationError(f"Env record (line {line_no}) field 'script' must be str")
    if not isinstance(rec["bead"], str):
        raise ValidationError(f"Env record (line {line_no}) field 'bead' must be str")
    if not isinstance(rec["git_sha"], str):
        raise ValidationError(f"Env record (line {line_no}) field 'git_sha' must be str")
    if not isinstance(rec["dirty"], bool):
        raise ValidationError(f"Env record (line {line_no}) field 'dirty' must be bool")
    if not isinstance(rec["host"], str):
        raise ValidationError(f"Env record (line {line_no}) field 'host' must be str")
    if not isinstance(rec["bins"], list):
        raise ValidationError(f"Env record (line {line_no}) field 'bins' must be list")
    if not isinstance(rec["fss_env"], dict):
        raise ValidationError(f"Env record (line {line_no}) field 'fss_env' must be dict")


def validate_summary_record(rec, line_no):
    required = ["step", "verdict", "steps", "failures", "repro"]
    for req in required:
        if req not in rec:
            raise ValidationError(f"Summary record (line {line_no}) missing required field '{req}'")

    if rec["step"] != "summary":
        raise ValidationError(f"Summary record (line {line_no}) has step != 'summary'")
    if rec["verdict"] not in SUMMARY_VERDICTS:
        raise ValidationError(
            f"Summary record (line {line_no}) invalid verdict '{rec.get('verdict')}', must be one of {sorted(SUMMARY_VERDICTS)}"
        )
    if not isinstance(rec["steps"], int):
        raise ValidationError(f"Summary record (line {line_no}) field 'steps' must be int")
    if not isinstance(rec["failures"], list):
        raise ValidationError(f"Summary record (line {line_no}) field 'failures' must be list")
    if not isinstance(rec["repro"], str):
        raise ValidationError(f"Summary record (line {line_no}) field 'repro' must be str")


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
            raise ValidationError(f"Step record (line {line_no}) missing required field '{req}'")

    if not isinstance(rec["ts"], str):
        raise ValidationError(f"Step record (line {line_no}) field 'ts' must be str")
    if not isinstance(rec["script"], str):
        raise ValidationError(f"Step record (line {line_no}) field 'script' must be str")
    if not isinstance(rec["bead"], str):
        raise ValidationError(f"Step record (line {line_no}) field 'bead' must be str")
    if not isinstance(rec["step"], str):
        raise ValidationError(f"Step record (line {line_no}) field 'step' must be str")
    if not isinstance(rec["cmd"], (str, list)):
        raise ValidationError(f"Step record (line {line_no}) field 'cmd' must be str or list")
    if not isinstance(rec["exit"], int):
        raise ValidationError(f"Step record (line {line_no}) field 'exit' must be int")
    if not isinstance(rec["duration_ms"], (int, float)):
        raise ValidationError(f"Step record (line {line_no}) field 'duration_ms' must be int or float")

    verdict = rec["verdict"]
    if verdict not in STEP_VERDICTS:
        raise ValidationError(
            f"Step record (line {line_no}) invalid verdict '{verdict}', must be one of {sorted(STEP_VERDICTS)}"
        )

    stdout_excerpt = rec.get("stdout_excerpt", "")
    if not isinstance(stdout_excerpt, str):
        raise ValidationError(f"Step record (line {line_no}) field 'stdout_excerpt' must be str")
    stdout_bytes = len(stdout_excerpt.encode("utf-8"))
    if stdout_bytes > MAX_EXCERPT_BYTES:
        raise ValidationError(
            f"Step record (line {line_no}) stdout_excerpt exceeds 4 KiB cap ({stdout_bytes} bytes > {MAX_EXCERPT_BYTES})"
        )

    stderr_excerpt = rec.get("stderr_excerpt", "")
    if not isinstance(stderr_excerpt, str):
        raise ValidationError(f"Step record (line {line_no}) field 'stderr_excerpt' must be str")
    stderr_bytes = len(stderr_excerpt.encode("utf-8"))
    if stderr_bytes > MAX_EXCERPT_BYTES:
        raise ValidationError(
            f"Step record (line {line_no}) stderr_excerpt exceeds 4 KiB cap ({stderr_bytes} bytes > {MAX_EXCERPT_BYTES})"
        )

    if not isinstance(rec["repro"], str):
        raise ValidationError(f"Step record (line {line_no}) field 'repro' must be str")


def validate_file(file_path: Path):
    """Validates a single log file."""
    size = file_path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise ValidationError(
            f"Log file '{file_path}' exceeds 10 MiB cap ({size} bytes > {MAX_FILE_BYTES})"
        )

    with open(file_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    if not lines:
        raise ValidationError(f"Log file '{file_path}' is empty")

    last_step = None
    for idx, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line:
            raise ValidationError(f"Empty line encountered at line {idx}", line=raw_line)

        try:
            rec = json.loads(line)
        except Exception as e:
            raise ValidationError(f"Invalid JSON at line {idx}: {e}", line=raw_line) from e

        if not isinstance(rec, dict):
            raise ValidationError(f"Record at line {idx} is not a JSON object", line=raw_line)

        try:
            check_no_secret_keys(rec)

            step = rec.get("step")
            if not step or not isinstance(step, str):
                raise ValidationError(f"Record at line {idx} missing valid 'step' string", line=raw_line)

            if idx == 1:
                if step != "env":
                    raise ValidationError(f"First record must be an 'env' record, got '{step}'", line=raw_line)
                validate_env_record(rec, idx)
            elif step == "summary":
                validate_summary_record(rec, idx)
            else:
                validate_step_record(rec, idx)

            last_step = step
        except ValidationError as ve:
            if ve.line is None:
                ve.line = raw_line
            raise ve

    if last_step != "summary":
        raise ValidationError(f"Log file '{file_path}' does not end with a 'summary' record (last record was '{last_step}')")


def find_log_files(target: Path):
    if target.is_file():
        return [target]
    if target.is_dir():
        files = []
        for p in sorted(target.rglob("*")):
            # Skip temp directories created by e2e_tmpdir
            if "tmp" in p.parts:
                continue
            if p.is_file() and (p.suffix in {".log", ".jsonl"} or p.name.startswith("run_")):
                files.append(p)
        return files
    raise ValidationError(f"Target path does not exist: {target}")


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
            sys.stderr.write(f"VALIDATION_ERROR: {exc}\n")
            sys.exit(1)

    if not all_files:
        sys.stderr.write("Error: No log files found to validate\n")
        sys.exit(1)

    for file_path in all_files:
        try:
            validate_file(file_path)
            print(f"PASS: {file_path}")
        except ValidationError as exc:
            sys.stderr.write(f"VALIDATION_ERROR: {exc}\n")
            if exc.line:
                sys.stderr.write(f"Offending line: {exc.line.strip()}\n")
            sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""scripts/e2e/runner_verdict.py

Verdict half of scripts/e2e/run.sh (fss-2h5zq.1). The runner executes a CAP- e2e script as a child
process in a fresh, private log directory and then calls this judge. The verdict comes from the
log the child left, never from the child's exit status alone: a script can disarm its own EXIT
trap (``builtin trap - EXIT``, a redefined ``trap`` function, ``exec``) and leave with status 0,
but it cannot make a missing or failing summary look like a pass here.

PASS requires all of:

* the child exited 0;
* the run directory holds exactly one ``<suite>/run_*.log``;
* that log passes ``validate_log.validate_file`` (env first, exactly one summary and it is last,
  summary consistent with the step records, caps, no secrets);
* the summary verdict is ``pass`` with empty ``failures`` and ``run_failures`` and no truncation;
* no step record has verdict ``fail``, and no harness/malformed record is present;
* at least one record passed or ran;
* the summary's ``log_path`` names that same log.

Anything else is FAIL, with every reason listed. Output: one JSON object on stdout; exit 0 for
PASS, 1 for FAIL, 2 for usage errors. The object is also written to ``runner_verdict.json`` in the
run directory.
"""

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from validate_log import ValidationError, validate_file  # noqa: E402

HARNESS_STEP_PREFIXES = ("harness_", "malformed_caplog")


def judge(run_dir: Path, child_exit: int) -> tuple[list[str], str | None]:
    reasons: list[str] = []
    if child_exit != 0:
        reasons.append(f"child_exit_{child_exit}")

    logs = sorted(p for p in run_dir.glob("*/run_*.log") if p.is_file())
    stray = sorted(p for p in run_dir.rglob("run_*.log")
                   if p.is_file() and p not in logs
                   and not any(part.startswith("tmp_") for part in p.relative_to(run_dir).parts))
    if stray:
        reasons.append(f"unexpected_log_files:{len(stray)}")
    if len(logs) != 1:
        reasons.append(f"expected_exactly_one_log_found_{len(logs)}")
        return reasons, None
    log = logs[0]

    try:
        validate_file(log)
    except ValidationError as err:
        reasons.append(f"log_invalid:{err.code}:{err.message}")

    records = []
    try:
        for line in log.read_text(encoding="utf-8").splitlines():
            records.append(json.loads(line))
    except (OSError, UnicodeDecodeError, ValueError) as err:
        reasons.append(f"log_unreadable:{err}")
        return reasons, str(log)

    summaries = [r for r in records if isinstance(r, dict) and r.get("step") == "summary"]
    if len(summaries) != 1:
        reasons.append(f"expected_exactly_one_summary_found_{len(summaries)}")
    if not records or not isinstance(records[-1], dict) or records[-1].get("step") != "summary":
        reasons.append("log_does_not_end_with_summary")
    else:
        summary = records[-1]
        if summary.get("verdict") != "pass":
            reasons.append(f"summary_verdict_{summary.get('verdict')}")
        if summary.get("failures"):
            reasons.append(f"summary_failures:{len(summary['failures'])}")
        if summary.get("run_failures"):
            reasons.append("summary_run_failures:" + ",".join(map(str, summary["run_failures"])))
        for field in ("failures_truncated", "skipped_truncated", "preserved_tmpdirs_truncated"):
            if summary.get(field):
                reasons.append(f"summary_{field}")
        log_path = summary.get("log_path")
        if not isinstance(log_path, str) or not log_path or \
                os.path.realpath(log_path) != os.path.realpath(log):
            reasons.append("summary_log_path_mismatch")

    steps = [r for r in records[1:] if isinstance(r, dict) and r.get("step") not in ("env", "summary")]
    failed = [r.get("step") for r in steps if r.get("verdict") == "fail"]
    if failed:
        reasons.append(f"fail_records:{len(failed)}")
    harness = [r.get("step") for r in steps
               if isinstance(r.get("step"), str) and r["step"].startswith(HARNESS_STEP_PREFIXES)]
    if harness:
        reasons.append(f"harness_or_malformed_records:{len(harness)}")
    unknown = [r.get("step") for r in steps if r.get("verdict") not in ("pass", "ran", "skip", "fail")]
    if unknown:
        reasons.append(f"records_without_known_verdict:{len(unknown)}")
    if not any(r.get("verdict") in ("pass", "ran") for r in steps):
        reasons.append("no_passing_or_ran_records")
    return reasons, str(log)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--child-exit", required=True, type=int)
    parser.add_argument("--script", required=True)
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    if not run_dir.is_dir():
        print(f"runner_verdict: run directory missing: {run_dir}", file=sys.stderr)
        return 2
    reasons, log = judge(run_dir, args.child_exit)
    verdict = "pass" if not reasons else "fail"
    result = {
        "runner_verdict": verdict,
        "script": args.script,
        "child_exit": args.child_exit,
        "log": log,
        "reasons": reasons,
    }
    text = json.dumps(result, sort_keys=True)
    try:
        (run_dir / "runner_verdict.json").write_text(text + "\n", encoding="utf-8")
    except OSError as err:
        print(f"runner_verdict: could not write runner_verdict.json: {err}", file=sys.stderr)
        verdict = "fail"
    print(text)
    return 0 if verdict == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())

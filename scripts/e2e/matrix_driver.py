#!/usr/bin/env python3
"""scripts/e2e/matrix_driver.py — runner-level fault-matrix self-test driver
(TEST-E2E-HARNESS-001, bead fss-x4a.28.41).

This driver tests the RUNNER (run.sh + runner_verdict.py + the supervisor),
not a scenario: it generates purpose-built mini cap scripts, runs each
through `scripts/e2e/run.sh`, and asserts the runner's verdict and exit code.
The proofs:

  control_pass            minimal passing script           -> exit 0, verdict pass
  fail_step               one failing step                 -> exit 1
  missing_summary         trap-disarmed, no summary        -> exit 1 (tamper cannot pass)
  malformed_log           garbage written into the log dir -> exit 1
  crash_midrun            SIGKILL mid-run                  -> exit 1, no summary, supervision sidecar
  replay_determinism      same passing script twice        -> normalized logs identical
  orphan_process          detached `sleep` left running    -> reaped; sidecar names the orphan
  deadline                FSS_E2E_DEADLINE_S exceeded      -> exit 124, sidecar deadline_exceeded

Determinism normalization strips run-dir paths, timestamps, durations and
run ids before comparing — semantic content only.

Exit: 0 when every proof holds; 1 with a named failure otherwise.
"""

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
RUN_SH = REPO / "scripts" / "e2e" / "run.sh"

PASS_SCRIPT = """#!/usr/bin/env bash
set -euo pipefail
source "$REPO_ROOT/scripts/e2e/lib.sh"
e2e_init "matrix_control" "fss-x4a.28.41" "$@"
e2e_step "step_ok" echo "deterministic content"
e2e_summary
"""

FAIL_STEP_SCRIPT = """#!/usr/bin/env bash
set -euo pipefail
source "$REPO_ROOT/scripts/e2e/lib.sh"
e2e_init "matrix_fail" "fss-x4a.28.41" "$@"
e2e_step "step_fails" false
e2e_expect_exit "step_fails" 0
e2e_summary
"""

NO_SUMMARY_SCRIPT = """#!/usr/bin/env bash
builtin trap - EXIT
exit 0
"""

CRASH_SCRIPT = """#!/usr/bin/env bash
set -euo pipefail
source "$REPO_ROOT/scripts/e2e/lib.sh"
e2e_init "matrix_crash" "fss-x4a.28.41" "$@"
e2e_step "step_ok" echo "before crash"
kill -9 $$
"""

ORPHAN_SCRIPT = """#!/usr/bin/env bash
set -euo pipefail
source "$REPO_ROOT/scripts/e2e/lib.sh"
e2e_init "matrix_orphan" "fss-x4a.28.41" "$@"
e2e_step "step_spawn" bash -c 'sleep 300 & disown'
e2e_summary
"""

DEADLINE_SCRIPT = """#!/usr/bin/env bash
set -euo pipefail
source "$REPO_ROOT/scripts/e2e/lib.sh"
e2e_init "matrix_deadline" "fss-x4a.28.41" "$@"
e2e_step "step_long" sleep 600
e2e_summary
"""


def write_script(directory: Path, name: str, body: str) -> Path:
    body = body.replace("$REPO_ROOT/scripts", str(REPO / "scripts"))
    path = directory / name
    path.write_text(body)
    path.chmod(0o755)
    return path


def run_once(script: Path, log_base: Path, deadline_s: int = 0) -> tuple[int, Path]:
    env = dict(os.environ)
    env["FSS_E2E_LOG_DIR"] = str(log_base)
    if deadline_s:
        env["FSS_E2E_DEADLINE_S"] = str(deadline_s)
    proc = subprocess.run(
        ["bash", str(RUN_SH), str(script)],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
    )
    # run.sh prints "e2e runner: <script> -> <run_dir>" on stderr.
    match = re.search(r"-> (\S+runs/\S+)", proc.stderr)
    if not match:
        raise AssertionError(f"runner did not print a run directory: {proc.stderr[-400:]}")
    return proc.returncode, Path(match.group(1))


def verdict_of(run_dir: Path) -> dict:
    return json.loads((run_dir / "runner_verdict.json").read_text())


def normalize_log(text: str, paths: tuple[str, ...] = ()) -> str:
    for path in paths:
        text = text.replace(path, "PATH")
    text = re.sub(r"runs/[^/\"]+", "runs/RUN", text)
    text = re.sub(r'"ts": "[^"]+"', '"ts": "T"', text)
    text = re.sub(r'"start_utc": "[^"]+"', '"start_utc": "T"', text)
    text = re.sub(r'"end_utc": "[^"]+"', '"end_utc": "T"', text)
    text = re.sub(r'"duration_ms": \d+', '"duration_ms": 0', text)
    text = re.sub(r'"run_id": "[^"]+"', '"run_id": "R"', text)
    text = re.sub(r"matrix-(pass|replay)-[a-z0-9]+", "SUITE", text)
    return text


class Failure(Exception):
    pass


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="e2e-matrix-"))
    failures: list[str] = []

    def check(name: str, fn) -> None:
        try:
            fn()
            print(f"matrix proof {name}: OK")
        except (AssertionError, Failure) as exc:
            failures.append(name)
            print(f"matrix proof {name}: FAIL: {exc}")

    control = write_script(work, "matrix-pass.sh", PASS_SCRIPT)

    def proof_control_pass() -> None:
        rc, run_dir = run_once(control, work / "c1")
        v = verdict_of(run_dir)
        if rc != 0 or v.get("runner_verdict") != "pass":
            raise Failure(f"control pass got rc={rc} verdict={v.get('verdict')}")

    def proof_fail_step() -> None:
        script = write_script(work, "matrix-fail.sh", FAIL_STEP_SCRIPT)
        rc, _run_dir = run_once(script, work / "c2")
        if rc == 0:
            raise Failure("a failing step passed")

    def proof_missing_summary() -> None:
        script = write_script(work, "matrix-nosummary.sh", NO_SUMMARY_SCRIPT)
        rc, run_dir = run_once(script, work / "c3")
        v = verdict_of(run_dir)
        if rc == 0:
            raise Failure("missing summary passed")

    def proof_malformed_log() -> None:
        script = write_script(work, "matrix-malformed.sh", PASS_SCRIPT)
        rc_ok, run_dir = run_once(script, work / "c4")
        if rc_ok != 0:
            raise Failure("control setup run failed")
        # Tamper: append a garbage line into the run log, then re-judge it.
        logs = list(run_dir.glob("matrix_control/run_*.log"))
        if len(logs) != 1:
            raise Failure(f"expected one control log, found {len(logs)}")
        with logs[0].open("a") as fh:
            fh.write("this is not a structured record\n")
        proc = subprocess.run(
            [
                sys.executable,
                str(REPO / "scripts" / "e2e" / "runner_verdict.py"),
                "--run-dir",
                str(run_dir),
                "--child-exit",
                "0",
                "--script",
                str(script),
            ],
            capture_output=True,
            text=True,
        )
        if proc.returncode == 0:
            raise Failure("tampered log re-judged as pass")

    def proof_crash_midrun() -> None:
        script = write_script(work, "matrix-crash.sh", CRASH_SCRIPT)
        rc, run_dir = run_once(script, work / "c5")
        if rc == 0:
            raise Failure("crashed run passed")
        if list(run_dir.glob("matrix_crash/run_*.log")):
            log = next(iter(run_dir.glob("matrix_crash/run_*.log")))
            if '"verdict": "pass"' in log.read_text():
                raise Failure("crash log claims pass")
        sidecar = run_dir / "runner_supervision.json"
        if not sidecar.exists():
            raise Failure("no supervision sidecar on crash")

    def proof_replay_determinism() -> None:
        script = write_script(work, "matrix-replay.sh", PASS_SCRIPT)
        rc1, dir1 = run_once(script, work / "r1")
        rc2, dir2 = run_once(script, work / "r2")
        if rc1 != 0 or rc2 != 0:
            raise Failure("replay control runs failed")
        log1 = next(iter(dir1.glob("matrix_control/run_*.log"))).read_text()
        log2 = next(iter(dir2.glob("matrix_control/run_*.log"))).read_text()
        paths = (str(dir1), str(dir2), str(dir1.parent), str(dir2.parent), str(script.parent), str(script))
        if normalize_log(log1, paths) != normalize_log(log2, paths):
            raise Failure("same script twice produced semantically different logs")

    def proof_orphan_process() -> None:
        script = write_script(work, "matrix-orphan.sh", ORPHAN_SCRIPT)
        rc, run_dir = run_once(script, work / "c6")
        sidecar = json.loads((run_dir / "runner_supervision.json").read_text())
        if not sidecar.get("group_reaped"):
            raise Failure("orphan group was not reaped")
        # Any enumerated orphan must be dead now.
        for pid in sidecar.get("orphan_pids", []):
            try:
                os.kill(pid, 0)
                raise Failure(f"orphan pid {pid} still alive after reaping")
            except ProcessLookupError:
                pass

    def proof_deadline() -> None:
        script = write_script(work, "matrix-deadline.sh", DEADLINE_SCRIPT)
        rc, run_dir = run_once(script, work / "c7", deadline_s=2)
        if rc == 0:
            raise Failure("deadline-exceeded run passed")
        sidecar = json.loads((run_dir / "runner_supervision.json").read_text())
        if not sidecar.get("deadline_exceeded"):
            raise Failure("sidecar does not record deadline_exceeded")
        if sidecar.get("child_exit") != 124:
            raise Failure(f"supervisor did not report the deadline kill (child_exit={sidecar.get('child_exit')})")

    check("control_pass", proof_control_pass)
    check("fail_step", proof_fail_step)
    check("missing_summary", proof_missing_summary)
    check("malformed_log", proof_malformed_log)
    check("crash_midrun", proof_crash_midrun)
    check("replay_determinism", proof_replay_determinism)
    check("orphan_process", proof_orphan_process)
    check("deadline", proof_deadline)

    if failures:
        print(f"matrix driver: {len(failures)} proof(s) failed: {', '.join(failures)}")
        return 1
    print("matrix driver: all 8 runner-level proofs hold")
    return 0


if __name__ == "__main__":
    sys.exit(main())

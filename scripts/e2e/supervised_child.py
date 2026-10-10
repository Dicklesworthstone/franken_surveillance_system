#!/usr/bin/env python3
"""scripts/e2e/supervised_child.py — the e2e runner's child supervisor
(TEST-E2E-HARNESS-001, bead fss-x4a.28.41).

The runner executes every scenario through this supervisor so that two
contract behaviors hold for EVERY script, not just well-behaved ones:

1. Deadline: when FSS_E2E_DEADLINE_S is set (>0 seconds), a child that
   exceeds the budget is killed (its whole process group) and the run is
   recorded as deadline-exceeded. An expired deadline is never a PASS: the
   run log then lacks a summary and the existing verdict rules fail it.
2. No orphan processes: the child runs in a NEW process group; when the
   child exits (normally, by failure, or by deadline kill), every surviving
   member of the group is SIGTERM-then-SIGKILL reaped and the reaped set is
   recorded. A scenario that leaks a background process is surfaced, never
   silently left running.

Portable: POSIX only (macOS has no setsid(1)); uses os.setsid in the child
via preexec_fn. Writes a `runner_supervision.json` sidecar into the run
directory (never a .log — the log belongs to the child).

Exit code: the child's exit code, or 124 on deadline kill (GNU timeout
convention).
"""

import json
import os
import signal
import subprocess
import sys
import time


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: supervised_child.py <command...>", file=sys.stderr)
        return 2
    cmd = sys.argv[1:]
    deadline_s = float(os.environ.get("FSS_E2E_DEADLINE_S", "0") or 0)
    run_dir = os.environ.get("FSS_E2E_LOG_DIR", "")

    start = time.monotonic()
    proc = subprocess.Popen(
        cmd,
        preexec_fn=os.setsid,  # new process group: the group id == child pid
        close_fds=True,
    )
    pgid = proc.pid
    deadline_exceeded = False
    try:
        rc = proc.wait(timeout=deadline_s if deadline_s > 0 else None)
    except subprocess.TimeoutExpired:
        deadline_exceeded = True
        _kill_group(pgid)
        rc = 124

    # Orphan reaping: any group member still alive after the child exits.
    reaped = _reap_group(pgid)
    elapsed_ms = int((time.monotonic() - start) * 1000)

    if run_dir:
        sidecar = os.path.join(run_dir, "runner_supervision.json")
        with open(sidecar, "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "schema": "fss.e2e_runner_supervision.v1",
                    "child_pid": pgid,
                    "child_exit": rc,
                    "deadline_s": deadline_s,
                    "deadline_exceeded": deadline_exceeded,
                    "elapsed_ms": elapsed_ms,
                    "group_reaped": reaped["group_reaped"],
                    "orphan_pids": reaped["pids"],
                    "enumeration": reaped["enumeration"],
                },
                fh,
                sort_keys=True,
            )
            fh.write("\n")
    return rc


def _kill_group(pgid: int) -> None:
    """SIGTERM, brief grace, SIGKILL the whole process group."""
    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        return
    except PermissionError:
        return
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        if not _group_alive(pgid):
            return
        time.sleep(0.02)
    try:
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def _group_alive(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _reap_group(pgid: int) -> dict:
    """Kill any surviving members of the child's process group. Evidence is
    honest about enumeration limits: `enumeration` is "ps" when member pids
    were listed, "unavailable" when enumeration failed but the live group was
    killed regardless (a hanging `ps` must never block reaping)."""
    if not _group_alive(pgid):
        return {"group_reaped": False, "pids": [], "enumeration": "not_needed"}
    members: list[int] = []
    enumeration = "unavailable"
    try:
        out = subprocess.run(
            ["ps", "-eo", "pid=,pgid="], capture_output=True, text=True, timeout=2
        )
        for line in out.stdout.splitlines():
            parts = line.split()
            if len(parts) == 2 and int(parts[1]) == pgid:
                members.append(int(parts[0]))
        enumeration = "ps"
    except (OSError, subprocess.TimeoutExpired, ValueError):
        pass
    _kill_group(pgid)
    return {"group_reaped": True, "pids": members, "enumeration": enumeration}


if __name__ == "__main__":
    sys.exit(main())

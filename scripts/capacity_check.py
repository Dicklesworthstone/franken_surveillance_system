#!/usr/bin/env python3
"""scripts/capacity_check.py — host capacity and quarantine preflight for
qualification lanes (FSS-186, bead fss-x4a.26.6).

A qualification lane that runs under disk pressure corrupts evidence and
produces non-reproducible builds (the 2026-08-14 incident class). This check
gives every lane a typed capacity state instead of silent corruption:

  sufficient   — the capacity probe (sbh, the machine's disk-pressure
                 authority) reports the needed headroom is present;
  insufficient — pressure: the lane must refuse with reclaim guidance (the
                 receipt records the typed non-pass state);
  unavailable  — no capacity authority exists on this host (sbh missing):
                 the lane continues but the receipt records capacity as
                 UNPROVEN — never silently treated as proven;
  error        — the authority itself failed: fail closed for heavy lanes.

Output is one JSON object (the typed state + evidence) on stdout. Exit codes:
0 sufficient, 1 insufficient, 2 unavailable, 3 error. These are stable
identities — callers must not parse prose.
"""

import json
import shutil
import subprocess
import sys

SCHEMA = "fss.capacity_check.v1"


def probe_sbh(need_bytes: int) -> dict:
    """Runs the host's disk-pressure authority (sbh) and maps the result to a
    typed capacity state. sbh is the sanctioned tool for this machine class;
    other hosts report unavailable rather than pretending a probe ran."""
    if shutil.which("sbh") is None:
        return {
            "state": "unavailable",
            "evidence": "sbh not installed on this host; capacity unproven",
        }
    try:
        proc = subprocess.run(
            ["sbh", "check", "--need", str(need_bytes)],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"state": "error", "evidence": f"sbh probe failed: {exc}"}
    # sbh prints one JSON record on stdout; the exit code is the state.
    available = None
    try:
        report = json.loads(proc.stdout.strip().splitlines()[-1])
        available = report.get("container_available_bytes")
    except (ValueError, IndexError, AttributeError):
        pass
    if proc.returncode == 0:
        return {
            "state": "sufficient",
            "evidence": f"sbh reports headroom for {need_bytes} bytes",
            "availableBytes": available,
        }
    return {
        "state": "insufficient",
        "evidence": f"sbh check --need {need_bytes} refused: insufficient headroom; reclaim before qualifying",
        "availableBytes": available,
    }


def main() -> int:
    need = int(sys.argv[1]) if len(sys.argv) > 1 else 10 * 1024**3
    result = probe_sbh(need)
    result["schema"] = SCHEMA
    result["needBytes"] = need
    print(json.dumps(result, sort_keys=True))
    return {"sufficient": 0, "insufficient": 1, "unavailable": 2, "error": 3}[result["state"]]


if __name__ == "__main__":
    sys.exit(main())

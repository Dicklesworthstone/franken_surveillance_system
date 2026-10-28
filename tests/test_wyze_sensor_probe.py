#!/usr/bin/env python3
"""Unit-test wyze_sensor_probe.sh with fake shells (no device, no network).

The script's contract (FLASH-DAY-RUNBOOK.md §0.2 sensor-variant decision
table): read the sensor's i2c address through the unit's root shell —
0x29 = gc4653, 0x3c = os04d10 — map it to the thingino image, and NEVER
write anything (read-only i2c probes). SHELL_CMD overrides the transport,
which is exactly how these tests drive it.

  python3 tests/test_wyze_sensor_probe.py
"""
from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE.parent / "deliverables" / "scripts" / "wyze_sensor_probe.sh"

FAILURES: list[str] = []


def check(cond: bool, what: str) -> None:
    print(("  PASS  " if cond else "  FAIL  ") + what)
    if not cond:
        FAILURES.append(what)


def run(shell_out: str, json: bool = False, shell_rc: int = 0) -> tuple[int, str]:
    d = Path(tempfile.mkdtemp())
    fake = d / "fake-shell.out"
    fake.write_text(shell_out)
    env = dict(os.environ, SHELL_CMD=f"cat {fake}; exit {shell_rc}")
    args = ["sh", str(SCRIPT), "-"] + (["--json"] if json else [])
    p = subprocess.run(args, capture_output=True, text=True, env=env, timeout=30)
    return p.returncode, p.stdout + p.stderr


def main() -> int:
    print("== wyze_sensor_probe unit tests (fake shells)")

    # gc4653 answered on bus 0
    rc, out = run("HIT /dev/i2c-0 0x29 0x00\nPROBE-DONE\n", json=True)
    check(rc == 0 and '"variant":"gc4653"' in out and '"i2c_addr":"0x29"' in out
          and '"chip_header_byte":"0x40"' in out,
          "0x29 -> gc4653 JSON with image + header byte")

    # os04d10 answered on bus 1
    rc, out = run("HIT /dev/i2c-1 0x3c 0x00\nPROBE-DONE\n", json=True)
    check(rc == 0 and '"variant":"os04d10"' in out and '"i2c_addr":"0x3c"' in out
          and '"chip_header_byte":"0x52"' in out,
          "0x3c -> os04d10 JSON with image + header byte")

    # both answered -> deterministic gc4653-first decision, stated in text form
    rc, out = run("HIT /dev/i2c-0 0x29 0x00\nHIT /dev/i2c-1 0x3c 0x00\nPROBE-DONE\n")
    check(rc == 0 and "VARIANT=gc4653" in out,
          "both addresses answered -> gc4653 (first in map) with VARIANT= line")

    # plain (non-JSON) mode names the bus and the record instruction
    rc, out = run("HIT /dev/i2c-0 0x29 0x00\nPROBE-DONE\n")
    check(rc == 0 and "/dev/i2c-0" in out and "FLASH-DAY-RUNBOOK" in out,
          "text mode names the bus and the runbook record instruction")

    # neither answered -> exit 1, actionable message
    rc, out = run("PROBE-DONE\n")
    check(rc == 1 and "neither i2c address answered" in out,
          "no i2c hit -> exit 1 with the asleep/wedged hint")

    # probe script never completed (shell died mid-read) -> exit 1
    rc, out = run("HIT /dev/i2c-0 0x29 0x00\n")
    check(rc == 1 and "did not complete" in out,
          "missing PROBE-DONE -> exit 1 (transport/trace failure)")

    # read-only invariant: the probe text may not contain a write primitive
    script = SCRIPT.read_text()
    writes = [ln for ln in script.splitlines()
              if "i2cset" in ln and not ln.strip().startswith("#")]
    check(not writes, "probe contains no i2cset (read-only invariant)")
    check("i2cget" in script, "probe uses i2cget read primitive")

    # the address map matches the preflight WARN + runbook table
    check("0x29" in script and "gc4653" in script and "0x3c" in script
          and "os04d10" in script,
          "address map 0x29=gc4653 / 0x3c=os04d10 present (preflight §9 parity)")

    print("verdict: %s" % ("PASS" if not FAILURES else "FAIL %d" % len(FAILURES)))
    return 0 if not FAILURES else 1


if __name__ == "__main__":
    raise SystemExit(main())

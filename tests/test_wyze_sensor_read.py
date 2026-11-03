#!/usr/bin/env python3
"""Unit-test wyze_sensor_read.py with fake shell transcripts (no device, no network).

Contract under test (FLASH-DAY-RUNBOOK.md §0.2 + thingino/sensor-info sensors.csv):
- gc4653-class chip at i2c 0x29, ID regs 0x03f0/0x03f1 = 0x46/0x53 (2-byte reg → i2cdump)
- os04d10 at 0x3c, ID regs 0x02/0x03 = 0x53/0x04 (1-byte reg → i2cget)
- /dev/i2c-0 is the T41 sensor bus; 1..2 swept; PROBE-DONE sentinel required
- read-only invariant: no i2cset / no i2c transfers that write in the generated script

  python3 tests/test_wyze_sensor_read.py
"""
from __future__ import annotations

import importlib.util
import io
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE.parent / "deliverables" / "scripts" / "wyze_sensor_read.py"

spec = importlib.util.spec_from_file_location("wyze_sensor_read", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

FAILURES: list[str] = []


def check(cond: bool, what: str) -> None:
    print(("  PASS  " if cond else "  FAIL  ") + what)
    if not cond:
        FAILURES.append(what)


def run_cli(transcript: str, *flags: str) -> tuple[int, str]:
    p = subprocess.run([sys.executable, str(SCRIPT), "-", "--stdin", *flags],
                       input=transcript, capture_output=True, text=True, timeout=30)
    return p.returncode, p.stdout + p.stderr


def main() -> int:
    print("== wyze_sensor_read unit tests (fake shells)")

    # 1. gc4653 via i2cdump on bus 0: dump row 00: with 0x46@0x00? No — 2-byte reg
    #    0x03f0 means dump page 03; busybox i2cdump prints "0300:" style rows.
    dump_gc = ("DUMP gc4653 /dev/i2c-0 0x29 0300: 00 00 00 00 00 00 00 00 "
               "00 00 00 00 00 00 00 00\n"
               "DUMP gc4653 /dev/i2c-0 0x29 03f0: 46 53 00 00 00 00 00 00 "
               "00 00 00 00 00 00 00 00\nPROBE-DONE\n")
    rc, out = run_cli(dump_gc, "--json")
    v = mod.parse_output(dump_gc)
    check(v["verdict"] == "matched" and v["variant"] == "gc4653"
          and v["bus"] == "/dev/i2c-0" and v["i2c_addr"] == "0x29",
          "gc4653 i2cdump 0x03f0=46 0x03f1=53 -> matched gc4653 on bus 0")
    check(rc == 0 and '"variant":"gc4653"' in out and '"image":"thingino_gc4653.bin"' in out
          and '"chip_header_byte":"0x40"' in out, "gc4653 JSON carries image + header byte")

    # 2. os04d10 via i2cget 1-byte regs on bus 1
    get_os = ("HIT os04d10 /dev/i2c-1 0x3c 0x2=0x53\n"
              "HIT os04d10 /dev/i2c-1 0x3c 0x3=0x4\nPROBE-DONE\n")
    rc, out = run_cli(get_os, "--json")
    v = mod.parse_output(get_os)
    check(v["verdict"] == "matched" and v["variant"] == "os04d10" and v["bus"] == "/dev/i2c-1"
          and v["chip_header_byte"] == "0x52",
          "os04d10 i2cget 0x02=53 0x03=04 -> matched os04d10 (bus 1 sweep works)")

    # 3. both candidates answer -> first map entry wins deterministically
    both = dump_gc + get_os
    v = mod.parse_output(both)
    check(v["variant"] == "gc4653", "both answered -> gc4653 (first in map)")

    # 4. wrong ID values on the right address -> no match, exit 1
    wrong = ("DUMP gc4653 /dev/i2c-0 0x29 03f0: 00 00 00 00 00 00 00 00 "
             "00 00 00 00 00 00 00 00\nPROBE-DONE\n")
    rc, out = run_cli(wrong)
    check(rc == 1 and "neither sensor identity" in out,
          "address answers but IDs wrong -> exit 1, no variant claimed")

    # 5. truncated transcript (no PROBE-DONE) -> exit 1 with the incomplete reason
    rc, out = run_cli("DUMP gc4653 /dev/i2c-0 0x29 03f0: 46 53\n")
    check(rc == 1 and "did not complete" in out,
          "missing PROBE-DONE -> exit 1 (transport/trace failure)")

    # 6. read-only invariant on the generated probe: no write primitives
    script = mod.build_script()
    bad = [ln for ln in script.splitlines()
           if ("i2cset" in ln or "i2ctransfer" in ln or "insmod" in ln
               or "rmmod" in ln or "modprobe" in ln)]
    check(not bad, "probe script contains no i2cset/i2ctransfer/insmod/rmmod (read-only)")

    # 7. the probe reads both families' registers on every bus
    check("0x29" in script and "0x3c" in script and "i2c-2" in script,
          "probe covers 0x29 + 0x3c across /dev/i2c-0..2")

    # 8. address-map parity with the preflight WARN text
    check(mod.SENSORS["gc4653"]["addr"] == 0x29 and mod.SENSORS["os04d10"]["addr"] == 0x3C,
          "address map 0x29=gc4653 / 0x3c=os04d10 (preflight §9 parity)")

    # 9. cli exit codes: stdin path without match
    rc, out = run_cli("PROBE-DONE\n")
    check(rc == 1 and "FAIL" in out, "empty-but-complete probe -> exit 1 with FAIL line")

    print()
    if FAILURES:
        print(f"verdict: FAIL ({len(FAILURES)})")
        return 1
    print("verdict: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())

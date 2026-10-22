#!/usr/bin/env python3
"""Bounded malformed 0xCC51 probe harness (owner LAN, read-only).

Every case is HMAC-valid unless stated, so the camera's auth gate passes and
the datagram actually reaches the 0x1002 / 0x1502 / 0x1202 parsers. Each case
is retried 3x; a case only counts as a "kill" if a *fresh* baseline afterwards
also fails and then recovers (timed).

Usage:
  ./malformed_tutk_probe.py --uid U --enr E --mac M --host H [--case NAME|--list]
"""
import argparse
import socket
import struct
import sys
import time

import tutk_cc51 as C

CASES = {}


def case(fn):
    CASES[fn.__name__] = fn
    return fn


# --- 0x1002 field abuse (correctly HMAC'd, so the parser is the only gate) --
@case
def p0_base(k, sid):
    return C.disc(k, 0, 0, sid)


@case
def p0_psize_ffff(k, sid):
    return C.disc(k, 0, 0, sid, psize=0xFFFF)


@case
def p0_psize_0000(k, sid):
    return C.disc(k, 0, 0, sid, psize=0)


@case
def p0_psize_0001(k, sid):
    return C.disc(k, 0, 0, sid, psize=1) if False else C.disc(k, 0, 0, sid, psize=1)


@case
def p0_seq_ffff(k, sid):
    return C.disc(k, 0xFFFF, 0, sid)


@case
def p0_seq_7(k, sid):
    return C.disc(k, 7, 0, sid)


@case
def p0_dir_request(k, sid):
    return C.disc(k, 0, 0, sid, direction=0x0000)


@case
def p0_bad_sid(k, sid):
    return C.disc(k, 0, 0, b"\xaa" * 8)


@case
def p0_big1400(k, sid):
    return C.disc(k, 0, 0, sid) + b"A" * 1348


@case
def p0_trunc_after_auth(k, sid):
    return C.disc(k, 0, 0, sid)[:-1]


@case
def p0_trunc45(k, sid):
    return C.disc(k, 0, 0, sid)[:45]


@case
def p0_noauth32(k, sid):
    return C.disc(k, 0, 0, sid)[:32]


# --- 0x1502 before any discovery/DTLS --------------------------------------
@case
def p1_dtls_psize_ffff(k, sid):
    hdr = struct.pack("<HHHHHHHH", C.MAGIC, 0, C.CMD_DTLS, 0xFFFF, 0, 0, 0x0010, 0)
    return C.sign(k, hdr + sid + struct.pack("<I", 1)) + b"\x16\xfe\xfd" + b"\x00" * 8


@case
def p1_dtls_short(k, sid):
    hdr = struct.pack("<HHHHHHHH", C.MAGIC, 0, C.CMD_DTLS, 16, 0, 0, 0x0010, 0)
    return hdr + sid + struct.pack("<I", 1) + b"\x00" * 20


@case
def p1_dtls_big(k, sid):
    payload = b"\x16\xfe\xfd" + bytes(range(256)) * 5 + b"\x00" * 100
    hdr = struct.pack("<HHHHHHHH", C.MAGIC, 0, C.CMD_DTLS, (16 + len(payload) + 20) & 0xFFFF, 0, 0, 0x0010, 0)
    return C.sign(k, hdr + sid + struct.pack("<I", 1)) + payload + b"\x00" * 20


@case
def p1_dtls_noauth(k, sid):
    hdr = struct.pack("<HHHHHHHH", C.MAGIC, 0, C.CMD_DTLS, 16 + 16 + 20, 0, 0, 0x0010, 0)
    return hdr + sid + struct.pack("<I", 1) + b"\x16\xfe\xfd" + b"\x00" * 16


# --- 0x1202 keepalive ------------------------------------------------------
@case
def p2_keep(k, sid):
    hdr = struct.pack("<HHHHHHHH", C.MAGIC, 0, C.CMD_KEEP, 0x24, 0, 0, 0, 0)
    return C.sign(k, hdr + struct.pack("<I", 1) + sid)


@case
def p2_keep_psize_ffff(k, sid):
    hdr = struct.pack("<HHHHHHHH", C.MAGIC, 0, C.CMD_KEEP, 0xFFFF, 0, 0, 0, 0)
    return C.sign(k, hdr + struct.pack("<I", 1) + sid)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--uid", required=True)
    ap.add_argument("--enr", required=True)
    ap.add_argument("--mac", required=True)
    ap.add_argument("--port", type=int, default=32761)
    ap.add_argument("--wait", type=float, default=0.7)
    ap.add_argument("--case", action="append")
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args()
    if a.list:
        for n in CASES:
            print(n)
        return 0

    k = C.key(a.uid, a.enr, a.mac)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(a.wait)
    addr = (a.host, a.port)

    def fresh():
        """One HMAC-valid seq=0 discovery on a new sid; returns the reply."""
        sid = C.set_sid(bytes([time.time_ns() & 0xFF, 0x5A]))
        for _ in range(3):
            s.sendto(C.disc(k, 0, 0, sid), addr)
            try:
                return s.recvfrom(4096)
            except socket.timeout:
                pass
        return None

    r = fresh()
    print(f"pre-baseline: {'ANSWER %dB' % len(r[0]) if r else 'SILENT'}")

    for name in (a.case or list(CASES)):
        fn = CASES[name]
        for attempt in range(3):
            side = C.set_sid(bytes([attempt, 0xA5]))
            pkt = fn(k, side)
            t0 = time.monotonic()
            s.sendto(pkt, addr)
            try:
                d, src = s.recvfrom(4096)
                print(f"{name:22s} len={len(pkt):5d} ANSWER {len(d)}B in {(time.monotonic()-t0)*1000:.0f}ms from {src[1]}")
                break
            except socket.timeout:
                if attempt < 2:
                    continue
                if fresh() is not None:
                    print(f"{name:22s} len={len(pkt):5d} silent x3 (listener alive)")
                else:
                    t0 = time.monotonic()
                    rec = False
                    while time.monotonic() - t0 < 20:
                        if fresh() is not None:
                            rec = True
                            break
                        time.sleep(1)
                    print(f"{name:22s} len={len(pkt):5d} SILENT x3 + baseline dead, recovered={rec} in {time.monotonic()-t0:.0f}s")
        time.sleep(0.2)
    return 0


if __name__ == "__main__":
    sys.exit(main())

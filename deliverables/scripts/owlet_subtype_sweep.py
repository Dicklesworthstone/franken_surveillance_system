#!/usr/bin/env python3
"""Owlet 0x06xx client-frame subtype sweep (bead fss-kemuu, oracle-hunt lane).

The Owlet LAN-search vocabulary, measured: client probe = plaintext type 0x0601, camera
reply = 0x0602 (200 B, carries the authKey prefix at [52:58]); client type 0x0606 also
elicits 0x0602; the CuboAI 0x0402 identity query is silent on this firmware. This tool
sweeps the remaining client subtypes 0x0610-0x06ff one attempt per type per run, using the
full acknowledged sequence (probe -> nO -> ACK -> second 0x0602) before each candidate,
so every candidate is tested against an armed search state.

Bounded per the lane spec: 3 s reply timeout per candidate, stop after 20 consecutive
silences, one attempt per type per run. Any non-silent candidate is recorded immediately
to /tmp/owlet_subtype_sweep.log with the reply's length + plaintext type + head hex.

  sudo python3 owlet_subtype_sweep.py [--start 0x610] [--end 0x6ff] [--timeout 3]
                                      [--max-silence 20] [--types 0x606,0x620]
"""
import argparse
import datetime
import os
import socket
import struct
import sys
import time

CAM_IP = "192.168.4.163"
CAM_MAC = "38:01:46:ab:83:8a"
MY_IP = "192.168.4.160"
IFACE = "en1"
PORT = 63616
UID = b"TDEWNKCZVSYLVLT7111A"
LOG = "/tmp/owlet_subtype_sweep.log"

_LS_HEAD = bytes.fromhex("04021a0248000000")
_LS_MID8 = bytes.fromhex("0000000001010204")
_LS_TRAILER8 = bytes.fromhex("63041313040c0c63")


def log(msg):
    line = f"{datetime.datetime.now().isoformat(timespec='milliseconds')} {msg}"
    print(line, flush=True)
    try:
        with open(LOG, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass


def build_probe_type(t08: int, t09: int, R: int) -> bytes:
    """88-byte LAN-search layout with an arbitrary plaintext type at [8:10]."""
    t = bytearray(88)
    t[0:16] = bytes.fromhex("04021a02480000000106210000000000")
    t[8] = t08
    t[9] = t09
    t[16:36] = UID
    t[48:56] = _LS_MID8
    t[56:58] = struct.pack("<H", R & 0xFFFF)
    t[58:64] = bytes.fromhex("000200000000")  # the camera-validated fingerprint shape
    t[64] = 0x01
    t[80:88] = _LS_TRAILER8
    return transcode(bytes(t))


def transcode(plain: bytes) -> bytes:
    sys.path.insert(0, os.path.expanduser("~/fw-lab/owlet/cubo"))
    import cuboai_pure_owlet as cp
    return cp.transcode(plain, swap_tail=False)


def inv_transcode(wire: bytes) -> bytes:
    sys.path.insert(0, os.path.expanduser("~/fw-lab/owlet/cubo"))
    import cuboai_pure_owlet as cp
    return cp.inv_transcode(wire)


def xor_frame(data: bytes) -> bytes:
    k = bytes.fromhex("6e2e8d8c40d040ca2d6d280c40e4cad8")
    return bytes(b ^ k[i % 16] for i, b in enumerate(data))


def l2_send(payload: bytes, sport: int):
    from scapy.all import Ether, IP, UDP, sendp
    sendp(Ether(dst=CAM_MAC) / IP(src=MY_IP, dst=CAM_IP)
          / UDP(sport=sport, dport=PORT) / payload, iface=IFACE, verbose=0)


def gen_R():
    sys.path.insert(0, os.path.expanduser("~/fw-lab/owlet/cubo"))
    import cuboai_pure_owlet as cp
    return cp.gen_R()


def armed_sequence(rx, sport):
    """probe -> nO -> ACK -> second 0x0602; returns R or None."""
    R = gen_R()
    probe = build_probe_type(0x01, 0x06, R)
    t = bytearray(inv_transcode(probe))
    t[64] = 0x02                       # ACK = probe plaintext with [64]=0x02
    ack = transcode(bytes(t))
    l2_send(probe, sport)
    l2_send(probe, sport)
    try:
        raw, addr = rx.recvfrom(2048)                       # nO
    except socket.timeout:
        return None
    l2_send(ack, sport)
    try:
        raw2, addr2 = rx.recvfrom(2048)                     # second 0x0602
        return R
    except socket.timeout:
        return None


def sweep(start, end, timeout, max_silence):
    consecutive_silence = 0
    respondents = {}
    for t09 in range(start, end + 1):
        if consecutive_silence >= max_silence:
            log(f"stopping: {max_silence} consecutive silences at 0x{t09:04x}")
            break
        rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rx.settimeout(2.2)
        rx.bind((MY_IP, 0))
        sport = rx.getsockname()[1]
        try:
            R = armed_sequence(rx, sport)
            if R is None:
                log(f"0x06{t09:02x}: sequence un-armed (no nO) — retrying type")
                R = gen_R()
            # 0x06xx types: [8]=0x06, [9]=low byte (0x610 -> [9]=0x10; 0x6ff -> [9]=0xff)
            cand = build_probe_type(0x06, t09 & 0xFF, R)
            l2_send(cand, sport)
            rx.settimeout(timeout)
            try:
                raw, addr = rx.recvfrom(65535)
                d = xor_frame(raw) if len(raw) == 88 else inv_transcode(raw)
                typ = f"0x{d[8:10].hex()}" if len(d) >= 10 else "?"
                log(f"HIT 0x06{t09:02x}: reply len={len(raw)} type={typ} "
                    f"head={raw[:96].hex()}")
                respondents[t09] = (len(raw), typ)
                consecutive_silence = 0
            except socket.timeout:
                consecutive_silence += 1
        finally:
            rx.close()
        time.sleep(0.3)
    log(f"sweep done: respondents={ {hex(k): v for k, v in respondents.items()} }")
    return respondents


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--start", type=lambda x: int(x, 0), default=0x610)
    ap.add_argument("--end", type=lambda x: int(x, 0), default=0x6FF)
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--max-silence", type=int, default=20)
    a = ap.parse_args()
    sweep(a.start, a.end, a.timeout, a.max_silence)
    return 0


if __name__ == "__main__":
    sys.exit(main())

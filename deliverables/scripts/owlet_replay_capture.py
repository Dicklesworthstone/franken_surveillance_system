#!/usr/bin/env python3
"""Owlet orphan-phase replay — the app's own post-search frames, verbatim (fss-kemuu).

`owlet_direct_connect.py` proves the *auth pair* reproduces the app byte for byte, and it
still gets no `0x2041`: the camera answers nothing at all after the search leg. Decoding the
capture shows there is a whole layer our bare pair omits — the app registers the session
first:

    0x2043 registration  92 B + 576 B x3 + 76 B          (index 0, 4-7)
    0x0504 / 0x4010      88 B channel frames, ClientHello (11-12, ...)
    0x2043 re-registers  320 B x6, 52 B beacons, login    (20-31, 50)

So this replays the captured app->camera datagrams **in their original order and relative
timing**, after establishing the search leg the camera needs to answer at all (probe -> nO
-> ACK, which is what the real client does before index 0). Nothing is re-encoded: the
bytes are the app's.

    sudo owlet_replay_capture.py run [--from I] [--to J] [--speed X] [--wait S]

`--from/--to` slice the frame range (defaults 0..end). `--speed` scales the captured gaps
(1.0 = original pacing, clamped at 0.5 s) — the sequence is a DTLS handshake, so pacing is
part of the contract, not cosmetic. Exit 0 only on a `0x2041`.
"""
import argparse
import os
import re
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import owlet_grant_loop as gl
import owlet_direct_connect as dc

CAPTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "docs", "exploit",
                       "captures", "owlet_auth_java_hook_2026-11-03.log")
# The LAN-direct capture (10-29) is the one that matters for a LAN replay: same unit, app
# talking to the camera's own session socket, NOTHING between them. Its frames are 0x407
# (LAN envelope) where the 11-03 relay capture carries 0x504 (what the relay re-wraps), so
# replaying the relay form at the camera hands it a type it never sees on this path.
LAN_CAPTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "docs",
                           "exploit", "captures", "owlet_auth_exchange.log")
MAX_GAP = 0.5

# two log formats are on disk: "[TS] sendto fd=N addr len=L" + indented hex=, and the older
# one-line "[S] fd=N > addr len=L hex=<h>" (S = app, R = camera)
RE_SENDTO = re.compile(r"\[(\d\d):(\d\d):(\d\d\.\d\d\d)\] (sendto|recvfrom) fd=\d+ \S+ len=(\d+)")
RE_INLINE = re.compile(r"\[([SR])\] fd=\d+ [<>] \S+ len=(\d+) hex=([0-9a-f]*)")


def parse(path):
    """[(t_seconds, bytes)] for app->camera datagrams, in capture order.

    Only the app direction is ours to replay; what the camera said belongs to the live run.
    Timestamps start at the first replayed frame, so leading idle time does not leak into
    the schedule. Frames longer than the dump cap arrive truncated — `short()` reports it.
    """
    frames, cur = [], None
    for line in open(path, errors="replace"):
        m = RE_INLINE.search(line)
        if m:
            if m.group(1) == "S" and m.group(3):
                frames.append((0.0, bytes.fromhex(m.group(3)), int(m.group(2))))
            continue
        m = RE_SENDTO.match(line)
        if m:
            cur = {"t": int(m.group(1)) * 3600 + int(m.group(2)) * 60 + float(m.group(3)),
                   "dir": m.group(4), "len": int(m.group(5))}
            continue
        m = re.match(r"\s+hex=([0-9a-f]+)", line)
        if m and cur is not None:
            if cur["dir"] == "sendto":
                frames.append((cur["t"], bytes.fromhex(m.group(1)), cur["len"]))
            cur = None
    if not frames:
        return frames
    t0 = frames[0][0]
    return [(t - t0, b, n) for t, b, n in frames]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["run"])
    ap.add_argument("--capture", default=LAN_CAPTURE,
                    help="capture log to replay (default: the LAN-direct one; the relay "
                         "capture carries 0x504 wrappers the camera does not see on LAN)")
    ap.add_argument("--from", dest="lo", type=int, default=0)
    ap.add_argument("--to", dest="hi", type=int, default=None)
    ap.add_argument("--speed", type=float, default=1.0, help="gap scale (1 = as captured)")
    ap.add_argument("--wait", type=float, default=12.0, help="seconds to listen after the last frame")
    ap.add_argument("--gap", type=float, default=0.005,
                    help="floor between frames when the capture has no clock")
    ap.add_argument("--probe-tries", type=int, default=6)
    a = ap.parse_args()

    frames = parse(a.capture)[a.lo:a.hi]
    if not frames:
        print(f"no frames in {a.capture}[{a.lo}:{a.hi}]", file=sys.stderr)
        return 2
    dc.adopt_iface()

    cred = gl.load_creds()
    if not cred:
        print("no credentials (run owlet_relay_watch.py mint)", file=sys.stderr)
        return 2
    uid = cred["tutkid"].encode()

    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.settimeout(2.5)
    rx.bind((gl.MY_IP, 0))
    sport = rx.getsockname()[1]
    R = gl.gen_R()
    cam_addr = None
    for _ in range(a.probe_tries):
        gl.l2_send(gl.build_probe(uid, R), sport)
        gl.l2_send(gl.build_probe(uid, R), sport)
        try:
            _, a1 = rx.recvfrom(2048)
        except socket.timeout:
            continue
        cam_addr = (a1[0], a1[1])
        break
    if cam_addr is None:
        print("no nO — camera not answering LAN search", file=sys.stderr)
        return 3
    short = sum(1 for _, b, n in frames if len(b) < n)
    gl.log(f"replay: cam={cam_addr[0]}:{cam_addr[1]} sport={sport} frames={len(frames)} "
           f"speed={a.speed} truncated={short}")
    gl.l2_send_to(gl.build_ack(uid, R), sport, cam_addr)

    got = {"grant": False, "types": []}

    def listen():
        end = time.time() + a.wait + 5.0
        while time.time() < end:
            try:
                raw, addr = rx.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            typ = dc.classify(raw)
            got["types"].append(hex(typ))
            gl.log(f"cam<- {len(raw)}B type={hex(typ)} from={addr[1]} hex={gl.hx(raw, 96)}")
            if typ == 0x2041:
                got["grant"] = True

    th = threading.Thread(target=listen, daemon=True)
    th.start()

    last = 0.0
    for off, blob, declared in frames:
        gap = max(min(max(off - last, 0.0), MAX_GAP) / max(a.speed, 0.01), a.gap)
        if gap:
            time.sleep(gap)
        last = off
        gl.l2_send_to(blob, sport, cam_addr)
        gl.log(f"cam-> {len(blob)}B {blob[:8].hex()}" + (" (truncated)" if len(blob) < declared else ""))

    time.sleep(a.wait)
    gl.log(f"types seen: {sorted(set(got['types']))}"
           + ("  *** 0x2041 GRANT ***" if got["grant"] else "  no grant"))
    rx.close()
    return 0 if got["grant"] else 1


if __name__ == "__main__":
    sys.exit(main())

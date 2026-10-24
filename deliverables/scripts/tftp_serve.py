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
        if len(data) < 4 or struct.unpack(">H", data[:2])[0] != RRQ:
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

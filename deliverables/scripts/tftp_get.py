#!/usr/bin/env python3
"""Minimal TFTP RRQ fetcher (for the dnsmasq read channel)."""
import socket
import struct
import sys


def get(host: str, name: str, port: int = 69, timeout: float = 3.0) -> bytes:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    s.sendto(struct.pack(">H", 1) + name.encode() + b"\0octet\0", (host, port))
    out = bytearray()
    peer = None
    while True:
        data, addr = s.recvfrom(65536)
        op = struct.unpack(">H", data[:2])[0]
        if op == 5:
            raise OSError(f"tftp error {struct.unpack('>H', data[2:4])[0]}: {data[4:].decode(errors='replace')}")
        if op != 3:
            raise OSError(f"unexpected op {op}")
        block = struct.unpack(">H", data[2:4])[0]
        out += data[4:]
        peer = addr
        s.sendto(struct.pack(">HH", 4, block), peer)
        if len(data) - 4 < 512:
            return bytes(out)


if __name__ == "__main__":
    host, name = sys.argv[1], sys.argv[2]
    sys.stdout.buffer.write(get(host, name))

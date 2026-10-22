#!/usr/bin/env python3
"""TUTK/IOTC OLD-protocol (0x0601) LAN-search probe — credential-less.

Byte-exact mirror of `fss_tutk::oldproto::build_probe` / `parse_response`
(crates/fss-tutk/src/oldproto.rs). Port 32761 is the OLD-protocol search port;
`0x0601` on 10001 is silent.

The response is a `0x0602` answer whose body carries the 20-byte device UID
verbatim at [16:36]. The UID alone authenticates nothing; it is an inventory
seed and the identity half of the CVE-2023-63xx replay class.

Usage: tutk_discover_lan.py <bind_ip> <target_ip>...
"""
import socket
import struct
import sys
import time

K16 = b"Charlie is the d"
PROBE_PORT = 32761

LS_HEAD16 = bytes([
    0x04, 0x02, 0x1a, 0x02, 0x48, 0x00, 0x00, 0x00,
    0x01, 0x06, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00,
])
LS_MID8 = bytes([0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x02, 0x04])
LS_TRAILER8 = bytes([0x63, 0x04, 0x13, 0x13, 0x04, 0x0c, 0x0c, 0x63])


def ror32(v, r):
    r &= 31
    return ((v >> r) | (v << (32 - r))) & 0xFFFFFFFF


def rol32(v, r):
    r &= 31
    return ((v << r) | (v >> (32 - r))) & 0xFFFFFFFF


def _byte(v, i):
    return (v >> (8 * i)) & 0xFF


def block_transform(blk):
    k = [struct.unpack_from("<I", K16, 4 * i)[0] for i in range(4)]
    w = [struct.unpack_from("<I", blk, 4 * i)[0] for i in range(4)]
    a = ror32(w[0], 1) ^ k[0]
    b = ror32(w[1], 5) ^ k[1]
    c = ror32(w[2], 9) ^ k[2]
    d = ror32(w[3], 13) ^ k[3]
    ecx = (_byte(d, 2) << 24) | (_byte(d, 0) << 16) | (_byte(c, 2) << 8) | _byte(d, 1)
    r10 = (_byte(a, 0) << 24) | (_byte(b, 1) << 16) | (_byte(a, 1) << 8) | _byte(a, 2)
    r8 = (_byte(d, 3) << 24) | (_byte(c, 0) << 16) | (_byte(c, 1) << 8) | _byte(c, 3)
    r9 = (_byte(a, 3) << 24) | (_byte(b, 3) << 16) | (_byte(b, 0) << 8) | _byte(b, 2)
    return b"".join(struct.pack("<I", v) for v in
                    (ror32(r8, 3), ror32(ecx, 7), ror32(r10, 11), ror32(r9, 15)))


def inv_block_transform(blk):
    k = [struct.unpack_from("<I", K16, 4 * i)[0] for i in range(4)]
    o = [struct.unpack_from("<I", blk, 4 * i)[0] for i in range(4)]
    r8, ecx, r10, r9 = rol32(o[0], 3), rol32(o[1], 7), rol32(o[2], 11), rol32(o[3], 15)
    d2, d0, c2, d1 = _byte(ecx, 3), _byte(ecx, 2), _byte(ecx, 1), _byte(ecx, 0)
    a0, b1, a1, a2 = _byte(r10, 3), _byte(r10, 2), _byte(r10, 1), _byte(r10, 0)
    d3, c0, c1, c3 = _byte(r8, 3), _byte(r8, 2), _byte(r8, 1), _byte(r8, 0)
    a3, b3, b0, b2 = _byte(r9, 3), _byte(r9, 2), _byte(r9, 1), _byte(r9, 0)
    a = a0 | (a1 << 8) | (a2 << 16) | (a3 << 24)
    b = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
    c = c0 | (c1 << 8) | (c2 << 16) | (c3 << 24)
    d = d0 | (d1 << 8) | (d2 << 16) | (d3 << 24)
    return b"".join(struct.pack("<I", v) for v in
                    (rol32(a ^ k[0], 1), rol32(b ^ k[1], 5), rol32(c ^ k[2], 9), rol32(d ^ k[3], 13)))


def transcode(plain, swap_tail=False):
    full = len(plain) - (len(plain) & 0xF)
    out = b"".join(block_transform(plain[o:o + 16]) for o in range(0, full, 16))
    t = bytes(K16[i] ^ plain[full + i] for i in range(len(plain) - full))
    return out + t


def inv_transcode(wire):
    full = len(wire) - (len(wire) & 0xF)
    out = b"".join(inv_block_transform(wire[o:o + 16]) for o in range(0, full, 16))
    return out + bytes(K16[i] ^ wire[full + i] for i in range(len(wire) - full))


def build_probe(fingerprint=b"\xf5\x05\x20\x26\x10\x08"):
    t = bytearray(88)
    t[0:16] = LS_HEAD16
    t[48:56] = LS_MID8
    t[56:58] = struct.pack("<H", 0x0601)
    t[58:64] = fingerprint
    t[64] = 0x01
    t[80:88] = LS_TRAILER8
    return transcode(bytes(t))


def parse(data):
    plain = inv_transcode(data)
    if len(plain) < 16:
        return None
    cmd = struct.unpack_from("<H", plain, 8)[0]
    uid = ""
    if len(plain) >= 36:
        body = plain[16:36]
        uid = body.split(b"\x00")[0].decode("ascii", "replace")
    return cmd, uid


def main():
    bind_ip = sys.argv[1]
    targets = sys.argv[2:]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind_ip, 0))
    sock.settimeout(0.15)
    probe = build_probe()
    deadline = time.monotonic() + 3.0
    seen = {}
    while time.monotonic() < deadline:
        for t in targets:
            sock.sendto(probe, (t, PROBE_PORT))
        while True:
            try:
                data, addr = sock.recvfrom(2048)
            except socket.timeout:
                break
            parsed = parse(data)
            if parsed is None:
                print(f"{addr[0]}: malformed {data.hex()}")
                continue
            seen[addr[0]] = parsed
            print(f"{addr[0]}: cmd=0x{parsed[0]:04x} uid={parsed[1]!r} len={len(data)}")
    for t in targets:
        if t not in seen:
            print(f"{t}: silent")


if __name__ == "__main__":
    main()

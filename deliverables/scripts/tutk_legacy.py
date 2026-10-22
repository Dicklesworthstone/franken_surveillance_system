#!/usr/bin/env python3
"""Legacy TUTK/IOTC (TransCode) LAN helper — the *unauthenticated* half of the
same device that also speaks 0xCC51.

Discovery 0x0601 and the 0x0402 session request carry no auth material; only
the CC51 path HMACs (uid||authKey). Used here to measure what a LAN attacker
gets with no ENR/AuthKey at all.

Read-only: presence probes and discovery only.
"""
import socket
import struct
import sys
import time

CHARLIE = b"Charlie is the designer of P2P!!"
SID_SUFFIX = b"\x76\x0a\x9d\x24\x88\xba"


def _rotl(x, n):
    n &= 31
    return x if n == 0 else ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _rotr(x, n):
    n &= 31
    return x if n == 0 else ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def _swap(src, n):
    if n == 16:
        return bytes([src[11], src[9], src[8], src[15], src[13], src[10], src[12],
                      src[14], src[2], src[1], src[5], src[0], src[6], src[4], src[7], src[3]])
    if n == 8:
        return bytes([src[7], src[4], src[3], src[2], src[1], src[6], src[5], src[0]])
    if n == 4:
        return bytes([src[2], src[3], src[0], src[1]])
    if n == 2:
        return bytes([src[1], src[0]])
    return bytes(src[:n])


def _block(fn, src):
    """Encode (transcode) or decode (reverse) whole 16-byte blocks + tail."""
    src = bytes(src)
    out = bytearray()
    off = 0
    n = len(src)
    while n >= 16:
        blklel = bytearray(16)
        for j in range(0, 16, 4):
            struct.pack_into("<I", blklel, j, fn(struct.unpack_from("<I", src, off + j)[0], j + (1 if fn is _rotr else 3)))
        t = bytearray(16)
        if fn is _rotr:            # encode: rotate, xor, swap, rotate
            for j in range(16):
                t[j] = blklel[j] ^ CHARLIE[j]
            sw = _swap(bytes(t), 16)
            res = bytearray(16)
            for j in range(0, 16, 4):
                struct.pack_into("<I", res, j, _rotr(struct.unpack_from("<I", sw, j)[0], j + 3))
        else:                      # decode: rotate, swap, xor, rotate
            d = _swap(bytes(blklel), 16)
            for j in range(16):
                t[j] = d[j] ^ CHARLIE[j]
            resdeg = bytearray(16)
            for j in range(0, 16, 4):
                struct.pack_into("<I", resdeg, j, _rotl(struct.unpack_from("<I", t, j)[0], j + 1))
            res = resdeg
        out += res
        off += 16
        n -= 16
    tail = bytes([src[off + i] ^ CHARLIE[i] for i in range(n)])
    out += _swap(tail, n)
    return bytes(out)


def transcode(src):
    out = bytearray(_block(_rotr, src[:16]))
    if src[3] & 1:                                  # partial encryption
        rem = len(src) - 16
        out += _block(_rotr, src[16:16 + min(rem, 48)])
        if rem > 48:
            out += src[64:]
    else:
        out += _block(_rotr, src[16:])
    return bytes(out)


def rtranscode(src):
    out = bytearray(_block(_rotl, src[:16]))
    if out[3] & 1:
        rem = len(src) - 16
        out += _block(_rotl, src[16:16 + min(rem, 48)])
        if rem > 48:
            out += src[64:]
    else:
        out += _block(_rotl, src[16:])
    return bytes(out)


def build_disco(uid, sid, stage=1):
    b = bytearray(88)
    b[0:4] = b"\x04\x02\x1a\x02"
    struct.pack_into("<H", b, 4, 72)        # body size
    struct.pack_into("<H", b, 8, 0x0601)    # cmd disco req
    struct.pack_into("<H", b, 10, 0x0021)   # flags
    body = b[16:]
    body[0:20] = uid.ljust(20, b"A")[:20]
    body[36:40] = b"\x01\x01\x02\x04"       # sdk 4.2.1.1
    body[40:48] = sid
    body[48] = stage
    return transcode(bytes(b))


def build_session(uid, sid):
    b = bytearray(52)
    b[0:4] = b"\x04\x02\x1a\x02"
    struct.pack_into("<H", b, 4, 36)
    struct.pack_into("<H", b, 8, 0x0402)
    struct.pack_into("<H", b, 10, 0x0033)
    body = b[16:]
    body[0:20] = uid.ljust(20, b"A")[:20]
    body[20:28] = sid
    struct.pack_into("<I", body, 32, int(time.time()))
    return transcode(bytes(b))




def discover(host, port=32761, tries=6, wait=0.9, sock=None):
    """Return (adopted_port, uid, sid) or (None, None, None).

    Pass `sock` to reuse one source port across discovery and the session
    request — the camera keys its slot on the source port.
    """
    s = sock or socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(wait)
    sid = bytes([0x11, 0x22]) + SID_SUFFIX
    uid = b"WYZE0123456789ABCDEF"
    for _ in range(tries):
        s.sendto(build_disco(uid, sid), (host, port))
        try:
            d, a = s.recvfrom(2048)
        except socket.timeout:
            continue
        r = rtranscode(d)
        if len(r) >= 44 and struct.unpack_from("<H", r, 8)[0] == 0x0602:
            real_uid = r[16:36]
            return a[1], real_uid, sid
    return None, None, None


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "192.168.5.242"
    port, uid, sid = discover(host)
    print("adopted_port", port, "uid", uid, "sid", sid.hex() if sid else None)

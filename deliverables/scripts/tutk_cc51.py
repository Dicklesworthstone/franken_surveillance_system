#!/usr/bin/env python3
"""Authenticated 0xCC51 (TUTK NEW) probe client with optional HMAC.

Mirrors crates/fss-tutk/src/wire.rs. The HMAC key is UID(20) || AuthKey(8)
where AuthKey = b64(SHA256(ENR + MAC.upper())[0:6]) with +/=/ -> Z/9/A.
"""
import base64
import hashlib
import hmac
import socket
import struct
import sys

MAGIC = 0xCC51
CMD_DISC = 0x1002
CMD_DTLS = 0x1502
CMD_KEEP = 0x1202
SID_SUFFIX = b"\x76\x0a\x9d\x24\x88\xba"


def auth_key(enr, mac):
    h = hashlib.sha256(enr.encode() + mac.upper().encode()).digest()[:6]
    return base64.b64encode(h).decode().replace("+", "Z").replace("/", "9").replace("=", "A").encode()


def key(uid, enr, mac):
    return uid.encode() + auth_key(enr, mac)


def psk(enr):
    """PSK = SHA256(ENR), zeroed from the first NUL (C-string quirk)."""
    h = hashlib.sha256(enr.encode()).digest()
    n = h.find(b"\x00")
    return h if n < 0 else h[:n] + b"\x00" * (32 - n)


def sign(k, body):
    return body + hmac.new(k, body, hashlib.sha1).digest()


def disc(k, seq=0, ticketbraces=0, sid=b"\x00" * 8, psize=0x28, direction=0):
    hdrgun = struct.pack("<HHHHHHHH", MAGIC, 0, CMD_DISC, psize, direction, 0, seq, ticketbraces)
    return sign(k, hdrgun + sid + bytes([0x00, 0x08, 0x03, 0x04, 0x1D, 0, 0, 0]))


def bind(uid, enr, mac, host, port=32761, wait=1.0):
    """Unconnected UDP socket: the camera answers from a freshly adopted port,
    so a connected socket would drop the reply."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(wait)
    return s, (host, port)


def set_sid(sid2=b"\x11\x22"):
    return sid2 + SID_SUFFIX


if __name__ == "__main__":
    uid, enr, mac, host = sys.argv[1:5]
    k = key(uid, enr, mac)
    print("authkey", auth_key(enr, mac), "psk", psk(enr).hex())
    s = bind(uid, enr, mac, host)
    sid = set_sid()
    for i in range(3):
        s.send(disc(k, 0, 0, sid))
        try:
            d = s.recv(2048)
            print("ANSWER", len(d), d[:16].hex())
            break
        except socket.timeout:
            print("silent", i)

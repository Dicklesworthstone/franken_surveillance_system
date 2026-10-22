#!/usr/bin/env python3
"""UDP relay that carries a stock OpenSSL DTLS client over TUTK 0x1502 frames.

The camera only speaks DTLS inside HMAC'd 0xCC51 `0x1502` wrappers, so a normal
`openssl s_client -dtls1_2` cannot talk to it directly. This script:

  1. performs 0x1002 discovery (seq 0 -> 2 -> 3) to learn the adopted port and
     ticket,
  2. listens on a loopback UDP port for the DTLS client,
  3. wraps every client->camera datagram in a 0x1502 frame and strips the
     wrapper off camera->client datagrams.

Read-only w.r.t. the camera.

  ./dtls_proxy.py --host 192.168.5.242 --uid .. --enr .. --mac ..
  # then: openssl s_client -dtls1_2 -connect 127.0.0.1:<printed port> ...
"""
import argparse
import hashlib
import hmac
import socket
import struct
import sys
import time

import tutk_cc51 as C

HDR = 28
AUTH = 20


def discovery(s, addr, k, sid):
    """Drive seq 0 -> 2 -> 3; return (adopted_port, ticket)."""
    for _ in range(12):
        s.sendto(C.disc(k, 0, 0, sid), addr)
        try:
            d, src = s.recvfrom(2048)
        except socket.timeout:
            continue
        if len(d) == 52 and struct.unpack_from("<H", d, 12)[0] == 1:
            ticket = struct.unpack_from("<H", d, 14)[0]
            port = src[1]
            for _ in range(4):
                s.sendto(C.disc(k, 2, ticket, sid), (addr[0], port))
                try:
                    d3, _ = s.recvfrom(2048)
                except socket.timeout:
                    continue
                if struct.unpack_from("<H", d3, 12)[0] == 3:
                    return port, ticket
            break
        time.sleep(0.3)
    raise RuntimeError("discovery did not reach seq 3")


def wrap(k, sid, ticket, payload):
    hdr = struct.pack("<HHHHHHHH", C.MAGIC, 0, C.CMD_DTLS,
                      (16 + len(payload) + AUTH) & 0xFFFF, 0, 0, 0x0010, ticket)
    body = hdr + sid + struct.pack("<I", 1)
    return body + payload + hmac.new(k, body, hashlib.sha1).digest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--uid", required=True)
    ap.add_argument("--enr", required=True)
    ap.add_argument("--mac", required=True)
    ap.add_argument("--listen", type=int, default=0)
    a = ap.parse_args()

    k = C.key(a.uid, a.enr, a.mac)
    sid = C.set_sid()
    cam = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cam.settimeout(0.6)
    port, ticket = discovery(cam, (a.host, 32761), k, sid)
    print(f"# discovery ok: adopted port {port} ticket 0x{ticket:04x} sid {sid.hex()}", flush=True)

    lc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    lc.bind(("127.0.0.1", a.listen))
    lc.settimeout(0.2)
    print(f"# dtls client -> 127.0.0.1:{lc.getsockname()[1]}", flush=True)

    client = None
    while True:
        try:
            data, src = lc.recvfrom(4096)
            client = src
            cam.sendto(wrap(k, sid, ticket, data), (a.host, port))
        except socket.timeout:
            pass
        try:
            d, _ = cam.recvfrom(4096)
        except socket.timeout:
            continue
        if len(d) > HDR + AUTH and d[:2] == b"\x51\xcc" and struct.unpack_from("<H", d, 4)[0] == C.CMD_DTLS:
            if client:
                lc.sendto(d[HDR:-AUTH], client)
            else:
                print(f"# camera spoke before client: {d.hex()[:80]}", flush=True)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Local fake camera: exercise the broker, the injector and the command body with no hardware.

Connects to the local proxy on 127.0.0.1:8883 with a real device certificate (mutual TLS, ALPN
`x-amzn-mqtt-ca`), sends CONNECT with the thing name as client id, SUBSCRIBEs to the five topics the
stock client subscribes, and prints every PUBLISH it receives (payload as text and hex).

  wyze_fake_device.py [--thing 80482c4bcf0b] [--cert-dir DIR] [--port 8883] [--secs 30]

The proxy injects into `hl/devices/<THING>/cmd` for its own THING, so the cmd topic of that thing is
subscribed as well when it differs.
"""
import argparse
import os
import socket
import ssl
import struct
import sys
import time

IOT_DIR = os.path.expanduser("~/.config/fss-lab/wyze_iot")


def enc_len(n: int) -> bytes:
    out = b""
    while True:
        b, n = n % 128, n // 128
        out += bytes([b | (0x80 if n else 0)])
        if not n:
            return out


def pkt(kind: int, body: bytes, flags: int = 0) -> bytes:
    return bytes([(kind << 4) | flags]) + enc_len(len(body)) + body


def s(x: str) -> bytes:
    b = x.encode()
    return len(b).to_bytes(2, "big") + b


def read_pkt(sock):
    head = sock.recv(1)
    if not head:
        return None, b""
    mult, n = 1, 0
    while True:
        b = sock.recv(1)
        if not b:
            return None, b""
        n += (b[0] & 0x7F) * mult
        mult *= 128
        if not b[0] & 0x80:
            break
    body = b""
    while len(body) < n:
        c = sock.recv(n - len(body))
        if not c:
            return None, b""
        body += c
    return head[0], body


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--thing", default="80482c4bcf0b")
    ap.add_argument("--client-id", default="", help="defaults to --thing; AWS rejects a duplicate id")
    ap.add_argument("--inject-thing", default=os.environ.get("THING", "80482c525905"))
    ap.add_argument("--cert-dir", default=os.path.join(IOT_DIR, "80482C4BCF0B"))
    ap.add_argument("--port", type=int, default=8883)
    ap.add_argument("--secs", type=float, default=30.0)
    ap.add_argument("--cafile", default="/Users/jemanuel/fss-exploit/fw/root_system/local/cacert.pem",
                    help="trust anchor for the local proxy (the device's own bundle)")
    a = ap.parse_args()

    ctx = ssl.create_default_context(cafile=a.cafile)
    # OpenSSL 3 wants an AKI the forged intermediate does not carry; the camera's libcurl does not.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.load_cert_chain(os.path.join(a.cert_dir, "cert.pem"), os.path.join(a.cert_dir, "privkey.pem"))
    ctx.set_alpn_protocols(["x-amzn-mqtt-ca"])
    raw = socket.create_connection(("127.0.0.1", a.port), timeout=10)
    sock = ctx.wrap_socket(raw, server_hostname="a24rq1e5m4mtei.iot.us-west-2.amazonaws.com")
    print(f"tls ok alpn={sock.selected_alpn_protocol()}", flush=True)
    sock.settimeout(20.0)

    # clean_session = 0, keepalive 60, client id = thing name
    cid = a.client_id or a.thing
    sock.sendall(pkt(1, s("MQTT") + bytes([4, 0x00]) + b"\x00\x3c" + s(cid)))
    # a persistent session can deliver queued messages before the CONNACK; skip past them
    while True:
        try:
            kind, body = read_pkt(sock)
        except (socket.timeout, TimeoutError):
            print("timeout before connack", flush=True)
            return 1
        if kind is None:
            print("closed before connack", flush=True)
            return 1
        if kind >> 4 == 2:
            print(f"connack {body.hex()}", flush=True)
            break
        print(f"pre-connack type {kind >> 4} len={len(body)}", flush=True)

    topics = [f"hl/devices/{a.thing}/cmd",
              f"$aws/things/{a.thing}/shadow/name/wyze-service/update/delta",
              f"$aws/things/{a.thing}/shadow/name/wyze-service/get/accepted",
              f"$aws/things/{a.thing}/shadow/name/wyze-secure/update/delta",
              f"$aws/things/{a.thing}/shadow/name/wyze-secure/get/accepted"]
    if a.inject_thing and a.inject_thing != a.thing:
        topics.append(f"hl/devices/{a.inject_thing}/cmd")
    sub = struct.pack(">H", 1) + b"".join(s(t) + b"\x01" for t in topics)
    sock.sendall(pkt(8, sub))
    try:
        kind, body = read_pkt(sock)
        print(f"suback {body.hex()} for {len(topics)} topics", flush=True)
    except (socket.timeout, TimeoutError):
        print(f"no suback; subscribed to {len(topics)} topics anyway", flush=True)

    end = time.time() + a.secs
    sock.settimeout(1.0)
    while time.time() < end:
        try:
            kind, body = read_pkt(sock)
        except (socket.timeout, TimeoutError):
            continue
        except OSError as exc:
            print(f"socket end {exc!r}", flush=True)
            break
        if kind is None:
            print("closed", flush=True)
            break
        t = kind >> 4
        if t == 3:
            qos = (kind >> 1) & 3
            tl = struct.unpack(">H", body[:2])[0]
            topic = body[2:2 + tl].decode(errors="replace")
            j = 2 + tl + (2 if qos else 0)
            payload = body[j:]
            print(f"PUBLISH {topic} len={len(payload)}", flush=True)
            print(f"  text={payload[:400].decode(errors='replace')!r}", flush=True)
            print(f"  hex={payload[:400].hex()}", flush=True)
            if qos == 1:
                sock.sendall(pkt(4, body[2 + tl:4 + tl]))
        elif t == 12:
            sock.sendall(pkt(13, b""))
        else:
            print(f"type {t} {body[:40].hex()}", flush=True)
    sock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

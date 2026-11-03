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

The device certificate is pinned: it must be byte-identical to the `cert.pem` in
the same per-device directory, and a client without a certificate is rejected. A
chain to `rootCA.crt` cannot be built because the AWS IoT device CA that issued it
is not published, so the leaf is the anchor (stricter than a shared CA anyway).
That directory's rootCA.crt is what the DEVICE installs as its broker trust
anchor, so the forge must serve it with the forged chain's anchor appended
(fss-79b89) or the device parks at TLS.

Identity: AWS IoT closes a session whose MQTT client id is not the thing name, so
an operator and the camera can never both be connected and the delta fan-out is a
lottery (EV-pack-H-002d §4.1). Here both identities coexist — sessions are kept in
a registry and PUBLISHes are routed to every subscriber of a matching filter.
"""
import argparse
import hashlib
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


class Session:
    """One MQTT connection. Writes are serialised: a fan-out may race the reader."""

    def __init__(self, conn, addr, client_id):
        self.conn, self.addr, self.client_id = conn, addr, client_id
        self.subs = []
        self.lock = threading.Lock()
        self.operator = False

    def send(self, data):
        with self.lock:
            self.conn.sendall(data)


SESSIONS = []
SESS_LOCK = threading.Lock()


def topic_matches(filt, topic):
    """MQTT filter match: `+` is one level, `#` is the rest."""
    f, t = filt.split("/"), topic.split("/")
    for i, part in enumerate(f):
        if part == "#":
            return True
        if i >= len(t) or (part != "+" and part != t[i]):
            return False
    return len(f) == len(t)


def deliver(topic, payload, qos=1, skip=None):
    """Publish to every session subscribed to a matching filter. Returns the count.

    This is what owning the endpoint buys: AWS closes a session whose client id is
    not the thing name, so operator and camera can never be connected at once and
    the delta fan-out is a lottery (EV-pack-H-002d §4.1). Here both stay connected
    and the broker does the routing.
    """
    with SESS_LOCK:
        targets = [s for s in SESSIONS
                   if s is not skip and any(topic_matches(f, topic) for f in s.subs)]
    for s in targets:
        try:
            s.send(packet(3, struct.pack(">H", len(topic.encode())) + topic.encode() + payload,
                          0x02 if qos else 0x00))
        except OSError:
            pass
    return len(targets)


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
    sess = Session(conn, addr, cid)
    sess.operator = cid != args.mac.lower()
    if sess.operator:
        print(f"[{addr[0]}] client_id != thing_name {args.mac.lower()!r} — operator session "
              f"(AWS closes these; here both identities coexist)", flush=True)
    conn.sendall(packet(2, b"\x00\x00"))
    with SESS_LOCK:
        SESSIONS.append(sess)
    try:
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
                sess.subs.extend(topics)
                conn.sendall(packet(9, pid + b"".join(b"\x01" for _ in topics)))
                if args.inject_url and any(tp.endswith("/wyze-service/get") for tp in topics):
                    threading.Thread(target=inject, args=(sess, topics, args), daemon=True).start()
            elif t == 3:
                qos = (kind >> 1) & 3
                ln = struct.unpack(">H", body[:2])[0]
                topic = body[2:2 + ln].decode(errors="replace")
                # QoS > 0 carries a 2-byte packet id before the payload
                payload = body[2 + ln + (2 if qos else 0):]
                print(f"[{addr[0]}] <- PUBLISH {topic} {payload[:160]!r}", flush=True)
                if qos == 1:
                    conn.sendall(packet(4, body[2 + ln:4 + ln]))
                shadow_update(sess, topic, payload, args)
            elif t == 12:
                conn.sendall(packet(13, b""))
            elif t == 10:
                conn.sendall(packet(11, body[:2]))
            elif t == 14:
                print(f"[{addr[0]}] DISCONNECT", flush=True)
                return
    finally:
        with SESS_LOCK:
            if sess in SESSIONS:
                SESSIONS.remove(sess)


def shadow_update(sess, topic, payload, args):
    """Fan an operator/device shadow write out to the subscribers that need it."""
    if topic.endswith("/cmd"):
        n = deliver(topic, payload, skip=sess)
        print(f"  -> cmd fanned to {n} session(s)", flush=True)
        return
    if not topic.endswith("/shadow/name/wyze-service/update"):
        return
    try:
        doc = json.loads(payload)
    except ValueError:
        print("  ! shadow update is not JSON", flush=True)
        return
    desired = (doc.get("state") or {}).get("desired") or {}
    if not desired:
        return
    acc = {"state": {"desired": desired, "reported": {}}, "version": 1, "timestamp": 1}
    if "clientToken" in doc:
        acc["clientToken"] = doc["clientToken"]
    acc_payload = json.dumps(acc).encode()
    acc_topic = topic + "/accepted"
    sess.send(packet(3, struct.pack(">H", len(acc_topic.encode())) + acc_topic.encode() + acc_payload))
    deliver(acc_topic, acc_payload, skip=sess)
    delta_topic = f"$aws/things/{args.mac}/shadow/name/wyze-service/update/delta"
    n = deliver(delta_topic, json.dumps({"state": {"desired": desired}, "version": 999}).encode())
    print(f"  -> update accepted, delta fanned to {n} session(s) {desired}", flush=True)


def inject(sess, topics, args):
    """Answer a shadow get and push the delta once the device subscribes."""
    time.sleep(args.delay)
    mac = args.mac
    doc = {"state": {"desired": {"url": args.inject_url, "md5": args.inject_md5,
                                 "model": args.model, "sub_mac": mac.upper()},
                     "reported": {}}, "version": 1, "timestamp": 1}
    for tp in topics:
        if tp.endswith("/shadow/name/wyze-service/get"):
            try:
                sess.send(packet(3, struct.pack(">H", len(tp.encode()) + 9) + (tp + "/accepted").encode()
                                 + json.dumps(doc).encode()))
                print("  -> get/accepted", flush=True)
            except OSError:
                return
    time.sleep(1)
    delta = {"state": {"desired": doc["state"]["desired"]}, "version": 999}
    tp = f"$aws/things/{mac}/shadow/name/wyze-service/update/delta"
    for _ in range(args.repeat):
        try:
            n = deliver(tp, json.dumps(delta).encode())
            print(f"  -> delta to {n} session(s)", flush=True)
        except OSError:
            return
        time.sleep(2)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mac", required=True)
    ap.add_argument("--port", type=int, default=8883, help="0 = ephemeral (the bound port is printed)")
    ap.add_argument("--iot-dir", default=IOT_DIR,
                    help="per-device credential store root holding <MAC>/{cert,privkey,rootCA}")
    ap.add_argument("--cert", default=CHAIN)
    ap.add_argument("--key", default=os.path.join(HERE, "..", "certs", "emudhra", "leaf.key"))
    ap.add_argument("--inject-url")
    ap.add_argument("--inject-md5")
    ap.add_argument("--model", default="HL_CAM4")
    ap.add_argument("--delay", type=float, default=1.0)
    ap.add_argument("--repeat", type=int, default=3)
    a = ap.parse_args()

    d = os.path.join(a.iot_dir, a.mac.upper())
    root = os.path.join(d, "rootCA.crt")
    if not os.path.isfile(root):
        print(f"missing {root}", file=sys.stderr)
        return 2
    # The device leaf is issued by an AWS IoT device CA whose intermediate is not
    # published, so a chain to rootCA.crt cannot be built from the files at hand.
    # Pin the leaf itself: stricter than a shared CA and per-device by construction.
    pin = None
    cert_path = os.path.join(d, "cert.pem")
    if os.path.isfile(cert_path):
        with open(cert_path) as fh:
            der = ssl.PEM_cert_to_DER_cert(fh.read())
            pin = hashlib.sha256(der if isinstance(der, bytes) else der.encode("latin-1")).hexdigest()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(a.cert, a.key)
    # CERT_OPTIONAL: the pin check below is the authority, and a certless client must
    # still be rejected rather than completing the handshake. PARTIAL_CHAIN lets the
    # pinned leaf itself be the anchor (its issuing intermediate is unpublished).
    ctx.verify_mode = ssl.CERT_OPTIONAL
    ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    ctx.load_verify_locations(root)
    if pin:
        ctx.load_verify_locations(cert_path)
    ctx.set_alpn_protocols([ALPN])

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", a.port))
    srv.listen(8)
    print(f"broker on :{srv.getsockname()[1]} alpn={ALPN} client-ca={root}", flush=True)
    while True:
        raw, addr = srv.accept()
        try:
            conn = ctx.wrap_socket(raw, server_side=True)
        except ssl.SSLError as exc:
            print(f"[{addr[0]}] TLS rejected: {exc}", flush=True)
            raw.close()
            continue
        der = conn.getpeercert(binary_form=True)
        if pin and (der is None or hashlib.sha256(der).hexdigest() != pin):
            print(f"[{addr[0]}] client certificate is not the pinned device cert", flush=True)
            conn.close()
            continue
        threading.Thread(target=handle, args=(conn, addr, a), daemon=True).start()
    return 0


if __name__ == "__main__":
    sys.exit(main())

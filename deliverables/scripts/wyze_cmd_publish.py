#!/usr/bin/env python3
"""Publish one command to a camera through the real broker, as a *separate* client.

Self-publishing on the device's own session (what the transparent proxy does) is PUBACKed but the
device's stack does not surface it to the command callback. Connecting with the device certificate
and the thing name, publishing, and hanging up delivers it as a normal broker message instead.

  wyze_cmd_publish.py <MAC> <ACTION> <JSON-PARAMS> [--enc ENR]

The body is XXTEA-encrypted with the ENR string, exactly as the cloud does.
"""
import base64
import json
import os
import socket
import ssl
import struct
import sys
import time

IOT = ("aws-iot.wyzecam.com", 8883)
SNI = "a24rq1e5m4mtei.iot.us-west-2.amazonaws.com"
IOT_DIR = os.path.expanduser("~/.config/fss-lab/wyze_iot")


def xxtea(data: bytes, key: bytes) -> bytes:
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


def enc_len(n: int) -> bytes:
    out = b""
    while True:
        d, n = n % 128, n // 128
        out += bytes([d | (0x80 if n else 0)])
        if not n:
            return out


def pkt(kind: int, body: bytes, flags: int = 0) -> bytes:
    return bytes([(kind << 4) | flags]) + enc_len(len(body)) + body


def s(x: str) -> bytes:
    b = x.encode()
    return len(b).to_bytes(2, "big") + b


def main() -> int:
    mac = sys.argv[1].upper()
    action = sys.argv[2]
    params = json.loads(sys.argv[3])
    enr = sys.argv[5] if len(sys.argv) > 5 and sys.argv[4] == "--enc" else None
    d = os.path.join(IOT_DIR, mac)
    ctx = ssl.create_default_context(cafile=os.path.join(d, "rootCA.crt"))
    ctx.load_cert_chain(os.path.join(d, "cert.pem"), os.path.join(d, "privkey.pem"))
    ctx.set_alpn_protocols(["x-amzn-mqtt-ca"])
    body = json.dumps({"Action": action, "Params": params, "Guid": os.urandom(8).hex(),
                       "Ts": int(time.time() * 1000)}, separators=(",", ":")).encode()
    if enr:
        body = xxtea(body + b"\0" * (-len(body) % 4), enr.encode())
    topic = f"hl/devices/{mac.lower()}/cmd"
    w = ctx.wrap_socket(socket.create_connection(IOT, timeout=10), server_hostname=SNI)
    w.settimeout(8)
    cid = mac.lower() + os.environ.get("CID_SUFFIX", "")
    w.sendall(pkt(1, s("MQTT") + bytes([4, 0x02]) + b"\x00\x3c" + s(cid)))
    if w.recv(4) != b"\x20\x02\x00\x00":
        sys.exit("connack refused")
    pid = os.urandom(2)
    w.sendall(pkt(3, s(topic) + pid + body, 0x02))
    try:
        r = w.recv(4)
        print("puback" if r[:1] == b"\x40" else f"reply {r!r}")
    except socket.timeout:
        print("no puback")
    w.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

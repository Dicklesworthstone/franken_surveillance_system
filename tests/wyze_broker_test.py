#!/usr/bin/env python3
"""Live test of the emulated broker: mutual TLS, identity coexistence, shadow fan-out.

Two facts are asserted end to end, over a real TLS session against a real listener:

  * the device-side trust path works only with the SERVED anchor bundle — a client
    trusting the store rootCA.crt alone fails, one trusting store root + the forged
    chain's anchor connects and the broker accepts the device certificate;
  * the client-id rule that AWS enforces (id must equal the thing name, else the
    session is closed — EV-pack-H-002d §4.1) is relaxed here on purpose, so an
    operator session and the camera coexist and a shadow write reaches the device.

  python3 tests/wyze_broker_test.py
"""
import json
import os
import re
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
BROKER = os.path.join(ROOT, "deliverables", "scripts", "wyze_mqtt_broker.py")
CERTS = os.path.join(ROOT, "deliverables", "certs")
STORE = os.path.join(CERTS, "iot")
MAC = "80482C4BCF0B"
THING = MAC.lower()
HOST = "a24rq1e5m4mtei.iot.us-west-2.amazonaws.com"
DELTA = f"$aws/things/{MAC}/shadow/name/wyze-service/update/delta"
UPDATE = f"$aws/things/{MAC}/shadow/name/wyze-service/update"
CMD = f"hl/devices/{THING}/cmd"

FAILURES = []


def check(name, cond, detail=""):
    print(f"  [{'ok ' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


def enc_len(n):
    out = b""
    while True:
        d, n = n % 128, n // 128
        out += bytes([d | (0x80 if n else 0)])
        if not n:
            return out


def pkt(kind, body, flags=0):
    return bytes([(kind << 4) | flags]) + enc_len(len(body)) + body


def s(x):
    b = x.encode()
    return struct.pack(">H", len(b)) + b


def read_packet(sock):
    head = sock.recv(1)
    if not head:
        return None, b""
    n, mult = 0, 1
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


def client_ctx(cafile, device=True):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.load_verify_locations(cafile)
    c.check_hostname = True
    if device:
        c.load_cert_chain(os.path.join(STORE, MAC, "cert.pem"), os.path.join(STORE, MAC, "privkey.pem"))
    c.set_alpn_protocols(["x-amzn-mqtt-ca"])
    return c


def connect(port, ctx, client_id):
    raw = socket.create_connection(("127.0.0.1", port), timeout=5)
    c = ctx.wrap_socket(raw, server_hostname=HOST)
    c.sendall(pkt(1, s("MQTT") + b"\x04\x02" + b"\x00\x3c" + s(client_id)))
    kind, body = read_packet(c)
    return c, kind, body


def subscribe(c, topic):
    c.sendall(pkt(8, b"\x00\x01" + s(topic) + b"\x01"))
    return read_packet(c)


def start_broker():
    p = subprocess.Popen([sys.executable, BROKER, "--mac", MAC, "--port", "0", "--iot-dir", STORE],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    deadline = time.time() + 10
    port = None
    while time.time() < deadline:
        line = p.stdout.readline()
        m = re.search(r"broker on :(\d+)", line or "")
        if m:
            port = int(m.group(1))
            break
        if p.poll() is not None:
            break
    if port is None:
        p.kill()
        raise SystemExit("broker did not start")
    return p, port


def main() -> int:
    p, port = start_broker()
    try:
        bundle = os.path.join(tempfile.mkdtemp(), "rootCA.crt")
        with open(bundle, "wb") as out:
            out.write(open(os.path.join(STORE, MAC, "rootCA.crt"), "rb").read())
            out.write(b"\n" + open(os.path.join(CERTS, "emudhra", "aaa-root.pem"), "rb").read())
        alone = os.path.join(STORE, MAC, "rootCA.crt")

        print("device-side trust anchor:")
        try:
            connect(port, client_ctx(alone), THING)[0].close()
            check("store root alone is rejected (the park)", False, "connected")
        except ssl.SSLError as exc:
            check("store root alone is rejected (the park)", True)
            check("rejection is hostname verification",
                  "CERTIFICATE_VERIFY_FAILED" in str(exc), str(exc))
        dev, kind, body = connect(port, client_ctx(bundle), THING)
        check("bundle validates the broker and CONNACK is accepted", kind >> 4 == 2 and body[:2] == b"\x00\x00")
        check("ALPN negotiated", dev.selected_alpn_protocol() == "x-amzn-mqtt-ca")
        kind, body = subscribe(dev, DELTA)
        check("SUBACK for the delta topic", kind >> 4 == 9)
        kind, body = subscribe(dev, "hl/devices/+/cmd")
        check("SUBACK for the wildcard cmd filter", kind >> 4 == 9)

        print("operator identity coexists with the device id:")
        op, kind, body = connect(port, client_ctx(bundle), "omp-test")
        check("operator CONNACK accepted (AWS would close it)", kind >> 4 == 2 and body[:2] == b"\x00\x00")
        kind, body = subscribe(op, CMD)
        check("SUBACK for the cmd topic", kind >> 4 == 9)

        print("shadow write fans out:")
        op.sendall(pkt(3, s(UPDATE) + b"\x00\x01" + json.dumps(
            {"state": {"desired": {"url": "https://x/cap.tar", "md5": "abc", "model": "HL_CAM4"}},
             "clientToken": "tok"}).encode(), 0x02))
        kind, body = read_packet(op)
        check("publisher gets PUBACK", kind >> 4 == 4)
        kind, body = read_packet(op)
        ln = struct.unpack(">H", body[:2])[0]
        check("publisher gets update/accepted", body[2:2 + ln].decode() == UPDATE + "/accepted")
        check("accepted echoes the clientToken", json.loads(body[2 + ln:]).get("clientToken") == "tok")
        dev.settimeout(5)
        kind, body = read_packet(dev)
        ln = struct.unpack(">H", body[:2])[0]
        check("device session receives the delta", body[2:2 + ln].decode() == DELTA)
        check("delta carries the operator payload",
              json.loads(body[2 + ln:])["state"]["desired"]["md5"] == "abc")

        print("command fan-out:")
        op.sendall(pkt(3, s(CMD) + b"\x00\x01" + b"\xde\xad", 0x02))
        kind, body = read_packet(op)
        check("cmd PUBACK", kind >> 4 == 4)
        kind, body = read_packet(dev)
        ln = struct.unpack(">H", body[:2])[0]
        check("device session receives the cmd on its filter",
              body[2:2 + ln].decode() == CMD and body[2 + ln:] == b"\xde\xad")

        print("mutual TLS:")
        try:
            connect(port, client_ctx(bundle, device=False), "no-cert")[0].close()
            check("client without a certificate is rejected", False, "connected")
        except (ssl.SSLError, ConnectionResetError):
            # CERT_OPTIONAL lets the handshake finish; the pin check closes it after
            check("client without a certificate is rejected", True)

        print("topic matching:")
        sys.path.insert(0, os.path.join(ROOT, "deliverables", "scripts"))
        import wyze_mqtt_broker as br
        check("+ matches one level", br.topic_matches("hl/devices/+/cmd", CMD))
        check("# matches the rest", br.topic_matches("$aws/#", DELTA))
        check("no false prefix match", not br.topic_matches("hl/devices/+/cmd", CMD + "/x"))
        check("literal mismatch", not br.topic_matches("a/b", "a/c"))
    finally:
        p.kill()
        p.wait(timeout=5)

    if FAILURES:
        print(f"\n{len(FAILURES)} failure(s): {FAILURES}")
        return 1
    print("\nall broker checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

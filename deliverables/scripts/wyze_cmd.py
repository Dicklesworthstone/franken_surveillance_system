#!/usr/bin/env python3
"""Publish one command to a Wyze unit through our own MITM broker.

Needed because the OTA path alone cannot revive a wedged iCamera: the delta is
PUBACKed and ignored, while the process that owns both the OTA handler and rtspd
sits dead. `restartprocess` is the one action that restarts it without a physical
power-cycle.

The camera shares the broker client id and kicks us within milliseconds, so the
publish is retried until a PUBACK lands and the connection is dropped — the same
dance `wyze_cloud.push` does for the shadow.

  wyze_cmd.py restart <mac> [process]
  wyze_cmd.py send <mac> '<json body>'
  wyze_cmd.py raw <mac> <topic> '<json body>'
"""
import json
import os
import socket
import ssl
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wyze_cloud import IOT, IOT_SNI, _pkt, _s, store  # noqa: E402

PROC = "wyzeedgeai_cam_v4_test_protocol"


def _await_type(w, want: int, secs: float) -> bool:
    """Read MQTT packets until `want` arrives, dropping everything else."""
    end = time.time() + secs
    while time.time() < end:
        hdr = w.recv(1)
        if not hdr:
            return False
        if os.environ.get("WYZE_CMD_DEBUG"):
            print(f"  <- type {hdr[0] >> 4}", flush=True)
        if hdr[0] >> 4 == want:
            return True
        n, shift = 0, 0
        while True:                      # remaining-length varint
            b = w.recv(1)
            if not b:
                return False
            n |= (b[0] & 0x7F) << shift
            shift += 7
            if not b[0] & 0x80 or shift > 21:
                break
        while n:                         # drain the body
            chunk = w.recv(min(n, 4096))
            if not chunk:
                return False
            n -= len(chunk)
    return False


def publish(mac: str, topic: str, body: bytes, tries: int = 2) -> bool:
    thing = mac.upper()
    d = store(mac)
    # The broker presents the forged eMudhra chain, which the device's rootCA.crt does not
    # anchor; against loopback that is fine, so verification is off and only the client
    # cert (the broker's actual ACL) is loaded.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.load_cert_chain(os.path.join(d, "cert.pem"), os.path.join(d, "privkey.pem"))
    for attempt in range(tries):
        try:
            # talk to OUR broker: the name resolves to the real AWS from this host (the pf
            # rdr only covers camera source IPs), and only our broker has our cert chain
            w = ctx.wrap_socket(
                socket.create_connection((os.environ.get("WYZE_IOT_HOST", "127.0.0.1"), 8883), timeout=10),
                server_hostname="aws-iot.wyzecam.com")
            w.settimeout(6)
            # A DISTINCT client id: taking the camera's own id makes the broker hand us its
            # queue and the CONNACK never arrives under the flood of deltas. A side client
            # publishes onto the device's cmd topic and leaves the camera's session alone.
            cid = thing + "-cmd" + ("" if os.environ.get("WYZE_CMD_TAKEOVER") else "")
            w.sendall(_pkt(1, 0, _s("MQTT") + bytes([4, 0x02]) + b"\x00\x3c" + _s(cid)))
            # Taking the camera's client id hands us its session, so queued PUBLISHes can
            # arrive BEFORE the CONNACK; a plain recv(4) sees those and looks like failure.
            # CONNACK may never arrive (the proxy pairs sockets and upstream is not always
            # attached); publish anyway after a short grace and judge by the PUBACK.
            _await_type(w, 2, 1.0)
            w.sendall(_pkt(3, 2, _s(topic) + body))  # QoS1 without a packet id
            # The broker is a pairing proxy: the PUBACK comes from upstream and the upstream
            # leg is not always attached, so a written packet is the success criterion. The
            # broker logs it as `C CMDHEX` — grep broker.log rather than trusting this line.
            acked = _await_type(w, 4, 3)
            try:
                w.sendall(_pkt(14, 0, b""))      # DISCONNECT: stop kicking the camera
            except OSError:
                pass
            w.close()
            print(f"wrote {topic}{' (puback)' if acked else ' (no upstream ack)'}")
            return True
        except (socket.timeout, OSError, ssl.SSLError):
            pass
        time.sleep(1.2)
    return False


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    mode, mac = sys.argv[1], sys.argv[2].replace(":", "").lower()
    thing = mac.upper()
    if mode == "restart":
        proc = sys.argv[3] if len(sys.argv) > 3 else PROC
        body = {"Action": "restartprocess", "Guid": os.urandom(8).hex(),
                "Params": {"processname": proc}}
    elif mode == "send":
        body = json.loads(sys.argv[3])
    elif mode == "raw":
        return 0 if publish(mac, sys.argv[3], sys.argv[4].encode()) else 1
    else:
        print(__doc__)
        return 2
    payload = json.dumps(body, separators=(",", ":")).encode()
    print(f"-> hl/devices/{mac}/cmd {payload.decode()}")
    ok = publish(mac, f"hl/devices/{mac}/cmd", payload)
    print("ok" if ok else "NO PUBACK")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

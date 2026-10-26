#!/usr/bin/env python3
"""Prove the broker accepts a client presenting the device certificate.

Connects with the per-device cert/key, verifies the broker against the forged
eMudhra chain, offers ALPN x-amzn-mqtt-ca, subscribes to the shadow get topic and
waits for the delta. Exits 0 only if CONNACK and SUBACK both arrive.

  wyze_mqtt_probe.py --mac 80482C4BCF0B [--port 8884] [--no-client-cert]
"""
import argparse
import os
import sys
import time

import socket
import ssl

import paho.mqtt.client as mqtt

HERE = os.path.dirname(os.path.abspath(__file__))
CHAIN = os.path.join(HERE, "..", "certs", "emudhra", "serve.pem")
# the served chain ends at the AAA cross-sign; the client trusts the AAA root
ISSUER = os.path.join(HERE, "..", "certs", "emudhra", "aaa-root.pem")
IOT_DIR = os.path.expanduser("~/.config/fss-lab/wyze_iot")
SNI = "a24rq1e5m4mtei.iot.us-west-2.amazonaws.com"

got = {"conn": False, "sub": False, "delta": False}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mac", required=True)
    ap.add_argument("--port", type=int, default=8884)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--no-client-cert", action="store_true")
    ap.add_argument("--wait", type=float, default=8.0)
    a = ap.parse_args()

    d = os.path.join(IOT_DIR, a.mac.upper())
    c = mqtt.Client(client_id=a.mac.lower(), protocol=mqtt.MQTTv311)
    kw = dict(ca_certs=ISSUER, alpn_protocols=["x-amzn-mqtt-ca"], tls_version=ssl.PROTOCOL_TLS)
    if not a.no_client_cert:
        kw["certfile"] = os.path.join(d, "cert.pem")
        kw["keyfile"] = os.path.join(d, "privkey.pem")
    c.tls_set(**kw)

    def on_connect(cl, u, f, rc):
        got["conn"] = rc == 0
        print("CONNACK rc=", rc, flush=True)
        cl.subscribe(f"$aws/things/{a.mac}/shadow/name/wyze-service/get", qos=1)

    def on_subscribe(cl, u, mid, granted):
        got["sub"] = True
        print("SUBACK", granted, flush=True)

    def on_message(cl, u, msg):
        if msg.topic.endswith("update/delta"):
            got["delta"] = True
            print("DELTA", msg.payload[:120], flush=True)

    c.on_connect, c.on_subscribe, c.on_message = on_connect, on_subscribe, on_message
    # the certificate is issued for the IoT name, so connect by name and steer the
    # lookup at the broker under test
    real = socket.getaddrinfo
    socket.getaddrinfo = lambda h, p, *rest, **k: real(a.host if h == SNI else h, p, *rest, **k)
    try:
        c.connect(SNI, a.port, keepalive=30)
    except Exception as exc:
        print("connect failed:", exc)
        return 1
    c.loop_start()
    end = time.time() + a.wait
    while time.time() < end and not (got["conn"] and got["sub"]):
        time.sleep(0.2)
    time.sleep(1.5)
    c.loop_stop()
    c.disconnect()
    print("result", got)
    return 0 if (got["conn"] and got["sub"]) else 1


if __name__ == "__main__":
    sys.exit(main())

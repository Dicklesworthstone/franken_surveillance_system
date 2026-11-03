#!/usr/bin/env python3
"""Unit-test the get_iot_certificate responder against the device-side contract.

The consumer is iCamera fcn.005e0d64 (iot_certificate.c) + cloud_check_comm_resp
(fcn.005e1948). The contract, verified in disassembly (fss-79b89, ota-path.md §18):

  envelope: "code" MUST be the string "1" (strcmp at 0x5e1978 vs literal "1" 0x868790)
  data:     client_id (str, required)  keep_alive (number, required — cJSON type 8)
            thing_name (str, required) client_cert_url / client_private_key_url /
            root_cert_url (str, required)
            client_username / client_password: required-PRESENT strings, may be empty
            (type 0x10 checked; missing is tolerated via 0x5e1434/0x5e1464)

  python3 tests/wyze_iot_certificate_test.py
"""
import importlib.util
import json
import os
import socket
import ssl
import subprocess
import sys
import time
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SERVE = os.path.join(HERE, "..", "deliverables", "scripts", "wyze_forge_serve.py")

spec = importlib.util.spec_from_file_location("wyze_forge_serve", SERVE)
forge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(forge)

FAILURES = []


def check(name, cond, detail=""):
    tag = "ok " if cond else "FAIL"
    print(f"  [{tag}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


def make_store(tmp):
    d = os.path.join(tmp, "80482C4BCF0B")
    os.makedirs(d, exist_ok=True)
    # minimal structurally-valid PEM-ish files; contents irrelevant to the shape test
    open(os.path.join(d, "cert.pem"), "w").write("-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n")
    open(os.path.join(d, "privkey.pem"), "w").write("-----BEGIN PRIVATE KEY-----\nX\n-----END PRIVATE KEY-----\n")
    open(os.path.join(d, "rootCA.crt"), "w").write("-----BEGIN CERTIFICATE-----\nR\n-----END CERTIFICATE-----\n")
    return d


def test_shape(tmp):
    print("envelope + data vs iotCertBodyParse contract:")
    store = make_store(tmp)
    obj = forge.iot_certificate_response(store, "80482C4BCF0B", trace_id="t" * 32)

    # envelope: code string "1" (cloud_check_comm_resp), msg, traceId
    check("code is string '1'", obj.get("code") == "1", repr(obj.get("code")))
    check("msg == SUCCESS", obj.get("msg") == "SUCCESS")
    check("traceId honored", obj["traceId"] == "t" * 32)

    data = obj["data"]
    # required string fields (missing => parse fail at 0x5e146c/0x5e14cc)
    check("client_id present+str", isinstance(data.get("client_id"), str) and data["client_id"])
    check("client_id is lowercase mac", data.get("client_id") == "80482c4bcf0b",
          repr(data.get("client_id")))
    check("thing_name present+str", isinstance(data.get("thing_name"), str) and data["thing_name"])
    check("thing_name == client_id", data["thing_name"] == data["client_id"])
    # keep_alive must be a NUMBER (cJSON type 8 checked at 0x5e1010 — a string here
    # makes the parse fail with "no keep_alive")
    ka = data.get("keep_alive")
    check("keep_alive is number", isinstance(ka, int) and not isinstance(ka, bool), repr(ka))
    check("keep_alive == 300 (app capture)", ka == 300)
    # username/password: required-PRESENT strings, empty in the real answer
    for f in ("client_username", "client_password"):
        v = data.get(f)
        check(f"{f} present+str", isinstance(v, str), repr(v))
    # the three URLs, exact key names the parser looks up (0x877404/0x877488/0x877514)
    for f in ("client_cert_url", "client_private_key_url", "root_cert_url"):
        v = data.get(f)
        check(f"{f} present+str", isinstance(v, str) and v.startswith("https://"), repr(v))
    check("urls under /fss/", data["client_cert_url"].endswith("/fss/cert.pem")
          and data["client_private_key_url"].endswith("/fss/privkey.pem")
          and data["root_cert_url"].endswith("/fss/rootCA.crt"))
    # no ca_cert_url key — the parser only reads root_cert_url (0x877514)
    check("no legacy ca_cert_url key", "ca_cert_url" not in data)
    # top-level key set exactly matches the captured envelope
    check("top-level keys", set(obj) == {"code", "msg", "data", "traceId"}, str(sorted(obj)))
    return obj


def test_missing_store(tmp):
    print("missing-store path (loud log, URLs still served):")
    empty = os.path.join(tmp, "empty-store")
    os.makedirs(empty, exist_ok=True)
    obj = forge.iot_certificate_response(empty, "80482C4BCF0B")
    check("still returns envelope", obj.get("code") == "1")
    check("urls unchanged", obj["data"]["client_cert_url"].endswith("/fss/cert.pem"))


def test_mac_fallback(tmp):
    print("mac normalization:")
    store = make_store(tmp)
    obj = forge.iot_certificate_response(store, "80482c4bcf0b")
    check("lowercase input -> lowercase id", obj["data"]["client_id"] == "80482c4bcf0b")
    # empty mac at the handler layer defaults to the store's first MAC dir
    # (mirrors the in-handler fallback; tested via the same listdir logic)
    entry = next((e for e in sorted(os.listdir(tmp))
                  if os.path.isdir(os.path.join(tmp, e))), None)
    obj2 = forge.iot_certificate_response(store, "")
    check("empty mac leaves id empty for handler to fill", obj2["data"]["client_id"] == "")
    check("store has a MAC dir to fall back to", entry == "80482C4BCF0B", repr(entry))


def test_root_bundle(tmp):
    """The served rootCA.crt must validate the FORGED BROKER LEAF for the broker host.

    The device installs exactly these bytes as /tmp/aws_iot/rootCA.crt and verifies the
    8883 leaf against them. Served without the forged chain's anchor the session dies
    at TLS ("unable to get local issuer certificate") — that is the park after a
    successful certificate handoff (fss-79b89).
    """
    print("rootCA.crt bundle (device-side trust anchor):")
    certs = os.path.join(HERE, "..", "deliverables", "certs")
    store_root = open(os.path.join(certs, "iot", "80482C4BCF0B", "rootCA.crt"), "rb").read()
    aaa = os.path.join(certs, "emudhra", "aaa-root.pem")
    leaf = os.path.join(certs, "emudhra", "leaf.pem")
    inter = os.path.join(certs, "emudhra", "ev-ca-aaa-cross.pem")
    host = "a24rq1e5m4mtei.iot.us-west-2.amazonaws.com"

    bundle = forge.iot_root_bundle(store_root, [aaa])
    check("store root kept verbatim at the front", bundle.startswith(store_root))
    check("anchor appended, newline separated",
          store_root + b"\n" in bundle and aaa.encode() and open(aaa, "rb").read() in bundle)

    # the real question: does a client trusting the served bytes accept the broker leaf?
    served = os.path.join(tmp, "served-rootCA.crt")
    open(served, "wb").write(bundle)
    r = subprocess.run(["openssl", "verify", "-CAfile", served, "-untrusted", inter,
                        "-verify_hostname", host, leaf], capture_output=True, text=True)
    check("served bundle validates the forged leaf for the broker host",
          r.returncode == 0, (r.stdout + r.stderr).strip())
    # and the store root alone does not — the regression this fix removes
    alone = os.path.join(tmp, "store-rootCA.crt")
    open(alone, "wb").write(store_root)
    r = subprocess.run(["openssl", "verify", "-CAfile", alone, "-untrusted", inter,
                        "-verify_hostname", host, leaf], capture_output=True, text=True)
    check("store root alone does NOT validate the forged leaf", r.returncode != 0)

    check("missing anchor is loud, not fatal",
          forge.iot_root_bundle(b"-----BEGIN CERTIFICATE-----\nX\n", ["/nonexistent.pem"])
          .startswith(b"-----BEGIN CERTIFICATE-----\nX\n"))
    check("no anchor -> bytes unchanged",
          forge.iot_root_bundle(b"pem\n", []) == b"pem\n")


def test_served_root_bundle_live(tmp):
    """The handler actually ships the bundle, and ships the other two files verbatim."""
    print("live /fss/ serving:")
    certs = os.path.join(HERE, "..", "deliverables", "certs")
    store = os.path.join(certs, "iot", "80482C4BCF0B")
    served = os.path.join(tmp, "served")
    os.makedirs(served, exist_ok=True)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    proc = subprocess.Popen([sys.executable, SERVE, "--dir", served, "--port", str(port),
                             "--iot-cert", "--iot-cert-dir", os.path.join(certs, "iot"),
                             "--cert", os.path.join(certs, "emudhra", "leaf.pem"),
                             "--key", os.path.join(certs, "emudhra", "leaf.key")],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        # not create_default_context: X509_STRICT wants AKI/SKI that this chain lacks
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(os.path.join(certs, "emudhra", "aaa-root.pem"))
        def connect():
            # the forge serves one connection at a time (plain HTTPServer): one per GET
            deadline = time.time() + 10
            while True:
                try:
                    return ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=2),
                                           server_hostname="s3-us-west-2.amazonaws.com")
                except OSError:
                    if time.time() > deadline:
                        raise
                    time.sleep(0.2)

        def get(name):
            c = connect()
            try:
                c.sendall(f"GET /fss/{name} HTTP/1.1\r\nHost: s3-us-west-2.amazonaws.com\r\n"
                          f"Connection: close\r\n\r\n".encode())
                buf = b""
                while True:
                    chunk = c.recv(65536)
                    if not chunk:
                        return buf
                    buf += chunk
            finally:
                c.close()

        root = get("rootCA.crt").split(b"\r\n\r\n", 1)[1]
        check("served rootCA.crt carries the store root",
              open(os.path.join(store, "rootCA.crt"), "rb").read() in root)
        check("served rootCA.crt carries the forged-chain anchor",
              open(os.path.join(certs, "emudhra", "aaa-root.pem"), "rb").read() in root)
        bundle_path = os.path.join(tmp, "live-rootCA.crt")
        open(bundle_path, "wb").write(root)
        r = subprocess.run(["openssl", "verify", "-CAfile", bundle_path, "-untrusted",
                            os.path.join(certs, "emudhra", "ev-ca-aaa-cross.pem"),
                            "-verify_hostname", "a24rq1e5m4mtei.iot.us-west-2.amazonaws.com",
                            os.path.join(certs, "emudhra", "leaf.pem")],
                           capture_output=True, text=True)
        check("served bytes validate the broker leaf", r.returncode == 0, r.stderr.strip())
        check("cert.pem served verbatim",
              get("cert.pem").split(b"\r\n\r\n", 1)[1]
              == open(os.path.join(store, "cert.pem"), "rb").read())
    finally:
        proc.kill()
        proc.wait(timeout=5)


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        test_shape(tmp)
        test_missing_store(tmp)
        test_mac_fallback(tmp)
        test_root_bundle(tmp)
        test_served_root_bundle_live(tmp)
    if FAILURES:
        print(f"\n{len(FAILURES)} failure(s): {FAILURES}")
        return 1
    print("\nall iot_certificate contract checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

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
import sys
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


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        test_shape(tmp)
        test_missing_store(tmp)
        test_mac_fallback(tmp)
    if FAILURES:
        print(f"\n{len(FAILURES)} failure(s): {FAILURES}")
        return 1
    print("\nall iot_certificate contract checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

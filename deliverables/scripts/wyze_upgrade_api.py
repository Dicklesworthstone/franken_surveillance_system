#!/usr/bin/env python3
"""Signed requests to the Wyze upgrade service (the OTA push path).

The signature was recovered from the app: `Signature2 = HMAC_MD5(body, md5(access_token + secret))`
with the per-appid secret from the 127-row table, appid 9319141212m2ik -> wyze_app_secret_key_132.
The service is a different host from the main API and rejects every request without it.

  wyze_upgrade_api.py version  <MAC> <MODEL> <CURRENT> <HARDWARE>
  wyze_upgrade_api.py push     <MAC> <MODEL> <CURRENT> <HARDWARE> <ID> <TARGET>
  wyze_upgrade_api.py status   <MAC> <MODEL> <TARGET>

`push` is what makes the cloud emit its own `cmd 1234` to the device, which is the only way to read
the real command body (see docs/exploit/wyze-lan-rce.md).
"""
import hashlib
import hmac
import json
import os
import ssl
import sys
import urllib.request

HOST = "https://wyze-upgrade-service.wyzecam.com"
APPID = "9319141212m2ik"
SECRET = "wyze_app_secret_key_132"
AUTH = os.path.expanduser("~/.config/fss-lab/wyze_auth.json")


def token() -> str:
    tok = os.environ.get("WYZE_TOKEN")
    if tok:
        return tok
    with open(AUTH) as fh:
        return json.load(fh)["access_token"]


def post(path: str, body: dict) -> dict:
    raw = json.dumps(body, separators=(",", ":")).encode()
    key = hashlib.md5((token() + SECRET).encode()).hexdigest().encode()
    sig = hmac.new(key, raw, hashlib.md5).hexdigest().upper()
    req = urllib.request.Request(HOST + path, data=raw, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("appid", APPID)
    req.add_header("access_token", token())
    req.add_header("Signature2", sig)
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
        return json.loads(resp.read())


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    cmd, mac = sys.argv[1], sys.argv[2].upper()
    if cmd == "version":
        print(json.dumps(post("/app/v2/upgrade/get_upgrade_firmware", {
            "deviceId": mac, "deviceModel": sys.argv[3],
            "currentVer": sys.argv[4], "hardwareVer": sys.argv[5]}), indent=2))
    elif cmd == "push":
        print(json.dumps(post("/app/v2/upgrade/begin_upgrade", {
            "deviceId": mac, "deviceModel": sys.argv[3], "currentVer": sys.argv[4],
            "hardwareVer": sys.argv[5], "id": int(sys.argv[6]),
            "targetVer": sys.argv[7], "testCode": "Test Version"}), indent=2))
    elif cmd == "status":
        print(json.dumps(post("/app/v2/upgrade/get_upgrade_status", {
            "deviceId": mac, "deviceModel": sys.argv[3], "targetVer": sys.argv[4]}), indent=2))
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

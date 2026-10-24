#!/usr/bin/env python3
"""Tapo cloud client: login, device list, and the `preWakeUp` / `reboot` services.

The LAN wake surfaces are served by `main` itself, so a camera whose app is dead
cannot answer them. The app's own wake is a cloud thing-service
(`ThingCloudRepository.M0/N0` -> `executeThingServiceQos0(..., "preWakeUp", ...)`),
which is what this drives.

Signing is the Tapo Android app's: HMAC-SHA1 over
`base64(md5(body))\\ntimestamp\\nnonce\\npath` with the app-level keys, sent in
`X-Authorization`. The timestamp is the app's fixed `9999999999`.

Credentials come from `--email`/`--password`, `TAPO_EMAIL`/`TAPO_PASSWORD`, or
`~/.config/fss-lab/tapo.env` (`TAPO_EMAIL=…`, `TAPO_PASSWORD=…`). The token is
cached in `~/.config/fss-lab/tapo_token.json` (0600).

Usage:
  tapo_cloud.py login
  tapo_cloud.py devices
  tapo_cloud.py wake <thingName>
  tapo_cloud.py reboot <thingName>
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
import uuid

LOGIN_HOST = "https://n-wap.i.tplinkcloud.com"
ACCESS_KEY = "4d11b6b9d5ea4d19a829adbb9714b057"
SECRET_KEY = "6ed7d97f3e73467f8a5bab90b577ba4c"
SIGN_TS = "9999999999"
APP_TYPE = "TP-Link_Tapo_Android"
ENV_FILE = os.path.expanduser("~/.config/fss-lab/tapo.env")
TOKEN_FILE = os.path.expanduser("~/.config/fss-lab/tapo_token.json")
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE  # the Tapo hosts still serve an expired chain


def creds() -> tuple[str, str]:
    email = os.environ.get("TAPO_EMAIL")
    password = os.environ.get("TAPO_PASSWORD")
    if not (email and password) and os.path.exists(ENV_FILE):
        for line in open(ENV_FILE):
            k, _, v = line.strip().partition("=")
            if k == "TAPO_EMAIL":
                email = email or v
            elif k == "TAPO_PASSWORD":
                password = password or v
    if not (email and password):
        sys.exit("no credentials: set TAPO_EMAIL/TAPO_PASSWORD or write %s" % ENV_FILE)
    return email, password


def signed_post(url: str, body: dict, token: str | None = None) -> dict:
    raw = json.dumps(body, separators=(",", ":"))
    path = "/" + url.split("/", 3)[3].split("?")[0]
    md5 = base64.b64encode(hashlib.md5(raw.encode()).digest()).decode()
    nonce = str(uuid.uuid1())
    sig = hmac.new(SECRET_KEY.encode(), ("%s\n%s\n%s\n%s" % (md5, SIGN_TS, nonce, path)).encode(),
                   hashlib.sha1).hexdigest()
    req = urllib.request.Request(url, data=raw.encode(), method="POST")
    req.add_header("Content-Md5", md5)
    req.add_header("X-Authorization",
                   "Timestamp=%s, Nonce=%s, AccessKey=%s, Signature=%s"
                   % (SIGN_TS, nonce, ACCESS_KEY, sig))
    req.add_header("Content-Type", "application/json; charset=UTF-8")
    req.add_header("User-Agent", "okhttp/3.12.13")
    if token:
        req.add_header("Authorization", "ut|" + token)
    try:
        return json.loads(urllib.request.urlopen(req, context=CTX, timeout=25).read())
    except urllib.error.HTTPError as exc:
        return json.loads(exc.read() or b"{}")


def login() -> dict:
    email, password = creds()
    body = {"appType": APP_TYPE, "appVersion": "2.12.705", "cloudPassword": password,
            "cloudUserName": email, "platform": "Android 12", "refreshTokenNeeded": False,
            "terminalMeta": "1", "terminalName": "fss", "terminalUUID":
            str(uuid.uuid1()).replace("-", "").upper()}
    res = signed_post(LOGIN_HOST + "/api/v2/account/login", body)
    result = res.get("result") or {}
    if res.get("error_code") != 0 or result.get("errorCode") not in (None, "0", 0):
        sys.exit("login failed: %s" % json.dumps(res)[:300])
    tok = {"token": result["token"], "appServerUrl": result["appServerUrl"],
           "email": email, "ts": time.time()}
    fd = os.open(TOKEN_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(tok, fh)
    print("token ok, appServerUrl %s" % tok["appServerUrl"])
    return tok


def session() -> dict:
    if not os.path.exists(TOKEN_FILE):
        return login()
    tok = json.load(open(TOKEN_FILE))
    if time.time() - tok.get("ts", 0) > 6 * 3600:
        return login()
    return tok


def api(tok: dict, path: str, body: dict) -> dict:
    url = tok["appServerUrl"].rstrip("/") + path + "?token=" + tok["token"]
    res = signed_post(url, body, tok["token"])
    if res.get("error_code") not in (0, None):
        sys.exit("api %s failed: %s" % (path, json.dumps(res)[:300]))
    return res


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["login", "devices", "wake", "reboot"])
    ap.add_argument("thing", nargs="?")
    a = ap.parse_args()

    if a.cmd == "login":
        login()
        return 0

    tok = session()
    if a.cmd == "devices":
        res = api(tok, "/api/v2/common/getDeviceList", {})
        for d in res.get("result", {}).get("deviceList", []):
            print("%-34s %-12s %-16s %s" % (d.get("deviceId"), d.get("deviceModel"),
                                            d.get("ip") or d.get("lanIp") or "-",
                                            d.get("deviceName")))
        return 0

    if not a.thing:
        sys.exit("thing name required")
    service = "preWakeUp" if a.cmd == "wake" else "reboot"
    res = api(tok, "/v1/things/%s/services/qos0" % a.thing,
              {"serviceId": service, "inputParams": {}})
    print(json.dumps(res)[:300])
    return 0


if __name__ == "__main__":
    sys.exit(main())

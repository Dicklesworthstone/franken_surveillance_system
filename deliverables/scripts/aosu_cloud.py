#!/usr/bin/env python3
"""AOSU (Glazero) owner API client — reverse-engineered from the 5.10.12 APK.

Everything here was read out of the app, not guessed:

  * `Gz-Pid` is the channel constant `AppChannel.OooO0oO()` = **"glazero"**
    (`AppConstant.APP_CHANNEL_PID` -> `AppChannelPlatform.OooO0OO()`).
  * Login is **form-encoded** `POST /v1/user/login` with
    `region,countryCode,countryAbbr,type=1,email,password,pwType=2`
    (`AccountCenter.OooOooO` -> `AccountWebService.OooO0oO`).
  * `password` is `base64(AES-128-CBC(PKCS7(password)))` with
    **key = iv = "PZR1ryiUhJloWoRd"** — a constant at `libglazero-security.so:0x18bc4`
    consumed by `SecurityCore.nativeEncryptP` (Java_..._nativeEncryptP calls
    `SecurityCore::aes_encrypt_pkcs7` with the same buffer as key and iv).
  * Every request carries `uuid` and `t` query params (`CommonInterceptor`), and
    `Gz-Sign = md5("uuid:<uuid>:t:<t>:&sM&GGlUCSXjZqQNxmkdU^scUs**0R@C")` lowercased
    (`SignInterceptor`).
  * The server 404s without the app User-Agent and answers `104 pid参数错误`
    without `Gz-Pid`, so both are mandatory.

Usage:
  aosu_cloud.py login                 # prints sid/uid, caches them 0600
  aosu_cloud.py call PATH [JSON]      # signed call, prints body
  aosu_cloud.py devices               # convenience: /v1/dev/getList

Not yet found: `local_key`. Neither `/v1/dev/getList` (even with detail), `getInfoBySn`,
`getModelInfoBySn`, `capability` nor `getInfoByCode` carries it; it comes from the Tuya
`api.json` gateway, whose request signing lives in `libthing_security.so`.
"""
import base64
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.parse
import uuid

API = "https://api.aosulife.com"
UA = "aosu/5.10.12 (com.glazero.android; build:21713; Android 14) okhttp/4.12.0"
KEY = b"PZR1ryiUhJloWoRd"
SIGN_SALT = "&sM&GGlUCSXjZqQNxmkdU^scUs**0R@C"
CACHE = os.path.expanduser("~/.config/fss-lab/aosu_session.json")


def encrypt_password(pw: str) -> str:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.padding import PKCS7

    pad = PKCS7(128).padder()
    data = pad.update(pw.encode()) + pad.finalize()
    enc = Cipher(algorithms.AES(KEY), modes.CBC(KEY)).encryptor()
    return base64.b64encode(enc.update(data) + enc.finalize()).decode()


def base_headers(sid=None, uid=None, sign=None) -> list[str]:
    h = ["-H", "Gz-Pid: glazero", "-H", "Gz-AppId: com.glazero.android",
         "-H", "Gz-AppVer: 5.10.12", "-H", "Gz-OsType: android", "-H", "Gz-OsVer: 34",
         "-H", "Gz-BuildType: release", "-H", "Gz-Channel: official", "-H", "Gz-Lang: en",
         "-H", f"Gz-Imei: {uuid.uuid4()}", "-H", "Gz-Timezone: America/New_York"]
    if sid:
        h += ["-H", f"Gz-Sid: {sid}"]
    if uid:
        h += ["-H", f"Gz-Uid: {uid}"]
    if sign:
        h += ["-H", f"Gz-Sign: {sign}"]
    return h


def curl(url: str, headers: list[str], data: str | None, ctype: str | None = None) -> str:
    args = ["curl", "-s", "-m", "25", "-A", UA] + headers
    if ctype:
        args += ["-H", f"content-type: {ctype}"]
    if data is not None:
        args += ["-X", "POST", "-d", data]
    args.append(url)
    return subprocess.run(args, capture_output=True, text=True).stdout


def login(email: str) -> dict:
    creds = dict(
        line.split("=", 1) for line in open(os.path.expanduser("~/.config/fss-lab/aosu.env")) if "=" in line
    )
    u, t = str(uuid.uuid4()), str(int(time.time() * 1000))
    sign = hashlib.md5(f"uuid:{u}:t:{t}:{SIGN_SALT}".encode()).hexdigest()
    form = urllib.parse.urlencode(dict(
        region="US", countryCode="1", countryAbbr="US", type="1", email=email,
        password=encrypt_password(creds["AOSU_PASSWORD"].strip()), pwType="2"))
    out = curl(f"{API}/v1/user/login?uuid={u}&t={t}", base_headers(sign=sign), form,
               "application/x-www-form-urlencoded")
    body = json.loads(out)
    if body.get("errno") != 0:
        raise SystemExit(f"login failed: {out[:300]}")
    save(body["data"])
    return body["data"]


def save(data: dict) -> None:
    os.makedirs(os.path.dirname(CACHE), exist_ok=True)
    with open(CACHE, "w") as fh:
        json.dump({"sid": data["sid"], "uid": data["uid"]}, fh)
    os.chmod(CACHE, 0o600)


def session() -> dict:
    if not os.path.exists(CACHE):
        raise SystemExit("no cached session; run: aosu_cloud.py login <email>")
    return json.load(open(CACHE))


def call(path: str, body: str | None = None, ctype: str = "application/json") -> str:
    s = session()
    u, t = str(uuid.uuid4()), str(int(time.time() * 1000))
    sign = hashlib.md5(f"uuid:{u}:t:{t}:{SIGN_SALT}".encode()).hexdigest()
    return curl(f"{API}{path}?uuid={u}&t={t}", base_headers(s["sid"], s["uid"], sign),
                body if body is not None else "", ctype)


def main() -> int:
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "login":
        email = sys.argv[2] if len(sys.argv) > 2 else "jeffrey.emanuel@gmail.com"
        d = login(email)
        print(json.dumps({"uid": d["uid"], "sid": d["sid"][:8] + "..."}))
    elif cmd == "call":
        print(call(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None))
    elif cmd == "devices":
        out = call("/v1/dev/getList")
        for dev in json.loads(out)["data"]["list"]:
            print(dev.get("name"), dev.get("sn"), dev.get("model"), "online=" + str(dev.get("online")))
    else:
        print(__doc__)
    return 0


if __name__ == "__main__":
    sys.exit(main())

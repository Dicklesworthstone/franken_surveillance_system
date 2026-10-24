#!/usr/bin/env python3
"""Signed client for the Tuya `api.json` gateway used by the AOSU app.

The sign is `ThingApiSignManager.generateSignatureSdk` -> `libthing_security.so` cmd 1, driven
here through tools/thing-sign (Docker).  Canonical string: sorted allowed keys, `k=v` joined by
`||`, with `postData` replaced by swap(md5base64(postData)).  The BMP key carrier makes the
signer reject ~99% of inputs (`read_keys_from_content` returns 21); the requestId is re-rolled
until the BMP byte at the hash index is valid.

  aosu_tuya_api.py login            # Tuya session for the owner uid (AOSU password)
  aosu_tuya_api.py keyget <devId>   # thing.m.device.key.get -> localKey
  aosu_tuya_api.py call <action> <postData-json> [--sid SID]
"""
import base64
import hashlib
import json
import os
import random
import subprocess
import sys
import time
import urllib.parse
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
HARNESS = os.path.join(REPO, "tools", "thing-sign")
BMP = os.path.join(HARNESS, "assets", "t_s.bmp")
APPID = "7hvgpakg784c3pj5qe3e"
SECRET = "rgtgvk8mp8xycftdjpnjs3sfkahmkafn"
API = "https://a1-us.iotbing.com/api.json"
UA = "aosu/5.10.12 (com.glazero.android; build:21739; Android 14) okhttp/4.12.0"
CACHE = os.path.expanduser("~/.config/fss-lab/aosu_tuya_session.json")
ALLOWED = ["a", "v", "lat", "lon", "lang", "deviceId", "appVersion", "ttid", "isH5", "h5Token",
           "os", "clientId", "postData", "time", "requestId", "et", "n4h5", "sid", "chKey", "sp"]


def md5b64(s: str) -> str:
    return base64.b64encode(hashlib.md5(s.encode()).digest()).decode()


def swap(s: str) -> str:
    return s[8:16] + s[0:8] + s[24:32] + s[16:24]


def canonical(params: dict) -> str:
    out = []
    excl = set(filter(None, os.environ.get("SIGN_EXCLUDE", "").split(",")))
    for k in sorted(params):
        if k not in ALLOWED or k in excl or params[k] in (None, ""):
            continue
        v = params[k]
        if k == "postData":
            v = swap(md5b64(v))
        if os.environ.get("SIGN_ENCODED") == "1":
            v = urllib.parse.quote(v, safe="")
        out.append(f"{k}={v}")
    return "||".join(out)


def bmp_byte(canon: str) -> int:
    data = open(BMP, "rb").read()[54:]
    h = 0
    for c in canon.encode():
        h = (31 * h + c) & 0xFFFFFFFF
    if h >= 2 ** 31:
        h -= 2 ** 32
    h = abs(h)
    return data[(h % len(data)) // 2 % len(data)]


def enc_key(request_id: str, ecode: str | None) -> bytes:
    r = subprocess.run(["docker", "run", "--rm", "--platform", "linux/arm64", "fss-jvm",
                        "java", "-cp", "/w/out", "Run", "enc", request_id, ecode or ""],
                       capture_output=True, text=True, timeout=120)
    for line in r.stderr.splitlines():
        if line.startswith("KEY="):
            return bytes.fromhex(line[4:])
    raise SystemExit("getEncryptoKey failed:\n" + r.stderr[-600:])


_CHKEY = None
def chkey() -> str:
    global _CHKEY
    if _CHKEY:
        return _CHKEY
    d = "/tmp/fss-sign"
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, "seed.txt"), "w").write(SECRET)
    open(os.path.join(d, "appid.txt"), "w").write(os.environ.get("CLIENT_ID", APPID))
    open(os.path.join(d, "package.txt"), "w").write(os.environ.get("PACKAGE", "com.glazero.android"))
    open(os.path.join(d, "cert.der"), "wb").write(open(os.path.join(HARNESS, "cert.der"), "rb").read())
    r = subprocess.run(["docker", "run", "--rm", "--platform", "linux/arm64",
                        "-v", d + ":/data", "fss-jvm", "java", "-cp", "/w/out", "Run", "chkey"],
                       capture_output=True, text=True, timeout=120)
    for line in r.stderr.splitlines():
        if line.startswith("CHKEY="):
            _CHKEY = line[6:]
            return _CHKEY
    raise SystemExit("getChKey failed:\n" + r.stderr[-600:])


def encrypt_post(post: dict, request_id: str, ecode: str | None) -> str:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = enc_key(request_id, ecode)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, json.dumps(post, separators=(",", ":")).encode(), None)
    return base64.b64encode(nonce + ct).decode()


def sign(canon: str) -> str:
    d = "/tmp/fss-sign"
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, "in.txt"), "w").write(canon)
    open(os.path.join(d, "seed.txt"), "w").write(SECRET)
    open(os.path.join(d, "appid.txt"), "w").write(os.environ.get("CLIENT_ID", APPID))
    open(os.path.join(d, "package.txt"), "w").write(os.environ.get("PACKAGE", "com.glazero.android"))
    open(os.path.join(d, "cert.der"), "wb").write(open(os.path.join(HARNESS, "cert.der"), "rb").read())
    r = subprocess.run(["docker", "run", "--rm", "--platform", "linux/arm64",
                        "-v", d + ":/data", "fss-jvm"],
                       capture_output=True, text=True, timeout=120)
    for line in r.stderr.splitlines():
        if line.startswith("RESULT="):
            v = line.split("=", 1)[1]
            if v != "null":
                return v
    raise SystemExit("sign failed:\n" + r.stderr[-800:])


def build(action: str, post: dict, sid: str | None = None, ver: str = "1.0") -> dict:
    ios = os.environ.get("IOS_STYLE") == "1"
    for _ in range(5000):
        p = {
            "a": action, "v": ver, "clientId": os.environ.get("CLIENT_ID", APPID), "os": os.environ.get("TUYA_OS","Android"),
            "appVersion": os.environ.get("TUYA_VER","5.10.12"), "deviceId": str(uuid.uuid4()).upper(),
            "ttid": os.environ.get("TUYA_TTID","appstore_r"),
            "bundleId": os.environ.get("TUYA_BUNDLE","com.glazero.ios"), "osSystem": os.environ.get("TUYA_OSSYS","14"), "channel": "sdk",
            "nd": "1", "platform": os.environ.get("TUYA_PLATFORM","Pixel 7"), "chKey": chkey(), "cp": "gzip", "lang": "en", "lat": "0", "lon": "0", "et": os.environ.get("TUYA_ET","3"),
            "time": str(int(time.time())), "requestId": str(uuid.uuid4()).upper(),
            "postData": "",
        }
        if sid:
            p["sid"] = sid
        rid = p["requestId"]
        for k in filter(None, os.environ.get("DROP", "").split(",")):
            p.pop(k, None)
        if ios:
            for k in ("a", "clientId", "lat", "requestId"):
                p.pop(k, None)

        p["postData"] = json.dumps(post, separators=(",", ":")) if os.environ.get("PLAIN") == "1" else encrypt_post(post, rid, sid and None)
        c = canonical(p)
        if bmp_byte(c) <= 2:
            p["sign"] = sign(c)
            return p
    raise SystemExit("no valid requestId")


def post(p: dict, path: str = "/api.json", query: str = "") -> dict:
    q = urllib.parse.quote
    body = "&".join(f"{k}={q(v, safe='')}" for k, v in p.items() if k != "sign" and not (k == "a" and os.environ.get("QUERY_A") == "1"))
    body += "&sign=" + p["sign"]
    r = subprocess.run(["curl", "-sS", "-m", "30", "-A", UA,
                        "-H", "content-type: application/x-www-form-urlencoded",
                        "--data-binary", body, "https://a1-us.iotbing.com" + path + query], capture_output=True, text=True)
    try:
        return json.loads(r.stdout)
    except Exception:
        return {"_raw": r.stdout, "_err": r.stderr}


def main() -> int:
    a = sys.argv[1:]
    if not a:
        print(__doc__)
        return 2
    if a[0] == "login":
        env = dict(l.split("=", 1) for l in open(os.path.expanduser("~/.config/fss-lab/aosu.env")).read().splitlines() if "=" in l)
        uid = json.load(open(os.path.expanduser("~/.config/fss-lab/aosu_login_resp.json")))["data"]["tuyaUid"]
        post_data = {"countryCode": "1", "email": uid, "passwd": md5b64(env["AOSU_PASSWORD"]),
                     "extra": "{\"group\":1}", "token": "", "ifencrypt": 0}
        act = "thing.m.user.email.password.login"
        q = ("?a=" + act) if os.environ.get("QUERY_A") == "1" else ""
        r = post(build(act, post_data, ver="1.0"), os.environ.get("LOGIN_PATH", "/api.json"), q)
        print(json.dumps(r)[:1200])
        if r.get("success") and r.get("result"):
            res = r["result"]
            sid = res.get("sid") or res.get("t")
            if sid:
                os.makedirs(os.path.dirname(CACHE), exist_ok=True)
                open(CACHE, "w").write(json.dumps({"sid": sid, "uid": uid}))
                os.chmod(CACHE, 0o600)
                print("sid cached")
        return 0
    if a[0] == "keyget":
        sid = json.load(open(CACHE))["sid"]
        r = post(build("thing.m.device.key.get", {"gwId": a[1]}, sid))
        print(json.dumps(r, indent=1)[:2000])
        return 0
    if a[0] == "call":
        sid = None
        if "--sid" in a:
            i = a.index("--sid")
            sid = a[i + 1]
            del a[i:i + 2]
        r = post(build(a[1], json.loads(a[2]) if len(a) > 2 else {}, sid))
        print(json.dumps(r, indent=1)[:3000])
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())

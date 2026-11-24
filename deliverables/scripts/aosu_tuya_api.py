#!/usr/bin/env python3
"""Signed client for the Tuya `api.json` gateway used by the AOSU app.

The sign is `ThingApiSignManager.generateSignatureSdk` -> `libthing_security.so` cmd 1, driven
here through `tuya_thing_sign.py` + `tools/thing-sign` (isolated read-only Docker mount; zero
shared `/tmp/fss-sign` mutations).  Canonical string: sorted allowed keys, `k=v` joined by
`||`, with `postData` replaced by swap_hex(md5(postData)).  The BMP key carrier makes the
signer reject ~99% of inputs (`read_keys_from_content` returns 21); the requestId is re-rolled
until the BMP byte at the hash index is valid.

Environment overrides (matching docs/exploit/tuya-fresh-registration-runbook.md):
  FSS_SIGN_APPID  (or legacy CLIENT_ID)  — Tuya appKey / clientId override
  FSS_SIGN_SEED                          — Tuya appSecret override (defaults to baked /w/cfg/seed.txt)
  FSS_SIGN_PACKAGE (or legacy PACKAGE)   — Android package name override (default com.glazero.android)
  FSS_SIGN_PLATFORM (or DOCKER_PLATFORM) — Docker platform (default linux/arm64)

  aosu_tuya_api.py login            # Tuya session for the owner uid (AOSU password)
  aosu_tuya_api.py keyget <devId>   # thing.m.device.key.get -> localKey
  aosu_tuya_api.py call <action> <postData-json> [--sid SID]
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.parse
import uuid
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
HARNESS = os.path.join(REPO, "tools", "thing-sign")
BMP = os.path.join(HARNESS, "assets", "t_s.bmp")
APPID = "7hvgpakg784c3pj5qe3e"
API = "https://a1-us.iotbing.com/api.json"
UA = "aosu/5.10.12 (com.glazero.android; build:21739; Android 14) okhttp/4.12.0"
CACHE = os.path.expanduser("~/.config/fss-lab/aosu_tuya_session.json")
ALLOWED = [
    "a", "v", "lat", "lon", "lang", "deviceId", "appVersion", "ttid", "isH5", "h5Token",
    "os", "clientId", "postData", "time", "requestId", "et", "n4h5", "sid", "chKey", "sp",
]

if HERE not in sys.path:
    sys.path.insert(0, HERE)
import tuya_thing_sign as tts  # noqa: E402


def _resolved_appid() -> str:
    return os.environ.get("FSS_SIGN_APPID") or os.environ.get("CLIENT_ID") or APPID


def _resolved_seed() -> str | None:
    val = os.environ.get("FSS_SIGN_SEED")
    return val if val else None


def _resolved_package() -> str | None:
    return os.environ.get("FSS_SIGN_PACKAGE") or os.environ.get("PACKAGE") or None


def _resolved_platform() -> str:
    return os.environ.get("FSS_SIGN_PLATFORM") or os.environ.get("DOCKER_PLATFORM") or tts.DEFAULT_PLATFORM


def md5b64(s: str) -> str:
    return base64.b64encode(hashlib.md5(s.encode("utf-8")).digest()).decode("ascii")


def swap(s: str) -> str:
    return tts.swap_hex(s)


def canonical(params: dict[str, Any]) -> str:
    # VERIFIED against the real app (emulator Frida capture, 2026-10-27):
    # postData digest = SWAPPED MD5-HEX, not swap(md5-base64):
    #   hex = md5(postData).hexdigest(); swap = hex[8:16]+hex[0:8]+hex[24:32]+hex[16:24]
    # Proof pair: evidence/aosu_sign_ground_truth.json (harness == app, exact match).
    out = []
    excl = set(filter(None, os.environ.get("SIGN_EXCLUDE", "").split(",")))
    for k in sorted(params):
        if k not in ALLOWED or k in excl or params[k] in (None, ""):
            continue
        v = str(params[k])
        if k == "postData":
            v = tts.swap_hex(hashlib.md5(v.encode("utf-8")).hexdigest())
        if os.environ.get("SIGN_ENCODED") == "1":
            v = urllib.parse.quote(v, safe="")
        out.append(f"{k}={v}")
    return "||".join(out)


def bmp_byte(canon: str) -> int:
    with open(BMP, "rb") as fh:
        data = fh.read()[54:]
    if not data:
        raise RuntimeError(f"BMP carrier {BMP} has no pixel payload")
    h = 0
    for c in canon.encode("utf-8"):
        h = (31 * h + c) & 0xFFFFFFFF
    if h >= 2 ** 31:
        h -= 2 ** 32
    h = abs(h)
    return data[(h % len(data)) // 2 % len(data)]


def enc_key(request_id: str, ecode: str | None) -> bytes:
    r = tts._docker_run(
        ["java", "-cp", "/w/out", "Run", "enc", request_id, ecode or ""],
        seed_override=_resolved_seed(),
        appid_override=_resolved_appid(),
        package_override=_resolved_package(),
        platform=_resolved_platform(),
    )
    for line in r.stderr.splitlines():
        if line.startswith("KEY="):
            return bytes.fromhex(line[4:].strip())
    raise SystemExit("getEncryptoKey failed:\n" + r.stderr[-600:])


_CHKEY_CACHE: dict[tuple[str, str | None, str | None, str], str] = {}


def chkey() -> str:
    appid = _resolved_appid()
    seed = _resolved_seed()
    pkg = _resolved_package()
    plat = _resolved_platform()
    ck = (appid, seed, pkg, plat)
    if ck in _CHKEY_CACHE:
        return _CHKEY_CACHE[ck]
    r = tts._docker_run(
        ["java", "-cp", "/w/out", "Run", "chkey"],
        seed_override=seed,
        appid_override=appid,
        package_override=pkg,
        platform=plat,
    )
    for line in r.stderr.splitlines():
        if line.startswith("CHKEY="):
            val = line[6:].strip()
            _CHKEY_CACHE[ck] = val
            return val
    raise SystemExit("getChKey failed:\n" + r.stderr[-600:])


def encrypt_post(post: dict[str, Any], request_id: str, ecode: str | None) -> str:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = enc_key(request_id, ecode)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, json.dumps(post, separators=(",", ":")).encode("utf-8"), None)
    return base64.b64encode(nonce + ct).decode("ascii")


def sign(canon: str) -> str:
    r = tts._docker_run(
        [],
        canon=canon,
        seed_override=_resolved_seed(),
        appid_override=_resolved_appid(),
        package_override=_resolved_package(),
        platform=_resolved_platform(),
    )
    for line in r.stderr.splitlines():
        if line.startswith("RESULT="):
            v = line.split("=", 1)[1].strip()
            if v and v != "null":
                return v
    raise SystemExit("sign failed:\n" + r.stderr[-800:])


def build(action: str, post: dict[str, Any], sid: str | None = None, ver: str = "1.0") -> dict[str, Any]:
    ios = os.environ.get("IOS_STYLE") == "1"
    default_os = "iOS" if ios else "Android"
    default_ttid = "appstore_r" if ios else "android"
    default_bundle = "com.glazero.ios" if ios else "com.glazero.android"
    default_lang = "en" if ios else "en_US"
    client_id = _resolved_appid()

    for _ in range(5000):
        p: dict[str, Any] = {
            "a": action,
            "v": ver,
            "clientId": client_id,
            "os": os.environ.get("TUYA_OS", default_os),
            "appVersion": os.environ.get("TUYA_VER", "5.10.12"),
            "deviceId": str(uuid.uuid4()).upper(),
            "ttid": os.environ.get("TUYA_TTID", default_ttid),
            "bundleId": os.environ.get("TUYA_BUNDLE", default_bundle),
            "osSystem": os.environ.get("TUYA_OSSYS", "14"),
            "channel": "sdk",
            "nd": "1",
            "platform": os.environ.get("TUYA_PLATFORM", "Pixel 7"),
            "chKey": chkey(),
            "cp": "gzip",
            "lang": os.environ.get("TUYA_LANG", default_lang),
            "lat": "0",
            "lon": "0",
            "et": os.environ.get("TUYA_ET", "3"),
            "time": str(int(time.time())),
            "requestId": str(uuid.uuid4()).upper(),
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

        p["postData"] = (
            json.dumps(post, separators=(",", ":"))
            if os.environ.get("PLAIN") == "1"
            else encrypt_post(post, rid, None)
        )
        c = canonical(p)
        if bmp_byte(c) <= 2:
            p["sign"] = sign(c)
            return p
    raise SystemExit("no valid requestId")


def post(p: dict[str, Any], path: str = "/api.json", query: str = "") -> dict[str, Any]:
    q = urllib.parse.quote
    body = "&".join(
        f"{k}={q(str(v), safe='')}"
        for k, v in p.items()
        if k != "sign" and not (k == "a" and os.environ.get("QUERY_A") == "1")
    )
    body += "&sign=" + urllib.parse.quote(str(p["sign"]), safe="")
    r = subprocess.run(
        [
            "curl", "-sS", "-m", "30", "-A", UA,
            "-H", "content-type: application/x-www-form-urlencoded",
            "--data-binary", body,
            "https://a1-us.iotbing.com" + path + query,
        ],
        capture_output=True,
        text=True,
        timeout=45,
        check=False,
    )
    try:
        doc = json.loads(r.stdout)
        return doc if isinstance(doc, dict) else {"_raw": doc}
    except Exception:
        return {"_raw": r.stdout, "_err": r.stderr, "_rc": r.returncode}


def _write_cache_0600(cache_path: str, payload: dict[str, Any]) -> None:
    parent = os.path.dirname(os.path.abspath(cache_path))
    os.makedirs(parent, exist_ok=True)
    tmp = f"{cache_path}.tmp.{os.getpid()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, cache_path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _diagnose_if_error(resp: dict[str, Any]) -> bool:
    if resp.get("success") is True:
        return True
    diag = tts.classify_gateway_response(resp)
    print(f"gateway diagnosis: {json.dumps(diag)}", file=sys.stderr)
    return False


def main(argv: list[str] | None = None) -> int:
    a = list(sys.argv[1:] if argv is None else argv)
    if not a:
        print(__doc__)
        return 2
    if a[0] == "login":
        env_path = os.path.expanduser("~/.config/fss-lab/aosu.env")
        resp_path = os.path.expanduser("~/.config/fss-lab/aosu_login_resp.json")
        with open(env_path, encoding="utf-8") as fh:
            env = dict(line.split("=", 1) for line in fh.read().splitlines() if "=" in line)
        with open(resp_path, encoding="utf-8") as fh:
            uid = json.load(fh)["data"]["tuyaUid"]
        post_data = {
            "countryCode": "1",
            "email": uid,
            "passwd": md5b64(env["AOSU_PASSWORD"]),
            "extra": "{\"group\":1}",
            "token": "",
            "ifencrypt": 0,
        }
        act = "thing.m.user.email.password.login"
        q = ("?a=" + act) if os.environ.get("QUERY_A") == "1" else ""
        r = post(build(act, post_data, ver="1.0"), os.environ.get("LOGIN_PATH", "/api.json"), q)
        print(json.dumps(r)[:1200])
        if r.get("success") and isinstance(r.get("result"), dict):
            res = r["result"]
            sid = res.get("sid") or res.get("t")
            if sid:
                _write_cache_0600(CACHE, {"sid": sid, "uid": uid})
                print("sid cached")
                return 0
        _diagnose_if_error(r)
        return 1
    if a[0] == "keyget":
        if len(a) < 2:
            print("usage: aosu_tuya_api.py keyget <devId>", file=sys.stderr)
            return 2
        with open(CACHE, encoding="utf-8") as fh:
            sid = json.load(fh)["sid"]
        r = post(build("thing.m.device.key.get", {"gwId": a[1]}, sid))
        print(json.dumps(r, indent=1)[:2000])
        return 0 if _diagnose_if_error(r) else 1
    if a[0] == "call":
        sid = None
        if "--sid" in a:
            i = a.index("--sid")
            if i + 1 >= len(a):
                print("usage: aosu_tuya_api.py call <action> [<postData-json>] [--sid SID]", file=sys.stderr)
                return 2
            sid = a[i + 1]
            del a[i : i + 2]
        if len(a) < 2:
            print("usage: aosu_tuya_api.py call <action> [<postData-json>] [--sid SID]", file=sys.stderr)
            return 2
        r = post(build(a[1], json.loads(a[2]) if len(a) > 2 else {}, sid))
        print(json.dumps(r, indent=1)[:3000])
        return 0 if _diagnose_if_error(r) else 1
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())

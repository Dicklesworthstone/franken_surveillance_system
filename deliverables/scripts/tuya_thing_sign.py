#!/usr/bin/env python3
"""Tuya OEM `api.json` signer — KDF-correctness entry for the AOSU lane.

Ground truth (Frida capture of the real app on an emulator, 2026-10-27):
  evidence/aosu_sign_ground_truth.json — canonical string + sign captured from
  com.glazero.android 5.10.12 at SecureNativeApi.doCommandNative (cmd 1), and the
  harness (tools/thing-sign, real libthing_security.so under Docker) reproduces the
  sign EXACTLY for that canonical.

Verified contract:
  cmd0: doCommandNative(ctx, 0, appSecret, appId, false)  — THING_SMART_SECRET /
        THING_SMART_APPKEY from the app manifest.
  cmd1: doCommandNative(ctx, 1, canonical, null, false)
  canonical: sorted allowed keys, k=v joined by `||`, with
        postData -> swap_hex(md5(postData)):
            hex = md5(postData).hexdigest()
            swap = hex[8:16]+hex[0:8]+hex[24:32]+hex[16:24]
        (swapped MD5-HEX — the swap(md5-base64) form is WRONG for this gateway)
  KDF environment inputs (all must match the installed app):
        PackageInfo.signatures  -> the signing cert OF THE INSTALLED APK
        package name            -> com.glazero.android
        assets                  -> t_s.bmp + tecrkcehc_ext (crafted for that cert)

Usage:
  tuya_thing_sign.py selftest            # verify harness == captured ground truth
  tuya_thing_sign.py sign <canon-file>   # sign a canonical string (file or '-')
  tuya_thing_sign.py canon <json-map>    # build the canonical string from a field map
"""
import json
import hashlib
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
HARNESS = os.path.join(REPO, "tools", "thing-sign")
EVIDENCE = os.path.join(REPO, "evidence", "aosu_sign_ground_truth.json")
DOCKERMOUNT = "/tmp/fss-sign"

ALLOWED = ["a", "v", "lat", "lon", "lang", "deviceId", "appVersion", "ttid", "isH5",
           "h5Token", "os", "clientId", "postData", "time", "requestId", "et",
           "n4h5", "sid", "chKey", "sp"]


def swap_hex(hexstr: str) -> str:
    """Tuya postData digest: swapped md5-hex (verified against the real app)."""
    return hexstr[8:16] + hexstr[0:8] + hexstr[24:32] + hexstr[16:24]


def canonical(params: dict) -> str:
    parts = []
    for k in sorted(params):
        if k not in ALLOWED:
            continue
        v = params[k]
        if v is None or v == "":
            continue
        if k == "postData":
            v = swap_hex(hashlib.md5(v.encode()).hexdigest())
        parts.append(f"{k}={v}")
    return "||".join(parts)


def harness_sign(canon: str) -> str:
    os.makedirs(DOCKERMOUNT, exist_ok=True)
    open(os.path.join(DOCKERMOUNT, "in.txt"), "w").write(canon)
    r = subprocess.run(["docker", "run", "--rm", "--platform", "linux/arm64",
                        "-v", f"{DOCKERMOUNT}:/data", "fss-jvm"],
                       capture_output=True, text=True, timeout=120)
    for line in r.stderr.splitlines():
        if line.startswith("RESULT="):
            v = line.split("=", 1)[1]
            return None if v == "null" else v
    raise RuntimeError("harness produced no RESULT (stderr tail): " + r.stderr[-400:])


def selftest() -> int:
    gt = json.load(open(EVIDENCE))
    canon = gt["captured_canonical"]
    got = harness_sign(canon)
    want = gt["captured_sign"]
    ok = got == want
    print(f"captured sign : {want}")
    print(f"harness sign  : {got}")
    print(f"match         : {ok}")
    # also verify the canonical builder round-trips
    rebuilt = canonical(gt["request_map"])
    print(f"canonical eq  : {rebuilt == canon}")
    return 0 if (ok and rebuilt == canon) else 1




def enc_key(request_id: str, ecode: str = "") -> bytes:
    """getEncryptoKey via the harness (requires a warm-up cmd1 first — the harness enc path
    does cmd0 + warmup + key derivation)."""
    r = subprocess.run(["docker", "run", "--rm", "--platform", "linux/arm64",
                        "-v", f"{DOCKERMOUNT}:/data", "fss-jvm",
                        "java", "-cp", "/w/out", "Run", "enc", request_id, ecode],
                       capture_output=True, text=True, timeout=120)
    for line in r.stderr.splitlines():
        if line.startswith("KEY="):
            return bytes.fromhex(line[4:])
    raise RuntimeError("enc key derivation failed: " + r.stderr[-400:])


def encrypt_post(post_obj: dict, request_id: str) -> str:
    """et=3 postData: AES-GCM(random 12B nonce, key=getEncryptoKey(rid)) -> b64(nonce+ct)."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = enc_key(request_id)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, json.dumps(post_obj, separators=(",", ":")).encode(), None)
    import base64
    return base64.b64encode(nonce + ct).decode()


def ch_key() -> str:
    """getChKey via harness."""
    os.makedirs(DOCKERMOUNT, exist_ok=True)
    r = subprocess.run(["docker", "run", "--rm", "--platform", "linux/arm64",
                        "-v", f"{DOCKERMOUNT}:/data", "fss-jvm",
                        "java", "-cp", "/w/out", "Run", "chkey"],
                       capture_output=True, text=True, timeout=120)
    for line in r.stderr.splitlines():
        if line.startswith("CHKEY="):
            return line[6:]
    raise RuntimeError("chKey derivation failed: " + r.stderr[-400:])


def api_call(action: str, post_obj: dict, ver: str = "1.0",
             identity: dict | None = None, host: str = "https://a1-us.iotbing.com",
             sid: str | None = None) -> dict:
    """Full et=3 api.json round trip with a fresh sign, mimicking the app's envelope.

    identity: clientId/appVersion/ttid overrides (defaults = AOSU Android app).
    """
    import urllib.parse, urllib.request, time, uuid, base64
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    ident = {"clientId": "7hvgpakg784c3pj5qe3e", "appVersion": "5.10.12",
             "ttid": "android", "os": "Android", "lang": "en_US"}
    if identity:
        ident.update(identity)
    rid = str(uuid.uuid4())
    key = enc_key(rid, sid or "")
    nonce = os.urandom(12)
    pd = base64.b64encode(nonce + AESGCM(key).encrypt(
        nonce, json.dumps(post_obj, separators=(",", ":")).encode(), None)).decode()
    params = {"a": action, "v": ver, "clientId": ident["clientId"], "os": ident["os"],
              "appVersion": ident["appVersion"], "deviceId": rid, "ttid": ident["ttid"],
              "lang": ident["lang"], "et": "3", "cp": "gzip", "channel": "sdk", "nd": "1",
              "time": str(int(time.time())), "requestId": rid, "postData": pd,
              "chKey": ch_key()}
    if sid:
        params["sid"] = sid
    canon = canonical(params)
    sign = harness_sign(canon)
    if not sign:
        raise RuntimeError("harness refused to sign (bmp gate)")
    params["sign"] = sign
    body = "&".join(f"{k}={urllib.parse.quote(str(v), safe='')}" for k, v in params.items())
    req = urllib.request.Request(host + "/api.json", data=body.encode(), headers={
        "User-Agent": "aosu/5.10.12 (com.glazero.android; build:21739; Android 14) okhttp/4.12.0",
        "content-type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def main() -> int:
    a = sys.argv[1:]
    if not a:
        print(__doc__)
        return 2
    if a[0] == "selftest":
        return selftest()
    if a[0] == "sign":
        src = sys.stdin.read() if a[1] == "-" else open(a[1]).read()
        s = harness_sign(src.strip())
        print(s or "null")
        return 0 if s else 1
    if a[0] == "call":
        action=a[1]; post=json.loads(a[2]) if len(a)>2 else {}
        sid=a[3] if len(a)>3 else None
        print(json.dumps(api_call(action, post, sid=sid), indent=1)[:4000])
        return 0
    if a[0] == "canon":
        params = json.loads(a[1])
        print(canonical(params))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())

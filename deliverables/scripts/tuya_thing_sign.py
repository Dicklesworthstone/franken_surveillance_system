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
    if a[0] == "canon":
        params = json.loads(a[1])
        print(canonical(params))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Tuya/Thing api.json signer CLI — pure-Python front end for the fss sign lane.

Owns the *client-side* half of bead fss-fkkpw: canonical-string construction,
the swap(md5-base64) postData transform, and driving tools/thing-sign (the
libthing_security.so harness — PearlGull's pane) or recording/verifying signs.
The .so internals (BMP KDF, bignum chain, cert digest) stay in the harness; this
CLI never reimplements them, it feeds them exactly the canonical string the app
would have built.

Sign semantics (reversed in docs/research/EV-pack-H-003.md §"the Tuya signer"):
  canonical string = sorted params as k=v, '||'-joined, over the ALLOWED set;
  postData is replaced by swap(md5-base64(postData)) where swap rotates the
  32-char hex-of-b64 characters by 8 (s[8:16]+s[0:8]+s[24:32]+s[16:24]);
  sign = doCommandNative(ctx, 1, canonical) — 64 hex chars.

The sign is validated only by /api.json (/log.json ignores it), so the honest
oracle for this CLI is: (a) canonical string equality against captured requests,
and (b) sign stability + shape. Cross-checking a produced sign against the
gateway is the harness lane's business.

Usage:
  tuya_thing_sign.py canonical --action thing.m.device.key.get \
      --post-data '{"gwId":"<id>"}' --sid <sid> [--client-id q95…|7hvg…] [--json]
  tuya_thing_sign.py sign --file <canonical.txt>          # via Docker harness
  tuya_thing_sign.py verify --file <canonical.txt> --sign <64hex>
  tuya_thing_sign.py selftest                             # fixture unit tests
"""
import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
import uuid

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
HERE = os.path.dirname(os.path.abspath(__file__))
HARNESS = os.path.join(REPO, "tools", "thing-sign")

ALLOWED = ["a", "v", "lat", "lon", "lang", "deviceId", "appVersion", "ttid", "isH5",
           "h5Token", "os", "clientId", "postData", "time", "requestId", "et", "n4h5",
           "sid", "chKey", "sp"]
ANDROID_APPID = "7hvgpakg784c3pj5qe3e"      # com.glazero.android THING_SMART_APPKEY
IOS_APPID = "q95kcu85qnkdwaee9w3j"          # com.glazero.ios (captured replay, adb)
# The app "secret" below is a client-side constant extracted from the APK (public to anyone
# with the app); it seeds the .so harness, it is not a credential of this repo. UBS B105 is
# accepted noise for a mirrored app constant.
APP_SECRET = "rgtgvk8mp8xycftdjpnjs3sfkahmkafn"
SIGN_RE = r"[0-9a-f]{64}"


def md5b64(s: str) -> str:
    # MD5 is mandated by the sign scheme (gateway validates md5-based digests).
    return base64.b64encode(hashlib.md5(s.encode(), usedforsecurity=False).digest()).decode()


def swap(s: str) -> str:
    """Rotate the 32-char md5-base64 alphabet string by 8, per the captured client."""
    return s[8:16] + s[0:8] + s[24:32] + s[16:24]


def canonical(params: dict, exclude: list[str] | None = None,
              postdata_pre_transformed: bool = False) -> str:
    """The exact string doCommandNative(ctx, 1, …) is fed. Deterministic.

    Only ALLOWED keys, sorted; None/empty dropped; postData -> swap(md5b64(v)).
    With `postdata_pre_transformed`, the caller supplies postData already in
    final (swapped) form — used to reproduce captured canonical strings byte
    for byte without knowing the pre-image.
    """
    excl = set(exclude or [])
    out = []
    for k in sorted(params):
        if k not in ALLOWED or k in excl or params[k] in (None, ""):
            continue
        v = params[k]
        if k == "postData" and not postdata_pre_transformed:
            v = swap(md5b64(v))
        out.append(f"{k}={v}")
    return "||".join(out)


def build_params(action: str, post_data: str, sid: str, client_id: str = IOS_APPID,
                 app_version: str = "5.5.11", os_name: str = "IOS",
                 ttid: str = "appstore_r", et: str = "0.0.2",
                 device_id: str | None = None) -> dict:
    """Parameters matching the captured /api.json shape (in.txt is the template)."""
    return {
        "a": action,
        "appVersion": app_version,
        "clientId": client_id,
        "deviceId": device_id or str(uuid.uuid4()).upper(),
        "et": et,
        "lang": "en",
        "lat": "0",
        "lon": "0",
        "os": os_name,
        "postData": post_data,
        "requestId": str(uuid.uuid4()).upper(),
        "sid": sid,
        "time": str(int(__import__("time").time())),
        "ttid": ttid,
        "v": "1.0",
    }


def bmp_byte(canon: str, bmp_path: str | None = None) -> int:
    """read_keys_from_content's index probe (EV-pack-H-003 §signer): 31*h+c over the
    canonical, then ((h % pixel_len) / 2) % pixel_len into the BMP pixel data."""
    path = bmp_path or os.path.join(HARNESS, "assets", "t_s.bmp")
    with open(path, "rb") as fh:
        data = fh.read()[54:]
    h = 0
    for c in canon.encode():
        h = (31 * h + c) & 0xFFFFFFFF
    if h >= 2 ** 31:
        h -= 2 ** 32
    h = abs(h)
    return data[(h % len(data)) // 2 % len(data)]


def canonical_sha(canon: str) -> str:
    """Structural oracle: pins the canonical string without depending on the .so."""
    return hashlib.sha256(canon.encode()).hexdigest()


def harness_sign(canon: str, client_id: str = IOS_APPID,
                 bmp: str | None = None) -> str:
    """Drive tools/thing-sign's Docker harness (RESULT= line). The .so does the KDF."""
    d = os.path.join(os.environ.get("TMPDIR", "/tmp"), "fss-sign")
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, "in.txt"), "w").write(canon)
    open(os.path.join(d, "seed.txt"), "w").write(APP_SECRET)
    open(os.path.join(d, "appid.txt"), "w").write(client_id)
    open(os.path.join(d, "package.txt"), "w").write(
        "com.glazero.ios" if client_id == IOS_APPID else "com.glazero.android")
    open(os.path.join(d, "cert.der"), "wb").write(
        open(os.path.join(HARNESS, "cert.der"), "rb").read())
    if bmp:
        import shutil
        shutil.copy(bmp, os.path.join(HARNESS, "assets", "t_s.bmp"))
    r = subprocess.run(["/usr/local/bin/docker", "run", "--rm", "--platform", "linux/arm64",
                        "-v", d + ":/data", "fss-jvm"],
                       capture_output=True, text=True, timeout=120, check=False)
    # check=False is deliberate: the harness prints diagnostics on stderr even when the
    # container exits non-zero; RESULT= parsing below is the success criterion.
    for line in r.stderr.splitlines():
        if line.startswith("RESULT="):
            v = line.split("=", 1)[1]
            if v != "null":
                return v
    raise SystemExit("sign failed:\n" + r.stderr[-800:])


def verify(canon: str, sign: str) -> dict:
    """Shape + stability verification of a produced sign. NOT a gateway check."""
    import re
    ok_shape = re.fullmatch(SIGN_RE, sign or "") is not None
    return {"canonical_sha": canonical_sha(canon), "sign": sign,
            "sign_shape_ok": ok_shape,
            "len": len(sign or ""),
            "bmp_index_byte": bmp_byte(canon)}


# ---------------------------------------------------------------- fixtures --
# Captured request (tools/thing-sign/in.txt, from the iOS app replay; the harness
# README pins its expected sign as 2d2b754c…88e0 — full value lives with the
# harness lane, so the CLI pins on canonical equality + shape, not the value).
CAPTURED_CANONICAL = (
    "a=smartlife.m.rtc.log||appVersion=5.5.11||clientId=q95kcu85qnkdwaee9w3j||"
    "deviceId=EFE7C757-316F-4CE9-AC30-BFF799BBBCCE||et=0.0.2||lang=en||lat=0||"
    "lon=0||os=IOS||postData=THYzmFuZYBXWsuVpwGOb0A==||requestId=05A04511-0FDD-"
    "46F8-BA0F-7BA13E005DDA||sid=az174769C09331465BSaBG93c26fa4f30fd5c3fafbd5fe4"
    "bba915ec1||time=1791352903||ttid=appstore_r||v=1.0")
# in.txt's postData is the app's already-swapped form; swap-inverting it yields the
# md5 digest of the (uncommitted) plaintext blob as base64: 6015d6b2e5694c7633985b99c0639bd0.


def selftest() -> int:
    """Fixture tests. Structural oracles only — sign VALUES belong to the .so lane."""
    failures = []

    def check(name, cond, detail=""):
        print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  ({detail})" if detail and not cond else ""))
        if not cond:
            failures.append(name)

    # 1. swap: rotation by 8 is an involution and preserves the alphabet content
    m = md5b64("hello world")
    check("swap is an involution", swap(swap(m)) == m)
    check("swap preserves multiset", sorted(swap(m)) == sorted(m))
    check("swap shape", swap(m) == m[8:16] + m[0:8] + m[24:32] + m[16:24])

    # 2. canonical: rebuild the captured request and demand exact equality.
    #    in.txt is the app's OWN canonical (postData already in swapped final form);
    #    the raw pre-image md5 digest is b64-decodable from it (6015d6b2…bd0) but the
    #    plaintext blob is not committed, so equality uses pre_transformed=True.
    rebuilt = canonical({
        "a": "smartlife.m.rtc.log", "appVersion": "5.5.11",
        "clientId": IOS_APPID, "deviceId": "EFE7C757-316F-4CE9-AC30-BFF799BBBCCE",
        "et": "0.0.2", "lang": "en", "lat": "0", "lon": "0", "os": "IOS",
        "postData": "THYzmFuZYBXWsuVpwGOb0A==",
        "requestId": "05A04511-0FDD-46F8-BA0F-7BA13E005DDA",
        "sid": "az174769C09331465BSaBG93c26fa4f30fd5c3fafbd5fe4bba915ec1",
        "time": "1791352903", "ttid": "appstore_r", "v": "1.0"},
        postdata_pre_transformed=True)
    check("canonical reproduces captured in.txt", rebuilt == CAPTURED_CANONICAL,
          f"got {rebuilt[:80]}…")

    # 2b. the swap-invert round trip on the captured value: swap^-1 gives the md5
    #     digest as b64 — a pinned derivation of the pre-image digest.
    inv = swap("THYzmFuZYBXWsuVpwGOb0A==")
    check("captured postData swap-inverts to md5 digest b64",
          inv == "YBXWsuVpTHYzmFuZwGOb0A==")

    # 3. in.txt file on disk matches the fixture (drift detector for the lane)
    in_txt = os.path.join(HARNESS, "in.txt")
    if os.path.exists(in_txt):
        disk = open(in_txt).read().strip()
        check("tools/thing-sign/in.txt unchanged", disk == CAPTURED_CANONICAL)
    else:
        check("tools/thing-sign/in.txt exists", False)

    # 4. excluded/empty/None handling: dropping a field changes the string, is stable
    p = {"a": "x", "sid": "", "et": "0.0.2", "n4h5": None}
    c1, c2 = canonical(p), canonical(p)
    check("canonical deterministic", c1 == c2)
    check("empty sid dropped", "sid=" not in c1 and c1 == "a=x||et=0.0.2")

    # 5. postData transform lands in the canonical swapped (known-value round trip)
    c3 = canonical({"a": "x", "postData": "test"})
    swapped = swap(md5b64("test"))
    check("postData swapped in canonical", f"postData={swapped}" in c3)

    # 6. BMP index probe is a stable integer 0..255 for the captured canonical
    b = bmp_byte(CAPTURED_CANONICAL)
    check("bmp_byte in range", isinstance(b, int) and 0 <= b <= 255, str(b))

    # 7. canonical_sha is a stable structural pin for the captured request
    check("captured canonical sha pinned",
          canonical_sha(CAPTURED_CANONICAL) == canonical_sha(rebuilt))

    # 8. build_params emits only ALLOWED keys
    extra = {k: v for k, v in build_params("thing.m.device.key.get",
                                           '{"gwId":"eb28f4fa8cd86eb3669izf"}',
                                           "az174769C09331465BSaBG93c26fa4f30fd5c3fafbd5fe4bba915ec1"
                                           ).items()}
    check("build_params within ALLOWED", all(k in ALLOWED for k in extra))

    print(f"selftest: {len(failures)} failure(s)")
    return 1 if failures else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_can = sub.add_parser("canonical", help="build the canonical string")
    p_can.add_argument("--action", required=True)
    p_can.add_argument("--post-data", required=True)
    p_can.add_argument("--sid", required=True)
    p_can.add_argument("--client-id", default=IOS_APPID)
    p_can.add_argument("--os", dest="os_name", default="IOS")
    p_can.add_argument("--ttid", default="appstore_r")
    p_can.add_argument("--et", default="0.0.2")
    p_can.add_argument("--app-version", default="5.5.11")
    p_can.add_argument("--device-id", default=None)
    p_can.add_argument("--json", action="store_true")

    p_sig = sub.add_parser("sign", help="run the canonical through the Docker harness")
    p_sig.add_argument("--file", required=True, help="file holding the canonical string")
    p_sig.add_argument("--client-id", default=IOS_APPID)
    p_sig.add_argument("--bmp", default=None, help="optional replacement t_s.bmp")

    p_ver = sub.add_parser("verify", help="shape/stability check of a sign")
    p_ver.add_argument("--file", required=True)
    p_ver.add_argument("--sign", required=True)
    p_ver.add_argument("--json", action="store_true")

    sub.add_parser("selftest", help="run the fixture tests")

    a = ap.parse_args()

    if a.cmd == "canonical":
        params = build_params(a.action, a.post_data, a.sid, a.client_id,
                              a.app_version, a.os_name, a.ttid, a.et, a.device_id)
        canon = canonical(params)
        if a.json:
            print(json.dumps({"canonical": canon,
                              "canonical_sha": canonical_sha(canon),
                              "bmp_index_byte": bmp_byte(canon),
                              "params": params}, indent=2))
        else:
            print(canon)
        return 0

    if a.cmd == "sign":
        canon = open(a.file).read().strip()
        print(harness_sign(canon, a.client_id, a.bmp))
        return 0

    if a.cmd == "verify":
        canon = open(a.file).read().strip()
        out = verify(canon, a.sign)
        print(json.dumps(out, indent=2) if a.json else
              f"shape={'ok' if out['sign_shape_ok'] else 'BAD'} "
              f"len={out['len']} canonical_sha={out['canonical_sha'][:16]}…")
        return 0 if out["sign_shape_ok"] else 6

    if a.cmd == "selftest":
        return selftest()
    return 2


if __name__ == "__main__":
    sys.exit(main())

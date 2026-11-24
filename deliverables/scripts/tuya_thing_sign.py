#!/usr/bin/env python3
"""Tuya OEM `api.json` signer — KDF-correctness entry for the AOSU lane.

Ground truth (Frida capture of the real app on an emulator, 2026-10-27):
  evidence/aosu_sign_ground_truth.json & evidence/aosu_emu_gsdk2_capture.jsonl —
  canonical strings + signs captured from com.glazero.android 5.10.12 at
  ThingApiSignManager.generateSignatureSdk / SecureNativeApi.doCommandNative (cmd 1).
  The Dockerized harness (tools/thing-sign/Dockerfile.jvm, real arm64 libthing_security.so)
  reproduces every captured signature byte-exact with zero host-state dependencies.

Verified contract:
  cmd0: doCommandNative(ctx, 0, appSecret, appId, false)  — THING_SMART_SECRET /
        THING_SMART_APPKEY from the app manifest (baked defaults in /w/cfg/).
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
  tuya_thing_sign.py selftest                        # verify harness == captured ground truth
  tuya_thing_sign.py sign <canon-file|->             # sign a canonical string
  tuya_thing_sign.py canon <json-map>                # build the canonical string from a field map
  tuya_thing_sign.py chkey                           # derive getChKey via harness
  tuya_thing_sign.py digest [msg] [key]              # run native computeDigest via harness
  tuya_thing_sign.py classify-response <json-or-file> # diagnose gateway error (burned reg vs bad sign)
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
HARNESS = os.path.join(REPO, "tools", "thing-sign")
EVIDENCE = os.path.join(REPO, "evidence", "aosu_sign_ground_truth.json")
DEFAULT_IMAGE = os.environ.get("FSS_SIGN_IMAGE", "fss-jvm")
DEFAULT_PLATFORM = os.environ.get("FSS_SIGN_PLATFORM", "linux/arm64")

ALLOWED = [
    "a", "v", "lat", "lon", "lang", "deviceId", "appVersion", "ttid", "isH5",
    "h5Token", "os", "clientId", "postData", "time", "requestId", "et",
    "n4h5", "sid", "chKey", "sp",
]


def swap_hex(hexstr: str) -> str:
    """Tuya postData digest: swapped md5-hex (verified against the real app)."""
    if len(hexstr) != 32:
        raise ValueError(f"expected 32-char md5 hex digest, got len={len(hexstr)}")
    return hexstr[8:16] + hexstr[0:8] + hexstr[24:32] + hexstr[16:24]


def canonical(params: dict[str, Any]) -> str:
    parts = []
    for k in sorted(params):
        if k not in ALLOWED:
            continue
        v = params[k]
        if v is None or v == "":
            continue
        val = str(v)
        if k == "postData":
            val = swap_hex(hashlib.md5(val.encode("utf-8")).hexdigest())
        parts.append(f"{k}={val}")
    return "||".join(parts)


def classify_gateway_response(payload: dict[str, Any]) -> dict[str, Any]:
    """Classify a Tuya /api.json response so burned registrations are never misdiagnosed as bad signs."""
    if payload.get("success") is True:
        return {
            "classification": "ok",
            "sign_valid": True,
            "registration_burned": False,
            "error_code": None,
            "remediation": None,
        }
    code = str(payload.get("errorCode") or "").strip().upper()
    msg = str(payload.get("errorMsg") or "").strip()
    if code == "ILLEGAL_CLIENT_ID":
        return {
            "classification": "burned_registration_not_sign_error",
            "sign_valid": None,
            "registration_burned": True,
            "error_code": code,
            "error_msg": msg,
            "remediation": (
                "Registration is burned on the Tuya gateway (not a signing mismatch). "
                "Follow docs/exploit/tuya-fresh-registration-runbook.md to obtain a fresh "
                "Tuya IoT Platform app_id/app_secret."
            ),
        }
    if code in ("SING_VALIDATE_FALED", "SIGN_VALIDATE_FAILED", "SIGNATURE_INVALID"):
        return {
            "classification": "signing_mismatch",
            "sign_valid": False,
            "registration_burned": False,
            "error_code": code,
            "error_msg": msg,
            "remediation": (
                "Gateway rejected signature. Verify appSecret (seed.txt), appId (appid.txt), "
                "PackageInfo cert.der, canonical postData swap_hex(md5), and run test_tuya_sign.py."
            ),
        }
    return {
        "classification": "other_gateway_error",
        "sign_valid": None,
        "registration_burned": False,
        "error_code": code or "UNKNOWN",
        "error_msg": msg,
        "remediation": "Inspect gateway errorCode/errorMsg; run test_tuya_sign.py to rule out local signer drift.",
    }


def _docker_run(
    extra_args: list[str],
    *,
    canon: str | None = None,
    seed_override: str | None = None,
    appid_override: str | None = None,
    cert_override_path: str | None = None,
    package_override: str | None = None,
    image: str | None = None,
    platform: str | None = None,
    timeout: int = 120,
) -> subprocess.CompletedProcess[str]:
    """Run the fss-jvm container with an isolated read-only /data override dir.

    Zero host-state dependencies: any file not written into the per-call temp dir
    falls back cleanly to /w/cfg/ baked into the image by tools/thing-sign/Dockerfile.jvm.
    """
    img = image or os.environ.get("FSS_SIGN_IMAGE", DEFAULT_IMAGE)
    plat = platform if platform is not None else os.environ.get("FSS_SIGN_PLATFORM", DEFAULT_PLATFORM)
    seed_val = seed_override if seed_override is not None else os.environ.get("FSS_SIGN_SEED")
    appid_val = appid_override if appid_override is not None else os.environ.get("FSS_SIGN_APPID")
    cert_path = cert_override_path if cert_override_path is not None else os.environ.get("FSS_SIGN_CERT")
    pkg_val = package_override if package_override is not None else os.environ.get("FSS_SIGN_PACKAGE")

    with tempfile.TemporaryDirectory(prefix="fss-tuya-sign-") as td:
        td_path = Path(td)
        if canon is not None:
            (td_path / "in.txt").write_text(canon, encoding="utf-8")
        if seed_val is not None:
            (td_path / "seed.txt").write_text(seed_val, encoding="utf-8")
        if appid_val is not None:
            (td_path / "appid.txt").write_text(appid_val, encoding="utf-8")
        if pkg_val is not None:
            (td_path / "package.txt").write_text(pkg_val, encoding="utf-8")
        if cert_path is not None:
            (td_path / "cert.der").write_bytes(Path(cert_path).read_bytes())

        cmd = ["docker", "run", "--rm"]
        if plat:
            cmd.extend(["--platform", plat])
        cmd.extend(["-v", f"{td}:/data:ro", img])
        cmd.extend(extra_args)
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        if r.returncode != 0:
            raise RuntimeError(
                f"fss-jvm container exited {r.returncode} (image={img}, platform={plat}): "
                + (r.stderr or r.stdout)[-500:]
            )
        return r


def harness_sign(
    canon: str,
    *,
    seed_override: str | None = None,
    appid_override: str | None = None,
    cert_override_path: str | None = None,
    image: str | None = None,
) -> str | None:
    r = _docker_run(
        [],
        canon=canon,
        seed_override=seed_override,
        appid_override=appid_override,
        cert_override_path=cert_override_path,
        image=image,
    )
    for line in r.stderr.splitlines():
        if line.startswith("RESULT="):
            v = line.split("=", 1)[1].strip()
            return None if v == "null" else v
    raise RuntimeError("harness produced no RESULT (stderr tail): " + r.stderr[-400:])


def compute_digest(msg: str = "abc", key: str = "key", *, image: str | None = None) -> str:
    r = _docker_run(["java", "-cp", "/w/out", "Run", "digest", msg, key], image=image)
    for line in r.stderr.splitlines():
        if line.startswith("DIGEST="):
            return line.split("=", 1)[1].strip()
    raise RuntimeError("computeDigest failed (stderr tail): " + r.stderr[-400:])


def selftest() -> int:
    gt = json.loads(Path(EVIDENCE).read_text(encoding="utf-8"))
    canon = gt["captured_canonical"]
    got = harness_sign(canon)
    want = gt["captured_sign"]
    ok = got == want
    print(f"captured sign : {want}")
    print(f"harness sign  : {got}")
    print(f"match         : {ok}")
    rebuilt = canonical(gt["request_map"])
    print(f"canonical eq  : {rebuilt == canon}")
    return 0 if (ok and rebuilt == canon) else 1


def enc_key(
    request_id: str,
    ecode: str = "",
    *,
    seed_override: str | None = None,
    appid_override: str | None = None,
    image: str | None = None,
) -> bytes:
    """getEncryptoKey via the harness (does cmd0 + warmup + key derivation)."""
    r = _docker_run(
        ["java", "-cp", "/w/out", "Run", "enc", request_id, ecode],
        seed_override=seed_override,
        appid_override=appid_override,
        image=image,
    )
    for line in r.stderr.splitlines():
        if line.startswith("KEY="):
            return bytes.fromhex(line[4:].strip())
    raise RuntimeError("enc key derivation failed: " + r.stderr[-400:])


def encrypt_post(post_obj: dict[str, Any], request_id: str) -> str:
    """et=3 postData: AES-GCM(random 12B nonce, key=getEncryptoKey(rid)) -> b64(nonce+ct)."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = enc_key(request_id)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, json.dumps(post_obj, separators=(",", ":")).encode("utf-8"), None)
    return base64.b64encode(nonce + ct).decode("ascii")


def ch_key(
    *,
    seed_override: str | None = None,
    appid_override: str | None = None,
    image: str | None = None,
) -> str:
    """getChKey via harness."""
    r = _docker_run(
        ["java", "-cp", "/w/out", "Run", "chkey"],
        seed_override=seed_override,
        appid_override=appid_override,
        image=image,
    )
    for line in r.stderr.splitlines():
        if line.startswith("CHKEY="):
            return line[6:].strip()
    raise RuntimeError("chKey derivation failed: " + r.stderr[-400:])


def api_call(
    action: str,
    post_obj: dict[str, Any],
    ver: str = "1.0",
    identity: dict[str, Any] | None = None,
    host: str = "https://a1-us.iotbing.com",
    sid: str | None = None,
) -> dict[str, Any]:
    """Full et=3 api.json round trip with a fresh sign, mimicking the app's envelope."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    ident = {
        "clientId": os.environ.get("FSS_SIGN_APPID") or os.environ.get("CLIENT_ID") or "7hvgpakg784c3pj5qe3e",
        "appVersion": "5.10.12",
        "ttid": "android",
        "os": "Android",
        "lang": "en_US",
    }
    if identity:
        ident.update(identity)
    rid = str(uuid.uuid4())
    key = enc_key(rid, sid or "")
    nonce = os.urandom(12)
    pd = base64.b64encode(
        nonce + AESGCM(key).encrypt(
            nonce, json.dumps(post_obj, separators=(",", ":")).encode("utf-8"), None
        )
    ).decode("ascii")
    params = {
        "a": action, "v": ver, "clientId": ident["clientId"], "os": ident["os"],
        "appVersion": ident["appVersion"], "deviceId": rid, "ttid": ident["ttid"],
        "lang": ident["lang"], "et": "3", "cp": "gzip", "channel": "sdk", "nd": "1",
        "time": str(int(time.time())), "requestId": rid, "postData": pd,
        "chKey": ch_key(),
    }
    if sid:
        params["sid"] = sid
    canon = canonical(params)
    sign = harness_sign(canon)
    if not sign:
        raise RuntimeError("harness refused to sign (bmp gate)")
    params["sign"] = sign
    body = "&".join(f"{k}={urllib.parse.quote(str(v), safe='')}" for k, v in params.items())
    req = urllib.request.Request(
        host + "/api.json",
        data=body.encode("utf-8"),
        headers={
            "User-Agent": "aosu/5.10.12 (com.glazero.android; build:21739; Android 14) okhttp/4.12.0",
            "content-type": "application/x-www-form-urlencoded",
        },
    )
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
        if len(a) < 2:
            print("usage: tuya_thing_sign.py sign <canon-file|->", file=sys.stderr)
            return 2
        src = sys.stdin.read() if a[1] == "-" else Path(a[1]).read_text(encoding="utf-8")
        s = harness_sign(src.strip())
        print(s or "null")
        return 0 if s else 1
    if a[0] == "chkey":
        print(ch_key())
        return 0
    if a[0] == "digest":
        msg = a[1] if len(a) > 1 else "abc"
        key = a[2] if len(a) > 2 else "key"
        print(compute_digest(msg, key))
        return 0
    if a[0] == "classify-response":
        if len(a) < 2:
            print("usage: tuya_thing_sign.py classify-response <json-or-file>", file=sys.stderr)
            return 2
        raw = a[1]
        if Path(raw).is_file():
            raw = Path(raw).read_text(encoding="utf-8")
        doc = json.loads(raw)
        print(json.dumps(classify_gateway_response(doc), indent=2))
        return 0
    if a[0] == "call":
        if len(a) < 2:
            print("usage: tuya_thing_sign.py call <action> [<postData-json>] [<sid>]", file=sys.stderr)
            return 2
        action = a[1]
        post = json.loads(a[2]) if len(a) > 2 else {}
        sid = a[3] if len(a) > 3 else None
        resp = api_call(action, post, sid=sid)
        print(json.dumps(resp, indent=1)[:4000])
        if resp.get("success") is not True:
            print(f"gateway diagnosis: {json.dumps(classify_gateway_response(resp))}", file=sys.stderr)
            return 1
        return 0
    if a[0] == "canon":
        if len(a) < 2:
            print("usage: tuya_thing_sign.py canon <json-map>", file=sys.stderr)
            return 2
        params = json.loads(a[1])
        print(canonical(params))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())

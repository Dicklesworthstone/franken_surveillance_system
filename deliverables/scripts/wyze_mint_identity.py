#!/usr/bin/env python3
"""Mint a Wyze device IoT identity (cert/key/rootCA) for a SECOND unit via the cloud.

fss-79b89 follow-up (CloudyHawk order, GreenGlacier lane): `.4.24` (80482C4BCF0B) has its
owner store under deliverables/certs/iot/; `.4.23` (80482C525905) never got one. This drives
the exact flow proven in EV-pack-H-002d §1–§2:

  1. owner login  POST https://auth-prod.api.wyze.com/api/user/login
     (triple-MD5 password, apikey/keyid headers from ~/.config/fss-lab/wyze.env)
  2. cert issue   POST https://app.wyzecam.com/device/system/get_iot_certificate
     (appid wc4p_5b0e5bc2788d4ff68c7b98a5656148d0, sc "verify_method", sv = the access key,
      enr per unit — NOT empty: an empty enr is the 404 identity carrier)
  3. download the three presigned S3 URLs into deliverables/certs/iot/<MAC>/
     (repo copy is authoritative; ~/.config is not versioned and vanished once)

Usage:
  wyze_mint_identity.py                       # default MAC 80482C525905
  wyze_mint_identity.py <MAC> <ENR> [MODEL]   # explicit identity

Secrets are read from wyze.env / the env at runtime and never printed (lab rule).
"""
import hashlib
import json
import os
import sys
import time
import urllib.request
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_IOT_DIR = os.path.join(HERE, "..", "certs", "iot")
ENV_PATH = os.path.expanduser("~/.config/fss-lab/wyze.env")

AUTH_HOST = "https://auth-prod.api.wyze.com"
API_HOST = "https://app.wyzecam.com"
APPID_CERT = "wc4p_5b0e5bc2788d4ff68c7b98a5656148d0"
SV_CERT = "5b0e5bc2788d4ff68c7b98a5656148d0"
PHONE = "d39515e3-5b94-4b29-b63f-1b3456cc270a"
FILES = {"root_cert_url": "rootCA.crt", "client_cert_url": "cert.pem",
         "client_private_key_url": "privkey.pem"}

# per-unit identity: enr is the TUTK session secret, observed in cleartext from the device's
# own certificate POST (emudhra-ca.md) / wyze_inventory.json
KNOWN = {
    "80482C525905": "Lt6RL78/0V0Pe1y2",   # .4.23, captured 2026-10-25 (emudhra-ca.md)
    "80482C4BCF0B": "O7y73ZL+K47xvSPY",   # .4.24 (EV-pack-H-002d §2)
}


def load_env() -> dict:
    env = {}
    with open(ENV_PATH) as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k] = v
    return env


def login(env: dict) -> str:
    """Owner login; returns the access token. Password is md5^3, exactly as proven."""
    email, pw = env["WYZE_EMAIL"], env["WYZE_PASSWORD"]
    h = hashlib.md5(hashlib.md5(hashlib.md5(pw.encode()).hexdigest().encode())
                    .hexdigest().encode()).hexdigest()
    body = json.dumps({"email": email, "password": h}).encode()
    req = urllib.request.Request(AUTH_HOST + "/api/user/login", data=body, method="POST",
                                 headers={"apikey": env["WYZE_API_KEY"],
                                          "keyid": env["WYZE_KEY_ID"],
                                          "phone-id": str(uuid.uuid4()),
                                          "content-type": "application/json",
                                          "user-agent": "docker-wyze-bridge/3.0"})
    with urllib.request.urlopen(req, timeout=25) as r:
        j = json.loads(r.read())
    tok = j.get("access_token")
    if not tok:
        sys.exit("login failed: " + json.dumps(j)[:300])
    return tok


def issue_cert(tok: str, mac: str, enr: str, model: str) -> dict:
    body = {
        "mac": mac, "product_model": model, "product_type": "Camera",
        "hardware_ver": "0.0.0.0", "firmware_ver": "4.52.17.26", "enr": enr,
        "sc": "verify_method", "sv": SV_CERT, "ts": int(time.time() * 1000),
        "access_token": tok, "appid": "wc4p", "app_name": "wyze",
        "app_version": "2.50.0", "phone_id": PHONE,
    }
    req = urllib.request.Request(API_HOST + "/device/system/get_iot_certificate",
                                 data=json.dumps(body).encode(), method="POST",
                                 headers={"content-type": "application/json",
                                          "appid": APPID_CERT,
                                          "user-agent": "wyze_ios/3.22.0"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            j = json.loads(r.read())
    except urllib.error.HTTPError as e:
        sys.exit(f"cert issue HTTP {e.code}: {e.read()[:300]}")
    if j.get("code") not in ("1", 1):
        sys.exit(f"cert refused ({j.get('code')}): {j.get('msg', j)}")
    return j["data"]


def download(data: dict, out_dir: str) -> list:
    os.makedirs(out_dir, exist_ok=True)
    got = []
    for key, name in FILES.items():
        url = data[key]
        with urllib.request.urlopen(url, timeout=30) as r, \
                open(os.path.join(out_dir, name), "wb") as fh:
            fh.write(r.read())
        got.append(name)
    return got


def main() -> int:
    argv = sys.argv[1:]
    mac = (argv[0] if argv else "80482C525905").upper().replace(":", "")
    enr = argv[1] if len(argv) > 1 else KNOWN.get(mac)
    model = argv[2] if len(argv) > 2 else "HL_CAM4"
    if not enr:
        sys.exit(f"no known enr for {mac}; pass it as argv[1] "
                 "(source: device's own get_iot_certificate POST or wyze_inventory.json)")
    env = load_env()
    print(f"login  {AUTH_HOST} as {env['WYZE_EMAIL'][:3]}…")
    tok = login(env)
    print(f"issue  {API_HOST}/device/system/get_iot_certificate mac={mac} model={model}")
    data = issue_cert(tok, mac, enr, model)
    print(f"thing_name={data.get('thing_name')} client_id={data.get('client_id')} "
          f"keep_alive={data.get('keep_alive')}")
    out = os.path.normpath(os.path.join(REPO_IOT_DIR, mac))
    got = download(data, out)
    for name in got:
        path = os.path.join(out, name)
        print(f"stored {path} ({os.path.getsize(path)} B)")
    print("mint ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())

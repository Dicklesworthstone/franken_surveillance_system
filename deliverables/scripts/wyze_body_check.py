#!/usr/bin/env python3
"""Validate the command bodies the proxy emits, using a fake-device capture.

Reads a `wyze_fake_device.py` log, takes every `hl/devices/<thing>/cmd` PUBLISH,
XXTEA-decrypts it with the ENR and checks the result is the cloud's JSON shape
with a url/md5 that match the staged capsule.

  wyze_body_check.py /tmp/fake.log --enr O7y73ZL+K47xvSPY --md5 5c96… [--url-frag 4.52.17.33]
"""
import argparse
import json
import re
import sys

DELTA = 0x9E3779B9


def xxtea(data: bytes, key: bytes, decrypt: bool = False) -> bytes:
    n = len(data) // 4
    if n < 2:
        return data
    v = list(__import__("struct").unpack("<%dI" % n, data[:n * 4]))
    k = list(__import__("struct").unpack("<4I", (key + b"\0" * 16)[:16]))
    rounds = 6 + 52 // n
    if decrypt:
        total = (rounds * DELTA) & 0xFFFFFFFF
        y = v[0]
        for _ in range(rounds):
            e = (total >> 2) & 3
            for p in range(n - 1, -1, -1):
                z = v[(p - 1) % n]
                mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((total ^ y) + (k[(p & 3) ^ e] ^ z))
                v[p] = (v[p] - mx) & 0xFFFFFFFF
                y = v[p]
            total = (total - DELTA) & 0xFFFFFFFF
    else:
        total = 0
        z = v[n - 1]
        for _ in range(rounds):
            total = (total + DELTA) & 0xFFFFFFFF
            e = (total >> 2) & 3
            for p in range(n):
                y = v[(p + 1) % n]
                mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((total ^ y) + (k[(p & 3) ^ e] ^ z))
                v[p] = (v[p] + mx) & 0xFFFFFFFF
                z = v[p]
    return __import__("struct").pack("<%dI" % n, *v)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("--enr", required=True)
    ap.add_argument("--md5", required=True)
    ap.add_argument("--url-frag", default="4.52.17.33")
    a = ap.parse_args()

    lines = open(a.log, errors="replace").read().splitlines()
    topic = None
    n = ok = 0
    for ln in lines:
        m = re.match(r"PUBLISH (\S+) len=(\d+)", ln)
        if m:
            topic = m.group(1)
            continue
        m = re.match(r"\s+hex=([0-9a-f]+)", ln)
        if not m or not topic or not topic.endswith("/cmd"):
            continue
        n += 1
        raw = bytes.fromhex(m.group(1))
        try:
            pt = xxtea(raw, a.enr.encode(), True)
            doc = json.loads(pt.split(b"\0")[0])
        except Exception as exc:
            print(f"#{n} MALFORMED decrypt/json: {exc}")
            continue
        par = doc.get("Params") or {}
        problems = []
        if doc.get("Action") != "upgrade":
            problems.append(f"Action={doc.get('Action')!r}")
        for k in ("model", "url", "firmware_ver", "md5"):
            if not par.get(k):
                problems.append(f"Params.{k} missing")
        if a.url_frag not in (par.get("url") or ""):
            problems.append(f"url={par.get('url')!r}")
        if par.get("md5") != a.md5:
            problems.append(f"md5={par.get('md5')!r} != staged")
        if not doc.get("Guid"):
            problems.append("Guid missing")
        if not isinstance(doc.get("Ts"), int):
            problems.append("Ts missing/not int")
        if problems:
            print(f"#{n} BAD {'; '.join(problems)}")
        else:
            ok += 1
            print(f"#{n} ok {json.dumps(doc)[:120]}")
    print(f"\n{n} cmd bodies, {ok} well-formed")
    return 0 if n and ok == n else 1


if __name__ == "__main__":
    sys.exit(main())

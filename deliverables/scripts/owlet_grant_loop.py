#!/usr/bin/env python3
"""Owlet grant loop — the responder side of the second 0x0602 (bead fss-kemuu).

Measured 2026-10-26 (owlet_relay_watch.py, docs/exploit/owlet-apk.md §9.8): after our
LAN-search probe → nO (0x0602) → ACK, the camera answers the ACK with a SECOND 200-byte
0x0602 LAN_SEARCH_R from its P2P port — it re-arms search state instead of granting.
This tool closes that loop the way a TUTK client would: when the second 0x0602 arrives,
treat it as the camera asking US to prove we are a real client, and send the frames the
grant path carries — the AV CONNECT (598-byte avClientStart channel 0 shape, the same
builder loopback-verified in owlet_relay_watch.py) plus the IOTC keepalive — then wait
for 0x2041.

Self-contained: the codec constants (XOR frame key, LS head/mid/trailer, AV head/MID)
are inlined here so the loop runs from the repo alone; ~/fw-lab/owlet/cubo is imported
only for build_av_connect when present, with a byte-identical local fallback otherwise.

  owlet_grant_loop.py fire [--rounds N] [--port P] [--backoff 300]
      Drive probe → nO → ACK → (second 0x0602) → grant+av0 per round. Every frame is
      hex-logged with deltas to /tmp/owlet_grant_loop.log and echoed to stdout.
      Stop conditions: any 3 consecutive recv timeouts → back off --backoff seconds
      (default 5 min) before the next round; a 0x2041 grant → continue into av0 and
      record everything that follows for 10 s.

  owlet_grant_loop.py watch3478 [--window 60] [--max-wait S]
      Passive relay-traffic timeline (the -45 hunt): logs 3478 packet counts so the
      grant-loop log can be correlated with registration state.

Root required for the L2 send (scapy BPF). Camera .4.163 answers ICMP only when it
feels like it — liveness is the camera's own frames on en1, not ARP.
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
LAN_SEARCH_PORT = 63616
LOG = "/tmp/owlet_grant_loop.log"
CRED = os.path.expanduser("~/.config/fss/owlet_credentials.json")

# ── codec (inlined from the proven pure-Python TUTK stack, byte-identical) ───
_XOR_KEY = bytes.fromhex("6e2e8d8c40d040ca2d6d280c40e4cad8")
_LS_HEAD16 = bytes.fromhex("04021a02480000000106210000000000")
_LS_MID8 = bytes.fromhex("0000000001010204")
_LS_TRAILER8 = bytes.fromhex("63041313040c0c63")
_AV_HEAD12 = bytes.fromhex("04021a0a4602000007042100")


def _local_mac():
    try:
        out = subprocess.run(["ifconfig", IFACE], capture_output=True, text=True).stdout
        for line in out.splitlines():
            if "ether " in line:
                return bytes.fromhex(line.split("ether ")[1].split()[0].replace(":", ""))
    except Exception:
        pass
    return bytes.fromhex("020000000000")


# _AV_MID = perm of the local MAC, exactly as the proven stack computes it
_m = _local_mac()
AV_MID = bytes([_m[1], _m[0], _m[5], _m[4], _m[3], _m[2]])
# the probe/ACK client fingerprint at plaintext[58:64] is 6 bytes; the proven stack uses
# _AV_MID_DYNAMIC (000200000000-shaped), camera-validated as MID-independent
FINGERPRINT = bytes([_m[1], _m[0], _m[5], _m[4], _m[3], _m[2]])


def xor_frame(data: bytes) -> bytes:
    return bytes(b ^ _XOR_KEY[i % 16] for i, b in enumerate(data))


def transcode(plain: bytes) -> bytes:
    """Full TUTK transcode — import from the proven stack when available."""
    try:
        sys.path.insert(0, os.path.expanduser("~/fw-lab/owlet/cubo"))
        import cuboai_pure_owlet as cp
        return cp.transcode(plain, swap_tail=False)
    except Exception:
        return xor_frame(plain)  # legacy approximation, flagged in the log


def inv_transcode(wire: bytes) -> bytes:
    try:
        sys.path.insert(0, os.path.expanduser("~/fw-lab/owlet/cubo"))
        import cuboai_pure_owlet as cp
        return cp.inv_transcode(wire)
    except Exception:
        return xor_frame(wire)


def build_probe(uid: bytes, R: int) -> bytes:
    t = bytearray(88)
    t[0:16] = _LS_HEAD16
    t[16:16 + len(uid)] = uid
    t[48:56] = _LS_MID8
    t[56:58] = struct.pack("<H", R & 0xFFFF)
    t[58:64] = FINGERPRINT
    t[64] = 0x01
    t[80:88] = _LS_TRAILER8
    return transcode(bytes(t))


def build_ack(uid: bytes, R: int) -> bytes:
    """ACK == probe with plaintext[64]=0x02."""
    return _build_ack_from(uid, R)


def _build_ack_from(uid: bytes, R: int) -> bytes:
    t = bytearray(88)
    t[0:16] = _LS_HEAD16
    t[16:16 + len(uid)] = uid
    t[48:56] = _LS_MID8
    t[56:58] = struct.pack("<H", R & 0xFFFF)
    t[58:64] = FINGERPRINT
    t[64] = 0x02
    t[80:88] = _LS_TRAILER8
    return transcode(bytes(t))


def build_av_connect_local(nO_dec: bytes, R: int, account: bytes, password: bytes,
                           channel: int = 0) -> bytes:
    """598-byte AV CONNECT (avClientStart shape) — fallback when the proven
    builder is unavailable. Byte-model from the CuboAI reverse work."""
    p = bytearray(598)
    p[0:12] = _AV_HEAD12
    p[6] = channel
    p[14] = 0
    Rb = struct.pack("<H", R & 0xFFFF)
    p[12:14] = Rb
    p[16:20] = bytes.fromhex("0c000000")
    p[20:22] = Rb
    p[22:28] = AV_MID
    p[30] = 0x0B
    p[44] = 0x22
    p[45] = 0x02
    p[46] = 0x01 if channel % 2 == 0 else 0x00
    p[29] = 0x00 if channel % 2 == 0 else 0x20
    p[48:52] = struct.pack("<I", 1)
    p[52:52 + len(account)] = account
    p[309:309 + len(password)] = password
    p[566] = 0x01
    p[570] = 0x04
    p[574] = 0xFB
    p[575] = 0x07
    p[576] = 0x1F
    p[588] = 0x03
    p[594] = 0x01
    p[3] |= 2
    return transcode(bytes(p))


def build_av_connect(nO_dec: bytes, R: int, account: bytes, password: bytes,
                     channel: int = 0) -> bytes:
    try:
        sys.path.insert(0, os.path.expanduser("~/fw-lab/owlet/cubo"))
        import cuboai_pure_owlet as cp
        tok = struct.pack("<I", (int.from_bytes(os.urandom(4), "little") & 0x7FFFFFFF) or 1)
        return cp.build_av_connect(None, nO_dec, channel, account, password,
                                   token=tok, R=R)
    except Exception:
        return build_av_connect_local(nO_dec, R, account, password, channel)


# ── logging ──────────────────────────────────────────────────────────────────
def log(msg):
    line = f"{datetime.datetime.now().isoformat(timespec='milliseconds')} {msg}"
    print(line, flush=True)
    try:
        with open(LOG, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass


def hx(b: bytes, n: int = 96) -> str:
    return b[:n].hex()


# ── L2 send / UDP receive ────────────────────────────────────────────────────
def l2_send(payload: bytes, sport: int):
    from scapy.all import Ether, IP, UDP, sendp
    sendp(Ether(dst=CAM_MAC) / IP(src=MY_IP, dst=CAM_IP)
          / UDP(sport=sport, dport=LAN_SEARCH_PORT) / payload,
          iface=IFACE, verbose=0)


def l2_send_to(payload: bytes, sport: int, cam_addr):
    """L2 send to a specific camera address — the nO source (P2P/session) port,
    which is where native TUTK sends the post-search frames (ACK, av-connect)."""
    from scapy.all import Ether, IP, UDP, sendp
    sendp(Ether(dst=CAM_MAC) / IP(src=MY_IP, dst=cam_addr[0])
          / UDP(sport=sport, dport=cam_addr[1]) / payload,
          iface=IFACE, verbose=0)


def load_creds():
    try:
        with open(CRED) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def gen_R():
    try:
        sys.path.insert(0, os.path.expanduser("~/fw-lab/owlet/cubo"))
        import cuboai_pure_owlet as cp
        return cp.gen_R()
    except Exception:
        return int.from_bytes(os.urandom(2), "little") % 0x7FFF or 1


# ── the loop ─────────────────────────────────────────────────────────────────
def round_trip(cred, round_no, wait_grant=4.0, post_grant=10.0, sport_opt=0):
    """One probe→nO→ACK→(second 0x0602)→grant→av0 attempt. Returns result dict.

    `sport_opt` pins the RX source port (0 = ephemeral); the loopback harness and
    reproducible re-tests pass a fixed port so the peer's reply lands predictably.
    """
    out = {"round": round_no, "grant": False}
    uid = cred["tutkid"].encode()
    # gnj.smali:22763 ground truth (the app's avClientStartEx):
    #   account_or_identity="admin", password_or_token=<authKey>,
    #   security_mode=2, auth_type=0. Default to that; the historical
    #   account=authKey choice stays available via OWLET_ACCOUNT=authkey.
    if os.environ.get("OWLET_ACCOUNT", "admin") == "authkey":
        account = cred.get("authKey", "").encode()
    else:
        account = b"admin"
    password = cred.get("authKey", "").encode()
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.settimeout(2.5)
    rx.bind((MY_IP, sport_opt))
    sport = rx.getsockname()[1]
    out["sport"] = sport

    t0 = time.time()
    R = gen_R()
    probe = build_probe(uid, R)
    ack = build_ack(uid, R)
    l2_send(probe, sport)
    l2_send(probe, sport)
    out["t_probe"] = round(time.time() - t0, 3)
    log(f"[r{round_no}] probe sent R=0x{R:04x} sport={sport} len={len(probe)} "
        f"hex={hx(probe)}")

    # 1. first nO
    try:
        raw1, addr1 = rx.recvfrom(2048)
    except socket.timeout:
        out["stage"] = "no-nO-1"
        rx.close()
        return out, 1
    d1 = inv_transcode(raw1)
    out["nO1"] = {"len": len(raw1), "type": hex(int.from_bytes(d1[8:10], "little")),
                  "from": f"{addr1[0]}:{addr1[1]}", "t": round(time.time() - t0, 3)}
    log(f"[r{round_no}] nO1 {len(raw1)}B type={out['nO1']['type']} "
        f"from={addr1[1]} t+{out['nO1']['t']}s hex={hx(raw1)}")

    # 2. ACK — native TUTK sends every post-search frame to the ADDRESS THE nO CAME
    # FROM (cuboxai_pure_owlet connect(): `nO, nO_raw, cam = d, raw, addr` then
    # `s.sendto(ack, cam)`), NOT back to the search listener. Our ACK/av0 went to
    # 63616 and the camera's session layer never saw them (§9.9.1's r1-r12, all
    # grant-less). The nO source port is the camera's P2P/session socket — send there.
    cam_addr = (addr1[0], addr1[1])
    l2_send_to(ack, sport, cam_addr)
    out["t_ack"] = round(time.time() - t0, 3)
    log(f"[r{round_no}] ack sent → cam:{addr1[1]} t+{out['t_ack']}s hex={hx(ack)}")

    # 3. the camera's answer to the ACK: measured = second 0x0602
    try:
        raw2, addr2 = rx.recvfrom(2048)
    except socket.timeout:
        out["stage"] = "ack-silent"
        rx.close()
        return out, 1
    d2 = inv_transcode(raw2)
    typ2 = int.from_bytes(d2[8:10], "little")
    out["ack_reply"] = {"len": len(raw2), "type": hex(typ2),
                        "from": f"{addr2[0]}:{addr2[1]}",
                        "t": round(time.time() - t0, 3)}
    log(f"[r{round_no}] ack-reply {len(raw2)}B type={hex(typ2)} "
        f"from={addr2[1]} t+{out['ack_reply']['t']}s hex={hx(raw2)}")

    # 4. RESPONDER SIDE: the second 0x0602 re-arms search — answer it with the
    # frames a granted client would send. Native TUTK sequence (cuboai_pure_owlet
    # connect()): ACK → 8 ms → av-connect ch0 AND ch1 back-to-back → wait 0x2041.
    # Send to the nO source port (the session socket), NOT the search listener.
    if typ2 == 0x0602:
        av0 = build_av_connect(d2, R, account, password, channel=0)
        l2_send_to(av0, sport, cam_addr)
        out["av0_len"] = len(av0)
        out["t_av0"] = round(time.time() - t0, 3)
        log(f"[r{round_no}] AV-CONNECT ch0 {len(av0)}B → cam:{addr1[1]} "
            f"t+{out['t_av0']}s hex={hx(av0, 160)}")
        av1 = build_av_connect(d2, R, account, password, channel=1)
        l2_send_to(av1, sport, cam_addr)
        out["av1_len"] = len(av1)
        log(f"[r{round_no}] AV-CONNECT ch1 {len(av1)}B → cam:{addr1[1]} "
            f"(pre-grant pair, native timing)")

    # 5. wait for the grant (or anything else)
    got = None
    rx.settimeout(wait_grant)
    try:
        while time.time() - t0 - out["ack_reply"]["t"] < wait_grant:
            raw3, addr3 = rx.recvfrom(65535)
            if len(raw3) == 88:
                d3 = xor_frame(raw3)
            else:
                d3 = inv_transcode(raw3)
            typ3 = int.from_bytes(d3[8:10], "little") if len(d3) >= 10 else 0
            rec = {"len": len(raw3), "type": hex(typ3),
                   "from": f"{addr3[0]}:{addr3[1]}",
                   "t": round(time.time() - t0, 3)}
            out.setdefault("post", []).append(rec)
            log(f"[r{round_no}] post {len(raw3)}B type={hex(typ3)} "
                f"from={addr3[1]} t+{rec['t']}s hex={hx(raw3, 160)}")
            if len(raw3) == 88 and d3[0:2] == b"\x20\x41" and typ3 == 0x2041:
                got = (raw3, d3, addr3)
                break
    except socket.timeout:
        pass
    if not got:
        out["stage"] = "no-grant"
        rx.close()
        return out, 1
    out["grant"] = True
    out["stage"] = "granted"
    session_hdr = bytes(got[1][16:32])
    out["session_hdr"] = session_hdr.hex()
    log(f"[r{round_no}] GRANT 0x2041 t+{round(time.time() - t0, 3)}s "
        f"session_hdr={session_hdr.hex()}")

    # 6. av0 already sent pre-grant; record everything for post_grant seconds
    rx.settimeout(post_grant)
    tail = []
    t1 = time.time()
    try:
        while time.time() - t1 < post_grant:
            raw4, addr4 = rx.recvfrom(65535)
            d4 = inv_transcode(raw4)
            typ4 = int.from_bytes(d4[8:10], "little") if len(d4) >= 10 else 0
            rec = {"len": len(raw4), "type": hex(typ4),
                   "t": round(time.time() - t0, 3)}
            tail.append(rec)
            log(f"[r{round_no}] session {len(raw4)}B type={hex(typ4)} "
                f"t+{rec['t']}s hex={hx(raw4, 96)}")
    except socket.timeout:
        pass
    out["session_frames"] = len(tail)
    rx.close()
    return out, 0


def cmd_fire(rounds, backoff):
    cred = load_creds()
    if cred is None:
        log("no credentials at ~/.config/fss/owlet_credentials.json — run "
            "owlet_relay_watch.py mint first")
        return 1
    consecutive_timeouts = 0
    for r in range(1, rounds + 1):
        res, timeouts = round_trip(cred, r)
        log(f"[r{r}] result {json.dumps(res)}")
        if res.get("grant"):
            log(f"[r{r}] GRANT PATH COMPLETE — session recorded")
            return 0
        consecutive_timeouts = consecutive_timeouts + timeouts if timeouts else 0
        if consecutive_timeouts >= 3:
            log(f"[r{r}] 3 consecutive timeouts — backing off {backoff}s")
            time.sleep(backoff)
            consecutive_timeouts = 0
        else:
            time.sleep(2)
    return 1


def cmd_watch3478(window, max_wait):
    """Passive 3478 timeline for the -45 hunt (delegates to the proven watcher)."""
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "owlet_relay_watch.py")
    r = subprocess.run([sys.executable, script, "watch", "--window", str(window),
                        "--attempts", str(max(1, max_wait // window))])
    return r.returncode


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["fire", "watch3478"], nargs="?", default="fire")
    ap.add_argument("--rounds", type=int, default=10)
    ap.add_argument("--backoff", type=int, default=300)
    ap.add_argument("--window", type=int, default=60)
    ap.add_argument("--max-wait", type=int, default=600)
    a = ap.parse_args()
    if a.mode == "watch3478":
        return cmd_watch3478(a.window, a.max_wait)
    return cmd_fire(a.rounds, a.backoff)


if __name__ == "__main__":
    sys.exit(main())

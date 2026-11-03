#!/usr/bin/env python3
"""Unit-test thingino_bootwatch.py (deliverables/scripts/thingino_bootwatch.py).

No device, no network: mock discovery + mock acceptance drive watch() end to
end, and the pure helpers are covered directly. Per the marching orders this is
the flash-day one-command watcher, so the certificate verdicts are the contract:

  python3 tests/test_thingino_bootwatch.py
"""
from __future__ import annotations

import importlib.util
import re
import json
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE.parent / "deliverables" / "scripts" / "thingino_bootwatch.py"
spec = importlib.util.spec_from_file_location("thingino_bootwatch", SCRIPT)
bw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bw)

FAILURES: list[str] = []


def check(cond: bool, what: str) -> None:
    print(("  PASS  " if cond else "  FAIL  ") + what)
    if not cond:
        FAILURES.append(what)


# --- pure helpers -----------------------------------------------------------------------------

check(bw.norm_mac("80:48:2C:4B:CF:0B") == "80:48:2c:4b:cf:0b", "norm_mac upper -> lower")
check(bw.norm_mac("80-48-2c-4b-cf-b") == "80:48:2c:4b:cf:0b",
      "norm_mac dash form + short octet zero-pads (arp prints cf:b)")
check(bw.mac_prefix("80:48:2c:4b:cf:0b") == "80:48:2c", "mac_prefix takes OUI")

# --- ARP table parse (synthetic output; no subprocess when we stub arp_table) ------------------

orig_arp_table = bw.arp_table


def fake_arp_table():
    return [("192.168.4.51", "80:48:2c:4b:cf:0b"), ("192.168.4.39", "80:48:2c:52:59:05"),
            ("192.168.4.71", "02:00:00:00:00:00"), ("192.168.4.1", "48:dd:0c:c9:ec:0d")]


bw.arp_table = fake_arp_table
orig_reachable = bw.reachable


def fake_reachable_ok(ip, timeout=2.0):
    return True, "icmp"


def fake_reachable_dead(ip, timeout=2.0):
    return False, "no-answer"


d = bw.ArpDiscovery("80:48:2c:4b:cf:0b", "80:48:2c", 1)
bw.reachable = fake_reachable_ok
ip, detail = d.poll_once()
check(ip == "192.168.4.51" and "icmp" in detail, "ArpDiscovery: exact MAC + reachable -> IP")
d2 = bw.ArpDiscovery(None, "80:48:2c", 1)
ip2, _ = d2.poll_once()
check(ip2 in ("192.168.4.51", "192.168.4.39"), "ArpDiscovery: OUI-prefix mode matches either Wyze unit")
d3 = bw.ArpDiscovery("00:11:22:33:44:55", "00:11:22", 1)
ip3, det3 = d3.poll_once()
check(ip3 is None, "ArpDiscovery: non-matching MAC -> None")
bw.reachable = fake_reachable_dead
d4 = bw.ArpDiscovery("80:48:2c:4b:cf:0b", "80:48:2c", 1)
ip4, det4 = d4.poll_once()
check(ip4 is None and "asleep" in det4, "ArpDiscovery: ARP-present-but-silent -> None (presence rule)")
bw.arp_table = orig_arp_table

# --- MockDiscovery timing ---------------------------------------------------------------------

md = bw.MockDiscovery({"ip": "10.0.0.9", "after_s": 0.2, "detail": "later"}, time.monotonic())
ip5, _ = md.poll_once()
check(ip5 is None, "MockDiscovery: before after_s -> None")
time.sleep(0.25)
ip6, _ = md.poll_once()
check(ip6 == "10.0.0.9", "MockDiscovery: after after_s -> scripted IP")

# --- build_cert verdicts -----------------------------------------------------------------------

img = bw.image_digest(None)
check(img == {"path": None, "sha256": None}, "image_digest: None -> nulls")
c1 = bw.build_cert("t0", "80:48:2c:4b:cf:0b", {"ip": None, "utc": None, "discovery": None},
                   img, None, 1.0)
check(c1["verdict"] == "NOT-SEEN" and c1["schema"] == bw.CERT_SCHEMA, "verdict NOT-SEEN")
c2 = bw.build_cert("t0", "80:48:2c:4b:cf:0b",
                   {"ip": "1.2.3.4", "utc": "u", "discovery": {"provider": "x", "detail": "y"}},
                   img, {"schema": "fss.tailnet-acceptance.v1", "all_pass": False,
                         "rows": [{"row": "rtsp-port", "pass": False, "detail": "no connection"}]}, 2.0)
check(c2["verdict"] == "BOOTED-UNACCEPTED", "verdict BOOTED-UNACCEPTED when acceptance fails")
c3 = bw.build_cert("t0", None,
                   {"ip": "1.2.3.4", "utc": "u", "discovery": None},
                   img, {"all_pass": True, "rows": []}, 3.0)
check(c3["verdict"] == "BOOTED-ACCEPTED", "verdict BOOTED-ACCEPTED when all rows pass")

# --- real image digest -------------------------------------------------------------------------

tailnet = HERE.parent / "deliverables" / "firmware" / "thingino-wyze_cam4_t41nq_os04d10_atbm6062s-tailnet.bin"
if tailnet.exists():
    d = bw.image_digest(str(tailnet))
    check(d["sha256"].startswith("033eb3643fdb2d2b"),
          "image_digest: committed tailnet image == 033eb364… (cert anchors the flashed bytes)")

# --- end-to-end watch(): real acceptance against a loopback mock device ------------------------

# A minimal mock "device": HTTP server answering GET / (http-control row) and POST onvif;
# plus a TCP listener on an RTSP port answering DESCRIBE with SDP. We run the REAL
# tailnet_acceptance contract (not the mock-acceptance shim) against it via run_acceptance.
onvif_body = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
    'xmlns:tds="http://www.onvif.org/ver10/device/wsdl" '
    'xmlns:tt="http://www.onvif.org/ver10/schema">'
    '<s:Body><tds:GetCapabilitiesResponse><tds:Capabilities>'
    '<tt:Media><tt:XAddr>http://127.0.0.1/onvif/media_service</tt:XAddr>'
    '<tt:StreamingCapabilities><tt:RTP_RTSP_TCP>true</tt:RTP_RTSP_TCP>'
    '</tt:StreamingCapabilities></tt:Media>'
    '</tds:Capabilities></tds:GetCapabilitiesResponse></s:Body></s:Envelope>'
)
device_info_body = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
    'xmlns:tds="http://www.onvif.org/ver10/device/wsdl" '
    'xmlns:tt="http://www.onvif.org/ver10/schema">'
    '<s:Body><tds:GetDeviceInformationResponse>'
    '<tds:Manufacturer>thingino</tds:Manufacturer><tds:Model>wyze_cam4</tds:Model>'
    '<tds:FirmwareVersion>thingino-tailnet-1</tds:FirmwareVersion>'
    '</tds:GetDeviceInformationResponse></s:Body></s:Envelope>'
)
profiles_body = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
    'xmlns:trt="http://www.onvif.org/ver10/media/wsdl" '
    'xmlns:tt="http://www.onvif.org/ver10/schema">'
    '<s:Body><trt:GetProfilesResponse>'
    '<tt:profile token="profile_1" fixed="true">'
    '<tt:VideoEncoderConfiguration><tt:H264></tt:H264>'
    '</tt:VideoEncoderConfiguration></tt:profile>'
    '</trt:GetProfilesResponse></s:Body></s:Envelope>'
)


class Device(threading.Thread):
    """Raw-socket HTTP device mock: tolerant of any request path (the harness
    re-derives the media path from the XAddr detail line, which carries trailing
    text), answering the three ONVIF bodies and plain GET."""

    def __init__(self, port: int):
        super().__init__(daemon=True)
        self.port = port
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(8)
        self.stop_flag = False

    def run(self) -> None:
        while not self.stop_flag:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            try:
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                if not data:
                    conn.close()
                    continue
                head = data.decode("utf-8", "replace")
                m = re.search(r"Content-Length:\s*(\d+)", head, re.I)
                body_in = b""
                if m:
                    want = int(m.group(1))
                    body_in = data.split(b"\r\n\r\n", 1)[1]
                    while len(body_in) < want:
                        body_in += conn.recv(4096)
                req = body_in.decode("utf-8", "replace")
                if "GetDeviceInformation" in req:
                    out = device_info_body.encode()
                elif "GetProfiles" in req:
                    out = profiles_body.encode()
                elif "GetCapabilities" in req:
                    out = onvif_body.encode()
                else:
                    out = b"ok"
                conn.sendall(("HTTP/1.1 200 OK\r\n"
                              "Content-Type: application/soap+xml; charset=utf-8\r\n"
                              f"Content-Length: {len(out)}\r\n"
                              "Connection: close\r\n\r\n").encode() + out)
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def stop(self) -> None:
        self.stop_flag = True
        try:
            self.sock.close()
        except OSError:
            pass


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


http_port = free_port()
srv = Device(http_port)
srv.start()

# RTSP mock: DESCRIBE -> 200 + SDP; SETUP/PLAY -> 200
rtsp_port = free_port()
rtsp = socket.socket()
rtsp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
rtsp.bind(("127.0.0.1", rtsp_port))
rtsp.listen(4)


def rtsp_serve() -> None:
    """One socket, one loop: DESCRIBE -> SETUP -> PLAY on the same connection
    (the contract checks the handshake over a single session)."""
    while True:
        try:
            conn, _ = rtsp.accept()
        except OSError:
            return
        try:
            while True:
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break  # client closed; serve the next connection
                    data += chunk
                if b"\r\n\r\n" not in data:
                    break
                text = data.decode("utf-8", "replace")
                first = text.splitlines()[0] if text else ""
                cseq = next((l.split(":", 1)[1].strip() for l in text.splitlines()
                             if l.lower().startswith("cseq:")), "1")
                if "DESCRIBE" in first:
                    sdp = ("v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=thingino\r\nt=0 0\r\n"
                           "m=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\n")
                    body = sdp.encode()
                    conn.sendall((f"RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\n"
                                  "Content-Type: application/sdp\r\n"
                                  f"Content-Length: {len(body)}\r\n\r\n").encode() + body)
                elif "SETUP" in first:
                    conn.sendall((f"RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\n"
                                  "Session: 12345678\r\n"
                                  "Transport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n"
                                  f"Content-Length: 0\r\n\r\n").encode())
                elif "PLAY" in first:
                    conn.sendall((f"RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\n"
                                  "Session: 12345678\r\n"
                                  f"Content-Length: 0\r\n\r\n").encode())
                else:
                    conn.sendall((f"RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\n"
                                  f"Content-Length: 0\r\n\r\n").encode())
        except OSError:
            continue
        finally:
            try:
                conn.close()
            except OSError:
                pass


threading.Thread(target=rtsp_serve, daemon=True).start()

# Point bootwatch's acceptance at the mock ports by monkey-patching run_contract import
ta_spec = importlib.util.spec_from_file_location(
    "ta_for_test", HERE.parent / "deliverables" / "scripts" / "tailnet_acceptance.py")
ta = importlib.util.module_from_spec(ta_spec)
ta_spec.loader.exec_module(ta)

calls = {}


def fake_run_acceptance(ip, args):
    calls["ip"] = ip
    rows, all_pass, _ = ta.run_contract(
        ip, rtsp_port=rtsp_port, onvif_port=http_port, http_port=http_port,
        timeout=5.0, require_tailnet_bind=False, expect_model="wyze_cam4",
        ssh_user=None, want_frame=False)
    return {"schema": "fss.tailnet-acceptance.v1", "host": ip, "all_pass": all_pass,
            "rows": rows}


disc = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
disc.write(json.dumps({"ip": "127.0.0.1", "after_s": 0, "detail": "mock device up"}))
disc.close()

cert_out = Path(tempfile.mkdtemp()) / "cert.json"
args = type(bw.args_stub, (), {})() if hasattr(bw, "args_stub") else None


class Args:
    mac = "80:48:2c:4b:cf:0b"
    mac_prefix = "80:48:2c"
    image = str(tailnet)
    cert = str(cert_out)
    timeout = 10.0
    poll = 0.2
    expect_model = "wyze_cam4"
    ssh_user = None
    no_frame = True
    timeout_per_probe = 5.0
    mock_discovery = disc.name
    mock_acceptance = None


# run_acceptance is resolved inside watch() by name; patch the module attribute
orig_accept = bw.run_acceptance
bw.run_acceptance = fake_run_acceptance
try:
    cert = bw.watch(Args())
finally:
    bw.run_acceptance = orig_accept

check(calls.get("ip") == "127.0.0.1", "watch: acceptance ran against the discovered IP")
check(cert["verdict"] == "BOOTED-ACCEPTED", "watch end-to-end: real contract rows all pass -> BOOTED-ACCEPTED")
saved = json.loads(cert_out.read_text())
check(saved["schema"] == bw.CERT_SCHEMA and saved["ip"] == "127.0.0.1"
      and saved["verdict"] == "BOOTED-ACCEPTED"
      and len(saved["acceptance"]["rows"]) >= 8,
      "watch: certificate artifact written with schema + acceptance rows")
rows_by_name = {r["row"]: r for r in cert["acceptance"]["rows"]}
check(rows_by_name["rtsp-handshake"]["pass"], "real row: rtsp-handshake PASS")
check(rows_by_name["onvif-device-info"]["pass"], "real row: onvif-device-info PASS (thingino/wyze_cam4)")
check(rows_by_name["onvif-profile-s"]["pass"], "real row: onvif-profile-s PASS")
check(rows_by_name["http-control"]["pass"], "real row: http-control PASS")
check(rows_by_name["onvif-device-info"]["detail"].find("wyze_cam4") >= 0,
      "identity gate: expect-model matched the flashed-image Model")

# --- not-seen path ------------------------------------------------------------------------------

disc2 = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
disc2.write(json.dumps({"after_s": 999, "detail": "mock: silence"}))
disc2.close()
cert_out2 = Path(tempfile.mkdtemp()) / "cert2.json"


class Args2(Args):
    mock_discovery = disc2.name
    cert = str(cert_out2)
    timeout = 0.5
    poll = 0.2


cert2 = bw.watch(Args2())
check(cert2["verdict"] == "NOT-SEEN" and cert2["ip"] is None,
      "watch: silence for --timeout -> NOT-SEEN certificate")

srv.stop()
print()
if FAILURES:
    print("FAILURES: %d" % len(FAILURES))
    sys.exit(1)
print("all asserts passed")

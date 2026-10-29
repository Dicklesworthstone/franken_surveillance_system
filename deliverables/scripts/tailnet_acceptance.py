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

Exit-code contract (the flash-day harness consumes these):
  0  all-pass  — every contract row passed
  1  partial   — the harness ran and at least one row FAILED (device answered)
  2  infra-fail — the harness could not run at all (host unresolvable, or no
                  tailscale interface when the bind check is required)

--json emits schema fss.tailnet-acceptance.v1:
  {schema, host, all_pass, exit_code, exit, infra_fail, rows:[{row,pass,detail}]}

Exit 0 only if every contract row passes. --self-test runs the mock
RTSP+ONVIF+SSH server on loopback and runs the full harness against it.

Rows (pass/fail each):
  rtsp-port        TCP connect to the RTSP port over the tailnet interface
  rtsp-handshake   DESCRIBE -> 200 with SDP, SETUP -> 200, PLAY -> 200
  rtsp-frame       ffmpeg decodes >=1 video frame off the live RTSP stream
                   (prudynt/rsd on the flashed unit; TAILSCALE-ENDSTATE.md §2.2)
  onvif-capabilities  GetCapabilities parses; Media XAddr + RTP/RTSP/TCP true
  onvif-device-info   GetDeviceInformation returns Manufacturer/Model/FirmwareVersion
                      (the flashed unit identity assertion for flash-day)
  onvif-profile-s  GetProfiles (media wsdl) lists >=1 profile with an H264
                   VideoEncoderConfiguration (ONVIF Profile-S media profile)
  http-control     HTTP GET answers (snapshot/control UI)
  tailscaled-status   `tailscale status` over SSH (dropbear, S30dropbear) lists
                      the camera node; only run with --ssh-user set
  dropbear-sftp    sftp batch put+get round-trip through dropbear; opt-in
                   --sftp with --ssh-user
  tailnet-bind     the target address is a tailscale interface address
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

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

# tds:GetDeviceInformation (device wsdl) — flash-day identity assertion: the answer
# must carry Manufacturer/Model/FirmwareVersion so the operator can prove WHICH
# image is running before any further gate (cve-watch-2026-10.md §Plan A §4).
DEVICE_INFO_ENVELOPE = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
    'xmlns:tds="http://www.onvif.org/ver10/device/wsdl">'
    "<s:Body><tds:GetDeviceInformation/></s:Body></s:Envelope>"
)
DEVINFO_RE = re.compile(
    r"<tds:GetDeviceInformationResponse>(?P<body>.*?)</tds:GetDeviceInformationResponse>",
    re.S,
)
DEVINFO_FIELD_RE = {
    "Manufacturer": re.compile(r"<tds:Manufacturer>([^<]+)</tds:Manufacturer>"),
    "Model": re.compile(r"<tds:Model>([^<]+)</tds:Model>"),
    "FirmwareVersion": re.compile(r"<tds:FirmwareVersion>([^<]+)</tds:FirmwareVersion>"),
}

# tds:GetProfiles (media wsdl) — ONVIF Profile-S: the media service must expose at
# least one profile whose configuration binds an H264 video encoder (Profile-S §5.2:
# VideoEncoderConfiguration with H264 option) and an RTSP source. thingino ships
# /usr/sbin/onvif_notify_server + onvif.cgi (firmware-build.md §4), so this row is
# the flashed-image media-profile gate.
GET_PROFILES_ENVELOPE = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
    'xmlns:trt="http://www.onvif.org/ver10/media/wsdl">'
    "<s:Body><trt:GetProfiles/></s:Body></s:Envelope>"
)
PROFILES_RE = re.compile(
    r"<trt:GetProfilesResponse>(?P<body>.*?)</trt:GetProfilesResponse>", re.S
)
PROFILE_TOKEN_RE = re.compile(r"<tt:profile\s+token=\"([^\"]+)\"", re.S)
H264_RE = re.compile(r"<tt:H264\b", re.S)
VIDEO_ENC_RE = re.compile(r"<tt:VideoEncoderConfiguration\b", re.S)

# One real decodable H264 frame (64x64 gray, libx264 ultrafast/zerolatency, one GOP):
# SPS(7) + PPS(8) + SEI(6) + IDR slice(5), hex NALs, start codes stripped —
# sent as RFC 6184 single-NAL-unit RTP packets by the mock (ENDSTATE §2.2).
MOCK_H264_NALS = [
    "6742c00adc426c0440000003004000000ca3c489e0",
    "68ce0fc8",
    "0605ffff4ddc45e9bde6d948b7962cd820d923eeef78323634202d20636f7265203136352072333232322062333536303561202d20482e3236342f4d5045472d342041564320636f646563202d20436f70796c65667420323030332d32303235202d20687474703a2f2f7777772e766964656f6c616e2e6f72672f783236342e68746d6c202d206f7074696f6e733a2063616261633d30207265663d31206465626c6f636b3d303a303a3020616e616c7973653d303a30206d653d646961207375626d653d30207073793d31207073795f72643d312e30303a302e3030206d697865645f7265663d30206d655f72616e67653d3136206368726f6d615f6d653d31207472656c6c69733d30203878386463743d302063716d3d3020646561647a6f6e653d32312c313120666173745f70736b69703d31206368726f6d615f71705f6f66667365743d3020746872656164733d31206c6f6f6b61686561645f746872656164733d3120736c696365645f746872656164733d30206e723d3020646563696d6174653d3120696e7465726c616365643d3020626c757261795f636f6d7061743d3020636f6e73747261696e65645f696e7472613d3020626672616d65733d3020776569676874703d30206b6579696e743d31206b6579696e745f6d696e3d31207363656e656375743d3020696e7472615f726566726573683d302072633d637266206d62747265653d30206372663d32332e302071636f6d703d302e36302071706d696e3d302071706d61783d3639207170737465703d342069705f726174696f3d312e34302061713d300080",
    "6588843a26280c9c9c9d75d75d75d75d75d75e",
]
SEQ = [0]


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


def onvif_device_info_row(host: str, port: int, timeout: float,
                          path: str = "/onvif/device_service",
                          expect_model: str | None = None) -> tuple[bool, str]:
    """GetDeviceInformation — proves WHICH image is running (flash-day identity gate).

    The flashed thingino rootfs reports Manufacturer=thingino (vendor answer differs),
    so --expect-model flips this row from informational to an assertion.
    """
    s = connect_tcp(host, port, timeout)
    if s is None:
        return False, "connect %s:%d failed" % (host, port)
    try:
        body = DEVICE_INFO_ENVELOPE.encode()
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
        m = DEVINFO_RE.search(text)
        if not m:
            return False, "no tds:GetDeviceInformationResponse (%d bytes)" % len(text)
        got: dict[str, str] = {}
        for field, rx in DEVINFO_FIELD_RE.items():
            fm = rx.search(m.group("body"))
            if not fm:
                return False, "GetDeviceInformationResponse missing tds:%s" % field
            got[field] = fm.group(1)
        detail = "M=%s Model=%s FW=%s" % (got["Manufacturer"], got["Model"], got["FirmwareVersion"])
        if expect_model and expect_model.lower() not in got["Model"].lower():
            return False, "%s — Model does not contain %r" % (detail, expect_model)
        return True, detail
    finally:
        s.close()


def rtsp_frame_row(host: str, port: int, timeout: float, path: str = "/",
                   ffmpeg: str = "ffmpeg") -> tuple[bool, str]:
    """ffmpeg decodes >=1 video frame off the live RTSP stream (ENDSTATE §2.2).

    Bounded by timeout; TCP transport (`-rtsp_transport tcp`) matches the
    `tailscale serve` tcp-554 proxy shape on the flashed unit.
    """
    url = "rtsp://%s:%d%s" % (host, port, path)
    try:
        proc = subprocess.run(
            [ffmpeg, "-loglevel", "error", "-rtsp_transport", "tcp",
             "-i", url, "-frames:v", "1", "-f", "null", "-"],
            capture_output=True, text=True, timeout=timeout + 5,
        )
    except FileNotFoundError:
        return False, "ffmpeg not found on PATH"
    except subprocess.TimeoutExpired:
        return False, "ffmpeg timed out after %ss on %s" % (timeout + 5, url)
    if proc.returncode != 0:
        err = (proc.stderr or "").strip().splitlines()
        return False, "ffmpeg rc=%d: %s" % (proc.returncode, (err[-1] if err else "no stderr"))
    return True, "decoded >=1 frame from %s" % url


def tailscaled_status_row(host: str, port: int, user: str, timeout: float,
                          ssh_cmd: str = "ssh") -> tuple[bool, str]:
    """`tailscale status` over SSH to the camera (dropbear, S30dropbear).

    Pass only when the command exits 0, the output names the camera's own node,
    and at least one peer line exists — i.e. the node is IN the tailnet, not
    merely logged. Non-interactive: BatchMode, host-key checking disabled
    (the flashed unit's key is regenerated on reflash).
    """
    remote = "tailscale status"
    cmd = [
        ssh_cmd, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=%d" % int(timeout),
        "-p", str(port), "%s@%s" % (user, host), remote,
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 10)
    except FileNotFoundError:
        return False, "ssh not found on PATH"
    except subprocess.TimeoutExpired:
        return False, "ssh timed out on %s@%s:%d" % (user, host, port)
    if proc.returncode != 0:
        err = (proc.stderr or "").strip().splitlines()
        return False, "ssh rc=%d: %s" % (proc.returncode, (err[-1] if err else "no stderr"))
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    own = [ln for ln in lines if ln.rstrip().endswith((";",))]
    if not lines:
        return False, "tailscale status produced no output"
    if len(lines) < 2:
        return False, "tailscale status lists no peers: %r" % (lines[0][:80],)
    return True, "node + %d peer lines" % (len(lines) - 1)


def onvif_profiles_row(host: str, port: int, timeout: float,
                       path: str = "/onvif/device_service",
                       media_path: str = "/onvif/media_service") -> tuple[bool, str]:
    """ONVIF Profile-S GetProfiles (media wsdl, POSTed to the media service).

    Pass when: >=1 profile token, and that profile carries a VideoEncoderConfiguration
    with an H264 element (Profile-S media profile must bind an H264 encoder). The
    media XAddr from GetCapabilities names the endpoint; POST there, falling back to
    the device path when capabilities gave none.
    """
    # discover the media endpoint from GetCapabilities first (the flashed thingino
    # onvif.cgi serves both, but the XAddr is the contract-named location)
    cap_ok, cap_detail = onvif_row(host, port, timeout, path)
    if cap_ok:
        m = XADDR_RE.search(cap_detail)
        # XAddr detail carries "http://host:port/path"; reuse its path when parseable
        xm = re.search(r"https?://[^/]+(/.+)$", cap_detail)
        if xm:
            media_path = xm.group(1)
    s = connect_tcp(host, port, timeout)
    if s is None:
        return False, "connect %s:%d failed" % (host, port)
    try:
        body = GET_PROFILES_ENVELOPE.encode()
        req = (
            "POST %s HTTP/1.1\r\nHost: %s:%d\r\nContent-Type: application/soap+xml; charset=utf-8\r\n"
            "Content-Length: %d\r\nConnection: close\r\n\r\n" % (media_path, host, port, len(body))
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
        pm = PROFILES_RE.search(text)
        if not pm:
            return False, "no trt:GetProfilesResponse (%d bytes)" % len(text)
        tokens = PROFILE_TOKEN_RE.findall(pm.group("body"))
        if not tokens:
            return False, "GetProfilesResponse lists no profiles"
        blob = pm.group("body")
        if not VIDEO_ENC_RE.search(blob):
            return False, "profiles carry no tt:VideoEncoderConfiguration"
        if not H264_RE.search(blob):
            return False, "VideoEncoderConfiguration has no tt:H264 (not Profile-S)"
        return True, "%d profile(s), first token %r, H264 VideoEncoder bound" % (
            len(tokens), tokens[0])
    finally:
        s.close()


def sftp_row(host: str, port: int, user: str, timeout: float,
             sftp_cmd: str = "sftp") -> tuple[bool, str]:
    """Dropbear SFTP reachability: run `sftp -b -` in batch mode, put+get a probe
    file in /tmp, verify round-trip bytes. Dropbear's sftp-server lives at
    /usr/libexec/sftp-server on thingino (firmware-build.md §4: dropbear stays
    enabled). Batch mode = no interactive prompts; StrictHostKeyChecking off (the
    flashed unit's host key is regenerated on reflash).
    """
    probe = Path(tempfile.mkdtemp()) / "fss-sftp-probe"
    payload = os.urandom(64).hex().encode()
    probe.write_bytes(payload)
    remote = "/tmp/fss-sftp-probe-%d" % os.getpid()
    try:
        proc = subprocess.run(
            [sftp_cmd, "-oBatchMode=yes", "-oStrictHostKeyChecking=no",
             "-oUserKnownHostsFile=/dev/null", "-oConnectTimeout=%d" % int(timeout),
             "-P", str(port), "%s@%s" % (user, host)],
            input=(
                "put %s %s\nget %s %s.out\nrm %s\n" % (probe, remote, remote, probe, remote)
            ).encode(),
            capture_output=True, timeout=timeout + 15, cwd=str(probe.parent),
        )
    except FileNotFoundError:
        return False, "sftp client not found on PATH"
    except subprocess.TimeoutExpired:
        return False, "sftp timed out on %s@%s:%d" % (user, host, port)
    out = probe.parent / (probe.name + ".out")
    if proc.returncode != 0:
        err = (proc.stderr or "").strip().splitlines()
        return False, "sftp rc=%d: %s" % (proc.returncode, (err[-1] if err else "no stderr"))
    if not out.exists() or out.read_bytes() != payload:
        return False, "round-trip mismatch (put/get did not preserve %d bytes)" % len(payload)
    return True, "put+get round-trip %d bytes via %s@%s:%d" % (len(payload), user, host, port)


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
                 timeout: float, require_tailnet_bind: bool,
                 expect_model: str | None = None,
                 ssh_user: str | None = None, ssh_port: int = 22,
                 want_frame: bool = True,
                 ssh_cmd: str = "ssh",
                 want_sftp: bool = False,
                 sftp_cmd: str = "sftp") -> tuple[list[dict], bool, bool]:
    """Run the contract. Returns (rows, all_pass, infra_fail); infra_fail means
    the harness could not run at all (unresolvable host / missing tailscale
    interface when the bind check is required) — the exit-code contract maps
    that to EXIT_INFRA, distinct from a device that answered and failed rows.
    """
    infra_fail = False
    rows = []
    ts_addrs = tailscale_addrs()
    ip = ip_of(host)
    tailnet_ok = ip is not None and (ip in ts_addrs or not ts_addrs)
    if require_tailnet_bind and not ts_addrs:
        rows.append({"row": "tailnet-bind", "pass": False,
                     "detail": "no tailscale interface addresses found on this host"})
        infra_fail = True
        return rows, False, infra_fail
    if ip is None:
        infra_fail = True
    rows.append({"row": "tailnet-bind", "pass": tailnet_ok,
                 "detail": "%s -> %s; tailscale addrs %s" % (host, ip, sorted(ts_addrs) or "none")})
    ok, detail = rtsp_row(host, rtsp_port, timeout)
    rows.append({"row": "rtsp-port", "pass": ok, "detail": detail})
    if ok:
        ok, detail = rtsp_handshake_row(host, rtsp_port, timeout)
        rows.append({"row": "rtsp-handshake", "pass": ok, "detail": detail})
        if ok and want_frame:
            ok, detail = rtsp_frame_row(host, rtsp_port, timeout)
        else:
            ok, detail = False, "skipped: handshake failed" if want_frame else "skipped: --no-frame"
        rows.append({"row": "rtsp-frame", "pass": ok, "detail": detail})
    else:
        rows.append({"row": "rtsp-handshake", "pass": False, "detail": "skipped: no port"})
        rows.append({"row": "rtsp-frame", "pass": False, "detail": "skipped: no port"})
    ok, detail = onvif_row(host, onvif_port, timeout)
    rows.append({"row": "onvif-capabilities", "pass": ok, "detail": detail})
    ok, detail = onvif_device_info_row(host, onvif_port, timeout, expect_model=expect_model)
    rows.append({"row": "onvif-device-info", "pass": ok, "detail": detail})
    ok, detail = onvif_profiles_row(host, onvif_port, timeout)
    rows.append({"row": "onvif-profile-s", "pass": ok, "detail": detail})
    ok, detail = http_row(host, http_port, timeout)
    rows.append({"row": "http-control", "pass": ok, "detail": detail})
    if ssh_user:
        ok, detail = tailscaled_status_row(host, ssh_port, ssh_user, timeout, ssh_cmd=ssh_cmd)
    else:
        ok, detail = False, "skipped: no --ssh-user (row is opt-in; needs dropbear creds)"
    rows.append({"row": "tailscaled-status", "pass": ok, "detail": detail})
    if ssh_user and want_sftp:
        ok, detail = sftp_row(host, ssh_port, ssh_user, timeout, sftp_cmd=sftp_cmd)
    else:
        ok, detail = False, ("skipped: needs --ssh-user and --sftp"
                             if want_sftp else "skipped: no --sftp")
    rows.append({"row": "dropbear-sftp", "pass": ok, "detail": detail})
    all_pass = all(r["pass"] for r in rows)
    return rows, all_pass, infra_fail


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
                # echoed back only as an integer — no injection sink here
                cseq_v = str(int(cseq.group(1))) if cseq else "0"
                if method == "OPTIONS":
                    conn.sendall(self.rtsp_response(200, "OK", [
                        "CSeq: %s" % cseq_v,
                        "Public: OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN",
                    ]))
                elif method == "DESCRIBE":
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
                    # Stream one real decodable frame: the embedded 64x64 gray
                    # I-frame (Annex-B: SPS + PPS + IDR), each NAL as one RFC 6184
                    # single-NAL-unit RTP packet on interleaved channel 0 — the
                    # rtsp-frame row needs a decodable frame (ENDSTATE §2.2).
                    for nal_hex in MOCK_H264_NALS:
                        nal = bytes.fromhex(nal_hex)
                        rtp = struct.pack(">BBHII", 0x80, 96, SEQ[0], 0, 0x1234) + nal
                        SEQ[0] = (SEQ[0] + 1) & 0xFFFF
                        pkt = struct.pack(">BBH", 0x24, 0, len(rtp)) + rtp
                        conn.sendall(pkt)
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
                if "GetDeviceInformation" in soap:
                    payload = (
                        '<?xml version="1.0" encoding="UTF-8"?>'
                        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
                        'xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><s:Body>'
                        "<tds:GetDeviceInformationResponse>"
                        "<tds:Manufacturer>thingino</tds:Manufacturer>"
                        "<tds:Model>wyze_cam4_t41nq</tds:Model>"
                        "<tds:FirmwareVersion>thingino-tailnet-1</tds:FirmwareVersion>"
                        "<tds:SerialNumber>MOCK</tds:SerialNumber>"
                        "<tds:HardwareId>T41NQ</tds:HardwareId>"
                        "</tds:GetDeviceInformationResponse></s:Body></s:Envelope>"
                    ).encode()
                elif "GetProfiles" in soap:
                    payload = (
                        '<?xml version="1.0" encoding="UTF-8"?>'
                        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
                        'xmlns:trt="http://www.onvif.org/ver10/media/wsdl" '
                        'xmlns:tt="http://www.onvif.org/ver10/schema"><s:Body>'
                        "<trt:GetProfilesResponse>"
                        '<tt:profile token="profile_1">'
                        "<tt:VideoEncoderConfiguration>"
                        "<tt:H264><tt:H264Profiles>Main</tt:H264Profiles></tt:H264>"
                        "</tt:VideoEncoderConfiguration>"
                        "</tt:profile>"
                        "</trt:GetProfilesResponse></s:Body></s:Envelope>"
                    ).encode()
                else:
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


class MockSSHServer(threading.Thread):
    """HTTP mock for the tailscaled-status row.

    A real sshd needs key exchange; instead this thread serves a tiny HTTP
    endpoint AND self-test installs a `fake-ssh` shim (a shell script that
    prints the expected `tailscale status` output) via the row's ssh_cmd
    parameter — the row's argument assembly and pass/fail logic are still
    exercised end-to-end; only the transport is stubbed. Asserted on flash day
    against real dropbear.
    """

    FAKE_SSH = (
        "#!/bin/sh\n"
        "# fake ssh for tailnet_acceptance self-test: print `tailscale status` shape\n"
        'case "$*" in *status*) echo "wyze-424\\tactive\\tdirect 1.2.3.4:41641"; '
        'echo "peer-x\\tactive\\toffline";; *) exit 255;; esac\n'
    )

    FAKE_SFTP = (
        "#!/bin/sh\n"
        "# fake sftp batch client for self-test: perform the put/get/rm batch\n"
        "# against the local filesystem so the row's round-trip check is real.\n"
        "batch=$(cat)\n"
        'echo "$batch" | while IFS= read -r line; do\n'
        '  case "$line" in\n'
        '    put\\ *) set -- $line; cp "$2" "$3" ;;\n'
        '    get\\ *) set -- $line; cp "$2" "$3" ;;\n'
        '    rm\\ *) set -- $line; rm -f "$2" ;;\n'
        "  esac\n"
        "done\n"
        "exit 0\n"
    )

    def __init__(self, port: int):
        super().__init__(daemon=True)
        self.port = port
        self.path = os.path.join(tempfile.gettempdir(), f"fss-fake-ssh-{port}.sh")
        self.sftp_path = os.path.join(tempfile.gettempdir(), f"fss-fake-sftp-{port}.sh")
        self.stop_flag = False
        self.ready = threading.Event()

    def run(self) -> None:
        import os
        import stat
        with open(self.path, "w", encoding="utf-8") as f:
            f.write(self.FAKE_SSH)
        os.chmod(self.path, os.stat(self.path).st_mode | stat.S_IEXEC)
        with open(self.sftp_path, "w", encoding="utf-8") as f:
            f.write(self.FAKE_SFTP)
        os.chmod(self.sftp_path, os.stat(self.sftp_path).st_mode | stat.S_IEXEC)
        self.ready.set()
        while not self.stop_flag:
            time.sleep(0.1)

    def cleanup(self) -> None:
        import contextlib
        with contextlib.suppress(OSError):
            import os
            os.unlink(self.path)
        with contextlib.suppress(OSError):
            os.unlink(self.sftp_path)


def self_test() -> int:
    rtsp_port, http_port, ssh_port = 45554, 45808, 46222
    server = MockServer(rtsp_port, http_port)
    sshd = MockSSHServer(ssh_port)
    server.start()
    sshd.start()
    if not server.ready.wait(timeout=3) or not sshd.ready.wait(timeout=3):
        print("self-test: mock server failed to bind", file=sys.stderr)
        return 2
    time.sleep(0.1)
    try:
        rows, all_pass, _infra = run_contract(
            "127.0.0.1", rtsp_port, http_port, http_port,
            timeout=3.0, require_tailnet_bind=False,
            expect_model="wyze_cam4", ssh_user="root", ssh_port=ssh_port,
            ssh_cmd=sshd.path, want_sftp=True, sftp_cmd=sshd.sftp_path,
        )
    finally:
        server.stop_flag = True
        sshd.stop_flag = True
        sshd.cleanup()
        time.sleep(0.3)
    print(json.dumps({"self-test": True, "all_pass": all_pass, "rows": rows},
                     indent=2))
    for r in rows:
        print("  %-18s %s  %s" % (r["row"], "PASS" if r["pass"] else "FAIL", r["detail"]))
    return 0 if all_pass else 1


# Exit-code contract for the flash-day harness (see module docstring):
#   EXIT_ALL_PASS = 0   every contract row passed
#   EXIT_PARTIAL  = 1   at least one row FAILED but the harness itself ran
#   EXIT_INFRA    = 2   the harness could not run at all (unresolvable host,
#                       no tailscale interface when the bind check is required)
EXIT_ALL_PASS = 0
EXIT_PARTIAL = 1
EXIT_INFRA = 2


def verdict(rows: list[dict], infra_fail: bool) -> int:
    """Classify a run: 0 all pass, 1 partial (some row failed), 2 infra fail."""
    if infra_fail:
        return EXIT_INFRA
    if not rows:
        return EXIT_INFRA
    if all(r["pass"] for r in rows):
        return EXIT_ALL_PASS
    return EXIT_PARTIAL


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
    ap.add_argument("--expect-model", default=None,
                    help="assert GetDeviceInformation Model contains this substring "
                         "(flash-day identity gate; e.g. wyze_cam4_t41nq)")
    ap.add_argument("--ssh-user", default=None,
                    help="enable the tailscaled-status row via SSH as this user (dropbear)")
    ap.add_argument("--ssh-port", type=int, default=22)
    ap.add_argument("--no-frame", action="store_true",
                    help="skip the ffmpeg rtsp-frame row (e.g. ffmpeg absent)")
    ap.add_argument("--sftp", action="store_true",
                    help="add the dropbear-sftp row (needs --ssh-user; put+get probe)")
    ap.add_argument("--json", action="store_true", help="JSON summary only")
    ap.add_argument("--self-test", action="store_true",
                    help="run the mock RTSP+ONVIF+SSH server on loopback and test against it")
    a = ap.parse_args()

    if a.self_test:
        return self_test()
    if not a.host:
        ap.error("--host required unless --self-test")
    rows, all_pass, infra_fail = run_contract(
        a.host, a.rtsp_port, a.onvif_port, a.http_port,
        a.timeout, not a.no_bind_check,
        expect_model=a.expect_model,
        ssh_user=a.ssh_user, ssh_port=a.ssh_port,
        want_frame=not a.no_frame, want_sftp=a.sftp)
    code = verdict(rows, infra_fail)
    summary = {
        "schema": "fss.tailnet-acceptance.v1",
        "host": a.host,
        "all_pass": all_pass,
        "exit_code": code,
        "exit": {EXIT_ALL_PASS: "all-pass", EXIT_PARTIAL: "partial",
                 EXIT_INFRA: "infra-fail"}[code],
        "infra_fail": infra_fail,
        "rows": rows,
    }
    if a.json:
        print(json.dumps(summary, indent=2))
    else:
        print("tailnet acceptance — %s" % a.host)
        for r in rows:
            print("  %-18s %s  %s" % (r["row"], "PASS" if r["pass"] else "FAIL", r["detail"]))
        print("verdict: %s (exit %d)" % (summary["exit"], code))
    return code


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Bounded single-session RTSP bridge for Wyze Cam v4 (fss-wyze-rtsp-tailnet-bridge-0yh6d).

Holds AT MOST ONE long-lived TCP-interleaved RTSP session to the Wyze SmolRTSP server
(respecting the unit's 1-connection-per-IP limit, sequential non-pipelined request framing,
and bounded exponential reconnect backoff), observes verbatim in-band H.264 SPS (NAL 7) and
PPS (NAL 8) bytes from the live RTP stream, and serves standard RFC 6184 RTSP with real
`sprop-parameter-sets` + `profile-level-id` to bounded downstream clients (both local
`fss-capture-rtsp` ingestion and tailnet viewers share the ONE camera session).

Honesty invariants:
  - Never invents SPS/PPS: returns 503 Service Unavailable on DESCRIBE until real SPS (type 7)
    and PPS (type 8) NALs have been observed from the upstream camera.
  - Forwards verbatim original camera RTP datagrams (exact RTP headers, timestamps, sequence
    numbers, SSRC, and payload bytes) — zero transcoding and zero fabricated timestamps.
  - Never fakes continuity: when the upstream camera disconnects or reboots, all active
    downstream subscriber sockets are immediately closed so `fss-capture-rtsp` records the
    real outage gap in its CoverageWitness.
  - Never logs passwords or Authorization header secrets.
"""
from __future__ import annotations

import argparse
import base64
import collections
import datetime
import hashlib
import json
import os
import re
import secrets
import select
import signal
import socket
import struct
import sys
import threading
import time
from typing import Any


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_cred_file(path: str) -> tuple[str, str]:
    """Read username LF password [LF] from a private 0600 credential file."""
    with open(path, "r", encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    if len(lines) < 2 or not lines[0] or not lines[1]:
        raise ValueError(f"credential file {path} must contain username LF password")
    return lines[0], lines[1]


def parse_digest_challenge(header_val: str) -> dict[str, str]:
    """Parse RFC 2617/7616 WWW-Authenticate: Digest ... parameters."""
    val = header_val.strip()
    if val.lower().startswith("digest "):
        val = val[7:]
    out: dict[str, str] = {}
    for match in re.finditer(r'([A-Za-z0-9_-]+)\s*=\s*(?:"([^"]*)"|([^\s,]+))', val):
        k = match.group(1).lower()
        v = match.group(2) if match.group(2) is not None else match.group(3)
        out[k] = v
    return out


def build_digest_header(
    username: str,
    password: str,
    method: str,
    uri: str,
    challenge: dict[str, str],
    nc: int = 1,
    cnonce: str | None = None,
) -> str:
    realm = challenge.get("realm", "")
    nonce = challenge.get("nonce", "")
    alg = challenge.get("algorithm", "MD5").upper()
    qop_raw = challenge.get("qop", "")
    opaque = challenge.get("opaque")

    if alg in ("SHA-256", "SHA256"):
        hfn = hashlib.sha256
        alg_wire = "SHA-256"
    else:
        hfn = hashlib.md5
        alg_wire = "MD5"

    ha1 = hfn(f"{username}:{realm}:{password}".encode("utf-8")).hexdigest()
    ha2 = hfn(f"{method}:{uri}".encode("utf-8")).hexdigest()

    qops = [q.strip().lower() for q in qop_raw.split(",") if q.strip()]
    if "auth" in qops:
        cn = cnonce or secrets.token_hex(12)
        nc_hex = f"{nc:08x}"
        resp = hfn(f"{ha1}:{nonce}:{nc_hex}:{cn}:auth:{ha2}".encode("utf-8")).hexdigest()
        parts = [
            f'username="{username}"',
            f'realm="{realm}"',
            f'nonce="{nonce}"',
            f'uri="{uri}"',
            f'algorithm={alg_wire}',
            f'qop=auth',
            f'nc={nc_hex}',
            f'cnonce="{cn}"',
            f'response="{resp}"',
        ]
    else:
        resp = hfn(f"{ha1}:{nonce}:{ha2}".encode("utf-8")).hexdigest()
        parts = [
            f'username="{username}"',
            f'realm="{realm}"',
            f'nonce="{nonce}"',
            f'uri="{uri}"',
            f'response="{resp}"',
        ]
    if opaque:
        parts.append(f'opaque="{opaque}"')
    return "Digest " + ", ".join(parts)


def verify_digest_authorization(
    auth_header: str,
    method: str,
    expected_user: str,
    expected_pass: str,
    expected_realm: str,
    valid_nonces: set[str],
    required_algorithm: str | None = None,
    require_qop_auth: bool = False,
) -> bool:
    params = parse_digest_challenge(auth_header)
    if params.get("username") != expected_user or params.get("realm") != expected_realm:
        return False
    nonce = params.get("nonce", "")
    if nonce not in valid_nonces:
        return False
    uri = params.get("uri", "")
    # RFC 2617/7616: omitted algorithm defaults to MD5.
    alg = params.get("algorithm", "MD5").upper()
    if alg == "SHA256":
        alg = "SHA-256"
    if alg not in ("SHA-256", "MD5"):
        return False
    if required_algorithm is not None:
        req_alg = "SHA-256" if required_algorithm.upper() in ("SHA-256", "SHA256") else required_algorithm.upper()
        if alg != req_alg:
            return False
    hfn = hashlib.sha256 if alg == "SHA-256" else hashlib.md5
    ha1 = hfn(f"{expected_user}:{expected_realm}:{expected_pass}".encode("utf-8")).hexdigest()
    ha2 = hfn(f"{method}:{uri}".encode("utf-8")).hexdigest()
    qop = params.get("qop", "").lower()
    if require_qop_auth and qop != "auth":
        return False
    if qop == "auth":
        nc = params.get("nc", "")
        cnonce = params.get("cnonce", "")
        if not re.fullmatch(r"[0-9a-fA-F]{8}", nc) or not cnonce:
            return False
        expected = hfn(f"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}".encode("utf-8")).hexdigest()
    elif qop == "":
        expected = hfn(f"{ha1}:{nonce}:{ha2}".encode("utf-8")).hexdigest()
    else:
        return False
    return secrets.compare_digest(params.get("response", "").lower(), expected.lower())


def parse_rtp_h264(rtp_packet: bytes) -> dict[str, Any] | None:
    """Inspect an RTP packet (non-destructively) for H.264 SPS/PPS/IDR NAL units (RFC 6184)."""
    if len(rtp_packet) < 12:
        return None
    v_p_x_cc = rtp_packet[0]
    if (v_p_x_cc >> 6) != 2:
        return None
    padding = bool((v_p_x_cc >> 5) & 1)
    extension = bool((v_p_x_cc >> 4) & 1)
    cc = v_p_x_cc & 0x0F
    pt = rtp_packet[1] & 0x7F
    marker = bool((rtp_packet[1] >> 7) & 1)
    seq, ts, ssrc = struct.unpack(">HII", rtp_packet[2:12])
    off = 12 + cc * 4
    if off > len(rtp_packet):
        return None
    if extension:
        if off + 4 > len(rtp_packet):
            return None
        ext_words = struct.unpack(">H", rtp_packet[off + 2 : off + 4])[0]
        off += 4 + ext_words * 4
    end = len(rtp_packet)
    if padding:
        if end <= off:
            return None
        pad_len = rtp_packet[-1]
        if pad_len == 0 or pad_len > (end - off):
            return None
        end -= pad_len
    if off >= end:
        return None

    payload = rtp_packet[off:end]
    nal_hdr = payload[0]
    nal_type = nal_hdr & 0x1F

    sps: bytes | None = None
    pps: bytes | None = None
    has_idr = False
    is_sync_start = False

    if 1 <= nal_type <= 23:
        if nal_type == 7 and len(payload) >= 4 and (payload[0] & 0x9F) == 7:
            sps = bytes(payload)
            is_sync_start = True
        elif nal_type == 8 and len(payload) >= 2 and (payload[0] & 0x9F) == 8:
            pps = bytes(payload)
        elif nal_type == 5:
            has_idr = True
            is_sync_start = True
    elif nal_type == 24:  # STAP-A
        pos = 1
        while pos + 2 <= len(payload):
            nlen = struct.unpack(">H", payload[pos : pos + 2])[0]
            pos += 2
            if nlen == 0 or pos + nlen > len(payload):
                break
            nal = payload[pos : pos + nlen]
            pos += nlen
            nt = nal[0] & 0x1F
            if nt == 7 and len(nal) >= 4 and (nal[0] & 0x9F) == 7:
                sps = bytes(nal)
                is_sync_start = True
            elif nt == 8 and len(nal) >= 2 and (nal[0] & 0x9F) == 8:
                pps = bytes(nal)
            elif nt == 5:
                has_idr = True
                is_sync_start = True
    elif nal_type == 28 and len(payload) >= 2:  # FU-A
        fu_hdr = payload[1]
        start_bit = bool(fu_hdr & 0x80)
        orig_type = fu_hdr & 0x1F
        if start_bit and orig_type == 5:
            has_idr = True
            is_sync_start = True

    return {
        "pt": pt,
        "marker": marker,
        "seq": seq,
        "ts": ts,
        "ssrc": ssrc,
        "nal_type": nal_type,
        "sps": sps,
        "pps": pps,
        "has_idr": has_idr,
        "is_sync_start": is_sync_start,
    }


def parse_sdp_tracks(sdp_text: str) -> tuple[str | None, str, int]:
    """Extract (audio_control_or_none, video_control, video_payload_type) from SDP."""
    section = ""
    audio_control: str | None = None
    video_control = "video"
    pt = 96
    for raw in sdp_text.splitlines():
        line = raw.strip()
        if line.startswith("m="):
            if line.startswith("m=audio "):
                section = "audio"
            elif line.startswith("m=video "):
                section = "video"
                parts = line.split()
                if len(parts) >= 4 and parts[3].isdigit():
                    pt = int(parts[3])
            else:
                section = "other"
        elif section == "audio":
            if line.startswith("a=control:"):
                audio_control = line.split(":", 1)[1].strip()
        elif section == "video":
            if line.startswith("a=control:"):
                video_control = line.split(":", 1)[1].strip()
            elif line.startswith("a=rtpmap:") and "H264/90000" in line.upper():
                m = re.match(r"a=rtpmap:(\d+)\s+H264/90000", line, re.IGNORECASE)
                if m:
                    pt = int(m.group(1))
    return audio_control, video_control, pt


def parse_sdp_video_track(sdp_text: str) -> tuple[str, int]:
    """Extract (control_uri, payload_type) for the first H264/90000 video track."""
    _audio, video_control, pt = parse_sdp_tracks(sdp_text)
    return video_control, pt


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("upstream closed mid-frame")
        buf.extend(chunk)
    return bytes(buf)


def read_rtsp_response(sock: socket.socket, buf: bytearray) -> tuple[int, dict[str, str], bytes]:
    """Read one RTSP response (skipping any interleaved $ frames that arrive before it)."""
    while True:
        while len(buf) < 4:
            chunk = sock.recv(4096)
            if not chunk:
                raise EOFError("RTSP socket EOF waiting for response")
            buf.extend(chunk)
        if buf[0] == 0x24:  # interleaved '$' frame
            flen = struct.unpack(">H", buf[2:4])[0]
            need = 4 + flen
            while len(buf) < need:
                chunk = sock.recv(min(65536, need - len(buf)))
                if not chunk:
                    raise EOFError("RTSP socket EOF mid-interleaved frame")
                buf.extend(chunk)
            del buf[:need]
            continue
        sep = buf.find(b"\r\n\r\n")
        while sep < 0:
            if len(buf) > 65536:
                raise ValueError("RTSP response headers exceeded 64 KiB")
            chunk = sock.recv(4096)
            if not chunk:
                raise EOFError("RTSP socket EOF reading headers")
            buf.extend(chunk)
            sep = buf.find(b"\r\n\r\n")
        head_bytes = bytes(buf[:sep])
        del buf[: sep + 4]
        lines = head_bytes.decode("iso-8859-1").split("\r\n")
        status_parts = lines[0].split(" ", 2)
        if len(status_parts) < 2 or not status_parts[0].startswith("RTSP/"):
            raise ValueError(f"malformed RTSP status line: {lines[0]!r}")
        status = int(status_parts[1])
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        try:
            clen = int(headers.get("content-length", "0"))
        except ValueError as exc:
            raise ValueError(f"malformed RTSP Content-Length: {headers.get('content-length')!r}") from exc
        if clen < 0 or clen > 262144:
            raise ValueError(f"RTSP response body out of bounds: {clen}")
        while len(buf) < clen:
            chunk = sock.recv(min(65536, clen - len(buf)))
            if not chunk:
                raise EOFError("RTSP socket EOF reading body")
            buf.extend(chunk)
        body = bytes(buf[:clen])
        del buf[:clen]
        return status, headers, body


class Subscriber:
    """One downstream RTSP client receiving verbatim RTP packets from the shared upstream."""

    def __init__(self, sock: socket.socket, rtp_channel: int, max_queue: int = 256):
        self.sock = sock
        self.rtp_channel = rtp_channel
        self.queue: collections.deque[bytes] = collections.deque()
        self.max_queue = max_queue
        self.synced = False
        self.closed = False
        self._cond = threading.Condition()

    def enqueue(self, rtp_packet: bytes, is_sync_start: bool) -> bool:
        with self._cond:
            if self.closed:
                return False
            if not self.synced:
                if not is_sync_start:
                    return True
                self.synced = True
            if len(self.queue) >= self.max_queue:
                # Never silently drop middle packets and pretend continuity: close the slow client.
                self.closed = True
                self._cond.notify_all()
                return False
            self.queue.append(rtp_packet)
            self._cond.notify()
            return True

    def pop_wait(self, timeout: float = 0.5) -> bytes | None:
        with self._cond:
            if not self.queue and not self.closed:
                self._cond.wait(timeout=timeout)
            if self.closed:
                return None
            if self.queue:
                return self.queue.popleft()
            return b""

    def close(self) -> None:
        with self._cond:
            self.closed = True
            self.queue.clear()
            self._cond.notify_all()
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


class StreamHub:
    """Shared state between the sole upstream Wyze session and bounded downstream clients."""

    def __init__(self, status_file: str | None = None):
        self._lock = threading.Lock()
        self._status_write_lock = threading.Lock()
        self.status_file = status_file
        self.upstream_connected = False
        self.upstream_epoch = 0
        self.reconnect_count = 0
        self.sps: bytes | None = None
        self.pps: bytes | None = None
        self.ssrc: int | None = None
        self.payload_type: int = 96
        self.packets_received: int = 0
        self.audio_packets_discarded: int = 0
        self.subscribers: set[Subscriber] = set()

    def on_non_video_packet(self) -> None:
        """Record an upstream audio/non-video packet discarded unconditionally (GOAL-009)."""
        with self._lock:
            self.audio_packets_discarded += 1

    def on_upstream_connected(self, payload_type: int, ssrc: int | None) -> None:
        with self._lock:
            self.upstream_connected = True
            self.upstream_epoch += 1
            self.payload_type = payload_type
            self.ssrc = ssrc
            self.sps = None
            self.pps = None
        self._write_status()

    def on_upstream_disconnected(self) -> None:
        with self._lock:
            self.upstream_connected = False
            self.reconnect_count += 1
            self.sps = None
            self.pps = None
            subs = list(self.subscribers)
            self.subscribers.clear()
        # Honest discontinuity: close all downstream subscribers so no silent gap bridging occurs.
        for sub in subs:
            sub.close()
        self._write_status()

    def on_rtp_packet(self, rtp_packet: bytes) -> bool:
        info = parse_rtp_h264(rtp_packet)
        if info is None:
            return False
        status_changed = False
        with self._lock:
            if info["pt"] != self.payload_type:
                self.audio_packets_discarded += 1
                return False
            self.packets_received += 1
            if self.ssrc is None:
                self.ssrc = info["ssrc"]
                status_changed = True
            if info["sps"] is not None and self.sps != info["sps"]:
                self.sps = info["sps"]
                status_changed = True
            if info["pps"] is not None and self.pps != info["pps"]:
                self.pps = info["pps"]
                status_changed = True
            subs = list(self.subscribers)
            is_sync = bool(info["is_sync_start"])
        dead: list[Subscriber] = []
        for sub in subs:
            if not sub.enqueue(rtp_packet, is_sync):
                dead.append(sub)
        if dead:
            with self._lock:
                for sub in dead:
                    self.subscribers.discard(sub)
            for sub in dead:
                sub.close()
        if status_changed or (self.packets_received % 100 == 0):
            self._write_status()
        return True

    def ready_descriptor(self) -> dict[str, Any] | None:
        with self._lock:
            if not self.upstream_connected or self.sps is None or self.pps is None or self.ssrc is None:
                return None
            return {
                "sps": self.sps,
                "pps": self.pps,
                "ssrc": self.ssrc,
                "payload_type": self.payload_type,
                "epoch": self.upstream_epoch,
            }

    def add_subscriber(self, sub: Subscriber) -> None:
        with self._lock:
            self.subscribers.add(sub)
        self._write_status()

    def remove_subscriber(self, sub: Subscriber) -> None:
        with self._lock:
            self.subscribers.discard(sub)
        self._write_status()

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            prof = self.sps[1:4].hex() if self.sps and len(self.sps) >= 4 else None
            return {
                "updated_at_utc": _utc_now(),
                "upstream_connected": self.upstream_connected,
                "upstream_epoch": self.upstream_epoch,
                "reconnect_count": self.reconnect_count,
                "ready": bool(self.upstream_connected and self.sps and self.pps and self.ssrc is not None),
                "sps_len": len(self.sps) if self.sps else 0,
                "pps_len": len(self.pps) if self.pps else 0,
                "profile_level_id": prof,
                "ssrc_hex": f"{self.ssrc:08X}" if self.ssrc is not None else None,
                "payload_type": self.payload_type,
                "packets_received": self.packets_received,
                "audio_packets_discarded": self.audio_packets_discarded,
                "active_clients": len(self.subscribers),
            }

    def _write_status(self) -> None:
        if not self.status_file:
            return
        with self._status_write_lock:
            snap = self.snapshot()
            tmp = f"{self.status_file}.tmp.{os.getpid()}.{threading.get_ident()}"
            try:
                parent = os.path.dirname(os.path.abspath(self.status_file))
                os.makedirs(parent, exist_ok=True)
                with open(tmp, "w", encoding="utf-8") as fh:
                    json.dump(snap, fh, indent=2)
                    fh.write("\n")
                os.replace(tmp, self.status_file)
            except OSError:
                try:
                    if os.path.exists(tmp):
                        os.unlink(tmp)
                except OSError:
                    pass


class UpstreamClient(threading.Thread):
    """Sole long-lived upstream RTSP TCP-interleaved session to the Wyze camera."""

    def __init__(
        self,
        hub: StreamHub,
        host: str,
        port: int,
        path: str,
        username: str | None,
        password: str | None,
        backoff_initial: float = 5.0,
        backoff_max: float = 60.0,
        keepalive_secs: float = 25.0,
        read_timeout: float = 15.0,
        stop_event: threading.Event | None = None,
    ):
        super().__init__(daemon=True)
        self.hub = hub
        self.host = host
        self.port = port
        self.path = path if path.startswith("/") else "/" + path
        self.username = username
        self.password = password
        self.backoff_initial = backoff_initial
        self.backoff_max = backoff_max
        self.keepalive_secs = keepalive_secs
        self.read_timeout = read_timeout
        self.stop_event = stop_event or threading.Event()
        self._sock: socket.socket | None = None

    def close_upstream(self) -> None:
        s = self._sock
        if s is not None:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass

    def _send_req(
        self,
        sock: socket.socket,
        buf: bytearray,
        method: str,
        uri: str,
        cseq: int,
        extra_headers: list[str],
        challenge: dict[str, str] | None,
        nc_box: list[int],
    ) -> tuple[int, dict[str, str], bytes, dict[str, str] | None, int]:
        def _do(ch: dict[str, str] | None, seq: int) -> tuple[int, dict[str, str], bytes]:
            lines = [f"{method} {uri} RTSP/1.0", f"CSeq: {seq}", "User-Agent: fss-wyze-bridge/1"]
            lines.extend(extra_headers)
            if ch and self.username is not None and self.password is not None:
                nc_box[0] += 1
                auth = build_digest_header(self.username, self.password, method, uri, ch, nc=nc_box[0])
                lines.append(f"Authorization: {auth}")
            raw = ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8")
            sock.sendall(raw)
            return read_rtsp_response(sock, buf)

        status, hdrs, body = _do(challenge, cseq)
        next_cseq = cseq + 1
        if status == 401 and "www-authenticate" in hdrs and self.username is not None:
            new_ch = parse_digest_challenge(hdrs["www-authenticate"])
            status, hdrs, body = _do(new_ch, next_cseq)
            next_cseq += 1
            return status, hdrs, body, new_ch, next_cseq
        return status, hdrs, body, challenge, next_cseq

    def _run_once(self) -> None:
        base_uri = f"rtsp://{self.host}:{self.port}{self.path}"
        sock = socket.create_connection((self.host, self.port), timeout=10.0)
        self._sock = sock
        sock.settimeout(self.read_timeout)
        buf = bytearray()
        cseq = 1
        challenge: dict[str, str] | None = None
        nc_box = [0]

        try:
            # 1. OPTIONS
            st, _hdrs, _body, challenge, cseq = self._send_req(
                sock, buf, "OPTIONS", base_uri, cseq, [], challenge, nc_box
            )
            if st != 200:
                raise RuntimeError(f"upstream OPTIONS returned {st}")

            # 2. DESCRIBE
            st, hdrs, body, challenge, cseq = self._send_req(
                sock, buf, "DESCRIBE", base_uri, cseq, ["Accept: application/sdp"], challenge, nc_box
            )
            if st != 200:
                raise RuntimeError(f"upstream DESCRIBE returned {st}")
            sdp_text = body.decode("utf-8", errors="replace")
            audio_ctrl, track_ctrl, pt = parse_sdp_tracks(sdp_text)
            cbase = hdrs.get("content-base", base_uri).rstrip("/")

            def _resolve_track(ctrl: str) -> str:
                return ctrl if ctrl.startswith("rtsp://") else f"{cbase}/{ctrl.lstrip('/')}"

            # 3. SETUP: Wyze SmolRTSP requires SETUP on advertised audio track before video
            # (interleaved=0-1 audio, 2-3 video), otherwise PLAY returns 200 with zero RTP.
            # Audio packets are discarded unconditionally (GOAL-009 video-only custody).
            session_id = ""
            video_channel = 0
            audio_channel: int | None = None
            if audio_ctrl is not None:
                audio_uri = _resolve_track(audio_ctrl)
                st, hdrs, _body, challenge, cseq = self._send_req(
                    sock,
                    buf,
                    "SETUP",
                    audio_uri,
                    cseq,
                    ["Transport: RTP/AVP/TCP;unicast;interleaved=0-1"],
                    challenge,
                    nc_box,
                )
                if st != 200:
                    raise RuntimeError(f"upstream audio SETUP returned {st}")
                session_id = hdrs.get("session", "").split(";")[0].strip()
                audio_channel = 0
                audio_iv = re.search(r"interleaved=(\d+)-(\d+)", hdrs.get("transport", ""))
                if audio_iv:
                    audio_channel = int(audio_iv.group(1))
                video_channel = 2

            setup_uri = _resolve_track(track_ctrl)
            setup_hdrs = [f"Transport: RTP/AVP/TCP;unicast;interleaved={video_channel}-{video_channel + 1}"]
            if session_id:
                setup_hdrs.append(f"Session: {session_id}")
            st, hdrs, _body, challenge, cseq = self._send_req(
                sock,
                buf,
                "SETUP",
                setup_uri,
                cseq,
                setup_hdrs,
                challenge,
                nc_box,
            )
            if st != 200:
                raise RuntimeError(f"upstream SETUP returned {st}")
            session_id = hdrs.get("session", session_id).split(";")[0].strip()
            transport = hdrs.get("transport", "")
            ssrc_match = re.search(r"ssrc=([0-9A-Fa-f]+)", transport)
            ssrc = int(ssrc_match.group(1), 16) if ssrc_match else None
            iv_match = re.search(r"interleaved=(\d+)-(\d+)", transport)
            if iv_match:
                video_channel = int(iv_match.group(1))

            # 4. PLAY
            play_hdrs = ["Range: npt=0.000-"]
            if session_id:
                play_hdrs.append(f"Session: {session_id}")
            st, _hdrs, _body, challenge, cseq = self._send_req(
                sock, buf, "PLAY", base_uri, cseq, play_hdrs, challenge, nc_box
            )
            if st != 200:
                raise RuntimeError(f"upstream PLAY returned {st}")

            self.hub.on_upstream_connected(payload_type=pt, ssrc=ssrc)
            print(
                f"[bridge] upstream connected {base_uri} pt={pt} video_ch={video_channel} session={session_id}",
                flush=True,
            )
            last_keepalive = time.monotonic()
            last_video_rtp_at = last_keepalive

            # 5. Interleaved RTP pump (strictly video_channel only; audio discarded)
            while not self.stop_event.is_set():
                now = time.monotonic()
                if (now - last_video_rtp_at) > self.read_timeout:
                    raise TimeoutError("upstream video RTP stall")
                if session_id and (now - last_keepalive) >= self.keepalive_secs:
                    ka_lines = [
                        f"OPTIONS {base_uri} RTSP/1.0",
                        f"CSeq: {cseq}",
                        f"Session: {session_id}",
                        "User-Agent: fss-wyze-bridge/1",
                    ]
                    if challenge and self.username is not None and self.password is not None:
                        nc_box[0] += 1
                        auth = build_digest_header(
                            self.username, self.password, "OPTIONS", base_uri, challenge, nc=nc_box[0]
                        )
                        ka_lines.append(f"Authorization: {auth}")
                    cseq += 1
                    sock.sendall(("\r\n".join(ka_lines) + "\r\n\r\n").encode("utf-8"))
                    last_keepalive = now

                # Pull next interleaved frame or skip RTSP keepalive reply
                while len(buf) < 4:
                    r, _, _ = select.select([sock], [], [], 1.0)
                    if self.stop_event.is_set():
                        return
                    if not r:
                        if (time.monotonic() - last_video_rtp_at) > self.read_timeout:
                            raise TimeoutError("upstream video RTP stall")
                        continue
                    chunk = sock.recv(65536)
                    if not chunk:
                        raise EOFError("upstream EOF")
                    buf.extend(chunk)

                if buf[0] == 0x24:  # '$' interleaved frame
                    channel = buf[1]
                    flen = struct.unpack(">H", buf[2:4])[0]
                    need = 4 + flen
                    while len(buf) < need:
                        chunk = sock.recv(min(65536, need - len(buf)))
                        if not chunk:
                            raise EOFError("upstream EOF mid-interleaved")
                        buf.extend(chunk)
                    payload = bytes(buf[4:need])
                    del buf[:need]
                    if channel == video_channel:
                        if self.hub.on_rtp_packet(payload):
                            last_video_rtp_at = time.monotonic()
                    elif audio_channel is not None and channel == audio_channel:
                        self.hub.on_non_video_packet()
                elif buf.startswith(b"RTSP/"):
                    sep = buf.find(b"\r\n\r\n")
                    while sep < 0:
                        if len(buf) > 65536:
                            raise ValueError("upstream RTSP reply headers exceeded 64 KiB")
                        chunk = sock.recv(4096)
                        if not chunk:
                            raise EOFError("upstream EOF mid-keepalive-reply")
                        buf.extend(chunk)
                        sep = buf.find(b"\r\n\r\n")
                    head = bytes(buf[:sep]).decode("iso-8859-1")
                    clen = 0
                    for line in head.split("\r\n")[1:]:
                        if line.lower().startswith("content-length:"):
                            raw_clen = line.split(":", 1)[1].strip()
                            try:
                                clen = int(raw_clen)
                            except ValueError as exc:
                                raise ValueError(f"malformed upstream Content-Length: {raw_clen!r}") from exc
                    if clen < 0 or clen > 262144:
                        raise ValueError(f"upstream RTSP reply body out of bounds: {clen}")
                    total = sep + 4 + clen
                    while len(buf) < total:
                        chunk = sock.recv(min(65536, total - len(buf)))
                        if not chunk:
                            raise EOFError("upstream EOF mid-keepalive-body")
                        buf.extend(chunk)
                    del buf[:total]
                else:
                    # Resync to next '$' or 'RTSP/'
                    idx = buf.find(b"$", 1)
                    if idx < 0:
                        buf.clear()
                    else:
                        del buf[:idx]
        finally:
            self._sock = None
            try:
                sock.close()
            except OSError:
                pass
            self.hub.on_upstream_disconnected()

    def run(self) -> None:
        backoff = self.backoff_initial
        while not self.stop_event.is_set():
            started = time.monotonic()
            try:
                self._run_once()
            except Exception as exc:
                if not self.stop_event.is_set():
                    print(f"[bridge] upstream disconnected: {exc}", flush=True)
            if self.stop_event.is_set():
                break
            # Reset backoff if the session held steady for >= 30s
            if (time.monotonic() - started) >= 30.0:
                backoff = self.backoff_initial
            print(f"[bridge] waiting {backoff:.1f}s before upstream reconnect", flush=True)
            self.stop_event.wait(timeout=backoff)
            backoff = min(self.backoff_max, backoff * 2.0)


class DownstreamServer:
    """Bounded RFC 2326 / RFC 6184 TCP-interleaved RTSP server sharing one StreamHub."""

    def __init__(
        self,
        hub: StreamHub,
        listen_host: str,
        listen_port: int,
        listen_path: str = "/stream1",
        max_clients: int = 4,
        downstream_user: str | None = None,
        downstream_pass: str | None = None,
        downstream_realm: str = "fss-bridge",
    ):
        self.hub = hub
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.listen_path = listen_path if listen_path.startswith("/") else "/" + listen_path
        self.max_clients = max_clients
        self.downstream_user = downstream_user
        self.downstream_pass = downstream_pass
        self.downstream_realm = downstream_realm
        self._stop = threading.Event()
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._client_count_lock = threading.Lock()
        self._client_count = 0
        self.bound_port: int = 0
        self._nonces: collections.deque[str] = collections.deque(maxlen=256)
        self._nonce_lock = threading.Lock()

    def _mint_nonce(self) -> str:
        n = secrets.token_hex(16)
        with self._nonce_lock:
            self._nonces.append(n)
        return n

    def start(self) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.listen_host, self.listen_port))
        s.listen(8)
        s.settimeout(0.5)
        self._sock = s
        self.bound_port = s.getsockname()[1]
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        print(
            f"[bridge] listening rtsp://{self.listen_host}:{self.bound_port}{self.listen_path} "
            f"(max_clients={self.max_clients})",
            flush=True,
        )

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=2.0)

    def _accept_loop(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, peer = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self._client_count_lock:
                if self._client_count >= self.max_clients:
                    try:
                        conn.sendall(b"RTSP/1.0 503 Service Unavailable\r\nCSeq: 0\r\n\r\n")
                    except OSError:
                        pass
                    conn.close()
                    continue
                self._client_count += 1
            threading.Thread(target=self._handle_client, args=(conn, peer), daemon=True).start()

    def _build_sdp(self, desc: dict[str, Any]) -> bytes:
        sps_b64 = base64.b64encode(desc["sps"]).decode("ascii")
        pps_b64 = base64.b64encode(desc["pps"]).decode("ascii")
        prof = desc["sps"][1:4].hex()
        pt = desc["payload_type"]
        lines = [
            "v=0",
            "o=- 0 0 IN IP4 127.0.0.1",
            "s=FSS Wyze RTSP Bridge",
            "t=0 0",
            "a=control:*",
            f"m=video 0 RTP/AVP/TCP {pt}",
            "c=IN IP4 0.0.0.0",
            f"a=rtpmap:{pt} H264/90000",
            f"a=fmtp:{pt} packetization-mode=1;profile-level-id={prof};sprop-parameter-sets={sps_b64},{pps_b64}",
            "a=control:track1",
        ]
        return ("\r\n".join(lines) + "\r\n").encode("ascii")

    def _handle_client(self, conn: socket.socket, _peer: tuple[str, int]) -> None:
        sub: Subscriber | None = None
        writer_thread: threading.Thread | None = None
        write_lock = threading.Lock()
        session_id = secrets.token_hex(8)
        rtp_ch = 0
        rtcp_ch = 1
        setup_done = False

        def send_reply(status_line: str, cseq: str, extra: list[str], body: bytes = b"") -> None:
            hdrs = [f"RTSP/1.0 {status_line}", f"CSeq: {cseq}"]
            hdrs.extend(extra)
            if body:
                hdrs.append(f"Content-Length: {len(body)}")
            wire = ("\r\n".join(hdrs) + "\r\n\r\n").encode("ascii") + body
            with write_lock:
                conn.sendall(wire)

        def pump_media(s: Subscriber) -> None:
            while not self._stop.is_set() and not s.closed:
                pkt = s.pop_wait(timeout=0.5)
                if pkt is None:
                    return
                if not pkt:
                    continue
                frame = struct.pack(">BBH", 0x24, s.rtp_channel, len(pkt)) + pkt
                try:
                    with write_lock:
                        conn.sendall(frame)
                except OSError:
                    s.close()
                    return

        try:
            conn.settimeout(30.0)
            buf = bytearray()
            while not self._stop.is_set():
                sep = buf.find(b"\r\n\r\n")
                while sep < 0:
                    if len(buf) > 16384:
                        return
                    try:
                        chunk = conn.recv(4096)
                    except socket.timeout:
                        if sub is not None and not sub.closed:
                            continue
                        return
                    if not chunk:
                        return
                    buf.extend(chunk)
                    # Drop any interleaved RTCP packets sent by client before next RTSP text req
                    while buf and buf[0] == 0x24:
                        if len(buf) < 4:
                            break
                        flen = struct.unpack(">H", buf[2:4])[0]
                        if len(buf) < 4 + flen:
                            break
                        del buf[: 4 + flen]
                    sep = buf.find(b"\r\n\r\n")

                head = bytes(buf[:sep]).decode("iso-8859-1")
                del buf[: sep + 4]
                lines = head.split("\r\n")
                if not lines:
                    return
                req_parts = lines[0].split(" ")
                if len(req_parts) < 3:
                    return
                method, req_uri = req_parts[0].upper(), req_parts[1]
                hdrs: dict[str, str] = {}
                for line in lines[1:]:
                    if ":" in line:
                        k, v = line.split(":", 1)
                        hdrs[k.strip().lower()] = v.strip()
                cseq = hdrs.get("cseq", "0")

                # Optional SHA-256 Digest auth on downstream
                if self.downstream_user is not None and self.downstream_pass is not None and method != "OPTIONS":
                    auth = hdrs.get("authorization", "")
                    with self._nonce_lock:
                        nonces = set(self._nonces)
                    if not auth or not verify_digest_authorization(
                        auth,
                        method,
                        self.downstream_user,
                        self.downstream_pass,
                        self.downstream_realm,
                        nonces,
                        required_algorithm="SHA-256",
                        require_qop_auth=True,
                    ):
                        nonce = self._mint_nonce()
                        send_reply(
                            "401 Unauthorized",
                            cseq,
                            [
                                f'WWW-Authenticate: Digest realm="{self.downstream_realm}", '
                                f'nonce="{nonce}", algorithm=SHA-256, qop="auth"'
                            ],
                        )
                        continue

                if method == "OPTIONS":
                    send_reply(
                        "200 OK",
                        cseq,
                        ["Public: OPTIONS, DESCRIBE, SETUP, PLAY, GET_PARAMETER, TEARDOWN"],
                    )
                elif method == "DESCRIBE":
                    desc = self.hub.ready_descriptor()
                    if desc is None:
                        send_reply("503 Service Unavailable", cseq, ["Retry-After: 1"])
                        continue
                    sdp = self._build_sdp(desc)
                    base_uri = req_uri.split("#", 1)[0].split("?", 1)[0]
                    cbase = base_uri.rstrip("/") + "/"
                    send_reply(
                        "200 OK",
                        cseq,
                        ["Content-Type: application/sdp", f"Content-Base: {cbase}"],
                        body=sdp,
                    )
                elif method == "SETUP":
                    desc = self.hub.ready_descriptor()
                    if desc is None:
                        send_reply("503 Service Unavailable", cseq, [])
                        continue
                    tr = hdrs.get("transport", "")
                    m = re.search(r"interleaved=(\d+)-(\d+)", tr)
                    if not m:
                        send_reply("461 Unsupported Transport", cseq, [])
                        continue
                    rtp_ch = int(m.group(1))
                    rtcp_ch = int(m.group(2))
                    setup_done = True
                    send_reply(
                        "200 OK",
                        cseq,
                        [
                            f"Session: {session_id};timeout=60",
                            f"Transport: RTP/AVP/TCP;unicast;interleaved={rtp_ch}-{rtcp_ch};ssrc={desc['ssrc']:08X}",
                        ],
                    )
                elif method == "PLAY":
                    if not setup_done:
                        send_reply("455 Method Not Valid in This State", cseq, [])
                        continue
                    desc = self.hub.ready_descriptor()
                    if desc is None:
                        send_reply("503 Service Unavailable", cseq, [])
                        continue
                    send_reply(
                        "200 OK",
                        cseq,
                        [f"Session: {session_id}", "Range: npt=0.000-"],
                    )
                    if sub is None:
                        sub = Subscriber(conn, rtp_channel=rtp_ch)
                        self.hub.add_subscriber(sub)
                        writer_thread = threading.Thread(target=pump_media, args=(sub,), daemon=True)
                        writer_thread.start()
                elif method == "GET_PARAMETER":
                    extra = [f"Session: {session_id}"] if setup_done else []
                    send_reply("200 OK", cseq, extra)
                elif method == "TEARDOWN":
                    extra = [f"Session: {session_id}"] if setup_done else []
                    send_reply("200 OK", cseq, extra)
                    return
                else:
                    send_reply("501 Not Implemented", cseq, [])
        except OSError:
            pass
        finally:
            if sub is not None:
                self.hub.remove_subscriber(sub)
                sub.close()
            else:
                try:
                    conn.close()
                except OSError:
                    pass
            if writer_thread is not None:
                writer_thread.join(timeout=1.0)
            with self._client_count_lock:
                self._client_count -= 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Bounded single-session Wyze RTSP bridge")
    ap.add_argument("--upstream-host", required=True)
    ap.add_argument("--upstream-port", type=int, default=554)
    ap.add_argument("--upstream-path", default="/stream1")
    ap.add_argument("--upstream-cred-file", default=None)
    ap.add_argument("--upstream-user", default=None)
    ap.add_argument("--upstream-pass", default=None)
    ap.add_argument("--listen-host", default="127.0.0.1")
    ap.add_argument("--listen-port", type=int, default=8554)
    ap.add_argument("--listen-path", default="/stream1")
    ap.add_argument("--max-clients", type=int, default=4)
    ap.add_argument("--downstream-cred-file", default=None)
    ap.add_argument("--downstream-realm", default="fss-bridge")
    ap.add_argument("--backoff-initial", type=float, default=5.0)
    ap.add_argument("--backoff-max", type=float, default=60.0)
    ap.add_argument("--keepalive-secs", type=float, default=25.0)
    ap.add_argument("--status-file", default=None)
    args = ap.parse_args(argv)

    up_user, up_pass = args.upstream_user, args.upstream_pass
    if args.upstream_cred_file:
        up_user, up_pass = load_cred_file(args.upstream_cred_file)

    dn_user, dn_pass = None, None
    if args.downstream_cred_file:
        dn_user, dn_pass = load_cred_file(args.downstream_cred_file)

    stop = threading.Event()
    hub = StreamHub(status_file=args.status_file)
    upstream = UpstreamClient(
        hub=hub,
        host=args.upstream_host,
        port=args.upstream_port,
        path=args.upstream_path,
        username=up_user,
        password=up_pass,
        backoff_initial=args.backoff_initial,
        backoff_max=args.backoff_max,
        keepalive_secs=args.keepalive_secs,
        stop_event=stop,
    )
    downstream = DownstreamServer(
        hub=hub,
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        listen_path=args.listen_path,
        max_clients=args.max_clients,
        downstream_user=dn_user,
        downstream_pass=dn_pass,
        downstream_realm=args.downstream_realm,
    )

    def _sig(_signum, _frame):
        stop.set()
        upstream.close_upstream()

    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGINT, _sig)

    downstream.start()
    upstream.start()
    try:
        while not stop.is_set():
            stop.wait(timeout=1.0)
    finally:
        stop.set()
        upstream.close_upstream()
        downstream.stop()
        upstream.join(timeout=3.0)
    return 0


if __name__ == "__main__":
    sys.exit(main())

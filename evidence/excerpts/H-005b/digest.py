#!/usr/bin/env python3
"""Probe Streamd Digest auth on :8800 with candidate (user, password) pairs."""
import hashlib, os, re, socket, sys, uuid

HOST, PORT = "192.168.4.70", 8800


def raw(req: bytes, timeout=6.0) -> bytes:
    s = socket.create_connection((HOST, PORT), timeout=timeout)
    s.sendall(req)
    buf = b""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            buf += d
            if b"\r\n\r\n" in buf:
                break
    except socket.timeout:
        pass
    finally:
        s.close()
    return buf


def challenge():
    r = raw(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
    m = re.search(rb"WWW-Authenticate: (Digest .*)", r)
    if not m:
        raise SystemExit(f"no challenge: {r[:200]!r}")
    return dict((k.lower(), v.strip('"')) for k, v in
                (p.strip().split("=", 1) for p in m.group(1).decode()[7:].split(",")))


def try_pair(user, pw, method="SHA256"):
    c = challenge()
    h = (hashlib.sha256 if method == "SHA256" else hashlib.md5)(pw.encode()).hexdigest().upper()
    cnonce = uuid.uuid4().hex[:24]
    nc = "00000001"
    ha1 = hashlib.md5(":".join((user, c["realm"], h)).encode()).hexdigest()
    ha2 = hashlib.md5(b"POST:/stream").hexdigest()
    resp = hashlib.md5(":".join((ha1, c["nonce"], nc, cnonce, c["qop"], ha2)).encode()).hexdigest()
    auth = (f'Digest username="{user}",realm="{c["realm"]}",uri="/stream",algorithm=MD5,'
            f'nonce="{c["nonce"]}",nc={nc},cnonce="{cnonce}",qop={c["qop"]},'
            f'response="{resp}",opaque="{c["opaque"]}"')
    req = (f"POST /stream HTTP/1.1\r\nHost: x\r\nAuthorization: {auth}\r\n"
           f"Content-Type: multipart/mixed;boundary=--x\r\nConnection: close\r\n\r\n").encode()
    r = raw(req)
    line = r.split(b"\r\n", 1)[0].decode(errors="replace")
    return line, r[:400]


if __name__ == "__main__":
    pairs = [("admin", "TPL075526460603"), ("admin", "admin"),
             ("admin", "TPL075526460603".lower())]
    if len(sys.argv) > 2:
        pairs = [(sys.argv[1], sys.argv[2])]
    for u, p in pairs:
        for meth in ("SHA256", "MD5"):
            try:
                line, body = try_pair(u, p, meth)
            except Exception as e:  # noqa: BLE001
                line, body = f"ERR {e}", b""
            print(f"{u}:{p} [{meth}] -> {line}")
            print("   ", body.split(b"\r\n\r\n", 1)[0][:300])

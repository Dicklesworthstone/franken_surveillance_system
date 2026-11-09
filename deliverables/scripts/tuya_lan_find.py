#!/usr/bin/env python3
"""Find Tuya devices on the LAN (AOSU cameras, and the H2E HomeBase that fronts them).

The AOSU row is blocked on a `local_key`, which only the gateway can hand out, and the
gateway has never been located on the LAN. Tuya devices announce themselves three ways:

  * UDP 6666/6667 broadcasts (discovery / setup-mode beacons),
  * TCP 6668, the local control protocol every Tuya device listens on,
  * their MAC in the ARP table.

This prints the union, with OUI names, and never writes to a device. Bounded: one
/24, 0.6 s connect timeout, 8 s of passive listening.

  tuya_lan_find.py [--subnet 192.168.4] [--listen 8]
"""
import argparse
import concurrent.futures as cf
import socket
import struct
import subprocess
import sys
import time

# OUIs seen on owner Tuya/AOSU hardware; unknown OUIs are still reported.
KNOWN = {
    "60:d5:61": "AOSU/Tuya (registry aosu)",
    "d8:1f:12": "Tuya",
    "18:69:d8": "Tuya",
    "38:1a:52": "Tuya",
    "50:02:91": "Tuya",
    "68:57:2d": "Tuya",
    "84:e3:42": "Tuya",
    "a0:20:a6": "Espressif (Tuya module)",
}


ARP_SNAPSHOT = "/tmp/fleet_arp_snapshot.txt"


PREFIX = bytes.fromhex("000055aa")


def probe_device(ip: str, secs: float = 3.0) -> None:
    """Unicast a 0x23 DP_QUERY-style frame and print whatever comes back.

    Nothing here is authenticated: 0x23 is the pre-key discovery command, so a reply
    (even AES-ECB encrypted with the device-id-derived key) proves the unit is reachable
    and talking. The payload, when it decrypts, carries the gwId.
    """
    for port in (6667, 6666):
        for _round in range(3):
            _probe_once(ip, port, secs)
            time.sleep(1.2)


def _probe_once(ip: str, port: int, secs: float) -> None:
    for cmd_len in (b"\x00\x00\x00\x04", b"\x00\x00\x00\x00"):
        frame = PREFIX + b"\x00\x00\x00\x00" + b"\x00\x00\x00\x23" + cmd_len + b"\x00\x00\x00\x00"
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.7)
        try:
            sock.sendto(frame, (ip, port))
        except OSError as e:
            print(f"  {ip}:{port} send failed ({e})")
            sock.close()
            continue
        end = time.time() + secs
        while time.time() < end:
            try:
                data, peer = sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            printable = "".join(chr(c) if 32 <= c < 127 else "." for c in data)
            print(f"  reply {ip}:{peer[1]} {len(data)}B {data[:48].hex()}")
            print(f"        {printable[:120]}")
            break
        sock.close()


def arp_table() -> dict[str, str]:
    """ip -> mac. Under this harness's inherited environment `arp -an` prints a single
    entry regardless of interpreter, so the fleet's own snapshot file is preferred
    (written by `zsh -c 'arp -a > /tmp/fleet_arp_snapshot.txt'` from a login shell)."""
    out = {}
    try:
        age = time.time() - __import__("os").path.getmtime(ARP_SNAPSHOT)
        # a stale snapshot still beats `arp -an` here, which returns one line
        if age > 600:
            print(f"arp snapshot is {age / 60:.0f} min old — refresh it", file=sys.stderr)
        lines = open(ARP_SNAPSHOT, encoding="utf-8", errors="replace").read().splitlines()
    except OSError:
        lines = []
    if not lines:
        try:
            r = subprocess.run(["/usr/sbin/arp", "-an"], capture_output=True, text=True, timeout=10)
            lines = r.stdout.splitlines()
        except (OSError, subprocess.TimeoutExpired):
            return out
    for line in lines:
        parts = line.split()
        if len(parts) < 4 or "(" not in line:
            continue
        ip = parts[1].strip("()")
        mac = parts[3]
        if mac != "(incomplete)":
            out[ip] = mac.lower()
    return out


def probe(ip: str, port: int, timeout: float = 0.6) -> bool:
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def listen_udp(port: int, secs: float) -> set[str]:
    """Passive: collect source IPs of anything broadcasting to a discovery port."""
    seen: set[str] = set()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        s.bind(("", port))
    except OSError as e:
        print(f"udp {port}: bind failed ({e}) — another listener?", file=sys.stderr)
        s.close()
        return seen
    s.settimeout(0.5)
    end = time.time() + secs
    while time.time() < end:
        try:
            data, peer = s.recvfrom(2048)
        except socket.timeout:
            continue
        except OSError:
            break
        seen.add(peer[0])
        print(f"  udp{port} {peer[0]}:{peer[1]} {len(data)}B {data[:32].hex()}")
    s.close()
    return seen


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--subnet", default="192.168.4")
    ap.add_argument("--listen", type=float, default=8.0)
    ap.add_argument("--probe", help="unicast a discovery frame at this IP (4.x camera)")
    a = ap.parse_args()

    arp = arp_table()
    print(f"arp: {len(arp)} cached neighbours")

    # a broadcast probe wakes devices that only answer while awake
    for port in (6666, 6667):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for _ in range(3):
            try:
                s.sendto(struct.pack(">I", 0) + b"\x00" * 8, ("255.255.255.255", port))
            except OSError:
                pass
            time.sleep(0.1)
        s.close()

    hits: dict[str, str] = {}
    with cf.ThreadPoolExecutor(max_workers=64) as ex:
        futs = {ex.submit(probe, f"{a.subnet}.{i}", 6668): f"{a.subnet}.{i}" for i in range(1, 255)}
        for f in cf.as_completed(futs):
            if f.result():
                hits[futs[f]] = "tcp6668"
    print(f"tcp6668 listeners: {sorted(hits) or 'none'}")

    if a.probe:
        print(f"probing {a.probe} …")
        probe_device(a.probe)
        hits.setdefault(a.probe, "probe")

    print(f"listening udp 6666/6667 for {a.listen:.0f}s …")
    for port in (6666, 6667):
        for ip in listen_udp(port, a.listen):
            hits.setdefault(ip, f"udp{port}")

    arp.update(arp_table())
    if not hits and not arp:
        print("no candidates")
        return 1
    print("\nip            mac                oui                         via")
    for ip in sorted(hits, key=lambda x: tuple(int(p) for p in x.split("."))):
        mac = arp.get(ip, "?")
        oui = KNOWN.get(mac[:8], "")
        print(f"{ip:<13} {mac:<18} {oui:<27} {hits[ip]}")
    for ip, mac in sorted(arp.items()):
        if ip not in hits and mac[:8] in KNOWN:
            print(f"{ip:<13} {mac:<18} {KNOWN[mac[:8]]:<27} arp")
    return 0


if __name__ == "__main__":
    sys.exit(main())

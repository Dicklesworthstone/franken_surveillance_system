#!/usr/bin/env python3
"""Wake a Tapo (and try any Wi-Fi camera) with a WoWLAN magic packet.

The vendor apps reach a sleeping unit without user interaction; this is how. The SoC keeps a
wake receiver while the application SoC sleeps, so a magic packet on the LAN is enough and no
PIR event or power-cycle is needed.

Sent to the broadcast address and to the unicast address on UDP 9 and 7, several times — a
sleeping radio misses single frames.

  tapo_wake.py <mac> [--broadcast 192.168.4.255] [--rounds 6] [--ip IP] [--wait N]
"""
import argparse
import socket
import sys
import time


def send(mac: str, dst_ip: str, broadcast: bool, rounds: int = 70, gap: float = 0.5) -> None:
    raw = bytes.fromhex(mac.replace(":", "").replace("-", ""))
    if len(raw) != 6:
        sys.exit(f"bad mac {mac}")
    pkt = b"\xff" * 6 + raw * 16
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if broadcast:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    targets = [(dst_ip, 9), (dst_ip, 7)] if broadcast else [(dst_ip, p)] if False else [(dst_ip, 9), (dst_ip, 7)]
    for _ in range(rounds):
        for dst in targets:
            try:
                s.sendto(pkt, dst)
            except OSError:
                pass
        time.sleep(gap)
    s.close()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("mac")
    ap.add_argument("--broadcast", default="192.168.4.255")
    ap.add_argument("--ip", help="also unicast here")
    ap.add_argument("--rounds", type=int, default=70)   # a deep-sleep unit needed 24 s of frames
    ap.add_argument("--gap", type=float, default=0.5)
    ap.add_argument("--wait", type=float, default=45.0, help="seconds to keep sending and probing")
    ap.add_argument("--port", type=int, default=443)
    a = ap.parse_args()

    send(a.mac, a.broadcast, True, a.rounds, a.gap)
    if a.ip:
        send(a.mac, a.ip, False, a.rounds, a.gap)
    print(f"magic sent to {a.mac} (broadcast{' + ' + a.ip if a.ip else ''})")
    if not a.ip or a.wait <= 0:
        return 0
    end = time.time() + a.wait
    while time.time() < end:
        s = socket.socket()
        s.settimeout(1)
        try:
            if s.connect_ex((a.ip, a.port)) == 0:
                print(f"awake: {a.ip}:{a.port} open after {a.wait - (end - time.time()):.1f}s")
                return 0
        finally:
            s.close()
        send(a.mac, a.ip, False, 2, 0.3)
        time.sleep(1.5)
    print(f"no response on {a.ip}:{a.port} within {a.wait}s")
    return 1


if __name__ == "__main__":
    sys.exit(main())

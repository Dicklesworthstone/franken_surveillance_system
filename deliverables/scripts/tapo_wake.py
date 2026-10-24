#!/usr/bin/env python3
"""Wake a sleeping Tapo camera and prove it with a TCP answer.

The C460/C660 are battery cameras. When they sleep, the Wi-Fi chip still answers
ARP/ICMP (and may RST TCP), but every userspace listener is gone. `ping` and
`nc -z` therefore say nothing. The only honest liveness signal is a completed
TCP connect to a port the app owns (443/8800) or a UDP reply from the app.

This script fires the wake surfaces the vendor app itself uses, in a fixed
order, and after every burst checks TCP. Each probe is timestamped and timed so
a negative result is diagnosable rather than mysterious.

Surfaces (from the 3.23.2 app, `libtdp` / `TPDiscoveryUtils`):

  tdp    TDP v2 discovery, opcode 1, flags 0x11 (broadcast) / 0x21 (unicast),
         port 20004 (camera discovery) and 20002 (TDP server). v1 uses opcode 2.
         Header is 16 bytes big-endian, CRC32 over header+payload, checksum
         field seeded 0x5A6B7C8D. Payload is {"params":{"rsa_key":...}}.
  ssdp   M-SEARCH to the unit and to 239.255.255.250:1900.
  kasa   UDP 9999: plain get_sysinfo, autokey-encrypted get_sysinfo, and the
         0x0ABA1000 magic number (`UDP_DISCOVERY_MAGIC_NUMBER`).
  arp    paced ARP requests (scapy). Routed subnets will not see these.
  icmp   paced echo requests.

Usage:
  tapo_wake.py <ip> [--mac MAC] [--rounds 3] [--gap 3] [--timeout 1.0]
  tapo_wake.py <ip> --watch [--watch-secs 300]

Exit 0 as soon as a TCP answer appears, 1 if the budget is exhausted.
"""
import argparse
import hashlib
import json
import socket
import struct
import sys
import time
import zlib

TDP_PORTS = (20004, 20002)
TCP_PORTS = (443, 8800)
SSDP_ADDR = ("239.255.255.250", 1900)
TDP_CHECKSUM_SEED = 1516993677  # 0x5A6B7C8D, TDPDefine.TDP_CHECKSUM_DEFAULT


def now() -> float:
    return time.monotonic()


def stamp(t0: float, label: str, detail: str = "") -> None:
    print("%8.3fs  %-6s %s" % (now() - t0, label, detail), flush=True)


def tdp_packet(version: int, opcode: int, flags: int, payload: bytes) -> bytes:
    hdr = bytearray(16)
    hdr[0] = version
    struct.pack_into(">H", hdr, 2, opcode)
    struct.pack_into(">H", hdr, 4, len(payload))
    hdr[6] = flags
    struct.pack_into(">I", hdr, 8, 0x1234567)
    struct.pack_into(">I", hdr, 12, TDP_CHECKSUM_SEED)
    body = bytes(hdr) + payload
    struct.pack_into(">I", hdr, 12, zlib.crc32(body) & 0xFFFFFFFF)
    return bytes(hdr) + payload


def udp_exchange(host: str, port: int, payload: bytes, timeout: float) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(payload, (host, port))
        data, addr = s.recvfrom(4096)
        return "reply %s %dB %r" % (addr, len(data), data[:48])
    except socket.timeout:
        return "timeout"
    except OSError as exc:
        return "error %s" % exc
    finally:
        s.close()


def tcp_probe(host: str, timeout: float) -> list[str]:
    hits = []
    for port in TCP_PORTS:
        s = socket.socket()
        s.settimeout(timeout)
        t = now()
        try:
            s.connect((host, port))
            hits.append("%d OPEN %.0fms" % (port, (now() - t) * 1000))
        except ConnectionRefusedError:
            hits.append("%d RST" % port)
        except socket.timeout:
            hits.append("%d filtered" % port)
        except OSError as exc:
            hits.append("%d %s" % (port, type(exc).__name__))
        finally:
            s.close()
    return hits


def probe_tdp(host: str, t0: float, timeout: float) -> None:
    payload = json.dumps({"params": {"rsa_key": "x"}}).encode()
    directed = host.rsplit(".", 1)[0] + ".255"
    for port in TDP_PORTS:
        for flags, name in ((0x11, "bcast"), (0x21, "ucast")):
            stamp(t0, "tdp", "v2 op1 %s :%d -> %s"
                  % (name, port, udp_exchange(host, port, tdp_packet(2, 1, flags, payload), timeout)))
        stamp(t0, "tdp", "v2 op1 directed %s:%d -> %s"
              % (directed, port, udp_exchange(directed, port, tdp_packet(2, 1, 0x11, payload), timeout)))
        stamp(t0, "tdp", "magic :%d -> %s"
              % (port, udp_exchange(host, port, bytes((0x0A, 0xBA, 0x10, 0x00)), timeout)))
    # v1 discovery (opcode 2) for older firmware paths
    stamp(t0, "tdp", "v1 op2 ucast :20002 -> %s"
          % udp_exchange(host, 20002, tdp_packet(1, 2, 0x21, payload), timeout))


def probe_ssdp(host: str, t0: float, timeout: float) -> None:
    msg = (b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
           b'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n')
    stamp(t0, "ssdp", "unicast -> %s" % udp_exchange(host, 1900, msg, timeout))
    stamp(t0, "ssdp", "multicast -> %s" % udp_exchange(SSDP_ADDR[0], SSDP_ADDR[1], msg, timeout))


def kasa_packet(obj: dict) -> bytes:
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    key = hashlib.md5(b"bigbang").digest()
    iv = hashlib.md5(key).digest()
    padder = padding.PKCS7(128).padder()
    pt = padder.update(json.dumps(obj).encode()) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct = enc.update(pt) + enc.finalize()
    return len(ct).to_bytes(4, "big") + ct


def probe_kasa(host: str, t0: float, timeout: float) -> None:
    sysinfo = {"system": {"get_sysinfo": {}}}
    for port in (9999, 9998):
        stamp(t0, "kasa", "plain :%d -> %s"
              % (port, udp_exchange(host, port, json.dumps(sysinfo).encode(), timeout)))
        stamp(t0, "kasa", "autokey :%d -> %s"
              % (port, udp_exchange(host, port, kasa_packet(sysinfo), timeout)))
    stamp(t0, "kasa", "magic :9999 -> %s"
          % udp_exchange(host, 9999, bytes((0x0A, 0xBA, 0x10, 0x00)), timeout))


def probe_arp(host: str, mac: str | None, t0: float) -> None:
    try:
        from scapy.all import ARP, Ether, srp
    except ImportError:
        stamp(t0, "arp", "scapy missing")
        return
    dst = mac or "ff:ff:ff:ff:ff:ff"
    t = now()
    try:
        ans, _ = srp(Ether(dst=dst) / ARP(pdst=host), timeout=1.0, verbose=False)
    except Exception as exc:  # /dev/bpf* needs root
        stamp(t0, "arp", "unavailable (%s)" % type(exc).__name__)
        return
    stamp(t0, "arp", "%d reply(ies) %.0fms" % (len(ans), (now() - t) * 1000))


def probe_icmp(host: str, t0: float) -> None:
    import subprocess

    t = now()
    rc = subprocess.run(["ping", "-c", "1", "-W", "1000", host],
                        capture_output=True).returncode
    stamp(t0, "icmp", "%s %.0fms" % ("reply" if rc == 0 else "loss", (now() - t) * 1000))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("--mac", default=None, help="unit MAC for directed ARP")
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--gap", type=float, default=3.0, help="seconds between rounds")
    ap.add_argument("--timeout", type=float, default=1.0)
    ap.add_argument("--watch", action="store_true", help="only poll TCP")
    ap.add_argument("--watch-secs", type=float, default=300.0)
    a = ap.parse_args()

    t0 = now()
    if a.watch:
        print("watching %s for a TCP answer (%.0fs)" % (a.host, a.watch_secs), flush=True)
        while now() - t0 < a.watch_secs:
            hits = tcp_probe(a.host, 0.5)
            if any("OPEN" in h for h in hits):
                stamp(t0, "tcp", " ".join(hits))
                return 0
            time.sleep(2)
        stamp(t0, "tcp", "no answer in %.0fs" % a.watch_secs)
        return 1

    for r in range(a.rounds):
        print("--- round %d/%d" % (r + 1, a.rounds), flush=True)
        probe_icmp(a.host, t0)
        probe_arp(a.host, a.mac, t0)
        probe_tdp(a.host, t0, a.timeout)
        probe_ssdp(a.host, t0, a.timeout)
        probe_kasa(a.host, t0, a.timeout)
        hits = tcp_probe(a.host, a.timeout)
        stamp(t0, "tcp", " ".join(hits))
        if any("OPEN" in h for h in hits):
            print("WOKEN: %s answers TCP" % a.host, flush=True)
            return 0
        time.sleep(a.gap)
    print("no TCP answer after %d rounds" % a.rounds, flush=True)
    return 1


if __name__ == "__main__":
    sys.exit(main())

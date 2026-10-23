#!/usr/bin/env python3
"""Send a Wyze v4 Wi-Fi ioctl (0x29a0 = set ssid/pwd) through the fss-tutk session probe.

Why a wrapper: the Rust `session_probe` example is the maintained TUTK client (correct DTLS
psk-identity handling, K-auth retransmit, clean close); the ad-hoc Python client in
`deliverables/scripts/dtlslib.py` still completes the handshake but its K-auth retry cadence is
rejected by fw 4.52.17.26. So drive the Rust example.

0x29a0 takes JSON `{"ssid":..,"pwd":..}`; both are parsed, length-checked `<32` / `<64`, echoed
back in the `0x29a1` reply as `{"ssid":..,"result":1}`, applied to the wpa config and then the unit
reboots and returns on its previous SSID. It is a LAN Wi-Fi re-provision and a clean remote-reboot
primitive; it is NOT a shell sink (see docs/exploit/wifi-ssid-inject.md).

Usage:
  wyze_wifi_ioctl.py <ip> <cfg.json> <ssid> <pwd> [cmd_hex]

cfg.json is the lab tuple from ~/fss-exploit/cfg/<ip>.json (uid/enr/mac). Set IFACE to override the
source address (default 192.168.4.222).
"""
import json
import os
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
EXE = os.path.join(REPO, "target/debug/examples/session_probe")


def main():
    if len(sys.argv) < 5:
        print(__doc__)
        return 2
    ip, cfgp, ssid, pwd = sys.argv[1:5]
    cmd = sys.argv[5] if len(sys.argv) > 5 else "0x29a0"
    if len(ssid.encode()) >= 32 or len(pwd.encode()) >= 64:
        print("ssid must be <32 bytes and pwd <64 bytes")
        return 2
    cfg = json.load(open(cfgp))

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump({"ssid": ssid, "pwd": pwd}, fh)
        payload = fh.name

    args = [EXE, "--ip", ip, "--uid", cfg["uid"], "--enr", cfg["enr"], "--mac", cfg["mac"],
            "--ioctl", cmd, "--payload-file", payload, "--secs", os.environ.get("SECS", "4")]
    if not os.path.exists(EXE):
        args = ["cargo", "run", "-q", "-p", "fss-tutk", "--example", "session_probe", "--"] + args[1:]
    print("payload:", json.load(open(payload)))
    return subprocess.call(args, cwd=REPO)


if __name__ == "__main__":
    sys.exit(main())

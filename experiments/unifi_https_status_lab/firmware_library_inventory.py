#!/usr/bin/env python3
"""Owner-scoped, read-only inventory of specific camera firmware libraries.

Uses a retained TLS pin and the previously observed SSH host key. No camera
diagnostic executable or settings operation is invoked; SSH can create logs.
This laboratory helper does not authenticate physical device identity.
"""

import ipaddress
import json
import os
import pathlib
import re
import socket
import ssl
import subprocess

NAMES = (
    "libasound.so.2", "libcus3a.so", "libfdk-aac.so.2", "libispalgo.so",
    "libmi_divp.so", "libmi_isp.so", "libmi_rgn.so", "libmi_sensor.so",
    "libmi_vif.so", "libmi_vpe.so", "libopus.so.0", "libubnt_audio_utils.so",
    "libubnt_watchdog_entity.so",
)
assert all(re.fullmatch(r"[A-Za-z0-9_.-]+", name) for name in NAMES)


def main():
    root = pathlib.Path("/data/tmp/fss-unifi-lib-inventory-20261116-01")
    os.mkdir(root, 0o700)
    lines = subprocess.check_output(
        ["journalctl", "-u", "fss-unifi-neighbor-discovery.service", "-S", "-10min", "-o", "cat", "--no-pager"],
        text=True, timeout=10,
    ).splitlines()
    candidates = {
        camera["address"] for line in lines if line.startswith('{"schema":"fss.unifi_discovery_lab.v2"')
        for camera in json.loads(line).get("cameras", []) if camera.get("platform") == "UVC G4 Instant"
    }
    if len(candidates) != 1:
        raise RuntimeError("ambiguous camera candidate")
    host = candidates.pop()
    if ipaddress.ip_address(host) not in ipaddress.ip_network("192.168.4.0/22"):
        raise RuntimeError("camera outside owner scope")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, 443), timeout=5) as tcp:
        with context.wrap_socket(tcp, server_hostname=host) as tls:
            if tls.getpeercert(binary_form=True) != pathlib.Path("/data/unifi-g4-recorder/fss-trial-DGXi2K/cert.der").read_bytes():
                raise RuntimeError("camera pin mismatch")
    cred = json.loads(pathlib.Path("/data/unifi-g4-recorder/camera-credential.json").read_text())
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", cred["username"]):
        raise RuntimeError("invalid camera username")
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, (cred["password"] + "\n").encode())
    finally:
        os.close(write_fd)
    names = " ".join(NAMES)
    command = (
        "for n in " + names + "; do found=0; "
        'for d in /lib /usr/lib; do if [ -f "$d/$n" ]; then '
        's=$(wc -c < "$d/$n") || exit 1; printf "%s %s %s\\n" "$n" "$d" "$s"; found=1; break; fi; done; '
        'if [ "$found" = 0 ]; then printf "%s missing 0\\n" "$n"; fi; done'
    )
    args = ["strace", "-f", "--seccomp-bpf", "-e", "trace=unlink,unlinkat,rmdir",
            "-e", "inject=unlink,unlinkat,rmdir:error=EPERM", "-o", str(root / "local.trace"),
            "sshpass", "-d", str(read_fd), "ssh", "-F", "/dev/null", "-o", "IdentityAgent=none",
            "-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password",
            "-o", "StrictHostKeyChecking=yes", "-o",
            "UserKnownHostsFile=/data/unifi-g4-recorder/fss-ssh-observe-20261116-01/known_hosts",
            "-o", "ConnectTimeout=7", cred["username"] + "@" + host, command]
    try:
        result = subprocess.run(args, stdin=subprocess.DEVNULL, pass_fds=(read_fd,),
                                capture_output=True, text=True, timeout=20, check=False)
    finally:
        os.close(read_fd)
    if result.returncode or len(result.stdout) > 4096:
        raise RuntimeError("bounded inventory failed")
    seen = set()
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) != 3 or parts[0] not in NAMES or parts[0] in seen or parts[1] not in ("/lib", "/usr/lib", "missing"):
            raise RuntimeError("unexpected inventory response")
        size = int(parts[2])
        if not 0 <= size <= 64 * 1024 * 1024 or (parts[1] == "missing") != (size == 0):
            raise RuntimeError("invalid inventory size")
        seen.add(parts[0])
        print("library=" + parts[0] + " location=" + parts[1] + " bytes=" + str(size))
    if len(seen) != len(NAMES):
        raise RuntimeError("incomplete inventory response")
    print("inventory_complete=true count=" + str(len(seen)))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("inventory_refused=" + type(error).__name__)
        raise SystemExit(1)

#!/usr/bin/env python3
"""Owner-scoped, payload-free one-shot streamer diagnostic laboratory probe.

This uses the camera's existing diagnostic client as a laboratory oracle, not
as production transport. It sends only GetVideoSettings. A returned value is
an untrusted current camera claim; it cannot settle earlier camera effects.
"""

import ipaddress
import json
import os
import pathlib
import re
import socket
import ssl
import subprocess
import sys

ROOT = pathlib.Path("/data/tmp/fss-unifi-streamer-read-20261116-02")
PIN = pathlib.Path("/data/unifi-g4-recorder/fss-trial-DGXi2K/cert.der")
CREDENTIAL = pathlib.Path("/data/unifi-g4-recorder/camera-credential.json")
HOST_KEYS = "/data/unifi-g4-recorder/fss-ssh-observe-20261116-01/known_hosts"


def main():
    # Kept as an audit artifact only. The device-side client lifecycle is not
    # protected from deletion, so no further physical invocation is permitted.
    raise RuntimeError("physical diagnostic client disabled: device deletion cannot be excluded")
    os.mkdir(ROOT, 0o700)
    lines = subprocess.check_output(
        ["journalctl", "-u", "fss-unifi-neighbor-discovery.service", "-S", "-10min", "-o", "cat", "--no-pager"],
        text=True, timeout=10,
    ).splitlines()
    addresses = {
        candidate["address"]
        for line in lines if line.startswith('{"schema":"fss.unifi_discovery_lab.v2"')
        for candidate in json.loads(line).get("cameras", [])
        if candidate.get("platform") == "UVC G4 Instant"
    }
    if len(addresses) != 1:
        raise RuntimeError("ambiguous camera candidate")
    host = addresses.pop()
    if ipaddress.ip_address(host) not in ipaddress.ip_network("192.168.4.0/22"):
        raise RuntimeError("camera outside owner scope")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, 443), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname=host) as tls:
            if tls.getpeercert(binary_form=True) != PIN.read_bytes():
                raise RuntimeError("camera certificate pin mismatch")
    credential = json.loads(CREDENTIAL.read_text())
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", credential["username"]):
        raise RuntimeError("invalid camera user")
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, (credential["password"] + "\n").encode())
    finally:
        os.close(write_fd)
    # Fixed command, no interpolated device data, and no remote file creation.
    command = "timeout 5 ubnt_ipc_cli -T=ubnt_streamer -r=1 -t=2500 '-m={\"functionName\":\"GetVideoSettings\"}'"
    args = ["strace", "-f", "--seccomp-bpf", "-e", "trace=unlink,unlinkat,rmdir",
            "-e", "inject=unlink,unlinkat,rmdir:error=EPERM", "-o", str(ROOT / "local.trace"),
            "sshpass", "-d", str(read_fd), "ssh", "-F", "/dev/null", "-o", "IdentityAgent=none",
            "-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password",
            "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + HOST_KEYS,
            "-o", "ConnectTimeout=7", credential["username"] + "@" + host, command]
    try:
        result = subprocess.run(args, stdin=subprocess.DEVNULL, pass_fds=(read_fd,),
                                capture_output=True, timeout=18, check=False)
    finally:
        os.close(read_fd)
    print("pinned_camera_candidate=matched")
    print("ssh_command_exit=" + str(result.returncode))
    print("stdout_bytes=" + str(len(result.stdout)))
    print("stderr_bytes=" + str(len(result.stderr)))
    # The response may contain sensitive configuration. Do not print or persist it.
    try:
        response = json.loads(result.stdout)
    except (ValueError, UnicodeDecodeError):
        print("response_json=unavailable")
    else:
        print("response_json=" + ("object" if isinstance(response, dict) else "other"))
        if isinstance(response, dict):
            print("response_function_claim=" + str(response.get("functionName") == "__response__").lower())
            print("response_status_zero=" + str(response.get("statusCode") == 0).lower())
            print("response_payload_object=" + str(isinstance(response.get("payload"), dict)).lower())
            allowed = {"video", "videos", "settings", "videoSettings", "channels", "streams",
                       "result", "payload", "width", "height", "fps", "frameRate", "resolution",
                       "avSerializer", "serializers", "codec", "encoder", "name", "status"}
            counts = {key: 0 for key in allowed}
            stack = [(response, 0)]
            visited = 0
            while stack:
                item, depth = stack.pop()
                visited += 1
                if visited > 10000 or depth > 16:
                    raise RuntimeError("response structure exceeds bound")
                if isinstance(item, dict):
                    for key, value in item.items():
                        if key in counts:
                            counts[key] += 1
                        if isinstance(value, (dict, list)):
                            stack.append((value, depth + 1))
                elif isinstance(item, list):
                    stack.extend((value, depth + 1) for value in item if isinstance(value, (dict, list)))
            print("recognized_field_counts=" + ",".join(
                key + ":" + str(counts[key]) for key in sorted(counts) if counts[key]))
    print("effect_settlement=unproven")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("probe_refused=" + type(error).__name__, file=sys.stderr)
        raise SystemExit(1)

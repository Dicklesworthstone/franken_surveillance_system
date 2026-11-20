#!/usr/bin/env python3
"""Read-only, bounded copy of specific camera libraries for an isolated lab.

Not a production dependency. Output is private and create-only; no device
file, client, or setting is changed by the requested shell commands. SSH may
write device audit logs. The observed TLS pin and SSH key are not independent
physical-device authentication.
"""

import hashlib
import ipaddress
import json
import os
import pathlib
import re
import socket
import ssl
import subprocess
import sys

LIBRARIES = {
    "libasound.so.2": 562760, "libcus3a.so": 22428, "libfdk-aac.so.2": 472568,
    "libispalgo.so": 147252, "libmi_divp.so": 9588, "libmi_isp.so": 69128,
    "libmi_rgn.so": 9616, "libmi_sensor.so": 9588, "libmi_vif.so": 9588,
    "libmi_vpe.so": 13700, "libopus.so.0": 255276, "libubnt_audio_utils.so": 59508,
    "libubnt_watchdog_entity.so": 63392,
}
if sys.argv[1:] == ["--transitive"]:
    LIBRARIES = {"libmi_ai.so": None, "librt.so.1": None, "libspeexdsp.so.1": None}
    SUFFIX = "03"
elif not sys.argv[1:]:
    SUFFIX = "02"
else:
    raise SystemExit("invalid laboratory option")
assert all(re.fullmatch(r"[A-Za-z0-9_.-]+", name)
           and (size is None or 0 < size <= 2 * 1024 * 1024)
           for name, size in LIBRARIES.items())


def main():
    root = pathlib.Path("/data/tmp/fss-unifi-lib-copy-20261116-" + SUFFIX)
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
    names = " ".join(LIBRARIES) + " " + " ".join(LIBRARIES)
    command = (
        "for n in " + names + "; do f=/lib/$n; [ -f \"$f\" ] || exit 3; "
        's=$(wc -c < "$f") || exit 4; [ "$s" -gt 0 ] && [ "$s" -le 2097152 ] || exit 5; '
        'printf "%s %s\\n" "$n" "$s"; head -c "$s" "$f" || exit 7; done'
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
                                capture_output=True, timeout=30, check=False)
    finally:
        os.close(read_fd)
    if result.returncode or len(result.stdout) > 2 * len(LIBRARIES) * (2 * 1024 * 1024 + 256):
        raise RuntimeError("bounded library copy failed")
    data = memoryview(result.stdout)
    position = 0
    first = {}
    first_sizes = {}
    verified = []
    for index, (expected_name, expected_size) in enumerate(list(LIBRARIES.items()) * 2):
        end = result.stdout.find(b"\n", position, min(len(data), position + 256))
        if end < 0:
            raise RuntimeError("invalid library header")
        parts = bytes(data[position:end]).decode("ascii").split()
        if len(parts) != 2 or parts[0] != expected_name:
            raise RuntimeError("library inventory changed")
        actual_size = int(parts[1])
        if not 0 < actual_size <= 2 * 1024 * 1024 or (expected_size is not None and actual_size != expected_size):
            raise RuntimeError("library size changed")
        if index < len(LIBRARIES):
            first_sizes[expected_name] = actual_size
        elif first_sizes[expected_name] != actual_size:
            raise RuntimeError("library size changed between reads")
        position = end + 1
        chunk = data[position:position + actual_size]
        if len(chunk) != actual_size:
            raise RuntimeError("library body truncated")
        digest = hashlib.sha256(chunk).hexdigest()
        if index < len(LIBRARIES):
            first[expected_name] = digest
        elif first[expected_name] != digest:
            raise RuntimeError("library digest changed between reads")
        else:
            verified.append((expected_name, chunk, digest))
        position += actual_size
    if position != len(data):
        raise RuntimeError("unexpected trailing library bytes")
    for name, chunk, digest in verified:
        fd = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(chunk)
        print("copied=" + name + " sha256=" + digest)
    print("library_copy_verified=" + str(len(verified)))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("copy_refused=" + type(error).__name__)
        raise SystemExit(1)

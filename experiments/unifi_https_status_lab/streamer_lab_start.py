#!/usr/bin/env python3
"""Bounded startup of the copied streamer in a prepared device-free chroot.

Caller must execute inside isolated network/IPC namespaces under deletion
denial. This runs no camera command and supplies only an empty synthetic
configuration. It sends no IPC request and reports no private output.
"""

import os
import pathlib
import socket
import subprocess
import sys
import time

# Audit artifact only. The previous laboratory launch lacked a PID namespace
# and the firmware attempted process management; never run this driver again.
raise SystemExit("disabled: streamer process management requires verified PID isolation")

if len(sys.argv) != 2 or sys.argv[1] != "02":
    raise SystemExit("expected an explicit unused lab sequence")
ROOT = pathlib.Path("/data/tmp/fss-unifi-streamer-chroot-20261116-" + sys.argv[1])
config = ROOT / "etc/synthetic.json"
fd = os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "wb") as output:
    output.write(b"{}\n")
log = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
log.bind(str(ROOT / "dev/log"))
log.setblocking(False)
process = subprocess.Popen(
    ["chroot", str(ROOT), "/qemu-arm", "/bin/ubnt_streamer", "-c=/etc/synthetic.json"],
    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    env={"PATH": "/bin:/usr/bin"},
)
socket_path = ROOT / "var/run/ipc/ubnt_streamer"
observed = False
messages = []
try:
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline and process.poll() is None:
        try:
            message = log.recv(4096)
            if len(messages) < 128:
                messages.append(message)
        except BlockingIOError:
            pass
        if socket_path.is_socket():
            observed = True
            break
        time.sleep(0.05)
finally:
    if process.poll() is None:
        process.terminate()
    try:
        stdout, stderr = process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate(timeout=5)
    while True:
        try:
            message = log.recv(4096)
            if len(messages) < 128:
                messages.append(message)
        except BlockingIOError:
            break
    log.close()
report = (stdout + stderr + b"\n".join(messages)).decode("utf-8", "replace").lower()
log_path = ROOT / "synthetic-start.log"
fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "wb") as output:
    output.write(b"\n".join(messages)[:65536])
print("streamer_socket_observed=" + str(observed).lower())
print("streamer_exit=" + str(process.returncode))
print("stdout_bytes=" + str(len(stdout)))
print("stderr_bytes=" + str(len(stderr)))
print("synthetic_log_messages=" + str(len(messages)))
for name, variants in {
    "configuration": ("configuration", "config"),
    "hardware": ("hardware", "/dev/", "device"),
    "missing_file": ("no such file", "not found", "does not exist"),
    "permission": ("permission denied", "operation not permitted"),
}.items():
    print("diagnostic_" + name + "=" + str(any(value in report for value in variants)).lower())

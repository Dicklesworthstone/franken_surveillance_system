#!/usr/bin/env python3
"""Isolated, synthetic vendor-listener interoperability fixture, never a camera client.

Run only inside caller-created network and IPC namespaces with deletion blocked.
The copied firmware is a lab oracle; no camera, credentials, or network is used.
"""

import os
import pathlib
import re
import shutil
import subprocess
import sys
import time

if len(sys.argv) != 3:
    raise SystemExit("usage: fixture PRIVATE_SCRATCH TEST_BINARY")
scratch = pathlib.Path(sys.argv[1]).resolve(strict=True)
binary = pathlib.Path(sys.argv[2]).resolve(strict=True)
source = pathlib.Path("/data/tmp/fss-unifi-ipc-server-lab-20261116-01")
lab = scratch / "lab"
lab.mkdir(mode=0o700)
shutil.copytree(source / "bin", lab / "bin")
shutil.copytree(source / "lib", lab / "lib")
shutil.copy2(source / "qemu-arm", lab / "qemu-arm")
(lab / "dev").mkdir()
(lab / "var/run/ipc").mkdir(parents=True)
(lab / "var/lock").mkdir()
socket_path = lab / "var/run/ipc/ubnt_streamer"
server = subprocess.Popen(
    ["chroot", str(lab), "/qemu-arm", "/bin/ubnt_ipc_cli", "-l=.*", "-N=ubnt_streamer", "-t=5000"],
    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
)
try:
    deadline = time.monotonic() + 8
    while not socket_path.is_socket():
        if server.poll() is not None:
            raise RuntimeError("firmware listener exited before socket admission")
        if time.monotonic() >= deadline:
            raise TimeoutError("firmware listener did not start")
        time.sleep(0.05)
    env = dict(os.environ, TMPDIR=str(scratch), FSS_SYNTHETIC_IPC_SOCKET=str(socket_path))
    client = subprocess.run(
        [str(binary), "--ignored", "--exact", "unix_request_reaches_isolated_firmware_listener", "--nocapture"],
        env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=12,
    )
finally:
    server.terminate()
    try:
        stdout, stderr = server.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        server.kill()
        stdout, stderr = server.communicate(timeout=5)

observed = stdout.decode("utf-8", "replace")
checks = {
    "rust_test_passed": client.returncode == 0 and "firmware_fixture_response=deadline owner=spent" in client.stdout,
    "listener_function": bool(re.search(r'"functionName"\s*:\s*"GetVideoSettings"', observed)),
    "listener_sender": bool(re.search(r'"from"\s*:\s*"fss_fixture"', observed)),
    "listener_id": bool(re.search(r'"id"\s*:\s*123(?:\D|$)', observed)),
    "listener_nonqueued": bool(re.search(r'"queueIfDestUnavailable"\s*:\s*false', observed)),
}
for key, value in checks.items():
    print(key + "=" + str(value).lower())
print("client_status=" + str(client.returncode))
print("listener_status=" + str(server.returncode))
print("listener_stderr_bytes=" + str(len(stderr)))
if not all(checks.values()):
    print("synthetic_client_output=" + client.stdout[-2000:])
    print("synthetic_client_error=" + client.stderr[-2000:])
    print("synthetic_listener_output=" + observed[-2000:])
    raise SystemExit(1)

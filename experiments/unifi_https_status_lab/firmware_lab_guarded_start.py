#!/usr/bin/env python3
"""Guarded copied-streamer lab startup after an in-namespace synthetic preflight.

This must be PID 1 of new user, PID, mount, IPC, and network namespaces, with
proc mounted for that PID namespace. It exposes no device nodes or real camera
configuration. Firmware and descendants are traced with signal, namespace,
cross-process-write, and deletion syscalls denied. This is a laboratory oracle,
not production software or a claim of physical-camera behavior.
"""

import os
import pathlib
import hashlib
import json
import re
import socket
import subprocess
import sys
import time

from lab_log_pump import LabLogPump

if len(sys.argv) != 4 or os.getpid() != 1:
    raise SystemExit("expected PID-namespace init and private scratch/preflight/chroot paths")
scratch = pathlib.Path(sys.argv[1]).resolve(strict=True)
preflight = pathlib.Path(sys.argv[2]).resolve(strict=True)
root = pathlib.Path(sys.argv[3]).resolve(strict=True)
if root.parent != pathlib.Path("/data/tmp") or not re.fullmatch(
        r"fss-unifi-streamer-chroot-20261116-[0-9]{2}", root.name):
    raise SystemExit("invalid private chroot path")
if preflight.parent != scratch or any((scratch / name).exists() for name in ("preflight.trace", "streamer.trace", "client.trace")):
    raise SystemExit("invalid or previously used private scratch")
for namespace in ("user", "pid", "net", "ipc", "mnt"):
    host = os.environ.get("FSS_HOST_" + namespace.upper() + "NS")
    if not host or os.readlink("/proc/self/ns/" + namespace) == host:
        raise SystemExit("namespace separation not established: " + namespace)

denied = ("kill,tkill,tgkill,rt_sigqueueinfo,rt_tgsigqueueinfo,pidfd_send_signal,"
          "unlink,unlinkat,rmdir,rename,renameat,renameat2,truncate,ftruncate,ptrace,process_vm_writev,pidfd_open,pidfd_getfd,"
          "setns,unshare,mount,umount2,pivot_root")
def traced(trace, command):
    observed = ",socket,connect,bind,listen,accept,accept4,recvfrom,sendto,read,write,readv,writev,close"
    return ["strace", "-f", "--seccomp-bpf", "-s", "1", "-e", "trace=" + denied + observed,
            "-e", "inject=" + denied + ":error=EPERM", "-o", str(trace), *command]

env = dict(os.environ, FSS_EXPECTED_PID_INIT="python3")
check = subprocess.run(traced(scratch / "preflight.trace", ["python3", str(preflight)]),
                       env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                       timeout=12, check=False)
markers = ("synthetic_user_pid_net_ipc_mount_namespaces=separate",
           "synthetic_signal_zero_self_probes=denied_6_of_6",
           "synthetic_nonexistent_unlink=denied", "synthetic_nonexistent_rename=denied", "synthetic_child_signal_probe=denied",
           "firmware_executed=false")
if check.returncode != 0 or not all(marker in check.stdout for marker in markers):
    print("same_namespace_guard_preflight=failed")
    print(check.stdout[-2000:])
    print(check.stderr[-2000:])
    raise SystemExit(1)
print("same_namespace_guard_preflight=passed", flush=True)

test_binary = pathlib.Path("/data/tmp/fss-ipc-streamer-test-20261116-01/test-bin")
expected_test = os.environ.get("FSS_EXPECTED_TEST_SHA256", "")
if not re.fullmatch(r"[0-9a-f]{64}", expected_test):
    raise SystemExit("missing expected test hash")
digest = hashlib.sha256()
with test_binary.open("rb") as incoming:
    for chunk in iter(lambda: incoming.read(1024 * 1024), b""):
        digest.update(chunk)
if digest.hexdigest() != expected_test:
    raise SystemExit("test executable hash mismatch")

if any((root / "dev").iterdir()):
    raise SystemExit("lab device directory is not empty")

def create(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)

create(root / "etc/synthetic.json", b"{}\n")
create(root / "tmp/system.cfg", b"fixture.enabled=0\n")
create(root / "lib/version", b"UVC.gen4s.v4.70.37.0.abcdef.261116.0000\n")
create(root / "lib/semver", b"4.70.37\n")
library = (root / "lib/libubnt_variant_utils.so").read_bytes()
if len(library) > 4 * 1024 * 1024:
    raise SystemExit("lab library exceeds bound")
names = sorted({name.decode("ascii") for name in re.findall(
    rb"(?<![A-Za-z0-9_])feature_[a-z0-9_]{1,64}(?=\x00)", library)})
if "feature_hdr" not in names or len(names) > 256:
    raise SystemExit("synthetic feature inventory refused")
board = ("board.sysid=0x0001\nboard.name=UVC\nboard.shortname=LAB\n"
         "board.hwaddr=000000000000\nboard.reboot=0\nboard.upgrade=0\n"
         "board.videosensor=0\nboard.phycount=1\nboard.revision=1\nboard.hwrev=1\n")
board += "".join(name + "=0\n" for name in names)
create(root / "etc/board.info", board.encode("ascii"))
create(root / "etc/features.conf", json.dumps({name: 0 for name in names}, sort_keys=True).encode() + b"\n")
print("synthetic_feature_fields=" + str(len(names)), flush=True)
log = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
log.bind(str(root / "dev/log"))
log.setblocking(False)
pump = LabLogPump(log)
command = ["chroot", str(root), "/qemu-arm", "/bin/ubnt_streamer", "-c=/etc/synthetic.json"]
process = subprocess.Popen(traced(scratch / "streamer.trace", command), stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={"PATH": "/bin:/usr/bin"})
observed = False
forced_stop = False
messages = pump.messages
client = None
client_process = None
try:
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline and process.poll() is None:
        pump.drain()
        if (root / "var/run/ipc/ubnt_streamer").is_socket():
            observed = True
            pump.pause(4)
            print("synthetic_listener_initialization_wait_seconds=4", flush=True)
            if process.poll() is not None:
                print("streamer_exited_before_client=true", flush=True)
                break
            client_env = {"PATH": "/bin:/usr/bin", "TMPDIR": "/data/tmp",
                          "FSS_SYNTHETIC_IPC_SOCKET": str(root / "var/run/ipc/ubnt_streamer")}
            client_process = subprocess.Popen(traced(scratch / "client.trace", [str(test_binary), "--ignored", "--exact",
                "unix_request_reaches_isolated_firmware_streamer", "--nocapture", "--test-threads=1"]),
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=client_env)
            client = pump.wait(client_process, 8)
            break
        time.sleep(0.05)
finally:
    if client_process is not None:
        if client_process.poll() is None:
            client_process.terminate()
        try:
            client_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            client_process.kill()
            client_process.wait(timeout=5)
        client_process.stdout.close()
        client_process.stderr.close()
    if process.poll() is None:
        forced_stop = True
        process.terminate()
    try:
        stdout, stderr = process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate(timeout=5)
    pump.drain()
    log.close()

fd = os.open(scratch / "synthetic-start.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "wb") as output:
    output.write(b"\n".join(messages)[:65536])
trace = (scratch / "streamer.trace").read_text(errors="replace")
signal_lines = [line for line in trace.splitlines() if "(INJECTED)" in line
                and any(" " + name + "(" in line for name in
                        ("kill", "tkill", "tgkill", "rt_sigqueueinfo", "rt_tgsigqueueinfo", "pidfd_send_signal"))]
print("streamer_socket_observed=" + str(observed).lower())
print("tracer_exit=" + str(process.returncode))
print("forced_stop=" + str(forced_stop).lower())
print("synthetic_log_messages=" + str(len(messages)))
print("synthetic_log_messages_omitted=" + str(pump.omitted_messages))
print("denied_signal_syscalls=" + str(len(signal_lines)))
print("stdout_bytes=" + str(len(stdout)))
print("stderr_bytes=" + str(len(stderr)))
print("rust_client_exit=" + (str(client.returncode) if client is not None else "not_run"))
if client is not None:
    print("synthetic_rust_client_stdout=" + client.stdout[-3000:].decode(errors="replace"))
    print("synthetic_rust_client_stderr=" + client.stderr[-2000:].decode(errors="replace"))
    print("synthetic_rust_client_output_omitted=" + json.dumps(client.omitted_bytes))
raise SystemExit(0 if client is not None and client.returncode == 0 else 1)

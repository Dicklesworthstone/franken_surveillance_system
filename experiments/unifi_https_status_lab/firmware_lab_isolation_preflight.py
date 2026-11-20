#!/usr/bin/env python3
"""Synthetic Linux namespace and syscall-denial preflight; never runs firmware.

The caller supplies namespace identities measured outside the test and runs
this as a child of the intended traced PID-namespace init. Signal probes use
only signal zero against this process; the unlink probe targets a nonexistent
procfs descriptor. No external process is signalled and no file is removed.
"""

import ctypes
import errno
import os
import pathlib

if os.uname().machine != "x86_64":
    raise SystemExit("unsupported preflight architecture")
for namespace in ("user", "pid", "net", "ipc", "mnt"):
    host = os.environ.get("FSS_HOST_" + namespace.upper() + "NS")
    actual = os.readlink("/proc/self/ns/" + namespace)
    if not host or actual == host:
        raise SystemExit("namespace separation not established: " + namespace)
expected_init = os.environ.get("FSS_EXPECTED_PID_INIT", "strace")
parent_comm = pathlib.Path("/proc", str(os.getppid()), "comm").read_text().strip()
if (os.getpid() <= 1 or os.getppid() < 1 or parent_comm != "strace"
        or expected_init not in ("strace", "python3")
        or pathlib.Path("/proc/1/comm").read_text().strip() != expected_init):
    raise SystemExit("unexpected PID namespace or tracer ancestry")
if not pathlib.Path("/proc/self/status").read_text().split("NSpid:", 1)[1].splitlines()[0].split():
    raise SystemExit("missing PID namespace evidence")

try:
    os.kill(os.getpid(), 0)
except OSError as error:
    if error.errno != errno.EPERM:
        raise
else:
    raise SystemExit("kill syscall was not denied")

libc = ctypes.CDLL(None, use_errno=True)
for name, number, arguments in (
    ("tkill", 200, (os.getpid(), 0)),
    ("tgkill", 234, (os.getpid(), os.getpid(), 0)),
    ("rt_sigqueueinfo", 129, (os.getpid(), 0, 0)),
    ("rt_tgsigqueueinfo", 297, (os.getpid(), os.getpid(), 0, 0)),
    ("pidfd_send_signal", 424, (-1, 0, 0, 0)),
):
    ctypes.set_errno(0)
    result = libc.syscall(number, *arguments)
    if result != -1 or ctypes.get_errno() != errno.EPERM:
        raise SystemExit(name + " syscall was not denied")

try:
    os.unlink("/proc/self/fd/999999999")
except OSError as error:
    if error.errno != errno.EPERM:
        raise
else:
    raise SystemExit("unlink syscall was not denied")

try:
    os.rename("/proc/self/fd/999999999", "/proc/self/fd/999999998")
except OSError as error:
    if error.errno != errno.EPERM:
        raise
else:
    raise SystemExit("rename syscall was not denied")

child = os.fork()
if child == 0:
    try:
        os.kill(os.getpid(), 0)
    except OSError as error:
        os._exit(0 if error.errno == errno.EPERM else 2)
    os._exit(1)
_, child_status = os.waitpid(child, 0)
if not os.WIFEXITED(child_status) or os.WEXITSTATUS(child_status) != 0:
    raise SystemExit("signal guard did not follow child")

print("synthetic_user_pid_net_ipc_mount_namespaces=separate")
print("synthetic_signal_zero_self_probes=denied_6_of_6")
print("synthetic_nonexistent_unlink=denied")
print("synthetic_nonexistent_rename=denied")
print("synthetic_child_signal_probe=denied")
print("firmware_executed=false")

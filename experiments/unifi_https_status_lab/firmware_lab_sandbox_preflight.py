#!/usr/bin/env python3
"""PID-namespace-init rehearsal of the firmware lab guard; runs no firmware.

Run only inside the new user, PID, mount, network and IPC namespaces. It
launches the synthetic preflight as a traced child and refuses if any required
observation is missing. Paths must be caller-created private scratch paths.
"""

import os
import pathlib
import subprocess
import sys

if len(sys.argv) != 3 or os.getpid() != 1:
    raise SystemExit("expected PID-namespace init and two scratch paths")
scratch = pathlib.Path(sys.argv[1]).resolve(strict=True)
preflight = pathlib.Path(sys.argv[2]).resolve(strict=True)
if preflight.parent != scratch or (scratch / "guard.trace").exists():
    raise SystemExit("invalid or previously used scratch")
for namespace in ("user", "pid", "net", "ipc", "mnt"):
    host = os.environ.get("FSS_HOST_" + namespace.upper() + "NS")
    if not host or os.readlink("/proc/self/ns/" + namespace) == host:
        raise SystemExit("namespace separation not established: " + namespace)

denied = ("kill,tkill,tgkill,rt_sigqueueinfo,rt_tgsigqueueinfo,pidfd_send_signal,"
          "unlink,unlinkat,rmdir,rename,renameat,renameat2,truncate,ftruncate,ptrace,process_vm_writev,pidfd_open,pidfd_getfd,"
          "setns,unshare,mount,umount2,pivot_root")
args = ["strace", "-f", "--seccomp-bpf", "-e", "trace=" + denied,
        "-e", "inject=" + denied + ":error=EPERM", "-o", str(scratch / "guard.trace"),
        "python3", str(preflight)]
env = dict(os.environ, FSS_EXPECTED_PID_INIT="python3")
result = subprocess.run(args, env=env, stdin=subprocess.DEVNULL,
                        capture_output=True, text=True, timeout=12, check=False)
markers = ("synthetic_user_pid_net_ipc_mount_namespaces=separate",
           "synthetic_signal_zero_self_probes=denied_6_of_6",
           "synthetic_nonexistent_unlink=denied", "synthetic_nonexistent_rename=denied", "synthetic_child_signal_probe=denied",
           "firmware_executed=false")
if result.returncode != 0 or not all(marker in result.stdout for marker in markers):
    print("guard_preflight=failed exit=" + str(result.returncode))
    print(result.stdout[-2000:])
    print(result.stderr[-2000:])
    raise SystemExit(1)
print("same_namespace_guard_preflight=passed")
print("pid_init=controlled_supervisor")
print("firmware_executed=false")

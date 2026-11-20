#!/usr/bin/env python3
"""Create a fresh, device-free chroot using only previously copied firmware.

This laboratory helper creates files exclusively and does not run the image.
The caller must separately isolate network and IPC and block deletion before
starting anything inside the chroot. It is not production camera software.
"""

import hashlib
import os
import pathlib
import shutil
import sys

if len(sys.argv) != 2 or sys.argv[1] not in ("01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12", "15", "16"):
    raise SystemExit("expected an explicit unused lab sequence")
ROOT = pathlib.Path("/data/tmp/fss-unifi-streamer-chroot-20261116-" + sys.argv[1])
BASE = pathlib.Path("/data/tmp/fss-unifi-ipc-server-lab-20261116-01")
PRIVATE = pathlib.Path("/data/unifi-g4-recorder/fss-ssh-observe-20261116-01")
COPIED = [pathlib.Path("/data/tmp/fss-unifi-lib-copy-20261116-02"),
          pathlib.Path("/data/tmp/fss-unifi-lib-copy-20261116-03")]
EXPECTED = "30e9bd2cf236a0f0cfe4c86e458d9fec14a3c41059565f3bdb5450bfbbf12013"


def copy_exclusive(source, target, executable=False):
    if not source.is_file() or source.stat().st_size > 16 * 1024 * 1024:
        raise RuntimeError("invalid source file")
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700 if executable else 0o600)
    with source.open("rb") as incoming, os.fdopen(fd, "wb") as output:
        shutil.copyfileobj(incoming, output, 1024 * 1024)


os.mkdir(ROOT, 0o700)
for name in ("bin", "lib", "dev", "etc", "tmp", "var"):
    (ROOT / name).mkdir()
(ROOT / "var/run/ipc").mkdir(parents=True)
(ROOT / "var/lock").mkdir()
for source in sorted((BASE / "lib").iterdir()):
    copy_exclusive(source, ROOT / "lib" / source.name)
copy_exclusive(PRIVATE / "libubnt_encoder.so", ROOT / "lib/libubnt_encoder.so")
for directory in COPIED:
    for source in sorted(directory.glob("*.so*")):
        copy_exclusive(source, ROOT / "lib" / source.name)
if hashlib.sha256((PRIVATE / "ubnt_streamer.elf").read_bytes()).hexdigest() != EXPECTED:
    raise RuntimeError("streamer binary changed")
copy_exclusive(PRIVATE / "ubnt_streamer.elf", ROOT / "bin/ubnt_streamer", executable=True)
copy_exclusive(BASE / "qemu-arm", ROOT / "qemu-arm", executable=True)
print("isolated_lab_prepared=true")
print("streamer_sha256=" + EXPECTED)
print("library_count=" + str(sum(1 for _ in (ROOT / "lib").iterdir())))
print("device_nodes=0")

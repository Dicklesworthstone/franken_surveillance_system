#!/usr/bin/env python3
"""Drive c660_post_shell.sh with a fake shell, puller and finder.

What the harness must guarantee: no shell means no ROP line, an incomplete pull means the same,
and a pulled build whose numbers differ from the offline baseline stops with the mismatch shown
instead of printing last week's addresses.

  python3 tests/c660_post_shell_test.py
"""
import json
import os
import stat
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
POST_SHELL = os.path.join(HERE, "..", "deliverables", "scripts", "c660_post_shell.sh")

GOOD = {"sink": {"buffer_offset": 0x318, "pc_offset": 0x424}, "pop": 0x24462,
        "pivot": {"addr": 0x28514e, "kind": "blx", "r1_offset": 0}, "system": 0x15928}
BAD = dict(GOOD, pop=0x20004)

failures = []


def check(name, cond, detail=""):
    print("%s %s%s" % ("ok " if cond else "FAIL", name,
                       " — %r" % (detail,) if detail and not cond else ""))
    if not cond:
        failures.append(name)


def stub(path, body, shell=True):
    with open(path, "w") as fh:
        fh.write("#!/bin/bash\n" + body if shell else body)
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
    return path


def run(tmp, shell_ok, finder_json, main_bytes=b"\x7fELF"):
    out = os.path.join(tmp, "out")
    os.makedirs(out, exist_ok=True)
    # the harness runs the puller with python3, like the real tapo_post.py
    pull = stub(os.path.join(tmp, "pull"),
                'import os\n'
                'os.makedirs("%s", exist_ok=True)\n'
                'open("%s/bin_main", "w").write("x" * 64)\n' % (out, out))
    finder = stub(os.path.join(tmp, "finder"),
                  'import sys, json\nprint(json.dumps(%r))\n' % finder_json, shell=False)
    nc = stub(os.path.join(tmp, "nc"), "exit %d\n" % (0 if shell_ok else 1))
    env = dict(os.environ, OUT=out, WAIT="2", POST=pull, FINDER=finder, NC_CMD=nc)
    p = subprocess.run([POST_SHELL, "192.168.4.71"], env=env, capture_output=True, text=True,
                       timeout=60)
    return p.returncode, p.stdout


def main():
    with tempfile.TemporaryDirectory() as tmp:
        print("no shell")
        rc, out = run(tmp, False, GOOD)
        check("exit 1, no ROP line", rc == 1 and "tapo_connectap_rop.py" not in out, (rc, out))

    with tempfile.TemporaryDirectory() as tmp:
        print("match")
        rc, out = run(tmp, True, GOOD)
        check("exit 0", rc == 0, (rc, out))
        check("ROP line carries the baseline",
              "--offset 1060" in out and "--pop 0x24462" in out, out)
        check("target host is the one given", "192.168.4.71" in out, out)

    with tempfile.TemporaryDirectory() as tmp:
        print("mismatch")
        rc, out = run(tmp, True, BAD)
        check("exit 3", rc == 3, (rc, out))
        check("both sides shown", "MISMATCH pop" in out and "0x20004" in out, out)
        check("no ROP line", "tapo_connectap_rop.py" not in out, out)

    if failures:
        print("\n%d failure(s): %s" % (len(failures), ", ".join(failures)))
        return 1
    print("\nall checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

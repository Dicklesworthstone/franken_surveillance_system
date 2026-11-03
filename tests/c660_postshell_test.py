#!/usr/bin/env python3
"""Contract test for the C660 post-shell chain (fss-hzvri).

The C660 chain is derived offline from the BCL1 initramfs, so the unit is never asked to re-derive
it. That moves the whole risk onto one gate: if the pulled `/bin/main` is not the decoded build,
the constants are somebody else's addresses. Everything here pins that gate and the order that
makes the one-shot shell usable:

  identity   sha256(/bin/main) is compared against the decoded binary and a mismatch stops before
             the ROP; the pinned hash and the four chain numbers are literal in the script
  order      pull -> hash gate -> ROP -> RTSP enable -> RTSP verify
  route      the per-session host route (§1) is added before any connect

  python3 tests/c660_postshell_test.py
"""
import hashlib
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
POST = os.path.join(HERE, "..", "deliverables", "scripts", "c660_postshell.sh")
WATCH = os.path.join(HERE, "..", "deliverables", "scripts", "c660_convert_watch.sh")
MAC = "50:3d:d1:2f:49:b9"
PINNED_HASH = "bf72d72a0e120614c15c3ca99de0b9b4ec40571c9a02b1b37f805dae06bcd217"
REAL_MAIN = os.environ.get("C660_MAIN", "/tmp/c660x/bin/main")

FAILURES = []


def check(name, cond, detail=""):
    print("  [%s] %s%s" % ("ok " if cond else "FAIL", name,
                           " — %s" % detail if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


def exe(path, body):
    open(path, "w").write(body)
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
    return path


def test_static_pin(td):
    print("script carries the decoded identity and chain:")
    src = open(POST).read()
    check("sha256 pin present", PINNED_HASH in src)
    for name, want in (("OFFSET", "0x424"), ("POP", "0x24462"),
                       ("PIVOT", "0x28514e"), ("SYSTEM", "0x15928")):
        m = re.search(r"^%s=(\S+)$" % name, src, re.M)
        check("%s is %s" % (name, want), bool(m) and m.group(1) == want, m.group(0) if m else "absent")
    check("no on-unit re-derivation",
          "FINDER" not in src and not re.search(r"python3?\s+[^\n]*find_chain\.py", src))


def test_real_binary_identity(td):
    print("pinned hash is the decoded binary:")
    if not os.path.isfile(REAL_MAIN):
        print("  [skip] %s absent (decode c660_fw.bin.dec block 5 first)" % REAL_MAIN)
        return
    blob = open(REAL_MAIN, "rb").read()
    check("decoded /bin/main hashes to the pin",
          hashlib.sha256(blob).hexdigest() == PINNED_HASH)
    check("decoded /bin/main is ARM ET_EXEC",
          blob[:4] == b"\x7fELF" and int.from_bytes(blob[16:18], "little") == 2)


class FakeShell:
    def __init__(self):
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.port = self.srv.getsockname()[1]
        self.srv.listen(8)
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            c.sendall(b"$ ")
            c.close()

    def close(self):
        self.srv.close()


def run_chain(td, payload, order, want_hash):
    shell = FakeShell()
    outdir = os.path.join(td, "pane")
    post = exe(os.path.join(td, "post.py"), r"""#!/usr/bin/env python3
import os, sys
args = sys.argv[1:]
out = os.environ["OUTDIR"]
open(os.environ["ORDER"], "a").write("post %%s\n" %% " ".join(args))
if "--pull" in args:
    open(os.path.join(out, "proc_mtd"), "w").write("mtd0: 00040000 00010000\n")
    open(os.path.join(out, "bin_main"), "wb").write(%r)
elif "--rtsp-verify" in args:
    print("554 DESCRIBE 200")
sys.exit(0)
""" % payload)
    rop = exe(os.path.join(td, "rop.py"), r"""#!/usr/bin/env python3
import os, sys
open(os.environ["ORDER"], "a").write("rop %s\n" % " ".join(sys.argv[1:]))
""")
    route = exe(os.path.join(td, "route.sh"), """#!/bin/bash
echo "route $*" >> %s
""" % order)
    env = dict(os.environ)
    env.update({"OUTDIR": outdir, "ORDER": order, "SHELL_PORT": str(shell.port),
                "WAIT": "10", "POST_TOOL": post, "ROP_TOOL": rop, "ROUTE_CMD": route,
                "PY": sys.executable, "RTSP_WAIT": "0"})
    if want_hash is not None:
        env["WANT_HASH"] = want_hash
    r = subprocess.run(["bash", POST, "127.0.0.1"], capture_output=True, text=True,
                       timeout=60, env=env)
    shell.close()
    return r, outdir, order


def test_chain_order(td):
    print("chain: route, order, pinned arguments, verification:")
    payload = b"\x7fELF" + b"c660" * 32
    want = hashlib.sha256(payload).hexdigest()
    order = os.path.join(td, "order")
    r, outdir, _ = run_chain(td, payload, order, want)
    check("chain completes", r.returncode == 0, "rc=%d %s" % (r.returncode, r.stdout[-400:]))
    steps = [ln.split()[0] for ln in open(order).read().splitlines()]
    check("host route first",
          open(order).read().splitlines()[0] == "route 127.0.0.1 192.168.4.1")
    check("pull before the ROP", steps[1:3] == ["post", "rop"], repr(steps))
    check("RTSP writes after the ROP", steps[-2:] == ["post", "post"], repr(steps))
    rop = [ln for ln in open(order).read().splitlines() if ln.startswith("rop")][0]
    for want_arg in ("--offset 0x424", "--pop 0x24462", "--pivot 0x28514e", "--system 0x15928"):
        check("ROP carries %s" % want_arg, want_arg in rop, rop)
    cred = open(os.path.join(outdir, "rtsp_cred.txt")).read().split()
    check("credential stored once", len(cred) == 2 and cred[0] == "fssuser", repr(cred))
    verify = [ln for ln in open(order).read().splitlines() if "--rtsp-verify" in ln][0]
    check("verification uses the stored password", cred[1] in verify, verify)


def test_hash_mismatch(td):
    print("chain: a different /bin/main stops before the ROP:")
    order = os.path.join(td, "order2")
    r, outdir, _ = run_chain(td, b"\x7fELF" + b"other-build", order, None)
    check("mismatch exits 4", r.returncode == 4, "rc=%d" % r.returncode)
    check("both hashes reported", "decoded image" in r.stdout and "sha256(/bin/main)" in r.stdout)
    check("no ROP fired", "rop" not in open(order).read())
    check("log names the re-derivation", "re-derive" in r.stdout)


def test_empty_pull(td):
    print("chain: an empty pull stops before the gate:")
    shell = FakeShell()
    order = os.path.join(td, "order3")
    post = exe(os.path.join(td, "post3.py"), """#!/usr/bin/env python3
import os, sys
open(os.environ["ORDER"], "a").write("post\\n")
if "--pull" in sys.argv:
    open(os.path.join(os.environ["OUTDIR"], "proc_mtd"), "w").write("x\\n")
""")
    env = dict(os.environ)
    env.update({"OUTDIR": os.path.join(td, "pane3"), "ORDER": order, "SHELL_PORT": str(shell.port),
                "WAIT": "10", "POST_TOOL": post, "ROP_TOOL": "/bin/false",
                "ROUTE_CMD": "/bin/true", "PY": sys.executable})
    r = subprocess.run(["bash", POST, "127.0.0.1"], capture_output=True, text=True,
                       timeout=60, env=env)
    shell.close()
    check("empty /bin/main exits 2", r.returncode == 2, "rc=%d" % r.returncode)


def run_watch(td, arp_file, port, chain, deadline="0", force=False):
    env = dict(os.environ)
    env.update({"MAC": MAC, "LOG": os.path.join(td, "w.log"),
                "STATE": os.path.join(td, "w.state"), "POLL": "0.1",
                "WATCH_DEADLINE": deadline, "ARP_CMD": "cat " + arp_file,
                "PING": "true", "POSTSHELL": chain,
                "SHELL_PORT": str(port or 4444)})
    if force:
        env["FORCE"] = "1"
    return subprocess.run(["bash", WATCH], capture_output=True, text=True, timeout=30, env=env)


def test_convert_watch(td):
    print("conversion watcher: gates on the MAC, fires once, then stands down:")
    calls = os.path.join(td, "chain.calls")
    chain = exe(os.path.join(td, "chain.sh"), "#!/bin/bash\necho \"$1\" >> %s\n" % calls)
    arp = os.path.join(td, "arp.txt")
    # another camera owns .4.71 in this fixture; ours is loopback so the fake shell can bind it
    open(arp, "w").write("? (192.168.4.71) at 8c:4f:0:22:e3:2c on en1 ifscope [ethernet]\n"
                         "? (127.0.0.1) at %s on lo0 ifscope [ethernet]\n" % MAC)

    r = run_watch(td, arp, None, chain, deadline="0.03")
    check("no listener -> no conversion", r.returncode == 4, "rc=%d" % r.returncode)
    check("chain untouched without a shell", not os.path.exists(calls))

    shell = FakeShell()
    r = run_watch(td, arp, shell.port, chain)
    shell.close()
    check("shell -> converts", r.returncode == 0, "rc=%d %s" % (r.returncode, r.stdout[-300:]))
    got = open(calls).read().split() if os.path.exists(calls) else []
    check("chain got the MAC-resolved address, not the foreign one", got == ["127.0.0.1"], repr(got))
    state = open(os.path.join(td, "w.state")).read()
    check("state records the completed conversion",
          state.startswith("done 127.0.0.1"), repr(state))

    r = run_watch(td, arp, None, chain)
    check("a restart does not convert twice", r.returncode == 3, "rc=%d" % r.returncode)
    check("still exactly one chain run", len(open(calls).read().split()) == 1)


def main():
    for name, fn in (("static pin", test_static_pin),
                     ("real binary", test_real_binary_identity),
                     ("chain order", test_chain_order),
                     ("hash mismatch", test_hash_mismatch),
                     ("empty pull", test_empty_pull),
                     ("convert watcher", test_convert_watch)):
        with tempfile.TemporaryDirectory() as td:
            try:
                fn(td)
            except Exception as exc:
                check("%s raised" % name, False, repr(exc))
    print("\n%d failure(s)" % len(FAILURES))
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())

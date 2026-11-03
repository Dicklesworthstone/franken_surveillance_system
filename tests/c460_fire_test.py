#!/usr/bin/env python3
"""Contract test for the C460 fire watcher and the post-shell chain (fss-tapo-460-root-zhhtf).

Two properties decide whether the armed shot is safe to leave running unattended, and both are
tested here without hardware:

  presence + one-shot   the watcher must fire only on ARP-resolved-by-MAC AND ICMP (a dozing unit
                        keeps an ARP entry and serves nothing), exactly once per boot, and it must
                        find the unit after DHCP moved it.
  chain order           the shell is one-shot, so the artifacts that only root can give are pulled
                        before anything can restart the crashed process; the ROP is installed from
                        the unit's own /bin/main before the RTSP writes; the RTSP account is then
                        *verified*, not assumed.

  python3 tests/c460_fire_test.py
"""
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(HERE, "..", "deliverables", "scripts")
FIRE = os.path.join(SCRIPTS, "c460_fire.sh")
POST = os.path.join(SCRIPTS, "c460_postshell.sh")
MAC = "50:3d:d1:e3:e2:07"

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


def arp_fixture(td, mac, ip, complete=True):
    """One line in the census form the resolver parses (`arp -an`)."""
    p = os.path.join(td, "arp.txt")
    entry = "? (%s) at %s on en1 ifscope [ethernet]" % (ip, mac)
    if not complete:
        entry = "? (%s) at (incomplete) on en1 ifscope [ethernet]" % ip
    open(p, "w").write("? (192.168.4.1) at 48:dd:0c:c9:ec:0d on en1 ifscope [ethernet]\n"
                       + entry + "\n")
    return p


def run_fire(td, arp_file, guard, postshell, deadline="0", extra_env=None):
    env = dict(os.environ)
    env.update({
        "MAC": MAC, "ADDR": "0xbef8b000", "OFFSET": "1060",
        "LOG": os.path.join(td, "fire.log"), "STATE": os.path.join(td, "fire.state"),
        "POLL": "0.1", "GUARD_GAP": "0", "WATCH_DEADLINE": deadline,
        "ARP_CMD": "cat " + arp_file, "PING": "true",
        "GUARD": guard, "POSTSHELL": postshell, "PY": sys.executable,
    })
    env.update(extra_env or {})
    return subprocess.run(["bash", FIRE], capture_output=True, text=True, timeout=30, env=env)


def test_presence_and_one_shot(td):
    print("watcher: MAC presence, one shot, hang-hit address:")
    calls = os.path.join(td, "guard.calls")
    post = os.path.join(td, "post.calls")
    guard = exe(os.path.join(td, "guard.py"), r"""#!/usr/bin/env python3
import sys
open(%r, "a").write(" ".join(sys.argv[1:]) + "\n")
print("SHELL on 192.168.4.33:4444")
""" % calls)
    postshell = exe(os.path.join(td, "post.sh"), "#!/bin/bash\necho \"$1\" >> %s\n" % post)

    # incomplete entry for the same MAC is NOT presence
    r = run_fire(td, arp_fixture(td, MAC, "192.168.4.33", complete=False), guard, postshell,
                 deadline="0.03")
    check("incomplete ARP entry holds fire", r.returncode == 4, "rc=%d %s" % (r.returncode, r.stdout))
    check("no payload on an incomplete entry", not os.path.exists(calls))

    # DHCP moved the unit: the watcher must follow the MAC, not a remembered IP
    r = run_fire(td, arp_fixture(td, MAC, "192.168.4.77"), guard, postshell)
    check("fires once on ARP+ICMP", r.returncode == 0, "rc=%d %s" % (r.returncode, r.stdout))
    lines = open(calls).read().splitlines() if os.path.exists(calls) else []
    check("exactly one payload", len(lines) == 1, repr(lines))
    check("payload targets the MAC-resolved address",
          bool(lines) and "--host 192.168.4.77" in lines[0], repr(lines))
    check("payload uses the hang-hit address and offset",
          bool(lines) and "--addr 0xbef8b000" in lines[0] and "--offset 1060" in lines[0],
          repr(lines))
    check("state records the shell", "shell" in open(os.path.join(td, "fire.state")).read())
    check("post-shell chain ran with that address",
          os.path.exists(post) and open(post).read().strip() == "192.168.4.77")

    r = run_fire(td, arp_fixture(td, MAC, "192.168.4.77"), guard, postshell)
    check("a restart does not re-fire", r.returncode == 3, "rc=%d" % r.returncode)
    check("still exactly one payload", len(open(calls).read().splitlines()) == 1)

    r = run_fire(td, arp_fixture(td, MAC, "192.168.4.77"), guard, postshell,
                 extra_env={"FORCE": "1"})
    check("FORCE re-arms after a real power cycle", r.returncode == 0
          and len(open(calls).read().splitlines()) == 2)


class FakeShell:
    """Accept :4444 the way the bind shell does: one accept, then answer line-wise."""

    def __init__(self):
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.port = self.srv.getsockname()[1]
        self.srv.listen(8)
        self.stop = False
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while not self.stop:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            c.sendall(b"$ ")
            c.close()

    def close(self):
        self.stop = True
        self.srv.close()


def test_chain_order(td):
    print("post-shell chain: order, arguments, verification:")
    shell = FakeShell()
    outdir = os.path.join(td, "pane")
    order = os.path.join(td, "order")
    payload = os.path.join(td, "bin_main")

    post = exe(os.path.join(td, "post.py"), r"""#!/usr/bin/env python3
import os, sys
args = sys.argv[1:]
out = os.environ["OUTDIR"]
open(os.environ["ORDER"], "a").write("post %s\n" % " ".join(args))
if "--pull" in args:
    open(os.path.join(out, "proc_mtd"), "w").write("mtd0: 00040000 00010000\n")
    open(os.path.join(out, "bin_main"), "wb").write(b"\x7fELF" + b"\0" * 64)
elif "--rtsp-verify" in args:
    print("554 DESCRIBE 200")
sys.exit(0)
""")
    chain = exe(os.path.join(td, "chain.py"), r"""#!/usr/bin/env python3
import sys
print("tapo_connectap_rop.py <host> --offset 0x424 --pop 0x20004 --pivot 0xe1080 --system 0x1b468")
""")
    rop = exe(os.path.join(td, "rop.py"), r"""#!/usr/bin/env python3
import os, sys
open(os.environ["ORDER"], "a").write("rop %s\n" % " ".join(sys.argv[1:]))
""")

    env = dict(os.environ)
    env.update({"OUTDIR": outdir, "ORDER": order, "SHELL_PORT": str(shell.port),
                "WAIT": "10", "CHAIN": chain, "POST_TOOL": post, "ROP_TOOL": rop,
                "PY": sys.executable, "OBJDUMP": "true", "RTSP_WAIT": "0"})
    r = subprocess.run(["bash", POST, "127.0.0.1"], capture_output=True, text=True,
                       timeout=60, env=env)
    shell.close()

    check("chain completes", r.returncode == 0, "rc=%d %s" % (r.returncode, r.stdout[-400:]))
    steps = [ln.split()[0] for ln in open(order).read().splitlines()]
    check("pull precedes the ROP", steps[:2] == ["post", "rop"], repr(steps))
    check("RTSP writes come after the ROP", steps[-2:] == ["post", "post"], repr(steps))
    check("pull ran before any derivation", "--pull" in open(order).read().splitlines()[0])
    rop_args = [ln for ln in open(order).read().splitlines() if ln.startswith("rop")][0]
    for want in ("--offset 0x424", "--pop 0x20004", "--pivot 0xe1080", "--system 0x1b468"):
        check("ROP carries %s" % want, want in rop_args, rop_args)
    cred = open(os.path.join(outdir, "rtsp_cred.txt")).read().split()
    check("credential stored once", len(cred) == 2 and cred[0] == "fssuser", repr(cred))
    verify = [ln for ln in open(order).read().splitlines() if "--rtsp-verify" in ln][0]
    check("verification uses the stored password", cred[1] in verify, verify)


def test_chain_real_derivation(td):
    """The chain step must work on real disassembly, not only on a canned argument line."""
    print("post-shell chain: real find_chain over a synthetic ARM /bin/main:")
    try:
        import tapo_gadget_test as gadget
    except ImportError:
        check("gadget fixture importable", False)
        return
    if not (gadget.AS and gadget.LD):
        print("  [skip] arm-none-eabi binutils not installed")
        return
    elf = gadget.build_fixture(td)
    shell = FakeShell()
    outdir = os.path.join(td, "pane3")
    order = os.path.join(td, "order3")
    blob = open(elf, "rb").read()
    post = exe(os.path.join(td, "post3.py"), r"""#!/usr/bin/env python3
import os, sys
open(os.environ["ORDER"], "a").write("post\n")
if "--pull" in sys.argv:
    open(os.path.join(os.environ["OUTDIR"], "proc_mtd"), "w").write("mtd0: 00040000 00010000\n")
    open(os.path.join(os.environ["OUTDIR"], "bin_main"), "wb").write(%r)
""" % blob)
    rop = exe(os.path.join(td, "rop3.py"), r"""#!/usr/bin/env python3
import os, sys
open(os.environ["ORDER"], "a").write("rop %s\n" % " ".join(sys.argv[1:]))
""")
    env = dict(os.environ)
    env.update({"OUTDIR": outdir, "ORDER": order, "SHELL_PORT": str(shell.port), "WAIT": "10",
                "POST_TOOL": post, "ROP_TOOL": rop, "PY": sys.executable})
    r = subprocess.run(["bash", POST, "127.0.0.1", "--skip-rtsp"], capture_output=True,
                       text=True, timeout=60, env=env)
    shell.close()
    check("real derivation reaches the ROP", r.returncode == 0,
          "rc=%d %s" % (r.returncode, r.stdout[-300:]))
    lines = [ln for ln in open(order).read().splitlines() if ln.startswith("rop")]
    args = lines[0] if lines else ""
    for want in ("--offset", "--pop", "--pivot", "--system"):
        check("derived %s" % want, want in args, args)
    check("no NOT FOUND placeholder", "NOT" not in args, args)


def test_chain_empty_pull(td):
    print("post-shell chain: an empty pull stops before the ROP:")
    shell = FakeShell()
    outdir = os.path.join(td, "pane2")
    order = os.path.join(td, "order2")
    post = exe(os.path.join(td, "post2.py"), r"""#!/usr/bin/env python3
import os, sys
open(os.environ["ORDER"], "a").write("post\n")
if "--pull" in sys.argv:
    open(os.path.join(os.environ["OUTDIR"], "proc_mtd"), "w").write("x\\n")
""")
    rop = exe(os.path.join(td, "rop2.py"), r"""#!/usr/bin/env python3
open(__import__("os").environ["ORDER"], "a").write("rop\\n")
""")
    env = dict(os.environ)
    env.update({"OUTDIR": outdir, "ORDER": order, "SHELL_PORT": str(shell.port), "WAIT": "10",
                "CHAIN": "/bin/true", "POST_TOOL": post, "ROP_TOOL": rop, "PY": sys.executable})
    r = subprocess.run(["bash", POST, "127.0.0.1"], capture_output=True, text=True,
                       timeout=60, env=env)
    shell.close()
    check("empty /bin/main exits 2", r.returncode == 2, "rc=%d" % r.returncode)
    check("no ROP on an empty pull", "rop" not in open(order).read())


def main():
    for name, fn in (("presence/one-shot", test_presence_and_one_shot),
                     ("chain order", test_chain_order),
                     ("real derivation", test_chain_real_derivation),
                     ("empty pull", test_chain_empty_pull)):
        with tempfile.TemporaryDirectory() as td:
            try:
                fn(td)
            except Exception as exc:  # a harness error is a failure, not a pass
                check("%s raised" % name, False, repr(exc))
    print("\n%d failure(s)" % len(FAILURES))
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())

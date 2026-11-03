#!/usr/bin/env python3
"""Drive c660_sweep_watch.sh with fake ARP/ICMP/harness and check the state machine.

The watcher gates a one-shot root attempt, so the properties that matter are: it fires only on
real presence (ARP *and* ICMP), it walks downward in batches with the resume address persisted,
it stops on a hang, it never mistakes an old HANG line for a new hit, and the per-batch brute
index is reset (a stale index makes the next batch fire nothing).

  python3 tests/c660_sweep_watch_test.py
"""
import os
import re
import stat
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
WATCH = os.path.join(HERE, "..", "deliverables", "scripts", "c660_sweep_watch.sh")
MAC = "50:3d:d1:2f:49:b9"

failures = []


def check(name, cond, detail=""):
    print("%s %s%s" % ("ok " if cond else "FAIL", name,
                       " — %r" % (detail,) if detail and not cond else ""))
    if not cond:
        failures.append(name)


def stub(path, body, exe="/bin/bash"):
    with open(path, "w") as fh:
        fh.write("#!%s\n" % exe + body)
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
    return path


ARP_MATCH = ('echo "? (192.168.4.71) at 50:3d:d1:2f:49:b9 on en0 ifscope [ethernet]"\n'
             'echo "? (192.168.4.99) at aa:20:13:00:ee:ff on en0 ifscope [ethernet]"\n')
ARP_ABSENT = "exit 0\n"


def run(tmp, arp_body, harness_body, ping_body="exit 0", max_wait="3",
        start="0xbef80000", end="0xbef00000", batch="2", step="0x400", log_pre="",
        mac=MAC, harness=None):
    log = os.path.join(tmp, "log")
    if log_pre:
        open(log, "w").write(log_pre)
    env = dict(os.environ,
               MAC=mac, LOG=log, PHASE_FILE=os.path.join(tmp, "phase"),
               ADDR_FILE=os.path.join(tmp, "addr"), POLL="1", MAX_WAIT=max_wait,
               START=start, END=end, BATCH=batch, STEP=step,
               ARP_CMD=stub(os.path.join(tmp, "arp"), arp_body),
               ROUTE_CMD=stub(os.path.join(tmp, "route"),
                              'echo "$@" >> %s\n' % os.path.join(tmp, "route.calls")),
               PING_CMD=stub(os.path.join(tmp, "ping"), ping_body),
               HARNESS=harness or stub(os.path.join(tmp, "harness"), harness_body))
    p = subprocess.run([WATCH], env=env, capture_output=True, text=True, timeout=90)
    read = lambda n: open(os.path.join(tmp, n)).read().strip() if os.path.exists(
        os.path.join(tmp, n)) else ""
    return p.returncode, read("phase"), read("addr"), read("log")


def main():
    with tempfile.TemporaryDirectory() as tmp:
        print("presence")
        rc, phase, _addr, log = run(
            tmp, ARP_MATCH,
            'print("addr=0xbef80000 alive")\nprint("HANG at 0xbef80000 (recovered in 13.2s) — address found")\n')
        check("hang -> DONE and rc 0", phase == "DONE" and rc == 0, (phase, rc))
        check("log names the follow-up",
              "tapo_post.py" in log and "find_chain.py" in log, log)
        check("the batch is logged once", log.count("addr=0xbef80000") == 1, log)

    with tempfile.TemporaryDirectory() as tmp:
        print("ARP present but ICMP dead (Eero proxy-answer)")
        _rc, phase, _addr, log = run(tmp, ARP_MATCH, 'print("addr=x alive")\n', ping_body="exit 1")
        check("no walk while ICMP fails", "addr=x" not in log, log)
        check("still WAITING", phase == "WAITING", phase)

    with tempfile.TemporaryDirectory() as tmp:
        print("batching")
        rc, phase, addr, log = run(
            tmp, ARP_MATCH,
            'print("idx=" + open("/tmp/pane1/brute.192.168.4.71.idx").read().strip() + " x")\n',
            start="0xbef84000", end="0xbef83000")
        check("range exhausted -> EXHAUSTED, rc 1", phase == "EXHAUSTED" and rc == 1,
              (phase, rc))
        check("each batch advanced by BATCH*STEP",
              log.count(" x") == 2 and addr == "0xbef83000", (log.count(" x"), addr))
        check("brute index is reset per batch (the harness always sees 0)",
              [ln.split()[0] for ln in log.splitlines() if ln.endswith(" x")] == ["idx=0", "idx=0"],
              log)

    with tempfile.TemporaryDirectory() as tmp:
        print("stale HANG line")
        rc, phase, _addr, log = run(tmp, ARP_MATCH, 'print("addr=x alive")\n',
                                    start="0xbef84000", end="0xbef83000",
                                    log_pre="HANG at 0xdeadbeef (recovered in 9s) — address found\n")
        # the tail is cut from the current line count, so an older HANG line must not end the walk
        check("pre-existing HANG does not end the walk",
              phase == "EXHAUSTED" and rc == 1 and "0xdeadbeef" in log, (phase, rc))

    with tempfile.TemporaryDirectory() as tmp:
        print("absent unit")
        rc, phase, _addr, log = run(tmp, ARP_ABSENT, 'print("addr=x alive")\n')
        check("absent -> wait, then exit 2 without firing",
              rc == 2 and "addr=x" not in log, (rc, log))
        check("phase stays WAITING", phase == "WAITING", phase)

    # arp prints octets without leading zeros. A raw compare only works while every octet of the
    # target MAC is two digits, so a MAC with a low octet has to be exercised against that form.
    with tempfile.TemporaryDirectory() as tmp:
        print("arp octet forms")
        low = "50:3d:d1:0:2f:49"          # octet 00 as arp prints it
        unpadded = 'echo "? (192.168.4.71) at 50:3d:d1:0:2f:49 on en1 ifscope [ethernet]"\n'
        rc, phase, _addr, log = run(
            tmp, unpadded, 'print("addr=0xbef80000 alive")\nprint("HANG at 0xbef80000 (recovered in 4.0s) — address found")\n',
            mac=low)
        check("a low octet matches arp's unpadded print", phase == "DONE" and rc == 0, (phase, rc, log))

    with tempfile.TemporaryDirectory() as tmp:
        print("octet collision does not false-positive")
        # `50:3d:d1:2:f:49` must not match `50:3d:d1:0:2f:49`: arithmetic collapse of `0:`/`2f`
        # is exactly what the old norm did.
        other = ('echo "? (192.168.4.71) at 50:3d:d1:2:2f:49 on en1 ifscope [ethernet]"\n'
                 'echo "? (192.168.4.72) at 50:3d:d1:2:f:49 on en1 ifscope [ethernet]"\n')
        rc, phase, _addr, log = run(tmp, other, 'print("addr=x alive")\n', mac="50:3d:d1:0:2f:49")
        check("a one-digit vs two-digit octet stays distinct", phase == "WAITING" and rc == 2,
              (phase, rc))

    # The stub harness above proves the state machine. It cannot catch argument drift against the
    # real harness, so one case runs the REAL tapo_connectap_sc.py through the watcher's exact argv
    # with login/req patched (no radio). It also pins the outcome lines the watcher greps for.
    with tempfile.TemporaryDirectory() as tmp:
        print("real harness accepts the watcher's argv")
        shim = stub(os.path.join(tmp, "real_harness_shim"), (
            "import sys, importlib.util\n"
            "spec = importlib.util.spec_from_file_location('sc', %r)\n"
            "sc = importlib.util.module_from_spec(spec); spec.loader.exec_module(sc)\n"
            "sc.login = lambda host, tries=90: {'stok': 'x'}\n"
            "sc.req = lambda host, sess, payload, timeout=6: {'raw': b''}  # DEAD, as the real req marks it\n"
            "sys.argv = ['sc'] + sys.argv[1:]\n"
            "sc.main()\n") % os.path.join(HERE, "..", "deliverables", "scripts", "tapo_connectap_sc.py"),
            exe="/opt/homebrew/bin/python3")
        rc, phase, _addr, log = run(tmp, ARP_MATCH, "", harness=shim)
        check("the real parser takes --sledfill/--pcround/--hang/--mac", "error:" not in log, log[-400:])
        # the index path is shared with any live watcher, so the candidate can be base or base+step
        check("real DEAD path reaches the watcher's HANG pattern at column 0",
              bool(re.search(r"^HANG at 0xbef[0-9a-f]{5} \(", log, re.M)), log[-400:])
        check("real run ends the walk as DONE", phase == "DONE" and rc == 0, (phase, rc))

    with tempfile.TemporaryDirectory() as tmp:
        print("host route before firing")
        rc, phase, _addr, log = run(
            tmp, ARP_MATCH, 'print("addr=x alive")\n',
            start="0xbef84000", end="0xbef83000")
        calls = open(os.path.join(tmp, "route.calls")).read() if os.path.exists(
            os.path.join(tmp, "route.calls")) else ""
        check("route add -host <ip> <gw> is asserted per batch",
              calls.count("-host 192.168.4.71 192.168.4.1") == 2, calls)

    with tempfile.TemporaryDirectory() as tmp:
        print("no route while absent")
        run(tmp, ARP_ABSENT, 'print("addr=x alive")\n')
        check("an absent unit gets no route",
              not os.path.exists(os.path.join(tmp, "route.calls")))

    if failures:
        print("\n%d failure(s): %s" % (len(failures), ", ".join(failures)))
        return 1
    print("\nall checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

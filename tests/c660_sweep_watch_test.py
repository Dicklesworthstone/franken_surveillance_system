#!/usr/bin/env python3
"""Drive c660_sweep_watch.sh with fake ARP/ICMP/harness and check the state machine.

The watcher gates a one-shot root attempt, so the properties that matter are: it fires only on
real presence (ARP *and* ICMP), it walks downward in batches with the resume address persisted,
it stops on a hang, it never mistakes an old HANG line for a new hit, and the per-batch brute
index is reset (a stale index makes the next batch fire nothing).

  python3 tests/c660_sweep_watch_test.py
"""
import os
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


def stub(path, body):
    with open(path, "w") as fh:
        fh.write("#!/bin/bash\n" + body)
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
    return path


ARP_MATCH = ('echo "? (192.168.4.71) at 50:3d:d1:2f:49:b9 on en0 ifscope [ethernet]"\n'
             'echo "? (192.168.4.99) at aa:20:13:00:ee:ff on en0 ifscope [ethernet]"\n')
ARP_ABSENT = "exit 0\n"


def run(tmp, arp_body, harness_body, ping_body="exit 0", max_wait="3",
        start="0xbef80000", end="0xbef00000", batch="2", step="0x400", log_pre=""):
    log = os.path.join(tmp, "log")
    if log_pre:
        open(log, "w").write(log_pre)
    env = dict(os.environ,
               MAC=MAC, LOG=log, PHASE_FILE=os.path.join(tmp, "phase"),
               ADDR_FILE=os.path.join(tmp, "addr"), POLL="1", MAX_WAIT=max_wait,
               START=start, END=end, BATCH=batch, STEP=step,
               ARP_CMD=stub(os.path.join(tmp, "arp"), arp_body),
               PING_CMD=stub(os.path.join(tmp, "ping"), ping_body),
               HARNESS=stub(os.path.join(tmp, "harness"), harness_body))
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
        rc, phase, addr, log = run(tmp, ARP_MATCH, 'print("addr=x alive")\n',
                                   start="0xbef84000", end="0xbef83000")
        check("range exhausted -> EXHAUSTED, rc 1", phase == "EXHAUSTED" and rc == 1,
              (phase, rc))
        check("each batch advanced by BATCH*STEP",
              log.count("addr=x") == 2 and addr == "0xbef83000", (log.count("addr=x"), addr))
        check("brute index is reset per batch",
              open("/tmp/pane1/brute.192.168.4.71.idx").read().strip() == "0"
              if os.path.exists("/tmp/pane1/brute.192.168.4.71.idx") else False)

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

    if failures:
        print("\n%d failure(s): %s" % (len(failures), ", ".join(failures)))
        return 1
    print("\nall checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

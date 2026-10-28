#!/usr/bin/env python3
"""Owlet relay-quiet watcher: fire ONE root-attempt chain only inside a relay-quiet window.

The camera's TUTK relay registration (24 B refreshes to :3478) holds the single-client
slot, so a grant attempt outside a quiet window is guaranteed `no grant` (240+ logged
attempts, 2026-10-28). This watcher waits for >=QUIET seconds with no :3478 frame from
the camera, then fires the proven chain once, then re-arms.

  sudo python3 owlet_quietwatch.py [--quiet 90] [--rounds 4] [--gap 120]
"""
import argparse
import datetime
import subprocess
import sys
import time

CAM = "192.168.4.163"
LOG = "/tmp/owlet_quietwatch.log"
ROOT = "/Users/jemanuel/projects/franken_surveillance_system"


def log(msg):
    line = f"{datetime.datetime.now().isoformat(timespec='seconds')} {msg}"
    print(line, flush=True)
    with open(LOG, "a") as f:
        f.write(line + "\n")


def relay_quiet(timeout):
    """True if NO :3478 frame from the camera within `timeout` seconds."""
    r = subprocess.run(
        ["sudo", "-n", "tcpdump", "-i", "en0", "-n", "-c", "1",
         f"src host {CAM} and port 3478"],
        capture_output=True, text=True, timeout=timeout + 5)
    return r.returncode != 0 or "captured" not in (r.stderr or "") or \
        "1 packet" not in (r.stderr or "") and "0 packets captured" in (r.stderr or "")


def quiet_window(seconds):
    """True if the camera stays :3478-silent for `seconds`."""
    end = time.time() + seconds
    while time.time() < end:
        try:
            if not relay_quiet(15):
                return False
        except subprocess.TimeoutExpired:
            pass
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quiet", type=int, default=90)
    ap.add_argument("--rounds", type=int, default=4)
    ap.add_argument("--gap", type=int, default=120)
    a = ap.parse_args()
    log(f"watcher up: quiet>={a.quiet}s rounds={a.rounds}")
    for rnd in range(1, a.rounds + 1):
        log(f"round {rnd}: waiting for relay-quiet >= {a.quiet}s ...")
        if quiet_window(a.quiet):
            log(f"round {rnd}: QUIET — firing one root attempt")
            r = subprocess.run(
                ["sudo", "-n", "python3",
                 f"{ROOT}/deliverables/scripts/owlet_root_attempt.py"],
                capture_output=True, text=True, timeout=120)
            tail = (r.stdout or "").strip().splitlines()[-3:]
            for t in tail:
                log("  " + t)
            if "grant" in (r.stdout or "") and "no grant" not in (r.stdout or ""):
                log("GRANT observed — stopping")
                return 0
        else:
            log(f"round {rnd}: relay still active, no window")
        time.sleep(a.gap)
    log("watcher done: no grant")
    return 1


if __name__ == "__main__":
    sys.exit(main())

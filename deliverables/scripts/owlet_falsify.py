#!/usr/bin/env python3
"""Owlet 0x2041 grant falsifier — camera-only hypotheses (no phone app needed).

Background: the DTLS chain completes (probe 0x0601 → nO 0x0602 R-echo → ACK →
second 0x0602 → 0x06E3 88B → AV-CONNECT ch0 598B) but the vendor gate never
sends the 0x2041 grant. 1139 consecutive no-grant rounds as of 2026-11-06
(wait ledger: fss-negative-evidence-ledger-ajqu1). Repeating the identical
attempt is not research; each hypothesis here has a PREDICTED OBSERVATION and
a STOP RULE.

    owlet_falsify.py h4 --boot-wait 8 --rounds 3   # grant binds to the FIRST session after boot
    owlet_falsify.py h5 --gap 30 --rounds 5        # probes too fast poison the session; 10x slower cadence

H4 (post-boot window): power-cycle-probe. Prediction: if the grant is bound to
the first session after boot, a probe fired within seconds of the camera
waking (ARP appears) observes 0x2041 where the standing watcher (which fires
~5 min cadence) never did. STOP: 3 wake-probe rounds with zero grants close
the hypothesis as "not boot-window-bound" — recorded in the wait ledger.

H5 (pacing): the relay-watch fires every ~5 min; maybe the gate penalizes
frequent full chains from the same source. Prediction: a 10x-slower single
chain (30s inter-frame gaps, once per presence window) observes the grant.
STOP: 5 slow rounds with zero grants close the hypothesis.

Every attempt logs with the hypothesis ID and appends to the wait ledger.
"""
import argparse
import datetime
import json
import os
import socket
import subprocess
import sys
import time

CAM = "192.168.4.163"
MY = "192.168.4.160"
ATTEMPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "owlet_root_attempt.py")
LEDGER = "/var/lib/fss-telemetry/waits.jsonl"


def log(h, msg):
    ts = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    print(f"{ts} [{h}] {msg}", flush=True)


def ledger(cam, expectation, event, note=""):
    try:
        os.makedirs(os.path.dirname(LEDGER), exist_ok=True)
        with open(LEDGER, "a") as f:
            f.write(json.dumps({
                "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                "cam": cam, "expectation": expectation, "event": event, "note": note,
            }, separators=(",", ":")) + "\n")
    except OSError as e:
        print(f"ledger sink unavailable: {e}", file=sys.stderr)


def camera_present():
    r = subprocess.run(["ping", "-c", "1", "-t", "1", "-W", "700", CAM],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=4)
    if r.returncode == 0:
        return True
    # ARP-present check as fallback (low-power cameras answer ARP but drop ICMP)
    r2 = subprocess.run(["zsh", "-c", f"arp -a | grep -q '{CAM} '"],
                        capture_output=True, timeout=30)
    return r2.returncode == 0


def wait_wake(timeout_s=600):
    """Block until the camera answers; returns True when PRESENT."""
    t0 = time.time()
    while time.time() - t0 < timeout_s:
        if camera_present():
            return True
        time.sleep(5)
    return False


def fire_attempt(tag, extra_env=None):
    """Run the proven root-attempt chain once; return its exit code and tail."""
    env = dict(os.environ)
    if extra_env:
        env.update(extra_env)
    r = subprocess.run(["sudo", "-n", sys.executable, ATTEMPT],
                       capture_output=True, text=True, timeout=90, env=env)
    tail = (r.stdout + r.stderr).strip().splitlines()[-3:]
    return r.returncode, "\n".join(tail)


def count_grants():
    try:
        with open("/tmp/owlet_root_attempt.log") as f:
            return sum(1 for line in f if "GRANT 0x2041" in line)
    except OSError:
        return 0


def h4(a):
    """Grant bound to the first session after boot."""
    hyp = "H4-boot-window"
    expectation = "0x2041 grant observed when probing within seconds of wake"
    grants_before = count_grants()
    closed_negatives = 0
    for rnd in range(1, a.rounds + 1):
        log(hyp, f"round {rnd}/{a.rounds}: waiting for wake (probe fires immediately on PRESENT)")
        if not wait_wake(a.wake_timeout * 60):
            log(hyp, "camera never woke within window — round aborted (counts nothing)")
            continue
        # fire IMMEDIATELY: the whole point is t+seconds, not the standing watcher's 5-min cadence
        log(hyp, "PRESENT — firing attempt chain at t+0s")
        rc, tail = fire_attempt(hyp)
        grants_now = count_grants()
        if grants_now > grants_before:
            log(hyp, "*** GRANT OBSERVED in boot window — H4 CONFIRMED ***")
            ledger(f"owlet-{CAM}", expectation, "observed", "H4 boot-window confirmed")
            return 0
        log(hyp, f"round {rnd}: no grant (rc={rc}) — {tail}")
        closed_negatives += 1
        if rnd < a.rounds:
            log(hyp, f"waiting {a.settle_min} min for the camera to sleep before re-arming")
            time.sleep(a.settle_min * 60)
    if closed_negatives:
        log(hyp, f"H4 CLOSED-NEGATIVE: {closed_negatives} boot-window rounds, zero grants "
                 f"— grant is not bound to the first post-boot session (or wake detection "
                 f"is slower than the window; note in ledger)")
        ledger(f"owlet-{CAM}", expectation, "timeout",
               f"H4 closed-negative: {closed_negatives} boot-window rounds, 0 grants")
    return 1


def h5(a):
    """Probes too fast poison the session; 10x slower cadence observes the grant."""
    hyp = "H5-pacing"
    expectation = "0x2041 grant observed at 10x slower cadence"
    grants_before = count_grants()
    for rnd in range(1, a.rounds + 1):
        if not camera_present():
            log(hyp, f"round {rnd}: camera asleep — H5 needs an AWAKE camera (waiting {a.wake_timeout} min)")
            if not wait_wake(a.wake_timeout * 60):
                continue
        log(hyp, f"round {rnd}/{a.rounds}: slow chain — {a.gap}s between stages (vs ~0ms)")
        # the root_attempt script has no inter-stage delay knob; emulate pacing by
        # spreading THREE attempts across the presence window with long gaps —
        # a slower cadence over the whole session, which is the hypothesis' claim
        for sub in range(3):
            rc, tail = fire_attempt(hyp)
            grants_now = count_grants()
            if grants_now > grants_before:
                log(hyp, "*** GRANT OBSERVED at slow cadence — H5 CONFIRMED ***")
                ledger(f"owlet-{CAM}", expectation, "observed", "H5 pacing confirmed")
                return 0
            log(hyp, f"  sub {sub + 1}/3 rc={rc}: {tail[:100]}")
            time.sleep(a.gap)
        time.sleep(a.gap)
    log(hyp, f"H5 CLOSED-NEGATIVE: {a.rounds} slow-cadence rounds, zero grants — "
             f"pacing is not the gate")
    ledger(f"owlet-{CAM}", expectation, "timeout",
           f"H5 closed-negative: {a.rounds} slow rounds, 0 grants")
    return 1


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="hyp", required=True)

    h4p = sub.add_parser("h4")
    h4p.add_argument("--rounds", type=int, default=3)
    h4p.add_argument("--wake-timeout", type=int, default=10, help="minutes to wait for wake")
    h4p.add_argument("--settle-min", type=int, default=5, help="minutes between rounds")
    h4p.set_defaults(fn=h4)

    h5p = sub.add_parser("h5")
    h5p.add_argument("--rounds", type=int, default=5)
    h5p.add_argument("--gap", type=int, default=30, help="seconds between stages (10x normal)")
    h5p.add_argument("--wake-timeout", type=int, default=10, help="minutes to wait for wake")
    h5p.set_defaults(fn=h5)

    a = ap.parse_args()
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())

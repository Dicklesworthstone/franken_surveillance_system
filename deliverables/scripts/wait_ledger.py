#!/usr/bin/env python3
"""Wait ledger — negative evidence for every armed wait in the liberation fleet.

Born from the fleet's largest time sink: multi-hour waits (assis OTA cadence,
Owlet 0x2041 grant, Yi re-provision window, C460 DS window) whose OUTCOMES were
narrated in prose logs. When a wait produces nothing, that NOTHING is evidence.
Without a ledger, future sessions re-run dead waits because "maybe it fired
while we weren't looking" — measured 2026-11-06: the Yi listener sat idle 20h,
the Owlet watcher accumulated 1139 no-grant rounds invisible to handoffs.

Two modes:

  wait_ledger.py begin --cam C --expectation "E" --check-cmd "PROBE" \
               [--interval 60] [--max 240] [--tag T]     # runs the probe loop

  wait_ledger.py record --cam C --expectation "E" --state open|observed|timeout|cancelled \
               [--observations N] [--note TEXT]          # import/record without looping

Events append to /var/lib/fss-telemetry/waits.jsonl (one JSON per line) and a
human table renders with `wait_ledger.py show`.

State machine: open → observed | timeout | cancelled. An observed wait records
the observation artifact path. Terminal states never transition again (append a
new wait instead). Sink failure degrades to stderr + exit 0 — instrumentation
must never kill the mission.
"""
import argparse
import datetime
import json
import os
import subprocess
import sys
import time

DIR = "/var/lib/fss-telemetry"
WAITS = os.path.join(DIR, "waits.jsonl")


def _append(rec):
    try:
        os.makedirs(DIR, exist_ok=True)
        with open(WAITS, "a") as f:
            f.write(json.dumps(rec, separators=(",", ":")) + "\n")
    except OSError as e:
        print(f"wait_ledger: sink unavailable ({e}); recording lost", file=sys.stderr)


def _load():
    out = []
    try:
        with open(WAITS) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        out.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    except OSError:
        pass
    return out


def _latest_by_key():
    """Key = (cam, expectation). Terminal state wins; latest ts breaks ties."""
    latest = {}
    for r in _load():
        k = (r.get("cam"), r.get("expectation"))
        cur = latest.get(k)
        rank = {"open": 0, "timeout": 1, "cancelled": 1, "observed": 2}
        if cur is None:
            latest[k] = r
            continue
        # a later OPEN record supersedes an older terminal one (new wait cycle)
        if r.get("ts", "") > cur.get("ts", ""):
            latest[k] = r
    return latest


def cmd_begin(a):
    """Run the probe loop, recording ticks/observations/end state."""
    started = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    _append({"ts": started, "cam": a.cam, "expectation": a.expectation,
             "event": "begin", "interval": a.interval, "max": a.max, "tag": a.tag})
    deadline = time.time() + a.max * 60
    ticks = observations = 0
    last_obs = ""
    end_reason = "timeout"
    while time.time() < deadline:
        ticks += 1
        try:
            r = subprocess.run(a.check_cmd, shell=True, capture_output=True, text=True,
                               timeout=max(5, a.interval))
        except subprocess.TimeoutExpired:
            r = None
        out = (r.stdout + r.stderr).strip() if r else ""
        ok = (r.returncode == 0 and out != "") if r else False
        if ok:
            observations += 1
            last_obs = out[:400]
        time.sleep(a.interval)
        if ok and a.single:
            end_reason = "observed"
            break
    rec = {"ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
           "cam": a.cam, "expectation": a.expectation, "event": "end",
           "end_reason": end_reason, "ticks": ticks, "observations": observations,
           "last_observation": last_obs, "tag": a.tag}
    _append(rec)
    print(f"wait end: {end_reason} after {ticks} ticks, {observations} observations")
    if last_obs:
        print(f"last observation: {last_obs}")
    return 0


def cmd_record(a):
    _append({"ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
             "cam": a.cam, "expectation": a.expectation, "event": a.state,
             "observations": a.observations, "note": a.note, "tag": a.tag})
    print(f"recorded: {a.state} — {a.cam}: {a.expectation[:80]}")
    return 0


def cmd_show(_a):
    latest = _latest_by_key()
    if not latest:
        print("wait ledger: empty")
        return 0
    print("| cam | expectation | state | observations | since | note/tag |")
    print("|---|---|---|---|---|---|")
    for (cam, exp), r in sorted(latest.items()):
        state = r.get("end_reason") or r.get("event", "?")
        obs = r.get("observations", r.get("ticks", "—"))
        note = r.get("note") or r.get("tag") or ""
        print(f"| {cam} | {exp[:60]} | {state} | {obs} | {r.get('ts','?')[:19]} | {note[:40]} |")
    return 0


def cmd_seed(a):
    """Import historical counts as baseline waits (evidence from before the ledger existed)."""
    seeded = 0
    for item in a.items:
        # format: CAM|EXPECTATION|STATE|OBSERVATIONS|NOTE
        parts = item.split("|")
        if len(parts) != 5:
            print(f"seed: bad item (want CAM|EXP|STATE|OBS|NOTE): {item[:60]}", file=sys.stderr)
            continue
        cam, exp, state, obs, note = parts
        _append({"ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                 "cam": cam, "expectation": exp, "event": state,
                 "observations": int(obs) if obs.isdigit() else 0,
                 "note": note, "tag": "historical-import"})
        seeded += 1
    print(f"seeded {seeded} historical waits")
    return 0


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("begin")
    b.add_argument("--cam", required=True)
    b.add_argument("--expectation", required=True)
    b.add_argument("--check-cmd", required=True)
    b.add_argument("--interval", type=int, default=60, help="seconds between probes")
    b.add_argument("--max", type=int, default=240, help="minutes before timeout")
    b.add_argument("--single", action="store_true", help="stop at first observation")
    b.add_argument("--tag", default="")
    b.set_defaults(fn=cmd_begin)

    r = sub.add_parser("record")
    r.add_argument("--cam", required=True)
    r.add_argument("--expectation", required=True)
    r.add_argument("--state", choices=["open", "observed", "timeout", "cancelled"], required=True)
    r.add_argument("--observations", type=int, default=0)
    r.add_argument("--note", default="")
    r.add_argument("--tag", default="")
    r.set_defaults(fn=cmd_record)

    s = sub.add_parser("show")
    s.set_defaults(fn=cmd_show)

    seed = sub.add_parser("seed")
    seed.add_argument("items", nargs="+", help="CAM|EXPECTATION|STATE|OBSERVATIONS|NOTE")
    seed.set_defaults(fn=cmd_seed)

    a = ap.parse_args()
    try:
        return a.fn(a)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())

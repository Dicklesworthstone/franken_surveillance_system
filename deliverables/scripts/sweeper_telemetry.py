#!/usr/bin/env python3
"""sweeper_telemetry.py — structured JSONL sink + rollup for Tapo sweep/fire activity.

The C460 sweeper has processed 800+ PIR wakes and 100k login attempts (2026-11-06),
all narrated in prose logs. This turns weeks of waiting into queryable data:
wakes/hour histograms, DS-state transitions, fire attempts + port outcomes.

    sweeper_telemetry.py emit --cam c460 --event wake --details '{"ip":"192.168.4.243"}'
    sweeper_telemetry.py import-prose /tmp/c460_incremental_sweep.log --cam c460
    sweeper_telemetry.py rollup --cam c460 --since 7d

Storage: /var/lib/fss-telemetry/sweeper-<cam>.jsonl (one file per daemon to
make concurrent appends safe; rotation at 50MB, keep 2). Sink failure degrades
to stderr + exit 0 — instrumentation NEVER blocks the mission.
"""
import argparse
import collections
import datetime
import glob
import json
import os
import re
import sys
import time

DIR = "/var/lib/fss-telemetry"
MAX_BYTES = 50 * 1024 * 1024
KEEP = 2
EVENTS = {"wake", "probe", "fire", "rop_result", "login_attempt", "ds_state",
          "present", "absent", "shell", "beacon"}


def sink_path(cam):
    return os.path.join(DIR, f"sweeper-{cam}.jsonl")


def _append(cam, rec):
    try:
        os.makedirs(DIR, exist_ok=True)
        p = sink_path(cam)
        # rotation
        if os.path.exists(p) and os.path.getsize(p) > MAX_BYTES:
            for i in range(KEEP, 0, -1):
                older = f"{p}.{i}"
                newer = f"{p}.{i-1}" if i > 1 else p
                if os.path.exists(newer):
                    os.replace(newer, older)
        with open(p, "a") as f:
            f.write(json.dumps(rec, separators=(",", ":")) + "\n")
    except OSError as e:
        print(f"telemetry sink unavailable ({e}); event lost", file=sys.stderr)


def _records(cam):
    recs = []
    for p in sorted(glob.glob(os.path.join(DIR, f"sweeper-{cam}.jsonl*"))):
        try:
            for line in open(p, errors="replace"):
                line = line.strip()
                if line:
                    try:
                        recs.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except OSError:
            continue
    return recs


def cmd_emit(a):
    details = {}
    if a.details:
        try:
            details = json.loads(a.details)
        except json.JSONDecodeError as e:
            print(f"details must be JSON: {e}", file=sys.stderr)
            return 2
    _append(a.cam, {"ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                    "cam": a.cam, "event": a.event, "details": details})
    return 0


PROSE_PATTERNS = [
    # "2026-11-05 11:09:04 watching for 50:3d:d1:e3:e2:07 (fire 0xbef8b000 offset 1060 when ARP+ICMP present)"
    (re.compile(r"^(?P<d>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) watching for (?P<mac>[0-9a-f:]+) \(fire (?P<addr>0x[0-9a-f]+)"),
     lambda m: {"event": "probe", "details": {"boot_addr": m["addr"]}}),
    (re.compile(r"^(?P<d>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) PRESENT"),
     lambda m: {"event": "present", "details": {}}),
    (re.compile(r"^(?P<d>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) absent \(ARP or ICMP\)"),
     lambda m: {"event": "absent", "details": {}}),
    (re.compile(r"^(?P<d>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) unit (?P<ip>[\d.]+) — gap (?P<gap>\d+)s, then (?P<mode>[\w ]+)"),
     lambda m: {"event": "fire", "details": {"ip": m["ip"], "gap_s": int(m["gap"]), "mode": m["mode"].strip()}}),
    (re.compile(r"^(?P<d>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) sweep found no hang — boot address outside this window"),
     lambda m: {"event": "rop_result", "details": {"outcome": "no-hang"}}),
    (re.compile(r"^(?P<d>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) login ok \((?P<tries>\d+) tries\)"),
     lambda m: {"event": "ds_state", "details": {"state": "login-ok", "tries": int(m["tries"])}}),
    (re.compile(r"^(?P<h>\d{2}:\d{2}:\d{2}) login wait: try (?P<tries>\d+), DS closed"),
     lambda m: {"event": "login_attempt", "details": {"ds": "closed", "tries": int(m["tries"])}}),
    (re.compile(r"^(?P<h>\d{2}:\d{2}:\d{2}) (?P<state>DS \w+|login ok).*"),
     lambda m: {"event": "ds_state", "details": {"raw": m["state"]}}),
]


def cmd_import_prose(a):
    """Best-effort import of existing prose logs into the sink."""
    imported = 0
    day_hint = None
    try:
        lines = open(a.path, errors="replace").read().splitlines()
    except OSError as e:
        print(f"cannot read {a.path}: {e}", file=sys.stderr)
        return 2
    for line in lines:
        for pat, mk in PROSE_PATTERNS:
            m = pat.match(line.strip())
            if not m:
                continue
            gd = m.groupdict()
            if "d" in gd:
                ts = gd["d"].replace(" ", "T") + "-05:00"  # log times are local
                day_hint = gd["d"][:10]
            else:
                # time-only lines: attach the last seen date or import date
                day = day_hint or datetime.date.today().isoformat()
                ts = f"{day}T{gd['h']}-05:00"
            rec = {"ts": ts, "cam": a.cam, **mk(m)}
            _append(a.cam, rec)
            imported += 1
            break
    print(f"imported {imported} events from {a.path}")
    return 0


def cmd_rollup(a):
    recs = _records(a.cam)
    if a.since:
        cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
            days=int(a.since.rstrip("d")))
        recs = [r for r in recs if _ts(r) >= cutoff]
    if not recs:
        print(f"no events for {a.cam}")
        return 0
    by_hour = collections.Counter(r["ts"][:13] for r in recs)
    by_event = collections.Counter(r["event"] for r in recs)
    fires = [r for r in recs if r["event"] == "fire"]
    rop = [r for r in recs if r["event"] == "rop_result"]
    login = [r for r in recs if r["event"] == "login_attempt"]
    print(f"=== rollup: {a.cam} — {len(recs)} events ===")
    print("| metric | value |")
    print("|---|---|")
    print(f"| total events | {len(recs)} |")
    print(f"| wakes/present | {by_event.get('present', 0) + by_event.get('wake', 0)} |")
    print(f"| fire attempts | {len(fires)} |")
    print(f"| rop no-hang results | {len(rop)} |")
    print(f"| login attempts (DS closed) | {len(login)} |")
    if login:
        tries = [r["details"].get("tries", 0) for r in login]
        print(f"| max login-try counter | {max(tries)} |")
    # longest dry spell of present-events
    pres = sorted(r["ts"] for r in recs if r["event"] == "present")
    if len(pres) > 1:
        gaps = [(datetime.datetime.fromisoformat(b) - datetime.datetime.fromisoformat(a_))
                for a_, b in zip(pres, pres[1:])]
        longest = max(gaps)
        print(f"| longest wake gap | {longest} |")
    print("|---|---|")
    print("Events/hour (last 24 buckets):")
    for hour, n in sorted(by_hour.items())[-24:]:
        print(f"  {hour}  {'█' * min(n, 40)} {n}")


def _ts(r):
    try:
        return datetime.datetime.fromisoformat(r["ts"])
    except (KeyError, ValueError):
        return datetime.datetime.min.replace(tzinfo=datetime.timezone.utc)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("emit")
    e.add_argument("--cam", required=True)
    e.add_argument("--event", required=True, choices=sorted(EVENTS))
    e.add_argument("--details", default="")
    e.set_defaults(fn=cmd_emit)
    i = sub.add_parser("import-prose")
    i.add_argument("path")
    i.add_argument("--cam", required=True)
    i.set_defaults(fn=cmd_import_prose)
    r = sub.add_parser("rollup")
    r.add_argument("--cam", required=True)
    r.add_argument("--since", default=None, help="e.g. 7d")
    r.set_defaults(fn=cmd_rollup)
    a = ap.parse_args()
    try:
        return a.fn(a)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())

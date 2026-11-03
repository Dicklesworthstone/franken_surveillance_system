#!/usr/bin/env python3
"""Parser checks for owlet_replay_capture.py (fss-kemuu).

The replay is only as honest as its frame slice: it must take the app direction AND ONLY
the app direction from two different on-disk log formats, keep capture order, and notice
when a frame was truncated by the hook's dump cap (a truncated 576 B registration frame
looks perfectly well-formed otherwise).

Runs standalone (no pytest on this host): `python3 tests/owlet_replay_capture_test.py`.
"""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "deliverables", "scripts"))
import owlet_replay_capture as rc   # noqa: E402

fails = 0


def check(name, cond, detail=""):
    global fails
    print(f"  [{'ok ' if cond else 'FAIL'}] {name}{' — ' + detail if detail and not cond else ''}")
    if not cond:
        fails += 1


def main():
    print("frame extraction")
    relay = rc.parse(rc.CAPTURE)
    lan = rc.parse(rc.LAN_CAPTURE)

    check("relay capture yields the app direction only",
          relay and all(len(b) != 200 for _, b, _ in relay),
          "200 B frames are the camera's")
    check("relay capture is ordered and non-empty", len(relay) > 50, f"n={len(relay)}")
    check("relay offsets are non-decreasing", all(a[0] <= b[0] for a, b in zip(relay, relay[1:])))
    check("relay offsets start at zero", relay[0][0] == 0.0)
    check("relay capture reports its truncated frames",
          sum(1 for _, b, n in relay if len(b) < n) >= 4,
          "the 576/320/291 B registrations are capped at 128 by the old hook")

    fams = {b[:2].hex() for _, b, _ in lan}
    check("LAN app frames stay in the capture's prefix families",
          fams <= {"6e6c", "6e6f", "4e6d", "6c6c", "6f6c"}, str(sorted(fams)))
    check("LAN capture has the ClientHello", any(len(b) == 291 for _, b, _ in lan))
    check("LAN capture is untruncated", sum(1 for _, b, n in lan if len(b) < n) == 0)

    print("inline-format parsing")
    tmp = "/tmp/owlet_replay_parse_tmp.log"
    with open(tmp, "w") as fh:
        fh.write("[S] fd=1 > 0.0.0.0:36167 len=4 hex=aabbccdd\n")
        fh.write("[R] < 0.0.0.0:36167 len=2 hex=eeff\n")
        fh.write("[S] fd=1 > 0.0.0.0:36167 len=8 hex=0102030405060708\n")
    got = rc.parse(tmp)
    check("camera frames are dropped", [b.hex() for _, b, _ in got] == ["aabbccdd", "0102030405060708"])
    check("declared length is preserved", [n for _, _, n in got] == [4, 8])
    check("clockless captures stay at zero", [t for t, _, _ in got] == [0.0, 0.0])

    print(f"\n{'FAILED' if fails else 'all replay-parser checks passed'} ({fails} failure(s))")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())

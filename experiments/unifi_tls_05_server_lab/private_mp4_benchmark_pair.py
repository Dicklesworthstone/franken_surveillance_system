#!/usr/bin/env python3
"""Alternate two private MP4 decoder binaries on the authorized media host.

This timing-only laboratory tool prints no media, credentials or frame hashes.
Run the separate frame-by-frame oracle comparison before claiming equivalence.
Each wall time includes process startup, input, demux and decode; child CPU
time is recorded separately to expose scheduling noise on a shared host.
"""

import argparse
import hashlib
import resource
import statistics
import subprocess
import time
from pathlib import Path


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument("clip", type=Path)
    parser.add_argument("--pairs", type=int, default=3, choices=range(1, 6))
    args = parser.parse_args()
    binaries = {"before": args.before, "after": args.after}
    times = {"before": [], "after": []}
    reference = None
    for pair in range(args.pairs):
        order = ("before", "after") if pair % 2 == 0 else ("after", "before")
        for name in order:
            cpu_start = resource.getrusage(resource.RUSAGE_CHILDREN)
            with args.clip.open("rb") as source:
                start = time.monotonic()
                result = subprocess.run(
                    [str(binaries[name]), "--owner-authorized"], stdin=source,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300,
                    check=False,
                )
                wall = time.monotonic() - start
            cpu_end = resource.getrusage(resource.RUSAGE_CHILDREN)
            cpu = ((cpu_end.ru_utime + cpu_end.ru_stime)
                   - (cpu_start.ru_utime + cpu_start.ru_stime))
            if result.returncode or cpu <= 0:
                raise RuntimeError(f"{name} decode failed (exit {result.returncode})")
            report = result.stdout.decode("ascii").splitlines()
            if len(report) != 1 or not report[0].startswith("private_mp4_decode=ok "):
                raise RuntimeError(f"{name} decode report invalid")
            if reference is not None and reference != report[0]:
                raise RuntimeError("decode reports differed")
            reference = report[0]
            times[name].append((wall, cpu))
            print(f"run={pair + 1} variant={name} wall_seconds={wall:.3f} cpu_seconds={cpu:.3f}",
                  flush=True)
    before_cpu = statistics.median(cpu for _, cpu in times["before"])
    after_cpu = statistics.median(cpu for _, cpu in times["after"])
    print(f"before_sha256={digest(args.before)} after_sha256={digest(args.after)}")
    print(f"pairs={args.pairs} before_median_cpu={before_cpu:.3f} "
          f"after_median_cpu={after_cpu:.3f} cpu_speedup={before_cpu / after_cpu:.3f}")
    print(reference)


if __name__ == "__main__":
    main()

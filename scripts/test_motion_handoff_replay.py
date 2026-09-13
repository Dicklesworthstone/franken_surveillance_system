#!/usr/bin/env python3
"""Execute the actual Rust fixture twice and check an independent analytic oracle.

This is synthetic reference qualification, not real-property accuracy. No output
is substituted when Cargo or the accepted toolchain is unavailable.
"""
from __future__ import annotations
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
LIMIT = 64 * 1024
COMMAND = ["cargo", "run", "--locked", "--offline", "--quiet", "-p", "fss-geometry",
           "--example", "predict_handoff"]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def expected_region(kind, route):
    radius, height = (0.2, 1.5) if kind == "person" else (0.3, 0.8)
    point = [-4.0, -8.0, 0.0] if route == 1 else [-8.0, -4.0, 0.0]
    center = [0.0, -8.0, 10.0] if route == 1 else [-8.0, 0.0, 10.0]
    pixels = []
    for dx in [-radius, radius]:
        for dy in [-radius, radius]:
            for dz in [0.0, height]:
                depth = center[2] - (point[2] + dz)
                pixels.append([0.5 + (point[0] + dx - center[0]) / depth,
                               0.5 - (point[1] + dy - center[1]) / depth])
    return [min(p[0] for p in pixels), min(p[1] for p in pixels),
            max(p[0] for p in pixels), max(p[1] for p in pixels)]


def validate(data):
    require(len(data) <= LIMIT, "replay output too large")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    def finite(value):
        raise ValueError("nonfinite JSON constant: " + value)
    rows = [json.loads(line, object_pairs_hook=unique, parse_constant=finite)
            for line in data.decode("utf-8").splitlines()]
    require(len(rows) == 4, "four complete route/class outcomes required")
    expected_keys = [("person", 1), ("person", 2), ("bear", 1), ("bear", 2)]
    for row, (kind, route) in zip(rows, expected_keys):
        require(row["schema"] == "fss.handoff.replay/1" and row["synthetic"] is True,
                "wrong replay identity or synthetic scope")
        require(row["event"] == "modeled_sample_eligibility", "wrong event definition")
        require((row["class"], row["route"]) == (kind, route), "unstable route/class order")
        require(row["camera"] == (11 if route == 1 else 22), "incorrect next camera")
        require(row["capture_ns"] == 4_000_000_000, "incorrect nominal capture time")
        require(row["availability_ns"] == [4_200_000_000, 4_400_000_000], "incorrect availability")
        require(row["mass"] == (4 if kind == "person" and route == 1 else 1), "class bias leaked")
        require(row["total_mass"] == (5 if kind == "person" else 2), "route mass was lost")
        require(row["protected"] is (route == 2), "protected off-path alternative lost")
        region = row["region"]
        require(len(region) == 4 and all(type(x) in (int, float) and math.isfinite(x) for x in region),
                "invalid image region")
        require(all(abs(a - b) < 1e-10 for a, b in zip(region, expected_region(kind, route))),
                "image region disagrees with independent analytic projection")
        require(row["body_generation"] == (71 if kind == "person" else 72), "wrong body hypothesis")
        require((row["clock"], row["track_revision"], row["image_mode"],
                 row["observation_generation"]) == (3, 5, 9, 8), "basis mismatch")
        require(type(row["work_units"]) is int and 0 < row["work_units"] <= 1_000_000,
                "work accounting outside budget")
    return rows


def execute():
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        env = dict(os.environ, CARGO_NET_OFFLINE="true")
        result = subprocess.run(COMMAND, cwd=ROOT, env=env, stdout=output, stderr=errors,
                                timeout=120, check=False)
        output.seek(0)
        data = output.read(LIMIT + 1)
        errors.seek(0)
        diagnostic = errors.read(8192).decode("utf-8", errors="replace")
        require(result.returncode == 0, f"Rust replay failed ({result.returncode}): {diagnostic}")
        validate(data)
        return data


def main():
    if shutil.which("cargo") is None:
        print(json.dumps({"status": "NOT_RUN", "reason": "Cargo is unavailable",
                          "scope": "Rust replay", "command": COMMAND}))
        return 2
    try:
        first, second = execute(), execute()
        require(first == second, "repeated Rust execution changed the transcript")
        print(json.dumps({"status": "PASS", "scope": "synthetic Rust motion/handoff replay only",
                          "records": 4, "runs": 2, "sha256": hashlib.sha256(first).hexdigest(),
                          "command": COMMAND, "real_property_qualified": False}))
        return 0
    except (ValueError, OSError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        print(json.dumps({"status": "FAIL", "error": str(error), "command": COMMAND}))
        return 1


if __name__ == "__main__":
    sys.exit(main())

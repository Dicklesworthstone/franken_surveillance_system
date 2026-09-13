#!/usr/bin/env python3
"""Run the real Rust example and independently check its known synthetic truth.

Requires the repository's accepted Rust toolchain. No Python model/codec/runtime
is introduced into FSS; this is a laboratory consumer of executable output.
"""
from pathlib import Path
import json
import math
import subprocess


def main():
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        ["cargo", "run", "--locked", "--offline", "--quiet", "-p", "fss-geometry", "--example", "register_camera"],
        cwd=root, text=True, capture_output=True, timeout=120, check=True)
    rows = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    if len(rows) != 1:
        raise AssertionError("expected exactly one complete example record")
    row = rows[0]
    checks = {
        "center": math.dist(row["camera_center"], [4, -8, 5]) < 1e-4,
        "independent_ground_ray": math.dist(row["ground_hit"], [4, 2, 0]) < 1e-4,
        "fit": 0 <= row["fit_rms_px"] < 1e-4 and row["inliers"] == 24,
        "holdout": row["holdout_passed"] is True,
        "bounded": 0 < row["work_units"] <= 10_000_000,
        "no_qualification_laundering": row["physical_accuracy_qualified"] is False,
    }
    if not all(checks.values()):
        raise AssertionError(json.dumps({"checks": checks, "result": row}, allow_nan=False))
    print(json.dumps({"status": "PASS", "scope": "executed Rust synthetic registration and ground projection", "checks": checks}, sort_keys=True))


if __name__ == "__main__":
    main()

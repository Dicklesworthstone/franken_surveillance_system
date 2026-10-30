#!/usr/bin/env python3
"""Reproduce synthetic clock inputs; these labels are not retained media custody.

Default mode verifies exact checked-in bytes. --write replaces only these two
synthetic fixtures. This generator is not the production alignment implementation.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCALE = 1_000_000_000
OFFSET = 50_000_000


def pin(label: str) -> str:
    return "sha256:" + hashlib.sha256(("fss.synthetic.clock." + label).encode()).hexdigest()


def fixture(drift: bool) -> dict:
    cameras = []
    for camera, center in [(1, [-2, 0, 0]), (2, [2, 1, 0])]:
        cameras.append({"id": camera, "clock": camera * 10,
            "calibration_digest": pin(f"calibration:{camera}"),
            "image_domain": pin(f"image:{camera}"),
            "intrinsics": {"width": 1280, "height": 960, "fx": 640, "fy": 640, "cx": 640, "cy": 480},
            "rotation": [[1, 0, 0], [0, 1, 0], [0, 0, 1]], "center": center})
    value = {"schema": "fss.clock_drift_query.v1" if drift else "fss.clock_alignment_query.v1",
        "world_basis": pin("world"), "association_evidence": pin("association"),
        "reference_camera": cameras[0], "target_camera": cameras[1],
        "fit_options": {"max_reprojection_pixels": 0.001 if drift else 0.05,
            "max_distance": 1000, "max_speed": 20, "max_condition_number": 10000000000,
            "max_iterations": 16}, "training": [], "validation": []}
    if drift:
        value["target_anchor_ns"] = str(OFFSET)
        value["hypotheses"] = [{"offset_ns": str(OFFSET), "skew_ppb": str(rate)} for rate in [-500000, 0, 500000]]
    else:
        value["offsets_ns"] = ["0", str(OFFSET), "100000000"]
    training = [n * SCALE for n in [-10, -6, -2, 2, 6, 10]] if drift else [-200000000, -100000000, 0, 100000000, 200000000]
    validation = [n * SCALE for n in [-8, -4, 0, 4, 8]] if drift else [-150000000, 150000000]
    velocity = [0.06, -0.01, 0.025] if drift else [0.6, -0.1, 0.25]
    for camera in cameras:
        for role, times in [("training", training), ("validation", validation)]:
            for reference in times:
                t = reference / SCALE
                point = [p + v * t - c for p, v, c in zip([0.3, 0.2, 7.0], velocity, camera["center"])]
                local = reference if camera["id"] == 1 else OFFSET + reference * (SCALE + (500000 if drift else 0)) // SCALE
                label = f'{camera["id"]}:{reference}:{"drift" if drift else "offset"}'
                row = {"camera": camera["id"], "clock": camera["clock"],
                    "pixel": [640 + 640 * point[0] / point[2], 480 + 640 * point[1] / point[2]],
                    "sigma_pixels": 1, "exposure": "synthetic:" + label,
                    "source_digest": pin("source:" + label), "evidence_digest": pin("evidence:" + label)}
                row["capture_ns" if role == "training" else "capture_interval_ns"] = str(local) if role == "training" else [str(local), str(local)]
                value[role].append(row)
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    okay = True
    for name, drift in [("moving_feature.json", False), ("drifting_feature.json", True)]:
        data = (json.dumps(fixture(drift), sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
        path = ROOT / "fixtures" / "clock-alignment" / name
        if args.write:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        if not path.is_file() or path.read_bytes() != data:
            print(f"FAIL {name}: fixture differs from deterministic generator")
            okay = False
        else:
            print(f"PASS {name} sha256:{hashlib.sha256(data).hexdigest()}")
    return 0 if okay else 1


if __name__ == "__main__":
    raise SystemExit(main())

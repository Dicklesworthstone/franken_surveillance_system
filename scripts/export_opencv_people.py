#!/usr/bin/env python3
"""Offline laboratory export only. OpenCV is never a production dependency.

Run with an already installed opencv-python 4.13.0.92, for example:
  python3 scripts/export_opencv_people.py /tmp/people.f32le
No network calls, model code loading, directory creation, or overwrite.
The output must match the checked-in coefficients byte-for-byte.
"""
import argparse
import hashlib
import importlib.metadata
from pathlib import Path
import struct

EXPECTED = "cb2198952eaa5bc7e43d950b9f2aa1966528063c7295c7262133e7fa0d3d564c"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    import cv2  # Offline oracle, not imported by any Rust process/build helper.
    if cv2.__version__ != "4.13.0" or importlib.metadata.version("opencv-python") != "4.13.0.92":
        raise SystemExit("refusing an unpinned exporter version")
    coefficients = cv2.HOGDescriptor_getDefaultPeopleDetector().reshape(-1)
    if len(coefficients) != 3781:
        raise SystemExit("unexpected model shape")
    data = b"".join(struct.pack("<f", float(value)) for value in coefficients)
    if hashlib.sha256(data).hexdigest() != EXPECTED:
        raise SystemExit("upstream export differs from retained candidate")
    with args.output.open("xb") as output:
        output.write(data)
    print(f"exported 3781 F32LE parameters; sha256={EXPECTED}; no qualification or activation")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""FSS-024 production-absence harness for the laboratory-oracle surface.

Proves three facts, failing closed:
  1. The `lab-oracle` feature of `fss-runtime` is NOT a default feature and
     no workspace member enables it outside dev/test contexts.
  2. No production source file (crates/*/src/**.rs) references the lab
     module (`fss_runtime::lab`, `runtime::lab`, `lab::`, `mod lab`,
     `LabSession`, `LabOracleExecutor`, `LabTaint`, `LabOutput`) unless the
     reference sits inside the module itself or the single cfg-gated
     registration line in fss-runtime/src/lib.rs.
  3. The workspace policy stays `foreign_runtime_role =
     "sealed_laboratory_oracle_only"`.

Exit 0 = production absence proven. Exit 1 = violation, with the evidence
list on stdout. Secret-free: only paths and policy strings are printed.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

LAB_SYMBOLS = re.compile(
    r"fss_runtime::lab\b|runtime::lab\b|\blab::|\bmod lab\b|"
    r"\bLabSession\b|\bLabOracleExecutor\b|\bLabTaint\b|\bLabOutput\b"
)

GATE_LINE = re.compile(
    r'#\[cfg\(any\(feature = "lab-oracle", test\)\)\]'
)

VIOLATIONS: list[str] = []


def violation(msg: str) -> None:
    VIOLATIONS.append(msg)


def check_feature_default() -> None:
    manifest = REPO / "crates" / "fss-runtime" / "Cargo.toml"
    with manifest.open("rb") as fh:
        doc = tomllib.load(fh)
    features = doc.get("features", {})
    default = features.get("default", [])
    if "lab-oracle" in default:
        violation(f"{manifest}: 'lab-oracle' listed in default features")
    if "lab-oracle" not in features:
        violation(f"{manifest}: 'lab-oracle' feature missing entirely")
    # No workspace member may enable the feature as a real dependency.
    for member in (REPO / "crates").iterdir():
        mf = member / "Cargo.toml"
        if not mf.is_file():
            continue
        with mf.open("rb") as fh:
            doc = tomllib.load(fh)
        for dep in doc.get("dependencies", {}).values():
            if isinstance(dep, dict) and "lab-oracle" in dep.get("features", []):
                violation(f"{mf}: dependency enables 'lab-oracle'")


def check_sources() -> None:
    src_root = REPO / "crates" / "fss-runtime" / "src"
    for rs in sorted((REPO / "crates").glob("*/src/**/*.rs")):
        text = rs.read_text(encoding="utf-8")
        if not LAB_SYMBOLS.search(text):
            continue
        if rs == src_root / "lab.rs":
            continue  # the module itself
        if rs == src_root / "lib.rs":
            # Only a cfg-gated registration may mention the module: the gate
            # attribute on the same line as, or immediately above, the
            # `pub mod lab;` declaration.
            lines = text.splitlines()
            for n, line in enumerate(lines, 1):
                if not LAB_SYMBOLS.search(line):
                    continue
                gated = bool(GATE_LINE.search(line)) or (
                    n >= 2 and GATE_LINE.search(lines[n - 2])
                )
                if not gated:
                    violation(f"{rs}:{n}: ungated lab reference: {line.strip()}")
            continue
        violation(f"{rs}: references the lab surface outside fss-runtime")


def check_policy() -> None:
    ws = REPO / "Cargo.toml"
    text = ws.read_text(encoding="utf-8")
    if 'foreign_runtime_role = "sealed_laboratory_oracle_only"' not in text:
        violation(f"{ws}: foreign_runtime_role policy changed or missing")


def main() -> int:
    check_feature_default()
    check_sources()
    check_policy()
    if VIOLATIONS:
        print("LAB-ORACLE ABSENCE: FAILED (production surface reachable)")
        for v in VIOLATIONS:
            print(f"  - {v}")
        return 1
    print("LAB-ORACLE ABSENCE: proven (feature off by default, no ungated references, policy intact)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

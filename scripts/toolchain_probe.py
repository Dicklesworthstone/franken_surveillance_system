#!/usr/bin/env python3
"""scripts/toolchain_probe.py — candidate-latest-nightly probe and promotion
report (FSS-184, bead fss-x4a.26.4).

architecture/local_qualification.toml toolchain policy: "candidate nightlies
are promoted only by local full qualification; release uses the exact accepted
pin." This probe NEVER promotes anything — it reports candidacy:

  current            — no installed toolchain is newer than the accepted pin;
  candidate-available — an installed toolchain is newer than the pin (the
                       report names it and the required promotion gate);
  unavailable         — the probe authority (rustup) could not be consulted;
                       candidacy is UNPROVEN, never silently current;
  error               — the probe itself failed.

The report (schema fss.toolchain_promotion.v1) pins: accepted channel, exact
pin file, discovered candidate (if any), and the promotion requirement (local
full qualification + explicit pin change). Exit codes: 0 current, 1
candidate-available (candidacy is a finding, not a failure of the probe), 2
unavailable, 3 error.
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

SCHEMA = "fss.toolchain_promotion.v1"
PIN_FILE = "rust-toolchain.toml"
NIGHTLY_RE = re.compile(r"^nightly-(\d{4})-(\d{2})-(\d{2})$")


def read_accepted_pin(root: Path) -> str | None:
    try:
        text = (root / PIN_FILE).read_text(encoding="utf-8")
    except OSError:
        return None
    match = re.search(r'channel\s*=\s*"([^"]+)"', text)
    return match.group(1) if match else None


def _nightly_key(name: str) -> tuple[int, int, int] | None:
    match = NIGHTLY_RE.match(name.strip())
    if not match:
        return None
    y, m, d = (int(g) for g in match.groups())
    return (y, m, d)


def list_installed_toolchains() -> list[str] | None:
    """Consults rustup (the probe authority). None = unavailable."""
    try:
        proc = subprocess.run(
            ["rustup", "toolchain", "list"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    names = []
    for line in proc.stdout.splitlines():
        name = line.split(None, 1)[0].strip() if line.strip() else ""
        if name:
            names.append(name)
    return names


def probe(root: Path) -> dict:
    accepted = read_accepted_pin(root)
    if accepted is None:
        return {
            "state": "error",
            "evidence": f"accepted pin unreadable from {PIN_FILE}",
        }
    installed = list_installed_toolchains()
    if installed is None:
        return {
            "state": "unavailable",
            "evidence": "rustup unavailable; nightly candidacy unproven",
            "acceptedPin": accepted,
        }
    accepted_key = _nightly_key(accepted)
    candidate: str | None = None
    if accepted_key is not None:
        for name in installed:
            key = _nightly_key(name)
            if key is not None and key > accepted_key and (candidate is None or key > _nightly_key(candidate)):  # noqa: PLR2004 - tuple compare
                candidate = name
    report: dict = {
        "schema": SCHEMA,
        "acceptedPin": accepted,
        "pinFile": PIN_FILE,
        "installedCount": len(installed),
    }
    if candidate is None:
        report.update({
            "state": "current",
            "evidence": "no installed nightly is newer than the accepted pin",
        })
    else:
        report.update({
            "state": "candidate-available",
            "candidate": candidate,
            "evidence": (
                "candidate nightly installed but NOT promoted: promotion requires "
                "local full qualification and an explicit rust-toolchain.toml pin change"
            ),
        })
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="FSS-184 candidate-nightly probe")
    parser.add_argument("--root", type=Path, default=Path("."))
    args = parser.parse_args()
    report = probe(args.root)
    print(json.dumps(report, sort_keys=True))
    return {
        "current": 0,
        "candidate-available": 1,
        "unavailable": 2,
        "error": 3,
    }[report["state"]]


if __name__ == "__main__":
    sys.exit(main())

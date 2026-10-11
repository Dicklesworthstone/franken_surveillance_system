#!/usr/bin/env python3
"""scripts/sbom_crosscheck.py — the SBOM/provenance/source/license/qualification
cross-check (FSS-190, bead fss-x4a.26.10).

The release generators (scripts/release_artifacts.py) produce an SPDX SBOM and
a schema-conformant license inventory from cargo metadata. This checker proves
the four artifacts AGREE — a release must never ship a bundle whose SBOM,
license inventory, source lock, and qualification receipt disagree:

  1. SBOM packages == license inventory packages (name+version), no one-sided
     entries in either direction;
  2. inventory packages == Cargo.lock packages (the source leg);
  3. every package carries a license string; NOASSERTION is a release error
     with remediation guidance (license truth, not omission);
  4. the SBOM documentNamespace binds version+target+metadata digest
     (the provenance leg) when a metadata path is supplied;
  5. when a qualification receipt is supplied, it must parse, its status must
     be "passed", and its cargoLockDigest must match the current Cargo.lock
     (the qualification leg).

Output: one JSON report (schema fss.sbom_crosscheck.v1) on stdout; exit 0 when
every check passes, 1 on any failure, 2 on usage error. Stable identities —
callers must not parse prose.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

SCHEMA = "fss.sbom_crosscheck.v1"


def _lock_packages(lock_text: str) -> set[tuple[str, str]]:
    """Cargo.lock [[package]] name+version pairs (minimal TOML-table walk —
    no toml dependency needed for this fixed shape)."""
    packages: set[tuple[str, str]] = set()
    name = None
    for line in lock_text.splitlines():
        line = line.strip()
        if line == "[[package]]":
            name = None
        elif line.startswith("name = ") and name is None:
            name = line.split("=", 1)[1].strip().strip('"')
        elif line.startswith("version = ") and name is not None:
            version = line.split("=", 1)[1].strip().strip('"')
            packages.add((name, version))
            name = None
    return packages


def _sbom_packages(sbom: dict) -> set[tuple[str, str]]:
    out = set()
    for pkg in sbom.get("packages", []):
        name = pkg.get("name")
        version = pkg.get("versionInfo")
        if name and version:
            out.add((name, version))
    return out


def _inventory_packages(inventory: dict) -> set[tuple[str, str]]:
    out = set()
    for pkg in inventory.get("packages", []):
        name = pkg.get("name")
        version = pkg.get("version")
        if name and version:
            out.add((name, version))
    return out


def crosscheck(sbom: dict, inventory: dict, lock_text: str, metadata: dict | None, receipt: dict | None) -> list[str]:
    """Returns the list of failure strings (empty = pass)."""
    failures: list[str] = []

    if sbom.get("spdxVersion") != "SPDX-2.3":
        failures.append("sbom: spdxVersion is not SPDX-2.3")
    if inventory.get("schema") != "fss.license_inventory.v1":
        failures.append("inventory: schema is not fss.license_inventory.v1")

    sbom_pkgs = _sbom_packages(sbom)
    inv_pkgs = _inventory_packages(inventory)
    if sbom_pkgs != inv_pkgs:
        only_sbom = sorted(sbom_pkgs - inv_pkgs)[:3]
        only_inv = sorted(inv_pkgs - sbom_pkgs)[:3]
        failures.append(
            f"sbom/inventory package sets differ: only-in-sbom={only_sbom} only-in-inventory={only_inv}"
        )

    lock_pkgs = _lock_packages(lock_text)
    if inv_pkgs != lock_pkgs:
        only_inv = sorted(inv_pkgs - lock_pkgs)[:3]
        only_lock = sorted(lock_pkgs - inv_pkgs)[:3]
        failures.append(
            f"inventory/lock package sets differ: only-in-inventory={only_inv} only-in-lock={only_lock}"
        )

    no_license = sorted(
        (p.get("name"), p.get("version"))
        for p in inventory.get("packages", [])
        if not p.get("license") or p.get("license") == "NOASSERTION"
    )
    if no_license:
        failures.append(
            f"inventory: {len(no_license)} package(s) without a license (release error): {no_license[:3]} — declare the license per package; NOASSERTION cannot ship"
        )

    if metadata is not None:
        # The generator's namespace is sha256(version:target:metadata_digest) —
        # verify the SBOM namespace binds that exact provenance chain. The
        # version/target values come from the license inventory (same context).
        md_digest = hashlib.sha256(
            json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        seed = f"{inventory.get('version')}:{inventory.get('target')}:{md_digest}".encode()
        expected_ns_tail = hashlib.sha256(seed).hexdigest()
        ns = sbom.get("documentNamespace", "")
        if not ns.endswith(expected_ns_tail):
            failures.append("sbom: documentNamespace does not bind version+target+metadata digest (provenance leg)")

    if receipt is not None:
        if receipt.get("status") != "passed":
            failures.append(f"qualification receipt status is {receipt.get('status')!r}, not 'passed'")
        want = "sha256:" + hashlib.sha256(lock_text.encode()).hexdigest()
        if receipt.get("cargoLockDigest") != want:
            failures.append("qualification receipt cargoLockDigest does not match the current Cargo.lock")

    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description="FSS-190 SBOM/inventory/lock/qualification cross-check")
    parser.add_argument("--sbom", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, default=None, help="cargo metadata JSON (provenance leg)")
    parser.add_argument("--receipt", type=Path, default=None, help="qualification receipt JSON (qualification leg)")
    args = parser.parse_args()

    try:
        sbom = json.loads(args.sbom.read_text(encoding="utf-8"))
        inventory = json.loads(args.inventory.read_text(encoding="utf-8"))
        lock_text = args.lock.read_text(encoding="utf-8")
        metadata = json.loads(args.metadata.read_text(encoding="utf-8")) if args.metadata else None
        receipt = json.loads(args.receipt.read_text(encoding="utf-8")) if args.receipt else None
    except (OSError, ValueError) as exc:
        print(json.dumps({"schema": SCHEMA, "status": "error", "detail": str(exc)}, sort_keys=True))
        return 2

    failures = crosscheck(sbom, inventory, lock_text, metadata, receipt)
    status = "failed" if failures else "passed"
    report = {
        "schema": SCHEMA,
        "status": status,
        "sbomPackages": len(_sbom_packages(sbom)),
        "inventoryPackages": len(_inventory_packages(inventory)),
        "lockPackages": len(_lock_packages(lock_text)),
        "failures": failures,
    }
    print(json.dumps(report, sort_keys=True))
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())

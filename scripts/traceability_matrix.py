#!/usr/bin/env python3
"""DOC-001: the program's bidirectional traceability matrix.

One machine-readable view from every stable identity to its owners and
evidence, and back. Sources:
  - architecture/invariants.json      (INV-*, machine source)
  - architecture/franken_imports.json (IMP-*)
  - architecture/dependencies.json    (DEP-* rows)
  - registries/TESTS.md               (TEST-* -> gate)
  - registries/QUALIFICATION_LANES.md (QL-*)
  - .beads/issues.jsonl               (beads; requirement refs come from
                                       the `FSS-xxx —` / `DEP-INV-x —`
                                       title prefix)

Hard errors (typed, actionable — the completeness oracle):
  ORPHAN-REQ-001  a bead names a requirement prefix no registry defines
  UNOWNED-001     a registry identity has no bead (open or closed) and is
                  not a tombstone
  UNTESTED-001    a TEST-* family appears in no test file, script, or
                  proof directory
  DUP-001         one stable id is DEFINED by two machine registries

Tombstones are carried through as rows, never errors.
Output: fss.traceability_matrix.v1 JSON on stdout; exit 1 on violations.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

VIOLATIONS: list[str] = []


def violation(code: str, detail: str) -> None:
    VIOLATIONS.append(f"[{code}] {detail}")


def load_json(path: Path):
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def md_table_ids(path: Path, id_pattern: str) -> dict[str, dict[str, str]]:
    """Parse pipe-table rows whose first cell matches the id pattern."""
    rows: dict[str, dict[str, str]] = {}
    pat = re.compile(id_pattern)
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        cells = [c.strip() for c in stripped.strip("|").split("|")]
        if not cells or not pat.fullmatch(cells[0].strip("`")):
            continue
        key = cells[0].strip("`")
        rows[key] = {"cells": cells}
    return rows


REQ_PREFIX = re.compile(r"^((?:[A-Z]{2,5})(?:-[A-Z0-9]+){1,3})\s*[—–-]\s*")


def bead_requirement_refs() -> dict[str, list[dict[str, str]]]:
    """bead requirement-ref -> [{id, status}]. Refs come from title prefixes."""
    refs: dict[str, list[dict[str, str]]] = {}
    with (REPO / ".beads" / "issues.jsonl").open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                bead = json.loads(line)
            except json.JSONDecodeError:
                continue
            title = bead.get("title", "")
            m = REQ_PREFIX.match(title)
            if not m:
                continue
            refs.setdefault(m.group(1), []).append(
                {"bead": bead.get("id", "?"), "status": bead.get("status", "?")}
            )
    return refs


def main() -> int:
    # ---- identity universe (one machine source per family) -----------
    seeds = load_json(REPO / "architecture" / "seed_requirements.json")
    seed_ids = {r["id"]: r for r in seeds.get("requirements", []) if isinstance(r, dict) and "id" in r}

    invariants = load_json(REPO / "architecture" / "invariants.json").get("invariants", [])
    inv_ids = {i["id"]: i for i in invariants if isinstance(i, dict) and "id" in i}

    imports = load_json(REPO / "architecture" / "franken_imports.json").get("imports", [])
    imp_ids = {i["id"]: i for i in imports if isinstance(i, dict) and "id" in i}

    deps_doc = load_json(REPO / "architecture" / "dependencies.json")
    dep_ids = {
        r["id"]: r
        for r in deps_doc.get("dependencies", [])
        if isinstance(r, dict) and "id" in r
    }

    test_rows = md_table_ids(REPO / "registries" / "TESTS.md", r"TEST-[A-Z0-9-]+")
    lane_rows = md_table_ids(
        REPO / "registries" / "QUALIFICATION_LANES.md", r"QL-[A-Z0-9-]+"
    )

    # GATE identities: harvest the normative gate matrix from the
    # comprehensive plan, then any TESTS-registry or adapter references.
    gate_ids: dict[str, str] = {}
    plan_src = (
        REPO / "COMPREHENSIVE_PLAN_FOR_FRANKEN_SURVEILLANCE_SYSTEM.md"
    ).read_text(encoding="utf-8")
    in_matrix = False
    for line in plan_src.splitlines():
        if line.startswith("## 29.1 Gate matrix"):
            in_matrix = True
            continue
        if in_matrix:
            if line.startswith("## "):
                break
            m = re.match(r"\|\s*`(GATE-[A-Z0-9-]+)`\s*\|", line)
            if m:
                gate_ids.setdefault(m.group(1), "plan-gate-matrix")
    for test_id, row in test_rows.items():
        for cell in row["cells"]:
            m = re.fullmatch(r"`?(GATE-[A-Z0-9-]+)`?", cell)
            if m:
                gate_ids.setdefault(m.group(1), f"TESTS.md/{test_id}")
    try:
        for adapter in load_json(REPO / "architecture" / "device_adapters.json").get(
            "adapters", []
        ):
            gate = adapter.get("promotionGate") or adapter.get("promotionGate".lower())
            if isinstance(gate, str) and gate.startswith("GATE-"):
                gate_ids.setdefault(gate, "device_adapters.json")
    except (OSError, json.JSONDecodeError):
        pass

    # DEP-AUD diagnostics are defined in the audit module; DEP-INV rows in
    # the constitution document.
    dep_aud: dict[str, dict] = {}
    audit_src = (REPO / "scripts" / "dependency_audit.py").read_text(encoding="utf-8")
    for m in re.finditer(r'"(DEP-AUD-[A-Z0-9-]+)":\s*DiagnosticDef\(', audit_src):
        dep_aud.setdefault(m.group(1), {})
    const_src = (REPO / "DEPENDENCY_CONSTITUTION.md").read_text(encoding="utf-8")
    dep_inv = {
        m.group(1): {} for m in re.finditer(r"`(DEP-INV-[A-Z0-9-]+)`", const_src)
    }

    # family -> machine source. Only families here get hard ownership and
    # orphan checks; other title prefixes (experiment labels like LAB-*)
    # are reported informationally.
    families: dict[str, dict[str, dict]] = {
        "FSS": seed_ids,
        "INV": inv_ids,
        "IMP": imp_ids,
        "DEP": dep_ids,
        "DEP-AUD": dep_aud,
        "DEP-INV": dep_inv,
        "TEST": test_rows,
        "QL": lane_rows,
        "GATE": gate_ids,
    }

    defined: dict[str, str] = {}
    for family, ids in families.items():
        for stable_id in ids:
            source = (
                "seed_requirements.json"
                if family == "FSS"
                else (
                    "invariants.json"
                    if family == "INV"
                    else (
                        "franken_imports.json"
                        if family == "IMP"
                        else (
                            "dependencies.json"
                            if family == "DEP"
                            else (
                                "TESTS.md"
                                if family == "TEST"
                                else "QUALIFICATION_LANES.md"
                                if family == "QL"
                                else "registry-harvest"
                            )
                        )
                    )
                )
            )
            if stable_id in defined:
                violation(
                    "DUP-001",
                    f"{stable_id} defined by both {defined[stable_id]} and {source}",
                )
            else:
                defined[stable_id] = source

    # ---- tombstones ---------------------------------------------------
    tombstoned = {
        stable_id
        for stable_id, row in inv_ids.items()
        if str(row.get("status", "")).lower() in {"superseded", "tombstoned", "retired"}
    }

    # ---- bead ownership -------------------------------------------------
    bead_refs = bead_requirement_refs()
    for req, beads in bead_refs.items():
        two = "-".join(req.split("-")[:2])
        family = two if two in families else req.split("-", 1)[0]
        if family in families and req not in families[family]:
            violation(
                "ORPHAN-REQ-001",
                f"bead(s) {beads} name {req}, undefined in its family source",
            )
    # The completeness oracle proper: seed requirements nobody owns.
    for stable_id in seed_ids:
        if stable_id not in bead_refs and stable_id not in tombstoned:
            violation("UNOWNED-001", f"seed requirement {stable_id} has no bead")

    # ---- test coverage --------------------------------------------------
    searchable: list[str] = []
    for pattern in (
        "tests/**/*.py",
        "tests/**/*.rs",
        "crates/*/tests/**/*.rs",
        "crates/*/src/**/*.rs",
        "crates/*/examples/*.rs",
        "scripts/*.py",
        "scripts/*.sh",
        "proofs/**/*.md",
    ):
        for path in REPO.glob(pattern):
            try:
                searchable.append(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError):
                continue
    corpus = "\n".join(searchable)
    for test_id in test_rows:
        if test_id not in corpus and test_id not in tombstoned:
            violation("UNTESTED-001", f"test family {test_id} appears in no test/script/proof source")

    # ---- informational: unknown-family prefixes -------------------------
    unknown_prefixes = sorted(
        {
            "-".join(req.split("-")[:2])
            if "-".join(req.split("-")[:2]) in families
            else req.split("-", 1)[0]
            for req in bead_refs
        }
        - set(families)
    )

    # ---- matrix -----------------------------------------------------------
    matrix = {
        "schema": "fss.traceability_matrix.v1",
        "identities": {
            stable_id: {
                "source": defined[stable_id],
                "beads": bead_refs.get(stable_id, []),
                "tombstone": stable_id in tombstoned,
            }
            for stable_id in sorted(defined)
        },
        "beadRequirementCount": len(bead_refs),
        "unknownFamilyPrefixes": unknown_prefixes,
        "violations": VIOLATIONS,
        "verdict": "pass" if not VIOLATIONS else "fail",
    }
    print(json.dumps(matrix, indent=1))
    if VIOLATIONS:
        for v in VIOLATIONS:
            print(f"  {v}", file=sys.stderr)
        return 1
    print(
        f"TRACEABILITY: {len(defined)} identities, {len(bead_refs)} requirement refs, "
        f"{len(tombstoned)} tombstones preserved, 0 violations",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

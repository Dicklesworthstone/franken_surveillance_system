#!/usr/bin/env python3
"""Tests for scripts/traceability_matrix.py (DOC-001)."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "traceability_matrix.py"

spec = importlib.util.spec_from_file_location("traceability_matrix", SCRIPT)
tm = importlib.util.module_from_spec(spec)
sys.modules["traceability_matrix"] = tm
spec.loader.exec_module(tm)


def build_repo(
    *,
    seeds: list[str],
    invariants: list[str],
    tests_md: str,
    beads: list[tuple[str, str]],
    corpus_files: dict[str, str] | None = None,
    extra_seed_dup: bool = False,
) -> Path:
    root = Path(tempfile.mkdtemp())
    (root / "architecture").mkdir()
    (root / "registries").mkdir()
    (root / ".beads").mkdir()
    (root / "tests").mkdir()
    (root / "scripts").mkdir()
    (root / "proofs").mkdir()

    seed_reqs = [{"id": s, "title": f"req {s}"} for s in seeds]
    if extra_seed_dup:
        seed_reqs.append({"id": seeds[0], "title": "dup"})
    (root / "architecture" / "seed_requirements.json").write_text(
        json.dumps({"schema": "t", "requirements": seed_reqs})
    )
    (root / "architecture" / "invariants.json").write_text(
        json.dumps(
            {
                "schema": "t",
                "invariants": [{"id": i, "text": "x", "status": "active"} for i in invariants],
            }
        )
    )
    (root / "architecture" / "franken_imports.json").write_text(
        json.dumps({"schema": "t", "imports": []})
    )
    (root / "architecture" / "dependencies.json").write_text(
        json.dumps({"schema": "t", "dependencies": []})
    )
    (root / "registries" / "TESTS.md").write_text(tests_md)
    (root / "registries" / "QUALIFICATION_LANES.md").write_text("# lanes\n")
    (root / "scripts" / "dependency_audit.py").write_text("# no diagnostics\n")
    (root / "DEPENDENCY_CONSTITUTION.md").write_text("# no invariants\n")
    (root / "COMPREHENSIVE_PLAN_FOR_FRANKEN_SURVEILLANCE_SYSTEM.md").write_text(
        "# plan\n\n## 29.1 Gate matrix\n\n| Gate | Name | Evidence |\n|---|---|---|\n\n## 30 end\n"
    )
    with (root / ".beads" / "issues.jsonl").open("w") as fh:
        for bid, title in beads:
            fh.write(json.dumps({"id": bid, "title": title, "status": "closed"}) + "\n")
    for rel, content in (corpus_files or {}).items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    return root


def run(root: Path) -> dict:
    tm.REPO = root
    tm.VIOLATIONS.clear()
    import io
    import contextlib

    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = tm.main()
    matrix = json.loads(out.getvalue())
    matrix["_rc"] = rc
    return matrix


def test_pass_path() -> None:
    root = build_repo(
        seeds=["FSS-001"],
        invariants=["INV-001"],
        tests_md="# t\n\n| ID | Family | Gate |\n|---|---|---|\n| `TEST-A-001` | a | `GATE-010` |\n",
        beads=[("b1", "FSS-001 — the requirement")],
        corpus_files={"tests/a.rs": "// TEST-A-001"},
    )
    m = run(root)
    assert m["_rc"] == 0, m["violations"]
    assert m["verdict"] == "pass"
    assert m["identities"]["FSS-001"]["beads"][0]["bead"] == "b1"
    assert m["identities"]["FSS-001"]["tombstone"] is False


def test_orphan_requirement() -> None:
    root = build_repo(
        seeds=["FSS-001"],
        invariants=[],
        tests_md="# t\n",
        beads=[("b1", "FSS-999 — ghost requirement")],
    )
    m = run(root)
    assert m["_rc"] == 1
    assert any("ORPHAN-REQ-001" in v and "FSS-999" in v for v in m["violations"])


def test_unowned_seed_requirement() -> None:
    root = build_repo(
        seeds=["FSS-001", "FSS-002"],
        invariants=[],
        tests_md="# t\n",
        beads=[("b1", "FSS-001 — owned")],
    )
    m = run(root)
    assert m["_rc"] == 1
    assert any("UNOWNED-001" in v and "FSS-002" in v for v in m["violations"])


def test_untested_family() -> None:
    root = build_repo(
        seeds=["FSS-001"],
        invariants=[],
        tests_md="# t\n\n| ID | Family | Gate |\n|---|---|---|\n| `TEST-B-001` | b | `GATE-010` |\n",
        beads=[("b1", "FSS-001 — owned")],
        corpus_files={},
    )
    m = run(root)
    assert m["_rc"] == 1
    assert any("UNTESTED-001" in v and "TEST-B-001" in v for v in m["violations"])


def test_duplicate_identity() -> None:
    root = build_repo(
        seeds=["INV-001"],
        invariants=["INV-001"],
        tests_md="# t\n",
        beads=[("b1", "INV-001 — owned")],
    )
    m = run(root)
    assert any("DUP-001" in v for v in m["violations"])


def test_tombstones_never_error() -> None:
    root = Path(tempfile.mkdtemp())
    (root / "architecture").mkdir()
    (root / "registries").mkdir()
    (root / ".beads").mkdir()
    (root / "tests").mkdir()
    (root / "scripts").mkdir()
    (root / "proofs").mkdir()
    (root / "architecture" / "seed_requirements.json").write_text(
        json.dumps({"schema": "t", "requirements": []})
    )
    (root / "architecture" / "invariants.json").write_text(
        json.dumps(
            {
                "schema": "t",
                "invariants": [
                    {"id": "INV-009", "text": "x", "status": "superseded"},
                ],
            }
        )
    )
    (root / "architecture" / "franken_imports.json").write_text(
        json.dumps({"schema": "t", "imports": []})
    )
    (root / "architecture" / "dependencies.json").write_text(
        json.dumps({"schema": "t", "dependencies": []})
    )
    (root / "registries" / "TESTS.md").write_text("# t\n")
    (root / "registries" / "QUALIFICATION_LANES.md").write_text("# lanes\n")
    (root / "scripts" / "dependency_audit.py").write_text("# none\n")
    (root / "DEPENDENCY_CONSTITUTION.md").write_text("# none\n")
    (root / "COMPREHENSIVE_PLAN_FOR_FRANKEN_SURVEILLANCE_SYSTEM.md").write_text(
        "# plan\n\n## 29.1 Gate matrix\n\n| Gate |\n|---|\n\n## 30 end\n"
    )
    (root / ".beads" / "issues.jsonl").write_text("")
    m = run(root)
    assert m["_rc"] == 0
    assert m["identities"]["INV-009"]["tombstone"] is True


def main() -> int:
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except AssertionError as exc:
                failures += 1
                print(f"FAIL {name}: {exc}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

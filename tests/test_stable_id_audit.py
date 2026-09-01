#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/stable_id_audit.py"

spec = importlib.util.spec_from_file_location("stable_id_audit", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def write_fixture(root: Path, plan: str, rows: list[dict[str, str]], goals: list[str], scenarios: list[str]) -> tuple[Path, Path]:
    plan_path = root / "plan.md"
    resolution_path = root / "resolution.json"
    plan_path.write_text(plan, encoding="utf-8")
    resolution_path.write_text(
        json.dumps(
            {
                "schema": "fss.stable_id_resolution.v1",
                "expected": {
                    "goalCanonicalIds": goals,
                    "northStarCanonicalIds": scenarios,
                },
                "resolutions": rows,
            }
        ),
        encoding="utf-8",
    )
    return plan_path, resolution_path


def row(legacy: str, title: str, canonical: str) -> dict[str, str]:
    return {
        "legacyId": legacy,
        "title": title,
        "canonicalId": canonical,
        "disposition": "fixture",
        "titleDigest": module._title_digest(legacy, title),
    }


with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    plan, resolution = write_fixture(
        root,
        """### `GOAL-001` — First
### `GOAL-001` — Second
### Scenario NS-1 — One
### Scenario NS-1 — Two
""",
        [
            row("GOAL-001", "First", "GOAL-001"),
            row("GOAL-001", "Second", "GOAL-002"),
            row("NS-1", "One", "NS-1"),
            row("NS-1", "Two", "NS-2"),
        ],
        ["GOAL-001", "GOAL-002"],
        ["NS-1", "NS-2"],
    )
    report = module.audit(plan, resolution)
    assert report["canonicalDefinitionCount"] == 4
    assert report["legacyCollisions"] == {"GOAL-001": 2, "NS-1": 2}

with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    plan, resolution = write_fixture(
        root,
        """### `GOAL-001` — First
### `GOAL-001` — Second
### Scenario NS-1 — One
""",
        [row("GOAL-001", "First", "GOAL-001")],
        ["GOAL-001", "GOAL-002"],
        ["NS-1"],
    )
    try:
        module.audit(plan, resolution)
    except module.AuditError as exc:
        assert "unresolved collided" in str(exc)
    else:
        raise AssertionError("unresolved collision should fail")

with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    bad = row("GOAL-001", "First", "GOAL-001")
    bad["titleDigest"] = "sha256:" + "0" * 64
    plan, resolution = write_fixture(
        root,
        """### `GOAL-001` — First
### Scenario NS-1 — One
""",
        [bad],
        ["GOAL-001"],
        ["NS-1"],
    )
    try:
        module.audit(plan, resolution)
    except module.AuditError as exc:
        assert "fingerprint mismatch" in str(exc)
    else:
        raise AssertionError("fingerprint drift should fail")

print("stable-ID audit tests passed")

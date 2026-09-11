#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/stable_id_audit.py"

spec = importlib.util.spec_from_file_location("stable_id_audit", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
sys.modules["stable_id_audit"] = module
spec.loader.exec_module(module)


def write_fixture(
    root: Path,
    plan: str,
    rows: list[dict[str, str]],
    goals: list[str],
    scenarios: list[str],
) -> tuple[Path, Path]:
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


def test_baseline_duplicate_collision_and_resolution() -> None:
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
        assert report["status"] == "passed"


def test_unresolved_collision_rejected() -> None:
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
            assert exc.error_id == module.ERR_COLLISION
            assert "unresolved collided" in str(exc)
        else:
            raise AssertionError("unresolved collision should fail")


def test_fingerprint_mismatch_rejected() -> None:
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
            assert exc.error_id == module.ERR_FINGERPRINT_MISMATCH
            assert "fingerprint mismatch" in str(exc)
        else:
            raise AssertionError("fingerprint drift should fail")


def test_stale_resolution_rejected() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        plan, resolution = write_fixture(
            root,
            """### `GOAL-001` — First
### Scenario NS-1 — One
""",
            [
                row("GOAL-001", "First", "GOAL-001"),
                row("GOAL-002", "Phantom", "GOAL-002"),
            ],
            ["GOAL-001"],
            ["NS-1"],
        )
        try:
            module.audit(plan, resolution)
        except module.AuditError as exc:
            assert exc.error_id == module.ERR_STALE_RESOLUTION
            assert "stale occurrences" in str(exc)
        else:
            raise AssertionError("stale resolution row should fail")


def test_canonical_collision_rejected() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        plan, resolution = write_fixture(
            root,
            """### `GOAL-001` — First
### `GOAL-002` — Second
### Scenario NS-1 — One
""",
            [
                row("GOAL-001", "First", "GOAL-001"),
                row("GOAL-002", "Second", "GOAL-001"),
            ],
            ["GOAL-001"],
            ["NS-1"],
        )
        try:
            module.audit(plan, resolution)
        except module.AuditError as exc:
            assert exc.error_id == module.ERR_CANONICAL_COLLISION
            assert "canonical ID reused" in str(exc)
        else:
            raise AssertionError("canonical collision should fail")


def test_census_drift_rejected() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        plan, resolution = write_fixture(
            root,
            """### `GOAL-001` — First
### Scenario NS-1 — One
""",
            [],
            ["GOAL-001", "GOAL-002"],
            ["NS-1"],
        )
        try:
            module.audit(plan, resolution)
        except module.AuditError as exc:
            assert exc.error_id == module.ERR_CENSUS_DRIFT
            assert "census drift" in str(exc)
        else:
            raise AssertionError("census drift should fail")


def test_planted_negative_false_green_reproduction() -> None:
    """Proves the old check-policy set-dedup regex was a false green on collided definitions.

    Old check:
      re.compile(r"\\b(INV|GOAL|...)-[0-9]{3}\\b").findall(...) inserted into a set().
    Flaws:
      1. NS-1..NS-13 were omitted completely (only 3 digits matched).
      2. Duplicate definitions of GOAL-019 were silently deduplicated in set().
    """
    import re
    old_regex = re.compile(
        r"\b(INV|GOAL|NONGOAL|CAP|EFFECT|ERR|SCHEMA|ADR|INT|WP|GATE|TEST|SLO|COST|RISK|OPEN|LAB|ADP|MOD|ALG|PUB|DEC|DEP|REL|FMT|TRACE|ATP|AGT|AOP|AVIEW|KSTATE|PROV|QL)-[0-9]{3}\b"
    )

    collided_text = """### `GOAL-019` — Agent legibility
### `GOAL-019` — Agent epistemic ergonomics
### Scenario NS-9 — Cold-start orientation
### Scenario NS-9 — Cold resume after host loss
"""
    # 1. Under old logic:
    matches = old_regex.findall(collided_text)
    unique_set = set(matches)
    # Old logic falsely passes: exactly 1 GOAL found in set, 0 NS found, collision hidden!
    assert unique_set == {"GOAL"}
    assert len(unique_set) == 1

    # 2. Under new definition-aware checker:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        plan, resolution = write_fixture(
            root,
            collided_text,
            [],  # Empty resolutions: collision must fail!
            ["GOAL-019"],
            ["NS-9"],
        )
        try:
            module.audit(plan, resolution)
        except module.AuditError as exc:
            assert exc.error_id == module.ERR_COLLISION
            assert "unresolved collided stable definition GOAL-019" in str(exc)
        else:
            raise AssertionError("new checker must reject unresolved duplicate definitions")


def test_exhaustive_grammar_families_and_widths() -> None:
    # Test valid 1-digit and 2-digit NS
    for n in range(1, 16):
        rule, num = module.validate_identifier_syntax(f"NS-{n}")
        assert rule.name == "NS"
        assert num == str(n)

    # Test valid ADR widths: 3 and 4 digits
    rule, _ = module.validate_identifier_syntax("ADR-001")
    assert rule.name == "ADR"
    rule, _ = module.validate_identifier_syntax("ADR-0001")
    assert rule.name == "ADR"
    rule, _ = module.validate_identifier_syntax("ADR-0013")
    assert rule.name == "ADR"

    # Test all normative families with valid sample
    for name, rule in module.NORMATIVE_FAMILIES.items():
        if rule.hierarchical:
            tok = f"{name}-SUB-001"
            parsed_rule, _ = module.validate_identifier_syntax(tok)
            assert parsed_rule.name == name
        elif rule.name == "NS":
            tok = "NS-1"
            parsed_rule, _ = module.validate_identifier_syntax(tok)
            assert parsed_rule.name == "NS"
        else:
            width = rule.allowed_widths[0]
            tok = f"{name}-{'0' * width}"
            parsed_rule, _ = module.validate_identifier_syntax(tok)
            assert parsed_rule.name == name

    # Test malformed width rejections
    for bad_token in ["GOAL-1", "INV-12", "ADR-1", "NS-001", "NS-0", "NS-100", "GATE-99"]:
        try:
            module.validate_identifier_syntax(bad_token)
        except module.AuditError as exc:
            assert exc.error_id == module.ERR_MALFORMED_WIDTH, f"Expected ERR_MALFORMED_WIDTH for {bad_token}"
        else:
            raise AssertionError(f"Expected malformed width failure for {bad_token}")

    # Test malformed zero-padding rejections on NS
    for bad_ns in ["NS-01", "NS-09"]:
        try:
            module.validate_identifier_syntax(bad_ns)
        except module.AuditError as exc:
            assert exc.error_id == module.ERR_MALFORMED_WIDTH
            assert "malformed zero padding" in str(exc)
        else:
            raise AssertionError(f"Expected zero padding failure for {bad_ns}")


def test_grammar_case_and_unknown_families() -> None:
    for bad_case in ["goal-001", "Goal-001", "ns-1", "Adr-0001"]:
        try:
            module.validate_identifier_syntax(bad_case)
        except module.AuditError as exc:
            assert exc.error_id == module.ERR_MALFORMED_CASE, f"Expected ERR_MALFORMED_CASE for {bad_case}"
        else:
            raise AssertionError(f"Expected malformed case failure for {bad_case}")

    for unknown in ["FOO-001", "UNKNOWN-999", "BAR-BAZ-001", "FAKE-NS-1"]:
        try:
            module.validate_identifier_syntax(unknown)
        except module.AuditError as exc:
            assert exc.error_id == module.ERR_UNKNOWN_FAMILY, f"Expected ERR_UNKNOWN_FAMILY for {unknown}"
        else:
            raise AssertionError(f"Expected unknown family failure for {unknown}")

    for bad_hier in ["GOAL-SUB-001", "INV-EXTRA-001", "NS-SUB-1", "GATE-EXTRA-001"]:
        try:
            module.validate_identifier_syntax(bad_hier)
        except module.AuditError as exc:
            assert exc.error_id == module.ERR_MALFORMED_HIERARCHY, f"Expected ERR_MALFORMED_HIERARCHY for {bad_hier}"
        else:
            raise AssertionError(f"Expected malformed hierarchy failure for {bad_hier}")


def test_reference_resolution_and_dangling_references() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        plan, resolution = write_fixture(
            root,
            """### `GOAL-001` — First
### Scenario NS-1 — One

Here is a reference to GOAL-001 which is valid.
Here is a reference to GOAL-999 which is dangling.
""",
            [],
            ["GOAL-001"],
            ["NS-1"],
        )
        try:
            module.audit(plan, resolution)
        except module.AuditError as exc:
            assert exc.error_id == module.ERR_DANGLING_REFERENCE
            assert "dangling reference to 'GOAL-999'" in str(exc)
        else:
            raise AssertionError("dangling reference should fail")


def test_code_fences_and_prose_exclusions() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        plan, resolution = write_fixture(
            root,
            """### `GOAL-001` — First
### Scenario NS-1 — One

In standard prose: UTF-8, RFC-7231, and ISO-8601 are valid technical standards and not stable IDs.

```text
# This code fence has example IDs that must not cause dangling reference errors:
FOO-001
GOAL-999
INV-999
```

Reference to GOAL-001 again.
""",
            [],
            ["GOAL-001"],
            ["NS-1"],
        )
        report = module.audit(plan, resolution)
        assert report["status"] == "passed"
        assert report["referenceCount"] == 1


def test_crlf_and_bom() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        crlf_text = "\ufeff### `GOAL-001` — First\r\n### Scenario NS-1 — One\r\n"
        plan, resolution = write_fixture(
            root,
            crlf_text,
            [],
            ["GOAL-001"],
            ["NS-1"],
        )
        report = module.audit(plan, resolution)
        assert report["status"] == "passed"
        assert report["canonicalDefinitionCount"] == 2


def test_census_markdown_sources_hook() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        f1 = root / "doc1.md"
        f2 = root / "doc2.md"
        f1.write_text("### `INV-001` — First\n\nReference to INV-001\n", encoding="utf-8")
        f2.write_text("Reference to INV-001\n", encoding="utf-8")
        res_file = root / "resolution.json"
        res_file.write_text(json.dumps({"schema": "fss.stable_id_resolution.v1", "resolutions": []}), encoding="utf-8")

        result = module.census_markdown_sources([f1, f2], res_file)
        assert result["status"] == "passed"
        assert result["totalDefinitions"] == 1
        assert result["totalReferences"] == 2

        # Dangling reference in doc2
        f2.write_text("Reference to INV-999\n", encoding="utf-8")
        try:
            module.census_markdown_sources([f1, f2], res_file)
        except module.AuditError as exc:
            assert exc.error_id == module.ERR_DANGLING_REFERENCE
        else:
            raise AssertionError("expected dangling reference error in multi-file census")

        # Colliding definitions across files without resolution
        f2.write_text("### `INV-001` — Second Meaning\n", encoding="utf-8")
        try:
            module.census_markdown_sources([f1, f2], res_file)
        except module.AuditError as exc:
            assert exc.error_id == module.ERR_COLLISION
        else:
            raise AssertionError("expected collision error in multi-file census")


def test_cli_flags_and_jsonl() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        jsonl_path = root / "out.jsonl"
        # Test CLI --emit-grammar
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--emit-grammar"],
            capture_output=True,
            text=True,
            check=True,
        )
        grammar = json.loads(proc.stdout)
        assert grammar["schema"] == "fss.stable_id_grammar.v1"
        assert "NS" in grammar["families"]
        assert "ADR" in grammar["families"]

        # Test CLI --jsonl
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--jsonl", str(jsonl_path)],
            capture_output=True,
            text=True,
            check=True,
        )
        assert jsonl_path.is_file()
        lines = [json.loads(line) for line in jsonl_path.read_text(encoding="utf-8").splitlines()]
        assert len(lines) > 0
        assert any(item["kind"] == "definition" and item["id"] == "GOAL-001" for item in lines)


def test_real_repository_audit() -> None:
    report = module.audit(module.DEFAULT_PLAN, module.DEFAULT_RESOLUTION)
    assert report["status"] == "passed"
    assert report["schema"] == "fss.stable_id_audit.v1"
    assert report["grammarVersion"] == "fss.stable_id_grammar.v1"
    assert report["goalCanonicalCount"] == 25
    assert report["northStarCanonicalCount"] == 15
    assert report["sourceDefinitionCount"] == 40
    assert report["legacyCollisions"] == {
        "GOAL-019": 2,
        "GOAL-020": 2,
        "NS-9": 2,
        "NS-10": 2,
    }


def main() -> None:
    test_baseline_duplicate_collision_and_resolution()
    test_unresolved_collision_rejected()
    test_fingerprint_mismatch_rejected()
    test_stale_resolution_rejected()
    test_canonical_collision_rejected()
    test_census_drift_rejected()
    test_planted_negative_false_green_reproduction()
    test_exhaustive_grammar_families_and_widths()
    test_grammar_case_and_unknown_families()
    test_reference_resolution_and_dangling_references()
    test_code_fences_and_prose_exclusions()
    test_crlf_and_bom()
    test_census_markdown_sources_hook()
    test_cli_flags_and_jsonl()
    test_real_repository_audit()
    print("all stable-ID audit tests passed")


if __name__ == "__main__":
    main()

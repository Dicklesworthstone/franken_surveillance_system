#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/stable_id_audit.py"

sys.path.insert(0, str(ROOT / "scripts"))
import stable_id_audit as module


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
# Fenced stable-ID examples must resolve to live definitions; non-family tokens are ignored:
FOO-001
GOAL-001
NS-1
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


def test_loophole_1_fenced_code_block_collision_and_extractor_consistency() -> None:
    # 1. _extract_plan_definitions must not extract definitions from code blocks
    plan_text = """```markdown
### `GOAL-001` — Laundered In Code Fence
```
### `GOAL-001` — Legitimate Definition
"""
    defs = module._extract_plan_definitions(plan_text)
    assert len(defs) == 1, f"Expected 1 definition, got {len(defs)}: code fences must not be parsed as definitions"

    # 2. Definitions in code block must not be treated as live definitions or cause false collisions
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        doc1 = root / "doc1.md"
        doc2 = root / "doc2.md"
        doc1.write_text("### `INV-001` — First Meaning\n", encoding="utf-8")
        doc2.write_text("```markdown\n### `INV-001` — First Meaning\n```\n", encoding="utf-8")
        res_file = root / "resolution.json"
        res_file.write_text(json.dumps({"schema": "fss.stable_id_resolution.v1", "resolutions": []}), encoding="utf-8")
        report = module.census_markdown_sources([doc1, doc2], res_file)
        assert report["status"] == "passed"
        assert report["totalDefinitions"] == 1
        defs2, _, examples2 = module._extract_all_occurrences(doc2.read_text(encoding="utf-8"), "doc2.md")
        assert len(defs2) == 0
        assert "INV-001" in examples2


def test_loophole_2_html_comments_multiline_and_single_line() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        doc = root / "doc.md"
        # Multiline HTML comment containing deprecated definition should not cause collision
        doc.write_text("""### `INV-001` — Active Definition
<!--
### `INV-001` — Deprecated Commented Out
-->
""", encoding="utf-8")
        res_file = root / "resolution.json"
        res_file.write_text(json.dumps({"schema": "fss.stable_id_resolution.v1", "resolutions": []}), encoding="utf-8")
        report = module.census_markdown_sources([doc], res_file)
        assert report["status"] == "passed"
        assert report["totalDefinitions"] == 1

        # Single-line comment should not extract references
        doc2 = root / "doc2.md"
        doc2.write_text("<!-- Reference to INV-999 in comment -->\n", encoding="utf-8")
        report2 = module.census_markdown_sources([doc2], res_file)
        assert report2["status"] == "passed"
        assert report2["totalReferences"] == 0


def test_loophole_3_width_aliasing_collision_and_resolution() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        doc1 = root / "doc1.md"
        doc2 = root / "doc2.md"
        # ADR-001 and ADR-0001 are the same entity (ADR #1)
        doc1.write_text("### `ADR-001` — First Decision\n", encoding="utf-8")
        doc2.write_text("### `ADR-0001` — Conflicting Decision\n", encoding="utf-8")
        res_file = root / "resolution.json"
        res_file.write_text(json.dumps({"schema": "fss.stable_id_resolution.v1", "resolutions": []}), encoding="utf-8")
        try:
            module.census_markdown_sources([doc1, doc2], res_file)
        except module.AuditError as exc:
            assert exc.error_id == module.ERR_COLLISION
            assert "ADR-001" in str(exc) or "ADR-0001" in str(exc)
        else:
            raise AssertionError("ADR-001 and ADR-0001 must be recognized as colliding aliases")


def test_loophole_4_prose_exclusion_not_masking_real_definitions_or_invalid_tokens() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        doc = root / "doc.md"
        # Headings with prefix in EXCLUDED_PROSE_PREFIXES (e.g. CI) must not be silently skipped as definitions
        doc.write_text("""### `CI-001` — First Meaning
### `CI-001` — Colliding Second Meaning
""", encoding="utf-8")
        res_file = root / "resolution.json"
        res_file.write_text(json.dumps({"schema": "fss.stable_id_resolution.v1", "resolutions": []}), encoding="utf-8")
        try:
            module.census_markdown_sources([doc], res_file)
        except module.AuditError as exc:
            # Must raise either unknown family (since CI is not normative) or collision, not silently pass
            assert exc.error_id in (module.ERR_UNKNOWN_FAMILY, module.ERR_COLLISION)
        else:
            raise AssertionError("heading with prose-like prefix must not be silently ignored")


def test_loophole_5_near_miss_and_registry_ingestion_validation() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        arch_dir = root / "architecture"
        arch_dir.mkdir()
        bad_json = arch_dir / "bad_reg.json"
        # Invalid family in architecture JSON must be rejected on ingestion
        bad_json.write_text(json.dumps({"id": "GOLA-001"}), encoding="utf-8")
        try:
            module._load_repository_definitions(root)
        except module.AuditError as exc:
            assert exc.error_id == module.ERR_UNKNOWN_FAMILY
            assert "GOLA" in str(exc)
        else:
            raise AssertionError("invalid ID in architecture JSON must fail validation on ingestion")


def test_loophole_6_tombstoned_id_reference_rejected() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        doc = root / "doc.md"
        doc.write_text("Reference to tombstoned GOAL-099 should be rejected\n", encoding="utf-8")
        res_file = root / "resolution.json"
        res_file.write_text(
            json.dumps({
                "schema": "fss.stable_id_resolution.v1",
                "resolutions": [
                    {
                        "legacyId": "GOAL-099",
                        "title": "Obsolete Goal",
                        "canonicalId": "GOAL-099",
                        "disposition": "tombstone",
                        "status": "tombstone",
                        "titleDigest": module._title_digest("GOAL-099", "Obsolete Goal"),
                    }
                ],
            }),
            encoding="utf-8",
        )
        try:
            module.census_markdown_sources([doc], res_file)
        except module.AuditError as exc:
            assert exc.error_id in (module.ERR_TOMBSTONE_REFERENCE, module.ERR_DANGLING_REFERENCE)
        else:
            raise AssertionError("referencing a tombstoned ID must fail")


def test_loophole_7_stale_fingerprint_in_census_markdown_sources() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        doc = root / "doc.md"
        doc.write_text("### `GOAL-019` — Agent legibility\n", encoding="utf-8")
        res_file = root / "resolution.json"
        res_file.write_text(
            json.dumps({
                "schema": "fss.stable_id_resolution.v1",
                "resolutions": [
                    {
                        "legacyId": "GOAL-019",
                        "title": "Agent legibility",
                        "canonicalId": "GOAL-019",
                        "disposition": "retained",
                        "titleDigest": "sha256:" + "0" * 64,  # Fabricated fingerprint!
                    }
                ],
            }),
            encoding="utf-8",
        )
        try:
            module.census_markdown_sources([doc], res_file)
        except module.AuditError as exc:
            assert exc.error_id == module.ERR_FINGERPRINT_MISMATCH
            assert "fingerprint mismatch" in str(exc)
        else:
            raise AssertionError("stale/fabricated fingerprint in resolution must be rejected in multi-file census")


def test_loophole_8_corrupt_architecture_json_fails_closed() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        arch_dir = root / "architecture"
        arch_dir.mkdir()
        bad_json = arch_dir / "corrupt.json"
        bad_json.write_text('{"unclosed_json: ', encoding="utf-8")
        try:
            module._load_repository_definitions(root)
        except module.AuditError as exc:
            assert exc.error_id == module.ERR_SCHEMA_ERROR
        else:
            raise AssertionError("corrupt architecture JSON must fail closed with ERR_SCHEMA_ERROR")


def test_extractor_inconsistency_between_plan_defs_and_all_occurrences() -> None:
    """Proves that _extract_plan_definitions and _extract_all_occurrences contradict each other.

    _extract_plan_definitions skips code blocks (returns 0 defs), but _extract_all_occurrences
    extracts definitions inside code blocks (returns 1 def).
    """
    text = """```markdown
### `INV-001` — Example definition in code fence
```
"""
    plan_defs = module._extract_plan_definitions(text)
    all_defs, _, _ = module._extract_all_occurrences(text, "test.md")
    assert len(plan_defs) == len(all_defs), (
        f"Inconsistent extractors: _extract_plan_definitions returned {len(plan_defs)} definitions, "
        f"while _extract_all_occurrences returned {len(all_defs)} definitions from the same fenced block!"
    )


def test_near_miss_delimiter_bypass_special_cased_to_goal() -> None:
    """Proves line 345 'if cand.startswith("G") or "-" in cand or "_" in cand:' special-cases GOAL.

    INV001, ADR001, CAP001 lack '-' and '_' and do not start with 'G', so they are silently dropped
    without syntax validation instead of raising ERR_MALFORMED_WIDTH or ERR_UNKNOWN_FAMILY.
    """
    plan_text = "### `INV001` — Missing hyphen in INV\n"
    try:
        module._extract_plan_definitions(plan_text)
    except module.AuditError as exc:
        assert exc.error_id in (module.ERR_MALFORMED_WIDTH, module.ERR_UNKNOWN_FAMILY)
    else:
        raise AssertionError("INV001 without hyphen must raise ERR_MALFORMED_WIDTH or ERR_UNKNOWN_FAMILY")


def test_underscore_near_miss_completely_invisible_in_census_markdown() -> None:
    """Proves that underscore near-misses in markdown documents are invisible to census_markdown_sources."""
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp)
        doc = p / "doc.md"
        doc.write_text("### `GOAL_001` — Underscore typo\n", encoding="utf-8")
        res = p / "res.json"
        res.write_text(json.dumps({"schema": "fss.stable_id_resolution.v1", "resolutions": []}), encoding="utf-8")

        try:
            module.census_markdown_sources([doc], res)
        except module.AuditError as exc:
            assert exc.error_id in (module.ERR_MALFORMED_WIDTH, module.ERR_UNKNOWN_FAMILY)
        else:
            raise AssertionError("GOAL_001 with underscore must raise ERR_MALFORMED_WIDTH or ERR_UNKNOWN_FAMILY")


def test_tombstone_disposition_leak_in_architecture_json() -> None:
    """Proves _load_repository_definitions only checks 'status', ignoring 'disposition: tombstone'."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        arch = root / "architecture"
        arch.mkdir()
        (arch / "goals.json").write_text(
            json.dumps({"id": "GOAL-099", "disposition": "tombstone"}),
            encoding="utf-8",
        )
        known = module._load_repository_definitions(root)
        assert "GOAL-099" not in known, (
            "Tombstoned ID with 'disposition: tombstone' was leaked into known_targets!"
        )


def test_markdown_title_drift_silently_passed_in_census_sources() -> None:
    """Proves census_markdown_sources does not detect title drift between markdown and resolution table."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        doc = root / "doc.md"
        doc.write_text("### `GOAL-001` — New Title in Markdown\n", encoding="utf-8")
        res = root / "res.json"
        res.write_text(
            json.dumps({
                "schema": "fss.stable_id_resolution.v1",
                "resolutions": [
                    {
                        "legacyId": "GOAL-001",
                        "title": "Old Stale Title in Resolution",
                        "canonicalId": "GOAL-001",
                        "titleDigest": module._title_digest("GOAL-001", "Old Stale Title in Resolution"),
                    }
                ],
            }),
            encoding="utf-8",
        )
        try:
            module.census_markdown_sources([doc], res)
        except module.AuditError as exc:
            assert exc.error_id == module.ERR_FINGERPRINT_MISMATCH
        else:
            raise AssertionError("markdown title drift must raise ERR_FINGERPRINT_MISMATCH")


def test_census_markdown_sources_silently_skips_missing_files() -> None:
    """Proves census_markdown_sources silently skips missing file paths instead of failing closed."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        missing_doc = root / "nonexistent_doc.md"
        res = root / "res.json"
        res.write_text(json.dumps({"schema": "fss.stable_id_resolution.v1", "resolutions": []}), encoding="utf-8")
        try:
            module.census_markdown_sources([missing_doc], res)
        except (module.AuditError, FileNotFoundError):
            pass
        else:
            raise AssertionError("missing file in census_markdown_sources must fail closed")


# ---------------------------------------------------------------------------
# review-440 (fss-x4a.6.21): fenced examples must still resolve; fenced
# heading-shaped definitions must not launder conflicting semantics.
# ---------------------------------------------------------------------------


def expect_audit_error(error_ids: tuple[str, ...], fn, *args, **kwargs) -> Exception:
    try:
        fn(*args, **kwargs)
    except module.AuditError as exc:
        assert exc.error_id in error_ids, f"expected one of {error_ids}, got {exc.error_id}: {exc}"
        return exc
    raise AssertionError(f"expected AuditError in {error_ids}, but call succeeded")


def empty_resolution(root: Path) -> Path:
    res = root / "resolution.json"
    res.write_text(json.dumps({"schema": "fss.stable_id_resolution.v1", "resolutions": []}), encoding="utf-8")
    return res


def test_review440_tombstoned_id_in_code_fence_must_be_rejected() -> None:
    """review-440 failing test 1: a fenced example naming a tombstoned ID is an error."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        doc = root / "doc.md"
        doc.write_text(
            "```markdown\nHere is an example referencing a tombstoned ID: `INV-999`\n```\n",
            encoding="utf-8",
        )
        res = root / "resolution.json"
        res.write_text(
            json.dumps({
                "schema": "fss.stable_id_resolution.v1",
                "resolutions": [
                    {
                        "legacyId": "INV-999",
                        "title": "Tombstoned Invariant",
                        "canonicalId": "INV-999",
                        "titleDigest": module._title_digest("INV-999", "Tombstoned Invariant"),
                        "status": "tombstone",
                    }
                ],
            }),
            encoding="utf-8",
        )
        expect_audit_error((module.ERR_TOMBSTONE_REFERENCE,), module.census_markdown_sources, [doc], res)


def test_review440_dangling_id_in_code_fence_must_be_rejected() -> None:
    """review-440 failing test 2: a fenced example naming an unregistered ID is an error."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        doc = root / "doc.md"
        doc.write_text("```markdown\nExample with fictitious ID: `INV-8888`\n```\n", encoding="utf-8")
        res = empty_resolution(root)
        expect_audit_error((module.ERR_DANGLING_REFERENCE,), module.census_markdown_sources, [doc], res)


def test_review440_conflicting_definition_inside_code_fence_must_not_be_laundered() -> None:
    """review-440 failing test 3: a fenced heading that conflicts with a live definition collides."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        doc1 = root / "doc1.md"
        doc2 = root / "doc2.md"
        doc1.write_text("### `INV-001` — Deterministic Execution Requirement\n", encoding="utf-8")
        doc2.write_text("```markdown\n### `INV-001` — Conflicting Fallback Policy\n```\n", encoding="utf-8")
        res = empty_resolution(root)
        expect_audit_error((module.ERR_COLLISION,), module.census_markdown_sources, [doc1, doc2], res)


def test_fenced_example_of_old_fixture_is_now_dangling() -> None:
    """The fixture formerly accepted by test_code_fences_and_prose_exclusions must now fail closed."""
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        plan, resolution = write_fixture(
            root,
            """### `GOAL-001` — First
### Scenario NS-1 — One

```text
FOO-001
GOAL-999
INV-999
```
""",
            [],
            ["GOAL-001"],
            ["NS-1"],
        )
        exc = expect_audit_error((module.ERR_DANGLING_REFERENCE,), module.audit, plan, resolution)
        assert "GOAL-999" in str(exc)
        assert "example" in str(exc)


def test_plan_audit_rejects_tombstoned_fenced_example() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        plan, resolution = write_fixture(
            root,
            """### `GOAL-001` — First
### Scenario NS-1 — One

```text
see GOAL-002
```
""",
            [],
            ["GOAL-001"],
            ["NS-1"],
        )
        scan = module._scan_markdown(plan.read_text(encoding="utf-8"), "plan.md")
        assert [e.raw_id for e in scan.examples] == ["GOAL-002"]
        expect_audit_error(
            (module.ERR_TOMBSTONE_REFERENCE,),
            module._validate_fenced_occurrences,
            scan,
            valid_targets={"GOAL-001", "GOAL-002", "NS-1"},
            tombstoned_ids={"GOAL-002"},
            live_titles={},
        )


def test_plan_audit_rejects_conflicting_fenced_heading() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        plan, resolution = write_fixture(
            root,
            """### `GOAL-001` — First
### Scenario NS-1 — One

```markdown
### `GOAL-001` — Something Else Entirely
```
""",
            [],
            ["GOAL-001"],
            ["NS-1"],
        )
        exc = expect_audit_error((module.ERR_COLLISION,), module.audit, plan, resolution)
        assert "GOAL-001" in str(exc)


def test_plan_audit_accepts_matching_fenced_heading_and_counts_examples() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        plan, resolution = write_fixture(
            root,
            """### `GOAL-001` — First
### Scenario NS-1 — One

```markdown
### `GOAL-001` — First
Scenario NS-1 is referenced here.
```
""",
            [],
            ["GOAL-001"],
            ["NS-1"],
        )
        report = module.audit(plan, resolution)
        assert report["status"] == "passed"
        assert report["sourceDefinitionCount"] == 2
        assert report["exampleCount"] == 2
        assert report["fencedDefinitionCount"] == 1


def test_fenced_heading_without_live_title_fails_closed() -> None:
    """A fenced heading whose ID resolves only via a title-less registry cannot be verified."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        doc = root / "doc.md"
        doc.write_text("```markdown\n### `INV-001` — Unverifiable Title\n```\n", encoding="utf-8")
        scan = module._scan_markdown(doc.read_text(encoding="utf-8"), str(doc))
        assert [d.legacy_id for d in scan.fenced_definitions] == ["INV-001"]
        expect_audit_error(
            (module.ERR_COLLISION,),
            module._validate_fenced_occurrences,
            scan,
            valid_targets={"INV-001"},
            tombstoned_ids=set(),
            live_titles={},
        )


def test_fenced_non_family_tokens_are_not_examples() -> None:
    scan = module._scan_markdown("```sh\nexport FOO-001=1\ncurl http-2\n```\n", "doc.md")
    assert scan.examples == []
    assert scan.fenced_definitions == []


# ---------------------------------------------------------------------------
# review-440 findings 5/6/7: residual holes found while re-verifying.
# ---------------------------------------------------------------------------


def test_finding5_architecture_json_delimiterless_near_miss_rejected() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        arch = root / "architecture"
        arch.mkdir()
        (arch / "reg.json").write_text(json.dumps({"id": "INV001"}), encoding="utf-8")
        expect_audit_error((module.ERR_MALFORMED_WIDTH,), module._load_repository_definitions, root)


def test_finding5_registry_table_delimiterless_near_miss_rejected() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        reg = root / "registries"
        reg.mkdir()
        (reg / "REG.md").write_text("| ID | Title |\n|---|---|\n| `INV001` | Missing hyphen |\n", encoding="utf-8")
        expect_audit_error((module.ERR_MALFORMED_WIDTH,), module._load_repository_definitions, root)


def test_finding5_unbackticked_near_miss_heading_rejected_in_census() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        doc = root / "doc.md"
        doc.write_text("### INV001 — Missing hyphen, no backticks\n", encoding="utf-8")
        res = empty_resolution(root)
        expect_audit_error((module.ERR_MALFORMED_WIDTH,), module.census_markdown_sources, [doc], res)


def test_finding5_lowercase_underscore_near_miss_rejected() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        doc = root / "doc.md"
        doc.write_text("Prose that cites goal_001 by mistake.\n", encoding="utf-8")
        res = empty_resolution(root)
        expect_audit_error(
            (module.ERR_MALFORMED_CASE, module.ERR_MALFORMED_WIDTH), module.census_markdown_sources, [doc], res
        )


def test_finding5_noncanonical_goal_heading_not_silently_dropped_from_plan() -> None:
    for text in (
        "### GOAL-001 — Missing backticks\n",
        "## `GOAL-001` — Wrong heading level\n",
        "### Scenario `NS-1` — Backticked scenario\n",
    ):
        expect_audit_error((module.ERR_CENSUS_DRIFT,), module._extract_plan_definitions, text)


def test_finding6_tombstone_status_is_case_insensitive() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        arch = root / "architecture"
        arch.mkdir()
        (arch / "goals.json").write_text(
            json.dumps({"rows": [{"id": "GOAL-098", "status": "Tombstoned"}, {"id": "GOAL-097", "disposition": " SUPERSEDED "}]}),
            encoding="utf-8",
        )
        known = module._load_repository_definitions(root)
        assert "GOAL-098" not in known
        assert "GOAL-097" not in known
        index = module._load_repository_index(root)
        assert {"GOAL-098", "GOAL-097"} <= index.tombstoned


def test_finding6_architecture_tombstones_surface_as_tombstone_references() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        arch = root / "architecture"
        arch.mkdir()
        (arch / "goals.json").write_text(
            json.dumps({"rows": [{"id": "GOAL-099", "disposition": "tombstone"}, {"id": "GOAL-099", "status": "active"}]}),
            encoding="utf-8",
        )
        index = module._load_repository_index(root)
        # A tombstone anywhere wins over a live row elsewhere: superseded entries remain tombstoned.
        assert "GOAL-099" in index.tombstoned
        scan = module._scan_markdown("Refers to GOAL-099.\n", "doc.md")
        expect_audit_error(
            (module.ERR_TOMBSTONE_REFERENCE,),
            module._validate_references,
            scan.references,
            valid_targets=index.known,
            tombstoned_ids=index.tombstoned,
        )


def test_finding6_non_string_status_fails_closed() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        arch = root / "architecture"
        arch.mkdir()
        (arch / "goals.json").write_text(json.dumps({"id": "GOAL-096", "status": {"state": "tombstone"}}), encoding="utf-8")
        expect_audit_error((module.ERR_SCHEMA_ERROR,), module._load_repository_definitions, root)


def test_finding7_plan_title_drift_reports_fingerprint_mismatch() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        plan, resolution = write_fixture(
            root,
            """### `GOAL-001` — Drifted Title
### Scenario NS-1 — One
""",
            [row("GOAL-001", "First", "GOAL-001")],
            ["GOAL-001"],
            ["NS-1"],
        )
        exc = expect_audit_error((module.ERR_FINGERPRINT_MISMATCH,), module.audit, plan, resolution)
        assert "Drifted Title" in str(exc)


def test_finding7_census_resolution_rows_are_strictly_typed() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        doc = root / "doc.md"
        doc.write_text("### `GOAL-001` — First\n", encoding="utf-8")
        res = root / "res.json"
        bad_rows = [
            {"legacyId": "GOAL-001", "title": 123, "canonicalId": "GOAL-001", "titleDigest": "sha256:" + "0" * 64},
            {"legacyId": "GOAL-001", "title": "First", "titleDigest": module._title_digest("GOAL-001", "First")},
        ]
        for bad in bad_rows:
            res.write_text(json.dumps({"schema": "fss.stable_id_resolution.v1", "resolutions": [bad]}), encoding="utf-8")
            expect_audit_error((module.ERR_SCHEMA_ERROR,), module.census_markdown_sources, [doc], res)
        res.write_text(json.dumps({"schema": "fss.bogus.v9", "resolutions": []}), encoding="utf-8")
        expect_audit_error((module.ERR_SCHEMA_ERROR,), module.census_markdown_sources, [doc], res)


def test_finding7_census_title_drift_against_canonical_alias() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        doc = root / "doc.md"
        doc.write_text("### `GOAL-024` — Not The Remapped Title\n", encoding="utf-8")
        res = root / "res.json"
        res.write_text(
            json.dumps({
                "schema": "fss.stable_id_resolution.v1",
                "resolutions": [row("GOAL-019", "Agent epistemic ergonomics", "GOAL-024")],
            }),
            encoding="utf-8",
        )
        expect_audit_error((module.ERR_FINGERPRINT_MISMATCH,), module.census_markdown_sources, [doc], res)


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
    test_loophole_1_fenced_code_block_collision_and_extractor_consistency()
    test_loophole_2_html_comments_multiline_and_single_line()
    test_loophole_3_width_aliasing_collision_and_resolution()
    test_loophole_4_prose_exclusion_not_masking_real_definitions_or_invalid_tokens()
    test_loophole_5_near_miss_and_registry_ingestion_validation()
    test_loophole_6_tombstoned_id_reference_rejected()
    test_loophole_7_stale_fingerprint_in_census_markdown_sources()
    test_loophole_8_corrupt_architecture_json_fails_closed()
    test_extractor_inconsistency_between_plan_defs_and_all_occurrences()
    test_near_miss_delimiter_bypass_special_cased_to_goal()
    test_underscore_near_miss_completely_invisible_in_census_markdown()
    test_tombstone_disposition_leak_in_architecture_json()
    test_markdown_title_drift_silently_passed_in_census_sources()
    test_census_markdown_sources_silently_skips_missing_files()
    test_review440_tombstoned_id_in_code_fence_must_be_rejected()
    test_review440_dangling_id_in_code_fence_must_be_rejected()
    test_review440_conflicting_definition_inside_code_fence_must_not_be_laundered()
    test_fenced_example_of_old_fixture_is_now_dangling()
    test_plan_audit_rejects_tombstoned_fenced_example()
    test_plan_audit_rejects_conflicting_fenced_heading()
    test_plan_audit_accepts_matching_fenced_heading_and_counts_examples()
    test_fenced_heading_without_live_title_fails_closed()
    test_fenced_non_family_tokens_are_not_examples()
    test_finding5_architecture_json_delimiterless_near_miss_rejected()
    test_finding5_registry_table_delimiterless_near_miss_rejected()
    test_finding5_unbackticked_near_miss_heading_rejected_in_census()
    test_finding5_lowercase_underscore_near_miss_rejected()
    test_finding5_noncanonical_goal_heading_not_silently_dropped_from_plan()
    test_finding6_tombstone_status_is_case_insensitive()
    test_finding6_architecture_tombstones_surface_as_tombstone_references()
    test_finding6_non_string_status_fails_closed()
    test_finding7_plan_title_drift_reports_fingerprint_mismatch()
    test_finding7_census_resolution_rows_are_strictly_typed()
    test_finding7_census_title_drift_against_canonical_alias()
    print("all stable-ID audit tests passed")


if __name__ == "__main__":
    main()


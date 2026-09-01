#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PLAN = ROOT / "COMPREHENSIVE_PLAN_FOR_FRANKEN_SURVEILLANCE_SYSTEM.md"
DEFAULT_RESOLUTION = ROOT / "architecture/stable_id_resolution.json"

GOAL_HEADING = re.compile(r"^### `(?P<id>GOAL-\d{3})` — (?P<title>.+?)\s*$")
NS_HEADING = re.compile(r"^### Scenario (?P<id>NS-\d+) — (?P<title>.+?)\s*$")


class AuditError(ValueError):
    pass


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AuditError(f"top-level JSON value must be an object: {path}")
    return value


def _title_digest(legacy_id: str, title: str) -> str:
    payload = legacy_id.encode("utf-8") + b"\0" + title.encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _extract(plan_text: str) -> list[tuple[str, str, int]]:
    rows: list[tuple[str, str, int]] = []
    for line_number, line in enumerate(plan_text.splitlines(), 1):
        match = GOAL_HEADING.match(line) or NS_HEADING.match(line)
        if match is not None:
            rows.append((match.group("id"), match.group("title").strip(), line_number))
    return rows


def audit(plan_path: Path, resolution_path: Path) -> dict[str, Any]:
    plan_text = plan_path.read_text(encoding="utf-8")
    resolution = _load_json(resolution_path)
    if resolution.get("schema") != "fss.stable_id_resolution.v1":
        raise AuditError("unsupported stable-ID resolution schema")

    raw_resolutions = resolution.get("resolutions")
    if not isinstance(raw_resolutions, list):
        raise AuditError("resolutions must be an array")

    by_occurrence: dict[tuple[str, str], dict[str, Any]] = {}
    canonical_from_resolution: set[str] = set()
    for index, row in enumerate(raw_resolutions):
        if not isinstance(row, dict):
            raise AuditError(f"resolution row {index} is not an object")
        legacy_id = row.get("legacyId")
        title = row.get("title")
        canonical_id = row.get("canonicalId")
        digest = row.get("titleDigest")
        if not all(isinstance(value, str) and value for value in (legacy_id, title, canonical_id, digest)):
            raise AuditError(f"resolution row {index} has missing string fields")
        key = (legacy_id, title)
        if key in by_occurrence:
            raise AuditError(f"duplicate resolution occurrence: {legacy_id} / {title}")
        if digest != _title_digest(legacy_id, title):
            raise AuditError(f"title fingerprint mismatch for {legacy_id} / {title}")
        if canonical_id in canonical_from_resolution:
            raise AuditError(f"canonical ID reused in resolution table: {canonical_id}")
        canonical_from_resolution.add(canonical_id)
        by_occurrence[key] = row

    extracted = _extract(plan_text)
    legacy_counts: dict[str, int] = {}
    for legacy_id, _, _ in extracted:
        legacy_counts[legacy_id] = legacy_counts.get(legacy_id, 0) + 1

    definitions: list[dict[str, Any]] = []
    for legacy_id, title, line_number in extracted:
        count = legacy_counts[legacy_id]
        resolution_row = by_occurrence.get((legacy_id, title))
        if count > 1 and resolution_row is None:
            raise AuditError(
                f"unresolved collided stable definition {legacy_id} at line {line_number}: {title}"
            )
        if resolution_row is not None:
            canonical_id = str(resolution_row["canonicalId"])
            digest = str(resolution_row["titleDigest"])
        else:
            canonical_id = legacy_id
            digest = _title_digest(legacy_id, title)
        definitions.append(
            {
                "legacy_id": legacy_id,
                "title": title,
                "line": line_number,
                "canonical_id": canonical_id,
                "title_digest": digest,
            }
        )

    used_resolution_keys = {
        (definition["legacy_id"], definition["title"])
        for definition in definitions
        if (definition["legacy_id"], definition["title"]) in by_occurrence
    }
    unused = sorted(set(by_occurrence) - used_resolution_keys)
    if unused:
        rendered = ", ".join(f"{legacy}/{title}" for legacy, title in unused)
        raise AuditError(f"resolution table contains stale occurrences: {rendered}")

    canonical_ids = [definition["canonical_id"] for definition in definitions]
    if len(canonical_ids) != len(set(canonical_ids)):
        duplicates = sorted(
            identifier for identifier in set(canonical_ids)
            if canonical_ids.count(identifier) > 1
        )
        raise AuditError("canonical stable IDs collide: " + ", ".join(duplicates))

    expected = resolution.get("expected")
    if not isinstance(expected, dict):
        raise AuditError("expected canonical ID sets are missing")
    expected_goals = expected.get("goalCanonicalIds")
    expected_ns = expected.get("northStarCanonicalIds")
    actual_goals = sorted(
        (definition["canonical_id"] for definition in definitions if definition["canonical_id"].startswith("GOAL-")),
        key=lambda value: int(value.rsplit("-", 1)[1]),
    )
    actual_ns = sorted(
        (definition["canonical_id"] for definition in definitions if definition["canonical_id"].startswith("NS-")),
        key=lambda value: int(value.rsplit("-", 1)[1]),
    )
    if actual_goals != expected_goals:
        raise AuditError(f"canonical GOAL census drift: expected {expected_goals}, observed {actual_goals}")
    if actual_ns != expected_ns:
        raise AuditError(f"canonical North Star census drift: expected {expected_ns}, observed {actual_ns}")

    collisions = {
        legacy_id: count for legacy_id, count in sorted(legacy_counts.items()) if count > 1
    }
    return {
        "schema": "fss.stable_id_audit.v1",
        "source": plan_path.name,
        "resolution": resolution_path.relative_to(ROOT).as_posix()
        if resolution_path.is_relative_to(ROOT) else str(resolution_path),
        "sourceDefinitionCount": len(definitions),
        "canonicalDefinitionCount": len(set(canonical_ids)),
        "goalCanonicalCount": len(actual_goals),
        "northStarCanonicalCount": len(actual_ns),
        "legacyCollisions": collisions,
        "definitions": [
            {
                "legacyId": definition["legacy_id"],
                "canonicalId": definition["canonical_id"],
                "title": definition["title"],
                "line": definition["line"],
                "titleDigest": definition["title_digest"],
            }
            for definition in definitions
        ],
        "status": "passed",
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Resolve and audit FSS's published goal and North Star stable definitions"
    )
    parser.add_argument("--plan", type=Path, default=DEFAULT_PLAN)
    parser.add_argument("--resolution", type=Path, default=DEFAULT_RESOLUTION)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        report = audit(args.plan, args.resolution)
    except (OSError, json.JSONDecodeError, AuditError) as exc:
        print(f"stable-ID audit failed: {exc}", file=sys.stderr)
        return 1
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    print(rendered, end="")
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

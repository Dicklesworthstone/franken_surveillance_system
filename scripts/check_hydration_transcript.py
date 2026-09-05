#!/usr/bin/env python3
"""Validate synthetic reference-hydration transcripts; never a release qualification root."""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import sys
from typing import Any

EXPECTED = {
    "success": ("ok", "H2", "H2", "available", "complete", True),
    "budget-fallback": ("ok", "H3", "H1", "available", "partial", True),
    "privacy-denied": ("denied", "H1", "hydration_privacy_denied"),
    "expired": ("typed_unavailable", "H1", None, "expired", "stale", False),
    "h4-denied": ("denied", "H4", "hydration_laboratory_grant_required"),
    "h4-qualified": ("ok", "H4", "H4", "available", "complete", False),
}
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
BASE_FIELDS = {
    "schema", "scenario", "outcome", "handleId", "descriptorDigest", "requestDigest",
    "requestedLevel", "artifactDigest", "continuationDigest",
}


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_constant(value: str) -> None:
    raise ValueError(f"non-JSON numeric constant: {value}")


def validate(scenario: str, payload: bytes) -> dict[str, Any]:
    if scenario not in EXPECTED:
        raise ValueError("unknown scenario")
    if len(payload) > 16_384:
        raise ValueError("transcript exceeds the reference record limit")
    lines = payload.decode("utf-8").splitlines()
    if len(lines) != 1:
        raise ValueError("expected exactly one complete NDJSON record")
    record = json.loads(lines[0], object_pairs_hook=unique_object, parse_constant=reject_constant)
    if not isinstance(record, dict):
        raise ValueError("record must be an object")
    expected = EXPECTED[scenario]
    fields = BASE_FIELDS | ({"error"} if expected[0] == "denied" else {
        "subjectDigest", "receiptDigest", "availability", "deliveredLevel", "completeness",
        "serviceTimeNs", "reproduction",
    })
    if set(record) != fields:
        raise ValueError("unexpected or missing transcript fields")
    if record["schema"] != "fss.hydration_rehearsal.v1" or record["scenario"] != scenario:
        raise ValueError("wrong schema or scenario")
    if (record["outcome"], record["requestedLevel"]) != expected[:2]:
        raise ValueError("wrong outcome or requested level")
    for field in ("descriptorDigest", "requestDigest"):
        if not isinstance(record[field], str) or not DIGEST.fullmatch(record[field]):
            raise ValueError(f"invalid {field}")
    if not isinstance(record["handleId"], str) or not record["handleId"].startswith("semantic-handle:"):
        raise ValueError("invalid handle identity")
    if not DIGEST.fullmatch(record["handleId"][len("semantic-handle:"):]):
        raise ValueError("invalid handle identity digest")
    if expected[0] == "denied":
        if record["error"] != expected[2]:
            raise ValueError("wrong refusal code")
        if record["artifactDigest"] is not None or record["continuationDigest"] is not None:
            raise ValueError("refusal disclosed an artifact or continuation")
        return record
    if (record["deliveredLevel"], record["availability"], record["completeness"]) != expected[2:5]:
        raise ValueError("wrong level, availability, or completeness")
    for field in ("subjectDigest", "receiptDigest"):
        if not isinstance(record[field], str) or not DIGEST.fullmatch(record[field]):
            raise ValueError(f"invalid {field}")
    for field, present in (("artifactDigest", expected[2] is not None), ("continuationDigest", expected[5])):
        if present:
            if not isinstance(record[field], str) or not DIGEST.fullmatch(record[field]):
                raise ValueError(f"invalid {field}")
        elif record[field] is not None:
            raise ValueError(f"unexpected {field}")
    expected_time = 100 if scenario == "expired" else 20
    if type(record["serviceTimeNs"]) is not int or record["serviceTimeNs"] != expected_time:
        raise ValueError("wrong service time")
    if record["reproduction"] != f"cargo run -q -p fss-cli --bin fss-hydration-rehearsal -- --scenario {scenario}":
        raise ValueError("wrong reproduction command")
    return record


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: scripts/check_hydration_transcript.py TRANSCRIPT_DIRECTORY")
    root = pathlib.Path(sys.argv[1])
    digests = {}
    for scenario in EXPECTED:
        first = (root / f"{scenario}.first.ndjson").read_bytes()
        second = (root / f"{scenario}.second.ndjson").read_bytes()
        validate(scenario, first)
        validate(scenario, second)
        if first != second:
            raise ValueError(f"{scenario}: nondeterministic transcript")
        digests[scenario] = "sha256:" + hashlib.sha256(first).hexdigest()
    print(json.dumps({"status": "pass", "scenarios": list(EXPECTED), "transcriptDigests": digests}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

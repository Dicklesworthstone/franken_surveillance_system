#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

cargo build --quiet -p fss-cli --bin fss-hydration-rehearsal
BINARY="${ROOT}/target/debug/fss-hydration-rehearsal"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/fss-hydration-qualification.XXXXXX")"
trap 'rm -rf "${WORK}"' EXIT

scenarios=(
  success
  budget-fallback
  privacy-denied
  expired
  h4-denied
  h4-qualified
)

for scenario in "${scenarios[@]}"; do
  first="${WORK}/${scenario}.first.ndjson"
  second="${WORK}/${scenario}.second.ndjson"
  "${BINARY}" --scenario "${scenario}" > "${first}"
  "${BINARY}" --scenario "${scenario}" > "${second}"
  cmp "${first}" "${second}"
done

python3 - "${WORK}" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
expected = {
    "success": {
        "outcome": "success",
        "requested_level": "H2",
        "delivered_level": "H2",
        "availability": "available",
        "completeness": "complete",
        "continuation": True,
    },
    "budget-fallback": {
        "outcome": "success",
        "requested_level": "H3",
        "delivered_level": "H1",
        "availability": "available",
        "completeness": "partial",
        "continuation": True,
    },
    "privacy-denied": {
        "outcome": "denied",
        "requested_level": "H1",
        "error": "hydration_privacy_denied",
    },
    "expired": {
        "outcome": "success",
        "requested_level": "H1",
        "delivered_level": "none",
        "availability": "expired",
        "completeness": "stale",
        "continuation": False,
        "artifact_digest": "none",
    },
    "h4-denied": {
        "outcome": "denied",
        "requested_level": "H4",
        "error": "hydration_laboratory_grant_required",
    },
    "h4-qualified": {
        "outcome": "success",
        "requested_level": "H4",
        "delivered_level": "H4",
        "availability": "available",
        "completeness": "complete",
        "continuation": False,
    },
}

for scenario, fields in expected.items():
    path = root / f"{scenario}.first.ndjson"
    lines = path.read_text(encoding="utf-8").splitlines()
    if len(lines) != 1:
        raise SystemExit(f"{scenario}: expected one NDJSON record, found {len(lines)}")
    record = json.loads(lines[0])
    if record.get("schema") != "fss.hydration_rehearsal.v1":
        raise SystemExit(f"{scenario}: wrong schema")
    if record.get("scenario") != scenario:
        raise SystemExit(f"{scenario}: wrong scenario")
    for key, expected_value in fields.items():
        if record.get(key) != expected_value:
            raise SystemExit(
                f"{scenario}: {key}={record.get(key)!r}, expected {expected_value!r}"
            )
    for key in ("handle_id", "descriptor_digest", "request_digest"):
        if not record.get(key):
            raise SystemExit(f"{scenario}: missing {key}")
    if record["outcome"] == "success" and not record.get("receipt_digest"):
        raise SystemExit(f"{scenario}: missing receipt_digest")

print(json.dumps({"status": "pass", "scenarios": sorted(expected)}, separators=(",", ":")))
PY

from __future__ import annotations

import hashlib
import importlib.util
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("hydration_transcript", ROOT / "scripts/check_hydration_transcript.py")
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


def digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


def record(scenario: str) -> dict:
    expected = CHECKER.EXPECTED[scenario]
    value = {
        "schema": "fss.hydration_rehearsal.v1", "scenario": scenario, "outcome": expected[0],
        "handleId": "semantic-handle:" + digest("handle"), "descriptorDigest": digest("descriptor"),
        "requestDigest": digest("request"), "requestedLevel": expected[1],
        "artifactDigest": None, "continuationDigest": None,
    }
    if expected[0] == "denied":
        value["error"] = expected[2]
    else:
        value.update({
            "subjectDigest": digest("subject"), "receiptDigest": digest("receipt"),
            "availability": expected[3], "deliveredLevel": expected[2], "completeness": expected[4],
            "serviceTimeNs": 100 if scenario == "expired" else 20,
            "reproduction": f"cargo run -q -p fss-cli --bin fss-hydration-rehearsal -- --scenario {scenario}",
            "artifactDigest": digest("artifact") if expected[2] is not None else None,
            "continuationDigest": digest("cursor") if expected[5] else None,
        })
    return value


def encode(value: dict) -> bytes:
    return (json.dumps(value, separators=(",", ":")) + "\n").encode()


class HydrationTranscriptTests(unittest.TestCase):
    def test_every_registered_scenario(self):
        for scenario in CHECKER.EXPECTED:
            with self.subTest(scenario=scenario):
                value = record(scenario)
                self.assertEqual(CHECKER.validate(scenario, encode(value)), value)

    def test_missing_and_unexpected_fields(self):
        valid = record("success")
        for key in list(valid):
            changed = valid.copy()
            del changed[key]
            with self.subTest(field=key), self.assertRaises(ValueError):
                CHECKER.validate("success", encode(changed))
        changed = {**valid, "rawPrivatePayload": "must never appear"}
        with self.assertRaises(ValueError):
            CHECKER.validate("success", encode(changed))

    def test_rejects_wrong_types_states_and_proof_shapes(self):
        for field, bad in [
            ("receiptDigest", ""), ("descriptorDigest", "not-a-digest"),
            ("artifactDigest", None), ("continuationDigest", "none"),
            ("serviceTimeNs", True), ("serviceTimeNs", 100),
            ("completeness", "partial"), ("requestedLevel", "H1"),
            ("handleId", "mutable:latest"), ("reproduction", "unrelated command"),
        ]:
            changed = record("success")
            changed[field] = bad
            with self.subTest(field=field, bad=bad), self.assertRaises(ValueError):
                CHECKER.validate("success", encode(changed))

    def test_refusal_cannot_expose_payload_or_change_error(self):
        for field, bad in [("artifactDigest", digest("leak")), ("continuationDigest", digest("leak")), ("error", "success")]:
            changed = record("privacy-denied")
            changed[field] = bad
            with self.subTest(field=field), self.assertRaises(ValueError):
                CHECKER.validate("privacy-denied", encode(changed))

    def test_duplicate_keys_invalid_json_multiple_records_and_bounds(self):
        valid = encode(record("success"))
        duplicate = valid.replace(b'{"schema":', b'{"schema":"duplicate","schema":', 1)
        invalid_constant = valid.replace(b'"serviceTimeNs":20', b'"serviceTimeNs":NaN')
        for payload in (duplicate, invalid_constant, valid + valid, valid[:20], b"[]\n", b" " * 16_385, b"\xff\n"):
            with self.subTest(payload=payload[:30]), self.assertRaises(ValueError):
                CHECKER.validate("success", payload)


if __name__ == "__main__":
    unittest.main()

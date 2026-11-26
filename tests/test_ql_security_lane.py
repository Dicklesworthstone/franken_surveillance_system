#!/usr/bin/env python3
"""Contract & fault tests for reusable lane QL-SECURITY-001 (scripts/lanes/security.sh, fss-x4a.29.18)."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "lanes" / "security.sh"


class TestQlSecurityLane(unittest.TestCase):
    def test_list_covers_all_six_security_pillars(self) -> None:
        out = subprocess.check_output(["bash", str(SCRIPT), "--list"], text=True)
        lines = [line.split("\t") for line in out.strip().splitlines() if line.strip()]
        self.assertGreaterEqual(len(lines), 12)
        pillars = {parts[1] for parts in lines}
        self.assertEqual(
            pillars,
            {
                "capability_non_escalation",
                "secret_redaction",
                "parser_resource_bounds",
                "sandboxing_runtime_isolation",
                "mask_before_publication",
                "retention_and_deletion",
            },
        )
        for parts in lines:
            self.assertEqual(parts[0], "QL-SECURITY-001")

    def test_missing_prerequisite_fails_closed_non_pass(self) -> None:
        proc = subprocess.run(
            ["bash", str(SCRIPT), "--dry-run-missing-prereq"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 5)
        self.assertIn("unavailable_prerequisite", proc.stderr)

    def test_static_lane_run_and_standalone_verifier_and_tamper_refusals(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            run_dir = Path(td) / "sec-run"
            proc = subprocess.run(
                ["bash", str(SCRIPT), "--only-static", "--receipt-dir", str(run_dir)],
                capture_output=True,
                text=True,
                cwd=str(REPO),
            )
            self.assertEqual(proc.returncode, 0, f"stderr={proc.stderr}")
            receipt_path = run_dir / "security-receipt.json"
            self.assertTrue(receipt_path.is_file())
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(receipt["laneId"], "QL-SECURITY-001")
            self.assertEqual(receipt["status"], "passed")
            self.assertEqual(len(receipt["commands"]), 6)

            # Full standalone verifier MUST refuse a static-only receipt (cannot fake 6-pillar pass)!
            refuse_partial = subprocess.run(
                ["bash", str(SCRIPT), "--verify-receipt", str(receipt_path)],
                capture_output=True,
                text=True,
                cwd=str(REPO),
            )
            self.assertNotEqual(refuse_partial.returncode, 0)
            self.assertIn("incomplete QL-SECURITY-001 receipt", refuse_partial.stderr)

            # Standalone verifier with --allow-static-only passes cleanly on unmodified static bundle!
            ver = subprocess.run(
                ["bash", str(SCRIPT), "--verify-receipt", str(receipt_path), "--allow-static-only"],
                capture_output=True,
                text=True,
                cwd=str(REPO),
            )
            self.assertEqual(ver.returncode, 0, f"stderr={ver.stderr}")
            self.assertIn("[PASS] QL-SECURITY-001 standalone verifier", ver.stdout)

            # Fault 1: Tampering a step log invalidates digest -> verifier MUST fail closed!
            log_file = run_dir / "sec-01-semantic-planes.log"
            orig_bytes = log_file.read_bytes()
            log_file.write_bytes(orig_bytes + b"\ntampered")
            bad_digest = subprocess.run(
                ["bash", str(SCRIPT), "--verify-receipt", str(receipt_path), "--allow-static-only"],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(bad_digest.returncode, 0)
            log_file.write_bytes(orig_bytes)

            # Fault 2: Secret canary leak in a log (even if digest matches!) MUST fail closed!
            steps_path = run_dir / "security-steps.jsonl"
            orig_steps = steps_path.read_text(encoding="utf-8")
            leaked_bytes = orig_bytes + b"\nAuthorization: Bearer supersecret\n"
            log_file.write_bytes(leaked_bytes)
            import hashlib
            leaked_digest = "sha256:" + hashlib.sha256(leaked_bytes).hexdigest()
            rows = [json.loads(line) for line in orig_steps.splitlines() if line.strip()]
            rows[0]["outputDigest"] = leaked_digest
            steps_path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
            orig_receipt_text = receipt_path.read_text(encoding="utf-8")
            rec_copy = json.loads(orig_receipt_text)
            rec_copy["commands"][0]["outputDigest"] = leaked_digest
            receipt_path.write_text(json.dumps(rec_copy), encoding="utf-8")
            secret_fail = subprocess.run(
                ["bash", str(SCRIPT), "--verify-receipt", str(receipt_path), "--allow-static-only"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(secret_fail.returncode, 3)

            # Fault 3: Skipped status in receipt MUST NEVER pass standalone verification!
            log_file.write_bytes(orig_bytes)
            steps_path.write_text(orig_steps, encoding="utf-8")
            rec_skip = json.loads(orig_receipt_text)
            rec_skip["commands"][0]["status"] = "skipped"
            receipt_path.write_text(json.dumps(rec_skip), encoding="utf-8")
            skip_fail = subprocess.run(
                ["bash", str(SCRIPT), "--verify-receipt", str(receipt_path), "--allow-static-only"],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(skip_fail.returncode, 0)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Contract & fault tests for reusable lane QL-CUSTODY-001 (scripts/lanes/custody.sh, fss-x4a.29.21)."""

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "lanes" / "custody.sh"


class TestQlCustodyLane(unittest.TestCase):
    def test_list_covers_all_five_custody_pillars(self) -> None:
        out = subprocess.check_output(["bash", str(SCRIPT), "--list"], text=True)
        lines = [line.split("\t") for line in out.strip().splitlines() if line.strip()]
        self.assertEqual(len(lines), 8)
        pillars = {parts[1] for parts in lines}
        self.assertEqual(
            pillars,
            {
                "source_and_manifest_roots",
                "exact_assets_and_checksums",
                "sbom_and_license_agreement",
                "separated_signing_authority",
                "root_last_upload_download_verify",
            },
        )
        for parts in lines:
            self.assertEqual(parts[0], "QL-CUSTODY-001")

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
            run_dir = Path(td) / "custody-run"
            proc = subprocess.run(
                ["bash", str(SCRIPT), "--only-static", "--receipt-dir", str(run_dir)],
                capture_output=True,
                text=True,
                cwd=str(REPO),
            )
            self.assertEqual(proc.returncode, 0, f"stderr={proc.stderr}")
            receipt_path = run_dir / "custody-receipt.json"
            self.assertTrue(receipt_path.is_file())
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(receipt["laneId"], "QL-CUSTODY-001")
            self.assertEqual(receipt["status"], "passed")
            self.assertEqual(len(receipt["commands"]), 6)

            # Full verifier MUST refuse static-only receipt (cannot fake 5-pillar pass).
            refuse_partial = subprocess.run(
                ["bash", str(SCRIPT), "--verify-receipt", str(receipt_path)],
                capture_output=True,
                text=True,
                cwd=str(REPO),
            )
            self.assertNotEqual(refuse_partial.returncode, 0)
            self.assertIn("incomplete QL-CUSTODY-001 receipt", refuse_partial.stderr)

            # Static-only verifier passes on clean bundle.
            ver = subprocess.run(
                ["bash", str(SCRIPT), "--verify-receipt", str(receipt_path), "--allow-static-only"],
                capture_output=True,
                text=True,
                cwd=str(REPO),
            )
            self.assertEqual(ver.returncode, 0, f"stderr={ver.stderr}")
            self.assertIn("[PASS] QL-CUSTODY-001 standalone verifier", ver.stdout)

            # Fault 1: Tampering a step log invalidates digest.
            log_file = run_dir / "cus-01-policy-constitution.log"
            orig_bytes = log_file.read_bytes()
            log_file.write_bytes(orig_bytes + b"\ntampered")
            bad_digest = subprocess.run(
                ["bash", str(SCRIPT), "--verify-receipt", str(receipt_path), "--allow-static-only"],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(bad_digest.returncode, 0)
            log_file.write_bytes(orig_bytes)

            # Fault 2: Secret canary leak in a log (even with updated digest) MUST exit 3.
            steps_path = run_dir / "custody-steps.jsonl"
            orig_steps = steps_path.read_text(encoding="utf-8")
            leaked_bytes = orig_bytes + b"\nBEGIN PRIVATE KEY\n"
            log_file.write_bytes(leaked_bytes)
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

            # Fault 3: Skipped status in receipt MUST fail closed.
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

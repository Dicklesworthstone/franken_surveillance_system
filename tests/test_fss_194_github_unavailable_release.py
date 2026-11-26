#!/usr/bin/env python3
"""tests/test_fss_194_github_unavailable_release.py — contract, negative-mutation,
and sealed-offline drill tests for FSS-194 (bead fss-x4a.26.14).
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "offline_github_unavailable_drill.py"
sys.path.insert(0, str(REPO / "scripts"))

import offline_github_unavailable_drill as drill  # noqa: E402


class TestFss194GithubUnavailableRelease(unittest.TestCase):
    def test_full_offline_drill_passes_with_zero_gh_invocations(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fss194-test-") as tmp:
            out_path = Path(tmp) / "drill-receipt.json"
            proc = subprocess.run(
                [sys.executable, str(SCRIPT), "--output", str(out_path)],
                cwd=str(REPO),
                capture_output=True,
                text=True,
                timeout=120,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            report = json.loads(proc.stdout)
            self.assertEqual(report["schema"], "fss.github_unavailable_drill.v1")
            self.assertEqual(report["state"], "passed")
            self.assertFalse(report["githubHostedRequired"])
            self.assertEqual(report["ghInvocationCount"], 0)
            self.assertEqual(report["failures"], [])
            self.assertTrue(report["drillDigest"].startswith("sha256:"))
            self.assertTrue(out_path.is_file())
            written = json.loads(out_path.read_text(encoding="utf-8"))
            self.assertEqual(written, report)

            check_ids = {c["id"]: c["status"] for c in report["checks"]}
            for must_pass in (
                "constitutional_local_qualification_toml",
                "workflow_yaml_supplementary_only_audit",
                "local_entrypoints_offline_seal_audit",
                "github_cli_outage_trap_verified",
                "offline_local_qualification_receipt",
                "offline_sbom_license_lock_receipt_crosscheck",
                "offline_root_last_release_publish",
                "offline_root_last_verify_remote",
                "offline_separated_authority_refusal",
                "offline_lost_ack_indeterminate_reconcile",
                "zero_github_cli_invocations",
            ):
                self.assertEqual(
                    check_ids.get(must_pass),
                    "passed",
                    f"expected {must_pass} to pass; got {check_ids}",
                )

    def test_hosted_authority_request_fails_closed_with_remediation(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--simulate-hosted-authority-request"],
            cwd=str(REPO),
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 1)
        report = json.loads(proc.stdout)
        self.assertEqual(report["state"], "github_hosted_not_release_authority")
        self.assertEqual(report["errorCode"], "ERR-RELEASE-HOSTED-AUTHORITY-REFUSED-001")
        self.assertFalse(report["githubHostedRequired"])
        self.assertIn("scripts/qualify.sh", report["remediation"])

    def test_workflow_audit_catches_planted_release_write_and_gh_release_bypass(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fss194-wf-neg-") as tmp:
            fake_repo = Path(tmp)
            wf_dir = fake_repo / ".github" / "workflows"
            wf_dir.mkdir(parents=True)
            (wf_dir / "ci.yml").write_text("name: ci\n", encoding="utf-8")
            (wf_dir / "release.yml").write_text(
                "name: bad release\n"
                "permissions:\n"
                "  contents: write\n"
                "jobs:\n"
                "  pub:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - run: gh release create v1.0.0\n",
                encoding="utf-8",
            )
            errors, count = drill.audit_workflows(fake_repo)
            self.assertEqual(count, 2)
            joined = "\n".join(errors)
            self.assertIn("gh_release_cli", joined)
            self.assertIn("contents: write", joined)
            self.assertIn("scripts/release_qualify.sh", joined)
            self.assertIn("GitHub-hosted runners", joined)

    def test_config_audit_rejects_github_hosted_required_true(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fss194-cfg-neg-") as tmp:
            fake_repo = Path(tmp)
            arch = fake_repo / "architecture"
            arch.mkdir()
            (arch / "local_qualification.toml").write_text(
                'authority = "github_actions"\n'
                'github_hosted_required = true\n',
                encoding="utf-8",
            )
            errors = drill.audit_local_qualification_config(fake_repo)
            joined = "\n".join(errors)
            self.assertIn("authority=", joined)
            self.assertIn("github_hosted_required=True", joined)


if __name__ == "__main__":
    unittest.main()

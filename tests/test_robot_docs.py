from __future__ import annotations

"""Contract and regression tests for self-describing robot docs (fss-x4a.24.34 / FSS-234).

Verifies:
1. Live repository robot docs pass fail-closed consistency and freshness checks.
2. Generator is strictly deterministic and byte-idempotent.
3. Planted staleness (tampered markdown or JSON) fails closed with ERR-ROBOT-DOCS-STALE-001.
4. Missing generated files fail closed with ERR-ROBOT-DOCS-MISSING-001.
5. Registry drift (added, removed, or modified operations/views/resources) is detected immediately.
6. Corrupt JSON files fail closed with ERR-ROBOT-DOCS-CORRUPT-001.
7. Subprocess CLI invocations (--check, --json) conform to expected formats and exit codes.
"""

import copy
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from generate_robot_docs import (
    ERR_ROBOT_DOCS_CORRUPT,
    ERR_ROBOT_DOCS_DRIFT,
    ERR_ROBOT_DOCS_MISSING,
    ERR_ROBOT_DOCS_STALE,
    generate_docs,
)
from robot_docs_checker import (
    ERR_ROBOT_DOCS_UNREGISTERED,
    validate_robot_docs,
)


class RobotDocsContractTests(unittest.TestCase):
    """Exhaustive contract tests for robot documentation generation and verification."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.fake_root = Path(self.temp_dir.name)

        # Mirror necessary directories for standalone sandbox testing
        (self.fake_root / "architecture").mkdir(parents=True, exist_ok=True)
        (self.fake_root / "registries").mkdir(parents=True, exist_ok=True)
        (self.fake_root / "docs").mkdir(parents=True, exist_ok=True)

        for arch_file in [
            "fss1_public_registry.json",
            "agent_operations.json",
            "agent_views.json",
            "capabilities.json",
            "operation_crosswalk.json",
        ]:
            src = ROOT / "architecture" / arch_file
            if src.exists():
                shutil.copyfile(src, self.fake_root / "architecture" / arch_file)

        for reg_file in ["ERRORS.md", "SCHEMAS.md"]:
            src = ROOT / "registries" / reg_file
            if src.exists():
                shutil.copyfile(src, self.fake_root / "registries" / reg_file)

        # Copy generated robot docs
        if (ROOT / "docs/ROBOT_DOCS.md").exists():
            shutil.copyfile(ROOT / "docs/ROBOT_DOCS.md", self.fake_root / "docs/ROBOT_DOCS.md")
        if (ROOT / "docs/ROBOT_DOCS.json").exists():
            shutil.copyfile(ROOT / "docs/ROBOT_DOCS.json", self.fake_root / "docs/ROBOT_DOCS.json")

    def test_live_robot_docs_pass(self) -> None:
        """Live repository robot documentation passes validation with zero errors."""
        res = validate_robot_docs(ROOT)
        self.assertTrue(res.passed, f"Live robot docs validation failed: {res.errors}")
        self.assertEqual(len(res.errors), 0)
        self.assertEqual(res.operations_count, 14)
        self.assertEqual(res.views_count, 8)
        self.assertEqual(res.resources_count, 15)
        self.assertEqual(
            res.stats["freeze_digest"],
            "sha256:9bbec4e6845ea702f676cd22472e5fb0d35ca3b3d97f66cbfccb452182413da8",
        )
        self.assertEqual(res.stats["semantic_protocol"], "fss/1")
        self.assertEqual(res.stats["generation"], "gen:fss1:public-v1")

    def test_generation_is_byte_idempotent(self) -> None:
        """Generating robot docs repeatedly produces byte-identical outputs."""
        md1, json1 = generate_docs(ROOT)
        md2, json2 = generate_docs(ROOT)
        self.assertEqual(md1, md2)
        self.assertEqual(json1, json2)

    def test_missing_markdown_fails_closed(self) -> None:
        """Missing docs/ROBOT_DOCS.md causes validation to fail with ERR-ROBOT-DOCS-MISSING-001."""
        md_file = self.fake_root / "docs/ROBOT_DOCS.md"
        if md_file.exists():
            md_file.unlink()

        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_ROBOT_DOCS_MISSING, error_codes)

    def test_missing_json_fails_closed(self) -> None:
        """Missing docs/ROBOT_DOCS.json causes validation to fail with ERR-ROBOT-DOCS-MISSING-001."""
        json_file = self.fake_root / "docs/ROBOT_DOCS.json"
        if json_file.exists():
            json_file.unlink()

        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_ROBOT_DOCS_MISSING, error_codes)

    def test_planted_stale_markdown_fails_closed(self) -> None:
        """Tampering with a single line in docs/ROBOT_DOCS.md fails with ERR-ROBOT-DOCS-STALE-001."""
        md_file = self.fake_root / "docs/ROBOT_DOCS.md"
        content = md_file.read_text(encoding="utf-8")
        tampered = content + "\n<!-- unauthorized trailing text -->\n"
        md_file.write_text(tampered, encoding="utf-8")

        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_ROBOT_DOCS_STALE, error_codes)

    def test_planted_stale_json_fails_closed(self) -> None:
        """Tampering with a property in docs/ROBOT_DOCS.json fails with ERR-ROBOT-DOCS-STALE-001."""
        json_file = self.fake_root / "docs/ROBOT_DOCS.json"
        data = json.loads(json_file.read_text(encoding="utf-8"))
        data["operations"][0]["purpose"] = "tampered unauthorized purpose"
        json_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_ROBOT_DOCS_STALE, error_codes)

    def test_corrupt_json_fails_closed(self) -> None:
        """Corrupt JSON in docs/ROBOT_DOCS.json fails closed with ERR-ROBOT-DOCS-CORRUPT-001."""
        json_file = self.fake_root / "docs/ROBOT_DOCS.json"
        json_file.write_text("{ unclosed invalid json", encoding="utf-8")

        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_ROBOT_DOCS_CORRUPT, error_codes)

    def test_drift_when_operation_added_in_registry(self) -> None:
        """Adding an operation in architecture/agent_operations.json triggers drift/staleness detection."""
        ops_file = self.fake_root / "architecture/agent_operations.json"
        ops_data = json.loads(ops_file.read_text(encoding="utf-8"))
        new_op = copy.deepcopy(ops_data["operations"][0])
        new_op["id"] = "AOP-999"
        new_op["name"] = "unregistered.synthetic"
        ops_data["operations"].append(new_op)
        ops_file.write_text(json.dumps(ops_data, indent=2), encoding="utf-8")

        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertTrue(
            ERR_ROBOT_DOCS_STALE in error_codes or ERR_ROBOT_DOCS_DRIFT in error_codes,
            f"Expected stale or drift error, got: {error_codes}",
        )

    def test_drift_when_operation_removed_in_registry(self) -> None:
        """Removing an operation in architecture/agent_operations.json triggers drift/staleness detection."""
        ops_file = self.fake_root / "architecture/agent_operations.json"
        ops_data = json.loads(ops_file.read_text(encoding="utf-8"))
        ops_data["operations"] = [op for op in ops_data["operations"] if op["id"] != "AOP-014"]
        ops_file.write_text(json.dumps(ops_data, indent=2), encoding="utf-8")

        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertTrue(
            ERR_ROBOT_DOCS_STALE in error_codes or ERR_ROBOT_DOCS_DRIFT in error_codes,
            f"Expected stale or drift error, got: {error_codes}",
        )

    def test_drift_when_view_token_budget_changed(self) -> None:
        """Modifying view maximumTokens in architecture/agent_views.json triggers drift detection."""
        views_file = self.fake_root / "architecture/agent_views.json"
        views_data = json.loads(views_file.read_text(encoding="utf-8"))
        views_data["views"][0]["maximumTokens"] += 1000
        views_file.write_text(json.dumps(views_data, indent=2), encoding="utf-8")

        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_ROBOT_DOCS_STALE, error_codes)

    def test_drift_when_resource_uri_changed(self) -> None:
        """Modifying a resource uriTemplate in fss1_public_registry.json triggers drift detection."""
        fss1_file = self.fake_root / "architecture/fss1_public_registry.json"
        fss1_data = json.loads(fss1_file.read_text(encoding="utf-8"))
        fss1_data["resources"][0]["uriTemplate"] = "fss://altered/uri/{deployment}"
        fss1_file.write_text(json.dumps(fss1_data, indent=2), encoding="utf-8")

        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_ROBOT_DOCS_STALE, error_codes)

    def test_cli_subprocess_generate_check_mode(self) -> None:
        """`python3 -B scripts/generate_robot_docs.py --check` exits with 0 on live repo."""
        result = subprocess.run(
            [sys.executable, "-B", str(ROOT / "scripts/generate_robot_docs.py"), "--check"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, f"stdout: {result.stdout}\nstderr: {result.stderr}")
        self.assertIn("OK: robot docs are fresh and match machine registries.", result.stdout)

    def test_cli_subprocess_checker_human_output(self) -> None:
        """`python3 -B scripts/robot_docs_checker.py` exits with 0 and prints [PASS]."""
        result = subprocess.run(
            [sys.executable, "-B", str(ROOT / "scripts/robot_docs_checker.py")],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, f"stdout: {result.stdout}\nstderr: {result.stderr}")
        self.assertIn("[PASS]", result.stdout)

    def test_cli_subprocess_checker_json_output(self) -> None:
        """`python3 -B scripts/robot_docs_checker.py --json` emits valid status JSON."""
        result = subprocess.run(
            [sys.executable, "-B", str(ROOT / "scripts/robot_docs_checker.py"), "--json"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, f"stdout: {result.stdout}\nstderr: {result.stderr}")
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "passed")
        self.assertEqual(payload["operations_count"], 14)
        self.assertEqual(payload["views_count"], 8)
        self.assertEqual(payload["resources_count"], 15)
        self.assertEqual(payload["errors"], [])

    def test_operations_exact_crosswalk_consistency(self) -> None:
        """Every operation documented matches the operation crosswalk exactly."""
        docs_json = json.loads((ROOT / "docs/ROBOT_DOCS.json").read_text(encoding="utf-8"))
        crosswalk = json.loads((ROOT / "architecture/operation_crosswalk.json").read_text(encoding="utf-8"))
        cw_by_id = {c["operation_id"]: c for c in crosswalk["crosswalk"]}

        self.assertEqual(len(docs_json["operations"]), 14)
        for op in docs_json["operations"]:
            cw = cw_by_id[op["id"]]
            self.assertEqual(op["cliCommand"], cw["cli_command"])
            self.assertEqual(op["mcpToolName"], cw["mcp_tool_name"])
            self.assertEqual(op["libraryEntryPoint"], cw["library_entry_point"])
            self.assertEqual(op["primaryErrorId"], cw["primary_error_id"])

    def test_views_exact_registry_consistency(self) -> None:
        """Every view documented matches the agent_views registry exactly."""
        docs_json = json.loads((ROOT / "docs/ROBOT_DOCS.json").read_text(encoding="utf-8"))
        views_reg = json.loads((ROOT / "architecture/agent_views.json").read_text(encoding="utf-8"))
        reg_by_id = {v["id"]: v for v in views_reg["views"]}

        self.assertEqual(len(docs_json["views"]), 8)
        for view in docs_json["views"]:
            expected = reg_by_id[view["id"]]
            self.assertEqual(view["name"], expected["name"])
            self.assertEqual(view["targetTokens"], expected["targetTokens"])
            self.assertEqual(view["maximumTokens"], expected["maximumTokens"])
            self.assertEqual(view["requiredSections"], expected["requiredSections"])

    def test_resources_exact_registry_consistency(self) -> None:
        """Every resource URI template documented matches fss1_public_registry exactly."""
        docs_json = json.loads((ROOT / "docs/ROBOT_DOCS.json").read_text(encoding="utf-8"))
        fss1_reg = json.loads((ROOT / "architecture/fss1_public_registry.json").read_text(encoding="utf-8"))
        reg_by_id = {r["id"]: r for r in fss1_reg["resources"]}

        self.assertEqual(len(docs_json["resources"]), 15)
        for res in docs_json["resources"]:
            expected = reg_by_id[res["id"]]
            self.assertEqual(res["uriTemplate"], expected["uriTemplate"])
            self.assertEqual(res["payloadSchema"], expected["payloadSchema"])


if __name__ == "__main__":
    unittest.main()

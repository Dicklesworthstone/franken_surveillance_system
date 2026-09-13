from __future__ import annotations

"""Contract and regression tests for self-describing robot docs (fss-x4a.24.34 / FSS-234).

Verifies:
1. Live repository robot docs pass fail-closed consistency and freshness checks.
2. Generator is strictly deterministic and byte-idempotent.
3. Planted staleness (tampered markdown or JSON) fails closed with exact ERR-ROBOT-DOCS-STALE-001.
4. Missing generated files fail closed with exact ERR-ROBOT-DOCS-MISSING-001.
5. Registry drift (added, removed, or modified operations/views/resources) triggers exact error codes.
6. Corrupt JSON files and duplicate keys fail closed with exact ERR-ROBOT-DOCS-CORRUPT-001.
7. Subprocess CLI invocations (--check, --json) conform to expected formats and exit codes.
8. Mutants M3-M7, M9-M13, M15 killed with exact finding-code sets.
9. Synthetic model tests prove correct formatting independent of committed disk files.
"""

import copy
import json
import os
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
    ERR_ROBOT_DOCS_SECRET_DETECTED,
    ERR_ROBOT_DOCS_STALE,
    ERR_ROBOT_DOCS_UNREGISTERED,
    collect_robot_docs_model,
    escape_markdown_cell,
    escape_markdown_inline,
    escape_markdown_text,
    generate_docs,
    generate_robot_docs_json,
    generate_robot_docs_markdown,
)
from robot_docs_checker import (
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
        """Live repository robot documentation passes validation with zero errors and exact counts."""
        res = validate_robot_docs(ROOT)
        self.assertTrue(res.passed, f"Live robot docs validation failed: {res.errors}")
        self.assertEqual(len(res.errors), 0)
        self.assertEqual(res.operations_count, 14)
        self.assertEqual(res.views_count, 8)
        self.assertEqual(res.resources_count, 15)
        self.assertEqual(res.schemas_count, 73)
        self.assertEqual(res.capabilities_count, 12)
        self.assertEqual(res.errors_count, 250)
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
        """Missing docs/ROBOT_DOCS.md causes validation to fail with exact ERR-ROBOT-DOCS-MISSING-001."""
        md_file = self.fake_root / "docs/ROBOT_DOCS.md"
        if md_file.exists():
            md_file.unlink()

        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertEqual(error_codes, [ERR_ROBOT_DOCS_MISSING])

    def test_missing_json_fails_closed(self) -> None:
        """Missing docs/ROBOT_DOCS.json causes validation to fail with exact ERR-ROBOT-DOCS-MISSING-001."""
        json_file = self.fake_root / "docs/ROBOT_DOCS.json"
        if json_file.exists():
            json_file.unlink()

        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertEqual(error_codes, [ERR_ROBOT_DOCS_MISSING])

    def test_planted_stale_markdown_fails_closed(self) -> None:
        """Tampering with a single line in docs/ROBOT_DOCS.md fails with exact ERR-ROBOT-DOCS-STALE-001."""
        md_file = self.fake_root / "docs/ROBOT_DOCS.md"
        content = md_file.read_text(encoding="utf-8")
        tampered = content + "\n<!-- unauthorized trailing text -->\n"
        md_file.write_text(tampered, encoding="utf-8")

        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertEqual(error_codes, [ERR_ROBOT_DOCS_STALE])

    def test_planted_stale_json_fails_closed(self) -> None:
        """Tampering with a property in docs/ROBOT_DOCS.json fails with exact ERR-ROBOT-DOCS-STALE-001."""
        json_file = self.fake_root / "docs/ROBOT_DOCS.json"
        data = json.loads(json_file.read_text(encoding="utf-8"))
        data["operations"][0]["purpose"] = "tampered unauthorized purpose"
        json_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertEqual(error_codes, [ERR_ROBOT_DOCS_STALE])

    def test_corrupt_json_fails_closed(self) -> None:
        """Corrupt JSON in docs/ROBOT_DOCS.json fails closed with exact ERR-ROBOT-DOCS-CORRUPT-001."""
        json_file = self.fake_root / "docs/ROBOT_DOCS.json"
        json_file.write_text("{ unclosed invalid json", encoding="utf-8")

        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertEqual(error_codes, [ERR_ROBOT_DOCS_CORRUPT])

    def test_mutant_m3_disordered_operations_in_json(self) -> None:
        """Mutant M3: Swapping order of operations in ROBOT_DOCS.json triggers ERR-ROBOT-DOCS-STALE-001."""
        json_file = self.fake_root / "docs/ROBOT_DOCS.json"
        data = json.loads(json_file.read_text(encoding="utf-8"))
        data["operations"][0], data["operations"][1] = data["operations"][1], data["operations"][0]
        json_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_ROBOT_DOCS_STALE, error_codes)

    def test_mutant_m4_tampered_view_sections(self) -> None:
        """Mutant M4: Modifying view maximumTokens in agent_views.json triggers ERR-ROBOT-DOCS-STALE-001."""
        views_file = self.fake_root / "architecture/agent_views.json"
        views_data = json.loads(views_file.read_text(encoding="utf-8"))
        views_data["views"][0]["maximumTokens"] += 1000
        views_file.write_text(json.dumps(views_data, indent=2), encoding="utf-8")

        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertEqual(set(error_codes), {ERR_ROBOT_DOCS_STALE})

    def test_mutant_m5_tampered_resource_uri(self) -> None:
        """Mutant M5: Modifying a resource uriTemplate in fss1_public_registry triggers ERR-ROBOT-DOCS-STALE-001."""
        fss1_file = self.fake_root / "architecture/fss1_public_registry.json"
        fss1_data = json.loads(fss1_file.read_text(encoding="utf-8"))
        fss1_data["resources"][0]["uriTemplate"] = "fss://altered/uri/{deployment}"
        fss1_file.write_text(json.dumps(fss1_data, indent=2), encoding="utf-8")

        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertEqual(set(error_codes), {ERR_ROBOT_DOCS_STALE})

    def test_mutant_m6_capability_field_tampering(self) -> None:
        """Mutant M6: Modifying capability defaultRole in capabilities.json triggers ERR-ROBOT-DOCS-STALE-001."""
        caps_file = self.fake_root / "architecture/capabilities.json"
        caps_data = json.loads(caps_file.read_text(encoding="utf-8"))
        cancel_cap = next(c for c in caps_data["capabilities"] if c["id"] == "CAP-AGENT-CANCEL-001")
        cancel_cap["defaultRole"] = "unauthorized modified role"
        caps_file.write_text(json.dumps(caps_data, indent=2), encoding="utf-8")

        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertEqual(set(error_codes), {ERR_ROBOT_DOCS_STALE})

    def test_mutant_m7_schema_rule_tampering(self) -> None:
        """Mutant M7: Modifying schema compatibilityRule in SCHEMAS.md triggers ERR-ROBOT-DOCS-STALE-001."""
        schemas_file = self.fake_root / "registries/SCHEMAS.md"
        content = schemas_file.read_text(encoding="utf-8")
        tampered = content.replace("immutable; additions compatible", "breaking mutation permitted")
        schemas_file.write_text(tampered, encoding="utf-8")

        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertEqual(set(error_codes), {ERR_ROBOT_DOCS_STALE})

    def test_mutant_m9_duplicate_json_key(self) -> None:
        """Mutant M9: Duplicate key in a registry JSON triggers exact ERR-ROBOT-DOCS-CORRUPT-001."""
        ops_file = self.fake_root / "architecture/agent_operations.json"
        text = ops_file.read_text(encoding="utf-8")
        # Inject duplicate key at top level
        injected = '{\n  "asOf": "2026-09-12",\n  "asOf": "2026-09-13",\n' + text[1:]
        ops_file.write_text(injected, encoding="utf-8")

        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertEqual(error_codes, [ERR_ROBOT_DOCS_CORRUPT])

    def test_mutant_m9b_duplicate_operation_id(self) -> None:
        """Mutant M9b: Duplicate operation ID in agent_operations.json triggers exact ERR-ROBOT-DOCS-CORRUPT-001."""
        ops_file = self.fake_root / "architecture/agent_operations.json"
        data = json.loads(ops_file.read_text(encoding="utf-8"))
        dup_op = copy.deepcopy(data["operations"][0])
        data["operations"].append(dup_op)
        ops_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertEqual(error_codes, [ERR_ROBOT_DOCS_CORRUPT])

    def test_mutant_m10_cross_registry_mismatch(self) -> None:
        """Mutant M10: Operation missing in operation_crosswalk.json triggers exact ERR-ROBOT-DOCS-DRIFT-001."""
        cw_file = self.fake_root / "architecture/operation_crosswalk.json"
        data = json.loads(cw_file.read_text(encoding="utf-8"))
        data["crosswalk"] = [c for c in data["crosswalk"] if c["operation_id"] != "AOP-014"]
        cw_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertEqual(error_codes, [ERR_ROBOT_DOCS_DRIFT])

    def test_mutant_m11_unregistered_capability_reference(self) -> None:
        """Mutant M11: Operation referencing unregistered capability triggers exact ERR-ROBOT-DOCS-UNREGISTERED-001."""
        ops_file = self.fake_root / "architecture/agent_operations.json"
        data = json.loads(ops_file.read_text(encoding="utf-8"))
        data["operations"][0]["requiredCapabilities"].append("CAP-NONEXISTENT-999")
        ops_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertEqual(error_codes, [ERR_ROBOT_DOCS_UNREGISTERED])

    def test_mutant_m11b_unregistered_schema_reference(self) -> None:
        """Mutant M11b: Operation referencing unregistered schema triggers exact ERR-ROBOT-DOCS-UNREGISTERED-001."""
        ops_file = self.fake_root / "architecture/agent_operations.json"
        data = json.loads(ops_file.read_text(encoding="utf-8"))
        data["operations"][0]["requestPayloadSchema"] = "fss.unregistered_payload.v99"
        ops_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertEqual(error_codes, [ERR_ROBOT_DOCS_UNREGISTERED])

    def test_mutant_m11c_unregistered_error_reference(self) -> None:
        """Mutant M11c: Crosswalk referencing unregistered error triggers exact ERR-ROBOT-DOCS-UNREGISTERED-001."""
        cw_file = self.fake_root / "architecture/operation_crosswalk.json"
        data = json.loads(cw_file.read_text(encoding="utf-8"))
        data["crosswalk"][0]["primary_error_id"] = "ERR-UNREGISTERED-MAGIC-001"
        cw_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertEqual(error_codes, [ERR_ROBOT_DOCS_UNREGISTERED])

    def test_mutant_m12_secret_token_in_registry(self) -> None:
        """Mutant M12: Registry containing secret token triggers exact ERR-ROBOT-DOCS-SECRET-DETECTED-001."""
        views_file = self.fake_root / "architecture/agent_views.json"
        data = json.loads(views_file.read_text(encoding="utf-8"))
        data["views"][0]["purpose"] = "view with token=ghp_secretTokenVal123456789"
        views_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertEqual(error_codes, [ERR_ROBOT_DOCS_SECRET_DETECTED])

    def test_mutant_m12b_private_home_path_in_registry(self) -> None:
        """Mutant M12b: Registry containing home path triggers exact ERR-ROBOT-DOCS-SECRET-DETECTED-001."""
        views_file = self.fake_root / "architecture/agent_views.json"
        data = json.loads(views_file.read_text(encoding="utf-8"))
        data["views"][0]["purpose"] = "view reading /home/ubuntu/.ssh/id_rsa keys"
        views_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertEqual(error_codes, [ERR_ROBOT_DOCS_SECRET_DETECTED])

    def test_mutant_m13_markdown_escaping(self) -> None:
        """Mutant M13: Pipes, newlines, and heading injections are safely sanitized."""
        cell = escape_markdown_cell("text with | pipe and \n newline")
        self.assertEqual(cell, "text with \\| pipe and   newline")
        self.assertNotIn("|", cell.replace("\\|", ""))

        text = escape_markdown_text("description\n## Injected Heading\nnormal text")
        self.assertNotIn("\n## ", text)
        self.assertIn("\\# Injected Heading", text)

        inline = escape_markdown_inline("foo `bar` baz\nqux")
        self.assertEqual(inline, "foo 'bar' baz qux")

    def test_mutant_m15_synthetic_model_golden(self) -> None:
        """Mutant M15: Pure synthetic model produces deterministic golden outputs without relying on committed docs."""
        synthetic_model = {
            "schema": "fss.robot_docs.v1",
            "asOf": "2026-09-12",
            "semanticProtocol": "fss/1",
            "registryGeneration": "gen:fss1:synthetic-v1",
            "freezeDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "operations": [
                {
                    "id": "AOP-901",
                    "name": "synth.operation",
                    "purpose": "A test synthetic operation",
                    "mode": "sync",
                    "owner": "fss-synth",
                    "defaultView": "AVIEW-901",
                    "effectful": False,
                    "durable": True,
                    "cliCommand": "fss synth op",
                    "mcpToolName": "synth_op",
                    "libraryEntryPoint": "fss_synth::op",
                    "requestEnvelope": "fss.agent_request_envelope.v1",
                    "responseEnvelope": "fss.agent_response_envelope.v1",
                    "requestPayloadSchema": "",
                    "responsePayloadSchemas": [],
                    "requiredCapabilities": ["CAP-SYNTH-001"],
                    "retryClasses": ["safe_retry"],
                    "primaryErrorId": "ERR-SYNTH-001",
                    "errorIdentities": ["ERR-SYNTH-001"],
                    "exitIdentities": ["EXIT-OK-000"],
                    "gate": "QL-AGENT-001",
                    "status": "specified",
                }
            ],
            "views": [
                {
                    "id": "AVIEW-901",
                    "name": "synth_view",
                    "owner": "fss-synth",
                    "purpose": "Synthetic view for testing",
                    "targetTokens": 500,
                    "maximumTokens": 1000,
                    "requiredSections": ["summary"],
                    "gate": "QL-AGENT-001",
                    "status": "specified",
                }
            ],
            "resources": [
                {
                    "id": "ARES-901",
                    "name": "synth_resource",
                    "owner": "fss-synth",
                    "uriTemplate": "fss://synth/{id}",
                    "requestEnvelope": "fss.agent_request_envelope.v1",
                    "responseEnvelope": "fss.agent_response_envelope.v1",
                    "payloadSchema": "",
                    "compatibilityClass": "backward_compatible",
                    "status": "specified",
                }
            ],
            "schemas": [
                {
                    "id": "SCHEMA-SYNTH-001",
                    "schema": "fss.synth.v1",
                    "file": "schemas/synth.v1.json",
                    "authority": "authority",
                    "compatibilityRule": "immutable; additions compatible",
                }
            ],
            "capabilities": [
                {
                    "id": "CAP-SYNTH-001",
                    "capability": "execute synthetic test operation",
                    "scope": "test",
                    "plane": "cognition",
                    "defaultRole": "test role",
                    "denialReason": "denied",
                    "safeAlternative": "alternative",
                    "generation": "gen:fss1:synthetic-v1",
                }
            ],
            "errors": [
                {
                    "id": "ERR-SYNTH-001",
                    "description": "Synthetic error for test",
                    "guidance": "Retry synthetic test",
                }
            ],
            "discovery": {
                "capabilities": {
                    "cli": "fss capabilities --json",
                    "description": "Report all supported device, model, and agent capabilities in typed JSON",
                }
            },
        }

        md = generate_robot_docs_markdown(synthetic_model)
        json_str = generate_robot_docs_json(synthetic_model)

        self.assertIn("# Self-Describing Robot Documentation (`fss/1`)", md)
        self.assertIn("| `AOP-901` | `synth.operation` |", md)
        self.assertIn("| `AVIEW-901` | `synth_view` |", md)
        self.assertIn("| `ARES-901` | `synth_resource` |", md)
        self.assertIn("| `SCHEMA-SYNTH-001` | `fss.synth.v1` |", md)
        self.assertIn("| `CAP-SYNTH-001` | execute synthetic test operation |", md)
        self.assertIn("| `ERR-SYNTH-001` | Synthetic error for test |", md)

        parsed = json.loads(json_str)
        self.assertEqual(parsed["schema"], "fss.robot_docs.v1")
        self.assertEqual(parsed["operations"][0]["id"], "AOP-901")

    def test_output_dir_outside_repo(self) -> None:
        """generate_robot_docs.py --output-dir outside repo writes successfully without crash."""
        with tempfile.TemporaryDirectory() as out_dir:
            result = subprocess.run(
                [sys.executable, "-B", str(ROOT / "scripts/generate_robot_docs.py"), "--output-dir", out_dir],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, f"stdout: {result.stdout}\nstderr: {result.stderr}")
            self.assertTrue((Path(out_dir) / "ROBOT_DOCS.md").is_file())
            self.assertTrue((Path(out_dir) / "ROBOT_DOCS.json").is_file())

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
        self.assertEqual(payload["schemas_count"], 73)
        self.assertEqual(payload["capabilities_count"], 12)
        self.assertEqual(payload["errors_count"], 250)
        self.assertEqual(payload["errors"], [])


if __name__ == "__main__":
    unittest.main()

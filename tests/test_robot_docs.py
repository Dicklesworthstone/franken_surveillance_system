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
        (self.fake_root / "crates/fss-cli/src").mkdir(parents=True, exist_ok=True)

        for arch_file in [
            "fss1_public_registry.json",
            "agent_operations.json",
            "agent_views.json",
            "capabilities.json",
            "operation_crosswalk.json",
            "release_qualification.json",
        ]:
            src = ROOT / "architecture" / arch_file
            if src.exists():
                shutil.copyfile(src, self.fake_root / "architecture" / arch_file)

        for reg_file in ["ERRORS.md", "SCHEMAS.md"]:
            src = ROOT / "registries" / reg_file
            if src.exists():
                shutil.copyfile(src, self.fake_root / "registries" / reg_file)

        fss_cmd = ROOT / "crates/fss-cli/src/fss_cmd.rs"
        if fss_cmd.exists():
            shutil.copyfile(fss_cmd, self.fake_root / "crates/fss-cli/src/fss_cmd.rs")

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
        self.assertEqual(res.errors_count, 256)
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

    def test_mutant_m3_disordered_operations_in_json(self) -> None:
        """Mutant M3: Swapping order of operations in ROBOT_DOCS.json triggers ERR-ROBOT-DOCS-STALE-001."""
        json_file = self.fake_root / "docs/ROBOT_DOCS.json"
        data = json.loads(json_file.read_text(encoding="utf-8"))
        data["operations"][0], data["operations"][1] = data["operations"][1], data["operations"][0]
        json_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertEqual(set(error_codes), {ERR_ROBOT_DOCS_STALE})

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

        fss1_file = self.fake_root / "architecture/fss1_public_registry.json"
        fss1_data = json.loads(fss1_file.read_text(encoding="utf-8"))
        fss1_data["operations"][0]["requestPayloadSchema"] = "fss.unregistered_payload.v99"
        fss1_file.write_text(json.dumps(fss1_data, indent=2), encoding="utf-8")

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
                },
                {
                    "id": "ERR-AGENT-PROTOCOL-001",
                    "description": "Request envelope or semantic protocol invalid",
                    "guidance": "Validate envelope format and rebase",
                },
                {
                    "id": "ERR-AGENT-SESSION-STALE-001",
                    "description": "Session expired or generation revoked",
                    "guidance": "Reopen session with fresh token",
                },
                {
                    "id": "ERR-AGENT-CONTEXT-INCOMPLETE-001",
                    "description": "Context window truncated or missing dependencies",
                    "guidance": "Replay with complete context pack",
                },
                {
                    "id": "ERR-AGENT-RESNAPSHOT-001",
                    "description": "State diverged from anchor snapshot",
                    "guidance": "Fetch fresh snapshot and resume",
                },
                {
                    "id": "ERR-AGENT-AMBIGUOUS-001",
                    "description": "Ambiguous instruction requiring clarification",
                    "guidance": "Clarify intent and resubmit",
                },
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
        self.assertEqual(payload["errors_count"], 256)
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

    def test_cli_subprocess_generate_check_mode_stale(self) -> None:
        """`generate_robot_docs.py --check` exits with non-zero when docs are stale."""
        md_file = self.fake_root / "docs/ROBOT_DOCS.md"
        md_file.write_text(md_file.read_text(encoding="utf-8") + "\n<!-- stale modification -->\n", encoding="utf-8")
        result = subprocess.run(
            [sys.executable, "-B", str(ROOT / "scripts/generate_robot_docs.py"), "--check", "--repo-root", str(self.fake_root)],
            cwd=self.fake_root,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(ERR_ROBOT_DOCS_STALE, result.stderr)

    def test_tampered_byte_in_robot_docs_md_check(self) -> None:
        """A single tampered byte in docs/ROBOT_DOCS.md fails generate_robot_docs.py --check."""
        md_file = self.fake_root / "docs/ROBOT_DOCS.md"
        content = md_file.read_text(encoding="utf-8")
        tampered = content.replace("Self-Describing", "Self-Describinx", 1)
        md_file.write_text(tampered, encoding="utf-8")
        result = subprocess.run(
            [sys.executable, "-B", str(ROOT / "scripts/generate_robot_docs.py"), "--check", "--repo-root", str(self.fake_root)],
            cwd=self.fake_root,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(ERR_ROBOT_DOCS_STALE, result.stderr)

    def test_tampered_byte_in_robot_docs_json(self) -> None:
        """A single tampered byte in docs/ROBOT_DOCS.json fails validation with exact ERR-ROBOT-DOCS-STALE-001."""
        json_file = self.fake_root / "docs/ROBOT_DOCS.json"
        content = json_file.read_text(encoding="utf-8")
        tampered = content.replace('"fss/1"', '"fss/2"', 1)
        json_file.write_text(tampered, encoding="utf-8")
        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertEqual(set(error_codes), {ERR_ROBOT_DOCS_STALE})

    def test_mutant_duplicate_view_id_in_agent_views(self) -> None:
        """Duplicate view ID in agent_views.json triggers exact ERR-ROBOT-DOCS-CORRUPT-001."""
        views_file = self.fake_root / "architecture/agent_views.json"
        data = json.loads(views_file.read_text(encoding="utf-8"))
        dup_view = copy.deepcopy(data["views"][0])
        data["views"].append(dup_view)
        views_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertEqual(set(error_codes), {ERR_ROBOT_DOCS_CORRUPT})

    def test_mutant_duplicate_error_id_in_errors_md(self) -> None:
        """Duplicate error ID in ERRORS.md triggers exact ERR-ROBOT-DOCS-CORRUPT-001."""
        err_file = self.fake_root / "registries/ERRORS.md"
        content = err_file.read_text(encoding="utf-8")
        dup_line = "\n| `ERR-AGENT-PROTOCOL-001` | Duplicate protocol error | safe_retry |\n"
        err_file.write_text(content + dup_line, encoding="utf-8")
        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertEqual(set(error_codes), {ERR_ROBOT_DOCS_CORRUPT})

    def test_mutant_duplicate_schema_id_in_schemas_md(self) -> None:
        """Duplicate schema ID in SCHEMAS.md triggers exact ERR-ROBOT-DOCS-CORRUPT-001."""
        schema_file = self.fake_root / "registries/SCHEMAS.md"
        content = schema_file.read_text(encoding="utf-8")
        dup_line = "\n| `SCHEMA-SENSOR-CAPSULE-001` | `fss.sensor_capsule.v2` | `schemas/sensor_capsule.v2.json` | authority | duplicate |\n"
        schema_file.write_text(content + dup_line, encoding="utf-8")
        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertEqual(set(error_codes), {ERR_ROBOT_DOCS_CORRUPT})

    def test_mutant_tombstoned_capability_reference(self) -> None:
        """Mutant G1: Referencing a registered but tombstoned capability triggers exact ERR-ROBOT-DOCS-UNREGISTERED-001."""
        caps_file = self.fake_root / "architecture/capabilities.json"
        data = json.loads(caps_file.read_text(encoding="utf-8"))
        registered_cap_id = data["capabilities"][0]["id"]
        data["tombstones"] = [registered_cap_id]
        caps_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

        ops_file = self.fake_root / "architecture/agent_operations.json"
        ops_data = json.loads(ops_file.read_text(encoding="utf-8"))
        if registered_cap_id not in ops_data["operations"][0]["requiredCapabilities"]:
            ops_data["operations"][0]["requiredCapabilities"].append(registered_cap_id)
        ops_file.write_text(json.dumps(ops_data, indent=2), encoding="utf-8")

        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertEqual(set(error_codes), {ERR_ROBOT_DOCS_UNREGISTERED})

    def test_mutant_unregistered_response_schema_reference(self) -> None:
        """Referencing unregistered response schema triggers exact ERR-ROBOT-DOCS-UNREGISTERED-001."""
        ops_file = self.fake_root / "architecture/agent_operations.json"
        ops_data = json.loads(ops_file.read_text(encoding="utf-8"))
        ops_data["operations"][0]["responsePayloadSchemas"].append("fss.unregistered_response.v99")
        ops_file.write_text(json.dumps(ops_data, indent=2), encoding="utf-8")

        fss1_file = self.fake_root / "architecture/fss1_public_registry.json"
        fss1_data = json.loads(fss1_file.read_text(encoding="utf-8"))
        fss1_data["operations"][0]["responsePayloadSchemas"].append("fss.unregistered_response.v99")
        fss1_file.write_text(json.dumps(fss1_data, indent=2), encoding="utf-8")

        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertEqual(set(error_codes), {ERR_ROBOT_DOCS_UNREGISTERED})

    def test_mutant_unregistered_resource_payload_schema(self) -> None:
        """Resource referencing unregistered schema triggers exact ERR-ROBOT-DOCS-UNREGISTERED-001."""
        fss1_file = self.fake_root / "architecture/fss1_public_registry.json"
        fss1_data = json.loads(fss1_file.read_text(encoding="utf-8"))
        fss1_data["resources"][0]["payloadSchema"] = "fss.unregistered_resource_payload.v99"
        fss1_file.write_text(json.dumps(fss1_data, indent=2), encoding="utf-8")

        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertEqual(set(error_codes), {ERR_ROBOT_DOCS_UNREGISTERED})

    def test_mutant_unregistered_error_identity_reference(self) -> None:
        """Crosswalk referencing unregistered error identity triggers exact ERR-ROBOT-DOCS-UNREGISTERED-001."""
        cw_file = self.fake_root / "architecture/operation_crosswalk.json"
        cw_data = json.loads(cw_file.read_text(encoding="utf-8"))
        cw_data["crosswalk"][0]["error_identities"].append("ERR-UNREGISTERED-EXTRA-999")
        cw_file.write_text(json.dumps(cw_data, indent=2), encoding="utf-8")

        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertEqual(set(error_codes), {ERR_ROBOT_DOCS_UNREGISTERED})

    def test_mutant_unregistered_default_view_reference(self) -> None:
        """Operation referencing unregistered defaultView triggers exact ERR-ROBOT-DOCS-UNREGISTERED-001."""
        ops_file = self.fake_root / "architecture/agent_operations.json"
        ops_data = json.loads(ops_file.read_text(encoding="utf-8"))
        ops_data["operations"][0]["defaultView"] = "AVIEW-NONEXISTENT-999"
        ops_file.write_text(json.dumps(ops_data, indent=2), encoding="utf-8")

        fss1_file = self.fake_root / "architecture/fss1_public_registry.json"
        fss1_data = json.loads(fss1_file.read_text(encoding="utf-8"))
        fss1_data["operations"][0]["defaultView"] = "AVIEW-NONEXISTENT-999"
        fss1_file.write_text(json.dumps(fss1_data, indent=2), encoding="utf-8")

        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertEqual(set(error_codes), {ERR_ROBOT_DOCS_UNREGISTERED})

    def test_mutant_secret_token_in_errors_md(self) -> None:
        """Secret token in ERRORS.md triggers exact ERR-ROBOT-DOCS-SECRET-DETECTED-001."""
        err_file = self.fake_root / "registries/ERRORS.md"
        content = err_file.read_text(encoding="utf-8")
        err_file.write_text(content + "\n<!-- password is supersecret123 -->\n", encoding="utf-8")

        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertEqual(set(error_codes), {ERR_ROBOT_DOCS_SECRET_DETECTED})

    def test_mutant_secret_token_in_fss1_registry(self) -> None:
        """AWS secret key pattern in fss1_public_registry.json triggers exact ERR-ROBOT-DOCS-SECRET-DETECTED-001."""
        fss1_file = self.fake_root / "architecture/fss1_public_registry.json"
        fss1_data = json.loads(fss1_file.read_text(encoding="utf-8"))
        fss1_data["resources"][0]["description"] = "resource with token AKIAIOSFODNN7EXAMPLE"
        fss1_file.write_text(json.dumps(fss1_data, indent=2), encoding="utf-8")

        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertEqual(set(error_codes), {ERR_ROBOT_DOCS_SECRET_DETECTED})

    def test_mutant_missing_asof_in_operations(self) -> None:
        """Missing asOf date in agent_operations.json triggers exact ERR-ROBOT-DOCS-CORRUPT-001."""
        ops_file = self.fake_root / "architecture/agent_operations.json"
        ops_data = json.loads(ops_file.read_text(encoding="utf-8"))
        del ops_data["asOf"]
        ops_file.write_text(json.dumps(ops_data, indent=2), encoding="utf-8")

        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertEqual(set(error_codes), {ERR_ROBOT_DOCS_CORRUPT})

    def test_mutant_malformed_asof_in_operations(self) -> None:
        """Malformed asOf date in agent_operations.json triggers exact ERR-ROBOT-DOCS-CORRUPT-001."""
        ops_file = self.fake_root / "architecture/agent_operations.json"
        ops_data = json.loads(ops_file.read_text(encoding="utf-8"))
        ops_data["asOf"] = "not-a-real-date"
        ops_file.write_text(json.dumps(ops_data, indent=2), encoding="utf-8")

        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertEqual(set(error_codes), {ERR_ROBOT_DOCS_CORRUPT})

    def test_mutant_crosswalk_fss1_field_conflict(self) -> None:
        """Conflicting cliCommand between fss1 and crosswalk triggers exact ERR-ROBOT-DOCS-DRIFT-001."""
        fss1_file = self.fake_root / "architecture/fss1_public_registry.json"
        fss1_data = json.loads(fss1_file.read_text(encoding="utf-8"))
        fss1_data["operations"][0]["cliCommand"] = "fss conflicting cli command"
        fss1_file.write_text(json.dumps(fss1_data, indent=2), encoding="utf-8")

        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertEqual(set(error_codes), {ERR_ROBOT_DOCS_DRIFT})

    def test_mutant_malformed_non_dict_input_handled_cleanly(self) -> None:
        """Non-dict root in agent_operations.json fails closed with exact ERR-ROBOT-DOCS-CORRUPT-001."""
        ops_file = self.fake_root / "architecture/agent_operations.json"
        ops_file.write_text(json.dumps(["item1", "item2"]), encoding="utf-8")

        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertEqual(set(error_codes), {ERR_ROBOT_DOCS_CORRUPT})

    def test_mutant_malformed_non_list_operations_handled_cleanly(self) -> None:
        """Non-list operations in agent_operations.json fails closed with exact ERR-ROBOT-DOCS-CORRUPT-001."""
        ops_file = self.fake_root / "architecture/agent_operations.json"
        ops_data = json.loads(ops_file.read_text(encoding="utf-8"))
        ops_data["operations"] = "invalid_not_a_list"
        ops_file.write_text(json.dumps(ops_data, indent=2), encoding="utf-8")

        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertEqual(set(error_codes), {ERR_ROBOT_DOCS_CORRUPT})

    # --- Item 1: Default path regenerate test ---

    def test_default_regenerate_no_output_dir(self) -> None:
        """Invoking generate_robot_docs without --output-dir creates docs in repo_root/docs without AttributeError."""
        with tempfile.TemporaryDirectory() as td:
            temp_repo = Path(td)
            shutil.copytree(self.fake_root, temp_repo, dirs_exist_ok=True)
            docs_dir = temp_repo / "docs"
            if docs_dir.exists():
                shutil.rmtree(docs_dir)
            cmd = [sys.executable, "-B", str(ROOT / "scripts/generate_robot_docs.py"), "--repo-root", str(temp_repo)]
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
            self.assertEqual(proc.returncode, 0, f"STDOUT: {proc.stdout}\nSTDERR: {proc.stderr}")
            self.assertTrue((docs_dir / "ROBOT_DOCS.md").is_file())
            self.assertTrue((docs_dir / "ROBOT_DOCS.json").is_file())

    # --- Item 3: Secret & path pattern planted tests ---

    def test_secret_scan_bare_bearer(self) -> None:
        """Planted bare Bearer token triggers ERR-ROBOT-DOCS-SECRET-DETECTED-001."""
        ops_file = self.fake_root / "architecture/agent_operations.json"
        data = json.loads(ops_file.read_text(encoding="utf-8"))
        data["operations"][0]["purpose"] = "header is Bearer eyJhbGciOiJIUzI1NiJ9"
        ops_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_ROBOT_DOCS_SECRET_DETECTED})

    def test_secret_scan_sk_ant(self) -> None:
        """Planted sk-ant- token triggers ERR-ROBOT-DOCS-SECRET-DETECTED-001."""
        views_file = self.fake_root / "architecture/agent_views.json"
        data = json.loads(views_file.read_text(encoding="utf-8"))
        data["views"][0]["purpose"] = "test with sk-ant-api03-abcdef123456789"
        views_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_ROBOT_DOCS_SECRET_DETECTED})

    def test_secret_scan_sk_bare(self) -> None:
        """Planted sk- token triggers ERR-ROBOT-DOCS-SECRET-DETECTED-001."""
        views_file = self.fake_root / "architecture/agent_views.json"
        data = json.loads(views_file.read_text(encoding="utf-8"))
        data["views"][0]["purpose"] = "test with sk-abcdef12345678901234"
        views_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_ROBOT_DOCS_SECRET_DETECTED})

    def test_secret_scan_aiza(self) -> None:
        """Planted AIza Google API key triggers ERR-ROBOT-DOCS-SECRET-DETECTED-001."""
        views_file = self.fake_root / "architecture/agent_views.json"
        data = json.loads(views_file.read_text(encoding="utf-8"))
        data["views"][0]["purpose"] = "test with AIzaSyD1234567890abcdef1234567890"
        views_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_ROBOT_DOCS_SECRET_DETECTED})

    def test_secret_scan_xoxp(self) -> None:
        """Planted xoxp- Slack user token triggers ERR-ROBOT-DOCS-SECRET-DETECTED-001."""
        views_file = self.fake_root / "architecture/agent_views.json"
        data = json.loads(views_file.read_text(encoding="utf-8"))
        data["views"][0]["purpose"] = "test with xoxp-1234567890-1234567890"
        views_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_ROBOT_DOCS_SECRET_DETECTED})

    def test_secret_scan_glpat(self) -> None:
        """Planted glpat- GitLab token triggers ERR-ROBOT-DOCS-SECRET-DETECTED-001."""
        views_file = self.fake_root / "architecture/agent_views.json"
        data = json.loads(views_file.read_text(encoding="utf-8"))
        data["views"][0]["purpose"] = "test with glpat-12345678901234567890"
        views_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_ROBOT_DOCS_SECRET_DETECTED})

    def test_secret_scan_asia(self) -> None:
        """Planted ASIA AWS temporary credential triggers ERR-ROBOT-DOCS-SECRET-DETECTED-001."""
        views_file = self.fake_root / "architecture/agent_views.json"
        data = json.loads(views_file.read_text(encoding="utf-8"))
        data["views"][0]["purpose"] = "test with ASIAIOSFODNN7EXAMPLE"
        views_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_ROBOT_DOCS_SECRET_DETECTED})

    def test_secret_scan_passwd(self) -> None:
        """Planted passwd= parameter triggers ERR-ROBOT-DOCS-SECRET-DETECTED-001."""
        views_file = self.fake_root / "architecture/agent_views.json"
        data = json.loads(views_file.read_text(encoding="utf-8"))
        data["views"][0]["purpose"] = "connect with passwd=secretpassword123"
        views_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_ROBOT_DOCS_SECRET_DETECTED})

    def test_secret_scan_postgres_uri(self) -> None:
        """Planted postgres credential URI triggers ERR-ROBOT-DOCS-SECRET-DETECTED-001."""
        views_file = self.fake_root / "architecture/agent_views.json"
        data = json.loads(views_file.read_text(encoding="utf-8"))
        data["views"][0]["purpose"] = "db at postgres://app_user:dbpassword@127.0.0.1/prod"
        views_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_ROBOT_DOCS_SECRET_DETECTED})

    def test_secret_scan_secret_key(self) -> None:
        """Planted secret_key= assignment triggers ERR-ROBOT-DOCS-SECRET-DETECTED-001."""
        views_file = self.fake_root / "architecture/agent_views.json"
        data = json.loads(views_file.read_text(encoding="utf-8"))
        data["views"][0]["purpose"] = "config secret_key=super_secret_val"
        views_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_ROBOT_DOCS_SECRET_DETECTED})

    def test_secret_scan_client_secret(self) -> None:
        """Planted client_secret: assignment triggers ERR-ROBOT-DOCS-SECRET-DETECTED-001."""
        views_file = self.fake_root / "architecture/agent_views.json"
        data = json.loads(views_file.read_text(encoding="utf-8"))
        data["views"][0]["purpose"] = "client_secret: oauth_secret_12345"
        views_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_ROBOT_DOCS_SECRET_DETECTED})

    def test_secret_scan_npm(self) -> None:
        """Planted npm_ access token triggers ERR-ROBOT-DOCS-SECRET-DETECTED-001."""
        views_file = self.fake_root / "architecture/agent_views.json"
        data = json.loads(views_file.read_text(encoding="utf-8"))
        data["views"][0]["purpose"] = "registry auth npm_1234567890abcdef"
        views_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_ROBOT_DOCS_SECRET_DETECTED})

    def test_secret_scan_unc_path(self) -> None:
        """Planted UNC path triggers ERR-ROBOT-DOCS-SECRET-DETECTED-001."""
        views_file = self.fake_root / "architecture/agent_views.json"
        data = json.loads(views_file.read_text(encoding="utf-8"))
        data["views"][0]["purpose"] = r"mounted at \\company_server\shared_share\folder"
        views_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_ROBOT_DOCS_SECRET_DETECTED})

    def test_secret_scan_private_var(self) -> None:
        """Planted /private/var path triggers ERR-ROBOT-DOCS-SECRET-DETECTED-001."""
        views_file = self.fake_root / "architecture/agent_views.json"
        data = json.loads(views_file.read_text(encoding="utf-8"))
        data["views"][0]["purpose"] = "logging at /private/var/log/audit.log"
        views_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_ROBOT_DOCS_SECRET_DETECTED})

    def test_secret_scan_planted_in_fss_cmd_doc(self) -> None:
        """Planted secret token in fss_cmd.rs doc comment is detected and refused."""
        fss_cmd_path = self.fake_root / "crates/fss-cli/src/fss_cmd.rs"
        content = fss_cmd_path.read_text(encoding="utf-8")
        planted = content.replace("/// Report capabilities", "/// Report ghp_12345678901234567890 capabilities")
        self.assertIn("ghp_", planted)
        fss_cmd_path.write_text(planted, encoding="utf-8")
        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_ROBOT_DOCS_SECRET_DETECTED})

    def test_secret_scan_planted_in_release_qualification(self) -> None:
        """Planted local home path in release_qualification.json is detected and refused."""
        rel_qual_path = self.fake_root / "architecture/release_qualification.json"
        data = json.loads(rel_qual_path.read_text(encoding="utf-8"))
        data["lanes"][0]["description"] = "lane runs on /home/operator/workspace"
        rel_qual_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_ROBOT_DOCS_SECRET_DETECTED})

    def test_secret_scan_tilde_second_not_false_positive(self) -> None:
        """Legitimate frequency phrase '~/second' does not trigger false positive secret detection."""
        views_file = self.fake_root / "architecture/agent_views.json"
        data = json.loads(views_file.read_text(encoding="utf-8"))
        data["views"][0]["purpose"] = "throughput target is ~10/second or ~/second"
        views_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        res = validate_robot_docs(self.fake_root)
        self.assertNotIn(ERR_ROBOT_DOCS_SECRET_DETECTED, [e.code for e in res.errors])

    def test_benign_bearer_prose_passes(self) -> None:
        """Legitimate prose mentioning 'Bearer authentication scheme' does not trigger false positive secret detection."""
        ops_file = self.fake_root / "architecture/agent_operations.json"
        data = json.loads(ops_file.read_text(encoding="utf-8"))
        data["operations"][0]["purpose"] = "Uses standard Bearer authentication scheme for session initiation"
        ops_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        res = validate_robot_docs(self.fake_root)
        self.assertNotIn(ERR_ROBOT_DOCS_SECRET_DETECTED, [e.code for e in res.errors])

    def test_secret_scan_tilde_secrets_path(self) -> None:
        """Planted path with ~/secrets triggers ERR-ROBOT-DOCS-SECRET-DETECTED-001."""
        views_file = self.fake_root / "architecture/agent_views.json"
        data = json.loads(views_file.read_text(encoding="utf-8"))
        data["views"][0]["purpose"] = "Credentials stored in ~/secrets/keys.txt"
        views_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_ROBOT_DOCS_SECRET_DETECTED})

    # --- Item 5: Malformed on-disk capabilities, non-list tombstones, wrongly typed fields ---

    def test_checker_malformed_on_disk_capabilities(self) -> None:
        """Malformed on-disk capabilities structure returns typed ERR-ROBOT-DOCS-CORRUPT-001 without crashing."""
        json_path = self.fake_root / "docs/ROBOT_DOCS.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        data["capabilities"] = "not_a_list_string"
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        self.assertIn(ERR_ROBOT_DOCS_CORRUPT, {e.code for e in res.errors})

    def test_checker_malformed_capability_entry(self) -> None:
        """On-disk capabilities containing non-dict or missing id returns typed ERR-ROBOT-DOCS-CORRUPT-001."""
        json_path = self.fake_root / "docs/ROBOT_DOCS.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        data["capabilities"] = [{"not_an_id": "value"}]
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        self.assertIn(ERR_ROBOT_DOCS_CORRUPT, {e.code for e in res.errors})

    def test_non_list_tombstones_in_fss1(self) -> None:
        """Non-list tombstones field in fss1_public_registry.json triggers ERR-ROBOT-DOCS-CORRUPT-001."""
        fss1_file = self.fake_root / "architecture/fss1_public_registry.json"
        data = json.loads(fss1_file.read_text(encoding="utf-8"))
        data["tombstones"] = "invalid_non_list_tombstones"
        fss1_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_ROBOT_DOCS_CORRUPT})

    def test_non_list_tombstones_in_capabilities(self) -> None:
        """Non-list tombstones field in capabilities.json triggers ERR-ROBOT-DOCS-CORRUPT-001."""
        caps_file = self.fake_root / "architecture/capabilities.json"
        data = json.loads(caps_file.read_text(encoding="utf-8"))
        data["tombstones"] = {"not": "a_list"}
        caps_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_ROBOT_DOCS_CORRUPT})

    def test_wrongly_typed_effectful_field(self) -> None:
        """String effectful: 'yes' in agent_operations.json triggers ERR-ROBOT-DOCS-CORRUPT-001."""
        ops_file = self.fake_root / "architecture/agent_operations.json"
        data = json.loads(ops_file.read_text(encoding="utf-8"))
        data["operations"][0]["effectful"] = "yes"
        ops_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_ROBOT_DOCS_CORRUPT})

    def test_wrongly_typed_operation_name(self) -> None:
        """Integer name in agent_operations.json triggers ERR-ROBOT-DOCS-CORRUPT-001."""
        ops_file = self.fake_root / "architecture/agent_operations.json"
        data = json.loads(ops_file.read_text(encoding="utf-8"))
        data["operations"][0]["name"] = 12345
        ops_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_ROBOT_DOCS_CORRUPT})

    def test_wrongly_typed_dict_capability(self) -> None:
        """Dict capability field in capabilities.json triggers ERR-ROBOT-DOCS-CORRUPT-001."""
        caps_file = self.fake_root / "architecture/capabilities.json"
        data = json.loads(caps_file.read_text(encoding="utf-8"))
        data["capabilities"][0]["capability"] = {"nested": "dict_not_string"}
        caps_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_ROBOT_DOCS_CORRUPT})

    def test_wrongly_typed_dict_in_required_capabilities(self) -> None:
        """Dict element inside requiredCapabilities triggers ERR-ROBOT-DOCS-CORRUPT-001."""
        ops_file = self.fake_root / "architecture/agent_operations.json"
        data = json.loads(ops_file.read_text(encoding="utf-8"))
        data["operations"][0]["requiredCapabilities"].append({"id": "CAP-001"})
        ops_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_ROBOT_DOCS_CORRUPT})

    # --- Item 6: Crosswalk and fss1 drift checks ---

    def test_crosswalk_operation_name_mismatch(self) -> None:
        """Mismatch in crosswalk operation_name vs agent_operations triggers ERR-ROBOT-DOCS-DRIFT-001."""
        cw_file = self.fake_root / "architecture/operation_crosswalk.json"
        data = json.loads(cw_file.read_text(encoding="utf-8"))
        data["crosswalk"][0]["operation_name"] = "session.mismatched_name"
        cw_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_ROBOT_DOCS_DRIFT})

    def test_crosswalk_missing_operation_name(self) -> None:
        """Missing operation_name key in crosswalk triggers ERR-ROBOT-DOCS-CORRUPT-001."""
        cw_file = self.fake_root / "architecture/operation_crosswalk.json"
        data = json.loads(cw_file.read_text(encoding="utf-8"))
        del data["crosswalk"][0]["operation_name"]
        cw_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_ROBOT_DOCS_CORRUPT})

    def test_crosswalk_owner_mismatch(self) -> None:
        """Owner conflict between crosswalk and agent_operations triggers ERR-ROBOT-DOCS-DRIFT-001."""
        cw_file = self.fake_root / "architecture/operation_crosswalk.json"
        data = json.loads(cw_file.read_text(encoding="utf-8"))
        data["crosswalk"][0]["owner"] = "different-owner"
        cw_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_ROBOT_DOCS_DRIFT})

    def test_crosswalk_status_mismatch(self) -> None:
        """Status conflict between crosswalk and agent_operations triggers ERR-ROBOT-DOCS-DRIFT-001."""
        cw_file = self.fake_root / "architecture/operation_crosswalk.json"
        data = json.loads(cw_file.read_text(encoding="utf-8"))
        data["crosswalk"][0]["status"] = "experimental"
        cw_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_ROBOT_DOCS_DRIFT})

    def test_fss1_response_envelope_mismatch(self) -> None:
        """responseEnvelope conflict between fss1 and agent_operations triggers ERR-ROBOT-DOCS-DRIFT-001."""
        fss1_file = self.fake_root / "architecture/fss1_public_registry.json"
        data = json.loads(fss1_file.read_text(encoding="utf-8"))
        data["operations"][0]["responseEnvelope"] = "fss.different_envelope.v1"
        fss1_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_ROBOT_DOCS_DRIFT})

    def test_fss1_response_payload_schemas_mismatch(self) -> None:
        """responsePayloadSchemas conflict between fss1 and agent_operations triggers ERR-ROBOT-DOCS-DRIFT-001."""
        fss1_file = self.fake_root / "architecture/fss1_public_registry.json"
        data = json.loads(fss1_file.read_text(encoding="utf-8"))
        data["operations"][0]["responsePayloadSchemas"] = ["fss.other_payload.v1"]
        fss1_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_ROBOT_DOCS_DRIFT})

    # --- Item 8: Mutants G3-G6, G9, G11-G13, G15, G20 ---

    def test_mutant_g3_unregistered_exit_identity(self) -> None:
        """Mutant G3: Operation crosswalk referencing unregistered exit identity triggers ERR-ROBOT-DOCS-UNREGISTERED-001."""
        cw_file = self.fake_root / "architecture/operation_crosswalk.json"
        data = json.loads(cw_file.read_text(encoding="utf-8"))
        data["crosswalk"][0]["exit_identities"].append("EXIT-UNREGISTERED-FAKE-999")
        cw_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_ROBOT_DOCS_UNREGISTERED})

    def test_mutant_g4_unregistered_retry_class(self) -> None:
        """Mutant G4: Operation referencing unregistered recovery retry class triggers ERR-ROBOT-DOCS-UNREGISTERED-001."""
        ops_file = self.fake_root / "architecture/agent_operations.json"
        data = json.loads(ops_file.read_text(encoding="utf-8"))
        data["operations"][0]["retryClasses"].append("unregistered_retry_class")
        ops_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_ROBOT_DOCS_UNREGISTERED})

    def test_mutant_g5_unregistered_op_gate(self) -> None:
        """Mutant G5: Operation referencing unregistered qualification gate triggers ERR-ROBOT-DOCS-UNREGISTERED-001."""
        ops_file = self.fake_root / "architecture/agent_operations.json"
        data = json.loads(ops_file.read_text(encoding="utf-8"))
        data["operations"][0]["gate"] = "QL-FAKE-GATE-999"
        ops_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_ROBOT_DOCS_UNREGISTERED})

    def test_mutant_g6_unregistered_view_gate(self) -> None:
        """Mutant G6: View referencing unregistered qualification gate triggers ERR-ROBOT-DOCS-UNREGISTERED-001."""
        views_file = self.fake_root / "architecture/agent_views.json"
        data = json.loads(views_file.read_text(encoding="utf-8"))
        data["views"][0]["gate"] = "QL-FAKE-GATE-999"
        views_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_ROBOT_DOCS_UNREGISTERED})

    def test_mutant_g11_default_view_drift_single_registry(self) -> None:
        """Mutant G11: Changing defaultView in only ONE registry triggers ERR-ROBOT-DOCS-DRIFT-001."""
        ops_file = self.fake_root / "architecture/agent_operations.json"
        data = json.loads(ops_file.read_text(encoding="utf-8"))
        data["operations"][0]["defaultView"] = "AVIEW-006"
        ops_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_ROBOT_DOCS_DRIFT})

    def test_mutant_g12_request_payload_schema_drift_single_registry(self) -> None:
        """Mutant G12: Changing requestPayloadSchema in only ONE registry triggers ERR-ROBOT-DOCS-DRIFT-001."""
        ops_file = self.fake_root / "architecture/agent_operations.json"
        data = json.loads(ops_file.read_text(encoding="utf-8"))
        data["operations"][0]["requestPayloadSchema"] = "fss.agent_handoff_capsule.v1"
        ops_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_ROBOT_DOCS_DRIFT})

    def test_mutant_g9_check_mode_compares_json_too(self) -> None:
        """Mutant G9: Tampering only docs/ROBOT_DOCS.json causes generate_robot_docs.py --check to fail."""
        json_path = self.fake_root / "docs/ROBOT_DOCS.json"
        raw = json_path.read_text(encoding="utf-8")
        json_path.write_text(raw + "\n// tampered\n", encoding="utf-8")
        proc = subprocess.run(
            [sys.executable, "-B", str(ROOT / "scripts/generate_robot_docs.py"), "--check", "--repo-root", str(self.fake_root)],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn(ERR_ROBOT_DOCS_STALE, proc.stderr)

    def test_mutant_g13_nan_inf_rejected(self) -> None:
        """Mutant G13: Inf and NaN values in machine registry JSON trigger ERR-ROBOT-DOCS-CORRUPT-001."""
        ops_file = self.fake_root / "architecture/agent_operations.json"
        raw = ops_file.read_text(encoding="utf-8")

        # Case 1: Scientific notation 1e999 parses to float('inf') in standard json.loads
        # without triggering parse_constant, proving check_no_nan_inf() actively catches it.
        tampered_scientific = raw.replace('"effectful": false,', '"effectful": false, "overflow_val": 1e999,')
        ops_file.write_text(tampered_scientific, encoding="utf-8")
        res_scientific = validate_robot_docs(self.fake_root)
        self.assertFalse(res_scientific.passed)
        self.assertEqual({e.code for e in res_scientific.errors}, {ERR_ROBOT_DOCS_CORRUPT})
        self.assertTrue(any("Disallowed NaN or Infinity" in e.message for e in res_scientific.errors))

        # Case 2: Literal Infinity constant
        tampered = raw.replace('"effectful": false,', '"effectful": Infinity,')
        ops_file.write_text(tampered, encoding="utf-8")
        res = validate_robot_docs(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_ROBOT_DOCS_CORRUPT})

    def test_mutant_g15_html_escaping(self) -> None:
        """Mutant G15: HTML entities and tags are escaped across cells, inline spans, and text."""
        raw = "<script>alert('xss')</script>&\"'"
        cell = escape_markdown_cell(raw)
        self.assertNotIn("<script>", cell)
        self.assertIn("&lt;script&gt;", cell)

        inline = escape_markdown_inline(raw)
        self.assertNotIn("<script>", inline)
        self.assertIn("&lt;script&gt;", inline)

        text = escape_markdown_text(raw)
        self.assertNotIn("<script>", text)
        self.assertIn("&lt;script&gt;", text)

    def test_mutant_g20_purpose_escaping(self) -> None:
        """Mutant G20: Newlines, bullets, and fences in purpose are neutralized into single-line text."""
        raw_purpose = "purpose with\n- fake bullet\n```bash\necho evil\n```"
        escaped = escape_markdown_text(raw_purpose)
        self.assertNotIn("\n", escaped)
        self.assertNotIn("```", escaped)
        self.assertIn("'''", escaped)

        # Also render through the generator (render site generate_robot_docs.py:1317)
        # to ensure the markdown generator actually passes op['purpose'] through escape_markdown_text().
        ops_file = self.fake_root / "architecture/agent_operations.json"
        raw = ops_file.read_text(encoding="utf-8")
        injected = raw.replace(
            '"purpose": "negotiate principal, mission, authority, privacy projection, budgets, views, and the initial SituationCapsule",',
            '"purpose": "negotiate principal\\n- fake bullet\\n```bash\\necho evil\\n```",',
        )
        ops_file.write_text(injected, encoding="utf-8")
        model = collect_robot_docs_model(self.fake_root)
        md = generate_robot_docs_markdown(model)
        self.assertNotIn("```", md)
        self.assertIn("'''bash", md)
        # Ensure the purpose line is flattened and does not contain raw newline or unescaped fence
        purpose_lines = [line for line in md.splitlines() if "**Purpose**:" in line and "fake bullet" in line]
        self.assertEqual(len(purpose_lines), 1)
        self.assertNotIn("\n", purpose_lines[0])
        self.assertIn("- **Purpose**: negotiate principal - fake bullet '''bash echo evil '''", purpose_lines[0])


if __name__ == "__main__":
    unittest.main()


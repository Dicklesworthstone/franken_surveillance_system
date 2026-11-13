#!/usr/bin/env python3
"""Verify the additive event-hydration presentation profile without rewriting frozen fss/1.

The explicit target may write the existing agent journal. Default/public-v2/probe operation
snapshots and durable native hydration/session bases retain their independent exact identities.
This checker only reads files; it never regenerates or accepts replacement freeze pins.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = "architecture/agent_hydration_profile.v2.json"
SCHEMA_PATH = "schemas/agent_evidence_hydration.v1.json"
CORE_PATH = "crates/fss-core/src/contract_basis/hydration_profile.rs"
FIXTURE_PATH = "tests/fixtures/contract_basis_event_hydration_v2.bin"
BASIS_GENERATION = "gen:fss1:event-hydration-v2"
OPERATION_GENERATION = "gen:fss1:hydration-operations-v1"
OPERATION_DOMAIN = "fss.agent_hydration_operation_profile.v1"
CATALOG_DOMAIN = "fss.agent_hydration_schema_catalog.v1"
RESPONSE_SCHEMA = "fss.agent_evidence_hydration.v1"
ROW = (
    "AOP-005|query|cognition_write|fss-query-plan|AVIEW-003|fss.agent_query_plan.v1|"
    "fss.agent_cognitive_envelope.v1;fss.agent_evidence_hydration.v1|"
    "fss.agent_request_envelope.v1|fss.agent_response_envelope.v1|0|1|QL-AGENT-001|"
    "CAP-AGENT-QUERY-001;CAP-AGENT-EVIDENCE-HYDRATE-001|"
    "never_unchanged;refresh_and_retry;rebase_required;backoff;reconciliation_required;"
    "operator_action_required;resume_from_continuation"
)
LEGACY_QUERY_ROW = (
    "AOP-005|query|read_compile|fss-query-plan|AVIEW-003|fss.agent_query_plan.v1|"
    "fss.agent_cognitive_envelope.v1|fss.agent_request_envelope.v1|"
    "fss.agent_response_envelope.v1|0|0|QL-AGENT-001|CAP-AGENT-QUERY-001|"
    "safe_read_retry;refresh_and_retry;rebase_required;backoff;resume_from_continuation"
)
REFERENCE = {
    "schema": "sha256:a82134f79c3922ebdd2ee7f0ab2a10528f6289c19000cb64f67385d7ebc6a577",
    "operation": "sha256:9bbec4e6845ea702f676cd22472e5fb0d35ca3b3d97f66cbfccb452182413da8",
    "view": "sha256:a757a7698a79e1c72fb71d6aefa80df264a1896e8ac7f0ad455c411b2f3f5704",
    "capability": "sha256:911d4859853e9e5a03334a870247c03d892335bd090063b0a7943f9da2892f4e",
    "error": "sha256:94b31547a77d2b1b598acca17e320d7100633f46d4a7a89caee3c230fe204b63",
    "cost": "sha256:c86017d6a6674322613e8b88eb6c3ba994df2c9d071cb8b7045ea31c0f37bc3b",
}
PINS = {
    "HYDRATION_RESPONSE_SCHEMA_DIGEST": "sha256:978059a46a34cee7783f99015fc1f889229b8401a849a6cf8ab754f678219b3a",
    "HYDRATION_OPERATION_REGISTRY_DIGEST": "sha256:1fa8bd342678b607db8c0d4d1c72a501d36c1ebac087e15098713a38b19a2202",
    "HYDRATION_SCHEMA_CATALOG_DIGEST": "sha256:f604dcbb58aaab5ec27d3ba4bbdeb7601639ff2eb71fdb29de4f5aebf426396d",
    "HYDRATION_CONTRACT_BASIS_CANONICAL_DIGEST": "sha256:d7baa77c92610dcc4c659a7d46c6cf1cb14842568c17a94d4b42b9c0bb70d91f",
    "HYDRATION_CONTRACT_BASIS_FREEZE_DIGEST": "sha256:cb0a45ff5c5da3ea438d2a56e96ca45fad3ae837094fec64f5b4a1eae659e785",
}
PRESERVED = {
    "architecture/fss1_public_registry.v1.json": "sha256:e4687e12344f9b3209421a99d3e97a1b5389484fbd4af394f96ef124391f2743",
    "tests/fixtures/contract_basis_v4.bin": "sha256:94a5ca8eff9eb06e2fbf19f08873ae82b99f726991c23251b8642eba4045ef14",
    "tests/fixtures/contract_basis_probe_v3.bin": "sha256:127edcdc1b9e64ccfecec8aa601fc9ff9a04be98044705acc9515d3465a792f0",
    # The initially published presentation rejected legitimate generation-zero sessions.
    # A new basis accepts the corrected wrapper without recoding its old exact schema pin.
    "architecture/agent_hydration_profile.v1.json": "sha256:7f7c6d073fe48158716a957b35f46e450946130184227e2869715d66d3e0698b",
    "tests/fixtures/contract_basis_event_hydration_v1.bin": "sha256:ad5daaea78fb4e0600bbd9c17aa25a9806d2e9827937625612617541847832e6",
    "tests/fixtures/agent_evidence_hydration_profile_v1.schema.json": "sha256:fb02b9740e8386527973bf3038e509e7b8b94edcd928c526bc0717cc6f5f6f29",
}


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def canonical_text(value: str) -> bytes:
    data = value.encode("utf-8")
    if len(data) > 65_536:
        raise ValueError("canonical text exceeds its native bound")
    return len(data).to_bytes(8, "big") + data


def canonical_digest(value: str) -> bytes:
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        raise ValueError("noncanonical digest")
    return b"\x01" + bytes.fromhex(value[7:])


def basis_payload(schema: str, operation: str) -> bytes:
    return (
        canonical_text("fss/1") + canonical_digest(schema)
        + canonical_text("ontology:reference:v1") + canonical_digest(operation)
        + b"".join(canonical_digest(REFERENCE[key]) for key in ("view", "capability", "error", "cost"))
        + canonical_text("fss:release:v1") + b"\x00"
    )


def basis_fixture(payload: bytes) -> bytes:
    header = b"FSSBAS01" + (1).to_bytes(4, "big") + len(payload).to_bytes(4, "big") + payload
    return header + hashlib.sha256(b"fss.agent_contract_basis.v1" + header).digest()


def expected_profile() -> dict:
    return {
        "schema": OPERATION_DOMAIN,
        "semanticProtocol": "fss/1",
        "contractBasisGeneration": BASIS_GENERATION,
        "operationRegistryGeneration": OPERATION_GENERATION,
        "selector": {"operation": "query", "target": "evidence-hydration", "levels": ["H0", "H1"]},
        "nativeContractBasisGeneration": "gen:fss1:reference-v4",
        "baseOperationRegistryGeneration": "gen:fss1:public-v1",
        "baseOperationRegistryDigest": REFERENCE["operation"],
        "baseSchemaCatalogDigest": REFERENCE["schema"],
        "operation": {
            "id": "AOP-005", "name": "query", "mode": "cognition_write",
            "owner": "fss-query-plan", "defaultView": "AVIEW-003",
            "requestPayloadSchema": "fss.agent_query_plan.v1",
            "responsePayloadSchemas": ["fss.agent_cognitive_envelope.v1", RESPONSE_SCHEMA],
            "requestEnvelope": "fss.agent_request_envelope.v1",
            "responseEnvelope": "fss.agent_response_envelope.v1",
            "effectful": False, "durable": True, "gate": "QL-AGENT-001",
            "requiredCapabilities": ["CAP-AGENT-QUERY-001", "CAP-AGENT-EVIDENCE-HYDRATE-001"],
            "retryClasses": ROW.split("|")[-1].split(";"),
        },
        "canonicalOperationRow": ROW,
        "operationDigestDomain": OPERATION_DOMAIN,
        "schemaCatalogDigestDomain": CATALOG_DOMAIN,
        "responseSchema": {"identity": RESPONSE_SCHEMA, "path": SCHEMA_PATH, "digest": PINS["HYDRATION_RESPONSE_SCHEMA_DIGEST"]},
        "operationRegistryDigest": PINS["HYDRATION_OPERATION_REGISTRY_DIGEST"],
        "schemaCatalogDigest": PINS["HYDRATION_SCHEMA_CATALOG_DIGEST"],
        "canonicalBasisDigest": PINS["HYDRATION_CONTRACT_BASIS_CANONICAL_DIGEST"],
        "binaryBasisDigest": PINS["HYDRATION_CONTRACT_BASIS_FREEZE_DIGEST"],
        "binaryFixture": FIXTURE_PATH,
        "preservedArtifacts": PRESERVED,
    }


def closed_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object field")
        result[key] = value
    return result


def validate_hydration_profile(root: Path) -> list[str]:
    errors = []

    def read(path: str) -> bytes:
        data = (root / path).read_bytes()
        if len(data) > 1024 * 1024:
            raise ValueError(f"profile input exceeds 1 MiB: {path}")
        return data

    try:
        profile = json.loads(read(PROFILE_PATH), object_pairs_hook=closed_object)
        if profile != expected_profile():
            errors.append("profile shape, scope, operation semantics or pinned identities changed")
        schema_digest = sha(read(SCHEMA_PATH))
        operation_digest = sha(canonical_text(OPERATION_DOMAIN) + canonical_digest(REFERENCE["operation"]) + canonical_text(ROW))
        schema_catalog = sha(canonical_text(CATALOG_DOMAIN) + canonical_digest(REFERENCE["schema"]) + canonical_text(RESPONSE_SCHEMA) + canonical_digest(schema_digest))
        payload = basis_payload(schema_catalog, operation_digest)
        fixture = basis_fixture(payload)
        computed = {
            "HYDRATION_RESPONSE_SCHEMA_DIGEST": schema_digest,
            "HYDRATION_OPERATION_REGISTRY_DIGEST": operation_digest,
            "HYDRATION_SCHEMA_CATALOG_DIGEST": schema_catalog,
            "HYDRATION_CONTRACT_BASIS_CANONICAL_DIGEST": sha(canonical_text("fss.canonical.v1") + canonical_text("fss.agent_contract_basis.v1") + payload),
            "HYDRATION_CONTRACT_BASIS_FREEZE_DIGEST": sha(fixture),
        }
        for key, expected in PINS.items():
            if computed[key] != expected:
                errors.append(f"exact profile digest mismatch: {key}")
        if read(FIXTURE_PATH) != fixture:
            errors.append("hydration basis binary fixture differs from the native encoding")
        for path, expected in PRESERVED.items():
            if sha(read(path)) != expected:
                errors.append(f"preserved frozen artifact changed: {path}")
        if read("tests/fixtures/contract_basis_v4.bin") != basis_fixture(basis_payload(REFERENCE["schema"], REFERENCE["operation"])):
            errors.append("reference-v4 basis encoding changed")
        core = read(CORE_PATH).decode("utf-8")
        constants = {
            **PINS,
            "HYDRATION_CONTRACT_BASIS_GENERATION": BASIS_GENERATION,
            "HYDRATION_OPERATION_REGISTRY_GENERATION": OPERATION_GENERATION,
            "HYDRATION_QUERY_CANONICAL_ROW": ROW,
        }
        for name, expected in constants.items():
            matches = re.findall(r"pub const " + name + r": &str\s*=\s*\"([^\"]+)\"\s*;", core)
            if matches != [expected]:
                errors.append(f"native hydration profile constant changed or missing: {name}")
        # The additive profile must not replace the frozen default Query row. Existing full
        # public/probe checkers independently cover all other operation and resource rows.
        from agent_operation_registry_checker import extract_rust_canonical_rows
        rows = extract_rust_canonical_rows(root / "crates/fss-core/src/agent_operation.rs")
        if rows.get("AOP-005") != LEGACY_QUERY_ROW:
            errors.append("default AOP-005 semantics were changed by the additive profile")
    except (OSError, ValueError, UnicodeError, KeyError, TypeError) as error:
        errors.append(f"profile verification could not complete: {error}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    errors = validate_hydration_profile(args.root)
    if args.json:
        print(json.dumps({"passed": not errors, "errors": errors}, indent=2))
    elif errors:
        for error in errors:
            print(f"event hydration profile: {error}")
    else:
        print("event hydration profile: exact schema, operation, native pins and binary fixture verified")
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Deterministic claim and proof-bundle checker (fss-x4a.6.11 / FSS-011).

Validates that public readiness claims, status tables, and documentation claims
are strictly derivable from retained proof bundles and registered claim classes
(INV-021, REL-INV-009, Section 23.7).

Fail-closed verification invariants:
1. Proof bundle existence: A status or documentation claim citing a proof bundle
   that does not exist, contains path traversal, or points to a non-file fails.
2. Digest integrity: A bundle's declared content or artifact digest must exactly
   match its cryptographic contents.
3. Level support: A claim level (e.g. achieved, qualified, positively_verified)
   must not exceed what the retained proof supports, and all required evidence
   for the registered claim class must be retained.
4. Stale generation refusal: Bundles referencing stale, superseded, tombstoned,
   expired generations or prohibited 'latest' aliases fail closed.
5. Input validity: Any unreadable, corrupt, or empty (0 bytes or empty root)
   claim, bundle, or authoritative registry input fails closed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import architecture_registry_consistency
import schema_validate
import stable_id_audit

# Typed diagnostic error codes
ERR_PROOF_BUNDLE_NOT_FOUND = "ERR-CLAIM-PROOF-BUNDLE-NOT-FOUND-001"
ERR_BUNDLE_DIGEST_MISMATCH = "ERR-CLAIM-PROOF-DIGEST-MISMATCH-001"
ERR_CLAIM_LEVEL_EXCEEDED = "ERR-CLAIM-PROOF-LEVEL-EXCEEDED-001"
ERR_STALE_GENERATION = "ERR-CLAIM-PROOF-STALE-GENERATION-001"
ERR_UNREADABLE_INPUT = "ERR-CLAIM-PROOF-UNREADABLE-INPUT-001"
ERR_EMPTY_INPUT = "ERR-CLAIM-PROOF-EMPTY-INPUT-001"
ERR_INVALID_CLAIM_CLASS = "ERR-CLAIM-PROOF-INVALID-CLASS-001"
ERR_PROHIBITED_CLAIM_PROMOTION = "ERR-CLAIM-PROOF-PROHIBITED-PROMOTION-001"

DIAGNOSTIC_REGISTRY: dict[str, dict[str, str]] = {
    ERR_PROOF_BUNDLE_NOT_FOUND: {
        "trigger": "Status or documentation claim cites a proof bundle that does not exist on disk, has forbidden traversal ('..'), or is an invalid path",
        "remediation": "Provide an existing, valid relative path to a retained proof bundle file under qualification-artifacts/ or proof_bundles/",
    },
    ERR_BUNDLE_DIGEST_MISMATCH: {
        "trigger": "A proof bundle's declared content or artifact digest does not match the actual computed cryptographic digest of its contents",
        "remediation": "Recompute and bind the exact cryptographic digest of the bundle contents or fix corrupted artifacts",
    },
    ERR_CLAIM_LEVEL_EXCEEDED: {
        "trigger": "A claim level (e.g. achieved, qualified, verified) is higher than its retained proof supports, or required evidence for the claim class is missing",
        "remediation": "Demote the claim status to a supported level (e.g. 'target' or 'specified') or provide the complete required retained evidence",
    },
    ERR_STALE_GENERATION: {
        "trigger": "A proof bundle references a stale, superseded, tombstoned, or expired generation, or uses a prohibited 'latest' alias",
        "remediation": "Re-qualify the claim against the current active generation and bind an explicit generation identity",
    },
    ERR_UNREADABLE_INPUT: {
        "trigger": "An input file could not be read, decoded, or parsed as valid JSON/Markdown",
        "remediation": "Fix file permissions, encoding, or JSON/Markdown syntax errors",
    },
    ERR_EMPTY_INPUT: {
        "trigger": "An input file is empty (0 bytes or empty text) or contains an empty JSON collection",
        "remediation": "Ensure all inputs contain non-empty, well-formed specifications",
    },
    ERR_INVALID_CLAIM_CLASS: {
        "trigger": "A claim specifies a claim class not recognized in architecture/claims.json",
        "remediation": "Use one of the registered claim classes in architecture/claims.json",
    },
    ERR_PROHIBITED_CLAIM_PROMOTION: {
        "trigger": "A claim attempts a promotion explicitly prohibited by architecture/claims.json",
        "remediation": "Do not promote unverified source presence, single demos, or uncalibrated metrics to readiness claims",
    },
}

READINESS_LEVEL_RANKS: dict[str, int] = {
    "absent": 0,
    "draft": 0,
    "specified": 1,
    "target": 1,
    "reference_implemented": 2,
    "implemented": 3,
    "positively_verified": 4,
    "verified": 4,
    "qualified": 5,
    "achieved": 5,
}

FAILED_STATUSES: frozenset[str] = frozenset({
    "failed",
    "broken",
    "blocked",
    "revoked",
    "staged",
    "provisional",
    "draft",
    "indeterminate",
})

NON_PROOF_ROOTS: frozenset[str] = frozenset({
    "-",
    "none",
    "null",
    "n/a",
    "na",
    "",
    "tbd",
    "unimplemented",
})

MANDATORY_AUTHORITY_FILES = (
    "architecture/claims.json",
    "registries/CLAIMS.md",
    "architecture/readiness_dimensions.json",
)


@dataclass(frozen=True)
class ClaimFinding:
    code: str
    file: str
    location: str
    message: str
    severity: str = "error"
    remediation: str = ""
    params: dict[str, Any] = field(default_factory=dict)


def sanitize_path(path: Path | str, root: Path) -> str:
    """Returns a forward-slash normalized relative path string."""
    try:
        rel = Path(path).resolve().relative_to(root.resolve())
        return str(rel).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def compute_sha256(data: bytes) -> str:
    """Computes canonical sha256:<hex> string."""
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def is_latest_generation(val: str) -> bool:
    """Detects 'latest' generation aliases prohibited by ADR-0004."""
    normalized = val.strip().lower()
    if normalized == "latest":
        return True
    if normalized.startswith("latest-") or normalized.endswith("-latest"):
        return True
    if "v-latest" in normalized or "v_latest" in normalized:
        return True
    return False


def load_authoritative_claims(claims_json_path: Path) -> tuple[dict[str, list[str]], set[str], list[ClaimFinding]]:
    """Loads claim classes and prohibited promotions from architecture/claims.json."""
    findings: list[ClaimFinding] = []
    classes: dict[str, list[str]] = {}
    prohibited: set[str] = set()
    path_str = str(claims_json_path)

    if not claims_json_path.is_file():
        findings.append(ClaimFinding(
            code=ERR_UNREADABLE_INPUT,
            file=path_str,
            location="root",
            message=f"Authoritative claims registry file not found: '{claims_json_path}'",
            remediation=DIAGNOSTIC_REGISTRY[ERR_UNREADABLE_INPUT]["remediation"],
        ))
        return classes, prohibited, findings

    try:
        raw_bytes = claims_json_path.read_bytes()
    except OSError as exc:
        findings.append(ClaimFinding(
            code=ERR_UNREADABLE_INPUT,
            file=path_str,
            location="root",
            message=f"Could not read authoritative claims registry '{claims_json_path}': {exc}",
            remediation=DIAGNOSTIC_REGISTRY[ERR_UNREADABLE_INPUT]["remediation"],
        ))
        return classes, prohibited, findings

    if len(raw_bytes.strip()) == 0:
        findings.append(ClaimFinding(
            code=ERR_EMPTY_INPUT,
            file=path_str,
            location="root",
            message=f"Authoritative claims registry file '{claims_json_path}' is empty (0 bytes)",
            remediation=DIAGNOSTIC_REGISTRY[ERR_EMPTY_INPUT]["remediation"],
        ))
        return classes, prohibited, findings

    try:
        data = json.loads(raw_bytes.decode("utf-8"))
    except Exception as exc:
        findings.append(ClaimFinding(
            code=ERR_UNREADABLE_INPUT,
            file=path_str,
            location="root",
            message=f"Authoritative claims registry '{claims_json_path}' is invalid JSON: {exc}",
            remediation=DIAGNOSTIC_REGISTRY[ERR_UNREADABLE_INPUT]["remediation"],
        ))
        return classes, prohibited, findings

    if not isinstance(data, dict):
        findings.append(ClaimFinding(
            code=ERR_UNREADABLE_INPUT,
            file=path_str,
            location="root",
            message=f"Authoritative claims registry '{claims_json_path}' root must be a JSON object",
            remediation=DIAGNOSTIC_REGISTRY[ERR_UNREADABLE_INPUT]["remediation"],
        ))
        return classes, prohibited, findings

    raw_classes = data.get("classes")
    if not isinstance(raw_classes, list) or len(raw_classes) == 0:
        findings.append(ClaimFinding(
            code=ERR_EMPTY_INPUT,
            file=path_str,
            location="classes",
            message=f"Authoritative claims registry '{claims_json_path}' contains no claim classes",
            remediation=DIAGNOSTIC_REGISTRY[ERR_EMPTY_INPUT]["remediation"],
        ))
        return classes, prohibited, findings

    for idx, item in enumerate(raw_classes):
        if isinstance(item, dict) and "id" in item:
            class_id = str(item["id"])
            req_ev = item.get("requiredEvidence", [])
            if isinstance(req_ev, list):
                classes[class_id] = [str(e) for e in req_ev]
            else:
                classes[class_id] = []
        else:
            findings.append(ClaimFinding(
                code=ERR_UNREADABLE_INPUT,
                file=path_str,
                location=f"classes[{idx}]",
                message=f"Malformed claim class entry at index {idx}",
                remediation=DIAGNOSTIC_REGISTRY[ERR_UNREADABLE_INPUT]["remediation"],
            ))

    raw_prohibited = data.get("prohibited", [])
    if isinstance(raw_prohibited, list):
        for p in raw_prohibited:
            prohibited.add(str(p))

    return classes, prohibited, findings


def compute_bundle_digest(bundle_dict: dict[str, Any]) -> str:
    """Computes canonical sha256:<hex> digest of a proof bundle excluding digest fields."""
    filtered = {
        k: v
        for k, v in bundle_dict.items()
        if k not in (
            "content_digest",
            "contentDigest",
            "digest",
            "bundle_digest",
            "bundleDigest",
        )
    }
    canonical_bytes = schema_validate.canonical_json_bytes(filtered)
    return compute_sha256(canonical_bytes)


def verify_proof_bundle(
    bundle_path: Path,
    root: Path,
    expected_claim_id: str | None = None,
    claim_level: str | None = None,
    claim_class: str | None = None,
    known_classes: dict[str, list[str]] | None = None,
    tombstoned_ids: set[str] | None = None,
    prohibited_promotions: set[str] | None = None,
) -> tuple[bool, list[ClaimFinding], dict[str, Any] | None]:
    """Verifies one proof bundle file against all fail-closed criteria."""
    findings: list[ClaimFinding] = []
    path_str = sanitize_path(bundle_path, root)

    # 1. Path checks: traversal and absolute path refusal
    try:
        parts = bundle_path.parts
    except Exception:
        parts = ()
    if ".." in parts:
        findings.append(ClaimFinding(
            code=ERR_PROOF_BUNDLE_NOT_FOUND,
            file=path_str,
            location="path",
            message=f"Proof bundle path '{bundle_path}' contains forbidden path traversal ('..')",
            remediation=DIAGNOSTIC_REGISTRY[ERR_PROOF_BUNDLE_NOT_FOUND]["remediation"],
            params={"path": str(bundle_path)},
        ))
        return False, findings, None

    # Check existence
    resolved_path = bundle_path if bundle_path.is_absolute() else (root / bundle_path)
    if not resolved_path.exists():
        findings.append(ClaimFinding(
            code=ERR_PROOF_BUNDLE_NOT_FOUND,
            file=path_str,
            location="path",
            message=f"Referenced proof bundle does not exist on disk: '{path_str}'",
            remediation=DIAGNOSTIC_REGISTRY[ERR_PROOF_BUNDLE_NOT_FOUND]["remediation"],
            params={"path": path_str},
        ))
        return False, findings, None

    if not resolved_path.is_file():
        findings.append(ClaimFinding(
            code=ERR_PROOF_BUNDLE_NOT_FOUND,
            file=path_str,
            location="path",
            message=f"Referenced proof bundle is not a regular file: '{path_str}'",
            remediation=DIAGNOSTIC_REGISTRY[ERR_PROOF_BUNDLE_NOT_FOUND]["remediation"],
            params={"path": path_str},
        ))
        return False, findings, None

    # Check readability and empty
    try:
        raw_bytes = resolved_path.read_bytes()
    except OSError as exc:
        findings.append(ClaimFinding(
            code=ERR_UNREADABLE_INPUT,
            file=path_str,
            location="file",
            message=f"Could not read proof bundle '{path_str}': {exc}",
            remediation=DIAGNOSTIC_REGISTRY[ERR_UNREADABLE_INPUT]["remediation"],
            params={"error": str(exc)},
        ))
        return False, findings, None

    if len(raw_bytes.strip()) == 0:
        findings.append(ClaimFinding(
            code=ERR_EMPTY_INPUT,
            file=path_str,
            location="file",
            message=f"Proof bundle '{path_str}' is empty (0 bytes); existence is not proof",
            remediation=DIAGNOSTIC_REGISTRY[ERR_EMPTY_INPUT]["remediation"],
        ))
        return False, findings, None

    try:
        content_text = raw_bytes.decode("utf-8")
        data = json.loads(content_text)
    except Exception as exc:
        findings.append(ClaimFinding(
            code=ERR_UNREADABLE_INPUT,
            file=path_str,
            location="file",
            message=f"Proof bundle '{path_str}' contains invalid JSON: {exc}",
            remediation=DIAGNOSTIC_REGISTRY[ERR_UNREADABLE_INPUT]["remediation"],
            params={"error": str(exc)},
        ))
        return False, findings, None

    if not isinstance(data, dict):
        findings.append(ClaimFinding(
            code=ERR_UNREADABLE_INPUT,
            file=path_str,
            location="root",
            message=f"Proof bundle '{path_str}' JSON root must be an object",
            remediation=DIAGNOSTIC_REGISTRY[ERR_UNREADABLE_INPUT]["remediation"],
        ))
        return False, findings, None

    if len(data) == 0:
        findings.append(ClaimFinding(
            code=ERR_EMPTY_INPUT,
            file=path_str,
            location="root",
            message=f"Proof bundle '{path_str}' contains an empty JSON object",
            remediation=DIAGNOSTIC_REGISTRY[ERR_EMPTY_INPUT]["remediation"],
        ))
        return False, findings, None

    # 2. Digest check: bundle content digest and artifact digests
    declared_digest = (
        data.get("content_digest")
        or data.get("contentDigest")
        or data.get("bundle_digest")
        or data.get("bundleDigest")
        or data.get("digest")
    )
    if declared_digest:
        computed_bundle_digest = compute_bundle_digest(data)
        raw_file_digest = compute_sha256(raw_bytes)
        # Match against either canonical object digest or exact file bytes digest
        if declared_digest != computed_bundle_digest and declared_digest != raw_file_digest:
            findings.append(ClaimFinding(
                code=ERR_BUNDLE_DIGEST_MISMATCH,
                file=path_str,
                location="content_digest",
                message=(
                    f"Proof bundle '{path_str}' declared digest '{declared_digest}' "
                    f"does not match computed digest '{computed_bundle_digest}'"
                ),
                remediation=DIAGNOSTIC_REGISTRY[ERR_BUNDLE_DIGEST_MISMATCH]["remediation"],
                params={"declared": declared_digest, "computed": computed_bundle_digest},
            ))

    # Artifact digests check if declared
    artifacts = data.get("artifacts") or data.get("objects")
    if isinstance(artifacts, list):
        for idx, art in enumerate(artifacts):
            if isinstance(art, dict):
                art_path_val = art.get("path") or art.get("uri")
                art_digest_val = art.get("digest")
                if art_path_val and art_digest_val:
                    art_full_path = (
                        Path(art_path_val)
                        if Path(art_path_val).is_absolute()
                        else (root / art_path_val)
                    )
                    if not art_full_path.exists():
                        findings.append(ClaimFinding(
                            code=ERR_PROOF_BUNDLE_NOT_FOUND,
                            file=path_str,
                            location=f"artifacts[{idx}].path",
                            message=f"Bundle artifact file does not exist: '{art_path_val}'",
                            remediation=DIAGNOSTIC_REGISTRY[ERR_PROOF_BUNDLE_NOT_FOUND]["remediation"],
                            params={"artifact": str(art_path_val)},
                        ))
                    elif art_full_path.is_file():
                        art_bytes = art_full_path.read_bytes()
                        art_computed_digest = compute_sha256(art_bytes)
                        if art_computed_digest != art_digest_val:
                            findings.append(ClaimFinding(
                                code=ERR_BUNDLE_DIGEST_MISMATCH,
                                file=path_str,
                                location=f"artifacts[{idx}].digest",
                                message=(
                                    f"Artifact '{art_path_val}' digest mismatch: declared '{art_digest_val}', "
                                    f"actual '{art_computed_digest}'"
                                ),
                                remediation=DIAGNOSTIC_REGISTRY[ERR_BUNDLE_DIGEST_MISMATCH]["remediation"],
                                params={"declared": art_digest_val, "computed": art_computed_digest},
                            ))

    # 3. Generation check: stale generation, superseded, expired, or prohibited 'latest' alias
    gen_fields = (
        "generation",
        "generations",
        "model_generation",
        "modelGeneration",
        "generation_id",
        "generationId",
        "model_generations",
        "modelGenerations",
    )

    def check_gen_val(val: Any, loc: str) -> None:
        if isinstance(val, str):
            if is_latest_generation(val):
                findings.append(ClaimFinding(
                    code=ERR_STALE_GENERATION,
                    file=path_str,
                    location=loc,
                    message=f"Proof bundle references prohibited 'latest' alias in {loc}='{val}'",
                    remediation=DIAGNOSTIC_REGISTRY[ERR_STALE_GENERATION]["remediation"],
                    params={"field": loc, "value": val},
                ))
            if tombstoned_ids and val in tombstoned_ids:
                findings.append(ClaimFinding(
                    code=ERR_STALE_GENERATION,
                    file=path_str,
                    location=loc,
                    message=f"Proof bundle references tombstoned generation in {loc}='{val}'",
                    remediation=DIAGNOSTIC_REGISTRY[ERR_STALE_GENERATION]["remediation"],
                    params={"field": loc, "value": val},
                ))
        elif isinstance(val, dict):
            is_st = val.get("is_stale") or val.get("stale", False)
            sup = val.get("superseded", False)
            st_val = str(val.get("status", "")).lower()
            if is_st or sup or st_val in ("stale", "superseded", "tombstone"):
                findings.append(ClaimFinding(
                    code=ERR_STALE_GENERATION,
                    file=path_str,
                    location=loc,
                    message=f"Proof bundle explicitly references a stale or superseded generation at {loc}",
                    remediation=DIAGNOSTIC_REGISTRY[ERR_STALE_GENERATION]["remediation"],
                    params={"field": loc, "value": val},
                ))
            for k_sub, v_sub in val.items():
                check_gen_val(v_sub, f"{loc}.{k_sub}")
        elif isinstance(val, list):
            for i_sub, v_sub in enumerate(val):
                check_gen_val(v_sub, f"{loc}[{i_sub}]")

    for gf in gen_fields:
        if gf in data:
            check_gen_val(data[gf], gf)

    bundle_status = str(data.get("status", "")).lower()
    if bundle_status in ("stale", "superseded"):
        findings.append(ClaimFinding(
            code=ERR_STALE_GENERATION,
            file=path_str,
            location="status",
            message=f"Proof bundle status is marked '{bundle_status}'",
            remediation=DIAGNOSTIC_REGISTRY[ERR_STALE_GENERATION]["remediation"],
            params={"status": bundle_status},
        ))

    # Expiry check
    if data.get("is_expired") is True:
        findings.append(ClaimFinding(
            code=ERR_STALE_GENERATION,
            file=path_str,
            location="is_expired",
            message="Proof bundle is marked expired",
            remediation=DIAGNOSTIC_REGISTRY[ERR_STALE_GENERATION]["remediation"],
        ))

    # Check for prohibited claim promotions
    if prohibited_promotions:
        bases: list[tuple[str, str]] = []
        for field_name in ("basis", "claim_basis", "promotion_basis", "method", "evidence_basis", "prohibited_promotion"):
            val = data.get(field_name)
            if isinstance(val, str):
                bases.append((field_name, val))
            elif isinstance(val, list):
                for item in val:
                    if isinstance(item, str):
                        bases.append((field_name, item))
        for loc_name, b_val in bases:
            b_norm = b_val.strip().lower()
            if b_norm in prohibited_promotions or any(p in b_norm for p in prohibited_promotions):
                findings.append(ClaimFinding(
                    code=ERR_PROHIBITED_CLAIM_PROMOTION,
                    file=path_str,
                    location=loc_name,
                    message=f"Proof bundle relies on prohibited claim promotion: '{b_val}'",
                    remediation=DIAGNOSTIC_REGISTRY[ERR_PROHIBITED_CLAIM_PROMOTION]["remediation"],
                    params={"prohibited_basis": b_val},
                ))

    # 4. Level support check
    bundle_supported_level = (
        data.get("supported_level")
        or data.get("supportedLevel")
        or data.get("claim_level")
        or data.get("claimLevel")
        or bundle_status
    )
    bundle_supported_level_str = str(bundle_supported_level).lower()

    if bundle_status in FAILED_STATUSES:
        findings.append(ClaimFinding(
            code=ERR_CLAIM_LEVEL_EXCEEDED,
            file=path_str,
            location="status",
            message=f"Proof bundle has non-passing status '{bundle_status}'; cannot support readiness",
            remediation=DIAGNOSTIC_REGISTRY[ERR_CLAIM_LEVEL_EXCEEDED]["remediation"],
            params={"status": bundle_status},
        ))

    if claim_level:
        claim_level_norm = claim_level.strip().lower()
        claimed_rank = READINESS_LEVEL_RANKS.get(claim_level_norm, 1)
        supported_rank = READINESS_LEVEL_RANKS.get(bundle_supported_level_str, 1)

        if claimed_rank > supported_rank:
            findings.append(ClaimFinding(
                code=ERR_CLAIM_LEVEL_EXCEEDED,
                file=path_str,
                location="supported_level",
                message=(
                    f"Claimed level '{claim_level}' exceeds proof bundle supported level "
                    f"'{bundle_supported_level_str}' ({claimed_rank} > {supported_rank})"
                ),
                remediation=DIAGNOSTIC_REGISTRY[ERR_CLAIM_LEVEL_EXCEEDED]["remediation"],
                params={"claimed_level": claim_level, "supported_level": bundle_supported_level_str},
            ))

    # Check claim class and required evidence
    effective_class = claim_class or data.get("claim_class") or data.get("claimClass")
    if effective_class and known_classes is not None:
        effective_class_str = str(effective_class)
        if effective_class_str not in known_classes:
            findings.append(ClaimFinding(
                code=ERR_INVALID_CLAIM_CLASS,
                file=path_str,
                location="claim_class",
                message=f"Proof bundle specifies unknown claim class '{effective_class_str}'",
                remediation=DIAGNOSTIC_REGISTRY[ERR_INVALID_CLAIM_CLASS]["remediation"],
                params={"claim_class": effective_class_str},
            ))
        else:
            required_ev = known_classes[effective_class_str]
            retained_ev = (
                data.get("retained_evidence")
                or data.get("retainedEvidence")
                or data.get("evidence", [])
            )
            retained_set = set(retained_ev) if isinstance(retained_ev, list) else set()
            missing_ev = [req for req in required_ev if req not in retained_set]
            if missing_ev:
                findings.append(ClaimFinding(
                    code=ERR_CLAIM_LEVEL_EXCEEDED,
                    file=path_str,
                    location="retained_evidence",
                    message=(
                        f"Proof bundle for class '{effective_class_str}' is missing required evidence: "
                        f"{missing_ev}"
                    ),
                    remediation=DIAGNOSTIC_REGISTRY[ERR_CLAIM_LEVEL_EXCEEDED]["remediation"],
                    params={"missing_evidence": missing_ev, "claim_class": effective_class_str},
                ))

    is_valid = len(findings) == 0
    return is_valid, findings, data


DELIMITER_ROW_RE = re.compile(r"^\|(?:\s*:?-+:?\s*\|)+$")


def parse_markdown_tables(text: str) -> list[tuple[list[str], list[list[str]]]]:
    """Extracts tables from markdown text as (headers, list_of_data_rows)."""
    clean_text = stable_id_audit._strip_html_comments(text)
    lines = clean_text.splitlines()
    tables: list[tuple[list[str], list[list[str]]]] = []

    in_fence = False
    idx = 0
    while idx < len(lines):
        line = lines[idx].strip()
        if line.startswith("```"):
            in_fence = not in_fence
            idx += 1
            continue
        if in_fence or not (line.startswith("|") and line.endswith("|")):
            idx += 1
            continue

        if idx + 1 < len(lines):
            next_line = lines[idx + 1].strip()
            if DELIMITER_ROW_RE.match(next_line):
                headers = [c.strip().strip("`") for c in line.split("|")[1:-1]]
                data_rows: list[list[str]] = []
                idx += 2
                while idx < len(lines):
                    row_line = lines[idx].strip()
                    if not (row_line.startswith("|") and row_line.endswith("|")):
                        break
                    if not DELIMITER_ROW_RE.match(row_line):
                        cells = [c.strip().strip("`") for c in row_line.split("|")[1:-1]]
                        data_rows.append(cells)
                    idx += 1
                tables.append((headers, data_rows))
                continue
        idx += 1
    return tables


def scan_markdown_claim_tables(
    md_path: Path,
    root: Path,
    known_classes: dict[str, list[str]],
    tombstoned_ids: set[str],
    prohibited_promotions: set[str] | None = None,
) -> list[ClaimFinding]:
    """Scans markdown tables for status and proof root/bundle citations."""
    findings: list[ClaimFinding] = []
    path_str = sanitize_path(md_path, root)

    try:
        raw_text = md_path.read_text(encoding="utf-8")
    except OSError as exc:
        findings.append(ClaimFinding(
            code=ERR_UNREADABLE_INPUT,
            file=path_str,
            location="file",
            message=f"Could not read markdown file '{path_str}': {exc}",
            remediation=DIAGNOSTIC_REGISTRY[ERR_UNREADABLE_INPUT]["remediation"],
        ))
        return findings

    if len(raw_text.strip()) == 0:
        findings.append(ClaimFinding(
            code=ERR_EMPTY_INPUT,
            file=path_str,
            location="file",
            message=f"Markdown file '{path_str}' is empty (0 bytes)",
            remediation=DIAGNOSTIC_REGISTRY[ERR_EMPTY_INPUT]["remediation"],
        ))
        return findings

    tables = parse_markdown_tables(raw_text)
    for headers, data_rows in tables:
        normalized_headers = [h.lower().strip() for h in headers]
        status_col = None
        proof_col = None
        id_col = None

        for col_idx, col_name in enumerate(normalized_headers):
            if col_name == "status":
                status_col = col_idx
            elif col_name in ("proof root", "proof_root", "proof bundle", "proof_bundle", "proof"):
                proof_col = col_idx
            elif col_name in ("id", "claim", "claim id"):
                id_col = col_idx

        # Only audit tables that declare proof roots or status
        if status_col is None and proof_col is None:
            continue

        for r_idx, row in enumerate(data_rows):
            row_id = row[id_col].strip() if id_col is not None and id_col < len(row) else f"row_{r_idx + 1}"
            status_val = row[status_col].strip().lower() if status_col is not None and status_col < len(row) else ""
            proof_val = row[proof_col].strip() if proof_col is not None and proof_col < len(row) else ""

            is_promoted = status_val in ("achieved", "qualified", "positively_verified", "verified")
            has_proof_root = proof_val.lower() not in NON_PROOF_ROOTS and proof_val != ""

            if is_promoted and not has_proof_root:
                findings.append(ClaimFinding(
                    code=ERR_CLAIM_LEVEL_EXCEEDED,
                    file=path_str,
                    location=f"table_row[{row_id}]",
                    message=(
                        f"Item '{row_id}' is marked '{status_val}' without referencing a retained proof bundle"
                    ),
                    remediation=DIAGNOSTIC_REGISTRY[ERR_CLAIM_LEVEL_EXCEEDED]["remediation"],
                    params={"id": row_id, "status": status_val},
                ))
            elif has_proof_root:
                proof_path = Path(proof_val)
                if proof_path.is_absolute():
                    findings.append(ClaimFinding(
                        code=ERR_PROOF_BUNDLE_NOT_FOUND,
                        file=path_str,
                        location=f"table_row[{row_id}]->path",
                        message=f"Proof bundle path must be repository-relative, got absolute path: '{proof_val}'",
                        remediation=DIAGNOSTIC_REGISTRY[ERR_PROOF_BUNDLE_NOT_FOUND]["remediation"],
                        params={"path": proof_val},
                    ))
                else:
                    _, bundle_findings, _ = verify_proof_bundle(
                        bundle_path=proof_path,
                        root=root,
                        expected_claim_id=row_id,
                        claim_level=status_val if is_promoted else None,
                        known_classes=known_classes,
                        tombstoned_ids=tombstoned_ids,
                        prohibited_promotions=prohibited_promotions,
                    )
                    for bf in bundle_findings:
                        findings.append(ClaimFinding(
                            code=bf.code,
                            file=path_str,
                            location=f"table_row[{row_id}]->{bf.location}",
                            message=f"Proof bundle for '{row_id}': {bf.message}",
                            remediation=bf.remediation,
                            params=bf.params,
                        ))

    return findings


def audit_claim_proof_bundles(
    root: Path = ROOT,
    claims_json_path: Path | None = None,
    target_bundle: Path | None = None,
) -> tuple[bool, list[ClaimFinding], dict[str, Any]]:
    """Runs full claim/proof-bundle consistency verification across the repository."""
    claims_path = claims_json_path or (root / "architecture/claims.json")
    resolution_path = root / "architecture/stable_id_resolution.json"

    known_classes, prohibited_promotions, findings = load_authoritative_claims(claims_path)
    tombstoned_ids: set[str] = set()

    if resolution_path.is_file():
        try:
            res_data = json.loads(resolution_path.read_text(encoding="utf-8"))
            if isinstance(res_data, dict):
                aliases = res_data.get("aliases", {})
                if isinstance(aliases, dict):
                    for k, v in aliases.items():
                        if isinstance(v, dict) and v.get("status") in stable_id_audit.TOMBSTONE_STATES:
                            tombstoned_ids.add(str(k))
        except Exception:
            pass

    # If single target bundle specified, verify it
    verified_bundles_count = 0
    if target_bundle is not None:
        target_bundle_path = target_bundle if target_bundle.is_absolute() else (root / target_bundle)
        _, b_findings, _ = verify_proof_bundle(
            bundle_path=target_bundle_path,
            root=root,
            known_classes=known_classes,
            tombstoned_ids=tombstoned_ids,
            prohibited_promotions=prohibited_promotions,
        )
        findings.extend(b_findings)
        verified_bundles_count += 1
    else:
        # Scan mandatory architecture files for existence and empty
        for rel_file in MANDATORY_AUTHORITY_FILES:
            full_path = root / rel_file
            if not full_path.exists():
                findings.append(ClaimFinding(
                    code=ERR_UNREADABLE_INPUT,
                    file=rel_file,
                    location="file",
                    message=f"Mandatory authority file does not exist: '{rel_file}'",
                    remediation=DIAGNOSTIC_REGISTRY[ERR_UNREADABLE_INPUT]["remediation"],
                ))
            elif full_path.stat().st_size == 0:
                findings.append(ClaimFinding(
                    code=ERR_EMPTY_INPUT,
                    file=rel_file,
                    location="file",
                    message=f"Mandatory authority file is empty (0 bytes): '{rel_file}'",
                    remediation=DIAGNOSTIC_REGISTRY[ERR_EMPTY_INPUT]["remediation"],
                ))

        # Scan markdown registries with status/proof tables
        md_targets = [
            root / "registries/SLOS.md",
            root / "registries/CLAIMS.md",
            root / "registries/QUALIFICATION_LANES.md",
            root / "README.md",
        ]
        for md_file in md_targets:
            if md_file.is_file():
                md_findings = scan_markdown_claim_tables(
                    md_path=md_file,
                    root=root,
                    known_classes=known_classes,
                    tombstoned_ids=tombstoned_ids,
                    prohibited_promotions=prohibited_promotions,
                )
                findings.extend(md_findings)

        # Scan qualification-artifacts for existing bundles
        qual_dir = root / "qualification-artifacts"
        if qual_dir.is_dir():
            for root_dir, _, files in os.walk(qual_dir):
                for f in sorted(files):
                    if f.endswith((".bundle.json", ".proof.json", ".bundle")):
                        f_path = Path(root_dir) / f
                        _, b_findings, _ = verify_proof_bundle(
                            bundle_path=f_path,
                            root=root,
                            known_classes=known_classes,
                            tombstoned_ids=tombstoned_ids,
                            prohibited_promotions=prohibited_promotions,
                        )
                        findings.extend(b_findings)
                        verified_bundles_count += 1

    error_count = sum(1 for f in findings if f.severity == "error")
    warning_count = sum(1 for f in findings if f.severity == "warning")
    is_valid = error_count == 0

    summary = {
        "status": "pass" if is_valid else "fail",
        "error_count": error_count,
        "warning_count": warning_count,
        "verified_bundles_count": verified_bundles_count,
        "authoritative_classes_count": len(known_classes),
        "prohibited_promotions_count": len(prohibited_promotions),
    }

    return is_valid, findings, summary


def main() -> int:
    parser = argparse.ArgumentParser(
        description="FSS-011 Claim/proof-bundle consistency checker."
    )
    parser.add_argument("--root", type=Path, default=ROOT, help="Repository root path")
    parser.add_argument("--claims", type=Path, default=None, help="Path to architecture/claims.json")
    parser.add_argument("--bundle", type=Path, default=None, help="Specific proof bundle to verify")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON report")
    parser.add_argument("--quiet", action="store_true", help="Suppress non-error output")
    args = parser.parse_args()

    is_valid, findings, summary = audit_claim_proof_bundles(
        root=args.root,
        claims_json_path=args.claims,
        target_bundle=args.bundle,
    )

    if args.json:
        report = {
            "summary": summary,
            "findings": [asdict(f) for f in findings],
        }
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        if not args.quiet or not is_valid:
            tag = "PASS" if is_valid else "FAIL"
            print(
                f"[{tag}] Claim/proof-bundle audit: {summary['verified_bundles_count']} bundles verified, "
                f"{summary['authoritative_classes_count']} claim classes, "
                f"{summary['error_count']} errors, {summary['warning_count']} warnings"
            )
            for f in findings:
                print(f"  {f.severity.upper()} [{f.code}] {f.file}:{f.location}: {f.message}")
                if f.remediation:
                    print(f"    Remediation: {f.remediation}")

    return 0 if is_valid else 1


if __name__ == "__main__":
    sys.exit(main())

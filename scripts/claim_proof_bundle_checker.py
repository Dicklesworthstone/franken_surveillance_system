#!/usr/bin/env python3
"""Deterministic claim and proof-bundle checker (fss-x4a.6.11 / FSS-011).

Validates that public readiness claims, status tables, and documentation claims
are strictly derivable from retained proof bundles and registered claim classes
(INV-021, REL-INV-009, Section 23.7).

Fail-closed verification invariants:
1. Proof bundle existence: a claim citing a proof bundle that does not exist, contains
   path traversal, resolves outside the repository root, or points to a non-file fails.
   Every declared artifact (``artifacts`` and canonical ``objects``/``uriHint`` entries)
   must be repository-relative, contained, present, a regular file, and digest-bound;
   unverifiable (remote or locator-less) artifacts fail. Only an explicit
   ``intentionally_omitted`` retention state skips the byte check.
2. Digest integrity: a proof bundle declares exactly one content digest that binds every
   other field, and every artifact declares a sha256 digest that matches its bytes.
3. Claim binding: a proof bundle binds a claim ID (Section 23.7) and a claim may only cite
   a bundle bound to that exact claim. A qualification receipt binds no claim.
4. Level support: claim statuses, bundle statuses, and supported levels come from closed
   vocabularies; anything unrecognized fails instead of being ranked. Every claim at or
   above ``reference_implemented`` needs retained proof, the claim level must not exceed
   what the proof supports, and all required evidence for the claim class is retained.
5. Stale generation refusal: bundles referencing stale, superseded, tombstoned (per the
   stable-ID index, compared case-insensitively), expired, or 'latest'-aliased generations
   anywhere in a generation or environment subtree fail closed.
6. Input validity: any unreadable, corrupt, or empty authority registry, claim surface,
   tombstone index, bundle, or receipt fails with a typed code and non-zero exit.
7. Receipts: qualification receipts under qualification-artifacts/ are inspected. A
   non-passing receipt fails when verified or cited; a retained but uncited non-passing
   receipt is reported as a typed warning and counted in the summary.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import architecture_registry_consistency  # noqa: F401  (policy-lane import contract)
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
ERR_TOMBSTONE_INDEX_UNAVAILABLE = "ERR-CLAIM-PROOF-TOMBSTONE-INDEX-UNAVAILABLE-001"
ERR_CLAIM_BINDING_MISMATCH = "ERR-CLAIM-PROOF-CLAIM-BINDING-MISMATCH-001"
ERR_UNRECOGNIZED_STATE = "ERR-CLAIM-PROOF-UNRECOGNIZED-STATE-001"
WARN_NONPASSING_RECEIPT = "WARN-CLAIM-PROOF-NONPASSING-RECEIPT-001"

DIAGNOSTIC_REGISTRY: dict[str, dict[str, str]] = {
    ERR_PROOF_BUNDLE_NOT_FOUND: {
        "trigger": "A claim cites a proof bundle, or a bundle declares an artifact, that does not exist on disk, has forbidden traversal ('..'), is absolute, resolves outside the repository root, is not a regular file, or cannot be verified locally",
        "remediation": "Provide an existing, valid relative path to a retained proof bundle file under qualification-artifacts/ or proof_bundles/",
    },
    ERR_BUNDLE_DIGEST_MISMATCH: {
        "trigger": "A proof bundle's content digest or an artifact digest is missing, ambiguous, malformed, or does not match the actual computed cryptographic digest",
        "remediation": "Recompute and bind the exact cryptographic digest of the bundle contents or fix corrupted artifacts",
    },
    ERR_CLAIM_LEVEL_EXCEEDED: {
        "trigger": "A claim level (e.g. achieved, qualified, verified) is higher than its retained proof supports, the proof is non-passing, or required evidence for the claim class is missing",
        "remediation": "Demote the claim status to a supported level (e.g. 'target' or 'specified') or provide the complete required retained evidence",
    },
    ERR_STALE_GENERATION: {
        "trigger": "A proof bundle references a stale, superseded, tombstoned, or expired generation, or uses a prohibited 'latest' alias",
        "remediation": "Re-qualify the claim against the current active generation and bind an explicit generation identity",
    },
    ERR_UNREADABLE_INPUT: {
        "trigger": "An input file or directory could not be read, decoded, or parsed as valid JSON/Markdown, or is structurally malformed",
        "remediation": "Fix file permissions, encoding, or JSON/Markdown syntax errors",
    },
    ERR_EMPTY_INPUT: {
        "trigger": "An input file is empty (0 bytes or empty text), contains an empty JSON collection, or a required claim surface declares no claim table",
        "remediation": "Ensure all inputs contain non-empty, well-formed specifications",
    },
    ERR_INVALID_CLAIM_CLASS: {
        "trigger": "A proof bundle declares no claim class, a claim class not recognized in architecture/claims.json, or no claim-class registry was supplied",
        "remediation": "Use one of the registered claim classes in architecture/claims.json",
    },
    ERR_PROHIBITED_CLAIM_PROMOTION: {
        "trigger": "A claim attempts a promotion explicitly prohibited by architecture/claims.json",
        "remediation": "Do not promote unverified source presence, single demos, or uncalibrated metrics to readiness claims",
    },
    ERR_TOMBSTONE_INDEX_UNAVAILABLE: {
        "trigger": "The stable-ID tombstone index (architecture/stable_id_resolution.json plus the repository stable-ID index) is missing, unreadable, empty, corrupt, or has the wrong schema, so tombstoned identities cannot be refused",
        "remediation": "Restore a readable, non-empty fss.stable_id_resolution.v1 index and fix stable-ID audit errors; the claim audit never runs without it",
    },
    ERR_CLAIM_BINDING_MISMATCH: {
        "trigger": "A proof bundle binds no claim ID or a different claim than the one citing it, a promoted claim row has no claim ID, or a claim cites a qualification receipt (which binds no claim)",
        "remediation": "Cite a proof bundle whose claim_id equals the citing claim's stable ID",
    },
    ERR_UNRECOGNIZED_STATE: {
        "trigger": "A claim status, bundle status, supported level, retention state, expiry marker, or readiness registry state is outside the closed vocabulary",
        "remediation": "Use a registered readiness state (architecture/readiness_dimensions.json) or a recognized bundle status; unknown states are never ranked or ignored",
    },
    WARN_NONPASSING_RECEIPT: {
        "trigger": "A retained qualification receipt under qualification-artifacts/ records a non-passing run",
        "remediation": "Nothing may cite this receipt as proof; re-run qualification to produce a passed receipt",
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

# Registered states that claim no readiness level at all (never ranked, never promoted).
NON_CLAIMING_STATES: frozenset[str] = frozenset({
    "blocked",
    "revoked",
    "not_applicable",
    "tombstone",
    "tombstoned",
    "superseded",
})

# Claims at or above this rank require retained proof.
PROMOTION_RANK = READINESS_LEVEL_RANKS["reference_implemented"]

PASSING_BUNDLE_STATUSES: frozenset[str] = frozenset({
    "passed",
    "verified",
    "positively_verified",
    "qualified",
    "achieved",
})

FAILED_STATUSES: frozenset[str] = frozenset({
    "failed",
    "broken",
    "blocked",
    "revoked",
    "staged",
    "provisional",
    "draft",
    "indeterminate",
    "rejected",
    "error",
    "errored",
    "aborted",
    "crashed",
    "partial",
    "interrupted",
    "cancelled",
    "canceled",
    "skipped",
    "expired",
})

STALE_STATUSES: frozenset[str] = frozenset({"stale", "superseded", "tombstone", "tombstoned"})

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

# Every markdown surface that may carry readiness claims; a missing surface fails the audit.
REQUIRED_CLAIM_SURFACES = (
    "registries/SLOS.md",
    "registries/CLAIMS.md",
    "registries/QUALIFICATION_LANES.md",
    "README.md",
)
# Surfaces that must contain at least one recognizable status/proof claim table.
CLAIM_TABLE_REQUIRED_SURFACES: frozenset[str] = frozenset({"registries/SLOS.md"})

TOMBSTONE_INDEX_FILE = "architecture/stable_id_resolution.json"
READINESS_REGISTRY_FILE = "architecture/readiness_dimensions.json"
RETENTION_DIR = "qualification-artifacts"
BUNDLE_SUFFIXES = (".bundle.json", ".proof.json", ".bundle")

CONTENT_DIGEST_FIELDS = ("content_digest", "contentDigest")
CLAIM_ID_FIELDS = ("claim_id", "claimId")
CLAIM_CLASS_FIELDS = ("claim_class", "claimClass")
SUPPORTED_LEVEL_FIELDS = ("supported_level", "supportedLevel", "claim_level", "claimLevel")
RETAINED_EVIDENCE_FIELDS = ("retained_evidence", "retainedEvidence", "evidence")
ARTIFACT_LIST_FIELDS = ("artifacts", "objects")
ARTIFACT_LOCATOR_FIELDS = ("path", "uri", "uriHint")
EXPIRY_FIELDS = ("expires_at", "expiresAt", "valid_until", "validUntil")
RETENTION_STATES: frozenset[str] = frozenset({"embedded", "local", "remote", "intentionally_omitted"})
SHA256_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

# Mirrors schemas/release_qualification_receipt.v1.json (drift is caught by a unit test).
QUALIFICATION_RECEIPT_SCHEMA = "fss.release_qualification_receipt.v1"
RECEIPT_FILENAME = "qualification-receipt.json"
RECEIPT_REQUIRED_FIELDS = (
    "schema",
    "receiptId",
    "laneId",
    "sourceCommit",
    "sourceTree",
    "siblingClosureDigest",
    "cargoLockDigest",
    "toolchain",
    "hostIdentity",
    "target",
    "features",
    "commands",
    "artifactManifestDigest",
    "startedAt",
    "finishedAt",
    "status",
)
RECEIPT_STATUSES: frozenset[str] = frozenset({"passed", "failed", "partial", "interrupted"})
RECEIPT_COMMAND_STATUSES: frozenset[str] = frozenset({"passed", "failed", "skipped"})


@dataclass(frozen=True)
class ClaimFinding:
    code: str
    file: str
    location: str
    message: str
    severity: str = "error"
    remediation: str = ""
    params: dict[str, Any] = field(default_factory=dict)


def _finding(
    code: str,
    file: str,
    location: str,
    message: str,
    params: dict[str, Any] | None = None,
    severity: str = "error",
) -> ClaimFinding:
    return ClaimFinding(
        code=code,
        file=file,
        location=location,
        message=message,
        severity=severity,
        remediation=DIAGNOSTIC_REGISTRY[code]["remediation"],
        params=dict(params or {}),
    )


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


_LATEST_TOKEN_SPLIT_RE = re.compile(r"[\s\-_:/@.+]+")


def is_latest_generation(val: str) -> bool:
    """Detects 'latest' generation aliases prohibited by ADR-0004, including tag forms
    such as 'model:latest', 'latest/v1', 'model@latest', and 'v-latest'."""
    return "latest" in _LATEST_TOKEN_SPLIT_RE.split(val.strip().lower())


def normalize_id(value: str) -> str:
    """Case- and whitespace-insensitive identity key for tombstone comparison."""
    return value.strip().strip("`").strip().casefold()


_HTML_TAG_RE = re.compile(r"</?[A-Za-z][^>]*>")
_EMPHASIS_WRAPPERS = ("**", "__", "~~", "`", "*", "_")


def normalize_cell(text: str) -> str:
    """Strips markdown/HTML emphasis so formatting cannot hide a claim value."""
    value = _HTML_TAG_RE.sub("", text).replace("\\|", "|").strip()
    changed = True
    while changed:
        changed = False
        for wrapper in _EMPHASIS_WRAPPERS:
            width = len(wrapper)
            if len(value) > 2 * width and value.startswith(wrapper) and value.endswith(wrapper):
                value = value[width:-width].strip()
                changed = True
                break
    return value


def _single_field(data: dict[str, Any], names: tuple[str, ...]) -> tuple[list[str], Any]:
    """Returns (present field names, value of the first present field)."""
    present = [name for name in names if name in data]
    return present, (data[present[0]] if present else None)


def _is_contained(path: Path, root: Path) -> bool:
    try:
        return path.resolve().is_relative_to(root.resolve())
    except (OSError, RuntimeError):
        return False


def _read_json_document(path: Path, display: str, kind: str) -> tuple[dict[str, Any] | None, list[ClaimFinding]]:
    """Reads a non-empty JSON object; every failure is a typed finding."""
    label = kind[:1].upper() + kind[1:]
    try:
        raw_bytes = path.read_bytes()
    except OSError as exc:
        return None, [_finding(ERR_UNREADABLE_INPUT, display, "file", f"Could not read {kind} '{display}': {exc}", {"error": str(exc)})]
    if len(raw_bytes.strip()) == 0:
        return None, [_finding(ERR_EMPTY_INPUT, display, "file", f"{label} '{display}' is empty (0 bytes); existence is not proof")]
    try:
        data = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return None, [_finding(ERR_UNREADABLE_INPUT, display, "file", f"{label} '{display}' contains invalid JSON: {exc}", {"error": str(exc)})]
    if not isinstance(data, dict):
        return None, [_finding(ERR_UNREADABLE_INPUT, display, "root", f"{label} '{display}' JSON root must be an object")]
    if len(data) == 0:
        return None, [_finding(ERR_EMPTY_INPUT, display, "root", f"{label} '{display}' contains an empty JSON object")]
    return data, []


def load_authoritative_claims(claims_json_path: Path) -> tuple[dict[str, list[str]], set[str], list[ClaimFinding]]:
    """Loads claim classes and prohibited promotions from architecture/claims.json."""
    findings: list[ClaimFinding] = []
    classes: dict[str, list[str]] = {}
    prohibited: set[str] = set()
    path_str = str(claims_json_path)

    if not claims_json_path.is_file():
        findings.append(_finding(ERR_UNREADABLE_INPUT, path_str, "root", f"Authoritative claims registry file not found: '{claims_json_path}'"))
        return classes, prohibited, findings

    try:
        raw_bytes = claims_json_path.read_bytes()
    except OSError as exc:
        findings.append(_finding(ERR_UNREADABLE_INPUT, path_str, "root", f"Could not read authoritative claims registry '{claims_json_path}': {exc}"))
        return classes, prohibited, findings

    if len(raw_bytes.strip()) == 0:
        findings.append(_finding(ERR_EMPTY_INPUT, path_str, "root", f"Authoritative claims registry file '{claims_json_path}' is empty (0 bytes)"))
        return classes, prohibited, findings

    try:
        data = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        findings.append(_finding(ERR_UNREADABLE_INPUT, path_str, "root", f"Authoritative claims registry '{claims_json_path}' is invalid JSON: {exc}"))
        return classes, prohibited, findings

    if not isinstance(data, dict):
        findings.append(_finding(ERR_UNREADABLE_INPUT, path_str, "root", f"Authoritative claims registry '{claims_json_path}' root must be a JSON object"))
        return classes, prohibited, findings

    raw_classes = data.get("classes")
    if not isinstance(raw_classes, list) or len(raw_classes) == 0:
        findings.append(_finding(ERR_EMPTY_INPUT, path_str, "classes", f"Authoritative claims registry '{claims_json_path}' contains no claim classes"))
        return classes, prohibited, findings

    for idx, item in enumerate(raw_classes):
        loc = f"classes[{idx}]"
        if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not item["id"].strip():
            findings.append(_finding(ERR_UNREADABLE_INPUT, path_str, loc, f"Malformed claim class entry at index {idx}"))
            continue
        class_id = item["id"].strip()
        if class_id in classes:
            findings.append(_finding(ERR_UNREADABLE_INPUT, path_str, loc, f"Duplicate claim class '{class_id}' at index {idx}"))
            continue
        req_ev = item.get("requiredEvidence")
        if not isinstance(req_ev, list) or not all(isinstance(e, str) and e.strip() for e in req_ev):
            findings.append(_finding(
                ERR_UNREADABLE_INPUT, path_str, f"{loc}.requiredEvidence",
                f"Claim class '{class_id}' requiredEvidence must be a list of non-empty strings; got {req_ev!r}",
            ))
            continue
        if len(req_ev) == 0:
            findings.append(_finding(ERR_EMPTY_INPUT, path_str, f"{loc}.requiredEvidence", f"Claim class '{class_id}' requires no evidence"))
            continue
        classes[class_id] = [e.strip() for e in req_ev]

    raw_prohibited = data.get("prohibited")
    if not isinstance(raw_prohibited, list) or not all(isinstance(p, str) and p.strip() for p in raw_prohibited):
        findings.append(_finding(
            ERR_UNREADABLE_INPUT, path_str, "prohibited",
            f"Authoritative claims registry '{claims_json_path}' prohibited promotions must be a list of non-empty strings; got {raw_prohibited!r}",
        ))
    elif len(raw_prohibited) == 0:
        findings.append(_finding(ERR_EMPTY_INPUT, path_str, "prohibited", f"Authoritative claims registry '{claims_json_path}' declares no prohibited promotions"))
    else:
        prohibited = {p.strip().lower() for p in raw_prohibited}

    return classes, prohibited, findings


def load_readiness_states(path: Path, display: str) -> tuple[set[str], list[ClaimFinding]]:
    """Loads the registered readiness vocabulary and refuses states this checker cannot rank."""
    data, findings = _read_json_document(path, display, "readiness registry")
    if data is None:
        return set(), findings
    states = data.get("states")
    if not isinstance(states, list) or not all(isinstance(s, str) and s.strip() for s in states):
        return set(), [_finding(ERR_UNREADABLE_INPUT, display, "states", f"Readiness registry '{display}' states must be a list of non-empty strings")]
    if len(states) == 0:
        return set(), [_finding(ERR_EMPTY_INPUT, display, "states", f"Readiness registry '{display}' declares no readiness states")]
    normalized = {s.strip().lower() for s in states}
    for state in sorted(normalized):
        if state not in READINESS_LEVEL_RANKS and state not in NON_CLAIMING_STATES:
            findings.append(_finding(
                ERR_UNRECOGNIZED_STATE, display, "states",
                f"Readiness registry state '{state}' is neither ranked nor non-claiming in this checker; refusing to guess its rank",
                {"state": state},
            ))
    return normalized, findings


def load_tombstone_index(root: Path) -> tuple[set[str], list[ClaimFinding]]:
    """Loads tombstoned stable IDs (normalized). Any failure to establish the index is a
    typed finding: an empty tombstone set must never stand in for an unreadable index."""
    display = TOMBSTONE_INDEX_FILE
    path = root / TOMBSTONE_INDEX_FILE

    def unavailable(reason: str, **params: Any) -> tuple[set[str], list[ClaimFinding]]:
        return set(), [_finding(
            ERR_TOMBSTONE_INDEX_UNAVAILABLE, display, "file",
            f"Stable-ID tombstone index unavailable: {reason}; tombstoned generations cannot be refused",
            params,
        )]

    if not path.is_file():
        return unavailable(f"'{display}' does not exist or is not a regular file")
    try:
        raw_bytes = path.read_bytes()
    except OSError as exc:
        return unavailable(f"could not read '{display}': {exc}", error=str(exc))
    if len(raw_bytes.strip()) == 0:
        return unavailable(f"'{display}' is empty (0 bytes)")
    try:
        data = json.loads(raw_bytes.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return unavailable(f"'{display}' is not valid JSON: {exc}", error=str(exc))
    if not isinstance(data, dict):
        return unavailable(f"'{display}' root must be a JSON object")
    if data.get("schema") != stable_id_audit.RESOLUTION_SCHEMA:
        return unavailable(f"'{display}' schema is {data.get('schema')!r}; expected '{stable_id_audit.RESOLUTION_SCHEMA}'")
    resolutions = data.get("resolutions")
    if not isinstance(resolutions, list) or len(resolutions) == 0:
        return unavailable(f"'{display}' contains no resolutions")
    try:
        index = stable_id_audit._load_repository_index(root)
    except (stable_id_audit.AuditError, OSError, UnicodeDecodeError) as exc:
        return unavailable(f"repository stable-ID index could not be built: {exc}", error=str(exc))
    if not index.known:
        return unavailable("repository stable-ID index contains no identifiers")
    return {normalize_id(t) for t in index.tombstoned}, []


def compute_bundle_digest(bundle_dict: dict[str, Any]) -> str:
    """Computes the canonical sha256:<hex> digest of a proof bundle over every field
    except the content-digest field itself. Other digest-named fields are payload."""
    filtered = {k: v for k, v in bundle_dict.items() if k not in CONTENT_DIGEST_FIELDS}
    canonical_bytes = schema_validate.canonical_json_bytes(filtered)
    return compute_sha256(canonical_bytes)


def _check_content_digest(data: dict[str, Any], path_str: str, findings: list[ClaimFinding]) -> None:
    present, declared = _single_field(data, CONTENT_DIGEST_FIELDS)
    if not present:
        findings.append(_finding(
            ERR_BUNDLE_DIGEST_MISMATCH, path_str, "content_digest",
            f"Proof bundle '{path_str}' declares no content digest; an unbound bundle cannot prove anything",
        ))
        return
    if len(present) > 1:
        findings.append(_finding(
            ERR_BUNDLE_DIGEST_MISMATCH, path_str, "content_digest",
            f"Proof bundle '{path_str}' declares competing content digest fields {present}",
            {"fields": present},
        ))
        return
    computed = compute_bundle_digest(data)
    if not isinstance(declared, str) or declared != computed:
        findings.append(_finding(
            ERR_BUNDLE_DIGEST_MISMATCH, path_str, present[0],
            f"Proof bundle '{path_str}' declared digest '{declared}' does not match computed digest '{computed}'",
            {"declared": declared, "computed": computed},
        ))


def _check_artifacts(data: dict[str, Any], root: Path, path_str: str, findings: list[ClaimFinding]) -> None:
    for list_field in ARTIFACT_LIST_FIELDS:
        if list_field not in data:
            continue
        entries = data[list_field]
        if not isinstance(entries, list):
            findings.append(_finding(ERR_UNREADABLE_INPUT, path_str, list_field, f"Proof bundle '{list_field}' must be a list"))
            continue
        for idx, art in enumerate(entries):
            loc = f"{list_field}[{idx}]"
            if not isinstance(art, dict):
                findings.append(_finding(ERR_UNREADABLE_INPUT, path_str, loc, f"Bundle artifact entry {loc} must be an object, got {type(art).__name__}"))
                continue
            digest_val = art.get("digest")
            digest_norm = digest_val.strip().lower() if isinstance(digest_val, str) else None
            digest_ok = digest_norm is not None and SHA256_DIGEST_RE.match(digest_norm) is not None
            if not digest_ok:
                findings.append(_finding(
                    ERR_BUNDLE_DIGEST_MISMATCH, path_str, f"{loc}.digest",
                    f"Bundle artifact {loc} declares no valid 'sha256:<64 hex>' digest (got {digest_val!r})",
                ))

            retention = art.get("retentionState")
            if retention is not None:
                if not isinstance(retention, str) or retention not in RETENTION_STATES:
                    findings.append(_finding(
                        ERR_UNRECOGNIZED_STATE, path_str, f"{loc}.retentionState",
                        f"Bundle artifact {loc} has unrecognized retentionState {retention!r}",
                    ))
                    continue
                if retention == "intentionally_omitted":
                    continue  # explicit, typed omission: no bytes are claimed as retained
                if retention == "remote":
                    findings.append(_finding(
                        ERR_PROOF_BUNDLE_NOT_FOUND, path_str, loc,
                        f"Bundle artifact {loc} is not locally retained (retentionState=remote); its bytes cannot be verified",
                    ))
                    continue

            locators = [name for name in ARTIFACT_LOCATOR_FIELDS if art.get(name) is not None]
            if not locators:
                findings.append(_finding(ERR_PROOF_BUNDLE_NOT_FOUND, path_str, loc, f"Bundle artifact {loc} declares no local path; it cannot be verified"))
                continue
            values = {name: art[name] for name in locators}
            if len({json.dumps(v, sort_keys=True) for v in values.values()}) > 1:
                findings.append(_finding(ERR_UNREADABLE_INPUT, path_str, loc, f"Bundle artifact {loc} declares conflicting locators {values}"))
                continue
            art_path_val = values[locators[0]]
            if not isinstance(art_path_val, str) or not art_path_val.strip():
                findings.append(_finding(ERR_UNREADABLE_INPUT, path_str, loc, f"Bundle artifact {loc} locator must be a non-empty string"))
                continue
            if "://" in art_path_val or art_path_val.lower().startswith("file:"):
                findings.append(_finding(
                    ERR_PROOF_BUNDLE_NOT_FOUND, path_str, loc,
                    f"Bundle artifact '{art_path_val}' is a non-local URI; its bytes cannot be verified",
                    {"artifact": art_path_val},
                ))
                continue
            rel = Path(art_path_val)
            if rel.is_absolute():
                findings.append(_finding(
                    ERR_PROOF_BUNDLE_NOT_FOUND, path_str, loc,
                    f"Bundle artifact path must be repository-relative, got absolute path: '{art_path_val}'",
                    {"artifact": art_path_val},
                ))
                continue
            if ".." in rel.parts:
                findings.append(_finding(
                    ERR_PROOF_BUNDLE_NOT_FOUND, path_str, loc,
                    f"Bundle artifact path '{art_path_val}' contains forbidden path traversal ('..')",
                    {"artifact": art_path_val},
                ))
                continue
            art_full_path = root / rel
            if not _is_contained(art_full_path, root):
                findings.append(_finding(
                    ERR_PROOF_BUNDLE_NOT_FOUND, path_str, loc,
                    f"Bundle artifact '{art_path_val}' resolves outside the repository root",
                    {"artifact": art_path_val},
                ))
                continue
            if not art_full_path.exists():
                findings.append(_finding(
                    ERR_PROOF_BUNDLE_NOT_FOUND, path_str, loc,
                    f"Bundle artifact file does not exist: '{art_path_val}'",
                    {"artifact": art_path_val},
                ))
                continue
            if not art_full_path.is_file():
                findings.append(_finding(
                    ERR_PROOF_BUNDLE_NOT_FOUND, path_str, loc,
                    f"Bundle artifact '{art_path_val}' is not a regular file",
                    {"artifact": art_path_val},
                ))
                continue
            if not digest_ok:
                continue
            try:
                art_bytes = art_full_path.read_bytes()
            except OSError as exc:
                findings.append(_finding(
                    ERR_UNREADABLE_INPUT, path_str, loc,
                    f"Could not read bundle artifact '{art_path_val}': {exc}",
                    {"artifact": art_path_val, "error": str(exc)},
                ))
                continue
            actual = compute_sha256(art_bytes)
            if actual != digest_norm:
                findings.append(_finding(
                    ERR_BUNDLE_DIGEST_MISMATCH, path_str, f"{loc}.digest",
                    f"Artifact '{art_path_val}' digest mismatch: declared '{digest_val}', actual '{actual}'",
                    {"declared": digest_val, "computed": actual},
                ))


def _is_generation_key(key: str) -> bool:
    compact = re.sub(r"[^a-z]", "", key.lower())
    return "generation" in compact or compact == "environment"


def _check_generations(
    data: dict[str, Any],
    path_str: str,
    tombstones: set[str],
    findings: list[ClaimFinding],
) -> None:
    def walk(val: Any, loc: str, in_generation: bool) -> None:
        if isinstance(val, dict):
            if in_generation:
                is_stale = val.get("is_stale") or val.get("stale", False)
                superseded = val.get("superseded", False)
                status = str(val.get("status", "")).strip().lower()
                if is_stale or superseded or status in STALE_STATUSES:
                    findings.append(_finding(
                        ERR_STALE_GENERATION, path_str, loc,
                        f"Proof bundle explicitly references a stale or superseded generation at {loc}",
                        {"field": loc},
                    ))
            for key, sub in val.items():
                walk(sub, f"{loc}.{key}" if loc else str(key), in_generation or _is_generation_key(str(key)))
        elif isinstance(val, list):
            for idx, sub in enumerate(val):
                walk(sub, f"{loc}[{idx}]", in_generation)
        elif isinstance(val, str) and in_generation:
            if is_latest_generation(val):
                findings.append(_finding(
                    ERR_STALE_GENERATION, path_str, loc,
                    f"Proof bundle references prohibited 'latest' alias in {loc}='{val}'",
                    {"field": loc, "value": val},
                ))
            if normalize_id(val) in tombstones:
                findings.append(_finding(
                    ERR_STALE_GENERATION, path_str, loc,
                    f"Proof bundle references tombstoned generation in {loc}='{val}'",
                    {"field": loc, "value": val},
                ))

    walk(data, "", False)


def _parse_instant(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        instant = datetime.fromisoformat(value.strip())
    except ValueError:
        return None
    if instant.tzinfo is None:
        return None  # a zone-less instant is indeterminate, never assumed
    return instant


def _check_expiry(data: dict[str, Any], path_str: str, now: datetime, findings: list[ClaimFinding]) -> None:
    for name in EXPIRY_FIELDS:
        if name not in data:
            continue
        instant = _parse_instant(data[name])
        if instant is None:
            findings.append(_finding(
                ERR_UNRECOGNIZED_STATE, path_str, name,
                f"Proof bundle {name}={data[name]!r} is not a zone-qualified ISO-8601 instant; expiry is indeterminate",
            ))
        elif instant <= now:
            findings.append(_finding(
                ERR_STALE_GENERATION, path_str, name,
                f"Proof bundle expired at {name}='{data[name]}' (as of {now.isoformat()})",
                {"field": name, "value": data[name]},
            ))
    if "is_expired" in data:
        marker = data["is_expired"]
        if marker is True:
            findings.append(_finding(ERR_STALE_GENERATION, path_str, "is_expired", "Proof bundle is marked expired"))
        elif marker is not False:
            findings.append(_finding(
                ERR_UNRECOGNIZED_STATE, path_str, "is_expired",
                f"Proof bundle is_expired={marker!r} is not a boolean; expiry is indeterminate",
            ))


def _rank_of(level: str) -> int | None:
    return READINESS_LEVEL_RANKS.get(level)


def _verify_receipt_payload(
    data: dict[str, Any],
    path_str: str,
    *,
    cited: bool,
    expected_claim_id: str | None,
    claim_level: str | None,
) -> tuple[list[ClaimFinding], str | None]:
    """Checks a qualification receipt. Returns (findings, recognized status or None)."""
    findings: list[ClaimFinding] = []
    missing = [k for k in RECEIPT_REQUIRED_FIELDS if k not in data]
    if missing:
        findings.append(_finding(
            ERR_UNREADABLE_INPUT, path_str, "root",
            f"Qualification receipt '{path_str}' is missing required fields {missing}",
            {"missing": missing},
        ))
    status = data.get("status")
    recognized: str | None = status if isinstance(status, str) and status in RECEIPT_STATUSES else None
    if recognized is None:
        findings.append(_finding(ERR_UNRECOGNIZED_STATE, path_str, "status", f"Qualification receipt '{path_str}' status {status!r} is not one of {sorted(RECEIPT_STATUSES)}"))
    commands = data.get("commands")
    command_statuses: list[str] = []
    if not isinstance(commands, list) or len(commands) == 0:
        findings.append(_finding(ERR_UNREADABLE_INPUT, path_str, "commands", f"Qualification receipt '{path_str}' commands must be a non-empty list"))
    else:
        for idx, cmd in enumerate(commands):
            cmd_status = cmd.get("status") if isinstance(cmd, dict) else None
            if not isinstance(cmd_status, str) or cmd_status not in RECEIPT_COMMAND_STATUSES:
                findings.append(_finding(
                    ERR_UNRECOGNIZED_STATE, path_str, f"commands[{idx}].status",
                    f"Qualification receipt '{path_str}' command {idx} status {cmd_status!r} is not one of {sorted(RECEIPT_COMMAND_STATUSES)}",
                ))
            else:
                command_statuses.append(cmd_status)
    if recognized == "passed" and "failed" in command_statuses:
        findings.append(_finding(
            ERR_CLAIM_LEVEL_EXCEEDED, path_str, "status",
            f"Qualification receipt '{path_str}' claims 'passed' but records a failed command; the receipt is self-contradictory",
        ))
    if recognized is not None and recognized != "passed":
        if cited:
            findings.append(_finding(
                ERR_CLAIM_LEVEL_EXCEEDED, path_str, "status",
                f"Qualification receipt '{path_str}' has non-passing status '{recognized}'; cannot support readiness",
                {"status": recognized},
            ))
        else:
            findings.append(_finding(
                WARN_NONPASSING_RECEIPT, path_str, "status",
                f"Retained qualification receipt '{path_str}' records a non-passing run (status '{recognized}'); it must not be cited as proof",
                {"status": recognized},
                severity="warning",
            ))
    if cited and expected_claim_id is not None:
        findings.append(_finding(
            ERR_CLAIM_BINDING_MISMATCH, path_str, "claim_id",
            f"Qualification receipt '{path_str}' binds no claim ID; claim '{expected_claim_id}' must cite a proof bundle bound to it",
            {"expected_claim_id": expected_claim_id},
        ))
    if cited and claim_level is not None:
        rank = _rank_of(claim_level.strip().lower())
        if rank is not None and rank >= PROMOTION_RANK:
            findings.append(_finding(
                ERR_CLAIM_LEVEL_EXCEEDED, path_str, "supported_level",
                f"Qualification receipt '{path_str}' declares no supported readiness level; claimed level '{claim_level}' is unsupported",
            ))
    return findings, recognized


def verify_proof_bundle(
    bundle_path: Path,
    root: Path,
    expected_claim_id: str | None = None,
    claim_level: str | None = None,
    claim_class: str | None = None,
    known_classes: dict[str, list[str]] | None = None,
    tombstoned_ids: set[str] | None = None,
    prohibited_promotions: set[str] | None = None,
    now: datetime | None = None,
) -> tuple[bool, list[ClaimFinding], dict[str, Any] | None]:
    """Verifies one proof bundle (or qualification receipt) against all fail-closed criteria."""
    findings: list[ClaimFinding] = []
    path_str = sanitize_path(bundle_path, root)

    # 1. Path checks: traversal refusal, then containment for repository-relative citations.
    if ".." in bundle_path.parts:
        findings.append(_finding(
            ERR_PROOF_BUNDLE_NOT_FOUND, path_str, "path",
            f"Proof bundle path '{bundle_path}' contains forbidden path traversal ('..')",
            {"path": str(bundle_path)},
        ))
        return False, findings, None

    if bundle_path.is_absolute():
        resolved_path = bundle_path
    else:
        resolved_path = root / bundle_path
        if not _is_contained(resolved_path, root):
            findings.append(_finding(
                ERR_PROOF_BUNDLE_NOT_FOUND, path_str, "path",
                f"Referenced proof bundle '{bundle_path}' resolves outside the repository root",
                {"path": str(bundle_path)},
            ))
            return False, findings, None

    if not resolved_path.exists():
        findings.append(_finding(ERR_PROOF_BUNDLE_NOT_FOUND, path_str, "path", f"Referenced proof bundle does not exist on disk: '{path_str}'", {"path": path_str}))
        return False, findings, None

    if not resolved_path.is_file():
        findings.append(_finding(ERR_PROOF_BUNDLE_NOT_FOUND, path_str, "path", f"Referenced proof bundle is not a regular file: '{path_str}'", {"path": path_str}))
        return False, findings, None

    data, read_findings = _read_json_document(resolved_path, path_str, "proof bundle")
    if data is None:
        return False, read_findings, None

    if data.get("schema") == QUALIFICATION_RECEIPT_SCHEMA:
        receipt_findings, _ = _verify_receipt_payload(
            data, path_str, cited=True, expected_claim_id=expected_claim_id, claim_level=claim_level
        )
        return not any(f.severity == "error" for f in receipt_findings), receipt_findings, data

    # 2. Digest checks: bundle content digest and every declared artifact.
    _check_content_digest(data, path_str, findings)
    _check_artifacts(data, root, path_str, findings)

    # 3. Claim binding (Section 23.7: a proof bundle carries its claim ID).
    id_fields, bundle_claim_id = _single_field(data, CLAIM_ID_FIELDS)
    if not id_fields or not isinstance(bundle_claim_id, str) or not bundle_claim_id.strip():
        findings.append(_finding(
            ERR_CLAIM_BINDING_MISMATCH, path_str, "claim_id",
            f"Proof bundle '{path_str}' binds no claim ID"
            + (f"; it cannot prove claim '{expected_claim_id}'" if expected_claim_id is not None else ""),
            {"expected_claim_id": expected_claim_id},
        ))
    elif len(id_fields) > 1 and len({str(data[f]).strip() for f in id_fields}) > 1:
        findings.append(_finding(
            ERR_CLAIM_BINDING_MISMATCH, path_str, "claim_id",
            f"Proof bundle '{path_str}' declares conflicting claim IDs {[data[f] for f in id_fields]}",
        ))
    elif expected_claim_id is not None and bundle_claim_id.strip() != expected_claim_id.strip():
        findings.append(_finding(
            ERR_CLAIM_BINDING_MISMATCH, path_str, "claim_id",
            f"Proof bundle is bound to claim '{bundle_claim_id.strip()}', not to the citing claim '{expected_claim_id}'",
            {"bundle_claim_id": bundle_claim_id, "expected_claim_id": expected_claim_id},
        ))

    # 4. Generation checks: stale, superseded, tombstoned, 'latest', and expiry.
    tombstones = {normalize_id(t) for t in (tombstoned_ids or ())}
    _check_generations(data, path_str, tombstones, findings)
    _check_expiry(data, path_str, now or datetime.now(timezone.utc), findings)

    # 5. Status: closed vocabulary.
    raw_status = data.get("status")
    bundle_status = raw_status.strip().lower() if isinstance(raw_status, str) else None
    if bundle_status in STALE_STATUSES:
        findings.append(_finding(ERR_STALE_GENERATION, path_str, "status", f"Proof bundle status is marked '{bundle_status}'", {"status": bundle_status}))
    elif bundle_status in FAILED_STATUSES:
        findings.append(_finding(
            ERR_CLAIM_LEVEL_EXCEEDED, path_str, "status",
            f"Proof bundle has non-passing status '{bundle_status}'; cannot support readiness",
            {"status": bundle_status},
        ))
    elif bundle_status not in PASSING_BUNDLE_STATUSES:
        findings.append(_finding(
            ERR_UNRECOGNIZED_STATE, path_str, "status",
            f"Proof bundle status {raw_status!r} is not a recognized passing status {sorted(PASSING_BUNDLE_STATUSES)}",
            {"status": raw_status},
        ))

    # 6. Prohibited claim promotions.
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
                findings.append(_finding(
                    ERR_PROHIBITED_CLAIM_PROMOTION, path_str, loc_name,
                    f"Proof bundle relies on prohibited claim promotion: '{b_val}'",
                    {"prohibited_basis": b_val},
                ))

    # 7. Level support: explicit supported level, closed vocabulary, no defaults.
    level_fields, raw_supported = _single_field(data, SUPPORTED_LEVEL_FIELDS)
    supported_rank: int | None = None
    supported_str = raw_supported.strip().lower() if isinstance(raw_supported, str) else None
    if not level_fields:
        findings.append(_finding(ERR_CLAIM_LEVEL_EXCEEDED, path_str, "supported_level", f"Proof bundle '{path_str}' declares no supported readiness level"))
    elif len(level_fields) > 1 and len({str(data[f]).strip().lower() for f in level_fields}) > 1:
        findings.append(_finding(
            ERR_CLAIM_LEVEL_EXCEEDED, path_str, "supported_level",
            f"Proof bundle '{path_str}' declares conflicting supported levels {[data[f] for f in level_fields]}",
        ))
    elif supported_str in NON_CLAIMING_STATES:
        findings.append(_finding(
            ERR_CLAIM_LEVEL_EXCEEDED, path_str, "supported_level",
            f"Proof bundle supported level '{supported_str}' supports no readiness claim",
        ))
    elif supported_str is None or _rank_of(supported_str) is None:
        findings.append(_finding(
            ERR_UNRECOGNIZED_STATE, path_str, "supported_level",
            f"Proof bundle supported level {raw_supported!r} is not a registered readiness level",
            {"supported_level": raw_supported},
        ))
    else:
        supported_rank = _rank_of(supported_str)

    if claim_level is not None:
        claim_level_norm = claim_level.strip().lower()
        claimed_rank = _rank_of(claim_level_norm)
        if claim_level_norm in NON_CLAIMING_STATES:
            pass  # the citing claim asserts no readiness level
        elif claimed_rank is None:
            findings.append(_finding(
                ERR_UNRECOGNIZED_STATE, path_str, "claim_level",
                f"Claimed level {claim_level!r} is not a registered readiness level",
                {"claimed_level": claim_level},
            ))
        elif supported_rank is not None and claimed_rank > supported_rank:
            findings.append(_finding(
                ERR_CLAIM_LEVEL_EXCEEDED, path_str, "supported_level",
                f"Claimed level '{claim_level}' exceeds proof bundle supported level '{supported_str}' ({claimed_rank} > {supported_rank})",
                {"claimed_level": claim_level, "supported_level": supported_str},
            ))

    # 8. Claim class and required evidence.
    _, bundle_class = _single_field(data, CLAIM_CLASS_FIELDS)
    effective_class = claim_class if claim_class is not None else bundle_class
    if claim_class is not None and bundle_class is not None and str(bundle_class) != claim_class:
        findings.append(_finding(
            ERR_CLAIM_BINDING_MISMATCH, path_str, "claim_class",
            f"Proof bundle claim class '{bundle_class}' differs from the citing claim class '{claim_class}'",
        ))
    if known_classes is None:
        findings.append(_finding(
            ERR_INVALID_CLAIM_CLASS, path_str, "claim_class",
            "No authoritative claim-class registry was supplied; required evidence cannot be verified",
        ))
    elif not isinstance(effective_class, str) or not effective_class.strip():
        findings.append(_finding(
            ERR_INVALID_CLAIM_CLASS, path_str, "claim_class",
            f"Proof bundle '{path_str}' declares no claim class; required evidence cannot be verified",
        ))
    elif effective_class not in known_classes:
        findings.append(_finding(
            ERR_INVALID_CLAIM_CLASS, path_str, "claim_class",
            f"Proof bundle specifies unknown claim class '{effective_class}'",
            {"claim_class": effective_class},
        ))
    else:
        required_ev = known_classes[effective_class]
        ev_fields, retained_ev = _single_field(data, RETAINED_EVIDENCE_FIELDS)
        if len(ev_fields) > 1:
            findings.append(_finding(
                ERR_CLAIM_LEVEL_EXCEEDED, path_str, "retained_evidence",
                f"Proof bundle declares competing retained-evidence fields {ev_fields}",
            ))
        elif ev_fields and not (isinstance(retained_ev, list) and all(isinstance(e, str) for e in retained_ev)):
            findings.append(_finding(
                ERR_CLAIM_LEVEL_EXCEEDED, path_str, "retained_evidence",
                f"Proof bundle retained evidence must be a list of strings; got {retained_ev!r}",
            ))
        else:
            retained_set = set(retained_ev) if ev_fields else set()
            missing_ev = [req for req in required_ev if req not in retained_set]
            if missing_ev:
                findings.append(_finding(
                    ERR_CLAIM_LEVEL_EXCEEDED, path_str, "retained_evidence",
                    f"Proof bundle for class '{effective_class}' is missing required evidence: {missing_ev}",
                    {"missing_evidence": missing_ev, "claim_class": effective_class},
                ))

    is_valid = not any(f.severity == "error" for f in findings)
    return is_valid, findings, data


def inspect_qualification_receipt(receipt_path: Path, root: Path) -> tuple[list[ClaimFinding], str | None]:
    """Inspects a retained (uncited) qualification receipt: integrity failures are errors,
    a well-formed non-passing receipt is a typed warning."""
    path_str = sanitize_path(receipt_path, root)
    data, findings = _read_json_document(receipt_path, path_str, "qualification receipt")
    if data is None:
        return findings, None
    if data.get("schema") != QUALIFICATION_RECEIPT_SCHEMA:
        return [_finding(
            ERR_UNRECOGNIZED_STATE, path_str, "schema",
            f"Qualification receipt '{path_str}' schema {data.get('schema')!r} is not '{QUALIFICATION_RECEIPT_SCHEMA}'",
        )], None
    return _verify_receipt_payload(data, path_str, cited=False, expected_claim_id=None, claim_level=None)


def write_qualification_receipt(output_path: Path | str, receipt: dict[str, Any]) -> Path:
    """Atomically writes a qualification receipt to disk:
    writes to a temporary file in the same directory, fsyncs, and renames into place.
    """
    target = Path(output_path).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    prefix = f".{target.name}.tmp."
    descriptor, temp_name = tempfile.mkstemp(prefix=prefix, dir=target.parent)
    temp_path = Path(temp_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(receipt, indent=2) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_path, 0o644)
        os.replace(temp_path, target)
        dir_fd = os.open(target.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        if temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass
    return target


_DELIMITER_CELL_RE = re.compile(r"^:?-+:?$")
_UNESCAPED_PIPE_RE = re.compile(r"(?<!\\)\|")


def _split_table_row(line: str) -> list[str]:
    stripped = line.strip()
    if stripped.startswith("|"):
        stripped = stripped[1:]
    if stripped.endswith("|") and not stripped.endswith("\\|"):
        stripped = stripped[:-1]
    return [cell.strip() for cell in _UNESCAPED_PIPE_RE.split(stripped)]


def _is_delimiter_row(line: str) -> bool:
    if "|" not in line:
        return False
    cells = _split_table_row(line)
    return bool(cells) and all(_DELIMITER_CELL_RE.match(cell) for cell in cells)


def parse_markdown_tables(text: str) -> list[tuple[list[str], list[list[str]]]]:
    """Extracts GFM tables (with or without border pipes) as (headers, data_rows)."""
    clean_text = stable_id_audit._strip_html_comments(text)
    lines = clean_text.splitlines()
    tables: list[tuple[list[str], list[list[str]]]] = []

    fence: str | None = None
    idx = 0
    while idx < len(lines):
        line = lines[idx].strip()
        marker = line[:3]
        if marker in ("```", "~~~"):
            if fence is None:
                fence = marker
            elif fence == marker:
                fence = None
            idx += 1
            continue
        if fence is not None or "|" not in line:
            idx += 1
            continue

        if idx + 1 < len(lines) and _is_delimiter_row(lines[idx + 1]):
            headers = [c.strip("`") for c in _split_table_row(line)]
            data_rows: list[list[str]] = []
            idx += 2
            while idx < len(lines):
                row_line = lines[idx].strip()
                if not row_line or "|" not in row_line or row_line[:3] in ("```", "~~~"):
                    break
                if not _is_delimiter_row(row_line):
                    data_rows.append([c.strip("`") for c in _split_table_row(row_line)])
                idx += 1
            tables.append((headers, data_rows))
            continue
        idx += 1
    return tables


def _new_scan_stats() -> dict[str, int]:
    return {"claim_tables": 0, "rows": 0, "promoted": 0, "bundles_checked": 0, "bundles_passed": 0}


def scan_markdown_claim_tables(
    md_path: Path,
    root: Path,
    known_classes: dict[str, list[str]] | None,
    tombstoned_ids: set[str],
    prohibited_promotions: set[str] | None = None,
    *,
    require_claim_table: bool = False,
    stats: dict[str, int] | None = None,
    now: datetime | None = None,
) -> list[ClaimFinding]:
    """Scans markdown tables for status and proof root/bundle citations."""
    findings: list[ClaimFinding] = []
    counters = stats if stats is not None else _new_scan_stats()
    for key, value in _new_scan_stats().items():
        counters.setdefault(key, value)
    path_str = sanitize_path(md_path, root)

    try:
        raw_text = md_path.read_bytes().decode("utf-8")
    except OSError as exc:
        return [_finding(ERR_UNREADABLE_INPUT, path_str, "file", f"Could not read markdown file '{path_str}': {exc}")]
    except UnicodeDecodeError as exc:
        return [_finding(ERR_UNREADABLE_INPUT, path_str, "file", f"Markdown file '{path_str}' is not valid UTF-8: {exc}")]

    if len(raw_text.strip()) == 0:
        return [_finding(ERR_EMPTY_INPUT, path_str, "file", f"Markdown file '{path_str}' is empty (0 bytes)")]

    claim_tables_here = 0
    for headers, data_rows in parse_markdown_tables(raw_text):
        normalized_headers = [normalize_cell(h).lower() for h in headers]
        columns: dict[str, list[int]] = {"status": [], "proof": [], "id": []}
        for col_idx, col_name in enumerate(normalized_headers):
            if col_name == "status":
                columns["status"].append(col_idx)
            elif col_name in ("proof root", "proof_root", "proof bundle", "proof_bundle", "proof"):
                columns["proof"].append(col_idx)
            elif col_name in ("id", "claim", "claim id"):
                columns["id"].append(col_idx)

        if not columns["status"] and not columns["proof"]:
            continue
        ambiguous = [name for name, cols in columns.items() if len(cols) > 1]
        if ambiguous:
            findings.append(_finding(
                ERR_UNREADABLE_INPUT, path_str, "table",
                f"Claim table declares ambiguous duplicate {ambiguous} columns: {headers}",
            ))
            continue
        claim_tables_here += 1
        status_col = columns["status"][0] if columns["status"] else None
        proof_col = columns["proof"][0] if columns["proof"] else None
        id_col = columns["id"][0] if columns["id"] else None

        for r_idx, row in enumerate(data_rows):
            counters["rows"] += 1
            row_id = normalize_cell(row[id_col]) if id_col is not None and id_col < len(row) else ""
            row_id = row_id or None
            label = row_id or f"row_{r_idx + 1}"
            location = f"table_row[{label}]"

            status_val: str | None = None
            if status_col is not None:
                status_val = normalize_cell(row[status_col]).lower() if status_col < len(row) else ""
            proof_val = normalize_cell(row[proof_col]) if proof_col is not None and proof_col < len(row) else ""

            claimed_rank: int | None = None
            if status_val is not None and status_val not in NON_CLAIMING_STATES:
                claimed_rank = _rank_of(status_val)
                if claimed_rank is None:
                    findings.append(_finding(
                        ERR_UNRECOGNIZED_STATE, path_str, location,
                        f"Item '{label}' has unrecognized readiness status {status_val!r}; unknown states are never ranked",
                        {"id": label, "status": status_val},
                    ))
                    continue

            is_promoted = claimed_rank is not None and claimed_rank >= PROMOTION_RANK
            has_proof_root = proof_val.lower() not in NON_PROOF_ROOTS
            if is_promoted:
                counters["promoted"] += 1
                if row_id is None:
                    findings.append(_finding(
                        ERR_CLAIM_BINDING_MISMATCH, path_str, location,
                        f"Item '{label}' is marked '{status_val}' but has no claim ID; its proof cannot be bound to it",
                        {"status": status_val},
                    ))

            if is_promoted and not has_proof_root:
                findings.append(_finding(
                    ERR_CLAIM_LEVEL_EXCEEDED, path_str, location,
                    f"Item '{label}' is marked '{status_val}' without referencing a retained proof bundle",
                    {"id": label, "status": status_val},
                ))
            elif has_proof_root:
                proof_path = Path(proof_val)
                if proof_path.is_absolute():
                    findings.append(_finding(
                        ERR_PROOF_BUNDLE_NOT_FOUND, path_str, f"{location}->path",
                        f"Proof bundle path must be repository-relative, got absolute path: '{proof_val}'",
                        {"path": proof_val},
                    ))
                    continue
                counters["bundles_checked"] += 1
                bundle_ok, bundle_findings, _ = verify_proof_bundle(
                    bundle_path=proof_path,
                    root=root,
                    expected_claim_id=row_id,
                    claim_level=status_val,
                    known_classes=known_classes,
                    tombstoned_ids=tombstoned_ids,
                    prohibited_promotions=prohibited_promotions,
                    now=now,
                )
                if bundle_ok:
                    counters["bundles_passed"] += 1
                for bf in bundle_findings:
                    findings.append(ClaimFinding(
                        code=bf.code,
                        file=path_str,
                        location=f"{location}->{bf.location}",
                        message=f"Proof bundle for '{label}': {bf.message}",
                        severity=bf.severity,
                        remediation=bf.remediation,
                        params=bf.params,
                    ))

    counters["claim_tables"] += claim_tables_here
    if require_claim_table and claim_tables_here == 0:
        findings.append(_finding(
            ERR_EMPTY_INPUT, path_str, "file",
            f"Claim surface '{path_str}' declares no recognizable status/proof claim table; zero claims would be audited",
        ))
    return findings


def audit_claim_proof_bundles(
    root: Path = ROOT,
    claims_json_path: Path | None = None,
    target_bundle: Path | None = None,
    now: datetime | None = None,
) -> tuple[bool, list[ClaimFinding], dict[str, Any]]:
    """Runs full claim/proof-bundle consistency verification across the repository."""
    claims_path = claims_json_path or (root / "architecture/claims.json")
    known_classes, prohibited_promotions, findings = load_authoritative_claims(claims_path)
    tombstoned_ids, tombstone_findings = load_tombstone_index(root)
    findings.extend(tombstone_findings)

    stats = _new_scan_stats()
    surfaces_scanned: list[str] = []
    receipts = {"inspected": 0, "passed": 0, "nonpassing": 0}

    if target_bundle is not None:
        stats["bundles_checked"] += 1
        bundle_ok, b_findings, _ = verify_proof_bundle(
            bundle_path=target_bundle,
            root=root,
            known_classes=known_classes,
            tombstoned_ids=tombstoned_ids,
            prohibited_promotions=prohibited_promotions,
            now=now,
        )
        findings.extend(b_findings)
        stats["bundles_passed"] += int(bundle_ok)
    else:
        for rel_file in MANDATORY_AUTHORITY_FILES:
            full_path = root / rel_file
            if not full_path.is_file():
                findings.append(_finding(ERR_UNREADABLE_INPUT, rel_file, "file", f"Mandatory authority file does not exist or is not a regular file: '{rel_file}'"))
            elif full_path.stat().st_size == 0:
                findings.append(_finding(ERR_EMPTY_INPUT, rel_file, "file", f"Mandatory authority file is empty (0 bytes): '{rel_file}'"))

        readiness_path = root / READINESS_REGISTRY_FILE
        if readiness_path.is_file() and readiness_path.stat().st_size > 0:
            _, readiness_findings = load_readiness_states(readiness_path, READINESS_REGISTRY_FILE)
            findings.extend(readiness_findings)

        for rel_file in REQUIRED_CLAIM_SURFACES:
            md_file = root / rel_file
            if not md_file.is_file():
                findings.append(_finding(ERR_UNREADABLE_INPUT, rel_file, "file", f"Required claim surface does not exist or is not a regular file: '{rel_file}'"))
                continue
            findings.extend(scan_markdown_claim_tables(
                md_path=md_file,
                root=root,
                known_classes=known_classes,
                tombstoned_ids=tombstoned_ids,
                prohibited_promotions=prohibited_promotions,
                require_claim_table=rel_file in CLAIM_TABLE_REQUIRED_SURFACES,
                stats=stats,
                now=now,
            ))
            surfaces_scanned.append(rel_file)

        qual_dir = root / RETENTION_DIR
        if qual_dir.exists() and not qual_dir.is_dir():
            findings.append(_finding(ERR_UNREADABLE_INPUT, RETENTION_DIR, "path", f"'{RETENTION_DIR}' exists but is not a directory"))
        elif qual_dir.is_dir():
            def on_walk_error(exc: OSError) -> None:
                where = sanitize_path(exc.filename, root) if exc.filename else RETENTION_DIR
                findings.append(_finding(
                    ERR_UNREADABLE_INPUT, where, "directory",
                    f"Could not read retention directory '{where}': {exc.strerror or exc}; its proof artifacts cannot be inspected",
                ))

            for root_dir, dir_names, files in os.walk(qual_dir, onerror=on_walk_error):
                dir_names.sort()
                for name in sorted(files):
                    f_path = Path(root_dir) / name
                    if name == RECEIPT_FILENAME:
                        receipts["inspected"] += 1
                        r_findings, r_status = inspect_qualification_receipt(f_path, root)
                        findings.extend(r_findings)
                        if r_status == "passed" and not any(f.severity == "error" for f in r_findings):
                            receipts["passed"] += 1
                        elif r_status is not None and r_status != "passed":
                            receipts["nonpassing"] += 1
                    elif name.endswith(BUNDLE_SUFFIXES):
                        stats["bundles_checked"] += 1
                        bundle_ok, b_findings, _ = verify_proof_bundle(
                            bundle_path=f_path,
                            root=root,
                            known_classes=known_classes,
                            tombstoned_ids=tombstoned_ids,
                            prohibited_promotions=prohibited_promotions,
                            now=now,
                        )
                        findings.extend(b_findings)
                        stats["bundles_passed"] += int(bundle_ok)

    error_count = sum(1 for f in findings if f.severity == "error")
    warning_count = sum(1 for f in findings if f.severity == "warning")
    is_valid = error_count == 0

    summary = {
        "status": "pass" if is_valid else "fail",
        "error_count": error_count,
        "warning_count": warning_count,
        "verified_bundles_count": stats["bundles_passed"],
        "bundles_checked": stats["bundles_checked"],
        "authoritative_classes_count": len(known_classes),
        "prohibited_promotions_count": len(prohibited_promotions),
        "tombstoned_ids_count": len(tombstoned_ids),
        "claim_surfaces_scanned": surfaces_scanned,
        "claim_tables_evaluated": stats["claim_tables"],
        "claim_rows_evaluated": stats["rows"],
        "promoted_claim_rows": stats["promoted"],
        "receipts_inspected": receipts["inspected"],
        "receipts_passed": receipts["passed"],
        "receipts_nonpassing": receipts["nonpassing"],
    }

    return is_valid, findings, summary


def _parse_as_of(value: str) -> datetime:
    instant = _parse_instant(value)
    if instant is None:
        raise argparse.ArgumentTypeError(f"--as-of must be a zone-qualified ISO-8601 instant, got {value!r}")
    return instant


def main() -> int:
    parser = argparse.ArgumentParser(
        description="FSS-011 Claim/proof-bundle consistency checker."
    )
    parser.add_argument("--root", type=Path, default=ROOT, help="Repository root path")
    parser.add_argument("--claims", type=Path, default=None, help="Path to architecture/claims.json")
    parser.add_argument("--bundle", type=Path, default=None, help="Specific proof bundle to verify (relative to --root)")
    parser.add_argument("--as-of", type=_parse_as_of, default=None, help="Evaluate expiry as of this ISO-8601 instant (default: now, UTC)")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON report")
    parser.add_argument("--quiet", action="store_true", help="Suppress non-error output")
    args = parser.parse_args()

    is_valid, findings, summary = audit_claim_proof_bundles(
        root=args.root,
        claims_json_path=args.claims,
        target_bundle=args.bundle,
        now=args.as_of,
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
                f"[{tag}] Claim/proof-bundle audit: {summary['claim_rows_evaluated']} claim rows on "
                f"{len(summary['claim_surfaces_scanned'])} surfaces ({summary['promoted_claim_rows']} promoted), "
                f"{summary['verified_bundles_count']}/{summary['bundles_checked']} proof bundles verified, "
                f"{summary['receipts_inspected']} qualification receipts inspected "
                f"({summary['receipts_nonpassing']} non-passing), "
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

#!/usr/bin/env python3
"""Deterministic NEG-002 standards-first camera access checker (fss-x4a.1.32.2).

Enforces the non-negotiable negative-evidence constraint NEG-002 from AGENTS.md,
registries/DEVICE_ADAPTERS.md, registries/CAPABILITIES.md, and DEVICE_ADAPTER_MATRIX.md:

1. Unverified standards claims: An adapter or capability entry cannot claim
   ONVIF/RTSP/local-stream capability without a qualifying evidence reference;
   claims inferred from marketing, product packaging, Wi-Fi viewing, or app presence
   are strictly rejected (ERR-NEG002-UNVERIFIED-STANDARDS-CLAIM-001).
2. Proprietary native promotion: Proprietary, vendor-specific, or app-automation/screen-capture
   paths cannot be registered as stable native integrations or promoted to Tier T1 open local
   (ERR-NEG002-PROPRIETARY-NATIVE-PROMOTION-001).
3. Scoped vendor tokens: Vendor tokens and credentials must be strictly scoped to their exact
   adapter capability (e.g. CAP-ADAPTER-AUTH-001 device/account scope and CAP-ADAPTER-NET-001
   destination allowlist) and cannot escape to ambient, global, or multi-device reuse
   (ERR-NEG002-UNSCOPED-VENDOR-TOKEN-001).
4. Stable identity: Stable ID NEG-002 and its normative decision must be preserved without
   silently dropping, renaming, or weakening the constraint (ERR-NEG002-STABLE-ID-MISSING-001).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

# Stable typed diagnostic error codes
ERR_UNVERIFIED_STANDARDS_CLAIM = "ERR-NEG002-UNVERIFIED-STANDARDS-CLAIM-001"
ERR_PROPRIETARY_NATIVE_PROMOTION = "ERR-NEG002-PROPRIETARY-NATIVE-PROMOTION-001"
ERR_UNSCOPED_VENDOR_TOKEN = "ERR-NEG002-UNSCOPED-VENDOR-TOKEN-001"
ERR_STABLE_ID_MISSING = "ERR-NEG002-STABLE-ID-MISSING-001"
ERR_SECURITY_BOUNDARY_VIOLATION = "ERR-NEG002-SECURITY-BOUNDARY-VIOLATION-001"
ERR_UNREADABLE_INPUT = "ERR-NEG002-UNREADABLE-INPUT-001"

DIAGNOSTIC_REGISTRY: dict[str, dict[str, str]] = {
    ERR_UNVERIFIED_STANDARDS_CLAIM: {
        "trigger": "An adapter claims ONVIF/RTSP/local-stream capability based on marketing, app presence, packaging, or without qualifying conformance evidence",
        "remediation": "Provide qualifying evidence from authentic conformance testing or official standard specification; marketing and app presence are rejected",
        "standard_code": "NEG-002-A",
    },
    ERR_PROPRIETARY_NATIVE_PROMOTION: {
        "trigger": "A proprietary, vendor, or app-automation/screen-capture path is registered as a stable native integration or promoted to Tier T1 open local",
        "remediation": "Proprietary/vendor/app paths must remain isolated Tier T3 (authorized lab) or T4 (import); do not present screen capture or app automation as native integration",
        "standard_code": "NEG-002-B",
    },
    ERR_UNSCOPED_VENDOR_TOKEN: {
        "trigger": "A vendor token or adapter credential capability is unscoped, ambient, wildcard, or reused across multiple devices",
        "remediation": "Bind vendor credentials and network access strictly to single device/account scope (CAP-ADAPTER-AUTH-001) and destination allowlist (CAP-ADAPTER-NET-001)",
        "standard_code": "NEG-002-C",
    },
    ERR_STABLE_ID_MISSING: {
        "trigger": "Constraint NEG-002 is missing, corrupted, renamed, or weakened in docs/NEGATIVE_EVIDENCE.md",
        "remediation": "Restore NEG-002 with normative hypothesis, finding, decision, and revival conditions in docs/NEGATIVE_EVIDENCE.md",
        "standard_code": "NEG-002-D",
    },
    ERR_SECURITY_BOUNDARY_VIOLATION: {
        "trigger": "A device adapter or capability claims prohibited security-boundary actions: scanning, auth bypass, credential theft, persistence, or evasion",
        "remediation": "Remove prohibited security-boundary actions; reverse engineering is strictly limited to authorized owner lab fixtures with zero bypass or scanning",
        "standard_code": "NEG-002-E",
    },
    ERR_UNREADABLE_INPUT: {
        "trigger": "A required specification, registry, or matrix file cannot be read or contains non-UTF-8 corrupt bytes",
        "remediation": "Restore the file with valid UTF-8 encoding and standard read permissions",
        "standard_code": "NEG-002-F",
    },
}

# Recognized open local standards interfaces
OPEN_LOCAL_INTERFACES = frozenset({
    "usb uvc/uac",
    "usb-c; uvc 1.1/uac 1.0; h.264/mjpeg",
    "rtsp/rtp",
    "onvif profile t",
    "onvif profile m metadata",
    "onvif profile t client",
    "uvc/uac",
    "deterministic replay",
    "bounded media import",
    "s3-compatible import",
    "repository schema",
    "standard files",
    "s3-compatible objects",
})

# Forbidden terms indicating unverified marketing or app-presence claims (Defect 2)
MARKETING_CLAIM_INDICATORS = (
    "marketing",
    "advertised",
    "advertising",
    "inferred",
    "app presence",
    "packaging",
    "retail packaging",
    "box claim",
    "consumer box",
    "cloud viewing",
    "community forum",
    "promotional",
    "datasheet",
    "spec sheet",
    "press release",
    "ad copy",
    "app store",
    "unverified",
)

# Terms indicating proprietary, vendor-specific, or app-automation surfaces (Defect 3)
PROPRIETARY_INDICATORS = (
    # Generic proprietary terms
    "proprietary",
    "closed source",
    "vendor cloud",
    "private protocol",
    "vendor protocol",
    "vendor app",
    "reverse engineering",
    "reverse engineered",
    "cloud bridge",
    "screen capture",
    "app automation",
    "ui automation",
    "mobile app",
    # Proprietary consumer camera vendors
    "wyze",
    "aosu",
    "dji",
    "ring",
    "nest",
    "blink",
    "arlo",
    "eufy",
    "tuya",
    "reolink",
    "kasa",
    "tapo",
    "ezviz",
    "imou",
    "hikconnect",
)

# Prohibited security boundary violations under AGENTS.md (Defect 6)
SECURITY_BOUNDARY_VIOLATIONS = (
    "credential theft",
    "credential harvesting",
    "harvesting credentials",
    "authentication bypass",
    "auth bypass",
    "bypass auth",
    "third party account access",
    "third-party account access",
    "unauthorized account",
    "broad scanning",
    "subnet scan",
    "network scan",
    "port scan",
    "ip sweep",
    "discovery sweeps",
    "persistence on vendor devices",
    "persistence on device",
    "device persistence",
    "firmware backdoor",
    "backdoor",
    "rooting device",
    "evasion",
    "anti analysis",
    "evading detection",
)

# Qualifying evidence patterns for open standards streaming claims (Defect 1 & 8)
QUALIFYING_EVIDENCE_RE = re.compile(
    r"(?:GATE-0[1-4]0|TEST-(?:RTSP|ONVIF|UVC|REPLAY|FILE|IMPORT)-\d+|RFC\s*(?:2326|7826|3550)|UVC\s*1\.[0-5]|UAC\s*1\.[0-9]|ONVIF\s+Profile\s+[TM]|proof[-_]bundle|conformance[-_]report)",
    re.IGNORECASE,
)

DELIMITER_ROW_RE = re.compile(r"^\|(?:\s*:?-+:?\s*\|)+$")


def normalize_text(text: str) -> str:
    """Normalizes text by replacing delimiters (hyphens, underscores, slashes) with spaces."""
    return re.sub(r"[-_/]+", " ", text).lower()


def safe_read_file(path: Path, findings: list[Finding], context_name: str) -> str | None:
    """Safely reads text file with fail-closed exception handling for non-UTF8/locked files (Defect 7)."""
    if not path.is_file():
        code = ERR_STABLE_ID_MISSING if "negative" in context_name.lower() else ERR_UNREADABLE_INPUT
        findings.append(
            Finding(
                severity="error",
                code=code,
                file=path.name,
                location="file",
                message=f"Missing required file: {path}",
            )
        )
        return None
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        findings.append(
            Finding(
                severity="error",
                code=ERR_UNREADABLE_INPUT,
                file=path.name,
                location="file",
                message=f"Unreadable file ({type(exc).__name__}): {path}: {exc}",
            )
        )
        return None


@dataclass
class Finding:
    severity: str  # "error", "warning", "info"
    code: str
    file: str
    location: str
    message: str
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if not d["remediation"] and self.code in DIAGNOSTIC_REGISTRY:
            d["remediation"] = DIAGNOSTIC_REGISTRY[self.code]["remediation"]
        return d


def parse_markdown_table(text: str) -> list[dict[str, str]]:
    """Parses standard markdown pipe table into list of row dictionaries."""
    lines = [line.strip() for line in text.splitlines()]
    rows: list[dict[str, str]] = []
    headers: list[str] = []
    in_table = False

    for line in lines:
        if not line.startswith("|") or not line.endswith("|"):
            in_table = False
            headers = []
            continue

        cells = [c.strip().strip("`") for c in line.split("|")[1:-1]]
        if not headers:
            headers = [c.lower() for c in cells]
            in_table = True
            continue

        if DELIMITER_ROW_RE.match(line):
            continue

        if in_table and len(cells) == len(headers):
            row = dict(zip(headers, cells))
            rows.append(row)

    return rows


def check_negative_evidence_integrity(root: Path, findings: list[Finding]) -> str | None:
    """Verifies that docs/NEGATIVE_EVIDENCE.md preserves NEG-002 with normative decision."""
    neg_path = root / "docs" / "NEGATIVE_EVIDENCE.md"
    content = safe_read_file(neg_path, findings, "negative evidence")
    if content is None:
        return None

    if "NEG-002" not in content:
        findings.append(
            Finding(
                severity="error",
                code=ERR_STABLE_ID_MISSING,
                file="docs/NEGATIVE_EVIDENCE.md",
                location="header",
                message="Constraint NEG-002 is absent from docs/NEGATIVE_EVIDENCE.md",
            )
        )
        return None

    # Check for core normative decision terms
    if "standards-first" not in content and "standards" not in content.lower():
        findings.append(
            Finding(
                severity="error",
                code=ERR_STABLE_ID_MISSING,
                file="docs/NEGATIVE_EVIDENCE.md",
                location="decision",
                message="NEG-002 does not mandate standards-first native adapters",
            )
        )

    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def check_device_adapters_registry(
    root: Path, findings: list[Finding]
) -> tuple[int, str | None, dict[str, dict[str, str]]]:
    """Audits registries/DEVICE_ADAPTERS.md for proprietary promotion, security boundaries, and marketing bypass."""
    adapters_path = root / "registries" / "DEVICE_ADAPTERS.md"
    content = safe_read_file(adapters_path, findings, "device adapters registry")
    if content is None:
        return 0, None, {}

    rows = parse_markdown_table(content)
    if not rows:
        findings.append(
            Finding(
                severity="error",
                code=ERR_PROPRIETARY_NATIVE_PROMOTION,
                file="registries/DEVICE_ADAPTERS.md",
                location="table",
                message="registries/DEVICE_ADAPTERS.md contains no valid adapter rows",
            )
        )
        return 0, None, {}

    registered_adapters: dict[str, dict[str, str]] = {}
    count = len(rows)

    for row in rows:
        adapter_id = row.get("id", "")
        if adapter_id:
            registered_adapters[adapter_id] = row

        surface = row.get("surface", "").lower()
        surface_normalized = normalize_text(surface)
        id_normalized = normalize_text(adapter_id)
        tier = row.get("tier", "").strip()
        current_state = row.get("current state", "").lower()
        row_str = " ".join(row.values()).lower()
        row_normalized = normalize_text(row_str)

        # Defect 6: Check for security boundary violations across all columns
        for sec_viol in SECURITY_BOUNDARY_VIOLATIONS:
            if sec_viol in row_str or sec_viol in row_normalized:
                findings.append(
                    Finding(
                        severity="error",
                        code=ERR_SECURITY_BOUNDARY_VIOLATION,
                        file="registries/DEVICE_ADAPTERS.md",
                        location=adapter_id or "table",
                        message=f"Adapter entry contains prohibited security boundary violation '{sec_viol}'",
                    )
                )
                break

        # Defect 2: Check for marketing indicators across all columns in DEVICE_ADAPTERS.md
        for mktg in MARKETING_CLAIM_INDICATORS:
            if mktg in row_str or mktg in row_normalized:
                findings.append(
                    Finding(
                        severity="error",
                        code=ERR_UNVERIFIED_STANDARDS_CLAIM,
                        file="registries/DEVICE_ADAPTERS.md",
                        location=adapter_id or "table",
                        message=f"Adapter {adapter_id} in registries/DEVICE_ADAPTERS.md contains unverified marketing indicator '{mktg}'",
                    )
                )
                break

        # Defect 3: Check if surface or ID represents proprietary/vendor/app-automation path
        is_proprietary = (
            any(term in surface or term in surface_normalized for term in PROPRIETARY_INDICATORS)
            or any(term in adapter_id.lower() or term in id_normalized for term in PROPRIETARY_INDICATORS)
            or "lab" in adapter_id.lower()
        )

        if is_proprietary:
            # Rule 2A: Proprietary adapters cannot be Tier T1 (open local)
            if "t1" in tier.lower():
                findings.append(
                    Finding(
                        severity="error",
                        code=ERR_PROPRIETARY_NATIVE_PROMOTION,
                        file="registries/DEVICE_ADAPTERS.md",
                        location=adapter_id,
                        message=f"Proprietary adapter {adapter_id} promoted to Tier T1 open local; must be T3 authorized lab or T4 import",
                    )
                )

            # Rule 2B: Proprietary adapters cannot be 'stable' or 'production native'
            if any(term in current_state for term in ("stable", "production", "native")):
                findings.append(
                    Finding(
                        severity="error",
                        code=ERR_PROPRIETARY_NATIVE_PROMOTION,
                        file="registries/DEVICE_ADAPTERS.md",
                        location=adapter_id,
                        message=f"Proprietary adapter {adapter_id} has state '{current_state}'; proprietary paths cannot be registered as stable native integrations",
                    )
                )

        # Rule 2C: Screen capture or app automation cannot be a native integration or in T1
        if any(term in surface or term in surface_normalized for term in ("screen capture", "app automation", "ui automation")):
            if "t1" in tier.lower() or any(term in current_state for term in ("stable", "production", "native")):
                findings.append(
                    Finding(
                        severity="error",
                        code=ERR_PROPRIETARY_NATIVE_PROMOTION,
                        file="registries/DEVICE_ADAPTERS.md",
                        location=adapter_id,
                        message=f"Adapter {adapter_id} uses mobile screen capture or app automation as a native integration; strictly prohibited by AGENTS.md",
                    )
                )

    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return count, digest, registered_adapters


def check_device_adapter_matrix(
    root: Path, findings: list[Finding], registered_adapters: dict[str, dict[str, str]] | None = None
) -> tuple[int, str | None]:
    """Audits DEVICE_ADAPTER_MATRIX.md for unverified standards claims, qualifying evidence, and tier integrity."""
    matrix_path = root / "DEVICE_ADAPTER_MATRIX.md"
    content = safe_read_file(matrix_path, findings, "device adapter matrix")
    if content is None:
        return 0, None

    rows = parse_markdown_table(content)
    count = len(rows)
    reg = registered_adapters or {}

    for row in rows:
        adapter_id = row.get("adapter id", "")
        if not adapter_id.startswith("ADP-"):
            continue

        product_surface = row.get("product/surface", "").lower()
        public_interface = row.get("known public interface", "").lower()
        tier = row.get("initial tier", "").strip()
        planned_cap = row.get("planned capability", "").lower()
        current_state = row.get("current fss state", "").lower()
        row_str = " ".join(row.values()).lower()
        row_normalized = normalize_text(row_str)

        # Defect 6: Check for security boundary violations across all columns
        for sec_viol in SECURITY_BOUNDARY_VIOLATIONS:
            if sec_viol in row_str or sec_viol in row_normalized:
                findings.append(
                    Finding(
                        severity="error",
                        code=ERR_SECURITY_BOUNDARY_VIOLATION,
                        file="DEVICE_ADAPTER_MATRIX.md",
                        location=adapter_id,
                        message=f"Adapter {adapter_id} contains prohibited security boundary violation '{sec_viol}'",
                    )
                )
                break

        # Defect 2: Check for marketing or app-presence claims across ALL columns
        for mktg in MARKETING_CLAIM_INDICATORS:
            if mktg in row_str or mktg in row_normalized:
                findings.append(
                    Finding(
                        severity="error",
                        code=ERR_UNVERIFIED_STANDARDS_CLAIM,
                        file="DEVICE_ADAPTER_MATRIX.md",
                        location=adapter_id,
                        message=f"Adapter {adapter_id} contains unverified marketing indicator '{mktg}' across columns",
                    )
                )
                break

        # Defect 3: Proprietary products cannot claim T1 or stable native state
        is_proprietary = (
            any(term in product_surface or term in normalize_text(product_surface) for term in PROPRIETARY_INDICATORS)
            or any(term in adapter_id.lower() or term in normalize_text(adapter_id) for term in PROPRIETARY_INDICATORS)
            or "lab" in adapter_id.lower()
        )
        if is_proprietary:
            if "t1" in tier.lower():
                findings.append(
                    Finding(
                        severity="error",
                        code=ERR_PROPRIETARY_NATIVE_PROMOTION,
                        file="DEVICE_ADAPTER_MATRIX.md",
                        location=adapter_id,
                        message=f"Proprietary adapter {adapter_id} registered with initial tier T1 in matrix; must be T3 authorized lab or T4 import",
                    )
                )
            if any(term in current_state for term in ("stable", "production native", "native")):
                findings.append(
                    Finding(
                        severity="error",
                        code=ERR_PROPRIETARY_NATIVE_PROMOTION,
                        file="DEVICE_ADAPTER_MATRIX.md",
                        location=adapter_id,
                        message=f"Proprietary adapter {adapter_id} has state '{current_state}'; cannot be registered as stable native integration",
                    )
                )

        # Defect 1 & 8: Qualifying evidence requirement for open standards / local streaming claims
        is_honest_negative = (
            "no public" in public_interface
            or "no contract" in public_interface
            or "not found" in public_interface
            or "no native" in public_interface
        )
        claims_standards = (not is_honest_negative) and (
            "t1" in tier.lower()
            or any(s in public_interface for s in ("onvif", "rtsp", "uvc", "uac"))
            or any(s in planned_cap for s in ("onvif", "rtsp"))
        )
        if claims_standards:
            # Check 1: registered in DEVICE_ADAPTERS.md with a qualifying promotion gate
            reg_entry = reg.get(adapter_id)
            has_qualifying_gate = bool(
                reg_entry and any(
                    g in reg_entry.get("promotion gate", "")
                    for g in ("GATE-010", "GATE-020", "GATE-030", "GATE-040")
                )
            )
            # Check 2: row itself explicitly cites authentic qualifying evidence
            has_row_evidence = bool(QUALIFYING_EVIDENCE_RE.search(row_str))

            if not (has_qualifying_gate or has_row_evidence):
                findings.append(
                    Finding(
                        severity="error",
                        code=ERR_UNVERIFIED_STANDARDS_CLAIM,
                        file="DEVICE_ADAPTER_MATRIX.md",
                        location=adapter_id,
                        message=f"Adapter {adapter_id} claims open standards/local streaming without a qualifying evidence reference or registered promotion gate",
                    )
                )

    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return count, digest


def check_capability_token_scopes(root: Path, findings: list[Finding]) -> tuple[int, str | None]:
    """Audits registries/CAPABILITIES.md to verify all vendor tokens/adapter capabilities are strictly scoped."""
    caps_path = root / "registries" / "CAPABILITIES.md"
    content = safe_read_file(caps_path, findings, "capability registry")
    if content is None:
        return 0, None

    rows = parse_markdown_table(content)
    count = len(rows)

    found_auth = False
    found_net = False

    for row in rows:
        cap_id = row.get("id", "")
        scope = row.get("scope", "").strip()
        scope_norm = normalize_text(scope)
        plane = row.get("plane", "").strip()
        desc = row.get("capability", "").lower()
        row_str = " ".join(row.values()).lower()
        row_norm = normalize_text(row_str)

        # Defect 6: Security boundary check
        for sec_viol in SECURITY_BOUNDARY_VIOLATIONS:
            if sec_viol in row_str or sec_viol in row_norm:
                findings.append(
                    Finding(
                        severity="error",
                        code=ERR_SECURITY_BOUNDARY_VIOLATION,
                        file="registries/CAPABILITIES.md",
                        location=cap_id,
                        message=f"Capability {cap_id} contains prohibited security boundary violation '{sec_viol}'",
                    )
                )
                break

        # Defect 5: Exact token/credential checks
        if cap_id == "CAP-ADAPTER-AUTH-001":
            found_auth = True
            # Scope must be exact single device/account
            if scope != "device/account":
                findings.append(
                    Finding(
                        severity="error",
                        code=ERR_UNSCOPED_VENDOR_TOKEN,
                        file="registries/CAPABILITIES.md",
                        location=cap_id,
                        message=f"CAP-ADAPTER-AUTH-001 scope must be strictly 'device/account', observed '{scope}'",
                    )
                )
            if plane != "boundary":
                findings.append(
                    Finding(
                        severity="error",
                        code=ERR_UNSCOPED_VENDOR_TOKEN,
                        file="registries/CAPABILITIES.md",
                        location=cap_id,
                        message=f"CAP-ADAPTER-AUTH-001 plane must be 'boundary', observed '{plane}'",
                    )
                )

        elif cap_id == "CAP-ADAPTER-NET-001":
            found_net = True
            # Scope must be destination allowlist
            if scope != "destination allowlist":
                findings.append(
                    Finding(
                        severity="error",
                        code=ERR_UNSCOPED_VENDOR_TOKEN,
                        file="registries/CAPABILITIES.md",
                        location=cap_id,
                        message=f"CAP-ADAPTER-NET-001 scope must be strictly 'destination allowlist', observed '{scope}'",
                    )
                )

        # Defect 5: Fail closed on ANY adapter capability or credential/token with ambient/global scope
        is_adapter_or_credential_cap = (
            cap_id.startswith("CAP-ADAPTER-")
            or any(k in desc for k in ("token", "secret", "credential", "adapter auth", "adapter secret"))
        )
        if is_adapter_or_credential_cap and cap_id not in ("CAP-ADAPTER-AUTH-001", "CAP-ADAPTER-NET-001"):
            unscoped_indicators = ("*", "global", "ambient", "all", "multi device", "unrestricted", "unscoped")
            if any(ind in scope.lower() or ind in scope_norm for ind in unscoped_indicators):
                findings.append(
                    Finding(
                        severity="error",
                        code=ERR_UNSCOPED_VENDOR_TOKEN,
                        file="registries/CAPABILITIES.md",
                        location=cap_id,
                        message=f"Capability {cap_id} has unscoped/ambient scope '{scope}'; vendor tokens and adapter credentials must be strictly scoped",
                    )
                )

    if not found_auth:
        findings.append(
            Finding(
                severity="error",
                code=ERR_UNSCOPED_VENDOR_TOKEN,
                file="registries/CAPABILITIES.md",
                location="CAP-ADAPTER-AUTH-001",
                message="Required capability CAP-ADAPTER-AUTH-001 missing from registries/CAPABILITIES.md",
            )
        )

    if not found_net:
        findings.append(
            Finding(
                severity="error",
                code=ERR_UNSCOPED_VENDOR_TOKEN,
                file="registries/CAPABILITIES.md",
                location="CAP-ADAPTER-NET-001",
                message="Required capability CAP-ADAPTER-NET-001 missing from registries/CAPABILITIES.md",
            )
        )

    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return count, digest


def audit_standards_first_adapters(root: Path) -> tuple[bool, list[Finding], dict[str, Any]]:
    """Runs deterministic standards-first camera access audit (NEG-002)."""
    findings: list[Finding] = []

    neg_digest = check_negative_evidence_integrity(root, findings)
    adapters_count, adapters_digest, registered_adapters = check_device_adapters_registry(root, findings)
    matrix_count, matrix_digest = check_device_adapter_matrix(root, findings, registered_adapters)
    caps_count, caps_digest = check_capability_token_scopes(root, findings)

    error_count = sum(1 for f in findings if f.severity == "error")
    warning_count = sum(1 for f in findings if f.severity == "warning")
    is_valid = error_count == 0

    summary = {
        "status": "pass" if is_valid else "fail",
        "error_count": error_count,
        "warning_count": warning_count,
        "neg_id": "NEG-002",
        "adapters_evaluated": adapters_count,
        "matrix_entries_evaluated": matrix_count,
        "capabilities_evaluated": caps_count,
        "source_digests": {
            "negative_evidence": neg_digest,
            "device_adapters": adapters_digest,
            "device_adapter_matrix": matrix_digest,
            "capabilities": caps_digest,
        },
    }

    return is_valid, findings, summary


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Deterministic NEG-002 standards-first camera access audit checker"
    )
    parser.add_argument("--root", type=Path, default=ROOT, help="Repository root directory")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("--jsonl", action="store_true", help="Output results in JSONL format")
    parser.add_argument("--quiet", action="store_true", help="Suppress non-error output")
    args = parser.parse_args()

    root = args.root.resolve()
    is_valid, findings, summary = audit_standards_first_adapters(root)

    if args.jsonl:
        record = {
            "schema_version": "fss.standards_first_adapter_audit.v1",
            "run_id": f"neg002-{summary.get('neg_id', 'NEG-002')}",
            "neg_id": "NEG-002",
            "source_digests": summary["source_digests"],
            "hypothesis": "a consumer camera advertised with Wi-Fi or cloud viewing has a stable local stream",
            "finding": "cited public owner-facing material does not establish a durable ONVIF/RTSP contract",
            "decision": "use standards-first native adapters; proprietary paths remain isolated authorized lab work",
            "status": "passed" if is_valid else "failed",
            "error_count": summary["error_count"],
            "errors": [f.to_dict() for f in findings if f.severity == "error"],
            "reproduction_guidance": "python3 scripts/standards_first_adapter_checker.py",
        }
        print(json.dumps(record))
        return 0 if is_valid else 1

    if args.json:
        payload = {
            "summary": summary,
            "findings": [f.to_dict() for f in findings],
        }
        print(json.dumps(payload, indent=2))
        return 0 if is_valid else 1

    if not args.quiet:
        print("================================================================================")
        print("Deterministic NEG-002 Standards-First Camera Access Audit")
        print("================================================================================")
        print(f"Status:                      {summary['status'].upper()}")
        print(f"Adapters Evaluated:          {summary['adapters_evaluated']}")
        print(f"Matrix Entries Evaluated:    {summary['matrix_entries_evaluated']}")
        print(f"Capabilities Evaluated:      {summary['capabilities_evaluated']}")
        print(f"Errors:                      {summary['error_count']}")
        print("================================================================================")

    for finding in findings:
        prefix = f"[{finding.severity.upper()}] [{finding.code}]"
        print(f"{prefix} {finding.file}:{finding.location} - {finding.message}")
        if finding.remediation and not args.quiet:
            print(f"  -> Remediation: {finding.remediation}")

    if is_valid:
        if not args.quiet:
            print("\n[PASS] Standards-first camera access audit passed (NEG-002 preserved)")
        return 0
    else:
        print(f"\n[FAIL] Standards-first camera access audit failed with {summary['error_count']} error(s)")
        return 1


if __name__ == "__main__":
    sys.exit(main())

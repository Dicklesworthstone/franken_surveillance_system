#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import types
from pathlib import Path
from typing import Any

if __name__ not in sys.modules:
    sys.modules[__name__] = types.ModuleType(__name__)

from dataclasses import dataclass, field
from enum import Enum

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PLAN = ROOT / "COMPREHENSIVE_PLAN_FOR_FRANKEN_SURVEILLANCE_SYSTEM.md"
DEFAULT_RESOLUTION = ROOT / "architecture/stable_id_resolution.json"

GRAMMAR_SCHEMA = "fss.stable_id_grammar.v1"
AUDIT_SCHEMA = "fss.stable_id_audit.v1"
RESOLUTION_SCHEMA = "fss.stable_id_resolution.v1"

# Stable diagnostic error codes
ERR_COLLISION = "ERR-STABLE-ID-COLLISION-001"
ERR_UNKNOWN_FAMILY = "ERR-STABLE-ID-UNKNOWN-FAMILY-001"
ERR_MALFORMED_WIDTH = "ERR-STABLE-ID-MALFORMED-WIDTH-001"
ERR_MALFORMED_CASE = "ERR-STABLE-ID-MALFORMED-CASE-001"
ERR_MALFORMED_HIERARCHY = "ERR-STABLE-ID-MALFORMED-HIERARCHY-001"
ERR_DANGLING_REFERENCE = "ERR-STABLE-ID-DANGLING-REFERENCE-001"
ERR_FINGERPRINT_MISMATCH = "ERR-STABLE-ID-FINGERPRINT-MISMATCH-001"
ERR_STALE_RESOLUTION = "ERR-STABLE-ID-STALE-RESOLUTION-001"
ERR_CANONICAL_COLLISION = "ERR-STABLE-ID-CANONICAL-COLLISION-001"
ERR_CENSUS_DRIFT = "ERR-STABLE-ID-CENSUS-DRIFT-001"
ERR_SCHEMA_ERROR = "ERR-STABLE-ID-SCHEMA-ERROR-001"
ERR_TOMBSTONE_REFERENCE = "ERR-STABLE-ID-TOMBSTONE-REFERENCE-001"

# Status/disposition values (compared case-insensitively, whitespace-trimmed) that retire an ID.
TOMBSTONE_STATES = frozenset({"tombstone", "tombstoned", "superseded"})


class OccurrenceKind(str, Enum):
    DEFINITION = "definition"
    REFERENCE = "reference"
    ALIAS = "alias"
    SUCCESSOR = "successor"
    TOMBSTONE = "tombstone"
    EXAMPLE = "example"
    MALFORMED = "malformed"


@dataclass(frozen=True)
class FamilyRule:
    name: str
    allowed_widths: tuple[int, ...]
    hierarchical: bool = False
    allow_leading_zeros: bool = True
    min_value: int | None = None
    max_value: int | None = None
    status: str = "normative"


# Versioned machine grammar for all normative stable-ID families
NORMATIVE_FAMILIES: dict[str, FamilyRule] = {
    "INV": FamilyRule("INV", (3,), hierarchical=False),
    "MODEL-INV": FamilyRule("MODEL-INV", (3,), hierarchical=False),
    "REL-INV": FamilyRule("REL-INV", (3,), hierarchical=False),
    "XFER-INV": FamilyRule("XFER-INV", (3,), hierarchical=False),
    "GOAL": FamilyRule("GOAL", (3,), hierarchical=False),
    "NONGOAL": FamilyRule("NONGOAL", (3,), hierarchical=False),
    "NS": FamilyRule(
        "NS",
        (1, 2),
        hierarchical=False,
        allow_leading_zeros=False,
        min_value=1,
        max_value=99,
        status="legacy-variable-width",
    ),
    "ADR": FamilyRule("ADR", (3, 4), hierarchical=False),
    "WP": FamilyRule("WP", (3,), hierarchical=False),
    "GATE": FamilyRule("GATE", (3,), hierarchical=False),
    "CAP": FamilyRule("CAP", (3,), hierarchical=True),
    "EFFECT": FamilyRule("EFFECT", (3,), hierarchical=True),
    "ERR": FamilyRule("ERR", (3,), hierarchical=True),
    "EXIT": FamilyRule("EXIT", (3,), hierarchical=True),
    "SCHEMA": FamilyRule("SCHEMA", (3,), hierarchical=True),
    "TEST": FamilyRule("TEST", (3,), hierarchical=True),
    "SLO": FamilyRule("SLO", (3,), hierarchical=True),
    "RISK": FamilyRule("RISK", (3,), hierarchical=True),
    "OPEN": FamilyRule("OPEN", (3,), hierarchical=False),
    "INT": FamilyRule("INT", (3,), hierarchical=True),
    "COST": FamilyRule("COST", (3,), hierarchical=True),
    "SEC": FamilyRule("SEC", (3,), hierarchical=False),
    "PRIV": FamilyRule("PRIV", (3,), hierarchical=False),
    "FORMAL": FamilyRule("FORMAL", (3,), hierarchical=False),
    "NEG": FamilyRule("NEG", (3,), hierarchical=False),
    "FSS": FamilyRule("FSS", (3,), hierarchical=False),
    "LAB": FamilyRule("LAB", (3,), hierarchical=False),
    "ADP": FamilyRule("ADP", (3,), hierarchical=True),
    "MOD": FamilyRule("MOD", (3,), hierarchical=True),
    "MODEL": FamilyRule("MODEL", (3,), hierarchical=True),
    "ALG": FamilyRule("ALG", (3,), hierarchical=True),
    "PUB": FamilyRule("PUB", (3,), hierarchical=True),
    "DEC": FamilyRule("DEC", (3,), hierarchical=True),
    "DEP": FamilyRule("DEP", (3,), hierarchical=True),
    "REL": FamilyRule("REL", (3,), hierarchical=True),
    "FMT": FamilyRule("FMT", (3,), hierarchical=False),
    "TRACE": FamilyRule("TRACE", (3,), hierarchical=False),
    "ATP": FamilyRule("ATP", (3,), hierarchical=False),
    "IMP": FamilyRule("IMP", (3,), hierarchical=True),
    "QL": FamilyRule("QL", (3,), hierarchical=True),
    "XFER": FamilyRule("XFER", (3,), hierarchical=True),
    "GRAPH": FamilyRule("GRAPH", (3,), hierarchical=False),
    "AGT": FamilyRule("AGT", (3,), hierarchical=True),
    "AOP": FamilyRule("AOP", (3,), hierarchical=False),
    "ARES": FamilyRule("ARES", (3,), hierarchical=False),
    "AVIEW": FamilyRule("AVIEW", (3,), hierarchical=False),
    "KSTATE": FamilyRule("KSTATE", (3,), hierarchical=False),
    "PROV": FamilyRule("PROV", (3,), hierarchical=False),
    "DOC": FamilyRule("DOC", (3,), hierarchical=False),
    "DRIFT": FamilyRule("DRIFT", (3,), hierarchical=False),
    "BUILD": FamilyRule("BUILD", (3,), hierarchical=True),
    "SHA": FamilyRule("SHA", (3,), hierarchical=False),
}

EXCLUDED_PROSE_PREFIXES = {
    "UTF", "RFC", "ISO", "IEEE", "POSIX", "CVE", "W3C"
}


def _strip_html_comments(text: str) -> str:
    """Strips HTML comments while preserving newline count for accurate line numbering."""
    def replacer(match: re.Match[str]) -> str:
        return "\n" * match.group(0).count("\n")
    return re.sub(r"<!--[\s\S]*?-->", replacer, text)


def _normalize_key(token: str) -> tuple[str, int] | str:
    """Normalizes numeric stable IDs so aliases like ADR-001 and ADR-0001 map to the same key."""
    parts = token.rsplit("-", 1)
    if len(parts) == 2 and parts[1].isdigit():
        prefix = parts[0]
        num = int(parts[1])
        if prefix in NORMATIVE_FAMILIES:
            return (NORMATIVE_FAMILIES[prefix].name, num)
    return token


def _canonical_id(token: str) -> str:
    """Returns canonical string representation for an ID."""
    parts = token.rsplit("-", 1)
    if len(parts) == 2 and parts[1].isdigit():
        prefix = parts[0]
        num = int(parts[1])
        if prefix == "ADR":
            return f"ADR-{num:04d}"
        if prefix == "NS":
            return f"NS-{num}"
    return token


STABLE_ID_GRAMMAR = {
    "schema": GRAMMAR_SCHEMA,
    "version": "1.0.0",
    "families": {
        name: {
            "allowedWidths": list(rule.allowed_widths),
            "hierarchical": rule.hierarchical,
            "allowLeadingZeros": rule.allow_leading_zeros,
            "minValue": rule.min_value,
            "maxValue": rule.max_value,
            "status": rule.status,
        }
        for name, rule in NORMATIVE_FAMILIES.items()
    },
}

ID_TOKEN_RE = re.compile(r"\b([A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)*-\d+)\b")
UNDERSCORE_REF_RE = re.compile(r"\b([A-Za-z][A-Za-z0-9]*(?:[-_][A-Za-z0-9]+)*_\d+)\b")

HEADING_DEF_RE = re.compile(
    r"^#{1,6}\s+(?:(?:\d+\.)*\d+\s+)?(?:`(?P<id_backtick>[A-Za-z0-9_-]+)`|`?(?P<id>[A-Za-z][A-Za-z0-9]*(?:[-_][A-Za-z0-9]+)*[-_]\d+)`?|Scenario\s+(?P<scenario_id>[A-Za-z0-9-_]+))\s+[—–-]\s*(?P<title>.+?)\s*$"
)
TABLE_DEF_RE = re.compile(
    r"^\|\s*`?(?P<id>[A-Za-z][A-Za-z0-9]*(?:[-_][A-Za-z0-9]+)*[-_]\d+)`?\s*\|\s*(?P<title>[^|]+?)\s*\|"
)
LIST_DEF_RE = re.compile(
    r"^(?:\d+\.|\*|-)\s+`?(?P<id>[A-Za-z][A-Za-z0-9]*(?:[-_][A-Za-z0-9]+)*[-_]\d+)`?[:—–-]?\s+(?P<title>.+?)\s*$"
)

GOAL_HEADING = re.compile(r"^### `(?P<id>GOAL-\d{3})` — (?P<title>.+?)\s*$")
NS_HEADING = re.compile(r"^### Scenario (?P<id>NS-\d+) — (?P<title>.+?)\s*$")

# Near-miss shapes: a definition-shaped heading or table row whose ID token is not in the strict
# grammar (missing delimiter, underscore, lowercase, wrong heading shape). These are never
# silently dropped: a family-shaped token is pushed through validate_identifier_syntax.
HEADING_NEAR_MISS_RE = re.compile(
    r"^#{1,6}\s+(?:(?:\d+\.)*\d+\s+)?(?:Scenario\s+)?`?(?P<id>[A-Za-z][A-Za-z0-9_-]*\d)`?\s+[—–-]\s*\S"
)
TABLE_FIRST_CELL_RE = re.compile(r"^\|\s*`?(?P<id>[A-Za-z][A-Za-z0-9_-]*\d)`?\s*\|")
FAMILY_SHAPED_RE = re.compile(r"^(?P<alpha>[A-Za-z]+)[A-Za-z0-9_-]*\d$")


class AuditError(ValueError):
    """Stable audit failure with deterministic error identity."""

    def __init__(
        self,
        error_id_or_msg: str,
        message: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        if message is not None:
            super().__init__(f"{error_id_or_msg}: {message}")
            self.error_id = error_id_or_msg
            self.message = message
        else:
            super().__init__(error_id_or_msg)
            self.error_id = "ERR-STABLE-ID-AUDIT-001"
            self.message = error_id_or_msg
        self.details = details or {}


def _title_digest(legacy_id: str, title: str) -> str:
    """Computes the deterministic title fingerprint for a stable identifier definition."""
    payload = legacy_id.encode("utf-8") + b"\0" + title.encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception as exc:
        raise AuditError(ERR_SCHEMA_ERROR, f"failed to parse JSON from {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise AuditError(ERR_SCHEMA_ERROR, f"top-level JSON value must be an object: {path}")
    return value


def _is_tombstone_marker(value: Any, *, where: str) -> bool:
    """True when a status/disposition value retires an ID. Non-string markers fail closed."""
    if value is None:
        return False
    if not isinstance(value, str):
        raise AuditError(
            ERR_SCHEMA_ERROR,
            f"status/disposition must be a string at {where}, got {type(value).__name__}: {value!r}",
        )
    return value.strip().lower() in TOMBSTONE_STATES


def validate_identifier_syntax(token: str) -> tuple[FamilyRule, str]:
    """Validates token against grammar. Returns (FamilyRule, numeric_str) or raises AuditError."""
    if not token.isupper() and any(c.isalpha() for c in token):
        raise AuditError(
            ERR_MALFORMED_CASE,
            f"malformed lowercase in identifier '{token}': stable IDs must be uppercase",
        )

    parts = token.split("-")
    if len(parts) < 2:
        raise AuditError(
            ERR_MALFORMED_WIDTH,
            f"identifier '{token}' lacks numeric delimiter",
        )
    numeric_str = parts[-1]
    if not numeric_str.isdigit():
        raise AuditError(
            ERR_MALFORMED_WIDTH,
            f"identifier '{token}' suffix '{numeric_str}' is not numeric",
        )

    prefix = "-".join(parts[:-1])
    base_family = parts[0]

    if prefix in NORMATIVE_FAMILIES:
        rule = NORMATIVE_FAMILIES[prefix]
    elif base_family in NORMATIVE_FAMILIES:
        rule = NORMATIVE_FAMILIES[base_family]
        if len(parts) > 2 and not rule.hierarchical:
            raise AuditError(
                ERR_MALFORMED_HIERARCHY,
                f"family '{base_family}' does not permit hierarchical sub-prefixes: '{token}'",
            )
    else:
        raise AuditError(
            ERR_UNKNOWN_FAMILY,
            f"unknown stable-ID family '{base_family}' in '{token}'",
        )

    width = len(numeric_str)
    if width not in rule.allowed_widths:
        expected = " or ".join(str(w) for w in rule.allowed_widths)
        raise AuditError(
            ERR_MALFORMED_WIDTH,
            f"malformed numeric width {width} for family '{rule.name}' in '{token}' (expected {expected} digits)",
        )

    if not rule.allow_leading_zeros and width > 1 and numeric_str.startswith("0"):
        unpadded = numeric_str.lstrip("0") or "0"
        raise AuditError(
            ERR_MALFORMED_WIDTH,
            f"malformed zero padding in '{token}' (expected unpadded '{rule.name}-{unpadded}')",
        )

    if rule.min_value is not None and int(numeric_str) < rule.min_value:
        raise AuditError(
            ERR_MALFORMED_WIDTH,
            f"value {numeric_str} below minimum bound {rule.min_value} for '{token}'",
        )
    if rule.max_value is not None and int(numeric_str) > rule.max_value:
        raise AuditError(
            ERR_MALFORMED_WIDTH,
            f"value {numeric_str} exceeds maximum bound {rule.max_value} for '{token}'",
        )

    return rule, numeric_str


def _family_alpha(token: str) -> str | None:
    """Upper-cased leading alphabetic run when it names a normative family, else None."""
    match = FAMILY_SHAPED_RE.match(token)
    if match is None:
        return None
    alpha = match.group("alpha").upper()
    return alpha if alpha in NORMATIVE_FAMILIES else None


def _validate_if_family_shaped(token: str) -> None:
    """Near-miss guard: any family-shaped token must satisfy the strict grammar."""
    if _family_alpha(token) is not None:
        validate_identifier_syntax(token)


def _is_exact_family_token(token: str) -> bool:
    """True for tokens whose leading segment is exactly (case-sensitively) a normative family."""
    return token.split("-")[0] in NORMATIVE_FAMILIES

def _is_candidate_identifier(token: str) -> bool:
    """True when a hyphenated token is ID-like enough to warrant strict grammar validation.

    Uppercase-leading tokens are ID-like even with an unknown family (fail closed with
    ERR_UNKNOWN_FAMILY). Lowercase tokens are prose unless their leading alpha run names a
    normative family when upper-cased ("goal-001" is a malformed GOAL reference, while
    "first-240" and "Draft-3" are ordinary prose).
    """
    match = FAMILY_SHAPED_RE.match(token)
    if match is None:
        return False
    alpha = match.group("alpha")
    return alpha.isupper() or alpha.upper() in NORMATIVE_FAMILIES


def _definition_candidate(match: re.Match[str]) -> str | None:
    groups = match.groupdict()
    return groups.get("id_backtick") or groups.get("id") or groups.get("scenario_id")


def _definition_title(match: re.Match[str]) -> str:
    return match.group("title").strip().strip("`").strip()


@dataclass
class ParsedDefinition:
    legacy_id: str
    title: str
    line: int
    source: str
    title_digest: str
    canonical_id: str = ""


@dataclass
class ParsedReference:
    raw_id: str
    line: int
    source: str


@dataclass
class MarkdownScan:
    """Classified stable-ID occurrences of one markdown source.

    ``definitions``/``references`` come from live text. ``examples`` are family tokens inside
    fenced code blocks, and ``fenced_definitions`` are heading-shaped definitions inside fences.
    Fenced occurrences never create live definitions, but they are still validated: every example
    must resolve to a live, non-tombstoned owner, and every fenced definition must repeat the
    title of a live definition of the same ID.
    """

    definitions: list[ParsedDefinition] = field(default_factory=list)
    references: list[ParsedReference] = field(default_factory=list)
    examples: list[ParsedReference] = field(default_factory=list)
    fenced_definitions: list[ParsedDefinition] = field(default_factory=list)


@dataclass
class RepositoryIndex:
    """Stable IDs known from registries, ADRs, and architecture JSON."""

    known: set[str] = field(default_factory=set)
    tombstoned: set[str] = field(default_factory=set)
    titles: dict[tuple[str, int] | str, set[str]] = field(default_factory=dict)


def _add_title(titles: dict[tuple[str, int] | str, set[str]], identifier: str, title: str) -> None:
    titles.setdefault(_normalize_key(identifier), set()).add(title)


def _extract_plan_definitions(plan_text: str, source_name: str = "plan.md") -> list[ParsedDefinition]:
    """Extracts goal and scenario definitions from plan text using strict headings."""
    definitions: list[ParsedDefinition] = []
    clean_text = _strip_html_comments(plan_text)
    in_code_fence = False
    for line_number, line in enumerate(clean_text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("```"):
            in_code_fence = not in_code_fence
            continue
        if in_code_fence:
            continue

        match = GOAL_HEADING.match(line) or NS_HEADING.match(line)
        if match is not None:
            legacy_id = match.group("id")
            title = match.group("title").strip()
            validate_identifier_syntax(legacy_id)
            definitions.append(
                ParsedDefinition(
                    legacy_id=legacy_id,
                    title=title,
                    line=line_number,
                    source=source_name,
                    title_digest=_title_digest(legacy_id, title),
                )
            )
            continue

        near_miss = re.match(r"^###\s+`(?P<id>[A-Za-z0-9_-]+)`\s+[—–-]\s*(?P<title>.+?)\s*$", line)
        if near_miss:
            validate_identifier_syntax(near_miss.group("id"))
        near_scenario = re.match(r"^###\s+Scenario\s+(?P<id>[A-Za-z0-9_-]+)\s+[—–-]\s*(?P<title>.+?)\s*$", line)
        if near_scenario:
            validate_identifier_syntax(near_scenario.group("id"))
        near_heading = HEADING_NEAR_MISS_RE.match(line)
        if near_heading:
            candidate = near_heading.group("id")
            _validate_if_family_shaped(candidate)
            family = _family_alpha(candidate)
            if family in ("GOAL", "NS"):
                raise AuditError(
                    ERR_CENSUS_DRIFT,
                    f"non-canonical {family} definition heading at {source_name}:{line_number} would be "
                    f"dropped from the census: {stripped!r}",
                )
    return definitions


def _scan_markdown(text: str, source_name: str) -> MarkdownScan:
    """Classifies every stable-ID occurrence of a markdown source."""
    scan = MarkdownScan()
    clean_text = _strip_html_comments(text)
    in_code_fence = False

    for line_number, line in enumerate(clean_text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("```"):
            in_code_fence = not in_code_fence
            continue

        if in_code_fence:
            heading = HEADING_DEF_RE.match(stripped)
            if heading:
                candidate_id = _definition_candidate(heading)
                if candidate_id and _is_exact_family_token(candidate_id):
                    title = _definition_title(heading)
                    scan.fenced_definitions.append(
                        ParsedDefinition(
                            legacy_id=candidate_id,
                            title=title,
                            line=line_number,
                            source=source_name,
                            title_digest=_title_digest(candidate_id, title),
                        )
                    )
            for m in ID_TOKEN_RE.finditer(line):
                token = m.group(1)
                if _is_exact_family_token(token):
                    scan.examples.append(ParsedReference(raw_id=token, line=line_number, source=source_name))
            continue

        def_match = (
            HEADING_DEF_RE.match(line)
            or TABLE_DEF_RE.match(line)
            or LIST_DEF_RE.match(line)
        )
        defined_id = None
        if def_match:
            candidate_id = _definition_candidate(def_match)
            if (
                candidate_id
                and not candidate_id.startswith("ID")
                and not candidate_id.startswith("---")
            ):
                validate_identifier_syntax(candidate_id)
                title = _definition_title(def_match)
                defined_id = candidate_id
                scan.definitions.append(
                    ParsedDefinition(
                        legacy_id=defined_id,
                        title=title,
                        line=line_number,
                        source=source_name,
                        title_digest=_title_digest(defined_id, title),
                    )
                )
        else:
            near_heading = HEADING_NEAR_MISS_RE.match(line)
            if near_heading:
                _validate_if_family_shaped(near_heading.group("id"))
            near_cell = TABLE_FIRST_CELL_RE.match(line)
            if near_cell:
                _validate_if_family_shaped(near_cell.group("id"))

        for m in ID_TOKEN_RE.finditer(line):
            token = m.group(1)
            prefix = token.split("-")[0]
            if prefix in EXCLUDED_PROSE_PREFIXES and prefix not in NORMATIVE_FAMILIES:
                continue
            # Ordinary lowercase prose phrases (e.g. "first-240", "Draft-3") are not
            # stable-ID references; only candidate identifiers enter strict validation.
            if not _is_candidate_identifier(token):
                continue
            if token == defined_id:
                continue
            validate_identifier_syntax(token)
            scan.references.append(
                ParsedReference(
                    raw_id=token,
                    line=line_number,
                    source=source_name,
                )
            )

        for m in UNDERSCORE_REF_RE.finditer(line):
            token = m.group(1)
            base = token.replace("_", "-").split("-")[0]
            if base.upper() in NORMATIVE_FAMILIES:
                validate_identifier_syntax(token)

    return scan


def _extract_all_occurrences(
    text: str, source_name: str
) -> tuple[list[ParsedDefinition], list[ParsedReference], list[str]]:
    """Extracts definitions, references, and example occurrences from markdown text."""
    scan = _scan_markdown(text, source_name)
    return scan.definitions, scan.references, [example.raw_id for example in scan.examples]


def _validate_references(
    references: list[ParsedReference],
    *,
    valid_targets: set[str],
    tombstoned_ids: set[str],
    context: str = "",
) -> None:
    """Every reference must resolve to a live owner that is not tombstoned anywhere."""
    where_suffix = f" in {context}" if context else ""
    for ref in references:
        if ref.raw_id in tombstoned_ids or _canonical_id(ref.raw_id) in tombstoned_ids:
            raise AuditError(
                ERR_TOMBSTONE_REFERENCE,
                f"reference to tombstoned/superseded identifier '{ref.raw_id}'{where_suffix} at {ref.source}:{ref.line}",
            )
        if ref.raw_id not in valid_targets and _canonical_id(ref.raw_id) not in valid_targets:
            syntax_note = ""
            try:
                validate_identifier_syntax(ref.raw_id)
            except AuditError as exc:
                syntax_note = f"; the token is also malformed: {exc.message}"
            raise AuditError(
                ERR_DANGLING_REFERENCE,
                f"dangling reference to '{ref.raw_id}'{where_suffix} at {ref.source}:{ref.line} "
                f"(no active owner or historical mapping found){syntax_note}",
            )


def _validate_fenced_occurrences(
    scan: MarkdownScan,
    *,
    valid_targets: set[str],
    tombstoned_ids: set[str],
    live_titles: dict[tuple[str, int] | str, set[str]],
) -> None:
    """Fenced examples must resolve; fenced definitions may only restate a live definition."""
    _validate_references(
        scan.examples,
        valid_targets=valid_targets,
        tombstoned_ids=tombstoned_ids,
        context="fenced example",
    )
    for fenced in scan.fenced_definitions:
        titles = live_titles.get(_normalize_key(fenced.legacy_id), set())
        if not titles:
            raise AuditError(
                ERR_COLLISION,
                f"fenced definition {fenced.legacy_id} at {fenced.source}:{fenced.line} ('{fenced.title}') "
                "cannot be verified: no live definition title is recorded for this ID",
            )
        if fenced.title not in titles:
            raise AuditError(
                ERR_COLLISION,
                f"fenced definition {fenced.legacy_id} at {fenced.source}:{fenced.line} ('{fenced.title}') "
                f"conflicts with live definition title(s) {sorted(titles)}",
            )


def _load_repository_index(root: Path) -> RepositoryIndex:
    """Loads known, tombstoned, and titled stable IDs from registries, ADRs, and architecture JSON."""
    index = RepositoryIndex()

    def ingest_definition(candidate: str, title: str) -> None:
        validate_identifier_syntax(candidate)
        index.known.add(candidate)
        index.known.add(_canonical_id(candidate))
        _add_title(index.titles, candidate, title)

    reg_dir = root / "registries"
    if reg_dir.is_dir():
        for path in sorted(reg_dir.glob("*.md")):
            clean = _strip_html_comments(path.read_text(encoding="utf-8-sig", errors="strict"))
            in_code_fence = False
            for line in clean.splitlines():
                stripped = line.strip()
                if stripped.startswith("```"):
                    in_code_fence = not in_code_fence
                    continue
                if in_code_fence:
                    continue
                m = TABLE_DEF_RE.match(line) or HEADING_DEF_RE.match(line) or LIST_DEF_RE.match(line)
                if m:
                    cand = _definition_candidate(m)
                    if cand and not cand.startswith("ID") and not cand.startswith("---"):
                        ingest_definition(cand, _definition_title(m))
                    continue
                near_heading = HEADING_NEAR_MISS_RE.match(line)
                if near_heading:
                    _validate_if_family_shaped(near_heading.group("id"))
                near_cell = TABLE_FIRST_CELL_RE.match(line)
                if near_cell:
                    _validate_if_family_shaped(near_cell.group("id"))

    adr_dir = root / "docs/adr"
    if adr_dir.is_dir():
        for path in sorted(adr_dir.glob("*.md")):
            clean = _strip_html_comments(path.read_text(encoding="utf-8-sig", errors="strict"))
            in_code_fence = False
            for line in clean.splitlines():
                stripped = line.strip()
                if stripped.startswith("```"):
                    in_code_fence = not in_code_fence
                    continue
                if in_code_fence:
                    continue
                m = HEADING_DEF_RE.match(line)
                if m:
                    cand = _definition_candidate(m)
                    if cand:
                        ingest_definition(cand, _definition_title(m))
                    continue
                near_heading = HEADING_NEAR_MISS_RE.match(line)
                if near_heading:
                    _validate_if_family_shaped(near_heading.group("id"))

    def stable_id_shaped(key: str, value: str) -> bool:
        if key in ("legacyId", "canonicalId"):
            return True
        return ("-" in value or "_" in value) and any(c.isdigit() for c in value) and not value.startswith("DEP-CLASS-")

    arch_dir = root / "architecture"
    if arch_dir.is_dir():
        for path in sorted(arch_dir.glob("*.json")):
            data = _load_json(path)
            rel = path.name

            def walk(obj: Any) -> None:
                if isinstance(obj, dict):
                    retired = _is_tombstone_marker(obj.get("status"), where=f"{rel} status") or _is_tombstone_marker(
                        obj.get("disposition"), where=f"{rel} disposition"
                    )
                    if retired:
                        for key in ("legacyId", "canonicalId", "id", "gate"):
                            value = obj.get(key)
                            if isinstance(value, str) and stable_id_shaped(key, value):
                                validate_identifier_syntax(value)
                                index.tombstoned.add(value)
                                index.tombstoned.add(_canonical_id(value))
                        return
                    for k, v in obj.items():
                        if k in ("legacyId", "canonicalId", "id", "gate") and isinstance(v, str):
                            if stable_id_shaped(k, v):
                                validate_identifier_syntax(v)
                                index.known.add(v)
                                index.known.add(_canonical_id(v))
                            elif "-" not in v and "_" not in v:
                                # Delimiter-less near-miss such as INV001 must not be skipped.
                                _validate_if_family_shaped(v)
                        walk(v)
                elif isinstance(obj, list):
                    for item in obj:
                        walk(item)

            walk(data)

    return index


def _load_repository_definitions(root: Path) -> set[str]:
    """Loads all known canonical definition IDs from registries, docs, and architecture JSON."""
    return _load_repository_index(root).known


def audit(
    plan_path: Path = DEFAULT_PLAN,
    resolution_path: Path = DEFAULT_RESOLUTION,
    corpus_paths: list[Path] | None = None,
) -> dict[str, Any]:
    """Executes the definition-aware, collision-free stable-ID census and audit."""
    plan_text = _strip_html_comments(plan_path.read_text(encoding="utf-8-sig"))
    resolution = _load_json(resolution_path)
    if resolution.get("schema") != RESOLUTION_SCHEMA:
        raise AuditError(ERR_SCHEMA_ERROR, "unsupported stable-ID resolution schema")

    raw_resolutions = resolution.get("resolutions")
    if not isinstance(raw_resolutions, list):
        raise AuditError(ERR_SCHEMA_ERROR, "resolutions must be an array")

    by_occurrence: dict[tuple[str, str], dict[str, Any]] = {}
    canonical_from_resolution: set[str] = set()
    legacy_from_resolution: set[str] = set()
    tombstoned_ids: set[str] = set()
    # Every resolution title (live or tombstoned) recorded per ID, for title-drift detection.
    resolution_titles: dict[tuple[str, int] | str, set[str]] = {}
    # Titles of live (non-tombstoned) resolution rows, for verifying fenced definitions.
    live_titles: dict[tuple[str, int] | str, set[str]] = {}

    for index, row in enumerate(raw_resolutions):
        if not isinstance(row, dict):
            raise AuditError(ERR_SCHEMA_ERROR, f"resolution row {index} is not an object")
        legacy_id = row.get("legacyId")
        title = row.get("title")
        canonical_id = row.get("canonicalId")
        digest = row.get("titleDigest")

        if not all(
            isinstance(value, str) and value
            for value in (legacy_id, title, canonical_id, digest)
        ):
            raise AuditError(ERR_SCHEMA_ERROR, f"resolution row {index} has missing string fields")

        validate_identifier_syntax(legacy_id)
        validate_identifier_syntax(canonical_id)

        key = (legacy_id, title)
        if key in by_occurrence:
            raise AuditError(
                ERR_COLLISION,
                f"duplicate resolution occurrence: {legacy_id} / {title}",
            )
        if digest != _title_digest(legacy_id, title):
            raise AuditError(
                ERR_FINGERPRINT_MISMATCH,
                f"title fingerprint mismatch for {legacy_id} / {title}",
            )
        if canonical_id in canonical_from_resolution:
            raise AuditError(
                ERR_CANONICAL_COLLISION,
                f"canonical ID reused in resolution table: {canonical_id}",
            )

        is_tombstone = _is_tombstone_marker(row.get("status"), where=f"resolution row {index} status") or _is_tombstone_marker(
            row.get("disposition"), where=f"resolution row {index} disposition"
        )
        _add_title(resolution_titles, legacy_id, title)
        _add_title(resolution_titles, canonical_id, title)
        if is_tombstone:
            tombstoned_ids.add(legacy_id)
            tombstoned_ids.add(_canonical_id(legacy_id))
            tombstoned_ids.add(canonical_id)
            tombstoned_ids.add(_canonical_id(canonical_id))
        else:
            canonical_from_resolution.add(canonical_id)
            canonical_from_resolution.add(_canonical_id(canonical_id))
            legacy_from_resolution.add(legacy_id)
            legacy_from_resolution.add(_canonical_id(legacy_id))
            _add_title(live_titles, legacy_id, title)
            _add_title(live_titles, canonical_id, title)

        by_occurrence[key] = row

    extracted = _extract_plan_definitions(plan_text, source_name=plan_path.name)

    norm_counts: dict[tuple[str, int] | str, int] = {}
    legacy_counts: dict[str, int] = {}
    for d in extracted:
        norm_key = _normalize_key(d.legacy_id)
        norm_counts[norm_key] = norm_counts.get(norm_key, 0) + 1
        legacy_counts[d.legacy_id] = legacy_counts.get(d.legacy_id, 0) + 1

    definitions: list[ParsedDefinition] = []
    for d in extracted:
        norm_key = _normalize_key(d.legacy_id)
        count = norm_counts[norm_key]
        resolution_row = by_occurrence.get((d.legacy_id, d.title)) or by_occurrence.get((_canonical_id(d.legacy_id), d.title))
        if count > 1 and resolution_row is None:
            raise AuditError(
                ERR_COLLISION,
                f"unresolved collided stable definition {d.legacy_id} at line {d.line}: {d.title}",
            )
        recorded_titles = resolution_titles.get(norm_key)
        if resolution_row is None and recorded_titles:
            raise AuditError(
                ERR_FINGERPRINT_MISMATCH,
                f"plan definition title '{d.title}' for {d.legacy_id} at line {d.line} does not match any "
                f"fingerprinted resolution title {sorted(recorded_titles)}",
            )
        if resolution_row is not None:
            d.canonical_id = str(resolution_row["canonicalId"])
            d.title_digest = str(resolution_row["titleDigest"])
        else:
            d.canonical_id = _canonical_id(d.legacy_id)
            d.title_digest = _title_digest(d.legacy_id, d.title)
        definitions.append(d)

    used_resolution_keys = set()
    for d in definitions:
        if (d.legacy_id, d.title) in by_occurrence:
            used_resolution_keys.add((d.legacy_id, d.title))
        elif (_canonical_id(d.legacy_id), d.title) in by_occurrence:
            used_resolution_keys.add((_canonical_id(d.legacy_id), d.title))

    unused = sorted(set(by_occurrence) - used_resolution_keys)
    if unused:
        rendered = ", ".join(f"{legacy}/{title}" for legacy, title in unused)
        raise AuditError(
            ERR_STALE_RESOLUTION,
            f"resolution table contains stale occurrences: {rendered}",
        )

    canonical_ids = [d.canonical_id for d in definitions]
    if len(canonical_ids) != len(set(canonical_ids)):
        duplicates = sorted(
            identifier
            for identifier in set(canonical_ids)
            if canonical_ids.count(identifier) > 1
        )
        raise AuditError(
            ERR_CANONICAL_COLLISION,
            "canonical stable IDs collide: " + ", ".join(duplicates),
        )

    expected = resolution.get("expected")
    if not isinstance(expected, dict):
        raise AuditError(ERR_SCHEMA_ERROR, "expected canonical ID sets are missing")
    expected_goals = expected.get("goalCanonicalIds")
    expected_ns = expected.get("northStarCanonicalIds")
    actual_goals = sorted(
        (d.canonical_id for d in definitions if d.canonical_id.startswith("GOAL-")),
        key=lambda value: int(value.rsplit("-", 1)[1]),
    )
    actual_ns = sorted(
        (d.canonical_id for d in definitions if d.canonical_id.startswith("NS-")),
        key=lambda value: int(value.rsplit("-", 1)[1]),
    )
    if expected_goals is not None and actual_goals != expected_goals:
        raise AuditError(
            ERR_CENSUS_DRIFT,
            f"canonical GOAL census drift: expected {expected_goals}, observed {actual_goals}",
        )
    if expected_ns is not None and actual_ns != expected_ns:
        raise AuditError(
            ERR_CENSUS_DRIFT,
            f"canonical North Star census drift: expected {expected_ns}, observed {actual_ns}",
        )

    known_targets = set(canonical_ids) | set(legacy_from_resolution)
    if plan_path == DEFAULT_PLAN or (plan_path.is_file() and plan_path.resolve().is_relative_to(ROOT)):
        repo_index = _load_repository_index(ROOT)
        known_targets.update(repo_index.known)
        tombstoned_ids.update(repo_index.tombstoned)
        for key, titles in repo_index.titles.items():
            live_titles.setdefault(key, set()).update(titles)
    scan = _scan_markdown(plan_text, source_name=plan_path.name)
    references = scan.references
    known_targets.update(d.legacy_id for d in scan.definitions)
    known_targets.update(_canonical_id(d.legacy_id) for d in scan.definitions)

    _validate_references(references, valid_targets=known_targets, tombstoned_ids=tombstoned_ids)

    for d in definitions:
        _add_title(live_titles, d.legacy_id, d.title)
        _add_title(live_titles, d.canonical_id, d.title)
    for d in scan.definitions:
        _add_title(live_titles, d.legacy_id, d.title)
    _validate_fenced_occurrences(
        scan,
        valid_targets=known_targets,
        tombstoned_ids=tombstoned_ids,
        live_titles=live_titles,
    )

    per_family_counts: dict[str, dict[str, int]] = {}
    for d in definitions:
        prefix = d.canonical_id.split("-")[0]
        rec = per_family_counts.setdefault(prefix, {"definitions": 0, "references": 0})
        rec["definitions"] += 1
    for ref in references:
        prefix = ref.raw_id.split("-")[0]
        rec = per_family_counts.setdefault(prefix, {"definitions": 0, "references": 0})
        rec["references"] += 1

    collisions = {
        legacy_id: count
        for legacy_id, count in sorted(legacy_counts.items())
        if count > 1
    }

    try:
        res_rel = resolution_path.relative_to(ROOT).as_posix()
    except ValueError:
        res_rel = str(resolution_path)

    return {
        "schema": AUDIT_SCHEMA,
        "grammarVersion": GRAMMAR_SCHEMA,
        "source": plan_path.name,
        "resolution": res_rel,
        "sourceDefinitionCount": len(definitions),
        "canonicalDefinitionCount": len(set(canonical_ids)),
        "referenceCount": len(references),
        "exampleCount": len(scan.examples),
        "fencedDefinitionCount": len(scan.fenced_definitions),
        "goalCanonicalCount": len(actual_goals),
        "northStarCanonicalCount": len(actual_ns),
        "legacyCollisions": collisions,
        "perFamilyCounts": per_family_counts,
        "definitions": [
            {
                "legacyId": d.legacy_id,
                "canonicalId": d.canonical_id,
                "title": d.title,
                "line": d.line,
                "titleDigest": d.title_digest,
            }
            for d in definitions
        ],
        "status": "passed",
    }


def census_markdown_sources(
    paths: list[Path],
    resolution_path: Path = DEFAULT_RESOLUTION,
) -> dict[str, Any]:
    """Audits multiple markdown documents across the repository. Hook for check-policy.py."""
    resolution = _load_json(resolution_path)
    if resolution.get("schema") != RESOLUTION_SCHEMA:
        raise AuditError(ERR_SCHEMA_ERROR, "unsupported stable-ID resolution schema")
    raw_resolutions = resolution.get("resolutions")
    if not isinstance(raw_resolutions, list):
        raise AuditError(ERR_SCHEMA_ERROR, "resolutions must be an array")

    by_occurrence = {}
    res_titles_by_id: dict[str, set[str]] = {}
    repo_index = _load_repository_index(ROOT)
    valid_targets = set(repo_index.known)
    tombstoned_ids: set[str] = set(repo_index.tombstoned)
    live_titles: dict[tuple[str, int] | str, set[str]] = {
        key: set(titles) for key, titles in repo_index.titles.items()
    }

    for index, r in enumerate(raw_resolutions):
        if not isinstance(r, dict):
            raise AuditError(ERR_SCHEMA_ERROR, f"resolution row {index} is not an object")
        legacy_id = r.get("legacyId")
        title = r.get("title")
        canonical_id = r.get("canonicalId")
        digest = r.get("titleDigest")

        for field_name, value in (
            ("legacyId", legacy_id),
            ("title", title),
            ("canonicalId", canonical_id),
            ("titleDigest", digest),
        ):
            if not isinstance(value, str) or not value:
                raise AuditError(
                    ERR_SCHEMA_ERROR,
                    f"resolution row {index} field {field_name} must be a non-empty string, got {value!r}",
                )

        validate_identifier_syntax(legacy_id)
        validate_identifier_syntax(canonical_id)

        expected_digest = _title_digest(legacy_id, title)
        if digest != expected_digest:
            raise AuditError(
                ERR_FINGERPRINT_MISMATCH,
                f"title fingerprint mismatch for {legacy_id} / '{title}': expected {expected_digest}, got {digest}",
            )

        res_titles_by_id.setdefault(legacy_id, set()).add(title)
        res_titles_by_id.setdefault(_canonical_id(legacy_id), set()).add(title)
        res_titles_by_id.setdefault(canonical_id, set()).add(title)
        res_titles_by_id.setdefault(_canonical_id(canonical_id), set()).add(title)

        by_occurrence[(legacy_id, title)] = r
        by_occurrence[(_canonical_id(legacy_id), title)] = r

        is_tombstone = _is_tombstone_marker(r.get("status"), where=f"resolution row {index} status") or _is_tombstone_marker(
            r.get("disposition"), where=f"resolution row {index} disposition"
        )
        if is_tombstone:
            tombstoned_ids.add(legacy_id)
            tombstoned_ids.add(_canonical_id(legacy_id))
            tombstoned_ids.add(canonical_id)
            tombstoned_ids.add(_canonical_id(canonical_id))
        else:
            valid_targets.add(canonical_id)
            valid_targets.add(_canonical_id(canonical_id))
            valid_targets.add(legacy_id)
            valid_targets.add(_canonical_id(legacy_id))
            _add_title(live_titles, legacy_id, title)
            _add_title(live_titles, canonical_id, title)

    all_defs: list[ParsedDefinition] = []
    all_refs: list[ParsedReference] = []
    scans: list[MarkdownScan] = []

    for path in paths:
        if not path.is_file():
            raise AuditError(ERR_SCHEMA_ERROR, f"markdown source path does not exist: {path}")
        text = _strip_html_comments(path.read_text(encoding="utf-8-sig", errors="strict"))
        scan = _scan_markdown(text, source_name=str(path))
        scans.append(scan)
        all_defs.extend(scan.definitions)
        all_refs.extend(scan.references)

    for d in all_defs:
        expected_titles = res_titles_by_id.get(d.legacy_id) or res_titles_by_id.get(_canonical_id(d.legacy_id))
        if expected_titles is not None and d.title not in expected_titles:
            raise AuditError(
                ERR_FINGERPRINT_MISMATCH,
                f"markdown definition title '{d.title}' for {d.legacy_id} at {d.source}:{d.line} does not match resolution table",
            )

    def_counts: dict[tuple[str, int] | str, int] = {}
    for d in all_defs:
        key = _normalize_key(d.legacy_id)
        def_counts[key] = def_counts.get(key, 0) + 1

    for d in all_defs:
        key = _normalize_key(d.legacy_id)
        if def_counts[key] > 1:
            res_row = by_occurrence.get((d.legacy_id, d.title)) or by_occurrence.get((_canonical_id(d.legacy_id), d.title))
            if res_row is None:
                raise AuditError(
                    ERR_COLLISION,
                    f"unresolved collided stable definition {d.legacy_id} at {d.source}:{d.line}: {d.title}",
                )

    target_ids = valid_targets | {d.legacy_id for d in all_defs} | {_canonical_id(d.legacy_id) for d in all_defs}
    _validate_references(all_refs, valid_targets=target_ids, tombstoned_ids=tombstoned_ids)

    for d in all_defs:
        _add_title(live_titles, d.legacy_id, d.title)
    for scan in scans:
        _validate_fenced_occurrences(
            scan,
            valid_targets=target_ids,
            tombstoned_ids=tombstoned_ids,
            live_titles=live_titles,
        )

    return {
        "schema": AUDIT_SCHEMA,
        "grammarVersion": GRAMMAR_SCHEMA,
        "totalDefinitions": len(all_defs),
        "totalReferences": len(all_refs),
        "totalExamples": sum(len(scan.examples) for scan in scans),
        "totalFencedDefinitions": sum(len(scan.fenced_definitions) for scan in scans),
        "status": "passed",
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Resolve and audit FSS goal and North Star stable definitions against versioned grammar"
    )
    parser.add_argument("--plan", type=Path, default=DEFAULT_PLAN)
    parser.add_argument("--resolution", type=Path, default=DEFAULT_RESOLUTION)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--emit-grammar", action="store_true", help="Print stable-ID grammar as JSON")
    parser.add_argument("--jsonl", type=Path, help="Write classified occurrences to JSONL file")
    args = parser.parse_args()

    if args.emit_grammar:
        print(json.dumps(STABLE_ID_GRAMMAR, indent=2, sort_keys=True))
        return 0

    try:
        report = audit(args.plan, args.resolution)
    except (OSError, json.JSONDecodeError, AuditError) as exc:
        print(f"stable-ID audit failed: {exc}", file=sys.stderr)
        return 1
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    print(rendered, end="")
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")

    if args.jsonl is not None:
        args.jsonl.parent.mkdir(parents=True, exist_ok=True)
        plan_text = args.plan.read_text(encoding="utf-8-sig")
        scan = _scan_markdown(plan_text, source_name=args.plan.name)
        records = []
        for d in scan.definitions:
            records.append({
                "schema": "fss.stable_id_occurrence.v1",
                "grammarVersion": GRAMMAR_SCHEMA,
                "sourcePath": d.source,
                "line": d.line,
                "kind": OccurrenceKind.DEFINITION.value,
                "id": d.legacy_id,
                "semanticFingerprint": d.title_digest,
                "status": "active",
                "resolution": d.canonical_id or None,
            })
        for r in scan.references:
            records.append({
                "schema": "fss.stable_id_occurrence.v1",
                "grammarVersion": GRAMMAR_SCHEMA,
                "sourcePath": r.source,
                "line": r.line,
                "kind": OccurrenceKind.REFERENCE.value,
                "id": r.raw_id,
                "semanticFingerprint": hashlib.sha256(r.raw_id.encode()).hexdigest()[:16],
                "status": "active",
                "resolution": None,
            })
        for ex in scan.examples:
            records.append({
                "schema": "fss.stable_id_occurrence.v1",
                "grammarVersion": GRAMMAR_SCHEMA,
                "sourcePath": ex.source,
                "line": ex.line,
                "kind": OccurrenceKind.EXAMPLE.value,
                "id": ex.raw_id,
                "semanticFingerprint": hashlib.sha256(ex.raw_id.encode()).hexdigest()[:16],
                "status": "example",
                "resolution": None,
            })
        for fd in scan.fenced_definitions:
            records.append({
                "schema": "fss.stable_id_occurrence.v1",
                "grammarVersion": GRAMMAR_SCHEMA,
                "sourcePath": fd.source,
                "line": fd.line,
                "kind": OccurrenceKind.EXAMPLE.value,
                "id": fd.legacy_id,
                "semanticFingerprint": fd.title_digest,
                "status": "example-definition",
                "resolution": None,
            })
        with args.jsonl.open("w", encoding="utf-8") as f:
            for rec in records:
                f.write(json.dumps(rec, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


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
8. Claim-class realization: a promoted bundle of a realized class (``slo``, ``proof``, ``bounded_model``) has
   the evidence its registry row demands opened from disk and bound to the claim; each
   missing or mismatched item fails closed with a registered finding id. A bundle cannot pick
   its own class: the citing claim's class (for SLO ids, the SLO registry's) governs, and a
   bundle class that disagrees fails. An ``slo`` target and comparator come only from the
   authoritative registries/SLOS.md row (parsed by slo_validate), never from the measurement.
   A claim row declares its class in a ``Class`` column (the SLO registry governs SLO ids); a
   promoted bundle whose class no claim row or registry resolves fails closed, and a retained
   bundle inherits the class of the claim row that cites it.
9. Counting: only a passing bundle at a promoted level counts as verified; passing unpromoted
   bundles are reported separately, and 'draft'/'absent' support no readiness level at all.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import math
import os
import re
import sys
import tomllib
import unicodedata
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import architecture_registry_consistency  # noqa: F401  (policy-lane import contract)
from qualification_receipt import write_qualification_receipt  # noqa: F401  (the one atomic receipt writer)
import schema_validate
import slo_validate  # the one SLOS.md parser; slo targets are never re-parsed here
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
ERR_CLAIM_REGISTRY_DRIFT = "ERR-CLAIM-REGISTRY-DRIFT-001"
ERR_CLAIM_ID_REUSED = "ERR-CLAIM-ID-REUSED-001"
ERR_CLAIM_MISSING_FIELD = "ERR-CLAIM-MISSING-FIELD-001"
ERR_CLAIM_ASSUMPTIONS_MISSING = "ERR-CLAIM-ASSUMPTIONS-MISSING-001"
ERR_PROOF_FORMAL_MODEL_UNBOUND = "ERR-CLAIM-PROOF-FORMAL-MODEL-UNBOUND-001"
ERR_PROOF_MODEL_GENERATION_MISMATCH = "ERR-CLAIM-PROOF-MODEL-GENERATION-MISMATCH-001"
ERR_PROOF_THEOREM_UNBOUND = "ERR-CLAIM-PROOF-THEOREM-UNBOUND-001"
ERR_PROOF_FORMAL_ARTIFACT_MISSING = "ERR-CLAIM-PROOF-FORMAL-ARTIFACT-MISSING-001"
ERR_PROOF_TESTS_ONLY = "ERR-CLAIM-PROOF-TESTS-ONLY-001"
ERR_PROOF_TOOLCHAIN_UNBOUND = "ERR-CLAIM-PROOF-TOOLCHAIN-UNBOUND-001"
ERR_PROOF_CHECK_RECEIPT_INVALID = "ERR-CLAIM-PROOF-CHECK-RECEIPT-INVALID-001"
ERR_PROOF_UNPROVEN_PLACEHOLDER = "ERR-CLAIM-PROOF-UNPROVEN-PLACEHOLDER-001"
ERR_PROOF_UNSOUND_ESCAPE = "ERR-CLAIM-PROOF-UNSOUND-ESCAPE-001"
ERR_PROOF_PROVER_RUN_REQUIRED = "ERR-CLAIM-PROOF-PROVER-RUN-REQUIRED-001"
ERR_CLAIM_GENERATION_UNBOUND = "ERR-CLAIM-GENERATION-UNBOUND-001"
ERR_CLAIM_CLASS_REGISTRY_INVALID = "ERR-CLAIM-CLASS-REGISTRY-INVALID-001"
ERR_CLAIM_CLASS_EVIDENCE_UNINSPECTED = "ERR-CLAIM-CLASS-EVIDENCE-UNINSPECTED-001"
ERR_BOUND_DERIVATION_UNBOUND = "ERR-CLAIM-BOUND-DERIVATION-UNBOUND-001"
ERR_BOUND_EXPRESSION_UNBOUND = "ERR-CLAIM-BOUND-EXPRESSION-UNBOUND-001"
ERR_BOUND_UNITS_MISSING = "ERR-CLAIM-BOUND-UNITS-MISSING-001"
ERR_BOUND_TIGHTER_THAN_DERIVATION = "ERR-CLAIM-BOUND-TIGHTER-THAN-DERIVATION-001"
ERR_BOUND_SENSITIVITY_MISSING = "ERR-CLAIM-BOUND-SENSITIVITY-MISSING-001"
ERR_BOUND_VALUE_OUT_OF_DOMAIN = "ERR-CLAIM-BOUND-VALUE-OUT-OF-DOMAIN-001"
ERR_BOUND_DERIVATION_NOT_RECOMPUTABLE = "ERR-CLAIM-BOUND-DERIVATION-NOT-RECOMPUTABLE-001"
ERR_BOUND_DIMENSION_MISMATCH = "ERR-CLAIM-BOUND-DIMENSION-MISMATCH-001"
ERR_SLO_TARGET_UNBOUND = "ERR-CLAIM-SLO-TARGET-UNBOUND-001"
ERR_SLO_COMPARATOR_OVERRIDE = "ERR-CLAIM-SLO-COMPARATOR-OVERRIDE-001"
ERR_SLO_ACTUAL_INVALID = "ERR-CLAIM-SLO-ACTUAL-INVALID-001"
ERR_SLO_GENERATION_UNBOUND = "ERR-CLAIM-SLO-GENERATION-UNBOUND-001"
ERR_SLO_FRESHNESS_UNSET = "ERR-CLAIM-SLO-FRESHNESS-BOUND-UNSET-001"
ERR_SLO_WINDOW_INVALID = "ERR-CLAIM-SLO-WINDOW-INVALID-001"
ERR_SLO_MEASUREMENT_NOT_PASSED = "ERR-CLAIM-SLO-MEASUREMENT-NOT-PASSED-001"
ERR_SLO_ENVIRONMENT_UNRETAINED = "ERR-CLAIM-SLO-ENVIRONMENT-UNRETAINED-001"
ERR_SLO_REGISTRY_INVALID = "ERR-CLAIM-SLO-REGISTRY-INVALID-001"
ERR_CLAIM_CLASS_UNRESOLVED = "ERR-CLAIM-CLASS-UNRESOLVED-001"

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
    ERR_CLAIM_REGISTRY_DRIFT: {
        "trigger": "The machine-readable claims registry (architecture/claims.json) and its human-readable markdown source (registries/CLAIMS.md) differ in claim class IDs, ordering, meaning, minimum evidence, or row count",
        "remediation": "Reconcile architecture/claims.json and registries/CLAIMS.md so that all normative rows and fields are mirror-equal",
    },
    ERR_CLAIM_ID_REUSED: {
        "trigger": "A claim class ID is duplicated, renumbered, or reused across different claim classes",
        "remediation": "Preserve stable identities; never reuse, duplicate, or renumber an existing claim class ID",
    },
    ERR_CLAIM_MISSING_FIELD: {
        "trigger": "A claim class entry in the registry is missing required normative fields (id, meaning, minimum_evidence, requiredEvidence) or a table row lacks required columns",
        "remediation": "Provide all required normative fields for each claim class row in both JSON and Markdown",
    },
    ERR_SLO_FRESHNESS_UNSET: {
        "trigger": "An operation-cost row listing an 'slo' claim's SLO declares no measurement_max_age_days (the strictest bound over all such rows applies), so the measurement freshness bound is unset and staleness cannot be decided",
        "remediation": "A user decision: set measurement_max_age_days on the operation's row in architecture/operation_cost_registry.toml; the checker never assumes a default",
    },
    ERR_CLAIM_CLASS_REGISTRY_INVALID: {
        "trigger": "A registry that binds claim ids to classes (architecture/invariants.json) declares an id that is not an exact token, or declares one id more than once (compared ignoring case), e.g. once tombstoned and once normative",
        "remediation": "Give every stable id exactly one row; a tombstoned id keeps its single tombstone row",
    },
    ERR_CLAIM_CLASS_EVIDENCE_UNINSPECTED: {
        "trigger": "A promoted claim's class has no evidence inspection in this checker (only slo, proof, and bounded_model are realized), so its bundle's evidence names alone can never verify it",
        "remediation": "Realize the class's registry row with evidence inspection, or keep the claim below a promoted readiness level",
    },
    ERR_CLAIM_ASSUMPTIONS_MISSING: {
        "trigger": "A promoted 'proof' or 'bounded_model' claim declares no assumptions, or an assumption lacks a non-empty 'id' and 'statement', or an assumption id is duplicated",
        "remediation": "Declare every assumption the claim rests on as a named {id, statement} entry",
    },
    ERR_PROOF_FORMAL_MODEL_UNBOUND: {
        "trigger": "A promoted 'proof' claim declares no formal model reference, or its retained fss.formal_model.v1 manifest or model source is missing, unreadable, not digest-bound, names a different model, or is not declared for the claim ID",
        "remediation": "Retain the declared formal model (manifest plus digest-bound source) and bind it to the claim ID",
    },
    ERR_PROOF_MODEL_GENERATION_MISMATCH: {
        "trigger": "A 'proof' claim's formal model generation differs from the claim generation, from the declared model reference, or from the generation the check receipt checked",
        "remediation": "Re-check the proof against the formal model at the claim's exact generation; never splice generations",
    },
    ERR_PROOF_THEOREM_UNBOUND: {
        "trigger": "A 'proof' claim declares no theorem statement, binds the theorem to a different claim, or the check receipt checked a different statement",
        "remediation": "Bind the exact theorem statement to the claim ID and re-check it",
    },
    ERR_PROOF_FORMAL_ARTIFACT_MISSING: {
        "trigger": "A 'proof' claim retains no single formal proof artifact, or it is not on disk, empty, not digest-bound, or not a source of the declared formal checker's language",
        "remediation": "Retain the exact formal artifact the checker verified",
    },
    ERR_PROOF_TESTS_ONLY: {
        "trigger": "A 'proof' claim is backed by tests (test-runner toolchain, test source, or test results) instead of a machine-checked formal artifact",
        "remediation": "Demote the claim to a class that tests can support, or supply a machine-checked formal proof",
    },
    ERR_PROOF_TOOLCHAIN_UNBOUND: {
        "trigger": "A 'proof' claim's formal checker identity is missing, not a registered formal checker, 'latest'-aliased, or differs between the bundle and its check receipt",
        "remediation": "Pin the exact registered formal checker and version in both the bundle and the check receipt",
    },
    ERR_PROOF_CHECK_RECEIPT_INVALID: {
        "trigger": "A 'proof' claim's check receipt is missing, malformed, non-passing, or not bound to the claim ID, the formal model, and the formal artifact digest",
        "remediation": "Re-run the formal checker and retain a passing fss.proof_check_receipt.v1 bound to the claim, model, and artifact",
    },
    ERR_PROOF_UNPROVEN_PLACEHOLDER: {
        "trigger": "A 'proof' claim's formal artifact contains, outside comments and string literals, an unproven placeholder: a Lean identifier component sorry, sorryAx, admit, or stop (or a confusable lookalike), or TLAPS OMITTED in any case",
        "remediation": "Complete the proof; a placeholder is never a checked proof",
    },
    ERR_PROOF_PROVER_RUN_REQUIRED: {
        "trigger": "A promoted 'proof' bundle passed every static pre-filter check, but a proof counts as verified only with a qualification receipt from actually running the prover in sealed qualification (for example Lean lake build plus #print axioms showing only the standard axioms, or tlapm with every obligation proved), bound to the artifact digest, prover version, and theorem name; no such receipt mechanism is defined yet",
        "remediation": "A user decision: define the prover-run qualification receipt; until then no proof claim is verified, whatever its static evidence",
    },
    ERR_PROOF_UNSOUND_ESCAPE: {
        "trigger": "A 'proof' claim's formal artifact contains, outside comments and string literals, an escape the static pre-filter knows can make a false theorem check: a Lean axiom, compiler trust (native_decide, decide +native, bv_decide, implemented_by, ofReduceBool, trustCompiler, extern), lcProof, a kernel bypass (skipKernelTC, set_option debug.*), user metaprogramming (elab, by_elab, macro, syntax, run_cmd, initialize), a #-command, or an import outside Init/Std/Lean; or a TLA+ AXIOM, ASSUMPTION, or ASSUME outside a THEOREM sequent (nested modules included), or EXTENDS/INSTANCE of a non-standard module other than the declared model",
        "remediation": "Remove the escape; declare assumptions in the proof bundle and model, never as unchecked axioms in the proof",
    },
    ERR_CLAIM_GENERATION_UNBOUND: {
        "trigger": "A promoted 'proof' or 'bounded_model' claim is cited by no claim row declaring its current generation (Generation column), or its citing rows declare conflicting generations",
        "remediation": "Declare the claim's current generation in its claim row and bind the proof bundle to exactly that generation",
    },
    ERR_BOUND_DERIVATION_UNBOUND: {
        "trigger": "A promoted 'bounded_model' claim retains no single fss.bound_derivation.v1 derivation, or it is not on disk, not digest-bound, malformed, has no derivation steps, or is not bound to the claim ID and generation",
        "remediation": "Retain the analytic derivation bound to the claim ID and its exact generation",
    },
    ERR_BOUND_EXPRESSION_UNBOUND: {
        "trigger": "A 'bounded_model' claim's bound expression, comparator, or value is missing, non-finite, bound to another claim, or differs from the derivation",
        "remediation": "Bind the exact derived bound expression, comparator, and value to the claim ID",
    },
    ERR_BOUND_UNITS_MISSING: {
        "trigger": "A 'bounded_model' claim's bound or derivation declares no units, or the claimed units differ from the derivation's units",
        "remediation": "Declare identical explicit units in the claim and its derivation; units are never converted implicitly",
    },
    ERR_BOUND_TIGHTER_THAN_DERIVATION: {
        "trigger": "A 'bounded_model' claim asserts a bound tighter than the analytically derived bound (below a derived upper bound or above a derived lower bound)",
        "remediation": "Claim at most the derived bound, or retain a derivation that supports the tighter bound",
    },
    ERR_BOUND_SENSITIVITY_MISSING: {
        "trigger": "A 'bounded_model' claim's derivation declares no sensitivity analysis or no invalidators",
        "remediation": "Retain the sensitivity analysis and the invalidating conditions with the derivation",
    },
    ERR_BOUND_VALUE_OUT_OF_DOMAIN: {
        "trigger": "A 'bounded_model' claimed, derived, or input value lies outside its registered unit's domain (negative for any registered unit, above 100 for percent units, above 1 for auprc)",
        "remediation": "Correct the value or its unit; a bound outside its unit's domain bounds nothing",
    },
    ERR_BOUND_DIMENSION_MISMATCH: {
        "trigger": "A 'bounded_model' derivation formula is dimensionally inconsistent: + or - combines different units, or the units propagated through * and / differ from the derivation's units (count units are dimensionless; bare numbers adopt the other operand's unit)",
        "remediation": "Correct the formula or the recorded input units; units are never converted implicitly",
    },
    ERR_BOUND_DERIVATION_NOT_RECOMPUTABLE: {
        "trigger": "A 'bounded_model' derivation records no usable inputs {name: {value, units}} or no arithmetic formula over them, the formula is not the derived expression's right-hand side, uses anything beyond + - * / on recorded inputs and numbers, or does not recompute the derived value",
        "remediation": "Record every input with its value and units and the exact arithmetic yielding the derived value",
    },
    ERR_SLO_TARGET_UNBOUND: {
        "trigger": "An 'slo' claim's target cannot be resolved to exactly one numeric threshold of its registries/SLOS.md row (unregistered, tombstoned, or non-numeric row), the measurement declares no or a different unit, or the measurement restates a target that differs from the row or uses a non-canonical target field",
        "remediation": "Claim only an SLO row with a registered numeric threshold, measure in its exact unit, and never restate or relax the target",
    },
    ERR_SLO_COMPARATOR_OVERRIDE: {
        "trigger": "An 'slo' measurement declares a comparator that differs from the comparator of its registries/SLOS.md row",
        "remediation": "Remove the comparator from the measurement; the SLO row alone defines the comparison",
    },
    ERR_SLO_ACTUAL_INVALID: {
        "trigger": "An 'slo' measurement has no single canonical numeric 'actual': it is missing, non-numeric, boolean, negative, overflowing, present only as a rounded value, or shadowed by another actual-like field",
        "remediation": "Retain exactly one finite, non-negative numeric 'actual' in the SLO unit; never report only a rounded value",
    },
    ERR_SLO_GENERATION_UNBOUND: {
        "trigger": "An 'slo' bundle or measurement declares no generation, or the measurement declares no operation-cost registry generation",
        "remediation": "Bind the bundle and its measurement to one explicit generation and to the operation-cost registry generation measured against",
    },
    ERR_SLO_WINDOW_INVALID: {
        "trigger": "An 'slo' measurement validity window is missing, unparseable, zone-less, empty, finished before it started, or lies in the future",
        "remediation": "Retain a zone-qualified ISO-8601 measurement window that ended before the evaluation instant",
    },
    ERR_SLO_MEASUREMENT_NOT_PASSED: {
        "trigger": "An 'slo' measurement status is missing or anything other than 'passed'",
        "remediation": "Re-run the measurement; a failed, partial, or unlabelled run never supports an slo claim",
    },
    ERR_SLO_ENVIRONMENT_UNRETAINED: {
        "trigger": "An 'slo' claim retains no single digest-bound fss.environment_manifest.v1 artifact, or its measurement is not bound to that manifest's digest",
        "remediation": "Retain the exact environment manifest and bind the measurement to its digest",
    },
    ERR_SLO_REGISTRY_INVALID: {
        "trigger": "The SLO registry (registries/SLOS.md) or operation-cost registry (architecture/operation_cost_registry.toml) consulted for an 'slo' claim is missing, unreadable, empty, malformed, or declares no rows or generation",
        "remediation": "Repair the registry under the audited root; slo claims are never checked against a silently skipped registry",
    },
    ERR_CLAIM_CLASS_UNRESOLVED: {
        "trigger": "A promoted proof bundle's claim id is bound to a claim class by no registry (SLO ids by registries/SLOS.md grammar, invariant ids by architecture/invariants.json); a citing row's Class column or the bundle's own declaration never resolves a class",
        "remediation": "Declare the class in the citing claim row; a bundle never chooses the class its evidence is checked against",
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

# Registered levels a proof bundle can never support (they assert that nothing exists yet).
UNSUPPORTING_LEVELS: frozenset[str] = frozenset({"absent", "draft"})

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

# Claim class 'slo' (fss-x4a.30.87.5).
SLO_REGISTRY_FILE = "registries/SLOS.md"
OPERATION_COST_REGISTRY_FILE = "architecture/operation_cost_registry.toml"
SLO_MEASUREMENT_SCHEMA = "fss.slo_measurement.v1"
SLO_ENVIRONMENT_SCHEMA = "fss.environment_manifest.v1"
# The measurement freshness bound is a policy value the user sets per operation-cost row
# (measurement_max_age_days); none is hard-coded here, and an unset bound fails closed.
SLO_MAX_AGE_FIELD = "measurement_max_age_days"
SLO_MAX_AGE_RANGE_DAYS = (1, 36500)
# A positive SLO target grammar (review S1), the tightest that accepts every live
# registries/SLOS.md target; tests pin that every live target parses. Tokens are whitespace-
# separated and compared exactly:
#   TARGET  := [STATISTIC] SUBJECT* CLAUSE ("and" CLAUSE)* CONTEXT*
#   CLAUSE  := COMPARATOR NUMBER UNIT        (UNIT: slo_validate.REGISTERED_UNITS; '%' may be glued)
# A target with no comparator character declares no threshold. Anything else is unbound.
SLO_TARGET_STATISTICS: frozenset[str] = frozenset({"p50", "p90", "p95", "p99", "p99.9"})
SLO_TARGET_COMPARATORS: dict[str, str] = {"≤": "<=", "<": "<", "≥": ">=", ">": ">"}
SLO_TARGET_SUBJECT_WORDS: frozenset[str] = frozenset({
    "glass-to-glass", "live-proxy", "latency", "first", "event", "hypothesis", "alert", "dispatch",
    "bounded", "event-status", "query", "initial", "agent", "answer", "cold", "mission",
    "orientation", "reaches", "a", "useful", "`SituationCapsule`", "SituationCapsule", "in",
    "material", "committed", "delta", "available", "to", "subscribed", "local",
})
SLO_TARGET_CONTEXT_WORDS: frozenset[str] = frozenset({
    "on", "LAN", "after", "first", "observable", "threat", "evidence", "policy", "corroboration",
    "without", "model", "refinement", ",", "resumable", "qualified", "observation-window",
    "continuity", "for", "wired/reference", "sensors",
})
SLO_TARGET_COMPARATOR_CHARS = frozenset("≤≥<>=")
_SLO_TARGET_NUMBER_RE = re.compile(r"(\d{1,3}(?:,\d{3})+|\d+)(?:\.\d+)?")
# slo_validate findings that make the SLO target definitions themselves untrustworthy.
SLO_STRUCTURAL_CODES: frozenset[str] = frozenset({
    slo_validate.CODE_INVALID_SLO_ID,
    slo_validate.CODE_DUPLICATE_SLO_ID,
    slo_validate.CODE_INVALID_SLO_STATUS,
    slo_validate.CODE_MISSING_TARGET,
    slo_validate.CODE_INVALID_TOMBSTONE,
    slo_validate.CODE_MALFORMED_TABLE,
    slo_validate.CODE_AMBIGUOUS_TARGET_UNIT,
})
_COMPARATOR_ALIASES: dict[str, str] = {
    "\u2264": "<=", "<=": "<=", "le": "<=",
    "<": "<", "lt": "<",
    "\u2265": ">=", ">=": ">=", "ge": ">=",
    ">": ">", "gt": ">",
}
_SLO_THRESHOLD_RE = re.compile(r"(\u2264|<=|\u2265|>=|<|>)\s*(\d{1,3}(?:,\d{3})+(?:\.\d+)?|\d+(?:\.\d+)?)")
SLO_COMPARATOR_FIELDS = ("comparison", "comparator", "operator")
SLO_ROUNDED_FIELDS = ("reported_rounded", "reported_rounded_ms", "rounded", "rounded_value", "rounded_ms")
# Any field that could carry a competing actual value (actual_ms, achieved, observed_*, p95_ms, ...).
_ACTUAL_ALIAS_RE = re.compile(r"^(?:actual|achieved|observed|measured)(?:_|$)|^p\d{1,3}(?:_|$)|^value$", re.IGNORECASE)


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
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:  # RecursionError: nesting too deep
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
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:  # RecursionError: nesting too deep
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
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:  # RecursionError: nesting too deep
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


@dataclass(frozen=True)
class CostRegistry:
    """The operation-cost registry an slo claim is bound to."""
    generation: str
    operations: dict[str, dict[str, Any]]


@dataclass(frozen=True)
class SloThreshold:
    """One numeric threshold parsed from the target cell of an authoritative SLO row."""
    comparator: str
    value: float
    unit: str


def _authority_file(root: Path, rel: str) -> tuple[Path, Path]:
    """The authority file for an audit of root: the copy under root whenever anything exists
    there (so a malformed or empty copy is audited, never bypassed); the repository's own copy
    only when root holds nothing at that path. Returns (path, the root it belongs to)."""
    candidate = root / rel
    if candidate.exists() or candidate.is_symlink():
        return candidate, root
    return ROOT / rel, ROOT


def _registry_invalid(rel: str, message: str) -> list[ClaimFinding]:
    return [_finding(ERR_SLO_REGISTRY_INVALID, rel, "file", message, {"registry": rel})]


def _read_authority_text(path: Path, rel: str) -> tuple[str | None, list[ClaimFinding]]:
    if not path.is_file():
        return None, _registry_invalid(rel, f"Registry '{rel}' is missing or not a regular file")
    try:
        text = path.read_bytes().decode("utf-8")
    except OSError as exc:
        return None, _registry_invalid(rel, f"Registry '{rel}' could not be read: {exc}")
    except UnicodeDecodeError as exc:
        return None, _registry_invalid(rel, f"Registry '{rel}' is not valid UTF-8: {exc}")
    if not text.strip():
        return None, _registry_invalid(rel, f"Registry '{rel}' is empty")
    return text, []


def load_operation_cost_registry(root: Path) -> tuple[CostRegistry | None, list[ClaimFinding]]:
    """Loads architecture/operation_cost_registry.toml (operation id -> row, plus its declared
    generation). Every defect is returned as a finding; the registry is never silently empty."""
    path, _ = _authority_file(root, OPERATION_COST_REGISTRY_FILE)
    text, findings = _read_authority_text(path, OPERATION_COST_REGISTRY_FILE)
    if text is None:
        return None, findings
    try:
        data = tomllib.loads(text)
    except (ValueError, OverflowError) as exc:  # TOMLDecodeError, or an integer beyond the digit limit
        return None, _registry_invalid(OPERATION_COST_REGISTRY_FILE, f"Registry '{OPERATION_COST_REGISTRY_FILE}' is not valid TOML: {exc}")
    generation = _nonempty_str(data.get("generation"))
    if generation is None:
        return None, _registry_invalid(OPERATION_COST_REGISTRY_FILE, f"Registry '{OPERATION_COST_REGISTRY_FILE}' declares no generation")
    rows = data.get("operation")
    if not isinstance(rows, list) or not rows:
        return None, _registry_invalid(OPERATION_COST_REGISTRY_FILE, f"Registry '{OPERATION_COST_REGISTRY_FILE}' declares no [[operation]] rows")
    operations: dict[str, dict[str, Any]] = {}
    problems: list[str] = []
    for idx, row in enumerate(rows):
        op_id = _nonempty_str(row.get("id")) if isinstance(row, dict) else None
        slo_ids = row.get("slo_ids") if isinstance(row, dict) else None
        if op_id is None:
            problems.append(f"operation[{idx}] has no id")
        elif not isinstance(slo_ids, list) or not all(isinstance(s, str) for s in slo_ids):
            problems.append(f"operation '{op_id}' slo_ids is not a list of strings")
        elif op_id in operations:
            problems.append(f"operation '{op_id}' is declared twice")
        else:
            operations[op_id] = row
    if problems:
        return None, _registry_invalid(OPERATION_COST_REGISTRY_FILE, f"Registry '{OPERATION_COST_REGISTRY_FILE}' is malformed: {problems}")
    return CostRegistry(generation=generation, operations=operations), []


_MD_FENCE_OPEN_RE = re.compile(r" {0,3}(`{3,}|~{3,})(.*)$")
_MD_FENCE_CLOSE_RE = re.compile(r" {0,3}(`{3,}|~{3,})[ \t]*$")


def _visible_markdown(text: str) -> str:
    """Markdown as rendered, for SLOS.md and every claim table alike: fenced code blocks are
    blanked with CommonMark fence rules (a fence closes only with the same character at least as
    long; a backtick fence's info string has no backtick), HTML comments outside fences are
    removed, and a comment opener inside a fence is fence content. Line structure is kept."""
    out: list[str] = []
    fence: tuple[str, int] | None = None
    in_comment = False
    for line in text.splitlines():
        if fence is not None:
            closing = _MD_FENCE_CLOSE_RE.fullmatch(line)
            if closing and closing.group(1)[0] == fence[0] and len(closing.group(1)) >= fence[1]:
                fence = None
            out.append("")
            continue
        if in_comment:
            end = line.find("-->")
            if end < 0:
                out.append("")
                continue
            line = line[end + 3:]
            in_comment = False
        elif (opening := _MD_FENCE_OPEN_RE.match(line)) and not (opening.group(1)[0] == "`" and "`" in opening.group(2)):
            fence = (opening.group(1)[0], len(opening.group(1)))
            out.append("")
            continue
        visible, rest = "", line
        while True:
            start = rest.find("<!--")
            if start < 0:
                visible += rest
                break
            visible += rest[:start]
            end = rest.find("-->", start + 4)
            if end < 0:
                in_comment = True
                break
            rest = rest[end + 3:]
        out.append(visible)
    return "\n".join(out) + "\n"



def load_slo_registry(root: Path) -> tuple[dict[str, slo_validate.SloRow], list[ClaimFinding]]:
    """Resolves the authoritative SLO rows through slo_validate.parse_slos (the one SLOS.md
    parser). Structural defects (IDs, duplicates, table shape, target grammar, tombstones,
    statuses) fail closed; proof-root findings about promoted rows are the claim checker's own
    concern and are not a defect of the target definitions."""
    path, base = _authority_file(root, SLO_REGISTRY_FILE)
    text, findings = _read_authority_text(path, SLO_REGISTRY_FILE)
    if text is None:
        return {}, findings
    slo_findings: list[slo_validate.SloFinding] = []
    rows = slo_validate.parse_slos(_visible_markdown(text), path, base, slo_findings)
    structural = [f for f in slo_findings if f.severity == "error" and f.code in SLO_STRUCTURAL_CODES]
    if structural:
        return {}, _registry_invalid(
            SLO_REGISTRY_FILE,
            f"Registry '{SLO_REGISTRY_FILE}' is malformed: {[f'{f.code}: {f.message}' for f in structural[:5]]}",
        )
    if not rows:
        return {}, _registry_invalid(SLO_REGISTRY_FILE, f"Registry '{SLO_REGISTRY_FILE}' declares no SLO rows")
    return rows, []


def _slo_target_tokens(target: str) -> list[str]:
    tokens: list[str] = []
    for token in target.split():
        if len(token) > 1 and token.endswith(","):
            tokens.extend([token[:-1], ","])
        else:
            tokens.append(token)
    return tokens


def _parse_slo_target(target: str) -> tuple[list[SloThreshold], str | None]:
    """Reads an SLO target cell with the positive grammar above. Returns (thresholds, None), or
    ([], reason) when the target contains a comparator but is not a sentence of the grammar."""
    if not any(ch in SLO_TARGET_COMPARATOR_CHARS for ch in target):
        return [], None
    tokens = _slo_target_tokens(target)
    units = sorted(slo_validate.REGISTERED_UNITS, key=lambda u: -len(u.split()))
    n, pos = len(tokens), 0
    if pos < n and tokens[pos] in SLO_TARGET_STATISTICS:
        pos += 1
    while pos < n and tokens[pos] not in SLO_TARGET_COMPARATORS:
        if tokens[pos] not in SLO_TARGET_SUBJECT_WORDS:
            return [], f"'{tokens[pos][:24]}' is not a subject word of the SLO target grammar"
        pos += 1
    if pos == n:
        return [], "no comparator stands alone as a token"
    thresholds: list[SloThreshold] = []
    while True:
        comparator = SLO_TARGET_COMPARATORS[tokens[pos]]
        pos += 1
        if pos == n:
            return [], "a comparator is not followed by a number"
        number_token, unit = tokens[pos], None
        if number_token.endswith("%") and _SLO_TARGET_NUMBER_RE.fullmatch(number_token[:-1]):
            number_token, unit = number_token[:-1], "%"
        if not _SLO_TARGET_NUMBER_RE.fullmatch(number_token):
            return [], f"'{number_token[:24]}' is not a threshold number"
        value = float(number_token.replace(",", ""))
        if not math.isfinite(value):
            return [], f"threshold '{number_token[:24]}...' is not a finite number"
        pos += 1
        if unit is None:
            for candidate in units:
                width = len(candidate.split())
                if " ".join(tokens[pos:pos + width]) == candidate:
                    unit, pos = candidate, pos + width
                    break
        if unit is None:
            return [], f"'{' '.join(tokens[pos:pos + 2])[:24]}' is not a registered unit"
        thresholds.append(SloThreshold(comparator, value, unit))
        if pos + 1 < n and tokens[pos] == "and" and tokens[pos + 1] in SLO_TARGET_COMPARATORS:
            pos += 1
            continue
        break
    for token in tokens[pos:]:
        if token not in SLO_TARGET_CONTEXT_WORDS:
            return [], f"'{token[:24]}' is not a context word of the SLO target grammar"
    return thresholds, None


def _repository_slo_ids(root: Path) -> set[str] | None:
    """Ids of the rows of registries/SLOS.md under root, or None when that registry cannot be
    read (the slo verifier then refuses the claim as ERR-CLAIM-SLO-REGISTRY-INVALID-001)."""
    rows, registry_findings = load_slo_registry(root)
    return None if registry_findings else set(rows)


def _registry_claim_class(
    claim_id: Any,
    class_bindings: dict[str, str | None] | None = None,
    slo_root: Path | None = None,
) -> str | None:
    """The claim class a registry binds to a claim id. An SLO-grammar id is an 'slo' claim only
    when registries/SLOS.md (under slo_root, else the repository's) has its row; explicit
    bindings never bind SLO-grammar ids. Any other id only through class_bindings, which the
    audit loads from the owning registries; a tombstoned id is bound to None and stays unbound.
    A claim row's Class column never binds."""
    if not isinstance(claim_id, str):
        return None
    slo_id = claim_id.strip().strip("`").strip()
    if slo_validate.SLO_ID_REGEX.match(slo_id):
        members = _repository_slo_ids(slo_root if slo_root is not None else ROOT)
        return "slo" if members is None or slo_id in members else None
    return class_bindings.get(claim_id) if class_bindings else None


INVARIANT_REGISTRY_FILE = "architecture/invariants.json"


def load_claim_class_bindings(root: Path) -> tuple[dict[str, str | None], list[ClaimFinding]]:
    """Claim-id -> class bindings from the owning machine registries under root (the repository's
    own copy when root has none). Invariant ids are bound by architecture/invariants.json; a
    tombstoned invariant id is bound to None so that no explicit binding can revive it. SLO ids
    are bound by their registries/SLOS.md rows in _registry_claim_class. No repository registry
    binds proof, bounded_model, statistical, benchmark, compatibility, or agent claim ids yet."""
    path, _ = _authority_file(root, INVARIANT_REGISTRY_FILE)
    data, findings = _read_json_document(path, INVARIANT_REGISTRY_FILE, "invariant registry")
    if data is None:
        return {}, findings
    rows = data.get("invariants")
    if not isinstance(rows, list) or not rows:
        return {}, [_finding(ERR_EMPTY_INPUT, INVARIANT_REGISTRY_FILE, "invariants", f"Registry '{INVARIANT_REGISTRY_FILE}' declares no invariants")]
    bindings: dict[str, str | None] = {}
    folded: set[str] = set()
    for idx, row in enumerate(rows):
        inv_id = _exact_token(row.get("id")) if isinstance(row, dict) else None
        if inv_id is None:
            return {}, [_finding(ERR_CLAIM_CLASS_REGISTRY_INVALID, INVARIANT_REGISTRY_FILE, f"invariants[{idx}]", f"Invariant row {idx} declares no exact id: {row!r}")]
        if inv_id.casefold() in folded:
            return {}, [_finding(
                ERR_CLAIM_CLASS_REGISTRY_INVALID, INVARIANT_REGISTRY_FILE, f"invariants[{idx}]",
                f"Invariant id '{inv_id}' is declared more than once (ids are compared ignoring case); no claim can be bound through it",
                {"id": inv_id},
            )]
        folded.add(inv_id.casefold())
        status = row.get("status")
        tombstoned = isinstance(status, str) and status.strip().lower() in STALE_STATUSES
        bindings[inv_id] = None if tombstoned else "invariant"
    return bindings, []


def _scan_nan_inf_negative(obj: Any, path_str: str, location: str, findings: list[ClaimFinding]) -> bool:
    """Scans structures recursively for NaN or Infinity float/string values."""
    has_error = False
    if isinstance(obj, float):
        if math.isnan(obj) or math.isinf(obj):
            findings.append(_finding(
                ERR_CLAIM_LEVEL_EXCEEDED, path_str, location,
                f"Numeric value corrupted by NaN or Infinity: observed {obj!r}",
            ))
            return True
    elif isinstance(obj, str):
        s_lower = obj.strip().lower()
        if s_lower in ("nan", "+nan", "-nan", "infinity", "+infinity", "-infinity", "inf", "-inf"):
            findings.append(_finding(
                ERR_CLAIM_LEVEL_EXCEEDED, path_str, location,
                f"Numeric value corrupted by NaN or Infinity string: observed {obj!r}",
            ))
            return True
    elif isinstance(obj, dict):
        for k, v in obj.items():
            loc = f"{location}.{k}" if location else str(k)
            if _scan_nan_inf_negative(v, path_str, loc, findings):
                has_error = True
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            loc = f"{location}[{idx}]"
            if _scan_nan_inf_negative(item, path_str, loc, findings):
                has_error = True
    return has_error


def _check_slo_window(
    meas: dict[str, Any],
    now: datetime,
    max_age: timedelta | None,
    path_str: str,
    loc: str,
    params: dict[str, Any],
    findings: list[ClaimFinding],
) -> None:
    """The measurement window is a real validity interval: both ends zone-qualified ISO-8601,
    finished strictly after started, not in the future, and no older than the operation-cost
    row's measurement_max_age_days (an unset bound is reported by the caller, never assumed)."""
    window = meas.get("measurement_window")
    if not isinstance(window, dict):
        findings.append(_finding(ERR_SLO_WINDOW_INVALID, path_str, f"{loc}.measurement_window",
                                 "Measurement declares no measurement_window {started_at, finished_at}", params))
        return
    started_raw, finished_raw = window.get("started_at"), window.get("finished_at")
    started, finished = _parse_instant(started_raw), _parse_instant(finished_raw)
    if started is None or finished is None:
        findings.append(_finding(
            ERR_SLO_WINDOW_INVALID, path_str, f"{loc}.measurement_window",
            f"Measurement window {started_raw!r}..{finished_raw!r} is not a pair of zone-qualified ISO-8601 instants",
            params,
        ))
    elif finished <= started:
        findings.append(_finding(
            ERR_SLO_WINDOW_INVALID, path_str, f"{loc}.measurement_window",
            f"Measurement window finished at {finished_raw} which is not after it started at {started_raw}",
            params,
        ))
    elif finished > now:
        findings.append(_finding(
            ERR_SLO_WINDOW_INVALID, path_str, f"{loc}.measurement_window",
            f"Measurement window ends at {finished_raw}, after the evaluation instant {now.isoformat()}",
            params,
        ))
    elif max_age is not None and now - finished > max_age:
        findings.append(_finding(
            ERR_STALE_GENERATION, path_str, f"{loc}.measurement_window",
            f"Measurement window ended at {finished_raw}, older than the registry's measurement_max_age_days "
            f"of {max_age.days} days as of {now.isoformat()}",
            {**params, "finished_at": finished_raw, "max_age_days": max_age.days},
        ))


def _resolve_slo_threshold(
    claim_id: str,
    slo_rows: dict[str, slo_validate.SloRow],
    meas: dict[str, Any],
    path_str: str,
    loc: str,
    params: dict[str, Any],
    findings: list[ClaimFinding],
) -> SloThreshold | None:
    """The single threshold of the authoritative SLO row measured in the measurement's unit."""
    def unbound(message: str) -> None:
        findings.append(_finding(ERR_SLO_TARGET_UNBOUND, path_str, f"{loc}.target", message, params))

    row = slo_rows.get(claim_id)
    if row is None:
        unbound(f"Claim '{claim_id}' is not a row of {SLO_REGISTRY_FILE}; its target cannot be resolved")
        return None
    if row.is_tombstone:
        unbound(f"SLO '{claim_id}' is tombstoned; it has no active target")
        return None
    thresholds, defect = _parse_slo_target(row.target)
    if defect is not None:
        unbound(f"SLO '{claim_id}' target '{row.target[:120]}' is outside the SLO target grammar: {defect}")
        return None
    if thresholds and not slo_validate.validate_target_units(row.target, False):
        thresholds = []
    if not thresholds:
        unbound(f"SLO '{claim_id}' target '{row.target}' declares no numeric threshold a measurement can establish")
        return None
    unit = _exact_text(meas.get("unit"))
    if unit is None:
        unbound(f"Measurement declares no exact unit (got {meas.get('unit')!r}); SLO '{claim_id}' thresholds are in {sorted({t.unit for t in thresholds})}")
        return None
    matching = [t for t in thresholds if t.unit == unit]
    if len(matching) != 1:
        unbound(
            f"Measurement unit '{unit}' selects {len(matching)} thresholds of SLO '{claim_id}' target "
            f"'{row.target}' (units {sorted({t.unit for t in thresholds})}); units are never converted"
        )
        return None
    return matching[0]


def _slo_freshness_bound(
    cost_registry: CostRegistry,
    claim_id: str,
    path_str: str,
    loc: str,
    params: dict[str, Any],
    findings: list[ClaimFinding],
) -> timedelta | None:
    """The strictest measurement_max_age_days over every operation row listing the SLO, so a
    measurement cannot pick a laxer row (review S2). Every such row must set a valid bound; an
    unset one fails closed, a malformed one is a registry finding."""
    rows = sorted((op_id, row) for op_id, row in cost_registry.operations.items() if claim_id in row["slo_ids"])
    low, high = SLO_MAX_AGE_RANGE_DAYS
    invalid = [op_id for op_id, row in rows if row.get(SLO_MAX_AGE_FIELD) is not None and (
        isinstance(row[SLO_MAX_AGE_FIELD], bool) or not isinstance(row[SLO_MAX_AGE_FIELD], int)
        or not low <= row[SLO_MAX_AGE_FIELD] <= high)]
    if invalid:
        findings.extend(_registry_invalid(
            OPERATION_COST_REGISTRY_FILE,
            f"Operation(s) {invalid} {SLO_MAX_AGE_FIELD} is not a whole number of days in [{low}, {high}]",
        ))
        return None
    unset = [op_id for op_id, row in rows if row.get(SLO_MAX_AGE_FIELD) is None]
    if not rows or unset:
        findings.append(_finding(
            ERR_SLO_FRESHNESS_UNSET, path_str, f"{loc}.operation_id",
            f"Operation row(s) {unset or '(none)'} listing SLO '{claim_id}' declare no {SLO_MAX_AGE_FIELD} in "
            f"{OPERATION_COST_REGISTRY_FILE}; the measurement freshness bound is unset, so staleness cannot be decided",
            {**params, "unset_operations": unset},
        ))
        return None
    return timedelta(days=min(row[SLO_MAX_AGE_FIELD] for _, row in rows))


def _verify_slo_claim_evidence(
    bundle_data: dict[str, Any],
    root: Path,
    path_str: str,
    expected_claim_id: str | None,
    now: datetime,
    findings: list[ClaimFinding],
) -> None:
    """Opens and binds the evidence an 'slo' claim demands (fss-x4a.30.87.5):

    - the SLO registry (via slo_validate.parse_slos) and operation-cost registry, fail-closed;
    - one retained, digest-bound fss.environment_manifest.v1 the measurement is bound to;
    - one retained, digest-bound fss.slo_measurement.v1 with status 'passed', bound to the
      claim's SLO id, a registered operation associated with that SLO, the bundle generation,
      and the operation-cost registry generation;
    - a real validity window (ISO-8601, ordered, not future, not older than the operation-cost row's
      measurement_max_age_days; an unset bound fails closed)
      evaluated against the injected ``now``;
    - exactly one canonical numeric ``actual`` compared, unrounded, against the target and
      comparator of the authoritative SLO row; the measurement can neither restate nor override them.
    """
    if _scan_nan_inf_negative(bundle_data, path_str, "bundle", findings):
        return
    claim_id = _bound_claim_id(bundle_data, expected_claim_id)
    params: dict[str, Any] = {"claim_class": "slo", "claim_id": claim_id}

    artifacts_field, artifacts_list = _single_field(bundle_data, ARTIFACT_LIST_FIELDS)
    if not artifacts_field or not isinstance(artifacts_list, list) or len(artifacts_list) == 0:
        findings.append(_finding(
            ERR_CLAIM_LEVEL_EXCEEDED, path_str, "artifacts",
            "SLO claim proof bundle requires a retained measurement artifact on disk; artifacts list is missing or empty",
            params,
        ))
        return

    slo_rows, slo_registry_findings = load_slo_registry(root)
    cost_registry, cost_registry_findings = load_operation_cost_registry(root)
    findings.extend(slo_registry_findings)
    findings.extend(cost_registry_findings)

    bundle_generation = _nonempty_str(bundle_data.get("generation"))
    if bundle_generation is None:
        findings.append(_finding(ERR_SLO_GENERATION_UNBOUND, path_str, "generation",
                                 "SLO claim proof bundle declares no generation", params))

    env_doc, env_reason = _open_role_document(bundle_data, root, "environment_manifest", SLO_ENVIRONMENT_SCHEMA)
    env_digest: str | None = None
    if env_doc is None:
        findings.append(_finding(ERR_SLO_ENVIRONMENT_UNRETAINED, path_str, "artifacts",
                                 f"SLO claim {env_reason}", params))
    elif len(env_doc) < 2:
        findings.append(_finding(ERR_SLO_ENVIRONMENT_UNRETAINED, path_str, "artifacts",
                                 "SLO claim environment manifest declares nothing beyond its schema", params))
    else:
        env_digest = str(_role_artifacts(bundle_data, "environment_manifest")[0]["digest"]).strip().lower()

    meas, meas_reason = _open_role_document(bundle_data, root, "measurement_artifact", SLO_MEASUREMENT_SCHEMA)
    if meas is None:
        findings.append(_finding(ERR_CLAIM_LEVEL_EXCEEDED, path_str, "artifacts",
                                 f"SLO claim requires a retained measurement: {meas_reason}", params))
        return
    loc = f"artifact[{_artifact_locator(_role_artifacts(bundle_data, 'measurement_artifact')[0])}]"
    if _scan_nan_inf_negative({k: v for k, v in meas.items() if k != "actual"}, path_str, loc, findings):
        return  # the actual itself is judged below, as ERR-CLAIM-SLO-ACTUAL-INVALID-001

    if meas.get("status") != "passed":
        findings.append(_finding(ERR_SLO_MEASUREMENT_NOT_PASSED, path_str, f"{loc}.status",
                                 f"Measurement status {meas.get('status')!r} is not 'passed'", params))

    # Binding: SLO id and registered operation associated with it.
    meas_slo = _nonempty_str(meas.get("slo_id"))
    if meas_slo is None:
        findings.append(_finding(ERR_CLAIM_BINDING_MISMATCH, path_str, f"{loc}.slo_id",
                                 "Measurement is not bound to an SLO id ('slo_id')", params))
    elif meas_slo != claim_id:
        findings.append(_finding(ERR_CLAIM_BINDING_MISMATCH, path_str, f"{loc}.slo_id",
                                 f"Measurement binds SLO '{meas_slo}', expected '{claim_id}'",
                                 {**params, "bound_slo": meas_slo}))
    meas_op = _nonempty_str(meas.get("operation_id"))
    op_row: dict[str, Any] | None = None
    if meas_op is None:
        findings.append(_finding(ERR_CLAIM_BINDING_MISMATCH, path_str, f"{loc}.operation_id",
                                 "Measurement names no 'operation_id' from the operation-cost registry", params))
    elif cost_registry is not None:
        op_row = cost_registry.operations.get(meas_op)
        if op_row is None:
            findings.append(_finding(ERR_CLAIM_BINDING_MISMATCH, path_str, f"{loc}.operation_id",
                                     f"Measurement names operation '{meas_op}', which is not in the operation-cost registry",
                                     {**params, "operation_id": meas_op}))
        elif claim_id not in op_row["slo_ids"]:
            findings.append(_finding(ERR_CLAIM_BINDING_MISMATCH, path_str, f"{loc}.operation_id",
                                     f"Operation '{meas_op}' is not associated with SLO '{claim_id}' (slo_ids {op_row['slo_ids']})",
                                     {**params, "operation_id": meas_op}))

    # Generations: required, equal to the bundle's, and bound to the cost-registry generation.
    meas_generation = _nonempty_str(meas.get("generation"))
    if meas_generation is None:
        findings.append(_finding(ERR_SLO_GENERATION_UNBOUND, path_str, f"{loc}.generation",
                                 "Measurement declares no generation", params))
    elif bundle_generation is not None and meas_generation != bundle_generation:
        findings.append(_finding(ERR_STALE_GENERATION, path_str, f"{loc}.generation",
                                 f"Measurement generation '{meas_generation}' is not the bundle generation '{bundle_generation}'",
                                 params))
    cost_generation = _nonempty_str(meas.get("operation_cost_generation"))
    if cost_generation is None:
        findings.append(_finding(ERR_SLO_GENERATION_UNBOUND, path_str, f"{loc}.operation_cost_generation",
                                 "Measurement is not bound to an operation-cost registry generation", params))
    elif cost_registry is not None and cost_generation != cost_registry.generation:
        findings.append(_finding(ERR_STALE_GENERATION, path_str, f"{loc}.operation_cost_generation",
                                 f"Measurement was taken against operation-cost generation '{cost_generation}', "
                                 f"not the registry's current '{cost_registry.generation}'", params))

    # Environment binding.
    bound_env = meas.get("environment_manifest_digest")
    if not isinstance(bound_env, str) or not bound_env.strip():
        findings.append(_finding(ERR_SLO_ENVIRONMENT_UNRETAINED, path_str, f"{loc}.environment_manifest_digest",
                                 "Measurement is not bound to a retained environment manifest digest", params))
    elif env_digest is not None and bound_env.strip().lower() != env_digest:
        findings.append(_finding(ERR_SLO_ENVIRONMENT_UNRETAINED, path_str, f"{loc}.environment_manifest_digest",
                                 f"Measurement binds environment manifest '{bound_env}', not the retained '{env_digest}'",
                                 params))

    max_age: timedelta | None = None
    if cost_registry is not None:
        max_age = _slo_freshness_bound(cost_registry, claim_id, path_str, loc, params, findings)
    _check_slo_window(meas, now, max_age, path_str, loc, params, findings)

    # Target and comparator come only from the authoritative SLO row.
    threshold = None
    if not slo_registry_findings:
        threshold = _resolve_slo_threshold(claim_id, slo_rows, meas, path_str, loc, params, findings)
    target_aliases = sorted(k for k in meas if k != "target" and k.lower().startswith("target"))
    if target_aliases:
        findings.append(_finding(ERR_SLO_TARGET_UNBOUND, path_str, f"{loc}.target",
                                 f"Measurement declares non-canonical target field(s) {target_aliases}; the target is the SLO row's",
                                 params))
    if "target" in meas and threshold is not None:
        restated = meas["target"]
        if _finite_number(restated) != threshold.value:
            findings.append(_finding(
                ERR_SLO_TARGET_UNBOUND, path_str, f"{loc}.target",
                f"Measurement target {restated!r} differs from the authoritative SLO target {threshold.value} {threshold.unit}",
                params,
            ))
    for name in SLO_COMPARATOR_FIELDS:
        if name in meas:
            declared = meas[name]
            normalized = _COMPARATOR_ALIASES.get(declared.strip().lower()) if isinstance(declared, str) else None
            if threshold is None or normalized != threshold.comparator:
                findings.append(_finding(
                    ERR_SLO_COMPARATOR_OVERRIDE, path_str, f"{loc}.{name}",
                    f"Measurement declares comparator {declared!r}; only the SLO row's comparator "
                    f"{threshold.comparator if threshold else '(none)'!r} applies",
                    params,
                ))

    # Exactly one canonical, finite, non-negative numeric actual; never a rounded value.
    actual: float | None = None
    shadows = sorted(k for k in meas if k != "actual" and _ACTUAL_ALIAS_RE.match(k))
    if shadows:
        findings.append(_finding(
            ERR_SLO_ACTUAL_INVALID, path_str, f"{loc}.actual",
            f"Measurement declares actual-like field(s) {shadows} "
            f"{'beside' if 'actual' in meas else 'instead of'} the single canonical 'actual'",
            params,
        ))
    elif "actual" not in meas:
        rounded_only = sorted(k for k in meas if k in SLO_ROUNDED_FIELDS)
        findings.append(_finding(
            ERR_SLO_ACTUAL_INVALID, path_str, f"{loc}.actual",
            "Measurement declares no 'actual'" + (f"; rounded value(s) {rounded_only} are never compared" if rounded_only else ""),
            params,
        ))
    else:
        raw_actual = meas["actual"]
        actual = _finite_number(raw_actual)
        if actual is None or actual < 0.0:
            findings.append(_finding(ERR_SLO_ACTUAL_INVALID, path_str, f"{loc}.actual",
                                     f"Measurement actual {raw_actual!r} is not a finite non-negative number", params))
            actual = None

    if threshold is not None and actual is not None:
        met = {
            "<=": actual <= threshold.value,
            "<": actual < threshold.value,
            ">=": actual >= threshold.value,
            ">": actual > threshold.value,
        }[threshold.comparator]
        if not met:
            rounded = [meas[k] for k in SLO_ROUNDED_FIELDS if k in meas]
            findings.append(_finding(
                ERR_CLAIM_LEVEL_EXCEEDED, path_str, f"{loc}.actual",
                f"SLO target not achieved: actual {actual} {threshold.unit} does not satisfy "
                f"'{threshold.comparator} {threshold.value} {threshold.unit}' of SLO '{claim_id}'"
                + (f" (rounded values {rounded} are never compared)" if rounded else ""),
                {**params, "actual": actual, "target": threshold.value, "comparator": threshold.comparator},
            ))


def _is_promoted_bundle(bundle_data: dict[str, Any], claim_level: str | None) -> bool:
    """True when the citing claim or the bundle itself asserts a promoted readiness level."""
    claim_rank = _rank_of(claim_level.strip().lower()) if isinstance(claim_level, str) else None
    bundle_level_tuple = _single_field(bundle_data, SUPPORTED_LEVEL_FIELDS)
    bundle_level_str = bundle_level_tuple[1] if bundle_level_tuple[0] else None
    bundle_rank = _rank_of(bundle_level_str.strip().lower()) if isinstance(bundle_level_str, str) else None
    return (
        (claim_rank is not None and claim_rank >= PROMOTION_RANK)
        or (bundle_rank is not None and bundle_rank >= PROMOTION_RANK)
        or (isinstance(bundle_level_str, str) and bundle_level_str.strip().lower() in ("achieved", "promoted"))
        or (isinstance(claim_level, str) and claim_level.strip().lower() in ("achieved", "promoted"))
    )


def _nonempty_str(value: Any) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _bound_claim_id(bundle_data: dict[str, Any], expected_claim_id: str | None) -> str:
    if isinstance(expected_claim_id, str) and expected_claim_id.strip():
        return expected_claim_id.strip()
    _, bundle_claim_id = _single_field(bundle_data, CLAIM_ID_FIELDS)
    return _nonempty_str(bundle_claim_id) or ""


def _role_artifacts(bundle_data: dict[str, Any], role: str) -> list[dict[str, Any]]:
    """Declared artifact entries (``artifacts``/``objects``) carrying exactly this role."""
    found: list[dict[str, Any]] = []
    for list_field in ARTIFACT_LIST_FIELDS:
        entries = bundle_data.get(list_field)
        if isinstance(entries, list):
            found.extend(e for e in entries if isinstance(e, dict) and e.get("role") == role)
    return found


def _artifact_locator(entry: dict[str, Any]) -> Any:
    for name in ARTIFACT_LOCATOR_FIELDS:
        if entry.get(name) is not None:
            return entry[name]
    return None


def _open_retained_file(root: Path, rel_val: Any, declared_digest: Any) -> tuple[bytes | None, str]:
    """Opens a contained, repository-relative retained file and verifies its sha256 binding.

    Returns (bytes, "") or (None, reason). Never trusts a declaration it cannot open."""
    if not isinstance(rel_val, str) or not rel_val.strip():
        return None, "declares no local path"
    if "://" in rel_val or rel_val.lower().startswith("file:"):
        return None, f"'{rel_val}' is a non-local URI whose bytes cannot be verified"
    rel = Path(rel_val)
    if rel.is_absolute() or ".." in rel.parts:
        return None, f"'{rel_val}' is not a contained repository-relative path"
    full = root / rel
    if not _is_contained(full, root):
        return None, f"'{rel_val}' resolves outside the repository root"
    if not full.is_file():
        return None, f"'{rel_val}' does not exist on disk as a regular file"
    try:
        raw = full.read_bytes()
    except OSError as exc:
        return None, f"'{rel_val}' could not be read: {exc}"
    digest = declared_digest.strip().lower() if isinstance(declared_digest, str) else None
    if digest is None or SHA256_DIGEST_RE.match(digest) is None:
        return None, f"'{rel_val}' is not bound by a 'sha256:<64 hex>' digest"
    if compute_sha256(raw) != digest:
        return None, f"'{rel_val}' bytes do not match its declared digest"
    return raw, ""


def _json_object(raw: bytes) -> dict[str, Any] | None:
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):  # RecursionError: nesting too deep
        return None
    return doc if isinstance(doc, dict) else None


def _open_role_document(
    bundle_data: dict[str, Any],
    root: Path,
    role: str,
    schema: str,
) -> tuple[dict[str, Any] | None, str]:
    """Opens the single retained artifact with this role as a JSON document of this schema."""
    entries = _role_artifacts(bundle_data, role)
    if len(entries) != 1:
        return None, f"requires exactly one retained '{role}' artifact, found {len(entries)}"
    raw, reason = _open_retained_file(root, _artifact_locator(entries[0]), entries[0].get("digest"))
    if raw is None:
        return None, f"'{role}' artifact {reason}"
    doc = _json_object(raw)
    if doc is None:
        return None, f"'{role}' artifact is not a JSON object"
    if doc.get("schema") != schema:
        return None, f"'{role}' artifact schema {doc.get('schema')!r} is not '{schema}'"
    return doc, ""


def _check_assumptions(
    bundle_data: dict[str, Any],
    path_str: str,
    params: dict[str, Any],
    findings: list[ClaimFinding],
) -> list[str] | None:
    """Declared assumptions must be a non-empty list of {id, statement} entries whose ids are
    exact tokens (nothing stripped) and unique ignoring case."""
    raw = bundle_data.get("assumptions")
    label = f"'{params['claim_class']}' claim '{params['claim_id']}'"
    if not isinstance(raw, list) or len(raw) == 0:
        findings.append(_finding(
            ERR_CLAIM_ASSUMPTIONS_MISSING, path_str, "assumptions",
            f"{label} declares no assumptions; its registry row requires named assumptions (got {raw!r})",
            params,
        ))
        return None
    ids: list[str] = []
    folded: set[str] = set()
    ok = True
    for idx, item in enumerate(raw):
        a_id = _exact_token(item.get("id")) if isinstance(item, dict) else None
        statement = _exact_text(item.get("statement")) if isinstance(item, dict) else None
        if a_id is None or statement is None:
            ok = False
            findings.append(_finding(
                ERR_CLAIM_ASSUMPTIONS_MISSING, path_str, f"assumptions[{idx}]",
                f"{label} assumption {idx} must be an object with an exact 'id' and 'statement' (got {item!r})",
                params,
            ))
        elif a_id.casefold() in folded:
            ok = False
            findings.append(_finding(
                ERR_CLAIM_ASSUMPTIONS_MISSING, path_str, f"assumptions[{idx}]",
                f"{label} declares assumption id '{a_id}' more than once (ids are compared ignoring case)",
                params,
            ))
        else:
            ids.append(a_id)
            folded.add(a_id.casefold())
    return ids if ok else None


# Claim class 'proof' (fss-x4a.30.87.2): "theorem under declared formal model".
# Row minimum_evidence: formal artifact, assumptions, toolchain identity, check receipt.
FORMAL_MODEL_SCHEMA = "fss.formal_model.v1"
PROOF_CHECK_RECEIPT_SCHEMA = "fss.proof_check_receipt.v1"
# Closed vocabulary of theorem provers (the proofs/lean4 and proofs/tla targets) and the
# formal-language source suffixes each one checks. TLC and Apalache are model checkers: they
# check invariants of bounded models and do not check THEOREMs, so they cannot back a 'proof'.
FORMAL_PROOF_CHECKERS: dict[str, tuple[str, ...]] = {
    "lean4": (".lean",),
    "tlaps": (".tla",),
}
PASSING_PROOF_CHECK_STATUSES: frozenset[str] = frozenset({"passed"})
TEST_EVIDENCE_TOKENS: frozenset[str] = frozenset({
    "test", "tests", "pytest", "unittest", "nextest", "proptest", "quickcheck", "fuzz", "fuzzing",
})
TEST_SOURCE_SUFFIXES: tuple[str, ...] = (".py", ".rs", ".sh", ".js", ".ts", ".log")
_EVIDENCE_TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+")


def _is_test_evidence(value: str) -> bool:
    return any(tok in TEST_EVIDENCE_TOKENS for tok in _EVIDENCE_TOKEN_SPLIT_RE.split(value.strip().lower()))


_EXACT_TOKEN_RE = re.compile(r"[\x21-\x7e]+")
# A concrete checker release: major.minor[.patch[.build]] with an optional numbered pre-release,
# or a dated nightly. Ranges, wildcards, channels, and aliases ('*', '>=2.0', '2.x', 'stable',
# 'nightly', 'dev', 'HEAD', 'unknown', 'latest') never identify what actually checked a proof.
_CONCRETE_VERSION_RE = re.compile(r"v?\d+(?:\.\d+){1,3}(?:-(?:rc|alpha|beta)\.?\d+)?|nightly-\d{4}-\d{2}-\d{2}")
_THEOREM_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_'.]*")
FORMAL_SUFFIX_LANGUAGES: dict[str, str] = {".lean": "lean", ".tla": "tla"}
_TLA_HEADER_RE = re.compile(r"\A\s*-{4,}[ \t]*MODULE[ \t]+[A-Za-z0-9_]+[ \t]*-{4,}[ \t]*$", re.M)
_TLA_HEADER_LINE_RE = re.compile(r"[ \t]*-{4,}[ \t]*MODULE[ \t]+[A-Za-z0-9_]+[ \t]*-{4,}[ \t]*")
_TLA_TERMINATOR_LINE_RE = re.compile(r"[ \t]*={4,}[ \t]*")
_TLA_PLACEHOLDER_RE = re.compile(r"\bOMITTED\b", re.IGNORECASE)
_TLA_ASSUMPTION_UNIT_RE = re.compile(r"[ \t]*(ASSUME|ASSUMPTION|AXIOM)\b")
# Lean 4: identifier components (plain or «quoted») of lexed code are compared exactly; a
# component with non-ASCII letters is also compared through a confusable skeleton.
LEAN_PLACEHOLDER_NAMES: frozenset[str] = frozenset({"sorry", "sorryAx", "admit", "stop"})
LEAN_ESCAPE_NAMES: frozenset[str] = frozenset({
    "axiom", "native_decide", "elab", "elab_rules", "macro", "macro_rules", "syntax",
    "declare_syntax_cat", "run_cmd", "run_tac", "run_elab", "initialize", "builtin_initialize",
    # Round 3: compiler trust, kernel bypass, and elaboration-time proof construction.
    "lcProof", "implemented_by", "ofReduceBool", "trustCompiler", "bv_decide", "skipKernelTC",
    "native", "by_elab", "extern",
})
# Imports are refused unless their root is Lean core. Mathlib is not admitted: the checker cannot
# pin its version or integrity, and admitting it is a user decision.
LEAN_IMPORT_ROOTS: frozenset[str] = frozenset({"Init", "Std", "Lean"})
LEAN_BODY_DECLARATIONS: frozenset[str] = frozenset({"def", "theorem", "lemma", "abbrev", "instance", "example"})
LEAN_DECLARATION_MODIFIERS: frozenset[str] = frozenset({"private", "protected", "noncomputable", "partial", "unsafe", "nonrec"})
_LEAN_ATTRIBUTES_RE = re.compile(r"(?:@\[[^\]\n]*\][ \t]*)+")
_LEAN_HASH_COMMAND_RE = re.compile(r"(?<![\w'!?.])#[A-Za-z_]\w*")
_LEAN_DEBUG_OPTION_RE = re.compile(r"\bset_option[ \t]+(debug\.[\w.]*)")
_LEAN_IMPORT_RE = re.compile(r"(?m)^[ \t]*import[ \t]+([^\n]*)")
_LEAN_MAX_INTERPOLATION_DEPTH = 64
# TLA+ standard and TLAPS library modules; EXTENDS/INSTANCE of anything else (other than the
# declared model module or a module nested in the file) is refused.
TLA_STANDARD_MODULES: frozenset[str] = frozenset({
    "Naturals", "Integers", "Reals", "Sequences", "FiniteSets", "Bags", "TLC", "RealTime", "TLAPS",
    "NaturalsInduction", "WellFoundedInduction", "SequenceTheorems", "FiniteSetTheorems",
})
TLA_THEOREM_KEYWORDS: frozenset[str] = frozenset({"THEOREM", "LEMMA", "PROPOSITION", "COROLLARY"})
_TLA_HEADER_NAME_RE = re.compile(r"[ \t]*-{4,}[ \t]*MODULE[ \t]+([A-Za-z0-9_]+)[ \t]*-{4,}[ \t]*")
_TLA_TOKEN_RE = re.compile(r"==|<\d+>[A-Za-z0-9_]*\.?|[A-Za-z_][A-Za-z0-9_]*|\S")
_TLA_STEP_RE = re.compile(r"<\d+>[A-Za-z0-9_]*\.?")
# First token of every column-0 line of recognisable Lean 4 source (commands, modifiers,
# attributes, equation alternatives).
LEAN_COMMAND_STARTS: frozenset[str] = frozenset({
    "import", "open", "namespace", "section", "end", "variable", "universe", "theorem", "lemma",
    "def", "example", "abbrev", "instance", "structure", "class", "inductive", "set_option",
    "noncomputable", "private", "protected", "partial", "unsafe", "attribute", "local", "scoped",
    "mutual", "notation", "infix", "infixl", "infixr", "prefix", "postfix", "deriving",
    "termination_by", "decreasing_by", "where", "export", "opaque", "axiom", "macro",
    "macro_rules", "elab", "elab_rules", "syntax", "declare_syntax_cat", "run_cmd", "run_tac",
    "run_elab", "initialize", "builtin_initialize", "omit", "include", "|", "#check", "#print",
    "#reduce", "#eval", "#guard_msgs", "#help",
})
_LEAN_IDENT_RE = re.compile(r"«[^»\n]*»|[^\W\d][\w'!?]*")
_LEAN_IDENT_CHAR_RE = re.compile(r"[\w'!?.]")
_LEAN_RAW_STRING_RE = re.compile(r'r(#*)"')
_LEAN_CHAR_LITERAL_RE = re.compile(r"'(?:\\(?:x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|.)|[^\\'\n])'")
# Letters that render like ASCII in common fonts (Cyrillic, Greek, IPA, small caps); NFKC folds
# fullwidth forms first and combining marks are dropped.
_CONFUSABLES = str.maketrans({
    "а": "a", "с": "c", "ԁ": "d", "е": "e", "һ": "h", "і": "i", "ј": "j", "ӏ": "l", "м": "m", "о": "o",
    "р": "p", "ԛ": "q", "г": "r", "ѕ": "s", "т": "t", "у": "y", "х": "x", "ԝ": "w", "к": "k", "п": "n",
    "А": "A", "В": "B", "С": "C", "Е": "E", "Н": "H", "І": "I", "К": "K", "М": "M", "О": "O", "Р": "P",
    "Ѕ": "S", "Т": "T", "Х": "X", "Ү": "Y",
    "α": "a", "ο": "o", "ρ": "p", "τ": "t", "ι": "i", "υ": "u", "ν": "v", "κ": "k", "χ": "x", "ϲ": "c",
    "Α": "A", "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X", "Ι": "I", "Υ": "Y", "Κ": "K", "Μ": "M",
    "ı": "i", "ɑ": "a", "ɡ": "g", "ʀ": "r", "ꜱ": "s", "ᴀ": "a", "ᴅ": "d", "ᴍ": "m", "ᴏ": "o",
    "ᴘ": "p", "ᴛ": "t", "ʏ": "y", "ᴜ": "u",
})
# Tokens that mark test code in any directory segment or file stem (split at non-alphanumerics
# and camelCase boundaries); whole directory segments that name test suites.
_TEST_PATH_TOKENS: frozenset[str] = frozenset({"test", "tests", "testing", "pytest", "unittest", "fuzz", "fuzzing"})
_TEST_SUITE_DIRS: frozenset[str] = frozenset({"spec", "specs"})
_NAME_TOKEN_RE = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")



def _exact_token(value: Any) -> str | None:
    """An identity token compared byte for byte: printable ASCII with no whitespace of any kind.
    A non-breaking, zero-width, or other invisible character is never stripped into a match."""
    return value if isinstance(value, str) and _EXACT_TOKEN_RE.fullmatch(value) else None


def _exact_text(value: Any) -> str | None:
    """Human text compared exactly: non-empty, no leading or trailing space, and no whitespace,
    control, or format character other than U+0020. Nothing is stripped."""
    if not isinstance(value, str) or not value.strip(" ") or value != value.strip(" "):
        return None
    for ch in value:
        if ch != " " and (ch.isspace() or unicodedata.category(ch) in ("Cc", "Cf", "Zs", "Zl", "Zp")):
            return None
    return value


# A generation is a plain token: letters, digits, and : . _ + / - (no markdown, no whitespace).
_GENERATION_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9:._+/\-]*")


def _bind_claim_row_generation(
    bundle_generation: str | None,
    claim_generation: Any,
    path_str: str,
    params: dict[str, Any],
    findings: list[ClaimFinding],
) -> None:
    """The bundle generation must be the citing claim row's current generation, never merely
    consistent with the bundle's own artifacts."""
    label = f"'{params['claim_class']}' claim '{params['claim_id']}'"
    row_generation = claim_generation if isinstance(claim_generation, str) and _GENERATION_TOKEN_RE.fullmatch(claim_generation) else None
    if row_generation is None:
        findings.append(_finding(
            ERR_CLAIM_GENERATION_UNBOUND, path_str, "claim_generation",
            f"{label} is cited by no claim row declaring its current generation (got {claim_generation!r}); "
            "the bundle generation cannot be bound to the claim",
            params,
        ))
    elif bundle_generation is not None and bundle_generation != row_generation:
        findings.append(_finding(
            ERR_STALE_GENERATION, path_str, "generation",
            f"{label} bundle generation '{bundle_generation}' is not the claim row's current generation '{row_generation}'",
            {**params, "bundle_generation": bundle_generation, "claim_generation": row_generation},
        ))


def _classify_checker(value: Any, where: str, path_str: str, params: dict[str, Any], findings: list[ClaimFinding]) -> str | None:
    """Returns the normalized checker when it is a registered formal checker, else records why not."""
    checker = _exact_token(value)
    if checker is None:
        findings.append(_finding(ERR_PROOF_TOOLCHAIN_UNBOUND, path_str, where, f"'proof' claim '{params['claim_id']}' {where} names no exact formal checker (got {value!r})", params))
        return None
    norm = checker.lower()
    if _is_test_evidence(norm):
        findings.append(_finding(
            ERR_PROOF_TESTS_ONLY, path_str, where,
            f"'proof' claim '{params['claim_id']}' {where} is the test runner '{checker}', not a formal checker; tests cannot prove a theorem",
            params,
        ))
        return None
    if norm not in FORMAL_PROOF_CHECKERS:
        findings.append(_finding(
            ERR_PROOF_TOOLCHAIN_UNBOUND, path_str, where,
            f"'proof' claim '{params['claim_id']}' {where} '{checker}' is not a registered formal checker {sorted(FORMAL_PROOF_CHECKERS)}",
            params,
        ))
        return None
    return norm


def _classify_version(value: Any, where: str, path_str: str, params: dict[str, Any], findings: list[ClaimFinding]) -> str | None:
    version = _exact_token(value)
    if version is None or _CONCRETE_VERSION_RE.fullmatch(version) is None:
        findings.append(_finding(
            ERR_PROOF_TOOLCHAIN_UNBOUND, path_str, where,
            f"'proof' claim '{params['claim_id']}' {where} must pin a concrete checker release such as '2.19' or "
            f"'v4.9.0' (got {value!r}); ranges, wildcards, channels, and aliases are refused",
            params,
        ))
        return None
    return version


def _name_tokens(segment: str) -> list[str]:
    tokens: list[str] = []
    for part in re.split(r"[^A-Za-z0-9]+", segment):
        tokens.extend(token.lower() for token in _NAME_TOKEN_RE.findall(part))
    return tokens


def _test_path_marker(locator: str) -> str | None:
    """Why a formal-artifact path is test code in disguise, checked before any suffix gate: a
    directory segment or file stem with a test token (test_*, *_test(s), __tests__, unit-tests,
    fuzz, TestSpec, ...), a test-suite directory (spec/), or a source suffix hidden before the
    formal one (.py.tla)."""
    parts = Path(locator).parts
    for segment in parts[:-1]:
        if segment.lower() in _TEST_SUITE_DIRS:
            return f"lives under the test-suite directory '{segment}'"
        if any(token in _TEST_PATH_TOKENS for token in _name_tokens(segment)):
            return f"lives under the test directory '{segment}'"
    name = parts[-1] if parts else locator
    if any(token in _TEST_PATH_TOKENS for token in _name_tokens(name.split(".", 1)[0])):
        return "is a test-named file"
    inner = [s.lower() for s in Path(name).suffixes[:-1]]
    if any(s in TEST_SOURCE_SUFFIXES for s in inner):
        return f"hides a {inner} source behind a formal suffix"
    return None


class _LexError(ValueError):
    """Formal source the checker cannot lex; it is never assumed well-formed."""


def _blank(fragment: str) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in fragment)


def _nested_comment_end(text: str, start: int, opener: str, closer: str) -> int:
    depth, j, n = 0, start, len(text)
    while j < n:
        if text.startswith(opener, j):
            depth, j = depth + 1, j + len(opener)
        elif text.startswith(closer, j):
            depth, j = depth - 1, j + len(closer)
            if depth == 0:
                return j
        else:
            j += 1
    raise _LexError(f"unterminated '{opener}' comment")


def _normalize_source(text: str) -> str:
    """Valid source files may carry a leading BOM and CRLF line ends; neither is a defect."""
    if text.startswith("\ufeff"):
        text = text[1:]
    return text.replace("\r\n", "\n")


def _lex_lean(text: str) -> str:
    """Lean 4 code with comments (nested /- -/ and --), string, raw-string, and char literal
    contents blanked (line structure kept), interpolation braces of s!/m!/f!-style strings kept
    as code, and everything after a #exit command dropped (#exit itself stays, and is refused)."""
    code, _ = _lex_lean_from(text, 0, stop_at_brace=False, depth=0)
    return code


def _lex_lean_from(text: str, i: int, stop_at_brace: bool, depth: int) -> tuple[str, int]:
    out: list[str] = []
    n = len(text)
    in_ident = False  # inside an identifier: a quote here is a prime (h'), not a char literal
    braces = 0
    while i < n:
        ch = text[i]
        if text.startswith("/-", i):
            j = _nested_comment_end(text, i, "/-", "-/")
            out.append(_blank(text[i:j]))
            i, in_ident = j, False
        elif text.startswith("--", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i, in_ident = j, False
        elif ch == "r" and not in_ident and _LEAN_RAW_STRING_RE.match(text, i):
            opener = _LEAN_RAW_STRING_RE.match(text, i)
            closer = '"' + opener.group(1)
            j = text.find(closer, opener.end())
            if j < 0:
                raise _LexError("unterminated raw string literal")
            out.append(_blank(text[i:j + len(closer)]))
            i, in_ident = j + len(closer), False
        elif ch == '"':
            if in_ident and i > 0 and text[i - 1] == "!":
                piece, i = _lex_lean_interpolated(text, i, depth)
                out.append(piece)
            else:
                j = i + 1
                while j < n and text[j] != '"':
                    j += 2 if text[j] == "\\" else 1
                if j >= n:
                    raise _LexError("unterminated string literal")
                out.append(_blank(text[i:j + 1]))
                i = j + 1
            in_ident = False
        elif ch == "'" and not in_ident and _LEAN_CHAR_LITERAL_RE.match(text, i):
            literal = _LEAN_CHAR_LITERAL_RE.match(text, i)
            out.append(_blank(literal.group(0)))
            i, in_ident = literal.end(), False
        elif ch == "#" and not in_ident and text.startswith("#exit", i) and not _LEAN_IDENT_CHAR_RE.match(text[i + 5:i + 6] or " "):
            out.append("#exit")
            break  # Lean ignores everything after #exit; the command itself is refused
        elif stop_at_brace and ch == "}" and braces == 0:
            return "".join(out), i
        else:
            if stop_at_brace and ch == "{":
                braces += 1
            elif stop_at_brace and ch == "}":
                braces -= 1
            out.append(ch)
            in_ident = (ch.isalnum() or ch in "_'!?") if in_ident else (ch.isalpha() or ch == "_")
            i += 1
    if stop_at_brace:
        raise _LexError("unterminated '{' in an interpolated string")
    return "".join(out), i


def _lex_lean_interpolated(text: str, i: int, depth: int) -> tuple[str, int]:
    """An s!"..{e}.." string: literal text blanked, each {e} lexed as code."""
    if depth >= _LEAN_MAX_INTERPOLATION_DEPTH:
        raise _LexError("interpolated strings nest too deeply")
    out = [" "]
    j, n = i + 1, len(text)
    while j < n:
        c = text[j]
        if c == "\\":
            out.append(_blank(text[j:j + 2]))
            j += 2
        elif c == '"':
            out.append(" ")
            return "".join(out), j + 1
        elif c == "{":
            code, end = _lex_lean_from(text, j + 1, stop_at_brace=True, depth=depth + 1)
            out.append(" " + code + " ")
            j = end + 1
        else:
            out.append("\n" if c == "\n" else " ")
            j += 1
    raise _LexError("unterminated interpolated string literal")


def _blank_tla(text: str) -> str:
    """TLA+ text with nested (* *) comments, \\* line comments, and string contents blanked."""
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        if text.startswith("(*", i):
            j = _nested_comment_end(text, i, "(*", "*)")
            out.append(_blank(text[i:j]))
            i = j
        elif text.startswith("\\*", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif text[i] == '"':
            j = i + 1
            while j < n and text[j] not in '"\n':
                j += 2 if text[j] == "\\" else 1
            if j >= n or text[j] != '"':
                raise _LexError("unterminated string literal")
            out.append(_blank(text[i:j + 1]))
            i = j + 1
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def _lex_tla(text: str) -> tuple[str, str, frozenset[str]]:
    """The first TLA+ module, lexed: (its top-level units, the bodies of modules nested in it,
    the nested module names). The header must open the file; text after the module's '===='
    is dropped."""
    lines = _blank_tla(text).split("\n")
    start = next((k for k, line in enumerate(lines) if line.strip()), None)
    if start is None or not _TLA_HEADER_NAME_RE.fullmatch(lines[start]):
        raise _LexError("does not open with a '---- MODULE Name ----' header")
    depth, top, nested, names = 1, [], [], set()
    for line in lines[start + 1:]:
        header = _TLA_HEADER_NAME_RE.fullmatch(line)
        if header:
            depth += 1
            names.add(header.group(1))
            top.append("")
            nested.append("")
        elif _TLA_TERMINATOR_LINE_RE.fullmatch(line):
            depth -= 1
            if depth == 0:
                return "\n".join(top), "\n".join(nested), frozenset(names)
            top.append("")
            nested.append("")
        else:
            top.append(line if depth == 1 else "")
            nested.append(line if depth > 1 else "")
    raise _LexError("the module is not closed by a '====' line")


def _tla_module_name(raw: bytes) -> str | None:
    """The module name in a TLA+ source's opening header, if it has one."""
    try:
        text = _normalize_source(raw.decode("utf-8"))
    except UnicodeDecodeError:
        return None
    first = next((line for line in text.split("\n") if line.strip()), "")
    header = _TLA_HEADER_NAME_RE.fullmatch(first)
    return header.group(1) if header else None


def _skeleton(name: str) -> str:
    folded = unicodedata.normalize("NFKC", name)
    folded = "".join(c for c in unicodedata.normalize("NFD", folded) if unicodedata.category(c) != "Mn")
    return folded.translate(_CONFUSABLES).casefold()


def _lean_names(code: str) -> list[str]:
    return [m.group(0).strip("«»") for m in _LEAN_IDENT_RE.finditer(code)]


def _lean_forbidden(code: str, names: frozenset[str]) -> list[str]:
    folded = {n.casefold() for n in names}
    hits = set()
    for name in _lean_names(code):
        if name in names or (not name.isascii() and _skeleton(name) in folded):
            hits.add(name)
    return sorted(hits)


def _lean_command_escapes(code: str) -> set[str]:
    """#-commands (#eval, #exit, #print, ...), debug options, and imports outside Lean core."""
    hits = {m.group(0) for m in _LEAN_HASH_COMMAND_RE.finditer(code)}
    hits |= {f"set_option {m.group(1)}" for m in _LEAN_DEBUG_OPTION_RE.finditer(code)}
    for match in _LEAN_IMPORT_RE.finditer(code):
        for name in match.group(1).split():
            if name.strip("«»").split(".")[0] not in LEAN_IMPORT_ROOTS:
                hits.add(f"import {name}")
    return hits


def _lean_shape_problem(code: str) -> str | None:
    """Recognisable Lean 4, independent of indentation: every line at the file's base indentation
    begins a Lean command, imports precede everything else, and every def/theorem/lemma/abbrev/
    instance/example has a body (':=', 'where', or equation alternatives)."""
    lines = code.split("\n")
    indents = [len(line) - len(line.lstrip(" \t")) for line in lines if line.strip()]
    if not indents:
        return None  # nothing but comments or strings: the theorem check reports what is missing
    base = min(indents)
    starts: list[int] = []
    seen_other = False
    for number, line in enumerate(lines):
        if not line.strip() or len(line) - len(line.lstrip(" \t")) > base:
            continue
        head = line.split()[0]
        if not (head.startswith("@[") or head.startswith("#") or head in LEAN_COMMAND_STARTS):
            return f"line {number + 1} does not begin a Lean 4 command ({head[:24]!r})"  # #-commands are refused as escapes
        if head == "import":
            if seen_other:
                return f"line {number + 1} imports after other commands"
        else:
            seen_other = True
        starts.append(number)
    for k, number in enumerate(starts):
        end = starts[k + 1] if k + 1 < len(starts) else len(lines)
        stripped = lines[number].strip()
        attributes = _LEAN_ATTRIBUTES_RE.match(stripped)
        words = [w for w in stripped[attributes.end() if attributes else 0:].split() if w not in LEAN_DECLARATION_MODIFIERS]
        if words and words[0] in LEAN_BODY_DECLARATIONS:
            body = "\n".join(lines[number:end])
            if ":=" not in body and re.search(r"\bwhere\b", body) is None and re.search(r"(?m)^[ \t]*\|", body) is None:
                return f"line {number + 1}: '{words[0]}' declaration has no ':=', 'where', or equation alternatives"
    return None


def _theorem_declaration(language: str, code: str, name: str) -> re.Match[str] | None:
    escaped = re.escape(name)
    if language == "tla":
        pattern = rf"(?m)^[ \t]*(?:THEOREM|LEMMA|PROPOSITION|COROLLARY)[ \t]+{escaped}[ \t]*=="
    else:
        pattern = rf"(?m)^[ \t]*(?:@\[[^\]\n]*\][ \t]*)?(?:(?:private|protected|noncomputable)[ \t]+)*(?:theorem|lemma)[ \t]+{escaped}(?=[\s:({{\[]|$)"
    return re.search(pattern, code)


def _declares_theorem(language: str, code: str, name: str) -> bool:
    return _theorem_declaration(language, code, name) is not None


def _lean_theorem_shaped(code: str, name: str) -> bool:
    """A Lean theorem declares a type (':') and a proof (':=', equation alternatives, or where)."""
    match = _theorem_declaration("lean", code, name)
    if match is None:
        return False
    rest = code[match.end():]
    stop = re.search(r"\n(?=\S)", rest)
    declaration = rest[:stop.start()] if stop else rest
    head, assign, _ = declaration.partition(":=")
    if assign:
        return ":" in head
    return ":" in declaration and (re.search(r"(?m)^[ \t]*\|", declaration) is not None or re.search(r"\bwhere\b", declaration) is not None)


def _tla_assumption_escapes(code: str) -> list[str]:
    """ASSUMPTION and AXIOM units, and every ASSUME that is not a sequent directly after
    'THEOREM Name ==' (or LEMMA/PROPOSITION/COROLLARY), an unnamed theorem keyword, SUFFICES, or a
    proof-step label."""
    tokens = _TLA_TOKEN_RE.findall(code)
    hits: list[str] = []
    for k, token in enumerate(tokens):
        if token in ("ASSUMPTION", "AXIOM"):
            hits.append(token)
        elif token == "ASSUME":
            prev = tokens[k - 1] if k >= 1 else ""
            sequent = (
                prev in TLA_THEOREM_KEYWORDS or prev == "SUFFICES" or _TLA_STEP_RE.fullmatch(prev) is not None
                or (prev == "==" and k >= 3 and tokens[k - 3] in TLA_THEOREM_KEYWORDS)
            )
            if not sequent:
                hits.append("ASSUME")
    return hits


def _tla_module_escapes(code: str, nested_names: frozenset[str], allowed_modules: frozenset[str] | None) -> set[str]:
    """EXTENDS (including continuation lines) and INSTANCE of a module that is neither standard,
    nested in the file, nor the declared model module. When the model is unknown the bundle is
    already refused for it, so non-standard references are not judged."""
    if allowed_modules is None:
        return set()
    admitted = TLA_STANDARD_MODULES | nested_names | allowed_modules
    tokens = _TLA_TOKEN_RE.findall(code)
    hits: set[str] = set()
    for k, token in enumerate(tokens):
        if token == "EXTENDS":
            j = k + 1
            while j < len(tokens) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", tokens[j]):
                if tokens[j] not in admitted:
                    hits.add(f"EXTENDS {tokens[j]}")
                if j + 1 < len(tokens) and tokens[j + 1] == ",":
                    j += 2
                else:
                    break
        elif token == "INSTANCE" and k + 1 < len(tokens) and tokens[k + 1] not in admitted:
            hits.add(f"INSTANCE {tokens[k + 1]}")
    return hits


def _check_formal_content(
    raw: bytes,
    locator: str,
    language: str,
    theorem_name: str | None,
    path_str: str,
    params: dict[str, Any],
    findings: list[ClaimFinding],
    allowed_modules: frozenset[str] | None = None,
) -> None:
    """A static pre-filter, defense in depth only: it can never establish a proof (a proof is
    verified only by a prover-run receipt). It lexes the artifact in its suffix's language and
    requires, in what remains: recognisable source, the named theorem, no unproven placeholder,
    and no unsound escape it knows of."""
    label = f"'proof' claim '{params['claim_id']}'"
    loc = "artifacts[role=formal_artifact]"
    language_name = "TLA+" if language == "tla" else "Lean 4"
    try:
        text = _normalize_source(raw.decode("utf-8"))
    except UnicodeDecodeError:
        findings.append(_finding(ERR_PROOF_FORMAL_ARTIFACT_MISSING, path_str, loc, f"{label} formal artifact '{locator}' is not UTF-8 formal source text", params))
        return
    if language == "lean" and _TLA_HEADER_RE.search(text) is not None:
        findings.append(_finding(ERR_PROOF_FORMAL_ARTIFACT_MISSING, path_str, loc, f"{label} formal artifact '{locator}' is a TLA+ module, not Lean source", params))
        return
    try:
        if language == "tla":
            code, nested, nested_names = _lex_tla(text)
        else:
            code, nested, nested_names = _lex_lean(text), "", frozenset()
    except _LexError as exc:
        findings.append(_finding(ERR_PROOF_FORMAL_ARTIFACT_MISSING, path_str, loc, f"{label} formal artifact '{locator}' is not well-formed {language_name} source: {exc}", params))
        return
    if language == "lean":
        problem = _lean_shape_problem(code)
        if problem is not None:
            findings.append(_finding(ERR_PROOF_FORMAL_ARTIFACT_MISSING, path_str, loc, f"{label} formal artifact '{locator}' is not recognisably Lean 4 source: {problem}", params))
            return
        placeholders = _lean_forbidden(code, LEAN_PLACEHOLDER_NAMES)
        escapes = sorted(set(_lean_forbidden(code, LEAN_ESCAPE_NAMES)) | _lean_command_escapes(code))
    else:
        whole = code + "\n" + nested
        placeholders = sorted({m.group(0) for m in _TLA_PLACEHOLDER_RE.finditer(whole)})
        escapes = sorted(set(_tla_assumption_escapes(code)) | set(_tla_assumption_escapes(nested))
                         | _tla_module_escapes(whole, nested_names, allowed_modules))
    if placeholders:
        findings.append(_finding(
            ERR_PROOF_UNPROVEN_PLACEHOLDER, path_str, loc,
            f"{label} formal artifact '{locator}' contains unproven placeholder(s) {placeholders}; it proves nothing",
            params,
        ))
    if escapes:
        findings.append(_finding(
            ERR_PROOF_UNSOUND_ESCAPE, path_str, loc,
            f"{label} formal artifact '{locator}' contains unsound escape(s) {escapes} that can make a false theorem check",
            params,
        ))
    if theorem_name is not None:
        if not _declares_theorem(language, code, theorem_name):
            findings.append(_finding(
                ERR_PROOF_THEOREM_UNBOUND, path_str, loc,
                f"{label} formal artifact '{locator}' does not declare the claimed theorem '{theorem_name}' at top level, outside comments and strings",
                params,
            ))
        elif language == "lean" and not _lean_theorem_shaped(code, theorem_name):
            findings.append(_finding(
                ERR_PROOF_FORMAL_ARTIFACT_MISSING, path_str, loc,
                f"{label} formal artifact '{locator}' declares '{theorem_name}' without a Lean type and proof; it is not recognisably Lean 4",
                params,
            ))



def _verify_proof_claim_evidence(
    bundle_data: dict[str, Any],
    root: Path,
    path_str: str,
    expected_claim_id: str | None,
    findings: list[ClaimFinding],
    claim_generation: str | None = None,
) -> None:
    """Opens and validates the evidence the 'proof' row demands; every gap fails closed.

    Identity fields (claim, model, generation, checker, version, theorem name, digests) are
    compared byte for byte; nothing is stripped.

    0. Generation: the bundle generation is the citing claim row's current generation.
    1. Assumptions: non-empty, each a named {id, statement}.
    2. Theorem: {claim_id, name, statement} bound to the claim ID.
    3. Toolchain identity: a registered formal checker pinned to a concrete release.
    4. Declared formal model: {model_id, generation} whose retained fss.formal_model.v1
       manifest exists, names the same model, is declared for this claim, has a
       digest-bound model source on disk, and carries the bundle generation.
    5. Formal artifact: exactly one, on disk, digest-bound, not test code (path markers are
       checked before the suffix), a single case-exact formal suffix, source in that language,
       declaring the named theorem outside comments, with no unproven placeholder.
    6. Check receipt: a passing fss.proof_check_receipt.v1 bound to the claim, model
       (id, generation, source digest), theorem (name, statement), toolchain, and formal
       artifact digest.
    """
    claim_id = _bound_claim_id(bundle_data, expected_claim_id)
    params: dict[str, Any] = {"claim_class": "proof", "claim_id": claim_id}
    label = f"'proof' claim '{claim_id}'"
    bundle_generation = _exact_token(bundle_data.get("generation"))
    if bundle_generation is None:
        findings.append(_finding(
            ERR_PROOF_MODEL_GENERATION_MISMATCH, path_str, "generation",
            f"{label} declares no exact generation (got {bundle_data.get('generation')!r}); its formal model generation cannot be bound to it",
            params,
        ))
    _bind_claim_row_generation(bundle_generation, claim_generation, path_str, params, findings)

    # 1. Assumptions.
    _check_assumptions(bundle_data, path_str, params, findings)

    # 2. Theorem bound to the claim.
    theorem = bundle_data.get("theorem")
    statement: str | None = None
    theorem_name: str | None = None
    if not isinstance(theorem, dict):
        findings.append(_finding(ERR_PROOF_THEOREM_UNBOUND, path_str, "theorem", f"{label} declares no theorem {{claim_id, name, statement}}", params))
    else:
        statement = _exact_text(theorem.get("statement"))
        if statement is None:
            findings.append(_finding(ERR_PROOF_THEOREM_UNBOUND, path_str, "theorem.statement", f"{label} theorem has no exact statement (got {theorem.get('statement')!r})", params))
        theorem_name = _exact_token(theorem.get("name"))
        if theorem_name is None or _THEOREM_NAME_RE.fullmatch(theorem_name) is None:
            findings.append(_finding(
                ERR_PROOF_THEOREM_UNBOUND, path_str, "theorem.name",
                f"{label} theorem declares no formal name the artifact can declare (got {theorem.get('name')!r})",
                params,
            ))
            theorem_name = None
        theorem_claim = _exact_token(theorem.get("claim_id"))
        if theorem_claim != claim_id:
            findings.append(_finding(
                ERR_PROOF_THEOREM_UNBOUND, path_str, "theorem.claim_id",
                f"{label} theorem is bound to claim {theorem.get('claim_id')!r}, not '{claim_id}'",
                params,
            ))

    # 3. Toolchain identity.
    toolchain = bundle_data.get("toolchain_identity")
    declared_checker: str | None = None
    declared_version: str | None = None
    checker: str | None = None
    if not isinstance(toolchain, dict):
        findings.append(_finding(
            ERR_PROOF_TOOLCHAIN_UNBOUND, path_str, "toolchain_identity",
            f"{label} declares no toolchain_identity {{checker, version}}",
            params,
        ))
    else:
        declared_checker = (_exact_token(toolchain.get("checker")) or "").lower() or None
        checker = _classify_checker(toolchain.get("checker"), "toolchain_identity.checker", path_str, params, findings)
        declared_version = _classify_version(toolchain.get("version"), "toolchain_identity.version", path_str, params, findings)

    # 4. Declared formal model, opened and bound to the claim.
    declared_model = bundle_data.get("formal_model")
    declared_model_id: str | None = None
    declared_model_gen: str | None = None
    if not isinstance(declared_model, dict) or _exact_token(declared_model.get("model_id")) is None:
        findings.append(_finding(
            ERR_PROOF_FORMAL_MODEL_UNBOUND, path_str, "formal_model",
            f"{label} declares no exact formal model reference {{model_id, generation}} (got {declared_model!r})",
            params,
        ))
    else:
        declared_model_id = _exact_token(declared_model.get("model_id"))
        declared_model_gen = _exact_token(declared_model.get("generation"))
        if declared_model_gen is None:
            findings.append(_finding(
                ERR_PROOF_FORMAL_MODEL_UNBOUND, path_str, "formal_model.generation",
                f"{label} formal model reference declares no exact generation",
                params,
            ))
        elif bundle_generation is not None and declared_model_gen != bundle_generation:
            findings.append(_finding(
                ERR_PROOF_MODEL_GENERATION_MISMATCH, path_str, "formal_model.generation",
                f"{label} formal model generation '{declared_model_gen}' differs from the claim generation '{bundle_generation}'",
                {**params, "model_generation": declared_model_gen, "claim_generation": bundle_generation},
            ))

    manifest, reason = _open_role_document(bundle_data, root, "formal_model", FORMAL_MODEL_SCHEMA)
    model_id: str | None = declared_model_id
    model_gen: str | None = declared_model_gen
    source_digest: str | None = None
    model_module: str | None = None
    if manifest is None:
        findings.append(_finding(ERR_PROOF_FORMAL_MODEL_UNBOUND, path_str, "artifacts[role=formal_model]", f"{label} formal model: {reason}", params))
    else:
        manifest_id = _exact_token(manifest.get("model_id"))
        manifest_gen = _exact_token(manifest.get("generation"))
        manifest_claims = manifest.get("claim_ids")
        if manifest_id is None:
            findings.append(_finding(ERR_PROOF_FORMAL_MODEL_UNBOUND, path_str, "formal_model.model_id", f"{label} formal model manifest declares no exact model_id", params))
        elif declared_model_id is not None and manifest_id != declared_model_id:
            findings.append(_finding(
                ERR_PROOF_FORMAL_MODEL_UNBOUND, path_str, "formal_model.model_id",
                f"{label} declares formal model '{declared_model_id}' but the retained manifest is model '{manifest_id}'",
                params,
            ))
        if not isinstance(manifest_claims, list) or claim_id not in [c for c in manifest_claims if isinstance(c, str)]:
            findings.append(_finding(
                ERR_PROOF_FORMAL_MODEL_UNBOUND, path_str, "formal_model.claim_ids",
                f"{label} formal model manifest is not declared for this claim (claim_ids={manifest_claims!r})",
                params,
            ))
        if manifest_gen is None:
            findings.append(_finding(ERR_PROOF_FORMAL_MODEL_UNBOUND, path_str, "formal_model.generation", f"{label} formal model manifest declares no exact generation", params))
        else:
            if bundle_generation is not None and manifest_gen != bundle_generation:
                findings.append(_finding(
                    ERR_PROOF_MODEL_GENERATION_MISMATCH, path_str, "formal_model.generation",
                    f"{label} retained formal model generation '{manifest_gen}' differs from the claim generation '{bundle_generation}'",
                    {**params, "model_generation": manifest_gen, "claim_generation": bundle_generation},
                ))
            if declared_model_gen is not None and manifest_gen != declared_model_gen:
                findings.append(_finding(
                    ERR_PROOF_MODEL_GENERATION_MISMATCH, path_str, "formal_model.generation",
                    f"{label} declared model generation '{declared_model_gen}' differs from the retained manifest generation '{manifest_gen}'",
                    params,
                ))
        source = manifest.get("source")
        if not isinstance(source, dict):
            findings.append(_finding(ERR_PROOF_FORMAL_MODEL_UNBOUND, path_str, "formal_model.source", f"{label} formal model manifest declares no model source {{path, digest}}", params))
        else:
            source_bytes, source_reason = _open_retained_file(root, source.get("path"), source.get("digest"))
            if source_bytes is None:
                findings.append(_finding(ERR_PROOF_FORMAL_MODEL_UNBOUND, path_str, "formal_model.source", f"{label} formal model source {source_reason}", params))
            elif not source_bytes.strip():
                findings.append(_finding(ERR_PROOF_FORMAL_MODEL_UNBOUND, path_str, "formal_model.source", f"{label} formal model source is empty", params))
            else:
                source_digest = compute_sha256(source_bytes)
                model_module = _tla_module_name(source_bytes)
        model_id = manifest_id or declared_model_id
        model_gen = manifest_gen or declared_model_gen

    # 5. Formal artifact: the checked proof itself; tests never substitute for it.
    formal_entries = _role_artifacts(bundle_data, "formal_artifact")
    formal_digest: str | None = None
    art_loc = "artifacts[role=formal_artifact]"
    if len(formal_entries) != 1:
        findings.append(_finding(
            ERR_PROOF_FORMAL_ARTIFACT_MISSING, path_str, art_loc,
            f"{label} requires exactly one retained 'formal_artifact', found {len(formal_entries)}",
            params,
        ))
        test_roles = sorted({
            str(e.get("role")) for field_name in ARTIFACT_LIST_FIELDS
            for e in (bundle_data.get(field_name) if isinstance(bundle_data.get(field_name), list) else [])
            if isinstance(e, dict) and isinstance(e.get("role"), str) and _is_test_evidence(e["role"])
        })
        if not formal_entries and test_roles:
            findings.append(_finding(
                ERR_PROOF_TESTS_ONLY, path_str, "artifacts",
                f"{label} is backed only by test evidence {test_roles}; tests cannot prove a theorem",
                params,
            ))
    else:
        locator = _artifact_locator(formal_entries[0])
        raw, art_reason = _open_retained_file(root, locator, formal_entries[0].get("digest"))
        if raw is None:
            findings.append(_finding(ERR_PROOF_FORMAL_ARTIFACT_MISSING, path_str, art_loc, f"{label} formal artifact {art_reason}", params))
        elif not raw.strip():
            findings.append(_finding(ERR_PROOF_FORMAL_ARTIFACT_MISSING, path_str, art_loc, f"{label} formal artifact '{locator}' is empty", params))
        else:
            allowed = FORMAL_PROOF_CHECKERS[checker] if checker is not None else tuple(sorted({s for v in FORMAL_PROOF_CHECKERS.values() for s in v}))
            marker = _test_path_marker(str(locator))
            suffixes = Path(str(locator)).suffixes
            if marker is not None:
                findings.append(_finding(
                    ERR_PROOF_TESTS_ONLY, path_str, art_loc,
                    f"{label} formal artifact '{locator}' {marker}; tests cannot prove a theorem",
                    params,
                ))
            elif len(suffixes) != 1 or suffixes[0] not in allowed:
                findings.append(_finding(
                    ERR_PROOF_FORMAL_ARTIFACT_MISSING, path_str, art_loc,
                    f"{label} formal artifact '{locator}' is not a single-suffix formal source for checker {checker!r} "
                    f"(expected exactly one of {list(allowed)}, case-sensitive)",
                    params,
                ))
            else:
                formal_digest = compute_sha256(raw)
                _check_formal_content(
                    raw, str(locator), FORMAL_SUFFIX_LANGUAGES[suffixes[0]], theorem_name, path_str, params, findings,
                    allowed_modules=frozenset({model_module}) if model_module else None,
                )

    # 6. Check receipt bound to claim, model, theorem, toolchain, and artifact.
    receipt, receipt_reason = _open_role_document(bundle_data, root, "proof_check_receipt", PROOF_CHECK_RECEIPT_SCHEMA)
    if receipt is None:
        findings.append(_finding(ERR_PROOF_CHECK_RECEIPT_INVALID, path_str, "artifacts[role=proof_check_receipt]", f"{label} check receipt: {receipt_reason}", params))
        return
    r_loc = "proof_check_receipt"
    r_status = receipt.get("status")
    if r_status not in PASSING_PROOF_CHECK_STATUSES:
        findings.append(_finding(ERR_PROOF_CHECK_RECEIPT_INVALID, path_str, f"{r_loc}.status", f"{label} check receipt status {r_status!r} is not passing", params))
    if _exact_token(receipt.get("claim_id")) != claim_id:
        findings.append(_finding(
            ERR_PROOF_CHECK_RECEIPT_INVALID, path_str, f"{r_loc}.claim_id",
            f"{label} check receipt is bound to claim {receipt.get('claim_id')!r}",
            params,
        ))
    r_checker = _classify_checker(receipt.get("checker"), f"{r_loc}.checker", path_str, params, findings)
    r_version = _classify_version(receipt.get("checker_version"), f"{r_loc}.checker_version", path_str, params, findings)
    if declared_checker is not None and r_checker is not None and r_checker != declared_checker:
        findings.append(_finding(
            ERR_PROOF_TOOLCHAIN_UNBOUND, path_str, f"{r_loc}.checker",
            f"{label} check receipt checker '{r_checker}' differs from the declared toolchain '{declared_checker}'",
            params,
        ))
    if declared_version is not None and r_version is not None and r_version != declared_version:
        findings.append(_finding(
            ERR_PROOF_TOOLCHAIN_UNBOUND, path_str, f"{r_loc}.checker_version",
            f"{label} check receipt checker version '{r_version}' differs from the declared toolchain version '{declared_version}'",
            params,
        ))
    r_model = _exact_token(receipt.get("model_id"))
    if r_model is None or (model_id is not None and r_model != model_id):
        findings.append(_finding(
            ERR_PROOF_CHECK_RECEIPT_INVALID, path_str, f"{r_loc}.model_id",
            f"{label} check receipt checked model {receipt.get('model_id')!r}, not '{model_id}'",
            params,
        ))
    r_model_gen = _exact_token(receipt.get("model_generation"))
    if r_model_gen is None or (model_gen is not None and r_model_gen != model_gen):
        findings.append(_finding(
            ERR_PROOF_MODEL_GENERATION_MISMATCH, path_str, f"{r_loc}.model_generation",
            f"{label} check receipt checked model generation {receipt.get('model_generation')!r}, not '{model_gen}'",
            {**params, "receipt_model_generation": receipt.get("model_generation"), "model_generation": model_gen},
        ))
    r_source = _exact_token(receipt.get("model_source_digest"))
    if r_source is None or SHA256_DIGEST_RE.fullmatch(r_source) is None:
        findings.append(_finding(
            ERR_PROOF_CHECK_RECEIPT_INVALID, path_str, f"{r_loc}.model_source_digest",
            f"{label} check receipt records no model source digest (got {receipt.get('model_source_digest')!r})",
            params,
        ))
    elif source_digest is not None and r_source != source_digest:
        findings.append(_finding(
            ERR_PROOF_CHECK_RECEIPT_INVALID, path_str, f"{r_loc}.model_source_digest",
            f"{label} check receipt checked model source '{r_source}', not the retained model source '{source_digest}'",
            params,
        ))
    r_digest = _exact_token(receipt.get("formal_artifact_digest"))
    if r_digest is None or SHA256_DIGEST_RE.fullmatch(r_digest) is None:
        findings.append(_finding(ERR_PROOF_CHECK_RECEIPT_INVALID, path_str, f"{r_loc}.formal_artifact_digest", f"{label} check receipt binds no exact formal artifact digest", params))
    elif formal_digest is not None and r_digest != formal_digest:
        findings.append(_finding(
            ERR_PROOF_CHECK_RECEIPT_INVALID, path_str, f"{r_loc}.formal_artifact_digest",
            f"{label} check receipt checked artifact '{r_digest}', not the retained formal artifact '{formal_digest}'",
            params,
        ))
    r_statement = _exact_text(receipt.get("theorem_statement"))
    if statement is not None and r_statement != statement:
        findings.append(_finding(
            ERR_PROOF_THEOREM_UNBOUND, path_str, f"{r_loc}.theorem_statement",
            f"{label} check receipt checked theorem {receipt.get('theorem_statement')!r}, not the claimed statement",
            params,
        ))
    r_name = _exact_token(receipt.get("theorem_name"))
    if theorem_name is not None and r_name != theorem_name:
        findings.append(_finding(
            ERR_PROOF_THEOREM_UNBOUND, path_str, f"{r_loc}.theorem_name",
            f"{label} check receipt checked theorem {receipt.get('theorem_name')!r}, not '{theorem_name}'",
            params,
        ))



# Claim class 'bounded_model' (fss-x4a.30.87.3): "analytically derived bound under assumptions".
# Row minimum_evidence: derivation, units, assumptions, sensitivity and invalidators.
BOUND_DERIVATION_SCHEMA = "fss.bound_derivation.v1"
BOUND_COMPARATORS: frozenset[str] = frozenset({"<=", ">="})
# Units are slo_validate.REGISTERED_UNITS, compared exactly. Every registered unit is a
# physical, rate, count, size, or score quantity, so none may be negative (slo_validate F4);
# percent units stop at 100 and auprc at 1.
BOUND_PERCENT_UNITS: frozenset[str] = frozenset({"%", "percent", "percentage"})
BOUND_UNIT_MAXIMA: dict[str, float] = {**{u: 100.0 for u in BOUND_PERCENT_UNITS}, "auprc": 1.0}
# Text that names nothing: a derivation step, sensitivity effect, or invalidator must say something.
PLACEHOLDER_TEXT: frozenset[str] = frozenset({
    "none", "n/a", "na", "-", "--", "?", "tbd", "tba", "todo", "unknown", "null", "nil", "nothing",
    "not applicable", "...", ".",
})
_FORMULA_MAX_LENGTH = 512
_FORMULA_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_FORMULA_REL_TOL = 1e-9


class _FormulaError(ValueError):
    """A derivation formula that cannot be recomputed as plain arithmetic over its inputs."""


def _finite_number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except OverflowError:  # a JSON integer beyond float range is not a finite measurement
        return None
    return number if math.isfinite(number) else None


# Words that carry no content on their own; a substantive entry needs two other distinct words.
PLACEHOLDER_WORDS: frozenset[str] = frozenset({
    "none", "na", "tbd", "tba", "todo", "unknown", "null", "nil", "nothing", "not", "applicable", "fixme", "xxx",
})
_CONTENT_WORD_RE = re.compile(r"[^\W\d_]{2,}")
MIN_CONTENT_WORDS = 2


def _substantive(value: Any) -> bool:
    """Text that says something: punctuation never disguises a placeholder, and it needs at
    least two distinct words of two or more letters that are not placeholder words."""
    if not isinstance(value, str):
        return False
    words = {word.casefold() for word in _CONTENT_WORD_RE.findall(value)}
    return len(words - PLACEHOLDER_WORDS) >= MIN_CONTENT_WORDS


def _unit_domain_violation(value: float, unit: str) -> str | None:
    if value < 0.0:
        return "is negative"
    maximum = BOUND_UNIT_MAXIMA.get(unit)
    if maximum is not None and value > maximum:
        return f"exceeds {maximum:g} {unit}"
    return None


def _evaluate_formula(formula: str, inputs: dict[str, float]) -> float:
    """Recomputes a derivation formula: + - * / and unary +/- over recorded inputs and numbers.
    Anything else (calls, attributes, names that are not inputs, powers) is refused, every
    intermediate result must be finite, a product or quotient of nonzero operands must not
    underflow to zero, and the formula must name at least one recorded input."""
    tree = _parse_formula(formula)
    if not any(isinstance(node, ast.Name) for node in ast.walk(tree)):
        raise _FormulaError("formula names no recorded input; its derived value would be self-asserted")

    def evaluate(node: ast.AST) -> float:
        if isinstance(node, ast.Expression):
            return evaluate(node.body)
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub, ast.Mult, ast.Div)):
            left, right = evaluate(node.left), evaluate(node.right)
            if isinstance(node.op, ast.Add):
                result = left + right
            elif isinstance(node.op, ast.Sub):
                result = left - right
            elif isinstance(node.op, ast.Mult):
                result = left * right
            else:
                if right == 0.0:
                    raise _FormulaError("formula divides by zero")
                result = left / right
            if not math.isfinite(result):
                raise _FormulaError(f"formula intermediate result {ast.unparse(node)[:60]!r} is not finite")
            if result == 0.0 and isinstance(node.op, (ast.Mult, ast.Div)) and left != 0.0 and right != 0.0:
                raise _FormulaError(f"formula intermediate result {ast.unparse(node)[:60]!r} underflows to zero")
            return result
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
            operand = evaluate(node.operand)
            return -operand if isinstance(node.op, ast.USub) else operand
        if isinstance(node, ast.Constant) and type(node.value) in (int, float):
            number = _finite_number(node.value)
            if number is None:
                raise _FormulaError(f"formula constant {node.value!r} is not a finite number")
            return number
        if isinstance(node, ast.Name):
            if node.id not in inputs:
                raise _FormulaError(f"formula names '{node.id}', which is not a recorded input")
            return inputs[node.id]
        raise _FormulaError(f"formula uses unsupported syntax '{type(node).__name__}'")

    try:
        result = evaluate(tree)
    except RecursionError as exc:
        raise _FormulaError("formula nests too deeply") from exc
    if not math.isfinite(result):
        raise _FormulaError("formula result is not finite")
    return result


_FORMULA_MAX_DEPTH = 64


def _parse_formula(formula: str) -> ast.Expression:
    """Parses a formula and refuses one nested deeper than _FORMULA_MAX_DEPTH syntax-tree levels,
    measured iteratively, so no later recursive walk (evaluation, dimensions, ast.unparse) can
    exhaust the interpreter stack."""
    if len(formula) > _FORMULA_MAX_LENGTH:
        raise _FormulaError(f"formula exceeds {_FORMULA_MAX_LENGTH} characters")
    try:
        tree = ast.parse(formula, mode="eval")
    except (SyntaxError, ValueError, RecursionError) as exc:
        raise _FormulaError(f"formula is not arithmetic: {exc}") from exc
    stack: list[tuple[ast.AST, int]] = [(tree, 1)]
    while stack:
        node, depth = stack.pop()
        if depth > _FORMULA_MAX_DEPTH:
            raise _FormulaError(f"formula nests more than {_FORMULA_MAX_DEPTH} levels")
        stack.extend((child, depth + 1) for child in ast.iter_child_nodes(node))
    return tree


def _formula_input_names(formula: str) -> set[str] | None:
    try:
        tree = _parse_formula(formula)
    except _FormulaError:
        return None
    return {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}


class _DimensionError(_FormulaError):
    """A derivation formula whose units do not propagate consistently."""


# Registered units that count entities are dimensionless (a count has dimension one); every
# other registered unit is its own dimension and is never converted into another.
BOUND_COUNT_UNITS: frozenset[str] = frozenset({
    "frames", "tasks", "processes", "descriptors", "calls", "operations", "tokens", "output tokens",
    "semantic calls", "access_units", "object operation",
})


def _unit_dimension(unit: str) -> tuple[dict[str, int], str | None]:
    """(dimension exponents, count kind): a count unit is dimensionless but keeps its own kind,
    so distinct count units never add; any other registered unit is its own dimension."""
    return ({}, unit) if unit in BOUND_COUNT_UNITS else ({unit: 1}, None)


def _format_dimension(dimension: tuple[dict[str, int], str | None] | None) -> str:
    if dimension is None:
        return "a bare number"
    exponents, kind = dimension
    if kind is not None:
        return f"a count of {kind}"
    return "*".join(f"{u}^{p}" if p != 1 else u for u, p in sorted(exponents.items())) or "dimensionless"


def _check_formula_dimensions(formula: str, input_units: dict[str, str], result_unit: str) -> None:
    """Propagates units through + - * /. + and - need equal dimensions and equal count kinds (frames
    and tasks never add); * and / add and subtract exponents, and a count scales the other operand
    (frames * ms is ms); a bare number adopts the other operand's dimension under + and - and is
    dimensionless under * and /. The result must have the dimension of result_unit. The formula's
    depth is capped by _parse_formula, so this recursion is bounded."""
    tree = _parse_formula(formula)

    def combine(a: dict[str, int], b: dict[str, int], sign: int) -> dict[str, int]:
        out = dict(a)
        for unit, power in b.items():
            out[unit] = out.get(unit, 0) + sign * power
            if out[unit] == 0:
                del out[unit]
        return out

    def dimension(node: ast.AST) -> tuple[dict[str, int], str | None] | None:  # None: a bare number
        if isinstance(node, ast.Expression):
            return dimension(node.body)
        if isinstance(node, ast.BinOp):
            left, right = dimension(node.left), dimension(node.right)
            if isinstance(node.op, (ast.Add, ast.Sub)):
                if left is None or right is None:
                    return right if left is None else left
                if left != right:
                    raise _DimensionError(
                        f"formula {ast.unparse(node)[:60]!r} combines {_format_dimension(left)} with {_format_dimension(right)}"
                    )
                return left
            if left is None and right is None:
                return None
            exponents = combine((left or ({}, None))[0], (right or ({}, None))[0], 1 if isinstance(node.op, ast.Mult) else -1)
            if exponents:
                return exponents, None
            if left is None or right is None:
                return {}, (right if left is None else left)[1]
            return {}, None
        if isinstance(node, ast.UnaryOp):
            return dimension(node.operand)
        if isinstance(node, ast.Name):
            if node.id not in input_units:
                raise _FormulaError(f"formula names '{node.id}', which is not a recorded input")
            return _unit_dimension(input_units[node.id])
        return None

    result = dimension(tree)
    expected = _unit_dimension(result_unit)
    if result is not None and result != expected:
        raise _DimensionError(
            f"formula yields {_format_dimension(result)}, not the derivation's units '{result_unit}' ({_format_dimension(expected)})"
        )


def _verify_bounded_model_claim_evidence(
    bundle_data: dict[str, Any],
    root: Path,
    path_str: str,
    expected_claim_id: str | None,
    findings: list[ClaimFinding],
    claim_generation: str | None = None,
) -> None:
    """Opens and validates the evidence the 'bounded_model' row demands; every gap fails closed.

    0. Generation: the bundle generation is the citing claim row's current generation.
    1. Assumptions: non-empty, each an exact {id, statement}, ids unique ignoring case; every
       assumption the derivation relies on is declared by the claim.
    2. Bound: {claim_id, expression, comparator, value, units} bound to the claim ID, a finite
       value inside its unit's domain, and a registered unit (slo_validate.REGISTERED_UNITS).
    3. Derivation: exactly one retained fss.bound_derivation.v1 on disk, digest-bound, bound to
       the claim ID and generation, with substantive steps.
    4. The claimed expression, comparator, and units equal the derivation's exactly.
    5. Recomputation: the derivation records inputs {name: {value, units}} and the arithmetic
       'formula' that is its expression's right-hand side; the checker recomputes it and it
       must yield the derived value.
    6. Sensitivity entries {parameter, partial} name recorded inputs and a substantive effect;
       invalidators are substantive.
    7. The claimed bound is never tighter than the derived bound (no tolerance).
    """
    claim_id = _bound_claim_id(bundle_data, expected_claim_id)
    params: dict[str, Any] = {"claim_class": "bounded_model", "claim_id": claim_id}
    label = f"'bounded_model' claim '{claim_id}'"
    bundle_generation = _exact_token(bundle_data.get("generation"))
    _bind_claim_row_generation(bundle_generation, claim_generation, path_str, params, findings)

    # 1. Assumptions (the derivation cross-check follows below).
    assumption_ids = _check_assumptions(bundle_data, path_str, params, findings)

    def registered_units(value: Any, where: str, what: str) -> str | None:
        units = _exact_token(value)
        if units is None:
            findings.append(_finding(ERR_BOUND_UNITS_MISSING, path_str, where, f"{label} {what} declares no exact units (got {value!r})", params))
            return None
        if units not in slo_validate.REGISTERED_UNITS:
            findings.append(_finding(
                ERR_BOUND_UNITS_MISSING, path_str, where,
                f"{label} {what} units '{units}' are not a registered unit (slo_validate.REGISTERED_UNITS, compared exactly)",
                params,
            ))
            return None
        return units

    def in_domain(value: float | None, units: str | None, where: str, what: str) -> float | None:
        if value is None or units is None:
            return value
        violation = _unit_domain_violation(value, units)
        if violation is not None:
            findings.append(_finding(
                ERR_BOUND_VALUE_OUT_OF_DOMAIN, path_str, where,
                f"{label} {what} {value} {units} {violation}; it lies outside the unit's domain",
                {**params, "value": value, "units": units},
            ))
            return None
        return value

    # 2. The claimed bound.
    bound = bundle_data.get("bound")
    expression: str | None = None
    comparator: str | None = None
    value: float | None = None
    units: str | None = None
    if not isinstance(bound, dict):
        findings.append(_finding(
            ERR_BOUND_EXPRESSION_UNBOUND, path_str, "bound",
            f"{label} declares no bound {{claim_id, expression, comparator, value, units}}",
            params,
        ))
    else:
        bound_claim = _exact_token(bound.get("claim_id"))
        if bound_claim != claim_id:
            findings.append(_finding(ERR_BOUND_EXPRESSION_UNBOUND, path_str, "bound.claim_id", f"{label} bound is bound to claim {bound.get('claim_id')!r}", params))
        expression = _exact_text(bound.get("expression"))
        if expression is None:
            findings.append(_finding(ERR_BOUND_EXPRESSION_UNBOUND, path_str, "bound.expression", f"{label} bound declares no exact expression", params))
        raw_comparator = bound.get("comparator")
        if raw_comparator in BOUND_COMPARATORS:
            comparator = raw_comparator
        else:
            findings.append(_finding(
                ERR_BOUND_EXPRESSION_UNBOUND, path_str, "bound.comparator",
                f"{label} bound comparator {raw_comparator!r} is not one of {sorted(BOUND_COMPARATORS)}",
                params,
            ))
        value = _finite_number(bound.get("value"))
        if value is None:
            findings.append(_finding(ERR_BOUND_EXPRESSION_UNBOUND, path_str, "bound.value", f"{label} bound value {bound.get('value')!r} is not a finite number", params))
        units = registered_units(bound.get("units"), "bound.units", "bound")
        value = in_domain(value, units, "bound.value", "claimed bound")

    # 3. The derivation artifact, opened and bound to the claim.
    derivation, reason = _open_role_document(bundle_data, root, "derivation", BOUND_DERIVATION_SCHEMA)
    if derivation is None:
        findings.append(_finding(ERR_BOUND_DERIVATION_UNBOUND, path_str, "artifacts[role=derivation]", f"{label} derivation: {reason}", params))
        return
    d_loc = "derivation"
    if _exact_token(derivation.get("claim_id")) != claim_id:
        findings.append(_finding(
            ERR_BOUND_DERIVATION_UNBOUND, path_str, f"{d_loc}.claim_id",
            f"{label} derivation is bound to claim {derivation.get('claim_id')!r}",
            params,
        ))
    d_generation = _exact_token(derivation.get("generation"))
    if d_generation is None or bundle_generation is None or d_generation != bundle_generation:
        findings.append(_finding(
            ERR_BOUND_DERIVATION_UNBOUND, path_str, f"{d_loc}.generation",
            f"{label} derivation generation {derivation.get('generation')!r} differs from the claim generation {bundle_generation!r}",
            params,
        ))
    steps = derivation.get("steps")
    if not (isinstance(steps, list) and len(steps) > 0 and all(_substantive(s) for s in steps)):
        findings.append(_finding(ERR_BOUND_DERIVATION_UNBOUND, path_str, f"{d_loc}.steps", f"{label} derivation declares no substantive derivation steps (got {steps!r})", params))

    # 4. Expression, comparator, value, and units agree exactly with the derivation.
    d_expression = _exact_text(derivation.get("expression"))
    if d_expression is None:
        findings.append(_finding(ERR_BOUND_DERIVATION_UNBOUND, path_str, f"{d_loc}.expression", f"{label} derivation declares no exact derived expression", params))
    elif expression is not None and d_expression != expression:
        findings.append(_finding(
            ERR_BOUND_EXPRESSION_UNBOUND, path_str, "bound.expression",
            f"{label} claimed expression {expression!r} differs from the derived expression {d_expression!r}",
            params,
        ))
    d_comparator = derivation.get("comparator")
    if d_comparator not in BOUND_COMPARATORS:
        findings.append(_finding(ERR_BOUND_DERIVATION_UNBOUND, path_str, f"{d_loc}.comparator", f"{label} derivation comparator {d_comparator!r} is not registered", params))
        d_comparator = None
    elif comparator is not None and d_comparator != comparator:
        findings.append(_finding(
            ERR_BOUND_EXPRESSION_UNBOUND, path_str, "bound.comparator",
            f"{label} claimed comparator '{comparator}' differs from the derived comparator '{d_comparator}'",
            params,
        ))
    d_value = _finite_number(derivation.get("derived_value"))
    if d_value is None:
        findings.append(_finding(
            ERR_BOUND_DERIVATION_UNBOUND, path_str, f"{d_loc}.derived_value",
            f"{label} derivation derived_value {derivation.get('derived_value')!r} is not a finite number",
            params,
        ))
    d_units = registered_units(derivation.get("units"), f"{d_loc}.units", "derivation")
    if units is not None and d_units is not None and d_units != units:
        findings.append(_finding(
            ERR_BOUND_UNITS_MISSING, path_str, "bound.units",
            f"{label} claimed units '{units}' differ from the derivation units '{d_units}'; units are never converted implicitly",
            params,
        ))
    d_value = in_domain(d_value, d_units, f"{d_loc}.derived_value", "derived value")

    d_assumptions = derivation.get("assumption_ids")
    if not (isinstance(d_assumptions, list) and len(d_assumptions) > 0 and all(_exact_token(a) for a in d_assumptions)):
        findings.append(_finding(ERR_BOUND_DERIVATION_UNBOUND, path_str, f"{d_loc}.assumption_ids", f"{label} derivation names no exact assumption ids", params))
    elif assumption_ids is not None:
        omitted = sorted(set(d_assumptions) - set(assumption_ids))
        if omitted:
            findings.append(_finding(
                ERR_CLAIM_ASSUMPTIONS_MISSING, path_str, "assumptions",
                f"{label} omits assumptions its derivation relies on: {omitted}",
                {**params, "omitted_assumptions": omitted},
            ))

    # 5. Recompute the derived value from the recorded inputs.
    raw_inputs = derivation.get("inputs")
    inputs: dict[str, float] | None = None
    if not isinstance(raw_inputs, dict) or not raw_inputs:
        findings.append(_finding(
            ERR_BOUND_DERIVATION_NOT_RECOMPUTABLE, path_str, f"{d_loc}.inputs",
            f"{label} derivation records no inputs {{name: {{value, units}}}} (got {raw_inputs!r}); its derived value is self-asserted",
            params,
        ))
    else:
        inputs = {}
        input_units_map: dict[str, str] = {}
        for name, entry in raw_inputs.items():
            where = f"{d_loc}.inputs.{name}"
            number = _finite_number(entry.get("value")) if isinstance(entry, dict) else None
            if not isinstance(name, str) or _FORMULA_NAME_RE.fullmatch(name) is None or number is None:
                findings.append(_finding(
                    ERR_BOUND_DERIVATION_NOT_RECOMPUTABLE, path_str, where,
                    f"{label} derivation input {name!r} must be an identifier with a finite 'value' (got {entry!r})",
                    params,
                ))
                inputs = None
                continue
            input_units = registered_units(entry.get("units"), f"{where}.units", f"derivation input '{name}'")
            number = in_domain(number, input_units, where, f"derivation input '{name}'")
            if input_units is None or number is None:
                inputs = None
            elif inputs is not None:
                inputs[name] = number
                input_units_map[name] = input_units
    formula = _exact_text(derivation.get("formula"))
    if formula is None:
        findings.append(_finding(
            ERR_BOUND_DERIVATION_NOT_RECOMPUTABLE, path_str, f"{d_loc}.formula",
            f"{label} derivation records no arithmetic formula over its inputs (got {derivation.get('formula')!r})",
            params,
        ))
    else:
        if d_expression is not None and d_comparator is not None:
            _, separator, rhs = d_expression.partition(d_comparator)
            try:
                same_tree = bool(separator) and ast.dump(_parse_formula(rhs.strip())) == ast.dump(_parse_formula(formula))
            except _FormulaError:
                same_tree = False
            if not same_tree:
                findings.append(_finding(
                    ERR_BOUND_DERIVATION_NOT_RECOMPUTABLE, path_str, f"{d_loc}.formula",
                    f"{label} derivation formula {formula!r} is not the right-hand side of its expression {d_expression!r}",
                    params,
                ))
        if inputs is not None:
            try:
                recomputed = _evaluate_formula(formula, inputs)
            except _FormulaError as exc:
                findings.append(_finding(ERR_BOUND_DERIVATION_NOT_RECOMPUTABLE, path_str, f"{d_loc}.formula", f"{label} derivation {exc}", params))
            else:
                if d_value is not None and not math.isclose(recomputed, d_value, rel_tol=_FORMULA_REL_TOL, abs_tol=0.0):
                    findings.append(_finding(
                        ERR_BOUND_DERIVATION_NOT_RECOMPUTABLE, path_str, f"{d_loc}.derived_value",
                        f"{label} derivation formula recomputes {recomputed}, not the asserted derived value {d_value}",
                        {**params, "recomputed_value": recomputed, "derived_value": d_value},
                    ))
                    d_value = None
            used = _formula_input_names(formula)
            unused = sorted(set(inputs) - used) if used is not None else []
            if unused:
                findings.append(_finding(
                    ERR_BOUND_DERIVATION_NOT_RECOMPUTABLE, path_str, f"{d_loc}.inputs",
                    f"{label} derivation records input(s) {unused} that its formula never uses",
                    {**params, "unused_inputs": unused},
                ))
            # Units are independent of the numbers: check them even when recomputation failed.
            if d_units is not None:
                try:
                    _check_formula_dimensions(formula, input_units_map, d_units)
                except _DimensionError as exc:
                    findings.append(_finding(ERR_BOUND_DIMENSION_MISMATCH, path_str, f"{d_loc}.formula", f"{label} derivation {exc}", params))
                except (_FormulaError, RecursionError):
                    pass  # not arithmetic over recorded inputs: already reported by the recomputation

    # 6. Sensitivity analysis and invalidators say something.
    sensitivity = derivation.get("sensitivity")
    sensitivity_ok = isinstance(sensitivity, list) and len(sensitivity) > 0
    if sensitivity_ok:
        for entry in sensitivity:
            parameter = _exact_token(entry.get("parameter")) if isinstance(entry, dict) else None
            if parameter is None or not _substantive(entry.get("partial")) or (isinstance(raw_inputs, dict) and raw_inputs and parameter not in raw_inputs):
                sensitivity_ok = False
                break
    if not sensitivity_ok:
        findings.append(_finding(
            ERR_BOUND_SENSITIVITY_MISSING, path_str, f"{d_loc}.sensitivity",
            f"{label} derivation declares no substantive sensitivity analysis: each entry is "
            f"{{parameter: a recorded input, partial: its effect}} (got {sensitivity!r})",
            params,
        ))
    invalidators = derivation.get("invalidators")
    if not (isinstance(invalidators, list) and len(invalidators) > 0 and all(_substantive(i) for i in invalidators)):
        findings.append(_finding(
            ERR_BOUND_SENSITIVITY_MISSING, path_str, f"{d_loc}.invalidators",
            f"{label} derivation declares no substantive invalidators (got {invalidators!r})",
            params,
        ))

    # 7. Never tighter than the derivation.
    comparable = (
        value is not None and d_value is not None
        and comparator is not None and comparator == d_comparator
        and units is not None and units == d_units
        and expression is not None and expression == d_expression
    )
    if comparable:
        tighter = value < d_value if comparator == "<=" else value > d_value
        if tighter:
            findings.append(_finding(
                ERR_BOUND_TIGHTER_THAN_DERIVATION, path_str, "bound.value",
                f"{label} claims '{expression}' {comparator} {value} {units}, tighter than the derived bound {d_value} {units}",
                {**params, "claimed_value": value, "derived_value": d_value, "comparator": comparator, "units": units},
            ))


# Classes whose registry rows the checker realizes with evidence inspection; every other class
# fails closed when promoted (review item P7).
REALIZED_CLAIM_CLASSES: frozenset[str] = frozenset({"slo", "proof", "bounded_model"})


def _naive_instant_finding(now: datetime | None, where: str) -> ClaimFinding | None:
    if now is not None and (now.tzinfo is None or now.utcoffset() is None):
        return _finding(
            ERR_UNRECOGNIZED_STATE, where, "now",
            f"Evaluation instant {now.isoformat()} is not zone-qualified; expiry and measurement windows are indeterminate",
        )
    return None


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
    claim_generation: str | None = None,
    class_bindings: dict[str, str] | None = None,
) -> tuple[bool, list[ClaimFinding], dict[str, Any] | None]:
    """Verifies one proof bundle (or qualification receipt) against all fail-closed criteria.
    claim_generation is the citing claim row's current generation (Generation column)."""
    findings: list[ClaimFinding] = []
    path_str = sanitize_path(bundle_path, root)
    naive = _naive_instant_finding(now, path_str)
    if naive is not None:
        return False, [naive], None

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
    inexact_ids = [f for f in id_fields if _exact_token(data[f]) is None]
    if id_fields and inexact_ids and any(isinstance(data[f], str) and data[f].strip() for f in inexact_ids):
        findings.append(_finding(
            ERR_CLAIM_BINDING_MISMATCH, path_str, "claim_id",
            f"Proof bundle '{path_str}' declares claim id(s) {[data[f] for f in inexact_ids]!r} that are not exact tokens; "
            "identity is compared byte for byte, never stripped",
            {"expected_claim_id": expected_claim_id},
        ))
    elif not id_fields or not isinstance(bundle_claim_id, str) or not bundle_claim_id.strip():
        findings.append(_finding(
            ERR_CLAIM_BINDING_MISMATCH, path_str, "claim_id",
            f"Proof bundle '{path_str}' binds no claim ID"
            + (f"; it cannot prove claim '{expected_claim_id}'" if expected_claim_id is not None else ""),
            {"expected_claim_id": expected_claim_id},
        ))
    elif len(id_fields) > 1 and len({str(data[f]) for f in id_fields}) > 1:
        findings.append(_finding(
            ERR_CLAIM_BINDING_MISMATCH, path_str, "claim_id",
            f"Proof bundle '{path_str}' declares conflicting claim IDs {[data[f] for f in id_fields]}",
        ))
    elif expected_claim_id is not None and bundle_claim_id != expected_claim_id.strip():
        findings.append(_finding(
            ERR_CLAIM_BINDING_MISMATCH, path_str, "claim_id",
            f"Proof bundle is bound to claim '{bundle_claim_id.strip()}', not to the citing claim '{expected_claim_id}'",
            {"bundle_claim_id": bundle_claim_id, "expected_claim_id": expected_claim_id},
        ))

    # 4. Generation checks: stale, superseded, tombstoned, 'latest', and expiry.
    tombstones = {normalize_id(t) for t in (tombstoned_ids or ())}
    _check_generations(data, path_str, tombstones, findings)
    effective_now = now if now is not None else datetime.now(timezone.utc)
    _check_expiry(data, path_str, effective_now, findings)

    # 5. Status: closed vocabulary.
    raw_status = data.get("status")
    # Byte-exact: a status is never stripped or case-folded into the vocabulary.
    bundle_status = raw_status if isinstance(raw_status, str) and _exact_token(raw_status) is not None else None
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
    elif supported_str in NON_CLAIMING_STATES or supported_str in UNSUPPORTING_LEVELS:
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

    # 8. Claim class and required evidence. The class is the citing claim's: the registry's
    # where one governs the claim id (every SLO id is an 'slo' claim), else the claim row's Class
    # column. A bundle never picks its own class: one that declares none or disagrees fails, and
    # a promoted bundle whose class nothing but the bundle itself asserts fails closed.
    _, raw_bundle_class = _single_field(data, CLAIM_CLASS_FIELDS)
    bundle_class = _exact_token(raw_bundle_class)
    inexact_class = bundle_class is None and isinstance(raw_bundle_class, str) and bool(raw_bundle_class.strip())
    if inexact_class:
        findings.append(_finding(
            ERR_CLAIM_BINDING_MISMATCH, path_str, "claim_class",
            f"Proof bundle claim class {raw_bundle_class!r} is not an exact class name; it is never stripped into a match",
            {"bundle_claim_class": raw_bundle_class},
        ))
    row_class = _nonempty_str(claim_class)
    registry_class = _registry_claim_class(
        expected_claim_id if expected_claim_id is not None else bundle_claim_id, class_bindings, slo_root=root,
    )
    if row_class is not None and registry_class is not None and row_class != registry_class:
        findings.append(_finding(
            ERR_CLAIM_BINDING_MISMATCH, path_str, "claim_class",
            f"Citing claim row class '{row_class}' contradicts the registry class '{registry_class}' of its claim",
            {"row_claim_class": row_class, "claim_class": registry_class},
        ))
    citing_class = registry_class  # a row's Class column alone never resolves a class (review item A)
    unresolved = citing_class is None and _is_promoted_bundle(data, claim_level)
    effective_class = None if unresolved else (citing_class if citing_class is not None else bundle_class)
    if unresolved:
        findings.append(_finding(
            ERR_CLAIM_CLASS_UNRESOLVED, path_str, "claim_class",
            f"Promoted proof bundle '{path_str}' has a claim id no registry binds to a class (row class {row_class!r}); "
            f"its own declaration {raw_bundle_class!r} is not authoritative, so no evidence can be verified",
            {"bundle_claim_class": raw_bundle_class},
        ))
    if citing_class is not None and bundle_class is not None and bundle_class != citing_class:
        findings.append(_finding(
            ERR_CLAIM_BINDING_MISMATCH, path_str, "claim_class",
            f"Proof bundle claim class '{bundle_class}' differs from the citing claim class '{citing_class}'",
            {"bundle_claim_class": bundle_class, "claim_class": citing_class},
        ))
    if bundle_class is None and not inexact_class and effective_class is not None:
        findings.append(_finding(
            ERR_INVALID_CLAIM_CLASS, path_str, "claim_class",
            f"Proof bundle '{path_str}' declares no claim class; it must restate the citing claim class '{effective_class}'",
        ))
    if known_classes is None:
        findings.append(_finding(
            ERR_INVALID_CLAIM_CLASS, path_str, "claim_class",
            "No authoritative claim-class registry was supplied; required evidence cannot be verified",
        ))
    elif unresolved:
        pass  # reported above; required evidence of an unknown class is never checked
    elif effective_class is None:
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

        if effective_class == "slo" and _is_promoted_bundle(data, claim_level):
            _verify_slo_claim_evidence(data, root, path_str, expected_claim_id, effective_now, findings)
        elif effective_class == "proof" and _is_promoted_bundle(data, claim_level):
            _verify_proof_claim_evidence(data, root, path_str, expected_claim_id, findings, claim_generation)
            if not any(f.severity == "error" for f in findings):
                # Static scanning cannot establish a Lean or TLA+ proof (orchestrator decision,
                # round-3 review): a proof is verified only by a prover-run qualification receipt.
                findings.append(_finding(
                    ERR_PROOF_PROVER_RUN_REQUIRED, path_str, "proof_check_receipt",
                    f"'proof' claim '{_bound_claim_id(data, expected_claim_id)}' passed the static pre-filter, but static "
                    "evidence never verifies a proof: a qualification receipt from actually running the prover is "
                    "required, and that receipt mechanism is not defined yet",
                    {"claim_class": "proof", "claim_id": _bound_claim_id(data, expected_claim_id)},
                ))
        elif effective_class == "bounded_model" and _is_promoted_bundle(data, claim_level):
            _verify_bounded_model_claim_evidence(data, root, path_str, expected_claim_id, findings, claim_generation)
        elif effective_class not in REALIZED_CLAIM_CLASSES and _is_promoted_bundle(data, claim_level):
            findings.append(_finding(
                ERR_CLAIM_CLASS_EVIDENCE_UNINSPECTED, path_str, "claim_class",
                f"Claim class '{effective_class}' has no evidence inspection in this checker; a promoted "
                f"'{effective_class}' claim is never verified from its bundle's evidence names alone",
                {"claim_class": effective_class},
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


_DELIMITER_CELL_RE = re.compile(r"^:?-+:?$")
_UNESCAPED_PIPE_RE = re.compile(r"(?<!\\)\|")


class _Cell(str):
    """A table cell's trimmed value that remembers its raw text, for fields compared exactly."""

    raw: str

    def __new__(cls, value: str, raw: str) -> "_Cell":
        cell = super().__new__(cls, value)
        cell.raw = raw
        return cell


def _split_table_row(line: str) -> list[str]:
    stripped = line.strip()
    if stripped.startswith("|"):
        stripped = stripped[1:]
    if stripped.endswith("|") and not stripped.endswith("\\|"):
        stripped = stripped[:-1]
    return [_Cell(cell.strip(), cell) for cell in _UNESCAPED_PIPE_RE.split(stripped)]


def _is_delimiter_row(line: str) -> bool:
    if "|" not in line:
        return False
    cells = _split_table_row(line)
    return bool(cells) and all(_DELIMITER_CELL_RE.match(cell) for cell in cells)


def parse_markdown_tables(text: str) -> list[tuple[list[str], list[list[str]]]]:
    """Extracts GFM tables (with or without border pipes) as (headers, data_rows)."""
    clean_text = _visible_markdown(text)  # one visibility rule for claim tables and SLOS.md (review S3)
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
                    data_rows.append([_Cell(c.strip("`"), c.raw) for c in _split_table_row(row_line)])
                idx += 1
            tables.append((headers, data_rows))
            continue
        idx += 1
    return tables


def _new_scan_stats() -> dict[str, int]:
    return {"claim_tables": 0, "rows": 0, "promoted": 0, "bundles_checked": 0, "bundles_passed": 0, "bundles_unpromoted": 0}


def _row_promoted(claim_level: str | None) -> bool:
    """Whether the citing claim row's own status promotes the claim (never the bundle's level)."""
    if not isinstance(claim_level, str):
        return False
    level = claim_level.strip().lower()
    rank = _rank_of(level)
    return (rank is not None and rank >= PROMOTION_RANK) or level in ("achieved", "promoted")


def _outcome_key(root: Path, path: Path, data: dict[str, Any] | None, claim_id: str | None = None) -> str:
    """One outcome per claim when a claim row cites the bundle (several bundles or rows for one
    claim are one claim); otherwise one per bundle: its exact declared content digest when it has
    one (two copies at different paths are one bundle), else its resolved path."""
    if isinstance(claim_id, str) and claim_id:
        return f"claim:{claim_id}"
    if isinstance(data, dict):
        _, declared = _single_field(data, CONTENT_DIGEST_FIELDS)
        digest = _exact_token(declared)
        if digest is not None and SHA256_DIGEST_RE.fullmatch(digest):
            return f"digest:{digest}"
    return f"path:{_citation_key(root, path)}"


def _record_outcome(table: dict[str, dict[str, Any]], key: str, ok: bool, promoted: bool, resolved: str) -> None:
    """A bundle is verified only when every check of it passed and some citing row's own status
    promotes it; a passing bundle cited below that (or by no row) is counted as unpromoted."""
    outcome = table.setdefault(key, {"ok": True, "promoted": False, "paths": set()})
    outcome["ok"] = outcome["ok"] and ok
    outcome["promoted"] = outcome["promoted"] or promoted
    outcome["paths"].add(resolved)


def _citation_key(root: Path, path: Path) -> str:
    target = path if path.is_absolute() else root / path
    try:
        return str(target.resolve())
    except (OSError, RuntimeError):
        return str(target)


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
    cited_classes: dict[str, set[str | None]] | None = None,
    cited_generations: dict[str, set[str | None]] | None = None,
    class_bindings: dict[str, str] | None = None,
    outcomes: dict[str, dict[str, Any]] | None = None,
) -> list[ClaimFinding]:
    """Scans markdown tables for status and proof root/bundle citations. A ``Class`` column
    declares each claim row's class and a ``Generation`` column its current generation;
    cited_classes / cited_generations record, per cited bundle, what its citing rows declare
    (the retention walk inherits them)."""
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
    local_outcomes: dict[str, dict[str, Any]] = {}
    for headers, data_rows in parse_markdown_tables(raw_text):
        normalized_headers = [normalize_cell(h).lower() for h in headers]
        columns: dict[str, list[int]] = {"status": [], "proof": [], "id": [], "class": [], "generation": []}
        for col_idx, col_name in enumerate(normalized_headers):
            if col_name == "status":
                columns["status"].append(col_idx)
            elif col_name in ("proof root", "proof_root", "proof bundle", "proof_bundle", "proof"):
                columns["proof"].append(col_idx)
            elif col_name in ("id", "claim", "claim id"):
                columns["id"].append(col_idx)
            elif col_name in ("class", "claim class", "claim_class"):
                columns["class"].append(col_idx)
            elif col_name in ("generation", "claim generation", "claim_generation"):
                columns["generation"].append(col_idx)

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
        class_col = columns["class"][0] if columns["class"] else None
        generation_col = columns["generation"][0] if columns["generation"] else None

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
            class_val = normalize_cell(row[class_col]).lower() if class_col is not None and class_col < len(row) else ""
            row_class = class_val if class_val not in NON_PROOF_ROOTS else None
            # The generation cell is compared byte for byte: backticks, bold, NBSP, or zero-width
            # characters are never normalized away (only ASCII spaces and tabs around it are).
            raw_generation = getattr(row[generation_col], "raw", row[generation_col]) if generation_col is not None and generation_col < len(row) else ""
            generation_text = raw_generation.strip(" \t")
            row_generation = generation_text if generation_text and generation_text.lower() not in NON_PROOF_ROOTS else None

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
                bundle_ok, bundle_findings, bundle_data = verify_proof_bundle(
                    bundle_path=proof_path,
                    root=root,
                    expected_claim_id=row_id,
                    claim_level=status_val,
                    claim_class=row_class,
                    claim_generation=row_generation,
                    class_bindings=class_bindings,
                    known_classes=known_classes,
                    tombstoned_ids=tombstoned_ids,
                    prohibited_promotions=prohibited_promotions,
                    now=now,
                )
                key = _outcome_key(root, proof_path, bundle_data, row_id)
                resolved = _citation_key(root, proof_path)
                _record_outcome(local_outcomes, key, bundle_ok, _row_promoted(status_val), resolved)
                if outcomes is not None:
                    _record_outcome(outcomes, key, bundle_ok, _row_promoted(status_val), resolved)
                if cited_classes is not None:
                    cited_classes.setdefault(_citation_key(root, proof_path), set()).add(row_class)
                if cited_generations is not None:
                    cited_generations.setdefault(_citation_key(root, proof_path), set()).add(row_generation)
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

    counters["bundles_checked"] += len(local_outcomes)
    counters["bundles_passed"] += sum(1 for o in local_outcomes.values() if o["ok"] and o["promoted"])
    counters["bundles_unpromoted"] += sum(1 for o in local_outcomes.values() if o["ok"] and not o["promoted"])
    counters["claim_tables"] += claim_tables_here
    if require_claim_table and claim_tables_here == 0:
        findings.append(_finding(
            ERR_EMPTY_INPUT, path_str, "file",
            f"Claim surface '{path_str}' declares no recognizable status/proof claim table; zero claims would be audited",
        ))
    return findings


BASELINE_CLAIMS_GENERATION = "gen:fss1:claims-v1"
BASELINE_CLAIMS_FREEZE_DIGEST = "sha256:a771b73ed343bbbb04a4cc98a9a7d2853caa533b2600b60090f1ab14d74e1916"

EXPECTED_CLAIMS_FREEZE_DIGESTS: dict[str, str] = {
    BASELINE_CLAIMS_GENERATION: BASELINE_CLAIMS_FREEZE_DIGEST,
}

CANONICAL_PROHIBITED_PROMOTIONS: tuple[str, ...] = (
    "source_presence_as_support",
    "single_demo_as_readiness",
    "version_string_as_conformance",
    "aggregate_accuracy_as_event_recall",
    "unbounded_never_miss_claim",
    "compact_output_as_sufficient_context_without_omission_receipt",
    "recommendation_score_as_effect_authority",
    "memory_or_prior_handoff_as_live_truth",
    "lower_call_count_as_agent_efficiency_without_task_quality_and_cost_vector",
)

CANONICAL_CLAIM_CLASSES: dict[str, dict[str, Any]] = {
    "invariant": {
        "id": "invariant",
        "claim_class": "invariant",
        "meaning": "behavior forbidden/required for all reachable states",
        "minimum_evidence": "contract, mechanical check, adversarial counterexample suite",
        "requiredEvidence": [
            "contract",
            "mechanical_check",
            "counterexample_suite",
        ],
    },
    "proof": {
        "id": "proof",
        "claim_class": "proof",
        "meaning": "theorem under declared formal model",
        "minimum_evidence": "formal artifact, assumptions, toolchain identity, check receipt",
        "requiredEvidence": [
            "formal_artifact",
            "toolchain_identity",
            "proof_check_receipt",
        ],
    },
    "bounded_model": {
        "id": "bounded_model",
        "claim_class": "bounded_model",
        "meaning": "analytically derived bound under assumptions",
        "minimum_evidence": "derivation, units, assumptions, sensitivity and invalidators",
        "requiredEvidence": [
            "assumptions",
            "derivation",
            "sensitivity_analysis",
        ],
    },
    "statistical": {
        "id": "statistical",
        "claim_class": "statistical",
        "meaning": "estimated population/task behavior",
        "minimum_evidence": "sealed dataset manifest, sampling protocol, raw results, confidence interval",
        "requiredEvidence": [
            "dataset_manifest",
            "sampling_protocol",
            "confidence_interval",
            "held_out_results",
        ],
    },
    "slo": {
        "id": "slo",
        "claim_class": "slo",
        "meaning": "operational latency/availability/cost target achieved",
        "minimum_evidence": "operation-cost row, environment, workload, raw measurements, failures",
        "requiredEvidence": [
            "operation_cost_row",
            "measurement_artifact",
            "environment_manifest",
        ],
    },
    "benchmark": {
        "id": "benchmark",
        "claim_class": "benchmark",
        "meaning": "comparative performance",
        "minimum_evidence": "pinned same-workload oracle, exact versions, raw samples, variance, command",
        "requiredEvidence": [
            "same_workload_oracle",
            "raw_samples",
            "variance",
            "reproduction_command",
        ],
    },
    "compatibility": {
        "id": "compatibility",
        "claim_class": "compatibility",
        "meaning": "exact device/model/provider tuple works",
        "minimum_evidence": "tuple identity, fixture, conformance/soak/crash/security evidence",
        "requiredEvidence": [
            "device_firmware_app_tuple",
            "fixture_digest",
            "conformance_receipt",
        ],
    },
    "agent_task": {
        "id": "agent_task",
        "claim_class": "agent_task",
        "meaning": "task-level agent correctness, calibration, safety, and efficiency",
        "minimum_evidence": "sealed task corpus, anchor-aligned transcripts, CognitiveFacet owner/anchor compatibility, WorldEnvelope/control classification, task/evidence/safety metrics, resource cost vector, failures/abstentions/interventions",
        "requiredEvidence": [
            "sealed_task_corpus_manifest",
            "anchor_aligned_transcripts",
            "world_envelope_and_control_classification_metrics",
            "cognitive_facet_owner_anchor_compatibility",
            "task_correctness_and_calibration",
            "evidence_use_and_unsafe_action_metrics",
            "resource_cost_vector",
            "failures_abstentions_and_operator_interventions",
        ],
    },
    "agent_accretion": {
        "id": "agent_accretion",
        "claim_class": "agent_accretion",
        "meaning": "improvement from retained handoff/experience/procedures across repeated tasks",
        "minimum_evidence": "repeated-task corpus, no-memory baseline, quality non-regression, resource-savings distribution, harmful-transfer/trauma-guard evidence",
        "requiredEvidence": [
            "sealed_repeated_task_corpus",
            "baseline_without_prior_experience",
            "learning_and_handoff_roots",
            "task_quality_non_regression",
            "resource_savings_distribution",
            "harmful_transfer_and_trauma_guard_results",
        ],
    },
}

REQUIRED_NORMATIVE_CLAIM_CLASSES: tuple[str, ...] = tuple(CANONICAL_CLAIM_CLASSES.keys())

MANDATORY_CLAIMS_TOP_LEVEL_FIELDS: tuple[str, ...] = (
    "schema",
    "generation",
    "freezeDigest",
    "sourceDocument",
    "prohibited",
    "classes",
)

MANDATORY_CLAIM_ROW_FIELDS: tuple[str, ...] = (
    "id",
    "claim_class",
    "meaning",
    "minimum_evidence",
    "requiredEvidence",
)


def compute_canonical_claims_digest(
    data_or_classes: dict[str, Any] | list[dict[str, Any]],
    schema: str = "fss.claims.v1",
    generation: str = BASELINE_CLAIMS_GENERATION,
    source_document: str = "registries/CLAIMS.md",
    prohibited: list[str] | None = None,
) -> str:
    """Computes SHA-256 digest of canonically serialized claims registry data.

    Binds top-level metadata (schema, generation, sourceDocument, prohibited)
    and deterministically sorted classes rows with their requiredEvidence.
    """
    if isinstance(data_or_classes, dict):
        data = data_or_classes
        schema_val = str(data.get("schema", "")).strip()
        generation_val = str(data.get("generation", "")).strip()
        source_doc_val = str(data.get("sourceDocument", "")).strip()
        raw_prohibited = data.get("prohibited")
        prohibited_val = sorted(str(p).strip() for p in raw_prohibited) if isinstance(raw_prohibited, list) else []
        raw_classes = data.get("classes", [])
    else:
        schema_val = schema
        generation_val = generation
        source_doc_val = source_document
        prohibited_val = sorted(str(p).strip() for p in (prohibited or list(CANONICAL_PROHIBITED_PROMOTIONS)))
        raw_classes = data_or_classes

    sorted_classes = sorted(raw_classes, key=lambda r: str(r.get("id", "")))
    canonical_payload = {
        "classes": [
            {
                "claim_class": str(r.get("claim_class", "")).strip(),
                "id": str(r.get("id", "")).strip(),
                "meaning": str(r.get("meaning", "")).strip(),
                "minimum_evidence": str(r.get("minimum_evidence", "")).strip(),
                "requiredEvidence": sorted(str(e).strip() for e in r.get("requiredEvidence", [])),
            }
            for r in sorted_classes
        ],
        "generation": generation_val,
        "prohibited": prohibited_val,
        "schema": schema_val,
        "sourceDocument": source_doc_val,
    }
    canonical_bytes = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(canonical_bytes).hexdigest()}"


def audit_claim_kind_registry(
    root: Path = ROOT,
    claims_json_path: Path | None = None,
    claims_md_path: Path | None = None,
) -> list[ClaimFinding]:
    """Audits the machine-readable claim-kind registry (architecture/claims.json)
    against the normative human-readable registry (registries/CLAIMS.md) and the pinned baseline.

    Enforces fail-closed verification:
    1. ERR_CLAIM_ID_REUSED: Reused, duplicate, case-folded, or tombstoned stable IDs.
    2. ERR_CLAIM_MISSING_FIELD: Missing required normative fields in JSON, top-level metadata, or Markdown.
    3. ERR_CLAIM_REGISTRY_DRIFT: Any divergence in row count, IDs, ordering, meaning, minimum evidence, required evidence, or prohibited promotions.
    4. ERR_BUNDLE_DIGEST_MISMATCH: Computed canonical digest mismatch against declared freezeDigest or pinned baseline freeze digest.
    5. ERR_STALE_GENERATION: Unrecognized or unpinned registry generation.
    """
    findings: list[ClaimFinding] = []
    json_path = claims_json_path or (root / "architecture/claims.json")
    md_path = claims_md_path or (root / "registries/CLAIMS.md")
    json_str = sanitize_path(json_path, root)
    md_str = sanitize_path(md_path, root)

    if not json_path.is_file():
        return [_finding(ERR_UNREADABLE_INPUT, json_str, "file", f"Claims registry file not found: '{json_path}'")]
    if not md_path.is_file():
        return [_finding(ERR_UNREADABLE_INPUT, md_str, "file", f"Claims markdown source file not found: '{md_path}'")]

    try:
        json_bytes = json_path.read_bytes()
    except OSError as exc:
        return [_finding(ERR_UNREADABLE_INPUT, json_str, "file", f"Could not read claims registry '{json_path}': {exc}")]

    if len(json_bytes.strip()) == 0:
        return [_finding(ERR_EMPTY_INPUT, json_str, "file", "Claims registry file is empty (0 bytes)")]

    try:
        data = json.loads(json_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:  # RecursionError: nesting too deep
        return [_finding(ERR_UNREADABLE_INPUT, json_str, "file", f"Claims registry '{json_path}' is invalid JSON: {exc}")]

    if not isinstance(data, dict):
        return [_finding(ERR_UNREADABLE_INPUT, json_str, "file", "Claims registry root must be a JSON object")]

    # Check top-level metadata fields
    for field_name in MANDATORY_CLAIMS_TOP_LEVEL_FIELDS:
        if field_name not in data:
            findings.append(_finding(
                ERR_CLAIM_MISSING_FIELD, json_str, field_name,
                f"Claims registry root missing required '{field_name}' property",
            ))

    schema_val = data.get("schema")
    if schema_val is not None:
        if not isinstance(schema_val, str) or not schema_val.strip():
            findings.append(_finding(ERR_CLAIM_MISSING_FIELD, json_str, "schema", "Claims registry 'schema' must be a non-empty string"))
        elif schema_val != "fss.claims.v1":
            findings.append(_finding(
                ERR_CLAIM_REGISTRY_DRIFT, json_str, "schema",
                f"Claims registry 'schema' must be 'fss.claims.v1', observed '{schema_val}'",
            ))

    source_doc = data.get("sourceDocument")
    if source_doc is not None:
        if not isinstance(source_doc, str) or not source_doc.strip():
            findings.append(_finding(ERR_CLAIM_MISSING_FIELD, json_str, "sourceDocument", "Claims registry 'sourceDocument' must be a non-empty string"))
        elif source_doc != "registries/CLAIMS.md":
            findings.append(_finding(
                ERR_CLAIM_REGISTRY_DRIFT, json_str, "sourceDocument",
                f"Claims registry 'sourceDocument' must be 'registries/CLAIMS.md', observed '{source_doc}'",
            ))

    generation_val = data.get("generation")
    if generation_val is not None:
        if not isinstance(generation_val, str) or not generation_val.strip():
            findings.append(_finding(ERR_CLAIM_MISSING_FIELD, json_str, "generation", "Claims registry 'generation' must be a non-empty string"))
        elif generation_val not in EXPECTED_CLAIMS_FREEZE_DIGESTS:
            findings.append(_finding(
                ERR_STALE_GENERATION, json_str, "generation",
                f"Claims registry generation '{generation_val}' is not recognized or lacks an authorized freeze digest",
            ))

    prohibited_list = data.get("prohibited")
    if prohibited_list is not None:
        if not isinstance(prohibited_list, list) or len(prohibited_list) == 0:
            findings.append(_finding(ERR_CLAIM_MISSING_FIELD, json_str, "prohibited", "Claims registry 'prohibited' must be a non-empty list"))
        elif not all(isinstance(p, str) and p.strip() for p in prohibited_list):
            findings.append(_finding(ERR_CLAIM_MISSING_FIELD, json_str, "prohibited", "Claims registry 'prohibited' entries must be non-empty strings"))
        else:
            norm_prohibited = [p.strip() for p in prohibited_list]
            if sorted(norm_prohibited) != sorted(CANONICAL_PROHIBITED_PROMOTIONS):
                findings.append(_finding(
                    ERR_CLAIM_REGISTRY_DRIFT, json_str, "prohibited",
                    f"Claims registry 'prohibited' list has diverged from canonical baseline: observed {norm_prohibited}, expected {list(CANONICAL_PROHIBITED_PROMOTIONS)}",
                ))

    # Freeze digest verification
    declared_digest = data.get("freezeDigest")
    computed_digest = compute_canonical_claims_digest(data)
    if declared_digest is not None:
        if not isinstance(declared_digest, str) or not declared_digest.strip():
            findings.append(_finding(ERR_CLAIM_MISSING_FIELD, json_str, "freezeDigest", "Claims registry 'freezeDigest' must be a non-empty string"))
        elif declared_digest != computed_digest:
            findings.append(_finding(
                ERR_BUNDLE_DIGEST_MISMATCH, json_str, "freezeDigest",
                f"Claims registry freezeDigest mismatch: declared '{declared_digest}', computed '{computed_digest}'",
            ))
        elif generation_val and generation_val in EXPECTED_CLAIMS_FREEZE_DIGESTS:
            expected_digest = EXPECTED_CLAIMS_FREEZE_DIGESTS[generation_val]
            if declared_digest != expected_digest:
                findings.append(_finding(
                    ERR_BUNDLE_DIGEST_MISMATCH, json_str, "freezeDigest",
                    f"Claims registry freezeDigest '{declared_digest}' diverged from pinned baseline freeze digest '{expected_digest}'",
                ))

    # Tombstone verification
    tombstoned_ids, tombstone_findings = load_tombstone_index(root)
    findings.extend(tombstone_findings)
    tombstoned_folded = {t.lower() for t in tombstoned_ids}

    classes = data.get("classes")
    if not isinstance(classes, list) or len(classes) == 0:
        findings.append(_finding(ERR_EMPTY_INPUT, json_str, "classes", "Claims registry declares no claim classes"))
        return findings

    seen_ids: set[str] = set()
    json_rows: list[dict[str, Any]] = []

    for idx, item in enumerate(classes):
        loc = f"classes[{idx}]"
        if not isinstance(item, dict):
            findings.append(_finding(ERR_UNREADABLE_INPUT, json_str, loc, f"Malformed claim class entry at index {idx}"))
            continue

        cid = item.get("id")
        if not isinstance(cid, str) or not cid.strip():
            findings.append(_finding(ERR_CLAIM_MISSING_FIELD, json_str, f"{loc}.id", f"Claim class at index {idx} missing required 'id' field"))
            continue
        cid = cid.strip()

        # Mandatory claim_class field
        claim_class_val = item.get("claim_class")
        if not isinstance(claim_class_val, str) or not claim_class_val.strip():
            findings.append(_finding(
                ERR_CLAIM_MISSING_FIELD, json_str, f"{loc}.claim_class",
                f"Claim class '{cid}' missing required non-empty 'claim_class' field",
            ))
        elif claim_class_val.strip() != cid:
            findings.append(_finding(
                ERR_CLAIM_ID_REUSED, json_str, f"{loc}.claim_class",
                f"Claim class '{cid}' has conflicting or renumbered claim_class '{claim_class_val}'",
            ))

        # Case-insensitive duplicate check
        cid_lower = cid.lower()
        if cid_lower in seen_ids:
            findings.append(_finding(
                ERR_CLAIM_ID_REUSED, json_str, f"{loc}.id",
                f"Duplicate or case-colliding claim class ID '{cid}' at index {idx}",
                {"id": cid},
            ))
        seen_ids.add(cid_lower)

        # Tombstone check
        if cid in tombstoned_ids or cid_lower in tombstoned_folded:
            findings.append(_finding(
                ERR_CLAIM_ID_REUSED, json_str, f"{loc}.id",
                f"Claim class '{cid}' is a tombstoned identifier and cannot be used as an active class",
                {"id": cid},
            ))

        meaning = item.get("meaning")
        if not isinstance(meaning, str) or not meaning.strip():
            findings.append(_finding(
                ERR_CLAIM_MISSING_FIELD, json_str, f"{loc}.meaning",
                f"Claim class '{cid}' missing required non-empty 'meaning' field",
            ))

        min_ev = item.get("minimum_evidence")
        if min_ev is None:
            min_ev = item.get("minimumEvidence")
        if not isinstance(min_ev, str) or not min_ev.strip():
            findings.append(_finding(
                ERR_CLAIM_MISSING_FIELD, json_str, f"{loc}.minimum_evidence",
                f"Claim class '{cid}' missing required non-empty 'minimum_evidence' field",
            ))

        req_ev = item.get("requiredEvidence")
        if not isinstance(req_ev, list) or len(req_ev) == 0 or not all(isinstance(e, str) and e.strip() for e in req_ev):
            findings.append(_finding(
                ERR_CLAIM_MISSING_FIELD, json_str, f"{loc}.requiredEvidence",
                f"Claim class '{cid}' missing required non-empty 'requiredEvidence' list",
            ))

        # Baseline comparison
        if cid not in CANONICAL_CLAIM_CLASSES:
            findings.append(_finding(
                ERR_CLAIM_REGISTRY_DRIFT, json_str, f"{loc}.id",
                f"Unrecognized claim class '{cid}' not present in canonical baseline",
                {"id": cid},
            ))
        else:
            baseline = CANONICAL_CLAIM_CLASSES[cid]
            if isinstance(meaning, str) and meaning.strip() != baseline["meaning"]:
                findings.append(_finding(
                    ERR_CLAIM_REGISTRY_DRIFT, json_str, f"{loc}.meaning",
                    f"Claim class '{cid}' meaning diverged from baseline: observed {meaning.strip()!r}, expected {baseline['meaning']!r}",
                ))
            if isinstance(min_ev, str) and min_ev.strip() != baseline["minimum_evidence"]:
                findings.append(_finding(
                    ERR_CLAIM_REGISTRY_DRIFT, json_str, f"{loc}.minimum_evidence",
                    f"Claim class '{cid}' minimum_evidence diverged from baseline: observed {min_ev.strip()!r}, expected {baseline['minimum_evidence']!r}",
                ))
            if isinstance(req_ev, list) and sorted(e.strip() for e in req_ev) != sorted(baseline["requiredEvidence"]):
                findings.append(_finding(
                    ERR_CLAIM_REGISTRY_DRIFT, json_str, f"{loc}.requiredEvidence",
                    f"Claim class '{cid}' requiredEvidence diverged from baseline: observed {sorted(req_ev)}, expected {sorted(baseline['requiredEvidence'])}",
                ))

        json_rows.append({
            "id": cid,
            "meaning": meaning.strip() if isinstance(meaning, str) else "",
            "minimum_evidence": min_ev.strip() if isinstance(min_ev, str) else "",
            "required_evidence": req_ev if isinstance(req_ev, list) else [],
        })

    # Check all canonical baseline classes are present
    for baseline_cid in CANONICAL_CLAIM_CLASSES:
        if baseline_cid.lower() not in seen_ids:
            findings.append(_finding(
                ERR_CLAIM_REGISTRY_DRIFT, json_str, "classes",
                f"Canonical claim class '{baseline_cid}' is missing from claims registry",
                {"missing_class": baseline_cid},
            ))

    # Parse markdown source
    try:
        md_text = md_path.read_text(encoding="utf-8")
    except OSError as exc:
        findings.append(_finding(ERR_UNREADABLE_INPUT, md_str, "file", f"Could not read markdown source '{md_path}': {exc}"))
        return findings

    tables = parse_markdown_tables(md_text)
    claim_table: tuple[list[str], list[list[str]]] | None = None
    for headers, rows in tables:
        normalized_headers = [h.strip().lower() for h in headers]
        if "claim class" in normalized_headers:
            if claim_table is not None:
                findings.append(_finding(ERR_CLAIM_REGISTRY_DRIFT, md_str, "table", "Duplicate claim table found in markdown source"))
            claim_table = (headers, rows)

    if claim_table is None:
        findings.append(_finding(ERR_CLAIM_MISSING_FIELD, md_str, "table", "No claim table with 'Claim class' header found in markdown source"))
        return findings

    headers, data_rows = claim_table
    norm_headers = [h.strip().lower() for h in headers]
    try:
        class_col = norm_headers.index("claim class")
        meaning_col = norm_headers.index("meaning")
        evidence_col = norm_headers.index("minimum evidence")
    except ValueError as exc:
        findings.append(_finding(ERR_CLAIM_MISSING_FIELD, md_str, "headers", f"Missing required column in claims table: {exc}"))
        return findings

    md_seen_ids: set[str] = set()
    md_rows: list[dict[str, str]] = []
    for r_idx, row in enumerate(data_rows):
        if len(row) <= max(class_col, meaning_col, evidence_col):
            findings.append(_finding(
                ERR_CLAIM_MISSING_FIELD, md_str, f"row[{r_idx}]",
                f"Claim table row {r_idx + 1} has insufficient columns: {row}",
            ))
            continue
        c_id = row[class_col].strip().strip("`")
        m_val = row[meaning_col].strip()
        e_val = row[evidence_col].strip()

        if not c_id:
            findings.append(_finding(ERR_CLAIM_MISSING_FIELD, md_str, f"row[{r_idx}].id", f"Empty claim class ID at row {r_idx + 1}"))
            continue
        c_id_lower = c_id.lower()
        if c_id_lower in md_seen_ids:
            findings.append(_finding(ERR_CLAIM_ID_REUSED, md_str, f"row[{r_idx}].id", f"Duplicate or case-colliding claim class ID '{c_id}' in markdown table"))
        md_seen_ids.add(c_id_lower)

        if c_id in tombstoned_ids or c_id_lower in tombstoned_folded:
            findings.append(_finding(
                ERR_CLAIM_ID_REUSED, md_str, f"row[{r_idx}].id",
                f"Claim class '{c_id}' in markdown table is a tombstoned identifier and cannot be resurrected",
            ))

        if not m_val:
            findings.append(_finding(ERR_CLAIM_MISSING_FIELD, md_str, f"row[{r_idx}].meaning", f"Claim class '{c_id}' in markdown table has empty meaning"))
        if not e_val:
            findings.append(_finding(ERR_CLAIM_MISSING_FIELD, md_str, f"row[{r_idx}].evidence", f"Claim class '{c_id}' in markdown table has empty minimum evidence"))

        md_rows.append({"id": c_id, "meaning": m_val, "minimum_evidence": e_val})

    # Validate forbidden promotions section in markdown
    if "## forbidden claim promotions" not in md_text.lower():
        findings.append(_finding(
            ERR_CLAIM_MISSING_FIELD, md_str, "section",
            "Missing '## Forbidden claim promotions' section in CLAIMS.md",
        ))
    else:
        in_forbidden = False
        forbidden_bullets: list[str] = []
        for line in md_text.splitlines():
            stripped = line.strip()
            if stripped.startswith("## ") and "forbidden claim promotions" in stripped.lower():
                in_forbidden = True
                continue
            if in_forbidden:
                if stripped.startswith("## "):
                    break
                if stripped.startswith("- "):
                    forbidden_bullets.append(stripped[2:].strip())
        if len(forbidden_bullets) == 0:
            findings.append(_finding(
                ERR_EMPTY_INPUT, md_str, "section.forbidden",
                "'## Forbidden claim promotions' section contains no bullet items",
            ))

    lines = md_text.splitlines()
    in_claim_table = False
    table_ended = False
    for l_idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("|") and "claim class" in stripped.lower():
            in_claim_table = True
            continue
        if in_claim_table:
            if not stripped or stripped.startswith("##"):
                in_claim_table = False
                table_ended = True
                continue
        elif table_ended and stripped.startswith("|") and not stripped.startswith("##"):
            findings.append(_finding(
                ERR_CLAIM_REGISTRY_DRIFT, md_str, f"line {l_idx}",
                f"Orphan claim row outside header-bounded table: '{stripped}'",
            ))

    json_ids = [r["id"] for r in json_rows]
    md_ids = [r["id"] for r in md_rows]

    if json_ids != md_ids:
        findings.append(_finding(
            ERR_CLAIM_REGISTRY_DRIFT, json_str, "classes",
            f"Claim class ordering or IDs differ between {json_str} and {md_str}: JSON has {json_ids}, Markdown has {md_ids}",
            {"json_ids": json_ids, "markdown_ids": md_ids},
        ))

    for j_row, m_row in zip(json_rows, md_rows):
        cid = j_row["id"]
        if cid != m_row["id"]:
            continue
        if j_row["meaning"] != m_row["meaning"]:
            findings.append(_finding(
                ERR_CLAIM_REGISTRY_DRIFT, json_str, f"{cid}.meaning",
                f"Claim class '{cid}' meaning differs between JSON and Markdown: {j_row['meaning']!r} != {m_row['meaning']!r}",
                {"id": cid, "json_meaning": j_row["meaning"], "md_meaning": m_row["meaning"]},
            ))
        if j_row["minimum_evidence"] != m_row["minimum_evidence"]:
            findings.append(_finding(
                ERR_CLAIM_REGISTRY_DRIFT, json_str, f"{cid}.minimum_evidence",
                f"Claim class '{cid}' minimum_evidence differs between JSON and Markdown: {j_row['minimum_evidence']!r} != {m_row['minimum_evidence']!r}",
                {"id": cid, "json_evidence": j_row["minimum_evidence"], "md_evidence": m_row["minimum_evidence"]},
            ))

    for req_class in REQUIRED_NORMATIVE_CLAIM_CLASSES:
        if req_class not in json_ids:
            findings.append(_finding(
                ERR_CLAIM_REGISTRY_DRIFT, json_str, "classes",
                f"Mandatory normative claim class '{req_class}' missing from claims registry",
                {"missing_class": req_class},
            ))
        if req_class not in md_ids:
            findings.append(_finding(
                ERR_CLAIM_REGISTRY_DRIFT, md_str, "table",
                f"Mandatory normative claim class '{req_class}' missing from CLAIMS.md table",
                {"missing_class": req_class},
            ))

    return findings


def audit_claim_proof_bundles(
    root: Path = ROOT,
    claims_json_path: Path | None = None,
    target_bundle: Path | None = None,
    now: datetime | None = None,
    class_bindings: dict[str, str] | None = None,
) -> tuple[bool, list[ClaimFinding], dict[str, Any]]:
    """Runs full claim/proof-bundle consistency verification across the repository."""
    claims_path = claims_json_path or (root / "architecture/claims.json")
    known_classes, prohibited_promotions, findings = load_authoritative_claims(claims_path)
    tombstoned_ids, tombstone_findings = load_tombstone_index(root)
    findings.extend(tombstone_findings)

    # Validate claim-kind registry mirror equality
    registry_findings = audit_claim_kind_registry(
        root=root,
        claims_json_path=claims_path,
        claims_md_path=root / "registries/CLAIMS.md",
    )
    findings.extend(registry_findings)

    stats = _new_scan_stats()
    surfaces_scanned: list[str] = []
    receipts = {"inspected": 0, "passed": 0, "nonpassing": 0}
    # Class bindings come from the owning registries; an explicit binding (Python API only, never
    # a claim row or bundle) may add ids no registry covers but never overrides a registry.
    naive = _naive_instant_finding(now, "audit")
    if naive is not None:
        findings.append(naive)
    registry_bindings, binding_findings = load_claim_class_bindings(root)
    findings.extend(binding_findings)
    bindings: dict[str, str | None] = {**(class_bindings or {}), **registry_bindings}
    # One outcome per bundle (content digest, else resolved path): a bundle cited by several rows,
    # stored twice, or also retained under qualification-artifacts is counted once.
    outcomes: dict[str, dict[str, Any]] = {}

    if target_bundle is not None:
        bundle_ok, b_findings, b_data = verify_proof_bundle(
            bundle_path=target_bundle,
            root=root,
            known_classes=known_classes,
            tombstoned_ids=tombstoned_ids,
            prohibited_promotions=prohibited_promotions,
            now=now,
            class_bindings=bindings,
        )
        findings.extend(b_findings)
        _record_outcome(outcomes, _outcome_key(root, target_bundle, b_data), bundle_ok, False, _citation_key(root, target_bundle))
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
                class_bindings=bindings,
                outcomes=outcomes,
            ))
            surfaces_scanned.append(rel_file)

        cited_paths: set[str] = set().union(*(o["paths"] for o in outcomes.values()))
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
                        resolved = _citation_key(root, f_path)
                        if resolved in cited_paths:
                            continue  # verified as cited by its claim row(s); never checked or counted twice
                        bundle_ok, b_findings, b_data = verify_proof_bundle(
                            bundle_path=f_path,
                            root=root,
                            known_classes=known_classes,
                            tombstoned_ids=tombstoned_ids,
                            prohibited_promotions=prohibited_promotions,
                            now=now,
                            class_bindings=bindings,
                        )
                        findings.extend(b_findings)
                        _record_outcome(outcomes, _outcome_key(root, f_path, b_data), bundle_ok, False, resolved)  # no citing row adds no promotion

    error_count = sum(1 for f in findings if f.severity == "error")
    warning_count = sum(1 for f in findings if f.severity == "warning")
    is_valid = error_count == 0

    summary = {
        "status": "pass" if is_valid else "fail",
        "error_count": error_count,
        "warning_count": warning_count,
        "verified_bundles_count": sum(1 for o in outcomes.values() if o["ok"] and o["promoted"]),
        "unpromoted_bundles_count": sum(1 for o in outcomes.values() if o["ok"] and not o["promoted"]),
        "bundles_checked": len(outcomes),
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
        now=args.as_of if args.as_of is not None else datetime.now(timezone.utc),
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
                f"{summary['verified_bundles_count']}/{summary['bundles_checked']} proof bundles verified "
                f"({summary['unpromoted_bundles_count']} unpromoted, not counted as verified), "
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

#![forbid(unsafe_code)]
//! Deterministic public claim scope, evidence, exclusion, and expiry evaluator (`FSS-195`,
//! bead `fss-x4a.26.15`).
//!
//! Public readiness claims (support matrices, release status, documentation badges, and
//! qualification summaries) must be mechanically derived from retained receipts bound to an exact
//! source/sibling/toolchain/target/generation scope tuple (`INV-021`, `REL-INV-009`, `NONGOAL-013`).
//!
//! Core fail-closed invariants:
//! - Source presence, prose assertions, skipped/partial/unavailable receipts, or `"latest"`
//!   generation aliases can never promote a claim to [`ClaimEvaluationVerdict::Certified`].
//! - Any matching exclusion rule, expired validity window (`now_ns >= expires_at_ns`), scope
//!   mismatch, tombstoned/superseded generation, missing required lane, or unresolved
//!   `Indeterminate` evidence withholds certification and preserves exact typed defects and
//!   remediation guidance.
//! - Cooperative cancellation is checked before and during receipt inspection so no partial
//!   certified verdict ever escapes.
//! - Sans-IO and deterministic: callers supply exact scope tuples, receipts, exclusions,
//!   tombstones, and `now_ns`; nothing here reads clocks, filesystems, or networks.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, TimestampNs,
};

/// Registered digest domain for public claim evaluation receipts (`SCHEMA-DOMAIN-CORE-CLAIM-EVALUATOR-001`).
pub const CLAIM_EVALUATION_RECEIPT_DOMAIN: &str = "fss.claim_evaluation_receipt.v1";

/// Format version for canonical claim evaluation receipts.
pub const CLAIM_EVALUATION_FORMAT_VERSION: u32 = 1;

/// Forbidden mutable ref/tag aliases that can never back a public claim (`ADR-0004`).
/// `"latest"` is forbidden in any delimited segment; the other aliases are forbidden when
/// used as the whole identifier or as a ref/tag suffix after `:`, `@`, or `/`.
const FORBIDDEN_SUFFIX_ALIASES: &[&str] = &["auto", "head", "current"];

/// Hard bounds protecting claim evaluation from unbounded inputs or adversarial payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimEvaluationLimits {
    /// Maximum number of retained evidence receipts accepted in one evaluation.
    pub max_receipts: usize,
    /// Maximum number of required lane IDs declared by one claim.
    pub max_required_lanes: usize,
    /// Maximum number of explicit exclusion rules accepted in one evaluation.
    pub max_exclusions: usize,
    /// Maximum number of tombstoned/superseded generation IDs checked in one evaluation.
    pub max_tombstones: usize,
    /// Maximum UTF-8 byte length of any single identifier or textual scope/exclusion field.
    pub max_text_bytes: usize,
}

impl Default for ClaimEvaluationLimits {
    fn default() -> Self {
        Self {
            max_receipts: 256,
            max_required_lanes: 64,
            max_exclusions: 128,
            max_tombstones: 512,
            max_text_bytes: 512,
        }
    }
}

impl ClaimEvaluationLimits {
    /// Fails closed on zero or absurdly wide policy bounds without silently clamping.
    pub fn validate(self) -> Result<(), ClaimEvaluatorError> {
        if !(1..=4096).contains(&self.max_receipts)
            || !(1..=256).contains(&self.max_required_lanes)
            || !(1..=1024).contains(&self.max_exclusions)
            || !(1..=4096).contains(&self.max_tombstones)
            || !(16..=4096).contains(&self.max_text_bytes)
        {
            return Err(ClaimEvaluatorError::InvalidPolicy);
        }
        Ok(())
    }
}

/// Typed operational error when claim evaluation inputs or policy fail preflight or cancel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClaimEvaluatorError {
    /// Policy bounds are zero or out of supported range.
    InvalidPolicy,
    /// An input exceeded a configured bound.
    LimitExceeded(&'static str),
    /// Malformed identifier, empty field, control byte, or inverted timestamp interval.
    InvalidInput(&'static str),
    /// Caller cancellation observed before releasing a verdict.
    Cancelled,
}

impl fmt::Display for ClaimEvaluatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy => write!(f, "claim evaluator policy bounds are invalid"),
            Self::LimitExceeded(what) => write!(f, "claim evaluator limit exceeded: {what}"),
            Self::InvalidInput(what) => write!(f, "invalid claim evaluator input: {what}"),
            Self::Cancelled => write!(f, "claim evaluation cancelled before completion"),
        }
    }
}

impl std::error::Error for ClaimEvaluatorError {}

/// Ordered public readiness levels; a claim never exceeds what retained proof supports.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ClaimReadinessLevel {
    /// Specified/declared in registries only; requires no runtime proof.
    Declared,
    /// Deterministic reference implementation verified by unit/contract tests.
    ReferenceImplemented,
    /// Qualified on an exact controlled local target tuple via `scripts/qualify.sh`.
    LocallyQualified,
    /// Full controlled release-candidate matrix qualified across required native hosts.
    ReleaseQualified,
}

impl ClaimReadinessLevel {
    /// Stable machine-readable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Declared => "declared",
            Self::ReferenceImplemented => "reference_implemented",
            Self::LocallyQualified => "locally_qualified",
            Self::ReleaseQualified => "release_qualified",
        }
    }
}

impl CanonicalEncode for ClaimReadinessLevel {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(match self {
            Self::Declared => 1,
            Self::ReferenceImplemented => 2,
            Self::LocallyQualified => 3,
            Self::ReleaseQualified => 4,
        });
    }
}

impl CanonicalDecode for ClaimReadinessLevel {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::Declared),
            2 => Ok(Self::ReferenceImplemented),
            3 => Ok(Self::LocallyQualified),
            4 => Ok(Self::ReleaseQualified),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Exact typed execution status of a retained qualification receipt.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EvidenceReceiptStatus {
    /// All required checks in the lane passed without secret leaks or drift.
    Passed,
    /// One or more checks failed.
    Failed,
    /// One or more checks were skipped (never equivalent to pass).
    Skipped,
    /// Only a subset of required checks/targets ran (never equivalent to pass).
    Partial,
    /// Execution was interrupted before completion.
    Interrupted,
    /// Required host, device, oracle, or capacity was unavailable.
    Unavailable,
    /// Outcome could not be conclusively established.
    Indeterminate,
    /// Execution was cooperatively cancelled.
    Cancelled,
}

impl EvidenceReceiptStatus {
    /// Stable machine-readable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
            Self::Partial => "partial",
            Self::Interrupted => "interrupted",
            Self::Unavailable => "unavailable",
            Self::Indeterminate => "indeterminate",
            Self::Cancelled => "cancelled",
        }
    }
}

/// Non-collapsed verdict emitted by [`evaluate_public_claim`].
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ClaimEvaluationVerdict {
    /// Requested readiness level is strictly backed by fresh, exact-scope, unexcluded proof.
    Certified,
    /// One or more explicit exclusion rules block certification for this claim or scope.
    Excluded,
    /// One or more required proofs have expired at `now_ns`.
    Expired,
    /// Evidence scope tuple (target, source, sibling closure, toolchain, basis) disagrees.
    ScopeMismatch,
    /// Claim or evidence references a tombstoned, superseded, or `"latest"`-aliased generation.
    StaleGeneration,
    /// Required lane missing, non-passing receipt, or requested level exceeds proof support.
    InsufficientEvidence,
    /// Unresolved indeterminate evidence or conflicting receipts for the same lane.
    Indeterminate,
}

impl ClaimEvaluationVerdict {
    /// Stable machine-readable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Certified => "certified",
            Self::Excluded => "excluded",
            Self::Expired => "expired",
            Self::ScopeMismatch => "scope_mismatch",
            Self::StaleGeneration => "stale_generation",
            Self::InsufficientEvidence => "insufficient_evidence",
            Self::Indeterminate => "indeterminate",
        }
    }
}

impl CanonicalEncode for ClaimEvaluationVerdict {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(match self {
            Self::Certified => 1,
            Self::Excluded => 2,
            Self::Expired => 3,
            Self::ScopeMismatch => 4,
            Self::StaleGeneration => 5,
            Self::InsufficientEvidence => 6,
            Self::Indeterminate => 7,
        });
    }
}

impl CanonicalDecode for ClaimEvaluationVerdict {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::Certified),
            2 => Ok(Self::Excluded),
            3 => Ok(Self::Expired),
            4 => Ok(Self::ScopeMismatch),
            5 => Ok(Self::StaleGeneration),
            6 => Ok(Self::InsufficientEvidence),
            7 => Ok(Self::Indeterminate),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Exact immutable build/platform/generation scope tuple bound by both claim and evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimScopeTuple {
    /// Exact target triple (e.g. `aarch64-apple-darwin`, `x86_64-unknown-linux-gnu`).
    pub target_triple: String,
    /// Exact immutable source commit (`git:<sha>`).
    pub source_commit: String,
    /// Exact sibling closure content digest.
    pub sibling_closure_digest: ContentDigest,
    /// Pinned Rust toolchain channel (e.g. `nightly-2026-08-31`).
    pub toolchain: String,
    /// Pinned `ContractBasis` canonical digest.
    pub contract_basis_digest: ContentDigest,
    /// Pinned generation identifiers (device, model, provider, corpus, policy) bound to the scope.
    pub pinned_generations: Vec<String>,
}

impl CanonicalEncode for ClaimScopeTuple {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.target_triple);
        encoder.text(&self.source_commit);
        encoder.digest(self.sibling_closure_digest);
        encoder.text(&self.toolchain);
        encoder.digest(self.contract_basis_digest);
        encoder.u64(self.pinned_generations.len() as u64);
        for gen_id in &self.pinned_generations {
            encoder.text(gen_id);
        }
    }
}

impl CanonicalDecode for ClaimScopeTuple {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let target_triple = decoder.text()?.to_owned();
        let source_commit = decoder.text()?.to_owned();
        let sibling_closure_digest = decoder.digest()?;
        let toolchain = decoder.text()?.to_owned();
        let contract_basis_digest = decoder.digest()?;
        let count = decoder.u64()? as usize;
        if count > 512 {
            return Err(ContractError::InvalidIdentifier);
        }
        let mut pinned_generations = Vec::with_capacity(count);
        for _ in 0..count {
            pinned_generations.push(decoder.text()?.to_owned());
        }
        Ok(Self {
            target_triple,
            source_commit,
            sibling_closure_digest,
            toolchain,
            contract_basis_digest,
            pinned_generations,
        })
    }
}

/// One retained qualification/proof receipt supplied as evidence for a public claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimEvidenceRecord {
    /// Stable receipt identifier.
    pub receipt_id: String,
    /// Registered lane identity (e.g. `QL-MEDIA-001`, `QL-PERF-001`).
    pub lane_id: String,
    /// Exact content digest of the retained receipt bundle.
    pub receipt_digest: ContentDigest,
    /// Exact scope tuple attested by this receipt.
    pub scope: ClaimScopeTuple,
    /// Highest readiness level this receipt class is authorized to support.
    pub supported_level: ClaimReadinessLevel,
    /// Typed execution status of the lane run.
    pub status: EvidenceReceiptStatus,
    /// Timestamp when the receipt was sealed.
    pub issued_at_ns: TimestampNs,
    /// Exclusive expiry timestamp (`now_ns >= expires_at_ns` is expired).
    pub expires_at_ns: TimestampNs,
}

/// Explicit exclusion rule preventing a claim from being certified over unsupported/excluded scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimExclusionRule {
    /// Stable exclusion identifier (e.g. `EXCL-NONGOAL-013`, `EXCL-PYTORCH-UNAVAILABLE`).
    pub exclusion_id: String,
    /// Optional exact target triple filter (`None` applies to all targets).
    pub target_triple: Option<String>,
    /// Optional generation identifier filter (`None` applies regardless of generation).
    pub generation_id: Option<String>,
    /// Human-readable reason explaining the exclusion.
    pub reason: String,
}

/// One typed defect explaining why a claim could not be certified and how to repair it.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ClaimDefect {
    /// Stable error code conforming to `registries/ERRORS.md` style.
    pub code: String,
    /// Subject identifier (lane ID, receipt ID, exclusion ID, or generation ID).
    pub subject: String,
    /// Deterministic explanation without secrets or raw private media.
    pub detail: String,
    /// Safe recovery/remediation action.
    pub guidance: String,
}

impl CanonicalEncode for ClaimDefect {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.code);
        encoder.text(&self.subject);
        encoder.text(&self.detail);
        encoder.text(&self.guidance);
    }
}

impl CanonicalDecode for ClaimDefect {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        Ok(Self {
            code: decoder.text()?.to_owned(),
            subject: decoder.text()?.to_owned(),
            detail: decoder.text()?.to_owned(),
            guidance: decoder.text()?.to_owned(),
        })
    }
}

/// Complete request to evaluate one public claim against retained evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicClaimEvaluationRequest {
    /// Stable public claim identifier (e.g. `CLAIM-MEDIA-H264-LOCAL-001`).
    pub claim_id: String,
    /// Readiness level requested by the public status/matrix surface.
    pub requested_level: ClaimReadinessLevel,
    /// Exact scope tuple the public claim purports to cover.
    pub scope: ClaimScopeTuple,
    /// Registered qualification lanes whose fresh passing receipts are mandatory.
    pub required_lanes: Vec<String>,
    /// Retained evidence receipts available for evaluation.
    pub evidence: Vec<ClaimEvidenceRecord>,
    /// Explicit exclusions active for this claim or release channel.
    pub exclusions: Vec<ClaimExclusionRule>,
    /// Tombstoned or superseded generation IDs that must be refused fail-closed.
    pub tombstoned_generations: Vec<String>,
    /// Caller-supplied evaluation timestamp (sans-IO; no ambient clock reads).
    pub evaluated_at_ns: TimestampNs,
}

/// Deterministic, content-addressed evaluation receipt produced by [`evaluate_public_claim`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimEvaluationReceipt {
    /// Format version (`CLAIM_EVALUATION_FORMAT_VERSION`).
    pub format_version: u32,
    /// Stable evaluated claim identifier.
    pub claim_id: String,
    /// Level requested by the caller.
    pub requested_level: ClaimReadinessLevel,
    /// Effective level actually supported (downgraded to `Declared` on any non-certified verdict).
    pub effective_level: ClaimReadinessLevel,
    /// Exact non-collapsed verdict.
    pub verdict: ClaimEvaluationVerdict,
    /// Exact evaluated scope tuple.
    pub scope: ClaimScopeTuple,
    /// Evaluation timestamp supplied by caller.
    pub evaluated_at_ns: TimestampNs,
    /// Tightest expiry bound across all verified required receipts (`None` if non-certified or `Declared`).
    pub valid_until_ns: Option<TimestampNs>,
    /// Sorted content digests of verified receipts backing the verdict.
    pub verified_receipt_digests: Vec<ContentDigest>,
    /// Sorted exclusion IDs matched during evaluation.
    pub matched_exclusions: Vec<String>,
    /// Sorted typed defects and safe repair guidance (empty iff `Certified`).
    pub defects: Vec<ClaimDefect>,
    /// Domain-separated SHA-256 content digest over all fields above.
    pub receipt_digest: ContentDigest,
}

impl ClaimEvaluationReceipt {
    /// Recomputes the exact domain-separated SHA-256 receipt digest over all fields.
    #[must_use]
    pub fn computed_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(CLAIM_EVALUATION_RECEIPT_DOMAIN);
        encoder.u32(self.format_version);
        encoder.text(&self.claim_id);
        self.requested_level.encode_canonical(&mut encoder);
        self.effective_level.encode_canonical(&mut encoder);
        self.verdict.encode_canonical(&mut encoder);
        self.scope.encode_canonical(&mut encoder);
        encoder.i128(self.evaluated_at_ns.0);
        match self.valid_until_ns {
            Some(ts) => {
                encoder.u8(1);
                encoder.i128(ts.0);
            }
            None => encoder.u8(0),
        }
        encoder.u64(self.verified_receipt_digests.len() as u64);
        for digest in &self.verified_receipt_digests {
            encoder.digest(*digest);
        }
        encoder.u64(self.matched_exclusions.len() as u64);
        for excl in &self.matched_exclusions {
            encoder.text(excl);
        }
        encoder.u64(self.defects.len() as u64);
        for defect in &self.defects {
            defect.encode_canonical(&mut encoder);
        }
        ContentDigest::sha256(&encoder.finish())
    }

    /// Returns `true` iff `receipt_digest` matches [`Self::computed_digest`].
    #[must_use]
    pub fn verify_digest(&self) -> bool {
        self.receipt_digest == self.computed_digest()
    }
}

impl CanonicalEncode for ClaimEvaluationReceipt {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u32(self.format_version);
        encoder.text(&self.claim_id);
        self.requested_level.encode_canonical(encoder);
        self.effective_level.encode_canonical(encoder);
        self.verdict.encode_canonical(encoder);
        self.scope.encode_canonical(encoder);
        encoder.i128(self.evaluated_at_ns.0);
        match self.valid_until_ns {
            Some(ts) => {
                encoder.u8(1);
                encoder.i128(ts.0);
            }
            None => encoder.u8(0),
        }
        encoder.u64(self.verified_receipt_digests.len() as u64);
        for digest in &self.verified_receipt_digests {
            encoder.digest(*digest);
        }
        encoder.u64(self.matched_exclusions.len() as u64);
        for excl in &self.matched_exclusions {
            encoder.text(excl);
        }
        encoder.u64(self.defects.len() as u64);
        for defect in &self.defects {
            defect.encode_canonical(encoder);
        }
        encoder.digest(self.receipt_digest);
    }
}

impl CanonicalDecode for ClaimEvaluationReceipt {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let format_version = decoder.u32()?;
        if format_version != CLAIM_EVALUATION_FORMAT_VERSION {
            return Err(ContractError::InvalidIdentifier);
        }
        let claim_id = decoder.text()?.to_owned();
        let requested_level = ClaimReadinessLevel::decode_canonical(decoder)?;
        let effective_level = ClaimReadinessLevel::decode_canonical(decoder)?;
        let verdict = ClaimEvaluationVerdict::decode_canonical(decoder)?;
        let scope = ClaimScopeTuple::decode_canonical(decoder)?;
        let evaluated_at_ns = TimestampNs(decoder.i128()?);
        let valid_until_ns = match decoder.u8()? {
            0 => None,
            1 => Some(TimestampNs(decoder.i128()?)),
            _ => return Err(ContractError::InvalidIdentifier),
        };
        let digest_count = decoder.u64()? as usize;
        if digest_count > 4096 {
            return Err(ContractError::InvalidIdentifier);
        }
        let mut verified_receipt_digests = Vec::with_capacity(digest_count);
        for _ in 0..digest_count {
            verified_receipt_digests.push(decoder.digest()?);
        }
        let excl_count = decoder.u64()? as usize;
        if excl_count > 1024 {
            return Err(ContractError::InvalidIdentifier);
        }
        let mut matched_exclusions = Vec::with_capacity(excl_count);
        for _ in 0..excl_count {
            matched_exclusions.push(decoder.text()?.to_owned());
        }
        let defect_count = decoder.u64()? as usize;
        if defect_count > 4096 {
            return Err(ContractError::InvalidIdentifier);
        }
        let mut defects = Vec::with_capacity(defect_count);
        for _ in 0..defect_count {
            defects.push(ClaimDefect::decode_canonical(decoder)?);
        }
        let receipt_digest = decoder.digest()?;
        let receipt = Self {
            format_version,
            claim_id,
            requested_level,
            effective_level,
            verdict,
            scope,
            evaluated_at_ns,
            valid_until_ns,
            verified_receipt_digests,
            matched_exclusions,
            defects,
            receipt_digest,
        };
        if !receipt.verify_digest() {
            return Err(ContractError::InvalidIdentifier);
        }
        // Fail closed on structurally self-contradictory receipts even if SHA-256 was recomputed.
        let limits = ClaimEvaluationLimits::default();
        if validate_identifier(&receipt.claim_id, "claim_id", limits.max_text_bytes).is_err()
            || validate_scope(&receipt.scope, limits).is_err()
        {
            return Err(ContractError::InvalidIdentifier);
        }
        if receipt.verdict == ClaimEvaluationVerdict::Certified {
            if !receipt.defects.is_empty()
                || !receipt.matched_exclusions.is_empty()
                || receipt.effective_level != receipt.requested_level
            {
                return Err(ContractError::InvalidIdentifier);
            }
        } else if receipt.effective_level != ClaimReadinessLevel::Declared
            || receipt.valid_until_ns.is_some()
        {
            return Err(ContractError::InvalidIdentifier);
        }
        if !receipt
            .verified_receipt_digests
            .windows(2)
            .all(|w| w[0] < w[1])
            || !receipt.matched_exclusions.windows(2).all(|w| w[0] < w[1])
            || !receipt.defects.windows(2).all(|w| w[0] < w[1])
        {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(receipt)
    }
}

fn validate_identifier(
    value: &str,
    field: &'static str,
    max_bytes: usize,
) -> Result<(), ClaimEvaluatorError> {
    if value.is_empty() || value.len() > max_bytes {
        return Err(ClaimEvaluatorError::InvalidInput(field));
    }
    if value
        .bytes()
        .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
    {
        return Err(ClaimEvaluatorError::InvalidInput(field));
    }
    Ok(())
}

fn validate_text(
    value: &str,
    field: &'static str,
    max_bytes: usize,
) -> Result<(), ClaimEvaluatorError> {
    if value.is_empty() || value.len() > max_bytes || value.bytes().any(|b| b.is_ascii_control()) {
        return Err(ClaimEvaluatorError::InvalidInput(field));
    }
    Ok(())
}

fn is_forbidden_alias(gen_id: &str) -> bool {
    if gen_id
        .split(['-', '_', ':', '/', '@', '.', '+'])
        .any(|token| token.eq_ignore_ascii_case("latest"))
    {
        return true;
    }
    if FORBIDDEN_SUFFIX_ALIASES
        .iter()
        .any(|alias| gen_id.eq_ignore_ascii_case(alias))
    {
        return true;
    }
    let last_ref_segment = gen_id.rsplit([':', '@', '/']).next().unwrap_or("");
    FORBIDDEN_SUFFIX_ALIASES
        .iter()
        .any(|alias| last_ref_segment.eq_ignore_ascii_case(alias))
}

fn validate_scope(
    scope: &ClaimScopeTuple,
    limits: ClaimEvaluationLimits,
) -> Result<(), ClaimEvaluatorError> {
    validate_identifier(&scope.target_triple, "target_triple", limits.max_text_bytes)?;
    validate_identifier(&scope.source_commit, "source_commit", limits.max_text_bytes)?;
    validate_identifier(&scope.toolchain, "toolchain", limits.max_text_bytes)?;
    if scope.pinned_generations.len() > limits.max_tombstones {
        return Err(ClaimEvaluatorError::LimitExceeded("pinned_generations"));
    }
    for gen_id in &scope.pinned_generations {
        validate_identifier(gen_id, "pinned_generation", limits.max_text_bytes)?;
    }
    Ok(())
}

/// Evaluates one public claim against its exact scope, retained evidence receipts, explicit
/// exclusions, tombstoned/superseded generations, and expiry window (`FSS-195`).
pub fn evaluate_public_claim(
    request: &PublicClaimEvaluationRequest,
    limits: ClaimEvaluationLimits,
    mut is_cancelled: impl FnMut() -> bool,
) -> Result<ClaimEvaluationReceipt, ClaimEvaluatorError> {
    limits.validate()?;
    if is_cancelled() {
        return Err(ClaimEvaluatorError::Cancelled);
    }

    validate_identifier(&request.claim_id, "claim_id", limits.max_text_bytes)?;
    validate_scope(&request.scope, limits)?;

    if request.required_lanes.len() > limits.max_required_lanes {
        return Err(ClaimEvaluatorError::LimitExceeded("required_lanes"));
    }
    if request.evidence.len() > limits.max_receipts {
        return Err(ClaimEvaluatorError::LimitExceeded("evidence_receipts"));
    }
    if request.exclusions.len() > limits.max_exclusions {
        return Err(ClaimEvaluatorError::LimitExceeded("exclusions"));
    }
    if request.tombstoned_generations.len() > limits.max_tombstones {
        return Err(ClaimEvaluatorError::LimitExceeded("tombstoned_generations"));
    }

    let mut required_lanes = BTreeSet::new();
    for lane in &request.required_lanes {
        validate_identifier(lane, "required_lane", limits.max_text_bytes)?;
        required_lanes.insert(lane.clone());
    }
    if request.requested_level > ClaimReadinessLevel::Declared && required_lanes.is_empty() {
        return Err(ClaimEvaluatorError::InvalidInput(
            "promoted_claim_requires_at_least_one_lane",
        ));
    }

    let mut tombstones = BTreeSet::new();
    for tomb in &request.tombstoned_generations {
        validate_identifier(tomb, "tombstoned_generation", limits.max_text_bytes)?;
        tombstones.insert(tomb.to_ascii_lowercase());
    }

    for excl in &request.exclusions {
        validate_identifier(&excl.exclusion_id, "exclusion_id", limits.max_text_bytes)?;
        validate_text(&excl.reason, "exclusion_reason", limits.max_text_bytes)?;
        if let Some(target) = &excl.target_triple {
            validate_identifier(target, "exclusion_target_triple", limits.max_text_bytes)?;
        }
        if let Some(gen_id) = &excl.generation_id {
            validate_identifier(gen_id, "exclusion_generation_id", limits.max_text_bytes)?;
        }
    }

    let mut seen_receipt_ids: BTreeMap<&str, (&ContentDigest, EvidenceReceiptStatus)> =
        BTreeMap::new();
    for rec in &request.evidence {
        if is_cancelled() {
            return Err(ClaimEvaluatorError::Cancelled);
        }
        validate_identifier(&rec.receipt_id, "receipt_id", limits.max_text_bytes)?;
        validate_identifier(&rec.lane_id, "lane_id", limits.max_text_bytes)?;
        validate_scope(&rec.scope, limits)?;
        if rec.issued_at_ns.0 >= rec.expires_at_ns.0 {
            return Err(ClaimEvaluatorError::InvalidInput("inverted_receipt_window"));
        }
        if let Some((prev_digest, prev_status)) = seen_receipt_ids.get(rec.receipt_id.as_str())
            && (*prev_digest != &rec.receipt_digest || *prev_status != rec.status)
        {
            return Err(ClaimEvaluatorError::InvalidInput(
                "conflicting_duplicate_receipt_id",
            ));
        }
        seen_receipt_ids.insert(&rec.receipt_id, (&rec.receipt_digest, rec.status));
    }

    let mut defects: Vec<ClaimDefect> = Vec::new();
    let mut matched_exclusions: BTreeSet<String> = BTreeSet::new();
    let mut has_stale_gen = false;
    let mut has_scope_mismatch = false;
    let mut has_expired = false;
    let mut has_indeterminate = false;
    let mut has_insufficient = false;

    // 1. Stale/tombstoned or forbidden mutable alias check on claim scope generations.
    for gen_id in &request.scope.pinned_generations {
        if is_forbidden_alias(gen_id) || tombstones.contains(&gen_id.to_ascii_lowercase()) {
            has_stale_gen = true;
            defects.push(ClaimDefect {
                code: "ERR-CLAIM-PROOF-STALE-GENERATION-001".to_owned(),
                subject: gen_id.clone(),
                detail: format!(
                    "claim scope references tombstoned or forbidden mutable generation '{gen_id}'"
                ),
                guidance: "pin an immutable active generation and re-run qualification".to_owned(),
            });
        }
    }
    if is_forbidden_alias(&request.scope.toolchain) {
        has_stale_gen = true;
        defects.push(ClaimDefect {
            code: "ERR-CLAIM-PROOF-STALE-GENERATION-001".to_owned(),
            subject: request.scope.toolchain.clone(),
            detail: "claim scope toolchain uses a forbidden mutable alias".to_owned(),
            guidance: "pin an exact dated nightly toolchain channel".to_owned(),
        });
    }
    if is_forbidden_alias(&request.scope.source_commit) {
        has_stale_gen = true;
        defects.push(ClaimDefect {
            code: "ERR-CLAIM-PROOF-STALE-GENERATION-001".to_owned(),
            subject: request.scope.source_commit.clone(),
            detail: "claim scope source_commit uses a forbidden mutable ref alias".to_owned(),
            guidance: "pin an immutable exact commit digest".to_owned(),
        });
    }

    // 2. Explicit exclusion evaluation (exclusions always block certification).
    for excl in &request.exclusions {
        let target_matches = excl
            .target_triple
            .as_deref()
            .is_none_or(|t| t == request.scope.target_triple);
        let gen_matches = excl.generation_id.as_deref().is_none_or(|g| {
            request
                .scope
                .pinned_generations
                .iter()
                .any(|pg| pg.eq_ignore_ascii_case(g))
        });
        if target_matches && gen_matches {
            matched_exclusions.insert(excl.exclusion_id.clone());
            defects.push(ClaimDefect {
                code: "ERR-CLAIM-EXCLUDED-001".to_owned(),
                subject: excl.exclusion_id.clone(),
                detail: excl.reason.clone(),
                guidance: "preserve explicit exclusion in public matrix until scope is implemented and qualified".to_owned(),
            });
        }
    }

    // 3. Evaluate retained evidence per required lane.
    let mut verified_digests: BTreeSet<ContentDigest> = BTreeSet::new();
    let mut tightest_expiry: Option<TimestampNs> = None;

    if request.requested_level > ClaimReadinessLevel::Declared {
        for lane in &required_lanes {
            if is_cancelled() {
                return Err(ClaimEvaluatorError::Cancelled);
            }
            let lane_records: Vec<&ClaimEvidenceRecord> = request
                .evidence
                .iter()
                .filter(|r| r.lane_id == *lane)
                .collect();

            if lane_records.is_empty() {
                has_insufficient = true;
                defects.push(ClaimDefect {
                    code: "ERR-CLAIM-PROOF-BUNDLE-NOT-FOUND-001".to_owned(),
                    subject: lane.clone(),
                    detail: format!("no retained receipt found for required lane '{lane}'"),
                    guidance: format!(
                        "execute lane {lane} on the exact target tuple and retain its receipt"
                    ),
                });
                continue;
            }

            let mut lane_verified = false;
            let mut lane_had_pass = false;
            let mut lane_had_non_pass = false;
            let mut lane_verified_digests: Vec<ContentDigest> = Vec::new();
            let mut lane_tightest_expiry: Option<TimestampNs> = None;

            for rec in lane_records {
                if is_cancelled() {
                    return Err(ClaimEvaluatorError::Cancelled);
                }
                // Check receipt generation and mutable-alias hygiene first.
                let mut rec_stale = false;
                for gen_id in &rec.scope.pinned_generations {
                    if is_forbidden_alias(gen_id)
                        || tombstones.contains(&gen_id.to_ascii_lowercase())
                    {
                        rec_stale = true;
                        has_stale_gen = true;
                        defects.push(ClaimDefect {
                            code: "ERR-CLAIM-PROOF-STALE-GENERATION-001".to_owned(),
                            subject: rec.receipt_id.clone(),
                            detail: format!(
                                "receipt references stale/forbidden generation '{gen_id}'"
                            ),
                            guidance: "re-qualify against active immutable generations".to_owned(),
                        });
                    }
                }
                if is_forbidden_alias(&rec.scope.toolchain)
                    || is_forbidden_alias(&rec.scope.source_commit)
                {
                    rec_stale = true;
                    has_stale_gen = true;
                    defects.push(ClaimDefect {
                        code: "ERR-CLAIM-PROOF-STALE-GENERATION-001".to_owned(),
                        subject: rec.receipt_id.clone(),
                        detail: "receipt scope uses a forbidden mutable toolchain or commit alias"
                            .to_owned(),
                        guidance: "re-qualify with pinned immutable toolchain and commit"
                            .to_owned(),
                    });
                }
                if rec_stale {
                    continue;
                }

                // Exact scope match check.
                if rec.scope != request.scope {
                    has_scope_mismatch = true;
                    defects.push(ClaimDefect {
                        code: "ERR-CLAIM-SCOPE-MISMATCH-001".to_owned(),
                        subject: rec.receipt_id.clone(),
                        detail: format!(
                            "receipt scope ({}/{}/{}) disagrees with claim scope ({}/{}/{})",
                            rec.scope.target_triple,
                            rec.scope.source_commit,
                            rec.scope.toolchain,
                            request.scope.target_triple,
                            request.scope.source_commit,
                            request.scope.toolchain,
                        ),
                        guidance: "re-run the lane on the exact declared source/sibling/toolchain/target tuple".to_owned(),
                    });
                    continue;
                }

                // Status checks (never coerce skipped/partial/unavailable/failed/indeterminate into pass).
                match rec.status {
                    EvidenceReceiptStatus::Passed => {
                        lane_had_pass = true;
                    }
                    EvidenceReceiptStatus::Indeterminate => {
                        lane_had_non_pass = true;
                        has_indeterminate = true;
                        defects.push(ClaimDefect {
                            code: "ERR-CLAIM-INDETERMINATE-001".to_owned(),
                            subject: rec.receipt_id.clone(),
                            detail: format!(
                                "receipt for lane '{lane}' ended in indeterminate state"
                            ),
                            guidance: "reconcile indeterminate execution and re-run lane cleanly"
                                .to_owned(),
                        });
                        continue;
                    }
                    other => {
                        lane_had_non_pass = true;
                        has_insufficient = true;
                        defects.push(ClaimDefect {
                            code: "ERR-CLAIM-PROOF-LEVEL-EXCEEDED-001".to_owned(),
                            subject: rec.receipt_id.clone(),
                            detail: format!(
                                "receipt for lane '{lane}' has non-passing status '{}'",
                                other.as_str()
                            ),
                            guidance: "repair the failing/skipped/unavailable lane check and retain a passing receipt".to_owned(),
                        });
                        continue;
                    }
                }

                // Expiry check (`now >= expires_at` is expired; future-issued receipt is invalid/expired).
                if request.evaluated_at_ns.0 >= rec.expires_at_ns.0
                    || request.evaluated_at_ns.0 < rec.issued_at_ns.0
                {
                    has_expired = true;
                    defects.push(ClaimDefect {
                        code: "ERR-CLAIM-EXPIRED-001".to_owned(),
                        subject: rec.receipt_id.clone(),
                        detail: format!(
                            "receipt for lane '{lane}' is outside validity window [{}..{}) at {}",
                            rec.issued_at_ns.0, rec.expires_at_ns.0, request.evaluated_at_ns.0
                        ),
                        guidance: "re-execute the lane to mint a fresh non-expired receipt"
                            .to_owned(),
                    });
                    continue;
                }

                // Readiness level bound check.
                if rec.supported_level < request.requested_level {
                    has_insufficient = true;
                    defects.push(ClaimDefect {
                        code: "ERR-CLAIM-PROOF-LEVEL-EXCEEDED-001".to_owned(),
                        subject: rec.receipt_id.clone(),
                        detail: format!(
                            "receipt supports '{}' which is below requested '{}'",
                            rec.supported_level.as_str(),
                            request.requested_level.as_str()
                        ),
                        guidance:
                            "lower the public claim level or execute full matrix qualification"
                                .to_owned(),
                    });
                    continue;
                }

                lane_verified = true;
                lane_verified_digests.push(rec.receipt_digest);
                lane_tightest_expiry = Some(match lane_tightest_expiry {
                    Some(prev) if prev.0 <= rec.expires_at_ns.0 => prev,
                    _ => rec.expires_at_ns,
                });
            }

            if lane_had_pass && lane_had_non_pass {
                has_indeterminate = true;
                defects.push(ClaimDefect {
                    code: "ERR-CLAIM-CONFLICTING-EVIDENCE-001".to_owned(),
                    subject: lane.clone(),
                    detail: format!(
                        "lane '{lane}' carries both passing and non-passing receipts for the same scope"
                    ),
                    guidance: "quarantine conflicting receipts and re-run from a clean snapshot".to_owned(),
                });
            } else if lane_verified {
                for digest in lane_verified_digests {
                    verified_digests.insert(digest);
                }
                if let Some(lane_exp) = lane_tightest_expiry {
                    tightest_expiry = Some(match tightest_expiry {
                        Some(prev) if prev.0 <= lane_exp.0 => prev,
                        _ => lane_exp,
                    });
                }
            } else if !has_scope_mismatch && !has_expired && !has_stale_gen && !has_indeterminate {
                has_insufficient = true;
            }
        }
    }

    if is_cancelled() {
        return Err(ClaimEvaluatorError::Cancelled);
    }

    defects.sort();
    defects.dedup();

    // Deterministic priority ordering for non-collapsed verdict selection.
    let verdict = if !matched_exclusions.is_empty() {
        ClaimEvaluationVerdict::Excluded
    } else if has_stale_gen {
        ClaimEvaluationVerdict::StaleGeneration
    } else if has_indeterminate {
        ClaimEvaluationVerdict::Indeterminate
    } else if has_scope_mismatch {
        ClaimEvaluationVerdict::ScopeMismatch
    } else if has_expired {
        ClaimEvaluationVerdict::Expired
    } else if has_insufficient || !defects.is_empty() {
        ClaimEvaluationVerdict::InsufficientEvidence
    } else {
        ClaimEvaluationVerdict::Certified
    };

    let effective_level = if verdict == ClaimEvaluationVerdict::Certified {
        request.requested_level
    } else {
        ClaimReadinessLevel::Declared
    };
    let valid_until_ns = if verdict == ClaimEvaluationVerdict::Certified {
        tightest_expiry
    } else {
        None
    };

    let mut receipt = ClaimEvaluationReceipt {
        format_version: CLAIM_EVALUATION_FORMAT_VERSION,
        claim_id: request.claim_id.clone(),
        requested_level: request.requested_level,
        effective_level,
        verdict,
        scope: request.scope.clone(),
        evaluated_at_ns: request.evaluated_at_ns,
        valid_until_ns,
        verified_receipt_digests: verified_digests.into_iter().collect(),
        matched_exclusions: matched_exclusions.into_iter().collect(),
        defects,
        receipt_digest: ContentDigest::sha256(b"pending"),
    };
    receipt.receipt_digest = receipt.computed_digest();
    Ok(receipt)
}

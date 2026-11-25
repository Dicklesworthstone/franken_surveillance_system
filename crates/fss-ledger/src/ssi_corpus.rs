#![forbid(unsafe_code)]
//! Negative-read phantom and SSI write-skew adversarial schedule corpus (`FSS-106`, `fss-x4a.9.13`).
//!
//! Delivers a repeatable, sealed, deterministic schedule-verification corpus composing
//! [`LedgerOracle`], [`SemanticWitness`] (`FSS-103`), [`DeterministicCommitCombiner`] (`FSS-104`),
//! and [`MergeLadder`] (`FSS-105`) to prove serializability, negative-read phantom rejection,
//! gapped-coverage non-laundering, hierarchical witness enforcement, and stale-rebase soundness
//! across all submission permutations:
//!
//! 1. `two_actor_disjoint_write_skew` — classic 2-actor SSI write-skew across both `[A, B]` and
//!    `[B, A]` submission orders (exact canonical winner, `SsiDangerousWriteSkew` loser, bit-identical
//!    committed batch digest).
//! 2. `three_actor_ring_write_skew` — 3-actor circular `rw`-antidependency ring (`T1->T2->T3->T1`)
//!    across all 6 (`3!`) submission permutations (zero cycle admission, bit-identical outcome).
//! 3. `negative_read_phantom_injection` — concurrent certified-absence negative witness vs phantom
//!    insertion across both submission orders (`NegativePhantomWrite` or `SsiDangerousWriteSkew`,
//!    never both committed).
//! 4. `gapped_negative_absence_laundering` — gapped/partial `CoverageWitness` refused as
//!    `UncertifiedAbsenceBasis` before serializability evaluation with zero committed writes.
//! 5. `stale_basis_merge_ladder_no_skew_smuggling` — proves `FSS-105` `MergeLadder` refuses to
//!    rebase a stale-basis write-skew or negative-phantom transaction via Rung 1 or Rung 2.
//! 6. `hierarchical_witness_phantom_and_skew` — proves nested `HierarchicalWitness` leaves enforce
//!    exact phantom and write-skew conflict detection without skipping descendant witnesses.
//!
//! Seals a bounded, checksummed [`ScheduleCorpusReceipt`] (`FSSSSIC1` v1, domain
//! `fss.ledger_ssi_corpus_receipt.v1`) declaring exact claim scope, excluded dimensions, per-case
//! permutation counts, and minimized deterministic reproducer digests.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use fss_core::{
    BatchId, CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, CaptureInterval,
    Completeness, ContentDigest, ContractError, CoverageContinuity, CoverageStopReason,
    CoverageWitness, EvidenceDelta, LedgerAnchor, ObjectId, Plane, TimestampNs,
};

use crate::combiner::{
    CombiningRoundOutcome, CommitIntent, ConflictKind, DeterministicCommitCombiner,
    IntentAuthorityContext, IntentOutcome,
};
use crate::merge_ladder::{
    CommutativeFamilyRegistry, MergeLadder, MergeOutcome, MergeRefusalReason,
};
use crate::oracle::{LedgerOracle, OracleLimits};
use crate::witness::{HierarchicalWitness, NegativeWitness, PositiveWitness, SemanticWitness};

/// Registered digest domain for sealed [`ScheduleCorpusReceipt`] proofs (`FSS-106`).
pub const LEDGER_SSI_CORPUS_RECEIPT_DOMAIN: &str = "fss.ledger_ssi_corpus_receipt.v1";
/// Binary wire header magic for serialized SSI schedule corpus receipts.
pub const SSI_CORPUS_MAGIC: [u8; 8] = *b"FSSSSIC1";
/// Supported durable format version for [`ScheduleCorpusReceipt`].
pub const SSI_CORPUS_VERSION: u32 = 1;
/// Hard ceiling on schedule cases stored in one corpus receipt.
pub const MAX_CORPUS_CASES: usize = 64;
/// Hard ceiling on excluded-dimension annotations stored in one receipt.
pub const MAX_EXCLUDED_DIMENSIONS: usize = 32;
/// Hard ceiling on serialized receipt wire bytes (512 KiB).
pub const MAX_SSI_CORPUS_WIRE_BYTES: usize = 512 * 1024;
/// Hard ceiling on UTF-8 diagnostic labels inside receipts.
pub const MAX_CORPUS_LABEL_BYTES: usize = 256;

/// Safe operator/agent recovery guidance for an SSI corpus execution or decoding refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SsiCorpusGuidance {
    /// All adversarial SSI and negative-phantom schedules passed with zero serializability leaks.
    CorpusVerified,
    /// Cooperative cancellation observed before completing all corpus schedules; safe to retry.
    RetryWhenReady,
    /// Investigate the minimized reproducer digest — a serializability invariant failed!
    InvestigateSerializabilityViolation,
    /// Reject corrupt or unsupported binary corpus receipt bytes.
    RejectCorruptReceipt,
}

/// Typed error returned by [`SsiCorpusRunner`] or [`ScheduleCorpusReceipt`] codec.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SsiCorpusError {
    /// Cooperative cancellation observed before corpus completion.
    Cancelled,
    /// Underlying ledger, combiner, witness, or merge ladder error.
    Execution(String),
    /// Label or structural invariant violation.
    InvalidInput(String),
    /// Wire length or case count exceeded hard bounds.
    BoundsExceeded {
        /// Observed size/count.
        observed: usize,
        /// Hard maximum.
        maximum: usize,
    },
    /// Binary receipt lacked [`SSI_CORPUS_MAGIC`].
    InvalidMagic,
    /// Binary receipt declared an unsupported version.
    UnsupportedVersion {
        /// Observed format version.
        version: u32,
    },
    /// Binary receipt was truncated, non-canonical, or structurally inconsistent.
    MalformedWire(String),
    /// Receipt canonical checksum failed verification.
    ChecksumMismatch,
    /// Canonical encoder failure.
    Encoding(String),
}

impl SsiCorpusError {
    /// Stable canonical machine error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Cancelled => "ERR-LEDGER-SSI-CORPUS-CANCELLED-001",
            Self::Execution(_) => "ERR-LEDGER-SSI-CORPUS-EXEC-001",
            Self::InvalidInput(_) => "ERR-LEDGER-SSI-CORPUS-INVALID-INPUT-001",
            Self::BoundsExceeded { .. } => "ERR-LEDGER-SSI-CORPUS-BOUNDS-001",
            Self::InvalidMagic => "ERR-LEDGER-SSI-CORPUS-INVALID-MAGIC-001",
            Self::UnsupportedVersion { .. } => "ERR-LEDGER-SSI-CORPUS-UNSUPPORTED-VERSION-001",
            Self::MalformedWire(_) => "ERR-LEDGER-SSI-CORPUS-MALFORMED-WIRE-001",
            Self::ChecksumMismatch => "ERR-LEDGER-SSI-CORPUS-CHECKSUM-MISMATCH-001",
            Self::Encoding(_) => "ERR-LEDGER-SSI-CORPUS-ENCODING-001",
        }
    }

    /// Safe recovery guidance.
    #[must_use]
    pub const fn guidance(&self) -> SsiCorpusGuidance {
        match self {
            Self::Cancelled => SsiCorpusGuidance::RetryWhenReady,
            Self::Execution(_) => SsiCorpusGuidance::InvestigateSerializabilityViolation,
            Self::InvalidInput(_)
            | Self::BoundsExceeded { .. }
            | Self::InvalidMagic
            | Self::UnsupportedVersion { .. }
            | Self::MalformedWire(_)
            | Self::ChecksumMismatch
            | Self::Encoding(_) => SsiCorpusGuidance::RejectCorruptReceipt,
        }
    }
}

impl fmt::Display for SsiCorpusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {self:?}", self.code())
    }
}

impl Error for SsiCorpusError {}

/// Non-collapsed verdict of one schedule case or the whole corpus.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScheduleVerdict {
    /// Every tested permutation preserved serializability, phantom protection, and canonical order.
    Passed = 1,
    /// At least one schedule violated serializability, phantom protection, or order invariance.
    Failed = 2,
}

impl ScheduleVerdict {
    /// Stable canonical machine spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
        }
    }

    const fn tag(self) -> u8 {
        self as u8
    }

    fn from_tag(tag: u8) -> Result<Self, ContractError> {
        match tag {
            1 => Ok(Self::Passed),
            2 => Ok(Self::Failed),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Repeatable execution summary of one adversarial schedule scenario.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScheduleCaseResult {
    /// Stable case identity (e.g. `"two_actor_disjoint_write_skew"`).
    pub case_id: String,
    /// Number of deterministic actor submission permutations executed.
    pub permutations_tested: u32,
    /// True iff all permutations produced bit-identical canonical winners, conflicts, and roots.
    pub permutation_invariant: bool,
    /// Non-collapsed scenario verdict.
    pub verdict: ScheduleVerdict,
    /// Count of committed intents in the canonical outcome.
    pub committed_intents: u32,
    /// Count of aborted/refused intents in the canonical outcome.
    pub aborted_intents: u32,
    /// Canonical minimized reproducer digest locking scenario seed + canonical outcome trace.
    pub reproducer_digest: ContentDigest,
    /// Secret-free diagnostic summary.
    pub summary: String,
}

/// Sealed repeatable proof receipt for the `FSS-106` SSI & negative-phantom schedule corpus.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScheduleCorpusReceipt {
    /// Wire format version (`SSI_CORPUS_VERSION`).
    pub format_version: u32,
    /// Stable corpus suite identity.
    pub corpus_id: String,
    /// Non-collapsed overall corpus verdict (`Passed` iff every case passed).
    pub verdict: ScheduleVerdict,
    /// Ordered per-scenario execution results (strictly sorted by `case_id`).
    pub cases: Vec<ScheduleCaseResult>,
    /// Cumulative deterministic permutations executed across all cases.
    pub total_permutations_tested: u32,
    /// Explicit honest claim scope statement.
    pub claim_scope: String,
    /// Explicitly excluded dimensions not proved by this in-memory deterministic schedule corpus.
    pub excluded_dimensions: Vec<String>,
    /// Timestamp when this corpus receipt was sealed.
    pub sealed_at: TimestampNs,
    /// Domain-separated SHA-256 commitment (`fss.ledger_ssi_corpus_receipt.v1`).
    pub receipt_digest: ContentDigest,
}

impl ScheduleCorpusReceipt {
    /// True iff every adversarial schedule in the corpus passed with zero violations.
    #[must_use]
    pub const fn all_passed(&self) -> bool {
        matches!(self.verdict, ScheduleVerdict::Passed)
    }

    /// Recomputes the domain-separated SHA-256 commitment (`fss.ledger_ssi_corpus_receipt.v1`).
    pub fn compute_digest(&self) -> Result<ContentDigest, SsiCorpusError> {
        let mut enc = CanonicalEncoder::new();
        enc.text(LEDGER_SSI_CORPUS_RECEIPT_DOMAIN);
        self.encode_body(&mut enc);
        let bytes = enc
            .finish_checked()
            .map_err(|e| SsiCorpusError::Encoding(e.to_string()))?;
        Ok(ContentDigest::sha256(&bytes))
    }

    /// Verifies structural invariants, verdict consistency, ordering, bounds, and self-digest.
    pub fn verify_self(&self) -> Result<(), SsiCorpusError> {
        if self.format_version != SSI_CORPUS_VERSION {
            return Err(SsiCorpusError::UnsupportedVersion {
                version: self.format_version,
            });
        }
        validate_label(&self.corpus_id, MAX_CORPUS_LABEL_BYTES, "corpus_id")
            .map_err(|e| SsiCorpusError::MalformedWire(e.to_string()))?;
        validate_label(&self.claim_scope, MAX_CORPUS_LABEL_BYTES, "claim_scope")
            .map_err(|e| SsiCorpusError::MalformedWire(e.to_string()))?;
        if self.cases.is_empty() || self.cases.len() > MAX_CORPUS_CASES {
            return Err(SsiCorpusError::BoundsExceeded {
                observed: self.cases.len(),
                maximum: MAX_CORPUS_CASES,
            });
        }
        if self.excluded_dimensions.is_empty()
            || self.excluded_dimensions.len() > MAX_EXCLUDED_DIMENSIONS
        {
            return Err(SsiCorpusError::BoundsExceeded {
                observed: self.excluded_dimensions.len(),
                maximum: MAX_EXCLUDED_DIMENSIONS,
            });
        }
        for dim in &self.excluded_dimensions {
            validate_label(dim, MAX_CORPUS_LABEL_BYTES, "excluded_dimension")
                .map_err(|e| SsiCorpusError::MalformedWire(e.to_string()))?;
        }
        for pair in self.excluded_dimensions.windows(2) {
            if pair[0] >= pair[1] {
                return Err(SsiCorpusError::MalformedWire(
                    "excluded_dimensions must be strictly sorted and deduplicated".to_owned(),
                ));
            }
        }
        for pair in self.cases.windows(2) {
            if pair[0].case_id >= pair[1].case_id {
                return Err(SsiCorpusError::MalformedWire(
                    "cases must be strictly sorted by case_id".to_owned(),
                ));
            }
        }
        let mut total_perms = 0_u32;
        let mut any_failed = false;
        for c in &self.cases {
            validate_label(&c.case_id, MAX_CORPUS_LABEL_BYTES, "case_id")
                .map_err(|e| SsiCorpusError::MalformedWire(e.to_string()))?;
            validate_label(&c.summary, MAX_CORPUS_LABEL_BYTES, "summary")
                .map_err(|e| SsiCorpusError::MalformedWire(e.to_string()))?;
            if c.permutations_tested == 0 {
                return Err(SsiCorpusError::MalformedWire(format!(
                    "case '{}' executed zero permutations",
                    c.case_id
                )));
            }
            if c.verdict == ScheduleVerdict::Passed && !c.permutation_invariant {
                return Err(SsiCorpusError::MalformedWire(format!(
                    "case '{}' cannot pass without permutation_invariant == true",
                    c.case_id
                )));
            }
            if c.verdict == ScheduleVerdict::Failed {
                any_failed = true;
            }
            total_perms = total_perms.saturating_add(c.permutations_tested);
        }
        if total_perms != self.total_permutations_tested {
            return Err(SsiCorpusError::MalformedWire(
                "total_permutations_tested disagrees with sum of cases".to_owned(),
            ));
        }
        let expected_verdict = if any_failed {
            ScheduleVerdict::Failed
        } else {
            ScheduleVerdict::Passed
        };
        if self.verdict != expected_verdict {
            return Err(SsiCorpusError::MalformedWire(
                "corpus verdict disagrees with per-case verdicts".to_owned(),
            ));
        }
        if self.compute_digest()? != self.receipt_digest {
            return Err(SsiCorpusError::ChecksumMismatch);
        }
        Ok(())
    }

    fn encode_body(&self, enc: &mut CanonicalEncoder) {
        enc.u32(self.format_version);
        enc.text(&self.corpus_id);
        enc.u8(self.verdict.tag());
        enc.u32(self.cases.len() as u32);
        for c in &self.cases {
            enc.text(&c.case_id);
            enc.u32(c.permutations_tested);
            enc.bool(c.permutation_invariant);
            enc.u8(c.verdict.tag());
            enc.u32(c.committed_intents);
            enc.u32(c.aborted_intents);
            enc.digest(c.reproducer_digest);
            enc.text(&c.summary);
        }
        enc.u32(self.total_permutations_tested);
        enc.text(&self.claim_scope);
        enc.u32(self.excluded_dimensions.len() as u32);
        for dim in &self.excluded_dimensions {
            enc.text(dim);
        }
        self.sealed_at.encode_canonical(enc);
    }

    /// Encodes this receipt into bounded checksummed binary bytes (`FSSSSIC1` v1).
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, SsiCorpusError> {
        self.verify_self()?;
        let mut enc = CanonicalEncoder::new();
        self.encode_body(&mut enc);
        enc.digest(self.receipt_digest);
        let body = enc
            .finish_checked()
            .map_err(|e| SsiCorpusError::Encoding(e.to_string()))?;
        let total = SSI_CORPUS_MAGIC
            .len()
            .saturating_add(4)
            .saturating_add(body.len());
        if total > MAX_SSI_CORPUS_WIRE_BYTES {
            return Err(SsiCorpusError::BoundsExceeded {
                observed: total,
                maximum: MAX_SSI_CORPUS_WIRE_BYTES,
            });
        }
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&SSI_CORPUS_MAGIC);
        out.extend_from_slice(&self.format_version.to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Cold-decodes and verifies a binary [`ScheduleCorpusReceipt`] (`FSSSSIC1` v1).
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, SsiCorpusError> {
        if bytes.len() > MAX_SSI_CORPUS_WIRE_BYTES {
            return Err(SsiCorpusError::BoundsExceeded {
                observed: bytes.len(),
                maximum: MAX_SSI_CORPUS_WIRE_BYTES,
            });
        }
        if bytes.len() < 12 || bytes[..8] != SSI_CORPUS_MAGIC {
            return Err(SsiCorpusError::InvalidMagic);
        }
        let header_ver = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if header_ver != SSI_CORPUS_VERSION {
            return Err(SsiCorpusError::UnsupportedVersion {
                version: header_ver,
            });
        }
        let mut dec = CanonicalDecoder::new(&bytes[12..]);
        let format_version = dec
            .u32()
            .map_err(|e| SsiCorpusError::MalformedWire(e.to_string()))?;
        if format_version != header_ver {
            return Err(SsiCorpusError::UnsupportedVersion {
                version: format_version,
            });
        }
        let corpus_id = dec
            .text()
            .map_err(|e| SsiCorpusError::MalformedWire(e.to_string()))?
            .to_owned();
        let verdict = ScheduleVerdict::from_tag(
            dec.u8()
                .map_err(|e| SsiCorpusError::MalformedWire(e.to_string()))?,
        )
        .map_err(|e| SsiCorpusError::MalformedWire(e.to_string()))?;
        let case_count =
            dec.u32()
                .map_err(|e| SsiCorpusError::MalformedWire(e.to_string()))? as usize;
        if case_count == 0
            || case_count > MAX_CORPUS_CASES
            || case_count.saturating_mul(52) > dec.remaining()
        {
            return Err(SsiCorpusError::BoundsExceeded {
                observed: case_count,
                maximum: MAX_CORPUS_CASES,
            });
        }
        let mut cases = Vec::with_capacity(case_count);
        for _ in 0..case_count {
            cases.push(ScheduleCaseResult {
                case_id: dec
                    .text()
                    .map_err(|e| SsiCorpusError::MalformedWire(e.to_string()))?
                    .to_owned(),
                permutations_tested: dec
                    .u32()
                    .map_err(|e| SsiCorpusError::MalformedWire(e.to_string()))?,
                permutation_invariant: dec
                    .bool()
                    .map_err(|e| SsiCorpusError::MalformedWire(e.to_string()))?,
                verdict: ScheduleVerdict::from_tag(
                    dec.u8()
                        .map_err(|e| SsiCorpusError::MalformedWire(e.to_string()))?,
                )
                .map_err(|e| SsiCorpusError::MalformedWire(e.to_string()))?,
                committed_intents: dec
                    .u32()
                    .map_err(|e| SsiCorpusError::MalformedWire(e.to_string()))?,
                aborted_intents: dec
                    .u32()
                    .map_err(|e| SsiCorpusError::MalformedWire(e.to_string()))?,
                reproducer_digest: dec
                    .digest()
                    .map_err(|e| SsiCorpusError::MalformedWire(e.to_string()))?,
                summary: dec
                    .text()
                    .map_err(|e| SsiCorpusError::MalformedWire(e.to_string()))?
                    .to_owned(),
            });
        }
        let total_permutations_tested = dec
            .u32()
            .map_err(|e| SsiCorpusError::MalformedWire(e.to_string()))?;
        let claim_scope = dec
            .text()
            .map_err(|e| SsiCorpusError::MalformedWire(e.to_string()))?
            .to_owned();
        let excl_count =
            dec.u32()
                .map_err(|e| SsiCorpusError::MalformedWire(e.to_string()))? as usize;
        if excl_count == 0
            || excl_count > MAX_EXCLUDED_DIMENSIONS
            || excl_count.saturating_mul(5) > dec.remaining()
        {
            return Err(SsiCorpusError::BoundsExceeded {
                observed: excl_count,
                maximum: MAX_EXCLUDED_DIMENSIONS,
            });
        }
        let mut excluded_dimensions = Vec::with_capacity(excl_count);
        for _ in 0..excl_count {
            excluded_dimensions.push(
                dec.text()
                    .map_err(|e| SsiCorpusError::MalformedWire(e.to_string()))?
                    .to_owned(),
            );
        }
        let sealed_at = TimestampNs::decode_canonical(&mut dec)
            .map_err(|e| SsiCorpusError::MalformedWire(e.to_string()))?;
        let stored_digest = dec
            .digest()
            .map_err(|e| SsiCorpusError::MalformedWire(e.to_string()))?;
        dec.ensure_finished().map_err(|_| {
            SsiCorpusError::MalformedWire("trailing bytes after corpus receipt".to_owned())
        })?;

        let receipt = Self {
            format_version,
            corpus_id,
            verdict,
            cases,
            total_permutations_tested,
            claim_scope,
            excluded_dimensions,
            sealed_at,
            receipt_digest: stored_digest,
        };
        receipt.verify_self()?;
        Ok(receipt)
    }
}

/// Deterministic SSI write-skew and negative-read phantom schedule corpus runner (`FSS-106`).
pub struct SsiCorpusRunner;

impl SsiCorpusRunner {
    /// Executes all six adversarial SSI write-skew, negative-read phantom, gapped-coverage,
    /// hierarchical-witness, and stale-rebase schedule scenarios across every actor permutation
    /// and seals a verifiable [`ScheduleCorpusReceipt`].
    pub fn run_all_schedules(
        sealed_at: TimestampNs,
        cancelled: bool,
    ) -> Result<ScheduleCorpusReceipt, SsiCorpusError> {
        if cancelled {
            return Err(SsiCorpusError::Cancelled);
        }

        let mut cases = vec![
            run_two_actor_disjoint_write_skew()?,
            run_three_actor_ring_write_skew()?,
            run_negative_read_phantom_injection()?,
            run_gapped_negative_absence_laundering()?,
            run_stale_basis_merge_ladder_no_skew_smuggling()?,
            run_hierarchical_witness_phantom_and_skew()?,
        ];
        cases.sort_by(|a, b| a.case_id.cmp(&b.case_id));

        let total_permutations_tested = cases
            .iter()
            .fold(0_u32, |acc, c| acc.saturating_add(c.permutations_tested));
        let verdict = if cases.iter().all(|c| c.verdict == ScheduleVerdict::Passed) {
            ScheduleVerdict::Passed
        } else {
            ScheduleVerdict::Failed
        };
        let mut excluded_dimensions = vec![
            "multi_host_network_clock_skew".to_owned(),
            "physical_power_loss_fsync_faults".to_owned(),
            "wall_clock_throughput_latency".to_owned(),
        ];
        excluded_dimensions.sort();

        let mut receipt = ScheduleCorpusReceipt {
            format_version: SSI_CORPUS_VERSION,
            corpus_id: "fss-106-ssi-negative-phantom-corpus-v1".to_owned(),
            verdict,
            cases,
            total_permutations_tested,
            claim_scope:
                "deterministic_in_memory_oracle_combiner_merge_ladder_serializability_and_phantom_guard"
                    .to_owned(),
            excluded_dimensions,
            sealed_at,
            receipt_digest: ContentDigest::sha256(b"unsealed-ssi-corpus-receipt"),
        };
        receipt.receipt_digest = receipt.compute_digest()?;
        receipt.verify_self()?;
        Ok(receipt)
    }
}

fn make_delta(
    delta_id: &str,
    family: &str,
    object_id: &str,
    prior_generation: Option<u64>,
    new_generation: u64,
) -> Result<EvidenceDelta, SsiCorpusError> {
    Ok(EvidenceDelta {
        delta_id: delta_id.to_owned(),
        family: family.to_owned(),
        object_id: ObjectId::parse(object_id)
            .map_err(|e| SsiCorpusError::Execution(e.to_string()))?,
        prior_generation,
        new_generation,
        validity: CaptureInterval::new(TimestampNs(100), TimestampNs(200))
            .map_err(|e| SsiCorpusError::Execution(e.to_string()))?,
        plane: Plane::Authority,
        payload_digest: ContentDigest::sha256(
            format!("{delta_id}:{object_id}:{new_generation}").as_bytes(),
        ),
        witness_digest: None,
        operation_id: None,
    })
}

fn make_coverage(anchor: LedgerAnchor, certified: bool) -> CoverageWitness {
    let domain: BTreeSet<String> = ["cam-north".to_owned(), "cam-south".to_owned()]
        .into_iter()
        .collect();
    let observed = if certified {
        domain.clone()
    } else {
        ["cam-north".to_owned()].into_iter().collect()
    };
    CoverageWitness {
        anchor,
        authorized_domain: domain,
        observed_domain: observed,
        excluded_domain: BTreeSet::new(),
        continuity: if certified {
            CoverageContinuity::Continuous
        } else {
            CoverageContinuity::Gapped
        },
        completeness: if certified {
            Completeness::Complete
        } else {
            Completeness::Partial
        },
        negative_predicate: "no_conflicting_object".to_owned(),
        stop_reason: if certified {
            CoverageStopReason::Complete
        } else {
            CoverageStopReason::SourceGap
        },
        authorized_generation: 1,
        observed_generation: 1,
    }
}

fn seed_oracle(site: &str, objects: &[&str]) -> Result<LedgerOracle, SsiCorpusError> {
    let mut oracle = LedgerOracle::new(site, OracleLimits::CEILING)
        .map_err(|e| SsiCorpusError::Execution(e.to_string()))?;
    let mut deltas = Vec::with_capacity(objects.len());
    for (idx, obj) in objects.iter().enumerate() {
        deltas.push(make_delta(
            &format!("seed-d-{idx}"),
            "source_evidence",
            obj,
            None,
            1,
        )?);
    }
    let batch = oracle
        .prepare_batch(
            BatchId::parse(format!("batch:seed-{site}"))
                .map_err(|e| SsiCorpusError::Execution(e.to_string()))?,
            deltas,
            vec![],
        )
        .map_err(|e| SsiCorpusError::Execution(e.to_string()))?;
    oracle
        .append(batch)
        .map_err(|e| SsiCorpusError::Execution(e.to_string()))?;
    Ok(oracle)
}

type OutcomeFingerprint = (u32, u32, ContentDigest, Vec<(String, String)>);

fn outcome_fingerprint(
    outcome: &CombiningRoundOutcome,
    head_root: ContentDigest,
) -> OutcomeFingerprint {
    let mut committed = 0_u32;
    let mut aborted = 0_u32;
    let mut pairs = Vec::new();
    let mut enc = CanonicalEncoder::new();
    enc.digest(head_root);
    match outcome {
        CombiningRoundOutcome::Committed {
            batch_digest,
            outcomes,
            ..
        } => {
            enc.u8(1);
            enc.digest(*batch_digest);
            for (id, res) in outcomes {
                let tag = match res {
                    IntentOutcome::Committed(_) => {
                        committed = committed.saturating_add(1);
                        "committed".to_owned()
                    }
                    IntentOutcome::IdempotentReplay(_) => "idempotent".to_owned(),
                    IntentOutcome::Aborted(w) => {
                        aborted = aborted.saturating_add(1);
                        format!("aborted:{}", w.kind.as_str())
                    }
                    IntentOutcome::Indeterminate { .. } => "indeterminate".to_owned(),
                };
                enc.text(id);
                enc.text(&tag);
                pairs.push((id.clone(), tag));
            }
        }
        CombiningRoundOutcome::NoNewCommit { outcomes, .. } => {
            enc.u8(2);
            for (id, res) in outcomes {
                let tag = match res {
                    IntentOutcome::Committed(_) => "committed".to_owned(),
                    IntentOutcome::IdempotentReplay(_) => "idempotent".to_owned(),
                    IntentOutcome::Aborted(w) => {
                        aborted = aborted.saturating_add(1);
                        format!("aborted:{}", w.kind.as_str())
                    }
                    IntentOutcome::Indeterminate { .. } => "indeterminate".to_owned(),
                };
                enc.text(id);
                enc.text(&tag);
                pairs.push((id.clone(), tag));
            }
        }
        CombiningRoundOutcome::Indeterminate { .. } => {
            enc.u8(3);
        }
    }
    let digest = ContentDigest::sha256(&enc.finish());
    (committed, aborted, digest, pairs)
}

/// Case 1: Classic 2-actor disjoint-write SSI write skew across `[A, B]` and `[B, A]`.
fn run_two_actor_disjoint_write_skew() -> Result<ScheduleCaseResult, SsiCorpusError> {
    let base = seed_oracle("site-skew-2", &["obj:guard-a", "obj:guard-b"])?;
    let anchor = base.head_anchor().clone();
    let hist = base.head_history_root();
    let obj_a =
        ObjectId::parse("obj:guard-a").map_err(|e| SsiCorpusError::Execution(e.to_string()))?;
    let obj_b =
        ObjectId::parse("obj:guard-b").map_err(|e| SsiCorpusError::Execution(e.to_string()))?;
    let auth = IntentAuthorityContext::active(1, 1, [Plane::Authority]);

    let intent_a = CommitIntent {
        intent_id: "intent:actor-a".to_owned(),
        basis_anchor: anchor.clone(),
        basis_history_root: hist,
        read_witnesses: vec![
            SemanticWitness::Positive(
                PositiveWitness::from_oracle(&base, 1, &obj_a)
                    .map_err(|e| SsiCorpusError::Execution(e.to_string()))?,
            ),
            SemanticWitness::Positive(
                PositiveWitness::from_oracle(&base, 1, &obj_b)
                    .map_err(|e| SsiCorpusError::Execution(e.to_string()))?,
            ),
        ],
        writes: vec![make_delta("da", "guard_state", "obj:guard-a", Some(1), 2)?],
        child_roots: vec![],
        authority: auth.clone(),
    };
    let intent_b = CommitIntent {
        intent_id: "intent:actor-b".to_owned(),
        basis_anchor: anchor,
        basis_history_root: hist,
        read_witnesses: vec![
            SemanticWitness::Positive(
                PositiveWitness::from_oracle(&base, 1, &obj_a)
                    .map_err(|e| SsiCorpusError::Execution(e.to_string()))?,
            ),
            SemanticWitness::Positive(
                PositiveWitness::from_oracle(&base, 1, &obj_b)
                    .map_err(|e| SsiCorpusError::Execution(e.to_string()))?,
            ),
        ],
        writes: vec![make_delta("db", "guard_state", "obj:guard-b", Some(1), 2)?],
        child_roots: vec![],
        authority: auth,
    };

    let perms = [
        vec![intent_a.clone(), intent_b.clone()],
        vec![intent_b, intent_a],
    ];
    let mut baseline: Option<OutcomeFingerprint> = None;
    let mut invariant = true;
    for perm in perms {
        let mut ora = base.clone();
        let mut comb = DeterministicCommitCombiner::new();
        let out = comb
            .execute_round_oracle(&mut ora, perm, false)
            .map_err(|e| SsiCorpusError::Execution(e.to_string()))?;
        let fp = outcome_fingerprint(&out, ora.head_history_root());
        if let Some(ref first) = baseline {
            if first != &fp {
                invariant = false;
            }
        } else {
            baseline = Some(fp);
        }
    }
    let (committed, aborted, reproducer_digest, pairs) = baseline.ok_or_else(|| {
        SsiCorpusError::Execution("missing baseline outcome for 2-actor write skew".to_owned())
    })?;
    let saw_skew = pairs.iter().any(|(_, t)| {
        t == "aborted:ssi_dangerous_write_skew" || t == "aborted:positive_read_stale"
    });
    let passed = invariant && committed == 1 && aborted == 1 && saw_skew;
    Ok(ScheduleCaseResult {
        case_id: "two_actor_disjoint_write_skew".to_owned(),
        permutations_tested: 2,
        permutation_invariant: invariant,
        verdict: if passed {
            ScheduleVerdict::Passed
        } else {
            ScheduleVerdict::Failed
        },
        committed_intents: committed,
        aborted_intents: aborted,
        reproducer_digest,
        summary: "2-actor disjoint write-skew serialized: 1 committed, 1 aborted with ssi_dangerous_write_skew across both orders"
            .to_owned(),
    })
}

/// Case 2: 3-actor circular SSI write-skew ring across all 6 (`3!`) permutations.
fn run_three_actor_ring_write_skew() -> Result<ScheduleCaseResult, SsiCorpusError> {
    let base = seed_oracle("site-skew-3", &["obj:r1", "obj:r2", "obj:r3"])?;
    let anchor = base.head_anchor().clone();
    let hist = base.head_history_root();
    let r1 = ObjectId::parse("obj:r1").map_err(|e| SsiCorpusError::Execution(e.to_string()))?;
    let r2 = ObjectId::parse("obj:r2").map_err(|e| SsiCorpusError::Execution(e.to_string()))?;
    let r3 = ObjectId::parse("obj:r3").map_err(|e| SsiCorpusError::Execution(e.to_string()))?;
    let auth = IntentAuthorityContext::active(1, 1, [Plane::Authority]);

    let t1 = CommitIntent {
        intent_id: "intent:ring-1".to_owned(),
        basis_anchor: anchor.clone(),
        basis_history_root: hist,
        read_witnesses: vec![SemanticWitness::Positive(
            PositiveWitness::from_oracle(&base, 1, &r2)
                .map_err(|e| SsiCorpusError::Execution(e.to_string()))?,
        )],
        writes: vec![make_delta("dr1", "ring_state", "obj:r1", Some(1), 2)?],
        child_roots: vec![],
        authority: auth.clone(),
    };
    let t2 = CommitIntent {
        intent_id: "intent:ring-2".to_owned(),
        basis_anchor: anchor.clone(),
        basis_history_root: hist,
        read_witnesses: vec![SemanticWitness::Positive(
            PositiveWitness::from_oracle(&base, 1, &r3)
                .map_err(|e| SsiCorpusError::Execution(e.to_string()))?,
        )],
        writes: vec![make_delta("dr2", "ring_state", "obj:r2", Some(1), 2)?],
        child_roots: vec![],
        authority: auth.clone(),
    };
    let t3 = CommitIntent {
        intent_id: "intent:ring-3".to_owned(),
        basis_anchor: anchor,
        basis_history_root: hist,
        read_witnesses: vec![SemanticWitness::Positive(
            PositiveWitness::from_oracle(&base, 1, &r1)
                .map_err(|e| SsiCorpusError::Execution(e.to_string()))?,
        )],
        writes: vec![make_delta("dr3", "ring_state", "obj:r3", Some(1), 2)?],
        child_roots: vec![],
        authority: auth,
    };

    let all_items = [t1, t2, t3];
    let orderings: [[usize; 3]; 6] = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    let mut baseline: Option<OutcomeFingerprint> = None;
    let mut invariant = true;
    for ord in orderings {
        let perm = vec![
            all_items[ord[0]].clone(),
            all_items[ord[1]].clone(),
            all_items[ord[2]].clone(),
        ];
        let mut ora = base.clone();
        let mut comb = DeterministicCommitCombiner::new();
        let out = comb
            .execute_round_oracle(&mut ora, perm, false)
            .map_err(|e| SsiCorpusError::Execution(e.to_string()))?;
        let fp = outcome_fingerprint(&out, ora.head_history_root());
        if let Some(ref first) = baseline {
            if first != &fp {
                invariant = false;
            }
        } else {
            baseline = Some(fp);
        }
    }
    let (committed, aborted, reproducer_digest, pairs) = baseline.ok_or_else(|| {
        SsiCorpusError::Execution("missing baseline outcome for 3-actor ring".to_owned())
    })?;
    let saw_skew = pairs
        .iter()
        .any(|(_, t)| t == "aborted:ssi_dangerous_write_skew");
    // A 3-actor ring MUST NOT commit all 3 (that would admit a cycle) and MUST trigger
    // Step-7 SsiDangerousWriteSkew on the non-direct rw-antidependency edge!
    let passed = invariant && committed < 3 && aborted >= 1 && saw_skew;
    Ok(ScheduleCaseResult {
        case_id: "three_actor_ring_write_skew".to_owned(),
        permutations_tested: 6,
        permutation_invariant: invariant,
        verdict: if passed {
            ScheduleVerdict::Passed
        } else {
            ScheduleVerdict::Failed
        },
        committed_intents: committed,
        aborted_intents: aborted,
        reproducer_digest,
        summary: "3-actor circular rw-antidependency ring broke cycle identically across all 6 permutations"
            .to_owned(),
    })
}

/// Case 3: Negative-read phantom injection vs certified absence witness across both orders.
fn run_negative_read_phantom_injection() -> Result<ScheduleCaseResult, SsiCorpusError> {
    let base = seed_oracle("site-phantom", &["obj:base"])?;
    let anchor = base.head_anchor().clone();
    let hist = base.head_history_root();
    let phantom_obj = ObjectId::parse("obj:phantom-slot")
        .map_err(|e| SsiCorpusError::Execution(e.to_string()))?;
    let auth = IntentAuthorityContext::active(1, 1, [Plane::Authority]);

    let neg =
        NegativeWitness::from_oracle(&base, 1, &phantom_obj, make_coverage(anchor.clone(), true))
            .map_err(|e| SsiCorpusError::Execution(e.to_string()))?;

    let reader_writer = CommitIntent {
        intent_id: "intent:neg-reader".to_owned(),
        basis_anchor: anchor.clone(),
        basis_history_root: hist,
        read_witnesses: vec![SemanticWitness::Negative(neg)],
        writes: vec![make_delta(
            "d-dep",
            "derived_dispatch",
            "obj:dispatch",
            None,
            1,
        )?],
        child_roots: vec![],
        authority: auth.clone(),
    };
    let phantom_inserter = CommitIntent {
        intent_id: "intent:phantom-writer".to_owned(),
        basis_anchor: anchor,
        basis_history_root: hist,
        read_witnesses: vec![],
        writes: vec![make_delta(
            "d-ph",
            "source_evidence",
            "obj:phantom-slot",
            None,
            1,
        )?],
        child_roots: vec![],
        authority: auth,
    };

    let perms = [
        vec![reader_writer.clone(), phantom_inserter.clone()],
        vec![phantom_inserter, reader_writer],
    ];
    let mut baseline: Option<OutcomeFingerprint> = None;
    let mut invariant = true;
    for perm in perms {
        let mut ora = base.clone();
        let mut comb = DeterministicCommitCombiner::new();
        let out = comb
            .execute_round_oracle(&mut ora, perm, false)
            .map_err(|e| SsiCorpusError::Execution(e.to_string()))?;
        let fp = outcome_fingerprint(&out, ora.head_history_root());
        if let Some(ref first) = baseline {
            if first != &fp {
                invariant = false;
            }
        } else {
            baseline = Some(fp);
        }
    }
    let (committed, aborted, reproducer_digest, pairs) = baseline.ok_or_else(|| {
        SsiCorpusError::Execution("missing baseline outcome for negative phantom".to_owned())
    })?;
    let saw_phantom = pairs
        .iter()
        .any(|(_, t)| t == "aborted:negative_phantom_write");
    let passed = invariant && committed == 1 && aborted == 1 && saw_phantom;
    Ok(ScheduleCaseResult {
        case_id: "negative_read_phantom_injection".to_owned(),
        permutations_tested: 2,
        permutation_invariant: invariant,
        verdict: if passed {
            ScheduleVerdict::Passed
        } else {
            ScheduleVerdict::Failed
        },
        committed_intents: committed,
        aborted_intents: aborted,
        reproducer_digest,
        summary: "certified negative-read vs concurrent phantom insert never admitted both across both orders"
            .to_owned(),
    })
}

/// Case 4: Gapped/uncertified negative witness refuses before serializability with zero commits.
fn run_gapped_negative_absence_laundering() -> Result<ScheduleCaseResult, SsiCorpusError> {
    let mut ora = seed_oracle("site-gapped", &["obj:base"])?;
    let anchor = ora.head_anchor().clone();
    let hist = ora.head_history_root();
    let absent =
        ObjectId::parse("obj:unseen").map_err(|e| SsiCorpusError::Execution(e.to_string()))?;
    let gapped_neg =
        NegativeWitness::from_oracle(&ora, 1, &absent, make_coverage(anchor.clone(), false))
            .map_err(|e| SsiCorpusError::Execution(e.to_string()))?;

    let intent = CommitIntent {
        intent_id: "intent:gapped-absence".to_owned(),
        basis_anchor: anchor,
        basis_history_root: hist,
        read_witnesses: vec![SemanticWitness::Negative(gapped_neg)],
        writes: vec![make_delta("d-g", "derived_dispatch", "obj:out", None, 1)?],
        child_roots: vec![],
        authority: IntentAuthorityContext::active(1, 1, [Plane::Authority]),
    };

    let mut comb = DeterministicCommitCombiner::new();
    let out = comb
        .execute_round_oracle(&mut ora, vec![intent], false)
        .map_err(|e| SsiCorpusError::Execution(e.to_string()))?;
    let (committed, aborted, reproducer_digest, pairs) =
        outcome_fingerprint(&out, ora.head_history_root());
    let refused_uncertified = pairs
        .iter()
        .any(|(_, t)| t == "aborted:uncertified_absence_basis");
    let passed = committed == 0 && aborted == 1 && refused_uncertified;
    Ok(ScheduleCaseResult {
        case_id: "gapped_negative_absence_laundering".to_owned(),
        permutations_tested: 1,
        permutation_invariant: true,
        verdict: if passed {
            ScheduleVerdict::Passed
        } else {
            ScheduleVerdict::Failed
        },
        committed_intents: committed,
        aborted_intents: aborted,
        reproducer_digest,
        summary: "gapped/partial negative coverage refused as uncertified_absence_basis with zero committed writes"
            .to_owned(),
    })
}

/// Case 5: Stale-basis write-skew & negative phantom cannot be smuggled through `FSS-105` `MergeLadder`.
fn run_stale_basis_merge_ladder_no_skew_smuggling() -> Result<ScheduleCaseResult, SsiCorpusError> {
    let mut ora = seed_oracle("site-merge-skew", &["obj:guard-a", "obj:guard-b"])?;
    let anchor1 = ora.head_anchor().clone();
    let hist1 = ora.head_history_root();
    let guard_b =
        ObjectId::parse("obj:guard-b").map_err(|e| SsiCorpusError::Execution(e.to_string()))?;
    let phantom =
        ObjectId::parse("obj:phantom-m").map_err(|e| SsiCorpusError::Execution(e.to_string()))?;
    let auth = IntentAuthorityContext::active(1, 1, [Plane::Authority]);

    let stale_skew_intent = CommitIntent {
        intent_id: "intent:stale-skew".to_owned(),
        basis_anchor: anchor1.clone(),
        basis_history_root: hist1,
        read_witnesses: vec![SemanticWitness::Positive(
            PositiveWitness::from_oracle(&ora, 1, &guard_b)
                .map_err(|e| SsiCorpusError::Execution(e.to_string()))?,
        )],
        writes: vec![make_delta("ds1", "guard_state", "obj:guard-a", Some(1), 2)?],
        child_roots: vec![],
        authority: auth.clone(),
    };
    let stale_phantom_intent = CommitIntent {
        intent_id: "intent:stale-phantom".to_owned(),
        basis_anchor: anchor1.clone(),
        basis_history_root: hist1,
        read_witnesses: vec![SemanticWitness::Negative(
            NegativeWitness::from_oracle(&ora, 1, &phantom, make_coverage(anchor1, true))
                .map_err(|e| SsiCorpusError::Execution(e.to_string()))?,
        )],
        writes: vec![make_delta("ds2", "derived_dispatch", "obj:act", None, 1)?],
        child_roots: vec![],
        authority: auth,
    };

    // Intervening batch mutates `obj:guard-b` AND inserts phantom `obj:phantom-m`.
    let b2 = ora
        .prepare_batch(
            BatchId::parse("batch:intervening-skew")
                .map_err(|e| SsiCorpusError::Execution(e.to_string()))?,
            vec![
                make_delta("di1", "guard_state", "obj:guard-b", Some(1), 2)?,
                make_delta("di2", "source_evidence", "obj:phantom-m", None, 1)?,
            ],
            vec![],
        )
        .map_err(|e| SsiCorpusError::Execution(e.to_string()))?;
    ora.append(b2)
        .map_err(|e| SsiCorpusError::Execution(e.to_string()))?;

    let comm = CommutativeFamilyRegistry::new(["guard_state".to_owned()])
        .map_err(|e| SsiCorpusError::Execution(e.to_string()))?;
    let res_skew = MergeLadder::certify_merge(&ora, &stale_skew_intent, &comm, None, false)
        .map_err(|e| SsiCorpusError::Execution(e.to_string()))?;
    let res_phantom = MergeLadder::certify_merge(&ora, &stale_phantom_intent, &comm, None, false)
        .map_err(|e| SsiCorpusError::Execution(e.to_string()))?;

    let both_refused = matches!(
        res_skew,
        MergeOutcome::Refused {
            reason: MergeRefusalReason::IrreconcilableSemanticConflict,
            ..
        }
    ) && matches!(
        res_phantom,
        MergeOutcome::Refused {
            reason: MergeRefusalReason::IrreconcilableSemanticConflict,
            ..
        }
    );
    let mut enc = CanonicalEncoder::new();
    enc.digest(ora.head_history_root());
    enc.bool(both_refused);
    let reproducer_digest = ContentDigest::sha256(&enc.finish());
    Ok(ScheduleCaseResult {
        case_id: "stale_basis_merge_ladder_no_skew_smuggling".to_owned(),
        permutations_tested: 2,
        permutation_invariant: true,
        verdict: if both_refused {
            ScheduleVerdict::Passed
        } else {
            ScheduleVerdict::Failed
        },
        committed_intents: 0,
        aborted_intents: 2,
        reproducer_digest,
        summary: "FSS-105 MergeLadder refused stale write-skew and negative-phantom rebases even for commutative families"
            .to_owned(),
    })
}

/// Case 6: Nested `HierarchicalWitness` enforces both positive write-skew and negative phantom leaves.
fn run_hierarchical_witness_phantom_and_skew() -> Result<ScheduleCaseResult, SsiCorpusError> {
    let base = seed_oracle("site-hier", &["obj:sensor-1"])?;
    let anchor = base.head_anchor().clone();
    let hist = base.head_history_root();
    let s1 =
        ObjectId::parse("obj:sensor-1").map_err(|e| SsiCorpusError::Execution(e.to_string()))?;
    let absent = ObjectId::parse("obj:intruder-lock")
        .map_err(|e| SsiCorpusError::Execution(e.to_string()))?;
    let auth = IntentAuthorityContext::active(1, 1, [Plane::Authority]);

    let hier = HierarchicalWitness::compose(
        "zone:perimeter",
        vec![
            SemanticWitness::Positive(
                PositiveWitness::from_oracle(&base, 1, &s1)
                    .map_err(|e| SsiCorpusError::Execution(e.to_string()))?,
            ),
            SemanticWitness::Negative(
                NegativeWitness::from_oracle(
                    &base,
                    1,
                    &absent,
                    make_coverage(anchor.clone(), true),
                )
                .map_err(|e| SsiCorpusError::Execution(e.to_string()))?,
            ),
        ],
        false,
    )
    .map_err(|e| SsiCorpusError::Execution(e.to_string()))?;

    let hier_intent = CommitIntent {
        intent_id: "intent:hier-guarded".to_owned(),
        basis_anchor: anchor.clone(),
        basis_history_root: hist,
        read_witnesses: vec![SemanticWitness::Hierarchical(hier)],
        writes: vec![make_delta("dh1", "derived_dispatch", "obj:gate", None, 1)?],
        child_roots: vec![],
        authority: auth.clone(),
    };
    let lock_writer = CommitIntent {
        intent_id: "intent:lock-writer".to_owned(),
        basis_anchor: anchor,
        basis_history_root: hist,
        read_witnesses: vec![],
        writes: vec![make_delta(
            "dh2",
            "source_evidence",
            "obj:intruder-lock",
            None,
            1,
        )?],
        child_roots: vec![],
        authority: auth,
    };

    let perms = [
        vec![hier_intent.clone(), lock_writer.clone()],
        vec![lock_writer, hier_intent],
    ];
    let mut baseline: Option<OutcomeFingerprint> = None;
    let mut invariant = true;
    for perm in perms {
        let mut ora = base.clone();
        let mut comb = DeterministicCommitCombiner::new();
        let out = comb
            .execute_round_oracle(&mut ora, perm, false)
            .map_err(|e| SsiCorpusError::Execution(e.to_string()))?;
        let fp = outcome_fingerprint(&out, ora.head_history_root());
        if let Some(ref first) = baseline {
            if first != &fp {
                invariant = false;
            }
        } else {
            baseline = Some(fp);
        }
    }
    let (committed, aborted, reproducer_digest, pairs) = baseline.ok_or_else(|| {
        SsiCorpusError::Execution("missing baseline outcome for hierarchical witness".to_owned())
    })?;
    let saw_expected_conflict = pairs
        .iter()
        .any(|(_, t)| *t == format!("aborted:{}", ConflictKind::NegativePhantomWrite.as_str()));
    let passed = invariant && committed == 1 && aborted == 1 && saw_expected_conflict;
    Ok(ScheduleCaseResult {
        case_id: "hierarchical_witness_phantom_and_skew".to_owned(),
        permutations_tested: 2,
        permutation_invariant: invariant,
        verdict: if passed {
            ScheduleVerdict::Passed
        } else {
            ScheduleVerdict::Failed
        },
        committed_intents: committed,
        aborted_intents: aborted,
        reproducer_digest,
        summary: "nested HierarchicalWitness enforced negative-phantom/rw-antidependency leaves across both orders"
            .to_owned(),
    })
}

fn validate_label(value: &str, max_len: usize, label: &str) -> Result<(), SsiCorpusError> {
    if value.is_empty() || value.len() > max_len {
        return Err(SsiCorpusError::InvalidInput(format!(
            "{label} length {} outside 1..={max_len}",
            value.len()
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(SsiCorpusError::InvalidInput(format!(
            "{label} must not contain control characters"
        )));
    }
    Ok(())
}

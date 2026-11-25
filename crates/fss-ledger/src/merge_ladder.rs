#![forbid(unsafe_code)]
//! Intent-replay / structural / commutative merge certificate ladder (`FSS-105`, `fss-x4a.9.12`).
//!
//! Composes [`SemanticWitness`] (`FSS-103`), [`CommitIntent`] & [`DeterministicCommitCombiner`]
//! (`FSS-104`), and [`LedgerOracle`] to resolve stale-basis conflicts through a strict three-rung
//! sound merge ladder without silent overwrites, authority laundering, or lost uncertainty:
//!
//! 1. **Rung 1 — [`MergeRung::CommutativeAlgebraic`]:** proves that intervening committed writes
//!    on the same target objects belong exclusively to an explicitly registered commutative
//!    algebraic delta family (e.g. monotonic append-only observation counters / disjoint evidence
//!    tag sets) with zero read-witness invalidation, emitting a freshly anchored commutative delta
//!    with updated `prior_generation`/`new_generation`.
//! 2. **Rung 2 — [`MergeRung::StructuralNonOverlapping`]:** proves zero overlap between the
//!    intervening committed history `(basis_seq..=head_seq]` and the intent's positive read set,
//!    certified negative read set, and target write set — rebasing the intent cleanly onto
//!    `head_anchor` with freshly minted `FSS-103` read witnesses at `head_anchor`.
//! 3. **Rung 3 — [`MergeRung::DeterministicIntentReplay`]:** re-executes a caller-provided pure
//!    deterministic intent compiler against the exact canonical [`LedgerOracle`] view at
//!    `head_anchor`, emitting freshly anchored read witnesses and writes — OR fails closed cleanly
//!    into [`MergeOutcome::Refused`] when domain invariants, authority/privacy scope, or certified
//!    coverage cannot be preserved.
//!
//! Every admitted merge carries a bounded, checksummed [`MergeCertificate`] (`FSSMC001` v1,
//! domain `fss.ledger_merge_certificate.v1`) binding source anchor, target anchor, rung proof,
//! intervening batch digests, and rebased intent digest so the resulting [`CommitIntent`] commits
//! directly through [`DeterministicCommitCombiner`].

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, EvidenceDelta, LedgerAnchor, ObjectId,
};

use crate::combiner::{CommitCombinerError, CommitIntent};
use crate::oracle::{LedgerOracle, ObjectRead};
use crate::witness::{NegativeWitness, PositiveWitness, SemanticWitness};

/// Registered digest domain for sealed [`MergeCertificate`] commitments (`FSS-105`).
pub const LEDGER_MERGE_CERTIFICATE_DOMAIN: &str = "fss.ledger_merge_certificate.v1";
/// Binary wire header magic for serialized merge certificates.
pub const MERGE_CERT_MAGIC: [u8; 8] = *b"FSSMC001";
/// Supported durable format version for [`MergeCertificate`].
pub const MERGE_CERT_VERSION: u32 = 1;
/// Hard ceiling on intervening committed batches scanned during one merge attempt.
pub const MAX_MERGE_INTERVENING_BATCHES: usize = 4_096;
/// Hard ceiling on serialized certificate wire bytes (512 KiB).
pub const MAX_MERGE_CERT_WIRE_BYTES: usize = 512 * 1024;
/// Hard ceiling on diagnostic text / family label bytes.
pub const MAX_MERGE_LABEL_BYTES: usize = 256;

/// Ordered three-rung sound merge ladder (`FSS-105`).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MergeRung {
    /// Rung 1: Algebraic commutativity proof over registered commutative delta families.
    CommutativeAlgebraic = 1,
    /// Rung 2: Zero overlap between intervening history and intent read/write sets.
    StructuralNonOverlapping = 2,
    /// Rung 3: Pure deterministic replay of intent compiler against fresh canonical head view.
    DeterministicIntentReplay = 3,
}

impl MergeRung {
    /// Stable canonical machine spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CommutativeAlgebraic => "commutative_algebraic",
            Self::StructuralNonOverlapping => "structural_non_overlapping",
            Self::DeterministicIntentReplay => "deterministic_intent_replay",
        }
    }

    const fn tag(self) -> u8 {
        self as u8
    }

    fn from_tag(tag: u8) -> Result<Self, ContractError> {
        match tag {
            1 => Ok(Self::CommutativeAlgebraic),
            2 => Ok(Self::StructuralNonOverlapping),
            3 => Ok(Self::DeterministicIntentReplay),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Non-collapsed refusal reason when no sound merge rung applies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MergeRefusalReason {
    /// Capability, privacy, authority generation, or plane authorization refused/revoked.
    AuthorityOrPrivacyRefused,
    /// Source basis anchor diverged from canonical ledger history or exceeded head.
    DivergentOrFutureBasis,
    /// Read witness failed local invariants or disagreed with source basis anchor.
    InvalidSourceWitness,
    /// Negative read witness lacked certified coverage (`!certifies_absence()`).
    UncertifiedAbsenceBasis,
    /// Non-commutative intervening mutation invalidated positive/negative read or write target
    /// and deterministic replay declined to merge.
    IrreconcilableSemanticConflict,
    /// Intervening batch distance exceeded hard scan ceiling.
    InterveningSpanTooLarge,
}

impl MergeRefusalReason {
    /// Stable canonical machine spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthorityOrPrivacyRefused => "authority_or_privacy_refused",
            Self::DivergentOrFutureBasis => "divergent_or_future_basis",
            Self::InvalidSourceWitness => "invalid_source_witness",
            Self::UncertifiedAbsenceBasis => "uncertified_absence_basis",
            Self::IrreconcilableSemanticConflict => "irreconcilable_semantic_conflict",
            Self::InterveningSpanTooLarge => "intervening_span_too_large",
        }
    }
}

/// Safe operator/agent recovery guidance for a refused merge attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MergeGuidance {
    /// Re-authorize revoked capability/privacy or refresh authority generation.
    ReauthorizeAndReplan,
    /// Obtain certified coverage before retrying absence-dependent intent.
    WaitForCertifiedCoverage,
    /// Escalate semantic conflict to fresh investigation/operator decision (do not force overwrite).
    EscalateSemanticConflict,
    /// Compact/checkpoint or re-derive fresh intent directly from head anchor.
    ReanchorDirectlyAtHead,
    /// Cooperative cancellation observed; safe to retry when ready.
    RetryWhenReady,
    /// Reject corrupt or unsupported binary merge certificate bytes.
    RejectCorruptCertificate,
}

/// Typed error returned by [`MergeLadder`] or [`MergeCertificate`] wire codec.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MergeLadderError {
    /// Structural intent error from [`CommitIntent`].
    Intent(CommitCombinerError),
    /// Cooperative cancellation observed before completing merge certification.
    Cancelled,
    /// Invalid configuration or label violation.
    InvalidInput(String),
    /// Wire length or batch count exceeded hard protocol ceilings.
    BoundsExceeded {
        /// Observed size/count.
        observed: usize,
        /// Hard maximum.
        maximum: usize,
    },
    /// Binary certificate lacked [`MERGE_CERT_MAGIC`].
    InvalidMagic,
    /// Binary certificate declared an unsupported version.
    UnsupportedVersion {
        /// Observed version.
        version: u32,
    },
    /// Binary certificate was truncated, non-canonical, or structurally inconsistent.
    MalformedWire(String),
    /// Certificate canonical checksum failed verification.
    ChecksumMismatch,
    /// Underlying ledger or canonical encoding error.
    Ledger(String),
}

impl MergeLadderError {
    /// Stable canonical machine error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Intent(_) => "ERR-LEDGER-MERGE-INTENT-001",
            Self::Cancelled => "ERR-LEDGER-MERGE-CANCELLED-001",
            Self::InvalidInput(_) => "ERR-LEDGER-MERGE-INVALID-INPUT-001",
            Self::BoundsExceeded { .. } => "ERR-LEDGER-MERGE-BOUNDS-001",
            Self::InvalidMagic => "ERR-LEDGER-MERGE-INVALID-MAGIC-001",
            Self::UnsupportedVersion { .. } => "ERR-LEDGER-MERGE-UNSUPPORTED-VERSION-001",
            Self::MalformedWire(_) => "ERR-LEDGER-MERGE-MALFORMED-WIRE-001",
            Self::ChecksumMismatch => "ERR-LEDGER-MERGE-CHECKSUM-MISMATCH-001",
            Self::Ledger(_) => "ERR-LEDGER-MERGE-LEDGER-001",
        }
    }

    /// Safe recovery guidance.
    #[must_use]
    pub const fn guidance(&self) -> MergeGuidance {
        match self {
            Self::Cancelled => MergeGuidance::RetryWhenReady,
            Self::Intent(_) | Self::InvalidInput(_) | Self::BoundsExceeded { .. } => {
                MergeGuidance::ReanchorDirectlyAtHead
            }
            Self::InvalidMagic
            | Self::UnsupportedVersion { .. }
            | Self::MalformedWire(_)
            | Self::ChecksumMismatch => MergeGuidance::RejectCorruptCertificate,
            Self::Ledger(_) => MergeGuidance::EscalateSemanticConflict,
        }
    }
}

impl fmt::Display for MergeLadderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {self:?}", self.code())
    }
}

impl Error for MergeLadderError {}

impl From<CommitCombinerError> for MergeLadderError {
    fn from(value: CommitCombinerError) -> Self {
        Self::Intent(value)
    }
}

/// Explicitly registered delta families proven algebraically commutative under Rung 1.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CommutativeFamilyRegistry {
    /// Registered commutative delta family names (e.g. `"monotonic_counter"`, `"observation_set"`).
    pub families: BTreeSet<String>,
}

impl CommutativeFamilyRegistry {
    /// Creates a registry containing `families` after validating label bounds.
    pub fn new(families: impl IntoIterator<Item = String>) -> Result<Self, MergeLadderError> {
        let mut set = BTreeSet::new();
        for f in families {
            validate_label(&f, MAX_MERGE_LABEL_BYTES, "commutative_family")?;
            set.insert(f);
        }
        Ok(Self { families: set })
    }

    /// True iff `family` is explicitly certified commutative.
    #[must_use]
    pub fn is_commutative(&self, family: &str) -> bool {
        self.families.contains(family)
    }
}

/// Sealed proof certificate authorizing a rebased [`CommitIntent`] (`FSSMC001` v1).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MergeCertificate {
    /// Wire format version (`MERGE_CERT_VERSION`).
    pub format_version: u32,
    /// Stable intent identity.
    pub intent_id: String,
    /// Rung of the merge ladder that certified this rebase.
    pub rung: MergeRung,
    /// Original stale basis anchor.
    pub source_anchor: LedgerAnchor,
    /// Original history root at `source_anchor`.
    pub source_history_root: ContentDigest,
    /// Original intent canonical digest.
    pub source_intent_digest: ContentDigest,
    /// Target fresh head anchor onto which the intent was rebased.
    pub target_anchor: LedgerAnchor,
    /// Target fresh head history root.
    pub target_history_root: ContentDigest,
    /// Rebased intent canonical digest (`CommitIntent::canonical_digest`).
    pub rebased_intent_digest: ContentDigest,
    /// Ordered canonical batch digests of all intervening commits `(source_seq..=target_seq]`.
    pub intervening_batch_digests: Vec<ContentDigest>,
    /// Authority generation verified during certification.
    pub authority_generation: u64,
    /// Privacy policy epoch verified during certification.
    pub privacy_epoch: u64,
    /// Secret-free justification / algebraic rule label.
    pub proof_note: String,
    /// Domain-separated SHA-256 commitment (`fss.ledger_merge_certificate.v1`).
    pub certificate_digest: ContentDigest,
}

impl MergeCertificate {
    /// Recomputes the domain-separated SHA-256 commitment (`fss.ledger_merge_certificate.v1`).
    pub fn compute_digest(&self) -> Result<ContentDigest, MergeLadderError> {
        let mut enc = CanonicalEncoder::new();
        enc.text(LEDGER_MERGE_CERTIFICATE_DOMAIN);
        self.encode_body(&mut enc);
        let bytes = enc
            .finish_checked()
            .map_err(|e| MergeLadderError::Ledger(e.to_string()))?;
        Ok(ContentDigest::sha256(&bytes))
    }

    /// Verifies structural invariants and cryptographic self-digest of this certificate.
    pub fn verify_self(&self) -> Result<(), MergeLadderError> {
        if self.format_version != MERGE_CERT_VERSION {
            return Err(MergeLadderError::UnsupportedVersion {
                version: self.format_version,
            });
        }
        validate_label(&self.intent_id, 128, "intent_id")
            .map_err(|e| MergeLadderError::MalformedWire(e.to_string()))?;
        validate_label(&self.proof_note, MAX_MERGE_LABEL_BYTES, "proof_note")
            .map_err(|e| MergeLadderError::MalformedWire(e.to_string()))?;
        if self.source_anchor.site_lineage != self.target_anchor.site_lineage
            || self.source_anchor.ledger_epoch != self.target_anchor.ledger_epoch
            || self.target_anchor.commit_sequence < self.source_anchor.commit_sequence
        {
            return Err(MergeLadderError::MalformedWire(
                "target_anchor must advance monotonically on the same lineage and epoch".to_owned(),
            ));
        }
        let expected_span =
            (self.target_anchor.commit_sequence - self.source_anchor.commit_sequence) as usize;
        if expected_span > MAX_MERGE_INTERVENING_BATCHES {
            return Err(MergeLadderError::BoundsExceeded {
                observed: expected_span,
                maximum: MAX_MERGE_INTERVENING_BATCHES,
            });
        }
        if self.intervening_batch_digests.len() != expected_span {
            return Err(MergeLadderError::MalformedWire(format!(
                "intervening_batch_digests len {} != sequence delta {expected_span}",
                self.intervening_batch_digests.len()
            )));
        }
        if self.compute_digest()? != self.certificate_digest {
            return Err(MergeLadderError::ChecksumMismatch);
        }
        Ok(())
    }

    fn encode_body(&self, enc: &mut CanonicalEncoder) {
        enc.u32(self.format_version);
        enc.text(&self.intent_id);
        enc.u8(self.rung.tag());
        self.source_anchor.encode_canonical(enc);
        enc.digest(self.source_history_root);
        enc.digest(self.source_intent_digest);
        self.target_anchor.encode_canonical(enc);
        enc.digest(self.target_history_root);
        enc.digest(self.rebased_intent_digest);
        enc.u64(self.intervening_batch_digests.len() as u64);
        for d in &self.intervening_batch_digests {
            enc.digest(*d);
        }
        enc.u64(self.authority_generation);
        enc.u64(self.privacy_epoch);
        enc.text(&self.proof_note);
    }

    /// Encodes this certificate into bounded checksummed binary bytes (`FSSMC001` v1).
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, MergeLadderError> {
        self.verify_self()?;
        let mut enc = CanonicalEncoder::new();
        self.encode_body(&mut enc);
        enc.digest(self.certificate_digest);
        let body = enc
            .finish_checked()
            .map_err(|e| MergeLadderError::Ledger(e.to_string()))?;
        let total = MERGE_CERT_MAGIC
            .len()
            .saturating_add(4)
            .saturating_add(body.len());
        if total > MAX_MERGE_CERT_WIRE_BYTES {
            return Err(MergeLadderError::BoundsExceeded {
                observed: total,
                maximum: MAX_MERGE_CERT_WIRE_BYTES,
            });
        }
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&MERGE_CERT_MAGIC);
        out.extend_from_slice(&self.format_version.to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Cold-decodes and verifies a binary [`MergeCertificate`] (`FSSMC001` v1).
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, MergeLadderError> {
        if bytes.len() > MAX_MERGE_CERT_WIRE_BYTES {
            return Err(MergeLadderError::BoundsExceeded {
                observed: bytes.len(),
                maximum: MAX_MERGE_CERT_WIRE_BYTES,
            });
        }
        if bytes.len() < 12 || bytes[..8] != MERGE_CERT_MAGIC {
            return Err(MergeLadderError::InvalidMagic);
        }
        let header_ver = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if header_ver != MERGE_CERT_VERSION {
            return Err(MergeLadderError::UnsupportedVersion {
                version: header_ver,
            });
        }
        let mut dec = CanonicalDecoder::new(&bytes[12..]);
        let format_version = dec
            .u32()
            .map_err(|e| MergeLadderError::MalformedWire(e.to_string()))?;
        if format_version != header_ver {
            return Err(MergeLadderError::UnsupportedVersion {
                version: format_version,
            });
        }
        let intent_id = dec
            .text()
            .map_err(|e| MergeLadderError::MalformedWire(e.to_string()))?
            .to_owned();
        let rung = MergeRung::from_tag(
            dec.u8()
                .map_err(|e| MergeLadderError::MalformedWire(e.to_string()))?,
        )
        .map_err(|e| MergeLadderError::MalformedWire(e.to_string()))?;
        let source_anchor = LedgerAnchor::decode_canonical(&mut dec)
            .map_err(|e| MergeLadderError::MalformedWire(e.to_string()))?;
        let source_history_root = dec
            .digest()
            .map_err(|e| MergeLadderError::MalformedWire(e.to_string()))?;
        let source_intent_digest = dec
            .digest()
            .map_err(|e| MergeLadderError::MalformedWire(e.to_string()))?;
        let target_anchor = LedgerAnchor::decode_canonical(&mut dec)
            .map_err(|e| MergeLadderError::MalformedWire(e.to_string()))?;
        let target_history_root = dec
            .digest()
            .map_err(|e| MergeLadderError::MalformedWire(e.to_string()))?;
        let rebased_intent_digest = dec
            .digest()
            .map_err(|e| MergeLadderError::MalformedWire(e.to_string()))?;
        let batch_count = usize::try_from(
            dec.u64()
                .map_err(|e| MergeLadderError::MalformedWire(e.to_string()))?,
        )
        .map_err(|_| MergeLadderError::BoundsExceeded {
            observed: usize::MAX,
            maximum: MAX_MERGE_INTERVENING_BATCHES,
        })?;
        if batch_count > MAX_MERGE_INTERVENING_BATCHES
            || batch_count.saturating_mul(32) > dec.remaining()
        {
            return Err(MergeLadderError::BoundsExceeded {
                observed: batch_count,
                maximum: MAX_MERGE_INTERVENING_BATCHES,
            });
        }
        let mut intervening_batch_digests = Vec::with_capacity(batch_count);
        for _ in 0..batch_count {
            intervening_batch_digests.push(
                dec.digest()
                    .map_err(|e| MergeLadderError::MalformedWire(e.to_string()))?,
            );
        }
        let authority_generation = dec
            .u64()
            .map_err(|e| MergeLadderError::MalformedWire(e.to_string()))?;
        let privacy_epoch = dec
            .u64()
            .map_err(|e| MergeLadderError::MalformedWire(e.to_string()))?;
        let proof_note = dec
            .text()
            .map_err(|e| MergeLadderError::MalformedWire(e.to_string()))?
            .to_owned();
        let stored_digest = dec
            .digest()
            .map_err(|e| MergeLadderError::MalformedWire(e.to_string()))?;
        dec.ensure_finished().map_err(|_| {
            MergeLadderError::MalformedWire("trailing bytes after merge certificate".to_owned())
        })?;

        let cert = Self {
            format_version,
            intent_id,
            rung,
            source_anchor,
            source_history_root,
            source_intent_digest,
            target_anchor,
            target_history_root,
            rebased_intent_digest,
            intervening_batch_digests,
            authority_generation,
            privacy_epoch,
            proof_note,
            certificate_digest: stored_digest,
        };
        cert.verify_self()?;
        Ok(cert)
    }
}

/// Non-collapsed outcome of evaluating the three-rung merge ladder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MergeOutcome {
    /// A sound merge rung certified the rebased intent, ready for [`crate::DeterministicCommitCombiner`].
    Certified {
        /// Rebased intent anchored at `head_anchor` with fresh `FSS-103` witnesses and generations.
        rebased_intent: Box<CommitIntent>,
        /// Sealed verifiable merge certificate.
        certificate: Box<MergeCertificate>,
    },
    /// No sound merge rung could preserve semantic invariants; caller must escalate or re-plan.
    Refused {
        /// Typed refusal classification.
        reason: MergeRefusalReason,
        /// Offending object identity, if applicable.
        conflicting_object: Option<ObjectId>,
        /// Secret-free diagnostic explanation.
        detail: String,
        /// Safe recovery guidance.
        guidance: MergeGuidance,
    },
}

/// Pure deterministic intent-replay compiler invoked only at Rung 3 when Rungs 1 and 2 cannot apply.
pub type IntentReplayFn<'a> =
    &'a dyn Fn(&LedgerOracle, &CommitIntent) -> Result<Option<CommitIntent>, MergeLadderError>;

/// Deterministic three-rung merge certificate ladder (`FSS-105`).
pub struct MergeLadder;

impl MergeLadder {
    /// Attempts to rebase `intent` from its stale `basis_anchor` onto `oracle.head_anchor()`
    /// following the strict soundness order:
    /// 1. [`MergeRung::StructuralNonOverlapping`] when zero read/write overlap occurred;
    /// 2. [`MergeRung::CommutativeAlgebraic`] when write-target overlap occurred ONLY within
    ///    explicitly registered commutative delta families and zero read witnesses were invalidated;
    /// 3. [`MergeRung::DeterministicIntentReplay`] when an optional pure replay compiler produces
    ///    a verified head-anchored intent.
    ///
    /// Otherwise returns [`MergeOutcome::Refused`] (never silently overwriting or dropping uncertainty).
    pub fn certify_merge(
        oracle: &LedgerOracle,
        intent: &CommitIntent,
        commutative_families: &CommutativeFamilyRegistry,
        replay_fn: Option<IntentReplayFn<'_>>,
        cancelled: bool,
    ) -> Result<MergeOutcome, MergeLadderError> {
        if cancelled {
            return Err(MergeLadderError::Cancelled);
        }
        intent.validate_structure()?;
        let source_intent_digest = intent.canonical_digest()?;

        // 0. Authority & privacy pre-flight check BEFORE any merge evaluation!
        if !intent.authority.capability_active
            || !intent.authority.privacy_active
            || intent.authority.authority_generation
                != intent.authority.expected_authority_generation
            || intent
                .writes
                .iter()
                .any(|d| !intent.authority.allowed_planes.contains(&d.plane))
        {
            return Ok(MergeOutcome::Refused {
                reason: MergeRefusalReason::AuthorityOrPrivacyRefused,
                conflicting_object: None,
                detail: "intent authority, privacy, generation, or plane projection invalid"
                    .to_owned(),
                guidance: MergeGuidance::ReauthorizeAndReplan,
            });
        }

        // 1. Verify source basis anchor & history root against canonical ledger history.
        let head_anchor = oracle.head_anchor().clone();
        let head_history_root = oracle.head_history_root();
        let basis_seq = intent.basis_anchor.commit_sequence;
        if intent.basis_anchor.site_lineage != head_anchor.site_lineage
            || intent.basis_anchor.ledger_epoch != head_anchor.ledger_epoch
            || basis_seq > head_anchor.commit_sequence
        {
            return Ok(MergeOutcome::Refused {
                reason: MergeRefusalReason::DivergentOrFutureBasis,
                conflicting_object: None,
                detail:
                    "intent basis_anchor lineage, epoch, or sequence disagrees with ledger head"
                        .to_owned(),
                guidance: MergeGuidance::ReanchorDirectlyAtHead,
            });
        }
        if oracle.anchor_at(basis_seq) != Some(&intent.basis_anchor)
            || oracle.history_root_at(basis_seq) != Some(intent.basis_history_root)
        {
            return Ok(MergeOutcome::Refused {
                reason: MergeRefusalReason::DivergentOrFutureBasis,
                conflicting_object: None,
                detail: "intent basis_anchor or basis_history_root diverged from canonical history"
                    .to_owned(),
                guidance: MergeGuidance::ReanchorDirectlyAtHead,
            });
        }

        let span = (head_anchor.commit_sequence - basis_seq) as usize;
        if span > MAX_MERGE_INTERVENING_BATCHES {
            return Ok(MergeOutcome::Refused {
                reason: MergeRefusalReason::InterveningSpanTooLarge,
                conflicting_object: None,
                detail: format!(
                    "intervening span {span} exceeds hard ceiling {MAX_MERGE_INTERVENING_BATCHES}"
                ),
                guidance: MergeGuidance::ReanchorDirectlyAtHead,
            });
        }

        // 2. Verify every source FSS-103 read witness against the exact oracle at `basis_anchor`.
        let mut pos_reads: Vec<PositiveWitness> = Vec::new();
        let mut neg_reads: Vec<NegativeWitness> = Vec::new();
        for w in &intent.read_witnesses {
            if w.anchor() != &intent.basis_anchor || w.history_root() != intent.basis_history_root {
                return Ok(MergeOutcome::Refused {
                    reason: MergeRefusalReason::InvalidSourceWitness,
                    conflicting_object: None,
                    detail: "source read witness anchor/history_root disagrees with intent basis"
                        .to_owned(),
                    guidance: MergeGuidance::ReanchorDirectlyAtHead,
                });
            }
            if let Err(err) = w.verify_against_oracle(oracle, false) {
                return Ok(MergeOutcome::Refused {
                    reason: MergeRefusalReason::InvalidSourceWitness,
                    conflicting_object: None,
                    detail: format!("source read witness failed oracle verification: {err}"),
                    guidance: MergeGuidance::ReanchorDirectlyAtHead,
                });
            }
            collect_witnesses(w, &mut pos_reads, &mut neg_reads);
        }
        for neg in &neg_reads {
            if !neg.certified || !neg.coverage.certifies_absence() {
                return Ok(MergeOutcome::Refused {
                    reason: MergeRefusalReason::UncertifiedAbsenceBasis,
                    conflicting_object: Some(neg.object_id.clone()),
                    detail: "cannot merge intent backed by uncertified/gapped absence coverage"
                        .to_owned(),
                    guidance: MergeGuidance::WaitForCertifiedCoverage,
                });
            }
        }

        // 3. Collect all intervening committed batches and mutated objects `(basis_seq..=head_seq]`.
        let mut intervening_batch_digests = Vec::with_capacity(span);
        let mut mutated_objects: BTreeSet<ObjectId> = BTreeSet::new();
        let mut mutated_families_by_obj: std::collections::BTreeMap<ObjectId, BTreeSet<String>> =
            std::collections::BTreeMap::new();
        let start_idx = usize::try_from(basis_seq).unwrap_or(oracle.batch_count());
        for idx in start_idx..oracle.batch_count() {
            let Some((batch, _)) = oracle.entry_at_index(idx) else {
                break;
            };
            intervening_batch_digests.push(batch.batch_digest);
            for d in &batch.deltas {
                mutated_objects.insert(d.object_id.clone());
                mutated_families_by_obj
                    .entry(d.object_id.clone())
                    .or_default()
                    .insert(d.family.clone());
            }
        }

        // Verify every source write delta's prior/new generation was valid at `basis_anchor`.
        let basis_view = oracle
            .view_at(basis_seq)
            .map_err(|e| MergeLadderError::Ledger(e.to_string()))?;
        for delta in &intent.writes {
            let basis_gen = match basis_view.object(&delta.object_id) {
                ObjectRead::Present { revision, .. } => Some(revision.generation),
                ObjectRead::AbsentAtAnchor { .. } => None,
            };
            let expected_new = basis_gen.map_or(1, |g| g.saturating_add(1));
            if delta.prior_generation != basis_gen || delta.new_generation != expected_new {
                return Ok(MergeOutcome::Refused {
                    reason: MergeRefusalReason::IrreconcilableSemanticConflict,
                    conflicting_object: Some(delta.object_id.clone()),
                    detail: format!(
                        "source write generation {:?}/{} disagrees with basis_anchor state {:?}",
                        delta.prior_generation, delta.new_generation, basis_gen
                    ),
                    guidance: MergeGuidance::ReanchorDirectlyAtHead,
                });
            }
        }

        // Check whether ANY read witness object mutated in `(basis_seq..=head_seq]`.
        let stale_read_obj: Option<ObjectId> = pos_reads
            .iter()
            .map(|p| &p.object_id)
            .chain(neg_reads.iter().map(|n| &n.object_id))
            .find(|obj| mutated_objects.contains(*obj))
            .cloned();

        let write_overlap_objs: Vec<ObjectId> = intent
            .writes
            .iter()
            .filter(|w| mutated_objects.contains(&w.object_id))
            .map(|w| w.object_id.clone())
            .collect();

        // RUNG 2 (Structural non-overlapping): zero read overlap AND zero write overlap!
        if stale_read_obj.is_none() && write_overlap_objs.is_empty() {
            let rebased = rebase_intent_at_head(
                oracle,
                intent,
                &pos_reads,
                &neg_reads,
                &head_anchor,
                head_history_root,
                false,
            )?;
            let cert = seal_certificate(
                intent,
                source_intent_digest,
                MergeRung::StructuralNonOverlapping,
                head_anchor,
                head_history_root,
                rebased.canonical_digest()?,
                intervening_batch_digests,
                "zero_read_write_overlap_with_intervening_history",
            )?;
            return Ok(MergeOutcome::Certified {
                rebased_intent: Box::new(rebased),
                certificate: Box::new(cert),
            });
        }

        // RUNG 1 (Commutative algebraic merge): zero read overlap, and EVERY overlapping write
        // target mutated ONLY via explicitly registered commutative families (both intent & history)!
        if stale_read_obj.is_none() && !write_overlap_objs.is_empty() {
            let all_commutative = intent.writes.iter().all(|w| {
                if !mutated_objects.contains(&w.object_id) {
                    return true;
                }
                if !commutative_families.is_commutative(&w.family) {
                    return false;
                }
                mutated_families_by_obj
                    .get(&w.object_id)
                    .is_some_and(|fams| fams.iter().all(|f| commutative_families.is_commutative(f)))
            });
            if all_commutative {
                let rebased = rebase_intent_at_head(
                    oracle,
                    intent,
                    &pos_reads,
                    &neg_reads,
                    &head_anchor,
                    head_history_root,
                    true,
                )?;
                let cert = seal_certificate(
                    intent,
                    source_intent_digest,
                    MergeRung::CommutativeAlgebraic,
                    head_anchor,
                    head_history_root,
                    rebased.canonical_digest()?,
                    intervening_batch_digests,
                    "certified_commutative_family_generation_rebase",
                )?;
                return Ok(MergeOutcome::Certified {
                    rebased_intent: Box::new(rebased),
                    certificate: Box::new(cert),
                });
            }
        }

        // RUNG 3 (Deterministic intent replay): invoke caller's pure deterministic replay compiler
        // against the fresh canonical head view and validate every invariant on its output!
        if let Some(replay) = replay_fn
            && let Some(replayed) = replay(oracle, intent)?
        {
            replayed.validate_structure()?;
            if replayed.intent_id != intent.intent_id
                || replayed.basis_anchor != head_anchor
                || replayed.basis_history_root != head_history_root
                || replayed.authority != intent.authority
            {
                return Ok(MergeOutcome::Refused {
                    reason: MergeRefusalReason::IrreconcilableSemanticConflict,
                    conflicting_object: stale_read_obj
                        .or_else(|| write_overlap_objs.into_iter().next()),
                    detail:
                        "deterministic intent replay output failed head anchor or authority binding"
                            .to_owned(),
                    guidance: MergeGuidance::EscalateSemanticConflict,
                });
            }
            if replayed
                .writes
                .iter()
                .any(|d| !replayed.authority.allowed_planes.contains(&d.plane))
            {
                return Ok(MergeOutcome::Refused {
                    reason: MergeRefusalReason::AuthorityOrPrivacyRefused,
                    conflicting_object: stale_read_obj
                        .or_else(|| write_overlap_objs.into_iter().next()),
                    detail: "replayed intent attempted write outside authorized semantic planes"
                        .to_owned(),
                    guidance: MergeGuidance::ReauthorizeAndReplan,
                });
            }
            let mut replayed_pos = Vec::new();
            let mut replayed_neg = Vec::new();
            for w in &replayed.read_witnesses {
                if w.anchor() != &head_anchor
                    || w.history_root() != head_history_root
                    || w.verify_against_oracle(oracle, false).is_err()
                {
                    return Ok(MergeOutcome::Refused {
                        reason: MergeRefusalReason::IrreconcilableSemanticConflict,
                        conflicting_object: stale_read_obj
                            .or_else(|| write_overlap_objs.into_iter().next()),
                        detail: "replayed intent carried invalid head read witnesses".to_owned(),
                        guidance: MergeGuidance::EscalateSemanticConflict,
                    });
                }
                collect_witnesses(w, &mut replayed_pos, &mut replayed_neg);
            }
            for neg in &replayed_neg {
                if !neg.certified || !neg.coverage.certifies_absence() {
                    return Ok(MergeOutcome::Refused {
                        reason: MergeRefusalReason::UncertifiedAbsenceBasis,
                        conflicting_object: Some(neg.object_id.clone()),
                        detail: "replayed negative read witness lacks certified absence coverage"
                            .to_owned(),
                        guidance: MergeGuidance::WaitForCertifiedCoverage,
                    });
                }
            }
            // Verify every replayed write matches exact current head generation!
            let head_view = oracle
                .view_at(head_anchor.commit_sequence)
                .map_err(|e| MergeLadderError::Ledger(e.to_string()))?;
            for delta in &replayed.writes {
                let cur_gen = match head_view.object(&delta.object_id) {
                    ObjectRead::Present { revision, .. } => Some(revision.generation),
                    ObjectRead::AbsentAtAnchor { .. } => None,
                };
                let expected_new = cur_gen.map_or(1, |g| g.saturating_add(1));
                if delta.prior_generation != cur_gen || delta.new_generation != expected_new {
                    return Ok(MergeOutcome::Refused {
                        reason: MergeRefusalReason::IrreconcilableSemanticConflict,
                        conflicting_object: Some(delta.object_id.clone()),
                        detail: "replayed write generations do not match head anchor".to_owned(),
                        guidance: MergeGuidance::EscalateSemanticConflict,
                    });
                }
            }
            let rebased_digest = replayed.canonical_digest()?;
            let cert = seal_certificate(
                intent,
                source_intent_digest,
                MergeRung::DeterministicIntentReplay,
                head_anchor,
                head_history_root,
                rebased_digest,
                intervening_batch_digests,
                "deterministic_intent_replay_verified_at_head",
            )?;
            return Ok(MergeOutcome::Certified {
                rebased_intent: Box::new(replayed),
                certificate: Box::new(cert),
            });
        }

        // Fail closed cleanly: no sound merge rung succeeded.
        Ok(MergeOutcome::Refused {
            reason: MergeRefusalReason::IrreconcilableSemanticConflict,
            conflicting_object: stale_read_obj.or_else(|| write_overlap_objs.into_iter().next()),
            detail: "non-commutative semantic conflict with intervening history; merge refused"
                .to_owned(),
            guidance: MergeGuidance::EscalateSemanticConflict,
        })
    }
}

fn collect_witnesses(
    w: &SemanticWitness,
    pos: &mut Vec<PositiveWitness>,
    neg: &mut Vec<NegativeWitness>,
) {
    match w {
        SemanticWitness::Positive(p) => pos.push(p.clone()),
        SemanticWitness::Negative(n) => neg.push(n.clone()),
        SemanticWitness::Hierarchical(h) => {
            for child in &h.children {
                collect_witnesses(child, pos, neg);
            }
        }
    }
}

fn rebase_intent_at_head(
    oracle: &LedgerOracle,
    source: &CommitIntent,
    pos_reads: &[PositiveWitness],
    neg_reads: &[NegativeWitness],
    head_anchor: &LedgerAnchor,
    head_history_root: ContentDigest,
    advance_overlapping_generations: bool,
) -> Result<CommitIntent, MergeLadderError> {
    let head_seq = head_anchor.commit_sequence;
    let mut fresh_witnesses = Vec::with_capacity(pos_reads.len() + neg_reads.len());
    for p in pos_reads {
        let fresh = PositiveWitness::from_oracle(oracle, head_seq, &p.object_id)
            .map_err(|e| MergeLadderError::Ledger(e.to_string()))?;
        fresh_witnesses.push(SemanticWitness::Positive(fresh));
    }
    for n in neg_reads {
        let mut fresh_cov = n.coverage.clone();
        fresh_cov.anchor = head_anchor.clone();
        let fresh = NegativeWitness::from_oracle(oracle, head_seq, &n.object_id, fresh_cov)
            .map_err(|e| MergeLadderError::Ledger(e.to_string()))?;
        fresh_witnesses.push(SemanticWitness::Negative(fresh));
    }

    let head_view = oracle
        .view_at(head_seq)
        .map_err(|e| MergeLadderError::Ledger(e.to_string()))?;
    let mut fresh_writes: Vec<EvidenceDelta> = Vec::with_capacity(source.writes.len());
    for delta in &source.writes {
        let mut updated = delta.clone();
        if advance_overlapping_generations {
            let cur_gen = match head_view.object(&delta.object_id) {
                ObjectRead::Present { revision, .. } => Some(revision.generation),
                ObjectRead::AbsentAtAnchor { .. } => None,
            };
            updated.prior_generation = cur_gen;
            updated.new_generation = cur_gen.map_or(1, |g| g.saturating_add(1));
        }
        fresh_writes.push(updated);
    }

    Ok(CommitIntent {
        intent_id: source.intent_id.clone(),
        basis_anchor: head_anchor.clone(),
        basis_history_root: head_history_root,
        read_witnesses: fresh_witnesses,
        writes: fresh_writes,
        child_roots: source.child_roots.clone(),
        authority: source.authority.clone(),
    })
}

#[allow(clippy::too_many_arguments)]
fn seal_certificate(
    intent: &CommitIntent,
    source_intent_digest: ContentDigest,
    rung: MergeRung,
    target_anchor: LedgerAnchor,
    target_history_root: ContentDigest,
    rebased_intent_digest: ContentDigest,
    intervening_batch_digests: Vec<ContentDigest>,
    proof_note: &str,
) -> Result<MergeCertificate, MergeLadderError> {
    let mut cert = MergeCertificate {
        format_version: MERGE_CERT_VERSION,
        intent_id: intent.intent_id.clone(),
        rung,
        source_anchor: intent.basis_anchor.clone(),
        source_history_root: intent.basis_history_root,
        source_intent_digest,
        target_anchor,
        target_history_root,
        rebased_intent_digest,
        intervening_batch_digests,
        authority_generation: intent.authority.authority_generation,
        privacy_epoch: intent.authority.privacy_epoch,
        proof_note: proof_note.to_owned(),
        certificate_digest: ContentDigest::sha256(b"unsealed-merge-certificate"),
    };
    cert.certificate_digest = cert.compute_digest()?;
    Ok(cert)
}

fn validate_label(value: &str, max_len: usize, label: &str) -> Result<(), MergeLadderError> {
    if value.is_empty() || value.len() > max_len {
        return Err(MergeLadderError::InvalidInput(format!(
            "{label} length {} outside 1..={max_len}",
            value.len()
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(MergeLadderError::InvalidInput(format!(
            "{label} must not contain control characters"
        )));
    }
    Ok(())
}

#![forbid(unsafe_code)]
//! Counterfactual branch overlay and live-intent recompilation (`FSS-108`, `fss-x4a.9.15`).
//!
//! Composes [`LedgerOracle`], [`SemanticWitness`] (`FSS-103`), [`CommitIntent`] &
//! [`DeterministicCommitCombiner`] (`FSS-104`), and [`MergeLadder`] (`FSS-105`) to support
//! isolated counterfactual / what-if exploration over an exact pinned canonical anchor WITHOUT
//! EVER mutating canonical history or laundering hypothetical deltas into canonical truth:
//!
//! - **Isolated read-only overlay (`CounterfactualBranchOverlay`):** anchors at one exact
//!   `(basis_anchor, basis_history_root)`, forbids `grants_effect_authority == true`, enforces
//!   capability/privacy/plane scope, and layers bounded hypothetical `EvidenceDelta` changes in
//!   branch memory only.
//! - **Non-collapsed read & diff projection (`OverlayReadState`):** explicitly distinguishes
//!   `CanonicalUnmodified`, `HypotheticallyCreated`, `HypotheticallyUpdated`, and `AbsentInBoth`
//!   so callers never confuse counterfactual assumptions with canonical history.
//! - **Live-intent recompilation (`recompile_for_live_head`):** compiles a branch-derived
//!   candidate [`CommitIntent`] against the current live canonical `LedgerOracle` head:
//!   - Refuses with [`RecompileRefusalReason::CounterfactualAssumptionNotCanonical`] if any write
//!     or read depends on hypothetical-only overlay state that does NOT exist in canonical truth;
//!   - Validates authority/privacy/plane bounds BEFORE recompilation;
//!   - When canonical head matches `basis_anchor`, verifies all witnesses/generations directly;
//!   - When canonical head advanced past `basis_anchor`, delegates soundly to `FSS-105`
//!     [`MergeLadder::certify_merge`] and seals a bounded checksummed
//!     [`CounterfactualRecompileReceipt`] (`FSSCFBR1` v1, domain
//!     `fss.ledger_counterfactual_receipt.v1`).

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, EvidenceDelta, LedgerAnchor, ObjectId, ObjectRevision, Plane, TimestampNs,
};

use crate::combiner::{CommitCombinerError, CommitIntent};
use crate::merge_ladder::{
    CommutativeFamilyRegistry, IntentReplayFn, MergeCertificate, MergeLadder, MergeLadderError,
    MergeOutcome, MergeRefusalReason, MergeRung,
};
use crate::oracle::{LedgerOracle, ObjectRead};
use crate::witness::{NegativeWitness, PositiveWitness, SemanticWitness};

/// Registered digest domain for sealed [`CounterfactualRecompileReceipt`] commitments (`FSS-108`).
pub const LEDGER_COUNTERFACTUAL_RECEIPT_DOMAIN: &str = "fss.ledger_counterfactual_receipt.v1";
/// Binary wire header magic for serialized counterfactual recompilation receipts.
pub const COUNTERFACTUAL_RECEIPT_MAGIC: [u8; 8] = *b"FSSCFBR1";
/// Supported durable format version for [`CounterfactualRecompileReceipt`].
pub const COUNTERFACTUAL_RECEIPT_VERSION: u32 = 1;
/// Hard ceiling on hypothetical overlay deltas in one counterfactual branch.
pub const MAX_OVERLAY_DELTAS: usize = 1_024;
/// Hard ceiling on serialized receipt wire bytes (512 KiB).
pub const MAX_COUNTERFACTUAL_WIRE_BYTES: usize = 512 * 1024;
/// Hard ceiling on label/diagnostic UTF-8 bytes.
pub const MAX_COUNTERFACTUAL_LABEL_BYTES: usize = 256;

/// Explicit authority context for counterfactual branch exploration (`grants_effect_authority` MUST be `false`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchAuthorityContext {
    /// Pinned `ContractBasis` digest.
    pub contract_basis_digest: ContentDigest,
    /// Active authority generation.
    pub authority_generation: u64,
    /// Expected authority generation.
    pub expected_authority_generation: u64,
    /// Active privacy policy epoch.
    pub privacy_epoch: u64,
    /// True while branch read/cognition capability remains active.
    pub capability_active: bool,
    /// True while privacy authorization remains active.
    pub privacy_active: bool,
    /// Semantic planes authorized for hypothetical deltas in this branch.
    pub allowed_planes: BTreeSet<Plane>,
    /// MUST remain `false`: counterfactual branches NEVER carry live effect authority!
    pub grants_effect_authority: bool,
}

impl BranchAuthorityContext {
    /// Constructs an active read/cognition-only branch authority (`grants_effect_authority = false`).
    #[must_use]
    pub fn active(
        contract_basis_digest: ContentDigest,
        authority_generation: u64,
        privacy_epoch: u64,
        allowed_planes: impl IntoIterator<Item = Plane>,
    ) -> Self {
        Self {
            contract_basis_digest,
            authority_generation,
            expected_authority_generation: authority_generation,
            privacy_epoch,
            capability_active: true,
            privacy_active: true,
            allowed_planes: allowed_planes.into_iter().collect(),
            grants_effect_authority: false,
        }
    }

    fn validate(&self) -> Result<(), CounterfactualError> {
        if self.grants_effect_authority {
            return Err(CounterfactualError::AuthorityRefused(
                "counterfactual branch cannot carry effect authority".to_owned(),
            ));
        }
        if !self.capability_active || !self.privacy_active {
            return Err(CounterfactualError::AuthorityRefused(
                "branch capability or privacy authorization revoked".to_owned(),
            ));
        }
        if self.authority_generation != self.expected_authority_generation {
            return Err(CounterfactualError::AuthorityRefused(format!(
                "stale authority generation {} != expected {}",
                self.authority_generation, self.expected_authority_generation
            )));
        }
        if self.allowed_planes.is_empty() {
            return Err(CounterfactualError::AuthorityRefused(
                "branch authority must authorize at least one semantic plane".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Safe operator/agent recovery guidance for a refused counterfactual operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CounterfactualGuidance {
    /// Re-authorize branch capability/privacy or strip forbidden effect authority.
    ReauthorizeBranch,
    /// Repair invalid branch label, generation progression, or intent structure.
    RepairBranchInput,
    /// Do not launder counterfactual overlay assumptions into live commits; materialize or drop them explicitly.
    RemoveCounterfactualDependency,
    /// Live canonical head diverged semantically; escalate or re-derive fresh intent at head.
    ReanchorAtLiveHead,
    /// Obtain certified absence coverage before recompiling absence-dependent intent.
    WaitForCertifiedCoverage,
    /// Cooperative cancellation observed; safe to retry cleanly.
    RetryWhenReady,
    /// Reject corrupt or unsupported binary recompilation receipt bytes.
    RejectCorruptReceipt,
}

/// Typed error returned by [`CounterfactualBranchOverlay`] or [`CounterfactualRecompileReceipt`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CounterfactualError {
    /// Authority, privacy, generation, plane, or forbidden effect-authority refusal.
    AuthorityRefused(String),
    /// Cooperative cancellation observed before completing the operation.
    Cancelled,
    /// Invalid label, basis mismatch, or overlay generation conflict.
    InvalidInput(String),
    /// Overlay delta count or wire size exceeded hard bounds.
    BoundsExceeded {
        /// Observed count/size.
        observed: usize,
        /// Hard maximum.
        maximum: usize,
    },
    /// Structural intent error from [`CommitIntent`].
    Intent(CommitCombinerError),
    /// Underlying merge ladder error.
    Merge(MergeLadderError),
    /// Binary receipt lacked [`COUNTERFACTUAL_RECEIPT_MAGIC`].
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
    /// Underlying ledger or encoder error.
    Ledger(String),
}

impl CounterfactualError {
    /// Stable canonical machine error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::AuthorityRefused(_) => "ERR-LEDGER-COUNTERFACTUAL-AUTHORITY-001",
            Self::Cancelled => "ERR-LEDGER-COUNTERFACTUAL-CANCELLED-001",
            Self::InvalidInput(_) | Self::Intent(_) => "ERR-LEDGER-COUNTERFACTUAL-INPUT-001",
            Self::BoundsExceeded { .. } => "ERR-LEDGER-COUNTERFACTUAL-BOUNDS-001",
            Self::Merge(_) | Self::Ledger(_) => "ERR-LEDGER-COUNTERFACTUAL-RECOMPILE-001",
            Self::InvalidMagic => "ERR-LEDGER-COUNTERFACTUAL-INVALID-MAGIC-001",
            Self::UnsupportedVersion { .. } => "ERR-LEDGER-COUNTERFACTUAL-UNSUPPORTED-VERSION-001",
            Self::MalformedWire(_) => "ERR-LEDGER-COUNTERFACTUAL-MALFORMED-WIRE-001",
            Self::ChecksumMismatch => "ERR-LEDGER-COUNTERFACTUAL-CHECKSUM-MISMATCH-001",
        }
    }

    /// Safe recovery guidance.
    #[must_use]
    pub const fn guidance(&self) -> CounterfactualGuidance {
        match self {
            Self::AuthorityRefused(_) => CounterfactualGuidance::ReauthorizeBranch,
            Self::Cancelled => CounterfactualGuidance::RetryWhenReady,
            Self::InvalidInput(_) | Self::Intent(_) | Self::BoundsExceeded { .. } => {
                CounterfactualGuidance::RepairBranchInput
            }
            Self::Merge(_) | Self::Ledger(_) => CounterfactualGuidance::ReanchorAtLiveHead,
            Self::InvalidMagic
            | Self::UnsupportedVersion { .. }
            | Self::MalformedWire(_)
            | Self::ChecksumMismatch => CounterfactualGuidance::RejectCorruptReceipt,
        }
    }
}

impl fmt::Display for CounterfactualError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {self:?}", self.code())
    }
}

impl Error for CounterfactualError {}

impl From<CommitCombinerError> for CounterfactualError {
    fn from(value: CommitCombinerError) -> Self {
        Self::Intent(value)
    }
}

impl From<MergeLadderError> for CounterfactualError {
    fn from(value: MergeLadderError) -> Self {
        Self::Merge(value)
    }
}

/// Non-collapsed read state distinguishing canonical history from hypothetical branch overlay deltas.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OverlayReadState {
    /// Object exists in canonical history at `basis_anchor` and was NOT modified in this branch.
    CanonicalUnmodified {
        /// Canonical revision at `basis_anchor`.
        revision: ObjectRevision,
    },
    /// Object is ABSENT in canonical history at `basis_anchor`, created ONLY inside this overlay.
    HypotheticallyCreated {
        /// Overlay revision (never canonical).
        overlay_revision: ObjectRevision,
    },
    /// Object exists in canonical history AND was hypothetically modified inside this overlay.
    HypotheticallyUpdated {
        /// Original canonical revision at `basis_anchor`.
        canonical_revision: ObjectRevision,
        /// Hypothetical overlay revision (never canonical).
        overlay_revision: ObjectRevision,
    },
    /// Object is absent in both canonical `basis_anchor` and this counterfactual branch overlay.
    AbsentInBoth,
}

/// Isolated counterfactual branch overlay anchored at an exact canonical `(basis_anchor, basis_history_root)`.
#[derive(Clone, Debug)]
pub struct CounterfactualBranchOverlay {
    branch_id: String,
    basis_anchor: LedgerAnchor,
    basis_history_root: ContentDigest,
    authority: BranchAuthorityContext,
    max_overlay_deltas: usize,
    overlay_deltas: Vec<EvidenceDelta>,
    overlay_objects: BTreeMap<ObjectId, ObjectRevision>,
}

impl CounterfactualBranchOverlay {
    /// Opens a new isolated counterfactual branch pinned at `oracle.head_anchor()` WITHOUT
    /// mutating `oracle`.
    pub fn open(
        branch_id: &str,
        oracle: &LedgerOracle,
        authority: BranchAuthorityContext,
        max_overlay_deltas: usize,
        cancelled: bool,
    ) -> Result<Self, CounterfactualError> {
        if cancelled {
            return Err(CounterfactualError::Cancelled);
        }
        authority.validate()?;
        validate_label(branch_id, MAX_COUNTERFACTUAL_LABEL_BYTES, "branch_id")?;
        if max_overlay_deltas == 0 || max_overlay_deltas > MAX_OVERLAY_DELTAS {
            return Err(CounterfactualError::BoundsExceeded {
                observed: max_overlay_deltas,
                maximum: MAX_OVERLAY_DELTAS,
            });
        }
        Ok(Self {
            branch_id: branch_id.to_owned(),
            basis_anchor: oracle.head_anchor().clone(),
            basis_history_root: oracle.head_history_root(),
            authority,
            max_overlay_deltas,
            overlay_deltas: Vec::new(),
            overlay_objects: BTreeMap::new(),
        })
    }

    /// Stable counterfactual branch identity.
    #[must_use]
    pub fn branch_id(&self) -> &str {
        &self.branch_id
    }

    /// Exact canonical basis anchor pinned when this branch opened.
    #[must_use]
    pub const fn basis_anchor(&self) -> &LedgerAnchor {
        &self.basis_anchor
    }

    /// Exact canonical history root pinned when this branch opened.
    #[must_use]
    pub const fn basis_history_root(&self) -> ContentDigest {
        self.basis_history_root
    }

    /// Number of hypothetical deltas layered inside this branch.
    #[must_use]
    pub fn overlay_delta_count(&self) -> usize {
        self.overlay_deltas.len()
    }

    /// Canonical object identities touched hypothetically inside this branch overlay.
    #[must_use]
    pub fn overlay_object_ids(&self) -> BTreeSet<ObjectId> {
        self.overlay_objects.keys().cloned().collect()
    }

    /// Deterministic digest over `(branch_id, basis_anchor, basis_history_root, overlay_deltas)`.
    pub fn overlay_digest(&self) -> Result<ContentDigest, CounterfactualError> {
        let mut enc = CanonicalEncoder::new();
        enc.text("fss.ledger_counterfactual_receipt.v1");
        enc.text("overlay_state");
        enc.text(&self.branch_id);
        self.basis_anchor.encode_canonical(&mut enc);
        enc.digest(self.basis_history_root);
        enc.u64(self.overlay_deltas.len() as u64);
        for d in &self.overlay_deltas {
            d.encode_canonical(&mut enc);
        }
        let bytes = enc
            .finish_checked()
            .map_err(|e| CounterfactualError::Ledger(e.to_string()))?;
        Ok(ContentDigest::sha256(&bytes))
    }

    /// Applies one hypothetical [`EvidenceDelta`] strictly inside this isolated overlay without
    /// touching `oracle`. Enforces semantic-plane authorization and exact generation continuity.
    pub fn apply_hypothetical_delta(
        &mut self,
        oracle: &LedgerOracle,
        delta: EvidenceDelta,
        cancelled: bool,
    ) -> Result<(), CounterfactualError> {
        if cancelled {
            return Err(CounterfactualError::Cancelled);
        }
        self.authority.validate()?;
        validate_label(&delta.delta_id, MAX_COUNTERFACTUAL_LABEL_BYTES, "delta_id")?;
        validate_label(
            &delta.family,
            MAX_COUNTERFACTUAL_LABEL_BYTES,
            "delta_family",
        )?;
        if !self.authority.allowed_planes.contains(&delta.plane) {
            return Err(CounterfactualError::AuthorityRefused(format!(
                "delta plane {:?} is outside branch allowed_planes",
                delta.plane
            )));
        }
        if self
            .overlay_deltas
            .iter()
            .any(|existing| existing.delta_id == delta.delta_id)
        {
            return Err(CounterfactualError::InvalidInput(format!(
                "duplicate hypothetical delta_id '{}'",
                delta.delta_id
            )));
        }
        if self.overlay_deltas.len() >= self.max_overlay_deltas {
            return Err(CounterfactualError::BoundsExceeded {
                observed: self.overlay_deltas.len().saturating_add(1),
                maximum: self.max_overlay_deltas,
            });
        }
        self.ensure_oracle_matches_basis(oracle)?;

        let current_gen = match self.read_object(oracle, &delta.object_id)? {
            OverlayReadState::CanonicalUnmodified { revision } => Some(revision.generation),
            OverlayReadState::HypotheticallyCreated { overlay_revision }
            | OverlayReadState::HypotheticallyUpdated {
                overlay_revision, ..
            } => Some(overlay_revision.generation),
            OverlayReadState::AbsentInBoth => None,
        };
        let expected_new = current_gen.map_or(1, |g| g.saturating_add(1));
        if delta.prior_generation != current_gen || delta.new_generation != expected_new {
            return Err(CounterfactualError::InvalidInput(format!(
                "hypothetical delta generation {:?}/{} does not follow overlay state {:?}",
                delta.prior_generation, delta.new_generation, current_gen
            )));
        }

        let rev = ObjectRevision {
            family: delta.family.clone(),
            generation: delta.new_generation,
            plane: delta.plane,
            payload_digest: delta.payload_digest,
            validity: delta.validity,
        };
        self.overlay_objects.insert(delta.object_id.clone(), rev);
        self.overlay_deltas.push(delta);
        Ok(())
    }

    /// Reads `object_id` through this branch overlay without ever collapsing hypothetical vs canonical state.
    pub fn read_object(
        &self,
        oracle: &LedgerOracle,
        object_id: &ObjectId,
    ) -> Result<OverlayReadState, CounterfactualError> {
        self.ensure_oracle_matches_basis(oracle)?;
        let basis_view = oracle
            .view_at(self.basis_anchor.commit_sequence)
            .map_err(|e| CounterfactualError::Ledger(e.to_string()))?;
        let canonical = match basis_view.object(object_id) {
            ObjectRead::Present { revision, .. } => Some(revision.clone()),
            ObjectRead::AbsentAtAnchor { .. } => None,
        };
        let overlay = self.overlay_objects.get(object_id).cloned();
        Ok(match (canonical, overlay) {
            (Some(c), None) => OverlayReadState::CanonicalUnmodified { revision: c },
            (None, Some(o)) => OverlayReadState::HypotheticallyCreated {
                overlay_revision: o,
            },
            (Some(c), Some(o)) => OverlayReadState::HypotheticallyUpdated {
                canonical_revision: c,
                overlay_revision: o,
            },
            (None, None) => OverlayReadState::AbsentInBoth,
        })
    }

    /// Returns the explicit diff between this branch overlay and canonical `basis_anchor`.
    pub fn diff_from_canonical(
        &self,
        oracle: &LedgerOracle,
    ) -> Result<BTreeMap<ObjectId, OverlayReadState>, CounterfactualError> {
        let mut diff = BTreeMap::new();
        for obj_id in self.overlay_objects.keys() {
            diff.insert(obj_id.clone(), self.read_object(oracle, obj_id)?);
        }
        Ok(diff)
    }

    /// Recompiles a branch-derived candidate [`CommitIntent`] onto `oracle.head_anchor()` so it
    /// can be safely submitted to [`crate::DeterministicCommitCombiner`].
    ///
    /// - Refuses if `candidate_intent` depends on unpromoted counterfactual-only overlay objects
    ///   whose generations diverge from canonical `basis_anchor`;
    /// - Verifies capability, privacy, authority generation, and plane scope BEFORE recompiling;
    /// - Re-verifies directly at head when canonical history has not advanced, or delegates to
    ///   `FSS-105` [`MergeLadder::certify_merge`] when canonical history advanced;
    /// - Never mutates `oracle` and never promotes counterfactual state as canonical truth!
    pub fn recompile_for_live_head(
        &self,
        oracle: &LedgerOracle,
        candidate_intent: &CommitIntent,
        commutative_families: &CommutativeFamilyRegistry,
        replay_fn: Option<IntentReplayFn<'_>>,
        recompiled_at: TimestampNs,
        cancelled: bool,
    ) -> Result<RecompileOutcome, CounterfactualError> {
        if cancelled {
            return Err(CounterfactualError::Cancelled);
        }
        self.authority.validate()?;
        candidate_intent.validate_structure()?;
        self.ensure_oracle_matches_basis(oracle)?;

        // Verify candidate intent authority/privacy/planes match active scope!
        if !candidate_intent.authority.capability_active
            || !candidate_intent.authority.privacy_active
            || candidate_intent.authority.authority_generation
                != candidate_intent.authority.expected_authority_generation
            || candidate_intent.authority.authority_generation
                != self.authority.authority_generation
            || candidate_intent.authority.privacy_epoch != self.authority.privacy_epoch
            || !candidate_intent
                .authority
                .allowed_planes
                .is_subset(&self.authority.allowed_planes)
            || candidate_intent.writes.iter().any(|w| {
                !candidate_intent.authority.allowed_planes.contains(&w.plane)
                    || !self.authority.allowed_planes.contains(&w.plane)
            })
        {
            return Ok(RecompileOutcome::Refused {
                reason: RecompileRefusalReason::AuthorityOrPrivacyRefused,
                offending_object: None,
                detail:
                    "candidate intent authority, privacy epoch, generation, or plane scope refused"
                        .to_owned(),
                guidance: CounterfactualGuidance::ReauthorizeBranch,
            });
        }

        if candidate_intent.basis_anchor != self.basis_anchor
            || candidate_intent.basis_history_root != self.basis_history_root
        {
            return Ok(RecompileOutcome::Refused {
                reason: RecompileRefusalReason::BasisAnchorMismatch,
                offending_object: None,
                detail: "candidate intent basis_anchor disagrees with counterfactual branch basis"
                    .to_owned(),
                guidance: CounterfactualGuidance::ReanchorAtLiveHead,
            });
        }

        // Guard: NEVER allow a live-recompiled intent to launder hypothetical overlay state
        // (either read witnesses or write generations) that does NOT exist in canonical history!
        let basis_view = oracle
            .view_at(self.basis_anchor.commit_sequence)
            .map_err(|e| CounterfactualError::Ledger(e.to_string()))?;
        for w in &candidate_intent.read_witnesses {
            if let Some(offending) =
                find_counterfactual_read_laundering(w, &basis_view, &self.overlay_objects)
            {
                return Ok(RecompileOutcome::Refused {
                    reason: RecompileRefusalReason::CounterfactualAssumptionNotCanonical,
                    offending_object: Some(offending.clone()),
                    detail: format!(
                        "read witness for '{}' matches unpromoted counterfactual overlay state rather than canonical basis",
                        offending.as_str()
                    ),
                    guidance: CounterfactualGuidance::RemoveCounterfactualDependency,
                });
            }
        }
        for delta in &candidate_intent.writes {
            let canonical_gen = match basis_view.object(&delta.object_id) {
                ObjectRead::Present { revision, .. } => Some(revision.generation),
                ObjectRead::AbsentAtAnchor { .. } => None,
            };
            let expected_canonical_new = canonical_gen.map_or(1, |g| g.saturating_add(1));
            if self.overlay_objects.contains_key(&delta.object_id)
                && (delta.prior_generation != canonical_gen
                    || delta.new_generation != expected_canonical_new)
            {
                return Ok(RecompileOutcome::Refused {
                    reason: RecompileRefusalReason::CounterfactualAssumptionNotCanonical,
                    offending_object: Some(delta.object_id.clone()),
                    detail: format!(
                        "write to '{}' depends on unpromoted counterfactual overlay generation {:?} (canonical {:?})",
                        delta.object_id.as_str(),
                        delta.prior_generation,
                        canonical_gen
                    ),
                    guidance: CounterfactualGuidance::RemoveCounterfactualDependency,
                });
            }
        }

        let head_anchor = oracle.head_anchor().clone();
        let head_history_root = oracle.head_history_root();
        let overlay_digest = self.overlay_digest()?;
        let source_intent_digest = candidate_intent.canonical_digest()?;

        // Fast path: canonical head has NOT advanced past `basis_anchor`!
        if head_anchor == self.basis_anchor && head_history_root == self.basis_history_root {
            for w in &candidate_intent.read_witnesses {
                if w.anchor() != &head_anchor
                    || w.history_root() != head_history_root
                    || w.verify_against_oracle(oracle, false).is_err()
                {
                    return Ok(RecompileOutcome::Refused {
                        reason: RecompileRefusalReason::InvalidOrStaleWitness,
                        offending_object: None,
                        detail: "candidate read witness failed canonical verification at head"
                            .to_owned(),
                        guidance: CounterfactualGuidance::ReanchorAtLiveHead,
                    });
                }
                if !all_negative_certified(w) {
                    return Ok(RecompileOutcome::Refused {
                        reason: RecompileRefusalReason::UncertifiedAbsenceBasis,
                        offending_object: None,
                        detail: "candidate negative read witness lacks certified absence coverage"
                            .to_owned(),
                        guidance: CounterfactualGuidance::WaitForCertifiedCoverage,
                    });
                }
            }
            for delta in &candidate_intent.writes {
                let cur_gen = match basis_view.object(&delta.object_id) {
                    ObjectRead::Present { revision, .. } => Some(revision.generation),
                    ObjectRead::AbsentAtAnchor { .. } => None,
                };
                let expected_new = cur_gen.map_or(1, |g| g.saturating_add(1));
                if delta.prior_generation != cur_gen || delta.new_generation != expected_new {
                    return Ok(RecompileOutcome::Refused {
                        reason: RecompileRefusalReason::LiveHeadSemanticConflict,
                        offending_object: Some(delta.object_id.clone()),
                        detail: "candidate write generation disagrees with canonical head"
                            .to_owned(),
                        guidance: CounterfactualGuidance::ReanchorAtLiveHead,
                    });
                }
            }
            let receipt = seal_recompile_receipt(
                &self.branch_id,
                &self.basis_anchor,
                self.basis_history_root,
                overlay_digest,
                &head_anchor,
                head_history_root,
                source_intent_digest,
                source_intent_digest,
                RecompileStrategy::DirectHeadMatch,
                None,
                &self.authority,
                recompiled_at,
            )?;
            return Ok(RecompileOutcome::Compiled {
                live_intent: Box::new(candidate_intent.clone()),
                merge_certificate: None,
                receipt: Box::new(receipt),
            });
        }

        // Live head advanced: delegate soundly to FSS-105 MergeLadder!
        match MergeLadder::certify_merge(
            oracle,
            candidate_intent,
            commutative_families,
            replay_fn,
            cancelled,
        )? {
            MergeOutcome::Certified {
                rebased_intent,
                certificate,
            } => {
                if rebased_intent
                    .writes
                    .iter()
                    .any(|w| !self.authority.allowed_planes.contains(&w.plane))
                {
                    return Ok(RecompileOutcome::Refused {
                        reason: RecompileRefusalReason::AuthorityOrPrivacyRefused,
                        offending_object: None,
                        detail: "rebased intent escaped branch semantic plane boundary".to_owned(),
                        guidance: CounterfactualGuidance::ReauthorizeBranch,
                    });
                }
                let live_digest = rebased_intent.canonical_digest()?;
                let strategy = RecompileStrategy::MergeLadderRebased(certificate.rung);
                let receipt = seal_recompile_receipt(
                    &self.branch_id,
                    &self.basis_anchor,
                    self.basis_history_root,
                    overlay_digest,
                    &head_anchor,
                    head_history_root,
                    source_intent_digest,
                    live_digest,
                    strategy,
                    Some(certificate.certificate_digest),
                    &self.authority,
                    recompiled_at,
                )?;
                Ok(RecompileOutcome::Compiled {
                    live_intent: rebased_intent,
                    merge_certificate: Some(certificate),
                    receipt: Box::new(receipt),
                })
            }
            MergeOutcome::Refused {
                reason,
                conflicting_object,
                detail,
                ..
            } => {
                let (mapped_reason, guidance) = match reason {
                    MergeRefusalReason::AuthorityOrPrivacyRefused => (
                        RecompileRefusalReason::AuthorityOrPrivacyRefused,
                        CounterfactualGuidance::ReauthorizeBranch,
                    ),
                    MergeRefusalReason::UncertifiedAbsenceBasis => (
                        RecompileRefusalReason::UncertifiedAbsenceBasis,
                        CounterfactualGuidance::WaitForCertifiedCoverage,
                    ),
                    MergeRefusalReason::DivergentOrFutureBasis
                    | MergeRefusalReason::InterveningSpanTooLarge => (
                        RecompileRefusalReason::BasisAnchorMismatch,
                        CounterfactualGuidance::ReanchorAtLiveHead,
                    ),
                    MergeRefusalReason::InvalidSourceWitness => (
                        RecompileRefusalReason::InvalidOrStaleWitness,
                        CounterfactualGuidance::ReanchorAtLiveHead,
                    ),
                    MergeRefusalReason::IrreconcilableSemanticConflict => (
                        RecompileRefusalReason::LiveHeadSemanticConflict,
                        CounterfactualGuidance::ReanchorAtLiveHead,
                    ),
                };
                Ok(RecompileOutcome::Refused {
                    reason: mapped_reason,
                    offending_object: conflicting_object,
                    detail,
                    guidance,
                })
            }
        }
    }

    fn ensure_oracle_matches_basis(
        &self,
        oracle: &LedgerOracle,
    ) -> Result<(), CounterfactualError> {
        let seq = self.basis_anchor.commit_sequence;
        if oracle.anchor_at(seq) != Some(&self.basis_anchor)
            || oracle.history_root_at(seq) != Some(self.basis_history_root)
        {
            return Err(CounterfactualError::InvalidInput(
                "supplied LedgerOracle diverged from branch basis_anchor or basis_history_root"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

/// Strategy used to safely recompile a branch intent onto the live canonical head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecompileStrategy {
    /// Canonical head remained unchanged at `basis_anchor`; verified directly.
    DirectHeadMatch,
    /// Canonical head advanced; soundly rebased through `FSS-105` [`MergeLadder`] rung.
    MergeLadderRebased(MergeRung),
}

impl RecompileStrategy {
    /// Stable canonical machine spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DirectHeadMatch => "direct_head_match",
            Self::MergeLadderRebased(MergeRung::CommutativeAlgebraic) => {
                "merge_ladder_commutative_algebraic"
            }
            Self::MergeLadderRebased(MergeRung::StructuralNonOverlapping) => {
                "merge_ladder_structural_non_overlapping"
            }
            Self::MergeLadderRebased(MergeRung::DeterministicIntentReplay) => {
                "merge_ladder_deterministic_intent_replay"
            }
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::DirectHeadMatch => 1,
            Self::MergeLadderRebased(MergeRung::CommutativeAlgebraic) => 2,
            Self::MergeLadderRebased(MergeRung::StructuralNonOverlapping) => 3,
            Self::MergeLadderRebased(MergeRung::DeterministicIntentReplay) => 4,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, ContractError> {
        match tag {
            1 => Ok(Self::DirectHeadMatch),
            2 => Ok(Self::MergeLadderRebased(MergeRung::CommutativeAlgebraic)),
            3 => Ok(Self::MergeLadderRebased(
                MergeRung::StructuralNonOverlapping,
            )),
            4 => Ok(Self::MergeLadderRebased(
                MergeRung::DeterministicIntentReplay,
            )),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Non-collapsed refusal reason when a branch-derived intent cannot recompile onto live head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecompileRefusalReason {
    /// Branch or intent capability, privacy, generation, or plane authorization refused.
    AuthorityOrPrivacyRefused,
    /// Candidate intent depended on hypothetical overlay state not present in canonical history.
    CounterfactualAssumptionNotCanonical,
    /// Candidate intent basis anchor diverged from branch basis or exceeded span limits.
    BasisAnchorMismatch,
    /// Candidate read witness failed canonical verification.
    InvalidOrStaleWitness,
    /// Candidate negative read witness lacked certified absence coverage.
    UncertifiedAbsenceBasis,
    /// Live canonical head mutated incompatibly with candidate reads/writes.
    LiveHeadSemanticConflict,
}

/// Non-collapsed outcome of [`CounterfactualBranchOverlay::recompile_for_live_head`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecompileOutcome {
    /// Successfully compiled into a head-anchored live [`CommitIntent`] ready for `FSS-104` combiner.
    Compiled {
        /// Head-anchored canonical [`CommitIntent`].
        live_intent: Box<CommitIntent>,
        /// Optional `FSS-105` [`MergeCertificate`] when live head had advanced past `basis_anchor`.
        merge_certificate: Option<Box<MergeCertificate>>,
        /// Sealed verifiable recompilation receipt (`FSSCFBR1` v1).
        receipt: Box<CounterfactualRecompileReceipt>,
    },
    /// Refused cleanly without mutating canonical history or laundering counterfactual state.
    Refused {
        /// Typed refusal classification.
        reason: RecompileRefusalReason,
        /// Offending object identity, if applicable.
        offending_object: Option<ObjectId>,
        /// Secret-free diagnostic detail.
        detail: String,
        /// Safe recovery guidance.
        guidance: CounterfactualGuidance,
    },
}

/// Sealed binary receipt binding counterfactual branch exploration to live-head intent recompilation (`FSSCFBR1` v1).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CounterfactualRecompileReceipt {
    /// Wire format version (`COUNTERFACTUAL_RECEIPT_VERSION`).
    pub format_version: u32,
    /// Stable counterfactual branch identity.
    pub branch_id: String,
    /// Exact pinned `ContractBasis` digest.
    pub contract_basis_digest: ContentDigest,
    /// Original branch basis anchor.
    pub basis_anchor: LedgerAnchor,
    /// Original branch basis history root.
    pub basis_history_root: ContentDigest,
    /// Commitment over branch hypothetical overlay deltas.
    pub overlay_digest: ContentDigest,
    /// Target live canonical head anchor.
    pub live_head_anchor: LedgerAnchor,
    /// Target live canonical head history root.
    pub live_head_history_root: ContentDigest,
    /// Original branch-derived candidate intent digest.
    pub source_intent_digest: ContentDigest,
    /// Live head-anchored recompiled intent digest.
    pub live_intent_digest: ContentDigest,
    /// Strategy that certified live recompilation.
    pub strategy: RecompileStrategy,
    /// Optional `FSS-105` `MergeCertificate` digest (present iff `strategy == MergeLadderRebased(_)`).
    pub merge_certificate_digest: Option<ContentDigest>,
    /// Authority generation verified during recompilation.
    pub authority_generation: u64,
    /// Privacy policy epoch verified during recompilation.
    pub privacy_epoch: u64,
    /// Timestamp when this receipt was sealed.
    pub recompiled_at: TimestampNs,
    /// Domain-separated SHA-256 commitment (`fss.ledger_counterfactual_receipt.v1`).
    pub receipt_digest: ContentDigest,
}

impl CounterfactualRecompileReceipt {
    /// Recomputes the domain-separated SHA-256 commitment (`fss.ledger_counterfactual_receipt.v1`).
    pub fn compute_digest(&self) -> Result<ContentDigest, CounterfactualError> {
        let mut enc = CanonicalEncoder::new();
        enc.text(LEDGER_COUNTERFACTUAL_RECEIPT_DOMAIN);
        self.encode_body(&mut enc);
        let bytes = enc
            .finish_checked()
            .map_err(|e| CounterfactualError::Ledger(e.to_string()))?;
        Ok(ContentDigest::sha256(&bytes))
    }

    /// Verifies structural invariants, strategy/certificate consistency, and self-digest.
    pub fn verify_self(&self) -> Result<(), CounterfactualError> {
        if self.format_version != COUNTERFACTUAL_RECEIPT_VERSION {
            return Err(CounterfactualError::UnsupportedVersion {
                version: self.format_version,
            });
        }
        validate_label(&self.branch_id, MAX_COUNTERFACTUAL_LABEL_BYTES, "branch_id")
            .map_err(|e| CounterfactualError::MalformedWire(e.to_string()))?;
        if self.basis_anchor.site_lineage != self.live_head_anchor.site_lineage
            || self.basis_anchor.ledger_epoch != self.live_head_anchor.ledger_epoch
            || self.live_head_anchor.commit_sequence < self.basis_anchor.commit_sequence
        {
            return Err(CounterfactualError::MalformedWire(
                "live_head_anchor must advance monotonically on the same lineage and epoch"
                    .to_owned(),
            ));
        }
        match self.strategy {
            RecompileStrategy::DirectHeadMatch => {
                if self.merge_certificate_digest.is_some()
                    || self.live_head_anchor != self.basis_anchor
                    || self.live_head_history_root != self.basis_history_root
                {
                    return Err(CounterfactualError::MalformedWire(
                        "DirectHeadMatch requires identical basis/head anchor and no merge certificate"
                            .to_owned(),
                    ));
                }
            }
            RecompileStrategy::MergeLadderRebased(_) => {
                if self.merge_certificate_digest.is_none() {
                    return Err(CounterfactualError::MalformedWire(
                        "MergeLadderRebased requires a sealed merge_certificate_digest".to_owned(),
                    ));
                }
            }
        }
        if self.compute_digest()? != self.receipt_digest {
            return Err(CounterfactualError::ChecksumMismatch);
        }
        Ok(())
    }

    fn encode_body(&self, enc: &mut CanonicalEncoder) {
        enc.u32(self.format_version);
        enc.text(&self.branch_id);
        enc.digest(self.contract_basis_digest);
        self.basis_anchor.encode_canonical(enc);
        enc.digest(self.basis_history_root);
        enc.digest(self.overlay_digest);
        self.live_head_anchor.encode_canonical(enc);
        enc.digest(self.live_head_history_root);
        enc.digest(self.source_intent_digest);
        enc.digest(self.live_intent_digest);
        enc.u8(self.strategy.tag());
        match self.merge_certificate_digest {
            Some(d) => {
                enc.u8(1);
                enc.digest(d);
            }
            None => enc.u8(0),
        }
        enc.u64(self.authority_generation);
        enc.u64(self.privacy_epoch);
        self.recompiled_at.encode_canonical(enc);
    }

    /// Encodes this receipt into bounded checksummed binary bytes (`FSSCFBR1` v1).
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, CounterfactualError> {
        self.verify_self()?;
        let mut enc = CanonicalEncoder::new();
        self.encode_body(&mut enc);
        enc.digest(self.receipt_digest);
        let body = enc
            .finish_checked()
            .map_err(|e| CounterfactualError::Ledger(e.to_string()))?;
        let total = COUNTERFACTUAL_RECEIPT_MAGIC
            .len()
            .saturating_add(4)
            .saturating_add(body.len());
        if total > MAX_COUNTERFACTUAL_WIRE_BYTES {
            return Err(CounterfactualError::BoundsExceeded {
                observed: total,
                maximum: MAX_COUNTERFACTUAL_WIRE_BYTES,
            });
        }
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&COUNTERFACTUAL_RECEIPT_MAGIC);
        out.extend_from_slice(&self.format_version.to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Cold-decodes and verifies a binary [`CounterfactualRecompileReceipt`] (`FSSCFBR1` v1).
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CounterfactualError> {
        if bytes.len() > MAX_COUNTERFACTUAL_WIRE_BYTES {
            return Err(CounterfactualError::BoundsExceeded {
                observed: bytes.len(),
                maximum: MAX_COUNTERFACTUAL_WIRE_BYTES,
            });
        }
        if bytes.len() < 12 || bytes[..8] != COUNTERFACTUAL_RECEIPT_MAGIC {
            return Err(CounterfactualError::InvalidMagic);
        }
        let header_ver = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if header_ver != COUNTERFACTUAL_RECEIPT_VERSION {
            return Err(CounterfactualError::UnsupportedVersion {
                version: header_ver,
            });
        }
        let mut dec = CanonicalDecoder::new(&bytes[12..]);
        let format_version = dec
            .u32()
            .map_err(|e| CounterfactualError::MalformedWire(e.to_string()))?;
        if format_version != header_ver {
            return Err(CounterfactualError::UnsupportedVersion {
                version: format_version,
            });
        }
        let branch_id = dec
            .text()
            .map_err(|e| CounterfactualError::MalformedWire(e.to_string()))?
            .to_owned();
        let contract_basis_digest = dec
            .digest()
            .map_err(|e| CounterfactualError::MalformedWire(e.to_string()))?;
        let basis_anchor = LedgerAnchor::decode_canonical(&mut dec)
            .map_err(|e| CounterfactualError::MalformedWire(e.to_string()))?;
        let basis_history_root = dec
            .digest()
            .map_err(|e| CounterfactualError::MalformedWire(e.to_string()))?;
        let overlay_digest = dec
            .digest()
            .map_err(|e| CounterfactualError::MalformedWire(e.to_string()))?;
        let live_head_anchor = LedgerAnchor::decode_canonical(&mut dec)
            .map_err(|e| CounterfactualError::MalformedWire(e.to_string()))?;
        let live_head_history_root = dec
            .digest()
            .map_err(|e| CounterfactualError::MalformedWire(e.to_string()))?;
        let source_intent_digest = dec
            .digest()
            .map_err(|e| CounterfactualError::MalformedWire(e.to_string()))?;
        let live_intent_digest = dec
            .digest()
            .map_err(|e| CounterfactualError::MalformedWire(e.to_string()))?;
        let strategy = RecompileStrategy::from_tag(
            dec.u8()
                .map_err(|e| CounterfactualError::MalformedWire(e.to_string()))?,
        )
        .map_err(|e| CounterfactualError::MalformedWire(e.to_string()))?;
        let merge_certificate_digest = match dec
            .u8()
            .map_err(|e| CounterfactualError::MalformedWire(e.to_string()))?
        {
            0 => None,
            1 => Some(
                dec.digest()
                    .map_err(|e| CounterfactualError::MalformedWire(e.to_string()))?,
            ),
            other => {
                return Err(CounterfactualError::MalformedWire(format!(
                    "invalid merge_certificate_digest tag {other}"
                )));
            }
        };
        let authority_generation = dec
            .u64()
            .map_err(|e| CounterfactualError::MalformedWire(e.to_string()))?;
        let privacy_epoch = dec
            .u64()
            .map_err(|e| CounterfactualError::MalformedWire(e.to_string()))?;
        let recompiled_at = TimestampNs::decode_canonical(&mut dec)
            .map_err(|e| CounterfactualError::MalformedWire(e.to_string()))?;
        let stored_digest = dec
            .digest()
            .map_err(|e| CounterfactualError::MalformedWire(e.to_string()))?;
        dec.ensure_finished().map_err(|_| {
            CounterfactualError::MalformedWire(
                "trailing bytes after counterfactual receipt".to_owned(),
            )
        })?;

        let receipt = Self {
            format_version,
            branch_id,
            contract_basis_digest,
            basis_anchor,
            basis_history_root,
            overlay_digest,
            live_head_anchor,
            live_head_history_root,
            source_intent_digest,
            live_intent_digest,
            strategy,
            merge_certificate_digest,
            authority_generation,
            privacy_epoch,
            recompiled_at,
            receipt_digest: stored_digest,
        };
        receipt.verify_self()?;
        Ok(receipt)
    }
}

#[allow(clippy::too_many_arguments)]
fn seal_recompile_receipt(
    branch_id: &str,
    basis_anchor: &LedgerAnchor,
    basis_history_root: ContentDigest,
    overlay_digest: ContentDigest,
    live_head_anchor: &LedgerAnchor,
    live_head_history_root: ContentDigest,
    source_intent_digest: ContentDigest,
    live_intent_digest: ContentDigest,
    strategy: RecompileStrategy,
    merge_certificate_digest: Option<ContentDigest>,
    authority: &BranchAuthorityContext,
    recompiled_at: TimestampNs,
) -> Result<CounterfactualRecompileReceipt, CounterfactualError> {
    let mut receipt = CounterfactualRecompileReceipt {
        format_version: COUNTERFACTUAL_RECEIPT_VERSION,
        branch_id: branch_id.to_owned(),
        contract_basis_digest: authority.contract_basis_digest,
        basis_anchor: basis_anchor.clone(),
        basis_history_root,
        overlay_digest,
        live_head_anchor: live_head_anchor.clone(),
        live_head_history_root,
        source_intent_digest,
        live_intent_digest,
        strategy,
        merge_certificate_digest,
        authority_generation: authority.authority_generation,
        privacy_epoch: authority.privacy_epoch,
        recompiled_at,
        receipt_digest: ContentDigest::sha256(b"unsealed-counterfactual-receipt"),
    };
    receipt.receipt_digest = receipt.compute_digest()?;
    Ok(receipt)
}

fn find_counterfactual_read_laundering(
    w: &SemanticWitness,
    basis_view: &crate::oracle::AnchoredView<'_>,
    overlay_objects: &BTreeMap<ObjectId, ObjectRevision>,
) -> Option<ObjectId> {
    match w {
        SemanticWitness::Positive(pos) => {
            let overlay_rev = overlay_objects.get(&pos.object_id)?;
            let canonical_matches = match basis_view.object(&pos.object_id) {
                ObjectRead::Present { revision, .. } => {
                    revision.generation == pos.revision.generation
                        && revision.payload_digest == pos.revision.payload_digest
                }
                ObjectRead::AbsentAtAnchor { .. } => false,
            };
            if !canonical_matches
                && overlay_rev.generation == pos.revision.generation
                && overlay_rev.payload_digest == pos.revision.payload_digest
            {
                Some(pos.object_id.clone())
            } else {
                None
            }
        }
        SemanticWitness::Negative(_) => None,
        SemanticWitness::Hierarchical(h) => h
            .children
            .iter()
            .find_map(|c| find_counterfactual_read_laundering(c, basis_view, overlay_objects)),
    }
}

fn all_negative_certified(w: &SemanticWitness) -> bool {
    match w {
        SemanticWitness::Positive(PositiveWitness { .. }) => true,
        SemanticWitness::Negative(NegativeWitness {
            certified,
            coverage,
            ..
        }) => *certified && coverage.certifies_absence(),
        SemanticWitness::Hierarchical(h) => h.children.iter().all(all_negative_certified),
    }
}

fn validate_label(value: &str, max_len: usize, label: &str) -> Result<(), CounterfactualError> {
    if value.is_empty() || value.len() > max_len {
        return Err(CounterfactualError::InvalidInput(format!(
            "{label} length {} outside 1..={max_len}",
            value.len()
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(CounterfactualError::InvalidInput(format!(
            "{label} must not contain control characters"
        )));
    }
    Ok(())
}

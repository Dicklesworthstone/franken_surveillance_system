#![forbid(unsafe_code)]
//! Derived beliefs realization (AGT-LAYER-004, INV-069).
//!
//! Cognition plane types:
//! - [`DerivedBelief`]
//! - [`DerivedBeliefParams`]
//! - [`DerivationInputs`]

use crate::belief::BeliefInterval;
use crate::canonical::{CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder};
use crate::contract::{ContractError, KnowledgeState, Plane, ProvenanceClass};
use crate::{
    ContentDigest, Generation, KnowledgeCell, KnowledgeCellParams, KnowledgeStateBasis,
    LedgerAnchor, StaleBasis,
};

use super::AgentAbstractionLayer;

/// Maximum number of supporting evidence roots allowed for a single [`DerivedBelief`].
pub const MAX_DERIVED_BELIEF_EVIDENCE: usize = 1024;

/// Maximum number of contradicting evidence roots allowed for a single [`DerivedBelief`].
pub const MAX_DERIVED_BELIEF_CONTRADICTIONS: usize = 1024;

/// Encoded width of one canonical digest: one algorithm tag byte plus 32 digest bytes.
const ENCODED_DIGEST_BYTES: usize = 33;

/// Registered digest domain tag (`registries/DIGEST_DOMAINS.md`) hashed first into every
/// derivation receipt.
pub const DERIVED_BELIEF_RECEIPT_DOMAIN: &str = "fss.derived_belief.receipt.v1";

/// Registered digest domain tag (`registries/DIGEST_DOMAINS.md`) that prefixes the canonical
/// encoding in [`DerivedBelief::canonical_digest`], so a belief digest never collides with the
/// digest of another type over the same bytes.
pub const DERIVED_BELIEF_DOMAIN: &str = "fss.derived_belief.v1";

/// An anchor-pinned, generation-pinned derived belief (AGT-LAYER-004, INV-069).
///
/// Derived beliefs represent supported entities, tracks, events, relations, and uncertainties
/// derived from canonical evidence. Per AGENTS.md and INV-069:
/// - Derived state is anchor-pinned and rebuildable.
/// - Derived state lives strictly in the Cognition plane and must NEVER claim authority.
/// - Derived state can NEVER authorize effects or certify absence beyond coverage.
///
/// A value exists only through a validating path ([`DerivedBelief::new`],
/// [`DerivedBelief::rebuild`], or canonical decode), and its fields are private, so no caller can
/// upgrade a validated belief to `known`, zero its generation, or swap its receipt afterwards.
/// Field assignment does not compile:
///
/// ```compile_fail,E0616
/// use fss_core::{DerivedBelief, KnowledgeState};
///
/// fn upgrade(belief: &mut DerivedBelief) {
///     belief.knowledge_state = KnowledgeState::Known;
/// }
/// ```
///
/// Nor does a struct literal that skips validation:
///
/// ```compile_fail,E0451
/// use fss_core::{DerivedBelief, DerivedBeliefParams, Generation, KnowledgeState};
///
/// fn forge(params: DerivedBeliefParams) -> DerivedBelief {
///     DerivedBelief {
///         belief_id: params.belief_id,
///         anchor: params.anchor,
///         generation: Generation(0),
///         statement: params.statement,
///         knowledge_state: KnowledgeState::Known,
///         provenance: params.provenance,
///         uncertainty: params.uncertainty,
///         supporting_evidence: params.supporting_evidence,
///         contradictions: params.contradictions,
///         derivation_receipt: params.derivation_receipt,
///     }
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DerivedBelief {
    /// Stable proposition identity (e.g. `belief:track:001`).
    belief_id: String,
    /// Exact ledger anchor to which this derivation is pinned (INV-069).
    anchor: LedgerAnchor,
    /// Generation identifier for the derivation model/engine.
    generation: Generation,
    /// Compact human-readable statement.
    statement: String,
    /// Epistemic state: never `Known`, and never a state whose registry meaning requires a typed
    /// basis this belief cannot carry (`Stale`, `Redacted`, `Indeterminate`).
    knowledge_state: KnowledgeState,
    /// Epistemic provenance: strictly `ProvenanceClass::Derived`.
    provenance: ProvenanceClass,
    /// Bounded uncertainty micro-probability interval ([0, 1_000_000]).
    uncertainty: BeliefInterval,
    /// Evidence roots supporting the derivation, strictly ascending.
    supporting_evidence: Vec<ContentDigest>,
    /// Contradicting evidence roots, strictly ascending and disjoint from the support set.
    contradictions: Vec<ContentDigest>,
    /// Receipt digest equal to [`DerivedBelief::compute_derivation_receipt`] over the inputs.
    derivation_receipt: ContentDigest,
}

/// Parameters for constructing a [`DerivedBelief`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DerivedBeliefParams {
    /// Stable proposition identity (e.g. `belief:track:001`).
    pub belief_id: String,
    /// Exact ledger anchor to which this derivation is pinned (INV-069).
    pub anchor: LedgerAnchor,
    /// Generation identifier for the derivation model/engine.
    pub generation: Generation,
    /// Compact human-readable statement.
    pub statement: String,
    /// Epistemic state (must NOT be `Known`; derived beliefs are `Estimated`, `Conflicted`, etc.).
    pub knowledge_state: KnowledgeState,
    /// Epistemic provenance: strictly `ProvenanceClass::Derived`.
    pub provenance: ProvenanceClass,
    /// Bounded uncertainty micro-probability interval ([0, 1_000_000]).
    pub uncertainty: BeliefInterval,
    /// Evidence roots supporting the derivation, strictly ascending.
    pub supporting_evidence: Vec<ContentDigest>,
    /// Contradicting evidence roots, strictly ascending and disjoint from the support set.
    pub contradictions: Vec<ContentDigest>,
    /// Receipt digest; must equal [`DerivedBelief::compute_derivation_receipt`] over the inputs.
    pub derivation_receipt: ContentDigest,
}

impl DerivedBeliefParams {
    /// Returns the borrowed derivation inputs that this parameter set hashes into its receipt.
    #[must_use]
    pub fn derivation_inputs(&self) -> DerivationInputs<'_> {
        DerivationInputs {
            belief_id: &self.belief_id,
            anchor: &self.anchor,
            generation: self.generation,
            statement: &self.statement,
            knowledge_state: self.knowledge_state,
            provenance: self.provenance,
            uncertainty: &self.uncertainty,
            supporting_evidence: &self.supporting_evidence,
            contradictions: &self.contradictions,
        }
    }

    /// Replaces `derivation_receipt` with the receipt recomputed from these inputs.
    ///
    /// This is how a deriver seals an honest parameter set. [`DerivedBelief::new`] refuses any
    /// receipt that differs from this recomputation.
    pub fn with_computed_receipt(mut self) -> Result<Self, ContractError> {
        self.derivation_receipt =
            DerivedBelief::compute_derivation_receipt(&self.derivation_inputs())?;
        Ok(self)
    }
}

/// Borrowed derivation inputs hashed into a [`DerivedBelief`] derivation receipt.
///
/// Every field that the receipt witnesses is named here, so the receipt computation takes one
/// typed input instead of a long positional argument list.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DerivationInputs<'a> {
    /// Stable proposition identity.
    pub belief_id: &'a str,
    /// Exact ledger anchor the derivation is pinned to.
    pub anchor: &'a LedgerAnchor,
    /// Generation identifier for the derivation model/engine.
    pub generation: Generation,
    /// Compact human-readable statement.
    pub statement: &'a str,
    /// Epistemic state.
    pub knowledge_state: KnowledgeState,
    /// Epistemic provenance.
    pub provenance: ProvenanceClass,
    /// Bounded uncertainty interval.
    pub uncertainty: &'a BeliefInterval,
    /// Evidence roots supporting the derivation.
    pub supporting_evidence: &'a [ContentDigest],
    /// Contradicting evidence roots.
    pub contradictions: &'a [ContentDigest],
}

/// Returns whether every byte of `digest` is zero.
fn is_all_zero(digest: ContentDigest) -> bool {
    digest.bytes().iter().all(|&byte| byte == 0)
}

/// Returns whether `anchor` names canonical evidence: a site lineage and a non-zero state root.
fn anchor_names_canonical_state(anchor: &LedgerAnchor) -> bool {
    !anchor.site_lineage.is_empty() && !is_all_zero(anchor.state_root)
}

/// Requires a strictly ascending, and therefore duplicate-free, digest set.
///
/// Only one spelling of a set is accepted, so equal sets always yield equal canonical digests.
fn check_strictly_ascending(digests: &[ContentDigest]) -> Result<(), ContractError> {
    for pair in digests.windows(2) {
        match pair {
            [previous, next] if previous == next => {
                return Err(ContractError::DerivedBeliefDuplicateEvidence);
            }
            [previous, next] if previous > next => {
                return Err(ContractError::NonCanonicalOrdering);
            }
            _ => {}
        }
    }
    Ok(())
}

impl DerivedBelief {
    /// Validates and constructs a new derived belief from parameters.
    pub fn new(params: DerivedBeliefParams) -> Result<Self, ContractError> {
        let belief = Self {
            belief_id: params.belief_id,
            anchor: params.anchor,
            generation: params.generation,
            statement: params.statement,
            knowledge_state: params.knowledge_state,
            provenance: params.provenance,
            uncertainty: params.uncertainty,
            supporting_evidence: params.supporting_evidence,
            contradictions: params.contradictions,
            derivation_receipt: params.derivation_receipt,
        };
        belief.validate()?;
        Ok(belief)
    }

    /// Validates all constitutional and semantic invariants for this derived belief (INV-069).
    ///
    /// Checks run in a fixed order, so each defect reports one exact error:
    /// identity, statement, anchor (lineage and non-zero state root), generation, provenance,
    /// `known` refusal, evidence presence and bounds, strictly ascending evidence and
    /// contradiction sets, disjoint support and contradictions, uncertainty bounds, non-zero
    /// receipt, and finally the receipt matching its recomputation from the inputs.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.belief_id.is_empty() || self.belief_id.len() > 128 {
            return Err(ContractError::InvalidIdentifier);
        }
        if self.statement.is_empty() || self.statement.len() > 512 {
            return Err(ContractError::InvalidIdentifier);
        }
        if !anchor_names_canonical_state(&self.anchor) {
            return Err(ContractError::DerivedBeliefMissingAnchor);
        }
        if self.generation.0 == 0 {
            return Err(ContractError::GenerationConflict);
        }
        if self.provenance != ProvenanceClass::Derived {
            return Err(ContractError::KnowledgeStateBasisMismatch);
        }
        if self.knowledge_state == KnowledgeState::Known {
            return Err(ContractError::DerivedBeliefKnownForbidden);
        }
        // States whose registry meaning requires a typed basis (KSTATE-005/007/008) cannot be
        // carried by a derived belief: staleness is expressed by anchor freshness, and redaction
        // and unresolved external outcomes are not derivation results. Each is refused with the
        // exact error `KnowledgeCell::validate` would raise, so no invalid cell can be emitted.
        match self.knowledge_state {
            KnowledgeState::Stale => return Err(ContractError::StaleBasisRequired),
            KnowledgeState::Redacted => return Err(ContractError::RedactionMarkerRequired),
            KnowledgeState::Indeterminate => {
                return Err(ContractError::ReconciliationBasisRequired);
            }
            KnowledgeState::Known
            | KnowledgeState::Estimated
            | KnowledgeState::Unknown
            | KnowledgeState::Conflicted
            | KnowledgeState::NotObservable
            | KnowledgeState::NotApplicable => {}
        }
        if self.supporting_evidence.is_empty() {
            return Err(ContractError::EvidenceRequired);
        }
        if self.supporting_evidence.len() > MAX_DERIVED_BELIEF_EVIDENCE {
            return Err(ContractError::ArithmeticOverflow);
        }
        if self.contradictions.len() > MAX_DERIVED_BELIEF_CONTRADICTIONS {
            return Err(ContractError::ArithmeticOverflow);
        }
        check_strictly_ascending(&self.supporting_evidence)?;
        check_strictly_ascending(&self.contradictions)?;
        if self
            .contradictions
            .iter()
            .any(|digest| self.supporting_evidence.binary_search(digest).is_ok())
        {
            return Err(ContractError::DerivedBeliefEvidenceOverlap);
        }
        if self.uncertainty.lower_micro() > self.uncertainty.upper_micro()
            || self.uncertainty.upper_micro() > crate::belief::MICRO_DENOMINATOR
        {
            return Err(ContractError::InvalidProbabilityInterval);
        }
        if is_all_zero(self.derivation_receipt) {
            return Err(ContractError::InvalidDigest);
        }
        if Self::compute_derivation_receipt(&self.derivation_inputs())? != self.derivation_receipt {
            return Err(ContractError::DigestMismatch);
        }
        Ok(())
    }

    /// Returns the stable proposition identity.
    #[must_use]
    pub fn belief_id(&self) -> &str {
        &self.belief_id
    }

    /// Returns the exact ledger anchor this derivation is pinned to.
    #[must_use]
    pub const fn anchor(&self) -> &LedgerAnchor {
        &self.anchor
    }

    /// Returns the derivation generation.
    #[must_use]
    pub const fn generation(&self) -> Generation {
        self.generation
    }

    /// Returns the compact human-readable statement.
    #[must_use]
    pub fn statement(&self) -> &str {
        &self.statement
    }

    /// Returns the epistemic state (never `Known`).
    #[must_use]
    pub const fn knowledge_state(&self) -> KnowledgeState {
        self.knowledge_state
    }

    /// Returns the provenance class (always `Derived`).
    #[must_use]
    pub const fn provenance(&self) -> ProvenanceClass {
        self.provenance
    }

    /// Returns the bounded uncertainty interval.
    #[must_use]
    pub const fn uncertainty(&self) -> &BeliefInterval {
        &self.uncertainty
    }

    /// Returns the strictly ascending supporting evidence roots.
    #[must_use]
    pub fn supporting_evidence(&self) -> &[ContentDigest] {
        &self.supporting_evidence
    }

    /// Returns the strictly ascending contradicting evidence roots.
    #[must_use]
    pub fn contradictions(&self) -> &[ContentDigest] {
        &self.contradictions
    }

    /// Returns the derivation receipt.
    #[must_use]
    pub const fn derivation_receipt(&self) -> ContentDigest {
        self.derivation_receipt
    }

    /// Returns the borrowed derivation inputs that the receipt witnesses.
    #[must_use]
    pub fn derivation_inputs(&self) -> DerivationInputs<'_> {
        DerivationInputs {
            belief_id: &self.belief_id,
            anchor: &self.anchor,
            generation: self.generation,
            statement: &self.statement,
            knowledge_state: self.knowledge_state,
            provenance: self.provenance,
            uncertainty: &self.uncertainty,
            supporting_evidence: &self.supporting_evidence,
            contradictions: &self.contradictions,
        }
    }

    /// Constitutional Hard Gate: A derived belief can NEVER claim authority (AGENTS.md).
    #[must_use]
    pub const fn may_claim_authority(&self) -> bool {
        false
    }

    /// Constitutional Hard Gate: A derived belief can NEVER authorize effects (INV-069).
    #[must_use]
    pub const fn may_authorize_effects(&self) -> bool {
        false
    }

    /// Returns the semantic plane for this derived belief (`Plane::Cognition`).
    #[must_use]
    pub const fn plane(&self) -> Plane {
        Plane::Cognition
    }

    /// Returns whether this derived belief is anchor-pinned to canonical evidence: its anchor
    /// names a site lineage and a non-zero state root.
    #[must_use]
    pub fn is_anchor_pinned(&self) -> bool {
        anchor_names_canonical_state(&self.anchor)
    }

    /// Verifies that this derived belief is pinned to the exact specified active anchor.
    #[must_use]
    pub fn is_anchor_pinned_to(&self, active_anchor: &LedgerAnchor) -> bool {
        self.is_anchor_pinned() && self.anchor == *active_anchor
    }

    /// Validates this belief's anchor against the caller's current anchor (KSTATE-005 semantics).
    ///
    /// - `current` must itself name canonical state (site lineage and non-zero state root), or
    ///   the check fails with [`ContractError::DerivedBeliefMissingAnchor`].
    /// - An anchor strictly older than `current` under [`StaleBasis::validate`] (same site
    ///   lineage, lower `(ledger_epoch, commit_sequence)`) is stale:
    ///   [`ContractError::StaleAnchor`]. A newer commit in the same epoch therefore makes the
    ///   belief stale.
    /// - Otherwise only the exact pinned anchor is fresh. A same-position anchor with a
    ///   different state root or epoch vector, a future anchor, or a different site lineage is
    ///   refused with [`ContractError::DerivedBeliefAnchorMismatch`].
    pub fn validate_anchor_freshness(&self, current: &LedgerAnchor) -> Result<(), ContractError> {
        if !anchor_names_canonical_state(current) {
            return Err(ContractError::DerivedBeliefMissingAnchor);
        }
        let older = StaleBasis::OlderAnchor {
            valid_at: Box::new(self.anchor.clone()),
            current: Box::new(current.clone()),
        };
        if older.validate().is_ok() {
            return Err(ContractError::StaleAnchor);
        }
        if self.anchor != *current {
            return Err(ContractError::DerivedBeliefAnchorMismatch);
        }
        Ok(())
    }

    /// Returns whether this derived belief can be rebuilt from its canonical derivation inputs:
    /// every invariant holds, including the receipt matching its recomputation.
    #[must_use]
    pub fn is_rebuildable(&self) -> bool {
        self.validate().is_ok()
    }

    /// Rebuilds the derived belief from its canonical derivation inputs.
    ///
    /// The receipt is recomputed from the inputs; a stored receipt that differs from the
    /// recomputation fails with [`ContractError::DigestMismatch`]. The rebuilt value then passes
    /// the full [`DerivedBelief::validate`] again.
    pub fn rebuild(&self) -> Result<Self, ContractError> {
        let recomputed = Self::compute_derivation_receipt(&self.derivation_inputs())?;
        if recomputed != self.derivation_receipt {
            return Err(ContractError::DigestMismatch);
        }
        Self::new(DerivedBeliefParams {
            belief_id: self.belief_id.clone(),
            anchor: self.anchor.clone(),
            generation: self.generation,
            statement: self.statement.clone(),
            knowledge_state: self.knowledge_state,
            provenance: self.provenance,
            uncertainty: self.uncertainty.clone(),
            supporting_evidence: self.supporting_evidence.clone(),
            contradictions: self.contradictions.clone(),
            derivation_receipt: recomputed,
        })
    }

    /// Computes the deterministic canonical digest of this derived belief: SHA-256 over the
    /// [`DERIVED_BELIEF_DOMAIN`] tag followed by the canonical encoding.
    ///
    /// Fails instead of hashing an empty or partial encoding when the encoder records an error.
    pub fn canonical_digest(&self) -> Result<ContentDigest, ContractError> {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(DERIVED_BELIEF_DOMAIN);
        self.encode_canonical(&mut encoder);
        Ok(ContentDigest::sha256(&encoder.finish_checked()?))
    }

    /// Computes the deterministic canonical derivation receipt from derivation inputs.
    ///
    /// The encoding order (domain tag, identity, anchor, generation, statement, state,
    /// provenance, uncertainty, evidence, contradictions) is part of the receipt identity.
    /// An input the encoder refuses (e.g. over-long text) fails instead of hashing empty bytes.
    pub fn compute_derivation_receipt(
        inputs: &DerivationInputs<'_>,
    ) -> Result<ContentDigest, ContractError> {
        let ev_len = u32::try_from(inputs.supporting_evidence.len())
            .map_err(|_| ContractError::ArithmeticOverflow)?;
        let contra_len = u32::try_from(inputs.contradictions.len())
            .map_err(|_| ContractError::ArithmeticOverflow)?;
        let mut encoder = CanonicalEncoder::new();
        encoder.text(DERIVED_BELIEF_RECEIPT_DOMAIN);
        encoder.text(inputs.belief_id);
        inputs.anchor.encode_canonical(&mut encoder);
        encoder.u64(inputs.generation.0);
        encoder.text(inputs.statement);
        inputs.knowledge_state.encode_canonical(&mut encoder);
        inputs.provenance.encode_canonical(&mut encoder);
        inputs.uncertainty.encode_canonical(&mut encoder);
        encoder.u32(ev_len);
        for d in inputs.supporting_evidence {
            encoder.digest(*d);
        }
        encoder.u32(contra_len);
        for d in inputs.contradictions {
            encoder.digest(*d);
        }
        Ok(ContentDigest::sha256(&encoder.finish_checked()?))
    }

    /// Returns the abstraction layer for this belief (`AGT-LAYER-004`).
    #[must_use]
    pub const fn layer(&self) -> AgentAbstractionLayer {
        AgentAbstractionLayer::DerivedBeliefs
    }

    /// Converts this derived belief into a canonical [`KnowledgeCell`] at the caller's anchor.
    ///
    /// This is the boundary where a derived belief reaches agent-facing knowledge. It
    /// re-validates every invariant (so a derived belief can never yield an irreversible-effect
    /// premise: `known` is refused) and evaluates anchor freshness against `current`.
    ///
    /// Per KSTATE-005 and AGENTS.md:
    /// - When `current` equals `self.anchor`, the emitted cell preserves `self.knowledge_state`.
    /// - When `self.anchor` is strictly older than `current` on the same site lineage (anchor drift),
    ///   the emitted cell is labelled [`KnowledgeState::Stale`] carrying
    ///   [`KnowledgeStateBasis::Stale(StaleBasis::OlderAnchor)`]. This stale cell can NEVER serve
    ///   as an irreversible-effect premise.
    /// - Forked anchors, different site lineages, or future anchors are refused with
    ///   [`ContractError::DerivedBeliefAnchorMismatch`].
    /// - An invalid `current` anchor (e.g. all-zero state root) is refused with
    ///   [`ContractError::DerivedBeliefMissingAnchor`].
    ///
    /// The emitted cell must itself pass [`KnowledgeCell::validate`]; its error is propagated,
    /// so no invalid cell ever leaves this boundary.
    pub fn to_knowledge_cell(
        &self,
        current: &LedgerAnchor,
    ) -> Result<KnowledgeCell, ContractError> {
        self.validate()?;
        if !anchor_names_canonical_state(current) {
            return Err(ContractError::DerivedBeliefMissingAnchor);
        }
        let older = StaleBasis::OlderAnchor {
            valid_at: Box::new(self.anchor.clone()),
            current: Box::new(current.clone()),
        };
        let (knowledge_state, state_basis) = if self.anchor == *current {
            (self.knowledge_state, None)
        } else if older.validate().is_ok() {
            (
                KnowledgeState::Stale,
                Some(KnowledgeStateBasis::Stale(older)),
            )
        } else {
            return Err(ContractError::DerivedBeliefAnchorMismatch);
        };
        KnowledgeCell::new(KnowledgeCellParams {
            claim_id: self.belief_id.clone(),
            statement: self.statement.clone(),
            knowledge_state,
            provenance: self.provenance,
            hypothesis: None,
            evidence: self.supporting_evidence.clone(),
            contradictions: self.contradictions.clone(),
            valid_until: None,
            state_basis,
        })
    }

    /// Decodes a derived belief and enforces freshness against the caller's current anchor.
    pub fn decode_at_anchor(
        decoder: &mut CanonicalDecoder<'_>,
        current: &LedgerAnchor,
    ) -> Result<Self, ContractError> {
        let belief = Self::decode_canonical(decoder)?;
        belief.validate_anchor_freshness(current)?;
        Ok(belief)
    }
}

impl CanonicalEncode for DerivedBelief {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        let (Ok(ev_len), Ok(contra_len)) = (
            u32::try_from(self.supporting_evidence.len()),
            u32::try_from(self.contradictions.len()),
        ) else {
            encoder.fail(ContractError::ArithmeticOverflow);
            return;
        };
        encoder.text(&self.belief_id);
        self.anchor.encode_canonical(encoder);
        encoder.u64(self.generation.0);
        encoder.text(&self.statement);
        self.knowledge_state.encode_canonical(encoder);
        self.provenance.encode_canonical(encoder);
        self.uncertainty.encode_canonical(encoder);
        encoder.u32(ev_len);
        for digest in &self.supporting_evidence {
            encoder.digest(*digest);
        }
        encoder.u32(contra_len);
        for digest in &self.contradictions {
            encoder.digest(*digest);
        }
        encoder.digest(self.derivation_receipt);
    }
}

impl CanonicalDecode for DerivedBelief {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let belief_id = decoder.text()?.to_owned();
        let anchor = LedgerAnchor::decode_canonical(decoder)?;
        let generation = Generation(decoder.u64()?);
        let statement = decoder.text()?.to_owned();
        let knowledge_state = KnowledgeState::decode_canonical(decoder)?;
        let provenance = ProvenanceClass::decode_canonical(decoder)?;
        let uncertainty = BeliefInterval::decode_canonical(decoder)?;

        let raw_evidence_len = decoder.u32()?;
        let evidence_len =
            usize::try_from(raw_evidence_len).map_err(|_| ContractError::ArithmeticOverflow)?;
        let max_evidence_possible = decoder.remaining() / ENCODED_DIGEST_BYTES;
        if evidence_len > MAX_DERIVED_BELIEF_EVIDENCE || evidence_len > max_evidence_possible {
            return Err(ContractError::ArithmeticOverflow);
        }
        let mut supporting_evidence = Vec::with_capacity(evidence_len);
        for _ in 0..evidence_len {
            supporting_evidence.push(decoder.digest()?);
        }

        let raw_contra_len = decoder.u32()?;
        let contra_len =
            usize::try_from(raw_contra_len).map_err(|_| ContractError::ArithmeticOverflow)?;
        let max_contra_possible = decoder.remaining() / ENCODED_DIGEST_BYTES;
        if contra_len > MAX_DERIVED_BELIEF_CONTRADICTIONS || contra_len > max_contra_possible {
            return Err(ContractError::ArithmeticOverflow);
        }
        let mut contradictions = Vec::with_capacity(contra_len);
        for _ in 0..contra_len {
            contradictions.push(decoder.digest()?);
        }

        let derivation_receipt = decoder.digest()?;

        let belief = Self {
            belief_id,
            anchor,
            generation,
            statement,
            knowledge_state,
            provenance,
            uncertainty,
            supporting_evidence,
            contradictions,
            derivation_receipt,
        };
        belief.validate()?;
        Ok(belief)
    }
}

#[cfg(test)]
mod tests {
    //! Planted-bypass tests that need private field access: they forge states that no public
    //! path can produce and prove every boundary refuses them.

    use super::*;
    use crate::{DigestAlgorithm, TimestampNs};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn sealed_params() -> Result<DerivedBeliefParams, Box<dyn std::error::Error>> {
        Ok(DerivedBeliefParams {
            belief_id: "belief:unit:001".to_owned(),
            anchor: LedgerAnchor::genesis("site:unit"),
            generation: Generation(3),
            statement: "Unit-test derived proposition".to_owned(),
            knowledge_state: KnowledgeState::Estimated,
            provenance: ProvenanceClass::Derived,
            uncertainty: BeliefInterval::new(100_000, 900_000)?,
            supporting_evidence: vec![ContentDigest::sha256(b"unit-evidence")],
            contradictions: Vec::new(),
            derivation_receipt: ContentDigest::sha256(b"unsealed"),
        }
        .with_computed_receipt()?)
    }

    fn zero_digest() -> ContentDigest {
        ContentDigest::new(DigestAlgorithm::Sha256, [0; 32])
    }

    #[test]
    fn planted_known_after_construction_is_refused_at_the_cell_boundary() -> TestResult {
        let mut belief = DerivedBelief::new(sealed_params()?)?;
        let anchor = belief.anchor.clone();
        belief.knowledge_state = KnowledgeState::Known;

        assert_eq!(
            belief.validate(),
            Err(ContractError::DerivedBeliefKnownForbidden)
        );
        match belief.to_knowledge_cell(&anchor) {
            Err(err) => assert_eq!(err, ContractError::DerivedBeliefKnownForbidden),
            Ok(cell) => {
                return Err(format!(
                    "forged known belief yielded a cell (effect premise: {})",
                    cell.is_irreversible_effect_premise(TimestampNs(0))
                )
                .into());
            }
        }
        Ok(())
    }

    #[test]
    fn planted_struct_literal_generation_zero_known_is_refused() -> TestResult {
        let params = sealed_params()?;
        let anchor = params.anchor.clone();
        let forged = DerivedBelief {
            belief_id: params.belief_id,
            anchor: params.anchor,
            generation: Generation(0),
            statement: params.statement,
            knowledge_state: KnowledgeState::Known,
            provenance: ProvenanceClass::Derived,
            uncertainty: params.uncertainty,
            supporting_evidence: params.supporting_evidence,
            contradictions: params.contradictions,
            derivation_receipt: params.derivation_receipt,
        };

        match forged.to_knowledge_cell(&anchor) {
            Err(err) => assert_eq!(err, ContractError::GenerationConflict),
            Ok(cell) => {
                return Err(format!(
                    "forged generation-0 known belief yielded a cell (effect premise: {})",
                    cell.is_irreversible_effect_premise(TimestampNs(0))
                )
                .into());
            }
        }
        Ok(())
    }

    #[test]
    fn rebuild_recomputes_and_refuses_tampered_inputs_or_receipt() -> TestResult {
        let valid = DerivedBelief::new(sealed_params()?)?;
        assert_eq!(valid.rebuild(), Ok(valid.clone()));

        let mut tampered_statement = valid.clone();
        tampered_statement.statement = "Tampered statement after sealing".to_owned();
        assert_eq!(
            tampered_statement.rebuild(),
            Err(ContractError::DigestMismatch)
        );

        let mut tampered_evidence = valid.clone();
        tampered_evidence.supporting_evidence = vec![ContentDigest::sha256(b"swapped-evidence")];
        assert_eq!(
            tampered_evidence.rebuild(),
            Err(ContractError::DigestMismatch)
        );

        let mut forged_receipt = valid;
        forged_receipt.derivation_receipt = ContentDigest::sha256(b"forged receipt");
        assert_eq!(forged_receipt.rebuild(), Err(ContractError::DigestMismatch));
        Ok(())
    }

    #[test]
    fn anchor_pinning_predicate_is_false_for_unpinned_anchors() -> TestResult {
        let valid = DerivedBelief::new(sealed_params()?)?;
        assert!(valid.is_anchor_pinned());

        let mut zero_root = valid.clone();
        zero_root.anchor.state_root = zero_digest();
        assert!(!zero_root.is_anchor_pinned());
        let zero_root_anchor = zero_root.anchor.clone();
        assert!(!zero_root.is_anchor_pinned_to(&zero_root_anchor));

        let mut no_lineage = valid;
        no_lineage.anchor.site_lineage = String::new();
        assert!(!no_lineage.is_anchor_pinned());
        Ok(())
    }

    #[test]
    fn rebuildable_predicate_is_false_when_receipt_or_anchor_is_broken() -> TestResult {
        let valid = DerivedBelief::new(sealed_params()?)?;
        assert!(valid.is_rebuildable());

        let mut late_contradiction = valid.clone();
        late_contradiction.contradictions = vec![ContentDigest::sha256(b"late-contradiction")];
        assert!(!late_contradiction.is_rebuildable());

        let mut zero_root = valid;
        zero_root.anchor.state_root = zero_digest();
        assert!(!zero_root.is_rebuildable());
        Ok(())
    }

    #[test]
    fn encoder_failure_is_reported_instead_of_a_partial_encoding() {
        let mut encoder = CanonicalEncoder::new();
        encoder.u32(7);
        encoder.fail(ContractError::ArithmeticOverflow);
        encoder.u32(9);
        encoder.fail(ContractError::InvalidDigest);
        assert_eq!(
            encoder.finish_checked(),
            Err(ContractError::ArithmeticOverflow)
        );
    }

    #[test]
    fn to_knowledge_cell_emits_stale_cell_on_anchor_drift_and_refuses_mismatches() -> TestResult {
        let mut params = sealed_params()?;
        params.anchor.commit_sequence = 10;
        let params = params.with_computed_receipt()?;
        let belief = DerivedBelief::new(params)?;
        let pinned = belief.anchor.clone();
        let now = TimestampNs(1_000_000_000);

        // 1. Same anchor: preserves belief knowledge_state, no state basis
        let fresh_cell = belief.to_knowledge_cell(&pinned)?;
        assert_eq!(fresh_cell.knowledge_state(), belief.knowledge_state);
        assert_eq!(fresh_cell.provenance(), ProvenanceClass::Derived);
        assert_eq!(fresh_cell.state_basis(), None);
        assert!(!fresh_cell.is_irreversible_effect_premise(now));
        assert_eq!(fresh_cell.validate(), Ok(()));

        // 2. Anchor drift: strictly newer commit sequence in same epoch -> Stale cell with OlderAnchor basis
        let mut newer_sequence = pinned.clone();
        newer_sequence.commit_sequence += 1;
        let stale_seq_cell = belief.to_knowledge_cell(&newer_sequence)?;
        assert_eq!(stale_seq_cell.knowledge_state(), KnowledgeState::Stale);
        assert_eq!(stale_seq_cell.provenance(), ProvenanceClass::Derived);
        assert_eq!(
            stale_seq_cell.state_basis(),
            Some(&KnowledgeStateBasis::Stale(StaleBasis::OlderAnchor {
                valid_at: Box::new(pinned.clone()),
                current: Box::new(newer_sequence.clone()),
            }))
        );
        assert!(!stale_seq_cell.is_irreversible_effect_premise(now));
        assert_eq!(stale_seq_cell.validate(), Ok(()));

        // 3. Anchor drift: strictly newer epoch -> Stale cell with OlderAnchor basis
        let mut newer_epoch = pinned.clone();
        newer_epoch.ledger_epoch += 1;
        newer_epoch.commit_sequence = 0;
        let stale_epoch_cell = belief.to_knowledge_cell(&newer_epoch)?;
        assert_eq!(stale_epoch_cell.knowledge_state(), KnowledgeState::Stale);
        assert_eq!(
            stale_epoch_cell.state_basis(),
            Some(&KnowledgeStateBasis::Stale(StaleBasis::OlderAnchor {
                valid_at: Box::new(pinned.clone()),
                current: Box::new(newer_epoch.clone()),
            }))
        );
        assert!(!stale_epoch_cell.is_irreversible_effect_premise(now));
        assert_eq!(stale_epoch_cell.validate(), Ok(()));

        // 4. Forked anchor: same epoch/seq but different state root -> refused
        let mut forked = pinned.clone();
        forked.state_root = ContentDigest::sha256(b"divergent_state_root");
        assert_eq!(
            belief.to_knowledge_cell(&forked),
            Err(ContractError::DerivedBeliefAnchorMismatch)
        );

        // 5. Other lineage: different site lineage -> refused
        let mut other_site = pinned.clone();
        other_site.site_lineage = "site:other:lineage".into();
        assert_eq!(
            belief.to_knowledge_cell(&other_site),
            Err(ContractError::DerivedBeliefAnchorMismatch)
        );

        // 6. Future anchor: current is in the past relative to belief anchor -> refused
        let mut older_current = pinned.clone();
        older_current.commit_sequence = pinned.commit_sequence.saturating_sub(1);
        assert_eq!(
            belief.to_knowledge_cell(&older_current),
            Err(ContractError::DerivedBeliefAnchorMismatch)
        );

        // 7. Missing anchor: all-zero state root -> refused
        let mut zero_root = pinned;
        zero_root.state_root = zero_digest();
        assert_eq!(
            belief.to_knowledge_cell(&zero_root),
            Err(ContractError::DerivedBeliefMissingAnchor)
        );

        Ok(())
    }
}

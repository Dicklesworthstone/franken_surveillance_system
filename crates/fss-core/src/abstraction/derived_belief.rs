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
use crate::{ContentDigest, Generation, KnowledgeCell, LedgerAnchor};

use super::AgentAbstractionLayer;

/// Maximum number of supporting evidence roots allowed for a single [`DerivedBelief`].
pub const MAX_DERIVED_BELIEF_EVIDENCE: usize = 1024;

/// Maximum number of contradicting evidence roots allowed for a single [`DerivedBelief`].
pub const MAX_DERIVED_BELIEF_CONTRADICTIONS: usize = 1024;

/// An anchor-pinned, generation-pinned derived belief (AGT-LAYER-004, INV-069).
///
/// Derived beliefs represent supported entities, tracks, events, relations, and uncertainties
/// derived from canonical evidence. Per AGENTS.md and INV-069:
/// - Derived state is anchor-pinned and rebuildable.
/// - Derived state lives strictly in the Cognition plane and must NEVER claim authority.
/// - Derived state can NEVER authorize effects or certify absence beyond coverage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DerivedBelief {
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
    /// Evidence roots supporting the derivation.
    pub supporting_evidence: Vec<ContentDigest>,
    /// Contradicting evidence roots.
    pub contradictions: Vec<ContentDigest>,
    /// Receipt digest witnessing the deterministic derivation calculation.
    pub derivation_receipt: ContentDigest,
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
    /// Evidence roots supporting the derivation.
    pub supporting_evidence: Vec<ContentDigest>,
    /// Contradicting evidence roots.
    pub contradictions: Vec<ContentDigest>,
    /// Receipt digest witnessing the deterministic derivation calculation.
    pub derivation_receipt: ContentDigest,
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
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.belief_id.is_empty() || self.belief_id.len() > 128 {
            return Err(ContractError::InvalidIdentifier);
        }
        if self.statement.is_empty() || self.statement.len() > 512 {
            return Err(ContractError::InvalidIdentifier);
        }
        if self.anchor.site_lineage.is_empty() {
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
        if self.supporting_evidence.is_empty() {
            return Err(ContractError::EvidenceRequired);
        }
        if self.supporting_evidence.len() > MAX_DERIVED_BELIEF_EVIDENCE {
            return Err(ContractError::ArithmeticOverflow);
        }
        if self.contradictions.len() > MAX_DERIVED_BELIEF_CONTRADICTIONS {
            return Err(ContractError::ArithmeticOverflow);
        }
        if self.uncertainty.lower_micro() > self.uncertainty.upper_micro()
            || self.uncertainty.upper_micro() > crate::belief::MICRO_DENOMINATOR
        {
            return Err(ContractError::InvalidProbabilityInterval);
        }
        if self.derivation_receipt.bytes().iter().all(|&b| b == 0) {
            return Err(ContractError::InvalidDigest);
        }
        Ok(())
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

    /// Returns whether this derived belief is anchor-pinned to canonical evidence.
    #[must_use]
    pub fn is_anchor_pinned(&self) -> bool {
        !self.anchor.site_lineage.is_empty()
    }

    /// Verifies that this derived belief is pinned to the exact specified active anchor.
    #[must_use]
    pub fn is_anchor_pinned_to(&self, active_anchor: &LedgerAnchor) -> bool {
        self.is_anchor_pinned() && self.anchor == *active_anchor
    }

    /// Validates that this derived belief's anchor is not stale relative to the given active epoch.
    pub fn validate_anchor_freshness(&self, active_epoch: u64) -> Result<(), ContractError> {
        if self.anchor.ledger_epoch < active_epoch {
            return Err(ContractError::StaleAnchor);
        }
        Ok(())
    }

    /// Returns whether this derived belief is rebuildable from canonical history.
    #[must_use]
    pub fn is_rebuildable(&self) -> bool {
        self.is_anchor_pinned()
            && self.generation.0 > 0
            && !self.supporting_evidence.is_empty()
            && !self.derivation_receipt.bytes().iter().all(|&b| b == 0)
    }

    /// Rebuilds the derived belief from its canonical derivation inputs, verifying determinism.
    pub fn rebuild(&self) -> Result<Self, ContractError> {
        if !self.is_rebuildable() {
            return Err(ContractError::EvidenceRequired);
        }
        let rebuilt = Self::new(DerivedBeliefParams {
            belief_id: self.belief_id.clone(),
            anchor: self.anchor.clone(),
            generation: self.generation,
            statement: self.statement.clone(),
            knowledge_state: self.knowledge_state,
            provenance: self.provenance,
            uncertainty: self.uncertainty.clone(),
            supporting_evidence: self.supporting_evidence.clone(),
            contradictions: self.contradictions.clone(),
            derivation_receipt: self.derivation_receipt,
        })?;
        Ok(rebuilt)
    }

    /// Computes the deterministic canonical digest of this derived belief.
    #[must_use]
    pub fn canonical_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        self.encode_canonical(&mut encoder);
        ContentDigest::sha256(&encoder.finish())
    }

    /// Computes the deterministic canonical derivation receipt from derivation inputs.
    ///
    /// The encoding order (domain tag, identity, anchor, generation, statement, state,
    /// provenance, uncertainty, evidence, contradictions) is part of the receipt identity.
    pub fn compute_derivation_receipt(
        inputs: &DerivationInputs<'_>,
    ) -> Result<ContentDigest, ContractError> {
        let ev_len = u32::try_from(inputs.supporting_evidence.len())
            .map_err(|_| ContractError::ArithmeticOverflow)?;
        let contra_len = u32::try_from(inputs.contradictions.len())
            .map_err(|_| ContractError::ArithmeticOverflow)?;
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.derived_belief.receipt.v1");
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
        Ok(ContentDigest::sha256(&encoder.finish()))
    }

    /// Returns the abstraction layer for this belief (`AGT-LAYER-004`).
    #[must_use]
    pub const fn layer(&self) -> AgentAbstractionLayer {
        AgentAbstractionLayer::DerivedBeliefs
    }

    /// Converts this derived belief into a canonical [`KnowledgeCell`].
    #[must_use]
    pub fn to_knowledge_cell(&self) -> KnowledgeCell {
        KnowledgeCell {
            claim_id: self.belief_id.clone(),
            statement: self.statement.clone(),
            knowledge_state: self.knowledge_state,
            provenance: self.provenance,
            hypothesis: None,
            evidence: self.supporting_evidence.clone(),
            contradictions: self.contradictions.clone(),
            valid_until: None,
            state_basis: None,
        }
    }
}

impl CanonicalEncode for DerivedBelief {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        let ev_len = match u32::try_from(self.supporting_evidence.len()) {
            Ok(len) => len,
            Err(_) => {
                encoder.bytes(&[0u8; crate::canonical::MAX_CANONICAL_BYTES_LEN + 1]);
                return;
            }
        };
        let contra_len = match u32::try_from(self.contradictions.len()) {
            Ok(len) => len,
            Err(_) => {
                encoder.bytes(&[0u8; crate::canonical::MAX_CANONICAL_BYTES_LEN + 1]);
                return;
            }
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
        let max_evidence_possible = decoder.remaining() / 33;
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
        let max_contra_possible = decoder.remaining() / 33;
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

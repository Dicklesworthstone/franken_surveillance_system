#![forbid(unsafe_code)]
//! Situation capsule realization (AGT-LAYER-005, INV-116).
//!
//! Cognition plane types:
//! - [`SituationCapsulePublication`]
//! - [`SituationCapsulePublicationParams`]
//! - [`SituationCapsuleRecord`] (type alias for [`SituationCapsulePublication`])
//!
//! Output: "SituationCapsule containing SituationFrame with WorldEnvelope, MeaningfulDelta,
//! obligations, resource state, categorized control envelope, ContextPack, compression proof,
//! and affordance frontier."
//!
//! Prohibition: "Cannot hide decision-changing omissions or rebase evidence identities."

use crate::agent::SituationCapsule;
use crate::canonical::{CanonicalEncode, CanonicalEncoder};
use crate::compression::SemanticCompressionReceipt;
use crate::contract::{ContractError, Plane};
use crate::delta::{MeaningfulDelta, MeaningfulDeltaClass};
use crate::projection::{ControlEnvelope, ResourceState, SemanticContextPack};
use crate::{ContentDigest, Generation};

use super::AgentAbstractionLayer;

/// Publication of a mission-oriented situation capsule (AGT-LAYER-005, INV-116).
///
/// Output: "SituationCapsule containing SituationFrame with WorldEnvelope, MeaningfulDelta,
/// obligations, resource state, categorized control envelope, ContextPack, compression proof,
/// and affordance frontier."
///
/// Prohibition: "Cannot hide decision-changing omissions or rebase evidence identities."
#[derive(Clone, Debug, PartialEq)]
pub struct SituationCapsulePublication {
    /// Stable publication identity (e.g. `publication:situation:mission01:rev10`).
    pub publication_id: String,
    /// Generation of the active agent abstraction stack.
    pub generation: Generation,
    /// The mission-oriented situation capsule carrying SituationFrame with WorldEnvelope,
    /// obligations, and affordances.
    pub capsule: SituationCapsule,
    /// Meaningful delta between prior and current situation, if following an anchor.
    pub meaningful_delta: Option<MeaningfulDelta>,
    /// Explicit available/reserved resource state and pressure.
    pub resource_state: ResourceState,
    /// Categorized control envelope partitioning the affordance frontier across possible worlds.
    pub control_envelope: ControlEnvelope,
    /// Bounded decision-oriented semantic context pack.
    pub context_pack: SemanticContextPack,
    /// Cryptographic compression receipt witnessing selection, omission, and critical preservation.
    pub compression_receipt: SemanticCompressionReceipt,
}

/// Type alias for [`SituationCapsulePublication`].
pub type SituationCapsuleRecord = SituationCapsulePublication;

/// Parameters for constructing a [`SituationCapsulePublication`].
#[derive(Clone, Debug, PartialEq)]
pub struct SituationCapsulePublicationParams {
    /// Stable publication identity.
    pub publication_id: String,
    /// Generation of the active agent abstraction stack.
    pub generation: Generation,
    /// Situation capsule.
    pub capsule: SituationCapsule,
    /// Meaningful delta relative to prior anchor.
    pub meaningful_delta: Option<MeaningfulDelta>,
    /// Available/reserved resource state.
    pub resource_state: ResourceState,
    /// Categorized control envelope.
    pub control_envelope: ControlEnvelope,
    /// Semantic context pack.
    pub context_pack: SemanticContextPack,
    /// Compression receipt.
    pub compression_receipt: SemanticCompressionReceipt,
}

impl SituationCapsulePublication {
    /// Validates and constructs a new situation capsule publication from parameters.
    pub fn new(params: SituationCapsulePublicationParams) -> Result<Self, ContractError> {
        let publication = Self {
            publication_id: params.publication_id,
            generation: params.generation,
            capsule: params.capsule,
            meaningful_delta: params.meaningful_delta,
            resource_state: params.resource_state,
            control_envelope: params.control_envelope,
            context_pack: params.context_pack,
            compression_receipt: params.compression_receipt,
        };
        publication.validate()?;
        Ok(publication)
    }

    /// Validates all constitutional and semantic invariants for this publication (INV-116).
    pub fn validate(&self) -> Result<(), ContractError> {
        // 1. Identity validation
        if self.publication_id.trim().is_empty()
            || self.publication_id.len() > 128
            || self.publication_id.chars().any(|c| c.is_ascii_whitespace() || c.is_ascii_control())
        {
            return Err(ContractError::InvalidIdentifier);
        }

        // 2. Generation pinning: cannot be generation 0
        if self.generation.0 == 0 {
            return Err(ContractError::GenerationConflict);
        }

        // 3. Inner capsule validation (frame, world envelope, cell typed bases, affordance frontier)
        self.capsule.validate()?;

        // 4. Anchor and continuity coherence
        if let Some(prev) = &self.capsule.previous_anchor {
            let Some(delta) = &self.meaningful_delta else {
                // When previous anchor is declared, meaningful delta is mandatory
                return Err(ContractError::EvidenceRequired);
            };
            if delta.basis_anchor != *prev {
                return Err(ContractError::StaleAnchor);
            }
            if delta.result_anchor != self.capsule.anchor {
                return Err(ContractError::StaleAnchor);
            }
            if delta.contract_basis.basis_digest() != self.capsule.contract_basis.basis_digest() {
                return Err(ContractError::InvalidIdentifier);
            }
            delta.validate()?;
        } else if let Some(delta) = &self.meaningful_delta {
            if delta.result_anchor != self.capsule.anchor {
                return Err(ContractError::StaleAnchor);
            }
            delta.validate()?;
        }

        // 5. Categorized control envelope coherence:
        // Proves that the control envelope is the exact deterministic partition of the
        // affordance frontier against the exact world envelope.
        self.control_envelope.validate_against(
            &self.capsule.frame.world_envelope,
            &self.capsule.affordances,
        )?;

        // 6. Context pack and compression receipt coherence:
        if self.context_pack.anchor != self.capsule.anchor {
            return Err(ContractError::StaleAnchor);
        }
        self.context_pack.verify()?;

        if self.compression_receipt.source_anchor != self.capsule.anchor {
            return Err(ContractError::StaleAnchor);
        }
        self.compression_receipt.validate()?;
        self.compression_receipt.validate_for(&self.context_pack)?;

        // 7. Prohibition: Cannot hide decision-changing omissions (INV-116)
        if let Some(delta) = &self.meaningful_delta {
            // Omission justification check
            if delta.omitted_count > 0 {
                if delta.omission_reasons.is_empty() {
                    return Err(ContractError::EvidenceRequired);
                }
                for reason in &delta.omission_reasons {
                    if reason.trim().is_empty() {
                        return Err(ContractError::InvalidIdentifier);
                    }
                }
                if delta.continuation.trim().is_empty() {
                    return Err(ContractError::EvidenceRequired);
                }
            }

            // Non-coalescible transitions must not omit concrete changes
            if delta.classes.contains(&MeaningfulDeltaClass::CoverageLoss)
                && delta.coverage_changes.is_empty()
            {
                return Err(ContractError::EvidenceRequired);
            }
            if delta.classes.contains(&MeaningfulDeltaClass::PlanInvalidation)
                && delta.invalidated_assumptions.is_empty()
            {
                return Err(ContractError::EvidenceRequired);
            }
            if delta.classes.contains(&MeaningfulDeltaClass::Obligation)
                && delta.obligation_changes.is_empty()
            {
                return Err(ContractError::EvidenceRequired);
            }
            if delta.classes.contains(&MeaningfulDeltaClass::EffectUncertainty)
                && delta.effect_uncertainty_changes.is_empty()
            {
                return Err(ContractError::EvidenceRequired);
            }
        }

        // 8. Prohibition: Cannot rebase evidence identities (INV-116)
        for item in &self.context_pack.items {
            for handle in &item.expansion_handles {
                if handle.trim().is_empty() {
                    return Err(ContractError::InvalidIdentifier);
                }
            }
        }
        for handle in &self.capsule.frame.evidence_handles {
            if handle.trim().is_empty() {
                return Err(ContractError::InvalidIdentifier);
            }
        }

        // Digests must not be all-zeros
        if self.control_envelope.envelope_digest.bytes().iter().all(|&b| b == 0) {
            return Err(ContractError::InvalidDigest);
        }
        if self.context_pack.situation_fingerprint.bytes().iter().all(|&b| b == 0) {
            return Err(ContractError::InvalidDigest);
        }

        Ok(())
    }

    /// Returns the abstraction layer (`AGT-LAYER-005`).
    #[must_use]
    pub const fn layer(&self) -> AgentAbstractionLayer {
        AgentAbstractionLayer::SituationCapsule
    }

    /// Returns the semantic plane (`Plane::Cognition`).
    #[must_use]
    pub const fn plane(&self) -> Plane {
        Plane::Cognition
    }

    /// Returns the normative invariant ID (`INV-116`).
    #[must_use]
    pub const fn invariant(&self) -> &'static str {
        "INV-116"
    }

    /// Constitutional Hard Gate: Situation capsule can NEVER claim authority (AGENTS.md).
    #[must_use]
    pub const fn may_claim_authority(&self) -> bool {
        false
    }

    /// Constitutional Hard Gate: Situation capsule can NEVER authorize effects directly (INV-116).
    #[must_use]
    pub const fn may_authorize_effects(&self) -> bool {
        false
    }

    /// Returns whether this publication is anchor-pinned to canonical evidence.
    #[must_use]
    pub fn is_anchor_pinned(&self) -> bool {
        !self.capsule.anchor.site_lineage.is_empty()
    }

    /// Returns whether this publication is rebuildable from canonical history.
    #[must_use]
    pub const fn is_rebuildable(&self) -> bool {
        true
    }

    /// Returns whether this publication is anchor-pinned and rebuildable.
    #[must_use]
    pub fn is_anchor_pinned_rebuildable(&self) -> bool {
        self.is_anchor_pinned() && self.is_rebuildable()
    }

    /// Returns true: strictly prohibits hiding decision-changing omissions.
    #[must_use]
    pub const fn prohibits_hiding_decision_changing_omissions(&self) -> bool {
        true
    }

    /// Returns true: strictly prohibits rebasing evidence identities.
    #[must_use]
    pub const fn prohibits_rebasing_evidence_identities(&self) -> bool {
        true
    }

    /// Appends the canonical representation of the publication to the encoder.
    pub fn encode_fields(&self, encoder: &mut CanonicalEncoder) -> Result<(), ContractError> {
        encoder.text(&self.publication_id);
        encoder.u64(self.generation.0);
        let capsule_digest = self.capsule.decision_fingerprint()?;
        encoder.digest(capsule_digest);
        match &self.meaningful_delta {
            Some(delta) => {
                encoder.bool(true);
                delta.encode_canonical(encoder);
            }
            None => {
                encoder.bool(false);
            }
        }
        self.resource_state.encode_canonical(encoder);
        encoder.digest(self.control_envelope.control_digest());
        self.context_pack.encode_canonical(encoder);
        encoder.digest(self.compression_receipt.receipt_digest());
        Ok(())
    }

    /// Returns a domain-separated digest of the publication's canonical encoding, validating first.
    pub fn validated_digest(&self, domain: &str) -> Result<ContentDigest, ContractError> {
        self.validate()?;
        let mut encoder = CanonicalEncoder::new();
        encoder.text(domain);
        self.encode_fields(&mut encoder)?;
        Ok(ContentDigest::sha256(&encoder.finish()))
    }

    /// Returns the decision fingerprint used for replay comparison and handoff roots.
    pub fn decision_fingerprint(&self) -> Result<ContentDigest, ContractError> {
        self.validated_digest("fss.situation_capsule_publication.v1")
    }
}

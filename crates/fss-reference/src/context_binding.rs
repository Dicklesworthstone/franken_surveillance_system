//! Self-contained exact descriptor bindings for reference context publications.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use fss_core::hydration::{HydrationError, HydrationLevel, SemanticHandle};
use fss_core::{
    CanonicalEncode, CanonicalEncoder, ContentDigest, ContextBindingError,
    ContextExpansionBinding, ContextExpansionBindingSet, ContractError, HandoffCapsule, HandoffId,
    TimestampNs,
};

use crate::{ReferenceError, ReferenceSituationPublication};

/// Failure while constructing or verifying a descriptor-bound reference publication.
#[derive(Debug)]
pub enum ReferenceContextBindingError {
    /// Base reference-publication failure.
    Reference(ReferenceError),
    /// Exact slot/descriptor binding failure.
    Binding(ContextBindingError),
}

impl fmt::Display for ReferenceContextBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reference(error) => {
                write!(formatter, "reference context publication error: {error}")
            }
            Self::Binding(error) => write!(formatter, "reference context binding error: {error}"),
        }
    }
}

impl std::error::Error for ReferenceContextBindingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Reference(error) => Some(error),
            Self::Binding(error) => Some(error),
        }
    }
}

impl From<ReferenceError> for ReferenceContextBindingError {
    fn from(value: ReferenceError) -> Self {
        Self::Reference(value)
    }
}

impl From<ContextBindingError> for ReferenceContextBindingError {
    fn from(value: ContextBindingError) -> Self {
        Self::Binding(value)
    }
}

impl From<HydrationError> for ReferenceContextBindingError {
    fn from(value: HydrationError) -> Self {
        Self::Binding(ContextBindingError::Hydration(value))
    }
}

impl From<ContractError> for ReferenceContextBindingError {
    fn from(value: ContractError) -> Self {
        Self::Binding(ContextBindingError::Contract(value))
    }
}

/// One caller-supplied exact descriptor used to resolve a context expansion slot.
#[derive(Clone, Debug, PartialEq)]
pub struct ReferenceExpansionBindingSpec {
    /// Stable slot emitted by the context pack or compression receipt.
    pub slot_id: String,
    /// Exact immutable semantic-handle descriptor revision.
    pub descriptor: SemanticHandle,
    /// Exact hydration level exposed by this slot.
    pub hydration_level: HydrationLevel,
    /// Bounded description of the additional context.
    pub purpose: String,
}

/// Reference publication plus the complete descriptor-bound expansion graph.
#[derive(Clone, Debug, PartialEq)]
pub struct BoundReferenceSituationPublication {
    /// Verified resource/control/context/compression publication.
    pub publication: ReferenceSituationPublication,
    /// Complete one-to-one slot bindings.
    pub expansion_bindings: ContextExpansionBindingSet,
    /// Canonically ordered exact descriptor revisions, with no unused entries.
    pub descriptors: Vec<SemanticHandle>,
    /// Digest of the complete bound publication.
    pub bound_publication_digest: ContentDigest,
}

impl BoundReferenceSituationPublication {
    /// Publishes a self-contained expansion graph for one exact reference publication.
    pub fn publish(
        publication: ReferenceSituationPublication,
        specs: Vec<ReferenceExpansionBindingSpec>,
    ) -> Result<Self, ReferenceContextBindingError> {
        publication.verify()?;
        let mut bindings = Vec::with_capacity(specs.len());
        let mut descriptors = Vec::with_capacity(specs.len());
        for spec in specs {
            bindings.push(ContextExpansionBinding::publish(
                spec.slot_id,
                &spec.descriptor,
                spec.hydration_level,
                spec.purpose,
            )?);
            descriptors.push(spec.descriptor);
        }
        descriptors.sort_by(descriptor_order);
        descriptors.dedup_by(|left, right| {
            left.handle_id == right.handle_id
                && left.descriptor_digest == right.descriptor_digest
                && left == right
        });
        let expansion_bindings = ContextExpansionBindingSet::publish(
            &publication.context_pack,
            &publication.compression_receipt,
            bindings,
        )?;
        let mut bound = Self {
            publication,
            expansion_bindings,
            descriptors,
            bound_publication_digest: ContentDigest::sha256(
                b"unpublished-bound-reference-situation-publication",
            ),
        };
        bound.validate_body()?;
        bound.bound_publication_digest = bound.computed_digest();
        bound.verify()?;
        Ok(bound)
    }

    /// Recomputes the complete descriptor-bound publication digest.
    #[must_use]
    pub fn computed_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.reference_bound_situation_publication.v1");
        encoder.digest(self.publication.publication_digest);
        encoder.digest(self.expansion_bindings.binding_set_digest);
        encoder.u64(self.descriptors.len() as u64);
        for descriptor in &self.descriptors {
            descriptor.encode_canonical(&mut encoder);
        }
        ContentDigest::sha256(&encoder.finish())
    }

    /// Verifies the base publication, exact catalog closure, and complete bound identity.
    pub fn verify(&self) -> Result<ContentDigest, ReferenceContextBindingError> {
        self.validate_body()?;
        if self.bound_publication_digest != self.computed_digest() {
            return Err(ContractError::DigestMismatch.into());
        }
        Ok(self.bound_publication_digest)
    }

    /// Returns every semantic proof root required to resume without ambient descriptor state.
    #[must_use]
    pub fn proof_roots(&self) -> BTreeSet<ContentDigest> {
        let mut roots = self.publication.situation.proof_roots.clone();
        roots.insert(self.publication.publication_digest);
        roots.insert(self.publication.situation.capsule.decision_fingerprint());
        roots.insert(self.publication.resource_state.state_digest());
        roots.insert(self.publication.control_envelope.control_digest());
        roots.insert(self.publication.context_pack.pack_digest);
        roots.insert(self.publication.compression_receipt.receipt_digest());
        roots.insert(self.expansion_bindings.binding_set_digest);
        for descriptor in &self.descriptors {
            roots.insert(descriptor.subject_digest);
            roots.insert(descriptor.descriptor_digest);
            roots.insert(descriptor.ladder_policy_digest());
        }
        for binding in &self.expansion_bindings.bindings {
            roots.insert(binding.binding_digest);
            roots.insert(binding.reference.reference_digest);
            roots.insert(binding.reference.subject_digest);
            roots.insert(binding.reference.descriptor_digest);
            roots.insert(binding.reference.ladder_policy_digest);
        }
        roots.insert(self.bound_publication_digest);
        roots
    }

    fn validate_body(&self) -> Result<(), ReferenceContextBindingError> {
        self.publication.verify()?;
        let mut descriptors = BTreeMap::new();
        let mut prior: Option<(&str, ContentDigest)> = None;
        for descriptor in &self.descriptors {
            descriptor.verify()?;
            let key = (descriptor.handle_id.as_str(), descriptor.descriptor_digest);
            if prior.is_some_and(|value| value >= key) {
                return Err(ContractError::NonCanonicalOrdering.into());
            }
            prior = Some(key);
            if descriptors
                .insert(
                    (descriptor.handle_id.clone(), descriptor.descriptor_digest),
                    descriptor,
                )
                .is_some()
            {
                return Err(ContractError::NonCanonicalOrdering.into());
            }
        }
        self.expansion_bindings.validate_catalog(
            &self.publication.context_pack,
            &self.publication.compression_receipt,
            &self.descriptors,
        )?;

        let required_descriptors: BTreeSet<_> = self
            .expansion_bindings
            .bindings
            .iter()
            .map(|binding| {
                (
                    binding.reference.handle_id.clone(),
                    binding.reference.descriptor_digest,
                )
            })
            .collect();
        let supplied_descriptors: BTreeSet<_> = self
            .descriptors
            .iter()
            .map(|descriptor| (descriptor.handle_id.clone(), descriptor.descriptor_digest))
            .collect();
        if required_descriptors != supplied_descriptors {
            return Err(ContractError::IncompletePublicationGraph.into());
        }
        Ok(())
    }
}

/// Seals a handoff rooted in the exact publication, bindings, and descriptor revisions.
pub fn seal_bound_reference_publication_handoff(
    publication: &BoundReferenceSituationPublication,
    handoff_id: HandoffId,
    created_at: TimestampNs,
    expires_at: TimestampNs,
) -> Result<HandoffCapsule, ReferenceContextBindingError> {
    let publication_root = publication.verify()?;
    let handoff = HandoffCapsule::publish(
        handoff_id,
        publication.publication.situation.capsule.mission_id.clone(),
        publication.publication.situation.capsule.session_id.clone(),
        publication
            .publication
            .situation
            .capsule
            .principal_id
            .clone(),
        publication.publication.situation.capsule.anchor.clone(),
        publication_root,
        publication.proof_roots(),
        publication
            .publication
            .situation
            .capsule
            .contract_basis
            .clone(),
        created_at,
        expires_at,
    )?;
    handoff.verify()?;
    Ok(handoff)
}

fn descriptor_order(left: &SemanticHandle, right: &SemanticHandle) -> std::cmp::Ordering {
    (&left.handle_id, left.descriptor_digest).cmp(&(&right.handle_id, right.descriptor_digest))
}

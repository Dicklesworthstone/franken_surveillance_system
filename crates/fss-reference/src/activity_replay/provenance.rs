#![forbid(unsafe_code)]
//! Preserve producer origins at the retained activity → knowledge/report boundary.
//!
//! Only [`VerifiedActivityObservation`] can produce a verified projection. The observation has
//! already checked complete deletion/privacy authority, native custody, exact role membership,
//! independent JPEG/model replay and an unchanged ledger head. Public claim fields and their
//! integrity digest are transferable descriptions, not authentication or a custody lease. A
//! recipient must rerun the native owner against independently selected authority before calling
//! [`VerifiedActivityObservation::verify_knowledge_projection`].

use std::collections::BTreeSet;
use std::fmt;

use fss_core::{
    CanonicalEncode, CanonicalEncoder, ContentDigest, ContractError, EvidenceOrigin,
    EvidenceReference, KnowledgeCell, LedgerAnchor, ProvenanceClass,
};

use super::belief::{
    ACTIVITY_BELIEF_ALGORITHM, ACTIVITY_BELIEF_GENERATION, ActivityEvidenceBinding,
    ActivityEvidenceSet,
};
use super::operator::VerifiedActivityObservation;

/// Domain of the exact producer, authority, role closure and knowledge projection.
pub const ACTIVITY_KNOWLEDGE_PROJECTION_DOMAIN: &str = "fss.activity_knowledge_projection.v1";
/// Explicit operator report profile; the default legacy report is unchanged.
pub const ACTIVITY_PRODUCER_ORIGINS_PROFILE: &str = "producer-origins-v1";
/// Every successful native activity replay consumes these eight named roles.
pub const ACTIVITY_EVIDENCE_ROLE_COUNT: usize = 8;

/// Native computational role, established by the decoder/replayer rather than container family.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ActivityEvidenceRole {
    /// Independently reproduced model result.
    Result,
    /// Independently reproduced invocation receipt.
    Invocation,
    /// Retained original evaluated JPEG bytes.
    FrameSource,
    /// Retained original reference JPEG bytes.
    ReferenceSource,
    /// Bound source-capsule metadata; its timing assertions are not physical observations.
    FrameCapsule,
    /// Bound reference-capsule metadata; its timing assertions are not physical observations.
    ReferenceCapsule,
    /// Independently reproduced evaluated-frame decode record.
    FrameDecode,
    /// Independently reproduced reference-frame decode record.
    ReferenceDecode,
}

impl ActivityEvidenceRole {
    /// Stable role order, including separate roles which happen to share the same content.
    pub const ALL: [Self; ACTIVITY_EVIDENCE_ROLE_COUNT] = [
        Self::Result,
        Self::Invocation,
        Self::FrameSource,
        Self::ReferenceSource,
        Self::FrameCapsule,
        Self::ReferenceCapsule,
        Self::FrameDecode,
        Self::ReferenceDecode,
    ];

    /// Stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Result => "result",
            Self::Invocation => "invocation",
            Self::FrameSource => "frame_source",
            Self::ReferenceSource => "reference_source",
            Self::FrameCapsule => "frame_capsule",
            Self::ReferenceCapsule => "reference_capsule",
            Self::FrameDecode => "frame_decode",
            Self::ReferenceDecode => "reference_decode",
        }
    }

    /// Classification of this role within the verified native computation.
    ///
    /// `Observed` describes custody of the exact original bytes, never live scene authenticity.
    /// Capsules are conservatively `Derived` metadata: replay binds their bytes and checks their
    /// relations, but does not authenticate an operator-supplied capture time, calibration or
    /// device clock. Retaining a record cannot turn those assertions into observed physics.
    #[must_use]
    pub const fn origin(self) -> EvidenceOrigin {
        EvidenceOrigin::Produced(match self {
            Self::FrameSource | Self::ReferenceSource => ProvenanceClass::Observed,
            Self::Result
            | Self::Invocation
            | Self::FrameCapsule
            | Self::ReferenceCapsule
            | Self::FrameDecode
            | Self::ReferenceDecode => ProvenanceClass::Derived,
        })
    }

    fn binding(self, evidence: &ActivityEvidenceSet) -> &ActivityEvidenceBinding {
        match self {
            Self::Result => &evidence.result,
            Self::Invocation => &evidence.invocation,
            Self::FrameSource => &evidence.frame_source,
            Self::ReferenceSource => &evidence.reference_source,
            Self::FrameCapsule => &evidence.frame_capsule,
            Self::ReferenceCapsule => &evidence.reference_capsule,
            Self::FrameDecode => &evidence.frame_decode,
            Self::ReferenceDecode => &evidence.reference_decode,
        }
    }
}

/// Transferable claim about one producer role. Construction alone grants no verified status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivityOriginBinding {
    /// Exact computational role; equal content in a second role remains a separate binding.
    pub role: ActivityEvidenceRole,
    /// Origin asserted for this role; the native owner checks it against its own classification.
    pub origin: EvidenceOrigin,
    /// Payload and complete authority revision, including family, plane and validity.
    pub evidence: ActivityEvidenceBinding,
}

impl CanonicalEncode for ActivityOriginBinding {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(self.role.as_str());
        self.origin.encode_canonical(encoder);
        encoder.digest(self.evidence.digest);
        self.evidence.authority.encode_canonical(encoder);
        self.evidence.revision.encode_canonical(encoder);
    }
}

/// Untrusted interchange candidate. A matching self-computed digest does not authenticate it.
///
/// Every field must match an independently obtained [`VerifiedActivityObservation`]. A caller
/// cannot recover verified status by deserializing this claim, supplying an origin map, relabeling
/// a cell, or constructing a structurally valid [`fss_core::DerivedBelief`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivityProjectionClaim {
    /// Exact anchor observed before and after native verification.
    pub anchor: LedgerAnchor,
    /// Complete committed journal root; the anchor alone does not identify the whole history.
    pub ledger_root: ContentDigest,
    /// Independently selected native producer algorithm.
    pub producer_algorithm: String,
    /// Exact generation of the native belief-construction contract.
    pub producer_generation: u64,
    /// Receipt of the independently reproduced belief, including its uncertainty and inputs.
    pub derivation_receipt: ContentDigest,
    /// Exact Estimated/Derived proposition, with every distinct content/origin pair preserved.
    pub cell: KnowledgeCell,
    /// Complete eight-role closure in [`ActivityEvidenceRole::ALL`] order; never digest-only.
    pub roles: Vec<ActivityOriginBinding>,
}

impl ActivityProjectionClaim {
    /// Bounded canonical integrity fingerprint, explicitly not proof of native verification.
    ///
    /// Semantically forged claims can have valid integrity digests. Use the private observation's
    /// verification method to check the producer, anchor, full closure and exact cell together.
    pub fn integrity_digest(&self) -> Result<ContentDigest, ContractError> {
        // Check counts before the cell encoder allocates its sorted/deduplicated inventory.
        if self.roles.len() > ACTIVITY_EVIDENCE_ROLE_COUNT
            || self.cell.evidence().len() > ACTIVITY_EVIDENCE_ROLE_COUNT
            || self.cell.contradictions().len() > ACTIVITY_EVIDENCE_ROLE_COUNT
        {
            return Err(ContractError::InvalidIdentifier);
        }
        let role_count =
            u8::try_from(self.roles.len()).map_err(|_| ContractError::ArithmeticOverflow)?;
        // This fallible entry point owns the complete encoding. There is deliberately no
        // infallible CanonicalEncode implementation which could bypass the intake bounds.
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.canonical.v1");
        encoder.text(ACTIVITY_KNOWLEDGE_PROJECTION_DOMAIN);
        self.anchor.encode_canonical(&mut encoder);
        encoder.digest(self.ledger_root);
        encoder.text(&self.producer_algorithm);
        encoder.u64(self.producer_generation);
        encoder.digest(self.derivation_receipt);
        self.cell.encode_canonical(&mut encoder);
        encoder.u8(role_count);
        for binding in &self.roles {
            binding.encode_canonical(&mut encoder);
        }
        Ok(ContentDigest::sha256(&encoder.finish_checked()?))
    }
}

/// A projection created only from the successful native custody/replay owner.
///
/// There is no public constructor or decoder. The public claim and its digest cannot be used to
/// manufacture this type. This is an observation at one anchor, never an irreversible-effect
/// premise, transferable permission, physical truth certificate or future custody guarantee.
#[derive(Debug)]
pub struct VerifiedActivityProjection {
    claim: ActivityProjectionClaim,
    digest: ContentDigest,
}

impl VerifiedActivityProjection {
    /// Exact transferable claim. Mutating a clone loses the producer's verified binding.
    #[must_use]
    pub const fn claim(&self) -> &ActivityProjectionClaim {
        &self.claim
    }

    /// Integrity identity of the complete projection; it is not a signature or authentication.
    #[must_use]
    pub const fn integrity_digest(&self) -> ContentDigest {
        self.digest
    }
}

/// A producer-bound projection refuses without returning a partially verified claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActivityProjectionError {
    /// Canonical cell or fingerprint encoding failed.
    Contract(ContractError),
    /// The exact observation anchor or committed history differs.
    AnchorMismatch,
    /// Native algorithm, generation or derivation receipt differs.
    ProducerMismatch,
    /// A role, origin, payload or complete authority revision is missing, added or changed.
    EvidenceClosureMismatch,
    /// The proposition, state, provenance or complete typed evidence set differs.
    CellMismatch,
}

impl fmt::Display for ActivityProjectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(error) => write!(f, "activity projection contract: {error}"),
            Self::AnchorMismatch => f.write_str("activity projection authority anchor differs"),
            Self::ProducerMismatch => f.write_str("activity projection native producer differs"),
            Self::EvidenceClosureMismatch => {
                f.write_str("activity projection requires the exact producer-origin role closure")
            }
            Self::CellMismatch => {
                f.write_str("activity projection differs from the producer-bound knowledge cell")
            }
        }
    }
}
impl std::error::Error for ActivityProjectionError {}
impl From<ContractError> for ActivityProjectionError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}

fn origin_bindings(evidence: &ActivityEvidenceSet) -> Vec<ActivityOriginBinding> {
    ActivityEvidenceRole::ALL
        .into_iter()
        .map(|role| ActivityOriginBinding {
            role,
            origin: role.origin(),
            evidence: role.binding(evidence).clone(),
        })
        .collect()
}

fn supporting_references(roles: &[ActivityOriginBinding]) -> Vec<EvidenceReference> {
    // Deduplicate the compound reference, never the digest alone. Multiple roles still remain
    // in the closure, including two roles with exactly the same digest and the same origin.
    roles
        .iter()
        .map(|binding| EvidenceReference::new(binding.evidence.digest, binding.origin))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

impl VerifiedActivityObservation {
    /// Projects this successful native observation without dropping producer-origin classes.
    /// No caller-supplied cell or origin registry is admitted at this construction boundary.
    pub fn knowledge_projection(
        &self,
    ) -> Result<VerifiedActivityProjection, ActivityProjectionError> {
        let belief = self.belief();
        let roles = origin_bindings(self.evidence());
        let references = supporting_references(&roles);
        let mut params = belief.to_knowledge_cell(belief.anchor())?.to_params();
        params.evidence = references
            .iter()
            .map(|reference| reference.digest)
            .collect();
        let cell = KnowledgeCell::new(params)?.with_evidence_origins(
            &references
                .iter()
                .map(|reference| reference.origin)
                .collect::<Vec<_>>(),
        )?;
        let claim = ActivityProjectionClaim {
            anchor: belief.anchor().clone(),
            ledger_root: self.ledger_root(),
            producer_algorithm: ACTIVITY_BELIEF_ALGORITHM.to_owned(),
            producer_generation: ACTIVITY_BELIEF_GENERATION.0,
            derivation_receipt: belief.derivation_receipt(),
            cell,
            roles,
        };
        let digest = claim.integrity_digest()?;
        Ok(VerifiedActivityProjection { claim, digest })
    }

    /// Checks an untrusted projection against this independently obtained native observation.
    ///
    /// All eight roles and every authority-revision coordinate must survive interchange. Equal
    /// digests cannot conceal an omitted role or a changed origin. Cell comparison includes its
    /// statement, epistemic state, provenance, evidence origins, contradictions and validity.
    /// Recomputing an attacker's integrity digest never substitutes for this owner-bound check.
    pub fn verify_knowledge_projection(
        &self,
        candidate: &ActivityProjectionClaim,
    ) -> Result<VerifiedActivityProjection, ActivityProjectionError> {
        let verified = self.knowledge_projection()?;
        let expected = verified.claim();
        if candidate.anchor != expected.anchor || candidate.ledger_root != expected.ledger_root {
            return Err(ActivityProjectionError::AnchorMismatch);
        }
        if candidate.producer_algorithm != expected.producer_algorithm
            || candidate.producer_generation != expected.producer_generation
            || candidate.derivation_receipt != expected.derivation_receipt
        {
            return Err(ActivityProjectionError::ProducerMismatch);
        }
        if candidate.roles != expected.roles {
            return Err(ActivityProjectionError::EvidenceClosureMismatch);
        }
        if candidate.cell != expected.cell {
            return Err(ActivityProjectionError::CellMismatch);
        }
        Ok(verified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fss_core::{CaptureInterval, ObjectId, ObjectRevision, Plane, TimestampNs};

    #[test]
    fn a_content_alias_retains_every_role_and_every_distinct_origin() -> Result<(), ContractError> {
        let binding = ActivityEvidenceBinding {
            digest: ContentDigest::sha256(b"shared-content"),
            authority: ObjectId::parse("object:test:origin-alias")?,
            revision: ObjectRevision {
                generation: 1,
                family: "test:origin-alias".to_owned(),
                plane: Plane::Authority,
                payload_digest: ContentDigest::sha256(b"container"),
                validity: CaptureInterval::new(TimestampNs(0), TimestampNs(1))?,
            },
        };
        // Exercise alias accounting only. These synthetic role assignments do not construct a
        // VerifiedActivityObservation or establish that the same bytes are a JPEG and metadata.
        let evidence = ActivityEvidenceSet {
            result: binding.clone(),
            invocation: binding.clone(),
            frame_source: binding.clone(),
            reference_source: binding.clone(),
            frame_capsule: binding.clone(),
            reference_capsule: binding.clone(),
            frame_decode: binding.clone(),
            reference_decode: binding.clone(),
        };
        let roles = origin_bindings(&evidence);
        assert_eq!(roles.len(), 8);
        let references = supporting_references(&roles);
        assert_eq!(references.len(), 2);
        assert!(references.contains(&EvidenceReference::produced(
            binding.digest,
            ProvenanceClass::Observed,
        )));
        assert!(references.contains(&EvidenceReference::produced(
            binding.digest,
            ProvenanceClass::Derived,
        )));
        for role in [
            ActivityEvidenceRole::FrameCapsule,
            ActivityEvidenceRole::ReferenceCapsule,
        ] {
            assert_eq!(
                role.origin(),
                EvidenceOrigin::Produced(ProvenanceClass::Derived)
            );
        }
        Ok(())
    }
}

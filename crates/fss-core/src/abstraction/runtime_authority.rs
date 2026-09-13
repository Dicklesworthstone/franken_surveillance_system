#![forbid(unsafe_code)]
//! Runtime authority and custody realization (AGT-LAYER-001, INV-006).
//!
//! Authority plane types:
//! - [`RuntimeGrant`]
//! - [`SourceCustody`]
//! - [`RuntimeAuthorityParams`]
//! - [`RuntimeAuthorityAndCustodyRecord`]
//! - Type alias [`RuntimeAuthorityRecord`]
//! - Type alias [`RuntimeAuthorityAndCustody`]

use crate::agent::ContractBasis;
use crate::canonical::{CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder};
use crate::contract::{ContractError, Plane};
use crate::digest::ContentDigest;
use crate::effect::{Obligation, ObligationId, ObligationState};
use crate::ids::{Generation, validate_id};
use crate::region::{ContextAuthority, QuiescenceProof, RegionId, RegionKind, RegionState};
pub use crate::sensor_capsule::SourceCustody;
use core::fmt;
use core::str::FromStr;

use super::AgentAbstractionLayer;

/// Canonical domain tag for runtime authority and custody records.
pub const RUNTIME_AUTHORITY_DOMAIN: &str = "fss.runtime_authority_and_custody.v1";

/// Strongly typed capability grant in the runtime authority plane (AGT-LAYER-001).
///
/// Under AGT-LAYER-001 and INV-006, grants are typed to registered capabilities
/// or explicit test/prohibited variants; substring denylists are forbidden.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RuntimeGrant {
    /// Adapter authentication grant.
    AdapterAuth,
    /// Adapter network communication grant.
    AdapterNet,
    /// Agent cancellation grant.
    AgentCancel,
    /// Agent case write grant.
    AgentCaseWrite,
    /// Agent evidence hydration grant.
    AgentEvidenceHydrate,
    /// Agent explanation grant.
    AgentExplain,
    /// Agent feedback grant.
    AgentFeedback,
    /// Agent finding write grant.
    AgentFindingWrite,
    /// Agent handoff read grant.
    AgentHandoffRead,
    /// Agent handoff write grant.
    AgentHandoffWrite,
    /// Agent investigation grant.
    AgentInvestigate,
    /// Agent plan commit grant.
    AgentPlanCommit,
    /// Agent plan prepare grant.
    AgentPlanPrepare,
    /// Agent query grant.
    AgentQuery,
    /// Agent session open grant.
    AgentSessionOpen,
    /// Agent session read grant.
    AgentSessionRead,
    /// Agent session write grant.
    AgentSessionWrite,
    /// Agent situation read grant.
    AgentSituationRead,
    /// Agent work claim grant.
    AgentWorkClaim,
    /// Alert effect commit grant.
    AlertCommit,
    /// Alert effect prepare grant.
    AlertPrepare,
    /// Device calibration grant.
    Calibrate,
    /// Deletion effect commit grant.
    DeleteCommit,
    /// Deletion effect prepare grant.
    DeletePrepare,
    /// Drone capture operation grant.
    DroneCapture,
    /// Drone flight operation grant.
    DroneFlight,
    /// Data export commit grant.
    ExportCommit,
    /// Data export prepare grant.
    ExportPrepare,
    /// Ledger append grant.
    LedgerAppend,
    /// Media decode grant.
    MediaDecode,
    /// Model inference grant.
    ModelInfer,
    /// Object publish grant.
    ObjectPublish,
    /// Object stage grant.
    ObjectStage,
    /// Event observation grant.
    ObserveEvent,
    /// Status observation grant.
    ObserveStatus,
    /// Pan-tilt-zoom effect commit grant.
    PtzCommit,
    /// Pan-tilt-zoom effect prepare grant.
    PtzPrepare,
    /// Spatial geometry read grant.
    ReadGeometry,
    /// Raw media read grant.
    ReadMedia,
    /// Repair effect commit grant.
    RepairCommit,
    /// Repair effect prepare grant.
    RepairPrepare,
    /// Retention effect commit grant.
    RetentionCommit,
    /// Retention effect prepare grant.
    RetentionPrepare,

    /// Prohibited cognition variant for inferring mission meaning.
    InferMissionMeaning,
    /// Prohibited cognition variant for inferring physical truth.
    InferPhysicalTruth,
}

impl RuntimeGrant {
    /// Returns the canonical stable string identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AdapterAuth => "CAP-ADAPTER-AUTH-001",
            Self::AdapterNet => "CAP-ADAPTER-NET-001",
            Self::AgentCancel => "CAP-AGENT-CANCEL-001",
            Self::AgentCaseWrite => "CAP-AGENT-CASE-WRITE-001",
            Self::AgentEvidenceHydrate => "CAP-AGENT-EVIDENCE-HYDRATE-001",
            Self::AgentExplain => "CAP-AGENT-EXPLAIN-001",
            Self::AgentFeedback => "CAP-AGENT-FEEDBACK-001",
            Self::AgentFindingWrite => "CAP-AGENT-FINDING-WRITE-001",
            Self::AgentHandoffRead => "CAP-AGENT-HANDOFF-READ-001",
            Self::AgentHandoffWrite => "CAP-AGENT-HANDOFF-WRITE-001",
            Self::AgentInvestigate => "CAP-AGENT-INVESTIGATE-001",
            Self::AgentPlanCommit => "CAP-AGENT-PLAN-COMMIT-001",
            Self::AgentPlanPrepare => "CAP-AGENT-PLAN-PREPARE-001",
            Self::AgentQuery => "CAP-AGENT-QUERY-001",
            Self::AgentSessionOpen => "CAP-AGENT-SESSION-OPEN-001",
            Self::AgentSessionRead => "CAP-AGENT-SESSION-READ-001",
            Self::AgentSessionWrite => "CAP-AGENT-SESSION-WRITE-001",
            Self::AgentSituationRead => "CAP-AGENT-SITUATION-READ-001",
            Self::AgentWorkClaim => "CAP-AGENT-WORK-CLAIM-001",
            Self::AlertCommit => "CAP-ALERT-COMMIT-001",
            Self::AlertPrepare => "CAP-ALERT-PREPARE-001",
            Self::Calibrate => "CAP-CALIBRATE-001",
            Self::DeleteCommit => "CAP-DELETE-COMMIT-001",
            Self::DeletePrepare => "CAP-DELETE-PREPARE-001",
            Self::DroneCapture => "CAP-DRONE-CAPTURE-001",
            Self::DroneFlight => "CAP-DRONE-FLIGHT-001",
            Self::ExportCommit => "CAP-EXPORT-COMMIT-001",
            Self::ExportPrepare => "CAP-EXPORT-PREPARE-001",
            Self::LedgerAppend => "CAP-LEDGER-APPEND-001",
            Self::MediaDecode => "CAP-MEDIA-DECODE-001",
            Self::ModelInfer => "CAP-MODEL-INFER-001",
            Self::ObjectPublish => "CAP-OBJECT-PUBLISH-001",
            Self::ObjectStage => "CAP-OBJECT-STAGE-001",
            Self::ObserveEvent => "CAP-OBSERVE-EVENT-001",
            Self::ObserveStatus => "CAP-OBSERVE-STATUS-001",
            Self::PtzCommit => "CAP-PTZ-COMMIT-001",
            Self::PtzPrepare => "CAP-PTZ-PREPARE-001",
            Self::ReadGeometry => "CAP-READ-GEOMETRY-001",
            Self::ReadMedia => "CAP-READ-MEDIA-001",
            Self::RepairCommit => "CAP-REPAIR-COMMIT-001",
            Self::RepairPrepare => "CAP-REPAIR-PREPARE-001",
            Self::RetentionCommit => "CAP-RETENTION-COMMIT-001",
            Self::RetentionPrepare => "CAP-RETENTION-PREPARE-001",
            Self::InferMissionMeaning => "PROHIBITED-INFER-MISSION-MEANING",
            Self::InferPhysicalTruth => "PROHIBITED-INFER-PHYSICAL-TRUTH",
        }
    }

    /// Resolves a capability grant from its registered identifier.
    pub fn from_id(id: &str) -> Result<Self, ContractError> {
        match id {
            "CAP-ADAPTER-AUTH-001" => Ok(Self::AdapterAuth),
            "CAP-ADAPTER-NET-001" => Ok(Self::AdapterNet),
            "CAP-AGENT-CANCEL-001" => Ok(Self::AgentCancel),
            "CAP-AGENT-CASE-WRITE-001" => Ok(Self::AgentCaseWrite),
            "CAP-AGENT-EVIDENCE-HYDRATE-001" => Ok(Self::AgentEvidenceHydrate),
            "CAP-AGENT-EXPLAIN-001" => Ok(Self::AgentExplain),
            "CAP-AGENT-FEEDBACK-001" => Ok(Self::AgentFeedback),
            "CAP-AGENT-FINDING-WRITE-001" => Ok(Self::AgentFindingWrite),
            "CAP-AGENT-HANDOFF-READ-001" => Ok(Self::AgentHandoffRead),
            "CAP-AGENT-HANDOFF-WRITE-001" => Ok(Self::AgentHandoffWrite),
            "CAP-AGENT-INVESTIGATE-001" => Ok(Self::AgentInvestigate),
            "CAP-AGENT-PLAN-COMMIT-001" => Ok(Self::AgentPlanCommit),
            "CAP-AGENT-PLAN-PREPARE-001" => Ok(Self::AgentPlanPrepare),
            "CAP-AGENT-QUERY-001" => Ok(Self::AgentQuery),
            "CAP-AGENT-SESSION-OPEN-001" => Ok(Self::AgentSessionOpen),
            "CAP-AGENT-SESSION-READ-001" => Ok(Self::AgentSessionRead),
            "CAP-AGENT-SESSION-WRITE-001" => Ok(Self::AgentSessionWrite),
            "CAP-AGENT-SITUATION-READ-001" => Ok(Self::AgentSituationRead),
            "CAP-AGENT-WORK-CLAIM-001" => Ok(Self::AgentWorkClaim),
            "CAP-ALERT-COMMIT-001" => Ok(Self::AlertCommit),
            "CAP-ALERT-PREPARE-001" => Ok(Self::AlertPrepare),
            "CAP-CALIBRATE-001" => Ok(Self::Calibrate),
            "CAP-DELETE-COMMIT-001" => Ok(Self::DeleteCommit),
            "CAP-DELETE-PREPARE-001" => Ok(Self::DeletePrepare),
            "CAP-DRONE-CAPTURE-001" => Ok(Self::DroneCapture),
            "CAP-DRONE-FLIGHT-001" => Ok(Self::DroneFlight),
            "CAP-EXPORT-COMMIT-001" => Ok(Self::ExportCommit),
            "CAP-EXPORT-PREPARE-001" => Ok(Self::ExportPrepare),
            "CAP-LEDGER-APPEND-001" => Ok(Self::LedgerAppend),
            "CAP-MEDIA-DECODE-001" => Ok(Self::MediaDecode),
            "CAP-MODEL-INFER-001" => Ok(Self::ModelInfer),
            "CAP-OBJECT-PUBLISH-001" => Ok(Self::ObjectPublish),
            "CAP-OBJECT-STAGE-001" => Ok(Self::ObjectStage),
            "CAP-OBSERVE-EVENT-001" => Ok(Self::ObserveEvent),
            "CAP-OBSERVE-STATUS-001" => Ok(Self::ObserveStatus),
            "CAP-PTZ-COMMIT-001" => Ok(Self::PtzCommit),
            "CAP-PTZ-PREPARE-001" => Ok(Self::PtzPrepare),
            "CAP-READ-GEOMETRY-001" => Ok(Self::ReadGeometry),
            "CAP-READ-MEDIA-001" => Ok(Self::ReadMedia),
            "CAP-REPAIR-COMMIT-001" => Ok(Self::RepairCommit),
            "CAP-REPAIR-PREPARE-001" => Ok(Self::RepairPrepare),
            "CAP-RETENTION-COMMIT-001" => Ok(Self::RetentionCommit),
            "CAP-RETENTION-PREPARE-001" => Ok(Self::RetentionPrepare),
            "PROHIBITED-INFER-MISSION-MEANING"
            | "cap:mission-meaning"
            | "cap:mission_meaning"
            | "cap:infer-mission-meaning" => Ok(Self::InferMissionMeaning),
            "PROHIBITED-INFER-PHYSICAL-TRUTH"
            | "cap:physicaltruth"
            | "cap:physical-truth"
            | "cap:physical_truth"
            | "cap:infer-physical-truth" => Ok(Self::InferPhysicalTruth),
            _ => Err(ContractError::UnregisteredCapabilityGrant(id.to_string())),
        }
    }

    /// Returns true if this grant illegally claims to infer mission meaning.
    #[must_use]
    pub const fn infers_mission_meaning(self) -> bool {
        matches!(self, Self::InferMissionMeaning)
    }

    /// Returns true if this grant illegally claims to infer physical truth.
    #[must_use]
    pub const fn infers_physical_truth(self) -> bool {
        matches!(self, Self::InferPhysicalTruth)
    }

    /// Returns the semantic plane for this grant.
    #[must_use]
    pub const fn plane(self) -> Plane {
        match self {
            Self::InferMissionMeaning | Self::InferPhysicalTruth => Plane::Cognition,
            Self::AlertCommit
            | Self::AlertPrepare
            | Self::DeleteCommit
            | Self::DeletePrepare
            | Self::DroneFlight
            | Self::ExportCommit
            | Self::ExportPrepare
            | Self::PtzCommit
            | Self::PtzPrepare
            | Self::RepairCommit
            | Self::RepairPrepare
            | Self::RetentionCommit
            | Self::RetentionPrepare => Plane::Effect,
            _ => Plane::Authority,
        }
    }
}

impl fmt::Display for RuntimeGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RuntimeGrant {
    type Err = ContractError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_id(s)
    }
}

impl CanonicalEncode for RuntimeGrant {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(self.as_str());
    }
}

impl CanonicalDecode for RuntimeGrant {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let text = decoder.text()?;
        Self::from_id(text)
    }
}

/// Parameters for constructing a [`RuntimeAuthorityAndCustodyRecord`].
#[derive(Clone, Debug, PartialEq)]
pub struct RuntimeAuthorityParams {
    /// Stable record identifier.
    pub record_id: String,
    /// Generation of the runtime authority plane.
    pub generation: Generation,
    /// Explicit context authority (`Cx`).
    pub context: ContextAuthority,
    /// Active capability grants held by this record.
    pub grants: Vec<RuntimeGrant>,
    /// Region identity in the runtime tree.
    pub region_id: RegionId,
    /// Kind of region.
    pub region_kind: RegionKind,
    /// Owning parent region identity, if non-root.
    pub parent_region_id: Option<RegionId>,
    /// Current execution or closure state of the region.
    pub region_state: RegionState,
    /// Verified quiescence proof / drain record (required when Closed).
    pub quiescence_proof: Option<QuiescenceProof>,
    /// Source evidence custodial status.
    pub custody: SourceCustody,
    /// Durable obligations tracked within this region.
    pub obligations: Vec<Obligation>,
    /// Cryptographic object roots under custody.
    pub object_roots: Vec<ContentDigest>,
    /// Cryptographic receipt roots issued under this authority.
    pub receipt_roots: Vec<ContentDigest>,
    /// Optional contract basis binding capability and registry digests.
    pub contract_basis: Option<ContractBasis>,
}

/// An authoritative runtime authority and custody record (AGT-LAYER-001, INV-006).
///
/// Output: "Context, grants, regions, obligations, object roots, and receipts."
/// Prohibition: "Cannot infer mission meaning or physical truth."
#[derive(Clone, Debug, PartialEq)]
pub struct RuntimeAuthorityAndCustodyRecord {
    /// Stable record identifier (e.g. `auth:record:001`).
    pub record_id: String,
    /// Generation identifier.
    pub generation: Generation,
    /// Context authority (`Cx`) carrying principal, trace, budgets, and capabilities.
    pub context: ContextAuthority,
    /// Active capability grants held under this authority.
    pub grants: Vec<RuntimeGrant>,
    /// Region identity in the single-owner runtime tree.
    pub region_id: RegionId,
    /// Kind of region in the normative tree.
    pub region_kind: RegionKind,
    /// Parent region identity (must be None for ProcessRegion, Some for others).
    pub parent_region_id: Option<RegionId>,
    /// Lifecycle state of the region.
    pub region_state: RegionState,
    /// Verified quiescence proof emitted upon closure.
    pub quiescence_proof: Option<QuiescenceProof>,
    /// Source evidence custody status.
    pub custody: SourceCustody,
    /// Durable obligations tracked in this authority boundary.
    pub obligations: Vec<Obligation>,
    /// Object roots held under custody.
    pub object_roots: Vec<ContentDigest>,
    /// Receipt roots published by this authority.
    pub receipt_roots: Vec<ContentDigest>,
    /// Optional contract basis wiring this authority into registries.
    pub contract_basis: Option<ContractBasis>,
}

/// Type alias for [`RuntimeAuthorityAndCustodyRecord`].
pub type RuntimeAuthorityRecord = RuntimeAuthorityAndCustodyRecord;
/// Type alias for backward compatibility.
pub type RuntimeAuthorityAndCustody = RuntimeAuthorityAndCustodyRecord;

impl RuntimeAuthorityAndCustodyRecord {
    /// Constructs and validates a new runtime authority and custody record.
    pub fn new(params: RuntimeAuthorityParams) -> Result<Self, ContractError> {
        let record = Self {
            record_id: params.record_id,
            generation: params.generation,
            context: params.context,
            grants: params.grants,
            region_id: params.region_id,
            region_kind: params.region_kind,
            parent_region_id: params.parent_region_id,
            region_state: params.region_state,
            quiescence_proof: params.quiescence_proof,
            custody: params.custody,
            obligations: params.obligations,
            object_roots: params.object_roots,
            receipt_roots: params.receipt_roots,
            contract_basis: params.contract_basis,
        };
        record.validate()?;
        Ok(record)
    }

    /// Validates constitutional invariants for this record (INV-006 & AGENTS.md).
    pub fn validate(&self) -> Result<(), ContractError> {
        // 1. Identity validation
        validate_id(&self.record_id)?;

        // 2. Generation pinning: cannot be generation 0
        if self.generation.0 == 0 {
            return Err(ContractError::GenerationConflict);
        }

        // 3. Cx context authority validation
        self.context.validate()?;
        if self.generation.0 != self.context.generation {
            return Err(ContractError::GenerationConflict);
        }

        // 4. Grants validation:
        // Strictly ascending order with no duplicates
        for window in self.grants.windows(2) {
            if window[0] == window[1] {
                return Err(ContractError::DuplicateGrant(
                    window[0].as_str().to_string(),
                ));
            }
            if window[0] > window[1] {
                return Err(ContractError::NonCanonicalOrdering);
            }
        }

        // Monotone Cx binding: all grants must be held by context authority
        for grant in &self.grants {
            if !self.context.has_capability(grant.as_str()) {
                return Err(ContractError::UnboundCapabilityGrant(
                    grant.as_str().to_string(),
                ));
            }
        }

        // Constitutional Hard Gate: Cannot infer mission meaning (INV-006)
        if !self.prohibits_mission_meaning_inference() {
            return Err(ContractError::ProhibitedMissionMeaningInference);
        }

        // Constitutional Hard Gate: Cannot infer physical truth (INV-006)
        if !self.prohibits_physical_truth_inference() {
            return Err(ContractError::ProhibitedPhysicalTruthInference);
        }

        // 5. Region ownership invariants (INV-006 & single-owner rule)
        // Self-parented region check
        if self.parent_region_id.as_ref() == Some(&self.region_id) {
            return Err(ContractError::SelfParentedRegion(
                self.region_id.to_string(),
            ));
        }

        // ProcessRegion is root: must have no parent
        if self.region_kind == RegionKind::Process {
            if self.parent_region_id.is_some() {
                return Err(ContractError::RootRegionWithParent(
                    self.region_id.to_string(),
                ));
            }
        } else if self.parent_region_id.is_none() {
            // Non-root region missing parent: orphan work forbidden
            return Err(ContractError::OrphanRegion(self.region_id.to_string()));
        }

        // Cancellation lifecycle: DrainRequested, Draining, or Finalizing requires cancellation reason
        if matches!(
            self.region_state,
            RegionState::DrainRequested | RegionState::Draining | RegionState::Finalizing
        ) && self.context.cancellation_reason.is_none()
        {
            return Err(ContractError::MissingCancellationReason);
        }

        // Quiescence check for Closed state
        if self.region_state == RegionState::Closed {
            // Closed region must have a verified drain record (quiescence proof)
            let proof = self
                .quiescence_proof
                .as_ref()
                .ok_or(ContractError::MissingDrainRecord)?;

            if proof.region_id != self.region_id {
                return Err(ContractError::ProofRegionMismatch(
                    proof.region_id.to_string(),
                ));
            }
            if proof.region_kind != self.region_kind {
                return Err(ContractError::ProofRegionMismatch(
                    proof.region_kind.as_str().to_string(),
                ));
            }
            if proof.parent_id != self.parent_region_id {
                return Err(ContractError::ProofRegionMismatch(
                    proof
                        .parent_id
                        .as_ref()
                        .map(|p| p.to_string())
                        .unwrap_or_else(|| "none".to_string()),
                ));
            }
            if proof.indeterminate_obligations != 0 {
                return Err(ContractError::IndeterminateObligationOnClosure(format!(
                    "quiescence_proof.indeterminate_obligations={}",
                    proof.indeterminate_obligations
                )));
            }
            if self.obligations.is_empty() && proof.total_obligations != 0 {
                return Err(ContractError::ProofRegionMismatch(format!(
                    "proof.total_obligations ({}) != 0 with empty record obligations",
                    proof.total_obligations,
                )));
            }
            if proof.total_obligations < self.obligations.len() as u64 {
                return Err(ContractError::ProofRegionMismatch(format!(
                    "proof.total_obligations ({}) < record.obligations ({})",
                    proof.total_obligations,
                    self.obligations.len(),
                )));
            }
            if !self.obligations.is_empty() && proof.total_tasks == 0 {
                return Err(ContractError::ProofRegionMismatch(
                    "proof.total_tasks=0 with non-empty record obligations".to_string(),
                ));
            }
            let expected_digest = QuiescenceProof::compute_digest(
                &proof.region_id,
                proof.region_kind,
                proof.parent_id.as_ref(),
                proof.closed_at,
                proof.total_tasks,
                proof.total_obligations,
                proof.indeterminate_obligations,
            );
            if proof.proof_digest != expected_digest {
                return Err(ContractError::DigestMismatch);
            }

            // Closed region cannot retain pending or indeterminate obligations
            for ob in &self.obligations {
                if ob.state == ObligationState::Pending {
                    return Err(ContractError::UnresolvedObligationOnClosure(
                        ob.obligation_id.to_string(),
                    ));
                }
                if ob.state == ObligationState::Indeterminate {
                    return Err(ContractError::IndeterminateObligationOnClosure(
                        ob.obligation_id.to_string(),
                    ));
                }
            }
        } else if self.quiescence_proof.is_some() {
            // Premature quiescence proof before region closure is forbidden
            return Err(ContractError::PrematureQuiescenceProof);
        }

        // 6. Custody invariants
        match &self.custody {
            SourceCustody::Retained {
                source_digest,
                source_bytes,
                storage_handle,
            } => {
                if *source_bytes == 0 {
                    return Err(ContractError::EvidenceRequired);
                }
                if storage_handle.is_empty() || storage_handle.len() > 256 {
                    return Err(ContractError::InvalidIdentifier);
                }
                if source_digest.bytes() == [0u8; 32] {
                    return Err(ContractError::InvalidDigest);
                }
                // Object roots must contain exactly the retained source digest without extra unrelated roots
                if self.object_roots.len() != 1 || self.object_roots[0] != *source_digest {
                    return Err(ContractError::CustodyRootMismatch);
                }
            }
            SourceCustody::NotRetained => {
                if !self.object_roots.is_empty() {
                    return Err(ContractError::EvidenceRequired);
                }
            }
        }

        // 7. Obligations invariants
        // Strictly ascending order with no duplicates
        for window in self.obligations.windows(2) {
            if window[0].obligation_id == window[1].obligation_id {
                return Err(ContractError::DuplicateObligation(
                    window[0].obligation_id.to_string(),
                ));
            }
            if window[0].obligation_id > window[1].obligation_id {
                return Err(ContractError::NonCanonicalOrdering);
            }
        }
        for ob in &self.obligations {
            validate_id(ob.obligation_id.as_str())?;
            if ob.terminal_predicate.is_empty() || ob.terminal_predicate.len() > 512 {
                return Err(ContractError::InvalidIdentifier);
            }
            if ob.operation_id != self.context.operation_id {
                return Err(ContractError::ObligationConflict);
            }
            match ob.state {
                ObligationState::Verified | ObligationState::Failed => {
                    if ob.proof_digest.is_none() {
                        return Err(ContractError::EvidenceRequired);
                    }
                }
                ObligationState::Pending => {
                    if ob.proof_digest.is_some() {
                        return Err(ContractError::InvalidEffectTransition);
                    }
                }
                ObligationState::Indeterminate | ObligationState::Cancelled => {}
            }
        }

        // 8. Object roots and receipt roots validation
        for root in &self.object_roots {
            if root.bytes() == [0u8; 32] {
                return Err(ContractError::InvalidDigest);
            }
        }
        for receipt in &self.receipt_roots {
            if receipt.bytes() == [0u8; 32] {
                return Err(ContractError::InvalidDigest);
            }
        }
        for window in self.receipt_roots.windows(2) {
            if window[0] >= window[1] {
                return Err(ContractError::NonCanonicalOrdering);
            }
        }

        // 9. Contract basis cross-check, when wired
        if self
            .contract_basis
            .as_ref()
            .is_some_and(|basis| basis.capability_registry_digest.bytes() == [0u8; 32])
        {
            return Err(ContractError::InvalidDigest);
        }

        Ok(())
    }

    /// Validates all constitutional and semantic invariants for runtime authority and custody.
    pub fn validate_invariants(&self) -> Result<(), ContractError> {
        self.validate()
    }

    /// Returns the abstraction layer (`AGT-LAYER-001`).
    #[must_use]
    pub const fn layer(&self) -> AgentAbstractionLayer {
        AgentAbstractionLayer::RuntimeAuthorityAndCustody
    }

    /// Returns the semantic plane (`Plane::Authority`).
    #[must_use]
    pub const fn plane(&self) -> Plane {
        Plane::Authority
    }

    /// Returns the normative invariant ID (`INV-006`).
    #[must_use]
    pub const fn invariant(&self) -> &'static str {
        "INV-006"
    }

    /// Returns true if this record prohibits mission meaning inference.
    ///
    /// Derived from real record state: returns false if any grant or state
    /// attempts to infer mission meaning.
    #[must_use]
    pub fn prohibits_mission_meaning_inference(&self) -> bool {
        !self.grants.iter().any(|g| g.infers_mission_meaning())
    }

    /// Returns true if this record prohibits physical truth inference.
    ///
    /// Derived from real record state: returns false if any grant or state
    /// attempts to infer physical truth.
    #[must_use]
    pub fn prohibits_physical_truth_inference(&self) -> bool {
        !self.grants.iter().any(|g| g.infers_physical_truth())
    }

    /// Returns whether this record may claim authority plane ownership (always true).
    #[must_use]
    pub const fn may_claim_authority(&self) -> bool {
        true
    }

    /// Returns whether this record may authorize side effects (always false for runtime authority alone).
    #[must_use]
    pub const fn may_authorize_effects(&self) -> bool {
        false
    }

    /// Returns whether this layer is anchor-pinned (false for L0 runtime authority).
    #[must_use]
    pub const fn is_anchor_pinned(&self) -> bool {
        false
    }

    /// Returns whether this layer is rebuildable (false for L0 runtime authority).
    #[must_use]
    pub const fn is_rebuildable(&self) -> bool {
        false
    }

    /// Returns true if the specified capability grant is held.
    #[must_use]
    pub fn has_grant(&self, grant: RuntimeGrant) -> bool {
        self.grants.contains(&grant)
    }

    /// Returns true if source evidence is retained under custody.
    #[must_use]
    pub const fn is_retained_custody(&self) -> bool {
        self.custody.is_retained()
    }

    /// Returns true if the region is quiescent (closed with verified drain record).
    #[must_use]
    pub fn is_quiescent(&self) -> bool {
        self.region_state == RegionState::Closed && self.quiescence_proof.is_some()
    }

    /// Computes the canonical content digest of this runtime authority record.
    #[must_use]
    pub fn canonical_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        self.encode_canonical(&mut encoder);
        ContentDigest::sha256(&encoder.finish())
    }
}

impl CanonicalEncode for RuntimeAuthorityAndCustodyRecord {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(RUNTIME_AUTHORITY_DOMAIN);
        encoder.text(&self.record_id);
        self.generation.encode_canonical(encoder);
        self.context.encode_canonical(encoder);
        encoder.u64(self.grants.len() as u64);
        for grant in &self.grants {
            grant.encode_canonical(encoder);
        }
        self.region_id.encode_canonical(encoder);
        self.region_kind.encode_canonical(encoder);
        match &self.parent_region_id {
            Some(pid) => {
                encoder.bool(true);
                pid.encode_canonical(encoder);
            }
            None => encoder.bool(false),
        }
        self.region_state.encode_canonical(encoder);
        match &self.quiescence_proof {
            Some(proof) => {
                encoder.bool(true);
                proof.encode_canonical(encoder);
            }
            None => encoder.bool(false),
        }
        self.custody.encode_canonical(encoder);
        encoder.u64(self.obligations.len() as u64);
        for ob in &self.obligations {
            ob.encode_canonical(encoder);
        }
        encoder.u64(self.object_roots.len() as u64);
        for root in &self.object_roots {
            encoder.digest(*root);
        }
        encoder.u64(self.receipt_roots.len() as u64);
        for receipt in &self.receipt_roots {
            encoder.digest(*receipt);
        }
        match &self.contract_basis {
            Some(basis) => {
                encoder.bool(true);
                basis.encode_canonical(encoder);
            }
            None => encoder.bool(false),
        }
    }
}

impl CanonicalDecode for RuntimeAuthorityAndCustodyRecord {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let domain = decoder.text()?;
        if domain != RUNTIME_AUTHORITY_DOMAIN {
            return Err(ContractError::InvalidIdentifier);
        }
        let record_id = decoder.text()?.to_string();
        let generation = Generation::decode_canonical(decoder)?;
        let context = ContextAuthority::decode_canonical(decoder)?;
        let grant_count = decoder.u64()?;
        if grant_count > decoder.remaining() as u64 {
            return Err(ContractError::CountBoundExceeded);
        }
        let grant_count = grant_count as usize;
        let mut grants = Vec::with_capacity(grant_count);
        let mut prev_grant: Option<RuntimeGrant> = None;
        for _ in 0..grant_count {
            let grant = RuntimeGrant::decode_canonical(decoder)?;
            if let Some(prev) = prev_grant {
                if grant == prev {
                    return Err(ContractError::DuplicateGrant(grant.as_str().to_string()));
                }
                if grant < prev {
                    return Err(ContractError::NonCanonicalOrdering);
                }
            }
            prev_grant = Some(grant);
            grants.push(grant);
        }
        let region_id = RegionId::decode_canonical(decoder)?;
        let region_kind = RegionKind::decode_canonical(decoder)?;
        let parent_region_id = if decoder.bool()? {
            Some(RegionId::decode_canonical(decoder)?)
        } else {
            None
        };
        let region_state = RegionState::decode_canonical(decoder)?;
        let quiescence_proof = if decoder.bool()? {
            Some(QuiescenceProof::decode_canonical(decoder)?)
        } else {
            None
        };
        let custody = SourceCustody::decode_canonical(decoder)?;
        let ob_count = decoder.u64()?;
        if ob_count > decoder.remaining() as u64 {
            return Err(ContractError::CountBoundExceeded);
        }
        let ob_count = ob_count as usize;
        let mut obligations = Vec::with_capacity(ob_count);
        let mut prev_ob: Option<ObligationId> = None;
        for _ in 0..ob_count {
            let ob = Obligation::decode_canonical(decoder)?;
            if let Some(prev) = &prev_ob {
                if ob.obligation_id == *prev {
                    return Err(ContractError::DuplicateObligation(
                        ob.obligation_id.to_string(),
                    ));
                }
                if ob.obligation_id < *prev {
                    return Err(ContractError::NonCanonicalOrdering);
                }
            }
            prev_ob = Some(ob.obligation_id.clone());
            obligations.push(ob);
        }
        let root_count = decoder.u64()?;
        if root_count > decoder.remaining() as u64 {
            return Err(ContractError::CountBoundExceeded);
        }
        let root_count = root_count as usize;
        let mut object_roots = Vec::with_capacity(root_count);
        let mut prev_root: Option<ContentDigest> = None;
        for _ in 0..root_count {
            let root = decoder.digest()?;
            if let Some(prev) = prev_root
                && root <= prev
            {
                return Err(ContractError::NonCanonicalOrdering);
            }
            prev_root = Some(root);
            object_roots.push(root);
        }
        let receipt_count = decoder.u64()?;
        if receipt_count > decoder.remaining() as u64 {
            return Err(ContractError::CountBoundExceeded);
        }
        let receipt_count = receipt_count as usize;
        let mut receipt_roots = Vec::with_capacity(receipt_count);
        let mut prev_receipt: Option<ContentDigest> = None;
        for _ in 0..receipt_count {
            let receipt = decoder.digest()?;
            if let Some(prev) = prev_receipt
                && receipt <= prev
            {
                return Err(ContractError::NonCanonicalOrdering);
            }
            prev_receipt = Some(receipt);
            receipt_roots.push(receipt);
        }
        let contract_basis = if decoder.bool()? {
            Some(ContractBasis::decode_canonical(decoder)?)
        } else {
            None
        };

        let record = Self {
            record_id,
            generation,
            context,
            grants,
            region_id,
            region_kind,
            parent_region_id,
            region_state,
            quiescence_proof,
            custody,
            obligations,
            object_roots,
            receipt_roots,
            contract_basis,
        };
        record.validate()?;
        Ok(record)
    }
}

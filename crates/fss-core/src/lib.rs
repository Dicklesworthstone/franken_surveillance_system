#![forbid(unsafe_code)]
//! Dependency-free semantic reference contracts for Franken Surveillance System.
//!
//! This crate owns deterministic identities, canonical encoding, append-only evidence
//! state, witnessed absence, event semantics, effect reconciliation, and the first
//! agent-facing situation and handoff objects. It performs no device I/O and invokes
//! no foreign runtime.

mod agent;
mod canonical;
mod compression;
mod context_binding;
mod context_binding_metadata;
mod continuation;
mod contract;
mod delta;
mod digest;
mod effect;
mod event;
mod evidence;
pub mod hydration;
mod ids;
mod projection;
mod time;

pub use agent::{
    ActionAffordance, AffordanceClass, ContractBasis, ContractBasisRegistryBytes, HandoffCapsule,
    HandoffPublishParams, KnowledgeCell, PossibleWorld, SituationCapsule, SituationFrame,
    WorldEnvelope,
};
pub use canonical::{
    CANONICAL_FORMAT_MAGIC, CANONICAL_VERSION_1, CanonicalDecode, CanonicalDecoder,
    CanonicalEncode, CanonicalEncoder, CanonicalVersionEnvelope, MAX_CANONICAL_BYTES_LEN,
    MAX_CANONICAL_TEXT_BYTES,
};
pub use compression::SemanticCompressionReceipt;
pub use context_binding::{
    ContextBindingError, ContextExpansionBinding, ContextExpansionBindingSet,
    SemanticHandleReference,
};
pub use continuation::*;
pub use contract::{
    BudgetDimension, BudgetError, BudgetLogRecord, BudgetQuantitiesSpec, BudgetQuantity,
    BudgetVector, BudgetVectorBuilder, BudgetVectorSpec, Completeness, ContractError,
    EvidenceClass, HypothesisDisposition, KnowledgeState, Plane, ProvenanceClass, RecoveryClass,
    RuntimeOutcome,
};
pub use delta::{DeltaPriority, MeaningfulDelta, MeaningfulDeltaClass, SilenceCertificate};
pub use digest::{ContentDigest, DigestAlgorithm, Sha256Hasher, sha256};
pub use effect::{
    EffectIntent, EffectJournal, EffectState, Obligation, ObligationState, OperationReceipt,
};
pub use event::{EventEvidence, EventHypothesis, EventKind, EventState, ProbabilityInterval};
pub use evidence::{
    ClockBasis, CoverageContinuity, CoverageStopReason, CoverageWitness, EvidenceDelta,
    EvidenceDeltaBatch, LedgerAnchor, LedgerSnapshot, ObjectRevision, ReferenceLedger,
    SensorCapsule, SensorSourceBytesSpec,
};
pub use hydration::{
    HYDRATION_VIEW_ID, HandleAvailability, HydrationArtifact, HydrationError, HydrationLevel,
    HydrationPurpose, HydrationReceipt, HydrationReceiptSpec, HydrationRequest,
    HydrationRequestSpec, HydrationResponse, LaboratoryAccess, SemanticHandle, SemanticHandleSpec,
};
pub use ids::{
    AdapterEpoch, AdapterGeneration, AffordanceId, BatchId, CalibrationGeneration, CapsuleId,
    CaseId, ContextPackId, DeviceGeneration, DeviceId, EpisodeId, Epoch, EventId, FindingId,
    Generation, GraphGeneration, HandoffId, HypothesisId, IdempotencyKey, IdentityLifecycleState,
    LedgerEpoch, MissionId, ModelGeneration, ObjectId, ObligationId, OntologyGeneration,
    OperationId, PlanId, PolicyEpoch, PolicyGeneration, PolicyId, PrincipalId, PrivacyEpoch,
    PrivacyGeneration, PropertyId, SchemaEpoch, SchemaId, SearchGeneration, SensorId, SessionId,
    StreamGeneration, StreamId, TombstoneId, TombstoneReason, TombstoneRecord, TombstoneRegistry,
    TrackId, WorkspaceId,
};

pub use projection::{
    BranchCondition, CompressionCompleteness, CompressionLossClass, CompressionStopReason,
    CompressionTransform, CompressionTransformKind, ContextItem, ControlEnvelope,
    CriticalPreservation, ExpansionHandle, ResourcePressure, ResourceState, SemanticContextPack,
    reference_token_count,
};
pub use time::{
    CaptureInterval, CaptureIntervalWithBasis, IntervalContainment, IntervalUnion,
    TemporalPrecedence, TimeIntervalError, TimestampNs,
};

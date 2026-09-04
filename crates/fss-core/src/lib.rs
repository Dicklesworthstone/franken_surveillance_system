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
    ActionAffordance, AffordanceClass, ContractBasis, HandoffCapsule, KnowledgeCell, PossibleWorld,
    SituationCapsule, SituationFrame, WorldEnvelope,
};
pub use canonical::{CanonicalEncode, CanonicalEncoder};
pub use compression::SemanticCompressionReceipt;
pub use context_binding::{
    ContextBindingError, ContextExpansionBinding, ContextExpansionBindingSet,
    SemanticHandleReference,
};
pub use continuation::*;
pub use contract::{
    BudgetVector, Completeness, ContractError, EvidenceClass, HypothesisDisposition,
    KnowledgeState, Plane, ProvenanceClass, RecoveryClass, RuntimeOutcome,
};
pub use delta::{DeltaPriority, MeaningfulDelta, MeaningfulDeltaClass, SilenceCertificate};
pub use digest::{ContentDigest, DigestAlgorithm, sha256};
pub use effect::{
    EffectIntent, EffectJournal, EffectState, Obligation, ObligationState, OperationReceipt,
};
pub use event::{EventEvidence, EventHypothesis, EventKind, EventState, ProbabilityInterval};
pub use evidence::{
    ClockBasis, CoverageContinuity, CoverageStopReason, CoverageWitness, EvidenceDelta,
    EvidenceDeltaBatch, LedgerAnchor, LedgerSnapshot, ObjectRevision, ReferenceLedger,
    SensorCapsule,
};
pub use ids::{
    BatchId, CapsuleId, EventId, HandoffId, IdempotencyKey, MissionId, ObjectId, ObligationId,
    OperationId, PrincipalId, SensorId, SessionId, StreamId,
};
pub use projection::{
    BranchCondition, CompressionCompleteness, CompressionLossClass, CompressionStopReason,
    CompressionTransform, CompressionTransformKind, ContextItem, ControlEnvelope,
    CriticalPreservation, ExpansionHandle, ResourcePressure, ResourceState, SemanticContextPack,
    reference_token_count,
};
pub use time::{CaptureInterval, TimestampNs};

#![forbid(unsafe_code)]
//! Dependency-free semantic reference contracts for Franken Surveillance System.
//!
//! This crate owns deterministic identities, canonical encoding, append-only evidence
//! state, witnessed absence, event semantics, effect reconciliation, and the first
//! agent-facing situation and handoff objects. It performs no device I/O and invokes
//! no foreign runtime.

pub mod acquisition;
mod agent;
pub mod belief;
mod canonical;
mod compression;
mod context_binding;
mod context_binding_metadata;
mod continuation;
mod contract;
mod delta;
mod digest;
pub mod durable;
pub mod effect;
pub mod event;
pub mod event_store;
mod evidence;
pub mod hydration;
pub mod identity;
mod ids;
pub mod negative_evidence;
mod outcome;
pub mod pricing;
mod projection;
pub mod region;
pub mod sensor_capsule;
pub mod temporal_verifier;
pub mod test_event;
mod time;

pub use agent::{
    ActionAffordance, AffordanceClass, ContractBasis, ContractBasisRegistryBytes, HandoffCapsule,
    HandoffPublishParams, KnowledgeCell, KnowledgeStateBasis, MissionLifecycleState, PossibleWorld,
    REDACTED_STATEMENT_MARKER, ReconciliationBasis, ReconciliationBranch, RedactionMarker,
    RedactionReason, SituationCapsule, SituationFrame, StaleBasis, WorldEnvelope,
};
pub use belief::{
    BELIEF_INTERVAL_DOMAIN, BeliefError, BeliefInterval, CONTRADICTION_DOMAIN, Contradiction,
    ContradictionParams, MAX_CLAIM_ID_LEN, MAX_CONFLICTING_EVIDENCE, MAX_CONTRADICTION_ID_LEN,
    MAX_FAILURE_DOMAINS, MAX_STATEMENT_LEN, MAX_UNRESOLVED_WORLDS, MAX_WORLD_ID_LEN,
    MICRO_DENOMINATOR, MIN_CONFLICTING_EVIDENCE, MIN_FAILURE_DOMAINS, MIN_UNRESOLVED_WORLDS,
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
pub use durable::{
    CANONICAL_DURABLE_MAGIC, CANONICAL_DURABLE_VERSION_1, ChecksumPlacement, ChecksumScope,
    DEFAULT_MAX_PAYLOAD_LEN, DurableError, DurableFormat, DurableFormatBuilder, DurableFrame,
    DurableHeader, Endianness, LengthWidth, VersionWidth,
};
pub use effect::{
    EFFECT_INTENT_SCHEMA, EFFECT_RECONCILIATION_SCHEMA, EffectIntent, EffectJournal,
    EffectJournalTransition, EffectReconciliationRecord, EffectSchemaError, EffectState,
    IndeterminateEffectReason, MAX_DETAIL_LEN, MAX_EFFECT_CLASS_LEN, MAX_ERROR_CODE_LEN,
    MAX_TERMINAL_PREDICATE_LEN, Obligation, ObligationState, OperationReceipt,
    PREPARED_EFFECT_SCHEMA, PROVIDER_FAILURE_RECEIPT_SCHEMA, PROVIDER_OBSERVATION_RECEIPT_SCHEMA,
    PreparedEffect, PreparedOperation, ProviderFailureLookup, ProviderFailureReceipt,
    ProviderObservationReceipt, ProviderReceiptLookup, ReconciliationOutcome,
};
pub use event::{
    DecisionPath, EVENT_HYPOTHESIS_MAGIC, EVENT_HYPOTHESIS_SCHEMA, EVENT_HYPOTHESIS_VERSION_1,
    EVIDENCE_GRAPH_MAGIC, EVIDENCE_GRAPH_SCHEMA, EVIDENCE_GRAPH_VERSION_1, EventDecodeError,
    EventEvidence, EventHypothesis, EventKind, EventRevision, EventState, EventTransitionParams,
    EvidenceEdgeRelation, EvidenceGraph, EvidenceNode, EvidenceNodeKind, MAX_ABSTENTION_REASON_LEN,
    MAX_EDGES_COUNT, MAX_EVENT_ID_LEN, MAX_EVIDENCE_COUNT, MAX_FAILURE_DOMAIN_LEN,
    MAX_GRAPH_ID_LEN, MAX_MODEL_RECEIPTS_COUNT, MAX_NODE_LABEL_LEN, MAX_NODES_COUNT,
    MAX_TRACK_ID_LEN, MAX_TRACKS_COUNT, MAX_ZONE_ID_LEN, MAX_ZONES_COUNT, ProbabilityInterval,
    evidence_class_as_str, evidence_class_from_u8, evidence_class_to_u8, parse_evidence_class,
};
pub use event_store::*;
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
pub use identity::{
    AdapterCapabilities, AdapterIdentity, AdapterKind, CredentialMethod, DeviceCapabilities,
    DeviceClass, DeviceIdentity, IsolationMode, MediaKind, SourceIdentity, SourceKind,
    StandardsComplianceError,
};
pub use ids::{
    AdapterEpoch, AdapterGeneration, AdapterId, AffordanceId, AppGeneration, ApplicationGeneration,
    BatchId, CalibrationGeneration, CapsuleId, CaseId, ContextPackId, DeviceGeneration, DeviceId,
    EpisodeId, Epoch, EventId, FindingId, FirmwareGeneration, Generation, GraphGeneration,
    HandoffId, HypothesisId, IdempotencyKey, IdentityLifecycleState, LedgerEpoch, MissionId,
    ModelGeneration, ObjectId, ObligationId, OntologyGeneration, OperationId, PlanId, PolicyEpoch,
    PolicyGeneration, PolicyId, PrincipalId, PrivacyEpoch, PrivacyGeneration, PropertyId,
    SchemaEpoch, SchemaId, SearchGeneration, SensorId, SessionId, SourceId, StreamGeneration,
    StreamId, TombstoneId, TombstoneReason, TombstoneRecord, TombstoneRegistry, TrackId,
    WorkspaceId,
};
pub use negative_evidence::*;

pub use outcome::{
    ERR_AUTH_DENIED_001, ERR_COVERAGE_UNKNOWN_001, ERR_EFFECT_INDETERMINATE_001,
    ERR_OP_EXECUTION_FAILED_001, ERR_OP_ID_MALFORMED_001, ERR_OP_INDETERMINATE_001,
    ERR_OP_INVALID_OUTCOME_001, ERR_OP_NOT_OBSERVABLE_001, ERR_OP_PRECONDITION_FAILED_001,
    ERR_OP_RECONCILIATION_REQUIRED_001, ERR_OP_TIMEOUT_001, ERR_OP_UNAUTHORIZED_001,
    ERR_PRECONDITION_STALE_001, ErrorId, IndeterminateDetail, OperationError, OperationOutcome,
    RefusalDetail, RefusalReason, validate_error_id,
};

pub use projection::{
    BranchCondition, CompressionCompleteness, CompressionLossClass, CompressionStopReason,
    CompressionTransform, CompressionTransformKind, ContextItem, ControlEnvelope,
    CriticalPreservation, ExpansionHandle, ResourcePressure, ResourceState, SemanticContextPack,
    SemanticContextPackPublishParams, reference_token_count,
};
pub use time::{
    CaptureInterval, CaptureIntervalWithBasis, IntervalContainment, IntervalUnion,
    TemporalPrecedence, TimeIntervalError, TimestampNs,
};

pub use sensor_capsule::{
    CapsuleDecodeError, ContinuityState, DecodeState, ExplicitOmission, IntegrityWitness,
    MAX_CAPSULE_ID_LEN, MAX_CODEC_LEN, MAX_CONTAINER_LEN, MAX_FIRMWARE_FINGERPRINT_LEN,
    MAX_POLICY_RULE_LEN, MAX_RETENTION_CLASS_LEN, MAX_STORAGE_HANDLE_LEN, MAX_STR_LEN,
    MAX_UNCERTAINTY_REASON_LEN, MediaDescriptor, OmissionReason, PrivacyDescriptor,
    PublicationDescriptor, PublicationState, RedactionState, SENSOR_CAPSULE_MAGIC,
    SENSOR_CAPSULE_METADATA_DOMAIN, SENSOR_CAPSULE_SCHEMA, SENSOR_CAPSULE_VERSION_1,
    SensorCapsuleV1, SourceCustody,
};

pub use acquisition::*;
pub use pricing::*;
pub use region::*;
pub use temporal_verifier::*;
pub use test_event::*;

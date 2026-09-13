#![forbid(unsafe_code)]
//! Dependency-free semantic reference contracts for Franken Surveillance System.
//!
//! This crate owns deterministic identities, canonical encoding, append-only evidence
//! state, witnessed absence, event semantics, effect reconciliation, and the first
//! agent-facing situation and handoff objects. It performs no device I/O and invokes
//! no foreign runtime.

pub mod abstraction;
pub mod acquisition;
mod agent;
pub mod belief;
mod canonical;
mod compression;
mod context_binding;
mod context_binding_metadata;
mod continuation;
mod contract;
pub mod contract_basis;
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

pub use abstraction::{
    AGENT_ABSTRACTION_FREEZE_DIGEST, AGENT_ABSTRACTION_GENERATION,
    AGENT_ABSTRACTIONS_FREEZE_DIGEST, AGENT_ABSTRACTIONS_GENERATION, AgentAbstractionLayer,
    CANONICAL_LAYERS, DERIVED_BELIEF_DOMAIN, DERIVED_BELIEF_RECEIPT_DOMAIN, DerivationInputs,
    DerivedBelief, DerivedBeliefParams, MAX_DERIVED_BELIEF_CONTRADICTIONS,
    MAX_DERIVED_BELIEF_EVIDENCE, NegativeReadClaim, NegativeReadOutcome, RUNTIME_AUTHORITY_DOMAIN,
    RuntimeAuthorityAndCustody, RuntimeAuthorityAndCustodyRecord, RuntimeAuthorityParams,
    RuntimeAuthorityRecord, RuntimeGrant, SOURCE_EVIDENCE_RECORD_FORMAT_VERSION,
    SourceEvidenceClassification, SourceEvidenceParams, SourceEvidenceRecord, WorldFact,
    WorldFactKind, evaluate_negative_read,
};

pub use agent::{
    ActionAffordance, AffordanceClass, ContractBasis, ContractBasisRegistryBytes, HandoffCapsule,
    HandoffPublishParams, KnowledgeCell, KnowledgeStateBasis, LABORATORY_PROVENANCE_MARKER,
    MissionLifecycleState, PossibleWorld, REDACTED_STATEMENT_MARKER, ReconciliationBasis,
    ReconciliationBranch, RedactionMarker, RedactionReason, SituationCapsule, SituationFrame,
    StaleBasis, WorldEnvelope,
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
pub use contract_basis::{
    BasisCompatibility, CANONICAL_ONTOLOGY_GENERATION_ID, CANONICAL_PRODUCER_RELEASE_ID,
    CANONICAL_SEMANTIC_PROTOCOL, CONTRACT_BASIS_FORMAT_VERSION, CONTRACT_BASIS_MAGIC,
    CompatibilityResult, ContractBasisError, ContractBasisRefusal, MAX_CONTRACT_BASIS_BINARY_BYTES,
    MIN_CONTRACT_BASIS_BINARY_BYTES, REFERENCE_CAPABILITY_REGISTRY_DIGEST,
    REFERENCE_CONTRACT_BASIS_CANONICAL_DIGEST, REFERENCE_CONTRACT_BASIS_FREEZE_DIGEST,
    REFERENCE_CONTRACT_BASIS_GENERATION, REFERENCE_COST_REGISTRY_DIGEST,
    REFERENCE_ERROR_REGISTRY_DIGEST, REFERENCE_OPERATION_REGISTRY_DIGEST,
    REFERENCE_SCHEMA_CATALOG_DIGEST, REFERENCE_VIEW_REGISTRY_DIGEST, RegistryDigestSet,
    SCHEMA_CONTRACT_BASIS, StaleBasisReason, check_basis_freshness, check_compatibility,
    decode_canonical_binary, encode_canonical_binary, negotiate_basis, reference_contract_basis,
    refuse_stale_anchor, validate_contract_basis,
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
    MAX_DETAIL_LEN, MAX_EFFECT_CLASS_LEN, MAX_ERROR_CODE_LEN, MAX_TERMINAL_PREDICATE_LEN,
    Obligation, ObligationState, OperationReceipt, PREPARED_EFFECT_SCHEMA,
    PROVIDER_FAILURE_RECEIPT_SCHEMA, PROVIDER_OBSERVATION_RECEIPT_SCHEMA, PreparedEffect,
    PreparedOperation, ProviderFailureLookup, ProviderFailureReceipt, ProviderObservationReceipt,
    ProviderReceiptLookup, ReconciliationOutcome,
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
    AlternateSystem, AudioFeaturesArtifact, BoundingBox, CropArtifact,
    DecisionArtifactKind, GraphNeighborhoodArtifact, H0Identity, H0IdentityParams,
    H0_CONTENT, H0_LEVEL_ID, H0_LEVEL_NAME, H0_SCHEMA, H0_SEMANTIC_OWNER,
    H1ContentSpec, H1SemanticSynopsis, H1SynopsisParams, H1_CONTENT, H1_LEVEL_ID,
    H1_LEVEL_NAME, H1_OWNER, H1_SCHEMA, H2DecisionArtifact, H2DecisionArtifactParams,
    H2PrivacyClass, H2_CONTENT, H2_LEVEL_ID, H2_LEVEL_NAME, H2_OWNER, H2_SCHEMA,
    H4LaboratoryExpansion, H4LaboratoryExpansionParams, H4_CONTENT, H4_LEVEL_ID,
    H4_LEVEL_NAME, H4_OWNER, H4_SCHEMA, HYDRATION_VIEW_ID, HandleAvailability,
    HydrationArtifact, HydrationError, HydrationLevel, HydrationPurpose, HydrationReceipt,
    HydrationReceiptSpec, HydrationRequest, HydrationRequestSpec, HydrationResponse,
    IntermediateArtifact, KeyframeArtifact, LaboratoryAccess, LaboratoryArtifact,
    LaboratoryQuarantine, MAX_H4_ALTERNATE_SYSTEMS, MAX_H4_IDENTIFIER_LEN,
    MAX_H4_INTERMEDIATES, MAX_H4_METADATA_LEN, MAX_H4_ORACLE_COMPARISONS, MAX_H4_PROOF_ROOTS,
    OracleComparison, RedactedRegion, RedactionTransform, ReplayBundleRef,
    SEMANTIC_HYDRATION_OWNER, SemanticHandle, SemanticHandleSpec, SynopsisClassification,
    SynopsisQuality, TrajectoryArtifact, TrajectoryWaypoint, is_registered_redaction_transform,
    is_valid_h0_screened_field,
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

#![forbid(unsafe_code)]
//! Dependency-free semantic foundation for Franken Surveillance System.
//!
//! This crate owns canonical identities, deterministic encoding, content
//! digests, time intervals, budgets, outcome classes, and stable errors. It
//! intentionally performs no device I/O and has no ambient authority.

pub mod canonical;
pub mod contract;
pub mod digest;
pub mod ids;
pub mod time;

pub use canonical::{CanonicalEncode, CanonicalEncoder};
pub use contract::{
    BudgetVector, Completeness, ContractError, EvidenceClass, HypothesisDisposition,
    KnowledgeState, Plane, ProvenanceClass, RecoveryClass, RuntimeOutcome,
};
pub use digest::{ContentDigest, DigestAlgorithm, Sha256};
pub use ids::{
    BatchId, CapsuleId, EventId, HandoffId, IdempotencyKey, MissionId, ObjectId, ObligationId,
    OperationId, PrincipalId, SensorId, SessionId, StreamId,
};
pub use time::{CaptureInterval, TimestampNs};

/// Semantic protocol identifier implemented by this foundation.
pub const PROTOCOL_VERSION: &str = "fss/1";

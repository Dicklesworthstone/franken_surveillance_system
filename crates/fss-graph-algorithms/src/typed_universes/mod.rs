#![forbid(unsafe_code)]
//! Typed FSS graph projection universes (`H_vis`, `G_effect`, `G_auth`, `G_world`)
//! built over [`crate::projection::ImmutableGraphProjection`] (`FSS-151`) with
//! deterministic versioning, `v1 -> v2` migration, removed-field tombstones,
//! incremental vs full-rebuild equivalence, and [`fss_core::GraphAlgorithmWitness`] emission.
//!
//! Covers:
//! - [`h_vis`] (`PROJ-VISIBILITY-001`, `fss-x4a.23.69.2`): 12-dimension visibility & coverage
//!   hypergraph `H_vis` + linked lossy camera-to-cell bipartite projection;
//! - [`g_effect`] (`PROJ-EFFECT-001`, `fss-x4a.23.69.7`): effect & obligation dependency graph
//!   `G_effect` with wait-cycle detection, critical path, cancellation potential, and honest
//!   completion;
//! - [`g_auth`] (`PROJ-AUTH-001`, `fss-x4a.23.69.9`): trust & authority graph `G_auth` with
//!   monotone narrowing, type-distinct authority edges, cache partitioning, and capability
//!   noninterference;
//! - [`g_world`] (`PROJ-WORLD-001`, `fss-x4a.23.69.12`): factorized `WorldEnvelope` graph
//!   `G_world` with protected high-loss world survival across compression/rerank/handoff,
//!   typed affordance classification, and plan binding/invalidation.
//!
//! All four projections are derived cognition (`grants_effect_authority() == false`): none of
//! them ever becomes canonical truth, upgrades absent coverage, or authorizes an effect.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use fss_core::{
    CanonicalEncoder, ContentDigest, GraphAlgorithmWitness, GraphAlgorithmWitnessParams,
    LedgerAnchor, Sha256Hasher,
};

use crate::projection::{GraphUniverse, ProjectionError};

pub mod g_auth;
pub mod g_effect;
pub mod g_world;
pub mod h_vis;

/// Legacy compatible wire version supported for deterministic old-to-new migration.
pub const LEGACY_UNIVERSE_WIRE_VERSION: u32 = 1;
/// Current canonical wire version for typed graph universe snapshots.
pub const CURRENT_UNIVERSE_WIRE_VERSION: u32 = 2;
/// Hard ceiling on serialized bytes for any single typed universe snapshot (4 MiB).
pub const MAX_UNIVERSE_WIRE_BYTES: usize = 4 * 1024 * 1024;
/// Maximum UTF-8 bytes in stable identifiers or labels inside typed universes.
pub const MAX_UNIVERSE_LABEL_BYTES: usize = 128;
/// Maximum entities/factors permitted in one typed universe instance.
pub const MAX_UNIVERSE_ITEMS: usize = 4_096;

/// Compatibility and migration outcome returned when loading a durable typed-universe wire fixture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UniverseMigrationReport {
    /// Wire version read from the persisted fixture.
    pub source_version: u32,
    /// Active canonical version after loading/migration (`CURRENT_UNIVERSE_WIRE_VERSION`).
    pub target_version: u32,
    /// Whether deterministic `v1 -> v2` migration ran.
    pub migrated: bool,
    /// Removed legacy fields explicitly preserved as tombstones without renumbering.
    pub tombstoned_fields: Vec<String>,
    /// Canonical digest of the loaded/migrated universe.
    pub universe_digest: ContentDigest,
}

/// Safe recovery guidance paired with every typed universe failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TypedUniverseGuidance {
    /// Repair malformed IDs, duplicate entries, invalid bounds, or semantic invariant violations.
    RepairInput,
    /// Re-authorize capability, privacy scope, universe, or authority generation.
    ReauthorizeScope,
    /// Re-acquire handles or recompile from one consistent anchor and generation.
    RebaseToSingleAnchorAndGeneration,
    /// Increase operation budget or narrow query scope before re-running.
    IncreaseBudget,
    /// Cooperative cancellation observed; retry from pinned anchor when ready.
    RetryFromPinnedAnchor,
    /// Quarantine unknown wire version or corrupt payload and rebuild from `EvidenceDeltaBatch`.
    QuarantineAndRebuildFromLedger,
}

/// Unified typed fail-closed error across `H_vis`, `G_effect`, `G_auth`, and `G_world`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TypedUniverseError {
    /// Underlying [`crate::projection::ImmutableGraphProjection`] error.
    Projection(ProjectionError),
    /// Invalid node/edge/factor specification, duplicate ID, or broken domain invariant.
    InvalidInput(String),
    /// Mixed ledger anchors or mismatched policy/authority generations refused fail-closed.
    MixedAnchorOrGeneration(String),
    /// Capability escalation, delegation cycle, expiry, or noninterference violation.
    AuthorityViolation(String),
    /// Attempted pruning/deletion of an unproven protected high-loss possible world.
    ProtectedWorldDeletionForbidden(String),
    /// Operation budget exhausted before completion.
    BudgetExhausted {
        /// Operations performed before stop.
        used: u64,
        /// Configured hard operation ceiling.
        limit: u64,
    },
    /// Cooperative cancellation observed before completion.
    Cancelled,
    /// Wire header magic mismatch.
    InvalidMagic,
    /// Unknown or future wire format version quarantined fail-closed.
    UnsupportedVersion {
        /// Observed wire version.
        version: u32,
    },
    /// Wire payload corrupt, truncated, or exceeds hard bounds.
    MalformedWire(String),
    /// Wire checksum failed verification.
    ChecksumMismatch,
    /// `GraphAlgorithmWitness` validation failed.
    Witness(String),
}

impl TypedUniverseError {
    /// Stable machine error identity aligned with `registries/ERRORS.md`.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Projection(err) => err.code(),
            Self::InvalidInput(_) => "ERR-GRAPH-UNIVERSE-INVALID-INPUT-001",
            Self::MixedAnchorOrGeneration(_) => "ERR-GRAPH-UNIVERSE-MIXED-GENERATION-001",
            Self::AuthorityViolation(_) => "ERR-GRAPH-UNIVERSE-AUTHORITY-001",
            Self::ProtectedWorldDeletionForbidden(_) => "ERR-GRAPH-WORLD-PROTECTED-DELETE-001",
            Self::BudgetExhausted { .. } => "ERR-GRAPH-UNIVERSE-BUDGET-001",
            Self::Cancelled => "ERR-GRAPH-UNIVERSE-CANCELLED-001",
            Self::InvalidMagic => "ERR-GRAPH-UNIVERSE-INVALID-MAGIC-001",
            Self::UnsupportedVersion { .. } => "ERR-GRAPH-UNIVERSE-UNSUPPORTED-VERSION-001",
            Self::MalformedWire(_) => "ERR-GRAPH-UNIVERSE-MALFORMED-WIRE-001",
            Self::ChecksumMismatch => "ERR-GRAPH-UNIVERSE-CHECKSUM-MISMATCH-001",
            Self::Witness(_) => "ERR-GRAPH-UNIVERSE-WITNESS-001",
        }
    }

    /// Safe recovery guidance for this refusal.
    #[must_use]
    pub const fn guidance(&self) -> TypedUniverseGuidance {
        match self {
            Self::Projection(ProjectionError::AuthorityRevoked(_))
            | Self::Projection(ProjectionError::StaleAuthorityGeneration { .. })
            | Self::AuthorityViolation(_) => TypedUniverseGuidance::ReauthorizeScope,
            Self::Projection(ProjectionError::StaleHandleGeneration { .. })
            | Self::Projection(ProjectionError::HandleOutOfRange { .. })
            | Self::MixedAnchorOrGeneration(_) => {
                TypedUniverseGuidance::RebaseToSingleAnchorAndGeneration
            }
            Self::Projection(ProjectionError::Cancelled) | Self::Cancelled => {
                TypedUniverseGuidance::RetryFromPinnedAnchor
            }
            Self::BudgetExhausted { .. } => TypedUniverseGuidance::IncreaseBudget,
            Self::InvalidMagic
            | Self::UnsupportedVersion { .. }
            | Self::MalformedWire(_)
            | Self::ChecksumMismatch
            | Self::Projection(ProjectionError::InvalidMagic)
            | Self::Projection(ProjectionError::UnsupportedVersion { .. })
            | Self::Projection(ProjectionError::MalformedWire(_))
            | Self::Projection(ProjectionError::ChecksumMismatch) => {
                TypedUniverseGuidance::QuarantineAndRebuildFromLedger
            }
            Self::InvalidInput(_)
            | Self::ProtectedWorldDeletionForbidden(_)
            | Self::Witness(_)
            | Self::Projection(_) => TypedUniverseGuidance::RepairInput,
        }
    }
}

impl fmt::Display for TypedUniverseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {self:?}", self.code())
    }
}

impl Error for TypedUniverseError {}

impl From<ProjectionError> for TypedUniverseError {
    fn from(value: ProjectionError) -> Self {
        Self::Projection(value)
    }
}

/// Deterministic checked work-budget tracker for typed universe analyses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OpBudget {
    limit: u64,
    used: u64,
}

impl OpBudget {
    pub(crate) fn new(limit: u64) -> Result<Self, TypedUniverseError> {
        if limit == 0 {
            return Err(TypedUniverseError::InvalidInput(
                "operation budget limit must be >= 1".to_owned(),
            ));
        }
        Ok(Self { limit, used: 0 })
    }

    pub(crate) fn charge(
        &mut self,
        units: u64,
        is_cancelled: &mut impl FnMut() -> bool,
    ) -> Result<(), TypedUniverseError> {
        if is_cancelled() {
            return Err(TypedUniverseError::Cancelled);
        }
        let next = self.used.saturating_add(units);
        if next > self.limit {
            return Err(TypedUniverseError::BudgetExhausted {
                used: next,
                limit: self.limit,
            });
        }
        self.used = next;
        Ok(())
    }

    pub(crate) const fn used(&self) -> u64 {
        self.used
    }
}

pub(crate) fn validate_clean_label(value: &str, field: &str) -> Result<(), TypedUniverseError> {
    if value.is_empty() || value.len() > MAX_UNIVERSE_LABEL_BYTES {
        return Err(TypedUniverseError::InvalidInput(format!(
            "{field} length {} outside 1..={MAX_UNIVERSE_LABEL_BYTES}",
            value.len()
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(TypedUniverseError::InvalidInput(format!(
            "{field} must not contain control characters"
        )));
    }
    Ok(())
}

pub(crate) fn seal_wire_envelope(
    magic: [u8; 8],
    version: u32,
    domain: &str,
    payload: &[u8],
) -> Result<Vec<u8>, TypedUniverseError> {
    let total = 16_usize
        .checked_add(payload.len())
        .and_then(|n| n.checked_add(32))
        .ok_or_else(|| TypedUniverseError::MalformedWire("wire length overflow".to_owned()))?;
    if total > MAX_UNIVERSE_WIRE_BYTES {
        return Err(TypedUniverseError::MalformedWire(format!(
            "wire length {total} exceeds maximum {MAX_UNIVERSE_WIRE_BYTES}"
        )));
    }
    let payload_len = u32::try_from(payload.len())
        .map_err(|_| TypedUniverseError::MalformedWire("payload length exceeds u32".to_owned()))?;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&magic);
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&payload_len.to_be_bytes());
    out.extend_from_slice(payload);
    let mut hasher = Sha256Hasher::new();
    hasher.update(domain.as_bytes());
    hasher.update(&out);
    let checksum = hasher
        .finalize()
        .map_err(|e| TypedUniverseError::MalformedWire(e.to_string()))?;
    out.extend_from_slice(&checksum);
    Ok(out)
}

pub(crate) fn open_wire_envelope<'a>(
    bytes: &'a [u8],
    magic: [u8; 8],
    domain: &str,
) -> Result<(u32, &'a [u8]), TypedUniverseError> {
    if bytes.len() > MAX_UNIVERSE_WIRE_BYTES {
        return Err(TypedUniverseError::MalformedWire(format!(
            "wire length {} exceeds maximum {MAX_UNIVERSE_WIRE_BYTES}",
            bytes.len()
        )));
    }
    if bytes.len() < 48 {
        return Err(TypedUniverseError::MalformedWire(
            "wire envelope truncated below minimum header+checksum length".to_owned(),
        ));
    }
    if bytes[..8] != magic {
        return Err(TypedUniverseError::InvalidMagic);
    }
    let version = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    if version != LEGACY_UNIVERSE_WIRE_VERSION && version != CURRENT_UNIVERSE_WIRE_VERSION {
        return Err(TypedUniverseError::UnsupportedVersion { version });
    }
    let declared_len = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as usize;
    let expected_total = 16_usize
        .checked_add(declared_len)
        .and_then(|n| n.checked_add(32))
        .ok_or_else(|| TypedUniverseError::MalformedWire("declared length overflow".to_owned()))?;
    if bytes.len() != expected_total {
        return Err(TypedUniverseError::MalformedWire(format!(
            "wire length {} disagrees with declared payload length {declared_len}",
            bytes.len()
        )));
    }
    let split = bytes.len() - 32;
    let (body, trailer) = bytes.split_at(split);
    let mut hasher = Sha256Hasher::new();
    hasher.update(domain.as_bytes());
    hasher.update(body);
    let computed = hasher
        .finalize()
        .map_err(|e| TypedUniverseError::MalformedWire(e.to_string()))?;
    if computed.as_slice() != trailer {
        return Err(TypedUniverseError::ChecksumMismatch);
    }
    Ok((version, &body[16..]))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_universe_witness(
    algorithm_id: &str,
    implementation_id: &str,
    universe: GraphUniverse,
    projection_id: &str,
    anchor: &LedgerAnchor,
    node_count: usize,
    edge_count: usize,
    input_digest: ContentDigest,
    policy_id: &str,
    operations: u64,
    peak_working_bytes: u64,
    decision_path_digest: ContentDigest,
    output_digest: ContentDigest,
) -> Result<GraphAlgorithmWitness, TypedUniverseError> {
    let mut dominant_operation_counts = BTreeMap::new();
    dominant_operation_counts.insert("universe_ops".to_owned(), operations);
    dominant_operation_counts.insert("nodes_visited".to_owned(), node_count as u64);
    dominant_operation_counts.insert("edges_scanned".to_owned(), edge_count as u64);

    let mut budget_consumed = BTreeMap::new();
    budget_consumed.insert("operations".to_owned(), operations);
    budget_consumed.insert("working_bytes".to_owned(), peak_working_bytes);

    let scoped_projection_id = format!("{}:{projection_id}", universe.as_str());
    GraphAlgorithmWitness::new(GraphAlgorithmWitnessParams {
        algorithm_id: algorithm_id.to_owned(),
        implementation_id: implementation_id.to_owned(),
        projection_id: scoped_projection_id,
        anchor: anchor.clone(),
        node_count: node_count as u64,
        edge_count: edge_count as u64,
        input_digest,
        policy_id: policy_id.to_owned(),
        dominant_operation_counts,
        peak_working_bytes,
        budget_consumed,
        exactness: GraphAlgorithmWitness::EXACT.to_owned(),
        error_bound: None,
        stop_reason: GraphAlgorithmWitness::STOP_COMPLETED.to_owned(),
        decision_path_digest,
        output_digest,
    })
    .map_err(|e| TypedUniverseError::Witness(e.to_string()))
}

pub(crate) fn hash_domain_tag(domain: &str, tag: u8, payload: &[u8]) -> ContentDigest {
    let mut enc = CanonicalEncoder::new();
    enc.text(domain);
    enc.u8(tag);
    enc.bytes(payload);
    ContentDigest::sha256(&enc.finish())
}

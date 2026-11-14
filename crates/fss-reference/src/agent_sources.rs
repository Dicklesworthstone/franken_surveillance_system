#![forbid(unsafe_code)]
//! Bounded historical source inventory through the existing AOP-005 metadata read.
//!
//! Rows reuse the operational status owner's sensor-capsule and continuity semantics. They
//! describe retained history, not an enrolled device registry, present sensor health or physical
//! coverage. The complete bounded inventory and protected snapshot are verified before exact
//! filters and pagination. No media is read and no writer/recovery owner is opened.
//!
//! One immutable read owner charges opening metadata, every capsule and final revalidation to
//! one nonrenewing allowance. Verification remains a bounded sequence of observations, not an
//! atomic filesystem snapshot or a lease preventing concurrent changes.

mod read;
mod result;

use std::path::Path;

use fss_core::{
    BudgetQuantitiesSpec, BudgetVector, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContinuationError, PrincipalId, SensorId, StreamId,
};

use crate::ReplayCx;
use crate::agent_follow::AnchorToken;
use crate::agent_orient::OrientLimits;
use crate::deployment_status::{SourceInventory, StreamInventory};
use crate::ingest::FileIngestError;
use crate::retained_source::ImmutableRetainedReadLimits;

pub use result::{DeploymentSourcesQuery, row_json};

/// Maximum returned sensor/stream pairs per page.
pub const MAX_SOURCES_QUERY_ENTRIES: u32 = 32;
/// Default returned sensor/stream pairs per page.
pub const DEFAULT_SOURCES_QUERY_ENTRIES: u32 = 16;

/// Conjunctive exact native identity predicates; no labels or URL aliases are inferred.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SourcesQueryFilter {
    /// Exact native sensor identity, or all retained sensors.
    pub sensor_id: Option<SensorId>,
    /// Exact stream generation identity, or all retained streams.
    pub stream_id: Option<StreamId>,
}

impl SourcesQueryFilter {
    /// Compare the existing identities without normalization or substring matching.
    pub fn matches(&self, row: &SourcesQueryRow) -> bool {
        self.sensor_id
            .as_ref()
            .is_none_or(|id| id.as_str() == row.stream.sensor_id)
            && self
                .stream_id
                .as_ref()
                .is_none_or(|id| id.as_str() == row.stream.stream_id)
    }

    /// Literal interpretation of these structured predicates.
    pub fn description(&self) -> String {
        format!(
            "Retained source inventory; exact sensor={}; exact stream={}; capsule metadata and historical continuity only; current health, media availability and physical coverage remain unknown",
            self.sensor_id.as_ref().map_or("any", SensorId::as_str),
            self.stream_id.as_ref().map_or("any", StreamId::as_str),
        )
    }
}

impl CanonicalEncode for SourcesQueryFilter {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.bool(self.sensor_id.is_some());
        if let Some(id) = &self.sensor_id {
            id.encode_canonical(encoder);
        }
        encoder.bool(self.stream_id.is_some());
        if let Some(id) = &self.stream_id {
            id.encode_canonical(encoder);
        }
    }
}

/// One exact read request. The principal is an audit label, not authentication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourcesQueryRequest {
    /// Predicates applied after the complete bounded inventory has been verified.
    pub filter: SourcesQueryFilter,
    /// Must match the principal of the caller's explicit metadata I/O authority.
    pub principal: PrincipalId,
    /// Returned stream rows per page, in 1..=32.
    pub max_entries: u32,
    /// Exact current authority and effect-prefix precondition, when supplied.
    pub expected_anchor: Option<AnchorToken>,
    /// Native cursor from the same principal, predicates, page size, limits and index.
    pub continuation: Option<String>,
}

impl SourcesQueryRequest {
    /// Reject scalar and cursor errors before opening any deployment path.
    pub fn validate(&self) -> Result<(), SourcesQueryError> {
        if !(1..=MAX_SOURCES_QUERY_ENTRIES).contains(&self.max_entries) {
            return Err(SourcesQueryError::InvalidRequest(
                "source page size outside bounds",
            ));
        }
        if self.continuation.as_ref().is_some_and(|token| {
            token.len() > 256
                || !token.starts_with("continuation:")
                || !token.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b':' | b'+' | b'.' | b'_' | b'-')
                })
        }) {
            return Err(SourcesQueryError::InvalidRequest(
                "invalid source continuation spelling",
            ));
        }
        Ok(())
    }
}

/// Complete-index bounds and the aggregate I/O allowance shared through final verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourcesQueryLimits {
    /// One allowance for opening metadata, capsule reads and all final rereads.
    pub read: ImmutableRetainedReadLimits,
    /// Complete ledger object and committed batch bound, before filtering.
    pub max_objects: usize,
    /// Complete retained capsule metadata bound, before filtering.
    pub max_capsules: usize,
    /// Complete sensor/stream pair bound, before filtering.
    pub max_streams: usize,
    /// Aggregate capsule metadata bytes in the original inventory pass.
    /// Final rereads remain charged to the independent shared read allowance.
    pub max_metadata_bytes: usize,
}

impl Default for SourcesQueryLimits {
    fn default() -> Self {
        Self {
            read: ImmutableRetainedReadLimits {
                snapshot: OrientLimits::default(),
                max_read_bytes: 256 * 1024 * 1024,
                max_read_objects: 65_536,
            },
            max_objects: 65_536,
            max_capsules: 16_384,
            max_streams: 1024,
            max_metadata_bytes: 64 * 1024 * 1024,
        }
    }
}

impl SourcesQueryLimits {
    /// Reject zero and widened bounds before filesystem access.
    pub fn validate(&self) -> Result<(), SourcesQueryError> {
        let ceiling = Self::default();
        for (value, maximum) in [
            (self.max_objects, ceiling.max_objects),
            (self.max_capsules, ceiling.max_capsules),
            (self.max_streams, ceiling.max_streams),
            (self.max_metadata_bytes, ceiling.max_metadata_bytes),
            (self.read.max_read_bytes, ceiling.read.max_read_bytes),
            (self.read.max_read_objects, ceiling.read.max_read_objects),
            (
                self.read.snapshot.max_layout_bytes,
                ceiling.read.snapshot.max_layout_bytes,
            ),
            (
                self.read.snapshot.max_journal_bytes,
                ceiling.read.snapshot.max_journal_bytes,
            ),
            (
                self.read.snapshot.max_object_bytes,
                ceiling.read.snapshot.max_object_bytes,
            ),
            (
                self.read.snapshot.max_events,
                ceiling.read.snapshot.max_events,
            ),
            (
                self.read.snapshot.max_revisions_per_event,
                ceiling.read.snapshot.max_revisions_per_event,
            ),
        ] {
            if value == 0 || value > maximum {
                return Err(SourcesQueryError::InvalidRequest(
                    "source read limits outside bounds",
                ));
            }
        }
        Ok(())
    }

    /// Admitted bytes and read attempts; not a syscall, CPU or observed-latency claim.
    pub fn allowance(&self) -> Result<BudgetVector, SourcesQueryError> {
        self.validate()?;
        Ok(BudgetVector::from_quantities(BudgetQuantitiesSpec {
            latency_ms: 60_000,
            bytes: self.read.max_read_bytes as u64,
            storage_operations: self.read.max_read_objects as u64,
            ..BudgetQuantitiesSpec::ZERO
        }))
    }
}

/// A sensor/stream row using the status owner's single historical continuity rule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourcesQueryRow {
    /// Exact native inventory; byte totals are capsule declarations, not payload verification.
    pub stream: StreamInventory,
    /// First and last retained capsule metadata digests in canonical digest order, deduplicated.
    /// These are representative real proof handles, not every capsule or any source-media bytes.
    /// The selection witness separately binds the complete capsule metadata index.
    pub capsule_metadata: Vec<ContentDigest>,
}

impl SourcesQueryRow {
    /// Canonical identity of every returned field.
    pub fn row_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.agent_sources.row.v1");
        let stream = &self.stream;
        encoder.text(&stream.sensor_id);
        encoder.text(&stream.stream_id);
        encoder.u64(stream.capsules as u64);
        encoder.u64(stream.recorded_gaps as u64);
        encoder.u64(stream.declared_source_bytes);
        encoder.u64(stream.clock_bases.len() as u64);
        for basis in &stream.clock_bases {
            encoder.text(basis);
        }
        encoder.i128(stream.capture_earliest.0);
        encoder.i128(stream.capture_latest.0);
        encoder.u64(stream.witnessed_continuous as u64);
        encoder.u64(stream.witnessed_degraded as u64);
        encoder.text(stream.continuity.as_str());
        encoder.text(stream.continuity_reason.as_str());
        encoder.u64(self.capsule_metadata.len() as u64);
        for digest in &self.capsule_metadata {
            encoder.digest(*digest);
        }
        ContentDigest::sha256(&encoder.finish())
    }
}

/// Whole-deployment inventory accounting, unchanged by predicates or pagination.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SourcesQuerySummary {
    /// Distinct retained sensors represented by eligible capsule metadata.
    pub sensors: usize,
    /// Distinct retained sensor/stream pairs.
    pub streams: usize,
    /// All historical capsule object identities, including deleted/incomplete ones.
    pub capsule_objects: usize,
    /// Eligible retained capsule metadata objects.
    pub retained_capsules: usize,
    /// Capsule objects excluded by committed deletion authority.
    pub deleted_capsules: usize,
    /// Capsule objects excluded because their native import did not complete.
    pub incomplete_import_capsules: usize,
    /// Current completed native import declarations.
    pub completed_imports: usize,
    /// Native import declarations excluded by committed deletion authority.
    pub deleted_imports: usize,
    /// All incomplete import object identities in native canonical order.
    pub incomplete_imports: Vec<String>,
}

impl From<&SourceInventory> for SourcesQuerySummary {
    fn from(inventory: &SourceInventory) -> Self {
        Self {
            sensors: inventory.sensors.len(),
            streams: inventory.streams.len(),
            capsule_objects: inventory.capsule_objects,
            retained_capsules: inventory.retained_capsules,
            deleted_capsules: inventory.deleted_capsules,
            incomplete_import_capsules: inventory.incomplete_import_capsules,
            completed_imports: inventory.completed_imports,
            deleted_imports: inventory.deleted_imports,
            incomplete_imports: inventory.incomplete_imports.clone(),
        }
    }
}

impl CanonicalEncode for SourcesQuerySummary {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        for value in [
            self.sensors,
            self.streams,
            self.capsule_objects,
            self.retained_capsules,
            self.deleted_capsules,
            self.incomplete_import_capsules,
            self.completed_imports,
            self.deleted_imports,
            self.incomplete_imports.len(),
        ] {
            encoder.u64(value as u64);
        }
        for id in &self.incomplete_imports {
            encoder.text(id);
        }
    }
}

/// Complete refusal; unavailable or inconsistent metadata never becomes an empty success.
#[derive(Debug)]
pub enum SourcesQueryError {
    /// Invalid page, cursor or read limits.
    InvalidRequest(&'static str),
    /// Root or principal differs from explicit metadata authority.
    Unauthorized,
    /// Immutable metadata custody or final verification refused.
    Source(FileIngestError),
    /// Native capsule identity or current inventory is inconsistent.
    InvalidRecord,
    /// Complete inventory exceeds an admitted bound.
    OverBudget,
    /// The current authority/effect prefix differs from the requested precondition.
    AnchorChanged,
    /// Caller cancellation or deadline refusal was observed.
    Cancelled,
    /// Cursor does not belong to this exact query scope and verified inventory.
    Continuation(ContinuationError),
    /// The registered AOP-005 read plan could not be compiled.
    Contract,
}

impl SourcesQueryError {
    /// Stable non-disclosing diagnostic.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest(_) => "sources.invalid_request",
            Self::Unauthorized => "sources.unauthorized",
            Self::Source(_) => "sources.metadata_unavailable",
            Self::InvalidRecord => "sources.invalid_record",
            Self::OverBudget => "sources.over_budget",
            Self::AnchorChanged => "sources.anchor_changed",
            Self::Cancelled => "sources.cancelled",
            Self::Continuation(_) => "sources.continuation",
            Self::Contract => "sources.contract",
        }
    }
}

impl std::fmt::Display for SourcesQueryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}
impl std::error::Error for SourcesQueryError {}

/// Read existing retained source history under exact root/principal-bound metadata authority.
///
/// No ReadMedia capability is required or inferred. All retained capsule metadata and the
/// complete protected snapshot are verified before filters; failed verification refuses the
/// entire page. Canonical transports admit AgentQuery, the exact limits and a live deadline
/// before constructing the supplied replay context. The principal alone is an audit label.
pub fn query_sources(
    root: &Path,
    request: &SourcesQueryRequest,
    limits: SourcesQueryLimits,
    cx: &ReplayCx,
    cancelled: &(impl Fn() -> bool + Sync),
) -> Result<DeploymentSourcesQuery, SourcesQueryError> {
    read::query(root, request, limits, cx, cancelled)
}

fn hex(digest: ContentDigest) -> String {
    digest.bytes().iter().map(|byte| format!("{byte:02x}")).collect()
}

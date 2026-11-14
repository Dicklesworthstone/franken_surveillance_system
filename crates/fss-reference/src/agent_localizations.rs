#![forbid(unsafe_code)]
//! Bounded discovery of retained inactive localization packages through canonical AOP-005.
//!
//! Native publication/source/privacy metadata is verified before filtering or pagination.
//! Archive pins and receipt handles do not establish payload availability, replay success,
//! adoption, current calibration or physical coverage. No media or writer owner is opened.

mod read;
mod result;

use std::path::Path;

use fss_core::{
    BudgetQuantitiesSpec, BudgetVector, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContinuationError, DigestAlgorithm, PrincipalId, SensorId, StreamId,
};

use crate::ReplayCx;
use crate::agent_follow::AnchorToken;
use crate::agent_orient::OrientLimits;
use crate::ingest::FileIngestError;
use crate::ingest::twin_localization::retained::RecordedLocalizationMetadata;
use crate::retained_source::ImmutableRetainedReadLimits;

pub use result::{DeploymentLocalizationsQuery, row_json};

/// Maximum returned package rows per page.
pub const MAX_LOCALIZATIONS_QUERY_ENTRIES: u32 = 32;
/// Default returned package rows per page.
pub const DEFAULT_LOCALIZATIONS_QUERY_ENTRIES: u32 = 16;
/// Complete current package index ceiling, independent of returned page size.
pub const MAX_LOCALIZATIONS_QUERY_PACKAGES: usize = 1024;

/// Conjunctive exact native source and original archive identity predicates.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LocalizationsQueryFilter {
    /// Exact capsule sensor identity, or all retained localization sources.
    pub sensor_id: Option<SensorId>,
    /// Exact capsule stream generation identity, or all retained localization streams.
    pub stream_id: Option<StreamId>,
    /// Exact completed import identity, or all retained imports.
    pub import_identity: Option<ContentDigest>,
    /// Exact original property archive content pin, or all retained property archives.
    pub twin_digest: Option<ContentDigest>,
}

impl LocalizationsQueryFilter {
    /// Match native identities without labels, normalization or substring matching.
    pub fn matches(&self, row: &LocalizationsQueryRow) -> bool {
        let metadata = &row.metadata;
        self.sensor_id
            .as_ref()
            .is_none_or(|id| id == &metadata.sensor_id)
            && self
                .stream_id
                .as_ref()
                .is_none_or(|id| id == &metadata.stream_id)
            && self
                .import_identity
                .is_none_or(|id| id == metadata.import_identity)
            && self.twin_digest.is_none_or(|id| id == metadata.twin_digest)
    }

    /// Literal interpretation of the exact predicates and inactive receipt scope.
    pub fn description(&self) -> String {
        format!(
            "Retained inactive localization metadata; exact sensor={}; exact stream={}; exact import={}; exact twin archive={}; native receipt/source/privacy bindings only; replay, payload availability, adoption, current calibration and physical coverage are not established",
            self.sensor_id.as_ref().map_or("any", SensorId::as_str),
            self.stream_id.as_ref().map_or("any", StreamId::as_str),
            self.import_identity
                .map_or_else(|| "any".to_owned(), |id| id.to_text()),
            self.twin_digest
                .map_or_else(|| "any".to_owned(), |id| id.to_text()),
        )
    }
}

impl CanonicalEncode for LocalizationsQueryFilter {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.bool(self.sensor_id.is_some());
        if let Some(id) = &self.sensor_id {
            id.encode_canonical(encoder);
        }
        encoder.bool(self.stream_id.is_some());
        if let Some(id) = &self.stream_id {
            id.encode_canonical(encoder);
        }
        for digest in [self.import_identity, self.twin_digest] {
            encoder.bool(digest.is_some());
            if let Some(digest) = digest {
                encoder.digest(digest);
            }
        }
    }
}

/// One exact metadata read request. A principal is an audit label, not authentication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalizationsQueryRequest {
    /// Predicates applied after the complete bounded native index has been verified.
    pub filter: LocalizationsQueryFilter,
    /// Must match the caller's explicit metadata I/O authority.
    pub principal: PrincipalId,
    /// Returned packages per page, in 1..=32.
    pub max_entries: u32,
    /// Exact current authority and effect-prefix precondition, when supplied.
    pub expected_anchor: Option<AnchorToken>,
    /// Native cursor for the same principal, predicates, limits, page and complete index.
    pub continuation: Option<String>,
}

impl LocalizationsQueryRequest {
    /// Reject malformed scalar identities and cursor spelling before filesystem access.
    pub fn validate(&self) -> Result<(), LocalizationsQueryError> {
        if !(1..=MAX_LOCALIZATIONS_QUERY_ENTRIES).contains(&self.max_entries) {
            return Err(LocalizationsQueryError::InvalidRequest(
                "localization page size outside bounds",
            ));
        }
        if [self.filter.import_identity, self.filter.twin_digest]
            .into_iter()
            .flatten()
            .any(|digest| {
                digest.algorithm() != DigestAlgorithm::Sha256 || digest.bytes() == [0; 32]
            })
        {
            return Err(LocalizationsQueryError::InvalidRequest(
                "invalid localization digest predicate",
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
            return Err(LocalizationsQueryError::InvalidRequest(
                "invalid localization continuation spelling",
            ));
        }
        Ok(())
    }
}

/// Complete-index bounds and one aggregate allowance shared through final verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalizationsQueryLimits {
    /// Opening metadata, recipe/receipt/source/root reads and all final rereads share this.
    pub read: ImmutableRetainedReadLimits,
    /// Complete ledger object and batch bound, before filtering.
    pub max_objects: usize,
    /// Complete current native localization package bound, before filtering.
    pub max_localizations: usize,
}

impl Default for LocalizationsQueryLimits {
    fn default() -> Self {
        Self {
            read: ImmutableRetainedReadLimits {
                snapshot: OrientLimits::default(),
                max_read_bytes: 256 * 1024 * 1024,
                max_read_objects: 65_536,
            },
            max_objects: 65_536,
            max_localizations: MAX_LOCALIZATIONS_QUERY_PACKAGES,
        }
    }
}

impl LocalizationsQueryLimits {
    /// Reject zero or widened bounds before opening any deployment path.
    pub fn validate(&self) -> Result<(), LocalizationsQueryError> {
        let ceiling = Self::default();
        for (value, maximum) in [
            (self.max_objects, ceiling.max_objects),
            (self.max_localizations, ceiling.max_localizations),
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
                return Err(LocalizationsQueryError::InvalidRequest(
                    "localization read limits outside bounds",
                ));
            }
        }
        Ok(())
    }

    /// Admitted payload bytes and read attempts, not a syscall/CPU/latency measurement.
    pub fn allowance(&self) -> Result<BudgetVector, LocalizationsQueryError> {
        self.validate()?;
        Ok(BudgetVector::from_quantities(BudgetQuantitiesSpec {
            latency_ms: 60_000,
            bytes: self.read.max_read_bytes as u64,
            storage_operations: self.read.max_read_objects as u64,
            ..BudgetQuantitiesSpec::ZERO
        }))
    }
}

/// One native inactive localization package's metadata; no candidate pose is interpreted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalizationsQueryRow {
    /// Exact original source/archive pins and currently admitted native custody/privacy.
    pub metadata: RecordedLocalizationMetadata,
}

impl LocalizationsQueryRow {
    /// Canonical identity of every returned typed metadata field.
    pub fn row_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.agent_localizations.row.v1");
        let metadata = &self.metadata;
        for digest in [
            metadata.package_identity,
            metadata.receipt_digest,
            metadata.publication_root,
            metadata.import_identity,
            metadata.import_root,
            metadata.source_manifest,
            metadata.capsule_digest,
            metadata.mask_binding,
            metadata.twin_digest,
            metadata.scene_digest,
            metadata.atlas_package,
            metadata.atlas_provenance,
            metadata.descriptor_generation,
        ] {
            encoder.digest(digest);
        }
        encoder.text(metadata.publication_slot.as_str());
        metadata.source_anchor.encode_canonical(&mut encoder);
        metadata.sensor_id.encode_canonical(&mut encoder);
        metadata.stream_id.encode_canonical(&mut encoder);
        metadata.capture.encode_canonical(&mut encoder);
        encoder.u64(metadata.segment_index);
        encoder.u64(metadata.range_start);
        encoder.u64(metadata.range_count);
        encoder.text(metadata.codec);
        encoder.bool(metadata.mask_policy.is_some());
        if let Some(policy) = metadata.mask_policy {
            encoder.digest(policy);
        }
        encoder.u64(metadata.committed_sequence);
        ContentDigest::sha256(&encoder.finish())
    }
}

/// Complete refusal; corrupt, stale or unavailable metadata never becomes an empty success.
#[derive(Debug)]
pub enum LocalizationsQueryError {
    /// Invalid page, digest selector, cursor spelling or read limits.
    InvalidRequest(&'static str),
    /// Root or principal differs from explicit metadata authority.
    Unauthorized,
    /// Immutable metadata custody or final revalidation refused.
    Source(FileIngestError),
    /// Native recipe/receipt/source/publication bindings are inconsistent or stale.
    InvalidRecord,
    /// Complete native index exceeds an admitted bound.
    OverBudget,
    /// Current authority/effect prefix differs from the requested precondition.
    AnchorChanged,
    /// Caller cancellation or deadline refusal was observed.
    Cancelled,
    /// Cursor belongs to another exact request, principal, index or protected snapshot.
    Continuation(ContinuationError),
    /// Registered AOP-005 metadata plan could not be compiled.
    Contract,
}

impl LocalizationsQueryError {
    /// Stable non-disclosing diagnostic.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest(_) => "localizations.invalid_request",
            Self::Unauthorized => "localizations.unauthorized",
            Self::Source(_) => "localizations.metadata_unavailable",
            Self::InvalidRecord => "localizations.invalid_record",
            Self::OverBudget => "localizations.over_budget",
            Self::AnchorChanged => "localizations.anchor_changed",
            Self::Cancelled => "localizations.cancelled",
            Self::Continuation(_) => "localizations.continuation",
            Self::Contract => "localizations.contract",
        }
    }
}

impl std::fmt::Display for LocalizationsQueryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}
impl std::error::Error for LocalizationsQueryError {}

/// Discover retained inactive localization packages using explicit immutable metadata authority.
///
/// The whole native current index and protected metadata are verified before predicates and
/// pagination. Canonical transports admit AgentQuery and the exact limits with a live deadline.
/// This read grants no ReadMedia, camera activation, calibration or effect authority.
pub fn query_localizations(
    root: &Path,
    request: &LocalizationsQueryRequest,
    limits: LocalizationsQueryLimits,
    cx: &ReplayCx,
    cancelled: &(impl Fn() -> bool + Sync),
) -> Result<DeploymentLocalizationsQuery, LocalizationsQueryError> {
    read::query(root, request, limits, cx, cancelled)
}

fn hex(digest: ContentDigest) -> String {
    digest
        .bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

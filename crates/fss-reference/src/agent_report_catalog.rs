#![forbid(unsafe_code)]
//! Bounded discovery of retained detection, zone-report and scalar model-run metadata.
//!
//! This metadata-only read verifies current cognition declarations, their exact publication
//! roots and retained report bytes. It does not reconstruct source media, rerun inference,
//! establish current source availability, or grant the separate authority needed by tracks or
//! QSR queries. Zone report semantics and QSR eligibility remain for their native readers.
//! Verification is a bounded sequence of observations with live admission, not an atomic
//! filesystem snapshot or a read lease preventing concurrent mutation.

mod read;
mod result;

use std::path::Path;

use fss_core::{
    BudgetQuantitiesSpec, BudgetVector, CanonicalEncode, CanonicalEncoder, CaptureInterval,
    ContentDigest, ContinuationError, PrincipalId,
};

use crate::ReplayCx;
use crate::agent_follow::AnchorToken;
use crate::agent_orient::OrientLimits;
use crate::ingest::FileIngestError;
use crate::ingest::inference::RecordedInferenceMetadata;
use crate::ingest::package_event::PACKAGE_DETECTION_FAMILY;
use crate::ingest::package_zones::PACKAGE_ZONE_FAMILY;
use crate::reference_deployment::FAMILY_MODEL_INVOCATION_RECEIPT;
use crate::retained_source::ImmutableRetainedReadLimits;

pub use result::DeploymentReportCatalogQuery;

/// Maximum complete report index, before any filter or pagination is applied.
pub const MAX_REPORT_CATALOG_REPORTS: usize = 4096;
/// Maximum returned report handles per page.
pub const MAX_REPORT_CATALOG_ENTRIES: u32 = 32;
/// Default returned report handles per page.
pub const DEFAULT_REPORT_CATALOG_ENTRIES: u32 = 16;

/// Existing cognition families supported by this metadata discovery read.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ReportCatalogFamily {
    /// A retained canonical package detection record and its original report identity.
    PackageDetectionRecord,
    /// A retained package-zone report, with its original v1 or v2 schema preserved.
    PackageZoneReport,
    /// A native RecordedInference (`object:model-run`) receipt. Other model receipt producers
    /// are outside this view; model and tensor payloads are not inspected.
    ModelInvocationReceipt,
}

impl ReportCatalogFamily {
    /// Existing native family spelling; no alias or inferred family is accepted.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PackageDetectionRecord => PACKAGE_DETECTION_FAMILY,
            Self::PackageZoneReport => PACKAGE_ZONE_FAMILY,
            Self::ModelInvocationReceipt => FAMILY_MODEL_INVOCATION_RECEIPT,
        }
    }

    /// Parse an exact native family without normalization.
    pub fn parse(value: &str) -> Result<Self, ReportCatalogError> {
        match value {
            PACKAGE_DETECTION_FAMILY => Ok(Self::PackageDetectionRecord),
            PACKAGE_ZONE_FAMILY => Ok(Self::PackageZoneReport),
            FAMILY_MODEL_INVOCATION_RECEIPT => Ok(Self::ModelInvocationReceipt),
            _ => Err(ReportCatalogError::InvalidRequest("unknown report family")),
        }
    }
}

/// Conjunctive predicates over the family and interval declared by retained cognition.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReportCatalogFilter {
    /// Exact existing cognition family, or all supported families.
    pub family: Option<ReportCatalogFamily>,
    /// Inclusive lower endpoint in the declared source-native time domain.
    pub from_ns: Option<i128>,
    /// Inclusive upper endpoint; no UTC conversion or physical coverage is inferred.
    pub through_ns: Option<i128>,
}

impl ReportCatalogFilter {
    /// Refuse an inverted interval before filesystem access.
    pub fn validate(&self) -> Result<(), ReportCatalogError> {
        if self
            .from_ns
            .zip(self.through_ns)
            .is_some_and(|(a, b)| a > b)
        {
            return Err(ReportCatalogError::InvalidRequest(
                "inverted report interval",
            ));
        }
        Ok(())
    }

    /// Closed interval overlap of declarations, never precise event timing or coverage.
    pub fn matches(&self, row: &ReportCatalogRow) -> bool {
        self.family.is_none_or(|family| family == row.family)
            && self
                .from_ns
                .is_none_or(|time| row.validity.latest.0 >= time)
            && self
                .through_ns
                .is_none_or(|time| row.validity.earliest.0 <= time)
    }

    /// Literal, bounded interpretation of these structured predicates.
    pub fn description(&self) -> String {
        format!(
            "Retained report metadata; family={}; model receipts are limited to native object:model-run declarations; closed declared source-native overlap [{},{}]; source availability, reconstruction and QSR eligibility remain unknown",
            self.family.map_or("any", ReportCatalogFamily::as_str),
            self.from_ns
                .map_or_else(|| "unbounded".to_owned(), |time| time.to_string()),
            self.through_ns
                .map_or_else(|| "unbounded".to_owned(), |time| time.to_string()),
        )
    }
}

impl CanonicalEncode for ReportCatalogFilter {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.bool(self.family.is_some());
        if let Some(family) = self.family {
            encoder.text(family.as_str());
        }
        for value in [self.from_ns, self.through_ns] {
            encoder.bool(value.is_some());
            if let Some(value) = value {
                encoder.i128(value);
            }
        }
    }
}

/// One exact metadata query. The principal is an audit label, not authentication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportCatalogRequest {
    /// Predicates applied only after the complete bounded metadata index is verified.
    pub filter: ReportCatalogFilter,
    /// Audit principal, which must match the caller's explicit metadata I/O authority.
    pub principal: PrincipalId,
    /// Page size in 1..=32.
    pub max_entries: u32,
    /// Optional exact current authority and effect-prefix precondition.
    pub expected_anchor: Option<AnchorToken>,
    /// Native exact continuation from an earlier page of the same query.
    pub continuation: Option<String>,
}

impl ReportCatalogRequest {
    /// Validate scalar inputs and exact cursor spelling before any I/O.
    pub fn validate(&self) -> Result<(), ReportCatalogError> {
        self.filter.validate()?;
        if !(1..=MAX_REPORT_CATALOG_ENTRIES).contains(&self.max_entries) {
            return Err(ReportCatalogError::InvalidRequest(
                "report page size outside bounds",
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
            return Err(ReportCatalogError::InvalidRequest(
                "invalid report continuation spelling",
            ));
        }
        Ok(())
    }
}

/// Complete-index and aggregate I/O ceilings, shared through final verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReportCatalogLimits {
    /// Native metadata reads, report reads and final rereads use this one allowance.
    pub read: ImmutableRetainedReadLimits,
    /// Complete supported-family report index, before filtering.
    pub max_reports: usize,
    /// Maximum ledger objects and committed batches considered.
    pub max_objects: usize,
}

impl Default for ReportCatalogLimits {
    fn default() -> Self {
        Self {
            read: ImmutableRetainedReadLimits {
                snapshot: OrientLimits::default(),
                max_read_bytes: 256 * 1024 * 1024,
                max_read_objects: 65_536,
            },
            max_reports: MAX_REPORT_CATALOG_REPORTS,
            max_objects: 65_536,
        }
    }
}

impl ReportCatalogLimits {
    /// Refuse zero or widened limits before opening an existing deployment.
    pub fn validate(&self) -> Result<(), ReportCatalogError> {
        let ceiling = Self::default();
        for (value, maximum) in [
            (self.max_reports, ceiling.max_reports),
            (self.max_objects, ceiling.max_objects),
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
                return Err(ReportCatalogError::InvalidRequest(
                    "report read limits outside bounds",
                ));
            }
        }
        Ok(())
    }

    /// Admitted payload bytes and read attempts; not a syscall, CPU or observed-latency claim.
    pub fn allowance(&self) -> Result<BudgetVector, ReportCatalogError> {
        self.validate()?;
        Ok(BudgetVector::from_quantities(BudgetQuantitiesSpec {
            latency_ms: 60_000,
            bytes: self.read.max_read_bytes as u64,
            storage_operations: self.read.max_read_objects as u64,
            ..BudgetQuantitiesSpec::ZERO
        }))
    }
}

/// A verified retained metadata handle, without source reconstruction or media authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportCatalogRow {
    /// Existing committed cognition family.
    pub family: ReportCatalogFamily,
    /// Retained report object handle. For a detector this is the original report object;
    /// for a model run it is the receipt object, with the semantic native lookup key separately
    /// preserved in `model_run.run_identity`.
    pub report_digest: ContentDigest,
    /// Exact payload digest from the committed cognition delta.
    pub record_digest: ContentDigest,
    /// Verified root of the native publication manifest.
    pub provenance_root: ContentDigest,
    /// Exact existing publication slot spelling.
    pub publication_slot: String,
    /// Existing native metadata domain, preserving zone versions and model receipt identity.
    pub schema: String,
    /// Closed validity interval declared in the retained cognition delta.
    pub validity: CaptureInterval,
    /// Commit sequence of the exact retention batch.
    pub committed_sequence: u64,
    /// Exact scalar-run selectors and retained runtime provenance. Absent for package reports.
    /// These verified metadata declarations do not establish tensor or source availability.
    pub model_run: Option<RecordedInferenceMetadata>,
}

impl ReportCatalogRow {
    /// Canonical selection identity of every returned field.
    pub fn row_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.agent_report_catalog.row.v1");
        encoder.text(self.family.as_str());
        encoder.digest(self.report_digest);
        encoder.digest(self.record_digest);
        encoder.digest(self.provenance_root);
        encoder.text(&self.publication_slot);
        encoder.text(&self.schema);
        self.validity.encode_canonical(&mut encoder);
        encoder.u64(self.committed_sequence);
        if let Some(run) = &self.model_run {
            encoder.digest(run.run_identity);
            encoder.digest(run.executor_profile_digest);
            encoder.digest(run.model_digest);
            encoder.digest(run.frame_root);
            encoder.digest(run.import_identity);
            encoder.u64(run.segment_index);
            encoder.u8(match run.interpretation {
                crate::ingest::recorded_decode::ComponentInterpretation::Grayscale => 0,
                crate::ingest::recorded_decode::ComponentInterpretation::YCbCr => 1,
            });
        }
        ContentDigest::sha256(&encoder.finish())
    }
}

/// Complete refusal. Unavailable metadata never becomes a successful empty catalog.
#[derive(Debug)]
pub enum ReportCatalogError {
    /// A malformed request or widened read limit.
    InvalidRequest(&'static str),
    /// Explicit metadata authority does not match the selected root or principal.
    Unauthorized,
    /// Native immutable history, metadata custody or final verification refused.
    Source(FileIngestError),
    /// Current declarations, canonical record, manifest and publication do not agree.
    InvalidRecord,
    /// Complete index exceeds the caller's admitted ceiling.
    OverBudget,
    /// Current authority/effect prefix differs from the caller's exact precondition.
    AnchorChanged,
    /// Caller cancellation or deadline refusal was observed.
    Cancelled,
    /// Native continuation does not belong to this exact result set or request.
    Continuation(ContinuationError),
    /// The registered AOP-005 read plan could not be constructed.
    Contract,
}

impl ReportCatalogError {
    /// Stable diagnostic without private paths or untrusted payload text.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest(_) => "report_catalog.invalid_request",
            Self::Unauthorized => "report_catalog.unauthorized",
            Self::Source(_) => "report_catalog.metadata_unavailable",
            Self::InvalidRecord => "report_catalog.invalid_record",
            Self::OverBudget => "report_catalog.over_budget",
            Self::AnchorChanged => "report_catalog.anchor_changed",
            Self::Cancelled => "report_catalog.cancelled",
            Self::Continuation(_) => "report_catalog.continuation",
            Self::Contract => "report_catalog.contract",
        }
    }
}

impl std::fmt::Display for ReportCatalogError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}
impl std::error::Error for ReportCatalogError {}

/// Discover current retained detector, zone and scalar-run metadata without source-media reads.
///
/// The caller supplies metadata I/O authority and a live cancellation/deadline probe. No
/// `ReadMedia` capability is required or inferred. Every supported current report is verified
/// before filters are applied; limits, corruption, deletion and cancellation refuse the page.
/// `ReplayCx` binds metadata I/O to its root and principal; it does not retain the original
/// `ContextAuthority` grant set or quantities. Canonical transports admit `AgentQuery` and bind
/// these caller-supplied limits and the live deadline before constructing that context.
pub fn query_report_catalog(
    root: &Path,
    request: &ReportCatalogRequest,
    limits: ReportCatalogLimits,
    cx: &ReplayCx,
    cancelled: &(impl Fn() -> bool + Sync),
) -> Result<DeploymentReportCatalogQuery, ReportCatalogError> {
    read::query(root, request, limits, cx, cancelled)
}

fn hex(digest: ContentDigest) -> String {
    digest
        .bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

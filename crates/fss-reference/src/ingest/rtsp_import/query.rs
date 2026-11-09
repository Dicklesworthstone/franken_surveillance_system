#![forbid(unsafe_code)]
//! Protected catalog metadata selection followed by separately authorized native window imports.
//!
//! The preview reads metadata only. Execution revalidates that exact deployment/query decision,
//! then retains each selected whole window through the unchanged source-closed import owner.
//! Catalog metadata is a selection witness, not a partially retained catalog graph. No capture
//! clock, continuity between imports, source availability or media-disclosure grant is inferred.
//!
//! Publication is incremental. A refusal may follow durable earlier imports or an unconfirmed
//! current import. Any changed deployment anchor requires a new preview and approval; identical
//! child requests still reconcile through their existing native identities.

mod batch;
mod execute;
mod plan;

/// Conditional UTC selections across independent capture sessions or one discovered namespace.
pub mod utc;

pub use execute::{
    import_rtsp_query, import_rtsp_query_existing, import_rtsp_query_pinned,
    import_rtsp_query_pinned_existing,
};
pub use plan::preview_rtsp_query_import;

use std::fmt;
use std::ops::Range;
use std::path::{Path, PathBuf};

use fss_core::{ContentDigest, TimestampNs};

use super::{RtspImportError, RtspImportReceipt, RtspImportRequest};
use crate::agent_recording_context::{
    DeploymentRecordingQuery, RecordingContextError, RecordingContextLimits,
    RecordingContextRequest,
};
use crate::agent_recordings::RecordingQueryRow;
use crate::{ReferenceDeployment, ReferenceError};

/// Same finite selected-output bound as the protected recording query.
pub const MAX_WINDOWS: usize = 32;
/// Cooperative action boundary, including before any destination recovery or source payload read.
pub const STAGE_QUERY_IMPORT: &str = "rtsp_query_import:authority";
/// Boundary before the complete protected metadata decision is revalidated.
pub const STAGE_QUERY_REVALIDATE: &str = "rtsp_query_import:revalidate";
/// Boundary before the next independent native import.
pub const STAGE_QUERY_WINDOW: &str = "rtsp_query_import:next_window";
/// Final read-only source-layout/cancellation observation before aggregate success.
pub const STAGE_QUERY_FINALIZE: &str = "rtsp_query_import:finalize_source";

const DOMAIN: &str = "fss.rtsp_query_import_plan.v1";
const POLICY: &str = "protected-exact-catalog-query:whole-selected-native-windows:unknown-capture-time:unchanged-native-child-identities:exact-descriptor-check:one-import-work-account:independent-imports:no-partial-catalog:repreview-after-anchor-change:no-continuity:no-absence:no-media-delivery:v1";

/// Independent whole-selection acquisition bounds; metadata read limits remain separately priced.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtspQueryImportSettings {
    /// Existing destination site; must agree with both the protected snapshot and opened owner.
    pub site: String,
    /// Explicit destination receive time, shared by all children. Capture times remain unknown.
    pub receive_time: TimestampNs,
    /// Aggregate complete native samples, bounded by the existing catalog import ceiling.
    pub max_frames: usize,
    /// Aggregate original selected-window payloads, including each root and all four children.
    pub max_original_bytes: u64,
    /// Aggregate reconstructed MP4 bytes, checked before each child's first publication.
    pub max_media_bytes: u64,
    /// Whole native-import work ceiling. Existing archive-owner recovery has separate I/O bounds.
    pub max_work: u64,
}

/// One immutable metadata-selected window and its exact, independently authorized native request.
#[derive(Clone, Debug)]
pub struct RtspQueryImportWindow {
    /// Catalog ordinal, original descriptor and requested decode-clock overlap.
    pub row: RecordingQueryRow,
    /// Whole-window source custody request; it never narrows retention to the overlap.
    pub request: RtspImportRequest,
}

/// Read-only observation and deterministic acquisition recipe. Construction grants no write access.
#[derive(Clone, Debug)]
pub struct RtspQueryImportPlan {
    deployment_root: PathBuf,
    archive_root: PathBuf,
    request: RecordingContextRequest,
    limits: RecordingContextLimits,
    settings: RtspQueryImportSettings,
    query: DeploymentRecordingQuery,
    windows: Vec<RtspQueryImportWindow>,
    frames: usize,
    original_bytes: u64,
    digest: ContentDigest,
}
impl RtspQueryImportPlan {
    /// Exact context, selection, paths, settings, child requests and policy commitment.
    #[must_use]
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }
    /// Protected context and native metadata observation; no source availability is certified.
    #[must_use]
    pub fn query(&self) -> &DeploymentRecordingQuery {
        &self.query
    }
    /// Whole-selection acquisition settings bound by the plan.
    #[must_use]
    pub fn settings(&self) -> &RtspQueryImportSettings {
        &self.settings
    }
    /// All selected complete native requests in catalog order, with no truncation.
    #[must_use]
    pub fn windows(&self) -> &[RtspQueryImportWindow] {
        &self.windows
    }
    /// Declared total samples, independently checked against every loaded native descriptor.
    #[must_use]
    pub const fn frames(&self) -> usize {
        self.frames
    }
    /// Declared selected whole-window custody bytes, not bytes read by the metadata preview.
    #[must_use]
    pub const fn original_bytes(&self) -> u64 {
        self.original_bytes
    }
    /// Existing destination owner selected by this plan.
    #[must_use]
    pub fn deployment_root(&self) -> &Path {
        &self.deployment_root
    }
    /// Exact archive owner selected by this plan.
    #[must_use]
    pub fn archive_root(&self) -> &Path {
        &self.archive_root
    }
    /// Aggregate selected-source read allowance for the optional two-pass pinned reader.
    /// The legacy v1 plan/native identities remain unchanged; a transport selecting this
    /// strategy must bind the strategy and these values into its own exact approval.
    #[must_use]
    pub fn source_limits(&self) -> fss_publication::custody_audit::CustodyAuditLimits {
        batch::source_limits(
            self.windows.len(),
            self.original_bytes,
            self.windows
                .iter()
                .map(|window| window.row.entry.byte_len())
                .max()
                .unwrap_or(0),
        )
    }
}

/// Current independent original-read and destination-retention permission for one exact plan.
pub trait RtspQueryImportAuthority {
    /// Admit opening/recovering the existing destination before a mutable owner is available.
    /// The caller must enforce exact approval, current principal, capabilities and deadline.
    fn permit_open(&self, plan: &RtspQueryImportPlan) -> bool;

    /// Recheck exact approval, current privacy/retention policy, revocation and deadline.
    /// Query read admission and an unchanged historical source root never supply this grant.
    fn permit(&self, plan: &RtspQueryImportPlan, destination: &ReferenceDeployment) -> bool;
}

/// One completed native import. Its source closure contains this whole window, not the catalog.
#[derive(Debug)]
pub struct RtspQueryImportedWindow {
    /// Original stable ordinal within the pinned catalog.
    pub ordinal: usize,
    /// Original immutable recording-window root.
    pub source_root: ContentDigest,
    /// Requested native decode-clock overlap; retention includes the complete selected window.
    pub overlap: Range<u64>,
    /// Unchanged native receipt, directly usable by retained decode and screened local review.
    pub import: RtspImportReceipt,
}

/// Complete finite acquisition result. An empty query produces zero native imports.
#[derive(Debug)]
pub struct RtspQueryImportReceipt {
    /// Independently approved plan that was revalidated before the first native import.
    pub plan_digest: ContentDigest,
    /// Completed whole-window imports in selected catalog order.
    pub imports: Vec<RtspQueryImportedWindow>,
    /// Actual total native samples, checked against the complete metadata selection.
    pub frames: usize,
    /// Actual selected original custody bytes; shared objects count conservatively per window.
    pub original_bytes: u64,
    /// Actual total reconstructed MP4 bytes across independent imports.
    pub media_bytes: u64,
    /// Native import work charged during this call, without replenishment between windows.
    pub work_used: u64,
}

/// Payload-free typed refusal. No error is converted into an empty or partially successful query.
#[derive(Debug)]
pub enum RtspQueryImportError {
    /// Invalid settings, owner scope, malformed descriptor or aggregate admission bounds.
    Invalid(&'static str),
    /// Protected metadata context or query could not be verified.
    Context(Box<RecordingContextError>),
    /// A complete protected UTC session selection could not be verified.
    UtcSessionsContext(
        Box<crate::agent_recording_context::utc_sessions::RecordingUtcSessionsContextError>,
    ),
    /// A complete protected UTC namespace selection could not be verified.
    UtcDiscoveryContext(
        Box<crate::agent_recording_context::utc_discover::RecordingUtcDiscoveryContextError>,
    ),
    /// The approved context/selection differs from current metadata or the opened owner.
    StalePlan,
    /// Independent current authority, cancellation or deadline refused.
    Denied,
    /// Opening the existing destination failed; no alternate root or fresh deployment is created.
    Destination(Box<ReferenceError>),
    /// Existing native source or publication owner refused.
    Import(RtspImportError),
}
impl RtspQueryImportError {
    /// Existing non-disclosing import error family; the typed variant retains the exact cause.
    #[must_use]
    pub fn stable_id(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "ERR-RTSP-IMPORT-REQUEST-001",
            Self::Denied => "ERR-RTSP-IMPORT-AUTHORITY-001",
            Self::Context(_)
            | Self::UtcSessionsContext(_)
            | Self::UtcDiscoveryContext(_)
            | Self::StalePlan => "ERR-RTSP-IMPORT-SOURCE-001",
            Self::Destination(_) => "ERR-RTSP-IMPORT-CUSTODY-001",
            Self::Import(error) => error.stable_id(),
        }
    }
}
impl fmt::Display for RtspQueryImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.stable_id())
    }
}
impl std::error::Error for RtspQueryImportError {}
impl From<RtspImportError> for RtspQueryImportError {
    fn from(value: RtspImportError) -> Self {
        Self::Import(value)
    }
}
impl From<RecordingContextError> for RtspQueryImportError {
    fn from(value: RecordingContextError) -> Self {
        Self::Context(Box::new(value))
    }
}

/// Failed acquisition with the confirmed durable prefix, never an aggregate success receipt.
#[derive(Debug)]
pub struct RtspQueryImportFailure {
    /// Typed refusal without source-media contents.
    pub reason: RtspQueryImportError,
    /// Earlier imports whose complete native receipts were obtained.
    pub completed: Vec<RtspQueryImportedWindow>,
    /// Index into the plan's selected windows, not an original catalog ordinal.
    pub next_window: usize,
    /// The current native call may have published before its receipt was lost or refused.
    pub current_import_may_be_durable: bool,
}
impl fmt::Display for RtspQueryImportFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.reason, f)
    }
}
impl std::error::Error for RtspQueryImportFailure {}

fn failure(reason: RtspQueryImportError) -> RtspQueryImportFailure {
    RtspQueryImportFailure {
        reason,
        completed: Vec::new(),
        next_window: 0,
        current_import_may_be_durable: false,
    }
}

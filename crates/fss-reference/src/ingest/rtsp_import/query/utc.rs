#![forbid(unsafe_code)]
//! Independently approved acquisition of conditional UTC candidates.
//!
//! Sessions keep separate codec, generation, receive/decode clock and catalog coordinates.
//! Unknown-clock rows survive selection and consume the same aggregate allowance as timed
//! rows. Retention copies whole source-closed native windows, never an incomplete catalog or
//! clock root. Conditional node-observation metadata does not become a camera capture hint.

mod execute;
mod plan;

pub use execute::{import_rtsp_utc_query_pinned, import_rtsp_utc_query_pinned_existing};
pub use plan::preview_rtsp_utc_query_import;

use std::path::{Path, PathBuf};

use fss_core::ContentDigest;

use super::{RtspQueryImportError, RtspQueryImportSettings};
use crate::ReferenceDeployment;
use crate::agent_orient::DeploymentSnapshot;
use crate::agent_recording_context::utc_discover::{
    DeploymentRecordingUtcDiscoveryQuery, RecordingUtcDiscoveryContextLimits,
    RecordingUtcDiscoveryContextRequest,
};
use crate::agent_recording_context::utc_sessions::{
    DeploymentRecordingUtcSessionsQuery, RecordingUtcSessionsContextLimits,
    RecordingUtcSessionsContextRequest,
};
use crate::agent_recordings::utc_set::RecordingUtcSetQueryRow;
use crate::ingest::rtsp_import::{RtspImportReceipt, RtspImportRequest};
use crate::rtsp::recording_catalog::CatalogScope;

/// Complete original metadata request and its independently bounded protected read owner.
#[derive(Clone, Debug)]
pub enum RtspUtcQueryImportInput {
    /// Explicitly pinned independent captures of one exact sensor and stream.
    Sessions {
        /// Exact original sources, clock/catalog pins, predicate and principal.
        request: RecordingUtcSessionsContextRequest,
        /// One aggregate protected metadata allowance across the entire union.
        limits: RecordingUtcSessionsContextLimits,
    },
    /// Complete canonical catalog namespace with one independently pinned clock.
    Discovery {
        /// Exact historical namespace, retained clock, predicate and principal.
        request: RecordingUtcDiscoveryContextRequest,
        /// One aggregate protected metadata and directory-discovery allowance.
        limits: RecordingUtcDiscoveryContextLimits,
    },
}

/// Original protected observation, preserving every conditional clock assumption and gap.
#[derive(Clone, Debug)]
pub enum RtspUtcQueryImportObservation {
    /// Original source-separated union in canonical session order.
    Sessions(DeploymentRecordingUtcSessionsQuery),
    /// Original complete discovered namespace, inventory and conditional selection.
    Discovery(DeploymentRecordingUtcDiscoveryQuery),
}
impl RtspUtcQueryImportObservation {
    /// Current protected deployment metadata; no mutable owner or disclosure grant.
    #[must_use]
    pub fn snapshot(&self) -> &DeploymentSnapshot {
        match self {
            Self::Sessions(query) => &query.snapshot,
            Self::Discovery(query) => &query.snapshot,
        }
    }
    /// Exact authority/effect prefix used by this read-only observation.
    #[must_use]
    pub fn anchor_token(&self) -> &str {
        match self {
            Self::Sessions(query) => &query.anchor_token,
            Self::Discovery(query) => &query.anchor_token,
        }
    }
    /// Existing protected context request identity, including every metadata allowance.
    #[must_use]
    pub const fn request_digest(&self) -> ContentDigest {
        match self {
            Self::Sessions(query) => query.request_digest,
            Self::Discovery(query) => query.request_digest,
        }
    }
    /// Existing protected decision identity, including unselected references and unknowns.
    #[must_use]
    pub const fn decision_digest(&self) -> ContentDigest {
        match self {
            Self::Sessions(query) => query.decision_digest,
            Self::Discovery(query) => query.decision_digest,
        }
    }
}

/// One exact candidate; conditional UTC selection never narrows original source custody.
#[derive(Clone, Debug)]
pub struct RtspUtcQueryImportWindow {
    /// Canonical source position for sessions; absent for a single discovered namespace.
    pub session_index: Option<usize>,
    /// Exact independent session-pin identity; absent for namespace discovery.
    pub session_digest: Option<ContentDigest>,
    /// Original historical source and native receive/decode-clock coordinates.
    pub scope: CatalogScope,
    /// Independent retained clock root, not a new capture timestamp assertion.
    pub clock_root: ContentDigest,
    /// Rehashed canonical clock metadata used by the conditional selection.
    pub clock_metadata_digest: ContentDigest,
    /// Original descriptor, all catalog memberships, optional ordinal and UTC envelope.
    pub row: RecordingUtcSetQueryRow,
    /// Unchanged native whole-window request with unknown capture time.
    pub request: RtspImportRequest,
}

/// Immutable exact preview; its construction grants neither source reads nor retention.
#[derive(Clone, Debug)]
pub struct RtspUtcQueryImportPlan {
    deployment_root: PathBuf,
    archive_root: PathBuf,
    input: RtspUtcQueryImportInput,
    settings: RtspQueryImportSettings,
    query: RtspUtcQueryImportObservation,
    windows: Vec<RtspUtcQueryImportWindow>,
    frames: usize,
    original_bytes: u64,
    digest: ContentDigest,
}
impl RtspUtcQueryImportPlan {
    /// Exact paths, protected metadata, original clock provenance and acquisition bounds.
    #[must_use]
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }
    /// Complete protected observation including every per-source and aggregate gap.
    #[must_use]
    pub const fn query(&self) -> &RtspUtcQueryImportObservation {
        &self.query
    }
    /// Exact original query variant and metadata limits, never inferred from selected rows.
    #[must_use]
    pub const fn input(&self) -> &RtspUtcQueryImportInput {
        &self.input
    }
    /// Shared complete-selection retention and reconstruction bounds.
    #[must_use]
    pub const fn settings(&self) -> &RtspQueryImportSettings {
        &self.settings
    }
    /// All candidates, including unavailable-clock rows, in native canonical query order.
    #[must_use]
    pub fn windows(&self) -> &[RtspUtcQueryImportWindow] {
        &self.windows
    }
    /// Declared sample total, checked again against every full native replay.
    #[must_use]
    pub const fn frames(&self) -> usize {
        self.frames
    }
    /// Whole-window retained-original quote, not total source I/O or all-read cost.
    #[must_use]
    pub const fn original_bytes(&self) -> u64 {
        self.original_bytes
    }
    /// Exact existing destination selected before any mutable open.
    #[must_use]
    pub fn deployment_root(&self) -> &Path {
        &self.deployment_root
    }
    /// Exact independently verified read-only archive owner.
    #[must_use]
    pub fn archive_root(&self) -> &Path {
        &self.archive_root
    }
    /// One fixed whole-selection original read/I/O allowance, including both integrity passes.
    #[must_use]
    pub fn source_limits(&self) -> fss_publication::custody_audit::CustodyAuditLimits {
        super::batch::source_limits(
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

/// Independent current permission for original source reads and destination retention.
pub trait RtspUtcQueryImportAuthority {
    /// Exact approval, principal, deadline and capabilities before destination recovery.
    fn permit_open(&self, plan: &RtspUtcQueryImportPlan) -> bool;
    /// Recheck current policy, retention and revocation at every native action boundary.
    fn permit(&self, plan: &RtspUtcQueryImportPlan, destination: &ReferenceDeployment) -> bool;
}

/// One durable native child with the exact original conditional selection coordinates.
#[derive(Debug)]
pub struct RtspUtcQueryImportedWindow {
    /// Original metadata observation, never upgraded to trusted UTC or camera capture time.
    pub selection: RtspUtcQueryImportWindow,
    /// Unchanged native source-closed import receipt.
    pub import: RtspImportReceipt,
}

/// Complete bounded result; no unknown-clock candidate is silently omitted.
#[derive(Debug)]
pub struct RtspUtcQueryImportReceipt {
    /// Independently approved and freshly revalidated selection.
    pub plan_digest: ContentDigest,
    /// Complete native receipts in original canonical query order.
    pub imports: Vec<RtspUtcQueryImportedWindow>,
    /// Actual verified whole-window native samples.
    pub frames: usize,
    /// Actual original bytes retained, conservatively counted per selected window.
    pub original_bytes: u64,
    /// Actual reconstructed initialization-plus-fragment bytes.
    pub media_bytes: u64,
    /// Native read/replay, descriptor and publication work used without replenishment.
    pub work_used: u64,
}

/// Failure preserves the durable prefix and uncertainty about the current child.
#[derive(Debug)]
pub struct RtspUtcQueryImportFailure {
    /// Stable non-disclosing refusal with its typed cause.
    pub reason: RtspQueryImportError,
    /// Earlier children with complete native receipts.
    pub completed: Vec<RtspUtcQueryImportedWindow>,
    /// Index of the next or uncertain candidate in the immutable original selection.
    pub next_window: usize,
    /// The current child's publication began but its complete receipt was not obtained.
    pub current_import_may_be_durable: bool,
}
impl std::fmt::Display for RtspUtcQueryImportFailure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.reason, out)
    }
}
impl std::error::Error for RtspUtcQueryImportFailure {}

fn failure(reason: RtspQueryImportError) -> RtspUtcQueryImportFailure {
    RtspUtcQueryImportFailure {
        reason,
        completed: Vec::new(),
        next_window: 0,
        current_import_may_be_durable: false,
    }
}

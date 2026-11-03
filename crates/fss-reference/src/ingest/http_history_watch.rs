#![forbid(unsafe_code)]
//! Bounded, restartable processing of an independently pinned native reconnect history.
//!
//! The existing durable history owner verifies every selected connection and original byte.
//! Explicit per-generation camera and capture-time assumptions then feed the existing retained
//! HTTP importer, followed by the whole-recording zone-entry walker. Every reconnect starts an
//! independent background model and tracker. No receive clock is interpreted as capture time.
//!
//! Import custody is durable; analysis is read-only. A stopped invocation may have committed an
//! earlier import, and an exact retry verifies and reuses it through the existing importer.
//! There is no competing progress journal, automatic reconnect, head discovery, event approval,
//! effect authority or assertion that a prefix without a candidate was a quiet physical scene.

mod plan;
mod report;

use std::fmt;

use fss_codec_mjpeg::DecodeBudget;
use fss_core::ContentDigest;
use fss_geometry::WorkBudget;
use fss_publication::{LocalRootPublisher, PublishCancellation, PublishCutPoint};

use super::http_archive::{HttpWirePin, HttpWireScope};
use super::http_import::{
    HttpImportAuthority, HttpImportError, HttpImportReceipt, HttpImportRequest, import_http,
};
use super::long_watch::LongWatchReport;
use super::recorded_watch::{WatchError, WatchPlan};
use crate::http_reconnect_history::{
    ArchivedReconnectBoundary, BoundaryOutcome, HistoryError, ReconnectHistoryPin,
    VerifiedReconnectHistory,
};
use crate::{ReferenceDeployment, ReplayCx};

pub use plan::{
    HttpHistoryWatchBinding, HttpHistoryWatchLimits, HttpHistoryWatchPlan,
    HttpHistoryWatchReservation,
};
pub use report::HttpHistoryWatchReport;

/// One live checkpoint for source reads, imports and completion of the bounded processor.
pub const STAGE_HTTP_HISTORY_WATCH: &str = "http_history_watch:authority";
/// Cooperative restart cut before each generation's retained import begins.
pub const STAGE_HTTP_HISTORY_GENERATION: &str = "http_history_watch:next_generation";
/// Versioned, bounded JSON projection; no new durable journal or event schema is introduced.
pub const HTTP_HISTORY_WATCH_REPORT_SCHEMA: &str = "fss.http_history_watch_report.v1";
const POLICY: &[u8] = b"exact-native-history-prefix:explicit-generation-camera-capture-binding:\
source-closed-original-retention:fixed-upfront-generation-reservations:\
independent-background-and-tracker-per-connection:masked-before-perception:\
exact-import-reconciliation:no-network-resume:no-automatic-event:no-absence:no-alert:v1";
type Result<T> = std::result::Result<T, HttpHistoryWatchError>;

/// Current permission to disclose the selected originals and retain their exact imports in the
/// destination. This is separate from capture permission and from any future event approval.
pub trait HttpHistoryWatchAuthority {
    /// Recheck current policy, original access, destination retention and owner revocation.
    fn permit(&self, plan: &HttpHistoryWatchPlan, destination: &ReferenceDeployment) -> bool;
}

/// No refusal authorizes a repair, skipped generation, budget refill or nominal fallback.
#[derive(Debug)]
pub enum HttpHistoryWatchError {
    /// Invalid exact pin, generation binding, timing assumption, hint or limit configuration.
    Invalid(&'static str),
    /// Current owner authority, cancellation or deadline refused.
    Denied,
    /// A complete reservation or combined output exceeds its independent hard bound.
    Limit,
    /// The selected native history or its originals could not be verified.
    History(HistoryError),
    /// Existing source-closed retained import refused.
    Import(HttpImportError),
    /// Existing native streaming analysis refused.
    Watch(Box<WatchError>),
}
impl HttpHistoryWatchError {
    /// Stable registered error identity; native failures retain their own owner identity.
    pub fn stable_id(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "ERR-HTTP-HISTORY-WATCH-REQUEST-001",
            Self::Denied => "ERR-HTTP-HISTORY-WATCH-AUTHORITY-001",
            Self::Limit => "ERR-HTTP-HISTORY-WATCH-LIMIT-001",
            Self::History(error) => error.stable_id(),
            Self::Import(error) => error.stable_id(),
            Self::Watch(error) => error.stable_id(),
        }
    }
}
impl fmt::Display for HttpHistoryWatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {self:?}", self.stable_id())
    }
}
impl std::error::Error for HttpHistoryWatchError {}
impl From<HistoryError> for HttpHistoryWatchError {
    fn from(error: HistoryError) -> Self {
        Self::History(error)
    }
}
impl From<HttpImportError> for HttpHistoryWatchError {
    fn from(error: HttpImportError) -> Self {
        Self::Import(error)
    }
}
impl From<WatchError> for HttpHistoryWatchError {
    fn from(error: WatchError) -> Self {
        Self::Watch(Box::new(error))
    }
}

/// Explicit observation of how one selected response was processed, never a coverage claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpHistoryWatchStatus {
    /// Complete original JPEGs were imported and the whole retained recording was analyzed.
    Analyzed,
    /// The native connection ended without retaining any response bytes.
    EmptyResponse,
    /// Native replay reached the selected nonempty prefix without a complete original JPEG.
    NoCompleteJpeg,
}
impl HttpHistoryWatchStatus {
    /// Stable JSON spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Analyzed => "analyzed",
            Self::EmptyResponse => "empty_response",
            Self::NoCompleteJpeg => "no_complete_jpeg",
        }
    }
}

/// Immutable per-generation result. Reports and proposals grant no new publication capability.
#[derive(Debug)]
pub struct HttpHistoryWatchGeneration {
    boundary: ArchivedReconnectBoundary,
    binding: HttpHistoryWatchBinding,
    status: HttpHistoryWatchStatus,
    import: Option<HttpImportReceipt>,
    watch_plan: Option<WatchPlan>,
    watch_report: Option<LongWatchReport>,
}
impl HttpHistoryWatchGeneration {
    /// One-based native connection ordinal, including failed byte-empty attempts.
    pub fn connection(&self) -> u32 {
        self.boundary.connection()
    }
    /// Exact source generation, independent from tracker-local identities.
    pub fn generation(&self) -> u64 {
        self.boundary.scope().stream.generation
    }
    /// Native original response, receive clock and retention-decision identities.
    pub fn source(&self) -> HttpWireScope {
        self.boundary.scope()
    }
    /// Exact original-byte prefix owned by this ended connection.
    pub fn prefix(&self) -> HttpWirePin {
        self.boundary.prefix()
    }
    /// Archived native completion/failure class, never inferred from diagnostic strings.
    pub fn native_outcome(&self) -> BoundaryOutcome {
        self.boundary.outcome()
    }
    /// Explicit per-generation camera and operator capture-time assumptions.
    pub fn binding(&self) -> &HttpHistoryWatchBinding {
        &self.binding
    }
    /// Whether the generation was analyzed or contained no complete source frames.
    pub const fn status(&self) -> HttpHistoryWatchStatus {
        self.status
    }
    /// Exact completed retained import, including whether a retry verified existing custody.
    pub fn import(&self) -> Option<&HttpImportReceipt> {
        self.import.as_ref()
    }
    /// Exact native whole-recording plan, suitable for a separately approved event rerun.
    pub fn watch_plan(&self) -> Option<&WatchPlan> {
        self.watch_plan.as_ref()
    }
    /// Read-only native proposals. An immutable reference cannot publish the held report.
    pub fn watch_report(&self) -> Option<&LongWatchReport> {
        self.watch_report.as_ref()
    }
}

struct Access<'a> {
    authority: &'a dyn HttpHistoryWatchAuthority,
    plan: &'a HttpHistoryWatchPlan,
    destination: &'a ReferenceDeployment,
    cx: &'a ReplayCx,
}
impl Access<'_> {
    fn check(&self) -> Result<()> {
        if self.cx.checkpoint(STAGE_HTTP_HISTORY_WATCH).is_err()
            || !self.authority.permit(self.plan, self.destination)
        {
            return Err(HttpHistoryWatchError::Denied);
        }
        Ok(())
    }
}
impl PublishCancellation for Access<'_> {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        self.check().is_err()
    }
}
struct ImportAccess<'a> {
    authority: &'a dyn HttpHistoryWatchAuthority,
    plan: &'a HttpHistoryWatchPlan,
    request: ContentDigest,
    cx: &'a ReplayCx,
}
impl HttpImportAuthority for ImportAccess<'_> {
    fn permit(&self, request: &HttpImportRequest, destination: &ReferenceDeployment) -> bool {
        request.digest().is_ok_and(|digest| digest == self.request)
            && Access {
                authority: self.authority,
                plan: self.plan,
                destination,
                cx: self.cx,
            }
            .check()
            .is_ok()
    }
}

/// Verify an exact ended history, durably reconcile every import, then independently analyze
/// each generation. Whole-invocation history/import work and framing budgets are never reset.
/// On error completed imports remain durable; rerun the same exact plan to verify and reuse them.
/// Current privacy masks are applied by the native walker before any perception or screening.
pub fn process_http_history<'cx>(
    archive: &LocalRootPublisher,
    destination: &mut ReferenceDeployment,
    plan: &HttpHistoryWatchPlan,
    limits: &HttpHistoryWatchLimits,
    authority: &dyn HttpHistoryWatchAuthority,
    cx: &ReplayCx,
    work: &mut WorkBudget<'cx>,
    framing: &mut DecodeBudget<'cx>,
) -> Result<HttpHistoryWatchReport> {
    let reservation = plan.reservation(limits)?;
    let plan_digest = plan.digest(limits)?;
    if cx.root_dir() != destination.root()
        || archive.root_dir().starts_with(destination.root())
        || destination.root().starts_with(archive.root_dir())
    {
        return Err(HttpHistoryWatchError::Invalid(
            "source and destination roots",
        ));
    }
    let history = {
        let access = Access {
            authority,
            plan,
            destination,
            cx,
        };
        access.check()?;
        VerifiedReconnectHistory::load(archive, plan.history, limits.history, &access, work)?
    };
    // Validate the entire mapping and known prefix bounds before the first destination mutation.
    for (boundary, binding) in history.boundaries().iter().zip(&plan.bindings) {
        if boundary.scope().stream.generation != binding.generation
            || boundary.prefix().bytes > limits.maximum_bytes_per_generation
            || boundary.totals().frames > limits.maximum_frames_per_generation as u64
        {
            return Err(HttpHistoryWatchError::Invalid(
                "generation mapping or prefix bound",
            ));
        }
    }
    let mut generations = Vec::with_capacity(plan.bindings.len());
    for (boundary, binding) in history.boundaries().iter().zip(&plan.bindings) {
        cx.checkpoint(STAGE_HTTP_HISTORY_GENERATION)
            .map_err(|_| HttpHistoryWatchError::Denied)?;
        Access {
            authority,
            plan,
            destination,
            cx,
        }
        .check()?;
        let mut result = HttpHistoryWatchGeneration {
            boundary: boundary.clone(),
            binding: binding.clone(),
            status: HttpHistoryWatchStatus::EmptyResponse,
            import: None,
            watch_plan: None,
            watch_report: None,
        };
        if boundary.prefix().bytes != 0 {
            let request = HttpImportRequest {
                source: boundary.scope(),
                pin: boundary.prefix(),
                sensor: binding.sensor.clone(),
                stream: binding.stream.clone(),
                receive_time: binding.receive_time,
                capture_hint: Some(binding.capture_hint),
                max_frames: limits.maximum_frames_per_generation,
                max_bytes: limits.maximum_bytes_per_generation,
            };
            let access = ImportAccess {
                authority,
                plan,
                request: request.digest()?,
                cx,
            };
            match import_http(archive, destination, &request, &access, cx, work, framing) {
                Ok(receipt) => {
                    result.watch_plan =
                        Some(plan.watch_plan(receipt.import_identity, receipt.frames));
                    result.import = Some(receipt);
                    result.status = HttpHistoryWatchStatus::Analyzed;
                }
                Err(HttpImportError::NoCompleteFrames) => {
                    result.status = HttpHistoryWatchStatus::NoCompleteJpeg;
                }
                Err(error) => return Err(error.into()),
            }
        }
        generations.push(result);
    }
    // All imports are complete first: every proposal is analyzed at the same deployment basis.
    for generation in &mut generations {
        Access {
            authority,
            plan,
            destination,
            cx,
        }
        .check()?;
        if let Some(watch_plan) = &generation.watch_plan {
            generation.watch_report = Some(if plan.screened {
                LongWatchReport::analyze_screened(
                    destination,
                    watch_plan,
                    plan.options,
                    &limits.watch,
                    cx,
                )?
            } else {
                LongWatchReport::analyze(destination, watch_plan, plan.options, &limits.watch, cx)?
            });
        }
    }
    let access = Access {
        authority,
        plan,
        destination,
        cx,
    };
    access.check()?;
    // A detached, cached history is never allowed to bless an archive damaged during processing.
    VerifiedReconnectHistory::load(archive, plan.history, limits.history, &access, work)?;
    access.check()?;
    let report = HttpHistoryWatchReport {
        plan_digest,
        history: history.pin(),
        reservation,
        generations,
        maximum_report_bytes: limits.maximum_report_bytes,
        source_reads: history.reads(),
        source_bytes: history.bytes(),
        screened: plan.screened,
    };
    report.to_json(destination.current_anchor().commit_sequence, &[])?;
    Ok(report)
}

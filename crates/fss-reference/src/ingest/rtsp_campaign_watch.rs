#![forbid(unsafe_code)]
//! Exact retained RTSP campaign history → independent native imports → per-attempt watch.
//!
//! Every selected start remains visible, including failed, empty and unknown native outcomes.
//! Metadata supplies exact catalog coordinates, never original custody. The complete selected
//! inventory passes native original verification before any import; imports verify again, and
//! final disclosure rechecks both history and sources. One caller work account spans every pass.
//! All imports precede every analysis, so all read-only proposals share the final destination
//! anchor. Background/tracker state never crosses attempts, and no absence/event/effect authority
//! follows from an exact history prefix or a candidate-free retained recording.

mod plan;
mod report;

use std::fmt;
use std::path::Path;

use fss_core::ContentDigest;
use fss_geometry::WorkBudget;
use fss_publication::LocalRootPublisher;

use super::long_watch::LongWatchReport;
use super::recorded_watch::{WatchError, WatchPlan};
use super::rtsp_campaign_sources::{self, SourceLimits, Sources, Stages};
use super::rtsp_import::{RtspImportError, RtspImportReceipt};
use super::rtsp_selected_watch::{RtspSelectedWatchError, RtspWatchSelection};
use crate::rtsp::campaign_history::{
    CampaignAttemptHistory, CampaignAuthority, CampaignHistoryError, CampaignOperation,
    CampaignPin, CampaignPlan,
};
use crate::{ReferenceDeployment, ReplayCx};

pub use plan::{
    RtspCampaignWatchBinding, RtspCampaignWatchLimits, RtspCampaignWatchPlan,
    RtspCampaignWatchReservation,
};
pub use report::RtspCampaignWatchReport;

/// Current owner authority checkpoint for every processing phase and native import I/O cut.
pub const STAGE_RTSP_CAMPAIGN_WATCH: &str = "rtsp_campaign_watch:authority";
/// Before each complete original verification, before any destination import.
pub const STAGE_RTSP_CAMPAIGN_PREFLIGHT: &str = "rtsp_campaign_watch:preflight";
/// Before each exact restartable retained import.
pub const STAGE_RTSP_CAMPAIGN_IMPORT: &str = "rtsp_campaign_watch:next_import";
/// Before each independent native detector/tracker run at the common final import anchor.
pub const STAGE_RTSP_CAMPAIGN_ANALYZE: &str = "rtsp_campaign_watch:next_analysis";
/// Before final original/history revalidation; a refusal leaves any completed imports durable.
pub const STAGE_RTSP_CAMPAIGN_REVALIDATE: &str = "rtsp_campaign_watch:revalidate";
/// Last live owner check before disclosing the complete report.
pub const STAGE_RTSP_CAMPAIGN_RELEASE: &str = "rtsp_campaign_watch:release";
/// Versioned complete metadata/candidate projection; no parallel durable progress journal.
pub const RTSP_CAMPAIGN_WATCH_REPORT_SCHEMA: &str = "fss.rtsp_campaign_watch_report.v1";
const POLICY: &[u8] =
    b"exact-campaign-prefix:every-selected-start:exact-ordered-catalog-inventory:\
codec-specific-native-namespace:all-source-preflight-before-import:current-custody-on-import:\
final-history-and-source-revalidation:one-import-work-account:fixed-upfront-watch-reservations:\
all-imports-before-analysis:independent-attempt-trackers:masked-before-perception:\
recorded-unindexed-pictures-explicit:no-latest:no-resume:no-event:no-absence:no-alert:v1";
type Result<T> = std::result::Result<T, RtspCampaignWatchError>;

/// Current metadata disclosure plus explicit original-read, destination-retention and analysis
/// authority. Capture permission and retained history alone never grant this capability.
pub trait RtspCampaignWatchAuthority: CampaignAuthority {
    /// Recheck current principal, destination, privacy/retention policy, deadline and revocation.
    fn permit_watch(&self, plan: &RtspCampaignWatchPlan, destination: &ReferenceDeployment)
    -> bool;
}

/// Refusals never authorize skipping a catalog, refilling a budget, repairing sources or resuming
/// acquisition. Successfully completed native imports remain durable and exactly retryable.
#[derive(Debug)]
pub enum RtspCampaignWatchError {
    /// Invalid history mapping, source owner, exact namespace, sample count or pure request.
    Invalid(&'static str),
    /// Current owner, deadline or cancellation refused.
    Denied,
    /// Whole-operation reservation or complete report limit exceeded.
    Limit,
    /// Native immutable campaign verification refused.
    History(CampaignHistoryError),
    /// Native source-closed import or preflight refused.
    Import(RtspImportError),
    /// Shared exact-selection/configuration admission refused.
    Selection(RtspSelectedWatchError),
    /// Native whole-recording analysis refused.
    Watch(Box<WatchError>),
}
impl RtspCampaignWatchError {
    /// Stable native failure identities are preserved rather than flattened to a new success row.
    pub fn stable_id(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "ERR-RTSP-CAMPAIGN-WATCH-REQUEST-001",
            Self::Denied => "ERR-RTSP-CAMPAIGN-WATCH-AUTHORITY-001",
            Self::Limit => "ERR-RTSP-CAMPAIGN-WATCH-LIMIT-001",
            Self::History(error) => error.stable_id(),
            Self::Import(error) => error.stable_id(),
            Self::Selection(error) => error.stable_id(),
            Self::Watch(error) => error.stable_id(),
        }
    }
}
impl fmt::Display for RtspCampaignWatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {self:?}", self.stable_id())
    }
}
impl std::error::Error for RtspCampaignWatchError {}
impl From<CampaignHistoryError> for RtspCampaignWatchError {
    fn from(e: CampaignHistoryError) -> Self {
        Self::History(e)
    }
}
impl From<RtspImportError> for RtspCampaignWatchError {
    fn from(e: RtspImportError) -> Self {
        Self::Import(e)
    }
}
impl From<RtspSelectedWatchError> for RtspCampaignWatchError {
    fn from(e: RtspSelectedWatchError) -> Self {
        Self::Selection(e)
    }
}
impl From<WatchError> for RtspCampaignWatchError {
    fn from(e: WatchError) -> Self {
        Self::Watch(Box::new(e))
    }
}

/// Processing observation for one selected start. None of these statuses certifies a quiet scene.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RtspCampaignWatchStatus {
    /// Every exactly recorded catalog was imported and analyzed; unindexed pictures stay explicit.
    Analyzed,
    /// Native finish recorded zero durable pictures and no catalog. Source bytes may still exist.
    RecordedNoDurablePictures,
    /// Native finish recorded durable pictures but supplied no exact catalog bindings.
    RecordedPicturesWithoutCatalog,
    /// The selected start has no selected finish; later activity and native outcome remain unknown.
    StartedWithoutRetainedFinish,
    /// A controller finish exists but the native owner observation was unavailable.
    NativeObservationUnavailable,
}
impl RtspCampaignWatchStatus {
    /// Stable machine spelling, independent from native/controller diagnostic identities.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Analyzed => "analyzed",
            Self::RecordedNoDurablePictures => "recorded_no_durable_pictures",
            Self::RecordedPicturesWithoutCatalog => "recorded_pictures_without_catalog",
            Self::StartedWithoutRetainedFinish => "started_without_retained_finish",
            Self::NativeObservationUnavailable => "native_observation_unavailable",
        }
    }
}

/// Immutable per-attempt result. Proposals are read-only and confer no event publication authority.
#[derive(Debug)]
pub struct RtspCampaignWatchAttempt {
    recorded: CampaignAttemptHistory,
    selection: Option<RtspWatchSelection>,
    request_digest: Option<ContentDigest>,
    status: RtspCampaignWatchStatus,
    import: Option<RtspImportReceipt>,
    windows: usize,
    pages: usize,
    watch_plan: Option<WatchPlan>,
    watch_report: Option<LongWatchReport>,
}
impl RtspCampaignWatchAttempt {
    /// One-based ordinal from the retained acquisition plan.
    pub const fn ordinal(&self) -> u32 {
        self.recorded.attempt.ordinal
    }
    /// Original source generation; local track identities never join another attempt.
    pub const fn generation(&self) -> u64 {
        self.recorded.attempt.generation
    }
    /// Exact selected start/finish and native/controller observations.
    pub fn recorded(&self) -> &CampaignAttemptHistory {
        &self.recorded
    }
    /// Entire exact saved catalog inventory, when available.
    pub fn selection(&self) -> Option<&RtspWatchSelection> {
        self.selection.as_ref()
    }
    /// Native canonical import request identity, absent for non-analyzable rows.
    pub const fn request_digest(&self) -> Option<ContentDigest> {
        self.request_digest
    }
    /// Explicit processing observation, separate from native success or failure.
    pub const fn status(&self) -> RtspCampaignWatchStatus {
        self.status
    }
    /// Durable native retained import, including whether this execution reconciled an exact retry.
    pub fn import(&self) -> Option<&RtspImportReceipt> {
        self.import.as_ref()
    }
    /// Complete independently sealed windows included in this attempt's exact catalog selection.
    pub const fn windows(&self) -> usize {
        self.windows
    }
    /// Every saved catalog page in this attempt's exact selected inventory.
    pub const fn pages(&self) -> usize {
        self.pages
    }
    /// Native whole-recording plan, usable only under separately current event authority.
    pub fn watch_plan(&self) -> Option<&WatchPlan> {
        self.watch_plan.as_ref()
    }
    /// Read-only native candidates and refusal/health accounting.
    pub fn watch_report(&self) -> Option<&LongWatchReport> {
        self.watch_report.as_ref()
    }
    /// Native recorded count, unknown when no direct native observation was retained.
    pub fn recorded_durable_pictures(&self) -> Option<u64> {
        self.recorded
            .finish
            .as_ref()?
            .native
            .as_ref()
            .map(|native| native.durable_pictures)
    }
    /// Samples included in the verified retained catalog import, before any decode refusal.
    pub fn catalogued_pictures(&self) -> u64 {
        self.import.as_ref().map_or(0, |i| i.frames as u64)
    }
    /// Frames actually decoded by the native watch; tolerance and screening remain in its report.
    pub fn decoded_pictures(&self) -> u64 {
        self.watch_report
            .as_ref()
            .map_or(0, |w| w.frames_decoded() as u64)
    }
    /// Recorded durable pictures not represented by the saved catalog inventory. Unknown native
    /// counts stay unknown rather than being turned into a claim that no pictures exist.
    pub fn recorded_pictures_without_catalog(&self) -> Option<u64> {
        self.recorded_durable_pictures()
            .map(|count| count - self.catalogued_pictures())
    }
}

fn check(
    authority: &dyn RtspCampaignWatchAuthority,
    plan: &RtspCampaignWatchPlan,
    destination: &ReferenceDeployment,
    cx: &ReplayCx,
) -> Result<()> {
    if cx.checkpoint(STAGE_RTSP_CAMPAIGN_WATCH).is_err()
        || !authority.permit_watch(plan, destination)
    {
        return Err(RtspCampaignWatchError::Denied);
    }
    Ok(())
}

struct WatchAccess<'a> {
    authority: &'a dyn RtspCampaignWatchAuthority,
    plan: &'a RtspCampaignWatchPlan,
}
impl CampaignAuthority for WatchAccess<'_> {
    fn permit(&self, operation: CampaignOperation, plan: &CampaignPlan) -> bool {
        self.authority.permit(operation, plan)
    }
    fn permit_read(&self, pin: CampaignPin, root: &Path, principal: &str) -> bool {
        self.authority.permit_read(pin, root, principal)
    }
}
impl rtsp_campaign_sources::Authority for WatchAccess<'_> {
    fn check(&self, destination: &ReferenceDeployment, cx: &ReplayCx) -> Result<()> {
        check(self.authority, self.plan, destination, cx)
    }
}

/// Verify one exact metadata prefix and every saved original catalog before any import. Sources
/// are independently held owners aligned with every selected start; a non-analyzable row requires
/// `None`, so missing/failed/unknown attempts never cause directory creation or speculative reads.
/// Native imports then reverify current source custody; all analyses use the final import anchor.
/// Final history/source verification and current authority must pass before a report is returned.
#[allow(clippy::too_many_arguments)]
pub fn process_rtsp_campaign(
    archives: &[Option<&LocalRootPublisher>],
    destination: &mut ReferenceDeployment,
    plan: &RtspCampaignWatchPlan,
    limits: &RtspCampaignWatchLimits,
    authority: &dyn RtspCampaignWatchAuthority,
    history_cx: &ReplayCx,
    cx: &ReplayCx,
    work: &mut WorkBudget<'_>,
) -> Result<RtspCampaignWatchReport> {
    let reservation = plan.reservation(limits)?;
    let plan_digest = plan.digest(limits)?;
    let access = WatchAccess { authority, plan };
    let sources = Sources::prepare(
        plan.source_plan(),
        SourceLimits {
            history: limits.history,
            publication: limits.history_publication,
        },
        Stages {
            preflight: STAGE_RTSP_CAMPAIGN_PREFLIGHT,
            import: STAGE_RTSP_CAMPAIGN_IMPORT,
            revalidate: STAGE_RTSP_CAMPAIGN_REVALIDATE,
        },
        archives,
        &access,
        destination,
        history_cx,
        cx,
        work,
    )?;
    let mut attempts: Vec<_> = sources
        .import_all(destination, cx, work)?
        .into_iter()
        .map(|row| {
            let status = match row.recorded.finish.as_ref() {
                None => RtspCampaignWatchStatus::StartedWithoutRetainedFinish,
                Some(finish) => match &finish.native {
                    None => RtspCampaignWatchStatus::NativeObservationUnavailable,
                    Some(native)
                        if native.bindings.catalogs.is_empty() && native.durable_pictures == 0 =>
                    {
                        RtspCampaignWatchStatus::RecordedNoDurablePictures
                    }
                    Some(native) if native.bindings.catalogs.is_empty() => {
                        RtspCampaignWatchStatus::RecordedPicturesWithoutCatalog
                    }
                    Some(_) => RtspCampaignWatchStatus::Analyzed,
                },
            };
            let watch_plan = row
                .import
                .as_ref()
                .map(|import| plan.watch_plan(import.import_identity, import.frames));
            RtspCampaignWatchAttempt {
                recorded: row.recorded,
                selection: row.selection,
                request_digest: row.request_digest,
                status,
                import: row.import,
                windows: row.windows,
                pages: row.pages,
                watch_plan,
                watch_report: None,
            }
        })
        .collect();
    let basis = destination.current_anchor().clone();
    for row in &mut attempts {
        cx.checkpoint(STAGE_RTSP_CAMPAIGN_ANALYZE)
            .map_err(|_| RtspCampaignWatchError::Denied)?;
        check(authority, plan, destination, cx)?;
        if let Some(watch) = &row.watch_plan {
            row.watch_report = Some(if plan.screened {
                LongWatchReport::analyze_screened(
                    destination,
                    watch,
                    plan.options,
                    &limits.watch,
                    cx,
                )?
            } else {
                LongWatchReport::analyze(destination, watch, plan.options, &limits.watch, cx)?
            });
        }
    }
    let current_history = sources.revalidate(destination, history_cx, cx, work)?;
    let report = RtspCampaignWatchReport {
        plan_digest,
        history: current_history,
        reservation,
        attempts,
        basis,
        maximum_report_bytes: limits.maximum_report_bytes,
        screened: plan.screened,
    };
    report.to_json(destination.current_anchor().commit_sequence)?;
    cx.checkpoint(STAGE_RTSP_CAMPAIGN_RELEASE)
        .map_err(|_| RtspCampaignWatchError::Denied)?;
    check(authority, plan, destination, cx)?;
    Ok(report)
}

#![forbid(unsafe_code)]
//! Exact retained RTSP campaigns → motion-independent native detector bursts.
//!
//! Every selected start remains visible. Exact original custody uses the same sealed owner as
//! campaign watch, without running a foreground detector. One deterministic round-robin schedule
//! and one nonrenewable inference resource pool span all attempts. Native AVC/HEVC inference
//! drains each analyzed source range strictly; quota-skipped and short attempts remain explicitly
//! unsampled. Optional native per-attempt retention supports exact cold numerical replay.

mod budget;
mod plan;
mod report;

use std::fmt;
use std::path::Path;

use fss_core::{ContentDigest, LedgerAnchor};
use fss_geometry::WorkBudget;
use fss_publication::LocalRootPublisher;

use super::long_sentinel::retained::{
    LongSentinelRetentionError, RetainedLongSentinel, retain_long_sentinel_detection,
};
use super::long_sentinel::{LongSentinelReport, LongSentinelRequest, run_long_sentinel_detection};
use super::package_detect::PackageDetectError;
use super::package_event::RetentionStatus;
use super::privacy_mask::current_mask;
use super::rgb_package::{MAX_RGB_PACKAGE_BYTES, RgbDetectorPackage};
use super::rtsp_campaign_sources::{self, ImportedAttempt, SourceLimits, Sources, Stages};
use super::rtsp_campaign_watch::RtspCampaignWatchError;
use super::rtsp_import::RtspImportReceipt;
use super::rtsp_selected_watch::RtspWatchSelection;
use crate::rtsp::campaign_history::{
    CampaignAttemptHistory, CampaignAuthority, CampaignOperation, CampaignPin, CampaignPlan,
};
use crate::{ReferenceDeployment, ReplayCx, ScalarExecCx};

pub use plan::{
    MAX_CAMPAIGN_SENTINEL_INFERENCES, MAX_CAMPAIGN_SENTINEL_OUTPUT_BYTES,
    RtspCampaignSentinelAllocation, RtspCampaignSentinelConfig, RtspCampaignSentinelLimits,
    RtspCampaignSentinelPlan, RtspCampaignSentinelReservation,
};
pub use report::RtspCampaignSentinelReport;

/// Current whole-operation authority check, including each source I/O cut.
pub const STAGE_RTSP_CAMPAIGN_SENTINEL_AUTHORITY: &str = "rtsp_campaign_sentinel:authority";
/// Each complete original-source preflight, before all destination imports.
pub const STAGE_RTSP_CAMPAIGN_SENTINEL_PREFLIGHT: &str = "rtsp_campaign_sentinel:preflight";
/// Before each exact restartable original import.
pub const STAGE_RTSP_CAMPAIGN_SENTINEL_IMPORT: &str = "rtsp_campaign_sentinel:next_import";
/// Before each independent native model computation at the common final import anchor.
pub const STAGE_RTSP_CAMPAIGN_SENTINEL_ANALYZE: &str = "rtsp_campaign_sentinel:next_analysis";
/// Before each explicitly requested native aggregate retention, after all analyses succeed.
pub const STAGE_RTSP_CAMPAIGN_SENTINEL_RETAIN: &str = "rtsp_campaign_sentinel:retain";
/// Before final original/history verification; completed exact imports/retentions remain durable.
pub const STAGE_RTSP_CAMPAIGN_SENTINEL_REVALIDATE: &str = "rtsp_campaign_sentinel:revalidate";
/// Final live owner checkpoint before disclosing a complete campaign report.
pub const STAGE_RTSP_CAMPAIGN_SENTINEL_RELEASE: &str = "rtsp_campaign_sentinel:release";
/// Versioned complete projection, not a parallel authoritative progress journal.
pub const RTSP_CAMPAIGN_SENTINEL_REPORT_SCHEMA: &str = "fss.rtsp_campaign_sentinel_report.v1";

const POLICY: &[u8] = b"exact-campaign-prefix:every-selected-start:shared-native-source-owner:\
all-source-preflight-before-import:current-custody-on-import:final-original-and-history-closure:\
motion-independent:round-robin-whole-bursts:actual-catalog-samples:not-unindexed-durable-count:\
global-inference-ceiling:native-per-attempt-64:nonrenewable-source-pixel-jpeg-head-report-pools:\
source-pool-max-chunk-and-encoded:pixel-pool-max-raster-and-coded-capacity:\
all-imports-before-all-analysis:all-analysis-before-native-retention:strict-full-video-range:\
short-and-quota-skipped-unsampled:independent-bursts-and-attempts:current-privacy:\
bounded-aggregate-tensor-output:no-model-download:no-event:no-absence:no-alert:no-resume:v1";
type Result<T> = std::result::Result<T, RtspCampaignSentinelError>;

/// Current history disclosure, original read, destination import, model and optional native
/// retention authority. Capture permission and retained observations never grant this capability.
pub trait RtspCampaignSentinelAuthority: CampaignAuthority {
    /// Recheck principal, scopes, policy, current privacy, model, retention choice and revocation.
    fn permit_sentinel(
        &self,
        plan: &RtspCampaignSentinelPlan,
        destination: &ReferenceDeployment,
    ) -> bool;
}

/// A refusal releases no partial campaign success. Exact completed native imports or retained
/// children survive and reconcile on retry; budgets are not replenished within an invocation.
#[derive(Debug)]
pub enum RtspCampaignSentinelError {
    /// Invalid exact request, package, sampling or pure configuration.
    Invalid(&'static str),
    /// Current authority, owner cancellation or deadline refused.
    Denied,
    /// Whole-operation resource, resident-output or complete-report bound exceeded.
    Limit,
    /// Shared native exact campaign history/source/import owner refused.
    Source(RtspCampaignWatchError),
    /// Native strict source/decode/model/head computation refused.
    Detection(PackageDetectError),
    /// Existing native detector aggregate retention refused.
    Retention(LongSentinelRetentionError),
}
impl RtspCampaignSentinelError {
    /// Stable native failure identities stay visible; no failed attempt becomes a success row.
    pub fn stable_id(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "ERR-RTSP-CAMPAIGN-SENTINEL-REQUEST-001",
            Self::Denied => "ERR-RTSP-CAMPAIGN-SENTINEL-AUTHORITY-001",
            Self::Limit => "ERR-RTSP-CAMPAIGN-SENTINEL-LIMIT-001",
            Self::Source(error) => error.stable_id(),
            Self::Detection(error) => error.stable_id(),
            Self::Retention(error) => error.stable_id(),
        }
    }
}
impl fmt::Display for RtspCampaignSentinelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {self:?}", self.stable_id())
    }
}
impl std::error::Error for RtspCampaignSentinelError {}
impl From<RtspCampaignWatchError> for RtspCampaignSentinelError {
    fn from(error: RtspCampaignWatchError) -> Self {
        match error {
            RtspCampaignWatchError::Denied => Self::Denied,
            other => Self::Source(other),
        }
    }
}
impl From<PackageDetectError> for RtspCampaignSentinelError {
    fn from(error: PackageDetectError) -> Self {
        Self::Detection(error)
    }
}
impl From<LongSentinelRetentionError> for RtspCampaignSentinelError {
    fn from(error: LongSentinelRetentionError) -> Self {
        Self::Retention(error)
    }
}

/// Per-attempt processing observation, independent of its recorded native/controller outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RtspCampaignSentinelStatus {
    /// Granted complete bursts were inferred and the entire native video range drained strictly.
    Analyzed,
    /// Original catalogs were imported but no complete global inference allowance remained.
    BudgetSkipped,
    /// Original catalogs were imported but contain no complete configured inference burst.
    TooShortForBurst,
    /// Native finish recorded zero durable pictures and no catalog; original packets may exist.
    RecordedNoDurablePictures,
    /// Native finish recorded pictures without usable exact catalog bindings.
    RecordedPicturesWithoutCatalog,
    /// Selected start lacks a selected finish; later acquisition and outcome remain unknown.
    StartedWithoutRetainedFinish,
    /// Controller finish exists without a direct native outcome observation.
    NativeObservationUnavailable,
}
impl RtspCampaignSentinelStatus {
    /// Stable machine spelling; none asserts scene absence or acquisition completion.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Analyzed => "analyzed",
            Self::BudgetSkipped => "budget_skipped",
            Self::TooShortForBurst => "too_short_for_burst",
            Self::RecordedNoDurablePictures => "recorded_no_durable_pictures",
            Self::RecordedPicturesWithoutCatalog => "recorded_pictures_without_catalog",
            Self::StartedWithoutRetainedFinish => "started_without_retained_finish",
            Self::NativeObservationUnavailable => "native_observation_unavailable",
        }
    }
}

/// Small acknowledgement from the native aggregate owner. Full model archives are not retained
/// again in each in-memory campaign row; cold replay opens the native content-addressed closure.
#[derive(Clone, Debug)]
pub struct RtspCampaignSentinelRetention {
    report: ContentDigest,
    root: ContentDigest,
    recipe: ContentDigest,
    package: ContentDigest,
    anchor: LedgerAnchor,
    status: RetentionStatus,
    children: Vec<ContentDigest>,
}
impl RtspCampaignSentinelRetention {
    fn from_native(native: &RetainedLongSentinel) -> Self {
        Self {
            report: native.report_digest(),
            root: native.root(),
            recipe: native.recipe_digest(),
            package: native.package_digest(),
            anchor: native.authority_anchor().clone(),
            status: native.status(),
            children: native.child_reports().to_vec(),
        }
    }
    /// Exact native aggregate report and cold numerical replay lookup handle.
    pub const fn report_digest(&self) -> ContentDigest {
        self.report
    }
    /// Complete native source/model/recipe/report closure root.
    pub const fn root(&self) -> ContentDigest {
        self.root
    }
    /// Exact retained native execution recipe identity, including residual resource limits.
    pub const fn recipe_digest(&self) -> ContentDigest {
        self.recipe
    }
    /// Exact retained complete model archive identity.
    pub const fn package_digest(&self) -> ContentDigest {
        self.package
    }
    /// Native canonical retention anchor, separate from the campaign analysis basis.
    pub fn authority_anchor(&self) -> &LedgerAnchor {
        &self.anchor
    }
    /// Newly retained or exact already-retained acknowledgement.
    pub const fn status(&self) -> RetentionStatus {
        self.status
    }
    /// Independent complete burst report handles; they confer no event authority.
    pub fn child_reports(&self) -> &[ContentDigest] {
        &self.children
    }
}

/// Immutable exact source observation, allocation and optional native inference/retention result.
#[derive(Debug)]
pub struct RtspCampaignSentinelAttempt {
    source: ImportedAttempt,
    status: RtspCampaignSentinelStatus,
    allocation: RtspCampaignSentinelAllocation,
    sentinel: Option<LongSentinelReport>,
    retained: Option<RtspCampaignSentinelRetention>,
}
impl RtspCampaignSentinelAttempt {
    /// Original one-based retained attempt ordinal.
    pub const fn ordinal(&self) -> u32 {
        self.source.recorded.attempt.ordinal
    }
    /// Independent original source generation, never a cross-attempt track identity.
    pub const fn generation(&self) -> u64 {
        self.source.recorded.attempt.generation
    }
    /// Exact selected start/finish and native/controller observations.
    pub fn recorded(&self) -> &CampaignAttemptHistory {
        &self.source.recorded
    }
    /// Every exact saved catalog pin for this attempt, when available.
    pub fn selection(&self) -> Option<&RtspWatchSelection> {
        self.source.selection.as_ref()
    }
    /// Exact native source import request identity.
    pub const fn request_digest(&self) -> Option<ContentDigest> {
        self.source.request_digest
    }
    /// Processing observation, distinct from native acquisition success or failure.
    pub const fn status(&self) -> RtspCampaignSentinelStatus {
        self.status
    }
    /// Durable source-verified import, including exact-retry acknowledgement.
    pub fn import(&self) -> Option<&RtspImportReceipt> {
        self.source.import.as_ref()
    }
    /// Complete native recording windows in the exact catalog selection.
    pub const fn windows(&self) -> usize {
        self.source.windows
    }
    /// Every selected saved catalog page, without truncation.
    pub const fn pages(&self) -> usize {
        self.source.pages
    }
    /// Native recorded durable pictures, unknown when no native observation exists.
    pub fn recorded_durable_pictures(&self) -> Option<u64> {
        self.recorded()
            .finish
            .as_ref()?
            .native
            .as_ref()
            .map(|n| n.durable_pictures)
    }
    /// Verified catalog samples, separate from decoded frames and model calls.
    pub fn catalogued_pictures(&self) -> u64 {
        self.import().map_or(0, |i| i.frames as u64)
    }
    /// Native pictures actually decoded, including unsampled video reference frames. This is
    /// zero for imported attempts that received no complete inference burst.
    pub fn decoded_pictures(&self) -> u64 {
        self.sentinel_report()
            .map_or(0, |report| report.usage().decoded_frames as u64)
    }
    /// Recorded durable pictures outside the saved catalog inventory, preserving unknowns.
    pub fn recorded_pictures_without_catalog(&self) -> Option<u64> {
        self.recorded_durable_pictures()
            .map(|count| count - self.catalogued_pictures())
    }
    /// Exact campaign-wide whole-burst allocation derived from verified catalog counts.
    pub const fn allocation(&self) -> &RtspCampaignSentinelAllocation {
        &self.allocation
    }
    /// Complete strict native model report; absent for unsampled or unavailable attempts.
    pub fn sentinel_report(&self) -> Option<&LongSentinelReport> {
        self.sentinel.as_ref()
    }
    /// Explicit native aggregate retention acknowledgement, separate from analysis completion.
    pub fn retained(&self) -> Option<&RtspCampaignSentinelRetention> {
        self.retained.as_ref()
    }
}

fn check(
    authority: &dyn RtspCampaignSentinelAuthority,
    plan: &RtspCampaignSentinelPlan,
    destination: &ReferenceDeployment,
    cx: &ReplayCx,
    scalar: &ScalarExecCx,
) -> Result<()> {
    if cx
        .checkpoint(STAGE_RTSP_CAMPAIGN_SENTINEL_AUTHORITY)
        .is_err()
        || scalar
            .checkpoint(STAGE_RTSP_CAMPAIGN_SENTINEL_AUTHORITY)
            .is_err()
        || !authority.permit_sentinel(plan, destination)
    {
        return Err(RtspCampaignSentinelError::Denied);
    }
    Ok(())
}

struct SentinelAccess<'a> {
    authority: &'a dyn RtspCampaignSentinelAuthority,
    plan: &'a RtspCampaignSentinelPlan,
    scalar: &'a ScalarExecCx,
}
impl CampaignAuthority for SentinelAccess<'_> {
    fn permit(&self, operation: CampaignOperation, plan: &CampaignPlan) -> bool {
        self.authority.permit(operation, plan)
    }
    fn permit_read(&self, pin: CampaignPin, root: &Path, principal: &str) -> bool {
        self.authority.permit_read(pin, root, principal)
    }
}
impl rtsp_campaign_sources::Authority for SentinelAccess<'_> {
    fn check(
        &self,
        destination: &ReferenceDeployment,
        cx: &ReplayCx,
    ) -> std::result::Result<(), RtspCampaignWatchError> {
        check(self.authority, self.plan, destination, cx, self.scalar)
            .map_err(|_| RtspCampaignWatchError::Denied)
    }
}

fn status(
    source: &ImportedAttempt,
    allocation: RtspCampaignSentinelAllocation,
) -> RtspCampaignSentinelStatus {
    if source.import.is_some() {
        return if allocation.eligible_bursts == 0 {
            RtspCampaignSentinelStatus::TooShortForBurst
        } else if allocation.admitted_inferences == 0 {
            RtspCampaignSentinelStatus::BudgetSkipped
        } else {
            RtspCampaignSentinelStatus::Analyzed
        };
    }
    match source.recorded.finish.as_ref() {
        None => RtspCampaignSentinelStatus::StartedWithoutRetainedFinish,
        Some(finish) => match &finish.native {
            None => RtspCampaignSentinelStatus::NativeObservationUnavailable,
            Some(native) if native.durable_pictures == 0 => {
                RtspCampaignSentinelStatus::RecordedNoDurablePictures
            }
            Some(_) => RtspCampaignSentinelStatus::RecordedPicturesWithoutCatalog,
        },
    }
}

/// Analyze every exact retained campaign source through independently scheduled trained-model
/// bursts. Complete preflight and exact allocation precede all imports; all imports precede all
/// model work; all computations precede optional native retention. Final source/history/current
/// authority checks gate the combined report. No foreground gate, event or camera effect occurs.
#[allow(clippy::too_many_arguments)]
pub fn process_rtsp_campaign_sentinel(
    archives: &[Option<&LocalRootPublisher>],
    destination: &mut ReferenceDeployment,
    package: &RgbDetectorPackage,
    archive_bytes: &[u8],
    plan: &RtspCampaignSentinelPlan,
    limits: &RtspCampaignSentinelLimits,
    authority: &dyn RtspCampaignSentinelAuthority,
    history_cx: &ReplayCx,
    cx: &ReplayCx,
    scalar: &ScalarExecCx,
    work: &mut WorkBudget<'_>,
) -> Result<RtspCampaignSentinelReport> {
    let reservation = plan.reservation(limits)?;
    let plan_digest = plan.digest(limits)?;
    check(authority, plan, destination, cx, scalar)?;
    if archive_bytes.len() > MAX_RGB_PACKAGE_BYTES
        || ContentDigest::sha256(archive_bytes) != plan.package_digest
        || package.archive_digest() != plan.package_digest
        || package.model().backend() != plan.backend
    {
        return Err(RtspCampaignSentinelError::Invalid(
            "exact model archive or native backend",
        ));
    }
    if let Some(score) = plan.minimum_score_ppm {
        package
            .contract_with_threshold(score)
            .map_err(|_| RtspCampaignSentinelError::Invalid("package threshold contract"))?;
    }
    let access = SentinelAccess {
        authority,
        plan,
        scalar,
    };
    let sources = Sources::prepare(
        plan.source_plan(),
        SourceLimits {
            history: limits.history,
            publication: limits.history_publication,
        },
        Stages {
            preflight: STAGE_RTSP_CAMPAIGN_SENTINEL_PREFLIGHT,
            import: STAGE_RTSP_CAMPAIGN_SENTINEL_IMPORT,
            revalidate: STAGE_RTSP_CAMPAIGN_SENTINEL_REVALIDATE,
        },
        archives,
        &access,
        destination,
        history_cx,
        cx,
        work,
    )?;
    let allocation = plan.allocate(&sources.frame_counts())?;
    let mut attempts: Vec<_> = sources
        .import_all(destination, cx, work)?
        .into_iter()
        .zip(allocation)
        .map(|(source, allocation)| RtspCampaignSentinelAttempt {
            status: status(&source, allocation),
            source,
            allocation,
            sentinel: None,
            retained: None,
        })
        .collect();
    let basis = destination.current_anchor().clone();
    let mut pool = budget::Pool::new(limits.sentinel);
    for row in &mut attempts {
        cx.checkpoint(STAGE_RTSP_CAMPAIGN_SENTINEL_ANALYZE)
            .map_err(|_| RtspCampaignSentinelError::Denied)?;
        check(authority, plan, destination, cx, scalar)?;
        if row.allocation.admitted_inferences == 0 {
            continue;
        }
        let import = row.import().ok_or(RtspCampaignSentinelError::Invalid(
            "allocated source import unavailable",
        ))?;
        let request = LongSentinelRequest {
            import_identity: import.import_identity,
            first_segment: 0,
            segment_count: import.frames,
            interpretation: plan.interpretation,
            minimum_score_ppm: plan.minimum_score_ppm,
        };
        let remaining = pool.remaining()?;
        let report = run_long_sentinel_detection(
            destination,
            package,
            &request,
            plan.native_config(row.allocation),
            &remaining,
            cx,
            scalar,
        )?;
        // A native CRA/BLA-led HEVC range may legitimately skip a leading RASL picture.
        // Campaign strict coverage requires every catalogued picture, including unsampled ones.
        if report.usage().decoded_frames != import.frames {
            return Err(RtspCampaignSentinelError::Invalid(
                "native decode did not cover every catalogued picture",
            ));
        }
        pool.charge(&report, row.allocation.admitted_inferences)?;
        row.sentinel = Some(report);
    }
    if plan.retain {
        for row in &mut attempts {
            let Some(report) = row.sentinel.as_ref() else {
                continue;
            };
            cx.checkpoint(STAGE_RTSP_CAMPAIGN_SENTINEL_RETAIN)
                .map_err(|_| RtspCampaignSentinelError::Denied)?;
            check(authority, plan, destination, cx, scalar)?;
            let retained =
                retain_long_sentinel_detection(destination, package, archive_bytes, report, cx)?;
            row.retained = Some(RtspCampaignSentinelRetention::from_native(&retained));
        }
    }
    let history = sources.revalidate(destination, history_cx, cx, work)?;
    // Retention can advance the ledger without changing the computation's source identity.
    // Recheck the native privacy binding itself rather than demanding an unchanged ledger head.
    for row in &attempts {
        check(authority, plan, destination, cx, scalar)?;
        if let Some(report) = &row.sentinel {
            for child in report.reports() {
                let first = child
                    .frames
                    .first()
                    .ok_or(RtspCampaignSentinelError::Invalid(
                        "native burst has no source frame",
                    ))?;
                let mask =
                    current_mask(destination, &first.capsule.sensor_id).map_err(|error| {
                        PackageDetectError::Frame {
                            segment: first.segment,
                            source: Box::new(error),
                        }
                    })?;
                if mask != child.privacy {
                    return Err(RtspCampaignSentinelError::Invalid(
                        "current privacy differs from native inference binding",
                    ));
                }
            }
        }
    }
    let report = RtspCampaignSentinelReport {
        plan_digest,
        history,
        reservation,
        attempts,
        basis,
        usage: pool.usage,
        source_pool_charged: pool.source_charged,
        pixel_pool_charged: pool.pixels_charged,
        native_report_bytes: pool.report_bytes,
        maximum_report_bytes: limits.maximum_report_bytes,
        package: plan.package_digest,
        backend: plan.backend,
        sampling: plan.sampling,
        retain: plan.retain,
    };
    report.to_json(destination.current_anchor().commit_sequence)?;
    cx.checkpoint(STAGE_RTSP_CAMPAIGN_SENTINEL_RELEASE)
        .map_err(|_| RtspCampaignSentinelError::Denied)?;
    check(authority, plan, destination, cx, scalar)?;
    Ok(report)
}

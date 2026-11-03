#![forbid(unsafe_code)]
//! Exact ended HTTP histories → motion-independent native detector bursts.
//!
//! Every recorded connection remains visible, including empty, incomplete and failed responses.
//! Explicit source/camera/capture assumptions feed the same original-preserving importer as
//! history watch. One round-robin whole-burst schedule and one nonrenewable native resource pool
//! span all generations. Optional native aggregate retention supports source-closed cold replay.
//! No foreground gate, cross-reconnect track, receive-to-capture inference, event or effect occurs.

mod plan;
mod report;

use std::fmt;

use fss_codec_mjpeg::DecodeBudget;
use fss_core::{ContentDigest, LedgerAnchor};
use fss_geometry::{GeometryError, WorkBudget};
use fss_publication::LocalRootPublisher;

use super::RetainedFileImport;
use super::http_archive::{HttpWirePin, HttpWireScope};
use super::http_history_sources::{self, ImportedGeneration, Sources};
use super::http_history_watch::{HttpHistoryWatchBinding, HttpHistoryWatchError};
use super::http_import::HttpImportReceipt;
use super::long_sentinel::pool;
use super::long_sentinel::retained::{
    LongSentinelRetentionError, RetainedLongSentinel, retain_long_sentinel_detection,
};
use super::long_sentinel::{LongSentinelReport, LongSentinelRequest, run_long_sentinel_detection};
use super::package_detect::PackageDetectError;
use super::package_event::RetentionStatus;
use super::privacy_mask::current_mask;
use super::recorded_decode::source_capsule;
use super::rgb_package::{MAX_RGB_PACKAGE_BYTES, RgbDetectorPackage};
use crate::http_reconnect_history::BoundaryOutcome;
use crate::{ReferenceDeployment, ReplayCx, ScalarExecCx};

pub use plan::{
    HttpHistorySentinelAllocation, HttpHistorySentinelConfig, HttpHistorySentinelLimits,
    HttpHistorySentinelPlan, HttpHistorySentinelReservation, MAX_HTTP_HISTORY_SENTINEL_INFERENCES,
    MAX_HTTP_HISTORY_SENTINEL_OUTPUT_BYTES, MAX_HTTP_HISTORY_SENTINEL_REPORT_BYTES,
};
pub use report::HttpHistorySentinelReport;

/// Live complete-operation permission check, including native source I/O cut points.
pub const STAGE_HTTP_HISTORY_SENTINEL_AUTHORITY: &str = "http_history_sentinel:authority";
/// Before original history verification and any destination import.
pub const STAGE_HTTP_HISTORY_SENTINEL_PREFLIGHT: &str = "http_history_sentinel:preflight";
/// Before each exact restartable retained import.
pub const STAGE_HTTP_HISTORY_SENTINEL_IMPORT: &str = "http_history_sentinel:next_import";
/// Before each independent native trained-model computation at the common analysis anchor.
pub const STAGE_HTTP_HISTORY_SENTINEL_ANALYZE: &str = "http_history_sentinel:next_analysis";
/// Before each explicitly requested native aggregate retention, after all computations succeed.
pub const STAGE_HTTP_HISTORY_SENTINEL_RETAIN: &str = "http_history_sentinel:retain";
/// Before final original/history/destination custody checks and report disclosure.
pub const STAGE_HTTP_HISTORY_SENTINEL_REVALIDATE: &str = "http_history_sentinel:revalidate";
/// Final current-authority checkpoint before returning the complete combined report.
pub const STAGE_HTTP_HISTORY_SENTINEL_RELEASE: &str = "http_history_sentinel:release";
/// Complete bounded projection; this adds no parallel progress journal or event format.
pub const HTTP_HISTORY_SENTINEL_REPORT_SCHEMA: &str = "fss.http_history_sentinel_report.v1";

const POLICY: &[u8] = b"exact-ended-history:every-connection:shared-native-source-owner:\
explicit-generation-camera-capture-binding:all-original-preflight-before-import:\
all-imports-before-model:all-model-before-retention:final-history-and-destination-custody:\
motion-independent:connection-round-robin-whole-bursts:actual-imported-jpeg-count:\
global-inference-ceiling:native-per-generation-64:nonrenewable-source-pixel-jpeg-head-report-pools:\
selected-only-jpeg:bounded-resident-tensor-output:current-privacy:independent-bursts-and-generations:\
failed-and-incomplete-native-outcomes-preserved:short-and-quota-skipped-unsampled:\
no-capture-inference:no-download:no-network-resume:no-event:no-absence:no-alert:v1";
type Result<T> = std::result::Result<T, HttpHistorySentinelError>;

/// Current original read, destination import, model execution and optional native retention
/// authority. Capture permission and stored model observations never grant these capabilities.
pub trait HttpHistorySentinelAuthority {
    /// Recheck exact plan, destination, principal, privacy, owner approval and revocation.
    fn permit_sentinel(
        &self,
        plan: &HttpHistorySentinelPlan,
        destination: &ReferenceDeployment,
    ) -> bool;
}

/// No refusal releases partial success or silently skips a generation. Completed native imports
/// and explicitly requested retentions remain durable and reconcile on an exact retry.
#[derive(Debug)]
pub enum HttpHistorySentinelError {
    /// Invalid exact source/model choice, timing assumption, sampling or resource configuration.
    Invalid(&'static str),
    /// Current authority, cancellation or deadline refused.
    Denied,
    /// Complete invocation resources, resident tensors or report bytes exceed their allowance.
    Limit,
    /// Shared native HTTP history, original custody or exact retained import refused.
    Source(HttpHistoryWatchError),
    /// Native source decode, model or detection-head computation refused.
    Detection(PackageDetectError),
    /// Existing source-closed native aggregate retention refused.
    Retention(LongSentinelRetentionError),
}
impl HttpHistorySentinelError {
    /// Stable owner error; underlying native refusals keep their original identities.
    pub fn stable_id(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "ERR-HTTP-HISTORY-SENTINEL-REQUEST-001",
            Self::Denied => "ERR-HTTP-HISTORY-SENTINEL-AUTHORITY-001",
            Self::Limit => "ERR-HTTP-HISTORY-SENTINEL-LIMIT-001",
            Self::Source(error) => error.stable_id(),
            Self::Detection(error) => error.stable_id(),
            Self::Retention(error) => error.stable_id(),
        }
    }
}
impl fmt::Display for HttpHistorySentinelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {self:?}", self.stable_id())
    }
}
impl std::error::Error for HttpHistorySentinelError {}
impl From<HttpHistoryWatchError> for HttpHistorySentinelError {
    fn from(error: HttpHistoryWatchError) -> Self {
        match error {
            HttpHistoryWatchError::Denied => Self::Denied,
            HttpHistoryWatchError::Invalid(reason) => Self::Invalid(reason),
            HttpHistoryWatchError::Limit => Self::Limit,
            other => Self::Source(other),
        }
    }
}
impl From<PackageDetectError> for HttpHistorySentinelError {
    fn from(error: PackageDetectError) -> Self {
        Self::Detection(error)
    }
}
impl From<LongSentinelRetentionError> for HttpHistorySentinelError {
    fn from(error: LongSentinelRetentionError) -> Self {
        Self::Retention(error)
    }
}
impl From<pool::Error> for HttpHistorySentinelError {
    fn from(error: pool::Error) -> Self {
        match error {
            pool::Error::Invalid(reason) => Self::Invalid(reason),
            pool::Error::Limit => Self::Limit,
        }
    }
}

/// Processing observation, independent of recorded native acquisition completion or failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpHistorySentinelStatus {
    /// All granted complete independent bursts were inferred from their original JPEGs.
    Analyzed,
    /// Originals were imported but no complete global inference allowance remained.
    BudgetSkipped,
    /// Originals were imported but contain no complete configured burst.
    TooShortForBurst,
    /// The native connection ended without retaining response bytes.
    EmptyResponse,
    /// Native replay reached a nonempty exact prefix with no complete original JPEG.
    NoCompleteJpeg,
}
impl HttpHistorySentinelStatus {
    /// Stable JSON spelling; no status certifies absence or physical coverage.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Analyzed => "analyzed",
            Self::BudgetSkipped => "budget_skipped",
            Self::TooShortForBurst => "too_short_for_burst",
            Self::EmptyResponse => "empty_response",
            Self::NoCompleteJpeg => "no_complete_jpeg",
        }
    }
}

/// Small native acknowledgement; complete model bytes are held by the retained content closure,
/// not copied into every in-memory history row.
#[derive(Clone, Debug)]
pub struct HttpHistorySentinelRetention {
    report: ContentDigest,
    root: ContentDigest,
    recipe: ContentDigest,
    package: ContentDigest,
    anchor: LedgerAnchor,
    status: RetentionStatus,
    children: Vec<ContentDigest>,
}
impl HttpHistorySentinelRetention {
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
    /// Exact native aggregate and cold numerical replay lookup handle.
    pub const fn report_digest(&self) -> ContentDigest {
        self.report
    }
    /// Complete native source/model/recipe/report closure root.
    pub const fn root(&self) -> ContentDigest {
        self.root
    }
    /// Exact native execution recipe, including the original residual resource ceilings.
    pub const fn recipe_digest(&self) -> ContentDigest {
        self.recipe
    }
    /// Complete original native model archive digest.
    pub const fn package_digest(&self) -> ContentDigest {
        self.package
    }
    /// Native canonical retention anchor, separate from the common analysis basis.
    pub fn authority_anchor(&self) -> &LedgerAnchor {
        &self.anchor
    }
    /// New or exact already-retained native acknowledgement.
    pub const fn status(&self) -> RetentionStatus {
        self.status
    }
    /// Independent complete burst report handles; they grant no event authority.
    pub fn child_reports(&self) -> &[ContentDigest] {
        &self.children
    }
}

/// Immutable original-boundary observation and its independent inference/retention result.
#[derive(Debug)]
pub struct HttpHistorySentinelGeneration {
    source: ImportedGeneration,
    status: HttpHistorySentinelStatus,
    allocation: HttpHistorySentinelAllocation,
    sentinel: Option<LongSentinelReport>,
    retained: Option<HttpHistorySentinelRetention>,
}
impl HttpHistorySentinelGeneration {
    /// One-based native connection ordinal, including failed byte-empty attempts.
    pub fn connection(&self) -> u32 {
        self.source.boundary.connection()
    }
    /// Exact native original source generation, not a tracker identity.
    pub fn generation(&self) -> u64 {
        self.source.boundary.scope().stream.generation
    }
    /// Native source, receive-clock and retention-evidence identities.
    pub fn source(&self) -> HttpWireScope {
        self.source.boundary.scope()
    }
    /// Exact original response prefix, including wrappers and an incomplete tail.
    pub fn prefix(&self) -> HttpWirePin {
        self.source.boundary.prefix()
    }
    /// Typed archived native outcome; a computed prefix never turns a failed response complete.
    pub fn native_outcome(&self) -> BoundaryOutcome {
        self.source.boundary.outcome()
    }
    /// Explicit owner camera and capture-time assumptions.
    pub fn binding(&self) -> &HttpHistoryWatchBinding {
        &self.source.binding
    }
    /// Processing status, independent of native acquisition outcome.
    pub const fn status(&self) -> HttpHistorySentinelStatus {
        self.status
    }
    /// Completed original-bound import and exact-retry acknowledgement.
    pub fn import(&self) -> Option<&HttpImportReceipt> {
        self.source.import.as_ref()
    }
    /// Exact history-wide whole-burst allocation from actual import receipts.
    pub const fn allocation(&self) -> &HttpHistorySentinelAllocation {
        &self.allocation
    }
    /// Complete native model report, absent for unsampled or empty connections.
    pub fn sentinel_report(&self) -> Option<&LongSentinelReport> {
        self.sentinel.as_ref()
    }
    /// Optional source-closed native retention and cold-replay handle.
    pub fn retained(&self) -> Option<&HttpHistorySentinelRetention> {
        self.retained.as_ref()
    }
}

fn check(
    authority: &dyn HttpHistorySentinelAuthority,
    plan: &HttpHistorySentinelPlan,
    destination: &ReferenceDeployment,
    cx: &ReplayCx,
    scalar: &ScalarExecCx,
) -> Result<()> {
    if cx
        .checkpoint(STAGE_HTTP_HISTORY_SENTINEL_AUTHORITY)
        .is_err()
        || scalar
            .checkpoint(STAGE_HTTP_HISTORY_SENTINEL_AUTHORITY)
            .is_err()
        || !authority.permit_sentinel(plan, destination)
    {
        return Err(HttpHistorySentinelError::Denied);
    }
    Ok(())
}
struct Access<'a> {
    authority: &'a dyn HttpHistorySentinelAuthority,
    plan: &'a HttpHistorySentinelPlan,
    scalar: &'a ScalarExecCx,
}
impl http_history_sources::Authority for Access<'_> {
    fn check(
        &self,
        destination: &ReferenceDeployment,
        cx: &ReplayCx,
    ) -> std::result::Result<(), HttpHistoryWatchError> {
        check(self.authority, self.plan, destination, cx, self.scalar)
            .map_err(|_| HttpHistoryWatchError::Denied)
    }
}
fn status(
    source: &ImportedGeneration,
    allocation: HttpHistorySentinelAllocation,
) -> HttpHistorySentinelStatus {
    if source.import.is_some() {
        if allocation.eligible_bursts == 0 {
            HttpHistorySentinelStatus::TooShortForBurst
        } else if allocation.admitted_inferences == 0 {
            HttpHistorySentinelStatus::BudgetSkipped
        } else {
            HttpHistorySentinelStatus::Analyzed
        }
    } else if source.boundary.prefix().bytes == 0 {
        HttpHistorySentinelStatus::EmptyResponse
    } else {
        HttpHistorySentinelStatus::NoCompleteJpeg
    }
}
fn source_error<E: std::error::Error + 'static>(
    segment: usize,
) -> impl FnOnce(E) -> HttpHistorySentinelError {
    move |error| {
        PackageDetectError::Frame {
            segment,
            source: Box::new(error),
        }
        .into()
    }
}

fn charge_source_work(work: &mut WorkBudget<'_>, units: u64) -> Result<()> {
    work.charge(units).map_err(|error| match error {
        GeometryError::Cancelled => HttpHistorySentinelError::Denied,
        _ => HttpHistorySentinelError::Limit,
    })
}

/// Import every complete original JPEG before any model work, then independently infer granted
/// bursts without a motion gate. All computation precedes optional native retention. A final
/// full history and destination-custody check gates the complete report. Whole-invocation source
/// work, framing and model resource accounts are never reset at connection boundaries.
#[allow(clippy::too_many_arguments)]
pub fn process_http_history_sentinel<'cx>(
    archive: &LocalRootPublisher,
    destination: &mut ReferenceDeployment,
    package: &RgbDetectorPackage,
    archive_bytes: &[u8],
    plan: &HttpHistorySentinelPlan,
    limits: &HttpHistorySentinelLimits,
    authority: &dyn HttpHistorySentinelAuthority,
    cx: &ReplayCx,
    scalar: &ScalarExecCx,
    work: &mut WorkBudget<'cx>,
    framing: &mut DecodeBudget<'cx>,
) -> Result<HttpHistorySentinelReport> {
    let reservation = plan.reservation(limits)?;
    let plan_digest = plan.digest(limits)?;
    check(authority, plan, destination, cx, scalar)?;
    if archive_bytes.len() > MAX_RGB_PACKAGE_BYTES
        || ContentDigest::sha256(archive_bytes) != plan.package_digest
        || package.archive_digest() != plan.package_digest
        || package.model().backend() != plan.backend
    {
        return Err(HttpHistorySentinelError::Invalid(
            "exact model archive or native backend",
        ));
    }
    if let Some(score) = plan.minimum_score_ppm {
        package
            .contract_with_threshold(score)
            .map_err(|_| HttpHistorySentinelError::Invalid("package threshold contract"))?;
    }
    cx.checkpoint(STAGE_HTTP_HISTORY_SENTINEL_PREFLIGHT)
        .map_err(|_| HttpHistorySentinelError::Denied)?;
    let access = Access {
        authority,
        plan,
        scalar,
    };
    let sources = Sources::prepare(
        archive,
        plan.source_plan(),
        limits.source_limits(),
        &access,
        STAGE_HTTP_HISTORY_SENTINEL_IMPORT,
        destination,
        cx,
        work,
    )?;
    let imported = sources.import_all(destination, cx, work, framing)?;
    // Counts are actual complete native import receipts, never a guessed total from receive reads.
    let allocation = plan.allocate(
        &imported
            .iter()
            .map(|row| row.import.as_ref().map_or(0, |i| i.frames))
            .collect::<Vec<_>>(),
    )?;
    let mut generations: Vec<_> = imported
        .into_iter()
        .zip(allocation)
        .map(|(source, allocation)| HttpHistorySentinelGeneration {
            status: status(&source, allocation),
            source,
            allocation,
            sentinel: None,
            retained: None,
        })
        .collect();
    let basis = destination.current_anchor().clone();
    let mut pool = pool::Pool::new(limits.sentinel);
    for row in &mut generations {
        cx.checkpoint(STAGE_HTTP_HISTORY_SENTINEL_ANALYZE)
            .map_err(|_| HttpHistorySentinelError::Denied)?;
        check(authority, plan, destination, cx, scalar)?;
        if row.allocation.admitted_inferences == 0 {
            continue;
        }
        let import = row.import().ok_or(HttpHistorySentinelError::Invalid(
            "allocated import unavailable",
        ))?;
        let request = LongSentinelRequest {
            import_identity: import.import_identity,
            first_segment: 0,
            segment_count: import.frames,
            interpretation: plan.interpretation,
            minimum_score_ppm: plan.minimum_score_ppm,
        };
        let report = run_long_sentinel_detection(
            destination,
            package,
            &request,
            plan.native_config(row.allocation),
            &pool.remaining()?,
            cx,
            scalar,
        )?;
        // Native MJPEG decodes only the admitted independent images. Unselected images remain
        // explicit unsampled source coordinates, unlike strict inter-coded video draining.
        pool.charge(&report, row.allocation.admitted_inferences)?;
        row.sentinel = Some(report);
    }
    if plan.retain {
        for row in &mut generations {
            let Some(report) = row.sentinel.as_ref() else {
                continue;
            };
            cx.checkpoint(STAGE_HTTP_HISTORY_SENTINEL_RETAIN)
                .map_err(|_| HttpHistorySentinelError::Denied)?;
            check(authority, plan, destination, cx, scalar)?;
            let retained =
                retain_long_sentinel_detection(destination, package, archive_bytes, report, cx)?;
            row.retained = Some(HttpHistorySentinelRetention::from_native(&retained));
        }
    }
    cx.checkpoint(STAGE_HTTP_HISTORY_SENTINEL_REVALIDATE)
        .map_err(|_| HttpHistorySentinelError::Denied)?;
    sources.revalidate(destination, cx, work)?;
    for row in &generations {
        check(authority, plan, destination, cx, scalar)?;
        if let Some(import) = row.import() {
            let retained = RetainedFileImport::open(
                destination,
                import.import_identity,
                limits.sentinel.package.read,
                cx,
            )
            .map_err(source_error(0))?;
            if retained.import_root() != import.import_root
                || retained.manifest_digest() != import.manifest_digest
                || retained.manifest().segment_spans.len() != import.frames
            {
                return Err(HttpHistorySentinelError::Invalid(
                    "current destination import identity",
                ));
            }
            // This independent custody pass is explicitly reserved before I/O and charged to
            // shared source work. It does not replenish any model/decode resource allowance.
            charge_source_work(
                work,
                retained
                    .manifest()
                    .input_bytes
                    .checked_add(row.prefix().bytes)
                    .ok_or(HttpHistorySentinelError::Limit)?,
            )?;
            for segment in 0..import.frames {
                check(authority, plan, destination, cx, scalar)?;
                charge_source_work(work, 1)?;
                let (capsule, _) = source_capsule(destination, &retained, segment)
                    .map_err(source_error(segment))?;
                if capsule.sensor_id != row.binding().sensor
                    || capsule.stream_id != row.binding().stream
                {
                    return Err(HttpHistorySentinelError::Invalid(
                        "current source capsule binding",
                    ));
                }
            }
            retained
                .verify_source(destination, limits.sentinel.package.read, cx)
                .map_err(source_error(0))?;
        }
        if let Some(report) = row.sentinel_report() {
            for child in report.reports() {
                let first = child
                    .frames
                    .first()
                    .ok_or(HttpHistorySentinelError::Invalid(
                        "native burst has no source frame",
                    ))?;
                let mask = current_mask(destination, &first.capsule.sensor_id)
                    .map_err(source_error(first.segment))?;
                if mask != child.privacy {
                    return Err(HttpHistorySentinelError::Invalid(
                        "current privacy differs from native inference binding",
                    ));
                }
            }
        }
    }
    let report = HttpHistorySentinelReport {
        plan_digest,
        history: sources.history().pin(),
        reservation,
        generations,
        basis,
        usage: pool.usage,
        source_pool_charged: pool.source_charged,
        pixel_pool_charged: pool.pixels_charged,
        native_report_bytes: pool.report_bytes,
        maximum_report_bytes: limits.maximum_report_bytes,
        source_reads: sources.history().reads(),
        source_bytes: sources.history().bytes(),
        package: plan.package_digest,
        backend: plan.backend,
        sampling: plan.sampling,
        retain: plan.retain,
    };
    report.to_json(destination.current_anchor().commit_sequence)?;
    cx.checkpoint(STAGE_HTTP_HISTORY_SENTINEL_RELEASE)
        .map_err(|_| HttpHistorySentinelError::Denied)?;
    check(authority, plan, destination, cx, scalar)?;
    Ok(report)
}

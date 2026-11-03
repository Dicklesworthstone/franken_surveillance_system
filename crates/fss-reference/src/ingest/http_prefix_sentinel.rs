#![forbid(unsafe_code)]
//! Trained detection over an explicitly selected prefix of one HTTP camera generation.
//!
//! A requested frame stop is not an ended response. Native HTTP import retains every original
//! byte, including read-ahead JPEGs and the unfinished tail, while inference selects only the
//! caller's acknowledged first N frames. The existing long-sentinel owner records unsampled
//! frames within that selection; additional imported frames are reported separately. No socket,
//! EOF, connection history, cross-generation continuity or effect authority is manufactured.

use std::fmt;

use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget};
use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm, LedgerAnchor};
use fss_geometry::{GeometryError, WorkBudget};
use fss_publication::{LocalRootPublisher, PublishCancellation, PublishCutPoint};

use super::RetainedFileImport;
use super::http_archive::{HttpArchiveError, HttpArchiveLimits, HttpWireArchive};
use super::http_import::{
    HttpImportAuthority, HttpImportError, HttpImportReceipt, HttpImportRequest,
};
use super::long_sentinel::retained::{
    LongSentinelRetentionError, RetainedLongSentinel, retain_long_sentinel_detection,
};
use super::long_sentinel::{
    LongSentinelConfig, LongSentinelLimits, LongSentinelPlan, LongSentinelReport,
    LongSentinelRequest, LongSentinelReservation, run_long_sentinel_detection,
};
use super::package_detect::PackageDetectError;
use super::privacy_mask::current_mask;
use super::recorded_decode::source_capsule;
use super::rgb_package::{MAX_RGB_PACKAGE_BYTES, RgbDetectorPackage};
use crate::{KernelBackend, ReferenceDeployment, ReplayCx, ScalarExecCx};

/// Current original-read, model-execution and optional retained-cognition permission boundary.
pub const STAGE_HTTP_PREFIX_SENTINEL_AUTHORITY: &str = "http_prefix_sentinel:authority";
/// Exact original-prefix verification before the first destination mutation.
pub const STAGE_HTTP_PREFIX_SENTINEL_PREFLIGHT: &str = "http_prefix_sentinel:preflight";
/// One native import of all complete frames and every original source byte.
pub const STAGE_HTTP_PREFIX_SENTINEL_IMPORT: &str = "http_prefix_sentinel:import";
/// Typed retained-import progress must be accepted before any native model inference.
pub const STAGE_HTTP_PREFIX_SENTINEL_PROGRESS: &str = "http_prefix_sentinel:progress";
/// Native detector execution over only the acknowledged source-frame selection.
pub const STAGE_HTTP_PREFIX_SENTINEL_ANALYZE: &str = "http_prefix_sentinel:analyze";
/// Existing source-closed long-sentinel retention after successful computation.
pub const STAGE_HTTP_PREFIX_SENTINEL_RETAIN: &str = "http_prefix_sentinel:retain";
/// Complete source, destination and current-privacy revalidation before disclosure.
pub const STAGE_HTTP_PREFIX_SENTINEL_REVALIDATE: &str = "http_prefix_sentinel:revalidate";
/// Final current-authority check; failure never returns a partial report.
pub const STAGE_HTTP_PREFIX_SENTINEL_RELEASE: &str = "http_prefix_sentinel:release";

const POLICY: &str = "one-explicit-http-prefix:original-read-ahead-and-partial-tail-retained:\
acknowledged-first-n-only:whole-burst-native-schedule:one-source-pixel-jpeg-head-allowance:\
native-model-and-retention:current-privacy:all-original-and-destination-revalidation:\
no-ended-history:no-capture-time-inference:no-network:no-event:no-absence:v1";
const MAX_RESIDENT_OUTPUT_BYTES: u64 = 1024 * 1024 * 1024;
type Result<T> = std::result::Result<T, HttpPrefixSentinelError>;

/// Exact original prefix, independently acknowledged range and explicit model policy.
#[derive(Clone, Debug)]
pub struct HttpPrefixSentinelPlan {
    /// Native import request. Its frame bound covers all read-ahead, not only selected frames.
    pub import: HttpImportRequest,
    /// First N complete original parts selected by the caller, from one source generation.
    /// This is an explicit selection assertion, not proof that the response or camera ended.
    pub acknowledged_frames: usize,
    /// Explicit JPEG interpretation; no component guessing is permitted.
    pub interpretation: ComponentInterpretation,
    /// Exact original native RGB package bytes admitted by the caller.
    pub package_digest: ContentDigest,
    /// Native kernel backend and its pinned implementation generation.
    pub backend: KernelBackend,
    /// Native package threshold unless an explicit inclusive ppm threshold is selected.
    pub minimum_score_ppm: Option<u32>,
    /// A single native schedule and nonrenewable model-call allowance, at most 64 calls.
    pub sampling: LongSentinelConfig,
    /// Explicitly request existing source-closed aggregate/model retention after computation.
    pub retain: bool,
}

impl HttpPrefixSentinelPlan {
    /// Validate and reserve the complete native computation without source or model I/O.
    pub fn reservation(&self, limits: &LongSentinelLimits) -> Result<LongSentinelReservation> {
        self.import.digest()?;
        if self.acknowledged_frames == 0
            || self.acknowledged_frames > self.import.max_frames
            || self.package_digest.algorithm() != DigestAlgorithm::Sha256
            || self.package_digest.bytes() == [0; 32]
            || self
                .minimum_score_ppm
                .is_some_and(|score| score > 1_000_000)
        {
            return Err(HttpPrefixSentinelError::Invalid(
                "prefix selection or model identity",
            ));
        }
        let schedule = LongSentinelPlan::new(0, self.acknowledged_frames, self.sampling)?;
        let reservation = schedule.reservation(limits)?;
        if reservation.output_bytes > MAX_RESIDENT_OUTPUT_BYTES {
            return Err(HttpPrefixSentinelError::Limit);
        }
        Ok(reservation)
    }

    /// Bind every source byte, camera/time assumption, selection, backend and resource ceiling.
    pub fn digest(&self, limits: &LongSentinelLimits) -> Result<ContentDigest> {
        self.reservation(limits)?;
        let mut e = CanonicalEncoder::new();
        e.text("fss.http_prefix_sentinel_plan.v1");
        e.text(POLICY);
        e.digest(self.import.digest()?);
        e.u64(self.acknowledged_frames as u64);
        e.text(match self.interpretation {
            ComponentInterpretation::Grayscale => "grayscale",
            ComponentInterpretation::YCbCr => "ycbcr",
        });
        e.digest(self.package_digest);
        e.text(self.backend.stable_id());
        e.digest(self.backend.generation());
        e.bool(self.minimum_score_ppm.is_some());
        if let Some(score) = self.minimum_score_ppm {
            e.u32(score);
        }
        e.digest(LongSentinelPlan::new(0, self.acknowledged_frames, self.sampling)?.digest());
        e.digest(limits.digest());
        e.u64(MAX_RESIDENT_OUTPUT_BYTES);
        e.bool(self.retain);
        Ok(ContentDigest::sha256(
            &e.finish_checked()
                .map_err(|_| HttpPrefixSentinelError::Limit)?,
        ))
    }
}

/// Current explicit source, destination, principal, model and optional retention permission.
pub trait HttpPrefixSentinelAuthority {
    /// Recheck the entire approved plan and current policy; capture permission alone is insufficient.
    fn permit_sentinel(
        &self,
        plan: &HttpPrefixSentinelPlan,
        destination: &ReferenceDeployment,
    ) -> bool;
}

/// Native source/import/model errors retain their original identity and recovery semantics.
#[derive(Debug)]
pub enum HttpPrefixSentinelError {
    /// Invalid exact selection or a mismatch between selected and verified original frames.
    Invalid(&'static str),
    /// Current permission, cancellation or deadline refused.
    Denied,
    /// A nonrenewable work, output or allocation allowance was exhausted.
    Limit,
    /// The caller's typed retained-import progress sink refused; no inference was started.
    ProgressRefused,
    /// Original source or native import custody refused.
    Import(HttpImportError),
    /// Native retained decode, model or detection-head computation refused.
    Detection(PackageDetectError),
    /// Existing native source-closed report/model retention refused.
    Retention(LongSentinelRetentionError),
}
impl HttpPrefixSentinelError {
    /// Stable public refusal; no variant authorizes acquisition, repair or model substitution.
    pub fn stable_id(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "ERR-HTTP-PREFIX-SENTINEL-REQUEST-001",
            Self::Denied => "ERR-HTTP-PREFIX-SENTINEL-AUTHORITY-001",
            Self::Limit => "ERR-HTTP-PREFIX-SENTINEL-LIMIT-001",
            Self::ProgressRefused => "ERR-HTTP-PREFIX-SENTINEL-PROGRESS-001",
            Self::Import(error) => error.stable_id(),
            Self::Detection(error) => error.stable_id(),
            Self::Retention(error) => error.stable_id(),
        }
    }
}
impl fmt::Display for HttpPrefixSentinelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {self:?}", self.stable_id())
    }
}
impl std::error::Error for HttpPrefixSentinelError {}
impl From<HttpImportError> for HttpPrefixSentinelError {
    fn from(error: HttpImportError) -> Self {
        match error {
            HttpImportError::Denied => Self::Denied,
            other => Self::Import(other),
        }
    }
}
impl From<PackageDetectError> for HttpPrefixSentinelError {
    fn from(error: PackageDetectError) -> Self {
        Self::Detection(error)
    }
}
impl From<LongSentinelRetentionError> for HttpPrefixSentinelError {
    fn from(error: LongSentinelRetentionError) -> Self {
        Self::Retention(error)
    }
}
fn source_error(error: HttpArchiveError) -> HttpPrefixSentinelError {
    HttpImportError::Source(format!("{error:?}")).into()
}
fn frame_error<E: std::error::Error + 'static>(
    segment: usize,
) -> impl FnOnce(E) -> HttpPrefixSentinelError {
    move |error| {
        PackageDetectError::Frame {
            segment,
            source: Box::new(error),
        }
        .into()
    }
}
fn charge(work: &mut WorkBudget<'_>, units: u64) -> Result<()> {
    work.charge(units).map_err(|error| match error {
        GeometryError::Cancelled => HttpPrefixSentinelError::Denied,
        _ => HttpPrefixSentinelError::Limit,
    })
}

/// Typed composition of unchanged native owners; there is no parallel persisted report format.
#[derive(Debug)]
pub struct HttpPrefixSentinelReport {
    plan_digest: ContentDigest,
    import: HttpImportReceipt,
    acknowledged_frames: usize,
    read_ahead: usize,
    sentinel: LongSentinelReport,
    retained: Option<RetainedLongSentinel>,
    basis: LedgerAnchor,
}
impl HttpPrefixSentinelReport {
    /// Exact approved plan and every native execution ceiling.
    pub fn plan_digest(&self) -> ContentDigest {
        self.plan_digest
    }
    /// Native original/import closure, including actual framing ending and all read-ahead frames.
    pub fn import(&self) -> &HttpImportReceipt {
        &self.import
    }
    /// Complete source-frame range admitted to the native schedule, before sampling.
    pub fn acknowledged_frames(&self) -> usize {
        self.acknowledged_frames
    }
    /// Additional complete imported JPEGs retained for custody but never selected for this run.
    pub fn imported_read_ahead_frames(&self) -> usize {
        self.read_ahead
    }
    /// Existing native computation, including sampling, unsampled ranges and actual resource usage.
    pub fn sentinel_report(&self) -> &LongSentinelReport {
        &self.sentinel
    }
    /// Existing source-closed aggregate, absent unless explicitly requested.
    pub fn retained(&self) -> Option<&RetainedLongSentinel> {
        self.retained.as_ref()
    }
    /// Destination anchor after complete import, before any new cognition retention.
    pub fn analysis_basis(&self) -> &LedgerAnchor {
        &self.basis
    }
}

fn check(
    authority: &dyn HttpPrefixSentinelAuthority,
    plan: &HttpPrefixSentinelPlan,
    destination: &ReferenceDeployment,
    cx: &ReplayCx,
    scalar: &ScalarExecCx,
) -> Result<()> {
    if cx.checkpoint(STAGE_HTTP_PREFIX_SENTINEL_AUTHORITY).is_err()
        || scalar
            .checkpoint(STAGE_HTTP_PREFIX_SENTINEL_AUTHORITY)
            .is_err()
        || !authority.permit_sentinel(plan, destination)
    {
        return Err(HttpPrefixSentinelError::Denied);
    }
    Ok(())
}
struct Permit<'a> {
    authority: &'a dyn HttpPrefixSentinelAuthority,
    plan: &'a HttpPrefixSentinelPlan,
    scalar: &'a ScalarExecCx,
}
impl HttpImportAuthority for Permit<'_> {
    fn permit(&self, request: &HttpImportRequest, destination: &ReferenceDeployment) -> bool {
        request
            .digest()
            .ok()
            .zip(self.plan.import.digest().ok())
            .is_some_and(|(a, b)| a == b)
            && self
                .scalar
                .checkpoint(STAGE_HTTP_PREFIX_SENTINEL_AUTHORITY)
                .is_ok()
            && self.authority.permit_sentinel(self.plan, destination)
    }
}
struct SourceAccess<'a> {
    authority: &'a dyn HttpPrefixSentinelAuthority,
    plan: &'a HttpPrefixSentinelPlan,
    destination: &'a ReferenceDeployment,
    cx: &'a ReplayCx,
    scalar: &'a ScalarExecCx,
}
impl PublishCancellation for SourceAccess<'_> {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        check(
            self.authority,
            self.plan,
            self.destination,
            self.cx,
            self.scalar,
        )
        .is_err()
    }
}
fn verify_originals(
    archive: &LocalRootPublisher,
    access: &SourceAccess<'_>,
    work: &mut WorkBudget<'_>,
) -> Result<()> {
    let request = &access.plan.import;
    HttpWireArchive::load(
        archive,
        request.source,
        request.pin,
        HttpArchiveLimits {
            maximum_reads: 4096,
            maximum_bytes: request.max_bytes,
            maximum_scan_roots: 65536,
            maximum_spool_object_bytes: 16 * 1024 * 1024,
        },
        access,
        work,
    )
    .map_err(source_error)?;
    Ok(())
}

/// Import one exact response prefix and run the existing detector over only the acknowledged
/// first N frames. Every invocation shares the caller's source/framing accounts. Native imports
/// and requested retentions may survive a later refusal and reconcile on an exact cold retry.
#[allow(clippy::too_many_arguments)]
pub fn process_http_prefix_sentinel<'cx>(
    archive: &LocalRootPublisher,
    destination: &mut ReferenceDeployment,
    package: &RgbDetectorPackage,
    package_bytes: &[u8],
    plan: &HttpPrefixSentinelPlan,
    limits: &LongSentinelLimits,
    authority: &dyn HttpPrefixSentinelAuthority,
    cx: &ReplayCx,
    scalar: &ScalarExecCx,
    work: &mut WorkBudget<'cx>,
    framing: &mut DecodeBudget<'cx>,
) -> Result<HttpPrefixSentinelReport> {
    process_http_prefix_sentinel_observed(
        archive,
        destination,
        package,
        package_bytes,
        plan,
        limits,
        authority,
        cx,
        scalar,
        work,
        framing,
        &mut |_| true,
    )
}

/// The same native operation with an explicit retained-import checkpoint for a presentation or
/// recovery owner. The observer sees only a verified native receipt. It runs before inference,
/// under current authority on both sides; refusing stops without undoing its durable import.
/// Accepting a receipt grants no authority and is not proof of externally durable output.
#[allow(clippy::too_many_arguments)]
pub fn process_http_prefix_sentinel_observed<'cx>(
    archive: &LocalRootPublisher,
    destination: &mut ReferenceDeployment,
    package: &RgbDetectorPackage,
    package_bytes: &[u8],
    plan: &HttpPrefixSentinelPlan,
    limits: &LongSentinelLimits,
    authority: &dyn HttpPrefixSentinelAuthority,
    cx: &ReplayCx,
    scalar: &ScalarExecCx,
    work: &mut WorkBudget<'cx>,
    framing: &mut DecodeBudget<'cx>,
    observer: &mut dyn FnMut(&HttpImportReceipt) -> bool,
) -> Result<HttpPrefixSentinelReport> {
    let plan_digest = plan.digest(limits)?;
    check(authority, plan, destination, cx, scalar)?;
    if cx.root_dir() != destination.root()
        || archive.root_dir().starts_with(destination.root())
        || destination.root().starts_with(archive.root_dir())
        || package_bytes.len() > MAX_RGB_PACKAGE_BYTES
        || ContentDigest::sha256(package_bytes) != plan.package_digest
        || package.archive_digest() != plan.package_digest
        || package.model().backend() != plan.backend
    {
        return Err(HttpPrefixSentinelError::Invalid(
            "exact storage, package or backend binding",
        ));
    }
    if let Some(score) = plan.minimum_score_ppm {
        package
            .contract_with_threshold(score)
            .map_err(|_| HttpPrefixSentinelError::Invalid("threshold contract"))?;
    }
    cx.checkpoint(STAGE_HTTP_PREFIX_SENTINEL_PREFLIGHT)
        .map_err(|_| HttpPrefixSentinelError::Denied)?;
    verify_originals(
        archive,
        &SourceAccess {
            authority,
            plan,
            destination,
            cx,
            scalar,
        },
        work,
    )?;
    cx.checkpoint(STAGE_HTTP_PREFIX_SENTINEL_IMPORT)
        .map_err(|_| HttpPrefixSentinelError::Denied)?;
    check(authority, plan, destination, cx, scalar)?;
    let import = super::http_import::import_http(
        archive,
        destination,
        &plan.import,
        &Permit {
            authority,
            plan,
            scalar,
        },
        cx,
        work,
        framing,
    )?;
    let read_ahead = import.frames.checked_sub(plan.acknowledged_frames).ok_or(
        HttpPrefixSentinelError::Invalid("acknowledged frames exceed complete original parts"),
    )?;
    let basis = destination.current_anchor().clone();
    cx.checkpoint(STAGE_HTTP_PREFIX_SENTINEL_PROGRESS)
        .map_err(|_| HttpPrefixSentinelError::Denied)?;
    check(authority, plan, destination, cx, scalar)?;
    let accepted = observer(&import);
    check(authority, plan, destination, cx, scalar)?;
    if !accepted {
        return Err(HttpPrefixSentinelError::ProgressRefused);
    }
    cx.checkpoint(STAGE_HTTP_PREFIX_SENTINEL_ANALYZE)
        .map_err(|_| HttpPrefixSentinelError::Denied)?;
    check(authority, plan, destination, cx, scalar)?;
    let sentinel = run_long_sentinel_detection(
        destination,
        package,
        &LongSentinelRequest {
            import_identity: import.import_identity,
            first_segment: 0,
            segment_count: plan.acknowledged_frames,
            interpretation: plan.interpretation,
            minimum_score_ppm: plan.minimum_score_ppm,
        },
        plan.sampling,
        limits,
        cx,
        scalar,
    )?;
    let retained = if plan.retain {
        cx.checkpoint(STAGE_HTTP_PREFIX_SENTINEL_RETAIN)
            .map_err(|_| HttpPrefixSentinelError::Denied)?;
        check(authority, plan, destination, cx, scalar)?;
        Some(retain_long_sentinel_detection(
            destination,
            package,
            package_bytes,
            &sentinel,
            cx,
        )?)
    } else {
        None
    };
    cx.checkpoint(STAGE_HTTP_PREFIX_SENTINEL_REVALIDATE)
        .map_err(|_| HttpPrefixSentinelError::Denied)?;
    check(authority, plan, destination, cx, scalar)?;
    verify_originals(
        archive,
        &SourceAccess {
            authority,
            plan,
            destination,
            cx,
            scalar,
        },
        work,
    )?;
    let source =
        RetainedFileImport::open(destination, import.import_identity, limits.package.read, cx)
            .map_err(HttpImportError::from)?;
    if source.import_root() != import.import_root
        || source.manifest_digest() != import.manifest_digest
        || source.manifest().segment_spans.len() != import.frames
    {
        return Err(HttpPrefixSentinelError::Invalid(
            "current retained import binding",
        ));
    }
    charge(
        work,
        source
            .manifest()
            .input_bytes
            .checked_add(plan.import.pin.bytes)
            .ok_or(HttpPrefixSentinelError::Limit)?,
    )?;
    for segment in 0..import.frames {
        check(authority, plan, destination, cx, scalar)?;
        charge(work, 1)?;
        let (capsule, _) =
            source_capsule(destination, &source, segment).map_err(frame_error(segment))?;
        if capsule.sensor_id != plan.import.sensor || capsule.stream_id != plan.import.stream {
            return Err(HttpPrefixSentinelError::Invalid(
                "current source capsule binding",
            ));
        }
    }
    source
        .verify_source(destination, limits.package.read, cx)
        .map_err(HttpImportError::from)?;
    let mask = current_mask(destination, &plan.import.sensor).map_err(frame_error(0))?;
    if sentinel.reports().iter().any(|child| child.privacy != mask) {
        return Err(HttpPrefixSentinelError::Invalid(
            "current privacy differs from native inference binding",
        ));
    }
    cx.checkpoint(STAGE_HTTP_PREFIX_SENTINEL_RELEASE)
        .map_err(|_| HttpPrefixSentinelError::Denied)?;
    check(authority, plan, destination, cx, scalar)?;
    Ok(HttpPrefixSentinelReport {
        plan_digest,
        import,
        acknowledged_frames: plan.acknowledged_frames,
        read_ahead,
        sentinel,
        retained,
        basis,
    })
}

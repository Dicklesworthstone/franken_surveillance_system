#![forbid(unsafe_code)]
//! Measured frozen-pose residuals from one exact retained exposure, never automatic activation.
//!
//! Native replay owns pixels, privacy, feature extraction and atlas custody. The original
//! hash-pinned calibration input supplies the legacy image basis. The existing twin monitor
//! rematches those actual extracted features against the frozen adopted pose; it never uses the
//! query's fitted pose as its baseline. Passing says only that this recorded exposure passed
//! this policy. It does not establish present-day or continuous camera validity. Historical replay
//! checks adoption at the exact monitor publication prefix; later owner withdrawal or recovery
//! remains intact, while current source and privacy custody still govern access.

mod recipe;
use super::calibration_adoption::{
    AdoptionError, RetainedAdoption, adopted_currency, retained_adoptions,
    retained_adoptions_from_batches,
};
use super::recorded_decode::video_budget::RecordedVideoDecodeBudget;
use super::recorded_decode::{DecodeBudget, RecordedDecodeError, retained_source_capsule};
use super::site_calibration::{
    CalibrationImageBasis, MAX_CALIBRATION_BYTES, MAX_OBSERVATION_BYTES, SiteCalibration,
    SiteCalibrationError,
};
use super::twin_localization::retained::RetainedLocalization;
use super::twin_localization::{
    RecordedImageMode, RecordedLocalizationBinding, RecordedLocalizationError,
    RecordedLocalizationSource,
};
use super::{RetainedFileImport, RetainedReadLimits};
use crate::{ReferenceDeployment, ReferenceError, ReplayCx};
use fss_core::{
    CanonicalEncode, CanonicalEncoder, CaptureInterval, ContentDigest, ContractError,
    DigestAlgorithm, LedgerAnchor, Plane, SensorId,
};
use fss_geometry::{GeometryBasis, GeometryError, WorkBudget};
use fss_object::ObjectManifest;
use fss_publication::{LocalPublicationState, SlotName};
use fss_twin::calibration_monitor::{
    CalibrationDisposition, CalibrationMonitorError, CalibrationMonitorPolicy,
    CalibrationMonitorReport, FrozenCalibration, monitor_calibration,
};
use fss_twin::localization::LocalizationCamera;
use recipe::Recipe;
pub use recipe::{MAX_MONITOR_RECIPE_BYTES, MONITOR_APPROVAL_DOMAIN, MONITOR_PACKAGE_DOMAIN};
use std::fmt;

/// Canonical measured-observation domain, distinct from owner withdrawal authority.
pub const MONITOR_RECEIPT_DOMAIN: &str = "fss.recorded_calibration_monitor_receipt.v1";
/// Deployment and restore domain for independent observation approval.
pub const MONITOR_SCOPE_DOMAIN: &str = "fss.recorded_calibration_monitor_scope.v1";
/// Fixed policy identity. Defaults or operator-adjusted thresholds cannot silently change a receipt.
pub const MONITOR_POLICY: &str = "fss.recorded_calibration_monitor_policy.v1:frozen-pinhole:inlier-3px:rms-1.5px:support-8:fraction-0.7:span-0.08:single-retained-exposure";
/// Complete observation receipt ceiling, including every bounded matched landmark residual.
pub const MAX_MONITOR_RECEIPT_BYTES: usize = 128 * 1024;
/// Exact scope of a passing or contradicting result.
pub const MONITOR_CLAIM: &str =
    "measured_residuals_for_one_retained_exposure_not_continuous_camera_validity";

/// Explicit source and calibration pins. Original camera input is already hashed by the
/// existing v1/v2 calibration, so no legacy record needs a new wire format.
#[derive(Clone, Copy, Debug)]
pub struct MonitorRequest<'a> {
    /// Complete existing canonical SiteCalibration v1/v2 bytes.
    pub calibration_bytes: &'a [u8],
    /// The calibration's semantic identity, verified before source replay.
    pub calibration_digest: ContentDigest,
    /// Explicit camera handle in the calibration and current adoption.
    pub camera_handle: u64,
    /// Exact current, unwithdrawn adoption receipt.
    pub adoption_digest: ContentDigest,
    /// Original hash-pinned observation text or JPEG metadata.
    pub camera_input: &'a [u8],
    /// Complete retained native localization recipe identity.
    pub localization_identity: ContentDigest,
    /// Independently supplied expected localization publication root.
    pub localization_root: ContentDigest,
    /// Independently supplied expected native localization receipt.
    pub localization_receipt: ContentDigest,
}

/// Explicit retention state; a measured contradiction does not itself withdraw owner authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MonitorStatus {
    /// Measured read-only preview; no observation is retained.
    Proposed,
    /// This call published the approved observation and replay graph.
    Retained,
    /// An exact durable observation already exists and was verified without a new append.
    AlreadyRetained,
    /// The retained complete observation was reproduced against its historical adoption prefix.
    Replayed,
}
impl MonitorStatus {
    /// Stable report token.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Retained => "retained",
            Self::AlreadyRetained => "already_retained",
            Self::Replayed => "replayed",
        }
    }
}

/// Refusals preserve unavailable evidence as a refusal, never a passing calibration check.
#[derive(Debug)]
pub enum MonitorError {
    /// Invalid bounds, zero pins or malformed explicit request.
    InvalidInput(&'static str),
    /// Source, original camera, image, native descriptor or map basis differs.
    BasisMismatch(&'static str),
    /// Monitoring reuses the exact original calibration exposure or pixels.
    FitExposure,
    /// Supplied approval does not name the recomputed measured observation.
    StaleApproval(ContentDigest),
    /// Retained replay graph, manifest or authority reachability is missing or inconsistent.
    Custody(&'static str),
    /// Actual native replay differs from the retained complete observation.
    ReplayDiverged,
    /// Caller cancellation occurred before completion.
    Cancelled,
    /// Exact adoption at the required current or historical prefix is absent, stale, withdrawn or another sensor.
    Adoption(Box<AdoptionError>),
    /// Existing calibration or original input cannot be validated as requested.
    Calibration(SiteCalibrationError),
    /// Existing retained native localization owner refused source/replay work.
    Localization(RecordedLocalizationError),
    /// Frozen-pose matching or residual assessment refused.
    Monitor(CalibrationMonitorError),
    /// Native geometry or work allowance refused.
    Geometry(GeometryError),
    /// Canonical replay recipe is invalid.
    Contract(ContractError),
    /// Deployment publication refused.
    Reference(Box<ReferenceError>),
}
impl MonitorError {
    /// Existing stable calibration refusal, preserving nested source and adoption identities.
    pub fn stable_id(&self) -> &'static str {
        match self {
            Self::Localization(e) => e.stable_id(),
            Self::Adoption(e) => e.stable_id(),
            _ => "ERR-CALIBRATION-INVALID-001",
        }
    }
}
impl fmt::Display for MonitorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(s) => write!(f, "invalid calibration monitoring request: {s}"),
            Self::BasisMismatch(s) => write!(f, "calibration monitor basis mismatch: {s}"),
            Self::FitExposure => f.write_str(
                "calibration monitor reuses the original calibration exposure or pixels",
            ),
            Self::StaleApproval(d) => write!(
                f,
                "calibration monitoring approval {d} does not match this exact observed receipt"
            ),
            Self::Custody(s) => write!(f, "calibration monitor custody: {s}"),
            Self::ReplayDiverged => f.write_str(
                "calibration monitor native replay differs from the retained observation",
            ),
            Self::Cancelled => f.write_str("calibration monitoring cancelled"),
            Self::Adoption(e) => write!(f, "{e}"),
            Self::Calibration(e) => write!(f, "{e}"),
            Self::Localization(e) => write!(f, "{e}"),
            Self::Monitor(e) => write!(f, "{e}"),
            Self::Geometry(e) => write!(f, "{e}"),
            Self::Contract(e) => write!(f, "{e}"),
            Self::Reference(e) => write!(f, "{e}"),
        }
    }
}
impl std::error::Error for MonitorError {}
impl From<ContractError> for MonitorError {
    fn from(e: ContractError) -> Self {
        Self::Contract(e)
    }
}
impl From<GeometryError> for MonitorError {
    fn from(e: GeometryError) -> Self {
        Self::Geometry(e)
    }
}
impl From<CalibrationMonitorError> for MonitorError {
    fn from(e: CalibrationMonitorError) -> Self {
        Self::Monitor(e)
    }
}
impl From<RecordedLocalizationError> for MonitorError {
    fn from(e: RecordedLocalizationError) -> Self {
        Self::Localization(e)
    }
}
impl From<SiteCalibrationError> for MonitorError {
    fn from(e: SiteCalibrationError) -> Self {
        Self::Calibration(e)
    }
}
impl From<AdoptionError> for MonitorError {
    fn from(e: AdoptionError) -> Self {
        Self::Adoption(Box::new(e))
    }
}
impl From<ReferenceError> for MonitorError {
    fn from(e: ReferenceError) -> Self {
        Self::Reference(Box::new(e))
    }
}
type Result<T> = std::result::Result<T, MonitorError>;

fn policy() -> CalibrationMonitorPolicy {
    CalibrationMonitorPolicy {
        inlier_threshold_px: 3.0,
        maximum_rms_px: 1.5,
        minimum_support: 8,
        minimum_inlier_fraction: 0.7,
        minimum_image_span: 0.08,
    }
}
fn checkpoint(cx: &ReplayCx, stage: &'static str) -> Result<()> {
    cx.checkpoint(stage).map_err(|_| MonitorError::Cancelled)
}
fn sha(bytes: [u8; 32]) -> ContentDigest {
    ContentDigest::new(DigestAlgorithm::Sha256, bytes)
}
fn checked(digest: ContentDigest) -> Result<()> {
    if digest.algorithm() != DigestAlgorithm::Sha256 || digest.bytes() == [0; 32] {
        return Err(MonitorError::InvalidInput("nonzero SHA-256 pins required"));
    }
    Ok(())
}
fn scope(deployment: &ReferenceDeployment) -> ContentDigest {
    let mut e = CanonicalEncoder::new();
    e.text(MONITOR_SCOPE_DOMAIN);
    e.text(&deployment.current_anchor().site_lineage);
    e.u64(deployment.current_anchor().ledger_epoch);
    ContentDigest::sha256(&e.finish())
}
/// A historical check is reachable only after verifying the retained monitor publication.
/// It changes admission of historical replay, never the canonical observation or adoption state.
#[derive(Clone, Debug)]
enum AdoptionCheck {
    Current,
    PublishedPrefix {
        batch_count: usize,
        anchor: LedgerAnchor,
    },
}

fn checked_adoption(
    deployment: &ReferenceDeployment,
    request: &MonitorRequest<'_>,
    calibration: &SiteCalibration,
    sensor: &SensorId,
    check: &AdoptionCheck,
) -> Result<RetainedAdoption> {
    let camera = calibration
        .cameras
        .iter()
        .find(|camera| camera.identity.camera == request.camera_handle)
        .ok_or(MonitorError::InvalidInput(
            "calibration has no requested camera",
        ))?;
    let history =
        match check {
            AdoptionCheck::Current => retained_adoptions(deployment)?,
            AdoptionCheck::PublishedPrefix {
                batch_count,
                anchor,
            } => {
                let prefix = deployment.ledger().batches().get(..*batch_count).ok_or(
                    MonitorError::Custody("monitor publication prefix unavailable"),
                )?;
                if prefix.last().map(|batch| &batch.new_anchor) != Some(anchor) {
                    return Err(MonitorError::Custody(
                        "monitor publication prefix anchor differs",
                    ));
                }
                retained_adoptions_from_batches(prefix, |digest, maximum| {
                    deployment
                        .publisher()
                        .spool()
                        .read_bounded(digest, maximum)
                        .map_err(|_| {
                            AdoptionError::InvalidRecord(
                                "historical calibration authority receipt unreadable",
                            )
                        })
                })?
            }
        };
    let current = adopted_currency(
        &history,
        request.calibration_digest,
        &camera.name,
        camera.identity,
        || Ok(sensor.clone()),
    )?
    .ok_or(MonitorError::BasisMismatch(
        "monitoring requires the exact retained adoption",
    ))?;
    if current.digest != request.adoption_digest
        || current.receipt.twin_package != calibration.twin_package
        || current.receipt.camera_name != camera.name
    {
        return Err(MonitorError::BasisMismatch(
            "adoption at the checked prefix or twin differs from the requested baseline",
        ));
    }
    Ok(current)
}

/// Immutable measured observation; raw query pixels and descriptors are not disclosed in reports.
#[derive(Debug)]
pub struct RecordedCalibrationMonitor {
    recipe: Recipe,
    source: RecordedLocalizationBinding,
    sensor: SensorId,
    capture: CaptureInterval,
    camera_name: String,
    input_kind: &'static str,
    result: CalibrationMonitorReport,
    encoded: Vec<u8>,
    geometry_work: u64,
    status: MonitorStatus,
    adoption_check: AdoptionCheck,
}
impl RecordedCalibrationMonitor {
    /// Canonical measured-observation receipt identity.
    pub fn digest(&self) -> ContentDigest {
        self.recipe.receipt
    }
    /// Exact canonical measured-observation bytes.
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }
    /// Exact explicit approval for derived publication only.
    pub fn approval(&self) -> ContentDigest {
        recipe::approval(self.digest())
    }
    /// Immutable replay recipe identity and source of the monitor slot name.
    pub fn identity(&self) -> ContentDigest {
        self.recipe.identity()
    }
    /// Expected complete replay graph root, also available before retention.
    pub fn publication_root(&self) -> Result<ContentDigest> {
        Ok(manifest(&self.recipe)?.root())
    }
    /// Original verified source, exposure and current privacy binding.
    pub fn source(&self) -> &RecordedLocalizationBinding {
        &self.source
    }
    /// Actual frozen-pose residuals and support computed by the native monitor.
    pub fn result(&self) -> &CalibrationMonitorReport {
        &self.result
    }
    /// Preview, retention or native replay state.
    pub fn status(&self) -> MonitorStatus {
        self.status
    }
    /// Bounded single-exposure outcome; never a continuing camera-validity lease.
    pub fn outcome(&self) -> &'static str {
        match self.result.disposition {
            CalibrationDisposition::ValidUnderPolicy => "pass_under_policy",
            CalibrationDisposition::Invalidate => "contradicted",
            CalibrationDisposition::Indeterminate => "indeterminate",
        }
    }
    /// Deterministic metadata/residual projection without source pixels or descriptors.
    pub fn to_json(&self) -> Result<String> {
        let (adoption_basis, adoption_sequence, adoption_root) = match &self.adoption_check {
            AdoptionCheck::Current => ("current", "null".to_owned(), "null".to_owned()),
            AdoptionCheck::PublishedPrefix { anchor, .. } => (
                "monitor_publication_prefix",
                anchor.commit_sequence.to_string(),
                format!("\"{}\"", anchor.state_root),
            ),
        };
        let optional =
            |value: Option<f64>| value.map_or_else(|| "null".to_owned(), |n| n.to_string());
        let residuals: Vec<_> = self
            .result
            .residuals
            .iter()
            .map(|r| {
                format!(
                    "{{\"landmark\":{},\"error_px\":{},\"in_image\":{},\"inlier\":{}}}",
                    r.landmark,
                    optional(r.error_px),
                    r.in_image,
                    r.inlier
                )
            })
            .collect();
        let recommendation = if self.result.disposition == CalibrationDisposition::Invalidate
            && matches!(&self.adoption_check, AdoptionCheck::Current)
        {
            format!(
                "{{\"action\":\"preview_owner_withdrawal\",\"camera_handle\":{},\"adoption_digest\":\"{}\",\"reason\":\"residual_drift\",\"evidence\":\"{}\"}}",
                self.recipe.camera_handle, self.recipe.adoption, self.source.capsule
            )
        } else {
            "null".to_owned()
        };
        Ok(format!(
            concat!(
                "{{\"format\":\"fss.calibration_monitor_report.v1\",\"status\":\"{}\",\"outcome\":\"{}\",",
                "\"adoption_check\":\"{}\",\"adoption_basis_sequence\":{},\"adoption_basis_state_root\":{},",
                "\"receipt_digest\":\"{}\",\"approval_digest\":\"{}\",\"monitor_identity\":\"{}\",\"monitor_root\":\"{}\",",
                "\"camera_handle\":{},\"camera_name\":\"{}\",\"sensor_id\":\"{}\",\"calibration_digest\":\"{}\",\"adoption_digest\":\"{}\",",
                "\"calibration_input_kind\":\"{}\",\"camera_input_digest\":\"{}\",\"localization_identity\":\"{}\",\"localization_root\":\"{}\",",
                "\"localization_receipt\":\"{}\",\"twin_digest\":\"{}\",\"atlas_digest\":\"{}\",\"image_domain\":\"{}\",\"query_pixels\":\"{}\",\"image_dimensions\":{:?},",
                "\"capsule\":\"{}\",\"exposure\":\"{}\",\"decoded_luma\":\"{}\",\"privacy_mask_binding\":\"{}\",",
                "\"capture_earliest_ns\":\"{}\",\"capture_latest_ns\":\"{}\",\"matched_landmarks\":{},\"projected\":{},\"inliers\":{},",
                "\"rms_inlier_px\":{},\"maximum_inlier_error_px\":{},\"image_span_fraction\":{:?},\"residuals\":[{}],",
                "\"geometry_work_units\":{},\"policy\":\"{}\",\"claim\":\"{}\",\"calibration_activated\":false,\"adoption_invalidated\":false,\"recommendation\":{}}}"
            ),
            self.status.as_str(),
            self.outcome(),
            adoption_basis,
            adoption_sequence,
            adoption_root,
            self.digest(),
            self.approval(),
            self.identity(),
            self.publication_root()?,
            self.recipe.camera_handle,
            self.camera_name,
            self.sensor,
            self.recipe.calibration_identity,
            self.recipe.adoption,
            self.input_kind,
            self.recipe.camera_input,
            self.recipe.localization,
            self.recipe.localization_root,
            self.recipe.localization_receipt,
            sha(self.result.twin_digest),
            sha(self.result.atlas_digest),
            sha(self.result.matches.query.image_domain),
            sha(self.result.matches.query.pixels),
            self.result.matches.query.dimensions,
            self.source.capsule,
            self.source.exposure,
            self.source.luma,
            self.source.mask_binding,
            self.capture.earliest.0,
            self.capture.latest.0,
            self.result.matches.correspondences.len(),
            self.result.projected,
            self.result.inliers,
            optional(self.result.rms_inlier_px),
            optional(self.result.maximum_inlier_error_px),
            self.result.image_span_fraction,
            residuals.join(","),
            self.geometry_work,
            MONITOR_POLICY,
            MONITOR_CLAIM,
            recommendation
        ))
    }
}

fn encode_observation(
    deployment: &ReferenceDeployment,
    request: &MonitorRequest<'_>,
    basis: CalibrationImageBasis,
    source: &RecordedLocalizationBinding,
    capsule: &fss_core::SensorCapsule,
    result: &CalibrationMonitorReport,
    work: u64,
) -> Result<Vec<u8>> {
    if result.matches.correspondences.len() > 512 || result.residuals.len() > 512 {
        return Err(MonitorError::InvalidInput(
            "monitor output exceeds its bound",
        ));
    }
    if result
        .image_span_fraction
        .iter()
        .copied()
        .chain(result.rms_inlier_px)
        .chain(result.maximum_inlier_error_px)
        .chain(result.residuals.iter().filter_map(|r| r.error_px))
        .any(|value| !value.is_finite() || value < 0.0)
    {
        return Err(MonitorError::BasisMismatch(
            "non-finite frozen-pose residual",
        ));
    }
    let mut e = CanonicalEncoder::new();
    e.text(MONITOR_RECEIPT_DOMAIN);
    e.text(MONITOR_POLICY);
    e.text(MONITOR_CLAIM);
    e.digest(scope(deployment));
    for d in [
        request.calibration_digest,
        ContentDigest::sha256(request.calibration_bytes),
        request.adoption_digest,
        basis.input_digest,
        request.localization_identity,
        request.localization_root,
        request.localization_receipt,
        source.import_identity,
        source.import_root,
        source.manifest,
        source.capsule,
        source.encoded_source,
        source.exposure,
        source.luma,
        source.decode_receipt,
        source.mask_binding,
    ] {
        e.digest(d);
    }
    e.u64(request.camera_handle);
    capsule.sensor_id.encode_canonical(&mut e);
    capsule.capture.encode_canonical(&mut e);
    e.text(capsule.clock_basis.as_str());
    source.source_anchor.encode_canonical(&mut e);
    e.bool(source.mask_policy.is_some());
    if let Some(mask) = source.mask_policy {
        e.digest(mask);
    }
    e.u64(source.segment);
    e.u64(source.range_start);
    e.u64(source.range_count);
    e.text(source.codec);
    for image in [basis.image, result.matches.query] {
        e.digest(sha(image.exposure));
        e.digest(sha(image.pixels));
        e.digest(sha(image.image_domain));
        for n in image.dimensions {
            e.u32(n);
        }
    }
    e.digest(sha(result.twin_digest));
    e.digest(sha(result.atlas_digest));
    let p = policy();
    for n in [
        p.inlier_threshold_px,
        p.maximum_rms_px,
        p.minimum_inlier_fraction,
        p.minimum_image_span,
    ] {
        e.u64(n.to_bits());
    }
    e.u64(p.minimum_support as u64);
    e.u8(match result.disposition {
        CalibrationDisposition::ValidUnderPolicy => 0,
        CalibrationDisposition::Invalidate => 1,
        CalibrationDisposition::Indeterminate => 2,
    });
    for n in [
        result.matches.correspondences.len(),
        result.projected,
        result.inliers,
    ] {
        e.u64(n as u64);
    }
    for value in [result.rms_inlier_px, result.maximum_inlier_error_px] {
        e.bool(value.is_some());
        if let Some(value) = value {
            e.u64(value.to_bits());
        }
    }
    for value in result.image_span_fraction {
        e.u64(value.to_bits());
    }
    e.u64(result.residuals.len() as u64);
    for r in &result.residuals {
        e.u64(r.landmark);
        e.bool(r.error_px.is_some());
        if let Some(error) = r.error_px {
            e.u64(error.to_bits());
        }
        e.bool(r.in_image);
        e.bool(r.inlier);
    }
    e.u64(work);
    let bytes = e.finish();
    if bytes.len() > MAX_MONITOR_RECEIPT_BYTES {
        return Err(MonitorError::InvalidInput(
            "monitor receipt exceeds its bound",
        ));
    }
    Ok(bytes)
}

/// Re-run exact retained native perception against the current unwithdrawn frozen adoption.
/// No source, calibration, monitor object or authority is staged by a preview, including refusals.
pub fn preview_monitor(
    deployment: &mut ReferenceDeployment,
    request: &MonitorRequest<'_>,
    jpeg: &mut DecodeBudget<'_>,
    video: &mut RecordedVideoDecodeBudget,
    geometry: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<RecordedCalibrationMonitor> {
    observe(
        deployment,
        request,
        AdoptionCheck::Current,
        jpeg,
        video,
        geometry,
        cx,
    )
}

fn observe(
    deployment: &mut ReferenceDeployment,
    request: &MonitorRequest<'_>,
    adoption_check: AdoptionCheck,
    jpeg: &mut DecodeBudget<'_>,
    video: &mut RecordedVideoDecodeBudget,
    geometry: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<RecordedCalibrationMonitor> {
    checkpoint(cx, "calibration_monitor:begin")?;
    let work_start = geometry.used();
    if request.camera_handle == 0
        || request.calibration_bytes.len() > MAX_CALIBRATION_BYTES
        || request.camera_input.len() > MAX_OBSERVATION_BYTES
    {
        return Err(MonitorError::InvalidInput("camera or input byte bound"));
    }
    for d in [
        request.calibration_digest,
        request.adoption_digest,
        request.localization_identity,
        request.localization_root,
        request.localization_receipt,
    ] {
        checked(d)?;
    }
    geometry.charge(
        (request.calibration_bytes.len() + request.camera_input.len() + MAX_MONITOR_RECEIPT_BYTES)
            as u64,
    )?;
    let (calibration, identity) =
        SiteCalibration::decode(request.calibration_bytes, Some(request.calibration_digest))?;
    if identity != request.calibration_digest {
        return Err(MonitorError::BasisMismatch("calibration identity"));
    }
    let original = calibration.camera_input_basis(request.camera_handle, request.camera_input)?;
    let camera = calibration
        .cameras
        .iter()
        .find(|c| c.identity.camera == request.camera_handle)
        .ok_or(MonitorError::InvalidInput("unknown camera"))?;
    let frozen_pose = camera.pinhole_pose()?;
    let package = RetainedLocalization::open(
        deployment,
        request.localization_identity,
        RetainedReadLimits::default(),
        geometry,
        cx,
    )?;
    if package.publication_root() != request.localization_root
        || package.receipt_digest() != request.localization_receipt
        || package.twin_digest() != calibration.twin_package
        || package.atlas_package() != calibration.atlas_package
    {
        return Err(MonitorError::BasisMismatch(
            "localization root, receipt, twin or atlas package",
        ));
    }
    let interpretation = match package.source() {
        RecordedLocalizationSource::Jpeg(request) => request.interpretation,
        RecordedLocalizationSource::H264 { request, .. } => request.interpretation,
        RecordedLocalizationSource::H265 { request, .. } => request.interpretation,
    };
    if original
        .interpretation
        .is_some_and(|expected| expected != interpretation)
    {
        return Err(MonitorError::BasisMismatch(
            "original calibration component interpretation",
        ));
    }
    let source = RetainedFileImport::open(
        deployment,
        package.source().import_identity(),
        RetainedReadLimits::default(),
        cx,
    )
    .map_err(|e| MonitorError::Localization(RecordedDecodeError::from(e).into()))?;
    let capsule = retained_source_capsule(deployment, &source, package.source().segment())
        .map_err(|e| MonitorError::Localization(e.into()))?;
    checked_adoption(
        deployment,
        request,
        &calibration,
        &capsule.sensor_id,
        &adoption_check,
    )?;
    let replay = package.replay_context(
        deployment,
        GeometryBasis::new(1, 1)?,
        jpeg,
        video,
        geometry,
        cx,
    )?;
    let image_camera = match replay.image {
        RecordedImageMode::Pinhole(camera) => camera.intrinsics,
        RecordedImageMode::Raw(spec) => spec.target,
    };
    if image_camera != frozen_pose.intrinsics
        || replay.twin.source_scene_digest() != calibration.twin_source.bytes()
        || replay.atlas.atlas().digest() != calibration.atlas_fingerprint
        || replay.atlas.provenance() != calibration.atlas_provenance.bytes()
        || replay.result.result().query_features().descriptor_domain()
            != calibration.descriptor_domain
        || replay.capsule != capsule
    {
        return Err(MonitorError::BasisMismatch(
            "native replay image model, source or atlas provenance",
        ));
    }
    let query = replay.result.result().query_features();
    if query.identity().dimensions != original.image.dimensions
        || query.identity().image_domain != original.image.image_domain
    {
        return Err(MonitorError::BasisMismatch(
            "original calibration image domain or pixel grid",
        ));
    }
    let binding = replay.result.source();
    if query.identity().exposure == original.image.exposure
        || query.identity().pixels == original.image.pixels
        || binding.luma.bytes() == original.image.pixels
        || original.encoded_frame == Some(binding.encoded_source)
    {
        return Err(MonitorError::FitExposure);
    }
    if replay.atlas.atlas().references().iter().any(|reference| {
        let image = reference.frame.identity();
        image.exposure == query.identity().exposure
            || image.pixels == query.identity().pixels
            || image.pixels == binding.luma.bytes()
    }) {
        return Err(MonitorError::BasisMismatch(
            "monitor reuses atlas reference exposure or pixels",
        ));
    }
    let result = monitor_calibration(
        &replay.twin,
        replay.atlas.atlas(),
        query,
        FrozenCalibration {
            id: request.calibration_digest.bytes(),
            camera: LocalizationCamera {
                intrinsics: frozen_pose.intrinsics,
                image_domain: original.image.image_domain,
            },
            pose: frozen_pose.pose,
        },
        replay.options.matching,
        policy(),
        geometry,
    )?;
    geometry.charge(0)?;
    checkpoint(cx, "calibration_monitor:observed")?;
    checked_adoption(
        deployment,
        request,
        &calibration,
        &capsule.sensor_id,
        &adoption_check,
    )?;
    let work = geometry.used() - work_start;
    let encoded = encode_observation(
        deployment, request, original, binding, &capsule, &result, work,
    )?;
    let recipe = Recipe {
        calibration_object: ContentDigest::sha256(request.calibration_bytes),
        calibration_identity: request.calibration_digest,
        camera_input: ContentDigest::sha256(request.camera_input),
        camera_handle: request.camera_handle,
        adoption: request.adoption_digest,
        localization: request.localization_identity,
        localization_root: request.localization_root,
        localization_receipt: request.localization_receipt,
        receipt: ContentDigest::sha256(&encoded),
    };
    Ok(RecordedCalibrationMonitor {
        recipe,
        source: binding.clone(),
        sensor: capsule.sensor_id,
        capture: capsule.capture,
        camera_name: camera.name.clone(),
        input_kind: camera.input.as_str(),
        result,
        encoded,
        geometry_work: work,
        status: MonitorStatus::Proposed,
        adoption_check,
    })
}

fn slot(identity: ContentDigest) -> Result<SlotName> {
    checked(identity)?;
    SlotName::parse(&format!("calibration-monitor-{}", &identity.to_text()[7..]))
        .map_err(|_| MonitorError::Custody("invalid monitor slot"))
}
fn manifest(recipe: &Recipe) -> Result<ObjectManifest> {
    ObjectManifest::new(
        slot(recipe.identity())?.as_str(),
        vec![
            recipe.calibration_object,
            recipe.camera_input,
            recipe.localization_root,
            recipe.receipt,
            recipe::approval(recipe.receipt),
            recipe.adoption,
        ],
        Some(recipe.identity()),
    )
    .map_err(|_| MonitorError::Custody("invalid monitor object graph"))
}
fn read(
    deployment: &ReferenceDeployment,
    digest: ContentDigest,
    maximum: usize,
    geometry: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<Vec<u8>> {
    checkpoint(cx, "calibration_monitor:read")?;
    geometry.charge(maximum as u64)?;
    deployment
        .publisher()
        .spool()
        .read_bounded(digest, maximum)
        .map_err(|_| MonitorError::Custody("missing or corrupt monitor replay object"))
}
fn check_publication(
    deployment: &ReferenceDeployment,
    recipe: &Recipe,
    capture: Option<CaptureInterval>,
) -> Result<AdoptionCheck> {
    deployment.ledger().verify_durable_head().map_err(|_| {
        MonitorError::Custody("monitor publication history is not durably verified")
    })?;
    let slot = slot(recipe.identity())?;
    let expected = manifest(recipe)?;
    let publisher = deployment.publisher();
    let root = publisher
        .root(&slot)
        .ok_or(MonitorError::Custody("monitor root not published"))?;
    if root.state != LocalPublicationState::Durable || root.root != expected.root() {
        return Err(MonitorError::Custody(
            "monitor root is not exact and durable",
        ));
    }
    let object = format!("object:local-root:{}", slot.as_str());
    let (batch_index, batch, delta) = deployment
        .ledger()
        .batches()
        .iter()
        .enumerate()
        .rev()
        .find_map(|(index, b)| {
            b.deltas
                .iter()
                .find(|d| d.object_id.as_str() == object)
                .map(|d| (index, b, d))
        })
        .ok_or(MonitorError::Custody(
            "monitor root has no authority reachability",
        ))?;
    let mut closure: Vec<_> = publisher
        .root_closure(&slot)
        .ok_or(MonitorError::Custody("monitor closure unavailable"))?
        .into_iter()
        .filter(|d| *d != expected.root())
        .collect();
    closure.sort_unstable();
    if batch.batch_id.as_str() != format!("batch:local-root:{}", slot.as_str())
        || batch.deltas.len() != 1
        || delta.family != "local_root_reachability"
        || delta.delta_id != format!("delta:local-root:{}", slot.as_str())
        || delta.plane != Plane::Authority
        || delta.prior_generation.is_some()
        || delta.new_generation != 1
        || delta.payload_digest != expected.root()
        || delta.witness_digest.is_some()
        || delta.operation_id.is_some()
        || capture.is_some_and(|expected| delta.validity != expected)
        || batch.children != closure
    {
        return Err(MonitorError::Custody(
            "monitor root authority binding mismatch",
        ));
    }
    // Exclude this publication batch. Its sole delta is reachability, so the basis is exactly
    // the owner state against which this observation was admitted, without later withdrawals.
    Ok(AdoptionCheck::PublishedPrefix {
        batch_count: batch_index,
        anchor: batch.basis_anchor.clone(),
    })
}

/// Explicit approval retains only the measured observation and replay graph. It never consumes
/// a calibration withdrawal approval or changes which camera calibration is adopted.
pub fn retain_monitor(
    deployment: &mut ReferenceDeployment,
    request: &MonitorRequest<'_>,
    approval: ContentDigest,
    jpeg: &mut DecodeBudget<'_>,
    video: &mut RecordedVideoDecodeBudget,
    geometry: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<RecordedCalibrationMonitor> {
    let mut report = preview_monitor(deployment, request, jpeg, video, geometry, cx)?;
    if approval != report.approval() {
        return Err(MonitorError::StaleApproval(approval));
    }
    let recipe_bytes = report.recipe.encode();
    Recipe::decode(&recipe_bytes)?;
    let approved = recipe::approval_bytes(report.digest());
    let slot = slot(report.identity())?;
    let manifest = manifest(&report.recipe)?;
    let existing = deployment.publisher().root(&slot).map(|root| root.root);
    let was_retained = existing.is_some()
        && check_publication(deployment, &report.recipe, Some(report.capture)).is_ok();
    let payloads = [
        recipe_bytes.as_slice(),
        report.encoded.as_slice(),
        request.calibration_bytes,
        request.camera_input,
        approved.as_slice(),
    ];
    if let Some(root) = existing {
        if root != manifest.root() {
            return Err(MonitorError::Custody("existing monitor root differs"));
        }
        let manifest_bytes = manifest.canonical_bytes();
        if read(deployment, root, manifest_bytes.len(), geometry, cx)? != manifest_bytes {
            return Err(MonitorError::Custody("existing monitor manifest differs"));
        }
        for bytes in payloads {
            if read(
                deployment,
                ContentDigest::sha256(bytes),
                bytes.len(),
                geometry,
                cx,
            )? != bytes
            {
                return Err(MonitorError::Custody("existing monitor object differs"));
            }
        }
    } else {
        for bytes in payloads {
            checkpoint(cx, "calibration_monitor:stage")?;
            geometry.charge(bytes.len() as u64)?;
            let digest = deployment
                .publisher_mut()
                .stage_object(bytes)
                .map_err(|_| MonitorError::Custody("monitor staging failed"))?;
            deployment
                .publisher_mut()
                .verify_object(digest)
                .map_err(|_| MonitorError::Custody("monitor staging verification failed"))?;
        }
        deployment
            .publisher_mut()
            .stage_manifest(&slot, &manifest)
            .map_err(|_| MonitorError::Custody("monitor manifest staging failed"))?;
    }
    checkpoint(cx, "calibration_monitor:publish")?;
    geometry.charge(0)?;
    deployment.publish_and_commit(&slot, &manifest, report.capture, cx)?;
    cx.checkpoint_post_commit("calibration_monitor:retained");
    check_publication(deployment, &report.recipe, Some(report.capture))?;
    report.status = if was_retained {
        MonitorStatus::AlreadyRetained
    } else {
        MonitorStatus::Retained
    };
    Ok(report)
}

/// Rebuild a retained monitor from its original calibration/input bytes and exact localization
/// replay package. The exact adoption must have been current and unwithdrawn at the monitor's
/// verified publication prefix; a later withdrawal or replacement remains intact. Current source
/// and privacy custody still apply. Historical reproduction is no continuing validity lease.
/// Nothing is staged, repaired or appended by this replay.
pub fn replay_monitor(
    deployment: &mut ReferenceDeployment,
    identity: ContentDigest,
    expected_root: ContentDigest,
    expected_receipt: ContentDigest,
    jpeg: &mut DecodeBudget<'_>,
    video: &mut RecordedVideoDecodeBudget,
    geometry: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<RecordedCalibrationMonitor> {
    for pin in [identity, expected_root, expected_receipt] {
        checked(pin)?;
    }
    let encoded = read(deployment, identity, MAX_MONITOR_RECIPE_BYTES, geometry, cx)?;
    let recipe = Recipe::decode(&encoded)?;
    if recipe.identity() != identity
        || recipe.receipt != expected_receipt
        || manifest(&recipe)?.root() != expected_root
    {
        return Err(MonitorError::Custody(
            "monitor pins disagree with retained recipe",
        ));
    }
    let expected_manifest = manifest(&recipe)?.canonical_bytes();
    if read(
        deployment,
        expected_root,
        expected_manifest.len(),
        geometry,
        cx,
    )? != expected_manifest
    {
        return Err(MonitorError::Custody("retained monitor manifest differs"));
    }
    let calibration = read(
        deployment,
        recipe.calibration_object,
        MAX_CALIBRATION_BYTES,
        geometry,
        cx,
    )?;
    let input = read(
        deployment,
        recipe.camera_input,
        MAX_OBSERVATION_BYTES,
        geometry,
        cx,
    )?;
    let expected = read(
        deployment,
        recipe.receipt,
        MAX_MONITOR_RECEIPT_BYTES,
        geometry,
        cx,
    )?;
    let approved = read(
        deployment,
        recipe::approval(recipe.receipt),
        256,
        geometry,
        cx,
    )?;
    if approved != recipe::approval_bytes(recipe.receipt) {
        return Err(MonitorError::Custody("monitor review approval differs"));
    }
    let adoption_check = check_publication(deployment, &recipe, None)?;
    let request = MonitorRequest {
        calibration_bytes: &calibration,
        calibration_digest: recipe.calibration_identity,
        camera_handle: recipe.camera_handle,
        adoption_digest: recipe.adoption,
        camera_input: &input,
        localization_identity: recipe.localization,
        localization_root: recipe.localization_root,
        localization_receipt: recipe.localization_receipt,
    };
    let mut report = observe(
        deployment,
        &request,
        adoption_check,
        jpeg,
        video,
        geometry,
        cx,
    )?;
    check_publication(deployment, &recipe, Some(report.capture))?;
    if report.recipe != recipe || report.encoded != expected {
        return Err(MonitorError::ReplayDiverged);
    }
    report.status = MonitorStatus::Replayed;
    Ok(report)
}

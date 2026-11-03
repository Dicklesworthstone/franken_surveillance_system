#![forbid(unsafe_code)]
//! Source-bound camera-pose proposals from retained native decoded luma.
//!
//! This is the custody/privacy bridge to the existing twin localizer. It accepts an exact
//! completed recording, never caller-provided query pixels or matches. The current sensor
//! privacy policy excludes descriptor support, including rectification footprints. Results are
//! reproducible candidate receipts, not calibration certificates, coverage, or activation.

mod receipt;
pub mod retained;

use fss_core::{CanonicalEncode, CanonicalEncoder, ContentDigest, LedgerAnchor, SensorCapsule};
use fss_geometry::{GeometryError, WorkBudget};
use fss_twin::PropertyTwin;
use fss_twin::localization::native::{
    GrayImage, ImageLocalization, ImageLocalizationOptions, localize_gray_frame,
};
use fss_twin::localization::{
    ImageIdentity, LocalizationAtlas, LocalizationCamera, LocalizationError, LocalizationOutcome,
};
use fss_twin::rectification::{
    RawFrameIdentity, RawGrayFrame, RawLocalizationError, RectificationError, RectificationPlan,
    RectificationReceipt, RectificationSpec, localize_raw_frame,
};

use super::privacy_mask::{MaskBinding, PrivacyMaskError, current_mask};
use super::recorded_decode::h264::{RecordedH264Frame, RecordedH264Range, RecordedH264Request};
use super::recorded_decode::h265::{RecordedH265Frame, RecordedH265Range, RecordedH265Request};
use super::recorded_decode::video_budget::RecordedVideoDecodeBudget;
use super::recorded_decode::{
    DecodeBudget, RecordedDecodeError, RecordedDecodeRequest, RecordedFrame,
    retained_source_capsule,
};
use super::{RetainedFileImport, RetainedReadLimits};
use crate::{ReferenceDeployment, ReplayCx};

/// Canonical candidate receipt; this format carries no effect or calibration authority.
pub const RECEIPT_DOMAIN: &str = "fss.recorded_twin_localization_receipt.v1";
/// Source exposure identity, independent of decoding, privacy policy and rectification.
pub const EXPOSURE_DOMAIN: &str = "fss.recorded_twin_localization_exposure.v1";
/// Stable refusal identity; nested source/privacy refusals retain their existing identities.
pub const ERR_RECORDED_LOCALIZATION_REFUSED: &str = "ERR-RECORDED-LOCALIZATION-REFUSED-001";
/// Boundary before any source work.
pub const STAGE_LOCALIZATION_SOURCE: &str = "recorded_localization:source";
/// Boundary before returning a complete candidate receipt, after revalidating current custody.
pub const STAGE_LOCALIZATION_COMPLETE: &str = "recorded_localization:complete";
/// Bound for a complete candidate receipt, including all descriptor decisions and poses.
pub const MAX_RECEIPT_BYTES: usize = 256 * 1024;

type Result<T> = std::result::Result<T, RecordedLocalizationError>;

/// Exact retained source selection. Video selection is by original coding segment, even when
/// the codec emits pictures in display order. The entire requested range must succeed.
#[derive(Clone, Debug)]
pub enum RecordedLocalizationSource {
    /// One retained JPEG, decoded and retained through the canonical JPEG owner.
    Jpeg(RecordedDecodeRequest),
    /// A picture within an explicitly bounded IDR-starting AVC range.
    H264 {
        request: RecordedH264Request,
        segment: usize,
    },
    /// A picture within an explicitly bounded IRAP-starting HEVC range; skipped RASL is refused.
    H265 {
        request: RecordedH265Request,
        segment: usize,
    },
}
impl RecordedLocalizationSource {
    /// Completed source-import identity.
    pub fn import_identity(&self) -> ContentDigest {
        match self {
            Self::Jpeg(r) => r.import_identity,
            Self::H264 { request, .. } => request.import_identity,
            Self::H265 { request, .. } => request.import_identity,
        }
    }
    /// Original source segment to localize.
    pub fn segment(&self) -> usize {
        match self {
            Self::Jpeg(r) => r.segment_index,
            Self::H264 { segment, .. } | Self::H265 { segment, .. } => *segment,
        }
    }
    fn limits(&self) -> RetainedReadLimits {
        match self {
            Self::Jpeg(r) => r.read_limits,
            Self::H264 { request, .. } => request.read_limits,
            Self::H265 { request, .. } => request.read_limits,
        }
    }
    fn range(&self) -> (usize, usize) {
        match self {
            Self::Jpeg(r) => (r.segment_index, 1),
            Self::H264 { request, .. } => (request.first_segment, request.segment_count),
            Self::H265 { request, .. } => (request.first_segment, request.segment_count),
        }
    }
}

/// Explicit owner image interpretation. A raw lens model is never silently treated as pinhole.
#[derive(Clone, Copy, Debug)]
pub enum RecordedImageMode {
    /// Native luma is already on this exact undistorted pinhole image grid.
    Pinhole(LocalizationCamera),
    /// Native luma is rectified using this complete frozen model and declared sample range.
    Raw(RectificationSpec),
}

/// Exact immutable map, atlas, image mode and bounded localization policy.
#[derive(Clone, Copy, Debug)]
pub struct RecordedLocalizationPlan<'a> {
    /// Verified property revision. It must equal the atlas's original property binding.
    pub twin: &'a PropertyTwin,
    /// Verified native-descriptor atlas, including its original reference exposures.
    pub atlas: &'a LocalizationAtlas,
    /// Fixed owner-supplied image interpretation, not estimated from this query.
    pub image: RecordedImageMode,
    /// Exact extraction, matching and pose-search configuration, included in the receipt.
    pub options: ImageLocalizationOptions,
}

/// Non-disclosing typed failure; no refusal exposes a partial candidate or decoded image.
#[derive(Debug)]
pub enum RecordedLocalizationError {
    /// Invalid range, configuration, dimensions, or hard allocation/output limit.
    InvalidRequest,
    /// Current source, decode, pixel digest, or privacy identities disagree.
    SourceMismatch,
    /// The selected video segment did not yield an admitted output picture.
    NoSelectedPicture,
    /// Explicit context cancellation at a composition boundary.
    Cancelled,
    /// Exact retained source or native decoder refused the request.
    Decode(RecordedDecodeError),
    /// The current privacy policy could not be admitted.
    Privacy(PrivacyMaskError),
    /// Work exhaustion, cancellation, or invalid geometry.
    Geometry(GeometryError),
    /// Existing atlas/localization owner refused the query.
    Localization(LocalizationError),
    /// Existing source-to-pinhole owner refused the model or raw frame.
    Rectification(RectificationError),
    /// A retained package has no current ledgered publication or disagrees with its recipe.
    RetainedPackage,
    /// Native recomputation disagrees with the immutable candidate receipt.
    ReplayDiverged,
    /// V1 packages require a flat source root whose complete native closure can be retained.
    PartitionedSource,
    /// Exact property archive could not be imported.
    Twin(fss_twin::TwinError),
    /// Exact descriptor archive could not be imported.
    Atlas(fss_twin::atlas_archive::ArchiveError),
}
impl RecordedLocalizationError {
    /// Stable parent or existing nested refusal identity for operator tooling.
    pub fn stable_id(&self) -> &'static str {
        match self {
            Self::Decode(e) => e.stable_id(),
            Self::Privacy(e) => e.stable_id(),
            _ => ERR_RECORDED_LOCALIZATION_REFUSED,
        }
    }
}
impl std::fmt::Display for RecordedLocalizationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRequest => {
                f.write_str("invalid or excessive retained localization request")
            }
            Self::SourceMismatch => f.write_str("retained localization source or privacy mismatch"),
            Self::NoSelectedPicture => {
                f.write_str("selected segment has no admitted decoded picture")
            }
            Self::Cancelled => f.write_str("retained localization cancelled"),
            Self::Decode(e) => write!(f, "{e}"),
            Self::Privacy(e) => write!(f, "{e}"),
            Self::Geometry(e) => write!(f, "{e}"),
            Self::Localization(e) => write!(f, "{e}"),
            Self::Rectification(e) => write!(f, "{e}"),
            Self::RetainedPackage => {
                f.write_str("retained localization package unavailable or inconsistent")
            }
            Self::ReplayDiverged => {
                f.write_str("native localization replay diverged from retained receipt")
            }
            Self::PartitionedSource => {
                f.write_str("retained localization v1 requires an unpartitioned source import")
            }
            Self::Twin(e) => write!(f, "{e}"),
            Self::Atlas(e) => write!(f, "{e}"),
        }
    }
}
impl std::error::Error for RecordedLocalizationError {}
impl From<RecordedDecodeError> for RecordedLocalizationError {
    fn from(e: RecordedDecodeError) -> Self {
        Self::Decode(e)
    }
}
impl From<PrivacyMaskError> for RecordedLocalizationError {
    fn from(e: PrivacyMaskError) -> Self {
        Self::Privacy(e)
    }
}
impl From<GeometryError> for RecordedLocalizationError {
    fn from(e: GeometryError) -> Self {
        Self::Geometry(e)
    }
}
impl From<LocalizationError> for RecordedLocalizationError {
    fn from(e: LocalizationError) -> Self {
        Self::Localization(e)
    }
}
impl From<RectificationError> for RecordedLocalizationError {
    fn from(e: RectificationError) -> Self {
        Self::Rectification(e)
    }
}
impl From<RawLocalizationError> for RecordedLocalizationError {
    fn from(e: RawLocalizationError) -> Self {
        match e {
            RawLocalizationError::Rectification(e) => Self::Rectification(e),
            RawLocalizationError::Localization(e) => Self::Localization(e),
        }
    }
}
impl From<fss_twin::TwinError> for RecordedLocalizationError {
    fn from(error: fss_twin::TwinError) -> Self {
        Self::Twin(error)
    }
}
impl From<fss_twin::atlas_archive::ArchiveError> for RecordedLocalizationError {
    fn from(error: fss_twin::atlas_archive::ArchiveError) -> Self {
        Self::Atlas(error)
    }
}

/// Immutable source pins of a native decoded query. The full native receipt is also embedded
/// verbatim in the candidate receipt, preserving codec identity and original capture uncertainty.
#[derive(Clone, Debug)]
pub struct RecordedLocalizationBinding {
    /// Completed immutable recording.
    pub import_identity: ContentDigest,
    /// Currently retained source publication root.
    pub import_root: ContentDigest,
    /// Source manifest, including exact original source spans and omissions.
    pub manifest: ContentDigest,
    /// Completion anchor of this source, not an unrelated latest ledger tip.
    pub source_anchor: LedgerAnchor,
    /// Original selected capsule content address.
    pub capsule: ContentDigest,
    /// Exact original encoded bytes named by that capsule.
    pub encoded_source: ContentDigest,
    /// Original exposure shared by all native/rectified/privacy derivations of this capsule.
    pub exposure: ContentDigest,
    /// Exact masked native luma plane, checked again by the twin image constructor.
    pub luma: ContentDigest,
    /// Exact existing JPEG/AVC/HEVC receipt content address.
    pub decode_receipt: ContentDigest,
    /// Existing JPEG derivative root, when JPEG publication was used.
    pub decode_root: Option<ContentDigest>,
    /// Explicit no-policy or current-policy identity.
    pub mask_binding: ContentDigest,
    /// Current immutable policy, if present.
    pub mask_policy: Option<ContentDigest>,
    /// Selected original coding segment.
    pub segment: u64,
    /// IDR/IRAP segment needed to reconstruct video state; JPEG equals selected segment.
    pub range_start: u64,
    /// Complete admitted source range length, including buffered/skipped pictures.
    pub range_count: u64,
    /// Native decoded source grid, before rectification.
    pub dimensions: [u32; 2],
    /// Native receipt family; only "jpeg", "h264", and "h265" are constructed.
    pub codec: &'static str,
}

/// Complete bounded derived proposal. Accessors borrow immutable state, so receipt bytes and
/// native candidate results cannot diverge after construction. Nothing is automatically adopted.
#[derive(Debug)]
pub struct RecordedLocalization {
    source: RecordedLocalizationBinding,
    result: ImageLocalization,
    rectification: Option<RectificationReceipt>,
    geometry_work: u64,
    encoded: Vec<u8>,
}
impl RecordedLocalization {
    /// Exact source/decode/privacy pins checked during this operation.
    pub fn source(&self) -> &RecordedLocalizationBinding {
        &self.source
    }
    /// Selection accounting, all matching decisions, and explicit candidate/abstention outcome.
    pub fn result(&self) -> &ImageLocalization {
        &self.result
    }
    /// Actual native rectification map and privacy-footprint accounting, if requested.
    pub fn rectification(&self) -> Option<&RectificationReceipt> {
        self.rectification.as_ref()
    }
    /// Charged geometry work, including fixed bounded receipt serialization reservation.
    pub fn geometry_work(&self) -> u64 {
        self.geometry_work
    }
    /// Canonical reproducible candidate receipt, with the exact native source receipt embedded.
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }
    /// Content identity of the entire candidate receipt.
    pub fn digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.encoded)
    }
}

/// Deterministic identity of an original retained exposure. Hashing both the exact capsule and
/// its source bytes identity prevents a caller from borrowing an atlas reference identity.
pub fn retained_exposure(capsule: &SensorCapsule) -> Result<ContentDigest> {
    let bytes = capsule
        .try_canonical_bytes()
        .map_err(RecordedDecodeError::from)?;
    let mut e = CanonicalEncoder::new();
    e.text(EXPOSURE_DOMAIN);
    e.digest(ContentDigest::sha256(&bytes));
    e.digest(capsule.source_digest);
    Ok(ContentDigest::sha256(&e.finish()))
}

enum Frame {
    Jpeg(RecordedFrame),
    H264(RecordedH264Frame),
    H265(RecordedH265Frame),
}
impl Frame {
    fn pixels(&self) -> &[u8] {
        match self {
            Self::Jpeg(f) => f.pixels(),
            Self::H264(f) => f.pixels(),
            Self::H265(f) => f.pixels(),
        }
    }
    fn capsule(&self) -> &SensorCapsule {
        match self {
            Self::Jpeg(f) => f.receipt().capsule(),
            Self::H264(f) => f.receipt().capsule(),
            Self::H265(f) => f.receipt().capsule(),
        }
    }
    fn binding(
        &self,
        retained: &RetainedFileImport,
        source: &RecordedLocalizationSource,
    ) -> Result<(RecordedLocalizationBinding, Vec<u8>)> {
        let (dimensions, luma, bytes, decode_root, mask_binding, mask_policy, codec) = match self {
            Self::Jpeg(f) => {
                let r = f.receipt();
                (
                    r.dimensions(),
                    ContentDigest::new(fss_core::DigestAlgorithm::Sha256, r.codec().luma_sha256),
                    r.encoded()?,
                    Some(f.publication_root()),
                    r.mask_binding(),
                    r.mask_policy(),
                    "jpeg",
                )
            }
            Self::H264(f) => {
                let r = f.receipt();
                (
                    r.dimensions(),
                    r.luma_sha256(),
                    r.encoded(),
                    None,
                    r.mask_binding(),
                    r.mask_policy(),
                    "h264",
                )
            }
            Self::H265(f) => {
                let r = f.receipt();
                (
                    r.dimensions(),
                    r.luma_sha256(),
                    r.encoded(),
                    None,
                    r.mask_binding(),
                    r.mask_policy(),
                    "h265",
                )
            }
        };
        let capsule = self.capsule();
        let capsule_bytes = capsule
            .try_canonical_bytes()
            .map_err(RecordedDecodeError::from)?;
        let (start, count) = source.range();
        Ok((
            RecordedLocalizationBinding {
                import_identity: source.import_identity(),
                import_root: retained.import_root(),
                manifest: retained.manifest_digest(),
                source_anchor: retained.authority_anchor().clone(),
                capsule: ContentDigest::sha256(&capsule_bytes),
                encoded_source: capsule.source_digest,
                exposure: retained_exposure(capsule)?,
                luma,
                decode_receipt: ContentDigest::sha256(&bytes),
                decode_root,
                mask_binding,
                mask_policy,
                segment: source.segment() as u64,
                range_start: start as u64,
                range_count: count as u64,
                dimensions,
                codec,
            },
            bytes,
        ))
    }
}

fn checkpoint(cx: &ReplayCx, stage: &'static str) -> Result<()> {
    cx.checkpoint(stage)
        .map_err(|_| RecordedLocalizationError::Cancelled)
}

fn validate(plan: RecordedLocalizationPlan<'_>, source: &RecordedLocalizationSource) -> Result<()> {
    let (start, count) = source.range();
    if count == 0
        || count > 1024
        || source.segment() < start
        || start
            .checked_add(count)
            .is_none_or(|end| source.segment() >= end)
        || plan.atlas.twin_digest() != plan.twin.digest()
    {
        return Err(RecordedLocalizationError::InvalidRequest);
    }
    validate_options(plan.options)
}

fn validate_options(options: ImageLocalizationOptions) -> Result<()> {
    let e = options.extraction;
    let m = options.matching;
    let s = options.solving;
    if !(1..=254).contains(&e.threshold)
        || !(1..=512).contains(&e.maximum_features)
        || !(1..=128).contains(&e.separation)
        || m.maximum_distance > 256
        || !(1..=99).contains(&m.ratio_percent)
        || s.ransac_trials > 1024
        || !(1..=100).contains(&s.refinement_iterations)
        || !(0.001..=128.0).contains(&s.inlier_threshold_px)
        || !(6..=512).contains(&s.minimum_inliers)
        || !(0.0 < s.minimum_inlier_fraction && s.minimum_inlier_fraction <= 1.0)
        || !(1e-10..=0.1).contains(&s.minimum_axis_ratio)
        || !(0.0..=1.0).contains(&s.minimum_image_span)
    {
        return Err(RecordedLocalizationError::InvalidRequest);
    }
    Ok(())
}

fn decode(
    deployment: &mut ReferenceDeployment,
    source: &RecordedLocalizationSource,
    jpeg: &mut DecodeBudget<'_>,
    video: &mut RecordedVideoDecodeBudget,
    geometry: &mut WorkBudget<'_>,
    cx: &ReplayCx,
    replay_jpeg: bool,
) -> Result<Frame> {
    match source {
        RecordedLocalizationSource::Jpeg(request) => {
            let frame = if replay_jpeg {
                let frame = RecordedFrame::open(deployment, request, cx)?;
                frame.verify_by_replay(deployment, request, jpeg, cx)?;
                frame
            } else {
                RecordedFrame::decode_and_publish(deployment, request, jpeg, cx)?
            };
            Ok(Frame::Jpeg(frame))
        }
        RecordedLocalizationSource::H264 { request, segment } => {
            // Enforce this image consumer's ceiling before the codec allocates its DPB.
            let mut request = request.clone();
            request.decoder_limits.max_width = request.decoder_limits.max_width.min(4096);
            request.decoder_limits.max_height = request.decoder_limits.max_height.min(4096);
            request.decoder_limits.max_macroblocks =
                request.decoder_limits.max_macroblocks.min(16_384);
            let mut range = RecordedH264Range::open_with_budget(deployment, request, video, cx)?;
            let mut selected = None;
            loop {
                geometry.charge(0)?;
                let Some(frame) = range.next_frame_with_budget(deployment, video, cx)? else {
                    break;
                };
                if frame.segment_index() == *segment as u64 {
                    if selected.is_some() {
                        return Err(RecordedLocalizationError::SourceMismatch);
                    }
                    selected = Some(frame);
                }
            }
            selected
                .map(Frame::H264)
                .ok_or(RecordedLocalizationError::NoSelectedPicture)
        }
        RecordedLocalizationSource::H265 { request, segment } => {
            let mut request = request.clone();
            request.decoder_limits.max_width = request.decoder_limits.max_width.min(4096);
            request.decoder_limits.max_height = request.decoder_limits.max_height.min(4096);
            request.decoder_limits.max_luma_samples =
                request.decoder_limits.max_luma_samples.min(4_194_304);
            let mut range = RecordedH265Range::open_with_budget(deployment, request, video, cx)?;
            let mut selected = None;
            loop {
                geometry.charge(0)?;
                let Some(frame) = range.next_frame_with_budget(deployment, video, cx)? else {
                    break;
                };
                if frame.segment_index() == *segment as u64 {
                    if selected.is_some() {
                        return Err(RecordedLocalizationError::SourceMismatch);
                    }
                    selected = Some(frame);
                }
            }
            selected
                .map(Frame::H265)
                .ok_or(RecordedLocalizationError::NoSelectedPicture)
        }
    }
}

fn allowed_mask(
    mask: &MaskBinding,
    dimensions: [u32; 2],
    budget: &mut WorkBudget<'_>,
) -> Result<Vec<u8>> {
    let [w, h] = dimensions;
    let count = (w as usize)
        .checked_mul(h as usize)
        .ok_or(RecordedLocalizationError::InvalidRequest)?;
    if w == 0 || h == 0 || w > 4096 || h > 4096 || count > 4_194_304 {
        return Err(RecordedLocalizationError::InvalidRequest);
    }
    budget.charge(count as u64)?;
    let mut allowed = Vec::new();
    allowed
        .try_reserve_exact(count)
        .map_err(|_| RecordedLocalizationError::InvalidRequest)?;
    allowed.resize(count, 1);
    if let MaskBinding::Policy(retained) = mask {
        if retained.policy.resolution() != dimensions {
            return Err(RecordedLocalizationError::SourceMismatch);
        }
        for region in retained.policy.regions() {
            // Regions can overlap; every actual write is charged, including overlaps.
            budget.charge(u64::from(region.width()) * u64::from(region.height()))?;
            for y in region.y()..region.y() + region.height() {
                budget.charge(0)?;
                let start = y as usize * w as usize + region.x() as usize;
                allowed[start..start + region.width() as usize].fill(0);
            }
        }
    }
    Ok(allowed)
}

/// Decode an exact retained source and produce bounded, privacy-screened pose candidates.
///
/// Geometry and JPEG budgets may share a caller cancellation flag through their existing
/// cancellable constructors. The video path polls context cancellation at native AU boundaries
/// and the supplied geometry budget before each output. A complete requested range is required
/// before localization; neither budget exhaustion nor a later damaged AU returns partial poses.
/// JPEG's existing decode publication can complete before a later localization refusal.
pub fn localize_recorded_frame(
    deployment: &mut ReferenceDeployment,
    source: &RecordedLocalizationSource,
    plan: RecordedLocalizationPlan<'_>,
    jpeg_budget: &mut DecodeBudget<'_>,
    video_budget: &mut RecordedVideoDecodeBudget,
    geometry_budget: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<RecordedLocalization> {
    localize_inner(
        deployment,
        source,
        plan,
        jpeg_budget,
        video_budget,
        geometry_budget,
        cx,
        false,
    )
}

fn localize_inner(
    deployment: &mut ReferenceDeployment,
    source: &RecordedLocalizationSource,
    plan: RecordedLocalizationPlan<'_>,
    jpeg_budget: &mut DecodeBudget<'_>,
    video_budget: &mut RecordedVideoDecodeBudget,
    geometry_budget: &mut WorkBudget<'_>,
    cx: &ReplayCx,
    replay_jpeg: bool,
) -> Result<RecordedLocalization> {
    checkpoint(cx, STAGE_LOCALIZATION_SOURCE)?;
    validate(plan, source)?;
    let work_start = geometry_budget.used();
    geometry_budget.charge(MAX_RECEIPT_BYTES as u64)?;
    // Compile/admit raw lens models before source decoding or JPEG derivative publication.
    let rectifier = match plan.image {
        RecordedImageMode::Pinhole(_) => None,
        RecordedImageMode::Raw(spec) => Some(RectificationPlan::compile(spec, geometry_budget)?),
    };
    let frame = decode(
        deployment,
        source,
        jpeg_budget,
        video_budget,
        geometry_budget,
        cx,
        replay_jpeg,
    )?;
    let retained =
        RetainedFileImport::open(deployment, source.import_identity(), source.limits(), cx)
            .map_err(RecordedDecodeError::from)?;
    let capsule = retained_source_capsule(deployment, &retained, source.segment())?;
    if frame.capsule() != &capsule {
        return Err(RecordedLocalizationError::SourceMismatch);
    }
    let (binding, native_receipt) = frame.binding(&retained, source)?;
    let mask = current_mask(deployment, &capsule.sensor_id)?;
    if mask.digest() != binding.mask_binding || mask.policy_digest() != binding.mask_policy {
        return Err(RecordedLocalizationError::SourceMismatch);
    }
    let allowed = allowed_mask(&mask, binding.dimensions, geometry_budget)?;
    let (result, rectification) = match (plan.image, rectifier.as_ref()) {
        (RecordedImageMode::Pinhole(camera), None) => {
            let image = GrayImage::new(
                ImageIdentity {
                    exposure: binding.exposure.bytes(),
                    pixels: binding.luma.bytes(),
                    image_domain: camera.image_domain,
                    dimensions: binding.dimensions,
                },
                frame.pixels(),
                &allowed,
                geometry_budget,
            )?;
            (
                localize_gray_frame(
                    plan.atlas,
                    plan.twin,
                    &image,
                    camera,
                    plan.options,
                    geometry_budget,
                )?,
                None,
            )
        }
        (RecordedImageMode::Raw(spec), Some(rectifier)) => {
            // Constructing the source mask identity is its own full hash walk. The raw
            // frame owner separately charges verification of that identity below.
            geometry_budget.charge(allowed.len() as u64)?;
            let raw = RawGrayFrame::new(
                RawFrameIdentity {
                    exposure: binding.exposure.bytes(),
                    storage: binding.luma.bytes(),
                    allowed_mask: ContentDigest::sha256(&allowed).bytes(),
                    image_domain: spec.source_domain,
                    calibration: spec.calibration,
                    dimensions: binding.dimensions,
                    row_stride: binding.dimensions[0],
                    range: spec.range,
                },
                frame.pixels(),
                &allowed,
                geometry_budget,
            )?;
            let localized = localize_raw_frame(
                plan.atlas,
                plan.twin,
                rectifier,
                &raw,
                plan.options,
                geometry_budget,
            )?;
            (localized.result, Some(localized.rectification))
        }
        _ => return Err(RecordedLocalizationError::InvalidRequest),
    };
    if let LocalizationOutcome::GeometricFailure(
        e @ (GeometryError::Cancelled | GeometryError::BudgetExhausted),
    ) = result.localization.outcome
    {
        return Err(e.into());
    }
    geometry_budget.charge(0)?;
    checkpoint(cx, STAGE_LOCALIZATION_COMPLETE)?;
    // No stale mask or missing/deleted source can escape merely because matching succeeded.
    let current =
        RetainedFileImport::open(deployment, source.import_identity(), source.limits(), cx)
            .map_err(RecordedDecodeError::from)?;
    if current != retained || current_mask(deployment, &capsule.sensor_id)? != mask {
        return Err(RecordedLocalizationError::SourceMismatch);
    }
    let geometry_work = geometry_budget.used() - work_start;
    let encoded = receipt::encode(
        &binding,
        &native_receipt,
        plan,
        &result,
        rectification.as_ref(),
        geometry_work,
    )?;
    geometry_budget.charge(0)?;
    checkpoint(cx, STAGE_LOCALIZATION_COMPLETE)?;
    Ok(RecordedLocalization {
        source: binding,
        result,
        rectification,
        geometry_work,
        encoded,
    })
}

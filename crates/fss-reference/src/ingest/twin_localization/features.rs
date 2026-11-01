#![forbid(unsafe_code)]
//! Sealed native features from exact retained JPEG, AVC or HEVC source evidence.
//!
//! Callers declare an image-domain interpretation, never pixels, timestamps or privacy masks.
//! Existing native owners provide masked luma and codec receipts. Extraction excludes the whole
//! descriptor footprint under the current sensor policy. The result remains derived cognition:
//! its declared image domain does not certify a lens model or activate camera calibration.

use std::path::PathBuf;
use std::sync::Arc;

use fss_core::{CanonicalEncode, CanonicalEncoder, ContentDigest, DigestAlgorithm, SensorCapsule};
use fss_geometry::WorkBudget;
use fss_twin::localization::native::{
    ExtractionOptions, FeatureSelection, GrayImage, extract_gray,
};
use fss_twin::localization::{FeatureFrame, ImageIdentity};

use super::{
    DecodeAccess, RecordedLocalizationBinding, RecordedLocalizationError,
    RecordedLocalizationSource, allowed_mask, checkpoint, decode,
};
use crate::ingest::privacy_mask::{MaskBinding, current_mask};
use crate::ingest::recorded_decode::video_budget::RecordedVideoDecodeBudget;
use crate::ingest::recorded_decode::{
    DecodeBudget, RecordedDecodeError, RecordedFrame, retained_source_capsule, verify_custody,
};
use crate::ingest::retained::SourceReadBudget;
use crate::ingest::{RetainedFileImport, VerifiedChunkCache};
use crate::{ReferenceDeployment, ReplayCx};

type Result<T> = std::result::Result<T, RecordedLocalizationError>;

/// Complete native source range ceiling, including buffered and skipped codec pictures.
pub const MAX_FEATURE_RANGE_SEGMENTS: usize = 64;
/// Hard decoded image allocation ceiling, imposed before native decoder allocation.
pub const MAX_FEATURE_PIXELS: usize = 4_194_304;
/// Hard width and height ceiling of a native feature grid.
pub const MAX_FEATURE_DIMENSION: u32 = 4096;
/// Canonical identity of this source-bound extraction, with no effect authority.
pub const FEATURE_DOMAIN: &str = "fss.recorded_native_features.v1";
/// Cooperative boundary before source work or JPEG derivative publication.
pub const STAGE_FEATURE_SOURCE: &str = "recorded_features:source";
/// Cooperative boundary before returning features or revalidating a downstream result.
pub const STAGE_FEATURE_REVALIDATE: &str = "recorded_features:revalidate";

/// One nonrenewable original-source allowance, shared across views and final revalidation.
/// Counts actual original chunk and HTTP/RTSP origin-proof reads, including failed attempts.
/// This axis is separate from JPEG work, video admission and geometry work.
#[derive(Clone, Debug)]
pub struct RecordedFeatureReadBudget {
    source: SourceReadBudget,
}
impl RecordedFeatureReadBudget {
    /// Construct a cumulative allowance. Zero admits no original-source reads.
    pub fn new(maximum_source_bytes: u64) -> Self {
        Self {
            source: SourceReadBudget::new(maximum_source_bytes),
        }
    }

    /// Also poll an owner-held deadline/cancellation probe before each source reservation.
    /// Clones preserve both the allowance and the probe; they never renew either.
    pub fn with_cancellation_probe(
        maximum_source_bytes: u64,
        cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Self {
        Self {
            source: SourceReadBudget::with_cancellation_probe(maximum_source_bytes, cancelled),
        }
    }

    /// Source bytes reserved so far, including final revalidation and unsuccessful reads.
    pub fn used(&self) -> u64 {
        self.source.used()
    }
}

/// Exact retained source and bounded native extraction on a declared image grid.
#[derive(Clone, Debug)]
pub struct RecordedFeatureRequest {
    /// JPEG segment or complete IDR/IRAP-starting native video range and selected coding segment.
    pub source: RecordedLocalizationSource,
    /// Explicit owner interpretation of this native grid; not a calibration certificate.
    pub image_domain: ContentDigest,
    /// Existing deterministic FAST/descriptor selection, with at most 512 features.
    pub extraction: ExtractionOptions,
}

/// Immutable features, native receipt and full source evidence, constructed only by this owner.
/// No raw pixels are exposed. Call [`Self::revalidate`] after downstream computation and before
/// releasing a report; retained source or privacy may have changed since extraction.
pub struct RecordedFeatures {
    frame: FeatureFrame,
    selection: FeatureSelection,
    source: RecordedLocalizationBinding,
    capsule: SensorCapsule,
    native_receipt: Vec<u8>,
    geometry_work: u64,
    digest: ContentDigest,
    retained: RetainedFileImport,
    request: RecordedFeatureRequest,
    mask: MaskBinding,
    source_budget: SourceReadBudget,
    deployment_root: PathBuf,
    context_root: PathBuf,
    principal: String,
}
impl std::fmt::Debug for RecordedFeatures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordedFeatures")
            .field("digest", &self.digest)
            .field("selected", &self.selection.selected)
            .field("codec", &self.source.codec)
            .finish_non_exhaustive()
    }
}
impl RecordedFeatures {
    /// Exact native descriptors, pixel coordinates and original exposure identity.
    pub fn frame(&self) -> &FeatureFrame {
        &self.frame
    }
    /// Complete extraction scope, actual allowed-mask digest and counted omissions.
    pub fn selection(&self) -> FeatureSelection {
        self.selection
    }
    /// Full native source/decode/privacy bindings, including the source completion anchor.
    pub fn source(&self) -> &RecordedLocalizationBinding {
        &self.source
    }
    /// Original authenticated source capsule, with unmodified capture interval and clock basis.
    pub fn capsule(&self) -> &SensorCapsule {
        &self.capsule
    }
    /// Complete existing native codec receipt. Its digest equals `source().decode_receipt`.
    pub fn native_receipt(&self) -> &[u8] {
        &self.native_receipt
    }
    /// Deterministic geometry/extraction work, excluding the independent source and codec axes.
    pub fn geometry_work(&self) -> u64 {
        self.geometry_work
    }
    /// Canonical identity binding source, privacy, declaration and the complete feature set.
    pub fn digest(&self) -> ContentDigest {
        self.digest
    }

    /// Revalidate exact current source custody and privacy without renewing any allowance.
    ///
    /// JPEG also reopens and verifies its retained decode publication. Video checks every
    /// original capsule and source span in the complete admitted range, plus container
    /// structural spans that can supply decoder bootstrap. No codec output is regenerated.
    /// Ordinary unrelated ledger appends, including another JPEG decode, do not stale this
    /// snapshot: the immutable source-completion anchor is the binding, not the latest tip.
    pub fn revalidate(
        &self,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
        work: &mut WorkBudget<'_>,
    ) -> Result<()> {
        guard(&self.source_budget, cx, work, STAGE_FEATURE_REVALIDATE)?;
        if deployment.root() != self.deployment_root
            || cx.root_dir() != self.context_root
            || cx.io_authority().principal() != self.principal
        {
            return Err(RecordedLocalizationError::SourceMismatch);
        }
        let current = RetainedFileImport::open(
            deployment,
            self.request.source.import_identity(),
            self.request.source.limits(),
            cx,
        )
        .map_err(RecordedDecodeError::from)?;
        if current != self.retained {
            return Err(RecordedLocalizationError::SourceMismatch);
        }
        let capsule = retained_source_capsule(deployment, &current, self.request.source.segment())?;
        if capsule != self.capsule || current_mask(deployment, &capsule.sensor_id)? != self.mask {
            return Err(RecordedLocalizationError::SourceMismatch);
        }
        match &self.request.source {
            RecordedLocalizationSource::Jpeg(request) => {
                let decoded = RecordedFrame::open_with_source_budget(
                    deployment,
                    request,
                    cx,
                    Some(&self.source_budget),
                )?;
                if Some(decoded.publication_root()) != self.source.decode_root
                    || decoded.receipt().encoded()? != self.native_receipt
                    || decoded.receipt().capsule() != &self.capsule
                {
                    return Err(RecordedLocalizationError::SourceMismatch);
                }
            }
            RecordedLocalizationSource::H264 { .. } | RecordedLocalizationSource::H265 { .. } => {
                self.revalidate_video(deployment, &current, cx, work)?;
            }
        }
        guard(&self.source_budget, cx, work, STAGE_FEATURE_REVALIDATE)?;
        // A callback can withdraw privacy during a read boundary; compare again before release.
        if current_mask(deployment, &self.capsule.sensor_id)? != self.mask {
            return Err(RecordedLocalizationError::SourceMismatch);
        }
        Ok(())
    }

    fn revalidate_video(
        &self,
        deployment: &ReferenceDeployment,
        retained: &RetainedFileImport,
        cx: &ReplayCx,
        work: &mut WorkBudget<'_>,
    ) -> Result<()> {
        let source = &self.request.source;
        let (start, count) = source.range();
        let mut chunks = VerifiedChunkCache::with_source_budget(Some(&self.source_budget));
        for segment in start..start + count {
            guard(&self.source_budget, cx, work, STAGE_FEATURE_REVALIDATE)?;
            let capsule = retained_source_capsule(deployment, retained, segment)?;
            let bytes = retained
                .read_segment_cached(deployment, segment, source.limits(), cx, &mut chunks)
                .map_err(RecordedDecodeError::from)?;
            verify_custody(&capsule, &bytes)?;
        }
        if matches!(
            retained.manifest().format.as_str(),
            "mp4avc" | "mp4hevc" | "mkvavc" | "mkvhevc"
        ) {
            // This is deliberately conservative: all bounded structural spans are checked,
            // so neither out-of-band parameter sets nor in-band bootstrap entry metadata can
            // silently disappear after a successful native range decode.
            for index in 0..retained.manifest().omission_spans.len() {
                guard(&self.source_budget, cx, work, STAGE_FEATURE_REVALIDATE)?;
                retained
                    .read_omission_span_budgeted(
                        deployment,
                        index,
                        source.limits(),
                        cx,
                        Some(&self.source_budget),
                    )
                    .map_err(RecordedDecodeError::from)?;
            }
        }
        Ok(())
    }
}

fn guard(
    source: &SourceReadBudget,
    cx: &ReplayCx,
    work: &mut WorkBudget<'_>,
    stage: &'static str,
) -> Result<()> {
    source.checkpoint().map_err(RecordedDecodeError::from)?;
    work.charge(0)?;
    checkpoint(cx, stage)
}

fn validate(request: &RecordedFeatureRequest) -> Result<()> {
    let (start, count) = request.source.range();
    let options = request.extraction;
    if request.image_domain.algorithm() != DigestAlgorithm::Sha256
        || request.image_domain.bytes() == [0; 32]
        || count == 0
        || count > MAX_FEATURE_RANGE_SEGMENTS
        || request.source.segment() < start
        || start
            .checked_add(count)
            .is_none_or(|end| request.source.segment() >= end)
        || !(1..=254).contains(&options.threshold)
        || !(1..=512).contains(&options.maximum_features)
        || !(1..=128).contains(&options.separation)
    {
        return Err(RecordedLocalizationError::InvalidRequest);
    }
    Ok(())
}

fn bounded_source(source: &RecordedLocalizationSource) -> RecordedLocalizationSource {
    let mut source = source.clone();
    if let RecordedLocalizationSource::Jpeg(request) = &mut source {
        request.decode_limits.maximum_dimension = request
            .decode_limits
            .maximum_dimension
            .min(MAX_FEATURE_DIMENSION);
        request.decode_limits.maximum_pixels =
            request.decode_limits.maximum_pixels.min(MAX_FEATURE_PIXELS);
    }
    // The shared native video helper imposes the same 4096/4,194,304 sample ceilings
    // before opening its DPB. The public source request remains otherwise unchanged.
    source
}

/// Decode exact retained evidence and extract a complete, privacy-screened native feature set.
///
/// The JPEG owner may complete its ordinary derived decode publication before a later feature
/// refusal. AVC/HEVC decode the entire admitted range and publish no decode objects. The initial
/// return and every later revalidation consume the same original-source allowance. All feature
/// selection, omission counts and descriptor generations come from the existing native extractor.
pub fn extract_recorded_features(
    deployment: &mut ReferenceDeployment,
    request: &RecordedFeatureRequest,
    source_budget: &RecordedFeatureReadBudget,
    jpeg: &mut DecodeBudget<'_>,
    video: &mut RecordedVideoDecodeBudget,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<RecordedFeatures> {
    guard(&source_budget.source, cx, work, STAGE_FEATURE_SOURCE)?;
    validate(request)?;
    let request = RecordedFeatureRequest {
        source: bounded_source(&request.source),
        ..request.clone()
    };
    let work_start = work.used();
    let decoded = decode(
        deployment,
        &request.source,
        jpeg,
        video,
        work,
        cx,
        DecodeAccess {
            replay_jpeg: false,
            source_budget: Some(&source_budget.source),
        },
    )?;
    guard(&source_budget.source, cx, work, STAGE_FEATURE_SOURCE)?;
    let retained = RetainedFileImport::open(
        deployment,
        request.source.import_identity(),
        request.source.limits(),
        cx,
    )
    .map_err(RecordedDecodeError::from)?;
    let capsule = retained_source_capsule(deployment, &retained, request.source.segment())?;
    if decoded.capsule() != &capsule {
        return Err(RecordedLocalizationError::SourceMismatch);
    }
    let (binding, native_receipt) = decoded.binding(&retained, &request.source)?;
    if native_receipt.len() > 16 * 1024 {
        return Err(RecordedLocalizationError::InvalidRequest);
    }
    let mask = current_mask(deployment, &capsule.sensor_id)?;
    if mask.digest() != binding.mask_binding || mask.policy_digest() != binding.mask_policy {
        return Err(RecordedLocalizationError::SourceMismatch);
    }
    let allowed = allowed_mask(&mask, binding.dimensions, work)?;
    let image = GrayImage::new(
        ImageIdentity {
            exposure: binding.exposure.bytes(),
            pixels: binding.luma.bytes(),
            image_domain: request.image_domain.bytes(),
            dimensions: binding.dimensions,
        },
        decoded.pixels(),
        &allowed,
        work,
    )?;
    let extracted = extract_gray(&image, request.extraction, work)?;
    drop(decoded);
    let digest = feature_digest(
        &binding,
        &native_receipt,
        &extracted.frame,
        extracted.selection,
        work,
    )?;
    let result = RecordedFeatures {
        frame: extracted.frame,
        selection: extracted.selection,
        source: binding,
        capsule,
        native_receipt,
        geometry_work: work.used() - work_start,
        digest,
        retained,
        request,
        mask,
        source_budget: source_budget.source.clone(),
        deployment_root: deployment.root().to_path_buf(),
        context_root: cx.root_dir().to_path_buf(),
        principal: cx.io_authority().principal().to_owned(),
    };
    result.revalidate(deployment, cx, work)?;
    Ok(result)
}

fn feature_digest(
    binding: &RecordedLocalizationBinding,
    native_receipt: &[u8],
    frame: &FeatureFrame,
    selection: FeatureSelection,
    work: &mut WorkBudget<'_>,
) -> Result<ContentDigest> {
    let mut e = CanonicalEncoder::new();
    e.text(FEATURE_DOMAIN);
    e.text("derived_native_features_no_effect_authority");
    e.text(binding.codec);
    for digest in [
        binding.import_identity,
        binding.import_root,
        binding.manifest,
        binding.capsule,
        binding.encoded_source,
        binding.exposure,
        binding.luma,
        binding.decode_receipt,
        binding.mask_binding,
    ] {
        e.digest(digest);
    }
    binding.source_anchor.encode_canonical(&mut e);
    for digest in [binding.decode_root, binding.mask_policy] {
        e.bool(digest.is_some());
        if let Some(digest) = digest {
            e.digest(digest);
        }
    }
    e.u64(binding.segment);
    e.u64(binding.range_start);
    e.u64(binding.range_count);
    for dimension in binding.dimensions {
        e.u32(dimension);
    }
    e.bytes(native_receipt);
    e.bytes(&frame.identity().image_domain);
    e.bytes(&frame.descriptor_domain());
    e.bytes(&selection.mask_digest);
    e.u8(selection.threshold);
    e.u32(u32::from(selection.separation));
    for value in [
        selection.maximum_features,
        selection.tested_centers,
        selection.local_maxima,
        selection.selected,
        selection.omitted,
    ] {
        e.u64(value as u64);
    }
    e.u64(frame.features().len() as u64);
    for feature in frame.features() {
        e.u64(feature.id);
        for coordinate in feature.pixel {
            e.u64(coordinate.to_bits());
        }
        for word in feature.descriptor.0 {
            e.u64(word);
        }
    }
    let bytes = e.finish();
    if bytes.len() > 128 * 1024 {
        return Err(RecordedLocalizationError::InvalidRequest);
    }
    work.charge(bytes.len() as u64)?;
    Ok(ContentDigest::sha256(&bytes))
}

#![forbid(unsafe_code)]
//! Exact retained model and resource settings for native long-watch detector replay.
//!
//! Parsing grants no execution authority. Stored reservations must fit current caller ceilings
//! before loading the model or reading source, and the verified package must reproduce every
//! model/contract/kernel binding before inference. All fields have one canonical encoding.

use crate::ingest::RetainedReadLimits;
use crate::ingest::detector_cascade::CascadeConfig;
use crate::ingest::long_watch::LongWatchLimits;
use crate::ingest::package_detect::PackageDetectLimits;
use crate::ingest::recorded_watch::{WatchError, WatchLimits};
use crate::ingest::rgb_inference::RgbRunLimits;
use crate::ingest::rgb_package::RgbDetectorPackage;
use crate::{ExecBudget, KernelBackend};
use fss_codec_mjpeg::color::RgbDecodeLimits;
use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest, DigestAlgorithm};

/// Canonical implementation-profile identity; detector scores remain uncalibrated evidence.
pub const RECIPE_DOMAIN: &str = "fss.long_watch_detector_recipe.v1";
/// Fixed work reservation for digest/license/graph/weights admission, independent of inference.
pub const DETECTOR_IMPORT_WORK_UNITS: u64 = 1 << 36;
/// Bound before any recipe field is parsed or cloned.
pub const MAX_LONG_WATCH_DETECTOR_RECIPE_BYTES: usize = 8192;
const POLICY: &[u8] =
    b"native-long-watch-detector-v1:complete-model-custody:exact-kernel-generation:\
confirmed-actual-entry-selection:shared-inference-allowance:masked-native-rgb:\
uncalibrated-same-sensor-evidence:no-event-kind-probability-or-authority-upgrade";
type Result<T> = std::result::Result<T, WatchError>;

/// Immutable settings and verified model bindings. No loose model path is retained.
#[derive(Clone, Debug)]
pub struct LongWatchDetectorRecipe {
    package_digest: ContentDigest,
    manifest_digest: ContentDigest,
    model_digest: ContentDigest,
    contract_digest: ContentDigest,
    backend: KernelBackend,
    config: CascadeConfig,
    package_limits: PackageDetectLimits,
    watch_limits: LongWatchLimits,
}

impl LongWatchDetectorRecipe {
    /// Capture the already verified package and every declared resource ceiling.
    pub fn new(
        package: &RgbDetectorPackage,
        config: CascadeConfig,
        package_limits: PackageDetectLimits,
        watch_limits: &LongWatchLimits,
    ) -> Result<Self> {
        let contract_digest = detector_contract(package, config)?;
        let value = Self {
            package_digest: package.archive_digest(),
            manifest_digest: package.manifest_digest(),
            model_digest: package.model().digest(),
            contract_digest,
            backend: package.model().backend(),
            config,
            package_limits,
            watch_limits: *watch_limits,
        };
        value.validate()?;
        Ok(value)
    }

    /// Exact archived model package; its bytes are part of the analysis closure.
    pub const fn package_digest(&self) -> ContentDigest {
        self.package_digest
    }
    /// Model manifest identity, including model generation and license.
    pub const fn manifest_digest(&self) -> ContentDigest {
        self.manifest_digest
    }
    /// Native model identity, binding preprocessing and execution backend.
    pub const fn model_digest(&self) -> ContentDigest {
        self.model_digest
    }
    /// Exact detection-head contract including any explicit threshold override.
    pub const fn contract_digest(&self) -> ContentDigest {
        self.contract_digest
    }
    /// Original execution kernel family; it is never silently replaced on replay.
    pub const fn backend(&self) -> KernelBackend {
        self.backend
    }
    /// Whole-scan inference selection and association policy.
    pub const fn config(&self) -> CascadeConfig {
        self.config
    }
    /// Complete original package settings. This composition decodes through `watch_limits().decode`;
    /// `run.preprocess`, `run.execution`, `run.maximum_output_bytes`, and the two detection-head
    /// fields govern the selected native pipeline. Package read/JPEG/AVC/HEVC and `run.decode`
    /// settings are retained for exact caller-policy identity, not additional decoder allowances.
    pub const fn package_limits(&self) -> &PackageDetectLimits {
        &self.package_limits
    }
    /// Complete source/JPEG/AVC/HEVC/scan limits, unlike historical model-free watch records.
    pub const fn watch_limits(&self) -> &LongWatchLimits {
        &self.watch_limits
    }
    /// Exact fixed model-loading reservation.
    pub const fn import_work_units(&self) -> u64 {
        DETECTOR_IMPORT_WORK_UNITS
    }
    /// Exact canonical recipe identity.
    pub fn digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.to_bytes())
    }

    fn validate(&self) -> Result<()> {
        self.config.validate()?;
        self.watch_limits.validate()?;
        for digest in [
            self.package_digest,
            self.manifest_digest,
            self.model_digest,
            self.contract_digest,
        ] {
            if digest.algorithm() != DigestAlgorithm::Sha256 || digest.bytes() == [0; 32] {
                return Err(WatchError::InvalidPlan(
                    "invalid long-watch detector identity",
                ));
            }
        }
        // This reference profile admits the existing bounded package defaults or narrower limits.
        // Zero work can intentionally produce an explicit refused-frame outcome. A later-stage refusal
        // can follow an executed model; the outcome separately accounts for inference attempts.
        reservations_fit(
            package_bytes(&self.package_limits),
            package_bytes(&PackageDetectLimits::default()),
        )?;
        Ok(())
    }

    /// Check every stored reservation before executing under a current caller's authority.
    /// Narrowing a ceiling refuses the recipe rather than recomputing under changed settings.
    pub fn validate_within(
        &self,
        watch: &LongWatchLimits,
        package: &PackageDetectLimits,
    ) -> Result<()> {
        self.validate()?;
        watch.validate()?;
        reservations_fit(watch_bytes(&self.watch_limits), watch_bytes(watch))?;
        reservations_fit(package_bytes(&self.package_limits), package_bytes(package))
    }

    /// Rebind a freshly verified retained package before permitting native execution.
    pub fn verify_package(&self, package: &RgbDetectorPackage) -> Result<()> {
        let contract_digest = detector_contract(package, self.config)?;
        if package.archive_digest() != self.package_digest
            || package.manifest_digest() != self.manifest_digest
            || package.model().digest() != self.model_digest
            || package.model().backend() != self.backend
            || contract_digest != self.contract_digest
        {
            return Err(WatchError::InvalidPlan(
                "retained detector package or generation changed",
            ));
        }
        Ok(())
    }

    /// Canonical bytes; no caller paths, inferred capture times or credentials are included.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = CanonicalEncoder::new();
        e.text(RECIPE_DOMAIN);
        e.bytes(POLICY);
        for digest in [
            self.package_digest,
            self.manifest_digest,
            self.model_digest,
            self.contract_digest,
        ] {
            e.digest(digest);
        }
        e.text(self.backend.stable_id());
        e.digest(self.backend.generation());
        e.bytes(&fss_codec_mjpeg::color::rgb_decoder_identity());
        e.digest(crate::ingest::recorded_decode::video_rgb::video_rgb_transform_identity());
        e.u64(DETECTOR_IMPORT_WORK_UNITS);
        e.u64(self.config.max_inferences as u64);
        e.u64(self.config.frames_per_track as u64);
        e.u32(self.config.minimum_association_iou_ppm);
        match self.config.minimum_score_ppm {
            Some(score) => {
                e.bool(true);
                e.u32(score);
            }
            None => e.bool(false),
        }
        encode_limits(&mut e, &self.watch_limits);
        encode_package(&mut e, &self.package_limits);
        e.finish()
    }

    /// Recover one bounded canonical recipe, refusing unknown kernels and changed decoder code.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_LONG_WATCH_DETECTOR_RECIPE_BYTES {
            return Err(WatchError::Limit);
        }
        let mut d = CanonicalDecoder::new(bytes);
        if d.text()? != RECIPE_DOMAIN || d.bytes()? != POLICY {
            return Err(WatchError::InvalidPlan(
                "unknown long-watch detector recipe",
            ));
        }
        let package_digest = d.digest()?;
        let manifest_digest = d.digest()?;
        let model_digest = d.digest()?;
        let contract_digest = d.digest()?;
        let backend = match d.text()? {
            "scalar-reference.v1" => KernelBackend::ScalarReference,
            "optimized-cpu.v1" => KernelBackend::OptimizedCpuV1,
            _ => return Err(WatchError::InvalidPlan("unknown retained detector kernel")),
        };
        if d.digest()? != backend.generation()
            || d.bytes()? != fss_codec_mjpeg::color::rgb_decoder_identity().as_slice()
            || d.digest()?
                != crate::ingest::recorded_decode::video_rgb::video_rgb_transform_identity()
            || d.u64()? != DETECTOR_IMPORT_WORK_UNITS
        {
            return Err(WatchError::InvalidPlan(
                "retained detector semantics changed",
            ));
        }
        let config = CascadeConfig {
            max_inferences: usize_value(&mut d)?,
            frames_per_track: usize_value(&mut d)?,
            minimum_association_iou_ppm: d.u32()?,
            minimum_score_ppm: if d.bool()? { Some(d.u32()?) } else { None },
        };
        let watch_limits = decode_limits(&mut d)?;
        let package_limits = decode_package(&mut d)?;
        d.ensure_finished()?;
        let value = Self {
            package_digest,
            manifest_digest,
            model_digest,
            contract_digest,
            backend,
            config,
            package_limits,
            watch_limits,
        };
        value.validate()?;
        if value.to_bytes() != bytes {
            return Err(WatchError::InvalidPlan(
                "noncanonical long-watch detector recipe",
            ));
        }
        Ok(value)
    }

    /// Decode with an independently pinned content identity.
    pub fn from_retained_bytes(bytes: &[u8], expected: ContentDigest) -> Result<Self> {
        if ContentDigest::sha256(bytes) != expected {
            return Err(WatchError::InvalidPlan(
                "long-watch detector recipe digest mismatch",
            ));
        }
        Self::from_bytes(bytes)
    }
}

fn detector_contract(package: &RgbDetectorPackage, config: CascadeConfig) -> Result<ContentDigest> {
    match config.minimum_score_ppm {
        None => Ok(package.contract().digest()),
        Some(score) => package
            .contract_with_threshold(score)
            .map(|contract| contract.digest())
            .map_err(|_| WatchError::InvalidPlan("invalid long-watch detector contract")),
    }
}

fn reservations_fit(stored: Vec<u8>, allowed: Vec<u8>) -> Result<()> {
    let mut s = CanonicalDecoder::new(&stored);
    let mut a = CanonicalDecoder::new(&allowed);
    while s.remaining() != 0 {
        if s.u64()? > a.u64()? {
            return Err(WatchError::Limit);
        }
    }
    a.ensure_finished()?;
    Ok(())
}
fn watch_bytes(limits: &LongWatchLimits) -> Vec<u8> {
    let mut e = CanonicalEncoder::new();
    encode_limits(&mut e, limits);
    e.finish()
}
fn package_bytes(limits: &PackageDetectLimits) -> Vec<u8> {
    let mut e = CanonicalEncoder::new();
    encode_package(&mut e, limits);
    e.finish()
}

fn encode_rgb(e: &mut CanonicalEncoder, limits: RgbDecodeLimits) {
    for value in [
        limits.frame.maximum_bytes as u64,
        u64::from(limits.frame.maximum_dimension),
        limits.frame.maximum_pixels as u64,
        limits.frame.maximum_markers as u64,
        limits.maximum_output_bytes as u64,
    ] {
        e.u64(value);
    }
}
fn decode_rgb(d: &mut CanonicalDecoder<'_>) -> Result<RgbDecodeLimits> {
    Ok(RgbDecodeLimits {
        frame: fss_codec_mjpeg::DecodeLimits {
            maximum_bytes: usize_value(d)?,
            maximum_dimension: word_value(d)?,
            maximum_pixels: usize_value(d)?,
            maximum_markers: usize_value(d)?,
        },
        maximum_output_bytes: usize_value(d)?,
    })
}
fn encode_package(e: &mut CanonicalEncoder, limits: &PackageDetectLimits) {
    // Preserve the caller's complete package settings, including inactive decoder fields. Native
    // custody/colour decode belongs to the shared watch owner; already-decoded FrameRun input
    // uses only preprocessing, graph execution, output and head fields from these settings.
    // Reuse the bounded source/codec encoding, then append the active RGB/model owners.
    let codecs = LongWatchLimits {
        decode: WatchLimits {
            read_limits: limits.read,
            jpeg_limits: limits.jpeg.frame,
            jpeg_work_units: limits.jpeg_work_units,
            h264_limits: limits.h264,
            h265_limits: limits.h265,
        },
        ..LongWatchLimits::default()
    };
    encode_limits(e, &codecs);
    e.u64(limits.jpeg.maximum_output_bytes as u64);
    encode_rgb(e, limits.run.decode);
    for value in [
        limits.run.preprocess.max_macs,
        limits.run.preprocess.max_bytes as u64,
        limits.run.execution.max_macs,
        limits.run.execution.max_bytes as u64,
        limits.run.maximum_output_bytes as u64,
        limits.detection_work_units,
        limits.detection_scratch_bytes as u64,
    ] {
        e.u64(value);
    }
}
fn decode_package(d: &mut CanonicalDecoder<'_>) -> Result<PackageDetectLimits> {
    let codecs = decode_limits(d)?;
    let expected = LongWatchLimits::default();
    if codecs.maximum_source_chunk_bytes != expected.maximum_source_chunk_bytes
        || codecs.maximum_pixel_samples != expected.maximum_pixel_samples
        || codecs.maximum_assignment_work != expected.maximum_assignment_work
        || codecs.maximum_trace_bytes != expected.maximum_trace_bytes
    {
        return Err(WatchError::InvalidPlan(
            "unknown detector codec reservation encoding",
        ));
    }
    let jpeg = RgbDecodeLimits {
        frame: codecs.decode.jpeg_limits,
        maximum_output_bytes: usize_value(d)?,
    };
    let decode = decode_rgb(d)?;
    let run = RgbRunLimits {
        decode,
        preprocess: ExecBudget::new(d.u64()?, usize_value(d)?),
        execution: ExecBudget::new(d.u64()?, usize_value(d)?),
        maximum_output_bytes: usize_value(d)?,
    };
    Ok(PackageDetectLimits {
        read: codecs.decode.read_limits,
        jpeg,
        jpeg_work_units: codecs.decode.jpeg_work_units,
        h264: codecs.decode.h264_limits,
        h265: codecs.decode.h265_limits,
        run,
        detection_work_units: d.u64()?,
        detection_scratch_bytes: usize_value(d)?,
    })
}

fn usize_value(decoder: &mut CanonicalDecoder<'_>) -> Result<usize> {
    usize::try_from(decoder.u64()?).map_err(|_| WatchError::Limit)
}
fn word_value(decoder: &mut CanonicalDecoder<'_>) -> Result<u32> {
    u32::try_from(decoder.u64()?).map_err(|_| WatchError::Limit)
}
fn encode_limits(encoder: &mut CanonicalEncoder, limits: &LongWatchLimits) {
    let decode = &limits.decode;
    for value in [
        decode.read_limits.max_source_bytes,
        decode.read_limits.max_chunk_bytes,
        decode.read_limits.max_segment_bytes,
        decode.jpeg_limits.maximum_bytes as u64,
        u64::from(decode.jpeg_limits.maximum_dimension),
        decode.jpeg_limits.maximum_pixels as u64,
        decode.jpeg_limits.maximum_markers as u64,
        decode.jpeg_work_units,
        u64::from(decode.h264_limits.max_width),
        u64::from(decode.h264_limits.max_height),
        u64::from(decode.h264_limits.max_macroblocks),
        decode.h264_limits.max_pictures,
        decode.h264_limits.max_nal_bytes as u64,
        u64::from(decode.h264_limits.max_slices_per_picture),
        u64::from(decode.h264_limits.max_reference_frames),
        u64::from(decode.h265_limits.max_width),
        u64::from(decode.h265_limits.max_height),
        decode.h265_limits.max_luma_samples,
        decode.h265_limits.max_pictures,
        decode.h265_limits.max_nal_bytes as u64,
        u64::from(decode.h265_limits.max_slices_per_picture),
        u64::from(decode.h265_limits.max_dpb_pictures),
        limits.maximum_source_chunk_bytes,
        limits.maximum_pixel_samples,
        limits.maximum_assignment_work,
        limits.maximum_trace_bytes as u64,
    ] {
        encoder.u64(value);
    }
}
fn decode_limits(decoder: &mut CanonicalDecoder<'_>) -> Result<LongWatchLimits> {
    let read_limits = RetainedReadLimits {
        max_source_bytes: decoder.u64()?,
        max_chunk_bytes: decoder.u64()?,
        max_segment_bytes: decoder.u64()?,
    };
    let jpeg_limits = fss_codec_mjpeg::DecodeLimits {
        maximum_bytes: usize_value(decoder)?,
        maximum_dimension: word_value(decoder)?,
        maximum_pixels: usize_value(decoder)?,
        maximum_markers: usize_value(decoder)?,
    };
    let jpeg_work_units = decoder.u64()?;
    let h264_limits = fss_codec_h264::DecoderLimits {
        max_width: word_value(decoder)?,
        max_height: word_value(decoder)?,
        max_macroblocks: word_value(decoder)?,
        max_pictures: decoder.u64()?,
        max_nal_bytes: usize_value(decoder)?,
        max_slices_per_picture: word_value(decoder)?,
        max_reference_frames: word_value(decoder)?,
    };
    let h265_limits = fss_codec_h265::DecoderLimits {
        max_width: word_value(decoder)?,
        max_height: word_value(decoder)?,
        max_luma_samples: decoder.u64()?,
        max_pictures: decoder.u64()?,
        max_nal_bytes: usize_value(decoder)?,
        max_slices_per_picture: word_value(decoder)?,
        max_dpb_pictures: word_value(decoder)?,
    };
    Ok(LongWatchLimits {
        decode: WatchLimits {
            read_limits,
            jpeg_limits,
            jpeg_work_units,
            h264_limits,
            h265_limits,
        },
        maximum_source_chunk_bytes: decoder.u64()?,
        maximum_pixel_samples: decoder.u64()?,
        maximum_assignment_work: decoder.u64()?,
        maximum_trace_bytes: usize_value(decoder)?,
    })
}

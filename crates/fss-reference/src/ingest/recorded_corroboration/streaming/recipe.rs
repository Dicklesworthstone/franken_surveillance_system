#![forbid(unsafe_code)]
//! Complete bounded owner recipe, retained beneath both source-analysis roots.

use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest, ContractError};

use super::{
    CorroborationDependencies, CorroborationError, CorroborationOptions, CorroborationPlan,
    LongCorroborationLimits, LongCorroborationReport, PLAN_DOMAIN, POLICY, Result,
    health_policy_bytes,
};
use crate::ingest::RetainedReadLimits;
use crate::ingest::recorded_corroboration::{
    CorroborationCamera, CorroborationGates, GroundHomography, GroundZone, MAX_CORROBORATION_ZONES,
};
use crate::ingest::recorded_decode::ComponentInterpretation;
use crate::ingest::recorded_decode::h264::H264_DECODER_LABEL;
use crate::ingest::recorded_decode::h265::H265_DECODER_LABEL;
use crate::ingest::recorded_watch::{WatchDetectorConfig, WatchLimits, WatchTrackerConfig};
use crate::{ReferenceDeployment, ReplayCx};

/// Hard ceiling checked before parsing or cloning any variable-length recipe fields.
pub const MAX_LONG_CORROBORATION_RECIPE_BYTES: usize = 128 * 1024;

/// Immutable owner inputs needed to repeat the complete native computation. The import identities
/// resolve through retained custody; current source and privacy guards still apply when replayed.
/// This carries owner assertions and configured ceilings, never a calibration or coverage claim.
#[derive(Clone, Debug)]
pub struct LongCorroborationRecipe {
    plan: CorroborationPlan,
    options: CorroborationOptions,
    limits: LongCorroborationLimits,
    dependencies: CorroborationDependencies,
    screened: bool,
}
impl LongCorroborationRecipe {
    /// Validate an exact owner configuration without opening source custody or running a decoder.
    pub fn new(
        plan: &CorroborationPlan,
        options: CorroborationOptions,
        limits: &LongCorroborationLimits,
        dependencies: &CorroborationDependencies,
        screened: bool,
    ) -> Result<Self> {
        plan.validate()?;
        plan.watch_plan(&plan.cameras[0], 1).validate()?;
        limits.validate()?;
        dependencies.validate_for(plan)?;
        let value = Self {
            plan: plan.clone(),
            options,
            limits: *limits,
            dependencies: dependencies.clone(),
            screened,
        };
        if value.to_bytes().len() > MAX_LONG_CORROBORATION_RECIPE_BYTES {
            return Err(CorroborationError::Limit);
        }
        Ok(value)
    }
    /// Both import identities, matrices, ground rectangles, gates and perception settings.
    pub fn plan(&self) -> &CorroborationPlan {
        &self.plan
    }
    /// Exact declared gap/recovery behavior.
    pub const fn options(&self) -> CorroborationOptions {
        self.options
    }
    /// All retained-read, JPEG/AVC/HEVC decode and aggregate per-camera ceilings.
    pub const fn limits(&self) -> &LongCorroborationLimits {
        &self.limits
    }
    /// Canonical owner common-cause declarations, including explicit empty declarations.
    pub fn dependencies(&self) -> &CorroborationDependencies {
        &self.dependencies
    }
    /// Whether the retained fixed conservative health policy was selected for this computation.
    pub const fn health_screened(&self) -> bool {
        self.screened
    }
    /// Exact content identity of the complete recipe, also reported as the streaming plan digest.
    pub fn digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.to_bytes())
    }

    /// Canonical full configuration. Decoder identities and health-policy bytes prevent a future
    /// implementation from silently interpreting these inputs under different semantics.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(PLAN_DOMAIN);
        encoder.bytes(POLICY);
        encoder.bytes(&fss_codec_mjpeg::decoder_identity());
        encoder.text(H264_DECODER_LABEL);
        encoder.text(H265_DECODER_LABEL);
        encoder.bytes(health_policy_bytes());
        encoder.digest(self.plan.digest());
        for camera in &self.plan.cameras {
            encoder.text(&camera.name);
            encoder.digest(camera.import_identity);
            camera.homography.encode(&mut encoder);
        }
        encoder.u8(match self.plan.interpretation {
            ComponentInterpretation::Grayscale => 0,
            ComponentInterpretation::YCbCr => 1,
        });
        encoder.u64(self.plan.zones.len() as u64);
        for zone in &self.plan.zones {
            encoder.text(&zone.zone_id);
            for value in [zone.x, zone.y, zone.width, zone.height] {
                encoder.u64(value.to_bits());
            }
        }
        encoder.u64(self.plan.gates.time_gate_ns);
        encoder.u64(self.plan.gates.distance_gate.to_bits());
        for value in [
            self.plan.detector.base_threshold,
            self.plan.detector.threshold_sigma,
            self.plan.detector.learning_rate_num,
            self.plan.detector.learning_rate_den,
        ] {
            encoder.u32(u32::from(value));
        }
        encoder.u64(self.plan.detector.minimum_region_pixels as u64);
        encoder.u32(self.plan.tracker.confirmation_hits);
        encoder.u32(self.plan.tracker.maximum_missed_frames);
        encoder.u32(self.plan.tracker.minimum_iou_ppm);
        encoder.bool(self.options.tolerate_decode_refusals);
        encoder.bool(self.screened);
        encoder.bytes(&self.dependencies.to_bytes());
        encode_limits(&mut encoder, &self.limits);
        // The immutable constructor bounds the whole record below the fixed canonical ceiling.
        encoder.finish()
    }

    /// Recover exact owner inputs from custody bytes and an independently pinned recipe digest.
    /// Unknown semantics, a mismatched digest, overlong counts and trailing bytes are refused.
    /// Successful parsing alone does not grant authority; [`Self::analyze`] reopens both sources.
    pub fn from_retained_bytes(bytes: &[u8], expected: ContentDigest) -> Result<Self> {
        if bytes.len() > MAX_LONG_CORROBORATION_RECIPE_BYTES {
            return Err(CorroborationError::Limit);
        }
        if ContentDigest::sha256(bytes) != expected {
            return Err(ContractError::DigestMismatch.into());
        }
        let mut decoder = CanonicalDecoder::new(bytes);
        if decoder.text()? != PLAN_DOMAIN
            || decoder.bytes()? != POLICY
            || decoder.bytes()? != fss_codec_mjpeg::decoder_identity().as_slice()
            || decoder.text()? != H264_DECODER_LABEL
            || decoder.text()? != H265_DECODER_LABEL
            || decoder.bytes()? != health_policy_bytes()
        {
            return Err(CorroborationError::InvalidPlan(
                "unknown streaming recipe or decoder/health semantics",
            ));
        }
        let declared_plan = decoder.digest()?;
        let mut cameras = Vec::with_capacity(2);
        for _ in 0..2 {
            let name = decoder.text()?.to_owned();
            let import_identity = decoder.digest()?;
            let mut matrix = [0.0; 9];
            for value in &mut matrix {
                *value = f64::from_bits(decoder.u64()?);
            }
            cameras.push(CorroborationCamera {
                name,
                import_identity,
                homography: GroundHomography { matrix },
            });
        }
        let interpretation = match decoder.u8()? {
            0 => ComponentInterpretation::Grayscale,
            1 => ComponentInterpretation::YCbCr,
            _ => {
                return Err(CorroborationError::InvalidPlan(
                    "unknown component interpretation",
                ));
            }
        };
        let count = usize_value(&mut decoder)?;
        if !(1..=MAX_CORROBORATION_ZONES).contains(&count) {
            return Err(CorroborationError::Limit);
        }
        let mut zones = Vec::with_capacity(count);
        for _ in 0..count {
            zones.push(GroundZone {
                zone_id: decoder.text()?.to_owned(),
                x: f64::from_bits(decoder.u64()?),
                y: f64::from_bits(decoder.u64()?),
                width: f64::from_bits(decoder.u64()?),
                height: f64::from_bits(decoder.u64()?),
            });
        }
        let gates = CorroborationGates {
            time_gate_ns: decoder.u64()?,
            distance_gate: f64::from_bits(decoder.u64()?),
        };
        let detector = WatchDetectorConfig {
            base_threshold: short_value(&mut decoder)?,
            threshold_sigma: short_value(&mut decoder)?,
            learning_rate_num: short_value(&mut decoder)?,
            learning_rate_den: short_value(&mut decoder)?,
            minimum_region_pixels: usize_value(&mut decoder)?,
        };
        let tracker = WatchTrackerConfig {
            confirmation_hits: decoder.u32()?,
            maximum_missed_frames: decoder.u32()?,
            minimum_iou_ppm: decoder.u32()?,
        };
        let options = CorroborationOptions {
            tolerate_decode_refusals: decoder.bool()?,
        };
        let screened = decoder.bool()?;
        let dependencies = CorroborationDependencies::from_bytes(decoder.bytes()?)?;
        let limits = decode_limits(&mut decoder)?;
        decoder.ensure_finished()?;
        let plan = CorroborationPlan {
            cameras: cameras.try_into().map_err(|_| CorroborationError::Limit)?,
            interpretation,
            zones,
            gates,
            detector,
            tracker,
        };
        if plan.digest() != declared_plan {
            return Err(ContractError::DigestMismatch.into());
        }
        let value = Self::new(&plan, options, &limits, &dependencies, screened)?;
        if value.to_bytes() != bytes {
            return Err(ContractError::NonCanonicalOrdering.into());
        }
        Ok(value)
    }

    /// Repeat this full recipe from retained imports, applying each sensor's current privacy
    /// policy. A changed privacy generation changes analysis and exact approval identities.
    pub fn analyze(
        &self,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
    ) -> Result<LongCorroborationReport> {
        let analyze = if self.screened {
            LongCorroborationReport::analyze_screened
        } else {
            LongCorroborationReport::analyze
        };
        analyze(
            deployment,
            &self.plan,
            self.options,
            &self.limits,
            &self.dependencies,
            cx,
        )
    }
}

fn usize_value(decoder: &mut CanonicalDecoder<'_>) -> Result<usize> {
    usize::try_from(decoder.u64()?).map_err(|_| CorroborationError::Limit)
}
fn short_value(decoder: &mut CanonicalDecoder<'_>) -> Result<u16> {
    u16::try_from(decoder.u32()?).map_err(|_| CorroborationError::Limit)
}
fn word_value(decoder: &mut CanonicalDecoder<'_>) -> Result<u32> {
    u32::try_from(decoder.u64()?).map_err(|_| CorroborationError::Limit)
}
fn encode_limits(encoder: &mut CanonicalEncoder, limits: &LongCorroborationLimits) {
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
fn decode_limits(decoder: &mut CanonicalDecoder<'_>) -> Result<LongCorroborationLimits> {
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
    Ok(LongCorroborationLimits {
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

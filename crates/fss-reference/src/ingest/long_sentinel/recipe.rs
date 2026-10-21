#![forbid(unsafe_code)]
//! Exact source, schedule, model, kernel and resource settings for cold sentinel replay.

use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest, DigestAlgorithm};

use super::retained::{LongSentinelRetentionError as Error, Result};
use super::{LongSentinelConfig, LongSentinelLimits, LongSentinelPlan, LongSentinelRequest};
use crate::KernelBackend;
use crate::ingest::long_watch::detector::recipe::{
    DETECTOR_IMPORT_WORK_UNITS, decode_package, encode_package, package_bytes, reservations_fit,
};
use crate::ingest::recorded_decode::ComponentInterpretation;
use crate::ingest::recorded_decode::video_budget::{
    VIDEO_DECODE_SEPARATE_AXIS_POLICY, VIDEO_DECODE_WORK_MODEL,
};
use crate::ingest::rgb_package::RgbDetectorPackage;

pub(super) const DOMAIN: &str = "fss.long_sentinel_recipe.v1";
pub(super) const MAX_BYTES: usize = 8192;
const POLICY: &[u8] = b"long-sentinel-replay-v1:original-whole-decode-range:\
motion-independent-whole-burst-prefix:complete-model-archive:exact-native-kernel:\
all-original-reservations:current-privacy:no-gap-bridging:no-absence:no-effect-authority";

#[derive(Clone, Debug)]
pub(super) struct Recipe {
    pub(super) request: LongSentinelRequest,
    pub(super) config: LongSentinelConfig,
    pub(super) limits: LongSentinelLimits,
    pub(super) package: ContentDigest,
    pub(super) manifest: ContentDigest,
    pub(super) model: ContentDigest,
    pub(super) graph: ContentDigest,
    pub(super) contract: ContentDigest,
    pub(super) backend: KernelBackend,
}

impl Recipe {
    pub(super) fn new(
        package: &RgbDetectorPackage,
        request: &LongSentinelRequest,
        config: LongSentinelConfig,
        limits: &LongSentinelLimits,
    ) -> Result<Self> {
        let value = Self {
            request: request.clone(),
            config,
            limits: *limits,
            package: package.archive_digest(),
            manifest: package.manifest_digest(),
            model: package.model().digest(),
            graph: package.graph_digest(),
            contract: contract(package, request.minimum_score_ppm)?,
            backend: package.model().backend(),
        };
        value.validate()?;
        Ok(value)
    }

    pub(super) fn plan(&self) -> Result<LongSentinelPlan> {
        Ok(LongSentinelPlan::new(
            self.request.first_segment,
            self.request.segment_count,
            self.config,
        )?)
    }

    fn validate(&self) -> Result<()> {
        self.limits.validate()?;
        self.plan()?.reservation(&self.limits)?;
        if self
            .request
            .minimum_score_ppm
            .is_some_and(|score| score > 1_000_000)
        {
            return Err(Error::InvalidRecord);
        }
        for identity in [
            self.request.import_identity,
            self.package,
            self.manifest,
            self.model,
            self.graph,
            self.contract,
        ] {
            valid_digest(identity)?;
        }
        Ok(())
    }

    /// Stored reservations are admitted as a whole; replay never replaces them with the
    /// current ceilings, even when the replacement would happen to reproduce this fixture.
    pub(super) fn validate_within(&self, allowed: &LongSentinelLimits) -> Result<()> {
        self.validate()?;
        allowed.validate()?;
        if self.limits.maximum_source_chunk_bytes > allowed.maximum_source_chunk_bytes
            || self.limits.maximum_pixel_samples > allowed.maximum_pixel_samples
            || self.limits.maximum_report_bytes > allowed.maximum_report_bytes
        {
            return Err(Error::Limit);
        }
        reservations_fit(
            package_bytes(&self.limits.package),
            package_bytes(&allowed.package),
        )?;
        Ok(())
    }

    pub(super) fn verify_package(&self, package: &RgbDetectorPackage) -> Result<()> {
        if package.archive_digest() != self.package
            || package.manifest_digest() != self.manifest
            || package.model().digest() != self.model
            || package.graph_digest() != self.graph
            || package.model().backend() != self.backend
            || contract(package, self.request.minimum_score_ppm)? != self.contract
        {
            return Err(Error::InvalidRecord);
        }
        Ok(())
    }

    pub(super) fn import_work_units(&self) -> u64 {
        DETECTOR_IMPORT_WORK_UNITS
    }

    pub(super) fn encode(&self) -> Vec<u8> {
        let mut e = CanonicalEncoder::new();
        e.text(DOMAIN);
        e.bytes(POLICY);
        for digest in [
            self.package,
            self.manifest,
            self.model,
            self.graph,
            self.contract,
        ] {
            e.digest(digest);
        }
        e.text(self.backend.stable_id());
        e.digest(self.backend.generation());
        e.bytes(&fss_codec_mjpeg::color::rgb_decoder_identity());
        e.digest(crate::ingest::recorded_decode::video_rgb::video_rgb_transform_identity());
        e.text(VIDEO_DECODE_WORK_MODEL);
        e.text(VIDEO_DECODE_SEPARATE_AXIS_POLICY);
        e.u64(DETECTOR_IMPORT_WORK_UNITS);
        e.digest(self.request.import_identity);
        e.u64(self.request.first_segment as u64);
        e.u64(self.request.segment_count as u64);
        e.u8(match self.request.interpretation {
            ComponentInterpretation::Grayscale => 0,
            ComponentInterpretation::YCbCr => 1,
        });
        match self.request.minimum_score_ppm {
            Some(score) => {
                e.bool(true);
                e.u32(score);
            }
            None => e.bool(false),
        }
        e.u64(self.config.every_frames as u64);
        e.u64(self.config.burst_frames as u64);
        e.u64(self.config.max_inferences as u64);
        encode_package(&mut e, &self.limits.package);
        e.u64(self.limits.maximum_source_chunk_bytes);
        e.u64(self.limits.maximum_pixel_samples);
        e.u64(self.limits.maximum_report_bytes as u64);
        e.finish()
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_BYTES {
            return Err(Error::Limit);
        }
        let mut d = CanonicalDecoder::new(bytes);
        if d.text()? != DOMAIN || d.bytes()? != POLICY {
            return Err(Error::InvalidRecord);
        }
        let package = digest(&mut d)?;
        let manifest = digest(&mut d)?;
        let model = digest(&mut d)?;
        let graph = digest(&mut d)?;
        let contract = digest(&mut d)?;
        let backend = match d.text()? {
            "scalar-reference.v1" => KernelBackend::ScalarReference,
            "optimized-cpu.v1" => KernelBackend::OptimizedCpuV1,
            _ => return Err(Error::InvalidRecord),
        };
        if d.digest()? != backend.generation()
            || d.bytes()? != fss_codec_mjpeg::color::rgb_decoder_identity().as_slice()
            || d.digest()?
                != crate::ingest::recorded_decode::video_rgb::video_rgb_transform_identity()
            || d.text()? != VIDEO_DECODE_WORK_MODEL
            || d.text()? != VIDEO_DECODE_SEPARATE_AXIS_POLICY
            || d.u64()? != DETECTOR_IMPORT_WORK_UNITS
        {
            return Err(Error::InvalidRecord);
        }
        let request = LongSentinelRequest {
            import_identity: digest(&mut d)?,
            first_segment: usize_value(&mut d)?,
            segment_count: usize_value(&mut d)?,
            interpretation: match d.u8()? {
                0 => ComponentInterpretation::Grayscale,
                1 => ComponentInterpretation::YCbCr,
                _ => return Err(Error::InvalidRecord),
            },
            minimum_score_ppm: if d.bool()? { Some(d.u32()?) } else { None },
        };
        let config = LongSentinelConfig {
            every_frames: usize_value(&mut d)?,
            burst_frames: usize_value(&mut d)?,
            max_inferences: usize_value(&mut d)?,
        };
        let limits = LongSentinelLimits {
            package: decode_package(&mut d)?,
            maximum_source_chunk_bytes: d.u64()?,
            maximum_pixel_samples: d.u64()?,
            maximum_report_bytes: usize_value(&mut d)?,
        };
        d.ensure_finished()?;
        let value = Self {
            request,
            config,
            limits,
            package,
            manifest,
            model,
            graph,
            contract,
            backend,
        };
        value.validate()?;
        if value.encode() != bytes {
            return Err(Error::InvalidRecord);
        }
        Ok(value)
    }
}

fn contract(package: &RgbDetectorPackage, threshold: Option<u32>) -> Result<ContentDigest> {
    match threshold {
        None => Ok(package.contract().digest()),
        Some(score) => package
            .contract_with_threshold(score)
            .map(|contract| contract.digest())
            .map_err(|_| Error::InvalidRecord),
    }
}

pub(super) fn valid_digest(value: ContentDigest) -> Result<()> {
    if value.algorithm() != DigestAlgorithm::Sha256 || value.bytes() == [0; 32] {
        return Err(Error::InvalidRecord);
    }
    Ok(())
}

pub(super) fn digest(decoder: &mut CanonicalDecoder<'_>) -> Result<ContentDigest> {
    let value = decoder.digest()?;
    valid_digest(value)?;
    Ok(value)
}

pub(super) fn usize_value(decoder: &mut CanonicalDecoder<'_>) -> Result<usize> {
    usize::try_from(decoder.u64()?).map_err(|_| Error::Limit)
}

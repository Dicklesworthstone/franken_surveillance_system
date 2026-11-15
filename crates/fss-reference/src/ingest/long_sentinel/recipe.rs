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
    // Preserve saved numerical identities during custody-only inspection. Current source labels
    // may change; decoding must not silently rewrite a historical recipe under those labels.
    backend_generation: ContentDigest,
    jpeg_rgb_generation: [u8; 32],
    video_rgb_generation: ContentDigest,
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
            backend_generation: package.model().backend().generation(),
            jpeg_rgb_generation: fss_codec_mjpeg::color::rgb_decoder_identity(),
            video_rgb_generation:
                crate::ingest::recorded_decode::video_rgb::video_rgb_transform_identity(),
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
            self.backend_generation,
            self.video_rgb_generation,
        ] {
            valid_digest(identity)?;
        }
        if self.jpeg_rgb_generation == [0; 32] {
            return Err(Error::InvalidRecord);
        }
        Ok(())
    }

    pub(super) fn replay_compatible(&self) -> bool {
        self.backend_generation == self.backend.generation()
            && self.jpeg_rgb_generation == fss_codec_mjpeg::color::rgb_decoder_identity()
            && self.video_rgb_generation
                == crate::ingest::recorded_decode::video_rgb::video_rgb_transform_identity()
    }

    pub(super) fn verify_replay_profile(&self) -> Result<()> {
        if !self.replay_compatible() {
            return Err(Error::ProfileChanged);
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
        e.digest(self.backend_generation);
        e.bytes(&self.jpeg_rgb_generation);
        e.digest(self.video_rgb_generation);
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
        let backend_generation = digest(&mut d)?;
        let jpeg_rgb_generation = d.bytes()?.try_into().map_err(|_| Error::InvalidRecord)?;
        let video_rgb_generation = digest(&mut d)?;
        if d.text()? != VIDEO_DECODE_WORK_MODEL
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
            backend_generation,
            jpeg_rgb_generation,
            video_rgb_generation,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn recipe() -> Recipe {
        Recipe {
            request: LongSentinelRequest {
                import_identity: ContentDigest::sha256(b"source import"),
                first_segment: 0,
                segment_count: 3,
                interpretation: ComponentInterpretation::YCbCr,
                minimum_score_ppm: None,
            },
            config: LongSentinelConfig {
                every_frames: 3,
                burst_frames: 1,
                max_inferences: 1,
            },
            limits: LongSentinelLimits::default(),
            package: ContentDigest::sha256(b"archive"),
            manifest: ContentDigest::sha256(b"manifest"),
            model: ContentDigest::sha256(b"model"),
            graph: ContentDigest::sha256(b"graph"),
            contract: ContentDigest::sha256(b"contract"),
            backend: KernelBackend::ScalarReference,
            backend_generation: KernelBackend::ScalarReference.generation(),
            jpeg_rgb_generation: fss_codec_mjpeg::color::rgb_decoder_identity(),
            video_rgb_generation:
                crate::ingest::recorded_decode::video_rgb::video_rgb_transform_identity(),
        }
    }

    #[test]
    fn historical_numerical_generations_roundtrip_exactly_but_refuse_execution() -> Result<()> {
        let current = recipe();
        assert!(Recipe::decode(&current.encode())?.replay_compatible());
        for changed in 0..3 {
            let mut saved = current.clone();
            let historical = ContentDigest::sha256(b"historical numerical generation");
            match changed {
                0 => saved.backend_generation = historical,
                1 => saved.jpeg_rgb_generation = historical.bytes(),
                _ => saved.video_rgb_generation = historical,
            }
            let original = saved.encode();
            let decoded = Recipe::decode(&original)?;
            assert_eq!(
                decoded.encode(),
                original,
                "inspection rewrote saved identity"
            );
            assert!(!decoded.replay_compatible());
            assert!(matches!(
                decoded.verify_replay_profile(),
                Err(Error::ProfileChanged)
            ));
            assert_eq!(decoded.request, current.request);
            assert_eq!(decoded.package, current.package);
            assert_eq!(decoded.model, current.model);
            assert_eq!(decoded.graph, current.graph);
            assert_eq!(decoded.contract, current.contract);
        }
        Ok(())
    }

    #[test]
    fn historical_profile_syntax_stays_strictly_bounded_and_nonzero() {
        for invalid in 0..3 {
            let mut saved = recipe();
            match invalid {
                0 => {
                    saved.backend_generation = ContentDigest::new(DigestAlgorithm::Sha256, [0; 32])
                }
                1 => saved.jpeg_rgb_generation = [0; 32],
                _ => {
                    saved.video_rgb_generation =
                        ContentDigest::new(DigestAlgorithm::Sha256, [0; 32])
                }
            }
            assert!(Recipe::decode(&saved.encode()).is_err());
        }
        let mut trailing = recipe().encode();
        trailing.push(0);
        assert!(Recipe::decode(&trailing).is_err());
    }
}

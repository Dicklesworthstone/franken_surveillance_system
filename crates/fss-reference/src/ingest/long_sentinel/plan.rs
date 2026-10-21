#![forbid(unsafe_code)]
//! Pure finite schedules and checked whole-operation resource reservations.

use std::collections::BTreeSet;

use fss_codec_mjpeg::ComponentInterpretation;
use fss_core::{CanonicalEncoder, ContentDigest};

use super::LONG_SENTINEL_POLICY;
use crate::ingest::long_watch::MAX_LONG_WATCH_FRAMES;
use crate::ingest::long_watch::detector::recipe::encode_package;
use crate::ingest::package_detect::sentinel::{MAX_SENTINEL_BURST_FRAMES, SentinelBurst};
use crate::ingest::package_detect::{
    MAX_PACKAGE_DETECT_FRAMES, PackageDetectError, PackageDetectLimits,
};
use crate::ingest::recorded_decode::video_budget::{
    VIDEO_DECODE_SEPARATE_AXIS_POLICY, VIDEO_DECODE_WORK_MODEL,
};

/// Hard cumulative source-chunk read ceiling, including verified HTTP/RTSP source origins.
pub const MAX_LONG_SENTINEL_SOURCE_CHUNK_BYTES: u64 = 512 * 1024 * 1024;
/// Hard cumulative decoded pixel ceiling. This counts each decoded raster once, not RGB bytes.
pub const MAX_LONG_SENTINEL_PIXEL_SAMPLES: u64 = 64 * 1024 * 1024 * 1024;
/// Hard complete rendered aggregate ceiling; reports are never truncated to fit it.
pub const MAX_LONG_SENTINEL_REPORT_BYTES: usize = 16 * 1024 * 1024;

/// Exact retained range and native image interpretation, independent of foreground activity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LongSentinelRequest {
    /// Exact completed retained import.
    pub import_identity: ContentDigest,
    /// First zero-based source segment; AVC/HEVC must start at an IDR/IRAP.
    pub first_segment: usize,
    /// Requested source segments, at most [`MAX_LONG_WATCH_FRAMES`].
    pub segment_count: usize,
    /// Explicit JPEG interpretation; native AVC/HEVC require YCbCr.
    pub interpretation: ComponentInterpretation,
    /// Package threshold unless an explicit inclusive ppm threshold is supplied.
    pub minimum_score_ppm: Option<u32>,
}

/// Motion-independent schedule and one inference allowance for the complete source range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LongSentinelConfig {
    /// Distance between burst starts, 1..=[`MAX_LONG_WATCH_FRAMES`].
    pub every_frames: usize,
    /// Consecutive segments in a burst, 1..=8 and no larger than the period.
    pub burst_frames: usize,
    /// Total admitted frames, at least one complete burst and at most 64.
    pub max_inferences: usize,
}
impl Default for LongSentinelConfig {
    fn default() -> Self {
        Self {
            every_frames: 16,
            burst_frames: 3,
            max_inferences: 12,
        }
    }
}
impl LongSentinelConfig {
    /// Validate before source custody, decoding, or model execution.
    pub fn validate(&self) -> Result<(), PackageDetectError> {
        if !(1..=MAX_LONG_WATCH_FRAMES).contains(&self.every_frames)
            || !(1..=MAX_SENTINEL_BURST_FRAMES).contains(&self.burst_frames)
            || self.burst_frames > self.every_frames
            || self.max_inferences < self.burst_frames
            || self.max_inferences > MAX_PACKAGE_DETECT_FRAMES
        {
            return Err(PackageDetectError::InvalidRequest);
        }
        Ok(())
    }
}

/// Native per-frame ceilings plus nonrenewable whole-operation bounds.
#[derive(Clone, Copy, Debug)]
pub struct LongSentinelLimits {
    /// Existing native source/decode/inference/head limits, with shared JPEG and head work.
    pub package: PackageDetectLimits,
    /// Total source bytes fetched, including original HTTP/RTSP custody verification.
    pub maximum_source_chunk_bytes: u64,
    /// Cumulative pixel admission. JPEG checks actual SOF dimensions before reconstruction;
    /// video reserves the configured coded-luma capacity per access unit before native decode,
    /// including buffered and skipped pictures. Actual returned raster usage is also reported.
    pub maximum_pixel_samples: u64,
    /// Complete aggregate report byte ceiling, including all ordinary child reports.
    pub maximum_report_bytes: usize,
}
impl Default for LongSentinelLimits {
    fn default() -> Self {
        Self {
            package: PackageDetectLimits::default(),
            maximum_source_chunk_bytes: MAX_LONG_SENTINEL_SOURCE_CHUNK_BYTES,
            maximum_pixel_samples: 1024 * 1024 * 1024,
            maximum_report_bytes: MAX_LONG_SENTINEL_REPORT_BYTES,
        }
    }
}
impl LongSentinelLimits {
    /// Admit whole-operation bounds before opening any retained source.
    /// Native owners still validate each codec/model bound at its own boundary.
    pub fn validate(&self) -> Result<(), PackageDetectError> {
        if !(1..=MAX_LONG_SENTINEL_SOURCE_CHUNK_BYTES).contains(&self.maximum_source_chunk_bytes)
            || !(1..=MAX_LONG_SENTINEL_PIXEL_SAMPLES).contains(&self.maximum_pixel_samples)
            || !(1..=MAX_LONG_SENTINEL_REPORT_BYTES).contains(&self.maximum_report_bytes)
        {
            return Err(PackageDetectError::InvalidRequest);
        }
        Ok(())
    }

    /// Every exact source, codec, inference, head, and whole-operation resource choice.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.long_sentinel_limits.v1");
        encode_package(&mut encoder, &self.package);
        encoder.u64(self.maximum_source_chunk_bytes);
        encoder.u64(self.maximum_pixel_samples);
        encoder.u64(self.maximum_report_bytes as u64);
        ContentDigest::sha256(&encoder.finish())
    }
}

/// Checked ceilings, not a claim that every reserved operation or byte was consumed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LongSentinelReservation {
    /// Whole-operation source-read allowance.
    pub source_chunk_bytes: u64,
    /// Whole-operation decoded raster allowance.
    pub pixel_samples: u64,
    /// Independent encoded-byte ceiling for native video work, excluding original-custody reads.
    pub video_encoded_bytes: u64,
    /// Independent pre-codec video capacity ceiling, including decode-ahead and skipped pictures.
    pub video_coded_luma_capacity: u64,
    /// Checked sum of the two independent native video admission axes; no borrowing between them.
    pub video_decode_work_units: u64,
    /// Shared cumulative JPEG decoder work.
    pub jpeg_work_units: u64,
    /// Shared cumulative detection-head work.
    pub detection_work_units: u64,
    /// Frames actually admitted by the pure schedule, at most 64.
    pub inferences: usize,
    /// Checked admitted count times the per-frame preprocessing ceiling.
    pub preprocess_macs: u64,
    /// Checked admitted count times the per-frame neural execution ceiling.
    pub execution_macs: u64,
    /// Checked admitted count times the per-frame complete-output allowance.
    pub output_bytes: u64,
    /// Complete rendered report allowance.
    pub report_bytes: usize,
}

/// One maximal unsampled source range, inclusive start plus length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LongSentinelRange {
    /// First source segment in this range.
    pub first_segment: usize,
    /// Number of consecutive source segments not admitted to inference.
    pub segment_count: usize,
}

/// Validated immutable schedule; no caller-provided set can bypass inference admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LongSentinelPlan {
    first: usize,
    count: usize,
    config: LongSentinelConfig,
    bursts: Vec<SentinelBurst>,
}
impl LongSentinelPlan {
    /// Compile all full bursts, preserving explicit later budget refusals and an unsampled tail.
    pub fn new(
        first_segment: usize,
        segment_count: usize,
        config: LongSentinelConfig,
    ) -> Result<Self, PackageDetectError> {
        config.validate()?;
        let end = first_segment
            .checked_add(segment_count)
            .ok_or(PackageDetectError::InvalidRequest)?;
        if segment_count < config.burst_frames
            || segment_count > MAX_LONG_WATCH_FRAMES
            || u64::try_from(end).is_err()
        {
            return Err(PackageDetectError::InvalidRequest);
        }
        let mut bursts = Vec::new();
        let mut remaining = config.max_inferences;
        for offset in (0..segment_count).step_by(config.every_frames) {
            if config.burst_frames > segment_count - offset {
                break;
            }
            let admitted = remaining >= config.burst_frames;
            if admitted {
                remaining -= config.burst_frames;
            }
            bursts.push(SentinelBurst {
                first_segment: first_segment + offset,
                segment_count: config.burst_frames,
                admitted,
            });
        }
        Ok(Self {
            first: first_segment,
            count: segment_count,
            config,
            bursts,
        })
    }

    /// First requested source segment.
    #[must_use]
    pub const fn first_segment(&self) -> usize {
        self.first
    }
    /// Complete requested source range length.
    #[must_use]
    pub const fn segment_count(&self) -> usize {
        self.count
    }
    /// Exact sampling and inference-admission choices.
    #[must_use]
    pub const fn config(&self) -> LongSentinelConfig {
        self.config
    }
    /// All full scheduled bursts in source order, including every budget refusal.
    #[must_use]
    pub fn bursts(&self) -> &[SentinelBurst] {
        &self.bursts
    }
    /// Exact selected source segments, never more than 64.
    #[must_use]
    pub fn selected_segments(&self) -> BTreeSet<usize> {
        self.bursts
            .iter()
            .filter(|burst| burst.admitted)
            .flat_map(|burst| burst.first_segment..burst.first_segment + burst.segment_count)
            .collect()
    }
    /// Compact complement of the admitted set; at most 65 maximal ranges.
    #[must_use]
    pub fn unsampled_ranges(&self) -> Vec<LongSentinelRange> {
        let mut ranges = Vec::new();
        let mut next = self.first;
        for segment in self.selected_segments() {
            if next < segment {
                ranges.push(LongSentinelRange {
                    first_segment: next,
                    segment_count: segment - next,
                });
            }
            next = segment + 1;
        }
        let end = self.first + self.count;
        if next < end {
            ranges.push(LongSentinelRange {
                first_segment: next,
                segment_count: end - next,
            });
        }
        ranges
    }
    /// Sampling identity, separate from source/model identity and exact resource limits.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(LONG_SENTINEL_POLICY);
        encoder.text(VIDEO_DECODE_WORK_MODEL);
        encoder.text(VIDEO_DECODE_SEPARATE_AXIS_POLICY);
        for value in [
            self.first,
            self.count,
            self.config.every_frames,
            self.config.burst_frames,
            self.config.max_inferences,
        ] {
            encoder.u64(value as u64);
        }
        ContentDigest::sha256(&encoder.finish())
    }
    /// Check every aggregate inference reservation before any source read or model execution.
    pub fn reservation(
        &self,
        limits: &LongSentinelLimits,
    ) -> Result<LongSentinelReservation, PackageDetectError> {
        limits.validate()?;
        let inferences = self.selected_segments().len();
        let count = u64::try_from(inferences).map_err(|_| PackageDetectError::InvalidRequest)?;
        let product = |per_frame: u64| {
            count
                .checked_mul(per_frame)
                .ok_or(PackageDetectError::InvalidRequest)
        };
        Ok(LongSentinelReservation {
            source_chunk_bytes: limits.maximum_source_chunk_bytes,
            pixel_samples: limits.maximum_pixel_samples,
            video_encoded_bytes: limits.maximum_source_chunk_bytes,
            video_coded_luma_capacity: limits.maximum_pixel_samples,
            video_decode_work_units: limits
                .maximum_source_chunk_bytes
                .checked_add(limits.maximum_pixel_samples)
                .ok_or(PackageDetectError::InvalidRequest)?,
            jpeg_work_units: limits.package.jpeg_work_units,
            detection_work_units: limits.package.detection_work_units,
            inferences,
            preprocess_macs: product(limits.package.run.preprocess.max_macs)?,
            execution_macs: product(limits.package.run.execution.max_macs)?,
            output_bytes: product(
                u64::try_from(limits.package.run.maximum_output_bytes)
                    .map_err(|_| PackageDetectError::InvalidRequest)?,
            )?,
            report_bytes: limits.maximum_report_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn samples_past_short_ranges_without_a_motion_input() -> Result<(), PackageDetectError> {
        let config = LongSentinelConfig {
            every_frames: 1024,
            burst_frames: 3,
            max_inferences: 9,
        };
        let plan = LongSentinelPlan::new(17, 4096, config)?;
        assert_eq!(
            plan.selected_segments(),
            BTreeSet::from([17, 18, 19, 1041, 1042, 1043, 2065, 2066, 2067])
        );
        assert_eq!(plan.bursts().len(), 4);
        assert!(!plan.bursts()[3].admitted);
        assert_eq!(plan.bursts()[3].first_segment, 3089);
        assert_eq!(plan.unsampled_ranges().len(), 3);
        assert_eq!(
            plan.unsampled_ranges().last(),
            Some(&LongSentinelRange {
                first_segment: 2068,
                segment_count: 2045,
            })
        );
        Ok(())
    }

    #[test]
    fn complete_burst_prefix_and_compact_complement_match_membership_oracle()
    -> Result<(), PackageDetectError> {
        for count in [1, 2, 7, 63, 64, 65, 127, 1025, MAX_LONG_WATCH_FRAMES] {
            for every in [1, 3, 8, 64, 65, 1024, MAX_LONG_WATCH_FRAMES] {
                for burst in [1, 3, 8].into_iter().filter(|b| *b <= every && *b <= count) {
                    for budget in [burst, (burst + 1).min(64), 64] {
                        let config = LongSentinelConfig {
                            every_frames: every,
                            burst_frames: burst,
                            max_inferences: budget,
                        };
                        let plan = LongSentinelPlan::new(37, count, config)?;
                        let expected: BTreeSet<usize> = (0..count)
                            .filter(|offset| {
                                let group = offset / every;
                                offset % every < burst
                                    && group * every + burst <= count
                                    && (group + 1) * burst <= budget
                            })
                            .map(|offset| 37 + offset)
                            .collect();
                        assert_eq!(plan.selected_segments(), expected);
                        let ranges = plan.unsampled_ranges();
                        assert!(ranges.len() <= MAX_PACKAGE_DETECT_FRAMES + 1);
                        let unsampled: BTreeSet<_> = ranges
                            .into_iter()
                            .flat_map(|range| {
                                range.first_segment..range.first_segment + range.segment_count
                            })
                            .collect();
                        assert!(expected.is_disjoint(&unsampled));
                        assert_eq!(expected.len() + unsampled.len(), count);
                        assert_eq!(
                            expected.union(&unsampled).copied().collect::<Vec<_>>(),
                            (37..37 + count).collect::<Vec<_>>()
                        );
                    }
                }
            }
        }
        Ok(())
    }

    #[test]
    fn schedule_cannot_renew_inference_or_decode_allowances() -> Result<(), PackageDetectError> {
        let config = LongSentinelConfig {
            every_frames: 2,
            burst_frames: 2,
            max_inferences: 5,
        };
        let plan = LongSentinelPlan::new(0, MAX_LONG_WATCH_FRAMES, config)?;
        let limits = LongSentinelLimits::default();
        let reservation = plan.reservation(&limits)?;
        assert_eq!(reservation.inferences, 4);
        assert_eq!(
            reservation.video_encoded_bytes,
            limits.maximum_source_chunk_bytes
        );
        assert_eq!(
            reservation.video_coded_luma_capacity,
            limits.maximum_pixel_samples
        );
        assert_eq!(
            reservation.video_decode_work_units,
            limits.maximum_source_chunk_bytes + limits.maximum_pixel_samples
        );
        assert_eq!(reservation.jpeg_work_units, limits.package.jpeg_work_units);
        assert_eq!(
            reservation.detection_work_units,
            limits.package.detection_work_units
        );
        assert_eq!(
            reservation.preprocess_macs,
            4 * limits.package.run.preprocess.max_macs
        );
        assert_eq!(
            reservation.execution_macs,
            4 * limits.package.run.execution.max_macs
        );
        assert_eq!(
            reservation.output_bytes,
            4 * limits.package.run.maximum_output_bytes as u64
        );
        let mut overflow = limits;
        overflow.package.run.preprocess.max_macs = u64::MAX;
        assert!(plan.reservation(&overflow).is_err());
        overflow = limits;
        overflow.package.run.execution.max_macs = u64::MAX;
        assert!(plan.reservation(&overflow).is_err());
        overflow = limits;
        overflow.package.run.maximum_output_bytes = usize::MAX;
        if usize::BITS >= 64 {
            assert!(plan.reservation(&overflow).is_err());
        }
        Ok(())
    }

    #[test]
    fn exact_bounds_and_policy_are_bound_even_when_selection_is_unchanged()
    -> Result<(), PackageDetectError> {
        let config = LongSentinelConfig {
            every_frames: 1024,
            burst_frames: 3,
            max_inferences: 3,
        };
        let a = LongSentinelPlan::new(0, 1024, config)?;
        let b = LongSentinelPlan::new(0, 2048, config)?;
        assert_eq!(a.selected_segments(), b.selected_segments());
        assert_ne!(a.digest(), b.digest());
        let limits = LongSentinelLimits::default();
        let narrowed = LongSentinelLimits {
            maximum_pixel_samples: limits.maximum_pixel_samples - 1,
            ..limits
        };
        assert_ne!(limits.digest(), narrowed.digest());
        let mut changed = limits;
        changed.package.run.execution.max_bytes -= 1;
        assert_ne!(limits.digest(), changed.digest());
        for (first, count) in [
            (0, 0),
            (0, 2),
            (0, MAX_LONG_WATCH_FRAMES + 1),
            (usize::MAX, 3),
        ] {
            assert!(LongSentinelPlan::new(first, count, config).is_err());
        }
        for config in [
            LongSentinelConfig {
                every_frames: 0,
                ..config
            },
            LongSentinelConfig {
                every_frames: MAX_LONG_WATCH_FRAMES + 1,
                ..config
            },
            LongSentinelConfig {
                burst_frames: 9,
                max_inferences: 9,
                ..config
            },
            LongSentinelConfig {
                max_inferences: 65,
                ..config
            },
        ] {
            assert!(LongSentinelPlan::new(0, 1024, config).is_err());
        }
        Ok(())
    }
}

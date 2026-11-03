#![forbid(unsafe_code)]
//! Pure exact-history/model admission and a finite whole-history burst schedule.

use fss_codec_mjpeg::ComponentInterpretation;
use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm};

use super::{HttpHistorySentinelError as Error, POLICY, Result};
use crate::KernelBackend;
use crate::http_reconnect_history::{ReconnectHistoryLimits, ReconnectHistoryPin};
use crate::ingest::http_history_sources::{SourceLimits, SourcePlan};
use crate::ingest::http_history_watch::{HttpHistoryWatchBinding, HttpHistoryWatchLimits};
use crate::ingest::http_import::MAX_FRAMES;
use crate::ingest::http_reconnect::MAX_RECONNECT_CONNECTIONS;
use crate::ingest::long_sentinel::{
    LongSentinelConfig, LongSentinelLimits, LongSentinelReservation,
};
use crate::ingest::long_watch::MAX_LONG_WATCH_FRAMES;
use crate::ingest::package_detect::MAX_PACKAGE_DETECT_FRAMES;
use crate::ingest::package_detect::sentinel::MAX_SENTINEL_BURST_FRAMES;

/// Each of at most 32 native connections still admits no more than 64 model calls.
pub const MAX_HTTP_HISTORY_SENTINEL_INFERENCES: usize =
    MAX_RECONNECT_CONNECTIONS * MAX_PACKAGE_DETECT_FRAMES;
/// Bound all model tensor outputs held before optional native aggregate retention.
pub const MAX_HTTP_HISTORY_SENTINEL_OUTPUT_BYTES: u64 = 1024 * 1024 * 1024;
/// Complete combined report ceiling, including unchanged native burst reports.
pub const MAX_HTTP_HISTORY_SENTINEL_REPORT_BYTES: usize = 32 * 1024 * 1024 + 65536;

/// Deterministic sampling independent of foreground activity or unproven capture cadence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpHistorySentinelConfig {
    /// Source-frame distance between complete burst starts in each connection.
    pub every_frames: usize,
    /// Whole contiguous frames per burst, 1..=8 and no greater than the period.
    pub burst_frames: usize,
    /// One model-call ceiling for the entire history, not a new allowance per generation.
    pub max_inferences: usize,
}
impl Default for HttpHistorySentinelConfig {
    fn default() -> Self {
        Self {
            every_frames: 16,
            burst_frames: 3,
            max_inferences: 48,
        }
    }
}
impl HttpHistorySentinelConfig {
    /// Validate without source, model, filesystem or network access.
    pub fn validate(&self) -> Result<()> {
        if !(1..=MAX_LONG_WATCH_FRAMES).contains(&self.every_frames)
            || !(1..=MAX_SENTINEL_BURST_FRAMES).contains(&self.burst_frames)
            || self.burst_frames > self.every_frames
            || self.max_inferences < self.burst_frames
            || self.max_inferences > MAX_HTTP_HISTORY_SENTINEL_INFERENCES
        {
            return Err(Error::Invalid("history sentinel sampling bounds"));
        }
        Ok(())
    }
}

/// Exact original history, explicit camera/time assumptions and a pinned native model policy.
#[derive(Clone, Debug)]
pub struct HttpHistorySentinelPlan {
    /// Independently saved ended-history prefix; never a discovered latest head.
    pub history: ReconnectHistoryPin,
    /// One explicit binding per selected connection, including empty and failed responses.
    pub bindings: Vec<HttpHistoryWatchBinding>,
    /// Explicit native JPEG component interpretation; no content-dependent guess.
    pub interpretation: ComponentInterpretation,
    /// Expected digest of the complete original local native model archive.
    pub package_digest: ContentDigest,
    /// Native kernel choice and implementation generation, bound into approval.
    pub backend: KernelBackend,
    /// Native package threshold unless an explicit inclusive ppm threshold is supplied.
    pub minimum_score_ppm: Option<u32>,
    /// Whole-history round-robin allocation of complete independent bursts.
    pub sampling: HttpHistorySentinelConfig,
    /// Separately requested native aggregate/model retention after all computations succeed.
    pub retain: bool,
}

/// Independent custody/import bounds and one nonrenewable inference resource pool.
#[derive(Clone, Copy, Debug)]
pub struct HttpHistorySentinelLimits {
    /// Initial and final exact history/original inspections share the caller's work account.
    pub history: ReconnectHistoryLimits,
    /// Complete original JPEG count in each connection, 1..=4096.
    pub maximum_frames_per_generation: usize,
    /// Original and reconstructed-media ceilings for each import, at most 64 MiB each.
    pub maximum_bytes_per_generation: u64,
    /// Global source/pixel/JPEG/head/report pools; native frame/model limits stay per frame.
    pub sentinel: LongSentinelLimits,
    /// Complete combined JSON ceiling, without omitted rows or truncated native reports.
    pub maximum_report_bytes: usize,
}
impl Default for HttpHistorySentinelLimits {
    fn default() -> Self {
        let source = HttpHistoryWatchLimits::default();
        Self {
            history: source.history,
            maximum_frames_per_generation: source.maximum_frames_per_generation,
            maximum_bytes_per_generation: source.maximum_bytes_per_generation,
            sentinel: LongSentinelLimits::default(),
            maximum_report_bytes: MAX_HTTP_HISTORY_SENTINEL_REPORT_BYTES,
        }
    }
}
impl HttpHistorySentinelLimits {
    pub(super) fn source_limits(&self) -> SourceLimits {
        SourceLimits {
            history: self.history,
            maximum_frames_per_generation: self.maximum_frames_per_generation,
            maximum_bytes_per_generation: self.maximum_bytes_per_generation,
        }
    }
}

/// Checked conservative ceilings, distinct from measured native usage and exact allocations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpHistorySentinelReservation {
    /// Every selected native connection, including empty and incomplete responses.
    pub connections: u32,
    /// Sum of per-generation complete-frame admission ceilings.
    pub maximum_frames: u64,
    /// Two complete bounded cold-history original-byte verification passes.
    pub history_verification_bytes: u64,
    /// Sum of the independent original-response import ceilings.
    pub import_original_bytes: u64,
    /// Sum of the independent reconstructed-media import ceilings.
    pub import_media_bytes: u64,
    /// Final destination media plus original-response custody verification allowance.
    /// Native metadata/capsule reads keep their existing separate bounded owners.
    pub destination_verification_bytes: u64,
    /// One global inference reservation; no field is renewed for a later generation.
    pub inference: LongSentinelReservation,
}

/// Exact schedule derived from the actual imported original JPEG inventory.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HttpHistorySentinelAllocation {
    /// Complete original JPEGs, not raw receive reads or a guessed capture duration.
    pub imported_frames: usize,
    /// Every complete scheduled burst in this connection's retained source range.
    pub eligible_bursts: usize,
    /// Whole bursts admitted by immutable connection-order round robin.
    pub admitted_bursts: usize,
    /// Exact model calls, always admitted_bursts times burst_frames.
    pub admitted_inferences: usize,
    /// Eligible bursts withheld by the global or native per-generation ceiling.
    pub budget_skipped_bursts: usize,
}

impl HttpHistorySentinelPlan {
    pub(super) fn source_plan(&self) -> SourcePlan<'_> {
        SourcePlan {
            pin: self.history,
            bindings: &self.bindings,
        }
    }

    /// Validate all choices and worst-case sums before any source/model read or mutation.
    pub fn reservation(
        &self,
        limits: &HttpHistorySentinelLimits,
    ) -> Result<HttpHistorySentinelReservation> {
        self.source_plan().validate(limits.source_limits())?;
        self.sampling.validate()?;
        limits.sentinel.validate()?;
        if self.package_digest.algorithm() != DigestAlgorithm::Sha256
            || self.package_digest.is_laboratory()
            || self.package_digest.bytes() == [0; 32]
            || self
                .minimum_score_ppm
                .is_some_and(|score| score > 1_000_000)
            || !(1..=MAX_HTTP_HISTORY_SENTINEL_REPORT_BYTES).contains(&limits.maximum_report_bytes)
        {
            return Err(Error::Invalid("package, threshold or report limit"));
        }
        let p = limits.sentinel.package;
        if p.jpeg_work_units == 0
            || p.detection_work_units == 0
            || p.detection_scratch_bytes == 0
            || p.run.preprocess.max_macs == 0
            || p.run.preprocess.max_bytes == 0
            || p.run.execution.max_macs == 0
            || p.run.execution.max_bytes == 0
            || p.run.maximum_output_bytes == 0
            || !(1..=512 * 1024 * 1024).contains(&p.read.max_source_bytes)
            || !(1..=16 * 1024 * 1024).contains(&p.read.max_chunk_bytes)
            || !(1..=16 * 1024 * 1024).contains(&p.read.max_segment_bytes)
        {
            return Err(Error::Invalid(
                "native read, model or nonrenewable work limits",
            ));
        }
        // Inactive native video fields still belong to the approved exact recipe.
        fss_codec_h264::Decoder::new(p.h264).map_err(|_| Error::Invalid("AVC decoder limits"))?;
        fss_codec_h265::Decoder::new(p.h265).map_err(|_| Error::Invalid("HEVC decoder limits"))?;
        let count = self.sampling.max_inferences as u64;
        let product = |per_frame: u64| count.checked_mul(per_frame).ok_or(Error::Limit);
        let output_bytes = product(p.run.maximum_output_bytes as u64)?;
        if output_bytes > MAX_HTTP_HISTORY_SENTINEL_OUTPUT_BYTES {
            return Err(Error::Limit);
        }
        let n = u64::from(self.history.connections);
        let media = n
            .checked_mul(limits.maximum_bytes_per_generation)
            .ok_or(Error::Limit)?;
        let original = media.min(limits.history.maximum_bytes);
        let global = limits.sentinel;
        Ok(HttpHistorySentinelReservation {
            connections: self.history.connections,
            maximum_frames: n
                .checked_mul(limits.maximum_frames_per_generation as u64)
                .ok_or(Error::Limit)?,
            history_verification_bytes: limits
                .history
                .maximum_bytes
                .checked_mul(2)
                .ok_or(Error::Limit)?,
            import_original_bytes: original,
            import_media_bytes: media,
            destination_verification_bytes: original.checked_add(media).ok_or(Error::Limit)?,
            inference: LongSentinelReservation {
                source_chunk_bytes: global.maximum_source_chunk_bytes,
                pixel_samples: global.maximum_pixel_samples,
                video_encoded_bytes: 0,
                video_coded_luma_capacity: 0,
                video_decode_work_units: 0,
                jpeg_work_units: p.jpeg_work_units,
                detection_work_units: p.detection_work_units,
                inferences: self.sampling.max_inferences,
                preprocess_macs: product(p.run.preprocess.max_macs)?,
                execution_macs: product(p.run.execution.max_macs)?,
                output_bytes,
                report_bytes: global.maximum_report_bytes,
            },
        })
    }

    /// Fair complete-burst admission in connection order. A short tail, unspent partial allowance
    /// and the native 64-frame ceiling stay explicit; no sampled burst bridges a reconnect.
    pub fn allocate(&self, frames: &[usize]) -> Result<Vec<HttpHistorySentinelAllocation>> {
        self.sampling.validate()?;
        if frames.len() != self.bindings.len() || frames.len() > MAX_RECONNECT_CONNECTIONS {
            return Err(Error::Invalid("exact imported frame inventory"));
        }
        let config = self.sampling;
        let mut rows = Vec::with_capacity(frames.len());
        for &count in frames {
            if count > MAX_FRAMES {
                return Err(Error::Invalid("imported frame ceiling"));
            }
            let eligible = if count < config.burst_frames {
                0
            } else {
                1 + (count - config.burst_frames) / config.every_frames
            };
            rows.push(HttpHistorySentinelAllocation {
                imported_frames: count,
                eligible_bursts: eligible,
                budget_skipped_bursts: eligible,
                ..HttpHistorySentinelAllocation::default()
            });
        }
        let per_generation = MAX_PACKAGE_DETECT_FRAMES / config.burst_frames;
        let mut remaining = config.max_inferences / config.burst_frames;
        while remaining != 0 {
            let mut progressed = false;
            for row in &mut rows {
                if remaining != 0 && row.admitted_bursts < row.eligible_bursts.min(per_generation) {
                    row.admitted_bursts += 1;
                    row.admitted_inferences += config.burst_frames;
                    row.budget_skipped_bursts -= 1;
                    remaining -= 1;
                    progressed = true;
                }
            }
            if !progressed {
                break;
            }
        }
        Ok(rows)
    }

    pub(super) fn native_config(
        &self,
        allocation: HttpHistorySentinelAllocation,
    ) -> LongSentinelConfig {
        LongSentinelConfig {
            every_frames: self.sampling.every_frames,
            burst_frames: self.sampling.burst_frames,
            max_inferences: allocation.admitted_inferences,
        }
    }

    /// Canonical exact approval identity, including all bindings, complete model/backend choices,
    /// immutable sampling, optional retention and every supplied native/source resource ceiling.
    pub fn digest(&self, limits: &HttpHistorySentinelLimits) -> Result<ContentDigest> {
        self.reservation(limits)?;
        let mut e = CanonicalEncoder::new();
        e.text("fss.http_history_sentinel_plan.v1");
        e.digest(ContentDigest::sha256(POLICY));
        e.digest(self.history.session);
        e.digest(self.history.root);
        e.u32(self.history.connections);
        for binding in &self.bindings {
            e.u64(binding.generation);
            e.text(binding.sensor.as_str());
            e.text(binding.stream.as_str());
            e.i128(binding.receive_time.0);
            e.i128(binding.capture_hint.start_ns.0);
            e.u64(binding.capture_hint.uncertainty_ns);
            e.u64(binding.capture_hint.assumed_fps.to_bits());
        }
        e.text(match self.interpretation {
            ComponentInterpretation::Grayscale => "gray",
            ComponentInterpretation::YCbCr => "ycbcr",
        });
        e.digest(self.package_digest);
        e.text(self.backend.stable_id());
        e.digest(self.backend.generation());
        e.bool(self.minimum_score_ppm.is_some());
        if let Some(score) = self.minimum_score_ppm {
            e.u32(score);
        }
        for n in [
            self.sampling.every_frames,
            self.sampling.burst_frames,
            self.sampling.max_inferences,
        ] {
            e.u64(n as u64);
        }
        e.bool(self.retain);
        let h = limits.history;
        let a = h.archive;
        for value in [
            a.maximum_reads as u64,
            a.maximum_bytes,
            a.maximum_scan_roots as u64,
            a.maximum_spool_object_bytes as u64,
            h.maximum_reads,
            h.maximum_bytes,
            limits.maximum_frames_per_generation as u64,
            limits.maximum_bytes_per_generation,
        ] {
            e.u64(value);
        }
        e.digest(limits.sentinel.digest());
        e.u64(limits.maximum_report_bytes as u64);
        Ok(ContentDigest::sha256(
            &e.finish_checked().map_err(|_| Error::Limit)?,
        ))
    }
}

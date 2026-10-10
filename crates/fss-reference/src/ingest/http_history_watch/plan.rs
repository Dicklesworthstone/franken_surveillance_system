#![forbid(unsafe_code)]
//! Pure exact-plan validation and fixed whole-invocation resource reservations.

use fss_codec_mjpeg::ComponentInterpretation;
use fss_core::{CanonicalEncoder, ContentDigest, SensorId, StreamId, TimestampNs};

use super::{HttpHistoryWatchError, POLICY, Result};
use crate::http_reconnect_history::{ReconnectHistoryLimits, ReconnectHistoryPin};
use crate::ingest::file_adapter::{CaptureHint, FileIngestAdapter};
use crate::ingest::http_archive::HttpArchiveLimits;
use crate::ingest::http_import::{HttpImportError, MAX_BYTES, MAX_FRAMES};
use crate::ingest::long_watch::LongWatchLimits;
use crate::ingest::recorded_watch::{
    WatchDetectorConfig, WatchOptions, WatchPlan, WatchTrackerConfig, WatchZone,
};

const PLAN_DOMAIN: &str = "fss.http_history_watch_plan.v1";
const MAX_REPORT_BYTES: usize = 32 * 1024 * 1024 + 65536;
const MAX_TRACE_BYTES: u64 = 256 * 1024 * 1024;

/// Owner assertion for one exact native generation. Reconnects never infer camera capture time
/// from receive timestamps or continue another generation's tracker.
#[derive(Clone, Debug, PartialEq)]
pub struct HttpHistoryWatchBinding {
    /// Exact native source generation, in strictly increasing connection order.
    pub generation: u64,
    /// Owner-declared sensor; this is not remote camera authentication.
    pub sensor: SensorId,
    /// Owner-declared stream; original source generations remain independently bound.
    pub stream: StreamId,
    /// Explicit destination ingest timestamp, never inferred from the receive clock.
    pub receive_time: TimestampNs,
    /// Explicit operator capture-start, uncertainty and assumed frame-rate declaration.
    pub capture_hint: CaptureHint,
}

/// Exact selected history and all per-generation analysis choices. No latest-head lookup or
/// implicit binding is admitted. The caller's current authority independently names a destination.
#[derive(Clone, Debug)]
pub struct HttpHistoryWatchPlan {
    /// Independently saved history root, session identity and exact connection count.
    pub history: ReconnectHistoryPin,
    /// One explicit binding for every selected connection, including empty failed attempts.
    pub bindings: Vec<HttpHistoryWatchBinding>,
    /// Explicit JPEG source component interpretation.
    pub interpretation: ComponentInterpretation,
    /// Owner image zones, interpreted independently in every selected generation.
    pub zones: Vec<WatchZone>,
    /// Shared foreground thresholds, with fresh background state at each reconnect.
    pub detector: WatchDetectorConfig,
    /// Shared tracker thresholds, with independent track identities at each reconnect.
    pub tracker: WatchTrackerConfig,
    /// Typed native decode refusal policy, defaulting to strict analysis.
    pub options: WatchOptions,
    /// Screen the privacy-masked pixels and withhold publication hints on degraded visibility.
    pub screened: bool,
}

/// Fixed independent ceilings. No connection may consume another connection's unused allowance;
/// the total work admitted up front is explicit in [`HttpHistoryWatchReservation`].
#[derive(Clone, Copy, Debug)]
pub struct HttpHistoryWatchLimits {
    /// Complete cold-history and original archive verification bounds.
    pub history: ReconnectHistoryLimits,
    /// Complete original JPEG count per generation, from one through 4096.
    pub maximum_frames_per_generation: usize,
    /// Independent original and reconstructed byte ceilings per generation, at most 64 MiB.
    pub maximum_bytes_per_generation: u64,
    /// One fixed native whole-recording analysis allowance reserved for each generation.
    pub watch: LongWatchLimits,
    /// Complete combined JSON bound, at most 32 MiB plus 64 KiB of envelope metadata.
    pub maximum_report_bytes: usize,
}
impl Default for HttpHistoryWatchLimits {
    fn default() -> Self {
        Self {
            history: ReconnectHistoryLimits {
                archive: HttpArchiveLimits {
                    maximum_reads: 4096,
                    maximum_bytes: MAX_BYTES,
                    maximum_scan_roots: 65536,
                    maximum_spool_object_bytes: 16 * 1024 * 1024,
                },
                maximum_reads: 8192,
                maximum_bytes: 512 * 1024 * 1024,
            },
            maximum_frames_per_generation: 128,
            maximum_bytes_per_generation: MAX_BYTES,
            watch: LongWatchLimits::default(),
            maximum_report_bytes: MAX_REPORT_BYTES,
        }
    }
}

/// Checked worst-case reservations for this exact invocation; these are ceilings, not observed
/// usage. The caller also supplies one shared history/import work budget and framing budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpHistoryWatchReservation {
    /// Exact selected connection count, at most 32.
    pub connections: u32,
    /// Sum of the fixed per-generation frame allowances.
    pub frames: u64,
    /// Sum of per-generation original-byte ceilings, narrowed by the complete-history ceiling.
    pub original_bytes: u64,
    /// Sum of native source-read allowances, including original HTTP verification.
    pub source_read_bytes: u64,
    /// Sum of foreground luma-sample allowances. Screening has the same separate native ceiling.
    pub pixel_samples: u64,
    /// Sum of deterministic assignment-work allowances.
    pub assignment_work: u64,
    /// Sum of native JPEG decode-work allowances.
    pub jpeg_work: u64,
    /// Sum of retained analysis-trace ceilings, never more than 256 MiB.
    pub trace_bytes: u64,
    /// Independent complete JSON projection ceiling.
    pub report_bytes: u64,
}

impl HttpHistoryWatchPlan {
    pub(super) fn watch_plan(&self, import: ContentDigest, frames: usize) -> WatchPlan {
        WatchPlan {
            import_identity: import,
            interpretation: self.interpretation,
            first_segment: 0,
            segment_count: frames,
            zones: self.zones.clone(),
            detector: self.detector,
            tracker: self.tracker,
        }
    }

    /// Validate the complete selection and reserve all generation allowances before any I/O.
    pub fn reservation(
        &self,
        limits: &HttpHistoryWatchLimits,
    ) -> Result<HttpHistoryWatchReservation> {
        self.history
            .validate()
            .map_err(|_| HttpHistoryWatchError::Invalid("history pin"))?;
        limits
            .history
            .validate()
            .map_err(|_| HttpHistoryWatchError::Invalid("history limits"))?;
        limits.watch.validate()?;
        let read = limits.watch.decode.read_limits;
        if self.bindings.len() != self.history.connections as usize
            || !(1..=MAX_FRAMES).contains(&limits.maximum_frames_per_generation)
            || !(1..=MAX_BYTES).contains(&limits.maximum_bytes_per_generation)
            || !(1..=MAX_REPORT_BYTES).contains(&limits.maximum_report_bytes)
            || limits.watch.decode.jpeg_work_units == 0
            || !(1..=512 * 1024 * 1024).contains(&read.max_source_bytes)
            || !(1..=16 * 1024 * 1024).contains(&read.max_chunk_bytes)
            || !(1..=16 * 1024 * 1024).contains(&read.max_segment_bytes)
        {
            return Err(HttpHistoryWatchError::Invalid(
                "binding count or independent limits",
            ));
        }
        let mut previous = 0;
        for binding in &self.bindings {
            let hint = binding.capture_hint;
            if binding.generation <= previous
                || binding.receive_time.0 < 0
                || hint.start_ns.0 < 0
                || hint.assumed_fps <= 0.0
                || !hint.assumed_fps.is_finite()
            {
                return Err(HttpHistoryWatchError::Invalid(
                    "ordered generation or capture timing",
                ));
            }
            // Validate every admitted timestamp endpoint, not only frame zero.
            for index in [0, limits.maximum_frames_per_generation - 1] {
                FileIngestAdapter::compute_capture_interval(
                    index,
                    Some(&hint),
                    binding.receive_time,
                )
                .map_err(HttpImportError::from)?;
            }
            previous = binding.generation;
        }
        self.watch_plan(ContentDigest::sha256(POLICY), 1)
            .validate()?;
        let n = u64::from(self.history.connections);
        let reserve = |value: u64| n.checked_mul(value).ok_or(HttpHistoryWatchError::Limit);
        let trace_bytes = reserve(limits.watch.maximum_trace_bytes as u64)?;
        if trace_bytes > MAX_TRACE_BYTES {
            return Err(HttpHistoryWatchError::Limit);
        }
        Ok(HttpHistoryWatchReservation {
            connections: self.history.connections,
            frames: reserve(limits.maximum_frames_per_generation as u64)?,
            original_bytes: reserve(limits.maximum_bytes_per_generation)?
                .min(limits.history.maximum_bytes),
            source_read_bytes: reserve(limits.watch.maximum_source_chunk_bytes)?,
            pixel_samples: reserve(limits.watch.maximum_pixel_samples)?,
            assignment_work: reserve(limits.watch.maximum_assignment_work)?,
            jpeg_work: reserve(limits.watch.decode.jpeg_work_units)?,
            trace_bytes,
            report_bytes: limits.maximum_report_bytes as u64,
        })
    }

    /// Canonical exact approval identity, including all bindings, analysis choices and ceilings.
    pub fn digest(&self, limits: &HttpHistoryWatchLimits) -> Result<ContentDigest> {
        let reservation = self.reservation(limits)?;
        let mut e = CanonicalEncoder::new();
        e.text(PLAN_DOMAIN);
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
        // Reuse the native policy/config encoding; no import exists at pure planning time.
        e.digest(self.watch_plan(ContentDigest::sha256(POLICY), 1).digest());
        e.bool(self.options.tolerate_decode_refusals);
        e.bool(self.screened);
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
        let w = limits.watch;
        let d = w.decode;
        for value in [
            d.read_limits.max_source_bytes,
            d.read_limits.max_chunk_bytes,
            d.read_limits.max_segment_bytes,
            d.jpeg_limits.maximum_bytes as u64,
            u64::from(d.jpeg_limits.maximum_dimension),
            d.jpeg_limits.maximum_pixels as u64,
            d.jpeg_limits.maximum_markers as u64,
            d.jpeg_work_units,
            w.maximum_source_chunk_bytes,
            w.maximum_pixel_samples,
            w.maximum_assignment_work,
            w.maximum_trace_bytes as u64,
            limits.maximum_report_bytes as u64,
        ] {
            e.u64(value);
        }
        // These decoder choices are inactive for HTTP MJPEG, but still bind every supplied field.
        let avc = d.h264_limits;
        let hevc = d.h265_limits;
        for value in [
            u64::from(avc.max_width),
            u64::from(avc.max_height),
            u64::from(avc.max_macroblocks),
            avc.max_pictures,
            avc.max_nal_bytes as u64,
            u64::from(avc.max_slices_per_picture),
            u64::from(avc.max_reference_frames),
            u64::from(hevc.max_width),
            u64::from(hevc.max_height),
            hevc.max_luma_samples,
            hevc.max_pictures,
            hevc.max_nal_bytes as u64,
            u64::from(hevc.max_slices_per_picture),
            u64::from(hevc.max_dpb_pictures),
        ] {
            e.u64(value);
        }
        for value in [
            reservation.frames,
            reservation.original_bytes,
            reservation.source_read_bytes,
            reservation.pixel_samples,
            reservation.assignment_work,
            reservation.jpeg_work,
            reservation.trace_bytes,
            reservation.report_bytes,
        ] {
            e.u64(value);
        }
        let bytes = e
            .finish_checked()
            .map_err(|_| HttpHistoryWatchError::Limit)?;
        Ok(ContentDigest::sha256(&bytes))
    }
}

#![forbid(unsafe_code)]
//! Whole-range, bounded MJPEG temporal analysis without artificial tracking windows.
//!
//! Pixels are decoded, masked, detected and tracked once in source order. Only scalar temporal
//! state survives a frame; the bounded trace retains identities and geometry, never pixel arrays.
//! This is sampled occupancy, not continuous presence, identity, threat or absence evidence.
//! Opt-in `analyze_screened` applies conservative visual-degradation screening to those same
//! masked pixels. Its findings remain diagnostics and prevent publication of the complete scan.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use fss_codec_mjpeg::{DecodeBudget, decode_luma};
use fss_core::{
    CanonicalEncode, CanonicalEncoder, CaptureInterval, ContentDigest, DecisionPath, EventEvidence,
    EventHypothesis, EventId, EventKind, EventState, EvidenceClass, EvidenceEdgeRelation,
    LedgerAnchor, ObjectId, ProbabilityInterval, SensorCapsule, SensorId,
};
use fss_object::ObjectManifest;
use fss_publication::SlotName;

use super::foreground::{ForegroundConfig, ForegroundDetector};
use super::privacy_mask::{MaskBinding, current_mask};
use super::recorded_decode::h264::{RecordedH264Range, RecordedH264Request};
use super::recorded_decode::h265::{RecordedH265Range, RecordedH265Request};
use super::recorded_decode::{RecordedDecodeError, source_capsule, validate_limits};
use super::recorded_watch::{
    SourcePublicationGuard, WatchError, WatchLimits, WatchOptions, WatchPlan, WatchStatus,
    WatchZone,
};
use super::retained::SourceReadBudget;
use super::sensor_health::{
    HealthFrame, policy_bytes as health_policy_bytes, policy_digest as health_policy_digest,
};
use super::streaming_dwell::{DwellAccumulator, MAX_STREAM_DWELL_SAMPLES, StreamDwellSpan};
use super::tolerant_decode::{
    DecodeRefusal, TolerantFrame, TolerantItem, TolerantRequest, TolerantSource, tolerable,
};
use super::tracker::{
    Detection, MultiObjectTracker, TrackStatus, TrackedTarget, TrackerConfig, TrackerLimits,
};
use super::zone_dwell::{DwellError, DwellPolicy, DwellSample, MAX_DWELL_EPISODES};
use super::{RetainedFileImport, RetainedReadLimits};
use crate::{
    ReferenceDeployment, ReferenceError, ReferencePolicyAction, ReferencePolicyDecision, ReplayCx,
};

mod classify;
pub(super) mod detector;
mod fusion;
/// Bounded native MJPEG continuation and source-verified durable checkpoints.
pub mod incremental;
pub(in crate::ingest) mod limits;
pub(super) mod reader;
/// Verified immutable trained classifier and its bounded native inference policy.
pub use super::long_watch::LongWatchDetector as LongDwellDetector;
use reader::ChunkCursor;
mod health;
use health::Screening;
pub use health::{
    HEALTH_PUBLICATION_BLOCKED, HealthFindingRun, LongDwellHealthSummary, MAX_HEALTH_FINDING_RUNS,
};

/// Maximum requested source segments, counted across the complete scan.
pub const MAX_LONG_DWELL_FRAMES: usize = MAX_STREAM_DWELL_SAMPLES;
/// Hard metadata-trace ceiling; pixels and compressed source are not retained in this buffer.
pub const MAX_LONG_DWELL_TRACE_BYTES: usize = 8 * 1024 * 1024;
/// Hard total foreground pixel-processing ceiling for one invocation.
pub const MAX_LONG_DWELL_PIXELS: u64 = 64 * 1024 * 1024 * 1024;
/// Hard total assignment-work ceiling for one invocation.
pub const MAX_LONG_DWELL_ASSIGNMENT: u64 = 64 * 1024 * 1024 * 1024;
const MAX_TRACKS: usize = 64;
const MAX_REFUSAL_RUNS: usize = 128;
const MAX_REPORT_BYTES: usize = 1024 * 1024;
pub(super) const POLICY: &[u8] =
    b"fss.long-dwell.policy.v1:mjpeg-native-luma:masked-before-perception:\
running-variance:kalman-global-iou:confirmed-actual-matches:strict-rounded-zone-interior:\
conservative-capture-endpoints:reset-background-and-tracker-on-source-or-decode-gap:\
one-whole-range-budget:unclassified:indeterminate:hold:no-absence:no-alert";
/// Policy of inter-coded (H.264/H.265, Annex-B or MP4) scans: frames in display order, dwell
/// positions are display positions, and decoding restarts only at IDR/IRAP pictures.
pub(super) const POLICY_INTER: &[u8] = b"fss.long-dwell.policy.v1:inter-coded-display-order-luma:\
display-order-positions:idr-or-irap-restart:masked-before-perception:running-variance:\
kalman-global-iou:confirmed-actual-matches:strict-rounded-zone-interior:\
conservative-capture-endpoints:reset-background-and-tracker-on-source-or-decode-gap:\
one-whole-range-budget:unclassified:indeterminate:hold:no-absence:no-alert";
pub(super) const ANALYSIS_DOMAIN: &str = "fss.long_dwell_analysis.v1";
const FRAME_DOMAIN: &str = "fss.long_dwell_frame.v1";
pub(super) const EPISODE_DOMAIN: &str = "fss.long_dwell_episode.v1";
const APPROVAL_DOMAIN: &str = "fss.long_dwell_approval.v1";
const UNCERTAINTY: &str = "Consecutive actual foreground-track samples meet an owner-selected dwell rule. Capture times are operator assumptions; one sensor, uncalibrated, no continuous occupancy or intent proof.";
type Result<T> = std::result::Result<T, WatchError>;

/// Whole-scan ceilings, not allowances replenished for each frame, chunk or episode.
#[derive(Clone, Copy, Debug)]
pub struct LongDwellLimits {
    /// Existing retained-read and native JPEG/AVC/HEVC decode ceilings.
    pub decode: WatchLimits,
    /// Bytes fetched from source chunks; metadata reads are separately bounded by their owners.
    pub maximum_source_chunk_bytes: u64,
    /// Sum of decoded luma sample counts, charged before foreground processing. A whole-recording
    /// trained detector's optional second pass consumes this same ceiling for its decoded pixels.
    /// Opt-in screening has a separate cumulative sample counter with this same ceiling.
    pub maximum_pixel_samples: u64,
    /// Sum of checked Hungarian admission bounds, charged before tracker updates.
    pub maximum_assignment_work: u64,
    /// Complete trace bytes, including each frame's framing, bounded before append.
    pub maximum_trace_bytes: usize,
}
impl Default for LongDwellLimits {
    fn default() -> Self {
        Self {
            decode: WatchLimits::default(),
            maximum_source_chunk_bytes: 512 * 1024 * 1024,
            maximum_pixel_samples: 1024 * 1024 * 1024,
            maximum_assignment_work: 1024 * 1024 * 1024,
            maximum_trace_bytes: MAX_LONG_DWELL_TRACE_BYTES,
        }
    }
}
impl LongDwellLimits {
    /// Validate aggregate ceilings before opening source custody.
    pub fn validate(&self) -> Result<()> {
        validate_limits(self.decode.jpeg_limits)?;
        if self.maximum_source_chunk_bytes == 0
            || self.maximum_source_chunk_bytes > 512 * 1024 * 1024
            || !(1..=MAX_LONG_DWELL_PIXELS).contains(&self.maximum_pixel_samples)
            || !(1..=MAX_LONG_DWELL_ASSIGNMENT).contains(&self.maximum_assignment_work)
            || !(1..=MAX_LONG_DWELL_TRACE_BYTES).contains(&self.maximum_trace_bytes)
        {
            return Err(WatchError::InvalidPlan(
                "long-dwell aggregate limits out of bounds",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct Episode {
    epoch: u64,
    track: u64,
    zone: usize,
    span: StreamDwellSpan,
}

/// One source-closed proposal. The inner event and provenance are immutable to callers.
#[derive(Clone, Debug)]
pub struct LongDwellCandidate {
    episode: Episode,
    class_evidence: Vec<super::detector_cascade::ClassEvidence>,
    event: EventHypothesis,
    record: Vec<u8>,
    manifest: ObjectManifest,
    slot: SlotName,
    approval: ContentDigest,
    status: WatchStatus,
}
impl LongDwellCandidate {
    /// Exact approval; it cannot be used for entry-mode or short-range dwell proposals.
    pub const fn proposal_digest(&self) -> ContentDigest {
        self.approval
    }
    /// Event proposed by this episode; it always remains unclassified and indeterminate.
    pub fn event(&self) -> &EventHypothesis {
        &self.event
    }
    /// Absolute source positions and conservative duration of the qualifying episode.
    pub const fn span(&self) -> &StreamDwellSpan {
        &self.episode.span
    }
    /// Current publication classification.
    pub const fn status(&self) -> WatchStatus {
        self.status
    }
    /// Uncalibrated class annotations from actual observations within this episode only.
    pub fn class_evidence(&self) -> &[super::detector_cascade::ClassEvidence] {
        &self.class_evidence
    }
}

/// Complete bounded result. Analysis writes no objects or authority; publication is separate.
#[derive(Debug)]
pub struct LongDwellReport {
    plan: WatchPlan,
    rule: DwellPolicy,
    options: WatchOptions,
    root: PathBuf,
    site: String,
    principal: String,
    basis: LedgerAnchor,
    import_root: ContentDigest,
    sensor: SensorId,
    media_format: String,
    privacy: MaskBinding,
    publication_guard: SourcePublicationGuard,
    analysis: Vec<u8>,
    analysis_manifest: ObjectManifest,
    analysis_slot: SlotName,
    candidates: Vec<LongDwellCandidate>,
    decoded: usize,
    unreliable: usize,
    masked_zones: usize,
    restarts: usize,
    refusals: Vec<DecodeRefusal>,
    source_bytes: u64,
    pixel_samples: u64,
    assignment_work: u64,
    jpeg_work: u64,
    /// Exact analysis policy bytes (MJPEG or inter-coded), staged with the analysis.
    policy: &'static [u8],
    health: Option<LongDwellHealthSummary>,
    health_diagnostic: Option<super::historical_health::HistoricalHealthDiagnostic>,
    detector: Option<super::long_watch::detector::Completed>,
    /// Original native work reservation and a slice of the existing immutable analysis trace.
    classification: Option<classify::ClassificationSource>,
}

fn checkpoint(cx: &ReplayCx, stage: &'static str) -> Result<()> {
    cx.checkpoint(stage)
        .map_err(|_| RecordedDecodeError::Cancelled.into())
}
fn hex(d: ContentDigest) -> String {
    d.bytes().iter().map(|v| format!("{v:02x}")).collect()
}
fn dwell_error(error: DwellError) -> WatchError {
    match error {
        DwellError::Limit => WatchError::Limit,
        DwellError::ClockReversed => {
            WatchError::InvalidPlan("capture clock regressed during long dwell")
        }
        _ => WatchError::InvalidPlan("invalid streaming dwell input or policy"),
    }
}
fn tracker_config(plan: &WatchPlan) -> TrackerConfig {
    TrackerConfig {
        min_hits: plan.tracker.confirmation_hits,
        max_misses: plan.tracker.maximum_missed_frames,
        iou_threshold: f64::from(plan.tracker.minimum_iou_ppm) / 1_000_000.0,
        process_noise: 1.0,
        measurement_noise: 1.0,
    }
}
fn background_config(plan: &WatchPlan, dimensions: [u32; 2]) -> ForegroundConfig {
    ForegroundConfig {
        base_threshold: plan.detector.base_threshold,
        threshold_sigma: plan.detector.threshold_sigma,
        learning_rate_num: plan.detector.learning_rate_num,
        learning_rate_den: plan.detector.learning_rate_den,
        minimum_region_pixels: plan.detector.minimum_region_pixels,
        dimensions,
    }
}
fn inside(target: &TrackedTarget, zone: &WatchZone) -> bool {
    let x = target.cx.round();
    let y = target.cy.round();
    x > f64::from(zone.x)
        && x < f64::from(zone.x) + f64::from(zone.width)
        && y > f64::from(zone.y)
        && y < f64::from(zone.y) + f64::from(zone.height)
}
fn add_episode(
    episodes: &mut Vec<Episode>,
    epoch: u64,
    track: u64,
    zone: usize,
    span: Option<StreamDwellSpan>,
) -> Result<()> {
    if let Some(span) = span {
        if episodes.len() == MAX_DWELL_EPISODES {
            return Err(WatchError::Limit);
        }
        episodes.push(Episode {
            epoch,
            track,
            zone,
            span,
        });
    }
    Ok(())
}

/// Borrowed, already masked native perception output. No pixel history is exposed or retained.
pub(super) struct ScanObservation<'a> {
    pub(super) epoch: u64,
    pub(super) position: usize,
    pub(super) segment: usize,
    pub(super) capsule: &'a SensorCapsule,
    pub(super) capsule_digest: ContentDigest,
    pub(super) luma_digest: ContentDigest,
    pub(super) dimensions: [u32; 2],
    pub(super) time_reliable: bool,
    pub(super) privacy: &'a MaskBinding,
    pub(super) tracks: &'a [TrackedTarget],
    pub(super) zone_entries: &'a [super::long_watch::LongWatchEntry],
}

/// A scoped consumer of the existing streaming tracker, with no alternate media engine.
pub(super) trait ScanObserver {
    fn observe(&mut self, frame: ScanObservation<'_>) -> Result<()>;
}

/// Whole-scan state shared by the MJPEG and inter-coded frame sources.
struct Scan<'a, 'observer> {
    plan: &'a WatchPlan,
    rule: ScanRule,
    masked: &'a BTreeSet<usize>,
    limits: &'a LongDwellLimits,
    privacy: &'a MaskBinding,
    health_source: ContentDigest,
    health: Option<Screening>,
    time_reliable: bool,
    tracker: MultiObjectTracker,
    background: Option<ForegroundDetector>,
    dimensions: Option<[u32; 2]>,
    temporal: TemporalAccumulator,
    observer: Option<&'observer mut dyn ScanObserver>,
    previous_capture: Option<CaptureInterval>,
    capture_scope: Option<CaptureInterval>,
    previous_tracks: u64,
    trace: Vec<u8>,
    decoded: usize,
    unreliable: usize,
    restarts: usize,
    refusals: Vec<DecodeRefusal>,
    pixel_samples: u64,
    assignment_work: u64,
}

impl Scan<'_, '_> {
    /// Resets background, tracking and dwell state at a source or decode discontinuity.
    fn restart(&mut self) -> Result<()> {
        self.temporal.restart()?;
        self.tracker = MultiObjectTracker::new(tracker_config(self.plan))?;
        self.background = None;
        self.previous_capture = None;
        self.previous_tracks = 0;
        self.restarts += 1;
        Ok(())
    }

    /// Records refused segments `first..=last`, merging with an adjacent run of the same id.
    fn refused(&mut self, first: usize, last: usize, error_id: &str) -> Result<()> {
        match self.refusals.last_mut() {
            Some(run)
                if run.last_segment.checked_add(1) == Some(first) && run.error_id == error_id =>
            {
                run.last_segment = last;
            }
            _ => {
                if self.refusals.len() == MAX_REFUSAL_RUNS {
                    return Err(WatchError::Limit);
                }
                self.refusals.push(DecodeRefusal {
                    first_segment: first,
                    last_segment: last,
                    error_id: error_id.to_owned(),
                });
            }
        }
        Ok(())
    }

    /// Analyses one decoded frame: dimensions and zone fit, pixel budget, privacy mask (applied
    /// before any perception; idempotent for inter-coded frames the range already masked),
    /// optional screening, capture-time reliability, foreground, tracking, dwell and trace.
    /// `segment` is the coding segment; `position` the dwell position (equal for MJPEG).
    #[allow(clippy::too_many_arguments)]
    fn frame(
        &mut self,
        segment: usize,
        position: usize,
        capsule: &SensorCapsule,
        capsule_digest: ContentDigest,
        gap: bool,
        size: [u32; 2],
        mut pixels: Vec<u8>,
        mut frame_record: CanonicalEncoder,
        cx: &ReplayCx,
    ) -> Result<()> {
        let plan = self.plan;
        checkpoint(cx, "long_dwell:decoded")?;
        if self.dimensions.is_some_and(|old| old != size) {
            return Err(WatchError::DimensionChange { segment });
        }
        if self.dimensions.is_none() {
            for zone in &plan.zones {
                if u64::from(zone.x) + u64::from(zone.width) > u64::from(size[0])
                    || u64::from(zone.y) + u64::from(zone.height) > u64::from(size[1])
                {
                    return Err(WatchError::InvalidPlan(
                        "long-dwell zones must fit the decoded frame",
                    ));
                }
            }
            self.dimensions = Some(size);
        }
        charge(
            &mut self.pixel_samples,
            u64::from(size[0]) * u64::from(size[1]),
            self.limits.maximum_pixel_samples,
        )?;
        self.privacy
            .apply_luma(&mut pixels, size)
            .map_err(RecordedDecodeError::from)?;
        // A hull of the actual decoded capsule hints, independent of event eligibility. This
        // never claims continuous coverage across the hull or a present sensor state.
        self.capture_scope =
            Some(
                self.capture_scope
                    .map_or(capsule.capture, |prior| CaptureInterval {
                        earliest: prior.earliest.min(capsule.capture.earliest),
                        latest: prior.latest.max(capsule.capture.latest),
                    }),
            );
        let health_observation = match &mut self.health {
            Some(screen) => Some(screen.observe(
                HealthFrame {
                    source_generation: self.health_source,
                    segment: segment as u64,
                    capsule_digest,
                    capture: capsule.capture,
                    dimensions: size,
                    gap_before: capsule.gap_before || gap,
                    pixels: &pixels,
                },
                self.time_reliable,
                cx,
            )?),
            None => None,
        };
        if self.time_reliable {
            if self.previous_capture.is_some_and(|old| {
                capsule.capture.earliest < old.earliest || capsule.capture.latest < old.latest
            }) {
                return Err(dwell_error(DwellError::ClockReversed));
            }
            self.previous_capture = Some(capsule.capture);
        } else {
            self.unreliable += 1;
        }
        if self.background.is_none() {
            self.background = Some(ForegroundDetector::new(background_config(plan, size))?);
        }
        let foreground = self
            .background
            .as_mut()
            .ok_or(WatchError::Conflict)?
            .observe(&pixels, size[0], size[1])?;
        if foreground.boxes.len() > MAX_TRACKS {
            return Err(WatchError::Limit);
        }
        let detections: Vec<_> = foreground
            .boxes
            .iter()
            .map(|b| Detection {
                box_x: f64::from(b.x),
                box_y: f64::from(b.y),
                box_w: f64::from(b.width),
                box_h: f64::from(b.height),
            })
            .collect();
        let previous_tracks = self.previous_tracks;
        let work = if detections.is_empty() {
            0
        } else {
            previous_tracks * previous_tracks * (previous_tracks + detections.len() as u64)
        };
        charge(
            &mut self.assignment_work,
            work,
            self.limits.maximum_assignment_work,
        )?;
        let mut output = self.tracker.try_step(
            &detections,
            TrackerLimits {
                max_tracks: MAX_TRACKS,
                max_detections: MAX_TRACKS,
                ..TrackerLimits::default()
            },
        )?;
        self.previous_tracks = output.tracks.len() as u64;
        output.tracks.sort_by_key(|target| target.id);
        self.temporal.observe(
            plan,
            self.rule,
            &output.tracks,
            self.masked,
            position,
            self.time_reliable.then_some(capsule.capture),
            segment,
            capsule_digest,
        )?;
        let luma_digest = ContentDigest::sha256(&pixels);
        if let Some(observer) = &mut self.observer {
            observer.observe(ScanObservation {
                epoch: self.temporal.epoch(),
                position,
                segment,
                capsule,
                capsule_digest,
                luma_digest,
                dimensions: size,
                time_reliable: self.time_reliable,
                privacy: self.privacy,
                tracks: &output.tracks,
                zone_entries: match &self.temporal {
                    TemporalAccumulator::Entry { entries, .. } => {
                        let first = entries.partition_point(|entry| entry.position < position);
                        &entries[first..]
                    }
                    _ => &[],
                },
            })?;
        }
        frame_record.bool(true);
        frame_record.u64(self.temporal.epoch());
        frame_record.u32(size[0]);
        frame_record.u32(size[1]);
        frame_record.digest(luma_digest);
        frame_record.bool(foreground.baseline_initialized);
        frame_record.u64(detections.len() as u64);
        for detection in &detections {
            for value in [
                detection.box_x,
                detection.box_y,
                detection.box_w,
                detection.box_h,
            ] {
                frame_record.u64(value.to_bits());
            }
        }
        frame_record.u64(output.tracks.len() as u64);
        for target in &output.tracks {
            frame_record.u64(target.id);
            frame_record.u8(match target.status {
                TrackStatus::Tentative => 0,
                TrackStatus::Confirmed => 1,
                TrackStatus::Lost => 2,
            });
            frame_record.u32(target.hits);
            frame_record.u32(target.misses);
            for value in [
                target.cx,
                target.cy,
                target.vx,
                target.vy,
                target.box_w,
                target.box_h,
            ] {
                frame_record.u64(value.to_bits());
            }
        }
        if let Some(observation) = health_observation {
            frame_record.text("sensor_health");
            frame_record.bytes(&observation.canonical_bytes());
        }
        append_trace(
            &mut self.trace,
            &frame_record.finish_checked()?,
            self.limits.maximum_trace_bytes,
        )?;
        self.decoded += 1;
        Ok(())
    }

    /// One decoded inter-coded frame at dwell `position` (display order).
    fn inter_frame(
        &mut self,
        position: usize,
        frame: TolerantFrame,
        first_capsule: &SensorCapsule,
        screened: bool,
        cx: &ReplayCx,
    ) -> Result<()> {
        if frame.capsule.sensor_id != first_capsule.sensor_id
            || (screened && frame.capsule.stream_id != first_capsule.stream_id)
        {
            return Err(RecordedDecodeError::InvalidReceipt.into());
        }
        let mut record = CanonicalEncoder::new();
        record.text(self.rule.frame_domain());
        record.u64(position as u64);
        record.u64(frame.segment as u64);
        record.digest(frame.capsule_digest);
        frame.capsule.capture.encode_canonical(&mut record);
        record.bool(self.time_reliable);
        record.bool(false);
        self.frame(
            frame.segment,
            position,
            &frame.capsule,
            frame.capsule_digest,
            false,
            frame.dimensions,
            frame.pixels,
            record,
            cx,
        )
    }

    /// Decodes an inter-coded (H.264/H.265, Annex-B or MP4) range in display order and
    /// analyses every frame; returns the custody chunk bytes read. Dwell positions are display
    /// positions `first_segment + k`, advanced past refused runs and breaks; each trace record
    /// also names the frame's coding segment and capsule. Without opt-in tolerance the first
    /// decode refusal refuses the scan (source gaps were already refused).
    #[allow(clippy::too_many_arguments)]
    fn inter_frames(
        &mut self,
        deployment: &ReferenceDeployment,
        first_capsule: &SensorCapsule,
        options: WatchOptions,
        end: usize,
        format: &str,
        screened: bool,
        cx: &ReplayCx,
    ) -> Result<u64> {
        let plan = self.plan;
        let decode = self.limits.decode;
        let mut position = plan.first_segment;
        let source_budget = SourceReadBudget::new(self.limits.maximum_source_chunk_bytes);
        if options.tolerate_decode_refusals {
            let request = TolerantRequest {
                import_identity: plan.import_identity,
                interpretation: plan.interpretation,
                first_segment: plan.first_segment,
                end,
                read_limits: decode.read_limits,
                jpeg_limits: decode.jpeg_limits,
                h264_limits: decode.h264_limits,
                h265_limits: decode.h265_limits,
                stream: true,
            };
            let mut source =
                TolerantSource::open_with_source_budget(deployment, request, &source_budget, cx)?;
            let mut budget = DecodeBudget::new(decode.jpeg_work_units);
            while let Some(item) = source.next(deployment, &mut budget, cx)? {
                checkpoint(cx, "long_dwell:frame")?;
                match item {
                    TolerantItem::Frame(frame) => {
                        self.inter_frame(position, *frame, first_capsule, screened, cx)?;
                        position = position.checked_add(1).ok_or(WatchError::Limit)?;
                    }
                    TolerantItem::Break(refusal) => {
                        if let Some(screen) = &mut self.health {
                            screen.discontinuity();
                        }
                        let mut record = CanonicalEncoder::new();
                        record.text(self.rule.frame_domain());
                        record.text("break");
                        record.u64(position as u64);
                        let skipped = match &refusal {
                            Some(run) => {
                                record.bool(true);
                                record.u64(run.first_segment as u64);
                                record.u64(run.last_segment as u64);
                                record.text(&run.error_id);
                                if run.error_id.ends_with("-RANGE-GAP-001") {
                                    self.time_reliable = false;
                                }
                                self.refused(run.first_segment, run.last_segment, &run.error_id)?;
                                run.last_segment - run.first_segment + 1
                            }
                            None => {
                                record.bool(false);
                                self.time_reliable = false;
                                1
                            }
                        };
                        append_trace(
                            &mut self.trace,
                            &record.finish_checked()?,
                            self.limits.maximum_trace_bytes,
                        )?;
                        position = position.checked_add(skipped).ok_or(WatchError::Limit)?;
                        self.restart()?;
                    }
                }
            }
            return Ok(source.chunk_bytes_read());
        }
        let frame = |segment: u64,
                     capsule: &SensorCapsule,
                     capsule_digest: ContentDigest,
                     dimensions: [u32; 2],
                     pixels: &[u8]|
         -> Result<TolerantFrame> {
            Ok(TolerantFrame {
                segment: usize::try_from(segment).map_err(|_| WatchError::Limit)?,
                capsule: capsule.clone(),
                capsule_digest,
                dimensions,
                pixels: pixels.to_vec(),
            })
        };
        if matches!(format, "annexb" | "mp4avc" | "mkvavc") {
            let request = RecordedH264Request {
                import_identity: plan.import_identity,
                first_segment: plan.first_segment,
                segment_count: plan.segment_count,
                interpretation: plan.interpretation,
                read_limits: decode.read_limits,
                decoder_limits: decode.h264_limits,
            };
            let mut range = RecordedH264Range::open_stream_with_source_budget(
                deployment,
                request,
                &source_budget,
                cx,
            )?;
            while let Some(decoded) = range.next_frame(deployment, cx)? {
                checkpoint(cx, "long_dwell:frame")?;
                let frame = frame(
                    decoded.segment_index(),
                    decoded.capsule(),
                    decoded.capsule_digest(),
                    decoded.dimensions(),
                    decoded.pixels(),
                )?;
                self.inter_frame(position, frame, first_capsule, screened, cx)?;
                position = position.checked_add(1).ok_or(WatchError::Limit)?;
            }
            Ok(source_budget.used())
        } else {
            let request = RecordedH265Request {
                import_identity: plan.import_identity,
                first_segment: plan.first_segment,
                segment_count: plan.segment_count,
                interpretation: plan.interpretation,
                read_limits: decode.read_limits,
                decoder_limits: decode.h265_limits,
            };
            let mut range = RecordedH265Range::open_stream_with_source_budget(
                deployment,
                request,
                &source_budget,
                cx,
            )?;
            while let Some(decoded) = range.next_frame(deployment, cx)? {
                checkpoint(cx, "long_dwell:frame")?;
                let frame = frame(
                    decoded.segment_index(),
                    decoded.capsule(),
                    decoded.capsule_digest(),
                    decoded.dimensions(),
                    decoded.pixels(),
                )?;
                self.inter_frame(position, frame, first_capsule, screened, cx)?;
                position = position.checked_add(1).ok_or(WatchError::Limit)?;
            }
            Ok(source_budget.used())
        }
    }
}

struct TemporalState {
    active: BTreeMap<(u64, usize), DwellAccumulator>,
    episodes: Vec<Episode>,
    epoch: u64,
}

/// Two temporal consumers share the exact same source/perception walk. Entry observation is
/// not a zero-duration dwell rule: it records the first actual confirmed match per track/zone.
enum TemporalAccumulator {
    Dwell(TemporalState),
    Observed {
        epoch: u64,
    },
    Entry {
        epoch: u64,
        seen: BTreeSet<(u64, usize)>,
        entries: Vec<super::long_watch::LongWatchEntry>,
    },
}
impl TemporalAccumulator {
    fn new(rule: ScanRule) -> Self {
        match rule {
            ScanRule::Dwell(_) => Self::Dwell(TemporalState {
                active: BTreeMap::new(),
                episodes: Vec::new(),
                epoch: 0,
            }),
            ScanRule::Observed => Self::Observed { epoch: 0 },
            ScanRule::ZoneEntry => Self::Entry {
                epoch: 0,
                seen: BTreeSet::new(),
                entries: Vec::new(),
            },
        }
    }

    fn epoch(&self) -> u64 {
        match self {
            Self::Dwell(state) => state.epoch,
            Self::Entry { epoch, .. } | Self::Observed { epoch } => *epoch,
        }
    }

    fn restart(&mut self) -> Result<()> {
        match self {
            Self::Dwell(state) => state.restart(),
            Self::Observed { epoch } => {
                *epoch = epoch.checked_add(1).ok_or(WatchError::Limit)?;
                Ok(())
            }
            Self::Entry { epoch, seen, .. } => {
                *epoch = epoch.checked_add(1).ok_or(WatchError::Limit)?;
                seen.clear();
                Ok(())
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn observe(
        &mut self,
        plan: &WatchPlan,
        rule: ScanRule,
        tracks: &[TrackedTarget],
        masked: &BTreeSet<usize>,
        position: usize,
        capture: Option<CaptureInterval>,
        segment: usize,
        capsule_digest: ContentDigest,
    ) -> Result<()> {
        match (self, rule) {
            (Self::Observed { .. }, ScanRule::Observed) => Ok(()),
            (Self::Dwell(state), ScanRule::Dwell(rule)) => {
                state.observe(plan, rule, tracks, masked, position, capture)
            }
            (
                Self::Entry {
                    epoch,
                    seen,
                    entries,
                },
                ScanRule::ZoneEntry,
            ) => {
                // Lost timing never becomes a physical entry time. The report counts each
                // excluded decoded frame, and its empty candidate set cannot certify absence.
                let Some(capture) = capture else {
                    return Ok(());
                };
                for target in tracks {
                    if target.status != TrackStatus::Confirmed || target.misses != 0 {
                        continue;
                    }
                    for (zone, geometry) in plan.zones.iter().enumerate() {
                        if masked.contains(&zone)
                            || !inside(target, geometry)
                            || seen.contains(&(target.id, zone))
                        {
                            continue;
                        }
                        if entries.len() == super::long_watch::MAX_LONG_WATCH_CANDIDATES {
                            return Err(WatchError::Limit);
                        }
                        seen.insert((target.id, zone));
                        entries.push(super::long_watch::LongWatchEntry {
                            epoch: *epoch,
                            track: target.id,
                            zone,
                            position,
                            segment,
                            capsule_digest,
                            capture,
                            filtered_box: [target.cx, target.cy, target.box_w, target.box_h]
                                .map(|value| value.round() as i64),
                        });
                    }
                }
                Ok(())
            }
            _ => Err(WatchError::Conflict),
        }
    }

    fn finish(&mut self) -> Result<(Vec<Episode>, Vec<super::long_watch::LongWatchEntry>)> {
        match self {
            Self::Observed { .. } => Ok((Vec::new(), Vec::new())),
            Self::Dwell(state) => {
                state.finish_active()?;
                let mut episodes = std::mem::take(&mut state.episodes);
                episodes.sort_by_key(|e| {
                    (
                        e.span.trigger.position,
                        e.epoch,
                        e.track,
                        e.zone,
                        e.span.first.position,
                    )
                });
                Ok((episodes, Vec::new()))
            }
            Self::Entry { entries, .. } => {
                let mut entries = std::mem::take(entries);
                entries.sort_by_key(|e| (e.position, e.epoch, e.track, e.zone));
                Ok((Vec::new(), entries))
            }
        }
    }
}
impl TemporalState {
    fn finish_active(&mut self) -> Result<()> {
        for ((track, zone), state) in std::mem::take(&mut self.active) {
            add_episode(
                &mut self.episodes,
                self.epoch,
                track,
                zone,
                state.finish().map_err(dwell_error)?,
            )?;
        }
        Ok(())
    }
    fn restart(&mut self) -> Result<()> {
        self.finish_active()?;
        self.epoch = self.epoch.checked_add(1).ok_or(WatchError::Limit)?;
        Ok(())
    }
    fn observe(
        &mut self,
        plan: &WatchPlan,
        rule: DwellPolicy,
        tracks: &[TrackedTarget],
        masked: &BTreeSet<usize>,
        segment: usize,
        capture: Option<CaptureInterval>,
    ) -> Result<()> {
        let mut eligible = BTreeSet::new();
        if capture.is_some() {
            for target in tracks {
                if target.status != TrackStatus::Confirmed || target.misses != 0 {
                    continue;
                }
                for (zone, geometry) in plan.zones.iter().enumerate() {
                    if !masked.contains(&zone) && inside(target, geometry) {
                        eligible.insert((target.id, zone));
                    }
                }
            }
        }
        // End every missed or excluded track/zone now, even if the tracker keeps coasting it.
        let ended: Vec<_> = self
            .active
            .keys()
            .filter(|key| !eligible.contains(*key))
            .copied()
            .collect();
        for (track, zone) in ended {
            let state = self
                .active
                .remove(&(track, zone))
                .ok_or(WatchError::Conflict)?;
            add_episode(
                &mut self.episodes,
                self.epoch,
                track,
                zone,
                state.finish().map_err(dwell_error)?,
            )?;
        }
        for (track, zone) in eligible {
            let state = match self.active.entry((track, zone)) {
                std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
                std::collections::btree_map::Entry::Vacant(entry) => entry
                    .insert(DwellAccumulator::new(rule, plan.segment_count).map_err(dwell_error)?),
            };
            let span = state
                .push(DwellSample {
                    position: segment,
                    capture,
                    matched_inside: true,
                    discontinuity: false,
                })
                .map_err(dwell_error)?;
            add_episode(&mut self.episodes, self.epoch, track, zone, span)?;
        }
        Ok(())
    }
}

fn append_trace(trace: &mut Vec<u8>, record: &[u8], maximum: usize) -> Result<()> {
    let additional = 8_usize.checked_add(record.len()).ok_or(WatchError::Limit)?;
    if trace
        .len()
        .checked_add(additional)
        .is_none_or(|n| n > maximum)
    {
        return Err(WatchError::Limit);
    }
    trace
        .try_reserve(additional)
        .map_err(|_| WatchError::Limit)?;
    trace.extend_from_slice(&(record.len() as u64).to_be_bytes());
    trace.extend_from_slice(record);
    Ok(())
}
fn charge(used: &mut u64, amount: u64, maximum: u64) -> Result<()> {
    *used = used
        .checked_add(amount)
        .filter(|n| *n <= maximum)
        .ok_or(WatchError::Limit)?;
    Ok(())
}

/// The temporal consumer changes, but source decode, authority, privacy and cost do not.
#[derive(Clone, Copy, Debug)]
pub(super) enum ScanRule {
    Dwell(DwellPolicy),
    ZoneEntry,
    Observed,
}
impl ScanRule {
    const fn frame_domain(self) -> &'static str {
        match self {
            Self::Dwell(_) => FRAME_DOMAIN,
            Self::ZoneEntry => "fss.long_watch_frame.v1",
            Self::Observed => "fss.long_corroboration_frame.v1",
        }
    }
}

fn source_read_error(error: WatchError) -> WatchError {
    if let WatchError::Decode(decode) = &error
        && let RecordedDecodeError::Source(source) = decode.as_ref()
        && matches!(
            source.as_ref(),
            super::FileIngestError::SpoolCapacityExceeded {
                limit: "stream_source_chunk_bytes",
                ..
            }
        )
    {
        return WatchError::Limit;
    }
    error
}

/// Private completed native scan. It contains bounded scalar trace/evidence, never pixel history.
pub(super) struct ScanData {
    limits: LongDwellLimits,
    pub(super) import_root: ContentDigest,
    pub(super) manifest_digest: ContentDigest,
    pub(super) import_anchor: LedgerAnchor,
    pub(super) sensor: SensorId,
    pub(super) privacy: MaskBinding,
    pub(super) publication_guard: SourcePublicationGuard,
    pub(super) trace: Vec<u8>,
    episodes: Vec<Episode>,
    pub(super) entries: Vec<super::long_watch::LongWatchEntry>,
    pub(super) decoded: usize,
    pub(super) unreliable: usize,
    pub(super) masked_zones: usize,
    pub(super) restarts: usize,
    pub(super) refusals: Vec<DecodeRefusal>,
    pub(super) source_bytes: u64,
    pub(super) pixel_samples: u64,
    pub(super) assignment_work: u64,
    pub(super) jpeg_work: u64,
    pub(super) health: Option<LongDwellHealthSummary>,
    pub(super) health_diagnostic: Option<super::historical_health::HistoricalHealthDiagnostic>,
    pub(super) media_format: String,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn run_scan(
    deployment: &ReferenceDeployment,
    plan: &WatchPlan,
    rule: ScanRule,
    options: WatchOptions,
    limits: &LongDwellLimits,
    cx: &ReplayCx,
    screened: bool,
) -> Result<ScanData> {
    run_scan_inner(deployment, plan, rule, options, limits, cx, screened, None)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn run_zone_observed_scan(
    deployment: &ReferenceDeployment,
    plan: &WatchPlan,
    options: WatchOptions,
    limits: &LongDwellLimits,
    cx: &ReplayCx,
    screened: bool,
    observer: &mut dyn ScanObserver,
) -> Result<ScanData> {
    run_scan_inner(
        deployment,
        plan,
        ScanRule::ZoneEntry,
        options,
        limits,
        cx,
        screened,
        Some(observer),
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn run_observed_scan(
    deployment: &ReferenceDeployment,
    plan: &WatchPlan,
    options: WatchOptions,
    limits: &LongDwellLimits,
    cx: &ReplayCx,
    screened: bool,
    observer: &mut dyn ScanObserver,
) -> Result<ScanData> {
    run_scan_inner(
        deployment,
        plan,
        ScanRule::Observed,
        options,
        limits,
        cx,
        screened,
        Some(observer),
    )
}

struct ScanPreparation {
    retained: RetainedFileImport,
    first_capsule: SensorCapsule,
    sensor: SensorId,
    privacy: MaskBinding,
    publication_guard: SourcePublicationGuard,
    masked: BTreeSet<usize>,
    time_reliable: bool,
    inter: bool,
}

fn prepare_scan(
    deployment: &ReferenceDeployment,
    plan: &WatchPlan,
    rule: ScanRule,
    options: WatchOptions,
    limits: &LongDwellLimits,
    cx: &ReplayCx,
) -> Result<ScanPreparation> {
    checkpoint(cx, "long_dwell:analyze")?;
    if cx.root_dir() != deployment.root() {
        return Err(WatchError::Conflict);
    }
    if deployment.site_lineage().len() > 256 || cx.io_authority().principal().len() > 128 {
        return Err(WatchError::InvalidPlan(
            "site or principal exceeds long-dwell bounds",
        ));
    }
    if !(1..=MAX_LONG_DWELL_FRAMES).contains(&plan.segment_count)
        || plan.first_segment.checked_add(plan.segment_count).is_none()
    {
        return Err(WatchError::InvalidPlan(
            "long dwell requires 1..65536 segments",
        ));
    }
    // Reuse every existing zone/config check without broadening ordinary watch's range.
    let mut validation = plan.clone();
    validation.segment_count = 1;
    validation.validate()?;
    if let ScanRule::Dwell(rule) = rule {
        rule.validate().map_err(dwell_error)?;
    }
    limits.validate()?;
    deployment
        .ledger()
        .verify_durable_head()
        .map_err(ReferenceError::from)?;
    let retained = RetainedFileImport::open(
        deployment,
        plan.import_identity,
        limits.decode.read_limits,
        cx,
    )?;
    let source = retained.manifest();
    let inter = match source.format.as_str() {
        "mjpeg" => false,
        "annexb" | "hevc" | "mp4avc" | "mp4hevc" | "mkvavc" | "mkvhevc" => true,
        _ => return Err(RecordedDecodeError::UnsupportedMedia.into()),
    };
    if source.capture_time_label != "operator_assumption" {
        return Err(WatchError::InvalidPlan(
            "long dwell requires explicit capture-time hints",
        ));
    }
    let end = plan.first_segment + plan.segment_count;
    if end > source.segment_spans.len() {
        return Err(RecordedDecodeError::Unavailable.into());
    }
    if !options.tolerate_decode_refusals {
        for span in &source.segment_spans[plan.first_segment + 1..end] {
            if span.gap_before {
                return Err(WatchError::SourceGap {
                    segment: span.segment_index,
                });
            }
        }
    }
    let (first_capsule, _) = source_capsule(deployment, &retained, plan.first_segment)?;
    let sensor = first_capsule.sensor_id.clone();
    let privacy = current_mask(deployment, &sensor).map_err(RecordedDecodeError::from)?;
    let mut publication_guard = SourcePublicationGuard::capture(
        deployment,
        &retained,
        &sensor,
        &privacy,
        limits.decode.read_limits,
        cx,
    );
    let capsule_prefix = format!("batch:file-import:{}:c", hex(plan.import_identity));
    let capsule_objects: BTreeSet<String> = source.segment_spans[plan.first_segment..end]
        .iter()
        .map(|span| format!("object:capsule:{}", span.capsule_id.as_str()))
        .collect();
    let capsule_digests: BTreeSet<ContentDigest> = deployment
        .ledger()
        .batches()
        .iter()
        .filter(|batch| {
            batch
                .batch_id
                .as_str()
                .strip_prefix(&capsule_prefix)
                .is_some_and(|suffix| {
                    !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit())
                })
        })
        .flat_map(|batch| batch.deltas.iter())
        .filter(|delta| {
            delta.family == "sensor_capsule"
                && delta.plane == fss_core::Plane::Authority
                && delta.prior_generation.is_none()
                && delta.new_generation == 1
                && capsule_objects.contains(delta.object_id.as_str())
        })
        .map(|delta| delta.payload_digest)
        .collect();
    if capsule_digests.len() != capsule_objects.len() {
        return Err(RecordedDecodeError::InvalidReceipt.into());
    }
    publication_guard.bind_capsules(capsule_digests);
    let masked: BTreeSet<usize> = plan
        .zones
        .iter()
        .enumerate()
        .filter_map(|(i, zone)| {
            privacy
                .policy()
                .filter(|p| {
                    p.zone_masking([zone.x, zone.y, zone.width, zone.height])
                        .any()
                })
                .map(|_| i)
        })
        .collect();
    // MP4 container structure is accounted, not lost media (never an MJPEG reason).
    let first_offset = source.segment_spans[plan.first_segment].offset;
    let time_reliable = !source.omission_spans.iter().any(|span| {
        !span.is_container_structure()
            && (matches!(rule, ScanRule::Dwell(_)) || span.offset < first_offset)
    }) && !source.segment_spans[..=plan.first_segment]
        .iter()
        .any(|s| s.gap_before);
    Ok(ScanPreparation {
        retained,
        first_capsule,
        sensor,
        privacy,
        publication_guard,
        masked,
        time_reliable,
        inter,
    })
}

fn start_scan<'a, 'observer>(
    prepared: &'a ScanPreparation,
    plan: &'a WatchPlan,
    rule: ScanRule,
    limits: &'a LongDwellLimits,
    screened: bool,
    observer: Option<&'observer mut dyn ScanObserver>,
) -> Result<Scan<'a, 'observer>> {
    let health = if screened {
        Some(Screening::new(
            plan.segment_count,
            limits.maximum_pixel_samples,
        )?)
    } else {
        None
    };
    let health_source = super::recorded_watch::masked_plan_digest(plan.digest(), &prepared.privacy);
    Ok(Scan {
        plan,
        rule,
        masked: &prepared.masked,
        limits,
        privacy: &prepared.privacy,
        health_source,
        health,
        time_reliable: prepared.time_reliable,
        tracker: MultiObjectTracker::new(tracker_config(plan))?,
        background: None,
        dimensions: None,
        temporal: TemporalAccumulator::new(rule),
        observer,
        previous_capture: None,
        capture_scope: None,
        previous_tracks: 0,
        trace: Vec::new(),
        decoded: 0,
        unreliable: 0,
        restarts: 0,
        refusals: Vec::new(),
        pixel_samples: 0,
        assignment_work: 0,
    })
}

#[allow(clippy::too_many_arguments)]
fn scan_mjpeg_range(
    scan: &mut Scan<'_, '_>,
    deployment: &ReferenceDeployment,
    prepared: &ScanPreparation,
    options: WatchOptions,
    first: usize,
    end: usize,
    cursor: &mut ChunkCursor,
    codec_budget: &mut DecodeBudget<'_>,
    screened: bool,
    cx: &ReplayCx,
) -> Result<()> {
    let plan = scan.plan;
    let limits = scan.limits;
    let rule = scan.rule;
    let retained = &prepared.retained;
    let source = retained.manifest();
    let sensor = &prepared.sensor;
    let first_capsule = &prepared.first_capsule;
    // `segment` is a source position (capsule lookup, cursor), not only a span index.
    #[allow(clippy::needless_range_loop)]
    for segment in first..end {
        checkpoint(cx, "long_dwell:frame")?;
        let gap = source.segment_spans[segment].gap_before && segment > plan.first_segment;
        if gap {
            if let Some(screen) = &mut scan.health {
                screen.discontinuity();
            }
            scan.time_reliable = false;
            scan.restart()?;
        }
        let (capsule, capsule_digest) = source_capsule(deployment, retained, segment)?;
        if &capsule.sensor_id != sensor {
            return Err(RecordedDecodeError::InvalidReceipt.into());
        }
        if screened && capsule.stream_id != first_capsule.stream_id {
            return Err(RecordedDecodeError::InvalidReceipt.into());
        }
        if source.segment_spans[segment].len > limits.decode.jpeg_limits.maximum_bytes as u64 {
            return Err(WatchError::Limit);
        }
        let bytes = cursor.segment(deployment, retained, segment, limits.decode.read_limits, cx)?;
        let mut frame_record = CanonicalEncoder::new();
        frame_record.text(rule.frame_domain());
        frame_record.u64(segment as u64);
        frame_record.digest(capsule_digest);
        capsule.capture.encode_canonical(&mut frame_record);
        frame_record.bool(scan.time_reliable);
        frame_record.bool(gap);
        let image = match decode_luma(
            &bytes,
            capsule.source_digest.bytes(),
            plan.interpretation,
            limits.decode.jpeg_limits,
            codec_budget,
        )
        .map_err(RecordedDecodeError::from)
        {
            Ok(image) => image,
            Err(error) if options.tolerate_decode_refusals && tolerable(&error) => {
                if let Some(screen) = &mut scan.health {
                    screen.discontinuity();
                }
                frame_record.bool(false);
                frame_record.text(error.stable_id());
                append_trace(
                    &mut scan.trace,
                    &frame_record.finish_checked()?,
                    limits.maximum_trace_bytes,
                )?;
                scan.refused(segment, segment, error.stable_id())?;
                scan.restart()?;
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        scan.frame(
            segment,
            segment,
            &capsule,
            capsule_digest,
            gap,
            image.dimensions(),
            image.pixels().to_vec(),
            frame_record,
            cx,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn finish_scan(
    scan: Scan<'_, '_>,
    deployment: &ReferenceDeployment,
    prepared: &ScanPreparation,
    plan: &WatchPlan,
    rule: ScanRule,
    options: WatchOptions,
    limits: &LongDwellLimits,
    source_bytes: u64,
    jpeg_work: u64,
    screened: bool,
    cx: &ReplayCx,
) -> Result<ScanData> {
    let source = prepared.retained.manifest();
    let first_capsule = &prepared.first_capsule;
    let retained = &prepared.retained;
    let end = plan.first_segment + plan.segment_count;
    let Scan {
        mut temporal,
        trace,
        decoded,
        unreliable,
        restarts,
        refusals,
        pixel_samples,
        assignment_work,
        health,
        capture_scope,
        ..
    } = scan;
    if decoded == 0 && !screened {
        return Err(RecordedDecodeError::Unavailable.into());
    }
    let (episodes, entries) = temporal.finish()?;
    deployment
        .ledger()
        .verify_durable_head()
        .map_err(ReferenceError::from)?;
    let health = health.map(|screen| screen.finish(plan.segment_count));
    // An entirely refused screened request still has historical source timing assertions, but
    // no screened-frame interval. Bind its requested capsule-hint hull explicitly; consumers
    // must distinguish it from the hull of actual screened samples and from live coverage.
    let capture_scope = if screened && capture_scope.is_none() {
        let mut hull = first_capsule.capture;
        for segment in plan.first_segment + 1..end {
            checkpoint(cx, "historical_health:requested_capture")?;
            let (capsule, _) = source_capsule(deployment, retained, segment)?;
            if capsule.sensor_id != first_capsule.sensor_id
                || capsule.stream_id != first_capsule.stream_id
            {
                return Err(RecordedDecodeError::InvalidReceipt.into());
            }
            hull.earliest = hull.earliest.min(capsule.capture.earliest);
            hull.latest = hull.latest.max(capsule.capture.latest);
        }
        Some(hull)
    } else {
        capture_scope
    };
    let health_diagnostic = health
        .as_ref()
        .map(|summary| {
            super::historical_health::HistoricalHealthDiagnostic::from_scan(
                deployment,
                plan,
                rule,
                options,
                limits,
                &prepared.retained,
                &prepared.first_capsule,
                &prepared.privacy,
                &prepared.publication_guard,
                capture_scope.ok_or(WatchError::Conflict)?,
                unreliable,
                restarts,
                source_bytes,
                pixel_samples,
                assignment_work,
                jpeg_work,
                summary,
                &trace,
                cx,
            )
            .map_err(|_| WatchError::InvalidPlan("invalid historical health diagnostic"))
        })
        .transpose()?;
    Ok(ScanData {
        limits: *limits,
        import_root: prepared.retained.import_root(),
        manifest_digest: prepared.retained.manifest_digest(),
        import_anchor: prepared.retained.authority_anchor().clone(),
        sensor: prepared.sensor.clone(),
        privacy: prepared.privacy.clone(),
        publication_guard: prepared.publication_guard.clone(),
        trace,
        episodes,
        entries,
        decoded,
        unreliable,
        masked_zones: prepared.masked.len(),
        restarts,
        refusals,
        source_bytes,
        pixel_samples,
        assignment_work,
        jpeg_work,
        health,
        health_diagnostic,
        media_format: source.format.clone(),
    })
}

#[allow(clippy::too_many_arguments)]
fn run_scan_inner(
    deployment: &ReferenceDeployment,
    plan: &WatchPlan,
    rule: ScanRule,
    options: WatchOptions,
    limits: &LongDwellLimits,
    cx: &ReplayCx,
    screened: bool,
    observer: Option<&mut dyn ScanObserver>,
) -> Result<ScanData> {
    let prepared = prepare_scan(deployment, plan, rule, options, limits, cx)?;
    let mut scan = start_scan(&prepared, plan, rule, limits, screened, observer)?;
    let end = plan.first_segment + plan.segment_count;
    let (source_bytes, jpeg_work) = if prepared.inter {
        let bytes = scan
            .inter_frames(
                deployment,
                &prepared.first_capsule,
                options,
                end,
                prepared.retained.manifest().format.as_str(),
                screened,
                cx,
            )
            .map_err(source_read_error)?;
        (bytes, 0)
    } else {
        let mut cursor = ChunkCursor::new(limits.maximum_source_chunk_bytes);
        let mut codec_budget = DecodeBudget::new(limits.decode.jpeg_work_units);
        scan_mjpeg_range(
            &mut scan,
            deployment,
            &prepared,
            options,
            plan.first_segment,
            end,
            &mut cursor,
            &mut codec_budget,
            screened,
            cx,
        )?;
        (cursor.bytes_read(), codec_budget.used())
    };
    finish_scan(
        scan,
        deployment,
        &prepared,
        plan,
        rule,
        options,
        limits,
        source_bytes,
        jpeg_work,
        screened,
        cx,
    )
}

impl LongDwellReport {
    /// Decode a whole native recording, preserving foreground/tracker/dwell state between frames.
    /// No 128-frame windows, model calls, pixel history, implicit retries, or coverage claims.
    pub fn analyze(
        deployment: &ReferenceDeployment,
        plan: &WatchPlan,
        rule: DwellPolicy,
        options: WatchOptions,
        limits: &LongDwellLimits,
        cx: &ReplayCx,
    ) -> Result<Self> {
        Self::analyze_inner(deployment, plan, rule, options, limits, cx, false, None)
    }

    /// Opt-in conservative-v1 screening over the same masked pixels, before perception.
    /// Findings preserve diagnostic candidates but block publication of the entire request.
    /// No finding is a diagnosis; a complete screen with no findings is not proof of health.
    pub fn analyze_screened(
        deployment: &ReferenceDeployment,
        plan: &WatchPlan,
        rule: DwellPolicy,
        options: WatchOptions,
        limits: &LongDwellLimits,
        cx: &ReplayCx,
    ) -> Result<Self> {
        Self::analyze_inner(deployment, plan, rule, options, limits, cx, true, None)
    }

    /// Analyze the complete recording, then classify bounded actual observations belonging to
    /// qualifying dwell episodes. Source, pixels, JPEG work, inference slots and detection-head
    /// work share one whole-invocation allowance. Publication retains the exact model package.
    #[allow(clippy::too_many_arguments)]
    pub fn analyze_with_detector(
        deployment: &ReferenceDeployment,
        plan: &WatchPlan,
        rule: DwellPolicy,
        options: WatchOptions,
        limits: &LongDwellLimits,
        detector: &LongDwellDetector<'_>,
        screened: bool,
        cx: &ReplayCx,
    ) -> Result<Self> {
        Self::analyze_inner(
            deployment,
            plan,
            rule,
            options,
            limits,
            cx,
            screened,
            Some(detector),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn analyze_inner(
        deployment: &ReferenceDeployment,
        plan: &WatchPlan,
        rule: DwellPolicy,
        options: WatchOptions,
        limits: &LongDwellLimits,
        cx: &ReplayCx,
        screened: bool,
        detector: Option<&LongDwellDetector<'_>>,
    ) -> Result<Self> {
        if let Some(detector) = detector {
            let _ = super::long_watch::detector::LongWatchDetectorRecipe::new(
                detector.package,
                detector.config,
                detector.limits,
                limits,
            )?;
        }
        let scan = run_scan(
            deployment,
            plan,
            ScanRule::Dwell(rule),
            options,
            limits,
            cx,
            screened,
        )?;
        let detector = detector
            .map(|detector| {
                classify::run_native_detector(deployment, plan, options, &scan, detector, cx)
            })
            .transpose()?;
        Self::from_scan(deployment, plan, rule, options, scan, detector, cx)
    }

    fn from_scan(
        deployment: &ReferenceDeployment,
        plan: &WatchPlan,
        rule: DwellPolicy,
        options: WatchOptions,
        scan: ScanData,
        detector: Option<super::long_watch::detector::Completed>,
        cx: &ReplayCx,
    ) -> Result<Self> {
        let ScanData {
            limits,
            import_root,
            manifest_digest,
            import_anchor,
            sensor,
            privacy,
            trace,
            episodes,
            decoded,
            unreliable,
            masked_zones,
            restarts,
            refusals,
            source_bytes,
            pixel_samples,
            assignment_work,
            jpeg_work,
            health,
            health_diagnostic,
            media_format,
            publication_guard,
            ..
        } = scan;
        let policy: &'static [u8] = if media_format == "mjpeg" {
            POLICY
        } else {
            POLICY_INTER
        };
        let mut e = CanonicalEncoder::new();
        e.text(ANALYSIS_DOMAIN);
        e.digest(ContentDigest::sha256(policy));
        e.text(deployment.site_lineage());
        e.digest(plan.digest());
        // Retain the complete replay recipe, not merely a hash requiring the original CLI.
        e.digest(plan.import_identity);
        e.u64(plan.first_segment as u64);
        e.u64(plan.segment_count as u64);
        e.u64(plan.zones.len() as u64);
        for zone in &plan.zones {
            e.text(&zone.zone_id);
            for value in [zone.x, zone.y, zone.width, zone.height] {
                e.u32(value);
            }
        }
        let parameters = super::recorded_watch::pipeline_parameters(
            plan.interpretation,
            &plan.detector,
            &plan.tracker,
        );
        e.u64(parameters.len() as u64);
        for parameter in parameters {
            e.u64(parameter);
        }
        e.digest(import_root);
        e.digest(manifest_digest);
        import_anchor.encode_canonical(&mut e);
        e.text(sensor.as_str());
        e.digest(privacy.digest());
        e.u64(rule.minimum_duration_ns);
        e.u64(rule.maximum_sample_gap_ns);
        e.u64(rule.minimum_observations as u64);
        e.bool(options.tolerate_decode_refusals);
        e.u64(plan.segment_count as u64);
        // Keep only a range into the canonical record, not another retained copy of the trace.
        // This private context enables a completed untrained scan to enter the existing
        // classifier stage later without decoding its foreground/tracker prefix again.
        let classification = if detector.is_none() {
            let start = e
                .clone()
                .finish_checked()?
                .len()
                .checked_add(std::mem::size_of::<u64>())
                .ok_or(WatchError::Limit)?;
            let end = start.checked_add(trace.len()).ok_or(WatchError::Limit)?;
            Some(classify::ClassificationSource {
                limits,
                manifest_digest,
                import_anchor: import_anchor.clone(),
                trace: start..end,
            })
        } else {
            None
        };
        e.bytes(&trace);
        if let Some(summary) = &health {
            e.text("sensor_health");
            e.bytes(health_policy_bytes());
            summary.encode(&mut e);
        }
        if let Some(detector) = &detector {
            e.text("detector_cascade");
            e.bytes(detector::SELECTION_POLICY);
            e.bytes(&detector.recipe.to_bytes());
            e.bytes(&detector.bytes);
        }
        let analysis = e.finish_checked()?;
        let analysis_digest = ContentDigest::sha256(&analysis);
        let mut children = BTreeSet::from([
            import_root,
            analysis_digest,
            ContentDigest::sha256(policy),
            ContentDigest::sha256(sensor.as_str().as_bytes()),
        ]);
        if let Some(policy) = privacy.policy() {
            children.insert(policy.digest());
        }
        if health.is_some() {
            children.insert(health_policy_digest());
        }
        if let Some(detector) = &detector {
            children.extend(detector.children());
        }
        let analysis_manifest =
            ObjectManifest::new("recorded-long-dwell-analysis-v1", children, None)?;
        let analysis_slot = slot("ld-a", analysis_digest)?;
        let principal = cx.io_authority().principal().to_owned();
        let mut candidates = Vec::new();
        for (index, episode) in episodes.into_iter().enumerate() {
            candidates.push(prepare_candidate(
                deployment,
                episode,
                plan,
                analysis_manifest.root(),
                &sensor,
                &principal,
                &privacy,
                policy,
                detector.as_ref().map(|detector| (detector, index)),
            )?);
        }
        let report = Self {
            plan: plan.clone(),
            rule,
            options,
            root: deployment.root().to_path_buf(),
            site: deployment.site_lineage().to_owned(),
            principal,
            basis: deployment.current_anchor().clone(),
            import_root,
            sensor,
            media_format,
            privacy,
            publication_guard,
            analysis,
            analysis_manifest,
            analysis_slot,
            candidates,
            decoded,
            unreliable,
            masked_zones,
            restarts,
            refusals,
            source_bytes: source_bytes
                .checked_add(detector.as_ref().map_or(0, |d| d.source_bytes))
                .ok_or(WatchError::Limit)?,
            pixel_samples: pixel_samples
                .checked_add(detector.as_ref().map_or(0, |d| d.pixel_samples))
                .ok_or(WatchError::Limit)?,
            assignment_work,
            jpeg_work: jpeg_work
                .checked_add(detector.as_ref().map_or(0, |d| d.jpeg_work))
                .ok_or(WatchError::Limit)?,
            policy,
            health,
            health_diagnostic,
            detector,
            classification,
        };
        report.to_json(deployment.current_anchor().commit_sequence, None)?;
        Ok(report)
    }

    /// Complete ordered proposals; no qualifying episode is silently dropped to fit a bound.
    pub fn candidates(&self) -> &[LongDwellCandidate] {
        &self.candidates
    }
    /// Exact canonical per-frame trace and its source/rule bindings.
    pub fn analysis_digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.analysis)
    }
    /// Complete root recomputed by the read-only retained replay owner.
    pub(crate) fn replay_analysis_root(&self) -> ContentDigest {
        self.analysis_manifest.root()
    }
    /// Actual source-chunk bytes fetched, not per-segment logical lengths.
    pub const fn source_chunk_bytes_read(&self) -> u64 {
        self.source_bytes
    }
    /// Successfully decoded source segments.
    pub const fn frames_decoded(&self) -> usize {
        self.decoded
    }
    /// Complete trained-stage output, including refused and budget-exhausted selected samples.
    pub fn detector_cascade(&self) -> Option<&super::detector_cascade::CascadeOutcome> {
        self.detector.as_ref().map(|detector| &detector.outcome)
    }
    /// Exact retained native decoder, model, kernel and whole-scan budget recipe.
    pub fn detector_recipe(&self) -> Option<&super::long_watch::detector::LongWatchDetectorRecipe> {
        self.detector.as_ref().map(|detector| &detector.recipe)
    }
    /// Explicit opt-in diagnostics; `None` means no screening was requested, never healthy.
    pub fn health_summary(&self) -> Option<&LongDwellHealthSummary> {
        self.health.as_ref()
    }
    /// Independently approvable historical diagnostic; this does not grant event authority.
    pub fn health_diagnostic(
        &self,
    ) -> Option<&super::historical_health::HistoricalHealthDiagnostic> {
        self.health_diagnostic.as_ref()
    }
    /// True when this report's health gate forbids any event publication.
    pub fn publication_blocked(&self) -> bool {
        self.health
            .as_ref()
            .is_some_and(LongDwellHealthSummary::publication_blocked)
    }

    /// Publish only exact, source- and principal-bound proposals after all approvals validate.
    pub fn publish(
        &mut self,
        deployment: &mut ReferenceDeployment,
        approvals: &BTreeSet<ContentDigest>,
        cx: &ReplayCx,
    ) -> Result<usize> {
        checkpoint(cx, "long_dwell:revalidate")?;
        if self.publication_blocked() {
            return Err(WatchError::InvalidPlan(HEALTH_PUBLICATION_BLOCKED));
        }
        if deployment.root() != self.root.as_path()
            || cx.root_dir() != deployment.root()
            || deployment.site_lineage() != self.site.as_str()
            || cx.io_authority().principal() != self.principal.as_str()
        {
            return Err(WatchError::Conflict);
        }
        for approval in approvals {
            if !self.candidates.iter().any(|c| c.approval == *approval) {
                return Err(WatchError::StaleApproval(*approval));
            }
        }
        self.publication_guard.revalidate(deployment, cx)?;
        for candidate in &mut self.candidates {
            if approvals.contains(&candidate.approval) {
                candidate.status = event_status(deployment, &candidate.event)?;
            }
        }
        self.to_json(deployment.current_anchor().commit_sequence, None)?;
        if !self
            .candidates
            .iter()
            .any(|c| approvals.contains(&c.approval) && c.status == WatchStatus::Prepared)
        {
            return Ok(0);
        }
        checkpoint(cx, "long_dwell:stage")?;
        for bytes in [
            self.analysis.as_slice(),
            self.policy,
            self.sensor.as_str().as_bytes(),
        ] {
            let digest = deployment.publisher_mut().stage_object(bytes)?;
            deployment.publisher_mut().verify_object(digest)?;
        }
        if let Some(detector) = &self.detector {
            for bytes in detector.staged() {
                let digest = deployment.publisher_mut().stage_object(bytes)?;
                deployment.publisher_mut().verify_object(digest)?;
            }
            let digest = deployment
                .publisher_mut()
                .stage_object(&detector.recipe.to_bytes())?;
            deployment.publisher_mut().verify_object(digest)?;
        }
        if self.health.is_some() {
            let digest = deployment
                .publisher_mut()
                .stage_object(health_policy_bytes())?;
            deployment.publisher_mut().verify_object(digest)?;
        }
        if let Some(policy) = self.privacy.policy() {
            let digest = deployment
                .publisher_mut()
                .stage_object(&policy.to_bytes())?;
            deployment.publisher_mut().verify_object(digest)?;
        }
        let validity = self
            .candidates
            .iter()
            .map(|c| c.event.interval)
            .reduce(|a, b| CaptureInterval {
                earliest: a.earliest.min(b.earliest),
                latest: a.latest.max(b.latest),
            })
            .ok_or(WatchError::Conflict)?;
        publish_manifest(
            deployment,
            &self.analysis_slot,
            &self.analysis_manifest,
            validity,
            cx,
        )?;
        let mut published = 0;
        for candidate in &mut self.candidates {
            if !approvals.contains(&candidate.approval)
                || candidate.status == WatchStatus::AlreadyPublished
            {
                continue;
            }
            checkpoint(cx, "long_dwell:episode")?;
            let digest = deployment.publisher_mut().stage_object(&candidate.record)?;
            deployment.publisher_mut().verify_object(digest)?;
            publish_manifest(
                deployment,
                &candidate.slot,
                &candidate.manifest,
                candidate.event.interval,
                cx,
            )?;
            checkpoint(cx, "long_dwell:commit")?;
            deployment.publish_event(
                &ReferencePolicyDecision {
                    event: candidate.event.clone(),
                    action: ReferencePolicyAction::Hold,
                },
                cx,
            )?;
            cx.checkpoint_post_commit("long_dwell:published");
            candidate.status = WatchStatus::Published;
            published += 1;
        }
        Ok(published)
    }

    /// Complete bounded JSON; source time, incomplete decoding, and lack of absence proof remain explicit.
    pub fn to_json(&self, authority_sequence: u64, approve_hint: Option<&str>) -> Result<String> {
        if approve_hint.is_some_and(|hint| hint.len() > 8192) {
            return Err(WatchError::Limit);
        }
        let approve_hint = if self.publication_blocked() {
            None
        } else {
            approve_hint
        };
        let candidates = self.candidates.iter().map(|c| {
            let span = c.span();
            let command = match (c.status, approve_hint) {
                (WatchStatus::Prepared, Some(hint)) => json(&format!("{hint} --approve {}", c.approval)),
                _ => "null".to_owned(),
            };
            let class_evidence = if self.detector.is_some() {
                format!(",\"class_evidence\":{}", super::detector_cascade::class_evidence_json(&c.class_evidence))
            } else { String::new() };
            format!(concat!("{{\"event_id\":{},\"zone_id\":{},\"tracker_epoch\":{},\"track_id\":{},",
                "\"first_segment\":{},\"trigger_segment\":{},\"last_segment\":{},\"matched_observations\":{},",
                "\"trigger_minimum_ns\":{},\"minimum_duration_ns\":{},\"proposal_digest\":{},",
                "\"provenance_root\":{},\"status\":{},\"publish_command\":{command}{class_evidence}}}"),
                json(c.event.event_id.as_str()), json(&self.plan.zones[c.episode.zone].zone_id),
                c.episode.epoch, c.episode.track, span.first.position, span.trigger.position, span.last.position,
                span.observations, json(&span.trigger_minimum_ns.to_string()), json(&span.minimum_duration_ns.to_string()),
                json(&c.approval.to_text()), json(&c.manifest.root().to_text()), json(c.status.as_str()), command = command, class_evidence = class_evidence)
        }).collect::<Vec<_>>().join(",");
        let refusals = self
            .refusals
            .iter()
            .map(|r| {
                format!(
                    "{{\"first_segment\":{},\"last_segment\":{},\"error_id\":{}}}",
                    r.first_segment,
                    r.last_segment,
                    json(&r.error_id)
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let mut text = format!(
            concat!(
                "{{\"format\":\"fss.long_dwell_report.v1\",\"site\":{},\"principal\":{},",
                "\"import_identity\":{},\"import_root\":{},\"plan_digest\":{},\"analysis_digest\":{},\"analysis_root\":{},",
                "\"analysis_basis_sequence\":{},\"analysis_basis_root\":{},\"authority_sequence\":{},\"first_segment\":{},\"segment_count\":{},",
                "\"frames_decoded\":{},\"unreliable_time_frames\":{},\"masked_zones\":{},\"tracking_restarts\":{},",
                "\"minimum_duration_ns\":{},\"maximum_sample_gap_ns\":{},\"minimum_observations\":{},",
                "\"tolerate_decode_refusals\":{},\"decode_refusals\":[{}],\"source_chunk_bytes_read\":{},",
                "\"pixel_samples_processed\":{},\"assignment_work_admitted\":{},\"jpeg_work_units\":{},\"trace_record_bytes\":{},",
                "\"privacy_binding\":{},\"candidate_count\":{},\"candidates\":[{}],",
                "\"media_format\":{},\"capture_time_label\":\"operator_assumption\",",
                "\"event_kind\":\"unclassified\",\"event_state\":\"indeterminate\",\"policy_action\":\"hold\",",
                "\"calibrated\":false,\"corroborated\":false,\"continuous_occupancy_proved\":false,",
                "\"absence_certifiable\":false,\"alert_authorized\":false,\"model_invoked\":{},",
                "\"qualification\":\"implemented_not_qualified\"}}"
            ),
            json(&self.site),
            json(&self.principal),
            json(&self.plan.import_identity.to_text()),
            json(&self.import_root.to_text()),
            json(&self.plan.digest().to_text()),
            json(&self.analysis_digest().to_text()),
            json(&self.analysis_manifest.root().to_text()),
            self.basis.commit_sequence,
            json(&self.basis.state_root.to_text()),
            authority_sequence,
            self.plan.first_segment,
            self.plan.segment_count,
            self.decoded,
            self.unreliable,
            self.masked_zones,
            self.restarts,
            json(&self.rule.minimum_duration_ns.to_string()),
            json(&self.rule.maximum_sample_gap_ns.to_string()),
            self.rule.minimum_observations,
            self.options.tolerate_decode_refusals,
            refusals,
            self.source_bytes,
            self.pixel_samples,
            self.assignment_work,
            self.jpeg_work,
            self.analysis.len(),
            json(&self.privacy.digest().to_text()),
            self.candidates.len(),
            candidates,
            json(&self.media_format),
            self.detector
                .as_ref()
                .is_some_and(|detector| detector.inference_pipeline_attempts != 0)
        );
        if let Some(summary) = &self.health {
            if text.pop() != Some('}') {
                return Err(WatchError::Conflict);
            }
            text.push_str(",\"sensor_health\":");
            text.push_str(&summary.to_json());
            text.push('}');
        }
        if let Some(detector) = &self.detector {
            if text.pop() != Some('}') {
                return Err(WatchError::Conflict);
            }
            text.push_str(&format!(
                ",\"detector_cascade\":{{{},{},\"recipe_digest\":{},\"source_chunk_bytes_read\":{},\"jpeg_work_units\":{},\"additional_pixel_samples_processed\":{},\"inference_pipeline_attempts\":{},\"inferences_completed\":{},\"model_invocation_semantics\":\"native_pipeline_attempted_model_mac_execution_not_guaranteed\"}}}}",
                detector.policy_json, super::detector_cascade::cascade_outcome_json(&detector.outcome),
                json(&detector.recipe.digest().to_text()), detector.source_bytes, detector.jpeg_work,
                detector.pixel_samples, detector.inference_pipeline_attempts, detector.outcome.inferred_segments().len(),
            ));
        }
        if text.len() > MAX_REPORT_BYTES {
            return Err(WatchError::Limit);
        }
        Ok(text)
    }
}

pub(super) fn slot(prefix: &str, digest: ContentDigest) -> Result<SlotName> {
    SlotName::parse(&format!("{prefix}-{}", hex(digest)))
        .map_err(|_| WatchError::InvalidPlan("long dwell slot"))
}
pub(super) fn event_status(
    d: &ReferenceDeployment,
    event: &EventHypothesis,
) -> Result<WatchStatus> {
    let object = ObjectId::parse(format!("object:event:{}", event.event_id.as_str()))?;
    let Some(current) = d.ledger().current().objects.get(&object) else {
        return Ok(WatchStatus::Prepared);
    };
    if d.ledger().batches().iter().any(|b| {
        b.deltas.iter().any(|delta| {
            delta.object_id == object
                && delta.family == "event_revision"
                && delta.new_generation == current.generation
                && delta.payload_digest == current.payload_digest
                && delta.witness_digest == Some(event.revision_digest())
        })
    }) {
        Ok(WatchStatus::AlreadyPublished)
    } else {
        Err(WatchError::Conflict)
    }
}
#[allow(clippy::too_many_arguments)]
fn prepare_candidate(
    d: &ReferenceDeployment,
    episode: Episode,
    plan: &WatchPlan,
    analysis_root: ContentDigest,
    sensor: &SensorId,
    principal: &str,
    privacy: &MaskBinding,
    policy: &[u8],
    detector: Option<(&super::long_watch::detector::Completed, usize)>,
) -> Result<LongDwellCandidate> {
    let mut e = CanonicalEncoder::new();
    e.text(EPISODE_DOMAIN);
    e.digest(analysis_root);
    e.text(&plan.zones[episode.zone].zone_id);
    e.u64(episode.epoch);
    e.u64(episode.track);
    for sample in [episode.span.first, episode.span.trigger, episode.span.last] {
        e.u64(sample.position as u64);
        sample
            .capture
            .ok_or(WatchError::Conflict)?
            .encode_canonical(&mut e);
    }
    e.u64(episode.span.observations as u64);
    e.text(&episode.span.trigger_minimum_ns.to_string());
    e.text(&episode.span.minimum_duration_ns.to_string());
    let record = e.finish_checked()?;
    let identity = ContentDigest::sha256(&record);
    let manifest = ObjectManifest::new(
        "recorded-long-dwell-episode-v1",
        [analysis_root, identity],
        None,
    )?;
    let interval = CaptureInterval::new(
        episode
            .span
            .first
            .capture
            .ok_or(WatchError::Conflict)?
            .earliest,
        episode
            .span
            .last
            .capture
            .ok_or(WatchError::Conflict)?
            .latest,
    )?;
    let sensor_digest = ContentDigest::sha256(sensor.as_str().as_bytes());
    let failure_domain = format!("recorded-sensor:{}", hex(sensor_digest));
    let mut evidence = vec![EventEvidence {
        digest: identity,
        class: EvidenceClass::Derived,
        failure_domain: failure_domain.clone(),
        supports: false,
        relation: EvidenceEdgeRelation::DerivedFrom,
        capsule_digest: None,
        identity_digest: Some(sensor_digest),
    }];
    let class_evidence = match detector {
        Some((detector, index)) => {
            let classes = detector
                .outcome
                .evidence
                .get(index)
                .ok_or(WatchError::Conflict)?
                .clone();
            let selected = detector.entries.get(index).ok_or(WatchError::Conflict)?;
            if classes.len() != selected.frames.len() {
                return Err(WatchError::Conflict);
            }
            for (class, frame) in classes.iter().zip(&selected.frames) {
                evidence.push(EventEvidence {
                    digest: class.digest,
                    class: EvidenceClass::Derived,
                    failure_domain: failure_domain.clone(),
                    supports: false,
                    relation: EvidenceEdgeRelation::DerivedFrom,
                    capsule_digest: Some(frame.capsule),
                    identity_digest: Some(sensor_digest),
                });
            }
            classes
        }
        None => Vec::new(),
    };
    if let Some(policy) = privacy.policy() {
        evidence.push(EventEvidence {
            digest: policy.digest(),
            class: EvidenceClass::Assertion,
            failure_domain,
            supports: false,
            relation: EvidenceEdgeRelation::RequiredBy,
            capsule_digest: None,
            identity_digest: Some(sensor_digest),
        });
    }
    evidence.sort_by_key(|item| item.digest);
    let event = EventHypothesis {
        schema: EventHypothesis::SCHEMA.to_owned(), event_id: EventId::parse(format!("event:long-dwell:{}", hex(identity)))?,
        revision: 1, supersedes: None, state: EventState::Indeterminate, kind: EventKind::Unclassified,
        interval, uncertainty_reason: Some(UNCERTAINTY.to_owned()), zone_ids: vec![plan.zones[episode.zone].zone_id.clone()],
        track_ids: vec![format!("track:{}:{}", episode.epoch, episode.track)], probability: ProbabilityInterval::new(0.0, 1.0)?,
        evidence,
        model_receipts: Vec::new(), decision_path: DecisionPath {
            policy_generation: ContentDigest::sha256(policy), fingerprint: manifest.root(), abstained: true,
            abstention_reason: Some("Sampled motion occupancy only; no classification, identity, intent, continuity, absence or alert authority.".to_owned()),
        },
    };
    event.validate()?;
    let mut e = CanonicalEncoder::new();
    e.text(APPROVAL_DOMAIN);
    e.text(d.site_lineage());
    e.text(principal);
    e.digest(event.revision_digest());
    e.digest(manifest.root());
    let approval = ContentDigest::sha256(&e.finish_checked()?);
    let status = event_status(d, &event)?;
    Ok(LongDwellCandidate {
        episode,
        class_evidence,
        event,
        record,
        manifest,
        slot: slot("ld-e", identity)?,
        approval,
        status,
    })
}
pub(super) fn publish_manifest(
    d: &mut ReferenceDeployment,
    slot: &SlotName,
    manifest: &ObjectManifest,
    validity: CaptureInterval,
    cx: &ReplayCx,
) -> Result<()> {
    for digest in manifest.children() {
        d.publisher_mut().verify_object(*digest)?;
    }
    match d.publisher().root(slot) {
        Some(root) if root.root != manifest.root() => return Err(WatchError::Conflict),
        Some(_) => {}
        None => {
            d.publisher_mut().stage_manifest(slot, manifest)?;
        }
    }
    d.publish_and_commit(slot, manifest, validity, cx)?;
    Ok(())
}
pub(super) fn json(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if u32::from(c) < 32 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod health_tests;
#[cfg(test)]
mod tests;

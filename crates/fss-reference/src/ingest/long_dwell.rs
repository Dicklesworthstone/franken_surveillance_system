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
    WatchError, WatchLimits, WatchOptions, WatchPlan, WatchStatus, WatchZone,
};
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

mod reader;
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
const POLICY: &[u8] = b"fss.long-dwell.policy.v1:mjpeg-native-luma:masked-before-perception:\
running-variance:kalman-global-iou:confirmed-actual-matches:strict-rounded-zone-interior:\
conservative-capture-endpoints:reset-background-and-tracker-on-source-or-decode-gap:\
one-whole-range-budget:unclassified:indeterminate:hold:no-absence:no-alert";
/// Policy of inter-coded (H.264/H.265, Annex-B or MP4) scans: frames in display order, dwell
/// positions are display positions, and decoding restarts only at IDR/IRAP pictures.
const POLICY_INTER: &[u8] = b"fss.long-dwell.policy.v1:inter-coded-display-order-luma:\
display-order-positions:idr-or-irap-restart:masked-before-perception:running-variance:\
kalman-global-iou:confirmed-actual-matches:strict-rounded-zone-interior:\
conservative-capture-endpoints:reset-background-and-tracker-on-source-or-decode-gap:\
one-whole-range-budget:unclassified:indeterminate:hold:no-absence:no-alert";
const ANALYSIS_DOMAIN: &str = "fss.long_dwell_analysis.v1";
const FRAME_DOMAIN: &str = "fss.long_dwell_frame.v1";
const EPISODE_DOMAIN: &str = "fss.long_dwell_episode.v1";
const APPROVAL_DOMAIN: &str = "fss.long_dwell_approval.v1";
const UNCERTAINTY: &str = "Consecutive actual foreground-track samples meet an owner-selected dwell rule. Capture times are operator assumptions; one sensor, uncalibrated, no continuous occupancy or intent proof.";
type Result<T> = std::result::Result<T, WatchError>;

/// Whole-scan ceilings, not allowances replenished for each frame, chunk or episode.
#[derive(Clone, Copy, Debug)]
pub struct LongDwellLimits {
    /// Existing retained-read and JPEG ceilings; inter-coded formats are not admitted here.
    pub decode: WatchLimits,
    /// Bytes fetched from source chunks; metadata reads are separately bounded by their owners.
    pub maximum_source_chunk_bytes: u64,
    /// Sum of decoded luma sample counts, charged before foreground processing.
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
    manifest_digest: ContentDigest,
    sensor: SensorId,
    privacy: MaskBinding,
    read_limits: RetainedReadLimits,
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

/// Whole-scan state shared by the MJPEG and inter-coded frame sources.
struct Scan<'a> {
    plan: &'a WatchPlan,
    rule: DwellPolicy,
    masked: &'a BTreeSet<usize>,
    limits: &'a LongDwellLimits,
    privacy: &'a MaskBinding,
    health_source: ContentDigest,
    health: Option<Screening>,
    time_reliable: bool,
    tracker: MultiObjectTracker,
    background: Option<ForegroundDetector>,
    dimensions: Option<[u32; 2]>,
    temporal: TemporalState,
    previous_capture: Option<CaptureInterval>,
    previous_tracks: u64,
    trace: Vec<u8>,
    decoded: usize,
    unreliable: usize,
    restarts: usize,
    refusals: Vec<DecodeRefusal>,
    pixel_samples: u64,
    assignment_work: u64,
}

impl Scan<'_> {
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
        )?;
        frame_record.bool(true);
        frame_record.u64(self.temporal.epoch);
        frame_record.u32(size[0]);
        frame_record.u32(size[1]);
        frame_record.digest(ContentDigest::sha256(&pixels));
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
        record.text(FRAME_DOMAIN);
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
        if options.tolerate_decode_refusals {
            let mut source = TolerantSource::open(
                deployment,
                TolerantRequest {
                    import_identity: plan.import_identity,
                    interpretation: plan.interpretation,
                    first_segment: plan.first_segment,
                    end,
                    read_limits: decode.read_limits,
                    jpeg_limits: decode.jpeg_limits,
                    h264_limits: decode.h264_limits,
                    h265_limits: decode.h265_limits,
                    stream: true,
                },
                cx,
            )?;
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
                        record.text(FRAME_DOMAIN);
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
        if matches!(format, "annexb" | "mp4avc") {
            let mut range = RecordedH264Range::open_stream(
                deployment,
                RecordedH264Request {
                    import_identity: plan.import_identity,
                    first_segment: plan.first_segment,
                    segment_count: plan.segment_count,
                    interpretation: plan.interpretation,
                    read_limits: decode.read_limits,
                    decoder_limits: decode.h264_limits,
                },
                cx,
            )?;
            while let Some(decoded) = range.next_frame(deployment, cx)? {
                checkpoint(cx, "long_dwell:frame")?;
                let receipt = decoded.receipt();
                let frame = frame(
                    receipt.segment_index(),
                    receipt.capsule(),
                    receipt.capsule_digest(),
                    receipt.dimensions(),
                    decoded.pixels(),
                )?;
                self.inter_frame(position, frame, first_capsule, screened, cx)?;
                position = position.checked_add(1).ok_or(WatchError::Limit)?;
            }
            Ok(range.chunk_bytes_read())
        } else {
            let mut range = RecordedH265Range::open_stream(
                deployment,
                RecordedH265Request {
                    import_identity: plan.import_identity,
                    first_segment: plan.first_segment,
                    segment_count: plan.segment_count,
                    interpretation: plan.interpretation,
                    read_limits: decode.read_limits,
                    decoder_limits: decode.h265_limits,
                },
                cx,
            )?;
            while let Some(decoded) = range.next_frame(deployment, cx)? {
                checkpoint(cx, "long_dwell:frame")?;
                let receipt = decoded.receipt();
                let frame = frame(
                    receipt.segment_index(),
                    receipt.capsule(),
                    receipt.capsule_digest(),
                    receipt.dimensions(),
                    decoded.pixels(),
                )?;
                self.inter_frame(position, frame, first_capsule, screened, cx)?;
                position = position.checked_add(1).ok_or(WatchError::Limit)?;
            }
            Ok(range.chunk_bytes_read())
        }
    }
}

struct TemporalState {
    active: BTreeMap<(u64, usize), DwellAccumulator>,
    episodes: Vec<Episode>,
    epoch: u64,
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

impl LongDwellReport {
    /// Decode a whole MJPEG range once, preserving foreground/tracker/dwell state between frames.
    /// No 128-frame windows, model calls, pixel history, implicit retries, or coverage claims.
    pub fn analyze(
        deployment: &ReferenceDeployment,
        plan: &WatchPlan,
        rule: DwellPolicy,
        options: WatchOptions,
        limits: &LongDwellLimits,
        cx: &ReplayCx,
    ) -> Result<Self> {
        Self::analyze_inner(deployment, plan, rule, options, limits, cx, false)
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
        Self::analyze_inner(deployment, plan, rule, options, limits, cx, true)
    }

    fn analyze_inner(
        deployment: &ReferenceDeployment,
        plan: &WatchPlan,
        rule: DwellPolicy,
        options: WatchOptions,
        limits: &LongDwellLimits,
        cx: &ReplayCx,
        screened: bool,
    ) -> Result<Self> {
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
        rule.validate().map_err(dwell_error)?;
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
            "annexb" | "hevc" | "mp4avc" | "mp4hevc" => true,
            _ => return Err(RecordedDecodeError::UnsupportedMedia.into()),
        };
        let policy: &'static [u8] = if inter { POLICY_INTER } else { POLICY };
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
        let health = if screened {
            Some(Screening::new(
                plan.segment_count,
                limits.maximum_pixel_samples,
            )?)
        } else {
            None
        };
        let health_source = super::recorded_watch::masked_plan_digest(plan.digest(), &privacy);
        // MP4 container structure is accounted, not lost media (never an MJPEG reason).
        let time_reliable = !source
            .omission_spans
            .iter()
            .any(|span| !span.is_container_structure())
            && !source.segment_spans[..=plan.first_segment]
                .iter()
                .any(|s| s.gap_before);
        let mut scan = Scan {
            plan,
            rule,
            masked: &masked,
            limits,
            privacy: &privacy,
            health_source,
            health,
            time_reliable,
            tracker: MultiObjectTracker::new(tracker_config(plan))?,
            background: None,
            dimensions: None,
            temporal: TemporalState {
                active: BTreeMap::new(),
                episodes: Vec::new(),
                epoch: 0,
            },
            previous_capture: None,
            previous_tracks: 0,
            trace: Vec::new(),
            decoded: 0,
            unreliable: 0,
            restarts: 0,
            refusals: Vec::new(),
            pixel_samples: 0,
            assignment_work: 0,
        };
        let (source_bytes, jpeg_work) = if inter {
            let bytes = scan.inter_frames(
                deployment,
                &first_capsule,
                options,
                end,
                source.format.as_str(),
                screened,
                cx,
            )?;
            (bytes, 0)
        } else {
            let mut cursor = ChunkCursor::new(limits.maximum_source_chunk_bytes);
            let mut codec_budget = DecodeBudget::new(limits.decode.jpeg_work_units);
            // `segment` is a source position (capsule lookup, cursor), not only a span index.
            #[allow(clippy::needless_range_loop)]
            for segment in plan.first_segment..end {
                checkpoint(cx, "long_dwell:frame")?;
                let gap = source.segment_spans[segment].gap_before && segment > plan.first_segment;
                if gap {
                    if let Some(screen) = &mut scan.health {
                        screen.discontinuity();
                    }
                    scan.time_reliable = false;
                    scan.restart()?;
                }
                let (capsule, capsule_digest) = source_capsule(deployment, &retained, segment)?;
                if capsule.sensor_id != sensor {
                    return Err(RecordedDecodeError::InvalidReceipt.into());
                }
                if screened && capsule.stream_id != first_capsule.stream_id {
                    return Err(RecordedDecodeError::InvalidReceipt.into());
                }
                if source.segment_spans[segment].len
                    > limits.decode.jpeg_limits.maximum_bytes as u64
                {
                    return Err(WatchError::Limit);
                }
                let bytes = cursor.segment(
                    deployment,
                    &retained,
                    segment,
                    limits.decode.read_limits,
                    cx,
                )?;
                let mut frame_record = CanonicalEncoder::new();
                frame_record.text(FRAME_DOMAIN);
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
                    &mut codec_budget,
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
            (cursor.bytes_read(), codec_budget.used())
        };
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
            ..
        } = scan;
        if decoded == 0 {
            return Err(RecordedDecodeError::Unavailable.into());
        }
        temporal.finish_active()?;
        temporal.episodes.sort_by_key(|e| {
            (
                e.span.trigger.position,
                e.epoch,
                e.track,
                e.zone,
                e.span.first.position,
            )
        });
        deployment
            .ledger()
            .verify_durable_head()
            .map_err(ReferenceError::from)?;
        let health = health.map(|screen| screen.finish(plan.segment_count));
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
        e.digest(retained.import_root());
        e.digest(retained.manifest_digest());
        retained.authority_anchor().encode_canonical(&mut e);
        e.text(sensor.as_str());
        e.digest(privacy.digest());
        e.u64(rule.minimum_duration_ns);
        e.u64(rule.maximum_sample_gap_ns);
        e.u64(rule.minimum_observations as u64);
        e.bool(options.tolerate_decode_refusals);
        e.u64(plan.segment_count as u64);
        e.bytes(&trace);
        if let Some(summary) = &health {
            e.text("sensor_health");
            e.bytes(health_policy_bytes());
            summary.encode(&mut e);
        }
        let analysis = e.finish_checked()?;
        let analysis_digest = ContentDigest::sha256(&analysis);
        let mut children = BTreeSet::from([
            retained.import_root(),
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
        let analysis_manifest =
            ObjectManifest::new("recorded-long-dwell-analysis-v1", children, None)?;
        let analysis_slot = slot("ld-a", analysis_digest)?;
        let principal = cx.io_authority().principal().to_owned();
        let mut candidates = Vec::new();
        for episode in temporal.episodes {
            candidates.push(prepare_candidate(
                deployment,
                episode,
                plan,
                analysis_manifest.root(),
                &sensor,
                &principal,
                &privacy,
                policy,
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
            import_root: retained.import_root(),
            manifest_digest: retained.manifest_digest(),
            sensor,
            privacy,
            read_limits: limits.decode.read_limits,
            analysis,
            analysis_manifest,
            analysis_slot,
            candidates,
            decoded,
            unreliable,
            masked_zones: masked.len(),
            restarts,
            refusals,
            source_bytes,
            pixel_samples,
            assignment_work,
            jpeg_work,
            policy,
            health,
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
    /// Actual source-chunk bytes fetched, not per-segment logical lengths.
    pub const fn source_chunk_bytes_read(&self) -> u64 {
        self.source_bytes
    }
    /// Successfully decoded source segments.
    pub const fn frames_decoded(&self) -> usize {
        self.decoded
    }
    /// Explicit opt-in diagnostics; `None` means no screening was requested, never healthy.
    pub fn health_summary(&self) -> Option<&LongDwellHealthSummary> {
        self.health.as_ref()
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
        deployment
            .ledger()
            .verify_durable_head()
            .map_err(ReferenceError::from)?;
        let source =
            RetainedFileImport::open(deployment, self.plan.import_identity, self.read_limits, cx)?;
        if source.import_root() != self.import_root
            || source.manifest_digest() != self.manifest_digest
        {
            return Err(WatchError::Conflict);
        }
        if current_mask(deployment, &self.sensor)
            .map_err(RecordedDecodeError::from)?
            .digest()
            != self.privacy.digest()
        {
            return Err(WatchError::InvalidPlan(
                "privacy generation changed; recompute long dwell",
            ));
        }
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
            format!(concat!("{{\"event_id\":{},\"zone_id\":{},\"tracker_epoch\":{},\"track_id\":{},",
                "\"first_segment\":{},\"trigger_segment\":{},\"last_segment\":{},\"matched_observations\":{},",
                "\"trigger_minimum_ns\":{},\"minimum_duration_ns\":{},\"proposal_digest\":{},",
                "\"provenance_root\":{},\"status\":{},\"publish_command\":{command}}}"),
                json(c.event.event_id.as_str()), json(&self.plan.zones[c.episode.zone].zone_id),
                c.episode.epoch, c.episode.track, span.first.position, span.trigger.position, span.last.position,
                span.observations, json(&span.trigger_minimum_ns.to_string()), json(&span.minimum_duration_ns.to_string()),
                json(&c.approval.to_text()), json(&c.manifest.root().to_text()), json(c.status.as_str()), command = command)
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
                "\"media_format\":\"mjpeg\",\"capture_time_label\":\"operator_assumption\",",
                "\"event_kind\":\"unclassified\",\"event_state\":\"indeterminate\",\"policy_action\":\"hold\",",
                "\"calibrated\":false,\"corroborated\":false,\"continuous_occupancy_proved\":false,",
                "\"absence_certifiable\":false,\"alert_authorized\":false,\"model_invoked\":false,",
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
            candidates
        );
        if let Some(summary) = &self.health {
            if text.pop() != Some('}') {
                return Err(WatchError::Conflict);
            }
            text.push_str(",\"sensor_health\":");
            text.push_str(&summary.to_json());
            text.push('}');
        }
        if text.len() > MAX_REPORT_BYTES {
            return Err(WatchError::Limit);
        }
        Ok(text)
    }
}

fn slot(prefix: &str, digest: ContentDigest) -> Result<SlotName> {
    SlotName::parse(&format!("{prefix}-{}", hex(digest)))
        .map_err(|_| WatchError::InvalidPlan("long dwell slot"))
}
fn event_status(d: &ReferenceDeployment, event: &EventHypothesis) -> Result<WatchStatus> {
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
        event,
        record,
        manifest,
        slot: slot("ld-e", identity)?,
        approval,
        status,
    })
}
fn publish_manifest(
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
fn json(value: &str) -> String {
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

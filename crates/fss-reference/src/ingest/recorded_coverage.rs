#![forbid(unsafe_code)]
//! Retained coverage witnesses of the model-free recorded pipelines.
//!
//! A [`CoverageRecord`] is what one `fss-event watch` run (or one camera of an
//! `fss-event corroborate` run) can honestly say about where its detector was able to see: one
//! [`CoverageWitness`] per (sensor, zone, maximal contiguous interval) in which
//!
//! * the frames were decoded continuously: no source gap, missing (for example skipped RASL)
//!   segment, or decode refusal inside the interval (by default a decode refusal refuses the whole
//!   run, so nothing is retained at all; a tolerant run names it `decode_refused`, see below);
//! * an image zone lies inside the decoded frame; a ground zone with geometric visibility is at
//!   or above its visibility threshold (see below);
//! * the background model is past its warm-up ([`BACKGROUND_WARMUP_FRAMES`]) and the tracker could
//!   still confirm a track before the run ended (the last `confirmation_hits - 1` frames are
//!   confirmation latency);
//! * no zone entry was emitted (an entry frame is recorded as its own interval, naming the
//!   candidate and the event it would publish);
//! * capture time is an operator assumption bound to the import (`operator_assumption`) and no
//!   source gap precedes the frame in the import: after a gap the frame index no longer predicts
//!   capture time, so the time is treated as unknown. Unknown capture time yields no witness.
//!
//! Everything else is an explicit [`UncoveredInterval`] with a typed [`UncoveredReason`]; nothing
//! is dropped. The witness binds the exact pipeline generation (detector policy and thresholds,
//! decoder label, tracker configuration, warm-up, and zone geometry), the sensor, the zone, and
//! its certain capture bounds: from the latest possible capture of its first frame to the earliest
//! possible capture of its last frame. A run whose bounds invert has no witness.
//!
//! Retention is authority-plane evidence and follows the recorded-event approval discipline: the
//! analysis only proposes a record and its exact approval digest; [`retain_coverage`] writes the
//! record (spool object, then one `coverage_witness` ledger batch) only when the operator presents
//! that digest, and a rerun of a retained analysis writes nothing. The witness never certifies
//! anything beyond its declared predicate, domain, and pipeline generation.
//!
//! Two opt-in extensions ([`build_coverage_with`], fss-2h5zq.53 and the fss-fnrgr follow-up)
//! never change a record built without them:
//!
//! * a ground zone may carry a geometric [`ZoneVisibility`] (see [`super::ground_visibility`]):
//!   below its registered threshold the zone is not observable (`occluded` or
//!   `outside_frustum`); above it every witness predicate states the visible fraction, the
//!   sampling policy and the occlusion model, and a frustum-only claim (`occlusion_unknown`) says
//!   so. Such a record is version 2 (the visibility block per zone); every other record keeps the
//!   exact version-1 bytes;
//! * a tolerant decode ([`super::tolerant_decode`]) names its refused segments as `decode_refused`
//!   intervals with the registered error id, and each restart of tracking after a gap ends an
//!   analysis epoch: the confirmation latency before every restart is uncovered, so no witness
//!   claims a gap or a frame whose entry could not have been confirmed.

use std::fmt;

use fss_core::{
    BatchId, CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, CaptureInterval,
    Completeness, ContentDigest, ContractError, CoverageContinuity, CoverageStopReason,
    CoverageWitness, EvidenceDelta, LedgerAnchor, ObjectId, Plane, TimestampNs,
};

use super::ground_visibility::{NotVisibleCause, ZoneVisibility};
use super::tolerant_decode::DecodeRefusal;
use crate::reference_deployment::FAMILY_COVERAGE_WITNESS;
use crate::{ReferenceDeployment, ReferenceError, ReplayCx};

/// Decoded frames the running-variance background model needs before its foreground output is
/// counted as coverage: the first frame only initializes the mean, and the next three establish
/// the variance term. Bound into every pipeline generation.
pub const BACKGROUND_WARMUP_FRAMES: usize = 4;
/// Generation of this coverage producer (`authorized_generation` of every witness it retains).
pub const COVERAGE_PRODUCER_GENERATION: u64 = 1;
/// Maximum zones in one record.
pub const MAX_COVERAGE_ZONES: usize = 16;
/// Maximum witnesses or uncovered intervals per zone.
pub const MAX_COVERAGE_INTERVALS: usize = 512;
/// Maximum bytes of one retained record.
pub const MAX_COVERAGE_RECORD_BYTES: usize = 4 * 1024 * 1024;
/// Time label of an import whose capture times are operator hints.
pub const OPERATOR_TIME_LABEL: &str = "operator_assumption";

const RECORD_MAGIC: &[u8] = b"FSSCOV01";
const RECORD_VERSION: u32 = 1;
/// Version of a record in which at least one zone carries a geometric visibility block.
const RECORD_VERSION_VISIBILITY: u32 = 2;
/// Canonical record domain.
pub const RECORD_DOMAIN: &str = "fss.recorded_watch_coverage.v1";
/// Pipeline-generation digest domain.
pub const PIPELINE_DOMAIN: &str = "fss.recorded_watch_pipeline_generation.v1";
/// Analysis-identity digest domain (anchor independent).
pub const IDENTITY_DOMAIN: &str = "fss.recorded_watch_coverage_identity.v1";
/// Exact approval digest domain.
pub const APPROVAL_DOMAIN: &str = "fss.recorded_watch_coverage_approval.v1";

fn hex(digest: ContentDigest) -> String {
    digest.bytes().iter().map(|b| format!("{b:02x}")).collect()
}

/// Which pipeline produced a record.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CoverageSource {
    /// `fss-event watch`: image zones.
    Watch,
    /// One camera of `fss-event corroborate`: ground zones.
    Corroborate,
}

impl CoverageSource {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Watch => "watch",
            Self::Corroborate => "corroborate",
        }
    }

    /// Scope prefix of this source's zones (`zone:` or `ground-zone:`).
    #[must_use]
    pub const fn scope_prefix(self) -> &'static str {
        match self {
            Self::Watch => "zone:",
            Self::Corroborate => "ground-zone:",
        }
    }

    fn parse(value: &str) -> Result<Self, ContractError> {
        match value {
            "watch" => Ok(Self::Watch),
            "corroborate" => Ok(Self::Corroborate),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Why an interval carries no witness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UncoveredReason {
    /// Background model warm-up frames.
    BackgroundWarmup,
    /// Trailing frames in which a new track could not be confirmed before the run ended.
    ConfirmationLatency,
    /// A confirmed track entered the zone in this frame.
    ZoneEntry {
        /// Candidate (watch) or ground-entry record (corroborate) identity.
        candidate: ContentDigest,
        /// Event that publishing the candidate records, when one exists.
        event_id: Option<String>,
    },
    /// Segments inside the range yielded no decoded frame (for example skipped RASL pictures).
    SegmentNotDecoded,
    /// The import's capture time is unknown.
    CaptureTimeUnknown,
    /// A source gap precedes the frame in the import, so its index no longer predicts capture.
    CaptureTimeUnreliableAfterGap,
    /// The zone is not entirely inside the decoded frame.
    ZoneOutsideFrame,
    /// Too few frames (or overlapping capture bounds) to bound a certain interval.
    IntervalTooShort,
    /// The retained segments were refused by the decoder (tolerant analysis only).
    DecodeRefused {
        /// Registered stable identity of the refusal.
        error_id: String,
    },
    /// The ground zone is below its visibility threshold, mostly hidden by opaque scene-mesh
    /// geometry.
    Occluded,
    /// The ground zone is below its visibility threshold, mostly behind the camera or outside
    /// the image.
    OutsideFrustum,
    /// The sensor's retained privacy mask covers part or all of the zone: masked pixels are
    /// never absence evidence (`ingest::privacy_mask::coverage`).
    PrivacyMasked,
}

impl UncoveredReason {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::BackgroundWarmup => "background_warmup",
            Self::ConfirmationLatency => "confirmation_latency",
            Self::ZoneEntry { .. } => "zone_entry",
            Self::SegmentNotDecoded => "segment_not_decoded",
            Self::CaptureTimeUnknown => "capture_time_unknown",
            Self::CaptureTimeUnreliableAfterGap => "capture_time_unreliable_after_gap",
            Self::ZoneOutsideFrame => "zone_outside_frame",
            Self::IntervalTooShort => "interval_too_short",
            Self::DecodeRefused { .. } => "decode_refused",
            Self::Occluded => "occluded",
            Self::OutsideFrustum => "outside_frustum",
            Self::PrivacyMasked => "privacy_masked",
        }
    }
}

/// One explicit interval without a witness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UncoveredInterval {
    /// First retained segment of the interval.
    pub first_segment: u64,
    /// Last retained segment of the interval.
    pub last_segment: u64,
    /// Conservative capture hull, when the interval has decoded neighbours to bound it.
    pub capture: Option<CaptureInterval>,
    /// Why no witness covers it.
    pub reason: UncoveredReason,
}

/// One retained witness with the segment range and bounds it was built from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZoneWitness {
    /// First decoded segment.
    pub first_segment: u64,
    /// Last decoded segment.
    pub last_segment: u64,
    /// Decoded frames in the interval.
    pub frames: u64,
    /// Hull of the frames' capture intervals.
    pub outer: CaptureInterval,
    /// Certain bounds: latest capture of the first frame to earliest capture of the last.
    pub covered: CaptureInterval,
    /// The fss-core witness.
    pub witness: CoverageWitness,
}

/// Coverage of one zone in one record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZoneCoverage {
    /// Scope (`zone:<id>` or `ground-zone:<id>`).
    pub scope: String,
    /// Zone identifier.
    pub zone_id: String,
    /// Owner geometry text (decoded pixels or ground-unit bits).
    pub geometry: String,
    /// Exact pipeline generation.
    pub pipeline_generation: ContentDigest,
    /// Witnesses in segment order.
    pub witnesses: Vec<ZoneWitness>,
    /// Uncovered intervals in segment order.
    pub uncovered: Vec<UncoveredInterval>,
    /// Geometric visibility of a ground zone, when geometry was supplied.
    pub visibility: Option<ZoneVisibility>,
}

/// Everything one analysed recording retains about coverage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoverageRecord {
    /// Producing pipeline.
    pub source: CoverageSource,
    /// Exact import.
    pub import_identity: ContentDigest,
    /// Retained import root.
    pub import_root: ContentDigest,
    /// Recording sensor.
    pub sensor_id: String,
    /// Analysis identity (watch analysis digest; corroborate plan and camera analysis).
    pub analysis_digest: ContentDigest,
    /// Authority anchor the analysis read (every witness carries it).
    pub basis: LedgerAnchor,
    /// Import time label (`operator_assumption` or `unknown`).
    pub capture_time_label: String,
    /// First analysed segment.
    pub first_segment: u64,
    /// Last analysed segment.
    pub last_segment: u64,
    /// Hull of every decoded frame's capture interval.
    pub analysed: CaptureInterval,
    /// Per-zone coverage in plan order.
    pub zones: Vec<ZoneCoverage>,
}

/// One decoded frame as coverage sees it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoverageFrame {
    /// Retained segment.
    pub segment: usize,
    /// Conservative capture interval of its capsule.
    pub capture: CaptureInterval,
}

/// One emitted zone entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoverageEntry {
    /// Segment of the entry frame.
    pub segment: usize,
    /// Candidate or entry-record identity.
    pub candidate: ContentDigest,
    /// Event its publication records, when one exists.
    pub event_id: Option<String>,
}

/// One zone to assess.
#[derive(Clone, Debug)]
pub struct CoverageZoneInput {
    /// Zone identifier.
    pub zone_id: String,
    /// Owner geometry text.
    pub geometry: String,
    /// Whether the zone lies entirely inside the decoded frame.
    pub inside_frame: bool,
    /// Pipeline generation for this zone.
    pub pipeline_generation: ContentDigest,
    /// Entries emitted into this zone.
    pub entries: Vec<CoverageEntry>,
}

/// Inputs of [`build_coverage`].
#[derive(Clone, Debug)]
pub struct CoverageInput<'a> {
    /// Producing pipeline.
    pub source: CoverageSource,
    /// Exact import.
    pub import_identity: ContentDigest,
    /// Retained import root.
    pub import_root: ContentDigest,
    /// Recording sensor.
    pub sensor_id: &'a str,
    /// Analysis identity.
    pub analysis_digest: ContentDigest,
    /// Authority anchor the analysis read.
    pub basis: LedgerAnchor,
    /// Import time label.
    pub capture_time_label: &'a str,
    /// `gap_before` of every segment of the import, in segment order.
    pub segment_gaps: &'a [bool],
    /// First planned segment.
    pub first_segment: usize,
    /// Last planned segment.
    pub last_segment: usize,
    /// Decoded frames in order.
    pub frames: &'a [CoverageFrame],
    /// Tracker confirmation hits.
    pub confirmation_hits: u32,
    /// Zones in plan order.
    pub zones: Vec<CoverageZoneInput>,
}

/// Optional inputs of [`build_coverage_with`]; the default is exactly [`build_coverage`].
#[derive(Clone, Debug, Default)]
pub struct CoverageExtras {
    /// Geometric visibility per zone, in [`CoverageInput::zones`] order (empty: none).
    pub visibility: Vec<Option<ZoneVisibility>>,
    /// Refused segment runs of a tolerant decode, in segment order.
    pub refusals: Vec<DecodeRefusal>,
    /// Segments of the first decoded frame after each tracking restart, in order.
    pub restarts: Vec<usize>,
}

/// Pipeline-generation digest for one zone: fixed policy digest, pipeline label (decoder and
/// composition), detector and tracker parameters, warm-up, and the zone's exact geometry.
#[must_use]
pub fn pipeline_generation(
    source: CoverageSource,
    policy: ContentDigest,
    decoder_label: &str,
    parameters: &[u64],
    zone_id: &str,
    geometry: &str,
) -> ContentDigest {
    let mut e = CanonicalEncoder::new();
    e.text(PIPELINE_DOMAIN);
    e.text(source.as_str());
    e.digest(policy);
    e.text(decoder_label);
    e.u64(parameters.len() as u64);
    for value in parameters {
        e.u64(*value);
    }
    e.u64(BACKGROUND_WARMUP_FRAMES as u64);
    e.text(zone_id);
    e.text(geometry);
    ContentDigest::sha256(&e.finish())
}

fn sensor_label(sensor: &str) -> String {
    hex(ContentDigest::sha256(sensor.as_bytes()))
        .chars()
        .take(32)
        .collect()
}

/// Exact witness domain of one (sensor, scope, certain interval).
#[must_use]
pub fn witness_domain(
    source: CoverageSource,
    sensor: &str,
    scope: &str,
    covered: CaptureInterval,
) -> String {
    format!(
        "{}:{}:{scope}:{}..{}",
        source.as_str(),
        sensor_label(sensor),
        covered.earliest.0,
        covered.latest.0
    )
}

/// Exact negative predicate of one witness.
#[must_use]
pub fn witness_predicate(
    source: CoverageSource,
    sensor: &str,
    scope: &str,
    generation: ContentDigest,
    covered: CaptureInterval,
) -> String {
    format!(
        "no confirmed foreground-track entry into {scope} of sensor {sensor} emitted by the {} \
         pipeline generation {generation} over capture [{}, {}] ns (coverage producer v{})",
        source.as_str(),
        covered.earliest.0,
        covered.latest.0,
        COVERAGE_PRODUCER_GENERATION
    )
}

/// [`witness_predicate`] followed by the zone's geometric visibility clause, if any.
#[must_use]
pub fn zone_witness_predicate(
    source: CoverageSource,
    sensor: &str,
    scope: &str,
    generation: ContentDigest,
    covered: CaptureInterval,
    visibility: Option<&ZoneVisibility>,
) -> String {
    let mut predicate = witness_predicate(source, sensor, scope, generation, covered);
    if let Some(visibility) = visibility {
        predicate.push_str(&visibility.predicate_clause());
    }
    predicate
}

fn hull(a: CaptureInterval, b: CaptureInterval) -> Result<CaptureInterval, ContractError> {
    CaptureInterval::new(a.earliest.min(b.earliest), a.latest.max(b.latest))
}

/// One step of the per-zone walk: a decoded frame or a run of undecoded segments.
enum Unit {
    Frame(CoverageFrame, Option<UncoveredReason>),
    Missing {
        first: usize,
        last: usize,
        capture: Option<CaptureInterval>,
    },
}

struct ZoneBuilder<'a> {
    input: &'a CoverageInput<'a>,
    scope: String,
    generation: ContentDigest,
    visibility: Option<ZoneVisibility>,
    witnesses: Vec<ZoneWitness>,
    uncovered: Vec<UncoveredInterval>,
    run: Vec<CoverageFrame>,
}

impl ZoneBuilder<'_> {
    fn push_uncovered(
        &mut self,
        first: usize,
        last: usize,
        capture: Option<CaptureInterval>,
        reason: UncoveredReason,
    ) -> Result<(), ContractError> {
        if let Some(previous) = self.uncovered.last_mut()
            && previous.reason == reason
            && previous.last_segment + 1 == first as u64
            && !matches!(reason, UncoveredReason::ZoneEntry { .. })
        {
            previous.last_segment = last as u64;
            previous.capture = match (previous.capture, capture) {
                (Some(a), Some(b)) => Some(hull(a, b)?),
                _ => None,
            };
            return Ok(());
        }
        if self.uncovered.len() == MAX_COVERAGE_INTERVALS {
            return Err(ContractError::BudgetExhausted);
        }
        self.uncovered.push(UncoveredInterval {
            first_segment: first as u64,
            last_segment: last as u64,
            capture,
            reason,
        });
        Ok(())
    }

    fn close_run(&mut self) -> Result<(), ContractError> {
        let run = std::mem::take(&mut self.run);
        let (Some(first), Some(last)) = (run.first().copied(), run.last().copied()) else {
            return Ok(());
        };
        let mut outer = first.capture;
        for frame in &run {
            outer = hull(outer, frame.capture)?;
        }
        let covered = (run.len() >= 2)
            .then(|| CaptureInterval::new(first.capture.latest, last.capture.earliest).ok())
            .flatten();
        let Some(covered) = covered else {
            return self.push_uncovered(
                first.segment,
                last.segment,
                Some(outer),
                UncoveredReason::IntervalTooShort,
            );
        };
        if self.witnesses.len() == MAX_COVERAGE_INTERVALS {
            return Err(ContractError::BudgetExhausted);
        }
        let source = self.input.source;
        let sensor = self.input.sensor_id;
        let domain = witness_domain(source, sensor, &self.scope, covered);
        let witness = CoverageWitness {
            anchor: self.input.basis.clone(),
            authorized_domain: [domain.clone()].into(),
            observed_domain: [domain].into(),
            excluded_domain: std::collections::BTreeSet::new(),
            continuity: CoverageContinuity::Continuous,
            completeness: Completeness::Complete,
            negative_predicate: zone_witness_predicate(
                source,
                sensor,
                &self.scope,
                self.generation,
                covered,
                self.visibility.as_ref(),
            ),
            stop_reason: CoverageStopReason::Complete,
            authorized_generation: COVERAGE_PRODUCER_GENERATION,
            observed_generation: COVERAGE_PRODUCER_GENERATION,
        };
        witness.require_certified_absence()?;
        self.witnesses.push(ZoneWitness {
            first_segment: first.segment as u64,
            last_segment: last.segment as u64,
            frames: run.len() as u64,
            outer,
            covered,
            witness,
        });
        Ok(())
    }
}

/// Builds the coverage record of one analysed recording. Pure: reads and writes nothing.
pub fn build_coverage(input: &CoverageInput<'_>) -> Result<CoverageRecord, ContractError> {
    build_coverage_with(input, &CoverageExtras::default())
}

/// Segment `segment`'s refusal, if a refused run contains it.
fn refused(extras: &CoverageExtras, segment: usize) -> Option<&DecodeRefusal> {
    extras
        .refusals
        .iter()
        .find(|run| run.first_segment <= segment && segment <= run.last_segment)
}

/// Index one past the last frame of the analysis epoch containing frame `position`: tracking
/// restarts at every frame whose segment is in `restarts`.
fn epoch_end(frames: &[CoverageFrame], restarts: &[usize], position: usize) -> usize {
    frames
        .iter()
        .enumerate()
        .skip(position + 1)
        .find(|(_, frame)| restarts.contains(&frame.segment))
        .map_or(frames.len(), |(index, _)| index)
}

/// [`build_coverage`] with geometric visibility and tolerant-decode gaps. With default extras
/// the record is byte-identical to [`build_coverage`].
pub fn build_coverage_with(
    input: &CoverageInput<'_>,
    extras: &CoverageExtras,
) -> Result<CoverageRecord, ContractError> {
    if (!extras.visibility.is_empty() && extras.visibility.len() != input.zones.len())
        || extras
            .refusals
            .iter()
            .any(|run| run.first_segment > run.last_segment || run.error_id.is_empty())
    {
        return Err(ContractError::InvalidIdentifier);
    }
    if input.zones.len() > MAX_COVERAGE_ZONES
        || input.frames.is_empty()
        || input.first_segment > input.last_segment
    {
        return Err(ContractError::InvalidIdentifier);
    }
    let mut analysed = input.frames[0].capture;
    for frame in input.frames {
        analysed = hull(analysed, frame.capture)?;
    }
    // Capture time is trustworthy only for operator-hinted imports, and only up to the first
    // source gap after segment 0: a gap means frames were lost, so later indices no longer
    // predict capture time.
    let time_known = input.capture_time_label == OPERATOR_TIME_LABEL;
    let first_gap = input
        .segment_gaps
        .iter()
        .enumerate()
        .skip(1)
        .find(|(_, gap)| **gap)
        .map(|(index, _)| index);
    let latency = (input.confirmation_hits.max(1) - 1) as usize;
    let count = input.frames.len();
    let mut zones = Vec::with_capacity(input.zones.len());
    for (zone_index, zone) in input.zones.iter().enumerate() {
        let scope = format!("{}{}", input.source.scope_prefix(), zone.zone_id);
        let visibility = extras.visibility.get(zone_index).cloned().flatten();
        let not_visible = visibility.as_ref().and_then(ZoneVisibility::cause);
        let mut builder = ZoneBuilder {
            input,
            scope: scope.clone(),
            generation: zone.pipeline_generation,
            visibility: visibility.clone(),
            witnesses: Vec::new(),
            uncovered: Vec::new(),
            run: Vec::new(),
        };
        let mut units = Vec::with_capacity(count + 2);
        let mut expected = input.first_segment;
        let mut previous: Option<CoverageFrame> = None;
        for (position, frame) in input.frames.iter().enumerate() {
            if frame.segment < expected {
                return Err(ContractError::NonCanonicalOrdering);
            }
            if frame.segment > expected {
                let capture = match previous {
                    Some(before) => Some(hull(before.capture, frame.capture)?),
                    None => None,
                };
                units.push(Unit::Missing {
                    first: expected,
                    last: frame.segment - 1,
                    capture,
                });
            }
            expected = frame.segment + 1;
            previous = Some(*frame);
            let entry = zone.entries.iter().find(|e| e.segment == frame.segment);
            let reason = if !time_known {
                Some(UncoveredReason::CaptureTimeUnknown)
            } else if let Some(cause) = not_visible {
                Some(match cause {
                    NotVisibleCause::Occluded => UncoveredReason::Occluded,
                    NotVisibleCause::OutsideFrustum => UncoveredReason::OutsideFrustum,
                })
            } else if !zone.inside_frame {
                Some(UncoveredReason::ZoneOutsideFrame)
            } else if first_gap.is_some_and(|gap| frame.segment >= gap) {
                Some(UncoveredReason::CaptureTimeUnreliableAfterGap)
            } else if let Some(entry) = entry {
                // An emitted entry is named even inside warm-up or latency: it is observed.
                Some(UncoveredReason::ZoneEntry {
                    candidate: entry.candidate,
                    event_id: entry.event_id.clone(),
                })
            } else if position < BACKGROUND_WARMUP_FRAMES {
                Some(UncoveredReason::BackgroundWarmup)
            } else if position + latency >= count
                || (!extras.restarts.is_empty()
                    && position + latency >= epoch_end(input.frames, &extras.restarts, position))
            {
                Some(UncoveredReason::ConfirmationLatency)
            } else {
                None
            };
            units.push(Unit::Frame(*frame, reason));
        }
        if expected <= input.last_segment {
            units.push(Unit::Missing {
                first: expected,
                last: input.last_segment,
                capture: None,
            });
        }
        for unit in units {
            match unit {
                Unit::Frame(frame, None) => builder.run.push(frame),
                Unit::Frame(frame, Some(reason)) => {
                    builder.close_run()?;
                    builder.push_uncovered(
                        frame.segment,
                        frame.segment,
                        Some(frame.capture),
                        reason,
                    )?;
                }
                Unit::Missing {
                    first,
                    last,
                    capture,
                } => {
                    builder.close_run()?;
                    if extras.refusals.is_empty() {
                        builder.push_uncovered(
                            first,
                            last,
                            capture,
                            UncoveredReason::SegmentNotDecoded,
                        )?;
                    } else {
                        for segment in first..=last {
                            let reason = match refused(extras, segment) {
                                Some(run) => UncoveredReason::DecodeRefused {
                                    error_id: run.error_id.clone(),
                                },
                                None => UncoveredReason::SegmentNotDecoded,
                            };
                            builder.push_uncovered(segment, segment, capture, reason)?;
                        }
                    }
                }
            }
        }
        builder.close_run()?;
        zones.push(ZoneCoverage {
            scope,
            zone_id: zone.zone_id.clone(),
            geometry: zone.geometry.clone(),
            pipeline_generation: zone.pipeline_generation,
            witnesses: builder.witnesses,
            uncovered: builder.uncovered,
            visibility,
        });
    }
    let record = CoverageRecord {
        source: input.source,
        import_identity: input.import_identity,
        import_root: input.import_root,
        sensor_id: input.sensor_id.to_owned(),
        analysis_digest: input.analysis_digest,
        basis: input.basis.clone(),
        capture_time_label: input.capture_time_label.to_owned(),
        first_segment: input.first_segment as u64,
        last_segment: input.last_segment as u64,
        analysed,
        zones,
    };
    record.validate()?;
    Ok(record)
}

impl CoverageRecord {
    /// Anchor-independent analysis identity: equal analyses of equal retained source share it.
    #[must_use]
    pub fn identity(&self) -> ContentDigest {
        let mut e = CanonicalEncoder::new();
        e.text(IDENTITY_DOMAIN);
        e.text(self.source.as_str());
        e.digest(self.import_identity);
        e.digest(self.analysis_digest);
        ContentDigest::sha256(&e.finish())
    }

    /// Ledger object of this analysis's coverage.
    pub fn object_id(&self) -> Result<ObjectId, ContractError> {
        ObjectId::parse(format!("object:coverage:{}", hex(self.identity())))
    }

    /// Exact record bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = CanonicalEncoder::new();
        let versioned = self.zones.iter().any(|zone| zone.visibility.is_some());
        e.bytes(RECORD_MAGIC);
        e.u32(if versioned {
            RECORD_VERSION_VISIBILITY
        } else {
            RECORD_VERSION
        });
        e.text(RECORD_DOMAIN);
        e.text(self.source.as_str());
        e.digest(self.import_identity);
        e.digest(self.import_root);
        e.text(&self.sensor_id);
        e.digest(self.analysis_digest);
        self.basis.encode_canonical(&mut e);
        e.text(&self.capture_time_label);
        e.u64(self.first_segment);
        e.u64(self.last_segment);
        self.analysed.encode_canonical(&mut e);
        e.u64(self.zones.len() as u64);
        for zone in &self.zones {
            e.text(&zone.scope);
            e.text(&zone.zone_id);
            e.text(&zone.geometry);
            e.digest(zone.pipeline_generation);
            if versioned {
                match &zone.visibility {
                    Some(visibility) => {
                        e.bool(true);
                        visibility.encode(&mut e);
                    }
                    None => e.bool(false),
                }
            }
            e.u64(zone.witnesses.len() as u64);
            for witness in &zone.witnesses {
                e.u64(witness.first_segment);
                e.u64(witness.last_segment);
                e.u64(witness.frames);
                witness.outer.encode_canonical(&mut e);
                witness.covered.encode_canonical(&mut e);
                witness.witness.encode_canonical(&mut e);
            }
            e.u64(zone.uncovered.len() as u64);
            for interval in &zone.uncovered {
                e.u64(interval.first_segment);
                e.u64(interval.last_segment);
                match interval.capture {
                    Some(capture) => {
                        e.bool(true);
                        capture.encode_canonical(&mut e);
                    }
                    None => e.bool(false),
                }
                e.text(interval.reason.as_str());
                if let UncoveredReason::DecodeRefused { error_id } = &interval.reason {
                    e.text(error_id);
                }
                if let UncoveredReason::ZoneEntry {
                    candidate,
                    event_id,
                } = &interval.reason
                {
                    e.digest(*candidate);
                    match event_id {
                        Some(id) => {
                            e.bool(true);
                            e.text(id);
                        }
                        None => e.bool(false),
                    }
                }
            }
        }
        e.finish()
    }

    /// Digest of the exact record bytes (the ledger payload).
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.to_bytes())
    }

    /// Decodes and validates exact retained bytes against their authority digest.
    pub fn from_bytes(bytes: &[u8], expected: ContentDigest) -> Result<Self, ContractError> {
        if bytes.len() > MAX_COVERAGE_RECORD_BYTES {
            return Err(ContractError::BudgetExhausted);
        }
        if ContentDigest::sha256(bytes) != expected {
            return Err(ContractError::DigestMismatch);
        }
        let mut d = CanonicalDecoder::new(bytes);
        if d.bytes()? != RECORD_MAGIC {
            return Err(ContractError::InvalidIdentifier);
        }
        let versioned = match d.u32()? {
            RECORD_VERSION => false,
            RECORD_VERSION_VISIBILITY => true,
            _ => return Err(ContractError::InvalidIdentifier),
        };
        if d.text()? != RECORD_DOMAIN {
            return Err(ContractError::InvalidIdentifier);
        }
        let source = CoverageSource::parse(d.text()?)?;
        let import_identity = d.digest()?;
        let import_root = d.digest()?;
        let sensor_id = d.text()?.to_owned();
        let analysis_digest = d.digest()?;
        let basis = LedgerAnchor::decode_canonical(&mut d)?;
        let capture_time_label = d.text()?.to_owned();
        let first_segment = d.u64()?;
        let last_segment = d.u64()?;
        let analysed = CaptureInterval::decode_canonical(&mut d)?;
        let bounded = |value: u64, maximum: usize| -> Result<usize, ContractError> {
            usize::try_from(value)
                .ok()
                .filter(|count| *count <= maximum)
                .ok_or(ContractError::BudgetExhausted)
        };
        let zone_count = bounded(d.u64()?, MAX_COVERAGE_ZONES)?;
        let mut zones = Vec::with_capacity(zone_count);
        for _ in 0..zone_count {
            let scope = d.text()?.to_owned();
            let zone_id = d.text()?.to_owned();
            let geometry = d.text()?.to_owned();
            let pipeline_generation = d.digest()?;
            let visibility = if versioned && d.bool()? {
                Some(ZoneVisibility::decode(&mut d)?)
            } else {
                None
            };
            let witness_count = bounded(d.u64()?, MAX_COVERAGE_INTERVALS)?;
            let mut witnesses = Vec::with_capacity(witness_count);
            for _ in 0..witness_count {
                witnesses.push(ZoneWitness {
                    first_segment: d.u64()?,
                    last_segment: d.u64()?,
                    frames: d.u64()?,
                    outer: CaptureInterval::decode_canonical(&mut d)?,
                    covered: CaptureInterval::decode_canonical(&mut d)?,
                    witness: CoverageWitness::decode_canonical(&mut d)?,
                });
            }
            let uncovered_count = bounded(d.u64()?, MAX_COVERAGE_INTERVALS)?;
            let mut uncovered = Vec::with_capacity(uncovered_count);
            for _ in 0..uncovered_count {
                let first_segment = d.u64()?;
                let last_segment = d.u64()?;
                let capture = if d.bool()? {
                    Some(CaptureInterval::decode_canonical(&mut d)?)
                } else {
                    None
                };
                let reason = match d.text()? {
                    "background_warmup" => UncoveredReason::BackgroundWarmup,
                    "confirmation_latency" => UncoveredReason::ConfirmationLatency,
                    "zone_entry" => {
                        let candidate = d.digest()?;
                        let event_id = if d.bool()? {
                            Some(d.text()?.to_owned())
                        } else {
                            None
                        };
                        UncoveredReason::ZoneEntry {
                            candidate,
                            event_id,
                        }
                    }
                    "segment_not_decoded" => UncoveredReason::SegmentNotDecoded,
                    "capture_time_unknown" => UncoveredReason::CaptureTimeUnknown,
                    "capture_time_unreliable_after_gap" => {
                        UncoveredReason::CaptureTimeUnreliableAfterGap
                    }
                    "zone_outside_frame" => UncoveredReason::ZoneOutsideFrame,
                    "interval_too_short" => UncoveredReason::IntervalTooShort,
                    "decode_refused" => UncoveredReason::DecodeRefused {
                        error_id: d.text()?.to_owned(),
                    },
                    "occluded" => UncoveredReason::Occluded,
                    "outside_frustum" => UncoveredReason::OutsideFrustum,
                    "privacy_masked" => UncoveredReason::PrivacyMasked,
                    _ => return Err(ContractError::InvalidIdentifier),
                };
                uncovered.push(UncoveredInterval {
                    first_segment,
                    last_segment,
                    capture,
                    reason,
                });
            }
            zones.push(ZoneCoverage {
                scope,
                zone_id,
                geometry,
                pipeline_generation,
                witnesses,
                uncovered,
                visibility,
            });
        }
        d.ensure_finished()?;
        let record = Self {
            source,
            import_identity,
            import_root,
            sensor_id,
            analysis_digest,
            basis,
            capture_time_label,
            first_segment,
            last_segment,
            analysed,
            zones,
        };
        record.validate()?;
        if record.to_bytes() != bytes {
            return Err(ContractError::NonCanonicalOrdering);
        }
        Ok(record)
    }

    /// Checks every witness against the record: exact domain and predicate recomputed from the
    /// record's sensor, scope, generation and certain bounds; certified absence; the record's
    /// anchor; certain bounds inside the outer hull; and a known capture time.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.sensor_id.is_empty()
            || self.first_segment > self.last_segment
            || self.zones.len() > MAX_COVERAGE_ZONES
        {
            return Err(ContractError::InvalidIdentifier);
        }
        for zone in &self.zones {
            if zone.scope != format!("{}{}", self.source.scope_prefix(), zone.zone_id)
                || zone.zone_id.is_empty()
            {
                return Err(ContractError::InvalidIdentifier);
            }
            if let Some(visibility) = &zone.visibility {
                visibility.validate()?;
                // A zone below its visibility threshold never carries a witness.
                if !visibility.observable() && !zone.witnesses.is_empty() {
                    return Err(ContractError::CoverageUncertified);
                }
            }
            for witness in &zone.witnesses {
                // Unknown capture time never yields a witness.
                if self.capture_time_label != OPERATOR_TIME_LABEL {
                    return Err(ContractError::CoverageUncertified);
                }
                let domain =
                    witness_domain(self.source, &self.sensor_id, &zone.scope, witness.covered);
                let predicate = zone_witness_predicate(
                    self.source,
                    &self.sensor_id,
                    &zone.scope,
                    zone.pipeline_generation,
                    witness.covered,
                    zone.visibility.as_ref(),
                );
                let inner = &witness.witness;
                inner.require_certified_absence()?;
                if inner.anchor != self.basis
                    || inner.authorized_domain.len() != 1
                    || !inner.authorized_domain.contains(&domain)
                    || inner.negative_predicate != predicate
                    || inner.authorized_generation != COVERAGE_PRODUCER_GENERATION
                    || witness.frames < 2
                    || witness.first_segment >= witness.last_segment
                    || witness.first_segment < self.first_segment
                    || witness.last_segment > self.last_segment
                    || witness.covered.earliest < witness.outer.earliest
                    || witness.covered.latest > witness.outer.latest
                {
                    return Err(ContractError::CoverageUncertified);
                }
            }
        }
        Ok(())
    }

    /// Every witness of the record.
    pub fn witnesses(&self) -> impl Iterator<Item = (&ZoneCoverage, &ZoneWitness)> {
        self.zones
            .iter()
            .flat_map(|zone| zone.witnesses.iter().map(move |witness| (zone, witness)))
    }
}

/// Exact approval digest of a set of records (one per camera, in order).
#[must_use]
pub fn approval_digest(records: &[&CoverageRecord]) -> ContentDigest {
    let digests: Vec<ContentDigest> = records.iter().map(|record| record.digest()).collect();
    approval_over(&digests)
}

fn approval_over(digests: &[ContentDigest]) -> ContentDigest {
    let mut e = CanonicalEncoder::new();
    e.text(APPROVAL_DOMAIN);
    e.u64(digests.len() as u64);
    for digest in digests {
        e.digest(*digest);
    }
    ContentDigest::sha256(&e.finish())
}

/// Retention state of a coverage proposal in this deployment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoverageStatus {
    /// Proposed only: nothing is retained.
    Proposed,
    /// Retained by this call.
    Retained,
    /// This analysis's coverage was already retained; nothing was written.
    AlreadyRetained,
}

impl CoverageStatus {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Retained => "retained",
            Self::AlreadyRetained => "already_retained",
        }
    }
}

/// Typed refusal of coverage retention.
#[derive(Debug)]
pub enum CoverageError {
    /// The approval matches neither this analysis's proposal nor its retained records.
    StaleApproval(ContentDigest),
    /// Record construction or validation failed.
    Contract(ContractError),
    /// Spool or ledger refusal.
    Reference(Box<ReferenceError>),
}

impl CoverageError {
    /// Registered stable identity (registries/ERRORS.md).
    #[must_use]
    pub fn stable_id(&self) -> &'static str {
        match self {
            Self::StaleApproval(_) => "ERR-COVERAGE-APPROVAL-STALE-001",
            Self::Contract(_) | Self::Reference(_) => "ERR-COVERAGE-001",
        }
    }
}

impl fmt::Display for CoverageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StaleApproval(digest) => write!(
                f,
                "coverage approval {digest} matches neither this analysis's proposal nor its \
                 retained coverage"
            ),
            Self::Contract(error) => write!(f, "coverage record: {error}"),
            Self::Reference(error) => write!(f, "coverage retention: {error}"),
        }
    }
}

impl std::error::Error for CoverageError {}

impl From<ContractError> for CoverageError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}

impl From<ReferenceError> for CoverageError {
    fn from(error: ReferenceError) -> Self {
        Self::Reference(Box::new(error))
    }
}

/// Payload digest of the committed coverage delta of `record`'s analysis, if any.
pub fn committed_record(
    deployment: &ReferenceDeployment,
    record: &CoverageRecord,
) -> Result<Option<ContentDigest>, ContractError> {
    let object = record.object_id()?;
    Ok(deployment
        .ledger()
        .batches()
        .iter()
        .flat_map(|batch| batch.deltas.iter())
        .find(|delta| delta.family == FAMILY_COVERAGE_WITNESS && delta.object_id == object)
        .map(|delta| delta.payload_digest))
}

/// Current retention state of `records` (all retained, or proposed).
pub fn coverage_status(
    deployment: &ReferenceDeployment,
    records: &[&CoverageRecord],
) -> Result<CoverageStatus, ContractError> {
    for record in records {
        if committed_record(deployment, record)?.is_none() {
            return Ok(CoverageStatus::Proposed);
        }
    }
    Ok(CoverageStatus::AlreadyRetained)
}

/// Checks, without writing, that `approval` is [`approval_digest`] of `records` or the approval
/// of the records already retained for these analyses; returns each record's committed payload.
pub fn check_approval(
    deployment: &ReferenceDeployment,
    records: &[&CoverageRecord],
    approval: ContentDigest,
) -> Result<Vec<Option<ContentDigest>>, CoverageError> {
    let mut committed = Vec::with_capacity(records.len());
    for record in records {
        record.validate()?;
        committed.push(committed_record(deployment, record)?);
    }
    let retained: Option<Vec<ContentDigest>> = committed.iter().copied().collect();
    let rerun = retained
        .as_ref()
        .is_some_and(|digests| approval_over(digests) == approval);
    if approval != approval_digest(records) && !rerun {
        return Err(CoverageError::StaleApproval(approval));
    }
    Ok(committed)
}

/// Retains exactly the approved coverage records: the approval must equal
/// [`approval_digest`] of `records`, or the approval of the records already retained for these
/// analyses (an exact rerun). Checked before any write. Records already retained are never
/// rewritten; the rest are staged in the spool and committed in one `coverage_witness` batch.
pub fn retain_coverage(
    deployment: &mut ReferenceDeployment,
    records: &[&CoverageRecord],
    approval: ContentDigest,
    cx: &ReplayCx,
) -> Result<CoverageStatus, CoverageError> {
    let committed = check_approval(deployment, records, approval)?;
    if committed.iter().all(Option::is_some) {
        return Ok(CoverageStatus::AlreadyRetained);
    }
    let mut deltas = Vec::new();
    let mut children = Vec::new();
    let mut identity = CanonicalEncoder::new();
    identity.text(APPROVAL_DOMAIN);
    for (record, existing) in records.iter().zip(&committed) {
        if existing.is_some() {
            continue;
        }
        let bytes = record.to_bytes();
        let digest = deployment.stage_payload(&bytes)?;
        identity.digest(digest);
        deltas.push(EvidenceDelta {
            delta_id: format!("delta:coverage:{}", hex(record.identity())),
            family: FAMILY_COVERAGE_WITNESS.to_owned(),
            object_id: record.object_id()?,
            prior_generation: None,
            new_generation: 1,
            validity: record.analysed,
            plane: Plane::Authority,
            payload_digest: digest,
            witness_digest: None,
            operation_id: None,
        });
        children.push(digest);
        children.push(record.import_root);
    }
    let batch = BatchId::parse(format!(
        "batch:coverage:{}",
        hex(ContentDigest::sha256(&identity.finish()))
    ))?;
    deployment.append_batch(batch, deltas, children, cx)?;
    Ok(CoverageStatus::Retained)
}

/// Latest capture instant a record analysed (its analysed hull's latest bound).
#[must_use]
pub fn analysed_through(record: &CoverageRecord) -> TimestampNs {
    record.analysed.latest
}

#[cfg(test)]
mod tests;

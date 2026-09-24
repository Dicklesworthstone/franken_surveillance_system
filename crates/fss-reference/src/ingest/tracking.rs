#![forbid(unsafe_code)]
//! Bounded single-camera box association over verified retained detector projections.
//!
//! Associations are hypotheses, never biometric identity, physical arrival/departure, or
//! cross-camera identity. No velocity is inferred from uncertain capture intervals. Matching
//! maximizes cardinality, then summed floor-quantized IoU, with deterministic ordering. Camera,
//! contract, geometry and source discontinuities reset all associations with explicit reasons.

use super::detections::{DetectionError, DetectionFrame, MAX_DETECTIONS};
use crate::ReplayCx;
use fss_core::{CanonicalEncode, CanonicalEncoder, ContentDigest, ContractError, SensorCapsule};
use std::error::Error;
use std::fmt;

/// Hard live-hypothesis ceiling, independently bounded from detector output size.
pub const MAX_LOCAL_TRACKS: usize = 128;

/// Explicit association/lifetime policy; frame counts are not time measurements.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrackingConfig {
    /// Inclusive IoU gate in millionths, between 1 and 1,000,000.
    pub minimum_iou_ppm: u32,
    /// Consecutive matched observations required for confirmation (1..128).
    pub confirmation_hits: u32,
    /// Number of processed, consecutive frames with no match retained before retirement (0..128).
    pub maximum_missed_frames: u32,
    /// Maximum retained hypotheses, at most MAX_LOCAL_TRACKS. Overflow refuses atomically.
    pub maximum_tracks: usize,
}
impl TrackingConfig {
    /// Deterministic identity including algorithm, numeric policy, and capacity behavior.
    pub fn digest(self) -> Result<ContentDigest, TrackingError> {
        if self.minimum_iou_ppm == 0
            || self.minimum_iou_ppm > 1_000_000
            || self.confirmation_hits == 0
            || self.confirmation_hits > 128
            || self.maximum_missed_frames > 128
            || self.maximum_tracks == 0
            || self.maximum_tracks > MAX_LOCAL_TRACKS
        {
            return Err(TrackingError::InvalidConfig);
        }
        let mut e = CanonicalEncoder::new();
        e.text("fss.local_box_association.v1:cardinality-then-floor-iou:hungarian:row-id-ties");
        e.u32(self.minimum_iou_ppm);
        e.u32(self.confirmation_hits);
        e.u32(self.maximum_missed_frames);
        e.u64(self.maximum_tracks as u64);
        Ok(ContentDigest::sha256(&e.finish_checked()?))
    }
}

/// Failures leave the track state and last result unchanged, but spent work is not refunded.
#[derive(Debug)]
pub enum TrackingError {
    /// Invalid policy or hard capacity.
    InvalidConfig,
    /// Same-source evidence was replayed backwards or a sequence was reinterpreted.
    OutOfOrder,
    /// Keeping all hypotheses would exceed capacity; nothing is silently evicted.
    Capacity,
    /// Cumulative association allowance exhausted.
    BudgetExceeded,
    /// Owner cancellation observed before state publication.
    Cancelled,
    /// A monotone observation counter cannot advance.
    CounterOverflow,
    /// Invalid canonical encoding.
    Contract(ContractError),
    /// Input detector projection could not be encoded.
    Detection(DetectionError),
}
impl fmt::Display for TrackingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidConfig => "invalid local tracking policy",
            Self::OutOfOrder => "out-of-order or reinterpreted tracking frame",
            Self::Capacity => "local track capacity exceeded",
            Self::BudgetExceeded => "local association work budget exhausted",
            Self::Cancelled => "local tracking owner cancelled",
            Self::CounterOverflow => "local tracking counter overflow",
            Self::Contract(_) => "invalid local tracking encoding",
            Self::Detection(_) => "invalid tracking input projection",
        })
    }
}
impl Error for TrackingError {}
impl From<ContractError> for TrackingError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}
impl From<DetectionError> for TrackingError {
    fn from(error: DetectionError) -> Self {
        Self::Detection(error)
    }
}

/// Owner-provided cumulative budget for candidate edges and Hungarian column probes.
#[derive(Debug)]
pub struct AssociationBudget {
    remaining: u64,
    used: u64,
}
impl AssociationBudget {
    /// Allocate deterministic operation units, not wall-clock time or energy.
    #[must_use]
    pub fn new(units: u64) -> Self {
        Self {
            remaining: units,
            used: 0,
        }
    }
    /// Units spent, including work in refused updates.
    #[must_use]
    pub fn used(&self) -> u64 {
        self.used
    }
    /// Unspent allowance.
    #[must_use]
    pub fn remaining(&self) -> u64 {
        self.remaining
    }
    fn charge(&mut self) -> Result<(), TrackingError> {
        if self.remaining == 0 {
            return Err(TrackingError::BudgetExceeded);
        }
        self.remaining -= 1;
        self.used += 1;
        Ok(())
    }
}

/// A reason old hypotheses cannot be associated with this frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrackReset {
    /// Import, sensor, or stream changed. No cross-camera identity is attempted.
    SourceChanged,
    /// The frozen model/output/class/threshold contract changed.
    ContractChanged,
    /// Coded image dimensions changed.
    GeometryChanged,
    /// A source sequence or segment was skipped.
    SequenceGap,
    /// The source capsule explicitly declares a gap.
    SourceGap,
    /// Clock basis or monotone capture bounds changed incompatibly.
    ClockChanged,
}
impl TrackReset {
    /// Stable report spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SourceChanged => "source_changed",
            Self::ContractChanged => "contract_changed",
            Self::GeometryChanged => "geometry_changed",
            Self::SequenceGap => "sequence_gap",
            Self::SourceGap => "source_gap",
            Self::ClockChanged => "clock_changed",
        }
    }
}

/// One local association hypothesis. Missing observations retain the last box explicitly as stale.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrackObservation {
    /// Deterministic seed- and history-bound hypothesis identity, not a real-world person ID.
    pub id: ContentDigest,
    /// Class index in the detector contract.
    pub class_index: usize,
    /// Last observed half-open box in 1/256 coded-image pixels.
    pub bounds: [u32; 4],
    /// Exact last observed F32 score bits, not a calibrated association probability.
    pub score_bits: u32,
    /// Original row matched in this frame; None means the box was not observed in this frame.
    pub observed_row: Option<usize>,
    /// First source sequence supporting this hypothesis.
    pub first_sequence: u64,
    /// Last source sequence with a match, not the current time when missed.
    pub last_seen_sequence: u64,
    /// Total observations matched so far.
    pub observations: u64,
    /// Current consecutive-hit count; a missed frame resets it to zero.
    pub consecutive_hits: u32,
    /// Consecutive processed frames without a match.
    pub missed_frames: u32,
    /// Whether confirmation_hits has been met; still an uncalibrated local hypothesis.
    pub confirmed: bool,
    /// Multiple feasible edges existed at either endpoint; never resolved into identity certainty.
    pub ambiguous: bool,
}

/// Why a local hypothesis was removed; neither condition proves physical departure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrackEnd {
    /// A source/contract/geometry/clock reset invalidated association.
    Reset,
    /// Explicit maximum missed-frame allowance was exceeded.
    MissedLimit,
}
/// An explicit retirement, not a disappearance silently omitted from the result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetiredTrack {
    /// Previous local hypothesis identity.
    pub id: ContentDigest,
    /// Why association stopped.
    pub reason: TrackEnd,
}

/// One complete atomic update. It is an advisory read projection, not ledger or effect authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrackingUpdate {
    /// Exact detector projection consumed.
    pub input_digest: ContentDigest,
    /// Previous update's canonical digest, preserving the association history.
    pub predecessor: Option<ContentDigest>,
    /// Frozen tracker policy and algorithm identity.
    pub config_digest: ContentDigest,
    /// Exact retained model run.
    pub run_identity: ContentDigest,
    /// Exact decoded frame publication root.
    pub frame_root: ContentDigest,
    /// Original capsule, including clock uncertainty and gap disclosure.
    pub capsule: SensorCapsule,
    /// Current active hypotheses in deterministic ID order.
    pub tracks: Vec<TrackObservation>,
    /// Retired hypotheses, including resets and missed-limit expiry.
    pub retired: Vec<RetiredTrack>,
    /// All applicable invalidators in stable order.
    pub resets: Vec<TrackReset>,
    /// Eligible class/geometry association edges before assignment.
    pub eligible_edges: usize,
    /// Candidate-edge and solver-probe units spent by this successful update.
    pub work_units: u64,
}
impl TrackingUpdate {
    /// Versioned internal projection bytes. Public fields are inspectable, not authenticated grants.
    pub fn encoded(&self) -> Result<Vec<u8>, TrackingError> {
        if self.tracks.len() > MAX_LOCAL_TRACKS
            || self.retired.len() > MAX_LOCAL_TRACKS
            || self.resets.len() > 6
        {
            return Err(TrackingError::Capacity);
        }
        let mut e = CanonicalEncoder::new();
        e.bytes(b"FSSTRKS1");
        e.u32(1);
        e.text("fss.local_box_tracks.v1");
        e.digest(self.input_digest);
        e.bool(self.predecessor.is_some());
        if let Some(digest) = self.predecessor {
            e.digest(digest);
        }
        e.digest(self.config_digest);
        e.digest(self.run_identity);
        e.digest(self.frame_root);
        self.capsule.encode_canonical(&mut e);
        e.u64(self.eligible_edges as u64);
        e.u64(self.work_units);
        e.u64(self.resets.len() as u64);
        for reset in &self.resets {
            e.text(reset.as_str());
        }
        e.u64(self.tracks.len() as u64);
        for t in &self.tracks {
            e.digest(t.id);
            e.u64(t.class_index as u64);
            for coordinate in t.bounds {
                e.u32(coordinate);
            }
            e.u32(t.score_bits);
            e.bool(t.observed_row.is_some());
            if let Some(row) = t.observed_row {
                e.u64(row as u64);
            }
            e.u64(t.first_sequence);
            e.u64(t.last_seen_sequence);
            e.u64(t.observations);
            e.u32(t.consecutive_hits);
            e.u32(t.missed_frames);
            e.bool(t.confirmed);
            e.bool(t.ambiguous);
        }
        e.u64(self.retired.len() as u64);
        for retired in &self.retired {
            e.digest(retired.id);
            e.u8(match retired.reason {
                TrackEnd::Reset => 0,
                TrackEnd::MissedLimit => 1,
            });
        }
        Ok(e.finish_checked()?)
    }
    /// Complete history-linked update digest.
    pub fn digest(&self) -> Result<ContentDigest, TrackingError> {
        Ok(ContentDigest::sha256(&self.encoded()?))
    }
}

#[derive(Clone, Debug)]
struct Proposal {
    row: usize,
    class_index: usize,
    bounds: [u32; 4],
    score_bits: u32,
}
#[derive(Clone, Debug)]
struct InputFrame {
    digest: ContentDigest,
    contract: ContentDigest,
    import: ContentDigest,
    segment: u64,
    capsule: SensorCapsule,
    dimensions: [u32; 2],
    run: ContentDigest,
    frame: ContentDigest,
    proposals: Vec<Proposal>,
}
impl InputFrame {
    fn from_detection(frame: &DetectionFrame) -> Result<Self, TrackingError> {
        let mut proposals: Vec<_> = frame
            .detections()
            .iter()
            .map(|d| Proposal {
                row: d.row(),
                class_index: d.class_index(),
                bounds: d.bounds().coordinates(),
                score_bits: d.score().to_bits(),
            })
            .collect();
        proposals.sort_by_key(|p| p.row);
        Ok(Self {
            digest: frame.digest()?,
            contract: frame.contract().digest(),
            import: frame.import_identity(),
            segment: frame.segment_index(),
            capsule: frame.capsule().clone(),
            dimensions: frame.dimensions(),
            run: frame.run_identity(),
            frame: frame.frame_root(),
            proposals,
        })
    }
    fn same_source(&self, other: &Self) -> bool {
        self.import == other.import
            && self.capsule.sensor_id == other.capsule.sensor_id
            && self.capsule.stream_id == other.capsule.stream_id
    }
}

fn overlap(a: [u32; 4], b: [u32; 4]) -> (u64, u64) {
    let area = |r: [u32; 4]| u64::from(r[2] - r[0]) * u64::from(r[3] - r[1]);
    let intersection = u64::from(a[2].min(b[2]).saturating_sub(a[0].max(b[0])))
        * u64::from(a[3].min(b[3]).saturating_sub(a[1].max(b[1])));
    (intersection, area(a) + area(b) - intersection)
}

/// Hungarian rectangular assignment with one unmatched dummy per row. Bounded nonnegative
/// integer costs prefer cardinality before total IoU. Ties visit ID-ordered rows and then
/// source-row-ordered columns. Disallowed edges cost more than an available unmatched dummy.
fn assign(
    weights: &[Vec<Option<u32>>],
    budget: &mut AssociationBudget,
    check: &mut impl FnMut() -> Result<(), TrackingError>,
) -> Result<Vec<Option<usize>>, TrackingError> {
    let n = weights.len();
    if n == 0 {
        return Ok(Vec::new());
    }
    let columns = weights[0].len();
    if n > MAX_LOCAL_TRACKS
        || columns > MAX_DETECTIONS
        || weights
            .iter()
            .any(|row| row.len() != columns || row.iter().flatten().any(|w| *w > 1_000_000))
    {
        return Err(TrackingError::Capacity);
    }
    let m = columns + n;
    let unmatched_cost = (n as i64 + 2) * 1_000_000;
    let mut u = vec![0_i64; n + 1];
    let mut v = vec![0_i64; m + 1];
    let mut p = vec![0_usize; m + 1];
    let mut way = vec![0_usize; m + 1];
    for i in 1..=n {
        check()?;
        p[0] = i;
        let mut j0 = 0;
        let mut minimum = vec![i64::MAX / 4; m + 1];
        let mut used = vec![false; m + 1];
        loop {
            used[j0] = true;
            let i0 = p[j0];
            let mut delta = i64::MAX / 4;
            let mut j1 = 0;
            for j in 1..=m {
                if used[j] {
                    continue;
                }
                check()?;
                budget.charge()?;
                let cost = if j > columns {
                    unmatched_cost
                } else {
                    weights[i0 - 1][j - 1].map_or(unmatched_cost + 1, |w| 1_000_000 - i64::from(w))
                };
                let reduced = cost - u[i0] - v[j];
                if reduced < minimum[j] {
                    minimum[j] = reduced;
                    way[j] = j0;
                }
                if minimum[j] < delta {
                    delta = minimum[j];
                    j1 = j;
                }
            }
            for j in 0..=m {
                if used[j] {
                    u[p[j]] += delta;
                    v[j] -= delta;
                } else {
                    minimum[j] -= delta;
                }
            }
            j0 = j1;
            if p[j0] == 0 {
                break;
            }
        }
        loop {
            let j1 = way[j0];
            p[j0] = p[j1];
            j0 = j1;
            if j0 == 0 {
                break;
            }
        }
    }
    let mut result = vec![None; n];
    for j in 1..=columns {
        if p[j] != 0 {
            result[p[j] - 1] = Some(j - 1);
        }
    }
    Ok(result)
}

/// Atomic bounded hypothesis state. Reconstruct it by replaying the exact ordered detector
/// projections; no hidden model, clock, tracker checkpoint file, or latest-frame lookup exists.
#[derive(Debug)]
pub struct LocalBoxTracker {
    config: TrackingConfig,
    config_digest: ContentDigest,
    tracks: Vec<TrackObservation>,
    previous: Option<InputFrame>,
    latest: Option<TrackingUpdate>,
}
impl LocalBoxTracker {
    /// Start a new explicit association history with a frozen policy.
    pub fn new(config: TrackingConfig) -> Result<Self, TrackingError> {
        Ok(Self {
            config_digest: config.digest()?,
            config,
            tracks: Vec::new(),
            previous: None,
            latest: None,
        })
    }
    /// Current active hypotheses, including explicitly stale unmatched boxes.
    #[must_use]
    pub fn tracks(&self) -> &[TrackObservation] {
        &self.tracks
    }
    /// Frozen policy identity.
    #[must_use]
    pub fn config_digest(&self) -> ContentDigest {
        self.config_digest
    }
    /// Associate one verified detector projection. Exact repeats return the previous update
    /// without aging tracks or charging again. Any failure leaves all hypotheses unchanged.
    pub fn observe(
        &mut self,
        frame: &DetectionFrame,
        budget: &mut AssociationBudget,
        cx: &ReplayCx,
    ) -> Result<TrackingUpdate, TrackingError> {
        let input = InputFrame::from_detection(frame)?;
        self.observe_input(input, budget, || {
            cx.checkpoint("local_tracking:work")
                .map_err(|_| TrackingError::Cancelled)
        })
    }
    fn observe_input(
        &mut self,
        input: InputFrame,
        budget: &mut AssociationBudget,
        mut check: impl FnMut() -> Result<(), TrackingError>,
    ) -> Result<TrackingUpdate, TrackingError> {
        check()?;
        if let Some(previous) = &self.previous {
            if previous.digest == input.digest {
                return self.latest.clone().ok_or(TrackingError::OutOfOrder);
            }
            if input.same_source(previous)
                && (input.capsule.sequence <= previous.capsule.sequence
                    || input.segment <= previous.segment)
            {
                return Err(TrackingError::OutOfOrder);
            }
        }
        if input.proposals.len() > MAX_DETECTIONS {
            return Err(TrackingError::Capacity);
        }
        let before = budget.used();
        let predecessor = self
            .latest
            .as_ref()
            .map(TrackingUpdate::digest)
            .transpose()?;
        let mut resets = Vec::new();
        if let Some(previous) = &self.previous {
            if !input.same_source(previous) {
                resets.push(TrackReset::SourceChanged);
            }
            if input.contract != previous.contract {
                resets.push(TrackReset::ContractChanged);
            }
            if input.dimensions != previous.dimensions {
                resets.push(TrackReset::GeometryChanged);
            }
            if input.same_source(previous)
                && (previous.capsule.sequence.checked_add(1) != Some(input.capsule.sequence)
                    || previous.segment.checked_add(1) != Some(input.segment))
            {
                resets.push(TrackReset::SequenceGap);
            }
            if input.capsule.clock_basis != previous.capsule.clock_basis
                || (input.same_source(previous)
                    && (input.capsule.capture.earliest < previous.capsule.capture.earliest
                        || input.capsule.capture.latest < previous.capsule.capture.latest))
            {
                resets.push(TrackReset::ClockChanged);
            }
        }
        if input.capsule.gap_before {
            resets.push(TrackReset::SourceGap);
        }
        let mut retired = Vec::new();
        let mut working = if resets.is_empty() {
            self.tracks.clone()
        } else {
            retired.extend(self.tracks.iter().map(|t| RetiredTrack {
                id: t.id,
                reason: TrackEnd::Reset,
            }));
            Vec::new()
        };
        working.sort_by_key(|t| t.id);
        let mut weights = Vec::with_capacity(working.len());
        let mut column_edges = vec![0_usize; input.proposals.len()];
        let mut row_edges = vec![0_usize; working.len()];
        let mut eligible_edges = 0;
        for (i, track) in working.iter().enumerate() {
            let mut row = Vec::with_capacity(input.proposals.len());
            for (j, proposal) in input.proposals.iter().enumerate() {
                check()?;
                budget.charge()?;
                let (intersection, union) = overlap(track.bounds, proposal.bounds);
                if track.class_index == proposal.class_index
                    && intersection > 0
                    && u128::from(intersection) * 1_000_000
                        >= u128::from(union) * u128::from(self.config.minimum_iou_ppm)
                {
                    row.push(Some(
                        ((u128::from(intersection) * 1_000_000) / u128::from(union)) as u32,
                    ));
                    row_edges[i] += 1;
                    column_edges[j] += 1;
                    eligible_edges += 1;
                } else {
                    row.push(None);
                }
            }
            weights.push(row);
        }
        let assignment = assign(&weights, budget, &mut check)?;
        let mut matched = vec![false; input.proposals.len()];
        let mut next = Vec::new();
        for (i, mut track) in working.into_iter().enumerate() {
            check()?;
            if let Some(j) = assignment[i] {
                let proposal = &input.proposals[j];
                matched[j] = true;
                track.bounds = proposal.bounds;
                track.score_bits = proposal.score_bits;
                track.observed_row = Some(proposal.row);
                track.last_seen_sequence = input.capsule.sequence;
                track.observations = track
                    .observations
                    .checked_add(1)
                    .ok_or(TrackingError::CounterOverflow)?;
                track.consecutive_hits = track
                    .consecutive_hits
                    .saturating_add(1)
                    .min(self.config.confirmation_hits);
                track.confirmed |= track.consecutive_hits >= self.config.confirmation_hits;
                track.missed_frames = 0;
                track.ambiguous = row_edges[i] > 1 || column_edges[j] > 1;
                next.push(track);
            } else {
                track.observed_row = None;
                track.consecutive_hits = 0;
                track.missed_frames += 1;
                if track.missed_frames > self.config.maximum_missed_frames {
                    retired.push(RetiredTrack {
                        id: track.id,
                        reason: TrackEnd::MissedLimit,
                    });
                } else {
                    next.push(track);
                }
            }
        }
        for (j, proposal) in input.proposals.iter().enumerate() {
            if matched[j] {
                continue;
            }
            check()?;
            let mut e = CanonicalEncoder::new();
            e.text("fss.local_track_seed.v1");
            e.digest(self.config_digest);
            e.digest(input.digest);
            e.bool(predecessor.is_some());
            if let Some(digest) = predecessor {
                e.digest(digest);
            }
            e.u64(proposal.row as u64);
            next.push(TrackObservation {
                id: ContentDigest::sha256(&e.finish_checked()?),
                class_index: proposal.class_index,
                bounds: proposal.bounds,
                score_bits: proposal.score_bits,
                observed_row: Some(proposal.row),
                first_sequence: input.capsule.sequence,
                last_seen_sequence: input.capsule.sequence,
                observations: 1,
                consecutive_hits: 1,
                missed_frames: 0,
                confirmed: self.config.confirmation_hits == 1,
                ambiguous: column_edges[j] > 0,
            });
        }
        if next.len() > self.config.maximum_tracks {
            return Err(TrackingError::Capacity);
        }
        next.sort_by_key(|t| t.id);
        retired.sort_by_key(|t| t.id);
        let update = TrackingUpdate {
            input_digest: input.digest,
            predecessor,
            config_digest: self.config_digest,
            run_identity: input.run,
            frame_root: input.frame,
            capsule: input.capsule.clone(),
            tracks: next.clone(),
            retired,
            resets,
            eligible_edges,
            work_units: budget.used() - before,
        };
        update.encoded()?;
        check()?;
        // Commit only after every fallible operation. Failed matching never ages or forgets tracks.
        self.tracks = next;
        self.previous = Some(input);
        self.latest = Some(update.clone());
        Ok(update)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fss_core::{CapsuleId, CaptureInterval, ClockBasis, SensorId, StreamId, TimestampNs};
    type TestResult = Result<(), Box<dyn Error>>;
    fn config() -> TrackingConfig {
        TrackingConfig {
            minimum_iou_ppm: 100_000,
            confirmation_hits: 2,
            maximum_missed_frames: 1,
            maximum_tracks: 128,
        }
    }
    fn input(sequence: u64, boxes: &[[u32; 4]]) -> Result<InputFrame, ContractError> {
        let mut e = CanonicalEncoder::new();
        e.u64(sequence);
        for b in boxes {
            for v in b {
                e.u32(*v);
            }
        }
        let digest = ContentDigest::sha256(&e.finish_checked()?);
        Ok(InputFrame {
            digest,
            contract: ContentDigest::sha256(b"contract"),
            import: ContentDigest::sha256(b"import"),
            segment: sequence,
            dimensions: [100, 100],
            run: digest,
            frame: digest,
            capsule: SensorCapsule {
                capsule_id: CapsuleId::parse(format!("capsule:{sequence}"))?,
                sensor_id: SensorId::parse("sensor:test")?,
                stream_id: StreamId::parse("stream:test")?,
                sequence,
                capture: CaptureInterval::new(TimestampNs(0), TimestampNs(1000))?,
                receive_time: TimestampNs(1000),
                clock_basis: ClockBasis::Estimated,
                source_digest: digest,
                source_bytes: 1,
                frame_count: 1,
                gap_before: false,
            },
            proposals: boxes
                .iter()
                .enumerate()
                .map(|(row, b)| Proposal {
                    row,
                    class_index: 0,
                    bounds: *b,
                    score_bits: 0.9_f32.to_bits(),
                })
                .collect(),
        })
    }
    fn step(
        tracker: &mut LocalBoxTracker,
        frame: InputFrame,
    ) -> Result<TrackingUpdate, TrackingError> {
        tracker.observe_input(frame, &mut AssociationBudget::new(1_000_000), || Ok(()))
    }
    #[test]
    fn global_matching_avoids_greedy_cardinality_loss() -> TestResult {
        let w = vec![
            vec![Some(900_000), Some(800_000)],
            vec![Some(850_000), None],
        ];
        assert_eq!(
            assign(&w, &mut AssociationBudget::new(100), &mut || Ok(()))?,
            vec![Some(1), Some(0)]
        );
        Ok(())
    }
    #[test]
    fn assignment_matches_exhaustive_small_oracle() -> TestResult {
        fn oracle(w: &[Vec<Option<u32>>], i: usize, mask: u32) -> (usize, u64) {
            if i == w.len() {
                return (0, 0);
            }
            let mut best = oracle(w, i + 1, mask);
            for (j, value) in w[i].iter().enumerate() {
                if mask & (1 << j) != 0 {
                    continue;
                }
                if let Some(value) = value {
                    let (count, score) = oracle(w, i + 1, mask | (1 << j));
                    best = best.max((count + 1, score + u64::from(*value)));
                }
            }
            best
        }
        let mut seed = 90513_u64;
        for n in 1..=4 {
            for d in 0..=4 {
                for _ in 0..20 {
                    let mut w = vec![vec![None; d]; n];
                    for row in &mut w {
                        for cell in row {
                            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                            if !seed.is_multiple_of(3) {
                                *cell = Some((seed % 1_000_001) as u32);
                            }
                        }
                    }
                    let result = assign(&w, &mut AssociationBudget::new(10000), &mut || Ok(()))?;
                    let mut objective = (0, 0_u64);
                    let mut used = std::collections::BTreeSet::new();
                    for (i, j) in result.iter().enumerate() {
                        if let Some(j) = j {
                            assert!(used.insert(*j));
                            let score = w[i][*j].ok_or(TrackingError::InvalidConfig)?;
                            objective.0 += 1;
                            objective.1 += u64::from(score);
                        }
                    }
                    assert_eq!(objective, oracle(&w, 0, 0));
                }
            }
        }
        Ok(())
    }
    #[test]
    fn repeated_frame_is_idempotent_and_consecutive_hits_confirm() -> TestResult {
        let mut tracker = LocalBoxTracker::new(config())?;
        let mut budget = AssociationBudget::new(1000);
        let a = input(0, &[[0, 0, 100, 100]])?;
        let first = tracker.observe_input(a.clone(), &mut budget, || Ok(()))?;
        assert!(!first.tracks[0].confirmed);
        let used = budget.used();
        assert_eq!(tracker.observe_input(a, &mut budget, || Ok(()))?, first);
        assert_eq!(budget.used(), used);
        let second = step(&mut tracker, input(1, &[[1, 0, 101, 100]])?)?;
        assert_eq!(second.tracks[0].id, first.tracks[0].id);
        assert!(second.tracks[0].confirmed);
        assert_eq!(second.predecessor, Some(first.digest()?));
        Ok(())
    }
    #[test]
    fn missed_frames_are_stale_then_explicitly_retired_not_absence() -> TestResult {
        let mut tracker = LocalBoxTracker::new(config())?;
        let first = step(&mut tracker, input(0, &[[0, 0, 100, 100]])?)?;
        let missed = step(&mut tracker, input(1, &[])?)?;
        assert_eq!(missed.tracks[0].observed_row, None);
        assert_eq!(missed.tracks[0].last_seen_sequence, 0);
        assert_eq!(missed.tracks[0].consecutive_hits, 0);
        let expired = step(&mut tracker, input(2, &[])?)?;
        assert!(expired.tracks.is_empty());
        assert_eq!(
            expired.retired,
            vec![RetiredTrack {
                id: first.tracks[0].id,
                reason: TrackEnd::MissedLimit
            }]
        );
        Ok(())
    }
    #[test]
    fn gap_retires_old_ids_and_preserves_all_reset_reasons() -> TestResult {
        let mut tracker = LocalBoxTracker::new(config())?;
        let first = step(&mut tracker, input(0, &[[0, 0, 100, 100]])?)?;
        let mut gap = input(2, &[[0, 0, 100, 100]])?;
        gap.capsule.gap_before = true;
        let result = step(&mut tracker, gap)?;
        assert_eq!(
            result.resets,
            vec![TrackReset::SequenceGap, TrackReset::SourceGap]
        );
        assert_ne!(result.tracks[0].id, first.tracks[0].id);
        assert_eq!(result.retired[0].reason, TrackEnd::Reset);
        Ok(())
    }
    #[test]
    fn contract_geometry_clock_and_camera_changes_reset_association() -> TestResult {
        for change in 0..4 {
            let mut tracker = LocalBoxTracker::new(config())?;
            let first = step(&mut tracker, input(0, &[[0, 0, 100, 100]])?)?;
            let mut next = input(1, &[[0, 0, 100, 100]])?;
            let reason = match change {
                0 => {
                    next.contract = ContentDigest::sha256(b"other contract");
                    TrackReset::ContractChanged
                }
                1 => {
                    next.dimensions = [101, 100];
                    TrackReset::GeometryChanged
                }
                2 => {
                    next.capsule.clock_basis = ClockBasis::HostMonotonic;
                    TrackReset::ClockChanged
                }
                _ => {
                    next.capsule.sensor_id = SensorId::parse("sensor:other")?;
                    TrackReset::SourceChanged
                }
            };
            let result = step(&mut tracker, next)?;
            assert!(result.resets.contains(&reason));
            assert_ne!(first.tracks[0].id, result.tracks[0].id);
        }
        Ok(())
    }
    #[test]
    fn backward_or_changed_same_sequence_is_refused_without_state_change() -> TestResult {
        let mut tracker = LocalBoxTracker::new(config())?;
        step(&mut tracker, input(2, &[[0, 0, 100, 100]])?)?;
        let before = tracker.tracks().to_vec();
        assert!(matches!(
            step(&mut tracker, input(1, &[])?),
            Err(TrackingError::OutOfOrder)
        ));
        assert!(matches!(
            step(&mut tracker, input(2, &[[0, 0, 90, 90]])?),
            Err(TrackingError::OutOfOrder)
        ));
        assert_eq!(tracker.tracks(), before);
        Ok(())
    }
    #[test]
    fn budget_and_cancellation_failures_do_not_advance_state() -> TestResult {
        let mut tracker = LocalBoxTracker::new(config())?;
        step(&mut tracker, input(0, &[[0, 0, 100, 100]])?)?;
        let before = tracker.tracks().to_vec();
        let mut budget = AssociationBudget::new(1);
        assert!(matches!(
            tracker.observe_input(input(1, &[[0, 0, 100, 100]])?, &mut budget, || Ok(())),
            Err(TrackingError::BudgetExceeded)
        ));
        assert_eq!(budget.used(), 1);
        assert_eq!(tracker.tracks(), before);
        assert!(matches!(
            tracker.observe_input(input(1, &[])?, &mut budget, || Err(
                TrackingError::Cancelled
            )),
            Err(TrackingError::Cancelled)
        ));
        assert_eq!(tracker.tracks(), before);
        assert_eq!(
            step(&mut tracker, input(1, &[[0, 0, 100, 100]])?)?.tracks[0].observations,
            2
        );
        Ok(())
    }
    #[test]
    fn capacity_overflow_does_not_drop_existing_hypotheses() -> TestResult {
        let mut c = config();
        c.maximum_tracks = 1;
        let mut tracker = LocalBoxTracker::new(c)?;
        step(&mut tracker, input(0, &[[0, 0, 100, 100]])?)?;
        let before = tracker.tracks().to_vec();
        assert!(matches!(
            step(
                &mut tracker,
                input(1, &[[0, 0, 100, 100], [200, 200, 300, 300]])?
            ),
            Err(TrackingError::Capacity)
        ));
        assert_eq!(tracker.tracks(), before);
        Ok(())
    }
    #[test]
    fn replay_is_byte_identical_and_ambiguity_remains_visible() -> TestResult {
        let mut left = LocalBoxTracker::new(config())?;
        let mut right = LocalBoxTracker::new(config())?;
        for seq in 0..4 {
            let frame = input(seq, &[[0, 0, 100, 100], [10, 0, 110, 100]])?;
            let a = step(&mut left, frame.clone())?;
            let b = step(&mut right, frame)?;
            assert_eq!(a.encoded()?, b.encoded()?);
            if seq > 0 {
                assert!(a.tracks.iter().all(|t| t.ambiguous));
            }
        }
        Ok(())
    }
    #[test]
    fn classes_never_associate_even_with_identical_geometry() -> TestResult {
        let mut tracker = LocalBoxTracker::new(config())?;
        let first = step(&mut tracker, input(0, &[[0, 0, 100, 100]])?)?;
        let mut next = input(1, &[[0, 0, 100, 100]])?;
        next.proposals[0].class_index = 1;
        let result = step(&mut tracker, next)?;
        assert_eq!(result.eligible_edges, 0);
        assert_eq!(result.tracks.len(), 2);
        assert!(
            result
                .tracks
                .iter()
                .any(|t| t.id == first.tracks[0].id && t.observed_row.is_none())
        );
        Ok(())
    }
}

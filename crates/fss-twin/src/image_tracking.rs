#![forbid(unsafe_code)]
//! Bounded image-space trajectory hypotheses before metric calibration is available.
//!
//! Integer constant-velocity prediction at exact capture times ranks a complete
//! speed-gated candidate graph; uncertain capture times use last-observation ranking.
//! Rectangular Hungarian assignment finds a global minimum including misses;
//! an exclusion solve for every selected edge detects competing assignments within
//! the owner's margin. Ambiguous edges do not update trajectories or create births.
//! All candidate costs remain in the report. Neither a selected path nor expiry is
//! person identity, corroboration, visible ground contact, or evidence of absence.

use crate::foreground::ForegroundSource;
use fss_core::ContentDigest;
use fss_geometry::{GeometryError, WorkBudget};

/// Hard bound on tracks and detections separately; complete outputs are never top-k.
pub const MAX_IMAGE_TRACKS: usize = 64;
/// Exposure deduplication is exact within a bounded episode, not a rolling cache.
pub const MAX_TRACKING_EXPOSURES: usize = 4096;
const MAX_COLUMNS: usize = MAX_IMAGE_TRACKS * 2;
const FORBIDDEN: i64 = 1_i64 << 50;
const SECOND: u64 = 1_000_000_000;

/// Failures leave the tracker unchanged (the caller's work budget is still charged).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImageTrackingError {
    /// Invalid policy, source identity, box, or duplicate detection record.
    InvalidInput,
    /// Camera, clock, image domain, dimensions, model, calibration or mask changed.
    BasisMismatch,
    /// Source exposure has already appeared in this episode.
    ReusedExposure,
    /// Capture intervals do not establish strictly forward order.
    CaptureOrder,
    /// Complete input, state, lifetime or allocation limit exceeded.
    Limit,
    /// Cooperative cancellation or work exhaustion.
    Geometry(GeometryError),
}
impl From<GeometryError> for ImageTrackingError {
    fn from(error: GeometryError) -> Self { Self::Geometry(error) }
}
impl std::fmt::Display for ImageTrackingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidInput => "invalid image-tracking input",
            Self::BasisMismatch => "image-tracking basis changed",
            Self::ReusedExposure => "image-tracking exposure reused",
            Self::CaptureOrder => "image-tracking capture order is uncertain",
            Self::Limit => "image-tracking complete-output limit",
            Self::Geometry(_) => "image-tracking work interrupted",
        })
    }
}
impl std::error::Error for ImageTrackingError {}

/// Explicit conditional assumptions; no policy is learned or activated implicitly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageTrackingPolicy {
    /// Maximum live anonymous trajectories, 1..=64.
    pub maximum_tracks: usize,
    /// Maximum detections in one complete input, 1..=64.
    pub maximum_detections: usize,
    /// Episode length, 1..=4096, bounding exact exposure deduplication.
    pub maximum_exposures: usize,
    /// Required accepted observations for the Established state, 1..=4096.
    pub minimum_observations: u32,
    /// Number of unmatched input exposures retained, 0..=4096.
    pub maximum_misses: u32,
    /// Maximum capture gap from the last observation, 1 ns..=one hour.
    pub maximum_gap_ns: u64,
    /// Conditional per-axis speed bound in pixels/second, 1..=1,000,000.
    pub maximum_speed: u32,
    /// Per-axis measurement/gating slack in pixels, 0..=65536.
    pub gate_padding: u32,
    /// Cost of leaving a track unmatched, in doubled-pixel L1 distance units.
    pub miss_cost: u32,
    /// Global cost margin within which an alternate assignment is ambiguous.
    pub ambiguity_margin: u32,
}
impl ImageTrackingPolicy {
    fn validate(self) -> Result<(), ImageTrackingError> {
        if !(1..=MAX_IMAGE_TRACKS).contains(&self.maximum_tracks)
            || !(1..=MAX_IMAGE_TRACKS).contains(&self.maximum_detections)
            || !(1..=MAX_TRACKING_EXPOSURES).contains(&self.maximum_exposures)
            || !(1..=4096).contains(&self.minimum_observations)
            || self.maximum_misses > 4096
            || self.maximum_gap_ns == 0 || self.maximum_gap_ns > 3600 * SECOND
            || self.maximum_speed == 0 || self.maximum_speed > 1_000_000
            || self.gate_padding > 65536 || self.miss_cost == 0
            || self.miss_cost > 1_000_000_000 || self.ambiguity_margin > 1_000_000_000 {
            return Err(ImageTrackingError::InvalidInput);
        }
        Ok(())
    }
}

/// Whether this exposure can contribute measurements, not whether its scene is safe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum TrackingAvailability {
    /// Measurement production was available; empty detections still do not prove absence.
    Available,
    /// No usable observation, for example an all-private or unknown background.
    Unobservable,
    /// Broad scene/camera disturbance; proposals remain retained but are not assimilated.
    Disturbed,
}

/// One source exposure plus immutable detector and permission identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageTrackingFrame {
    /// Original full-image capture and coordinate basis.
    pub source: ForegroundSource,
    /// Exact model/preprocessing generation, including configuration, not a model name.
    pub detector: [u8; 32],
    /// Exact permission mask. A change requires a new explicitly owned episode.
    pub permission_mask: [u8; 32],
    /// Complete detector report, including omissions and health limitations.
    pub evidence: [u8; 32],
    /// Explicit observation availability.
    pub availability: TrackingAvailability,
}

/// One anonymous proposal. No semantic class, biometric, contact or effect authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageDetection {
    /// Nonzero exposure-local ID; input order does not determine association.
    pub id: u64,
    /// Exact detection record distinct within this exposure.
    pub evidence: [u8; 32],
    /// Inclusive lower pixel-edge corner.
    pub min: [u32; 2],
    /// Exclusive upper pixel-edge corner.
    pub max: [u32; 2],
    /// Truncated/unknown silhouette: center motion cannot exclude a candidate.
    pub partial: bool,
}
impl ImageDetection {
    fn center(self) -> [i64; 2] {
        [i64::from(self.min[0]) + i64::from(self.max[0]),
         i64::from(self.min[1]) + i64::from(self.max[1])]
    }
}

/// Actual observed box and the source/report that produced it; never a prediction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageTrackObservation {
    /// Exact source, detector, permission and capture basis.
    pub frame: ImageTrackingFrame,
    /// Actual image-space proposal.
    pub detection: ImageDetection,
}
/// Lifecycle of a conditional trajectory, not a physical entity lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImageTrackState {
    /// Fewer than the configured observations.
    Tentative,
    /// Enough observations under the declared assignment policy, not corroborated.
    Established,
    /// Latest input supplied no unambiguous measurement; last box remains observed.
    Coasting,
}
/// A provisional trajectory with at most two actual observations for motion ranking.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageTrack {
    id: u64,
    latest: ImageTrackObservation,
    previous: Option<ImageTrackObservation>,
    observations: u32,
    misses: u32,
    state: ImageTrackState,
}
impl ImageTrack {
    /// Anonymous ID scoped to the tracker's explicit episode identity.
    pub fn id(&self) -> u64 { self.id }
    /// Most recent actual observation, even while coasting.
    pub fn latest(&self) -> ImageTrackObservation { self.latest }
    /// Previous actual observation when present.
    pub fn previous(&self) -> Option<ImageTrackObservation> { self.previous }
    /// Number of accepted actual observations, never including predictions.
    pub fn observations(&self) -> u32 { self.observations }
    /// Consecutive inputs without an accepted measurement.
    pub fn misses(&self) -> u32 { self.misses }
    /// Explicit measurement/continuation state.
    pub fn state(&self) -> ImageTrackState { self.state }
}

/// Every pair survives, including conditional exclusions and unresolved alternatives.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageAssociationCandidate {
    /// Existing anonymous trajectory.
    pub track: u64,
    /// Exposure-local detection.
    pub detection: u64,
    /// None is unavailable on a degraded frame, or conditionally speed-excluded
    /// on an Available frame. Neither case is evidence of physical absence.
    pub cost: Option<u32>,
    /// Part of one deterministic globally minimum-cost assignment.
    pub selected: bool,
    /// Selected edge has a competing global assignment within the configured margin.
    pub ambiguous: bool,
}
/// How a supplied proposal affected local trajectory hypotheses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImageDetectionDisposition {
    /// Began a new provisional path, with no admissible existing-track candidate.
    Started(u64),
    /// Continued a path stable under the declared global ambiguity margin.
    Continued(u64),
    /// Retained but not assimilated; no forced merge or new identity was invented.
    Unresolved,
    /// Measurement assimilation was unavailable or disturbed.
    Unavailable,
}
/// Proposal and decision remain linked, including proposals not assimilated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageDetectionDecision {
    /// Original detection, in deterministic ID order.
    pub detection: ImageDetection,
    /// Explicit local outcome.
    pub disposition: ImageDetectionDisposition,
}
/// Why a local path ended; neither reason asserts that a target disappeared.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImageTrackExpiry {
    /// Capture gap exceeded the declared prediction/retention horizon.
    CaptureHorizon,
    /// Too many input exposures lacked an accepted measurement.
    MissLimit,
}
/// Explicit terminal transition retaining the last observed source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpiredImageTrack {
    /// Complete final local track state.
    pub track: ImageTrack,
    /// Local lifetime limit, never negative physical evidence.
    pub reason: ImageTrackExpiry,
}

/// Atomic source-linked update. A report digest is not a canonical publication.
#[derive(Debug)]
pub struct ImageTrackingReport {
    prior: [u8; 32],
    digest: [u8; 32],
    frame: ImageTrackingFrame,
    candidates: Vec<ImageAssociationCandidate>,
    decisions: Vec<ImageDetectionDecision>,
    expired: Vec<ExpiredImageTrack>,
    assignment_cost: u64,
}
impl ImageTrackingReport {
    /// Prior local state/receipt chain, not a ledger anchor.
    pub fn prior_digest(&self) -> [u8; 32] { self.prior }
    /// Versioned local receipt chain, binding source, decisions and resulting state.
    pub fn digest(&self) -> [u8; 32] { self.digest }
    /// Complete unchanged input frame and availability.
    pub fn frame(&self) -> ImageTrackingFrame { self.frame }
    /// Full Cartesian candidate table, ordered by (track ID, detection ID).
    pub fn candidates(&self) -> &[ImageAssociationCandidate] { &self.candidates }
    /// Every proposal, including unresolved and unavailable outcomes.
    pub fn decisions(&self) -> &[ImageDetectionDecision] { &self.decisions }
    /// Explicit horizon/miss terminal transitions.
    pub fn expired(&self) -> &[ExpiredImageTrack] { &self.expired }
    /// Minimum global objective including miss costs, not a calibrated probability.
    pub fn assignment_cost(&self) -> u64 { self.assignment_cost }
}

/// Synchronous, owner-held state. No threads, I/O, auto-activation, or effect authority.
#[derive(Debug)]
pub struct ImageTracker {
    policy: ImageTrackingPolicy,
    digest: [u8; 32],
    basis: Option<ImageTrackingFrame>,
    last_capture: Option<[u64; 2]>,
    exposures: Vec<[u8; 32]>,
    tracks: Vec<ImageTrack>,
    next_id: u64,
}
impl ImageTracker {
    /// Begin an explicitly new episode. Its identity must be retained by the owner.
    pub fn new(episode: [u8; 32], policy: ImageTrackingPolicy,
        budget: &mut WorkBudget<'_>) -> Result<Self, ImageTrackingError> {
        budget.charge(32)?;
        policy.validate()?;
        if episode == [0; 32] { return Err(ImageTrackingError::InvalidInput); }
        let mut bytes = reserve(256)?;
        bytes.extend_from_slice(b"fss/image-tracking/reference/1\0");
        bytes.extend_from_slice(&episode);
        for n in [policy.maximum_tracks as u64, policy.maximum_detections as u64,
            policy.maximum_exposures as u64, u64::from(policy.minimum_observations),
            u64::from(policy.maximum_misses), policy.maximum_gap_ns, u64::from(policy.maximum_speed),
            u64::from(policy.gate_padding), u64::from(policy.miss_cost), u64::from(policy.ambiguity_margin)] {
            integer(&mut bytes, n);
        }
        let digest = ContentDigest::sha256(&bytes).bytes();
        budget.charge(0)?;
        Ok(Self { policy, digest, basis: None, last_capture: None,
            exposures: reserve(policy.maximum_exposures)?, tracks: reserve(policy.maximum_tracks)?, next_id: 1 })
    }
    /// Active anonymous trajectory hypotheses in ID order.
    pub fn tracks(&self) -> &[ImageTrack] { &self.tracks }
    /// Local receipt chain head; unchanged by all failed updates.
    pub fn digest(&self) -> [u8; 32] { self.digest }
    /// Exact immutable limits and conditional assumptions.
    pub fn policy(&self) -> ImageTrackingPolicy { self.policy }
    /// Number of accepted distinct source exposures in this bounded episode.
    pub fn exposure_count(&self) -> usize { self.exposures.len() }

    /// Consume a complete exposure transactionally. Even empty/degraded frames need
    /// their source identity and capture interval. Errors publish no partial state.
    pub fn update(&mut self, frame: ImageTrackingFrame, detections: &[ImageDetection],
        budget: &mut WorkBudget<'_>) -> Result<ImageTrackingReport, ImageTrackingError> {
        budget.charge(1)?;
        if detections.len() > self.policy.maximum_detections
            || self.exposures.len() >= self.policy.maximum_exposures { return Err(ImageTrackingError::Limit); }
        validate_frame(frame)?;
        if self.basis.is_some_and(|basis| !same_basis(basis, frame)) { return Err(ImageTrackingError::BasisMismatch); }
        budget.charge(self.exposures.len() as u64)?;
        if self.exposures.contains(&frame.source.image.exposure) { return Err(ImageTrackingError::ReusedExposure); }
        if self.last_capture.is_some_and(|last| last[1] >= frame.source.capture[0]) { return Err(ImageTrackingError::CaptureOrder); }
        let mut ordered = reserve(detections.len())?;
        ordered.extend_from_slice(detections);
        budget.charge((detections.len() * detections.len() + 1) as u64)?;
        ordered.sort_unstable_by_key(|d| d.id);
        for (i, detection) in ordered.iter().enumerate() {
            if detection.id == 0 || [frame.evidence, frame.source.image.exposure,
                frame.source.image.pixels, frame.detector, [0; 32]].contains(&detection.evidence)
                || (0..2).any(|axis| detection.min[axis] >= detection.max[axis]
                    || detection.max[axis] > frame.source.image.dimensions[axis])
                || ordered[..i].iter().any(|other| other.id == detection.id || other.evidence == detection.evidence) {
                return Err(ImageTrackingError::InvalidInput);
            }
        }
        let mut live = reserve(self.policy.maximum_tracks)?;
        let mut expired = reserve(self.policy.maximum_tracks)?;
        for track in &self.tracks {
            budget.charge(1)?;
            if frame.source.capture[1] - track.latest.frame.source.capture[0] > self.policy.maximum_gap_ns {
                expired.push(ExpiredImageTrack { track: *track, reason: ImageTrackExpiry::CaptureHorizon });
            } else { live.push(*track); }
        }
        let rows = live.len(); let columns = ordered.len() + rows;
        let mut costs = reserve(rows * columns)?;
        let mut candidates = reserve(rows * ordered.len())?;
        for track in &live {
            for detection in &ordered {
                budget.charge(32)?;
                let cost = if frame.availability == TrackingAvailability::Available {
                    pair_cost(*track, frame, *detection, self.policy)
                } else { None };
                candidates.push(ImageAssociationCandidate { track: track.id, detection: detection.id,
                    cost, selected: false, ambiguous: false });
                costs.push(cost.map_or(FORBIDDEN, i64::from));
            }
            for _ in 0..rows { costs.push(i64::from(self.policy.miss_cost)); }
        }
        let best = assign(&costs, rows, columns, None, budget)?;
        let mut decisions = reserve(ordered.len())?;
        for detection in &ordered {
            decisions.push(ImageDetectionDecision { detection: *detection,
                disposition: if frame.availability == TrackingAvailability::Available {
                    ImageDetectionDisposition::Unresolved
                } else { ImageDetectionDisposition::Unavailable } });
        }
        for (row, track) in live.iter_mut().enumerate() {
            budget.charge(1)?;
            let column = best.columns[row];
            let mut accepted = false;
            if column < ordered.len() {
                let alternate = assign(&costs, rows, columns, Some((row, column)), budget)?;
                let ambiguous = alternate.cost <= best.cost + u64::from(self.policy.ambiguity_margin);
                let candidate = &mut candidates[row * ordered.len() + column];
                candidate.selected = true; candidate.ambiguous = ambiguous;
                if !ambiguous {
                    track.previous = Some(track.latest);
                    track.latest = ImageTrackObservation { frame, detection: ordered[column] };
                    track.observations += 1; track.misses = 0;
                    track.state = observed_state(track.observations, self.policy);
                    decisions[column].disposition = ImageDetectionDisposition::Continued(track.id);
                    accepted = true;
                }
            }
            if !accepted { track.misses += 1; track.state = ImageTrackState::Coasting; }
        }
        let mut next = reserve(self.policy.maximum_tracks)?;
        for track in live {
            budget.charge(1)?;
            if track.misses > self.policy.maximum_misses {
                expired.push(ExpiredImageTrack { track, reason: ImageTrackExpiry::MissLimit });
            } else { next.push(track); }
        }
        let mut next_id = self.next_id;
        if frame.availability == TrackingAvailability::Available {
            for decision in &mut decisions {
                budget.charge(candidates.len() as u64 + 1)?;
                // A plausible old path prevents a forced birth, even if cost prefers a miss.
                if decision.disposition == ImageDetectionDisposition::Unresolved
                    && !candidates.iter().any(|c| c.detection == decision.detection.id && c.cost.is_some()) {
                    if next.len() == self.policy.maximum_tracks { return Err(ImageTrackingError::Limit); }
                    next.push(ImageTrack { id: next_id, latest: ImageTrackObservation { frame, detection: decision.detection },
                        previous: None, observations: 1, misses: 0, state: observed_state(1, self.policy) });
                    decision.disposition = ImageDetectionDisposition::Started(next_id);
                    next_id = next_id.checked_add(1).ok_or(ImageTrackingError::Limit)?;
                }
            }
        }
        expired.sort_unstable_by_key(|expired| expired.track.id);
        let mut report = ImageTrackingReport { prior: self.digest, digest: [0; 32], frame,
            candidates, decisions, expired, assignment_cost: best.cost };
        report.digest = receipt_digest(&report, &next, next_id, self.exposures.len() + 1, budget)?;
        // Everything fallible, including the final cancellation poll, precedes mutation.
        budget.charge(0)?;
        self.basis = Some(self.basis.unwrap_or(frame)); self.last_capture = Some(frame.source.capture);
        self.exposures.push(frame.source.image.exposure); self.tracks = next;
        self.next_id = next_id; self.digest = report.digest;
        Ok(report)
    }
}

fn observed_state(count: u32, policy: ImageTrackingPolicy) -> ImageTrackState {
    if count >= policy.minimum_observations { ImageTrackState::Established } else { ImageTrackState::Tentative }
}
fn validate_frame(frame: ImageTrackingFrame) -> Result<(), ImageTrackingError> {
    let source = frame.source;
    if source.camera == 0 || source.clock == 0 || source.capture[0] > source.capture[1]
        || source.image.dimensions.iter().any(|n| *n == 0 || *n > 65536)
        || [source.calibration, source.image.exposure, source.image.pixels, source.image.image_domain,
            frame.detector, frame.permission_mask, frame.evidence].contains(&[0; 32]) {
        return Err(ImageTrackingError::InvalidInput);
    }
    Ok(())
}
fn same_basis(a: ImageTrackingFrame, b: ImageTrackingFrame) -> bool {
    a.source.camera == b.source.camera && a.source.clock == b.source.clock
        && a.source.calibration == b.source.calibration && a.source.image.dimensions == b.source.image.dimensions
        && a.source.image.image_domain == b.source.image.image_domain
        && a.detector == b.detector && a.permission_mask == b.permission_mask
}
fn pair_cost(track: ImageTrack, frame: ImageTrackingFrame, detection: ImageDetection,
    policy: ImageTrackingPolicy) -> Option<u32> {
    let last = track.latest; let center = last.detection.center(); let incoming = detection.center();
    let elapsed = frame.source.capture[1].saturating_sub(last.frame.source.capture[0]);
    let reach = (u128::from(policy.maximum_speed) * u128::from(elapsed) * 2)
        .div_ceil(u128::from(SECOND)) + u128::from(policy.gate_padding) * 2;
    if !last.detection.partial && !detection.partial
        && (0..2).any(|axis| u128::from((incoming[axis] - center[axis]).unsigned_abs()) > reach) { return None; }
    let mut predicted = center;
    let previous = track.previous.filter(|previous| !previous.detection.partial && !last.detection.partial
        && [previous.frame.source.capture, last.frame.source.capture, frame.source.capture]
            .iter().all(|capture| capture[0] == capture[1]));
    if let Some(previous) = previous {
        let dt = last.frame.source.capture[0].saturating_sub(previous.frame.source.capture[0]);
        let ahead = frame.source.capture[0].saturating_sub(last.frame.source.capture[0]);
        if dt == 0 || ahead == 0 {
            return None;
        }
        let old = previous.detection.center();
        for (axis, predicted_axis) in predicted.iter_mut().enumerate() {
            let shift = i128::from(center[axis] - old[axis]) * i128::from(ahead) / i128::from(dt);
            // Clamp ranking only, not evidence or the complete speed-gated graph.
            *predicted_axis += shift.clamp(-1_000_000_000, 1_000_000_000) as i64;
        }
    }
    let distance = (incoming[0] - predicted[0]).unsigned_abs() + (incoming[1] - predicted[1]).unsigned_abs();
    Some(distance.min(1_000_000_000) as u32)
}

struct Assignment { columns: [usize; MAX_IMAGE_TRACKS], cost: u64 }
// Rectangular shortest augmenting path Hungarian solver. Every row has its own
// available miss column; FORBIDDEN cannot win against a finite full assignment.
fn assign(costs: &[i64], rows: usize, columns: usize, excluded: Option<(usize, usize)>,
    budget: &mut WorkBudget<'_>) -> Result<Assignment, ImageTrackingError> {
    budget.charge(1)?;
    if rows > MAX_IMAGE_TRACKS || columns > MAX_COLUMNS || columns < rows
        || costs.len() != rows * columns { return Err(ImageTrackingError::InvalidInput); }
    let mut u = [0_i64; MAX_IMAGE_TRACKS + 1]; let mut v = [0_i64; MAX_COLUMNS + 1];
    let mut p = [0_usize; MAX_COLUMNS + 1]; let mut way = [0_usize; MAX_COLUMNS + 1];
    for i in 1..=rows {
        p[0] = i; let mut j0 = 0;
        let mut minimum = [FORBIDDEN; MAX_COLUMNS + 1]; let mut used = [false; MAX_COLUMNS + 1];
        loop {
            budget.charge(columns as u64 * 2 + 1)?;
            used[j0] = true; let i0 = p[j0]; let mut delta = FORBIDDEN; let mut j1 = 0;
            for j in 1..=columns {
                if used[j] { continue; }
                let cost = if excluded == Some((i0 - 1, j - 1)) { FORBIDDEN }
                    else { costs[(i0 - 1) * columns + j - 1] };
                let current = cost - u[i0] - v[j];
                if current < minimum[j] { minimum[j] = current; way[j] = j0; }
                if minimum[j] < delta { delta = minimum[j]; j1 = j; }
            }
            if j1 == 0 || delta >= FORBIDDEN { return Err(ImageTrackingError::InvalidInput); }
            for j in 0..=columns {
                if used[j] { u[p[j]] += delta; v[j] -= delta; }
                else { minimum[j] -= delta; }
            }
            j0 = j1;
            if p[j0] == 0 { break; }
        }
        loop {
            budget.charge(1)?;
            let j1 = way[j0]; p[j0] = p[j1]; j0 = j1;
            if j0 == 0 { break; }
        }
    }
    let mut result = Assignment { columns: [usize::MAX; MAX_IMAGE_TRACKS], cost: 0 };
    for (j, &assigned_row) in p.iter().enumerate().take(columns + 1).skip(1) {
        if assigned_row != 0 {
            let row = assigned_row - 1; let column = j - 1;
            let cost = costs[row * columns + column];
            if !(0..FORBIDDEN).contains(&cost) || excluded == Some((row, column)) {
                return Err(ImageTrackingError::InvalidInput);
            }
            result.columns[row] = column; result.cost += cost as u64;
        }
    }
    budget.charge(0)?;
    Ok(result)
}

fn reserve<T>(count: usize) -> Result<Vec<T>, ImageTrackingError> {
    let mut values = Vec::new(); values.try_reserve_exact(count).map_err(|_| ImageTrackingError::Limit)?; Ok(values)
}
fn integer(bytes: &mut Vec<u8>, n: u64) { bytes.extend_from_slice(&n.to_le_bytes()); }
fn frame_bytes(bytes: &mut Vec<u8>, frame: ImageTrackingFrame) {
    let source = frame.source;
    for digest in [source.image.exposure, source.image.pixels, source.image.image_domain,
        source.calibration, frame.detector, frame.permission_mask, frame.evidence] { bytes.extend_from_slice(&digest); }
    for n in [source.camera, source.clock, source.capture[0], source.capture[1],
        u64::from(source.image.dimensions[0]), u64::from(source.image.dimensions[1])] { integer(bytes, n); }
    bytes.push(frame.availability as u8);
}
fn detection_bytes(bytes: &mut Vec<u8>, detection: ImageDetection) {
    integer(bytes, detection.id); bytes.extend_from_slice(&detection.evidence);
    for n in detection.min.into_iter().chain(detection.max) { integer(bytes, u64::from(n)); }
    bytes.push(u8::from(detection.partial));
}
fn track_bytes(bytes: &mut Vec<u8>, track: ImageTrack) {
    integer(bytes, track.id); integer(bytes, u64::from(track.observations)); integer(bytes, u64::from(track.misses));
    bytes.push(match track.state { ImageTrackState::Tentative => 0, ImageTrackState::Established => 1, ImageTrackState::Coasting => 2 });
    frame_bytes(bytes, track.latest.frame); detection_bytes(bytes, track.latest.detection);
    bytes.push(u8::from(track.previous.is_some()));
    if let Some(previous) = track.previous { frame_bytes(bytes, previous.frame); detection_bytes(bytes, previous.detection); }
}
fn receipt_digest(report: &ImageTrackingReport, tracks: &[ImageTrack], next_id: u64,
    exposure_count: usize, budget: &mut WorkBudget<'_>) -> Result<[u8; 32], ImageTrackingError> {
    // Upper bound covers every encoded record, avoiding hidden vector growth.
    let capacity = 512 + report.candidates.len() * 32 + report.decisions.len() * 96
        + (report.expired.len() + tracks.len()) * 768;
    budget.charge(capacity as u64)?;
    let mut bytes = reserve(capacity)?;
    bytes.extend_from_slice(b"fss/image-tracking/update/1\0"); bytes.extend_from_slice(&report.prior);
    frame_bytes(&mut bytes, report.frame); integer(&mut bytes, next_id);
    integer(&mut bytes, exposure_count as u64); integer(&mut bytes, report.assignment_cost);
    integer(&mut bytes, report.candidates.len() as u64);
    for candidate in &report.candidates {
        integer(&mut bytes, candidate.track); integer(&mut bytes, candidate.detection);
        bytes.push(u8::from(candidate.cost.is_some())); integer(&mut bytes, u64::from(candidate.cost.unwrap_or(0)));
        bytes.push(u8::from(candidate.selected)); bytes.push(u8::from(candidate.ambiguous));
    }
    integer(&mut bytes, report.decisions.len() as u64);
    for decision in &report.decisions {
        detection_bytes(&mut bytes, decision.detection);
        let (tag, id) = match decision.disposition { ImageDetectionDisposition::Started(id) => (0, id),
            ImageDetectionDisposition::Continued(id) => (1, id), ImageDetectionDisposition::Unresolved => (2, 0),
            ImageDetectionDisposition::Unavailable => (3, 0) };
        bytes.push(tag); integer(&mut bytes, id);
    }
    integer(&mut bytes, report.expired.len() as u64);
    for expired in &report.expired {
        track_bytes(&mut bytes, expired.track);
        bytes.push(match expired.reason { ImageTrackExpiry::CaptureHorizon => 0, ImageTrackExpiry::MissLimit => 1 });
    }
    integer(&mut bytes, tracks.len() as u64);
    for track in tracks { track_bytes(&mut bytes, *track); }
    let digest = ContentDigest::sha256(&bytes).bytes(); budget.charge(0)?; Ok(digest)
}

/// Shared bounded assignment over explicitly supplied candidate costs.
pub mod assignment;

#[cfg(test)]
mod tests;

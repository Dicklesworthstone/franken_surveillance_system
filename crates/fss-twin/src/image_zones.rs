#![forbid(unsafe_code)]
//! Observed image-zone transitions over the existing anonymous trajectory stream.
//!
//! A polygon is an owner-selected image region, not a metric property boundary.
//! Boxes, not predicted positions or invented ground-contact points, are classified.
//! Entry/exit names describe different observed sides; dwell describes a sampled
//! span, never proof of continuous occupancy, a person, intent or effect authority.

use crate::image_tracking::{ImageDetection, ImageTrackObservation, ImageTrackState,
    ImageTracker, ImageTrackingFrame, ImageTrackingReport, TrackingAvailability};
use fss_core::ContentDigest;
use fss_geometry::{GeometryError, WorkBudget};

/// Complete zone-set bound; observations are never selected by rank.
pub const MAX_IMAGE_ZONES: usize = 16;
/// A zone is a strictly convex integer polygon with this many vertices at most.
pub const MAX_ZONE_VERTICES: usize = 32;

/// Refusals leave the monitor unchanged, including its accepted tracker position.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImageZoneError {
    /// Invalid polygon, zero identity, duplicate zone or invalid temporal policy.
    InvalidInput,
    /// The camera/calibration/image/clock does not match the frozen zone basis.
    BasisMismatch,
    /// Wrong tracker, skipped update or stale report; replay the missing inputs.
    TrackingOrder,
    /// Complete set, output or allocation limit exceeded.
    Limit,
    /// Cooperative cancellation or work-budget refusal.
    Geometry(GeometryError),
}
impl From<GeometryError> for ImageZoneError {
    fn from(error: GeometryError) -> Self { Self::Geometry(error) }
}
impl std::fmt::Display for ImageZoneError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidInput => "invalid image-zone input",
            Self::BasisMismatch => "image-zone coordinate basis changed",
            Self::TrackingOrder => "image-zone tracker history mismatch",
            Self::Limit => "image-zone complete-output limit",
            Self::Geometry(_) => "image-zone work interrupted",
        })
    }
}
impl std::error::Error for ImageZoneError {}

/// Coordinates and nanoseconds belong to exactly this owner-resolved camera mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageZoneBasis {
    /// Nonzero physical camera handle.
    pub camera: u64,
    /// Nonzero common source-capture clock generation.
    pub clock: u64,
    /// Exact calibration, not a mutable camera name.
    pub calibration: [u8; 32],
    /// Exact distortion/crop/resize/pixel-origin chain.
    pub image_domain: [u8; 32],
    /// Width and height of the admitted image grid.
    pub dimensions: [u32; 2],
}
impl ImageZoneBasis {
    fn matches(self, frame: ImageTrackingFrame) -> bool {
        let s = frame.source;
        self.camera == s.camera && self.clock == s.clock && self.calibration == s.calibration
            && self.image_domain == s.image.image_domain && self.dimensions == s.image.dimensions
    }
}

/// Explicit zone declaration. Its interpretation is frozen when the monitor starts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImageZoneSpec {
    /// Nonzero local zone ID, unique in this set.
    pub id: u64,
    /// Ordered strictly convex vertices in pixel-edge coordinates; either winding.
    pub vertices: Vec<[u32; 2]>,
    /// L-infinity pixel slack: expand boxes before any definite side classification.
    pub margin: u32,
    /// Positive lower sampled-span threshold in ns; None disables dwell events.
    pub dwell_ns: Option<u64>,
}
/// Immutable owner assumptions shared by this monitor, not automatic defaults.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageZonePolicy {
    /// Evidence describing why these zones and temporal assumptions were chosen.
    pub selection_evidence: [u8; 32],
    /// Maximum possible gap between actual sightings, at most one hour.
    pub maximum_sample_gap_ns: u64,
}

/// Conservative relation of a complete observed box to the exact image polygon.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ImageZoneRelation {
    /// The expanded closed box lies strictly inside every polygon half-plane.
    Inside,
    /// A separating axis places the expanded box strictly outside the polygon.
    Outside,
    /// Touching, intersecting or within the declared boundary slack.
    Boundary,
    /// An incomplete silhouette cannot establish a definite side.
    Partial,
    /// No unambiguous observation of this trajectory in the current exposure.
    Unobserved,
    /// Measurements were unavailable on the current exposure.
    Unobservable,
    /// A scene/camera disturbance prevented measurement assimilation.
    Disturbed,
    /// The trajectory expired; this does not assert physical departure.
    Expired,
}
/// Evidence-bearing event class, without severity or automatic alert dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ImageZoneEventKind {
    /// First definite inside sighting after startup, interruption or partial evidence.
    ObservedInside,
    /// Definite outside then definite inside on the same anonymous trajectory.
    EnteredBetweenObservations,
    /// Definite inside then definite outside, not inferred from track expiry.
    LeftBetweenObservations,
    /// Uninterrupted inside samples have reached the configured lower time span.
    SampledDwell,
    /// A formerly usable side/run lost measurement continuity or exceeded the gap.
    ObservationInterrupted,
    /// Explicit trajectory retirement, retaining its last actual source.
    TrackExpired,
}
/// Complete observation cell; a coasting track never supplies a current box.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageZoneCell {
    /// Anonymous trajectory ID scoped by this report's tracker chain.
    pub track: u64,
    /// Owner-selected image zone ID.
    pub zone: u64,
    /// Current relation or explicit unavailability.
    pub relation: ImageZoneRelation,
    /// Last actual source sighting; check relation before treating it as current.
    pub last_observation: ImageTrackObservation,
    /// First inside sample in the current uninterrupted run, if any.
    pub dwell_start: Option<ImageTrackObservation>,
    /// Lower/upper span between first and last inside samples, not continuous presence.
    pub sampled_span_ns: Option<[u64; 2]>,
    /// Count of inside sightings supporting that span, never predicted frames.
    pub inside_samples: u32,
}
/// Original source endpoints are retained, including interruptions and retirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageZoneEvent {
    /// Stable event identity bound to this exact zone/tracker/report chain.
    pub digest: [u8; 32],
    /// Anonymous trajectory in the bound tracker episode.
    pub track: u64,
    /// Frozen local zone.
    pub zone: u64,
    /// Explicit observed, interval, interrupted or terminal event.
    pub kind: ImageZoneEventKind,
    /// Earlier source endpoint; None for a first inside sighting.
    pub from: Option<ImageTrackObservation>,
    /// Latest actual sighting, even when the triggering input has no measurement.
    pub to: ImageTrackObservation,
    /// Current classified/unavailable relation; interruptions do not masquerade as exits.
    pub relation: ImageZoneRelation,
}
/// Complete source-pinned read projection, not a canonical event revision or grant.
#[derive(Debug)]
pub struct ImageZoneReport {
    digest: [u8; 32], prior: [u8; 32], config: [u8; 32], tracking: [u8; 32],
    frame: ImageTrackingFrame, cells: Vec<ImageZoneCell>, events: Vec<ImageZoneEvent>,
}
impl ImageZoneReport {
    /// Complete local result identity, stable across exact retries.
    pub fn digest(&self) -> [u8; 32] { self.digest }
    /// Exact preceding monitor result or constructor identity.
    pub fn prior_digest(&self) -> [u8; 32] { self.prior }
    /// Frozen zone, basis, selection-evidence and temporal-policy identity.
    pub fn config_digest(&self) -> [u8; 32] { self.config }
    /// Accepted opaque ImageTrackingReport identity.
    pub fn tracking_digest(&self) -> [u8; 32] { self.tracking }
    /// Triggering source, including availability and clock uncertainty.
    pub fn frame(&self) -> ImageTrackingFrame { self.frame }
    /// Every active and explicitly expired track/zone pair, ordered by (track, zone).
    pub fn cells(&self) -> &[ImageZoneCell] { &self.cells }
    /// All resulting events in (track, zone, event-kind) order.
    pub fn events(&self) -> &[ImageZoneEvent] { &self.events }
}
#[derive(Clone, Copy)]
struct ZoneState {
    track: u64, zone: u64, side: Option<(ImageZoneRelation, ImageTrackObservation)>,
    inside: Option<ImageTrackObservation>, samples: u32, dwell_emitted: bool,
    last: Option<ImageTrackObservation>,
}
impl ZoneState {
    fn new(track: u64, zone: u64) -> Self {
        Self { track, zone, side: None, inside: None, samples: 0, dwell_emitted: false, last: None }
    }
    fn clear(&mut self) {
        self.side = None; self.inside = None; self.samples = 0;
        self.dwell_emitted = false; self.last = None;
    }
}

/// Bounded synchronous observer. State is rebuilt from exact retained tracking inputs.
/// Attaching midway starts new zone history, without retroactively inventing events.
pub struct ImageZoneMonitor {
    basis: ImageZoneBasis, policy: ImageZonePolicy, zones: Vec<ImageZoneSpec>,
    config: [u8; 32], digest: [u8; 32], expected_tracking: [u8; 32],
    states: Vec<ZoneState>, latest: Option<ImageZoneReport>,
}
impl ImageZoneMonitor {
    /// Freeze all zones and bind the exact tracker position before the next update.
    pub fn new(tracker: &ImageTracker, basis: ImageZoneBasis, policy: ImageZonePolicy,
        zones: &[ImageZoneSpec], budget: &mut WorkBudget<'_>) -> Result<Self, ImageZoneError> {
        budget.charge(1)?;
        if zones.is_empty() || zones.len() > MAX_IMAGE_ZONES { return Err(ImageZoneError::Limit); }
        if basis.camera == 0 || basis.clock == 0 || basis.calibration == [0;32]
            || basis.image_domain == [0;32] || basis.dimensions.iter().any(|n| *n == 0 || *n > 65536)
            || policy.selection_evidence == [0;32] || policy.maximum_sample_gap_ns == 0
            || policy.maximum_sample_gap_ns > 3_600_000_000_000 { return Err(ImageZoneError::InvalidInput); }
        let mut frozen = reserve(zones.len())?;
        for zone in zones { frozen.push(geometry::normalize(zone, basis.dimensions, budget)?); }
        frozen.sort_unstable_by_key(|z| z.id);
        if frozen.windows(2).any(|w| w[0].id == w[1].id) { return Err(ImageZoneError::InvalidInput); }
        let config = encoding::configuration(basis, policy, &frozen, budget)?;
        let mut bytes = reserve(96)?;
        bytes.extend_from_slice(b"fss/image-zone-monitor/reference/1\0");
        bytes.extend_from_slice(&config); bytes.extend_from_slice(&tracker.digest());
        budget.charge(bytes.len() as u64)?;
        let digest = ContentDigest::sha256(&bytes).bytes();
        budget.charge(0)?;
        Ok(Self { basis, policy, zones: frozen, config, digest, expected_tracking: tracker.digest(),
            states: Vec::new(), latest: None })
    }
    /// Current zone chain, unchanged after a refused update.
    pub fn digest(&self) -> [u8; 32] { self.digest }
    /// Exact next report predecessor required for gap-free consumption.
    pub fn tracking_digest(&self) -> [u8; 32] { self.expected_tracking }
    /// Frozen zone, basis and owner-selection identity.
    pub fn config_digest(&self) -> [u8; 32] { self.config }
    /// Explicit immutable gap and selection assumptions.
    pub fn policy(&self) -> ImageZonePolicy { self.policy }
    /// Frozen canonicalized polygons, sorted by ID; no mutable policy activation.
    pub fn zones(&self) -> &[ImageZoneSpec] { &self.zones }
    /// Exact coordinate basis required from every tracking report.
    pub fn basis(&self) -> ImageZoneBasis { self.basis }
    /// Latest complete read projection, or None before the first accepted report.
    pub fn latest(&self) -> Option<&ImageZoneReport> { self.latest.as_ref() }

    /// Consume the immediately succeeding opaque tracking report and current tracker.
    /// Exact repeats return the same borrowed result without duplicating dwell/events.
    /// A refused observation can be retried before advancing the upstream tracker.
    pub fn observe(&mut self, tracker: &ImageTracker, report: &ImageTrackingReport,
        budget: &mut WorkBudget<'_>) -> Result<&ImageZoneReport, ImageZoneError> {
        budget.charge(0)?;
        if tracker.digest() != report.digest() { return Err(ImageZoneError::TrackingOrder); }
        if self.latest.as_ref().is_some_and(|r| r.tracking == report.digest()) {
            return self.latest.as_ref().ok_or(ImageZoneError::TrackingOrder);
        }
        if report.prior_digest() != self.expected_tracking { return Err(ImageZoneError::TrackingOrder); }
        let frame = report.frame();
        if !self.basis.matches(frame) { return Err(ImageZoneError::BasisMismatch); }
        let capacity = (tracker.tracks().len() + report.expired().len()) * self.zones.len();
        let mut cells = reserve(capacity)?;
        let mut events = reserve(capacity * 2)?;
        let mut next = reserve(tracker.tracks().len() * self.zones.len())?;
        for track in tracker.tracks() {
            for zone in &self.zones {
                budget.charge(1 + self.states.len() as u64)?;
                let mut state = self.states.iter().find(|s| s.track == track.id() && s.zone == zone.id)
                    .copied().unwrap_or_else(|| ZoneState::new(track.id(), zone.id));
                let latest = track.latest();
                let relation = match frame.availability {
                    TrackingAvailability::Unobservable => ImageZoneRelation::Unobservable,
                    TrackingAvailability::Disturbed => ImageZoneRelation::Disturbed,
                    TrackingAvailability::Available if track.state() == ImageTrackState::Coasting
                        || latest.frame != frame => ImageZoneRelation::Unobserved,
                    TrackingAvailability::Available => geometry::classify(zone, latest.detection, budget)?,
                };
                budget.charge(8)?;
                advance(&mut state, zone, latest, relation, self.policy, &mut events)?;
                let span = state.inside.map(|first| span(first, latest));
                cells.push(ImageZoneCell { track: track.id(), zone: zone.id, relation,
                    last_observation: latest, dwell_start: state.inside,
                    sampled_span_ns: span, inside_samples: state.samples });
                next.push(state);
            }
        }
        for expired in report.expired() {
            for zone in &self.zones {
                budget.charge(1)?;
                let track = expired.track;
                let latest = track.latest();
                cells.push(ImageZoneCell { track: track.id(), zone: zone.id,
                    relation: ImageZoneRelation::Expired, last_observation: latest,
                    dwell_start: None, sampled_span_ns: None, inside_samples: 0 });
                push_event(&mut events, track.id(), zone.id, ImageZoneEventKind::TrackExpired,
                    None, latest, ImageZoneRelation::Expired);
            }
        }
        budget.charge((cells.len() * 16 + events.len() * 16) as u64)?;
        cells.sort_unstable_by_key(|c| (c.track, c.zone));
        events.sort_unstable_by_key(|e| (e.track, e.zone, e.kind as u8));
        let mut output = ImageZoneReport { digest: [0;32], prior: self.digest, config: self.config,
            tracking: report.digest(), frame, cells, events };
        encoding::seal(&mut output, budget)?;
        budget.charge(0)?;
        self.states = next; self.digest = output.digest; self.expected_tracking = report.digest();
        Ok(self.latest.insert(output))
    }
}
fn advance(state: &mut ZoneState, zone: &ImageZoneSpec, latest: ImageTrackObservation,
    relation: ImageZoneRelation, policy: ImageZonePolicy, events: &mut Vec<ImageZoneEvent>)
    -> Result<(), ImageZoneError> {
    let observable = matches!(relation, ImageZoneRelation::Inside | ImageZoneRelation::Outside | ImageZoneRelation::Boundary);
    let gap = state.last.is_some_and(|last| latest.frame.source.capture[1]
        .saturating_sub(last.frame.source.capture[0]) > policy.maximum_sample_gap_ns);
    if !observable || gap {
        if let Some(last) = state.last {
            push_event(events, state.track, state.zone, ImageZoneEventKind::ObservationInterrupted,
                Some(last), latest, relation);
        }
        state.clear();
        if !observable { return Ok(()); }
    }
    if relation == ImageZoneRelation::Boundary {
        // A witnessed boundary crossing may separate stable side endpoints; it never
        // accumulates inside dwell. Missing/partial evidence, unlike boundary evidence,
        // clears the side endpoint completely.
        state.inside = None; state.samples = 0; state.dwell_emitted = false;
    } else {
        let previous = state.side;
        if relation == ImageZoneRelation::Inside {
            let kind = match previous {
                None => Some(ImageZoneEventKind::ObservedInside),
                Some((ImageZoneRelation::Outside, _)) => Some(ImageZoneEventKind::EnteredBetweenObservations),
                _ => None,
            };
            if let Some(kind) = kind {
                push_event(events, state.track, state.zone, kind, previous.map(|p| p.1), latest, relation);
            }
            if state.inside.is_none() { state.inside = Some(latest); }
            state.samples = state.samples.checked_add(1).ok_or(ImageZoneError::Limit)?;
            if let Some(first) = state.inside {
                if !state.dwell_emitted && state.samples >= 2
                    && zone.dwell_ns.is_some_and(|threshold| span(first, latest)[0] >= threshold) {
                    push_event(events, state.track, state.zone, ImageZoneEventKind::SampledDwell,
                        Some(first), latest, relation);
                    state.dwell_emitted = true;
                }
            }
        } else {
            if let Some((ImageZoneRelation::Inside, first)) = previous {
                push_event(events, state.track, state.zone, ImageZoneEventKind::LeftBetweenObservations,
                    Some(first), latest, relation);
            }
            state.inside = None; state.samples = 0; state.dwell_emitted = false;
        }
        state.side = Some((relation, latest));
    }
    state.last = Some(latest);
    Ok(())
}
fn span(first: ImageTrackObservation, last: ImageTrackObservation) -> [u64; 2] {
    if first == last { return [0, 0]; }
    [last.frame.source.capture[0].saturating_sub(first.frame.source.capture[1]),
     last.frame.source.capture[1].saturating_sub(first.frame.source.capture[0])]
}
fn push_event(events: &mut Vec<ImageZoneEvent>, track: u64, zone: u64,
    kind: ImageZoneEventKind, from: Option<ImageTrackObservation>, to: ImageTrackObservation,
    relation: ImageZoneRelation) {
    events.push(ImageZoneEvent { digest: [0;32], track, zone, kind, from, to, relation });
}
fn reserve<T>(count: usize) -> Result<Vec<T>, ImageZoneError> {
    let mut values = Vec::new();
    values.try_reserve_exact(count).map_err(|_| ImageZoneError::Limit)?;
    Ok(values)
}
mod geometry;
mod encoding;
#[cfg(test)]
mod tests;

/// Native image composition with retained, resumable zone-analysis completion.
pub mod pipeline;

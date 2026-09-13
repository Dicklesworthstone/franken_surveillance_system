#![forbid(unsafe_code)]
//! Source-linked, uncertainty-preserving multi-target association candidates.
//!
//! A candidate is not an identity decision. This module never updates a track,
//! invents an observation, or treats an unmatched detection as a new person.

use crate::stream::{TrackReceipt, TrackSnapshot};
use crate::{Bounds3, ContactHypothesis, ContactObservation, ContactProjection, Interval,
    ProjectionOptions, ProjectionQuality, PropertyTwin, TrackingCamera, TwinError,
    project_contact, propagate_motion};
use fss_geometry::{GeometryError, WorkBudget};

/// Hard bound on each side of a single-camera, single-exposure association graph.
pub const MAX_ASSOCIATION_ITEMS: usize = 32;

/// A detector/contact proposal with no assigned persistent track identity.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct UnassignedContact {
    /// Nonzero detection-local ID within this exposure.
    pub id: u64,
    /// Exact detection/contact record; distinct from other records in the batch.
    pub evidence: [u8; 32],
    /// Closed rectangle in the admitted undistorted pixel-edge image domain.
    pub pixel_min: [f64; 2],
    /// Upper contact-rectangle corner, not an inclusive integer pixel index.
    pub pixel_max: [f64; 2],
    /// False retains unknown contact rather than inventing a box-bottom depth.
    pub visible_contact: bool,
}

/// One actual source exposure. Several cameras must use separate batches.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct AssociationFrame {
    /// Exact admitted camera, lens, clock and calibration snapshot.
    pub camera: TrackingCamera,
    /// Nonzero exposure handle within this camera.
    pub exposure: u64,
    /// Source-frame evidence identity, independently of detection record IDs.
    pub evidence: [u8; 32],
    /// Capture interval, never packet-receive time.
    pub capture: [u64; 2],
}

/// Explicit assumptions and complete-output limits. No default acceleration prior.
#[derive(Clone, Copy, Debug)]
pub struct AssociationOptions {
    /// Same conditional support-search volume used by native contact projection.
    pub projection: ProjectionOptions,
    /// Source units/second squared, applicable during source pair and prediction.
    pub acceleration: [f64; 3],
    /// Maximum interval from latest source observation to this exposure, <= one hour.
    pub maximum_gap_ns: u64,
    /// Maximum total retained support-pair overlaps, 1..=4096; never a top-k limit.
    pub maximum_witnesses: usize,
}

/// Failed operations expose no partially evaluated candidate graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssociationError {
    /// Malformed policy, detection IDs or source-frame declaration.
    InvalidInput,
    /// Stale property, source track, camera, clock or receipt.
    BasisMismatch,
    /// One of the active tracks already incorporates this camera exposure.
    ReusedExposure,
    /// A complete input/output or allocation limit was exceeded.
    Limit,
    /// Geometry failure, including cancellation and work exhaustion.
    Twin(TwinError),
}
impl From<TwinError> for AssociationError {
    fn from(error: TwinError) -> Self { Self::Twin(error) }
}
impl From<GeometryError> for AssociationError {
    fn from(error: GeometryError) -> Self { Self::Twin(error.into()) }
}
impl std::fmt::Display for AssociationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidInput => "invalid association input",
            Self::BasisMismatch => "association basis mismatch",
            Self::ReusedExposure => "association exposure already consumed",
            Self::Limit => "association limit exceeded",
            Self::Twin(_) => "association geometry operation failed",
        })
    }
}
impl std::error::Error for AssociationError {}

/// Why a geometrically unexcluded candidate cannot be narrowed by bounded motion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum UnresolvedAssociation {
    /// Latest observation did not establish usable source-pair motion.
    MotionUnavailable,
    /// Capture intervals do not establish an ordered forward prediction.
    CaptureOrder,
    /// Source motion is older than the explicit prediction horizon.
    Gap,
    /// Contact is hidden or the admitted mesh/search volume supplies no support.
    ContactUnavailable,
    /// At least one retained source or detection alternative has unknown bounds.
    UnknownBounds,
    /// A retained source mode conflicts with nominal modeled visibility.
    OcclusionConflict,
}

/// Orthogonal unresolved reasons; adding one never erases an earlier reason.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AssociationUncertainty(u8);
impl AssociationUncertainty {
    /// Whether a specific unresolved condition was encountered.
    pub fn contains(self, reason: UnresolvedAssociation) -> bool { self.0 & (1 << reason as u8) != 0 }
    /// Whether all evaluated alternatives had the needed conditional bounds.
    pub fn is_empty(self) -> bool { self.0 == 0 }
    fn insert(&mut self, reason: UnresolvedAssociation) { self.0 |= 1 << reason as u8; }
}

/// A detection's geometry, without exposing its temporary projection label as a track.
#[derive(Clone, Debug)]
pub struct DetectionProjection {
    detection: UnassignedContact,
    projection: ContactProjection,
}
impl DetectionProjection {
    /// Original unassigned source proposal.
    pub fn detection(&self) -> UnassignedContact { self.detection }
    /// Conditional bounds, nominal-only geometry, or unknown contact.
    pub fn quality(&self) -> ProjectionQuality { self.projection.quality() }
    /// Every support alternative, not only the nearest ray intersection.
    pub fn hypotheses(&self) -> &[ContactHypothesis] { self.projection.hypotheses() }
}

/// A conditional enclosure overlap, not independent corroboration or an identity proof.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct AssociationOverlap {
    /// Ordinal of the retained source motion mode.
    pub source_mode: usize,
    /// Revision-bound incoming support triangle.
    pub detection_triangle: u32,
    /// Common position region under the supplied error/acceleration assumptions.
    pub position: Bounds3,
}

/// One complete pair decision. Unknown alternatives are never converted to exclusions.
#[derive(Clone, Debug)]
pub struct AssociationPair {
    track: u64,
    detection: u64,
    overlaps: Vec<AssociationOverlap>,
    unresolved: AssociationUncertainty,
}
impl AssociationPair {
    /// Anonymous source track handle.
    pub fn track(&self) -> u64 { self.track }
    /// Incoming detection-local handle; it has not been assigned a track.
    pub fn detection(&self) -> u64 { self.detection }
    /// All bounded overlaps, preserving source-mode and incoming-surface identity.
    pub fn overlaps(&self) -> &[AssociationOverlap] { &self.overlaps }
    /// A retained unbounded/unobservable alternative, even when some overlaps exist.
    pub fn unresolved(&self) -> AssociationUncertainty { self.unresolved }
    /// False means excluded only within the declared finite geometry/motion model.
    /// It never supplies negative-evidence, identity, retention or effect authority.
    pub fn possible(&self) -> bool { !self.overlaps.is_empty() || !self.unresolved.is_empty() }
}

/// Source receipt and observations supporting one side of the candidate graph.
#[derive(Clone, Debug)]
pub struct AssociationSource {
    receipt: TrackReceipt,
    observations: Vec<ContactObservation>,
}
impl AssociationSource {
    /// Exact active epoch/revision, required again before consuming a decision.
    pub fn receipt(&self) -> TrackReceipt { self.receipt }
    /// Actual source observations: motion pair when present, otherwise latest source.
    pub fn observations(&self) -> &[ContactObservation] { &self.observations }
}

/// Complete graph from actual source observations, without a selected matching.
/// Private construction prevents manufacturing a successful partial graph.
pub struct AssociationGraph {
    twin_digest: [u8; 32],
    frame: AssociationFrame,
    options: AssociationOptions,
    sources: Vec<AssociationSource>,
    detections: Vec<DetectionProjection>,
    pairs: Vec<AssociationPair>,
}
impl std::fmt::Debug for AssociationGraph {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AssociationGraph").field("tracks", &self.sources.len())
            .field("detections", &self.detections.len()).finish_non_exhaustive()
    }
}
impl AssociationGraph {
    /// Exact original property import; process-local revision handles are insufficient.
    pub fn twin_digest(&self) -> [u8; 32] { self.twin_digest }
    /// Source exposure and admitted target camera snapshot.
    pub fn frame(&self) -> AssociationFrame { self.frame }
    /// Explicit conditional assumptions and search limits used by this graph.
    pub fn options(&self) -> AssociationOptions { self.options }
    /// Sources in anonymous track-ID order, including tracks with unavailable motion.
    pub fn sources(&self) -> &[AssociationSource] { &self.sources }
    /// Original proposals and their source-derived support alternatives, in ID order.
    pub fn detections(&self) -> &[DetectionProjection] { &self.detections }
    /// Full Cartesian table, ordered by (track ID, detection ID), including exclusions.
    pub fn pairs(&self) -> &[AssociationPair] { &self.pairs }

    /// Revalidate the exact active inputs, not just a matching track count.
    /// This checks source freshness, not identity adjudication or effect authority.
    pub fn check_current(&self, twin: &PropertyTwin, camera: TrackingCamera,
        tracks: &[TrackSnapshot<'_>], budget: &mut WorkBudget<'_>) -> Result<(), AssociationError> {
        budget.charge(0)?;
        if twin.digest() != self.twin_digest || twin.basis() != self.frame.camera.geometry
            || camera != self.frame.camera || tracks.len() != self.sources.len() {
            return Err(AssociationError::BasisMismatch);
        }
        validate_tracks(twin, self.frame, tracks, budget)?;
        for source in &self.sources {
            budget.charge(tracks.len() as u64)?;
            let current = tracks.iter().find(|s| s.receipt().scope.track == source.receipt.scope.track)
                .ok_or(AssociationError::BasisMismatch)?;
            if current.receipt() != source.receipt
                || current.projection().observation() != *source.observations.last()
                    .ok_or(AssociationError::BasisMismatch)? {
                return Err(AssociationError::BasisMismatch);
            }
        }
        budget.charge(0)?;
        Ok(())
    }
}

/// Project one exposure and retain every uncertainty-compatible target/detection pair.
///
/// No nearest-neighbor identity is selected. Unknown contact, motion, calibration
/// error or prediction support leaves candidate edges unresolved rather than absent.
/// This graph is conditional on the admitted mesh topology and finite search volume;
/// missing physical geometry and uncalibrated priors cannot be excluded by it.
pub fn gate_contact_batch(twin: &PropertyTwin, frame: AssociationFrame,
    tracks: &[TrackSnapshot<'_>], detections: &[UnassignedContact], options: AssociationOptions,
    budget: &mut WorkBudget<'_>) -> Result<AssociationGraph, AssociationError> {
    budget.charge(0)?;
    validate_input(twin, frame, detections, options, budget)?;
    validate_tracks(twin, frame, tracks, budget)?;
    for track in tracks {
        let latest = track.projection().observation();
        for detection in detections {
            budget.charge(3)?;
            if detection.evidence == latest.evidence
                || track.motion().is_some_and(|m| m.observations().iter().any(|o| o.evidence == detection.evidence)) {
                return Err(AssociationError::ReusedExposure);
            }
        }
    }
    let mut ordered = reserved(tracks.len())?;
    ordered.extend_from_slice(tracks);
    ordered.sort_by_key(|s| s.receipt().scope.track);
    let mut proposals = reserved(detections.len())?;
    proposals.extend_from_slice(detections);
    proposals.sort_by_key(|d| d.id);
    let mut projected = reserved(proposals.len())?;
    for detection in proposals {
        budget.charge(1)?;
        // project_contact requires a nonzero local label. It is not a track assignment;
        // this temporary label is never exposed through DetectionProjection's API.
        let observation = ContactObservation { evidence: detection.evidence, track: detection.id,
            camera: frame.camera.camera, exposure: frame.exposure, image_domain: frame.camera.image_domain,
            clock: frame.camera.clock, capture: frame.capture, pixel_min: detection.pixel_min,
            pixel_max: detection.pixel_max, visible_contact: detection.visible_contact };
        let projection = project_contact(twin, frame.camera, observation, options.projection, budget)?;
        projected.push(DetectionProjection { detection, projection });
    }
    let mut sources = reserved(ordered.len())?;
    let mut pairs = reserved(ordered.len() * projected.len())?;
    let mut witness_count = 0;
    for track in ordered {
        let latest = track.projection().observation();
        let mut observations = reserved(2)?;
        if let Some(motion) = track.motion() { observations.extend_from_slice(&motion.observations()); }
        else { observations.push(latest); }
        sources.push(AssociationSource { receipt: track.receipt(), observations });
        let unavailable = if frame.capture[0] < latest.capture[1] {
            Some(UnresolvedAssociation::CaptureOrder)
        } else if frame.capture[1] - latest.capture[0] > options.maximum_gap_ns {
            Some(UnresolvedAssociation::Gap)
        } else if track.motion().is_none() { Some(UnresolvedAssociation::MotionUnavailable) }
        else { None };
        let predicted = if unavailable.is_none() {
            Some(propagate_motion(track.motion().ok_or(AssociationError::InvalidInput)?,
                frame.capture, options.acceleration, budget)?)
        } else { None };
        for detection in &projected {
            budget.charge(1)?;
            let mut pair = AssociationPair { track: track.receipt().scope.track,
                detection: detection.detection.id, overlaps: Vec::new(), unresolved: AssociationUncertainty::default() };
            if let Some(reason) = unavailable { pair.unresolved.insert(reason); }
            if detection.quality() == ProjectionQuality::ContactUnknown || detection.hypotheses().is_empty() {
                pair.unresolved.insert(UnresolvedAssociation::ContactUnavailable);
            } else if let Some(predicted) = &predicted {
                let motion = track.motion().ok_or(AssociationError::InvalidInput)?;
                for prediction in predicted {
                    if motion.modes()[prediction.mode].nominal_occlusion_conflict {
                        pair.unresolved.insert(UnresolvedAssociation::OcclusionConflict);
                    }
                    for support in detection.hypotheses() {
                        budget.charge(16)?;
                        if support.nominal_occluded == Some(true) {
                            pair.unresolved.insert(UnresolvedAssociation::OcclusionConflict);
                        }
                        if let (Some(a), Some(b)) = (prediction.bounds, support.bounds) {
                            if let Some(position) = intersection(a, b)? {
                                if witness_count == options.maximum_witnesses { return Err(AssociationError::Limit); }
                                pair.overlaps.try_reserve(1).map_err(|_| AssociationError::Limit)?;
                                pair.overlaps.push(AssociationOverlap { source_mode: prediction.mode,
                                    detection_triangle: support.triangle, position });
                                witness_count += 1;
                            }
                        } else {
                            pair.unresolved.insert(UnresolvedAssociation::UnknownBounds);
                        }
                    }
                }
            }
            pairs.push(pair);
        }
    }
    budget.charge(0)?;
    Ok(AssociationGraph { twin_digest: twin.digest(), frame, options,
        sources, detections: projected, pairs })
}

fn intersection(a: Bounds3, b: Bounds3) -> Result<Option<Bounds3>, TwinError> {
    let mut result = a.0;
    for (axis, value) in result.iter_mut().enumerate() {
        let lo = a.0[axis].lower().max(b.0[axis].lower());
        let hi = a.0[axis].upper().min(b.0[axis].upper());
        if lo > hi { return Ok(None); }
        *value = Interval::new(lo, hi)?;
    }
    Ok(Some(Bounds3(result)))
}
fn reserved<T>(count: usize) -> Result<Vec<T>, AssociationError> {
    let mut result = Vec::new();
    result.try_reserve_exact(count).map_err(|_| AssociationError::Limit)?;
    Ok(result)
}
fn validate_input(twin: &PropertyTwin, frame: AssociationFrame, detections: &[UnassignedContact],
    options: AssociationOptions, budget: &mut WorkBudget<'_>) -> Result<(), AssociationError> {
    let c = frame.camera;
    let p = options.projection;
    if detections.len() > MAX_ASSOCIATION_ITEMS || options.maximum_witnesses == 0
        || options.maximum_witnesses > 4096 { return Err(AssociationError::Limit); }
    budget.charge(64 + (detections.len() * (detections.len() + 1)) as u64)?;
    if frame.exposure == 0 || frame.evidence == [0; 32] || frame.capture[0] > frame.capture[1]
        || c.geometry != twin.basis() || [c.camera, c.calibration, c.image_domain, c.clock].contains(&0)
        || c.validity[0] > c.validity[1] || frame.capture[0] < c.validity[0] || frame.capture[1] > c.validity[1] {
        return Err(AssociationError::BasisMismatch);
    }
    if options.maximum_gap_ns == 0 || options.maximum_gap_ns > 3_600_000_000_000
        || options.acceleration.iter().any(|x| !x.is_finite() || *x < 0.0 || *x > 1e6)
        || !p.near.is_finite() || !p.far.is_finite() || p.near <= 0.0 || p.far <= p.near
        || p.far > 1e9 || !(1..=128).contains(&p.max_hypotheses) {
        return Err(AssociationError::InvalidInput);
    }
    if let Some(e) = c.error {
        if e.centre.iter().chain(e.focal.iter()).chain(e.principal.iter())
            .any(|x| !x.is_finite() || *x < 0.0 || *x > 1e12)
            || !e.rotation_entry.is_finite() || !(0.0..=2.0).contains(&e.rotation_entry)
            || (0..2).any(|a| e.focal[a] >= c.intrinsics.focal_lengths()[a]) {
            return Err(AssociationError::InvalidInput);
        }
    }
    for (index, d) in detections.iter().enumerate() {
        if d.id == 0 || d.evidence == [0; 32] || !c.intrinsics.contains(d.pixel_min)
            || !c.intrinsics.contains(d.pixel_max) || (0..2).any(|a| d.pixel_min[a] > d.pixel_max[a])
            || detections[..index].iter().any(|prior| prior.id == d.id || prior.evidence == d.evidence) {
            return Err(AssociationError::InvalidInput);
        }
    }
    Ok(())
}
fn validate_tracks(twin: &PropertyTwin, frame: AssociationFrame, tracks: &[TrackSnapshot<'_>],
    budget: &mut WorkBudget<'_>) -> Result<(), AssociationError> {
    if tracks.len() > MAX_ASSOCIATION_ITEMS { return Err(AssociationError::Limit); }
    for (index, track) in tracks.iter().enumerate() {
        budget.charge(64 + index as u64)?;
        let receipt = track.receipt();
        let projection = track.projection();
        let latest = projection.observation();
        if receipt.scope.clock != frame.camera.clock || projection.twin_digest() != twin.digest()
            || projection.camera().geometry != twin.basis()
            || tracks[..index].iter().any(|s| s.receipt().scope.track == receipt.scope.track)
            || !track.cameras().contains(&frame.camera) {
            return Err(AssociationError::BasisMismatch);
        }
        if latest.camera == frame.camera.camera && latest.exposure == frame.exposure {
            return Err(AssociationError::ReusedExposure);
        }
    }
    budget.charge(0)?;
    Ok(())
}

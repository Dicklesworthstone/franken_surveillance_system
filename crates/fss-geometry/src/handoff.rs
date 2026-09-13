//! Visibility-aware, nominal sampled camera handoffs over retained motion routes.
//!
//! This reference computes first *modeled eligible samples*, not guaranteed first
//! physical visibility or detector success. Pose, clock, route, body and optical
//! assumptions belong to the caller. Results cannot certify an observed absence.

use crate::math::{add, checked, norm, sub};
use crate::{ForecastBasis, GeometryBasis, GeometryError, MotionForecast, MotionHypothesis,
    PinholeIntrinsics, RigidPose, TriangleMesh, WorkBudget};

/// Maximum authorized camera candidates in one request.
pub const MAX_HANDOFF_CAMERAS: usize = 64;
/// Maximum explicit body/posture probe points per route.
pub const MAX_BODY_SAMPLES: usize = 64;

/// Closed interval in a declared nanosecond clock or duration domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NanosecondInterval { earliest: u64, latest: u64 }
impl NanosecondInterval {
    /// Reject reversed intervals; exact instants are allowed.
    pub fn new(earliest: u64, latest: u64) -> Result<Self, GeometryError> {
        if earliest > latest { return Err(GeometryError::OutOfRange); }
        Ok(Self { earliest, latest })
    }
    /// Earliest included time or delay.
    pub fn earliest(self) -> u64 { self.earliest }
    /// Latest included time or delay.
    pub fn latest(self) -> u64 { self.latest }
    fn contains(self, time: u64) -> bool { self.earliest <= time && time <= self.latest }
    fn shifted(self, time: u64) -> Result<Self, GeometryError> {
        Self::new(time.checked_add(self.earliest).ok_or(GeometryError::OutOfRange)?,
            time.checked_add(self.latest).ok_or(GeometryError::OutOfRange)?)
    }
}

/// Periodic nominal capture schedule in the common forecast clock epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureSchedule { period_ns: u64, phase_ns: u64 }
impl CaptureSchedule {
    /// `phase_ns` is a residue in 0..period, not a first observation timestamp.
    pub fn new(period_ns: u64, phase_ns: u64) -> Result<Self, GeometryError> {
        if period_ns == 0 || phase_ns >= period_ns { return Err(GeometryError::OutOfRange); }
        Ok(Self { period_ns, phase_ns })
    }
    /// Capture period in nanoseconds, not a rounded nominal FPS label.
    pub fn period_ns(self) -> u64 { self.period_ns }
    /// Capture phase relative to the origin of the bound clock epoch.
    pub fn phase_ns(self) -> u64 { self.phase_ns }
    /// First representable sample at or after `time`; never wraps integer time.
    pub fn first_at_or_after(self, time: u64) -> Option<u64> {
        let remainder = time % self.period_ns;
        let wait = if remainder <= self.phase_ns { self.phase_ns - remainder }
            else { self.period_ns - (remainder - self.phase_ns) };
        time.checked_add(wait)
    }
}

/// Rectangle in normalized, undistorted pixel-edge image coordinates.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ImageRect { min: [f64; 2], max: [f64; 2] }
impl ImageRect {
    /// Validate nonempty area within the image; edges can equal zero or one.
    pub fn new(min: [f64; 2], max: [f64; 2]) -> Result<Self, GeometryError> {
        for axis in 0..2 {
            if !min[axis].is_finite() || !max[axis].is_finite()
                || min[axis] < 0.0 || max[axis] > 1.0 || min[axis] >= max[axis] {
                return Err(GeometryError::OutOfRange);
            }
        }
        Ok(Self { min, max })
    }
    /// Inclusive lower normalized corner.
    pub fn min(self) -> [f64; 2] { self.min }
    /// Upper normalized corner, not a pixel index.
    pub fn max(self) -> [f64; 2] { self.max }
    fn overlaps(self, other: Self) -> bool {
        self.min[0] <= other.max[0] && other.min[0] <= self.max[0]
            && self.min[1] <= other.max[1] && other.min[1] <= self.max[1]
    }
}

/// Explicit body/posture samples as offsets from a route's tracked point.
///
/// Offsets are in fixed property axes. They do not rotate automatically at turns.
/// Samples approximate an object; they are not a volumetric visibility proof.
#[derive(Clone, PartialEq)]
pub struct BodySamples { generation: u64, offsets: Vec<[f64; 3]> }
impl std::fmt::Debug for BodySamples {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BodySamples").field("generation", &self.generation)
            .field("sample_count", &self.offsets.len()).finish_non_exhaustive()
    }
}
impl BodySamples {
    /// Require 2..=64 distinct finite points; duplicates cannot inflate visibility.
    pub fn new(generation: u64, offsets: &[[f64; 3]], budget: &mut WorkBudget<'_>)
        -> Result<Self, GeometryError> {
        budget.charge(0)?;
        if generation == 0 { return Err(GeometryError::BasisMismatch); }
        if !(2..=MAX_BODY_SAMPLES).contains(&offsets.len()) { return Err(GeometryError::LimitExceeded); }
        for (index, offset) in offsets.iter().enumerate() {
            budget.charge(1 + index as u64)?;
            checked(*offset)?;
            if offsets[..index].iter().any(|prior| norm(sub(*offset, *prior)) <= 1e-12) {
                return Err(GeometryError::Degenerate);
            }
        }
        let mut owned = reserve(offsets.len())?;
        owned.extend_from_slice(offsets);
        budget.charge(0)?;
        Ok(Self { generation, offsets: owned })
    }
    /// Exact caller-owned body/posture generation.
    pub fn generation(&self) -> u64 { self.generation }
    /// Number of distinct supplied samples.
    pub fn sample_count(&self) -> usize { self.offsets.len() }
}

/// Caller-declared availability over the requested horizon, never inferred from silence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CameraAvailability {
    /// Use the supplied model only inside its validity interval.
    Ready,
    /// Known unavailable throughout this forecast's scope.
    Unavailable,
    /// Availability, calibration, or operating-envelope support is unresolved.
    Unknown,
}

/// One already authorized camera view. This is a model input, not a capability.
#[derive(Clone, Copy)]
pub struct HandoffCamera<'a> {
    /// Nonzero physical camera handle, unique within the authorized candidate set.
    pub id: u64,
    /// Exact property and geometry revision to which its pose is registered.
    pub geometry: GeometryBasis,
    /// Common capture-clock epoch, identical to the motion forecast's epoch.
    pub clock: u64,
    /// Owner-resolved snapshot binding calibration, health, privacy, and sampling policy.
    pub observation_generation: u64,
    /// Exact image mode used by the intrinsics and returned image coordinates.
    pub image_mode: u64,
    /// Calibrated world-to-camera transform.
    pub pose: RigidPose,
    /// Already undistorted camera model; raw fisheye/dewarped images are inadmissible.
    pub intrinsics: PinholeIntrinsics,
    /// Known availability or an explicit unknown.
    pub availability: CameraAvailability,
    /// Exclude this camera from next-new-camera outcomes without inventing a reacquisition.
    pub already_observing: bool,
    /// Closed time interval for this exact snapshot's assumptions.
    pub valid: NanosecondInterval,
    /// Nominal capture sampling; event-triggered wake with unknown time is `Unknown`.
    pub schedule: CaptureSchedule,
    /// Capture-to-system-availability delay, not a shift in geometric capture time.
    pub latency: NanosecondInterval,
    /// Fail closed when a candidate region intersects any privacy exclusion.
    pub privacy_masks: &'a [ImageRect],
    /// Required visible sample fraction in thousandths, in 1..=1000.
    pub visible_per_mille: u16,
    /// Minimum sample-bounding-region width and height in this image's pixels.
    pub minimum_extent_px: [f64; 2],
}
impl std::fmt::Debug for HandoffCamera<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandoffCamera").field("id", &self.id)
            .field("availability", &self.availability).finish_non_exhaustive()
    }
}

/// Associate a body hypothesis explicitly with a route; no person-shaped default.
#[derive(Clone, Copy, Debug)]
pub struct RouteBody<'a> {
    /// Exact retained motion route ID.
    pub route: u64,
    /// Supplied posture/size approximation appropriate to this alternative.
    pub body: &'a BodySamples,
}

/// Hard reference-kernel limits and explicitly chosen numerical self-hit margin.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct HandoffOptions {
    /// Scalar frame evaluations per route/camera; ceiling one million.
    pub max_samples_per_camera: u32,
    /// Self-intersection exclusion in property units, additionally bounded per ray.
    pub endpoint_margin: f64,
}

/// Conditional observation proposal, not a detected target or a coverage witness.
#[derive(Clone, Debug, PartialEq)]
pub struct PredictedObservation {
    /// Authorized physical camera handle.
    pub camera: u64,
    /// Snapshot binding health, privacy, calibration, and sampling assumptions.
    pub observation_generation: u64,
    /// Image domain in which the region is expressed.
    pub image_mode: u64,
    /// Nominal capture instant under this trajectory and sampling model.
    pub nominal_capture_ns: u64,
    /// Predicted availability interval after explicitly supplied processing/transport delay.
    pub availability_ns: NanosecondInterval,
    /// Encloses visible probe points, not a certified silhouette or probability region.
    pub region: ImageRect,
    /// Count of probe points with clear modeled optical segments.
    pub visible_samples: usize,
    /// Total probe count, retained so sampling approximation remains visible.
    pub body_samples: usize,
}

/// First nominal eligible capture among cameras not already observing this track.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NextCameraOutcome {
    /// Equal capture times retain the complete simultaneous set, in camera-ID order.
    Predicted {
        /// Nominal capture time, not whichever pipeline happens to respond first.
        nominal_capture_ns: u64,
        /// Complete simultaneous set under the fixed model.
        cameras: Vec<u64>,
    },
    /// No eligible sample in this model, horizon, and candidate set; NOT observed absence.
    NoModeledObservation,
    /// Unknown camera support or unmodeled motion prevents a complete first-event claim.
    Indeterminate,
}

/// Complete retained result for one motion/body alternative.
#[derive(Clone, Debug, PartialEq)]
pub struct RouteHandoff {
    /// Source route ID.
    pub route: u64,
    /// Unchanged heuristic route mass; never renormalized after a missing observation.
    pub mass: u64,
    /// Protected alternative flag, retained regardless of outcome.
    pub protected: bool,
    /// Exact supplied body/posture generation.
    pub body_generation: u64,
    /// First eligible sample per modeled camera, sorted by capture time then camera ID.
    pub observations: Vec<PredictedObservation>,
    /// Cameras whose unknown or insufficiently valid model could change the answer.
    pub unresolved_cameras: Vec<u64>,
    /// Whether this trajectory ends before the requested horizon.
    pub unmodeled_tail: bool,
    /// First-event classification; partial observations survive an indeterminate answer.
    pub next: NextCameraOutcome,
}

/// Candidate scope retained even when some cameras were excluded from prediction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandoffCameraScope {
    /// Authorized camera handle.
    pub camera: u64,
    /// Owner-resolved camera snapshot identity.
    pub observation_generation: u64,
    /// Qualified image-domain identity.
    pub image_mode: u64,
    /// Why the camera was or was not eligible for evaluation.
    pub availability: CameraAvailability,
    /// Whether excluded as an already-observing camera.
    pub already_observing: bool,
}

/// Atomic, bounded model prediction over all supplied route alternatives.
#[derive(Clone, Debug, PartialEq)]
pub struct CameraHandoffForecast {
    /// Exact input basis, required again on evaluation to detect a stale caller.
    pub basis: ForecastBasis,
    /// Nominal forecast origin in the bound capture-clock epoch.
    pub reference_ns: u64,
    /// Evaluated horizon; physical uncertainty is not implied by decimal precision.
    pub horizon_ns: u64,
    /// Full route mass, including unknown and no-observation alternatives.
    pub total_mass: u64,
    /// The complete already-authorized input camera set, in ID order.
    pub camera_scope: Vec<HandoffCameraScope>,
    /// Every retained motion hypothesis, in route-ID order.
    pub routes: Vec<RouteHandoff>,
}

/// Predict camera handoffs by evaluating real mesh occlusion at scheduled capture times.
///
/// The event is nominal sample eligibility, not true detection. Unknown camera
/// support cannot become a negative observation. A route not modeled to the end
/// can still establish a first event before that unknown tail; otherwise it remains
/// indeterminate. Latency never changes which camera captures first. All geometry,
/// routes, image domains, body samples, and schedules must be owner-resolved and
/// already capability/privacy scoped. Numeric errors/cancellation/pressure publish
/// no partial result. Calibration/clock uncertainty needs explicit additional
/// scenarios or a later uncertainty-aware solver, not invented confidence bounds.
pub fn predict_camera_handoffs(expected_basis: ForecastBasis, motion: &MotionForecast,
    mesh: &TriangleMesh, cameras: &[HandoffCamera<'_>], bodies: &[RouteBody<'_>],
    options: HandoffOptions, budget: &mut WorkBudget<'_>)
    -> Result<CameraHandoffForecast, GeometryError> {
    budget.charge(0)?;
    if expected_basis != motion.basis() || mesh.basis() != expected_basis.geometry() {
        return Err(GeometryError::BasisMismatch);
    }
    if cameras.is_empty() { return Err(GeometryError::EmptyInput); }
    if cameras.len() > MAX_HANDOFF_CAMERAS || bodies.len() != motion.hypotheses().len()
        || options.max_samples_per_camera == 0 || options.max_samples_per_camera > 1_000_000 {
        return Err(GeometryError::LimitExceeded);
    }
    if !options.endpoint_margin.is_finite() || options.endpoint_margin < 0.0
        || options.endpoint_margin > 1e6 { return Err(GeometryError::OutOfRange); }
    let end = motion.reference_ns().checked_add(motion.horizon_ns()).ok_or(GeometryError::OutOfRange)?;
    let mut ordered = reserve(cameras.len())?;
    for (index, camera) in cameras.iter().enumerate() {
        budget.charge(1 + index as u64)?;
        if camera.id == 0 || cameras[..index].iter().any(|prior| prior.id == camera.id) {
            return Err(GeometryError::InvalidIndex);
        }
        if camera.geometry != expected_basis.geometry() || camera.clock != expected_basis.clock()
            || camera.observation_generation == 0 || camera.image_mode == 0 {
            return Err(GeometryError::BasisMismatch);
        }
        if camera.privacy_masks.len() > 64 { return Err(GeometryError::LimitExceeded); }
        if !(1..=1000).contains(&camera.visible_per_mille)
            || camera.minimum_extent_px.iter().any(|x| !x.is_finite() || *x <= 0.0 || *x > 65536.0) {
            return Err(GeometryError::OutOfRange);
        }
        // Do not discover a timestamp overflow only after a seemingly useful prefix.
        camera.latency.shifted(end)?;
        ordered.push(camera);
    }
    for (index, binding) in bodies.iter().enumerate() {
        budget.charge(1 + index as u64 + motion.hypotheses().len() as u64)?;
        if bodies[..index].iter().any(|prior| prior.route == binding.route)
            || !motion.hypotheses().iter().any(|route| route.id() == binding.route) {
            return Err(GeometryError::InvalidIndex);
        }
    }
    budget.charge((ordered.len() as u64) * 6)?;
    ordered.sort_by_key(|camera| camera.id);
    let mut camera_scope = reserve(ordered.len())?;
    for camera in &ordered {
        camera_scope.push(HandoffCameraScope { camera: camera.id,
            observation_generation: camera.observation_generation, image_mode: camera.image_mode,
            availability: camera.availability, already_observing: camera.already_observing });
    }
    let mut routes = reserve(motion.hypotheses().len())?;
    for path in motion.hypotheses() {
        budget.charge(1 + bodies.len() as u64)?;
        let body = bodies.iter().find(|binding| binding.route == path.id())
            .ok_or(GeometryError::InvalidIndex)?.body;
        let mut observations = reserve(ordered.len())?;
        let mut unresolved = reserve(ordered.len())?;
        for camera in &ordered {
            budget.charge(1)?;
            if camera.already_observing || camera.availability == CameraAvailability::Unavailable { continue; }
            if camera.availability == CameraAvailability::Unknown {
                unresolved.push(camera.id);
                continue;
            }
            if !camera.valid.contains(motion.reference_ns()) || !camera.valid.contains(end) {
                unresolved.push(camera.id);
            }
            if let Some(observation) = first_sample(motion, path, mesh, camera, body, options, budget)? {
                observations.push(observation);
            }
        }
        budget.charge((observations.len() as u64) * 6)?;
        observations.sort_by_key(|hit| (hit.nominal_capture_ns, hit.camera));
        let unmodeled_tail = path.modeled_until_ns() < motion.horizon_ns();
        let next = if !unresolved.is_empty() || (unmodeled_tail && observations.is_empty()) {
            NextCameraOutcome::Indeterminate
        } else if let Some(first) = observations.first() {
            let time = first.nominal_capture_ns;
            let mut simultaneous = reserve(observations.len())?;
            for observation in &observations {
                budget.charge(1)?;
                if observation.nominal_capture_ns != time { break; }
                simultaneous.push(observation.camera);
            }
            NextCameraOutcome::Predicted { nominal_capture_ns: time, cameras: simultaneous }
        } else { NextCameraOutcome::NoModeledObservation };
        routes.push(RouteHandoff { route: path.id(), mass: path.mass(), protected: path.protected(),
            body_generation: body.generation(), observations, unresolved_cameras: unresolved,
            unmodeled_tail, next });
    }
    budget.charge(0)?;
    Ok(CameraHandoffForecast { basis: expected_basis, reference_ns: motion.reference_ns(),
        horizon_ns: motion.horizon_ns(), total_mass: motion.total_mass(), camera_scope, routes })
}

fn first_sample(motion: &MotionForecast, path: &MotionHypothesis, mesh: &TriangleMesh,
    camera: &HandoffCamera<'_>, body: &BodySamples, options: HandoffOptions,
    budget: &mut WorkBudget<'_>) -> Result<Option<PredictedObservation>, GeometryError> {
    let start = motion.reference_ns().max(camera.valid.earliest());
    let end = motion.reference_ns().checked_add(path.modeled_until_ns())
        .ok_or(GeometryError::OutOfRange)?.min(camera.valid.latest());
    let mut sample = camera.schedule.first_at_or_after(start);
    let mut samples = 0_u32;
    while let Some(time) = sample {
        budget.charge(1)?;
        if time > end { break; }
        if samples == options.max_samples_per_camera { return Err(GeometryError::LimitExceeded); }
        samples += 1;
        let position = path.position_at(time - motion.reference_ns(), budget)?
            .ok_or(GeometryError::OutOfRange)?;
        if let Some((region, visible)) = eligible_region(mesh, camera, body, position, options, budget)? {
            return Ok(Some(PredictedObservation { camera: camera.id,
                observation_generation: camera.observation_generation, image_mode: camera.image_mode,
                nominal_capture_ns: time, availability_ns: camera.latency.shifted(time)?,
                region, visible_samples: visible, body_samples: body.sample_count() }));
        }
        sample = time.checked_add(camera.schedule.period_ns());
    }
    Ok(None)
}

fn eligible_region(mesh: &TriangleMesh, camera: &HandoffCamera<'_>, body: &BodySamples,
    position: [f64; 3], options: HandoffOptions, budget: &mut WorkBudget<'_>)
    -> Result<Option<(ImageRect, usize)>, GeometryError> {
    let [width, height] = camera.intrinsics.dimensions();
    let dimensions = [f64::from(width), f64::from(height)];
    let mut min = [1.0_f64; 2];
    let mut max = [0.0_f64; 2];
    let mut points = [[0.0; 3]; MAX_BODY_SAMPLES];
    let mut pixels = [[0.0; 2]; MAX_BODY_SAMPLES];
    let mut projected = 0;
    for offset in &body.offsets {
        budget.charge(1)?;
        let point = checked(add(position, *offset))?;
        let pixel = match camera.pose.project(camera.intrinsics, point) {
            Ok(pixel) => pixel,
            Err(GeometryError::BehindCamera) => continue,
            Err(error) => return Err(error),
        };
        if !camera.intrinsics.contains(pixel) { continue; }
        points[projected] = point;
        pixels[projected] = pixel;
        projected += 1;
        for axis in 0..2 {
            min[axis] = min[axis].min(pixel[axis] / dimensions[axis]);
            max[axis] = max[axis].max(pixel[axis] / dimensions[axis]);
        }
    }
    if projected * 1000 < body.sample_count() * usize::from(camera.visible_per_mille)
        || min[0] >= max[0] || min[1] >= max[1] { return Ok(None); }
    // Privacy rejection precedes mesh expansion. This coarse bound intentionally
    // includes projected samples that might later turn out to be occluded.
    let projected_region = ImageRect::new(min, max)?;
    for mask in camera.privacy_masks {
        budget.charge(1)?;
        if projected_region.overlaps(*mask) { return Ok(None); }
    }
    min = [1.0; 2];
    max = [0.0; 2];
    let mut visible = 0;
    for index in 0..projected {
        budget.charge(1)?;
        let point = points[index];
        let distance = norm(sub(point, camera.pose.center()));
        if distance <= 1e-9 || options.endpoint_margin > distance * 1e-3 {
            return Err(GeometryError::Degenerate);
        }
        if mesh.segment_occluded(camera.geometry, camera.pose.center(), point,
            options.endpoint_margin, budget)? { continue; }
        visible += 1;
        for axis in 0..2 {
            min[axis] = min[axis].min(pixels[index][axis] / dimensions[axis]);
            max[axis] = max[axis].max(pixels[index][axis] / dimensions[axis]);
        }
    }
    if visible * 1000 < body.sample_count() * usize::from(camera.visible_per_mille)
        || (max[0] - min[0]) * dimensions[0] < camera.minimum_extent_px[0]
        || (max[1] - min[1]) * dimensions[1] < camera.minimum_extent_px[1] {
        return Ok(None);
    }
    let region = ImageRect::new(min, max)?;
    Ok(Some((region, visible)))
}

fn reserve<T>(count: usize) -> Result<Vec<T>, GeometryError> {
    let mut result = Vec::new();
    result.try_reserve_exact(count).map_err(|_| GeometryError::LimitExceeded)?;
    Ok(result)
}

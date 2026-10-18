#![forbid(unsafe_code)]
//! Source-linked reconstruction of one moving feature across staggered camera feeds.
//!
//! The upstream correspondence is an explicit hypothesis. This module estimates
//! position and constant velocity together, without assuming that frames arrived
//! simultaneously or that a ground plane supplies depth. It retains complete
//! capture intervals, source membership, calibration bounds and mesh conflicts.
//! The result is conditional on nominal interval midpoints and fixed camera
//! snapshots. Pixel-noise covariance is not a total physical-uncertainty bound.

use crate::multiview::FusionInput;
use crate::{PropertyTwin, ScaleEvidence, TwinError};
use fss_geometry::temporal_triangulation::{
    MAX_TEMPORAL_SPAN_NS, MAX_TEMPORAL_VIEWS, TemporalTriangulationError,
    TemporalTriangulationOptions, TimedCalibratedView, TriangulatedMotion, triangulate_motion,
};
use fss_geometry::triangulation::CalibratedView;
use fss_geometry::{GeometryBasis, GeometryError, WorkBudget};

/// Explicit source association, common scene time and conditional fitting policy.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MotionFusionRequest {
    /// Nonzero upstream common-feature hypothesis; not a permanent person identity.
    pub association_evidence: [u8; 32],
    /// Nonzero owner-resolved privacy namespace shared by all inputs; not a grant.
    pub privacy_domain: u64,
    /// Return position and its covariance at this shared scene-clock instant.
    /// It must lie within the nominal fitting interval; extrapolation is refused.
    pub reference_time_ns: u64,
    /// Bound on the complete capture-time hull, in 1..=60 seconds.
    pub max_capture_span_ns: u64,
    /// Maximum width of any input capture interval, no greater than the hull bound.
    /// Zero admits exact capture times only. This is an admission tolerance, not
    /// evidence that timestamp error is independent or included in covariance.
    pub max_capture_uncertainty_ns: u64,
    /// Reprojection, speed, distance, conditioning and bounded-iteration limits.
    pub triangulation: TemporalTriangulationOptions,
}

/// A nominal line-of-sight diagnostic for one retained camera exposure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MotionFusionVisibility {
    /// Logical camera; repeated rows are distinct exposures, not independent sensors.
    pub camera: u64,
    /// Exact source exposure within that camera.
    pub exposure: u64,
    /// Original observation evidence, including for a conflicting view.
    pub evidence: [u8; 32],
    /// Complete original inclusive capture-time interval.
    pub capture: [u64; 2],
    /// Integer interval midpoint used by the nominal fit, rounded toward the start.
    pub nominal_capture_time_ns: u64,
    /// None means the modeled point is outside the camera's image/range domain.
    /// False is only a clear nominal segment in this exact imported mesh; it is
    /// not a physical visibility or absence certificate.
    pub nominal_occluded: Option<bool>,
}

/// Immutable source-bearing conditional trajectory in the imported property frame.
#[derive(Clone, Debug)]
pub struct FusedSceneMotion {
    request: MotionFusionRequest,
    inputs: Vec<FusionInput>,
    estimate: TriangulatedMotion,
    visibility: Vec<MotionFusionVisibility>,
    capture_hull: [u64; 2],
    clock: u64,
    geometry: GeometryBasis,
    twin_digest: [u8; 32],
    source_scene_digest: [u8; 32],
    map_error: Option<f64>,
    scale: ScaleEvidence,
}

impl FusedSceneMotion {
    /// Original association, common reference time and admitted model/timing limits.
    pub fn request(&self) -> MotionFusionRequest {
        self.request
    }
    /// Complete inputs in canonical camera/nominal-time/exposure order.
    /// Rectangles and calibration bounds are retained without Gaussian conversion.
    pub fn inputs(&self) -> &[FusionInput] {
        &self.inputs
    }
    /// Position, estimated velocity and full conditional 6x6 pixel-noise covariance.
    /// Both position and covariance have been propagated to the requested scene
    /// time. Clock, camera, correspondence, acceleration, rectangle and shared-mode
    /// uncertainties are not included in that covariance.
    pub fn estimate(&self) -> &TriangulatedMotion {
        &self.estimate
    }
    /// One diagnostic for every source exposure, in the same order as `inputs`.
    pub fn visibility(&self) -> &[MotionFusionVisibility] {
        &self.visibility
    }
    /// Earliest through latest possible capture time, never interval intersection.
    pub fn capture_hull(&self) -> [u64; 2] {
        self.capture_hull
    }
    /// Exact shared capture-clock generation, never packet-arrival time.
    pub fn clock(&self) -> u64 {
        self.clock
    }
    /// Owner-resolved property and mesh generation.
    pub fn geometry(&self) -> GeometryBasis {
        self.geometry
    }
    /// Exact imported package identity for replay and invalidation.
    pub fn twin_digest(&self) -> [u8; 32] {
        self.twin_digest
    }
    /// Exact authoring/import source scene identity retained by that package.
    pub fn source_scene_digest(&self) -> [u8; 32] {
        self.source_scene_digest
    }
    /// Original scale declaration; source units have not been silently rescaled.
    pub fn scale(&self) -> ScaleEvidence {
        self.scale
    }
    /// Declared map error, separately retained and never inserted into pixel covariance.
    pub fn map_error(&self) -> Option<f64> {
        self.map_error
    }
    /// Any fitting exposure sees its nominal point through an opaque scene surface.
    /// A perfect reprojection fit cannot erase this scene/source disagreement.
    pub fn has_nominal_occlusion_conflict(&self) -> bool {
        self.visibility
            .iter()
            .any(|row| row.nominal_occluded == Some(true))
    }
}

/// Explicit refusal; no partially fitted or source-detached scene point is returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MotionFusionError {
    /// Twin, allocation, numeric, work or cancellation failure.
    Twin(TwinError),
    /// Insufficient or degenerate geometry, incompatible motion, or bounded fit failure.
    Triangulation(TemporalTriangulationError),
    /// Property, camera mode, clock or calibration validity is incompatible.
    /// One fixed snapshot per logical camera is required throughout this fit.
    Basis,
    /// Source identity, contact rectangle or declared pixel/calibration error is invalid.
    Observation,
    /// The same evidence record was offered more than once.
    DuplicateEvidence,
    /// The same camera exposure was offered more than once under different evidence IDs.
    DuplicateExposure,
    /// Inputs do not share the requested owner-resolved privacy namespace.
    PrivacyDomain,
    /// Invalid/excessive capture hull or interval uncertainty, or reference extrapolation.
    CaptureWindow,
    /// A common visible feature was not supplied; box bottoms cannot invent one.
    ContactUnknown,
}

impl From<TwinError> for MotionFusionError {
    fn from(error: TwinError) -> Self {
        Self::Twin(error)
    }
}
impl From<GeometryError> for MotionFusionError {
    fn from(error: GeometryError) -> Self {
        Self::Twin(TwinError::Geometry(error))
    }
}
impl From<TemporalTriangulationError> for MotionFusionError {
    fn from(error: TemporalTriangulationError) -> Self {
        Self::Triangulation(error)
    }
}
impl std::fmt::Display for MotionFusionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Twin(_) => "scene motion twin or work failure",
            Self::Triangulation(_) => "scene motion geometric fit refused",
            Self::Basis => "incompatible scene motion basis or camera snapshot",
            Self::Observation => "invalid scene motion observation",
            Self::DuplicateEvidence => "duplicate scene motion source evidence",
            Self::DuplicateExposure => "duplicate scene motion camera exposure",
            Self::PrivacyDomain => "incompatible scene motion privacy domain",
            Self::CaptureWindow => "inadmissible scene motion capture window",
            Self::ContactUnknown => "scene motion common feature is not visible",
        })
    }
}
impl std::error::Error for MotionFusionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Twin(error) => Some(error),
            Self::Triangulation(error) => Some(error),
            _ => None,
        }
    }
}

/// Reconstruct one already-associated moving feature from staggered camera frames.
///
/// Unlike point fusion with a supplied velocity, this solves position and velocity
/// jointly from at least four observations and two cameras. A bounded weighted
/// bearing fit and pixel-space refinement keep every observation; a contradictory
/// input is never silently removed to make the trajectory fit. Complete intervals
/// gate admission, while their explicitly nominal integer midpoints feed the fit.
/// Repeated camera exposures share their original calibration/failure domain.
///
/// The final state and all position/velocity cross-covariances are propagated to
/// the requested common scene time. Mesh visibility is checked at each exposure's
/// own modeled time, not by projecting that reference-time position into every feed.
/// Work is O(N^2 + N I B + N T), with N <= 128, I <= 32, B <= 8 and T imported
/// triangles. Scratch is O(N). Every phase uses the caller's single work budget.
pub fn fuse_scene_motion(
    twin: &PropertyTwin,
    inputs: &[FusionInput],
    request: MotionFusionRequest,
    budget: &mut WorkBudget<'_>,
) -> Result<FusedSceneMotion, MotionFusionError> {
    budget.charge(0)?;
    if inputs.len() > MAX_TEMPORAL_VIEWS {
        return Err(TwinError::Limit.into());
    }
    if inputs.len() < 4 {
        return Err(TemporalTriangulationError::InsufficientObservations.into());
    }
    if request.association_evidence == [0; 32] {
        return Err(MotionFusionError::Observation);
    }
    if request.privacy_domain == 0 {
        return Err(MotionFusionError::PrivacyDomain);
    }
    if request.max_capture_span_ns == 0
        || i128::from(request.max_capture_span_ns) > MAX_TEMPORAL_SPAN_NS
        || request.max_capture_uncertainty_ns > request.max_capture_span_ns
    {
        return Err(MotionFusionError::CaptureWindow);
    }
    budget.charge(256 * inputs.len() as u64)?;
    let mut ordered = reserved(inputs.len())?;
    ordered.extend_from_slice(inputs);
    // Validate before computing interval midpoints or ordering derived from them.
    let clock = inputs[0].camera.clock;
    let mut capture_hull = [u64::MAX, 0];
    for input in &ordered {
        budget.charge(64)?;
        validate_input(twin, *input, request, clock)?;
        capture_hull[0] = capture_hull[0].min(input.observation.capture[0]);
        capture_hull[1] = capture_hull[1].max(input.observation.capture[1]);
    }
    if capture_hull[1] - capture_hull[0] > request.max_capture_span_ns
        || !(capture_hull[0]..=capture_hull[1]).contains(&request.reference_time_ns)
    {
        return Err(MotionFusionError::CaptureWindow);
    }
    ordered.sort_by_key(|input| {
        (
            input.camera.camera,
            midpoint(input.observation.capture),
            input.observation.exposure,
        )
    });
    let mut views = reserved(ordered.len())?;
    for (index, input) in ordered.iter().enumerate() {
        for previous in &ordered[..index] {
            budget.charge(8)?;
            if previous.observation.evidence == input.observation.evidence {
                return Err(MotionFusionError::DuplicateEvidence);
            }
            if previous.camera.camera == input.camera.camera {
                if previous.observation.exposure == input.observation.exposure {
                    return Err(MotionFusionError::DuplicateExposure);
                }
                if previous.camera != input.camera {
                    return Err(MotionFusionError::Basis);
                }
            }
        }
        budget.charge(64)?;
        views.push(TimedCalibratedView {
            view: CalibratedView {
                camera: input.camera.camera,
                pose: input.camera.pose,
                intrinsics: input.camera.intrinsics,
                pixel: std::array::from_fn(|axis| {
                    input.observation.pixel_min[axis] * 0.5
                        + input.observation.pixel_max[axis] * 0.5
                }),
                sigma_pixels: input.sigma_pixels,
            },
            capture_time_ns: i128::from(midpoint(input.observation.capture)),
        });
    }
    let mut estimate = triangulate_motion(&views, request.triangulation, budget)?;
    if !(estimate.observed_time_range_ns[0]..=estimate.observed_time_range_ns[1])
        .contains(&i128::from(request.reference_time_ns))
    {
        return Err(MotionFusionError::CaptureWindow);
    }
    rebase(&mut estimate, request.reference_time_ns, budget)?;
    let mut visibility = reserved(ordered.len())?;
    for input in &ordered {
        budget.charge(256)?;
        let nominal_capture_time_ns = midpoint(input.observation.capture);
        let offset = i128::from(nominal_capture_time_ns) - estimate.reference_time_ns;
        let point = std::array::from_fn(|axis| {
            estimate.position[axis] + estimate.velocity_per_second[axis] * offset as f64 * 1e-9
        });
        let camera = input.camera;
        let center = camera.pose.center();
        let distance = (point[0] - center[0])
            .hypot(point[1] - center[1])
            .hypot(point[2] - center[2]);
        let camera_point = camera.pose.transform(point)?;
        let in_image = if camera_point[2] > 1e-9 {
            camera
                .intrinsics
                .contains(camera.intrinsics.project(camera_point)?)
        } else {
            false
        };
        let nominal_occluded = if in_image && distance <= request.triangulation.max_distance {
            Some(twin.mesh().segment_occluded(
                twin.basis(),
                center,
                point,
                distance * 1e-8,
                budget,
            )?)
        } else {
            None
        };
        visibility.push(MotionFusionVisibility {
            camera: camera.camera,
            exposure: input.observation.exposure,
            evidence: input.observation.evidence,
            capture: input.observation.capture,
            nominal_capture_time_ns,
            nominal_occluded,
        });
    }
    budget.charge(0)?;
    Ok(FusedSceneMotion {
        request,
        inputs: ordered,
        estimate,
        visibility,
        capture_hull,
        clock,
        geometry: twin.basis(),
        twin_digest: twin.digest(),
        source_scene_digest: twin.source_scene_digest(),
        map_error: twin.geometry_error(),
        scale: twin.scale(),
    })
}

fn reserved<T>(length: usize) -> Result<Vec<T>, MotionFusionError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(length)
        .map_err(|_| TwinError::Limit)?;
    Ok(values)
}

fn midpoint(capture: [u64; 2]) -> u64 {
    capture[0] + (capture[1] - capture[0]) / 2
}

fn validate_input(
    twin: &PropertyTwin,
    input: FusionInput,
    request: MotionFusionRequest,
    clock: u64,
) -> Result<(), MotionFusionError> {
    let camera = input.camera;
    let observation = input.observation;
    if input.privacy_domain != request.privacy_domain {
        return Err(MotionFusionError::PrivacyDomain);
    }
    if camera.geometry != twin.basis()
        || [
            camera.camera,
            camera.calibration,
            camera.image_domain,
            camera.clock,
        ]
        .contains(&0)
        || camera.clock != clock
        || observation.camera != camera.camera
        || observation.image_domain != camera.image_domain
        || observation.clock != camera.clock
        || camera.validity[0] > camera.validity[1]
        || observation.capture[0] > observation.capture[1]
        || observation.capture[0] < camera.validity[0]
        || observation.capture[1] > camera.validity[1]
    {
        return Err(MotionFusionError::Basis);
    }
    if observation.capture[1] - observation.capture[0] > request.max_capture_uncertainty_ns {
        return Err(MotionFusionError::CaptureWindow);
    }
    if observation.evidence == [0; 32]
        || observation.track == 0
        || observation.exposure == 0
        || !camera.intrinsics.contains(observation.pixel_min)
        || !camera.intrinsics.contains(observation.pixel_max)
        || (0..2).any(|axis| observation.pixel_min[axis] > observation.pixel_max[axis])
        || !input.sigma_pixels.is_finite()
        || !(1e-3..=1e3).contains(&input.sigma_pixels)
        || camera
            .error
            .is_some_and(|error| !error.valid_for(camera.intrinsics))
    {
        return Err(MotionFusionError::Observation);
    }
    if !observation.visible_contact {
        return Err(MotionFusionError::ContactUnknown);
    }
    Ok(())
}

fn rebase(
    estimate: &mut TriangulatedMotion,
    reference_time_ns: u64,
    budget: &mut WorkBudget<'_>,
) -> Result<(), MotionFusionError> {
    budget.charge(256)?;
    // Integer subtraction precedes conversion so a large capture epoch cannot
    // erase submillisecond camera offsets.
    let dt = (i128::from(reference_time_ns) - estimate.reference_time_ns) as f64 * 1e-9;
    let position = std::array::from_fn(|axis| {
        estimate.position[axis] + estimate.velocity_per_second[axis] * dt
    });
    let original = estimate.pixel_noise_covariance;
    let mut covariance = original;
    // F P F^T for F = [[I, dt I], [0, I]]. Computing one triangle and mirroring
    // preserves symmetry, including all position/velocity cross-covariances.
    for row in 0..6 {
        for column in row..6 {
            let mut value = original[row][column];
            if row < 3 {
                value += dt * original[row + 3][column];
            }
            if column < 3 {
                value += dt * original[row][column + 3];
            }
            if row < 3 && column < 3 {
                value += dt * dt * original[row + 3][column + 3];
            }
            covariance[row][column] = value;
            covariance[column][row] = value;
        }
    }
    if position.iter().any(|value| !value.is_finite())
        || covariance.iter().flatten().any(|value| !value.is_finite())
    {
        return Err(GeometryError::NonFinite.into());
    }
    estimate.reference_time_ns = i128::from(reference_time_ns);
    estimate.position = position;
    estimate.pixel_noise_covariance = covariance;
    Ok(())
}

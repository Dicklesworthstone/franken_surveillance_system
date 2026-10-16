#![forbid(unsafe_code)]
//! Source-linked multi-camera point fusion in an imported property frame.
//!
//! Correspondence is an explicit upstream hypothesis, not inferred identity. A
//! selected visible contact must identify the same physical feature in every
//! camera. Rectangles and calibration bounds are retained, but are NOT converted
//! into Gaussian noise or silently included in the conditional pixel covariance.
//! No detector, privacy grant, calibration activation or world publication occurs.

use crate::{ContactObservation, PropertyTwin, ScaleEvidence, TrackingCamera, TwinError};
use fss_geometry::triangulation::{
    CalibratedView, MAX_TRIANGULATION_VIEWS, TriangulatedPoint, TriangulationError,
    TriangulationOptions, triangulate,
};
use fss_geometry::{GeometryBasis, GeometryError, RigidPose, WorkBudget};

/// One owner-resolved, privacy-projected camera observation of a selected feature.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FusionInput {
    /// Exact camera, image-domain, clock and calibration snapshot.
    pub camera: TrackingCamera,
    /// Original evidence-bearing observation, including its complete pixel rectangle.
    pub observation: ContactObservation,
    /// Owner-resolved privacy namespace; this number does not itself grant access.
    pub privacy_domain: u64,
    /// Explicit statistical pixel-noise assumption, separate from deterministic bounds.
    pub sigma_pixels: f64,
}

/// Conditional motion of the same physical point throughout the capture hull.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CommonPointMotion {
    /// Caller asserts a stationary feature for this window, not merely overlapping times.
    Static,
    /// Caller-supplied constant world velocity. Acceleration and velocity uncertainty
    /// are not propagated; the receipt retains this model and its source evidence.
    Linear {
        /// Velocity in source-world units per second, not implicitly metres per second.
        velocity: [f64; 3],
        /// Nonzero upstream motion-estimate evidence identity.
        evidence: [u8; 32],
    },
}

/// One explicit fusion hypothesis and bounded temporal model.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FusionRequest {
    /// Nonzero upstream correspondence-hypothesis identity, not a person identity.
    pub association_evidence: [u8; 32],
    /// Every input must already belong to this nonzero owner-resolved privacy domain.
    pub privacy_domain: u64,
    /// Position is estimated at this time in the inputs' shared clock generation.
    pub reference_time_ns: u64,
    /// Bound on the FULL capture-time hull, including all timestamp uncertainty.
    /// At most one second. Zero requires exact simultaneous capture times.
    pub max_capture_span_ns: u64,
    /// Explicit stationarity or externally evidenced linear-motion assumption.
    pub motion: CommonPointMotion,
    /// Geometric consensus, conditioning and work policy.
    pub triangulation: TriangulationOptions,
}

/// Nominal line-of-sight diagnosis against the exact imported static mesh.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FusionVisibility {
    /// Logical camera identity in ascending order.
    pub camera: u64,
    /// Camera membership in the unique geometric consensus.
    pub inlier: bool,
    /// None means no front-facing, in-range projection. False is only a clear
    /// nominal segment in this mesh, never a physical-visibility certificate.
    pub nominal_occluded: Option<bool>,
}

/// Immutable nominal estimate with the original inputs and all conditional assumptions.
#[derive(Clone, Debug)]
pub struct FusedScenePoint {
    request: FusionRequest,
    inputs: Vec<FusionInput>,
    estimate: TriangulatedPoint,
    visibility: Vec<FusionVisibility>,
    capture_hull: [u64; 2],
    clock: u64,
    geometry: GeometryBasis,
    twin_digest: [u8; 32],
    map_error: Option<f64>,
    scale: ScaleEvidence,
}
impl FusedScenePoint {
    /// Exact association and temporal assumptions, including the motion-evidence handle.
    pub fn request(&self) -> FusionRequest { self.request }
    /// Original inputs in canonical camera order. Calibration error remains attached.
    pub fn inputs(&self) -> &[FusionInput] { &self.inputs }
    /// Nominal reference-time position. Covariance covers only the declared pixel
    /// noise model, not clock, motion, correspondence, rectangle or calibration error.
    pub fn estimate(&self) -> &TriangulatedPoint { &self.estimate }
    /// Diagnostics for all cameras; conflicting views are never silently erased.
    pub fn visibility(&self) -> &[FusionVisibility] { &self.visibility }
    /// Earliest to latest possible capture time, not the intersection of intervals.
    pub fn capture_hull(&self) -> [u64; 2] { self.capture_hull }
    /// Exact shared capture-clock generation.
    pub fn clock(&self) -> u64 { self.clock }
    /// Exact owner-resolved property and mesh revision.
    pub fn geometry(&self) -> GeometryBasis { self.geometry }
    /// Exact imported package identity, retained for replay/invalidation.
    pub fn twin_digest(&self) -> [u8; 32] { self.twin_digest }
    /// Original scale evidence. Coordinates have not been silently converted to metres.
    pub fn scale(&self) -> ScaleEvidence { self.scale }
    /// Map error declaration; unknown remains unknown and is not included in covariance.
    pub fn map_error(&self) -> Option<f64> { self.map_error }
    /// A fitting camera sees the nominal point through an opaque imported surface.
    /// This flags disagreement; it does not discard evidence or prove the map correct.
    pub fn has_nominal_occlusion_conflict(&self) -> bool {
        self.visibility.iter().any(|v| v.inlier && v.nominal_occluded == Some(true))
    }
}

/// Explicit refusal without a partial or source-detached world position.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FusionError {
    /// Underlying twin or budget failure.
    Twin(TwinError),
    /// Ambiguous, weak, inconsistent or nonconvergent camera geometry.
    Triangulation(TriangulationError),
    /// Camera, property, image domain, clock or calibration validity did not match.
    Basis,
    /// A source ID, pixel rectangle, noise assumption or calibration bound is invalid.
    Observation,
    /// The same source record is offered as multiple independent camera observations.
    DuplicateEvidence,
    /// Input privacy domains differ from the requested domain.
    PrivacyDomain,
    /// Capture hull is too wide, invalid, or does not contain the reference time.
    CaptureWindow,
    /// The motion model has no evidence or has invalid numeric components.
    Motion,
    /// A common visible contact was not supplied; a box bottom cannot invent one.
    ContactUnknown,
}
impl From<TwinError> for FusionError {
    fn from(error: TwinError) -> Self { Self::Twin(error) }
}
impl From<GeometryError> for FusionError {
    fn from(error: GeometryError) -> Self { Self::Twin(TwinError::Geometry(error)) }
}
impl From<TriangulationError> for FusionError {
    fn from(error: TriangulationError) -> Self { Self::Triangulation(error) }
}
impl std::fmt::Display for FusionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Twin(_) => "multi-view twin or work failure",
            Self::Triangulation(_) => "multi-view geometric solve refused",
            Self::Basis => "incompatible multi-view basis or calibration validity",
            Self::Observation => "invalid multi-view observation",
            Self::DuplicateEvidence => "duplicate multi-view source evidence",
            Self::PrivacyDomain => "incompatible multi-view privacy domain",
            Self::CaptureWindow => "inadmissible multi-view capture window",
            Self::Motion => "invalid multi-view motion assumption",
            Self::ContactUnknown => "multi-view contact is not visible",
        })
    }
}
impl std::error::Error for FusionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Twin(error) => Some(error),
            Self::Triangulation(error) => Some(error),
            _ => None,
        }
    }
}

/// Fuse a selected common point, optionally compensating known constant motion.
///
/// Linear compensation moves each ray origin into reference-time coordinates;
/// mesh visibility is checked at each camera's OWN nominal capture time. Timestamp
/// intervals are retained, their full hull gates admission, and interval midpoints
/// are used only for the explicitly nominal solve. No timing uncertainty is
/// laundered into the returned pixel-noise covariance. Work is O(V^3 + I V + V T),
/// where T is the imported triangle count, with V <= 32 and I <= 32.
pub fn fuse_scene_point(
    twin: &PropertyTwin,
    inputs: &[FusionInput],
    request: FusionRequest,
    budget: &mut WorkBudget<'_>,
) -> Result<FusedScenePoint, FusionError> {
    budget.charge(0)?;
    if inputs.len() > MAX_TRIANGULATION_VIEWS {
        return Err(TwinError::Limit.into());
    }
    if inputs.len() < 2 {
        return Err(TriangulationError::InsufficientViews.into());
    }
    if request.association_evidence == [0; 32] {
        return Err(FusionError::Observation);
    }
    if request.privacy_domain == 0 {
        return Err(FusionError::PrivacyDomain);
    }
    if request.max_capture_span_ns > 1_000_000_000 {
        return Err(FusionError::CaptureWindow);
    }
    let velocity = match request.motion {
        CommonPointMotion::Static => [0.0; 3],
        CommonPointMotion::Linear { velocity, evidence } => {
            if evidence == [0; 32]
                || velocity.iter().any(|v| !v.is_finite() || v.abs() > 1e9)
            {
                return Err(FusionError::Motion);
            }
            velocity
        }
    };
    budget.charge(256 * inputs.len() as u64)?;
    let mut ordered = Vec::new();
    ordered.try_reserve_exact(inputs.len()).map_err(|_| TwinError::Limit)?;
    ordered.extend_from_slice(inputs);
    ordered.sort_by_key(|input| input.camera.camera);
    let clock = ordered[0].camera.clock;
    let mut hull = [u64::MAX, 0];
    for (index, input) in ordered.iter().enumerate() {
        budget.charge(64)?;
        validate_input(twin, *input, request.privacy_domain, clock)?;
        if index > 0 && ordered[index - 1].camera.camera == input.camera.camera {
            return Err(TriangulationError::DuplicateCamera.into());
        }
        for previous in &ordered[..index] {
            budget.charge(1)?;
            if previous.observation.evidence == input.observation.evidence {
                return Err(FusionError::DuplicateEvidence);
            }
        }
        hull[0] = hull[0].min(input.observation.capture[0]);
        hull[1] = hull[1].max(input.observation.capture[1]);
    }
    if hull[1] - hull[0] > request.max_capture_span_ns
        || !(hull[0]..=hull[1]).contains(&request.reference_time_ns)
    {
        return Err(FusionError::CaptureWindow);
    }
    let mut views = Vec::new();
    views.try_reserve_exact(ordered.len()).map_err(|_| TwinError::Limit)?;
    for input in &ordered {
        budget.charge(128)?;
        let camera = input.camera;
        let observation = input.observation;
        let dt = capture_offset(observation.capture, request.reference_time_ns);
        let center = camera.pose.center();
        let effective_center = std::array::from_fn(|i| center[i] - velocity[i] * dt);
        views.push(CalibratedView {
            camera: camera.camera,
            pose: RigidPose::from_center(camera.pose.rotation(), effective_center)?,
            intrinsics: camera.intrinsics,
            pixel: std::array::from_fn(|i| {
                observation.pixel_min[i] * 0.5 + observation.pixel_max[i] * 0.5
            }),
            sigma_pixels: input.sigma_pixels,
        });
    }
    let estimate = triangulate(&views, request.triangulation, budget)?;
    let mut visibility = Vec::new();
    visibility.try_reserve_exact(ordered.len()).map_err(|_| TwinError::Limit)?;
    for (input, residual) in ordered.iter().zip(&estimate.residuals) {
        budget.charge(128)?;
        let dt = capture_offset(input.observation.capture, request.reference_time_ns);
        let point = std::array::from_fn(|i| estimate.position[i] + velocity[i] * dt);
        let center = input.camera.pose.center();
        let distance = (point[0] - center[0])
            .hypot(point[1] - center[1])
            .hypot(point[2] - center[2]);
        let nominal_occluded = if residual.pixels.is_some() {
            Some(twin.mesh().segment_occluded(
                twin.basis(), center, point, distance * 1e-8, budget,
            )?)
        } else {
            None
        };
        visibility.push(FusionVisibility {
            camera: input.camera.camera,
            inlier: residual.inlier,
            nominal_occluded,
        });
    }
    budget.charge(0)?;
    Ok(FusedScenePoint {
        request, inputs: ordered, estimate, visibility, capture_hull: hull, clock,
        geometry: twin.basis(), twin_digest: twin.digest(),
        map_error: twin.geometry_error(), scale: twin.scale(),
    })
}

// Subtract in integer space BEFORE conversion. Real capture clocks may be near
// u64::MAX, where converting absolute timestamps to f64 destroys nanosecond deltas.
fn capture_offset(capture: [u64; 2], reference: u64) -> f64 {
    let doubled = i128::from(capture[0]) + i128::from(capture[1]) - 2 * i128::from(reference);
    doubled as f64 * 0.5e-9
}

fn validate_input(
    twin: &PropertyTwin,
    input: FusionInput,
    privacy: u64,
    clock: u64,
) -> Result<(), FusionError> {
    let c = input.camera;
    let o = input.observation;
    if input.privacy_domain != privacy {
        return Err(FusionError::PrivacyDomain);
    }
    if c.geometry != twin.basis() || c.camera == 0 || c.calibration == 0
        || c.image_domain == 0 || c.clock == 0 || c.clock != clock
        || o.camera != c.camera || o.image_domain != c.image_domain || o.clock != c.clock
        || c.validity[0] > c.validity[1] || o.capture[0] > o.capture[1]
        || o.capture[0] < c.validity[0] || o.capture[1] > c.validity[1]
    {
        return Err(FusionError::Basis);
    }
    if o.evidence == [0; 32] || o.track == 0 || o.exposure == 0
        || !c.intrinsics.contains(o.pixel_min) || !c.intrinsics.contains(o.pixel_max)
        || (0..2).any(|i| o.pixel_min[i] > o.pixel_max[i])
        || !input.sigma_pixels.is_finite() || !(1e-3..=1e3).contains(&input.sigma_pixels)
        || c.error.is_some_and(|error| !error.valid_for(c.intrinsics))
    {
        return Err(FusionError::Observation);
    }
    if !o.visible_contact { return Err(FusionError::ContactUnknown); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SurfaceKind, TwinFeature, TwinObject};
    use fss_geometry::{IndexedTriangle, MeshLimits, PinholeIntrinsics, TriangleMesh};
    use std::sync::atomic::AtomicBool;

    const IDENTITY: [[f64; 3]; 3] = [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]];

    fn twin(opaque: bool) -> PropertyTwin {
        let basis = GeometryBasis::new(1, 1).unwrap();
        let vertices = vec![[-10.0, -10.0, 4.0], [10.0, -10.0, 4.0], [0.0, 10.0, 4.0]];
        let triangles = vec![IndexedTriangle { vertices: [0, 1, 2], feature: 1, support: false, opaque }];
        let mesh = TriangleMesh::from_indexed(basis, &vertices, &triangles,
            MeshLimits::default(), &mut WorkBudget::new(100)).unwrap();
        PropertyTwin {
            mesh, vertices, triangles, triangle_objects: vec![0],
            objects: vec![TwinObject { id: "wall".into(), feature: 0, support: false, opaque }],
            features: vec![TwinFeature { id: "wall".into(), surface: SurfaceKind::Structure }],
            digest: [2; 32], source: [3; 32], scope: "test".into(), epoch: "test".into(),
            scale: ScaleEvidence::Relative, geometry_error: None,
        }
    }
    fn input(id: u64, point: [f64; 3], capture: [u64; 2]) -> FusionInput {
        let center = if id == 1 { [-2.0, 0.0, 0.0] } else { [2.0, 0.0, 0.0] };
        let pose = RigidPose::from_center(IDENTITY, center).unwrap();
        let intrinsics = PinholeIntrinsics::new(1280, 720, 800.0, 800.0, 640.0, 360.0).unwrap();
        let pixel = pose.project(intrinsics, point).unwrap();
        FusionInput {
            camera: TrackingCamera {
                geometry: GeometryBasis::new(1, 1).unwrap(), camera: id, calibration: 2,
                image_domain: id + 10, clock: 7, validity: [0, u64::MAX], pose, intrinsics, error: None,
            },
            observation: ContactObservation {
                evidence: [id as u8; 32], track: id, camera: id, exposure: 1,
                image_domain: id + 10, clock: 7, capture,
                pixel_min: pixel, pixel_max: pixel, visible_contact: true,
            },
            privacy_domain: 9, sigma_pixels: 1.0,
        }
    }
    fn request() -> FusionRequest {
        FusionRequest {
            association_evidence: [8; 32], privacy_domain: 9,
            reference_time_ns: 1_000_000_000, max_capture_span_ns: 200_000_000,
            motion: CommonPointMotion::Static, triangulation: TriangulationOptions::default(),
        }
    }
    fn inputs() -> Vec<FusionInput> {
        vec![input(1, [0.0, 0.0, 8.0], [1_000_000_000; 2]),
             input(2, [0.0, 0.0, 8.0], [1_000_000_000; 2])]
    }
    fn solve(twin: &PropertyTwin, inputs: &[FusionInput], request: FusionRequest)
        -> Result<FusedScenePoint, FusionError>
    {
        fuse_scene_point(twin, inputs, request, &mut WorkBudget::new(1_000_000))
    }
    fn near(actual: [f64; 3], expected: [f64; 3]) {
        for i in 0..3 { assert!((actual[i] - expected[i]).abs() < 1e-7); }
    }

    #[test]
    fn unifies_point_and_preserves_unknown_calibration_and_relative_scale() {
        let result = solve(&twin(false), &inputs(), request()).unwrap();
        near(result.estimate().position, [0.0, 0.0, 8.0]);
        assert_eq!(result.inputs()[0].camera.error, None);
        assert_eq!(result.map_error(), None);
        assert_eq!(result.scale(), ScaleEvidence::Relative);
        assert_eq!(result.twin_digest(), [2; 32]);
        assert!(!result.has_nominal_occlusion_conflict());
    }

    #[test]
    fn wall_conflict_does_not_disappear_despite_perfect_reprojection() {
        let result = solve(&twin(true), &inputs(), request()).unwrap();
        assert!(result.estimate().rms_reprojection_pixels < 1e-8);
        assert!(result.has_nominal_occlusion_conflict());
        assert!(result.visibility().iter().all(|v| v.nominal_occluded == Some(true)));
        assert_eq!(result.inputs().len(), 2);
    }

    #[test]
    fn compensates_asynchronous_motion_in_world_coordinates() {
        let mut req = request();
        req.motion = CommonPointMotion::Linear { velocity: [2.0, 0.0, 0.0], evidence: [4; 32] };
        let views = [input(1, [-0.2, 0.0, 8.0], [900_000_000; 2]),
                     input(2, [0.2, 0.0, 8.0], [1_100_000_000; 2])];
        let result = solve(&twin(false), &views, req).unwrap();
        near(result.estimate().position, [0.0, 0.0, 8.0]);
        assert_eq!(result.capture_hull(), [900_000_000, 1_100_000_000]);
        assert_eq!(result.request().motion, req.motion);
        let uncompensated = solve(&twin(false), &views, request()).unwrap();
        assert!((uncompensated.estimate().position[2] - 8.0).abs() > 0.5);
    }

    #[test]
    fn rejects_wide_uncertain_hull_even_when_intervals_overlap() {
        let mut views = inputs();
        views[0].observation.capture = [800_000_000, 1_050_000_000];
        views[1].observation.capture = [950_000_000, 1_200_000_000];
        assert!(matches!(solve(&twin(false), &views, request()), Err(FusionError::CaptureWindow)));
    }

    #[test]
    fn exact_integer_timestamp_offsets_survive_near_u64_max() {
        assert_eq!(capture_offset([u64::MAX - 5, u64::MAX - 3], u64::MAX - 4), 0.0);
        assert!((capture_offset([u64::MAX; 2], u64::MAX - 4) - 4e-9).abs() < 1e-20);
    }

    #[test]
    fn mismatched_domains_clock_and_stale_validity_are_refused() {
        let map = twin(false);
        let mut views = inputs();
        views[1].privacy_domain = 10;
        assert!(matches!(solve(&map, &views, request()), Err(FusionError::PrivacyDomain)));
        views[1].privacy_domain = 9;
        views[1].camera.clock = 8;
        views[1].observation.clock = 8;
        assert!(matches!(solve(&map, &views, request()), Err(FusionError::Basis)));
        views[1].camera.clock = 7;
        views[1].observation.clock = 7;
        views[1].camera.validity[1] = 999_999_999;
        assert!(matches!(solve(&map, &views, request()), Err(FusionError::Basis)));
    }

    #[test]
    fn duplicated_sources_and_occluded_contacts_cannot_gain_depth() {
        let map = twin(false);
        let mut views = inputs();
        views[1].observation.evidence = views[0].observation.evidence;
        assert!(matches!(solve(&map, &views, request()), Err(FusionError::DuplicateEvidence)));
        views[1].observation.evidence = [2; 32];
        views[1].observation.visible_contact = false;
        assert!(matches!(solve(&map, &views, request()), Err(FusionError::ContactUnknown)));
    }

    #[test]
    fn permutation_preserves_estimate_and_original_sources() {
        let map = twin(false);
        let mut views = inputs();
        let first = solve(&map, &views, request()).unwrap();
        views.reverse();
        let second = solve(&map, &views, request()).unwrap();
        assert_eq!(first.estimate(), second.estimate());
        assert_eq!(first.inputs(), second.inputs());
        assert_eq!(first.visibility(), second.visibility());
    }

    #[test]
    fn cancellation_and_budget_exhaustion_never_return_partial_receipt() {
        let map = twin(false);
        let cancelled = AtomicBool::new(true);
        let result = fuse_scene_point(&map, &inputs(), request(),
            &mut WorkBudget::cancellable(1_000_000, &cancelled));
        assert!(matches!(result, Err(FusionError::Twin(TwinError::Geometry(GeometryError::Cancelled)))));
        let result = fuse_scene_point(&map, &inputs(), request(), &mut WorkBudget::new(0));
        assert!(matches!(result, Err(FusionError::Twin(TwinError::Geometry(GeometryError::BudgetExhausted)))));
    }
}

#![forbid(unsafe_code)]
//! Joint multi-camera refinement of single-camera site localizations.
//!
//! Each camera of one site is first localized on its own against the frozen
//! [`LocalizationAtlas`] (fixed-intrinsics, focal-scan, or radial-scan localization).
//! This module seeds the fss-geometry reference bundle adjuster from exactly those
//! caller-selected candidates, anchors it with the surveyed atlas landmarks as fixed
//! control points ([`BundleGaugeChoice::ControlPoints`], selected by
//! [`ControlSelection`]), and adds caller-supplied image tie points that two or more
//! cameras see but the atlas does not contain as free landmarks. Free landmarks are
//! what couple the cameras: a fixed control point seen by two cameras constrains each
//! pose separately but links nothing.
//!
//! Refusals are typed and never a fake success: too few or collinear control points,
//! a camera graph that shared tie points do not connect, a non-finite observation, a
//! seed that names no solved pose, or any bundle-adjuster refusal.
//!
//! Non-claims: the output is a candidate calibration, never an activation. Atlas
//! control positions are treated as exact (their declared survey errors only select
//! which landmarks are control points and are not propagated into covariance),
//! observations are treated as simultaneous (no per-camera time offset), and the
//! covariance is the adjuster's local Gauss-Newton approximation. Synthetic fixtures
//! do not establish accuracy on real site footage.

use std::collections::BTreeMap;

use crate::PropertyTwin;
use crate::focal_localization::{FocalLocalization, FocalLocalizationOutcome};
use crate::localization::{
    CameraLocalization, LocalizationAtlas, LocalizationOutcome, MatchReport,
};
use crate::radial_localization::{
    RadialLocalization, RadialLocalizationOutcome, RadialSampleOutcome,
};
use fss_geometry::{
    AnchoredBundleProblem, BundleAdjustment, BundleAdjustmentError, BundleCamera,
    BundleControlPoint, BundleGaugeChoice, BundleLandmark, BundleObservation, BundleOptions,
    BundleValidity, CameraGeneration, Correspondence, FocalRefinement, FocalSampleOutcome,
    GeometryBasis, GeometryError, IntrinsicsRefinement, MIN_CONTROL_POINTS, PinholeIntrinsics,
    PoseCandidate, RadialDistortion, RigidPose, WorkBudget, bundle_adjust_anchored,
    control_points_span_plane,
};

/// Largest number of caller tie observations admitted in one joint refinement.
pub const MAX_TIE_OBSERVATIONS: usize = 16_384;

/// Typed refusal of a joint refinement. No variant carries refined parameters.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum JointRefinementError {
    /// A zero, duplicate, or dangling camera/tie handle, or a duplicate tie observation.
    InvalidInput,
    /// The atlas was not built from this twin.
    BasisMismatch,
    /// A camera's localization was matched against another atlas, or one of its
    /// correspondences disagrees with the atlas landmark it names.
    AtlasMismatch {
        /// Camera handle.
        camera: u64,
    },
    /// The seed does not name a solved pose (no scan/candidates, or index out of range).
    NoPose {
        /// Camera handle.
        camera: u64,
    },
    /// A correspondence or tie observation holds a NaN or infinite value.
    NonFiniteObservation {
        /// Camera handle.
        camera: u64,
        /// Atlas landmark or tie handle.
        landmark: u64,
    },
    /// Fewer than two cameras: nothing is joint.
    TooFewCameras {
        /// Supplied cameras.
        cameras: usize,
    },
    /// Fewer than [`MIN_CONTROL_POINTS`] distinct atlas landmarks are used as inliers.
    TooFewControlPoints {
        /// Distinct atlas landmarks among the selected candidates' inliers.
        observed: usize,
    },
    /// Every used atlas landmark lies on one line; the metric gauge is not fixed.
    CollinearControlPoints,
    /// Shared tie points do not connect this camera to the smallest-handle camera.
    DisconnectedCameras {
        /// Smallest unreachable camera handle.
        camera: u64,
    },
    /// A tie handle equals an atlas landmark handle.
    TieCollidesWithAtlas {
        /// Tie handle.
        tie: u64,
    },
    /// A tie point's seeded viewing rays are (near) parallel; no initial position exists.
    DegenerateTie {
        /// Tie handle.
        tie: u64,
    },
    /// A fixed limit ([`MAX_TIE_OBSERVATIONS`]) was exceeded.
    Limit,
    /// Work accounting or cancellation refused preprocessing.
    Geometry(GeometryError),
    /// The bundle adjuster refused (including budget exhaustion and cancellation).
    Bundle(BundleAdjustmentError),
}
impl From<GeometryError> for JointRefinementError {
    fn from(error: GeometryError) -> Self {
        Self::Geometry(error)
    }
}
impl std::fmt::Display for JointRefinementError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidInput => f.write_str("invalid joint refinement input"),
            Self::BasisMismatch => f.write_str("atlas does not belong to this twin"),
            Self::AtlasMismatch { camera } => {
                write!(f, "camera {camera} localization is not bound to this atlas")
            }
            Self::NoPose { camera } => write!(f, "camera {camera} seed names no solved pose"),
            Self::NonFiniteObservation { camera, landmark } => {
                write!(f, "non-finite observation of {landmark} by camera {camera}")
            }
            Self::TooFewCameras { cameras } => write!(f, "{cameras} camera(s) cannot be joint"),
            Self::TooFewControlPoints { observed } => {
                write!(
                    f,
                    "{observed} atlas control point(s) observed; at least 3 required"
                )
            }
            Self::CollinearControlPoints => f.write_str("atlas control points are collinear"),
            Self::DisconnectedCameras { camera } => {
                write!(
                    f,
                    "camera {camera} shares no tie-point path with the others"
                )
            }
            Self::TieCollidesWithAtlas { tie } => {
                write!(f, "tie handle {tie} collides with an atlas landmark")
            }
            Self::DegenerateTie { tie } => write!(f, "tie {tie} rays are degenerate"),
            Self::Limit => f.write_str("joint refinement limit exceeded"),
            Self::Geometry(error) => write!(f, "joint refinement preprocessing: {error}"),
            Self::Bundle(error) => write!(f, "joint bundle adjustment refused: {error}"),
        }
    }
}
impl std::error::Error for JointRefinementError {}

/// Exactly which single-camera localization candidate seeds a camera.
///
/// The caller selects the candidate (for example the unique held-out-validated one);
/// this module never ranks candidates. What the localization estimated is what the
/// joint solve refines: fixed-intrinsics seeds keep their intrinsics, focal-scan
/// seeds refine one aspect-held focal length, radial-scan seeds additionally refine
/// radial `k1` and `k2` (`k2` seeded at zero). Principal points stay held.
#[derive(Clone, Copy, Debug)]
pub enum LocalizationSeed<'a> {
    /// A fixed-intrinsics [`CameraLocalization`] candidate.
    Fixed {
        /// Localization result.
        localization: &'a CameraLocalization,
        /// Candidate index in its pose search.
        candidate: usize,
    },
    /// A focal-scan [`FocalLocalization`] candidate.
    Focal {
        /// Localization result.
        localization: &'a FocalLocalization,
        /// Focal sample index.
        sample: usize,
        /// Candidate index within that sample.
        candidate: usize,
    },
    /// A joint focal/radial [`RadialLocalization`] candidate (raw distorted pixels).
    Radial {
        /// Localization result.
        localization: &'a RadialLocalization,
        /// Lens sample index.
        sample: usize,
        /// Candidate index within that sample.
        candidate: usize,
    },
}

/// One camera of the site: its owner-resolved generation and its localization seed.
#[derive(Clone, Copy, Debug)]
pub struct JointCamera<'a> {
    /// Exact camera generation the localization belongs to.
    pub identity: CameraGeneration,
    /// Selected single-camera localization candidate.
    pub seed: LocalizationSeed<'a>,
}

/// A caller-associated image observation of a non-atlas point (same pixel grid as
/// the camera's localization correspondences: raw pixels for radial seeds).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TieObservation {
    /// Observing camera handle.
    pub camera: u64,
    /// Nonzero tie handle, disjoint from atlas landmark handles.
    pub tie: u64,
    /// Observed pixel.
    pub pixel: [f64; 2],
}

/// Per-camera seed and before/after accounting.
#[derive(Clone, Copy, Debug)]
pub struct CameraRefinementSummary {
    /// Camera generation the refined estimate depends on.
    pub identity: CameraGeneration,
    /// Which intrinsics the joint solve refined for this camera.
    pub refinement: IntrinsicsRefinement,
    /// Seed intrinsics taken from the localization candidate.
    pub seed_intrinsics: PinholeIntrinsics,
    /// Seed distortion (radial seeds carry the scanned `k1`).
    pub seed_distortion: RadialDistortion,
    /// Seed world-to-camera pose from the localization candidate.
    pub seed_pose: RigidPose,
    /// RMS reprojection error (px) of this camera's joint observations at the seed.
    pub seed_rms_px: f64,
    /// RMS reprojection error (px) of the same observations after refinement.
    pub refined_rms_px: f64,
    /// Fixed atlas control-point observations (selected-candidate inliers).
    pub control_observations: usize,
    /// Free-landmark observations used (ties and non-control atlas landmarks).
    pub free_observations: usize,
}

/// A converged joint refinement: candidate geometry, never an activation.
#[derive(Clone, Debug)]
pub struct JointRefinement {
    /// Twin revision basis of the world frame.
    pub basis: GeometryBasis,
    /// Exact twin digest.
    pub twin_digest: [u8; 32],
    /// Exact atlas digest whose landmarks anchored the gauge.
    pub atlas_digest: [u8; 32],
    /// Refined cameras (pose, intrinsics, distortion, covariance), control points
    /// used, adjusted free landmarks (ties and non-control atlas landmarks) with
    /// covariance, and the solve report.
    pub adjustment: BundleAdjustment,
    /// Per-camera seeds and before/after RMS, sorted by camera handle.
    pub cameras: Vec<CameraRefinementSummary>,
    /// Tie or non-control atlas handles seen by fewer than two cameras, not used.
    pub excluded_points: Vec<u64>,
}
impl JointRefinement {
    /// RMS reprojection error (px) over all joint observations at the seeds.
    pub fn initial_rms_px(&self) -> f64 {
        self.adjustment.report().initial_rms_px
    }
    /// RMS reprojection error (px) over all joint observations after refinement.
    pub fn final_rms_px(&self) -> f64 {
        self.adjustment.report().final_rms_px
    }
    /// Exact camera generations the result depends on, sorted by camera.
    pub fn dependencies(&self) -> Vec<CameraGeneration> {
        self.adjustment.dependencies()
    }
    /// Validity against the current camera configuration (move/zoom invalidates).
    pub fn validity(&self, current: &[CameraGeneration]) -> BundleValidity {
        self.adjustment.validity(current)
    }
    /// Undistorted pinhole intrinsics and pose of one refined camera, for pinhole
    /// consumers such as ground-zone visibility. `None` for an unknown camera or a
    /// camera whose refined model carries radial distortion, which a pinhole
    /// consumer cannot represent.
    pub fn pinhole_camera(&self, camera: u64) -> Option<(PinholeIntrinsics, RigidPose)> {
        let adjusted = self.adjustment.camera(camera)?;
        (adjusted.distortion == RadialDistortion::NONE)
            .then_some((adjusted.intrinsics, adjusted.pose))
    }
}

struct Seed<'a> {
    identity: CameraGeneration,
    intrinsics: PinholeIntrinsics,
    distortion: RadialDistortion,
    refinement: IntrinsicsRefinement,
    candidate: &'a PoseCandidate,
    matches: &'a MatchReport,
}

fn resolve<'a>(camera: &JointCamera<'a>) -> Result<Seed<'a>, JointRefinementError> {
    let no_pose = JointRefinementError::NoPose {
        camera: camera.identity.camera,
    };
    let aspect_focal = IntrinsicsRefinement {
        focal: FocalRefinement::AspectHeld,
        principal_point: false,
        radial: false,
    };
    let (search, intrinsics, k1, refinement, matches) = match camera.seed {
        LocalizationSeed::Fixed {
            localization,
            candidate,
        } => {
            let LocalizationOutcome::Candidates(search) = &localization.outcome else {
                return Err(no_pose);
            };
            let search: &fss_geometry::PoseSearch = search;
            (
                (search, candidate),
                search.intrinsics(),
                0.0,
                IntrinsicsRefinement::FIXED,
                &localization.matches,
            )
        }
        LocalizationSeed::Focal {
            localization,
            sample,
            candidate,
        } => {
            let FocalLocalizationOutcome::Scan(scan) = &localization.outcome else {
                return Err(no_pose);
            };
            let sample = scan.samples().get(sample).ok_or(no_pose)?;
            let FocalSampleOutcome::Candidates(search) = sample.outcome() else {
                return Err(no_pose);
            };
            let search: &fss_geometry::PoseSearch = search;
            (
                (search, candidate),
                sample.intrinsics(),
                0.0,
                aspect_focal,
                &localization.matches,
            )
        }
        LocalizationSeed::Radial {
            localization,
            sample,
            candidate,
        } => {
            let RadialLocalizationOutcome::Scan(scan) = &localization.outcome else {
                return Err(no_pose);
            };
            let sample = scan.samples.get(sample).ok_or(no_pose)?;
            let RadialSampleOutcome::Candidates(search) = &sample.outcome else {
                return Err(no_pose);
            };
            let search: &fss_geometry::PoseSearch = search;
            (
                (search, candidate),
                sample.intrinsics,
                sample.k1,
                IntrinsicsRefinement {
                    radial: true,
                    ..aspect_focal
                },
                &localization.matches,
            )
        }
    };
    let (search, index) = search;
    let candidate = search.candidates().get(index).ok_or(no_pose)?;
    Ok(Seed {
        identity: camera.identity,
        intrinsics,
        distortion: RadialDistortion { k1, k2: 0.0 },
        refinement,
        candidate,
        matches,
    })
}

/// Distorted pixel of a world point, or `None` at/behind the camera.
fn project(
    seed_like: (PinholeIntrinsics, RadialDistortion, RigidPose),
    world: [f64; 3],
) -> Option<[f64; 2]> {
    let (intrinsics, distortion, pose) = seed_like;
    let p = pose.transform(world).ok()?;
    if p[2] <= 1e-9 {
        return None;
    }
    let (xn, yn) = (p[0] / p[2], p[1] / p[2]);
    let r2 = xn * xn + yn * yn;
    let d = 1.0 + distortion.k1 * r2 + distortion.k2 * r2 * r2;
    let [fx, fy] = intrinsics.focal_lengths();
    let [cx, cy] = intrinsics.principal_point();
    Some([fx * d * xn + cx, fy * d * yn + cy])
}

/// Unit world-frame viewing ray direction of a (distorted) pixel.
fn ray_direction(
    intrinsics: PinholeIntrinsics,
    distortion: RadialDistortion,
    pose: RigidPose,
    pixel: [f64; 2],
) -> [f64; 3] {
    let [fx, fy] = intrinsics.focal_lengths();
    let [cx, cy] = intrinsics.principal_point();
    let (xd, yd) = ((pixel[0] - cx) / fx, (pixel[1] - cy) / fy);
    // Fixed-count fixed-point undistortion of the Brown two-term model.
    let (mut xu, mut yu) = (xd, yd);
    for _ in 0..32 {
        let r2 = xu * xu + yu * yu;
        let d = 1.0 + distortion.k1 * r2 + distortion.k2 * r2 * r2;
        if !(d.is_finite() && d > 1e-6) {
            break;
        }
        xu = xd / d;
        yu = yd / d;
    }
    let r = pose.rotation();
    let camera = [xu, yu, 1.0];
    let world: [f64; 3] =
        std::array::from_fn(|k| r[0][k] * camera[0] + r[1][k] * camera[1] + r[2][k] * camera[2]);
    let n = (world[0] * world[0] + world[1] * world[1] + world[2] * world[2]).sqrt();
    [world[0] / n, world[1] / n, world[2] / n]
}

/// Least-squares point closest to all rays (sum of squared perpendicular distances).
fn triangulate(rays: &[([f64; 3], [f64; 3])]) -> Option<[f64; 3]> {
    let mut a = [[0.0; 3]; 3];
    let mut b = [0.0; 3];
    for (origin, d) in rays {
        for i in 0..3 {
            for j in 0..3 {
                let m = f64::from(u8::from(i == j)) - d[i] * d[j];
                a[i][j] += m;
                b[i] += m * origin[j];
            }
        }
    }
    let det = |m: [[f64; 3]; 3]| {
        m[0][0] * (m[1][1] * m[2][2] - m[1][2] * m[2][1])
            - m[0][1] * (m[1][0] * m[2][2] - m[1][2] * m[2][0])
            + m[0][2] * (m[1][0] * m[2][1] - m[1][1] * m[2][0])
    };
    let total = det(a);
    let scale = (a[0][0] + a[1][1] + a[2][2]) / 3.0;
    if !total.is_finite() || total.abs() <= 1e-9 * scale * scale * scale {
        return None;
    }
    let mut x = [0.0; 3];
    for (k, value) in x.iter_mut().enumerate() {
        let mut m = a;
        for row in 0..3 {
            m[row][k] = b[row];
        }
        *value = det(m) / total;
    }
    x.iter().all(|v| v.is_finite()).then_some(x)
}

fn rms(sum: f64, count: usize) -> f64 {
    if count == 0 {
        0.0
    } else {
        (sum / count as f64).sqrt()
    }
}

/// Which atlas landmarks are held fixed as surveyed control points.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ControlSelection {
    /// Every used atlas landmark is held fixed: the owner asserts the map is exact.
    AllAtlasLandmarks,
    /// Only landmarks whose declared per-axis map error is at most this bound (map
    /// units) are held fixed. Landmarks with a larger or unknown error become free
    /// landmarks seeded at their atlas position when two or more cameras see them,
    /// and are otherwise excluded and reported.
    DeclaredErrorAtMost(f64),
}

/// Joint refinement controls.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct JointOptions {
    /// Control-point selection policy.
    pub control: ControlSelection,
    /// Bundle-adjuster controls.
    pub bundle: BundleOptions,
}
impl Default for JointOptions {
    fn default() -> Self {
        Self {
            control: ControlSelection::AllAtlasLandmarks,
            bundle: BundleOptions::default(),
        }
    }
}

/// A free point (tie or non-control atlas landmark) with its per-camera views.
struct FreePoint {
    /// Atlas position used as the seed, or `None` for a tie (triangulated).
    atlas_seed: Option<[f64; 3]>,
    views: BTreeMap<usize, [f64; 2]>,
}

/// Jointly refine several single-camera localizations of one site.
///
/// Seeds come from the caller-selected localization candidates; each camera
/// contributes the selected candidate's inlier atlas correspondences. Atlas
/// landmarks admitted by [`ControlSelection`] become fixed control points that define
/// the gauge; no reference camera or scale anchor is fabricated. Tie observations and
/// non-control atlas landmarks seen by two or more cameras become free landmarks
/// (ties initialized by least-squares ray intersection from the seeded poses); those
/// seen once are reported in [`JointRefinement::excluded_points`]. Cameras must be
/// connected through shared free landmarks, since fixed control points couple no
/// two cameras. Deterministic: inputs are canonicalized by handle, and the adjuster
/// is bit-reproducible on one platform.
pub fn refine_site_jointly(
    twin: &PropertyTwin,
    atlas: &LocalizationAtlas,
    cameras: &[JointCamera<'_>],
    ties: &[TieObservation],
    options: JointOptions,
    budget: &mut WorkBudget<'_>,
) -> Result<JointRefinement, JointRefinementError> {
    use JointRefinementError as E;
    budget.charge(0)?;
    if twin.digest() != atlas.twin_digest() {
        return Err(E::BasisMismatch);
    }
    if let ControlSelection::DeclaredErrorAtMost(bound) = options.control
        && !(bound.is_finite() && bound >= 0.0)
    {
        return Err(E::InvalidInput);
    }
    if ties.len() > MAX_TIE_OBSERVATIONS {
        return Err(E::Limit);
    }
    let mut ordered: Vec<&JointCamera<'_>> = cameras.iter().collect();
    ordered.sort_by_key(|c| c.identity.camera);
    for (i, camera) in ordered.iter().enumerate() {
        let id = camera.identity;
        if id.camera == 0
            || id.intrinsics == 0
            || id.extrinsics == 0
            || (i > 0 && ordered[i - 1].identity.camera == id.camera)
        {
            return Err(E::InvalidInput);
        }
    }
    let mut seeds = Vec::with_capacity(ordered.len());
    for camera in &ordered {
        let seed = resolve(camera)?;
        budget.charge(seed.matches.correspondences.len() as u64 + 1)?;
        // Every matched correspondence, inlier or not, must be finite.
        for c in &seed.matches.correspondences {
            if c.pixel.iter().chain(&c.world).any(|x| !x.is_finite()) {
                return Err(E::NonFiniteObservation {
                    camera: seed.identity.camera,
                    landmark: c.landmark,
                });
            }
        }
        if seed.matches.atlas != atlas.digest() {
            return Err(E::AtlasMismatch {
                camera: seed.identity.camera,
            });
        }
        seeds.push(seed);
    }
    for tie in ties {
        if tie.pixel.iter().any(|x| !x.is_finite()) {
            return Err(E::NonFiniteObservation {
                camera: tie.camera,
                landmark: tie.tie,
            });
        }
    }
    if seeds.len() < 2 {
        return Err(E::TooFewCameras {
            cameras: seeds.len(),
        });
    }
    let camera_index: BTreeMap<u64, usize> = seeds
        .iter()
        .enumerate()
        .map(|(i, s)| (s.identity.camera, i))
        .collect();

    // Atlas observations: the selected candidate's inliers, bound to the atlas.
    let mut control: BTreeMap<u64, [f64; 3]> = BTreeMap::new();
    let mut free: BTreeMap<u64, FreePoint> = BTreeMap::new();
    let mut observations: Vec<BundleObservation> = Vec::new();
    let mut control_counts = vec![0_usize; seeds.len()];
    for (index, seed) in seeds.iter().enumerate() {
        let camera = seed.identity.camera;
        for &landmark in seed.candidate.inlier_landmarks() {
            budget.charge(4)?;
            let correspondence: &Correspondence = seed
                .matches
                .correspondences
                .iter()
                .find(|c| c.landmark == landmark)
                .ok_or(E::AtlasMismatch { camera })?;
            let atlas_point = atlas
                .landmarks()
                .binary_search_by_key(&landmark, |l| l.id)
                .map(|i| atlas.landmarks()[i])
                .map_err(|_| E::AtlasMismatch { camera })?;
            if atlas_point.world != correspondence.world {
                return Err(E::AtlasMismatch { camera });
            }
            let fixed = match options.control {
                ControlSelection::AllAtlasLandmarks => true,
                ControlSelection::DeclaredErrorAtMost(bound) => atlas_point
                    .error
                    .is_some_and(|e| e.iter().all(|x| *x <= bound)),
            };
            if fixed {
                control.insert(landmark, atlas_point.world);
                observations.push(BundleObservation {
                    camera,
                    landmark,
                    pixel: correspondence.pixel,
                });
                control_counts[index] += 1;
            } else {
                free.entry(landmark)
                    .or_insert_with(|| FreePoint {
                        atlas_seed: Some(atlas_point.world),
                        views: BTreeMap::new(),
                    })
                    .views
                    .insert(index, correspondence.pixel);
            }
        }
    }
    if control.len() < MIN_CONTROL_POINTS {
        return Err(E::TooFewControlPoints {
            observed: control.len(),
        });
    }
    let positions: Vec<[f64; 3]> = control.values().copied().collect();
    if !control_points_span_plane(&positions) {
        return Err(E::CollinearControlPoints);
    }

    // Tie points, canonical (handle, camera) order.
    for tie in ties {
        let &camera = camera_index.get(&tie.camera).ok_or(E::InvalidInput)?;
        if tie.tie == 0 {
            return Err(E::InvalidInput);
        }
        if atlas
            .landmarks()
            .binary_search_by_key(&tie.tie, |l| l.id)
            .is_ok()
        {
            return Err(E::TieCollidesWithAtlas { tie: tie.tie });
        }
        if free
            .entry(tie.tie)
            .or_insert_with(|| FreePoint {
                atlas_seed: None,
                views: BTreeMap::new(),
            })
            .views
            .insert(camera, tie.pixel)
            .is_some()
        {
            return Err(E::InvalidInput);
        }
    }
    let mut excluded_points = Vec::new();
    free.retain(|&handle, point| {
        let keep = point.views.len() >= 2;
        if !keep {
            excluded_points.push(handle);
        }
        keep
    });

    // Camera graph: cameras are coupled only through shared free landmarks.
    let mut reached = vec![false; seeds.len()];
    reached[0] = true;
    let mut changed = true;
    while changed {
        changed = false;
        for point in free.values() {
            if point.views.keys().any(|&c| reached[c]) {
                for &c in point.views.keys() {
                    if !reached[c] {
                        reached[c] = true;
                        changed = true;
                    }
                }
            }
        }
    }
    if let Some(i) = reached.iter().position(|r| !r) {
        return Err(E::DisconnectedCameras {
            camera: seeds[i].identity.camera,
        });
    }

    // Free-landmark seeds: atlas position, or ray intersection from seeded poses.
    let mut landmarks = Vec::with_capacity(free.len());
    let mut free_counts = vec![0_usize; seeds.len()];
    let mut seed_points: BTreeMap<u64, [f64; 3]> = control.clone();
    for (&handle, point) in &free {
        budget.charge(16 * point.views.len() as u64)?;
        let position = match point.atlas_seed {
            Some(position) => position,
            None => {
                let rays: Vec<([f64; 3], [f64; 3])> = point
                    .views
                    .iter()
                    .map(|(&c, &pixel)| {
                        let s = &seeds[c];
                        let pose = s.candidate.pose();
                        (
                            pose.center(),
                            ray_direction(s.intrinsics, s.distortion, pose, pixel),
                        )
                    })
                    .collect();
                triangulate(&rays).ok_or(E::DegenerateTie { tie: handle })?
            }
        };
        landmarks.push(BundleLandmark {
            landmark: handle,
            position,
        });
        seed_points.insert(handle, position);
        for (&c, &pixel) in &point.views {
            observations.push(BundleObservation {
                camera: seeds[c].identity.camera,
                landmark: handle,
                pixel,
            });
            free_counts[c] += 1;
        }
    }

    let problem = AnchoredBundleProblem {
        basis: twin.basis(),
        cameras: seeds
            .iter()
            .map(|s| BundleCamera {
                identity: s.identity,
                intrinsics: s.intrinsics,
                distortion: s.distortion,
                pose: s.candidate.pose(),
                refinement: s.refinement,
            })
            .collect(),
        landmarks,
        control_points: control
            .iter()
            .map(|(&landmark, &position)| BundleControlPoint { landmark, position })
            .collect(),
        observations,
        gauge: BundleGaugeChoice::ControlPoints,
    };
    let adjustment = bundle_adjust_anchored(&problem, options.bundle, budget).map_err(E::Bundle)?;

    // Per-camera before/after RMS over exactly the joint observations.
    let mut refined_points = control;
    for l in adjustment.landmarks() {
        refined_points.insert(l.landmark, l.position);
    }
    let mut sums = vec![(0.0_f64, 0.0_f64, 0_usize); seeds.len()];
    for o in &problem.observations {
        let &c = camera_index.get(&o.camera).ok_or(E::InvalidInput)?;
        let s = &seeds[c];
        let adjusted = adjustment
            .camera(o.camera)
            .ok_or(E::Bundle(BundleAdjustmentError::NumericalBreakdown))?;
        let before = seed_points
            .get(&o.landmark)
            .and_then(|&w| project((s.intrinsics, s.distortion, s.candidate.pose()), w));
        let after = refined_points
            .get(&o.landmark)
            .and_then(|&w| project((adjusted.intrinsics, adjusted.distortion, adjusted.pose), w));
        let (Some(before), Some(after)) = (before, after) else {
            return Err(E::Bundle(BundleAdjustmentError::NumericalBreakdown));
        };
        let squared = |p: [f64; 2]| (p[0] - o.pixel[0]).powi(2) + (p[1] - o.pixel[1]).powi(2);
        sums[c].0 += squared(before);
        sums[c].1 += squared(after);
        sums[c].2 += 2;
    }
    let summaries = seeds
        .iter()
        .enumerate()
        .map(|(i, s)| CameraRefinementSummary {
            identity: s.identity,
            refinement: s.refinement,
            seed_intrinsics: s.intrinsics,
            seed_distortion: s.distortion,
            seed_pose: s.candidate.pose(),
            seed_rms_px: rms(sums[i].0, sums[i].2),
            refined_rms_px: rms(sums[i].1, sums[i].2),
            control_observations: control_counts[i],
            free_observations: free_counts[i],
        })
        .collect();
    budget.charge(0)?;
    Ok(JointRefinement {
        basis: twin.basis(),
        twin_digest: twin.digest(),
        atlas_digest: atlas.digest(),
        adjustment,
        cameras: summaries,
        excluded_points,
    })
}

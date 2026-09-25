#![forbid(unsafe_code)]
//! Geometric visibility of an owner-drawn ground-plane zone from one camera (fss-2h5zq.53).
//!
//! A ground zone is only as observable as the camera's actual view of the ground. Being inside
//! the image frame is a 2D statement; this module makes it a geometric one:
//!
//! * **Sampling.** The zone polygon is sampled on the ground plane (`z = 0` of the property
//!   frame shared by the owner homography, the camera pose and the scene mesh) at the centres of
//!   a regular `grid x grid` lattice over its bounding box; only centres inside the polygon
//!   (even-odd rule) are samples. Grid size is policy ([`DEFAULT_VISIBILITY_GRID`]), bound into
//!   the zone's coverage pipeline generation.
//! * **Projection.** Each sample is projected into the camera, either through the inverse of the
//!   owner image→ground homography (the image point must map back, in front of the camera, onto
//!   the same ground point) or through a calibrated pinhole pose. A sample that falls behind the
//!   camera or outside the half-open decoded image domain is `outside_frustum`.
//! * **Occlusion.** With an owner scene mesh (fss-twin's imported evaluated mesh) *and* a
//!   calibrated pose, the segment from the optical centre to the sample is tested against every
//!   opaque mesh triangle (fss-geometry `segment_occluded`); a hit is `occluded`. Without a mesh,
//!   or without a pose to place the camera in the mesh frame, occlusion is explicitly
//!   `occlusion_unknown`: it is never assumed clear, and the claim is labelled frustum-only.
//!
//! The result is a [`ZoneVisibility`]: sample counts per class, the visible fraction in parts per
//! million, the registered threshold, the sampling policy and the occlusion model. A zone whose
//! visible fraction is below the threshold (or with no visible sample) is not observable for
//! coverage; the typed cause is `occluded` or `outside_frustum`. A clear mesh test concerns this
//! mesh only, never dynamic occluders, camera health, pixel scale or detector recall.

use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest, ContractError};
use fss_geometry::{
    GeometryBasis, GeometryError, PinholeIntrinsics, RigidPose, TriangleMesh, WorkBudget,
};
use fss_twin::{ImportExpectation, ImportLimits, PropertyTwin, TwinError, import_twin};

/// Registered sampling/projection/occlusion policy of this module.
pub const VISIBILITY_POLICY: &str = "fss.ground_visibility_policy.v1:grid-cell-centers:\
even-odd-polygon:ground-plane-z0:homography-roundtrip-or-pinhole:half-open-image:\
mesh-segment-occlusion-or-occlusion-unknown";
/// Default lattice side: `8 x 8 = 64` samples over the zone's bounding box.
pub const DEFAULT_VISIBILITY_GRID: u32 = 8;
/// Smallest admitted lattice side.
pub const MIN_VISIBILITY_GRID: u32 = 2;
/// Largest admitted lattice side (`32 x 32 = 1024` samples).
pub const MAX_VISIBILITY_GRID: u32 = 32;
/// Default threshold: every sample must be visible before the zone counts as observable.
pub const DEFAULT_VISIBILITY_THRESHOLD_PPM: u32 = 1_000_000;
/// Geometry work units one zone assessment may charge (mesh tests charge one per triangle).
pub const MAX_VISIBILITY_WORK: u64 = 200_000_000;
/// Endpoint margin of each occlusion segment, relative to its length, so the sample's own
/// ground surface is never counted as its occluder.
pub const OCCLUSION_MARGIN_RATIO: f64 = 1e-6;
/// Relative ground tolerance of the homography round trip (and of a pose/homography check).
pub const ROUND_TRIP_TOLERANCE: f64 = 1e-6;

/// Sampling density and threshold; both are bound into every coverage pipeline generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VisibilityPolicy {
    /// Lattice side, [`MIN_VISIBILITY_GRID`]..=[`MAX_VISIBILITY_GRID`].
    pub grid: u32,
    /// Minimum visible fraction, in parts per million (1..=1_000_000).
    pub threshold_ppm: u32,
}

impl Default for VisibilityPolicy {
    fn default() -> Self {
        Self {
            grid: DEFAULT_VISIBILITY_GRID,
            threshold_ppm: DEFAULT_VISIBILITY_THRESHOLD_PPM,
        }
    }
}

impl VisibilityPolicy {
    /// Refuses a lattice or threshold outside the registered bounds.
    pub fn validate(&self) -> Result<(), VisibilityError> {
        if !(MIN_VISIBILITY_GRID..=MAX_VISIBILITY_GRID).contains(&self.grid)
            || self.threshold_ppm == 0
            || self.threshold_ppm > 1_000_000
        {
            return Err(VisibilityError::InvalidPolicy);
        }
        Ok(())
    }

    /// Stable sampling label, for example `grid-cell-centers:8x8`.
    #[must_use]
    pub fn sampling_label(&self) -> String {
        format!("grid-cell-centers:{}x{}", self.grid, self.grid)
    }
}

/// An owner-calibrated pinhole camera in the ground/property frame (Z up, ground at `z = 0`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CameraPose {
    /// Undistorted pinhole intrinsics of the decoded image mode.
    pub intrinsics: PinholeIntrinsics,
    /// World-to-camera rigid transform.
    pub pose: RigidPose,
}

impl CameraPose {
    /// Validated pose from the decoded image size, `[fx, fy, cx, cy]` in pixels, a proper
    /// row-major world-to-camera rotation and a translation in ground units.
    pub fn from_parameters(
        dimensions: [u32; 2],
        focal_and_principal: [f64; 4],
        rotation: [[f64; 3]; 3],
        translation: [f64; 3],
    ) -> Result<Self, VisibilityError> {
        let [fx, fy, cx, cy] = focal_and_principal;
        Ok(Self {
            intrinsics: PinholeIntrinsics::new(dimensions[0], dimensions[1], fx, fy, cx, cy)?,
            pose: RigidPose::new(rotation, translation)?,
        })
    }

    /// Exact bits of `fx, fy, cx, cy`, the row-major rotation and the translation, in order.
    #[must_use]
    pub fn parameter_bits(&self) -> Vec<u64> {
        let [fx, fy] = self.intrinsics.focal_lengths();
        let [cx, cy] = self.intrinsics.principal_point();
        let mut bits = vec![fx.to_bits(), fy.to_bits(), cx.to_bits(), cy.to_bits()];
        for row in self.pose.rotation() {
            bits.extend(row.iter().map(|value| value.to_bits()));
        }
        bits.extend(self.pose.translation().iter().map(|value| value.to_bits()));
        bits
    }
}

/// How a camera maps the ground plane into its image.
#[derive(Clone, Copy, Debug)]
pub enum VisibilityCamera<'a> {
    /// Owner image→ground homography (row-major `h11..h33`); no camera position is known.
    Homography(&'a [f64; 9]),
    /// Calibrated pinhole pose.
    Pose(&'a CameraPose),
}

/// An owner scene mesh (imported through fss-twin) and the digest of the exact package bytes.
#[derive(Clone, Copy, Debug)]
pub struct SceneMesh<'a> {
    /// Evaluated triangle mesh in the ground/property frame.
    pub mesh: &'a TriangleMesh,
    /// SHA-256 of the imported package.
    pub package_digest: ContentDigest,
}

/// Camera model a visibility was computed with.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CameraModel {
    /// Owner homography (not a calibration certificate).
    OwnerHomography,
    /// Calibrated pinhole pose.
    CalibratedPose,
}

impl CameraModel {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OwnerHomography => "owner_homography",
            Self::CalibratedPose => "calibrated_pose",
        }
    }
}

/// Why occlusion could not be tested.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OcclusionUnknownReason {
    /// No owner scene mesh was supplied.
    NoSceneMesh,
    /// A mesh was supplied but the camera has no calibrated pose to place it in the mesh frame.
    NoCameraPose,
}

impl OcclusionUnknownReason {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoSceneMesh => "no_scene_mesh",
            Self::NoCameraPose => "no_camera_pose",
        }
    }
}

/// Occlusion model of one visibility.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Occlusion {
    /// Not tested: the claim is frustum-only.
    Unknown(OcclusionUnknownReason),
    /// Tested against the opaque triangles of this exact mesh package.
    MeshChecked(ContentDigest),
}

impl Occlusion {
    /// `occlusion_unknown` or `mesh_checked`.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Unknown(_) => "occlusion_unknown",
            Self::MeshChecked(_) => "mesh_checked",
        }
    }
}

/// Why a zone is not observable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NotVisibleCause {
    /// Most non-visible samples are hidden by opaque mesh geometry.
    Occluded,
    /// Most non-visible samples are behind the camera or outside the image.
    OutsideFrustum,
}

/// Geometric visibility of one ground zone from one camera.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZoneVisibility {
    /// Camera model used.
    pub camera_model: CameraModel,
    /// Lattice side of the sampling policy.
    pub grid: u32,
    /// Threshold in parts per million.
    pub threshold_ppm: u32,
    /// Samples inside the zone polygon.
    pub samples: u32,
    /// Samples visible (in front, inside the image, not occluded by the mesh when tested).
    pub visible: u32,
    /// Samples behind the camera or outside the image.
    pub outside_frustum: u32,
    /// Samples hidden by opaque mesh geometry.
    pub occluded: u32,
    /// Occlusion model.
    pub occlusion: Occlusion,
}

impl ZoneVisibility {
    /// Visible fraction in parts per million (floor).
    #[must_use]
    pub fn visible_fraction_ppm(&self) -> u32 {
        if self.samples == 0 {
            return 0;
        }
        let ppm = u64::from(self.visible) * 1_000_000 / u64::from(self.samples);
        u32::try_from(ppm).unwrap_or(1_000_000)
    }

    /// Whether the zone is observable for coverage: at least one visible sample and a visible
    /// fraction at or above the threshold.
    #[must_use]
    pub fn observable(&self) -> bool {
        self.visible > 0 && self.visible_fraction_ppm() >= self.threshold_ppm
    }

    /// Typed cause when not observable.
    #[must_use]
    pub fn cause(&self) -> Option<NotVisibleCause> {
        if self.observable() {
            None
        } else if self.occluded > 0 && self.occluded >= self.outside_frustum {
            Some(NotVisibleCause::Occluded)
        } else {
            Some(NotVisibleCause::OutsideFrustum)
        }
    }

    /// Whether any witness over this zone is frustum-only (occlusion not tested).
    #[must_use]
    pub fn frustum_only(&self) -> bool {
        matches!(self.occlusion, Occlusion::Unknown(_))
    }

    /// Stable sampling label, for example `grid-cell-centers:8x8`.
    #[must_use]
    pub fn sampling_label(&self) -> String {
        format!("grid-cell-centers:{}x{}", self.grid, self.grid)
    }

    /// `frustum_only` or `frustum_and_mesh_occlusion`.
    #[must_use]
    pub fn claim(&self) -> &'static str {
        if self.frustum_only() {
            "frustum_only"
        } else {
            "frustum_and_mesh_occlusion"
        }
    }

    /// Clause appended to every witness predicate over this zone: the visible fraction, the
    /// sampling policy and the occlusion model (frustum-only when occlusion is unknown).
    #[must_use]
    pub fn predicate_clause(&self) -> String {
        let occlusion = match self.occlusion {
            Occlusion::Unknown(reason) => format!(
                "occlusion_unknown ({}): the claim is frustum-only and an occluder in view could \
                 hide an entry",
                reason.as_str()
            ),
            Occlusion::MeshChecked(digest) => {
                format!("occlusion checked against owner scene mesh {digest} only")
            }
        };
        format!(
            "; geometric visibility {} of {} ground samples ({} ppm, threshold {} ppm) under {} \
             via {}; {occlusion}",
            self.visible,
            self.samples,
            self.visible_fraction_ppm(),
            self.threshold_ppm,
            self.sampling_label(),
            self.camera_model.as_str()
        )
    }

    /// One-line human summary for orientation gaps.
    #[must_use]
    pub fn summary(&self) -> String {
        let occlusion = match self.occlusion {
            Occlusion::Unknown(reason) => format!("occlusion_unknown ({})", reason.as_str()),
            Occlusion::MeshChecked(digest) => format!("mesh_checked ({digest})"),
        };
        format!(
            "{} of {} samples visible ({} ppm, threshold {} ppm), {} outside the frustum, {} \
             occluded, {}, {}",
            self.visible,
            self.samples,
            self.visible_fraction_ppm(),
            self.threshold_ppm,
            self.outside_frustum,
            self.occluded,
            self.sampling_label(),
            occlusion
        )
    }

    /// Canonical encoding (inside a v2 coverage record).
    pub fn encode(&self, e: &mut CanonicalEncoder) {
        e.text(self.camera_model.as_str());
        e.u32(self.grid);
        e.u32(self.threshold_ppm);
        e.u32(self.samples);
        e.u32(self.visible);
        e.u32(self.outside_frustum);
        e.u32(self.occluded);
        match self.occlusion {
            Occlusion::Unknown(reason) => {
                e.text("occlusion_unknown");
                e.text(reason.as_str());
            }
            Occlusion::MeshChecked(digest) => {
                e.text("mesh_checked");
                e.digest(digest);
            }
        }
    }

    /// Decodes and validates [`Self::encode`].
    pub fn decode(d: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let camera_model = match d.text()? {
            "owner_homography" => CameraModel::OwnerHomography,
            "calibrated_pose" => CameraModel::CalibratedPose,
            _ => return Err(ContractError::InvalidIdentifier),
        };
        let grid = d.u32()?;
        let threshold_ppm = d.u32()?;
        let samples = d.u32()?;
        let visible = d.u32()?;
        let outside_frustum = d.u32()?;
        let occluded = d.u32()?;
        let occlusion = match d.text()? {
            "occlusion_unknown" => Occlusion::Unknown(match d.text()? {
                "no_scene_mesh" => OcclusionUnknownReason::NoSceneMesh,
                "no_camera_pose" => OcclusionUnknownReason::NoCameraPose,
                _ => return Err(ContractError::InvalidIdentifier),
            }),
            "mesh_checked" => Occlusion::MeshChecked(d.digest()?),
            _ => return Err(ContractError::InvalidIdentifier),
        };
        let visibility = Self {
            camera_model,
            grid,
            threshold_ppm,
            samples,
            visible,
            outside_frustum,
            occluded,
            occlusion,
        };
        visibility.validate()?;
        Ok(visibility)
    }

    /// Internal consistency: counts add up, bounds hold, and an unknown occlusion counts no
    /// occluded sample.
    pub fn validate(&self) -> Result<(), ContractError> {
        let policy = VisibilityPolicy {
            grid: self.grid,
            threshold_ppm: self.threshold_ppm,
        };
        let total =
            u64::from(self.visible) + u64::from(self.outside_frustum) + u64::from(self.occluded);
        if policy.validate().is_err()
            || self.samples == 0
            || u64::from(self.samples) > u64::from(self.grid) * u64::from(self.grid)
            || total != u64::from(self.samples)
            || (self.frustum_only() && self.occluded != 0)
        {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(())
    }
}

/// Typed refusal of a visibility assessment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VisibilityError {
    /// Grid or threshold outside the registered bounds.
    InvalidPolicy,
    /// The zone polygon is not finite, has fewer than three vertices, or contains no sample.
    InvalidZone,
    /// The homography is not finite or not invertible.
    InvalidHomography,
    /// The pose's intrinsics describe another image size than the decoded frames.
    PoseDimensions,
    /// A geometry query failed (budget, cancellation, basis or degenerate segment).
    Geometry(GeometryError),
    /// The owner scene-mesh package was refused (digest, format, references or limits).
    SceneMesh(TwinError),
}

impl std::fmt::Display for VisibilityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPolicy => {
                f.write_str("visibility grid must be 2..32 and threshold 1..1000000 ppm")
            }
            Self::InvalidZone => {
                f.write_str("ground zone polygon is not finite or yields no sample")
            }
            Self::InvalidHomography => {
                f.write_str("ground homography is not finite or not invertible")
            }
            Self::PoseDimensions => {
                f.write_str("pose intrinsics describe another image size than the decoded frames")
            }
            Self::Geometry(error) => write!(f, "visibility geometry: {error}"),
            Self::SceneMesh(error) => write!(f, "owner scene mesh refused: {error}"),
        }
    }
}

impl std::error::Error for VisibilityError {}

impl From<GeometryError> for VisibilityError {
    fn from(error: GeometryError) -> Self {
        Self::Geometry(error)
    }
}

/// Geometry work units one scene-mesh import may charge.
pub const MAX_SCENE_MESH_IMPORT_WORK: u64 = 150_000_000;

/// Imports an owner scene mesh (fss-twin `FSSTWIN1` package, local Z-up source units shared with
/// the ground zones) against its exact package and source-scene digests. The mesh is evidence
/// of geometry the owner asserts, not a calibration certificate; a digest mismatch, a malformed
/// package or an exceeded bound is a typed refusal before any visibility query.
pub fn import_scene_mesh(
    bytes: &[u8],
    package: ContentDigest,
    source_scene: ContentDigest,
) -> Result<PropertyTwin, VisibilityError> {
    let basis = GeometryBasis::new(1, 1)?;
    let mut budget = WorkBudget::new(MAX_SCENE_MESH_IMPORT_WORK);
    import_twin(
        bytes,
        ImportExpectation {
            package_sha256: package.bytes(),
            source_scene_sha256: source_scene.bytes(),
            basis,
        },
        ImportLimits::default(),
        &mut budget,
    )
    .map_err(VisibilityError::SceneMesh)
}

/// Axis-aligned ground rectangle as a counter-clockwise polygon.
#[must_use]
pub fn rectangle(x: f64, y: f64, width: f64, height: f64) -> [(f64, f64); 4] {
    [
        (x, y),
        (x + width, y),
        (x + width, y + height),
        (x, y + height),
    ]
}

fn inside_polygon(polygon: &[(f64, f64)], x: f64, y: f64) -> bool {
    let mut inside = false;
    let mut previous = polygon[polygon.len() - 1];
    for &current in polygon {
        let (xi, yi) = current;
        let (xj, yj) = previous;
        if (yi > y) != (yj > y) && x < (xj - xi) * (y - yi) / (yj - yi) + xi {
            inside = !inside;
        }
        previous = current;
    }
    inside
}

/// Ground samples of `polygon` under `policy`, in row-major lattice order.
pub fn ground_samples(
    polygon: &[(f64, f64)],
    policy: VisibilityPolicy,
) -> Result<Vec<(f64, f64)>, VisibilityError> {
    policy.validate()?;
    if polygon.len() < 3
        || polygon
            .iter()
            .any(|(x, y)| !x.is_finite() || !y.is_finite())
    {
        return Err(VisibilityError::InvalidZone);
    }
    let (mut min_x, mut min_y) = polygon[0];
    let (mut max_x, mut max_y) = polygon[0];
    for &(x, y) in polygon {
        min_x = min_x.min(x);
        min_y = min_y.min(y);
        max_x = max_x.max(x);
        max_y = max_y.max(y);
    }
    let (width, height) = (max_x - min_x, max_y - min_y);
    if !(width.is_finite() && height.is_finite() && width > 0.0 && height > 0.0) {
        return Err(VisibilityError::InvalidZone);
    }
    let grid = f64::from(policy.grid);
    let mut samples = Vec::new();
    for row in 0..policy.grid {
        for column in 0..policy.grid {
            let x = min_x + width * (f64::from(column) + 0.5) / grid;
            let y = min_y + height * (f64::from(row) + 0.5) / grid;
            if inside_polygon(polygon, x, y) {
                samples.push((x, y));
            }
        }
    }
    if samples.is_empty() {
        return Err(VisibilityError::InvalidZone);
    }
    Ok(samples)
}

fn invert(matrix: &[f64; 9]) -> Result<[f64; 9], VisibilityError> {
    if !matrix.iter().all(|value| value.is_finite()) {
        return Err(VisibilityError::InvalidHomography);
    }
    let [a, b, c, d, e, f, g, h, i] = *matrix;
    let det = a * (e * i - f * h) - b * (d * i - f * g) + c * (d * h - e * g);
    if !det.is_finite() || det == 0.0 {
        return Err(VisibilityError::InvalidHomography);
    }
    let inverse = [
        (e * i - f * h) / det,
        (c * h - b * i) / det,
        (b * f - c * e) / det,
        (f * g - d * i) / det,
        (a * i - c * g) / det,
        (c * d - a * f) / det,
        (d * h - e * g) / det,
        (b * g - a * h) / det,
        (a * e - b * d) / det,
    ];
    if !inverse.iter().all(|value| value.is_finite()) {
        return Err(VisibilityError::InvalidHomography);
    }
    Ok(inverse)
}

/// Image point → ground point through an owner homography, or `None` at or beyond the horizon
/// (`w <= 0` relative to the matrix scale), exactly as the corroboration foot-point projection.
#[must_use]
pub fn homography_project(matrix: &[f64; 9], u: f64, v: f64) -> Option<(f64, f64)> {
    let [a, b, c, d, e, f, g, h, i] = *matrix;
    let w = g * u + h * v + i;
    let scale = matrix.iter().fold(0.0_f64, |m, x| m.max(x.abs()));
    if !w.is_finite() || w <= scale * 1e-12 {
        return None;
    }
    let x = (a * u + b * v + c) / w;
    let y = (d * u + e * v + f) / w;
    (x.is_finite() && y.is_finite()).then_some((x, y))
}

fn in_image(dimensions: [u32; 2], u: f64, v: f64) -> bool {
    u.is_finite()
        && v.is_finite()
        && u >= 0.0
        && v >= 0.0
        && u < f64::from(dimensions[0])
        && v < f64::from(dimensions[1])
}

fn close(a: (f64, f64), b: (f64, f64)) -> bool {
    let tolerance = ROUND_TRIP_TOLERANCE * (1.0 + b.0.abs().max(b.1.abs()));
    (a.0 - b.0).abs() <= tolerance && (a.1 - b.1).abs() <= tolerance
}

/// Image position of a ground sample through the homography's inverse, when the image point
/// maps back in front of the camera onto the same ground point.
fn homography_pixel(matrix: &[f64; 9], inverse: &[f64; 9], x: f64, y: f64) -> Option<(f64, f64)> {
    let [m11, m12, m13, m21, m22, m23, m31, m32, m33] = *inverse;
    let weight = m31 * x + m32 * y + m33;
    if !weight.is_finite() || weight == 0.0 {
        return None;
    }
    let u = (m11 * x + m12 * y + m13) / weight;
    let v = (m21 * x + m22 * y + m23) / weight;
    homography_project(matrix, u, v)
        .filter(|ground| close(*ground, (x, y)))
        .map(|_| (u, v))
}

/// Assesses one ground zone from one camera. Deterministic: equal inputs give equal results.
pub fn assess_ground_zone(
    camera: VisibilityCamera<'_>,
    dimensions: [u32; 2],
    polygon: &[(f64, f64)],
    mesh: Option<SceneMesh<'_>>,
    policy: VisibilityPolicy,
) -> Result<ZoneVisibility, VisibilityError> {
    let samples = ground_samples(polygon, policy)?;
    let mut budget = WorkBudget::new(MAX_VISIBILITY_WORK);
    let (camera_model, occlusion) = match (camera, mesh) {
        (VisibilityCamera::Homography(_), None) => (
            CameraModel::OwnerHomography,
            Occlusion::Unknown(OcclusionUnknownReason::NoSceneMesh),
        ),
        (VisibilityCamera::Homography(_), Some(_)) => (
            CameraModel::OwnerHomography,
            Occlusion::Unknown(OcclusionUnknownReason::NoCameraPose),
        ),
        (VisibilityCamera::Pose(_), None) => (
            CameraModel::CalibratedPose,
            Occlusion::Unknown(OcclusionUnknownReason::NoSceneMesh),
        ),
        (VisibilityCamera::Pose(_), Some(scene)) => (
            CameraModel::CalibratedPose,
            Occlusion::MeshChecked(scene.package_digest),
        ),
    };
    if let VisibilityCamera::Pose(pose) = camera
        && pose.intrinsics.dimensions() != dimensions
    {
        return Err(VisibilityError::PoseDimensions);
    }
    let inverse = match camera {
        VisibilityCamera::Homography(matrix) => Some(invert(matrix)?),
        VisibilityCamera::Pose(_) => None,
    };
    let (mut visible, mut outside, mut occluded) = (0_u32, 0_u32, 0_u32);
    for &(x, y) in &samples {
        budget.charge(1)?;
        let in_view = match (camera, inverse.as_ref()) {
            (VisibilityCamera::Homography(matrix), Some(inverse)) => {
                homography_pixel(matrix, inverse, x, y)
                    .is_some_and(|(u, v)| in_image(dimensions, u, v))
            }
            (VisibilityCamera::Pose(pose), _) => pose
                .pose
                .project(pose.intrinsics, [x, y, 0.0])
                .is_ok_and(|pixel| pose.intrinsics.contains(pixel)),
            (VisibilityCamera::Homography(_), None) => false,
        };
        if !in_view {
            outside += 1;
            continue;
        }
        let hidden = match (camera, mesh) {
            (VisibilityCamera::Pose(pose), Some(scene)) => {
                let from = pose.pose.center();
                let to = [x, y, 0.0];
                let length = ((to[0] - from[0]).powi(2)
                    + (to[1] - from[1]).powi(2)
                    + (to[2] - from[2]).powi(2))
                .sqrt();
                scene.mesh.segment_occluded(
                    scene.mesh.basis(),
                    from,
                    to,
                    OCCLUSION_MARGIN_RATIO * length,
                    &mut budget,
                )?
            }
            _ => false,
        };
        if hidden {
            occluded += 1;
        } else {
            visible += 1;
        }
    }
    let count = u32::try_from(samples.len()).map_err(|_| VisibilityError::InvalidZone)?;
    let visibility = ZoneVisibility {
        camera_model,
        grid: policy.grid,
        threshold_ppm: policy.threshold_ppm,
        samples: count,
        visible,
        outside_frustum: outside,
        occluded,
        occlusion,
    };
    visibility
        .validate()
        .map_err(|_| VisibilityError::InvalidZone)?;
    Ok(visibility)
}

/// Whether a calibrated pose and an owner homography describe the same ground map over the
/// samples the pose sees: every such sample's image point maps back through the homography
/// onto the sample (relative tolerance [`ROUND_TRIP_TOLERANCE`] scaled by 1000, so independent
/// owner assertions agree to a millionth of the zone scale, not to floating-point noise).
#[must_use]
pub fn pose_matches_homography(
    pose: &CameraPose,
    matrix: &[f64; 9],
    polygon: &[(f64, f64)],
    policy: VisibilityPolicy,
) -> bool {
    let Ok(samples) = ground_samples(polygon, policy) else {
        return false;
    };
    samples.iter().all(
        |&(x, y)| match pose.pose.project(pose.intrinsics, [x, y, 0.0]) {
            Ok(pixel) if pose.intrinsics.contains(pixel) => {
                homography_project(matrix, pixel[0], pixel[1]).is_some_and(|(gx, gy)| {
                    let tolerance = ROUND_TRIP_TOLERANCE * 1e3 * (1.0 + x.abs().max(y.abs()));
                    (gx - x).abs() <= tolerance && (gy - y).abs() <= tolerance
                })
            }
            _ => true,
        },
    )
}

/// Visibility parameters appended to a coverage pipeline generation: the policy identity, the
/// grid, the threshold, the camera pose bits (or a zero marker for a homography-only camera) and
/// the mesh package digest words (or a zero marker without a mesh).
pub fn bind_visibility_parameters(
    parameters: &mut Vec<u64>,
    policy: VisibilityPolicy,
    pose: Option<&CameraPose>,
    mesh: Option<ContentDigest>,
) {
    let words = |digest: ContentDigest| -> Vec<u64> {
        digest
            .bytes()
            .chunks(8)
            .map(|chunk| {
                chunk
                    .iter()
                    .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte))
            })
            .collect()
    };
    parameters.extend(words(ContentDigest::sha256(VISIBILITY_POLICY.as_bytes())));
    parameters.push(u64::from(policy.grid));
    parameters.push(u64::from(policy.threshold_ppm));
    match pose {
        Some(pose) => {
            parameters.push(1);
            parameters.extend(pose.parameter_bits());
        }
        None => parameters.push(0),
    }
    match mesh {
        Some(digest) => {
            parameters.push(1);
            parameters.extend(words(digest));
        }
        None => parameters.push(0),
    }
}

#[cfg(test)]
mod tests;

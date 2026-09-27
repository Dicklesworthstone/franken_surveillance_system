#![forbid(unsafe_code)]
//! Additional, fail-closed screening of *candidate* calibrated ground coverage.
//!
//! Existing pose sigma points omit lens uncertainty and pose/lens cross terms.
//! This screen uses the full camera covariance to enclose a radius-three LOCAL
//! LINEARIZED pixel/depth contour at the existing ground-grid samples. A contour
//! touching an image boundary, the camera plane or a current privacy rectangle
//! cannot support a nominal coverage proposal. It never creates a witness, never
//! upgrades a pose-sigma result, and does not assert nonlinear or physical coverage.
//! The ground, gauge and fixed parameters remain conditioning assumptions.
//!
//! No I/O occurs here. The caller resolves the current sensor mask, checks source
//! and calibration currency, and decides which existing proposals must be withheld.

use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm, SensorId};
use fss_geometry::{
    AdjustedCamera, BundleParameter, CAMERA_BLOCK_PARAMETERS, CAMERA_UNCERTAINTY_WORK_UNITS,
    CameraCovariance, CameraGeneration, FRUSTUM_UNCERTAINTY_WORK_UNITS, GeometryError, LinearizedFrustumRelation,
    ProjectionUncertaintyError, RadialDistortion, WorkBudget,
};

use super::ground_visibility::{VisibilityError, VisibilityPolicy, ground_samples, rectangle};
use super::privacy_mask::{MAX_MASK_REGIONS, MaskBinding};
use super::recorded_corroboration::{CorroborationError, GroundZone, MAX_CORROBORATION_ZONES};
use super::site_calibration::CalibratedCamera;

mod receipt;
pub use receipt::{CalibrationCoverageReceipt, CalibrationZoneReceipt, MAX_CALIBRATION_COVERAGE_RECEIPT_BYTES, apply_calibration_coverage};

/// Exact reference screen; the radius is not a confidence probability.
pub const CALIBRATION_COVERAGE_POLICY: &str = "fss.calibration_coverage_guard.v1:full-camera-marginal:\
exact-ground-grid:radius-3:linearized-pixel-depth:half-open-image:closed-contour-vs-half-open-mask:\
all-samples-inside-unmasked:abstention-only";
/// Caller-independent contour multiplier, matching the existing pose probe radius.
pub const CALIBRATION_COVERAGE_SIGMA: f64 = 3.0;
/// One explicit allowance shared by both cameras in the command-line guard.
pub const MAX_CALIBRATION_COVERAGE_WORK: u64 = 64_000_000;
const SETUP_WORK: u64 = 4_096;
const SAMPLE_OVERHEAD: u64 = (MAX_MASK_REGIONS as u64) * 2 + 16;
const SAMPLE_WORK: u64 =
    CAMERA_UNCERTAINTY_WORK_UNITS + FRUSTUM_UNCERTAINTY_WORK_UNITS + SAMPLE_OVERHEAD;

fn invalid(camera: &str, reason: &'static str) -> CorroborationError {
    CorroborationError::InvalidPose { camera: camera.to_owned(), reason }
}

fn geometry(error: GeometryError) -> CorroborationError {
    CorroborationError::Visibility(VisibilityError::Geometry(error))
}

fn projection(error: ProjectionUncertaintyError, camera: &str) -> CorroborationError {
    match error {
        ProjectionUncertaintyError::Geometry(error) => geometry(error),
        _ => invalid(camera, "full camera covariance is malformed, stale or not numerically positive semidefinite"),
    }
}

/// Convert the exact retained candidate, without dropping covariance or fixed slots.
/// This checks pinhole compatibility and bounds before cloning caller-owned vectors.
pub fn calibrated_camera_model(camera: &CalibratedCamera) -> Result<AdjustedCamera, CorroborationError> {
    let k = camera.covariance_parameters.len();
    if k > CAMERA_BLOCK_PARAMETERS
        || camera.fixed_parameters.len() > CAMERA_BLOCK_PARAMETERS
        || k + camera.fixed_parameters.len() != CAMERA_BLOCK_PARAMETERS
        || camera.covariance.len() != k * k
    {
        return Err(invalid(&camera.name, "full camera covariance has an invalid parameter partition or shape"));
    }
    let pose = camera.pinhole_pose().map_err(|_| invalid(&camera.name, "coverage requires a valid undistorted pinhole candidate"))?;
    Ok(AdjustedCamera {
        identity: camera.identity,
        intrinsics: pose.intrinsics,
        distortion: RadialDistortion::NONE,
        pose: pose.pose,
        covariance: CameraCovariance {
            parameters: camera.covariance_parameters.clone(),
            matrix: camera.covariance.clone(),
            fixed: camera.fixed_parameters.clone(),
        },
    })
}

/// All inputs to one camera's bounded screen. `calibration_digest` is the verified
/// parent file identity, not a claim that its geometry is physically current.
pub struct CalibrationCoverageInput<'a> {
    /// Owner camera name.
    pub camera_name: &'a str,
    /// Complete camera estimate, including within-camera covariance.
    pub camera: &'a AdjustedCamera,
    /// Pinned parent calibration identity.
    pub calibration_digest: ContentDigest,
    /// Source sensor resolved from the retained recording.
    pub sensor: &'a SensorId,
    /// That sensor's current authority-resolved privacy binding.
    pub privacy: &'a MaskBinding,
    /// Exact ground rectangles of the corroboration plan.
    pub zones: &'a [GroundZone],
    /// Existing ground-grid density and nominal visibility threshold.
    pub policy: VisibilityPolicy,
}

/// Mutually exclusive outcomes, ordered as encoded in the report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CalibrationSampleRelation {
    /// The local contour is inside the image and disjoint from the current mask.
    InsideUnmasked,
    /// The local contour is outside the image.
    OutsideFrustum,
    /// Its enclosure crosses an image boundary.
    FrustumBoundary,
    /// Its depth contour reaches the camera plane.
    CameraPlaneCrossing,
    /// The mean image pixel is already masked.
    PrivacyMasked,
    /// The mean is unmasked, but its contour enclosure meets a privacy rectangle.
    PrivacyBoundary,
    /// The mean is at/behind the camera plane; perspective covariance is undefined.
    MeanBehindCamera,
}
impl CalibrationSampleRelation {
    /// Stable field spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InsideUnmasked => "inside_unmasked",
            Self::OutsideFrustum => "outside_frustum",
            Self::FrustumBoundary => "frustum_boundary",
            Self::CameraPlaneCrossing => "camera_plane_crossing",
            Self::PrivacyMasked => "privacy_masked",
            Self::PrivacyBoundary => "privacy_boundary",
            Self::MeanBehindCamera => "mean_behind_camera",
        }
    }
}
const RELATIONS: [CalibrationSampleRelation; 7] = [
    CalibrationSampleRelation::InsideUnmasked, CalibrationSampleRelation::OutsideFrustum,
    CalibrationSampleRelation::FrustumBoundary, CalibrationSampleRelation::CameraPlaneCrossing,
    CalibrationSampleRelation::PrivacyMasked, CalibrationSampleRelation::PrivacyBoundary,
    CalibrationSampleRelation::MeanBehindCamera,
];

/// Bounded per-zone counts; no raw image, projected point or mask coordinates escape.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CalibrationZoneAssessment {
    zone_id: String,
    geometry: String,
    counts: [u32; 7],
}
impl CalibrationZoneAssessment {
    /// Owner zone identifier.
    pub fn zone_id(&self) -> &str { &self.zone_id }
    /// Number of assessed ground samples.
    pub fn samples(&self) -> u32 { self.counts.iter().sum() }
    /// Count of one mutually exclusive relation.
    pub fn count(&self, relation: CalibrationSampleRelation) -> u32 { self.counts[relation as usize] }
    /// Whether a pre-existing nominal witness needs to be withheld by this screen.
    /// A false result never grants a witness: the other coverage gates still apply.
    pub fn requires_abstention(&self) -> bool { self.counts[0] != self.samples() }
}

/// Candidate-calibration screen, bound to the exact consumed model, zones and mask.
#[derive(Clone, Debug)]
pub struct CalibrationCoverageAssessment {
    camera_name: String,
    camera_identity: CameraGeneration,
    policy: VisibilityPolicy,
    pose_covariance_bits: [u64; 36],
    privacy_generation: u64,
    sensor: SensorId,
    calibration_digest: ContentDigest,
    input_digest: ContentDigest,
    privacy_digest: ContentDigest,
    zones: Vec<CalibrationZoneAssessment>,
    work_units: u64,
    work_units_remaining: u64,
}
impl CalibrationCoverageAssessment {
    /// Per-zone counts, in canonical zone-name order.
    pub fn zones(&self) -> &[CalibrationZoneAssessment] { &self.zones }
    /// Exact consumed inputs, including full covariance, geometry, mask and policy.
    pub fn input_digest(&self) -> ContentDigest { self.input_digest }
    /// Charged reference work, not a wall-time or instruction count.
    pub fn work_units(&self) -> u64 { self.work_units }
    /// Bounded JSON. Passing means only that this additional screen did not object.
    pub fn to_json(&self) -> String {
        let zones: Vec<String> = self.zones.iter().map(|zone| {
            let counts = RELATIONS.iter().map(|relation| {
                format!("\"{}\":{}", relation.as_str(), zone.count(*relation))
            }).collect::<Vec<_>>().join(",");
            format!("{{\"zone_id\":{},\"samples\":{},\"requires_abstention\":{},\"counts\":{{{counts}}}}}",
                quoted(zone.zone_id()), zone.samples(), zone.requires_abstention())
        }).collect();
        format!(concat!(
            "{{\"format\":\"fss.calibration_camera_coverage.v1\",\"camera\":{},\"sensor_id\":{},",
            "\"calibration_digest\":\"{}\",\"input_digest\":\"{}\",\"privacy_binding_digest\":\"{}\",",
            "\"policy\":\"{}\",\"sigma_multiplier\":{},\"zones\":[{}],",
            "\"work_units\":{},\"work_units_remaining\":{},",
            "\"claim\":\"conditional_linearized_screen_not_coverage_or_physical_currency\"}}"),
            quoted(&self.camera_name), quoted(self.sensor.as_str()), self.calibration_digest,
            self.input_digest, self.privacy_digest, CALIBRATION_COVERAGE_POLICY,
            CALIBRATION_COVERAGE_SIGMA, zones.join(","), self.work_units, self.work_units_remaining)
    }
}

fn quoted(text: &str) -> String {
    let mut result = String::from("\"");
    for ch in text.chars() {
        match ch {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            ch if ch.is_control() => result.push_str(&format!("\\u{:04x}", u32::from(ch))),
            ch => result.push(ch),
        }
    }
    result.push('"');
    result
}

fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 64
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}

/// Closed contour enclosure intersects a half-open privacy rectangle. Touching
/// its included left/top edges counts; touching only its excluded right/bottom does not.
fn meets_mask(min: [f64; 2], max: [f64; 2], privacy: &MaskBinding) -> bool {
    privacy.policy().is_some_and(|policy| policy.regions().iter().any(|region| {
        max[0] >= f64::from(region.x()) && max[1] >= f64::from(region.y())
            && min[0] < f64::from(region.x()) + f64::from(region.width())
            && min[1] < f64::from(region.y()) + f64::from(region.height())
    }))
}

fn encode_parameter(e: &mut CanonicalEncoder, parameter: BundleParameter) {
    // Named tags retain the aspect-held Focal/Fx distinction.
    match parameter {
        BundleParameter::Rotation(axis) => { e.u8(0); e.u64(axis as u64); }
        BundleParameter::Translation(axis) => { e.u8(1); e.u64(axis as u64); }
        BundleParameter::Focal => e.u8(2), BundleParameter::Fx => e.u8(3),
        BundleParameter::Fy => e.u8(4), BundleParameter::Cx => e.u8(5),
        BundleParameter::Cy => e.u8(6), BundleParameter::K1 => e.u8(7),
        BundleParameter::K2 => e.u8(8),
    }
}

/// Screen one camera, without granting or retaining evidence. All declared grid
/// samples must pass for a zone not to request abstention, even with a lower
/// nominal visibility threshold. This conservative additional gate may withhold
/// useful coverage; it cannot turn an old uncovered interval into an absence claim.
pub fn assess_calibration_coverage(
    input: CalibrationCoverageInput<'_>,
    budget: &mut WorkBudget<'_>,
) -> Result<CalibrationCoverageAssessment, CorroborationError> {
    budget.charge(0).map_err(geometry)?;
    let start = budget.used();
    input.policy.validate()?;
    let camera = input.camera;
    let k = camera.covariance.parameters.len();
    if !valid_name(input.camera_name) || input.zones.is_empty()
        || input.zones.len() > MAX_CORROBORATION_ZONES
        || k > CAMERA_BLOCK_PARAMETERS || camera.covariance.fixed.len() > CAMERA_BLOCK_PARAMETERS
        || k + camera.covariance.fixed.len() != CAMERA_BLOCK_PARAMETERS
        || camera.covariance.matrix.len() != k * k
        || camera.distortion != RadialDistortion::NONE
        || input.calibration_digest.algorithm() != DigestAlgorithm::Sha256
        || input.calibration_digest.bytes() == [0; 32]
    {
        return Err(invalid(input.camera_name, "invalid bounded pinhole calibration coverage inputs"));
    }
    for zone in input.zones {
        if !valid_name(&zone.zone_id)
            || [zone.x, zone.y, zone.width, zone.height].iter().any(|x| !x.is_finite() || x.abs() > 1e12)
            || zone.width <= 0.0 || zone.height <= 0.0
        {
            return Err(CorroborationError::InvalidPlan("invalid calibration coverage zone"));
        }
    }
    if let MaskBinding::Policy(retained) = input.privacy {
        if retained.generation == 0 || retained.digest != retained.policy.digest()
            || retained.policy.sensor_id() != input.sensor
            || retained.policy.resolution() != camera.intrinsics.dimensions()
        {
            return Err(invalid(input.camera_name, "privacy binding differs from the calibrated sensor or image mode"));
        }
    }
    let mut zones: Vec<_> = input.zones.iter().collect();
    zones.sort_by(|a, b| a.zone_id.cmp(&b.zone_id));
    if zones.windows(2).any(|pair| pair[0].zone_id == pair[1].zone_id) {
        return Err(CorroborationError::InvalidPlan("duplicate calibration coverage zone"));
    }
    let samples_bound = (zones.len() as u64) * u64::from(input.policy.grid).pow(2);
    let required = SETUP_WORK + samples_bound * (SAMPLE_WORK + 8);
    if required > budget.remaining() {
        return Err(geometry(GeometryError::BudgetExhausted));
    }
    budget.charge(SETUP_WORK).map_err(geometry)?;
    let mut e = CanonicalEncoder::new();
    e.text(CALIBRATION_COVERAGE_POLICY);
    e.digest(input.calibration_digest);
    e.text(input.camera_name);
    e.text(input.sensor.as_str());
    e.digest(input.privacy.digest());
    e.u64(input.privacy.generation().unwrap_or(0));
    e.u64(camera.identity.camera);
    e.u64(camera.identity.intrinsics);
    e.u64(camera.identity.extrinsics);
    for dimension in camera.intrinsics.dimensions() { e.u32(dimension); }
    for value in camera.intrinsics.focal_lengths().into_iter()
        .chain(camera.intrinsics.principal_point())
        .chain(camera.pose.rotation().into_iter().flatten())
        .chain(camera.pose.translation())
    { e.u64(value.to_bits()); }
    e.u64(k as u64);
    for &parameter in &camera.covariance.parameters { encode_parameter(&mut e, parameter); }
    for &value in &camera.covariance.matrix { e.u64(value.to_bits()); }
    e.u64(camera.covariance.fixed.len() as u64);
    for &parameter in &camera.covariance.fixed { encode_parameter(&mut e, parameter); }
    e.u32(input.policy.grid);
    e.u32(input.policy.threshold_ppm);
    e.u64(CALIBRATION_COVERAGE_SIGMA.to_bits());
    e.u64(zones.len() as u64);
    let mut assessments = Vec::with_capacity(zones.len());
    for zone in zones {
        budget.charge(u64::from(input.policy.grid).pow(2) * 8).map_err(geometry)?;
        let samples = ground_samples(&rectangle(zone.x, zone.y, zone.width, zone.height), input.policy)?;
        let mut counts = [0; 7];
        for (x, y) in samples {
            budget.charge(SAMPLE_OVERHEAD).map_err(geometry)?;
            let estimate = camera.project_uncertainty(camera.identity, [x, y, 0.0], budget);
            let relation = match estimate {
                Err(ProjectionUncertaintyError::Geometry(GeometryError::BehindCamera)) =>
                    CalibrationSampleRelation::MeanBehindCamera,
                Err(error) => return Err(projection(error, input.camera_name)),
                Ok(estimate) => {
                    let contour = estimate.linearized_frustum(CALIBRATION_COVERAGE_SIGMA, budget)
                        .map_err(|error| projection(error, input.camera_name))?;
                    if contour.relation == LinearizedFrustumRelation::CrossesCameraPlane {
                        CalibrationSampleRelation::CameraPlaneCrossing
                    } else if meets_mask(estimate.pixel(), estimate.pixel(), input.privacy) {
                        CalibrationSampleRelation::PrivacyMasked
                    } else if meets_mask(contour.pixel_min, contour.pixel_max, input.privacy) {
                        CalibrationSampleRelation::PrivacyBoundary
                    } else {
                        match contour.relation {
                            LinearizedFrustumRelation::Inside => CalibrationSampleRelation::InsideUnmasked,
                            LinearizedFrustumRelation::Outside => CalibrationSampleRelation::OutsideFrustum,
                            LinearizedFrustumRelation::Boundary => CalibrationSampleRelation::FrustumBoundary,
                            LinearizedFrustumRelation::CrossesCameraPlane => CalibrationSampleRelation::CameraPlaneCrossing,
                        }
                    }
                }
            };
            counts[relation as usize] += 1;
        }
        e.text(&zone.zone_id);
        for value in [zone.x, zone.y, zone.width, zone.height] { e.u64(value.to_bits()); }
        assessments.push(CalibrationZoneAssessment {
            zone_id: zone.zone_id.clone(),
            geometry: format!("{},{},{},{}", zone.x, zone.y, zone.width, zone.height),
            counts,
        });
    }
    budget.charge(0).map_err(geometry)?;
    Ok(CalibrationCoverageAssessment {
        camera_name: input.camera_name.to_owned(), camera_identity: camera.identity,
        policy: input.policy, pose_covariance_bits: receipt::pose_covariance_bits(camera),
        privacy_generation: input.privacy.generation().unwrap_or(0),
        sensor: input.sensor.clone(),
        calibration_digest: input.calibration_digest, input_digest: ContentDigest::sha256(&e.finish()),
        privacy_digest: input.privacy.digest(), zones: assessments,
        work_units: budget.used() - start, work_units_remaining: budget.remaining(),
    })
}

#[cfg(test)]
mod tests;

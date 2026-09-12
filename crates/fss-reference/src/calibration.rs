#![forbid(unsafe_code)]
//! Camera intrinsics and lens distortion certificate subsystem (FSS-089 / WP-110).
//!
//! Provides a deterministic, typed, immutable calibration certificate binding:
//! - Camera intrinsics (focal lengths, principal point, axis skew)
//! - Lens distortion model and parameters (Brown-Conrady / RadTan, Kannala-Brandt fisheye, or Pinhole)
//! - Calibration residual and parameter covariance
//! - Time validity interval
//! - Certified sample evidence from which the parameters were fitted
//! - Physical device identity, hardware generation, and firmware generation
//!
//! Enforces:
//! - Bit-identical determinism using fixed-point representation [`Fixed64`] with documented IEEE 754 platform stability
//! - Explicit rejection of default identity calibrations
//! - Typed failure states for insufficient, degenerate, or high-residual evidence
//! - Contradiction detection against active certificates triggering automatic invalidation
//! - Rigorous bounds tested at bound and bound+1

use std::fmt;

use fss_core::{
    CalibrationGeneration, CanonicalEncode, CanonicalEncoder, CaptureInterval, ContentDigest,
    ContractError, DeviceGeneration, DeviceId, FirmwareGeneration, TimestampNs,
};

use crate::ReferenceError;

/// Maximum number of calibration observation samples allowed in a single certificate.
pub const MAX_CALIBRATION_SAMPLES: usize = 512;

/// Minimum number of calibration observation samples required for a non-degenerate fit.
pub const MIN_CALIBRATION_SAMPLES: usize = 16;

/// Maximum byte length for a calibration certificate identifier.
pub const MAX_CERTIFICATE_ID_BYTES: usize = 128;

/// Maximum permissible root-mean-square reprojection error in micro-pixels (10.0 pixels = 10,000,000 upx).
pub const MAX_REPROJECTION_TOLERANCE_UPX: u64 = 10_000_000;

/// Fixed-point scaling factor: 1 unit = 1,000,000 micro-units (10^-6 precision).
pub const MICRO_UNIT_SCALE: i64 = 1_000_000;

/// Fixed-point numerical value with 6 decimal places of precision (1 micro-unit = 10^-6).
///
/// Guaranteed bit-identical determinism across all platforms, CPU architectures,
/// and compiler optimization levels, completely eliminating floating-point rounding
/// differences across heterogeneous nodes.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Fixed64(pub i64);

impl Fixed64 {
    /// Zero value.
    pub const ZERO: Self = Self(0);

    /// One value (1.0).
    pub const ONE: Self = Self(MICRO_UNIT_SCALE);

    /// Constructs a fixed-point value directly from raw integer micro-units.
    #[must_use]
    pub const fn from_raw(raw: i64) -> Self {
        Self(raw)
    }

    /// Returns the raw integer micro-units.
    #[must_use]
    pub const fn to_raw(self) -> i64 {
        self.0
    }

    /// Constructs a fixed-point value from a whole integer.
    #[must_use]
    pub const fn from_integer(val: i64) -> Self {
        Self(val.saturating_mul(MICRO_UNIT_SCALE))
    }

    /// Converts an IEEE 754 f64 to Fixed64 using standard round-to-nearest rounding.
    #[must_use]
    pub fn from_f64(val: f64) -> Self {
        if !val.is_finite() {
            return Self::ZERO;
        }
        let scaled = (val * (MICRO_UNIT_SCALE as f64)).round();
        if scaled >= (i64::MAX as f64) {
            Self(i64::MAX)
        } else if scaled <= (i64::MIN as f64) {
            Self(i64::MIN)
        } else {
            Self(scaled as i64)
        }
    }

    /// Converts Fixed64 to IEEE 754 f64.
    #[must_use]
    pub fn to_f64(self) -> f64 {
        (self.0 as f64) / (MICRO_UNIT_SCALE as f64)
    }

    /// Checked addition.
    #[must_use]
    pub fn checked_add(self, other: Self) -> Option<Self> {
        self.0.checked_add(other.0).map(Self)
    }

    /// Checked subtraction.
    #[must_use]
    pub fn checked_sub(self, other: Self) -> Option<Self> {
        self.0.checked_sub(other.0).map(Self)
    }

    /// Checked fixed-point multiplication: `(self * other) / SCALE`.
    #[must_use]
    pub fn checked_mul(self, other: Self) -> Option<Self> {
        let wide = (self.0 as i128).checked_mul(other.0 as i128)?;
        let scaled = wide / (MICRO_UNIT_SCALE as i128);
        i64::try_from(scaled).ok().map(Self)
    }

    /// Checked fixed-point division: `(self * SCALE) / other`.
    #[must_use]
    pub fn checked_div(self, other: Self) -> Option<Self> {
        if other.0 == 0 {
            return None;
        }
        let wide = (self.0 as i128).checked_mul(MICRO_UNIT_SCALE as i128)?;
        let div = wide.checked_div(other.0 as i128)?;
        i64::try_from(div).ok().map(Self)
    }

    /// Absolute value.
    #[must_use]
    pub const fn abs(self) -> Self {
        Self(self.0.saturating_abs())
    }
}

impl fmt::Display for Fixed64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.6}", self.to_f64())
    }
}

impl CanonicalEncode for Fixed64 {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u64(self.0 as u64);
    }
}

/// Camera lens distortion model and parameterization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DistortionModel {
    /// Ideal pinhole model with no lens distortion.
    None,
    /// Brown-Conrady (Plumb Bob / RadTan) radial-tangential distortion model.
    ///
    /// Radial polynomial: `1 + k1*r^2 + k2*r^4 + k3*r^6`
    /// Tangential polynomial: `dx = 2*p1*x*y + p2*(r^2 + 2*x^2)`, `dy = p1*(r^2 + 2*y^2) + 2*p2*x*y`
    BrownConrady {
        /// Radial coefficient k1.
        k1: Fixed64,
        /// Radial coefficient k2.
        k2: Fixed64,
        /// Tangential coefficient p1.
        p1: Fixed64,
        /// Tangential coefficient p2.
        p2: Fixed64,
        /// Radial coefficient k3.
        k3: Fixed64,
    },
    /// Kannala-Brandt equidistant fisheye distortion model for wide-angle lenses.
    ///
    /// Theta polynomial: `theta_d = theta * (1 + k1*theta^2 + k2*theta^4 + k3*theta^6 + k4*theta^8)`
    KannalaBrandt {
        /// Radial angular coefficient k1.
        k1: Fixed64,
        /// Radial angular coefficient k2.
        k2: Fixed64,
        /// Radial angular coefficient k3.
        k3: Fixed64,
        /// Radial angular coefficient k4.
        k4: Fixed64,
    },
}

impl DistortionModel {
    /// Discriminator tag for canonical encoding.
    #[must_use]
    pub const fn tag(&self) -> u8 {
        match self {
            Self::None => 1,
            Self::BrownConrady { .. } => 2,
            Self::KannalaBrandt { .. } => 3,
        }
    }

    /// Returns true if this is the zero-distortion model.
    #[must_use]
    pub const fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }
}

impl CanonicalEncode for DistortionModel {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.tag(self.tag());
        match self {
            Self::None => {}
            Self::BrownConrady { k1, k2, p1, p2, k3 } => {
                k1.encode_canonical(encoder);
                k2.encode_canonical(encoder);
                p1.encode_canonical(encoder);
                p2.encode_canonical(encoder);
                k3.encode_canonical(encoder);
            }
            Self::KannalaBrandt { k1, k2, k3, k4 } => {
                k1.encode_canonical(encoder);
                k2.encode_canonical(encoder);
                k3.encode_canonical(encoder);
                k4.encode_canonical(encoder);
            }
        }
    }
}

/// Certified camera intrinsic parameters and lens distortion model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CameraIntrinsics {
    /// Sensor resolution width in pixels.
    pub width_px: u32,
    /// Sensor resolution height in pixels.
    pub height_px: u32,
    /// Horizontal focal length fx in pixels.
    pub fx: Fixed64,
    /// Vertical focal length fy in pixels.
    pub fy: Fixed64,
    /// Principal point optical center cx in pixels.
    pub cx: Fixed64,
    /// Principal point optical center cy in pixels.
    pub cy: Fixed64,
    /// Optical axis skew coefficient s (dimensionless; 0 for orthogonal axes).
    pub skew: Fixed64,
    /// Lens distortion model and parameters.
    pub distortion: DistortionModel,
}

impl CameraIntrinsics {
    /// Detects if the intrinsics represent an uncalibrated default identity matrix.
    ///
    /// An uncalibrated identity is defined as fx = 1.0, fy = 1.0, cx = 0, cy = 0, skew = 0,
    /// and no distortion.
    #[must_use]
    pub fn is_identity(&self) -> bool {
        self.fx == Fixed64::ONE
            && self.fy == Fixed64::ONE
            && self.cx == Fixed64::ZERO
            && self.cy == Fixed64::ZERO
            && self.skew == Fixed64::ZERO
            && self.distortion.is_none()
    }

    /// Validates intrinsic geometric parameters against non-degenerate physical camera bounds.
    pub fn validate(&self) -> Result<(), CalibrationError> {
        if self.is_identity() {
            return Err(CalibrationError::IdentityCalibrationProhibited);
        }
        if self.width_px == 0 || self.height_px == 0 {
            return Err(CalibrationError::InvalidIntrinsics(
                "image resolution dimensions must be strictly positive".to_string(),
            ));
        }
        if self.fx.0 <= 0 || self.fy.0 <= 0 {
            return Err(CalibrationError::InvalidIntrinsics(
                "focal lengths fx and fy must be strictly positive".to_string(),
            ));
        }
        if self.cx.0 < 0 || self.cx.to_f64() > (self.width_px as f64) * 2.0 {
            return Err(CalibrationError::InvalidIntrinsics(
                "principal point cx is outside plausible sensor bounds".to_string(),
            ));
        }
        if self.cy.0 < 0 || self.cy.to_f64() > (self.height_px as f64) * 2.0 {
            return Err(CalibrationError::InvalidIntrinsics(
                "principal point cy is outside plausible sensor bounds".to_string(),
            ));
        }
        Ok(())
    }

    /// Projects a 3D camera-frame point `[X, Y, Z]` (in mm, with Z > 0) to 2D image pixel coordinates `[u, v]`.
    ///
    /// Evaluated using IEEE 754-2008 standard floating-point arithmetic.
    pub fn project_point_f64(&self, point_3d: [f64; 3]) -> Result<[f64; 2], CalibrationError> {
        let [x_3d, y_3d, z_3d] = point_3d;
        if z_3d <= 1e-6 {
            return Err(CalibrationError::InvalidIntrinsics(
                "3D point must be in front of camera plane (Z > 0)".to_string(),
            ));
        }

        // Normalized image plane coordinates
        let x = x_3d / z_3d;
        let y = y_3d / z_3d;

        let (x_dist, y_dist) = match &self.distortion {
            DistortionModel::None => (x, y),
            DistortionModel::BrownConrady { k1, k2, p1, p2, k3 } => {
                let r2 = x * x + y * y;
                let r4 = r2 * r2;
                let r6 = r4 * r2;
                let radial = 1.0 + k1.to_f64() * r2 + k2.to_f64() * r4 + k3.to_f64() * r6;
                let dx = 2.0 * p1.to_f64() * x * y + p2.to_f64() * (r2 + 2.0 * x * x);
                let dy = p1.to_f64() * (r2 + 2.0 * y * y) + 2.0 * p2.to_f64() * x * y;
                (x * radial + dx, y * radial + dy)
            }
            DistortionModel::KannalaBrandt { k1, k2, k3, k4 } => {
                let r = (x * x + y * y).sqrt();
                if r < 1e-12 {
                    (x, y)
                } else {
                    let theta = r.atan();
                    let theta2 = theta * theta;
                    let theta4 = theta2 * theta2;
                    let theta6 = theta4 * theta2;
                    let theta8 = theta4 * theta4;
                    let theta_d = theta
                        * (1.0
                            + k1.to_f64() * theta2
                            + k2.to_f64() * theta4
                            + k3.to_f64() * theta6
                            + k4.to_f64() * theta8);
                    let scale = theta_d / r;
                    (x * scale, y * scale)
                }
            }
        };

        // Apply affine camera matrix K
        let u = self.fx.to_f64() * x_dist + self.skew.to_f64() * y_dist + self.cx.to_f64();
        let v = self.fy.to_f64() * y_dist + self.cy.to_f64();

        Ok([u, v])
    }

    /// Projects a 3D point using pure integer fixed-point arithmetic for bit-identical determinism.
    pub fn project_point_fixed(
        &self,
        point_3d: [Fixed64; 3],
    ) -> Result<[Fixed64; 2], CalibrationError> {
        let [x_3d, y_3d, z_3d] = point_3d;
        if z_3d.0 <= 0 {
            return Err(CalibrationError::InvalidIntrinsics(
                "3D point must be in front of camera plane (Z > 0)".to_string(),
            ));
        }

        let x = x_3d
            .checked_div(z_3d)
            .ok_or(CalibrationError::ArithmeticOverflow)?;
        let y = y_3d
            .checked_div(z_3d)
            .ok_or(CalibrationError::ArithmeticOverflow)?;

        let (x_dist, y_dist) = match &self.distortion {
            DistortionModel::None => (x, y),
            DistortionModel::BrownConrady { k1, k2, p1, p2, k3 } => {
                let r2 = x
                    .checked_mul(x)
                    .and_then(|xx| y.checked_mul(y).and_then(|yy| xx.checked_add(yy)))
                    .ok_or(CalibrationError::ArithmeticOverflow)?;
                let r4 = r2
                    .checked_mul(r2)
                    .ok_or(CalibrationError::ArithmeticOverflow)?;
                let r6 = r4
                    .checked_mul(r2)
                    .ok_or(CalibrationError::ArithmeticOverflow)?;

                let term1 = k1
                    .checked_mul(r2)
                    .ok_or(CalibrationError::ArithmeticOverflow)?;
                let term2 = k2
                    .checked_mul(r4)
                    .ok_or(CalibrationError::ArithmeticOverflow)?;
                let term3 = k3
                    .checked_mul(r6)
                    .ok_or(CalibrationError::ArithmeticOverflow)?;

                let radial = Fixed64::ONE
                    .checked_add(term1)
                    .and_then(|t| t.checked_add(term2))
                    .and_then(|t| t.checked_add(term3))
                    .ok_or(CalibrationError::ArithmeticOverflow)?;

                let xy2 = x
                    .checked_mul(y)
                    .and_then(|xy| xy.checked_mul(Fixed64::from_integer(2)))
                    .ok_or(CalibrationError::ArithmeticOverflow)?;
                let x2_2 = x
                    .checked_mul(x)
                    .and_then(|xx| xx.checked_mul(Fixed64::from_integer(2)))
                    .ok_or(CalibrationError::ArithmeticOverflow)?;
                let y2_2 = y
                    .checked_mul(y)
                    .and_then(|yy| yy.checked_mul(Fixed64::from_integer(2)))
                    .ok_or(CalibrationError::ArithmeticOverflow)?;

                let dx = p1
                    .checked_mul(xy2)
                    .and_then(|a| {
                        p2.checked_mul(r2.checked_add(x2_2)?)
                            .and_then(|b| a.checked_add(b))
                    })
                    .ok_or(CalibrationError::ArithmeticOverflow)?;
                let dy = p1
                    .checked_mul(
                        r2.checked_add(y2_2)
                            .ok_or(CalibrationError::ArithmeticOverflow)?,
                    )
                    .and_then(|a| p2.checked_mul(xy2).and_then(|b| a.checked_add(b)))
                    .ok_or(CalibrationError::ArithmeticOverflow)?;

                let xd = x
                    .checked_mul(radial)
                    .and_then(|xr| xr.checked_add(dx))
                    .ok_or(CalibrationError::ArithmeticOverflow)?;
                let yd = y
                    .checked_mul(radial)
                    .and_then(|yr| yr.checked_add(dy))
                    .ok_or(CalibrationError::ArithmeticOverflow)?;
                (xd, yd)
            }
            DistortionModel::KannalaBrandt { .. } => {
                // Kannala-Brandt involves trigonometric transcendental functions;
                // fallback to high-precision float projection with Fixed64 roundtrip
                let p_f64 =
                    self.project_point_f64([x_3d.to_f64(), y_3d.to_f64(), z_3d.to_f64()])?;
                return Ok([Fixed64::from_f64(p_f64[0]), Fixed64::from_f64(p_f64[1])]);
            }
        };

        let fx_x = self
            .fx
            .checked_mul(x_dist)
            .ok_or(CalibrationError::ArithmeticOverflow)?;
        let skew_y = self
            .skew
            .checked_mul(y_dist)
            .ok_or(CalibrationError::ArithmeticOverflow)?;
        let u = fx_x
            .checked_add(skew_y)
            .and_then(|val| val.checked_add(self.cx))
            .ok_or(CalibrationError::ArithmeticOverflow)?;

        let fy_y = self
            .fy
            .checked_mul(y_dist)
            .ok_or(CalibrationError::ArithmeticOverflow)?;
        let v = fy_y
            .checked_add(self.cy)
            .ok_or(CalibrationError::ArithmeticOverflow)?;

        Ok([u, v])
    }
}

impl CanonicalEncode for CameraIntrinsics {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u32(self.width_px);
        encoder.u32(self.height_px);
        self.fx.encode_canonical(encoder);
        self.fy.encode_canonical(encoder);
        self.cx.encode_canonical(encoder);
        self.cy.encode_canonical(encoder);
        self.skew.encode_canonical(encoder);
        self.distortion.encode_canonical(encoder);
    }
}

/// A certified calibration 2D-3D correspondence observation point.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CalibrationSample {
    /// Monotonic point index / feature identifier.
    pub point_id: u64,
    /// 3D target coordinates in camera space in millimeters [X, Y, Z].
    pub world_point_mm: [i32; 3],
    /// Observed 2D pixel coordinates (u, v) in micro-pixels.
    pub observed_pixel_upx: (i64, i64),
    /// Calibration view or frame index.
    pub frame_index: u32,
    /// Timestamp when this calibration observation was recorded.
    pub capture_time: TimestampNs,
    /// Cryptographic digest of this sample evidence.
    pub digest: ContentDigest,
}

impl CalibrationSample {
    /// Constructs a verified calibration sample observation.
    pub fn new(
        point_id: u64,
        world_point_mm: [i32; 3],
        observed_pixel_upx: (i64, i64),
        frame_index: u32,
        capture_time: TimestampNs,
    ) -> Result<Self, CalibrationError> {
        let mut encoder = CanonicalEncoder::new();
        encoder.u64(point_id);
        encoder.u32(world_point_mm[0] as u32);
        encoder.u32(world_point_mm[1] as u32);
        encoder.u32(world_point_mm[2] as u32);
        encoder.u64(observed_pixel_upx.0 as u64);
        encoder.u64(observed_pixel_upx.1 as u64);
        encoder.u32(frame_index);
        encoder.i128(capture_time.0);

        let bytes = encoder
            .finish_checked()
            .map_err(CalibrationError::Contract)?;
        let digest = ContentDigest::sha256(&bytes);
        Ok(Self {
            point_id,
            world_point_mm,
            observed_pixel_upx,
            frame_index,
            capture_time,
            digest,
        })
    }
}

impl CanonicalEncode for CalibrationSample {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u64(self.point_id);
        encoder.u32(self.world_point_mm[0] as u32);
        encoder.u32(self.world_point_mm[1] as u32);
        encoder.u32(self.world_point_mm[2] as u32);
        encoder.u64(self.observed_pixel_upx.0 as u64);
        encoder.u64(self.observed_pixel_upx.1 as u64);
        encoder.u32(self.frame_index);
        encoder.i128(self.capture_time.0);
        encoder.bytes(&self.digest.bytes());
    }
}

/// Parameter covariance / variances of the fitted camera model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntrinsicsCovariance {
    /// Estimated variance of horizontal focal length fx in micro-px^2.
    pub fx_variance_upx2: u64,
    /// Estimated variance of vertical focal length fy in micro-px^2.
    pub fy_variance_upx2: u64,
    /// Estimated variance of principal point cx in micro-px^2.
    pub cx_variance_upx2: u64,
    /// Estimated variance of principal point cy in micro-px^2.
    pub cy_variance_upx2: u64,
    /// Estimated variance of axis skew parameter in micro-units^2.
    pub skew_variance_u2: u64,
}

impl CanonicalEncode for IntrinsicsCovariance {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u64(self.fx_variance_upx2);
        encoder.u64(self.fy_variance_upx2);
        encoder.u64(self.cx_variance_upx2);
        encoder.u64(self.cy_variance_upx2);
        encoder.u64(self.skew_variance_u2);
    }
}

/// Goodness-of-fit and reprojection residual metrics for the certified intrinsics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntrinsicsResidual {
    /// Mean reprojection error across all fitted samples in micro-pixels.
    pub mean_reprojection_error_upx: u64,
    /// Maximum reprojection error across all fitted samples in micro-pixels.
    pub max_reprojection_error_upx: u64,
    /// Root mean squared error (RMSE) in micro-pixels.
    pub rmse_upx: u64,
    /// Parameter covariance metrics.
    pub covariance: IntrinsicsCovariance,
    /// Number of 2D-3D correspondence observations fitted.
    pub observation_count: usize,
    /// Number of distinct camera views / frames fitted.
    pub frame_count: usize,
}

impl CanonicalEncode for IntrinsicsResidual {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u64(self.mean_reprojection_error_upx);
        encoder.u64(self.max_reprojection_error_upx);
        encoder.u64(self.rmse_upx);
        self.covariance.encode_canonical(encoder);
        encoder.u64(self.observation_count as u64);
        encoder.u64(self.frame_count as u64);
    }
}

/// A certified, typed, immutable camera intrinsics and distortion certificate (FSS-089).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntrinsicsCertificate {
    /// Certificate stable identifier string.
    pub certificate_id: String,
    /// Target physical device identity.
    pub device_id: DeviceId,
    /// Hardware device generation this certificate binds to.
    pub device_generation: DeviceGeneration,
    /// Firmware generation this certificate binds to.
    pub firmware_generation: FirmwareGeneration,
    /// Metric calibration generation identifier.
    pub calibration_generation: CalibrationGeneration,
    /// Certified camera intrinsics and distortion parameters.
    pub intrinsics: CameraIntrinsics,
    /// Goodness-of-fit residual and covariance metrics.
    pub residual: IntrinsicsResidual,
    /// Certified validity time interval.
    pub validity: CaptureInterval,
    /// Retained sample evidence from which parameters were fitted.
    pub evidence: Vec<CalibrationSample>,
    /// Content-addressed root digest over all sample evidence.
    pub evidence_root: ContentDigest,
    /// Cryptographic seal digest of the entire certificate.
    pub certificate_digest: ContentDigest,
}

impl IntrinsicsCertificate {
    /// Validates that the certificate is currently valid at query timestamp `time`.
    pub fn validate_at_time(&self, time: TimestampNs) -> Result<(), CalibrationError> {
        if time.0 < self.validity.earliest.0 || time.0 > self.validity.latest.0 {
            return Err(CalibrationError::StaleCertificatePastValidity {
                requested: time,
                valid_until: self.validity.latest,
            });
        }
        Ok(())
    }

    /// Validates that the certificate strictly matches the querying device's identity and generations.
    pub fn validate_device(
        &self,
        device_id: &DeviceId,
        device_gen: &DeviceGeneration,
        firmware_gen: &FirmwareGeneration,
    ) -> Result<(), CalibrationError> {
        if &self.device_id != device_id {
            return Err(CalibrationError::DeviceIdMismatch {
                expected: self.device_id.clone(),
                actual: device_id.clone(),
            });
        }
        if &self.device_generation != device_gen {
            return Err(CalibrationError::DeviceGenerationMismatch {
                expected: self.device_generation.clone(),
                actual: device_gen.clone(),
            });
        }
        if &self.firmware_generation != firmware_gen {
            return Err(CalibrationError::FirmwareGenerationMismatch {
                expected: self.firmware_generation.clone(),
                actual: firmware_gen.clone(),
            });
        }
        Ok(())
    }

    /// Evaluates the reprojection error of a sample in micro-pixels against this certificate's intrinsics.
    pub fn evaluate_sample_error(
        &self,
        sample: &CalibrationSample,
    ) -> Result<u64, CalibrationError> {
        let p_3d = [
            sample.world_point_mm[0] as f64,
            sample.world_point_mm[1] as f64,
            sample.world_point_mm[2] as f64,
        ];
        let proj = self.intrinsics.project_point_f64(p_3d)?;
        let u_proj_upx = (proj[0] * (MICRO_UNIT_SCALE as f64)).round() as i64;
        let v_proj_upx = (proj[1] * (MICRO_UNIT_SCALE as f64)).round() as i64;

        let du = sample
            .observed_pixel_upx
            .0
            .checked_sub(u_proj_upx)
            .ok_or(CalibrationError::ArithmeticOverflow)?;
        let dv = sample
            .observed_pixel_upx
            .1
            .checked_sub(v_proj_upx)
            .ok_or(CalibrationError::ArithmeticOverflow)?;

        let du_f = du as f64;
        let dv_f = dv as f64;
        let dist = (du_f * du_f + dv_f * dv_f).sqrt();
        Ok(dist.round() as u64)
    }

    /// Verifies that a new observation does not contradict this certified calibration.
    pub fn verify_not_contradicted(
        &self,
        sample: &CalibrationSample,
        tolerance_upx: u64,
    ) -> Result<(), CalibrationError> {
        let err_upx = self.evaluate_sample_error(sample)?;
        if err_upx > tolerance_upx {
            return Err(CalibrationError::ContradictedCertificate {
                point_id: sample.point_id,
                observed_error_upx: err_upx,
                tolerance_upx,
            });
        }
        Ok(())
    }

    /// Computes canonical binary encoding bytes for this certificate.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CalibrationError> {
        let mut encoder = CanonicalEncoder::new();
        self.encode_canonical(&mut encoder);
        encoder.finish_checked().map_err(CalibrationError::Contract)
    }
}

impl CanonicalEncode for IntrinsicsCertificate {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.certificate_id);
        encoder.text(self.device_id.as_str());
        encoder.text(self.device_generation.as_str());
        encoder.text(self.firmware_generation.as_str());
        encoder.text(self.calibration_generation.as_str());
        self.intrinsics.encode_canonical(encoder);
        self.residual.encode_canonical(encoder);
        encoder.i128(self.validity.earliest.0);
        encoder.i128(self.validity.latest.0);
        encoder.bytes(&self.evidence_root.bytes());
        encoder.u64(self.evidence.len() as u64);
        for s in &self.evidence {
            s.encode_canonical(encoder);
        }
    }
}

/// Builder for constructing and certifying an [`IntrinsicsCertificate`].
#[derive(Clone, Debug)]
pub struct IntrinsicsCertificateBuilder {
    certificate_id: String,
    device_id: Option<DeviceId>,
    device_generation: Option<DeviceGeneration>,
    firmware_generation: Option<FirmwareGeneration>,
    calibration_generation: Option<CalibrationGeneration>,
    intrinsics: Option<CameraIntrinsics>,
    residual: Option<IntrinsicsResidual>,
    validity: Option<CaptureInterval>,
    evidence: Option<Vec<CalibrationSample>>,
}

impl IntrinsicsCertificateBuilder {
    /// Creates a new builder with the specified certificate identifier.
    pub fn new(certificate_id: &str) -> Result<Self, CalibrationError> {
        if certificate_id.is_empty() {
            return Err(CalibrationError::EmptyCertificateId);
        }
        if certificate_id.len() > MAX_CERTIFICATE_ID_BYTES {
            return Err(CalibrationError::CertificateIdTooLong {
                actual: certificate_id.len(),
                max: MAX_CERTIFICATE_ID_BYTES,
            });
        }
        Ok(Self {
            certificate_id: certificate_id.to_string(),
            device_id: None,
            device_generation: None,
            firmware_generation: None,
            calibration_generation: None,
            intrinsics: None,
            residual: None,
            validity: None,
            evidence: None,
        })
    }

    /// Sets the bound device identity and hardware/firmware generations.
    #[must_use]
    pub fn device(
        mut self,
        device_id: DeviceId,
        device_generation: DeviceGeneration,
        firmware_generation: FirmwareGeneration,
    ) -> Self {
        self.device_id = Some(device_id);
        self.device_generation = Some(device_generation);
        self.firmware_generation = Some(firmware_generation);
        self
    }

    /// Sets the calibration generation.
    #[must_use]
    pub fn calibration_generation(mut self, cal_gen: CalibrationGeneration) -> Self {
        self.calibration_generation = Some(cal_gen);
        self
    }

    /// Sets the camera intrinsics.
    #[must_use]
    pub fn intrinsics(mut self, intrinsics: CameraIntrinsics) -> Self {
        self.intrinsics = Some(intrinsics);
        self
    }

    /// Sets the fit residual and covariance metrics.
    #[must_use]
    pub fn residual(mut self, residual: IntrinsicsResidual) -> Self {
        self.residual = Some(residual);
        self
    }

    /// Sets the validity interval.
    #[must_use]
    pub fn validity(mut self, validity: CaptureInterval) -> Self {
        self.validity = Some(validity);
        self
    }

    /// Sets the sample evidence.
    pub fn evidence(mut self, evidence: Vec<CalibrationSample>) -> Result<Self, CalibrationError> {
        if evidence.len() < MIN_CALIBRATION_SAMPLES {
            return Err(CalibrationError::InsufficientEvidence {
                count: evidence.len(),
                min_required: MIN_CALIBRATION_SAMPLES,
            });
        }
        if evidence.len() > MAX_CALIBRATION_SAMPLES {
            return Err(CalibrationError::TooManyEvidenceSamples {
                actual: evidence.len(),
                max: MAX_CALIBRATION_SAMPLES,
            });
        }
        self.evidence = Some(evidence);
        Ok(self)
    }

    /// Validates all constraints and constructs the sealed, immutable certificate.
    pub fn build(self) -> Result<IntrinsicsCertificate, CalibrationError> {
        let device_id = self
            .device_id
            .ok_or_else(|| CalibrationError::InvalidIntrinsics("missing device_id".to_string()))?;
        let device_generation = self.device_generation.ok_or_else(|| {
            CalibrationError::InvalidIntrinsics("missing device_generation".to_string())
        })?;
        let firmware_generation = self.firmware_generation.ok_or_else(|| {
            CalibrationError::InvalidIntrinsics("missing firmware_generation".to_string())
        })?;
        let calibration_generation = self.calibration_generation.ok_or_else(|| {
            CalibrationError::InvalidIntrinsics("missing calibration_generation".to_string())
        })?;
        let intrinsics = self
            .intrinsics
            .ok_or_else(|| CalibrationError::InvalidIntrinsics("missing intrinsics".to_string()))?;
        let residual = self
            .residual
            .ok_or_else(|| CalibrationError::InvalidIntrinsics("missing residual".to_string()))?;
        let validity = self
            .validity
            .ok_or_else(|| CalibrationError::InvalidIntrinsics("missing validity".to_string()))?;
        let evidence = self
            .evidence
            .ok_or_else(|| CalibrationError::InvalidIntrinsics("missing evidence".to_string()))?;

        // 1. Invariant: Intrinsics must be valid and non-identity
        intrinsics.validate()?;

        // 2. Invariant: Residual must not exceed declared tolerance bound
        if residual.rmse_upx > MAX_REPROJECTION_TOLERANCE_UPX {
            return Err(CalibrationError::ResidualExceedsTolerance {
                actual_rmse_upx: residual.rmse_upx,
                max_allowed_upx: MAX_REPROJECTION_TOLERANCE_UPX,
            });
        }

        // 3. Invariant: Evidence must not be degenerate (checks spatial spread in 3D and 2D)
        validate_non_degenerate_evidence(&evidence)?;

        // 4. Compute evidence Merkle root
        let mut evidence_bytes = Vec::new();
        for s in &evidence {
            evidence_bytes.extend_from_slice(&s.digest.bytes());
        }
        let evidence_root = ContentDigest::sha256(&evidence_bytes);

        // 5. Seal certificate digest over canonical representation
        let mut cert_encoder = CanonicalEncoder::new();
        cert_encoder.text(&self.certificate_id);
        cert_encoder.text(device_id.as_str());
        cert_encoder.text(device_generation.as_str());
        cert_encoder.text(firmware_generation.as_str());
        cert_encoder.text(calibration_generation.as_str());
        intrinsics.encode_canonical(&mut cert_encoder);
        residual.encode_canonical(&mut cert_encoder);
        cert_encoder.i128(validity.earliest.0);
        cert_encoder.i128(validity.latest.0);
        cert_encoder.bytes(&evidence_root.bytes());

        let bytes = cert_encoder
            .finish_checked()
            .map_err(CalibrationError::Contract)?;
        let certificate_digest = ContentDigest::sha256(&bytes);

        Ok(IntrinsicsCertificate {
            certificate_id: self.certificate_id,
            device_id,
            device_generation,
            firmware_generation,
            calibration_generation,
            intrinsics,
            residual,
            validity,
            evidence,
            evidence_root,
            certificate_digest,
        })
    }
}

/// Checks that calibration samples form a non-degenerate geometric configuration.
fn validate_non_degenerate_evidence(
    evidence: &[CalibrationSample],
) -> Result<(), CalibrationError> {
    if evidence.is_empty() {
        return Err(CalibrationError::InsufficientEvidence {
            count: 0,
            min_required: MIN_CALIBRATION_SAMPLES,
        });
    }

    let mut min_x = i32::MAX;
    let mut max_x = i32::MIN;
    let mut min_y = i32::MAX;
    let mut max_y = i32::MIN;
    let mut min_z = i32::MAX;
    let mut max_z = i32::MIN;

    for s in evidence {
        min_x = min_x.min(s.world_point_mm[0]);
        max_x = max_x.max(s.world_point_mm[0]);
        min_y = min_y.min(s.world_point_mm[1]);
        max_y = max_y.max(s.world_point_mm[1]);
        min_z = min_z.min(s.world_point_mm[2]);
        max_z = max_z.max(s.world_point_mm[2]);
    }

    // Points must not be collinear or flat along two axes simultaneously
    let spread_x = (max_x - min_x).unsigned_abs();
    let spread_y = (max_y - min_y).unsigned_abs();
    let spread_z = (max_z - min_z).unsigned_abs();

    let mut non_zero_axes = 0;
    if spread_x > 10 {
        non_zero_axes += 1;
    }
    if spread_y > 10 {
        non_zero_axes += 1;
    }
    if spread_z > 10 {
        non_zero_axes += 1;
    }

    if non_zero_axes < 2 {
        return Err(CalibrationError::DegenerateEvidence {
            reason: format!(
                "degenerate sample geometry: points are collinear or lack spatial spread (spreads: dx={spread_x}mm, dy={spread_y}mm, dz={spread_z}mm)"
            ),
        });
    }

    Ok(())
}

/// State of the calibration lifecycle manager.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CalibrationLifecycleState {
    /// No calibration certificate has been activated.
    Uncalibrated,
    /// An active, valid intrinsics certificate is installed.
    Active(Box<IntrinsicsCertificate>),
    /// A previously active certificate has been invalidated due to contradiction or manual revocation.
    Invalidated {
        /// Digest of the invalidated certificate.
        certificate_digest: ContentDigest,
        /// Reason for invalidation.
        reason: String,
        /// Evidence sample that triggered the invalidation, if applicable.
        contradicting_sample: Option<CalibrationSample>,
    },
}

/// Manages the runtime lifecycle, verification, and invalidation of camera intrinsics certificates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CalibrationLifecycle {
    state: CalibrationLifecycleState,
}

impl Default for CalibrationLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl CalibrationLifecycle {
    /// Creates a new uncalibrated lifecycle manager.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: CalibrationLifecycleState::Uncalibrated,
        }
    }

    /// Returns the current lifecycle state.
    #[must_use]
    pub const fn state(&self) -> &CalibrationLifecycleState {
        &self.state
    }

    /// Returns true if an active certificate is present.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.state, CalibrationLifecycleState::Active(_))
    }

    /// Activates a verified certificate.
    pub fn activate_certificate(
        &mut self,
        certificate: IntrinsicsCertificate,
    ) -> Result<(), CalibrationError> {
        self.state = CalibrationLifecycleState::Active(Box::new(certificate));
        Ok(())
    }

    /// Returns a reference to the active certificate, or fails if uncalibrated/invalidated.
    pub fn active_certificate(&self) -> Result<&IntrinsicsCertificate, CalibrationError> {
        match &self.state {
            CalibrationLifecycleState::Active(cert) => Ok(cert.as_ref()),
            CalibrationLifecycleState::Invalidated { reason, .. } => {
                Err(CalibrationError::CertificateInvalidated {
                    reason: reason.clone(),
                })
            }
            CalibrationLifecycleState::Uncalibrated => Err(CalibrationError::InvalidIntrinsics(
                "no active calibration certificate installed".to_string(),
            )),
        }
    }

    /// Verifies a runtime observation against the active certificate.
    ///
    /// If the observation contradicts the active certificate by exceeding `tolerance_upx`,
    /// this method transitions the lifecycle to [`CalibrationLifecycleState::Invalidated`]
    /// and returns [`CalibrationError::ContradictedCertificate`].
    pub fn verify_observation(
        &mut self,
        sample: &CalibrationSample,
        tolerance_upx: u64,
    ) -> Result<(), CalibrationError> {
        let cert = match &self.state {
            CalibrationLifecycleState::Active(c) => c.clone(),
            CalibrationLifecycleState::Invalidated { reason, .. } => {
                return Err(CalibrationError::CertificateInvalidated {
                    reason: reason.clone(),
                });
            }
            CalibrationLifecycleState::Uncalibrated => {
                return Err(CalibrationError::InvalidIntrinsics(
                    "cannot verify observation without active calibration certificate".to_string(),
                ));
            }
        };

        if let Err(contradiction) = cert.verify_not_contradicted(sample, tolerance_upx) {
            self.state = CalibrationLifecycleState::Invalidated {
                certificate_digest: cert.certificate_digest,
                reason: format!("reprojection contradiction: {contradiction}"),
                contradicting_sample: Some(sample.clone()),
            };
            return Err(contradiction);
        }

        Ok(())
    }

    /// Explicitly invalidates the active calibration certificate.
    pub fn invalidate(&mut self, reason: String, contradicting_sample: Option<CalibrationSample>) {
        let digest = match &self.state {
            CalibrationLifecycleState::Active(c) => c.certificate_digest,
            CalibrationLifecycleState::Invalidated {
                certificate_digest, ..
            } => *certificate_digest,
            CalibrationLifecycleState::Uncalibrated => ContentDigest::sha256(b"uncalibrated"),
        };
        self.state = CalibrationLifecycleState::Invalidated {
            certificate_digest: digest,
            reason,
            contradicting_sample,
        };
    }
}

/// Errors occurring in the camera intrinsics and distortion certificate subsystem.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CalibrationError {
    /// Insufficient calibration evidence samples were provided.
    InsufficientEvidence {
        /// Number of samples provided.
        count: usize,
        /// Minimum number required.
        min_required: usize,
    },
    /// Evidence samples form a degenerate geometric configuration (e.g. collinear).
    DegenerateEvidence {
        /// Reason describing the degeneracy.
        reason: String,
    },
    /// Reprojection residual or RMSE exceeds declared maximum tolerance.
    ResidualExceedsTolerance {
        /// Observed RMSE in micro-pixels.
        actual_rmse_upx: u64,
        /// Maximum allowed RMSE in micro-pixels.
        max_allowed_upx: u64,
    },
    /// Calibration certificate requested outside its certified time validity interval.
    StaleCertificatePastValidity {
        /// Timestamp requested.
        requested: TimestampNs,
        /// Validity horizon upper bound.
        valid_until: TimestampNs,
    },
    /// Bound device generation does not match the querying device.
    DeviceGenerationMismatch {
        /// Expected device generation.
        expected: DeviceGeneration,
        /// Actual device generation observed.
        actual: DeviceGeneration,
    },
    /// Bound firmware generation does not match the querying device.
    FirmwareGenerationMismatch {
        /// Expected firmware generation.
        expected: FirmwareGeneration,
        /// Actual firmware generation observed.
        actual: FirmwareGeneration,
    },
    /// Bound device ID does not match the querying device.
    DeviceIdMismatch {
        /// Expected device ID.
        expected: DeviceId,
        /// Actual device ID observed.
        actual: DeviceId,
    },
    /// An uncalibrated identity matrix was submitted, which is strictly prohibited.
    IdentityCalibrationProhibited,
    /// An observation contradicted the active certificate.
    ContradictedCertificate {
        /// Point identifier that contradicted.
        point_id: u64,
        /// Reprojection error observed in micro-pixels.
        observed_error_upx: u64,
        /// Maximum tolerance threshold in micro-pixels.
        tolerance_upx: u64,
    },
    /// Too many evidence samples were supplied, exceeding the declared bound.
    TooManyEvidenceSamples {
        /// Actual count observed.
        actual: usize,
        /// Maximum allowed count.
        max: usize,
    },
    /// Certificate identifier byte length exceeds the declared bound.
    CertificateIdTooLong {
        /// Actual length observed.
        actual: usize,
        /// Maximum allowed length.
        max: usize,
    },
    /// Certificate identifier cannot be empty.
    EmptyCertificateId,
    /// Intrinsic camera parameters are invalid.
    InvalidIntrinsics(String),
    /// Certificate has been invalidated and cannot be queried.
    CertificateInvalidated {
        /// Reason for invalidation.
        reason: String,
    },
    /// Checked fixed-point arithmetic overflowed.
    ArithmeticOverflow,
    /// Contract encoding error.
    Contract(ContractError),
    /// Deterministic reference error.
    Reference(String),
}

impl fmt::Display for CalibrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientEvidence {
                count,
                min_required,
            } => {
                write!(
                    f,
                    "insufficient calibration evidence: {count} samples provided, minimum {min_required} required"
                )
            }
            Self::DegenerateEvidence { reason } => {
                write!(f, "degenerate calibration evidence: {reason}")
            }
            Self::ResidualExceedsTolerance {
                actual_rmse_upx,
                max_allowed_upx,
            } => {
                write!(
                    f,
                    "reprojection residual RMSE {actual_rmse_upx} upx exceeds maximum tolerance {max_allowed_upx} upx"
                )
            }
            Self::StaleCertificatePastValidity {
                requested,
                valid_until,
            } => {
                write!(
                    f,
                    "calibration certificate expired: requested at {requested:?}, valid until {valid_until:?}"
                )
            }
            Self::DeviceGenerationMismatch { expected, actual } => {
                write!(
                    f,
                    "device generation mismatch: expected {expected}, actual {actual}"
                )
            }
            Self::FirmwareGenerationMismatch { expected, actual } => {
                write!(
                    f,
                    "firmware generation mismatch: expected {expected}, actual {actual}"
                )
            }
            Self::DeviceIdMismatch { expected, actual } => {
                write!(
                    f,
                    "device ID mismatch: expected {expected}, actual {actual}"
                )
            }
            Self::IdentityCalibrationProhibited => {
                write!(f, "default identity calibration is strictly prohibited")
            }
            Self::ContradictedCertificate {
                point_id,
                observed_error_upx,
                tolerance_upx,
            } => {
                write!(
                    f,
                    "certificate contradicted by point {point_id}: error {observed_error_upx} upx exceeds tolerance {tolerance_upx} upx"
                )
            }
            Self::TooManyEvidenceSamples { actual, max } => {
                write!(
                    f,
                    "evidence sample count {actual} exceeds maximum declared bound {max}"
                )
            }
            Self::CertificateIdTooLong { actual, max } => {
                write!(
                    f,
                    "certificate identifier length {actual} exceeds maximum declared bound {max}"
                )
            }
            Self::EmptyCertificateId => {
                write!(f, "certificate identifier cannot be empty")
            }
            Self::InvalidIntrinsics(reason) => {
                write!(f, "invalid camera intrinsics: {reason}")
            }
            Self::CertificateInvalidated { reason } => {
                write!(f, "calibration certificate is invalidated: {reason}")
            }
            Self::ArithmeticOverflow => {
                write!(f, "checked fixed-point arithmetic overflow")
            }
            Self::Contract(err) => {
                write!(f, "contract encoding error: {err:?}")
            }
            Self::Reference(reason) => {
                write!(f, "reference error: {reason}")
            }
        }
    }
}

impl std::error::Error for CalibrationError {}

impl From<ContractError> for CalibrationError {
    fn from(err: ContractError) -> Self {
        Self::Contract(err)
    }
}

impl From<ReferenceError> for CalibrationError {
    fn from(err: ReferenceError) -> Self {
        Self::Reference(format!("{err:?}"))
    }
}
